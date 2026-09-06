//! A phone, through the relay, end to end: registered on the relay, enrolled
//! by the daemon, and then approving — with the daemon believing the relay
//! about nothing.
//!
//! The relay here is a fake: a few dozen lines of HTTP that answer the three
//! calls the daemon makes (`/api/device/phones`, `/present`, `/await`) and
//! sign whatever they are shown with a phone-shaped key. It is deliberately
//! as agreeable as a relay can be — it lists the phone, it says the phone
//! approved, it hands back a good signature — so that the test shows the
//! daemon's own roster, and nothing the relay said, deciding whether the
//! approval counts.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use countersign_verify::encoding::{b64url_encode, hex_encode};
use countersign_verify::{
    fingerprint_uri, signing_payload, verify_bundle, Decision, DeviceClass, MemoryCounters,
    RustCryptoBackend, VerifyPolicy, ENROLLMENT_ACTION,
};
use p256::ecdsa::SigningKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use signetd::audit::AuditStore;
use signetd::config::Config;
use signetd::daemon::{ApprovalRequest, Daemon, Origin};
use signetd::device::sign_low_s;
use signetd::relay::{RelayConfig, RelayDevice};
use signetd::roster::LocalRoster;

const URI: &str = "file:///Users/example/project";
const TOKEN: &str = "a-bearer-token-the-fake-relay-issued";

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("signetd-relay-phone-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn config() -> Config {
    Config::parse(&format!(
        r#"
[[environment]]
label = "laptop"
tier  = "development"
uri_fingerprints = ["{}"]

[policy]
default_tier = "production"
on_no_device = "deny"

[[policy.rule]]
tier = "development"
actions = ["fs.delete"]
decision = "require_approval"
"#,
        fingerprint_uri(URI)
    ))
    .unwrap()
}

fn delete_request() -> ApprovalRequest {
    ApprovalRequest {
        action: "fs.delete".into(),
        target_uri: Some(URI.into()),
        uri_fingerprint: None,
        target_kind: "filesystem".into(),
        statement: "rm demo/scratch.txt".into(),
        advisory: None,
        requester_id: "claude-code".into(),
        requester_instance: "test".into(),
        ttl_ms: Some(5_000),
    }
}

/// The phone on the far side of the relay.
struct Phone {
    key: SigningKey,
    device_id: String,
    public_key_hex: String,
    counter: AtomicU64,
}

impl Phone {
    fn new(seed: &[u8]) -> Self {
        let key = SigningKey::from_slice(&Sha256::digest(seed)).unwrap();
        let public = key.verifying_key().to_sec1_bytes();
        Self {
            device_id: hex_encode(&Sha256::digest(&public)),
            public_key_hex: hex_encode(&public),
            key,
            counter: AtomicU64::new(0),
        }
    }

    /// Sign a digest the way the iPhone app will: key and class alongside.
    fn sign(&self, request_digest: &str) -> Value {
        let counter = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
        let device_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let tbs = signing_payload(request_digest, counter, device_unix_ms).unwrap();
        let signature = sign_low_s(&self.key, &tbs);
        json!({
            "device_id": self.device_id,
            "counter": counter,
            "device_unix_ms": device_unix_ms,
            "signature": b64url_encode(&signature.to_bytes()),
            "dwell_ms": 5000,
            "public_key_hex": self.public_key_hex,
            "class": "enclave",
        })
    }
}

/// What the fake relay knows.
struct Relay {
    /// Whether the phone is registered on the account — what `/api/device/phones` lists.
    registered: Arc<AtomicBool>,
    /// Every presentation the daemon posted.
    presented: Arc<Mutex<Vec<Value>>>,
    base_url: String,
}

fn serve(phone: Arc<Phone>) -> Relay {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let registered = Arc::new(AtomicBool::new(true));
    let presented = Arc::new(Mutex::new(Vec::new()));

    let relay = Relay {
        registered: Arc::clone(&registered),
        presented: Arc::clone(&presented),
        base_url,
    };

    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let phone = Arc::clone(&phone);
            let registered = Arc::clone(&registered);
            let presented = Arc::clone(&presented);
            std::thread::spawn(move || handle(stream, &phone, &registered, &presented));
        }
    });
    relay
}

/// One HTTP/1.1 exchange, then close. Enough HTTP for `ureq`, no more.
fn handle(mut stream: TcpStream, phone: &Phone, registered: &AtomicBool, presented: &Mutex<Vec<Value>>) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        let n = stream.read(&mut chunk).unwrap_or(0);
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or_default().to_string();
    let mut content_length = 0usize;
    let mut authorization = String::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            match name.trim().to_ascii_lowercase().as_str() {
                "content-length" => content_length = value.trim().parse().unwrap_or(0),
                "authorization" => authorization = value.trim().to_string(),
                _ => {}
            }
        }
    }
    let mut body = buf[head_end..].to_vec();
    while body.len() < content_length {
        let n = stream.read(&mut chunk).unwrap_or(0);
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let path = target.split('?').next().unwrap_or_default();

    let (status, reply) = if authorization != format!("Bearer {TOKEN}") {
        (401, json!({ "error": "unknown_device", "message": "pair this daemon first" }))
    } else {
        match (method, path) {
            ("GET", "/api/device/phones") => {
                let phones = if registered.load(Ordering::SeqCst) {
                    vec![json!({
                        "device_id": phone.device_id,
                        "public_key_hex": phone.public_key_hex,
                        "class": "enclave",
                        "name": "Alice’s iPhone",
                    })]
                } else {
                    vec![]
                };
                (200, json!({ "phones": phones }))
            }
            ("POST", "/api/device/present") => {
                let presentation: Value = serde_json::from_slice(&body).unwrap();
                let mut list = presented.lock().unwrap();
                list.push(presentation);
                (200, json!({ "request": { "id": format!("r{}", list.len()) } }))
            }
            ("GET", "/api/device/await") => {
                // The phone approves whatever was shown last, instantly.
                let shown = presented.lock().unwrap().last().cloned().unwrap();
                let digest = shown["request_digest"].as_str().unwrap();
                (
                    200,
                    json!({
                        "status": "settled",
                        "outcome": {
                            "decision": "approved",
                            "bundle": {
                                "v": 1,
                                "decision": "approved",
                                "request_digest": digest,
                                "signatures": [phone.sign(digest)],
                            },
                        },
                    }),
                )
            }
            _ => (404, json!({ "error": "not_found", "message": path })),
        }
    };

    let text = reply.to_string();
    let _ = write!(
        stream,
        "HTTP/1.1 {status} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{text}",
        if status == 200 { "OK" } else { "Error" },
        text.len()
    );
    let _ = stream.flush();
}

struct Stack {
    daemon: Daemon,
    roster: Arc<Mutex<LocalRoster>>,
    dir: PathBuf,
}

fn stack(tag: &str, relay: &Relay) -> Stack {
    let dir = temp_dir(tag);
    let roster = Arc::new(Mutex::new(LocalRoster::default()));
    let device = RelayDevice::new(RelayConfig {
        base_url: relay.base_url.clone(),
        signet_id: "s".into(),
        token: TOKEN.into(),
        name: "desk".into(),
    })
    .with_roster(Arc::clone(&roster))
    .with_counter_file(&dir.join("relay-counter"));
    let audit = AuditStore::open(&dir.join("audit")).unwrap();
    let daemon = Daemon::new(config(), Box::new(device), Vec::new(), audit)
        .with_roster(Arc::clone(&roster), dir.clone());
    Stack { daemon, roster, dir }
}

#[test]
fn a_phone_is_enrolled_through_the_relay_and_then_approves_for_real() {
    let phone = Arc::new(Phone::new(b"alice's iphone"));
    let relay = serve(Arc::clone(&phone));
    let mut stack = stack("enroll", &relay);

    // 1. Before the ceremony, the relay lists the phone — and that alone lets
    //    it approve nothing.
    let early = stack.daemon.handle(&delete_request(), Origin::new(1)).unwrap();
    assert_ne!(early.decision, Decision::Approved, "{early:?}");
    assert!(early.envelope.is_none());
    assert_eq!(relay.presented.lock().unwrap().len(), 1, "the phone was asked, and its answer refused");

    // 2. The ceremony. The daemon presents it through the relay, the phone
    //    signs it, the daemon verifies against the key the signature carries,
    //    finds the phone's key in what the relay lists, and writes the record.
    let record = stack.daemon.enroll("alice@example.com", Some("Alice")).unwrap();
    assert_eq!(record.class(), DeviceClass::Enclave);
    assert!(!record.is_test_key);
    assert_eq!(record.device_id, phone.device_id);
    assert_eq!(record.public_key_hex, phone.public_key_hex);
    assert_eq!(record.operator.subject, "alice@example.com");
    record.verify_proof(&RustCryptoBackend).expect("the proof verifies against the phone's own key");
    assert!(LocalRoster::path_in(&stack.dir).exists(), "the roster was written");
    assert_eq!(stack.roster.lock().unwrap().records.len(), 1);

    let shown = relay.presented.lock().unwrap();
    let ceremony = shown.last().unwrap();
    let request: Value = serde_json::from_str(ceremony["request_json"].as_str().unwrap()).unwrap();
    assert_eq!(request["action"], ENROLLMENT_ACTION);
    assert_eq!(request["statement"], "Enroll this device as an approver for alice@example.com");
    // Two kinds of signer could answer — the phone and the browser page — and
    // the screen says so rather than naming one.
    let advisory = ceremony["render"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["role"] == "advisory")
        .unwrap()["text"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(advisory.contains("enclave") && advisory.contains("test"), "{advisory}");
    drop(shown);

    // 3. Now an approval is presented, signed by the phone, verified against
    //    the roster, and returned as an envelope.
    let response = stack.daemon.handle(&delete_request(), Origin::new(2)).unwrap();
    assert_eq!(response.decision, Decision::Approved, "{response:?}");
    let envelope = response.envelope.expect("approved carries an envelope");
    assert_eq!(envelope.bundle.signatures[0].device_id, phone.device_id);

    // 4. A DEFAULT verifier accepts it: the roster's record says enclave, and
    //    the default policy includes enclave. Nothing was turned on.
    let registry = stack.roster.lock().unwrap().registry().unwrap();
    let verified = verify_bundle(
        &envelope,
        &registry,
        &VerifyPolicy::default(),
        &mut MemoryCounters::new(),
        &RustCryptoBackend,
        None,
    )
    .expect("a default verifier accepts a phone's approval");
    assert_eq!(verified.signers.len(), 1);
    assert_eq!(verified.signers[0].class, DeviceClass::Enclave);

    // 5. Every approval the phone made landed in the trail, whichever way it went.
    assert_eq!(stack.daemon.audit().len(), 3);
}

#[test]
fn the_relay_listing_a_phone_does_not_make_it_an_approver() {
    // The relay says the phone is on the account, and the phone's signature is
    // perfectly good. This daemon never enrolled it. Refused.
    let phone = Arc::new(Phone::new(b"a phone somebody registered"));
    let relay = serve(Arc::clone(&phone));
    let mut stack = stack("unenrolled", &relay);

    let response = stack.daemon.handle(&delete_request(), Origin::new(1)).unwrap();
    assert_eq!(response.decision, Decision::Aborted, "{response:?}");
    assert!(response.envelope.is_none());
}

#[test]
fn a_phone_the_relay_no_longer_lists_is_still_enrolled() {
    // Forgetting a phone on the relay is not revoking it. The daemon's roster
    // has the key; the relay dropping the listing changes nothing about
    // whether the phone's signature is believed, because the roster is what
    // is consulted. (What the relay *would* do is refuse to accept the phone's
    // approval on its own side — a different gate, tested in web/.)
    let phone = Arc::new(Phone::new(b"alice's iphone, forgotten"));
    let relay = serve(Arc::clone(&phone));
    let mut stack = stack("forgotten", &relay);

    stack.daemon.enroll("alice@example.com", None).unwrap();
    relay.registered.store(false, Ordering::SeqCst);

    let response = stack.daemon.handle(&delete_request(), Origin::new(1)).unwrap();
    assert_eq!(response.decision, Decision::Approved, "{response:?}");
}

//! The app as a device, end to end over the control socket.
//!
//! A fake app holds a P-256 key the way the real one holds an enclave key,
//! attaches, is enrolled through the ceremony, then signs an approval — and a
//! **default** verifier accepts what it signed, because the record it enrolled
//! under is class `enclave`. That acceptance is the whole point of M1 and M2
//! together: the first approval in this repository that a verifier believes
//! without being told to accept test keys.
//!
//! The fake app's key is generated in memory, which is exactly what the class
//! forbids for a real device (device-class spec §2). The daemon cannot tell,
//! and this file is honest about that: nothing here attests to an enclave.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use countersign_verify::encoding::{b64url_encode, hex_encode};
use countersign_verify::{
    digest_of_json, fingerprint_uri, signing_payload, verify_bundle, Decision, DeviceClass,
    MemoryCounters, RustCryptoBackend, VerifyError, VerifyPolicy,
};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use signetd::app::{AppDevice, AppDevices};
use signetd::audit::AuditStore;
use signetd::config::Config;
use signetd::daemon::{ApprovalRequest, Daemon};
use signetd::roster::LocalRoster;
use signetd::service::{self, Client};

const URI: &str = "file:///Users/example/project";

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("signetd-app-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Unix socket paths are short-lived and length-limited; `/tmp` keeps them so.
fn socket_path(tag: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/cs-app-{}-{tag}.sock", std::process::id()))
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

struct Served {
    socket: PathBuf,
    roster: Arc<Mutex<LocalRoster>>,
    roster_dir: PathBuf,
}

fn serve(tag: &str) -> Served {
    let dir = temp_dir(tag);
    let socket = socket_path(tag);
    let _ = std::fs::remove_file(&socket);
    let roster = Arc::new(Mutex::new(LocalRoster::default()));
    let apps = Arc::new(AppDevices::new(Arc::clone(&roster)).with_counter_file(&dir.join("counters.json")));
    let audit = AuditStore::open(&dir.join("audit")).unwrap();
    let daemon = Daemon::new(config(), Box::new(AppDevice::new(Arc::clone(&apps))), Vec::new(), audit)
        .with_roster(Arc::clone(&roster), dir.clone());

    let path = socket.clone();
    std::thread::spawn(move || {
        let _ = service::serve(daemon, &path, None, Some(apps));
    });
    for _ in 0..100 {
        if UnixStream::connect(&socket).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Served {
        socket,
        roster,
        roster_dir: dir,
    }
}

/// The fake app: a key, a counter, and a loop that answers `device.present`.
struct FakeApp {
    key: SigningKey,
    device_id: String,
    counter: Arc<AtomicU64>,
    /// When set, the next signature reuses the previous counter — a replay.
    replay_next: Arc<AtomicBool>,
    /// When set, the next signature is left high-S if it came out that way.
    skip_low_s: Arc<AtomicBool>,
    seen: Arc<Mutex<Vec<Value>>>,
}

impl FakeApp {
    fn new() -> Self {
        let key = SigningKey::from_slice(&Sha256::digest(b"fake app enclave key for tests"))
            .expect("valid scalar");
        let public = key.verifying_key().to_sec1_bytes();
        Self {
            device_id: hex_encode(&Sha256::digest(&public)),
            key,
            counter: Arc::new(AtomicU64::new(0)),
            replay_next: Arc::new(AtomicBool::new(false)),
            skip_low_s: Arc::new(AtomicBool::new(false)),
            seen: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn public_key_hex(&self) -> String {
        hex_encode(&self.key.verifying_key().to_sec1_bytes())
    }

    /// Attach, then answer presentations forever on a background thread.
    fn attach_and_run(&self, socket: &Path) -> Value {
        let stream = UnixStream::connect(socket).unwrap();
        let mut writer = stream.try_clone().unwrap();
        let mut reader = BufReader::new(stream);

        writeln!(
            writer,
            "{}",
            json!({
                "jsonrpc": "2.0", "id": 1, "method": "device.attach",
                "params": {
                    "device_id": self.device_id,
                    "public_key_hex": self.public_key_hex(),
                    "name": "Fake Mac",
                    "class": "enclave",
                }
            })
        )
        .unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let response: Value = serde_json::from_str(&line).unwrap();

        let key = self.key.clone();
        let device_id = self.device_id.clone();
        let counter = Arc::clone(&self.counter);
        let replay_next = Arc::clone(&self.replay_next);
        let skip_low_s = Arc::clone(&self.skip_low_s);
        let seen = Arc::clone(&self.seen);
        std::thread::spawn(move || {
            let mut line = String::new();
            while reader.read_line(&mut line).is_ok_and(|n| n > 0) {
                let msg: Value = match serde_json::from_str(&line) {
                    Ok(v) => v,
                    Err(_) => {
                        line.clear();
                        continue;
                    }
                };
                line.clear();
                if msg.get("method").and_then(Value::as_str) != Some("device.present") {
                    continue;
                }
                let id = msg["id"].clone();
                let p = &msg["params"]["presentation"];
                seen.lock().unwrap().push(msg["params"].clone());

                // What a real app does before it renders anything: recompute
                // the digest from the bytes and refuse a mismatch.
                let request_json = p["request_json"].as_str().unwrap();
                let digest = p["request_digest"].as_str().unwrap().to_string();
                assert_eq!(digest_of_json(request_json).unwrap(), digest);

                let next = if replay_next.swap(false, Ordering::SeqCst) {
                    counter.load(Ordering::SeqCst)
                } else {
                    counter.fetch_add(1, Ordering::SeqCst) + 1
                };
                let now = signetd::device::now_unix_ms();
                let tbs = signing_payload(&digest, next, now).unwrap();
                let raw: Signature = key.sign(&tbs);
                let sig = if skip_low_s.swap(false, Ordering::SeqCst) {
                    // Deliberately un-normalized. Roughly half the time this
                    // is high-S, which the daemon must refuse; the test that
                    // uses it accounts for the other half.
                    raw
                } else {
                    raw.normalize_s()
                };
                writeln!(
                    writer,
                    "{}",
                    json!({
                        "jsonrpc": "2.0", "id": id,
                        "result": {
                            "outcome": "approved",
                            "signature": {
                                "device_id": device_id,
                                "counter": next,
                                "device_unix_ms": now,
                                "signature": b64url_encode(&sig.to_bytes()),
                                "dwell_ms": 5120,
                            }
                        }
                    })
                )
                .unwrap();
            }
        });
        response
    }
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

#[test]
fn an_attached_app_is_enrolled_by_the_ceremony_and_then_approves_for_real() {
    let served = serve("happy");
    let app = FakeApp::new();

    // 1. Attach. Not enrolled yet, and the daemon says so.
    let attached = app.attach_and_run(&served.socket);
    assert_eq!(attached["result"]["attached"], true, "{attached}");
    assert_eq!(attached["result"]["enrolled"], false);

    // 2. An approval before enrollment goes nowhere: no enrolled app to ask.
    let mut client = Client::connect(&served.socket).unwrap();
    let early = client.request_approval(&delete_request()).unwrap();
    assert_ne!(early.decision, Decision::Approved, "{early:?}");
    assert!(early.envelope.is_none());

    // 3. The ceremony. The app signs "Enroll this device as an approver for
    //    alice@example.com" and the roster gains an enclave record.
    let record = client.enroll("alice@example.com", Some("Alice")).unwrap();
    assert_eq!(record.class(), DeviceClass::Enclave);
    assert!(!record.is_test_key);
    assert_eq!(record.device_id, app.device_id);
    assert_eq!(record.operator.subject, "alice@example.com");
    record.verify_proof(&RustCryptoBackend).expect("the proof verifies against its own key");
    {
        let roster = served.roster.lock().unwrap();
        assert_eq!(roster.records.len(), 1);
        assert!(LocalRoster::path_in(&served.roster_dir).exists(), "written to disk");
    }
    let shown = app.seen.lock().unwrap();
    let ceremony = shown.last().unwrap();
    assert_eq!(ceremony["enrollment"], true);
    let statement = serde_json::from_str::<Value>(ceremony["presentation"]["request_json"].as_str().unwrap())
        .unwrap()["statement"]
        .clone();
    assert_eq!(statement, "Enroll this device as an approver for alice@example.com");
    drop(shown);

    // 4. Now an approval is presented, signed, verified by the daemon, and
    //    returned as an envelope.
    let response = client.request_approval(&delete_request()).unwrap();
    assert_eq!(response.decision, Decision::Approved, "{response:?}");
    let envelope = response.envelope.expect("approved carries an envelope");
    assert_eq!(envelope.bundle.signatures[0].device_id, app.device_id);

    // 5. A DEFAULT verifier accepts it. No accept_test_keys, nothing turned
    //    on — because the roster's record says enclave and the default policy
    //    includes enclave. The first approval in this repository that counts.
    let registry = served.roster.lock().unwrap().registry().unwrap();
    let verified = verify_bundle(
        &envelope,
        &registry,
        &VerifyPolicy::default(),
        &mut MemoryCounters::new(),
        &RustCryptoBackend,
        None,
    )
    .expect("a default verifier believes an enrolled enclave key");
    assert_eq!(verified.signers[0].class, DeviceClass::Enclave);
    assert_eq!(verified.operators(), vec!["alice@example.com"]);

    // 6. And a hardware-only verifier refuses the very same bundle.
    let err = verify_bundle(
        &envelope,
        &registry,
        &VerifyPolicy {
            accept_classes: vec![DeviceClass::Signet],
            ..Default::default()
        },
        &mut MemoryCounters::new(),
        &RustCryptoBackend,
        None,
    )
    .unwrap_err();
    assert!(matches!(err, VerifyError::ClassRejected { .. }), "got {err:?}");
}

#[test]
fn a_replayed_counter_from_the_app_is_refused_by_the_daemon() {
    let served = serve("replay");
    let app = FakeApp::new();
    app.attach_and_run(&served.socket);
    let mut client = Client::connect(&served.socket).unwrap();
    client.enroll("bob@example.com", None).unwrap();

    let first = client.request_approval(&delete_request()).unwrap();
    assert_eq!(first.decision, Decision::Approved);

    app.replay_next.store(true, Ordering::SeqCst);
    let replayed = client.request_approval(&delete_request()).unwrap();
    assert_ne!(replayed.decision, Decision::Approved, "a counter that did not advance is a replay");
    assert!(replayed.envelope.is_none());

    // The daemon's counter memory is on disk, so it survives its own restart.
    let counters: Value =
        serde_json::from_str(&std::fs::read_to_string(served.roster_dir.join("counters.json")).unwrap())
            .unwrap();
    assert_eq!(counters[&app.device_id], 2, "ceremony + one approval");
}

#[test]
fn a_signature_the_app_forgot_to_normalize_is_refused_when_it_is_high_s() {
    // Wire spec §4: the signer must normalize s, and CryptoKit does not do it
    // for you. This is the failure mode that ships an app that works half the
    // time. Try until the arithmetic hands us a high-S signature, then insist
    // the daemon refused that one.
    let served = serve("highs");
    let app = FakeApp::new();
    app.attach_and_run(&served.socket);
    let mut client = Client::connect(&served.socket).unwrap();
    client.enroll("carol@example.com", None).unwrap();

    let mut saw_refusal = false;
    for _ in 0..12 {
        app.skip_low_s.store(true, Ordering::SeqCst);
        let response = client.request_approval(&delete_request()).unwrap();
        match response.envelope {
            Some(envelope) => {
                // Came out low-S by luck; the daemon was right to accept it.
                let raw = countersign_verify::encoding::b64url_decode(
                    &envelope.bundle.signatures[0].signature,
                )
                .unwrap();
                assert!(countersign_verify::is_low_s(raw.as_slice().try_into().unwrap()));
            }
            None => {
                assert_ne!(response.decision, Decision::Approved);
                saw_refusal = true;
                break;
            }
        }
    }
    assert!(saw_refusal, "twelve signatures in a row came out low-S; astronomically unlikely");
}

#[test]
fn an_app_cannot_attach_with_a_software_class_or_a_borrowed_id() {
    let served = serve("attach");
    let stream = UnixStream::connect(&served.socket).unwrap();
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);
    let app = FakeApp::new();

    let mut ask = |params: Value| -> Value {
        writeln!(writer, "{}", json!({"jsonrpc":"2.0","id":1,"method":"device.attach","params":params})).unwrap();
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    };

    // A software key is not a device.
    let r = ask(json!({"device_id": app.device_id, "public_key_hex": app.public_key_hex(), "class": "test"}));
    assert!(r["error"]["message"].as_str().unwrap().contains("enclave"), "{r}");
    let r = ask(json!({"device_id": app.device_id, "public_key_hex": app.public_key_hex(), "class": "signet"}));
    assert!(r.get("error").is_some(), "an app is not a Signet: {r}");

    // An id that is not the digest of the key is someone else's id.
    let r = ask(json!({"device_id": "00".repeat(32), "public_key_hex": app.public_key_hex()}));
    assert!(r["error"]["message"].as_str().unwrap().contains("digest"), "{r}");

    // The right way in.
    let r = ask(json!({"device_id": app.device_id, "public_key_hex": app.public_key_hex()}));
    assert_eq!(r["result"]["attached"], true, "{r}");
}

#[test]
fn a_daemon_with_no_app_on_it_is_not_one_that_can_be_asked() {
    // `launch::connect_for_approval` is the hook's and the proxy's way in, and
    // what it owes them is a daemon that can present, not merely one that
    // answers. A daemon outliving its app — crashed, or killed — answers every
    // call and aborts every approval.
    //
    // Signet is not opened for either half of this: these sockets are in /tmp,
    // and Signet listens where Signet listens. The elapsed-time assertion is
    // that fact, and it is the one that keeps every other test in the
    // workspace from waiting on an app bundle.
    let served = serve("ready");
    let started = Instant::now();
    let refused = signetd::launch::connect_for_approval(&served.socket).unwrap_err();
    assert!(
        refused.to_string().contains("not attached to it"),
        "should name what is missing: {refused}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "waited for an app it had no reason to open"
    );

    let app = FakeApp::new();
    app.attach_and_run(&served.socket);
    signetd::launch::connect_for_approval(&served.socket)
        .expect("a daemon with an app attached is ready as it is");
}

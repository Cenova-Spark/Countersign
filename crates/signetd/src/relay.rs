//! The relay device: a Signet you are not sitting in front of.
//!
//! `signetd` holds the payload here exactly as it would for a device on the
//! end of a USB cable — it presents, it blocks, and it gets back a decision.
//! What changes is the transport, and the transport is now a party to the
//! conversation rather than a cable. Three consequences follow, and all three
//! are enforced below rather than assumed.
//!
//! **The relay is untrusted by design.** It holds no key and can forge nothing.
//! It can drop a request, and it can read one — that second limit is honest
//! rather than solved, and `NEXT_STEPS` §2.2 is where end-to-end encrypting the
//! payload belongs. What it cannot do is change a request, because the far end
//! recomputes `SHA-256(jcs(request))` from the bytes it was handed and refuses
//! to render anything that disagrees.
//!
//! **The signature is checked before it is believed.** A daemon that took the
//! relay's word for an approval would have moved the trust decision into the
//! one component the design says not to trust. So the signature is verified
//! here, over the payload this daemon computed, against a key this daemon
//! already has reason to believe in — and a mismatch is an abort, not a
//! warning.
//!
//! **Which key** depends on who is on the far end, and there are two answers.
//!
//! * **The browser page** signs with a published test key, derived exactly
//!   like `MockDevice`'s but from a different string, so the two do not
//!   collide on `device_id` and their counters stay independent. Wire spec §9
//!   refuses a software path to a production-valid signature, and this
//!   respects that the same way the mock does: not by a flag, but by being
//!   cryptographically incapable. A verifier refuses everything it produces
//!   unless somebody deliberately turned test keys on. It is labelled `test`
//!   and it is the demo.
//! * **A phone** signs with a non-extractable key in its secure enclave and
//!   says so — class `enclave`, with its public key beside the signature. The
//!   relay has registered that key to the account, but the relay's word is
//!   worth nothing here, so the daemon believes the key on exactly the terms
//!   `app.rs` believes the Mac app's: for the enrollment ceremony, the key the
//!   signature carries, because the ceremony is how a key becomes known; for
//!   anything else, the key in **this daemon's roster**, and a phone that is
//!   not enrolled, or has been revoked, is refused however good its signature
//!   is. Device-class spec §6 — pairing is not enrolling.
//!
//! Nothing here decides what the class is. The phone claims `enclave`, the
//! record the operator enrolls says `enclave`, and a verifier reads the record.
//! The carried class is used for one thing only: to tell a phone from the
//! browser demo, so that a test key cannot be dressed up as an enclave and an
//! unknown key cannot hide behind the `test` label.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use countersign_verify::encoding::{hex_decode, hex_encode};
use countersign_verify::{is_low_s, signing_payload, DeviceClass};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::device::{Cancel, Device, DeviceInfo, DeviceOutcome, Presentation};
use crate::roster::LocalRoster;

/// The string the browser demo's key is derived from.
///
/// Shaped like `device::TEST_KEY_DERIVATION` so the two are recognisably the
/// same kind of thing, and different from it so they are not the same key.
/// `web/src/lib/sign.js` derives from this identical string; if the two ever
/// drift, every browser approval fails the `device_id` check below — loudly,
/// which is the correct direction for this to break in.
pub const REMOTE_TEST_KEY_DERIVATION: &str = "countersign-v1 published test key · remote";

/// How long to wait between long-poll attempts that came back empty.
///
/// The relay holds each call open for several seconds itself, so this is only
/// the gap between them.
const POLL_GAP: Duration = Duration::from_millis(200);

/// Ceiling on a single HTTP call, comfortably above the relay's own hold.
const CALL_TIMEOUT: Duration = Duration::from_secs(20);

/// How long a fetched list of the account's phones is believed before it is
/// asked for again.
const PHONES_TTL: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum RelayError {
    Http(String),
    Unpaired(String),
    Refused { status: u16, message: String },
    Io(String),
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayError::Http(m) => write!(f, "cannot reach the relay: {m}"),
            RelayError::Unpaired(m) => write!(f, "{m}"),
            RelayError::Refused { status, message } => write!(f, "relay refused ({status}): {message}"),
            RelayError::Io(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for RelayError {}

/// What pairing produced, kept so the daemon can restart without re-pairing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    pub base_url: String,
    pub signet_id: String,
    /// A bearer token. The relay stores only its SHA-256, so this file is the
    /// only copy — it is written `0600` and never logged.
    pub token: String,
    #[serde(default)]
    pub name: String,
}

impl RelayConfig {
    pub fn path(run_dir: &Path) -> PathBuf {
        run_dir.join("relay.json")
    }

    pub fn load(run_dir: &Path) -> Result<Self, RelayError> {
        let path = Self::path(run_dir);
        let text = std::fs::read_to_string(&path).map_err(|_| {
            RelayError::Unpaired(format!(
                "this daemon is not paired with a relay yet.\n\
                 \x20 Sign in at the relay, open Pair a signet, and run the command it shows.\n\
                 \x20 (Pairing is stored at {})",
                path.display()
            ))
        })?;
        serde_json::from_str(&text)
            .map_err(|e| RelayError::Io(format!("{} is not readable: {e}", path.display())))
    }

    pub fn save(&self, run_dir: &Path) -> Result<(), RelayError> {
        let path = Self::path(run_dir);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| RelayError::Io(format!("cannot create {}: {e}", parent.display())))?;
        }
        let text = serde_json::to_string_pretty(self)
            .map_err(|e| RelayError::Io(format!("cannot serialize pairing: {e}")))?;
        std::fs::write(&path, text)
            .map_err(|e| RelayError::Io(format!("cannot write {}: {e}", path.display())))?;
        restrict(&path)
    }
}

#[cfg(unix)]
fn restrict(path: &Path) -> Result<(), RelayError> {
    use std::os::unix::fs::PermissionsExt;
    // A bearer token readable by every process on the box is not a bearer
    // token. Fail closed rather than leave it world-readable.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| RelayError::Io(format!("cannot restrict {}: {e}", path.display())))
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> Result<(), RelayError> {
    Ok(())
}

/// The browser demo's identity, derived rather than stored.
fn identity() -> (VerifyingKey, String) {
    let key = SigningKey::from_slice(&Sha256::digest(REMOTE_TEST_KEY_DERIVATION.as_bytes()))
        .expect("the derived test scalar is a valid P-256 key");
    let verifying = *key.verifying_key();
    // `device_id` is the SHA-256 of the SEC1 **uncompressed** encoding — spec
    // §4.2. `to_sec1_bytes` on a `VerifyingKey` gives the uncompressed form,
    // which is what `MockDevice` relies on too.
    let device_id = hex_encode(&Sha256::digest(verifying.to_sec1_bytes()));
    (verifying, device_id)
}

pub struct RelayDevice {
    config: RelayConfig,
    agent: ureq::Agent,
    /// The browser demo's key and id. The one signer this device knows
    /// without being told.
    test_verifying: VerifyingKey,
    test_device_id: String,
    /// Where a phone's key is looked up for anything but the ceremony. Absent
    /// only in tests of the test-key path; a daemon always has one.
    roster: Option<Arc<Mutex<LocalRoster>>>,
    /// The highest counter this daemon has accepted, per signer.
    ///
    /// Not the device's counter — the relay owns that. This is the daemon's own
    /// replay defence: a counter that goes backwards means something replayed
    /// an old approval at it, and that has to survive a restart to be worth
    /// anything. Keyed by `device_id` because the browser demo and each phone
    /// are independent signers with independent counters.
    counters: HashMap<String, u64>,
    counter_path: Option<PathBuf>,
    /// The phones the relay last said were on the account, and when it said so.
    phones: Mutex<Option<(Instant, Vec<RegisteredPhone>)>>,
}

/// A phone as the relay lists it — `GET /api/device/phones`.
#[derive(Debug, Clone, Deserialize)]
struct RegisteredPhone {
    device_id: String,
    public_key_hex: String,
    #[serde(default)]
    name: String,
    #[serde(default = "enclave")]
    class: DeviceClass,
}

fn enclave() -> DeviceClass {
    DeviceClass::Enclave
}

#[derive(Debug, Deserialize)]
struct Phones {
    #[serde(default)]
    phones: Vec<RegisteredPhone>,
}

impl RelayDevice {
    pub fn new(config: RelayConfig) -> Self {
        let (test_verifying, test_device_id) = identity();
        Self {
            config,
            agent: agent(),
            test_verifying,
            test_device_id,
            roster: None,
            counters: HashMap::new(),
            counter_path: None,
            phones: Mutex::new(None),
        }
    }

    /// The phones the relay says are registered to this account.
    ///
    /// Asked of the relay, believed for a few seconds, and used for one thing:
    /// finding a signer's public key *after* it has signed, so `Daemon::enroll`
    /// can write the record. Being on this list lets a phone approve nothing —
    /// the roster does that ([`Self::signer_key`]). A relay that padded it
    /// could add a name here and could not get a signature accepted.
    ///
    /// What is checked on the way in is what can be: the class is `enclave`
    /// and the id is the digest of the key. Anything else is dropped, not
    /// reported — a relay listing a phone wrongly is a relay problem.
    fn phones(&self) -> Vec<RegisteredPhone> {
        let mut cache = self.phones.lock().expect("phones mutex");
        if let Some((at, phones)) = &*cache {
            if at.elapsed() < PHONES_TTL {
                return phones.clone();
            }
        }
        match get_json::<Phones>(
            &self.agent,
            &self.url("/api/device/phones"),
            Some(self.config.token.as_str()),
        ) {
            Ok(listed) => {
                let phones: Vec<RegisteredPhone> = listed
                    .phones
                    .into_iter()
                    .filter(|p| {
                        p.class == DeviceClass::Enclave
                            && hex_decode(&p.public_key_hex)
                                .map(|key| hex_encode(&Sha256::digest(&key)) == p.device_id.to_ascii_lowercase())
                                .unwrap_or(false)
                    })
                    .collect();
                *cache = Some((Instant::now(), phones.clone()));
                phones
            }
            Err(e) => {
                eprintln!("signetd: cannot list the account's phones: {e}");
                // Stale is better than nothing for a lookup; for a decision it
                // would not be, and this is never a decision.
                cache.as_ref().map(|(_, p)| p.clone()).unwrap_or_default()
            }
        }
    }

    fn phone_info(&self, phone: &RegisteredPhone) -> DeviceInfo {
        DeviceInfo {
            device_id: phone.device_id.to_ascii_lowercase(),
            kind: if phone.name.is_empty() { "phone".into() } else { format!("phone · {}", phone.name) },
            is_test_key: false,
            class: DeviceClass::Enclave,
            public_key_hex: phone.public_key_hex.to_ascii_lowercase(),
            counter: self.highest_counter(&phone.device_id),
        }
    }

    fn test_info(&self) -> DeviceInfo {
        DeviceInfo {
            device_id: self.test_device_id.clone(),
            kind: "relay (browser page)".into(),
            is_test_key: true,
            class: DeviceClass::Test,
            public_key_hex: hex_encode(&self.test_verifying.to_sec1_bytes()),
            counter: self.highest_counter(&self.test_device_id),
        }
    }

    /// Look phones up here. Without it, only the browser demo can approve.
    pub fn with_roster(mut self, roster: Arc<Mutex<LocalRoster>>) -> Self {
        self.roster = Some(roster);
        self
    }

    /// Remember the highest accepted counters across restarts, in `path`.
    ///
    /// The file is a JSON object keyed by `device_id`. A file holding a bare
    /// integer is what this daemon wrote before phones existed — the browser
    /// demo's counter — and is read as exactly that, so an upgrade does not
    /// reopen the replay window for the one signer it already knew.
    pub fn with_counter_file(mut self, path: &Path) -> Self {
        if let Ok(text) = std::fs::read_to_string(path) {
            let text = text.trim();
            if let Ok(map) = serde_json::from_str::<HashMap<String, u64>>(text) {
                self.counters = map;
            } else if let Ok(legacy) = text.parse::<u64>() {
                self.counters.insert(self.test_device_id.clone(), legacy);
            }
        }
        self.counter_path = Some(path.to_path_buf());
        self
    }

    fn highest_counter(&self, device_id: &str) -> u64 {
        self.counters.get(device_id).copied().unwrap_or(0)
    }

    fn record_counter(&mut self, device_id: &str, counter: u64) -> Result<(), String> {
        self.counters.insert(device_id.to_string(), counter);
        if let Some(path) = &self.counter_path {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let text = serde_json::to_string(&self.counters).map_err(|e| e.to_string())?;
            // Fail closed: a counter that cannot be remembered is one that
            // could be replayed after the next restart.
            std::fs::write(path, text).map_err(|e| format!("cannot persist counter: {e}"))?;
        }
        Ok(())
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.config.base_url.trim_end_matches('/'))
    }

    /// Redeem a pairing code, binding this daemon to whoever minted it.
    pub fn pair(base_url: &str, code: &str, name: &str) -> Result<RelayConfig, RelayError> {
        let (_, device_id) = identity();
        let hostname = std::env::var("HOSTNAME")
            .ok()
            .or_else(|| {
                std::fs::read_to_string("/etc/hostname")
                    .ok()
                    .map(|h| h.trim().to_string())
            })
            .unwrap_or_default();

        let body = serde_json::json!({
            "code": code.trim().to_uppercase(),
            "device_id": device_id,
            "kind": "relay",
            "is_test_key": true,
            "name": name,
            "hostname": hostname,
        });

        #[derive(Deserialize)]
        struct Paired {
            signet_id: String,
            token: String,
            #[serde(default)]
            name: String,
        }

        let url = format!("{}/api/device/pair", base_url.trim_end_matches('/'));
        let paired: Paired = post_json(&agent(), &url, None, &body)?;

        Ok(RelayConfig {
            base_url: base_url.trim_end_matches('/').to_string(),
            signet_id: paired.signet_id,
            token: paired.token,
            name: paired.name,
        })
    }

    /// Decide which key a returned signature must verify against — or that
    /// there is none, in which case nothing it says matters.
    ///
    /// This is the whole of what the daemon believes about the far end, and
    /// it deliberately believes the relay about none of it.
    fn signer_key(
        &self,
        presentation: &Presentation,
        signed: &SignedOutcome,
    ) -> Result<VerifyingKey, String> {
        // The browser demo. Defined by a derived key, labelled `test`, and
        // not permitted to call itself anything else.
        if signed.device_id == self.test_device_id {
            if let Some(class) = signed.class {
                if class != DeviceClass::Test {
                    return Err(format!(
                        "the published test key claimed class {class}; it is test and only test"
                    ));
                }
            }
            if let Some(hex) = &signed.public_key_hex {
                if hex.to_ascii_lowercase() != hex_encode(&self.test_verifying.to_sec1_bytes()) {
                    return Err("the published test key arrived with somebody else's public key".into());
                }
            }
            return Ok(self.test_verifying);
        }

        // Anything else is a phone, and a phone has to say what it is and
        // show the key it is saying it about.
        match signed.class {
            Some(DeviceClass::Enclave) => {}
            Some(DeviceClass::Test) => {
                return Err(format!(
                    "device {} claims class test but is not the published test key; an unknown \
                     key does not get to hide behind the test label",
                    signed.device_id
                ))
            }
            Some(other) => {
                return Err(format!(
                    "device {} claims class {other}; only a phone (enclave) or the browser demo \
                     (test) reaches this daemon through the relay",
                    signed.device_id
                ))
            }
            None => {
                return Err(format!(
                    "device {} is not the published test key and carried no class; a phone must \
                     say enclave and show its key",
                    signed.device_id
                ))
            }
        }
        let carried_hex = signed
            .public_key_hex
            .as_deref()
            .ok_or_else(|| format!("device {} carried no public key", signed.device_id))?;
        let carried = hex_decode(carried_hex).map_err(|_| "public_key_hex is not hex".to_string())?;
        if carried.len() != 65 || carried[0] != 0x04 {
            return Err(
                "public_key_hex must be the 65-byte SEC1 uncompressed encoding (0x04 || X || Y)"
                    .into(),
            );
        }
        let carried_key = VerifyingKey::from_sec1_bytes(&carried)
            .map_err(|_| "public key is not a point on P-256".to_string())?;
        let derived = hex_encode(&Sha256::digest(&carried));
        if derived != signed.device_id.to_ascii_lowercase() {
            return Err(format!(
                "device_id {} is not the digest of the key it carries ({derived}); wire spec §4.2",
                signed.device_id
            ));
        }

        // The ceremony is how a key becomes known, so it is the one payload
        // verified against the key the signature carries. Enrollment spec §2.
        if presentation.is_enrollment() {
            return Ok(carried_key);
        }

        // Everything else is verified against what this daemon already holds.
        // The relay registered the phone; the relay's word is worth nothing.
        let roster = self
            .roster
            .as_ref()
            .ok_or_else(|| "this daemon has no roster, so no phone is enrolled".to_string())?;
        let roster = roster.lock().expect("roster mutex");
        let record = match roster.get(&derived) {
            Some(record) if record.status.is_active() => record,
            Some(_) => return Err(format!("phone {derived} is revoked")),
            None => {
                return Err(format!(
                    "phone {derived} is not enrolled; only the enrollment ceremony may be signed. \
                     Run `signetd enroll --subject you@example.com` and hold on the phone"
                ))
            }
        };
        if record.class() != DeviceClass::Enclave {
            return Err(format!(
                "phone {derived} is enrolled as {}, not enclave",
                record.class()
            ));
        }
        // The id derives from the key on both sides, so these cannot differ;
        // said out loud anyway, because the roster's key is the one that counts.
        if !record.public_key_hex.eq_ignore_ascii_case(carried_hex) {
            return Err(format!("phone {derived} carried a key that is not its enrolled key"));
        }
        let enrolled = hex_decode(&record.public_key_hex).map_err(|_| "roster key is not hex".to_string())?;
        VerifyingKey::from_sec1_bytes(&enrolled).map_err(|_| "roster key is not a P-256 point".to_string())
    }

    /// Verify what came back, against this daemon's own idea of the payload.
    ///
    /// Nothing here trusts the relay. The digest is the one this daemon
    /// computed, the key is one this daemon has its own reason to believe in
    /// ([`Self::signer_key`]), and the counter has to be ahead of every
    /// counter already accepted from that signer.
    fn verify(&mut self, presentation: &Presentation, signed: &SignedOutcome) -> Result<DeviceOutcome, String> {
        let key = self.signer_key(presentation, signed)?;

        // Spec §4.1: reject a counter at or below the highest already accepted
        // from this device. A device whose counter went backwards is a
        // compromised device, not a support ticket.
        let highest = self.highest_counter(&signed.device_id);
        if signed.counter <= highest {
            return Err(format!(
                "counter {} but {highest} was already accepted — refusing as a replay",
                signed.counter
            ));
        }

        let tbs = signing_payload(&presentation.request_digest, signed.counter, signed.device_unix_ms)
            .map_err(|e| e.to_string())?;
        let raw = countersign_verify::encoding::b64url_decode(&signed.signature)
            .map_err(|_| "signature is not base64url".to_string())?;
        let fixed: [u8; 64] = raw
            .as_slice()
            .try_into()
            .map_err(|_| "signature is not 64 bytes".to_string())?;
        // Spec §4 requires verifiers to reject `s > n/2`. Borrowed from
        // `countersign-verify` rather than re-derived, so the daemon and the
        // verifier cannot disagree about where the boundary is.
        if !is_low_s(&fixed) {
            return Err("signature is high-S (wire spec §4); the signer must normalize s".into());
        }
        let signature = Signature::from_slice(&fixed).map_err(|_| "malformed signature".to_string())?;
        if key.verify(&tbs, &signature).is_err() {
            return Err(format!(
                "signature does not cover this request (digest {})",
                presentation.request_digest
            ));
        }

        self.record_counter(&signed.device_id, signed.counter)?;

        // A phone this daemon has not seen listed yet just signed — the
        // ceremony, typically, moments after registering. Forget the cached
        // list so `devices()` asks again and `Daemon::enroll` finds its key.
        if signed.device_id != self.test_device_id {
            let mut cache = self.phones.lock().expect("phones mutex");
            let listed = cache
                .as_ref()
                .is_some_and(|(_, phones)| phones.iter().any(|p| p.device_id.eq_ignore_ascii_case(&signed.device_id)));
            if !listed {
                *cache = None;
            }
        }

        Ok(DeviceOutcome::Approved {
            device_id: signed.device_id.to_ascii_lowercase(),
            counter: signed.counter,
            device_unix_ms: signed.device_unix_ms,
            signature: signed.signature.clone(),
            dwell_ms: signed.dwell_ms,
        })
    }

    /// [`Self::verify`], with a refusal logged and turned into an abort — never
    /// a warning, and never a signature passed upstream for somebody else to
    /// notice.
    fn accept(&mut self, presentation: &Presentation, signed: &SignedOutcome) -> DeviceOutcome {
        match self.verify(presentation, signed) {
            Ok(outcome) => outcome,
            Err(why) => {
                eprintln!("signetd: refusing the relay's signature: {why}");
                DeviceOutcome::Aborted
            }
        }
    }
}

/// What the far end signed, plus what it says about itself.
///
/// `public_key_hex` and `class` are the phone's **claims**. They are used to
/// find the right key to check the signature against and for nothing else —
/// no record is ever written from them (device-class spec §4, §8).
#[derive(Debug, Deserialize)]
struct SignedOutcome {
    device_id: String,
    counter: u64,
    device_unix_ms: u64,
    signature: String,
    #[serde(default)]
    dwell_ms: Option<u64>,
    /// SEC1 uncompressed, lowercase hex. Required from a phone; optional from
    /// the browser demo, whose key is derived.
    #[serde(default)]
    public_key_hex: Option<String>,
    /// `enclave` for a phone, `test` for the browser demo. Absent is read as
    /// the browser demo, and only the browser demo's key satisfies that.
    #[serde(default)]
    class: Option<DeviceClass>,
}

#[derive(Debug, Deserialize)]
struct Presented {
    request: PresentedRequest,
}

#[derive(Debug, Deserialize)]
struct PresentedRequest {
    id: String,
}

#[derive(Debug, Deserialize)]
struct Awaited {
    status: String,
    #[serde(default)]
    outcome: Option<Outcome>,
}

#[derive(Debug, Deserialize)]
struct Outcome {
    decision: String,
    #[serde(default)]
    bundle: Option<OutcomeBundle>,
}

#[derive(Debug, Deserialize)]
struct OutcomeBundle {
    #[serde(default)]
    signatures: Vec<SignedOutcome>,
}

impl Device for RelayDevice {
    /// The first phone on the account, or the browser demo when there is none.
    /// `devices()` is where the truth lives.
    fn info(&self) -> DeviceInfo {
        self.phones()
            .first()
            .map(|p| self.phone_info(p))
            .unwrap_or_else(|| self.test_info())
    }

    /// Every signer that can answer through this relay: each phone on the
    /// account, then the browser page. All of them are asked by one `present`;
    /// this is how the daemon finds out which one signed.
    fn devices(&self) -> Vec<DeviceInfo> {
        let mut list: Vec<DeviceInfo> = self.phones().iter().map(|p| self.phone_info(p)).collect();
        list.push(self.test_info());
        list
    }

    fn present(&mut self, presentation: &Presentation, cancel: &Cancel) -> DeviceOutcome {
        let body = serde_json::json!({
            // The bytes, not a summary of them. This is what lets the far end
            // check the digest for itself.
            "request_json": presentation.request_json,
            "request_digest": presentation.request_digest,
            "render": presentation.render,
            "severity": presentation.severity,
            "requester": presentation.requester,
            "requester_changed": presentation.requester_changed,
            "ttl_ms": presentation.ttl_ms,
        });

        let auth = Some(self.config.token.as_str());
        let presented: Presented =
            match post_json(&self.agent, &self.url("/api/device/present"), auth, &body) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("signetd: {e}");
                    // Failing to reach the relay is not a refusal by a human,
                    // but it is not an approval either, and the daemon's
                    // `on_no_device` policy is what decides what happens next.
                    return DeviceOutcome::Aborted;
                }
            };

        eprintln!(
            "signetd: waiting for a remote approval — {} · {}",
            presentation.digest_short, self.config.name
        );

        let deadline = Instant::now() + Duration::from_millis(presentation.ttl_ms);
        let poll_url = self.url(&format!(
            "/api/device/await?request_id={}",
            presented.request.id
        ));

        while Instant::now() < deadline {
            // Withdrawn — a sibling device signed first. The relay's copy
            // expires on its own TTL; there is nothing to sign any more.
            if cancel.is_cancelled() {
                return DeviceOutcome::Aborted;
            }
            let awaited: Awaited = match get_json(&self.agent, &poll_url, auth) {
                Ok(a) => a,
                Err(e) => {
                    // A dropped connection mid-wait is ordinary on a phone
                    // network. Retry until the TTL says otherwise.
                    eprintln!("signetd: {e}");
                    if cancel.wait(POLL_GAP) {
                        return DeviceOutcome::Aborted;
                    }
                    continue;
                }
            };

            if awaited.status != "settled" {
                if cancel.wait(POLL_GAP) {
                    return DeviceOutcome::Aborted;
                }
                continue;
            }

            let Some(outcome) = awaited.outcome else {
                return DeviceOutcome::Expired;
            };

            return match outcome.decision.as_str() {
                "approved" => match outcome.bundle.and_then(|b| b.signatures.into_iter().next()) {
                    Some(signed) => self.accept(presentation, &signed),
                    None => {
                        eprintln!("signetd: relay reported an approval with no signature. Refusing.");
                        DeviceOutcome::Aborted
                    }
                },
                "expired" => DeviceOutcome::Expired,
                // Anything else — a refusal, or a decision this daemon does not
                // recognise — is not an approval.
                _ => DeviceOutcome::Aborted,
            };
        }

        DeviceOutcome::Expired
    }
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(CALL_TIMEOUT))
        .user_agent(concat!("signetd/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

fn post_json<T: serde::de::DeserializeOwned>(
    agent: &ureq::Agent,
    url: &str,
    token: Option<&str>,
    body: &serde_json::Value,
) -> Result<T, RelayError> {
    let mut request = agent.post(url);
    if let Some(token) = token {
        request = request.header("Authorization", &format!("Bearer {token}"));
    }
    read(request.send_json(body))
}

fn get_json<T: serde::de::DeserializeOwned>(
    agent: &ureq::Agent,
    url: &str,
    token: Option<&str>,
) -> Result<T, RelayError> {
    let mut request = agent.get(url);
    if let Some(token) = token {
        request = request.header("Authorization", &format!("Bearer {token}"));
    }
    read(request.call())
}

fn read<T: serde::de::DeserializeOwned>(
    result: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
) -> Result<T, RelayError> {
    let mut response = match result {
        Ok(response) => response,
        Err(ureq::Error::StatusCode(status)) => {
            return Err(RelayError::Refused {
                status,
                message: "the relay refused the call".to_string(),
            })
        }
        Err(e) => return Err(RelayError::Http(e.to_string())),
    };

    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        let message = response
            .body_mut()
            .read_to_string()
            .ok()
            .and_then(|text| {
                serde_json::from_str::<serde_json::Value>(&text)
                    .ok()
                    .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(String::from))
            })
            .unwrap_or_else(|| "no detail".to_string());
        return Err(RelayError::Refused { status, message });
    }

    response
        .body_mut()
        .read_json::<T>()
        .map_err(|e| RelayError::Http(format!("the relay sent something unreadable: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{now_unix_ms, sign_low_s};
    use countersign_verify::encoding::b64url_encode;
    use countersign_verify::{
        canonicalize_str, digest_of_json, enrollment_statement, ApprovalEnvelope, Bundle, Decision,
        DeviceSignature, EnrollmentRecord, Operator, Request, Requester, Target, ENROLLMENT_ACTION,
        VERSION,
    };

    fn device() -> RelayDevice {
        RelayDevice::new(RelayConfig {
            base_url: "https://example.invalid".into(),
            signet_id: "s".into(),
            token: "t".into(),
            name: "test".into(),
        })
    }

    fn presentation(request_json: &str) -> Presentation {
        let request_digest = digest_of_json(request_json).unwrap();
        Presentation {
            render: vec![],
            digest_short: request_digest[..12].to_string(),
            request_digest,
            request_json: request_json.to_string(),
            severity: countersign_pack::Severity::Critical,
            requester: "test".into(),
            requester_changed: true,
            ttl_ms: 1000,
        }
    }

    /// An approval that is not the ceremony.
    fn an_approval() -> Presentation {
        presentation(r#"{"action":"file.delete","statement":"rm demo/scratch.txt"}"#)
    }

    /// The ceremony, as `Daemon::enroll` would present it.
    fn the_ceremony(subject: &str) -> Presentation {
        let wire = Request {
            v: VERSION,
            nonce: "bm9uY2U".into(),
            requester: Requester {
                id: "signetd enroll".into(),
                instance: String::new(),
                pid: None,
            },
            action: ENROLLMENT_ACTION.into(),
            target: Target {
                kind: "enrollment".into(),
                uri_fingerprint: hex_encode(&Sha256::digest(subject.as_bytes())),
            },
            statement: enrollment_statement(subject),
            advisory: None,
            ttl_ms: 120_000,
        };
        let json = canonicalize_str(&serde_json::to_string(&wire).unwrap()).unwrap();
        presentation(&json)
    }

    /// A phone: a fresh enclave-shaped key, its id, and its SEC1 hex.
    struct Phone {
        key: SigningKey,
        device_id: String,
        public_key_hex: String,
    }

    impl Phone {
        fn new(seed: &[u8]) -> Self {
            let key = SigningKey::from_slice(&Sha256::digest(seed)).unwrap();
            let public = key.verifying_key().to_sec1_bytes();
            Self {
                device_id: hex_encode(&Sha256::digest(&public)),
                public_key_hex: hex_encode(&public),
                key,
            }
        }

        /// Sign a presentation the way the iPhone app will: key and class
        /// beside the signature.
        fn sign(&self, presentation: &Presentation, counter: u64) -> SignedOutcome {
            let device_unix_ms = now_unix_ms();
            let tbs = signing_payload(&presentation.request_digest, counter, device_unix_ms).unwrap();
            let signature = sign_low_s(&self.key, &tbs);
            SignedOutcome {
                device_id: self.device_id.clone(),
                counter,
                device_unix_ms,
                signature: b64url_encode(&signature.to_bytes()),
                dwell_ms: Some(5000),
                public_key_hex: Some(self.public_key_hex.clone()),
                class: Some(DeviceClass::Enclave),
            }
        }

        /// The record `Daemon::enroll` would write after this phone held on
        /// the ceremony — proof included, because the roster refuses a record
        /// without one.
        fn enrolled(&self, subject: &str) -> EnrollmentRecord {
            let ceremony = the_ceremony(subject);
            let signed = self.sign(&ceremony, 1);
            let mut record = EnrollmentRecord::new(
                &hex_decode(&self.public_key_hex).unwrap(),
                Operator::new(subject),
                now_unix_ms(),
            )
            .with_class(DeviceClass::Enclave);
            record.proof = Some(ApprovalEnvelope {
                request_json: ceremony.request_json.clone(),
                bundle: Bundle {
                    v: VERSION,
                    decision: Decision::Approved,
                    request_digest: ceremony.request_digest.clone(),
                    signatures: vec![DeviceSignature {
                        device_id: signed.device_id,
                        counter: signed.counter,
                        device_unix_ms: signed.device_unix_ms,
                        signature: signed.signature,
                        dwell_ms: signed.dwell_ms,
                    }],
                },
            });
            record
        }
    }

    fn roster_with(records: Vec<EnrollmentRecord>) -> Arc<Mutex<LocalRoster>> {
        let mut roster = LocalRoster::default();
        for record in records {
            roster.enroll(record).expect("a record this test built verifies");
        }
        Arc::new(Mutex::new(roster))
    }

    #[test]
    fn the_remote_signet_is_not_the_mock_signet() {
        // If these ever collide, two independent signers share an identity and
        // a per-device counter, and a verifier's replay defence starts firing
        // for real reasons.
        let (_, remote) = identity();
        let mock = crate::device::MockDevice::new(crate::device::MockBehaviour::Auto);
        assert_ne!(remote, mock.info().device_id);
    }

    #[test]
    fn the_device_id_matches_the_browsers_derivation() {
        // Pinned so a change on either side shows up here rather than as every
        // remote approval mysteriously failing. Recompute with:
        //   node -e '…sha256("countersign-v1 published test key · remote")…'
        let (_, remote) = identity();
        assert_eq!(
            remote,
            "17d53e622556ceeb05d8430817e01dc387bb0092fbe45350f20f602f3de3f11c"
        );
    }

    /// A signature the **browser** made, accepted by the **daemon**.
    ///
    /// Two implementations of the same crypto — WebCrypto in a phone,
    /// RustCrypto here — have to agree about the key derivation, the signing
    /// payload, the `r || s` encoding and the low-S rule, and a disagreement
    /// in any one of them means every remote approval fails with no useful
    /// error. This runs a real browser-made signature through the same
    /// acceptance path a live approval takes.
    ///
    /// Regenerate with: `node web/scripts/gen-remote-vector.mjs`
    #[test]
    fn a_signature_made_in_a_browser_verifies_here() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/remote-approval.json"
        ))
        .expect("the fixture is valid JSON");

        let (_, device_id) = identity();
        assert_eq!(
            fixture["device_id"].as_str().unwrap(),
            device_id,
            "the browser and the daemon derive different signets"
        );

        // The whole signature object, so the `public_key_hex` and `class` the
        // browser now sends travel through the same parser the live path uses.
        let signed: SignedOutcome = serde_json::from_value(fixture["signature"].clone()).unwrap();
        assert_eq!(signed.class, Some(DeviceClass::Test), "the browser labels itself test");
        assert_eq!(
            signed.public_key_hex.as_deref(),
            fixture["public_key_sec1_uncompressed_hex"].as_str()
        );

        let presentation = Presentation {
            render: vec![],
            request_digest: fixture["request_digest"].as_str().unwrap().to_string(),
            request_json: fixture["request_json"].as_str().unwrap().to_string(),
            digest_short: "df47 273e eace".into(),
            severity: countersign_pack::Severity::Critical,
            requester: "claude-code".into(),
            requester_changed: true,
            ttl_ms: 60_000,
        };

        let mut device = device();
        assert!(
            matches!(device.accept(&presentation, &signed), DeviceOutcome::Approved { .. }),
            "the daemon refused a signature the browser made"
        );
        // And the daemon now remembers it, so the same one cannot come back.
        assert_eq!(
            device.accept(&presentation, &signed),
            DeviceOutcome::Aborted,
            "the same signature replayed must be refused"
        );
    }

    /// The digest must come from the bytes, not from what the relay claims.
    #[test]
    fn the_fixtures_digest_is_the_digest_of_its_own_bytes() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/remote-approval.json"
        ))
        .unwrap();
        let recomputed = digest_of_json(fixture["request_json"].as_str().unwrap()).unwrap();
        assert_eq!(recomputed, fixture["request_digest"].as_str().unwrap());
    }

    #[test]
    fn a_relay_that_lies_about_the_device_is_refused() {
        // An unknown id with nothing to say for itself: not the test key, no
        // class, no key.
        let mut device = device();
        let outcome = device.accept(
            &an_approval(),
            &SignedOutcome {
                device_id: "ff".repeat(32),
                counter: 1,
                device_unix_ms: now_unix_ms(),
                signature: "A".repeat(86),
                dwell_ms: None,
                public_key_hex: None,
                class: None,
            },
        );
        assert_eq!(outcome, DeviceOutcome::Aborted);
    }

    #[test]
    fn a_replayed_counter_is_refused() {
        let mut device = device();
        let (_, device_id) = identity();
        device.counters.insert(device_id.clone(), 41);
        for counter in [1, 41] {
            assert_eq!(
                device.accept(
                    &an_approval(),
                    &SignedOutcome {
                        device_id: device_id.clone(),
                        counter,
                        device_unix_ms: now_unix_ms(),
                        signature: "A".repeat(86),
                        dwell_ms: None,
                        public_key_hex: None,
                        class: None,
                    },
                ),
                DeviceOutcome::Aborted,
                "counter {counter} is not ahead of 41",
            );
        }
    }

    // ── Phones ───────────────────────────────────────────────────────────

    #[test]
    fn a_phone_signs_the_ceremony_with_a_key_nobody_has_seen_before() {
        // No roster at all: the ceremony is verified against the key the
        // signature carries, because the ceremony is how the key becomes known.
        let phone = Phone::new(b"a phone nobody has met");
        let ceremony = the_ceremony("alice@example.com");
        let mut device = device();
        let outcome = device.accept(&ceremony, &phone.sign(&ceremony, 1));
        match outcome {
            DeviceOutcome::Approved { device_id, .. } => assert_eq!(device_id, phone.device_id),
            other => panic!("the ceremony was refused: {other:?}"),
        }
    }

    #[test]
    fn a_phone_that_is_not_enrolled_cannot_approve_however_good_its_signature() {
        let phone = Phone::new(b"a phone that skipped the ceremony");
        let approval = an_approval();
        let mut empty_roster = device().with_roster(roster_with(vec![]));
        assert_eq!(
            empty_roster.accept(&approval, &phone.sign(&approval, 1)),
            DeviceOutcome::Aborted
        );
        // And with no roster wired at all, the same.
        let mut rosterless = device();
        assert_eq!(
            rosterless.accept(&approval, &phone.sign(&approval, 1)),
            DeviceOutcome::Aborted
        );
    }

    #[test]
    fn an_enrolled_phone_approves_and_a_revoked_one_does_not() {
        let phone = Phone::new(b"alice's phone");
        let roster = roster_with(vec![phone.enrolled("alice@example.com")]);
        let mut device = device().with_roster(Arc::clone(&roster));
        let approval = an_approval();

        match device.accept(&approval, &phone.sign(&approval, 2)) {
            DeviceOutcome::Approved { device_id, counter, .. } => {
                assert_eq!(device_id, phone.device_id);
                assert_eq!(counter, 2);
            }
            other => panic!("an enrolled phone was refused: {other:?}"),
        }

        assert!(roster
            .lock()
            .unwrap()
            .revoke(&phone.device_id, now_unix_ms(), Some(2), Some("lost".into())));
        assert_eq!(
            device.accept(&approval, &phone.sign(&approval, 3)),
            DeviceOutcome::Aborted,
            "a revoked phone stays revoked"
        );
    }

    #[test]
    fn the_roster_decides_which_phones_count_not_the_relay() {
        // Two phones, both saying `enclave`, both with perfectly good
        // signatures. The relay would have registered both. Only the one this
        // daemon enrolled may approve.
        let alice = Phone::new(b"alice's phone");
        let mallory = Phone::new(b"a phone registered to the account by someone else");
        let mut device = device().with_roster(roster_with(vec![alice.enrolled("alice@example.com")]));
        let approval = an_approval();
        assert!(matches!(
            device.accept(&approval, &alice.sign(&approval, 2)),
            DeviceOutcome::Approved { .. }
        ));
        assert_eq!(
            device.accept(&approval, &mallory.sign(&approval, 1)),
            DeviceOutcome::Aborted
        );
    }

    #[test]
    fn a_phone_must_say_enclave_and_show_its_key() {
        let phone = Phone::new(b"alice's phone");
        let mut device = device().with_roster(roster_with(vec![phone.enrolled("alice@example.com")]));
        let approval = an_approval();

        let mut no_class = phone.sign(&approval, 2);
        no_class.class = None;
        assert_eq!(device.accept(&approval, &no_class), DeviceOutcome::Aborted, "no class");

        let mut no_key = phone.sign(&approval, 2);
        no_key.public_key_hex = None;
        assert_eq!(device.accept(&approval, &no_key), DeviceOutcome::Aborted, "no key");

        let mut as_test = phone.sign(&approval, 2);
        as_test.class = Some(DeviceClass::Test);
        assert_eq!(
            device.accept(&approval, &as_test),
            DeviceOutcome::Aborted,
            "an unknown key does not get to call itself test"
        );

        let mut as_signet = phone.sign(&approval, 2);
        as_signet.class = Some(DeviceClass::Signet);
        assert_eq!(
            device.accept(&approval, &as_signet),
            DeviceOutcome::Aborted,
            "a Signet does not arrive through the relay"
        );

        // None of the refusals above consumed the counter.
        assert!(matches!(
            device.accept(&approval, &phone.sign(&approval, 2)),
            DeviceOutcome::Approved { .. }
        ));
    }

    #[test]
    fn a_device_id_that_is_not_the_digest_of_its_key_is_refused() {
        let alice = Phone::new(b"alice's phone");
        let other = Phone::new(b"some other key");
        let mut device = device().with_roster(roster_with(vec![alice.enrolled("alice@example.com")]));
        let approval = an_approval();

        // Alice's enrolled id, somebody else's key and signature. The id is
        // in the roster; the key is not the id's key.
        let mut borrowed = other.sign(&approval, 2);
        borrowed.device_id = alice.device_id.clone();
        assert_eq!(device.accept(&approval, &borrowed), DeviceOutcome::Aborted);
    }

    #[test]
    fn the_test_key_may_not_claim_to_be_an_enclave() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/remote-approval.json"
        ))
        .unwrap();
        let mut signed: SignedOutcome = serde_json::from_value(fixture["signature"].clone()).unwrap();
        signed.class = Some(DeviceClass::Enclave);
        let presentation = Presentation {
            render: vec![],
            request_digest: fixture["request_digest"].as_str().unwrap().to_string(),
            request_json: fixture["request_json"].as_str().unwrap().to_string(),
            digest_short: "df47 273e eace".into(),
            severity: countersign_pack::Severity::Critical,
            requester: "claude-code".into(),
            requester_changed: true,
            ttl_ms: 60_000,
        };
        // Even with the test key enrolled as `test`, calling it enclave fails.
        assert_eq!(device().accept(&presentation, &signed), DeviceOutcome::Aborted);
    }

    #[test]
    fn counters_are_kept_per_signer_and_the_old_file_is_the_test_keys() {
        let dir = std::env::temp_dir().join(format!("signetd-relay-counters-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("relay-counter");
        // What a daemon from before phones wrote: one bare integer.
        std::fs::write(&path, "41").unwrap();

        let phone = Phone::new(b"alice's phone");
        let roster = roster_with(vec![phone.enrolled("alice@example.com")]);
        let (_, test_id) = identity();

        let mut first = device().with_roster(Arc::clone(&roster)).with_counter_file(&path);
        assert_eq!(first.highest_counter(&test_id), 41, "the legacy counter is the test key's");
        assert_eq!(first.highest_counter(&phone.device_id), 0, "and nobody else's");

        // The phone's counter 1 is fine even though the test key is at 41.
        let approval = an_approval();
        assert!(matches!(
            first.accept(&approval, &phone.sign(&approval, 1)),
            DeviceOutcome::Approved { .. }
        ));

        // Persisted as a map, and reloaded as one.
        let reloaded = device().with_roster(roster).with_counter_file(&path);
        assert_eq!(reloaded.highest_counter(&test_id), 41);
        assert_eq!(reloaded.highest_counter(&phone.device_id), 1);
    }
}

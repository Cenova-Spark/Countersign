//! The device: what the daemon presents to, and what signs.
//!
//! Real hardware does not exist yet, so the only implementation here is the
//! mock — and the mock is built so that it can never be mistaken for hardware.
//! It signs with the **published** test key from `spec/vectors/test-key.json`,
//! whose private half is in this repository, so every signature it produces is
//! refused by a default verifier.
//!
//! That is the whole safety mechanism, and it is worth being precise about why
//! it is stronger than a flag: a mock accidentally left running in a real
//! deployment fails loudly at verification rather than silently approving. The
//! bypass is not disabled, it is cryptographically incapable.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use countersign_pack::{RenderLine, Severity};
use countersign_verify::encoding::{b64url_encode, hex_encode};
use countersign_verify::{signing_payload, DeviceSignature};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The string the published test key is derived from.
///
/// Identical to `spec/vectors/test-key.json`, so the mock's device id is the
/// one already in the committed vectors.
pub const TEST_KEY_DERIVATION: &str = "countersign-v1 published test key";

/// How long a payload must be on screen before a turn counts.
///
/// A reflexive actuation is the attack this defeats: someone who has built a
/// habit of turning the dial cannot approve something that appeared 80 ms ago,
/// because they cannot have read it. Any new payload restarts the clock, so a
/// request that arrives *while* a hand is moving is not approvable by that
/// movement.
///
/// Scaled by severity, because friction has to be spent where it buys
/// something. A `low` action gets a beat; a `critical` one gets long enough
/// that turning is a decision rather than a reflex.
pub fn arm_delay_ms(severity: Severity) -> u64 {
    match severity {
        Severity::None | Severity::Low => 400,
        Severity::Moderate => 700,
        Severity::High => 1_200,
        Severity::Critical => 2_000,
    }
}

/// How long the actuation itself must be sustained before the detent commits.
///
/// Distinct from [`arm_delay_ms`], and the distinction matters. The arm delay is
/// elapsed time — you could spend it looking away. A hold is continuous
/// engagement: your hand is on the device for the whole of it, which is
/// awkward to do by accident and impossible to do while reaching for something
/// else.
///
/// Firmware enforces this at the detent. A terminal cannot mock a sustained
/// turn, so the reference mock approximates it with the arm delay and says so.
pub fn hold_ms(severity: Severity) -> u64 {
    match severity {
        Severity::None | Severity::Low => 300,
        Severity::Moderate => 800,
        Severity::High => 2_000,
        // Long enough that it cannot be mistaken for anything else you were
        // doing with your hands.
        Severity::Critical => 5_000,
    }
}

/// What the daemon asks the device to show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Presentation {
    /// Ordered display lines. The daemon writes the `label` and `digest` roles;
    /// only `primary` and `advisory` come from a pack.
    pub render: Vec<RenderLine>,
    /// Full request digest, lowercase hex. The device signs over this.
    pub request_digest: String,
    /// The first 12 hex characters, grouped — what the human compares.
    pub digest_short: String,
    /// The effective severity, after the tier floor and the pack.
    #[serde(default = "default_severity")]
    pub severity: Severity,
    /// Who is asking, as a display string. Partly claimed — see the daemon.
    #[serde(default)]
    pub requester: String,
    /// Whether this is a different requester from the last one a human saw.
    ///
    /// When true the device MUST take a separate acknowledgement before it will
    /// accept an approval at all. Defaults to `true` so that a payload which
    /// lost the field in transit asks for more, never less.
    #[serde(default = "default_true")]
    pub requester_changed: bool,
    pub ttl_ms: u64,
}

fn default_true() -> bool {
    true
}

fn default_severity() -> Severity {
    Severity::Critical
}

impl Presentation {
    /// How long before a turn on this payload may count.
    pub fn arm_delay_ms(&self) -> u64 {
        arm_delay_ms(self.severity)
    }

    /// How long the turn must be sustained.
    pub fn hold_ms(&self) -> u64 {
        hold_ms(self.severity)
    }
}

/// What the human did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceOutcome {
    Approved {
        counter: u64,
        device_unix_ms: u64,
        /// base64url unpadded, `r || s`.
        signature: String,
        dwell_ms: Option<u64>,
    },
    /// Declined at the device.
    Aborted,
    /// The TTL elapsed with no actuation.
    Expired,
}

impl DeviceOutcome {
    pub fn into_signature(self, device_id: String) -> Option<DeviceSignature> {
        match self {
            DeviceOutcome::Approved {
                counter,
                device_unix_ms,
                signature,
                dwell_ms,
            } => Some(DeviceSignature {
                device_id,
                counter,
                device_unix_ms,
                signature,
                dwell_ms,
            }),
            _ => None,
        }
    }
}

/// What the daemon knows about the attached device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: String,
    /// `"mock"` today. Hardware will say otherwise.
    pub kind: String,
    /// Whether this device signs with a published test key.
    ///
    /// Surfaced everywhere it can be, because a demo that looks identical to
    /// production is how a demo ends up in production.
    pub is_test_key: bool,
    pub counter: u64,
}

/// Something that can display a payload and sign it.
pub trait Device: Send {
    fn info(&self) -> DeviceInfo;

    /// Show the payload and wait for a human, the TTL, or an abort.
    fn present(&mut self, presentation: &Presentation) -> DeviceOutcome;
}

/// How the mock decides, without a human.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MockAction {
    Approve,
    Abort,
    Expire,
}

/// The mock's behaviour.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockBehaviour {
    /// Approve everything, with no human anywhere.
    ///
    /// For smoke tests only. It makes the daemon's plumbing exercisable without
    /// a person, and it proves nothing about the product — there is no
    /// approval step in it at all.
    Auto,
    /// Consume a scripted list of outcomes in order, then abort.
    ///
    /// The mode §9 of the wire spec asks for: fixture-driven, reproducible, and
    /// not a GUI that could grow into a software approval path.
    Script(Vec<MockAction>),
}

/// A software device signing with the published test key.
pub struct MockDevice {
    key: SigningKey,
    device_id: String,
    behaviour: MockBehaviour,
    cursor: usize,
    counter: u64,
    counter_path: Option<PathBuf>,
}

impl MockDevice {
    pub fn new(behaviour: MockBehaviour) -> Self {
        let key = SigningKey::from_slice(&Sha256::digest(TEST_KEY_DERIVATION.as_bytes()))
            .expect("the derived test scalar is a valid P-256 key");
        let device_id = hex_encode(&Sha256::digest(key.verifying_key().to_sec1_bytes()));
        Self {
            key,
            device_id,
            behaviour,
            cursor: 0,
            counter: 0,
            counter_path: None,
        }
    }

    /// Persist the counter across restarts.
    ///
    /// The real counter lives in a secure element and never resets; a mock that
    /// restarted at zero would make every replay test pass by accident and hide
    /// the defence it is meant to exercise.
    pub fn with_counter_file(mut self, path: &Path) -> Self {
        self.counter = std::fs::read_to_string(path)
            .ok()
            .and_then(|t| t.trim().parse().ok())
            .unwrap_or(0);
        self.counter_path = Some(path.to_path_buf());
        self
    }

    fn next_counter(&mut self) -> u64 {
        self.counter += 1;
        if let Some(path) = &self.counter_path {
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(path, self.counter.to_string());
        }
        self.counter
    }

    fn sign(&mut self, request_digest: &str) -> DeviceOutcome {
        let counter = self.next_counter();
        let device_unix_ms = now_unix_ms();

        let tbs = match signing_payload(request_digest, counter, device_unix_ms) {
            Ok(t) => t,
            // A malformed digest is the daemon's bug, not the human's; refusing
            // is the only safe answer.
            Err(_) => return DeviceOutcome::Aborted,
        };

        DeviceOutcome::Approved {
            counter,
            device_unix_ms,
            signature: b64url_encode(&sign_low_s(&self.key, &tbs).to_bytes()),
            dwell_ms: None,
        }
    }
}

impl Device for MockDevice {
    fn info(&self) -> DeviceInfo {
        DeviceInfo {
            device_id: self.device_id.clone(),
            kind: "mock".into(),
            is_test_key: true,
            counter: self.counter,
        }
    }

    fn present(&mut self, presentation: &Presentation) -> DeviceOutcome {
        let action = match &self.behaviour {
            MockBehaviour::Auto => MockAction::Approve,
            MockBehaviour::Script(actions) => {
                let action = actions.get(self.cursor).cloned();
                self.cursor += 1;
                // Running off the end aborts rather than approving. A fixture
                // that under-specifies must not start waving things through.
                action.unwrap_or(MockAction::Abort)
            }
        };

        match action {
            MockAction::Approve => self.sign(&presentation.request_digest),
            MockAction::Abort => DeviceOutcome::Aborted,
            MockAction::Expire => DeviceOutcome::Expired,
        }
    }
}

/// Sign, normalizing `s` into the low half.
///
/// **Not optional.** RustCrypto emits whichever `s` falls out of the
/// arithmetic, so roughly half its raw signatures are high-S and a conforming
/// verifier rejects those (wire spec §4). Firmware has the same obligation.
pub fn sign_low_s(key: &SigningKey, message: &[u8]) -> Signature {
    let sig: Signature = key.sign(message);
    sig.normalize_s()
}

pub fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use countersign_verify::{encoding::b64url_decode, is_low_s};

    fn presentation(digest: &str) -> Presentation {
        Presentation {
            render: vec![RenderLine::primary("DROP TABLE users")],
            request_digest: digest.into(),
            digest_short: digest[..12].into(),
            severity: Severity::Critical,
            requester: "test".into(),
            requester_changed: false,
            ttl_ms: 60_000,
        }
    }

    fn digest(seed: u8) -> String {
        hex_encode(&Sha256::digest([seed]))
    }

    #[test]
    fn the_mock_uses_the_published_test_key_and_says_so() {
        // Its device id must be the one already in the committed vectors, so a
        // verifier configured to accept test keys accepts this device.
        let info = MockDevice::new(MockBehaviour::Auto).info();
        assert!(info.is_test_key);
        assert_eq!(info.kind, "mock");
        assert_eq!(
            info.device_id,
            "d2eed8cf599a13c5cc39434b64307a75431fc6b95eb7ceeee7ecb94e40023f1a"
        );
    }

    #[test]
    fn every_signature_it_emits_is_low_s() {
        // The probabilistic bug: RustCrypto does not normalize, so about half
        // of unnormalized signatures would be rejected. One is not a test.
        let mut device = MockDevice::new(MockBehaviour::Auto);
        for seed in 0..48u8 {
            let outcome = device.present(&presentation(&digest(seed)));
            let DeviceOutcome::Approved { signature, .. } = outcome else {
                panic!("auto mode approves");
            };
            let raw: [u8; 64] = b64url_decode(&signature).unwrap().try_into().unwrap();
            assert!(is_low_s(&raw), "signature {seed} was not low-S");
        }
    }

    #[test]
    fn the_counter_advances_on_every_approval() {
        let mut device = MockDevice::new(MockBehaviour::Auto);
        let mut seen = Vec::new();
        for seed in 0..5u8 {
            if let DeviceOutcome::Approved { counter, .. } =
                device.present(&presentation(&digest(seed)))
            {
                seen.push(counter);
            }
        }
        assert_eq!(seen, vec![1, 2, 3, 4, 5]);
        assert_eq!(device.info().counter, 5);
    }

    #[test]
    fn the_counter_survives_a_restart() {
        // A mock that restarted at zero would make replay tests pass by
        // accident and hide the defence they exist to exercise.
        let dir = std::env::temp_dir().join(format!("countersign-mock-{}", std::process::id()));
        let path = dir.join("counter");
        let _ = std::fs::remove_file(&path);

        let mut first = MockDevice::new(MockBehaviour::Auto).with_counter_file(&path);
        first.present(&presentation(&digest(1)));
        first.present(&presentation(&digest(2)));
        assert_eq!(first.info().counter, 2);

        let second = MockDevice::new(MockBehaviour::Auto).with_counter_file(&path);
        assert_eq!(second.info().counter, 2, "the counter must not reset");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_script_is_consumed_in_order() {
        let mut device = MockDevice::new(MockBehaviour::Script(vec![
            MockAction::Approve,
            MockAction::Abort,
            MockAction::Expire,
        ]));
        assert!(matches!(
            device.present(&presentation(&digest(1))),
            DeviceOutcome::Approved { .. }
        ));
        assert_eq!(
            device.present(&presentation(&digest(2))),
            DeviceOutcome::Aborted
        );
        assert_eq!(
            device.present(&presentation(&digest(3))),
            DeviceOutcome::Expired
        );
    }

    #[test]
    fn a_script_that_runs_out_aborts_rather_than_approving() {
        // An under-specified fixture must not start waving things through.
        let mut device = MockDevice::new(MockBehaviour::Script(vec![MockAction::Approve]));
        device.present(&presentation(&digest(1)));
        assert_eq!(
            device.present(&presentation(&digest(2))),
            DeviceOutcome::Aborted
        );
    }

    #[test]
    fn an_aborted_presentation_carries_no_signature() {
        let outcome = MockDevice::new(MockBehaviour::Script(vec![MockAction::Abort]))
            .present(&presentation(&digest(1)));
        assert!(outcome.into_signature("d".into()).is_none());
    }

    #[test]
    fn arm_delay_scales_with_how_much_damage_is_on_screen() {
        // Friction has to be spent where it buys something. A trivial action
        // gets a beat; a destructive one gets long enough that turning is a
        // decision rather than a reflex.
        assert!(arm_delay_ms(Severity::Critical) > arm_delay_ms(Severity::High));
        assert!(arm_delay_ms(Severity::High) > arm_delay_ms(Severity::Moderate));
        assert!(arm_delay_ms(Severity::Moderate) > arm_delay_ms(Severity::Low));
        // Even the mildest payload has one, because the whole defence is that
        // no payload is approvable the instant it appears.
        assert!(arm_delay_ms(Severity::None) > 0);
    }

    #[test]
    fn a_presentation_that_forgets_its_severity_arms_slowest() {
        // A deserialized payload missing the field must not become the fastest
        // one to approve.
        let p: Presentation = serde_json::from_str(
            r#"{"render":[],"request_digest":"ab","digest_short":"ab","ttl_ms":1000}"#,
        )
        .unwrap();
        assert_eq!(p.severity, Severity::Critical);
        assert_eq!(p.arm_delay_ms(), arm_delay_ms(Severity::Critical));
    }

    #[test]
    fn a_malformed_digest_aborts_instead_of_signing_something_else() {
        let mut device = MockDevice::new(MockBehaviour::Auto);
        let mut bad = presentation(&digest(1));
        bad.request_digest = "not-a-digest".into();
        assert_eq!(device.present(&bad), DeviceOutcome::Aborted);
    }
}

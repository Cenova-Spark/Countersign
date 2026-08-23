//! Verification: registry, policy, replay defence, and the execution binding.
//!
//! Nothing here talks to a daemon, a USB device, or a network. That is a
//! deliberate constraint rather than an accident of scope — it is what lets a
//! wire proxy on a different host, a CI runner, or a Vault plugin verify against
//! a registered public key. Advisory approval (the agent asks, then decides for
//! itself whether to honour the answer) is where a deployment starts; enforcing
//! at a chokepoint the agent cannot go around is the only posture where the
//! security claim actually holds, and it needs exactly this crate and nothing
//! else.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use crate::bundle::{ApprovalEnvelope, Decision, DeviceSignature};
use crate::encoding::{b64url_decode, hex_encode, EncodingError};
use crate::enrollment::{DeviceStatus, EnrollmentError, EnrollmentRecord, Operator, Roster};
use crate::jcs::JcsError;
use crate::request::digest_of_json;
use crate::store::StoreError;

/// The domain separator prefixed to every signed payload, so a Countersign
/// signature can never be replayed as a signature over some other protocol's
/// bytes that happen to share a suffix.
const DOMAIN: &[u8] = b"countersign-v1\0";

/// `n/2` for P-256, big-endian. A signature with `s` above this is high-S.
const HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
];

// ---------------------------------------------------------------------------
// Crypto backend
// ---------------------------------------------------------------------------

/// The one cryptographic operation this crate needs.
///
/// It is a trait so the signature backend is swappable: a proxy that already
/// links a vetted P-256 implementation should not be made to carry a second
/// one, and a FIPS deployment may be required to use its own.
pub trait SignatureBackend {
    /// Verify an ECDSA-P256-SHA-256 signature.
    ///
    /// `public_key` is SEC1 uncompressed (65 bytes, `0x04 || x || y`).
    /// `signature` is `r || s`, 32 bytes each. SHA-256 is applied to `message`
    /// inside the operation — this is the ordinary primitive, not a prehash
    /// variant.
    fn verify_p256_sha256(&self, public_key: &[u8], message: &[u8], signature: &[u8; 64]) -> bool;
}

#[cfg(feature = "ecdsa-p256")]
mod rustcrypto {
    use super::SignatureBackend;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    /// The default backend, built on RustCrypto's `p256`.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct RustCryptoBackend;

    impl SignatureBackend for RustCryptoBackend {
        fn verify_p256_sha256(&self, public_key: &[u8], msg: &[u8], sig: &[u8; 64]) -> bool {
            let Ok(key) = VerifyingKey::from_sec1_bytes(public_key) else {
                return false;
            };
            let Ok(signature) = Signature::from_slice(sig) else {
                return false;
            };
            key.verify(msg, &signature).is_ok()
        }
    }
}

#[cfg(feature = "ecdsa-p256")]
pub use rustcrypto::RustCryptoBackend;

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// An enrolled device's public key, and who it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledDevice {
    /// Lowercase hex SHA-256 of `public_key`.
    pub device_id: String,
    /// SEC1 uncompressed, 65 bytes.
    pub public_key: Vec<u8>,
    /// Whether this is a **published** test key — one whose private half is in
    /// a public repository. See [`VerifyPolicy::accept_test_keys`].
    pub is_test_key: bool,
    /// The human this device belongs to.
    ///
    /// `None` means the verifier knows a key but not an owner, which is fine
    /// for authorizing and useless for auditing — "who approved this" has no
    /// answer beyond a hex string.
    pub operator: Option<Operator>,
    /// Active, or revoked from some instant.
    pub status: DeviceStatus,
    /// Operator-facing name. Never used in a decision.
    pub label: Option<String>,
}

impl EnrolledDevice {
    /// Enrol a production key. `device_id` is derived, never supplied — a
    /// caller-chosen id would let one key be registered under another's name.
    pub fn new(public_key: Vec<u8>) -> Self {
        let device_id = hex_encode(&Sha256::digest(&public_key));
        Self {
            device_id,
            public_key,
            is_test_key: false,
            operator: None,
            status: DeviceStatus::Active,
            label: None,
        }
    }

    /// Build from an enrollment record, carrying its owner and revocation
    /// status across.
    pub fn from_record(record: &EnrollmentRecord) -> Result<Self, EnrollmentError> {
        record.check_device_id()?;
        Ok(Self {
            device_id: record.device_id.clone(),
            public_key: record.public_key()?,
            is_test_key: record.is_test_key,
            operator: Some(record.operator.clone()),
            status: record.status.clone(),
            label: record.operator.display.clone(),
        })
    }

    pub fn with_operator(mut self, operator: Operator) -> Self {
        self.operator = Some(operator);
        self
    }

    /// Enrol a key as a known test key. Rejected by default at verification.
    pub fn test_key(public_key: Vec<u8>) -> Self {
        Self {
            is_test_key: true,
            ..Self::new(public_key)
        }
    }

    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

/// The set of keys a verifier will accept.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    devices: HashMap<String, EnrolledDevice>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn enrol(&mut self, device: EnrolledDevice) -> &mut Self {
        self.devices.insert(device.device_id.clone(), device);
        self
    }

    /// Build a registry from a roster that has already been verified and
    /// rollback-checked (see `enrollment::accept_roster`).
    ///
    /// Takes a `Roster` rather than a `SignedRoster` on purpose: this function
    /// cannot check a signature, and accepting the signed form would invite a
    /// caller to think it had.
    pub fn from_roster(roster: &Roster) -> Result<Self, EnrollmentError> {
        let mut registry = Self::new();
        for record in &roster.records {
            registry.enrol(EnrolledDevice::from_record(record)?);
        }
        Ok(registry)
    }

    pub fn get(&self, device_id: &str) -> Option<&EnrolledDevice> {
        self.devices.get(device_id)
    }

    /// Every device enrolled to one person.
    ///
    /// People legitimately hold more than one — a desk device and a travel
    /// device, or a replacement issued after a loss. Anything that acts on a
    /// *person* rather than a device (offboarding, an access review, "what does
    /// Alice hold?") has to go through here, because revoking the one device
    /// you happened to know about is not revoking the human.
    pub fn devices_for(&self, subject: &str) -> Vec<&EnrolledDevice> {
        let mut found: Vec<&EnrolledDevice> = self
            .devices
            .values()
            .filter(|d| d.operator.as_ref().is_some_and(|o| o.subject == subject))
            .collect();
        // HashMap order is not stable; an access review that reordered itself
        // between runs would be unreadable.
        found.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        found
    }

    /// Every device this registry knows, in a stable order.
    pub fn iter(&self) -> impl Iterator<Item = &EnrolledDevice> {
        let mut all: Vec<&EnrolledDevice> = self.devices.values().collect();
        all.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        all.into_iter()
    }

    pub fn len(&self) -> usize {
        self.devices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/// Why this verifier is checking — which decides how a revoked device is read.
///
/// These are genuinely different questions and conflating them costs one of two
/// things: either revoking a lost device fails to stop it, or it silently
/// invalidates years of legitimate approvals in the audit trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acceptance {
    /// Authorizing something now. A revoked device is refused, full stop.
    Now,
    /// Auditing a past approval. A device revoked *after* this instant still
    /// counts, because it was trusted when it signed.
    AsOf(u64),
}

/// What this verifier requires before it believes an approval.
#[derive(Debug, Clone)]
pub struct VerifyPolicy {
    /// How many distinct enrolled devices must sign. v1 devices produce one
    /// signature each; a 2-of-2 policy means two humans and two devices.
    pub required_signatures: usize,

    /// Whether signatures from **published test keys** count.
    ///
    /// Defaults to `false`, and that default is the safety mechanism that makes
    /// a software mock acceptable at all. The mock signs with a keypair whose
    /// private half is in the repository, so a mock accidentally left enabled in
    /// a real deployment fails loudly here instead of silently passing. The
    /// bypass is not disabled by a flag — it is cryptographically incapable of
    /// producing a production-valid approval.
    pub accept_test_keys: bool,

    /// Whether the threshold counts distinct **people** rather than distinct
    /// devices.
    ///
    /// Set this for any genuine dual-control rule. `required_signatures: 2`
    /// alone means two devices, and one person who owns two Signets satisfies
    /// it on their own — which is exactly the control the rule existed to
    /// prevent. Counting operators requires the verifier to know who each
    /// device belongs to, so a device with no enrollment record cannot count.
    pub require_distinct_operators: bool,

    /// Whether this verifier is authorizing an action or auditing history.
    ///
    /// [`Acceptance::Now`] by default, which refuses revoked devices outright.
    pub acceptance: Acceptance,

    /// Optional freshness window on `device_unix_ms`.
    ///
    /// `None` by default, because the counter is the authoritative replay
    /// defence and it survives a clock reset. A device with a wrong clock is a
    /// support ticket; a device whose counter went backwards is a compromised
    /// device. Set this only where you control the clocks.
    pub max_clock_skew_ms: Option<u64>,
}

impl Default for VerifyPolicy {
    fn default() -> Self {
        Self {
            required_signatures: 1,
            accept_test_keys: false,
            require_distinct_operators: false,
            acceptance: Acceptance::Now,
            max_clock_skew_ms: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Replay defence
// ---------------------------------------------------------------------------

/// Per-device high-water marks for the monotonic counter.
pub trait CounterStore {
    fn highest(&self, device_id: &str) -> Option<u64>;

    /// Remember that `counter` has been used, durably enough that a restart
    /// will not forget it.
    ///
    /// Returns a `Result`, and verification **fails** when it errors. That is
    /// deliberate: accepting an approval you cannot remember is strictly worse
    /// than refusing it, so a full disk must produce a refusal rather than a
    /// silent replay window.
    fn record(&mut self, device_id: &str, counter: u64) -> Result<(), StoreError>;
}

/// An in-memory [`CounterStore`].
///
/// Fine for a single long-lived process. A verifier that restarts — a CI job, a
/// serverless function — needs a durable store, or it accepts a replayed
/// approval once per restart.
#[derive(Debug, Clone, Default)]
pub struct MemoryCounters(HashMap<String, u64>);

impl MemoryCounters {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CounterStore for MemoryCounters {
    fn highest(&self, device_id: &str) -> Option<u64> {
        self.0.get(device_id).copied()
    }
    fn record(&mut self, device_id: &str, counter: u64) -> Result<(), StoreError> {
        let e = self.0.entry(device_id.to_string()).or_insert(counter);
        *e = (*e).max(counter);
        Ok(())
    }
}

/// A [`CounterStore`] that never remembers anything.
///
/// Named for what it costs, not for what it does. Use it only where replay is
/// prevented some other way — a nonce store, or a single-shot process that
/// exits after one verification.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoCounterStore;

impl CounterStore for NoCounterStore {
    fn highest(&self, _: &str) -> Option<u64> {
        None
    }
    fn record(&mut self, _: &str, _: u64) -> Result<(), StoreError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The bundle did not say `approved`.
    NotApproved(Decision),
    /// The bundle's digest did not match the request it travelled with.
    DigestMismatch {
        claimed: String,
        computed: String,
    },
    /// The approved statement is not the statement about to run.
    StatementMismatch,
    /// The approval was for a different target.
    TargetMismatch {
        approved: String,
        actual: String,
    },
    /// The approved action is not the action about to happen.
    ActionMismatch {
        approved: String,
        actual: String,
    },
    /// A signing device is not enrolled here.
    UnknownDevice(String),
    /// A signature came from a published test key and policy forbids those.
    TestKeyRejected(String),
    /// The signing device has been revoked.
    DeviceRevoked {
        device_id: String,
        status: DeviceStatus,
    },
    /// ECDSA verification failed.
    BadSignature(String),
    /// `s > n/2`. See [`VerifyError::HighS`] handling in `check_low_s`.
    HighS(String),
    /// A counter did not advance — a replay, or a rolled-back device.
    CounterRegression {
        device_id: String,
        seen: u64,
        highest: u64,
    },
    /// The device clock was outside the configured window.
    Stale {
        device_id: String,
        skew_ms: u64,
    },
    /// Fewer valid signatures than the policy requires.
    Threshold {
        got: usize,
        required: usize,
    },
    /// Fewer distinct *people* than a dual-control policy requires.
    OperatorThreshold {
        got: usize,
        required: usize,
    },
    /// A dual-control policy is in force and this verifier does not know who
    /// owns the signing device, so it cannot tell two people from one.
    UnknownOperator(String),
    /// The same device signed twice; it counts once.
    DuplicateDevice(String),
    Encoding(EncodingError),
    Jcs(JcsError),
    /// The replay defence could not be persisted, so the approval was refused.
    Store(StoreError),
    Malformed(String),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use VerifyError::*;
        match self {
            NotApproved(d) => write!(f, "not approved: {}", d.as_str()),
            DigestMismatch { claimed, computed } => write!(
                f,
                "bundle digest {claimed} does not cover this request (computed {computed})"
            ),
            StatementMismatch => f.write_str("the approved statement is not the one about to run"),
            TargetMismatch { approved, actual } => {
                write!(f, "approval was for target {approved}, not {actual}")
            }
            ActionMismatch { approved, actual } => {
                write!(f, "approval was for action {approved}, not {actual}")
            }
            UnknownDevice(id) => write!(f, "device {id} is not enrolled"),
            DeviceRevoked { device_id, status } => match status {
                DeviceStatus::Revoked {
                    reason: Some(why), ..
                } => {
                    write!(f, "device {device_id} was revoked: {why}")
                }
                _ => write!(f, "device {device_id} was revoked"),
            },
            TestKeyRejected(id) => write!(
                f,
                "device {id} is a published test key; production verification refuses these"
            ),
            BadSignature(id) => write!(f, "signature from {id} did not verify"),
            HighS(id) => write!(f, "signature from {id} is not low-S"),
            CounterRegression {
                device_id,
                seen,
                highest,
            } => write!(
                f,
                "device {device_id} counter {seen} is not above the highest seen ({highest})"
            ),
            Stale { device_id, skew_ms } => {
                write!(
                    f,
                    "device {device_id} clock is {skew_ms} ms outside the window"
                )
            }
            Threshold { got, required } => {
                write!(f, "{got} valid signature(s), policy requires {required}")
            }
            OperatorThreshold { got, required } => write!(
                f,
                "signatures came from {got} distinct person(s), policy requires {required}"
            ),
            UnknownOperator(id) => write!(
                f,
                "device {id} has no enrolled operator, so dual control cannot be established"
            ),
            DuplicateDevice(id) => write!(f, "device {id} signed more than once"),
            Encoding(e) => write!(f, "{e}"),
            Jcs(e) => write!(f, "{e}"),
            Store(e) => write!(
                f,
                "refused: the replay defence could not be recorded ({e}). An approval that \
                 cannot be remembered could be replayed after a restart"
            ),
            Malformed(m) => write!(f, "malformed: {m}"),
        }
    }
}

impl std::error::Error for VerifyError {}

impl From<EncodingError> for VerifyError {
    fn from(e: EncodingError) -> Self {
        VerifyError::Encoding(e)
    }
}

impl From<JcsError> for VerifyError {
    fn from(e: JcsError) -> Self {
        VerifyError::Jcs(e)
    }
}

/// A successful verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub request_digest: String,
    /// The signatures that counted, and who produced them.
    pub signers: Vec<VerifiedSigner>,
}

impl Verified {
    /// Just the device ids, in order.
    pub fn device_ids(&self) -> Vec<&str> {
        self.signers.iter().map(|s| s.device_id.as_str()).collect()
    }

    /// The human subjects behind the signatures, skipping any device whose
    /// owner this verifier does not know.
    ///
    /// This is the answer to "who approved this, and can you prove it" — the
    /// question a compliance owner actually asks. A verifier holding keys but
    /// no enrollment records can authorize all day and still not answer it.
    pub fn operators(&self) -> Vec<&str> {
        self.signers
            .iter()
            .filter_map(|s| s.operator.as_ref())
            .map(|o| o.subject.as_str())
            .collect()
    }
}

/// One signature that counted toward the threshold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSigner {
    pub device_id: String,
    /// The human the device is enrolled to, when the verifier knows.
    pub operator: Option<Operator>,
    pub counter: u64,
    pub device_unix_ms: u64,
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/// What the caller is about to do, and therefore what the approval must cover.
#[derive(Debug, Clone)]
pub struct Execution<'a> {
    /// The exact statement about to be executed.
    pub statement: &'a str,
    /// The fingerprint of the connection it is about to run on.
    pub uri_fingerprint: &'a str,
    /// The action namespace being performed, if the caller wants it checked.
    pub action: Option<&'a str>,
}

/// Verify that an approval covers **this** execution.
///
/// This is the function a proxy calls. The three bindings it adds over
/// [`verify_bundle`] are the ones that make a countersignature mean anything at
/// the point of use:
///
/// * the statement about to run is the statement that was displayed,
/// * on the target that was displayed,
/// * for the action that was approved.
///
/// Without them a verifier confirms only that *some* approval exists, which an
/// agent holding one valid approval can reuse for every subsequent statement.
pub fn verify_for_execution(
    envelope: &ApprovalEnvelope,
    execution: &Execution<'_>,
    registry: &Registry,
    policy: &VerifyPolicy,
    counters: &mut dyn CounterStore,
    backend: &dyn SignatureBackend,
    now_unix_ms: Option<u64>,
) -> Result<Verified, VerifyError> {
    let request = envelope
        .request()
        .map_err(|e| VerifyError::Malformed(e.to_string()))?;

    // Byte-for-byte. A statement that differs by a character is a different
    // statement, and normalizing before comparison here would be the whole
    // vulnerability: `DELETE FROM t WHERE id=1` approved, `DELETE FROM t` run.
    if request.statement != execution.statement {
        return Err(VerifyError::StatementMismatch);
    }

    if request.target.uri_fingerprint != execution.uri_fingerprint {
        return Err(VerifyError::TargetMismatch {
            approved: request.target.uri_fingerprint.clone(),
            actual: execution.uri_fingerprint.to_string(),
        });
    }

    if let Some(action) = execution.action {
        if request.action != action {
            return Err(VerifyError::ActionMismatch {
                approved: request.action.clone(),
                actual: action.to_string(),
            });
        }
    }

    verify_bundle(envelope, registry, policy, counters, backend, now_unix_ms)
}

/// Verify a bundle's signatures against the request it travels with.
///
/// Checks the cryptography and the replay defence. It does **not** check that
/// the approval matches what you are about to do — use [`verify_for_execution`]
/// for that.
pub fn verify_bundle(
    envelope: &ApprovalEnvelope,
    registry: &Registry,
    policy: &VerifyPolicy,
    counters: &mut dyn CounterStore,
    backend: &dyn SignatureBackend,
    now_unix_ms: Option<u64>,
) -> Result<Verified, VerifyError> {
    let bundle = &envelope.bundle;

    if bundle.decision != Decision::Approved {
        return Err(VerifyError::NotApproved(bundle.decision));
    }

    // Recompute from the request as received, never from a re-serialization.
    let computed = digest_of_json(&envelope.request_json)?;
    if computed != bundle.request_digest {
        return Err(VerifyError::DigestMismatch {
            claimed: bundle.request_digest.clone(),
            computed,
        });
    }

    verify_signatures(
        &computed,
        &bundle.signatures,
        registry,
        policy,
        counters,
        backend,
        now_unix_ms,
    )
}

/// Verify signatures against a `request_digest` alone.
///
/// The statement is not needed and is not accepted. That is deliberate and it is
/// what lets an audit trail be cryptographically checkable while carrying no
/// query text at all: the signature covers the digest, and the digest covers the
/// statement, so an auditor holding only digests can still prove every approval
/// is genuine and name who gave it.
///
/// Use [`verify_bundle`] when you do have the request — it additionally checks
/// that the digest covers it, which this cannot.
#[allow(clippy::too_many_arguments)]
pub fn verify_signatures(
    request_digest: &str,
    signatures: &[DeviceSignature],
    registry: &Registry,
    policy: &VerifyPolicy,
    counters: &mut dyn CounterStore,
    backend: &dyn SignatureBackend,
    now_unix_ms: Option<u64>,
) -> Result<Verified, VerifyError> {
    let computed = request_digest.to_string();
    let bundle_signatures = signatures;

    let mut counted: Vec<VerifiedSigner> = Vec::new();

    for sig in bundle_signatures {
        if counted.iter().any(|s| s.device_id == sig.device_id) {
            return Err(VerifyError::DuplicateDevice(sig.device_id.clone()));
        }

        let device = registry
            .get(&sig.device_id)
            .ok_or_else(|| VerifyError::UnknownDevice(sig.device_id.clone()))?;

        if device.is_test_key && !policy.accept_test_keys {
            return Err(VerifyError::TestKeyRejected(sig.device_id.clone()));
        }

        // Revocation is checked before the cryptography, because a revoked
        // device's signature is perfectly valid — that is exactly the problem.
        let permitted = match policy.acceptance {
            Acceptance::Now => device.status.is_active(),
            Acceptance::AsOf(t) => device.status.was_valid_at(t, Some(sig.counter)),
        };
        if !permitted {
            return Err(VerifyError::DeviceRevoked {
                device_id: sig.device_id.clone(),
                status: device.status.clone(),
            });
        }

        let raw = b64url_decode(&sig.signature)?;
        let raw: [u8; 64] = raw
            .try_into()
            .map_err(|_| VerifyError::BadSignature(sig.device_id.clone()))?;

        check_low_s(&raw, &sig.device_id)?;

        let tbs = signing_payload(&computed, sig.counter, sig.device_unix_ms)?;
        if !backend.verify_p256_sha256(&device.public_key, &tbs, &raw) {
            return Err(VerifyError::BadSignature(sig.device_id.clone()));
        }

        if let Some(highest) = counters.highest(&sig.device_id) {
            if sig.counter <= highest {
                return Err(VerifyError::CounterRegression {
                    device_id: sig.device_id.clone(),
                    seen: sig.counter,
                    highest,
                });
            }
        }

        if let (Some(window), Some(now)) = (policy.max_clock_skew_ms, now_unix_ms) {
            let skew = now.abs_diff(sig.device_unix_ms);
            if skew > window {
                return Err(VerifyError::Stale {
                    device_id: sig.device_id.clone(),
                    skew_ms: skew,
                });
            }
        }

        counted.push(VerifiedSigner {
            device_id: sig.device_id.clone(),
            operator: device.operator.clone(),
            counter: sig.counter,
            device_unix_ms: sig.device_unix_ms,
        });
    }

    if policy.require_distinct_operators {
        let mut subjects: Vec<&str> = Vec::new();
        for signer in &counted {
            let subject = signer
                .operator
                .as_ref()
                .map(|o| o.subject.as_str())
                .ok_or_else(|| VerifyError::UnknownOperator(signer.device_id.clone()))?;
            if !subjects.contains(&subject) {
                subjects.push(subject);
            }
        }
        if subjects.len() < policy.required_signatures {
            return Err(VerifyError::OperatorThreshold {
                got: subjects.len(),
                required: policy.required_signatures,
            });
        }
    } else if counted.len() < policy.required_signatures {
        return Err(VerifyError::Threshold {
            got: counted.len(),
            required: policy.required_signatures,
        });
    }

    // Only record once everything has passed, so a rejected bundle cannot burn
    // a counter value and lock out the approval that follows it.
    //
    // And if the record cannot be made durable, this fails. An approval we
    // could not remember is one that could be replayed after the next restart,
    // so the correct answer to a failing disk is a refusal.
    for sig in bundle_signatures {
        counters
            .record(&sig.device_id, sig.counter)
            .map_err(VerifyError::Store)?;
    }

    Ok(Verified {
        request_digest: computed,
        signers: counted,
    })
}

/// Build the bytes a device signs: domain separator, digest, counter, time.
///
/// The counter and timestamp are inside the signature rather than beside it so
/// that neither can be edited after the fact by anyone holding the bundle.
pub fn signing_payload(
    request_digest_hex: &str,
    counter: u64,
    device_unix_ms: u64,
) -> Result<Vec<u8>, VerifyError> {
    let digest = crate::encoding::hex_decode(request_digest_hex)?;
    if digest.len() != 32 {
        return Err(VerifyError::Malformed(format!(
            "request_digest is {} bytes, expected 32",
            digest.len()
        )));
    }
    let mut out = Vec::with_capacity(DOMAIN.len() + 32 + 16);
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(&digest);
    out.extend_from_slice(&counter.to_be_bytes());
    out.extend_from_slice(&device_unix_ms.to_be_bytes());
    Ok(out)
}

/// Whether a signature is well-formed and low-S.
///
/// Public because every signature path in this protocol needs it — approvals,
/// enrollment proofs, rosters and audit checkpoints — and three of the four
/// originally forgot. One predicate, one place to get it right.
pub fn is_low_s(signature: &[u8; 64]) -> bool {
    let (r, s) = signature.split_at(32);
    if r.iter().all(|b| *b == 0) || s.iter().all(|b| *b == 0) {
        return false;
    }
    s <= &HALF_ORDER[..]
}

/// Reject `s > n/2`, and reject a zero `r` or `s`.
///
/// ECDSA is malleable: for any valid `(r, s)`, `(r, n - s)` verifies just as
/// well. These signatures are retained as evidence, so without this rule a third
/// party can mint a second, different, equally valid signature over the same
/// approval — which is a gift to anyone arguing about what the audit log shows.
fn check_low_s(sig: &[u8; 64], device_id: &str) -> Result<(), VerifyError> {
    let (r, s) = sig.split_at(32);
    if r.iter().all(|b| *b == 0) || s.iter().all(|b| *b == 0) {
        return Err(VerifyError::BadSignature(device_id.to_string()));
    }
    if s > &HALF_ORDER[..] {
        return Err(VerifyError::HighS(device_id.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{Bundle, DeviceSignature};

    /// A backend that says yes to everything, so the non-cryptographic checks —
    /// which is most of this file — can be tested without a signing key.
    struct AlwaysValid;
    impl SignatureBackend for AlwaysValid {
        fn verify_p256_sha256(&self, _: &[u8], _: &[u8], _: &[u8; 64]) -> bool {
            true
        }
    }

    struct NeverValid;
    impl SignatureBackend for NeverValid {
        fn verify_p256_sha256(&self, _: &[u8], _: &[u8], _: &[u8; 64]) -> bool {
            false
        }
    }

    const REQ: &str = r#"{"action":"sql.execute","nonce":"n","requester":{"id":"a","instance":"b"},"statement":"DROP TABLE users;","target":{"kind":"database","uri_fingerprint":"9f2c"},"ttl_ms":60000,"v":1}"#;

    fn low_s_sig() -> String {
        let mut raw = [0u8; 64];
        raw[31] = 1; // r = 1
        raw[63] = 1; // s = 1, comfortably low
        crate::encoding::b64url_encode(&raw)
    }

    fn device(id_seed: u8) -> EnrolledDevice {
        let mut key = vec![0x04u8; 65];
        key[64] = id_seed;
        EnrolledDevice::new(key)
    }

    fn envelope(sigs: Vec<DeviceSignature>) -> ApprovalEnvelope {
        ApprovalEnvelope {
            request_json: REQ.to_string(),
            bundle: Bundle {
                v: 1,
                decision: Decision::Approved,
                request_digest: digest_of_json(REQ).unwrap(),
                signatures: sigs,
            },
        }
    }

    fn sig_for(d: &EnrolledDevice, counter: u64) -> DeviceSignature {
        DeviceSignature {
            device_id: d.device_id.clone(),
            counter,
            device_unix_ms: 1_755_859_200_123,
            signature: low_s_sig(),
            dwell_ms: Some(2140),
        }
    }

    fn registry_with(devices: &[&EnrolledDevice]) -> Registry {
        let mut r = Registry::new();
        for d in devices {
            r.enrol((*d).clone());
        }
        r
    }

    #[test]
    fn a_well_formed_approval_verifies() {
        let d = device(1);
        let env = envelope(vec![sig_for(&d, 5)]);
        let got = verify_bundle(
            &env,
            &registry_with(&[&d]),
            &VerifyPolicy::default(),
            &mut MemoryCounters::new(),
            &AlwaysValid,
            None,
        )
        .unwrap();
        assert_eq!(got.device_ids(), vec![d.device_id.as_str()]);
    }

    #[test]
    fn a_tampered_statement_is_caught_by_the_digest() {
        // The bundle is authentic; the request travelling with it was edited.
        // This is the check that makes content binding real.
        let d = device(1);
        let mut env = envelope(vec![sig_for(&d, 5)]);
        env.request_json = env
            .request_json
            .replace("DROP TABLE users;", "DROP TABLE orders;");
        let err = verify_bundle(
            &env,
            &registry_with(&[&d]),
            &VerifyPolicy::default(),
            &mut MemoryCounters::new(),
            &AlwaysValid,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(err, VerifyError::DigestMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn an_approval_cannot_be_reused_for_a_different_statement() {
        // The agent holds one genuine approval and tries to run something else
        // under it. Without the execution binding this succeeds.
        let d = device(1);
        let env = envelope(vec![sig_for(&d, 5)]);
        let err = verify_for_execution(
            &env,
            &Execution {
                statement: "DROP TABLE orders;",
                uri_fingerprint: "9f2c",
                action: None,
            },
            &registry_with(&[&d]),
            &VerifyPolicy::default(),
            &mut MemoryCounters::new(),
            &AlwaysValid,
            None,
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::StatementMismatch);
    }

    #[test]
    fn an_approval_cannot_be_replayed_against_a_different_database() {
        // Approved on staging, executed on production.
        let d = device(1);
        let env = envelope(vec![sig_for(&d, 5)]);
        let err = verify_for_execution(
            &env,
            &Execution {
                statement: "DROP TABLE users;",
                uri_fingerprint: "0000",
                action: None,
            },
            &registry_with(&[&d]),
            &VerifyPolicy::default(),
            &mut MemoryCounters::new(),
            &AlwaysValid,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(err, VerifyError::TargetMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn the_matching_execution_passes_every_binding() {
        let d = device(1);
        let env = envelope(vec![sig_for(&d, 5)]);
        assert!(verify_for_execution(
            &env,
            &Execution {
                statement: "DROP TABLE users;",
                uri_fingerprint: "9f2c",
                action: Some("sql.execute"),
            },
            &registry_with(&[&d]),
            &VerifyPolicy::default(),
            &mut MemoryCounters::new(),
            &AlwaysValid,
            None,
        )
        .is_ok());
    }

    #[test]
    fn test_keys_are_refused_by_default_and_accepted_only_on_purpose() {
        let mut d = device(1);
        d.is_test_key = true;
        let env = envelope(vec![sig_for(&d, 5)]);
        let reg = registry_with(&[&d]);

        let err = verify_bundle(
            &env,
            &reg,
            &VerifyPolicy::default(),
            &mut MemoryCounters::new(),
            &AlwaysValid,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(err, VerifyError::TestKeyRejected(_)),
            "got {err:?}"
        );

        let permissive = VerifyPolicy {
            accept_test_keys: true,
            ..Default::default()
        };
        assert!(verify_bundle(
            &env,
            &reg,
            &permissive,
            &mut MemoryCounters::new(),
            &AlwaysValid,
            None
        )
        .is_ok());
    }

    #[test]
    fn an_approval_whose_counter_cannot_be_persisted_is_refused() {
        // The failure a fallible `record` exists to surface. Without it a full
        // disk would return Ok for an approval nothing could remember, opening
        // a replay window that lasts until the next restart.
        struct FailingStore;
        impl CounterStore for FailingStore {
            fn highest(&self, _: &str) -> Option<u64> {
                None
            }
            fn record(&mut self, _: &str, _: u64) -> Result<(), StoreError> {
                Err(StoreError::Io(
                    "/counters".into(),
                    "no space left on device".into(),
                ))
            }
        }

        let d = device(1);
        let err = verify_bundle(
            &envelope(vec![sig_for(&d, 5)]),
            &registry_with(&[&d]),
            &VerifyPolicy::default(),
            &mut FailingStore,
            &AlwaysValid,
            None,
        )
        .unwrap_err();

        assert!(matches!(err, VerifyError::Store(_)), "got {err:?}");
        assert!(
            err.to_string().contains("could be replayed"),
            "the message should say why this is a refusal: {err}"
        );
    }

    #[test]
    fn a_replayed_bundle_is_refused_on_the_second_presentation() {
        let d = device(1);
        let env = envelope(vec![sig_for(&d, 5)]);
        let reg = registry_with(&[&d]);
        let mut counters = MemoryCounters::new();

        assert!(verify_bundle(
            &env,
            &reg,
            &VerifyPolicy::default(),
            &mut counters,
            &AlwaysValid,
            None
        )
        .is_ok());

        let err = verify_bundle(
            &env,
            &reg,
            &VerifyPolicy::default(),
            &mut counters,
            &AlwaysValid,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(err, VerifyError::CounterRegression { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn a_rejected_bundle_does_not_burn_a_counter_value() {
        // Otherwise a bad bundle at counter 9 would lock out the genuine
        // approval that arrives at counter 9 — a denial of service anyone
        // holding a forged bundle could trigger.
        let d = device(1);
        let env = envelope(vec![sig_for(&d, 9)]);
        let reg = registry_with(&[&d]);
        let mut counters = MemoryCounters::new();

        assert!(verify_bundle(
            &env,
            &reg,
            &VerifyPolicy::default(),
            &mut counters,
            &NeverValid,
            None
        )
        .is_err());
        assert_eq!(
            counters.highest(&d.device_id),
            None,
            "nothing should have been recorded"
        );

        assert!(verify_bundle(
            &env,
            &reg,
            &VerifyPolicy::default(),
            &mut counters,
            &AlwaysValid,
            None
        )
        .is_ok());
    }

    #[test]
    fn high_s_signatures_are_refused() {
        let d = device(1);
        let mut raw = [0u8; 64];
        raw[31] = 1;
        raw[32..].copy_from_slice(&[0xff; 32]); // s well above n/2
        let mut s = sig_for(&d, 5);
        s.signature = crate::encoding::b64url_encode(&raw);

        let err = verify_bundle(
            &envelope(vec![s]),
            &registry_with(&[&d]),
            &VerifyPolicy::default(),
            &mut MemoryCounters::new(),
            &AlwaysValid,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, VerifyError::HighS(_)), "got {err:?}");
    }

    #[test]
    fn the_low_s_boundary_is_inclusive() {
        // s == n/2 exactly is low-S and must pass; one above must not.
        let d = device(1);
        let mut at = [0u8; 64];
        at[31] = 1;
        at[32..].copy_from_slice(&HALF_ORDER);
        assert!(check_low_s(&at, "d").is_ok());

        let mut over = at;
        over[63] += 1;
        assert!(matches!(
            check_low_s(&over, "d"),
            Err(VerifyError::HighS(_))
        ));
        let _ = d;
    }

    #[test]
    fn a_zero_component_is_not_a_signature() {
        assert!(check_low_s(&[0u8; 64], "d").is_err());
    }

    #[test]
    fn an_unenrolled_device_is_refused() {
        let signer = device(1);
        let other = device(2);
        let err = verify_bundle(
            &envelope(vec![sig_for(&signer, 5)]),
            &registry_with(&[&other]),
            &VerifyPolicy::default(),
            &mut MemoryCounters::new(),
            &AlwaysValid,
            None,
        )
        .unwrap_err();
        assert!(matches!(err, VerifyError::UnknownDevice(_)), "got {err:?}");
    }

    #[test]
    fn a_revoked_device_cannot_authorize_anything_now() {
        // The point of revocation: the signature is still cryptographically
        // perfect, and that is exactly the problem.
        let mut d = device(1);
        d.status = DeviceStatus::Revoked {
            at_unix_ms: 1_000,
            at_counter: None,
            reason: Some("laptop bag on a train".into()),
        };
        let err = verify_bundle(
            &envelope(vec![sig_for(&d, 5)]),
            &registry_with(&[&d]),
            &VerifyPolicy::default(),
            &mut MemoryCounters::new(),
            &AlwaysValid,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(err, VerifyError::DeviceRevoked { .. }),
            "got {err:?}"
        );
        assert!(
            err.to_string().contains("train"),
            "the reason should reach the operator"
        );
    }

    #[test]
    fn auditing_a_past_approval_still_accepts_a_since_revoked_device() {
        // Otherwise revoking one lost device silently invalidates every
        // approval its owner ever gave, which is most of the value of keeping
        // them.
        let mut d = device(1);
        d.status = DeviceStatus::Revoked {
            at_unix_ms: 2_000,
            at_counter: None,
            reason: None,
        };
        let env = envelope(vec![sig_for(&d, 5)]);
        let reg = registry_with(&[&d]);

        let auditing = VerifyPolicy {
            acceptance: Acceptance::AsOf(1_000),
            ..Default::default()
        };
        assert!(
            verify_bundle(
                &env,
                &reg,
                &auditing,
                &mut MemoryCounters::new(),
                &AlwaysValid,
                None
            )
            .is_ok(),
            "signed before revocation"
        );

        let after = VerifyPolicy {
            acceptance: Acceptance::AsOf(3_000),
            ..Default::default()
        };
        assert!(
            verify_bundle(
                &env,
                &reg,
                &after,
                &mut MemoryCounters::new(),
                &AlwaysValid,
                None
            )
            .is_err(),
            "signed after revocation"
        );
    }

    #[test]
    fn verification_reports_who_approved_not_just_which_key() {
        // "Who approved this and can you prove it" is the question a compliance
        // owner asks, and a hex device id is not an answer.
        let mut d = device(1);
        d.operator = Some(Operator::new("alice@example.com"));
        let got = verify_bundle(
            &envelope(vec![sig_for(&d, 5)]),
            &registry_with(&[&d]),
            &VerifyPolicy::default(),
            &mut MemoryCounters::new(),
            &AlwaysValid,
            None,
        )
        .unwrap();
        assert_eq!(got.operators(), vec!["alice@example.com"]);
        assert_eq!(got.signers[0].counter, 5);
    }

    #[test]
    fn a_registry_built_from_a_roster_carries_owners_and_revocations() {
        let mut active = EnrollmentRecord::new(
            &{
                let mut k = vec![0x04u8; 65];
                k[64] = 1;
                k
            },
            Operator::new("alice@example.com"),
            1,
        );
        active.status = DeviceStatus::Active;

        let mut revoked = EnrollmentRecord::new(
            &{
                let mut k = vec![0x04u8; 65];
                k[64] = 2;
                k
            },
            Operator::new("bob@example.com"),
            1,
        );
        revoked.status = DeviceStatus::Revoked {
            at_unix_ms: 5,
            at_counter: None,
            reason: None,
        };

        let roster = Roster {
            v: 1,
            issued_at_unix_ms: 1,
            serial: 1,
            authority_id: "aa".into(),
            records: vec![active.clone(), revoked.clone()],
        };

        let registry = Registry::from_roster(&roster).unwrap();
        assert_eq!(registry.len(), 2);
        assert!(registry.get(&active.device_id).unwrap().status.is_active());
        assert!(!registry.get(&revoked.device_id).unwrap().status.is_active());
        assert_eq!(
            registry
                .get(&active.device_id)
                .unwrap()
                .operator
                .as_ref()
                .unwrap()
                .subject,
            "alice@example.com"
        );
    }

    #[test]
    fn a_non_approved_decision_never_verifies() {
        let d = device(1);
        let mut env = envelope(vec![]);
        env.bundle.decision = Decision::Aborted;
        let err = verify_bundle(
            &env,
            &registry_with(&[&d]),
            &VerifyPolicy::default(),
            &mut MemoryCounters::new(),
            &AlwaysValid,
            None,
        )
        .unwrap_err();
        assert_eq!(err, VerifyError::NotApproved(Decision::Aborted));
    }

    #[test]
    fn two_of_two_needs_two_distinct_devices() {
        let a = device(1);
        let b = device(2);
        let policy = VerifyPolicy {
            required_signatures: 2,
            ..Default::default()
        };

        // One signature is not enough.
        let err = verify_bundle(
            &envelope(vec![sig_for(&a, 1)]),
            &registry_with(&[&a, &b]),
            &policy,
            &mut MemoryCounters::new(),
            &AlwaysValid,
            None,
        )
        .unwrap_err();
        assert_eq!(
            err,
            VerifyError::Threshold {
                got: 1,
                required: 2
            }
        );

        // The same device twice is not two humans.
        let err = verify_bundle(
            &envelope(vec![sig_for(&a, 1), sig_for(&a, 2)]),
            &registry_with(&[&a, &b]),
            &policy,
            &mut MemoryCounters::new(),
            &AlwaysValid,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(err, VerifyError::DuplicateDevice(_)),
            "got {err:?}"
        );

        // Two devices is.
        assert!(verify_bundle(
            &envelope(vec![sig_for(&a, 1), sig_for(&b, 1)]),
            &registry_with(&[&a, &b]),
            &policy,
            &mut MemoryCounters::new(),
            &AlwaysValid,
            None
        )
        .is_ok());
    }

    #[test]
    fn dual_control_counts_people_not_devices() {
        // One person with two Signets must not satisfy a two-human rule.
        let mut a1 = device(1);
        let mut a2 = device(2);
        a1.operator = Some(Operator::new("alice@example.com"));
        a2.operator = Some(Operator::new("alice@example.com"));

        let mut bob = device(3);
        bob.operator = Some(Operator::new("bob@example.com"));

        let policy = VerifyPolicy {
            required_signatures: 2,
            require_distinct_operators: true,
            ..Default::default()
        };

        let err = verify_bundle(
            &envelope(vec![sig_for(&a1, 1), sig_for(&a2, 1)]),
            &registry_with(&[&a1, &a2, &bob]),
            &policy,
            &mut MemoryCounters::new(),
            &AlwaysValid,
            None,
        )
        .unwrap_err();
        assert_eq!(
            err,
            VerifyError::OperatorThreshold {
                got: 1,
                required: 2
            }
        );

        // Two actual people is fine.
        assert!(verify_bundle(
            &envelope(vec![sig_for(&a1, 1), sig_for(&bob, 1)]),
            &registry_with(&[&a1, &a2, &bob]),
            &policy,
            &mut MemoryCounters::new(),
            &AlwaysValid,
            None
        )
        .is_ok());
    }

    #[test]
    fn dual_control_refuses_a_device_whose_owner_is_unknown() {
        // Without an owner there is no way to tell two people from one, and
        // guessing in the permissive direction defeats the control.
        let anonymous = device(1);
        let mut bob = device(2);
        bob.operator = Some(Operator::new("bob@example.com"));

        let policy = VerifyPolicy {
            required_signatures: 2,
            require_distinct_operators: true,
            ..Default::default()
        };
        let err = verify_bundle(
            &envelope(vec![sig_for(&anonymous, 1), sig_for(&bob, 1)]),
            &registry_with(&[&anonymous, &bob]),
            &policy,
            &mut MemoryCounters::new(),
            &AlwaysValid,
            None,
        )
        .unwrap_err();
        assert!(
            matches!(err, VerifyError::UnknownOperator(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn one_person_with_two_devices_is_fine_when_dual_control_is_off() {
        // Owning a spare is normal; it only matters under a dual-control rule.
        let mut a1 = device(1);
        let mut a2 = device(2);
        a1.operator = Some(Operator::new("alice@example.com"));
        a2.operator = Some(Operator::new("alice@example.com"));

        let policy = VerifyPolicy {
            required_signatures: 2,
            ..Default::default()
        };
        assert!(verify_bundle(
            &envelope(vec![sig_for(&a1, 1), sig_for(&a2, 1)]),
            &registry_with(&[&a1, &a2]),
            &policy,
            &mut MemoryCounters::new(),
            &AlwaysValid,
            None
        )
        .is_ok());
    }

    #[test]
    fn clock_skew_is_only_checked_when_asked_for() {
        let d = device(1);
        let env = envelope(vec![sig_for(&d, 5)]);
        let reg = registry_with(&[&d]);
        let far_future = 2_000_000_000_000u64;

        // Default policy ignores the clock — the counter is what defends.
        assert!(verify_bundle(
            &env,
            &reg,
            &VerifyPolicy::default(),
            &mut MemoryCounters::new(),
            &AlwaysValid,
            Some(far_future)
        )
        .is_ok());

        let strict = VerifyPolicy {
            max_clock_skew_ms: Some(60_000),
            ..Default::default()
        };
        let err = verify_bundle(
            &env,
            &reg,
            &strict,
            &mut MemoryCounters::new(),
            &AlwaysValid,
            Some(far_future),
        )
        .unwrap_err();
        assert!(matches!(err, VerifyError::Stale { .. }), "got {err:?}");
    }

    #[test]
    fn the_signing_payload_is_domain_separated_and_fixed_width() {
        let digest = "00".repeat(32);
        let tbs = signing_payload(&digest, 41235, 1_755_859_200_123).unwrap();
        assert_eq!(tbs.len(), DOMAIN.len() + 32 + 8 + 8);
        assert!(tbs.starts_with(b"countersign-v1\0"));
        // Counter and timestamp are big-endian and inside the signature, so
        // neither can be edited by someone holding the bundle.
        assert_eq!(
            &tbs[DOMAIN.len() + 32..DOMAIN.len() + 40],
            &41235u64.to_be_bytes()
        );
    }

    #[test]
    fn a_short_digest_is_not_silently_padded() {
        assert!(signing_payload("abcd", 1, 1).is_err());
    }
}

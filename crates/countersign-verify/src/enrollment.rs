//! Enrollment: how a verifier learns which public keys to trust, and who may
//! add one.
//!
//! This is the trust root. Everything else in the protocol reduces to "a
//! signature from an enrolled key", so if enrollment is weak, nothing above it
//! is strong.
//!
//! # The three questions
//!
//! **What binds a key to a human?** An [`EnrollmentRecord`]. The signature
//! proves a device; the record maps that device to a person. This is the
//! `authorized_keys` model, and it is the right one — the alternative, putting
//! identity inside the device's signature, means re-flashing a device to change
//! someone's email address.
//!
//! **How does a verifier on another host learn it?** A [`Roster`]: a list of
//! records, signed by an enrollment authority, self-authenticating so the
//! distribution channel does not have to be trusted. Put it in git, on a web
//! server, in a config-management blob — a verifier configured with the
//! authority's public key can check it wherever it came from.
//!
//! **Who may register one?** Whoever holds the authority key, and — because of
//! [`verify_proof`] — only with the physical cooperation of the device being
//! enrolled.
//!
//! # Enrollment is itself an approval
//!
//! Proof of possession is not a new mechanism here. Enrolling a device means
//! asking it to countersign a request whose action is
//! [`ENROLLMENT_ACTION`] and whose statement is
//! [`enrollment_statement`] — so the device renders "Enroll this device as an
//! approver for alice@example.com" on its own screen, and a human turns the
//! dial.
//!
//! Reusing the approval path is deliberate. A separate enrollment ceremony
//! would be a second thing the device signs, with its own display rules and its
//! own chance to become blind signing. There is one signing construction in this
//! protocol and enrollment goes through it.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::bundle::{ApprovalEnvelope, Decision};
use crate::encoding::{b64url_decode, hex_decode, hex_encode};
use crate::request::digest_of_json;
use crate::store::StoreError;
use crate::verify::{is_low_s, signing_payload, SignatureBackend};

/// The reserved action a device countersigns to prove it holds its own key.
pub const ENROLLMENT_ACTION: &str = "countersign.enroll";

/// Domain separator for roster signatures, distinct from the approval one so a
/// roster signature can never be replayed as an approval or the reverse.
const ROSTER_DOMAIN: &[u8] = b"countersign-roster-v1\0";

/// The exact text a device displays and signs when being enrolled.
///
/// Fixed rather than free-form so a verifier can check it byte-for-byte. If an
/// enroller could write this string, they could show the human
/// "Enroll for testing" while binding the device to an administrator.
pub fn enrollment_statement(subject: &str) -> String {
    format!("Enroll this device as an approver for {subject}")
}

/// The human a device belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operator {
    /// A stable identifier — an email, an employee id, an OIDC subject.
    pub subject: String,
    /// A display name. Never used in a decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

impl Operator {
    pub fn new(subject: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            display: None,
        }
    }
}

/// Whether a device may still be used.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DeviceStatus {
    #[default]
    Active,
    /// Lost, replaced, or the operator left.
    Revoked {
        at_unix_ms: u64,
        /// The device counter at which trust ends, when it is known.
        ///
        /// Present, this makes revocation precise: approvals below it were
        /// produced before the device left the operator's control and remain
        /// historically valid. Absent, only the timestamp is available and
        /// audits fall back to that.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        at_counter: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
}

impl DeviceStatus {
    pub fn is_active(&self) -> bool {
        matches!(self, DeviceStatus::Active)
    }

    /// Whether a device in this state was trusted at a past instant.
    ///
    /// The distinction from [`is_active`](Self::is_active) matters more than it
    /// looks. Revoking a lost device must stop it authorizing anything from now
    /// on — and must *not* retroactively invalidate the approvals its owner
    /// legitimately gave last year, because the audit trail is most of the point
    /// of keeping them.
    pub fn was_valid_at(&self, unix_ms: u64, counter: Option<u64>) -> bool {
        match self {
            DeviceStatus::Active => true,
            DeviceStatus::Revoked {
                at_unix_ms,
                at_counter,
                ..
            } => {
                // A counter comparison beats a timestamp comparison whenever one
                // is available: it survives a clock that was wrong.
                match (at_counter, counter) {
                    (Some(cutoff), Some(seen)) => seen < *cutoff,
                    _ => unix_ms < *at_unix_ms,
                }
            }
        }
    }
}

/// What kind of thing holds the key — and therefore how much its signature
/// proves. See `spec/device-classes-v1.md`.
///
/// The class is a property of the **enrollment**, never of the signature. A
/// signer does not get to say what kind of thing it is, for the same reason it
/// does not get to say what its `device_id` is: a verifier learns the class
/// from a record it already trusts, and from nowhere else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceClass {
    /// A Signet: a secure element, a screen only the firmware draws on, a dial
    /// with one meaning, and a counter in silicon. The full wire-spec §1 claim.
    Signet,
    /// A platform secure enclave behind an operating-system presence check on
    /// every use, rendering on a general-purpose OS. A real approval with a
    /// smaller claim — the screen could be overlaid by a compromised OS, and
    /// the counter is software bound to the key rather than silicon.
    Enclave,
    /// A **published** private key. Proves nothing. Exists so software can be
    /// tested without a bypass that could survive into production.
    Test,
}

impl DeviceClass {
    pub fn as_str(self) -> &'static str {
        match self {
            DeviceClass::Signet => "signet",
            DeviceClass::Enclave => "enclave",
            DeviceClass::Test => "test",
        }
    }

    /// Whether this class is the published-test-key class.
    pub fn is_test(self) -> bool {
        matches!(self, DeviceClass::Test)
    }
}

impl std::fmt::Display for DeviceClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One enrolled device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentRecord {
    /// Lowercase hex SHA-256 of `public_key_hex`'s bytes. Derived, never
    /// asserted independently — see [`EnrollmentRecord::check_device_id`].
    pub device_id: String,
    /// SEC1 uncompressed public key, lowercase hex.
    pub public_key_hex: String,
    pub operator: Operator,
    pub enrolled_at_unix_ms: u64,
    #[serde(default)]
    pub status: DeviceStatus,
    /// Whether this is a **published** test key. Verifiers refuse these unless
    /// explicitly configured otherwise.
    #[serde(default)]
    pub is_test_key: bool,
    /// What kind of thing holds the key — `spec/device-classes-v1.md` §4.
    ///
    /// Absent on every roster issued before classes existed;
    /// [`EnrollmentRecord::class`] resolves those from `is_test_key`, so nothing
    /// already issued changes meaning. When present it MUST agree with
    /// `is_test_key`, and [`EnrollmentRecord::check_class`] refuses a record
    /// where the two disagree, because one of them is lying and a verifier
    /// cannot tell which.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<DeviceClass>,
    /// The countersigned enrollment, proving the device held its own key and a
    /// human was present. Optional in the format so a roster can be trimmed for
    /// size, but a verifier that never checks one is trusting the authority
    /// completely. **Mandatory for an `enclave` record** — see
    /// [`EnrollmentRecord::check_class`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<ApprovalEnvelope>,
}

impl EnrollmentRecord {
    pub fn new(public_key: &[u8], operator: Operator, enrolled_at_unix_ms: u64) -> Self {
        Self {
            device_id: hex_encode(&Sha256::digest(public_key)),
            public_key_hex: hex_encode(public_key),
            operator,
            enrolled_at_unix_ms,
            status: DeviceStatus::Active,
            is_test_key: false,
            class: None,
            proof: None,
        }
    }

    /// Set the class, keeping `is_test_key` in agreement with it.
    pub fn with_class(mut self, class: DeviceClass) -> Self {
        self.class = Some(class);
        self.is_test_key = class.is_test();
        self
    }

    /// The device's class, resolving records issued before the field existed.
    ///
    /// A record with no `class` is read as [`DeviceClass::Test`] when
    /// `is_test_key` is set and [`DeviceClass::Signet`] otherwise — every
    /// roster issued before `spec/device-classes-v1.md` keeps its meaning.
    pub fn class(&self) -> DeviceClass {
        match self.class {
            Some(class) => class,
            None if self.is_test_key => DeviceClass::Test,
            None => DeviceClass::Signet,
        }
    }

    /// Confirm the record is internally consistent about what kind of thing
    /// it describes.
    ///
    /// Two rules from `spec/device-classes-v1.md` §4. `class` and `is_test_key`
    /// must agree — a record claiming to be a Signet while flagged as a test
    /// key is lying in one of two places, and a verifier cannot tell which, so
    /// it refuses the record whole. And an `enclave` record must carry its
    /// proof: the ceremony rendered on the app's own screen and signed under a
    /// presence check is the only evidence that the key can sign at all, and
    /// a roster trimmed of it has trimmed the one thing that made the class
    /// mean something.
    pub fn check_class(&self) -> Result<(), EnrollmentError> {
        if let Some(class) = self.class {
            if class.is_test() != self.is_test_key {
                return Err(EnrollmentError::ClassMismatch {
                    class,
                    is_test_key: self.is_test_key,
                });
            }
        }
        if self.class() == DeviceClass::Enclave && self.proof.is_none() {
            return Err(EnrollmentError::EnclaveWithoutProof);
        }
        Ok(())
    }

    pub fn public_key(&self) -> Result<Vec<u8>, EnrollmentError> {
        hex_decode(&self.public_key_hex).map_err(|_| EnrollmentError::MalformedKey)
    }

    /// Confirm `device_id` really is the digest of `public_key_hex`.
    ///
    /// Without this a roster could list one key under another device's id, and
    /// every lookup keyed on the id would resolve to the wrong key.
    pub fn check_device_id(&self) -> Result<(), EnrollmentError> {
        let derived = hex_encode(&Sha256::digest(self.public_key()?));
        if derived != self.device_id {
            return Err(EnrollmentError::DeviceIdMismatch {
                claimed: self.device_id.clone(),
                derived,
            });
        }
        Ok(())
    }

    /// Whether this device may authorize something **now**.
    pub fn acceptable_now(&self) -> bool {
        self.status.is_active()
    }

    /// Whether this device was trusted at a past instant, for auditing.
    ///
    /// The distinction from [`acceptable_now`](Self::acceptable_now) matters
    /// more than it looks. Revoking a lost device must stop it authorizing
    /// anything from now on — and must *not* retroactively invalidate the
    /// approvals its owner legitimately gave last year, because the audit trail
    /// is most of the point of keeping them.
    pub fn was_valid_at(&self, unix_ms: u64, counter: Option<u64>) -> bool {
        self.status.was_valid_at(unix_ms, counter)
    }

    /// Check the device countersigned its own enrollment.
    ///
    /// This is the proof-of-possession step, and it is what stops an enroller
    /// from registering a public key they merely *observed*. It confirms four
    /// things: the approval was approved, it was signed by this record's own
    /// key, it carries the reserved enrollment action, and its statement names
    /// this record's operator exactly.
    pub fn verify_proof(&self, backend: &dyn SignatureBackend) -> Result<(), EnrollmentError> {
        self.check_device_id()?;
        self.check_class()?;
        let proof = self.proof.as_ref().ok_or(EnrollmentError::MissingProof)?;

        if proof.bundle.decision != Decision::Approved {
            return Err(EnrollmentError::ProofNotApproved(proof.bundle.decision));
        }

        let request = proof
            .request()
            .map_err(|e| EnrollmentError::MalformedProof(e.to_string()))?;

        if request.action != ENROLLMENT_ACTION {
            return Err(EnrollmentError::ProofWrongAction(request.action));
        }

        let expected = enrollment_statement(&self.operator.subject);
        if request.statement != expected {
            return Err(EnrollmentError::ProofStatementMismatch {
                expected,
                found: request.statement,
            });
        }

        // The digest must cover the request text the proof travels with.
        let digest = digest_of_json(&proof.request_json)
            .map_err(|e| EnrollmentError::MalformedProof(e.to_string()))?;
        if digest != proof.bundle.request_digest {
            return Err(EnrollmentError::MalformedProof(
                "digest does not cover request".into(),
            ));
        }

        let public_key = self.public_key()?;
        let signature = proof
            .bundle
            .signatures
            .iter()
            .find(|s| s.device_id == self.device_id)
            .ok_or(EnrollmentError::ProofNotSelfSigned)?;

        let raw = b64url_decode(&signature.signature)
            .map_err(|_| EnrollmentError::MalformedProof("signature encoding".into()))?;
        let raw: [u8; 64] = raw
            .try_into()
            .map_err(|_| EnrollmentError::MalformedProof("signature length".into()))?;

        if !is_low_s(&raw) {
            return Err(EnrollmentError::ProofNotLowS);
        }

        let tbs = signing_payload(&digest, signature.counter, signature.device_unix_ms)
            .map_err(|e| EnrollmentError::MalformedProof(e.to_string()))?;

        if !backend.verify_p256_sha256(&public_key, &tbs, &raw) {
            return Err(EnrollmentError::ProofBadSignature);
        }
        Ok(())
    }
}

/// A signed list of enrolled devices.
///
/// The unit of distribution. A verifier holds one authority public key,
/// configured out of band once, and can then accept a roster from anywhere —
/// the roster authenticates itself, so the fetch does not have to be trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Roster {
    pub v: u8,
    pub issued_at_unix_ms: u64,
    /// Monotonic. See [`RosterStore`] — without a rollback check, a revocation
    /// is undone by replaying yesterday's roster.
    pub serial: u64,
    /// Lowercase hex SHA-256 of the authority's SEC1 public key.
    pub authority_id: String,
    pub records: Vec<EnrollmentRecord>,
}

impl Roster {
    /// Revoke **every** device belonging to one person. Returns how many were
    /// changed.
    ///
    /// The operation offboarding actually needs. Revoking a single record is
    /// right for a lost device and wrong for a departing employee, who may hold
    /// a desk device, a travel device and a replacement issued last spring —
    /// and the one that gets forgotten is the one that still works.
    ///
    /// Already-revoked records are left alone, so an earlier, more precise
    /// revocation (one that recorded `at_counter`) is not coarsened by a later
    /// sweep.
    ///
    /// The caller must still bump [`Roster::serial`] and re-sign; this only
    /// edits records.
    pub fn revoke_all_for(
        &mut self,
        subject: &str,
        at_unix_ms: u64,
        reason: Option<String>,
    ) -> usize {
        let mut changed = 0;
        for record in &mut self.records {
            if record.operator.subject == subject && record.status.is_active() {
                record.status = DeviceStatus::Revoked {
                    at_unix_ms,
                    at_counter: None,
                    reason: reason.clone(),
                };
                changed += 1;
            }
        }
        changed
    }

    /// Every record belonging to one person, active or not.
    pub fn records_for(&self, subject: &str) -> Vec<&EnrollmentRecord> {
        self.records
            .iter()
            .filter(|r| r.operator.subject == subject)
            .collect()
    }
}

/// A roster and the authority's signature over it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRoster {
    /// The roster **as issued**. Kept as raw text for the same reason
    /// [`ApprovalEnvelope`] does: re-serializing through a struct drops fields
    /// a future version added, and the signature covers what was sent.
    pub roster_json: String,
    /// base64url unpadded, `r || s`.
    pub signature: String,
}

impl SignedRoster {
    pub fn roster(&self) -> Result<Roster, EnrollmentError> {
        serde_json::from_str(&self.roster_json)
            .map_err(|e| EnrollmentError::MalformedRoster(e.to_string()))
    }

    /// The bytes an authority signs: domain separator plus the roster digest.
    pub fn signing_payload(roster_json: &str) -> Result<Vec<u8>, EnrollmentError> {
        let digest_hex = digest_of_json(roster_json)
            .map_err(|e| EnrollmentError::MalformedRoster(e.to_string()))?;
        let digest = hex_decode(&digest_hex).map_err(|_| EnrollmentError::MalformedKey)?;
        let mut out = Vec::with_capacity(ROSTER_DOMAIN.len() + 32);
        out.extend_from_slice(ROSTER_DOMAIN);
        out.extend_from_slice(&digest);
        Ok(out)
    }

    /// Verify the authority's signature and return the roster.
    pub fn verify(
        &self,
        authority_public_key: &[u8],
        backend: &dyn SignatureBackend,
    ) -> Result<Roster, EnrollmentError> {
        let roster = self.roster()?;

        let authority_id = hex_encode(&Sha256::digest(authority_public_key));
        if roster.authority_id != authority_id {
            return Err(EnrollmentError::WrongAuthority {
                expected: authority_id,
                found: roster.authority_id,
            });
        }

        let raw = b64url_decode(&self.signature)
            .map_err(|_| EnrollmentError::MalformedRoster("signature encoding".into()))?;
        let raw: [u8; 64] = raw
            .try_into()
            .map_err(|_| EnrollmentError::MalformedRoster("signature length".into()))?;

        if !is_low_s(&raw) {
            return Err(EnrollmentError::RosterNotLowS);
        }

        let tbs = Self::signing_payload(&self.roster_json)?;
        if !backend.verify_p256_sha256(authority_public_key, &tbs, &raw) {
            return Err(EnrollmentError::RosterBadSignature);
        }

        for record in &roster.records {
            record.check_device_id()?;
            record.check_class()?;
        }

        Ok(roster)
    }
}

/// Remembers the highest roster serial accepted, so an old roster cannot be
/// replayed.
///
/// This is the revocation counterpart of the approval counter store, and it
/// matters for the same reason: a revocation that can be undone by serving
/// yesterday's file is not a revocation. An attacker who lost a device only
/// needs the verifier to keep reading a roster from before it was removed.
pub trait RosterStore {
    fn highest_serial(&self, authority_id: &str) -> Option<u64>;

    /// Remember this serial, durably.
    ///
    /// Fallible for the same reason `CounterStore::record` is: a serial that
    /// cannot be persisted is a rollback that will not be detected after the
    /// next restart, and every revocation between then and now quietly comes
    /// back.
    fn record_serial(&mut self, authority_id: &str, serial: u64) -> Result<(), StoreError>;
}

/// An in-memory [`RosterStore`]. A verifier that restarts needs a durable one,
/// or it accepts one rollback per restart.
#[derive(Debug, Clone, Default)]
pub struct MemoryRosterStore(std::collections::HashMap<String, u64>);

impl MemoryRosterStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl RosterStore for MemoryRosterStore {
    fn highest_serial(&self, authority_id: &str) -> Option<u64> {
        self.0.get(authority_id).copied()
    }
    fn record_serial(&mut self, authority_id: &str, serial: u64) -> Result<(), StoreError> {
        let e = self.0.entry(authority_id.to_string()).or_insert(serial);
        *e = (*e).max(serial);
        Ok(())
    }
}

/// Verify a roster and check it is not a rollback.
pub fn accept_roster(
    signed: &SignedRoster,
    authority_public_key: &[u8],
    backend: &dyn SignatureBackend,
    store: &mut dyn RosterStore,
) -> Result<Roster, EnrollmentError> {
    let roster = signed.verify(authority_public_key, backend)?;

    if let Some(highest) = store.highest_serial(&roster.authority_id) {
        if roster.serial < highest {
            return Err(EnrollmentError::RosterRollback {
                serial: roster.serial,
                highest,
            });
        }
    }

    // Persisted before the roster is handed back, so a caller cannot act on a
    // roster whose serial was never recorded.
    store
        .record_serial(&roster.authority_id, roster.serial)
        .map_err(EnrollmentError::Store)?;
    Ok(roster)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentError {
    MalformedKey,
    DeviceIdMismatch {
        claimed: String,
        derived: String,
    },
    MissingProof,
    ProofNotApproved(Decision),
    ProofWrongAction(String),
    ProofStatementMismatch {
        expected: String,
        found: String,
    },
    ProofNotSelfSigned,
    ProofBadSignature,
    /// The proof signature is not low-S (spec §4).
    ProofNotLowS,
    /// `class` and `is_test_key` disagree — one of them is lying.
    ClassMismatch {
        class: DeviceClass,
        is_test_key: bool,
    },
    /// An `enclave` record arrived without its enrollment proof, which is the
    /// one thing that made the class mean something.
    EnclaveWithoutProof,
    MalformedProof(String),
    MalformedRoster(String),
    WrongAuthority {
        expected: String,
        found: String,
    },
    RosterBadSignature,
    /// The roster signature is not low-S (spec §4).
    RosterNotLowS,
    RosterRollback {
        serial: u64,
        highest: u64,
    },
    /// The rollback defence could not be persisted, so the roster was refused.
    Store(StoreError),
}

impl std::fmt::Display for EnrollmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use EnrollmentError::*;
        match self {
            MalformedKey => f.write_str("public key is not valid hex"),
            DeviceIdMismatch { claimed, derived } => {
                write!(
                    f,
                    "record claims device_id {claimed} but its key derives {derived}"
                )
            }
            MissingProof => f.write_str("record carries no enrollment proof"),
            ProofNotApproved(d) => write!(f, "enrollment proof was {}, not approved", d.as_str()),
            ProofWrongAction(a) => {
                write!(
                    f,
                    "enrollment proof is for action {a:?}, not {ENROLLMENT_ACTION:?}"
                )
            }
            ProofStatementMismatch { expected, found } => {
                write!(f, "enrollment proof says {found:?}, expected {expected:?}")
            }
            ProofNotSelfSigned => {
                f.write_str("enrollment proof was not signed by the device it enrolls")
            }
            ProofBadSignature => f.write_str("enrollment proof signature did not verify"),
            ProofNotLowS => f.write_str("enrollment proof signature is not low-S"),
            ClassMismatch { class, is_test_key } => write!(
                f,
                "record says class {class} but is_test_key is {is_test_key}; one of them is wrong \
                 and a verifier cannot tell which"
            ),
            EnclaveWithoutProof => f.write_str(
                "an enclave record must carry its enrollment proof — without it nothing shows the \
                 key can sign under a presence check",
            ),
            MalformedProof(e) => write!(f, "malformed enrollment proof: {e}"),
            MalformedRoster(e) => write!(f, "malformed roster: {e}"),
            WrongAuthority { expected, found } => {
                write!(
                    f,
                    "roster is from authority {found}, this verifier trusts {expected}"
                )
            }
            RosterBadSignature => f.write_str("roster signature did not verify"),
            RosterNotLowS => f.write_str("roster signature is not low-S"),
            Store(e) => write!(
                f,
                "refused: the roster serial could not be recorded ({e}). A serial that cannot \
                 be remembered is a rollback that will not be detected"
            ),
            RosterRollback { serial, highest } => write!(
                f,
                "roster serial {serial} is older than the highest accepted ({highest}) — \
                 a replayed roster would undo revocations"
            ),
        }
    }
}

impl std::error::Error for EnrollmentError {}

#[cfg(test)]
mod tests {
    use super::*;

    struct AlwaysValid;
    impl SignatureBackend for AlwaysValid {
        fn verify_p256_sha256(&self, _: &[u8], _: &[u8], _: &[u8; 64]) -> bool {
            true
        }
    }

    fn key(seed: u8) -> Vec<u8> {
        let mut k = vec![0x04u8; 65];
        k[64] = seed;
        k
    }

    fn record(seed: u8) -> EnrollmentRecord {
        EnrollmentRecord::new(
            &key(seed),
            Operator::new("alice@example.com"),
            1_700_000_000_000,
        )
    }

    #[test]
    fn a_device_id_must_be_the_digest_of_its_own_key() {
        let mut r = record(1);
        assert!(r.check_device_id().is_ok());

        // Listing one key under another device's id would make every lookup
        // resolve to the wrong key.
        r.device_id = "00".repeat(32);
        assert!(matches!(
            r.check_device_id(),
            Err(EnrollmentError::DeviceIdMismatch { .. })
        ));
    }

    #[test]
    fn an_active_device_is_acceptable_and_a_revoked_one_is_not() {
        let mut r = record(1);
        assert!(r.acceptable_now());

        r.status = DeviceStatus::Revoked {
            at_unix_ms: 1_800_000_000_000,
            at_counter: None,
            reason: Some("lost".into()),
        };
        assert!(!r.acceptable_now());
    }

    #[test]
    fn revocation_does_not_retroactively_void_the_audit_trail() {
        // Revoking a lost device must stop it authorizing anything from now on,
        // and must not invalidate what its owner legitimately approved before.
        let mut r = record(1);
        r.status = DeviceStatus::Revoked {
            at_unix_ms: 1_800_000_000_000,
            at_counter: None,
            reason: None,
        };
        assert!(r.was_valid_at(1_700_000_000_000, None), "before revocation");
        assert!(!r.was_valid_at(1_900_000_000_000, None), "after revocation");
        assert!(!r.acceptable_now(), "but never acceptable for a new action");
    }

    #[test]
    fn a_revocation_counter_beats_a_timestamp_when_both_are_known() {
        // The counter survives a clock that was wrong, which is the whole
        // reason the protocol carries one.
        let mut r = record(1);
        r.status = DeviceStatus::Revoked {
            at_unix_ms: 1_800_000_000_000,
            at_counter: Some(500),
            reason: None,
        };
        // A wildly wrong device clock, but a counter below the cutoff.
        assert!(r.was_valid_at(1_900_000_000_000, Some(499)));
        assert!(!r.was_valid_at(1_700_000_000_000, Some(501)));
    }

    // ---- rosters ----------------------------------------------------------

    fn roster_json(serial: u64, authority: &[u8], records: Vec<EnrollmentRecord>) -> String {
        let roster = Roster {
            v: 1,
            issued_at_unix_ms: 1_700_000_000_000,
            serial,
            authority_id: hex_encode(&Sha256::digest(authority)),
            records,
        };
        serde_json::to_string(&roster).unwrap()
    }

    fn signed(serial: u64, authority: &[u8]) -> SignedRoster {
        SignedRoster {
            roster_json: roster_json(serial, authority, vec![record(1)]),
            signature: crate::encoding::b64url_encode(&[7u8; 64]),
        }
    }

    #[test]
    fn a_roster_from_another_authority_is_refused() {
        // A verifier trusts exactly one authority key, configured out of band.
        let ours = key(9);
        let theirs = key(8);
        let r = SignedRoster {
            roster_json: roster_json(1, &theirs, vec![record(1)]),
            signature: crate::encoding::b64url_encode(&[7u8; 64]),
        };
        assert!(matches!(
            r.verify(&ours, &AlwaysValid),
            Err(EnrollmentError::WrongAuthority { .. })
        ));
    }

    #[test]
    fn a_valid_roster_verifies_and_carries_its_records() {
        let authority = key(9);
        let roster = signed(1, &authority)
            .verify(&authority, &AlwaysValid)
            .unwrap();
        assert_eq!(roster.records.len(), 1);
        assert_eq!(roster.records[0].operator.subject, "alice@example.com");
    }

    #[test]
    fn a_roster_listing_a_mismatched_device_id_is_refused_whole() {
        let authority = key(9);
        let mut bad = record(1);
        bad.device_id = "ff".repeat(32);
        let r = SignedRoster {
            roster_json: roster_json(1, &authority, vec![bad]),
            signature: crate::encoding::b64url_encode(&[7u8; 64]),
        };
        assert!(matches!(
            r.verify(&authority, &AlwaysValid),
            Err(EnrollmentError::DeviceIdMismatch { .. })
        ));
    }

    #[test]
    fn an_old_roster_cannot_be_replayed_to_undo_a_revocation() {
        // The attack: someone who lost a device only needs the verifier to keep
        // reading the roster from before it was removed.
        let authority = key(9);
        let mut store = MemoryRosterStore::new();

        accept_roster(&signed(5, &authority), &authority, &AlwaysValid, &mut store).unwrap();

        let err = accept_roster(&signed(4, &authority), &authority, &AlwaysValid, &mut store)
            .unwrap_err();
        assert!(matches!(
            err,
            EnrollmentError::RosterRollback {
                serial: 4,
                highest: 5
            }
        ));

        // The same serial is fine — a re-fetch of the current roster.
        assert!(
            accept_roster(&signed(5, &authority), &authority, &AlwaysValid, &mut store).is_ok()
        );
        // And moving forward is fine.
        assert!(
            accept_roster(&signed(6, &authority), &authority, &AlwaysValid, &mut store).is_ok()
        );
    }

    #[test]
    fn revoking_a_person_revokes_every_device_they_hold() {
        // The offboarding hazard: someone holds three devices and only one is
        // remembered. The forgotten one is the one that still works.
        let mut work = record(1);
        let mut home = record(2);
        let mut spare = record(3);
        for r in [&mut work, &mut home, &mut spare] {
            r.operator = Operator::new("alice@example.com");
        }
        let mut bob = record(4);
        bob.operator = Operator::new("bob@example.com");

        let mut roster = Roster {
            v: 1,
            issued_at_unix_ms: 1,
            serial: 1,
            authority_id: "aa".into(),
            records: vec![work, home, spare, bob],
        };

        assert_eq!(roster.records_for("alice@example.com").len(), 3);
        let changed = roster.revoke_all_for("alice@example.com", 5_000, Some("left".into()));
        assert_eq!(changed, 3);

        assert!(roster
            .records_for("alice@example.com")
            .iter()
            .all(|r| !r.acceptable_now()));
        assert!(
            roster.records_for("bob@example.com")[0].acceptable_now(),
            "nobody else is affected"
        );
    }

    #[test]
    fn a_sweep_does_not_coarsen_an_earlier_precise_revocation() {
        // A device revoked with a counter cutoff keeps it; re-revoking would
        // throw away the precision that keeps history auditable.
        let mut lost = record(1);
        lost.operator = Operator::new("alice@example.com");
        lost.status = DeviceStatus::Revoked {
            at_unix_ms: 1_000,
            at_counter: Some(42),
            reason: Some("lost".into()),
        };
        let mut active = record(2);
        active.operator = Operator::new("alice@example.com");

        let mut roster = Roster {
            v: 1,
            issued_at_unix_ms: 1,
            serial: 1,
            authority_id: "aa".into(),
            records: vec![lost, active],
        };

        assert_eq!(roster.revoke_all_for("alice@example.com", 9_000, None), 1);
        assert!(matches!(
            roster.records[0].status,
            DeviceStatus::Revoked {
                at_counter: Some(42),
                ..
            }
        ));
    }

    #[test]
    fn a_class_less_record_resolves_from_its_test_flag() {
        // Every roster issued before spec/device-classes-v1.md keeps meaning.
        let mut r = record(1);
        assert_eq!(r.class, None);
        assert_eq!(r.class(), DeviceClass::Signet);
        r.is_test_key = true;
        assert_eq!(r.class(), DeviceClass::Test);
        assert!(r.check_class().is_ok());
    }

    #[test]
    fn a_class_that_disagrees_with_the_test_flag_is_refused() {
        // One of them is lying and a verifier cannot tell which.
        let mut r = record(1).with_class(DeviceClass::Signet);
        assert!(r.check_class().is_ok());
        r.is_test_key = true;
        assert_eq!(
            r.check_class(),
            Err(EnrollmentError::ClassMismatch {
                class: DeviceClass::Signet,
                is_test_key: true,
            })
        );

        let mut r = record(2).with_class(DeviceClass::Test);
        assert!(r.is_test_key, "with_class sets the flag");
        r.is_test_key = false;
        assert!(matches!(
            r.check_class(),
            Err(EnrollmentError::ClassMismatch { .. })
        ));
    }

    #[test]
    fn an_enclave_record_needs_its_proof() {
        let r = record(1).with_class(DeviceClass::Enclave);
        assert_eq!(r.check_class(), Err(EnrollmentError::EnclaveWithoutProof));
        // verify_proof reports the same thing, rather than the generic
        // MissingProof, so the caller learns which rule they broke.
        assert_eq!(
            r.verify_proof(&AlwaysValid),
            Err(EnrollmentError::EnclaveWithoutProof)
        );
    }

    #[test]
    fn class_round_trips_through_json_and_is_omitted_when_absent() {
        let r = record(1).with_class(DeviceClass::Enclave);
        let text = serde_json::to_string(&r).unwrap();
        assert!(text.contains(r#""class":"enclave""#), "got {text}");
        assert_eq!(
            serde_json::from_str::<EnrollmentRecord>(&text).unwrap().class,
            Some(DeviceClass::Enclave)
        );

        let legacy = serde_json::to_string(&record(1)).unwrap();
        assert!(!legacy.contains("class"), "a class-less record stays class-less: {legacy}");
    }

    #[test]
    fn a_record_without_a_proof_reports_that_rather_than_passing() {
        assert_eq!(
            record(1).verify_proof(&AlwaysValid),
            Err(EnrollmentError::MissingProof)
        );
    }

    #[test]
    fn the_enrollment_statement_is_fixed_text_naming_the_operator() {
        // Fixed so a verifier can check it byte-for-byte. If an enroller could
        // write this string, they could show the human "Enroll for testing"
        // while binding the device to an administrator.
        assert_eq!(
            enrollment_statement("alice@example.com"),
            "Enroll this device as an approver for alice@example.com"
        );
    }

    #[test]
    fn status_round_trips_through_json() {
        let revoked = DeviceStatus::Revoked {
            at_unix_ms: 1,
            at_counter: Some(2),
            reason: Some("lost".into()),
        };
        let text = serde_json::to_string(&revoked).unwrap();
        assert!(text.contains(r#""state":"revoked""#), "got {text}");
        assert_eq!(
            serde_json::from_str::<DeviceStatus>(&text).unwrap(),
            revoked
        );

        // An absent status defaults to active, so a hand-written roster entry
        // does the obvious thing.
        let r: EnrollmentRecord = serde_json::from_str(
            r#"{"device_id":"aa","public_key_hex":"bb","operator":{"subject":"x"},
                "enrolled_at_unix_ms":1}"#,
        )
        .unwrap();
        assert_eq!(r.status, DeviceStatus::Active);
    }
}

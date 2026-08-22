//! Checkpoints — the answer to log truncation.
//!
//! A hash chain detects insertion, reordering and edits. It does not detect
//! someone deleting the last twenty entries, because a shorter chain is still a
//! perfectly valid chain. A checkpoint is a signed statement that the log
//! reached a particular length and head, so a truncated log can be caught by
//! comparing it against one.
//!
//! # Be honest about what this buys
//!
//! A checkpoint signed by the daemon's own software key defends against someone
//! who edits the log **later** — a log consumer, a sync server, a backup, an
//! attacker with the file but not the key. It does **not** defend against
//! whoever controls the daemon at the moment of writing: they hold the key, so
//! they can sign whatever history they like.
//!
//! Getting that boundary right matters more than the feature. A compliance
//! buyer told "this log is tamper-proof" will eventually find out it means
//! "tamper-evident against everyone except the machine that wrote it", and it
//! is much better for them to read that here first.
//!
//! The stronger version is available and costs a dial turn: sign the head with
//! an enrolled Signet instead of the daemon key. Then even the machine that
//! wrote the log cannot rewrite it without a human present. That is worth doing
//! at a low frequency — hourly, or at shift boundaries — rather than per entry.

use countersign_verify::{
    encoding::{b64url_decode, hex_decode},
    is_low_s, SignatureBackend,
};
use serde::{Deserialize, Serialize};

use crate::AuditError;

/// Domain separator, distinct from the approval and roster ones so a checkpoint
/// signature can never be replayed as either.
const CHECKPOINT_DOMAIN: &[u8] = b"countersign-audit-v1\0";

/// A signed assertion about how far a log had got.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// The seq of the last entry covered.
    pub seq: u64,
    /// That entry's hash.
    pub head: String,
    /// Total entries at the time of signing.
    ///
    /// Carried as well as `seq` so a log that legitimately starts at a non-zero
    /// seq — a rotated file — can still be checked for completeness.
    pub entries: u64,
    pub at_unix_ms: u64,
    /// Lowercase hex SHA-256 of the signer's SEC1 public key.
    pub signer_id: String,
    /// base64url unpadded, `r || s`.
    pub signature: String,
}

impl Checkpoint {
    /// The bytes a checkpoint signer covers.
    pub fn signing_payload(
        head: &str,
        seq: u64,
        entries: u64,
        at_unix_ms: u64,
    ) -> Result<Vec<u8>, AuditError> {
        let head_bytes =
            hex_decode(head).map_err(|_| AuditError::Malformed("head is not hex".into()))?;
        if head_bytes.len() != 32 {
            return Err(AuditError::Malformed(format!(
                "head is {} bytes, expected 32",
                head_bytes.len()
            )));
        }
        let mut out = Vec::with_capacity(CHECKPOINT_DOMAIN.len() + 32 + 24);
        out.extend_from_slice(CHECKPOINT_DOMAIN);
        out.extend_from_slice(&head_bytes);
        out.extend_from_slice(&seq.to_be_bytes());
        out.extend_from_slice(&entries.to_be_bytes());
        out.extend_from_slice(&at_unix_ms.to_be_bytes());
        Ok(out)
    }

    /// Check the signature.
    pub fn verify(
        &self,
        signer_public_key: &[u8],
        backend: &dyn SignatureBackend,
    ) -> Result<(), AuditError> {
        let raw = b64url_decode(&self.signature)
            .map_err(|_| AuditError::Malformed("checkpoint signature encoding".into()))?;
        let raw: [u8; 64] = raw
            .try_into()
            .map_err(|_| AuditError::Malformed("checkpoint signature length".into()))?;

        if !is_low_s(&raw) {
            return Err(AuditError::CheckpointNotLowS);
        }

        let tbs = Self::signing_payload(&self.head, self.seq, self.entries, self.at_unix_ms)?;
        if !backend.verify_p256_sha256(signer_public_key, &tbs, &raw) {
            return Err(AuditError::CheckpointBadSignature);
        }
        Ok(())
    }

    /// Check a log's current state against this checkpoint.
    ///
    /// The truncation test: a log that has fewer entries than the checkpoint
    /// recorded, or whose head at that seq differs, has lost or altered
    /// history.
    pub fn check_log(
        &self,
        summary: &crate::ChainSummary,
        head_at_seq: Option<&str>,
    ) -> Result<(), AuditError> {
        let last = summary.last_seq.unwrap_or(0);
        if summary.last_seq.is_none() || last < self.seq {
            return Err(AuditError::Truncated {
                checkpoint_seq: self.seq,
                log_last_seq: summary.last_seq,
            });
        }

        let observed = head_at_seq.unwrap_or(&summary.head);
        if last == self.seq && observed != self.head {
            return Err(AuditError::CheckpointHeadMismatch {
                expected: self.head.clone(),
                found: observed.to_string(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{verify_chain, AuditLog, NewEntry};
    use countersign_verify::Decision;

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

    fn log_of(n: usize) -> AuditLog {
        let mut log = AuditLog::new();
        for i in 0..n {
            log.append(NewEntry {
                at_unix_ms: 1_700_000_000_000 + i as u64,
                action: "sql.ddl".into(),
                target_kind: "database".into(),
                target_fingerprint: "9f2c".into(),
                environment_label: "prod".into(),
                request_json: format!(
                    r#"{{"action":"sql.execute","nonce":"n{i}","requester":{{"id":"a","instance":"b"}},"statement":"DROP TABLE t{i}","target":{{"kind":"database","uri_fingerprint":"9f2c"}},"ttl_ms":1,"v":1}}"#
                ),
                decision: Decision::Approved,
                severity: None,
                signatures: vec![],
            })
            .unwrap();
        }
        log
    }

    fn checkpoint_for(log: &AuditLog) -> Checkpoint {
        Checkpoint {
            seq: log.entries().last().unwrap().seq,
            head: log.head().unwrap(),
            entries: log.len() as u64,
            at_unix_ms: 1_700_000_000_999,
            signer_id: "aa".repeat(32),
            signature: countersign_verify::encoding::b64url_encode(&[3u8; 64]),
        }
    }

    #[test]
    fn a_checkpoint_accepts_the_log_it_was_taken_from() {
        let log = log_of(5);
        let cp = checkpoint_for(&log);
        cp.check_log(&verify_chain(log.entries()).unwrap(), None)
            .unwrap();
    }

    #[test]
    fn a_checkpoint_catches_a_truncated_log() {
        // The failure the hash chain cannot see on its own.
        let log = log_of(5);
        let cp = checkpoint_for(&log);

        let mut entries = log.entries().to_vec();
        entries.truncate(3);
        let summary = verify_chain(&entries).unwrap();
        assert!(summary.entries == 3, "the truncated chain still links");

        let err = cp.check_log(&summary, None).unwrap_err();
        assert!(
            matches!(
                err,
                AuditError::Truncated {
                    checkpoint_seq: 4,
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn a_checkpoint_catches_a_log_rewritten_to_the_same_length() {
        let log = log_of(3);
        let mut cp = checkpoint_for(&log);
        cp.head = "ff".repeat(32);

        let err = cp
            .check_log(&verify_chain(log.entries()).unwrap(), None)
            .unwrap_err();
        assert!(
            matches!(err, AuditError::CheckpointHeadMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn a_log_that_has_grown_since_the_checkpoint_is_fine() {
        // Checkpoints are periodic; entries arrive between them.
        let log = log_of(3);
        let cp = checkpoint_for(&log);

        let grown = log_of(6);
        cp.check_log(&verify_chain(grown.entries()).unwrap(), None)
            .unwrap();
    }

    #[test]
    fn an_empty_log_fails_a_checkpoint_that_recorded_entries() {
        let log = log_of(3);
        let cp = checkpoint_for(&log);
        let empty = AuditLog::new();
        assert!(cp
            .check_log(&verify_chain(empty.entries()).unwrap(), None)
            .is_err());
    }

    #[test]
    fn checkpoint_signatures_are_checked() {
        let cp = checkpoint_for(&log_of(2));
        assert!(cp.verify(&[0x04; 65], &AlwaysValid).is_ok());
        assert_eq!(
            cp.verify(&[0x04; 65], &NeverValid).unwrap_err(),
            AuditError::CheckpointBadSignature
        );
    }

    #[test]
    fn the_signing_payload_is_domain_separated_and_fixed_width() {
        let tbs = Checkpoint::signing_payload(&"ab".repeat(32), 41, 42, 43).unwrap();
        assert_eq!(tbs.len(), CHECKPOINT_DOMAIN.len() + 32 + 24);
        assert!(tbs.starts_with(b"countersign-audit-v1\0"));
        // Distinct from the approval domain, so neither signature can be
        // replayed as the other.
        assert!(!tbs.starts_with(b"countersign-v1\0"));
    }

    #[test]
    fn a_malformed_head_is_refused_rather_than_padded() {
        assert!(Checkpoint::signing_payload("abcd", 1, 1, 1).is_err());
        assert!(Checkpoint::signing_payload("zz".repeat(32).as_str(), 1, 1, 1).is_err());
    }
}

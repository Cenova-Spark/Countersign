//! The hash-chained log, and the payloads that detach from it.

use countersign_verify::{
    canonicalize, digest_of_json, encoding::hex_encode, Decision, DeviceSignature,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::AuditError;

/// The `prev` of the first entry in a log.
pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One approval, as the log records it.
///
/// **There is no statement in here, and there must never be one.** Everything in
/// this struct is either a digest, an identifier, or a decision — nothing that
/// leaks the contents of a query. That is what makes the chain safe to hand to
/// an auditor, sync to a server, or commit to a repository, and it is why
/// redacting a statement cannot break the chain: the statement was never part
/// of it.
///
/// The statement lives in a detachable [`AuditPayload`], bound to this entry by
/// `request_digest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    /// Hash of the previous entry, or [`GENESIS`].
    pub prev: String,
    pub at_unix_ms: u64,
    /// The namespaced verb, after any pack refinement.
    pub action: String,
    pub target_kind: String,
    pub target_fingerprint: String,
    /// The environment label the daemon assigned — the one the device showed.
    ///
    /// Recorded because "was this production?" is the first question anyone
    /// asks of an audit trail, and because the requester never got to claim it.
    pub environment_label: String,
    pub request_digest: String,
    pub decision: Decision,
    /// The severity the pack (or the fail-closed path) settled on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    #[serde(default)]
    pub signatures: Vec<DeviceSignature>,
}

impl AuditEntry {
    /// This entry's hash: `SHA-256(jcs(entry))`, lowercase hex.
    pub fn hash(&self) -> Result<String, AuditError> {
        let value = serde_json::to_value(self).map_err(|e| AuditError::Malformed(e.to_string()))?;
        let canonical = canonicalize(&value).map_err(AuditError::Jcs)?;
        Ok(hex_encode(&Sha256::digest(canonical.as_bytes())))
    }

    /// Whether this entry records something that was actually authorized.
    pub fn is_approval(&self) -> bool {
        self.decision == Decision::Approved
    }
}

/// The statement behind one entry.
///
/// Detachable on purpose. Drop these and the chain still verifies, the
/// signatures still verify, and the auditor still learns who approved what kind
/// of action, when, on which target — just not the SQL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditPayload {
    pub seq: u64,
    /// The approval request exactly as it was sent, statement and all.
    pub request_json: String,
}

impl AuditPayload {
    /// Confirm this payload is the one the entry's digest commits to.
    ///
    /// This is what makes a detached payload trustworthy later: someone who
    /// holds a statement can prove it is the statement that was approved, and
    /// someone who does not holds a digest that reveals nothing.
    pub fn check_against(&self, entry: &AuditEntry) -> Result<(), AuditError> {
        if self.seq != entry.seq {
            return Err(AuditError::PayloadSeqMismatch {
                payload: self.seq,
                entry: entry.seq,
            });
        }
        let digest = digest_of_json(&self.request_json).map_err(AuditError::Jcs)?;
        if digest != entry.request_digest {
            return Err(AuditError::PayloadDigestMismatch {
                seq: self.seq,
                expected: entry.request_digest.clone(),
                computed: digest,
            });
        }
        Ok(())
    }
}

/// An append-only, hash-chained log.
#[derive(Debug, Clone, Default)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
    payloads: Vec<AuditPayload>,
}

/// Everything needed to append one approval, minus the bookkeeping the log owns.
#[derive(Debug, Clone)]
pub struct NewEntry {
    pub at_unix_ms: u64,
    pub action: String,
    pub target_kind: String,
    pub target_fingerprint: String,
    pub environment_label: String,
    pub request_json: String,
    pub decision: Decision,
    pub severity: Option<String>,
    pub signatures: Vec<DeviceSignature>,
}

impl AuditLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuild from entries and payloads that were read back from storage.
    ///
    /// Verifies the chain before returning, so a caller cannot accidentally
    /// carry on appending to a log that was tampered with — which would bury
    /// the break under valid links.
    pub fn load(entries: Vec<AuditEntry>, payloads: Vec<AuditPayload>) -> Result<Self, AuditError> {
        verify_chain(&entries)?;
        for payload in &payloads {
            let entry = entries
                .iter()
                .find(|e| e.seq == payload.seq)
                .ok_or(AuditError::OrphanPayload(payload.seq))?;
            payload.check_against(entry)?;
        }
        Ok(Self { entries, payloads })
    }

    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    pub fn payloads(&self) -> &[AuditPayload] {
        &self.payloads
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The hash of the most recent entry, or [`GENESIS`] for an empty log.
    pub fn head(&self) -> Result<String, AuditError> {
        match self.entries.last() {
            Some(e) => e.hash(),
            None => Ok(GENESIS.to_string()),
        }
    }

    /// Append one record. Returns the new entry's hash.
    pub fn append(&mut self, new: NewEntry) -> Result<String, AuditError> {
        let prev = self.head()?;
        let seq = self.entries.last().map_or(0, |e| e.seq + 1);

        let request_digest = digest_of_json(&new.request_json).map_err(AuditError::Jcs)?;

        let entry = AuditEntry {
            seq,
            prev,
            at_unix_ms: new.at_unix_ms,
            action: new.action,
            target_kind: new.target_kind,
            target_fingerprint: new.target_fingerprint,
            environment_label: new.environment_label,
            request_digest,
            decision: new.decision,
            severity: new.severity,
            signatures: new.signatures,
        };

        let hash = entry.hash()?;
        self.entries.push(entry);
        self.payloads.push(AuditPayload {
            seq,
            request_json: new.request_json,
        });
        Ok(hash)
    }
}

/// What a chain verification established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainSummary {
    pub entries: usize,
    /// The `prev` of the first entry.
    ///
    /// [`GENESIS`] for a complete log. For a slice — entries 900..1000 of a
    /// long log — this is the hash of entry 899, which this range cannot check.
    /// A verifier holding the earlier range can join them; one that does not
    /// should say so rather than imply the whole history was verified.
    pub anchor: String,
    /// Hash of the last entry, or [`GENESIS`] when empty.
    pub head: String,
    pub first_seq: Option<u64>,
    pub last_seq: Option<u64>,
}

impl ChainSummary {
    /// Whether this range starts at the beginning of the log.
    pub fn is_complete_history(&self) -> bool {
        self.anchor == GENESIS && self.first_seq.map_or(true, |s| s == 0)
    }
}

/// Verify that entries link, and that their sequence numbers are contiguous.
///
/// Detects insertion, reordering, and edits of any recorded field. It does
/// **not** detect truncation of the tail — dropping the last N entries leaves a
/// perfectly valid shorter chain. That is what a
/// [`Checkpoint`](crate::Checkpoint) is for.
pub fn verify_chain(entries: &[AuditEntry]) -> Result<ChainSummary, AuditError> {
    let Some(first) = entries.first() else {
        return Ok(ChainSummary {
            entries: 0,
            anchor: GENESIS.to_string(),
            head: GENESIS.to_string(),
            first_seq: None,
            last_seq: None,
        });
    };

    let anchor = first.prev.clone();
    let mut expected_prev = anchor.clone();
    let mut expected_seq = first.seq;

    for entry in entries {
        if entry.seq != expected_seq {
            return Err(AuditError::SeqGap {
                expected: expected_seq,
                found: entry.seq,
            });
        }
        if entry.prev != expected_prev {
            return Err(AuditError::BrokenLink {
                seq: entry.seq,
                expected: expected_prev,
                found: entry.prev.clone(),
            });
        }
        expected_prev = entry.hash()?;
        expected_seq += 1;
    }

    Ok(ChainSummary {
        entries: entries.len(),
        anchor,
        head: expected_prev,
        first_seq: Some(first.seq),
        last_seq: entries.last().map(|e| e.seq),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_json(statement: &str) -> String {
        format!(
            r#"{{"action":"sql.execute","nonce":"n{}","requester":{{"id":"a","instance":"b"}},"statement":"{statement}","target":{{"kind":"database","uri_fingerprint":"9f2c"}},"ttl_ms":60000,"v":1}}"#,
            statement.len()
        )
    }

    fn new_entry(statement: &str) -> NewEntry {
        NewEntry {
            at_unix_ms: 1_700_000_000_000,
            action: "sql.ddl".into(),
            target_kind: "database".into(),
            target_fingerprint: "9f2c".into(),
            environment_label: "prod-us-east-1".into(),
            request_json: request_json(statement),
            decision: Decision::Approved,
            severity: Some("critical".into()),
            signatures: vec![],
        }
    }

    fn log_of(statements: &[&str]) -> AuditLog {
        let mut log = AuditLog::new();
        for s in statements {
            log.append(new_entry(s)).unwrap();
        }
        log
    }

    #[test]
    fn an_empty_log_heads_at_genesis() {
        let log = AuditLog::new();
        assert_eq!(log.head().unwrap(), GENESIS);
        assert_eq!(verify_chain(log.entries()).unwrap().entries, 0);
    }

    #[test]
    fn entries_link_and_verify() {
        let log = log_of(&["DROP TABLE a", "DROP TABLE b", "DROP TABLE c"]);
        let summary = verify_chain(log.entries()).unwrap();
        assert_eq!(summary.entries, 3);
        assert_eq!(summary.anchor, GENESIS);
        assert_eq!(summary.head, log.head().unwrap());
        assert!(summary.is_complete_history());
    }

    #[test]
    fn no_statement_ever_reaches_the_chain() {
        // The property the whole design rests on. If a statement leaked into an
        // entry, a digests-only export would leak it too, and redacting one
        // would break every link after it.
        let log = log_of(&["DROP TABLE super_secret_table"]);
        let serialized = serde_json::to_string(&log.entries()[0]).unwrap();
        assert!(
            !serialized.contains("super_secret_table"),
            "statement leaked into the chain: {serialized}"
        );
        // But the payload has it, and is bound to the entry.
        assert!(log.payloads()[0]
            .request_json
            .contains("super_secret_table"));
        log.payloads()[0].check_against(&log.entries()[0]).unwrap();
    }

    #[test]
    fn editing_a_recorded_field_breaks_the_chain() {
        // Downgrading "prod" to "staging" after the fact is the edit someone
        // would actually make.
        let mut log = log_of(&["DROP TABLE a", "DROP TABLE b", "DROP TABLE c"]);
        let mut entries = log.entries().to_vec();
        entries[0].environment_label = "staging".into();

        let err = verify_chain(&entries).unwrap_err();
        assert!(
            matches!(err, AuditError::BrokenLink { seq: 1, .. }),
            "got {err:?}"
        );
        let _ = log.append(new_entry("x"));
    }

    #[test]
    fn removing_a_middle_entry_is_detected() {
        let log = log_of(&["a", "b", "c"]);
        let mut entries = log.entries().to_vec();
        entries.remove(1);
        assert!(matches!(
            verify_chain(&entries),
            Err(AuditError::SeqGap { .. })
        ));
    }

    #[test]
    fn reordering_entries_is_detected() {
        let log = log_of(&["a", "b", "c"]);
        let mut entries = log.entries().to_vec();
        entries.swap(1, 2);
        assert!(verify_chain(&entries).is_err());
    }

    #[test]
    fn truncating_the_tail_is_not_detected_by_the_chain_alone() {
        // Stated as a test because it is the chain's one real limitation, and
        // the reason checkpoints exist. A shorter chain is still a valid chain.
        let log = log_of(&["a", "b", "c"]);
        let mut entries = log.entries().to_vec();
        entries.pop();
        assert!(
            verify_chain(&entries).is_ok(),
            "a truncated log still links"
        );
    }

    #[test]
    fn a_slice_verifies_internally_and_admits_it_is_a_slice() {
        // Exporting entries 1.. of a longer log is legitimate; claiming it is
        // the complete history is not.
        let log = log_of(&["a", "b", "c"]);
        let slice = &log.entries()[1..];
        let summary = verify_chain(slice).unwrap();
        assert_eq!(summary.entries, 2);
        assert_ne!(summary.anchor, GENESIS);
        assert!(
            !summary.is_complete_history(),
            "a slice is not the whole history"
        );
    }

    #[test]
    fn a_payload_that_does_not_match_its_entry_is_refused() {
        let log = log_of(&["DROP TABLE a"]);
        let mut payload = log.payloads()[0].clone();
        payload.request_json = payload.request_json.replace("DROP TABLE a", "DROP TABLE b");

        let err = payload.check_against(&log.entries()[0]).unwrap_err();
        assert!(
            matches!(err, AuditError::PayloadDigestMismatch { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn loading_a_tampered_log_fails_rather_than_appending_over_the_break() {
        let log = log_of(&["a", "b"]);
        let mut entries = log.entries().to_vec();
        entries[0].action = "sql.read".into();
        assert!(AuditLog::load(entries, vec![]).is_err());
    }

    #[test]
    fn loading_a_payload_with_no_entry_is_refused() {
        let log = log_of(&["a"]);
        let orphan = AuditPayload {
            seq: 99,
            request_json: request_json("a"),
        };
        assert!(matches!(
            AuditLog::load(log.entries().to_vec(), vec![orphan]),
            Err(AuditError::OrphanPayload(99))
        ));
    }

    #[test]
    fn a_reloaded_log_continues_the_same_chain() {
        let log = log_of(&["a", "b"]);
        let head = log.head().unwrap();
        let mut reloaded = AuditLog::load(log.entries().to_vec(), log.payloads().to_vec()).unwrap();
        reloaded.append(new_entry("c")).unwrap();

        assert_eq!(reloaded.entries()[2].prev, head);
        assert_eq!(reloaded.entries()[2].seq, 2);
        assert!(verify_chain(reloaded.entries()).is_ok());
    }
}

//! The Countersign audit trail: hash-chained, tamper-evident, and exportable
//! without disclosing a single query.
//!
//! # The tension this resolves
//!
//! A compliance owner wants "who approved what, when, and can you prove it",
//! ideally somewhere central. The statements that would answer it are
//! production SQL — table names and literal values, which means customer data.
//! Syncing that to a server is exactly what a regulated shop cannot do, and
//! keeping it only on one laptop is exactly what an auditor will not accept.
//!
//! The resolution is structural rather than a policy toggle:
//!
//! * The **chain** ([`AuditEntry`]) contains only digests, identifiers and
//!   decisions. No statement ever enters it.
//! * The **payloads** ([`AuditPayload`]) hold the statements, bound to the chain
//!   by `request_digest`, and detach cleanly.
//!
//! So a [`Disclosure::DigestsOnly`] export is *fully verifiable*: every link
//! checks, every signature verifies (see
//! [`countersign_verify::verify_signatures`]), and every approval names the
//! human who gave it — while revealing nothing about what was run. Someone who
//! later obtains a statement can prove it is the one that was approved; someone
//! who does not learns nothing from the digest.
//!
//! This is why redaction cannot break anything here. There is nothing to
//! redact — the sensitive material was never in the part that gets shared.
//!
//! # What is tamper-evident, and what is not
//!
//! [`verify_chain`] detects insertion, reordering, and edits to any recorded
//! field. It does **not** detect truncation of the tail: a shorter chain is a
//! valid chain. [`Checkpoint`] closes that, and its own limits are documented
//! honestly in that module — a daemon-signed checkpoint defends against
//! everyone except the machine holding the daemon key.
//!
//! ```
//! use countersign_audit::{AuditLog, Disclosure, NewEntry};
//! use countersign_verify::Decision;
//!
//! let mut log = AuditLog::new();
//! log.append(NewEntry {
//!     at_unix_ms: 1_755_859_200_123,
//!     action: "sql.ddl".into(),
//!     target_kind: "database".into(),
//!     target_fingerprint: "9f2c".into(),
//!     environment_label: "prod-us-east-1".into(),
//!     request_json: r#"{"action":"sql.execute","nonce":"n","requester":{"id":"a","instance":"b"},"statement":"DROP TABLE users;","target":{"kind":"database","uri_fingerprint":"9f2c"},"ttl_ms":60000,"v":1}"#.into(),
//!     decision: Decision::Approved,
//!     severity: Some("critical".into()),
//!     signatures: vec![],
//! }).unwrap();
//!
//! let shareable = log.export(Disclosure::DigestsOnly, None);
//! assert!(shareable.payloads.is_empty());
//! assert!(!serde_json::to_string(&shareable).unwrap().contains("DROP TABLE"));
//! ```

#![forbid(unsafe_code)]

pub mod chain;
pub mod checkpoint;

use countersign_verify::JcsError;
use serde::{Deserialize, Serialize};

pub use chain::{
    verify_chain, AuditEntry, AuditLog, AuditPayload, ChainSummary, NewEntry, GENESIS,
};
pub use checkpoint::Checkpoint;

/// How much an export reveals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Disclosure {
    /// The chain alone: who approved what kind of action, when, on which
    /// target, in which environment — cryptographically verifiable, and
    /// carrying no query text.
    ///
    /// **This is the one that should sync.** A relay, a compliance system or a
    /// backup can hold it without becoming a custodian of anyone's queries.
    DigestsOnly,
    /// The chain plus the statements. Everything an operator needs to
    /// reconstruct what happened, and everything a leak would expose.
    WithStatements,
}

/// A portable slice of an audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditExport {
    pub v: u8,
    pub disclosure: Disclosure,
    pub entries: Vec<AuditEntry>,
    /// Empty under [`Disclosure::DigestsOnly`].
    #[serde(default)]
    pub payloads: Vec<AuditPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<Checkpoint>,
}

impl AuditLog {
    /// Export the whole log.
    pub fn export(&self, disclosure: Disclosure, checkpoint: Option<Checkpoint>) -> AuditExport {
        self.export_range(.., disclosure, checkpoint)
    }

    /// Export a contiguous range of entries by index.
    ///
    /// A partial export is legitimate — a year's log is not a single email
    /// attachment — and [`ChainSummary::is_complete_history`] is how the
    /// receiver tells a slice from the whole thing.
    pub fn export_range(
        &self,
        range: impl std::slice::SliceIndex<[AuditEntry], Output = [AuditEntry]> + Clone,
        disclosure: Disclosure,
        checkpoint: Option<Checkpoint>,
    ) -> AuditExport {
        let entries = self.entries()[range].to_vec();
        let payloads = match disclosure {
            Disclosure::DigestsOnly => Vec::new(),
            Disclosure::WithStatements => {
                let lo = entries.first().map(|e| e.seq);
                let hi = entries.last().map(|e| e.seq);
                self.payloads()
                    .iter()
                    .filter(|p| match (lo, hi) {
                        (Some(lo), Some(hi)) => p.seq >= lo && p.seq <= hi,
                        _ => false,
                    })
                    .cloned()
                    .collect()
            }
        };

        AuditExport {
            v: 1,
            disclosure,
            entries,
            payloads,
            checkpoint,
        }
    }
}

impl AuditExport {
    /// Verify the chain, any payloads present, and any checkpoint.
    ///
    /// Signature verification is deliberately *not* done here — it needs a
    /// registry and a signature backend, which are the caller's to supply. See
    /// [`countersign_verify::verify_signatures`], which works from
    /// [`AuditEntry::request_digest`] and therefore works on a digests-only
    /// export.
    pub fn verify(&self) -> Result<ChainSummary, AuditError> {
        let summary = verify_chain(&self.entries)?;

        if self.disclosure == Disclosure::DigestsOnly && !self.payloads.is_empty() {
            return Err(AuditError::DisclosureMismatch);
        }

        for payload in &self.payloads {
            let entry = self
                .entries
                .iter()
                .find(|e| e.seq == payload.seq)
                .ok_or(AuditError::OrphanPayload(payload.seq))?;
            payload.check_against(entry)?;
        }

        if let Some(cp) = &self.checkpoint {
            cp.check_log(&summary, None)?;
        }

        Ok(summary)
    }

    /// Drop every statement, turning a full export into a shareable one.
    #[must_use]
    pub fn redacted(mut self) -> Self {
        self.payloads.clear();
        self.disclosure = Disclosure::DigestsOnly;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditError {
    SeqGap {
        expected: u64,
        found: u64,
    },
    BrokenLink {
        seq: u64,
        expected: String,
        found: String,
    },
    PayloadSeqMismatch {
        payload: u64,
        entry: u64,
    },
    PayloadDigestMismatch {
        seq: u64,
        expected: String,
        computed: String,
    },
    OrphanPayload(u64),
    /// A digests-only export that carries statements anyway.
    DisclosureMismatch,
    Truncated {
        checkpoint_seq: u64,
        log_last_seq: Option<u64>,
    },
    CheckpointHeadMismatch {
        expected: String,
        found: String,
    },
    CheckpointBadSignature,
    /// The checkpoint signature is not low-S (spec §4).
    CheckpointNotLowS,
    Jcs(JcsError),
    Malformed(String),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use AuditError::*;
        match self {
            SeqGap { expected, found } => {
                write!(
                    f,
                    "expected entry {expected}, found {found} — an entry is missing"
                )
            }
            BrokenLink { seq, .. } => {
                write!(
                    f,
                    "entry {seq} does not follow the one before it — the log was altered"
                )
            }
            PayloadSeqMismatch { payload, entry } => {
                write!(f, "payload {payload} was checked against entry {entry}")
            }
            PayloadDigestMismatch { seq, .. } => write!(
                f,
                "the statement supplied for entry {seq} is not the statement that was approved"
            ),
            OrphanPayload(seq) => write!(f, "payload {seq} has no matching entry"),
            DisclosureMismatch => f.write_str("export claims digests-only but carries statements"),
            Truncated {
                checkpoint_seq,
                log_last_seq,
            } => write!(
                f,
                "checkpoint covers entry {checkpoint_seq} but the log ends at {log_last_seq:?} — \
                 entries have been removed"
            ),
            CheckpointHeadMismatch { .. } => {
                f.write_str("the log's head does not match the checkpoint — history was rewritten")
            }
            CheckpointBadSignature => f.write_str("checkpoint signature did not verify"),
            CheckpointNotLowS => f.write_str("checkpoint signature is not low-S"),
            Jcs(e) => write!(f, "{e}"),
            Malformed(m) => write!(f, "malformed: {m}"),
        }
    }
}

impl std::error::Error for AuditError {}

impl From<JcsError> for AuditError {
    fn from(e: JcsError) -> Self {
        AuditError::Jcs(e)
    }
}

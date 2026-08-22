//! The audit trail on disk.
//!
//! Two files, because the chain and the statements have different natural
//! retention and different sensitivity:
//!
//! * `chain.jsonl` — digests, identifiers, decisions. Safe to sync, safe to
//!   hand to an auditor, and the half that should be kept for as long as anyone
//!   might ask.
//! * `payloads.jsonl` — the statements. The sensitive half, and usually the one
//!   that should expire first.
//!
//! Deleting `payloads.jsonl` is a supported operation: the chain still verifies,
//! every signature still verifies, and every approval still names the human who
//! gave it. That is the property the whole split exists for, so it has a test.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use countersign_audit::{AuditEntry, AuditError, AuditLog, AuditPayload, NewEntry};

/// An append-only audit trail backed by two line-delimited JSON files.
#[derive(Debug)]
pub struct AuditStore {
    log: AuditLog,
    chain_path: PathBuf,
    payload_path: PathBuf,
}

impl AuditStore {
    /// Open (or create) a trail in `dir`, verifying whatever is already there.
    ///
    /// A tampered log fails here rather than being appended to, which is the
    /// point: continuing would bury the break under fresh, valid links.
    pub fn open(dir: &Path) -> Result<Self, StoreError> {
        std::fs::create_dir_all(dir)
            .map_err(|e| StoreError::Io(dir.to_path_buf(), e.to_string()))?;
        let chain_path = dir.join("chain.jsonl");
        let payload_path = dir.join("payloads.jsonl");

        let entries: Vec<AuditEntry> = read_lines(&chain_path)?;
        let payloads: Vec<AuditPayload> = read_lines(&payload_path)?;

        // Payloads may legitimately have been expired while the chain was kept,
        // so only keep the ones whose entry is still present.
        let payloads = payloads
            .into_iter()
            .filter(|p| entries.iter().any(|e| e.seq == p.seq))
            .collect();

        let log = AuditLog::load(entries, payloads).map_err(StoreError::Audit)?;
        Ok(Self {
            log,
            chain_path,
            payload_path,
        })
    }

    pub fn log(&self) -> &AuditLog {
        &self.log
    }

    pub fn len(&self) -> usize {
        self.log.len()
    }

    pub fn is_empty(&self) -> bool {
        self.log.is_empty()
    }

    /// Append one record and flush both files before returning.
    ///
    /// Flushed rather than buffered because the interesting crash is the one
    /// right after a destructive statement was approved, and a trail missing
    /// exactly that entry is worse than no trail.
    pub fn append(&mut self, new: NewEntry) -> Result<String, StoreError> {
        let hash = self.log.append(new).map_err(StoreError::Audit)?;

        let entry = self.log.entries().last().expect("just appended");
        append_line(&self.chain_path, entry)?;

        if let Some(payload) = self.log.payloads().last() {
            if payload.seq == entry.seq {
                append_line(&self.payload_path, payload)?;
            }
        }

        Ok(hash)
    }
}

fn read_lines<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Vec<T>, StoreError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let file =
        std::fs::File::open(path).map_err(|e| StoreError::Io(path.to_path_buf(), e.to_string()))?;
    let mut out = Vec::new();
    for (index, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(|e| StoreError::Io(path.to_path_buf(), e.to_string()))?;
        if line.trim().is_empty() {
            continue;
        }
        out.push(
            serde_json::from_str(&line).map_err(|e| StoreError::Corrupt {
                path: path.to_path_buf(),
                line: index + 1,
                message: e.to_string(),
            })?,
        );
    }
    Ok(out)
}

fn append_line<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), StoreError> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| StoreError::Io(path.to_path_buf(), e.to_string()))?;
    let line = serde_json::to_string(value)
        .map_err(|e| StoreError::Io(path.to_path_buf(), e.to_string()))?;
    writeln!(file, "{line}").map_err(|e| StoreError::Io(path.to_path_buf(), e.to_string()))?;
    file.flush()
        .map_err(|e| StoreError::Io(path.to_path_buf(), e.to_string()))?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    Io(PathBuf, String),
    Corrupt {
        path: PathBuf,
        line: usize,
        message: String,
    },
    Audit(AuditError),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(p, e) => write!(f, "{}: {e}", p.display()),
            StoreError::Corrupt {
                path,
                line,
                message,
            } => {
                write!(f, "{}:{line}: {message}", path.display())
            }
            StoreError::Audit(e) => write!(f, "audit trail is not intact: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

#[cfg(test)]
mod tests {
    use super::*;
    use countersign_verify::Decision;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("countersign-audit-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn entry(i: u64, statement: &str) -> NewEntry {
        NewEntry {
            at_unix_ms: 1_700_000_000_000 + i,
            action: "sql.ddl".into(),
            target_kind: "database".into(),
            target_fingerprint: "9f2c".into(),
            environment_label: "prod-us-east-1".into(),
            request_json: format!(
                r#"{{"action":"sql.execute","nonce":"n{i}","requester":{{"id":"a","instance":"b"}},"statement":"{statement}","target":{{"kind":"database","uri_fingerprint":"9f2c"}},"ttl_ms":1,"v":1}}"#
            ),
            decision: Decision::Approved,
            severity: Some("critical".into()),
            signatures: vec![],
        }
    }

    #[test]
    fn entries_survive_a_restart_and_keep_chaining() {
        let dir = temp_dir("restart");
        {
            let mut store = AuditStore::open(&dir).unwrap();
            store.append(entry(0, "DROP TABLE a")).unwrap();
            store.append(entry(1, "DROP TABLE b")).unwrap();
            assert_eq!(store.len(), 2);
        }

        let mut reopened = AuditStore::open(&dir).unwrap();
        assert_eq!(reopened.len(), 2, "the trail must survive a restart");
        reopened.append(entry(2, "DROP TABLE c")).unwrap();
        assert_eq!(reopened.log().entries()[2].seq, 2);
        assert_eq!(
            reopened.log().entries()[2].prev,
            reopened.log().entries()[1].hash().unwrap()
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn expiring_the_statements_leaves_a_trail_that_still_verifies() {
        // The operation the two-file split exists to make safe.
        let dir = temp_dir("expire");
        {
            let mut store = AuditStore::open(&dir).unwrap();
            store.append(entry(0, "DROP TABLE super_secret")).unwrap();
            store.append(entry(1, "DELETE FROM patients")).unwrap();
        }

        std::fs::remove_file(dir.join("payloads.jsonl")).unwrap();

        let store = AuditStore::open(&dir).expect("the chain alone must still load");
        assert_eq!(store.len(), 2);
        assert!(countersign_audit::verify_chain(store.log().entries()).is_ok());

        let chain = std::fs::read_to_string(dir.join("chain.jsonl")).unwrap();
        assert!(
            !chain.contains("super_secret"),
            "no statement may be in the chain file"
        );
        assert!(!chain.contains("patients"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_tampered_chain_refuses_to_open() {
        // Appending over a break would bury it under fresh valid links.
        let dir = temp_dir("tampered");
        {
            let mut store = AuditStore::open(&dir).unwrap();
            store.append(entry(0, "DROP TABLE a")).unwrap();
            store.append(entry(1, "DROP TABLE b")).unwrap();
        }

        let path = dir.join("chain.jsonl");
        let text = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, text.replace("prod-us-east-1", "local")).unwrap();

        let err = AuditStore::open(&dir).unwrap_err();
        assert!(matches!(err, StoreError::Audit(_)), "got {err:?}");
        assert!(err.to_string().contains("not intact"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_corrupt_line_names_the_file_and_the_line() {
        let dir = temp_dir("corrupt");
        {
            let mut store = AuditStore::open(&dir).unwrap();
            store.append(entry(0, "DROP TABLE a")).unwrap();
        }
        let path = dir.join("chain.jsonl");
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("{not json}\n");
        std::fs::write(&path, text).unwrap();

        let err = AuditStore::open(&dir).unwrap_err();
        assert!(
            matches!(err, StoreError::Corrupt { line: 2, .. }),
            "got {err:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_directory_opens_as_an_empty_trail() {
        let dir = temp_dir("empty");
        let store = AuditStore::open(&dir).unwrap();
        assert!(store.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

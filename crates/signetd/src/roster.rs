//! The operator's own devices — the *direct* trust model.
//!
//! Enrollment spec §7 names two models. An organisation runs a **roster**: a
//! signed list issued by an authority key, verifiable anywhere. One person
//! with their own machine runs **direct**: the records live in a file the
//! daemon owns, and the trust root is the filesystem the daemon already trusts
//! for its config and its audit trail.
//!
//! This is the second one. `~/.config/countersign/roster.json` holds the
//! enrollment records of every device this daemon will accept a signature
//! from — the Mac app's enclave key, a paired phone's, one day a Signet's.
//! Each record carries its proof, because the ceremony that produced it is
//! the only evidence the key can sign at all (device-class spec §4), and a
//! roster that dropped proofs would be a list of public keys, which anyone can
//! write.
//!
//! Records are never removed. Revocation is a status change with a timestamp
//! and a counter, so an audit of last year still resolves the device that
//! signed to the person who held it then (enrollment spec §5).

use std::path::{Path, PathBuf};

use countersign_verify::{
    DeviceClass, DeviceStatus, EnrolledDevice, EnrollmentError, EnrollmentRecord, Registry,
    RustCryptoBackend,
};
use serde::{Deserialize, Serialize};

/// The file's name inside the config directory.
pub const FILE_NAME: &str = "roster.json";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalRoster {
    pub v: u8,
    #[serde(default)]
    pub records: Vec<EnrollmentRecord>,
}

impl LocalRoster {
    pub fn path_in(config_dir: &Path) -> PathBuf {
        config_dir.join(FILE_NAME)
    }

    /// Load, or start empty if the file does not exist yet.
    ///
    /// Every record is checked on the way in — its id derives from its key,
    /// its class agrees with its flag, and its proof verifies against its own
    /// key. A roster that fails any of that is refused whole rather than
    /// trimmed to the records that pass, because a file the daemon wrote
    /// itself should never be in that state, and one that is has been edited.
    pub fn load(config_dir: &Path) -> Result<Self, RosterError> {
        let path = Self::path_in(config_dir);
        if !path.exists() {
            return Ok(Self {
                v: 1,
                records: Vec::new(),
            });
        }
        let text =
            std::fs::read_to_string(&path).map_err(|e| RosterError::Io(path.clone(), e.to_string()))?;
        let roster: Self =
            serde_json::from_str(&text).map_err(|e| RosterError::Parse(path.clone(), e.to_string()))?;
        for record in &roster.records {
            record
                .verify_proof(&RustCryptoBackend)
                .map_err(|e| RosterError::Record(record.device_id.clone(), e))?;
        }
        Ok(roster)
    }

    /// Write atomically — temp file, then rename — and `0600`.
    pub fn save(&self, config_dir: &Path) -> Result<(), RosterError> {
        std::fs::create_dir_all(config_dir)
            .map_err(|e| RosterError::Io(config_dir.to_path_buf(), e.to_string()))?;
        let path = Self::path_in(config_dir);
        let temp = path.with_extension("json.tmp");
        let mut text = serde_json::to_string_pretty(self)
            .map_err(|e| RosterError::Parse(path.clone(), e.to_string()))?;
        text.push('\n');
        std::fs::write(&temp, text).map_err(|e| RosterError::Io(temp.clone(), e.to_string()))?;
        restrict(&temp)?;
        std::fs::rename(&temp, &path).map_err(|e| RosterError::Io(path, e.to_string()))
    }

    pub fn get(&self, device_id: &str) -> Option<&EnrollmentRecord> {
        self.records.iter().find(|r| r.device_id == device_id)
    }

    /// Add a record, after checking it the same way `load` would.
    ///
    /// Re-enrolling a device that is already here replaces its record, which
    /// is the "silent re-enrollment" enrollment spec §8 forbids — so it is
    /// refused unless the subject is unchanged, and even then the new proof
    /// must verify. Changing whose device this is takes a revocation and a
    /// fresh enrollment under the new name.
    pub fn enroll(&mut self, record: EnrollmentRecord) -> Result<(), RosterError> {
        record
            .verify_proof(&RustCryptoBackend)
            .map_err(|e| RosterError::Record(record.device_id.clone(), e))?;
        if let Some(existing) = self.get(&record.device_id) {
            if existing.operator.subject != record.operator.subject {
                return Err(RosterError::SubjectChanged {
                    device_id: record.device_id.clone(),
                    was: existing.operator.subject.clone(),
                    now: record.operator.subject.clone(),
                });
            }
            if !existing.status.is_active() {
                return Err(RosterError::Revoked(record.device_id.clone()));
            }
        }
        self.records.retain(|r| r.device_id != record.device_id);
        self.records.push(record);
        Ok(())
    }

    /// Revoke one device. Returns whether anything changed.
    pub fn revoke(
        &mut self,
        device_id: &str,
        at_unix_ms: u64,
        at_counter: Option<u64>,
        reason: Option<String>,
    ) -> bool {
        match self.records.iter_mut().find(|r| r.device_id == device_id) {
            Some(record) if record.status.is_active() => {
                record.status = DeviceStatus::Revoked {
                    at_unix_ms,
                    at_counter,
                    reason,
                };
                true
            }
            _ => false,
        }
    }

    /// The registry a verifier uses — every record, active or not, with the
    /// revocation status carried across so `Acceptance` can read it.
    pub fn registry(&self) -> Result<Registry, EnrollmentError> {
        let mut registry = Registry::new();
        for record in &self.records {
            registry.enroll(EnrolledDevice::from_record(record)?);
        }
        Ok(registry)
    }

    /// Active devices of one class.
    pub fn active_of_class(&self, class: DeviceClass) -> Vec<&EnrollmentRecord> {
        self.records
            .iter()
            .filter(|r| r.status.is_active() && r.class() == class)
            .collect()
    }
}

#[cfg(unix)]
fn restrict(path: &Path) -> Result<(), RosterError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| RosterError::Io(path.to_path_buf(), e.to_string()))
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> Result<(), RosterError> {
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RosterError {
    Io(PathBuf, String),
    Parse(PathBuf, String),
    Record(String, EnrollmentError),
    SubjectChanged {
        device_id: String,
        was: String,
        now: String,
    },
    Revoked(String),
}

impl std::fmt::Display for RosterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use RosterError::*;
        match self {
            Io(p, e) => write!(f, "{}: {e}", p.display()),
            Parse(p, e) => write!(f, "{} is not a roster: {e}", p.display()),
            Record(id, e) => write!(f, "record for device {id} is not acceptable: {e}"),
            SubjectChanged { device_id, was, now } => write!(
                f,
                "device {device_id} is enrolled to {was}, not {now}. Changing whose device it is \
                 takes a revocation and a fresh enrollment, never a rewrite"
            ),
            Revoked(id) => write!(
                f,
                "device {id} was revoked; a revoked key stays revoked. Enroll a fresh key instead"
            ),
        }
    }
}

impl std::error::Error for RosterError {}

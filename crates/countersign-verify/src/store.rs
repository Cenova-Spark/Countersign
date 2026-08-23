//! Durable high-water marks.
//!
//! Two things in this protocol are only defences if they survive a restart:
//!
//! * **Device counters.** A verifier that forgets the highest counter it has
//!   seen accepts a replayed approval once per restart.
//! * **Roster serials.** A verifier that forgets the highest serial it has
//!   accepted can be handed yesterday's signed roster, and every revocation in
//!   between quietly comes back.
//!
//! Both are "the largest number I have seen for this id", so both live here.
//!
//! # Persist before you succeed
//!
//! [`CounterStore::record`](crate::CounterStore::record) returns a `Result`, and
//! verification fails if it returns an error. That is the whole design of this
//! module in one sentence: **accepting an approval you cannot remember is
//! strictly worse than refusing it.** A full disk must produce a refusal, not a
//! silent replay window.
//!
//! # Crash safety
//!
//! Writes go to a temporary file, are flushed to disk, and are then renamed over
//! the real one. Rename is atomic on POSIX, so a crash at any point leaves
//! either the complete previous state or the complete new state — never a
//! half-written file that fails to parse on the way back up.
//!
//! A crash between accepting an approval and persisting its counter would lose
//! the record, which is exactly why the persist happens first.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::enrollment::RosterStore;
use crate::verify::CounterStore;

/// Why a high-water mark could not be read or written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    Io(PathBuf, String),
    /// The file exists and could not be parsed.
    ///
    /// Deliberately fatal rather than "start empty". A store we cannot read is
    /// a store whose contents we do not know, and the safe reading of that is
    /// not "nothing has happened yet".
    Corrupt(PathBuf, String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(path, e) => write!(f, "{}: {e}", path.display()),
            StoreError::Corrupt(path, e) => write!(
                f,
                "{} is unreadable ({e}). Refusing to start with an empty replay history — \
                 inspect the file rather than deleting it",
                path.display()
            ),
        }
    }
}

impl std::error::Error for StoreError {}

/// A file-backed map of `id → highest value seen`.
///
/// Implements both [`CounterStore`] and [`RosterStore`]. Use two of them, one
/// file each — device counters and roster serials are different facts and a
/// shared file would let one rewrite the other.
#[derive(Debug, Clone)]
pub struct FileStore {
    path: PathBuf,
    marks: BTreeMap<String, u64>,
}

impl FileStore {
    /// Open a store, creating the parent directory and reading any existing
    /// state.
    ///
    /// A missing file is an empty store. An unreadable one is an error — see
    /// [`StoreError::Corrupt`].
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| StoreError::Io(parent.to_path_buf(), e.to_string()))?;
            }
        }

        let marks = match std::fs::read_to_string(&path) {
            Ok(text) if text.trim().is_empty() => BTreeMap::new(),
            Ok(text) => serde_json::from_str(&text)
                .map_err(|e| StoreError::Corrupt(path.clone(), e.to_string()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(StoreError::Io(path.clone(), e.to_string())),
        };

        Ok(Self { path, marks })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn len(&self) -> usize {
        self.marks.len()
    }

    pub fn is_empty(&self) -> bool {
        self.marks.is_empty()
    }

    pub fn get(&self, id: &str) -> Option<u64> {
        self.marks.get(id).copied()
    }

    /// Raise `id`'s mark to at least `value`, and persist before returning.
    ///
    /// A mark never goes down: a caller recording an older value is a no-op
    /// rather than a regression, so a replayed bundle cannot lower the bar for
    /// the next one.
    pub fn raise(&mut self, id: &str, value: u64) -> Result<(), StoreError> {
        let current = self.marks.get(id).copied().unwrap_or(0);
        if current >= value && self.marks.contains_key(id) {
            return Ok(());
        }
        self.marks.insert(id.to_string(), current.max(value));
        self.persist()
    }

    /// Write atomically: temp file, flush to disk, rename over the original.
    fn persist(&self) -> Result<(), StoreError> {
        let text = serde_json::to_string_pretty(&self.marks)
            .map_err(|e| StoreError::Io(self.path.clone(), e.to_string()))?;

        // Named from the real path so two stores in one directory cannot
        // collide on a temp file and overwrite each other's state.
        let temp = self.path.with_extension("tmp");

        {
            let mut file = std::fs::File::create(&temp)
                .map_err(|e| StoreError::Io(temp.clone(), e.to_string()))?;
            file.write_all(text.as_bytes())
                .map_err(|e| StoreError::Io(temp.clone(), e.to_string()))?;
            file.write_all(b"\n")
                .map_err(|e| StoreError::Io(temp.clone(), e.to_string()))?;
            // Flushed to the device, not just to the page cache. Without this
            // the rename can land before the contents do, and a power loss
            // leaves an atomically-renamed empty file.
            file.sync_all()
                .map_err(|e| StoreError::Io(temp.clone(), e.to_string()))?;
        }

        std::fs::rename(&temp, &self.path)
            .map_err(|e| StoreError::Io(self.path.clone(), e.to_string()))?;
        Ok(())
    }
}

impl CounterStore for FileStore {
    fn highest(&self, device_id: &str) -> Option<u64> {
        self.get(device_id)
    }

    fn record(&mut self, device_id: &str, counter: u64) -> Result<(), StoreError> {
        self.raise(device_id, counter)
    }
}

impl RosterStore for FileStore {
    fn highest_serial(&self, authority_id: &str) -> Option<u64> {
        self.get(authority_id)
    }

    fn record_serial(&mut self, authority_id: &str, serial: u64) -> Result<(), StoreError> {
        self.raise(authority_id, serial)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("cs-store-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn a_mark_survives_a_restart() {
        // The entire point. Without this a verifier accepts a replayed approval
        // once per restart.
        let dir = temp_dir("restart");
        let path = dir.join("counters.json");

        let mut store = FileStore::open(&path).unwrap();
        store.record("device-a", 41_235).unwrap();
        drop(store);

        let reopened = FileStore::open(&path).unwrap();
        assert_eq!(reopened.highest("device-a"), Some(41_235));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_mark_never_goes_backwards() {
        let dir = temp_dir("monotonic");
        let mut store = FileStore::open(dir.join("c.json")).unwrap();

        store.record("d", 100).unwrap();
        store.record("d", 40).unwrap();
        assert_eq!(
            store.highest("d"),
            Some(100),
            "an older value must not lower the bar"
        );

        store.record("d", 101).unwrap();
        assert_eq!(store.highest("d"), Some(101));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_counter_of_zero_is_remembered_as_seen() {
        // `Some(0)` and `None` mean different things: "I have seen this device
        // at counter 0" versus "I have never seen it". Collapsing them would
        // let counter 0 be replayed once.
        let dir = temp_dir("zero");
        let path = dir.join("c.json");

        let mut store = FileStore::open(&path).unwrap();
        store.record("d", 0).unwrap();
        assert_eq!(store.highest("d"), Some(0));

        let reopened = FileStore::open(&path).unwrap();
        assert_eq!(reopened.highest("d"), Some(0), "and it survives a restart");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn devices_do_not_share_a_mark() {
        let dir = temp_dir("separate");
        let mut store = FileStore::open(dir.join("c.json")).unwrap();
        store.record("a", 10).unwrap();
        store.record("b", 3).unwrap();

        assert_eq!(store.highest("a"), Some(10));
        assert_eq!(store.highest("b"), Some(3));
        assert_eq!(store.highest("c"), None);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_file_is_an_empty_store_and_a_corrupt_one_is_not() {
        let dir = temp_dir("corrupt");
        let path = dir.join("c.json");

        // Missing: fine, nothing has happened yet.
        assert!(FileStore::open(&path).unwrap().is_empty());

        // Corrupt: refuse. A store we cannot read is one whose contents we do
        // not know, and the safe reading of that is not "nothing has happened".
        std::fs::write(&path, "{not json").unwrap();
        let err = FileStore::open(&path).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt(..)), "got {err:?}");
        assert!(
            err.to_string().contains("rather than deleting"),
            "the message should not invite the destructive fix: {err}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_temporary_file_is_left_behind() {
        // A stale `.tmp` beside the store invites someone to wonder which one
        // is real.
        let dir = temp_dir("tmp");
        let path = dir.join("c.json");
        let mut store = FileStore::open(&path).unwrap();
        store.record("d", 1).unwrap();

        assert!(path.exists());
        assert!(!path.with_extension("tmp").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn two_stores_in_one_directory_do_not_overwrite_each_other() {
        // Device counters and roster serials are different facts, kept in
        // different files, and their temp files must not collide.
        let dir = temp_dir("two");
        let mut counters = FileStore::open(dir.join("counters.json")).unwrap();
        let mut serials = FileStore::open(dir.join("serials.json")).unwrap();

        counters.record("device", 7).unwrap();
        serials.record_serial("authority", 3).unwrap();

        let counters = FileStore::open(dir.join("counters.json")).unwrap();
        let serials = FileStore::open(dir.join("serials.json")).unwrap();
        assert_eq!(counters.highest("device"), Some(7));
        assert_eq!(serials.highest_serial("authority"), Some(3));
        assert_eq!(
            counters.highest("authority"),
            None,
            "the files are separate"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_same_store_serves_counters_and_roster_serials() {
        let dir = temp_dir("both-traits");
        let mut store = FileStore::open(dir.join("s.json")).unwrap();

        CounterStore::record(&mut store, "device", 5).unwrap();
        RosterStore::record_serial(&mut store, "authority", 9).unwrap();

        assert_eq!(CounterStore::highest(&store, "device"), Some(5));
        assert_eq!(RosterStore::highest_serial(&store, "authority"), Some(9));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_write_that_cannot_land_is_an_error_rather_than_a_silent_loss() {
        // The failure this module exists to surface. A store that swallowed a
        // write would report success for an approval it could not remember.
        let dir = temp_dir("readonly");
        let path = dir.join("c.json");
        let mut store = FileStore::open(&path).unwrap();
        store.record("d", 1).unwrap();

        // Remove the directory out from under it.
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            store.record("d", 2).is_err(),
            "a write that cannot land must be reported, not swallowed"
        );
    }
}

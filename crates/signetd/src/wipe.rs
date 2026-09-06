//! `signetd wipe` — a fresh start, for demos and development.
//!
//! Everything the daemon and the hook write, gone: the roster, the audit
//! trail, the installed plugins and their switches, the hook's replay state,
//! the counters of the mock, relay and app devices, and the relay pairing.
//! Two things stay. `config.toml` is the operator's, not the daemon's — it is
//! configuration, and a demo that wiped its own policy would have nothing to
//! show. And the Mac app's enclave key lives in the keychain under the app's
//! identity, out of this process's reach; the app forgets it itself and asks
//! this for the rest.
//!
//! The command refuses while a daemon is listening. A running daemon holds
//! the roster and the chain in memory and would write them straight back,
//! and a wipe that half-worked is the kind of state nobody can reason about.

use std::path::{Path, PathBuf};

/// One thing a wipe removes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub what: &'static str,
    pub path: PathBuf,
}

impl Target {
    pub fn exists(&self) -> bool {
        self.path.exists()
    }
}

/// Everything a wipe would remove, whether or not it is there right now.
///
/// The list is the daemon's own knowledge of what it writes. Anything the
/// operator wrote — `config.toml` — is not on it, and neither is the socket,
/// which a daemon that is not running does not have.
pub fn targets(config_dir: &Path, runtime_dir: &Path, packs_dir: &Path) -> Vec<Target> {
    let target = |what, path| Target { what, path };
    vec![
        target("the roster — every enrolled device", config_dir.join("roster.json")),
        target("the audit trail", config_dir.join("audit")),
        target("installed plugins and their switches", packs_dir.to_path_buf()),
        target("the hook's replay state", config_dir.join("hook-state")),
        target("the app devices' counters", runtime_dir.join("app-counters.json")),
        target("the mock device's counter", runtime_dir.join("mock-counter")),
        target("the relay counters", runtime_dir.join("relay-counter")),
        target("the relay pairing", runtime_dir.join("relay.json")),
    ]
}

/// Remove every target that exists. Returns the ones that went.
pub fn wipe(targets: &[Target]) -> Result<Vec<&Target>, WipeError> {
    let mut removed = Vec::new();
    for target in targets {
        let path = &target.path;
        if !path.exists() {
            continue;
        }
        let result = if path.is_dir() {
            std::fs::remove_dir_all(path)
        } else {
            std::fs::remove_file(path)
        };
        result.map_err(|e| WipeError::Io(path.clone(), e.to_string()))?;
        removed.push(target);
    }
    Ok(removed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WipeError {
    Io(PathBuf, String),
}

impl std::fmt::Display for WipeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WipeError::Io(p, e) => write!(f, "could not remove {}: {e}", p.display()),
        }
    }
}

impl std::error::Error for WipeError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(path: &Path) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"x").unwrap();
    }

    #[test]
    fn a_wipe_removes_what_the_daemon_wrote_and_keeps_what_the_operator_did() {
        let root = std::env::temp_dir().join(format!("signetd-wipe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let config = root.join("config");
        let run = root.join("run");
        let packs = config.join("packs");
        for rel in [
            "roster.json",
            "audit/chain.jsonl",
            "audit/payloads.jsonl",
            "hook-state/counters.json",
            "packs/packs.toml",
            "packs/countersign-db/countersign-plugin.json",
            "config.toml",
        ] {
            touch(&config.join(rel));
        }
        for rel in ["app-counters.json", "mock-counter", "relay-counter", "relay.json", "countersign.sock"] {
            touch(&run.join(rel));
        }

        let targets = targets(&config, &run, &packs);
        assert_eq!(targets.len(), 8);
        assert!(targets.iter().all(Target::exists));

        let removed = wipe(&targets).unwrap();
        assert_eq!(removed.len(), 8);
        assert!(targets.iter().all(|t| !t.exists()));
        assert!(config.join("config.toml").exists(), "configuration is the operator's");
        assert!(run.join("countersign.sock").exists(), "the socket is not state");

        // Again is fine: nothing to do is not an error.
        assert!(wipe(&targets).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }
}

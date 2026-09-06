//! `countersign-plugin.json` — what an installed plugin says about itself.
//!
//! A plugin is a directory. The manifest names it, names the artifact beside
//! it, pins that artifact's SHA-256, and states which action namespaces its
//! pack claims — so a host can know a namespace is spoken for **without
//! running anything**, which is what lets an installed-but-off pack refuse its
//! namespace rather than fall through to "unclassified".
//!
//! It may also *propose* policy rules. Propose, never apply: a host shows them
//! to the operator, who accepts each one. A plugin that could write policy
//! could write itself a `sql = auto_approve`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The file a plugin directory must contain.
pub const FILE_NAME: &str = "countersign-plugin.json";

/// The manifest format version this crate reads.
pub const MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub v: u32,
    /// `[a-z0-9][a-z0-9-]*`, at most 64 characters. Doubles as the directory
    /// name, so it cannot be allowed to contain a path separator.
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// The classifier, if this plugin ships one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack: Option<PackArtifact>,
    /// Rules the plugin suggests. Shown to the operator; never applied
    /// silently. Kept as raw JSON here because the rule schema belongs to the
    /// daemon, not to this crate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy: Vec<serde_json::Value>,
}

/// How a pack is packaged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactKind {
    /// A WebAssembly module with an empty import section. The only kind a
    /// marketplace distributes — see `crate::wasm`.
    Wasm,
    /// A native executable speaking the stdio protocol. Fine on your own
    /// machine; never listed publicly, because a native binary that sees
    /// production statements has every capability the OS gives it.
    Native,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackArtifact {
    pub kind: ArtifactKind,
    /// A file name relative to the plugin directory. No path separators.
    pub artifact: String,
    /// Lowercase hex SHA-256 of the artifact's bytes.
    pub sha256: String,
    /// The namespaces the pack claims, as `describe` will report them. Listed
    /// here so a host knows without running the pack.
    pub actions: Vec<String>,
    #[serde(default)]
    pub pure: bool,
}

impl Manifest {
    pub fn path_in(dir: &Path) -> PathBuf {
        dir.join(FILE_NAME)
    }

    pub fn load(dir: &Path) -> Result<Self, ManifestError> {
        let path = Self::path_in(dir);
        let text = std::fs::read_to_string(&path)
            .map_err(|e| ManifestError::Read(path.clone(), e.to_string()))?;
        let manifest: Self =
            serde_json::from_str(&text).map_err(|e| ManifestError::Parse(path, e.to_string()))?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn save(&self, dir: &Path) -> Result<(), ManifestError> {
        self.validate()?;
        let path = Self::path_in(dir);
        let mut text = serde_json::to_string_pretty(self)
            .map_err(|e| ManifestError::Parse(path.clone(), e.to_string()))?;
        text.push('\n');
        std::fs::write(&path, text).map_err(|e| ManifestError::Read(path, e.to_string()))
    }

    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.v != MANIFEST_VERSION {
            return Err(ManifestError::Version(self.v));
        }
        check_name(&self.name)?;
        if let Some(pack) = &self.pack {
            if pack.artifact.is_empty()
                || pack.artifact.contains('/')
                || pack.artifact.contains('\\')
                || pack.artifact.starts_with('.')
            {
                return Err(ManifestError::BadArtifactName(pack.artifact.clone()));
            }
            if pack.sha256.len() != 64 || !pack.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(ManifestError::BadHash(pack.sha256.clone()));
            }
            if pack.actions.is_empty() {
                return Err(ManifestError::NoActions);
            }
        }
        Ok(())
    }

    /// The pack artifact's path, **after** checking its hash.
    ///
    /// The hash is checked every time, not only at install. A plugin
    /// directory is ordinary files, and a classifier that was swapped under a
    /// good manifest is exactly the thing this line exists to notice.
    pub fn verified_artifact(&self, dir: &Path) -> Result<(PathBuf, Vec<u8>), ManifestError> {
        let pack = self.pack.as_ref().ok_or(ManifestError::NoPack)?;
        let path = dir.join(&pack.artifact);
        let bytes = std::fs::read(&path)
            .map_err(|e| ManifestError::Read(path.clone(), e.to_string()))?;
        let actual = sha256_hex(&bytes);
        if actual != pack.sha256.to_ascii_lowercase() {
            return Err(ManifestError::HashMismatch {
                artifact: path,
                expected: pack.sha256.clone(),
                actual,
            });
        }
        Ok((path, bytes))
    }
}

/// Lowercase hex SHA-256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Whether `name` may name a plugin — and therefore a directory.
pub fn check_name(name: &str) -> Result<(), ManifestError> {
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !name.starts_with('-');
    if ok {
        Ok(())
    } else {
        Err(ManifestError::BadName(name.to_string()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    Read(PathBuf, String),
    Parse(PathBuf, String),
    Version(u32),
    BadName(String),
    BadArtifactName(String),
    BadHash(String),
    NoActions,
    NoPack,
    HashMismatch {
        artifact: PathBuf,
        expected: String,
        actual: String,
    },
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ManifestError::*;
        match self {
            Read(p, e) => write!(f, "cannot read {}: {e}", p.display()),
            Parse(p, e) => write!(f, "{} is not a valid manifest: {e}", p.display()),
            Version(v) => write!(f, "manifest version {v} is not supported (this reads v{MANIFEST_VERSION})"),
            BadName(n) => write!(
                f,
                "{n:?} is not a plugin name — use lowercase letters, digits and hyphens, at most 64"
            ),
            BadArtifactName(a) => write!(f, "artifact {a:?} must be a plain file name in the plugin directory"),
            BadHash(h) => write!(f, "{h:?} is not a SHA-256 (64 hex characters)"),
            NoActions => f.write_str("a pack must claim at least one action namespace"),
            NoPack => f.write_str("this plugin has no pack"),
            HashMismatch { artifact, expected, actual } => write!(
                f,
                "{} does not match its manifest: expected sha256 {expected}, found {actual}. \
                 Refusing to run it",
                artifact.display()
            ),
        }
    }
}

impl std::error::Error for ManifestError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Manifest {
        Manifest {
            v: 1,
            name: "countersign-db".into(),
            version: "0.1.0".into(),
            description: None,
            license: Some("Apache-2.0".into()),
            source: None,
            pack: Some(PackArtifact {
                kind: ArtifactKind::Wasm,
                artifact: "countersign_db.wasm".into(),
                sha256: sha256_hex(b"pretend module"),
                actions: vec!["sql".into()],
                pure: true,
            }),
            policy: vec![],
        }
    }

    #[test]
    fn a_swapped_artifact_is_noticed_every_time_not_only_at_install() {
        let dir = std::env::temp_dir().join(format!("csp-manifest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let m = manifest();
        m.save(&dir).unwrap();
        std::fs::write(dir.join("countersign_db.wasm"), b"pretend module").unwrap();
        assert!(Manifest::load(&dir).unwrap().verified_artifact(&dir).is_ok());

        std::fs::write(dir.join("countersign_db.wasm"), b"something else").unwrap();
        assert!(matches!(
            Manifest::load(&dir).unwrap().verified_artifact(&dir),
            Err(ManifestError::HashMismatch { .. })
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_name_is_a_directory_name_and_is_checked_like_one() {
        for bad in ["", "Sql", "../etc", "a/b", "-x", &"a".repeat(65)] {
            assert!(check_name(bad).is_err(), "{bad:?} should be refused");
        }
        for good in ["countersign-db", "tf", "my-deploy-gate2"] {
            assert!(check_name(good).is_ok(), "{good:?} should be fine");
        }
    }

    #[test]
    fn an_artifact_cannot_point_outside_the_plugin_directory() {
        let mut m = manifest();
        m.pack.as_mut().unwrap().artifact = "../signetd".into();
        assert!(matches!(m.validate(), Err(ManifestError::BadArtifactName(_))));
    }
}

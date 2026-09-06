//! Installed plugins: where they live, which are on, and what "on" means.
//!
//! A plugin is a directory under the packs directory holding a
//! `countersign-plugin.json` and the artifact it names. Two states, and they
//! are the two states wire spec §6.2.2 already gives you:
//!
//! * **Installed** — the directory exists. The daemon knows the namespaces the
//!   pack claims, because the manifest says so, without running it.
//! * **On** — the pack is spawned, and its namespaces become presentable.
//!
//! The switch is a hard gate in both directions. An installed pack that is
//! **off** does not fall back to "unclassified, shown verbatim" the way a
//! namespace nobody claims does; it is refused without asking a human, and the
//! refusal names the pack and the command that turns it back on. Nothing
//! classified the statement, so nothing may claim it is mild — and an operator
//! who switched a pack off meant for that namespace to stop lighting the dial.
//!
//! The on/off state lives in `packs.toml` beside the plugin directories,
//! owned by `signetd pack …`, so the operator's hand-written `config.toml`
//! keeps its comments and nothing rewrites it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;

use countersign_pack::{
    manifest::{check_name, sha256_hex, MANIFEST_VERSION},
    ArtifactKind, HostConfig, Manifest, ManifestError, PackArtifact, PackHost, PackInfo,
};
use serde::{Deserialize, Serialize};

use crate::config::{namespace_of, Config};

/// The state file's name.
pub const STATE_FILE: &str = "packs.toml";

/// Where plugins live.
pub fn packs_dir() -> PathBuf {
    if let Ok(explicit) = std::env::var("COUNTERSIGN_PACKS_DIR") {
        return PathBuf::from(explicit);
    }
    crate::config::config_dir().join("packs")
}

/// One line of `packs.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackState {
    pub name: String,
    pub enabled: bool,
}

/// `packs.toml`: the operator's on/off decisions, one per installed plugin.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateFile {
    #[serde(default, rename = "pack")]
    pub packs: Vec<PackState>,
}

impl StateFile {
    pub fn load(dir: &Path) -> Result<Self, PacksError> {
        let path = dir.join(STATE_FILE);
        if !path.exists() {
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(&path)
            .map_err(|e| PacksError::Io(path.clone(), e.to_string()))?;
        toml::from_str(&text).map_err(|e| PacksError::State(path, e.to_string()))
    }

    pub fn save(&self, dir: &Path) -> Result<(), PacksError> {
        std::fs::create_dir_all(dir).map_err(|e| PacksError::Io(dir.to_path_buf(), e.to_string()))?;
        let path = dir.join(STATE_FILE);
        let text = toml::to_string(self).map_err(|e| PacksError::State(path.clone(), e.to_string()))?;
        let banner = "# Written by `signetd pack`. Installed plugins and whether each is on.\n\
                      # `on` makes a pack's namespaces presentable; `off` refuses them without asking.\n\n";
        std::fs::write(&path, format!("{banner}{text}"))
            .map_err(|e| PacksError::Io(path, e.to_string()))
    }

    fn entry_mut(&mut self, name: &str) -> Option<&mut PackState> {
        self.packs.iter_mut().find(|p| p.name == name)
    }
}

/// An installed plugin, as the daemon sees it before running anything.
#[derive(Debug, Clone)]
pub struct Installed {
    pub name: String,
    pub dir: PathBuf,
    pub manifest: Manifest,
    pub enabled: bool,
}

impl Installed {
    /// The namespaces this plugin's pack claims, per its manifest.
    pub fn namespaces(&self) -> Vec<String> {
        self.manifest
            .pack
            .as_ref()
            .map(|p| p.actions.iter().map(|a| namespace_of(a).to_string()).collect())
            .unwrap_or_default()
    }
}

/// Every installed plugin, in `packs.toml` order.
pub fn list(dir: &Path) -> Result<Vec<Installed>, PacksError> {
    let state = StateFile::load(dir)?;
    let mut out = Vec::with_capacity(state.packs.len());
    for entry in state.packs {
        let plugin_dir = dir.join(&entry.name);
        let manifest = Manifest::load(&plugin_dir).map_err(PacksError::Manifest)?;
        if manifest.name != entry.name {
            return Err(PacksError::NameMismatch {
                directory: entry.name.clone(),
                manifest: manifest.name.clone(),
            });
        }
        out.push(Installed {
            name: entry.name,
            dir: plugin_dir,
            manifest,
            enabled: entry.enabled,
        });
    }
    Ok(out)
}

/// Install a plugin directory — one holding a manifest and its artifact.
///
/// Copies, never links: the plugin directory is the daemon's copy, and a
/// source tree that changes later must not change what the daemon runs.
/// Installed **off**. Turning a pack on is a separate decision, and the
/// default set of presentable namespaces stays empty until somebody makes it.
pub fn install_dir(src: &Path, dir: &Path) -> Result<Installed, PacksError> {
    let manifest = Manifest::load(src).map_err(PacksError::Manifest)?;
    // Hash-check the source before copying a byte, so a mismatch names the
    // source the operator pointed at and not a half-installed copy.
    let artifact = manifest.verified_artifact(src).map_err(PacksError::Manifest)?;
    place(dir, &manifest, &artifact.1)
}

/// Install a WebAssembly module on its own, writing the manifest for it.
///
/// The module is instantiated once, here, to ask it `describe` — that is where
/// the claimed namespaces come from, and it means the manifest cannot disagree
/// with the pack about what it handles.
pub fn install_wasm(file: &Path, dir: &Path, name: Option<&str>) -> Result<Installed, PacksError> {
    let bytes = std::fs::read(file).map_err(|e| PacksError::Io(file.to_path_buf(), e.to_string()))?;
    let info = describe_module(file, &bytes)?;
    let manifest = manifest_for_module(file, &bytes, &info, name)?;
    place(dir, &manifest, &bytes)
}

/// Instantiate a module in the sandbox and ask it `describe`.
fn describe_module(file: &Path, bytes: &[u8]) -> Result<PackInfo, PacksError> {
    let host = PackHost::spawn_wasm(bytes, HostConfig::default())
        .map_err(|e| PacksError::Pack(file.to_path_buf(), e.to_string()))?;
    Ok(host.info().clone())
}

/// The manifest `install` writes for a bare module: what the module said
/// about itself, pinned to its bytes.
fn manifest_for_module(
    file: &Path,
    bytes: &[u8],
    info: &PackInfo,
    name: Option<&str>,
) -> Result<Manifest, PacksError> {
    let name = name.unwrap_or(&info.name).to_string();
    check_name(&name).map_err(PacksError::Manifest)?;
    let artifact_name = file
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| !n.is_empty())
        .unwrap_or("pack.wasm")
        .to_string();

    Ok(Manifest {
        v: MANIFEST_VERSION,
        name,
        version: info.version.clone(),
        description: None,
        license: None,
        source: None,
        pack: Some(PackArtifact {
            kind: ArtifactKind::Wasm,
            artifact: artifact_name,
            sha256: sha256_hex(bytes),
            actions: info.actions.clone(),
            pure: info.pure,
        }),
        policy: Vec::new(),
    })
}

/// What `signetd pack info` shows: everything about a plugin that can be
/// known before it is installed, and — for a module — what the pack says
/// about itself when asked inside the sandbox.
///
/// Nothing here installs anything, switches anything, or runs a native
/// binary. The sandbox is what makes asking a module safe, and a native pack
/// has none; what a native pack does is what its manifest says, and the
/// operator who installs it is trusting the person who built it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub source: Source,
    pub manifest: Manifest,
    /// The artifact's size on disk.
    pub artifact_len: u64,
    pub hash: HashCheck,
    /// A module's imports, `module.name` each. Empty is the sandbox; anything
    /// else and the daemon will refuse to start it. `None` when the artifact
    /// is native, or was not looked at because its hash is wrong.
    pub imports: Option<Vec<String>>,
    /// What the pack answered to `describe`, or why it was not asked.
    pub describe: Describe,
    /// `Some(on)` when a plugin of this name is installed.
    pub installed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// A plugin directory holding a manifest.
    Directory(PathBuf),
    /// A bare module. The manifest shown is the one `install` would write.
    Module(PathBuf),
    /// An installed plugin, named.
    Installed(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashCheck {
    Matches,
    Mismatch { expected: String, actual: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Describe {
    Answered(PackInfo),
    /// Not asked: a native pack is not run by `info`.
    NativeNotRun,
    /// Not asked: the artifact is not what the manifest pins.
    HashMismatch,
    /// Asked, and it could not be started or did not answer.
    Failed(String),
}

impl Report {
    /// Where the manifest and the pack disagree about what the pack is.
    ///
    /// The daemon presents what a running pack claims and no more, so a
    /// manifest that promises `sql` for a pack that answers `terraform` gets
    /// nothing presentable — which is worth knowing before the switch is
    /// flipped, not after. The plugin name is not compared: `install --name`
    /// lets it differ from the pack's own on purpose.
    pub fn disagreements(&self) -> Vec<String> {
        let (Describe::Answered(info), Some(pack)) = (&self.describe, self.manifest.pack.as_ref())
        else {
            return Vec::new();
        };
        let namespaces = |actions: &[String]| -> BTreeSet<String> {
            actions.iter().map(|a| namespace_of(a).to_string()).collect()
        };
        let join = |set: BTreeSet<String>| set.into_iter().collect::<Vec<_>>().join(", ");

        let mut out = Vec::new();
        if info.version != self.manifest.version {
            out.push(format!(
                "version: the manifest says {}, the pack says {}",
                self.manifest.version, info.version
            ));
        }
        let (claimed, answered) = (namespaces(&pack.actions), namespaces(&info.actions));
        if claimed != answered {
            out.push(format!(
                "namespaces: the manifest says {}, the pack says {}",
                join(claimed),
                join(answered)
            ));
        }
        if info.pure != pack.pure {
            out.push(format!(
                "pure: the manifest says {}, the pack says {}",
                pack.pure, info.pure
            ));
        }
        out
    }
}

/// Look at a plugin without installing it.
///
/// `source` is a plugin directory, a bare `.wasm` module, or the name of a
/// plugin already installed under `dir`.
pub fn inspect(source: &Path, dir: &Path) -> Result<Report, PacksError> {
    let (origin, plugin_dir) = if source.is_dir() {
        (Source::Directory(source.to_path_buf()), source.to_path_buf())
    } else if source.is_file() {
        return inspect_module(source, dir);
    } else {
        let name = source.to_str().unwrap_or_default();
        let candidate = dir.join(name);
        if check_name(name).is_ok() && candidate.is_dir() {
            (Source::Installed(candidate.clone()), candidate)
        } else {
            return Err(PacksError::Io(
                source.to_path_buf(),
                "not a plugin directory, a .wasm module, or the name of an installed plugin".into(),
            ));
        }
    };

    let manifest = Manifest::load(&plugin_dir).map_err(PacksError::Manifest)?;
    let pack = manifest
        .pack
        .as_ref()
        .ok_or(PacksError::Manifest(ManifestError::NoPack))?;
    let artifact = plugin_dir.join(&pack.artifact);
    let bytes = std::fs::read(&artifact)
        .map_err(|e| PacksError::Io(artifact.clone(), e.to_string()))?;
    let actual = sha256_hex(&bytes);
    let hash = if actual == pack.sha256.to_ascii_lowercase() {
        HashCheck::Matches
    } else {
        HashCheck::Mismatch {
            expected: pack.sha256.clone(),
            actual,
        }
    };

    // A swapped artifact is not looked at further, whatever it is. A native
    // one is not run. A module is asked, inside the sandbox.
    let (imports, describe) = match (&hash, pack.kind) {
        (HashCheck::Mismatch { .. }, _) => (None, Describe::HashMismatch),
        (HashCheck::Matches, ArtifactKind::Native) => (None, Describe::NativeNotRun),
        (HashCheck::Matches, ArtifactKind::Wasm) => ask_module(&artifact, &bytes),
    };
    let installed = installed_state(dir, &manifest.name)?;

    Ok(Report {
        source: origin,
        manifest,
        artifact_len: bytes.len() as u64,
        hash,
        imports,
        describe,
        installed,
    })
}

fn inspect_module(file: &Path, dir: &Path) -> Result<Report, PacksError> {
    let bytes = std::fs::read(file).map_err(|e| PacksError::Io(file.to_path_buf(), e.to_string()))?;
    let (imports, describe) = ask_module(file, &bytes);
    let info = match &describe {
        Describe::Answered(info) => info,
        // Without an answer there is no manifest to show. The reason names
        // the first import, when that is what stopped it.
        Describe::Failed(why) => return Err(PacksError::Pack(file.to_path_buf(), why.clone())),
        Describe::NativeNotRun | Describe::HashMismatch => unreachable!("a module is always asked"),
    };
    let manifest = manifest_for_module(file, &bytes, info, None)?;
    let installed = installed_state(dir, &manifest.name)?;
    Ok(Report {
        source: Source::Module(file.to_path_buf()),
        manifest,
        artifact_len: bytes.len() as u64,
        hash: HashCheck::Matches,
        imports,
        describe,
        installed,
    })
}

/// A module's imports, then its `describe` — the second only if the first
/// list is empty, because that is the order the daemon checks in.
fn ask_module(file: &Path, bytes: &[u8]) -> (Option<Vec<String>>, Describe) {
    let imports = match countersign_pack::wasm_host::imports(bytes) {
        Ok(list) => list,
        Err(e) => return (None, Describe::Failed(e.to_string())),
    };
    let describe = match describe_module(file, bytes) {
        Ok(info) => Describe::Answered(info),
        Err(e) => Describe::Failed(e.to_string()),
    };
    (Some(imports), describe)
}

fn installed_state(dir: &Path, name: &str) -> Result<Option<bool>, PacksError> {
    Ok(StateFile::load(dir)?
        .packs
        .iter()
        .find(|p| p.name == name)
        .map(|p| p.enabled))
}

fn place(dir: &Path, manifest: &Manifest, artifact_bytes: &[u8]) -> Result<Installed, PacksError> {
    let pack = manifest.pack.as_ref().ok_or(PacksError::Manifest(ManifestError::NoPack))?;
    let plugin_dir = dir.join(&manifest.name);
    if plugin_dir.exists() {
        return Err(PacksError::AlreadyInstalled(manifest.name.clone()));
    }
    std::fs::create_dir_all(&plugin_dir)
        .map_err(|e| PacksError::Io(plugin_dir.clone(), e.to_string()))?;

    let artifact_path = plugin_dir.join(&pack.artifact);
    std::fs::write(&artifact_path, artifact_bytes)
        .map_err(|e| PacksError::Io(artifact_path.clone(), e.to_string()))?;
    if pack.kind == ArtifactKind::Native {
        mark_executable(&artifact_path)?;
    }
    manifest.save(&plugin_dir).map_err(PacksError::Manifest)?;

    let mut state = StateFile::load(dir)?;
    state.packs.retain(|p| p.name != manifest.name);
    state.packs.push(PackState {
        name: manifest.name.clone(),
        enabled: false,
    });
    state.save(dir)?;

    Ok(Installed {
        name: manifest.name.clone(),
        dir: plugin_dir,
        manifest: manifest.clone(),
        enabled: false,
    })
}

#[cfg(unix)]
fn mark_executable(path: &Path) -> Result<(), PacksError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| PacksError::Io(path.to_path_buf(), e.to_string()))
}

#[cfg(not(unix))]
fn mark_executable(_path: &Path) -> Result<(), PacksError> {
    Ok(())
}

/// Uninstall: the directory goes, and so does the state line.
pub fn remove(dir: &Path, name: &str) -> Result<(), PacksError> {
    check_name(name).map_err(PacksError::Manifest)?;
    let mut state = StateFile::load(dir)?;
    let before = state.packs.len();
    state.packs.retain(|p| p.name != name);
    if state.packs.len() == before {
        return Err(PacksError::NotInstalled(name.to_string()));
    }
    let plugin_dir = dir.join(name);
    if plugin_dir.exists() {
        std::fs::remove_dir_all(&plugin_dir)
            .map_err(|e| PacksError::Io(plugin_dir, e.to_string()))?;
    }
    state.save(dir)
}

/// Switch a pack on or off. Returns the previous state.
pub fn set_enabled(dir: &Path, name: &str, enabled: bool) -> Result<bool, PacksError> {
    let mut state = StateFile::load(dir)?;
    let entry = state
        .entry_mut(name)
        .ok_or_else(|| PacksError::NotInstalled(name.to_string()))?;
    let was = entry.enabled;
    entry.enabled = enabled;
    state.save(dir)?;
    Ok(was)
}

/// What the daemon starts with.
#[derive(Debug, Default)]
pub struct Loaded {
    /// The packs that are on, running.
    pub hosts: Vec<PackHost>,
    /// Namespaces claimed by packs that are on. These become presentable.
    pub enabled_namespaces: BTreeSet<String>,
    /// Namespace → pack name, for packs that are installed and off. Requests
    /// in these namespaces are refused without asking anyone.
    pub off_namespaces: BTreeMap<String, String>,
    /// Packs that were on but could not start, with why. Each is reported
    /// and treated as off, which is the fail-closed reading: a pack that will
    /// not start is not classifying anything.
    pub failed: Vec<(String, String)>,
}

/// Spawn the packs that are on; note the namespaces of the ones that are off.
pub fn load(dir: &Path, host_config: HostConfig) -> Result<Loaded, PacksError> {
    let mut loaded = Loaded::default();
    for plugin in list(dir)? {
        let namespaces = plugin.namespaces();
        if !plugin.enabled {
            for ns in namespaces {
                loaded.off_namespaces.insert(ns, plugin.name.clone());
            }
            continue;
        }
        match spawn(&plugin, host_config.clone()) {
            Ok(host) => {
                // The manifest said which namespaces; the pack, now running,
                // says which it actually handles. Present what the pack claims
                // and no more — a manifest that promised `sql` for a pack that
                // answers `terraform` gets nothing presentable.
                for action in &host.info().actions {
                    loaded.enabled_namespaces.insert(namespace_of(action).to_string());
                }
                loaded.hosts.push(host);
            }
            Err(e) => {
                for ns in namespaces {
                    loaded.off_namespaces.insert(ns, plugin.name.clone());
                }
                loaded.failed.push((plugin.name.clone(), e.to_string()));
            }
        }
    }
    Ok(loaded)
}

fn spawn(plugin: &Installed, host_config: HostConfig) -> Result<PackHost, PacksError> {
    let pack = plugin
        .manifest
        .pack
        .as_ref()
        .ok_or(PacksError::Manifest(ManifestError::NoPack))?;
    // Every start, not only at install. See `Manifest::verified_artifact`.
    let (path, bytes) = plugin
        .manifest
        .verified_artifact(&plugin.dir)
        .map_err(PacksError::Manifest)?;
    match pack.kind {
        ArtifactKind::Wasm => PackHost::spawn_wasm(&bytes, host_config)
            .map_err(|e| PacksError::Pack(path, e.to_string())),
        ArtifactKind::Native => PackHost::spawn(Command::new(&path), host_config)
            .map_err(|e| PacksError::Pack(path, e.to_string())),
    }
}

/// Make the namespaces of the packs that are on presentable, alongside
/// whatever the operator's rules already named.
///
/// Written into `policy.presentable` explicitly, so `may_present` has one
/// answer and the daemon's startup banner can print it.
pub fn extend_presentable(config: &mut Config, enabled_namespaces: &BTreeSet<String>) {
    let mut all = config.policy.presentable_namespaces();
    all.extend(enabled_namespaces.iter().cloned());
    config.policy.presentable = Some(all.into_iter().collect());
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacksError {
    Io(PathBuf, String),
    State(PathBuf, String),
    Manifest(ManifestError),
    Pack(PathBuf, String),
    NameMismatch { directory: String, manifest: String },
    AlreadyInstalled(String),
    NotInstalled(String),
}

impl std::fmt::Display for PacksError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use PacksError::*;
        match self {
            Io(p, e) => write!(f, "{}: {e}", p.display()),
            State(p, e) => write!(f, "{} is not readable: {e}", p.display()),
            Manifest(e) => write!(f, "{e}"),
            Pack(p, e) => write!(f, "{}: {e}", p.display()),
            NameMismatch { directory, manifest } => write!(
                f,
                "plugin directory {directory:?} holds a manifest named {manifest:?}; refusing to \
                 guess which is right"
            ),
            AlreadyInstalled(n) => {
                write!(f, "{n} is already installed — `signetd pack remove {n}` first")
            }
            NotInstalled(n) => write!(f, "{n} is not installed — `signetd pack list` shows what is"),
        }
    }
}

impl std::error::Error for PacksError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("signetd-packs-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A native "pack" that is really `cat` would not speak the protocol, so
    /// these tests only exercise the bookkeeping: install, state, on/off,
    /// remove. The transport is covered in `countersign-pack`.
    fn fake_plugin(src: &Path, name: &str, actions: &[&str]) {
        std::fs::create_dir_all(src).unwrap();
        let bytes = b"#!/bin/sh\nexit 1\n";
        std::fs::write(src.join("pack.sh"), bytes).unwrap();
        Manifest {
            v: 1,
            name: name.into(),
            version: "0.0.1".into(),
            description: None,
            license: None,
            source: None,
            pack: Some(PackArtifact {
                kind: ArtifactKind::Native,
                artifact: "pack.sh".into(),
                sha256: sha256_hex(bytes),
                actions: actions.iter().map(|a| a.to_string()).collect(),
                pure: true,
            }),
            policy: vec![],
        }
        .save(src)
        .unwrap();
    }

    #[test]
    fn install_is_off_by_default_and_the_switch_is_recorded() {
        let root = temp("install");
        let src = root.join("src");
        let dir = root.join("packs");
        fake_plugin(&src, "countersign-tf", &["terraform"]);

        let installed = install_dir(&src, &dir).unwrap();
        assert!(!installed.enabled, "installing must not switch anything on");
        assert_eq!(installed.namespaces(), vec!["terraform".to_string()]);
        assert!(dir.join("countersign-tf").join("pack.sh").exists());

        assert!(!set_enabled(&dir, "countersign-tf", true).unwrap());
        assert!(list(&dir).unwrap()[0].enabled);
        assert!(set_enabled(&dir, "countersign-tf", false).unwrap());

        assert!(matches!(install_dir(&src, &dir), Err(PacksError::AlreadyInstalled(_))));
        remove(&dir, "countersign-tf").unwrap();
        assert!(list(&dir).unwrap().is_empty());
        assert!(!dir.join("countersign-tf").exists());
        assert!(matches!(remove(&dir, "countersign-tf"), Err(PacksError::NotInstalled(_))));
    }

    #[test]
    fn an_installed_pack_that_is_off_claims_its_namespace_without_running() {
        let root = temp("off");
        let src = root.join("src");
        let dir = root.join("packs");
        fake_plugin(&src, "countersign-tf", &["terraform.apply", "terraform.plan"]);
        install_dir(&src, &dir).unwrap();

        let loaded = load(&dir, HostConfig::default()).unwrap();
        assert!(loaded.hosts.is_empty());
        assert_eq!(
            loaded.off_namespaces.get("terraform").map(String::as_str),
            Some("countersign-tf")
        );
        assert!(loaded.enabled_namespaces.is_empty());
    }

    #[test]
    fn a_pack_that_is_on_but_will_not_start_is_treated_as_off() {
        // Fail closed: nothing is classifying `terraform`, so nothing may show
        // it verbatim at the floor as if that were fine.
        let root = temp("broken");
        let src = root.join("src");
        let dir = root.join("packs");
        fake_plugin(&src, "countersign-tf", &["terraform"]);
        install_dir(&src, &dir).unwrap();
        set_enabled(&dir, "countersign-tf", true).unwrap();

        let loaded = load(&dir, HostConfig::default()).unwrap();
        assert!(loaded.hosts.is_empty());
        assert_eq!(loaded.failed.len(), 1);
        assert!(loaded.off_namespaces.contains_key("terraform"));
    }

    #[test]
    fn a_swapped_artifact_stops_the_pack_from_starting() {
        let root = temp("swap");
        let src = root.join("src");
        let dir = root.join("packs");
        fake_plugin(&src, "countersign-tf", &["terraform"]);
        install_dir(&src, &dir).unwrap();
        set_enabled(&dir, "countersign-tf", true).unwrap();
        std::fs::write(dir.join("countersign-tf").join("pack.sh"), b"#!/bin/sh\ncurl evil\n").unwrap();

        let loaded = load(&dir, HostConfig::default()).unwrap();
        assert!(loaded.hosts.is_empty());
        assert!(loaded.failed[0].1.contains("does not match its manifest"), "{:?}", loaded.failed);
    }

    /// The db pack's module, if it has been built. Same skip rule as
    /// `countersign-pack/tests/wasm_pack.rs`: a fresh checkout stays green.
    fn db_module() -> Option<Vec<u8>> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/wasm32-unknown-unknown/release/countersign_db.wasm");
        match std::fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(_) => {
                eprintln!("skipping: {} not built", path.display());
                None
            }
        }
    }

    #[test]
    fn info_reads_a_native_plugin_and_runs_nothing() {
        let root = temp("info-native");
        let src = root.join("src");
        let dir = root.join("packs");
        // The fake pack exits 1 the moment it is run; a report that ran it
        // would say so.
        fake_plugin(&src, "countersign-tf", &["terraform.apply"]);

        let report = inspect(&src, &dir).unwrap();
        assert_eq!(report.source, Source::Directory(src.clone()));
        assert_eq!(report.hash, HashCheck::Matches);
        assert_eq!(report.describe, Describe::NativeNotRun);
        assert_eq!(report.imports, None);
        assert_eq!(report.installed, None);
        assert!(report.disagreements().is_empty());
        assert!(!dir.exists(), "info must not install anything");

        install_dir(&src, &dir).unwrap();
        let report = inspect(Path::new("countersign-tf"), &dir).unwrap();
        assert!(matches!(report.source, Source::Installed(_)));
        assert_eq!(report.installed, Some(false));
        set_enabled(&dir, "countersign-tf", true).unwrap();
        assert_eq!(inspect(Path::new("countersign-tf"), &dir).unwrap().installed, Some(true));

        assert!(inspect(Path::new("not-installed"), &dir).is_err());
    }

    #[test]
    fn info_notices_a_swapped_artifact_and_asks_it_nothing() {
        let root = temp("info-swap");
        let src = root.join("src");
        let dir = root.join("packs");
        fake_plugin(&src, "countersign-tf", &["terraform"]);
        std::fs::write(src.join("pack.sh"), b"#!/bin/sh\ncurl evil\n").unwrap();

        let report = inspect(&src, &dir).unwrap();
        assert!(matches!(report.hash, HashCheck::Mismatch { .. }));
        assert_eq!(report.describe, Describe::HashMismatch);
        assert_eq!(report.imports, None);
    }

    #[test]
    fn info_on_a_module_shows_the_manifest_install_would_write() {
        let Some(bytes) = db_module() else { return };
        let root = temp("info-wasm");
        let dir = root.join("packs");
        let file = root.join("countersign_db.wasm");
        std::fs::write(&file, &bytes).unwrap();

        let report = inspect(&file, &dir).unwrap();
        assert_eq!(report.source, Source::Module(file.clone()));
        assert_eq!(report.manifest.name, "countersign-db");
        assert_eq!(report.imports.as_deref(), Some(&[][..]), "the sandbox: nothing imported");
        let Describe::Answered(info) = &report.describe else {
            panic!("the module should answer: {:?}", report.describe)
        };
        assert_eq!(info.actions, vec!["sql".to_string()]);
        assert!(report.disagreements().is_empty());
        assert_eq!(report.installed, None);

        let installed = install_wasm(&file, &dir, None).unwrap();
        assert_eq!(installed.manifest, report.manifest, "what info showed is what install wrote");
        assert_eq!(inspect(&file, &dir).unwrap().installed, Some(false));
    }

    #[test]
    fn info_says_where_a_manifest_and_its_pack_disagree() {
        let Some(bytes) = db_module() else { return };
        let root = temp("info-disagree");
        let src = root.join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("pack.wasm"), &bytes).unwrap();
        // A manifest that promises Terraform, a different version, and impurity,
        // wrapped around the SQL pack.
        Manifest {
            v: 1,
            name: "countersign-tf".into(),
            version: "9.9.9".into(),
            description: None,
            license: None,
            source: None,
            pack: Some(PackArtifact {
                kind: ArtifactKind::Wasm,
                artifact: "pack.wasm".into(),
                sha256: sha256_hex(&bytes),
                actions: vec!["terraform".into()],
                pure: false,
            }),
            policy: vec![],
        }
        .save(&src)
        .unwrap();

        let report = inspect(&src, &root.join("packs")).unwrap();
        let disagreements = report.disagreements();
        assert_eq!(disagreements.len(), 3, "{disagreements:?}");
        assert!(disagreements[0].starts_with("version:"));
        assert!(disagreements[1].contains("the manifest says terraform, the pack says sql"));
        assert!(disagreements[2].starts_with("pure:"));
    }

    #[test]
    fn enabled_namespaces_join_the_presentable_set() {
        let mut config = Config::default();
        assert!(!config.policy.may_present("terraform.apply"));
        let mut on = BTreeSet::new();
        on.insert("terraform".to_string());
        extend_presentable(&mut config, &on);
        assert!(config.policy.may_present("terraform.apply"));
        assert!(!config.policy.may_present("sql.ddl"));
    }
}

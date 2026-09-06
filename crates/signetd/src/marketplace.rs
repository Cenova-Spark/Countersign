//! The marketplace: one `index.json` and a directory per plugin, read from a
//! URL or from a directory on this machine, and installed from with the same
//! checks the repository's CI runs on a pull request — because a daemon
//! cannot know that CI ran, and the pack it is about to start will see
//! production statements.
//!
//! What the index says is a claim. What gets installed is what the module
//! says about itself inside the sandbox, checked against the manifest's pin
//! and the index's, and refused wherever they disagree. Pack protocol §8.3
//! and §8.4 are the rules; `install` and `fetch_plugin` are those rules in
//! order.
//!
//! The index lives in this repository's `marketplace/` for now, which is a
//! placeholder for a repository of its own; `COUNTERSIGN_INDEX` or `--index`
//! points anywhere else, including at a directory, which is how the tests
//! and an offline demo run.

use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use countersign_pack::manifest::{check_name, sha256_hex, FILE_NAME};
use countersign_pack::{ArtifactKind, Manifest};
use serde::{Deserialize, Serialize};

use crate::packs::{self, Describe, Installed, PacksError, Report, Source};

/// Where the index is unless something else is said.
pub const DEFAULT_INDEX: &str =
    "https://raw.githubusercontent.com/Cenova-Spark/Countersign/main/marketplace/index.json";
pub const INDEX_FILE: &str = "index.json";
pub const INDEX_VERSION: u32 = 1;

/// The most a fetched file may be. A classifier is a few hundred kilobytes;
/// sixteen megabytes is far above that and far below a download that hurts.
const MAX_FETCH_BYTES: u64 = 16 << 20;
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// The index location: `COUNTERSIGN_INDEX`, or the default.
pub fn index_location() -> String {
    std::env::var("COUNTERSIGN_INDEX").unwrap_or_else(|_| DEFAULT_INDEX.to_string())
}

/// `index.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Index {
    pub v: u32,
    #[serde(default)]
    pub plugins: Vec<Entry>,
}

/// One listed plugin: what the index claims about it. Everything here is
/// re-checked against the plugin directory before anything is installed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The plugin's directory beside the index: a plain name, never a path.
    pub path: String,
    /// The module's SHA-256, which the manifest in that directory must pin too.
    pub sha256: String,
    /// The namespaces the manifest claims.
    pub actions: Vec<String>,
    #[serde(default)]
    pub pure: bool,
}

/// Where an index lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Location {
    /// The directory the index is in, as a URL ending in `/`.
    Url(String),
    /// The directory the index is in.
    Dir(PathBuf),
}

impl Location {
    /// A URL to `index.json` or to its directory; or a path to either.
    pub fn parse(text: &str) -> Location {
        if text.starts_with("http://") || text.starts_with("https://") {
            let base = text.strip_suffix(INDEX_FILE).unwrap_or(text);
            let base = if base.ends_with('/') { base.to_string() } else { format!("{base}/") };
            return Location::Url(base);
        }
        let path = PathBuf::from(text);
        if path.file_name().and_then(|n| n.to_str()) == Some(INDEX_FILE) {
            Location::Dir(path.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from(".")))
        } else {
            Location::Dir(path)
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Location::Url(base) => format!("{base}{INDEX_FILE}"),
            Location::Dir(dir) => dir.join(INDEX_FILE).display().to_string(),
        }
    }

    /// One file beside the index. `rel` is a plain directory name and a plain
    /// file name, nothing else — an index that says `../` is not followed.
    fn fetch(&self, rel: &str) -> Result<Vec<u8>, MarketError> {
        let relative = Path::new(rel);
        if relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err(MarketError::BadPath(rel.to_string()));
        }
        match self {
            Location::Dir(dir) => {
                let path = dir.join(relative);
                std::fs::read(&path).map_err(|e| MarketError::Fetch(path.display().to_string(), e.to_string()))
            }
            Location::Url(base) => {
                let url = format!("{base}{rel}");
                let agent: ureq::Agent = ureq::Agent::config_builder()
                    .timeout_global(Some(FETCH_TIMEOUT))
                    .user_agent(concat!("signetd/", env!("CARGO_PKG_VERSION")))
                    .build()
                    .into();
                let mut response = agent
                    .get(&url)
                    .call()
                    .map_err(|e| MarketError::Fetch(url.clone(), e.to_string()))?;
                response
                    .body_mut()
                    .with_config()
                    .limit(MAX_FETCH_BYTES)
                    .read_to_vec()
                    .map_err(|e| MarketError::Fetch(url, e.to_string()))
            }
        }
    }
}

/// Read the index.
pub fn load_index(location: &Location) -> Result<Index, MarketError> {
    let bytes = location.fetch(INDEX_FILE)?;
    let index: Index = serde_json::from_slice(&bytes)
        .map_err(|e| MarketError::BadIndex(location.describe(), e.to_string()))?;
    if index.v != INDEX_VERSION {
        return Err(MarketError::BadIndex(
            location.describe(),
            format!("index version {} is not supported (this reads v{INDEX_VERSION})", index.v),
        ));
    }
    Ok(index)
}

/// The listed plugin of that name.
pub fn find<'a>(index: &'a Index, name: &str) -> Result<&'a Entry, MarketError> {
    index
        .plugins
        .iter()
        .find(|e| e.name == name)
        .ok_or_else(|| MarketError::NotListed(name.to_string()))
}

/// Fetch a listed plugin's directory into `dest` — manifest and module —
/// checking everything §8.4 says to check, in the order that stops earliest.
///
/// `dest` is somewhere the daemon does not look; nothing is written where a
/// daemon will find it until every check has passed and `install` copies it
/// there.
pub fn fetch_plugin(location: &Location, entry: &Entry, dest: &Path) -> Result<Report, MarketError> {
    check_name(&entry.path).map_err(|_| MarketError::BadPath(entry.path.clone()))?;

    let manifest_bytes = location.fetch(&format!("{}/{FILE_NAME}", entry.path))?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| MarketError::BadManifest(entry.name.clone(), e.to_string()))?;
    manifest
        .validate()
        .map_err(|e| MarketError::BadManifest(entry.name.clone(), e.to_string()))?;
    if manifest.name != entry.name {
        return Err(MarketError::Disagree(format!(
            "the index lists {:?} but the manifest in {}/ is named {:?}",
            entry.name, entry.path, manifest.name
        )));
    }
    let pack = manifest
        .pack
        .as_ref()
        .ok_or_else(|| MarketError::BadManifest(entry.name.clone(), "this plugin has no pack".into()))?;
    // The WebAssembly rule (§8.3). A native pack is never installed from an
    // index, whatever the index says.
    if pack.kind != ArtifactKind::Wasm {
        return Err(MarketError::NotWasm(entry.name.clone()));
    }
    if !pack.sha256.eq_ignore_ascii_case(&entry.sha256) {
        return Err(MarketError::Disagree(format!(
            "the index says the module is {} and the manifest pins {}",
            entry.sha256, pack.sha256
        )));
    }

    let module = location.fetch(&format!("{}/{}", entry.path, pack.artifact))?;
    let actual = sha256_hex(&module);
    if actual != pack.sha256.to_ascii_lowercase() {
        return Err(MarketError::Disagree(format!(
            "the module fetched for {} is {actual}, not the {} the manifest pins",
            entry.name, pack.sha256
        )));
    }

    std::fs::create_dir_all(dest).map_err(|e| MarketError::Io(dest.to_path_buf(), e.to_string()))?;
    let artifact_path = dest.join(&pack.artifact);
    std::fs::write(&artifact_path, &module).map_err(|e| MarketError::Io(artifact_path, e.to_string()))?;
    manifest
        .save(dest)
        .map_err(|e| MarketError::BadManifest(entry.name.clone(), e.to_string()))?;

    // The sandbox check, and describe against the manifest. `inspect` looks
    // for an installed state under a packs dir; none is wanted here.
    let mut report = packs::inspect(dest, &dest.join("no-packs-here")).map_err(MarketError::Packs)?;
    report.source = Source::Index {
        index: location.describe(),
        name: entry.name.clone(),
    };
    refuse_unless_clean(&report)?;
    Ok(report)
}

/// What an index install and a publish both insist on: a module with no
/// imports, that answers `describe`, and agrees with its manifest.
fn refuse_unless_clean(report: &Report) -> Result<(), MarketError> {
    match &report.imports {
        Some(list) if list.is_empty() => {}
        Some(list) => {
            return Err(MarketError::Refused(format!(
                "the module imports {}; a pack must import nothing",
                list.join(", ")
            )))
        }
        None => return Err(MarketError::Refused("the module could not be read".into())),
    }
    match &report.describe {
        Describe::Answered(_) => {}
        Describe::Failed(why) => return Err(MarketError::Refused(format!("the module did not answer describe: {why}"))),
        Describe::NativeNotRun => return Err(MarketError::Refused("a native pack is never listed".into())),
        Describe::HashMismatch => return Err(MarketError::Refused("the module is not what its manifest pins".into())),
    }
    let disagreements = report.disagreements();
    if !disagreements.is_empty() {
        return Err(MarketError::Refused(format!(
            "the manifest and the module disagree — {}",
            disagreements.join("; ")
        )));
    }
    Ok(())
}

/// A place to fetch into that the daemon does not read. Unique per call,
/// not per name: two fetches of the same plugin in one process — the tests
/// do this — must not clean up under each other.
fn staging(name: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("signetd-market-{}-{sequence}-{name}", std::process::id()))
}

/// Look at a listed plugin without installing it: fetched, checked, and
/// reported the way `pack info` reports a local one.
pub fn inspect(location: &Location, name: &str) -> Result<Report, MarketError> {
    let index = load_index(location)?;
    let entry = find(&index, name)?;
    let dest = staging(name);
    let _ = std::fs::remove_dir_all(&dest);
    let result = fetch_plugin(location, entry, &dest);
    let _ = std::fs::remove_dir_all(&dest);
    result
}

/// Install a listed plugin, switched off, like any other install.
pub fn install(location: &Location, name: &str, packs_dir: &Path) -> Result<Installed, MarketError> {
    let index = load_index(location)?;
    let entry = find(&index, name)?;
    let dest = staging(name);
    let _ = std::fs::remove_dir_all(&dest);
    let result = fetch_plugin(location, entry, &dest)
        .and_then(|_| packs::install_dir(&dest, packs_dir).map_err(MarketError::Packs));
    let _ = std::fs::remove_dir_all(&dest);
    result
}

/// What `publish` may fill in on a manifest that `install` would otherwise
/// write bare, for a module handed over on its own.
#[derive(Debug, Clone, Default)]
pub struct PublishFields {
    pub description: Option<String>,
    pub license: Option<String>,
    pub source: Option<String>,
}

/// Stage a local plugin for a pull request: check it the way an install
/// would, copy its manifest and module into `market_dir/<name>/`, and write
/// its entry into the index there. The pull request itself is the person's.
pub fn publish(source: &Path, market_dir: &Path, fields: &PublishFields) -> Result<Entry, MarketError> {
    let report = packs::inspect(source, &market_dir.join("no-packs-here")).map_err(MarketError::Packs)?;
    let mut manifest = report.manifest.clone();
    if fields.description.is_some() {
        manifest.description = fields.description.clone();
    }
    if fields.license.is_some() {
        manifest.license = fields.license.clone();
    }
    if fields.source.is_some() {
        manifest.source = fields.source.clone();
    }
    let pack = manifest
        .pack
        .clone()
        .ok_or_else(|| MarketError::BadManifest(manifest.name.clone(), "this plugin has no pack".into()))?;
    if pack.kind != ArtifactKind::Wasm {
        return Err(MarketError::NotWasm(manifest.name.clone()));
    }
    refuse_unless_clean(&report)?;

    let module = match &report.source {
        Source::Module(file) => std::fs::read(file).map_err(|e| MarketError::Io(file.clone(), e.to_string()))?,
        Source::Directory(dir) | Source::Installed(dir) => {
            let file = dir.join(&pack.artifact);
            std::fs::read(&file).map_err(|e| MarketError::Io(file, e.to_string()))?
        }
        Source::Index { .. } => unreachable!("a local inspect never reports an index"),
    };

    let plugin_dir = market_dir.join(&manifest.name);
    std::fs::create_dir_all(&plugin_dir).map_err(|e| MarketError::Io(plugin_dir.clone(), e.to_string()))?;
    let artifact_path = plugin_dir.join(&pack.artifact);
    std::fs::write(&artifact_path, &module).map_err(|e| MarketError::Io(artifact_path, e.to_string()))?;
    manifest
        .save(&plugin_dir)
        .map_err(|e| MarketError::BadManifest(manifest.name.clone(), e.to_string()))?;

    let entry = Entry {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        description: manifest.description.clone(),
        path: manifest.name.clone(),
        sha256: pack.sha256.clone(),
        actions: pack.actions.clone(),
        pure: pack.pure,
    };
    let location = Location::Dir(market_dir.to_path_buf());
    let mut index = match load_index(&location) {
        Ok(index) => index,
        Err(MarketError::Fetch(..)) => Index {
            v: INDEX_VERSION,
            plugins: Vec::new(),
        },
        Err(e) => return Err(e),
    };
    index.plugins.retain(|e| e.name != entry.name);
    index.plugins.push(entry.clone());
    index.plugins.sort_by(|a, b| a.name.cmp(&b.name));
    let path = market_dir.join(INDEX_FILE);
    let mut text = serde_json::to_string_pretty(&index)
        .map_err(|e| MarketError::BadIndex(path.display().to_string(), e.to_string()))?;
    text.push('\n');
    std::fs::write(&path, text).map_err(|e| MarketError::Io(path, e.to_string()))?;
    Ok(entry)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarketError {
    Fetch(String, String),
    BadIndex(String, String),
    BadPath(String),
    NotListed(String),
    BadManifest(String, String),
    NotWasm(String),
    /// The index, the manifest and the bytes did not all agree.
    Disagree(String),
    /// The module itself failed a check that makes listing acceptable.
    Refused(String),
    Packs(PacksError),
    Io(PathBuf, String),
}

impl std::fmt::Display for MarketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use MarketError::*;
        match self {
            Fetch(what, e) => write!(f, "could not fetch {what}: {e}"),
            BadIndex(what, e) => write!(f, "{what} is not an index: {e}"),
            BadPath(p) => write!(f, "{p:?} is not a plain directory name; an index may not point outside itself"),
            NotListed(n) => write!(f, "{n} is not in the index — `signetd pack index` shows what is"),
            BadManifest(n, e) => write!(f, "{n}: {e}"),
            NotWasm(n) => write!(f, "{n} is a native pack, and an index distributes WebAssembly only (pack protocol §8.3)"),
            Disagree(e) => write!(f, "refusing: {e}"),
            Refused(e) => write!(f, "refusing: {e}"),
            Packs(e) => write!(f, "{e}"),
            Io(p, e) => write!(f, "{}: {e}", p.display()),
        }
    }
}

impl std::error::Error for MarketError {}

#[cfg(test)]
mod tests {
    use super::*;
    use countersign_pack::PackArtifact;

    fn temp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("signetd-market-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The db pack's module, if it has been built; the tests skip otherwise.
    fn db_module() -> Option<Vec<u8>> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/wasm32-unknown-unknown/release/countersign_db.wasm");
        std::fs::read(&path).ok().or_else(|| {
            eprintln!("skipping: {} not built", path.display());
            None
        })
    }

    fn published(tag: &str) -> Option<(PathBuf, PathBuf)> {
        let bytes = db_module()?;
        let root = temp(tag);
        let market = root.join("market");
        let module = root.join("countersign_db.wasm");
        std::fs::write(&module, &bytes).unwrap();
        let fields = PublishFields {
            description: Some("SQL, classified".into()),
            license: Some("Apache-2.0".into()),
            source: None,
        };
        let entry = publish(&module, &market, &fields).unwrap();
        assert_eq!(entry.name, "countersign-db");
        assert_eq!(entry.actions, vec!["sql".to_string()]);
        assert!(entry.pure);
        Some((root, market))
    }

    #[test]
    fn locations_are_a_directory_or_a_url_to_one() {
        assert_eq!(Location::parse("marketplace"), Location::Dir(PathBuf::from("marketplace")));
        assert_eq!(Location::parse("marketplace/index.json"), Location::Dir(PathBuf::from("marketplace")));
        assert_eq!(
            Location::parse("https://x.example/m/index.json"),
            Location::Url("https://x.example/m/".into())
        );
        assert_eq!(Location::parse("https://x.example/m"), Location::Url("https://x.example/m/".into()));
    }

    #[test]
    fn publish_stages_a_directory_and_an_entry_that_install_reads_back() {
        let Some((root, market)) = published("roundtrip") else { return };
        let location = Location::Dir(market.clone());
        let index = load_index(&location).unwrap();
        assert_eq!(index.plugins.len(), 1);
        assert!(market.join("countersign-db").join("countersign-plugin.json").exists());
        assert!(market.join("countersign-db").join("countersign_db.wasm").exists());
        let manifest = Manifest::load(&market.join("countersign-db")).unwrap();
        assert_eq!(manifest.description.as_deref(), Some("SQL, classified"));

        // Publishing again replaces the entry rather than adding a second.
        let module = root.join("countersign_db.wasm");
        publish(&module, &market, &PublishFields::default()).unwrap();
        assert_eq!(load_index(&location).unwrap().plugins.len(), 1);

        let packs_dir = root.join("packs");
        let installed = install(&location, "countersign-db", &packs_dir).unwrap();
        assert!(!installed.enabled, "installed off, like every install");
        assert_eq!(installed.manifest.pack.as_ref().unwrap().sha256, index.plugins[0].sha256);
        assert!(packs::list(&packs_dir).unwrap().iter().any(|p| p.name == "countersign-db"));

        let report = super::inspect(&location, "countersign-db").unwrap();
        assert!(matches!(report.source, Source::Index { .. }));
        assert!(matches!(install(&location, "nope", &packs_dir), Err(MarketError::NotListed(_))));
    }

    #[test]
    fn an_index_whose_hash_disagrees_with_the_manifest_installs_nothing() {
        let Some((root, market)) = published("hash-disagree") else { return };
        let location = Location::Dir(market.clone());
        let mut index = load_index(&location).unwrap();
        index.plugins[0].sha256 = "00".repeat(32);
        std::fs::write(market.join(INDEX_FILE), serde_json::to_string(&index).unwrap()).unwrap();
        let packs_dir = root.join("packs");
        assert!(matches!(install(&location, "countersign-db", &packs_dir), Err(MarketError::Disagree(_))));
        assert!(!packs_dir.exists());
    }

    #[test]
    fn a_module_swapped_under_a_good_manifest_installs_nothing() {
        let Some((root, market)) = published("swapped") else { return };
        std::fs::write(market.join("countersign-db").join("countersign_db.wasm"), b"\0asm\x01\0\0\0").unwrap();
        let err = install(&Location::Dir(market), "countersign-db", &root.join("packs")).unwrap_err();
        assert!(matches!(err, MarketError::Disagree(_)), "{err}");
    }

    #[test]
    fn a_native_plugin_is_never_installed_from_an_index() {
        let root = temp("native");
        let market = root.join("market");
        let dir = market.join("countersign-tf");
        std::fs::create_dir_all(&dir).unwrap();
        let bytes = b"#!/bin/sh\nexit 1\n";
        std::fs::write(dir.join("pack.sh"), bytes).unwrap();
        Manifest {
            v: 1,
            name: "countersign-tf".into(),
            version: "0.0.1".into(),
            description: None,
            license: None,
            source: None,
            pack: Some(PackArtifact {
                kind: ArtifactKind::Native,
                artifact: "pack.sh".into(),
                sha256: sha256_hex(bytes),
                actions: vec!["terraform".into()],
                pure: true,
            }),
            policy: vec![],
        }
        .save(&dir)
        .unwrap();
        let index = Index {
            v: 1,
            plugins: vec![Entry {
                name: "countersign-tf".into(),
                version: "0.0.1".into(),
                description: None,
                path: "countersign-tf".into(),
                sha256: sha256_hex(bytes),
                actions: vec!["terraform".into()],
                pure: true,
            }],
        };
        std::fs::write(market.join(INDEX_FILE), serde_json::to_string(&index).unwrap()).unwrap();
        let err = install(&Location::Dir(market.clone()), "countersign-tf", &root.join("packs")).unwrap_err();
        assert!(matches!(err, MarketError::NotWasm(_)), "{err}");
        // And publishing one is refused for the same reason.
        assert!(matches!(
            publish(&dir, &root.join("market2"), &PublishFields::default()),
            Err(MarketError::NotWasm(_))
        ));
    }

    #[test]
    fn an_index_cannot_point_outside_its_own_directory() {
        let Some((root, market)) = published("traversal") else { return };
        let location = Location::Dir(market.clone());
        let mut index = load_index(&location).unwrap();
        index.plugins[0].path = "../elsewhere".into();
        std::fs::write(market.join(INDEX_FILE), serde_json::to_string(&index).unwrap()).unwrap();
        let err = install(&location, "countersign-db", &root.join("packs")).unwrap_err();
        assert!(matches!(err, MarketError::BadPath(_)), "{err}");
    }

    #[test]
    fn a_manifest_that_promises_what_the_module_does_not_answer_is_refused() {
        let Some((root, market)) = published("describe") else { return };
        let location = Location::Dir(market.clone());
        let dir = market.join("countersign-db");
        let mut manifest = Manifest::load(&dir).unwrap();
        manifest.pack.as_mut().unwrap().actions = vec!["terraform".into()];
        manifest.save(&dir).unwrap();
        let mut index = load_index(&location).unwrap();
        index.plugins[0].actions = vec!["terraform".into()];
        std::fs::write(market.join(INDEX_FILE), serde_json::to_string(&index).unwrap()).unwrap();
        let err = install(&location, "countersign-db", &root.join("packs")).unwrap_err();
        match err {
            MarketError::Refused(why) => assert!(why.contains("namespaces"), "{why}"),
            other => panic!("expected a refusal, got {other}"),
        }
    }
}

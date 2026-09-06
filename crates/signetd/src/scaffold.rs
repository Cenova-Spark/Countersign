//! `signetd pack new` — a pack crate to rename.
//!
//! The files are `templates/pack` in the repository, embedded at build time.
//! That directory is a workspace member, so the template is compiled and its
//! tests run with everything else; a scaffold that can rot quietly is worse
//! than none. What changes on the way out: the crate name, the namespace,
//! and the dependency line, which points into the checkout here and at the
//! repository everywhere else.

use std::path::{Path, PathBuf};

use countersign_pack::manifest::check_name;

const TEMPLATE_NAME: &str = "countersign-pack-template";
const TEMPLATE_IDENT: &str = "countersign_pack_template";
const TEMPLATE_NAMESPACE: &str = "example";
const TEMPLATE_DEPENDENCY: &str = "countersign-pack = { path = \"../../crates/countersign-pack\" }";
const DEPENDENCY: &str =
    "countersign-pack = { git = \"https://github.com/Cenova-Spark/Countersign.git\" }";

const FILES: &[(&str, &str)] = &[
    ("Cargo.toml", include_str!("../../../templates/pack/Cargo.toml")),
    ("src/lib.rs", include_str!("../../../templates/pack/src/lib.rs")),
    ("src/main.rs", include_str!("../../../templates/pack/src/main.rs")),
    ("README.md", include_str!("../../../templates/pack/README.md")),
];

/// Appended to the scaffold's `Cargo.toml`. The template inherits this from
/// the workspace; a crate on its own has to say it.
const RELEASE_PROFILE: &str = "\n\
# Small modules: one codegen unit, link-time optimisation, symbols stripped.\n\
[profile.release]\n\
codegen-units = 1\n\
lto = true\n\
strip = true\n";

/// The crate identifier for a name: hyphens become underscores.
pub fn ident(name: &str) -> String {
    name.replace('-', "_")
}

/// The namespace a name suggests: the name without a `countersign-` prefix.
pub fn default_namespace(name: &str) -> String {
    name.strip_prefix("countersign-").unwrap_or(name).to_string()
}

/// Whether `namespace` may be one: the same shape as a plugin name, which
/// rules out the dot that would make it an action instead.
pub fn check_namespace(namespace: &str) -> Result<(), ScaffoldError> {
    check_name(namespace).map_err(|_| ScaffoldError::BadNamespace(namespace.to_string()))
}

/// The template, renamed. Paths are relative to the crate directory.
pub fn render(name: &str, namespace: &str) -> Result<Vec<(PathBuf, String)>, ScaffoldError> {
    check_name(name).map_err(|e| ScaffoldError::BadName(e.to_string()))?;
    check_namespace(namespace)?;
    let ident = ident(name);
    let mut out = Vec::with_capacity(FILES.len() + 1);
    for (path, text) in FILES {
        let mut text = text
            .replace(TEMPLATE_NAME, name)
            .replace(TEMPLATE_IDENT, &ident)
            .replace(&format!("\"{TEMPLATE_NAMESPACE}\""), &format!("\"{namespace}\""))
            .replace(&format!("{TEMPLATE_NAMESPACE}."), &format!("{namespace}."));
        if *path == "Cargo.toml" {
            if !text.contains(TEMPLATE_DEPENDENCY) {
                return Err(ScaffoldError::Template(
                    "the template's dependency line has changed; update scaffold.rs to match".into(),
                ));
            }
            text = text.replace(TEMPLATE_DEPENDENCY, DEPENDENCY);
            text.push_str(RELEASE_PROFILE);
        }
        out.push((PathBuf::from(path), text));
    }
    out.push((PathBuf::from(".gitignore"), "/target\n".into()));
    Ok(out)
}

/// Write the scaffold. `dest` must not exist: this never overwrites anything.
pub fn write(dest: &Path, name: &str, namespace: &str) -> Result<Vec<PathBuf>, ScaffoldError> {
    let files = render(name, namespace)?;
    if dest.exists() {
        return Err(ScaffoldError::Exists(dest.to_path_buf()));
    }
    let mut written = Vec::with_capacity(files.len());
    for (rel, text) in files {
        let path = dest.join(&rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| ScaffoldError::Io(parent.to_path_buf(), e.to_string()))?;
        }
        std::fs::write(&path, text).map_err(|e| ScaffoldError::Io(path.clone(), e.to_string()))?;
        written.push(rel);
    }
    Ok(written)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScaffoldError {
    BadName(String),
    BadNamespace(String),
    Exists(PathBuf),
    Io(PathBuf, String),
    Template(String),
}

impl std::fmt::Display for ScaffoldError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScaffoldError::BadName(e) => write!(f, "{e}"),
            ScaffoldError::BadNamespace(ns) => write!(
                f,
                "{ns:?} is not a namespace — lowercase letters, digits and hyphens, and no dot: \
                 `terraform` claims `terraform.apply` and everything else under it"
            ),
            ScaffoldError::Exists(p) => {
                write!(f, "{} already exists; refusing to write over it", p.display())
            }
            ScaffoldError::Io(p, e) => write!(f, "{}: {e}", p.display()),
            ScaffoldError::Template(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ScaffoldError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn file<'a>(files: &'a [(PathBuf, String)], name: &str) -> &'a str {
        &files.iter().find(|(p, _)| p == Path::new(name)).expect(name).1
    }

    #[test]
    fn the_scaffold_is_the_template_renamed_and_pointed_at_the_repository() {
        let files = render("countersign-tf", "terraform").unwrap();
        let cargo = file(&files, "Cargo.toml");
        assert!(cargo.contains("name = \"countersign-tf\""));
        assert!(cargo.contains(DEPENDENCY));
        assert!(!cargo.contains("path = \"../../crates"), "points into a checkout that is not there");
        assert!(cargo.contains("[profile.release]"));
        assert!(file(&files, "src/lib.rs").contains("NAMESPACE: &str = \"terraform\""));
        assert!(file(&files, "src/main.rs").contains("countersign_tf::ExamplePack"));
        assert!(file(&files, "README.md").contains("countersign_tf.wasm"));
        assert!(file(&files, "README.md").contains("\"action\":\"terraform.run\""));
        for (path, text) in &files {
            assert!(
                !text.contains(TEMPLATE_NAME) && !text.contains(TEMPLATE_IDENT),
                "{} still names the template",
                path.display()
            );
            assert!(
                !text.contains("\"example\"") && !text.contains("example."),
                "{} still names the template's namespace",
                path.display()
            );
        }
        assert!(files.iter().any(|(p, _)| p == Path::new(".gitignore")));
    }

    #[test]
    fn the_template_itself_is_what_the_substitutions_expect() {
        // If someone renames things in `templates/pack`, this is the test
        // that says so, rather than `pack new` quietly writing a crate that
        // still calls itself the template.
        assert!(FILES[0].1.contains(TEMPLATE_DEPENDENCY));
        assert!(FILES[0].1.contains(&format!("name = \"{TEMPLATE_NAME}\"")));
        assert!(FILES[1].1.contains(&format!("NAMESPACE: &str = \"{TEMPLATE_NAMESPACE}\"")));
        assert!(FILES[2].1.contains(&format!("{TEMPLATE_IDENT}::")));
    }

    #[test]
    fn the_default_namespace_drops_the_prefix() {
        assert_eq!(default_namespace("countersign-tf"), "tf");
        assert_eq!(default_namespace("k8s-gate"), "k8s-gate");
        assert_eq!(ident("countersign-tf"), "countersign_tf");
    }

    #[test]
    fn names_and_namespaces_are_checked_and_nothing_is_overwritten() {
        assert!(matches!(render("Bad Name", "x"), Err(ScaffoldError::BadName(_))));
        assert!(matches!(render("ok", "sql.ddl"), Err(ScaffoldError::BadNamespace(_))));

        let dir = std::env::temp_dir().join(format!("signetd-scaffold-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(matches!(write(&dir, "ok", "ok"), Err(ScaffoldError::Exists(_))));

        let dest = dir.join("countersign-tf");
        let written = write(&dest, "countersign-tf", "terraform").unwrap();
        assert_eq!(written.len(), 5);
        assert!(dest.join("src/lib.rs").exists());
        assert!(dest.join(".gitignore").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

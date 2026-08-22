//! `~/.config/countersign/config.toml` — environments and policy.
//!
//! The daemon owns this file, and the requester never sees it. That asymmetry
//! is the point: policy must not be supplied by the party being policed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use countersign_pack::Severity;
use serde::{Deserialize, Serialize};

/// How much an environment matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    Development,
    Staging,
    Production,
}

impl Tier {
    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Development => "development",
            Tier::Staging => "staging",
            Tier::Production => "production",
        }
    }

    /// The severity a request is assumed to carry before any pack speaks.
    ///
    /// A floor, never a ceiling — a pack can raise it and can never lower it.
    /// Production starts at `Moderate` so that an unclassifiable statement on a
    /// production target is already serious before anyone looks at it.
    pub fn severity_floor(self) -> Severity {
        match self {
            Tier::Development => Severity::None,
            Tier::Staging => Severity::Low,
            Tier::Production => Severity::Moderate,
        }
    }
}

/// One labelled environment, keyed on target fingerprints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Environment {
    /// What the device displays. Colour-coded by `tier`.
    pub label: String,
    pub tier: Tier,
    /// Lowercase-hex SHA-256 fingerprints of the URIs in this environment.
    #[serde(default)]
    pub uri_fingerprints: Vec<String>,
}

/// What a matching rule does.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleDecision {
    /// Ask the human. The only path that produces a signature.
    ///
    /// The `Default`, so that a rule built programmatically without stating a
    /// decision asks rather than allows.
    #[default]
    RequireApproval,
    /// Let it through and record it.
    AutoApprove,
    /// Refuse without asking anyone.
    Deny,
}

/// One policy rule. Omitted fields match anything.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<Tier>,
    /// Action namespaces or full verbs. `"sql"` matches `sql.ddl`; `"sql.ddl"`
    /// matches only that.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,
    /// Requester ids. **Advisory** — a requester can claim any id, so this may
    /// tighten a rule and must never be the only thing standing between an
    /// agent and a production table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requesters: Option<Vec<String>>,
    /// Only apply at or above this severity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_severity: Option<Severity>,
    /// Only apply to requests arriving on this kind of socket.
    ///
    /// The scoping hook for delegation: a forwarded socket hands the ability
    /// to ask to everything on the far side of a tunnel, so an operator will
    /// often want it to reach fewer actions than a local client does. Set
    /// `origin = "forwarded"` on a tighter rule and place it above the general
    /// one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<crate::daemon::OriginKind>,
    pub decision: RuleDecision,
}

/// What to do when approval is required and no device is attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnNoDevice {
    Deny,
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// The tier assumed for a fingerprint no environment claims.
    ///
    /// `Production` by default, and deliberately so: an unknown database is one
    /// nobody has classified yet, and the safe reading of that is not "probably
    /// dev". Fail toward friction.
    #[serde(default = "default_tier")]
    pub default_tier: Tier,

    /// Applies only where a rule already said `require_approval` — anything
    /// auto-approved never reaches the device, so a development tier that
    /// auto-approves is unaffected by this setting.
    #[serde(default = "default_on_no_device")]
    pub on_no_device: OnNoDevice,

    /// Action namespaces that may ever reach the device.
    ///
    /// Leave unset and it is derived: a namespace becomes presentable by being
    /// named in some rule's `actions`. Set it explicitly to override.
    ///
    /// This exists to stop the dial from being trained on trivia. Anything
    /// outside the set is refused **without asking a human**, so a plugin that
    /// wanted the dial to skip a track cannot make it light up — and the
    /// operator therefore never builds the reflex that a real approval would
    /// exploit. See `presentable_namespaces`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presentable: Option<Vec<String>>,

    /// Evaluated in file order; **first match wins**.
    #[serde(default, rename = "rule")]
    pub rules: Vec<Rule>,
}

impl Policy {
    /// Which namespaces may reach the device.
    ///
    /// Derived from the rules unless stated outright, because the natural way
    /// to say "this daemon handles SQL" is to write a rule about SQL — and
    /// requiring a second, separate list would mostly get copied wrong.
    ///
    /// A rule with no `actions` contributes nothing here. Such a rule means
    /// "whatever else, at this tier" and is a statement about severity, not an
    /// invitation for every namespace on the machine to start asking.
    pub fn presentable_namespaces(&self) -> BTreeSet<String> {
        if let Some(explicit) = &self.presentable {
            return explicit
                .iter()
                .map(|n| namespace_of(n).to_string())
                .collect();
        }
        self.rules
            .iter()
            .filter_map(|r| r.actions.as_ref())
            .flatten()
            .map(|a| namespace_of(a).to_string())
            .collect()
    }

    /// Whether an action may be shown to a human at all.
    pub fn may_present(&self, action: &str) -> bool {
        self.presentable_namespaces().contains(namespace_of(action))
    }
}

/// The namespace of an action verb: everything before the first `.`.
pub fn namespace_of(action: &str) -> &str {
    action.split_once('.').map_or(action, |(ns, _)| ns)
}

fn default_tier() -> Tier {
    Tier::Production
}

fn default_on_no_device() -> OnNoDevice {
    OnNoDevice::Deny
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            default_tier: default_tier(),
            on_no_device: default_on_no_device(),
            presentable: None,
            rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default, rename = "environment")]
    pub environments: Vec<Environment>,
    #[serde(default)]
    pub policy: Policy,
}

impl Config {
    pub fn parse(toml_text: &str) -> Result<Self, ConfigError> {
        let config: Config =
            toml::from_str(toml_text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::Read(path.to_path_buf(), e.to_string()))?;
        Self::parse(&text)
    }

    /// Load from `path`, or return defaults if it does not exist.
    ///
    /// A missing config is not an error, and the defaults are the strict ones:
    /// everything unknown is production, and production requires approval. A
    /// daemon that started permissively because someone had not written a
    /// config yet would be the worst possible default.
    pub fn load_or_default(path: &Path) -> Result<Self, ConfigError> {
        if path.exists() {
            Self::load(path)
        } else {
            Ok(Self {
                environments: Vec::new(),
                policy: Policy {
                    rules: vec![Rule {
                        tier: Some(Tier::Production),
                        // Named so that `sql` is presentable out of the box.
                        // Everything else is refused rather than shown, which
                        // is the whole point of the list.
                        actions: Some(vec!["sql".into()]),
                        decision: RuleDecision::RequireApproval,
                        ..Default::default()
                    }],
                    ..Default::default()
                },
            })
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
        for env in &self.environments {
            for fp in &env.uri_fingerprints {
                if fp.len() != 64 || !fp.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(ConfigError::BadFingerprint(fp.clone()));
                }
                // One database in two environments has no defensible answer —
                // whichever the daemon picked, the label on the screen could be
                // the wrong one, and the label is the part the requester is not
                // allowed to influence.
                if let Some(other) = seen.insert(fp, &env.label) {
                    if other != env.label {
                        return Err(ConfigError::DuplicateFingerprint {
                            fingerprint: fp.clone(),
                            first: other.to_string(),
                            second: env.label.clone(),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    /// Classify a target fingerprint into a label and tier.
    ///
    /// This is the function the requester does not get to call. The wire format
    /// deliberately has no `target.label` field; the answer comes from here.
    pub fn classify(&self, uri_fingerprint: &str) -> Classification {
        for env in &self.environments {
            if env.uri_fingerprints.iter().any(|f| f == uri_fingerprint) {
                return Classification {
                    label: env.label.clone(),
                    tier: env.tier,
                    known: true,
                };
            }
        }
        Classification {
            label: format!(
                "unknown ({})",
                &uri_fingerprint[..8.min(uri_fingerprint.len())]
            ),
            tier: self.policy.default_tier,
            known: false,
        }
    }
}

/// What the daemon decided a target is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classification {
    /// Rendered on the device.
    pub label: String,
    pub tier: Tier,
    /// Whether any environment claimed this fingerprint.
    pub known: bool,
}

/// The default config location.
pub fn default_path() -> PathBuf {
    if let Ok(explicit) = std::env::var("COUNTERSIGN_CONFIG") {
        return PathBuf::from(explicit);
    }
    config_dir().join("config.toml")
}

pub fn config_dir() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("countersign");
    }
    match std::env::var("HOME") {
        Ok(home) => PathBuf::from(home).join(".config").join("countersign"),
        Err(_) => PathBuf::from(".countersign"),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    Read(PathBuf, String),
    Parse(String),
    BadFingerprint(String),
    DuplicateFingerprint {
        fingerprint: String,
        first: String,
        second: String,
    },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Read(p, e) => write!(f, "cannot read {}: {e}", p.display()),
            ConfigError::Parse(e) => write!(f, "invalid config: {e}"),
            ConfigError::BadFingerprint(fp) => write!(
                f,
                "{fp:?} is not a fingerprint — expected 64 hex characters (the SHA-256 of a \
                 normalized URI; run `signetd fingerprint <uri>` to compute one)"
            ),
            ConfigError::DuplicateFingerprint {
                fingerprint,
                first,
                second,
            } => write!(
                f,
                "fingerprint {fingerprint} is claimed by both {first:?} and {second:?}; one \
                 database cannot be in two environments"
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[[environment]]
label = "prod-us-east-1"
tier  = "production"
uri_fingerprints = [
  "9f2c00000000000000000000000000000000000000000000000000000000aaaa",
]

[[environment]]
label = "local"
tier  = "development"
uri_fingerprints = [
  "c70100000000000000000000000000000000000000000000000000000000bbbb",
]

[policy]
default_tier = "production"
on_no_device = "deny"

[[policy.rule]]
tier = "development"
decision = "auto_approve"

[[policy.rule]]
tier = "production"
actions = ["sql.ddl", "sql.dml", "migration.apply"]
decision = "require_approval"
"#;

    const PROD_FP: &str = "9f2c00000000000000000000000000000000000000000000000000000000aaaa";
    const DEV_FP: &str = "c70100000000000000000000000000000000000000000000000000000000bbbb";

    #[test]
    fn the_handoff_config_sketch_parses() {
        let c = Config::parse(SAMPLE).unwrap();
        assert_eq!(c.environments.len(), 2);
        assert_eq!(c.policy.rules.len(), 2);
        assert_eq!(c.policy.default_tier, Tier::Production);
        assert_eq!(c.policy.on_no_device, OnNoDevice::Deny);
    }

    #[test]
    fn a_known_fingerprint_gets_its_label_and_tier() {
        let c = Config::parse(SAMPLE).unwrap();
        let prod = c.classify(PROD_FP);
        assert_eq!(prod.label, "prod-us-east-1");
        assert_eq!(prod.tier, Tier::Production);
        assert!(prod.known);

        assert_eq!(c.classify(DEV_FP).tier, Tier::Development);
    }

    #[test]
    fn an_unknown_fingerprint_is_treated_as_production() {
        // An unclassified database is one nobody has looked at yet, and the
        // safe reading of that is not "probably dev".
        let c = Config::parse(SAMPLE).unwrap();
        let unknown = c.classify(&"ff".repeat(32));
        assert_eq!(unknown.tier, Tier::Production);
        assert!(!unknown.known);
        assert!(
            unknown.label.starts_with("unknown"),
            "and it says so: {}",
            unknown.label
        );
    }

    #[test]
    fn a_missing_config_defaults_to_requiring_approval_everywhere() {
        // Starting permissively because nobody wrote a config yet would be the
        // worst possible default.
        let c = Config::load_or_default(Path::new("/nonexistent/countersign.toml")).unwrap();
        assert_eq!(c.policy.default_tier, Tier::Production);
        assert_eq!(c.classify(&"ab".repeat(32)).tier, Tier::Production);
        assert_eq!(c.policy.rules[0].decision, RuleDecision::RequireApproval);
    }

    #[test]
    fn a_fingerprint_in_two_environments_is_refused() {
        let bad = format!(
            r#"
[[environment]]
label = "prod"
tier = "production"
uri_fingerprints = ["{PROD_FP}"]

[[environment]]
label = "local"
tier = "development"
uri_fingerprints = ["{PROD_FP}"]
"#
        );
        assert!(matches!(
            Config::parse(&bad),
            Err(ConfigError::DuplicateFingerprint { .. })
        ));
    }

    #[test]
    fn the_same_fingerprint_twice_in_one_environment_is_fine() {
        let ok = format!(
            r#"
[[environment]]
label = "prod"
tier = "production"
uri_fingerprints = ["{PROD_FP}", "{PROD_FP}"]
"#
        );
        assert!(Config::parse(&ok).is_ok());
    }

    #[test]
    fn something_that_is_not_a_fingerprint_is_caught_at_load() {
        // Pasting a URI in here instead of its hash is the obvious mistake, and
        // it would silently classify nothing.
        let bad = r#"
[[environment]]
label = "prod"
tier = "production"
uri_fingerprints = ["postgres://db.example.com/app"]
"#;
        let err = Config::parse(bad).unwrap_err();
        assert!(matches!(err, ConfigError::BadFingerprint(_)));
        assert!(err.to_string().contains("64 hex"), "{err}");
    }

    #[test]
    fn severity_floors_rise_with_the_tier() {
        assert_eq!(Tier::Development.severity_floor(), Severity::None);
        assert_eq!(Tier::Staging.severity_floor(), Severity::Low);
        assert_eq!(Tier::Production.severity_floor(), Severity::Moderate);
    }

    #[test]
    fn tiers_order_from_least_to_most_consequential() {
        assert!(Tier::Development < Tier::Staging);
        assert!(Tier::Staging < Tier::Production);
    }
}

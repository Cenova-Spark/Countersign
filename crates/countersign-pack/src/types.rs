//! The pack protocol's data types. See `spec/pack-protocol-v1.md` §3.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The protocol version this crate speaks.
pub const PROTOCOL: u32 = 1;

/// How much damage the classified action could do.
///
/// Ordered, and the ordering is used: the host takes the maximum of its own
/// floor and the pack's answer, so a pack can raise severity and never lower it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Reads. Nothing changes.
    None,
    /// Additive and easily undone.
    Low,
    /// Changes existing data or structure, bounded.
    Moderate,
    /// Unbounded, privileged, or hard to undo.
    High,
    /// Destroys data or objects outright.
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::None => "none",
            Severity::Low => "low",
            Severity::Moderate => "moderate",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

/// What a display line is for.
///
/// Firmware renders roles; packs choose content. Modelling the screen as roles
/// rather than as `{statement, rows_affected}` is what keeps SQL out of the
/// firmware — it is the difference between a device that does databases and a
/// device that does anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RenderRole {
    /// The environment label. **Daemon-only** — see [`RenderRole::pack_may_emit`].
    Label,
    /// The statement, or a pack's rendering of it.
    Primary,
    /// Unverified detail. Rendered with a marker saying so.
    Advisory,
    /// The first 12 hex characters of the request digest. **Daemon-only.**
    Digest,
}

impl RenderRole {
    /// Whether a pack is allowed to emit this role.
    ///
    /// `Label` and `Digest` are exactly the two lines the requester must not be
    /// able to influence. The label is assigned locally so an agent cannot claim
    /// it is talking to dev; the digest is the human's cross-check between the
    /// screen and the signed bytes. A pack that could write either could show
    /// `local` above a production `DROP`.
    pub fn pack_may_emit(self) -> bool {
        matches!(self, RenderRole::Primary | RenderRole::Advisory)
    }
}

/// One line on the device's screen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RenderLine {
    pub role: RenderRole,
    pub text: String,
}

impl RenderLine {
    pub fn primary(text: impl Into<String>) -> Self {
        Self {
            role: RenderRole::Primary,
            text: text.into(),
        }
    }
    pub fn advisory(text: impl Into<String>) -> Self {
        Self {
            role: RenderRole::Advisory,
            text: text.into(),
        }
    }
}

/// A pack's self-description, returned from `describe`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackInfo {
    pub name: String,
    pub version: String,
    pub protocol: u32,
    /// The action **namespaces** this pack claims — `"sql"` claims
    /// `sql.execute`, `sql.ddl`, and everything else under `sql.`.
    pub actions: Vec<String>,
    /// The pack's assertion that `classify` performs no I/O and no network
    /// access. Operators rely on this; see spec §5.
    pub pure: bool,
}

/// What the host asks a pack to classify.
///
/// Note what is absent: the environment label, the tier, and any policy state.
/// A pack classifies the statement; it does not learn how serious the
/// environment thinks that is. Keeping policy out is what makes a pack's answer
/// cacheable and its behaviour independent of what it would take to get
/// approved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassifyRequest {
    pub action: String,
    pub statement: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetRef>,
    /// Free-form and optional. A pack MUST work with no hints at all — an
    /// engine hint may refine a dialect judgement, but a pack that only works
    /// when told the engine fails on the path that matters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hints: Option<Value>,
}

impl ClassifyRequest {
    pub fn new(action: impl Into<String>, statement: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            statement: statement.into(),
            target: None,
            hints: None,
        }
    }

    pub fn with_hints(mut self, hints: Value) -> Self {
        self.hints = Some(hints);
        self
    }
}

/// The target, minus anything that could identify a credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetRef {
    pub kind: String,
    pub uri_fingerprint: String,
}

/// A pack's verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassifyResponse {
    /// The refined verb. Must stay inside the requested namespace.
    pub action: String,
    pub severity: Severity,
    /// `None` means "unknown", which is a legitimate and common answer. A pack
    /// must never guess `Some(true)` — claiming an irreversible action can be
    /// undone is the one error that turns friction into a false sense of safety.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reversible: Option<bool>,
    #[serde(default)]
    pub render: Vec<RenderLine>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advisory: Option<Value>,
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl ClassifyResponse {
    /// A minimal response at a given severity.
    pub fn new(action: impl Into<String>, severity: Severity) -> Self {
        Self {
            action: action.into(),
            severity,
            reversible: None,
            render: Vec::new(),
            advisory: None,
            warnings: Vec::new(),
        }
    }

    /// Raise this response to at least `floor`.
    ///
    /// The asymmetry is the whole security model of the plugin interface: a pack
    /// can tell the daemon a statement is worse than it assumed, and can never
    /// tell it a statement is safer. If it could, the first thing an attacker
    /// would ship is a pack that classifies `DROP TABLE` as `none`.
    #[must_use]
    pub fn raised_to(mut self, floor: Severity) -> Self {
        self.severity = self.severity.max(floor);
        self
    }
}

/// The namespace of an action verb: everything before the first `.`.
pub fn namespace_of(action: &str) -> &str {
    action.split_once('.').map_or(action, |(ns, _)| ns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severities_order_from_harmless_to_destructive() {
        assert!(Severity::None < Severity::Low);
        assert!(Severity::Moderate < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn a_floor_raises_but_never_lowers() {
        let low = ClassifyResponse::new("sql.read", Severity::None);
        assert_eq!(
            low.clone().raised_to(Severity::High).severity,
            Severity::High
        );

        let high = ClassifyResponse::new("sql.ddl", Severity::Critical);
        assert_eq!(
            high.raised_to(Severity::Low).severity,
            Severity::Critical,
            "a low floor must not talk a critical statement down"
        );
    }

    #[test]
    fn only_primary_and_advisory_are_a_packs_to_write() {
        assert!(RenderRole::Primary.pack_may_emit());
        assert!(RenderRole::Advisory.pack_may_emit());
        assert!(
            !RenderRole::Label.pack_may_emit(),
            "the label is assigned locally"
        );
        assert!(
            !RenderRole::Digest.pack_may_emit(),
            "the digest is the human's cross-check"
        );
    }

    #[test]
    fn namespaces_split_at_the_first_dot() {
        assert_eq!(namespace_of("sql.execute"), "sql");
        assert_eq!(namespace_of("k8s.delete.namespace"), "k8s");
        assert_eq!(namespace_of("bare"), "bare");
    }

    #[test]
    fn severity_is_wire_stable() {
        assert_eq!(
            serde_json::to_string(&Severity::Critical).unwrap(),
            r#""critical""#
        );
        assert_eq!(
            serde_json::from_str::<Severity>(r#""moderate""#).unwrap(),
            Severity::Moderate
        );
    }
}

//! The policy engine: what should happen to this request?
//!
//! Policy is the daemon's, never the requester's. Everything here reads from
//! local config and from the pack's classification; nothing reads a field the
//! requesting agent chose.

use countersign_pack::Severity;

use crate::config::{Classification, Config, OnNoDevice, Rule, RuleDecision, Tier};
use crate::daemon::OriginKind;

/// What the daemon will do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Present it on the device and wait for a human.
    RequireApproval,
    /// Proceed without asking, and record it.
    AutoApprove,
    /// Refuse.
    Deny { reason: String },
}

/// The full decision, with enough detail to explain itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub outcome: Outcome,
    pub classification: Classification,
    /// The severity after the pack's answer was raised to the tier's floor.
    pub severity: Severity,
    /// Which rule matched, by index, or `None` when the default applied.
    pub matched_rule: Option<usize>,
    /// One line an operator can read when asking "why did that happen?".
    pub explanation: String,
}

/// What is being asked for.
#[derive(Debug, Clone)]
pub struct Evaluation<'a> {
    /// The refined action verb, after any pack classification.
    pub action: &'a str,
    /// The requester's claimed id. Advisory — never the only control.
    pub requester_id: &'a str,
    /// Effective severity: the pack's answer already raised to the tier floor.
    pub severity: Severity,
    /// Which socket this arrived on. Verified, unlike anything the requester
    /// says about itself.
    pub origin: OriginKind,
    /// Whether a device is currently attached.
    pub device_attached: bool,
}

/// Evaluate policy for one request.
pub fn evaluate(config: &Config, class: &Classification, eval: &Evaluation<'_>) -> Decision {
    let mut matched_rule = None;
    let mut outcome = None;

    // First match wins, in file order. Ordering is the operator's, so a
    // specific rule placed above a general one behaves the way reading the file
    // top to bottom suggests.
    for (index, rule) in config.policy.rules.iter().enumerate() {
        if rule_matches(rule, class.tier, eval) {
            matched_rule = Some(index);
            outcome = Some(match rule.decision {
                RuleDecision::RequireApproval => Outcome::RequireApproval,
                RuleDecision::AutoApprove => Outcome::AutoApprove,
                RuleDecision::Deny => Outcome::Deny {
                    reason: format!(
                        "policy rule {index} denies {} on {}",
                        eval.action, class.label
                    ),
                },
            });
            break;
        }
    }

    // Nothing matched. Requiring approval is the only defensible default: a
    // request nobody wrote a rule for is one nobody has thought about.
    let outcome = outcome.unwrap_or(Outcome::RequireApproval);

    // Before anything can reach the device, it has to be something this daemon
    // was set up to ask about.
    //
    // Without this, any namespace at all could make the dial light up, and the
    // attack that enables is not a clever one: wire a plugin so that turning
    // skips a track, let someone build the reflex over a week, then time a real
    // `DROP TABLE` to arrive as they reach for it. They turn without reading,
    // because turning has meant "next song" two hundred times.
    //
    // The defence is to keep the dial rare. An action nobody configured is
    // refused outright rather than shown, so the reflex never forms.
    let outcome = match outcome {
        Outcome::RequireApproval if !config.policy.may_present(eval.action) => Outcome::Deny {
            reason: format!(
                "{} is not an action this daemon presents for approval; add {:?} to a policy \
                 rule's `actions` (or to policy.presentable) if it genuinely warrants a human",
                eval.action,
                crate::config::namespace_of(eval.action)
            ),
        },
        other => other,
    };

    let (outcome, explanation) =
        apply_device_availability(config, class, eval, outcome, matched_rule);

    Decision {
        outcome,
        classification: class.clone(),
        severity: eval.severity,
        matched_rule,
        explanation,
    }
}

/// Fold in whether a device is actually present.
fn apply_device_availability(
    config: &Config,
    class: &Classification,
    eval: &Evaluation<'_>,
    outcome: Outcome,
    matched_rule: Option<usize>,
) -> (Outcome, String) {
    let rule_text = match matched_rule {
        Some(i) => format!("rule {i}"),
        None => "no rule matched, so the default applied".to_string(),
    };

    match outcome {
        Outcome::RequireApproval if !eval.device_attached => match config.policy.on_no_device {
            OnNoDevice::Deny => (
                Outcome::Deny {
                    reason: format!(
                        "{} on {} requires a countersignature and no device is attached",
                        eval.action, class.label
                    ),
                },
                format!(
                    "{rule_text} requires approval; no device attached and on_no_device = deny"
                ),
            ),
            OnNoDevice::Allow => (
                Outcome::AutoApprove,
                format!(
                    "{rule_text} requires approval; no device attached and on_no_device = allow, \
                     so this proceeded UNSIGNED"
                ),
            ),
        },
        Outcome::RequireApproval => (
            Outcome::RequireApproval,
            format!(
                "{rule_text} requires approval for {} on {} ({})",
                eval.action,
                class.label,
                eval.severity.as_str()
            ),
        ),
        Outcome::AutoApprove => (
            Outcome::AutoApprove,
            format!(
                "{rule_text} auto-approves {} on {}",
                eval.action, class.label
            ),
        ),
        Outcome::Deny { reason } => {
            let explanation = format!("{rule_text} denies this: {reason}");
            (Outcome::Deny { reason }, explanation)
        }
    }
}

fn rule_matches(rule: &Rule, tier: Tier, eval: &Evaluation<'_>) -> bool {
    if let Some(want) = rule.tier {
        if want != tier {
            return false;
        }
    }
    if let Some(actions) = &rule.actions {
        if !actions.iter().any(|a| action_matches(a, eval.action)) {
            return false;
        }
    }
    if let Some(requesters) = &rule.requesters {
        if !requesters.iter().any(|r| r == eval.requester_id) {
            return false;
        }
    }
    if let Some(min) = rule.min_severity {
        if eval.severity < min {
            return false;
        }
    }
    if let Some(want) = rule.origin {
        if want != eval.origin {
            return false;
        }
    }
    true
}

/// Whether a rule's action pattern covers an action verb.
///
/// A pattern matches the whole verb, or a `.`-delimited prefix of it: `"sql"`
/// covers `sql.ddl` and `sql.dml`, while `"sql.ddl"` covers only its own. The
/// boundary check is what stops `"sql"` from also matching a hypothetical
/// `sqlite.something`.
fn action_matches(pattern: &str, action: &str) -> bool {
    if pattern == action {
        return true;
    }
    action
        .strip_prefix(pattern)
        .is_some_and(|rest| rest.starts_with('.'))
}

/// The tier floor, applied to whatever the pack said.
///
/// A pack may raise severity and never lower it, so this is a `max`. The floor
/// exists because a statement nothing could classify is still on production.
pub fn effective_severity(tier: Tier, pack_severity: Severity) -> Severity {
    pack_severity.max(tier.severity_floor())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    const PROD_FP: &str = "9f2c00000000000000000000000000000000000000000000000000000000aaaa";
    const DEV_FP: &str = "c70100000000000000000000000000000000000000000000000000000000bbbb";

    fn config() -> Config {
        Config::parse(&format!(
            r#"
[[environment]]
label = "prod-us-east-1"
tier  = "production"
uri_fingerprints = ["{PROD_FP}"]

[[environment]]
label = "local"
tier  = "development"
uri_fingerprints = ["{DEV_FP}"]

[policy]
default_tier = "production"
on_no_device = "deny"

[[policy.rule]]
tier = "development"
decision = "auto_approve"

[[policy.rule]]
tier = "production"
actions = ["sql.ddl", "sql.dml"]
decision = "require_approval"

[[policy.rule]]
tier = "production"
actions = ["sql.read"]
decision = "auto_approve"
"#
        ))
        .unwrap()
    }

    fn eval<'a>(action: &'a str, severity: Severity, attached: bool) -> Evaluation<'a> {
        eval_from(action, severity, attached, OriginKind::Local)
    }

    fn eval_from<'a>(
        action: &'a str,
        severity: Severity,
        attached: bool,
        origin: OriginKind,
    ) -> Evaluation<'a> {
        Evaluation {
            action,
            requester_id: "claude-code",
            severity,
            origin,
            device_attached: attached,
        }
    }

    fn decide(fp: &str, action: &str, severity: Severity, attached: bool) -> Decision {
        let c = config();
        let class = c.classify(fp);
        let sev = effective_severity(class.tier, severity);
        evaluate(&c, &class, &eval(action, sev, attached))
    }

    #[test]
    fn a_destructive_statement_on_production_needs_a_human() {
        let d = decide(PROD_FP, "sql.ddl", Severity::Critical, true);
        assert_eq!(d.outcome, Outcome::RequireApproval);
        assert_eq!(d.classification.label, "prod-us-east-1");
        assert_eq!(d.matched_rule, Some(1));
    }

    #[test]
    fn a_read_on_production_goes_straight_through() {
        let d = decide(PROD_FP, "sql.read", Severity::None, true);
        assert_eq!(d.outcome, Outcome::AutoApprove);
        assert_eq!(d.matched_rule, Some(2));
    }

    #[test]
    fn development_is_waved_through_entirely() {
        let d = decide(DEV_FP, "sql.ddl", Severity::Critical, true);
        assert_eq!(d.outcome, Outcome::AutoApprove);
        assert_eq!(d.matched_rule, Some(0), "the development rule comes first");
    }

    #[test]
    fn an_unknown_database_is_treated_as_production() {
        // The single most important default in the file.
        let d = decide(&"ff".repeat(32), "sql.ddl", Severity::Critical, true);
        assert_eq!(d.outcome, Outcome::RequireApproval);
        assert_eq!(d.classification.tier, Tier::Production);
    }

    #[test]
    fn a_forwarded_socket_can_be_scoped_more_tightly_than_a_local_one() {
        // Forwarding is delegation: everything on the far side of the tunnel
        // gains the ability to ask. An operator will often want it to reach
        // fewer actions than a client sitting on their own machine.
        let c = Config::parse(&format!(
            r#"
[[environment]]
label = "prod"
tier = "production"
uri_fingerprints = ["{PROD_FP}"]

[[policy.rule]]
tier = "production"
origin = "forwarded"
actions = ["sql.ddl"]
decision = "deny"

[[policy.rule]]
tier = "production"
actions = ["sql"]
decision = "require_approval"
"#
        ))
        .unwrap();
        let class = c.classify(PROD_FP);

        let forwarded = evaluate(
            &c,
            &class,
            &eval_from("sql.ddl", Severity::Critical, true, OriginKind::Forwarded),
        );
        assert!(
            matches!(forwarded.outcome, Outcome::Deny { .. }),
            "got {:?}",
            forwarded.outcome
        );

        // The same statement from a local client still just asks.
        let local = evaluate(
            &c,
            &class,
            &eval_from("sql.ddl", Severity::Critical, true, OriginKind::Local),
        );
        assert_eq!(local.outcome, Outcome::RequireApproval);
    }

    #[test]
    fn a_rule_without_an_origin_applies_to_both() {
        for origin in [OriginKind::Local, OriginKind::Forwarded] {
            let d = evaluate(
                &config(),
                &config().classify(PROD_FP),
                &eval_from("sql.ddl", Severity::Critical, true, origin),
            );
            assert_eq!(d.outcome, Outcome::RequireApproval, "{origin:?}");
        }
    }

    #[test]
    fn an_unconfigured_namespace_is_refused_without_ever_asking_a_human() {
        // The habituation defence. If any plugin could make the dial light up,
        // someone could wire a turn to "skip track", let the reflex form, and
        // then time a real DROP to arrive as the user reaches for it.
        //
        // Refusing rather than asking keeps the dial rare, so the reflex never
        // forms in the first place.
        let d = decide(PROD_FP, "media.next", Severity::High, true);
        assert!(
            matches!(d.outcome, Outcome::Deny { .. }),
            "got {:?}",
            d.outcome
        );
        assert!(
            d.explanation.contains("not an action this daemon presents"),
            "{}",
            d.explanation
        );
    }

    #[test]
    fn a_namespace_becomes_presentable_by_being_named_in_a_rule() {
        // The natural way to say "this daemon handles SQL" is to write a rule
        // about SQL, so that is what makes it presentable.
        assert!(config().policy.may_present("sql.ddl"));
        assert!(!config().policy.may_present("media.next"));
        assert!(!config().policy.may_present("terraform.apply"));
    }

    #[test]
    fn a_catch_all_rule_does_not_open_the_dial_to_everything() {
        // `tier = production, decision = require_approval` with no `actions`
        // means "whatever else, at this tier" — a statement about severity, not
        // an invitation for every namespace on the machine to start asking.
        let c = Config::parse(&format!(
            r#"
[[environment]]
label = "prod"
tier = "production"
uri_fingerprints = ["{PROD_FP}"]

[[policy.rule]]
tier = "production"
actions = ["sql"]
decision = "require_approval"

[[policy.rule]]
tier = "production"
decision = "require_approval"
"#
        ))
        .unwrap();
        let class = c.classify(PROD_FP);

        let sql = evaluate(&c, &class, &eval("sql.ddl", Severity::Critical, true));
        assert_eq!(sql.outcome, Outcome::RequireApproval);

        let media = evaluate(&c, &class, &eval("media.next", Severity::Critical, true));
        assert!(
            matches!(media.outcome, Outcome::Deny { .. }),
            "got {:?}",
            media.outcome
        );
    }

    #[test]
    fn an_explicit_presentable_list_overrides_the_derived_one() {
        let c = Config::parse(&format!(
            r#"
[[environment]]
label = "prod"
tier = "production"
uri_fingerprints = ["{PROD_FP}"]

[policy]
presentable = ["terraform"]

[[policy.rule]]
tier = "production"
actions = ["sql"]
decision = "require_approval"
"#
        ))
        .unwrap();
        assert!(c.policy.may_present("terraform.apply"));
        assert!(
            !c.policy.may_present("sql.ddl"),
            "an explicit list is the whole list"
        );
    }

    #[test]
    fn an_unconfigured_namespace_cannot_sneak_in_as_a_lookalike() {
        // `sqlite.query` must not ride in on a rule that named `sql`.
        assert!(!config().policy.may_present("sqlite.query"));
    }

    #[test]
    fn no_device_means_denied_rather_than_allowed() {
        let d = decide(PROD_FP, "sql.ddl", Severity::Critical, false);
        assert!(
            matches!(d.outcome, Outcome::Deny { .. }),
            "got {:?}",
            d.outcome
        );
        assert!(
            d.explanation.contains("no device attached"),
            "{}",
            d.explanation
        );
    }

    #[test]
    fn no_device_does_not_block_something_that_was_auto_approved_anyway() {
        // Auto-approved requests never reach the device, so an unplugged
        // Signet must not stop someone reading from their laptop's database.
        let d = decide(DEV_FP, "sql.ddl", Severity::Critical, false);
        assert_eq!(d.outcome, Outcome::AutoApprove);
    }

    #[test]
    fn on_no_device_allow_says_loudly_that_nothing_was_signed() {
        let c = Config::parse(&format!(
            r#"
[[environment]]
label = "prod"
tier = "production"
uri_fingerprints = ["{PROD_FP}"]

[policy]
on_no_device = "allow"

[[policy.rule]]
tier = "production"
actions = ["sql"]
decision = "require_approval"
"#
        ))
        .unwrap();
        let class = c.classify(PROD_FP);
        let d = evaluate(&c, &class, &eval("sql.ddl", Severity::Critical, false));
        assert_eq!(d.outcome, Outcome::AutoApprove);
        assert!(d.explanation.contains("UNSIGNED"), "{}", d.explanation);
    }

    #[test]
    fn an_action_namespace_covers_its_verbs_but_not_a_lookalike() {
        assert!(action_matches("sql", "sql.ddl"));
        assert!(action_matches("sql", "sql.dml.delete"));
        assert!(action_matches("sql.ddl", "sql.ddl"));
        assert!(!action_matches("sql.ddl", "sql.dml"));
        // The boundary check that stops a prefix from over-reaching.
        assert!(!action_matches("sql", "sqlite.query"));
        assert!(!action_matches("sql", "sqlx"));
    }

    #[test]
    fn a_min_severity_rule_only_fires_at_or_above_it() {
        let c = Config::parse(&format!(
            r#"
[[environment]]
label = "prod"
tier = "production"
uri_fingerprints = ["{PROD_FP}"]

[[policy.rule]]
tier = "production"
actions = ["sql"]
min_severity = "critical"
decision = "deny"

[[policy.rule]]
tier = "production"
actions = ["sql"]
decision = "require_approval"
"#
        ))
        .unwrap();
        let class = c.classify(PROD_FP);

        let critical = evaluate(&c, &class, &eval("sql.ddl", Severity::Critical, true));
        assert!(matches!(critical.outcome, Outcome::Deny { .. }));

        let high = evaluate(&c, &class, &eval("sql.ddl", Severity::High, true));
        assert_eq!(high.outcome, Outcome::RequireApproval);
    }

    #[test]
    fn the_tier_floor_raises_a_packs_answer_and_never_lowers_it() {
        assert_eq!(
            effective_severity(Tier::Production, Severity::None),
            Severity::Moderate,
            "a read on production is not 'none' as far as policy is concerned"
        );
        assert_eq!(
            effective_severity(Tier::Development, Severity::Critical),
            Severity::Critical,
            "a dev tier must not talk a DROP down"
        );
    }

    #[test]
    fn every_decision_explains_itself() {
        // An operator asking "why did that need approval?" should not have to
        // read the rules file and guess.
        for (fp, action, sev, attached) in [
            (PROD_FP, "sql.ddl", Severity::Critical, true),
            (PROD_FP, "sql.read", Severity::None, true),
            (DEV_FP, "sql.ddl", Severity::Critical, true),
            (PROD_FP, "sql.ddl", Severity::Critical, false),
        ] {
            let d = decide(fp, action, sev, attached);
            assert!(!d.explanation.is_empty(), "{action} on {fp}");
        }
    }
}

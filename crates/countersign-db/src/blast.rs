//! Turning "what is this statement" into "how much could it destroy".
//!
//! [`countersign_sql`] answers the first question. This module answers the
//! second, and the two are genuinely different: a `DELETE` is a `DELETE` whether
//! it removes one row or forty million, and only one of those is worth waking
//! someone up for.
//!
//! # What this can and cannot know
//!
//! It never touches the database. There is no `EXPLAIN`, no row count, no
//! catalogue lookup — a pack is a pure function of its input (see the pack
//! protocol, §5), because the statement it is handed contains production data
//! and a pack that connects anywhere has turned an approval prompt into an
//! exfiltration channel.
//!
//! So the estimate is structural. "Unbounded" here means *this statement
//! contains no top-level `WHERE`*, not *this statement will touch every row* —
//! the first is knowable from the text and the second is not. A caller who
//! wants a real row count must supply it in the request's `advisory` block,
//! where it is rendered as the unverified claim it is.

use countersign_pack::Severity;
use countersign_sql::{
    analyze, code_tokens, split_on_semicolons, StatementKind, Tok, WriteCapability,
};

/// One statement's assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementAssessment {
    pub sql: String,
    pub kind: StatementKind,
    pub severity: Severity,
    /// No top-level `WHERE` on a statement whose scope one would bound.
    pub unbounded: bool,
}

/// A whole batch's assessment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assessment {
    /// The refined action verb: `sql.read`, `sql.dml`, `sql.ddl`, `sql.grant`,
    /// `sql.exec`, or `sql.unknown`.
    pub action: &'static str,
    pub severity: Severity,
    /// `Some(false)` for statements that destroy data or objects. Never
    /// `Some(true)` — see [`reversibility`].
    pub reversible: Option<bool>,
    pub read_only: bool,
    pub statements: Vec<StatementAssessment>,
    pub warnings: Vec<String>,
}

/// Assess a SQL string.
pub fn assess(sql: &str) -> Assessment {
    // The authoritative read-only and capability verdict. `analyze` classifies
    // the text under *both* backslash dialects and keeps the stronger answer,
    // which the per-statement pass below does not do — so its verdict is a floor
    // that the per-statement detail is never allowed to talk down.
    let safety = analyze(sql);

    let statements: Vec<StatementAssessment> = split_on_semicolons(sql)
        .into_iter()
        .map(|stmt| {
            let kind = analyze(&stmt).primary_kind;
            let unbounded = is_unbounded(&stmt, kind);
            StatementAssessment {
                severity: severity_of(&stmt, kind, unbounded),
                sql: stmt,
                kind,
                unbounded,
            }
        })
        .collect();

    let worst = statements
        .iter()
        .map(|s| s.severity)
        .max()
        .unwrap_or(Severity::None);
    let severity = worst.max(capability_floor(safety.required_capability()));

    let mut warnings = safety.warnings.clone();
    for s in &statements {
        if s.unbounded && matches!(s.kind, StatementKind::Update | StatementKind::Delete) {
            // `analyze` already warns on a missing WHERE, but it looks for the
            // keyword anywhere in the statement. This one is depth-aware, so it
            // is the one that fires on `UPDATE t SET a = (SELECT … WHERE …)`.
            let msg = format!(
                "{} has no top-level WHERE clause — it applies to every row.",
                s.kind.as_str().to_uppercase()
            );
            if !warnings.contains(&msg) {
                warnings.push(msg);
            }
        }
    }

    Assessment {
        action: action_for(&statements, safety.read_only),
        severity,
        reversible: reversibility(&statements),
        read_only: safety.read_only,
        statements,
        warnings,
    }
}

/// The refined verb policy rules key on.
///
/// Reported as the most consequential family in the batch, because a batch is
/// approved or refused as a unit — labelling `SELECT 1; DROP TABLE t` as
/// `sql.read` would be true of one statement and catastrophic as a verb.
fn action_for(statements: &[StatementAssessment], read_only: bool) -> &'static str {
    use StatementKind::*;

    let mut best = "sql.read";
    let mut rank = 0u8;
    for s in statements {
        let (verb, r) = match s.kind {
            Select | Explain | Show | Set | Tcl | Empty => ("sql.read", 0),
            Insert | Update | Delete => ("sql.dml", 1),
            // TRUNCATE sits with DDL rather than DML, which is a judgement call
            // worth stating. It touches rows, so DML is defensible — but most
            // engines implement it as DDL with an implicit commit that a
            // transaction cannot take back, and its blast radius is a DROP's,
            // not a DELETE's. An operator who gates `sql.ddl` to catch
            // "structural and irreversible" would be badly surprised to find
            // TRUNCATE outside it.
            Create | Alter | Drop | Truncate => ("sql.ddl", 2),
            Grant => ("sql.grant", 3),
            Call => ("sql.exec", 4),
            Other => ("sql.unknown", 5),
        };
        if r >= rank {
            rank = r;
            best = verb;
        }
    }

    // A batch `analyze` refuses to call read-only must never be reported with a
    // read-only verb. This fires when the two backslash readings disagree —
    // the per-statement pass sees a lone SELECT, `analyze` sees the DROP behind
    // it, and the verb has to follow `analyze`.
    if best == "sql.read" && !read_only {
        return "sql.unknown";
    }
    best
}

/// The severity floor implied by the capability `analyze` says the batch needs.
///
/// This is what keeps a dialect trick from producing a gentle verdict: the
/// per-statement pass reads backslashes one way, `analyze` reads them both, and
/// where they disagree this floor wins.
fn capability_floor(cap: WriteCapability) -> Severity {
    match cap {
        WriteCapability::Read => Severity::None,
        WriteCapability::Edit => Severity::Low,
        WriteCapability::Delete => Severity::High,
    }
}

fn severity_of(sql: &str, kind: StatementKind, unbounded: bool) -> Severity {
    use StatementKind::*;
    let toks = code_tokens(sql);

    match kind {
        Select | Explain | Show | Set | Tcl | Empty => Severity::None,

        Insert => Severity::Low,

        // Creating is additive — unless it replaces something that was already
        // there, which `CREATE OR REPLACE FUNCTION` silently does.
        Create => {
            if has_word(&toks, "REPLACE") {
                Severity::Moderate
            } else {
                Severity::Low
            }
        }

        // `ALTER TABLE … ADD COLUMN` is additive; `ALTER TABLE … DROP COLUMN`
        // destroys a column's data as thoroughly as a DROP destroys a table's.
        // Same keyword, two very different days.
        Alter => {
            if has_word(&toks, "DROP") {
                Severity::Critical
            } else {
                Severity::Moderate
            }
        }

        Update => {
            if unbounded {
                Severity::High
            } else {
                Severity::Moderate
            }
        }

        Delete => {
            if unbounded {
                Severity::Critical
            } else {
                Severity::High
            }
        }

        Truncate | Drop => Severity::Critical,

        // Changing who can read what is not destructive, and is exactly the
        // step that precedes something that is.
        Grant => Severity::High,

        // A procedure body is opaque to a scanner. It could do anything.
        Call => Severity::High,

        // Unrecognised syntax. `analyze` already refuses to call this
        // read-only; matching that with a low severity would undo the caution.
        Other => Severity::High,
    }
}

/// Whether a statement lacks the clause that would bound its scope.
///
/// The check is **depth-aware**, and that is the point of doing it here rather
/// than reading `analyze`'s warning: `analyze` asks whether the token `WHERE`
/// appears anywhere in the statement, so
/// `UPDATE t SET a = (SELECT max(x) FROM y WHERE z = 1)` looks bounded to it and
/// is not. A `WHERE` inside parentheses bounds a subquery, not the update.
fn is_unbounded(sql: &str, kind: StatementKind) -> bool {
    use StatementKind::*;
    match kind {
        Update | Delete => !has_top_level_word(&code_tokens(sql), "WHERE"),
        // Truncate takes no predicate at all; it is unbounded by construction.
        Truncate => true,
        _ => false,
    }
}

fn has_top_level_word(toks: &[Tok<'_>], kw: &str) -> bool {
    toks.iter().any(|t| t.depth == 0 && t.is(kw))
}

fn has_word(toks: &[Tok<'_>], kw: &str) -> bool {
    toks.iter().any(|t| t.is(kw))
}

/// Whether the batch can be undone.
///
/// Returns `Some(false)` or `None`, never `Some(true)`.
///
/// A pack has no way to know whether a transaction is open, whether the engine
/// has flashback, or whether last night's backup ran. Claiming an action is
/// reversible when it is not is the one error here that actively harms: it turns
/// deliberate friction into false confidence, and it does so at the exact moment
/// someone is deciding whether to turn the dial.
fn reversibility(statements: &[StatementAssessment]) -> Option<bool> {
    use StatementKind::*;
    let destroys = statements
        .iter()
        .any(|s| matches!(s.kind, Drop | Truncate | Delete) || (s.kind == Alter && s.unbounded));
    if destroys {
        Some(false)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sev(sql: &str) -> Severity {
        assess(sql).severity
    }
    fn action(sql: &str) -> &'static str {
        assess(sql).action
    }

    #[test]
    fn reads_are_harmless() {
        assert_eq!(sev("SELECT * FROM users"), Severity::None);
        assert_eq!(action("SELECT * FROM users"), "sql.read");
        assert_eq!(sev("EXPLAIN SELECT 1"), Severity::None);
        assert_eq!(sev("SHOW TABLES"), Severity::None);
    }

    #[test]
    fn a_keyword_in_a_literal_is_still_only_a_read() {
        // The whole reason this is built on a real scanner.
        assert_eq!(sev("SELECT 'DROP TABLE users' AS note"), Severity::None);
        assert_eq!(action("SELECT 1 -- DROP TABLE users"), "sql.read");
    }

    #[test]
    fn a_bounded_delete_is_serious_and_an_unbounded_one_is_worse() {
        assert_eq!(sev("DELETE FROM orders WHERE id = 1"), Severity::High);
        assert_eq!(sev("DELETE FROM orders"), Severity::Critical);
    }

    #[test]
    fn a_where_inside_a_subquery_does_not_bound_the_update() {
        // This is the case the flat keyword scan in `analyze` misses, and the
        // reason this module does its own depth-aware pass. The statement
        // rewrites every row of `t`.
        let sneaky = "UPDATE t SET a = (SELECT max(x) FROM y WHERE z = 1)";
        let a = assess(sneaky);
        assert!(
            a.statements[0].unbounded,
            "a subquery's WHERE bounds the subquery"
        );
        assert_eq!(a.severity, Severity::High);
        assert!(
            a.warnings.iter().any(|w| w.contains("no top-level WHERE")),
            "the human should be told why: {:?}",
            a.warnings
        );

        // And the genuinely bounded form is not flagged.
        let bounded = "UPDATE t SET a = (SELECT max(x) FROM y WHERE z = 1) WHERE id = 7";
        assert!(!assess(bounded).statements[0].unbounded);
        assert_eq!(assess(bounded).severity, Severity::Moderate);
    }

    #[test]
    fn a_where_in_a_delete_subquery_still_counts_when_it_is_top_level() {
        let sql = "DELETE FROM t WHERE id IN (SELECT id FROM stale)";
        assert!(!assess(sql).statements[0].unbounded);
        assert_eq!(sev(sql), Severity::High);
    }

    #[test]
    fn drop_and_truncate_are_critical_and_irreversible() {
        for sql in ["DROP TABLE users", "TRUNCATE users"] {
            let a = assess(sql);
            assert_eq!(a.severity, Severity::Critical, "{sql}");
            assert_eq!(a.reversible, Some(false), "{sql}");
            assert_eq!(a.action, "sql.ddl", "{sql}");
        }
    }

    #[test]
    fn alter_is_read_for_what_it_actually_does() {
        // Same verb, two very different days.
        assert_eq!(sev("ALTER TABLE t ADD COLUMN c int"), Severity::Moderate);
        assert_eq!(sev("ALTER TABLE t DROP COLUMN c"), Severity::Critical);
    }

    #[test]
    fn create_or_replace_is_not_merely_additive() {
        assert_eq!(sev("CREATE TABLE t (id int)"), Severity::Low);
        assert_eq!(
            sev("CREATE OR REPLACE FUNCTION f() RETURNS int AS $$ SELECT 1 $$ LANGUAGE sql"),
            Severity::Moderate,
            "replacing overwrites whatever was there"
        );
    }

    #[test]
    fn unknown_syntax_is_treated_as_dangerous() {
        // Matching `analyze`, which refuses to call this read-only.
        let a = assess("FOOBAR baz");
        assert_eq!(a.severity, Severity::High);
        assert_eq!(a.action, "sql.unknown");
        assert!(!a.read_only);
    }

    #[test]
    fn a_batch_is_judged_by_its_worst_statement() {
        let a = assess("SELECT 1; DROP TABLE users;");
        assert_eq!(a.severity, Severity::Critical);
        assert_eq!(a.action, "sql.ddl", "a batch is approved as a unit");
        assert_eq!(a.statements.len(), 2);
    }

    #[test]
    fn a_write_visible_only_under_the_other_backslash_dialect_still_raises_severity() {
        // MySQL reads '\'' as a one-character string, so the DROP is real. The
        // per-statement pass splits the other way and sees a lone SELECT; the
        // capability floor from `analyze` is what stops that from reading as
        // harmless.
        let sql = r"SELECT '\'' ; DROP TABLE users";
        let a = assess(sql);
        assert!(!a.read_only);
        assert!(a.severity >= Severity::High, "got {:?}", a.severity);
        assert_ne!(
            a.action, "sql.read",
            "a non-read-only batch is never sql.read"
        );
    }

    #[test]
    fn the_mirror_image_dialect_trick_is_caught_too() {
        // Standard-conforming SQL closes 'C:\' at its second quote, so the
        // DELETE is real; honoring the backslash would swallow it.
        let a = assess(r"SELECT 'C:\' AS root; DELETE FROM audit_log;");
        assert!(!a.read_only);
        assert!(a.severity >= Severity::High, "got {:?}", a.severity);
    }

    #[test]
    fn grants_and_calls_are_high_not_critical() {
        // Neither destroys data. Both are how someone gets to.
        assert_eq!(sev("GRANT ALL ON users TO app"), Severity::High);
        assert_eq!(action("GRANT ALL ON users TO app"), "sql.grant");
        assert_eq!(sev("CALL do_something()"), Severity::High);
        assert_eq!(action("CALL do_something()"), "sql.exec");
    }

    #[test]
    fn reversibility_is_never_claimed_optimistically() {
        // The only two answers are "definitely not" and "I don't know".
        assert_eq!(assess("DROP TABLE t").reversible, Some(false));
        assert_eq!(assess("INSERT INTO t VALUES (1)").reversible, None);
        assert_eq!(assess("SELECT 1").reversible, None);
        for sql in [
            "SELECT 1",
            "INSERT INTO t VALUES (1)",
            "UPDATE t SET a=1 WHERE id=2",
        ] {
            assert_ne!(
                assess(sql).reversible,
                Some(true),
                "{sql} must not claim reversible"
            );
        }
    }

    #[test]
    fn an_empty_statement_does_not_panic_or_alarm() {
        let a = assess("");
        assert_eq!(a.severity, Severity::None);
        assert!(a.statements.is_empty());
        assert_eq!(assess("   ;  ; ").severity, Severity::None);
    }

    #[test]
    fn half_typed_sql_is_assessed_without_panicking() {
        // An editor sends this on every keystroke.
        for sql in ["SELECT 'oops", "DELETE FROM", "UPDATE t SET a = (", "DROP"] {
            let _ = assess(sql);
        }
    }

    #[test]
    fn a_dollar_body_cannot_hide_a_following_write() {
        let a = assess("SELECT $$ it's a body $$ AS x; DELETE FROM users");
        assert!(!a.read_only);
        assert_eq!(a.severity, Severity::Critical, "the DELETE is unbounded");
    }
}

//! SQL statement classification — what does this statement actually do?
//!
//! [`analyze`] takes SQL text and answers two questions a gate needs: is every
//! statement read-only, and what is the strongest write privilege the batch
//! requires. It is comment- and string-literal-aware, so keywords hidden inside
//! strings or comments cannot smuggle a write past it, and a trailing
//! `-- DROP TABLE` comment cannot be misread as one.
//!
//! The tokenizer understands single-/double-quoted strings (with `''`/`""` and
//! backslash escapes), line/block comments, and dollar-quoted bodies
//! (`$tag$ ... $tag$`), so a keyword hidden in any of those can't be misread —
//! and, just as important, an unterminated-looking quote inside a dollar body
//! can't *swallow* a following statement and hide a write.
//!
//! That scan lives in [`crate::scan`], shared with the statement splitter, which
//! is what keeps the two in lock-step rather than a comment asking future
//! readers to do it by hand. The one place a scan has to make a dialect choice
//! is backslash handling — see [`crate::scan::BackslashEscapes`] and [`analyze`],
//! which resolves it by reading the SQL both ways and gating on the stronger
//! answer rather than by guessing the dialect.
//!
//! # This is a classifier, not a policy
//!
//! Nothing here decides whether a statement is allowed. It reports what the
//! statement *is*; the caller decides what that means. `countersign-db` maps
//! these verdicts onto approval severities, and a read-only connection gate maps
//! them onto permit/deny — same answer, two policies.
//!
//! See [`crate::scan`] for this module's provenance.

use serde::{Deserialize, Serialize};

// Blanking non-code regions is the first half of classification; the scan itself
// is shared with the statement splitter.
use crate::scan::{blank_non_code as sanitize, BackslashEscapes};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StatementKind {
    Select,
    Insert,
    Update,
    Delete,
    Truncate,
    Create,
    Alter,
    Drop,
    Grant,
    Explain,
    Show,
    Set,
    Tcl,
    Call,
    Empty,
    Other,
}

impl StatementKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            StatementKind::Select => "select",
            StatementKind::Insert => "insert",
            StatementKind::Update => "update",
            StatementKind::Delete => "delete",
            StatementKind::Truncate => "truncate",
            StatementKind::Create => "create",
            StatementKind::Alter => "alter",
            StatementKind::Drop => "drop",
            StatementKind::Grant => "grant",
            StatementKind::Explain => "explain",
            StatementKind::Show => "show",
            StatementKind::Set => "set",
            StatementKind::Tcl => "tcl",
            StatementKind::Call => "call",
            StatementKind::Empty => "empty",
            StatementKind::Other => "other",
        }
    }

    /// Whether a statement of this kind only reads — i.e. is safe to run on a
    /// read-only connection. Unknown/opaque kinds are conservatively *not* safe.
    pub fn is_read_only(&self) -> bool {
        matches!(
            self,
            StatementKind::Select
                | StatementKind::Explain
                | StatementKind::Show
                | StatementKind::Set
                | StatementKind::Tcl
                | StatementKind::Empty
        )
    }

    /// The level of write privilege this statement requires.
    ///
    /// The three-way split is what lets a caller grant *editing* on a read-only
    /// connection without granting *deletion*, or vice-versa — a distinction a
    /// boolean `is_write` cannot express, and the one operators actually want.
    ///
    /// `Edit` = additive / in-place data and structure changes. `Delete` =
    /// destructive or privileged statements (row/table removal, privilege grants,
    /// arbitrary procedure calls, and anything unclassifiable) — these need the
    /// stronger grant.
    pub fn capability(&self) -> WriteCapability {
        use StatementKind::*;
        match self {
            Select | Explain | Show | Set | Tcl | Empty => WriteCapability::Read,
            Insert | Update | Create | Alter => WriteCapability::Edit,
            Delete | Truncate | Drop | Grant | Call | Other => WriteCapability::Delete,
        }
    }
}

/// How much write privilege an operation needs, ordered `Read < Edit < Delete`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WriteCapability {
    Read,
    Edit,
    Delete,
}

impl WriteCapability {
    pub fn as_str(&self) -> &'static str {
        match self {
            WriteCapability::Read => "read",
            WriteCapability::Edit => "edit",
            WriteCapability::Delete => "delete",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatementClass {
    pub kind: StatementKind,
    pub read_only: bool,
    pub warnings: Vec<String>,
}

/// Aggregate analysis of a (possibly multi-statement) SQL string.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SqlSafety {
    /// True only if *every* statement is read-only, under **either** reading of
    /// backslash escapes (see [`analyze`]).
    pub read_only: bool,
    /// Kind of the first non-empty statement.
    pub primary_kind: StatementKind,
    pub statements: Vec<StatementClass>,
    pub warnings: Vec<String>,
    /// The privilege the whole batch needs — read it through
    /// [`SqlSafety::required_capability`]. It can exceed what `statements` alone
    /// implies, because it also accounts for the alternate backslash reading
    /// (see [`analyze`]); that stronger answer is what the gate must use.
    capability: WriteCapability,
}

/// Uppercased identifier/keyword tokens from already-sanitized SQL.
fn tokens(sanitized_stmt: &str) -> Vec<String> {
    sanitized_stmt
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|t| !t.is_empty())
        .map(|t| t.to_ascii_uppercase())
        .collect()
}

fn has(tokens: &[String], kw: &str) -> bool {
    tokens.iter().any(|t| t == kw)
}

/// Resolve the effective write kind inside a `WITH`/`EXPLAIN ANALYZE` wrapper.
fn embedded_write_kind(tokens: &[String]) -> Option<StatementKind> {
    if has(tokens, "INSERT") {
        Some(StatementKind::Insert)
    } else if has(tokens, "UPDATE") {
        Some(StatementKind::Update)
    } else if has(tokens, "DELETE") {
        Some(StatementKind::Delete)
    } else if has(tokens, "MERGE") {
        Some(StatementKind::Update)
    } else {
        None
    }
}

fn classify_statement(sanitized_stmt: &str) -> StatementClass {
    let toks = tokens(sanitized_stmt);
    let mut warnings = Vec::new();

    let kind = match toks.first().map(String::as_str) {
        None => StatementKind::Empty,
        Some("SELECT") | Some("VALUES") | Some("TABLE") => StatementKind::Select,
        Some("WITH") => embedded_write_kind(&toks).unwrap_or(StatementKind::Select),
        Some("SHOW") => StatementKind::Show,
        Some("EXPLAIN") => {
            if has(&toks, "ANALYZE") {
                // EXPLAIN ANALYZE actually executes the statement.
                embedded_write_kind(&toks).unwrap_or(StatementKind::Explain)
            } else {
                StatementKind::Explain
            }
        }
        Some("SET") | Some("RESET") => StatementKind::Set,
        Some("BEGIN") | Some("START") | Some("COMMIT") | Some("ROLLBACK") | Some("SAVEPOINT")
        | Some("RELEASE") | Some("END") => StatementKind::Tcl,
        Some("INSERT") => StatementKind::Insert,
        Some("UPDATE") => {
            if !has(&toks, "WHERE") {
                warnings.push("UPDATE without a WHERE clause affects every row.".into());
            }
            StatementKind::Update
        }
        Some("DELETE") => {
            if !has(&toks, "WHERE") {
                warnings.push("DELETE without a WHERE clause removes every row.".into());
            }
            StatementKind::Delete
        }
        Some("MERGE") | Some("UPSERT") | Some("REPLACE") => StatementKind::Update,
        Some("COPY") => {
            // COPY ... FROM imports (write); COPY ... TO exports (read).
            if has(&toks, "FROM") {
                StatementKind::Insert
            } else {
                StatementKind::Select
            }
        }
        Some("TRUNCATE") => {
            warnings.push("TRUNCATE removes all rows.".into());
            StatementKind::Truncate
        }
        Some("CREATE") => StatementKind::Create,
        Some("ALTER") | Some("COMMENT") | Some("REINDEX") | Some("VACUUM") | Some("CLUSTER")
        | Some("REFRESH") | Some("ANALYZE") => StatementKind::Alter,
        Some("DROP") => {
            warnings.push("DROP permanently removes database objects.".into());
            StatementKind::Drop
        }
        Some("GRANT") | Some("REVOKE") => StatementKind::Grant,
        // CALL/DO/EXEC can run arbitrary side effects — never read-only-safe.
        Some("CALL") | Some("DO") | Some("EXEC") | Some("EXECUTE") => StatementKind::Call,
        Some(_) => StatementKind::Other,
    };

    StatementClass {
        read_only: kind.is_read_only(),
        kind,
        warnings,
    }
}

/// Classify every `;`-separated statement of an already-blanked SQL string.
fn classify_batch(sanitized: &str) -> Vec<StatementClass> {
    sanitized
        .split(';')
        .map(classify_statement)
        .filter(|s| s.kind != StatementKind::Empty)
        .collect()
}

/// The strongest privilege a classified batch requires.
fn strongest(statements: &[StatementClass]) -> WriteCapability {
    statements
        .iter()
        .map(|s| s.kind.capability())
        .max()
        .unwrap_or(WriteCapability::Read)
}

/// Full safety analysis of a SQL string (handles multiple `;`-separated statements).
///
/// The blanking scan has to decide whether `\` escapes a quote, and the dialects
/// disagree (see [`crate::scan::BackslashEscapes`]) — but this function isn't
/// told the engine, and either choice alone hides a write from the other family:
/// `SELECT '\'' ; DROP TABLE t` reads as a lone SELECT when backslashes are
/// ignored, and `SELECT 'C:\' AS root; DELETE FROM audit_log;` reads as a lone
/// SELECT when they're honored. So classification is fail-safe rather than
/// dialect-specific: we classify both readings and gate on the stronger one, so a
/// write visible under *either* blocks the run. Only `read_only` and
/// [`required_capability`](SqlSafety::required_capability) take that maximum —
/// `primary_kind`, `statements` and `warnings` stay the honored reading, which is
/// what the editor's indicator and the migration diff already show.
pub fn analyze(sql: &str) -> SqlSafety {
    let statements = classify_batch(&sanitize(sql, BackslashEscapes::Honor));
    let alternate = classify_batch(&sanitize(sql, BackslashEscapes::Ignore));

    let primary_kind = statements
        .first()
        .map(|s| s.kind)
        .unwrap_or(StatementKind::Empty);

    let capability = strongest(&statements).max(strongest(&alternate));
    let read_only = statements.iter().all(|s| s.read_only) && alternate.iter().all(|s| s.read_only);
    let warnings = statements.iter().flat_map(|s| s.warnings.clone()).collect();

    SqlSafety {
        read_only,
        primary_kind,
        statements,
        warnings,
        capability,
    }
}

impl SqlSafety {
    /// The strongest write privilege any statement in this SQL requires. A
    /// pure-read batch is `Read`; a batch that both edits and deletes is `Delete`
    /// (the caller must hold the higher grant for the whole batch to run).
    ///
    /// This is the value every gate must use: it already accounts for both
    /// backslash readings (see [`analyze`]), which mapping over `statements`
    /// would not.
    pub fn required_capability(&self) -> WriteCapability {
        self.capability
    }
}

/// Convenience: is this SQL safe to run on a read-only connection?
pub fn is_read_only(sql: &str) -> bool {
    analyze(sql).read_only
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_select_is_read_only() {
        assert!(is_read_only("SELECT * FROM users"));
        assert!(is_read_only("  select 1  "));
        assert_eq!(analyze("SELECT 1").primary_kind, StatementKind::Select);
    }

    #[test]
    fn writes_are_blocked() {
        assert!(!is_read_only("INSERT INTO t VALUES (1)"));
        assert!(!is_read_only("update t set a = 1 where id = 2"));
        assert!(!is_read_only("DELETE FROM t WHERE id = 1"));
        assert!(!is_read_only("DROP TABLE t"));
        assert!(!is_read_only("TRUNCATE t"));
        assert!(!is_read_only("ALTER TABLE t ADD COLUMN c int"));
        assert!(!is_read_only("CREATE TABLE t (id int)"));
    }

    #[test]
    fn keywords_inside_strings_do_not_count() {
        // The literal contains DROP but the statement is a SELECT.
        assert!(is_read_only("SELECT 'DROP TABLE users' AS note"));
    }

    #[test]
    fn comments_are_ignored() {
        assert!(is_read_only("SELECT 1; -- DROP TABLE users"));
        assert!(is_read_only("/* DELETE FROM t */ SELECT 2"));
        assert!(!is_read_only("/* read */ UPDATE t SET a = 1 WHERE id = 1"));
    }

    #[test]
    fn dollar_quote_cannot_hide_a_write() {
        // An apostrophe inside a $$…$$ body must not swallow the trailing DELETE.
        assert!(!is_read_only(
            "SELECT $$ it's a body $$ AS x; DELETE FROM users"
        ));
        // A keyword genuinely inside a dollar body stays read-only.
        assert!(is_read_only("SELECT $$ DROP TABLE users $$ AS note"));
        // Tagged dollar-quote.
        assert!(!is_read_only("SELECT $tag$ x's $tag$; TRUNCATE t"));
    }

    #[test]
    fn backslash_escape_cannot_hide_a_write() {
        // MySQL treats '\'' as a one-char string; the DROP must stay visible.
        assert!(!is_read_only(r"SELECT '\'' ; DROP TABLE users"));
    }

    #[test]
    fn a_trailing_backslash_cannot_hide_a_write() {
        // The mirror image, and the reason classification reads both dialects: in
        // standard-conforming SQL (T-SQL, Postgres) `'C:\'` is an ordinary
        // Windows path that closes at its second quote, so the DELETE is real.
        // Honoring the backslash swallows it into an unterminated literal.
        let sql = r"SELECT 'C:\' AS root; DELETE FROM audit_log;";
        assert!(!is_read_only(sql));
        assert_eq!(analyze(sql).required_capability(), WriteCapability::Delete);
        // The UX-facing half still describes the statement the user typed.
        assert_eq!(analyze(sql).primary_kind, StatementKind::Select);
    }

    #[test]
    fn non_ascii_identifiers_survive() {
        // A multibyte identifier must not corrupt the keyword stream.
        assert!(is_read_only("SELECT café FROM naïve"));
        assert!(!is_read_only("UPDATE café SET x = 1 WHERE id = 1"));
    }

    #[test]
    fn missing_where_warns() {
        let a = analyze("UPDATE users SET active = false");
        assert_eq!(a.primary_kind, StatementKind::Update);
        assert!(!a.warnings.is_empty());

        let b = analyze("DELETE FROM users WHERE id = 1");
        assert!(b.warnings.is_empty());
    }

    #[test]
    fn cte_with_write_is_not_read_only() {
        assert!(is_read_only(
            "WITH recent AS (SELECT * FROM orders) SELECT * FROM recent"
        ));
        assert!(!is_read_only(
            "WITH moved AS (DELETE FROM orders RETURNING *) SELECT * FROM moved"
        ));
    }

    #[test]
    fn explain_analyze_executes() {
        assert!(is_read_only("EXPLAIN SELECT * FROM t"));
        assert!(!is_read_only("EXPLAIN ANALYZE DELETE FROM t WHERE id = 1"));
    }

    #[test]
    fn multi_statement_all_must_be_read_only() {
        assert!(is_read_only("SELECT 1; SELECT 2;"));
        assert!(!is_read_only("SELECT 1; DELETE FROM t WHERE id = 1;"));
    }

    #[test]
    fn session_and_tcl_are_read_only_safe() {
        assert!(is_read_only("SET statement_timeout = 5000"));
        assert!(is_read_only("BEGIN; SELECT 1; COMMIT;"));
    }

    #[test]
    fn unknown_is_conservative() {
        assert!(!is_read_only("FOOBAR baz"));
    }

    #[test]
    fn capability_classifies_edit_vs_delete() {
        // Reads need nothing.
        assert_eq!(
            analyze("SELECT 1").required_capability(),
            WriteCapability::Read
        );
        // In-place / additive writes are Edit.
        assert_eq!(
            analyze("UPDATE t SET a = 1 WHERE id = 2").required_capability(),
            WriteCapability::Edit
        );
        assert_eq!(
            analyze("INSERT INTO t VALUES (1)").required_capability(),
            WriteCapability::Edit
        );
        // Destructive / privileged statements need the stronger Delete grant.
        assert_eq!(
            analyze("DELETE FROM t WHERE id = 1").required_capability(),
            WriteCapability::Delete
        );
        assert_eq!(
            analyze("DROP TABLE t").required_capability(),
            WriteCapability::Delete
        );
        assert_eq!(
            analyze("TRUNCATE t").required_capability(),
            WriteCapability::Delete
        );
    }

    #[test]
    fn required_capability_takes_the_strongest() {
        // A batch that edits and deletes requires the higher (Delete) grant.
        assert_eq!(
            analyze("UPDATE t SET a = 1 WHERE id = 2; DELETE FROM t WHERE id = 3")
                .required_capability(),
            WriteCapability::Delete
        );
        assert!(WriteCapability::Read < WriteCapability::Edit);
        assert!(WriteCapability::Edit < WriteCapability::Delete);
    }
}

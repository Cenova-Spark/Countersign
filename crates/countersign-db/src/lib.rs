//! `countersign-db` — the database domain pack.
//!
//! The first of what should become many packs. It answers one question for
//! `signetd`: *given this SQL, how bad is it, and what should the device show?*
//!
//! # What it deliberately does not do
//!
//! It does not connect to anything. No `EXPLAIN`, no row counts, no catalogue
//! lookups — the statement it is handed is production text containing customer
//! data, and a pack that reaches the network has turned an approval prompt into
//! an exfiltration channel. Everything here is a pure function of the statement.
//!
//! It also does not decide anything. It classifies; policy decides. Its severity
//! can raise the host's floor and can never lower it, so when it is unsure the
//! honest answer costs one dial turn and the flattering answer costs a table.
//!
//! ```
//! use countersign_db::DbPack;
//! use countersign_pack::{ClassifyRequest, Pack, Severity};
//!
//! let pack = DbPack;
//! let verdict = pack.classify(&ClassifyRequest::new("sql.execute", "DELETE FROM orders"));
//!
//! assert_eq!(verdict.action, "sql.dml");
//! assert_eq!(verdict.severity, Severity::Critical); // no WHERE
//! assert_eq!(verdict.reversible, Some(false));
//! ```

// `deny` rather than `forbid`, for exactly one reason: the WebAssembly export
// glue at the bottom of this file needs four lines of `unsafe` to hand buffers
// across the module boundary, and `forbid` cannot be lifted for a single
// module. Nothing else in this crate may use it.
#![deny(unsafe_code)]

pub mod blast;

use countersign_pack::{ClassifyRequest, ClassifyResponse, Pack, PackInfo, RenderLine, PROTOCOL};
use serde_json::json;

pub use blast::{assess, Assessment, StatementAssessment};

// The WebAssembly build. `cargo build -p countersign-db --target
// wasm32-unknown-unknown --release` produces a module with an empty import
// section that a host drives through `countersign_pack::wasm`; this is the pack
// the marketplace distributes. The `unsafe` the ABI needs expands here, in this
// crate, where a reader can see it — see `countersign_pack::wasm`.
#[cfg(target_arch = "wasm32")]
#[allow(unsafe_code)]
mod wasm_exports {
    countersign_pack::export_pack!(super::DbPack);
}

/// How many statements of a batch get their own line on the device before the
/// rest collapse into a count.
///
/// Four is a screen's worth. The alternative — showing only the first — would
/// hide a `DROP` sitting in position five, which is precisely where someone
/// hiding one would put it.
const MAX_PRIMARY_LINES: usize = 4;

/// The pack.
#[derive(Debug, Clone, Copy, Default)]
pub struct DbPack;

impl Pack for DbPack {
    fn describe(&self) -> PackInfo {
        PackInfo {
            name: "countersign-db".into(),
            version: env!("CARGO_PKG_VERSION").into(),
            protocol: PROTOCOL,
            actions: vec!["sql".into()],
            pure: true,
        }
    }

    fn classify(&self, req: &ClassifyRequest) -> ClassifyResponse {
        let a = assess(&req.statement);

        let mut out = ClassifyResponse::new(a.action, a.severity);
        out.reversible = a.reversible;
        out.warnings = a.warnings.clone();
        out.render = render(&a, &req.statement);
        out.advisory = Some(json!({
            "statements": a.statements.len(),
            "read_only": a.read_only,
            "kinds": a.statements.iter().map(|s| s.kind.as_str()).collect::<Vec<_>>(),
            "unbounded": a.statements.iter().any(|s| s.unbounded),
        }));
        out
    }
}

/// Build the device's display lines.
///
/// Statements are emitted **verbatim**, not prettified. Wrapping and truncation
/// are the firmware's job, and the closer the rendered text stays to the signed
/// text the less room there is between what the human read and what they
/// authorized. A pack that reformats is a pack that can, one refactor later,
/// reformat misleadingly.
fn render(a: &Assessment, original: &str) -> Vec<RenderLine> {
    let mut lines = Vec::new();

    if a.statements.is_empty() {
        // Nothing parsed as a statement — show the raw text anyway rather than
        // an empty screen, so the human can see what was actually asked for.
        lines.push(RenderLine::primary(original.trim()));
        return lines;
    }

    for s in a.statements.iter().take(MAX_PRIMARY_LINES) {
        lines.push(RenderLine::primary(s.sql.clone()));
    }

    if a.statements.len() > MAX_PRIMARY_LINES {
        lines.push(RenderLine::advisory(format!(
            "+{} more statement(s) — {} in total",
            a.statements.len() - MAX_PRIMARY_LINES,
            a.statements.len()
        )));
    }

    // The single most useful thing to put in front of someone about to approve:
    // the scope is not bounded.
    if a.statements.iter().any(|s| s.unbounded) {
        lines.push(RenderLine::advisory("unbounded — no WHERE clause"));
    }

    if a.reversible == Some(false) {
        lines.push(RenderLine::advisory("not reversible"));
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use countersign_pack::{validate, RenderRole, Severity};

    fn classify(sql: &str) -> ClassifyResponse {
        DbPack.classify(&ClassifyRequest::new("sql.execute", sql))
    }

    #[test]
    fn the_pack_describes_itself_at_the_current_protocol() {
        let info = DbPack.describe();
        assert_eq!(info.name, "countersign-db");
        assert_eq!(info.protocol, PROTOCOL);
        assert_eq!(info.actions, vec!["sql"]);
        assert!(info.pure, "this pack performs no I/O and says so");
    }

    #[test]
    fn every_verdict_survives_the_hosts_validation() {
        // The rules a host enforces (namespace, forbidden render roles) must
        // never be tripped by this pack's own output.
        for sql in [
            "SELECT 1",
            "DELETE FROM t",
            "DROP TABLE t; TRUNCATE u; DELETE FROM v; UPDATE w SET a=1; SELECT 5",
            "FOOBAR baz",
            "",
            "SELECT 'oops",
        ] {
            let req = ClassifyRequest::new("sql.execute", sql);
            let resp = DbPack.classify(&req);
            assert!(validate(resp, &req).is_ok(), "rejected for {sql:?}");
        }
    }

    #[test]
    fn the_pack_never_emits_a_label_or_digest_line() {
        // Those two roles are the daemon's alone; a pack that could write them
        // could show "local" above a production DROP.
        let resp = classify("DROP TABLE users");
        assert!(
            resp.render.iter().all(|l| l.role.pack_may_emit()),
            "got {:?}",
            resp.render
        );
    }

    #[test]
    fn a_destructive_statement_reaches_the_screen_with_its_scope_spelled_out() {
        let resp = classify("DELETE FROM orders");
        assert_eq!(resp.severity, Severity::Critical);

        let primary: Vec<_> = resp
            .render
            .iter()
            .filter(|l| l.role == RenderRole::Primary)
            .map(|l| l.text.as_str())
            .collect();
        assert_eq!(primary, vec!["DELETE FROM orders"]);

        let advisory: Vec<_> = resp
            .render
            .iter()
            .filter(|l| l.role == RenderRole::Advisory)
            .map(|l| l.text.as_str())
            .collect();
        assert!(
            advisory.contains(&"unbounded — no WHERE clause"),
            "got {advisory:?}"
        );
        assert!(advisory.contains(&"not reversible"), "got {advisory:?}");
    }

    #[test]
    fn a_long_batch_never_hides_a_statement_without_saying_so() {
        // Five statements, four lines. The overflow must be announced, because
        // position five is exactly where someone would hide a DROP.
        let resp = classify("SELECT 1; SELECT 2; SELECT 3; SELECT 4; DROP TABLE users");
        let advisory: Vec<_> = resp
            .render
            .iter()
            .filter(|l| l.role == RenderRole::Advisory)
            .map(|l| l.text.clone())
            .collect();
        assert!(
            advisory
                .iter()
                .any(|t| t.contains("more statement") && t.contains("5 in total")),
            "got {advisory:?}"
        );
        // And the severity still reflects the hidden statement.
        assert_eq!(resp.severity, Severity::Critical);
    }

    #[test]
    fn statements_are_rendered_verbatim_not_reformatted() {
        // The closer the rendered text is to the signed text, the less room
        // there is between what the human read and what they authorized.
        let sql = "DELETE   FROM    orders";
        let resp = classify(sql);
        assert_eq!(resp.render[0].text, sql);
    }

    #[test]
    fn the_advisory_block_reports_shape_not_guesses() {
        let adv = classify("UPDATE t SET a = 1; DELETE FROM u")
            .advisory
            .unwrap();
        assert_eq!(adv["statements"], 2);
        assert_eq!(adv["read_only"], false);
        assert_eq!(adv["unbounded"], true);
        assert_eq!(adv["kinds"], json!(["update", "delete"]));
        // Nothing in here claims a row count. It cannot know one.
        assert!(adv.get("rows_affected").is_none());
    }

    #[test]
    fn a_read_is_reported_as_harmless_and_says_nothing_alarming() {
        let resp = classify("SELECT * FROM users LIMIT 10");
        assert_eq!(resp.severity, Severity::None);
        assert_eq!(resp.action, "sql.read");
        assert!(resp.warnings.is_empty());
        assert_eq!(resp.reversible, None);
    }

    #[test]
    fn empty_input_still_shows_the_human_something() {
        let resp = classify("");
        assert_eq!(resp.severity, Severity::None);
        assert_eq!(
            resp.render.len(),
            1,
            "an empty screen is worse than an empty statement"
        );
    }
}

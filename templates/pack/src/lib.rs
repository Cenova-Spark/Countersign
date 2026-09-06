//! A Countersign domain pack, ready to be renamed.
//!
//! A pack answers one question for `signetd`: *given this statement in my
//! namespace, how bad is it, and what should the approval screen show?* It
//! decides nothing — policy decides — and it connects to nothing. The
//! statement it is handed may be production text with customer data in it,
//! and a pack that reaches the network has turned an approval prompt into a
//! way out. Keep `classify` a pure function of its input.
//!
//! Three rules the host enforces (pack protocol §4), so write toward them:
//!
//! 1. A pack may **raise** severity and never lower it. When unsure, say
//!    more: the honest answer costs one dial turn, the flattering one costs
//!    a table.
//! 2. A pack cannot write the environment label or the digest. Those lines
//!    are the daemon's. Everything else on the screen is yours.
//! 3. Failure is closed. A crash, a timeout, a malformed answer or a wrong
//!    namespace all become `critical` with the cause named. There is no
//!    reward for a fragile pack.
//!
//! `cargo test` checks the answers against those rules. `cargo run` speaks
//! the stdio protocol. `cargo build --lib --release --target
//! wasm32-unknown-unknown` builds the module a marketplace can list.
//! README.md walks through it.

// The WebAssembly export glue at the bottom needs four lines of `unsafe` to
// hand buffers across the module boundary. It is allowed there and nowhere
// else in this crate.
#![deny(unsafe_code)]

use countersign_pack::{
    ClassifyRequest, ClassifyResponse, Pack, PackInfo, RenderLine, Severity, PROTOCOL,
};

/// The namespace this pack claims: `example.run`, `example.anything`, and
/// every other action under `example.`. A host never sends it anything else,
/// and an answer outside it is treated as a dead pack.
pub const NAMESPACE: &str = "example";

/// The pack. Stateless on purpose: a classifier that remembers is one whose
/// answer depends on what it saw before, which nobody can audit.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExamplePack;

impl Pack for ExamplePack {
    fn describe(&self) -> PackInfo {
        PackInfo {
            name: env!("CARGO_PKG_NAME").into(),
            version: env!("CARGO_PKG_VERSION").into(),
            protocol: PROTOCOL,
            actions: vec![NAMESPACE.into()],
            // The promise that `classify` does no I/O. The module build makes
            // it true by construction; the native build is trusted to keep it.
            pure: true,
        }
    }

    fn classify(&self, req: &ClassifyRequest) -> ClassifyResponse {
        // Replace this with a real reading of your domain. The shape to keep:
        // an action inside the namespace, how bad it is, whether it can be
        // undone, and the lines a person must read before they hold.
        let statement = req.statement.trim();
        let verb = statement
            .split_whitespace()
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();

        let (action, severity, reversible) = match verb.as_str() {
            "show" | "list" | "get" => ("read", Severity::None, Some(true)),
            "delete" | "drop" | "destroy" => ("destroy", Severity::Critical, Some(false)),
            // Unknown is not "probably fine". It is unclassified, and that
            // reads as high until someone teaches this pack otherwise.
            _ => ("change", Severity::High, None),
        };

        let mut out = ClassifyResponse::new(format!("{NAMESPACE}.{action}"), severity);
        out.reversible = reversible;
        out.render.push(RenderLine::primary(statement));
        if severity == Severity::Critical {
            out.render.push(RenderLine::advisory("cannot be undone"));
        }
        out
    }
}

// The WebAssembly build. The module imports nothing, so wherever it runs it
// cannot reach a network, a filesystem or a clock. `countersign_pack::wasm`
// describes the four exports this emits.
#[cfg(target_arch = "wasm32")]
#[allow(unsafe_code)]
mod wasm_exports {
    countersign_pack::export_pack!(super::ExamplePack);
}

#[cfg(test)]
mod tests {
    use super::*;
    use countersign_pack::validate;

    fn classify(statement: &str) -> ClassifyResponse {
        let req = ClassifyRequest::new(format!("{NAMESPACE}.run"), statement);
        let out = ExamplePack.classify(&req);
        // The host's own check: inside the namespace, and no line a pack may
        // not write. A pack that fails this is treated as dead.
        validate(out, &req).expect("the answer must pass the host's rules")
    }

    #[test]
    fn it_claims_exactly_its_namespace() {
        let info = ExamplePack.describe();
        assert_eq!(info.actions, vec![NAMESPACE.to_string()]);
        assert_eq!(info.protocol, PROTOCOL);
        assert!(info.pure);
    }

    #[test]
    fn destroying_is_critical_and_says_so_on_screen() {
        let out = classify("delete everything");
        assert_eq!(out.action, format!("{NAMESPACE}.destroy"));
        assert_eq!(out.severity, Severity::Critical);
        assert_eq!(out.reversible, Some(false));
        assert!(out.render.iter().any(|line| line.text == "cannot be undone"));
    }

    #[test]
    fn reading_changes_nothing() {
        let out = classify("show status");
        assert_eq!(out.action, format!("{NAMESPACE}.read"));
        assert_eq!(out.severity, Severity::None);
        assert_eq!(out.reversible, Some(true));
    }

    #[test]
    fn the_unknown_is_not_assumed_harmless() {
        let out = classify("frobnicate the widgets");
        assert!(out.severity >= Severity::High);
        assert_eq!(out.reversible, None);
    }

    #[test]
    fn the_statement_is_what_the_person_reads() {
        let out = classify("  delete everything ");
        assert_eq!(out.render[0].text, "delete everything");
    }
}

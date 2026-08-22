//! Dialect-tolerant SQL lexical scanning and statement classification.
//!
//! Two questions, answered without a full parser:
//!
//! * **Where does real SQL stop and inert text begin?** — [`scan`], and the
//!   splitter, tokenizer and normalizer built on it.
//! * **What does this statement do?** — [`classify`], which answers in terms of
//!   a [`StatementKind`] and the [`WriteCapability`] a batch requires.
//!
//! # There is deliberately no Countersign in here
//!
//! This crate does not know what an approval is. It is a dependency of the
//! `countersign-db` domain pack, and it is equally a dependency of a plain
//! read-only connection gate — which is the other thing it is currently used
//! for, in AddisDB.
//!
//! That separation is load-bearing rather than tasteful. The classifier and the
//! gate in front of the database must agree about what counts as a write; if
//! they are two implementations they drift, and the drift shows up as a
//! statement the gate blocks and the approval prompt calls harmless. One crate,
//! one answer.
//!
//! # It is a scanner, not a parser
//!
//! It knows where regions begin and end and nothing about grammar. It will
//! never tell you which rows a `DELETE` touches — only that it is a `DELETE`,
//! whether a `WHERE` is present, and that unknown syntax is not safe to assume
//! read-only.
//!
//! ```
//! use countersign_sql::{analyze, StatementKind, WriteCapability};
//!
//! // A keyword inside a literal is text, not a write.
//! assert!(analyze("SELECT 'DROP TABLE users' AS note").read_only);
//!
//! // A write hidden behind a dialect's backslash rules is still a write.
//! let sneaky = analyze(r"SELECT '\'' ; DROP TABLE users");
//! assert!(!sneaky.read_only);
//! assert_eq!(sneaky.required_capability(), WriteCapability::Delete);
//!
//! // And the UX-facing verdict still describes what the user typed.
//! assert_eq!(sneaky.primary_kind, StatementKind::Select);
//! ```

#![forbid(unsafe_code)]

pub mod classify;
pub mod scan;

pub use classify::{
    analyze, is_read_only, SqlSafety, StatementClass, StatementKind, WriteCapability,
};
pub use scan::{
    blank_non_code, code_tokens, normalize_statement, scan, split_on_semicolons, statement_digest,
    BackslashEscapes, Region, Scan, Span, Tok, TokKind,
};

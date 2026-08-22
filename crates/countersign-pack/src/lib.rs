//! The Countersign domain-pack plugin interface.
//!
//! `signetd` knows about "approval requests with a payload". It does not know
//! what SQL is, what a Terraform plan is, or what an npm tarball is. Everything
//! domain-specific — statement classification, blast-radius estimation, what
//! goes on the screen — lives in a pack.
//!
//! A pack is **an executable speaking line-delimited JSON-RPC 2.0 on stdio**,
//! the same shape MCP servers and language servers use. That costs a process
//! spawn and buys three things a compiled-in trait cannot: any language, no fork
//! pressure, and a real address-space boundary between third-party code and the
//! USB handle, the policy engine, the audit log and the enrolled keys.
//!
//! # Writing a pack
//!
//! ```no_run
//! use countersign_pack::{
//!     run_stdio, ClassifyRequest, ClassifyResponse, Pack, PackInfo, RenderLine, Severity,
//!     PROTOCOL,
//! };
//!
//! struct Noisy;
//!
//! impl Pack for Noisy {
//!     fn describe(&self) -> PackInfo {
//!         PackInfo {
//!             name: "countersign-noisy".into(),
//!             version: "0.1.0".into(),
//!             protocol: PROTOCOL,
//!             actions: vec!["demo".into()],
//!             pure: true,
//!         }
//!     }
//!
//!     fn classify(&self, req: &ClassifyRequest) -> ClassifyResponse {
//!         let mut out = ClassifyResponse::new("demo.act", Severity::High);
//!         out.render.push(RenderLine::primary(req.statement.clone()));
//!         out
//!     }
//! }
//!
//! fn main() -> std::io::Result<()> {
//!     run_stdio(&Noisy)
//! }
//! ```
//!
//! # Hosting packs
//!
//! [`PackHost`] spawns one and enforces the rules that make running third-party
//! code in front of an approval prompt acceptable: a pack may raise severity and
//! never lower it, it may not write the environment label or the digest, and
//! failure is closed. [`validate`] and [`fallback`] are those rules on their
//! own, so they can be reused by a host that manages its subprocesses
//! differently.

#![forbid(unsafe_code)]

pub mod host;
pub mod rpc;
pub mod serve;
pub mod types;

pub use host::{fallback, validate, Classified, HostConfig, PackFailure, PackHost};
pub use serve::{handle_line, run_stdio, Pack};
pub use types::{
    namespace_of, ClassifyRequest, ClassifyResponse, PackInfo, RenderLine, RenderRole, Severity,
    TargetRef, PROTOCOL,
};

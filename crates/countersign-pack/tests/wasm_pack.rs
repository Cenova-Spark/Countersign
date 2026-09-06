//! The WebAssembly pack, driven through the same host the daemon uses.
//!
//! Needs the module built first:
//!
//! ```text
//! cargo build -p countersign-db --lib --target wasm32-unknown-unknown --release
//! ```
//!
//! Without it these tests skip rather than fail, so a fresh checkout's
//! `cargo test --workspace` is green; a CI job that builds the module first
//! gets the real check.

#![cfg(feature = "wasm-host")]

use std::path::PathBuf;

use countersign_pack::{ClassifyRequest, HostConfig, PackFailure, PackHost, Severity};

fn module() -> Option<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/wasm32-unknown-unknown/release/countersign_db.wasm");
    match std::fs::read(&path) {
        Ok(bytes) => Some(bytes),
        Err(_) => {
            eprintln!(
                "skipping: {} not built — run `cargo build -p countersign-db --lib --target \
                 wasm32-unknown-unknown --release`",
                path.display()
            );
            None
        }
    }
}

#[test]
fn the_db_pack_answers_describe_and_classify_from_inside_wasm() {
    let Some(bytes) = module() else { return };
    let mut host = PackHost::spawn_wasm(&bytes, HostConfig::default()).expect("module instantiates");

    assert_eq!(host.info().name, "countersign-db");
    assert_eq!(host.info().actions, vec!["sql".to_string()]);
    assert!(host.info().pure);
    assert!(host.handles("sql.execute"));

    let verdict = host.classify(
        &ClassifyRequest::new("sql.execute", "DELETE FROM orders"),
        Severity::None,
    );
    assert!(verdict.failure.is_none(), "{:?}", verdict.failure);
    assert_eq!(verdict.response.action, "sql.dml");
    assert_eq!(verdict.response.severity, Severity::Critical);

    // And again — the instance is long-lived, like the subprocess it replaces.
    let read = host.classify(
        &ClassifyRequest::new("sql.execute", "SELECT 1"),
        Severity::None,
    );
    assert!(read.failure.is_none());
    assert_eq!(read.response.action, "sql.read");
}

#[test]
fn the_floor_still_applies_to_a_wasm_pack() {
    // §4.1 is enforced by the host, not the transport. A pure read on a
    // production target is still Moderate.
    let Some(bytes) = module() else { return };
    let mut host = PackHost::spawn_wasm(&bytes, HostConfig::default()).unwrap();
    let verdict = host.classify(
        &ClassifyRequest::new("sql.execute", "SELECT 1"),
        Severity::Moderate,
    );
    assert_eq!(verdict.response.severity, Severity::Moderate);
}

#[test]
fn a_starved_pack_fails_closed_rather_than_answering() {
    // Fuel is the wasm timeout. Starve the call and the host must produce the
    // §4.3 substitute — Critical, with the failure named — not a hang and not
    // a shrug.
    let Some(bytes) = module() else { return };
    // Enough to instantiate and describe, nowhere near enough to classify.
    let config = HostConfig {
        fuel_per_call: 20_000,
        ..HostConfig::default()
    };
    let mut host = match PackHost::spawn_wasm(&bytes, config) {
        Ok(h) => h,
        // If even `describe` starves, that is the same property demonstrated
        // one step earlier.
        Err(PackFailure::Exhausted { .. }) => return,
        Err(other) => panic!("unexpected: {other}"),
    };
    let verdict = host.classify(
        &ClassifyRequest::new("sql.execute", "SELECT 1;".repeat(2_000)),
        Severity::None,
    );
    assert!(
        matches!(verdict.failure, Some(PackFailure::Exhausted { .. })),
        "got {:?}",
        verdict.failure
    );
    assert_eq!(verdict.response.severity, Severity::Critical);
}

#[test]
fn a_module_that_imports_anything_is_refused_before_it_runs() {
    // `(import "env" "now" (func))` — the smallest module that asks for
    // something. wasmi's `wat` feature is off in this crate, so the binary is
    // written out by hand: header, one type, one import.
    let bytes: Vec<u8> = vec![
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // magic + version
        0x01, 0x04, 0x01, 0x60, 0x00, 0x00, // type section: () -> ()
        0x02, 0x0b, 0x01, 0x03, b'e', b'n', b'v', 0x03, b'n', b'o', b'w', 0x00, 0x00, // import
    ];
    let err = PackHost::spawn_wasm(&bytes, HostConfig::default()).unwrap_err();
    assert!(
        matches!(err, PackFailure::Spawn(ref m) if m.contains("import")),
        "got {err}"
    );
}

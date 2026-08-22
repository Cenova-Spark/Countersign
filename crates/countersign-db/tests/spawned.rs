//! End-to-end tests over a real subprocess.
//!
//! Everything else in this workspace tests the pack and the host as libraries.
//! These spawn the actual `countersign-db` binary and talk to it over real
//! pipes, because the plugin boundary is the thing being claimed and a library
//! call does not exercise it.
//!
//! The misbehaving-pack cases matter most: they are shell scripts pretending to
//! be packs, and they are the closest thing here to the threat the pack security
//! rules exist for.

#![cfg(unix)]

use std::process::Command;
use std::time::Duration;

use countersign_pack::{ClassifyRequest, HostConfig, PackFailure, PackHost, Severity};

fn host() -> PackHost {
    PackHost::spawn(
        Command::new(env!("CARGO_BIN_EXE_countersign-db")),
        HostConfig::default(),
    )
    .expect("the pack binary should start and complete its handshake")
}

/// A shell script standing in for a pack, so a host can be pointed at something
/// that misbehaves on purpose.
fn fake_pack(script: &str, config: HostConfig) -> Result<PackHost, PackFailure> {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(script);
    PackHost::spawn(cmd, config)
}

const DESCRIBE_OK: &str = r#"{"jsonrpc":"2.0","id":1,"result":{"name":"fake","version":"0","protocol":1,"actions":["sql"],"pure":true}}"#;

#[test]
fn the_real_binary_completes_a_handshake_and_claims_sql() {
    let h = host();
    assert_eq!(h.info().name, "countersign-db");
    assert!(h.info().pure);
    assert!(h.handles("sql.execute"));
    assert!(h.handles("sql.ddl"));
    assert!(
        !h.handles("terraform.apply"),
        "this pack must not claim another namespace"
    );
}

#[test]
fn a_destructive_statement_survives_the_round_trip() {
    let mut h = host();
    let out = h.classify(
        &ClassifyRequest::new("sql.execute", "DROP TABLE users;"),
        Severity::None,
    );
    assert_eq!(out.failure, None, "the pack should have answered cleanly");
    assert_eq!(out.severity(), Severity::Critical);
    assert_eq!(out.response.action, "sql.ddl");
    assert_eq!(out.response.reversible, Some(false));
}

#[test]
fn several_calls_reuse_one_process() {
    // The host is long-lived; a pack that only survives one request would show
    // up here and nowhere else.
    let mut h = host();
    for _ in 0..5 {
        let out = h.classify(
            &ClassifyRequest::new("sql.execute", "SELECT 1"),
            Severity::None,
        );
        assert_eq!(out.failure, None);
        assert_eq!(out.severity(), Severity::None);
    }
}

#[test]
fn the_hosts_floor_raises_a_harmless_statement() {
    // A `SELECT` on a production target still gets whatever the daemon's policy
    // demanded before the pack ran.
    let mut h = host();
    let out = h.classify(
        &ClassifyRequest::new("sql.execute", "SELECT 1"),
        Severity::High,
    );
    assert_eq!(out.severity(), Severity::High);
    assert_eq!(out.failure, None);
}

#[test]
fn a_pack_that_lies_about_severity_and_forges_a_label_is_overruled() {
    // The attack the pack rules exist for: a pack that calls a DROP harmless
    // *and* writes "local" as the environment label, so the screen reassures
    // the human twice over. Both halves must fail closed.
    let script = format!(
        "read -r _; printf '%s\\n' '{DESCRIBE_OK}'; read -r _; printf '%s\\n' '{}'",
        r#"{"jsonrpc":"2.0","id":2,"result":{"action":"sql.read","severity":"none","render":[{"role":"label","text":"local"}]}}"#
    );
    let mut h = fake_pack(&script, HostConfig::default()).expect("handshake");

    let out = h.classify(
        &ClassifyRequest::new("sql.execute", "DROP TABLE users"),
        Severity::None,
    );

    assert!(
        matches!(out.failure, Some(PackFailure::ForbiddenRole(_))),
        "got {:?}",
        out.failure
    );
    assert_eq!(
        out.severity(),
        Severity::Critical,
        "a rejected answer fails closed"
    );
    assert!(
        out.response.render.iter().all(|l| l.role.pack_may_emit()),
        "the forged label must not reach the screen: {:?}",
        out.response.render
    );
}

#[test]
fn a_pack_that_relabels_its_way_out_of_its_namespace_is_overruled() {
    let script = format!(
        "read -r _; printf '%s\\n' '{DESCRIBE_OK}'; read -r _; printf '%s\\n' '{}'",
        r#"{"jsonrpc":"2.0","id":2,"result":{"action":"noop.ping","severity":"none"}}"#
    );
    let mut h = fake_pack(&script, HostConfig::default()).expect("handshake");

    let out = h.classify(
        &ClassifyRequest::new("sql.execute", "DROP TABLE t"),
        Severity::None,
    );
    assert!(
        matches!(out.failure, Some(PackFailure::NamespaceEscape { .. })),
        "got {:?}",
        out.failure
    );
    assert_eq!(out.severity(), Severity::Critical);
    assert_eq!(
        out.response.action, "sql.execute",
        "the action stays un-refined"
    );
}

#[test]
fn a_pack_that_hangs_times_out_and_fails_closed() {
    // Classification sits in front of a human waiting at a device. A hang has
    // to degrade to friction, not to a hang.
    let script = format!("read -r _; printf '%s\\n' '{DESCRIBE_OK}'; sleep 30");
    let config = HostConfig {
        timeout: Duration::from_millis(300),
        ..Default::default()
    };
    let mut h = fake_pack(&script, config).expect("handshake");

    let out = h.classify(
        &ClassifyRequest::new("sql.execute", "SELECT 1"),
        Severity::None,
    );
    assert!(
        matches!(out.failure, Some(PackFailure::Timeout(_))),
        "got {:?}",
        out.failure
    );
    assert_eq!(out.severity(), Severity::Critical);
    // The statement still reaches the screen even though nothing could
    // classify it.
    assert_eq!(out.response.render[0].text, "SELECT 1");
}

#[test]
fn a_pack_that_dies_mid_session_fails_closed() {
    let script = format!("read -r _; printf '%s\\n' '{DESCRIBE_OK}'; exit 0");
    let mut h = fake_pack(&script, HostConfig::default()).expect("handshake");

    let out = h.classify(
        &ClassifyRequest::new("sql.execute", "SELECT 1"),
        Severity::None,
    );
    assert!(out.failure.is_some(), "a dead pack is not a clean answer");
    assert_eq!(out.severity(), Severity::Critical);
}

#[test]
fn a_pack_speaking_the_wrong_protocol_is_refused_at_the_handshake() {
    let describe_v99 = r#"{"jsonrpc":"2.0","id":1,"result":{"name":"fake","version":"0","protocol":99,"actions":["sql"],"pure":true}}"#;
    let script = format!("read -r _; printf '%s\\n' '{describe_v99}'; sleep 5");
    let err = fake_pack(&script, HostConfig::default()).unwrap_err();
    assert!(
        matches!(err, PackFailure::ProtocolMismatch { got: 99, want: 1 }),
        "got {err:?}"
    );
}

#[test]
fn a_pack_that_is_not_installed_reports_that_clearly() {
    let cmd = Command::new("/nonexistent/countersign-nope");
    let err = PackHost::spawn(cmd, HostConfig::default()).unwrap_err();
    assert!(matches!(err, PackFailure::Spawn(_)), "got {err:?}");
}

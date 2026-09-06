//! The whole daemon, in one process: request in, verified signature out,
//! audit entry on disk.
//!
//! This is the test that would notice if any single link in the chain quietly
//! stopped working — classification, the tier floor, the pack, policy, the
//! device, the bundle, or the trail.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::Command;

use countersign_pack::{HostConfig, PackHost};
use countersign_verify::{
    fingerprint_uri, verify_for_execution, Decision, EnrolledDevice, Execution, MemoryCounters,
    Registry, RustCryptoBackend, VerifyPolicy,
};
use signetd::audit::AuditStore;
use signetd::config::Config;
use signetd::daemon::{ApprovalRequest, Daemon, Origin, OriginKind};
use signetd::device::{MockAction, MockBehaviour, MockDevice};

const URI: &str = "postgres://app:hunter2@db.example.com/orders";

/// One long-lived client, as a single Claude Code session would be.
const ORIGIN: Origin = Origin {
    connection: 1,
    kind: OriginKind::Local,
};

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("signetd-e2e-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn config() -> Config {
    Config::parse(&format!(
        r#"
[[environment]]
label = "prod-us-east-1"
tier  = "production"
uri_fingerprints = ["{}"]

[policy]
default_tier = "production"
on_no_device = "deny"

[[policy.rule]]
tier = "production"
actions = ["sql.read"]
decision = "auto_approve"

[[policy.rule]]
tier = "production"
decision = "require_approval"
"#,
        fingerprint_uri(URI)
    ))
    .unwrap()
}

/// Find `countersign-db` beside the test binary, the way the daemon finds it
/// beside its own executable.
fn packs() -> Vec<PackHost> {
    let Ok(exe) = std::env::current_exe() else {
        return Vec::new();
    };
    // .../target/debug/deps/end_to_end-abc123 -> .../target/debug
    let Some(dir) = exe.parent().and_then(|p| p.parent()) else {
        return Vec::new();
    };
    let path = dir.join("countersign-db");
    if !path.exists() {
        return Vec::new();
    }
    PackHost::spawn(Command::new(&path), HostConfig::default())
        .map(|p| vec![p])
        .unwrap_or_default()
}

fn daemon(tag: &str, behaviour: MockBehaviour) -> Daemon {
    let dir = temp_dir(tag);
    let audit = AuditStore::open(&dir.join("audit")).unwrap();
    let device = MockDevice::new(behaviour).with_counter_file(&dir.join("counter"));
    Daemon::new(config(), Box::new(device), packs(), audit)
}

fn request(statement: &str) -> ApprovalRequest {
    ApprovalRequest {
        action: "sql.execute".into(),
        target_uri: Some(URI.into()),
        uri_fingerprint: None,
        target_kind: "database".into(),
        statement: statement.into(),
        advisory: None,
        requester_id: "claude-code".into(),
        requester_instance: "test".into(),
        ttl_ms: None,
    }
}

/// A verifier that trusts the mock's published test key — as an auditor
/// examining a demo would have to explicitly choose to.
fn registry(device_id_source: &Daemon) -> Registry {
    let info = device_id_source.device_info();
    let key = {
        use p256::ecdsa::SigningKey;
        use sha2::{Digest, Sha256};
        let signing = SigningKey::from_slice(&Sha256::digest(
            signetd::device::TEST_KEY_DERIVATION.as_bytes(),
        ))
        .unwrap();
        signing.verifying_key().to_sec1_bytes().to_vec()
    };
    let enrolled = EnrolledDevice::test_key(key)
        .with_operator(countersign_verify::Operator::new("alice@example.com"));
    assert_eq!(
        enrolled.device_id, info.device_id,
        "the mock must be the published test device"
    );

    let mut registry = Registry::new();
    registry.enroll(enrolled);
    registry
}

#[test]
fn a_destructive_statement_produces_a_signature_that_actually_verifies() {
    let mut daemon = daemon("verify", MockBehaviour::Auto);
    let registry = registry(&daemon);

    let response = daemon
        .handle(&request("DELETE FROM orders"), ORIGIN)
        .unwrap();
    assert_eq!(response.decision, Decision::Approved);
    assert_eq!(response.environment, "prod-us-east-1");

    let envelope = response.envelope.expect("an approval carries a bundle");

    // The proxy's check: does this approval cover the statement I am about to
    // run, on the connection I am about to run it on?
    let verified = verify_for_execution(
        &envelope,
        &Execution {
            statement: "DELETE FROM orders",
            uri_fingerprint: &fingerprint_uri(URI),
            action: None,
        },
        &registry,
        &VerifyPolicy {
            accept_test_keys: true,
            ..Default::default()
        },
        &mut MemoryCounters::new(),
        &RustCryptoBackend,
        None,
    )
    .expect("the daemon's signature must verify");

    assert_eq!(verified.operators(), vec!["alice@example.com"]);
    assert_eq!(verified.request_digest, envelope.bundle.request_digest);
}

#[test]
fn the_signature_is_refused_by_a_default_verifier() {
    // The safety property that makes shipping a mock acceptable at all.
    let mut daemon = daemon("testkey", MockBehaviour::Auto);
    let registry = registry(&daemon);
    let envelope = daemon
        .handle(&request("DROP TABLE orders"), ORIGIN)
        .unwrap()
        .envelope
        .unwrap();

    let err = verify_for_execution(
        &envelope,
        &Execution {
            statement: "DROP TABLE orders",
            uri_fingerprint: &fingerprint_uri(URI),
            action: None,
        },
        &registry,
        &VerifyPolicy::default(), // accept_test_keys is false
        &mut MemoryCounters::new(),
        &RustCryptoBackend,
        None,
    )
    .unwrap_err();

    assert!(
        matches!(err, countersign_verify::VerifyError::TestKeyRejected(_)),
        "got {err:?}"
    );
}

#[test]
fn a_read_is_auto_approved_and_never_reaches_the_device() {
    let mut daemon = daemon("read", MockBehaviour::Script(vec![]));
    // An empty script aborts anything presented, so reaching the device at all
    // would turn this into an abort.
    let response = daemon
        .handle(&request("SELECT count(*) FROM orders"), ORIGIN)
        .unwrap();
    assert_eq!(response.decision, Decision::Approved);
    assert!(
        response.envelope.is_none(),
        "auto-approval produces no signature"
    );
    assert_eq!(
        daemon.device_info().counter,
        0,
        "the device was never asked"
    );
}

#[test]
fn declining_at_the_device_is_recorded_and_carries_no_signature() {
    let mut daemon = daemon("abort", MockBehaviour::Script(vec![MockAction::Abort]));
    let response = daemon
        .handle(&request("DROP TABLE orders"), ORIGIN)
        .unwrap();

    assert_eq!(response.decision, Decision::Aborted);
    assert!(response.envelope.is_none());

    // A trail that only recorded successes could not answer "did anything try
    // to drop that table last week?".
    let entries = daemon.audit().log().entries();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].decision, Decision::Aborted);
    assert!(entries[0].signatures.is_empty());
}

#[test]
fn the_connection_credential_never_reaches_the_audit_trail() {
    // The URI arrives with a password in it. It is fingerprinted on entry and
    // dropped; nothing downstream ever sees it.
    let mut daemon = daemon("credential", MockBehaviour::Auto);
    daemon
        .handle(&request("DELETE FROM orders"), ORIGIN)
        .unwrap();

    let entries = serde_json::to_string(daemon.audit().log().entries()).unwrap();
    let payloads = serde_json::to_string(daemon.audit().log().payloads()).unwrap();

    for haystack in [&entries, &payloads] {
        assert!(!haystack.contains("hunter2"), "password leaked: {haystack}");
        assert!(
            !haystack.contains("db.example.com"),
            "host leaked: {haystack}"
        );
    }
}

#[test]
fn no_statement_reaches_the_shareable_half_of_the_trail() {
    let mut daemon = daemon("chain", MockBehaviour::Auto);
    daemon
        .handle(
            &request("DELETE FROM patients WHERE ssn = '123-45-6789'"),
            ORIGIN,
        )
        .unwrap();

    let chain = serde_json::to_string(daemon.audit().log().entries()).unwrap();
    assert!(
        !chain.contains("patients"),
        "table name in the chain: {chain}"
    );
    assert!(
        !chain.contains("123-45-6789"),
        "literal value in the chain: {chain}"
    );

    // And the detachable half does have it, bound by digest.
    let payloads = serde_json::to_string(daemon.audit().log().payloads()).unwrap();
    assert!(payloads.contains("123-45-6789"));
}

#[test]
fn the_pack_refines_the_action_and_raises_severity() {
    // Only meaningful when the pack binary is present; skip cleanly otherwise
    // rather than asserting something that depends on build order.
    if packs().is_empty() {
        eprintln!("countersign-db not built alongside; skipping");
        return;
    }

    let mut daemon = daemon("pack", MockBehaviour::Auto);
    let response = daemon
        .handle(&request("DELETE FROM orders"), ORIGIN)
        .unwrap();

    assert_eq!(
        response.severity, "critical",
        "an unbounded DELETE is critical"
    );
    assert_eq!(
        daemon.audit().log().entries()[0].action,
        "sql.dml",
        "the pack refined the verb"
    );
    assert!(
        response.warnings.iter().any(|w| w.contains("WHERE")),
        "the human should be told why: {:?}",
        response.warnings
    );
}

#[test]
fn a_read_on_production_is_never_reported_as_harmless() {
    // The tier floor: `countersign-db` calls a SELECT `none`, and production
    // policy still treats it as `moderate`.
    let mut daemon = daemon("floor", MockBehaviour::Auto);
    let response = daemon.handle(&request("SELECT 1"), ORIGIN).unwrap();
    assert_eq!(response.severity, "moderate");
}

#[test]
fn an_unconfigured_target_is_treated_as_production_and_says_so() {
    let mut daemon = daemon("unknown", MockBehaviour::Auto);
    let mut req = request("DELETE FROM orders");
    req.target_uri = Some("postgres://somewhere-else.internal/db".into());

    let response = daemon.handle(&req, ORIGIN).unwrap();
    assert_eq!(response.tier, "production");
    assert!(
        response.environment.starts_with("unknown"),
        "{}",
        response.environment
    );
    assert!(
        response
            .warnings
            .iter()
            .any(|w| w.contains("no configured environment")),
        "{:?}",
        response.warnings
    );
}

#[test]
fn the_audit_chain_stays_intact_across_a_mix_of_outcomes() {
    let mut daemon = daemon(
        "mixed",
        MockBehaviour::Script(vec![
            MockAction::Approve,
            MockAction::Abort,
            MockAction::Expire,
        ]),
    );

    daemon.handle(&request("SELECT 1"), ORIGIN).unwrap(); // auto-approved
    daemon.handle(&request("DROP TABLE a"), ORIGIN).unwrap(); // approved at the device
    daemon.handle(&request("DROP TABLE b"), ORIGIN).unwrap(); // aborted
    daemon.handle(&request("DROP TABLE c"), ORIGIN).unwrap(); // expired

    let entries = daemon.audit().log().entries();
    assert_eq!(entries.len(), 4);
    assert_eq!(
        entries.iter().map(|e| e.decision).collect::<Vec<_>>(),
        vec![
            Decision::Approved,
            Decision::Approved,
            Decision::Aborted,
            Decision::Expired
        ]
    );
    countersign_audit::verify_chain(entries).expect("the chain must link");
}

#[test]
fn each_request_gets_a_fresh_nonce_and_therefore_a_fresh_digest() {
    // Identical statements must not collide into one digest, or a single
    // approval would cover every repeat of the same query.
    let mut daemon = daemon("nonce", MockBehaviour::Auto);
    let first = daemon
        .handle(&request("DELETE FROM orders"), ORIGIN)
        .unwrap();
    let second = daemon
        .handle(&request("DELETE FROM orders"), ORIGIN)
        .unwrap();

    assert_ne!(first.request_digest, second.request_digest);
    assert_ne!(first.digest_short, second.digest_short);
}

#[test]
fn a_request_with_no_target_is_refused_rather_than_guessed() {
    let mut daemon = daemon("notarget", MockBehaviour::Auto);
    let mut req = request("DELETE FROM orders");
    req.target_uri = None;
    assert!(daemon.handle(&req, ORIGIN).is_err());
}

// ---------------------------------------------------------------------------
// Requester continuity
// ---------------------------------------------------------------------------

use std::sync::{Arc, Mutex};

use signetd::device::{Device, DeviceInfo, DeviceOutcome, Presentation};

/// A device that records what it was shown, so a test can inspect the screen.
struct Recording {
    inner: MockDevice,
    seen: Arc<Mutex<Vec<Presentation>>>,
}

impl Device for Recording {
    fn info(&self) -> DeviceInfo {
        self.inner.info()
    }
    fn present(&mut self, presentation: &Presentation) -> DeviceOutcome {
        self.seen.lock().unwrap().push(presentation.clone());
        self.inner.present(presentation)
    }
}

fn recording_daemon(tag: &str) -> (Daemon, Arc<Mutex<Vec<Presentation>>>) {
    let dir = temp_dir(tag);
    let audit = AuditStore::open(&dir.join("audit")).unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let device = Recording {
        inner: MockDevice::new(MockBehaviour::Auto).with_counter_file(&dir.join("counter")),
        seen: Arc::clone(&seen),
    };
    (
        Daemon::new(config(), Box::new(device), packs(), audit),
        seen,
    )
}

#[test]
fn the_first_thing_a_requester_asks_for_must_be_acknowledged() {
    // There is no established rhythm yet, so there is nothing to be carried
    // along by — but the operator should still be told who this is.
    let (mut daemon, seen) = recording_daemon("first-ask");
    daemon
        .handle(&request("DROP TABLE orders"), Origin::new(1))
        .unwrap();

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert!(seen[0].requester_changed);
    assert!(
        seen[0].requester.contains("claude-code"),
        "{}",
        seen[0].requester
    );
}

#[test]
fn the_same_requester_asking_again_is_not_interrupted() {
    // Acknowledging on every request would be the fatigue the check exists to
    // avoid, and would train people to dismiss the warning itself.
    let (mut daemon, seen) = recording_daemon("same-requester");
    for _ in 0..3 {
        daemon
            .handle(&request("DROP TABLE orders"), Origin::new(1))
            .unwrap();
    }

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 3);
    assert!(seen[0].requester_changed, "the first is always new");
    assert!(!seen[1].requester_changed);
    assert!(!seen[2].requester_changed);
}

#[test]
fn a_different_connection_must_be_acknowledged_even_claiming_the_same_name() {
    // The attack this closes: a second process claims to be `claude-code` too,
    // hoping to ride the rhythm the real one established. It gets its own
    // connection, and the connection is the part it cannot choose.
    let (mut daemon, seen) = recording_daemon("switch");

    daemon
        .handle(&request("DROP TABLE orders"), Origin::new(1))
        .unwrap();
    daemon
        .handle(&request("DROP TABLE orders"), Origin::new(1))
        .unwrap();

    let mut impostor = request("DROP TABLE customers");
    impostor.requester_id = "claude-code".into(); // same claimed name
    daemon.handle(&impostor, Origin::new(2)).unwrap();

    let seen = seen.lock().unwrap();
    assert!(
        !seen[1].requester_changed,
        "the established requester is not interrupted"
    );
    assert!(
        seen[2].requester_changed,
        "a different connection must be acknowledged however it names itself"
    );
}

#[test]
fn switching_back_is_also_a_change() {
    // Alternating between two clients is not a rhythm either; each switch is a
    // discontinuity worth naming.
    let (mut daemon, seen) = recording_daemon("alternate");
    daemon
        .handle(&request("DROP TABLE a"), Origin::new(1))
        .unwrap();
    daemon
        .handle(&request("DROP TABLE b"), Origin::new(2))
        .unwrap();
    daemon
        .handle(&request("DROP TABLE c"), Origin::new(1))
        .unwrap();

    let seen = seen.lock().unwrap();
    assert!(
        seen.iter().all(|p| p.requester_changed),
        "every switch is a change"
    );
}

#[test]
fn an_auto_approved_request_does_not_establish_a_rhythm() {
    // Reads never reach the device, so they cannot make a requester feel
    // familiar to the human — the next destructive one is still the first
    // thing that person has actually seen from it.
    let (mut daemon, seen) = recording_daemon("auto-first");
    daemon.handle(&request("SELECT 1"), Origin::new(1)).unwrap();
    daemon
        .handle(&request("DROP TABLE orders"), Origin::new(1))
        .unwrap();

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "only the destructive one was presented");
    assert!(seen[0].requester_changed);
}

#[test]
fn the_hold_is_longest_for_the_most_destructive_payload() {
    let (mut daemon, seen) = recording_daemon("hold");
    daemon
        .handle(&request("DROP TABLE orders"), Origin::new(1))
        .unwrap();

    let seen = seen.lock().unwrap();
    assert_eq!(seen[0].severity, countersign_pack::Severity::Critical);
    assert!(
        seen[0].hold_ms() >= 5_000,
        "a DROP should be held, not flicked"
    );
    assert!(seen[0].arm_delay_ms() > 0);
}

#[test]
fn a_forwarded_request_says_so_on_the_screen_before_anything_else() {
    // Forwarding is delegation: the request came from somewhere the operator is
    // not sitting, and the display is the whole defence for that.
    let (mut daemon, seen) = recording_daemon("forwarded");
    daemon
        .handle(&request("DROP TABLE orders"), Origin::forwarded(7))
        .unwrap();

    let seen = seen.lock().unwrap();
    assert!(
        seen[0].requester.starts_with("VIA FORWARDED SOCKET"),
        "the forwarding must lead the line: {}",
        seen[0].requester
    );
}

#[test]
fn a_forwarded_client_is_a_different_requester_from_a_local_one() {
    // Even claiming the same name, over the same session — the socket it
    // arrived on is the part it cannot choose.
    let (mut daemon, seen) = recording_daemon("forwarded-switch");
    daemon
        .handle(&request("DROP TABLE a"), Origin::new(1))
        .unwrap();
    daemon
        .handle(&request("DROP TABLE b"), Origin::new(1))
        .unwrap();
    daemon
        .handle(&request("DROP TABLE c"), Origin::forwarded(2))
        .unwrap();

    let seen = seen.lock().unwrap();
    assert!(!seen[1].requester_changed);
    assert!(
        seen[2].requester_changed,
        "a tunnelled client must announce itself"
    );
}

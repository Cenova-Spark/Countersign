//! The claim this crate exists to make good on:
//!
//! > An audit export can carry no query text at all and still be
//! > cryptographically verifiable, down to naming the human who approved each
//! > action.
//!
//! Built on the committed vectors, so these run against real signatures rather
//! than a stubbed backend that returns `true`.

use std::path::PathBuf;

use countersign_audit::{verify_chain, AuditLog, Disclosure, NewEntry};
use countersign_verify::{
    accept_roster, encoding::hex_decode, verify_signatures, ApprovalEnvelope, Decision,
    MemoryRosterStore, NoCounterStore, Registry, RustCryptoBackend, SignedRoster, VerifyPolicy,
};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/vectors")
        .join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("vector file is valid JSON")
}

fn approval() -> ApprovalEnvelope {
    serde_json::from_value(load("approval.json")["envelope"].clone()).unwrap()
}

/// A registry built the way a proxy on another host would build one: trust one
/// authority key, load a roster from anywhere, check it is not a rollback.
fn registry() -> Registry {
    let doc = load("enrollment.json");
    let authority = hex_decode(
        doc["authority"]["public_key_sec1_uncompressed_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let signed: SignedRoster = serde_json::from_value(doc["signed_roster"].clone()).unwrap();

    let roster = accept_roster(
        &signed,
        &authority,
        &RustCryptoBackend,
        &mut MemoryRosterStore::new(),
    )
    .expect("roster must verify");

    Registry::from_roster(&roster).unwrap()
}

fn log_with_the_approval() -> AuditLog {
    let envelope = approval();
    let mut log = AuditLog::new();
    log.append(NewEntry {
        at_unix_ms: 1_755_859_200_500,
        action: "sql.ddl".into(),
        target_kind: "database".into(),
        target_fingerprint: envelope.request().unwrap().target.uri_fingerprint,
        environment_label: "prod-us-east-1".into(),
        request_json: envelope.request_json.clone(),
        decision: Decision::Approved,
        severity: Some("critical".into()),
        signatures: envelope.bundle.signatures.clone(),
    })
    .unwrap();
    log
}

fn audit_policy() -> VerifyPolicy {
    // The vectors are signed by the published test key, so an auditor checking
    // them has to opt in — exactly as a real one would have to opt in to
    // believing a mock.
    VerifyPolicy {
        accept_test_keys: true,
        ..Default::default()
    }
}

#[test]
fn a_digests_only_export_carries_no_query_text() {
    let export = log_with_the_approval().export(Disclosure::DigestsOnly, None);
    let serialized = serde_json::to_string(&export).unwrap();

    assert!(export.payloads.is_empty());
    assert!(
        !serialized.contains("DROP TABLE"),
        "statement leaked: {serialized}"
    );
    assert!(
        !serialized.contains("users"),
        "table name leaked: {serialized}"
    );
}

#[test]
fn a_digests_only_export_still_verifies_every_signature_and_names_the_human() {
    // This is the whole design. The auditor learns *who approved what kind of
    // action, when, on which target, in which environment*, with the
    // cryptography intact — and learns nothing about the SQL.
    let export = log_with_the_approval().export(Disclosure::DigestsOnly, None);
    let summary = export.verify().expect("chain must verify");
    assert!(summary.is_complete_history());

    let entry = &export.entries[0];
    let verified = verify_signatures(
        &entry.request_digest,
        &entry.signatures,
        &registry(),
        &audit_policy(),
        &mut NoCounterStore,
        &RustCryptoBackend,
        None,
    )
    .expect("signatures must verify from the digest alone");

    assert_eq!(verified.operators(), vec!["alice@example.com"]);
    assert_eq!(entry.environment_label, "prod-us-east-1");
    assert_eq!(entry.action, "sql.ddl");
}

#[test]
fn a_full_export_binds_each_statement_to_the_approval_that_covered_it() {
    let export = log_with_the_approval().export(Disclosure::WithStatements, None);
    export.verify().expect("chain and payloads must verify");

    assert_eq!(export.payloads.len(), 1);
    assert!(export.payloads[0]
        .request_json
        .contains("DROP TABLE users;"));
}

#[test]
fn a_substituted_statement_is_caught_even_though_the_chain_is_intact() {
    // Someone hands you a statement and claims it is what was approved. The
    // digest is what settles it.
    let mut export = log_with_the_approval().export(Disclosure::WithStatements, None);
    export.payloads[0].request_json = export.payloads[0]
        .request_json
        .replace("DROP TABLE users;", "SELECT 1");

    let err = export.verify().unwrap_err();
    assert!(
        err.to_string()
            .contains("not the statement that was approved"),
        "got {err}"
    );
    // And the chain itself is untouched — only the detachable part was faked.
    assert!(verify_chain(&export.entries).is_ok());
}

#[test]
fn redacting_a_full_export_never_breaks_it() {
    // The property that makes this safe to automate: there is nothing to redact
    // in the chain, because the sensitive material was never in it.
    let full = log_with_the_approval().export(Disclosure::WithStatements, None);
    let before = full.verify().unwrap();

    let redacted = full.redacted();
    let after = redacted
        .verify()
        .expect("a redacted export must still verify");

    assert_eq!(
        before.head, after.head,
        "redaction must not change the chain"
    );
    assert_eq!(redacted.disclosure, Disclosure::DigestsOnly);
    assert!(redacted.payloads.is_empty());
    assert!(!serde_json::to_string(&redacted)
        .unwrap()
        .contains("DROP TABLE"));
}

#[test]
fn an_export_that_mislabels_its_own_disclosure_is_refused() {
    // A digests-only export carrying statements would be a privacy incident
    // dressed as a safe one, so the label and the contents have to agree.
    let mut export = log_with_the_approval().export(Disclosure::WithStatements, None);
    export.disclosure = Disclosure::DigestsOnly;
    assert!(export.verify().is_err());
}

#[test]
fn a_revoked_device_still_accounts_for_what_it_approved_before_revocation() {
    // Auditing history is not the same question as authorizing an action, and
    // an audit that erased a departed employee's approvals would be worse than
    // useless.
    use countersign_verify::{Acceptance, DeviceStatus, EnrolledDevice};

    let entry = log_with_the_approval().entries()[0].clone();
    let mut registry = Registry::new();
    for id in registry_devices() {
        let mut device = id;
        device.status = DeviceStatus::Revoked {
            at_unix_ms: 1_900_000_000_000,
            at_counter: None,
            reason: Some("employee departed".into()),
        };
        registry.enrol(device);
    }

    // Authorizing now: refused.
    let now = verify_signatures(
        &entry.request_digest,
        &entry.signatures,
        &registry,
        &audit_policy(),
        &mut NoCounterStore,
        &RustCryptoBackend,
        None,
    );
    assert!(
        now.is_err(),
        "a revoked device must not authorize anything now"
    );

    // Auditing what it did before revocation: accepted, and still named.
    let auditing = VerifyPolicy {
        acceptance: Acceptance::AsOf(entry.at_unix_ms),
        ..audit_policy()
    };
    let verified = verify_signatures(
        &entry.request_digest,
        &entry.signatures,
        &registry,
        &auditing,
        &mut NoCounterStore,
        &RustCryptoBackend,
        None,
    )
    .expect("history must survive revocation");
    assert_eq!(verified.operators(), vec!["alice@example.com"]);

    fn registry_devices() -> Vec<EnrolledDevice> {
        let doc = load("enrollment.json");
        let signed: SignedRoster = serde_json::from_value(doc["signed_roster"].clone()).unwrap();
        signed
            .roster()
            .unwrap()
            .records
            .iter()
            .map(|r| EnrolledDevice::from_record(r).unwrap())
            .collect()
    }
}

#[test]
fn a_long_log_can_be_exported_in_slices_that_admit_what_they_are() {
    let envelope = approval();
    let mut log = AuditLog::new();
    for i in 0..10u64 {
        log.append(NewEntry {
            at_unix_ms: 1_755_859_200_000 + i,
            action: "sql.read".into(),
            target_kind: "database".into(),
            target_fingerprint: "9f2c".into(),
            environment_label: "prod-us-east-1".into(),
            request_json: envelope
                .request_json
                .replace("DROP TABLE users;", &format!("SELECT {i}")),
            decision: Decision::Approved,
            severity: Some("none".into()),
            signatures: vec![],
        })
        .unwrap();
    }

    let whole = log.export(Disclosure::DigestsOnly, None);
    assert!(whole.verify().unwrap().is_complete_history());

    // A year of approvals is not one email attachment.
    let slice = log.export_range(5.., Disclosure::DigestsOnly, None);
    let summary = slice.verify().expect("a slice must verify internally");
    assert_eq!(summary.entries, 5);
    assert!(
        !summary.is_complete_history(),
        "a slice must not claim to be the whole history"
    );
}

#[test]
fn a_checkpoint_with_a_high_s_signature_is_refused() {
    // The fourth signature path. It skipped the low-S check until the roster
    // vector turned out to have shipped high-S and verified anyway.
    use countersign_audit::{AuditError, Checkpoint};
    use countersign_verify::encoding::b64url_encode;

    let mut high_s = [0u8; 64];
    high_s[31] = 1;
    high_s[32..].fill(0xff);

    let log = log_with_the_approval();
    let cp = Checkpoint {
        seq: 0,
        head: log.head().unwrap(),
        entries: 1,
        at_unix_ms: 1_755_859_300_000,
        signer_id: "aa".repeat(32),
        signature: b64url_encode(&high_s),
    };

    assert_eq!(
        cp.verify(&[0x04; 65], &RustCryptoBackend).unwrap_err(),
        AuditError::CheckpointNotLowS
    );
}

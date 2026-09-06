//! Conformance against `spec/vectors/`.
//!
//! These are the tests a port to Go or TypeScript has to pass. They read the
//! committed vector files rather than recomputing anything, so if this crate and
//! the files ever drift, this fails — which is the point. The files are the
//! contract; the crate is one implementation of it.
//!
//! Regenerate with `cargo run -p countersign-verify --example gen-vectors`.

use std::path::PathBuf;

use countersign_verify::encoding::hex_decode;
use countersign_verify::{
    canonicalize_str, verify_bundle, verify_for_execution, ApprovalEnvelope, EnrolledDevice,
    Execution, JcsError, MemoryCounters, Registry, RustCryptoBackend, VerifyError, VerifyPolicy,
};
use serde_json::Value;

fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors")
}

fn load(name: &str) -> Value {
    let path = vectors_dir().join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).expect("vector file is valid JSON")
}

#[test]
fn canonicalization_accept_vectors_match_byte_for_byte() {
    let doc = load("canonicalization.json");
    let cases = doc["accept"].as_array().expect("accept cases");
    assert!(!cases.is_empty(), "vector file must not be empty");

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let input = case["input"].as_str().unwrap();
        let expected = case["canonical"].as_str().unwrap();

        let got = canonicalize_str(input)
            .unwrap_or_else(|e| panic!("{name}: expected to canonicalize, got {e}"));
        assert_eq!(got, expected, "{name}: canonical form differs");

        // And the digest the rest of the protocol hangs off.
        let expected_digest = case["digest_sha256"].as_str().unwrap();
        let got_digest = countersign_verify::digest_of_json(input).unwrap();
        assert_eq!(got_digest, expected_digest, "{name}: digest differs");
    }
}

#[test]
fn each_reject_vector_fails_with_the_right_error() {
    // A port that silently accepts these produces digests nobody else can
    // reproduce, which presents as a valid approval failing to verify.
    let doc = load("canonicalization.json");
    let cases = doc["reject"].as_array().expect("reject cases");
    assert!(!cases.is_empty(), "vector file must not be empty");

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let input = case["input"].as_str().unwrap();
        let reason = case["reason"].as_str().unwrap();

        match (canonicalize_str(input), reason) {
            (Err(JcsError::UnsupportedNumber(_)), "unsupported_number") => {}
            (Err(JcsError::DuplicateKey(_)), "duplicate_key") => {}
            (other, _) => panic!("{name}: expected {reason}, got {other:?}"),
        }
    }
}

fn test_key_registry() -> (Registry, String) {
    let key = load("test-key.json");
    let public = hex_decode(key["public_key_sec1_uncompressed_hex"].as_str().unwrap()).unwrap();
    let device = EnrolledDevice::test_key(public).with_label("published test key");
    let id = device.device_id.clone();

    // The id in the file must be the id derived from the key, or the file is
    // describing a device that does not exist.
    assert_eq!(
        id,
        key["device_id"].as_str().unwrap(),
        "device_id must be derived from the key"
    );

    let mut registry = Registry::new();
    registry.enroll(device);
    (registry, id)
}

fn approval_envelope() -> ApprovalEnvelope {
    serde_json::from_value(load("approval.json")["envelope"].clone()).expect("envelope parses")
}

#[test]
fn the_signed_approval_vector_verifies_with_the_published_test_key() {
    let (registry, _) = test_key_registry();
    let envelope = approval_envelope();

    let permissive = VerifyPolicy {
        accept_test_keys: true,
        ..Default::default()
    };
    let verified = verify_bundle(
        &envelope,
        &registry,
        &permissive,
        &mut MemoryCounters::new(),
        &RustCryptoBackend,
        None,
    )
    .expect("the committed vector must verify");

    assert_eq!(verified.request_digest, envelope.bundle.request_digest);
    assert_eq!(verified.signers.len(), 1);
}

#[test]
fn the_test_key_is_refused_by_a_default_verifier() {
    // The safety property that makes a software mock acceptable: it is not
    // "disabled", it is cryptographically incapable of a production approval.
    let (registry, id) = test_key_registry();
    let err = verify_bundle(
        &approval_envelope(),
        &registry,
        &VerifyPolicy::default(),
        &mut MemoryCounters::new(),
        &RustCryptoBackend,
        None,
    )
    .unwrap_err();
    assert_eq!(err, VerifyError::TestKeyRejected(id));
}

#[test]
fn a_verifier_that_has_not_enrolled_the_key_refuses_it_outright() {
    let err = verify_bundle(
        &approval_envelope(),
        &Registry::new(),
        &VerifyPolicy {
            accept_test_keys: true,
            ..Default::default()
        },
        &mut MemoryCounters::new(),
        &RustCryptoBackend,
        None,
    )
    .unwrap_err();
    assert!(matches!(err, VerifyError::UnknownDevice(_)), "got {err:?}");
}

#[test]
fn the_vector_binds_to_its_own_statement_and_target() {
    let (registry, _) = test_key_registry();
    let envelope = approval_envelope();
    let request = envelope.request().unwrap();
    let policy = VerifyPolicy {
        accept_test_keys: true,
        ..Default::default()
    };

    // The execution it was approved for.
    assert!(verify_for_execution(
        &envelope,
        &Execution {
            statement: &request.statement,
            uri_fingerprint: &request.target.uri_fingerprint,
            action: Some(&request.action),
        },
        &registry,
        &policy,
        &mut MemoryCounters::new(),
        &RustCryptoBackend,
        None,
    )
    .is_ok());

    // A different table under the same approval.
    let err = verify_for_execution(
        &envelope,
        &Execution {
            statement: "DROP TABLE orders;",
            uri_fingerprint: &request.target.uri_fingerprint,
            action: None,
        },
        &registry,
        &policy,
        &mut MemoryCounters::new(),
        &RustCryptoBackend,
        None,
    )
    .unwrap_err();
    assert_eq!(err, VerifyError::StatementMismatch);
}

#[test]
fn flipping_one_bit_of_the_signature_breaks_it() {
    // Confirms the vector's signature is actually being checked rather than
    // waved through by a backend that returns true.
    let (registry, _) = test_key_registry();
    let mut envelope = approval_envelope();

    let sig = &mut envelope.bundle.signatures[0].signature;
    let mut bytes = countersign_verify::encoding::b64url_decode(sig).unwrap();
    bytes[10] ^= 0x01;
    *sig = countersign_verify::encoding::b64url_encode(&bytes);

    let err = verify_bundle(
        &envelope,
        &registry,
        &VerifyPolicy {
            accept_test_keys: true,
            ..Default::default()
        },
        &mut MemoryCounters::new(),
        &RustCryptoBackend,
        None,
    )
    .unwrap_err();
    assert!(
        matches!(err, VerifyError::BadSignature(_) | VerifyError::HighS(_)),
        "got {err:?}"
    );
}

#[test]
fn the_committed_signing_payload_is_the_one_this_crate_builds() {
    // Pins the exact preimage — domain separator, digest bytes, big-endian
    // counter and timestamp — so a port can compare hex rather than guess at
    // the concatenation order.
    let doc = load("approval.json");
    let envelope = approval_envelope();
    let sig = &envelope.bundle.signatures[0];

    let built = countersign_verify::signing_payload(
        &envelope.bundle.request_digest,
        sig.counter,
        sig.device_unix_ms,
    )
    .unwrap();

    assert_eq!(
        countersign_verify::encoding::hex_encode(&built),
        doc["signing_payload_hex"].as_str().unwrap()
    );
}

#[test]
fn the_committed_digest_covers_the_committed_request_bytes() {
    let envelope = approval_envelope();
    assert_eq!(
        countersign_verify::digest_of_json(&envelope.request_json).unwrap(),
        envelope.bundle.request_digest,
        "the vector's digest must cover its own request text"
    );
}

// ---------------------------------------------------------------------------
// Enrollment — the trust root
// ---------------------------------------------------------------------------

fn authority_public_key() -> Vec<u8> {
    hex_decode(
        load("enrollment.json")["authority"]["public_key_sec1_uncompressed_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap()
}

fn signed_roster() -> countersign_verify::SignedRoster {
    serde_json::from_value(load("enrollment.json")["signed_roster"].clone()).unwrap()
}

#[test]
fn the_roster_vector_verifies_against_the_published_authority_key() {
    let roster = signed_roster()
        .verify(&authority_public_key(), &RustCryptoBackend)
        .expect("the committed roster must verify");
    assert_eq!(roster.records.len(), 1);
    assert_eq!(roster.records[0].operator.subject, "alice@example.com");
}

#[test]
fn a_roster_signed_by_the_wrong_key_is_refused() {
    // A verifier trusts exactly one authority key, configured out of band. The
    // distribution channel is not trusted, so this is the only thing standing
    // between it and an attacker-supplied roster.
    let device_key = hex_decode(
        load("test-key.json")["public_key_sec1_uncompressed_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let err = signed_roster()
        .verify(&device_key, &RustCryptoBackend)
        .unwrap_err();
    assert!(
        matches!(
            err,
            countersign_verify::EnrollmentError::WrongAuthority { .. }
        ),
        "got {err:?}"
    );
}

#[test]
fn tampering_with_a_roster_record_breaks_its_signature() {
    // Promoting yourself into someone else's roster is the obvious attack.
    let mut signed = signed_roster();
    signed.roster_json = signed
        .roster_json
        .replace("alice@example.com", "mallory@example.com");

    let err = signed
        .verify(&authority_public_key(), &RustCryptoBackend)
        .unwrap_err();
    assert_eq!(err, countersign_verify::EnrollmentError::RosterBadSignature);
}

#[test]
fn the_enrollment_proof_shows_the_device_signed_for_its_own_operator() {
    // Proof of possession: without this, enrolling a device needs only its
    // public key, which is not a secret.
    let roster = signed_roster()
        .verify(&authority_public_key(), &RustCryptoBackend)
        .unwrap();
    roster.records[0]
        .verify_proof(&RustCryptoBackend)
        .expect("the committed enrollment proof must verify");
}

#[test]
fn an_enrollment_proof_cannot_be_re_pointed_at_a_different_person() {
    // The statement is fixed text naming the subject, so re-labelling the
    // record without a fresh dial turn fails: the device signed alice's name.
    let roster = signed_roster()
        .verify(&authority_public_key(), &RustCryptoBackend)
        .unwrap();
    let mut record = roster.records[0].clone();
    record.operator = countersign_verify::Operator::new("mallory@example.com");

    let err = record.verify_proof(&RustCryptoBackend).unwrap_err();
    assert!(
        matches!(
            err,
            countersign_verify::EnrollmentError::ProofStatementMismatch { .. }
        ),
        "got {err:?}"
    );
}

#[test]
fn an_enrollment_proof_signed_by_a_different_device_is_refused() {
    let roster = signed_roster()
        .verify(&authority_public_key(), &RustCryptoBackend)
        .unwrap();
    let mut record = roster.records[0].clone();

    // Swap in the approval vector, which is signed by the same key but is not
    // an enrollment — a proof has to be the enrollment ceremony, not any
    // approval the device happens to have produced.
    record.proof = Some(approval_envelope());
    let err = record.verify_proof(&RustCryptoBackend).unwrap_err();
    assert!(
        matches!(
            err,
            countersign_verify::EnrollmentError::ProofWrongAction(_)
        ),
        "got {err:?}"
    );
}

#[test]
fn a_registry_built_from_the_roster_verifies_the_approval_vector_end_to_end() {
    // The whole chain, as a proxy on another host would run it: trust one
    // authority key, load a roster from anywhere, build a registry, verify an
    // approval — and get back a human's name.
    let roster = countersign_verify::accept_roster(
        &signed_roster(),
        &authority_public_key(),
        &RustCryptoBackend,
        &mut countersign_verify::MemoryRosterStore::new(),
    )
    .unwrap();

    let registry = Registry::from_roster(&roster).unwrap();
    let envelope = approval_envelope();
    let request = envelope.request().unwrap();

    let verified = verify_for_execution(
        &envelope,
        &Execution {
            statement: &request.statement,
            uri_fingerprint: &request.target.uri_fingerprint,
            action: Some(&request.action),
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
    .expect("the roster's device should authorize its own approval");

    assert_eq!(verified.operators(), vec!["alice@example.com"]);
}

// ---------------------------------------------------------------------------
// Device classes — spec/device-classes-v1.md
// ---------------------------------------------------------------------------

fn enclave_record() -> countersign_verify::EnrollmentRecord {
    serde_json::from_value(load("device-classes.json")["record"].clone()).expect("record parses")
}

fn enclave_envelope() -> ApprovalEnvelope {
    serde_json::from_value(load("device-classes.json")["approval"]["envelope"].clone())
        .expect("envelope parses")
}

fn enclave_registry() -> Registry {
    let mut registry = Registry::new();
    registry.enroll(EnrolledDevice::from_record(&enclave_record()).expect("the record is consistent"));
    registry
}

#[test]
fn the_enclave_record_is_labelled_enclave_and_carries_its_proof() {
    let record = enclave_record();
    assert_eq!(record.class(), countersign_verify::DeviceClass::Enclave);
    assert!(!record.is_test_key, "an enclave record is not a test key");
    record
        .verify_proof(&RustCryptoBackend)
        .expect("the committed enclave proof must verify");
    // And the file's id is the id derived from the key, or it describes a
    // device that does not exist.
    assert_eq!(
        record.device_id,
        load("device-classes.json")["enclave_key"]["device_id"]
            .as_str()
            .unwrap()
    );
}

#[test]
fn an_enclave_approval_verifies_under_a_default_policy() {
    // The product decision, pinned: a biometric-gated enclave key is a real
    // approval with a smaller claim, and a default verifier accepts it.
    let verified = verify_bundle(
        &enclave_envelope(),
        &enclave_registry(),
        &VerifyPolicy::default(),
        &mut MemoryCounters::new(),
        &RustCryptoBackend,
        None,
    )
    .expect("the committed enclave approval must verify by default");

    assert_eq!(verified.signers.len(), 1);
    assert_eq!(
        verified.signers[0].class,
        countersign_verify::DeviceClass::Enclave,
        "the result must say what kind of thing signed"
    );
    assert_eq!(verified.operators(), vec!["bob@example.com"]);
}

#[test]
fn a_hardware_only_policy_refuses_the_same_approval() {
    // The one-line way back. Nothing else about the verifier changes.
    let err = verify_bundle(
        &enclave_envelope(),
        &enclave_registry(),
        &VerifyPolicy {
            accept_classes: vec![countersign_verify::DeviceClass::Signet],
            ..Default::default()
        },
        &mut MemoryCounters::new(),
        &RustCryptoBackend,
        None,
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            VerifyError::ClassRejected {
                class: countersign_verify::DeviceClass::Enclave,
                ..
            }
        ),
        "got {err:?}"
    );
}

#[test]
fn the_class_comes_from_the_record_and_never_from_the_signature() {
    // The same signature, enrolled under a different class, verifies under a
    // different policy — because nothing in the bundle says what kind of
    // device signed. A signer cannot promote itself.
    let public = enclave_record().public_key().unwrap();
    let mut as_signet = Registry::new();
    as_signet.enroll(EnrolledDevice::new(public.clone()));
    assert!(verify_bundle(
        &enclave_envelope(),
        &as_signet,
        &VerifyPolicy {
            accept_classes: vec![countersign_verify::DeviceClass::Signet],
            ..Default::default()
        },
        &mut MemoryCounters::new(),
        &RustCryptoBackend,
        None,
    )
    .is_ok());

    let mut as_test = Registry::new();
    as_test.enroll(EnrolledDevice::test_key(public));
    let err = verify_bundle(
        &enclave_envelope(),
        &as_test,
        &VerifyPolicy::default(),
        &mut MemoryCounters::new(),
        &RustCryptoBackend,
        None,
    )
    .unwrap_err();
    assert!(matches!(err, VerifyError::TestKeyRejected(_)), "got {err:?}");
}

#[test]
fn a_record_whose_class_and_test_flag_disagree_is_refused_whole() {
    // One of the two fields is lying and a verifier cannot tell which.
    let mut record = enclave_record();
    record.is_test_key = true;

    let err = EnrolledDevice::from_record(&record).unwrap_err();
    assert!(
        matches!(err, countersign_verify::EnrollmentError::ClassMismatch { .. }),
        "got {err:?}"
    );
    let err = record.verify_proof(&RustCryptoBackend).unwrap_err();
    assert!(
        matches!(err, countersign_verify::EnrollmentError::ClassMismatch { .. }),
        "got {err:?}"
    );
}

#[test]
fn an_enclave_record_stripped_of_its_proof_is_refused() {
    // A roster may trim proofs for size — except here. The proof is the only
    // evidence the key signs under a presence check at all.
    let mut record = enclave_record();
    record.proof = None;
    assert_eq!(
        EnrolledDevice::from_record(&record).unwrap_err(),
        countersign_verify::EnrollmentError::EnclaveWithoutProof
    );
}

#[test]
fn a_record_issued_before_classes_existed_keeps_its_meaning() {
    // enrollment.json predates the class field. Its record is a test key and
    // must still read as one, with nothing re-issued.
    let roster = signed_roster()
        .verify(&authority_public_key(), &RustCryptoBackend)
        .unwrap();
    let record = &roster.records[0];
    assert_eq!(record.class, None, "the legacy vector must stay class-less");
    assert_eq!(record.class(), countersign_verify::DeviceClass::Test);
    assert_eq!(
        EnrolledDevice::from_record(record).unwrap().class,
        countersign_verify::DeviceClass::Test
    );
}

#[test]
fn listing_test_in_accept_classes_is_the_same_as_accept_test_keys() {
    let (registry, _) = test_key_registry();
    let policy = VerifyPolicy {
        accept_classes: vec![countersign_verify::DeviceClass::Test],
        ..Default::default()
    };
    assert!(!policy.accept_test_keys, "the flag itself is still off");
    verify_bundle(
        &approval_envelope(),
        &registry,
        &policy,
        &mut MemoryCounters::new(),
        &RustCryptoBackend,
        None,
    )
    .expect("either spelling admits a test key");
}

#[test]
fn the_enclave_signing_payload_is_pinned() {
    let doc = load("device-classes.json");
    let envelope = enclave_envelope();
    let sig = &envelope.bundle.signatures[0];
    let built = countersign_verify::signing_payload(
        &envelope.bundle.request_digest,
        sig.counter,
        sig.device_unix_ms,
    )
    .unwrap();
    assert_eq!(
        countersign_verify::encoding::hex_encode(&built),
        doc["approval"]["signing_payload_hex"].as_str().unwrap()
    );
    assert_eq!(
        countersign_verify::digest_of_json(&envelope.request_json).unwrap(),
        envelope.bundle.request_digest,
        "the vector's digest must cover its own request text"
    );
}

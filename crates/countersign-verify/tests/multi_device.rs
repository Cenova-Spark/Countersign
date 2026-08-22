//! One person, several devices — and what happens when one of them is lost.
//!
//! Real P-256 keys and real signatures throughout, because the question these
//! answer ("can Alice still work after losing her work Signet?") is one where a
//! stubbed backend would prove nothing.

#![cfg(feature = "ecdsa-p256")]

use countersign_verify::encoding::{b64url_encode, hex_encode};
use countersign_verify::{
    canonicalize_str, digest_of_json, enrollment_statement, signing_payload, verify_bundle,
    Acceptance, ApprovalEnvelope, Bundle, Decision, DeviceSignature, DeviceStatus,
    EnrollmentRecord, MemoryCounters, Operator, Registry, Request, Requester, RustCryptoBackend,
    Target, VerifyError, VerifyPolicy, ENROLLMENT_ACTION, VERSION,
};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

/// Sign, normalizing `s` into the low half.
///
/// **Not optional.** RustCrypto emits whichever `s` falls out of the
/// arithmetic, so roughly half its signatures are high-S — and a conforming
/// verifier rejects those (spec §4). Forgetting this produces a signer that
/// works about half the time, which is far worse to debug than one that never
/// works.
fn sign_low_s(key: &SigningKey, msg: &[u8]) -> Signature {
    let sig: Signature = key.sign(msg);
    sig.normalize_s()
}

/// A distinct device key per name. Deterministic so failures are reproducible.
fn device_key(name: &str) -> SigningKey {
    SigningKey::from_slice(&Sha256::digest(
        format!("countersign test device {name}").as_bytes(),
    ))
    .expect("valid P-256 scalar")
}

fn public_of(key: &SigningKey) -> Vec<u8> {
    key.verifying_key().to_sec1_bytes().to_vec()
}

/// Sign a request with a device key, producing an approved envelope.
fn approve(key: &SigningKey, request: &Request, counter: u64, at_ms: u64) -> ApprovalEnvelope {
    let request_json = canonicalize_str(&serde_json::to_string(request).unwrap()).unwrap();
    let digest = digest_of_json(&request_json).unwrap();
    let tbs = signing_payload(&digest, counter, at_ms).unwrap();
    let sig = sign_low_s(key, &tbs);

    ApprovalEnvelope {
        request_json,
        bundle: Bundle {
            v: VERSION,
            decision: Decision::Approved,
            request_digest: digest,
            signatures: vec![DeviceSignature {
                device_id: hex_encode(&Sha256::digest(public_of(key))),
                counter,
                device_unix_ms: at_ms,
                signature: b64url_encode(&sig.to_bytes()),
                dwell_ms: Some(1500),
            }],
        },
    }
}

fn request(action: &str, statement: &str, nonce: &str, fingerprint: &str) -> Request {
    Request {
        v: VERSION,
        nonce: nonce.into(),
        requester: Requester {
            id: "test".into(),
            instance: "t".into(),
            pid: None,
        },
        action: action.into(),
        target: Target {
            kind: if action == ENROLLMENT_ACTION {
                "enrollment"
            } else {
                "database"
            }
            .into(),
            uri_fingerprint: fingerprint.into(),
        },
        statement: statement.into(),
        advisory: None,
        ttl_ms: 60_000,
    }
}

/// Run the enrollment ceremony for real: the device countersigns its own
/// enrollment statement.
fn enrol(name: &str, subject: &str, at_ms: u64) -> (SigningKey, EnrollmentRecord) {
    let key = device_key(name);
    let public = public_of(&key);

    let req = request(
        ENROLLMENT_ACTION,
        &enrollment_statement(subject),
        &format!("nonce-enrol-{name}"),
        &hex_encode(&Sha256::digest(subject.as_bytes())),
    );
    let proof = approve(&key, &req, 1, at_ms);

    let mut record = EnrollmentRecord::new(&public, Operator::new(subject), at_ms);
    record.proof = Some(proof);
    record
        .verify_proof(&RustCryptoBackend)
        .expect("a freshly enrolled device must prove possession");

    (key, record)
}

/// An ordinary approval on a database, for use against a registry.
fn db_approval(key: &SigningKey, counter: u64, at_ms: u64) -> ApprovalEnvelope {
    approve(
        key,
        &request(
            "sql.execute",
            "DELETE FROM orders WHERE id = 1",
            "nonce-db",
            "9f2c",
        ),
        counter,
        at_ms,
    )
}

fn registry_of(records: &[&EnrollmentRecord]) -> Registry {
    let mut r = Registry::new();
    for record in records {
        r.enrol(countersign_verify::EnrolledDevice::from_record(record).unwrap());
    }
    r
}

fn check(envelope: &ApprovalEnvelope, registry: &Registry) -> Result<Vec<String>, VerifyError> {
    verify_bundle(
        envelope,
        registry,
        &VerifyPolicy::default(),
        &mut MemoryCounters::new(),
        &RustCryptoBackend,
        None,
    )
    .map(|v| v.operators().iter().map(|s| s.to_string()).collect())
}

const ALICE: &str = "alice@example.com";
const T_ENROL: u64 = 1_700_000_000_000;
const T_LOST: u64 = 1_800_000_000_000;

#[test]
fn one_person_can_hold_a_work_and_a_home_device_at_once() {
    let (work_key, work) = enrol("alice-work", ALICE, T_ENROL);
    let (home_key, home) = enrol("alice-home", ALICE, T_ENROL);

    // Two records, two device ids, one subject.
    assert_ne!(work.device_id, home.device_id);
    assert_eq!(work.operator.subject, home.operator.subject);

    let registry = registry_of(&[&work, &home]);
    assert_eq!(
        registry.len(),
        2,
        "one subject must not collapse two devices"
    );

    // Either device authorizes, and both resolve to the same person.
    assert_eq!(
        check(&db_approval(&work_key, 10, T_ENROL), &registry).unwrap(),
        vec![ALICE]
    );
    assert_eq!(
        check(&db_approval(&home_key, 10, T_ENROL), &registry).unwrap(),
        vec![ALICE]
    );
}

#[test]
fn losing_one_device_does_not_lock_the_person_out_of_the_others() {
    let (work_key, mut work) = enrol("alice-work", ALICE, T_ENROL);
    let (home_key, home) = enrol("alice-home", ALICE, T_ENROL);

    // The work Signet is lost and revoked. Revocation is per device, not per
    // person — the home device is untouched.
    work.status = DeviceStatus::Revoked {
        at_unix_ms: T_LOST,
        at_counter: None,
        reason: Some("left on a train".into()),
    };

    let registry = registry_of(&[&work, &home]);

    let err = check(&db_approval(&work_key, 11, T_LOST), &registry).unwrap_err();
    assert!(
        matches!(err, VerifyError::DeviceRevoked { .. }),
        "got {err:?}"
    );

    assert_eq!(
        check(&db_approval(&home_key, 11, T_LOST), &registry).unwrap(),
        vec![ALICE],
        "the home device must keep working"
    );
}

#[test]
fn a_replacement_device_works_immediately_and_independently() {
    let (work_key, mut work) = enrol("alice-work", ALICE, T_ENROL);
    let (_home_key, home) = enrol("alice-home", ALICE, T_ENROL);

    work.status = DeviceStatus::Revoked {
        at_unix_ms: T_LOST,
        at_counter: None,
        reason: Some("lost".into()),
    };

    // Alice enrols the replacement under the same subject. Nothing about the
    // revoked record constrains it: a new key means a new device_id, and the
    // ceremony is the ordinary one.
    let (replacement_key, replacement) = enrol("alice-replacement", ALICE, T_LOST + 1);

    assert_ne!(replacement.device_id, work.device_id);
    assert_eq!(replacement.operator.subject, ALICE);
    assert!(replacement.acceptable_now());

    let registry = registry_of(&[&work, &home, &replacement]);
    assert_eq!(registry.len(), 3);

    assert_eq!(
        check(&db_approval(&replacement_key, 1, T_LOST + 2), &registry).unwrap(),
        vec![ALICE],
        "a replacement must work straight away"
    );

    // The lost one stays refused.
    assert!(check(&db_approval(&work_key, 99, T_LOST + 2), &registry).is_err());
}

#[test]
fn a_replacement_reuses_low_counter_values_without_tripping_replay_defence() {
    // A new device starts its counter near zero, well below whatever the lost
    // one had reached. Counters are per device, so this must not look like a
    // regression.
    let (work_key, work) = enrol("alice-work", ALICE, T_ENROL);
    let (replacement_key, replacement) = enrol("alice-replacement", ALICE, T_LOST);
    let registry = registry_of(&[&work, &replacement]);

    let mut counters = MemoryCounters::new();
    let policy = VerifyPolicy::default();

    verify_bundle(
        &db_approval(&work_key, 40_000, T_ENROL),
        &registry,
        &policy,
        &mut counters,
        &RustCryptoBackend,
        None,
    )
    .unwrap();

    verify_bundle(
        &db_approval(&replacement_key, 2, T_LOST),
        &registry,
        &policy,
        &mut counters,
        &RustCryptoBackend,
        None,
    )
    .expect("a fresh device's low counter is not a replay of the old device's high one");
}

#[test]
fn approvals_the_lost_device_gave_before_revocation_still_audit() {
    let (work_key, mut work) = enrol("alice-work", ALICE, T_ENROL);
    let envelope = db_approval(&work_key, 12, T_ENROL);

    work.status = DeviceStatus::Revoked {
        at_unix_ms: T_LOST,
        at_counter: None,
        reason: Some("lost".into()),
    };
    let registry = registry_of(&[&work]);

    let auditing = VerifyPolicy {
        acceptance: Acceptance::AsOf(T_ENROL),
        ..Default::default()
    };
    let verified = verify_bundle(
        &envelope,
        &registry,
        &auditing,
        &mut MemoryCounters::new(),
        &RustCryptoBackend,
        None,
    )
    .expect("history survives revocation");
    assert_eq!(verified.operators(), vec![ALICE]);
}

#[test]
fn two_of_alices_devices_are_still_only_one_person() {
    // The spare must not become a way to satisfy dual control alone.
    let (work_key, work) = enrol("alice-work", ALICE, T_ENROL);
    let (home_key, home) = enrol("alice-home", ALICE, T_ENROL);
    let (bob_key, bob) = enrol("bob", "bob@example.com", T_ENROL);

    let registry = registry_of(&[&work, &home, &bob]);
    let dual = VerifyPolicy {
        required_signatures: 2,
        require_distinct_operators: true,
        ..Default::default()
    };

    // Build one request signed by two devices.
    let req = request("sql.execute", "DROP TABLE users", "nonce-dual", "9f2c");
    let two_of = |a: &SigningKey, b: &SigningKey| {
        let mut env = approve(a, &req, 20, T_ENROL);
        let other = approve(b, &req, 20, T_ENROL);
        env.bundle.signatures.extend(other.bundle.signatures);
        env
    };

    let err = verify_bundle(
        &two_of(&work_key, &home_key),
        &registry,
        &dual,
        &mut MemoryCounters::new(),
        &RustCryptoBackend,
        None,
    )
    .unwrap_err();
    assert_eq!(
        err,
        VerifyError::OperatorThreshold {
            got: 1,
            required: 2
        }
    );

    let verified = verify_bundle(
        &two_of(&work_key, &bob_key),
        &registry,
        &dual,
        &mut MemoryCounters::new(),
        &RustCryptoBackend,
        None,
    )
    .expect("two actual people");
    assert_eq!(verified.signers.len(), 2);
}

#[test]
fn an_enrollment_proof_from_one_device_cannot_stand_in_for_another() {
    // Both of Alice's devices sign the same statement text, so the proof has to
    // be bound to the key, not the words.
    let (_work_key, work) = enrol("alice-work", ALICE, T_ENROL);
    let (_home_key, home) = enrol("alice-home", ALICE, T_ENROL);

    let mut forged = home.clone();
    forged.proof = work.proof.clone();

    let err = forged.verify_proof(&RustCryptoBackend).unwrap_err();
    assert_eq!(
        err,
        countersign_verify::EnrollmentError::ProofNotSelfSigned,
        "a proof signed by a different device must not enrol this one"
    );
}

#[test]
fn every_signature_the_signer_emits_is_low_s() {
    // The regression test for a bug this file found: RustCrypto's signer does
    // not normalize `s`, so roughly half of its raw signatures are high-S and a
    // conforming verifier rejects them.
    //
    // The committed vectors happened to land low-S, which hid it completely. A
    // single signature proves nothing here — the failure is probabilistic, so
    // the test has to be too. Without `sign_low_s`, this fails within a few
    // iterations essentially always.
    let (key, record) = enrol("low-s-property", ALICE, T_ENROL);
    let registry = registry_of(&[&record]);

    for counter in 1..64u64 {
        let envelope = db_approval(&key, counter, T_ENROL + counter);
        check(&envelope, &registry)
            .unwrap_or_else(|e| panic!("signature {counter} was rejected: {e}"));
    }
}

#[test]
fn every_signature_path_refuses_a_high_s_signature() {
    // Three of the four paths originally skipped this check, so the roster
    // vector shipped high-S and verified anyway. One predicate now backs all of
    // them; this pins each one to it.
    use countersign_verify::{is_low_s, Roster, SignedRoster};

    let mut high_s = [0u8; 64];
    high_s[31] = 1; // r = 1
    high_s[32..].fill(0xff); // s far above n/2
    assert!(!is_low_s(&high_s));
    let encoded = b64url_encode(&high_s);

    // Approval bundle.
    let (key, record) = enrol("high-s", ALICE, T_ENROL);
    let mut envelope = db_approval(&key, 5, T_ENROL);
    envelope.bundle.signatures[0].signature = encoded.clone();
    assert!(matches!(
        check(&envelope, &registry_of(&[&record])).unwrap_err(),
        VerifyError::HighS(_)
    ));

    // Enrollment proof.
    let mut forged = record.clone();
    let mut proof = forged.proof.clone().unwrap();
    proof.bundle.signatures[0].signature = encoded.clone();
    forged.proof = Some(proof);
    assert_eq!(
        forged.verify_proof(&RustCryptoBackend).unwrap_err(),
        countersign_verify::EnrollmentError::ProofNotLowS
    );

    // Roster.
    let authority = device_key("high-s-authority");
    let roster = Roster {
        v: VERSION,
        issued_at_unix_ms: T_ENROL,
        serial: 1,
        authority_id: hex_encode(&Sha256::digest(public_of(&authority))),
        records: vec![record],
    };
    let signed = SignedRoster {
        roster_json: serde_json::to_string(&roster).unwrap(),
        signature: encoded,
    };
    assert_eq!(
        signed
            .verify(&public_of(&authority), &RustCryptoBackend)
            .unwrap_err(),
        countersign_verify::EnrollmentError::RosterNotLowS
    );
}

#[test]
fn no_decision_other_than_approved_can_carry_a_signature() {
    // The structural half of "there is no signed denial" (spec §5.2). Even a
    // bundle that carries a perfectly valid signature is refused unless it says
    // `approved`, so a device could not express a countersigned "no" even if
    // some future firmware tried to.
    use countersign_verify::{Bundle, Decision};

    let (key, record) = enrol("no-signed-denial", ALICE, T_ENROL);
    let registry = registry_of(&[&record]);
    let genuine = db_approval(&key, 5, T_ENROL);

    for decision in [
        Decision::Aborted,
        Decision::Expired,
        Decision::Refused,
        Decision::NoDevice,
    ] {
        let envelope = ApprovalEnvelope {
            request_json: genuine.request_json.clone(),
            bundle: Bundle {
                v: VERSION,
                decision,
                request_digest: genuine.bundle.request_digest.clone(),
                // A real, verifiable signature, attached to a refusal.
                signatures: genuine.bundle.signatures.clone(),
            },
        };
        assert_eq!(
            check(&envelope, &registry).unwrap_err(),
            VerifyError::NotApproved(decision),
            "{decision:?} must never verify, signature or not"
        );
    }
}

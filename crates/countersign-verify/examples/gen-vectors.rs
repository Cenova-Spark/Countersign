//! Regenerate `spec/vectors/`.
//!
//! ```text
//! cargo run -p countersign-verify --example gen-vectors
//! ```
//!
//! Everything here is deterministic: the test key is derived from a published
//! string, and ECDSA signing uses RFC 6979 nonces. Running this twice produces
//! byte-identical files, so a diff in `spec/vectors/` means a behaviour change
//! and never noise.

use std::path::PathBuf;

use countersign_verify::encoding::{b64url_encode, hex_encode};
use countersign_verify::{
    canonicalize_str, digest_of_json, enrollment_statement, signing_payload, ApprovalEnvelope,
    Bundle, Decision, DeviceClass, DeviceSignature, EnrollmentRecord, Operator, Request,
    Requester, Roster, SignedRoster, Target, ENROLLMENT_ACTION, VERSION,
};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The string the published test key is derived from.
///
/// Deriving rather than hard-coding a random scalar means anyone can confirm
/// this really is the key in the repository and not some other key that happens
/// to be labelled one.
const TEST_KEY_DERIVATION: &str = "countersign-v1 published test key";

/// The string the published test **enrollment authority** key is derived from.
///
/// A separate key from the device key on purpose: a roster signed by the same
/// key it enrolls would prove nothing about who authorized the enrollment.
const TEST_AUTHORITY_DERIVATION: &str = "countersign-v1 published test enrollment authority";

/// The string the device-class vector's **enclave-labelled** key is derived
/// from.
///
/// A published key is exactly what the `enclave` class forbids, and that is
/// tolerable in a conformance vector and nowhere else: the record carries the
/// label so a port can test the acceptance and refusal paths for the class,
/// and the file's WARNING says never to enroll it anywhere real.
const ENCLAVE_VECTOR_DERIVATION: &str = "countersign-v1 published test key · enclave vector";

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

fn test_signing_key() -> SigningKey {
    let seed = Sha256::digest(TEST_KEY_DERIVATION.as_bytes());
    SigningKey::from_slice(&seed).expect("derived scalar is a valid P-256 key")
}

fn main() -> std::io::Result<()> {
    let out = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors");
    std::fs::create_dir_all(&out)?;

    let signing = test_signing_key();
    let public = signing.verifying_key().to_sec1_bytes().to_vec();
    let device_id = hex_encode(&Sha256::digest(&public));

    // ---- the published test key -------------------------------------------
    let key_doc = json!({
        "WARNING": "The private key below is PUBLIC. Anything it signs is worthless. \
                    Verifiers reject it unless accept_test_keys is explicitly set.",
        "derivation": format!("private scalar = SHA-256({TEST_KEY_DERIVATION:?})"),
        "curve": "P-256",
        "private_key_hex": hex_encode(&signing.to_bytes()),
        "public_key_sec1_uncompressed_hex": hex_encode(&public),
        "device_id": device_id,
    });
    write(&out.join("test-key.json"), &key_doc)?;

    // ---- canonicalization -------------------------------------------------
    // The cases where two implementations plausibly disagree. A port that
    // passes these is a port that will not reject a real approval.
    let cases = [
        ("key ordering", r#"{"b":1,"a":2}"#),
        (
            "nested and array",
            r#"{"z":[1,{"b":true,"a":null}],"y":"x"}"#,
        ),
        ("whitespace is insignificant", "  {\n \"a\" : 1 \n}  "),
        ("solidus is not escaped", r#"{"u":"a/b"}"#),
        (
            "short escapes are preferred",
            r#"{"s":"tab\there\nand\ranewline"}"#,
        ),
        (
            "other controls take lowercase backslash-u",
            r#"{"s":"\u0001"}"#,
        ),
        ("non-ascii travels as utf-8", r#"{"s":"café ☕"}"#),
        (
            "utf-16 key order puts astral planes first",
            "{\"\u{FFFD}\":1,\"\u{10140}\":2}",
        ),
        (
            "safe integer bounds",
            r#"{"hi":9007199254740991,"lo":-9007199254740991}"#,
        ),
        ("empty containers", r#"{"a":{},"b":[]}"#),
    ];

    let vectors: Vec<Value> = cases
        .iter()
        .map(|(name, input)| {
            let canonical = canonicalize_str(input).expect("case must canonicalize");
            json!({
                "name": name,
                "input": input,
                "canonical": canonical,
                "digest_sha256": hex_encode(&Sha256::digest(canonical.as_bytes())),
            })
        })
        .collect();

    // Inputs a conforming implementation must refuse rather than accept.
    let rejects = json!([
        { "name": "non-integer number", "input": r#"{"a":1.5}"#, "reason": "unsupported_number" },
        { "name": "integer above 2^53-1", "input": r#"{"a":9007199254740992}"#, "reason": "unsupported_number" },
        { "name": "duplicate key", "input": r#"{"a":1,"a":2}"#, "reason": "duplicate_key" },
    ]);

    write(
        &out.join("canonicalization.json"),
        &json!({
            "note": "RFC 8785 with the Countersign v1 integer restriction. See spec/countersign-v1.md §3.",
            "accept": vectors,
            "reject": rejects,
        }),
    )?;

    // ---- a signed approval ------------------------------------------------
    let request = Request {
        v: VERSION,
        nonce: "Y291bnRlcnNpZ24tdGVzdC12ZWN0b3Itbm9uY2UtMDE".into(),
        requester: Requester {
            id: "claude-code".into(),
            instance: "vector-session".into(),
            pid: None,
        },
        action: "sql.execute".into(),
        target: Target {
            kind: "database".into(),
            // fingerprint_uri("postgres://user:pass@db.example.com/app")
            uri_fingerprint: countersign_verify::fingerprint_uri(
                "postgres://user:pass@db.example.com/app",
            ),
        },
        statement: "DROP TABLE users;".into(),
        advisory: Some(json!({ "dependents": 3, "reversible": false, "rows_affected": 4200000 })),
        ttl_ms: 60000,
    };

    // The request travels as text, and the digest is over that text — so the
    // vector must pin the exact bytes, not a struct that could re-serialize
    // differently.
    let request_json = canonicalize_str(&serde_json::to_string(&request).unwrap()).unwrap();
    let digest = digest_of_json(&request_json).unwrap();

    let counter = 41235u64;
    let device_unix_ms = 1_755_859_200_123u64;
    let tbs = signing_payload(&digest, counter, device_unix_ms).unwrap();
    let signature = sign_low_s(&signing, &tbs);

    let bundle = Bundle {
        v: VERSION,
        decision: Decision::Approved,
        request_digest: digest.clone(),
        signatures: vec![DeviceSignature {
            device_id: device_id.clone(),
            counter,
            device_unix_ms,
            signature: b64url_encode(&signature.to_bytes()),
            dwell_ms: Some(2140),
        }],
    };

    write(
        &out.join("approval.json"),
        &json!({
            "note": "A complete approved envelope signed by the PUBLISHED TEST KEY. \
                     A conforming verifier accepts it only with accept_test_keys enabled.",
            "signing_payload_hex": hex_encode(&tbs),
            "digest_short": &digest[..12],
            "envelope": { "request_json": request_json, "bundle": bundle },
        }),
    )?;

    // ---- enrollment: a countersigned proof and a signed roster ------------
    //
    // Enrollment reuses the approval path exactly: the device renders
    // "Enroll this device as an approver for …" and a human turns the dial.
    // There is one signing construction in this protocol.
    let subject = "alice@example.com";
    let enroll_request = Request {
        v: VERSION,
        nonce: "Y291bnRlcnNpZ24tdGVzdC12ZWN0b3Itbm9uY2UtMDI".into(),
        requester: Requester {
            id: "countersign-cli".into(),
            // British spelling, kept on purpose: this string is inside the
            // signed request bytes of a committed vector, and changing it
            // would change the digest every port checks against.
            instance: "enrolment".into(),
            pid: None,
        },
        action: ENROLLMENT_ACTION.into(),
        target: Target {
            kind: "enrollment".into(),
            uri_fingerprint: hex_encode(&Sha256::digest(subject.as_bytes())),
        },
        statement: enrollment_statement(subject),
        advisory: None,
        ttl_ms: 120_000,
    };

    let enroll_json = canonicalize_str(&serde_json::to_string(&enroll_request).unwrap()).unwrap();
    let enroll_digest = digest_of_json(&enroll_json).unwrap();
    let enroll_counter = 1u64;
    let enroll_ms = 1_755_000_000_000u64;
    let enroll_tbs = signing_payload(&enroll_digest, enroll_counter, enroll_ms).unwrap();
    let enroll_sig = sign_low_s(&signing, &enroll_tbs);

    let proof = ApprovalEnvelope {
        request_json: enroll_json,
        bundle: Bundle {
            v: VERSION,
            decision: Decision::Approved,
            request_digest: enroll_digest,
            signatures: vec![DeviceSignature {
                device_id: device_id.clone(),
                counter: enroll_counter,
                device_unix_ms: enroll_ms,
                signature: b64url_encode(&enroll_sig.to_bytes()),
                dwell_ms: Some(1980),
            }],
        },
    };

    let mut record = EnrollmentRecord::new(&public, Operator::new(subject), enroll_ms);
    record.is_test_key = true;
    record.proof = Some(proof);

    let authority = SigningKey::from_slice(&Sha256::digest(TEST_AUTHORITY_DERIVATION.as_bytes()))
        .expect("derived scalar is a valid P-256 key");
    let authority_public = authority.verifying_key().to_sec1_bytes().to_vec();
    let authority_id = hex_encode(&Sha256::digest(&authority_public));

    let roster = Roster {
        v: VERSION,
        issued_at_unix_ms: enroll_ms,
        serial: 1,
        authority_id: authority_id.clone(),
        records: vec![record],
    };
    let roster_json = canonicalize_str(&serde_json::to_string(&roster).unwrap()).unwrap();
    let roster_tbs = SignedRoster::signing_payload(&roster_json).unwrap();
    let roster_sig = sign_low_s(&authority, &roster_tbs);
    let signed_roster = SignedRoster {
        roster_json,
        signature: b64url_encode(&roster_sig.to_bytes()),
    };

    write(
        &out.join("enrollment.json"),
        &json!({
            "note": "A countersigned enrollment proof and a roster signed by the PUBLISHED TEST \
                     AUTHORITY key. Both private halves are public; nothing here is trustworthy.",
            "authority": {
                "derivation": format!("private scalar = SHA-256({TEST_AUTHORITY_DERIVATION:?})"),
                "private_key_hex": hex_encode(&authority.to_bytes()),
                "public_key_sec1_uncompressed_hex": hex_encode(&authority_public),
                "authority_id": authority_id,
            },
            "roster_signing_payload_hex": hex_encode(&roster_tbs),
            "signed_roster": signed_roster,
        }),
    )?;

    // ---- device classes: an enclave record and an approval it signed --------
    //
    // A phone or a laptop approving under a biometric check is class
    // `enclave` — a real approval with a smaller claim
    // (spec/device-classes-v1.md). A default verifier accepts it and
    // `accept_classes = ["signet"]` refuses it, and this vector pins both so a
    // port cannot get one right and the other wrong.
    let enclave = SigningKey::from_slice(&Sha256::digest(ENCLAVE_VECTOR_DERIVATION.as_bytes()))
        .expect("derived scalar is a valid P-256 key");
    let enclave_public = enclave.verifying_key().to_sec1_bytes().to_vec();
    let enclave_id = hex_encode(&Sha256::digest(&enclave_public));
    let enclave_subject = "bob@example.com";
    let enclave_enrolled_ms = 1_756_000_000_000u64;

    // The proof is the ordinary ceremony, rendered on the app's own screen.
    // An enclave record without one is refused whole (§4), because the proof
    // is the only evidence the key can sign under a presence check at all.
    let enclave_enroll = Request {
        v: VERSION,
        nonce: "Y291bnRlcnNpZ24tdGVzdC12ZWN0b3Itbm9uY2UtMDM".into(),
        requester: Requester {
            id: "signet-app".into(),
            // British spelling, kept on purpose: this string is inside the
            // signed request bytes of a committed vector, and changing it
            // would change the digest every port checks against.
            instance: "enrolment".into(),
            pid: None,
        },
        action: ENROLLMENT_ACTION.into(),
        target: Target {
            kind: "enrollment".into(),
            uri_fingerprint: hex_encode(&Sha256::digest(enclave_subject.as_bytes())),
        },
        statement: enrollment_statement(enclave_subject),
        advisory: None,
        ttl_ms: 120_000,
    };
    let enclave_enroll_json =
        canonicalize_str(&serde_json::to_string(&enclave_enroll).unwrap()).unwrap();
    let enclave_enroll_digest = digest_of_json(&enclave_enroll_json).unwrap();
    let enclave_enroll_tbs = signing_payload(&enclave_enroll_digest, 1, enclave_enrolled_ms).unwrap();
    let enclave_enroll_sig = sign_low_s(&enclave, &enclave_enroll_tbs);

    let mut enclave_record = EnrollmentRecord::new(
        &enclave_public,
        Operator::new(enclave_subject),
        enclave_enrolled_ms,
    )
    .with_class(DeviceClass::Enclave);
    enclave_record.proof = Some(ApprovalEnvelope {
        request_json: enclave_enroll_json,
        bundle: Bundle {
            v: VERSION,
            decision: Decision::Approved,
            request_digest: enclave_enroll_digest,
            signatures: vec![DeviceSignature {
                device_id: enclave_id.clone(),
                counter: 1,
                device_unix_ms: enclave_enrolled_ms,
                signature: b64url_encode(&enclave_enroll_sig.to_bytes()),
                dwell_ms: Some(2410),
            }],
        },
    });

    let enclave_request = Request {
        v: VERSION,
        nonce: "Y291bnRlcnNpZ24tdGVzdC12ZWN0b3Itbm9uY2UtMDQ".into(),
        requester: Requester {
            id: "claude-code".into(),
            instance: "vector-session-2".into(),
            pid: None,
        },
        action: "sql.dml".into(),
        target: Target {
            kind: "database".into(),
            uri_fingerprint: countersign_verify::fingerprint_uri(
                "postgres://analyst:pw@warehouse.example.com/analytics",
            ),
        },
        statement: "DELETE FROM sessions WHERE expires_at < now();".into(),
        advisory: Some(json!({ "reversible": false, "rows_affected": 18250 })),
        ttl_ms: 60000,
    };
    let enclave_request_json =
        canonicalize_str(&serde_json::to_string(&enclave_request).unwrap()).unwrap();
    let enclave_digest = digest_of_json(&enclave_request_json).unwrap();
    let enclave_counter = 7u64;
    let enclave_ms = 1_756_000_120_000u64;
    let enclave_tbs = signing_payload(&enclave_digest, enclave_counter, enclave_ms).unwrap();
    let enclave_sig = sign_low_s(&enclave, &enclave_tbs);

    let enclave_bundle = Bundle {
        v: VERSION,
        decision: Decision::Approved,
        request_digest: enclave_digest.clone(),
        signatures: vec![DeviceSignature {
            device_id: enclave_id.clone(),
            counter: enclave_counter,
            device_unix_ms: enclave_ms,
            signature: b64url_encode(&enclave_sig.to_bytes()),
            dwell_ms: Some(5120),
        }],
    };

    write(
        &out.join("device-classes.json"),
        &json!({
            "WARNING": "The private key below is PUBLIC, and the record labels it `enclave` anyway — \
                        which is exactly what spec/device-classes-v1.md §2 forbids for a real device. \
                        It is labelled that way so a port can test the class acceptance and refusal \
                        paths. NEVER enroll this key anywhere.",
            "note": "An enrollment record of class `enclave` with its proof, and an approval that key \
                     signed. A default verifier accepts the approval; a verifier with \
                     accept_classes = [\"signet\"] refuses it with class_rejected.",
            "enclave_key": {
                "derivation": format!("private scalar = SHA-256({ENCLAVE_VECTOR_DERIVATION:?})"),
                "curve": "P-256",
                "private_key_hex": hex_encode(&enclave.to_bytes()),
                "public_key_sec1_uncompressed_hex": hex_encode(&enclave_public),
                "device_id": enclave_id,
            },
            "record": enclave_record,
            "approval": {
                "signing_payload_hex": hex_encode(&enclave_tbs),
                "digest_short": &enclave_digest[..12],
                "envelope": { "request_json": enclave_request_json, "bundle": enclave_bundle },
            },
            "expected": {
                "default_policy": "approved",
                "accept_classes_signet_only": "class_rejected",
                "record_with_is_test_key_true": "class_mismatch",
                "record_without_proof": "enclave_without_proof",
            },
        }),
    )?;

    println!("wrote vectors to {}", out.display());
    println!("device_id    {device_id}");
    println!("authority_id {authority_id}");
    println!("enclave_id   {enclave_id}");
    Ok(())
}

fn write(path: &std::path::Path, value: &Value) -> std::io::Result<()> {
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    std::fs::write(path, text)
}

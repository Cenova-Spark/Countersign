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
    Bundle, Decision, DeviceSignature, EnrollmentRecord, Operator, Request, Requester, Roster,
    SignedRoster, Target, ENROLLMENT_ACTION, VERSION,
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
/// key it enrols would prove nothing about who authorized the enrolment.
const TEST_AUTHORITY_DERIVATION: &str = "countersign-v1 published test enrollment authority";

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

    println!("wrote vectors to {}", out.display());
    println!("device_id    {device_id}");
    println!("authority_id {authority_id}");
    Ok(())
}

fn write(path: &std::path::Path, value: &Value) -> std::io::Result<()> {
    let mut text = serde_json::to_string_pretty(value)?;
    text.push('\n');
    std::fs::write(path, text)
}

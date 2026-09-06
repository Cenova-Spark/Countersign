//! A signature the **Swift package** made, verified by the **Rust** verifier.
//!
//! Two implementations of the same crypto — CryptoKit on a Mac, RustCrypto
//! here — have to agree about the key encoding, the signing payload, the
//! `r || s` layout and the low-S rule, and a disagreement in any one of them
//! means every approval from the app fails with no useful error. This runs a
//! real CryptoKit-made signature through the same acceptance path a live
//! approval takes, enrolled as the class the app will enroll under.
//!
//! Regenerate with:
//!
//! ```text
//! cd swift/CountersignKit && swift run countersign-swift-vector \
//!     > ../../crates/countersign-verify/tests/fixtures/swift-approval.json
//! ```

use countersign_verify::encoding::{b64url_decode, hex_decode};
use countersign_verify::{
    digest_of_json, is_low_s, signing_payload, verify_signatures, DeviceClass, DeviceSignature,
    EnrolledDevice, MemoryCounters, Registry, RustCryptoBackend, VerifyError, VerifyPolicy,
};
use serde_json::Value;

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/swift-approval.json")).expect("fixture is valid JSON")
}

fn signature(doc: &Value) -> DeviceSignature {
    let s = &doc["signature"];
    DeviceSignature {
        device_id: s["device_id"].as_str().unwrap().into(),
        counter: s["counter"].as_u64().unwrap(),
        device_unix_ms: s["device_unix_ms"].as_u64().unwrap(),
        signature: s["signature"].as_str().unwrap().into(),
        dwell_ms: s["dwell_ms"].as_u64(),
    }
}

#[test]
fn the_swift_fixture_is_internally_consistent() {
    let doc = fixture();
    let public = hex_decode(doc["public_key_sec1_uncompressed_hex"].as_str().unwrap()).unwrap();
    assert_eq!(public.len(), 65, "SEC1 uncompressed");
    assert_eq!(public[0], 0x04, "CryptoKit's x963Representation must carry the prefix");
    assert_eq!(
        EnrolledDevice::new(public.clone()).device_id,
        doc["device_id"].as_str().unwrap(),
        "device_id must be the digest of the key"
    );
    assert_eq!(
        digest_of_json(doc["request_json"].as_str().unwrap()).unwrap(),
        doc["request_digest"].as_str().unwrap(),
        "the digest must cover the request bytes"
    );
    let sig = signature(&doc);
    let tbs = signing_payload(doc["request_digest"].as_str().unwrap(), sig.counter, sig.device_unix_ms).unwrap();
    assert_eq!(
        countersign_verify::encoding::hex_encode(&tbs),
        doc["signing_payload_hex"].as_str().unwrap(),
        "Swift and Rust must build the same preimage"
    );
}

#[test]
fn a_signature_made_by_cryptokit_verifies_here_as_an_enclave_device() {
    let doc = fixture();
    let public = hex_decode(doc["public_key_sec1_uncompressed_hex"].as_str().unwrap()).unwrap();
    let sig = signature(&doc);

    let raw: [u8; 64] = b64url_decode(&sig.signature).unwrap().try_into().unwrap();
    assert!(is_low_s(&raw), "the Swift signer must normalize s — CryptoKit does not");

    // Enrolled as the app will be: class enclave, accepted by a default
    // verifier. The key is a software key, which the class forbids; this
    // fixture tests the arithmetic, not the enclave.
    let mut registry = Registry::new();
    registry.enroll(EnrolledDevice::enclave(public));

    let verified = verify_signatures(
        doc["request_digest"].as_str().unwrap(),
        std::slice::from_ref(&sig),
        &registry,
        &VerifyPolicy::default(),
        &mut MemoryCounters::new(),
        &RustCryptoBackend,
        None,
    )
    .expect("a default verifier accepts what the Swift package signed");
    assert_eq!(verified.signers[0].class, DeviceClass::Enclave);

    // And the same bytes are refused by a hardware-only policy.
    let err = verify_signatures(
        doc["request_digest"].as_str().unwrap(),
        &[sig],
        &registry,
        &VerifyPolicy {
            accept_classes: vec![DeviceClass::Signet],
            ..Default::default()
        },
        &mut MemoryCounters::new(),
        &RustCryptoBackend,
        None,
    )
    .unwrap_err();
    assert!(matches!(err, VerifyError::ClassRejected { .. }), "got {err:?}");
}

#[test]
fn flipping_one_bit_of_the_swift_signature_breaks_it() {
    let doc = fixture();
    let public = hex_decode(doc["public_key_sec1_uncompressed_hex"].as_str().unwrap()).unwrap();
    let mut sig = signature(&doc);
    let mut raw = b64url_decode(&sig.signature).unwrap();
    raw[5] ^= 0x01;
    sig.signature = countersign_verify::encoding::b64url_encode(&raw);

    let mut registry = Registry::new();
    registry.enroll(EnrolledDevice::enclave(public));
    let err = verify_signatures(
        doc["request_digest"].as_str().unwrap(),
        &[sig],
        &registry,
        &VerifyPolicy::default(),
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

// Conformance against spec/vectors/ — the same files the Rust and TypeScript
// implementations are checked against. If this port ever disagrees about a
// canonical form, a digest, or a signature, it fails here and not on a phone.

import CryptoKit
import Foundation
import Testing
@testable import CountersignKit

let vectors = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    .deletingLastPathComponent().deletingLastPathComponent()
    .appendingPathComponent("spec/vectors")

func load(_ name: String) throws -> JSONValue {
    let text = try String(contentsOf: vectors.appendingPathComponent(name), encoding: .utf8)
    // The vector files themselves contain non-integer content? No — but they
    // contain hex and text only, so the strict parser is fine for them too.
    return try JCS.parse(text)
}

struct Envelope {
    let requestJSON: String
    let requestDigest: String
    let signature: DeviceSignature
    let publicKeySEC1: Data
}

func approvalVector() throws -> Envelope {
    let doc = try load("approval.json")
    let key = try load("test-key.json")
    let env = doc["envelope"]!
    let sig = env["bundle"]!["signatures"]!.arrayValue![0]
    return Envelope(
        requestJSON: env["request_json"]!.stringValue!,
        requestDigest: env["bundle"]!["request_digest"]!.stringValue!,
        signature: DeviceSignature(
            device_id: sig["device_id"]!.stringValue!,
            counter: UInt64(sig["counter"]!.intValue!),
            device_unix_ms: UInt64(sig["device_unix_ms"]!.intValue!),
            signature: sig["signature"]!.stringValue!,
            dwell_ms: sig["dwell_ms"]?.intValue.map(UInt64.init)
        ),
        publicKeySEC1: try Hex.decode(key["public_key_sec1_uncompressed_hex"]!.stringValue!)
    )
}

@Suite("canonicalization vectors")
struct CanonicalizationVectors {
    @Test func acceptVectorsMatchByteForByte() throws {
        let doc = try load("canonicalization.json")
        let cases = doc["accept"]!.arrayValue!
        #expect(!cases.isEmpty)
        for c in cases {
            let name = c["name"]!.stringValue!
            let input = c["input"]!.stringValue!
            let canonical = try JCS.canonicalize(text: input)
            #expect(canonical == c["canonical"]!.stringValue!, "\(name): canonical form differs")
            let digest = Hex.encode(SHA256.hash(data: Data(canonical.utf8)))
            #expect(digest == c["digest_sha256"]!.stringValue!, "\(name): digest differs")
        }
    }

    @Test func rejectVectorsFailForTheStatedReason() throws {
        let doc = try load("canonicalization.json")
        for c in doc["reject"]!.arrayValue! {
            let name = c["name"]!.stringValue!
            let reason = c["reason"]!.stringValue!
            do {
                _ = try JCS.canonicalize(text: c["input"]!.stringValue!)
                Issue.record("\(name): should have been rejected")
            } catch let e as JCSError {
                #expect(e.kind == reason, "\(name): wrong reason \(e)")
            }
        }
    }

    @Test func astralPlaneKeysSortTheWayUTF16Does() throws {
        // Swift's String `<` is not UTF-16 order; the sort is written out.
        // U+FFFD sorts *after* U+10140 by code unit because the latter begins
        // with a surrogate.
        let high = "\u{10140}"
        let bmp = "\u{FFFD}"
        let canonical = try JCS.canonicalize(text: "{\"\(bmp)\":1,\"\(high)\":2}")
        #expect(canonical == "{\"\(high)\":2,\"\(bmp)\":1}")
    }
}

@Suite("the signed approval vector")
struct ApprovalVector {
    @Test func theDigestCoversTheCommittedRequestBytes() throws {
        let v = try approvalVector()
        #expect(try Countersign.requestDigest(json: v.requestJSON) == v.requestDigest)
    }

    @Test func theSigningPayloadIsThePinnedPreimage() throws {
        let doc = try load("approval.json")
        let v = try approvalVector()
        let built = try Countersign.signingPayload(
            requestDigestHex: v.requestDigest, counter: v.signature.counter, deviceUnixMs: v.signature.device_unix_ms)
        #expect(Hex.encode(built) == doc["signing_payload_hex"]!.stringValue!)
        #expect(Countersign.digestShort(v.requestDigest).replacingOccurrences(of: " ", with: "")
            == doc["digest_short"]!.stringValue!)
    }

    @Test func theSignatureVerifiesWithCryptoKit() throws {
        // Two implementations of the same crypto — RustCrypto made this,
        // CryptoKit checks it — agreeing on the key encoding, the payload, the
        // `r || s` layout and low-S.
        let v = try approvalVector()
        let tbs = try Countersign.signingPayload(
            requestDigestHex: v.requestDigest, counter: v.signature.counter, deviceUnixMs: v.signature.device_unix_ms)
        let raw = try Base64URL.decode(v.signature.signature)
        #expect(raw.count == 64)
        #expect(Countersign.isLowS(raw))
        #expect(Countersign.verify(publicKeySEC1: v.publicKeySEC1, message: tbs, signature: raw))

        var flipped = raw
        flipped[10] ^= 0x01
        #expect(!Countersign.verify(publicKeySEC1: v.publicKeySEC1, message: tbs, signature: flipped))
    }

    @Test func theTestKeyDerivesExactlyAsPublished() throws {
        // `x963Representation` must be the SEC1 uncompressed encoding the spec
        // hashes — 0x04 || X || Y — or every device id this package computes
        // matches nothing. This pins it against the committed key.
        let key = try load("test-key.json")
        let signer = try SoftwareSigner(derivedFrom: "countersign-v1 published test key")
        #expect(Hex.encode(signer.publicKeySEC1) == key["public_key_sec1_uncompressed_hex"]!.stringValue!)
        #expect(signer.publicKeySEC1.first == 0x04)
        #expect(signer.deviceID == key["device_id"]!.stringValue!)
    }
}

@Suite("the device-class vector")
struct DeviceClassVector {
    @Test func theEnclaveApprovalVerifiesAndItsRecordSaysEnclave() throws {
        let doc = try load("device-classes.json")
        let record = doc["record"]!
        #expect(record["class"]!.stringValue! == "enclave")
        #expect(record["is_test_key"]!.boolValue! == false)

        let publicKey = try Hex.decode(record["public_key_hex"]!.stringValue!)
        #expect(Countersign.deviceID(publicKeySEC1: publicKey) == record["device_id"]!.stringValue!)

        let approval = doc["approval"]!
        let env = approval["envelope"]!
        let sig = env["bundle"]!["signatures"]!.arrayValue![0]
        let digest = env["bundle"]!["request_digest"]!.stringValue!
        #expect(try Countersign.requestDigest(json: env["request_json"]!.stringValue!) == digest)

        let tbs = try Countersign.signingPayload(
            requestDigestHex: digest,
            counter: UInt64(sig["counter"]!.intValue!),
            deviceUnixMs: UInt64(sig["device_unix_ms"]!.intValue!))
        #expect(Hex.encode(tbs) == approval["signing_payload_hex"]!.stringValue!)
        let raw = try Base64URL.decode(sig["signature"]!.stringValue!)
        #expect(Countersign.verify(publicKeySEC1: publicKey, message: tbs, signature: raw))

        // And the proof — the enrollment ceremony — verifies against the
        // record's own key, over the fixed statement naming the subject.
        let proof = record["proof"]!
        let proofSig = proof["bundle"]!["signatures"]!.arrayValue![0]
        let proofDigest = proof["bundle"]!["request_digest"]!.stringValue!
        let proofRequest = try JCS.parse(proof["request_json"]!.stringValue!)
        #expect(proofRequest["action"]!.stringValue! == "countersign.enroll")
        #expect(proofRequest["statement"]!.stringValue! == "Enroll this device as an approver for bob@example.com")
        let proofTbs = try Countersign.signingPayload(
            requestDigestHex: proofDigest,
            counter: UInt64(proofSig["counter"]!.intValue!),
            deviceUnixMs: UInt64(proofSig["device_unix_ms"]!.intValue!))
        #expect(Countersign.verify(
            publicKeySEC1: publicKey, message: proofTbs, signature: try Base64URL.decode(proofSig["signature"]!.stringValue!)))
    }
}

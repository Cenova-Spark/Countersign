// Emit a signature made by this package for the Rust side to verify.
//
//   swift run countersign-swift-vector > crates/countersign-verify/tests/fixtures/swift-approval.json
//
// The key is derived from a published string, so the fixture names what
// signed it, and — like every other software key in this repository — it is
// worthless as a device. CryptoKit's nonces are randomized, so the signature
// differs run to run; the Rust test verifies whichever one is committed.

import CountersignKit
import Foundation

let derivation = "countersign-v1 published test key · swift vector"
let signer = try SoftwareSigner(derivedFrom: derivation)

// A request shaped like the one the Mac app will see first: Claude Code
// trying to delete a file in a development tree.
let request = """
{"action":"fs.delete","advisory":null,"nonce":"Y291bnRlcnNpZ24tdGVzdC12ZWN0b3Itbm9uY2UtMDU","requester":{"id":"claude-code","instance":"swift-vector"},"statement":"rm demo/scratch.txt","target":{"kind":"filesystem","uri_fingerprint":"87ed968af4720a7e49a047488402d06deff8e929e3a74b93552b06c510bca416"},"ttl_ms":60000,"v":1}
"""
let requestJSON = try JCS.canonicalize(text: request)
let digest = try Countersign.requestDigest(json: requestJSON)

let counters = MemoryCounterStore(2)
let signature = try Countersigner(signer: signer, counters: counters)
    .countersign(requestDigestHex: digest, dwellMs: 5_210, now: 1_757_000_000_000)

let doc: [String: Any] = [
    "WARNING": "The key below is derived from a published string and lives in ordinary memory. It is exactly what the enclave class forbids for a real device; it exists so countersign-verify can check a signature this Swift package produced.",
    "derivation": "private scalar = SHA-256(\"\(derivation)\")",
    "device_id": signer.deviceID,
    "public_key_sec1_uncompressed_hex": Hex.encode(signer.publicKeySEC1),
    "request_json": requestJSON,
    "request_digest": digest,
    "digest_short": Countersign.digestShort(digest),
    "signing_payload_hex": Hex.encode(try Countersign.signingPayload(
        requestDigestHex: digest, counter: signature.counter, deviceUnixMs: signature.device_unix_ms)),
    "signature": [
        "device_id": signature.device_id,
        "counter": signature.counter,
        "device_unix_ms": signature.device_unix_ms,
        "signature": signature.signature,
        "dwell_ms": signature.dwell_ms ?? 0,
    ],
]

let data = try JSONSerialization.data(withJSONObject: doc, options: [.prettyPrinted, .sortedKeys])
FileHandle.standardOutput.write(data)
FileHandle.standardOutput.write(Data("\n".utf8))

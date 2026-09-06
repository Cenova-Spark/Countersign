// The shapes on the control socket, and the one check that makes them safe
// to render.

import Foundation
import Testing
@testable import CountersignKit

let daemonPresent = """
{"presentation":{"render":[{"role":"label","text":"laptop"},{"role":"primary","text":"rm demo/scratch.txt"},{"role":"advisory","text":"deletes one file"},{"role":"digest","text":"a91f 4c2e 7b03"}],"request_digest":"__DIGEST__","request_json":"__REQUEST__","digest_short":"a91f 4c2e 7b03","severity":"high","requester":"claude-code · test (claimed)","requester_changed":true,"ttl_ms":60000},"arm_delay_ms":1200,"hold_ms":2000,"enrollment":false}
"""

let requestBytes = """
{"action":"fs.delete","advisory":null,"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ","requester":{"id":"claude-code","instance":"test"},"statement":"rm demo/scratch.txt","target":{"kind":"filesystem","uri_fingerprint":"87ed968af4720a7e49a047488402d06deff8e929e3a74b93552b06c510bca416"},"ttl_ms":60000,"v":1}
"""

func presentParams(digest: String) throws -> PresentParams {
    let escaped = requestBytes.replacingOccurrences(of: "\"", with: "\\\"")
    let text = daemonPresent
        .replacingOccurrences(of: "__DIGEST__", with: digest)
        .replacingOccurrences(of: "__REQUEST__", with: escaped)
    return try JSONDecoder().decode(PresentParams.self, from: Data(text.utf8))
}

@Suite("presentations")
struct Presentations {
    @Test func aDaemonShapedPresentDecodesAndItsDigestVerifies() throws {
        let digest = try Countersign.requestDigest(json: requestBytes)
        let params = try presentParams(digest: digest)
        #expect(params.arm_delay_ms == 1200)
        #expect(params.hold_ms == 2000)
        #expect(params.enrollment == false)
        #expect(params.presentation.severity == .high)
        #expect(params.presentation.requester_changed)
        #expect(params.presentation.render.count == 4)
        #expect(params.presentation.render[0].role == .label)
        #expect(params.presentation.statement == "rm demo/scratch.txt")
        #expect(params.presentation.action == "fs.delete")
        #expect(!params.presentation.isEnrollment)
        #expect(params.presentation.verifiedDigest())
    }

    @Test func aRewrittenPayloadIsRefusedNotShownWithAWarning() throws {
        // The digest the daemon computed, the bytes something else rewrote.
        let digest = try Countersign.requestDigest(json: requestBytes)
        var params = try presentParams(digest: digest)
        params.presentation.request_json = params.presentation.request_json
            .replacingOccurrences(of: "rm demo/scratch.txt", with: "rm -rf /")
        #expect(!params.presentation.verifiedDigest())

        // And a payload with no bytes at all cannot be verified, so it cannot
        // be rendered either.
        params.presentation.request_json = ""
        #expect(!params.presentation.verifiedDigest())
    }

    @Test func missingFieldsFailTowardMoreFriction() throws {
        // An older daemon, or a relay that dropped fields: severity defaults
        // to critical, requester_changed to true, and the timings follow.
        let text = """
        {"presentation":{"render":[],"request_digest":"\(String(repeating: "ab", count: 32))","digest_short":"abab abab abab","ttl_ms":1000}}
        """
        let params = try JSONDecoder().decode(PresentParams.self, from: Data(text.utf8))
        #expect(params.presentation.severity == .critical)
        #expect(params.presentation.requester_changed)
        #expect(params.arm_delay_ms == 2000)
        #expect(params.hold_ms == 5000)
    }

    @Test func theEnrollmentCeremonyIsRecognisedFromTheBytes() throws {
        let ceremony = """
        {"action":"countersign.enroll","advisory":null,"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ","requester":{"id":"signetd enroll","instance":""},"statement":"Enroll this device as an approver for alice@example.com","target":{"kind":"enrollment","uri_fingerprint":"\(String(repeating: "00", count: 32))"},"ttl_ms":120000,"v":1}
        """
        let p = Presentation(
            render: [], request_digest: try Countersign.requestDigest(json: ceremony), request_json: ceremony,
            digest_short: "", severity: .critical, requester: "", requester_changed: true, ttl_ms: 120_000)
        #expect(p.isEnrollment)
        #expect(p.verifiedDigest())
    }

    @Test func outcomesSerializeInTheShapeTheDaemonReads() throws {
        let sig = DeviceSignature(device_id: "aa", counter: 3, device_unix_ms: 4, signature: "sig", dwell_ms: 5120)
        let approved = PresentOutcome.approved(sig).resultJSON
        #expect(approved["outcome"] as? String == "approved")
        let inner = approved["signature"] as! [String: Any]
        #expect(inner["counter"] as? UInt64 == 3)
        #expect(inner["dwell_ms"] as? UInt64 == 5120)
        #expect(PresentOutcome.aborted.resultJSON["outcome"] as? String == "aborted")
        #expect(PresentOutcome.expired.resultJSON["signature"] == nil)
        // The daemon's decoder: what JSONSerialization emits must parse.
        _ = try JSONSerialization.data(withJSONObject: approved)
    }

    @Test func anAttachRequestClaimsEnclaveAndDerivesItsOwnId() {
        let signer = SoftwareSigner()
        let attach = AttachRequest(signer: signer, name: "Fake Mac")
        #expect(attach.class == "enclave")
        #expect(attach.device_id == Countersign.deviceID(publicKeySEC1: signer.publicKeySEC1))
        #expect(attach.public_key_hex.hasPrefix("04"))
        #expect(attach.public_key_hex.count == 130)
    }
}

// The approval flow from the socket to the signature, with a fake daemon and
// the test signer. The window is the only thing not here.

import CountersignKit
import Foundation
import SignetCore
import Testing

let requestJSON = """
{"action":"fs.delete","advisory":null,"nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQ","requester":{"id":"claude-code","instance":"t"},"statement":"rm demo/scratch.txt","target":{"kind":"filesystem","uri_fingerprint":"87ed968af4720a7e49a047488402d06deff8e929e3a74b93552b06c510bca416"},"ttl_ms":60000,"v":1}
"""

func presentParams(digest: String, requestJSON json: String = requestJSON, requesterChanged: Bool = true, ttl: Int = 60_000) -> [String: Any] {
    [
        "presentation": [
            "render": [["role": "label", "text": "laptop"], ["role": "primary", "text": "rm demo/scratch.txt"], ["role": "digest", "text": "x"]],
            "request_digest": digest,
            "request_json": json,
            "digest_short": Countersign.digestShort(digest),
            "severity": "high",
            "requester": "claude-code · t (claimed)",
            "requester_changed": requesterChanged,
            "ttl_ms": ttl,
        ],
        "arm_delay_ms": 1200,
        "hold_ms": 2000,
        "enrollment": false,
    ]
}

/// A controller that never starts anything: the fake daemon is already up.
func joiningController(path: String) -> DaemonController {
    DaemonController(binary: nil, socketPath: path)
}

@MainActor
func session(daemon: FakeDaemon, signer: SoftwareSigner) async -> AppSession {
    let s = AppSession(signer: signer, counters: MemoryCounterStore(), deviceName: "Test Mac", controller: joiningController(path: daemon.path))
    await s.start()
    return s
}

@Suite("the session")
struct SessionTests {
    @Test @MainActor func attachesWithItsOwnKeyAsAnEnclaveDevice() async throws {
        let daemon = try FakeDaemon()
        defer { daemon.close() }
        let signer = SoftwareSigner()
        let s = await session(daemon: daemon, signer: signer)

        #expect(s.daemonState == .external)
        #expect(s.attachment?.deviceID == signer.deviceID)
        #expect(s.attachment?.enrolled == false)
        let attach = daemon.attachRequest!
        #expect(attach["class"] as? String == "enclave")
        #expect(attach["public_key_hex"] as? String == Hex.encode(signer.publicKeySEC1))
        #expect(attach["name"] as? String == "Test Mac")
        // And the control connection worked: status and audit came back.
        #expect(s.status?.kind == "app")
        #expect(s.audit?.entries == 3)
    }

    @Test @MainActor func aPresentationIsShownAcknowledgedHeldAndSigned() async throws {
        let daemon = try FakeDaemon()
        defer { daemon.close() }
        let signer = SoftwareSigner()
        let s = await session(daemon: daemon, signer: signer)

        let digest = try Countersign.requestDigest(json: requestJSON)
        daemon.present(id: 7, params: presentParams(digest: digest))
        try await waitUntil { s.pending != nil }

        let pending = s.pending!
        #expect(pending.id == 7)
        #expect(pending.digestVerified)
        #expect(pending.phase == .reading)
        #expect(!pending.acknowledged, "the requester changed, so an acknowledgement is required first")
        #expect(!pending.canHold)

        // Read, acknowledge, hold — on a clock we drive, in frame-sized steps,
        // because a single 2-second jump is exactly what the machine treats
        // as a backgrounded app and discards.
        var now: Double = 0
        func advance(_ ms: Double) {
            let target = now + ms
            while now < target {
                now = min(target, now + 16)
                pending.hold.tick(now: now)
            }
        }
        s.rendered(now: now)
        s.acknowledge()
        #expect(pending.canHold)
        advance(1300)
        #expect(pending.hold.phase == .armed)
        pending.hold.press(now: now)
        advance(2100)
        #expect(pending.hold.phase == .committed)

        await s.commit(dwellMs: 2100)
        guard case .signed(let sig) = pending.phase else { Issue.record("not signed: \(pending.phase)"); return }
        #expect(sig.device_id == signer.deviceID)
        #expect(sig.counter == 1)
        #expect(sig.dwell_ms == 2100)

        // What the daemon received is the approval, in its shape, and it
        // verifies against the key that attached.
        let response = await daemon.awaitResponse()!
        #expect(response["id"] as? Int == 7)
        let result = response["result"] as! [String: Any]
        #expect(result["outcome"] as? String == "approved")
        let signature = result["signature"] as! [String: Any]
        let tbs = try Countersign.signingPayload(
            requestDigestHex: digest,
            counter: UInt64(signature["counter"] as! Int),
            deviceUnixMs: UInt64(signature["device_unix_ms"] as! Int))
        let raw = try Base64URL.decode(signature["signature"] as! String)
        #expect(Countersign.isLowS(raw))
        #expect(Countersign.verify(publicKeySEC1: signer.publicKeySEC1, message: tbs, signature: raw))
    }

    @Test @MainActor func aRewrittenPayloadIsRefusedAndCannotBeHeld() async throws {
        let daemon = try FakeDaemon()
        defer { daemon.close() }
        let s = await session(daemon: daemon, signer: SoftwareSigner())

        let digest = try Countersign.requestDigest(json: requestJSON)
        let rewritten = requestJSON.replacingOccurrences(of: "rm demo/scratch.txt", with: "rm -rf /")
        daemon.present(id: 8, params: presentParams(digest: digest, requestJSON: rewritten))
        try await waitUntil { s.pending != nil }

        let pending = s.pending!
        #expect(!pending.digestVerified)
        #expect(pending.phase == .refused)
        s.acknowledge()
        #expect(!pending.canHold)
        await s.commit(dwellMs: 9000)
        #expect(pending.phase == .refused, "nothing here can be approved")

        s.decline()
        let response = await daemon.awaitResponse()!
        #expect((response["result"] as! [String: Any])["outcome"] as? String == "aborted")
    }

    @Test @MainActor func decliningAndExpiringAreOrdinarySoftwareAndSignNothing() async throws {
        let daemon = try FakeDaemon()
        defer { daemon.close() }
        let s = await session(daemon: daemon, signer: SoftwareSigner())
        let digest = try Countersign.requestDigest(json: requestJSON)

        daemon.present(id: 9, params: presentParams(digest: digest))
        try await waitUntil { s.pending != nil }
        s.decline()
        #expect(s.pending?.phase == .declined)
        var response = await daemon.awaitResponse()!
        #expect((response["result"] as! [String: Any])["outcome"] as? String == "aborted")
        s.dismiss()
        #expect(s.pending == nil)

        daemon.present(id: 10, params: presentParams(digest: digest, ttl: 1))
        try await waitUntil { s.pending != nil }
        s.expire()
        #expect(s.pending?.phase == .expired)
        response = await daemon.awaitResponse()!
        #expect((response["result"] as! [String: Any])["outcome"] as? String == "expired")
    }

    @Test @MainActor func aWithdrawnPresentationTakesTheScreenDown() async throws {
        let daemon = try FakeDaemon()
        defer { daemon.close() }
        let s = await session(daemon: daemon, signer: SoftwareSigner())
        let digest = try Countersign.requestDigest(json: requestJSON)
        daemon.present(id: 11, params: presentParams(digest: digest))
        try await waitUntil { s.pending != nil }
        daemon.withdraw(digest: digest)
        try await waitUntil { s.pending?.phase == .withdrawn }
        #expect(s.pending?.hold.phase == .idle)
    }

    @Test @MainActor func theWindowIsToldAfterPendingIsSetNotBefore() async throws {
        let daemon = try FakeDaemon()
        defer { daemon.close() }
        let s = await session(daemon: daemon, signer: SoftwareSigner())
        let digest = try Countersign.requestDigest(json: requestJSON)

        // The app builds a view from this callback, and that view reads
        // `session.pending` back. A `$pending` sink fires before the store
        // and a window opened from one showed "Nothing pending"; the callback
        // the window hangs off must see the value already in place.
        var seen: [Bool] = []
        s.onPendingChange = { pending in seen.append(pending === s.pending) }
        daemon.present(id: 14, params: presentParams(digest: digest))
        try await waitUntil { s.pending != nil }
        #expect(seen == [true])

        s.decline()
        _ = await daemon.awaitResponse()
        s.dismiss()
        #expect(s.pending == nil)
        #expect(seen == [true, true], "and the window is told when there is nothing to show")
    }

    @Test @MainActor func aSecondPresentationWhileOneShowsIsAnsweredAbortedNotStacked() async throws {
        let daemon = try FakeDaemon()
        defer { daemon.close() }
        let s = await session(daemon: daemon, signer: SoftwareSigner())
        let digest = try Countersign.requestDigest(json: requestJSON)
        daemon.present(id: 12, params: presentParams(digest: digest))
        try await waitUntil { s.pending != nil }
        daemon.present(id: 13, params: presentParams(digest: digest))
        let response = await daemon.awaitResponse()!
        #expect(response["id"] as? Int == 13)
        #expect((response["result"] as! [String: Any])["outcome"] as? String == "aborted")
        #expect(s.pending?.id == 12, "the human keeps reading what they were reading")
    }
}

@Suite("the packs state file")
struct PacksParsing {
    @Test func readsWhatSignetdPackWrites() {
        let text = """
        # Written by `signetd pack`. Installed plugins and whether each is on.

        [[pack]]
        name = "countersign-db"
        enabled = true

        [[pack]]
        name = "countersign-tf"
        enabled = false
        """
        let parsed = InstalledPlugin.parsePacksToml(text)
        #expect(parsed.count == 2)
        #expect(parsed[0].name == "countersign-db" && parsed[0].enabled)
        #expect(parsed[1].name == "countersign-tf" && !parsed[1].enabled)
    }
}

@Suite("paths")
struct PathsMirrorTheDaemon {
    @Test func theSocketFollowsTheSameRules() {
        // Whatever the environment, the socket is under the runtime dir and
        // named like the daemon names it.
        #expect(Paths.socketPath.hasSuffix("countersign.sock") || ProcessInfo.processInfo.environment["COUNTERSIGN_SOCK"] != nil)
        #expect(Paths.rosterPath.lastPathComponent == "roster.json")
        #expect(Paths.packsDir.lastPathComponent == "packs" || ProcessInfo.processInfo.environment["COUNTERSIGN_PACKS_DIR"] != nil)
    }
}

/// Poll the main actor until `condition` holds, or fail after a second.
@MainActor
func waitUntil(_ condition: @MainActor () -> Bool) async throws {
    for _ in 0..<200 {
        if condition() { return }
        try await Task.sleep(nanoseconds: 5_000_000)
    }
    Issue.record("condition not met in time")
}

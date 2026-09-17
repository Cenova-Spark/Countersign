// The rules the shared screen enforces before a dial can turn.
//
// These live in `SignetUI` rather than in either app because they are the same
// on both, and a phone that got any of them wrong would be a second, weaker
// implementation of the one surface the design rests on.

import CountersignKit
import Testing

@testable import SignetUI

@Suite("the approval a person is looking at")
struct PendingApprovalTests {
    /// A request whose `request_json` really does digest to `request_digest`.
    private static func params(
        statement: String = "DROP TABLE users",
        requesterChanged: Bool = false,
        enrollment: Bool = false,
        ttlMs: UInt64 = 60_000,
        digestMatches: Bool = true
    ) throws -> PresentParams {
        let json = #"{"action":"sql.ddl","statement":"\#(statement)"}"#
        let digest =
            digestMatches
            ? try Countersign.requestDigest(json: json)
            // A digest over different bytes: what a rewrite in transit looks
            // like from this side.
            : try Countersign.requestDigest(json: #"{"action":"sql.ddl","statement":"SELECT 1"}"#)

        return PresentParams(
            presentation: Presentation(
                render: [RenderLine(role: .primary, text: statement)],
                request_digest: digest,
                request_json: json,
                digest_short: String(digest.prefix(12)),
                severity: .critical,
                requester: "claude-code (claimed)",
                requester_changed: requesterChanged,
                ttl_ms: ttlMs
            ),
            arm_delay_ms: 2_000,
            hold_ms: 5_000,
            enrollment: enrollment
        )
    }

    @Test("a changed requester locks the dial until it is acknowledged")
    func theDialIsLockedUntilARequesterChangeIsAcknowledged() throws {
        // Wire spec §6.3.2. The screen may render; the hold may not commit.
        let pending = PendingApproval(id: 1, params: try Self.params(requesterChanged: true))

        #expect(!(pending.acknowledged))
        #expect(!(pending.canHold), "a changed requester must be acknowledged first")

        pending.acknowledged = true
        #expect(pending.canHold)
    }

    @Test("an unchanged requester is not interrupted")
    func anUnchangedRequesterNeedsNoAcknowledgement() throws {
        // Asking every time would drain the acknowledgement of the information
        // it exists to carry.
        let pending = PendingApproval(id: 1, params: try Self.params(requesterChanged: false))
        #expect(pending.acknowledged)
        #expect(pending.canHold)
    }

    @Test("bytes that disagree with their digest can never be approved")
    func bytesThatDisagreeWithTheirDigestCanNeverBeApproved() throws {
        // The screen renders from the bytes that will be signed. If something
        // between the daemon and here rewrote them, there is nothing safe to
        // show and nothing safe to sign.
        let pending = PendingApproval(id: 1, params: try Self.params(digestMatches: false))

        #expect(!(pending.digestVerified))
        #expect(pending.phase == .refused)
        #expect(!(pending.canHold))

        // And acknowledging must not rescue it.
        pending.acknowledged = true
        #expect(!(pending.canHold))
    }

    @Test("only a request still being read can be held")
    func onlyAReadableRequestCanBeHeld() throws {
        let pending = PendingApproval(id: 1, params: try Self.params())
        #expect(pending.canHold)

        // Once answered, the dial is done: a second hold on a signed request
        // would be a second signature over one approval.
        for phase: PendingApproval.Phase in [.signing, .declined, .expired, .withdrawn] {
            pending.phase = phase
            #expect(!(pending.canHold), "\(phase) must not be holdable")
        }
    }

    @Test("the clock runs from arrival and floors at zero")
    func theClockRunsFromArrivalAndFloorsAtZero() throws {
        let pending = PendingApproval(id: 1, params: try Self.params(ttlMs: 60_000))
        #expect(pending.secondsLeft > 55)
        #expect(pending.secondsLeft <= 60)

        let done = PendingApproval(id: 2, params: try Self.params(ttlMs: 0))
        #expect(done.secondsLeft == 0, "never negative")
    }

    @Test("the hold machine takes its timings from the request")
    func theHoldMachineTakesItsTimingsFromTheRequest() throws {
        // The daemon scales the arm delay and the hold by severity, and the
        // screen must not second-guess it.
        let pending = PendingApproval(id: 1, params: try Self.params())
        #expect(pending.hold.armDelayMs == 2_000)
        #expect(pending.hold.holdMs == 5_000)
    }

    @Test("an enrollment is still subject to the digest check")
    func anEnrollmentIsStillSubjectToTheDigestCheck() throws {
        // The ceremony is an ordinary approval in every way that matters.
        let good = PendingApproval(id: 1, params: try Self.params(enrollment: true))
        #expect(good.canHold)

        let bad = PendingApproval(
            id: 2, params: try Self.params(enrollment: true, digestMatches: false))
        #expect(bad.phase == .refused)
    }
}

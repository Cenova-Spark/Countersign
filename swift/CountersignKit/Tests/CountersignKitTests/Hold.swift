// The three rules of §6.2.3 and §6.3.4, on a clock we control — a port of
// web/test/hold.test.js, including the one that is easy to miss: a
// backgrounded app must discard an accumulated hold, because
// `now - holdStartedAt` would otherwise come back from a thirty-second sleep
// already satisfied and approve on wake.

import Foundation
import Testing
@testable import CountersignKit

/// A clock and a frame loop that only move when told to.
final class Harness {
    var clock: Double = 0
    let hold: HoldMachine
    var committed: Double?

    init(armDelayMs: Double = 2000, holdMs: Double = 5000) {
        hold = HoldMachine(armDelayMs: armDelayMs, holdMs: holdMs)
        hold.onCommit = { [unowned self] dwell in self.committed = dwell }
    }

    /// Advance in frame-sized steps, ticking each time.
    func advance(_ ms: Double, step: Double = 16) {
        let target = clock + ms
        while clock < target {
            clock = min(target, clock + step)
            hold.tick(now: clock)
        }
    }

    /// Jump the clock without frames — a screen that slept — then one tick.
    func freeze(_ ms: Double) {
        clock += ms
        hold.tick(now: clock)
    }
}

@Suite("the hold")
struct Hold {
    @Test func aPressBeforeTheArmDelayDoesNothingAtAll() {
        let h = Harness()
        h.hold.armFrom(now: h.clock)
        h.advance(500)
        #expect(h.hold.phase == .arming)

        // Not "starts a shorter hold" — nothing.
        h.hold.press(now: h.clock)
        h.advance(1000)
        #expect(h.hold.phase == .arming)
        #expect(h.hold.holdProgress == 0)
        #expect(h.committed == nil)
    }

    @Test func aFullHoldAfterTheArmDelayCommitsAndOnlyThen() {
        let h = Harness()
        h.hold.armFrom(now: h.clock)
        h.advance(2100)
        #expect(h.hold.phase == .armed)

        h.hold.press(now: h.clock)
        h.advance(4800)
        #expect(h.hold.phase == .holding, "not yet — 5 s means 5 s")
        #expect(h.committed == nil)
        #expect(h.hold.holdProgress > 0.9)

        h.advance(300)
        #expect(h.hold.phase == .committed)
        #expect((h.committed ?? 0) >= 5000)
    }

    @Test func lettingGoEarlyGivesTheWholeHoldBack() {
        let h = Harness()
        h.hold.armFrom(now: h.clock)
        h.advance(2100)

        h.hold.press(now: h.clock)
        h.advance(4000)
        #expect(h.hold.holdProgress > 0.75)

        h.hold.release(now: h.clock)
        h.advance(400)
        // Discarded. Not paused, not banked.
        #expect(h.hold.holdProgress == 0)

        h.hold.press(now: h.clock)
        h.advance(4000)
        #expect(h.committed == nil, "a second 4 s hold must not finish the first one")
    }

    @Test func aThumbAlreadyDownWhenThePayloadRendersMustLiftFirst() {
        let h = Harness()
        // Engaged before the payload exists — the ordinary case: the previous
        // request just committed and the hand has not come back yet.
        h.hold.press(now: h.clock)
        h.hold.armFrom(now: h.clock)

        h.advance(2500)
        // The arm delay has passed, but the control has not been at rest
        // since the payload appeared. This is what the arm delay alone does
        // not catch, and why §6.2.3 states it separately.
        #expect(h.hold.phase == .rest)

        h.hold.press(now: h.clock)
        h.advance(6000)
        #expect(h.committed == nil, "a hold that began before the payload cannot approve it")

        h.hold.release(now: h.clock)
        h.advance(50)
        #expect(h.hold.phase == .armed)

        h.hold.press(now: h.clock)
        h.advance(5100)
        #expect(h.committed != nil, "a fresh press from rest approves normally")
    }

    @Test func aBackgroundedAppDiscardsTheHoldInsteadOfBankingIt() {
        let h = Harness()
        h.hold.armFrom(now: h.clock)
        h.advance(2100)

        h.hold.press(now: h.clock)
        h.advance(1000)
        #expect(h.hold.holdProgress > 0.15)

        // The screen slept for half a minute.
        h.freeze(30_000)
        #expect(h.hold.holdProgress == 0)
        #expect(h.committed == nil, "waking up must not approve anything")

        // And rest has to be re-established.
        h.advance(100)
        #expect(h.hold.phase == .rest)
    }

    @Test func anExplicitBackgroundEventLapsesToo() {
        let h = Harness()
        h.hold.armFrom(now: h.clock)
        h.advance(2100)
        h.hold.press(now: h.clock)
        h.advance(3000)
        h.hold.background()
        h.advance(16)
        #expect(h.hold.holdProgress == 0)
        #expect(h.hold.phase == .armed, "the finger came off with the app, so rest is re-established")
    }

    @Test func aNewPayloadRestartsTheArmDelay() {
        let h = Harness()
        h.hold.armFrom(now: h.clock)
        h.advance(1900)

        // Another request arrives 100 ms before this one was approvable.
        h.hold.armFrom(now: h.clock)
        h.advance(1000)
        h.hold.press(now: h.clock)
        h.advance(6000)
        #expect(h.committed == nil, "the new payload gets its own full arm delay")
    }

    @Test func severityScalesTheFriction() {
        let low = Harness(armDelayMs: Severity.low.armDelayMs, holdMs: Severity.low.holdMs)
        low.hold.armFrom(now: low.clock)
        low.advance(500)
        low.hold.press(now: low.clock)
        low.advance(350)
        #expect(low.committed != nil, "low severity commits quickly")

        #expect(Severity.critical.armDelayMs == 2000)
        #expect(Severity.critical.holdMs == 5000)
        #expect(Severity.low < Severity.critical)
    }

    @Test func aCommittedHoldIsFinal() {
        let h = Harness(armDelayMs: 400, holdMs: 300)
        h.hold.armFrom(now: h.clock)
        h.advance(500)
        h.hold.press(now: h.clock)
        h.advance(400)
        #expect(h.hold.phase == .committed)
        // Releasing afterwards changes nothing; a second commit never fires.
        let dwell = h.committed
        h.hold.release(now: h.clock)
        h.advance(1000)
        #expect(h.hold.phase == .committed)
        #expect(h.committed == dwell)
    }
}

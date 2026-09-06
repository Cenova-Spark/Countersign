// The approving actuation — a port of web/src/lib/hold.js.
//
// Wire spec §6.2.3 and §6.3.4 name three requirements, and they are three
// because each defends something the others do not:
//
//   Arm delay        elapsed since the payload finished rendering
//                    → you cannot approve what you have not had time to read
//   Rest transition  the actuator was observed at rest *after* that
//                    → you cannot approve with a movement that began before
//                      the payload existed
//   Hold             continuous engagement for the whole duration
//                    → you cannot approve something while reaching for
//                      something else
//
// Implemented here rather than collapsed into one timer, because collapsing
// them is the shortcut the spec spends a section warning about.
//
// On the enclave class the OS presence check is the *commit* of the hold, not
// a replacement for it (device-class spec §3.2): this machine reaches
// `.committed`, then the app asks the enclave to sign, and the enclave runs
// Face ID or Touch ID as part of that call.
//
// The clock is injected. An app drives `tick(now:)` from a display link; the
// tests drive it from a number.

import Foundation

public enum HoldPhase: Equatable {
    /// Nothing is presented.
    case idle
    /// The payload is on screen but has not been readable for long enough.
    case arming
    /// Readable, but a hand was already on the control when it appeared. It
    /// has to lift before anything counts.
    case rest
    /// Readable, and the control has been at rest since. A press starts a hold.
    case armed
    /// Engaged, accumulating toward the required duration.
    case holding
    /// The hold ran its full course. Sign now.
    case committed
}

public final class HoldMachine {
    /// The longest gap between ticks that still counts as continuous
    /// engagement. Generous next to a 60 Hz frame, tight next to a screen
    /// that slept.
    public static let lapseMs: Double = 400

    public private(set) var phase: HoldPhase = .idle
    /// 0…1 toward the required hold.
    public private(set) var holdProgress: Double = 0
    /// 0…1 toward the arm delay.
    public private(set) var armProgress: Double = 0
    /// How long the current hold has been sustained, in ms.
    public private(set) var dwellMs: Double = 0

    public var armDelayMs: Double
    public var holdMs: Double
    /// Called once, when the hold commits, with the dwell in ms.
    public var onCommit: ((Double) -> Void)?

    private var engaged = false
    private var armedAt: Double?
    private var holdStartedAt: Double?
    private var restSeen = false
    private var lastTickAt: Double?

    public init(armDelayMs: Double, holdMs: Double, onCommit: ((Double) -> Void)? = nil) {
        self.armDelayMs = armDelayMs
        self.holdMs = holdMs
        self.onCommit = onCommit
    }

    /// True once the payload has been readable AND the control has been at
    /// rest since — the state in which a press means something.
    public var ready: Bool { phase == .armed || phase == .holding }

    /// Armed, but a hand was already down when the payload appeared.
    public var awaitingRest: Bool { phase == .rest }

    /// Begin the arm delay. Call when the payload has **finished rendering**,
    /// not when it arrived — the gap between those two is precisely the time
    /// the payload was not readable, and measuring from arrival would hand it
    /// back.
    ///
    /// Any new payload restarts everything, including the rest requirement: a
    /// finger already down counts as never having been at rest since.
    public func armFrom(now: Double) {
        armedAt = now
        armProgress = 0
        holdStartedAt = nil
        holdProgress = 0
        dwellMs = 0
        lastTickAt = nil
        restSeen = !engaged
        phase = .arming
        tick(now: now)
    }

    public func disarm() {
        phase = .idle
        armedAt = nil
        holdStartedAt = nil
        holdProgress = 0
        armProgress = 0
        dwellMs = 0
    }

    /// The control was engaged — a finger down, a mouse down.
    ///
    /// Pressing before the payload has been readable, or without having been
    /// at rest since it appeared, does nothing at all. Not "starts a shorter
    /// hold" — nothing. The press is simply not an actuation yet.
    public func press(now: Double) {
        engaged = true
        if phase == .committed || phase == .idle { return }
        guard let armedAt, now - armedAt >= armDelayMs, restSeen else { return }
        holdStartedAt = now
        lastTickAt = now
        phase = .holding
        tick(now: now)
    }

    /// The control was released.
    ///
    /// Lifting is what satisfies the rest requirement: the control has now
    /// been observed at rest *since* the payload appeared. An accumulated hold
    /// is discarded — not paused, not banked (wire spec §6.3.4).
    public func release(now: Double) {
        engaged = false
        restSeen = true
        if phase == .committed { return }
        holdStartedAt = nil
        holdProgress = 0
        dwellMs = 0
        tick(now: now)
    }

    /// The app went to the background, the screen locked, another window took
    /// over. An unambiguous lapse: nobody's finger was verifiably on the
    /// control across it.
    public func background() {
        engaged = false
        lapse()
    }

    /// Advance the machine. Drive this every frame while a payload is shown.
    public func tick(now: Double) {
        if phase == .committed || phase == .idle { return }
        guard let armedAt else { return }

        let armElapsed = now - armedAt
        let armReady = armElapsed >= armDelayMs
        armProgress = min(1, armElapsed / armDelayMs)

        // A gap this long means the app stopped being animated. Whatever the
        // cause, the accumulated hold is discarded rather than credited:
        // `now - holdStartedAt` would otherwise come back from a thirty-second
        // sleep already satisfied and approve on wake.
        let gap = lastTickAt.map { now - $0 } ?? 0
        lastTickAt = now
        if gap > Self.lapseMs, holdStartedAt != nil {
            lapse()
            return
        }

        if let holdStartedAt {
            let held = now - holdStartedAt
            dwellMs = held
            holdProgress = min(1, held / holdMs)
            if holdProgress >= 1 {
                phase = .committed
                onCommit?(held)
                return
            }
            phase = .holding
        } else {
            holdProgress = 0
            phase = armReady ? (restSeen ? .armed : .rest) : .arming
        }
    }

    /// Give back an accumulated hold, exactly as an early release would, and
    /// require rest to be re-established — engagement across the gap cannot
    /// be shown, so rest cannot be assumed either.
    private func lapse() {
        guard holdStartedAt != nil else { return }
        holdStartedAt = nil
        holdProgress = 0
        dwellMs = 0
        restSeen = !engaged
        if phase == .holding { phase = restSeen ? .armed : .rest }
    }
}

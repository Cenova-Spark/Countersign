// The dial. One affordance, one meaning: press and hold, and it turns.
//
// The ring fills with the hold and the index mark turns a full circle with
// it, so the hand and the fill say the same thing and the commit is where the
// hand comes back to twelve. (The device's three detents, `web/src/lib/dial.js`,
// are a physical dial's feel; on a screen a full turn reads.) Letting go gives
// it all back, visibly, because §6.3.4 says an accumulated hold is discarded
// and the dial giving it back is the honest way to show that.

import CountersignKit
import SwiftUI

public struct HoldDial: View {
    let hold: HoldMachine
    let enabled: Bool
    /// Redraw trigger from the frame timer.
    let tick: Date

    public init(hold: HoldMachine, enabled: Bool, tick: Date) {
        self.hold = hold
        self.enabled = enabled
        self.tick = tick
    }

    @State private var pressed = false
    /// One full turn of the hand for one full ring.
    private let commitDegrees: Double = 360

    public var body: some View {
        let progress = hold.holdProgress
        let arm = hold.armProgress
        ZStack {
            Circle().fill(Theme.groundLift)
            Circle().stroke(Theme.hairline, lineWidth: 1)
            // The arm delay, as a faint ring completing.
            Circle()
                .trim(from: 0, to: arm)
                .stroke(Theme.inkFaint.opacity(0.5), style: StrokeStyle(lineWidth: 2, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .padding(3)
            // The hold, in amber.
            Circle()
                .trim(from: 0, to: progress)
                .stroke(Theme.amber, style: StrokeStyle(lineWidth: 4, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .padding(3)
            // The index mark, turning with the ring: a full circle by the commit.
            Capsule()
                .fill(Theme.amber)
                .frame(width: 4, height: 16)
                .offset(y: -30)
                .rotationEffect(.degrees(progress * commitDegrees))
            Text(caption)
                .font(.system(size: 9, weight: .semibold)).tracking(1.5)
                .foregroundColor(enabled ? Theme.inkDim : Theme.inkFaint)
        }
        .frame(width: 96, height: 96)
        .opacity(enabled ? 1 : 0.5)
        .contentShape(Circle())
        .gesture(
            DragGesture(minimumDistance: 0)
                .onChanged { _ in
                    guard enabled, !pressed else { return }
                    pressed = true
                    hold.press(now: nowMs())
                }
                .onEnded { _ in
                    pressed = false
                    hold.release(now: nowMs())
                }
        )
        .animation(.linear(duration: 0.1), value: progress)
        .accessibilityLabel("Hold to countersign")
    }

    private var caption: String {
        switch hold.phase {
        case .holding: return "HOLD"
        case .committed: return "SIGN"
        case .rest: return "LIFT"
        case .arming: return "READ"
        default: return enabled ? "HOLD" : "WAIT"
        }
    }
}

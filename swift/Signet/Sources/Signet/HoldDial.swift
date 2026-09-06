// The dial. One affordance, one meaning: press and hold, and it turns.
//
// Three detents to the commit, as on the device (`COMMIT_DEG = DETENT_DEG *
// 3`, `web/src/lib/dial.js`). The ring fills with the hold; the index mark
// turns with it; letting go gives it all back, visibly, because §6.3.4 says
// an accumulated hold is discarded and the dial giving it back is the honest
// way to show that.

import CountersignKit
import SwiftUI

struct HoldDial: View {
    let hold: HoldMachine
    let enabled: Bool
    /// Redraw trigger from the frame timer.
    let tick: Date

    @State private var pressed = false
    private let commitDegrees: Double = 30

    var body: some View {
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
            // The index mark, turning toward the commit detent.
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

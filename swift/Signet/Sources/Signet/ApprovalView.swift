// One request, three steps: read it, acknowledge it, hold to sign it.
//
// Acknowledging and approving are different controls, because §6.3.3 says
// same-control-different-gesture is the wrong answer for someone who is, by
// premise, not paying full attention. The screen renders from the bytes that
// will be signed, and refuses to render when the bytes and the digest
// disagree.

import CountersignKit
import SignetCore
import SwiftUI

struct ApprovalView: View {
    @EnvironmentObject var session: AppSession

    var body: some View {
        ZStack {
            Theme.ground.ignoresSafeArea()
            if let pending = session.pending {
                PendingView(pending: pending)
                    .environmentObject(session)
            } else {
                Text("Nothing pending").foregroundColor(Theme.inkDim)
            }
        }
        // The floor is what the controls need. The ceiling is the screen: the
        // window opens at the statement's own height up to that, and a longer
        // statement scrolls inside `DeviceScreen` rather than pushing the
        // dial off the bottom.
        .frame(minWidth: 440, maxWidth: .infinity, minHeight: 480, maxHeight: room)
    }

    private var room: CGFloat {
        ((NSScreen.main?.visibleFrame.height) ?? 800) - 24
    }
}

/// A monotonic clock in milliseconds, for the hold machine.
func nowMs() -> Double { ProcessInfo.processInfo.systemUptime * 1000 }

struct PendingView: View {
    @EnvironmentObject var session: AppSession
    @ObservedObject var pending: PendingApproval
    @State private var tick = Date()
    @State private var armed = false
    private let frames = Timer.publish(every: 1.0 / 60.0, on: .main, in: .common).autoconnect()

    var p: Presentation { pending.presentation }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .firstTextBaseline) {
                Text("SIGNET").font(.system(size: 12, weight: .bold)).tracking(4).foregroundColor(Theme.steelLit)
                Spacer()
                Legend(text: pending.params.enrollment ? "enrollment" : "approval requested")
            }
            .padding(.top, 28)

            // Sized before its siblings, so when the window is short it is the
            // statement that gives, by scrolling, and never the controls.
            DeviceScreen(presentation: p, enrollment: pending.params.enrollment)
                .layoutPriority(1)

            if !pending.digestVerified {
                Notice(
                    title: "Refusing to show this.",
                    message: "The payload does not match the digest it arrived with, which means something between the daemon and this screen rewrote it. Nothing here can be approved.")
            } else {
                switch pending.phase {
                case .reading, .signing:
                    readingControls
                case .signed:
                    Verdict(title: "Countersigned", message: "The daemon has the signature and has verified it against this Mac's enrolled key.", lit: true)
                case .declined:
                    Verdict(title: "Declined", message: "The daemon has been told no, and the trail records that a person said so.")
                case .expired:
                    Verdict(title: "Expired", message: "Nobody answered inside the request's lifetime. That is a different fact from a refusal, and the trail keeps them apart.")
                case .withdrawn:
                    Verdict(title: "Answered elsewhere", message: "Another of your devices signed this first.")
                case .refused:
                    EmptyView()
                case .failed(let why):
                    Verdict(title: "Not signed", message: why)
                }
            }

            Spacer(minLength: 0)

            HStack {
                if pending.phase == .reading || pending.phase == .refused {
                    Legend(text: "expires in \(pending.secondsLeft)s")
                    Spacer()
                    Button("Decline") { session.decline() }
                        .buttonStyle(.plain)
                        .foregroundColor(Theme.inkDim)
                } else {
                    Spacer()
                    Button("Close") { session.dismiss() }
                        .buttonStyle(.plain)
                        .foregroundColor(Theme.inkDim)
                }
            }
            .padding(.bottom, 20)
        }
        .padding(.horizontal, 24)
        .onAppear {
            // Arm from the frame after paint — §6.2.3 measures from the last
            // byte written to the screen, not from when the payload arrived.
            DispatchQueue.main.async {
                session.rendered(now: nowMs())
                armed = true
            }
            pending.hold.onCommit = { dwell in
                Task { @MainActor in await session.commit(dwellMs: dwell) }
            }
        }
        .onReceive(frames) { now in
            tick = now
            if pending.phase == .reading {
                pending.hold.tick(now: nowMs())
                if pending.secondsLeft == 0 { session.expire() }
            }
        }
    }

    @ViewBuilder private var readingControls: some View {
        if p.requester_changed && !pending.acknowledged {
            VStack(alignment: .leading, spacing: 8) {
                Legend(text: "the requester changed", lit: true)
                Text("Now asking: \(requesterText)")
                    .font(.system(size: 13)).foregroundColor(Theme.inkSoft)
                Text("Acknowledge that something else is asking before this can be approved. Acknowledging is not approving and signs nothing.")
                    .font(.system(size: 12)).foregroundColor(Theme.inkDim)
                Button(action: { session.acknowledge() }) {
                    Text("ACKNOWLEDGE").font(Theme.label).tracking(2.4).frame(maxWidth: .infinity).padding(.vertical, 11)
                }
                .buttonStyle(.plain)
                .foregroundColor(Theme.amber)
                .background(RoundedRectangle(cornerRadius: 3).stroke(Theme.amber, lineWidth: 1).background(Theme.amber.opacity(0.08)))
            }
        } else {
            HStack(alignment: .center, spacing: 20) {
                HoldDial(hold: pending.hold, enabled: pending.canHold, tick: tick)
                VStack(alignment: .leading, spacing: 6) {
                    Text(holdLabel).font(.system(size: 13, weight: .medium)).foregroundColor(Theme.ink)
                    // No client showed an enrollment digest; there is nothing
                    // to compare it with. What a person can check is the name.
                    Text(pending.params.enrollment
                        ? "Check the email above is yours. This Mac's approvals will be traced to it."
                        : "Confirm the digest above matches the one your client showed.")
                        .font(.system(size: 12)).foregroundColor(Theme.inkDim)
                    HStack(spacing: 6) {
                        Image(systemName: "touchid").foregroundColor(Theme.inkDim)
                        Text(pending.phase == .signing ? "Touch ID…" : "Touch ID when the hold commits")
                            .font(.system(size: 12)).foregroundColor(Theme.inkDim)
                    }
                    if !p.requester_changed {
                        Text("Asking: \(requesterText)").font(Theme.monoSmall).foregroundColor(Theme.inkFaint)
                    }
                }
            }
        }
    }

    private var requesterText: String {
        p.requester.replacingOccurrences(of: " (claimed)", with: "")
    }

    private var holdLabel: String {
        switch pending.hold.phase {
        case .arming: return "Read it. Arming…"
        case .rest: return "Lift your finger, then hold"
        case .armed: return "Hold to countersign · \(Int(pending.params.hold_ms / 1000)) s"
        case .holding: return "Keep holding…"
        case .committed: return "Signing"
        case .idle: return ""
        }
    }
}

/// The screen: rendered from the render lines the daemon assembled, whose
/// label and digest the daemon wrote and no pack could.
struct DeviceScreen: View {
    let presentation: Presentation
    let enrollment: Bool

    /// The lines at their full height, and the height the window has room
    /// for. When the first exceeds the second the lines scroll, and the
    /// screen says so.
    @State private var wanted: CGFloat = 0
    @State private var shown: CGFloat = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            let label = presentation.render.first { $0.role == .label }?.text ?? "unclassified"
            Text(label.uppercased())
                .font(Theme.label).tracking(2)
                .foregroundColor(Theme.ink)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 12).padding(.vertical, 7)
                .background(Theme.labelBar(for: enrollment ? .moderate : presentation.severity).opacity(0.85))

            VStack(alignment: .leading, spacing: 8) {
                // Only the lines scroll, and only when they must: the frame
                // below caps the scroll at the lines' own height, so a short
                // statement takes what it needs and no more. The label above
                // and the digest below never scroll away. The digest is the
                // person's cross-check and has to stay in sight.
                ScrollView(.vertical) {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(Array(presentation.render.enumerated()), id: \.offset) { _, line in
                            switch line.role {
                            case .primary:
                                Text(line.text).font(Theme.mono).foregroundColor(Theme.ink)
                                    .fixedSize(horizontal: false, vertical: true)
                            case .advisory:
                                HStack(alignment: .firstTextBaseline, spacing: 6) {
                                    Text(line.text).font(Theme.monoSmall).foregroundColor(Theme.caution)
                                    Text("ADV").font(.system(size: 9, weight: .semibold)).tracking(1.5)
                                        .foregroundColor(Theme.caution)
                                        .padding(.horizontal, 3).padding(.vertical, 1)
                                        .overlay(RoundedRectangle(cornerRadius: 2).stroke(Theme.caution.opacity(0.5), lineWidth: 0.5))
                                }
                            case .label, .digest:
                                EmptyView()
                            }
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(GeometryReader { lines in
                        Color.clear.preference(key: WantedHeight.self, value: lines.size.height)
                    })
                }
                .onPreferenceChange(WantedHeight.self) { wanted = $0 }
                .frame(maxHeight: wanted > 0 ? wanted : nil)
                .background(GeometryReader { room in
                    Color.clear
                        .onAppear { shown = room.size.height }
                        .onChange(of: room.size.height) { shown = $0 }
                })
                if wanted > shown + 1 {
                    // Wire spec §6: a long primary line truncates on screen
                    // with an ellipsis, and the signature covers all of it.
                    HStack {
                        Spacer()
                        Legend(text: "… more below", lit: true)
                    }
                }
                Divider().background(Theme.screenEdge).padding(.top, 4)
                HStack {
                    Legend(text: "digest")
                    Text(presentation.digest_short).font(Theme.mono).tracking(2).foregroundColor(Theme.inkSoft)
                }
            }
            .padding(12)
        }
        .background(Theme.screen)
        .overlay(RoundedRectangle(cornerRadius: 4).stroke(Theme.screenEdge, lineWidth: 1))
        .clipShape(RoundedRectangle(cornerRadius: 4))
    }
}

/// The height the statement's lines would take if nothing held them.
private struct WantedHeight: PreferenceKey {
    static let defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
        value = max(value, nextValue())
    }
}

struct Notice: View {
    let title: String
    let message: String
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.system(size: 13, weight: .semibold)).foregroundColor(Theme.ink)
            Text(message).font(.system(size: 12)).foregroundColor(Theme.inkSoft)
        }
        .padding(12)
        .background(Theme.refuse.opacity(0.14))
        .overlay(Rectangle().frame(width: 2).foregroundColor(Theme.refuse), alignment: .leading)
    }
}

struct Verdict: View {
    let title: String
    let message: String
    var lit = false
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.system(size: 20, weight: .semibold)).foregroundColor(lit ? Theme.amber : Theme.ink)
            Text(message).font(.system(size: 12)).foregroundColor(Theme.inkDim)
        }
    }
}

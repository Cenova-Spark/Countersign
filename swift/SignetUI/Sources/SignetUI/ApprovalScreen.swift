// One request, three steps: read it, acknowledge it, hold to sign it.
//
// Acknowledging and approving are different controls, because §6.3.3 says
// same-control-different-gesture is the wrong answer for someone who is, by
// premise, not paying full attention. The screen renders from the bytes that
// will be signed, and refuses to render when the bytes and the digest
// disagree.
//
// Shared by both apps. The window this sits in is the platform's problem —
// the Mac wraps it in `ApprovalView`, which is the only place `NSScreen`
// appears — and everything below is the same on either.

import CountersignKit
import SwiftUI

/// A monotonic clock in milliseconds, for the hold machine.
public func nowMs() -> Double { ProcessInfo.processInfo.systemUptime * 1000 }

public struct PendingView: View {
    @ObservedObject var pending: PendingApproval
    /// Unowned because the answer path outlives the view and owns it — the
    /// Mac's `AppSession`, the phone's relay client. A strong reference here
    /// would be a cycle through the view tree.
    unowned let actions: any ApprovalActions
    @State private var tick = Date()
    @State private var armed = false
    private let frames = Timer.publish(every: 1.0 / 60.0, on: .main, in: .common).autoconnect()

    public init(pending: PendingApproval, actions: any ApprovalActions) {
        self.pending = pending
        self.actions = actions
    }

    var p: Presentation { pending.presentation }

    public var body: some View {
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
                    Verdict(
                        title: "Countersigned",
                        message: "The daemon has the signature and has verified it against this "
                            + "\(actions.deviceNoun)'s enrolled key.",
                        tone: .signed)
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
                    Button("Decline") { actions.decline() }
                        .buttonStyle(.plain)
                        .foregroundColor(Theme.inkDim)
                } else {
                    Spacer()
                    Button("Close") { actions.dismiss() }
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
                actions.rendered(now: nowMs())
                armed = true
            }
            pending.hold.onCommit = { dwell in
                Task { @MainActor in await actions.commit(dwellMs: dwell) }
            }
        }
        .onReceive(frames) { now in
            tick = now
            if pending.phase == .reading {
                pending.hold.tick(now: nowMs())
                if pending.secondsLeft == 0 { actions.expire() }
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
                Button(action: { actions.acknowledge() }) {
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
                        ? "Check the email above is yours. This \(actions.deviceNoun)'s approvals will be traced to it."
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
///
/// Three bands, and which one may scroll is the whole design. The bar says
/// what is being asked and where — the action out of the bytes that will be
/// signed, the environment and its tier out of the daemon's own config. The
/// statement is the exact text, however long, and it is the only band that
/// scrolls. The advisories say what that text will *do*, and they are pinned:
/// a long command used to push them under the fold, which left the person
/// reading the noise and deciding without the summary. The digest is the
/// cross-check and never moves.
public struct DeviceScreen: View {
    let presentation: Presentation
    let enrollment: Bool

    /// The statement at its full height, and the height there is room for.
    /// When the first exceeds the second it scrolls, and the screen says so.
    @State private var wanted: CGFloat = 0
    @State private var shown: CGFloat = 0

    private var primaries: [RenderLine] { presentation.render.filter { $0.role == .primary } }
    private var advisories: [RenderLine] { presentation.render.filter { $0.role == .advisory } }

    public var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            bar
            VStack(alignment: .leading, spacing: 8) {
                statement
                if !advisories.isEmpty {
                    advisoryLines.layoutPriority(1)
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

    /// What is being asked, and where it lands.
    ///
    /// The action is read back out of `request_json` — the bytes the signature
    /// covers — and not from anything the daemon said about them, so the verb
    /// on screen is the verb in the payload. The label is the daemon's, from
    /// local config, and now carries its tier as a word: the bar's colour said
    /// production and nothing else did, and a colour is not a word.
    private var bar: some View {
        let label = presentation.render.first { $0.role == .label }?.text ?? "unclassified"
        return VStack(alignment: .leading, spacing: 4) {
            if let action = presentation.action {
                row("action", action, mono: true)
            }
            row("target", label, mono: false)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 12).padding(.vertical, 8)
        .background(Theme.labelBar(for: enrollment ? .moderate : presentation.severity).opacity(0.85))
    }

    private func row(_ legend: String, _ value: String, mono: Bool) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(legend.uppercased())
                .font(Theme.label).tracking(1.6)
                .foregroundColor(Theme.ink.opacity(0.6))
                .frame(width: 52, alignment: .leading)
            Text(mono ? value : value.uppercased())
                .font(mono ? Theme.monoSmall : Theme.label)
                .tracking(mono ? 0 : 2)
                .foregroundColor(Theme.ink)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
    }

    /// The exact text, and the only thing here that scrolls.
    private var statement: some View {
        VStack(alignment: .leading, spacing: 4) {
            ScrollView(.vertical) {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(Array(primaries.enumerated()), id: \.offset) { _, line in
                        Text(line.text).font(Theme.mono).foregroundColor(Theme.ink)
                            .fixedSize(horizontal: false, vertical: true)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(GeometryReader { lines in
                    Color.clear.preference(key: WantedHeight.self, value: lines.size.height)
                })
            }
            .onPreferenceChange(WantedHeight.self) { wanted = $0 }
            // Takes its own height when that fits, and gives before the
            // advisories or the dial do when it does not. Never nothing: two
            // lines of the statement stay visible however long it is.
            .frame(minHeight: min(44, wanted), maxHeight: wanted > 0 ? wanted : nil)
            .background(GeometryReader { room in
                Color.clear
                    .onAppear { shown = room.size.height }
                    .onChange(of: room.size.height) { shown = $0 }
            })
            if wanted > shown + 1 {
                // Wire spec §6: a long statement truncates on screen with an
                // ellipsis, and the signature covers all of it. Only the
                // statement is ever what is cut.
                HStack {
                    Spacer()
                    Legend(text: "… more below", lit: true)
                }
            }
        }
    }

    /// What the statement will do, according to the pack — pinned, marked
    /// unverified, and wrapped rather than clipped. Spec §6 requires the
    /// marker; being able to finish reading the line is ours.
    private var advisoryLines: some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(Array(advisories.enumerated()), id: \.offset) { _, line in
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text(line.text).font(Theme.monoSmall).foregroundColor(Theme.caution)
                        .fixedSize(horizontal: false, vertical: true)
                    Text("ADV").font(.system(size: 9, weight: .semibold)).tracking(1.5)
                        .foregroundColor(Theme.caution)
                        .padding(.horizontal, 3).padding(.vertical, 1)
                        .overlay(RoundedRectangle(cornerRadius: 2).stroke(Theme.caution.opacity(0.5), lineWidth: 0.5))
                    Spacer(minLength: 0)
                }
            }
        }
    }
}

/// The height the statement's lines would take if nothing held them.
private struct WantedHeight: PreferenceKey {
    static let defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
        value = max(value, nextValue())
    }
}

public struct Notice: View {
    let title: String
    let message: String
    public var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.system(size: 13, weight: .semibold)).foregroundColor(Theme.ink)
            Text(message).font(.system(size: 12)).foregroundColor(Theme.inkSoft)
        }
        .padding(12)
        .background(Theme.refuse.opacity(0.14))
        .overlay(Rectangle().frame(width: 2).foregroundColor(Theme.refuse), alignment: .leading)
    }
}

/// How a request ended. `signed` is the one outcome that gets a colour, a
/// mark and a ground of its own: it is the only one where something now
/// exists that did not before, and a person who looked away during the hold
/// should be able to tell from across the room. The payload stays above it,
/// unchanged — what was approved is as readable after as it was before.
public struct Verdict: View {
    enum Tone { case plain, signed }

    let title: String
    let message: String
    var tone: Tone = .plain

    public var body: some View {
        HStack(alignment: .top, spacing: 11) {
            if tone == .signed {
                Image(systemName: "checkmark.seal.fill")
                    .font(.system(size: 21))
                    .foregroundColor(Theme.signed)
                    .accessibilityHidden(true)
            }
            VStack(alignment: .leading, spacing: 5) {
                Text(title)
                    .font(.system(size: 20, weight: .semibold))
                    .foregroundColor(tone == .signed ? Theme.signed : Theme.ink)
                Text(message).font(.system(size: 12)).foregroundColor(Theme.inkDim)
            }
            Spacer(minLength: 0)
        }
        .padding(tone == .signed ? 12 : 0)
        .background(tone == .signed ? Theme.signed.opacity(0.12) : Color.clear)
        .overlay(alignment: .leading) {
            if tone == .signed {
                Rectangle().frame(width: 2).foregroundColor(Theme.signed)
            }
        }
    }
}

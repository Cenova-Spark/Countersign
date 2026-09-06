// The menu bar popover: is the daemon up, is this Mac enrolled, what is
// installed, what has been recorded — and the one action that changes what
// this Mac may do, enrolling it.

import CountersignKit
import SignetCore
import SwiftUI

struct MenuView: View {
    @EnvironmentObject var session: AppSession
    @State private var tab = 0

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            Picker("", selection: $tab) {
                Text("Devices").tag(0)
                Text("Plugins").tag(1)
                Text("Audit").tag(2)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .padding(.horizontal, 14).padding(.bottom, 10)

            Group {
                switch tab {
                case 0: DevicesView()
                case 1: PluginsView()
                default: AuditView()
                }
            }
            .frame(minHeight: 260, alignment: .top)

            Divider()
            HStack {
                if session.pending != nil {
                    Text("Something is waiting").font(.system(size: 12)).foregroundColor(Theme.amber)
                } else if let m = session.lastMessage {
                    Text(m).font(.system(size: 12)).foregroundColor(.secondary).lineLimit(1)
                }
                Spacer()
                Button("Quit") { NSApp.terminate(nil) }.buttonStyle(.plain).foregroundColor(.secondary)
            }
            .padding(12)
        }
        .task { await session.refresh() }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text("SIGNET").font(.system(size: 12, weight: .bold)).tracking(4).foregroundColor(.secondary)
                Spacer()
                StatusPill(session: session)
            }
            Text(statusLine).font(.system(size: 12)).foregroundColor(.secondary).lineLimit(2)
            if let e = session.connectionError {
                Text(e).font(.system(size: 11)).foregroundColor(Theme.refuse).lineLimit(3)
            }
        }
        .padding(14)
    }

    private var statusLine: String {
        switch session.daemonState {
        case .stopped: return "signetd is not running."
        case .failed(let why): return why
        case .external: return session.attachment == nil ? "Joined a running signetd; attaching…" : "Joined a running signetd."
        case .running(let pid): return "signetd running (pid \(pid))" + (session.attachment == nil ? "; attaching…" : "")
        }
    }
}

struct StatusPill: View {
    @ObservedObject var session: AppSession
    var body: some View {
        let (text, colour): (String, Color) = {
            if session.attachment == nil { return ("detached", .secondary) }
            return session.enrolled ? ("enrolled", Theme.amber) : ("not enrolled", Theme.caution)
        }()
        Text(text.uppercased()).font(.system(size: 9, weight: .semibold)).tracking(1.4)
            .foregroundColor(colour)
            .padding(.horizontal, 6).padding(.vertical, 2)
            .overlay(RoundedRectangle(cornerRadius: 2).stroke(colour.opacity(0.6), lineWidth: 0.5))
    }
}

struct DevicesView: View {
    @EnvironmentObject var session: AppSession
    @State private var subject = ""
    @State private var display = ""
    @State private var enrolling = false
    @State private var error: String?
    @State private var showHelp = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            ForEach(session.roster.records) { record in
                DeviceRow(record: record, isThisMac: record.device_id == session.deviceID)
            }
            if session.roster.records.isEmpty {
                Text("No devices enrolled yet.").font(.system(size: 12)).foregroundColor(.secondary)
            }

            if session.attachment != nil && !session.enrolled {
                Divider()
                HStack(spacing: 6) {
                    Text("Enroll this Mac").font(.system(size: 13, weight: .semibold))
                    // The why lives here, not on the sheet. Someone who wants
                    // it asks; someone who does not is shown a field and a button.
                    Button { showHelp.toggle() } label: {
                        Image(systemName: "questionmark.circle").foregroundColor(.secondary)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Why enroll")
                    .popover(isPresented: $showHelp, arrowEdge: .bottom) { EnrollHelp() }
                }
                TextField("Email", text: $subject)
                    .textFieldStyle(.roundedBorder)
                    .disabled(enrolling)
                    .onSubmit(enroll)
                TextField("Name (optional)", text: $display)
                    .textFieldStyle(.roundedBorder)
                    .disabled(enrolling)
                    .onSubmit(enroll)
                if enrolling {
                    // A status line, not a disabled button: a dimmed button on
                    // this dark ground reads as an empty one.
                    HStack(spacing: 6) {
                        ProgressView().controlSize(.small)
                        Text("Hold in the approval window.").font(.system(size: 11)).foregroundColor(Theme.amber)
                    }
                } else {
                    // Always enabled, so the label is always legible. A bad
                    // email is explained on press rather than by greying out.
                    Button("Enroll", action: enroll)
                        .buttonStyle(.borderedProminent)
                        .tint(Theme.amber)
                }
                if let error { Text(error).font(.system(size: 11)).foregroundColor(Theme.refuse) }
            }
        }
        .padding(.horizontal, 14)
        .onAppear {
            // The Mac already knows the person's name; typing it again is a
            // form for its own sake. The email stays theirs to type until
            // there is an account to take it from.
            if display.isEmpty { display = NSFullUserName() }
        }
    }

    private func enroll() {
        guard !enrolling else { return }
        let email = subject.trimmingCharacters(in: .whitespaces)
        guard DevicesView.looksLikeEmail(email) else {
            error = "Enter a valid email."
            return
        }
        enrolling = true
        error = nil
        Task {
            do { _ = try await session.enroll(subject: email, display: display.isEmpty ? nil : display) }
            catch { self.error = String(describing: error) }
            enrolling = false
        }
    }

    /// Enough of a check to catch a name typed where an email goes. Not a
    /// validator: the protocol takes any stable identifier as a subject, and a
    /// daemon-side rule is where a stricter policy would belong.
    static func looksLikeEmail(_ text: String) -> Bool {
        let parts = text.split(separator: "@", omittingEmptySubsequences: false)
        guard parts.count == 2, !parts[0].isEmpty else { return false }
        let domain = parts[1]
        return domain.contains(".") && !domain.hasPrefix(".") && !domain.hasSuffix(".") && !text.contains(" ")
    }
}

/// What enrolling is, for whoever asks.
struct EnrollHelp: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Why enroll?").font(.system(size: 13, weight: .semibold))
            Text("Enrolling ties this Mac's key to you, so approvals it makes can be traced to a person. Until then it can't approve anything.")
            Text("Your email is that identifier. It's stored in your own roster file on this Mac, and nowhere else.")
            Text("Pressing Enroll opens the approval window. Read it, hold the dial, and confirm with Touch ID.")
        }
        .font(.system(size: 11))
        .foregroundColor(.secondary)
        .frame(width: 260)
        .padding(12)
    }
}

struct DeviceRow: View {
    let record: EnrollmentRecord
    let isThisMac: Bool
    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: record.resolvedClass == "signet" ? "dial.medium" : (isThisMac ? "laptopcomputer" : "iphone"))
                .foregroundColor(.secondary).frame(width: 18)
            VStack(alignment: .leading, spacing: 2) {
                Text(isThisMac ? "This Mac" : (record.owner.display ?? record.owner.subject))
                    .font(.system(size: 13, weight: .medium))
                Text("\(record.device_id.prefix(12)) · \(record.owner.subject)")
                    .font(.system(size: 11, design: .monospaced)).foregroundColor(.secondary)
            }
            Spacer()
            Text(record.isActive ? record.resolvedClass : "revoked")
                .font(.system(size: 9, weight: .semibold)).tracking(1.2)
                .foregroundColor(record.isActive ? .secondary : Theme.refuse)
                .padding(.horizontal, 6).padding(.vertical, 2)
                .background(RoundedRectangle(cornerRadius: 2).fill(Color.secondary.opacity(0.12)))
        }
    }
}

struct PluginsView: View {
    @EnvironmentObject var session: AppSession
    @State private var busy: String?
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Installed is on disk. On means its namespaces may reach you. Off refuses them without asking.")
                .font(.system(size: 11)).foregroundColor(.secondary)
            ForEach(session.plugins) { plugin in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(plugin.name).font(.system(size: 13, weight: .medium))
                        Text("\(plugin.namespaces.joined(separator: ", ")) · \(plugin.kind) · \(plugin.manifest?.version ?? "")")
                            .font(.system(size: 11)).foregroundColor(.secondary)
                    }
                    Spacer()
                    Toggle("", isOn: Binding(
                        get: { plugin.enabled },
                        set: { on in
                            busy = plugin.name
                            error = nil
                            Task {
                                do { try await session.setPlugin(plugin.name, enabled: on) }
                                catch { self.error = String(describing: error) }
                                busy = nil
                            }
                        }))
                    .toggleStyle(.switch)
                    .labelsHidden()
                    .disabled(busy != nil)
                }
            }
            if session.plugins.isEmpty {
                Text("No plugins installed. Install one with `signetd pack install`.")
                    .font(.system(size: 12)).foregroundColor(.secondary)
            }
            if let error { Text(error).font(.system(size: 11)).foregroundColor(Theme.refuse) }
        }
        .padding(.horizontal, 14)
    }
}

struct AuditView: View {
    @EnvironmentObject var session: AppSession
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let a = session.audit {
                Text("\(a.entries) entries in the trail").font(.system(size: 13, weight: .medium))
                Text("head \(a.head.prefix(16))…").font(.system(size: 11, design: .monospaced)).foregroundColor(.secondary)
            }
            if let s = session.status {
                Text("Daemon device: \(s.kind) · counter \(s.counter) · \(s.environments) environment(s)")
                    .font(.system(size: 11)).foregroundColor(.secondary)
            }
            Divider()
            Text("Daemon log").font(.system(size: 11, weight: .semibold)).foregroundColor(.secondary)
            ScrollView {
                VStack(alignment: .leading, spacing: 1) {
                    ForEach(Array(session.log.suffix(40).enumerated()), id: \.offset) { _, line in
                        Text(line).font(.system(size: 10, design: .monospaced)).foregroundColor(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
            }
            .frame(maxHeight: 170)
        }
        .padding(.horizontal, 14)
    }
}

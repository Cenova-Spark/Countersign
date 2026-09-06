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

            Divider().padding(.top, 4)
            StartOver()
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

/// A fresh start, for demos and development. Two presses, with what it will
/// do said in between, because nothing here can be undone.
struct StartOver: View {
    @EnvironmentObject var session: AppSession
    @State private var confirming = false
    @State private var busy = false
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if busy {
                HStack(spacing: 6) {
                    ProgressView().controlSize(.small)
                    Text("Starting over…").font(.system(size: 11)).foregroundColor(Theme.amber)
                }
            } else if confirming {
                Text("Forgets this Mac's key, the roster, the audit trail, installed plugins and the relay pairing. For demos and development. It cannot be undone.")
                    .font(.system(size: 11)).foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 12) {
                    Button("Wipe everything", action: run)
                        .buttonStyle(.borderedProminent)
                        .tint(Theme.refuse)
                    Button("Keep") { confirming = false }
                        .buttonStyle(.plain).foregroundColor(.secondary)
                }
            } else {
                Button("Start over…") { confirming = true }
                    .buttonStyle(.plain).foregroundColor(.secondary).font(.system(size: 11))
            }
            if let error { Text(error).font(.system(size: 11)).foregroundColor(Theme.refuse) }
        }
    }

    private func run() {
        confirming = false
        busy = true
        error = nil
        Task {
            do { try await session.startOver() } catch { self.error = String(describing: error) }
            busy = false
        }
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

/// Installed plugins with their switches, and the marketplace under them.
/// Every button here runs the daemon's own `signetd pack …`; the tab never
/// has a second opinion about what a plugin is.
struct PluginsView: View {
    @EnvironmentObject var session: AppSession
    @State private var busy: String?
    @State private var error: String?
    @State private var editingIndex = false
    @State private var indexText = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("Installed is on disk. On means its namespaces may reach you. Off refuses them without asking.")
                .font(.system(size: 11)).foregroundColor(.secondary)
            ForEach(session.plugins) { plugin in
                HStack(alignment: .center) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(plugin.name).font(.system(size: 13, weight: .medium))
                        Text("\(plugin.namespaces.joined(separator: ", ")) · \(plugin.kind) · \(plugin.manifest?.version ?? "")")
                            .font(.system(size: 11)).foregroundColor(.secondary)
                    }
                    Spacer()
                    Button("Remove") { run("remove " + plugin.name) { try await session.removePlugin(plugin.name) } }
                        .buttonStyle(.plain).font(.system(size: 11)).foregroundColor(.secondary)
                        .disabled(busy != nil)
                    Toggle("", isOn: Binding(
                        get: { plugin.enabled },
                        set: { on in run(plugin.name) { try await session.setPlugin(plugin.name, enabled: on) } }))
                    .toggleStyle(.switch)
                    .labelsHidden()
                    .disabled(busy != nil)
                }
            }
            if session.plugins.isEmpty {
                Text(session.bundled.isEmpty
                     ? "Nothing installed."
                     : "Nothing installed. \(session.bundled.joined(separator: ", ")) ships with the app and classifies SQL until something is.")
                    .font(.system(size: 12)).foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else if !session.bundled.isEmpty {
                Text("\(session.bundled.joined(separator: ", ")) ships with the app and steps aside while anything is installed.")
                    .font(.system(size: 11)).foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Divider()
            HStack(alignment: .firstTextBaseline) {
                Text("Marketplace").font(.system(size: 13, weight: .semibold))
                Spacer()
                Button(editingIndex ? "Done" : "Where…") {
                    if editingIndex {
                        session.indexLocation = indexText
                        Task { await session.loadIndex() }
                    } else {
                        indexText = session.indexLocation
                    }
                    editingIndex.toggle()
                }
                .buttonStyle(.plain).font(.system(size: 11)).foregroundColor(.secondary)
                Button("Refresh") { Task { await session.loadIndex() } }
                    .buttonStyle(.plain).font(.system(size: 11)).foregroundColor(.secondary)
            }
            if editingIndex {
                TextField("Index URL or folder (empty for the default)", text: $indexText)
                    .textFieldStyle(.roundedBorder)
                    .onSubmit { session.indexLocation = indexText; editingIndex = false; Task { await session.loadIndex() } }
            }
            ForEach(session.available) { entry in
                HStack(alignment: .top) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(entry.name).font(.system(size: 13, weight: .medium))
                        Text("\(entry.namespaces.joined(separator: ", ")) · wasm · \(entry.version)")
                            .font(.system(size: 11)).foregroundColor(.secondary)
                        if let description = entry.description {
                            Text(description).font(.system(size: 11)).foregroundColor(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    Spacer()
                    if let on = entry.installed {
                        Text(on ? "on" : "installed, off").font(.system(size: 11)).foregroundColor(.secondary)
                    } else {
                        Button("Install") { run(entry.name) { try await session.installPlugin(named: entry.name) } }
                            .buttonStyle(.borderedProminent).tint(Theme.amber)
                            .disabled(busy != nil)
                    }
                }
            }
            if session.available.isEmpty {
                Text(session.indexNote ?? "Reading the index…")
                    .font(.system(size: 11)).foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text("Everything listed is WebAssembly, checked on this Mac before it is installed, and installed off.")
                    .font(.system(size: 11)).foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack(spacing: 8) {
                Button("Install from a file…", action: installFromFile)
                    .buttonStyle(.plain).font(.system(size: 11)).foregroundColor(.secondary)
                    .disabled(busy != nil)
                if let busy {
                    ProgressView().controlSize(.small)
                    Text(busy).font(.system(size: 11)).foregroundColor(Theme.amber)
                }
            }
            if let error { Text(error).font(.system(size: 11)).foregroundColor(Theme.refuse).fixedSize(horizontal: false, vertical: true) }
        }
        .padding(.horizontal, 14)
        .task { if session.available.isEmpty { await session.loadIndex() } }
    }

    private func run(_ what: String, _ work: @escaping () async throws -> Void) {
        busy = what
        error = nil
        Task {
            do { try await work() } catch { self.error = String(describing: error) }
            busy = nil
        }
    }

    /// A plugin directory holding a manifest, or a bare `.wasm` module.
    private func installFromFile() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = true
        panel.allowsMultipleSelection = false
        panel.message = "A plugin directory holding countersign-plugin.json, or a .wasm module."
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            run(url.lastPathComponent) { try await session.installPlugin(at: url) }
        }
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

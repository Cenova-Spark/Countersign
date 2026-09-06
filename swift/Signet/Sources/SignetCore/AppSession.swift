// The app's state, from the daemon's point of view.
//
// One session: a daemon (ours or joined), a **device** connection that has
// attached and is shown things, a **control** connection for status, audit
// and enrollment, and at most one pending approval — one signature, one
// statement (wire spec §9), so a second request while one is showing waits
// at the daemon, not here.
//
// Nothing in this file knows what a window is. The views bind to it.

import Combine
import CountersignKit
import Foundation

/// What the approval window is showing right now.
public final class PendingApproval: ObservableObject, Identifiable {
    public enum Phase: Equatable {
        /// On screen; the hold machine is running.
        case reading
        /// The hold committed; the enclave is signing (the biometric prompt
        /// is up).
        case signing
        case signed(DeviceSignature)
        case declined
        case expired
        case withdrawn
        /// The bytes do not match the digest. Nothing here can be approved.
        case refused
        case failed(String)
    }

    public let id: Int
    public let params: PresentParams
    public let receivedAt: Date
    public let hold: HoldMachine
    /// Whether `request_json` really digests to `request_digest`.
    public let digestVerified: Bool
    @Published public var acknowledged: Bool
    @Published public var phase: Phase

    init(id: Int, params: PresentParams) {
        self.id = id
        self.params = params
        self.receivedAt = Date()
        self.hold = HoldMachine(armDelayMs: params.arm_delay_ms, holdMs: params.hold_ms)
        self.digestVerified = params.presentation.verifiedDigest()
        // The web relay asks for an acknowledgement on every remote request;
        // here the daemon says whether the requester changed, and the app
        // follows it (wire spec §6.3.2).
        self.acknowledged = !params.presentation.requester_changed
        self.phase = digestVerified ? .reading : .refused
    }

    public var presentation: Presentation { params.presentation }
    public var expiresAt: Date { receivedAt.addingTimeInterval(Double(params.presentation.ttl_ms) / 1000) }
    public var secondsLeft: Int { max(0, Int(expiresAt.timeIntervalSinceNow.rounded(.up))) }

    /// Whether the dial may be held: read, acknowledged, and the bytes check.
    public var canHold: Bool {
        phase == .reading && acknowledged && digestVerified
    }
}

@MainActor
public final class AppSession: ObservableObject {
    public struct Attachment: Equatable {
        public var deviceID: String
        public var enrolled: Bool
        public var hint: String
    }

    @Published public private(set) var daemonState: DaemonController.State = .stopped
    @Published public private(set) var attachment: Attachment?
    @Published public private(set) var connectionError: String?
    @Published public private(set) var pending: PendingApproval? {
        // After the store, not before it. `$pending` publishes in `willSet`,
        // so a subscriber that opened the window from it built a view which
        // read `session.pending` back and found the old value — nil, for a
        // first request. "Nothing pending" is what a person saw while the
        // daemon waited for a hold, and closing that window answered aborted.
        didSet { onPendingChange?(pending) }
    }
    @Published public private(set) var lastMessage: String?
    @Published public private(set) var status: DeviceStatus?
    @Published public private(set) var audit: AuditSummary?
    @Published public private(set) var roster: LocalRoster = LocalRoster(v: 1, records: [])
    @Published public private(set) var plugins: [InstalledPlugin] = []
    /// The packs shipped beside the daemon, which run while nothing is installed.
    @Published public private(set) var bundled: [String] = []
    /// What the marketplace lists, and where that came from or why it could not.
    @Published public private(set) var available: [AvailablePlugin] = []
    @Published public private(set) var indexNote: String?
    @Published public private(set) var log: [String] = []

    /// Where the index is: a URL or a directory, empty for the daemon's
    /// default. Remembered on this Mac, because a demo from a checkout points
    /// it at a directory and a paying user never touches it.
    public var indexLocation: String {
        get { UserDefaults.standard.string(forKey: "indexLocation") ?? "" }
        set { UserDefaults.standard.set(newValue, forKey: "indexLocation") }
    }

    public private(set) var signer: Signer
    public private(set) var countersigner: Countersigner
    public let deviceName: String
    public let controller: DaemonController
    public let socketPath: String

    /// Called whenever `pending` changes, once the change can be read back.
    /// The approval window is opened and closed from here.
    public var onPendingChange: ((PendingApproval?) -> Void)?

    /// Forget this Mac's key and make a new one. Set by whoever holds the
    /// enclave device: the keychain item is under the app's identity, and
    /// the session cannot reach it.
    public var forgetKey: (() throws -> (Signer, CounterStore))?
    /// Remove what the daemon wrote. `signetd wipe --yes` unless something
    /// else is set — the tests set something that needs no binary.
    public var wipeDaemonState: (() throws -> Void)?

    private var device: DaemonConnection?
    private var control: DaemonConnection?
    private var reconnectScheduled = false
    private var startingOver = false

    public init(signer: Signer, counters: CounterStore, deviceName: String, controller: DaemonController) {
        self.signer = signer
        self.countersigner = Countersigner(signer: signer, counters: counters)
        self.deviceName = deviceName
        self.controller = controller
        self.socketPath = controller.socketPath
        controller.onLog = { [weak self] line in
            Task { @MainActor in self?.append(log: line) }
        }
        controller.onExit = { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                self.daemonState = self.controller.state
                self.scheduleReconnect()
            }
        }
    }

    /// The device's own id — what the roster keys on.
    public var deviceID: String { signer.deviceID }

    /// Whether this Mac may approve: attached, and the roster says so.
    public var enrolled: Bool { attachment?.enrolled ?? false }

    // MARK: Lifecycle

    /// Start or join the daemon, attach, and load everything the menu shows.
    public func start() async {
        do {
            try controller.ensureRunning()
            daemonState = controller.state
        } catch {
            daemonState = controller.state
            connectionError = String(describing: error)
            scheduleReconnect()
            return
        }
        await connect()
    }

    private func connect() async {
        do {
            let device = try DaemonConnection(path: socketPath)
            device.onPush = { [weak self] push in
                Task { @MainActor in self?.handle(push) }
            }
            device.onClose = { [weak self] in
                Task { @MainActor in
                    self?.attachment = nil
                    self?.device = nil
                    self?.scheduleReconnect()
                }
            }
            let response = try await device.attach(AttachRequest(signer: signer, name: deviceName))
            self.device = device
            attachment = Attachment(deviceID: response.device_id, enrolled: response.enrolled, hint: response.hint)
            connectionError = nil
            append(log: response.hint)

            control = try DaemonConnection(path: socketPath)
            await refresh()
        } catch {
            connectionError = String(describing: error)
            append(log: "connection failed: \(error)")
            scheduleReconnect()
        }
    }

    /// Drop both connections without letting their close handlers run: the
    /// handlers exist for a daemon that went away, not for one we are about
    /// to replace on purpose.
    private func disconnect() {
        device?.onClose = nil
        device?.onPush = nil
        device?.close()
        control?.close()
        device = nil
        control = nil
        attachment = nil
    }

    private func scheduleReconnect() {
        guard !reconnectScheduled, !startingOver else { return }
        reconnectScheduled = true
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: 1_500_000_000)
            reconnectScheduled = false
            if device == nil { await start() }
        }
    }

    /// Re-read status, audit, roster and plugins.
    public func refresh() async {
        roster = LocalRoster.load()
        plugins = InstalledPlugin.loadAll()
        bundled = bundledPacks()
        syncAvailable()
        if let control {
            status = try? await control.deviceStatus()
            audit = try? await control.auditSummary()
        }
        if let attachment {
            let active = roster.record(for: attachment.deviceID)?.isActive ?? false
            if active != attachment.enrolled {
                self.attachment?.enrolled = active
            }
        }
    }

    /// Run the enrollment ceremony for this Mac. The daemon will push it to
    /// the device connection, so the approval window appears while this call
    /// is in flight; it returns when the human has held.
    public func enroll(subject: String, display: String?) async throws -> EnrollmentRecord {
        guard let control else { throw RPCError.closed }
        let record = try await control.enroll(subject: subject, display: display)
        await refresh()
        attachment?.enrolled = true
        lastMessage = "Enrolled as \(record.owner.subject)"
        return record
    }

    /// Switch a plugin, then restart our daemon so it takes effect.
    public func setPlugin(_ name: String, enabled: Bool) async throws {
        try await runPack(["pack", enabled ? "enable" : "disable", name])
    }

    /// Install a listed plugin, switched off. The daemon restarts so the
    /// namespace is refused rather than shown unclassified until it is on.
    public func installPlugin(named name: String) async throws {
        try await runPack(["pack", "install", name] + indexArguments)
    }

    /// Install a plugin directory or a bare module from this Mac.
    public func installPlugin(at url: URL) async throws {
        try await runPack(["pack", "install", url.path])
    }

    public func removePlugin(_ name: String) async throws {
        try await runPack(["pack", "remove", name])
    }

    /// Ask the daemon's tool what the marketplace lists. Off the main actor,
    /// because the index may be a network away.
    public func loadIndex() async {
        guard let binary = controller.binary else {
            indexNote = "signetd was not found, so the marketplace cannot be read"
            return
        }
        let arguments = ["pack", "index", "--json"] + indexArguments
        do {
            let text = try await Task.detached { try DaemonCLI.run(binary, arguments) }.value
            let listing = try PluginIndex.decode(text)
            available = listing.plugins
            indexNote = listing.index
        } catch {
            available = []
            indexNote = String(describing: error)
        }
        syncAvailable()
    }

    private var indexArguments: [String] {
        let location = indexLocation.trimmingCharacters(in: .whitespaces)
        return location.isEmpty ? [] : ["--index", location]
    }

    /// Run one `signetd pack …`, re-read what is installed, and restart our
    /// daemon, which reads the packs directory at startup.
    private func runPack(_ arguments: [String]) async throws {
        guard let binary = controller.binary else { throw DaemonError.notFound }
        _ = try await Task.detached { try DaemonCLI.run(binary, arguments) }.value
        plugins = InstalledPlugin.loadAll()
        syncAvailable()
        if case .running = controller.state {
            disconnect()
            try controller.restart()
            await connect()
        } else {
            lastMessage = "Restart signetd for this to take effect"
        }
    }

    /// The listing's installed states, from what is on disk.
    private func syncAvailable() {
        available = available.map { entry in
            var entry = entry
            entry.installed = plugins.first { $0.name == entry.name }?.enabled
            return entry
        }
    }

    /// The packs beside the daemon binary: what it runs when nothing is installed.
    private func bundledPacks() -> [String] {
        guard let binary = controller.binary else { return [] }
        let dir = binary.deletingLastPathComponent()
        return ["countersign-db"].filter { FileManager.default.isExecutableFile(atPath: dir.appendingPathComponent($0).path) }
    }

    /// A fresh start, for demos and development: this Mac's key, the roster,
    /// the audit trail, the plugins and the relay pairing, all gone.
    ///
    /// Our daemon is stopped first, because a running one holds the roster
    /// and the chain and would write them straight back — `signetd wipe`
    /// refuses while anything is listening, so a daemon we only joined makes
    /// this fail with that reason. Then the key, which only the app can
    /// forget; then a new key, a new daemon, and an attach that will say
    /// "not enrolled".
    public func startOver() async throws {
        startingOver = true
        defer { startingOver = false }
        pending = nil
        disconnect()
        controller.stopAndWait()
        daemonState = controller.state
        do {
            if let wipeDaemonState {
                try wipeDaemonState()
            } else {
                guard let binary = controller.binary else { throw DaemonError.notFound }
                try DaemonCLI.run(binary, ["wipe", "--yes"])
            }
            if let forgetKey {
                let (fresh, counters) = try forgetKey()
                signer = fresh
                countersigner = Countersigner(signer: fresh, counters: counters)
            }
        } catch {
            append(log: "start over failed: \(error)")
            // Whatever state that left, get a daemon back before reporting it.
            await start()
            throw error
        }
        roster = LocalRoster(v: 1, records: [])
        plugins = []
        audit = nil
        status = nil
        await start()
        lastMessage = "Fresh start. Enroll this Mac to approve again."
    }

    // MARK: Presentations

    func handle(_ push: DaemonPush) {
        switch push {
        case .present(let id, let params):
            if let current = pending, current.phase == .reading {
                // One at a time is the daemon's rule too; if it ever asks
                // twice, the earlier one is what the human has been reading.
                append(log: "a second presentation arrived while one was showing; answering aborted")
                device?.respond(id: id, result: PresentOutcome.aborted.resultJSON)
                _ = current
                return
            }
            let approval = PendingApproval(id: id, params: params)
            pending = approval
            if !approval.digestVerified {
                append(log: "refusing to show \(params.presentation.digest_short): the bytes do not match the digest")
            }
        case .withdraw(let digest):
            if let current = pending, current.presentation.request_digest == digest, current.phase == .reading {
                current.phase = .withdrawn
                current.hold.disarm()
            }
        }
    }

    /// The payload has finished rendering; the arm delay starts now.
    public func rendered(now: Double) {
        pending?.hold.armFrom(now: now)
    }

    /// Acknowledging notices the request. It signs nothing.
    public func acknowledge() {
        pending?.acknowledged = true
    }

    /// Declining is ordinary software: tell the daemon no.
    public func decline() {
        guard let pending, pending.phase == .reading || pending.phase == .refused else { return }
        pending.phase = .declined
        pending.hold.disarm()
        device?.respond(id: pending.id, result: PresentOutcome.aborted.resultJSON)
    }

    /// The TTL elapsed with no actuation.
    public func expire() {
        guard let pending, pending.phase == .reading || pending.phase == .refused else { return }
        pending.phase = .expired
        pending.hold.disarm()
        device?.respond(id: pending.id, result: PresentOutcome.expired.resultJSON)
    }

    /// The hold committed. Sign — which runs the presence check — and answer.
    public func commit(dwellMs: Double) async {
        guard let pending, pending.phase == .reading, pending.canHold else { return }
        pending.phase = .signing
        do {
            let signature = try countersigner.countersign(
                requestDigestHex: pending.presentation.request_digest,
                dwellMs: UInt64(dwellMs.rounded()))
            pending.phase = .signed(signature)
            device?.respond(id: pending.id, result: PresentOutcome.approved(signature).resultJSON)
            lastMessage = "Countersigned \(pending.presentation.digest_short)"
        } catch {
            // A cancelled or failed presence check: nothing was signed, and
            // the payload goes back to readable so the human can try again or
            // decline.
            pending.phase = .reading
            pending.hold.armFrom(now: ProcessInfo.processInfo.systemUptime * 1000)
            append(log: "signing failed: \(error)")
            lastMessage = "Not signed: \(error)"
        }
    }

    /// The window closed after a terminal phase.
    public func dismiss() {
        if let pending, pending.phase == .reading || pending.phase == .refused {
            decline()
        }
        pending = nil
    }

    /// The enclave could not be set up at launch; say so where it is seen.
    public func noteStartupProblem(_ problem: String) {
        connectionError = problem
        append(log: problem)
    }

    private func append(log line: String) {
        log.append(line)
        if log.count > 200 { log.removeFirst(log.count - 200) }
    }
}

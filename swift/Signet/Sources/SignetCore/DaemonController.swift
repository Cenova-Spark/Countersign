// Running `signetd` from inside the app.
//
// The app bundles the daemon and starts it as `signetd run --device=app`. If
// a daemon is already listening — the operator started one in a terminal, or
// a previous app instance left one running — the app joins it instead. One
// daemon owns the device; the app is a client of it like the MCP bridge, the
// hook and the proxy, and none of those learn the daemon is being run by an
// app.

import Foundation

public final class DaemonController {
    public enum State: Equatable {
        case stopped
        /// A daemon we did not start is already listening.
        case external
        case running(pid: Int32)
        case failed(String)
    }

    public let binary: URL?
    public let socketPath: String
    public private(set) var state: State = .stopped
    /// The daemon's stderr, line by line — its startup banner and every
    /// refusal it explains. The menu shows the tail of this.
    public var onLog: ((String) -> Void)?
    public var onExit: ((Int32) -> Void)?

    private var process: Process?
    private var pipe: Pipe?
    private var partial = Data()

    public init(binary: URL? = DaemonController.locateSignetd(), socketPath: String = Paths.socketPath) {
        self.binary = binary
        self.socketPath = socketPath
    }

    /// Find `signetd`, in order: `$SIGNET_DAEMON`; beside this executable
    /// (an app bundle's `Contents/MacOS`); `Contents/Helpers`; and, for
    /// development, `target/debug/signetd` in any parent directory.
    public static func locateSignetd() -> URL? {
        let env = ProcessInfo.processInfo.environment
        if let explicit = env["SIGNET_DAEMON"], FileManager.default.isExecutableFile(atPath: explicit) {
            return URL(fileURLWithPath: explicit)
        }
        let exe = Bundle.main.executableURL ?? URL(fileURLWithPath: CommandLine.arguments[0])
        let dir = exe.deletingLastPathComponent()
        let candidates = [
            dir.appendingPathComponent("signetd"),
            dir.deletingLastPathComponent().appendingPathComponent("Helpers/signetd"),
        ]
        for c in candidates where FileManager.default.isExecutableFile(atPath: c.path) { return c }
        var probe = dir
        for _ in 0..<8 {
            let dev = probe.appendingPathComponent("target/debug/signetd")
            if FileManager.default.isExecutableFile(atPath: dev.path) { return dev }
            probe.deleteLastPathComponent()
        }
        return nil
    }

    /// Make sure something is listening: join a daemon that is, or start one.
    /// Returns once the socket accepts connections, or throws.
    public func ensureRunning(deviceModes: String = "app") throws {
        if UnixSocket.canConnect(path: socketPath) {
            if case .running = state { return }
            state = .external
            onLog?("joined a signetd already listening at \(socketPath)")
            return
        }
        guard let binary else {
            state = .failed("signetd not found. Set SIGNET_DAEMON to its path, or build the workspace.")
            throw DaemonError.notFound
        }

        let process = Process()
        process.executableURL = binary
        process.arguments = ["run", "--device=\(deviceModes)"]
        var env = ProcessInfo.processInfo.environment
        env["COUNTERSIGN_SOCK"] = socketPath
        process.environment = env
        let pipe = Pipe()
        process.standardError = pipe
        process.standardOutput = pipe
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            self?.drain(data)
        }
        process.terminationHandler = { [weak self] p in
            guard let self else { return }
            self.state = .stopped
            self.onLog?("signetd exited with status \(p.terminationStatus)")
            self.onExit?(p.terminationStatus)
        }
        do {
            try process.run()
        } catch {
            state = .failed("could not start \(binary.path): \(error.localizedDescription)")
            throw DaemonError.launch(error.localizedDescription)
        }
        self.process = process
        self.pipe = pipe
        state = .running(pid: process.processIdentifier)

        // The socket appears once the daemon has bound it. Two seconds is
        // generous for a process that prints a banner and listens.
        for _ in 0..<100 {
            if UnixSocket.canConnect(path: socketPath) { return }
            if !process.isRunning {
                state = .failed("signetd exited during startup; see its log")
                throw DaemonError.exitedEarly
            }
            Thread.sleep(forTimeInterval: 0.02)
        }
        state = .failed("signetd started but never listened on \(socketPath)")
        throw DaemonError.neverListened
    }

    public func stop() {
        guard let process, process.isRunning else { return }
        process.terminate()
    }

    /// Stop our daemon and wait until nothing answers on the socket. A daemon
    /// we joined is not ours to stop; this returns at once for it.
    public func stopAndWait() {
        if let process, process.isRunning {
            process.terminate()
            process.waitUntilExit()
        }
        state = .stopped
        for _ in 0..<50 where UnixSocket.canConnect(path: socketPath) {
            Thread.sleep(forTimeInterval: 0.02)
        }
    }

    /// Kill our daemon and start a fresh one — after `signetd pack …`, which
    /// the daemon reads at startup.
    public func restart() throws {
        stopAndWait()
        try ensureRunning()
    }

    private func drain(_ data: Data) {
        partial.append(data)
        while let newline = partial.firstIndex(of: 0x0a) {
            let line = partial.subdata(in: partial.startIndex..<newline)
            partial.removeSubrange(partial.startIndex...newline)
            if let text = String(data: line, encoding: .utf8) { onLog?(text) }
        }
    }
}

public enum DaemonError: Error, CustomStringConvertible {
    case notFound
    case launch(String)
    case exitedEarly
    case neverListened

    public var description: String {
        switch self {
        case .notFound: return "signetd was not found"
        case .launch(let m): return "signetd could not be started: \(m)"
        case .exitedEarly: return "signetd exited during startup"
        case .neverListened: return "signetd started but never listened"
        }
    }
}

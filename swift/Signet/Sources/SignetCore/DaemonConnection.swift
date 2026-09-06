// One JSON-RPC connection to the daemon.
//
// A connection is either a **client** — it calls `device.status`,
// `device.enroll`, and reads answers — or a **device**: it has attached, and
// from then on the daemon pushes `device.present` down it and expects one
// answer per push. The two directions share a socket in the protocol but not
// in this app: the daemon holds its lock across a whole human decision, so an
// `enroll` call has to travel on a different connection from the one that will
// be shown the ceremony. See `signetd::service`.

import CountersignKit
import Foundation

/// Something the daemon pushed to an attached device.
public enum DaemonPush: Equatable {
    /// Show this; answer with `PresentOutcome` under the same id.
    case present(id: Int, params: PresentParams)
    /// Take it down; somebody else answered.
    case withdraw(requestDigest: String)
}

public enum RPCError: Error, CustomStringConvertible, Equatable {
    case daemon(code: Int, message: String)
    case malformed(String)
    case closed

    public var description: String {
        switch self {
        case .daemon(_, let m): return m
        case .malformed(let m): return "unreadable answer from the daemon: \(m)"
        case .closed: return "the daemon closed the connection"
        }
    }
}

public final class DaemonConnection {
    private let socket: UnixSocket
    private let lock = NSLock()
    private var nextID = 1
    private var waiting: [Int: (Result<Any, RPCError>) -> Void] = [:]

    /// Pushes from the daemon, once attached. Delivered on an arbitrary
    /// thread; the app hops to the main actor.
    public var onPush: ((DaemonPush) -> Void)?
    public var onClose: (() -> Void)?

    public init(path: String) throws {
        socket = try UnixSocket(path: path)
        socket.startReading(
            onLine: { [weak self] line in self?.receive(line) },
            onClose: { [weak self] in self?.closed() }
        )
    }

    public func close() { socket.close() }

    // MARK: Calls

    /// Call a method and wait for its result, with a timeout.
    public func call(_ method: String, params: Any? = nil, timeout: TimeInterval = 10) async throws -> Any {
        let id: Int = lock.withLock {
            defer { nextID += 1 }
            return nextID
        }
        var request: [String: Any] = ["jsonrpc": "2.0", "id": id, "method": method]
        if let params { request["params"] = params }
        let line = String(decoding: try JSONSerialization.data(withJSONObject: request), as: UTF8.self)

        return try await withCheckedThrowingContinuation { continuation in
            let done = OneShot()
            lock.withLock {
                waiting[id] = { result in
                    guard done.claim() else { return }
                    continuation.resume(with: result)
                }
            }
            socket.send(line: line)
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { [weak self] in
                guard let self, done.claim() else { return }
                self.lock.withLock { _ = self.waiting.removeValue(forKey: id) }
                continuation.resume(throwing: RPCError.daemon(code: -1, message: "\(method) did not answer within \(Int(timeout)) s"))
            }
        }
    }

    /// Answer a push the daemon made. `result` is the JSON-RPC `result`.
    public func respond(id: Int, result: [String: Any]) {
        let response: [String: Any] = ["jsonrpc": "2.0", "id": id, "result": result]
        if let data = try? JSONSerialization.data(withJSONObject: response) {
            socket.send(line: String(decoding: data, as: UTF8.self))
        }
    }

    // MARK: Typed calls

    public func deviceStatus() async throws -> DeviceStatus {
        try decode(await call("device.status"))
    }

    public func auditSummary() async throws -> AuditSummary {
        try decode(await call("audit.summary"))
    }

    public func attach(_ request: AttachRequest) async throws -> AttachResponse {
        try decode(await call("device.attach", params: try dictionary(request)))
    }

    /// Runs the ceremony. Blocks until the human holds, declines, or the
    /// request expires — on **another** connection, which is being shown it.
    public func enroll(subject: String, display: String?) async throws -> EnrollmentRecord {
        var params: [String: Any] = ["subject": subject]
        if let display, !display.isEmpty { params["display"] = display }
        return try decode(await call("device.enroll", params: params, timeout: 130))
    }

    // MARK: Receiving

    private func receive(_ line: String) {
        guard let data = line.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return }

        if let method = object["method"] as? String {
            // A request or notification from the daemon: a push.
            let params = object["params"]
            switch method {
            case "device.present":
                guard let id = object["id"] as? Int,
                      let params,
                      let paramsData = try? JSONSerialization.data(withJSONObject: params),
                      let decoded = try? JSONDecoder().decode(PresentParams.self, from: paramsData)
                else { return }
                onPush?(.present(id: id, params: decoded))
            case "device.withdraw":
                let digest = (params as? [String: Any])?["request_digest"] as? String ?? ""
                onPush?(.withdraw(requestDigest: digest))
            default:
                break
            }
            return
        }

        // A response to something we called.
        guard let id = object["id"] as? Int else { return }
        let handler: ((Result<Any, RPCError>) -> Void)? = lock.withLock { waiting.removeValue(forKey: id) }
        guard let handler else { return }
        if let error = object["error"] as? [String: Any] {
            handler(.failure(.daemon(
                code: error["code"] as? Int ?? -1,
                message: error["message"] as? String ?? "unknown error")))
        } else {
            handler(.success(object["result"] ?? NSNull()))
        }
    }

    private func closed() {
        let pending: [(Result<Any, RPCError>) -> Void] = lock.withLock {
            let all = Array(waiting.values)
            waiting.removeAll()
            return all
        }
        for handler in pending { handler(.failure(.closed)) }
        onClose?()
    }

    private func decode<T: Decodable>(_ value: Any) throws -> T {
        do {
            let data = try JSONSerialization.data(withJSONObject: value)
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw RPCError.malformed(String(describing: error))
        }
    }

    private func dictionary<T: Encodable>(_ value: T) throws -> Any {
        try JSONSerialization.jsonObject(with: try JSONEncoder().encode(value))
    }
}

/// Resolve a continuation exactly once, whichever of two racers gets there.
final class OneShot {
    private var claimed = false
    private let lock = NSLock()
    func claim() -> Bool {
        lock.withLock {
            if claimed { return false }
            claimed = true
            return true
        }
    }
}

// MARK: The daemon's answer shapes

public struct DeviceStatus: Codable, Equatable {
    public var attached: Bool
    public var device_id: String
    public var kind: String
    public var is_test_key: Bool
    public var counter: UInt64
    public var environments: Int
}

public struct AuditSummary: Codable, Equatable {
    public var entries: Int
    public var head: String
}

public struct AttachResponse: Codable, Equatable {
    public var attached: Bool
    public var device_id: String
    public var enrolled: Bool
    public var hint: String
}

/// `countersign_verify::EnrollmentRecord`, the fields the app shows.
public struct EnrollmentRecord: Codable, Equatable, Identifiable {
    public struct Operator: Codable, Equatable {
        public var subject: String
        public var display: String?
    }
    public struct Status: Codable, Equatable {
        public var state: String
        public var reason: String?
        public var at_unix_ms: UInt64?
    }
    public var device_id: String
    public var public_key_hex: String
    public var `class`: String?
    /// `operator` on the wire — a Swift keyword, so `owner` here.
    public var owner: Operator
    public var enrolled_at_unix_ms: UInt64
    public var status: Status?
    public var is_test_key: Bool?

    enum CodingKeys: String, CodingKey {
        case device_id, public_key_hex, `class`, enrolled_at_unix_ms, status, is_test_key
        case owner = "operator"
    }

    public var id: String { device_id }
    /// Resolves a class-less record the way the verifier does.
    public var resolvedClass: String { `class` ?? ((is_test_key ?? false) ? "test" : "signet") }
    public var isActive: Bool { (status?.state ?? "active") == "active" }
}

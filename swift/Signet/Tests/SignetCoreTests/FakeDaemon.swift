// A daemon-shaped thing on a unix socket, for the tests. It speaks exactly
// enough of `signetd::service` to attach a device, push a presentation to it,
// and collect what comes back.

import Foundation

final class FakeDaemon {
    let path: String
    private let listenFD: Int32
    private var clients: [Int32] = []
    private let lock = NSLock()
    /// Every JSON object any client sent, in order.
    private(set) var received: [[String: Any]] = []
    /// The connection that attached, if any.
    private(set) var attachedFD: Int32?
    private(set) var attachRequest: [String: Any]?
    var enrolled = false
    private let gotResponse = DispatchSemaphore(value: 0)
    private var lastResponse: [String: Any]?

    init() throws {
        path = "/tmp/cs-fake-\(getpid())-\(UInt32.random(in: 0...999_999)).sock"
        unlink(path)
        listenFD = socket(AF_UNIX, SOCK_STREAM, 0)
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            raw.initializeMemory(as: UInt8.self, repeating: 0)
            for (i, b) in path.utf8.enumerated() { raw[i] = b }
        }
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(listenFD, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        precondition(bound == 0, "bind failed: \(errno)")
        precondition(listen(listenFD, 8) == 0)
        Thread { [self] in acceptLoop() }.start()
    }

    private func acceptLoop() {
        while true {
            let fd = accept(listenFD, nil, nil)
            if fd < 0 { return }
            lock.withLock { clients.append(fd) }
            Thread { [self] in serve(fd) }.start()
        }
    }

    private func serve(_ fd: Int32) {
        var buffer = Data()
        var chunk = [UInt8](repeating: 0, count: 65536)
        while true {
            let n = chunk.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!, $0.count) }
            if n <= 0 { return }
            buffer.append(contentsOf: chunk[0..<n])
            while let nl = buffer.firstIndex(of: 0x0a) {
                let line = buffer.subdata(in: buffer.startIndex..<nl)
                buffer.removeSubrange(buffer.startIndex...nl)
                guard let obj = try? JSONSerialization.jsonObject(with: line) as? [String: Any] else { continue }
                lock.withLock { received.append(obj) }
                handle(obj, on: fd)
            }
        }
    }

    private func handle(_ obj: [String: Any], on fd: Int32) {
        guard let method = obj["method"] as? String else {
            // A response to something we pushed.
            lock.withLock { lastResponse = obj }
            gotResponse.signal()
            return
        }
        let id = obj["id"] ?? NSNull()
        switch method {
        case "device.attach":
            let params = obj["params"] as? [String: Any] ?? [:]
            lock.withLock {
                attachedFD = fd
                attachRequest = params
            }
            if (params["class"] as? String) != "enclave" {
                reply(fd, ["jsonrpc": "2.0", "id": id, "error": ["code": -32602, "message": "an app may attach as class enclave only"]])
                return
            }
            reply(fd, ["jsonrpc": "2.0", "id": id, "result": [
                "attached": true, "device_id": params["device_id"] ?? "", "enrolled": enrolled,
                "hint": enrolled ? "enrolled" : "not enrolled",
            ]])
        case "device.status":
            reply(fd, ["jsonrpc": "2.0", "id": id, "result": [
                "attached": true, "device_id": "abc", "kind": "app", "is_test_key": false, "counter": 0, "environments": 1,
            ]])
        case "audit.summary":
            reply(fd, ["jsonrpc": "2.0", "id": id, "result": ["entries": 3, "head": "deadbeef"]])
        case "ping":
            reply(fd, ["jsonrpc": "2.0", "id": id, "result": ["pong": true]])
        default:
            reply(fd, ["jsonrpc": "2.0", "id": id, "error": ["code": -32601, "message": "unknown method \(method)"]])
        }
    }

    private func reply(_ fd: Int32, _ obj: [String: Any]) {
        let data = try! JSONSerialization.data(withJSONObject: obj) + Data("\n".utf8)
        _ = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!, data.count) }
    }

    /// Push a `device.present` to the attached connection.
    func present(id: Int, params: [String: Any]) {
        guard let fd = attachedFD else { preconditionFailure("nothing attached") }
        reply(fd, ["jsonrpc": "2.0", "id": id, "method": "device.present", "params": params])
    }

    func withdraw(digest: String) {
        guard let fd = attachedFD else { return }
        reply(fd, ["jsonrpc": "2.0", "method": "device.withdraw", "params": ["request_digest": digest]])
    }

    /// Wait for the device's answer to a push — off the main actor, because
    /// the app produces that answer *on* the main actor, and a test that
    /// blocked it with a semaphore would be waiting on itself.
    func awaitResponse(timeout: TimeInterval = 5) async -> [String: Any]? {
        await withCheckedContinuation { continuation in
            DispatchQueue.global().async {
                let ok = self.gotResponse.wait(timeout: .now() + timeout) == .success
                continuation.resume(returning: ok ? self.lock.withLock { self.lastResponse } : nil)
            }
        }
    }

    func close() {
        Darwin.close(listenFD)
        lock.withLock { clients.forEach { Darwin.close($0) } }
        unlink(path)
    }
}

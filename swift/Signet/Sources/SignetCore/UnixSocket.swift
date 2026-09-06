// A line-delimited unix-socket client, on POSIX sockets.
//
// Deliberately not the Network framework: a unix endpoint is a path and a
// file descriptor, and the daemon's protocol is one JSON object per line.
// Sixty lines of `read()` on a background thread is the whole transport, and
// it is a transport a reader can check against the daemon's own `service.rs`.

import Foundation

public enum SocketError: Error, CustomStringConvertible {
    case pathTooLong(String)
    case connect(String, errno: Int32)
    case closed

    public var description: String {
        switch self {
        case .pathTooLong(let p): return "socket path is too long for sun_path: \(p)"
        case .connect(let p, let e): return "cannot connect to \(p): \(String(cString: strerror(e)))"
        case .closed: return "the daemon closed the connection"
        }
    }
}

public final class UnixSocket {
    private let fd: Int32
    private let queue = DispatchQueue(label: "signet.socket.write")
    private var reader: Thread?
    private let lock = NSLock()
    private var isOpen = true

    /// Connect, or throw. Nothing is read until `startReading`.
    public init(path: String) throws {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        // 104 on macOS, and the trailing NUL has to fit.
        let capacity = MemoryLayout.size(ofValue: address.sun_path)
        guard bytes.count < capacity else { throw SocketError.pathTooLong(path) }
        withUnsafeMutableBytes(of: &address.sun_path) { raw in
            raw.initializeMemory(as: UInt8.self, repeating: 0)
            for (i, b) in bytes.enumerated() { raw[i] = b }
        }

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw SocketError.connect(path, errno: errno) }
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                Darwin.connect(fd, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else {
            let e = errno
            Darwin.close(fd)
            throw SocketError.connect(path, errno: e)
        }
        self.fd = fd
    }

    /// Whether anything is listening at `path`, without keeping a connection.
    public static func canConnect(path: String) -> Bool {
        guard let probe = try? UnixSocket(path: path) else { return false }
        probe.close()
        return true
    }

    /// Write one line. Serialized, so two callers cannot interleave bytes.
    public func send(line: String) {
        queue.async { [fd] in
            let data = Array((line + "\n").utf8)
            let total = data.count
            var offset = 0
            while offset < total {
                let n = data.withUnsafeBytes { raw in
                    Darwin.write(fd, raw.baseAddress!.advanced(by: offset), total - offset)
                }
                if n <= 0 { return }
                offset += n
            }
        }
    }

    /// Read lines on a background thread until the far end closes. Each
    /// complete line is handed to `onLine`; `onClose` fires once, after.
    public func startReading(onLine: @escaping (String) -> Void, onClose: @escaping () -> Void) {
        let thread = Thread { [fd] in
            var buffer = Data()
            var chunk = [UInt8](repeating: 0, count: 64 * 1024)
            while true {
                let n = chunk.withUnsafeMutableBytes { raw in Darwin.read(fd, raw.baseAddress!, raw.count) }
                if n <= 0 { break }
                buffer.append(contentsOf: chunk[0..<n])
                while let newline = buffer.firstIndex(of: 0x0a) {
                    let lineData = buffer.subdata(in: buffer.startIndex..<newline)
                    buffer.removeSubrange(buffer.startIndex...newline)
                    if let line = String(data: lineData, encoding: .utf8), !line.trimmingCharacters(in: .whitespaces).isEmpty {
                        onLine(line)
                    }
                }
            }
            onClose()
        }
        thread.name = "signet.socket.read"
        thread.start()
        reader = thread
    }

    public func close() {
        lock.lock()
        defer { lock.unlock() }
        guard isOpen else { return }
        isOpen = false
        shutdown(fd, SHUT_RDWR)
        Darwin.close(fd)
    }

    deinit { close() }
}

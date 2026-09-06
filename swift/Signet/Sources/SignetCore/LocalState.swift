// What the app shows that is not on the socket: the roster and the plugins,
// read off the same disk the daemon reads them from.
//
// The app and the daemon are on one machine, and these are the daemon's own
// files. Reading them directly is honest about that; the write path is the
// CLI, which is the same thing the daemon's README tells a person to run.

import Foundation

public struct LocalRoster: Codable, Equatable {
    public var v: Int
    public var records: [EnrollmentRecord]

    public static func load(from url: URL = Paths.rosterPath) -> LocalRoster {
        guard let data = try? Data(contentsOf: url),
              let roster = try? JSONDecoder().decode(LocalRoster.self, from: data)
        else { return LocalRoster(v: 1, records: []) }
        return roster
    }

    public func record(for deviceID: String) -> EnrollmentRecord? {
        records.first { $0.device_id == deviceID }
    }
}

/// One installed plugin: `packs.toml` says whether it is on, the manifest
/// says what it is.
public struct InstalledPlugin: Equatable, Identifiable {
    public struct Manifest: Codable, Equatable {
        public struct Pack: Codable, Equatable {
            public var kind: String
            public var artifact: String
            public var actions: [String]
        }
        public var name: String
        public var version: String
        public var description: String?
        public var pack: Pack?
        public var policy: [JSONBlob]?
    }

    public var name: String
    public var enabled: Bool
    public var manifest: Manifest?

    public var id: String { name }
    public var namespaces: [String] {
        (manifest?.pack?.actions ?? []).map { $0.split(separator: ".").first.map(String.init) ?? $0 }
    }
    public var kind: String { manifest?.pack?.kind ?? "-" }

    public static func loadAll(from dir: URL = Paths.packsDir) -> [InstalledPlugin] {
        let stateURL = dir.appendingPathComponent("packs.toml")
        guard let text = try? String(contentsOf: stateURL, encoding: .utf8) else { return [] }
        return parsePacksToml(text).map { entry in
            let manifestURL = dir.appendingPathComponent(entry.name).appendingPathComponent("countersign-plugin.json")
            let manifest = (try? Data(contentsOf: manifestURL)).flatMap { try? JSONDecoder().decode(Manifest.self, from: $0) }
            return InstalledPlugin(name: entry.name, enabled: entry.enabled, manifest: manifest)
        }
    }

    /// `packs.toml` is written by `signetd pack` and has exactly one shape:
    /// repeated `[[pack]]` tables with `name` and `enabled`. This reads that
    /// shape and nothing more.
    public static func parsePacksToml(_ text: String) -> [(name: String, enabled: Bool)] {
        var out: [(String, Bool)] = []
        var name: String?
        var enabled: Bool?
        func flush() {
            if let n = name { out.append((n, enabled ?? false)) }
            name = nil
            enabled = nil
        }
        for raw in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("#") || line.isEmpty { continue }
            if line == "[[pack]]" { flush(); continue }
            let parts = line.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count == 2 else { continue }
            switch parts[0] {
            case "name": name = parts[1].trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            case "enabled": enabled = parts[1] == "true"
            default: break
            }
        }
        flush()
        return out
    }
}

/// An opaque JSON value kept as-is, for the policy rules a manifest proposes.
public struct JSONBlob: Codable, Equatable {
    public let text: String
    public init(from decoder: Decoder) throws {
        // Round-trip through a generic container to keep the raw shape.
        let value = try decoder.singleValueContainer().decode(AnyJSON.self)
        text = value.rendered
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(text)
    }
}

indirect enum AnyJSON: Decodable {
    case null, bool(Bool), number(Double), string(String), array([AnyJSON]), object([String: AnyJSON])
    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null; return }
        if let b = try? c.decode(Bool.self) { self = .bool(b); return }
        if let n = try? c.decode(Double.self) { self = .number(n); return }
        if let s = try? c.decode(String.self) { self = .string(s); return }
        if let a = try? c.decode([AnyJSON].self) { self = .array(a); return }
        self = .object(try c.decode([String: AnyJSON].self))
    }
    var rendered: String {
        switch self {
        case .null: return "null"
        case .bool(let b): return b ? "true" : "false"
        case .number(let n): return n == n.rounded() ? String(Int64(n)) : String(n)
        case .string(let s): return "\"\(s)\""
        case .array(let a): return "[" + a.map(\.rendered).joined(separator: ", ") + "]"
        case .object(let o): return "{" + o.keys.sorted().map { "\($0) = \(o[$0]!.rendered)" }.joined(separator: ", ") + "}"
        }
    }
}

/// The write path for plugins: the CLI, run as a subprocess.
/// Run a `signetd` subcommand and wait for it. What the daemon's own tools
/// know how to do, the app asks them to do, rather than keeping a second
/// copy of the rules.
public enum DaemonCLI {
    /// Returns what the command printed. Throws with the same text when it
    /// exits non-zero, so the menu can show the daemon's own explanation.
    @discardableResult
    public static func run(_ signetd: URL, _ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = signetd
        process.arguments = arguments
        let pipe = Pipe()
        process.standardError = pipe
        process.standardOutput = pipe
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let text = (String(data: data, encoding: .utf8) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if process.terminationStatus != 0 { throw PackCLIError.failed(text) }
        return text
    }
}

public enum PackCLI {
    public static func setEnabled(_ name: String, _ on: Bool, signetd: URL) throws {
        try DaemonCLI.run(signetd, ["pack", on ? "enable" : "disable", name])
    }
}

public enum PackCLIError: Error, CustomStringConvertible {
    case failed(String)
    public var description: String {
        if case .failed(let m) = self { return m }
        return "pack command failed"
    }
}

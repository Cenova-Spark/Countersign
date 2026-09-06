// Where the daemon keeps things — the same rules `signetd` applies, so the
// app and the daemon agree on a socket without being told.

import Foundation

public enum Paths {
    static var env: [String: String] { ProcessInfo.processInfo.environment }

    /// `~/.config/countersign`, or `$XDG_CONFIG_HOME/countersign`.
    public static var configDir: URL {
        if let xdg = env["XDG_CONFIG_HOME"], !xdg.isEmpty {
            return URL(fileURLWithPath: xdg).appendingPathComponent("countersign")
        }
        return FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".config").appendingPathComponent("countersign")
    }

    /// Mirrors `signetd::daemon::runtime_dir`.
    public static var runtimeDir: URL {
        if let explicit = env["COUNTERSIGN_RUNTIME_DIR"], !explicit.isEmpty {
            return URL(fileURLWithPath: explicit)
        }
        if let xdg = env["XDG_RUNTIME_DIR"], !xdg.isEmpty {
            return URL(fileURLWithPath: xdg).appendingPathComponent("countersign")
        }
        return configDir.appendingPathComponent("run")
    }

    /// Mirrors `signetd::service::socket_path`.
    public static var socketPath: String {
        if let explicit = env["COUNTERSIGN_SOCK"], !explicit.isEmpty { return explicit }
        return runtimeDir.appendingPathComponent("countersign.sock").path
    }

    public static var rosterPath: URL { configDir.appendingPathComponent("roster.json") }

    /// Mirrors `signetd::packs::packs_dir`.
    public static var packsDir: URL {
        if let explicit = env["COUNTERSIGN_PACKS_DIR"], !explicit.isEmpty {
            return URL(fileURLWithPath: explicit)
        }
        return configDir.appendingPathComponent("packs")
    }

    public static var auditDir: URL { configDir.appendingPathComponent("audit") }
}

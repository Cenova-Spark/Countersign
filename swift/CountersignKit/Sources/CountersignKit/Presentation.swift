// What the daemon shows the app, and what the app answers — the shapes on
// the control socket (`signetd::device::Presentation`, `signetd::app`).
//
// The one rule that matters here is `Presentation.verifiedDigest()`: the app
// recomputes `SHA-256(jcs(request_json))` and refuses to render a payload
// whose digest disagrees with the one it was handed. Wire spec §6 requires
// rendering from the bytes that get signed; this is what makes that true when
// the bytes came through a relay or a socket rather than a cable.

import Foundation

public enum RenderRole: String, Codable {
    /// Written by the daemon from local config. Colour-coded by tier.
    case label
    /// From the pack, or the statement verbatim.
    case primary
    /// Unverified. Must carry a visible marker.
    case advisory
    /// The human's cross-check. Written by the daemon.
    case digest
}

public struct RenderLine: Codable, Equatable {
    public var role: RenderRole
    public var text: String
    public init(role: RenderRole, text: String) {
        self.role = role
        self.text = text
    }
}

/// Mirrors `countersign_pack::Severity` and the friction the daemon applies to
/// each (`signetd::device::arm_delay_ms` / `hold_ms`). The daemon sends the
/// resolved numbers too; these are what an app uses when it must decide alone.
public enum Severity: String, Codable, Comparable {
    case none, low, moderate, high, critical

    private var rank: Int {
        switch self {
        case .none: return 0
        case .low: return 1
        case .moderate: return 2
        case .high: return 3
        case .critical: return 4
        }
    }

    public static func < (a: Severity, b: Severity) -> Bool { a.rank < b.rank }

    /// How long a payload must be on screen before a press counts.
    public var armDelayMs: Double {
        switch self {
        case .none, .low: return 400
        case .moderate: return 700
        case .high: return 1_200
        case .critical: return 2_000
        }
    }

    /// How long the hold must be sustained.
    public var holdMs: Double {
        switch self {
        case .none, .low: return 300
        case .moderate: return 800
        case .high: return 2_000
        case .critical: return 5_000
        }
    }
}

public struct Presentation: Codable, Equatable {
    public var render: [RenderLine]
    public var request_digest: String
    /// The request as raw canonical JSON — the bytes the digest covers.
    public var request_json: String
    public var digest_short: String
    public var severity: Severity
    public var requester: String
    public var requester_changed: Bool
    public var ttl_ms: UInt64

    public init(render: [RenderLine], request_digest: String, request_json: String, digest_short: String,
                severity: Severity, requester: String, requester_changed: Bool, ttl_ms: UInt64) {
        self.render = render
        self.request_digest = request_digest
        self.request_json = request_json
        self.digest_short = digest_short
        self.severity = severity
        self.requester = requester
        self.requester_changed = requester_changed
        self.ttl_ms = ttl_ms
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        render = try c.decode([RenderLine].self, forKey: .render)
        request_digest = try c.decode(String.self, forKey: .request_digest)
        request_json = try c.decodeIfPresent(String.self, forKey: .request_json) ?? ""
        digest_short = try c.decode(String.self, forKey: .digest_short)
        // A payload that lost these in transit asks for more, never less.
        severity = try c.decodeIfPresent(Severity.self, forKey: .severity) ?? .critical
        requester = try c.decodeIfPresent(String.self, forKey: .requester) ?? ""
        requester_changed = try c.decodeIfPresent(Bool.self, forKey: .requester_changed) ?? true
        ttl_ms = try c.decode(UInt64.self, forKey: .ttl_ms)
    }

    /// Recompute the digest from the bytes. `false` means something between
    /// the daemon and this screen rewrote the payload, and the only safe
    /// response is to refuse to render it at all — showing it with a warning
    /// invites approving it anyway.
    public func verifiedDigest() -> Bool {
        guard !request_json.isEmpty,
              let computed = try? Countersign.requestDigest(json: request_json)
        else { return false }
        return computed == request_digest
    }

    /// The statement, out of the request bytes.
    public var statement: String? {
        (try? JCS.parse(request_json))?["statement"]?.stringValue
    }

    /// The action verb, out of the request bytes.
    public var action: String? {
        (try? JCS.parse(request_json))?["action"]?.stringValue
    }

    /// Whether this is the enrollment ceremony rather than an approval.
    public var isEnrollment: Bool { action == "countersign.enroll" }
}

/// The params of a `device.present` pushed to an attached app.
public struct PresentParams: Codable, Equatable {
    public var presentation: Presentation
    public var arm_delay_ms: Double
    public var hold_ms: Double
    public var enrollment: Bool

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        presentation = try c.decode(Presentation.self, forKey: .presentation)
        arm_delay_ms = try c.decodeIfPresent(Double.self, forKey: .arm_delay_ms) ?? presentation.severity.armDelayMs
        hold_ms = try c.decodeIfPresent(Double.self, forKey: .hold_ms) ?? presentation.severity.holdMs
        enrollment = try c.decodeIfPresent(Bool.self, forKey: .enrollment) ?? presentation.isEnrollment
    }

    public init(presentation: Presentation, arm_delay_ms: Double, hold_ms: Double, enrollment: Bool) {
        self.presentation = presentation
        self.arm_delay_ms = arm_delay_ms
        self.hold_ms = hold_ms
        self.enrollment = enrollment
    }
}

/// What the app answers a `device.present` with.
public enum PresentOutcome: Equatable {
    case approved(DeviceSignature)
    case aborted
    case expired

    /// The `result` object of the JSON-RPC response.
    public var resultJSON: [String: Any] {
        switch self {
        case .approved(let sig):
            var s: [String: Any] = [
                "device_id": sig.device_id,
                "counter": sig.counter,
                "device_unix_ms": sig.device_unix_ms,
                "signature": sig.signature,
            ]
            if let dwell = sig.dwell_ms { s["dwell_ms"] = dwell }
            return ["outcome": "approved", "signature": s]
        case .aborted: return ["outcome": "aborted"]
        case .expired: return ["outcome": "expired"]
        }
    }
}

/// What the app sends to become a device (`signetd::app::AttachRequest`).
public struct AttachRequest: Codable, Equatable {
    public var device_id: String
    public var public_key_hex: String
    public var name: String
    public var `class`: String

    public init(signer: Signer, name: String) {
        device_id = signer.deviceID
        public_key_hex = Hex.encode(signer.publicKeySEC1)
        self.name = name
        self.class = "enclave"
    }
}

// What signs, and what it owes.
//
// Two implementations. `SoftwareSigner` holds a P-256 key in memory: it is
// for tests and for producing the fixture the Rust side verifies, and it is
// exactly what device-class spec §2 forbids for a real device. `EnclaveDevice`
// (Enclave.swift) is the real one.

import CryptoKit
import Foundation

/// Something holding a P-256 key that can produce a low-S `r || s` signature.
public protocol Signer {
    /// SEC1 uncompressed, 65 bytes.
    var publicKeySEC1: Data { get }
    /// Lowercase hex SHA-256 of `publicKeySEC1`.
    var deviceID: String { get }
    /// Sign `message` with ECDSA-P256-SHA-256, returning `r || s`, normalized
    /// low-S. Implementations MUST normalize; see `Countersign.normalizeLowS`.
    func sign(_ message: Data) throws -> Data
}

/// A key in ordinary memory. **Tests and fixtures only.**
///
/// This is precisely the thing the `enclave` class forbids: a key an agent on
/// the same machine can read. It exists so the gesture rules and the wire
/// format can be exercised without a Secure Enclave, and so a deterministic
/// key can sign the fixture `countersign-verify` checks. Nothing that reaches
/// a user may construct one.
public struct SoftwareSigner: Signer {
    private let key: P256.Signing.PrivateKey

    public init(key: P256.Signing.PrivateKey) {
        self.key = key
    }

    public init() {
        self.init(key: P256.Signing.PrivateKey())
    }

    /// Derive the scalar from a string, the way the published test keys are
    /// derived, so a fixture can name the key it was signed with.
    public init(derivedFrom derivation: String) throws {
        let scalar = SHA256.hash(data: Data(derivation.utf8))
        self.init(key: try P256.Signing.PrivateKey(rawRepresentation: Data(scalar)))
    }

    public var publicKeySEC1: Data { key.publicKey.x963Representation }
    public var deviceID: String { Countersign.deviceID(publicKeySEC1: publicKeySEC1) }

    public func sign(_ message: Data) throws -> Data {
        try Countersign.normalizeLowS(try key.signature(for: message).rawRepresentation)
    }

    /// The raw, un-normalized signature — for tests that need a high-S one.
    public func signWithoutNormalizing(_ message: Data) throws -> Data {
        try key.signature(for: message).rawRepresentation
    }
}

/// Where the monotonic counter lives.
///
/// The counter must be advanced and persisted **before** a signature is
/// released (device-class spec §3.4): a crash between the two loses a
/// signature, never repeats a counter.
public protocol CounterStore {
    /// `nil` when nothing has been stored yet.
    func load() throws -> UInt64?
    func store(_ counter: UInt64) throws
    func clear() throws
}

/// In memory. Tests.
public final class MemoryCounterStore: CounterStore {
    private var value: UInt64?
    public init(_ initial: UInt64? = nil) { value = initial }
    public func load() throws -> UInt64? { value }
    public func store(_ counter: UInt64) throws { value = counter }
    public func clear() throws { value = nil }
}

/// Countersign one digest with any signer, advancing a counter first.
///
/// This is the one place in the package that turns a decision into a
/// signature. The apps call it after the hold commits and the presence check
/// passes; the enrollment ceremony calls it too. There is no second path.
public struct Countersigner {
    public let signer: Signer
    public let counters: CounterStore

    public init(signer: Signer, counters: CounterStore) {
        self.signer = signer
        self.counters = counters
    }

    public func countersign(requestDigestHex: String, dwellMs: UInt64? = nil, now: UInt64 = nowUnixMs()) throws -> DeviceSignature {
        // Advance and persist before signing. If the store fails, no
        // signature exists to have been made with a counter nobody remembers.
        let next = (try counters.load() ?? 0) + 1
        try counters.store(next)
        let tbs = try Countersign.signingPayload(requestDigestHex: requestDigestHex, counter: next, deviceUnixMs: now)
        let signature = try signer.sign(tbs)
        return DeviceSignature(
            device_id: signer.deviceID,
            counter: next,
            device_unix_ms: now,
            signature: Base64URL.encode(signature),
            dwell_ms: dwellMs
        )
    }
}

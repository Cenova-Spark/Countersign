// The digest, the signing payload, and the low-S rule — wire spec §3 and §4.
//
// CryptoKit does the ECDSA. This file does the three things around it that
// every port has to get byte-identical: the digest over the canonical request,
// the bytes a device signs, and the normalization of `s` that CryptoKit — like
// WebCrypto, like RustCrypto — does not do for you.

import CryptoKit
import Foundation

public enum Countersign {
    /// `"countersign-v1" || 0x00` — the domain separator from wire spec §4.
    public static let domain = Data("countersign-v1".utf8) + Data([0])

    /// The order of P-256's base point, big-endian.
    static let order: [UInt8] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
    ]

    /// `n / 2`. A signature with `s` above this is the malleable half.
    static let halfOrder: [UInt8] = [
        0x7f, 0xff, 0xff, 0xff, 0x80, 0x00, 0x00, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xde, 0x73, 0x7d, 0x56, 0xd3, 0x8b, 0xcf, 0x42, 0x79, 0xdc, 0xe5, 0x61, 0x7e, 0x31, 0x92, 0xa8,
    ]

    /// `request_digest = SHA-256(jcs(request))`, lowercase hex — wire spec §3.
    public static func requestDigest(json: String) throws -> String {
        let canonical = try JCS.canonicalize(text: json)
        return Hex.encode(SHA256.hash(data: Data(canonical.utf8)))
    }

    /// The first 12 hex characters, grouped in fours — what the human compares
    /// between their client and the device (wire spec §6.1).
    public static func digestShort(_ digestHex: String) -> String {
        let twelve = String(digestHex.prefix(12))
        var out = ""
        for (i, c) in twelve.enumerated() {
            if i > 0 && i % 4 == 0 { out += " " }
            out.append(c)
        }
        return out
    }

    /// `device_id = SHA-256(0x04 || X || Y)` — wire spec §4.2, over the SEC1
    /// uncompressed encoding. CryptoKit's `x963Representation` **is** that
    /// encoding, prefix included, which is the one thing the spec spends a
    /// page warning firmware authors to get right.
    public static func deviceID(publicKeySEC1: Data) -> String {
        Hex.encode(SHA256.hash(data: publicKeySEC1))
    }

    /// The bytes a device signs: domain separator, the raw digest, then the
    /// counter and the timestamp as big-endian u64 — inside the signature, so
    /// nobody holding the bundle can edit them afterwards.
    public static func signingPayload(requestDigestHex: String, counter: UInt64, deviceUnixMs: UInt64) throws -> Data {
        let digest = try Hex.decode(requestDigestHex)
        guard digest.count == 32 else {
            throw SigningError.badDigestLength(digest.count)
        }
        var out = domain
        out += digest
        out += Data.bigEndian(counter, length: 8)
        out += Data.bigEndian(deviceUnixMs, length: 8)
        return out
    }

    /// Whether `s` is in the low half of the order — what a verifier checks.
    public static func isLowS(_ signature: Data) -> Bool {
        guard signature.count == 64 else { return false }
        let r = signature.subdata(in: 0..<32)
        let s = signature.subdata(in: 32..<64)
        if r.allSatisfy({ $0 == 0 }) || s.allSatisfy({ $0 == 0 }) { return false }
        return compare(Array(s), halfOrder) <= 0
    }

    /// Force `s` into the low half. **Required of signers** by wire spec §4,
    /// and the half everyone forgets: CryptoKit emits whichever `s` the
    /// arithmetic produces, so a signer that skips this works about half the
    /// time — far worse to debug than one that never works.
    public static func normalizeLowS(_ signature: Data) throws -> Data {
        guard signature.count == 64 else { throw SigningError.badSignatureLength(signature.count) }
        let s = Array(signature.subdata(in: 32..<64))
        if compare(s, halfOrder) <= 0 { return signature }
        return signature.subdata(in: 0..<32) + Data(subtract(order, s))
    }

    /// Verify an ECDSA-P256-SHA-256 signature in `r || s` form over `message`.
    public static func verify(publicKeySEC1: Data, message: Data, signature: Data) -> Bool {
        guard let key = try? P256.Signing.PublicKey(x963Representation: publicKeySEC1),
              let sig = try? P256.Signing.ECDSASignature(rawRepresentation: signature)
        else { return false }
        return key.isValidSignature(sig, for: message)
    }

    // MARK: 256-bit arithmetic on byte arrays, big-endian

    /// −1, 0, +1 as `a` compares to `b`. Both 32 bytes.
    static func compare(_ a: [UInt8], _ b: [UInt8]) -> Int {
        for (x, y) in zip(a, b) where x != y {
            return x < y ? -1 : 1
        }
        return 0
    }

    /// `a − b`, both 32 bytes, `a ≥ b`.
    static func subtract(_ a: [UInt8], _ b: [UInt8]) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: 32)
        var borrow = 0
        for i in stride(from: 31, through: 0, by: -1) {
            var d = Int(a[i]) - Int(b[i]) - borrow
            if d < 0 {
                d += 256
                borrow = 1
            } else {
                borrow = 0
            }
            out[i] = UInt8(d)
        }
        return out
    }
}

public enum SigningError: Error, Equatable, CustomStringConvertible {
    case badDigestLength(Int)
    case badSignatureLength(Int)
    case enclaveUnavailable
    case keyNotEnclaveResident
    /// The counter's continuity could not be established, so the key was
    /// discarded and must be re-enrolled — device-class spec §3.4.
    case counterContinuityLost
    case keychain(OSStatus)
    case noKey

    public var description: String {
        switch self {
        case .badDigestLength(let n): return "request_digest is \(n) bytes, expected 32"
        case .badSignatureLength(let n): return "signature is \(n) bytes, expected 64"
        case .enclaveUnavailable: return "this device has no Secure Enclave, so it cannot approve"
        case .keyNotEnclaveResident: return "the key is not enclave-resident and may not be enrolled"
        case .counterContinuityLost:
            return "the counter's continuity could not be established; the key was discarded and must be re-enrolled"
        case .keychain(let status): return "keychain error \(status)"
        case .noKey: return "no signing key exists yet"
        }
    }
}

/// One signature over a request digest, in the shape wire spec §5 names.
public struct DeviceSignature: Codable, Equatable {
    public var device_id: String
    public var counter: UInt64
    public var device_unix_ms: UInt64
    /// base64url unpadded, `r || s`, low-S.
    public var signature: String
    /// Telemetry, never evidence (wire spec §5.3).
    public var dwell_ms: UInt64?

    public init(device_id: String, counter: UInt64, device_unix_ms: UInt64, signature: String, dwell_ms: UInt64? = nil) {
        self.device_id = device_id
        self.counter = counter
        self.device_unix_ms = device_unix_ms
        self.signature = signature
        self.dwell_ms = dwell_ms
    }
}

public func nowUnixMs() -> UInt64 {
    UInt64(Date().timeIntervalSince1970 * 1000)
}

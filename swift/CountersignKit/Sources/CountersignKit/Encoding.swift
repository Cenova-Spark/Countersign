// Hex and base64url, strictly.
//
// Same rule as the SDK's encoding.ts: every decoder validates before it
// decodes. In a protocol that hashes its own fields, accepting two spellings
// of the same bytes is how one request ends up with two digests.

import Foundation

public enum EncodingError: Error, Equatable, CustomStringConvertible {
    case oddHexLength
    case notHex
    case notBase64URL
    case impossibleBase64URLLength
    case base64URLTrailingBits
    case valueTooLarge(bytes: Int)

    public var description: String {
        switch self {
        case .oddHexLength: return "hex string has an odd length"
        case .notHex: return "not valid hex"
        case .notBase64URL: return "not valid unpadded base64url (padding and +/ are refused)"
        case .impossibleBase64URLLength: return "impossible base64url length"
        case .base64URLTrailingBits: return "base64url did not round-trip; input has trailing bits"
        case .valueTooLarge(let bytes): return "value does not fit in \(bytes) bytes"
        }
    }
}

public enum Hex {
    /// Lowercase hex.
    public static func encode<S: Sequence>(_ bytes: S) -> String where S.Element == UInt8 {
        var out = String()
        out.reserveCapacity(bytes.underestimatedCount * 2)
        for b in bytes {
            out.append(Self.digits[Int(b >> 4)])
            out.append(Self.digits[Int(b & 0x0f)])
        }
        return out
    }

    public static func decode(_ text: String) throws -> Data {
        let scalars = Array(text.utf8)
        guard scalars.count % 2 == 0 else { throw EncodingError.oddHexLength }
        var out = Data(capacity: scalars.count / 2)
        var i = 0
        while i < scalars.count {
            guard let hi = Self.value(scalars[i]), let lo = Self.value(scalars[i + 1]) else {
                throw EncodingError.notHex
            }
            out.append(hi << 4 | lo)
            i += 2
        }
        return out
    }

    private static let digits: [Character] = Array("0123456789abcdef")

    private static func value(_ c: UInt8) -> UInt8? {
        switch c {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return c - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): return c - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"): return c - UInt8(ascii: "A") + 10
        default: return nil
        }
    }
}

public enum Base64URL {
    /// Unpadded base64url — what the spec names for nonces and signatures.
    public static func encode<D: DataProtocol>(_ bytes: D) -> String {
        Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Decode unpadded base64url. Padding and the standard alphabet are refused.
    public static func decode(_ text: String) throws -> Data {
        for c in text.utf8 {
            let ok = (c >= UInt8(ascii: "A") && c <= UInt8(ascii: "Z"))
                || (c >= UInt8(ascii: "a") && c <= UInt8(ascii: "z"))
                || (c >= UInt8(ascii: "0") && c <= UInt8(ascii: "9"))
                || c == UInt8(ascii: "-") || c == UInt8(ascii: "_")
            guard ok else { throw EncodingError.notBase64URL }
        }
        guard text.count % 4 != 1 else { throw EncodingError.impossibleBase64URLLength }
        let padded = text
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            + String(repeating: "=", count: (4 - text.count % 4) % 4)
        guard let out = Data(base64Encoded: padded) else { throw EncodingError.notBase64URL }
        // Round-trip: Foundation decodes input it should have refused.
        guard encode(out) == text else { throw EncodingError.base64URLTrailingBits }
        return out
    }
}

extension Data {
    /// Big-endian bytes of `value`, left-padded to `length`.
    static func bigEndian(_ value: UInt64, length: Int) -> Data {
        var out = Data(repeating: 0, count: length)
        var v = value
        for i in stride(from: length - 1, through: 0, by: -1) {
            out[i] = UInt8(v & 0xff)
            v >>= 8
        }
        return out
    }
}

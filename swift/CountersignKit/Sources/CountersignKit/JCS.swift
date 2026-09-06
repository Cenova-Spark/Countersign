// RFC 8785 (JSON Canonicalization Scheme), restricted to integers.
//
// A port of web/src/lib/jcs.js, which is a port of the SDK's jcs.ts, which is
// a port of countersign-verify's jcs.rs. Canonicalization is where two
// implementations disagree silently and a valid approval fails to verify, so
// it is written out rather than depended on, and checked against the same
// committed vectors the others are.
//
// This one carries its own JSON parser rather than going through
// `JSONSerialization`, for three reasons that each cost a subtle bug
// otherwise: Foundation keeps the *last* of a duplicate key and says nothing;
// it hands numbers back as `NSNumber`, where `1`, `1.0` and `true` are hard to
// tell apart; and it accepts some inputs RFC 8259 does not. Two hundred lines
// of parser is cheaper than any one of those going wrong under a signature.

import Foundation

public enum JCSError: Error, Equatable, CustomStringConvertible {
    /// A number that is not an integer within ±(2^53 − 1). The v1 profile
    /// canonicalizes integers only.
    case unsupportedNumber(String)
    /// The same key twice in one object.
    case duplicateKey(String)
    case malformed(String)

    /// The kind names the vector files use.
    public var kind: String {
        switch self {
        case .unsupportedNumber: return "unsupported_number"
        case .duplicateKey: return "duplicate_key"
        case .malformed: return "malformed"
        }
    }

    public var description: String {
        switch self {
        case .unsupportedNumber(let n):
            return "number \(n) is not an integer within ±(2^53-1); Countersign v1 canonicalizes integers only"
        case .duplicateKey(let k): return "duplicate object key \"\(k)\""
        case .malformed(let m): return "malformed JSON: \(m)"
        }
    }
}

/// A parsed JSON value, integers only.
public indirect enum JSONValue: Equatable {
    case null
    case bool(Bool)
    case int(Int64)
    case string(String)
    case array([JSONValue])
    /// Insertion order is kept; canonicalization sorts on output.
    case object([(key: String, value: JSONValue)])

    public static func == (lhs: JSONValue, rhs: JSONValue) -> Bool {
        switch (lhs, rhs) {
        case (.null, .null): return true
        case (.bool(let a), .bool(let b)): return a == b
        case (.int(let a), .int(let b)): return a == b
        case (.string(let a), .string(let b)): return a == b
        case (.array(let a), .array(let b)): return a == b
        case (.object(let a), .object(let b)):
            return a.count == b.count && zip(a, b).allSatisfy { $0.key == $1.key && $0.value == $1.value }
        default: return false
        }
    }

    public subscript(key: String) -> JSONValue? {
        if case .object(let members) = self {
            return members.first(where: { $0.key == key })?.value
        }
        return nil
    }

    public var stringValue: String? {
        if case .string(let s) = self { return s }
        return nil
    }

    public var intValue: Int64? {
        if case .int(let i) = self { return i }
        return nil
    }

    public var boolValue: Bool? {
        if case .bool(let b) = self { return b }
        return nil
    }

    public var arrayValue: [JSONValue]? {
        if case .array(let a) = self { return a }
        return nil
    }
}

public enum JCS {
    /// The largest integer every JSON implementation agrees about: 2^53 − 1.
    public static let safeIntegerMax: Int64 = 9_007_199_254_740_991

    /// Canonicalize JSON text: parse strictly, then emit RFC 8785 form.
    public static func canonicalize(text: String) throws -> String {
        canonicalize(try parse(text))
    }

    /// Canonicalize an already-parsed value.
    public static func canonicalize(_ value: JSONValue) -> String {
        var out = String()
        write(value, into: &out)
        return out
    }

    /// Parse JSON text, refusing duplicate keys and non-integer numbers.
    public static func parse(_ text: String) throws -> JSONValue {
        var parser = Parser(Array(text.utf8))
        parser.skipWhitespace()
        let value = try parser.value()
        parser.skipWhitespace()
        guard parser.atEnd else { throw JCSError.malformed("trailing characters after the value") }
        return value
    }

    // MARK: Writing

    private static func write(_ value: JSONValue, into out: inout String) {
        switch value {
        case .null: out += "null"
        case .bool(let b): out += b ? "true" : "false"
        case .int(let i): out += String(i)
        case .string(let s): writeString(s, into: &out)
        case .array(let items):
            out += "["
            for (index, item) in items.enumerated() {
                if index > 0 { out += "," }
                write(item, into: &out)
            }
            out += "]"
        case .object(let members):
            // Sorted by UTF-16 code unit, not by Unicode scalar and not by
            // UTF-8 byte. The three differ above the BMP: U+FFFD sorts before
            // U+10000 by scalar, after it by UTF-16, because the latter
            // begins with a surrogate. Swift's default `<` on String is not
            // this, so it is written out.
            let sorted = members.sorted { a, b in utf16Less(a.key, b.key) }
            out += "{"
            for (index, member) in sorted.enumerated() {
                if index > 0 { out += "," }
                writeString(member.key, into: &out)
                out += ":"
                write(member.value, into: &out)
            }
            out += "}"
        }
    }

    static func utf16Less(_ a: String, _ b: String) -> Bool {
        a.utf16.lexicographicallyPrecedes(b.utf16)
    }

    /// RFC 8785 escaping: only `"`, `\` and C0 controls; the short forms where
    /// they exist; `\u00xx` with lowercase hex otherwise. `/` is not escaped,
    /// and non-ASCII travels as UTF-8.
    private static func writeString(_ s: String, into out: inout String) {
        out += "\""
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\u{08}": out += "\\b"
            case "\t": out += "\\t"
            case "\n": out += "\\n"
            case "\u{0C}": out += "\\f"
            case "\r": out += "\\r"
            default:
                if scalar.value < 0x20 {
                    out += "\\u" + String(format: "%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        out += "\""
    }

    // MARK: Parsing

    private struct Parser {
        let bytes: [UInt8]
        var i = 0

        init(_ bytes: [UInt8]) { self.bytes = bytes }

        var atEnd: Bool { i >= bytes.count }

        mutating func skipWhitespace() {
            while i < bytes.count, bytes[i] == 0x20 || bytes[i] == 0x09 || bytes[i] == 0x0a || bytes[i] == 0x0d {
                i += 1
            }
        }

        mutating func value() throws -> JSONValue {
            guard i < bytes.count else { throw JCSError.malformed("unexpected end of input") }
            switch bytes[i] {
            case UInt8(ascii: "{"): return try object()
            case UInt8(ascii: "["): return try array()
            case UInt8(ascii: "\""): return .string(try string())
            case UInt8(ascii: "t"): try literal("true"); return .bool(true)
            case UInt8(ascii: "f"): try literal("false"); return .bool(false)
            case UInt8(ascii: "n"): try literal("null"); return .null
            case UInt8(ascii: "-"), UInt8(ascii: "0")...UInt8(ascii: "9"): return try number()
            default:
                throw JCSError.malformed("unexpected character at offset \(i)")
            }
        }

        mutating func literal(_ word: String) throws {
            let w = Array(word.utf8)
            guard i + w.count <= bytes.count, Array(bytes[i..<(i + w.count)]) == w else {
                throw JCSError.malformed("invalid literal at offset \(i)")
            }
            i += w.count
        }

        mutating func object() throws -> JSONValue {
            i += 1 // {
            var members: [(key: String, value: JSONValue)] = []
            var seen = Set<String>()
            skipWhitespace()
            if i < bytes.count, bytes[i] == UInt8(ascii: "}") {
                i += 1
                return .object(members)
            }
            while true {
                skipWhitespace()
                guard i < bytes.count, bytes[i] == UInt8(ascii: "\"") else {
                    throw JCSError.malformed("expected a string key at offset \(i)")
                }
                let key = try string()
                // RFC 8785 requires rejection. Two parsers can otherwise
                // disagree about which of `{"ttl_ms":1,"ttl_ms":999999}`
                // wins, with the disagreement chosen by whoever sent it.
                guard !seen.contains(key) else { throw JCSError.duplicateKey(key) }
                seen.insert(key)
                skipWhitespace()
                guard i < bytes.count, bytes[i] == UInt8(ascii: ":") else {
                    throw JCSError.malformed("expected ':' at offset \(i)")
                }
                i += 1
                skipWhitespace()
                members.append((key: key, value: try value()))
                skipWhitespace()
                guard i < bytes.count else { throw JCSError.malformed("unterminated object") }
                if bytes[i] == UInt8(ascii: ",") { i += 1; continue }
                if bytes[i] == UInt8(ascii: "}") { i += 1; return .object(members) }
                throw JCSError.malformed("expected ',' or '}' at offset \(i)")
            }
        }

        mutating func array() throws -> JSONValue {
            i += 1 // [
            var items: [JSONValue] = []
            skipWhitespace()
            if i < bytes.count, bytes[i] == UInt8(ascii: "]") {
                i += 1
                return .array(items)
            }
            while true {
                skipWhitespace()
                items.append(try value())
                skipWhitespace()
                guard i < bytes.count else { throw JCSError.malformed("unterminated array") }
                if bytes[i] == UInt8(ascii: ",") { i += 1; continue }
                if bytes[i] == UInt8(ascii: "]") { i += 1; return .array(items) }
                throw JCSError.malformed("expected ',' or ']' at offset \(i)")
            }
        }

        mutating func string() throws -> String {
            i += 1 // opening quote
            var scalars = String.UnicodeScalarView()
            while i < bytes.count {
                let b = bytes[i]
                if b == UInt8(ascii: "\"") {
                    i += 1
                    return String(scalars)
                }
                if b == UInt8(ascii: "\\") {
                    i += 1
                    guard i < bytes.count else { break }
                    let e = bytes[i]
                    i += 1
                    switch e {
                    case UInt8(ascii: "\""): scalars.append("\"")
                    case UInt8(ascii: "\\"): scalars.append("\\")
                    case UInt8(ascii: "/"): scalars.append("/")
                    case UInt8(ascii: "b"): scalars.append("\u{08}")
                    case UInt8(ascii: "f"): scalars.append("\u{0C}")
                    case UInt8(ascii: "n"): scalars.append("\n")
                    case UInt8(ascii: "r"): scalars.append("\r")
                    case UInt8(ascii: "t"): scalars.append("\t")
                    case UInt8(ascii: "u"):
                        var unit = try hex4()
                        // A surrogate pair arrives as two escapes.
                        if (0xD800...0xDBFF).contains(unit) {
                            guard i + 1 < bytes.count, bytes[i] == UInt8(ascii: "\\"), bytes[i + 1] == UInt8(ascii: "u") else {
                                throw JCSError.malformed("lone high surrogate")
                            }
                            i += 2
                            let low = try hex4()
                            guard (0xDC00...0xDFFF).contains(low) else { throw JCSError.malformed("invalid surrogate pair") }
                            unit = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)
                        } else if (0xDC00...0xDFFF).contains(unit) {
                            throw JCSError.malformed("lone low surrogate")
                        }
                        guard let scalar = Unicode.Scalar(unit) else { throw JCSError.malformed("invalid escape") }
                        scalars.append(scalar)
                    default:
                        throw JCSError.malformed("invalid escape at offset \(i)")
                    }
                    continue
                }
                if b < 0x20 { throw JCSError.malformed("control character in string") }
                // Multi-byte UTF-8: decode one scalar.
                let (scalar, width) = try utf8Scalar(at: i)
                scalars.append(scalar)
                i += width
            }
            throw JCSError.malformed("unterminated string")
        }

        mutating func hex4() throws -> UInt32 {
            guard i + 4 <= bytes.count else { throw JCSError.malformed("short \\u escape") }
            var v: UInt32 = 0
            for k in 0..<4 {
                let c = bytes[i + k]
                let d: UInt32
                switch c {
                case UInt8(ascii: "0")...UInt8(ascii: "9"): d = UInt32(c - UInt8(ascii: "0"))
                case UInt8(ascii: "a")...UInt8(ascii: "f"): d = UInt32(c - UInt8(ascii: "a") + 10)
                case UInt8(ascii: "A")...UInt8(ascii: "F"): d = UInt32(c - UInt8(ascii: "A") + 10)
                default: throw JCSError.malformed("invalid \\u escape")
                }
                v = v << 4 | d
            }
            i += 4
            return v
        }

        func utf8Scalar(at start: Int) throws -> (Unicode.Scalar, Int) {
            let b0 = bytes[start]
            let width: Int
            switch b0 {
            case 0x00...0x7F: width = 1
            case 0xC2...0xDF: width = 2
            case 0xE0...0xEF: width = 3
            case 0xF0...0xF4: width = 4
            default: throw JCSError.malformed("invalid UTF-8")
            }
            guard start + width <= bytes.count else { throw JCSError.malformed("truncated UTF-8") }
            var decoder = UTF8()
            var iterator = bytes[start..<(start + width)].makeIterator()
            switch decoder.decode(&iterator) {
            case .scalarValue(let s): return (s, width)
            default: throw JCSError.malformed("invalid UTF-8")
            }
        }

        mutating func number() throws -> JSONValue {
            let start = i
            if bytes[i] == UInt8(ascii: "-") { i += 1 }
            guard i < bytes.count, (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(bytes[i]) else {
                throw JCSError.malformed("invalid number")
            }
            if bytes[i] == UInt8(ascii: "0") {
                i += 1
            } else {
                while i < bytes.count, (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(bytes[i]) { i += 1 }
            }
            var integral = true
            if i < bytes.count, bytes[i] == UInt8(ascii: ".") {
                integral = false
                i += 1
                while i < bytes.count, (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(bytes[i]) { i += 1 }
            }
            if i < bytes.count, bytes[i] == UInt8(ascii: "e") || bytes[i] == UInt8(ascii: "E") {
                integral = false
                i += 1
                if i < bytes.count, bytes[i] == UInt8(ascii: "+") || bytes[i] == UInt8(ascii: "-") { i += 1 }
                while i < bytes.count, (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(bytes[i]) { i += 1 }
            }
            let text = String(decoding: bytes[start..<i], as: UTF8.self)
            // Fractions and exponents are refused even when their value would
            // be integral: RFC 8785's number rule is a shortest-round-trip
            // double formatter, which is the one cross-language disagreement
            // this profile exists to avoid.
            guard integral, let value = Int64(text), abs(value) <= JCS.safeIntegerMax else {
                throw JCSError.unsupportedNumber(text)
            }
            return .int(value)
        }
    }
}

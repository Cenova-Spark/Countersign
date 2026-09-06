// Low-S, the counter, and the fourth signer in the repository that has to get
// both right by hand.

import Foundation
import Testing
@testable import CountersignKit

@Suite("low-S")
struct LowS {
    @Test func cryptoKitDoesNotNormalizeAndThisPackageDoes() throws {
        // Many signatures, not one: a single low-S result proves nothing
        // (wire spec §4). Over two hundred, roughly half come out high-S from
        // CryptoKit, and every one leaves this package low-S and still valid.
        let signer = SoftwareSigner()
        var sawHighS = false
        for i in 0..<200 {
            let message = Data("message \(i)".utf8)
            // ECDSA nonces are randomized in CryptoKit, so two calls to sign
            // give two different signatures; normalize *this* one and compare
            // it to itself.
            let raw = try signer.signWithoutNormalizing(message)
            if !Countersign.isLowS(raw) { sawHighS = true }
            let normalized = try Countersign.normalizeLowS(raw)
            #expect(Countersign.isLowS(normalized))
            #expect(Countersign.verify(publicKeySEC1: signer.publicKeySEC1, message: message, signature: normalized))
            // Normalizing never changes r, and never changes an already-low s.
            #expect(normalized.prefix(32) == raw.prefix(32))
            if Countersign.isLowS(raw) { #expect(normalized == raw) }
            // And the signer's own output is always low-S.
            #expect(Countersign.isLowS(try signer.sign(message)))
        }
        #expect(sawHighS, "two hundred low-S signatures in a row from CryptoKit is astronomically unlikely")
    }

    @Test func theBoundaryIsInclusiveAndZeroIsNotASignature() throws {
        var atHalf = Data(repeating: 0, count: 32)
        atHalf[31] = 1
        atHalf += Data(Countersign.halfOrder)
        #expect(Countersign.isLowS(atHalf))
        #expect(try Countersign.normalizeLowS(atHalf) == atHalf)

        var justOver = Data(repeating: 0, count: 32)
        justOver[31] = 1
        var s = Countersign.halfOrder
        s[31] += 1
        justOver += Data(s)
        #expect(!Countersign.isLowS(justOver))
        let fixed = try Countersign.normalizeLowS(justOver)
        #expect(Countersign.isLowS(fixed))
        // n − (n/2 + 1) == n/2, so the fixed s is exactly the half order.
        #expect(Array(fixed.suffix(32)) == Countersign.halfOrder)

        #expect(!Countersign.isLowS(Data(repeating: 0, count: 64)))
    }

    @Test func aWrongLengthIsRefusedNotPadded() {
        #expect(throws: SigningError.badSignatureLength(63)) {
            try Countersign.normalizeLowS(Data(repeating: 1, count: 63))
        }
        #expect(throws: SigningError.badDigestLength(31)) {
            try Countersign.signingPayload(requestDigestHex: String(repeating: "ab", count: 31), counter: 1, deviceUnixMs: 1)
        }
    }
}

@Suite("the countersigner")
struct CountersignerRules {
    @Test func theCounterAdvancesAndPersistsBeforeTheSignatureExists() throws {
        let store = MemoryCounterStore(41)
        let signer = SoftwareSigner()
        let cs = Countersigner(signer: signer, counters: store)
        let digest = String(repeating: "ab", count: 32)

        let sig = try cs.countersign(requestDigestHex: digest, dwellMs: 2140, now: 1_755_859_200_123)
        #expect(sig.counter == 42)
        #expect(try store.load() == 42)
        #expect(sig.device_id == signer.deviceID)
        #expect(sig.dwell_ms == 2140)

        let tbs = try Countersign.signingPayload(requestDigestHex: digest, counter: 42, deviceUnixMs: 1_755_859_200_123)
        let raw = try Base64URL.decode(sig.signature)
        #expect(Countersign.isLowS(raw))
        #expect(Countersign.verify(publicKeySEC1: signer.publicKeySEC1, message: tbs, signature: raw))

        // Never repeats.
        #expect(try cs.countersign(requestDigestHex: digest).counter == 43)
    }

    @Test func aCounterThatCannotBePersistedProducesNoSignature() throws {
        final class Broken: CounterStore {
            struct Disk: Error {}
            func load() throws -> UInt64? { 7 }
            func store(_ counter: UInt64) throws { throw Disk() }
            func clear() throws {}
        }
        let cs = Countersigner(signer: SoftwareSigner(), counters: Broken())
        #expect(throws: Broken.Disk.self) {
            try cs.countersign(requestDigestHex: String(repeating: "cd", count: 32))
        }
    }
}

@Suite("key and counter live and die together")
struct Continuity {
    @Test func theBindingTable() {
        // Device-class spec §3.4. A key whose counter is missing is discarded,
        // because a counter that could restart under the same device_id
        // defeats the replay defence, and one that restarts under a new id is
        // simply a new device.
        #expect(KeyContinuity.decide(keyExists: true, counterExists: true) == .useExisting)
        #expect(KeyContinuity.decide(keyExists: false, counterExists: false) == .generateFresh)
        #expect(KeyContinuity.decide(keyExists: false, counterExists: true) == .generateFresh)
        #expect(KeyContinuity.decide(keyExists: true, counterExists: false) == .continuityLost)
    }
}

@Suite("the keychain item")
struct KeychainItems {
    @Test func whatIsWrittenIsReadBackAndADeleteTakesItAway() throws {
        // The bug this pins: a lookup and a write that landed in different
        // keychains, so a key written at one launch was not found at the
        // next. Whichever keychain this process was given, the round trip
        // must close.
        let item = KeychainItem(service: "com.addisdb.countersign.tests", account: "round-trip-\(getpid())")
        defer { try? item.delete() }
        #expect(try item.read() == nil)
        try item.write(Data([1, 2, 3]))
        #expect(try item.read() == Data([1, 2, 3]))
        try item.write(Data([4]))
        #expect(try item.read() == Data([4]), "a second write updates, it does not duplicate")
        try item.delete()
        #expect(try item.read() == nil)
        try item.delete()
    }
}

@Suite("encoding")
struct Encoding {
    @Test func base64urlIsStrict() throws {
        #expect(Base64URL.encode(Data([0xfb, 0xff])) == "-_8")
        #expect(try Base64URL.decode("-_8") == Data([0xfb, 0xff]))
        #expect(throws: EncodingError.notBase64URL) { try Base64URL.decode("+/8=") }
        #expect(throws: EncodingError.impossibleBase64URLLength) { try Base64URL.decode("abcde") }
        // Trailing bits that do not round-trip are refused.
        #expect(throws: EncodingError.base64URLTrailingBits) { try Base64URL.decode("-_9") }
    }

    @Test func hexIsStrictAndLowercase() throws {
        #expect(Hex.encode(Data([0x00, 0xab, 0xff])) == "00abff")
        #expect(try Hex.decode("00ABff") == Data([0x00, 0xab, 0xff]))
        #expect(throws: EncodingError.oddHexLength) { try Hex.decode("abc") }
        #expect(throws: EncodingError.notHex) { try Hex.decode("zz") }
    }
}

// The enclave device — what makes an approval from this app class `enclave`.
//
// Device-class spec §3 is the contract this file implements:
//
//   §3.1  The key is generated in the Secure Enclave, non-extractable, and
//         every use requires an OS presence check bound to the *current*
//         biometric set. No passcode fallback — on a Mac the requester may be
//         running as the same user, and a passcode can be typed by software
//         with the right permission; a fingerprint cannot.
//   §3.4  The counter lives in a ThisDeviceOnly keychain item and is bound to
//         the key: if the key exists and the counter does not, continuity is
//         gone, and the key is discarded rather than reused under an id whose
//         counter might repeat. A new key is a new device; every verifier
//         already handles that.
//
// What this cannot do is prove to anyone else that the key really is in an
// enclave. That attestation is reserved, not specified (device-class spec §4).

import CryptoKit
import Foundation
import Security

/// The Secure Enclave key and its counter, together.
public final class EnclaveDevice: Signer {
    /// Namespaces the keychain items, so two apps on one Mac do not share a
    /// device.
    public let service: String
    private let keyStore: KeychainItem
    private let counters: CounterStore
    private var key: SecureEnclave.P256.Signing.PrivateKey

    /// Load the existing device, or generate one.
    ///
    /// Throws `.counterContinuityLost` when a key was found but its counter
    /// was not: the key has been deleted and the caller must enroll a fresh one.
    /// Throws `.enclaveUnavailable` on hardware without a Secure Enclave — the
    /// app may still display and acknowledge; it may not approve.
    public init(service: String = "com.addisdb.signet") throws {
        guard SecureEnclave.isAvailable else { throw SigningError.enclaveUnavailable }
        self.service = service
        self.keyStore = KeychainItem(service: service, account: "enclave-signing-key")
        let counterItem = KeychainItem(service: service, account: "enclave-counter")
        self.counters = KeychainCounterStore(item: counterItem)

        if let existing = try keyStore.read() {
            // Key and counter live and die together (§3.4).
            guard try counters.load() != nil else {
                try keyStore.delete()
                throw SigningError.counterContinuityLost
            }
            self.key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: existing)
        } else {
            // A fresh key gets a fresh counter, written first so the
            // invariant above holds from the first millisecond.
            try counters.clear()
            let fresh = try Self.generate()
            try counters.store(0)
            try keyStore.write(fresh.dataRepresentation)
            self.key = fresh
        }
    }

    /// The access control the class requires: enclave use only, and the
    /// current biometric set, with nothing to fall back to.
    static func accessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &error
        ) else {
            throw SigningError.keychain(OSStatus(errSecParam))
        }
        return control
    }

    static func generate() throws -> SecureEnclave.P256.Signing.PrivateKey {
        try SecureEnclave.P256.Signing.PrivateKey(accessControl: try accessControl())
    }

    public var publicKeySEC1: Data { key.publicKey.x963Representation }
    public var deviceID: String { Countersign.deviceID(publicKeySEC1: publicKeySEC1) }

    /// Sign. The Secure Enclave runs the biometric prompt itself as part of
    /// this call; a failed or cancelled check throws and nothing is signed.
    public func sign(_ message: Data) throws -> Data {
        try Countersign.normalizeLowS(try key.signature(for: message).rawRepresentation)
    }

    /// The countersigner over this key and its bound counter.
    public var countersigner: Countersigner {
        Countersigner(signer: self, counters: counters)
    }

    /// Forget the key and the counter — the user's explicit decision, never
    /// an app's tidy-up. After this the device must be enrolled again.
    public func reset() throws {
        try keyStore.delete()
        try counters.clear()
    }
}

/// The counter in a keychain item, `ThisDeviceOnly` so a backup restored to
/// another device does not clone it (device-class spec §3.4).
public final class KeychainCounterStore: CounterStore {
    private let item: KeychainItem

    public init(item: KeychainItem) { self.item = item }

    public func load() throws -> UInt64? {
        guard let data = try item.read(), data.count == 8 else { return nil }
        return data.withUnsafeBytes { $0.load(as: UInt64.self).bigEndian }
    }

    public func store(_ counter: UInt64) throws {
        try item.write(Data.bigEndian(counter, length: 8))
    }

    public func clear() throws {
        try item.delete()
    }
}

/// One generic-password keychain item, this device only, data-protection
/// keychain on macOS so it behaves like iOS's.
public struct KeychainItem {
    public let service: String
    public let account: String

    public init(service: String, account: String) {
        self.service = service
        self.account = account
    }

    /// Whether this process uses the data-protection keychain. Decided once,
    /// and then every operation on every item goes to the same place.
    ///
    /// The data-protection keychain behaves like iOS's and is what a signed,
    /// notarized app uses. A development build — `swift run`, or the ad-hoc
    /// bundle `build-app.sh` makes — has no application identifier and is
    /// refused it; for that case alone the legacy login keychain is used
    /// instead. Both are per-user; neither leaves the machine.
    ///
    /// One decision rather than one per call, because the refusal is not
    /// uniform: an unentitled *lookup* answers "not found", and only a write
    /// answers "missing entitlement". Falling back per call therefore found
    /// nothing in one keychain and wrote to the other — a fresh key on every
    /// launch, and an enrollment that did not survive a relaunch. Updating an
    /// item that does not exist changes nothing and gets the honest answer,
    /// so that is the probe.
    public static let usesDataProtectionKeychain: Bool = {
        #if os(macOS)
        let probe: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "countersign.keychain-probe",
            kSecAttrAccount as String: "which-keychain",
            kSecUseDataProtectionKeychain as String: true,
        ]
        let status = SecItemUpdate(probe as CFDictionary, [kSecAttrComment as String: ""] as CFDictionary)
        return status != errSecMissingEntitlement
        #else
        return true
        #endif
    }()

    private var base: [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        #if os(macOS)
        if Self.usesDataProtectionKeychain { query[kSecUseDataProtectionKeychain as String] = true }
        #endif
        return query
    }

    /// Not found is an answer; anything else that is not success is the caller's.
    private func check(_ status: OSStatus) throws {
        guard status == errSecSuccess || status == errSecItemNotFound else { throw SigningError.keychain(status) }
    }

    public func read() throws -> Data? {
        var query = base
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        try check(status)
        return status == errSecSuccess ? result as? Data : nil
    }

    public func write(_ data: Data) throws {
        var attributes = base
        attributes[kSecValueData as String] = data
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        var status = SecItemAdd(attributes as CFDictionary, nil)
        if status == errSecDuplicateItem {
            status = SecItemUpdate(base as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        }
        try check(status)
    }

    public func delete() throws {
        try check(SecItemDelete(base as CFDictionary))
    }
}

/// The §3.4 binding, on its own, so it can be tested without an enclave.
///
/// Given what the stores hold, decide whether the existing key may be used,
/// a fresh one must be made, or continuity was lost. `EnclaveDevice.init`
/// follows exactly this table.
public enum KeyContinuity: Equatable {
    case useExisting
    case generateFresh
    case continuityLost

    public static func decide(keyExists: Bool, counterExists: Bool) -> KeyContinuity {
        switch (keyExists, counterExists) {
        case (true, true): return .useExisting
        case (false, _): return .generateFresh
        case (true, false): return .continuityLost
        }
    }
}

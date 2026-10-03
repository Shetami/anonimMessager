import CryptoKit
import Foundation
import Security

/// A secret bound to this physical device. Mixed into every key derivation so
/// that copying the app's files off the phone is useless without the device.
public protocol DeviceSecretProvider: Sendable {
    func secret() throws -> Data
    /// Irreversibly destroys the secret, crypto-erasing everything derived from it.
    func destroy()
}

public enum DeviceSecretError: Error {
    case keychain(OSStatus)
}

/// Uses a Secure Enclave P-256 key when available: the device secret is an
/// ECDH result that can only be computed inside this phone's Secure Enclave.
/// Falls back to a random keychain item (simulator / devices without SE).
/// Keychain items are `WhenUnlockedThisDeviceOnly`: not in backups, not
/// migrated to other devices.
public final class KeychainDeviceSecret: DeviceSecretProvider, @unchecked Sendable {
    private let service: String

    public init(service: String = "com.calc.state") {
        self.service = service
    }

    public func secret() throws -> Data {
        if SecureEnclave.isAvailable {
            return try enclaveSecret()
        }
        if let existing = try read("k0") { return existing }
        let fresh = KeyDerivation.randomBytes(32)
        try write("k0", fresh)
        return fresh
    }

    public func destroy() {
        for account in ["k0", "se", "peer"] {
            let q: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: service,
                kSecAttrAccount as String: account,
            ]
            SecItemDelete(q as CFDictionary)
        }
    }

    private func enclaveSecret() throws -> Data {
        let key: SecureEnclave.P256.KeyAgreement.PrivateKey
        let peer: P256.KeyAgreement.PublicKey
        if let keyData = try read("se"), let peerData = try read("peer") {
            key = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: keyData)
            peer = try P256.KeyAgreement.PublicKey(rawRepresentation: peerData)
        } else {
            var error: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, &error)
            else { throw error!.takeRetainedValue() as Error }
            key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: access)
            peer = P256.KeyAgreement.PrivateKey().publicKey
            try write("se", key.dataRepresentation)
            try write("peer", peer.rawRepresentation)
        }
        let shared = try key.sharedSecretFromKeyAgreement(with: peer)
        return shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: Data(), sharedInfo: Data("device-secret".utf8), outputByteCount: 32
        ).data
    }

    private func read(_ account: String) throws -> Data? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
        ]
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw DeviceSecretError.keychain(status) }
        return out as? Data
    }

    private func write(_ account: String, _ data: Data) throws {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        SecItemDelete(q as CFDictionary)
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else { throw DeviceSecretError.keychain(status) }
    }
}

/// For tests only.
public final class InMemoryDeviceSecret: DeviceSecretProvider, @unchecked Sendable {
    private var value: Data?
    public init() {}
    public func secret() throws -> Data {
        if let value { return value }
        let v = KeyDerivation.randomBytes(32)
        value = v
        return v
    }
    public func destroy() { value = nil }
}

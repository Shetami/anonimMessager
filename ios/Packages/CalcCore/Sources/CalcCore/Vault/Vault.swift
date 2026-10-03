import CryptoKit
import Foundation

/// An unlocked profile. Each slot of the vault opens its own, completely
/// independent profile (own identity, contacts, database).
public struct UnlockedProfile: Sendable {
    public let slot: Int
    public let masterKey: SymmetricKey

    public var databaseKey: SymmetricKey { KeyDerivation.subkey(masterKey, info: "calc.db.v1") }
    public var indexKey: SymmetricKey { KeyDerivation.subkey(masterKey, info: "calc.index.v1") }

    /// File name derived from the key, so it says nothing about which slot it is.
    public var databaseFileName: String {
        let mac = HMAC<SHA256>.authenticationCode(for: Data("db-name".utf8), using: masterKey)
        return Data(mac).prefix(10).map { String(format: "%02x", $0) }.joined() + ".dat"
    }
}

public enum VaultError: Error, Equatable {
    case notInitialized
    case alreadyInitialized
    case codeTooShort
    case codeInUse
    case corrupted
}

/// Two-slot key vault giving plausible deniability.
///
/// File layout (fixed 152 bytes, no header or magic):
///
///     salt[32] || slot0[60] || slot1[60]
///     slot = AES-GCM(kek, masterKey[32], aad: slotIndex) as nonce[12] || ct[32] || tag[16]
///     kek  = HKDF(PBKDF2(code, salt) || deviceSecret)
///
/// Both slots always hold a wrapped master key and both profile databases are
/// created at setup, so the files look identical whether or not a decoy code
/// was ever set. The slot index of the primary profile is random. Only the
/// primary profile records the sibling's master key (in its own encrypted
/// database) so it can later assign a decoy code to it; the decoy profile has
/// no way to learn that another profile exists.
public final class Vault: @unchecked Sendable {
    public static let minimumCodeLength = 4
    public static let iterations: UInt32 = 400_000
    static let saltSize = 32
    static let slotSize = 60
    static let fileSize = saltSize + 2 * slotSize

    public let directory: URL
    private let deviceSecret: DeviceSecretProvider
    private let iterations: UInt32
    private let lock = NSLock()

    public init(directory: URL, deviceSecret: DeviceSecretProvider, iterations: UInt32 = Vault.iterations) {
        self.directory = directory
        self.deviceSecret = deviceSecret
        self.iterations = iterations
    }

    var fileURL: URL { directory.appendingPathComponent("state.bin") }

    public var isInitialized: Bool {
        (try? Data(contentsOf: fileURL))?.count == Self.fileSize
    }

    public struct SetupResult: Sendable {
        public let primary: UnlockedProfile
        /// Store this inside the primary profile's database.
        public let sibling: UnlockedProfile
    }

    public func setup(code: String) throws -> SetupResult {
        lock.lock(); defer { lock.unlock() }
        guard !isInitialized else { throw VaultError.alreadyInitialized }
        guard code.count >= Self.minimumCodeLength else { throw VaultError.codeTooShort }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let salt = KeyDerivation.randomBytes(Self.saltSize)
        let primarySlot = Int.random(in: 0...1)
        let primary = UnlockedProfile(slot: primarySlot, masterKey: SymmetricKey(size: .bits256))
        let sibling = UnlockedProfile(slot: 1 - primarySlot, masterKey: SymmetricKey(size: .bits256))

        let kek = try deriveKEK(code: code, salt: salt)
        // The sibling is wrapped under a random KEK until a decoy code is set.
        let slots = [
            primary.slot: try wrap(primary.masterKey, kek: kek, slot: primary.slot),
            sibling.slot: try wrap(sibling.masterKey, kek: SymmetricKey(size: .bits256), slot: sibling.slot),
        ]
        try writeFile(salt + slots[0]! + slots[1]!)
        return SetupResult(primary: primary, sibling: sibling)
    }

    /// Tries the code against both slots. Always does the same amount of work
    /// regardless of which (if any) slot opens.
    public func unlock(code: String) throws -> UnlockedProfile? {
        lock.lock(); defer { lock.unlock() }
        let file = try readFile()
        let kek = try deriveKEK(code: code, salt: file.prefix(Self.saltSize))
        var result: UnlockedProfile?
        for slot in 0...1 {
            if let mk = unwrap(slotData(file, slot), kek: kek, slot: slot), result == nil {
                result = UnlockedProfile(slot: slot, masterKey: mk)
            }
        }
        return result
    }

    /// Assigns (or reassigns) a code to a slot whose master key the caller
    /// knows. Used both for changing your own code and for setting the decoy
    /// code from the primary profile.
    public func setCode(_ code: String, for profile: UnlockedProfile) throws {
        lock.lock(); defer { lock.unlock() }
        guard code.count >= Self.minimumCodeLength else { throw VaultError.codeTooShort }
        var file = try readFile()
        let kek = try deriveKEK(code: code, salt: file.prefix(Self.saltSize))
        let other = 1 - profile.slot
        if unwrap(slotData(file, other), kek: kek, slot: other) != nil {
            throw VaultError.codeInUse
        }
        let range = slotRange(profile.slot)
        file.replaceSubrange(range, with: try wrap(profile.masterKey, kek: kek, slot: profile.slot))
        try writeFile(file)
    }

    /// Makes the slot unopenable by any code (e.g. "remove decoy code").
    public func revokeCode(for profile: UnlockedProfile) throws {
        lock.lock(); defer { lock.unlock() }
        var file = try readFile()
        file.replaceSubrange(
            slotRange(profile.slot),
            with: try wrap(profile.masterKey, kek: SymmetricKey(size: .bits256), slot: profile.slot))
        try writeFile(file)
    }

    /// Crypto-erase: destroys the device secret and overwrites the slot file.
    /// Everything encrypted under this vault becomes unrecoverable instantly,
    /// even if database files linger in flash.
    public func destroy() {
        lock.lock(); defer { lock.unlock() }
        deviceSecret.destroy()
        if let h = try? FileHandle(forWritingTo: fileURL) {
            try? h.write(contentsOf: KeyDerivation.randomBytes(Self.fileSize))
            try? h.synchronize()
            try? h.close()
        }
        try? FileManager.default.removeItem(at: directory)
    }

    // MARK: - Internals

    private func deriveKEK(code: String, salt: Data) throws -> SymmetricKey {
        let stretched = KeyDerivation.pbkdf2(code, salt: salt, iterations: iterations)
        return KeyDerivation.hkdf(stretched + (try deviceSecret.secret()), info: "calc.kek.v1", salt: salt)
    }

    private func wrap(_ key: SymmetricKey, kek: SymmetricKey, slot: Int) throws -> Data {
        let sealed = try AES.GCM.seal(key.data, using: kek, authenticating: Data([UInt8(slot)]))
        guard let combined = sealed.combined, combined.count == Self.slotSize else { throw VaultError.corrupted }
        return combined
    }

    private func unwrap(_ data: Data, kek: SymmetricKey, slot: Int) -> SymmetricKey? {
        guard let box = try? AES.GCM.SealedBox(combined: data),
              let raw = try? AES.GCM.open(box, using: kek, authenticating: Data([UInt8(slot)]))
        else { return nil }
        return SymmetricKey(data: raw)
    }

    private func slotRange(_ slot: Int) -> Range<Int> {
        let start = Self.saltSize + slot * Self.slotSize
        return start..<(start + Self.slotSize)
    }

    private func slotData(_ file: Data, _ slot: Int) -> Data {
        Data(file[slotRange(slot)])
    }

    private func readFile() throws -> Data {
        guard let d = try? Data(contentsOf: fileURL) else { throw VaultError.notInitialized }
        guard d.count == Self.fileSize else { throw VaultError.corrupted }
        return d
    }

    private func writeFile(_ data: Data) throws {
        #if os(iOS)
        try data.write(to: fileURL, options: [.atomic, .completeFileProtection])
        #else
        try data.write(to: fileURL, options: .atomic)
        #endif
        var url = fileURL
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? url.setResourceValues(values)
    }
}

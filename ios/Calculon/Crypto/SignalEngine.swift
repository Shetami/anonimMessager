import CalcCore
import Foundation
import LibSignalClient

/// Signal Protocol (PQXDH + Double Ratchet) via libsignal.
///
/// This is the only file that touches the libsignal API. Written against
/// LibSignalClient v0.103.1 (see ios/.libsignal-version); re-check it when
/// bumping the pin.
final class SignalEngine: E2EEngine {
    private let db: SecureDatabase
    private var store: PersistentSignalStore?
    private var localAddress: ProtocolAddress?
    private let ctx = NullContext()
    static let deviceID: UInt32 = 1

    enum EngineError: Error {
        case noIdentity
    }

    init(db: SecureDatabase) throws {
        self.db = db
        try reload()
    }

    // MARK: - Identity

    func createIdentity() throws -> (identityKey: Data, registrationId: UInt32) {
        let pair = IdentityKeyPair.generate()
        let regID = UInt32.random(in: 1...16380)
        try db.put(PersistentSignalStore.LocalIdentity(keyPair: pair.serialize(), registrationID: regID),
                   collection: PersistentSignalStore.C.identity, key: "self")
        try reload()
        return (pair.identityKey.serialize(), regID)
    }

    func identityKey() throws -> Data {
        try requireStore().identityKeyPair(context: ctx).identityKey.serialize()
    }

    func registrationID() throws -> UInt32 {
        try requireStore().localRegistrationId(context: ctx)
    }

    func sign(_ data: Data) throws -> Data {
        try requireStore().identityKeyPair(context: ctx).privateKey.generateSignature(message: data)
    }

    func verify(signature: Data, for data: Data, identityKey: Data) -> Bool {
        guard let ik = try? IdentityKey(bytes: identityKey) else { return false }
        return (try? ik.publicKey.verifySignature(message: data, signature: signature)) ?? false
    }

    // MARK: - Prekeys

    func generateSignedPreKey(id: UInt32) throws -> SignedKey {
        let store = try requireStore()
        let key = PrivateKey.generate()
        let sig = try store.identityKeyPair(context: ctx).privateKey.generateSignature(message: key.publicKey.serialize())
        let record = try SignedPreKeyRecord(id: id, timestamp: Self.nowMillis, privateKey: key, signature: sig)
        try store.storeSignedPreKey(record, id: id, context: ctx)
        return SignedKey(id: id, publicKey: key.publicKey.serialize(), signature: sig)
    }

    func generateKyberPreKey(id: UInt32, lastResort: Bool) throws -> SignedKey {
        let store = try requireStore()
        let pair = KEMKeyPair.generate()
        let sig = try store.identityKeyPair(context: ctx).privateKey.generateSignature(message: pair.publicKey.serialize())
        let record = try KyberPreKeyRecord(id: id, timestamp: Self.nowMillis, keyPair: pair, signature: sig)
        try store.storeKyberPreKey(record, id: id, oneTime: !lastResort)
        return SignedKey(id: id, publicKey: pair.publicKey.serialize(), signature: sig)
    }

    func generatePreKeys(startingAt id: UInt32, count: Int) throws -> [SignedKey] {
        let store = try requireStore()
        return try (0..<UInt32(count)).map { offset in
            let keyID = id + offset
            let key = PrivateKey.generate()
            try store.storePreKey(try PreKeyRecord(id: keyID, privateKey: key), id: keyID, context: ctx)
            return SignedKey(id: keyID, publicKey: key.publicKey.serialize())
        }
    }

    // MARK: - Sessions

    func hasSession(with address: String) -> Bool {
        guard let store, let addr = try? Self.address(address) else { return false }
        return (try? store.loadSession(for: addr, context: ctx)) != nil
    }

    func remoteIdentityKey(for address: String) -> Data? {
        guard let store, let addr = try? Self.address(address),
              let identity = try? store.identity(for: addr, context: ctx)
        else { return nil }
        return identity.serialize()
    }

    func startSession(with address: String, bundle dto: PreKeyBundleDTO) throws {
        let (store, local) = try requireSession()
        let addr = try Self.address(address)
        let identity = try IdentityKey(bytes: dto.identityKey)
        let signedPreKey = try PublicKey(dto.signedPreKey.publicKey)
        let kyberKey = try KEMPublicKey(dto.kyberPreKey.publicKey)
        let signedSig = dto.signedPreKey.signature ?? Data()
        let kyberSig = dto.kyberPreKey.signature ?? Data()
        let bundle: PreKeyBundle
        if let pk = dto.preKey {
            bundle = try PreKeyBundle(
                registrationId: dto.registrationId, deviceId: Self.deviceID,
                prekeyId: pk.id, prekey: try PublicKey(pk.publicKey),
                signedPrekeyId: dto.signedPreKey.id, signedPrekey: signedPreKey, signedPrekeySignature: signedSig,
                identity: identity,
                kyberPrekeyId: dto.kyberPreKey.id, kyberPrekey: kyberKey, kyberPrekeySignature: kyberSig)
        } else {
            bundle = try PreKeyBundle(
                registrationId: dto.registrationId, deviceId: Self.deviceID,
                signedPrekeyId: dto.signedPreKey.id, signedPrekey: signedPreKey, signedPrekeySignature: signedSig,
                identity: identity,
                kyberPrekeyId: dto.kyberPreKey.id, kyberPrekey: kyberKey, kyberPrekeySignature: kyberSig)
        }
        // Verifies the signed-prekey and Kyber signatures against the identity
        // key; the store refuses identity keys that don't hash to `address`.
        try processPreKeyBundle(bundle, for: addr, ourAddress: local,
                                sessionStore: store, identityStore: store, context: ctx)
    }

    func encrypt(_ plaintext: Data, for address: String) throws -> (EnvelopeContent.Kind, Data) {
        let (store, local) = try requireSession()
        let message = try signalEncrypt(message: plaintext, for: try Self.address(address), localAddress: local,
                                        sessionStore: store, identityStore: store, context: ctx)
        return (message.messageType == .preKey ? .preKey : .whisper, message.serialize())
    }

    func decrypt(_ ciphertext: Data, kind: EnvelopeContent.Kind, from address: String) throws -> Data {
        let (store, local) = try requireSession()
        let addr = try Self.address(address)
        switch kind {
        case .preKey:
            let plaintext = try signalDecryptPreKey(
                message: try PreKeySignalMessage(bytes: ciphertext), from: addr, localAddress: local,
                sessionStore: store, identityStore: store, preKeyStore: store,
                signedPreKeyStore: store, kyberPreKeyStore: store, context: ctx)
            try store.dropUsedOneTimeKyberKeys()
            return plaintext
        case .whisper:
            return try signalDecrypt(message: try SignalMessage(bytes: ciphertext), from: addr, to: local,
                                     sessionStore: store, identityStore: store, context: ctx)
        }
    }

    func deleteSession(with address: String) throws {
        try db.delete(collection: PersistentSignalStore.C.sessions, key: address)
        try db.delete(collection: PersistentSignalStore.C.identities, key: address)
        try reload()
    }

    // MARK: - Helpers

    private func reload() throws {
        store = try PersistentSignalStore.load(from: db)
        if let store {
            let ik = try store.identityKeyPair(context: ctx).identityKey.serialize()
            localAddress = try Self.address(AccountID.from(identityKey: ik))
        } else {
            localAddress = nil
        }
    }

    private func requireStore() throws -> PersistentSignalStore {
        guard let store else { throw EngineError.noIdentity }
        return store
    }

    private func requireSession() throws -> (PersistentSignalStore, ProtocolAddress) {
        guard let store, let localAddress else { throw EngineError.noIdentity }
        return (store, localAddress)
    }

    static func address(_ name: String) throws -> ProtocolAddress {
        try ProtocolAddress(name: name, deviceId: deviceID)
    }

    private static var nowMillis: UInt64 { UInt64(Date().timeIntervalSince1970 * 1000) }
}

/// libsignal's in-memory store with every mutation written through to the
/// profile's encrypted database.
final class PersistentSignalStore: InMemorySignalProtocolStore {
    enum C {
        static let identity = "sig.identity"
        static let preKeys = "sig.prekeys"
        static let signed = "sig.signed"
        static let kyber = "sig.kyber"
        static let kyberUsed = "sig.kyber.used"
        static let baseKeys = "sig.basekeys"
        static let sessions = "sig.sessions"
        static let identities = "sig.identities"
    }

    struct LocalIdentity: Codable {
        var keyPair: Data
        var registrationID: UInt32
    }

    struct Row: Codable {
        var key: String
        var data: Data
        var oneTime: Bool?
    }

    private let db: SecureDatabase
    private var restoring = true
    private var pendingKyberRemovals: [UInt32] = []

    private init(db: SecureDatabase, identity: IdentityKeyPair, registrationId: UInt32) {
        self.db = db
        super.init(identity: identity, registrationId: registrationId)
    }

    static func load(from db: SecureDatabase) throws -> PersistentSignalStore? {
        guard let local = try db.get(LocalIdentity.self, collection: C.identity, key: "self") else { return nil }
        let s = PersistentSignalStore(db: db, identity: try IdentityKeyPair(bytes: local.keyPair),
                                      registrationId: local.registrationID)
        let ctx = NullContext()
        for r in try db.list(Row.self, collection: C.preKeys) {
            try s.storePreKey(try PreKeyRecord(bytes: r.data), id: UInt32(r.key)!, context: ctx)
        }
        for r in try db.list(Row.self, collection: C.signed) {
            try s.storeSignedPreKey(try SignedPreKeyRecord(bytes: r.data), id: UInt32(r.key)!, context: ctx)
        }
        for r in try db.list(Row.self, collection: C.kyber) {
            try s.storeKyberPreKey(try KyberPreKeyRecord(bytes: r.data), id: UInt32(r.key)!, context: ctx)
        }
        for r in try db.list(Row.self, collection: C.identities) {
            _ = try s.saveIdentity(try IdentityKey(bytes: r.data), for: try SignalEngine.address(r.key), context: ctx)
        }
        for r in try db.list(Row.self, collection: C.sessions) {
            try s.storeSession(try SessionRecord(bytes: r.data), for: try SignalEngine.address(r.key), context: ctx)
        }
        s.restoring = false
        return s
    }

    private func persist(_ collection: String, _ key: String, _ data: Data, oneTime: Bool? = nil) throws {
        guard !restoring else { return }
        try db.put(Row(key: key, data: data, oneTime: oneTime), collection: collection, key: key)
    }

    // MARK: Identity binding

    /// A contact ID *is* the hash of its identity key, so exactly one key is
    /// ever acceptable for an address — no trust-on-first-use window.
    override func isTrustedIdentity(_ identity: IdentityKey, for address: ProtocolAddress,
                                    direction: Direction, context: StoreContext) throws -> Bool {
        guard AccountID.from(identityKey: identity.serialize()) == address.name else { return false }
        return try super.isTrustedIdentity(identity, for: address, direction: direction, context: context)
    }

    override func saveIdentity(_ identity: IdentityKey, for address: ProtocolAddress,
                               context: StoreContext) throws -> IdentityChange {
        let change = try super.saveIdentity(identity, for: address, context: context)
        try persist(C.identities, address.name, identity.serialize())
        return change
    }

    // MARK: Sessions

    override func storeSession(_ record: SessionRecord, for address: ProtocolAddress, context: StoreContext) throws {
        try super.storeSession(record, for: address, context: context)
        try persist(C.sessions, address.name, record.serialize())
    }

    // MARK: Prekeys

    override func storePreKey(_ record: PreKeyRecord, id: UInt32, context: StoreContext) throws {
        try super.storePreKey(record, id: id, context: context)
        try persist(C.preKeys, String(id), record.serialize())
    }

    override func removePreKey(id: UInt32, context: StoreContext) throws {
        try super.removePreKey(id: id, context: context)
        try db.delete(collection: C.preKeys, key: String(id))
    }

    override func storeSignedPreKey(_ record: SignedPreKeyRecord, id: UInt32, context: StoreContext) throws {
        try super.storeSignedPreKey(record, id: id, context: context)
        try persist(C.signed, String(id), record.serialize())
    }

    func storeKyberPreKey(_ record: KyberPreKeyRecord, id: UInt32, oneTime: Bool) throws {
        try super.storeKyberPreKey(record, id: id, context: NullContext())
        try persist(C.kyber, String(id), record.serialize(), oneTime: oneTime)
    }

    /// One-time Kyber keys must never be accepted twice, and a (key, base key)
    /// pair must never repeat — both checks survive app restarts.
    override func markKyberPreKeyUsed(id: UInt32, signedPreKeyId: UInt32, baseKey: PublicKey,
                                      context: StoreContext) throws {
        if try db.get(Bool.self, collection: C.kyberUsed, key: String(id)) != nil {
            throw SignalError.invalidMessage("one-time kyber prekey reused")
        }
        let seenKey = "\(id):\(signedPreKeyId):\(baseKey.serialize().base64EncodedString())"
        if try db.get(Bool.self, collection: C.baseKeys, key: seenKey) != nil {
            throw SignalError.invalidMessage("reused base key")
        }
        try super.markKyberPreKeyUsed(id: id, signedPreKeyId: signedPreKeyId, baseKey: baseKey, context: context)
        try db.put(true, collection: C.baseKeys, key: seenKey)
        if try db.get(Row.self, collection: C.kyber, key: String(id))?.oneTime == true {
            try db.put(true, collection: C.kyberUsed, key: String(id))
            pendingKyberRemovals.append(id)
        }
    }

    /// Deletes consumed one-time Kyber keys from disk after a successful decrypt.
    func dropUsedOneTimeKyberKeys() throws {
        for id in pendingKyberRemovals {
            try db.delete(collection: C.kyber, key: String(id))
        }
        pendingKyberRemovals.removeAll()
    }
}

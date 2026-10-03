import CryptoKit
import Foundation
import Observation

public enum MessengerError: Error, Equatable {
    case notRegistered
    case invalidContactID
    case cannotAddSelf
    case keyMismatch      // relay returned keys that don't match the contact ID
    case badSignature     // sealing key not signed by the contact's identity
    case unknownContact
}

/// Coordinates one unlocked profile: identity, contacts, messages and the
/// relay. Everything it persists goes through the profile's SecureDatabase.
@MainActor
@Observable
public final class MessengerService {
    public private(set) var state: ProfileState?
    public private(set) var contacts: [Contact] = []
    public private(set) var lastSyncError: Error?

    public var accountID: String? { state?.accountID }
    public var hasSiblingSlot: Bool { (try? db.get(SiblingSlot.self, collection: C.meta, key: "sibling")) != nil }

    @ObservationIgnored public let db: SecureDatabase
    @ObservationIgnored private let engine: E2EEngine
    @ObservationIgnored private let relay: RelayTransport
    @ObservationIgnored private var auth: RelayAuth?
    @ObservationIgnored private var sealing: Curve25519.KeyAgreement.PrivateKey?

    static let preKeyBatch = 100
    static let kyberBatch = 20
    static let replenishBelow = 20
    static let signedPreKeyLifetime: TimeInterval = 7 * 24 * 3600

    enum C {
        static let meta = "meta"
        static let contacts = "contacts"
        static let messages = "messages"
    }

    public init(db: SecureDatabase, engine: E2EEngine, relay: RelayTransport) {
        self.db = db
        self.engine = engine
        self.relay = relay
        load()
    }

    private func load() {
        state = try? db.get(ProfileState.self, collection: C.meta, key: "profile")
        if let state {
            auth = try? RelayAuth(accountID: state.accountID, key: .init(rawRepresentation: state.authKey))
            sealing = try? .init(rawRepresentation: state.sealingKey)
        }
        reloadContacts()
    }

    // MARK: - Registration

    /// Creates the identity and registers an anonymous mailbox. No phone
    /// number, email or any other identifier is involved.
    public func register() async throws {
        if state == nil {
            let (identityKey, _) = try engine.createIdentity()
            let s = ProfileState(
                accountID: AccountID.from(identityKey: identityKey),
                authKey: Curve25519.Signing.PrivateKey().rawRepresentation,
                sealingKey: Curve25519.KeyAgreement.PrivateKey().rawRepresentation,
                nextPreKeyID: 1, nextKyberID: 1, nextSignedPreKeyID: 1,
                signedPreKeyRotatedAt: Date(), registered: false)
            try saveState(s)
            load()
        }
        guard var s = state, !s.registered, let auth, let sealing else { return }

        let identityKey = try engine.identityKey()
        let registrationId = try engine.registrationID()
        let sealingPub = sealing.publicKey.rawRepresentation
        let signedPreKey = try engine.generateSignedPreKey(id: s.nextSignedPreKeyID)
        let kyberLastResort = try engine.generateKyberPreKey(id: s.nextKyberID, lastResort: true)
        let preKeys = try engine.generatePreKeys(startingAt: s.nextPreKeyID, count: Self.preKeyBatch)
        var kyber: [SignedKey] = []
        for i in 1...UInt32(Self.kyberBatch) {
            kyber.append(try engine.generateKyberPreKey(id: s.nextKyberID + i, lastResort: false))
        }
        s.nextSignedPreKeyID += 1
        s.nextPreKeyID += UInt32(Self.preKeyBatch)
        s.nextKyberID += UInt32(Self.kyberBatch) + 1

        let req = RegisterRequest(
            identityKey: identityKey,
            authKey: auth.key.publicKey.rawRepresentation,
            registrationId: registrationId,
            sealingKey: SignedKey(id: 0, publicKey: sealingPub, signature: try engine.sign(Self.sealingSignedData(sealingPub))),
            signedPreKey: signedPreKey,
            kyberLastResort: kyberLastResort,
            preKeys: preKeys,
            kyberPreKeys: kyber)
        do {
            try await relay.register(req, auth: auth)
        } catch RelayError.conflict {
            // Already registered by an earlier attempt whose response was lost.
        }
        s.registered = true
        s.signedPreKeyRotatedAt = Date()
        try saveState(s)
    }

    /// Domain-separated so a sealing-key signature can't be confused with any
    /// other identity-key signature.
    static func sealingSignedData(_ key: Data) -> Data {
        Data("calc.sealing-key.v1".utf8) + key
    }

    // MARK: - Contacts

    /// Adds a contact by ID. The relay's bundle is checked against the ID
    /// (which commits to the identity key) and the sealing-key signature, so a
    /// malicious relay cannot man-in-the-middle the conversation.
    @discardableResult
    public func addContact(id rawID: String, name: String, verifiedInPerson: Bool) async throws -> Contact {
        guard let id = AccountID.normalize(rawID) else { throw MessengerError.invalidContactID }
        guard id != state?.accountID else { throw MessengerError.cannotAddSelf }
        if var existing = contact(id) {
            existing.name = name.isEmpty ? existing.name : name
            existing.verified = existing.verified || verifiedInPerson
            existing.isRequest = false
            try saveContact(existing)
            return existing
        }
        let bundle = try await relay.bundle(for: id)
        try Self.verify(bundle: bundle, for: id, engine: engine)
        try engine.startSession(with: id, bundle: bundle)
        let c = Contact(
            id: id, name: name.isEmpty ? AccountID.grouped(id).prefix(9).description : name,
            identityKey: bundle.identityKey, sealingKey: bundle.sealingKey.publicKey,
            addedAt: Date(), verified: verifiedInPerson, isRequest: false,
            disappearAfter: nil, lastActivity: Date(), lastPreview: nil, unread: 0)
        try saveContact(c)
        return c
    }

    static func verify(bundle: PreKeyBundleDTO, for id: String, engine: E2EEngine) throws {
        guard AccountID.from(identityKey: bundle.identityKey) == id else { throw MessengerError.keyMismatch }
        guard let sig = bundle.sealingKey.signature,
              engine.verify(signature: sig, for: sealingSignedData(bundle.sealingKey.publicKey), identityKey: bundle.identityKey)
        else { throw MessengerError.badSignature }
    }

    public func contact(_ id: String) -> Contact? {
        try? db.get(Contact.self, collection: C.contacts, key: id)
    }

    public func rename(_ id: String, to name: String) throws {
        guard var c = contact(id) else { return }
        c.name = name
        c.isRequest = false
        try saveContact(c)
    }

    public func deleteContact(_ id: String) throws {
        try db.deleteGroup(collection: C.messages, group: id)
        try db.delete(collection: C.contacts, key: id)
        try engine.deleteSession(with: id)
        reloadContacts()
    }

    /// Clears the unread badge and sends a read receipt for every incoming
    /// message not reported yet. Messages stay `.received` if the receipt
    /// can't be sent, so the next call retries.
    public func markRead(_ id: String) async {
        guard var c = contact(id) else { return }
        if c.unread > 0 {
            c.unread = 0
            try? saveContact(c)
        }
        let pending = messages(with: id).filter { !$0.outgoing && $0.status == .received }
        guard !pending.isEmpty else { return }
        do {
            try await sendReceipt(.read, ids: pending.map(\.id), to: c)
        } catch {
            return
        }
        for var m in pending {
            m.status = .read
            try? saveMessage(m, preview: nil)
        }
    }

    // MARK: - Messages

    public func messages(with contactID: String) -> [ChatMessage] {
        let now = Date()
        return ((try? db.list(ChatMessage.self, collection: C.messages, group: contactID)) ?? [])
            .filter { $0.expiresAt.map { $0 > now } ?? true }
    }

    @discardableResult
    public func send(_ text: String, to contactID: String) async throws -> ChatMessage {
        guard let c = contact(contactID) else { throw MessengerError.unknownContact }
        let now = Date()
        var msg = ChatMessage(
            id: UUID().uuidString, contactID: contactID, outgoing: true, body: text, sentAt: now,
            status: .sending, expiresAt: c.disappearAfter.map { now.addingTimeInterval($0) })
        try saveMessage(msg, preview: text)
        do {
            try await deliver(MessagePayload(kind: .text, id: msg.id, body: text, sentAt: now, disappearAfter: c.disappearAfter), to: c)
            // A receipt may already have upgraded it while we were awaiting.
            if let stored = try? db.get(ChatMessage.self, collection: C.messages, key: msg.id),
               stored.status != .sending {
                return stored
            }
            msg.status = .sent
        } catch {
            msg.status = .failed
            try? saveMessage(msg, preview: nil)
            throw error
        }
        try saveMessage(msg, preview: nil)
        return msg
    }

    /// Sets the disappearing-messages timer for a chat and tells the peer.
    public func setDisappearing(_ seconds: TimeInterval?, for contactID: String) async throws {
        guard var c = contact(contactID) else { throw MessengerError.unknownContact }
        c.disappearAfter = seconds
        try saveContact(c)
        try await deliver(MessagePayload(kind: .timer, id: UUID().uuidString, body: "", sentAt: Date(), disappearAfter: seconds), to: c)
    }

    private func sendReceipt(_ kind: MessagePayload.Kind, ids: [String], to c: Contact) async throws {
        try await deliver(MessagePayload(kind: kind, id: UUID().uuidString, body: "", sentAt: Date(),
                                         disappearAfter: c.disappearAfter, ids: ids), to: c)
    }

    private func deliver(_ payload: MessagePayload, to c: Contact) async throws {
        guard let me = state?.accountID else { throw MessengerError.notRegistered }
        let (kind, ciphertext) = try engine.encrypt(try JSONEncoder().encode(payload), for: c.id)
        let content = EnvelopeContent(sender: me, kind: kind, ciphertext: ciphertext)
        let envelope = try SealedEnvelope.seal(content, to: .init(rawRepresentation: c.sealingKey))
        try await relay.send(envelope, to: c.id)
    }

    /// Fetches, decrypts and stores pending envelopes, then acknowledges them.
    /// Undecryptable envelopes are dropped (acked) rather than retried forever.
    @discardableResult
    public func sync() async -> Int {
        guard let auth, let sealing, state?.registered == true else { return 0 }
        var received = 0
        var delivered: [String: [String]] = [:] // contact ID → message IDs
        do {
            while true {
                let batch = try await relay.fetch(auth: auth)
                if batch.isEmpty { break }
                for env in batch {
                    if let msg = try? await handle(env.data, sealing: sealing) {
                        received += 1
                        delivered[msg.contactID, default: []].append(msg.id)
                    }
                }
                try await relay.ack(batch.map(\.id), auth: auth)
                if batch.count < 100 { break }
            }
            // Best effort: a lost delivery receipt only means one checkmark
            // until the read receipt arrives.
            for (contactID, ids) in delivered {
                if let c = contact(contactID) { try? await sendReceipt(.delivered, ids: ids, to: c) }
            }
            try await maintainKeys()
            purgeExpired()
            lastSyncError = nil
        } catch {
            lastSyncError = error
        }
        return received
    }

    /// Returns the stored message for an incoming text, nil for anything else.
    private func handle(_ data: Data, sealing: Curve25519.KeyAgreement.PrivateKey) async throws -> ChatMessage? {
        let content = try SealedEnvelope.open(data, with: sealing)
        guard AccountID.isValid(content.sender), content.sender != state?.accountID else { return nil }
        // The engine only trusts identity keys that hash to content.sender, so
        // a forged sender ID fails here.
        let plaintext = try engine.decrypt(content.ciphertext, kind: content.kind, from: content.sender)
        let payload = try JSONDecoder().decode(MessagePayload.self, from: plaintext)

        if payload.kind == .delivered || payload.kind == .read {
            applyReceipt(payload, from: content.sender)
            return nil
        }

        var c: Contact
        if let existing = contact(content.sender) {
            c = existing
        } else {
            // First message from someone who added us: fetch their sealing key
            // so we can reply, verifying it against their ID.
            let bundle = try await relay.bundle(for: content.sender)
            try Self.verify(bundle: bundle, for: content.sender, engine: engine)
            c = Contact(
                id: content.sender, name: AccountID.grouped(content.sender).prefix(9).description,
                identityKey: bundle.identityKey, sealingKey: bundle.sealingKey.publicKey,
                addedAt: Date(), verified: false, isRequest: true, disappearAfter: payload.disappearAfter,
                lastActivity: Date(), lastPreview: nil, unread: 0)
        }

        switch payload.kind {
        case .timer:
            c.disappearAfter = payload.disappearAfter
            try saveContact(c)
            return nil
        case .delivered, .read:
            return nil
        case .text:
            if c.disappearAfter != payload.disappearAfter { c.disappearAfter = payload.disappearAfter }
            c.unread += 1
            try saveContact(c)
            let now = Date()
            let msg = ChatMessage(
                id: payload.id, contactID: c.id, outgoing: false, body: payload.body,
                sentAt: min(payload.sentAt, now), status: .received,
                expiresAt: payload.disappearAfter.map { now.addingTimeInterval($0) })
            try saveMessage(msg, preview: payload.body)
            return msg
        }
    }

    /// Upgrades our outgoing messages to delivered/read. Only messages we sent
    /// to this very sender are touched, and status never moves backwards.
    private func applyReceipt(_ payload: MessagePayload, from sender: String) {
        let newStatus: ChatMessage.Status = payload.kind == .read ? .read : .delivered
        for id in payload.ids ?? [] {
            guard var m = try? db.get(ChatMessage.self, collection: C.messages, key: id),
                  m.outgoing, m.contactID == sender, m.status != .read,
                  !(m.status == .delivered && newStatus == .delivered)
            else { continue }
            m.status = newStatus
            try? saveMessage(m, preview: nil)
        }
    }

    /// Replenishes one-time prekeys and rotates the signed prekey weekly.
    private func maintainKeys() async throws {
        guard var s = state, let auth else { return }
        let counts = try await relay.keyCounts(auth: auth)
        var update = KeysUpdate()
        if counts.preKeys < Self.replenishBelow {
            update.preKeys = try engine.generatePreKeys(startingAt: s.nextPreKeyID, count: Self.preKeyBatch)
            s.nextPreKeyID += UInt32(Self.preKeyBatch)
        }
        if counts.kyberPreKeys < Self.replenishBelow / 4 {
            for _ in 0..<Self.kyberBatch {
                update.kyberPreKeys.append(try engine.generateKyberPreKey(id: s.nextKyberID, lastResort: false))
                s.nextKyberID += 1
            }
        }
        if Date().timeIntervalSince(s.signedPreKeyRotatedAt) > Self.signedPreKeyLifetime {
            update.signedPreKey = try engine.generateSignedPreKey(id: s.nextSignedPreKeyID)
            update.kyberLastResort = try engine.generateKyberPreKey(id: s.nextKyberID, lastResort: true)
            s.nextSignedPreKeyID += 1
            s.nextKyberID += 1
            s.signedPreKeyRotatedAt = Date()
        }
        guard update.signedPreKey != nil || !update.preKeys.isEmpty || !update.kyberPreKeys.isEmpty else { return }
        try await relay.updateKeys(update, auth: auth)
        try saveState(s)
    }

    public func purgeExpired() {
        let now = Date()
        for c in contacts {
            let all = (try? db.list(ChatMessage.self, collection: C.messages, group: c.id)) ?? []
            for m in all where (m.expiresAt.map { $0 <= now } ?? false) {
                try? db.delete(collection: C.messages, key: m.id)
            }
        }
    }

    // MARK: - Vault-related settings

    public func storeSibling(_ sibling: UnlockedProfile) throws {
        try db.put(SiblingSlot(slot: sibling.slot, masterKey: sibling.masterKey.data, codeAssigned: false),
                   collection: C.meta, key: "sibling")
    }

    public func sibling() -> UnlockedProfile? {
        guard let s = try? db.get(SiblingSlot.self, collection: C.meta, key: "sibling") else { return nil }
        return UnlockedProfile(slot: s.slot, masterKey: SymmetricKey(data: s.masterKey))
    }

    /// Removes the account from the relay. Local data is crypto-erased by the
    /// vault afterwards.
    public func deleteAccountFromRelay() async {
        guard let auth, state?.registered == true else { return }
        try? await relay.deleteAccount(auth: auth)
    }

    // MARK: - Persistence helpers

    private func saveState(_ s: ProfileState) throws {
        try db.put(s, collection: C.meta, key: "profile")
        state = s
    }

    private func saveContact(_ c: Contact) throws {
        try db.put(c, collection: C.contacts, key: c.id, sort: Int64(c.lastActivity.timeIntervalSince1970))
        reloadContacts()
    }

    private func saveMessage(_ m: ChatMessage, preview: String?) throws {
        try db.put(m, collection: C.messages, key: m.id, group: m.contactID,
                   sort: Int64(m.sentAt.timeIntervalSince1970 * 1000))
        if let preview, var c = contact(m.contactID) {
            c.lastActivity = Date()
            c.lastPreview = preview
            try saveContact(c)
        }
    }

    private func reloadContacts() {
        contacts = ((try? db.list(Contact.self, collection: C.contacts)) ?? [])
            .sorted { $0.lastActivity > $1.lastActivity }
    }
}

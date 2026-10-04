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
    case tooManyAttachments
    case attachmentTooLarge
}

/// Coordinates one unlocked profile: identity, contacts, messages and the
/// relay. Everything it persists goes through the profile's SecureDatabase.
@MainActor
@Observable
public final class MessengerService {
    public private(set) var state: ProfileState?
    public private(set) var contacts: [Contact] = []
    public private(set) var lastSyncError: Error?
    /// Envelopes (of any kind) the last sync fetched.
    @ObservationIgnored public private(set) var lastFetched = 0
    /// Attachment IDs being downloaded right now / whose last download failed.
    public private(set) var downloading: Set<String> = []
    public private(set) var failedDownloads: Set<String> = []

    public var accountID: String? { state?.accountID }
    public var hasSiblingSlot: Bool { (try? db.get(SiblingSlot.self, collection: C.meta, key: "sibling")) != nil }

    @ObservationIgnored public let db: SecureDatabase
    @ObservationIgnored public let files: AttachmentStore
    @ObservationIgnored private let engine: E2EEngine
    @ObservationIgnored private let relay: RelayTransport
    @ObservationIgnored private var auth: RelayAuth?
    @ObservationIgnored private var sealing: Curve25519.KeyAgreement.PrivateKey?
    @ObservationIgnored private var lastMaintenance: Date?
    @ObservationIgnored private var turn: (credentials: TurnCredentials, expires: Date)?
    /// Wakes up to delete messages when the earliest timer runs out.
    @ObservationIgnored private var expiryTask: Task<Void, Never>?
    @ObservationIgnored private var nextExpiry: Date?
    /// Attachments of deleted messages, so a download still in flight doesn't
    /// leave an orphan file behind.
    @ObservationIgnored private var removedAttachments: Set<String> = []

    /// Call signaling from accepted contacts, in the order it was sent.
    /// Message requests and strangers can't ring this device. `age` is how
    /// long ago the peer sent it (by their clock).
    @ObservationIgnored public var onCallSignal: ((_ contactID: String, _ signal: CallSignal, _ age: TimeInterval) -> Void)?

    static let preKeyBatch = 100
    static let kyberBatch = 20
    static let replenishBelow = 20
    static let signedPreKeyLifetime: TimeInterval = 7 * 24 * 3600
    static let maintenanceInterval: TimeInterval = 60
    /// Cached TURN credentials are replaced once less than this is left, which
    /// is also the longest call they're guaranteed to last.
    static let turnMinRemaining: TimeInterval = 2 * 3600
    public static let maxAttachments = 10
    public static let maxAttachmentSize = 100 << 20
    nonisolated static let maxThumbnailSize = 32 << 10

    enum C {
        static let meta = "meta"
        static let contacts = "contacts"
        static let messages = "messages"
    }

    public init(db: SecureDatabase, engine: E2EEngine, relay: RelayTransport) {
        self.db = db
        // Next to the database, with a name derived from it (which in turn is
        // derived from the profile key), so profiles can't be linked.
        self.files = AttachmentStore(directory: db.url.deletingPathExtension().appendingPathExtension("files"))
        self.engine = engine
        self.relay = relay
        load()
        // Whatever ran out while the profile was locked goes before anything
        // can show it.
        purgeExpired()
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
        for m in (try? db.list(ChatMessage.self, collection: C.messages, group: id)) ?? [] {
            deleteFiles(of: m)
        }
        try db.deleteGroup(collection: C.messages, group: id)
        try db.delete(collection: C.contacts, key: id)
        try engine.deleteSession(with: id)
        reloadContacts()
    }

    /// Clears the unread badge, starts the disappearing timers of incoming
    /// messages and sends a read receipt for every incoming message not
    /// reported yet. Messages stay `.received` if the receipt can't be sent,
    /// so the next call retries.
    public func markRead(_ id: String) async {
        guard var c = contact(id) else { return }
        if c.unread > 0 {
            c.unread = 0
            try? saveContact(c)
        }
        let now = Date()
        for var m in messages(with: id) where !m.outgoing && m.expiresAt == nil {
            guard let t = m.expiresIn else { continue }
            m.expiresAt = now.addingTimeInterval(t)
            try? saveMessage(m, preview: nil)
        }
        let pending = messages(with: id).filter { !$0.outgoing && $0.status == .received }
        guard !pending.isEmpty else { return }
        do {
            try await sendReceipt(.read, ids: pending.map(\.id), to: c)
        } catch {
            return
        }
        // Re-read: a message may have been deleted while we were awaiting.
        for p in pending {
            updateMessage(p.id) { $0.status = .read }
        }
    }

    // MARK: - Messages

    public func messages(with contactID: String) -> [ChatMessage] {
        let now = Date()
        return ((try? db.list(ChatMessage.self, collection: C.messages, group: contactID)) ?? [])
            .filter { $0.expiresAt.map { $0 > now } ?? true }
    }

    @discardableResult
    public func send(_ text: String, attachments: [OutgoingAttachment] = [], to contactID: String) async throws -> ChatMessage {
        guard let c = contact(contactID) else { throw MessengerError.unknownContact }
        guard attachments.count <= Self.maxAttachments else { throw MessengerError.tooManyAttachments }
        guard attachments.allSatisfy({ $0.data.count <= Self.maxAttachmentSize }) else {
            throw MessengerError.attachmentTooLarge
        }
        // Encrypt one at a time straight to disk, off the main actor, so only
        // one file's ciphertext is ever in memory.
        var pointers: [AttachmentPointer] = []
        for a in attachments {
            pointers.append(try await Self.encryptToDisk(a, files: files))
        }
        let now = Date()
        var msg = ChatMessage(
            id: UUID().uuidString, contactID: contactID, outgoing: true, body: text, sentAt: now,
            status: .sending, expiresAt: c.disappearAfter.map { now.addingTimeInterval($0) },
            attachments: pointers.isEmpty ? nil : pointers)
        try saveMessage(msg, preview: Self.preview(text, pointers))
        do {
            for p in pointers {
                try await relay.uploadAttachment(try files.read(p.id), id: p.id)
            }
            try await deliver(MessagePayload(kind: .text, id: msg.id, body: text, sentAt: now,
                                             disappearAfter: c.disappearAfter,
                                             attachments: pointers.isEmpty ? nil : pointers), to: c)
            // A receipt may already have upgraded it while we were awaiting,
            // or the user may have deleted it.
            guard let stored = try? db.get(ChatMessage.self, collection: C.messages, key: msg.id) else { return msg }
            if stored.status != .sending { return stored }
            msg.status = .sent
        } catch {
            msg.status = .failed
            updateMessage(msg.id) { $0.status = .failed }
            throw error
        }
        updateMessage(msg.id) { $0.status = .sent }
        return msg
    }

    nonisolated private static func encryptToDisk(_ a: OutgoingAttachment, files: AttachmentStore) async throws -> AttachmentPointer {
        try await Task.detached(priority: .userInitiated) {
            let key = SymmetricKey(size: .bits256)
            let id = KeyDerivation.randomBytes(16).map { String(format: "%02x", $0) }.joined()
            try files.write(try AttachmentCipher.encrypt(a.data, key: key), id: id)
            return AttachmentPointer(
                id: id, key: key.data, size: a.data.count,
                name: sanitizedName(a.name), mime: a.mime,
                thumbnail: a.thumbnail.flatMap { $0.count <= maxThumbnailSize ? $0 : nil },
                width: a.width, height: a.height)
        }.value
    }

    /// Text shown in the chat list for a message.
    static func preview(of m: ChatMessage) -> String {
        if let call = m.call { return "📞 " + call.label(outgoing: m.outgoing) }
        if let t = m.timerChange { return "⏱ " + t.label(outgoing: m.outgoing) }
        return preview(m.body, m.attachments ?? [])
    }

    static func preview(_ text: String, _ attachments: [AttachmentPointer]) -> String {
        guard text.isEmpty, let first = attachments.first else { return text }
        let label = first.isImage ? "Фото" : first.isVideo ? "Видео" : first.name
        return attachments.count == 1 ? "📎 \(label)" : "📎 \(label) и ещё \(attachments.count - 1)"
    }

    nonisolated static func sanitizedName(_ name: String) -> String {
        let base = (name as NSString).lastPathComponent.trimmingCharacters(in: .whitespacesAndNewlines)
        return base.isEmpty ? "file" : String(base.prefix(120))
    }

    // MARK: - Attachments

    /// Drops malformed pointers from a peer, and any that would collide with
    /// a file we already have.
    private func acceptedAttachments(_ pointers: [AttachmentPointer]?) -> [AttachmentPointer] {
        (pointers ?? []).prefix(Self.maxAttachments).compactMap { p in
            guard RelayClient.isValidBlobID(p.id), p.key.count == 32,
                  (0...Self.maxAttachmentSize).contains(p.size),
                  !files.contains(p.id)
            else { return nil }
            var p = p
            p.name = Self.sanitizedName(p.name)
            p.mime = String(p.mime.prefix(100))
            if (p.thumbnail?.count ?? 0) > Self.maxThumbnailSize { p.thumbnail = nil }
            return p
        }
    }

    public func isDownloaded(_ p: AttachmentPointer) -> Bool { files.contains(p.id) }

    /// Fetches an attachment, checks it decrypts, stores it and removes it
    /// from the relay. Safe to call repeatedly.
    public func download(_ p: AttachmentPointer) async {
        guard !downloading.contains(p.id), !files.contains(p.id) else { return }
        downloading.insert(p.id)
        failedDownloads.remove(p.id)
        defer { downloading.remove(p.id) }
        do {
            let blob = try await relay.downloadAttachment(p.id)
            let files = files
            try await Task.detached(priority: .utility) {
                let plain = try AttachmentCipher.decrypt(blob, key: SymmetricKey(data: p.key))
                guard plain.count == p.size else { throw AttachmentCipherError.malformed }
                try files.write(blob, id: p.id)
            }.value
            if removedAttachments.contains(p.id) { files.delete(p.id) }
            try? await relay.deleteAttachment(p.id)
        } catch {
            failedDownloads.insert(p.id)
        }
    }

    /// Decrypted contents of a downloaded (or sent) attachment.
    public func attachmentData(_ p: AttachmentPointer) async throws -> Data {
        let files = files
        return try await Task.detached(priority: .userInitiated) {
            try AttachmentCipher.decrypt(try files.read(p.id), key: SymmetricKey(data: p.key))
        }.value
    }

    private func deleteFiles(of m: ChatMessage) {
        for p in m.attachments ?? [] {
            files.delete(p.id)
            removedAttachments.insert(p.id)
        }
    }

    // MARK: - Disappearing messages and deletion

    /// Sets the disappearing-messages timer for a chat and tells the peer.
    public func setDisappearing(_ seconds: TimeInterval?, for contactID: String) async throws {
        guard var c = contact(contactID) else { throw MessengerError.unknownContact }
        guard c.disappearAfter != seconds else { return }
        c.disappearAfter = seconds
        try saveContact(c)
        recordTimerChange(seconds, in: c.id, outgoing: true)
        try await deliver(MessagePayload(kind: .timer, id: UUID().uuidString, body: "", sentAt: Date(), disappearAfter: seconds), to: c)
    }

    /// Adds a notice about a timer change to the chat. Notices don't
    /// disappear themselves, so a silent change can't go unnoticed.
    private func recordTimerChange(_ seconds: TimeInterval?, in contactID: String, outgoing: Bool, at date: Date = Date()) {
        let msg = ChatMessage(
            id: UUID().uuidString, contactID: contactID, outgoing: outgoing, body: "", sentAt: date,
            // Never .received: that would send a read receipt for it.
            status: outgoing ? .sent : .read, expiresAt: nil, timerChange: TimerChange(seconds: seconds))
        try? saveMessage(msg, preview: Self.preview(of: msg))
    }

    /// Deletes messages on this device only.
    public func deleteMessages(_ ids: [String], in contactID: String) {
        let doomed = ids.compactMap { try? db.get(ChatMessage.self, collection: C.messages, key: $0) }
            .filter { $0.contactID == contactID }
        // Nobody will fetch attachments of an incoming message we deleted
        // before downloading them.
        let blobs = doomed.filter { !$0.outgoing }.flatMap { $0.attachments ?? [] }.filter { !files.contains($0.id) }
        remove(doomed)
        deleteBlobs(blobs)
    }

    /// Deletes our own messages here and on the peer's device. Nothing is
    /// deleted if the request can't be sent.
    public func deleteForEveryone(_ ids: [String], in contactID: String) async throws {
        guard let c = contact(contactID) else { throw MessengerError.unknownContact }
        let doomed = ids.compactMap { try? db.get(ChatMessage.self, collection: C.messages, key: $0) }
            .filter { $0.contactID == contactID && $0.outgoing && $0.call == nil && $0.timerChange == nil }
        guard !doomed.isEmpty else { return }
        try await deliver(MessagePayload(kind: .delete, id: UUID().uuidString, body: "", sentAt: Date(),
                                         disappearAfter: c.disappearAfter, ids: doomed.map(\.id)), to: c)
        remove(doomed)
        // The peer may not have downloaded them yet; they no longer need to.
        deleteBlobs(doomed.flatMap { $0.attachments ?? [] })
    }

    /// Deletes the whole conversation but keeps the contact. With
    /// `forEveryone` the peer's copy is cleared too (nothing is deleted if
    /// that request can't be sent).
    public func clearChat(_ contactID: String, forEveryone: Bool) async throws {
        guard let c = contact(contactID) else { throw MessengerError.unknownContact }
        if forEveryone {
            try await deliver(MessagePayload(kind: .clear, id: UUID().uuidString, body: "", sentAt: Date(),
                                             disappearAfter: c.disappearAfter), to: c)
        }
        let all = (try? db.list(ChatMessage.self, collection: C.messages, group: contactID)) ?? []
        let blobs = all.flatMap { m in (m.attachments ?? []).filter { forEveryone || (!m.outgoing && !files.contains($0.id)) } }
        remove(all)
        deleteBlobs(blobs)
    }

    /// Applies a peer's delete or clear request. A peer can only delete their
    /// own messages, except when clearing the whole chat.
    private func applyDeletion(_ payload: MessagePayload, from c: Contact) {
        let all = (try? db.list(ChatMessage.self, collection: C.messages, group: c.id)) ?? []
        if payload.kind == .clear {
            remove(all)
        } else {
            let ids = Set(payload.ids ?? [])
            remove(all.filter { ids.contains($0.id) && !$0.outgoing && $0.call == nil && $0.timerChange == nil })
        }
    }

    private func deleteBlobs(_ pointers: [AttachmentPointer]) {
        guard !pointers.isEmpty else { return }
        Task { for p in pointers { try? await relay.deleteAttachment(p.id) } }
    }

    /// Deletes messages and their files, then fixes up the chat-list preview
    /// and unread count so no trace of them is left in the contact either.
    private func remove(_ doomed: [ChatMessage]) {
        guard !doomed.isEmpty else { return }
        for m in doomed {
            deleteFiles(of: m)
            try? db.delete(collection: C.messages, key: m.id)
        }
        for contactID in Set(doomed.map(\.contactID)) {
            guard var c = contact(contactID) else { continue }
            let unread = doomed.filter { $0.contactID == contactID && !$0.outgoing && $0.status == .received }.count
            c.unread = max(0, c.unread - unread)
            c.lastPreview = messages(with: contactID).last.map(Self.preview(of:))
            try? saveContact(c)
        }
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
    /// With `wait` > 0 the first fetch long-polls for up to that many seconds.
    @discardableResult
    public func sync(wait: Int = 0) async -> Int {
        guard let auth, let sealing, state?.registered == true else { return 0 }
        var received = 0
        var delivered: [String: [String]] = [:] // contact ID → message IDs
        var toDownload: [AttachmentPointer] = []
        lastFetched = 0
        do {
            var first = true
            while true {
                let batch = try await relay.fetch(auth: auth, wait: first ? wait : 0)
                first = false
                lastFetched += batch.count
                if batch.isEmpty { break }
                for env in batch {
                    if let msg = try? await handle(env.data, sealing: sealing) {
                        received += 1
                        delivered[msg.contactID, default: []].append(msg.id)
                        toDownload += msg.attachments ?? []
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
            // Skip messages a later envelope in the same sync deleted.
            toDownload.removeAll { removedAttachments.contains($0.id) }
            if !toDownload.isEmpty {
                // One at a time keeps memory bounded for large files.
                Task { for p in toDownload { await self.download(p) } }
            }
            if lastMaintenance.map({ Date().timeIntervalSince($0) > Self.maintenanceInterval }) ?? true {
                try await maintainKeys()
                // Fetched ahead of time so the request doesn't reveal a call.
                _ = try? await turnCredentials()
                lastMaintenance = Date()
            }
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
        if payload.kind == .call {
            if let signal = payload.call, let c = contact(content.sender), !c.isRequest {
                onCallSignal?(c.id, signal, max(0, Date().timeIntervalSince(payload.sentAt)))
            }
            return nil
        }
        if payload.kind == .delete || payload.kind == .clear {
            if let c = contact(content.sender) { applyDeletion(payload, from: c) }
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
                // Timer off until the payload sets it, so the chat shows a notice.
                addedAt: Date(), verified: false, isRequest: true, disappearAfter: nil,
                lastActivity: Date(), lastPreview: nil, unread: 0)
        }

        let timerChanged = c.disappearAfter != payload.disappearAfter
        switch payload.kind {
        case .timer:
            c.disappearAfter = payload.disappearAfter
            try saveContact(c)
            if timerChanged {
                recordTimerChange(payload.disappearAfter, in: c.id, outgoing: false, at: min(payload.sentAt, Date()))
            }
            return nil
        case .delivered, .read, .call, .delete, .clear:
            return nil
        case .text:
            // Message IDs are chosen by the sender: never let one replace a
            // message we already have (a duplicate delivery or a forgery).
            if (try? db.get(ChatMessage.self, collection: C.messages, key: payload.id)) != nil { return nil }
            let attachments = acceptedAttachments(payload.attachments)
            c.disappearAfter = payload.disappearAfter
            c.unread += 1
            try saveContact(c)
            let now = Date()
            let sentAt = min(payload.sentAt, now)
            if timerChanged {
                // Just before the message, so it reads in the right order.
                recordTimerChange(payload.disappearAfter, in: c.id, outgoing: false, at: sentAt.addingTimeInterval(-0.001))
            }
            // The timer starts once the message is read (see markRead).
            let msg = ChatMessage(
                id: payload.id, contactID: c.id, outgoing: false, body: payload.body,
                sentAt: sentAt, status: .received, expiresAt: nil,
                attachments: attachments.isEmpty ? nil : attachments, expiresIn: payload.disappearAfter)
            try saveMessage(msg, preview: Self.preview(of: msg))
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

    /// Deletes messages whose timer ran out and schedules the next run for
    /// the earliest timer still going.
    public func purgeExpired() {
        let now = Date()
        var expired: [ChatMessage] = []
        var next: Date?
        for c in contacts {
            for m in (try? db.list(ChatMessage.self, collection: C.messages, group: c.id)) ?? [] {
                guard let at = m.expiresAt else { continue }
                if at <= now {
                    expired.append(m)
                } else {
                    next = min(next ?? at, at)
                }
            }
        }
        remove(expired)
        nextExpiry = nil
        expiryTask?.cancel()
        expiryTask = nil
        if let next { scheduleExpiry(next) }
    }

    private func scheduleExpiry(_ date: Date) {
        guard nextExpiry.map({ date < $0 }) ?? true else { return }
        nextExpiry = date
        expiryTask?.cancel()
        expiryTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(max(0, date.timeIntervalSinceNow) + 0.05))
            guard !Task.isCancelled else { return }
            self?.purgeExpired()
        }
    }

    // MARK: - Calls

    public func sendCallSignal(_ signal: CallSignal, to contactID: String) async throws {
        guard let c = contact(contactID) else { throw MessengerError.unknownContact }
        try await deliver(MessagePayload(kind: .call, id: UUID().uuidString, body: "", sentAt: Date(),
                                         disappearAfter: c.disappearAfter, call: signal), to: c)
    }

    /// Serialized public identity key of this profile.
    public func localIdentityKey() throws -> Data { try engine.identityKey() }

    /// Cached, so fetching them doesn't coincide with (and reveal) a call.
    public func turnCredentials() async throws -> TurnCredentials {
        if let turn, turn.expires.timeIntervalSinceNow > Self.turnMinRemaining { return turn.credentials }
        let fresh = try await relay.turnCredentials()
        turn = (fresh, Date().addingTimeInterval(TimeInterval(fresh.ttl)))
        return fresh
    }

    /// Adds a finished call to the chat. A missed call counts as unread.
    public func recordCall(with contactID: String, outgoing: Bool, info: CallInfo, at date: Date = Date()) {
        guard let c = contact(contactID) else { return }
        let msg = ChatMessage(
            id: UUID().uuidString, contactID: contactID, outgoing: outgoing, body: "", sentAt: date,
            // Never .received: that would send a read receipt for it.
            status: outgoing ? .sent : .read,
            expiresAt: c.disappearAfter.map { Date().addingTimeInterval($0) }, call: info)
        try? saveMessage(msg, preview: Self.preview(of: msg))
        if !outgoing, info.outcome == .missed, var c = contact(contactID) {
            c.unread += 1
            try? saveContact(c)
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
        if let at = m.expiresAt { scheduleExpiry(at) }
        if let preview, var c = contact(m.contactID) {
            c.lastActivity = Date()
            c.lastPreview = preview
            try saveContact(c)
        }
    }

    /// Changes a stored message, unless it has been deleted in the meantime.
    private func updateMessage(_ id: String, _ change: (inout ChatMessage) -> Void) {
        guard var m = try? db.get(ChatMessage.self, collection: C.messages, key: id) else { return }
        change(&m)
        try? saveMessage(m, preview: nil)
    }

    private func reloadContacts() {
        contacts = ((try? db.list(Contact.self, collection: C.contacts)) ?? [])
            .sorted { $0.lastActivity > $1.lastActivity }
    }
}

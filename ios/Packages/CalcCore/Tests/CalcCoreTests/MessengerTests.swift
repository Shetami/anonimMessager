import CryptoKit
import Foundation
import Testing
@testable import CalcCore

/// Stand-in for libsignal: "encryption" is a passthrough tagged with the
/// identity, and signatures are SHA-256(identity || data). Enough to exercise
/// the messenger flow and the identity-binding checks.
final class FakeEngine: E2EEngine {
    var identity: Data?
    var sessions: Set<String> = []

    func createIdentity() throws -> (identityKey: Data, registrationId: UInt32) {
        let ik = Data([0x05]) + KeyDerivation.randomBytes(32)
        identity = ik
        return (ik, 1)
    }
    func identityKey() throws -> Data { identity! }
    func registrationID() throws -> UInt32 { 1 }
    func sign(_ data: Data) throws -> Data { Self.sig(identity!, data) }
    func verify(signature: Data, for data: Data, identityKey: Data) -> Bool { signature == Self.sig(identityKey, data) }
    static func sig(_ ik: Data, _ d: Data) -> Data { Data(SHA256.hash(data: ik + d)) }
    func generateSignedPreKey(id: UInt32) throws -> SignedKey { SignedKey(id: id, publicKey: Data(count: 33)) }
    func generateKyberPreKey(id: UInt32, lastResort: Bool) throws -> SignedKey { SignedKey(id: id, publicKey: Data(count: 64)) }
    func generatePreKeys(startingAt id: UInt32, count: Int) throws -> [SignedKey] {
        (0..<count).map { SignedKey(id: id + UInt32($0), publicKey: Data(count: 33)) }
    }
    func hasSession(with address: String) -> Bool { sessions.contains(address) }
    func startSession(with address: String, bundle: PreKeyBundleDTO) throws { sessions.insert(address) }
    func encrypt(_ plaintext: Data, for address: String) throws -> (EnvelopeContent.Kind, Data) {
        (.preKey, identity! + plaintext)
    }
    func decrypt(_ ciphertext: Data, kind: EnvelopeContent.Kind, from address: String) throws -> Data {
        let ik = ciphertext.prefix(33)
        guard AccountID.from(identityKey: ik) == address else { throw MessengerError.keyMismatch }
        sessions.insert(address)
        return ciphertext.dropFirst(33)
    }
    func deleteSession(with address: String) throws { sessions.remove(address) }
}

/// In-memory model of the Go relay.
final class FakeRelay: RelayTransport, @unchecked Sendable {
    var accounts: [String: RegisterRequest] = [:]
    var queues: [String: [RelayEnvelope]] = [:]
    /// Simulates a malicious relay that swaps in its own keys.
    var substituteIdentity: Data?

    func register(_ req: RegisterRequest, auth: RelayAuth) async throws {
        guard accounts[auth.accountID] == nil else { throw RelayError.conflict }
        accounts[auth.accountID] = req
    }
    func deleteAccount(auth: RelayAuth) async throws { accounts[auth.accountID] = nil }
    func bundle(for id: String) async throws -> PreKeyBundleDTO {
        guard let a = accounts[id] else { throw RelayError.notFound }
        return PreKeyBundleDTO(identityKey: substituteIdentity ?? a.identityKey, registrationId: a.registrationId,
                               sealingKey: a.sealingKey, signedPreKey: a.signedPreKey, preKey: a.preKeys.first,
                               kyberPreKey: a.kyberLastResort)
    }
    func updateKeys(_ update: KeysUpdate, auth: RelayAuth) async throws {}
    func keyCounts(auth: RelayAuth) async throws -> KeyCounts { KeyCounts(preKeys: 100, kyberPreKeys: 20) }
    func send(_ envelope: Data, to id: String) async throws {
        guard accounts[id] != nil else { throw RelayError.notFound }
        queues[id, default: []].append(RelayEnvelope(id: UUID().uuidString, data: envelope))
    }
    func fetch(auth: RelayAuth) async throws -> [RelayEnvelope] { queues[auth.accountID] ?? [] }
    func ack(_ ids: [String], auth: RelayAuth) async throws {
        queues[auth.accountID]?.removeAll { ids.contains($0.id) }
    }
}

@MainActor
struct MessengerTests {
    func makeService(_ relay: FakeRelay) throws -> MessengerService {
        let profile = UnlockedProfile(slot: 0, masterKey: SymmetricKey(size: .bits256))
        let db = try SecureDatabase(url: tempDir().appendingPathComponent("db"), profile: profile)
        return MessengerService(db: db, engine: FakeEngine(), relay: relay)
    }

    @Test func conversation() async throws {
        let relay = FakeRelay()
        let alice = try makeService(relay)
        let bob = try makeService(relay)
        try await alice.register()
        try await bob.register()

        try await alice.addContact(id: bob.accountID!, name: "Bob", verifiedInPerson: true)
        try await alice.send("hi bob", to: bob.accountID!)

        // The relay only ever sees opaque, padded envelopes.
        let raw = try #require(relay.queues[bob.accountID!]?.first?.data)
        #expect(raw.range(of: Data("hi bob".utf8)) == nil)
        #expect(raw.range(of: Data(alice.accountID!.utf8)) == nil)

        #expect(await bob.sync() == 1)
        let request = try #require(bob.contacts.first)
        #expect(request.id == alice.accountID)
        #expect(request.isRequest)
        #expect(bob.messages(with: request.id).map(\.body) == ["hi bob"])

        try await bob.send("hi alice", to: request.id)
        #expect(await alice.sync() == 1)
        #expect(alice.messages(with: bob.accountID!).map(\.body) == ["hi bob", "hi alice"])
    }

    @Test func receipts() async throws {
        let relay = FakeRelay()
        let alice = try makeService(relay)
        let bob = try makeService(relay)
        try await alice.register()
        try await bob.register()
        try await alice.addContact(id: bob.accountID!, name: "Bob", verifiedInPerson: false)
        try await alice.send("hi bob", to: bob.accountID!)
        #expect(alice.messages(with: bob.accountID!).map(\.status) == [.sent])

        await bob.sync()
        #expect(await alice.sync() == 0) // receipts aren't counted as messages
        #expect(alice.messages(with: bob.accountID!).map(\.status) == [.delivered])

        await bob.markRead(alice.accountID!)
        #expect(bob.messages(with: alice.accountID!).map(\.status) == [.read])
        await alice.sync()
        #expect(alice.messages(with: bob.accountID!).map(\.status) == [.read])

        // Already reported: no second receipt.
        await bob.markRead(alice.accountID!)
        #expect(relay.queues[alice.accountID!, default: []].isEmpty)
    }

    @Test func rejectsSubstitutedKeys() async throws {
        let relay = FakeRelay()
        let alice = try makeService(relay)
        let bob = try makeService(relay)
        try await alice.register()
        try await bob.register()
        relay.substituteIdentity = Data([0x05]) + Data(count: 32)
        await #expect(throws: MessengerError.keyMismatch) {
            try await alice.addContact(id: bob.accountID!, name: "Bob", verifiedInPerson: false)
        }
    }

    @Test func disappearingMessages() async throws {
        let relay = FakeRelay()
        let alice = try makeService(relay)
        let bob = try makeService(relay)
        try await alice.register()
        try await bob.register()
        try await alice.addContact(id: bob.accountID!, name: "Bob", verifiedInPerson: false)
        try await alice.setDisappearing(0.01, for: bob.accountID!)
        try await alice.send("gone soon", to: bob.accountID!)
        await bob.sync()
        #expect(bob.contacts.first?.disappearAfter == 0.01)
        try await Task.sleep(for: .milliseconds(50))
        #expect(bob.messages(with: alice.accountID!).isEmpty)
        #expect(alice.messages(with: bob.accountID!).isEmpty)
    }
}

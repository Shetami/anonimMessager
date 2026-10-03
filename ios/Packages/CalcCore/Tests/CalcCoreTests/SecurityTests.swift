import CryptoKit
import Foundation
import Testing
@testable import CalcCore

func tempDir() -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

struct VaultTests {
    func makeVault(_ secret: DeviceSecretProvider = InMemoryDeviceSecret()) -> Vault {
        Vault(directory: tempDir(), deviceSecret: secret, iterations: 1000)
    }

    @Test func primaryAndDecoyOpenDifferentProfiles() throws {
        let v = makeVault()
        let setup = try v.setup(code: "1337")
        #expect(try v.unlock(code: "1337")?.slot == setup.primary.slot)
        #expect(try v.unlock(code: "0000") == nil)
        // Sibling slot isn't openable until a decoy code is assigned.
        try v.setCode("2468", for: setup.sibling)
        let decoy = try #require(try v.unlock(code: "2468"))
        #expect(decoy.slot == setup.sibling.slot)
        #expect(decoy.masterKey == setup.sibling.masterKey)
        #expect(decoy.databaseFileName != setup.primary.databaseFileName)
    }

    @Test func decoyCodeCannotEqualPrimary() throws {
        let v = makeVault()
        let setup = try v.setup(code: "1337")
        #expect(throws: VaultError.codeInUse) { try v.setCode("1337", for: setup.sibling) }
    }

    @Test func fileSizeIsConstant() throws {
        let v = makeVault()
        let setup = try v.setup(code: "1337")
        let before = try Data(contentsOf: v.fileURL).count
        try v.setCode("2468", for: setup.sibling)
        #expect(try Data(contentsOf: v.fileURL).count == before)
    }

    @Test func revokeAndChange() throws {
        let v = makeVault()
        let setup = try v.setup(code: "1337")
        try v.setCode("2468", for: setup.sibling)
        try v.revokeCode(for: setup.sibling)
        #expect(try v.unlock(code: "2468") == nil)
        try v.setCode("9999", for: setup.primary)
        #expect(try v.unlock(code: "1337") == nil)
        #expect(try v.unlock(code: "9999")?.slot == setup.primary.slot)
    }

    @Test func deviceSecretIsRequired() throws {
        let secret = InMemoryDeviceSecret()
        let dir = tempDir()
        _ = try Vault(directory: dir, deviceSecret: secret, iterations: 1000).setup(code: "1337")
        // Same files, different device: nothing opens.
        let other = Vault(directory: dir, deviceSecret: InMemoryDeviceSecret(), iterations: 1000)
        #expect(try other.unlock(code: "1337") == nil)
    }

    @Test func destroyErasesEverything() throws {
        let v = makeVault()
        _ = try v.setup(code: "1337")
        v.destroy()
        #expect(!v.isInitialized)
    }
}

struct DatabaseTests {
    struct Item: Codable, Equatable { var n: Int }

    @Test func roundTripAndGroups() throws {
        let profile = UnlockedProfile(slot: 0, masterKey: SymmetricKey(size: .bits256))
        let db = try SecureDatabase(url: tempDir().appendingPathComponent("db"), profile: profile)
        try db.put(Item(n: 2), collection: "m", key: "b", group: "chat1", sort: 2)
        try db.put(Item(n: 1), collection: "m", key: "a", group: "chat1", sort: 1)
        try db.put(Item(n: 9), collection: "m", key: "c", group: "chat2", sort: 0)
        #expect(try db.list(Item.self, collection: "m", group: "chat1") == [Item(n: 1), Item(n: 2)])
        #expect(try db.get(Item.self, collection: "m", key: "c") == Item(n: 9))
        try db.deleteGroup(collection: "m", group: "chat1")
        #expect(try db.list(Item.self, collection: "m").count == 1)
    }

    @Test func plaintextNeverHitsDisk() throws {
        let url = tempDir().appendingPathComponent("db")
        let profile = UnlockedProfile(slot: 0, masterKey: SymmetricKey(size: .bits256))
        let db = try SecureDatabase(url: url, profile: profile)
        try db.put(["secret": "meet at the bridge"], collection: "contacts", key: "alice")
        let raw = try Data(contentsOf: url)
        for needle in ["meet at the bridge", "alice", "contacts"] {
            #expect(raw.range(of: Data(needle.utf8)) == nil)
        }
    }

    @Test func wrongKeyCannotRead() throws {
        let url = tempDir().appendingPathComponent("db")
        let key = SymmetricKey(size: .bits256)
        try SecureDatabase(url: url, profile: .init(slot: 0, masterKey: key)).put(Item(n: 1), collection: "m", key: "a")
        let other = try SecureDatabase(url: url, profile: .init(slot: 0, masterKey: SymmetricKey(size: .bits256)))
        #expect(try other.get(Item.self, collection: "m", key: "a") == nil)
    }
}

struct EnvelopeTests {
    @Test func sealAndOpen() throws {
        let recipient = Curve25519.KeyAgreement.PrivateKey()
        let content = EnvelopeContent(sender: "abc", kind: .whisper, ciphertext: Data(repeating: 7, count: 100))
        let sealed = try SealedEnvelope.seal(content, to: recipient.publicKey)
        #expect(try SealedEnvelope.open(sealed, with: recipient) == content)
        #expect(throws: (any Error).self) { try SealedEnvelope.open(sealed, with: .init()) }
    }

    @Test func lengthsAreBucketed() throws {
        let recipient = Curve25519.KeyAgreement.PrivateKey().publicKey
        let short = try SealedEnvelope.seal(.init(sender: "a", kind: .whisper, ciphertext: Data(count: 10)), to: recipient)
        let longer = try SealedEnvelope.seal(.init(sender: "a", kind: .whisper, ciphertext: Data(count: 500)), to: recipient)
        #expect(short.count == longer.count)
    }

    @Test func padding() {
        for n in [0, 1, 1023, 1024, 5000, 70000] {
            let d = Data(repeating: 0x80, count: n)
            let p = Padding.pad(d)
            #expect(p.count >= n + 1)
            #expect(Padding.unpad(p) == d)
        }
    }

    @Test func accountIDMatchesServer() {
        // Same vector as server: AccountID(0x05 || 32×0x00)
        let id = AccountID.from(identityKey: Data([0x05]) + Data(count: 32))
        #expect(id == "s2qb422dlmi2wm2zzg5yptqcendg6hpe")
        #expect(AccountID.normalize("calc:" + AccountID.grouped(id).uppercased()) == id)
    }

    @Test func relayAuthSignatureVerifies() throws {
        let key = Curve25519.Signing.PrivateKey()
        let header = try RelayAuth(accountID: "x", key: key).header(method: "GET", path: "/v1/messages", body: Data())
        let parts = header.dropFirst("Calc ".count).split(separator: ":").map(String.init)
        let payload = RelayAuth.payload(method: "GET", path: "/v1/messages", timestamp: Int64(parts[1])!, nonce: parts[2], body: Data())
        #expect(key.publicKey.isValidSignature(Data(base64Encoded: parts[3])!, for: payload))
    }
}

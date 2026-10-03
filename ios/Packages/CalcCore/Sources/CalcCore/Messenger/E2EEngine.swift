import Foundation

/// The end-to-end encryption engine (Signal Protocol). Implemented in the app
/// target on top of libsignal so this package stays dependency-free and
/// testable. Addresses are account IDs; the implementation must only trust an
/// identity key for address X if `AccountID.from(identityKey:) == X`, which
/// cryptographically binds every contact ID to exactly one identity key.
public protocol E2EEngine: AnyObject {
    /// Creates and persists a new identity. Returns the serialized public key.
    func createIdentity() throws -> (identityKey: Data, registrationId: UInt32)
    func identityKey() throws -> Data
    func registrationID() throws -> UInt32

    /// Signs with the identity key (XEdDSA); verified by peers.
    func sign(_ data: Data) throws -> Data
    func verify(signature: Data, for data: Data, identityKey: Data) -> Bool

    func generateSignedPreKey(id: UInt32) throws -> SignedKey
    /// One-time Kyber keys are deleted after first use; the last-resort key is reused.
    func generateKyberPreKey(id: UInt32, lastResort: Bool) throws -> SignedKey
    func generatePreKeys(startingAt id: UInt32, count: Int) throws -> [SignedKey]

    func hasSession(with address: String) -> Bool
    /// Runs X3DH/PQXDH against a fetched bundle. Must verify bundle signatures.
    func startSession(with address: String, bundle: PreKeyBundleDTO) throws
    func encrypt(_ plaintext: Data, for address: String) throws -> (EnvelopeContent.Kind, Data)
    func decrypt(_ ciphertext: Data, kind: EnvelopeContent.Kind, from address: String) throws -> Data
    func deleteSession(with address: String) throws
}

// MARK: - Persistent models (stored in the profile's SecureDatabase)

public struct ProfileState: Codable, Sendable {
    public var accountID: String
    public var authKey: Data
    public var sealingKey: Data
    public var nextPreKeyID: UInt32
    public var nextKyberID: UInt32
    public var nextSignedPreKeyID: UInt32
    public var signedPreKeyRotatedAt: Date
    public var registered: Bool
}

/// Only present in the primary profile: lets it assign a decoy code to the
/// other vault slot. The decoy profile never has this.
public struct SiblingSlot: Codable, Sendable {
    public var slot: Int
    public var masterKey: Data
    public var codeAssigned: Bool
}

public struct Contact: Codable, Identifiable, Hashable, Sendable {
    public var id: String
    public var name: String
    public var identityKey: Data
    public var sealingKey: Data
    public var addedAt: Date
    /// Set when the ID came from a scanned QR code (in-person verification).
    public var verified: Bool
    /// Contact reached out first and hasn't been named/accepted yet.
    public var isRequest: Bool
    /// Disappearing-messages timer in seconds (nil = off).
    public var disappearAfter: TimeInterval?
    public var lastActivity: Date
    public var lastPreview: String?
    public var unread: Int
}

public struct ChatMessage: Codable, Identifiable, Hashable, Sendable {
    public enum Status: String, Codable, Sendable { case sending, sent, failed, received }

    public var id: String
    public var contactID: String
    public var outgoing: Bool
    public var body: String
    public var sentAt: Date
    public var status: Status
    public var expiresAt: Date?
}

/// Plaintext inside the Signal message. Timestamps and everything else about
/// the message are only ever visible end-to-end.
public struct MessagePayload: Codable, Sendable {
    public enum Kind: String, Codable, Sendable { case text, timer }

    public var kind: Kind
    public var id: String
    public var body: String
    public var sentAt: Date
    public var disappearAfter: TimeInterval?
}

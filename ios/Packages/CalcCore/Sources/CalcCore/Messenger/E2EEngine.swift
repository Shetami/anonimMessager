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
    /// Outgoing: sending → sent (accepted by the relay) → delivered → read.
    /// Incoming: received, then read once the read receipt went out.
    public enum Status: String, Codable, Sendable { case sending, sent, failed, received, delivered, read }

    public var id: String
    public var contactID: String
    public var outgoing: Bool
    public var body: String
    public var sentAt: Date
    public var status: Status
    public var expiresAt: Date?
    public var attachments: [AttachmentPointer]? = nil
    /// Set for call-log entries (body is empty).
    public var call: CallInfo? = nil
}

/// Everything needed to fetch and decrypt one attachment from the relay.
/// Travels only inside the end-to-end encrypted message.
public struct AttachmentPointer: Codable, Hashable, Identifiable, Sendable {
    /// Relay blob ID: 128 random bits, hex.
    public var id: String
    /// ChaCha20-Poly1305 key for this attachment only.
    public var key: Data
    /// Plaintext size in bytes.
    public var size: Int
    public var name: String
    public var mime: String
    /// Small JPEG preview for photos and videos.
    public var thumbnail: Data?
    public var width: Int?
    public var height: Int?

    public var isImage: Bool { mime.hasPrefix("image/") }
    public var isVideo: Bool { mime.hasPrefix("video/") }
}

/// A file the user picked, before it is encrypted and uploaded.
public struct OutgoingAttachment: Sendable {
    public var data: Data
    public var name: String
    public var mime: String
    public var thumbnail: Data?
    public var width: Int?
    public var height: Int?

    public init(data: Data, name: String, mime: String, thumbnail: Data? = nil, width: Int? = nil, height: Int? = nil) {
        self.data = data
        self.name = name
        self.mime = mime
        self.thumbnail = thumbnail
        self.width = width
        self.height = height
    }
}

/// Plaintext inside the Signal message. Timestamps and everything else about
/// the message are only ever visible end-to-end.
public struct MessagePayload: Codable, Sendable {
    public enum Kind: String, Codable, Sendable { case text, timer, delivered, read, call }

    public var kind: Kind
    public var id: String
    public var body: String
    public var sentAt: Date
    public var disappearAfter: TimeInterval?
    /// Message IDs a delivered/read receipt refers to.
    public var ids: [String]? = nil
    public var attachments: [AttachmentPointer]? = nil
    public var call: CallSignal? = nil
}

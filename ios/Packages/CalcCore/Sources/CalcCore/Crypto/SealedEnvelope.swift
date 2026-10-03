import CryptoKit
import Foundation

/// What travels inside the sealed envelope. `ciphertext` is the Signal
/// Protocol message; the sender ID is only visible to the recipient.
public struct EnvelopeContent: Codable, Equatable, Sendable {
    public enum Kind: UInt8, Codable, Sendable {
        case preKey = 3   // matches libsignal CiphertextMessage.MessageType.preKey
        case whisper = 2  // matches libsignal CiphertextMessage.MessageType.whisper
    }

    public var sender: String
    public var senderDevice: UInt32
    public var kind: Kind
    public var ciphertext: Data

    public init(sender: String, senderDevice: UInt32 = 1, kind: Kind, ciphertext: Data) {
        self.sender = sender
        self.senderDevice = senderDevice
        self.kind = kind
        self.ciphertext = ciphertext
    }
}

public enum SealError: Error {
    case malformed
    case version
}

/// Hides the sender from the relay ("sealed sender" without server-issued
/// certificates). The recipient's sealing key is an X25519 key signed by
/// their identity key; the signature is checked when the bundle is fetched.
///
///     envelope = 0x01 || ephemeralPub[32] || ChaChaPoly(key, pad(json(content)))
///     key      = HKDF-SHA256(X25519(eph, recipientSealing),
///                            salt: ephemeralPub || recipientSealingPub,
///                            info: "calc.seal.v1")
///
/// Sender authenticity comes from the inner Signal message: it only decrypts
/// under the session bound to the sender's identity key.
public enum SealedEnvelope {
    static let version: UInt8 = 1

    public static func seal(_ content: EnvelopeContent, to sealingKey: Curve25519.KeyAgreement.PublicKey) throws -> Data {
        let eph = Curve25519.KeyAgreement.PrivateKey()
        let key = try deriveKey(
            shared: eph.sharedSecretFromKeyAgreement(with: sealingKey),
            ephemeral: eph.publicKey.rawRepresentation, recipient: sealingKey.rawRepresentation)
        let plaintext = Padding.pad(try JSONEncoder().encode(content))
        let box = try ChaChaPoly.seal(plaintext, using: key)
        return Data([version]) + eph.publicKey.rawRepresentation + box.combined
    }

    public static func open(_ data: Data, with sealingKey: Curve25519.KeyAgreement.PrivateKey) throws -> EnvelopeContent {
        guard data.count > 1 + 32 + 12 + 16 else { throw SealError.malformed }
        let bytes = Data(data)
        guard bytes[0] == version else { throw SealError.version }
        let ephRaw = bytes[1..<33]
        let eph = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephRaw)
        let key = try deriveKey(
            shared: sealingKey.sharedSecretFromKeyAgreement(with: eph),
            ephemeral: Data(ephRaw), recipient: sealingKey.publicKey.rawRepresentation)
        let box = try ChaChaPoly.SealedBox(combined: bytes[33...])
        guard let plaintext = Padding.unpad(try ChaChaPoly.open(box, using: key)) else { throw SealError.malformed }
        return try JSONDecoder().decode(EnvelopeContent.self, from: plaintext)
    }

    private static func deriveKey(shared: SharedSecret, ephemeral: Data, recipient: Data) -> SymmetricKey {
        shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: ephemeral + recipient,
            sharedInfo: Data("calc.seal.v1".utf8), outputByteCount: 32)
    }
}

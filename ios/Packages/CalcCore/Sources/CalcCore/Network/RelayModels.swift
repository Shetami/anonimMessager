import Foundation

/// Wire types shared with the relay (server/internal/store). Go encodes
/// []byte as base64, which is also Foundation's default for Data.
public struct SignedKey: Codable, Equatable, Sendable {
    public var id: UInt32
    public var publicKey: Data
    public var signature: Data?

    public init(id: UInt32, publicKey: Data, signature: Data? = nil) {
        self.id = id
        self.publicKey = publicKey
        self.signature = signature
    }
}

public struct RegisterRequest: Codable, Sendable {
    public var identityKey: Data
    public var authKey: Data
    public var registrationId: UInt32
    public var sealingKey: SignedKey
    public var signedPreKey: SignedKey
    public var kyberLastResort: SignedKey
    public var preKeys: [SignedKey]
    public var kyberPreKeys: [SignedKey]

    public init(identityKey: Data, authKey: Data, registrationId: UInt32, sealingKey: SignedKey,
                signedPreKey: SignedKey, kyberLastResort: SignedKey, preKeys: [SignedKey], kyberPreKeys: [SignedKey]) {
        self.identityKey = identityKey
        self.authKey = authKey
        self.registrationId = registrationId
        self.sealingKey = sealingKey
        self.signedPreKey = signedPreKey
        self.kyberLastResort = kyberLastResort
        self.preKeys = preKeys
        self.kyberPreKeys = kyberPreKeys
    }
}

public struct KeysUpdate: Codable, Sendable {
    public var signedPreKey: SignedKey?
    public var kyberLastResort: SignedKey?
    public var preKeys: [SignedKey]
    public var kyberPreKeys: [SignedKey]

    public init(signedPreKey: SignedKey? = nil, kyberLastResort: SignedKey? = nil,
                preKeys: [SignedKey] = [], kyberPreKeys: [SignedKey] = []) {
        self.signedPreKey = signedPreKey
        self.kyberLastResort = kyberLastResort
        self.preKeys = preKeys
        self.kyberPreKeys = kyberPreKeys
    }
}

public struct KeyCounts: Codable, Sendable {
    public var preKeys: Int
    public var kyberPreKeys: Int
}

public struct PreKeyBundleDTO: Codable, Sendable {
    public var identityKey: Data
    public var registrationId: UInt32
    public var sealingKey: SignedKey
    public var signedPreKey: SignedKey
    public var preKey: SignedKey?
    public var kyberPreKey: SignedKey
}

public struct RelayEnvelope: Codable, Sendable {
    public var id: String
    public var data: Data
}

struct FetchResponse: Codable {
    var messages: [RelayEnvelope]
}

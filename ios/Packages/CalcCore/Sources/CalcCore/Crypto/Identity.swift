import CryptoKit
import Foundation

public enum AccountID {
    /// Must match `api.AccountID` on the relay: lowercase unpadded base32 of
    /// the first 20 bytes of SHA-256(serialized identity public key).
    ///
    /// Because the ID commits to the identity key, a contact ID exchanged
    /// out-of-band (QR code in person) lets the client detect a relay that
    /// tries to substitute keys.
    public static func from(identityKey: Data) -> String {
        Base32.encode(Data(SHA256.hash(data: identityKey)).prefix(20)).lowercased()
    }

    public static func isValid(_ id: String) -> Bool {
        id.count == 32 && id.allSatisfy { Base32.alphabet.contains($0.uppercased()) }
    }

    /// "abcd efgh ..." groups of 4 for reading aloud / comparing.
    public static func grouped(_ id: String) -> String {
        stride(from: 0, to: id.count, by: 4).map { i -> String in
            let start = id.index(id.startIndex, offsetBy: i)
            let end = id.index(start, offsetBy: min(4, id.count - i))
            return String(id[start..<end])
        }.joined(separator: " ")
    }

    /// Accepts IDs pasted with spaces/dashes or as a "calc:" link.
    public static func normalize(_ input: String) -> String? {
        var s = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if s.hasPrefix("calc:") { s.removeFirst(5) }
        s = s.filter { !$0.isWhitespace && $0 != "-" }
        return isValid(s) ? s : nil
    }
}

public enum Base32 {
    static let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    public static func encode(_ data: Data) -> String {
        let chars = Array(alphabet)
        var out = ""
        var buffer = 0
        var bits = 0
        for byte in data {
            buffer = (buffer << 8) | Int(byte)
            bits += 8
            while bits >= 5 {
                out.append(chars[(buffer >> (bits - 5)) & 31])
                bits -= 5
            }
        }
        if bits > 0 {
            out.append(chars[(buffer << (5 - bits)) & 31])
        }
        return out
    }
}

/// Signs relay requests with the Ed25519 auth key. Must match the relay's
/// `api.SigningPayload`.
public struct RelayAuth: Sendable {
    public let accountID: String
    public let key: Curve25519.Signing.PrivateKey

    public init(accountID: String, key: Curve25519.Signing.PrivateKey) {
        self.accountID = accountID
        self.key = key
    }

    public static func payload(method: String, path: String, timestamp: Int64, nonce: String, body: Data) -> Data {
        let hash = SHA256.hash(data: body).map { String(format: "%02x", $0) }.joined()
        return Data("\(method)\n\(path)\n\(timestamp)\n\(nonce)\n\(hash)".utf8)
    }

    public func header(method: String, path: String, body: Data, now: Date = Date()) throws -> String {
        let ts = Int64(now.timeIntervalSince1970)
        let nonce = KeyDerivation.randomBytes(16).map { String(format: "%02x", $0) }.joined()
        let sig = try key.signature(for: Self.payload(method: method, path: path, timestamp: ts, nonce: nonce, body: body))
        return "Calc \(accountID):\(ts):\(nonce):\(sig.base64EncodedString())"
    }
}

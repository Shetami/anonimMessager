import CryptoKit
import Foundation

public enum AttachmentCipherError: Error {
    case malformed
}

/// Encrypts attachments for the relay with a fresh per-attachment key that
/// only travels inside the end-to-end encrypted message.
///
///     blob = ChaChaPoly(key, pad(file))
///
/// Padding grows in 5% steps (as Signal does), so the relay learns a file's
/// size only to within ~5%.
public enum AttachmentCipher {
    static let minimumSize = 1024

    public static func paddedSize(for length: Int) -> Int {
        let needed = length + 1
        if needed <= minimumSize { return minimumSize }
        let size = Int(pow(1.05, ceil(log(Double(needed)) / log(1.05))))
        return max(size, needed)
    }

    public static func encrypt(_ data: Data, key: SymmetricKey) throws -> Data {
        var padded = data
        padded.append(0x80)
        padded.append(Data(count: paddedSize(for: data.count) - padded.count))
        return try ChaChaPoly.seal(padded, using: key).combined
    }

    public static func decrypt(_ blob: Data, key: SymmetricKey) throws -> Data {
        let box = try ChaChaPoly.SealedBox(combined: blob)
        guard let plaintext = Padding.unpad(try ChaChaPoly.open(box, using: key)) else {
            throw AttachmentCipherError.malformed
        }
        return Data(plaintext)
    }
}

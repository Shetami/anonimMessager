import CommonCrypto
import CryptoKit
import Foundation

public enum KeyDerivation {
    /// PBKDF2-HMAC-SHA256. On its own this only slows guessing; the real
    /// protection against offline brute force is mixing in the device secret,
    /// which never leaves the device (Secure Enclave on real hardware).
    public static func pbkdf2(_ password: String, salt: Data, iterations: UInt32, length: Int = 32) -> Data {
        var out = Data(count: length)
        let pw = Array(password.utf8)
        let status = out.withUnsafeMutableBytes { outPtr in
            salt.withUnsafeBytes { saltPtr in
                pw.withUnsafeBufferPointer { pwPtr in
                    pwPtr.baseAddress!.withMemoryRebound(to: Int8.self, capacity: pw.count) { pwChars in
                        CCKeyDerivationPBKDF(
                            CCPBKDFAlgorithm(kCCPBKDF2), pwChars, pw.count,
                            saltPtr.bindMemory(to: UInt8.self).baseAddress, salt.count,
                            CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), iterations,
                            outPtr.bindMemory(to: UInt8.self).baseAddress, length)
                    }
                }
            }
        }
        precondition(status == kCCSuccess, "PBKDF2 failed")
        return out
    }

    public static func hkdf(_ ikm: Data, info: String, salt: Data = Data(), length: Int = 32) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: ikm), salt: salt,
            info: Data(info.utf8), outputByteCount: length)
    }

    public static func subkey(_ key: SymmetricKey, info: String) -> SymmetricKey {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: key, info: Data(info.utf8), outputByteCount: 32)
    }

    public static func randomBytes(_ count: Int) -> Data {
        var d = Data(count: count)
        let ok = d.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!) }
        precondition(ok == errSecSuccess, "SecRandomCopyBytes failed")
        return d
    }
}

extension SymmetricKey {
    public var data: Data { withUnsafeBytes { Data($0) } }
}

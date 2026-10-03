import CryptoKit
import Foundation

public enum RelayError: Error, Equatable {
    case http(Int)
    case notFound
    case conflict
    case mailboxFull
    case tooLarge
    case storageFull
    /// Network-level failure (no route, refused, TLS, local-network denied…).
    case transport(String)
}

public struct RelayConfig: Sendable {
    public var baseURL: URL
    /// Base64 SHA-256 hashes of the server's SubjectPublicKeyInfo. When
    /// non-empty, connections whose chain contains none of them are refused,
    /// so a rogue CA / TLS-intercepting proxy cannot read relay traffic.
    public var spkiPins: [String]

    public init(baseURL: URL, spkiPins: [String]) {
        self.baseURL = baseURL
        self.spkiPins = spkiPins
    }
}

public protocol RelayTransport: Sendable {
    func register(_ req: RegisterRequest, auth: RelayAuth) async throws
    func deleteAccount(auth: RelayAuth) async throws
    func bundle(for id: String) async throws -> PreKeyBundleDTO
    func updateKeys(_ update: KeysUpdate, auth: RelayAuth) async throws
    func keyCounts(auth: RelayAuth) async throws -> KeyCounts
    func send(_ envelope: Data, to id: String) async throws
    /// With `wait` > 0 the relay holds the request (long poll) until an
    /// envelope arrives or that many seconds pass.
    func fetch(auth: RelayAuth, wait: Int) async throws -> [RelayEnvelope]
    func ack(_ ids: [String], auth: RelayAuth) async throws
    /// Attachments are unauthenticated: the random blob ID is the capability.
    func uploadAttachment(_ blob: Data, id: String) async throws
    func downloadAttachment(_ id: String) async throws -> Data
    func deleteAttachment(_ id: String) async throws
    /// Unauthenticated, so the relay can't tie them to a mailbox.
    func turnCredentials() async throws -> TurnCredentials
}

public final class RelayClient: NSObject, RelayTransport, URLSessionDelegate, @unchecked Sendable {
    private let config: RelayConfig
    private var session: URLSession!

    public init(config: RelayConfig) {
        self.config = config
        super.init()
        let cfg = URLSessionConfiguration.ephemeral // no cookies, no cache, no credential storage
        cfg.urlCache = nil
        cfg.httpCookieStorage = nil
        cfg.httpShouldSetCookies = false
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        cfg.timeoutIntervalForRequest = 30
        cfg.tlsMinimumSupportedProtocolVersion = .TLSv13
        cfg.httpAdditionalHeaders = ["User-Agent": "calc"]
        session = URLSession(configuration: cfg, delegate: self, delegateQueue: nil)
    }

    public func register(_ req: RegisterRequest, auth: RelayAuth) async throws {
        _ = try await call("POST", "/v1/accounts", body: try JSONEncoder().encode(req), auth: auth)
    }

    public func deleteAccount(auth: RelayAuth) async throws {
        _ = try await call("DELETE", "/v1/accounts", auth: auth)
    }

    public func bundle(for id: String) async throws -> PreKeyBundleDTO {
        guard AccountID.isValid(id) else { throw RelayError.notFound }
        let data = try await call("GET", "/v1/accounts/\(id)/bundle")
        return try JSONDecoder().decode(PreKeyBundleDTO.self, from: data)
    }

    public func updateKeys(_ update: KeysUpdate, auth: RelayAuth) async throws {
        _ = try await call("PUT", "/v1/keys", body: try JSONEncoder().encode(update), auth: auth)
    }

    public func keyCounts(auth: RelayAuth) async throws -> KeyCounts {
        try JSONDecoder().decode(KeyCounts.self, from: try await call("GET", "/v1/keys/count", auth: auth))
    }

    public func send(_ envelope: Data, to id: String) async throws {
        guard AccountID.isValid(id) else { throw RelayError.notFound }
        _ = try await call("PUT", "/v1/messages/\(id)", body: envelope)
    }

    public func fetch(auth: RelayAuth, wait: Int) async throws -> [RelayEnvelope] {
        let data = wait > 0
            ? try await call("GET", "/v1/messages", query: [URLQueryItem(name: "wait", value: String(wait))],
                             auth: auth, timeout: TimeInterval(wait) + 15)
            : try await call("GET", "/v1/messages", auth: auth)
        return try JSONDecoder().decode(FetchResponse.self, from: data).messages
    }

    public func ack(_ ids: [String], auth: RelayAuth) async throws {
        guard !ids.isEmpty else { return }
        _ = try await call("POST", "/v1/messages/ack", body: try JSONEncoder().encode(["ids": ids]), auth: auth)
    }

    public func uploadAttachment(_ blob: Data, id: String) async throws {
        guard Self.isValidBlobID(id) else { throw RelayError.notFound }
        _ = try await call("PUT", "/v1/attachments/\(id)", body: blob, timeout: Self.attachmentTimeout)
    }

    public func downloadAttachment(_ id: String) async throws -> Data {
        guard Self.isValidBlobID(id) else { throw RelayError.notFound }
        return try await call("GET", "/v1/attachments/\(id)", timeout: Self.attachmentTimeout)
    }

    public func deleteAttachment(_ id: String) async throws {
        guard Self.isValidBlobID(id) else { throw RelayError.notFound }
        _ = try await call("DELETE", "/v1/attachments/\(id)")
    }

    public func turnCredentials() async throws -> TurnCredentials {
        try JSONDecoder().decode(TurnCredentials.self, from: try await call("GET", "/v1/turn"))
    }

    static let attachmentTimeout: TimeInterval = 15 * 60

    public static func isValidBlobID(_ id: String) -> Bool {
        id.count == 32 && id.allSatisfy { $0.isHexDigit && !$0.isUppercase }
    }

    /// The auth signature covers `path` only, never the query string.
    private func call(_ method: String, _ path: String, query: [URLQueryItem] = [], body: Data = Data(),
                      auth: RelayAuth? = nil, timeout: TimeInterval? = nil) async throws -> Data {
        var url = config.baseURL.appendingPathComponent(path)
        if !query.isEmpty { url.append(queryItems: query) }
        var req = URLRequest(url: url)
        req.httpMethod = method
        if let timeout { req.timeoutInterval = timeout }
        if !body.isEmpty {
            req.httpBody = body
            req.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        }
        if let auth {
            req.setValue(try auth.header(method: method, path: path, body: body), forHTTPHeaderField: "Authorization")
        }
        let data: Data
        let resp: URLResponse
        do {
            (data, resp) = try await session.data(for: req)
        } catch {
            throw RelayError.transport(error.localizedDescription)
        }
        let status = (resp as? HTTPURLResponse)?.statusCode ?? 0
        switch status {
        case 200..<300: return data
        case 404: throw RelayError.notFound
        case 409: throw RelayError.conflict
        case 413: throw RelayError.tooLarge
        case 429: throw RelayError.mailboxFull
        case 507: throw RelayError.storageFull
        default: throw RelayError.http(status)
        }
    }

    // MARK: - Certificate pinning

    public func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
                           completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust
        else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        guard SecTrustEvaluateWithError(trust, nil) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        if config.spkiPins.isEmpty {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        let chain = (SecTrustCopyCertificateChain(trust) as? [SecCertificate]) ?? []
        let matched = chain.contains { cert in
            guard let hash = Self.spkiHash(cert) else { return false }
            return config.spkiPins.contains(hash)
        }
        completionHandler(matched ? .useCredential : .cancelAuthenticationChallenge,
                          matched ? URLCredential(trust: trust) : nil)
    }

    /// SHA-256 over the DER SubjectPublicKeyInfo (same value as
    /// `openssl x509 -pubkey | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64`).
    static func spkiHash(_ cert: SecCertificate) -> String? {
        guard let key = SecCertificateCopyKey(cert),
              let raw = SecKeyCopyExternalRepresentation(key, nil) as Data?,
              let attrs = SecKeyCopyAttributes(key) as? [CFString: Any],
              let type = attrs[kSecAttrKeyType] as? String,
              let bits = attrs[kSecAttrKeySizeInBits] as? Int
        else { return nil }
        let ec = type == (kSecAttrKeyTypeECSECPrimeRandom as String)
        let rsa = type == (kSecAttrKeyTypeRSA as String)
        let header: [UInt8]
        switch (ec, rsa, bits) {
        case (true, _, 256):
            header = [0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                      0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00]
        case (true, _, 384):
            header = [0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                      0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00]
        case (_, true, 2048):
            header = [0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                      0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00]
        case (_, true, 4096):
            header = [0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                      0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00]
        default:
            return nil
        }
        return Data(SHA256.hash(data: Data(header) + raw)).base64EncodedString()
    }
}

import CalcCore
import Foundation

enum AppConfig {
    /// Your relay (see server/README.md). Must be HTTPS in release builds.
    static let relay = RelayConfig(
        baseURL: URL(string: "http://192.168.0.149:8090")!,
        // SHA-256 of the server key's SubjectPublicKeyInfo, base64. Pin the
        // leaf key AND a backup key so you can rotate certificates:
        //   openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der \
        //     | openssl dgst -sha256 -binary | base64
        spkiPins: [
            // "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ]
    )

    /// Fallback polling when the relay doesn't hold requests open (or fails).
    static let pollInterval: Duration = .seconds(5)
    /// How long the relay may hold a fetch open waiting for new envelopes
    /// (long poll): incoming calls and messages arrive within moments.
    static let longPollSeconds = 20
}

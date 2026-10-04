import CalcCore
import Foundation

enum AppConfig {
    /// Your relay: address and certificate pins live in RelayEndpoint.swift,
    /// which is kept out of git (see ios/RelayEndpoint.example.swift).
    static let relay = RelayConfig(baseURL: RelayEndpoint.url, spkiPins: RelayEndpoint.spkiPins)

    /// Fallback polling when the relay doesn't hold requests open (or fails).
    static let pollInterval: Duration = .seconds(5)
    /// How long the relay may hold a fetch open waiting for new envelopes
    /// (long poll): incoming calls and messages arrive within moments.
    static let longPollSeconds = 20
}

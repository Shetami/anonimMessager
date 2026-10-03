import CalcCore
import Foundation
import Observation

/// One unlocked profile: its database, Signal engine, messenger service and
/// the foreground sync loop. Dropped entirely on lock.
@MainActor
@Observable
final class Session {
    let profile: UnlockedProfile
    let service: MessengerService
    @ObservationIgnored let vault: Vault
    @ObservationIgnored private let onLock: () -> Void
    @ObservationIgnored private let onWipe: () -> Void
    @ObservationIgnored private var syncTask: Task<Void, Never>?
    /// Last registration failure, shown while the mailbox isn't registered yet.
    private(set) var registrationError: String?

    /// Seconds in background before auto-lock (0 = immediately).
    var autoLockSeconds: TimeInterval {
        didSet { try? service.db.put(autoLockSeconds, collection: "meta", key: "autolock") }
    }

    init(profile: UnlockedProfile, db: SecureDatabase, vault: Vault,
         onLock: @escaping () -> Void, onWipe: @escaping () -> Void) throws {
        self.profile = profile
        self.vault = vault
        self.onLock = onLock
        self.onWipe = onWipe
        let engine = try SignalEngine(db: db)
        self.service = MessengerService(db: db, engine: engine, relay: RelayClient(config: AppConfig.relay))
        self.autoLockSeconds = (try? db.get(TimeInterval.self, collection: "meta", key: "autolock")) ?? 0
    }

    func start() {
        syncTask = Task { [weak self] in
            guard let self else { return }
            // Keep retrying: the first attempt can fail e.g. while iOS is still
            // asking for local-network permission or the relay is unreachable.
            while !Task.isCancelled, self.service.state?.registered != true {
                do {
                    try await self.service.register()
                    self.registrationError = nil
                } catch {
                    self.registrationError = Self.describe(error)
                    try? await Task.sleep(for: .seconds(3))
                }
            }
            while !Task.isCancelled {
                await self.service.sync()
                try? await Task.sleep(for: AppConfig.pollInterval)
            }
        }
    }

    static func describe(_ error: Error) -> String {
        switch error {
        case RelayError.transport(let detail):
            return "Нет связи с сервером \(AppConfig.relay.baseURL.absoluteString): \(detail)"
        case RelayError.http(let code):
            return "Сервер ответил ошибкой \(code)"
        default:
            return String(describing: error)
        }
    }

    func stop() {
        syncTask?.cancel()
        syncTask = nil
    }

    func lock() { onLock() }

    // MARK: - Codes

    /// Only the primary profile knows the sibling slot.
    var canManageDecoy: Bool { service.sibling() != nil }

    func setDecoyCode(_ code: String) throws {
        guard let sibling = service.sibling() else { return }
        try vault.setCode(code, for: sibling)
    }

    func removeDecoyCode() throws {
        guard let sibling = service.sibling() else { return }
        try vault.revokeCode(for: sibling)
    }

    func changeCode(_ code: String) throws {
        try vault.setCode(code, for: profile)
    }

    func wipeEverything() async {
        stop()
        await service.deleteAccountFromRelay()
        onWipe()
    }
}

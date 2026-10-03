import CalcCore
import Foundation
import Observation
import SwiftUI
import UIKit

/// Top-level state: the calculator disguise, vault unlock and the unlocked
/// messenger session.
@MainActor
@Observable
final class AppModel {
    enum Phase {
        case calculator
        case messenger(Session)
    }

    enum SetupStep: Equatable {
        case choose
        case confirm(String)
    }

    private(set) var phase: Phase = .calculator
    var calculator = CalculatorEngine()
    private(set) var setupStep: SetupStep?
    private(set) var setupMessage: String?
    private(set) var obscured = false

    @ObservationIgnored let vault: Vault
    @ObservationIgnored private var unlockTask: Task<Void, Never>?
    @ObservationIgnored private var pendingCode: String?
    @ObservationIgnored private var backgroundedAt: Date?

    static var storageDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("calc", isDirectory: true)
    }

    init() {
        vault = Vault(directory: Self.storageDirectory, deviceSecret: KeychainDeviceSecret())
        if !vault.isInitialized { setupStep = .choose }
        NotificationCenter.default.addObserver(
            forName: UIScreen.capturedDidChangeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.updateObscured(active: true) }
        }
    }

    // MARK: - Keypad

    func press(_ key: CalcKey) {
        guard let submitted = calculator.press(key) else { return }
        if setupStep != nil {
            handleSetup(submitted)
        } else {
            attemptUnlock(submitted)
        }
    }

    /// Every "=" is silently tried against the vault in the background, so
    /// the calculator always responds instantly and a wrong code looks exactly
    /// like a normal calculation.
    private func attemptUnlock(_ code: String) {
        guard code.count >= Vault.minimumCodeLength else { return }
        if unlockTask != nil {
            pendingCode = code // only the latest submission matters
            return
        }
        let vault = self.vault
        unlockTask = Task {
            let profile = await Task.detached(priority: .userInitiated) { try? vault.unlock(code: code) }.value
            unlockTask = nil
            if let profile {
                pendingCode = nil
                openProfile(profile)
            } else if let next = pendingCode {
                pendingCode = nil
                attemptUnlock(next)
            }
        }
    }

    // MARK: - First-run setup

    private func handleSetup(_ code: String) {
        switch setupStep {
        case .choose:
            guard code.count >= Vault.minimumCodeLength else {
                setupMessage = "Минимум \(Vault.minimumCodeLength) символа"
                return
            }
            setupMessage = nil
            setupStep = .confirm(code)
            calculator.wipe()
        case .confirm(let first):
            guard code == first else {
                setupMessage = "Коды не совпали, попробуйте ещё раз"
                setupStep = .choose
                calculator.wipe()
                return
            }
            do {
                let result = try vault.setup(code: code)
                // Create both databases now so the sibling slot's file exists
                // whether or not a decoy code is ever set.
                _ = try SecureDatabase(url: databaseURL(for: result.sibling), profile: result.sibling)
                let session = try makeSession(result.primary)
                try session.service.storeSibling(result.sibling)
                setupStep = nil
                setupMessage = nil
                enter(session)
            } catch {
                setupMessage = "Ошибка: \(error.localizedDescription)"
                setupStep = .choose
            }
        case nil:
            break
        }
    }

    // MARK: - Session lifecycle

    private func openProfile(_ profile: UnlockedProfile) {
        do {
            enter(try makeSession(profile))
        } catch {
            calculator.wipe()
        }
    }

    private func makeSession(_ profile: UnlockedProfile) throws -> Session {
        let db = try SecureDatabase(url: databaseURL(for: profile), profile: profile)
        return try Session(profile: profile, db: db, vault: vault, onLock: { [weak self] in self?.lock() },
                           onWipe: { [weak self] in self?.wipeEverything() })
    }

    private func databaseURL(for profile: UnlockedProfile) -> URL {
        Self.storageDirectory.appendingPathComponent(profile.databaseFileName)
    }

    private func enter(_ session: Session) {
        calculator.wipe() // the code must not stay in history/display
        phase = .messenger(session)
        session.start()
    }

    func lock() {
        if case .messenger(let session) = phase { session.stop() }
        phase = .calculator
        calculator.wipe()
    }

    /// Panic wipe: removes the account from the relay (best effort), then
    /// crypto-erases the vault. The app returns to a fresh calculator.
    func wipeEverything() {
        if case .messenger(let session) = phase { session.stop() }
        phase = .calculator
        vault.destroy()
        calculator = CalculatorEngine()
        setupStep = .choose
    }

    // MARK: - Privacy

    func scenePhaseChanged(_ scenePhase: ScenePhase) {
        switch scenePhase {
        case .active:
            if let at = backgroundedAt, case .messenger(let s) = phase,
               Date().timeIntervalSince(at) > s.autoLockSeconds {
                lock()
            }
            backgroundedAt = nil
            updateObscured(active: true)
        case .inactive:
            updateObscured(active: false)
        case .background:
            backgroundedAt = Date()
            updateObscured(active: false)
            if case .messenger(let s) = phase, s.autoLockSeconds <= 0 { lock() }
            if case .calculator = phase { calculator.wipe() }
        @unknown default:
            break
        }
    }

    private func updateObscured(active: Bool) {
        obscured = !active || UIScreen.main.isCaptured
    }
}

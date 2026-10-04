import CalcCore
import Foundation
import Observation
import SwiftUI
import UIKit

/// Top-level state: the planner disguise, vault unlock and the unlocked
/// messenger session.
@MainActor
@Observable
final class AppModel {
    enum Phase {
        case planner
        case messenger(Session)
    }

    enum SetupStep: Equatable {
        case choose
        case confirm(String)
    }

    private(set) var phase: Phase = .planner
    var isMessengerOpen: Bool {
        if case .messenger = phase { return true }
        return false
    }
    var planner = TodoStore(fileURL: AppModel.plannerURL)
    /// Text in the "new task" field. Lives here so it can be wiped on lock and
    /// on background: a half-typed code must not linger on screen.
    var draft = ""
    private(set) var setupStep: SetupStep?
    private(set) var setupMessage: String?
    private(set) var obscured = false

    @ObservationIgnored let vault: Vault
    @ObservationIgnored private var unlockTask: Task<Void, Never>?
    @ObservationIgnored private var unlockQueue: [(task: UUID, code: String)] = []
    @ObservationIgnored private var backgroundedAt: Date?

    static var storageDirectory: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("calc", isDirectory: true)
    }

    static var plannerURL: URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("planner", isDirectory: true)
            .appendingPathComponent("tasks.json")
    }

    init() {
        vault = Vault(directory: Self.storageDirectory, deviceSecret: KeychainDeviceSecret())
        if !vault.isInitialized { setupStep = .choose }
        TempFiles.removeAll() // decrypted copies left behind by a crash
        NotificationCenter.default.addObserver(
            forName: UIScreen.capturedDidChangeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.updateObscured(active: true) }
        }
    }

    // MARK: - New task

    func submitDraft(on day: Date) {
        let text = TodoStore.normalize(draft)
        draft = ""
        guard !text.isEmpty else { return }
        let code = TodoStore.code(from: text)
        if setupStep != nil {
            handleSetup(code)
            return
        }
        let mayBeCode = code.count >= Vault.minimumCodeLength
        guard let task = planner.add(text, on: day, held: mayBeCode) else { return }
        if mayBeCode { attemptUnlock(task: task.id, code: code) }
    }

    /// Every new task is silently tried against the vault in the background.
    /// It appears in the list instantly either way, so a wrong code looks
    /// exactly like an ordinary task; it is only written to disk once the
    /// vault has rejected it.
    private func attemptUnlock(task: UUID, code: String) {
        unlockQueue.append((task, code))
        guard unlockTask == nil else { return }
        let vault = self.vault
        unlockTask = Task {
            while !unlockQueue.isEmpty {
                let (task, code) = unlockQueue.removeFirst()
                let profile = await Task.detached(priority: .userInitiated) { try? vault.unlock(code: code) }.value
                guard let profile else {
                    planner.release(task)
                    continue
                }
                planner.discard(task)
                if case .planner = phase { openProfile(profile) }
            }
            unlockTask = nil
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
        case .confirm(let first):
            guard code == first else {
                setupMessage = "Коды не совпали, попробуйте ещё раз"
                setupStep = .choose
                return
            }
            var created = false
            do {
                let result = try vault.setup(code: code)
                created = true
                // Create both databases now so the sibling slot's file exists
                // whether or not a decoy code is ever set.
                _ = try SecureDatabase(url: databaseURL(for: result.sibling), profile: result.sibling)
                let session = try makeSession(result.primary)
                try session.service.storeSibling(result.sibling)
                setupStep = nil
                setupMessage = nil
                enter(session)
            } catch {
                // Roll back a half-finished setup: otherwise the vault file
                // exists, every retry fails with alreadyInitialized and the
                // code can't be used to unlock either.
                if created { vault.destroy() }
                setupMessage = "Ошибка: \(String(describing: error))"
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
            draft = ""
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
        draft = ""
        phase = .messenger(session)
        session.start()
    }

    func lock() {
        if case .messenger(let session) = phase { session.stop() }
        phase = .planner
        draft = ""
        TempFiles.removeAll()
    }

    /// Panic wipe: removes the account from the relay (best effort), then
    /// crypto-erases the vault. The app returns to the planner (its tasks are
    /// kept: they are the cover story) and asks for a new code.
    func wipeEverything() {
        if case .messenger(let session) = phase { session.stop() }
        phase = .planner
        vault.destroy()
        TempFiles.removeAll()
        draft = ""
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
            // Calls only run in the foreground (no CallKit, no background audio).
            if case .messenger(let s) = phase { s.calls.shutdown() }
            if case .messenger(let s) = phase, s.autoLockSeconds <= 0 { lock() }
            if case .planner = phase { draft = "" }
        @unknown default:
            break
        }
    }

    private func updateObscured(active: Bool) {
        obscured = !active || UIScreen.main.isCaptured
    }
}

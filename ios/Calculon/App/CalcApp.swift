import CalcCore
import SwiftUI
import UIKit

@main
struct CalcApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @State private var model = AppModel()
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
        }
        .onChange(of: scenePhase) { _, phase in
            model.scenePhaseChanged(phase)
        }
    }
}

final class AppDelegate: NSObject, UIApplicationDelegate {
    /// Third-party keyboards can log keystrokes; only the system keyboard is allowed.
    func application(_ application: UIApplication,
                     shouldAllowExtensionPointIdentifier id: UIApplication.ExtensionPointIdentifier) -> Bool {
        id != .keyboard
    }
}

struct RootView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        ZStack {
            switch model.phase {
            case .planner:
                PlannerView()
            case .messenger(let session):
                ScreenshotShield {
                    MessengerRootView()
                        .environment(session)
                        .environment(session.service)
                        .environment(session.calls)
                }
                .ignoresSafeArea()
            }
            // While inactive (app switcher snapshot, control center, incoming
            // call) or while the screen is recorded/mirrored, only the
            // planner is ever visible.
            if model.obscured, case .messenger = model.phase {
                PlannerView().transition(.identity)
            }
        }
        // Planner and messenger share one palette and follow the system
        // appearance, so neither stands out from the other.
        .tint(Theme.accent)
    }
}

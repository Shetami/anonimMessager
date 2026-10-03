import SwiftUI
import UIKit
import UniformTypeIdentifiers

/// Hosts content inside the render layer of a secure UITextField. iOS blanks
/// that layer in screenshots, screen recordings and AirPlay mirroring.
/// This relies on a private view hierarchy detail; if it ever stops working
/// the content is simply shown unprotected (and AppModel still covers the
/// screen while `UIScreen.isCaptured`).
struct ScreenshotShield<Content: View>: UIViewControllerRepresentable {
    @ViewBuilder var content: Content

    func makeUIViewController(context: Context) -> ShieldController<Content> {
        ShieldController(root: content)
    }

    func updateUIViewController(_ vc: ShieldController<Content>, context: Context) {
        vc.host.rootView = content
    }
}

final class ShieldController<Content: View>: UIViewController {
    let host: UIHostingController<Content>
    private let field = UITextField()

    init(root: Content) {
        host = UIHostingController(rootView: root)
        host.overrideUserInterfaceStyle = .dark
        super.init(nibName: nil, bundle: nil)
    }

    required init?(coder: NSCoder) { fatalError() }

    override func viewDidLoad() {
        super.viewDidLoad()
        field.isSecureTextEntry = true
        field.isUserInteractionEnabled = false
        let canvas = field.subviews.first { String(describing: type(of: $0)).contains("CanvasView") }

        addChild(host)
        let container: UIView
        if let canvas {
            canvas.isUserInteractionEnabled = true
            canvas.removeFromSuperview()
            container = canvas
            container.translatesAutoresizingMaskIntoConstraints = false
            view.addSubview(container)
            pin(container, to: view)
        } else {
            container = view
        }
        host.view.translatesAutoresizingMaskIntoConstraints = false
        host.view.backgroundColor = .systemBackground
        container.addSubview(host.view)
        pin(host.view, to: container)
        host.didMove(toParent: self)
    }

    private func pin(_ v: UIView, to parent: UIView) {
        NSLayoutConstraint.activate([
            v.topAnchor.constraint(equalTo: parent.topAnchor),
            v.bottomAnchor.constraint(equalTo: parent.bottomAnchor),
            v.leadingAnchor.constraint(equalTo: parent.leadingAnchor),
            v.trailingAnchor.constraint(equalTo: parent.trailingAnchor),
        ])
    }
}

enum SecurePasteboard {
    /// Local-only (no Universal Clipboard to other devices) and expires after a minute.
    static func copy(_ text: String) {
        UIPasteboard.general.setItems(
            [[UTType.utf8PlainText.identifier: text]],
            options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(60)])
    }
}

enum JailbreakCheck {
    /// Heuristic only — a determined attacker can hide a jailbreak. Used to
    /// warn the user, not as a security boundary.
    static var isSuspicious: Bool {
        #if targetEnvironment(simulator)
        return false
        #else
        let paths = ["/Applications/Cydia.app", "/Applications/Sileo.app", "/var/jb", "/bin/bash",
                     "/usr/sbin/sshd", "/etc/apt", "/private/var/lib/apt/", "/usr/bin/ssh"]
        if paths.contains(where: { FileManager.default.fileExists(atPath: $0) }) { return true }
        let probe = "/private/calc-probe-\(UUID().uuidString)"
        if (try? "x".write(toFile: probe, atomically: false, encoding: .utf8)) != nil {
            try? FileManager.default.removeItem(atPath: probe)
            return true
        }
        return false
        #endif
    }
}

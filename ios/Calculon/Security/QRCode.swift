import AVFoundation
import CoreImage.CIFilterBuiltins
import SwiftUI
import UIKit

struct QRCodeImage: View {
    let text: String

    var body: some View {
        if let image = Self.render(text) {
            Image(uiImage: image).interpolation(.none).resizable().scaledToFit()
        }
    }

    static func render(_ text: String) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(text.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 10, y: 10)),
              let cg = CIContext().createCGImage(output, from: output.extent)
        else { return nil }
        return UIImage(cgImage: cg)
    }
}

struct QRScannerView: UIViewControllerRepresentable {
    let onCode: (String) -> Void
    let onCancel: () -> Void

    func makeUIViewController(context: Context) -> ScannerController {
        let vc = ScannerController()
        vc.onCode = onCode
        vc.onCancel = onCancel
        return vc
    }

    func updateUIViewController(_ vc: ScannerController, context: Context) {}
}

final class ScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onCode: ((String) -> Void)?
    var onCancel: (() -> Void)?
    private let session = AVCaptureSession()
    private var delivered = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black

        let cancel = UIButton(type: .system)
        cancel.setTitle("Отмена", for: .normal)
        cancel.titleLabel?.font = .preferredFont(forTextStyle: .headline)
        cancel.tintColor = .white
        cancel.addAction(UIAction { [weak self] _ in self?.onCancel?() }, for: .touchUpInside)
        cancel.translatesAutoresizingMaskIntoConstraints = false

        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input)
        else {
            view.addSubview(cancel)
            layout(cancel)
            return
        }
        session.addInput(input)
        let output = AVCaptureMetadataOutput()
        if session.canAddOutput(output) {
            session.addOutput(output)
            output.setMetadataObjectsDelegate(self, queue: .main)
            output.metadataObjectTypes = [.qr]
        }
        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.layer.bounds
        view.layer.addSublayer(preview)
        view.addSubview(cancel)
        layout(cancel)
        DispatchQueue.global(qos: .userInitiated).async { [session] in session.startRunning() }
    }

    private func layout(_ cancel: UIView) {
        NSLayoutConstraint.activate([
            cancel.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -24),
            cancel.centerXAnchor.constraint(equalTo: view.centerXAnchor),
        ])
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if session.isRunning { session.stopRunning() }
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput objects: [AVMetadataObject],
                        from connection: AVCaptureConnection) {
        guard !delivered,
              let code = (objects.first as? AVMetadataMachineReadableCodeObject)?.stringValue
        else { return }
        delivered = true
        session.stopRunning()
        onCode?(code)
    }
}

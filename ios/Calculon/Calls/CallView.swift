import AVFoundation
import CalcCore
import SwiftUI
import WebRTC

/// Full-screen call UI. Shown as an overlay inside the messenger (not as a
/// presented sheet) so it stays within the screenshot shield.
struct CallScreen: View {
    let call: ActiveCall
    @Environment(CallService.self) private var calls
    @Environment(MessengerService.self) private var service

    private var name: String { service.contact(call.contactID)?.name ?? "" }
    private var showsRemoteVideo: Bool { call.remoteTrack != nil && call.remoteVideo && call.phase == .connected }

    var body: some View {
        ZStack {
            Color.black.ignoresSafeArea()
            if showsRemoteVideo, let track = call.remoteTrack {
                RemoteVideoView(track: track).ignoresSafeArea()
            }
            VStack {
                header
                Spacer()
                controls
            }
            .padding(.bottom, 24)
            if call.cameraOn, let session = call.localSession {
                LocalPreview(session: session)
                    .frame(width: 110, height: 160)
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topTrailing)
                    .padding(.top, showsRemoteVideo ? 8 : 120)
                    .padding(.trailing, 12)
            }
        }
        .foregroundStyle(.white)
    }

    private var header: some View {
        VStack(spacing: 8) {
            if !showsRemoteVideo {
                Circle()
                    .fill(Color(white: 0.25))
                    .frame(width: 96, height: 96)
                    .overlay(Text(name.prefix(1).uppercased()).font(.largeTitle))
                    .padding(.top, 48)
            }
            Text(name).font(.title2.bold())
            status.font(.subheadline).foregroundStyle(.white.opacity(0.8))
        }
        .shadow(radius: showsRemoteVideo ? 4 : 0)
        .padding(.top, 12)
    }

    @ViewBuilder private var status: some View {
        switch call.phase {
        case .pending, .dialing: Text("Соединение…")
        case .ringingOut: Text("Вызов…")
        case .incoming: Text(call.startedVideo ? "Входящий видеозвонок" : "Входящий звонок")
        case .connecting: Text("Соединение…")
        case .reconnecting: Text("Восстановление связи…")
        case .ended(let message): Text(message)
        case .connected:
            if let at = call.connectedAt {
                TimelineView(.periodic(from: at, by: 1)) { ctx in
                    Text(Self.duration(ctx.date.timeIntervalSince(at))).monospacedDigit()
                }
            }
        }
    }

    @ViewBuilder private var controls: some View {
        switch call.phase {
        case .incoming:
            HStack(spacing: 72) {
                RoundButton(systemImage: "phone.down.fill", tint: .red, label: "Отклонить") { calls.hangup() }
                RoundButton(systemImage: call.startedVideo ? "video.fill" : "phone.fill", tint: .green,
                            label: "Ответить") { Task { await calls.accept() } }
            }
        case .ended:
            EmptyView()
        default:
            VStack(spacing: 28) {
                HStack(spacing: 24) {
                    ToggleButton(systemImage: call.muted ? "mic.slash.fill" : "mic.fill", on: call.muted,
                                 label: "Микрофон") { calls.toggleMute() }
                    ToggleButton(systemImage: "speaker.wave.2.fill", on: call.speaker,
                                 label: "Динамик") { calls.toggleSpeaker() }
                    ToggleButton(systemImage: call.cameraOn ? "video.fill" : "video.slash.fill", on: call.cameraOn,
                                 label: "Камера") { Task { await calls.toggleCamera() } }
                    if call.cameraOn {
                        ToggleButton(systemImage: "arrow.triangle.2.circlepath.camera", on: false,
                                     label: "Сменить камеру") { calls.switchCamera() }
                    }
                }
                RoundButton(systemImage: "phone.down.fill", tint: .red, label: "Завершить") { calls.hangup() }
            }
        }
    }

    static func duration(_ t: TimeInterval) -> String {
        let s = max(0, Int(t))
        return s >= 3600
            ? String(format: "%d:%02d:%02d", s / 3600, s / 60 % 60, s % 60)
            : String(format: "%d:%02d", s / 60, s % 60)
    }
}

private struct RoundButton: View {
    let systemImage: String
    let tint: Color
    let label: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: systemImage)
                .font(.system(size: 28))
                .frame(width: 72, height: 72)
                .background(tint, in: Circle())
        }
        .accessibilityLabel(label)
    }
}

private struct ToggleButton: View {
    let systemImage: String
    let on: Bool
    let label: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: systemImage)
                .font(.system(size: 22))
                .frame(width: 56, height: 56)
                .background(on ? Color.white : Color(white: 0.25), in: Circle())
                .foregroundStyle(on ? .black : .white)
        }
        .accessibilityLabel(label)
        .accessibilityAddTraits(on ? .isSelected : [])
    }
}

/// The peer's video, rendered with WebRTC's Metal view.
struct RemoteVideoView: UIViewRepresentable {
    let track: RTCVideoTrack

    func makeUIView(context: Context) -> RTCMTLVideoView {
        let view = RTCMTLVideoView(frame: .zero)
        view.videoContentMode = .scaleAspectFill
        track.add(view)
        context.coordinator.track = track
        return view
    }

    func updateUIView(_ view: RTCMTLVideoView, context: Context) {
        guard context.coordinator.track !== track else { return }
        context.coordinator.track?.remove(view)
        track.add(view)
        context.coordinator.track = track
    }

    static func dismantleUIView(_ view: RTCMTLVideoView, coordinator: Coordinator) {
        coordinator.track?.remove(view)
    }

    func makeCoordinator() -> Coordinator { Coordinator() }

    final class Coordinator {
        var track: RTCVideoTrack?
    }
}

/// Our own camera, straight from RingRTC's capture session.
struct LocalPreview: UIViewRepresentable {
    let session: AVCaptureSession

    func makeUIView(context: Context) -> PreviewView {
        let view = PreviewView()
        view.previewLayer.videoGravity = .resizeAspectFill
        view.previewLayer.session = session
        return view
    }

    func updateUIView(_ view: PreviewView, context: Context) {
        if view.previewLayer.session !== session { view.previewLayer.session = session }
    }

    final class PreviewView: UIView {
        override class var layerClass: AnyClass { AVCaptureVideoPreviewLayer.self }
        var previewLayer: AVCaptureVideoPreviewLayer { layer as! AVCaptureVideoPreviewLayer }
    }
}

/// A finished call in the chat timeline.
struct CallLogRow: View {
    let message: ChatMessage
    let info: CallInfo

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: icon).foregroundStyle(missed ? .red : .secondary)
            Text(info.label(outgoing: message.outgoing))
            if let d = info.duration, info.outcome == .answered {
                Text("· " + CallScreen.duration(d)).monospacedDigit()
            }
            Text("· ") + Text(message.sentAt, style: .time)
        }
        .font(.caption)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(Color(white: 0.12), in: Capsule())
        .frame(maxWidth: .infinity)
    }

    private var missed: Bool { info.outcome == .missed }

    private var icon: String {
        if info.video { return "video.fill" }
        if missed { return "phone.arrow.down.left" }
        return message.outgoing ? "phone.arrow.up.right" : "phone.arrow.down.left"
    }
}

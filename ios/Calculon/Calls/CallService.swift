import AudioToolbox
import AVFoundation
import CalcCore
import CryptoKit
import Foundation
import Observation
@preconcurrency import SignalRingRTC
import UIKit
@preconcurrency import WebRTC
#if DEBUG
import os
#endif

/// Call diagnostics for development. Compiled out of release builds, which
/// log nothing about calls.
enum CallDebug {
    #if DEBUG
    private static let logger = os.Logger(subsystem: "calc", category: "calls")
    private static let ringrtc: Void = RingRTCConsole().setUpRingRTCLogging(maxLogLevel: .info)

    private struct RingRTCConsole: RingRTCLogger {
        func log(level: RingRTCLogLevel, file: String, function: String, line: UInt32, message: String) {
            CallDebug.logger.debug("ringrtc \(file, privacy: .public):\(line) \(message, privacy: .public)")
        }
        func flush() {}
    }
    #endif

    static func start() {
        #if DEBUG
        _ = ringrtc
        #endif
    }

    static func log(_ message: @autoclosure () -> String) {
        #if DEBUG
        let m = message()
        logger.debug("\(m, privacy: .public)")
        #endif
    }
}

/// One 1:1 call. RingRTC keeps a reference to it for the call's lifetime.
@MainActor
@Observable
final class ActiveCall: CallManagerCallReference {
    enum Phase: Equatable {
        /// Incoming, still exchanging ICE: not shown until it actually rings.
        case pending
        case dialing
        case ringingOut
        case incoming
        case connecting
        case connected
        case reconnecting
        case ended(String)
    }

    let contactID: String
    let outgoing: Bool
    let startedVideo: Bool
    let startedAt = Date()
    @ObservationIgnored let capture = VideoCaptureController()
    var callID: UInt64?
    var phase: Phase
    var connectedAt: Date?
    var muted = false
    var speaker: Bool
    var cameraOn: Bool
    var frontCamera = true
    var remoteVideo = false
    var remoteTrack: RTCVideoTrack?
    var localSession: AVCaptureSession?
    @ObservationIgnored var finished = false

    init(contactID: String, outgoing: Bool, video: Bool) {
        self.contactID = contactID
        self.outgoing = outgoing
        startedVideo = video
        cameraOn = video
        speaker = video
        phase = outgoing ? .dialing : .pending
    }

    var isVisible: Bool { phase != .pending }
}

/// 1:1 voice and video calls via RingRTC, the library Signal's own calls use.
///
/// - Signaling (offer/answer/ICE/hangup/busy) travels as ordinary end-to-end
///   encrypted payloads through the blind relay, inside sealed envelopes, so
///   the relay can't tell a call from a text.
/// - Media is SRTP with keys from RingRTC's own key exchange, bound to both
///   identity keys (which our contact IDs commit to).
/// - Media is always relayed through TURN (`hideIp`), so peers never learn
///   each other's IP address.
/// - Only accepted contacts can ring (filtered in MessengerService).
///
/// Written against SignalRingRTC v2.72.0 (see ios/.ringrtc-version);
/// re-check it when bumping the pin.
@MainActor
@Observable
final class CallService {
    private(set) var current: ActiveCall?

    @ObservationIgnored private let service: MessengerService
    @ObservationIgnored private var manager: CallManager<ActiveCall, CallService>!
    @ObservationIgnored private var sendChain: Task<Void, Never>?
    @ObservationIgnored private var ringTask: Task<Void, Never>?

    /// One device per profile; RingRTC still wants device IDs.
    static let deviceID: UInt32 = 1

    init(service: MessengerService) {
        self.service = service
        // Don't open the microphone until the user actually accepts or the
        // callee answers (by default WebRTC records as soon as a call is set up).
        CallDebug.start()
        RTCAudioSession.sharedInstance().useManualAudio = true
        RTCAudioSession.sharedInstance().isAudioEnabled = false
        manager = CallManager(httpClient: HTTPClient())
        manager.delegate = self
        service.onCallSignal = { [weak self] contactID, signal, age in
            self?.receive(signal, from: contactID, age: age)
        }
    }

    // MARK: - User actions

    func call(_ contactID: String, video: Bool) async {
        guard current == nil, service.contact(contactID) != nil else { return }
        let call = ActiveCall(contactID: contactID, outgoing: true, video: video)
        current = call
        guard await Self.microphoneAllowed() else {
            close(call, message: "Нет доступа к микрофону")
            return
        }
        if video, !(await Self.cameraAllowed()) {
            call.cameraOn = false
        }
        guard current === call, !call.finished else { return }
        do {
            try manager.placeCall(call: call, remoteUuid: Self.uuid(for: contactID),
                                  callMediaType: video ? .videoCall : .audioCall, localDevice: Self.deviceID)
        } catch {
            close(call, message: "Не удалось начать звонок")
        }
    }

    func accept() async {
        guard let call = current, call.phase == .incoming, let id = call.callID else { return }
        stopRinging()
        guard await Self.microphoneAllowed() else {
            hangup()
            return
        }
        if call.cameraOn, !(await Self.cameraAllowed()) {
            call.cameraOn = false
            call.speaker = false
        }
        guard current === call, call.phase == .incoming else { return }
        call.phase = .connecting
        configureAudio(for: call)
        do {
            try manager.accept(callId: id)
            RTCAudioSession.sharedInstance().isAudioEnabled = true
        } catch {
            hangup()
        }
    }

    /// Declines a ringing call, cancels an outgoing one or ends a connected one.
    func hangup() {
        guard let call = current, !call.finished else { return }
        stopRinging()
        do {
            try manager.hangup()
        } catch {
            close(call, message: "Звонок завершён")
        }
    }

    func toggleMute() {
        guard let call = current else { return }
        call.muted.toggle()
        manager.setLocalAudioEnabled(enabled: !call.muted)
    }

    func toggleSpeaker() {
        guard let call = current else { return }
        call.speaker.toggle()
        configureAudio(for: call)
    }

    func toggleCamera() async {
        guard let call = current else { return }
        if !call.cameraOn, !(await Self.cameraAllowed()) { return }
        call.cameraOn.toggle()
        // Like any video call app: video goes to the loudspeaker.
        if call.cameraOn { call.speaker = true }
        configureAudio(for: call)
        manager.setLocalVideoEnabled(call: call, enabled: call.cameraOn)
    }

    func switchCamera() {
        guard let call = current, call.cameraOn else { return }
        call.frontCamera.toggle()
        let capture = call.capture, front = call.frontCamera
        DispatchQueue.global(qos: .userInitiated).async { capture.switchCamera(isUsingFrontCamera: front) }
    }

    /// Lock or background: a call never outlives the unlocked session.
    func shutdown() {
        let active = current.map { !$0.finished } ?? false
        hangup()
        stopRinging()
        teardownAudio()
        guard active else { return }
        // RingRTC asks us to send the hangup asynchronously; stay alive long
        // enough to deliver it so the peer isn't left waiting for a timeout.
        Task { [self] in
            try? await Task.sleep(for: .seconds(3))
            _ = self
        }
    }

    // MARK: - Signaling in

    private func receive(_ s: CallSignal, from contactID: String, age: TimeInterval) {
        guard let callID = s.callIDValue, let contact = service.contact(contactID),
              let local = try? service.localIdentityKey()
        else { return }
        let uuid = Self.uuid(for: contactID)
        let device = Self.deviceID
        CallDebug.log("recv \(s.kind) call=\(callID) age=\(Int(age))s candidates=\(s.candidates?.count ?? 0)")
        do {
            switch s.kind {
            case .offer:
                guard let opaque = s.opaque else { return }
                let video = s.video == true
                try manager.receivedOffer(
                    call: ActiveCall(contactID: contactID, outgoing: false, video: video), remoteUuid: uuid,
                    sourceDevice: device, callId: callID, opaque: opaque, messageAgeSec: UInt64(min(age, 86400)),
                    callMediaType: video ? .videoCall : .audioCall, localDevice: device,
                    senderIdentityKey: Self.keyBytes(contact.identityKey), receiverIdentityKey: Self.keyBytes(local))
            case .answer:
                guard let opaque = s.opaque else { return }
                try manager.receivedAnswer(
                    remoteUuid: uuid, sourceDevice: device, callId: callID, opaque: opaque,
                    senderIdentityKey: Self.keyBytes(contact.identityKey), receiverIdentityKey: Self.keyBytes(local))
            case .ice:
                try manager.receivedIceCandidates(remoteUuid: uuid, sourceDevice: device, callId: callID,
                                                  candidates: s.candidates ?? [])
            case .hangup:
                try manager.receivedHangup(remoteUuid: uuid, sourceDevice: device, callId: callID,
                                           hangupType: HangupType(rawValue: s.hangupType ?? 0) ?? .normal,
                                           deviceId: s.deviceID ?? device)
            case .busy:
                try manager.receivedBusy(remoteUuid: uuid, sourceDevice: device, callId: callID)
            }
        } catch {
            // Stale or malformed signaling for a call RingRTC doesn't know: ignore.
            CallDebug.log("recv \(s.kind) rejected by RingRTC: \(error)")
        }
    }

    // MARK: - Signaling out

    /// Signaling must reach the peer in order (offer before its ICE
    /// candidates), so sends are chained. Each still runs if the session locks
    /// meanwhile, so a final hangup gets out.
    private func send(_ signal: CallSignal, for call: ActiveCall) {
        let previous = sendChain
        let service = self.service
        let manager = self.manager!
        let contactID = call.contactID
        let callID = signal.callIDValue ?? 0
        sendChain = Task { @MainActor in
            await previous?.value
            do {
                try await service.sendCallSignal(signal, to: contactID)
                CallDebug.log("sent \(signal.kind) call=\(callID)")
                try? manager.signalingMessageDidSend(callId: callID)
            } catch {
                CallDebug.log("send \(signal.kind) failed: \(error)")
                manager.signalingMessageDidFail(callId: callID)
            }
        }
    }

    // MARK: - Lifecycle

    private func startMedia(_ call: ActiveCall) {
        guard !call.finished else { return }
        stopRinging()
        call.phase = .connected
        if call.connectedAt == nil { call.connectedAt = Date() }
        configureAudio(for: call)
        RTCAudioSession.sharedInstance().isAudioEnabled = true
        manager.setLocalAudioEnabled(enabled: !call.muted)
        manager.setLocalVideoEnabled(call: call, enabled: call.cameraOn)
        UIApplication.shared.isIdleTimerDisabled = true
    }

    /// Records the call in the chat and dismisses the call screen.
    private func finish(_ call: ActiveCall, outcome: CallInfo.Outcome, message: String) {
        guard !call.finished else { return }
        let duration = call.connectedAt.map { Date().timeIntervalSince($0) }
        service.recordCall(with: call.contactID, outgoing: call.outgoing,
                           info: CallInfo(video: call.startedVideo, outcome: outcome, duration: duration),
                           at: call.startedAt)
        close(call, message: message)
    }

    /// Ends the call locally without a call-log entry.
    private func close(_ call: ActiveCall, message: String) {
        guard !call.finished else { return }
        call.finished = true
        guard current === call else { return }
        stopRinging()
        teardownAudio()
        call.remoteTrack = nil
        call.localSession = nil
        call.phase = .ended(message)
        Task {
            try? await Task.sleep(for: .seconds(1.5))
            if current === call { current = nil }
        }
    }

    private static func outcome(for call: ActiveCall, reason: CallEndReason) -> (CallInfo.Outcome, String) {
        if call.connectedAt != nil { return (.answered, "Звонок завершён") }
        if call.outgoing {
            switch reason {
            case .remoteBusy, .remoteHangupBusy: return (.busy, "Абонент занят")
            case .remoteHangup, .remoteHangupDeclined: return (.declined, "Звонок отклонён")
            case .localHangup: return (.unanswered, "Звонок отменён")
            case .timeout: return (.unanswered, "Нет ответа")
            case .remoteGlare, .remoteReCall: return (.failed, "Собеседник звонит вам")
            default: return (.failed, "Не удалось соединиться")
            }
        }
        switch reason {
        case .localHangup: return (.declined, "Звонок отклонён")
        default: return (.missed, "Пропущенный звонок")
        }
    }

    // MARK: - Audio

    private func configureAudio(for call: ActiveCall) {
        let mode: AVAudioSession.Mode = call.cameraOn ? .videoChat : .voiceChat
        // WebRTC (re)applies this whenever it (re)starts the audio unit.
        let config = RTCAudioSessionConfiguration.webRTC()
        config.category = AVAudioSession.Category.playAndRecord.rawValue
        config.mode = mode.rawValue
        config.categoryOptions = [.allowBluetoothHFP]
        RTCAudioSessionConfiguration.setWebRTC(config)

        let session = RTCAudioSession.sharedInstance()
        session.lockForConfiguration()
        try? session.setCategory(.playAndRecord, mode: mode, options: [.allowBluetoothHFP])
        try? session.overrideOutputAudioPort(call.speaker ? .speaker : .none)
        session.unlockForConfiguration()
        // Screen off against the ear for voice calls on the earpiece.
        UIDevice.current.isProximityMonitoringEnabled = !call.speaker && !call.cameraOn
    }

    private func teardownAudio() {
        RTCAudioSession.sharedInstance().isAudioEnabled = false
        // Blocking call: keep it off the main thread.
        DispatchQueue.global(qos: .userInitiated).async {
            try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
        }
        UIDevice.current.isProximityMonitoringEnabled = false
        UIApplication.shared.isIdleTimerDisabled = false
    }

    /// Vibration only: the app is open whenever it can ring at all.
    private func startRinging() {
        ringTask?.cancel()
        ringTask = Task {
            while !Task.isCancelled {
                AudioServicesPlaySystemSound(kSystemSoundID_Vibrate)
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }

    private func stopRinging() {
        ringTask?.cancel()
        ringTask = nil
    }

    // MARK: - Helpers

    private static func microphoneAllowed() async -> Bool {
        await AVAudioApplication.requestRecordPermission()
    }

    private static func cameraAllowed() async -> Bool {
        await AVCaptureDevice.requestAccess(for: .video)
    }

    /// RingRTC addresses peers by UUID; derive a stable one from the contact ID.
    /// It never leaves the device.
    static func uuid(for contactID: String) -> UUID {
        let h = Array(SHA256.hash(data: Data("calc.call-peer.v1:\(contactID)".utf8)))
        return UUID(uuid: (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
                           h[8], h[9], h[10], h[11], h[12], h[13], h[14], h[15]))
    }

    /// Raw 32-byte Curve25519 key without libsignal's type prefix, as Signal
    /// passes it. RingRTC mixes both identity keys into the SRTP key
    /// derivation, binding the media to the verified identities.
    static func keyBytes(_ serialized: Data) -> Data {
        serialized.count == 33 ? Data(serialized.dropFirst()) : serialized
    }
}

// MARK: - RingRTC delegate

extension CallService: CallManagerDelegate {
    typealias CallManagerDelegateCallType = ActiveCall

    func callManager(_ callManager: CallManager<ActiveCall, CallService>, shouldStartCall call: ActiveCall,
                     callId: UInt64, isOutgoing: Bool, callMediaType: CallMediaType) {
        call.callID = callId
        CallDebug.log("shouldStartCall call=\(callId) outgoing=\(isOutgoing)")
        if !isOutgoing {
            guard current == nil else {
                callManager.drop(callId: callId)
                return
            }
            current = call
        }
        let service = self.service
        Task {
            do {
                let turn = try await service.turnCredentials()
                guard current === call, !call.finished else { return }
                let servers = [RTCIceServer(urlStrings: turn.urls, username: turn.username, credential: turn.password)]
                CallDebug.log("proceed call=\(callId) turn=\(turn.urls)")
                try callManager.proceed(callId: callId, iceServers: servers, hideIp: true,
                                        videoCaptureController: call.capture, dataMode: .normal,
                                        audioLevelsIntervalMillis: nil)
            } catch {
                CallDebug.log("proceed failed: \(error)")
                callManager.drop(callId: callId)
                if case RelayError.notFound = error {
                    close(call, message: "Сервер не поддерживает звонки")
                } else {
                    finish(call, outcome: call.outgoing ? .failed : .missed, message: "Нет связи с сервером")
                }
            }
        }
    }

    func callManager(_ callManager: CallManager<ActiveCall, CallService>, onEvent call: ActiveCall,
                     event: CallManagerEvent) {
        CallDebug.log("event \(event)")
        switch event {
        case .ringingLocal:
            guard current === call, !call.finished else { return }
            call.phase = .incoming
            startRinging()
        case .ringingRemote:
            if call.phase == .dialing { call.phase = .ringingOut }
        case .connectedLocal, .connectedRemote:
            startMedia(call)
        case .remoteVideoEnable:
            call.remoteVideo = true
        case .remoteVideoDisable:
            call.remoteVideo = false
        case .reconnecting:
            if call.phase == .connected { call.phase = .reconnecting }
        case .reconnected:
            if call.phase == .reconnecting { call.phase = .connected }
        case .receivedOfferExpired, .receivedOfferWhileActive, .receivedOfferWithGlare:
            // Never rang here: it's a missed call (RingRTC answers busy itself).
            if current !== call { finish(call, outcome: .missed, message: "") }
        case .glareHandlingFailure:
            finish(call, outcome: .failed, message: "Не удалось соединиться")
        case .remoteAudioEnable, .remoteAudioDisable, .remoteSharingScreenEnable, .remoteSharingScreenDisable:
            break
        @unknown default:
            break
        }
    }

    func callManager(_ callManager: CallManager<ActiveCall, CallService>, onCallEnded call: ActiveCall,
                     callId: UInt64, reason: CallEndReason, summary: CallSummary) {
        CallDebug.log("ended call=\(callId) reason=\(reason)")
        let (outcome, message) = Self.outcome(for: call, reason: reason)
        finish(call, outcome: outcome, message: message)
    }

    func callManager(_ callManager: CallManager<ActiveCall, CallService>, shouldSendOffer callId: UInt64,
                     call: ActiveCall, destinationDeviceId: UInt32?, opaque: Data, callMediaType: CallMediaType) {
        send(CallSignal(kind: .offer, callID: callId, opaque: opaque, video: callMediaType == .videoCall), for: call)
    }

    func callManager(_ callManager: CallManager<ActiveCall, CallService>, shouldSendAnswer callId: UInt64,
                     call: ActiveCall, destinationDeviceId: UInt32?, opaque: Data) {
        send(CallSignal(kind: .answer, callID: callId, opaque: opaque), for: call)
    }

    func callManager(_ callManager: CallManager<ActiveCall, CallService>, shouldSendIceCandidates callId: UInt64,
                     call: ActiveCall, destinationDeviceId: UInt32?, candidates: [Data]) {
        send(CallSignal(kind: .ice, callID: callId, candidates: candidates), for: call)
    }

    func callManager(_ callManager: CallManager<ActiveCall, CallService>, shouldSendHangup callId: UInt64,
                     call: ActiveCall, destinationDeviceId: UInt32?, hangupType: HangupType, deviceId: UInt32) {
        send(CallSignal(kind: .hangup, callID: callId, hangupType: hangupType.rawValue, deviceID: deviceId), for: call)
    }

    func callManager(_ callManager: CallManager<ActiveCall, CallService>, shouldSendBusy callId: UInt64,
                     call: ActiveCall, destinationDeviceId: UInt32?) {
        send(CallSignal(kind: .busy, callID: callId), for: call)
    }

    func callManager(_ callManager: CallManager<ActiveCall, CallService>, onUpdateLocalVideoSession call: ActiveCall,
                     session: AVCaptureSession?) {
        call.localSession = session
    }

    func callManager(_ callManager: CallManager<ActiveCall, CallService>, onAddRemoteVideoTrack call: ActiveCall,
                     track: RTCVideoTrack) {
        call.remoteTrack = track
    }

    // Unused: network route, audio levels, bandwidth, group calls.

    func callManager(_ callManager: CallManager<ActiveCall, CallService>, onNetworkRouteChangedFor call: ActiveCall,
                     networkRoute: NetworkRoute) {}

    nonisolated func callManager(_ callManager: CallManager<ActiveCall, CallService>, onAudioLevelsFor call: ActiveCall,
                                 capturedLevel: UInt16, receivedLevel: UInt16) {}

    func callManager(_ callManager: CallManager<ActiveCall, CallService>, onLowBandwidthForVideoFor call: ActiveCall,
                     recovered: Bool) {}

    func callManager(_ callManager: CallManager<ActiveCall, CallService>, shouldSendCallMessage recipientUuid: UUID,
                     message: Data, urgency: CallMessageUrgency) {}

    func callManager(_ callManager: CallManager<ActiveCall, CallService>, shouldSendCallMessageToGroup groupId: Data,
                     message: Data, urgency: CallMessageUrgency, overrideRecipients: [UUID]) {}

    func callManager(_ callManager: CallManager<ActiveCall, CallService>, shouldSendCallMessageToAdhocGroup message: Data,
                     urgency: CallMessageUrgency, expiration: Date, recipientsToEndorsements: [UUID: Data]) {}

    func callManager(_ callManager: CallManager<ActiveCall, CallService>, didUpdateRingForGroup groupId: Data,
                     ringId: Int64, sender: UUID, update: RingUpdate) {}
}

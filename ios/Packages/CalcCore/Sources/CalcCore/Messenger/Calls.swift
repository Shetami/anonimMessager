import Foundation

/// RingRTC signaling for one call. Travels end-to-end inside a Signal message
/// like any other payload, so the relay can't tell a call from a text.
public struct CallSignal: Codable, Equatable, Sendable {
    public enum Kind: String, Codable, Sendable { case offer, answer, ice, hangup, busy }

    public var kind: Kind
    /// RingRTC call ID, as a string: JSON numbers lose precision above 2^53.
    public var callID: String
    /// RingRTC's opaque offer/answer (its own key exchange and codec setup).
    public var opaque: Data?
    /// Offer only: the caller starts with video.
    public var video: Bool?
    public var candidates: [Data]?
    public var hangupType: Int32?
    public var deviceID: UInt32?

    public init(kind: Kind, callID: UInt64, opaque: Data? = nil, video: Bool? = nil, candidates: [Data]? = nil,
                hangupType: Int32? = nil, deviceID: UInt32? = nil) {
        self.kind = kind
        self.callID = String(callID)
        self.opaque = opaque
        self.video = video
        self.candidates = candidates
        self.hangupType = hangupType
        self.deviceID = deviceID
    }

    public var callIDValue: UInt64? { UInt64(callID) }
}

/// A finished call, stored in the chat like a message.
public struct CallInfo: Codable, Hashable, Sendable {
    public enum Outcome: String, Codable, Sendable {
        case answered
        /// Incoming call that rang out or that the caller cancelled.
        case missed
        /// Rejected by the callee (whichever side that was).
        case declined
        /// Outgoing call nobody picked up.
        case unanswered
        case busy
        case failed
    }

    public var video: Bool
    public var outcome: Outcome
    /// Seconds connected, for answered calls.
    public var duration: TimeInterval?

    public init(video: Bool, outcome: Outcome, duration: TimeInterval? = nil) {
        self.video = video
        self.outcome = outcome
        self.duration = duration
    }

    public func label(outgoing: Bool) -> String {
        let noun = video ? "видеозвонок" : "звонок"
        switch outcome {
        case .answered: return outgoing ? "Исходящий \(noun)" : "Входящий \(noun)"
        case .missed: return "Пропущенный \(noun)"
        case .declined: return outgoing ? "Звонок отклонён" : "Отклонённый \(noun)"
        case .unanswered: return "Нет ответа"
        case .busy: return "Абонент занят"
        case .failed: return "Звонок не удался"
        }
    }
}

/// Short-lived credentials for the relay's TURN server (coturn REST format).
public struct TurnCredentials: Codable, Equatable, Sendable {
    public var username: String
    public var password: String
    public var urls: [String]
    /// Lifetime in seconds from issue.
    public var ttl: Int

    public init(username: String, password: String, urls: [String], ttl: Int) {
        self.username = username
        self.password = password
        self.urls = urls
        self.ttl = ttl
    }
}

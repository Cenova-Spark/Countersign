// One request, in front of a person, with its clock running.
//
// Moved out of the Mac app's `AppSession` so the iPhone can bind to the same
// state. Everything here is derived from the request or from what the person
// has done; nothing in it knows how the request arrived or where the answer
// goes. That is `ApprovalActions`.
//
// It is not in `CountersignKit` because the kit is deliberately UI-free — the
// crypto and the gesture rules, nothing that a screen owns. `phase`,
// `acknowledged` and `secondsLeft` are what a view binds to.

import Combine
import CountersignKit
import Foundation

public final class PendingApproval: ObservableObject, Identifiable {
    public enum Phase: Equatable {
        /// On screen; the hold machine is running.
        case reading
        /// The hold committed; the enclave is signing (the biometric prompt
        /// is up).
        case signing
        case signed(DeviceSignature)
        case declined
        case expired
        case withdrawn
        /// The bytes do not match the digest. Nothing here can be approved.
        case refused
        case failed(String)
    }

    public let id: Int
    public let params: PresentParams
    public let receivedAt: Date
    public let hold: HoldMachine
    /// Whether `request_json` really digests to `request_digest`.
    public let digestVerified: Bool
    @Published public var acknowledged: Bool
    @Published public var phase: Phase

    public init(id: Int, params: PresentParams) {
        self.id = id
        self.params = params
        self.receivedAt = Date()
        self.hold = HoldMachine(armDelayMs: params.arm_delay_ms, holdMs: params.hold_ms)
        self.digestVerified = params.presentation.verifiedDigest()
        // The web relay asks for an acknowledgement on every remote request;
        // here the daemon says whether the requester changed, and the app
        // follows it (wire spec §6.3.2).
        self.acknowledged = !params.presentation.requester_changed
        self.phase = digestVerified ? .reading : .refused
    }

    public var presentation: Presentation { params.presentation }
    public var expiresAt: Date {
        receivedAt.addingTimeInterval(Double(params.presentation.ttl_ms) / 1000)
    }
    public var secondsLeft: Int { max(0, Int(expiresAt.timeIntervalSinceNow.rounded(.up))) }

    /// Whether the dial may be held: read, acknowledged, and the bytes check.
    public var canHold: Bool {
        phase == .reading && acknowledged && digestVerified
    }
}

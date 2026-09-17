// How the screen answers, without knowing who is listening.
//
// The Mac app's `AppSession` talks to a local daemon over a unix socket. The
// iPhone app will post to a relay over HTTPS. Neither of those belongs in a
// view, and the two have nothing in common except the six things a person can
// do to a request in front of them — so that is the whole of this protocol.
//
// It is six verbs and not one `answer(Decision)` on purpose. `rendered` is not
// an answer at all, `acknowledge` is explicitly not an approval (wire spec
// §6.3.2), and `expire` is something the clock does rather than the person.
// Collapsing them would lose the distinction the audit trail keeps.

import Foundation

@MainActor
public protocol ApprovalActions: AnyObject {
    /// What this device calls itself, for the two lines that name it —
    /// "this Mac's enrolled key", "this iPhone's approvals".
    ///
    /// A noun rather than a flag, because the sentences read better built than
    /// branched, and because the third device class will want its own word.
    var deviceNoun: String { get }

    /// The payload is on screen. The arm delay is measured from here.
    ///
    /// Called from the frame *after* paint, never from the frame that lays it
    /// out: §6.2.3 measures from the last byte written to the screen, and a
    /// timer started during layout would arm while the statement was still
    /// being drawn.
    func rendered(now: Double)

    /// The person has seen that something else is asking.
    ///
    /// Not an approval, signs nothing, and authorizes nothing. It only clears
    /// the way for a hold.
    func acknowledge()

    /// The person said no.
    func decline()

    /// The request's lifetime ran out with nobody answering. A different fact
    /// from a refusal, and the trail keeps them apart.
    func expire()

    /// The hold committed. `dwellMs` is how long it was held.
    ///
    /// Async because this is where the biometric prompt goes up and the
    /// enclave signs, and neither is instant.
    func commit(dwellMs: Double) async

    /// Close an answered request.
    func dismiss()
}

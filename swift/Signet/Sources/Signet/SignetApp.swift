// Signet for Mac — a menu bar item, and the window that appears when
// something needs a person.
//
// The app does three things and refuses a fourth. It runs the daemon, it is
// the daemon's device (Touch ID and the Secure Enclave), and it shows what
// the daemon has installed and enrolled. It does not approve anything from a
// notification, a menu item, or anywhere that is not the approval window with
// the full payload on it and the hold underneath — device-class spec §3.2.

import AppKit
import CountersignKit
import SignetCore
import SwiftUI

@main
struct SignetApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        MenuBarExtra {
            MenuView()
                .environmentObject(delegate.session)
                .frame(width: 380)
        } label: {
            MenuBarLabel(session: delegate.session)
        }
        .menuBarExtraStyle(.window)
    }
}

/// The dial as a menu bar glyph, amber while something is waiting.
struct MenuBarLabel: View {
    @ObservedObject var session: AppSession
    var body: some View {
        Image(systemName: session.pending == nil ? "circle.dotted.circle" : "circle.circle.fill")
            .symbolRenderingMode(.hierarchical)
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let session: AppSession
    private var approvalWindow: ApprovalWindowController?

    override init() {
        // The enclave key, or a clear reason there is none. An app without a
        // Secure Enclave can display and acknowledge; it cannot approve, and
        // it must not fall back to a software key (device-class spec §2).
        let signer: Signer
        let counters: CounterStore
        var startupProblem: String?
        do {
            let device = try EnclaveDevice()
            signer = device
            counters = device.countersigner.counters
        } catch {
            startupProblem = String(describing: error)
            // A signer that refuses: attaching will fail with a clear message
            // rather than the app pretending to be a device.
            signer = RefusingSigner(reason: String(describing: error))
            counters = MemoryCounterStore()
        }
        let controller = DaemonController()
        session = AppSession(signer: signer, counters: counters, deviceName: Host.current().localizedName ?? "Mac", controller: controller)
        super.init()
        if let startupProblem {
            Task { @MainActor in self.session.noteStartupProblem(startupProblem) }
        }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        // A menu bar app, whether or not the bundle's Info.plist says so.
        NSApp.setActivationPolicy(.accessory)
        // Not a `$pending` sink: that delivers before the property is set,
        // and a window built inside it renders "Nothing pending".
        session.onPendingChange = { [weak self] pending in
            guard let self else { return }
            if let pending {
                self.showApproval(pending)
            } else {
                self.approvalWindow?.close()
                self.approvalWindow = nil
            }
        }
        Task { await session.start() }
    }

    func applicationWillTerminate(_ notification: Notification) {
        session.controller.stop()
    }

    private func showApproval(_ pending: PendingApproval) {
        if approvalWindow == nil {
            approvalWindow = ApprovalWindowController(session: session)
        }
        approvalWindow?.show()
    }
}

/// A signer for a Mac that cannot sign. Every call fails with the reason, so
/// the daemon refuses the attach and the menu shows why.
struct RefusingSigner: Signer {
    let reason: String
    var publicKeySEC1: Data { Data() }
    var deviceID: String { "" }
    func sign(_ message: Data) throws -> Data { throw SigningError.enclaveUnavailable }
}

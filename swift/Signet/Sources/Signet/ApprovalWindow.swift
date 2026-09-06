// The window that appears when something needs a person.
//
// AppKit hosts it directly rather than a SwiftUI `Window` scene, because it
// has to appear from a background state without a view to ask for it, come to
// the front, and stay there while a five-second hold runs.

import AppKit
import SignetCore
import SwiftUI

final class ApprovalWindowController: NSWindowController, NSWindowDelegate {
    private let session: AppSession

    init(session: AppSession) {
        self.session = session
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 440, height: 560),
            styleMask: [.titled, .closable, .fullSizeContentView],
            backing: .buffered,
            defer: false)
        window.title = "Signet"
        window.titlebarAppearsTransparent = true
        window.titleVisibility = .hidden
        window.backgroundColor = NSColor(Theme.ground)
        window.isReleasedWhenClosed = false
        // Above ordinary windows, never above a screen saver or a login prompt.
        window.level = .floating
        window.contentView = NSHostingView(rootView: ApprovalView().environmentObject(session))
        super.init(window: window)
        window.delegate = self
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    func show() {
        guard let window else { return }
        window.center()
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
    }

    func windowWillClose(_ notification: Notification) {
        // Closing the window while something is readable is a decline —
        // declining is ordinary software (wire spec §5.2).
        Task { @MainActor in session.dismiss() }
    }

    func windowDidResignKey(_ notification: Notification) {
        // Focus went elsewhere mid-hold: nobody's hand is verifiably on the
        // control. The hold is given back.
        Task { @MainActor in session.pending?.hold.background() }
    }
}

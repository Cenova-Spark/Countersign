// The window that appears when something needs a person.
//
// AppKit hosts it directly rather than a SwiftUI `Window` scene, because it
// has to appear from a background state without a view to ask for it, come to
// the front, and stay there while a five-second hold runs.

import AppKit
import SignetCore
import SignetUI
import SwiftUI

final class ApprovalWindowController: NSWindowController, NSWindowDelegate {
    private let session: AppSession

    init(session: AppSession) {
        self.session = session
        // Resizable, because the statement decides how tall this wants to be
        // and the person decides how tall it may be. `ApprovalView` sets the
        // floor and the ceiling; a statement that does not fit scrolls inside
        // its screen with the digest and the dial staying put.
        let window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 440, height: 560),
            styleMask: [.titled, .closable, .resizable, .fullSizeContentView],
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
        let first = !window.isVisible
        if first { window.center() }
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
        if first {
            // The hosting view sizes the window to its content on the first
            // layout, growing it downward from wherever it was centred, which
            // is how a long statement once walked off the bottom of the
            // screen. Place it again after that layout, and keep the whole
            // frame on the screen. A later request leaves the window where
            // the person put it, at the size they gave it.
            DispatchQueue.main.async { [weak self] in self?.place(window) }
        }
    }

    private func place(_ window: NSWindow) {
        window.center()
        if let screen = window.screen ?? NSScreen.main {
            window.setFrame(window.constrainFrameRect(window.frame, to: screen), display: true)
        }
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

// The Mac's window around the shared approval screen.
//
// Everything a person reads lives in `SignetUI` so the iPhone renders exactly
// the same thing. What is left here is window geometry, which is the one part
// that genuinely differs: a Mac window has to be given a size, and a phone
// screen is the size it is.
//
// This is also the only file in the app that reaches for AppKit outside the
// menu bar and the window controller.

import AppKit
import CountersignKit
import SignetCore
import SignetUI
import SwiftUI

struct ApprovalView: View {
    @EnvironmentObject var session: AppSession

    var body: some View {
        ZStack {
            Theme.ground.ignoresSafeArea()
            if let pending = session.pending {
                PendingView(pending: pending, actions: session)
            } else {
                Text("Nothing pending").foregroundColor(Theme.inkDim)
            }
        }
        // The floor is what the controls need. The ceiling is the screen: the
        // window opens at the statement's own height up to that, and a longer
        // statement scrolls inside `DeviceScreen` rather than pushing the
        // dial off the bottom.
        .frame(minWidth: 440, maxWidth: .infinity, minHeight: 480, maxHeight: room)
    }

    private var room: CGFloat {
        ((NSScreen.main?.visibleFrame.height) ?? 800) - 24
    }
}

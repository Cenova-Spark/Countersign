// The instrument's own palette, taken from web/src/style.css, which took it
// off the form study. The chassis greys are the chassis greys; the amber is
// the index mark and the ACK cap; the red is the label bar the device paints
// over a production target. Nothing decorative was added.

import CountersignKit
import SwiftUI

public enum Theme {
    public static let ground = Color(hex: 0x0b0d10)
    public static let groundLift = Color(hex: 0x12151a)
    public static let hairline = Color(hex: 0x1e2329)
    public static let screen = Color(hex: 0x07080a)
    public static let screenEdge = Color(hex: 0x262c33)
    public static let ink = Color(hex: 0xf2f5f8)
    public static let inkSoft = Color(hex: 0xc9d1d9)
    public static let inkDim = Color(hex: 0x7b8794)
    public static let inkFaint = Color(hex: 0x5d666f)
    public static let steel = Color(hex: 0x747a82)
    public static let steelLit = Color(hex: 0x8d949e)
    public static let amber = Color(hex: 0xe08a4c)
    public static let caution = Color(hex: 0xd9a441)
    public static let refuse = Color(hex: 0xb0261b)
    /// Signed, and verified by the daemon against this Mac's enrolled key.
    /// Its own colour because amber was doing this, the ADV markers and the
    /// index mark all at once, and nobody reads "done" out of the same colour
    /// as "careful".
    public static let signed = Color(hex: 0x4f9d6b)

    /// The label bar takes the severity's colour: red for anything that could
    /// destroy, caution for moderate, steel for the rest.
    public static func labelBar(for severity: Severity) -> Color {
        switch severity {
        case .critical, .high: return refuse
        case .moderate: return caution
        case .low, .none: return steel
        }
    }

    public static let label = Font.system(size: 11, weight: .semibold, design: .default)
    public static let mono = Font.system(size: 13, design: .monospaced)
    public static let monoSmall = Font.system(size: 11, design: .monospaced)
}

extension Color {
    init(hex: UInt32) {
        self.init(
            red: Double((hex >> 16) & 0xff) / 255,
            green: Double((hex >> 8) & 0xff) / 255,
            blue: Double(hex & 0xff) / 255)
    }
}

/// Silkscreen: the voice of anything printed on the instrument.
public struct Legend: View {
    let text: String
    var lit = false

    public init(text: String, lit: Bool = false) {
        self.text = text
        self.lit = lit
    }

    public var body: some View {
        Text(text.uppercased())
            .font(Theme.label)
            .tracking(1.6)
            .foregroundColor(lit ? Theme.amber : Theme.inkFaint)
    }
}

// swift-tools-version: 6.0
//
// SignetUI — the approval screen, shared by the Mac app and the iPhone app.
//
// The screen a person reads before they hold is the part that must not differ
// between devices. A phone that laid out the statement differently, or put the
// digest somewhere else, or armed on a different rule, would be a second
// implementation of the one surface the whole design rests on — and the
// divergence would show up as a person approving something they had not read.
// So it lives here once, and both apps render it.
//
// What is deliberately *not* here: anything that knows where a request came
// from or how the answer gets back. The Mac talks to a local daemon over a
// unix socket; the phone will talk to a relay over HTTPS. Those have nothing in
// common and belong to their own targets — this package takes an already-parsed
// request and an `ApprovalActions` to answer through, and knows nothing else.
import PackageDescription

let package = Package(
    name: "SignetUI",
    platforms: [
        // The same range as CountersignKit: Secure Enclave keys through
        // CryptoKit on both, and the SwiftUI this uses.
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(name: "SignetUI", targets: ["SignetUI"]),
    ],
    dependencies: [
        .package(path: "../CountersignKit"),
    ],
    targets: [
        .target(
            name: "SignetUI",
            dependencies: [.product(name: "CountersignKit", package: "CountersignKit")],
            path: "Sources/SignetUI",
            // Swift 5 language mode, matching the kit and the app. The views
            // are main-actor by construction and strict concurrency has
            // nothing to add until the apps adopt it together.
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "SignetUITests",
            dependencies: ["SignetUI", .product(name: "CountersignKit", package: "CountersignKit")],
            path: "Tests/SignetUITests",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)

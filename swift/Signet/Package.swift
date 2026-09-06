// swift-tools-version: 6.0
//
// Signet — the Mac app. A menu bar item, the approval window, and the daemon
// it runs. Everything cryptographic and every gesture rule comes from
// CountersignKit; this package is the window around them.
import PackageDescription

let package = Package(
    name: "Signet",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(path: "../CountersignKit"),
    ],
    targets: [
        // The part of the app with no windows in it, so it can be tested:
        // the socket, the JSON-RPC routing, the daemon lifecycle, the state
        // read off disk, and the approval flow from presentation to answer.
        .target(
            name: "SignetCore",
            dependencies: [.product(name: "CountersignKit", package: "CountersignKit")],
            path: "Sources/SignetCore",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .executableTarget(
            name: "Signet",
            dependencies: ["SignetCore", .product(name: "CountersignKit", package: "CountersignKit")],
            path: "Sources/Signet",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "SignetCoreTests",
            dependencies: ["SignetCore", .product(name: "CountersignKit", package: "CountersignKit")],
            path: "Tests/SignetCoreTests",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)

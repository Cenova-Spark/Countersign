// swift-tools-version: 6.0
//
// CountersignKit — the crypto and the gesture rules, shared by the Mac app and
// the iPhone app, with no UI in it.
//
// Everything here is a port: JCS from web/src/lib/jcs.js, the signing payload
// and low-S rule from sign.js and p256.js, the hold from hold.js. It is
// checked against spec/vectors/ and not against the Rust, for the reason
// web/README.md gives — two implementations agreeing with each other and both
// being wrong is the failure this is meant to catch.
import PackageDescription

let package = Package(
    name: "CountersignKit",
    platforms: [
        // Secure Enclave keys through CryptoKit, `MenuBarExtra`, and the
        // data-protection keychain on macOS all land in this range.
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .library(name: "CountersignKit", targets: ["CountersignKit"]),
        .executable(name: "countersign-swift-vector", targets: ["GenerateVector"]),
    ],
    targets: [
        .target(
            name: "CountersignKit",
            path: "Sources/CountersignKit",
            // Swift 5 language mode: the hold machine and the enclave device
            // are plain classes driven from one thread (the main actor, in an
            // app), and strict concurrency checking has nothing to add to
            // that yet. Revisit when the apps adopt it wholesale.
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .executableTarget(
            name: "GenerateVector",
            dependencies: ["CountersignKit"],
            path: "Sources/GenerateVector",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "CountersignKitTests",
            dependencies: ["CountersignKit"],
            path: "Tests/CountersignKitTests",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)

// swift-tools-version: 6.0
// WardenFuse menu bar app. Build with scripts/build-app.sh, which first builds the Rust core
// (static library) and then this package, and assembles WardenFuse.app.
import PackageDescription

// Universal (arm64 + x86_64) static library assembled with lipo by scripts/build-app.sh.
let rustLib = "../target/universal-apple-darwin/release"

let package = Package(
    name: "WardenFuse",
    platforms: [.macOS(.v15)],
    targets: [
        .target(
            name: "CWardenFuseCore",
            path: "CWardenFuseCore",
            publicHeadersPath: "include"
        ),
        .executableTarget(
            name: "WardenFuse",
            dependencies: ["CWardenFuseCore"],
            path: "WardenFuse",
            exclude: ["Resources"],
            swiftSettings: [.swiftLanguageMode(.v5)],
            linkerSettings: [
                .unsafeFlags(["-L", rustLib]),
                .linkedLibrary("wardenfuse_core"),
                .linkedFramework("Security"),
                .linkedFramework("LocalAuthentication"),
                .linkedFramework("ServiceManagement"),
                .linkedFramework("SystemConfiguration"),
                .linkedFramework("CoreFoundation"),
            ]
        ),
        .testTarget(
            name: "WardenFuseTests",
            dependencies: ["WardenFuse"],
            path: "Tests/WardenFuseTests",
            swiftSettings: [.swiftLanguageMode(.v5)],
            linkerSettings: [.unsafeFlags(["-L", rustLib])]
        ),
    ]
)

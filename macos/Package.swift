// swift-tools-version: 6.0
// WardenFuse menu bar app. Build with scripts/build-app.sh, which first builds the Rust core
// (static library) and then this package, and assembles WardenFuse.app.
import PackageDescription

let rustLib = "../target/aarch64-apple-darwin/release"

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
    ]
)

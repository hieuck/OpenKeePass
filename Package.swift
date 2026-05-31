// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "OpenKeePassCore",
    platforms: [.iOS(.v15)],
    products: [
        .library(name: "KeePassCore", targets: ["KeePassCore"]),
        .library(name: "VaultStore", targets: ["VaultStore"]),
        .library(name: "SecurityKit", targets: ["SecurityKit"]),
        .library(name: "PasswordTools", targets: ["PasswordTools"]),
        .library(name: "SharedUI", targets: ["SharedUI"])
    ],
    targets: [
        .target(name: "KeePassCore", dependencies: [
            "CArgon2"
        ]),
        .target(
            name: "CArgon2",
            path: "Sources/CArgon2",
            exclude: ["src/genkat.c"],
            publicHeadersPath: "include"
        ),
        .target(name: "VaultStore", dependencies: ["KeePassCore", "SecurityKit"]),
        .target(name: "SecurityKit"),
        .target(name: "PasswordTools"),
        .target(name: "SharedUI", dependencies: ["KeePassCore", "PasswordTools"]),
        .testTarget(
            name: "KeePassCoreTests",
            dependencies: ["KeePassCore"],
            resources: [.copy("../../Fixtures/KDBX")]
        ),
        .testTarget(name: "VaultStoreTests", dependencies: ["VaultStore"]),
        .testTarget(name: "SecurityKitTests", dependencies: ["SecurityKit"]),
        .testTarget(name: "PasswordToolsTests", dependencies: ["PasswordTools"])
    ]
)

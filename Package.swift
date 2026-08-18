// swift-tools-version: 5.9
import Foundation
import PackageDescription

let fridaCoreTarget: Target
#if canImport(Darwin)
if ProcessInfo.processInfo.environment["USE_SYSTEM_FRIDA"] != nil {
    fridaCoreTarget = .systemLibrary(
        name: "FridaCore",
        path: "FridaCore",
        pkgConfig: "frida-core-1.0"
    )
} else {
    fridaCoreTarget = .binaryTarget(
        name: "FridaCore",
        url: "https://github.com/frida/frida-core/releases/download/17.18.0-snapshot.20260818.1/FridaCore.xcframework.zip",
        checksum: "c4c5c0a5a5cf170849d05492a85f9b3283f900a683b822515710dee12ffab73f"
    )
}
#else
fridaCoreTarget = .systemLibrary(
    name: "FridaCore",
    path: "FridaCore",
    pkgConfig: "frida-core-1.0"
)
#endif

let package = Package(
    name: "FridaSwift",
    platforms: [
        .macOS(.v11),
        .iOS(.v13),
    ],
    products: [
        .library(
            name: "Frida",
            targets: ["Frida"]
        ),
    ],
    targets: [
        fridaCoreTarget,
        .target(
            name: "Frida",
            dependencies: [
                "FridaCore",
            ],
            path: "Frida",
            exclude: [
                "Frida.version",
                "Frida_Private",
                "Info.plist",
                "generate-framework.py",
                "meson.build",
                "GLib/meson.build",
                "JSONGLib/meson.build",
            ],
            linkerSettings: [
                .linkedLibrary("resolv", .when(platforms: [.macOS, .iOS])),
            ]
        ),
        .testTarget(
            name: "FridaTests",
            dependencies: ["Frida"]
        ),
    ]
)

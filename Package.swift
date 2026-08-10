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
        url: "https://github.com/frida/frida-core/releases/download/17.17.0/FridaCore.xcframework.zip",
        checksum: "52d2eedb68930de5d7826ea2fcdfd81b2926fc5dc3d44e0e572bf953af136c1f"
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

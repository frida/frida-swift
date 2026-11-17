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
        url: "https://github.com/frida/frida-core/releases/download/17.27.0/FridaCore.xcframework.zip",
        checksum: "6945690044401b6af39b74c450f4818e32ad87b1e8a43646961413b4e9ed6bd4"
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

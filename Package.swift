// swift-tools-version: 5.9
import PackageDescription

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
        .binaryTarget(
            name: "FridaCore",
            url: "https://github.com/frida/frida-core/releases/download/17.9.1/FridaCore.xcframework.zip",
            checksum: "5df0ba31fb97765b2a4d391a3fa062a6b7657a92518aa0109ca7fc232ba8f7e5"
        ),
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
            ],
        )
    ]
)

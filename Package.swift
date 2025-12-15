// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "FridaSwift",
    platforms: [
        .macOS(.v11),
        .iOS(.v12),
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
            url: "https://github.com/frida/frida-core/releases/download/17.5.2/FridaCore.xcframework.zip",
            checksum: "1edfa0771080223931e5d745de1725be5b9e27cc6381979c47aac5f65358a79e"
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

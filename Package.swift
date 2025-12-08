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
            url: "https://github.com/frida/frida-core/releases/download/17.5.2-snapshot.20251208/FridaCore.xcframework.zip",
            checksum: "dd6731bc96f970bf5385def0a4febd3f38b446923ad6118be39e6b7902a3fe29"
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
            ],
            linkerSettings: [
                .linkedLibrary("resolv", .when(platforms: [.macOS, .iOS])),
            ],
        )
    ]
)

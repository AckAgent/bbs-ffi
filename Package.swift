// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "bbs-ffi",
    platforms: [.iOS("18.0"), .macOS("14.0")],
    products: [
        .library(name: "BbsFfi", targets: ["BbsFfi"]),
    ],
    targets: [
        .binaryTarget(
            name: "bbs_ffiFFI",
            url: "https://github.com/AckAgent/bbs-ffi/releases/download/v0.1.0/AckAgentBBSBindings.xcframework.zip",
            checksum: "3bf10fbd54014b45d280292d7ffb0f631f56f2c6ffde19a04abacbe36a3bdcad"
        ),
        .target(
            name: "BbsFfi",
            dependencies: ["bbs_ffiFFI"],
            path: "generated",
            sources: ["bbs_ffi.swift"]
        ),
    ]
)

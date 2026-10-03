// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "CalcCore",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "CalcCore", targets: ["CalcCore"]),
    ],
    targets: [
        .target(name: "CalcCore"),
        .testTarget(name: "CalcCoreTests", dependencies: ["CalcCore"]),
    ],
    swiftLanguageModes: [.v5]
)

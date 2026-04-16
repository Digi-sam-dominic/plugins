// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "CapDecryptBundle",
    platforms: [.iOS(.v15)],
    products: [
        .library(
            name: "CapDecryptBundle",
            targets: ["DecryptBundlePlugin"])
    ],
    dependencies: [
        .package(url: "https://github.com/ionic-team/capacitor-swift-pm.git", from: "8.0.0"),
        .package(url: "https://github.com/weichsel/ZIPFoundation.git", from: "0.9.19")
    ],
    targets: [
        .target(
            name: "DecryptBundlePlugin",
            dependencies: [
                .product(name: "Capacitor", package: "capacitor-swift-pm"),
                .product(name: "Cordova", package: "capacitor-swift-pm"),
                .product(name: "ZIPFoundation", package: "ZIPFoundation")
            ],
            path: "ios/Sources/DecryptBundlePlugin"),
        .testTarget(
            name: "DecryptBundlePluginTests",
            dependencies: ["DecryptBundlePlugin"],
            path: "ios/Tests/DecryptBundlePluginTests")
    ]
)
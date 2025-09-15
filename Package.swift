// swift-tools-version: 6.1
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "capstone",
    products: [
        .library(
            name: "Ccapstone",
            targets: ["Ccapstone"]
        ),
    ],
    targets: [
        .target(
            name: "Ccapstone",
            path: "bindings/swift/Ccapstone",
        ),
    ]
)

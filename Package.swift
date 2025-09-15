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
            cSettings: [
                .headerSearchPath("../../../include"),
                .define("CAPSTONE_USE_SYS_DYN_MEM"),
                .define("CAPSTONE_HAS_ARM"),
                .define("CAPSTONE_HAS_ARM64"),
                .define("CAPSTONE_HAS_AARCH64"),
                .define("CAPSTONE_HAS_MIPS"),
                .define("CAPSTONE_HAS_X86"),
                .define("CAPSTONE_HAS_POWERPC"),
                .define("CAPSTONE_HAS_SPARC"),
                .define("CAPSTONE_HAS_SYSTEMZ"),
                .define("CAPSTONE_HAS_XCORE"),
                .define("CAPSTONE_HAS_M68K"),
                .define("CAPSTONE_HAS_TMS320C64X"),
                .define("CAPSTONE_HAS_M680X"),
                .define("CAPSTONE_HAS_EVM"),
                .define("CAPSTONE_HAS_MOS65XX"),
                .define("CAPSTONE_HAS_WASM"),
                .define("CAPSTONE_HAS_BPF"),
                .define("CAPSTONE_HAS_RISCV"),
                .define("CAPSTONE_HAS_SH"),
                .define("CAPSTONE_HAS_TRICORE"),
                .define("CAPSTONE_HAS_ALPHA"),
                .define("CAPSTONE_HAS_HPPA"),
                .define("CAPSTONE_HAS_LOONGARCH"),
                .define("CAPSTONE_HAS_XTENSA"),
                .define("CAPSTONE_HAS_ARC"),
            ],
        ),
        .testTarget(
            name: "CcapstoneTests",
            dependencies: ["Ccapstone"],
            path: "bindings/swift/CcapstoneTests",
        ),
    ]
)

// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let architectures: [(trait: String, define: String)] = [
    ("ARM", "CAPSTONE_HAS_ARM"),
    ("ARM64", "CAPSTONE_HAS_ARM64"),
    ("AARCH64", "CAPSTONE_HAS_AARCH64"),
    ("MIPS", "CAPSTONE_HAS_MIPS"),
    ("X86", "CAPSTONE_HAS_X86"),
    ("POWERPC", "CAPSTONE_HAS_POWERPC"),
    ("SPARC", "CAPSTONE_HAS_SPARC"),
    ("SYSTEMZ", "CAPSTONE_HAS_SYSTEMZ"),
    ("XCORE", "CAPSTONE_HAS_XCORE"),
    ("M68K", "CAPSTONE_HAS_M68K"),
    ("TMS320C64X", "CAPSTONE_HAS_TMS320C64X"),
    ("M680X", "CAPSTONE_HAS_M680X"),
    ("EVM", "CAPSTONE_HAS_EVM"),
    ("MOS65XX", "CAPSTONE_HAS_MOS65XX"),
    ("WASM", "CAPSTONE_HAS_WASM"),
    ("BPF", "CAPSTONE_HAS_BPF"),
    ("RISCV", "CAPSTONE_HAS_RISCV"),
    ("SH", "CAPSTONE_HAS_SH"),
    ("TRICORE", "CAPSTONE_HAS_TRICORE"),
    ("ALPHA", "CAPSTONE_HAS_ALPHA"),
    ("HPPA", "CAPSTONE_HAS_HPPA"),
    ("LOONGARCH", "CAPSTONE_HAS_LOONGARCH"),
    ("XTENSA", "CAPSTONE_HAS_XTENSA"),
    ("ARC", "CAPSTONE_HAS_ARC"),
]

let package = Package(
    name: "capstone",
    products: [
        .library(
            name: "Ccapstone",
            targets: ["Ccapstone"]
        ),
    ],
    traits: Set(architectures.map { Trait(name: $0.trait) }),
    targets: [
        .target(
            name: "Ccapstone",
            path: "bindings/swift/Ccapstone",
            cSettings: [
                .headerSearchPath("../../../include"),
                .define("CAPSTONE_USE_SYS_DYN_MEM"),
            ] + architectures.map { .define($0.define, .when(traits: [$0.trait])) }
        ),
        .testTarget(
            name: "CcapstoneTests",
            dependencies: ["Ccapstone"],
            path: "bindings/swift/CcapstoneTests"
        ),
    ]
)

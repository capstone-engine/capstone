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

/// Traits kept under the name capstone v5 used, mapped to the trait that carries
/// the code today.
///
/// v6 renamed the ARM64 architecture to AArch64, and every source file under
/// arch/AArch64 now tests `CAPSTONE_HAS_AARCH64` alone — `CAPSTONE_HAS_ARM64`
/// survives only in the `all_arch` bitmask in cs.c. Enabling `ARM64` on its own
/// would therefore advertise the architecture while compiling none of its code,
/// so the legacy trait pulls the current one in.
let legacyTraitAliases: [String: Set<String>] = [
    "ARM64": ["AARCH64"],
]

/// capstone's own CMake build enables every architecture unless told otherwise,
/// and SwiftPM treats a package that declares no default traits as having none
/// enabled. Without this a plain `swift build` yields a library that supports no
/// architecture at all. Consumers wanting a smaller binary opt out per
/// dependency with `traits:`.
let defaultTrait = Trait.default(enabledTraits: Set(architectures.map(\.trait)))

let package = Package(
    name: "capstone",
    products: [
        .library(
            name: "Ccapstone",
            targets: ["Ccapstone"]
        ),
    ],
    traits: Set(
        architectures.map { architecture in
            Trait(
                name: architecture.trait,
                enabledTraits: legacyTraitAliases[architecture.trait] ?? []
            )
        } + [defaultTrait]
    ),
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

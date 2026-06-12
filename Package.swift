// swift-tools-version: 6.2

import PackageDescription

let architectures = [
	"ARM", "AARCH64", "M68K", "MIPS", "POWERPC", "SPARC", "SYSTEMZ", "XCORE", "X86", "TMS320C64X", "M680X", "EVM", "MOS65XX", "WASM", "BPF", "RISCV", "SH", "TRICORE", "ALPHA", "HPPA", "LOONGARCH", "XTENSA", "ARC"
]

var traits: Set<Trait> = Set(architectures.map { Trait(name: $0) })
traits.insert(.default(enabledTraits: Set(architectures)))

let package = Package(
	name: "capstone",
	products: [
		.library(name: "CapstoneKit", targets: ["CapstoneKit"]),
		.library(name: "capstone", targets: ["capstone"]),
	],
	traits: traits,
	targets: [
		.target(
			name: "CapstoneKit",
			dependencies: ["capstone"],
			path: "bindings/swift/Sources",
			swiftSettings: [
				.enableExperimentalFeature("SafeInteropWrappers"),
			]
		),
		.testTarget(
			name: "CapstoneKitTests",
			dependencies: ["CapstoneKit"],
			path: "bindings/swift/Tests"
		),
		.target(
			name: "capstone",
			path: ".",
			sources: [
				"arch",
				"cs.c",
				"Mapping.c",
				"MCInst.c",
				"MCInstPrinter.c",
				"MCInstrDesc.c",
				"MCRegisterInfo.c",
				"SStream.c",
				"utils.c",
			],
			cSettings: [
				.define("CAPSTONE_USE_SYS_DYN_MEM"),
				.disableWarning("shorten-64-to-32"),
			] + architectures
				.map { CSetting.define("CAPSTONE_HAS_\($0)") }
		),
	]
)

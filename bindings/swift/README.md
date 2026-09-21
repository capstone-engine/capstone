# Swift Package Manager support

This directory exposes the capstone C sources as a SwiftPM package, so that a
Swift project can depend on capstone directly from source with no system
library, no CMake invocation and no prebuilt binary.

```swift
.package(url: "https://github.com/MxIris-Reverse-Engineering/capstone", from: "6.0.0")
```

```swift
.target(name: "YourTarget", dependencies: [
    .product(name: "Ccapstone", package: "capstone"),
])
```

## Layout

`Ccapstone` does not hold a copy of the sources. It is a directory of symbolic
links pointing back at the real files in the repository root, so the SwiftPM
build always compiles the same code as the CMake and Makefile builds.

| Path | Contents |
| --- | --- |
| `Ccapstone/` | symlinks to the root `.c` / `.h` files and to `arch/` |
| `Ccapstone/include/capstone/` | symlinks to the public headers |
| `CcapstoneTests/` | Swift Testing suite exercising the C API |

## Choosing architectures

Every architecture is a package trait, and **all of them are enabled by
default** — matching what capstone's own CMake build does. A plain
`swift build` therefore produces a library supporting every architecture.

To build a smaller library, disable the defaults and name only what is needed:

```swift
.package(
    url: "https://github.com/MxIris-Reverse-Engineering/capstone",
    from: "6.0.0",
    traits: ["X86", "AARCH64"]
)
```

Dropping everything but x86 and AArch64 takes the compiled object code from
about 66 MB to about 16 MB.

The trait names match the `CAPSTONE_HAS_<ARCH>` macros of the C build:

`ARM` `AARCH64` `MIPS` `X86` `POWERPC` `SPARC` `SYSTEMZ` `XCORE` `M68K`
`TMS320C64X` `M680X` `EVM` `MOS65XX` `WASM` `BPF` `RISCV` `SH` `TRICORE`
`ALPHA` `HPPA` `LOONGARCH` `XTENSA` `ARC`

`ARM64` is accepted as well. It is the name v5 used for what v6 calls AArch64,
and it now enables `AARCH64` so that it keeps working; prefer `AARCH64` in new
code.

## Keeping the package in sync with upstream

Two scripts maintain what the SwiftPM build needs but the CMake build does not.
Run both after merging upstream, before building:

```sh
bindings/swift/Ccapstone/UpdateSymlink.sh                 # new root sources
bindings/swift/Ccapstone/include/capstone/UpdateSymlink.sh # new public headers
bindings/swift/UpdateArchitectureGuards.sh                 # new arch sources
```

`UpdateArchitectureGuards.sh` wraps every `arch/**/*.c` file that lacks one in
`#ifdef CAPSTONE_HAS_<ARCH>` … `#endif`. This is necessary because CMake
excludes a disabled architecture by leaving its files out of the source list,
which SwiftPM cannot express — SwiftPM compiles every file under the target
path and can only vary preprocessor macros. Upstream guards most files already,
but consistently misses the disassemblers, instruction printers and their
extensions; without the guards, disabling an architecture produces a link
failure rather than a smaller library. The script reads the macro for each file
off a sibling that is already guarded rather than deriving it from the
directory name, and is idempotent.

# Building Capstone

This guide describes how to build Capstone with `CMake`.

## Build commands

**Unix**

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release # For debug build change "Release" to "Debug"
cmake --build build
cmake --install build --prefix "<install-prefix>"
```

To create rpm, debian and OSX packages, run the following
```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCAPSTONE_BUILD_SHARED_LIBS=1 -DCMAKE_INSTALL_PREFIX=/usr
cmake --build build
cd build
cpack -G DEB
cpack -G RPM
cpack -G DragNDrop
```

**Windows**

```bash
cmake.exe -B build
cmake.exe --build build --config Release # For debug build change "Release" to "Debug"
cmake.exe --install build
```

## Tailor Capstone to your needs.

Enable and disable options in the "configure" step (first `cmake` command from above).
Options are added with `-D<OPTION>=ON/OFF` or `-D<OPTION>=1/0`

### Exclude architecture modules

You can build Capstone with only the architectures you need.
By default all are enabled.

- `CAPSTONE_ARCHITECTURE_DEFAULT`: Whether all architectures are enabled by default.
- `CAPSTONE_ARM_SUPPORT`: Support ARM.
- `CAPSTONE_AARCH64_SUPPORT`: Support AARCH64.
- `CAPSTONE_ALPHA_SUPPORT`: Support Alpha.
- `CAPSTONE_ARC_SUPPORT`: Support ARC.
- `CAPSTONE_HPPA_SUPPORT`: Support HPPA.
- `CAPSTONE_LOONGARCH_SUPPORT`: Support LoongArch.
- `CAPSTONE_M680X_SUPPORT`: Support M680X.
- `CAPSTONE_M68K_SUPPORT`: Support M68K.
- `CAPSTONE_MIPS_SUPPORT`: Support Mips.
- `CAPSTONE_MOS65XX_SUPPORT`: Support MOS65XX.
- `CAPSTONE_PPC_SUPPORT`: Support PPC.
- `CAPSTONE_SPARC_SUPPORT`: Support Sparc.
- `CAPSTONE_SYSTEMZ_SUPPORT`: Support SystemZ.
- `CAPSTONE_XCORE_SUPPORT`: Support XCore.
- `CAPSTONE_TRICORE_SUPPORT`: Support TriCore.
- `CAPSTONE_X86_SUPPORT`: Support X86.
- `CAPSTONE_TMS320C64X_SUPPORT`: Support TMS320C64X.
- `CAPSTONE_M680X_SUPPORT`: Support M680X.
- `CAPSTONE_EVM_SUPPORT`: Support EVM.
- `CAPSTONE_WASM_SUPPORT`: Support Web Assembly.
- `CAPSTONE_BPF_SUPPORT`: Support BPF.
- `CAPSTONE_RISCV_SUPPORT`: Support RISCV.
  
### Module registration

If you're building a static library that you intend to link into multiple consumers,
and they have differing architecture requirements, you may want `-DCAPSTONE_USE_ARCH_REGISTRATION=1`.

In your consumer code you can call `cs_arch_register_*()` to register the specific module for initialization.

In this way you only pay footprint size for the architectures you're actually using in each consumer,
without having to compile Capstone multiple times.

### Additional options

Capstone allows some more customization via the following options:

- `CAPSTONE_BUILD_SHARED_LIBS`: Build shared libraries.
- `CAPSTONE_BUILD_STATIC_LIBS`: Build static libraries (`ON` by default).
- `CAPSTONE_BUILD_STATIC_MSVC_RUNTIME`: (Windows only) - Build with static MSVC runtime. Always set if `CAPSTONE_BUILD_SHARED_LIBS=ON`.
- `CAPSTONE_BUILD_CSTOOL`: Enable/disable build of `cstool`. Default is enabled if build runs from the repository root.
- `CAPSTONE_USE_SYS_DYN_MEM`: change this to OFF to use your own dynamic memory management.
- `CAPSTONE_BUILD_MACOS_THIN`: MacOS only. Disables universal2 build. So you only get the binary for you processor architecture.
- `CAPSTONE_BUILD_DIET`: change this to ON to make the binaries more compact.
- `CAPSTONE_X86_REDUCE`: change this to ON to make X86 binary smaller.
- `CAPSTONE_X86_ATT_DISABLE`: change this to ON to disable AT&T syntax on x86.

By default, Capstone use system dynamic memory management, and both DIET and X86_REDUCE
modes are disabled. To use your own memory allocations, turn ON both DIET &
X86_REDUCE, run "cmake" with: `-DCAPSTONE_USE_SYS_DYN_MEM=0`, `-DCAPSTONE_BUILD_DIET=1`, `-DCAPSTONE_X86_REDUCE=1`

### Developer specific options

- `CAPSTONE_DEBUG`: Change this to ON to enable extra debug assertions. Automatically enabled with `Debug` build.
- `CAPSTONE_BUILD_CSTEST`: Build `cstest` in `suite/cstest/`. **Note:** `cstest` requires `libyaml` on your system. It attempts to build it from source otherwise.
- `CMAKE_EXPORT_COMPILE_COMMANDS`: To export `compile_commands.json` for `clangd` and other language servers.
- `ENABLE_ASAN`: Compiles Capstone with the address sanitizer.
- `ENABLE_COVERAGE`: Generate coverage files.
- `CAPSTONE_BUILD_LEGACY_TESTS`: Build some legacy integration tests.

## Building cstest

`cstest` is build together with Capstone by adding the flag `-DCAPSTONE_BUILD_CSTEST`.

The build requires `libyaml`. It is a fairly common package and should be provided by your package manager.

_Note:_ Currently `cstest` us only supported on Linux.

If you run another operation system, please install `cstest_py`.
See `bindings/python/BUILDING.md` for instructions.

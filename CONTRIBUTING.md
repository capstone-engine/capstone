Code structure
--------------

Capstone source is organized as followings.

```
.                   <- core engine + README.md + BUILDING.md etc
├── arch            <- code handling disasm engine for each arch
│   ├── AArch64     <- AArch64 engine
│   ├── Alpha       <- Alpha engine
│   ├── ARM         <- ARM engine
│   ├── BPF         <- Berkeley Packet Filter engine
│   ├── EVM         <- Ethereum engine
│   ├── HPPA        <- HPPA engine
│   ├── M680X       <- M680X engine
│   ├── M68K        <- M68K engine
│   ├── Mips        <- Mips engine
│   ├── MOS65XX     <- MOS65XX engine
│   ├── PowerPC     <- PowerPC engine
│   ├── RISCV       <- RISCV engine
│   ├── SH          <- SH engine
│   ├── Sparc       <- Sparc engine
│   ├── SystemZ     <- SystemZ engine
│   ├── TMS320C64x  <- TMS320C64x engine
│   ├── TriCore     <- TriCore engine
│   └── WASM        <- WASM engine
├── bindings        <- all bindings are under this dir
│   ├── java        <- Java bindings
│   ├── ocaml       <- Ocaml bindings
│   └── python      <- Python bindings
│       └── cstest  <- Testing tool for the Python bindings.
├── suite           <- Several tools used for development
│   ├── cstest      <- Testing tool to consume and check the test `yaml` files in `tests`
│   ├── fuzz        <- Fuzzer
│   └── auto-sync   <- The updater for Capstone modules
├── contrib         <- Code contributed by community to help Capstone integration
├── cstool          <- Cstool
├── docs            <- Documentation
├── include         <- API headers in C language (*.h)
├── packages        <- Packages for Linux/OSX/BSD.
├── windows         <- Windows support (for Windows kernel driver compile)
├── tests           <- Unit and itegration tests
└── xcode           <- Xcode support (for MacOSX compile)
```

Building
--------

Follow the instructions in [BUILDING.md](BUILDING.md) for how to compile and run test code.

Testing
-------

General testing docs are at [tests/README.md](tests/README.md).

You can test single instructions easily with the `cstool`.
For example:

```bash
$ cstool x32 "90 91"
```

Using `cstool` is also the prefered way for debugging a single instruction.

**Bindings**

Bindings currently have not equivalent to a `cstool`.

The Python bindings have `cstool` implemented.

Other bindings are out-of-date for a while because of missing maintainers.
They only have legacy integration tests.

Please check the issues or open a new one if you intent to work on them or need them.

Coding style
------------
- We provide a `.clang-format` for C code.
- Python files should be formatted with `black`.

Support
-------

**Please always open an issue or leave a comment in one, before starting work on an architecture! We can give support and save you a lot of time.**

Updating an Architecture
------------------------

The update tool for Capstone is called `Auto-Sync` and can be found in `suite/auto-sync`.

Not all architectures are supported yet.
Run `suite/auto-sync/Updater/ASUpdater.py -h` to get a list of currently supported architectures.

The documentation how to update with `Auto-Sync` or refactor an architecture module
can be found in [suite/auto-sync/README.md](suite/auto-sync/README.md).

If a module does not support `Auto-Sync` yet, it is highly recommended to refactor it
instead of attempting to update it manually.
Refactoring will take less time and updates it during the procedure.

The one exception is `x86`. In LLVM we use several emitter backends to generate C code.
One of those LLVM backends (the `DecoderEmitter`) has two versions.
One for `x86` and another for all the other architectures.
Until now it was not worth it to refactoring this unique `x86` backend. So `x86` is not
supported currently.

Adding an Architecture
----------------------

If your architecture is supported in LLVM or one of its forks, you can use `Auto-Sync` to
add the new module.
Checkout [suite/auto-sync/README.md](suite/auto-sync/README.md).

Otherwise, you need to implement the disassembler on your own and make it work with the Capstone API.

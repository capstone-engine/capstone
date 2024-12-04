Capstone Engine
===============

[![Build status](https://ci.appveyor.com/api/projects/status/a4wvbn89wu3pinas/branch/next?svg=true)](https://ci.appveyor.com/project/aquynh/capstone/branch/next)
[![pypi package](https://badge.fury.io/py/capstone.svg)](https://pypi.python.org/pypi/capstone)
[![pypi downloads](https://pepy.tech/badge/capstone)](https://pepy.tech/project/capstone)
[![oss-fuzz Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/capstone.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:capstone)

> [!TIP]
> Welcome to join our community group!
> &ensp; [<img src="https://img.shields.io/badge/Telegram-2CA5E0?style=flat-squeare&logo=telegram&logoColor=white" height="22" />](https://t.me/CapstoneEngine)

Capstone is a disassembly framework with the target of becoming the ultimate
disasm engine for binary analysis and reversing in the security community.

Created by Nguyen Anh Quynh, then developed and maintained by a small community,
Capstone offers some unparalleled features:

- Support multiple hardware architectures: ARM, AArch64, Alpha, ARC, BPF, Ethereum VM,
  LoongArch, HP PA-RISC (HPPA), M68K, M680X, Mips, MOS65XX, PPC, RISC-V(rv32G/rv64G), SH,
  Sparc, SystemZ, TMS320C64X, TriCore, Webassembly, XCore and X86 (16, 32, 64), Xtensa.

- Having clean/simple/lightweight/intuitive architecture-neutral API.

- Provide details on disassembled instruction (called “decomposer” by others).

- Provide semantics of the disassembled instruction, such as list of implicit
  registers read & written.

- Implemented in pure C language, with lightweight bindings for Swift, D, Clojure, F#,
  Common Lisp, Visual Basic, PHP, PowerShell, Emacs, Haskell, Perl, Python,
  Ruby, C#, NodeJS, Java, GO, C++, OCaml, Lua, Rust, Delphi, Free Pascal & Vala
  ready either in main code, or provided externally by the community).

- Native support for all popular platforms: Windows, Mac OSX, iOS, Android,
  Linux, \*BSD, Solaris, etc.

- Thread-safe by design.

- Special support for embedding into firmware or OS kernel.

- High performance & suitable for malware analysis (capable of handling various
  X86 malware tricks).

- Distributed under the open source BSD license.

Further information is available at https://www.capstone-engine.org


Compile
-------

See [BUILDING.md](BUILDING.md) file for how to compile and install Capstone.


Documentation
-------------

- Useful links and tutorials: [docs/README](docs/README)
- Software architecture overview: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Testing documentation: [tests/README.md](tests/README.md)
- Updater (Auto-Sync) documentation: [suite/auto-sync/README.md](suite/auto-sync/README.md)

Contributing
----

See [CONTRIBUTING.md](CONTRIBUTING.md) for an intro.

Fuzz
----

See suite/fuzz/README.md for more information.

License
-------

This project is released under the BSD license. If you redistribute the binary
or source code of Capstone, please attach file LICENSE.TXT with your products.

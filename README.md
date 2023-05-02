Capstone Engine
===============

[![Build Status](https://travis-ci.org/aquynh/capstone.svg?branch=next)](https://travis-ci.org/aquynh/capstone)
[![Build status](https://ci.appveyor.com/api/projects/status/a4wvbn89wu3pinas/branch/next?svg=true)](https://ci.appveyor.com/project/aquynh/capstone/branch/next)
[![pypi package](https://badge.fury.io/py/capstone.svg)](https://pypi.python.org/pypi/capstone)
[![pypi downloads](https://pepy.tech/badge/capstone)](https://pepy.tech/project/capstone)
[![Fuzzit Status](https://app.fuzzit.dev/badge?org_id=ANOh0D48gSLBxNZcDQMI&branch=master)](https://app.fuzzit.dev/admin/ANOh0D48gSLBxNZcDQMI/dashboard)<br/>
[![oss-fuzz Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/capstone.svg)](https://bugs.chromium.org/p/oss-fuzz/issues/list?sort=-opened&can=1&q=proj:capstone)

Capstone is a disassembly framework with the target of becoming the ultimate
disasm engine for binary analysis and reversing in the security community.

Created by Nguyen Anh Quynh, then developed and maintained by a small community,
Capstone offers some unparalleled features:

- Support multiple hardware architectures: ARM, ARM64 (ARMv8), BPF, Ethereum VM,
  M68K, M680X, Mips, MOS65XX, PPC, RISC-V(rv32G/rv64G), SH, Sparc, SystemZ,
  TMS320C64X, Webassembly, XCore and X86 (16, 32, 64).

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

Further information is available at http://www.capstone-engine.org


Compile
-------

See COMPILE.TXT file for how to compile and install Capstone.


Documentation
-------------

See docs/README for how to customize & program your own tools with Capstone.


Hack
----

See HACK.TXT file for the structure of the source code.


Fuzz
----

See suite/fuzz/README.md for more information.


License
-------

This project is released under the BSD license. If you redistribute the binary
or source code of Capstone, please attach file LICENSE.TXT with your products.

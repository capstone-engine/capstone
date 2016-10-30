To install Capstone, you should run `pip install capstone`.

If you would like to build Capstone with just the source distribution, without
pip, just run `python setup.py install` in the folder with setup.py in it.

In order to use this source distribution, you will need an environment that can
compile C code. On Linux, this is usually easy, but on Windows, this involves
installing Visual Studio and using the "Developer Command Prompt" to perform the
installation. See BUILDING.txt for more information.

If you don't want to build your own copy of Capstone, you can use a precompiled
binary distribution from PyPI. Saying `pip install capstone` should
automatically obtain an appropriate copy for your system. If it does not, please
open an issue at https://github.com/aquynh/capstone and tag @rhelmot - they
will fix this, probably!

--------------------------------------------------------------------------------

Capstone is a disassembly framework with the target of becoming the ultimate
disasm engine for binary analysis and reversing in the security community.

Created by Nguyen Anh Quynh, then developed and maintained by a small community,
Capstone offers some unparalleled features:

- Support multiple hardware architectures: ARM, ARM64 (ARMv8), Mips, PPC, Sparc,
  SystemZ, XCore and X86 (including X86_64).

- Having clean/simple/lightweight/intuitive architecture-neutral API.

- Provide details on disassembled instruction (called “decomposer” by others).

- Provide semantics of the disassembled instruction, such as list of implicit
  registers read & written.

- Implemented in pure C language, with lightweight wrappers for C++, C#, Go,
  Java, NodeJS, Ocaml, Python, Ruby & Vala ready (available in main code,
  or provided externally by the community).

- Native support for all popular platforms: Windows, Mac OSX, iOS, Android,
  Linux, *BSD, Solaris, etc.

- Thread-safe by design.

- Special support for embedding into firmware or OS kernel.

- High performance & suitable for malware analysis (capable of handling various
  X86 malware tricks).

- Distributed under the open source BSD license.

Further information is available at http://www.capstone-engine.org


[License]

This project is released under the BSD license. If you redistribute the binary
or source code of Capstone, please attach file LICENSE.TXT with your products.

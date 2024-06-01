## Why the Auto-Sync framework?

Capstone provides a simple API to leverage the LLVM disassemblers, without
having the big footprint of LLVM itself.

It does this by using a stripped down copy of LLVM disassemblers (one for each architecture)
and provides a uniform API to them.

The actual disassembly task (bytes to asm-text and decoded operands) is completely done by
the LLVM code.
Capstone takes the disassembled instructions, adds details to them (operand read/write info etc.)
and organizes them to a uniform structure (`cs_insn`, `cs_detail` etc.).
These objects are then accessible from the API.

Capstone is in C and LLVM is in C++. So to use the disassembler modules of LLVM,
Capstone effectively translates LLVM source files from C++ to C, without changing the semantics.
One could also call it a "disassembler port".

Capstone supports multiple architectures. So whenever LLVM
has a new release and adds more instructions, Capstone needs to update its modules as well.

In the past, the update procedure was done by hand and with some Python scripts.
But the task was tedious and error-prone.

To ease the complicated update procedure, Auto-Sync comes in.

<hr>

## How LLVM disassemblers work

Because effectively use the LLVM disassembler logic, one must understand how they operate.

Each architecture is defined in a so-called `.td` file, that is, a "Target Description" file.
Those files are a declarative description of an architecture.
They are written in a Domain-Specific Language called [TableGen](https://llvm.org/docs/TableGen/).
They contain instructions, registers, processor features, which instructions operands read and write and more information.

These files are consumed by "TableGen Backends". They parse and process them to generate C++ code.
The generated code is for example: enums, decoding algorithms (for instructions and operands) or
lookup tables for register names or alias.

Additionally, LLVM has handwritten files. They use the generated code to build the actual instruction classes
and handle architecture specific edge cases.

Capstone uses both of those files. The generated ones as well as the handwritten ones.

## Overview of updating steps

An Auto-Sync update has multiple steps:

**(1)** Changes in the auto-generated C++ files are handled completely automatically,
We have a LLVM fork with patched TableGen-backends, so they emit C code.

**(2)** Changes in LLVM's handwritten sources are handled semi-automatically.
For each source file, we search C++ syntax and replace it with the equivalent C syntax.
For this task we have the CppTranslator.

The end result is of course not perfectly valid C code.
It is merely an intermediate file, which still has some C++ syntax in it.

Because this leftover syntax was likely already fixed in the equivalent C file currently in Capstone,
we have a last step.
The translated file is diffed with the corresponding old file in Capstone.

The `Differ` tool parses both files into an abstract syntax tree.
From this AST it picks nodes with the same name and diffs them.
The diff is given to the user, and they can decide which one to accept.

All choices are also recorded and automatically applied next time.

**Example**

> Suppose there is a file `ArchDisassembler.cpp` in LLVM.
> Capstone has the C equivalent `ArchDisassembler.c`.
> 
> Now LLVM has a new release, and there were several additions in `ArchDisassembler.cpp`.
> 
> Auto-Sync will pass `ArchDisassembler.cpp` to the CppTranslator, which replaces most C++ syntax.
> The result is an intermediate file `transl_ArchDisassembler.cpp`.
> 
> The result is close to what we want (C code), but still contains invalid syntax.
> Most of this syntax errors were fixed before. They must be, because the C file `ArchDisassemble.c`
> is working fine.
> 
> So the intermediate file `transl_ArchDisassebmler.cpp` is compared to the old `ArchDisassemble.c.
> The Differ patches both files to an AST and automatically patches all nodes it can.
> 
> Effectively automate most of the boring, mechanical work involved in fixing-up `transl_ArchDisassebmler.cpp`.
> If something new came up, it asks the user for a decission.
> 
> The result is saved to `ArchDisassembler.c`, which is now up-to-date with the newest LLVM release.
> 
> In practice this file will still contain syntax errors. But not many, so they can easily be resolved.

**(3)** After (1) and (2), some changes in Capstone-only files follow.
This step is manual work.

<!--
Copyright © 2022 Rot127 <unisono@quyllur.org>
SPDX-License-Identifier: BSD-3
-->

# Architecture of the Auto-Sync framework

This document is split into four parts.

1. An overview of the update process and which subcomponents of `auto-sync` do what.
2. The instructions how to update an architecture which already supports `auto-sync`.
3. Instructions how to refactor an architecture to use `auto-sync`.
4. Notes about how to add a new architecture to Capstone with `auto-sync`.

Please read the section about capstone module design in
[ARCHITECTURE.md](https://github.com/capstone-engine/capstone/blob/next/docs/ARCHITECTURE.md) before proceeding.
The architectural understanding is important for the following.

## Update procedure

As already described in the `ARCHITECTURE` document, Capstone uses translated
and generated source code from LLVM.

Because LLVM is written in C++ and Capstone in C the update process is
internally complicated but almost completely automated.

`auto-sync` categorizes source files of a module into three groups. Each group is updated differently.

| File type                         | Update method | Edits by hand |
|-----------------------------------|----------------------|------------------------|
| Generated files | Generated by patched LLVM backends | Never/Not allowed |
| Translated LLVM C++ files         | `CppTranslater` and `Differ` | Only changes which are too complicated for automation. |
| Capstone files                    | By hand | all |

Let's look at the update procedure for each group in detail.

**Note**: The only exception to touch generated files is via git patches. This is the last resort
if something is broken in LLVM, and we cannot generate correct files.

**Generated files**

Generated files always have the file extension `.inc`.

There are generated files for the LLVM code and for Capstone. They can be distinguished by their names:

- For Capstone: `<ARCH>GenCS<NAME>.inc`.
- For LLVM code: `<ARCH>Gen<NAME>.inc`.

The files are generated by refactored [LLVM TableGen emitter backends](https://github.com/capstone-engine/llvm-capstone/tree/dev/llvm/utils/TableGen).

The procedure looks roughly like this:

```
                                                                   ┌──────────┐
    1               2                 3                4           │CS .inc   │
┌───────┐     ┌───────────┐     ┌───────────┐     ┌──────────┐  ┌─►│files     │
│ .td   │     │           │     │           │     │ Code-    │  │  └──────────┘
│ files ├────►│ TableGen  ├────►│  CodeGen  ├────►│ Emitter  ├──┤
└───────┘     └──────┬────┘     └───────────┘     └──────────┘  │  ┌──────────┐
                     │                                 ▲        └─►│LLVM .inc │
                     └─────────────────────────────────┘           │files     │
                                                                   └──────────┘
```


1. LLVM architectures are defined in `.td` files. They describe instructions, operands,
features and other properties of an architecture.

2. [LLVM TableGen](https://llvm.org/docs/TableGen/index.html) parses these files
and converts them to an internal representation.

3. In the second step a TableGen component called [CodeGen](https://llvm.org/docs/CodeGenerator.html)
abstracts the these properties even further.
The result is a representation which is _not_ specific to any architecture
(e.g. the `CodeGenInstruction` class can represent a machine instruction of any architecture).

4. The `Code-Emitter` uses the abstract representation of the architecture (provided from `CodeGen`) to
generated state machines for instruction decoding.
Architecture specific information (think of register names, operand properties etc.)
is taken from `TableGen's` internal representation.

The result is emitted to `.inc` files. Those are included in the translated C++ files or Capstone code where necessary.

**Translation of LLVM C++ files**

We use two tools to translate C++ to C files.

First the `CppTranslator` and afterward the `Differ`.

The `CppTranslator` parses the C++ files and patches C++ syntax
with its equivalent C syntax.

_Note_: For details about this checkout `suite/auto-sync/CppTranslator/README.md`.

Because the result of the `CppTranslator` is not perfect,
we still have many syntax problems left.

Those need to be fixed partially by hand.

**Differ**

In order to ease this process we run the `Differ` after the `CppTranslator`.

The `Differ` compares our two versions of C files we have now.
One of them are the C files currently used by the architecture module.
On the other hand we have the translated C files. Those are still faulty and need to be fixed.

Most fixes are syntactical problems. Those were almost always resolved before, during the last update.
The `Differ` helps you to compare the files and let you select which version to accept.

Sometimes (not very often though), the newly translated C files contain important changes.
Most often though, the old files are already correct.

The `Differ` parses both files into an abstract syntax tree and compares certain nodes with the same name
(mostly functions).

The user can choose if she accepts the version from the translated file or the old file.
This decision is saved for every node.
If there exists a saved decision for two nodes, and the nodes did not change since the last time,
it applies the previous decision automatically again.

The `Differ` is far from perfect. It only helps to automatically apply "known to be good" fixes
and gives the user a better interface to solve the other problems.
But there will still be syntax errors left afterward. These must be fixed by hand.
# V6 Release

With the `v6` release we added a new update mechanism called `auto-sync`.
This is a huge step for Capstone, because it allows for easy module updates, easier addition of new architectures, easy features addition and guarantees less faulty disassembly.

For `v6` we _updated_ the following architectures: `ARM`, `AArch64` and `PPC`.

These updates are significant! While in `v5` the most up-to-date module was based on `LLVM 7`,
the refactored modules will be based on `LLVM 17`!

As you can see, `auto-sync` solves the long existing problem that Capstone architecture modules were very hard to update.
For [`auto-sync`-enabled modules](https://github.com/capstone-engine/capstone/issues/2015) this is no longer the case.

To achieve it we refactored some LLVM backends, so they emit directly the code we use in Capstone.
Additionally, we implemented many scripts, which automate a great number of manual steps during the update.

Because most of the update steps are automated now the architecture modules must fit this update mechanism.
Which means they move closer to the original LLVM code.
On the flip site it brings many breaking changes.

You can find a list below with a description, justification and a possible way to revert this change locally (if there is any reasonable way).

With all the trouble this might bring for you, please keep in mind that this will only occur once for each architecture (when it gets refactored for `auto-sync`).
In the long term this will guarantee more stability, more correctness, more features and on top of this makes Capstone directly comparable to `llvm-obdjdump`.

We already added a handful of new features of which you can find a list below.

If you want to check the current state of this endeavor checkout https://github.com/capstone-engine/capstone/issues/2015.
Moreover, if you decide to update an existing architecture module (apart from already updated ones), it would be very much welcome!
If you want to join the effort, please drop us a note in the issue comments, so we can assist.

Almost all the new features in this release were sponsored and implemented by the [Rizin](https://rizin.re/) team.
The `auto-sync` updater, the additional updates of ARM, AArch64 and PPC, as well as the newly added Tricore and Alpha support, wouldn't have had happened without them.

With all that said, we hope you enjoy the new release!

## New features

**LoongArch**

- Architecture support was added (based on LLVM-18).

**HPPA**

- Architecture support was added.

**Alpha**

- Architecture support was added (based on LLVM-3)
- System operands are provided with way more detail in separated operand.

**AArch64**

- Updated to LLVM-18
- Adding new instructions of SME, SVE2 extensions. With it the `sme` and `pred` operands are added.
- System operands are provided with way more detail in separated operand.

**PPC**

- Updated to LLVM-16
- The instruction encoding formats are added for PPC. They are accessible via `cs_ppc->format`.
They do follow loosely the ISA formats of instructions but not quite. Unfortunately,
LLV doesn't group the instruction formats perfectly aligned with the ISA.
Nonetheless, we hope this additional information is useful to you.
- Branching information in `cs_ppc->bc` is way more detailed now.
- The Paired Single extension was added.

**SystemZ**

- Updated to LLVM-18
- Operands have now read/write access information
- Memory operands have now the address mode specified
- Immediate oprands have a new `imm_width` field. storing the bit width if known.
- CPU features can be enabled or disabled by SystemZ architecture (arch8-arch14).

**Mips**

- Updated to LLVM-18
- Support added for: `microMips32r3`, `microMips32r6`, `Mips16`, `Mips I ISA`, `Mips II ISA`, `Mips32 r2 ISA`, `Mips32 r3 ISA`, `Mips32 r5 ISA`, `Mips32 r6 ISA`, `Mips III ISA`, `Mips IV ISA`, `Mips V ISA`, `Mips64 r2 ISA`, `Mips64 r3 ISA`, `Mips64 r5 ISA`, `Mips64 r6 ISA`, `Octeon (cnMIPS)`, `Octeon+ (cnMIPS+)`, `NanoMips`
- Support for different register naming style (`CS_OPT_SYNTAX_NO_DOLLAR`, `CS_OPT_SYNTAX_NOREGNAME`)

**RISCV**

- Operands have now read/write access information

**Code quality**

- ASAN: All tests are now run with the address sanitizer enabled. This includes checking for leaks.
- Coverity code scanning workflow added.
- Testing was re-written from scratch. Now allowing fine-grained testing of all details and is more convenient to use by contributors.


## Breaking changes

**All `auto-sync` architectures**

| Keyword | Change | Justification | Possible revert |
|---------|--------|---------------|-----------------|
| Instr. alias | Capstone now clearly separates real instructions and their aliases. Previously many aliases were treated as real instructions. See [Instruction Alias](#instruction-alias) for details. | This became a simple necessity because CS operates with a copy of the LLVMs decoder without any changes. | This change is not revertible. |

**ARM**

| Keyword | Change | Justification | Possible revert |
|---------|--------|---------------|-----------------|
| Post-index | Post-index memory access has the disponent now set in the `MEMORY` operand! No longer as separated `reg`/`imm` operand. | The CS memory operand had a field which was there for disponents. Not having it set, for post-index operands was inconsistent. | Edit `ARM_set_detail_op_mem()` and add an immediate operand instead of setting the disponent. |
| Sign `mem.disp` | `mem.disp` is now always positive and the `subtracted` flag indicates if it should be subtracted. | It was inconsistent before. | Change behavior in `ARM_set_detail_op_mem()` |
| `ARM_CC` | `ARM_CC` → `ARMCC` and value change | They match the same LLVM enum. Better for LLVM compatibility and code generation. | Change it manually. |
| `ARMCC_*` | `ARMCC_EQ == 0` but `ARMCC_INVALID != 0` | They match the LLVM enum. Better for LLVM compatibility and code generation. | Change by hand. |
| System registers | System registers are no longer saved in `cs_arm->reg`, but are separated and have more detail. | System operands follow their own encoding logic. Hence, they should be separated in the details as well. | None |
| System operands | System operands have now the encoding of LLVM (SYSm value mostly) | See note about system registers. | None |
| Instruction enum | Multiple instructions which were only alias were removed from the instruction enum. | Alias are always disassembled as their real instructions and an additional field identifies which alias it is. | None |
| Instruction groups| Instruction groups, which actually were CPU features, were renamed to reflect that. | Names now match the ones in LLVM. Better for code generation. | Replace IDs with macros. |
| CPU features | CPU features get checked more strictly (`MCLASS`, `V8` etc.) | With many new supported extensions, some instruction bytes decode to a different instruction, depending on the enabled features. Hence, it becomes necessary. | None. |
| `writeback` | `writeback` member was moved to detail. | More architectures need a `writeback` flag. This is a simplification. | None. |
| Register alias | Register alias (`r15 = pc` etc.) are not printed if LLVM doesn't do it. Old Capstone register alias can be enabled by `CS_OPT_SYNTAX_CS_REG_ALIAS`. | Mimic LLVM as close as possible. | Enable `CS_OPT_SYNTAX_CS_REG_ALIAS` option. |
| Immediate | Immediate values (`arm_op.imm`) type changed to `int64_t` | Prevent loss of precision in some cases. | None. |
| `mem.lshift` | The `mem.lshift` field was removed. It was not set properly before and just duplicates information in `shift` | Remove faulty and duplicate code. | None. |

**PPC**

| Keyword | Change | Justification | Possible revert |
|---------|--------|---------------|-----------------|
| `PPC_BC` | The branch conditions were completely rewritten and save now all detail known about the bits. | More branch condition details were something missing. | None. |
| Predicates | Predicate enums were renamed due to the changes to the branch conditions. | See `PPC_BC` | None. |
| Instruction alias | Many instruction alias (e.g. `BF`) were removed from the instruction enum (see new alias feature below). | Alias information is provided separately in their own fields. | None. |
| `crx` | `ppc_ops_crx` was removed. | It was never used in the first place. | None. |
| `(RA\|0)` | The `(RA\|0)` cases (see ISA for details) for which `0` is used, the `PPC_REG_ZERO` register is used. The register name of it is `0`. | Mimics LLVM behavior. | None. |

**AArch64**

| Keyword | Change | Justification | Possible revert |
|---------|--------|---------------|-----------------|
| Post-index | Post-index memory access has the disponent now set int the `MEMORY` operand! No longer as separated `reg`/`imm` operand. | See post-index explanation for ARM. | See ARM. |
| `SME` operands | `SME` operands contain more detail now and member names are closer to the docs. | New feature. | None. |
| System operands | System Operands are separated into different types now. | System operands follow a special encoding. Some byte sequences match two different operands. Hence, a more detailed concept was necessary. | None. |
| `writeback` | `writeback` member was moved to detail. | See ARM explanation. | See ARM. |
| `arm64_vas` | `arm64_vas` renamed to `AArch64Layout_VectorLayout` | LLVM compatibility. | None. |
| Register alias | Register alias (`x29 = fp` etc.) are not printed if LLVM doesn't do it. Old Capstone register alias can be enabled by `CS_OPT_SYNTAX_CS_REG_ALIAS`. | Mimic LLVM as close as possible. | Enable option. |
| `AArch64CC_*` | `AArch64CC_EQ == 0` but `AArch64CC_INVALID != 0` | They match the LLVM enum. Better for LLVM compatibility and code generation. | Change by hand. |

**Mips**

| Keyword | Change | Justification | Possible revert |
|---------|--------|---------------|-----------------|
| `CS_OPT_SYNTAX_NO_DOLLAR` | Adds options which removes the `$` (dollar sign) from the register name. | New Feature | Enable option. |
| `CS_OPT_SYNTAX_NOREGNAME` | Implements the options to output raw register numbers (only the standard GPR are numeric). | Was not implemented | Enable option. |
| `cs_mips_op.uimm` | Access for the unsigned immediate value of the IMM operand. | Was missing | None. |
| `cs_mips_op.is_unsigned` | Defines if the IMM operand is signed (when false) or unsigned (when true). | Was missing | None. |
| `cs_mips_op.is_reglist` | Defines if the REG operand is part of a list of registers. | Was missing | None. |
| `cs_mips_op.access` | Defines how is this operand accessed, i.e. READ, WRITE or READ & WRITE. | Was missing | None. |

**SystemZ**

| Keyword | Change | Justification | Possible revert |
|---------|--------|---------------|-----------------|
| `SYSTEMZ_CC_*` | `SYSTEMZ_CC_O = 0` and `SYSTEMZ_CC_INVALID != 0` | They match the same LLVM values. Better for LLVM compatibility and code generation. | Change by hand. |

**Note about AArch64 and SystemZ**

`ARM64` was everywhere renamed to `AArch64`. And `SYSZ` to `SYSTEMZ`. This is a necessity to ensure that the update scripts stay reasonably simple.
Capstone was very inconsistent with the naming before (sometimes `AArch64` sometimes `ARM64`. Sometimes `SYSZ` sometimes `SYSTEMZ`).
Because Capstone uses a huge amount of LLVM code, we renamed everything to `AArch64` and `SystemZ`. This reduces complexity enormously because it follows the naming of LLVM.

Because this would completely break maintaining Capstone `v6` and `pre-v6` in a project, we added compatibility headers:

1. Make `arm64.h` a compatibility header which merely maps every member to the one in the `aarch64.h` header.
2. The `systemz.h` header includes the `SYSZ` to `SYSZTEMZ` mapping if `CAPSTONE_SYSTEMZ_COMPAT_HEADER` is defined.

We will continue to maintain both headers.

_Compatibility header_

If you want to use the compatibility header and stick with the `ARM64`/`SYSZ` naming, you can define `CAPSTONE_AARCH64_COMPAT_HEADER` and `CAPSTONE_SYSTEMZ_COMPAT_HEADER` before including `capstone.h`.

```c
#define CAPSTONE_SYSTEMZ_COMPAT_HEADER
#define CAPSTONE_AARCH64_COMPAT_HEADER
#include <capstone/capstone.h>

// Your code...
```

_Meta programming macros_

The following `sed` commands in a sh script should ease the replacement of `ARM64` with the macros a lot.
These macros are also part of the latest `v4` and `v5` release.

```sh
#!/bin/sh
echo "Replace enum names"

sed -i -E "s/CS_ARCH_ARM64/CS_AARCH64pre(CS_ARCH_)/g" $1
sed -i -E "s/ARM64_INS_(\\w+)/CS_AARCH64(_INS_\\1)/g" $1
sed -i -E "s/ARM64_REG_(\\w+)/CS_AARCH64(_REG_\\1)/g" $1
sed -i -E "s/ARM64_OP_(\\w+)/CS_AARCH64(_OP_\\1)/g" $1
sed -i -E "s/ARM64_EXT_(\\w+)/CS_AARCH64(_EXT_\\1)/g" $1
sed -i -E "s/ARM64_SFT_(\\w+)/CS_AARCH64(_SFT_\\1)/g" $1
sed -i -E "s/ARM64_VAS_(\\w+)/CS_AARCH64_VL_(\\1)/g" $1

sed -i -E "s/ARM64_CC_(\\w+)/CS_AARCH64CC(_\\1)/g" $1

echo "Replace type identifiers"

sed -i -E "s/cs_arm64_op /CS_aarch64_op() /g" $1
sed -i -E "s/arm64_reg /CS_aarch64_reg() /g" $1
sed -i -E "s/arm64_cc /CS_aarch64_cc() /g" $1
sed -i -E "s/cs_arm64 /CS_cs_aarch64() /g" $1
sed -i -E "s/arm64_extender /CS_aarch64_extender() /g" $1
sed -i -E "s/arm64_shifter /CS_aarch64_shifter() /g" $1
sed -i -E "s/arm64_vas /CS_aarch64_vas() /g" $1

echo "Replace detail->arm64"
sed -i -E "s/detail->arm64/detail->CS_aarch64()/g" $1	
```

_Example renaming with `sed`_

Simple renaming from `ARM64` to `AArch64`:

```sh
#!/bin/sh
echo "Replace enum names"

sed -i "s|CS_ARCH_ARM64|CS_ARCH_AARCH64|g" $1
sed -i "s|ARM64_INS_|AArch64_INS_|g" $1
sed -i "s|ARM64_REG_|AArch64_REG_|g" $1
sed -i "s|ARM64_OP_|AArch64_OP_|g" $1
sed -i "s|ARM64_EXT_|AArch64_EXT_|g" $1
sed -i "s|ARM64_SFT_|AArch64_SFT_|g" $1
sed -i "s|ARM64_CC_|AArch64CC_|g" $1

echo "Replace type identifiers"

sed -i "s|arm64_reg|aarch64_reg|g" $1
sed -i "s|arm64_cc |AArch64CC_CondCode |g" $1
sed -i "s|cs_arm64|cs_aarch64|g" $1
sed -i "s|arm64_extender |aarch64_extender |g" $1
sed -i "s|arm64_shifter |aarch64_shifter |g" $1
sed -i "s|arm64_vas |AArch64Layout_VectorLayout |g" $1

echo "Replace detail->arm64"

sed -i "s|detail->arm64|detail->aarch64|g" $1
```

Simple renaming from `SYSZ` to `SYSTEMZ`:

```sh
#!/bin/sh
echo "Replace enum names"

sed -i "s|CS_ARCH_SYSZ|CS_ARCH_SYSTEMZ|g" $1
sed -i "s|SYSZ_INS_|SYSTEMZ_INS_|g" $1
sed -i "s|SYSZ_REG_|SYSTEMZ_REG_|g" $1
sed -i "s|SYSZ_OP_|SYSTEMZ_OP_|g" $1
sed -i "s|SYSZ_CC_|SYSTEMZ_CC_|g" $1

echo "Replace type identifiers"

sed -i "s|sysz_reg|systemz_reg|g" $1
sed -i "s|sysz_cc |systemz_cc |g" $1
sed -i "s|cs_sysz|cs_systemz|g" $1
sed -i "s|sysz_op_type|systemz_op_type|g" $1
sed -i "s|sysz_op_type|systemz_op_type|g" $1
sed -i "s|sysz_op_mem|systemz_op_mem|g" $1
sed -i "s|sysz_op|systemz_op|g" $1

echo "Replace detail->sysz"

sed -i "s|detail->sysz|detail->systemz|g" $1
```

Write it into `rename_arm64.sh` and run it on files with `sh rename_arm64.sh <src-file>`

**Note about AArch64**

in `capstone.h` new mips ISA has been added which can be used by themselves.

```
	CS_MODE_MIPS16 = CS_MODE_16, ///< Generic mips16
	CS_MODE_MIPS32 = CS_MODE_32, ///< Generic mips32
	CS_MODE_MIPS64 = CS_MODE_64, ///< Generic mips64
	CS_MODE_MICRO = 1 << 4, ///< microMips
	CS_MODE_MIPS1 = 1 << 5, ///< Mips I ISA Support
	CS_MODE_MIPS2 = 1 << 6, ///< Mips II ISA Support
	CS_MODE_MIPS32R2 = 1 << 7, ///< Mips32r2 ISA Support
	CS_MODE_MIPS32R3 = 1 << 8, ///< Mips32r3 ISA Support
	CS_MODE_MIPS32R5 = 1 << 9, ///< Mips32r5 ISA Support
	CS_MODE_MIPS32R6 = 1 << 10, ///< Mips32r6 ISA Support
	CS_MODE_MIPS3 = 1 << 11, ///< MIPS III ISA Support
	CS_MODE_MIPS4 = 1 << 12, ///< MIPS IV ISA Support
	CS_MODE_MIPS5 = 1 << 13, ///< MIPS V ISA Support
	CS_MODE_MIPS64R2 = 1 << 14, ///< Mips64r2 ISA Support
	CS_MODE_MIPS64R3 = 1 << 15, ///< Mips64r3 ISA Support
	CS_MODE_MIPS64R5 = 1 << 16, ///< Mips64r5 ISA Support
	CS_MODE_MIPS64R6 = 1 << 17, ///< Mips64r6 ISA Support
	CS_MODE_OCTEON = 1 << 18, ///< Octeon cnMIPS Support
	CS_MODE_OCTEONP = 1 << 19, ///< Octeon+ cnMIPS Support
	CS_MODE_NANOMIPS = 1 << 20, ///< Generic nanomips 
	CS_MODE_NMS1 = ((1 << 21) | CS_MODE_NANOMIPS), ///< nanoMips NMS1
	CS_MODE_I7200 = ((1 << 22) | CS_MODE_NANOMIPS), ///< nanoMips I7200
	CS_MODE_MICRO32R3 = (CS_MODE_MICRO | CS_MODE_MIPS32R3), ///< microMips32r3
	CS_MODE_MICRO32R6 = (CS_MODE_MICRO | CS_MODE_MIPS32R6), ///< microMips32r6
```

It is also possible to disable floating point support by adding `CS_MODE_MIPS_NOFLOAT`.

**`CS_MODE_MIPS_PTR64` is now required to decode 64-bit pointers**, like jumps and calls (for example: `jal $t0`).

## New features

These features are only supported by `auto-sync`-enabled architectures.

**More code quality checks**

- `clang-tidy` is now run on all files changed by a PR.
- ASAN: All tests are now run with the address sanitizer enabled. This includes checking for leaks.

**Instruction formats for PPC**

The instruction encoding formats are added for PPC. They are accessible via `cs_ppc->format`.
They do follow loosely the ISA formats of instructions but not quite. Unfortunately,
LLV doesn't group the instruction formats perfectly aligned with the ISA.
Nonetheless, we hope this additional information is useful to you.

### Instruction Alias

Instruction alias are now properly separated from real instructions.

The `cs_insn->is_alias` flag is set, if the decoded instruction is an alias.

The real instruction `id` is still set in `cs_insn->id`.
The alias `id` is set in `cs_insn->alias_id`.

You can use as `cs_insn_name()` to retrieve the real and the alias name.

Additionally, you can now choose between the alias details and the real details.

If you always want the real instruction detail decoded (also for alias instructions),
you can enable the option with
```
cs_option(handle, CS_OPT_DETAIL, CS_OPT_DETAIL_REAL | CS_OPT_ON);
```

For the `cstool` you can enable it with the `-r` flag.

Without `-r` you get the `alias` operand set, _if_ the instruction is an alias.
This is the default behavior:

```
./cstool -d ppc32be 7a8a2000
 0  7a 8a 20 00  	rotldi	r10, r20, 4
	ID: 867 (rldicl)
	Is alias: 1828 (rotldi) with ALIAS operand set
	op_count: 3
		operands[0].type: REG = r10
		operands[0].access: WRITE
		operands[1].type: REG = r20
		operands[1].access: READ
		operands[2].type: IMM = 0x4
		operands[2].access: READ
```

If `-r` is set, you got the real operands. Even if the decoded instruction is an alias:

```
./cstool -d ppc32be 7a8a2000
 0  7a 8a 20 00  	rotldi	r10, r20, 4
	ID: 867 (rldicl)
	Is alias: 1828 (rotldi) with REAL operand set
	op_count: 4
		operands[0].type: REG = r10
		operands[0].access: WRITE
		operands[1].type: REG = r20
		operands[1].access: READ
		operands[2].type: IMM = 0x4
		operands[2].access: READ
		operands[3].type: IMM = 0x0
		operands[3].access: READ

```

**Note about alias as part of real instruction enum.**

LLVM defines some alias instructions as real instructions.
This is why you will still find alias instructions being listed in the instruction `enum`.
This happens due to some LLVM specific edge cases.

Nonetheless, an alias should never be **decoded** as real instruction.

If you find an alias which is decoded as a real instruction, please let us know.
Such an instruction is ill-defined in LLVM and should be fixed upstream.

### Refactoring of cstool

`cstool` has been refactored to simplify its usage; before you needed to add extra options in the C code to enable features and recompile, but now you can easily decode instructions with different syntaxes or options, by appending after the arch one of the followings values:

```
+att         ATT syntax (only: x86)
+intel       Intel syntax (only: x86)
+masm        Intel MASM syntax (only: x86)
+noregname   Number only registers (only: Arm64, ARM, LoongArch, Mips, PowerPC)
+moto        Use $ as hex prefix (only: MOS65XX)
+regalias    Use register aliases, like r9 > sb (only: ARM, Arm64)
+percentage  Adds % in front of the registers (only: PowerPC)
+nodollar    Removes $ in front of the registers (only: Mips)
+nofloat     Disables floating point support (only: Mips)
+ptr64       Enables 64-bit pointers support (only: Mips)
```

For example:
```
$ cstool -s ppc32+percentage 0c100097
 0  0c 10 00 97  stwu   %r24, 0x100c(0)
$ cstool -s ppc32 0c100097
 0  0c 10 00 97  stwu   r24, 0x100c(0)
$ cstool -s x32+att 0c1097
 0  0c 10        orb    $0x10, %al
 2  97           xchgl  %eax, %edi
$ cstool -s x32+intel 0c1097
 0  0c 10        or     al, 0x10
 2  97           xchg   edi, eax
$ cstool -s x32+masm 0c1097
 0  0c 10        or     al, 10h
 2  97           xchg   edi, eax
$ cstool -s arm+regalias 0c100097000000008fa2000034213456
 0  0c 10 00 97  strls    r1, [r0, -ip]
 4  00 00 00 00  andeq    r0, r0, r0
 8  8f a2 00 00  andeq    sl, r0, pc, lsl #5
10  34 21 34 56  shasxpl  r2, r4, r4
$ cstool -s arm 0c100097000000008fa2000034213456
 0  0c 10 00 97  strls    r1, [r0, -r12]
 4  00 00 00 00  andeq    r0, r0, r0
 8  8f a2 00 00  andeq    r10, r0, pc, lsl #5
10  34 21 34 56  shasxpl  r2, r4, r4
```

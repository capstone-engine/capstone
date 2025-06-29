# V6 Release

With the `v6` release we added a new update mechanism called `Auto-Sync`.
This is a huge step for Capstone, because it allows for easy module updates, easier addition of new architectures, easy features addition and guarantees less faulty disassembly.

This release adds a huge amount of new architectures, extensions, bug fixes and quality of life improvements.

## Contributors

Almost all the work was sponsored by [RizinOrg](https://rizin.re/). This release would have simply not happened without them.

The developers with the biggest contributions were (alphabetically):
- `TriCore` - @billow (Sponsored)
- `LoongArch` - @jiegec and @FurryAcetylCoA
- `Alpha`, `HPPA` - @R33v0LT (Sponsored)
- `AArch64`, `ARM`, `Auto-Sync`, `PPC`, `SystemZ`, modernized testing - @Rot127 (Sponsored)
- `Mips`, `NanoMips` - @wargio

There are also multiple smaller additions

- Reviewing all PRs = @kabeor
- Architecture module registration - @oleavr
- Building of thin binaries for Apple - @rickmark
- Python packaging and testing - @twizmwazin, @peace-maker
- `RISCV` operand access info - @wxrdnx

And of course there were many more improvements done by other contributors, which add to the release just as the ones above.
For a full list of all the developers, please see the release page.

With all that said, we hope you enjoy the new release!

## Overview

For `v6` we _updated_ the following architectures: `ARM`, `AArch64`, `Mips` (adding `NanoMips`!), `SystemZ`, `PPC`.
And added support for several more: `TriCore` (already in `v5`), `Alpha`, `HPPA`, `LoongArch`.

These updates are significant! While in `v5` the most up-to-date module was based on `LLVM 7`,
the refactored modules are based on `LLVM 16` (`ARM`, `PPC`) and `LLVM 18` (the others)!

As you can see, `Auto-Sync` solves the long existing problem that Capstone being hard to update.
For [`Auto-Sync`-enabled modules](https://github.com/capstone-engine/capstone/issues/2015) this is no longer the case.
The update process is no pretty much standardized and, while not yet 100% reproducible, creates consistently better maintainable and precise results.

To achieve it, we refactored some LLVM backends, so they emit directly the code we use in Capstone.
Additionally, we implemented many scripts, which automate a great number of manual steps during the update.

Because most of the update steps are automated now, the architecture modules must fit this update mechanism.
Which means they move closer to the original LLVM code.
On the flip site it brings many breaking changes.

You can find a list below with descriptions and justification.

With all the trouble this might bring for you, please keep in mind that this will only occur once for each architecture (when it gets refactored for `Auto-Sync`).
In the long term this will guarantee more stability, more correctness, more features and on top of this makes Capstone directly comparable to `llvm-obdjdump`.

If you want to check the current state of this endeavor read the [main Auto-Sync issue](https://github.com/capstone-engine/capstone/issues/2015).

Moreover, if you decide to update an existing architecture module (apart from already updated ones), it would be very much welcome!
If you want to join the effort, please drop us a note in the issue comments, so we can assist.

## Why an Alpha?

Because the changes are so vast and we still need more feedback from the community.

We had many early adopters who helped enormously to find bugs and report issues up until now.
But there are still features missing, modules not refactored, the test coverage below 100% in the relevant paths and `Auto-Sync` not completely done yet.
With all the new features we want to have more feedback from users and eyes on the code before calling it "complete".

Although, it is an Alpha, it doesn't mean it is not well tested!
The testing compared to any other release has increased a lot. Both in quantity, coverage and code quality checks.

The Alpha release now allows projects to pin-point their build to a specific commit and use the new features, while allowing us to add missing features
still on the list for `v6` Gold.

Some of them are: update and add more architectures (including x86), rework DIET build, improve Auto-Sync with reproducible file generation and quality of life features and more.

So when the final `v6` release happens, the `Auto-Sync` transformation of Capstone is completely done.
For `v7` we can then focus on other big features, like [SAIL](https://github.com/rems-project/sail) based disassembler modules or a new API to support VLIW architectures like Hexagon or E2K.

## New features

**LLVM disassembler based modules**

- The `cs_insn.illegal` flag was added. If it is set the instruction is decoded correctly but is considered illegal.
  This happens for instructions which use invalid operands or are in an illegal context.

**Auto-Sync-enabled modules**

**More code quality checks**

- `clang-tidy` is now run on all files changed by a PR.
- ASAN: All tests are now run with the address sanitizer enabled. This includes checking for leaks.
- Many more asserts were added. They are only enabled for debug builds (with a few exceptions).
  Enabling the option `CAPSTONE_ASSERTION_WARNINGS` for a release build will print warnings but won't abort the program.

**Instruction formats for PPC, SystemZ, LoongArch**

The instruction encoding formats are added for PPC. They are accessible via `cs_ppc->format`
(and the equivalently for SystemZ, LoongArch).
They do follow loosely the ISA formats of instructions but not quite. Unfortunately,
LLVM doesn't group the instruction formats perfectly aligned with the ISA.
Nonetheless, we hope this additional information is useful to you.

**LoongArch**

- Architecture support was added (based on LLVM-18).

**HPPA**

- Architecture support was added.

**Alpha**

- Architecture support was added (based on LLVM-3)

**AArch64**

- Updated to LLVM-18
- Adding new instructions of SME, SVE2 extensions. With it the new `sme` and `pred` operands are added.
- System operands are provided with way more detail in separated operand.
	- The `EXACTFPIMM` operand also sets the `fp` field.

**PPC**

- Updated to LLVM-16
- The instruction encoding formats are added for PPC. They are accessible via `cs_ppc->format`.
They do follow loosely the ISA formats of instructions but not quite. Unfortunately,
LLVM doesn't group the instruction formats perfectly aligned with the ISA.
Nonetheless, we hope this additional information is useful to you.
- Branching information in `cs_ppc->bc` is way more detailed now.
- The Paired Single extension was added.

**SystemZ**

- Updated to LLVM-18
- Operands have now read/write access information
- Memory operands have now the address mode specified
- Immediate operands have a new `imm_width` field. Storing the bit width if known.
- CPU features can be enabled or disabled, grouped by architecture (arch8-arch14).

**Mips**

- Updated to LLVM-18
- Support added for: `NanoMips`, `microMips32r3`, `microMips32r6`, `Mips16`, `Mips I ISA`, `Mips II ISA`, `Mips32 r2 ISA`, `Mips32 r3 ISA`, `Mips32 r5 ISA`, `Mips32 r6 ISA`, `Mips III ISA`, `Mips IV ISA`, `Mips V ISA`, `Mips64 r2 ISA`, `Mips64 r3 ISA`, `Mips64 r5 ISA`, `Mips64 r6 ISA`, `Octeon (cnMIPS)`, `Octeon+ (cnMIPS+)`
- Support for different register naming style (`CS_OPT_SYNTAX_NO_DOLLAR`, `CS_OPT_SYNTAX_NOREGNAME`)
- In `capstone.h` new MIPS ISA has been added which can be used by themselves.
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

- **`CS_MODE_MIPS_PTR64` is now required to decode 64-bit pointers**, like jumps and calls (for example: `jal $t0`).

**Sparc**

- Updated to LLVM-18
- V9 must be enabled explicitly now.
- Added Little Endian support. Big endian mode must be enabled explicitly now.
- Alias support added. It is possible to choose between real and alias details.
- ASI operands are now distinct from immediates.
- Memory barriers are now distinct from immediates.
- Operands have now read/write access information.
- The instruction format was added as detail.
- Instruction groups and modes changed to LLVM defined ones. Most notably: `64bit -> HasV9`.
- The condition codes are now separate between normal, fp, cp or register conditional flags.
  The flags can be normalized by unsetting the `SPARC_CC_..._BEGIN` bits.
- The CC fields and instruction uses is encoded now consistently in `cs_sparc::cc_field`.
  This might lead to confusions for instructions which list the cc field explicitly in their
  asm text. For example the instruction `fcmpeq	%fcc2, %f0, %f4` has 2 not 3 operands.
  Operands are the two registers `f0` and `f4` and the `cc_field` is set to `SPARC_CC_FIELD_FCC0`.

**RISCV**

- Operands have now read/write access information

**Xtensa**

- Architecture support was added (based on LLVM-18).
- Support for `LITBASE`. Set the `LITBASE` with `cs_option(handle, CS_OPT_LITBASE, litbase_value)`.

**BPF**

- Added support for eBPF `ATOMIC` class instructions (using Linux mnemonics, not GNU ones. E.g. `acmpxchg64` instead of `axchg`)
- Added support for eBPF signed `ALU` class instructions (`sdiv`, `smod`, `movs` variants. E.g. `smod r9, 0xc9d1d20b`)
- Added support for eBPF `JMP32` class instructions (E.g. `jslt32 r7, -0xa46e0bd, -0x33f1`)
- Updated the syntax for eBPF legacy packet instructions (similar to LLVM mnemonics, not GNU ones (E.g. `ldabsw [skb-0x8]`). `skb` is the socket buffer.
- Corrected the signedness interpretation of `immidiate` and `offset` operands

**UX**

- Instruction alias (see below).
- `cstool`: Architecture specific options can now be enabled with `cstool <arch>+<option>`.

**Developer improvements**

- Testing was re-written from scratch. Now allowing fine-grained testing of all details and is more convenient to use by contributors.
- Architecture modules from a static library, can be initialized on demand to decrease footprint (see: `cmake` option `CAPSTONE_USE_ARCH_REGISTRATION`).
- New `cmake` option to choose between fat and thin binary for Apple.

**Code quality**

- ASAN: All tests are now run with the address sanitizer enabled. This includes checking for leaks.
- Coverity code scanning workflow added and all reported bugs fixed.
- `clang-tidy` workflow added. All reported defects were fixed.

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

**Notes about alias as part of real instruction enum.**

LLVM defines some alias instructions as real instructions.
This is why you will still find alias instructions being listed in the "real" instruction enumeration.
This happens due to some LLVM specific edge cases.

Nonetheless, an alias should never be **decoded** as real instruction.

If you find an alias which is decoded as a real instruction, please let us know.
Such an instruction is ill-defined in LLVM and should be fixed upstream.

**No or partial support for alias**

- SystemZ: Not enabled by default in LLVM. Will be added in Beta.
- LoongArch: Implemented but not handled yet. Will be added in Beta.

- TriCore: No support in LLVM.
- Alpha: No support in LLVM.

- HPPA: Not a LLVM architecture. Alias are not supported.

## Breaking changes

**General**

| Keyword | Change | Justification |
|---------|--------|---------------|
| Make build | Building Capstone with `make` is deprecated now and is no longer supported. Build files will be removed in the next release. | It adds too much maintenance and `make` is not convenient to manage such a modular, complex project for multiple platforms. |
| Bindings | The Java and Ocaml bindings were abandoned for a while now. So in the Alpha release they are not yet up-to-date. | Not enough maintainers. |
| Python | Python 2 and <3.8 are dropped in the `v5` and `next` branch. | Python 2 and <3.8 are EOL. |

**All `Auto-Sync` architectures**

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
| Register alias | Register alias (`r15 = pc` etc.) are not printed if LLVM doesn't do it. Old Capstone register alias can be enabled by `CS_OPT_SYNTAX_CS_REG_ALIAS`. WARNING: This option uses a naive search and replace strategy to patch the register names in the asm text. And hence adds significant runtime at scale, if enabled. | Mimic LLVM as close as possible. | Enable `CS_OPT_SYNTAX_CS_REG_ALIAS` option. |
| Immediate | Immediate values (`arm_op.imm`) type changed to `int64_t` | Prevent loss of precision in some cases. | None. |
| `mem.lshift` | The `mem.lshift` field was removed. It was not set properly before and just duplicates information in `shift` | Remove faulty and duplicate code. | None. |
| Instr. alias | Capstone now clearly separates real instructions and their aliases. Previously many aliases were treated as real instructions. See above for details. | This became a simple necessity because CS operates with a copy of the LLVMs decoder without changes to the decoder logic. |
| Operand access type | Previously, operand access type is stored in the `uint8_t access;` field within operand details. However its possible values are stored in `enum cs_ac_type`. Now, the field has `enum cs_ac_type` type instead. | The user can find the connection between the field and the enum directly. | None |

**ARM**

| Keyword | Change | Justification |
|---------|--------|---------------|
| `ARMCC_*` | `ARMCC_EQ == 0` but `ARMCC_INVALID != 0` | They match the LLVM enum. Better for LLVM compatibility and code generation. Check the compatibility option below. |
| `ARM_CC` | `ARM_CC` → `ARMCC` and value change | They match the same LLVM enum. Better for LLVM compatibility and code generation. |
| Post-index | Post-index memory access has the disponent now set in the `MEMORY` operand! No longer as separated `reg`/`imm` operand. | The CS memory operand had a field which was there for disponents. Not having it set, for post-index operands was inconsistent. |
| Sign `mem.disp` | `mem.disp` is now always positive and the `subtracted` flag indicates if it should be subtracted. | It was inconsistent before. |
| System registers | System registers are no longer saved in `cs_arm->reg`, but are separated and have more detail. | System operands follow their own encoding logic. Hence, they should be separated in the details as well. |
| System operands | System operands have now the encoding of LLVM (SYSm value mostly) | See note about system registers. |
| Instruction enum | Multiple instructions which were only alias were removed from the instruction enum. | Alias are always disassembled as their real instructions and an additional field identifies which alias it is. |
| Instruction groups| Instruction groups, which actually were CPU features, were renamed to reflect that. | Names now match the ones in LLVM. Better for code generation. |
| CPU features | CPU features get checked more strictly (`MCLASS`, `V8` etc.) | With many new supported extensions, some instruction bytes decode to a different instruction, depending on the enabled features. Hence, it becomes necessary. |
| `writeback` | `writeback` member was moved to detail. | More architectures need a `writeback` flag. This is a simplification. |
| Register alias | Register alias (`r15 = pc` etc.) are not printed if LLVM doesn't do it. Old Capstone register alias can be enabled by `CS_OPT_SYNTAX_CS_REG_ALIAS`. WARNING: This option uses a naive search and replace strategy to patch the register names in the asm text. And hence adds significant runtime at scale, if enabled. | Mimic LLVM as close as possible. |
| Immediate | Immediate values (`arm_op.imm`) type changed to `int64_t` | Prevent loss of precision in some cases. |

**AArch64 (formerly ARM64)**

| Keyword | Change | Justification |
|---------|--------|---------------|
| ARM64 -> AArch64 | ARM64 was everywhere renamed to AArch64 to match the LLVM naming. | See below. |
| Post-index | Post-index memory access has the disponent now set int the `MEMORY` operand! No longer as separated `reg`/`imm` operand. | See post-index explanation for ARM. |
| `SME` operands | `SME` operands contain more detail now and member names are closer to the ISA terminology. | New SVE2, SME extensions required more detail. |
| System operands | System Operands are separated into different types now. | System operands follow a special encoding. Some byte sequences match two different operands. Hence, a more detailed concept was necessary. |
| `writeback` | `writeback` member was moved to detail. | See ARM explanation. |
| `arm64_vas` | `arm64_vas` renamed to `AArch64Layout_VectorLayout` | LLVM compatibility. |
| Register alias | Register alias (`x29 = fp` etc.) are not printed if LLVM doesn't do it. Old Capstone register alias can be enabled by `CS_OPT_SYNTAX_CS_REG_ALIAS`. WARNING: This option uses a naive search and replace strategy to patch the register names in the asm text. And hence adds significant runtime at scale, if enabled. | Mimic LLVM as close as possible. |
| `AArch64CC_*` | `AArch64CC_EQ == 0` but `AArch64CC_INVALID != 0` | They match the LLVM enum. Better for LLVM compatibility and code generation. |

**PPC**

| Keyword | Change | Justification |
|---------|--------|---------------|
| `PPC_BC` | The branch conditions were completely rewritten and save now all detail known about the bits. | More branch condition details were something missing. |
| Predicates | Predicate enums were renamed due to the changes to the branch conditions. | See `PPC_BC` |
| Instruction alias | Many instruction alias (e.g. `BF`) were removed from the instruction enum (see new alias feature below). | Alias information is provided separately in their own fields. |
| `crx` | `ppc_ops_crx` was removed. | It was never used in the first place. |
| `(RA\|0)` | The `(RA\|0)` cases (see ISA for details) for which `0` is used, the `PPC_REG_ZERO` register is used. The register name of it is `0`. | Mimics LLVM behavior. |
| `cr` `un/so` bit. | The verbose condition register names changes the `so` bit name to `un`. Just as LLVM does. | Mimics LLVM behavior. |

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

| Keyword | Change | Justification |
|---------|--------|---------------|
| SYSZ -> SystemZ | `SYSZ` was everywhere renamed to `SystemZ` to match the LLVM naming. | See below |
| `SYSTEMZ_CC_*` | `SYSTEMZ_CC_O = 0` and `SYSTEMZ_CC_INVALID != 0` | They match the same LLVM values. Better for LLVM compatibility and code generation. |

### Notes about AArch64, SystemZ and ARM renaming

`ARM64` was everywhere renamed to `AArch64`. And `SYSZ` to `SYSTEMZ`. This is a necessity to ensure that the update scripts stay reasonably simple.
Capstone was very inconsistent with the naming before (sometimes `AArch64` sometimes `ARM64`. Sometimes `SYSZ` sometimes `SYSTEMZ`).
Because Capstone uses a huge amount of LLVM code, we renamed everything to `AArch64` and `SystemZ`. This reduces complexity enormously because it follows the naming of LLVM.

Because this would completely break maintaining Capstone `v6` and `pre-v6` in a project, we added compatibility headers:

1. `arm64.h` is a compatibility header now, which merely maps every member to the one in the `aarch64.h` header. Defining `CAPSTONE_AARCH64_COMPAT_HEADER` before including `capstone.h` will include the headers in the right order.
2. The `systemz.h` header includes the `systemz_compatibility.h` header if `CAPSTONE_SYSTEMZ_COMPAT_HEADER` is defined.

We will continue to maintain both headers.

_Compatibility header_

If you want to use the compatibility header and stick with the `ARM64`/`SYSZ` naming, you can define `CAPSTONE_AARCH64_COMPAT_HEADER` and `CAPSTONE_SYSTEMZ_COMPAT_HEADER` before including `capstone.h`.

**Note**: The `CAPSTONE_ARM_COMPAT_HEADER` will only define macros for the `ARM_CC -> ARMCC` and `arm_cc -> ARMCC_CondCodes` renaming.

```c
#define CAPSTONE_SYSTEMZ_COMPAT_HEADER
#define CAPSTONE_AARCH64_COMPAT_HEADER
#define CAPSTONE_ARM_COMPAT_HEADER
#include <capstone/capstone.h>

// Your code...
```

_Example renaming with `sed`_

Alternatively you can perform the renaming with `sed`.

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

Write it into `rename.sh` and run it on files with `sh rename.sh <src-file>`

#### Python binding compatibility

The Python bindings were changed to match the renamed architectures. Thus the `capstone.arm64` module was moved to `capstone.aarch64` and the `capstone.sysz_const` module was moved to `capstone.systemz_const`. The constants and class names were renamed from `ARM64_*` to `AARCH64_*` and `SYSZ_*` to `SYSTEMZ_*` similarly (see above).

To allow using the old `ARM64_*` and `SYSZ_*` constants in scripts running against Capstone v6+, compatibility modules can be imported. They monkey-patch Capstone to export the same constants with the old name as well during runtime. The compatibility module has to be imported **before** anything else from Capstone.

To load the ARM64 constants import the old `capstone.arm64` module first:

```python
# First import legacy compatibility module using old `arm64` name instead of `aarch64`.
import capstone.arm64
# Then import anything else from capstone
import capstone # from capstone import *

# capstone.CS_ARCH_ARM64
# capstone.arm64.ARM64_INS_FDIV
```

To use the old `SYSZ_*` constants import the `capstone.sysz_const` module first:

```python
# First import legacy compatibility module using old `sysz_const` name instead of `systemz_const`.
import capstone.sysz_const
# Then import anything else from capstone.
import capstone # from capstone import *

# capstone.CS_ARCH_SYSZ
# capstone.systemz.SYSZ_REG_V3
```

To update your code to use the new constant names, use the `sed` replacement guide to replace the enum names from the C API above.

**Compatibility for detail**

There is no compatibility layer for type identifiers and detail names at the moment.

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

### Known bugs in the Alpha

**Arch64**

- Access information for `fcvtn` instructions with two vector registers are wrong.

- Some operands have incorrect access attributes set.
If the same register is used twice in the instruction,
once for reading and once for writing, those registers are required by the ISA to be the same,
the details for this register will always be `access = CS_AC_READ_WRITE`.
There is no distinction for `READ` and `WRITE`.

- Single memory operand _components_ (base register, offset) have no unique access information. Access information from memory operands should always refer to the memory. Not the register or immediate components.
Meaning, if a memory operand has the `CS_AC_READ` attribute set, it means the memory is read. Not all of it's components.

Please note though, `writeback` registers are correctly added to the `regs_write` list if `cs_reg_access` is called.

These issues will be addressed in the next releases. For a more detailed descriptions see: https://github.com/capstone-engine/capstone/issues/2472#issuecomment-2335226281 (starting at "eor and the others").

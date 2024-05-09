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
| System registers | System registers are no longer saved in `cs_arm->reg`, but are separated and have more detail. | System operands follow their own encoding logic. Hence, they should be separated in the details as well. | None |
| System operands | System operands have now the encoding of LLVM (SYSm value mostly) | See note about system registers. | None |
| Instruction enum | Multiple instructions which were only alias were removed from the instruction enum. | Alias are always disassembled as their real instructions and an additional field identifies which alias it is. | None |
| Instruction groups| Instruction groups, which actually were CPU features, were renamed to reflect that. | Names now match the ones in LLVM. Better for code generation. | Replace IDs with macros. |
| CPU features | CPU features get checked more strictly (`MCLASS`, `V8` etc.) | With many new supported extensions, some instruction bytes decode to a different instruction, depending on the enabled features. Hence, it becomes necessary. | None. |
| `writeback` | `writeback` member was moved to detail. | More architectures need a `writeback` flag. This is a simplification. | None. |
| Register alias | Register alias (`r15 = pc` etc.) are not printed if LLVM doesn't do it. Old Capstone register alias can be enabled by `CS_OPT_SYNTAX_CS_REG_ALIAS`. | Mimic LLVM as close as possible. | Enable `CS_OPT_SYNTAX_CS_REG_ALIAS` option. |
| Immediate | Immediate values (`arm_op.imm`) type changed to `int64_t` | Prevent loss of precision in some cases. | None. |

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

**Note about AArch64**

`ARM64` was everywhere renamed to `AArch64`. This is a necessity to ensure that the update scripts stay reasonably simple.
Capstone was very inconsistent with the naming before (sometimes `AArch64` sometimes `ARM64`).
Because Capstone uses a huge amount of LLVM code, we renamed everything to `AArch64`. This reduces complexity enormously.

Because this would completely break maintaining Capstone `v6` and `pre-v6` in a project, we added macros for meta-programming.

If you need to support the previous version of Capstone as well, you can use those macros (see below helper scripts).
Also, your can exclude/include code by checking `CS_NEXT_VERSION < 6`.

The following `sed` commands in a sh script should ease the renaming from `ARM64` to `AArch64` a lot.

Replacing with version sensitive macros:

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

Write it into `rename_arm64.sh` and run it on files with `sh rename_arm64.sh <src-file>`

## New features

These features are only supported by `auto-sync`-enabled architectures.

**More code quality checks**

- `clang-tidy` is now run on all files changed by a PR.

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
cs_option(handle, CS_OPT_DETAIL, CS_OPT_DETAIL_REAL);
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

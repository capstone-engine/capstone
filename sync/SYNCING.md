Capstone Auto-Sync
===============

Capstone Auto-Sync is an initiative to partly automate the synchronization of certain architectures to the latest.

Most of the Capstone's `.inc` files a generated from LLVM's TableGen backend and processed by python scrips
in `suite/synctools` into C-compatible files, which leads to the problem that with LLVM's update, it's not always
(hardly, in fact)
possible to use the synctools without patch in regard to LLVM's upstream change.

This syncing tools, however, using a custom-made LLVM TableGen
backend ([here](https://github.com/rizinorg/llvm-capstone))
to generate `.inc` files natively usable by Capstone. With certain adaptations in Capstone's structure, it is possible
to consistently automate large parts of the work on keeping up with LLVM's latest Target (i.e. `.td` files) update, and
optimally, there could be zero-overhead in the process of updating
(
see [this patch on missing bcxf instructions](https://github.com/rizinorg/llvm-capstone/commit/d594f4f6b0755ab11580e1e87d610b560e71b5ef))

## Components

There are three primary components on this syncing tools, listed below:

1. llvm-capstone (as shown above), this is where the custom `.inc` file generator lies, it's based on the latest HEAD of
   llvm-project and is prepared for rebase onto future versions.
2. CapstoneXXX(Arch)Modules.h, this is added for each supported architectures, and contains the necessary specialized
   decoder functions for TableGen-ed disassemblers, it also means that it is used to import the disassembler and expose
   it to Capstone.
3. XXX(Arch)GenDisassemblerTables.inc, this is the TableGen-ed file contains various information & codes generated from
   LLVM's Target Description (*.td)
   files, it is fully auto-generated and is recommended not to be modified manually, the following of this document will
   introduce various important parts of this file.

## TableGen-ed file

The tablegen-ed file has the following parts, respectively:

### Disassembler & Feature Enums

This disassembler part contains **tables** and codes of this architecture's instructions, and is expected to be
C-Compatible, the `DecodeInstruction` here can be used to define an instruction decoder function like that we could see
in `AArch64GenDisassemblerTables.inc`:

```c
// define the insn file extractor
FieldFromInstruction(fieldFromInstruction, uint32_t)
// define the `to MCInst` decoder
DecodeToMCInst(decodeToMCInst, fieldFromInstruction, uint32_t)
// define the instruction decoder `i.e. disassembler`
DecodeInstruction(decodeInstruction, fieldFromInstruction,
                          decodeToMCInst, uint32_t)
```

and thus this `decodeInstruction` can be called as a C function with the disassemble **table** given, like such:

```c
// Calling the auto-generated decoder function.
  result =
      decodeInstruction_4(DecoderTableARM32, MI, insn, Address, 0, ud->mode);
```

This part of file is enabled with macro `#{ARCH}_GET_DISASSEMBLER`

### Registers Info & Instruction Info Enums

Each disassembled MCInst contains OpCode ID and Operand ID (if they're not immediate) that might not be known to
Capstone. The Register & Instruction Info Enums exhibit there correspondence to the "magic numbers" within MCInst. And
can be used by Capstone to map each OpCode & Operand into the identifiable ones.

This also contains miscellaneous like Register Class IDs, which shall be vital to certain instructions.

This part of file is enabled with macro `#GET_INSTRINFO_ENUM` and `#GET_REGINFO_ENUM`

### Extra Register Info

Sometimes Capstone needs more information Certain information on registers, e.g., architectures have special registers
that possesses `Sub Register` or `Super Register` (like `D` and `Q`
registers in ARM64), and also, Capstone is using their names (in LLVM), like for instruction printing. This part
contains all the info. that might be needed to find a registers' name, their sub-regs or super-regs, and also it
contains register class definitions, making it possible to index into certain register class, or to find which class a
register belongs to.

This part of file is enabled with macro `#GET_REGINFO_EXTRA` and `#GET_REGINFO_MC_DESC`

### Instruction Printer (Asm Writer)

Printing an instruction, like that of disassembler, is provided with certain functions to perform, this includes:

1. `$ARCH_getMnemonic`, this function returns a pair of instruction mnemonic and its printer-specific operand info,
   given a valid `MCInst`.
2. `printInstruction`, this function prints instruction according to the given `MCInst`, and make it's output to a
   Capstone `SStream`, note that this method make callbacks to architecture-specific operand printers defined
   in `${ARCH}InstPrinter.c`, and the specialized operand printer should be manually tweaked to meet up with custom
   needs.
3. `getRegisterName`, this function maps register ID (LLVM internal) into their names, note that the name provided could
   be different from convention to convention, that's why we have `$ARCH_reg_name` in `${ARCH}Mapping.c` file. In this
   patched version this is used as a fallback for register that has not been named by Capstone.
4. `printAliasInstr`, some instructions might have aliases in that the performs the same under certain architecture,
   that's when this function is used, commonly, this function is called before `printInstruction` to make sure that the
   aliases is checked before printing the raw one.

The first two is accessed by `#GET_ASM_WRITER`, and the alias printing function is accessed by `#PRINT_ALIAS_INSTR`.

### Instruction Operand Info

Capstone partly rely on operand usages provided by LLVM, that has its cons and pros, this part of the file is for providing it.
It contains an instruction-to-info. mappings, giving Capstone information on the properties of an instructions' operand one-by-one.

This part also contains the LLVM internal name table for each instruction, which is not commonly used by capstone (but can be referenced if needed)
To enable this, use `#GET_INSTRINFO_MC_DESC`

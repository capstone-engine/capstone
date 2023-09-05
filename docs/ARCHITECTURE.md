# Capstone Architecture overview

## Architecture of Capstone

TODO

## Architecture of a Module

An architecture module is split into two components.

1. The disassembler logic, which decodes bytes to instructions.
2. The mapping logic, which maps the result from component 1 to
a Capstone internal representation and adds additional detail.

### Component 1 - Disassembler logic

The disassembler logic consists exclusively of code from LLVM.
It uses:

- Generated state machines, enums and the like for instruction decoding.
- Handwritten disassembler logic for decoding instruction operands
and controlling the decoding procedure.

### Component 2 - Mapping logic

The mapping component has three different task:

1. Serving as programmable interface for the Capstone core to the LLVM code.
2. Mapping LLVM decoded instructions to a Capstone instruction.
3. Adding additional detail to the Capstone instructions
(e.g. operand `read/write` attributes etc.).

### Instruction representation

There exist two structs which represent an instruction:

- `MCInst`: The LLVM representation of an instruction.
- `cs_insn`: The Capstone representation of an instruction.

The `MCInst` is used by the disassembler component for storing the decoded instruction.
The mapping component on the other hand, uses the `MCInst` to populate the `cs_insn`.

The `cs_insn` is meant to be used by the Capstone core.
It is distinct from the `MCInst`. It uses different instruction identifiers, other operand representation
and holds more details about an instruction.

### Disassembling process

There are two steps in disassembling an instruction.

1. Decoding bytes to a `MCInst`.
2. Decoding the assembler string for the `MCInst` AND mapping it to a `cs_insn` in the same step.

Here is a boiled down explanation about these steps.

**Step 1**

```
                                                                 ARCH_LLVM_getInstr(
                                     ARCH_getInstr(bytes)   ┌───┐   bytes)           ┌─────────┐            ┌──────────┐
                                    ┌──────────────────────►│ A ├──────────────────► │         ├───────────►│          ├────┐
                                    │                       │ R │                    │ LLVM    │            │ LLVM     │    │ Decode
                                    │                       │ C │                    │         │            │          │    │ Instr.
                                    │                       │ H │                    │         │decode(Op0) │          │◄───┘
┌────────┐ disasm(bytes) ┌──────────┴──┐                    │   │                    │ Disass- │ ◄──────────┤ Decoder  │
│CS Core ├──────────────►│ ARCH Module │                    │   │                    │ embler  ├──────────► │ State    │
└────────┘               └─────────────┘                    │ M │                    │         │            │ Machine  │
                                    ▲                       │ A │                    │         │decode(Op1) │          │
                                    │                       │ P │                    │         │ ◄──────────┤          │
                                    │                       │ P │                    │         ├──────────► │          │
                                    │                       │ I │                    │         │            │          │
                                    │                       │ N │                    │         │            │          │
                                    └───────────────────────┤ G │◄───────────────────┤         │◄───────────┤          │
                                                            └───┘                    └─────────┘            └──────────┘
```

In the first decoding step the instruction bytes get forwarded to the
decoder state machine.
After the instruction was identified, the state machine calls decoder functions
for each operand to extract the operand values from the bytes.

The disassembler and the state machine are equivalent to what `llvm-objdump` uses
(in fact they use the same files, except we translated them from C++ to C).

**Step 2**

```
                                      ARCH_printInst(        ARCH_LLVM_printInst(
                                         MCInst,                MCInst,
                                         asm_buf)      ┌───┐    asm_buf)         ┌────────┐            ┌──────────┐
                                      ┌───────────────►│ A ├───────────────────► │        ├───────────►│          ├──────┐
                                      │                │ R │                     │ LLVM   │            │ LLVM     │      │ Decode
                                      │                │ C │                     │        │            │          │      │ Mnemonic
                                      │                │ H │ add_cs_detail(Op0)  │        │ print(Op0) │          │◄─────┘
                                      │                │   │ ◄───────────────────┤        │ ◄──────────┤          │
           printer(MCInst,            │                │   ├───────────────────► │        ├──────────► │ Asm-     │
┌────────┐         asm_buf)┌──────────┴──┐             │   │                     │ Inst   │            │ Writer   │
│CS Core ├────────────────►│ ARCH Module │             │   │                     │ Printer│            │ State    │
└────────┘                 └─────────────┘             │ M │                     │        │            │ Machine  │
                                      ▲                │ A │ add_cs_detail(Op1)  │        │ print(Op1) │          │
                                      │                │ P │ ◄───────────────────┤        │ ◄──────────┤          │
                                      │                │ P ├───────────────────► │        ├──────────► │          │
                                      │                │ I │                     │        │            │          │
                                      │                │ N │                     │        │            │          │
                                      └────────────────┤ G │◄────────────────────┤        │◄───────────┤          │
                                                       └───┘                     └────────┘            └──────────┘
```

The second decoding step passes the `MCInst` and a buffer to the printer.

After determining the mnemonic, each operand is printed by using
functions defined in the `InstPrinter`.

Each time an operand is printed, the mapping component is called
to populate the `cs_insn` with the operand information and details.

Again the `InstPrinter` and `AsmWriter` are translated code from LLVM,
so they mirror the behavior of `llvm-objdump`.

Capstone Syncing
===============

This document describes the use of syncing tools and
used as a tracking file for sync progress.

## How to adapt an architecture with auto-sync

0. Get a copy of llvm-project source (or all it's architecture files)

1. Pull the modified llvm-tblgen backend

2. Build the modified backend with target `llvm-tblgen`
```shell
cmake --build ./llvm-project/build --target llvm-tblgen --config Release
```

3. Select the architecture from llvm as ARCH
```shell
export $ARCH=Mips
```

4. Use `llvm-tblgen` binary to generate the disassembler
```shell
llvm-tblgen --gen-capstone -I ./llvm-project/llvm/lib/Target/$ARCH  -I./llvm-project/build/include -I./llvm-project/llvm/include \
  -I ./llvm-project/llvm/lib/Target -omit-comments --long-string-literals=0 -class=Instruction ./llvm-project/llvm/lib/Target/$ARCH/$ARCH.td \
  > ./${ARCH}GenDisassemblerTables.inc
```

5. Use the `sync/main.py` script from this repo. to generate a disassembler callback file
```shell
python ./sync/main.py ./llvm-project/llvm/lib/Target/$ARCH/Disassembler/${ARCH}Disassembler.cpp \
  > ./Capstone${ARCH}Module.h
```

6. Integrate the `Capstone${Arch}Module.h` with corresponding backends in capstone

for more notes on integration see the `Note on Capstone{Arch}Module.h` chapter below

7. trunc the arch's disassembler and instruction printers to make it fit

this is a rather complicated step and highly depends on the original design of arch, the main idea
is to make it best fit the table-gened file

## How to sync with LLVM's update once the adaptation is done

simple, just repeat the step `4` on the previous chapter and replace the `.inc` file with newly generated one

## Note on Capstone{Arch}Module.h

0. ARM & AArch64 from llvm uses feature bits on operand decoding, but capstone ignores them, e.g.
```c++
const FeatureBitset &featureBits =
			  ((const MCDisassembler*)Decoder)->getSubtargetInfo().getFeatureBits();

bool hasMP = featureBits[ARM_FeatureMP];
bool hasV7Ops = featureBits[ARM_HasV7Ops];
```
in capstone scene it would simply be
```c
bool hasMP = true;
bool hasV7Ops = true;
```

1. The auto-sync python script does not performs well on template functions, so some manual override might be needed

## Current adaptation progress:

- [ ] All architectures
    - [x] Mips
    - [x] ARM
    - [x] AArch64
    - [x] Riscv
    - [x] PowerPC
    - [x] Sparc
    - [x] SystemZ
    - [ ] ~~TMS320C64x~~ (not supported by LLVM)
    - [x] XCore
    - [ ] ~~BPF~~ (structurally independent)
- [x] Disassembler
- [x] Instruction Printer
- [ ] Tests
- [ ] Mapping Supports
    - [x] Mips
- [ ] Binding Supports

## Some points that might have to be fixed later

- [ ] Feature bits
- [ ] Suspicious namespace conflicts
- [ ] PPC QPX ? PPC 64

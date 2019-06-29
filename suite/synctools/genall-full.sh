#!/bin/sh
# generate all X86*.inc files for Capstone, by Nguyen Anh Quynh

# Syntax: genall.sh <LLVM-build-lib-Target-ARCH> <clean-old-Capstone-arch-ARCH-dir>

# ./genall-full.sh tablegen ~/projects/capstone.git/arch/X86

echo "Generating GenAsmWriter.inc"
./asmwriter.py $1/X86GenAsmWriter.inc X86GenAsmWriter.inc X86GenRegisterName.inc X86

echo "Generating GenAsmWriter1.inc"
./asmwriter.py $1/X86GenAsmWriter1.inc X86GenAsmWriter1.inc X86GenRegisterName1.inc X86

echo "Generating instruction enum in insn_list.txt (for include/capstone/<arch>.h)"
./insn.py $1/X86GenAsmMatcher.inc $1/X86GenInstrInfo.inc $2/X86MappingInsn.inc > insn_list.txt
# then copy these instructions to include/capstone/x86.h

echo "Generating MappingInsnName.inc"
./mapping_insn_name.py $1/X86GenAsmMatcher.inc $1/X86GenInstrInfo.inc $2/X86MappingInsn.inc > X86MappingInsnName.inc

echo "Generating MappingInsn.inc"
./mapping_insn.py $1/X86GenAsmMatcher.inc $1/X86GenInstrInfo.inc $2/X86MappingInsn.inc > X86MappingInsn.inc

echo "Generating MappingInsnOp.inc"
./mapping_insn_op.py $1/X86GenAsmMatcher.inc $1/X86GenInstrInfo.inc  $2/X86MappingInsnOp.inc > X86MappingInsnOp.inc 

echo "Generating GenInstrInfo.inc"
./instrinfo.py $1/X86GenInstrInfo.inc $1/X86GenAsmMatcher.inc > X86GenInstrInfo.inc

echo "Generating GenDisassemblerTables.inc & X86GenDisassemblerTables2.inc"
./disassemblertables.py $1/X86GenDisassemblerTables.inc X86GenDisassemblerTables.inc X86GenDisassemblerTables2.inc

make x86

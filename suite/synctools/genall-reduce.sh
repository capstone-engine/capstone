#!/bin/sh
# generate all X86*reduce.inc files for Capstone, by Nguyen Anh Quynh

# Syntax: genall.sh <LLVM-build-lib-Target-ARCH> <clean-old-Capstone-arch-ARCH-dir>

# ./genall-reduce.sh tablegen ~/projects/capstone.git/arch/X86

echo "Generating GenAsmWriter_reduce.inc"
./asmwriter.py $1/X86GenAsmWriter_reduce.inc X86GenAsmWriter_reduce.inc X86GenRegisterName.inc X86

echo "Generating GenAsmWriter1_reduce.inc"
./asmwriter.py $1/X86GenAsmWriter1_reduce.inc X86GenAsmWriter1_reduce.inc X86GenRegisterName1.inc X86

echo "Generating MappingInsnName_reduce.inc"
./mapping_insn_name.py $1/X86GenAsmMatcher_reduce.inc $1/X86GenInstrInfo_reduce.inc $2/X86MappingInsn_reduce.inc > X86MappingInsnName_reduce.inc

echo "Generating MappingInsn_reduce.inc"
./mapping_insn.py $1/X86GenAsmMatcher_reduce.inc $1/X86GenInstrInfo_reduce.inc $2/X86MappingInsn_reduce.inc > X86MappingInsn_reduce.inc

echo "Generating MappingInsnOp_reduce.inc"
./mapping_insn_op.py $1/X86GenAsmMatcher.inc $1/X86GenInstrInfo_reduce.inc  $2/X86MappingInsnOp_reduce.inc > X86MappingInsnOp_reduce.inc 

echo "Generating GenInstrInfo_reduce.inc"
./instrinfo.py $1/X86GenInstrInfo_reduce.inc $1/X86GenAsmMatcher_reduce.inc > X86GenInstrInfo_reduce.inc

echo "Generating GenDisassemblerTables_reduce.inc & GenDisassemblerTables_reduce2.inc"
./disassemblertables_reduce.py $1/X86GenDisassemblerTables_reduce.inc X86GenDisassemblerTables_reduce.inc X86GenDisassemblerTables_reduce2.inc


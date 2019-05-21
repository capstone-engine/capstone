#!/bin/sh
# Generate raw X86*.inc files for Capstone, by Nguyen Anh Quynh

# Syntax: gen-tablegen-full.sh <path-to-llvm-tblgen> <path-to-X86-td-files>

# Example: ./gen-tablegen-full.sh ~/projects/llvm/7.0.1/build/bin X86

#TBLGEN_PATH=~/projects/llvm/7.0.1/build/bin
TBLGEN_PATH=$1
#DIR_TD="X86"
DIR_TD=$2

echo "Using llvm-tblgen from ${TBLGEN_PATH}"

echo "Generating X86GenInstrInfo.inc"
$TBLGEN_PATH/llvm-tblgen -gen-instr-info -I include -I ${DIR_TD} ${DIR_TD}/X86.td -o X86GenInstrInfo.inc

echo "Generating X86GenRegisterInfo.inc"
$TBLGEN_PATH/llvm-tblgen -gen-register-info -I include -I ${DIR_TD} ${DIR_TD}/X86.td -o X86GenRegisterInfo.inc

echo "Generating X86GenAsmMatcher.inc"
$TBLGEN_PATH/llvm-tblgen -gen-asm-matcher -I include -I ${DIR_TD} ${DIR_TD}/X86.td -o X86GenAsmMatcher.inc

echo "Generating X86GenDisassemblerTables.inc"
$TBLGEN_PATH/llvm-tblgen -gen-disassembler -I include -I ${DIR_TD} ${DIR_TD}/X86.td -o X86GenDisassemblerTables.inc

echo "Generating X86GenAsmWriter1.inc"
$TBLGEN_PATH/llvm-tblgen -gen-asm-writer -asmwriternum=1 -I include -I ${DIR_TD} ${DIR_TD}/X86.td -o X86GenAsmWriter1.inc

echo "Generating X86GenAsmWriter.inc"
$TBLGEN_PATH/llvm-tblgen -gen-asm-writer -I include -I ${DIR_TD} ${DIR_TD}/X86.td -o X86GenAsmWriter.inc


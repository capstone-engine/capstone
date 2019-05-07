#!/bin/sh
# Generate raw X86*reduce.inc files for Capstone, by Nguyen Anh Quynh

# Syntax: gen-tablegen-reduce.sh <path-to-llvm-tblgen> X86
# Example: ./gen-tablegen-reduce.sh ~/projects/llvm/7.0.1/build/bin X86

#TBLGEN_PATH=~/projects/llvm/7.0.1/build/bin
TBLGEN_PATH=$1
#DIR_TD="X86"
DIR_TD=$2

echo "Using llvm-tblgen from ${TBLGEN_PATH}"

echo "Generating X86GenAsmMatcher_reduce.inc"
$TBLGEN_PATH/llvm-tblgen -gen-asm-matcher -I include -I ${DIR_TD} ${DIR_TD}/X86_reduce.td -o X86GenAsmMatcher_reduce.inc

echo "Generating GenInstrInfo_reduce.inc"
$TBLGEN_PATH/llvm-tblgen -gen-instr-info -I include -I ${DIR_TD} ${DIR_TD}/X86_reduce.td -o X86GenInstrInfo_reduce.inc

echo "Generating X86GenDisassemblerTables_reduce.inc"
$TBLGEN_PATH/llvm-tblgen -gen-disassembler -I include -I ${DIR_TD} ${DIR_TD}/X86_reduce.td -o X86GenDisassemblerTables_reduce.inc

echo "Generating X86GenAsmWriter1_reduce.inc"
$TBLGEN_PATH/llvm-tblgen -gen-asm-writer -asmwriternum=1 -I include -I ${DIR_TD} ${DIR_TD}/X86_reduce.td -o X86GenAsmWriter1_reduce.inc

echo "Generating X86GenAsmWriter_reduce.inc"
$TBLGEN_PATH/llvm-tblgen -gen-asm-writer -I include -I ${DIR_TD} ${DIR_TD}/X86_reduce.td -o X86GenAsmWriter_reduce.inc


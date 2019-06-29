#!/bin/sh
# Generate raw X86*.inc files for Capstone, by Nguyen Anh Quynh
# This combines both -full & -reduce scripts, so we keep it here for reference only.

# Syntax: gen-tablegen.sh <path-to-llvm-tblgen>
# Example: ./gen-tablegen.sh ~/projects/llvm/7.0.1/build/bin

#TBLGEN_PATH=~/projects/llvm/7.0.1/build/bin
TBLGEN_PATH=$1

echo "Using llvm-tblgen from ${TBLGEN_PATH}"

echo "Generating X86GenInstrInfo.inc"
$TBLGEN_PATH/llvm-tblgen -gen-instr-info -I include -I X86 X86/X86.td -o X86GenInstrInfo.inc

echo "Generating X86GenRegisterInfo.inc"
$TBLGEN_PATH/llvm-tblgen -gen-register-info -I include -I X86 X86/X86.td -o X86GenRegisterInfo.inc

echo "Generating X86GenAsmMatcher.inc"
$TBLGEN_PATH/llvm-tblgen -gen-asm-matcher -I include -I X86 X86/X86.td -o X86GenAsmMatcher.inc

echo "Generating X86GenDisassemblerTables.inc"
$TBLGEN_PATH/llvm-tblgen -gen-disassembler -I include -I X86 X86/X86.td -o X86GenDisassemblerTables.inc

echo "Generating X86GenAsmWriter1.inc"
$TBLGEN_PATH/llvm-tblgen -gen-asm-writer -asmwriternum=1 -I include -I X86 X86/X86.td -o X86GenAsmWriter1.inc

echo "Generating X86GenAsmWriter.inc"
$TBLGEN_PATH/llvm-tblgen -gen-asm-writer -I include -I X86 X86/X86.td -o X86GenAsmWriter.inc


echo "Generating X86GenAsmMatcher_reduce.inc"
$TBLGEN_PATH/llvm-tblgen -gen-asm-matcher -I include -I X86 X86/X86_reduce.td -o X86GenAsmMatcher_reduce.inc

echo "Generating GenInstrInfo_reduce.inc"
$TBLGEN_PATH/llvm-tblgen -gen-instr-info -I include -I X86 X86/X86_reduce.td -o X86GenInstrInfo_reduce.inc

echo "Generating X86GenDisassemblerTables_reduce.inc"
$TBLGEN_PATH/llvm-tblgen -gen-disassembler -I include -I X86 X86/X86_reduce.td -o X86GenDisassemblerTables_reduce.inc

echo "Generating X86GenAsmWriter1_reduce.inc"
$TBLGEN_PATH/llvm-tblgen -gen-asm-writer -asmwriternum=1 -I include -I X86 X86/X86_reduce.td -o X86GenAsmWriter1_reduce.inc

echo "Generating X86GenAsmWriter.inc"
$TBLGEN_PATH/llvm-tblgen -gen-asm-writer -I include -I X86 X86/X86_reduce.td -o X86GenAsmWriter_reduce.inc



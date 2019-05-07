#!/bin/sh
# Generate raw .inc files for non-x86 architectures of Capstone, by Nguyen Anh Quynh

# Syntax: gen-tablegen-arch.sh <path-to-llvm-tblgen> <arch>

# Example: ./gen-tablegen-arch.sh ~/projects/llvm/7.0.1/build/bin ARM

TBLGEN_PATH=$1
DIR_TD=$2
ARCH=$2

echo "Using llvm-tblgen from ${TBLGEN_PATH}"

echo "Generating ${ARCH}GenInstrInfo.inc"
$TBLGEN_PATH/llvm-tblgen -gen-instr-info -I include -I ${DIR_TD} ${DIR_TD}/${ARCH}.td -o ${ARCH}GenInstrInfo.inc

echo "Generating ${ARCH}GenRegisterInfo.inc"
$TBLGEN_PATH/llvm-tblgen -gen-register-info -I include -I ${DIR_TD} ${DIR_TD}/${ARCH}.td -o ${ARCH}GenRegisterInfo.inc

echo "Generating ${ARCH}GenAsmMatcher.inc"
$TBLGEN_PATH/llvm-tblgen -gen-asm-matcher -I include -I ${DIR_TD} ${DIR_TD}/${ARCH}.td -o ${ARCH}GenAsmMatcher.inc

echo "Generating ${ARCH}GenDisassemblerTables.inc"
$TBLGEN_PATH/llvm-tblgen -gen-disassembler -I include -I ${DIR_TD} ${DIR_TD}/${ARCH}.td -o ${ARCH}GenDisassemblerTables.inc

echo "Generating ${ARCH}GenAsmWriter.inc"
$TBLGEN_PATH/llvm-tblgen -gen-asm-writer -I include -I ${DIR_TD} ${DIR_TD}/${ARCH}.td -o ${ARCH}GenAsmWriter.inc

echo "Generating ${ARCH}GenSubtargetInfo.inc"
$TBLGEN_PATH/llvm-tblgen -gen-subtarget -I include -I ${DIR_TD} ${DIR_TD}/${ARCH}.td -o ${ARCH}GenSubtargetInfo.inc

case $2 in
  ARM)
  # for ARM only
  echo "Generating ${ARCH}GenAsmWriter-digit.inc"
  $TBLGEN_PATH/llvm-tblgen -gen-asm-writer -I include -I ${DIR_TD} ${DIR_TD}/${ARCH}-digit.td -o ${ARCH}GenAsmWriter-digit.inc
  echo "Generating ${ARCH}GenSystemRegister.inc"
  $TBLGEN_PATH/llvm-tblgen -gen-searchable-tables -I include -I ${DIR_TD} ${DIR_TD}/${ARCH}.td -o ${ARCH}GenSystemRegister.inc
  ;;
  AArch64)
  echo "Generating ${ARCH}GenSystemOperands.inc"
  $TBLGEN_PATH/llvm-tblgen -gen-searchable-tables -I include -I ${DIR_TD} ${DIR_TD}/${ARCH}.td -o ${ARCH}GenSystemOperands.inc
  ;;
esac


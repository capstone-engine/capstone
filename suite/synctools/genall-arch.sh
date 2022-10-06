#!/bin/sh
# generate all ARCH*.inc files for Capstone, by Nguyen Anh Quynh

# Syntax: genall-arch.sh <LLVM-dir-with-inc-files> <clean-old-Capstone-arch-ARCH-dir> <arch>

# ./genall-arch.sh tablegen ~/projects/capstone.git/arch/ARM ARM
# ./genall-arch.sh tablegen ~/projects/capstone.git/arch/ARM AArch64
# ./genall-arch.sh tablegen ~/projects/capstone.git/arch/ARM PowerPC

ARCH=$3

echo "Generating ${ARCH}GenAsmWriter.inc"
./asmwriter.py $1/${ARCH}GenAsmWriter.inc ${ARCH}GenAsmWriter.inc ${ARCH}GenRegisterName.inc ${ARCH}

echo "Generating ${ARCH}MappingInsnName.inc (Copy comments to include/capstone/<arch>.h for complete insn list.)"
./mapping_insn_name-arch.py $1/${ARCH}GenAsmMatcher.inc > ${ARCH}MappingInsnName.inc
#./mapping_insn_name-arch.py tablegen/ARMGenAsmMatcher.inc

echo "Generating ${ARCH}MappingInsn.inc"
./mapping_insn-arch.py $1/${ARCH}GenAsmMatcher.inc $1/${ARCH}GenInstrInfo.inc $2/${ARCH}MappingInsn.inc > ${ARCH}MappingInsn.inc

echo "Generating ${ARCH}GenInstrInfo.inc"
./instrinfo-arch.py $1/${ARCH}GenInstrInfo.inc ${ARCH} > ${ARCH}GenInstrInfo.inc

echo "Generating ${ARCH}GenDisassemblerTables.inc"
./disassemblertables-arch.py $1/${ARCH}GenDisassemblerTables.inc ${ARCH} > ${ARCH}GenDisassemblerTables.inc

echo "Generating ${ARCH}GenRegisterInfo.inc"
./registerinfo.py $1/${ARCH}GenRegisterInfo.inc ${ARCH} > ${ARCH}GenRegisterInfo.inc

echo "Generating ${ARCH}GenSubtargetInfo.inc"
./subtargetinfo.py $1/${ARCH}GenSubtargetInfo.inc ${ARCH} > ${ARCH}GenSubtargetInfo.inc

case $3 in
  ARM)
  # for ARM only
  echo "Generating ${ARCH}GenAsmWriter-digit.inc"
  ./asmwriter.py $1/${ARCH}GenAsmWriter-digit.inc ${ARCH}GenAsmWriter.inc ${ARCH}GenRegisterName_digit.inc ${ARCH}
  echo "Generating ${ARCH}GenSystemRegister.inc"
  ./systemregister.py $1/${ARCH}GenSystemRegister.inc > ${ARCH}GenSystemRegister.inc
  echo "Generating instruction enum in insn_list.txt (for include/capstone/<arch>.h)"
  ./insn.py $1/${ARCH}GenAsmMatcher.inc $1/${ARCH}GenInstrInfo.inc $2/${ARCH}MappingInsn.inc > insn_list.txt
  # then copy these instructions to include/capstone/<arch>.h
  echo "Generating ${ARCH}MappingInsnOp.inc"
  ./mapping_insn_op-arch.py $1/${ARCH}GenAsmMatcher.inc $1/${ARCH}GenInstrInfo.inc  $2/${ARCH}MappingInsnOp.inc > ${ARCH}MappingInsnOp.inc 
  echo "Generating ${ARCH}GenSystemRegister.inc"
  ./systemregister.py $1/${ARCH}GenSystemRegister.inc > ${ARCH}GenSystemRegister.inc
  ;;
  AArch64)
  make arm64
  echo "Generating ${ARCH}GenSystemOperands.inc"
  ./systemoperand.py tablegen/AArch64GenSystemOperands.inc AArch64GenSystemOperands.inc AArch64GenSystemOperands_enum.inc
  echo "Generating instruction enum in insn_list.txt (for include/capstone/<arch>.h)"
  ./insn.py $1/${ARCH}GenAsmMatcher.inc $1/${ARCH}GenInstrInfo.inc $2/${ARCH}MappingInsn.inc > insn_list.txt
  # then copy these instructions to include/capstone/<arch>.h
  ./arm64_gen_vreg > AArch64GenRegisterV.inc
  echo "Generating ${ARCH}MappingInsnOp.inc"
  ./mapping_insn_op-arch.py $1/${ARCH}GenAsmMatcher.inc $1/${ARCH}GenInstrInfo.inc  $2/${ARCH}MappingInsnOp.inc > ${ARCH}MappingInsnOp.inc 
  ;;
  PowerPC)
  # PowerPC
  ./insn3.py $1/${ARCH}GenAsmMatcher.inc > insn_list.txt
  # then copy these instructions to include/capstone/arch.h
  ;;
  *)
  echo "Generating instruction enum in insn_list.txt (for include/capstone/<arch>.h)"
  ./insn.py $1/${ARCH}GenAsmMatcher.inc $1/${ARCH}GenInstrInfo.inc $2/${ARCH}MappingInsn.inc > insn_list.txt
  ;;
esac


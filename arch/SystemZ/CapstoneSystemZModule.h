//
// Created by Phosphorus15 on 2021/7/14.
//

#ifndef CAPSTONE_CAPSTONESYSTEMZMODULE_H
#define CAPSTONE_CAPSTONESYSTEMZMODULE_H

static void llvm_unreachable(const char *info) {}
static void assert(int val) {}

static DecodeStatus decodeRegisterClass(MCInst *Inst, uint64_t RegNo,
                                        const unsigned *Regs, unsigned Size);

static DecodeStatus DecodeGR32BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder);

static DecodeStatus DecodeGRH32BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                                uint64_t Address,
                                                MCRegisterInfo *Decoder);

static DecodeStatus DecodeGR64BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder);

static DecodeStatus DecodeGR128BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                                uint64_t Address,
                                                MCRegisterInfo *Decoder);

static DecodeStatus DecodeADDR64BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                                 uint64_t Address,
                                                 MCRegisterInfo *Decoder);

static DecodeStatus DecodeFP32BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder);

static DecodeStatus DecodeFP64BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder);

static DecodeStatus DecodeFP128BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                                uint64_t Address,
                                                MCRegisterInfo *Decoder);

static DecodeStatus DecodeVR32BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder);

static DecodeStatus DecodeVR64BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder);

static DecodeStatus DecodeVR128BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                                uint64_t Address,
                                                MCRegisterInfo *Decoder);

static DecodeStatus DecodeAR32BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder);

static DecodeStatus DecodeCR64BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder);

static DecodeStatus decodeUImmOperand(MCInst *Inst, uint64_t Imm, int N);

static DecodeStatus decodeSImmOperand(MCInst *Inst, uint64_t Imm, int N);

static DecodeStatus decodeU1ImmOperand(MCInst *Inst, uint64_t Imm,
                                       uint64_t Address,
                                       MCRegisterInfo *Decoder);

static DecodeStatus decodeU2ImmOperand(MCInst *Inst, uint64_t Imm,
                                       uint64_t Address,
                                       MCRegisterInfo *Decoder);

static DecodeStatus decodeU3ImmOperand(MCInst *Inst, uint64_t Imm,
                                       uint64_t Address,
                                       MCRegisterInfo *Decoder);

static DecodeStatus decodeU4ImmOperand(MCInst *Inst, uint64_t Imm,
                                       uint64_t Address,
                                       MCRegisterInfo *Decoder);

static DecodeStatus decodeU6ImmOperand(MCInst *Inst, uint64_t Imm,
                                       uint64_t Address,
                                       MCRegisterInfo *Decoder);

static DecodeStatus decodeU8ImmOperand(MCInst *Inst, uint64_t Imm,
                                       uint64_t Address,
                                       MCRegisterInfo *Decoder);

static DecodeStatus decodeU12ImmOperand(MCInst *Inst, uint64_t Imm,
                                        uint64_t Address,
                                        MCRegisterInfo *Decoder);

static DecodeStatus decodeU16ImmOperand(MCInst *Inst, uint64_t Imm,
                                        uint64_t Address,
                                        MCRegisterInfo *Decoder);

static DecodeStatus decodeU32ImmOperand(MCInst *Inst, uint64_t Imm,
                                        uint64_t Address,
                                        MCRegisterInfo *Decoder);

static DecodeStatus decodeS8ImmOperand(MCInst *Inst, uint64_t Imm,
                                       uint64_t Address,
                                       MCRegisterInfo *Decoder);

static DecodeStatus decodeS16ImmOperand(MCInst *Inst, uint64_t Imm,
                                        uint64_t Address,
                                        MCRegisterInfo *Decoder);

static DecodeStatus decodeS32ImmOperand(MCInst *Inst, uint64_t Imm,
                                        uint64_t Address,
                                        MCRegisterInfo *Decoder);

static DecodeStatus decodePCDBLOperand(MCInst *Inst, uint64_t Imm,
                                       uint64_t Address, bool isBranch,
                                       MCRegisterInfo *Decoder, int N);

static DecodeStatus decodePC12DBLBranchOperand(MCInst *Inst, uint64_t Imm,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder);

static DecodeStatus decodePC16DBLBranchOperand(MCInst *Inst, uint64_t Imm,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder);

static DecodeStatus decodePC24DBLBranchOperand(MCInst *Inst, uint64_t Imm,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder);

static DecodeStatus decodePC32DBLBranchOperand(MCInst *Inst, uint64_t Imm,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder);

static DecodeStatus decodePC32DBLOperand(MCInst *Inst, uint64_t Imm,
                                         uint64_t Address,
                                         MCRegisterInfo *Decoder);

static DecodeStatus decodeBDAddr12Operand(MCInst *Inst, uint64_t Field,
                                          const unsigned *Regs);

static DecodeStatus decodeBDAddr20Operand(MCInst *Inst, uint64_t Field,
                                          const unsigned *Regs);

static DecodeStatus decodeBDXAddr12Operand(MCInst *Inst, uint64_t Field,
                                           const unsigned *Regs);

static DecodeStatus decodeBDXAddr20Operand(MCInst *Inst, uint64_t Field,
                                           const unsigned *Regs);

static DecodeStatus decodeBDLAddr12Len4Operand(MCInst *Inst, uint64_t Field,
                                               const unsigned *Regs);

static DecodeStatus decodeBDLAddr12Len8Operand(MCInst *Inst, uint64_t Field,
                                               const unsigned *Regs);

static DecodeStatus decodeBDRAddr12Operand(MCInst *Inst, uint64_t Field,
                                           const unsigned *Regs);

static DecodeStatus decodeBDVAddr12Operand(MCInst *Inst, uint64_t Field,
                                           const unsigned *Regs);

static DecodeStatus decodeBDAddr32Disp12Operand(MCInst *Inst, uint64_t Field,
                                                uint64_t Address,
                                                MCRegisterInfo *Decoder);

static DecodeStatus decodeBDAddr32Disp20Operand(MCInst *Inst, uint64_t Field,
                                                uint64_t Address,
                                                MCRegisterInfo *Decoder);

static DecodeStatus decodeBDAddr64Disp12Operand(MCInst *Inst, uint64_t Field,
                                                uint64_t Address,
                                                MCRegisterInfo *Decoder);

static DecodeStatus decodeBDAddr64Disp20Operand(MCInst *Inst, uint64_t Field,
                                                uint64_t Address,
                                                MCRegisterInfo *Decoder);

static DecodeStatus decodeBDXAddr64Disp12Operand(MCInst *Inst, uint64_t Field,
                                                 uint64_t Address,
                                                 MCRegisterInfo *Decoder);

static DecodeStatus decodeBDXAddr64Disp20Operand(MCInst *Inst, uint64_t Field,
                                                 uint64_t Address,
                                                 MCRegisterInfo *Decoder);

static DecodeStatus decodeBDLAddr64Disp12Len4Operand(MCInst *Inst,
                                                     uint64_t Field,
                                                     uint64_t Address,
                                                     MCRegisterInfo *Decoder);

static DecodeStatus decodeBDLAddr64Disp12Len8Operand(MCInst *Inst,
                                                     uint64_t Field,
                                                     uint64_t Address,
                                                     MCRegisterInfo *Decoder);

static DecodeStatus decodeBDRAddr64Disp12Operand(MCInst *Inst, uint64_t Field,
                                                 uint64_t Address,
                                                 MCRegisterInfo *Decoder);

static DecodeStatus decodeBDVAddr64Disp12Operand(MCInst *Inst, uint64_t Field,
                                                 uint64_t Address,
                                                 MCRegisterInfo *Decoder);

#define GET_REGINFO_ENUM
#define GET_INSTRINFO_ENUM
#define MIPS_GET_DISASSEMBLER
#define GET_REGINFO_MC_DESC
#include "SystemZGenDisassemblerTables.inc"

static DecodeStatus decodeRegisterClass(MCInst *Inst, uint64_t RegNo,
                                        const unsigned *Regs, unsigned Size) {
  assert(RegNo < Size && "Invalid register");
  RegNo = Regs[RegNo];
  if (RegNo == 0)
    return MCDisassembler_Fail;
  MCOperand_CreateReg0(Inst, RegNo);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeGR32BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, SystemZMC_GR32Regs, 16);
}

static DecodeStatus DecodeGRH32BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                                uint64_t Address,
                                                MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, SystemZMC_GRH32Regs, 16);
}

static DecodeStatus DecodeGR64BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, SystemZMC_GR64Regs, 16);
}

static DecodeStatus DecodeGR128BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                                uint64_t Address,
                                                MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, SystemZMC_GR128Regs, 16);
}

static DecodeStatus DecodeADDR64BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                                 uint64_t Address,
                                                 MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, SystemZMC_GR64Regs, 16);
}

static DecodeStatus DecodeFP32BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, SystemZMC_FP32Regs, 16);
}

static DecodeStatus DecodeFP64BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, SystemZMC_FP64Regs, 16);
}

static DecodeStatus DecodeFP128BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                                uint64_t Address,
                                                MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, SystemZMC_FP128Regs, 16);
}

static DecodeStatus DecodeVR32BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, SystemZMC_VR32Regs, 32);
}

static DecodeStatus DecodeVR64BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, SystemZMC_VR64Regs, 32);
}

static DecodeStatus DecodeVR128BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                                uint64_t Address,
                                                MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, SystemZMC_VR128Regs, 32);
}

static DecodeStatus DecodeAR32BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, SystemZMC_AR32Regs, 16);
}

static DecodeStatus DecodeCR64BitRegisterClass(MCInst *Inst, uint64_t RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, SystemZMC_CR64Regs, 16);
}

static DecodeStatus decodeUImmOperand(MCInst *Inst, uint64_t Imm, int N) {
  //  if (!isUInt(Imm, N))
  //    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, Imm);
  return MCDisassembler_Success;
}

static DecodeStatus decodeSImmOperand(MCInst *Inst, uint64_t Imm, int N) {
  //  if (!isUInt(Imm, N))
  //    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, SignExtend64(Imm, N));
  return MCDisassembler_Success;
}

static DecodeStatus decodeU1ImmOperand(MCInst *Inst, uint64_t Imm,
                                       uint64_t Address,
                                       MCRegisterInfo *Decoder) {
  return decodeUImmOperand(Inst, Imm, 1);
}

static DecodeStatus decodeU2ImmOperand(MCInst *Inst, uint64_t Imm,
                                       uint64_t Address,
                                       MCRegisterInfo *Decoder) {
  return decodeUImmOperand(Inst, Imm, 2);
}

static DecodeStatus decodeU3ImmOperand(MCInst *Inst, uint64_t Imm,
                                       uint64_t Address,
                                       MCRegisterInfo *Decoder) {
  return decodeUImmOperand(Inst, Imm, 3);
}

static DecodeStatus decodeU4ImmOperand(MCInst *Inst, uint64_t Imm,
                                       uint64_t Address,
                                       MCRegisterInfo *Decoder) {
  return decodeUImmOperand(Inst, Imm, 4);
}

static DecodeStatus decodeU6ImmOperand(MCInst *Inst, uint64_t Imm,
                                       uint64_t Address,
                                       MCRegisterInfo *Decoder) {
  return decodeUImmOperand(Inst, Imm, 6);
}

static DecodeStatus decodeU8ImmOperand(MCInst *Inst, uint64_t Imm,
                                       uint64_t Address,
                                       MCRegisterInfo *Decoder) {
  return decodeUImmOperand(Inst, Imm, 8);
}

static DecodeStatus decodeU12ImmOperand(MCInst *Inst, uint64_t Imm,
                                        uint64_t Address,
                                        MCRegisterInfo *Decoder) {
  return decodeUImmOperand(Inst, Imm, 12);
}

static DecodeStatus decodeU16ImmOperand(MCInst *Inst, uint64_t Imm,
                                        uint64_t Address,
                                        MCRegisterInfo *Decoder) {
  return decodeUImmOperand(Inst, Imm, 16);
}

static DecodeStatus decodeU32ImmOperand(MCInst *Inst, uint64_t Imm,
                                        uint64_t Address,
                                        MCRegisterInfo *Decoder) {
  return decodeUImmOperand(Inst, Imm, 32);
}

static DecodeStatus decodeS8ImmOperand(MCInst *Inst, uint64_t Imm,
                                       uint64_t Address,
                                       MCRegisterInfo *Decoder) {
  return decodeSImmOperand(Inst, Imm, 8);
}

static DecodeStatus decodeS16ImmOperand(MCInst *Inst, uint64_t Imm,
                                        uint64_t Address,
                                        MCRegisterInfo *Decoder) {
  return decodeSImmOperand(Inst, Imm, 16);
}

static DecodeStatus decodeS32ImmOperand(MCInst *Inst, uint64_t Imm,
                                        uint64_t Address,
                                        MCRegisterInfo *Decoder) {
  return decodeSImmOperand(Inst, Imm, 32);
}

static DecodeStatus decodePCDBLOperand(MCInst *Inst, uint64_t Imm,
                                       uint64_t Address, bool isBranch,
                                       MCRegisterInfo *Decoder, int N) {
  //  assert(isUInt(Imm, N) && "Invalid PC-relative offset");
  uint64_t Value = SignExtend64(Imm, N) * 2 + Address;

  //  if (!tryAddingSymbolicOperand(Value, isBranch, Address, 2, N / 8,
  //                                Inst, Decoder))
  MCOperand_CreateImm0(Inst, Value);

  return MCDisassembler_Success;
}

static DecodeStatus decodePC12DBLBranchOperand(MCInst *Inst, uint64_t Imm,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder) {
  return decodePCDBLOperand(Inst, Imm, Address, true, Decoder, 12);
}

static DecodeStatus decodePC16DBLBranchOperand(MCInst *Inst, uint64_t Imm,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder) {
  return decodePCDBLOperand(Inst, Imm, Address, true, Decoder, 16);
}

static DecodeStatus decodePC24DBLBranchOperand(MCInst *Inst, uint64_t Imm,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder) {
  return decodePCDBLOperand(Inst, Imm, Address, true, Decoder, 24);
}

static DecodeStatus decodePC32DBLBranchOperand(MCInst *Inst, uint64_t Imm,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder) {
  return decodePCDBLOperand(Inst, Imm, Address, true, Decoder, 32);
}

static DecodeStatus decodePC32DBLOperand(MCInst *Inst, uint64_t Imm,
                                         uint64_t Address,
                                         MCRegisterInfo *Decoder) {
  return decodePCDBLOperand(Inst, Imm, Address, false, Decoder, 32);
}

static DecodeStatus decodeBDAddr12Operand(MCInst *Inst, uint64_t Field,
                                          const unsigned *Regs) {
  uint64_t Base = Field >> 12;
  uint64_t Disp = Field & 0xfff;
  assert(Base < 16 && "Invalid BDAddr12");
  MCOperand_CreateReg0(Inst, Base == 0 ? 0 : Regs[Base]);
  MCOperand_CreateImm0(Inst, Disp);
  return MCDisassembler_Success;
}

static DecodeStatus decodeBDAddr20Operand(MCInst *Inst, uint64_t Field,
                                          const unsigned *Regs) {
  uint64_t Base = Field >> 20;
  uint64_t Disp = ((Field << 12) & 0xff000) | ((Field >> 8) & 0xfff);
  // assert(Base < 16 && "Invalid BDAddr20");

  MCOperand_CreateReg0(Inst, Base == 0 ? 0 : Regs[Base]);
  MCOperand_CreateImm0(Inst, SignExtend64(Disp, 20));
  return MCDisassembler_Success;
}

static DecodeStatus decodeBDXAddr12Operand(MCInst *Inst, uint64_t Field,
                                           const unsigned *Regs) {
  uint64_t Index = Field >> 16;
  uint64_t Base = (Field >> 12) & 0xf;
  uint64_t Disp = Field & 0xfff;
  assert(Index < 16 && "Invalid BDXAddr12");
  MCOperand_CreateReg0(Inst, Base == 0 ? 0 : Regs[Base]);
  MCOperand_CreateImm0(Inst, Disp);
  MCOperand_CreateReg0(Inst, Index == 0 ? 0 : Regs[Index]);
  return MCDisassembler_Success;
}

static DecodeStatus decodeBDXAddr20Operand(MCInst *Inst, uint64_t Field,
                                           const unsigned *Regs) {
  uint64_t Index = Field >> 24;
  uint64_t Base = (Field >> 20) & 0xf;
  uint64_t Disp = ((Field & 0xfff00) >> 8) | ((Field & 0xff) << 12);
  assert(Index < 16 && "Invalid BDXAddr20");
  MCOperand_CreateReg0(Inst, Base == 0 ? 0 : Regs[Base]);
  MCOperand_CreateImm0(Inst, SignExtend64(Disp, 20));
  MCOperand_CreateReg0(Inst, Index == 0 ? 0 : Regs[Index]);
  return MCDisassembler_Success;
}

static DecodeStatus decodeBDLAddr12Len4Operand(MCInst *Inst, uint64_t Field,
                                               const unsigned *Regs) {
  uint64_t Length = Field >> 16;
  uint64_t Base = (Field >> 12) & 0xf;
  uint64_t Disp = Field & 0xfff;
  assert(Length < 16 && "Invalid BDLAddr12Len4");
  MCOperand_CreateReg0(Inst, Base == 0 ? 0 : Regs[Base]);
  MCOperand_CreateImm0(Inst, Disp);
  MCOperand_CreateImm0(Inst, Length + 1);
  return MCDisassembler_Success;
}

static DecodeStatus decodeBDLAddr12Len8Operand(MCInst *Inst, uint64_t Field,
                                               const unsigned *Regs) {
  uint64_t Length = Field >> 16;
  uint64_t Base = (Field >> 12) & 0xf;
  uint64_t Disp = Field & 0xfff;
  assert(Length < 256 && "Invalid BDLAddr12Len8");
  MCOperand_CreateReg0(Inst, Base == 0 ? 0 : Regs[Base]);
  MCOperand_CreateImm0(Inst, Disp);
  MCOperand_CreateImm0(Inst, Length + 1);
  return MCDisassembler_Success;
}

static DecodeStatus decodeBDRAddr12Operand(MCInst *Inst, uint64_t Field,
                                           const unsigned *Regs) {
  uint64_t Length = Field >> 16;
  uint64_t Base = (Field >> 12) & 0xf;
  uint64_t Disp = Field & 0xfff;
  assert(Length < 16 && "Invalid BDRAddr12");
  MCOperand_CreateReg0(Inst, Base == 0 ? 0 : Regs[Base]);
  MCOperand_CreateImm0(Inst, Disp);
  MCOperand_CreateReg0(Inst, Regs[Length]);
  return MCDisassembler_Success;
}

static DecodeStatus decodeBDVAddr12Operand(MCInst *Inst, uint64_t Field,
                                           const unsigned *Regs) {
  uint64_t Index = Field >> 16;
  uint64_t Base = (Field >> 12) & 0xf;
  uint64_t Disp = Field & 0xfff;
  assert(Index < 32 && "Invalid BDVAddr12");
  MCOperand_CreateReg0(Inst, Base == 0 ? 0 : Regs[Base]);
  MCOperand_CreateImm0(Inst, Disp);
  MCOperand_CreateReg0(Inst, SystemZMC_VR128Regs[Index]);
  return MCDisassembler_Success;
}

static DecodeStatus decodeBDAddr32Disp12Operand(MCInst *Inst, uint64_t Field,
                                                uint64_t Address,
                                                MCRegisterInfo *Decoder) {
  return decodeBDAddr12Operand(Inst, Field, SystemZMC_GR32Regs);
}

static DecodeStatus decodeBDAddr32Disp20Operand(MCInst *Inst, uint64_t Field,
                                                uint64_t Address,
                                                MCRegisterInfo *Decoder) {
  return decodeBDAddr20Operand(Inst, Field, SystemZMC_GR32Regs);
}

static DecodeStatus decodeBDAddr64Disp12Operand(MCInst *Inst, uint64_t Field,
                                                uint64_t Address,
                                                MCRegisterInfo *Decoder) {
  return decodeBDAddr12Operand(Inst, Field, SystemZMC_GR64Regs);
}

static DecodeStatus decodeBDAddr64Disp20Operand(MCInst *Inst, uint64_t Field,
                                                uint64_t Address,
                                                MCRegisterInfo *Decoder) {
  return decodeBDAddr20Operand(Inst, Field, SystemZMC_GR64Regs);
}

static DecodeStatus decodeBDXAddr64Disp12Operand(MCInst *Inst, uint64_t Field,
                                                 uint64_t Address,
                                                 MCRegisterInfo *Decoder) {
  return decodeBDXAddr12Operand(Inst, Field, SystemZMC_GR64Regs);
}

static DecodeStatus decodeBDXAddr64Disp20Operand(MCInst *Inst, uint64_t Field,
                                                 uint64_t Address,
                                                 MCRegisterInfo *Decoder) {
  return decodeBDXAddr20Operand(Inst, Field, SystemZMC_GR64Regs);
}

static DecodeStatus decodeBDLAddr64Disp12Len4Operand(MCInst *Inst,
                                                     uint64_t Field,
                                                     uint64_t Address,
                                                     MCRegisterInfo *Decoder) {
  return decodeBDLAddr12Len4Operand(Inst, Field, SystemZMC_GR64Regs);
}

static DecodeStatus decodeBDLAddr64Disp12Len8Operand(MCInst *Inst,
                                                     uint64_t Field,
                                                     uint64_t Address,
                                                     MCRegisterInfo *Decoder) {
  return decodeBDLAddr12Len8Operand(Inst, Field, SystemZMC_GR64Regs);
}

static DecodeStatus decodeBDRAddr64Disp12Operand(MCInst *Inst, uint64_t Field,
                                                 uint64_t Address,
                                                 MCRegisterInfo *Decoder) {
  return decodeBDRAddr12Operand(Inst, Field, SystemZMC_GR64Regs);
}

static DecodeStatus decodeBDVAddr64Disp12Operand(MCInst *Inst, uint64_t Field,
                                                 uint64_t Address,
                                                 MCRegisterInfo *Decoder) {
  return decodeBDVAddr12Operand(Inst, Field, SystemZMC_GR64Regs);
}

#endif // CAPSTONE_CAPSTONESYSTEMZMODULE_H

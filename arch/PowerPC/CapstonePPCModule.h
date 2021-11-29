//
// Created by Phosphorus15 on 2021/7/12.
//

#ifndef CAPSTONE_CAPSTONEPPCMODULE_H
#define CAPSTONE_CAPSTONEPPCMODULE_H

static void llvm_unreachable(const char *info) {}
static void assert(int val) {}

#define PPC_REGS0_31(X)                                                        \
  {                                                                            \
    X##0, X##1, X##2, X##3, X##4, X##5, X##6, X##7, X##8, X##9, X##10, X##11,  \
        X##12, X##13, X##14, X##15, X##16, X##17, X##18, X##19, X##20, X##21,  \
        X##22, X##23, X##24, X##25, X##26, X##27, X##28, X##29, X##30, X##31   \
  }

#define PPC_REGS_NO0_31(Z, X)                                                  \
  {                                                                            \
    Z, X##1, X##2, X##3, X##4, X##5, X##6, X##7, X##8, X##9, X##10, X##11,     \
        X##12, X##13, X##14, X##15, X##16, X##17, X##18, X##19, X##20, X##21,  \
        X##22, X##23, X##24, X##25, X##26, X##27, X##28, X##29, X##30, X##31   \
  }

#define PPC_REGS0_7(X)                                                         \
  { X##0, X##1, X##2, X##3, X##4, X##5, X##6, X##7 }

static DecodeStatus decodeCondBrTarget(MCInst *Inst, unsigned Imm,
                                       uint64_t Address,
                                       MCRegisterInfo *Decoder);

static DecodeStatus decodeDirectBrTarget(MCInst *Inst, unsigned Imm,
                                         uint64_t Address,
                                         MCRegisterInfo *Decoder);

static DecodeStatus decodeRegisterClass(MCInst *Inst, uint64_t RegNo,
                                        const unsigned *Regs);

static DecodeStatus DecodeCRRCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                            uint64_t Address,
                                            MCRegisterInfo *Decoder);

static DecodeStatus DecodeCRBITRCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder);

static DecodeStatus DecodeF4RCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                            uint64_t Address,
                                            MCRegisterInfo *Decoder);

static DecodeStatus DecodeF8RCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                            uint64_t Address,
                                            MCRegisterInfo *Decoder);

static DecodeStatus DecodeVFRCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                            uint64_t Address,
                                            MCRegisterInfo *Decoder);

static DecodeStatus DecodeVRRCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                            uint64_t Address,
                                            MCRegisterInfo *Decoder);

static DecodeStatus DecodeVSRCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                            uint64_t Address,
                                            MCRegisterInfo *Decoder);

static DecodeStatus DecodeVSFRCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                             uint64_t Address,
                                             MCRegisterInfo *Decoder);

static DecodeStatus DecodeVSSRCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                             uint64_t Address,
                                             MCRegisterInfo *Decoder);

static DecodeStatus DecodeGPRCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                            uint64_t Address,
                                            MCRegisterInfo *Decoder);

static DecodeStatus DecodeGPRC_NOR0RegisterClass(MCInst *Inst, uint64_t RegNo,
                                                 uint64_t Address,
                                                 MCRegisterInfo *Decoder);

static DecodeStatus DecodeG8RCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                            uint64_t Address,
                                            MCRegisterInfo *Decoder);

static DecodeStatus DecodeG8pRCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                             uint64_t Address,
                                             MCRegisterInfo *Decoder);

static DecodeStatus DecodeG8RC_NOX0RegisterClass(MCInst *Inst, uint64_t RegNo,
                                                 uint64_t Address,
                                                 MCRegisterInfo *Decoder);

static DecodeStatus DecodeSPERCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                             uint64_t Address,
                                             MCRegisterInfo *Decoder);
static DecodeStatus DecodeACCRCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                             uint64_t Address,
                                             MCRegisterInfo *Decoder);

static DecodeStatus DecodeVSRpRCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                              uint64_t Address,
                                              MCRegisterInfo *Decoder);

static DecodeStatus decodeUImmOperand(MCInst *Inst, uint64_t Imm,
                                      int64_t Address, MCRegisterInfo *Decoder,
                                      int);

static DecodeStatus decodeSImmOperand(MCInst *Inst, uint64_t Imm,
                                      int64_t Address, MCRegisterInfo *Decoder,
                                      unsigned N);

static DecodeStatus decodeImmZeroOperand(MCInst *Inst, uint64_t Imm,
                                         int64_t Address,
                                         MCRegisterInfo *Decoder);

static DecodeStatus decodeVSRpEvenOperands(MCInst *Inst, uint64_t RegNo,
                                           uint64_t Address,
                                           MCRegisterInfo *Decoder);

static DecodeStatus decodeMemRIOperands(MCInst *Inst, uint64_t Imm,
                                        int64_t Address,
                                        MCRegisterInfo *Decoder);

static DecodeStatus decodeMemRIXOperands(MCInst *Inst, uint64_t Imm,
                                         int64_t Address,
                                         MCRegisterInfo *Decoder);

static DecodeStatus decodeMemRIHashOperands(MCInst *Inst, uint64_t Imm,
                                            int64_t Address,
                                            MCRegisterInfo *Decoder);

static DecodeStatus decodeMemRIX16Operands(MCInst *Inst, uint64_t Imm,
                                           int64_t Address,
                                           MCRegisterInfo *Decoder);

static DecodeStatus decodeMemRI34PCRelOperands(MCInst *Inst, uint64_t Imm,
                                               int64_t Address,
                                               MCRegisterInfo *Decoder);

static DecodeStatus decodeMemRI34Operands(MCInst *Inst, uint64_t Imm,
                                          int64_t Address,
                                          MCRegisterInfo *Decoder);

static DecodeStatus decodeSPE8Operands(MCInst *Inst, uint64_t Imm,
                                       int64_t Address,
                                       MCRegisterInfo *Decoder);

static DecodeStatus decodeSPE4Operands(MCInst *Inst, uint64_t Imm,
                                       int64_t Address,
                                       MCRegisterInfo *Decoder);

static DecodeStatus decodeSPE2Operands(MCInst *Inst, uint64_t Imm,
                                       int64_t Address,
                                       MCRegisterInfo *Decoder);

static DecodeStatus decodeCRBitMOperand(MCInst *Inst, uint64_t Imm,
                                        int64_t Address,
                                        MCRegisterInfo *Decoder);

#define GET_REGINFO_ENUM
#define GET_INSTRINFO_ENUM
#define MIPS_GET_DISASSEMBLER
#define GET_REGINFO_MC_DESC
#include "PPCGenDisassemblerTables.inc"

static const unsigned RRegs[32] = PPC_REGS0_31(PPC_R);

static const unsigned RRegsNoR0[32] = PPC_REGS_NO0_31(PPC_ZERO, PPC_R);

static const unsigned XRegs[32] = PPC_REGS0_31(PPC_X);

static const unsigned XRegsNoX0[32] = PPC_REGS_NO0_31(PPC_ZERO8, PPC_X);

static const unsigned VSRpRegs[32] = PPC_REGS0_31(PPC_VSRp);

static const unsigned ACCRegs[8] = PPC_REGS0_7(PPC_ACC);

static const unsigned CRRegs[] = {PPC_CR0, PPC_CR1, PPC_CR2, PPC_CR3,
                                  PPC_CR4, PPC_CR5, PPC_CR6, PPC_CR7};

static const unsigned CRBITRegs[] = {
    PPC_CR0LT, PPC_CR0GT, PPC_CR0EQ, PPC_CR0UN, PPC_CR1LT, PPC_CR1GT, PPC_CR1EQ,
    PPC_CR1UN, PPC_CR2LT, PPC_CR2GT, PPC_CR2EQ, PPC_CR2UN, PPC_CR3LT, PPC_CR3GT,
    PPC_CR3EQ, PPC_CR3UN, PPC_CR4LT, PPC_CR4GT, PPC_CR4EQ, PPC_CR4UN, PPC_CR5LT,
    PPC_CR5GT, PPC_CR5EQ, PPC_CR5UN, PPC_CR6LT, PPC_CR6GT, PPC_CR6EQ, PPC_CR6UN,
    PPC_CR7LT, PPC_CR7GT, PPC_CR7EQ, PPC_CR7UN};

static const unsigned FRegs[] = {
    PPC_F0,  PPC_F1,  PPC_F2,  PPC_F3,  PPC_F4,  PPC_F5,  PPC_F6,  PPC_F7,
    PPC_F8,  PPC_F9,  PPC_F10, PPC_F11, PPC_F12, PPC_F13, PPC_F14, PPC_F15,
    PPC_F16, PPC_F17, PPC_F18, PPC_F19, PPC_F20, PPC_F21, PPC_F22, PPC_F23,
    PPC_F24, PPC_F25, PPC_F26, PPC_F27, PPC_F28, PPC_F29, PPC_F30, PPC_F31};

static const unsigned VFRegs[] = {
    PPC_VF0,  PPC_VF1,  PPC_VF2,  PPC_VF3,  PPC_VF4,  PPC_VF5,  PPC_VF6,
    PPC_VF7,  PPC_VF8,  PPC_VF9,  PPC_VF10, PPC_VF11, PPC_VF12, PPC_VF13,
    PPC_VF14, PPC_VF15, PPC_VF16, PPC_VF17, PPC_VF18, PPC_VF19, PPC_VF20,
    PPC_VF21, PPC_VF22, PPC_VF23, PPC_VF24, PPC_VF25, PPC_VF26, PPC_VF27,
    PPC_VF28, PPC_VF29, PPC_VF30, PPC_VF31};

static const unsigned VRegs[] = {
    PPC_V0,  PPC_V1,  PPC_V2,  PPC_V3,  PPC_V4,  PPC_V5,  PPC_V6,  PPC_V7,
    PPC_V8,  PPC_V9,  PPC_V10, PPC_V11, PPC_V12, PPC_V13, PPC_V14, PPC_V15,
    PPC_V16, PPC_V17, PPC_V18, PPC_V19, PPC_V20, PPC_V21, PPC_V22, PPC_V23,
    PPC_V24, PPC_V25, PPC_V26, PPC_V27, PPC_V28, PPC_V29, PPC_V30, PPC_V31};

static const unsigned VSRegs[] = {
    PPC_VSL0,  PPC_VSL1,  PPC_VSL2,  PPC_VSL3,  PPC_VSL4,  PPC_VSL5,  PPC_VSL6,
    PPC_VSL7,  PPC_VSL8,  PPC_VSL9,  PPC_VSL10, PPC_VSL11, PPC_VSL12, PPC_VSL13,
    PPC_VSL14, PPC_VSL15, PPC_VSL16, PPC_VSL17, PPC_VSL18, PPC_VSL19, PPC_VSL20,
    PPC_VSL21, PPC_VSL22, PPC_VSL23, PPC_VSL24, PPC_VSL25, PPC_VSL26, PPC_VSL27,
    PPC_VSL28, PPC_VSL29, PPC_VSL30, PPC_VSL31,

    PPC_V0,    PPC_V1,    PPC_V2,    PPC_V3,    PPC_V4,    PPC_V5,    PPC_V6,
    PPC_V7,    PPC_V8,    PPC_V9,    PPC_V10,   PPC_V11,   PPC_V12,   PPC_V13,
    PPC_V14,   PPC_V15,   PPC_V16,   PPC_V17,   PPC_V18,   PPC_V19,   PPC_V20,
    PPC_V21,   PPC_V22,   PPC_V23,   PPC_V24,   PPC_V25,   PPC_V26,   PPC_V27,
    PPC_V28,   PPC_V29,   PPC_V30,   PPC_V31};

static const unsigned VSFRegs[] = {
    PPC_F0,   PPC_F1,   PPC_F2,   PPC_F3,   PPC_F4,   PPC_F5,   PPC_F6,
    PPC_F7,   PPC_F8,   PPC_F9,   PPC_F10,  PPC_F11,  PPC_F12,  PPC_F13,
    PPC_F14,  PPC_F15,  PPC_F16,  PPC_F17,  PPC_F18,  PPC_F19,  PPC_F20,
    PPC_F21,  PPC_F22,  PPC_F23,  PPC_F24,  PPC_F25,  PPC_F26,  PPC_F27,
    PPC_F28,  PPC_F29,  PPC_F30,  PPC_F31,

    PPC_VF0,  PPC_VF1,  PPC_VF2,  PPC_VF3,  PPC_VF4,  PPC_VF5,  PPC_VF6,
    PPC_VF7,  PPC_VF8,  PPC_VF9,  PPC_VF10, PPC_VF11, PPC_VF12, PPC_VF13,
    PPC_VF14, PPC_VF15, PPC_VF16, PPC_VF17, PPC_VF18, PPC_VF19, PPC_VF20,
    PPC_VF21, PPC_VF22, PPC_VF23, PPC_VF24, PPC_VF25, PPC_VF26, PPC_VF27,
    PPC_VF28, PPC_VF29, PPC_VF30, PPC_VF31};

static const unsigned VSSRegs[] = {
    PPC_F0,   PPC_F1,   PPC_F2,   PPC_F3,   PPC_F4,   PPC_F5,   PPC_F6,
    PPC_F7,   PPC_F8,   PPC_F9,   PPC_F10,  PPC_F11,  PPC_F12,  PPC_F13,
    PPC_F14,  PPC_F15,  PPC_F16,  PPC_F17,  PPC_F18,  PPC_F19,  PPC_F20,
    PPC_F21,  PPC_F22,  PPC_F23,  PPC_F24,  PPC_F25,  PPC_F26,  PPC_F27,
    PPC_F28,  PPC_F29,  PPC_F30,  PPC_F31,

    PPC_VF0,  PPC_VF1,  PPC_VF2,  PPC_VF3,  PPC_VF4,  PPC_VF5,  PPC_VF6,
    PPC_VF7,  PPC_VF8,  PPC_VF9,  PPC_VF10, PPC_VF11, PPC_VF12, PPC_VF13,
    PPC_VF14, PPC_VF15, PPC_VF16, PPC_VF17, PPC_VF18, PPC_VF19, PPC_VF20,
    PPC_VF21, PPC_VF22, PPC_VF23, PPC_VF24, PPC_VF25, PPC_VF26, PPC_VF27,
    PPC_VF28, PPC_VF29, PPC_VF30, PPC_VF31};

static const unsigned GPRegs[] = {
    PPC_R0,  PPC_R1,  PPC_R2,  PPC_R3,  PPC_R4,  PPC_R5,  PPC_R6,  PPC_R7,
    PPC_R8,  PPC_R9,  PPC_R10, PPC_R11, PPC_R12, PPC_R13, PPC_R14, PPC_R15,
    PPC_R16, PPC_R17, PPC_R18, PPC_R19, PPC_R20, PPC_R21, PPC_R22, PPC_R23,
    PPC_R24, PPC_R25, PPC_R26, PPC_R27, PPC_R28, PPC_R29, PPC_R30, PPC_R31};

static const unsigned GP0Regs[] = {
    PPC_ZERO, PPC_R1,  PPC_R2,  PPC_R3,  PPC_R4,  PPC_R5,  PPC_R6,  PPC_R7,
    PPC_R8,   PPC_R9,  PPC_R10, PPC_R11, PPC_R12, PPC_R13, PPC_R14, PPC_R15,
    PPC_R16,  PPC_R17, PPC_R18, PPC_R19, PPC_R20, PPC_R21, PPC_R22, PPC_R23,
    PPC_R24,  PPC_R25, PPC_R26, PPC_R27, PPC_R28, PPC_R29, PPC_R30, PPC_R31};

static const unsigned G8Regs[] = {
    PPC_X0,  PPC_X1,  PPC_X2,  PPC_X3,  PPC_X4,  PPC_X5,  PPC_X6,  PPC_X7,
    PPC_X8,  PPC_X9,  PPC_X10, PPC_X11, PPC_X12, PPC_X13, PPC_X14, PPC_X15,
    PPC_X16, PPC_X17, PPC_X18, PPC_X19, PPC_X20, PPC_X21, PPC_X22, PPC_X23,
    PPC_X24, PPC_X25, PPC_X26, PPC_X27, PPC_X28, PPC_X29, PPC_X30, PPC_X31};

static const unsigned G80Regs[] = {
    PPC_ZERO8, PPC_X1,  PPC_X2,  PPC_X3,  PPC_X4,  PPC_X5,  PPC_X6,  PPC_X7,
    PPC_X8,    PPC_X9,  PPC_X10, PPC_X11, PPC_X12, PPC_X13, PPC_X14, PPC_X15,
    PPC_X16,   PPC_X17, PPC_X18, PPC_X19, PPC_X20, PPC_X21, PPC_X22, PPC_X23,
    PPC_X24,   PPC_X25, PPC_X26, PPC_X27, PPC_X28, PPC_X29, PPC_X30, PPC_X31};

static const unsigned SPERegs[] = {
    PPC_S0,  PPC_S1,  PPC_S2,  PPC_S3,  PPC_S4,  PPC_S5,  PPC_S6,  PPC_S7,
    PPC_S8,  PPC_S9,  PPC_S10, PPC_S11, PPC_S12, PPC_S13, PPC_S14, PPC_S15,
    PPC_S16, PPC_S17, PPC_S18, PPC_S19, PPC_S20, PPC_S21, PPC_S22, PPC_S23,
    PPC_S24, PPC_S25, PPC_S26, PPC_S27, PPC_S28, PPC_S29, PPC_S30, PPC_S31};

static DecodeStatus decodeCondBrTarget(MCInst *Inst, unsigned Imm,
                                       uint64_t Address,
                                       MCRegisterInfo *Decoder) {
  MCOperand_CreateImm0(Inst, SignExtend32(Imm, 14));
  return MCDisassembler_Success;
}

static DecodeStatus decodeDirectBrTarget(MCInst *Inst, unsigned Imm,
                                         uint64_t Address,
                                         MCRegisterInfo *Decoder) {
  int32_t Offset = SignExtend32(Imm, 24);
  MCOperand_CreateImm0(Inst, Offset);
  return MCDisassembler_Success;
}

static DecodeStatus decodeRegisterClass(MCInst *Inst, uint64_t RegNo,
                                        const unsigned *Regs) {
  MCOperand_CreateReg0(Inst, Regs[RegNo]);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeCRRCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                            uint64_t Address,
                                            MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, CRRegs);
}

static DecodeStatus DecodeCRBITRCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, CRBITRegs);
}

static DecodeStatus DecodeF4RCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                            uint64_t Address,
                                            MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, FRegs);
}

static DecodeStatus DecodeF8RCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                            uint64_t Address,
                                            MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, FRegs);
}

static DecodeStatus DecodeVFRCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                            uint64_t Address,
                                            MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, VFRegs);
}

static DecodeStatus DecodeVRRCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                            uint64_t Address,
                                            MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, VRegs);
}

static DecodeStatus DecodeVSRCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                            uint64_t Address,
                                            MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, VSRegs);
}

static DecodeStatus DecodeVSFRCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                             uint64_t Address,
                                             MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, VSFRegs);
}

static DecodeStatus DecodeVSSRCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                             uint64_t Address,
                                             MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, VSSRegs);
}

static DecodeStatus DecodeGPRCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                            uint64_t Address,
                                            MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, RRegs);
}

static DecodeStatus DecodeGPRC_NOR0RegisterClass(MCInst *Inst, uint64_t RegNo,
                                                 uint64_t Address,
                                                 MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, RRegsNoR0);
}

static DecodeStatus DecodeG8RCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                            uint64_t Address,
                                            MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, XRegs);
}

static DecodeStatus DecodeG8pRCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                             uint64_t Address,
                                             MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, XRegs);
}

static DecodeStatus DecodeG8RC_NOX0RegisterClass(MCInst *Inst, uint64_t RegNo,
                                                 uint64_t Address,
                                                 MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, XRegsNoX0);
}

static DecodeStatus DecodeSPERCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                             uint64_t Address,
                                             MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, SPERegs);
}

static DecodeStatus DecodeACCRCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                             uint64_t Address,
                                             MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, ACCRegs);
}

static DecodeStatus DecodeVSRpRCRegisterClass(MCInst *Inst, uint64_t RegNo,
                                              uint64_t Address,
                                              MCRegisterInfo *Decoder) {
  return decodeRegisterClass(Inst, RegNo, VSRpRegs);
}

static DecodeStatus decodeUImmOperand(MCInst *Inst, uint64_t Imm,
                                      int64_t Address, MCRegisterInfo *Decoder,
                                      int N) {
  //  assert(isUInt(Imm, N) && "Invalid immediate");
  MCOperand_CreateImm0(Inst, Imm);
  return MCDisassembler_Success;
}

static DecodeStatus decodeSImmOperand(MCInst *Inst, uint64_t Imm,
                                      int64_t Address, MCRegisterInfo *Decoder,
                                      unsigned N) {
  //  assert(isUInt(Imm, N) && "Invalid immediate");
  MCOperand_CreateImm0(Inst, SignExtend64(Imm, N));
  return MCDisassembler_Success;
}

static DecodeStatus decodeImmZeroOperand(MCInst *Inst, uint64_t Imm,
                                         int64_t Address,
                                         MCRegisterInfo *Decoder) {
  if (Imm != 0)
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, Imm);
  return MCDisassembler_Success;
}

static DecodeStatus decodeVSRpEvenOperands(MCInst *Inst, uint64_t RegNo,
                                           uint64_t Address,
                                           MCRegisterInfo *Decoder) {
  if (RegNo & 1)
    return MCDisassembler_Fail;
  MCOperand_CreateReg0(Inst, VSRpRegs[RegNo >> 1]);
  return MCDisassembler_Success;
}

static DecodeStatus decodeMemRIOperands(MCInst *Inst, uint64_t Imm,
                                        int64_t Address,
                                        MCRegisterInfo *Decoder) {
  // Decode the memri field (imm, reg), which has the low 16-bits as the
  // displacement and the next 5 bits as the register #.

  uint64_t Base = Imm >> 16;
  uint64_t Disp = Imm & 0xFFFF;

  assert(Base < 32 && "Invalid base register");

  switch (MCInst_getOpcode(Inst)) {
  default:
    break;
  case PPC_LBZU:
  case PPC_LHAU:
  case PPC_LHZU:
  case PPC_LWZU:
  case PPC_LFSU:
  case PPC_LFDU:
    // Add the tied output operand.
    MCOperand_CreateReg0(Inst, RRegsNoR0[Base]);
    break;
  case PPC_STBU:
  case PPC_STHU:
  case PPC_STWU:
  case PPC_STFSU:
  case PPC_STFDU:
    MCInst_insert0(Inst, 0, MCOperand_CreateReg1(Inst, RRegsNoR0[Base]));
    break;
  }

  MCOperand_CreateImm0(Inst, SignExtend64(Disp, 16));
  MCOperand_CreateReg0(Inst, RRegsNoR0[Base]);
  return MCDisassembler_Success;
}

static DecodeStatus decodeMemRIXOperands(MCInst *Inst, uint64_t Imm,
                                         int64_t Address,
                                         MCRegisterInfo *Decoder) {
  // Decode the memrix field (imm, reg), which has the low 14-bits as the
  // displacement and the next 5 bits as the register #.

  uint64_t Base = Imm >> 14;
  uint64_t Disp = Imm & 0x3FFF;

  assert(Base < 32 && "Invalid base register");

  if (MCInst_getOpcode(Inst) == PPC_LDU)
    // Add the tied output operand.
    MCOperand_CreateReg0(Inst, RRegsNoR0[Base]);
  else if (MCInst_getOpcode(Inst) == PPC_STDU)
    MCInst_insert0(Inst, 0, MCOperand_CreateReg1(Inst, RRegsNoR0[Base]));

  MCOperand_CreateImm0(Inst, SignExtend64(Disp << 2, 16));
  MCOperand_CreateReg0(Inst, RRegsNoR0[Base]);
  return MCDisassembler_Success;
}

static DecodeStatus decodeMemRIHashOperands(MCInst *Inst, uint64_t Imm,
                                            int64_t Address,
                                            MCRegisterInfo *Decoder) {
  // Decode the memrix field for a hash store or hash check operation.
  // The field is composed of a register and an immediate value that is 6 bits
  // and covers the range -8 to -512. The immediate is always negative and 2s
  // complement which is why we sign extend a 7 bit value.
  const uint64_t Base = Imm >> 6;
  const int64_t Disp = SignExtend64((Imm & 0x3F, 7) + 64, 64) * 8;

  assert(Base < 32 && "Invalid base register");

  MCOperand_CreateImm0(Inst, Disp);
  MCOperand_CreateReg0(Inst, RRegs[Base]);
  return MCDisassembler_Success;
}

static DecodeStatus decodeMemRIX16Operands(MCInst *Inst, uint64_t Imm,
                                           int64_t Address,
                                           MCRegisterInfo *Decoder) {
  // Decode the memrix16 field (imm, reg), which has the low 12-bits as the
  // displacement with 16-byte aligned, and the next 5 bits as the register #.

  uint64_t Base = Imm >> 12;
  uint64_t Disp = Imm & 0xFFF;

  assert(Base < 32 && "Invalid base register");

  MCOperand_CreateImm0(Inst, SignExtend64(Disp << 4, 16));
  MCOperand_CreateReg0(Inst, RRegsNoR0[Base]);
  return MCDisassembler_Success;
}

static DecodeStatus decodeMemRI34PCRelOperands(MCInst *Inst, uint64_t Imm,
                                               int64_t Address,
                                               MCRegisterInfo *Decoder) {
  // Decode the memri34_pcrel field (imm, reg), which has the low 34-bits as the
  // displacement, and the next 5 bits as an immediate 0.
  uint64_t Base = Imm >> 34;
  uint64_t Disp = Imm & 0x3FFFFFFFFUL;

  assert(Base < 32 && "Invalid base register");

  MCOperand_CreateImm0(Inst, SignExtend64(Disp, 34));
  return decodeImmZeroOperand(Inst, Base, Address, Decoder);
}

static DecodeStatus decodeMemRI34Operands(MCInst *Inst, uint64_t Imm,
                                          int64_t Address,
                                          MCRegisterInfo *Decoder) {
  // Decode the memri34 field (imm, reg), which has the low 34-bits as the
  // displacement, and the next 5 bits as the register #.
  uint64_t Base = Imm >> 34;
  uint64_t Disp = Imm & 0x3FFFFFFFFUL;

  assert(Base < 32 && "Invalid base register");

  MCOperand_CreateImm0(Inst, SignExtend64(Disp, 34));
  MCOperand_CreateReg0(Inst, RRegsNoR0[Base]);
  return MCDisassembler_Success;
}

static DecodeStatus decodeSPE8Operands(MCInst *Inst, uint64_t Imm,
                                       int64_t Address,
                                       MCRegisterInfo *Decoder) {
  // Decode the spe8disp field (imm, reg), which has the low 5-bits as the
  // displacement with 8-byte aligned, and the next 5 bits as the register #.

  uint64_t Base = Imm >> 5;
  uint64_t Disp = Imm & 0x1F;

  assert(Base < 32 && "Invalid base register");

  MCOperand_CreateImm0(Inst, Disp << 3);
  MCOperand_CreateReg0(Inst, RRegsNoR0[Base]);
  return MCDisassembler_Success;
}

static DecodeStatus decodeSPE4Operands(MCInst *Inst, uint64_t Imm,
                                       int64_t Address,
                                       MCRegisterInfo *Decoder) {
  // Decode the spe4disp field (imm, reg), which has the low 5-bits as the
  // displacement with 4-byte aligned, and the next 5 bits as the register #.

  uint64_t Base = Imm >> 5;
  uint64_t Disp = Imm & 0x1F;

  assert(Base < 32 && "Invalid base register");

  MCOperand_CreateImm0(Inst, Disp << 2);
  MCOperand_CreateReg0(Inst, RRegsNoR0[Base]);
  return MCDisassembler_Success;
}

static DecodeStatus decodeSPE2Operands(MCInst *Inst, uint64_t Imm,
                                       int64_t Address,
                                       MCRegisterInfo *Decoder) {
  // Decode the spe2disp field (imm, reg), which has the low 5-bits as the
  // displacement with 2-byte aligned, and the next 5 bits as the register #.

  uint64_t Base = Imm >> 5;
  uint64_t Disp = Imm & 0x1F;

  assert(Base < 32 && "Invalid base register");

  MCOperand_CreateImm0(Inst, Disp << 1);
  MCOperand_CreateReg0(Inst, RRegsNoR0[Base]);
  return MCDisassembler_Success;
}

static DecodeStatus decodeCRBitMOperand(MCInst *Inst, uint64_t Imm,
                                        int64_t Address,
                                        MCRegisterInfo *Decoder) {
  // The cr bit encoding is 0x80 >> cr_reg_num.

  unsigned Zeros = CountTrailingZeros_64(Imm);
  assert(Zeros < 8 && "Invalid CR bit value");

  MCOperand_CreateReg0(Inst, CRRegs[7 - Zeros]);
  return MCDisassembler_Success;
}

#endif // CAPSTONE_CAPSTONEPPCMODULE_H

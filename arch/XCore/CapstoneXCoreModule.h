//
// Created by Phosphorus15 on 2021/7/16.
//

#ifndef CAPSTONE_CAPSTONEXCOREMODULE_H
#define CAPSTONE_CAPSTONEXCOREMODULE_H

static void llvm_unreachable(const char *info) {}
static void assert(int val) {}
static DecodeStatus DecodeGRRegsRegisterClass(MCInst *Inst, unsigned RegNo,
                                              uint64_t Address,
                                              MCRegisterInfo *Decoder);

static DecodeStatus DecodeRRegsRegisterClass(MCInst *Inst, unsigned RegNo,
                                             uint64_t Address,
                                             MCRegisterInfo *Decoder);

static DecodeStatus DecodeBitpOperand(MCInst *Inst, unsigned Val,
                                      uint64_t Address,
                                      MCRegisterInfo *Decoder);

static DecodeStatus DecodeNegImmOperand(MCInst *Inst, unsigned Val,
                                        uint64_t Address,
                                        MCRegisterInfo *Decoder);

static DecodeStatus Decode2RInstruction(MCInst *Inst, unsigned Insn,
                                        uint64_t Address,
                                        MCRegisterInfo *Decoder);

static DecodeStatus Decode2RImmInstruction(MCInst *Inst, unsigned Insn,
                                           uint64_t Address,
                                           MCRegisterInfo *Decoder);

static DecodeStatus DecodeR2RInstruction(MCInst *Inst, unsigned Insn,
                                         uint64_t Address,
                                         MCRegisterInfo *Decoder);

static DecodeStatus Decode2RSrcDstInstruction(MCInst *Inst, unsigned Insn,
                                              uint64_t Address,
                                              MCRegisterInfo *Decoder);

static DecodeStatus DecodeRUSInstruction(MCInst *Inst, unsigned Insn,
                                         uint64_t Address,
                                         MCRegisterInfo *Decoder);

static DecodeStatus DecodeRUSBitpInstruction(MCInst *Inst, unsigned Insn,
                                             uint64_t Address,
                                             MCRegisterInfo *Decoder);

static DecodeStatus DecodeRUSSrcDstBitpInstruction(MCInst *Inst, unsigned Insn,
                                                   uint64_t Address,
                                                   MCRegisterInfo *Decoder);

static DecodeStatus DecodeL2RInstruction(MCInst *Inst, unsigned Insn,
                                         uint64_t Address,
                                         MCRegisterInfo *Decoder);

static DecodeStatus DecodeLR2RInstruction(MCInst *Inst, unsigned Insn,
                                          uint64_t Address,
                                          MCRegisterInfo *Decoder);

static DecodeStatus Decode3RInstruction(MCInst *Inst, unsigned Insn,
                                        uint64_t Address,
                                        MCRegisterInfo *Decoder);

static DecodeStatus Decode3RImmInstruction(MCInst *Inst, unsigned Insn,
                                           uint64_t Address,
                                           MCRegisterInfo *Decoder);

static DecodeStatus Decode2RUSInstruction(MCInst *Inst, unsigned Insn,
                                          uint64_t Address,
                                          MCRegisterInfo *Decoder);

static DecodeStatus Decode2RUSBitpInstruction(MCInst *Inst, unsigned Insn,
                                              uint64_t Address,
                                              MCRegisterInfo *Decoder);

static DecodeStatus DecodeL3RInstruction(MCInst *Inst, unsigned Insn,
                                         uint64_t Address,
                                         MCRegisterInfo *Decoder);

static DecodeStatus DecodeL3RSrcDstInstruction(MCInst *Inst, unsigned Insn,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder);

static DecodeStatus DecodeL2RUSInstruction(MCInst *Inst, unsigned Insn,
                                           uint64_t Address,
                                           MCRegisterInfo *Decoder);

static DecodeStatus DecodeL2RUSBitpInstruction(MCInst *Inst, unsigned Insn,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder);

static DecodeStatus DecodeL6RInstruction(MCInst *Inst, unsigned Insn,
                                         uint64_t Address,
                                         MCRegisterInfo *Decoder);

static DecodeStatus DecodeL5RInstruction(MCInst *Inst, unsigned Insn,
                                         uint64_t Address,
                                         MCRegisterInfo *Decoder);

static DecodeStatus DecodeL4RSrcDstInstruction(MCInst *Inst, unsigned Insn,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder);

static DecodeStatus DecodeL4RSrcDstSrcDstInstruction(MCInst *Inst,
                                                     unsigned Insn,
                                                     uint64_t Address,
                                                     MCRegisterInfo *Decoder);

static unsigned getReg(const MCRegisterInfo *MRI, unsigned RC, unsigned RegNo) {
  const MCRegisterClass *rc = MCRegisterInfo_getRegClass(MRI, RC);
  return rc->RegsBegin[RegNo];
}

#define GET_REGINFO_ENUM
#define GET_INSTRINFO_ENUM
#define MIPS_GET_DISASSEMBLER
#define GET_REGINFO_MC_DESC
#include "XCoreGenDisassemblerTables.inc"

FieldFromInstruction(fieldFromInstruction_2, uint16_t)
    DecodeToMCInst(decodeToMCInst_2, fieldFromInstruction_2,
                   uint16_t) DecodeInstruction(decodeInstruction_2,
                                               fieldFromInstruction_2,
                                               decodeToMCInst_2, uint16_t)

        FieldFromInstruction(fieldFromInstruction_4, uint32_t)
            DecodeToMCInst(decodeToMCInst_4, fieldFromInstruction_4, uint32_t)
                DecodeInstruction(decodeInstruction_4, fieldFromInstruction_4,
                                  decodeToMCInst_4, uint32_t)

                    static DecodeStatus
    DecodeGRRegsRegisterClass(MCInst *Inst, unsigned RegNo, uint64_t Address,
                              MCRegisterInfo *Decoder) {
  if (RegNo > 11)
    return MCDisassembler_Fail;
  unsigned Reg = getReg(Decoder, XCore_GRRegsRegClassID, RegNo);
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeRRegsRegisterClass(MCInst *Inst, unsigned RegNo,
                                             uint64_t Address,
                                             MCRegisterInfo *Decoder) {
  if (RegNo > 15)
    return MCDisassembler_Fail;
  unsigned Reg = getReg(Decoder, XCore_RRegsRegClassID, RegNo);
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeBitpOperand(MCInst *Inst, unsigned Val,
                                      uint64_t Address,
                                      MCRegisterInfo *Decoder) {
  if (Val > 11)
    return MCDisassembler_Fail;
  static const unsigned Values[] = {32 /*bpw*/, 1, 2, 3,  4,  5,
                                    6,          7, 8, 16, 24, 32};
  MCOperand_CreateImm0(Inst, Values[Val]);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeNegImmOperand(MCInst *Inst, unsigned Val,
                                        uint64_t Address,
                                        MCRegisterInfo *Decoder) {
  MCOperand_CreateImm0(Inst, -(int64_t)Val);
  return MCDisassembler_Success;
}

static DecodeStatus Decode2OpInstruction(unsigned Insn, unsigned *Op1,
                                         unsigned *Op2) {
  unsigned Combined = fieldFromInstruction(Insn, 6, 5);
  if (Combined < 27)
    return MCDisassembler_Fail;
  if (fieldFromInstruction(Insn, 5, 1)) {
    if (Combined == 31)
      return MCDisassembler_Fail;
    Combined += 5;
  }
  Combined -= 27;
  unsigned Op1High = Combined % 3;
  unsigned Op2High = Combined / 3;
  *Op1 = (Op1High << 2) | fieldFromInstruction(Insn, 2, 2);
  *Op2 = (Op2High << 2) | fieldFromInstruction(Insn, 0, 2);
  return MCDisassembler_Success;
}

static DecodeStatus Decode3OpInstruction(unsigned Insn, unsigned *Op1,
                                         unsigned *Op2, unsigned *Op3) {
  unsigned Combined = fieldFromInstruction(Insn, 6, 5);
  if (Combined >= 27)
    return MCDisassembler_Fail;

  unsigned Op1High = Combined % 3;
  unsigned Op2High = (Combined / 3) % 3;
  unsigned Op3High = Combined / 9;
  *Op1 = (Op1High << 2) | fieldFromInstruction(Insn, 4, 2);
  *Op2 = (Op2High << 2) | fieldFromInstruction(Insn, 2, 2);
  *Op3 = (Op3High << 2) | fieldFromInstruction(Insn, 0, 2);
  return MCDisassembler_Success;
}

static DecodeStatus Decode2OpInstructionFail(MCInst *Inst, unsigned Insn,
                                             uint64_t Address,
                                             MCRegisterInfo *Decoder) {
  // Try and decode as a 3R instruction.
  unsigned Opcode = fieldFromInstruction(Insn, 11, 5);
  switch (Opcode) {
  case 0x0:
    MCInst_setOpcode(Inst, XCore_STW_2rus);
    return Decode2RUSInstruction(Inst, Insn, Address, Decoder);
  case 0x1:
    MCInst_setOpcode(Inst, XCore_LDW_2rus);
    return Decode2RUSInstruction(Inst, Insn, Address, Decoder);
  case 0x2:
    MCInst_setOpcode(Inst, XCore_ADD_3r);
    return Decode3RInstruction(Inst, Insn, Address, Decoder);
  case 0x3:
    MCInst_setOpcode(Inst, XCore_SUB_3r);
    return Decode3RInstruction(Inst, Insn, Address, Decoder);
  case 0x4:
    MCInst_setOpcode(Inst, XCore_SHL_3r);
    return Decode3RInstruction(Inst, Insn, Address, Decoder);
  case 0x5:
    MCInst_setOpcode(Inst, XCore_SHR_3r);
    return Decode3RInstruction(Inst, Insn, Address, Decoder);
  case 0x6:
    MCInst_setOpcode(Inst, XCore_EQ_3r);
    return Decode3RInstruction(Inst, Insn, Address, Decoder);
  case 0x7:
    MCInst_setOpcode(Inst, XCore_AND_3r);
    return Decode3RInstruction(Inst, Insn, Address, Decoder);
  case 0x8:
    MCInst_setOpcode(Inst, XCore_OR_3r);
    return Decode3RInstruction(Inst, Insn, Address, Decoder);
  case 0x9:
    MCInst_setOpcode(Inst, XCore_LDW_3r);
    return Decode3RInstruction(Inst, Insn, Address, Decoder);
  case 0x10:
    MCInst_setOpcode(Inst, XCore_LD16S_3r);
    return Decode3RInstruction(Inst, Insn, Address, Decoder);
  case 0x11:
    MCInst_setOpcode(Inst, XCore_LD8U_3r);
    return Decode3RInstruction(Inst, Insn, Address, Decoder);
  case 0x12:
    MCInst_setOpcode(Inst, XCore_ADD_2rus);
    return Decode2RUSInstruction(Inst, Insn, Address, Decoder);
  case 0x13:
    MCInst_setOpcode(Inst, XCore_SUB_2rus);
    return Decode2RUSInstruction(Inst, Insn, Address, Decoder);
  case 0x14:
    MCInst_setOpcode(Inst, XCore_SHL_2rus);
    return Decode2RUSBitpInstruction(Inst, Insn, Address, Decoder);
  case 0x15:
    MCInst_setOpcode(Inst, XCore_SHR_2rus);
    return Decode2RUSBitpInstruction(Inst, Insn, Address, Decoder);
  case 0x16:
    MCInst_setOpcode(Inst, XCore_EQ_2rus);
    return Decode2RUSInstruction(Inst, Insn, Address, Decoder);
  case 0x17:
    MCInst_setOpcode(Inst, XCore_TSETR_3r);
    return Decode3RImmInstruction(Inst, Insn, Address, Decoder);
  case 0x18:
    MCInst_setOpcode(Inst, XCore_LSS_3r);
    return Decode3RInstruction(Inst, Insn, Address, Decoder);
  case 0x19:
    MCInst_setOpcode(Inst, XCore_LSU_3r);
    return Decode3RInstruction(Inst, Insn, Address, Decoder);
  }
  return MCDisassembler_Fail;
}

static DecodeStatus Decode2RInstruction(MCInst *Inst, unsigned Insn,
                                        uint64_t Address,
                                        MCRegisterInfo *Decoder) {
  unsigned Op1, Op2;
  DecodeStatus S = Decode2OpInstruction(Insn, &Op1, &Op2);
  if (S != MCDisassembler_Success)
    return Decode2OpInstructionFail(Inst, Insn, Address, Decoder);

  DecodeGRRegsRegisterClass(Inst, Op1, Address, Decoder);
  DecodeGRRegsRegisterClass(Inst, Op2, Address, Decoder);
  return S;
}

static DecodeStatus Decode2RImmInstruction(MCInst *Inst, unsigned Insn,
                                           uint64_t Address,
                                           MCRegisterInfo *Decoder) {
  unsigned Op1, Op2;
  DecodeStatus S = Decode2OpInstruction(Insn, &Op1, &Op2);
  if (S != MCDisassembler_Success)
    return Decode2OpInstructionFail(Inst, Insn, Address, Decoder);

  MCOperand_CreateImm0(Inst, Op1);
  DecodeGRRegsRegisterClass(Inst, Op2, Address, Decoder);
  return S;
}

static DecodeStatus DecodeR2RInstruction(MCInst *Inst, unsigned Insn,
                                         uint64_t Address,
                                         MCRegisterInfo *Decoder) {
  unsigned Op1, Op2;
  DecodeStatus S = Decode2OpInstruction(Insn, &Op2, &Op1);
  if (S != MCDisassembler_Success)
    return Decode2OpInstructionFail(Inst, Insn, Address, Decoder);

  DecodeGRRegsRegisterClass(Inst, Op1, Address, Decoder);
  DecodeGRRegsRegisterClass(Inst, Op2, Address, Decoder);
  return S;
}

static DecodeStatus Decode2RSrcDstInstruction(MCInst *Inst, unsigned Insn,
                                              uint64_t Address,
                                              MCRegisterInfo *Decoder) {
  unsigned Op1, Op2;
  DecodeStatus S = Decode2OpInstruction(Insn, &Op1, &Op2);
  if (S != MCDisassembler_Success)
    return Decode2OpInstructionFail(Inst, Insn, Address, Decoder);

  DecodeGRRegsRegisterClass(Inst, Op1, Address, Decoder);
  DecodeGRRegsRegisterClass(Inst, Op1, Address, Decoder);
  DecodeGRRegsRegisterClass(Inst, Op2, Address, Decoder);
  return S;
}

static DecodeStatus DecodeRUSInstruction(MCInst *Inst, unsigned Insn,
                                         uint64_t Address,
                                         MCRegisterInfo *Decoder) {
  unsigned Op1, Op2;
  DecodeStatus S = Decode2OpInstruction(Insn, &Op1, &Op2);
  if (S != MCDisassembler_Success)
    return Decode2OpInstructionFail(Inst, Insn, Address, Decoder);

  DecodeGRRegsRegisterClass(Inst, Op1, Address, Decoder);
  MCOperand_CreateImm0(Inst, Op2);
  return S;
}

static DecodeStatus DecodeRUSBitpInstruction(MCInst *Inst, unsigned Insn,
                                             uint64_t Address,
                                             MCRegisterInfo *Decoder) {
  unsigned Op1, Op2;
  DecodeStatus S = Decode2OpInstruction(Insn, &Op1, &Op2);
  if (S != MCDisassembler_Success)
    return Decode2OpInstructionFail(Inst, Insn, Address, Decoder);

  DecodeGRRegsRegisterClass(Inst, Op1, Address, Decoder);
  DecodeBitpOperand(Inst, Op2, Address, Decoder);
  return S;
}

static DecodeStatus DecodeRUSSrcDstBitpInstruction(MCInst *Inst, unsigned Insn,
                                                   uint64_t Address,
                                                   MCRegisterInfo *Decoder) {
  unsigned Op1, Op2;
  DecodeStatus S = Decode2OpInstruction(Insn, &Op1, &Op2);
  if (S != MCDisassembler_Success)
    return Decode2OpInstructionFail(Inst, Insn, Address, Decoder);

  DecodeGRRegsRegisterClass(Inst, Op1, Address, Decoder);
  DecodeGRRegsRegisterClass(Inst, Op1, Address, Decoder);
  DecodeBitpOperand(Inst, Op2, Address, Decoder);
  return S;
}

static DecodeStatus DecodeL2OpInstructionFail(MCInst *Inst, unsigned Insn,
                                              uint64_t Address,
                                              MCRegisterInfo *Decoder) {
  // Try and decode as a L3R / L2RUS instruction.
  unsigned Opcode = fieldFromInstruction(Insn, 16, 4) |
                    fieldFromInstruction(Insn, 27, 5) << 4;
  switch (Opcode) {
  case 0x0c:
    MCInst_setOpcode(Inst, XCore_STW_l3r);
    return DecodeL3RInstruction(Inst, Insn, Address, Decoder);
  case 0x1c:
    MCInst_setOpcode(Inst, XCore_XOR_l3r);
    return DecodeL3RInstruction(Inst, Insn, Address, Decoder);
  case 0x2c:
    MCInst_setOpcode(Inst, XCore_ASHR_l3r);
    return DecodeL3RInstruction(Inst, Insn, Address, Decoder);
  case 0x3c:
    MCInst_setOpcode(Inst, XCore_LDAWF_l3r);
    return DecodeL3RInstruction(Inst, Insn, Address, Decoder);
  case 0x4c:
    MCInst_setOpcode(Inst, XCore_LDAWB_l3r);
    return DecodeL3RInstruction(Inst, Insn, Address, Decoder);
  case 0x5c:
    MCInst_setOpcode(Inst, XCore_LDA16F_l3r);
    return DecodeL3RInstruction(Inst, Insn, Address, Decoder);
  case 0x6c:
    MCInst_setOpcode(Inst, XCore_LDA16B_l3r);
    return DecodeL3RInstruction(Inst, Insn, Address, Decoder);
  case 0x7c:
    MCInst_setOpcode(Inst, XCore_MUL_l3r);
    return DecodeL3RInstruction(Inst, Insn, Address, Decoder);
  case 0x8c:
    MCInst_setOpcode(Inst, XCore_DIVS_l3r);
    return DecodeL3RInstruction(Inst, Insn, Address, Decoder);
  case 0x9c:
    MCInst_setOpcode(Inst, XCore_DIVU_l3r);
    return DecodeL3RInstruction(Inst, Insn, Address, Decoder);
  case 0x10c:
    MCInst_setOpcode(Inst, XCore_ST16_l3r);
    return DecodeL3RInstruction(Inst, Insn, Address, Decoder);
  case 0x11c:
    MCInst_setOpcode(Inst, XCore_ST8_l3r);
    return DecodeL3RInstruction(Inst, Insn, Address, Decoder);
  case 0x12c:
    MCInst_setOpcode(Inst, XCore_ASHR_l2rus);
    return DecodeL2RUSBitpInstruction(Inst, Insn, Address, Decoder);
  case 0x12d:
    MCInst_setOpcode(Inst, XCore_OUTPW_l2rus);
    return DecodeL2RUSBitpInstruction(Inst, Insn, Address, Decoder);
  case 0x12e:
    MCInst_setOpcode(Inst, XCore_INPW_l2rus);
    return DecodeL2RUSBitpInstruction(Inst, Insn, Address, Decoder);
  case 0x13c:
    MCInst_setOpcode(Inst, XCore_LDAWF_l2rus);
    return DecodeL2RUSInstruction(Inst, Insn, Address, Decoder);
  case 0x14c:
    MCInst_setOpcode(Inst, XCore_LDAWB_l2rus);
    return DecodeL2RUSInstruction(Inst, Insn, Address, Decoder);
  case 0x15c:
    MCInst_setOpcode(Inst, XCore_CRC_l3r);
    return DecodeL3RSrcDstInstruction(Inst, Insn, Address, Decoder);
  case 0x18c:
    MCInst_setOpcode(Inst, XCore_REMS_l3r);
    return DecodeL3RInstruction(Inst, Insn, Address, Decoder);
  case 0x19c:
    MCInst_setOpcode(Inst, XCore_REMU_l3r);
    return DecodeL3RInstruction(Inst, Insn, Address, Decoder);
  }
  return MCDisassembler_Fail;
}

static DecodeStatus DecodeL2RInstruction(MCInst *Inst, unsigned Insn,
                                         uint64_t Address,
                                         MCRegisterInfo *Decoder) {
  unsigned Op1, Op2;
  DecodeStatus S =
      Decode2OpInstruction(fieldFromInstruction(Insn, 0, 16), &Op1, &Op2);
  if (S != MCDisassembler_Success)
    return DecodeL2OpInstructionFail(Inst, Insn, Address, Decoder);

  DecodeGRRegsRegisterClass(Inst, Op1, Address, Decoder);
  DecodeGRRegsRegisterClass(Inst, Op2, Address, Decoder);
  return S;
}

static DecodeStatus DecodeLR2RInstruction(MCInst *Inst, unsigned Insn,
                                          uint64_t Address,
                                          MCRegisterInfo *Decoder) {
  unsigned Op1, Op2;
  DecodeStatus S =
      Decode2OpInstruction(fieldFromInstruction(Insn, 0, 16), &Op1, &Op2);
  if (S != MCDisassembler_Success)
    return DecodeL2OpInstructionFail(Inst, Insn, Address, Decoder);

  DecodeGRRegsRegisterClass(Inst, Op2, Address, Decoder);
  DecodeGRRegsRegisterClass(Inst, Op1, Address, Decoder);
  return S;
}

static DecodeStatus Decode3RInstruction(MCInst *Inst, unsigned Insn,
                                        uint64_t Address,
                                        MCRegisterInfo *Decoder) {
  unsigned Op1, Op2, Op3;
  DecodeStatus S = Decode3OpInstruction(Insn, &Op1, &Op2, &Op3);
  if (S == MCDisassembler_Success) {
    DecodeGRRegsRegisterClass(Inst, Op1, Address, Decoder);
    DecodeGRRegsRegisterClass(Inst, Op2, Address, Decoder);
    DecodeGRRegsRegisterClass(Inst, Op3, Address, Decoder);
  }
  return S;
}

static DecodeStatus Decode3RImmInstruction(MCInst *Inst, unsigned Insn,
                                           uint64_t Address,
                                           MCRegisterInfo *Decoder) {
  unsigned Op1, Op2, Op3;
  DecodeStatus S = Decode3OpInstruction(Insn, &Op1, &Op2, &Op3);
  if (S == MCDisassembler_Success) {
    MCOperand_CreateImm0(Inst, Op1);
    DecodeGRRegsRegisterClass(Inst, Op2, Address, Decoder);
    DecodeGRRegsRegisterClass(Inst, Op3, Address, Decoder);
  }
  return S;
}

static DecodeStatus Decode2RUSInstruction(MCInst *Inst, unsigned Insn,
                                          uint64_t Address,
                                          MCRegisterInfo *Decoder) {
  unsigned Op1, Op2, Op3;
  DecodeStatus S = Decode3OpInstruction(Insn, &Op1, &Op2, &Op3);
  if (S == MCDisassembler_Success) {
    DecodeGRRegsRegisterClass(Inst, Op1, Address, Decoder);
    DecodeGRRegsRegisterClass(Inst, Op2, Address, Decoder);
    MCOperand_CreateImm0(Inst, Op3);
  }
  return S;
}

static DecodeStatus Decode2RUSBitpInstruction(MCInst *Inst, unsigned Insn,
                                              uint64_t Address,
                                              MCRegisterInfo *Decoder) {
  unsigned Op1, Op2, Op3;
  DecodeStatus S = Decode3OpInstruction(Insn, &Op1, &Op2, &Op3);
  if (S == MCDisassembler_Success) {
    DecodeGRRegsRegisterClass(Inst, Op1, Address, Decoder);
    DecodeGRRegsRegisterClass(Inst, Op2, Address, Decoder);
    DecodeBitpOperand(Inst, Op3, Address, Decoder);
  }
  return S;
}

static DecodeStatus DecodeL3RInstruction(MCInst *Inst, unsigned Insn,
                                         uint64_t Address,
                                         MCRegisterInfo *Decoder) {
  unsigned Op1, Op2, Op3;
  DecodeStatus S =
      Decode3OpInstruction(fieldFromInstruction(Insn, 0, 16), &Op1, &Op2, &Op3);
  if (S == MCDisassembler_Success) {
    DecodeGRRegsRegisterClass(Inst, Op1, Address, Decoder);
    DecodeGRRegsRegisterClass(Inst, Op2, Address, Decoder);
    DecodeGRRegsRegisterClass(Inst, Op3, Address, Decoder);
  }
  return S;
}

static DecodeStatus DecodeL3RSrcDstInstruction(MCInst *Inst, unsigned Insn,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder) {
  unsigned Op1, Op2, Op3;
  DecodeStatus S =
      Decode3OpInstruction(fieldFromInstruction(Insn, 0, 16), &Op1, &Op2, &Op3);
  if (S == MCDisassembler_Success) {
    DecodeGRRegsRegisterClass(Inst, Op1, Address, Decoder);
    DecodeGRRegsRegisterClass(Inst, Op1, Address, Decoder);
    DecodeGRRegsRegisterClass(Inst, Op2, Address, Decoder);
    DecodeGRRegsRegisterClass(Inst, Op3, Address, Decoder);
  }
  return S;
}

static DecodeStatus DecodeL2RUSInstruction(MCInst *Inst, unsigned Insn,
                                           uint64_t Address,
                                           MCRegisterInfo *Decoder) {
  unsigned Op1, Op2, Op3;
  DecodeStatus S =
      Decode3OpInstruction(fieldFromInstruction(Insn, 0, 16), &Op1, &Op2, &Op3);
  if (S == MCDisassembler_Success) {
    DecodeGRRegsRegisterClass(Inst, Op1, Address, Decoder);
    DecodeGRRegsRegisterClass(Inst, Op2, Address, Decoder);
    MCOperand_CreateImm0(Inst, Op3);
  }
  return S;
}

static DecodeStatus DecodeL2RUSBitpInstruction(MCInst *Inst, unsigned Insn,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder) {
  unsigned Op1, Op2, Op3;
  DecodeStatus S =
      Decode3OpInstruction(fieldFromInstruction(Insn, 0, 16), &Op1, &Op2, &Op3);
  if (S == MCDisassembler_Success) {
    DecodeGRRegsRegisterClass(Inst, Op1, Address, Decoder);
    DecodeGRRegsRegisterClass(Inst, Op2, Address, Decoder);
    DecodeBitpOperand(Inst, Op3, Address, Decoder);
  }
  return S;
}

static DecodeStatus DecodeL6RInstruction(MCInst *Inst, unsigned Insn,
                                         uint64_t Address,
                                         MCRegisterInfo *Decoder) {
  unsigned Op1, Op2, Op3, Op4, Op5, Op6;
  DecodeStatus S =
      Decode3OpInstruction(fieldFromInstruction(Insn, 0, 16), &Op1, &Op2, &Op3);
  if (S != MCDisassembler_Success)
    return S;
  S = Decode3OpInstruction(fieldFromInstruction(Insn, 16, 16), &Op4, &Op5,
                           &Op6);
  if (S != MCDisassembler_Success)
    return S;
  DecodeGRRegsRegisterClass(Inst, Op1, Address, Decoder);
  DecodeGRRegsRegisterClass(Inst, Op4, Address, Decoder);
  DecodeGRRegsRegisterClass(Inst, Op2, Address, Decoder);
  DecodeGRRegsRegisterClass(Inst, Op3, Address, Decoder);
  DecodeGRRegsRegisterClass(Inst, Op5, Address, Decoder);
  DecodeGRRegsRegisterClass(Inst, Op6, Address, Decoder);
  return S;
}

static DecodeStatus DecodeL5RInstructionFail(MCInst *Inst, unsigned Insn,
                                             uint64_t Address,
                                             MCRegisterInfo *Decoder) {
  // Try and decode as a L6R instruction.
  MCInst_clear(Inst);
  unsigned Opcode = fieldFromInstruction(Insn, 27, 5);
  switch (Opcode) {
  case 0x00:
    MCInst_setOpcode(Inst, XCore_LMUL_l6r);
    return DecodeL6RInstruction(Inst, Insn, Address, Decoder);
  }
  return MCDisassembler_Fail;
}

static DecodeStatus DecodeL5RInstruction(MCInst *Inst, unsigned Insn,
                                         uint64_t Address,
                                         MCRegisterInfo *Decoder) {
  unsigned Op1, Op2, Op3, Op4, Op5;
  DecodeStatus S =
      Decode3OpInstruction(fieldFromInstruction(Insn, 0, 16), &Op1, &Op2, &Op3);
  if (S != MCDisassembler_Success)
    return DecodeL5RInstructionFail(Inst, Insn, Address, Decoder);
  S = Decode2OpInstruction(fieldFromInstruction(Insn, 16, 16), &Op4, &Op5);
  if (S != MCDisassembler_Success)
    return DecodeL5RInstructionFail(Inst, Insn, Address, Decoder);

  DecodeGRRegsRegisterClass(Inst, Op1, Address, Decoder);
  DecodeGRRegsRegisterClass(Inst, Op4, Address, Decoder);
  DecodeGRRegsRegisterClass(Inst, Op2, Address, Decoder);
  DecodeGRRegsRegisterClass(Inst, Op3, Address, Decoder);
  DecodeGRRegsRegisterClass(Inst, Op5, Address, Decoder);
  return S;
}

static DecodeStatus DecodeL4RSrcDstInstruction(MCInst *Inst, unsigned Insn,
                                               uint64_t Address,
                                               MCRegisterInfo *Decoder) {
  unsigned Op1, Op2, Op3;
  unsigned Op4 = fieldFromInstruction(Insn, 16, 4);
  DecodeStatus S =
      Decode3OpInstruction(fieldFromInstruction(Insn, 0, 16), &Op1, &Op2, &Op3);
  if (S == MCDisassembler_Success) {
    DecodeGRRegsRegisterClass(Inst, Op1, Address, Decoder);
    S = DecodeGRRegsRegisterClass(Inst, Op4, Address, Decoder);
  }
  if (S == MCDisassembler_Success) {
    DecodeGRRegsRegisterClass(Inst, Op4, Address, Decoder);
    DecodeGRRegsRegisterClass(Inst, Op2, Address, Decoder);
    DecodeGRRegsRegisterClass(Inst, Op3, Address, Decoder);
  }
  return S;
}

static DecodeStatus DecodeL4RSrcDstSrcDstInstruction(MCInst *Inst,
                                                     unsigned Insn,
                                                     uint64_t Address,
                                                     MCRegisterInfo *Decoder) {
  unsigned Op1, Op2, Op3;
  unsigned Op4 = fieldFromInstruction(Insn, 16, 4);
  DecodeStatus S =
      Decode3OpInstruction(fieldFromInstruction(Insn, 0, 16), &Op1, &Op2, &Op3);
  if (S == MCDisassembler_Success) {
    DecodeGRRegsRegisterClass(Inst, Op1, Address, Decoder);
    S = DecodeGRRegsRegisterClass(Inst, Op4, Address, Decoder);
  }
  if (S == MCDisassembler_Success) {
    DecodeGRRegsRegisterClass(Inst, Op1, Address, Decoder);
    DecodeGRRegsRegisterClass(Inst, Op4, Address, Decoder);
    DecodeGRRegsRegisterClass(Inst, Op2, Address, Decoder);
    DecodeGRRegsRegisterClass(Inst, Op3, Address, Decoder);
  }
  return S;
}

#endif // CAPSTONE_CAPSTONEXCOREMODULE_H

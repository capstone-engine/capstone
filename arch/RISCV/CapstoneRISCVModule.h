//
// Created by Phosphorus15 on 2021/7/7.
//

#ifndef CAPSTONE_CAPSTONERISCVMODULE_H
#define CAPSTONE_CAPSTONERISCVMODULE_H

static void llvm_unreachable(const char *info) {}
static void assert(int val) {}

static DecodeStatus DecodeVRRegisterClass(MCInst *Inst, uint64_t RegNo,
					  uint64_t Address,
					  MCRegisterInfo *Decoder);

static DecodeStatus DecodeVRM2RegisterClass(MCInst *Inst, uint64_t RegNo,
					    uint64_t Address,
					    MCRegisterInfo *Decoder);

static DecodeStatus DecodeVRM4RegisterClass(MCInst *Inst, uint64_t RegNo,
					    uint64_t Address,
					    MCRegisterInfo *Decoder);

static DecodeStatus DecodeVRM8RegisterClass(MCInst *Inst, uint64_t RegNo,
					    uint64_t Address,
					    MCRegisterInfo *Decoder);

static DecodeStatus decodeVMaskReg(MCInst *Inst, uint64_t RegNo,
				   uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeFPR16RegisterClass(MCInst *Inst, uint64_t RegNo,
					     uint64_t Address,
					     MCRegisterInfo *Decoder);

static DecodeStatus decodeRVCInstrSImm(MCInst *Inst, unsigned Insn,
				       uint64_t Address,
				       MCRegisterInfo *Decoder);

static DecodeStatus decodeRVCInstrRdSImm(MCInst *Inst, unsigned Insn,
					 uint64_t Address,
					 MCRegisterInfo *Decoder);

static DecodeStatus decodeRVCInstrRdRs1UImm(MCInst *Inst, unsigned Insn,
					    uint64_t Address,
					    MCRegisterInfo *Decoder);

static DecodeStatus decodeRVCInstrRdRs2(MCInst *Inst, unsigned Insn,
					uint64_t Address,
					MCRegisterInfo *Decoder);

static DecodeStatus decodeRVCInstrRdRs1Rs2(MCInst *Inst, unsigned Insn,
					   uint64_t Address,
					   MCRegisterInfo *Decoder);

static DecodeStatus DecodeGPRRegisterClass(MCInst *Inst, uint64_t RegNo,
					   uint64_t Address,
					   const void *Decoder);

static DecodeStatus DecodeFPR32RegisterClass(MCInst *Inst, uint64_t RegNo,
					     uint64_t Address,
					     const void *Decoder);

static DecodeStatus DecodeFPR32CRegisterClass(MCInst *Inst, uint64_t RegNo,
					      uint64_t Address,
					      const void *Decoder);

static DecodeStatus DecodeFPR64RegisterClass(MCInst *Inst, uint64_t RegNo,
					     uint64_t Address,
					     const void *Decoder);

static DecodeStatus DecodeFPR64CRegisterClass(MCInst *Inst, uint64_t RegNo,
					      uint64_t Address,
					      const void *Decoder);

static DecodeStatus DecodeGPRNoX0RegisterClass(MCInst *Inst, uint64_t RegNo,
					       uint64_t Address,
					       const void *Decoder);

static DecodeStatus DecodeGPRNoX0X2RegisterClass(MCInst *Inst, uint64_t RegNo,
						 uint64_t Address,
						 const void *Decoder);

static DecodeStatus DecodeGPRCRegisterClass(MCInst *Inst, uint64_t RegNo,
					    uint64_t Address,
					    const void *Decoder);

static DecodeStatus decodeUImmOperand(MCInst *Inst, uint64_t Imm,
				      int64_t Address, const void *Decoder,
				      unsigned N);

static DecodeStatus decodeUImmNonZeroOperand(MCInst *Inst, uint64_t Imm,
					     int64_t Address,
					     const void *Decoder, unsigned N);

static DecodeStatus decodeSImmOperand(MCInst *Inst, uint64_t Imm,
				      int64_t Address, const void *Decoder,
				      unsigned N);

static DecodeStatus decodeSImmNonZeroOperand(MCInst *Inst, uint64_t Imm,
					     int64_t Address,
					     const void *Decoder, unsigned N);

static DecodeStatus decodeSImmOperandAndLsl1(MCInst *Inst, uint64_t Imm,
					     int64_t Address,
					     const void *Decoder, unsigned N);

static DecodeStatus decodeCLUIImmOperand(MCInst *Inst, uint64_t Imm,
					 int64_t Address, const void *Decoder);

static DecodeStatus decodeFRMArg(MCInst *Inst, uint64_t Imm, int64_t Address,
				 const void *Decoder);

#define GET_REGINFO_ENUM
#define GET_INSTRINFO_ENUM
#define MIPS_GET_DISASSEMBLER
#define GET_REGINFO_MC_DESC
#include "RISCVGenDisassemblerTables.inc"

static const unsigned GPRDecoderTable[] = {
    RISCV_X0,  RISCV_X1,  RISCV_X2,  RISCV_X3,  RISCV_X4,  RISCV_X5,  RISCV_X6,
    RISCV_X7,  RISCV_X8,  RISCV_X9,  RISCV_X10, RISCV_X11, RISCV_X12, RISCV_X13,
    RISCV_X14, RISCV_X15, RISCV_X16, RISCV_X17, RISCV_X18, RISCV_X19, RISCV_X20,
    RISCV_X21, RISCV_X22, RISCV_X23, RISCV_X24, RISCV_X25, RISCV_X26, RISCV_X27,
    RISCV_X28, RISCV_X29, RISCV_X30, RISCV_X31};

static DecodeStatus DecodeGPRRegisterClass(MCInst *Inst, uint64_t RegNo,
					   uint64_t Address,
					   const void *Decoder)
{
  unsigned Reg = 0;

  if (RegNo > sizeof(GPRDecoderTable))
    return MCDisassembler_Fail;

  // We must define our own mapping from RegNo to register identifier.
  // Accessing index RegNo in the register class will work in the case that
  // registers were added in ascending order, but not in general.
  Reg = GPRDecoderTable[RegNo];
  // Inst.addOperand(MCOperand::createReg(Reg));
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static const unsigned FPR32DecoderTable[] = {
    RISCV_F0_F,  RISCV_F1_F,  RISCV_F2_F,  RISCV_F3_F,  RISCV_F4_F,
    RISCV_F5_F,  RISCV_F6_F,  RISCV_F7_F,  RISCV_F8_F,  RISCV_F9_F,
    RISCV_F10_F, RISCV_F11_F, RISCV_F12_F, RISCV_F13_F, RISCV_F14_F,
    RISCV_F15_F, RISCV_F16_F, RISCV_F17_F, RISCV_F18_F, RISCV_F19_F,
    RISCV_F20_F, RISCV_F21_F, RISCV_F22_F, RISCV_F23_F, RISCV_F24_F,
    RISCV_F25_F, RISCV_F26_F, RISCV_F27_F, RISCV_F28_F, RISCV_F29_F,
    RISCV_F30_F, RISCV_F31_F};

static DecodeStatus DecodeFPR32RegisterClass(MCInst *Inst, uint64_t RegNo,
					     uint64_t Address,
					     const void *Decoder)
{
  unsigned Reg = 0;

  if (RegNo > sizeof(FPR32DecoderTable))
    return MCDisassembler_Fail;

  // We must define our own mapping from RegNo to register identifier.
  // Accessing index RegNo in the register class will work in the case that
  // registers were added in ascending order, but not in general.
  Reg = FPR32DecoderTable[RegNo];
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeFPR32CRegisterClass(MCInst *Inst, uint64_t RegNo,
					      uint64_t Address,
					      const void *Decoder)
{
  unsigned Reg = 0;

  if (RegNo > 8)
    return MCDisassembler_Fail;
  Reg = FPR32DecoderTable[RegNo + 8];
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static const unsigned FPR64DecoderTable[] = {
    RISCV_F0_D,  RISCV_F1_D,  RISCV_F2_D,  RISCV_F3_D,  RISCV_F4_D,
    RISCV_F5_D,  RISCV_F6_D,  RISCV_F7_D,  RISCV_F8_D,  RISCV_F9_D,
    RISCV_F10_D, RISCV_F11_D, RISCV_F12_D, RISCV_F13_D, RISCV_F14_D,
    RISCV_F15_D, RISCV_F16_D, RISCV_F17_D, RISCV_F18_D, RISCV_F19_D,
    RISCV_F20_D, RISCV_F21_D, RISCV_F22_D, RISCV_F23_D, RISCV_F24_D,
    RISCV_F25_D, RISCV_F26_D, RISCV_F27_D, RISCV_F28_D, RISCV_F29_D,
    RISCV_F30_D, RISCV_F31_D};

static DecodeStatus DecodeFPR64RegisterClass(MCInst *Inst, uint64_t RegNo,
					     uint64_t Address,
					     const void *Decoder)
{
  unsigned Reg = 0;

  if (RegNo > sizeof(FPR64DecoderTable))
    return MCDisassembler_Fail;

  // We must define our own mapping from RegNo to register identifier.
  // Accessing index RegNo in the register class will work in the case that
  // registers were added in ascending order, but not in general.
  Reg = FPR64DecoderTable[RegNo];
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeFPR64CRegisterClass(MCInst *Inst, uint64_t RegNo,
					      uint64_t Address,
					      const void *Decoder)
{
  unsigned Reg = 0;

  if (RegNo > 8)
    return MCDisassembler_Fail;
  Reg = FPR64DecoderTable[RegNo + 8];
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeGPRNoX0RegisterClass(MCInst *Inst, uint64_t RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
  if (RegNo == 0)
    return MCDisassembler_Fail;
  return DecodeGPRRegisterClass(Inst, RegNo, Address, Decoder);
}

static DecodeStatus DecodeGPRNoX0X2RegisterClass(MCInst *Inst, uint64_t RegNo,
						 uint64_t Address,
						 const void *Decoder)
{
  if (RegNo == 2)
    return MCDisassembler_Fail;
  return DecodeGPRNoX0RegisterClass(Inst, RegNo, Address, Decoder);
}

static DecodeStatus DecodeGPRCRegisterClass(MCInst *Inst, uint64_t RegNo,
					    uint64_t Address,
					    const void *Decoder)
{
  unsigned Reg = 0;

  if (RegNo > 8)
    return MCDisassembler_Fail;

  Reg = GPRDecoderTable[RegNo + 8];
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

// Add implied SP operand for instructions *SP compressed instructions. The SP
// operand isn't explicitly encoded in the instruction.
static void addImplySP(MCInst *Inst, int64_t Address, const void *Decoder)
{
  if (MCInst_getOpcode(Inst) == RISCV_C_LWSP ||
      MCInst_getOpcode(Inst) == RISCV_C_SWSP ||
      MCInst_getOpcode(Inst) == RISCV_C_LDSP ||
      MCInst_getOpcode(Inst) == RISCV_C_SDSP ||
      MCInst_getOpcode(Inst) == RISCV_C_FLWSP ||
      MCInst_getOpcode(Inst) == RISCV_C_FSWSP ||
      MCInst_getOpcode(Inst) == RISCV_C_FLDSP ||
      MCInst_getOpcode(Inst) == RISCV_C_FSDSP ||
      MCInst_getOpcode(Inst) == RISCV_C_ADDI4SPN) {
    DecodeGPRRegisterClass(Inst, 2, Address, Decoder);
  }

  if (MCInst_getOpcode(Inst) == RISCV_C_ADDI16SP) {
    DecodeGPRRegisterClass(Inst, 2, Address, Decoder);
    DecodeGPRRegisterClass(Inst, 2, Address, Decoder);
  }
}

static DecodeStatus decodeUImmOperand(MCInst *Inst, uint64_t Imm,
				      int64_t Address, const void *Decoder,
				      unsigned N)
{
  // CS_ASSERT(isUInt<N>(Imm) && "Invalid immediate");
  addImplySP(Inst, Address, Decoder);
  // Inst.addOperand(MCOperand::createImm(Imm));
  MCOperand_CreateImm0(Inst, Imm);
  return MCDisassembler_Success;
}

static DecodeStatus decodeUImmNonZeroOperand(MCInst *Inst, uint64_t Imm,
					     int64_t Address,
					     const void *Decoder, unsigned N)
{
  if (Imm == 0)
    return MCDisassembler_Fail;
  return decodeUImmOperand(Inst, Imm, Address, Decoder, N);
}

static DecodeStatus decodeSImmOperand(MCInst *Inst, uint64_t Imm,
				      int64_t Address, const void *Decoder,
				      unsigned N)
{
  // CS_ASSERT(isUInt<N>(Imm) && "Invalid immediate");
  addImplySP(Inst, Address, Decoder);
  // Sign-extend the number in the bottom N bits of Imm
  // Inst.addOperand(MCOperand::createImm(SignExtend64<N>(Imm)));
  MCOperand_CreateImm0(Inst, SignExtend64(Imm, N));
  return MCDisassembler_Success;
}

static DecodeStatus decodeSImmNonZeroOperand(MCInst *Inst, uint64_t Imm,
					     int64_t Address,
					     const void *Decoder, unsigned N)
{
  if (Imm == 0)
    return MCDisassembler_Fail;
  return decodeSImmOperand(Inst, Imm, Address, Decoder, N);
}

static DecodeStatus decodeSImmOperandAndLsl1(MCInst *Inst, uint64_t Imm,
					     int64_t Address,
					     const void *Decoder, unsigned N)
{
  // CS_ASSERT(isUInt<N>(Imm) && "Invalid immediate");
  // Sign-extend the number in the bottom N bits of Imm after accounting for
  // the fact that the N bit immediate is stored in N-1 bits (the LSB is
  // always zero)
  // Inst.addOperand(MCOperand::createImm(SignExtend64<N>(Imm << 1)));
  MCOperand_CreateImm0(Inst, SignExtend64(Imm << 1, N));
  return MCDisassembler_Success;
}

static DecodeStatus decodeCLUIImmOperand(MCInst *Inst, uint64_t Imm,
					 int64_t Address, const void *Decoder)
{
  // CS_ASSERT(isUInt<6>(Imm) && "Invalid immediate");
  if (Imm > 31) {
    Imm = (SignExtend64(Imm, 6) & 0xfffff);
  }
  // Inst.addOperand(MCOperand::createImm(Imm));
  MCOperand_CreateImm0(Inst, Imm);
  return MCDisassembler_Success;
}

static DecodeStatus decodeFRMArg(MCInst *Inst, uint64_t Imm, int64_t Address,
				 const void *Decoder)
{
  // CS_ASSERT(isUInt<3>(Imm) && "Invalid immediate");
  if (!RISCVFPRndMode_isValidRoundingMode(Imm))
    return MCDisassembler_Fail;

  // Inst.addOperand(MCOperand::createImm(Imm));
  MCOperand_CreateImm0(Inst, Imm);
  return MCDisassembler_Success;
}

static DecodeStatus decodeRVCInstrSImm(MCInst *Inst, unsigned Insn,
				       uint64_t Address,
				       MCRegisterInfo *Decoder)
{
  uint64_t SImm6 =
      fieldFromInstruction(Insn, 12, 1) << 5 | fieldFromInstruction(Insn, 2, 5);
  DecodeStatus Result = decodeSImmOperand(Inst, SImm6, Address, Decoder, 6);
  (void)Result;
  assert(Result == MCDisassembler_Success && "Invalid immediate");
  return MCDisassembler_Success;
}

static DecodeStatus decodeRVCInstrRdSImm(MCInst *Inst, unsigned Insn,
					 uint64_t Address,
					 MCRegisterInfo *Decoder)
{
  DecodeGPRRegisterClass(Inst, 0, Address, Decoder);
  uint64_t SImm6 =
      fieldFromInstruction(Insn, 12, 1) << 5 | fieldFromInstruction(Insn, 2, 5);
  DecodeStatus Result = decodeSImmOperand(Inst, SImm6, Address, Decoder, 6);
  (void)Result;
  assert(Result == MCDisassembler_Success && "Invalid immediate");
  return MCDisassembler_Success;
}

static DecodeStatus decodeRVCInstrRdRs1UImm(MCInst *Inst, unsigned Insn,
					    uint64_t Address,
					    MCRegisterInfo *Decoder)
{
  DecodeGPRRegisterClass(Inst, 0, Address, Decoder);
  MCInst_addOperand2(Inst, MCInst_getOperand(Inst, 0));
  uint64_t UImm6 =
      fieldFromInstruction(Insn, 12, 1) << 5 | fieldFromInstruction(Insn, 2, 5);
  DecodeStatus Result = decodeUImmOperand(Inst, UImm6, Address, Decoder, 6);
  (void)Result;
  assert(Result == MCDisassembler_Success && "Invalid immediate");
  return MCDisassembler_Success;
}

static DecodeStatus decodeRVCInstrRdRs2(MCInst *Inst, unsigned Insn,
					uint64_t Address,
					MCRegisterInfo *Decoder)
{
  unsigned Rd = fieldFromInstruction(Insn, 7, 5);
  unsigned Rs2 = fieldFromInstruction(Insn, 2, 5);
  DecodeGPRRegisterClass(Inst, Rd, Address, Decoder);
  DecodeGPRRegisterClass(Inst, Rs2, Address, Decoder);
  return MCDisassembler_Success;
}

static DecodeStatus decodeRVCInstrRdRs1Rs2(MCInst *Inst, unsigned Insn,
					   uint64_t Address,
					   MCRegisterInfo *Decoder)
{
  unsigned Rd = fieldFromInstruction(Insn, 7, 5);
  unsigned Rs2 = fieldFromInstruction(Insn, 2, 5);
  DecodeGPRRegisterClass(Inst, Rd, Address, Decoder);
  MCInst_addOperand2(Inst, MCInst_getOperand(Inst, 0));
  DecodeGPRRegisterClass(Inst, Rs2, Address, Decoder);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeVRRegisterClass(MCInst *Inst, uint64_t RegNo,
					  uint64_t Address,
					  MCRegisterInfo *Decoder)
{
  if (RegNo >= 32)
    return MCDisassembler_Fail;

  unsigned Reg = RISCV_V0 + RegNo;
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

// fixme super reg

static DecodeStatus DecodeVRM2RegisterClass(MCInst *Inst, uint64_t RegNo,
					    uint64_t Address,
					    MCRegisterInfo *Decoder)
{
  //  if (RegNo >= 32)
  //    return MCDisassembler_Fail;
  //
  //  if (RegNo % 2)
  //    return MCDisassembler_Fail;
  //
  //  const RISCVDisassembler *Dis =
  //  static_cast(Decoder, const RISCVDisassembler *);
  //  const MCRegisterInfo *RI = Dis->getContext().getRegisterInfo();
  //  MCRegister Reg =
  //      RI->getMatchingSuperReg(RISCV_V0 + RegNo, RISCV_sub_vrm1_0,
  //			      &RISCVMCRegisterClasses[RISCV_VRM2RegClassID]);
  //
  //  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeVRM4RegisterClass(MCInst *Inst, uint64_t RegNo,
					    uint64_t Address,
					    MCRegisterInfo *Decoder)
{
  //  if (RegNo >= 32)
  //    return MCDisassembler_Fail;
  //
  //  if (RegNo % 4)
  //    return MCDisassembler_Fail;
  //
  //  const RISCVDisassembler *Dis =
  //  static_cast(Decoder, const RISCVDisassembler *);
  //  const MCRegisterInfo *RI = Dis->getContext().getRegisterInfo();
  //  MCRegister Reg =
  //      RI->getMatchingSuperReg(RISCV_V0 + RegNo, RISCV_sub_vrm1_0,
  //			      &RISCVMCRegisterClasses[RISCV_VRM4RegClassID]);
  //
  //  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeVRM8RegisterClass(MCInst *Inst, uint64_t RegNo,
					    uint64_t Address,
					    MCRegisterInfo *Decoder)
{
  if (RegNo >= 32)
    return MCDisassembler_Fail;

  if (RegNo % 8)
    return MCDisassembler_Fail;
  //
  //  const RISCVDisassembler *Dis =
  //  static_cast(Decoder, const RISCVDisassembler *);
  //  const MCRegisterInfo *RI = Dis->getContext().getRegisterInfo();
  //  MCRegister Reg =
  //      RI->getMatchingSuperReg(RISCV_V0 + RegNo, RISCV_sub_vrm1_0,
  //			      &RISCVMCRegisterClasses[RISCV_VRM8RegClassID]);
  //
  //  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus decodeVMaskReg(MCInst *Inst, uint64_t RegNo,
				   uint64_t Address, MCRegisterInfo *Decoder)
{
  switch (RegNo) {
  default:
    return MCDisassembler_Fail;
  case 0:
    MCOperand_CreateReg0(Inst, RISCV_V0);
    break;
  case 1:
    break;
  }
  return MCDisassembler_Success;
}

static DecodeStatus DecodeFPR16RegisterClass(MCInst *Inst, uint64_t RegNo,
					     uint64_t Address,
					     MCRegisterInfo *Decoder)
{
  if (RegNo >= 32)
    return MCDisassembler_Fail;

  unsigned Reg = RISCV_F0_H + RegNo;
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

#endif // CAPSTONE_CAPSTONERISCVMODULE_H

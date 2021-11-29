static void llvm_unreachable(const char *info) {}
static void assert(int val) {}
static DecodeStatus DecodeGPR64RegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     MCRegisterInfo *Decoder);

static DecodeStatus DecodeCPU16RegsRegisterClass(MCInst *Inst, unsigned RegNo,
						 uint64_t Address,
						 MCRegisterInfo *Decoder);

static DecodeStatus DecodeGPRMM16RegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodeGPRMM16ZeroRegisterClass(MCInst *Inst, unsigned RegNo,
						   uint64_t Address,
						   MCRegisterInfo *Decoder);

static DecodeStatus DecodeGPRMM16MovePRegisterClass(MCInst *Inst,
						    unsigned RegNo,
						    uint64_t Address,
						    MCRegisterInfo *Decoder);

static DecodeStatus DecodeGPR32RegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     MCRegisterInfo *Decoder);

static DecodeStatus DecodePtrRegisterClass(MCInst *Inst, unsigned Insn,
					   uint64_t Address,
					   MCRegisterInfo *Decoder);

static DecodeStatus DecodeDSPRRegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    MCRegisterInfo *Decoder);

static DecodeStatus DecodeFGR64RegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     MCRegisterInfo *Decoder);

static DecodeStatus DecodeFGR32RegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     MCRegisterInfo *Decoder);

static DecodeStatus DecodeCCRRegisterClass(MCInst *Inst, unsigned RegNo,
					   uint64_t Address,
					   MCRegisterInfo *Decoder);

static DecodeStatus DecodeFCCRegisterClass(MCInst *Inst, unsigned RegNo,
					   uint64_t Address,
					   MCRegisterInfo *Decoder);

static DecodeStatus DecodeFGRCCRegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     MCRegisterInfo *Decoder);

static DecodeStatus DecodeHWRegsRegisterClass(MCInst *Inst, unsigned Insn,
					      uint64_t Address,
					      MCRegisterInfo *Decoder);

static DecodeStatus DecodeAFGR64RegisterClass(MCInst *Inst, unsigned RegNo,
					      uint64_t Address,
					      MCRegisterInfo *Decoder);

static DecodeStatus DecodeACC64DSPRegisterClass(MCInst *Inst, unsigned RegNo,
						uint64_t Address,
						MCRegisterInfo *Decoder);

static DecodeStatus DecodeHI32DSPRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodeLO32DSPRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodeMSA128BRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodeMSA128HRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodeMSA128WRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodeMSA128DRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodeMSACtrlRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodeCOP0RegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    MCRegisterInfo *Decoder);

static DecodeStatus DecodeCOP2RegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    MCRegisterInfo *Decoder);

static DecodeStatus DecodeBranchTarget(MCInst *Inst, unsigned Offset,
				       uint64_t Address,
				       MCRegisterInfo *Decoder);

static DecodeStatus DecodeBranchTarget1SImm16(MCInst *Inst, unsigned Offset,
					      uint64_t Address,
					      MCRegisterInfo *Decoder);

static DecodeStatus DecodeJumpTarget(MCInst *Inst, unsigned Insn,
				     uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeBranchTarget21(MCInst *Inst, unsigned Offset,
					 uint64_t Address,
					 MCRegisterInfo *Decoder);

static DecodeStatus DecodeBranchTarget21MM(MCInst *Inst, unsigned Offset,
					   uint64_t Address,
					   MCRegisterInfo *Decoder);

static DecodeStatus DecodeBranchTarget26(MCInst *Inst, unsigned Offset,
					 uint64_t Address,
					 MCRegisterInfo *Decoder);

static DecodeStatus DecodeBranchTarget7MM(MCInst *Inst, unsigned Offset,
					  uint64_t Address,
					  MCRegisterInfo *Decoder);

static DecodeStatus DecodeBranchTarget10MM(MCInst *Inst, unsigned Offset,
					   uint64_t Address,
					   MCRegisterInfo *Decoder);

static DecodeStatus DecodeBranchTargetMM(MCInst *Inst, unsigned Offset,
					 uint64_t Address,
					 MCRegisterInfo *Decoder);

static DecodeStatus DecodeBranchTarget26MM(MCInst *Inst, unsigned Offset,
					   uint64_t Address,
					   MCRegisterInfo *Decoder);

static DecodeStatus DecodeJumpTargetMM(MCInst *Inst, unsigned Insn,
				       uint64_t Address,
				       MCRegisterInfo *Decoder);

static DecodeStatus DecodeJumpTargetXMM(MCInst *Inst, unsigned Insn,
					uint64_t Address,
					MCRegisterInfo *Decoder);

static DecodeStatus DecodeMem(MCInst *Inst, unsigned Insn, uint64_t Address,
			      MCRegisterInfo *Decoder);

static DecodeStatus DecodeMemEVA(MCInst *Inst, unsigned Insn, uint64_t Address,
				 MCRegisterInfo *Decoder);

static DecodeStatus DecodeLoadByte15(MCInst *Inst, unsigned Insn,
				     uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeCacheOp(MCInst *Inst, unsigned Insn, uint64_t Address,
				  MCRegisterInfo *Decoder);

static DecodeStatus DecodeCacheeOp_CacheOpR6(MCInst *Inst, unsigned Insn,
					     uint64_t Address,
					     MCRegisterInfo *Decoder);

static DecodeStatus DecodeCacheOpMM(MCInst *Inst, unsigned Insn,
				    uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodePrefeOpMM(MCInst *Inst, unsigned Insn,
				    uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeSyncI(MCInst *Inst, unsigned Insn, uint64_t Address,
				MCRegisterInfo *Decoder);

static DecodeStatus DecodeSyncI_MM(MCInst *Inst, unsigned Insn,
				   uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeSynciR6(MCInst *Inst, unsigned Insn, uint64_t Address,
				  MCRegisterInfo *Decoder);

static DecodeStatus DecodeMSA128Mem(MCInst *Inst, unsigned Insn,
				    uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeMemMMImm4(MCInst *Inst, unsigned Insn,
				    uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeMemMMSPImm5Lsl2(MCInst *Inst, unsigned Insn,
					  uint64_t Address,
					  MCRegisterInfo *Decoder);

static DecodeStatus DecodeMemMMGPImm7Lsl2(MCInst *Inst, unsigned Insn,
					  uint64_t Address,
					  MCRegisterInfo *Decoder);

static DecodeStatus DecodeMemMMReglistImm4Lsl2(MCInst *Inst, unsigned Insn,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodeMemMMImm9(MCInst *Inst, unsigned Insn,
				    uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeMemMMImm12(MCInst *Inst, unsigned Insn,
				     uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeMemMMImm16(MCInst *Inst, unsigned Insn,
				     uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeFMem(MCInst *Inst, unsigned Insn, uint64_t Address,
			       MCRegisterInfo *Decoder);

static DecodeStatus DecodeFMemMMR2(MCInst *Inst, unsigned Insn,
				   uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeFMem2(MCInst *Inst, unsigned Insn, uint64_t Address,
				MCRegisterInfo *Decoder);

static DecodeStatus DecodeFMem3(MCInst *Inst, unsigned Insn, uint64_t Address,
				MCRegisterInfo *Decoder);

static DecodeStatus DecodeFMemCop2R6(MCInst *Inst, unsigned Insn,
				     uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeFMemCop2MMR6(MCInst *Inst, unsigned Insn,
				       uint64_t Address,
				       MCRegisterInfo *Decoder);

static DecodeStatus DecodeSpecial3LlSc(MCInst *Inst, unsigned Insn,
				       uint64_t Address,
				       MCRegisterInfo *Decoder);

static DecodeStatus DecodeAddiur2Simm7(MCInst *Inst, unsigned Value,
				       uint64_t Address,
				       MCRegisterInfo *Decoder);

static DecodeStatus DecodeLi16Imm(MCInst *Inst, unsigned Value,
				  uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodePOOL16BEncodedField(MCInst *Inst, unsigned Value,
					      uint64_t Address,
					      MCRegisterInfo *Decoder);

static DecodeStatus DecodeUImmWithOffsetAndScale(MCInst *Inst, unsigned Value,
						 uint64_t Address,
						 MCRegisterInfo *Decoder,
						 unsigned, unsigned, unsigned);

static DecodeStatus DecodeUImmWithOffset(MCInst *Inst, unsigned Value,
					 uint64_t Address,
					 MCRegisterInfo *Decoder, unsigned Bits,
					 unsigned Offset)
{
  return DecodeUImmWithOffsetAndScale(Inst, Value, Address, Decoder, Bits,
				      Offset, 1);
}
static DecodeStatus DecodeSImmWithOffsetAndScale(MCInst *Inst, unsigned Value,
						 uint64_t Address,
						 MCRegisterInfo *Decoder,
						 unsigned);

static DecodeStatus DecodeInsSize(MCInst *Inst, unsigned Insn, uint64_t Address,
				  MCRegisterInfo *Decoder);

static DecodeStatus DecodeSimm19Lsl2(MCInst *Inst, unsigned Insn,
				     uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeSimm18Lsl3(MCInst *Inst, unsigned Insn,
				     uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeSimm9SP(MCInst *Inst, unsigned Insn, uint64_t Address,
				  MCRegisterInfo *Decoder);

static DecodeStatus DecodeANDI16Imm(MCInst *Inst, unsigned Insn,
				    uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeSimm23Lsl2(MCInst *Inst, unsigned Insn,
				     uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeINSVE_DF(MCInst *MI, unsigned insn, uint64_t Address,
				   MCRegisterInfo *Decoder);

static DecodeStatus DecodeDAHIDATIMMR6(MCInst *MI, unsigned insn,
				       uint64_t Address,
				       MCRegisterInfo *Decoder);

static DecodeStatus DecodeDAHIDATI(MCInst *MI, unsigned insn, uint64_t Address,
				   MCRegisterInfo *Decoder);

static DecodeStatus DecodeDAHIDATIMMR6(MCInst *MI, unsigned insn,
				       uint64_t Address,
				       MCRegisterInfo *Decoder);

static DecodeStatus DecodeDAHIDATI(MCInst *MI, unsigned insn, uint64_t Address,
				   MCRegisterInfo *Decoder);

static DecodeStatus DecodeAddiGroupBranch(MCInst *MI, unsigned insn,
					  uint64_t Address,
					  MCRegisterInfo *Decoder);

static DecodeStatus DecodePOP35GroupBranchMMR6(MCInst *MI, unsigned insn,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodeDaddiGroupBranch(MCInst *MI, unsigned insn,
					   uint64_t Address,
					   MCRegisterInfo *Decoder);

static DecodeStatus DecodePOP37GroupBranchMMR6(MCInst *MI, unsigned insn,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodePOP65GroupBranchMMR6(MCInst *MI, unsigned insn,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodePOP75GroupBranchMMR6(MCInst *MI, unsigned insn,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodeBlezlGroupBranch(MCInst *MI, unsigned insn,
					   uint64_t Address,
					   MCRegisterInfo *Decoder);

static DecodeStatus DecodeBgtzlGroupBranch(MCInst *MI, unsigned insn,
					   uint64_t Address,
					   MCRegisterInfo *Decoder);

static DecodeStatus DecodeBgtzGroupBranch(MCInst *MI, unsigned insn,
					  uint64_t Address,
					  MCRegisterInfo *Decoder);

static DecodeStatus DecodeBlezGroupBranch(MCInst *MI, unsigned insn,
					  uint64_t Address,
					  MCRegisterInfo *Decoder);

static DecodeStatus DecodeBgtzGroupBranchMMR6(MCInst *MI, unsigned insn,
					      uint64_t Address,
					      MCRegisterInfo *Decoder);

static DecodeStatus DecodeBlezGroupBranchMMR6(MCInst *MI, unsigned insn,
					      uint64_t Address,
					      MCRegisterInfo *Decoder);

static DecodeStatus DecodeDINS(MCInst *MI, unsigned Insn, uint64_t Address,
			       MCRegisterInfo *Decoder);

static DecodeStatus DecodeDEXT(MCInst *MI, unsigned Insn, uint64_t Address,
			       MCRegisterInfo *Decoder);

static DecodeStatus DecodeCRC(MCInst *MI, unsigned Insn, uint64_t Address,
			      MCRegisterInfo *Decoder);

static DecodeStatus DecodeRegListOperand(MCInst *Inst, unsigned Insn,
					 uint64_t Address,
					 MCRegisterInfo *Decoder);

static DecodeStatus DecodeRegListOperand16(MCInst *Inst, unsigned Insn,
					   uint64_t Address,
					   MCRegisterInfo *Decoder);

static DecodeStatus DecodeMovePRegPair(MCInst *Inst, unsigned RegPair,
				       uint64_t Address,
				       MCRegisterInfo *Decoder);

static DecodeStatus DecodeMovePOperands(MCInst *Inst, unsigned Insn,
					uint64_t Address,
					MCRegisterInfo *Decoder);

#include "MipsGenDisassemblerTables.inc"

static DecodeStatus DecodeINSVE_DF(MCInst *MI, unsigned insn, uint64_t Address,
				   MCRegisterInfo *Decoder)
{
  DecodeStatus (*RegDecoder)(MCInst *, unsigned, uint64_t, MCRegisterInfo *);

  // The size of the n field depends on the element size
  // The register class also depends on this.
  unsigned tmp = fieldFromInstruction(insn, 17, 5);
  unsigned NSize = 0;
  RegDecoder = 0x0;
  if ((tmp & 0x18) == 0x00) { // INSVE_B
    NSize = 4;
    RegDecoder = DecodeMSA128BRegisterClass;
  } else if ((tmp & 0x1c) == 0x10) { // INSVE_H
    NSize = 3;
    RegDecoder = DecodeMSA128HRegisterClass;
  } else if ((tmp & 0x1e) == 0x18) { // INSVE_W
    NSize = 2;
    RegDecoder = DecodeMSA128WRegisterClass;
  } else if ((tmp & 0x1f) == 0x1c) { // INSVE_D
    NSize = 1;
    RegDecoder = DecodeMSA128DRegisterClass;
  } else
    llvm_unreachable("Invalid encoding");

  assert(NSize != 0 && RegDecoder != 0x0);

  // $wd
  tmp = fieldFromInstruction(insn, 6, 5);
  if (RegDecoder(MI, tmp, Address, Decoder) == MCDisassembler_Fail)
    return MCDisassembler_Fail;
  // $wd_in
  if (RegDecoder(MI, tmp, Address, Decoder) == MCDisassembler_Fail)
    return MCDisassembler_Fail;
  // $n
  tmp = fieldFromInstruction(insn, 16, NSize);
  MCOperand_CreateImm0(MI, tmp);
  // $ws
  tmp = fieldFromInstruction(insn, 11, 5);
  if (RegDecoder(MI, tmp, Address, Decoder) == MCDisassembler_Fail)
    return MCDisassembler_Fail;
  // $n2
  MCOperand_CreateImm0(MI, 0);

  return MCDisassembler_Success;
}

static DecodeStatus DecodeDAHIDATIMMR6(MCInst *MI, unsigned insn,
				       uint64_t Address,
				       MCRegisterInfo *Decoder)
{
  unsigned Rs = fieldFromInstruction(insn, 16, 5);
  unsigned Imm = fieldFromInstruction(insn, 0, 16);
  MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR64RegClassID, Rs));
  MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR64RegClassID, Rs));
  MCOperand_CreateImm0(MI, Imm);

  return MCDisassembler_Success;
}

static DecodeStatus DecodeDAHIDATI(MCInst *MI, unsigned insn, uint64_t Address,
				   MCRegisterInfo *Decoder)
{
  unsigned Rs = fieldFromInstruction(insn, 21, 5);
  unsigned Imm = fieldFromInstruction(insn, 0, 16);
  MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR64RegClassID, Rs));
  MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR64RegClassID, Rs));
  MCOperand_CreateImm0(MI, Imm);

  return MCDisassembler_Success;
}

static DecodeStatus DecodeAddiGroupBranch(MCInst *MI, unsigned insn,
					  uint64_t Address,
					  MCRegisterInfo *Decoder)
{
  // If we are called then we can assume that MIPS32r6/MIPS64r6 is enabled
  // (otherwise we would have matched the ADDI instruction from the earlier
  // ISA's instead).
  //
  // We have:
  //    0b001000 sssss ttttt iiiiiiiiiiiiiiii
  //      BOVC if rs >= rt
  //      BEQZALC if rs == 0 && rt != 0
  //      BEQC if rs < rt && rs != 0

  unsigned Rs = fieldFromInstruction(insn, 21, 5);
  unsigned Rt = fieldFromInstruction(insn, 16, 5);
  int64_t Imm = SignExtend64(fieldFromInstruction(insn, 0, 16), 16) * 4 + 4;
  bool HasRs = false;

  if (Rs >= Rt) {
    MCInst_setOpcode(MI, Mips_BOVC);
    HasRs = true;
  } else if (Rs != 0 && Rs < Rt) {
    MCInst_setOpcode(MI, Mips_BEQC);
    HasRs = true;
  } else
    MCInst_setOpcode(MI, Mips_BEQZALC);

  if (HasRs)
    MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rs));

  MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rt));
  MCOperand_CreateImm0(MI, Imm);

  return MCDisassembler_Success;
}

static DecodeStatus DecodePOP35GroupBranchMMR6(MCInst *MI, unsigned insn,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  unsigned Rt = fieldFromInstruction(insn, 21, 5);
  unsigned Rs = fieldFromInstruction(insn, 16, 5);
  int64_t Imm = 0;

  if (Rs >= Rt) {
    MCInst_setOpcode(MI, Mips_BOVC_MMR6);
    MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rt));
    MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rs));
    Imm = SignExtend64(fieldFromInstruction(insn, 0, 16), 16) * 2 + 4;
  } else if (Rs != 0 && Rs < Rt) {
    MCInst_setOpcode(MI, Mips_BEQC_MMR6);
    MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rs));
    MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rt));
    Imm = SignExtend64(fieldFromInstruction(insn, 0, 16), 16) * 4 + 4;
  } else {
    MCInst_setOpcode(MI, Mips_BEQZALC_MMR6);
    MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rt));
    Imm = SignExtend64(fieldFromInstruction(insn, 0, 16), 16) * 2 + 4;
  }

  MCOperand_CreateImm0(MI, Imm);

  return MCDisassembler_Success;
}

static DecodeStatus DecodeDaddiGroupBranch(MCInst *MI, unsigned insn,
					   uint64_t Address,
					   MCRegisterInfo *Decoder)
{
  // If we are called then we can assume that MIPS32r6/MIPS64r6 is enabled
  // (otherwise we would have matched the ADDI instruction from the earlier
  // ISA's instead).
  //
  // We have:
  //    0b011000 sssss ttttt iiiiiiiiiiiiiiii
  //      BNVC if rs >= rt
  //      BNEZALC if rs == 0 && rt != 0
  //      BNEC if rs < rt && rs != 0

  unsigned Rs = fieldFromInstruction(insn, 21, 5);
  unsigned Rt = fieldFromInstruction(insn, 16, 5);
  int64_t Imm = SignExtend64(fieldFromInstruction(insn, 0, 16), 16) * 4 + 4;
  bool HasRs = false;

  if (Rs >= Rt) {
    MCInst_setOpcode(MI, Mips_BNVC);
    HasRs = true;
  } else if (Rs != 0 && Rs < Rt) {
    MCInst_setOpcode(MI, Mips_BNEC);
    HasRs = true;
  } else
    MCInst_setOpcode(MI, Mips_BNEZALC);

  if (HasRs)
    MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rs));

  MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rt));
  MCOperand_CreateImm0(MI, Imm);

  return MCDisassembler_Success;
}

static DecodeStatus DecodePOP37GroupBranchMMR6(MCInst *MI, unsigned insn,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  unsigned Rt = fieldFromInstruction(insn, 21, 5);
  unsigned Rs = fieldFromInstruction(insn, 16, 5);
  int64_t Imm = 0;

  if (Rs >= Rt) {
    MCInst_setOpcode(MI, Mips_BNVC_MMR6);
    MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rt));
    MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rs));
    Imm = SignExtend64(fieldFromInstruction(insn, 0, 16), 16) * 2 + 4;
  } else if (Rs != 0 && Rs < Rt) {
    MCInst_setOpcode(MI, Mips_BNEC_MMR6);
    MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rs));
    MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rt));
    Imm = SignExtend64(fieldFromInstruction(insn, 0, 16), 16) * 4 + 4;
  } else {
    MCInst_setOpcode(MI, Mips_BNEZALC_MMR6);
    MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rt));
    Imm = SignExtend64(fieldFromInstruction(insn, 0, 16), 16) * 2 + 4;
  }

  MCOperand_CreateImm0(MI, Imm);

  return MCDisassembler_Success;
}

static DecodeStatus DecodePOP65GroupBranchMMR6(MCInst *MI, unsigned insn,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  // We have:
  //    0b110101 ttttt sssss iiiiiiiiiiiiiiii
  //      Invalid if rt == 0
  //      BGTZC_MMR6   if rs == 0  && rt != 0
  //      BLTZC_MMR6   if rs == rt && rt != 0
  //      BLTC_MMR6    if rs != rt && rs != 0  && rt != 0

  unsigned Rt = fieldFromInstruction(insn, 21, 5);
  unsigned Rs = fieldFromInstruction(insn, 16, 5);
  int64_t Imm = SignExtend64(fieldFromInstruction(insn, 0, 16), 16) * 4 + 4;
  bool HasRs = false;

  if (Rt == 0)
    return MCDisassembler_Fail;
  else if (Rs == 0)
    MCInst_setOpcode(MI, Mips_BGTZC_MMR6);
  else if (Rs == Rt)
    MCInst_setOpcode(MI, Mips_BLTZC_MMR6);
  else {
    MCInst_setOpcode(MI, Mips_BLTC_MMR6);
    HasRs = true;
  }

  if (HasRs)
    MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rs));

  MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rt));

  MCOperand_CreateImm0(MI, Imm);

  return MCDisassembler_Success;
}

static DecodeStatus DecodePOP75GroupBranchMMR6(MCInst *MI, unsigned insn,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  // We have:
  //    0b111101 ttttt sssss iiiiiiiiiiiiiiii
  //      Invalid if rt == 0
  //      BLEZC_MMR6   if rs == 0  && rt != 0
  //      BGEZC_MMR6   if rs == rt && rt != 0
  //      BGEC_MMR6    if rs != rt && rs != 0  && rt != 0

  unsigned Rt = fieldFromInstruction(insn, 21, 5);
  unsigned Rs = fieldFromInstruction(insn, 16, 5);
  int64_t Imm = SignExtend64(fieldFromInstruction(insn, 0, 16), 16) * 4 + 4;
  bool HasRs = false;

  if (Rt == 0)
    return MCDisassembler_Fail;
  else if (Rs == 0)
    MCInst_setOpcode(MI, Mips_BLEZC_MMR6);
  else if (Rs == Rt)
    MCInst_setOpcode(MI, Mips_BGEZC_MMR6);
  else {
    HasRs = true;
    MCInst_setOpcode(MI, Mips_BGEC_MMR6);
  }

  if (HasRs)
    MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rs));

  MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rt));

  MCOperand_CreateImm0(MI, Imm);

  return MCDisassembler_Success;
}

static DecodeStatus DecodeBlezlGroupBranch(MCInst *MI, unsigned insn,
					   uint64_t Address,
					   MCRegisterInfo *Decoder)
{
  // If we are called then we can assume that MIPS32r6/MIPS64r6 is enabled
  // (otherwise we would have matched the BLEZL instruction from the earlier
  // ISA's instead).
  //
  // We have:
  //    0b010110 sssss ttttt iiiiiiiiiiiiiiii
  //      Invalid if rs == 0
  //      BLEZC   if rs == 0  && rt != 0
  //      BGEZC   if rs == rt && rt != 0
  //      BGEC    if rs != rt && rs != 0  && rt != 0

  unsigned Rs = fieldFromInstruction(insn, 21, 5);
  unsigned Rt = fieldFromInstruction(insn, 16, 5);
  int64_t Imm = SignExtend64(fieldFromInstruction(insn, 0, 16), 16) * 4 + 4;
  bool HasRs = false;

  if (Rt == 0)
    return MCDisassembler_Fail;
  else if (Rs == 0)
    MCInst_setOpcode(MI, Mips_BLEZC);
  else if (Rs == Rt)
    MCInst_setOpcode(MI, Mips_BGEZC);
  else {
    HasRs = true;
    MCInst_setOpcode(MI, Mips_BGEC);
  }

  if (HasRs)
    MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rs));

  MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rt));

  MCOperand_CreateImm0(MI, Imm);

  return MCDisassembler_Success;
}

static DecodeStatus DecodeBgtzlGroupBranch(MCInst *MI, unsigned insn,
					   uint64_t Address,
					   MCRegisterInfo *Decoder)
{
  // If we are called then we can assume that MIPS32r6/MIPS64r6 is enabled
  // (otherwise we would have matched the BGTZL instruction from the earlier
  // ISA's instead).
  //
  // We have:
  //    0b010111 sssss ttttt iiiiiiiiiiiiiiii
  //      Invalid if rs == 0
  //      BGTZC   if rs == 0  && rt != 0
  //      BLTZC   if rs == rt && rt != 0
  //      BLTC    if rs != rt && rs != 0  && rt != 0

  bool HasRs = false;

  unsigned Rs = fieldFromInstruction(insn, 21, 5);
  unsigned Rt = fieldFromInstruction(insn, 16, 5);
  int64_t Imm = SignExtend64(fieldFromInstruction(insn, 0, 16), 16) * 4 + 4;

  if (Rt == 0)
    return MCDisassembler_Fail;
  else if (Rs == 0)
    MCInst_setOpcode(MI, Mips_BGTZC);
  else if (Rs == Rt)
    MCInst_setOpcode(MI, Mips_BLTZC);
  else {
    MCInst_setOpcode(MI, Mips_BLTC);
    HasRs = true;
  }

  if (HasRs)
    MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rs));

  MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rt));

  MCOperand_CreateImm0(MI, Imm);

  return MCDisassembler_Success;
}

static DecodeStatus DecodeBgtzGroupBranch(MCInst *MI, unsigned insn,
					  uint64_t Address,
					  MCRegisterInfo *Decoder)
{
  // If we are called then we can assume that MIPS32r6/MIPS64r6 is enabled
  // (otherwise we would have matched the BGTZ instruction from the earlier
  // ISA's instead).
  //
  // We have:
  //    0b000111 sssss ttttt iiiiiiiiiiiiiiii
  //      BGTZ    if rt == 0
  //      BGTZALC if rs == 0 && rt != 0
  //      BLTZALC if rs != 0 && rs == rt
  //      BLTUC   if rs != 0 && rs != rt

  unsigned Rs = fieldFromInstruction(insn, 21, 5);
  unsigned Rt = fieldFromInstruction(insn, 16, 5);
  int64_t Imm = SignExtend64(fieldFromInstruction(insn, 0, 16), 16) * 4 + 4;
  bool HasRs = false;
  bool HasRt = false;

  if (Rt == 0) {
    MCInst_setOpcode(MI, Mips_BGTZ);
    HasRs = true;
  } else if (Rs == 0) {
    MCInst_setOpcode(MI, Mips_BGTZALC);
    HasRt = true;
  } else if (Rs == Rt) {
    MCInst_setOpcode(MI, Mips_BLTZALC);
    HasRs = true;
  } else {
    MCInst_setOpcode(MI, Mips_BLTUC);
    HasRs = true;
    HasRt = true;
  }

  if (HasRs)
    MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rs));

  if (HasRt)
    MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rt));

  MCOperand_CreateImm0(MI, Imm);

  return MCDisassembler_Success;
}

static DecodeStatus DecodeBlezGroupBranch(MCInst *MI, unsigned insn,
					  uint64_t Address,
					  MCRegisterInfo *Decoder)
{
  // If we are called then we can assume that MIPS32r6/MIPS64r6 is enabled
  // (otherwise we would have matched the BLEZL instruction from the earlier
  // ISA's instead).
  //
  // We have:
  //    0b000110 sssss ttttt iiiiiiiiiiiiiiii
  //      Invalid   if rs == 0
  //      BLEZALC   if rs == 0  && rt != 0
  //      BGEZALC   if rs == rt && rt != 0
  //      BGEUC     if rs != rt && rs != 0  && rt != 0

  unsigned Rs = fieldFromInstruction(insn, 21, 5);
  unsigned Rt = fieldFromInstruction(insn, 16, 5);
  int64_t Imm = SignExtend64(fieldFromInstruction(insn, 0, 16), 16) * 4 + 4;
  bool HasRs = false;

  if (Rt == 0)
    return MCDisassembler_Fail;
  else if (Rs == 0)
    MCInst_setOpcode(MI, Mips_BLEZALC);
  else if (Rs == Rt)
    MCInst_setOpcode(MI, Mips_BGEZALC);
  else {
    HasRs = true;
    MCInst_setOpcode(MI, Mips_BGEUC);
  }

  if (HasRs)
    MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rs));
  MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rt));

  MCOperand_CreateImm0(MI, Imm);

  return MCDisassembler_Success;
}

static DecodeStatus DecodeDEXT(MCInst *MI, unsigned Insn, uint64_t Address,
			       MCRegisterInfo *Decoder)
{
  unsigned Msbd = fieldFromInstruction(Insn, 11, 5);
  unsigned Lsb = fieldFromInstruction(Insn, 6, 5);
  unsigned Size = 0;
  unsigned Pos = 0;

  switch (MCInst_getOpcode(MI)) {
  case Mips_DEXT:
    Pos = Lsb;
    Size = Msbd + 1;
    break;
  case Mips_DEXTM:
    Pos = Lsb;
    Size = Msbd + 1 + 32;
    break;
  case Mips_DEXTU:
    Pos = Lsb + 32;
    Size = Msbd + 1;
    break;
  default:
    llvm_unreachable("Unknown DEXT instruction!");
  }

  MCInst_setOpcode(MI, Mips_DEXT);

  unsigned Rs = fieldFromInstruction(Insn, 21, 5);
  unsigned Rt = fieldFromInstruction(Insn, 16, 5);

  MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR64RegClassID, Rt));
  MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR64RegClassID, Rs));
  MCOperand_CreateImm0(MI, Pos);
  MCOperand_CreateImm0(MI, Size);

  return MCDisassembler_Success;
}

static DecodeStatus DecodeDINS(MCInst *MI, unsigned Insn, uint64_t Address,
			       MCRegisterInfo *Decoder)
{
  unsigned Msbd = fieldFromInstruction(Insn, 11, 5);
  unsigned Lsb = fieldFromInstruction(Insn, 6, 5);
  unsigned Size = 0;
  unsigned Pos = 0;

  switch (MCInst_getOpcode(MI)) {
  case Mips_DINS:
    Pos = Lsb;
    Size = Msbd + 1 - Pos;
    break;
  case Mips_DINSM:
    Pos = Lsb;
    Size = Msbd + 33 - Pos;
    break;
  case Mips_DINSU:
    Pos = Lsb + 32;
    // mbsd = pos + size - 33
    // mbsd - pos + 33 = size
    Size = Msbd + 33 - Pos;
    break;
  default:
    llvm_unreachable("Unknown DINS instruction!");
  }

  unsigned Rs = fieldFromInstruction(Insn, 21, 5);
  unsigned Rt = fieldFromInstruction(Insn, 16, 5);

  MCInst_setOpcode(MI, Mips_DINS);
  MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR64RegClassID, Rt));
  MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR64RegClassID, Rs));
  MCOperand_CreateImm0(MI, Pos);
  MCOperand_CreateImm0(MI, Size);

  return MCDisassembler_Success;
}

static DecodeStatus DecodeCRC(MCInst *MI, unsigned Insn, uint64_t Address,
			      MCRegisterInfo *Decoder)
{
  unsigned Rs = fieldFromInstruction(Insn, 21, 5);
  unsigned Rt = fieldFromInstruction(Insn, 16, 5);
  MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rt));
  MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rs));
  MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rt));
  return MCDisassembler_Success;
}

static DecodeStatus DecodeCPU16RegsRegisterClass(MCInst *Inst, unsigned RegNo,
						 uint64_t Address,
						 MCRegisterInfo *Decoder)
{
  return MCDisassembler_Fail;
}

static DecodeStatus DecodeGPR64RegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     MCRegisterInfo *Decoder)
{
  if (RegNo > 31)
    return MCDisassembler_Fail;

  unsigned Reg = getReg(Inst->MRI, Mips_GPR64RegClassID, RegNo);
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeGPRMM16RegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  if (RegNo > 7)
    return MCDisassembler_Fail;
  unsigned Reg = getReg(Inst->MRI, Mips_GPRMM16RegClassID, RegNo);
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeGPRMM16ZeroRegisterClass(MCInst *Inst, unsigned RegNo,
						   uint64_t Address,
						   MCRegisterInfo *Decoder)
{
  if (RegNo > 7)
    return MCDisassembler_Fail;
  unsigned Reg = getReg(Inst->MRI, Mips_GPRMM16ZeroRegClassID, RegNo);
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeGPRMM16MovePRegisterClass(MCInst *Inst,
						    unsigned RegNo,
						    uint64_t Address,
						    MCRegisterInfo *Decoder)
{
  if (RegNo > 7)
    return MCDisassembler_Fail;
  unsigned Reg = getReg(Inst->MRI, Mips_GPRMM16MovePRegClassID, RegNo);
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeGPR32RegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     MCRegisterInfo *Decoder)
{
  if (RegNo > 31)
    return MCDisassembler_Fail;
  unsigned Reg = getReg(Inst->MRI, Mips_GPR32RegClassID, RegNo);
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodePtrRegisterClass(MCInst *Inst, unsigned RegNo,
					   uint64_t Address,
					   MCRegisterInfo *Decoder)
{
  if (Inst->csh->mode & CS_MODE_MIPS64)
    return DecodeGPR64RegisterClass(Inst, RegNo, Address, Decoder);

  return DecodeGPR32RegisterClass(Inst, RegNo, Address, Decoder);
}
static DecodeStatus DecodeDSPRRegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    MCRegisterInfo *Decoder)
{
  return DecodeGPR32RegisterClass(Inst, RegNo, Address, Decoder);
}

static DecodeStatus DecodeFGR64RegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     MCRegisterInfo *Decoder)
{
  if (RegNo > 31)
    return MCDisassembler_Fail;

  unsigned Reg = getReg(Inst->MRI, Mips_FGR64RegClassID, RegNo);
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeFGR32RegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     MCRegisterInfo *Decoder)
{
  if (RegNo > 31)
    return MCDisassembler_Fail;
  
  unsigned Reg = getReg(Inst->MRI, Mips_FGR32RegClassID, RegNo);
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeCCRRegisterClass(MCInst *Inst, unsigned RegNo,
					   uint64_t Address,
					   MCRegisterInfo *Decoder)
{
  if (RegNo > 31)
    return MCDisassembler_Fail;
  unsigned Reg = getReg(Inst->MRI, Mips_CCRRegClassID, RegNo);
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeFCCRegisterClass(MCInst *Inst, unsigned RegNo,
					   uint64_t Address,
					   MCRegisterInfo *Decoder)
{
  if (RegNo > 7)
    return MCDisassembler_Fail;
  unsigned Reg = getReg(Inst->MRI, Mips_FCCRegClassID, RegNo);
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeFGRCCRegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     MCRegisterInfo *Decoder)
{
  if (RegNo > 31)
    return MCDisassembler_Fail;

  unsigned Reg = getReg(Inst->MRI, Mips_FGRCCRegClassID, RegNo);
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeMem(MCInst *Inst, unsigned Insn, uint64_t Address,
			      MCRegisterInfo *Decoder)
{
  int Offset = SignExtend32(Insn & 0xffff, 16);
  unsigned Reg = fieldFromInstruction(Insn, 16, 5);
  unsigned Base = fieldFromInstruction(Insn, 21, 5);

  Reg = getReg(Inst->MRI, Mips_GPR32RegClassID, Reg);
  Base = getReg(Inst->MRI, Mips_GPR32RegClassID, Base);

  if (MCInst_getOpcode(Inst) == Mips_SC || MCInst_getOpcode(Inst) == Mips_SCD)
    MCOperand_CreateReg0(Inst, Reg);

  MCOperand_CreateReg0(Inst, Reg);
  MCOperand_CreateReg0(Inst, Base);
  MCOperand_CreateImm0(Inst, Offset);

  return MCDisassembler_Success;
}
static DecodeStatus DecodeMemEVA(MCInst *Inst, unsigned Insn, uint64_t Address,
				 MCRegisterInfo *Decoder)
{
  int Offset = SignExtend32(Insn >> 7, 9);
  unsigned Reg = fieldFromInstruction(Insn, 16, 5);
  unsigned Base = fieldFromInstruction(Insn, 21, 5);

  Reg = getReg(Inst->MRI, Mips_GPR32RegClassID, Reg);
  Base = getReg(Inst->MRI, Mips_GPR32RegClassID, Base);

  if (MCInst_getOpcode(Inst) == Mips_SCE)
    MCOperand_CreateReg0(Inst, Reg);

  MCOperand_CreateReg0(Inst, Reg);
  MCOperand_CreateReg0(Inst, Base);
  MCOperand_CreateImm0(Inst, Offset);

  return MCDisassembler_Success;
}
static DecodeStatus DecodeLoadByte15(MCInst *Inst, unsigned Insn,
				     uint64_t Address, MCRegisterInfo *Decoder)
{
  int Offset = SignExtend32(Insn & 0xffff, 16);
  unsigned Base = fieldFromInstruction(Insn, 16, 5);
  unsigned Reg = fieldFromInstruction(Insn, 21, 5);

  Base = getReg(Inst->MRI, Mips_GPR32RegClassID, Base);
  Reg = getReg(Inst->MRI, Mips_GPR32RegClassID, Reg);

  MCOperand_CreateReg0(Inst, Reg);
  MCOperand_CreateReg0(Inst, Base);
  MCOperand_CreateImm0(Inst, Offset);

  return MCDisassembler_Success;
}
static DecodeStatus DecodeCacheOp(MCInst *Inst, unsigned Insn, uint64_t Address,
				  MCRegisterInfo *Decoder)
{
  int Offset = SignExtend32(Insn & 0xffff, 16);
  unsigned Hint = fieldFromInstruction(Insn, 16, 5);
  unsigned Base = fieldFromInstruction(Insn, 21, 5);

  Base = getReg(Inst->MRI, Mips_GPR32RegClassID, Base);

  MCOperand_CreateReg0(Inst, Base);
  MCOperand_CreateImm0(Inst, Offset);
  MCOperand_CreateImm0(Inst, Hint);

  return MCDisassembler_Success;
}
static DecodeStatus DecodeCacheOpMM(MCInst *Inst, unsigned Insn,
				    uint64_t Address, MCRegisterInfo *Decoder)
{
  int Offset = SignExtend32(Insn & 0xfff, 12);
  unsigned Base = fieldFromInstruction(Insn, 16, 5);
  unsigned Hint = fieldFromInstruction(Insn, 21, 5);

  Base = getReg(Inst->MRI, Mips_GPR32RegClassID, Base);

  MCOperand_CreateReg0(Inst, Base);
  MCOperand_CreateImm0(Inst, Offset);
  MCOperand_CreateImm0(Inst, Hint);

  return MCDisassembler_Success;
}
static DecodeStatus DecodePrefeOpMM(MCInst *Inst, unsigned Insn,
				    uint64_t Address, MCRegisterInfo *Decoder)
{
  int Offset = SignExtend32(Insn & 0x1ff, 9);
  unsigned Base = fieldFromInstruction(Insn, 16, 5);
  unsigned Hint = fieldFromInstruction(Insn, 21, 5);

  Base = getReg(Inst->MRI, Mips_GPR32RegClassID, Base);

  MCOperand_CreateReg0(Inst, Base);
  MCOperand_CreateImm0(Inst, Offset);
  MCOperand_CreateImm0(Inst, Hint);

  return MCDisassembler_Success;
}
static DecodeStatus DecodeCacheeOp_CacheOpR6(MCInst *Inst, unsigned Insn,
					     uint64_t Address,
					     MCRegisterInfo *Decoder)
{
  int Offset = SignExtend32(Insn >> 7, 9);
  unsigned Hint = fieldFromInstruction(Insn, 16, 5);
  unsigned Base = fieldFromInstruction(Insn, 21, 5);

  Base = getReg(Inst->MRI, Mips_GPR32RegClassID, Base);

  MCOperand_CreateReg0(Inst, Base);
  MCOperand_CreateImm0(Inst, Offset);
  MCOperand_CreateImm0(Inst, Hint);

  return MCDisassembler_Success;
}
static DecodeStatus DecodeSyncI(MCInst *Inst, unsigned Insn, uint64_t Address,
				MCRegisterInfo *Decoder)
{
  int Offset = SignExtend32(Insn & 0xffff, 16);
  unsigned Base = fieldFromInstruction(Insn, 21, 5);

  Base = getReg(Inst->MRI, Mips_GPR32RegClassID, Base);

  MCOperand_CreateReg0(Inst, Base);
  MCOperand_CreateImm0(Inst, Offset);

  return MCDisassembler_Success;
}
static DecodeStatus DecodeSyncI_MM(MCInst *Inst, unsigned Insn,
				   uint64_t Address, MCRegisterInfo *Decoder)
{
  int Offset = SignExtend32(Insn & 0xffff, 16);
  unsigned Base = fieldFromInstruction(Insn, 16, 5);

  Base = getReg(Inst->MRI, Mips_GPR32RegClassID, Base);

  MCOperand_CreateReg0(Inst, Base);
  MCOperand_CreateImm0(Inst, Offset);

  return MCDisassembler_Success;
}
static DecodeStatus DecodeSynciR6(MCInst *Inst, unsigned Insn, uint64_t Address,
				  MCRegisterInfo *Decoder)
{
  int Immediate = SignExtend32(Insn & 0xffff, 16);
  unsigned Base = fieldFromInstruction(Insn, 16, 5);

  Base = getReg(Inst->MRI, Mips_GPR32RegClassID, Base);

  MCOperand_CreateReg0(Inst, Base);
  MCOperand_CreateImm0(Inst, Immediate);

  return MCDisassembler_Success;
}
static DecodeStatus DecodeMSA128Mem(MCInst *Inst, unsigned Insn,
				    uint64_t Address, MCRegisterInfo *Decoder)
{
  int Offset = SignExtend32(fieldFromInstruction(Insn, 16, 10), 10);
  unsigned Reg = fieldFromInstruction(Insn, 6, 5);
  unsigned Base = fieldFromInstruction(Insn, 11, 5);

  Reg = getReg(Inst->MRI, Mips_MSA128BRegClassID, Reg);
  Base = getReg(Inst->MRI, Mips_GPR32RegClassID, Base);

  MCOperand_CreateReg0(Inst, Reg);
  MCOperand_CreateReg0(Inst, Base);

  // The immediate field of an LD/ST instruction is scaled which means it must
  // be multiplied (when decoding) by the size (in bytes) of the instructions'
  // data format.
  // .b - 1 byte
  // .h - 2 bytes
  // .w - 4 bytes
  // .d - 8 bytes
  switch (MCInst_getOpcode(Inst)) {
  default:
    assert(false && "Unexpected instruction");
    return MCDisassembler_Fail;
    break;
  case Mips_LD_B:
  case Mips_ST_B:
    MCOperand_CreateImm0(Inst, Offset);
    break;
  case Mips_LD_H:
  case Mips_ST_H:
    MCOperand_CreateImm0(Inst, Offset * 2);
    break;
  case Mips_LD_W:
  case Mips_ST_W:
    MCOperand_CreateImm0(Inst, Offset * 4);
    break;
  case Mips_LD_D:
  case Mips_ST_D:
    MCOperand_CreateImm0(Inst, Offset * 8);
    break;
  }

  return MCDisassembler_Success;
}
static DecodeStatus DecodeMemMMImm4(MCInst *Inst, unsigned Insn,
				    uint64_t Address, MCRegisterInfo *Decoder)
{
  unsigned Offset = Insn & 0xf;
  unsigned Reg = fieldFromInstruction(Insn, 7, 3);
  unsigned Base = fieldFromInstruction(Insn, 4, 3);

  switch (MCInst_getOpcode(Inst)) {
  case Mips_LBU16_MM:
  case Mips_LHU16_MM:
  case Mips_LW16_MM:
    if (DecodeGPRMM16RegisterClass(Inst, Reg, Address, Decoder) ==
	MCDisassembler_Fail)
      return MCDisassembler_Fail;
    break;
  case Mips_SB16_MM:
  case Mips_SB16_MMR6:
  case Mips_SH16_MM:
  case Mips_SH16_MMR6:
  case Mips_SW16_MM:
  case Mips_SW16_MMR6:
    if (DecodeGPRMM16ZeroRegisterClass(Inst, Reg, Address, Decoder) ==
	MCDisassembler_Fail)
      return MCDisassembler_Fail;
    break;
  }

  if (DecodeGPRMM16RegisterClass(Inst, Base, Address, Decoder) ==
      MCDisassembler_Fail)
    return MCDisassembler_Fail;

  switch (MCInst_getOpcode(Inst)) {
  case Mips_LBU16_MM:
    if (Offset == 0xf)
      MCOperand_CreateImm0(Inst, -1);
    else
      MCOperand_CreateImm0(Inst, Offset);
    break;
  case Mips_SB16_MM:
  case Mips_SB16_MMR6:
    MCOperand_CreateImm0(Inst, Offset);
    break;
  case Mips_LHU16_MM:
  case Mips_SH16_MM:
  case Mips_SH16_MMR6:
    MCOperand_CreateImm0(Inst, Offset << 1);
    break;
  case Mips_LW16_MM:
  case Mips_SW16_MM:
  case Mips_SW16_MMR6:
    MCOperand_CreateImm0(Inst, Offset << 2);
    break;
  }

  return MCDisassembler_Success;
}

static DecodeStatus DecodeMemMMSPImm5Lsl2(MCInst *Inst, unsigned Insn,
					  uint64_t Address,
					  MCRegisterInfo *Decoder)
{
  unsigned Offset = Insn & 0x1F;
  unsigned Reg = fieldFromInstruction(Insn, 5, 5);

  Reg = getReg(Inst->MRI, Mips_GPR32RegClassID, Reg);

  MCOperand_CreateReg0(Inst, Reg);
  MCOperand_CreateReg0(Inst, Mips_SP);
  MCOperand_CreateImm0(Inst, Offset << 2);

  return MCDisassembler_Success;
}

static DecodeStatus DecodeMemMMGPImm7Lsl2(MCInst *Inst, unsigned Insn,
					  uint64_t Address,
					  MCRegisterInfo *Decoder)
{
  unsigned Offset = Insn & 0x7F;
  unsigned Reg = fieldFromInstruction(Insn, 7, 3);

  Reg = getReg(Inst->MRI, Mips_GPR32RegClassID, Reg);

  MCOperand_CreateReg0(Inst, Reg);
  MCOperand_CreateReg0(Inst, Mips_GP);
  MCOperand_CreateImm0(Inst, Offset << 2);

  return MCDisassembler_Success;
}

static DecodeStatus DecodeMemMMReglistImm4Lsl2(MCInst *Inst, unsigned Insn,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  int Offset;
  switch (MCInst_getOpcode(Inst)) {
  case Mips_LWM16_MMR6:
  case Mips_SWM16_MMR6:
    Offset = fieldFromInstruction(Insn, 4, 4);
    break;
  default:
    Offset = SignExtend32(Insn & 0xf, 4);
    break;
  }

  if (DecodeRegListOperand16(Inst, Insn, Address, Decoder) ==
      MCDisassembler_Fail)
    return MCDisassembler_Fail;

  MCOperand_CreateReg0(Inst, Mips_SP);
  MCOperand_CreateImm0(Inst, Offset << 2);

  return MCDisassembler_Success;
}
static DecodeStatus DecodeMemMMImm9(MCInst *Inst, unsigned Insn,
				    uint64_t Address, MCRegisterInfo *Decoder)
{
  int Offset = SignExtend32(Insn & 0x1ff, 9);
  unsigned Reg = fieldFromInstruction(Insn, 21, 5);
  unsigned Base = fieldFromInstruction(Insn, 16, 5);

  Reg = getReg(Inst->MRI, Mips_GPR32RegClassID, Reg);
  Base = getReg(Inst->MRI, Mips_GPR32RegClassID, Base);

  if (MCInst_getOpcode(Inst) == Mips_SCE_MM ||
      MCInst_getOpcode(Inst) == Mips_SC_MMR6)
    MCOperand_CreateReg0(Inst, Reg);

  MCOperand_CreateReg0(Inst, Reg);
  MCOperand_CreateReg0(Inst, Base);
  MCOperand_CreateImm0(Inst, Offset);

  return MCDisassembler_Success;
}
static DecodeStatus DecodeMemMMImm12(MCInst *Inst, unsigned Insn,
				     uint64_t Address, MCRegisterInfo *Decoder)
{
  int Offset = SignExtend32(Insn & 0x0fff, 12);
  unsigned Reg = fieldFromInstruction(Insn, 21, 5);
  unsigned Base = fieldFromInstruction(Insn, 16, 5);

  Reg = getReg(Inst->MRI, Mips_GPR32RegClassID, Reg);
  Base = getReg(Inst->MRI, Mips_GPR32RegClassID, Base);

  switch (MCInst_getOpcode(Inst)) {
  case Mips_SWM32_MM:
  case Mips_LWM32_MM:
    if (DecodeRegListOperand(Inst, Insn, Address, Decoder) ==
	MCDisassembler_Fail)
      return MCDisassembler_Fail;
    MCOperand_CreateReg0(Inst, Base);
    MCOperand_CreateImm0(Inst, Offset);
    break;
  case Mips_SC_MM:
    MCOperand_CreateReg0(Inst, Reg);
    0x0;
  default:
    MCOperand_CreateReg0(Inst, Reg);
    if (MCInst_getOpcode(Inst) == Mips_LWP_MM ||
	MCInst_getOpcode(Inst) == Mips_SWP_MM)
      MCOperand_CreateReg0(Inst, Reg + 1);

    MCOperand_CreateReg0(Inst, Base);
    MCOperand_CreateImm0(Inst, Offset);
  }

  return MCDisassembler_Success;
}
static DecodeStatus DecodeMemMMImm16(MCInst *Inst, unsigned Insn,
				     uint64_t Address, MCRegisterInfo *Decoder)
{
  int Offset = SignExtend32(Insn & 0xffff, 16);
  unsigned Reg = fieldFromInstruction(Insn, 21, 5);
  unsigned Base = fieldFromInstruction(Insn, 16, 5);

  Reg = getReg(Inst->MRI, Mips_GPR32RegClassID, Reg);
  Base = getReg(Inst->MRI, Mips_GPR32RegClassID, Base);

  MCOperand_CreateReg0(Inst, Reg);
  MCOperand_CreateReg0(Inst, Base);
  MCOperand_CreateImm0(Inst, Offset);

  return MCDisassembler_Success;
}
static DecodeStatus DecodeFMem(MCInst *Inst, unsigned Insn, uint64_t Address,
			       MCRegisterInfo *Decoder)
{
  int Offset = SignExtend32(Insn & 0xffff, 16);
  unsigned Reg = fieldFromInstruction(Insn, 16, 5);
  unsigned Base = fieldFromInstruction(Insn, 21, 5);

  Reg = getReg(Inst->MRI, Mips_FGR64RegClassID, Reg);
  Base = getReg(Inst->MRI, Mips_GPR32RegClassID, Base);

  MCOperand_CreateReg0(Inst, Reg);
  MCOperand_CreateReg0(Inst, Base);
  MCOperand_CreateImm0(Inst, Offset);

  return MCDisassembler_Success;
}
static DecodeStatus DecodeFMemMMR2(MCInst *Inst, unsigned Insn,
				   uint64_t Address, MCRegisterInfo *Decoder)
{
  // This function is the same as DecodeFMem but with the Reg and Base fields
  // swapped according to microMIPS spec.
  int Offset = SignExtend32(Insn & 0xffff, 16);
  unsigned Base = fieldFromInstruction(Insn, 16, 5);
  unsigned Reg = fieldFromInstruction(Insn, 21, 5);

  Reg = getReg(Inst->MRI, Mips_FGR64RegClassID, Reg);
  Base = getReg(Inst->MRI, Mips_GPR32RegClassID, Base);

  MCOperand_CreateReg0(Inst, Reg);
  MCOperand_CreateReg0(Inst, Base);
  MCOperand_CreateImm0(Inst, Offset);

  return MCDisassembler_Success;
}
static DecodeStatus DecodeFMem2(MCInst *Inst, unsigned Insn, uint64_t Address,
				MCRegisterInfo *Decoder)
{
  int Offset = SignExtend32(Insn & 0xffff, 16);
  unsigned Reg = fieldFromInstruction(Insn, 16, 5);
  unsigned Base = fieldFromInstruction(Insn, 21, 5);

  Reg = getReg(Inst->MRI, Mips_COP2RegClassID, Reg);
  Base = getReg(Inst->MRI, Mips_GPR32RegClassID, Base);

  MCOperand_CreateReg0(Inst, Reg);
  MCOperand_CreateReg0(Inst, Base);
  MCOperand_CreateImm0(Inst, Offset);

  return MCDisassembler_Success;
}
static DecodeStatus DecodeFMem3(MCInst *Inst, unsigned Insn, uint64_t Address,
				MCRegisterInfo *Decoder)
{
  int Offset = SignExtend32(Insn & 0xffff, 16);
  unsigned Reg = fieldFromInstruction(Insn, 16, 5);
  unsigned Base = fieldFromInstruction(Insn, 21, 5);

  Reg = getReg(Inst->MRI, Mips_COP3RegClassID, Reg);
  Base = getReg(Inst->MRI, Mips_GPR32RegClassID, Base);

  MCOperand_CreateReg0(Inst, Reg);
  MCOperand_CreateReg0(Inst, Base);
  MCOperand_CreateImm0(Inst, Offset);

  return MCDisassembler_Success;
}
static DecodeStatus DecodeFMemCop2R6(MCInst *Inst, unsigned Insn,
				     uint64_t Address, MCRegisterInfo *Decoder)
{
  int Offset = SignExtend32(Insn & 0x07ff, 11);
  unsigned Reg = fieldFromInstruction(Insn, 16, 5);
  unsigned Base = fieldFromInstruction(Insn, 11, 5);

  Reg = getReg(Inst->MRI, Mips_COP2RegClassID, Reg);
  Base = getReg(Inst->MRI, Mips_GPR32RegClassID, Base);

  MCOperand_CreateReg0(Inst, Reg);
  MCOperand_CreateReg0(Inst, Base);
  MCOperand_CreateImm0(Inst, Offset);

  return MCDisassembler_Success;
}
static DecodeStatus DecodeFMemCop2MMR6(MCInst *Inst, unsigned Insn,
				       uint64_t Address,
				       MCRegisterInfo *Decoder)
{
  int Offset = SignExtend32(Insn & 0x07ff, 11);
  unsigned Reg = fieldFromInstruction(Insn, 21, 5);
  unsigned Base = fieldFromInstruction(Insn, 16, 5);

  Reg = getReg(Inst->MRI, Mips_COP2RegClassID, Reg);
  Base = getReg(Inst->MRI, Mips_GPR32RegClassID, Base);

  MCOperand_CreateReg0(Inst, Reg);
  MCOperand_CreateReg0(Inst, Base);
  MCOperand_CreateImm0(Inst, Offset);

  return MCDisassembler_Success;
}
static DecodeStatus DecodeSpecial3LlSc(MCInst *Inst, unsigned Insn,
				       uint64_t Address,
				       MCRegisterInfo *Decoder)
{
  int64_t Offset = SignExtend64(Insn >> 7, 9) & 0x1ff;
  unsigned Rt = fieldFromInstruction(Insn, 16, 5);
  unsigned Base = fieldFromInstruction(Insn, 21, 5);

  Rt = getReg(Inst->MRI, Mips_GPR32RegClassID, Rt);
  Base = getReg(Inst->MRI, Mips_GPR32RegClassID, Base);

  if (MCInst_getOpcode(Inst) == Mips_SC_R6 ||
      MCInst_getOpcode(Inst) == Mips_SCD_R6) {
    MCOperand_CreateReg0(Inst, Rt);
  }

  MCOperand_CreateReg0(Inst, Rt);
  MCOperand_CreateReg0(Inst, Base);
  MCOperand_CreateImm0(Inst, Offset);

  return MCDisassembler_Success;
}
static DecodeStatus DecodeHWRegsRegisterClass(MCInst *Inst, unsigned RegNo,
					      uint64_t Address,
					      MCRegisterInfo *Decoder)
{
  // Currently only hardware register 29 is supported.
  if (RegNo != 29)
    return MCDisassembler_Fail;
  MCOperand_CreateReg0(Inst, Mips_HWR29);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeAFGR64RegisterClass(MCInst *Inst, unsigned RegNo,
					      uint64_t Address,
					      MCRegisterInfo *Decoder)
{
  if (RegNo > 30 || RegNo % 2)
    return MCDisassembler_Fail;

  unsigned Reg = getReg(Inst->MRI, Mips_AFGR64RegClassID, RegNo / 2);
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeACC64DSPRegisterClass(MCInst *Inst, unsigned RegNo,
						uint64_t Address,
						MCRegisterInfo *Decoder)
{
  if (RegNo >= 4)
    return MCDisassembler_Fail;

  unsigned Reg = getReg(Inst->MRI, Mips_ACC64DSPRegClassID, RegNo);
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeHI32DSPRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  if (RegNo >= 4)
    return MCDisassembler_Fail;

  unsigned Reg = getReg(Inst->MRI, Mips_HI32DSPRegClassID, RegNo);
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeLO32DSPRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  if (RegNo >= 4)
    return MCDisassembler_Fail;

  unsigned Reg = getReg(Inst->MRI, Mips_LO32DSPRegClassID, RegNo);
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeMSA128BRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  if (RegNo > 31)
    return MCDisassembler_Fail;

  unsigned Reg = getReg(Inst->MRI, Mips_MSA128BRegClassID, RegNo);
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeMSA128HRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  if (RegNo > 31)
    return MCDisassembler_Fail;

  unsigned Reg = getReg(Inst->MRI, Mips_MSA128HRegClassID, RegNo);
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeMSA128WRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  if (RegNo > 31)
    return MCDisassembler_Fail;

  unsigned Reg = getReg(Inst->MRI, Mips_MSA128WRegClassID, RegNo);
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeMSA128DRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  if (RegNo > 31)
    return MCDisassembler_Fail;

  unsigned Reg = getReg(Inst->MRI, Mips_MSA128DRegClassID, RegNo);
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeMSACtrlRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  if (RegNo > 7)
    return MCDisassembler_Fail;

  unsigned Reg = getReg(Inst->MRI, Mips_MSACtrlRegClassID, RegNo);
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeCOP0RegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    MCRegisterInfo *Decoder)
{
  if (RegNo > 31)
    return MCDisassembler_Fail;

  unsigned Reg = getReg(Inst->MRI, Mips_COP0RegClassID, RegNo);
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeCOP2RegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    MCRegisterInfo *Decoder)
{
  if (RegNo > 31)
    return MCDisassembler_Fail;

  unsigned Reg = getReg(Inst->MRI, Mips_COP2RegClassID, RegNo);
  MCOperand_CreateReg0(Inst, Reg);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeBranchTarget(MCInst *Inst, unsigned Offset,
				       uint64_t Address,
				       MCRegisterInfo *Decoder)
{
  int32_t BranchOffset = (SignExtend32(Offset, 16) * 4) + 4;
  MCOperand_CreateImm0(Inst, BranchOffset + Address);
  return MCDisassembler_Success;
}
static DecodeStatus DecodeBranchTarget1SImm16(MCInst *Inst, unsigned Offset,
					      uint64_t Address,
					      MCRegisterInfo *Decoder)
{
  int32_t BranchOffset = (SignExtend32(Offset, 16) * 2);
  MCOperand_CreateImm0(Inst, BranchOffset + Address);
  return MCDisassembler_Success;
}
static DecodeStatus DecodeJumpTarget(MCInst *Inst, unsigned Insn,
				     uint64_t Address, MCRegisterInfo *Decoder)
{
  debugln("jump target decode");
  unsigned JumpOffset = fieldFromInstruction(Insn, 0, 26) << 2;
  MCOperand_CreateImm0(Inst, JumpOffset);
  debugln("with exit");
  return MCDisassembler_Success;
}

static DecodeStatus DecodeBranchTarget21(MCInst *Inst, unsigned Offset,
					 uint64_t Address,
					 MCRegisterInfo *Decoder)
{
  int32_t BranchOffset = SignExtend32(Offset, 21) * 4 + 4;

  MCOperand_CreateImm0(Inst, BranchOffset + Address);
  return MCDisassembler_Success;
}
static DecodeStatus DecodeBranchTarget21MM(MCInst *Inst, unsigned Offset,
					   uint64_t Address,
					   MCRegisterInfo *Decoder)
{
  int32_t BranchOffset = SignExtend32(Offset, 21) * 4 + 4;

  MCOperand_CreateImm0(Inst, BranchOffset + Address);
  return MCDisassembler_Success;
}
static DecodeStatus DecodeBranchTarget26(MCInst *Inst, unsigned Offset,
					 uint64_t Address,
					 MCRegisterInfo *Decoder)
{
  int32_t BranchOffset = SignExtend32(Offset, 26) * 4 + 4;

  MCOperand_CreateImm0(Inst, BranchOffset + Address);
  return MCDisassembler_Success;
}
static DecodeStatus DecodeBranchTarget7MM(MCInst *Inst, unsigned Offset,
					  uint64_t Address,
					  MCRegisterInfo *Decoder)
{
  int32_t BranchOffset = SignExtend32(Offset << 1, 8);
  MCOperand_CreateImm0(Inst, BranchOffset + Address);
  return MCDisassembler_Success;
}
static DecodeStatus DecodeBranchTarget10MM(MCInst *Inst, unsigned Offset,
					   uint64_t Address,
					   MCRegisterInfo *Decoder)
{
  int32_t BranchOffset = SignExtend32(Offset << 1, 11);
  MCOperand_CreateImm0(Inst, BranchOffset + Address);
  return MCDisassembler_Success;
}
static DecodeStatus DecodeBranchTargetMM(MCInst *Inst, unsigned Offset,
					 uint64_t Address,
					 MCRegisterInfo *Decoder)
{
  int32_t BranchOffset = SignExtend32(Offset, 16) * 2 + 4;
  MCOperand_CreateImm0(Inst, BranchOffset + Address);
  return MCDisassembler_Success;
}
static DecodeStatus DecodeBranchTarget26MM(MCInst *Inst, unsigned Offset,
					   uint64_t Address,
					   MCRegisterInfo *Decoder)
{
  int32_t BranchOffset = SignExtend32(Offset << 1, 27);

  MCOperand_CreateImm0(Inst, BranchOffset + Address);
  return MCDisassembler_Success;
}
static DecodeStatus DecodeJumpTargetMM(MCInst *Inst, unsigned Insn,
				       uint64_t Address,
				       MCRegisterInfo *Decoder)
{
  unsigned JumpOffset = fieldFromInstruction(Insn, 0, 26) << 1;
  MCOperand_CreateImm0(Inst, JumpOffset);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeJumpTargetXMM(MCInst *Inst, unsigned Insn,
					uint64_t Address,
					MCRegisterInfo *Decoder)
{
  unsigned JumpOffset = fieldFromInstruction(Insn, 0, 26) << 2;
  MCOperand_CreateImm0(Inst, JumpOffset);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeAddiur2Simm7(MCInst *Inst, unsigned Value,
				       uint64_t Address,
				       MCRegisterInfo *Decoder)
{
  if (Value == 0)
    MCOperand_CreateImm0(Inst, 1);
  else if (Value == 0x7)
    MCOperand_CreateImm0(Inst, -1);
  else
    MCOperand_CreateImm0(Inst, Value << 2);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeLi16Imm(MCInst *Inst, unsigned Value,
				  uint64_t Address, MCRegisterInfo *Decoder)
{
  if (Value == 0x7F)
    MCOperand_CreateImm0(Inst, -1);
  else
    MCOperand_CreateImm0(Inst, Value);
  return MCDisassembler_Success;
}

static DecodeStatus DecodePOOL16BEncodedField(MCInst *Inst, unsigned Value,
					      uint64_t Address,
					      MCRegisterInfo *Decoder)
{
  MCOperand_CreateImm0(Inst, Value == 0x0 ? 8 : Value);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeUImmWithOffsetAndScale(MCInst *Inst, unsigned Value,
						 uint64_t Address,
						 MCRegisterInfo *Decoder,
						 unsigned Bits, unsigned Offset,
						 unsigned Scale)
{
  Value &= ((1 << Bits) - 1);
  Value *= Scale;
  MCOperand_CreateImm0(Inst, Value + Offset);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeSImmWithOffsetAndScale(MCInst *Inst, unsigned Value,
						 uint64_t Address,
						 MCRegisterInfo *Decoder,
						 unsigned Bits)
{
  unsigned Offset = 0; // we don't have default values in C, so here it goes
  unsigned ScaleBy = 1;
  int32_t Imm = SignExtend32(Value, Bits) * ScaleBy;
  debug("after extend %d\n", Imm);
  MCOperand_CreateImm0(Inst, (int64_t) Imm + Offset);
    debug("created Imm0 %ld\n", (int64_t) Imm + Offset);
  return MCDisassembler_Success;
}
static DecodeStatus DecodeInsSize(MCInst *Inst, unsigned Insn, uint64_t Address,
				  MCRegisterInfo *Decoder)
{
  // First we need to grab the pos(lsb) from MCInst.
  // This function only handles the 32 bit variants of ins, as dins
  // variants are handled differently.
  int Pos = MCOperand_getImm(MCInst_getOperand(Inst, 2));
  int Size = (int)Insn - Pos + 1;
  MCOperand_CreateImm0(Inst, SignExtend32(Size, 16));
  return MCDisassembler_Success;
}
static DecodeStatus DecodeSimm19Lsl2(MCInst *Inst, unsigned Insn,
				     uint64_t Address, MCRegisterInfo *Decoder)
{
  MCOperand_CreateImm0(Inst, SignExtend32(Insn, 19) * 4);
  return MCDisassembler_Success;
}
static DecodeStatus DecodeSimm18Lsl3(MCInst *Inst, unsigned Insn,
				     uint64_t Address, MCRegisterInfo *Decoder)
{
  MCOperand_CreateImm0(Inst, SignExtend32(Insn, 18) * 8);
  return MCDisassembler_Success;
}
static DecodeStatus DecodeSimm9SP(MCInst *Inst, unsigned Insn, uint64_t Address,
				  MCRegisterInfo *Decoder)
{
  int32_t DecodedValue;
  switch (Insn) {
  case 0:
    DecodedValue = 256;
    break;
  case 1:
    DecodedValue = 257;
    break;
  case 510:
    DecodedValue = -258;
    break;
  case 511:
    DecodedValue = -257;
    break;
  default:
    DecodedValue = SignExtend32(Insn, 9);
    break;
  }
  MCOperand_CreateImm0(Inst, DecodedValue * 4);
  return MCDisassembler_Success;
}
static DecodeStatus DecodeANDI16Imm(MCInst *Inst, unsigned Insn,
				    uint64_t Address, MCRegisterInfo *Decoder)
{
  // Insn must be >= 0, since it is unsigned that condition is always true.
  assert(Insn < 16);
  int32_t DecodedValues[] = {128, 1,  2,  3,  4,  7,   8,     15,
			     16,  31, 32, 63, 64, 255, 32768, 65535};
  MCOperand_CreateImm0(Inst, DecodedValues[Insn]);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeRegListOperand(MCInst *Inst, unsigned Insn,
					 uint64_t Address,
					 MCRegisterInfo *Decoder)
{
  unsigned Regs[] = {Mips_S0, Mips_S1, Mips_S2, Mips_S3, Mips_S4,
		     Mips_S5, Mips_S6, Mips_S7, Mips_FP};
  unsigned RegNum;

  unsigned RegLst = fieldFromInstruction(Insn, 21, 5);

  // Empty register lists are not allowed.
  if (RegLst == 0)
    return MCDisassembler_Fail;

  RegNum = RegLst & 0xf;

  // RegLst values 10-15, and 26-31 are reserved.
  if (RegNum > 9)
    return MCDisassembler_Fail;

  for (unsigned i = 0; i < RegNum; i++)
    MCOperand_CreateReg0(Inst, Regs[i]);

  if (RegLst & 0x10)
    MCOperand_CreateReg0(Inst, Mips_RA);

  return MCDisassembler_Success;
}

static DecodeStatus DecodeRegListOperand16(MCInst *Inst, unsigned Insn,
					   uint64_t Address,
					   MCRegisterInfo *Decoder)
{
  unsigned Regs[] = {Mips_S0, Mips_S1, Mips_S2, Mips_S3};
  unsigned RegLst;
  switch (MCInst_getOpcode(Inst)) {
  default:
    RegLst = fieldFromInstruction(Insn, 4, 2);
    break;
  case Mips_LWM16_MMR6:
  case Mips_SWM16_MMR6:
    RegLst = fieldFromInstruction(Insn, 8, 2);
    break;
  }
  unsigned RegNum = RegLst & 0x3;

  for (unsigned i = 0; i <= RegNum; i++)
    MCOperand_CreateReg0(Inst, Regs[i]);

  MCOperand_CreateReg0(Inst, Mips_RA);

  return MCDisassembler_Success;
}

static DecodeStatus DecodeMovePOperands(MCInst *Inst, unsigned Insn,
					uint64_t Address,
					MCRegisterInfo *Decoder)
{
  unsigned RegPair = fieldFromInstruction(Insn, 7, 3);
  if (DecodeMovePRegPair(Inst, RegPair, Address, Decoder) ==
      MCDisassembler_Fail)
    return MCDisassembler_Fail;

  unsigned RegRs;
  if (Inst->csh->mode & CS_MODE_MIPS32R6)
    RegRs = fieldFromInstruction(Insn, 0, 2) |
	    (fieldFromInstruction(Insn, 3, 1) << 2);
  else
    RegRs = fieldFromInstruction(Insn, 1, 3);
  if (DecodeGPRMM16MovePRegisterClass(Inst, RegRs, Address, Decoder) ==
      MCDisassembler_Fail)
    return MCDisassembler_Fail;

  unsigned RegRt = fieldFromInstruction(Insn, 4, 3);
  if (DecodeGPRMM16MovePRegisterClass(Inst, RegRt, Address, Decoder) ==
      MCDisassembler_Fail)
    return MCDisassembler_Fail;

  return MCDisassembler_Success;
}
static DecodeStatus DecodeMovePRegPair(MCInst *Inst, unsigned RegPair,
				       uint64_t Address,
				       MCRegisterInfo *Decoder)
{
  switch (RegPair) {
  default:
    return MCDisassembler_Fail;
  case 0:
    MCOperand_CreateReg0(Inst, Mips_A1);
    MCOperand_CreateReg0(Inst, Mips_A2);
    break;
  case 1:
    MCOperand_CreateReg0(Inst, Mips_A1);
    MCOperand_CreateReg0(Inst, Mips_A3);
    break;
  case 2:
    MCOperand_CreateReg0(Inst, Mips_A2);
    MCOperand_CreateReg0(Inst, Mips_A3);
    break;
  case 3:
    MCOperand_CreateReg0(Inst, Mips_A0);
    MCOperand_CreateReg0(Inst, Mips_S5);
    break;
  case 4:
    MCOperand_CreateReg0(Inst, Mips_A0);
    MCOperand_CreateReg0(Inst, Mips_S6);
    break;
  case 5:
    MCOperand_CreateReg0(Inst, Mips_A0);
    MCOperand_CreateReg0(Inst, Mips_A1);
    break;
  case 6:
    MCOperand_CreateReg0(Inst, Mips_A0);
    MCOperand_CreateReg0(Inst, Mips_A2);
    break;
  case 7:
    MCOperand_CreateReg0(Inst, Mips_A0);
    MCOperand_CreateReg0(Inst, Mips_A3);
    break;
  }

  return MCDisassembler_Success;
}

static DecodeStatus DecodeSimm23Lsl2(MCInst *Inst, unsigned Insn,
				     uint64_t Address, MCRegisterInfo *Decoder)
{
  MCOperand_CreateImm0(Inst, SignExtend32(Insn << 2, 25));
  return MCDisassembler_Success;
}
static DecodeStatus DecodeBgtzGroupBranchMMR6(MCInst *MI, unsigned insn,
					      uint64_t Address,
					      MCRegisterInfo *Decoder)
{
  // We have:
  //    0b000111 ttttt sssss iiiiiiiiiiiiiiii
  //      Invalid      if rt == 0
  //      BGTZALC_MMR6 if rs == 0 && rt != 0
  //      BLTZALC_MMR6 if rs != 0 && rs == rt
  //      BLTUC_MMR6   if rs != 0 && rs != rt

  unsigned Rt = fieldFromInstruction(insn, 21, 5);
  unsigned Rs = fieldFromInstruction(insn, 16, 5);
  unsigned Imm = 0;
  bool HasRs = false;
  bool HasRt = false;

  if (Rt == 0)
    return MCDisassembler_Fail;
  else if (Rs == 0) {
    MCInst_setOpcode(MI, Mips_BGTZALC_MMR6);
    HasRt = true;
    Imm = SignExtend64(fieldFromInstruction(insn, 0, 16), 16) * 2 + 4;
  } else if (Rs == Rt) {
    MCInst_setOpcode(MI, Mips_BLTZALC_MMR6);
    HasRs = true;
    Imm = SignExtend64(fieldFromInstruction(insn, 0, 16), 16) * 2 + 4;
  } else {
    MCInst_setOpcode(MI, Mips_BLTUC_MMR6);
    HasRs = true;
    HasRt = true;
    Imm = SignExtend64(fieldFromInstruction(insn, 0, 16), 16) * 4 + 4;
  }

  if (HasRs)
    MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rs));

  if (HasRt)
    MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rt));

  MCOperand_CreateImm0(MI, Imm);

  return MCDisassembler_Success;
}

static DecodeStatus DecodeBlezGroupBranchMMR6(MCInst *MI, unsigned insn,
					      uint64_t Address,
					      MCRegisterInfo *Decoder)
{
  // We have:
  //    0b000110 ttttt sssss iiiiiiiiiiiiiiii
  //      Invalid        if rt == 0
  //      BLEZALC_MMR6   if rs == 0  && rt != 0
  //      BGEZALC_MMR6   if rs == rt && rt != 0
  //      BGEUC_MMR6     if rs != rt && rs != 0  && rt != 0

  unsigned Rt = fieldFromInstruction(insn, 21, 5);
  unsigned Rs = fieldFromInstruction(insn, 16, 5);
  unsigned Imm = 0;
  bool HasRs = false;

  if (Rt == 0)
    return MCDisassembler_Fail;
  else if (Rs == 0) {
    MCInst_setOpcode(MI, Mips_BLEZALC_MMR6);
    Imm = SignExtend64(fieldFromInstruction(insn, 0, 16), 16) * 2 + 4;
  } else if (Rs == Rt) {
    MCInst_setOpcode(MI, Mips_BGEZALC_MMR6);
    Imm = SignExtend64(fieldFromInstruction(insn, 0, 16), 16) * 2 + 4;
  } else {
    HasRs = true;
    MCInst_setOpcode(MI, Mips_BGEUC_MMR6);
    Imm = SignExtend64(fieldFromInstruction(insn, 0, 16), 16) * 4 + 4;
  }

  if (HasRs)
    MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rs));
  MCOperand_CreateReg0(MI, getReg(MI->MRI, Mips_GPR32RegClassID, Rt));

  MCOperand_CreateImm0(MI, Imm);

  return MCDisassembler_Success;
}
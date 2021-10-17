static void llvm_unreachable(const char *info) {}
static void assert(int val) {}
static unsigned std_max(unsigned a, unsigned b) { return (a > b) ? a : b; }
static unsigned std_min(unsigned a, unsigned b) { return (a < b) ? a : b; }
static DecodeStatus DecodeGPRRegisterClass(MCInst *Inst, unsigned RegNo,
					   uint64_t Address,
					   MCRegisterInfo *Decoder);

static DecodeStatus DecodeCLRMGPRRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodetGPROddRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodetGPREvenRegisterClass(MCInst *Inst, unsigned RegNo,
						uint64_t Address,
						MCRegisterInfo *Decoder);

static DecodeStatus DecodeGPRwithAPSR_NZCVnospRegisterClass(
    MCInst *Inst, unsigned RegNo, uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeGPRnopcRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodeGPRwithAPSRRegisterClass(MCInst *Inst, unsigned RegNo,
						   uint64_t Address,
						   MCRegisterInfo *Decoder);

static DecodeStatus DecodeGPRwithZRRegisterClass(MCInst *Inst, unsigned RegNo,
						 uint64_t Address,
						 MCRegisterInfo *Decoder);

static DecodeStatus DecodeGPRwithZRnospRegisterClass(MCInst *Inst,
						     unsigned RegNo,
						     uint64_t Address,
						     MCRegisterInfo *Decoder);

static DecodeStatus DecodetGPRRegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    MCRegisterInfo *Decoder);

static DecodeStatus DecodetcGPRRegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     MCRegisterInfo *Decoder);

static DecodeStatus DecoderGPRRegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    MCRegisterInfo *Decoder);

static DecodeStatus DecodeGPRPairRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodeGPRPairnospRegisterClass(MCInst *Inst, unsigned RegNo,
						   uint64_t Address,
						   MCRegisterInfo *Decoder);

static DecodeStatus DecodeGPRspRegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     MCRegisterInfo *Decoder);

static DecodeStatus DecodeHPRRegisterClass(MCInst *Inst, unsigned RegNo,
					   uint64_t Address,
					   MCRegisterInfo *Decoder);

static DecodeStatus DecodeSPRRegisterClass(MCInst *Inst, unsigned RegNo,
					   uint64_t Address,
					   MCRegisterInfo *Decoder);

static DecodeStatus DecodeDPRRegisterClass(MCInst *Inst, unsigned RegNo,
					   uint64_t Address,
					   MCRegisterInfo *Decoder);

static DecodeStatus DecodeDPR_8RegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     MCRegisterInfo *Decoder);

static DecodeStatus DecodeSPR_8RegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     MCRegisterInfo *Decoder);

static DecodeStatus DecodeDPR_VFP2RegisterClass(MCInst *Inst, unsigned RegNo,
						uint64_t Address,
						MCRegisterInfo *Decoder);

static DecodeStatus DecodeQPRRegisterClass(MCInst *Inst, unsigned RegNo,
					   uint64_t Address,
					   MCRegisterInfo *Decoder);

static DecodeStatus DecodeMQPRRegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    MCRegisterInfo *Decoder);

static DecodeStatus DecodeQQPRRegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    MCRegisterInfo *Decoder);

static DecodeStatus DecodeQQQQPRRegisterClass(MCInst *Inst, unsigned RegNo,
					      uint64_t Address,
					      MCRegisterInfo *Decoder);

static DecodeStatus DecodeDPairRegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     MCRegisterInfo *Decoder);

static DecodeStatus DecodeDPairSpacedRegisterClass(MCInst *Inst, unsigned RegNo,
						   uint64_t Address,
						   MCRegisterInfo *Decoder);

static DecodeStatus DecodePredicateOperand(MCInst *Inst, unsigned Val,
					   uint64_t Address,
					   const void *Decoder);

static DecodeStatus DecodeCCOutOperand(MCInst *Inst, unsigned Val,
				       uint64_t Address,
				       MCRegisterInfo *Decoder);

static DecodeStatus DecodeRegListOperand(MCInst *Inst, unsigned Val,
					 uint64_t Address,
					 MCRegisterInfo *Decoder);

static DecodeStatus DecodeSPRRegListOperand(MCInst *Inst, unsigned Val,
					    uint64_t Address,
					    MCRegisterInfo *Decoder);

static DecodeStatus DecodeDPRRegListOperand(MCInst *Inst, unsigned Val,
					    uint64_t Address,
					    MCRegisterInfo *Decoder);

static DecodeStatus DecodeBitfieldMaskOperand(MCInst *Inst, unsigned Insn,
					      uint64_t Address,
					      MCRegisterInfo *Decoder);

static DecodeStatus DecodeCopMemInstruction(MCInst *Inst, unsigned Insn,
					    uint64_t Address,
					    MCRegisterInfo *Decoder);

static DecodeStatus DecodeAddrMode2IdxInstruction(MCInst *Inst, unsigned Insn,
						  uint64_t Address,
						  MCRegisterInfo *Decoder);

static DecodeStatus DecodeSORegMemOperand(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder);

static DecodeStatus DecodeAddrMode3Instruction(MCInst *Inst, unsigned Insn,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodeSORegImmOperand(MCInst *Inst, unsigned Insn,
					  uint64_t Address,
					  MCRegisterInfo *Decoder);

static DecodeStatus DecodeSORegRegOperand(MCInst *Inst, unsigned Insn,
					  uint64_t Address,
					  MCRegisterInfo *Decoder);

static DecodeStatus DecodeMemMultipleWritebackInstruction(
    MCInst *Inst, unsigned Insn, uint64_t Adddress, MCRegisterInfo *Decoder);

static DecodeStatus DecodeT2MOVTWInstruction(MCInst *Inst, unsigned Insn,
					     uint64_t Address,
					     MCRegisterInfo *Decoder);

static DecodeStatus DecodeArmMOVTWInstruction(MCInst *Inst, unsigned Insn,
					      uint64_t Address,
					      MCRegisterInfo *Decoder);

static DecodeStatus DecodeSMLAInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address,
					  MCRegisterInfo *Decoder);

static DecodeStatus DecodeHINTInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address,
					  MCRegisterInfo *Decoder);

static DecodeStatus DecodeCPSInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address,
					 MCRegisterInfo *Decoder);

static DecodeStatus DecodeTSTInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address,
					 MCRegisterInfo *Decoder);

static DecodeStatus DecodeSETPANInstruction(MCInst *Inst, unsigned Insn,
					    uint64_t Address,
					    MCRegisterInfo *Decoder);

static DecodeStatus DecodeT2CPSInstruction(MCInst *Inst, unsigned Insn,
					   uint64_t Address,
					   MCRegisterInfo *Decoder);

static DecodeStatus DecodeAddrModeImm12Operand(MCInst *Inst, unsigned Val,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodeAddrMode5Operand(MCInst *Inst, unsigned Val,
					   uint64_t Address,
					   MCRegisterInfo *Decoder);

static DecodeStatus DecodeAddrMode5FP16Operand(MCInst *Inst, unsigned Val,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodeAddrMode7Operand(MCInst *Inst, unsigned Val,
					   uint64_t Address,
					   MCRegisterInfo *Decoder);

static DecodeStatus DecodeT2BInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address,
					 MCRegisterInfo *Decoder);

static DecodeStatus DecodeBranchImmInstruction(MCInst *Inst, unsigned Insn,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodeAddrMode6Operand(MCInst *Inst, unsigned Val,
					   uint64_t Address,
					   MCRegisterInfo *Decoder);

static DecodeStatus DecodeVLDST1Instruction(MCInst *Inst, unsigned Val,
					    uint64_t Address,
					    MCRegisterInfo *Decoder);

static DecodeStatus DecodeVLDST2Instruction(MCInst *Inst, unsigned Val,
					    uint64_t Address,
					    MCRegisterInfo *Decoder);

static DecodeStatus DecodeVLDST3Instruction(MCInst *Inst, unsigned Val,
					    uint64_t Address,
					    MCRegisterInfo *Decoder);

static DecodeStatus DecodeVLDST4Instruction(MCInst *Inst, unsigned Val,
					    uint64_t Address,
					    MCRegisterInfo *Decoder);

static DecodeStatus DecodeVLDInstruction(MCInst *Inst, unsigned Val,
					 uint64_t Address,
					 MCRegisterInfo *Decoder);

static DecodeStatus DecodeVSTInstruction(MCInst *Inst, unsigned Val,
					 uint64_t Address,
					 MCRegisterInfo *Decoder);

static DecodeStatus DecodeVLD1DupInstruction(MCInst *Inst, unsigned Val,
					     uint64_t Address,
					     MCRegisterInfo *Decoder);

static DecodeStatus DecodeVLD2DupInstruction(MCInst *Inst, unsigned Val,
					     uint64_t Address,
					     MCRegisterInfo *Decoder);

static DecodeStatus DecodeVLD3DupInstruction(MCInst *Inst, unsigned Val,
					     uint64_t Address,
					     MCRegisterInfo *Decoder);

static DecodeStatus DecodeVLD4DupInstruction(MCInst *Inst, unsigned Val,
					     uint64_t Address,
					     MCRegisterInfo *Decoder);

static DecodeStatus DecodeVMOVModImmInstruction(MCInst *Inst, unsigned Val,
						uint64_t Address,
						MCRegisterInfo *Decoder);

static DecodeStatus DecodeMVEModImmInstruction(MCInst *Inst, unsigned Val,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodeMVEVADCInstruction(MCInst *Inst, unsigned Insn,
					     uint64_t Address,
					     MCRegisterInfo *Decoder);

static DecodeStatus DecodeVSHLMaxInstruction(MCInst *Inst, unsigned Val,
					     uint64_t Address,
					     MCRegisterInfo *Decoder);

static DecodeStatus DecodeShiftRight8Imm(MCInst *Inst, unsigned Val,
					 uint64_t Address,
					 MCRegisterInfo *Decoder);

static DecodeStatus DecodeShiftRight16Imm(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder);

static DecodeStatus DecodeShiftRight32Imm(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder);

static DecodeStatus DecodeShiftRight64Imm(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder);

static DecodeStatus DecodeTBLInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address,
					 MCRegisterInfo *Decoder);

static DecodeStatus DecodePostIdxReg(MCInst *Inst, unsigned Insn,
				     uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeMveAddrModeRQ(MCInst *Inst, unsigned Insn,
					uint64_t Address,
					MCRegisterInfo *Decoder);

static DecodeStatus DecodeMveAddrModeQ(MCInst *Inst, unsigned Insn,
				       uint64_t Address,
				       MCRegisterInfo *Decoder, int shift);

static DecodeStatus DecodeCoprocessor(MCInst *Inst, unsigned Insn,
				      uint64_t Address,
				      MCRegisterInfo *Decoder);

static DecodeStatus DecodeMemBarrierOption(MCInst *Inst, unsigned Insn,
					   uint64_t Address,
					   MCRegisterInfo *Decoder);

static DecodeStatus DecodeInstSyncBarrierOption(MCInst *Inst, unsigned Insn,
						uint64_t Address,
						MCRegisterInfo *Decoder);

static DecodeStatus DecodeMSRMask(MCInst *Inst, unsigned Insn, uint64_t Address,
				  MCRegisterInfo *Decoder);

static DecodeStatus DecodeBankedReg(MCInst *Inst, unsigned Insn,
				    uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeDoubleRegLoad(MCInst *Inst, unsigned Insn,
					uint64_t Address,
					MCRegisterInfo *Decoder);

static DecodeStatus DecodeDoubleRegStore(MCInst *Inst, unsigned Insn,
					 uint64_t Address,
					 MCRegisterInfo *Decoder);

static DecodeStatus DecodeLDRPreImm(MCInst *Inst, unsigned Insn,
				    uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeLDRPreReg(MCInst *Inst, unsigned Insn,
				    uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeSTRPreImm(MCInst *Inst, unsigned Insn,
				    uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeSTRPreReg(MCInst *Inst, unsigned Insn,
				    uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeVLD1LN(MCInst *Inst, unsigned Insn, uint64_t Address,
				 MCRegisterInfo *Decoder);

static DecodeStatus DecodeVLD2LN(MCInst *Inst, unsigned Insn, uint64_t Address,
				 MCRegisterInfo *Decoder);

static DecodeStatus DecodeVLD3LN(MCInst *Inst, unsigned Insn, uint64_t Address,
				 MCRegisterInfo *Decoder);

static DecodeStatus DecodeVLD4LN(MCInst *Inst, unsigned Insn, uint64_t Address,
				 MCRegisterInfo *Decoder);

static DecodeStatus DecodeVST1LN(MCInst *Inst, unsigned Insn, uint64_t Address,
				 MCRegisterInfo *Decoder);

static DecodeStatus DecodeVST2LN(MCInst *Inst, unsigned Insn, uint64_t Address,
				 MCRegisterInfo *Decoder);

static DecodeStatus DecodeVST3LN(MCInst *Inst, unsigned Insn, uint64_t Address,
				 MCRegisterInfo *Decoder);

static DecodeStatus DecodeVST4LN(MCInst *Inst, unsigned Insn, uint64_t Address,
				 MCRegisterInfo *Decoder);

static DecodeStatus DecodeVMOVSRR(MCInst *Inst, unsigned Insn, uint64_t Address,
				  MCRegisterInfo *Decoder);

static DecodeStatus DecodeVMOVRRS(MCInst *Inst, unsigned Insn, uint64_t Address,
				  MCRegisterInfo *Decoder);

static DecodeStatus DecodeSwap(MCInst *Inst, unsigned Insn, uint64_t Address,
			       MCRegisterInfo *Decoder);

static DecodeStatus DecodeVCVTD(MCInst *Inst, unsigned Insn, uint64_t Address,
				MCRegisterInfo *Decoder);

static DecodeStatus DecodeVCVTQ(MCInst *Inst, unsigned Insn, uint64_t Address,
				MCRegisterInfo *Decoder);

static DecodeStatus DecodeVCVTImmOperand(MCInst *Inst, unsigned Insn,
					 uint64_t Address,
					 MCRegisterInfo *Decoder);

static DecodeStatus DecodeNEONComplexLane64Instruction(MCInst *Inst,
						       unsigned Val,
						       uint64_t Address,
						       MCRegisterInfo *Decoder);

static DecodeStatus DecodeThumbAddSpecialReg(MCInst *Inst, uint16_t Insn,
					     uint64_t Address,
					     MCRegisterInfo *Decoder);

static DecodeStatus DecodeThumbBROperand(MCInst *Inst, unsigned Val,
					 uint64_t Address,
					 MCRegisterInfo *Decoder);

static DecodeStatus DecodeT2BROperand(MCInst *Inst, unsigned Val,
				      uint64_t Address,
				      MCRegisterInfo *Decoder);

static DecodeStatus DecodeThumbCmpBROperand(MCInst *Inst, unsigned Val,
					    uint64_t Address,
					    MCRegisterInfo *Decoder);

static DecodeStatus DecodeThumbAddrModeRR(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder);

static DecodeStatus DecodeThumbAddrModeIS(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder);

static DecodeStatus DecodeThumbAddrModePC(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder);

static DecodeStatus DecodeThumbAddrModeSP(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder);

static DecodeStatus DecodeT2AddrModeSOReg(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder);

static DecodeStatus DecodeT2LoadShift(MCInst *Inst, unsigned Val,
				      uint64_t Address,
				      MCRegisterInfo *Decoder);

static DecodeStatus DecodeT2LoadImm8(MCInst *Inst, unsigned Insn,
				     uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeT2LoadImm12(MCInst *Inst, unsigned Insn,
				      uint64_t Address,
				      MCRegisterInfo *Decoder);

static DecodeStatus DecodeT2LoadT(MCInst *Inst, unsigned Insn, uint64_t Address,
				  MCRegisterInfo *Decoder);

static DecodeStatus DecodeT2LoadLabel(MCInst *Inst, unsigned Insn,
				      uint64_t Address,
				      MCRegisterInfo *Decoder);

static DecodeStatus DecodeT2Imm8S4(MCInst *Inst, unsigned Val, uint64_t Address,
				   MCRegisterInfo *Decoder);

static DecodeStatus DecodeT2Imm7S4(MCInst *Inst, unsigned Val, uint64_t Address,
				   MCRegisterInfo *Decoder);

static DecodeStatus DecodeT2AddrModeImm8s4(MCInst *Inst, unsigned Val,
					   uint64_t Address,
					   MCRegisterInfo *Decoder);

static DecodeStatus DecodeT2AddrModeImm7s4(MCInst *Inst, unsigned Val,
					   uint64_t Address,
					   MCRegisterInfo *Decoder);

static DecodeStatus DecodeT2AddrModeImm0_1020s4(MCInst *Inst, unsigned Val,
						uint64_t Address,
						MCRegisterInfo *Decoder);

static DecodeStatus DecodeT2Imm8(MCInst *Inst, unsigned Val, uint64_t Address,
				 MCRegisterInfo *Decoder);

static DecodeStatus DecodeT2Imm7(MCInst *Inst, unsigned Val, uint64_t Address,
				 MCRegisterInfo *Decoder, unsigned shift);

static DecodeStatus DecodeT2AddrModeImm8(MCInst *Inst, unsigned Val,
					 uint64_t Address,
					 MCRegisterInfo *Decoder);

static DecodeStatus DecodeTAddrModeImm7(MCInst *Inst, unsigned Val,
					uint64_t Address,
					MCRegisterInfo *Decoder,
					unsigned shift);

static DecodeStatus DecodeT2AddrModeImm7(MCInst *Inst, unsigned Val,
					 uint64_t Address,
					 MCRegisterInfo *Decoder, int shift,
					 int WriteBack);

static DecodeStatus DecodeThumbAddSPImm(MCInst *Inst, uint16_t Val,
					uint64_t Address,
					MCRegisterInfo *Decoder);

static DecodeStatus DecodeThumbAddSPReg(MCInst *Inst, uint16_t Insn,
					uint64_t Address,
					MCRegisterInfo *Decoder);

static DecodeStatus DecodeThumbCPS(MCInst *Inst, uint16_t Insn,
				   uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeQADDInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address,
					  MCRegisterInfo *Decoder);

static DecodeStatus DecodeThumbBLXOffset(MCInst *Inst, unsigned Insn,
					 uint64_t Address,
					 MCRegisterInfo *Decoder);

static DecodeStatus DecodeT2AddrModeImm12(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder);

static DecodeStatus DecodeThumbTableBranch(MCInst *Inst, unsigned Insn,
					   uint64_t Address,
					   MCRegisterInfo *Decoder);

static DecodeStatus DecodeThumb2BCCInstruction(MCInst *Inst, unsigned Insn,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodeT2SOImm(MCInst *Inst, unsigned Val, uint64_t Address,
				  MCRegisterInfo *Decoder);

static DecodeStatus DecodeThumbBCCTargetOperand(MCInst *Inst, unsigned Val,
						uint64_t Address,
						MCRegisterInfo *Decoder);

static DecodeStatus DecodeThumbBLTargetOperand(MCInst *Inst, unsigned Val,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodeIT(MCInst *Inst, unsigned Val, uint64_t Address,
			     MCRegisterInfo *Decoder);

static DecodeStatus DecodeT2LDRDPreInstruction(MCInst *Inst, unsigned Insn,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodeT2STRDPreInstruction(MCInst *Inst, unsigned Insn,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodeT2Adr(MCInst *Inst, unsigned Val, uint64_t Address,
				MCRegisterInfo *Decoder);

static DecodeStatus DecodeT2LdStPre(MCInst *Inst, unsigned Val,
				    uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeT2ShifterImmOperand(MCInst *Inst, unsigned Val,
					      uint64_t Address,
					      MCRegisterInfo *Decoder);

static DecodeStatus DecodeLDR(MCInst *Inst, unsigned Val, uint64_t Address,
			      MCRegisterInfo *Decoder);

static DecodeStatus DecoderForMRRC2AndMCRR2(MCInst *Inst, unsigned Val,
					    uint64_t Address,
					    MCRegisterInfo *Decoder);

static DecodeStatus DecodeForVMRSandVMSR(MCInst *Inst, unsigned Val,
					 uint64_t Address,
					 MCRegisterInfo *Decoder);

static DecodeStatus DecodeBFLabelOperand(MCInst *Inst, unsigned Val,
					 uint64_t Address,
					 MCRegisterInfo *Decoder, bool isSigned,
					 bool isNeg, bool zeroPermitted,
					 int size);

static DecodeStatus DecodeBFAfterTargetOperand(MCInst *Inst, unsigned val,
					       uint64_t Address,
					       MCRegisterInfo *Decoder);

static DecodeStatus DecodePredNoALOperand(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder);

static DecodeStatus DecodeLOLoop(MCInst *Inst, unsigned Insn, uint64_t Address,
				 MCRegisterInfo *Decoder);

static DecodeStatus DecodeLongShiftOperand(MCInst *Inst, unsigned Val,
					   uint64_t Address,
					   MCRegisterInfo *Decoder);

static DecodeStatus DecodeVSCCLRM(MCInst *Inst, unsigned Insn, uint64_t Address,
				  MCRegisterInfo *Decoder);

static DecodeStatus DecodeVPTMaskOperand(MCInst *Inst, unsigned Val,
					 uint64_t Address,
					 MCRegisterInfo *Decoder);

static DecodeStatus DecodeVpredROperand(MCInst *Inst, unsigned Val,
					uint64_t Address,
					MCRegisterInfo *Decoder);

static DecodeStatus DecodeRestrictedIPredicateOperand(MCInst *Inst,
						      unsigned Val,
						      uint64_t Address,
						      MCRegisterInfo *Decoder);

static DecodeStatus DecodeRestrictedSPredicateOperand(MCInst *Inst,
						      unsigned Val,
						      uint64_t Address,
						      MCRegisterInfo *Decoder);

static DecodeStatus DecodeRestrictedUPredicateOperand(MCInst *Inst,
						      unsigned Val,
						      uint64_t Address,
						      MCRegisterInfo *Decoder);

static DecodeStatus DecodeRestrictedFPPredicateOperand(MCInst *Inst,
						       unsigned Val,
						       uint64_t Address,
						       MCRegisterInfo *Decoder);

static DecodeStatus DecodeVSTRVLDR_SYSREG(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder,
					  bool Writeback);

static DecodeStatus DecodeMVE_MEM_1_pre(MCInst *Inst, unsigned Val,
					uint64_t Address,
					MCRegisterInfo *Decoder, int shift);

static DecodeStatus DecodeMVE_MEM_2_pre(MCInst *Inst, unsigned Val,
					uint64_t Address,
					MCRegisterInfo *Decoder, int shift);

static DecodeStatus DecodeMVE_MEM_3_pre(MCInst *Inst, unsigned Val,
					uint64_t Address,
					MCRegisterInfo *Decoder, int shift);

static DecodeStatus DecodePowerTwoOperand(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder,
					  unsigned MinLog, unsigned MaxLog);

static DecodeStatus DecodeMVEPairVectorIndexOperand(MCInst *Inst, unsigned Val,
						    uint64_t Address,
						    MCRegisterInfo *Decoder,
						    unsigned start);

static DecodeStatus DecodeMVEVMOVQtoDReg(MCInst *Inst, unsigned Insn,
					 uint64_t Address,
					 MCRegisterInfo *Decoder);

static DecodeStatus DecodeMVEVMOVDRegtoQ(MCInst *Inst, unsigned Insn,
					 uint64_t Address,
					 MCRegisterInfo *Decoder);

static DecodeStatus DecodeMVEVCVTt1fp(MCInst *Inst, unsigned Insn,
				      uint64_t Address,
				      MCRegisterInfo *Decoder);

static DecodeStatus DecodeMVEVCMP(MCInst *Inst, unsigned Insn, uint64_t Address,
				  MCRegisterInfo *Decoder, unsigned scalar, void* omitted);

static DecodeStatus DecodeMveVCTP(MCInst *Inst, unsigned Insn, uint64_t Address,
				  MCRegisterInfo *Decoder);

static DecodeStatus DecodeMVEVPNOT(MCInst *Inst, unsigned Insn,
				   uint64_t Address, MCRegisterInfo *Decoder);

static DecodeStatus DecodeMVEOverlappingLongShift(MCInst *Inst, unsigned Insn,
						  uint64_t Address,
						  MCRegisterInfo *Decoder);

static DecodeStatus DecodeT2AddSubSPImm(MCInst *Inst, unsigned Insn,
					uint64_t Address,
					MCRegisterInfo *Decoder);

#define GET_INSTRINFO_ENUM
#define GET_REGINFO_ENUM
#define MIPS_GET_DISASSEMBLER
#include "ARMGenDisassemblerTables.inc"

FieldFromInstruction(fieldFromInstruction_2, uint16_t)
    DecodeToMCInst(decodeToMCInst_2, fieldFromInstruction_2,
		   uint16_t) DecodeInstruction(decodeInstruction_2,
					       fieldFromInstruction_2,
					       decodeToMCInst_2, uint16_t)

	FieldFromInstruction(fieldFromInstruction_4, uint32_t)
	    DecodeToMCInst(decodeToMCInst_4, fieldFromInstruction_4, uint32_t)
		DecodeInstruction(decodeInstruction_4, fieldFromInstruction_4,
				  decodeToMCInst_4, uint32_t)

		    static const uint16_t GPRDecoderTable[] = {
			ARM_R0,  ARM_R1, ARM_R2, ARM_R3, ARM_R4,  ARM_R5,
			ARM_R6,  ARM_R7, ARM_R8, ARM_R9, ARM_R10, ARM_R11,
			ARM_R12, ARM_SP, ARM_LR, ARM_PC};

static const uint16_t CLRMGPRDecoderTable[] = {
    ARM_R0, ARM_R1, ARM_R2,  ARM_R3,  ARM_R4,  ARM_R5, ARM_R6, ARM_R7,
    ARM_R8, ARM_R9, ARM_R10, ARM_R11, ARM_R12, 0,      ARM_LR, ARM_APSR};

static DecodeStatus DecodeGPRRegisterClass(MCInst *Inst, unsigned RegNo,
					   uint64_t Address,
					   MCRegisterInfo *Decoder)
{
  if (RegNo > 15)
    return MCDisassembler_Fail;

  unsigned Register = GPRDecoderTable[RegNo];
  MCOperand_CreateReg0(Inst, Register);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeCLRMGPRRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  if (RegNo > 15)
    return MCDisassembler_Fail;

  unsigned Register = CLRMGPRDecoderTable[RegNo];
  if (Register == 0)
    return MCDisassembler_Fail;

  MCOperand_CreateReg0(Inst, Register);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeGPRnopcRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  if (RegNo == 15)
    S = MCDisassembler_SoftFail;

  Check(&S, DecodeGPRRegisterClass(Inst, RegNo, Address, Decoder));

  return S;
}

static DecodeStatus DecodeGPRwithAPSRRegisterClass(MCInst *Inst, unsigned RegNo,
						   uint64_t Address,
						   MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  if (RegNo == 15) {
    MCOperand_CreateReg0(Inst, ARM_APSR_NZCV);
    return MCDisassembler_Success;
  }

  Check(&S, DecodeGPRRegisterClass(Inst, RegNo, Address, Decoder));
  return S;
}

static DecodeStatus DecodeGPRwithZRRegisterClass(MCInst *Inst, unsigned RegNo,
						 uint64_t Address,
						 MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  if (RegNo == 15) {
    MCOperand_CreateReg0(Inst, ARM_ZR);
    return MCDisassembler_Success;
  }

  if (RegNo == 13)
    Check(&S, MCDisassembler_SoftFail);

  Check(&S, DecodeGPRRegisterClass(Inst, RegNo, Address, Decoder));
  return S;
}

static DecodeStatus DecodeGPRwithZRnospRegisterClass(MCInst *Inst,
						     unsigned RegNo,
						     uint64_t Address,
						     MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;
  if (RegNo == 13)
    return MCDisassembler_Fail;
  Check(&S, DecodeGPRwithZRRegisterClass(Inst, RegNo, Address, Decoder));
  return S;
}

static DecodeStatus DecodetGPRRegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    MCRegisterInfo *Decoder)
{
  if (RegNo > 7)
    return MCDisassembler_Fail;
  return DecodeGPRRegisterClass(Inst, RegNo, Address, Decoder);
}

static const uint16_t GPRPairDecoderTable[] = {
    ARM_R0_R1, ARM_R2_R3,   ARM_R4_R5, ARM_R6_R7,
    ARM_R8_R9, ARM_R10_R11, ARM_R12_SP};

static DecodeStatus DecodeGPRPairRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  // According to the Arm ARM RegNo = 14 is undefined, but we return fail
  // rather than SoftFail as there is no GPRPair table entry for index 7.
  if (RegNo > 13)
    return MCDisassembler_Fail;

  if (RegNo & 1)
    S = MCDisassembler_SoftFail;

  unsigned RegisterPair = GPRPairDecoderTable[RegNo / 2];
  MCOperand_CreateReg0(Inst, RegisterPair);
  return S;
}

static DecodeStatus DecodeGPRPairnospRegisterClass(MCInst *Inst, unsigned RegNo,
						   uint64_t Address,
						   MCRegisterInfo *Decoder)
{
  if (RegNo > 13)
    return MCDisassembler_Fail;

  unsigned RegisterPair = GPRPairDecoderTable[RegNo / 2];
  MCOperand_CreateReg0(Inst, RegisterPair);

  if ((RegNo & 1) || RegNo > 10)
    return MCDisassembler_SoftFail;
  return MCDisassembler_Success;
}

static DecodeStatus DecodeGPRspRegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     MCRegisterInfo *Decoder)
{
  if (RegNo != 13)
    return MCDisassembler_Fail;

  unsigned Register = GPRDecoderTable[RegNo];
  MCOperand_CreateReg0(Inst, Register);
  return MCDisassembler_Success;
}

static DecodeStatus DecodetcGPRRegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     MCRegisterInfo *Decoder)
{
  unsigned Register = 0;
  switch (RegNo) {
  case 0:
    Register = ARM_R0;
    break;
  case 1:
    Register = ARM_R1;
    break;
  case 2:
    Register = ARM_R2;
    break;
  case 3:
    Register = ARM_R3;
    break;
  case 9:
    Register = ARM_R9;
    break;
  case 12:
    Register = ARM_R12;
    break;
  default:
    return MCDisassembler_Fail;
  }

  MCOperand_CreateReg0(Inst, Register);
  return MCDisassembler_Success;
}

static DecodeStatus DecoderGPRRegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  /* Ignored bit flags */

  if ((RegNo == 13 && !true) || RegNo == 15)
    S = MCDisassembler_SoftFail;

  Check(&S, DecodeGPRRegisterClass(Inst, RegNo, Address, Decoder));
  return S;
}

static const uint16_t SPRDecoderTable[] = {
    ARM_S0,  ARM_S1,  ARM_S2,  ARM_S3,  ARM_S4,  ARM_S5,  ARM_S6,  ARM_S7,
    ARM_S8,  ARM_S9,  ARM_S10, ARM_S11, ARM_S12, ARM_S13, ARM_S14, ARM_S15,
    ARM_S16, ARM_S17, ARM_S18, ARM_S19, ARM_S20, ARM_S21, ARM_S22, ARM_S23,
    ARM_S24, ARM_S25, ARM_S26, ARM_S27, ARM_S28, ARM_S29, ARM_S30, ARM_S31};

static DecodeStatus DecodeSPRRegisterClass(MCInst *Inst, unsigned RegNo,
					   uint64_t Address,
					   MCRegisterInfo *Decoder)
{
  if (RegNo > 31)
    return MCDisassembler_Fail;

  unsigned Register = SPRDecoderTable[RegNo];
  MCOperand_CreateReg0(Inst, Register);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeHPRRegisterClass(MCInst *Inst, unsigned RegNo,
					   uint64_t Address,
					   MCRegisterInfo *Decoder)
{
  return DecodeSPRRegisterClass(Inst, RegNo, Address, Decoder);
}

static const uint16_t DPRDecoderTable[] = {
    ARM_D0,  ARM_D1,  ARM_D2,  ARM_D3,  ARM_D4,  ARM_D5,  ARM_D6,  ARM_D7,
    ARM_D8,  ARM_D9,  ARM_D10, ARM_D11, ARM_D12, ARM_D13, ARM_D14, ARM_D15,
    ARM_D16, ARM_D17, ARM_D18, ARM_D19, ARM_D20, ARM_D21, ARM_D22, ARM_D23,
    ARM_D24, ARM_D25, ARM_D26, ARM_D27, ARM_D28, ARM_D29, ARM_D30, ARM_D31};

static DecodeStatus DecodeDPRRegisterClass(MCInst *Inst, unsigned RegNo,
					   uint64_t Address,
					   MCRegisterInfo *Decoder)
{
  /* Ignored bit flags */

  bool hasD32 = true;

  if (RegNo > 31 || (!hasD32 && RegNo > 15))
    return MCDisassembler_Fail;

  unsigned Register = DPRDecoderTable[RegNo];
  MCOperand_CreateReg0(Inst, Register);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeDPR_8RegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     MCRegisterInfo *Decoder)
{
  if (RegNo > 7)
    return MCDisassembler_Fail;
  return DecodeDPRRegisterClass(Inst, RegNo, Address, Decoder);
}

static DecodeStatus DecodeSPR_8RegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     MCRegisterInfo *Decoder)
{
  if (RegNo > 15)
    return MCDisassembler_Fail;
  return DecodeSPRRegisterClass(Inst, RegNo, Address, Decoder);
}

static DecodeStatus DecodeDPR_VFP2RegisterClass(MCInst *Inst, unsigned RegNo,
						uint64_t Address,
						MCRegisterInfo *Decoder)
{
  if (RegNo > 15)
    return MCDisassembler_Fail;
  return DecodeDPRRegisterClass(Inst, RegNo, Address, Decoder);
}

static const uint16_t QPRDecoderTable[] = {
    ARM_Q0, ARM_Q1, ARM_Q2,  ARM_Q3,  ARM_Q4,  ARM_Q5,  ARM_Q6,  ARM_Q7,
    ARM_Q8, ARM_Q9, ARM_Q10, ARM_Q11, ARM_Q12, ARM_Q13, ARM_Q14, ARM_Q15};

static DecodeStatus DecodeQPRRegisterClass(MCInst *Inst, unsigned RegNo,
					   uint64_t Address,
					   MCRegisterInfo *Decoder)
{
  if (RegNo > 31 || (RegNo & 1) != 0)
    return MCDisassembler_Fail;
  RegNo >>= 1;

  unsigned Register = QPRDecoderTable[RegNo];
  MCOperand_CreateReg0(Inst, Register);
  return MCDisassembler_Success;
}

static const uint16_t DPairDecoderTable[] = {
    ARM_Q0,  ARM_D1_D2,   ARM_Q1,  ARM_D3_D4,   ARM_Q2,  ARM_D5_D6,
    ARM_Q3,  ARM_D7_D8,   ARM_Q4,  ARM_D9_D10,  ARM_Q5,  ARM_D11_D12,
    ARM_Q6,  ARM_D13_D14, ARM_Q7,  ARM_D15_D16, ARM_Q8,  ARM_D17_D18,
    ARM_Q9,  ARM_D19_D20, ARM_Q10, ARM_D21_D22, ARM_Q11, ARM_D23_D24,
    ARM_Q12, ARM_D25_D26, ARM_Q13, ARM_D27_D28, ARM_Q14, ARM_D29_D30,
    ARM_Q15};

static DecodeStatus DecodeDPairRegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     MCRegisterInfo *Decoder)
{
  if (RegNo > 30)
    return MCDisassembler_Fail;

  unsigned Register = DPairDecoderTable[RegNo];
  MCOperand_CreateReg0(Inst, Register);
  return MCDisassembler_Success;
}

static const uint16_t DPairSpacedDecoderTable[] = {
    ARM_D0_D2,   ARM_D1_D3,   ARM_D2_D4,   ARM_D3_D5,   ARM_D4_D6,
    ARM_D5_D7,   ARM_D6_D8,   ARM_D7_D9,   ARM_D8_D10,  ARM_D9_D11,
    ARM_D10_D12, ARM_D11_D13, ARM_D12_D14, ARM_D13_D15, ARM_D14_D16,
    ARM_D15_D17, ARM_D16_D18, ARM_D17_D19, ARM_D18_D20, ARM_D19_D21,
    ARM_D20_D22, ARM_D21_D23, ARM_D22_D24, ARM_D23_D25, ARM_D24_D26,
    ARM_D25_D27, ARM_D26_D28, ARM_D27_D29, ARM_D28_D30, ARM_D29_D31};

static DecodeStatus DecodeDPairSpacedRegisterClass(MCInst *Inst, unsigned RegNo,
						   uint64_t Address,
						   MCRegisterInfo *Decoder)
{
  if (RegNo > 29)
    return MCDisassembler_Fail;

  unsigned Register = DPairSpacedDecoderTable[RegNo];
  MCOperand_CreateReg0(Inst, Register);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeCCOutOperand(MCInst *Inst, unsigned Val,
				       uint64_t Address,
				       MCRegisterInfo *Decoder)
{
  if (Val)
    MCOperand_CreateReg0(Inst, ARM_CPSR);
  else
    MCOperand_CreateReg0(Inst, 0);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeSORegImmOperand(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rm = fieldFromInstruction_4(Val, 0, 4);
  unsigned type = fieldFromInstruction_4(Val, 5, 2);
  unsigned imm = fieldFromInstruction_4(Val, 7, 5);

  // Register-immediate
  if (!Check(&S, DecoderGPRRegisterClass(Inst, Rm, Address, Decoder)))
    return MCDisassembler_Fail;

  ARM_AM_ShiftOpc Shift = ARM_AM_lsl;
  switch (type) {
  case 0:
    Shift = ARM_AM_lsl;
    break;
  case 1:
    Shift = ARM_AM_lsr;
    break;
  case 2:
    Shift = ARM_AM_asr;
    break;
  case 3:
    Shift = ARM_AM_ror;
    break;
  }

  if (Shift == ARM_AM_ror && imm == 0)
    Shift = ARM_AM_rrx;

  unsigned Op = Shift | (imm << 3);
  MCOperand_CreateImm0(Inst, Op);

  return S;
}

static DecodeStatus DecodeSORegRegOperand(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rm = fieldFromInstruction_4(Val, 0, 4);
  unsigned type = fieldFromInstruction_4(Val, 5, 2);
  unsigned Rs = fieldFromInstruction_4(Val, 8, 4);

  // Register-register
  if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rm, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rs, Address, Decoder)))
    return MCDisassembler_Fail;

  ARM_AM_ShiftOpc Shift = ARM_AM_lsl;
  switch (type) {
  case 0:
    Shift = ARM_AM_lsl;
    break;
  case 1:
    Shift = ARM_AM_lsr;
    break;
  case 2:
    Shift = ARM_AM_asr;
    break;
  case 3:
    Shift = ARM_AM_ror;
    break;
  }

  MCOperand_CreateImm0(Inst, Shift);

  return S;
}

static DecodeStatus DecodeRegListOperand(MCInst *Inst, unsigned Val,
					 uint64_t Address,
					 MCRegisterInfo *Decoder)
{
  unsigned i;
  DecodeStatus S = MCDisassembler_Success;
  unsigned opcode;
  bool NeedDisjointWriteback = false;
  unsigned WritebackReg = 0;

  opcode = MCInst_getOpcode(Inst);
  switch (opcode) {
  default:
    break;

  case ARM_LDMIA_UPD:
  case ARM_LDMDB_UPD:
  case ARM_LDMIB_UPD:
  case ARM_LDMDA_UPD:
  case ARM_t2LDMIA_UPD:
  case ARM_t2LDMDB_UPD:
  case ARM_t2STMIA_UPD:
  case ARM_t2STMDB_UPD:
    NeedDisjointWriteback = true;
    WritebackReg = MCOperand_getReg(MCInst_getOperand(Inst, 0));
    break;
  }

  // Empty register lists are not allowed.
  if (Val == 0)
    return MCDisassembler_Fail;

  for (i = 0; i < 16; ++i) {
    if (Val & (1 << i)) {
      if (!Check(&S, DecodeGPRRegisterClass(Inst, i, Address, Decoder)))
	return MCDisassembler_Fail;

      // Writeback not allowed if Rn is in the target list.
      if (NeedDisjointWriteback &&
	  WritebackReg == MCOperand_getReg(&(Inst->Operands[Inst->size - 1])))
	Check(&S, MCDisassembler_SoftFail);
    }
  }

  return S;
}

static DecodeStatus DecodeSPRRegListOperand(MCInst *Inst, unsigned Val,
					    uint64_t Address,
					    MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Vd = fieldFromInstruction_4(Val, 8, 5);
  unsigned regs = fieldFromInstruction_4(Val, 0, 8);

  // In case of unpredictable encoding, tweak the operands.
  if (regs == 0 || (Vd + regs) > 32) {
    regs = Vd + regs > 32 ? 32 - Vd : regs;
    regs = std_max(1u, regs);
    S = MCDisassembler_SoftFail;
  }

  if (!Check(&S, DecodeSPRRegisterClass(Inst, Vd, Address, Decoder)))
    return MCDisassembler_Fail;
  for (unsigned i = 0; i < (regs - 1); ++i) {
    if (!Check(&S, DecodeSPRRegisterClass(Inst, ++Vd, Address, Decoder)))
      return MCDisassembler_Fail;
  }

  return S;
}

static DecodeStatus DecodeDPRRegListOperand(MCInst *Inst, unsigned Val,
					    uint64_t Address,
					    MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Vd = fieldFromInstruction_4(Val, 8, 5);
  unsigned regs = fieldFromInstruction_4(Val, 1, 7);

  // In case of unpredictable encoding, tweak the operands.
  if (regs == 0 || regs > 16 || (Vd + regs) > 32) {
    regs = Vd + regs > 32 ? 32 - Vd : regs;
    regs = std_max(1u, regs);
    regs = std_min(16u, regs);
    S = MCDisassembler_SoftFail;
  }

  if (!Check(&S, DecodeDPRRegisterClass(Inst, Vd, Address, Decoder)))
    return MCDisassembler_Fail;
  for (unsigned i = 0; i < (regs - 1); ++i) {
    if (!Check(&S, DecodeDPRRegisterClass(Inst, ++Vd, Address, Decoder)))
      return MCDisassembler_Fail;
  }

  return S;
}

static DecodeStatus DecodeBitfieldMaskOperand(MCInst *Inst, unsigned Val,
					      uint64_t Address,
					      MCRegisterInfo *Decoder)
{
  // This operand encodes a mask of contiguous zeros between a specified MSB
  // and LSB.  To decode it, we create the mask of all bits MSB-and-lower,
  // the mask of all bits LSB-and-lower, and then xor them to create
  // the mask of that's all ones on [msb, lsb].  Finally we not it to
  // create the final mask.
  unsigned msb = fieldFromInstruction_4(Val, 5, 5);
  unsigned lsb = fieldFromInstruction_4(Val, 0, 5);

  DecodeStatus S = MCDisassembler_Success;
  if (lsb > msb) {
    Check(&S, MCDisassembler_SoftFail);
    // The check above will cause the warning for the "potentially undefined
    // instruction encoding" but we can't build a bad MCOperand value here
    // with a lsb > msb or else printing the MCInst will cause a crash.
    lsb = msb;
  }

  uint32_t msb_mask = 0xFFFFFFFF;
  if (msb != 31)
    msb_mask = (1U << (msb + 1)) - 1;
  uint32_t lsb_mask = (1U << lsb) - 1;

  MCOperand_CreateImm0(Inst, ~(msb_mask ^ lsb_mask));
  return S;
}

static DecodeStatus DecodeCopMemInstruction(MCInst *Inst, unsigned Insn,
					    uint64_t Address,
					    MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned pred = fieldFromInstruction_4(Insn, 28, 4);
  unsigned CRd = fieldFromInstruction_4(Insn, 12, 4);
  unsigned coproc = fieldFromInstruction_4(Insn, 8, 4);
  unsigned imm = fieldFromInstruction_4(Insn, 0, 8);
  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned U = fieldFromInstruction_4(Insn, 23, 1);
  /* Ignored bit flags */

  switch (MCInst_getOpcode(Inst)) {
  case ARM_LDC_OFFSET:
  case ARM_LDC_PRE:
  case ARM_LDC_POST:
  case ARM_LDC_OPTION:
  case ARM_LDCL_OFFSET:
  case ARM_LDCL_PRE:
  case ARM_LDCL_POST:
  case ARM_LDCL_OPTION:
  case ARM_STC_OFFSET:
  case ARM_STC_PRE:
  case ARM_STC_POST:
  case ARM_STC_OPTION:
  case ARM_STCL_OFFSET:
  case ARM_STCL_PRE:
  case ARM_STCL_POST:
  case ARM_STCL_OPTION:
  case ARM_t2LDC_OFFSET:
  case ARM_t2LDC_PRE:
  case ARM_t2LDC_POST:
  case ARM_t2LDC_OPTION:
  case ARM_t2LDCL_OFFSET:
  case ARM_t2LDCL_PRE:
  case ARM_t2LDCL_POST:
  case ARM_t2LDCL_OPTION:
  case ARM_t2STC_OFFSET:
  case ARM_t2STC_PRE:
  case ARM_t2STC_POST:
  case ARM_t2STC_OPTION:
  case ARM_t2STCL_OFFSET:
  case ARM_t2STCL_PRE:
  case ARM_t2STCL_POST:
  case ARM_t2STCL_OPTION:
  case ARM_t2LDC2_OFFSET:
  case ARM_t2LDC2L_OFFSET:
  case ARM_t2LDC2_PRE:
  case ARM_t2LDC2L_PRE:
  case ARM_t2STC2_OFFSET:
  case ARM_t2STC2L_OFFSET:
  case ARM_t2STC2_PRE:
  case ARM_t2STC2L_PRE:
  case ARM_LDC2_OFFSET:
  case ARM_LDC2L_OFFSET:
  case ARM_LDC2_PRE:
  case ARM_LDC2L_PRE:
  case ARM_STC2_OFFSET:
  case ARM_STC2L_OFFSET:
  case ARM_STC2_PRE:
  case ARM_STC2L_PRE:
  case ARM_t2LDC2_OPTION:
  case ARM_t2STC2_OPTION:
  case ARM_t2LDC2_POST:
  case ARM_t2LDC2L_POST:
  case ARM_t2STC2_POST:
  case ARM_t2STC2L_POST:
  case ARM_LDC2_POST:
  case ARM_LDC2L_POST:
  case ARM_STC2_POST:
  case ARM_STC2L_POST:
    if (coproc == 0xA || coproc == 0xB ||
	(true && (coproc == 0x8 || coproc == 0x9 || coproc == 0xA ||
		  coproc == 0xB || coproc == 0xE || coproc == 0xF)))
      return MCDisassembler_Fail;
    break;
  default:
    break;
  }

  if (true && (coproc != 14))
    return MCDisassembler_Fail;

  MCOperand_CreateImm0(Inst, coproc);
  MCOperand_CreateImm0(Inst, CRd);
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;

  switch (MCInst_getOpcode(Inst)) {
  case ARM_t2LDC2_OFFSET:
  case ARM_t2LDC2L_OFFSET:
  case ARM_t2LDC2_PRE:
  case ARM_t2LDC2L_PRE:
  case ARM_t2STC2_OFFSET:
  case ARM_t2STC2L_OFFSET:
  case ARM_t2STC2_PRE:
  case ARM_t2STC2L_PRE:
  case ARM_LDC2_OFFSET:
  case ARM_LDC2L_OFFSET:
  case ARM_LDC2_PRE:
  case ARM_LDC2L_PRE:
  case ARM_STC2_OFFSET:
  case ARM_STC2L_OFFSET:
  case ARM_STC2_PRE:
  case ARM_STC2L_PRE:
  case ARM_t2LDC_OFFSET:
  case ARM_t2LDCL_OFFSET:
  case ARM_t2LDC_PRE:
  case ARM_t2LDCL_PRE:
  case ARM_t2STC_OFFSET:
  case ARM_t2STCL_OFFSET:
  case ARM_t2STC_PRE:
  case ARM_t2STCL_PRE:
  case ARM_LDC_OFFSET:
  case ARM_LDCL_OFFSET:
  case ARM_LDC_PRE:
  case ARM_LDCL_PRE:
  case ARM_STC_OFFSET:
  case ARM_STCL_OFFSET:
  case ARM_STC_PRE:
  case ARM_STCL_PRE:
    imm = ARM_AM_getAM5Opc(U ? ARM_AM_add : ARM_AM_sub, imm);
    MCOperand_CreateImm0(Inst, imm);
    break;
  case ARM_t2LDC2_POST:
  case ARM_t2LDC2L_POST:
  case ARM_t2STC2_POST:
  case ARM_t2STC2L_POST:
  case ARM_LDC2_POST:
  case ARM_LDC2L_POST:
  case ARM_STC2_POST:
  case ARM_STC2L_POST:
  case ARM_t2LDC_POST:
  case ARM_t2LDCL_POST:
  case ARM_t2STC_POST:
  case ARM_t2STCL_POST:
  case ARM_LDC_POST:
  case ARM_LDCL_POST:
  case ARM_STC_POST:
  case ARM_STCL_POST:
    imm |= U << 8;
    0x0;
  default:
    // The 'option' variant doesn't encode 'U' in the immediate since
    // the immediate is unsigned [0,255].
    MCOperand_CreateImm0(Inst, imm);
    break;
  }

  switch (MCInst_getOpcode(Inst)) {
  case ARM_LDC_OFFSET:
  case ARM_LDC_PRE:
  case ARM_LDC_POST:
  case ARM_LDC_OPTION:
  case ARM_LDCL_OFFSET:
  case ARM_LDCL_PRE:
  case ARM_LDCL_POST:
  case ARM_LDCL_OPTION:
  case ARM_STC_OFFSET:
  case ARM_STC_PRE:
  case ARM_STC_POST:
  case ARM_STC_OPTION:
  case ARM_STCL_OFFSET:
  case ARM_STCL_PRE:
  case ARM_STCL_POST:
  case ARM_STCL_OPTION:
    if (!Check(&S, DecodePredicateOperand(Inst, pred, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  default:
    break;
  }

  return S;
}

static DecodeStatus DecodeAddrMode2IdxInstruction(MCInst *Inst, unsigned Insn,
						  uint64_t Address,
						  MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rt = fieldFromInstruction_4(Insn, 12, 4);
  unsigned Rm = fieldFromInstruction_4(Insn, 0, 4);
  unsigned imm = fieldFromInstruction_4(Insn, 0, 12);
  unsigned pred = fieldFromInstruction_4(Insn, 28, 4);
  unsigned reg = fieldFromInstruction_4(Insn, 25, 1);
  unsigned P = fieldFromInstruction_4(Insn, 24, 1);
  unsigned W = fieldFromInstruction_4(Insn, 21, 1);

  // On stores, the writeback operand precedes Rt.
  switch (MCInst_getOpcode(Inst)) {
  case ARM_STR_POST_IMM:
  case ARM_STR_POST_REG:
  case ARM_STRB_POST_IMM:
  case ARM_STRB_POST_REG:
  case ARM_STRT_POST_REG:
  case ARM_STRT_POST_IMM:
  case ARM_STRBT_POST_REG:
  case ARM_STRBT_POST_IMM:
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  default:
    break;
  }

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rt, Address, Decoder)))
    return MCDisassembler_Fail;

  // On loads, the writeback operand comes after Rt.
  switch (MCInst_getOpcode(Inst)) {
  case ARM_LDR_POST_IMM:
  case ARM_LDR_POST_REG:
  case ARM_LDRB_POST_IMM:
  case ARM_LDRB_POST_REG:
  case ARM_LDRBT_POST_REG:
  case ARM_LDRBT_POST_IMM:
  case ARM_LDRT_POST_REG:
  case ARM_LDRT_POST_IMM:
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  default:
    break;
  }

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;

  ARM_AM_AddrOpc Op = ARM_AM_add;
  if (!fieldFromInstruction_4(Insn, 23, 1))
    Op = ARM_AM_sub;

  bool writeback = (P == 0) || (W == 1);
  unsigned idx_mode = 0;
  if (P && writeback)
    idx_mode = ARMII_IndexModePre;
  else if (!P && writeback)
    idx_mode = ARMII_IndexModePost;

  if (writeback && (Rn == 15 || Rn == Rt))
    S = MCDisassembler_SoftFail; // UNPREDICTABLE

  if (reg) {
    if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rm, Address, Decoder)))
      return MCDisassembler_Fail;
    ARM_AM_ShiftOpc Opc = ARM_AM_lsl;
    switch (fieldFromInstruction_4(Insn, 5, 2)) {
    case 0:
      Opc = ARM_AM_lsl;
      break;
    case 1:
      Opc = ARM_AM_lsr;
      break;
    case 2:
      Opc = ARM_AM_asr;
      break;
    case 3:
      Opc = ARM_AM_ror;
      break;
    default:
      return MCDisassembler_Fail;
    }
    unsigned amt = fieldFromInstruction_4(Insn, 7, 5);
    if (Opc == ARM_AM_ror && amt == 0)
      Opc = ARM_AM_rrx;
    unsigned imm = ARM_AM_getAM2Opc(Op, amt, Opc, idx_mode);

    MCOperand_CreateImm0(Inst, imm);
  } else {
    MCOperand_CreateReg0(Inst, 0);
    unsigned tmp = ARM_AM_getAM2Opc(Op, imm, ARM_AM_lsl, idx_mode);
    MCOperand_CreateImm0(Inst, tmp);
  }

  if (!Check(&S, DecodePredicateOperand(Inst, pred, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeSORegMemOperand(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Val, 13, 4);
  unsigned Rm = fieldFromInstruction_4(Val, 0, 4);
  unsigned type = fieldFromInstruction_4(Val, 5, 2);
  unsigned imm = fieldFromInstruction_4(Val, 7, 5);
  unsigned U = fieldFromInstruction_4(Val, 12, 1);

  ARM_AM_ShiftOpc ShOp = ARM_AM_lsl;
  switch (type) {
  case 0:
    ShOp = ARM_AM_lsl;
    break;
  case 1:
    ShOp = ARM_AM_lsr;
    break;
  case 2:
    ShOp = ARM_AM_asr;
    break;
  case 3:
    ShOp = ARM_AM_ror;
    break;
  }

  if (ShOp == ARM_AM_ror && imm == 0)
    ShOp = ARM_AM_rrx;

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rm, Address, Decoder)))
    return MCDisassembler_Fail;
  unsigned shift;
  if (U)
    shift = ARM_AM_getAM2Opc(ARM_AM_add, imm, ShOp, 0);
  else
    shift = ARM_AM_getAM2Opc(ARM_AM_sub, imm, ShOp, 0);
  MCOperand_CreateImm0(Inst, shift);

  return S;
}

static DecodeStatus DecodeAddrMode3Instruction(MCInst *Inst, unsigned Insn,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rt = fieldFromInstruction_4(Insn, 12, 4);
  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rm = fieldFromInstruction_4(Insn, 0, 4);
  unsigned type = fieldFromInstruction_4(Insn, 22, 1);
  unsigned imm = fieldFromInstruction_4(Insn, 8, 4);
  unsigned U = ((~fieldFromInstruction_4(Insn, 23, 1)) & 1) << 8;
  unsigned pred = fieldFromInstruction_4(Insn, 28, 4);
  unsigned W = fieldFromInstruction_4(Insn, 21, 1);
  unsigned P = fieldFromInstruction_4(Insn, 24, 1);
  unsigned Rt2 = Rt + 1;

  bool writeback = (W == 1) | (P == 0);

  // For {LD,ST}RD, Rt must be even, else undefined.
  switch (MCInst_getOpcode(Inst)) {
  case ARM_STRD:
  case ARM_STRD_PRE:
  case ARM_STRD_POST:
  case ARM_LDRD:
  case ARM_LDRD_PRE:
  case ARM_LDRD_POST:
    if (Rt & 0x1)
      S = MCDisassembler_SoftFail;
    break;
  default:
    break;
  }
  switch (MCInst_getOpcode(Inst)) {
  case ARM_STRD:
  case ARM_STRD_PRE:
  case ARM_STRD_POST:
    if (P == 0 && W == 1)
      S = MCDisassembler_SoftFail;

    if (writeback && (Rn == 15 || Rn == Rt || Rn == Rt2))
      S = MCDisassembler_SoftFail;
    if (type && Rm == 15)
      S = MCDisassembler_SoftFail;
    if (Rt2 == 15)
      S = MCDisassembler_SoftFail;
    if (!type && fieldFromInstruction_4(Insn, 8, 4))
      S = MCDisassembler_SoftFail;
    break;
  case ARM_STRH:
  case ARM_STRH_PRE:
  case ARM_STRH_POST:
    if (Rt == 15)
      S = MCDisassembler_SoftFail;
    if (writeback && (Rn == 15 || Rn == Rt))
      S = MCDisassembler_SoftFail;
    if (!type && Rm == 15)
      S = MCDisassembler_SoftFail;
    break;
  case ARM_LDRD:
  case ARM_LDRD_PRE:
  case ARM_LDRD_POST:
    if (type && Rn == 15) {
      if (Rt2 == 15)
	S = MCDisassembler_SoftFail;
      break;
    }
    if (P == 0 && W == 1)
      S = MCDisassembler_SoftFail;
    if (!type && (Rt2 == 15 || Rm == 15 || Rm == Rt || Rm == Rt2))
      S = MCDisassembler_SoftFail;
    if (!type && writeback && Rn == 15)
      S = MCDisassembler_SoftFail;
    if (writeback && (Rn == Rt || Rn == Rt2))
      S = MCDisassembler_SoftFail;
    break;
  case ARM_LDRH:
  case ARM_LDRH_PRE:
  case ARM_LDRH_POST:
    if (type && Rn == 15) {
      if (Rt == 15)
	S = MCDisassembler_SoftFail;
      break;
    }
    if (Rt == 15)
      S = MCDisassembler_SoftFail;
    if (!type && Rm == 15)
      S = MCDisassembler_SoftFail;
    if (!type && writeback && (Rn == 15 || Rn == Rt))
      S = MCDisassembler_SoftFail;
    break;
  case ARM_LDRSH:
  case ARM_LDRSH_PRE:
  case ARM_LDRSH_POST:
  case ARM_LDRSB:
  case ARM_LDRSB_PRE:
  case ARM_LDRSB_POST:
    if (type && Rn == 15) {
      if (Rt == 15)
	S = MCDisassembler_SoftFail;
      break;
    }
    if (type && (Rt == 15 || (writeback && Rn == Rt)))
      S = MCDisassembler_SoftFail;
    if (!type && (Rt == 15 || Rm == 15))
      S = MCDisassembler_SoftFail;
    if (!type && writeback && (Rn == 15 || Rn == Rt))
      S = MCDisassembler_SoftFail;
    break;
  default:
    break;
  }

  if (writeback) { // Writeback
    if (P)
      U |= ARMII_IndexModePre << 9;
    else
      U |= ARMII_IndexModePost << 9;

    // On stores, the writeback operand precedes Rt.
    switch (MCInst_getOpcode(Inst)) {
    case ARM_STRD:
    case ARM_STRD_PRE:
    case ARM_STRD_POST:
    case ARM_STRH:
    case ARM_STRH_PRE:
    case ARM_STRH_POST:
      if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
	return MCDisassembler_Fail;
      break;
    default:
      break;
    }
  }

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rt, Address, Decoder)))
    return MCDisassembler_Fail;
  switch (MCInst_getOpcode(Inst)) {
  case ARM_STRD:
  case ARM_STRD_PRE:
  case ARM_STRD_POST:
  case ARM_LDRD:
  case ARM_LDRD_PRE:
  case ARM_LDRD_POST:
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rt + 1, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  default:
    break;
  }

  if (writeback) {
    // On loads, the writeback operand comes after Rt.
    switch (MCInst_getOpcode(Inst)) {
    case ARM_LDRD:
    case ARM_LDRD_PRE:
    case ARM_LDRD_POST:
    case ARM_LDRH:
    case ARM_LDRH_PRE:
    case ARM_LDRH_POST:
    case ARM_LDRSH:
    case ARM_LDRSH_PRE:
    case ARM_LDRSH_POST:
    case ARM_LDRSB:
    case ARM_LDRSB_PRE:
    case ARM_LDRSB_POST:
    case ARM_LDRHTr:
    case ARM_LDRSBTr:
      if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
	return MCDisassembler_Fail;
      break;
    default:
      break;
    }
  }

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;

  if (type) {
    MCOperand_CreateReg0(Inst, 0);
    MCOperand_CreateImm0(Inst, U | (imm << 4) | Rm);
  } else {
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rm, Address, Decoder)))
      return MCDisassembler_Fail;
    MCOperand_CreateImm0(Inst, U);
  }

  if (!Check(&S, DecodePredicateOperand(Inst, pred, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeRFEInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address,
					 MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned mode = fieldFromInstruction_4(Insn, 23, 2);

  switch (mode) {
  case 0:
    mode = ARM_AM_da;
    break;
  case 1:
    mode = ARM_AM_ia;
    break;
  case 2:
    mode = ARM_AM_db;
    break;
  case 3:
    mode = ARM_AM_ib;
    break;
  }

  MCOperand_CreateImm0(Inst, mode);
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeQADDInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address,
					  MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rd = fieldFromInstruction_4(Insn, 12, 4);
  unsigned Rm = fieldFromInstruction_4(Insn, 0, 4);
  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned pred = fieldFromInstruction_4(Insn, 28, 4);

  if (pred == 0xF)
    return DecodeCPSInstruction(Inst, Insn, Address, Decoder);

  if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rm, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodePredicateOperand(Inst, pred, Address, Decoder)))
    return MCDisassembler_Fail;
  return S;
}

static DecodeStatus
DecodeMemMultipleWritebackInstruction(MCInst *Inst, unsigned Insn,
				      uint64_t Address, MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned pred = fieldFromInstruction_4(Insn, 28, 4);
  unsigned reglist = fieldFromInstruction_4(Insn, 0, 16);

  if (pred == 0xF) {
    // Ambiguous with RFE and SRS
    switch (MCInst_getOpcode(Inst)) {
    case ARM_LDMDA:
      MCInst_setOpcode(Inst, ARM_RFEDA);
      break;
    case ARM_LDMDA_UPD:
      MCInst_setOpcode(Inst, ARM_RFEDA_UPD);
      break;
    case ARM_LDMDB:
      MCInst_setOpcode(Inst, ARM_RFEDB);
      break;
    case ARM_LDMDB_UPD:
      MCInst_setOpcode(Inst, ARM_RFEDB_UPD);
      break;
    case ARM_LDMIA:
      MCInst_setOpcode(Inst, ARM_RFEIA);
      break;
    case ARM_LDMIA_UPD:
      MCInst_setOpcode(Inst, ARM_RFEIA_UPD);
      break;
    case ARM_LDMIB:
      MCInst_setOpcode(Inst, ARM_RFEIB);
      break;
    case ARM_LDMIB_UPD:
      MCInst_setOpcode(Inst, ARM_RFEIB_UPD);
      break;
    case ARM_STMDA:
      MCInst_setOpcode(Inst, ARM_SRSDA);
      break;
    case ARM_STMDA_UPD:
      MCInst_setOpcode(Inst, ARM_SRSDA_UPD);
      break;
    case ARM_STMDB:
      MCInst_setOpcode(Inst, ARM_SRSDB);
      break;
    case ARM_STMDB_UPD:
      MCInst_setOpcode(Inst, ARM_SRSDB_UPD);
      break;
    case ARM_STMIA:
      MCInst_setOpcode(Inst, ARM_SRSIA);
      break;
    case ARM_STMIA_UPD:
      MCInst_setOpcode(Inst, ARM_SRSIA_UPD);
      break;
    case ARM_STMIB:
      MCInst_setOpcode(Inst, ARM_SRSIB);
      break;
    case ARM_STMIB_UPD:
      MCInst_setOpcode(Inst, ARM_SRSIB_UPD);
      break;
    default:
      return MCDisassembler_Fail;
    }

    // For stores (which become SRS's, the only operand is the mode.
    if (fieldFromInstruction_4(Insn, 20, 1) == 0) {
      // Check SRS encoding constraints
      if (!(fieldFromInstruction_4(Insn, 22, 1) == 1 &&
	    fieldFromInstruction_4(Insn, 20, 1) == 0))
	return MCDisassembler_Fail;

      MCOperand_CreateImm0(Inst, fieldFromInstruction_4(Insn, 0, 4));
      return S;
    }

    return DecodeRFEInstruction(Inst, Insn, Address, Decoder);
  }

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail; // Tied
  if (!Check(&S, DecodePredicateOperand(Inst, pred, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeRegListOperand(Inst, reglist, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeHINTInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address,
					  MCRegisterInfo *Decoder)
{
  unsigned pred = fieldFromInstruction_4(Insn, 28, 4);
  unsigned imm8 = fieldFromInstruction_4(Insn, 0, 8);
  /* Ignored bit flags */

  DecodeStatus S = MCDisassembler_Success;

  MCOperand_CreateImm0(Inst, imm8);

  if (!Check(&S, DecodePredicateOperand(Inst, pred, Address, Decoder)))
    return MCDisassembler_Fail;

  // ESB is unpredictable if pred != AL. Without the RAS extension, it is a NOP,
  // so all predicates should be allowed.
  if (imm8 == 0x10 && pred != 0xe && ((true) != 0))
    S = MCDisassembler_SoftFail;

  return S;
}

static DecodeStatus DecodeCPSInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address,
					 MCRegisterInfo *Decoder)
{
  unsigned imod = fieldFromInstruction_4(Insn, 18, 2);
  unsigned M = fieldFromInstruction_4(Insn, 17, 1);
  unsigned iflags = fieldFromInstruction_4(Insn, 6, 3);
  unsigned mode = fieldFromInstruction_4(Insn, 0, 5);

  DecodeStatus S = MCDisassembler_Success;

  // This decoder is called from multiple location that do not check
  // the full encoding is valid before they do.
  if (fieldFromInstruction_4(Insn, 5, 1) != 0 ||
      fieldFromInstruction_4(Insn, 16, 1) != 0 ||
      fieldFromInstruction_4(Insn, 20, 8) != 0x10)
    return MCDisassembler_Fail;

  // imod == '01' --> UNPREDICTABLE
  // NOTE: Even though this is technically UNPREDICTABLE, we choose to
  // return failure here.  The '01' imod value is unprintable, so there's
  // nothing useful we could do even if we returned UNPREDICTABLE.

  if (imod == 1)
    return MCDisassembler_Fail;

  if (imod && M) {
    MCInst_setOpcode(Inst, ARM_CPS3p);
    MCOperand_CreateImm0(Inst, imod);
    MCOperand_CreateImm0(Inst, iflags);
    MCOperand_CreateImm0(Inst, mode);
  } else if (imod && !M) {
    MCInst_setOpcode(Inst, ARM_CPS2p);
    MCOperand_CreateImm0(Inst, imod);
    MCOperand_CreateImm0(Inst, iflags);
    if (mode)
      S = MCDisassembler_SoftFail;
  } else if (!imod && M) {
    MCInst_setOpcode(Inst, ARM_CPS1p);
    MCOperand_CreateImm0(Inst, mode);
    if (iflags)
      S = MCDisassembler_SoftFail;
  } else {
    // imod == '00' && M == '0' --> UNPREDICTABLE
    MCInst_setOpcode(Inst, ARM_CPS1p);
    MCOperand_CreateImm0(Inst, mode);
    S = MCDisassembler_SoftFail;
  }

  return S;
}

static DecodeStatus DecodeT2CPSInstruction(MCInst *Inst, unsigned Insn,
					   uint64_t Address,
					   MCRegisterInfo *Decoder)
{
  unsigned imod = fieldFromInstruction_4(Insn, 9, 2);
  unsigned M = fieldFromInstruction_4(Insn, 8, 1);
  unsigned iflags = fieldFromInstruction_4(Insn, 5, 3);
  unsigned mode = fieldFromInstruction_4(Insn, 0, 5);

  DecodeStatus S = MCDisassembler_Success;

  // imod == '01' --> UNPREDICTABLE
  // NOTE: Even though this is technically UNPREDICTABLE, we choose to
  // return failure here.  The '01' imod value is unprintable, so there's
  // nothing useful we could do even if we returned UNPREDICTABLE.

  if (imod == 1)
    return MCDisassembler_Fail;

  if (imod && M) {
    MCInst_setOpcode(Inst, ARM_t2CPS3p);
    MCOperand_CreateImm0(Inst, imod);
    MCOperand_CreateImm0(Inst, iflags);
    MCOperand_CreateImm0(Inst, mode);
  } else if (imod && !M) {
    MCInst_setOpcode(Inst, ARM_t2CPS2p);
    MCOperand_CreateImm0(Inst, imod);
    MCOperand_CreateImm0(Inst, iflags);
    if (mode)
      S = MCDisassembler_SoftFail;
  } else if (!imod && M) {
    MCInst_setOpcode(Inst, ARM_t2CPS1p);
    MCOperand_CreateImm0(Inst, mode);
    if (iflags)
      S = MCDisassembler_SoftFail;
  } else {
    // imod == '00' && M == '0' --> this is a HINT instruction
    int imm = fieldFromInstruction_4(Insn, 0, 8);
    // HINT are defined only for immediate in [0..4]
    if (imm > 4)
      return MCDisassembler_Fail;
    MCInst_setOpcode(Inst, ARM_t2HINT);
    MCOperand_CreateImm0(Inst, imm);
  }

  return S;
}

static DecodeStatus DecodeT2MOVTWInstruction(MCInst *Inst, unsigned Insn,
					     uint64_t Address,
					     MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rd = fieldFromInstruction_4(Insn, 8, 4);
  unsigned imm = 0;

  imm |= (fieldFromInstruction_4(Insn, 0, 8) << 0);
  imm |= (fieldFromInstruction_4(Insn, 12, 3) << 8);
  imm |= (fieldFromInstruction_4(Insn, 16, 4) << 12);
  imm |= (fieldFromInstruction_4(Insn, 26, 1) << 11);

  if (MCInst_getOpcode(Inst) == ARM_t2MOVTi16)
    if (!Check(&S, DecoderGPRRegisterClass(Inst, Rd, Address, Decoder)))
      return MCDisassembler_Fail;
  if (!Check(&S, DecoderGPRRegisterClass(Inst, Rd, Address, Decoder)))
    return MCDisassembler_Fail;

  //  if (!tryAddingSymbolicOperand(Address, imm, false, 4, Inst, Decoder))
  MCOperand_CreateImm0(Inst, imm);

  return S;
}

static DecodeStatus DecodeArmMOVTWInstruction(MCInst *Inst, unsigned Insn,
					      uint64_t Address,
					      MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rd = fieldFromInstruction_4(Insn, 12, 4);
  unsigned pred = fieldFromInstruction_4(Insn, 28, 4);
  unsigned imm = 0;

  imm |= (fieldFromInstruction_4(Insn, 0, 12) << 0);
  imm |= (fieldFromInstruction_4(Insn, 16, 4) << 12);

  if (MCInst_getOpcode(Inst) == ARM_MOVTi16)
    if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rd, Address, Decoder)))
      return MCDisassembler_Fail;

  if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rd, Address, Decoder)))
    return MCDisassembler_Fail;

  //  if (!tryAddingSymbolicOperand(Address, imm, false, 4, Inst, Decoder))
  MCOperand_CreateImm0(Inst, imm);

  if (!Check(&S, DecodePredicateOperand(Inst, pred, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeSMLAInstruction(MCInst *Inst, unsigned Insn,
					  uint64_t Address,
					  MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rd = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rn = fieldFromInstruction_4(Insn, 0, 4);
  unsigned Rm = fieldFromInstruction_4(Insn, 8, 4);
  unsigned Ra = fieldFromInstruction_4(Insn, 12, 4);
  unsigned pred = fieldFromInstruction_4(Insn, 28, 4);

  if (pred == 0xF)
    return DecodeCPSInstruction(Inst, Insn, Address, Decoder);

  if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rm, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Ra, Address, Decoder)))
    return MCDisassembler_Fail;

  if (!Check(&S, DecodePredicateOperand(Inst, pred, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeTSTInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address,
					 MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Pred = fieldFromInstruction_4(Insn, 28, 4);
  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rm = fieldFromInstruction_4(Insn, 0, 4);

  if (Pred == 0xF)
    return DecodeSETPANInstruction(Inst, Insn, Address, Decoder);

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rm, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodePredicateOperand(Inst, Pred, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeSETPANInstruction(MCInst *Inst, unsigned Insn,
					    uint64_t Address,
					    MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Imm = fieldFromInstruction_4(Insn, 9, 1);

  /* Ignored bit flags */

  if (!true || !true)
    return MCDisassembler_Fail;

  // Decoder can be called from DecodeTST, which does not check the full
  // encoding is valid.
  if (fieldFromInstruction_4(Insn, 20, 12) != 0xf11 ||
      fieldFromInstruction_4(Insn, 4, 4) != 0)
    return MCDisassembler_Fail;
  if (fieldFromInstruction_4(Insn, 10, 10) != 0 ||
      fieldFromInstruction_4(Insn, 0, 4) != 0)
    S = MCDisassembler_SoftFail;

  MCInst_setOpcode(Inst, ARM_SETPAN);
  MCOperand_CreateImm0(Inst, Imm);

  return S;
}

static DecodeStatus DecodeAddrModeImm12Operand(MCInst *Inst, unsigned Val,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned add = fieldFromInstruction_4(Val, 12, 1);
  unsigned imm = fieldFromInstruction_4(Val, 0, 12);
  unsigned Rn = fieldFromInstruction_4(Val, 13, 4);

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;

  if (!add)
    imm *= -1;
  if (imm == 0 && !add)
    imm = INT32_MIN;
  MCOperand_CreateImm0(Inst, imm);
  //  if (Rn == 15)
  //    tryAddingPcLoadReferenceComment(Address, Address + imm + 8, Decoder);

  return S;
}

static DecodeStatus DecodeAddrMode5Operand(MCInst *Inst, unsigned Val,
					   uint64_t Address,
					   MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Val, 9, 4);
  // U == 1 to add imm, 0 to subtract it.
  unsigned U = fieldFromInstruction_4(Val, 8, 1);
  unsigned imm = fieldFromInstruction_4(Val, 0, 8);

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;

  if (U)
    MCOperand_CreateImm0(Inst, ARM_AM_getAM5Opc(ARM_AM_add, imm));
  else
    MCOperand_CreateImm0(Inst, ARM_AM_getAM5Opc(ARM_AM_sub, imm));

  return S;
}

static DecodeStatus DecodeAddrMode5FP16Operand(MCInst *Inst, unsigned Val,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Val, 9, 4);
  // U == 1 to add imm, 0 to subtract it.
  unsigned U = fieldFromInstruction_4(Val, 8, 1);
  unsigned imm = fieldFromInstruction_4(Val, 0, 8);

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;

  if (U)
    MCOperand_CreateImm0(Inst, getAM5FP16Opc(ARM_AM_add, imm));
  else
    MCOperand_CreateImm0(Inst, getAM5FP16Opc(ARM_AM_sub, imm));

  return S;
}

static DecodeStatus DecodeAddrMode7Operand(MCInst *Inst, unsigned Val,
					   uint64_t Address,
					   MCRegisterInfo *Decoder)
{
  return DecodeGPRRegisterClass(Inst, Val, Address, Decoder);
}

static DecodeStatus DecodeT2BInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address,
					 MCRegisterInfo *Decoder)
{
  DecodeStatus Status = MCDisassembler_Success;

  // Note the J1 and J2 values are from the encoded instruction.  So here
  // change them to I1 and I2 values via as documented:
  // I1 = NOT(J1 EOR S);
  // I2 = NOT(J2 EOR S);
  // and build the imm32 with one trailing zero as documented:
  // imm32 = SignExtend(S:I1:I2:imm10:imm11:'0', 32);
  unsigned S = fieldFromInstruction_4(Insn, 26, 1);
  unsigned J1 = fieldFromInstruction_4(Insn, 13, 1);
  unsigned J2 = fieldFromInstruction_4(Insn, 11, 1);
  unsigned I1 = !(J1 ^ S);
  unsigned I2 = !(J2 ^ S);
  unsigned imm10 = fieldFromInstruction_4(Insn, 16, 10);
  unsigned imm11 = fieldFromInstruction_4(Insn, 0, 11);
  unsigned tmp = (S << 23) | (I1 << 22) | (I2 << 21) | (imm10 << 11) | imm11;
  int imm32 = SignExtend32(tmp << 1, 25);
  //  if (!tryAddingSymbolicOperand(Address, Address + imm32 + 4,
  //				true, 4, Inst, Decoder))
  MCOperand_CreateImm0(Inst, imm32);

  return Status;
}

static DecodeStatus DecodeBranchImmInstruction(MCInst *Inst, unsigned Insn,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned pred = fieldFromInstruction_4(Insn, 28, 4);
  unsigned imm = fieldFromInstruction_4(Insn, 0, 24) << 2;

  if (pred == 0xF) {
    MCInst_setOpcode(Inst, ARM_BLXi);
    imm |= fieldFromInstruction_4(Insn, 24, 1) << 1;
    //    if (!tryAddingSymbolicOperand(Address, Address + SignExtend32(imm, 26)
    //    + 8,
    //				  true, 4, Inst, Decoder))
    MCOperand_CreateImm0(Inst, SignExtend32(imm, 26));
    return S;
  }

  //  if (!tryAddingSymbolicOperand(Address, Address + SignExtend32(imm, 26) +
  //  8,
  //				true, 4, Inst, Decoder))
  MCOperand_CreateImm0(Inst, SignExtend32(imm, 26));
  if (!Check(&S, DecodePredicateOperand(Inst, pred, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeAddrMode6Operand(MCInst *Inst, unsigned Val,
					   uint64_t Address,
					   MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rm = fieldFromInstruction_4(Val, 0, 4);
  unsigned align = fieldFromInstruction_4(Val, 4, 2);

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rm, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!align)
    MCOperand_CreateImm0(Inst, 0);
  else
    MCOperand_CreateImm0(Inst, 4 << align);

  return S;
}

static DecodeStatus DecodeVLDInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address,
					 MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rd = fieldFromInstruction_4(Insn, 12, 4);
  Rd |= fieldFromInstruction_4(Insn, 22, 1) << 4;
  unsigned wb = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  Rn |= fieldFromInstruction_4(Insn, 4, 2) << 4;
  unsigned Rm = fieldFromInstruction_4(Insn, 0, 4);

  // First output register
  switch (MCInst_getOpcode(Inst)) {
  case ARM_VLD1q16:
  case ARM_VLD1q32:
  case ARM_VLD1q64:
  case ARM_VLD1q8:
  case ARM_VLD1q16wb_fixed:
  case ARM_VLD1q16wb_register:
  case ARM_VLD1q32wb_fixed:
  case ARM_VLD1q32wb_register:
  case ARM_VLD1q64wb_fixed:
  case ARM_VLD1q64wb_register:
  case ARM_VLD1q8wb_fixed:
  case ARM_VLD1q8wb_register:
  case ARM_VLD2d16:
  case ARM_VLD2d32:
  case ARM_VLD2d8:
  case ARM_VLD2d16wb_fixed:
  case ARM_VLD2d16wb_register:
  case ARM_VLD2d32wb_fixed:
  case ARM_VLD2d32wb_register:
  case ARM_VLD2d8wb_fixed:
  case ARM_VLD2d8wb_register:
    if (!Check(&S, DecodeDPairRegisterClass(Inst, Rd, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  case ARM_VLD2b16:
  case ARM_VLD2b32:
  case ARM_VLD2b8:
  case ARM_VLD2b16wb_fixed:
  case ARM_VLD2b16wb_register:
  case ARM_VLD2b32wb_fixed:
  case ARM_VLD2b32wb_register:
  case ARM_VLD2b8wb_fixed:
  case ARM_VLD2b8wb_register:
    if (!Check(&S, DecodeDPairSpacedRegisterClass(Inst, Rd, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  default:
    if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd, Address, Decoder)))
      return MCDisassembler_Fail;
  }

  // Second output register
  switch (MCInst_getOpcode(Inst)) {
  case ARM_VLD3d8:
  case ARM_VLD3d16:
  case ARM_VLD3d32:
  case ARM_VLD3d8_UPD:
  case ARM_VLD3d16_UPD:
  case ARM_VLD3d32_UPD:
  case ARM_VLD4d8:
  case ARM_VLD4d16:
  case ARM_VLD4d32:
  case ARM_VLD4d8_UPD:
  case ARM_VLD4d16_UPD:
  case ARM_VLD4d32_UPD:
    if (!Check(&S,
	       DecodeDPRRegisterClass(Inst, (Rd + 1) % 32, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  case ARM_VLD3q8:
  case ARM_VLD3q16:
  case ARM_VLD3q32:
  case ARM_VLD3q8_UPD:
  case ARM_VLD3q16_UPD:
  case ARM_VLD3q32_UPD:
  case ARM_VLD4q8:
  case ARM_VLD4q16:
  case ARM_VLD4q32:
  case ARM_VLD4q8_UPD:
  case ARM_VLD4q16_UPD:
  case ARM_VLD4q32_UPD:
    if (!Check(&S,
	       DecodeDPRRegisterClass(Inst, (Rd + 2) % 32, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  default:
    break;
  }

  // Third output register
  switch (MCInst_getOpcode(Inst)) {
  case ARM_VLD3d8:
  case ARM_VLD3d16:
  case ARM_VLD3d32:
  case ARM_VLD3d8_UPD:
  case ARM_VLD3d16_UPD:
  case ARM_VLD3d32_UPD:
  case ARM_VLD4d8:
  case ARM_VLD4d16:
  case ARM_VLD4d32:
  case ARM_VLD4d8_UPD:
  case ARM_VLD4d16_UPD:
  case ARM_VLD4d32_UPD:
    if (!Check(&S,
	       DecodeDPRRegisterClass(Inst, (Rd + 2) % 32, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  case ARM_VLD3q8:
  case ARM_VLD3q16:
  case ARM_VLD3q32:
  case ARM_VLD3q8_UPD:
  case ARM_VLD3q16_UPD:
  case ARM_VLD3q32_UPD:
  case ARM_VLD4q8:
  case ARM_VLD4q16:
  case ARM_VLD4q32:
  case ARM_VLD4q8_UPD:
  case ARM_VLD4q16_UPD:
  case ARM_VLD4q32_UPD:
    if (!Check(&S,
	       DecodeDPRRegisterClass(Inst, (Rd + 4) % 32, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  default:
    break;
  }

  // Fourth output register
  switch (MCInst_getOpcode(Inst)) {
  case ARM_VLD4d8:
  case ARM_VLD4d16:
  case ARM_VLD4d32:
  case ARM_VLD4d8_UPD:
  case ARM_VLD4d16_UPD:
  case ARM_VLD4d32_UPD:
    if (!Check(&S,
	       DecodeDPRRegisterClass(Inst, (Rd + 3) % 32, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  case ARM_VLD4q8:
  case ARM_VLD4q16:
  case ARM_VLD4q32:
  case ARM_VLD4q8_UPD:
  case ARM_VLD4q16_UPD:
  case ARM_VLD4q32_UPD:
    if (!Check(&S,
	       DecodeDPRRegisterClass(Inst, (Rd + 6) % 32, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  default:
    break;
  }

  // Writeback operand
  switch (MCInst_getOpcode(Inst)) {
  case ARM_VLD1d8wb_fixed:
  case ARM_VLD1d16wb_fixed:
  case ARM_VLD1d32wb_fixed:
  case ARM_VLD1d64wb_fixed:
  case ARM_VLD1d8wb_register:
  case ARM_VLD1d16wb_register:
  case ARM_VLD1d32wb_register:
  case ARM_VLD1d64wb_register:
  case ARM_VLD1q8wb_fixed:
  case ARM_VLD1q16wb_fixed:
  case ARM_VLD1q32wb_fixed:
  case ARM_VLD1q64wb_fixed:
  case ARM_VLD1q8wb_register:
  case ARM_VLD1q16wb_register:
  case ARM_VLD1q32wb_register:
  case ARM_VLD1q64wb_register:
  case ARM_VLD1d8Twb_fixed:
  case ARM_VLD1d8Twb_register:
  case ARM_VLD1d16Twb_fixed:
  case ARM_VLD1d16Twb_register:
  case ARM_VLD1d32Twb_fixed:
  case ARM_VLD1d32Twb_register:
  case ARM_VLD1d64Twb_fixed:
  case ARM_VLD1d64Twb_register:
  case ARM_VLD1d8Qwb_fixed:
  case ARM_VLD1d8Qwb_register:
  case ARM_VLD1d16Qwb_fixed:
  case ARM_VLD1d16Qwb_register:
  case ARM_VLD1d32Qwb_fixed:
  case ARM_VLD1d32Qwb_register:
  case ARM_VLD1d64Qwb_fixed:
  case ARM_VLD1d64Qwb_register:
  case ARM_VLD2d8wb_fixed:
  case ARM_VLD2d16wb_fixed:
  case ARM_VLD2d32wb_fixed:
  case ARM_VLD2q8wb_fixed:
  case ARM_VLD2q16wb_fixed:
  case ARM_VLD2q32wb_fixed:
  case ARM_VLD2d8wb_register:
  case ARM_VLD2d16wb_register:
  case ARM_VLD2d32wb_register:
  case ARM_VLD2q8wb_register:
  case ARM_VLD2q16wb_register:
  case ARM_VLD2q32wb_register:
  case ARM_VLD2b8wb_fixed:
  case ARM_VLD2b16wb_fixed:
  case ARM_VLD2b32wb_fixed:
  case ARM_VLD2b8wb_register:
  case ARM_VLD2b16wb_register:
  case ARM_VLD2b32wb_register:
    MCOperand_CreateImm0(Inst, 0);
    break;
  case ARM_VLD3d8_UPD:
  case ARM_VLD3d16_UPD:
  case ARM_VLD3d32_UPD:
  case ARM_VLD3q8_UPD:
  case ARM_VLD3q16_UPD:
  case ARM_VLD3q32_UPD:
  case ARM_VLD4d8_UPD:
  case ARM_VLD4d16_UPD:
  case ARM_VLD4d32_UPD:
  case ARM_VLD4q8_UPD:
  case ARM_VLD4q16_UPD:
  case ARM_VLD4q32_UPD:
    if (!Check(&S, DecodeGPRRegisterClass(Inst, wb, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  default:
    break;
  }

  // AddrMode6 Base (register+alignment)
  if (!Check(&S, DecodeAddrMode6Operand(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;

  // AddrMode6 Offset (register)
  switch (MCInst_getOpcode(Inst)) {
  default:
    // The below have been updated to have explicit am6offset split
    // between fixed and register offset. For those instructions not
    // yet updated, we need to add an additional reg0 operand for the
    // fixed variant.
    //
    // The fixed offset encodes as Rm == 0xd, so we check for that.
    if (Rm == 0xd) {
      MCOperand_CreateReg0(Inst, 0);
      break;
    }
    // Fall through to handle the register offset variant.
    0x0;
  case ARM_VLD1d8wb_fixed:
  case ARM_VLD1d16wb_fixed:
  case ARM_VLD1d32wb_fixed:
  case ARM_VLD1d64wb_fixed:
  case ARM_VLD1d8Twb_fixed:
  case ARM_VLD1d16Twb_fixed:
  case ARM_VLD1d32Twb_fixed:
  case ARM_VLD1d64Twb_fixed:
  case ARM_VLD1d8Qwb_fixed:
  case ARM_VLD1d16Qwb_fixed:
  case ARM_VLD1d32Qwb_fixed:
  case ARM_VLD1d64Qwb_fixed:
  case ARM_VLD1d8wb_register:
  case ARM_VLD1d16wb_register:
  case ARM_VLD1d32wb_register:
  case ARM_VLD1d64wb_register:
  case ARM_VLD1q8wb_fixed:
  case ARM_VLD1q16wb_fixed:
  case ARM_VLD1q32wb_fixed:
  case ARM_VLD1q64wb_fixed:
  case ARM_VLD1q8wb_register:
  case ARM_VLD1q16wb_register:
  case ARM_VLD1q32wb_register:
  case ARM_VLD1q64wb_register:
    // The fixed offset post-increment encodes Rm == 0xd. The no-writeback
    // variant encodes Rm == 0xf. Anything else is a register offset post-
    // increment and we need to add the register operand to the instruction.
    if (Rm != 0xD && Rm != 0xF &&
	!Check(&S, DecodeGPRRegisterClass(Inst, Rm, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  case ARM_VLD2d8wb_fixed:
  case ARM_VLD2d16wb_fixed:
  case ARM_VLD2d32wb_fixed:
  case ARM_VLD2b8wb_fixed:
  case ARM_VLD2b16wb_fixed:
  case ARM_VLD2b32wb_fixed:
  case ARM_VLD2q8wb_fixed:
  case ARM_VLD2q16wb_fixed:
  case ARM_VLD2q32wb_fixed:
    break;
  }

  return S;
}

static DecodeStatus DecodeVLDST1Instruction(MCInst *Inst, unsigned Insn,
					    uint64_t Address,
					    MCRegisterInfo *Decoder)
{
  unsigned type = fieldFromInstruction_4(Insn, 8, 4);
  unsigned align = fieldFromInstruction_4(Insn, 4, 2);
  if (type == 6 && (align & 2))
    return MCDisassembler_Fail;
  if (type == 7 && (align & 2))
    return MCDisassembler_Fail;
  if (type == 10 && align == 3)
    return MCDisassembler_Fail;

  unsigned load = fieldFromInstruction_4(Insn, 21, 1);
  return load ? DecodeVLDInstruction(Inst, Insn, Address, Decoder)
	      : DecodeVSTInstruction(Inst, Insn, Address, Decoder);
}

static DecodeStatus DecodeVLDST2Instruction(MCInst *Inst, unsigned Insn,
					    uint64_t Address,
					    MCRegisterInfo *Decoder)
{
  unsigned size = fieldFromInstruction_4(Insn, 6, 2);
  if (size == 3)
    return MCDisassembler_Fail;

  unsigned type = fieldFromInstruction_4(Insn, 8, 4);
  unsigned align = fieldFromInstruction_4(Insn, 4, 2);
  if (type == 8 && align == 3)
    return MCDisassembler_Fail;
  if (type == 9 && align == 3)
    return MCDisassembler_Fail;

  unsigned load = fieldFromInstruction_4(Insn, 21, 1);
  return load ? DecodeVLDInstruction(Inst, Insn, Address, Decoder)
	      : DecodeVSTInstruction(Inst, Insn, Address, Decoder);
}

static DecodeStatus DecodeVLDST3Instruction(MCInst *Inst, unsigned Insn,
					    uint64_t Address,
					    MCRegisterInfo *Decoder)
{
  unsigned size = fieldFromInstruction_4(Insn, 6, 2);
  if (size == 3)
    return MCDisassembler_Fail;

  unsigned align = fieldFromInstruction_4(Insn, 4, 2);
  if (align & 2)
    return MCDisassembler_Fail;

  unsigned load = fieldFromInstruction_4(Insn, 21, 1);
  return load ? DecodeVLDInstruction(Inst, Insn, Address, Decoder)
	      : DecodeVSTInstruction(Inst, Insn, Address, Decoder);
}

static DecodeStatus DecodeVLDST4Instruction(MCInst *Inst, unsigned Insn,
					    uint64_t Address,
					    MCRegisterInfo *Decoder)
{
  unsigned size = fieldFromInstruction_4(Insn, 6, 2);
  if (size == 3)
    return MCDisassembler_Fail;

  unsigned load = fieldFromInstruction_4(Insn, 21, 1);
  return load ? DecodeVLDInstruction(Inst, Insn, Address, Decoder)
	      : DecodeVSTInstruction(Inst, Insn, Address, Decoder);
}

static DecodeStatus DecodeVSTInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address,
					 MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rd = fieldFromInstruction_4(Insn, 12, 4);
  Rd |= fieldFromInstruction_4(Insn, 22, 1) << 4;
  unsigned wb = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  Rn |= fieldFromInstruction_4(Insn, 4, 2) << 4;
  unsigned Rm = fieldFromInstruction_4(Insn, 0, 4);

  // Writeback Operand
  switch (MCInst_getOpcode(Inst)) {
  case ARM_VST1d8wb_fixed:
  case ARM_VST1d16wb_fixed:
  case ARM_VST1d32wb_fixed:
  case ARM_VST1d64wb_fixed:
  case ARM_VST1d8wb_register:
  case ARM_VST1d16wb_register:
  case ARM_VST1d32wb_register:
  case ARM_VST1d64wb_register:
  case ARM_VST1q8wb_fixed:
  case ARM_VST1q16wb_fixed:
  case ARM_VST1q32wb_fixed:
  case ARM_VST1q64wb_fixed:
  case ARM_VST1q8wb_register:
  case ARM_VST1q16wb_register:
  case ARM_VST1q32wb_register:
  case ARM_VST1q64wb_register:
  case ARM_VST1d8Twb_fixed:
  case ARM_VST1d16Twb_fixed:
  case ARM_VST1d32Twb_fixed:
  case ARM_VST1d64Twb_fixed:
  case ARM_VST1d8Twb_register:
  case ARM_VST1d16Twb_register:
  case ARM_VST1d32Twb_register:
  case ARM_VST1d64Twb_register:
  case ARM_VST1d8Qwb_fixed:
  case ARM_VST1d16Qwb_fixed:
  case ARM_VST1d32Qwb_fixed:
  case ARM_VST1d64Qwb_fixed:
  case ARM_VST1d8Qwb_register:
  case ARM_VST1d16Qwb_register:
  case ARM_VST1d32Qwb_register:
  case ARM_VST1d64Qwb_register:
  case ARM_VST2d8wb_fixed:
  case ARM_VST2d16wb_fixed:
  case ARM_VST2d32wb_fixed:
  case ARM_VST2d8wb_register:
  case ARM_VST2d16wb_register:
  case ARM_VST2d32wb_register:
  case ARM_VST2q8wb_fixed:
  case ARM_VST2q16wb_fixed:
  case ARM_VST2q32wb_fixed:
  case ARM_VST2q8wb_register:
  case ARM_VST2q16wb_register:
  case ARM_VST2q32wb_register:
  case ARM_VST2b8wb_fixed:
  case ARM_VST2b16wb_fixed:
  case ARM_VST2b32wb_fixed:
  case ARM_VST2b8wb_register:
  case ARM_VST2b16wb_register:
  case ARM_VST2b32wb_register:
    if (Rm == 0xF)
      return MCDisassembler_Fail;
    MCOperand_CreateImm0(Inst, 0);
    break;
  case ARM_VST3d8_UPD:
  case ARM_VST3d16_UPD:
  case ARM_VST3d32_UPD:
  case ARM_VST3q8_UPD:
  case ARM_VST3q16_UPD:
  case ARM_VST3q32_UPD:
  case ARM_VST4d8_UPD:
  case ARM_VST4d16_UPD:
  case ARM_VST4d32_UPD:
  case ARM_VST4q8_UPD:
  case ARM_VST4q16_UPD:
  case ARM_VST4q32_UPD:
    if (!Check(&S, DecodeGPRRegisterClass(Inst, wb, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  default:
    break;
  }

  // AddrMode6 Base (register+alignment)
  if (!Check(&S, DecodeAddrMode6Operand(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;

  // AddrMode6 Offset (register)
  switch (MCInst_getOpcode(Inst)) {
  default:
    if (Rm == 0xD)
      MCOperand_CreateReg0(Inst, 0);
    else if (Rm != 0xF) {
      if (!Check(&S, DecodeGPRRegisterClass(Inst, Rm, Address, Decoder)))
	return MCDisassembler_Fail;
    }
    break;
  case ARM_VST1d8wb_fixed:
  case ARM_VST1d16wb_fixed:
  case ARM_VST1d32wb_fixed:
  case ARM_VST1d64wb_fixed:
  case ARM_VST1q8wb_fixed:
  case ARM_VST1q16wb_fixed:
  case ARM_VST1q32wb_fixed:
  case ARM_VST1q64wb_fixed:
  case ARM_VST1d8Twb_fixed:
  case ARM_VST1d16Twb_fixed:
  case ARM_VST1d32Twb_fixed:
  case ARM_VST1d64Twb_fixed:
  case ARM_VST1d8Qwb_fixed:
  case ARM_VST1d16Qwb_fixed:
  case ARM_VST1d32Qwb_fixed:
  case ARM_VST1d64Qwb_fixed:
  case ARM_VST2d8wb_fixed:
  case ARM_VST2d16wb_fixed:
  case ARM_VST2d32wb_fixed:
  case ARM_VST2q8wb_fixed:
  case ARM_VST2q16wb_fixed:
  case ARM_VST2q32wb_fixed:
  case ARM_VST2b8wb_fixed:
  case ARM_VST2b16wb_fixed:
  case ARM_VST2b32wb_fixed:
    break;
  }

  // First input register
  switch (MCInst_getOpcode(Inst)) {
  case ARM_VST1q16:
  case ARM_VST1q32:
  case ARM_VST1q64:
  case ARM_VST1q8:
  case ARM_VST1q16wb_fixed:
  case ARM_VST1q16wb_register:
  case ARM_VST1q32wb_fixed:
  case ARM_VST1q32wb_register:
  case ARM_VST1q64wb_fixed:
  case ARM_VST1q64wb_register:
  case ARM_VST1q8wb_fixed:
  case ARM_VST1q8wb_register:
  case ARM_VST2d16:
  case ARM_VST2d32:
  case ARM_VST2d8:
  case ARM_VST2d16wb_fixed:
  case ARM_VST2d16wb_register:
  case ARM_VST2d32wb_fixed:
  case ARM_VST2d32wb_register:
  case ARM_VST2d8wb_fixed:
  case ARM_VST2d8wb_register:
    if (!Check(&S, DecodeDPairRegisterClass(Inst, Rd, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  case ARM_VST2b16:
  case ARM_VST2b32:
  case ARM_VST2b8:
  case ARM_VST2b16wb_fixed:
  case ARM_VST2b16wb_register:
  case ARM_VST2b32wb_fixed:
  case ARM_VST2b32wb_register:
  case ARM_VST2b8wb_fixed:
  case ARM_VST2b8wb_register:
    if (!Check(&S, DecodeDPairSpacedRegisterClass(Inst, Rd, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  default:
    if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd, Address, Decoder)))
      return MCDisassembler_Fail;
  }

  // Second input register
  switch (MCInst_getOpcode(Inst)) {
  case ARM_VST3d8:
  case ARM_VST3d16:
  case ARM_VST3d32:
  case ARM_VST3d8_UPD:
  case ARM_VST3d16_UPD:
  case ARM_VST3d32_UPD:
  case ARM_VST4d8:
  case ARM_VST4d16:
  case ARM_VST4d32:
  case ARM_VST4d8_UPD:
  case ARM_VST4d16_UPD:
  case ARM_VST4d32_UPD:
    if (!Check(&S,
	       DecodeDPRRegisterClass(Inst, (Rd + 1) % 32, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  case ARM_VST3q8:
  case ARM_VST3q16:
  case ARM_VST3q32:
  case ARM_VST3q8_UPD:
  case ARM_VST3q16_UPD:
  case ARM_VST3q32_UPD:
  case ARM_VST4q8:
  case ARM_VST4q16:
  case ARM_VST4q32:
  case ARM_VST4q8_UPD:
  case ARM_VST4q16_UPD:
  case ARM_VST4q32_UPD:
    if (!Check(&S,
	       DecodeDPRRegisterClass(Inst, (Rd + 2) % 32, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  default:
    break;
  }

  // Third input register
  switch (MCInst_getOpcode(Inst)) {
  case ARM_VST3d8:
  case ARM_VST3d16:
  case ARM_VST3d32:
  case ARM_VST3d8_UPD:
  case ARM_VST3d16_UPD:
  case ARM_VST3d32_UPD:
  case ARM_VST4d8:
  case ARM_VST4d16:
  case ARM_VST4d32:
  case ARM_VST4d8_UPD:
  case ARM_VST4d16_UPD:
  case ARM_VST4d32_UPD:
    if (!Check(&S,
	       DecodeDPRRegisterClass(Inst, (Rd + 2) % 32, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  case ARM_VST3q8:
  case ARM_VST3q16:
  case ARM_VST3q32:
  case ARM_VST3q8_UPD:
  case ARM_VST3q16_UPD:
  case ARM_VST3q32_UPD:
  case ARM_VST4q8:
  case ARM_VST4q16:
  case ARM_VST4q32:
  case ARM_VST4q8_UPD:
  case ARM_VST4q16_UPD:
  case ARM_VST4q32_UPD:
    if (!Check(&S,
	       DecodeDPRRegisterClass(Inst, (Rd + 4) % 32, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  default:
    break;
  }

  // Fourth input register
  switch (MCInst_getOpcode(Inst)) {
  case ARM_VST4d8:
  case ARM_VST4d16:
  case ARM_VST4d32:
  case ARM_VST4d8_UPD:
  case ARM_VST4d16_UPD:
  case ARM_VST4d32_UPD:
    if (!Check(&S,
	       DecodeDPRRegisterClass(Inst, (Rd + 3) % 32, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  case ARM_VST4q8:
  case ARM_VST4q16:
  case ARM_VST4q32:
  case ARM_VST4q8_UPD:
  case ARM_VST4q16_UPD:
  case ARM_VST4q32_UPD:
    if (!Check(&S,
	       DecodeDPRRegisterClass(Inst, (Rd + 6) % 32, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  default:
    break;
  }

  return S;
}

static DecodeStatus DecodeVLD1DupInstruction(MCInst *Inst, unsigned Insn,
					     uint64_t Address,
					     MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rd = fieldFromInstruction_4(Insn, 12, 4);
  Rd |= fieldFromInstruction_4(Insn, 22, 1) << 4;
  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rm = fieldFromInstruction_4(Insn, 0, 4);
  unsigned align = fieldFromInstruction_4(Insn, 4, 1);
  unsigned size = fieldFromInstruction_4(Insn, 6, 2);

  if (size == 0 && align == 1)
    return MCDisassembler_Fail;
  align *= (1 << size);

  switch (MCInst_getOpcode(Inst)) {
  case ARM_VLD1DUPq16:
  case ARM_VLD1DUPq32:
  case ARM_VLD1DUPq8:
  case ARM_VLD1DUPq16wb_fixed:
  case ARM_VLD1DUPq16wb_register:
  case ARM_VLD1DUPq32wb_fixed:
  case ARM_VLD1DUPq32wb_register:
  case ARM_VLD1DUPq8wb_fixed:
  case ARM_VLD1DUPq8wb_register:
    if (!Check(&S, DecodeDPairRegisterClass(Inst, Rd, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  default:
    if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  }
  if (Rm != 0xF) {
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
      return MCDisassembler_Fail;
  }

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, align);

  // The fixed offset post-increment encodes Rm == 0xd. The no-writeback
  // variant encodes Rm == 0xf. Anything else is a register offset post-
  // increment and we need to add the register operand to the instruction.
  if (Rm != 0xD && Rm != 0xF &&
      !Check(&S, DecodeGPRRegisterClass(Inst, Rm, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeVLD2DupInstruction(MCInst *Inst, unsigned Insn,
					     uint64_t Address,
					     MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rd = fieldFromInstruction_4(Insn, 12, 4);
  Rd |= fieldFromInstruction_4(Insn, 22, 1) << 4;
  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rm = fieldFromInstruction_4(Insn, 0, 4);
  unsigned align = fieldFromInstruction_4(Insn, 4, 1);
  unsigned size = 1 << fieldFromInstruction_4(Insn, 6, 2);
  align *= 2 * size;

  switch (MCInst_getOpcode(Inst)) {
  case ARM_VLD2DUPd16:
  case ARM_VLD2DUPd32:
  case ARM_VLD2DUPd8:
  case ARM_VLD2DUPd16wb_fixed:
  case ARM_VLD2DUPd16wb_register:
  case ARM_VLD2DUPd32wb_fixed:
  case ARM_VLD2DUPd32wb_register:
  case ARM_VLD2DUPd8wb_fixed:
  case ARM_VLD2DUPd8wb_register:
    if (!Check(&S, DecodeDPairRegisterClass(Inst, Rd, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  case ARM_VLD2DUPd16x2:
  case ARM_VLD2DUPd32x2:
  case ARM_VLD2DUPd8x2:
  case ARM_VLD2DUPd16x2wb_fixed:
  case ARM_VLD2DUPd16x2wb_register:
  case ARM_VLD2DUPd32x2wb_fixed:
  case ARM_VLD2DUPd32x2wb_register:
  case ARM_VLD2DUPd8x2wb_fixed:
  case ARM_VLD2DUPd8x2wb_register:
    if (!Check(&S, DecodeDPairSpacedRegisterClass(Inst, Rd, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  default:
    if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  }

  if (Rm != 0xF)
    MCOperand_CreateImm0(Inst, 0);

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, align);

  if (Rm != 0xD && Rm != 0xF) {
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rm, Address, Decoder)))
      return MCDisassembler_Fail;
  }

  return S;
}

static DecodeStatus DecodeVLD3DupInstruction(MCInst *Inst, unsigned Insn,
					     uint64_t Address,
					     MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rd = fieldFromInstruction_4(Insn, 12, 4);
  Rd |= fieldFromInstruction_4(Insn, 22, 1) << 4;
  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rm = fieldFromInstruction_4(Insn, 0, 4);
  unsigned inc = fieldFromInstruction_4(Insn, 5, 1) + 1;

  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S,
	     DecodeDPRRegisterClass(Inst, (Rd + inc) % 32, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeDPRRegisterClass(Inst, (Rd + 2 * inc) % 32, Address,
					Decoder)))
    return MCDisassembler_Fail;
  if (Rm != 0xF) {
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
      return MCDisassembler_Fail;
  }

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, 0);

  if (Rm == 0xD)
    MCOperand_CreateReg0(Inst, 0);
  else if (Rm != 0xF) {
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rm, Address, Decoder)))
      return MCDisassembler_Fail;
  }

  return S;
}

static DecodeStatus DecodeVLD4DupInstruction(MCInst *Inst, unsigned Insn,
					     uint64_t Address,
					     MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rd = fieldFromInstruction_4(Insn, 12, 4);
  Rd |= fieldFromInstruction_4(Insn, 22, 1) << 4;
  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rm = fieldFromInstruction_4(Insn, 0, 4);
  unsigned size = fieldFromInstruction_4(Insn, 6, 2);
  unsigned inc = fieldFromInstruction_4(Insn, 5, 1) + 1;
  unsigned align = fieldFromInstruction_4(Insn, 4, 1);

  if (size == 0x3) {
    if (align == 0)
      return MCDisassembler_Fail;
    align = 16;
  } else {
    if (size == 2) {
      align *= 8;
    } else {
      size = 1 << size;
      align *= 4 * size;
    }
  }

  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S,
	     DecodeDPRRegisterClass(Inst, (Rd + inc) % 32, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeDPRRegisterClass(Inst, (Rd + 2 * inc) % 32, Address,
					Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeDPRRegisterClass(Inst, (Rd + 3 * inc) % 32, Address,
					Decoder)))
    return MCDisassembler_Fail;
  if (Rm != 0xF) {
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
      return MCDisassembler_Fail;
  }

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, align);

  if (Rm == 0xD)
    MCOperand_CreateReg0(Inst, 0);
  else if (Rm != 0xF) {
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rm, Address, Decoder)))
      return MCDisassembler_Fail;
  }

  return S;
}

static DecodeStatus DecodeVMOVModImmInstruction(MCInst *Inst, unsigned Insn,
						uint64_t Address,
						MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rd = fieldFromInstruction_4(Insn, 12, 4);
  Rd |= fieldFromInstruction_4(Insn, 22, 1) << 4;
  unsigned imm = fieldFromInstruction_4(Insn, 0, 4);
  imm |= fieldFromInstruction_4(Insn, 16, 3) << 4;
  imm |= fieldFromInstruction_4(Insn, 24, 1) << 7;
  imm |= fieldFromInstruction_4(Insn, 8, 4) << 8;
  imm |= fieldFromInstruction_4(Insn, 5, 1) << 12;
  unsigned Q = fieldFromInstruction_4(Insn, 6, 1);

  if (Q) {
    if (!Check(&S, DecodeQPRRegisterClass(Inst, Rd, Address, Decoder)))
      return MCDisassembler_Fail;
  } else {
    if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd, Address, Decoder)))
      return MCDisassembler_Fail;
  }

  MCOperand_CreateImm0(Inst, imm);

  switch (MCInst_getOpcode(Inst)) {
  case ARM_VORRiv4i16:
  case ARM_VORRiv2i32:
  case ARM_VBICiv4i16:
  case ARM_VBICiv2i32:
    if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  case ARM_VORRiv8i16:
  case ARM_VORRiv4i32:
  case ARM_VBICiv8i16:
  case ARM_VBICiv4i32:
    if (!Check(&S, DecodeQPRRegisterClass(Inst, Rd, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  default:
    break;
  }

  return S;
}

static DecodeStatus DecodeMVEModImmInstruction(MCInst *Inst, unsigned Insn,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Qd = ((fieldFromInstruction_4(Insn, 22, 1) << 3) |
		 fieldFromInstruction_4(Insn, 13, 3));
  unsigned cmode = fieldFromInstruction_4(Insn, 8, 4);
  unsigned imm = fieldFromInstruction_4(Insn, 0, 4);
  imm |= fieldFromInstruction_4(Insn, 16, 3) << 4;
  imm |= fieldFromInstruction_4(Insn, 28, 1) << 7;
  imm |= cmode << 8;
  imm |= fieldFromInstruction_4(Insn, 5, 1) << 12;

  if (cmode == 0xF && MCInst_getOpcode(Inst) == ARM_MVE_VMVNimmi32)
    return MCDisassembler_Fail;

  if (!Check(&S, DecodeMQPRRegisterClass(Inst, Qd, Address, Decoder)))
    return MCDisassembler_Fail;

  MCOperand_CreateImm0(Inst, imm);

  MCOperand_CreateImm0(Inst, /*ARMVCC_None*/ 0);
  MCOperand_CreateReg0(Inst, 0);
  MCOperand_CreateImm0(Inst, 0);

  return S;
}

static DecodeStatus DecodeMVEVADCInstruction(MCInst *Inst, unsigned Insn,
					     uint64_t Address,
					     MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Qd = fieldFromInstruction_4(Insn, 13, 3);
  Qd |= fieldFromInstruction_4(Insn, 22, 1) << 3;
  if (!Check(&S, DecodeMQPRRegisterClass(Inst, Qd, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateReg0(Inst, ARM_FPSCR_NZCV);

  unsigned Qn = fieldFromInstruction_4(Insn, 17, 3);
  Qn |= fieldFromInstruction_4(Insn, 7, 1) << 3;
  if (!Check(&S, DecodeMQPRRegisterClass(Inst, Qn, Address, Decoder)))
    return MCDisassembler_Fail;
  unsigned Qm = fieldFromInstruction_4(Insn, 1, 3);
  Qm |= fieldFromInstruction_4(Insn, 5, 1) << 3;
  if (!Check(&S, DecodeMQPRRegisterClass(Inst, Qm, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!fieldFromInstruction_4(Insn, 12, 1)) // I bit clear => need input FPSCR
    MCOperand_CreateReg0(Inst, ARM_FPSCR_NZCV);
  MCOperand_CreateImm0(Inst, Qd);

  return S;
}

static DecodeStatus DecodeVSHLMaxInstruction(MCInst *Inst, unsigned Insn,
					     uint64_t Address,
					     MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rd = fieldFromInstruction_4(Insn, 12, 4);
  Rd |= fieldFromInstruction_4(Insn, 22, 1) << 4;
  unsigned Rm = fieldFromInstruction_4(Insn, 0, 4);
  Rm |= fieldFromInstruction_4(Insn, 5, 1) << 4;
  unsigned size = fieldFromInstruction_4(Insn, 18, 2);

  if (!Check(&S, DecodeQPRRegisterClass(Inst, Rd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rm, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, 8 << size);

  return S;
}

static DecodeStatus DecodeShiftRight8Imm(MCInst *Inst, unsigned Val,
					 uint64_t Address,
					 MCRegisterInfo *Decoder)
{
  MCOperand_CreateImm0(Inst, 8 - Val);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeShiftRight16Imm(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder)
{
  MCOperand_CreateImm0(Inst, 16 - Val);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeShiftRight32Imm(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder)
{
  MCOperand_CreateImm0(Inst, 32 - Val);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeShiftRight64Imm(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder)
{
  MCOperand_CreateImm0(Inst, 64 - Val);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeTBLInstruction(MCInst *Inst, unsigned Insn,
					 uint64_t Address,
					 MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rd = fieldFromInstruction_4(Insn, 12, 4);
  Rd |= fieldFromInstruction_4(Insn, 22, 1) << 4;
  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  Rn |= fieldFromInstruction_4(Insn, 7, 1) << 4;
  unsigned Rm = fieldFromInstruction_4(Insn, 0, 4);
  Rm |= fieldFromInstruction_4(Insn, 5, 1) << 4;
  unsigned op = fieldFromInstruction_4(Insn, 6, 1);

  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (op) {
    if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd, Address, Decoder)))
      return MCDisassembler_Fail; // Writeback
  }

  switch (MCInst_getOpcode(Inst)) {
  case ARM_VTBL2:
  case ARM_VTBX2:
    if (!Check(&S, DecodeDPairRegisterClass(Inst, Rn, Address, Decoder)))
      return MCDisassembler_Fail;
    break;
  default:
    if (!Check(&S, DecodeDPRRegisterClass(Inst, Rn, Address, Decoder)))
      return MCDisassembler_Fail;
  }

  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rm, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeThumbAddSpecialReg(MCInst *Inst, uint16_t Insn,
					     uint64_t Address,
					     MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned dst = fieldFromInstruction_2(Insn, 8, 3);
  unsigned imm = fieldFromInstruction_2(Insn, 0, 8);

  if (!Check(&S, DecodetGPRRegisterClass(Inst, dst, Address, Decoder)))
    return MCDisassembler_Fail;

  switch (MCInst_getOpcode(Inst)) {
  default:
    return MCDisassembler_Fail;
  case ARM_tADR:
    break; // tADR does not explicitly represent the PC as an operand.
  case ARM_tADDrSPi:
    MCOperand_CreateReg0(Inst, ARM_SP);
    break;
  }

  MCOperand_CreateImm0(Inst, imm);
  return S;
}

static DecodeStatus DecodeThumbBROperand(MCInst *Inst, unsigned Val,
					 uint64_t Address,
					 MCRegisterInfo *Decoder)
{
  //  if (!tryAddingSymbolicOperand(Address, Address + SignExtend32(Val<<1, 12)
  //  + 4,
  //				true, 2, Inst, Decoder))
  MCOperand_CreateImm0(Inst, SignExtend32(Val << 1, 12));
  return MCDisassembler_Success;
}

static DecodeStatus DecodeT2BROperand(MCInst *Inst, unsigned Val,
				      uint64_t Address, MCRegisterInfo *Decoder)
{
  //  if (!tryAddingSymbolicOperand(Address, Address + SignExtend32(Val, 21) +
  //  4,
  //				true, 4, Inst, Decoder))
  MCOperand_CreateImm0(Inst, SignExtend32(Val, 21));
  return MCDisassembler_Success;
}

static DecodeStatus DecodeThumbCmpBROperand(MCInst *Inst, unsigned Val,
					    uint64_t Address,
					    MCRegisterInfo *Decoder)
{
  //  if (!tryAddingSymbolicOperand(Address, Address + (Val<<1) + 4,
  //				true, 2, Inst, Decoder))
  MCOperand_CreateImm0(Inst, Val << 1);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeThumbAddrModeRR(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_2(Val, 0, 3);
  unsigned Rm = fieldFromInstruction_2(Val, 3, 3);

  if (!Check(&S, DecodetGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodetGPRRegisterClass(Inst, Rm, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeThumbAddrModeIS(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_2(Val, 0, 3);
  unsigned imm = fieldFromInstruction_2(Val, 3, 5);

  if (!Check(&S, DecodetGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, imm);

  return S;
}

static DecodeStatus DecodeThumbAddrModePC(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder)
{
  unsigned imm = Val << 2;

  MCOperand_CreateImm0(Inst, imm);

  return MCDisassembler_Success;
}

static DecodeStatus DecodeThumbAddrModeSP(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder)
{
  MCOperand_CreateReg0(Inst, ARM_SP);
  MCOperand_CreateImm0(Inst, Val);

  return MCDisassembler_Success;
}

static DecodeStatus DecodeT2AddrModeSOReg(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Val, 6, 4);
  unsigned Rm = fieldFromInstruction_4(Val, 2, 4);
  unsigned imm = fieldFromInstruction_4(Val, 0, 2);

  // Thumb stores cannot use PC as dest register.
  switch (MCInst_getOpcode(Inst)) {
  case ARM_t2STRHs:
  case ARM_t2STRBs:
  case ARM_t2STRs:
    if (Rn == 15)
      return MCDisassembler_Fail;
    break;
  default:
    break;
  }

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecoderGPRRegisterClass(Inst, Rm, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, imm);

  return S;
}

static DecodeStatus DecodeT2LoadShift(MCInst *Inst, unsigned Insn,
				      uint64_t Address, MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rt = fieldFromInstruction_4(Insn, 12, 4);
  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);

  /* Ignored bit flags */

  bool hasMP = true;
  bool hasV7Ops = true;

  if (Rn == 15) {
    switch (MCInst_getOpcode(Inst)) {
    case ARM_t2LDRBs:
      MCInst_setOpcode(Inst, ARM_t2LDRBpci);
      break;
    case ARM_t2LDRHs:
      MCInst_setOpcode(Inst, ARM_t2LDRHpci);
      break;
    case ARM_t2LDRSHs:
      MCInst_setOpcode(Inst, ARM_t2LDRSHpci);
      break;
    case ARM_t2LDRSBs:
      MCInst_setOpcode(Inst, ARM_t2LDRSBpci);
      break;
    case ARM_t2LDRs:
      MCInst_setOpcode(Inst, ARM_t2LDRpci);
      break;
    case ARM_t2PLDs:
      MCInst_setOpcode(Inst, ARM_t2PLDpci);
      break;
    case ARM_t2PLIs:
      MCInst_setOpcode(Inst, ARM_t2PLIpci);
      break;
    default:
      return MCDisassembler_Fail;
    }

    return DecodeT2LoadLabel(Inst, Insn, Address, Decoder);
  }

  if (Rt == 15) {
    switch (MCInst_getOpcode(Inst)) {
    case ARM_t2LDRSHs:
      return MCDisassembler_Fail;
    case ARM_t2LDRHs:
      MCInst_setOpcode(Inst, ARM_t2PLDWs);
      break;
    case ARM_t2LDRSBs:
      MCInst_setOpcode(Inst, ARM_t2PLIs);
      break;
    default:
      break;
    }
  }

  switch (MCInst_getOpcode(Inst)) {
  case ARM_t2PLDs:
    break;
  case ARM_t2PLIs:
    if (!hasV7Ops)
      return MCDisassembler_Fail;
    break;
  case ARM_t2PLDWs:
    if (!hasV7Ops || !hasMP)
      return MCDisassembler_Fail;
    break;
  default:
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rt, Address, Decoder)))
      return MCDisassembler_Fail;
  }

  unsigned addrmode = fieldFromInstruction_4(Insn, 4, 2);
  addrmode |= fieldFromInstruction_4(Insn, 0, 4) << 2;
  addrmode |= fieldFromInstruction_4(Insn, 16, 4) << 6;
  if (!Check(&S, DecodeT2AddrModeSOReg(Inst, addrmode, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeT2LoadImm8(MCInst *Inst, unsigned Insn,
				     uint64_t Address, MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rt = fieldFromInstruction_4(Insn, 12, 4);
  unsigned U = fieldFromInstruction_4(Insn, 9, 1);
  unsigned imm = fieldFromInstruction_4(Insn, 0, 8);
  imm |= (U << 8);
  imm |= (Rn << 9);
  unsigned add = fieldFromInstruction_4(Insn, 9, 1);

  /* Ignored bit flags */

  bool hasMP = true;
  bool hasV7Ops = true;

  if (Rn == 15) {
    switch (MCInst_getOpcode(Inst)) {
    case ARM_t2LDRi8:
      MCInst_setOpcode(Inst, ARM_t2LDRpci);
      break;
    case ARM_t2LDRBi8:
      MCInst_setOpcode(Inst, ARM_t2LDRBpci);
      break;
    case ARM_t2LDRSBi8:
      MCInst_setOpcode(Inst, ARM_t2LDRSBpci);
      break;
    case ARM_t2LDRHi8:
      MCInst_setOpcode(Inst, ARM_t2LDRHpci);
      break;
    case ARM_t2LDRSHi8:
      MCInst_setOpcode(Inst, ARM_t2LDRSHpci);
      break;
    case ARM_t2PLDi8:
      MCInst_setOpcode(Inst, ARM_t2PLDpci);
      break;
    case ARM_t2PLIi8:
      MCInst_setOpcode(Inst, ARM_t2PLIpci);
      break;
    default:
      return MCDisassembler_Fail;
    }
    return DecodeT2LoadLabel(Inst, Insn, Address, Decoder);
  }

  if (Rt == 15) {
    switch (MCInst_getOpcode(Inst)) {
    case ARM_t2LDRSHi8:
      return MCDisassembler_Fail;
    case ARM_t2LDRHi8:
      if (!add)
	MCInst_setOpcode(Inst, ARM_t2PLDWi8);
      break;
    case ARM_t2LDRSBi8:
      MCInst_setOpcode(Inst, ARM_t2PLIi8);
      break;
    default:
      break;
    }
  }

  switch (MCInst_getOpcode(Inst)) {
  case ARM_t2PLDi8:
    break;
  case ARM_t2PLIi8:
    if (!hasV7Ops)
      return MCDisassembler_Fail;
    break;
  case ARM_t2PLDWi8:
    if (!hasV7Ops || !hasMP)
      return MCDisassembler_Fail;
    break;
  default:
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rt, Address, Decoder)))
      return MCDisassembler_Fail;
  }

  if (!Check(&S, DecodeT2AddrModeImm8(Inst, imm, Address, Decoder)))
    return MCDisassembler_Fail;
  return S;
}

static DecodeStatus DecodeT2LoadImm12(MCInst *Inst, unsigned Insn,
				      uint64_t Address, MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rt = fieldFromInstruction_4(Insn, 12, 4);
  unsigned imm = fieldFromInstruction_4(Insn, 0, 12);
  imm |= (Rn << 13);

  /* Ignored bit flags */

  bool hasMP = true;
  bool hasV7Ops = true;

  if (Rn == 15) {
    switch (MCInst_getOpcode(Inst)) {
    case ARM_t2LDRi12:
      MCInst_setOpcode(Inst, ARM_t2LDRpci);
      break;
    case ARM_t2LDRHi12:
      MCInst_setOpcode(Inst, ARM_t2LDRHpci);
      break;
    case ARM_t2LDRSHi12:
      MCInst_setOpcode(Inst, ARM_t2LDRSHpci);
      break;
    case ARM_t2LDRBi12:
      MCInst_setOpcode(Inst, ARM_t2LDRBpci);
      break;
    case ARM_t2LDRSBi12:
      MCInst_setOpcode(Inst, ARM_t2LDRSBpci);
      break;
    case ARM_t2PLDi12:
      MCInst_setOpcode(Inst, ARM_t2PLDpci);
      break;
    case ARM_t2PLIi12:
      MCInst_setOpcode(Inst, ARM_t2PLIpci);
      break;
    default:
      return MCDisassembler_Fail;
    }
    return DecodeT2LoadLabel(Inst, Insn, Address, Decoder);
  }

  if (Rt == 15) {
    switch (MCInst_getOpcode(Inst)) {
    case ARM_t2LDRSHi12:
      return MCDisassembler_Fail;
    case ARM_t2LDRHi12:
      MCInst_setOpcode(Inst, ARM_t2PLDWi12);
      break;
    case ARM_t2LDRSBi12:
      MCInst_setOpcode(Inst, ARM_t2PLIi12);
      break;
    default:
      break;
    }
  }

  switch (MCInst_getOpcode(Inst)) {
  case ARM_t2PLDi12:
    break;
  case ARM_t2PLIi12:
    if (!hasV7Ops)
      return MCDisassembler_Fail;
    break;
  case ARM_t2PLDWi12:
    if (!hasV7Ops || !hasMP)
      return MCDisassembler_Fail;
    break;
  default:
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rt, Address, Decoder)))
      return MCDisassembler_Fail;
  }

  if (!Check(&S, DecodeT2AddrModeImm12(Inst, imm, Address, Decoder)))
    return MCDisassembler_Fail;
  return S;
}

static DecodeStatus DecodeT2LoadT(MCInst *Inst, unsigned Insn, uint64_t Address,
				  MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rt = fieldFromInstruction_4(Insn, 12, 4);
  unsigned imm = fieldFromInstruction_4(Insn, 0, 8);
  imm |= (Rn << 9);

  if (Rn == 15) {
    switch (MCInst_getOpcode(Inst)) {
    case ARM_t2LDRT:
      MCInst_setOpcode(Inst, ARM_t2LDRpci);
      break;
    case ARM_t2LDRBT:
      MCInst_setOpcode(Inst, ARM_t2LDRBpci);
      break;
    case ARM_t2LDRHT:
      MCInst_setOpcode(Inst, ARM_t2LDRHpci);
      break;
    case ARM_t2LDRSBT:
      MCInst_setOpcode(Inst, ARM_t2LDRSBpci);
      break;
    case ARM_t2LDRSHT:
      MCInst_setOpcode(Inst, ARM_t2LDRSHpci);
      break;
    default:
      return MCDisassembler_Fail;
    }
    return DecodeT2LoadLabel(Inst, Insn, Address, Decoder);
  }

  if (!Check(&S, DecoderGPRRegisterClass(Inst, Rt, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeT2AddrModeImm8(Inst, imm, Address, Decoder)))
    return MCDisassembler_Fail;
  return S;
}

static DecodeStatus DecodeT2LoadLabel(MCInst *Inst, unsigned Insn,
				      uint64_t Address, MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rt = fieldFromInstruction_4(Insn, 12, 4);
  unsigned U = fieldFromInstruction_4(Insn, 23, 1);
  int imm = fieldFromInstruction_4(Insn, 0, 12);

  /* Ignored bit flags */

  bool hasV7Ops = true;

  if (Rt == 15) {
    switch (MCInst_getOpcode(Inst)) {
    case ARM_t2LDRBpci:
    case ARM_t2LDRHpci:
      MCInst_setOpcode(Inst, ARM_t2PLDpci);
      break;
    case ARM_t2LDRSBpci:
      MCInst_setOpcode(Inst, ARM_t2PLIpci);
      break;
    case ARM_t2LDRSHpci:
      return MCDisassembler_Fail;
    default:
      break;
    }
  }

  switch (MCInst_getOpcode(Inst)) {
  case ARM_t2PLDpci:
    break;
  case ARM_t2PLIpci:
    if (!hasV7Ops)
      return MCDisassembler_Fail;
    break;
  default:
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rt, Address, Decoder)))
      return MCDisassembler_Fail;
  }

  if (!U) {
    // Special case for #-0.
    if (imm == 0)
      imm = INT32_MIN;
    else
      imm = -imm;
  }
  MCOperand_CreateImm0(Inst, imm);

  return S;
}

static DecodeStatus DecodeT2Imm8S4(MCInst *Inst, unsigned Val, uint64_t Address,
				   MCRegisterInfo *Decoder)
{
  if (Val == 0)
    MCOperand_CreateImm0(Inst, INT32_MIN);
  else {
    int imm = Val & 0xFF;

    if (!(Val & 0x100))
      imm *= -1;
    MCOperand_CreateImm0(Inst, imm * 4);
  }

  return MCDisassembler_Success;
}

static DecodeStatus DecodeT2Imm7S4(MCInst *Inst, unsigned Val, uint64_t Address,
				   MCRegisterInfo *Decoder)
{
  if (Val == 0)
    MCOperand_CreateImm0(Inst, INT32_MIN);
  else {
    int imm = Val & 0x7F;

    if (!(Val & 0x80))
      imm *= -1;
    MCOperand_CreateImm0(Inst, imm * 4);
  }

  return MCDisassembler_Success;
}

static DecodeStatus DecodeT2AddrModeImm8s4(MCInst *Inst, unsigned Val,
					   uint64_t Address,
					   MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Val, 9, 4);
  unsigned imm = fieldFromInstruction_4(Val, 0, 9);

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeT2Imm8S4(Inst, imm, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeT2AddrModeImm7s4(MCInst *Inst, unsigned Val,
					   uint64_t Address,
					   MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Val, 8, 4);
  unsigned imm = fieldFromInstruction_4(Val, 0, 8);

  if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeT2Imm7S4(Inst, imm, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeT2AddrModeImm0_1020s4(MCInst *Inst, unsigned Val,
						uint64_t Address,
						MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Val, 8, 4);
  unsigned imm = fieldFromInstruction_4(Val, 0, 8);

  if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;

  MCOperand_CreateImm0(Inst, imm);

  return S;
}

static DecodeStatus DecodeT2Imm8(MCInst *Inst, unsigned Val, uint64_t Address,
				 MCRegisterInfo *Decoder)
{
  int imm = Val & 0xFF;
  if (Val == 0)
    imm = INT32_MIN;
  else if (!(Val & 0x100))
    imm *= -1;
  MCOperand_CreateImm0(Inst, imm);

  return MCDisassembler_Success;
}

static DecodeStatus DecodeT2Imm7(MCInst *Inst, unsigned Val, uint64_t Address,
				 MCRegisterInfo *Decoder, unsigned shift)
{
  int imm = Val & 0x7F;
  if (Val == 0)
    imm = INT32_MIN;
  else if (!(Val & 0x80))
    imm *= -1;
  if (imm != INT32_MIN)
    imm *= (1U << shift);
  MCOperand_CreateImm0(Inst, imm);

  return MCDisassembler_Success;
}

static DecodeStatus DecodeT2AddrModeImm8(MCInst *Inst, unsigned Val,
					 uint64_t Address,
					 MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Val, 9, 4);
  unsigned imm = fieldFromInstruction_4(Val, 0, 9);

  // Thumb stores cannot use PC as dest register.
  switch (MCInst_getOpcode(Inst)) {
  case ARM_t2STRT:
  case ARM_t2STRBT:
  case ARM_t2STRHT:
  case ARM_t2STRi8:
  case ARM_t2STRHi8:
  case ARM_t2STRBi8:
    if (Rn == 15)
      return MCDisassembler_Fail;
    break;
  default:
    break;
  }

  // Some instructions always use an additive offset.
  switch (MCInst_getOpcode(Inst)) {
  case ARM_t2LDRT:
  case ARM_t2LDRBT:
  case ARM_t2LDRHT:
  case ARM_t2LDRSBT:
  case ARM_t2LDRSHT:
  case ARM_t2STRT:
  case ARM_t2STRBT:
  case ARM_t2STRHT:
    imm |= 0x100;
    break;
  default:
    break;
  }

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeT2Imm8(Inst, imm, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeTAddrModeImm7(MCInst *Inst, unsigned Val,
					uint64_t Address,
					MCRegisterInfo *Decoder, unsigned shift)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Val, 8, 3);
  unsigned imm = fieldFromInstruction_4(Val, 0, 8);

  if (!Check(&S, DecodetGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeT2Imm7(Inst, imm, Address, Decoder, shift)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeT2AddrModeImm7(MCInst *Inst, unsigned Val,
					 uint64_t Address,
					 MCRegisterInfo *Decoder, int shift,
					 int WriteBack)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Val, 8, 4);
  unsigned imm = fieldFromInstruction_4(Val, 0, 8);
  if (WriteBack) {
    if (!Check(&S, DecoderGPRRegisterClass(Inst, Rn, Address, Decoder)))
      return MCDisassembler_Fail;
  } else if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeT2Imm7(Inst, imm, Address, Decoder, shift)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeT2LdStPre(MCInst *Inst, unsigned Insn,
				    uint64_t Address, MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rt = fieldFromInstruction_4(Insn, 12, 4);
  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned addr = fieldFromInstruction_4(Insn, 0, 8);
  addr |= fieldFromInstruction_4(Insn, 9, 1) << 8;
  addr |= Rn << 9;
  unsigned load = fieldFromInstruction_4(Insn, 20, 1);

  if (Rn == 15) {
    switch (MCInst_getOpcode(Inst)) {
    case ARM_t2LDR_PRE:
    case ARM_t2LDR_POST:
      MCInst_setOpcode(Inst, ARM_t2LDRpci);
      break;
    case ARM_t2LDRB_PRE:
    case ARM_t2LDRB_POST:
      MCInst_setOpcode(Inst, ARM_t2LDRBpci);
      break;
    case ARM_t2LDRH_PRE:
    case ARM_t2LDRH_POST:
      MCInst_setOpcode(Inst, ARM_t2LDRHpci);
      break;
    case ARM_t2LDRSB_PRE:
    case ARM_t2LDRSB_POST:
      if (Rt == 15)
	MCInst_setOpcode(Inst, ARM_t2PLIpci);
      else
	MCInst_setOpcode(Inst, ARM_t2LDRSBpci);
      break;
    case ARM_t2LDRSH_PRE:
    case ARM_t2LDRSH_POST:
      MCInst_setOpcode(Inst, ARM_t2LDRSHpci);
      break;
    default:
      return MCDisassembler_Fail;
    }
    return DecodeT2LoadLabel(Inst, Insn, Address, Decoder);
  }

  if (!load) {
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
      return MCDisassembler_Fail;
  }

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rt, Address, Decoder)))
    return MCDisassembler_Fail;

  if (load) {
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
      return MCDisassembler_Fail;
  }

  if (!Check(&S, DecodeT2AddrModeImm8(Inst, addr, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeT2AddrModeImm12(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Val, 13, 4);
  unsigned imm = fieldFromInstruction_4(Val, 0, 12);

  // Thumb stores cannot use PC as dest register.
  switch (MCInst_getOpcode(Inst)) {
  case ARM_t2STRi12:
  case ARM_t2STRBi12:
  case ARM_t2STRHi12:
    if (Rn == 15)
      return MCDisassembler_Fail;
    break;
  default:
    break;
  }

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, imm);

  return S;
}

static DecodeStatus DecodeThumbAddSPImm(MCInst *Inst, uint16_t Insn,
					uint64_t Address,
					MCRegisterInfo *Decoder)
{
  unsigned imm = fieldFromInstruction_2(Insn, 0, 7);

  MCOperand_CreateReg0(Inst, ARM_SP);
  MCOperand_CreateReg0(Inst, ARM_SP);
  MCOperand_CreateImm0(Inst, imm);

  return MCDisassembler_Success;
}

static DecodeStatus DecodeThumbAddSPReg(MCInst *Inst, uint16_t Insn,
					uint64_t Address,
					MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  if (MCInst_getOpcode(Inst) == ARM_tADDrSP) {
    unsigned Rdm = fieldFromInstruction_2(Insn, 0, 3);
    Rdm |= fieldFromInstruction_2(Insn, 7, 1) << 3;

    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rdm, Address, Decoder)))
      return MCDisassembler_Fail;
    MCOperand_CreateReg0(Inst, ARM_SP);
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rdm, Address, Decoder)))
      return MCDisassembler_Fail;
  } else if (MCInst_getOpcode(Inst) == ARM_tADDspr) {
    unsigned Rm = fieldFromInstruction_2(Insn, 3, 4);

    MCOperand_CreateReg0(Inst, ARM_SP);
    MCOperand_CreateReg0(Inst, ARM_SP);
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rm, Address, Decoder)))
      return MCDisassembler_Fail;
  }

  return S;
}

static DecodeStatus DecodeThumbCPS(MCInst *Inst, uint16_t Insn,
				   uint64_t Address, MCRegisterInfo *Decoder)
{
  unsigned imod = fieldFromInstruction_2(Insn, 4, 1) | 0x2;
  unsigned flags = fieldFromInstruction_2(Insn, 0, 3);

  MCOperand_CreateImm0(Inst, imod);
  MCOperand_CreateImm0(Inst, flags);

  return MCDisassembler_Success;
}

static DecodeStatus DecodePostIdxReg(MCInst *Inst, unsigned Insn,
				     uint64_t Address, MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;
  unsigned Rm = fieldFromInstruction_4(Insn, 0, 4);
  unsigned add = fieldFromInstruction_4(Insn, 4, 1);

  if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rm, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, add);

  return S;
}

static DecodeStatus DecodeMveAddrModeRQ(MCInst *Inst, unsigned Insn,
					uint64_t Address,
					MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;
  unsigned Rn = fieldFromInstruction_4(Insn, 3, 4);
  unsigned Qm = fieldFromInstruction_4(Insn, 0, 3);

  if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeMQPRRegisterClass(Inst, Qm, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeMveAddrModeQ(MCInst *Inst, unsigned Insn,
				       uint64_t Address,
				       MCRegisterInfo *Decoder, int shift)
{
  DecodeStatus S = MCDisassembler_Success;
  unsigned Qm = fieldFromInstruction_4(Insn, 8, 3);
  int imm = fieldFromInstruction_4(Insn, 0, 7);

  if (!Check(&S, DecodeMQPRRegisterClass(Inst, Qm, Address, Decoder)))
    return MCDisassembler_Fail;

  if (!fieldFromInstruction_4(Insn, 7, 1)) {
    if (imm == 0)
      imm = INT32_MIN; // indicate -0
    else
      imm *= -1;
  }
  if (imm != INT32_MIN)
    imm *= (1U << shift);
  MCOperand_CreateImm0(Inst, imm);

  return S;
}

static DecodeStatus DecodeThumbBLXOffset(MCInst *Inst, unsigned Val,
					 uint64_t Address,
					 MCRegisterInfo *Decoder)
{
  // Val is passed in as S:J1:J2:imm10H:imm10L:'0'
  // Note only one trailing zero not two.  Also the J1 and J2 values are from
  // the encoded instruction.  So here change to I1 and I2 values via:
  // I1 = NOT(J1 EOR S);
  // I2 = NOT(J2 EOR S);
  // and build the imm32 with two trailing zeros as documented:
  // imm32 = SignExtend(S:I1:I2:imm10H:imm10L:'00', 32);
  unsigned S = (Val >> 23) & 1;
  unsigned J1 = (Val >> 22) & 1;
  unsigned J2 = (Val >> 21) & 1;
  unsigned I1 = !(J1 ^ S);
  unsigned I2 = !(J2 ^ S);
  unsigned tmp = (Val & ~0x600000) | (I1 << 22) | (I2 << 21);
  int imm32 = SignExtend32(tmp << 1, 25);

  //  if (!tryAddingSymbolicOperand(Address,
  //				(Address & ~2u) + imm32 + 4,
  //				true, 4, Inst, Decoder))
  MCOperand_CreateImm0(Inst, imm32);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeCoprocessor(MCInst *Inst, unsigned Val,
				      uint64_t Address, MCRegisterInfo *Decoder)
{
  if (Val == 0xA || Val == 0xB)
    return MCDisassembler_Fail;

  /* Ignored bit flags */

  if (ARM_getFeatureBits(Inst->csh->mode, ARM_HasV8Ops) &&
      !(Val == 14 || Val == 15))
    return MCDisassembler_Fail;

  MCOperand_CreateImm0(Inst, Val);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeThumbTableBranch(MCInst *Inst, unsigned Insn,
					   uint64_t Address,
					   MCRegisterInfo *Decoder)
{
  /* Ignored bit flags */
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_2(Insn, 16, 4);
  unsigned Rm = fieldFromInstruction_2(Insn, 0, 4);

  if (Rn == 13 && !true)
    S = MCDisassembler_SoftFail;
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecoderGPRRegisterClass(Inst, Rm, Address, Decoder)))
    return MCDisassembler_Fail;
  return S;
}

static DecodeStatus DecodeThumb2BCCInstruction(MCInst *Inst, unsigned Insn,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned pred = fieldFromInstruction_2(Insn, 22, 4);
  if (pred == 0xE || pred == 0xF) {
    unsigned opc = fieldFromInstruction_2(Insn, 4, 28);
    switch (opc) {
    default:
      return MCDisassembler_Fail;
    case 0xf3bf8f4:
      MCInst_setOpcode(Inst, ARM_t2DSB);
      break;
    case 0xf3bf8f5:
      MCInst_setOpcode(Inst, ARM_t2DMB);
      break;
    case 0xf3bf8f6:
      MCInst_setOpcode(Inst, ARM_t2ISB);
      break;
    }

    unsigned imm = fieldFromInstruction_2(Insn, 0, 4);
    return DecodeMemBarrierOption(Inst, imm, Address, Decoder);
  }

  unsigned brtarget = fieldFromInstruction_2(Insn, 0, 11) << 1;
  brtarget |= fieldFromInstruction_2(Insn, 11, 1) << 19;
  brtarget |= fieldFromInstruction_2(Insn, 13, 1) << 18;
  brtarget |= fieldFromInstruction_2(Insn, 16, 6) << 12;
  brtarget |= fieldFromInstruction_2(Insn, 26, 1) << 20;

  if (!Check(&S, DecodeT2BROperand(Inst, brtarget, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodePredicateOperand(Inst, pred, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeT2SOImm(MCInst *Inst, unsigned Val, uint64_t Address,
				  MCRegisterInfo *Decoder)
{
  unsigned ctrl = fieldFromInstruction_4(Val, 10, 2);
  if (ctrl == 0) {
    unsigned byte = fieldFromInstruction_4(Val, 8, 2);
    unsigned imm = fieldFromInstruction_4(Val, 0, 8);
    switch (byte) {
    case 0:
      MCOperand_CreateImm0(Inst, imm);
      break;
    case 1:
      MCOperand_CreateImm0(Inst, (imm << 16) | imm);
      break;
    case 2:
      MCOperand_CreateImm0(Inst, (imm << 24) | (imm << 8));
      break;
    case 3:
      MCOperand_CreateImm0(Inst, (imm << 24) | (imm << 16) | (imm << 8) | imm);
      break;
    }
  } else {
    unsigned unrot = fieldFromInstruction_4(Val, 0, 7) | 0x80;
    unsigned rot = fieldFromInstruction_4(Val, 7, 5);
    unsigned imm = (unrot >> rot) | (unrot << ((32 - rot) & 31));
    MCOperand_CreateImm0(Inst, imm);
  }

  return MCDisassembler_Success;
}

static DecodeStatus DecodeThumbBCCTargetOperand(MCInst *Inst, unsigned Val,
						uint64_t Address,
						MCRegisterInfo *Decoder)
{
  //  if (!tryAddingSymbolicOperand(Address, Address + SignExtend32(Val<<1, 9) +
  //  4,
  //				true, 2, Inst, Decoder))
  MCOperand_CreateImm0(Inst, SignExtend32(Val << 1, 9));
  return MCDisassembler_Success;
}

static DecodeStatus DecodeThumbBLTargetOperand(MCInst *Inst, unsigned Val,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  // Val is passed in as S:J1:J2:imm10:imm11
  // Note no trailing zero after imm11.  Also the J1 and J2 values are from
  // the encoded instruction.  So here change to I1 and I2 values via:
  // I1 = NOT(J1 EOR S);
  // I2 = NOT(J2 EOR S);
  // and build the imm32 with one trailing zero as documented:
  // imm32 = SignExtend(S:I1:I2:imm10:imm11:'0', 32);
  unsigned S = (Val >> 23) & 1;
  unsigned J1 = (Val >> 22) & 1;
  unsigned J2 = (Val >> 21) & 1;
  unsigned I1 = !(J1 ^ S);
  unsigned I2 = !(J2 ^ S);
  unsigned tmp = (Val & ~0x600000) | (I1 << 22) | (I2 << 21);
  int imm32 = SignExtend32(tmp << 1, 25);

  //  if (!tryAddingSymbolicOperand(Address, Address + imm32 + 4,
  //				true, 4, Inst, Decoder))
  MCOperand_CreateImm0(Inst, imm32);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeMemBarrierOption(MCInst *Inst, unsigned Val,
					   uint64_t Address,
					   MCRegisterInfo *Decoder)
{
  if (Val & ~0xf)
    return MCDisassembler_Fail;

  MCOperand_CreateImm0(Inst, Val);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeInstSyncBarrierOption(MCInst *Inst, unsigned Val,
						uint64_t Address,
						MCRegisterInfo *Decoder)
{
  if (Val & ~0xf)
    return MCDisassembler_Fail;

  MCOperand_CreateImm0(Inst, Val);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeMSRMask(MCInst *Inst, unsigned Val, uint64_t Address,
				  MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;
  /* Ignored bit flags */

  if (true) {
    unsigned ValLow = Val & 0xff;

    // Validate the SYSm value first.
    switch (ValLow) {
    case 0:  // apsr
    case 1:  // iapsr
    case 2:  // eapsr
    case 3:  // xpsr
    case 5:  // ipsr
    case 6:  // epsr
    case 7:  // iepsr
    case 8:  // msp
    case 9:  // psp
    case 16: // primask
    case 20: // control
      break;
    case 17: // basepri
    case 18: // basepri_max
    case 19: // faultmask
      if (!(true))
	// Values basepri, basepri_max and faultmask are only valid for v7m.
	return MCDisassembler_Fail;
      break;
    case 0x8a: // msplim_ns
    case 0x8b: // psplim_ns
    case 0x91: // basepri_ns
    case 0x93: // faultmask_ns
      if (!(true))
	return MCDisassembler_Fail;
      0x0;
    case 10:   // msplim
    case 11:   // psplim
    case 0x88: // msp_ns
    case 0x89: // psp_ns
    case 0x90: // primask_ns
    case 0x94: // control_ns
    case 0x98: // sp_ns
      if (!(true))
	return MCDisassembler_Fail;
      break;
    default:
      // Architecturally defined as unpredictable
      S = MCDisassembler_SoftFail;
      break;
    }

    if (MCInst_getOpcode(Inst) == ARM_t2MSR_M) {
      unsigned Mask = fieldFromInstruction_4(Val, 10, 2);
      if (!(true)) {
	// The ARMv6-M MSR bits {11-10} can be only 0b10, other values are
	// unpredictable.
	if (Mask != 2)
	  S = MCDisassembler_SoftFail;
      } else {
	// The ARMv7-M architecture stores an additional 2-bit mask value in
	// MSR bits {11-10}. The mask is used only with apsr, iapsr, eapsr and
	// xpsr, it has to be 0b10 in other cases. Bit mask{1} indicates if
	// the NZCVQ bits should be moved by the instruction. Bit mask{0}
	// indicates the move for the GE{3:0} bits, the mask{0} bit can be set
	// only if the processor includes the DSP extension.
	if (Mask == 0 || (Mask != 2 && ValLow > 3) || (!(true) && (Mask & 1)))
	  S = MCDisassembler_SoftFail;
      }
    }
  } else {
    // A/R class
    if (Val == 0)
      return MCDisassembler_Fail;
  }
  MCOperand_CreateImm0(Inst, Val);
  return S;
}

static DecodeStatus DecodeBankedReg(MCInst *Inst, unsigned Val,
				    uint64_t Address, MCRegisterInfo *Decoder)
{
  unsigned R = fieldFromInstruction_4(Val, 5, 1);
  unsigned SysM = fieldFromInstruction_4(Val, 0, 5);

  // The table of encodings for these banked registers comes from B9.2.3 of the
  // ARM ARM. There are patterns, but nothing regular enough to make this logic
  // neater. So by fiat, these values are UNPREDICTABLE:
  if (!lookupBankedRegByEncoding((R << 5) | SysM))
    return MCDisassembler_Fail;

  MCOperand_CreateImm0(Inst, Val);

  return MCDisassembler_Success;
}

static DecodeStatus DecodeDoubleRegLoad(MCInst *Inst, unsigned Insn,
					uint64_t Address,
					MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rt = fieldFromInstruction_4(Insn, 12, 4);
  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned pred = fieldFromInstruction_4(Insn, 28, 4);

  if (Rn == 0xF)
    S = MCDisassembler_SoftFail;

  if (!Check(&S, DecodeGPRPairRegisterClass(Inst, Rt, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodePredicateOperand(Inst, pred, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeDoubleRegStore(MCInst *Inst, unsigned Insn,
					 uint64_t Address,
					 MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rd = fieldFromInstruction_4(Insn, 12, 4);
  unsigned Rt = fieldFromInstruction_4(Insn, 0, 4);
  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned pred = fieldFromInstruction_4(Insn, 28, 4);

  if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rd, Address, Decoder)))
    return MCDisassembler_Fail;

  if (Rn == 0xF || Rd == Rn || Rd == Rt || Rd == Rt + 1)
    S = MCDisassembler_SoftFail;

  if (!Check(&S, DecodeGPRPairRegisterClass(Inst, Rt, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodePredicateOperand(Inst, pred, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeLDRPreImm(MCInst *Inst, unsigned Insn,
				    uint64_t Address, MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rt = fieldFromInstruction_4(Insn, 12, 4);
  unsigned imm = fieldFromInstruction_4(Insn, 0, 12);
  imm |= fieldFromInstruction_4(Insn, 16, 4) << 13;
  imm |= fieldFromInstruction_4(Insn, 23, 1) << 12;
  unsigned pred = fieldFromInstruction_4(Insn, 28, 4);

  if (Rn == 0xF || Rn == Rt)
    S = MCDisassembler_SoftFail;

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rt, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeAddrModeImm12Operand(Inst, imm, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodePredicateOperand(Inst, pred, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeLDRPreReg(MCInst *Inst, unsigned Insn,
				    uint64_t Address, MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rt = fieldFromInstruction_4(Insn, 12, 4);
  unsigned imm = fieldFromInstruction_4(Insn, 0, 12);
  imm |= fieldFromInstruction_4(Insn, 16, 4) << 13;
  imm |= fieldFromInstruction_4(Insn, 23, 1) << 12;
  unsigned pred = fieldFromInstruction_4(Insn, 28, 4);
  unsigned Rm = fieldFromInstruction_4(Insn, 0, 4);

  if (Rn == 0xF || Rn == Rt)
    S = MCDisassembler_SoftFail;
  if (Rm == 0xF)
    S = MCDisassembler_SoftFail;

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rt, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeSORegMemOperand(Inst, imm, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodePredicateOperand(Inst, pred, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeSTRPreImm(MCInst *Inst, unsigned Insn,
				    uint64_t Address, MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rt = fieldFromInstruction_4(Insn, 12, 4);
  unsigned imm = fieldFromInstruction_4(Insn, 0, 12);
  imm |= fieldFromInstruction_4(Insn, 16, 4) << 13;
  imm |= fieldFromInstruction_4(Insn, 23, 1) << 12;
  unsigned pred = fieldFromInstruction_4(Insn, 28, 4);

  if (Rn == 0xF || Rn == Rt)
    S = MCDisassembler_SoftFail;

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rt, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeAddrModeImm12Operand(Inst, imm, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodePredicateOperand(Inst, pred, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeSTRPreReg(MCInst *Inst, unsigned Insn,
				    uint64_t Address, MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rt = fieldFromInstruction_4(Insn, 12, 4);
  unsigned imm = fieldFromInstruction_4(Insn, 0, 12);
  imm |= fieldFromInstruction_4(Insn, 16, 4) << 13;
  imm |= fieldFromInstruction_4(Insn, 23, 1) << 12;
  unsigned pred = fieldFromInstruction_4(Insn, 28, 4);

  if (Rn == 0xF || Rn == Rt)
    S = MCDisassembler_SoftFail;

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rt, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeSORegMemOperand(Inst, imm, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodePredicateOperand(Inst, pred, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeVLD1LN(MCInst *Inst, unsigned Insn, uint64_t Address,
				 MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rm = fieldFromInstruction_4(Insn, 0, 4);
  unsigned Rd = fieldFromInstruction_4(Insn, 12, 4);
  Rd |= fieldFromInstruction_4(Insn, 22, 1) << 4;
  unsigned size = fieldFromInstruction_4(Insn, 10, 2);

  unsigned align = 0;
  unsigned index = 0;
  switch (size) {
  default:
    return MCDisassembler_Fail;
  case 0:
    if (fieldFromInstruction_4(Insn, 4, 1))
      return MCDisassembler_Fail; // UNDEFINED
    index = fieldFromInstruction_4(Insn, 5, 3);
    break;
  case 1:
    if (fieldFromInstruction_4(Insn, 5, 1))
      return MCDisassembler_Fail; // UNDEFINED
    index = fieldFromInstruction_4(Insn, 6, 2);
    if (fieldFromInstruction_4(Insn, 4, 1))
      align = 2;
    break;
  case 2:
    if (fieldFromInstruction_4(Insn, 6, 1))
      return MCDisassembler_Fail; // UNDEFINED
    index = fieldFromInstruction_4(Insn, 7, 1);

    switch (fieldFromInstruction_4(Insn, 4, 2)) {
    case 0:
      align = 0;
      break;
    case 3:
      align = 4;
      break;
    default:
      return MCDisassembler_Fail;
    }
    break;
  }

  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (Rm != 0xF) { // Writeback
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
      return MCDisassembler_Fail;
  }
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, align);
  if (Rm != 0xF) {
    if (Rm != 0xD) {
      if (!Check(&S, DecodeGPRRegisterClass(Inst, Rm, Address, Decoder)))
	return MCDisassembler_Fail;
    } else
      MCOperand_CreateReg0(Inst, 0);
  }

  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, index);

  return S;
}

static DecodeStatus DecodeVST1LN(MCInst *Inst, unsigned Insn, uint64_t Address,
				 MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rm = fieldFromInstruction_4(Insn, 0, 4);
  unsigned Rd = fieldFromInstruction_4(Insn, 12, 4);
  Rd |= fieldFromInstruction_4(Insn, 22, 1) << 4;
  unsigned size = fieldFromInstruction_4(Insn, 10, 2);

  unsigned align = 0;
  unsigned index = 0;
  switch (size) {
  default:
    return MCDisassembler_Fail;
  case 0:
    if (fieldFromInstruction_4(Insn, 4, 1))
      return MCDisassembler_Fail; // UNDEFINED
    index = fieldFromInstruction_4(Insn, 5, 3);
    break;
  case 1:
    if (fieldFromInstruction_4(Insn, 5, 1))
      return MCDisassembler_Fail; // UNDEFINED
    index = fieldFromInstruction_4(Insn, 6, 2);
    if (fieldFromInstruction_4(Insn, 4, 1))
      align = 2;
    break;
  case 2:
    if (fieldFromInstruction_4(Insn, 6, 1))
      return MCDisassembler_Fail; // UNDEFINED
    index = fieldFromInstruction_4(Insn, 7, 1);

    switch (fieldFromInstruction_4(Insn, 4, 2)) {
    case 0:
      align = 0;
      break;
    case 3:
      align = 4;
      break;
    default:
      return MCDisassembler_Fail;
    }
    break;
  }

  if (Rm != 0xF) { // Writeback
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
      return MCDisassembler_Fail;
  }
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, align);
  if (Rm != 0xF) {
    if (Rm != 0xD) {
      if (!Check(&S, DecodeGPRRegisterClass(Inst, Rm, Address, Decoder)))
	return MCDisassembler_Fail;
    } else
      MCOperand_CreateReg0(Inst, 0);
  }

  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, index);

  return S;
}

static DecodeStatus DecodeVLD2LN(MCInst *Inst, unsigned Insn, uint64_t Address,
				 MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rm = fieldFromInstruction_4(Insn, 0, 4);
  unsigned Rd = fieldFromInstruction_4(Insn, 12, 4);
  Rd |= fieldFromInstruction_4(Insn, 22, 1) << 4;
  unsigned size = fieldFromInstruction_4(Insn, 10, 2);

  unsigned align = 0;
  unsigned index = 0;
  unsigned inc = 1;
  switch (size) {
  default:
    return MCDisassembler_Fail;
  case 0:
    index = fieldFromInstruction_4(Insn, 5, 3);
    if (fieldFromInstruction_4(Insn, 4, 1))
      align = 2;
    break;
  case 1:
    index = fieldFromInstruction_4(Insn, 6, 2);
    if (fieldFromInstruction_4(Insn, 4, 1))
      align = 4;
    if (fieldFromInstruction_4(Insn, 5, 1))
      inc = 2;
    break;
  case 2:
    if (fieldFromInstruction_4(Insn, 5, 1))
      return MCDisassembler_Fail; // UNDEFINED
    index = fieldFromInstruction_4(Insn, 7, 1);
    if (fieldFromInstruction_4(Insn, 4, 1) != 0)
      align = 8;
    if (fieldFromInstruction_4(Insn, 6, 1))
      inc = 2;
    break;
  }

  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd + inc, Address, Decoder)))
    return MCDisassembler_Fail;
  if (Rm != 0xF) { // Writeback
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
      return MCDisassembler_Fail;
  }
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, align);
  if (Rm != 0xF) {
    if (Rm != 0xD) {
      if (!Check(&S, DecodeGPRRegisterClass(Inst, Rm, Address, Decoder)))
	return MCDisassembler_Fail;
    } else
      MCOperand_CreateReg0(Inst, 0);
  }

  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd + inc, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, index);

  return S;
}

static DecodeStatus DecodeVST2LN(MCInst *Inst, unsigned Insn, uint64_t Address,
				 MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rm = fieldFromInstruction_4(Insn, 0, 4);
  unsigned Rd = fieldFromInstruction_4(Insn, 12, 4);
  Rd |= fieldFromInstruction_4(Insn, 22, 1) << 4;
  unsigned size = fieldFromInstruction_4(Insn, 10, 2);

  unsigned align = 0;
  unsigned index = 0;
  unsigned inc = 1;
  switch (size) {
  default:
    return MCDisassembler_Fail;
  case 0:
    index = fieldFromInstruction_4(Insn, 5, 3);
    if (fieldFromInstruction_4(Insn, 4, 1))
      align = 2;
    break;
  case 1:
    index = fieldFromInstruction_4(Insn, 6, 2);
    if (fieldFromInstruction_4(Insn, 4, 1))
      align = 4;
    if (fieldFromInstruction_4(Insn, 5, 1))
      inc = 2;
    break;
  case 2:
    if (fieldFromInstruction_4(Insn, 5, 1))
      return MCDisassembler_Fail; // UNDEFINED
    index = fieldFromInstruction_4(Insn, 7, 1);
    if (fieldFromInstruction_4(Insn, 4, 1) != 0)
      align = 8;
    if (fieldFromInstruction_4(Insn, 6, 1))
      inc = 2;
    break;
  }

  if (Rm != 0xF) { // Writeback
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
      return MCDisassembler_Fail;
  }
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, align);
  if (Rm != 0xF) {
    if (Rm != 0xD) {
      if (!Check(&S, DecodeGPRRegisterClass(Inst, Rm, Address, Decoder)))
	return MCDisassembler_Fail;
    } else
      MCOperand_CreateReg0(Inst, 0);
  }

  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd + inc, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, index);

  return S;
}

static DecodeStatus DecodeVLD3LN(MCInst *Inst, unsigned Insn, uint64_t Address,
				 MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rm = fieldFromInstruction_4(Insn, 0, 4);
  unsigned Rd = fieldFromInstruction_4(Insn, 12, 4);
  Rd |= fieldFromInstruction_4(Insn, 22, 1) << 4;
  unsigned size = fieldFromInstruction_4(Insn, 10, 2);

  unsigned align = 0;
  unsigned index = 0;
  unsigned inc = 1;
  switch (size) {
  default:
    return MCDisassembler_Fail;
  case 0:
    if (fieldFromInstruction_4(Insn, 4, 1))
      return MCDisassembler_Fail; // UNDEFINED
    index = fieldFromInstruction_4(Insn, 5, 3);
    break;
  case 1:
    if (fieldFromInstruction_4(Insn, 4, 1))
      return MCDisassembler_Fail; // UNDEFINED
    index = fieldFromInstruction_4(Insn, 6, 2);
    if (fieldFromInstruction_4(Insn, 5, 1))
      inc = 2;
    break;
  case 2:
    if (fieldFromInstruction_4(Insn, 4, 2))
      return MCDisassembler_Fail; // UNDEFINED
    index = fieldFromInstruction_4(Insn, 7, 1);
    if (fieldFromInstruction_4(Insn, 6, 1))
      inc = 2;
    break;
  }

  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd + inc, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd + 2 * inc, Address, Decoder)))
    return MCDisassembler_Fail;

  if (Rm != 0xF) { // Writeback
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
      return MCDisassembler_Fail;
  }
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, align);
  if (Rm != 0xF) {
    if (Rm != 0xD) {
      if (!Check(&S, DecodeGPRRegisterClass(Inst, Rm, Address, Decoder)))
	return MCDisassembler_Fail;
    } else
      MCOperand_CreateReg0(Inst, 0);
  }

  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd + inc, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd + 2 * inc, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, index);

  return S;
}

static DecodeStatus DecodeVST3LN(MCInst *Inst, unsigned Insn, uint64_t Address,
				 MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rm = fieldFromInstruction_4(Insn, 0, 4);
  unsigned Rd = fieldFromInstruction_4(Insn, 12, 4);
  Rd |= fieldFromInstruction_4(Insn, 22, 1) << 4;
  unsigned size = fieldFromInstruction_4(Insn, 10, 2);

  unsigned align = 0;
  unsigned index = 0;
  unsigned inc = 1;
  switch (size) {
  default:
    return MCDisassembler_Fail;
  case 0:
    if (fieldFromInstruction_4(Insn, 4, 1))
      return MCDisassembler_Fail; // UNDEFINED
    index = fieldFromInstruction_4(Insn, 5, 3);
    break;
  case 1:
    if (fieldFromInstruction_4(Insn, 4, 1))
      return MCDisassembler_Fail; // UNDEFINED
    index = fieldFromInstruction_4(Insn, 6, 2);
    if (fieldFromInstruction_4(Insn, 5, 1))
      inc = 2;
    break;
  case 2:
    if (fieldFromInstruction_4(Insn, 4, 2))
      return MCDisassembler_Fail; // UNDEFINED
    index = fieldFromInstruction_4(Insn, 7, 1);
    if (fieldFromInstruction_4(Insn, 6, 1))
      inc = 2;
    break;
  }

  if (Rm != 0xF) { // Writeback
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
      return MCDisassembler_Fail;
  }
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, align);
  if (Rm != 0xF) {
    if (Rm != 0xD) {
      if (!Check(&S, DecodeGPRRegisterClass(Inst, Rm, Address, Decoder)))
	return MCDisassembler_Fail;
    } else
      MCOperand_CreateReg0(Inst, 0);
  }

  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd + inc, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd + 2 * inc, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, index);

  return S;
}

static DecodeStatus DecodeVLD4LN(MCInst *Inst, unsigned Insn, uint64_t Address,
				 MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rm = fieldFromInstruction_4(Insn, 0, 4);
  unsigned Rd = fieldFromInstruction_4(Insn, 12, 4);
  Rd |= fieldFromInstruction_4(Insn, 22, 1) << 4;
  unsigned size = fieldFromInstruction_4(Insn, 10, 2);

  unsigned align = 0;
  unsigned index = 0;
  unsigned inc = 1;
  switch (size) {
  default:
    return MCDisassembler_Fail;
  case 0:
    if (fieldFromInstruction_4(Insn, 4, 1))
      align = 4;
    index = fieldFromInstruction_4(Insn, 5, 3);
    break;
  case 1:
    if (fieldFromInstruction_4(Insn, 4, 1))
      align = 8;
    index = fieldFromInstruction_4(Insn, 6, 2);
    if (fieldFromInstruction_4(Insn, 5, 1))
      inc = 2;
    break;
  case 2:
    switch (fieldFromInstruction_4(Insn, 4, 2)) {
    case 0:
      align = 0;
      break;
    case 3:
      return MCDisassembler_Fail;
    default:
      align = 4 << fieldFromInstruction_4(Insn, 4, 2);
      break;
    }

    index = fieldFromInstruction_4(Insn, 7, 1);
    if (fieldFromInstruction_4(Insn, 6, 1))
      inc = 2;
    break;
  }

  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd + inc, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd + 2 * inc, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd + 3 * inc, Address, Decoder)))
    return MCDisassembler_Fail;

  if (Rm != 0xF) { // Writeback
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
      return MCDisassembler_Fail;
  }
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, align);
  if (Rm != 0xF) {
    if (Rm != 0xD) {
      if (!Check(&S, DecodeGPRRegisterClass(Inst, Rm, Address, Decoder)))
	return MCDisassembler_Fail;
    } else
      MCOperand_CreateReg0(Inst, 0);
  }

  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd + inc, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd + 2 * inc, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd + 3 * inc, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, index);

  return S;
}

static DecodeStatus DecodeVST4LN(MCInst *Inst, unsigned Insn, uint64_t Address,
				 MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rm = fieldFromInstruction_4(Insn, 0, 4);
  unsigned Rd = fieldFromInstruction_4(Insn, 12, 4);
  Rd |= fieldFromInstruction_4(Insn, 22, 1) << 4;
  unsigned size = fieldFromInstruction_4(Insn, 10, 2);

  unsigned align = 0;
  unsigned index = 0;
  unsigned inc = 1;
  switch (size) {
  default:
    return MCDisassembler_Fail;
  case 0:
    if (fieldFromInstruction_4(Insn, 4, 1))
      align = 4;
    index = fieldFromInstruction_4(Insn, 5, 3);
    break;
  case 1:
    if (fieldFromInstruction_4(Insn, 4, 1))
      align = 8;
    index = fieldFromInstruction_4(Insn, 6, 2);
    if (fieldFromInstruction_4(Insn, 5, 1))
      inc = 2;
    break;
  case 2:
    switch (fieldFromInstruction_4(Insn, 4, 2)) {
    case 0:
      align = 0;
      break;
    case 3:
      return MCDisassembler_Fail;
    default:
      align = 4 << fieldFromInstruction_4(Insn, 4, 2);
      break;
    }

    index = fieldFromInstruction_4(Insn, 7, 1);
    if (fieldFromInstruction_4(Insn, 6, 1))
      inc = 2;
    break;
  }

  if (Rm != 0xF) { // Writeback
    if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
      return MCDisassembler_Fail;
  }
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, align);
  if (Rm != 0xF) {
    if (Rm != 0xD) {
      if (!Check(&S, DecodeGPRRegisterClass(Inst, Rm, Address, Decoder)))
	return MCDisassembler_Fail;
    } else
      MCOperand_CreateReg0(Inst, 0);
  }

  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd + inc, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd + 2 * inc, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeDPRRegisterClass(Inst, Rd + 3 * inc, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, index);

  return S;
}

static DecodeStatus DecodeVMOVSRR(MCInst *Inst, unsigned Insn, uint64_t Address,
				  MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;
  unsigned Rt = fieldFromInstruction_4(Insn, 12, 4);
  unsigned Rt2 = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rm = fieldFromInstruction_4(Insn, 5, 1);
  unsigned pred = fieldFromInstruction_4(Insn, 28, 4);
  Rm |= fieldFromInstruction_4(Insn, 0, 4) << 1;

  if (Rt == 0xF || Rt2 == 0xF || Rm == 0x1F)
    S = MCDisassembler_SoftFail;

  if (!Check(&S, DecodeSPRRegisterClass(Inst, Rm, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeSPRRegisterClass(Inst, Rm + 1, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rt, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rt2, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodePredicateOperand(Inst, pred, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeVMOVRRS(MCInst *Inst, unsigned Insn, uint64_t Address,
				  MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;
  unsigned Rt = fieldFromInstruction_4(Insn, 12, 4);
  unsigned Rt2 = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Rm = fieldFromInstruction_4(Insn, 5, 1);
  unsigned pred = fieldFromInstruction_4(Insn, 28, 4);
  Rm |= fieldFromInstruction_4(Insn, 0, 4) << 1;

  if (Rt == 0xF || Rt2 == 0xF || Rm == 0x1F)
    S = MCDisassembler_SoftFail;

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rt, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rt2, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeSPRRegisterClass(Inst, Rm, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeSPRRegisterClass(Inst, Rm + 1, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodePredicateOperand(Inst, pred, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeIT(MCInst *Inst, unsigned Insn, uint64_t Address,
			     MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;
  unsigned pred = fieldFromInstruction_4(Insn, 4, 4);
  unsigned mask = fieldFromInstruction_4(Insn, 0, 4);

  if (pred == 0xF) {
    pred = 0xE;
    S = MCDisassembler_SoftFail;
  }

  if (mask == 0x0)
    return MCDisassembler_Fail;

  // IT masks are encoded as a sequence of replacement low-order bits
  // for the condition code. So if the low bit of the starting
  // condition code is 1, then we have to flip all the bits above the
  // terminating bit (which is the lowest 1 bit).
  if (pred & 1) {
    unsigned LowBit = mask & -mask;
    unsigned BitsAboveLowBit = 0xF & (-LowBit << 1);
    mask ^= BitsAboveLowBit;
  }

  MCOperand_CreateImm0(Inst, pred);
  MCOperand_CreateImm0(Inst, mask);
  return S;
}

static DecodeStatus DecodeT2LDRDPreInstruction(MCInst *Inst, unsigned Insn,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rt = fieldFromInstruction_4(Insn, 12, 4);
  unsigned Rt2 = fieldFromInstruction_4(Insn, 8, 4);
  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned addr = fieldFromInstruction_4(Insn, 0, 8);
  unsigned W = fieldFromInstruction_4(Insn, 21, 1);
  unsigned U = fieldFromInstruction_4(Insn, 23, 1);
  unsigned P = fieldFromInstruction_4(Insn, 24, 1);
  bool writeback = (W == 1) | (P == 0);

  addr |= (U << 8) | (Rn << 9);

  if (writeback && (Rn == Rt || Rn == Rt2))
    Check(&S, MCDisassembler_SoftFail);
  if (Rt == Rt2)
    Check(&S, MCDisassembler_SoftFail);

  // Rt
  if (!Check(&S, DecoderGPRRegisterClass(Inst, Rt, Address, Decoder)))
    return MCDisassembler_Fail;
  // Rt2
  if (!Check(&S, DecoderGPRRegisterClass(Inst, Rt2, Address, Decoder)))
    return MCDisassembler_Fail;
  // Writeback operand
  if (!Check(&S, DecoderGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  // addr
  if (!Check(&S, DecodeT2AddrModeImm8s4(Inst, addr, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeT2STRDPreInstruction(MCInst *Inst, unsigned Insn,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rt = fieldFromInstruction_4(Insn, 12, 4);
  unsigned Rt2 = fieldFromInstruction_4(Insn, 8, 4);
  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned addr = fieldFromInstruction_4(Insn, 0, 8);
  unsigned W = fieldFromInstruction_4(Insn, 21, 1);
  unsigned U = fieldFromInstruction_4(Insn, 23, 1);
  unsigned P = fieldFromInstruction_4(Insn, 24, 1);
  bool writeback = (W == 1) | (P == 0);

  addr |= (U << 8) | (Rn << 9);

  if (writeback && (Rn == Rt || Rn == Rt2))
    Check(&S, MCDisassembler_SoftFail);

  // Writeback operand
  if (!Check(&S, DecoderGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  // Rt
  if (!Check(&S, DecoderGPRRegisterClass(Inst, Rt, Address, Decoder)))
    return MCDisassembler_Fail;
  // Rt2
  if (!Check(&S, DecoderGPRRegisterClass(Inst, Rt2, Address, Decoder)))
    return MCDisassembler_Fail;
  // addr
  if (!Check(&S, DecodeT2AddrModeImm8s4(Inst, addr, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeT2Adr(MCInst *Inst, uint32_t Insn, uint64_t Address,
				MCRegisterInfo *Decoder)
{
  unsigned sign1 = fieldFromInstruction_4(Insn, 21, 1);
  unsigned sign2 = fieldFromInstruction_4(Insn, 23, 1);
  if (sign1 != sign2)
    return MCDisassembler_Fail;
  const unsigned Rd = fieldFromInstruction_4(Insn, 8, 4);
  //  assert(Inst.getNumOperands() == 0 && "We should receive an empty Inst");
  DecodeStatus S = DecoderGPRRegisterClass(Inst, Rd, Address, Decoder);

  unsigned Val = fieldFromInstruction_4(Insn, 0, 8);
  Val |= fieldFromInstruction_4(Insn, 12, 3) << 8;
  Val |= fieldFromInstruction_4(Insn, 26, 1) << 11;
  // If sign, then it is decreasing the address.
  if (sign1) {
    // Following ARMv7 Architecture Manual, when the offset
    // is zero, it is decoded as a subw, not as a adr.w
    if (!Val) {
      MCInst_setOpcode(Inst, ARM_t2SUBri12);
      MCOperand_CreateReg0(Inst, ARM_PC);
    } else
      Val = -Val;
  }
  MCOperand_CreateImm0(Inst, Val);
  return S;
}

static DecodeStatus DecodeT2ShifterImmOperand(MCInst *Inst, uint32_t Val,
					      uint64_t Address,
					      MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  // Shift of "asr #32" is not allowed in Thumb2 mode.
  if (Val == 0x20)
    S = MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, Val);
  return S;
}

static DecodeStatus DecodeSwap(MCInst *Inst, unsigned Insn, uint64_t Address,
			       MCRegisterInfo *Decoder)
{
  unsigned Rt = fieldFromInstruction_4(Insn, 12, 4);
  unsigned Rt2 = fieldFromInstruction_4(Insn, 0, 4);
  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  unsigned pred = fieldFromInstruction_4(Insn, 28, 4);

  if (pred == 0xF)
    return DecodeCPSInstruction(Inst, Insn, Address, Decoder);

  DecodeStatus S = MCDisassembler_Success;

  if (Rt == Rn || Rn == Rt2)
    S = MCDisassembler_SoftFail;

  if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rt, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rt2, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodePredicateOperand(Inst, pred, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeVCVTD(MCInst *Inst, unsigned Insn, uint64_t Address,
				MCRegisterInfo *Decoder)
{
  /* Ignored bit flags */
  bool hasFullFP16 = true;

  unsigned Vd = (fieldFromInstruction_4(Insn, 12, 4) << 0);
  Vd |= (fieldFromInstruction_4(Insn, 22, 1) << 4);
  unsigned Vm = (fieldFromInstruction_4(Insn, 0, 4) << 0);
  Vm |= (fieldFromInstruction_4(Insn, 5, 1) << 4);
  unsigned imm = fieldFromInstruction_4(Insn, 16, 6);
  unsigned cmode = fieldFromInstruction_4(Insn, 8, 4);
  unsigned op = fieldFromInstruction_4(Insn, 5, 1);

  DecodeStatus S = MCDisassembler_Success;

  // If the top 3 bits of imm are clear, this is a VMOV (immediate)
  if (!(imm & 0x38)) {
    if (cmode == 0xF) {
      if (op == 1)
	return MCDisassembler_Fail;
      MCInst_setOpcode(Inst, ARM_VMOVv2f32);
    }
    if (hasFullFP16) {
      if (cmode == 0xE) {
	if (op == 1) {
	  MCInst_setOpcode(Inst, ARM_VMOVv1i64);
	} else {
	  MCInst_setOpcode(Inst, ARM_VMOVv8i8);
	}
      }
      if (cmode == 0xD) {
	if (op == 1) {
	  MCInst_setOpcode(Inst, ARM_VMVNv2i32);
	} else {
	  MCInst_setOpcode(Inst, ARM_VMOVv2i32);
	}
      }
      if (cmode == 0xC) {
	if (op == 1) {
	  MCInst_setOpcode(Inst, ARM_VMVNv2i32);
	} else {
	  MCInst_setOpcode(Inst, ARM_VMOVv2i32);
	}
      }
    }
    return DecodeVMOVModImmInstruction(Inst, Insn, Address, Decoder);
  }

  if (!(imm & 0x20))
    return MCDisassembler_Fail;

  if (!Check(&S, DecodeDPRRegisterClass(Inst, Vd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeDPRRegisterClass(Inst, Vm, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, 64 - imm);

  return S;
}

static DecodeStatus DecodeVCVTQ(MCInst *Inst, unsigned Insn, uint64_t Address,
				MCRegisterInfo *Decoder)
{
  /* Ignored bit flags */
  bool hasFullFP16 = true;

  unsigned Vd = (fieldFromInstruction_4(Insn, 12, 4) << 0);
  Vd |= (fieldFromInstruction_4(Insn, 22, 1) << 4);
  unsigned Vm = (fieldFromInstruction_4(Insn, 0, 4) << 0);
  Vm |= (fieldFromInstruction_4(Insn, 5, 1) << 4);
  unsigned imm = fieldFromInstruction_4(Insn, 16, 6);
  unsigned cmode = fieldFromInstruction_4(Insn, 8, 4);
  unsigned op = fieldFromInstruction_4(Insn, 5, 1);

  DecodeStatus S = MCDisassembler_Success;

  // If the top 3 bits of imm are clear, this is a VMOV (immediate)
  if (!(imm & 0x38)) {
    if (cmode == 0xF) {
      if (op == 1)
	return MCDisassembler_Fail;
      MCInst_setOpcode(Inst, ARM_VMOVv4f32);
    }
    if (hasFullFP16) {
      if (cmode == 0xE) {
	if (op == 1) {
	  MCInst_setOpcode(Inst, ARM_VMOVv2i64);
	} else {
	  MCInst_setOpcode(Inst, ARM_VMOVv16i8);
	}
      }
      if (cmode == 0xD) {
	if (op == 1) {
	  MCInst_setOpcode(Inst, ARM_VMVNv4i32);
	} else {
	  MCInst_setOpcode(Inst, ARM_VMOVv4i32);
	}
      }
      if (cmode == 0xC) {
	if (op == 1) {
	  MCInst_setOpcode(Inst, ARM_VMVNv4i32);
	} else {
	  MCInst_setOpcode(Inst, ARM_VMOVv4i32);
	}
      }
    }
    return DecodeVMOVModImmInstruction(Inst, Insn, Address, Decoder);
  }

  if (!(imm & 0x20))
    return MCDisassembler_Fail;

  if (!Check(&S, DecodeQPRRegisterClass(Inst, Vd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeQPRRegisterClass(Inst, Vm, Address, Decoder)))
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, 64 - imm);

  return S;
}

static DecodeStatus DecodeNEONComplexLane64Instruction(MCInst *Inst,
						       unsigned Insn,
						       uint64_t Address,
						       MCRegisterInfo *Decoder)
{
  unsigned Vd = (fieldFromInstruction_4(Insn, 12, 4) << 0);
  Vd |= (fieldFromInstruction_4(Insn, 22, 1) << 4);
  unsigned Vn = (fieldFromInstruction_4(Insn, 16, 4) << 0);
  Vn |= (fieldFromInstruction_4(Insn, 7, 1) << 4);
  unsigned Vm = (fieldFromInstruction_4(Insn, 0, 4) << 0);
  Vm |= (fieldFromInstruction_4(Insn, 5, 1) << 4);
  unsigned q = (fieldFromInstruction_4(Insn, 6, 1) << 0);
  unsigned rotate = (fieldFromInstruction_4(Insn, 20, 2) << 0);

  DecodeStatus S = MCDisassembler_Success;
#define DestRegDecoder(Inst, Vd, Address, Decoder)                             \
  q ? DecodeQPRRegisterClass(Inst, Vd, Address, Decoder)                       \
    : DecodeDPRRegisterClass(Inst, Vd, Address, Decoder)

  if (!Check(&S, DestRegDecoder(Inst, Vd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DestRegDecoder(Inst, Vd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DestRegDecoder(Inst, Vn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeDPRRegisterClass(Inst, Vm, Address, Decoder)))
    return MCDisassembler_Fail;
  // The lane index does not have any bits in the encoding, because it can only
  // be 0.
  MCOperand_CreateImm0(Inst, 0);
  MCOperand_CreateImm0(Inst, rotate);

  return S;
}

static DecodeStatus DecodeLDR(MCInst *Inst, unsigned Val, uint64_t Address,
			      MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned Rn = fieldFromInstruction_4(Val, 16, 4);
  unsigned Rt = fieldFromInstruction_4(Val, 12, 4);
  unsigned Rm = fieldFromInstruction_4(Val, 0, 4);
  Rm |= (fieldFromInstruction_4(Val, 23, 1) << 4);
  unsigned Cond = fieldFromInstruction_4(Val, 28, 4);

  if (fieldFromInstruction_4(Val, 8, 4) != 0 || Rn == Rt)
    S = MCDisassembler_SoftFail;

  if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rt, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeAddrMode7Operand(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodePostIdxReg(Inst, Rm, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodePredicateOperand(Inst, Cond, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecoderForMRRC2AndMCRR2(MCInst *Inst, unsigned Val,
					    uint64_t Address,
					    MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned CRm = fieldFromInstruction_4(Val, 0, 4);
  unsigned opc1 = fieldFromInstruction_4(Val, 4, 4);
  unsigned cop = fieldFromInstruction_4(Val, 8, 4);
  unsigned Rt = fieldFromInstruction_4(Val, 12, 4);
  unsigned Rt2 = fieldFromInstruction_4(Val, 16, 4);

  if ((cop & ~0x1) == 0xa)
    return MCDisassembler_Fail;

  if (Rt == Rt2)
    S = MCDisassembler_SoftFail;

  // We have to check if the instruction is MRRC2
  // or MCRR2 when constructing the operands for
  // Inst. Reason is because MRRC2 stores to two
  // registers so it's tablegen desc has has two
  // outputs whereas MCRR doesn't store to any
  // registers so all of it's operands are listed
  // as inputs, therefore the operand order for
  // MRRC2 needs to be [Rt, Rt2, cop, opc1, CRm]
  // and MCRR2 operand order is [cop, opc1, Rt, Rt2, CRm]

  if (MCInst_getOpcode(Inst) == ARM_MRRC2) {
    if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rt, Address, Decoder)))
      return MCDisassembler_Fail;
    if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rt2, Address, Decoder)))
      return MCDisassembler_Fail;
  }
  MCOperand_CreateImm0(Inst, cop);
  MCOperand_CreateImm0(Inst, opc1);
  if (MCInst_getOpcode(Inst) == ARM_MCRR2) {
    if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rt, Address, Decoder)))
      return MCDisassembler_Fail;
    if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rt2, Address, Decoder)))
      return MCDisassembler_Fail;
  }
  MCOperand_CreateImm0(Inst, CRm);

  return S;
}

static DecodeStatus DecodeForVMRSandVMSR(MCInst *Inst, unsigned Val,
					 uint64_t Address,
					 MCRegisterInfo *Decoder)
{
  /* Ignored bit flags */
  DecodeStatus S = MCDisassembler_Success;

  // Add explicit operand for the destination sysreg, for cases where
  // we have to model it for code generation purposes.
  switch (MCInst_getOpcode(Inst)) {
  case ARM_VMSR_FPSCR_NZCVQC:
    MCOperand_CreateReg0(Inst, ARM_FPSCR_NZCV);
    break;
  case ARM_VMSR_P0:
    MCOperand_CreateReg0(Inst, ARM_VPR);
    break;
  }

  if (MCInst_getOpcode(Inst) != ARM_FMSTAT) {
    unsigned Rt = fieldFromInstruction_4(Val, 12, 4);

    if (true && !true) {
      if (Rt == 13 || Rt == 15)
	S = MCDisassembler_SoftFail;
      Check(&S, DecodeGPRRegisterClass(Inst, Rt, Address, Decoder));
    } else
      Check(&S, DecodeGPRnopcRegisterClass(Inst, Rt, Address, Decoder));
  }

  // Add explicit operand for the source sysreg, similarly to above.
  switch (MCInst_getOpcode(Inst)) {
  case ARM_VMRS_FPSCR_NZCVQC:
    MCOperand_CreateReg0(Inst, ARM_FPSCR_NZCV);
    break;
  case ARM_VMRS_P0:
    MCOperand_CreateReg0(Inst, ARM_VPR);
    break;
  }

  if (true) {
    MCOperand_CreateImm0(Inst, ARMCC_AL);
    MCOperand_CreateReg0(Inst, 0);
  } else {
    unsigned pred = fieldFromInstruction_4(Val, 28, 4);
    if (!Check(&S, DecodePredicateOperand(Inst, pred, Address, Decoder)))
      return MCDisassembler_Fail;
  }

  return S;
}

static DecodeStatus DecodeBFLabelOperand(MCInst *Inst, unsigned Val,
					 uint64_t Address,
					 MCRegisterInfo *Decoder, bool isSigned,
					 bool isNeg, bool zeroPermitted,
					 int size)
{
  DecodeStatus S = MCDisassembler_Success;
  if (Val == 0 && !zeroPermitted)
    S = MCDisassembler_Fail;

  uint64_t DecVal;
  if (isSigned)
    DecVal = SignExtend32(Val << 1, size + 1);
  else
    DecVal = (Val << 1);

  //  if (!tryAddingSymbolicOperand(Address, Address + DecVal + 4, true, 4,
  //  Inst,
  //				Decoder))
  MCOperand_CreateImm0(Inst, isNeg ? -DecVal : DecVal);
  return S;
}

static DecodeStatus DecodeBFAfterTargetOperand(MCInst *Inst, unsigned Val,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{

  uint64_t LocImm = MCOperand_getImm(MCInst_getOperand(Inst, 0));
  Val = LocImm + (2 << Val);
  //  if (!tryAddingSymbolicOperand(Address, Address + Val + 4, true, 4, Inst,
  //				Decoder))
  MCOperand_CreateImm0(Inst, Val);
  return MCDisassembler_Success;
}

static DecodeStatus DecodePredNoALOperand(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder)
{
  if (Val >= ARMCC_AL) // also exclude the non-condition NV
    return MCDisassembler_Fail;
  MCOperand_CreateImm0(Inst, Val);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeLOLoop(MCInst *Inst, unsigned Insn, uint64_t Address,
				 MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;
  unsigned Rn;

  if (MCInst_getOpcode(Inst) == ARM_MVE_LCTP)
    return S;

  unsigned Imm = fieldFromInstruction_4(Insn, 11, 1) |
		 fieldFromInstruction_4(Insn, 1, 10) << 1;
  switch (MCInst_getOpcode(Inst)) {
  case ARM_t2LEUpdate:
  case ARM_MVE_LETP:
    MCOperand_CreateReg0(Inst, ARM_LR);
    MCOperand_CreateReg0(Inst, ARM_LR);
    0x0;
  case ARM_t2LE:
    if (!Check(&S, DecodeBFLabelOperand(Inst, Imm, Address, Decoder, false,
					true, true, 11)))
      return MCDisassembler_Fail;
    break;
  case ARM_t2WLS:
  case ARM_MVE_WLSTP_8:
  case ARM_MVE_WLSTP_16:
  case ARM_MVE_WLSTP_32:
  case ARM_MVE_WLSTP_64:
    MCOperand_CreateReg0(Inst, ARM_LR);
    if (!Check(&S, DecoderGPRRegisterClass(Inst,
					   fieldFromInstruction_4(Insn, 16, 4),
					   Address, Decoder)) ||
	!Check(&S, DecodeBFLabelOperand(Inst, Imm, Address, Decoder, false,
					false, true, 11)))
      return MCDisassembler_Fail;
    break;
  case ARM_t2DLS:
  case ARM_MVE_DLSTP_8:
  case ARM_MVE_DLSTP_16:
  case ARM_MVE_DLSTP_32:
  case ARM_MVE_DLSTP_64:
      Rn = fieldFromInstruction_4(Insn, 16, 4);
    if (Rn == 0xF) {
      // Enforce all the rest of the instruction bits in LCTP, which
      // won't have been reliably checked based on LCTP's own tablegen
      // record, because we came to this decode by a roundabout route.
      uint32_t CanonicalLCTP = 0xF00FE001, SBZMask = 0x00300FFE;
      if ((Insn & ~SBZMask) != CanonicalLCTP)
	return MCDisassembler_Fail; // a mandatory bit is wrong: hard fail
      if (Insn != CanonicalLCTP)
	Check(&S, MCDisassembler_SoftFail); // an SBZ bit is wrong: soft fail

      MCInst_setOpcode(Inst, ARM_MVE_LCTP);
    } else {
      MCOperand_CreateReg0(Inst, ARM_LR);
      if (!Check(&S, DecoderGPRRegisterClass(
			 Inst, fieldFromInstruction_4(Insn, 16, 4), Address,
			 Decoder)))
	return MCDisassembler_Fail;
    }
    break;
  }
  return S;
}

static DecodeStatus DecodeLongShiftOperand(MCInst *Inst, unsigned Val,
					   uint64_t Address,
					   MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  if (Val == 0)
    Val = 32;

  MCOperand_CreateImm0(Inst, Val);

  return S;
}

static DecodeStatus DecodetGPROddRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       MCRegisterInfo *Decoder)
{
  if ((RegNo) + 1 > 11)
    return MCDisassembler_Fail;

  unsigned Register = GPRDecoderTable[(RegNo) + 1];
  MCOperand_CreateReg0(Inst, Register);
  return MCDisassembler_Success;
}

static DecodeStatus DecodetGPREvenRegisterClass(MCInst *Inst, unsigned RegNo,
						uint64_t Address,
						MCRegisterInfo *Decoder)
{
  if ((RegNo) > 14)
    return MCDisassembler_Fail;

  unsigned Register = GPRDecoderTable[(RegNo)];
  MCOperand_CreateReg0(Inst, Register);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeGPRwithAPSR_NZCVnospRegisterClass(
    MCInst *Inst, unsigned RegNo, uint64_t Address, MCRegisterInfo *Decoder)
{
  if (RegNo == 15) {
    MCOperand_CreateReg0(Inst, ARM_APSR_NZCV);
    return MCDisassembler_Success;
  }

  unsigned Register = GPRDecoderTable[RegNo];
  MCOperand_CreateReg0(Inst, Register);

  if (RegNo == 13)
    return MCDisassembler_SoftFail;

  return MCDisassembler_Success;
}

static DecodeStatus DecodeVSCCLRM(MCInst *Inst, unsigned Insn, uint64_t Address,
				  MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  MCOperand_CreateImm0(Inst, ARMCC_AL);
  MCOperand_CreateReg0(Inst, 0);
  if (MCInst_getOpcode(Inst) == ARM_VSCCLRMD) {
    unsigned reglist = (fieldFromInstruction_4(Insn, 1, 7) << 1) |
		       (fieldFromInstruction_4(Insn, 12, 4) << 8) |
		       (fieldFromInstruction_4(Insn, 22, 1) << 12);
    if (!Check(&S, DecodeDPRRegListOperand(Inst, reglist, Address, Decoder))) {
      return MCDisassembler_Fail;
    }
  } else {
    unsigned reglist = fieldFromInstruction_4(Insn, 0, 8) |
		       (fieldFromInstruction_4(Insn, 22, 1) << 8) |
		       (fieldFromInstruction_4(Insn, 12, 4) << 9);
    if (!Check(&S, DecodeSPRRegListOperand(Inst, reglist, Address, Decoder))) {
      return MCDisassembler_Fail;
    }
  }
  MCOperand_CreateReg0(Inst, ARM_VPR);

  return S;
}

static DecodeStatus DecodeMQPRRegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    MCRegisterInfo *Decoder)
{
  if (RegNo > 7)
    return MCDisassembler_Fail;

  unsigned Register = QPRDecoderTable[RegNo];
  MCOperand_CreateReg0(Inst, Register);
  return MCDisassembler_Success;
}

static const uint16_t QQPRDecoderTable[] = {ARM_Q0_Q1, ARM_Q1_Q2, ARM_Q2_Q3,
					    ARM_Q3_Q4, ARM_Q4_Q5, ARM_Q5_Q6,
					    ARM_Q6_Q7};

static DecodeStatus DecodeQQPRRegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    MCRegisterInfo *Decoder)
{
  if (RegNo > 6)
    return MCDisassembler_Fail;

  unsigned Register = QQPRDecoderTable[RegNo];
  MCOperand_CreateReg0(Inst, Register);
  return MCDisassembler_Success;
}

static const uint16_t QQQQPRDecoderTable[] = {ARM_Q0_Q1_Q2_Q3, ARM_Q1_Q2_Q3_Q4,
					      ARM_Q2_Q3_Q4_Q5, ARM_Q3_Q4_Q5_Q6,
					      ARM_Q4_Q5_Q6_Q7};

static DecodeStatus DecodeQQQQPRRegisterClass(MCInst *Inst, unsigned RegNo,
					      uint64_t Address,
					      MCRegisterInfo *Decoder)
{
  if (RegNo > 4)
    return MCDisassembler_Fail;

  unsigned Register = QQQQPRDecoderTable[RegNo];
  MCOperand_CreateReg0(Inst, Register);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeVPTMaskOperand(MCInst *Inst, unsigned Val,
					 uint64_t Address,
					 MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  // Parse VPT mask and encode it in the MCInst as an immediate with the same
  // format as the it_mask.  That is, from the second 'e|t' encode 'e' as 1 and
  // 't' as 0 and finish with a 1.
  unsigned Imm = 0;
  // We always start with a 't'.
  unsigned CurBit = 0;
  for (int i = 3; i >= 0; --i) {
    // If the bit we are looking at is not the same as last one, invert the
    // CurBit, if it is the same leave it as is.
    CurBit ^= (Val >> i) & 1U;

    // Encode the CurBit at the right place in the immediate.
    Imm |= (CurBit << i);

    // If we are done, finish the encoding with a 1.
    if ((Val & ~(~0U << i)) == 0) {
      Imm |= 1U << i;
      break;
    }
  }

  MCOperand_CreateImm0(Inst, Imm);

  return S;
}

static DecodeStatus DecodeVpredROperand(MCInst *Inst, unsigned RegNo,
					uint64_t Address,
					MCRegisterInfo *Decoder)
{
  // The vpred_r operand type includes an MQPR register field derived
  // from the encoding. But we don't actually want to add an operand
  // to the MCInst at this stage, because AddThumbPredicate will do it
  // later, and will infer the register number from the TIED_TO
  // constraint. So this is a deliberately empty decoder method that
  // will inhibit the auto-generated disassembly code from adding an
  // operand at all.
  return MCDisassembler_Success;
}

static DecodeStatus DecodeRestrictedIPredicateOperand(MCInst *Inst,
						      unsigned Val,
						      uint64_t Address,
						      MCRegisterInfo *Decoder)
{
  MCOperand_CreateImm0(Inst, (Val & 0x1) == 0 ? ARMCC_EQ : ARMCC_NE);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeRestrictedSPredicateOperand(MCInst *Inst,
						      unsigned Val,
						      uint64_t Address,
						      MCRegisterInfo *Decoder)
{
  unsigned Code;
  switch (Val & 0x3) {
  case 0:
    Code = ARMCC_GE;
    break;
  case 1:
    Code = ARMCC_LT;
    break;
  case 2:
    Code = ARMCC_GT;
    break;
  case 3:
    Code = ARMCC_LE;
    break;
  }
  MCOperand_CreateImm0(Inst, Code);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeRestrictedUPredicateOperand(MCInst *Inst,
						      unsigned Val,
						      uint64_t Address,
						      MCRegisterInfo *Decoder)
{
  MCOperand_CreateImm0(Inst, (Val & 0x1) == 0 ? ARMCC_HS : ARMCC_HI);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeRestrictedFPPredicateOperand(MCInst *Inst,
						       unsigned Val,
						       uint64_t Address,
						       MCRegisterInfo *Decoder)
{
  unsigned Code;
  switch (Val) {
  default:
    return MCDisassembler_Fail;
  case 0:
    Code = ARMCC_EQ;
    break;
  case 1:
    Code = ARMCC_NE;
    break;
  case 4:
    Code = ARMCC_GE;
    break;
  case 5:
    Code = ARMCC_LT;
    break;
  case 6:
    Code = ARMCC_GT;
    break;
  case 7:
    Code = ARMCC_LE;
    break;
  }

  MCOperand_CreateImm0(Inst, Code);
  return MCDisassembler_Success;
}

static DecodeStatus DecodeVCVTImmOperand(MCInst *Inst, unsigned Val,
					 uint64_t Address,
					 MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned DecodedVal = 64 - Val;

  switch (MCInst_getOpcode(Inst)) {
  case ARM_MVE_VCVTf16s16_fix:
  case ARM_MVE_VCVTs16f16_fix:
  case ARM_MVE_VCVTf16u16_fix:
  case ARM_MVE_VCVTu16f16_fix:
    if (DecodedVal > 16)
      return MCDisassembler_Fail;
    break;
  case ARM_MVE_VCVTf32s32_fix:
  case ARM_MVE_VCVTs32f32_fix:
  case ARM_MVE_VCVTf32u32_fix:
  case ARM_MVE_VCVTu32f32_fix:
    if (DecodedVal > 32)
      return MCDisassembler_Fail;
    break;
  }

  MCOperand_CreateImm0(Inst, 64 - Val);

  return S;
}

static DecodeStatus DecodeVSTRVLDR_SYSREG(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder,
					  bool Writeback)
{
  switch (MCInst_getOpcode(Inst)) {
  case ARM_VSTR_FPSCR_pre:
  case ARM_VSTR_FPSCR_NZCVQC_pre:
  case ARM_VLDR_FPSCR_pre:
  case ARM_VLDR_FPSCR_NZCVQC_pre:
  case ARM_VSTR_FPSCR_off:
  case ARM_VSTR_FPSCR_NZCVQC_off:
  case ARM_VLDR_FPSCR_off:
  case ARM_VLDR_FPSCR_NZCVQC_off:
  case ARM_VSTR_FPSCR_post:
  case ARM_VSTR_FPSCR_NZCVQC_post:
  case ARM_VLDR_FPSCR_post:
  case ARM_VLDR_FPSCR_NZCVQC_post:
    /* Ignored bit flags */

    if (!true && !true)
      return MCDisassembler_Fail;
  }

  DecodeStatus S = MCDisassembler_Success;
  //  FIXME if (unsigned Sysreg =
  //  FixedRegForVSTRVLDR_SYSREG(MCInst_getOpcode(Inst)))
  //    MCOperand_CreateReg0(Inst, Sysreg);
  unsigned Rn = fieldFromInstruction_4(Val, 16, 4);
  unsigned addr = fieldFromInstruction_4(Val, 0, 7) |
		  (fieldFromInstruction_4(Val, 23, 1) << 7) | (Rn << 8);

  if (Writeback) {
    if (!Check(&S, DecodeGPRnopcRegisterClass(Inst, Rn, Address, Decoder)))
      return MCDisassembler_Fail;
  }
  if (!Check(&S, DecodeT2AddrModeImm7s4(Inst, addr, Address, Decoder)))
    return MCDisassembler_Fail;

  MCOperand_CreateImm0(Inst, ARMCC_AL);
  MCOperand_CreateReg0(Inst, 0);

  return S;
}

static DecodeStatus DecodeMVE_MEM_1_pre(MCInst *Inst, unsigned Val,
					uint64_t Address,
					MCRegisterInfo *Decoder, int shift)
{
  unsigned Rn = fieldFromInstruction_4(Val, 16, 3);
  DecodeStatus S = MCDisassembler_Success;

  unsigned Qd = fieldFromInstruction(Val, 13, 3);
  unsigned addr = fieldFromInstruction(Val, 0, 7) |
		  (fieldFromInstruction(Val, 23, 1) << 7) | (Rn << 8);

  if (!Check(&S, DecodetGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeMQPRRegisterClass(Inst, Qd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeTAddrModeImm7(Inst, addr, Address, Decoder, shift)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeMVE_MEM_2_pre(MCInst *Inst, unsigned Val,
					uint64_t Address,
					MCRegisterInfo *Decoder, int shift)
{
  unsigned Rn = fieldFromInstruction_4(Val, 16, 4);
  DecodeStatus S = MCDisassembler_Success;

  unsigned Qd = fieldFromInstruction(Val, 13, 3);
  unsigned addr = fieldFromInstruction(Val, 0, 7) |
		  (fieldFromInstruction(Val, 23, 1) << 7) | (Rn << 8);

  if (!Check(&S, DecoderGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeMQPRRegisterClass(Inst, Qd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeT2AddrModeImm7(Inst, addr, Address, Decoder, shift, 1)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeMVE_MEM_3_pre(MCInst *Inst, unsigned Val,
					uint64_t Address,
					MCRegisterInfo *Decoder, int shift)
{
  unsigned Rn = fieldFromInstruction_4(Val, 17, 3);
  DecodeStatus S = MCDisassembler_Success;

  unsigned Qd = fieldFromInstruction(Val, 13, 3);
  unsigned addr = fieldFromInstruction(Val, 0, 7) |
		  (fieldFromInstruction(Val, 23, 1) << 7) | (Rn << 8);

  if (!Check(&S, DecodeMQPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeMQPRRegisterClass(Inst, Qd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeMveAddrModeQ(Inst, addr, Address, Decoder, shift)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodePowerTwoOperand(MCInst *Inst, unsigned Val,
					  uint64_t Address,
					  MCRegisterInfo *Decoder,
					  unsigned MinLog, unsigned MaxLog)
{
  DecodeStatus S = MCDisassembler_Success;

  if (Val < MinLog || Val > MaxLog)
    return MCDisassembler_Fail;

  MCOperand_CreateImm0(Inst, 1LL << Val);
  return S;
}

static DecodeStatus DecodeMVEPairVectorIndexOperand(MCInst *Inst, unsigned Val,
						    uint64_t Address,
						    MCRegisterInfo *Decoder,
						    unsigned start)
{
  DecodeStatus S = MCDisassembler_Success;

  MCOperand_CreateImm0(Inst, start + Val);

  return S;
}

static DecodeStatus DecodeMVEVMOVQtoDReg(MCInst *Inst, unsigned Insn,
					 uint64_t Address,
					 MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;
  unsigned Rt = fieldFromInstruction_4(Insn, 0, 4);
  unsigned Rt2 = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Qd = ((fieldFromInstruction_4(Insn, 22, 1) << 3) |
		 fieldFromInstruction_4(Insn, 13, 3));
  unsigned index = fieldFromInstruction_4(Insn, 4, 1);

  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rt, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rt2, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeMQPRRegisterClass(Inst, Qd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S,
	     DecodeMVEPairVectorIndexOperand(Inst, index, Address, Decoder, 2)))
    return MCDisassembler_Fail;
  if (!Check(&S,
	     DecodeMVEPairVectorIndexOperand(Inst, index, Address, Decoder, 0)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeMVEVMOVDRegtoQ(MCInst *Inst, unsigned Insn,
					 uint64_t Address,
					 MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;
  unsigned Rt = fieldFromInstruction_4(Insn, 0, 4);
  unsigned Rt2 = fieldFromInstruction_4(Insn, 16, 4);
  unsigned Qd = ((fieldFromInstruction_4(Insn, 22, 1) << 3) |
		 fieldFromInstruction_4(Insn, 13, 3));
  unsigned index = fieldFromInstruction_4(Insn, 4, 1);

  if (!Check(&S, DecodeMQPRRegisterClass(Inst, Qd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeMQPRRegisterClass(Inst, Qd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rt, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeGPRRegisterClass(Inst, Rt2, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S,
	     DecodeMVEPairVectorIndexOperand(Inst, index, Address, Decoder, 2)))
    return MCDisassembler_Fail;
  if (!Check(&S,
	     DecodeMVEPairVectorIndexOperand(Inst, index, Address, Decoder, 0)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeMVEOverlappingLongShift(MCInst *Inst, unsigned Insn,
						  uint64_t Address,
						  MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;

  unsigned RdaLo = fieldFromInstruction_4(Insn, 17, 3) << 1;
  unsigned RdaHi = fieldFromInstruction_4(Insn, 9, 3) << 1;
  unsigned Rm = fieldFromInstruction_4(Insn, 12, 4);

  if (RdaHi == 14) {
    // This value of RdaHi (really indicating pc, because RdaHi has to
    // be an odd-numbered register, so the low bit will be set by the
    // decode function below) indicates that we must decode as SQRSHR
    // or UQRSHL, which both have a single Rda register field with all
    // four bits.
    unsigned Rda = fieldFromInstruction_4(Insn, 16, 4);

    switch (MCInst_getOpcode(Inst)) {
    case ARM_MVE_ASRLr:
    case ARM_MVE_SQRSHRL:
      MCInst_setOpcode(Inst, ARM_MVE_SQRSHR);
      break;
    case ARM_MVE_LSLLr:
    case ARM_MVE_UQRSHLL:
      MCInst_setOpcode(Inst, ARM_MVE_UQRSHL);
      break;
    default:
      llvm_unreachable("Unexpected starting opcode!");
    }

    // Rda as output parameter
    if (!Check(&S, DecoderGPRRegisterClass(Inst, Rda, Address, Decoder)))
      return MCDisassembler_Fail;

    // Rda again as input parameter
    if (!Check(&S, DecoderGPRRegisterClass(Inst, Rda, Address, Decoder)))
      return MCDisassembler_Fail;

    // Rm, the amount to shift by
    if (!Check(&S, DecoderGPRRegisterClass(Inst, Rm, Address, Decoder)))
      return MCDisassembler_Fail;

    if (fieldFromInstruction_4(Insn, 6, 3) != 4)
      return MCDisassembler_SoftFail;

    if (Rda == Rm)
      return MCDisassembler_SoftFail;

    return S;
  }

  // Otherwise, we decode as whichever opcode our caller has already
  // put into Inst. Those all look the same:

  // RdaLo,RdaHi as output parameters
  if (!Check(&S, DecodetGPREvenRegisterClass(Inst, RdaLo, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodetGPROddRegisterClass(Inst, RdaHi, Address, Decoder)))
    return MCDisassembler_Fail;

  // RdaLo,RdaHi again as input parameters
  if (!Check(&S, DecodetGPREvenRegisterClass(Inst, RdaLo, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodetGPROddRegisterClass(Inst, RdaHi, Address, Decoder)))
    return MCDisassembler_Fail;

  // Rm, the amount to shift by
  if (!Check(&S, DecoderGPRRegisterClass(Inst, Rm, Address, Decoder)))
    return MCDisassembler_Fail;

  if (MCInst_getOpcode(Inst) == ARM_MVE_SQRSHRL ||
      MCInst_getOpcode(Inst) == ARM_MVE_UQRSHLL) {
    unsigned Saturate = fieldFromInstruction_4(Insn, 7, 1);
    // Saturate, the bit position for saturation
    MCOperand_CreateImm0(Inst, Saturate);
  }

  return S;
}

static DecodeStatus DecodeMVEVCVTt1fp(MCInst *Inst, unsigned Insn,
				      uint64_t Address, MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;
  unsigned Qd = ((fieldFromInstruction_4(Insn, 22, 1) << 3) |
		 fieldFromInstruction_4(Insn, 13, 3));
  unsigned Qm = ((fieldFromInstruction_4(Insn, 5, 1) << 3) |
		 fieldFromInstruction_4(Insn, 1, 3));
  unsigned imm6 = fieldFromInstruction_4(Insn, 16, 6);

  if (!Check(&S, DecodeMQPRRegisterClass(Inst, Qd, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeMQPRRegisterClass(Inst, Qm, Address, Decoder)))
    return MCDisassembler_Fail;
  if (!Check(&S, DecodeVCVTImmOperand(Inst, imm6, Address, Decoder)))
    return MCDisassembler_Fail;

  return S;
}

static DecodeStatus DecodeMVEVCMP(MCInst *Inst, unsigned Insn, uint64_t Address, MCRegisterInfo* Decoder,
                                   unsigned scalar, void * omitted)
{
  DecodeStatus S = MCDisassembler_Success;
  MCOperand_CreateReg0(Inst, ARM_VPR);
  unsigned Qn = fieldFromInstruction_4(Insn, 17, 3);
  if (!Check(&S, DecodeMQPRRegisterClass(Inst, Qn, Address, Decoder)))
    return MCDisassembler_Fail;

  unsigned fc;

  if (scalar) {
    fc = fieldFromInstruction_4(Insn, 12, 1) << 2 |
	 fieldFromInstruction_4(Insn, 7, 1) |
	 fieldFromInstruction_4(Insn, 5, 1) << 1;
    unsigned Rm = fieldFromInstruction_4(Insn, 0, 4);
    if (!Check(&S, DecodeGPRwithZRRegisterClass(Inst, Rm, Address, Decoder)))
      return MCDisassembler_Fail;
  } else {
    fc = fieldFromInstruction_4(Insn, 12, 1) << 2 |
	 fieldFromInstruction_4(Insn, 7, 1) |
	 fieldFromInstruction_4(Insn, 0, 1) << 1;
    unsigned Qm = fieldFromInstruction_4(Insn, 5, 1) << 4 |
		  fieldFromInstruction_4(Insn, 1, 3);
    if (!Check(&S, DecodeMQPRRegisterClass(Inst, Qm, Address, Decoder)))
      return MCDisassembler_Fail;
  }

  //  if (!Check(&S, predicate_decoder(Inst, fc, Address, Decoder)))
  //    return MCDisassembler_Fail;

  MCOperand_CreateImm0(Inst, /*ARMVCC_None*/ 0);
  MCOperand_CreateReg0(Inst, 0);
  MCOperand_CreateImm0(Inst, 0);

  return S;
}

static DecodeStatus DecodeMveVCTP(MCInst *Inst, unsigned Insn, uint64_t Address,
				  MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;
  MCOperand_CreateReg0(Inst, ARM_VPR);
  unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  if (!Check(&S, DecoderGPRRegisterClass(Inst, Rn, Address, Decoder)))
    return MCDisassembler_Fail;
  return S;
}

static DecodeStatus DecodeMVEVPNOT(MCInst *Inst, unsigned Insn,
				   uint64_t Address, MCRegisterInfo *Decoder)
{
  DecodeStatus S = MCDisassembler_Success;
  MCOperand_CreateReg0(Inst, ARM_VPR);
  MCOperand_CreateReg0(Inst, ARM_VPR);
  return S;
}

static DecodeStatus DecodeT2AddSubSPImm(MCInst *Inst, unsigned Insn,
					uint64_t Address,
					MCRegisterInfo *Decoder)
{
  const unsigned Rd = fieldFromInstruction_4(Insn, 8, 4);
  const unsigned Rn = fieldFromInstruction_4(Insn, 16, 4);
  const unsigned Imm12 = fieldFromInstruction_4(Insn, 26, 1) << 11 |
			 fieldFromInstruction_4(Insn, 12, 3) << 8 |
			 fieldFromInstruction_4(Insn, 0, 8);
  const unsigned TypeT3 = fieldFromInstruction_4(Insn, 25, 1);
  unsigned sign1 = fieldFromInstruction_4(Insn, 21, 1);
  unsigned sign2 = fieldFromInstruction_4(Insn, 23, 1);
  unsigned S = fieldFromInstruction_4(Insn, 20, 1);
  if (sign1 != sign2)
    return MCDisassembler_Fail;

  // T3 does a zext of imm12, where T2 does a ThumbExpandImm (T2SOImm)
  DecodeStatus DS = MCDisassembler_Success;
  if ((!Check(&DS,
	      DecodeGPRspRegisterClass(Inst, Rd, Address, Decoder))) || // dst
      (!Check(&DS, DecodeGPRspRegisterClass(Inst, Rn, Address, Decoder))))
    return MCDisassembler_Fail;
  if (TypeT3) {
    MCInst_setOpcode(Inst, sign1 ? ARM_t2SUBspImm12 : ARM_t2ADDspImm12);
    S = 0;
    MCOperand_CreateImm0(Inst, Imm12); // zext imm12
  } else {
    MCInst_setOpcode(Inst, sign1 ? ARM_t2SUBspImm : ARM_t2ADDspImm);
    if (!Check(&DS, DecodeT2SOImm(Inst, Imm12, Address, Decoder))) // imm12
      return MCDisassembler_Fail;
  }
  if (!Check(&DS, DecodeCCOutOperand(Inst, S, Address, Decoder))) // cc_out
    return MCDisassembler_Fail;

  MCOperand_CreateReg0(Inst, 0); // pred

  return DS;
}

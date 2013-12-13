//===-- X86Disassembler.cpp - Disassembler for x86 and x86_64 -------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is part of the X86 Disassembler.
// It contains code to translate the data produced by the decoder into
//  MCInsts.
// Documentation for the disassembler can be found in X86Disassembler.h.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <inttypes.h>	// debug
#include <string.h>

#include "../../cs_priv.h"

#include "X86Disassembler.h"
#include "X86DisassemblerDecoderCommon.h"
#include "X86DisassemblerDecoder.h"
#include "../../MCInst.h"
#include "mapping.h"

#define GET_REGINFO_ENUM
#include "X86GenRegisterInfo.inc"

#define GET_INSTRINFO_ENUM
#include "X86GenInstrInfo.inc"

struct reader_info {
	const uint8_t *code;
	uint64_t size;
	uint64_t offset;
};

// Fill-ins to make the compiler happy.  These constants are never actually
//   assigned; they are just filler to make an automatically-generated switch
//   statement work.
enum {
	X86_BX_SI = 500,
	X86_BX_DI = 501,
	X86_BP_SI = 502,
	X86_BP_DI = 503,
	X86_sib   = 504,
	X86_sib64 = 505
};

//
// Private code that translates from struct InternalInstructions to MCInsts.
//

/// translateRegister - Translates an internal register to the appropriate LLVM
///   register, and appends it as an operand to an MCInst.
///
/// @param mcInst     - The MCInst to append to.
/// @param reg        - The Reg to append.
static void translateRegister(MCInst *mcInst, Reg reg)
{
	//#define ENTRY(x) X86_x,
#define ENTRY(x) X86_##x,
	uint8_t llvmRegnums[] = {
		ALL_REGS
		0
	};
#undef ENTRY

	uint8_t llvmRegnum = llvmRegnums[reg];
	MCInst_addOperand(mcInst, MCOperand_CreateReg(llvmRegnum));
}

/// translateImmediate  - Appends an immediate operand to an MCInst.
///
/// @param mcInst       - The MCInst to append to.
/// @param immediate    - The immediate value to append.
/// @param operand      - The operand, as stored in the descriptor table.
/// @param insn         - The internal instruction.
static void translateImmediate(MCInst *mcInst, uint64_t immediate,
		const OperandSpecifier *operand, InternalInstruction *insn)
{
	OperandType type = (OperandType)operand->type;

	if (type == TYPE_RELv) {
		//isBranch = true;
		//pcrel = insn->startLocation + insn->immediateOffset + insn->immediateSize;
		switch (insn->displacementSize) {
			case 1:
				if (immediate & 0x80)
					immediate |= ~(0xffull);
				break;
			case 2:
				if (immediate & 0x8000)
					immediate |= ~(0xffffull);
				break;
			case 4:
				if (immediate & 0x80000000)
					immediate |= ~(0xffffffffull);
				break;
			case 8:
				break;
			default:
				break;
		}
	} // By default sign-extend all X86 immediates based on their encoding.
	else if (type == TYPE_IMM8 || type == TYPE_IMM16 || type == TYPE_IMM32 ||
			type == TYPE_IMM64) {
		uint32_t Opcode = MCInst_getOpcode(mcInst);
		switch (operand->encoding) {
			default:
				break;
			case ENCODING_IB:
				// Special case those X86 instructions that use the imm8 as a set of
				// bits, bit count, etc. and are not sign-extend.
				if (Opcode != X86_BLENDPSrri && Opcode != X86_BLENDPDrri &&
						Opcode != X86_PBLENDWrri && Opcode != X86_MPSADBWrri &&
						Opcode != X86_DPPSrri && Opcode != X86_DPPDrri &&
						Opcode != X86_INSERTPSrr && Opcode != X86_VBLENDPSYrri &&
						Opcode != X86_VBLENDPSYrmi && Opcode != X86_VBLENDPDYrri &&
						Opcode != X86_VBLENDPDYrmi && Opcode != X86_VPBLENDWrri &&
						Opcode != X86_VMPSADBWrri && Opcode != X86_VDPPSYrri &&
						Opcode != X86_VDPPSYrmi && Opcode != X86_VDPPDrri &&
						Opcode != X86_VINSERTPSrr && Opcode != X86_INT)
					if(immediate & 0x80)
						immediate |= ~(0xffull);
				break;
			case ENCODING_IW:
				if(immediate & 0x8000)
					immediate |= ~(0xffffull);
				break;
			case ENCODING_ID:
				if(immediate & 0x80000000)
					immediate |= ~(0xffffffffull);
				break;
			case ENCODING_IO:
				break;
		}
	}

	switch (type) {
		case TYPE_XMM32:
		case TYPE_XMM64:
		case TYPE_XMM128:
			MCInst_addOperand(mcInst, MCOperand_CreateReg(X86_XMM0 + (immediate >> 4)));
			return;
		case TYPE_XMM256:
			MCInst_addOperand(mcInst, MCOperand_CreateReg(X86_YMM0 + (immediate >> 4)));
			return;
		case TYPE_XMM512:
			MCInst_addOperand(mcInst, MCOperand_CreateReg(X86_ZMM0 + (immediate >> 4)));
			return;
		case TYPE_REL8:
			if(immediate & 0x80)
				immediate |= ~(0xffull);
			break;
		case TYPE_REL32:
		case TYPE_REL64:
			if(immediate & 0x80000000)
				immediate |= ~(0xffffffffull);
			break;
		default:
			// operand is 64 bits wide.  Do nothing.
			break;
	}

	MCInst_addOperand(mcInst, MCOperand_CreateImm(immediate));
}

/// translateRMRegister - Translates a register stored in the R/M field of the
///   ModR/M byte to its LLVM equivalent and appends it to an MCInst.
/// @param mcInst       - The MCInst to append to.
/// @param insn         - The internal instruction to extract the R/M field
///                       from.
/// @return             - 0 on success; -1 otherwise
static bool translateRMRegister(MCInst *mcInst, InternalInstruction *insn)
{
	if (insn->eaBase == EA_BASE_sib || insn->eaBase == EA_BASE_sib64) {
		//debug("A R/M register operand may not have a SIB byte");
		return true;
	}

	switch (insn->eaBase) {
		case EA_BASE_NONE:
			//debug("EA_BASE_NONE for ModR/M base");
			return true;
#define ENTRY(x) case EA_BASE_##x:
			ALL_EA_BASES
#undef ENTRY
				//debug("A R/M register operand may not have a base; "
				//      "the operand must be a register.");
				return true;
#define ENTRY(x)                                                      \
		case EA_REG_##x:                                                    \
				MCInst_addOperand(mcInst, MCOperand_CreateReg(X86_##x)); break;
			ALL_REGS
#undef ENTRY
		default:
				//debug("Unexpected EA base register");
				return true;
	}

	return false;
}

/// translateRMMemory - Translates a memory operand stored in the Mod and R/M
///   fields of an internal instruction (and possibly its SIB byte) to a memory
///   operand in LLVM's format, and appends it to an MCInst.
///
/// @param mcInst       - The MCInst to append to.
/// @param insn         - The instruction to extract Mod, R/M, and SIB fields
///                       from.
/// @return             - 0 on success; nonzero otherwise
static bool translateRMMemory(MCInst *mcInst, InternalInstruction *insn)
{
	// Addresses in an MCInst are represented as five operands:
	//   1. basereg       (register)  The R/M base, or (if there is a SIB) the 
	//                                SIB base
	//   2. scaleamount   (immediate) 1, or (if there is a SIB) the specified 
	//                                scale amount
	//   3. indexreg      (register)  x86_registerNONE, or (if there is a SIB)
	//                                the index (which is multiplied by the 
	//                                scale amount)
	//   4. displacement  (immediate) 0, or the displacement if there is one
	//   5. segmentreg    (register)  x86_registerNONE for now, but could be set
	//                                if we have segment overrides

	MCOperand *baseReg;
	MCOperand *scaleAmount;
	MCOperand *indexReg;
	MCOperand *displacement;
	MCOperand *segmentReg;

	if (insn->eaBase == EA_BASE_sib || insn->eaBase == EA_BASE_sib64) {
		if (insn->sibBase != SIB_BASE_NONE) {
			switch (insn->sibBase) {
#define ENTRY(x)                                          \
				case SIB_BASE_##x:                                  \
					baseReg = MCOperand_CreateReg(X86_##x); break;
				ALL_SIB_BASES
#undef ENTRY
				default:
					//debug("Unexpected sibBase");
					return true;
			}
		} else {
			baseReg = MCOperand_CreateReg(0);
		}

		// Check whether we are handling VSIB addressing mode for GATHER.
		// If sibIndex was set to SIB_INDEX_NONE, index offset is 4 and
		// we should use SIB_INDEX_XMM4|YMM4 for VSIB.
		// I don't see a way to get the correct IndexReg in readSIB:
		//   We can tell whether it is VSIB or SIB after instruction ID is decoded,
		//   but instruction ID may not be decoded yet when calling readSIB.
		uint32_t Opcode = MCInst_getOpcode(mcInst);
		bool IndexIs128 = (Opcode == X86_VGATHERDPDrm ||
				Opcode == X86_VGATHERDPDYrm ||
				Opcode == X86_VGATHERQPDrm ||
				Opcode == X86_VGATHERDPSrm ||
				Opcode == X86_VGATHERQPSrm ||
				Opcode == X86_VPGATHERDQrm ||
				Opcode == X86_VPGATHERDQYrm ||
				Opcode == X86_VPGATHERQQrm ||
				Opcode == X86_VPGATHERDDrm ||
				Opcode == X86_VPGATHERQDrm);
		bool IndexIs256 = (Opcode == X86_VGATHERQPDYrm ||
				Opcode == X86_VGATHERDPSYrm ||
				Opcode == X86_VGATHERQPSYrm ||
				Opcode == X86_VPGATHERQQYrm ||
				Opcode == X86_VPGATHERDDYrm ||
				Opcode == X86_VPGATHERQDYrm);
		if (IndexIs128 || IndexIs256) {
			unsigned IndexOffset = insn->sibIndex -
				(insn->addressSize == 8 ? SIB_INDEX_RAX:SIB_INDEX_EAX);
			SIBIndex IndexBase = IndexIs256 ? SIB_INDEX_YMM0 : SIB_INDEX_XMM0;
			insn->sibIndex = (SIBIndex)(IndexBase + (insn->sibIndex == SIB_INDEX_NONE ? 4 : IndexOffset));
		}

		if (insn->sibIndex != SIB_INDEX_NONE) {
			switch (insn->sibIndex) {
				default:
					//debug("Unexpected sibIndex");
					return true;
#define ENTRY(x)                                          \
				case SIB_INDEX_##x:                                 \
						indexReg = MCOperand_CreateReg(X86_##x); break;
					EA_BASES_32BIT
					EA_BASES_64BIT
					REGS_XMM
					REGS_YMM
					REGS_ZMM
#undef ENTRY
			}
		} else {
			indexReg = MCOperand_CreateReg(0);
		}

		scaleAmount = MCOperand_CreateImm(insn->sibScale);
	} else {
		switch (insn->eaBase) {
			case EA_BASE_NONE:
				if (insn->eaDisplacement == EA_DISP_NONE) {
					//debug("EA_BASE_NONE and EA_DISP_NONE for ModR/M base");
					return true;
				}
				if (insn->mode == MODE_64BIT) {
					baseReg = MCOperand_CreateReg(X86_RIP); // Section 2.2.1.6
				} else
					baseReg = MCOperand_CreateReg(0);

				indexReg = MCOperand_CreateReg(0);
				break;
			case EA_BASE_BX_SI:
				baseReg = MCOperand_CreateReg(X86_BX);
				indexReg = MCOperand_CreateReg(X86_SI);
				break;
			case EA_BASE_BX_DI:
				baseReg = MCOperand_CreateReg(X86_BX);
				indexReg = MCOperand_CreateReg(X86_DI);
				break;
			case EA_BASE_BP_SI:
				baseReg = MCOperand_CreateReg(X86_BP);
				indexReg = MCOperand_CreateReg(X86_SI);
				break;
			case EA_BASE_BP_DI:
				baseReg = MCOperand_CreateReg(X86_BP);
				indexReg = MCOperand_CreateReg(X86_DI);
				break;
			default:
				indexReg = MCOperand_CreateReg(0);
				switch (insn->eaBase) {
					default:
						//debug("Unexpected eaBase");
						return true;
						// Here, we will use the fill-ins defined above.  However,
						//   BX_SI, BX_DI, BP_SI, and BP_DI are all handled above and
						//   sib and sib64 were handled in the top-level if, so they're only
						//   placeholders to keep the compiler happy.
#define ENTRY(x)                                        \
					case EA_BASE_##x:                                 \
							baseReg = MCOperand_CreateReg(X86_##x); break; 
						ALL_EA_BASES
#undef ENTRY
#define ENTRY(x) case EA_REG_##x:
							ALL_REGS
#undef ENTRY
							//debug("A R/M memory operand may not be a register; "
							//      "the base field must be a base.");
							return true;
				}
		}

		scaleAmount = MCOperand_CreateImm(1);
	}

	displacement = MCOperand_CreateImm(insn->displacement);

	static const uint8_t segmentRegnums[SEG_OVERRIDE_max] = {
		0,        // SEG_OVERRIDE_NONE
		X86_CS,
		X86_SS,
		X86_DS,
		X86_ES,
		X86_FS,
		X86_GS
	};

	segmentReg = MCOperand_CreateReg(segmentRegnums[insn->segmentOverride]);

	MCInst_addOperand(mcInst, baseReg);
	MCInst_addOperand(mcInst, scaleAmount);
	MCInst_addOperand(mcInst, indexReg);

	MCInst_addOperand(mcInst, displacement);
	MCInst_addOperand(mcInst, segmentReg);

	return false;
}

/// translateRM - Translates an operand stored in the R/M (and possibly SIB)
///   byte of an instruction to LLVM form, and appends it to an MCInst.
///
/// @param mcInst       - The MCInst to append to.
/// @param operand      - The operand, as stored in the descriptor table.
/// @param insn         - The instruction to extract Mod, R/M, and SIB fields
///                       from.
/// @return             - 0 on success; nonzero otherwise
static bool translateRM(MCInst *mcInst, const OperandSpecifier *operand,
		InternalInstruction *insn)
{  
	switch (operand->type) {
		case TYPE_R8:
		case TYPE_R16:
		case TYPE_R32:
		case TYPE_R64:
		case TYPE_Rv:
		case TYPE_MM:
		case TYPE_MM32:
		case TYPE_MM64:
		case TYPE_XMM:
		case TYPE_XMM32:
		case TYPE_XMM64:
		case TYPE_XMM128:
		case TYPE_XMM256:
		case TYPE_XMM512:
		case TYPE_DEBUGREG:
		case TYPE_CONTROLREG:
			return translateRMRegister(mcInst, insn);
		case TYPE_M:
		case TYPE_M8:
		case TYPE_M16:
		case TYPE_M32:
		case TYPE_M64:
		case TYPE_M128:
		case TYPE_M256:
		case TYPE_M512:
		case TYPE_Mv:
		case TYPE_M32FP:
		case TYPE_M64FP:
		case TYPE_M80FP:
		case TYPE_M16INT:
		case TYPE_M32INT:
		case TYPE_M64INT:
		case TYPE_M1616:
		case TYPE_M1632:
		case TYPE_M1664:
		case TYPE_LEA:
			return translateRMMemory(mcInst, insn);
		default:
			//debug("Unexpected type for a R/M operand");
			return true;
	}
}

/// translateFPRegister - Translates a stack position on the FPU stack to its
///   LLVM form, and appends it to an MCInst.
///
/// @param mcInst       - The MCInst to append to.
/// @param stackPos     - The stack position to translate.
/// @return             - 0 on success; nonzero otherwise.
static bool translateFPRegister(MCInst *mcInst, uint8_t stackPos)
{
	if (stackPos >= 8) {
		//debug("Invalid FP stack position");
		return true;
	}

	MCInst_addOperand(mcInst, MCOperand_CreateReg(X86_ST0 + stackPos));

	return false;
}

/// translateOperand - Translates an operand stored in an internal instruction 
///   to LLVM's format and appends it to an MCInst.
///
/// @param mcInst       - The MCInst to append to.
/// @param operand      - The operand, as stored in the descriptor table.
/// @param insn         - The internal instruction.
/// @return             - false on success; true otherwise.
static bool translateOperand(MCInst *mcInst, const OperandSpecifier *operand, InternalInstruction *insn)
{
	switch (operand->encoding) {
		case ENCODING_REG:
			translateRegister(mcInst, insn->reg);
			return false;
		case ENCODING_RM:
			return translateRM(mcInst, operand, insn);
		case ENCODING_CB:
		case ENCODING_CW:
		case ENCODING_CD:
		case ENCODING_CP:
		case ENCODING_CO:
		case ENCODING_CT:
			//debug("Translation of code offsets isn't supported.");
			return true;
		case ENCODING_IB:
		case ENCODING_IW:
		case ENCODING_ID:
		case ENCODING_IO:
		case ENCODING_Iv:
		case ENCODING_Ia:
			translateImmediate(mcInst, insn->immediates[insn->numImmediatesTranslated++], operand, insn);
			return false;
		case ENCODING_RB:
		case ENCODING_RW:
		case ENCODING_RD:
		case ENCODING_RO:
			translateRegister(mcInst, insn->opcodeRegister);
			return false;
		case ENCODING_I:
			return translateFPRegister(mcInst, insn->opcodeModifier);
		case ENCODING_Rv:
			translateRegister(mcInst, insn->opcodeRegister);
			return false;
		case ENCODING_VVVV:
			translateRegister(mcInst, insn->vvvv);
			return false;
		case ENCODING_DUP:
			return translateOperand(mcInst, &insn->operands[operand->type - TYPE_DUP0], insn);
		default:
			//debug("Unhandled operand encoding during translation");
			return true;
	}
}

static bool translateInstruction(MCInst *mcInst, InternalInstruction *insn)
{
	int index;

	if (!insn->spec) {
		//debug("Instruction has no specification");
		return true;
	}

	MCInst_setOpcode(mcInst, insn->instructionID);

	// If when reading the prefix bytes we determined the overlapping 0xf2 or 0xf3
	// prefix bytes should be disassembled as xrelease and xacquire then set the
	// opcode to those instead of the rep and repne opcodes.
	if (insn->xAcquireRelease) {
		if (MCInst_getOpcode(mcInst) == X86_REP_PREFIX)
			MCInst_setOpcode(mcInst, X86_XRELEASE_PREFIX);
		else if (MCInst_getOpcode(mcInst) == X86_REPNE_PREFIX)
			MCInst_setOpcode(mcInst, X86_XACQUIRE_PREFIX);
	}

	insn->numImmediatesTranslated = 0;

	for (index = 0; index < X86_MAX_OPERANDS; ++index) {
		if (insn->operands[index].encoding != ENCODING_NONE) {
			if (translateOperand(mcInst, &insn->operands[index], insn)) {
				return true;
			}
		}
	}

	return false;
}

static int reader(const void* arg, uint8_t* byte, uint64_t address)
{
	struct reader_info *info = (void *)arg;

	if (address - info->offset >= info->size)
		// out of buffer range
		return -1;

	*byte = info->code[address - info->offset];

	return 0;
}

// copy x86 detail information from internal structure to public structure
static void update_pub_insn(cs_insn *pub, InternalInstruction *inter)
{
	int i, c;

	c = 0;
	for(i = 0; i < 0x100; i++) {
		if (inter->prefixPresent[i] > 0) {
			pub->x86.prefix[c] = inter->prefixPresent[i];
			c++;
		}
	}

	pub->x86.segment = x86_map_segment(inter->segmentOverride);

	if (inter->vexXopType > 0)
		memcpy(pub->x86.opcode, inter->vexXopPrefix, sizeof(pub->x86.opcode));
	else {
		pub->x86.opcode[0] = inter->opcode;
		pub->x86.opcode[1] = inter->twoByteEscape;
		pub->x86.opcode[2] = inter->threeByteEscape;
	}

	pub->x86.op_size = inter->operandSize;
	pub->x86.addr_size = inter->addressSize;
	pub->x86.disp_size = inter->displacementSize;
	pub->x86.imm_size = inter->immediateSize;

	pub->x86.modrm = inter->modRM;
	pub->x86.sib = inter->sib;
	pub->x86.disp = inter->displacement;

	pub->x86.sib_index = x86_map_sib_index(inter->sibIndex);
	pub->x86.sib_scale = inter->sibScale;
	pub->x86.sib_base = x86_map_sib_base(inter->sibBase);
}

// Public interface for the disassembler
bool X86_getInstruction(csh ud, const uint8_t *code, size_t code_len, MCInst *instr, uint16_t *size, uint64_t address, void *_info)
{
	cs_struct *handle = (cs_struct *)(uintptr_t)ud;
	InternalInstruction insn;
	struct reader_info info;
	int ret;
	bool result;

	info.code = code;
	info.size = code_len;
	info.offset = address;

	memset(&insn, 0, sizeof(insn));

	if (handle->mode & CS_MODE_16)
		ret = decodeInstruction(&insn,
				reader, &info,
				address,
				MODE_16BIT);
	else if (handle->mode & CS_MODE_32)
		ret = decodeInstruction(&insn,
				reader, &info,
				address,
				MODE_32BIT);
	else
		ret = decodeInstruction(&insn,
				reader, &info,
				address,
				MODE_64BIT);

	if (ret) {
		*size = insn.readerCursor - address;
		return false;
	} else {
		*size = insn.length;
		result = (!translateInstruction(instr, &insn)) ?  true : false;
		// save segment for printing hack
		instr->x86_segment = x86_map_segment(insn.segmentOverride);
		if (handle->detail)
			update_pub_insn(&instr->pub_insn, &insn);
		return result;
	}
}

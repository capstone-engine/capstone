//==-- AArch64InstPrinter.cpp - Convert AArch64 MCInst to assembly syntax --==//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This class prints an AArch64 MCInst to a .s file.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "AArch64InstPrinter.h"
#include "AArch64BaseInfo.h"
#include "../../MCInst.h"
#include "../../SStream.h"
#include "../../MCRegisterInfo.h"
#include "../../MathExtras.h"
#include "../../utils.h"

#include "mapping.h"

static char *getRegisterName(unsigned RegNo);
static void printOperand(MCInst *MI, unsigned OpNo, SStream *O);

// FIXME: make this status session's specific, not global like this
static bool doing_mem = false;
static void set_mem_access(MCInst *MI, bool status)
{
	if (MI->detail != CS_OPT_ON)
		return;

	doing_mem = status;

	if (doing_mem) {
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].type = ARM64_OP_MEM;
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].mem.base = ARM64_REG_INVALID;
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].mem.index = ARM64_REG_INVALID;
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].mem.disp = 0;
	} else {
		// done, create the next operand slot
		MI->pub_insn.arm64.op_count++;
	}
}

static int64_t unpackSignedImm(int BitWidth, uint64_t Value)
{
	//assert(!(Value & ~((1ULL << BitWidth)-1)) && "immediate not n-bit");
	if (Value & (1ULL <<  (BitWidth - 1)))
		return (int64_t)Value - (1LL << BitWidth);
	else
		return Value;
}

static void printOffsetSImm9Operand(MCInst *MI, unsigned OpNum, SStream *O)
{
	MCOperand *MOImm = MCInst_getOperand(MI, OpNum);
	int32_t Imm = unpackSignedImm(9, MCOperand_getImm(MOImm));

	if (Imm > HEX_THRESHOLD)
		SStream_concat(O, "#0x%x", Imm);
	else
		SStream_concat(O, "#%u", Imm);

	if (MI->detail) {
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].type = ARM64_OP_IMM;
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].imm = Imm;
		MI->pub_insn.arm64.op_count++;
	}
}

static void printAddrRegExtendOperand(MCInst *MI, unsigned OpNum,
		SStream *O, unsigned MemSize, unsigned RmSize)
{
	unsigned ExtImm = MCOperand_getImm(MCInst_getOperand(MI, OpNum));
	unsigned OptionHi = ExtImm >> 1;
	unsigned S = ExtImm & 1;
	bool IsLSL = OptionHi == 1 && RmSize == 64;

	char *Ext = 0;
	switch (OptionHi) {
		case 1:
			if (RmSize == 32) {
				Ext = "uxtw";
				if (MI->detail)
					MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count - 1].ext = ARM64_EXT_UXTW;
			} else {
				Ext = "lsl";
			}
			break;
		case 3:
			if (RmSize == 32) {
				Ext = "sxtw";
				if (MI->detail)
					MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count - 1].ext = ARM64_EXT_SXTW;
			} else {
				Ext = "sxtx";
				if (MI->detail)
					MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count - 1].ext = ARM64_EXT_SXTX;
			}
			break;
		default:
			break; //llvm_unreachable("Incorrect Option on load/store (reg offset)");
	}
	SStream_concat(O, Ext);

	if (S) {
		unsigned ShiftAmt = Log2_32(MemSize);
		if (ShiftAmt > HEX_THRESHOLD)
			SStream_concat(O, " #0x%x", ShiftAmt);
		else
			SStream_concat(O, " #%u", ShiftAmt);
			if (MI->detail) {
				if (doing_mem) {
					MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].shift.type = ARM64_SFT_LSL;
					MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].shift.value = ShiftAmt;
				} else {
					MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count - 1].shift.type = ARM64_SFT_LSL;
					MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count - 1].shift.value = ShiftAmt;
				}
			}
	} else if (IsLSL) {
		SStream_concat(O, " #0");
	}
}

static void printAddSubImmLSL0Operand(MCInst *MI, unsigned OpNum, SStream *O)
{
	MCOperand *Imm12Op = MCInst_getOperand(MI, OpNum);

	if (MCOperand_isImm(Imm12Op)) {
		int64_t Imm12 = MCOperand_getImm(Imm12Op);
		//assert(Imm12 >= 0 && "Invalid immediate for add/sub imm");
		if (Imm12 > HEX_THRESHOLD)
			SStream_concat(O, "#0x%"PRIx64, Imm12);
		else
			SStream_concat(O, "#%u"PRIu64, Imm12);
		if (MI->detail) {
			MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].type = ARM64_OP_IMM;
			MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].imm = Imm12;
			MI->pub_insn.arm64.op_count++;
		}
	}
}

static void printAddSubImmLSL12Operand(MCInst *MI, unsigned OpNum, SStream *O)
{
	printAddSubImmLSL0Operand(MI, OpNum, O);

	SStream_concat(O, ", lsl #12");
	if (MI->detail) {
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count - 1].shift.type = ARM64_SFT_LSL;
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count - 1].shift.value = 12;
	}
}

static void printBareImmOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	MCOperand *MO = MCInst_getOperand(MI, OpNum);
	uint64_t imm = MCOperand_getImm(MO);
	if (imm > HEX_THRESHOLD)
		SStream_concat(O, "0x%"PRIx64, imm);
	else
		SStream_concat(O, "%"PRIu64, imm);
	if (MI->detail) {
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].type = ARM64_OP_IMM;
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].imm = imm;
		MI->pub_insn.arm64.op_count++;
	}
}

static void printBFILSBOperand(MCInst *MI, unsigned OpNum,
		SStream *O, unsigned RegWidth)
{
	MCOperand *ImmROp = MCInst_getOperand(MI, OpNum);
	unsigned LSB = MCOperand_getImm(ImmROp) == 0 ? 0 : RegWidth - MCOperand_getImm(ImmROp);

	if (LSB > HEX_THRESHOLD)
		SStream_concat(O, "#0x%x", LSB);
	else
		SStream_concat(O, "#%u", LSB);
	if (MI->detail) {
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].type = ARM64_OP_IMM;
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].imm = LSB;
		MI->pub_insn.arm64.op_count++;
	}
}

static void printBFIWidthOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	MCOperand *ImmSOp = MCInst_getOperand(MI, OpNum);
	unsigned Width = MCOperand_getImm(ImmSOp) + 1;

	if (Width > HEX_THRESHOLD)
		SStream_concat(O, "#0x%x", Width);
	else
		SStream_concat(O, "#%u", Width);
}

static void printBFXWidthOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	MCOperand *ImmSOp = MCInst_getOperand(MI, OpNum);
	MCOperand *ImmROp = MCInst_getOperand(MI, OpNum - 1);

	unsigned ImmR = MCOperand_getImm(ImmROp);
	unsigned ImmS = MCOperand_getImm(ImmSOp);

	//assert(ImmS >= ImmR && "Invalid ImmR, ImmS combination for bitfield extract");

	if (ImmS - ImmR + 1 > HEX_THRESHOLD)
		SStream_concat(O, "#0x%x", (ImmS - ImmR + 1));
	else
		SStream_concat(O, "#%u", (ImmS - ImmR + 1));

	if (MI->detail) {
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].type = ARM64_OP_IMM;
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].imm = ImmS - ImmR + 1;
		MI->pub_insn.arm64.op_count++;
	}
}

static void printCRxOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	MCOperand *CRx = MCInst_getOperand(MI, OpNum);
	SStream_concat(O, "c%"PRIu64, MCOperand_getImm(CRx));

	if (MI->detail) {
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].type = ARM64_OP_CIMM;
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].imm = MCOperand_getImm(CRx);
		MI->pub_insn.arm64.op_count++;
	}
}

static void printCVTFixedPosOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	MCOperand *ScaleOp = MCInst_getOperand(MI, OpNum);

	if (64 - MCOperand_getImm(ScaleOp) > HEX_THRESHOLD)
		SStream_concat(O, "#0x%x", 64 - MCOperand_getImm(ScaleOp));
	else
		SStream_concat(O, "#%u", 64 - MCOperand_getImm(ScaleOp));
	if (MI->detail) {
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].type = ARM64_OP_IMM;
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].imm = 64 - MCOperand_getImm(ScaleOp);
		MI->pub_insn.arm64.op_count++;
	}
}

static void printFPImmOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	MCOperand *MOImm8 = MCInst_getOperand(MI, OpNum);

	//assert(MOImm8.isImm()
	//       && "Immediate operand required for floating-point immediate inst");

	uint32_t Imm8 = MCOperand_getImm(MOImm8);
	uint32_t Fraction = Imm8 & 0xf;
	uint32_t Exponent = (Imm8 >> 4) & 0x7;
	uint32_t Negative = (Imm8 >> 7) & 0x1;

	float Val = 1.0f + Fraction / 16.0f;

	// That is:
	// 000 -> 2^1,  001 -> 2^2,  010 -> 2^3,  011 -> 2^4,
	// 100 -> 2^-3, 101 -> 2^-2, 110 -> 2^-1, 111 -> 2^0
	if (Exponent & 0x4) {
		Val /= 1 << (7 - Exponent);
	} else {
		Val *= 1 << (Exponent + 1);
	}

	Val = Negative ? -Val : Val;

	//o << '#' << format("%.8f", Val);
	SStream_concat(O, "#%.8f", Val);
	if (MI->detail) {
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].type = ARM64_OP_FP;
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].fp = Val;
		MI->pub_insn.arm64.op_count++;
	}
}

static void printFPZeroOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	SStream_concat(O, "#0.0");
	if (MI->detail) {
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].type = ARM64_OP_FP;
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].fp = 0;
		MI->pub_insn.arm64.op_count++;
	}
}

static void printCondCodeOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	MCOperand *MO = MCInst_getOperand(MI, OpNum);
	SStream_concat(O, A64CondCodeToString((A64CC_CondCodes)(MCOperand_getImm(MO))));
	if (MI->detail)
		MI->pub_insn.arm64.cc = MCOperand_getImm(MO) + 1;
}

static void printLabelOperand(MCInst *MI, unsigned OpNum,
		SStream *O, unsigned field_width, unsigned scale)
{
	MCOperand *MO = MCInst_getOperand(MI, OpNum);

	if (!MCOperand_isImm(MO)) {
		printOperand(MI, OpNum, O);
		return;
	}

	// The immediate of LDR (lit) instructions is a signed 19-bit immediate, which
	// is multiplied by 4 (because all A64 instructions are 32-bits wide).
	uint64_t UImm = MCOperand_getImm(MO);
	uint64_t Sign = UImm & (1LL << (field_width - 1));
	int64_t SImm = scale * ((UImm & ~Sign) - Sign);

	// this is a relative address, so add with the address
	// of current instruction
	SImm += MI->address;

	if (MI->detail) {
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].type = ARM64_OP_IMM;
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].imm = SImm;
		MI->pub_insn.arm64.op_count++;
	}

	if (SImm > HEX_THRESHOLD)
		SStream_concat(O, "#0x%"PRIx64, SImm);
	else
		SStream_concat(O, "#%"PRIu64, SImm);
}

static void printLogicalImmOperand(MCInst *MI, unsigned OpNum,
		SStream *O, unsigned RegWidth)
{
	MCOperand *MO = MCInst_getOperand(MI, OpNum);
	uint64_t Val;
	A64Imms_isLogicalImmBits(RegWidth, MCOperand_getImm(MO), &Val);
	if (Val > HEX_THRESHOLD)
		SStream_concat(O, "#0x%"PRIx64, Val);
	else
		SStream_concat(O, "#%"PRIu64, Val);
	if (MI->detail) {
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].type = ARM64_OP_IMM;
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].imm = Val;
		MI->pub_insn.arm64.op_count++;
	}
}

static void printOffsetUImm12Operand(MCInst *MI, unsigned OpNum,
		SStream *O, int MemSize)
{
	MCOperand *MOImm = MCInst_getOperand(MI, OpNum);

	if (MCOperand_isImm(MOImm)) {
		uint32_t Imm = MCOperand_getImm(MOImm) * MemSize;

		if (Imm > HEX_THRESHOLD)
			SStream_concat(O, "#0x%x", Imm);
		else
			SStream_concat(O, "#%u", Imm);

		if (MI->detail) {
			if (doing_mem) {
				MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].mem.disp = Imm;
			} else {
				MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].type = ARM64_OP_IMM;
				MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].imm = Imm;
				MI->pub_insn.arm64.op_count++;
			}
		}
	}
}

static void printShiftOperand(MCInst *MI,  unsigned OpNum,
		SStream *O, A64SE_ShiftExtSpecifiers Shift)
{
	MCOperand *MO = MCInst_getOperand(MI, OpNum);

	// LSL #0 is not printed
	if (Shift == A64SE_LSL && MCOperand_isImm(MO) && MCOperand_getImm(MO) == 0)
		return;

	switch (Shift) {
		case A64SE_LSL: SStream_concat(O, "lsl"); break;
		case A64SE_LSR: SStream_concat(O, "lsr"); break;
		case A64SE_ASR: SStream_concat(O, "asr"); break;
		case A64SE_ROR: SStream_concat(O, "ror"); break;
		default: break; // llvm_unreachable("Invalid shift specifier in logical instruction");
	}

	unsigned int imm = MCOperand_getImm(MO);
	if (imm > HEX_THRESHOLD)
		SStream_concat(O, " #0x%x", imm);
	else
		SStream_concat(O, " #%u", imm);
	if (MI->detail) {
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count - 1].shift.type = Shift + 1;
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count - 1].shift.value = imm;
	}
}

static void printMoveWideImmOperand(MCInst *MI,  unsigned OpNum, SStream *O)
{
	MCOperand *UImm16MO = MCInst_getOperand(MI, OpNum);
	MCOperand *ShiftMO = MCInst_getOperand(MI, OpNum + 1);

	if (MCOperand_isImm(UImm16MO)) {
		uint64_t imm = MCOperand_getImm(UImm16MO);
		if (imm > HEX_THRESHOLD)
			SStream_concat(O, "#0x%"PRIx64, imm);
		else
			SStream_concat(O, "#%"PRIu64, imm);
		if (MI->detail) {
			MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].type = ARM64_OP_IMM;
			MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].imm = imm;
			MI->pub_insn.arm64.op_count++;
		}

		if (MCOperand_getImm(ShiftMO) != 0) {
			unsigned int shift = MCOperand_getImm(ShiftMO) * 16;
			if (shift > HEX_THRESHOLD)
				SStream_concat(O, ", lsl #0x%x", shift);
			else
				SStream_concat(O, ", lsl #%u", shift);
			if (MI->detail) {
				MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count - 1].shift.type = ARM64_SFT_LSL;
				MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count - 1].shift.value = shift;
			}
		}

		return;
	}
}

static void printNamedImmOperand(NamedImmMapper *Mapper,
		MCInst *MI, unsigned OpNum, SStream *O)
{
	bool ValidName;
	MCOperand *MO = MCInst_getOperand(MI, OpNum);
	char *Name = NamedImmMapper_toString(Mapper, MCOperand_getImm(MO), &ValidName);

	if (ValidName)
		SStream_concat(O, Name);
	else {
		uint64_t imm = MCOperand_getImm(MO);
		if (imm > HEX_THRESHOLD)
			SStream_concat(O, "#0x%"PRIx64, imm);
		else
			SStream_concat(O, "#%"PRIu64, imm);
		if (MI->detail) {
			MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].type = ARM64_OP_IMM;
			MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].imm = imm;
			MI->pub_insn.arm64.op_count++;
		}
	}
}

static void printSysRegOperand(SysRegMapper *Mapper,
		MCInst *MI, unsigned OpNum, SStream *O)
{
	bool ValidName;
	char Name[128];

	MCOperand *MO = MCInst_getOperand(MI, OpNum);

	SysRegMapper_toString(Mapper, MCOperand_getImm(MO), &ValidName, Name);
	if (ValidName) {
		SStream_concat(O, Name);
	}
}

#define GET_REGINFO_ENUM
#include "AArch64GenRegisterInfo.inc"

static inline bool isStackReg(unsigned RegNo)
{
	return RegNo == AArch64_XSP || RegNo == AArch64_WSP;
}

static void printRegExtendOperand(MCInst *MI, unsigned OpNum, SStream *O,
		A64SE_ShiftExtSpecifiers Ext)
{
	// FIXME: In principle TableGen should be able to detect this itself far more
	// easily. We will only accumulate more of these hacks.
	unsigned Reg0 = MCOperand_getReg(MCInst_getOperand(MI, 0));
	unsigned Reg1 = MCOperand_getReg(MCInst_getOperand(MI, 1));

	if (isStackReg(Reg0) || isStackReg(Reg1)) {
		A64SE_ShiftExtSpecifiers LSLEquiv;

		if (Reg0 == AArch64_XSP || Reg1 == AArch64_XSP)
			LSLEquiv = A64SE_UXTX;
		else
			LSLEquiv = A64SE_UXTW;

		if (Ext == LSLEquiv) {
			unsigned int shift = MCOperand_getImm(MCInst_getOperand(MI, OpNum));
			if (shift > HEX_THRESHOLD)
				SStream_concat(O, "lsl #0x%x", shift);
			else
				SStream_concat(O, "lsl #%u", shift);
			if (MI->detail) {
				MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count - 1].shift.type = ARM64_SFT_LSL;
				MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count - 1].shift.value = shift;
				MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count - 1].ext = Ext - 4;
			}
			return;
		}
	}

	switch (Ext) {
		case A64SE_UXTB: SStream_concat(O, "uxtb"); break;
		case A64SE_UXTH: SStream_concat(O, "uxth"); break;
		case A64SE_UXTW: SStream_concat(O, "uxtw"); break;
		case A64SE_UXTX: SStream_concat(O, "uxtx"); break;
		case A64SE_SXTB: SStream_concat(O, "sxtb"); break;
		case A64SE_SXTH: SStream_concat(O, "sxth"); break;
		case A64SE_SXTW: SStream_concat(O, "sxtw"); break;
		case A64SE_SXTX: SStream_concat(O, "sxtx"); break;
		default: break; //llvm_unreachable("Unexpected shift type for printing");
	}

	if (MI->detail)
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count - 1].ext = Ext - 4;
	MCOperand *MO = MCInst_getOperand(MI, OpNum);
	if (MCOperand_getImm(MO) != 0) {
		unsigned int shift = MCOperand_getImm(MO);
		if (shift > HEX_THRESHOLD)
			SStream_concat(O, " #0x%x", shift);
		else
			SStream_concat(O, " #%u", shift);
		if (MI->detail) {
			MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count - 1].shift.type = ARM64_SFT_LSL;
			MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count - 1].shift.value = shift;
		}
	}
}

static void printSImm7ScaledOperand(MCInst *MI, unsigned OpNum,
		SStream *O, int MemScale)
{
	MCOperand *MOImm = MCInst_getOperand(MI, OpNum);
	int32_t Imm = unpackSignedImm(7, MCOperand_getImm(MOImm));

	if (Imm * MemScale > HEX_THRESHOLD)
		SStream_concat(O, "#0x%x", Imm * MemScale);
	else
		SStream_concat(O, "#%u", Imm * MemScale);
	if (MI->detail) {
		if (doing_mem) {
			MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].mem.disp = Imm * MemScale;
		} else {
			MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].type = ARM64_OP_IMM;
			MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].imm = Imm * MemScale;
			MI->pub_insn.arm64.op_count++;
		}
	}
}

// TODO: handle this Vd register??
static void printVPRRegister(MCInst *MI, unsigned OpNo, SStream *O)
{
	unsigned Reg = MCOperand_getReg(MCInst_getOperand(MI, OpNo));
	char *Name = strdup(getRegisterName(Reg));
	Name[0] = 'v';
	SStream_concat(O, "%s", Name);
	free(Name);
	if (MI->detail) {
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].type = ARM64_OP_REG;
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].reg = Reg;
		MI->pub_insn.arm64.op_count++;
	}
}

static void printOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	MCOperand *Op = MCInst_getOperand(MI, OpNo);
	if (MCOperand_isReg(Op)) {
		unsigned Reg = MCOperand_getReg(Op);
		SStream_concat(O, getRegisterName(Reg));
		if (MI->detail) {
			if (doing_mem) {
				if (MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].mem.base == ARM64_REG_INVALID) {
					MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].mem.base = Reg;
				} else {
					MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].mem.index = Reg;
				}
			} else {
				MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].type = ARM64_OP_REG;
				MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].reg = Reg;
				MI->pub_insn.arm64.op_count++;
			}
		}
	} else if (MCOperand_isImm(Op)) {
		int64_t imm = MCOperand_getImm(Op);
		if (imm > HEX_THRESHOLD)
			SStream_concat(O, "#0x%"PRIx64, imm);
		else
			SStream_concat(O, "#%"PRIu64, imm);
		if (MI->detail) {
			if (doing_mem) {
				MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].mem.disp = imm;
			} else {
				MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].type = ARM64_OP_IMM;
				MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].imm = imm;
				MI->pub_insn.arm64.op_count++;
			}
		}
	}
}

#define GET_INSTRINFO_ENUM
#include "AArch64GenInstrInfo.inc"

static void printNeonMovImmShiftOperand(MCInst *MI, unsigned OpNum,
		SStream *O, A64SE_ShiftExtSpecifiers Ext, bool isHalf)
{
	MCOperand *MO = MCInst_getOperand(MI, OpNum);

	//assert(MO.isImm() &&
	//       "Immediate operand required for Neon vector immediate inst.");

	bool IsLSL = false;
	if (Ext == A64SE_LSL)
		IsLSL = true;
	else if (Ext != A64SE_MSL) {
		//llvm_unreachable("Invalid shift specifier in movi instruction");
	}

	int64_t Imm = MCOperand_getImm(MO);

	// MSL and LSLH accepts encoded shift amount 0 or 1.
	if ((!IsLSL || (IsLSL && isHalf)) && Imm != 0 && Imm != 1) {
		// llvm_unreachable("Invalid shift amount in movi instruction");
	}

	// LSH accepts encoded shift amount 0, 1, 2 or 3.
	if (IsLSL && (Imm < 0 || Imm > 3)) {
		//llvm_unreachable("Invalid shift amount in movi instruction");
	}

	// Print shift amount as multiple of 8 with MSL encoded shift amount
	// 0 and 1 printed as 8 and 16.
	if (!IsLSL)
		Imm++;
	Imm *= 8;

	// LSL #0 is not printed
	if (IsLSL) {
		if (Imm == 0)
			return;
		SStream_concat(O, ", lsl");
		if (MI->detail)
			MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count - 1].shift.type = ARM64_SFT_LSL;
	} else {
		SStream_concat(O, ", msl");
		if (MI->detail)
			MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count - 1].shift.type = ARM64_SFT_MSL;
	}

	if (Imm > HEX_THRESHOLD)
		SStream_concat(O, " #0x%"PRIx64, Imm);
	else
		SStream_concat(O, " #%"PRIu64, Imm);
	if (MI->detail)
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count - 1].shift.value = Imm;
}

static void printNeonUImm0Operand(MCInst *MI, unsigned OpNum, SStream *O)
{
	SStream_concat(O, "#0");
	// FIXME: vector ZERO
	if (MI->detail) {
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].type = ARM64_OP_IMM;
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].imm = 0;
		MI->pub_insn.arm64.op_count++;
	}
}

static void printUImmHexOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	MCOperand *MOUImm = MCInst_getOperand(MI, OpNum);

	//assert(MOUImm.isImm() &&
	//       "Immediate operand required for Neon vector immediate inst.");

	unsigned Imm = MCOperand_getImm(MOUImm);

	if (Imm > HEX_THRESHOLD)
		SStream_concat(O, "#0x%x", Imm);
	else
		SStream_concat(O, "#%u", Imm);
	if (MI->detail) {
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].type = ARM64_OP_IMM;
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].imm = Imm;
		MI->pub_insn.arm64.op_count++;
	}
}

static void printUImmBareOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	MCOperand *MOUImm = MCInst_getOperand(MI, OpNum);

	//assert(MOUImm.isImm()
	//		&& "Immediate operand required for Neon vector immediate inst.");

	unsigned Imm = MCOperand_getImm(MOUImm);
	if (Imm > HEX_THRESHOLD)
		SStream_concat(O, "0x%x", Imm);
	else
		SStream_concat(O, "%u", Imm);

	if (MI->detail) {
		if (doing_mem) {
			MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].mem.disp = Imm;
		} else {
			// FIXME: never has false branch??
		}
	}
}

static void printNeonUImm64MaskOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	MCOperand *MOUImm8 = MCInst_getOperand(MI, OpNum);

	//assert(MOUImm8.isImm() &&
	//       "Immediate operand required for Neon vector immediate bytemask inst.");

	uint32_t UImm8 = MCOperand_getImm(MOUImm8);
	uint64_t Mask = 0;

	// Replicates 0x00 or 0xff byte in a 64-bit vector
	unsigned ByteNum;
	for (ByteNum = 0; ByteNum < 8; ++ByteNum) {
		if ((UImm8 >> ByteNum) & 1)
			Mask |= (uint64_t)0xff << (8 * ByteNum);
	}

	if (Mask > HEX_THRESHOLD)
		SStream_concat(O, "#0x%"PRIx64, Mask);
	else
		SStream_concat(O, "#%"PRIu64, Mask);
	if (MI->detail) {
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].type = ARM64_OP_IMM;
		MI->pub_insn.arm64.operands[MI->pub_insn.arm64.op_count].imm = Mask;
		MI->pub_insn.arm64.op_count++;
	}
}

static void printMRSOperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	printSysRegOperand(&AArch64_MRSMapper, MI, OpNum, O);
}

static void printMSROperand(MCInst *MI, unsigned OpNum, SStream *O)
{
	printSysRegOperand(&AArch64_MSRMapper, MI, OpNum, O);
}

// If Count > 1, there are two valid kinds of vector list:
//   (1) {Vn.layout, Vn+1.layout, ... , Vm.layout}
//   (2) {Vn.layout - Vm.layout}
// We choose the first kind as output.
static void printVectorList(MCInst *MI, unsigned OpNum,
		SStream *O, MCRegisterInfo *MRI, A64Layout_VectorLayout Layout, unsigned Count)
{
	//assert(Count >= 1 && Count <= 4 && "Invalid Number of Vectors");

	unsigned Reg = MCOperand_getReg(MCInst_getOperand(MI, OpNum));
	const char *LayoutStr = A64VectorLayoutToString(Layout);
	SStream_concat(O, "{");
	if (Count > 1) { // Print sub registers separately
		bool IsVec64 = (Layout < A64Layout_VL_16B);
		unsigned SubRegIdx = IsVec64 ? AArch64_dsub_0 : AArch64_qsub_0;
		unsigned I;
		for (I = 0; I < Count; I++) {
			char *Name = strdup(getRegisterName(MCRegisterInfo_getSubReg(MRI, Reg, SubRegIdx++)));
			Name[0] = 'v';
			SStream_concat(O, "%s%s", Name, LayoutStr);
			if (I != Count - 1)
				SStream_concat(O, ", ");
			free(Name);
		}
	} else { // Print the register directly when NumVecs is 1.
		char *Name = strdup(getRegisterName(Reg));
		Name[0] = 'v';
		SStream_concat(O, "%s%s", Name, LayoutStr);
		free(Name);
	}
	SStream_concat(O, "}");
}

#define PRINT_ALIAS_INSTR
#include "AArch64GenAsmWriter.inc"

void AArch64_post_printer(csh handle, cs_insn *pub_insn, char *insn_asm)
{
	// check if this insn requests write-back
	if (strrchr(insn_asm, '!') != NULL)
		pub_insn->arm64.writeback = true;
}

void AArch64_printInst(MCInst *MI, SStream *O, void *Info)
{
	if (printAliasInstr(MI, O, Info)) {
		char *mnem = strdup(O->buffer);
		char *tab = strchr(mnem, '\t');
		if (tab) {
			*tab = '\0';
		}
		// reflect the new insn name (alias) in the opcode
		unsigned int id = AArch64_map_insn(mnem);
		MCInst_setOpcode(MI, AArch64_get_insn_id2(id));
		MCInst_setOpcodePub(MI, id);
		free(mnem);
	} else
		AArch64InstPrinter_printInstruction(MI, O, Info);
}


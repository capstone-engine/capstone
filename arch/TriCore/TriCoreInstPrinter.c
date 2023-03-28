//===- TriCoreInstPrinter.cpp - Convert TriCore MCInst to assembly syntax -===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This class prints an TriCore MCInst to a .s file.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifdef CAPSTONE_HAS_TRICORE

#include <platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../MCInst.h"
#include "../../MCRegisterInfo.h"
#include "../../MathExtras.h"
#include "../../SStream.h"
#include "../../utils.h"
#include "TriCoreInstPrinter.h"
#include "TriCoreMapping.h"

static const char *getRegisterName(unsigned RegNo);

static void printInstruction(MCInst *, uint64_t, SStream *);

static void printOperand(MCInst *MI, int OpNum, SStream *O);

void TriCore_post_printer(csh ud, cs_insn *insn, char *insn_asm, MCInst *mci) {
	/*
	   if (((cs_struct *)ud)->detail != CS_OPT_ON)
	   return;
	 */
}

#define GET_INSTRINFO_ENUM

#include "TriCoreGenInstrInfo.inc"

#define GET_REGINFO_ENUM

#include "TriCoreGenRegisterInfo.inc"

static void printOperand(MCInst *MI, int OpNum, SStream *O) {
	MCOperand *Op;
	if (OpNum >= MI->size)
		return;

	Op = MCInst_getOperand(MI, OpNum);

	if (MCOperand_isReg(Op)) {
		unsigned reg = MCOperand_getReg(Op);
		SStream_concat(O, "%%%s", getRegisterName(reg));

		if (MI->csh->detail) {
			MI->flat_insn->detail->tricore
					.operands[MI->flat_insn->detail->tricore.op_count]
					.type = TRICORE_OP_REG;
			MI->flat_insn->detail->tricore
					.operands[MI->flat_insn->detail->tricore.op_count]
					.reg = (uint8_t) TriCore_map_register(reg);
			MI->flat_insn->detail->tricore.op_count++;
		}
	} else if (MCOperand_isImm(Op)) {
		int64_t Imm = MCOperand_getImm(Op);

		if (Imm >= 0) {
			if (Imm > HEX_THRESHOLD)
				SStream_concat(O, "0x%" PRIx64, Imm);
			else
				SStream_concat(O, "%" PRIu64, Imm);
		} else {
			if (Imm < -HEX_THRESHOLD)
				SStream_concat(O, "-0x%" PRIx64, -Imm);
			else
				SStream_concat(O, "-%" PRIu64, -Imm);
		}

		if (MI->csh->detail) {
			MI->flat_insn->detail->tricore
					.operands[MI->flat_insn->detail->tricore.op_count]
					.type = TRICORE_OP_IMM;
			MI->flat_insn->detail->tricore
					.operands[MI->flat_insn->detail->tricore.op_count]
					.imm = Imm;
			MI->flat_insn->detail->tricore.op_count++;
		}
	}
}

static void printPairAddrRegsOperand(MCInst *MI, unsigned OpNum, SStream *O,
                                     MCRegisterInfo *MRI) {
	unsigned Reg = MCOperand_getReg(MCInst_getOperand(MI, OpNum));
	SStream_concat0(O, "[");
	SStream_concat(
			O, "%%%s",
			getRegisterName(MCRegisterInfo_getSubReg(MRI, Reg, TriCore_subreg_even)));
	if (MI->csh->detail) {
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.type = TRICORE_OP_REG;
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.reg = (uint8_t) TriCore_map_register(
				MCRegisterInfo_getSubReg(MRI, Reg, TriCore_subreg_even));
		MI->flat_insn->detail->tricore.op_count++;
	}
	SStream_concat0(O, "/");
	SStream_concat(
			O, "%%%s",
			getRegisterName(MCRegisterInfo_getSubReg(MRI, Reg, TriCore_subreg_odd)));
	if (MI->csh->detail) {
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.type = TRICORE_OP_REG;
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.reg = (uint8_t) TriCore_map_register(
				MCRegisterInfo_getSubReg(MRI, Reg, TriCore_subreg_odd));
		MI->flat_insn->detail->tricore.op_count++;
	}
	SStream_concat0(O, "]");
}

static void printSExtImm(MCInst *MI, int OpNum, SStream *O) {
	MCOperand *MO = MCInst_getOperand(MI, OpNum);
	if (MCOperand_isImm(MO)) {
		int64_t imm = MCOperand_getImm(MO);
		if (imm >= 0) {
			if (imm > HEX_THRESHOLD)
				SStream_concat(O, "0x%x", imm);
			else
				SStream_concat(O, "%u", imm);
		} else {
			if (imm < -HEX_THRESHOLD)
				SStream_concat(O, "-0x%x", -imm);
			else
				SStream_concat(O, "-%u", -imm);
		}
		if (MI->csh->detail) {
			MI->flat_insn->detail->tricore
					.operands[MI->flat_insn->detail->tricore.op_count]
					.type = TRICORE_OP_IMM;
			MI->flat_insn->detail->tricore
					.operands[MI->flat_insn->detail->tricore.op_count]
					.imm = (unsigned short int) imm;
			MI->flat_insn->detail->tricore.op_count++;
		}
	} else
		printOperand(MI, OpNum, O);
}

static inline void fill_tricore_imm(MCInst *MI, int64_t imm) {
	if (MI->csh->detail) {
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.type = TRICORE_OP_IMM;
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.imm = (int) imm;
		MI->flat_insn->detail->tricore.op_count++;
	}
}

static void sign_ext(MCInst *MI, int OpNum, SStream *O, unsigned n) {
	MCOperand *MO = MCInst_getOperand(MI, OpNum);
	if (MCOperand_isImm(MO)) {
		int64_t imm = MCOperand_getImm(MO);
		int64_t sign = imm >> (n - 1) & 0x1;
		for (unsigned i = n; i < 64; ++i) {
			imm = (imm & ~(1LL << i)) | (sign << i);
		}
		if (imm >= 0) {
			if (imm > HEX_THRESHOLD)
				SStream_concat(O, "0x%x", imm);
			else
				SStream_concat(O, "%u", imm);
		} else {
			if (imm < -HEX_THRESHOLD)
				SStream_concat(O, "-0x%x", -imm);
			else
				SStream_concat(O, "-%u", -imm);
		}
		fill_tricore_imm(MI, imm);
	} else
		printOperand(MI, OpNum, O);
}

static void off4_fixup(MCInst *MI, int64_t *off4) {
	switch (MCInst_getOpcode(MI)) {
		case TriCore_LD_A_slro:
		case TriCore_LD_A_sro:
		case TriCore_LD_W_slro:
		case TriCore_LD_W_sro:
		case TriCore_ST_A_sro:
		case TriCore_ST_A_ssro:
		case TriCore_ST_W_sro:
		case TriCore_ST_W_ssro: {
			*off4 *= 4;
			break;
		}
		case TriCore_LD_H_sro:
		case TriCore_LD_H_slro:
		case TriCore_ST_H_sro:
		case TriCore_ST_H_ssro: {
			*off4 *= 2;
			break;
		}
	}
}

static void zero_ext(MCInst *MI, int OpNum, SStream *O, unsigned n) {
	MCOperand *MO = MCInst_getOperand(MI, OpNum);
	if (MCOperand_isImm(MO)) {
		int64_t imm = MCOperand_getImm(MO);
		for (unsigned i = n + 1; i < 64; ++i) {
			imm &= ~(1LL << i);
		}
		if (n == 4) {
			off4_fixup(MI, &imm);
		}

		if (imm >= 0) {
			if (imm > HEX_THRESHOLD)
				SStream_concat(O, "0x%x", imm);
			else
				SStream_concat(O, "%u", imm);
		} else {
			if (imm < -HEX_THRESHOLD)
				SStream_concat(O, "-0x%x", -imm);
			else
				SStream_concat(O, "-%u", -imm);
		}
		fill_tricore_imm(MI, imm);
	} else
		printOperand(MI, OpNum, O);
}

#define printSExtImm_(n)                                                       \
  static void printSExtImm_ ##n(MCInst *MI, int OpNum, SStream *O)              \
  {                                                                            \
    sign_ext(MI, OpNum, O, n);                                                \
  }

printSExtImm_(24)

printSExtImm_(16)

printSExtImm_(10)

printSExtImm_(9)

printSExtImm_(8)

printSExtImm_(4)

static inline void printZExtImm(MCInst *MI, int OpNum, SStream *O) {
	MCOperand *MO = MCInst_getOperand(MI, OpNum);
	if (MCOperand_isImm(MO)) {
		uint64_t imm = (unsigned) MCOperand_getImm(MO);
		if (imm > HEX_THRESHOLD)
			SStream_concat(O, "0x%x", imm);
		else
			SStream_concat(O, "%u", imm);
		if (MI->csh->detail) {
			MI->flat_insn->detail->tricore
					.operands[MI->flat_insn->detail->tricore.op_count]
					.type = TRICORE_OP_IMM;
			MI->flat_insn->detail->tricore
					.operands[MI->flat_insn->detail->tricore.op_count]
					.imm = imm;
			MI->flat_insn->detail->tricore.op_count++;
		}
	} else
		printOperand(MI, OpNum, O);
}

#define printZExtImm_(n)                                                       \
  static void printZExtImm_ ##n(MCInst *MI, int OpNum, SStream *O)              \
  {                                                                            \
    zero_ext(MI, OpNum, O, n);                                                \
  }

printZExtImm_(16)

printZExtImm_(8)

printZExtImm_(4)

printZExtImm_(2)

printZExtImm_(1)

static void printOff18Imm(MCInst *MI, int OpNum, SStream *O) {
	MCOperand *MO = MCInst_getOperand(MI, OpNum);
	if (MCOperand_isImm(MO)) {
		uint32_t imm = (uint32_t) MCOperand_getImm(MO);
		imm = ((imm & 0x3C000)<< 14) | (imm & 0x3fff);
		SStream_concat(O, "0x%x", imm);
		fill_tricore_imm(MI, imm);
	} else
		printOperand(MI, OpNum, O);
}

static void printPCRelImmOperand(MCInst *MI, int OpNum, SStream *O) {
	MCOperand *Op = MCInst_getOperand(MI, OpNum);
	if (MCOperand_isImm(Op)) {
		unsigned imm = (unsigned) MCOperand_getImm(Op);
		if (imm > HEX_THRESHOLD)
			SStream_concat(O, "0x%x", imm);
		else
			SStream_concat(O, "%u", imm);
	} else
		printOperand(MI, OpNum, O);
}

// Print a 'bo' operand which is an addressing mode
// Base+Offset
static void printAddrBO(MCInst *MI, int OpNum, SStream *O) {

	unsigned Base = MCOperand_getReg(MCInst_getOperand(MI, OpNum));
	uint64_t Disp = (uint64_t) MCOperand_getImm(MCInst_getOperand(MI, OpNum + 1));

	SStream_concat(O, "[");
	SStream_concat(O, "%%%s", getRegisterName(Base));
	SStream_concat(O, "] ");

	if (Disp > HEX_THRESHOLD)
		SStream_concat(O, "0x%" PRIx64, Disp);
	else
		SStream_concat(O, "%" PRIu64, Disp);

	if (MI->csh->detail) {
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.type = TRICORE_OP_MEM;
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.mem.base = (uint8_t) TriCore_map_register(Base);
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.mem.disp = Disp;
		MI->flat_insn->detail->tricore.op_count++;
	}
}

// Print a 'preincbo' operand which is an addressing mode
// Pre-increment Base+Offset
static void printAddrPreIncBO(MCInst *MI, int OpNum, SStream *O) {

	unsigned Base = MCOperand_getReg(MCInst_getOperand(MI, OpNum));
	uint64_t Disp = (uint64_t) MCOperand_getImm(MCInst_getOperand(MI, OpNum + 1));

	SStream_concat(O, "[+");
	SStream_concat(O, "%%%s", getRegisterName(Base));
	SStream_concat(O, "] ");

	if (Disp > HEX_THRESHOLD)
		SStream_concat(O, "0x%" PRIx64, Disp);
	else
		SStream_concat(O, "%" PRIu64, Disp);

	if (MI->csh->detail) {
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.type = TRICORE_OP_MEM;
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.mem.base = (uint8_t) TriCore_map_register(Base);
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.mem.disp = Disp;
		MI->flat_insn->detail->tricore.op_count++;
	}
}

// Print a 'postincbo' operand which is an addressing mode
// Post-increment Base+Offset
static void printAddrPostIncBO(MCInst *MI, int OpNum, SStream *O) {

	unsigned Base = MCOperand_getReg(MCInst_getOperand(MI, OpNum));
	uint64_t Disp = (uint64_t) MCOperand_getImm(MCInst_getOperand(MI, OpNum + 1));

	SStream_concat(O, "[");
	SStream_concat(O, "%%%s", getRegisterName(Base));
	SStream_concat(O, "+] ");

	if (Disp > HEX_THRESHOLD)
		SStream_concat(O, "0x%" PRIx64, Disp);
	else
		SStream_concat(O, "%" PRIu64, Disp);

	if (MI->csh->detail) {
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.type = TRICORE_OP_MEM;
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.mem.base = (uint8_t) TriCore_map_register(Base);
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.mem.disp = Disp;
		MI->flat_insn->detail->tricore.op_count++;
	}
}

// Print a 'circbo' operand which is an addressing mode
// Circular Base+Offset
static void printAddrCircBO(MCInst *MI, unsigned OpNum, SStream *O,
                            MCRegisterInfo *MRI) {
	unsigned Base = MCOperand_getReg(MCInst_getOperand(MI, OpNum));
	uint64_t Disp = (uint64_t) MCOperand_getImm(MCInst_getOperand(MI, OpNum + 1));

	SStream_concat0(O, "[");
	SStream_concat(O, "%%%s",
	               getRegisterName(
			               MCRegisterInfo_getSubReg(MRI, Base, TriCore_subreg_even)));
	if (MI->csh->detail) {
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.type = TRICORE_OP_REG;
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.reg = (uint8_t) TriCore_map_register(
				MCRegisterInfo_getSubReg(MRI, Base, TriCore_subreg_even));
		MI->flat_insn->detail->tricore.op_count++;
	}
	SStream_concat0(O, "/");
	SStream_concat(
			O, "%%%s",
			getRegisterName(MCRegisterInfo_getSubReg(MRI, Base, TriCore_subreg_odd)));
	if (MI->csh->detail) {
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.type = TRICORE_OP_REG;
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.reg = (uint8_t) TriCore_map_register(
				MCRegisterInfo_getSubReg(MRI, Base, TriCore_subreg_odd));
		MI->flat_insn->detail->tricore.op_count++;
	}
	SStream_concat0(O, "+c] ");

	if (Disp > HEX_THRESHOLD)
		SStream_concat(O, "0x%" PRIx64, Disp);
	else
		SStream_concat(O, "%" PRIu64, Disp);

	if (MI->csh->detail) {
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.type = TRICORE_OP_MEM;
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.mem.base = (uint8_t) TriCore_map_register(Base);
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.mem.disp = Disp;
		MI->flat_insn->detail->tricore.op_count++;
	}
}

// Print a 'bitrevbo' operand which is an addressing mode
// Bit-Reverse Base+Offset
static void printAddrBitRevBO(MCInst *MI, unsigned OpNum, SStream *O,
                              MCRegisterInfo *MRI) {

	unsigned Base = MCOperand_getReg(MCInst_getOperand(MI, OpNum));

	SStream_concat0(O, "[");
	SStream_concat(O, "%%%s",
	               getRegisterName(
			               MCRegisterInfo_getSubReg(MRI, Base, TriCore_subreg_even)));
	if (MI->csh->detail) {
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.type = TRICORE_OP_REG;
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.reg = (uint8_t) TriCore_map_register(
				MCRegisterInfo_getSubReg(MRI, Base, TriCore_subreg_even));
		MI->flat_insn->detail->tricore.op_count++;
	}
	SStream_concat0(O, "/");
	SStream_concat(
			O, "%%%s",
			getRegisterName(MCRegisterInfo_getSubReg(MRI, Base, TriCore_subreg_odd)));
	if (MI->csh->detail) {
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.type = TRICORE_OP_REG;
		MI->flat_insn->detail->tricore
				.operands[MI->flat_insn->detail->tricore.op_count]
				.reg = (uint8_t) TriCore_map_register(
				MCRegisterInfo_getSubReg(MRI, Base, TriCore_subreg_odd));
		MI->flat_insn->detail->tricore.op_count++;
	}
	SStream_concat0(O, "+r]");
}

/// Returned by getMnemonic() of the AsmPrinters.
typedef struct {
	const char *first; // Menmonic
	uint64_t second;   // Bits
} MnemonicBitsInfo;

void set_mem_access(MCInst *MI, unsigned int access) {
	// TODO: TriCore
}

#define PRINT_ALIAS_INSTR

#include "TriCoreGenAsmWriter.inc"

void TriCore_printInst(MCInst *MI, SStream *O, void *Info) {
	printInstruction(MI, MI->address, O);
}

#endif

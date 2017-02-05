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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <platform.h>

#include "TriCoreInstPrinter.h"
#include "../../MCInst.h"
#include "../../utils.h"
#include "../../SStream.h"
#include "../../MCRegisterInfo.h"
#include "../../MathExtras.h"
#include "TriCoreMapping.h"

static char *getRegisterName(unsigned RegNo);
static void printInstruction(MCInst *MI, SStream *O, MCRegisterInfo *MRI);
static void printOperand(MCInst *MI, int OpNum, SStream *O);

void TriCore_post_printer(csh ud, cs_insn *insn, char *insn_asm, MCInst *mci)
{
	/*
	   if (((cs_struct *)ud)->detail != CS_OPT_ON)
	   return;
	 */
}

#define GET_INSTRINFO_ENUM
#include "TriCoreGenInstrInfo.inc"

#define GET_REGINFO_ENUM
#include "TriCoreGenRegisterInfo.inc"

static void printOperand(MCInst *MI, int OpNum, SStream *O)
{
	MCOperand *Op;
	if (OpNum >= MI->size)
		return;

	Op = MCInst_getOperand(MI, OpNum);

	if (MCOperand_isReg(Op)) {
		unsigned reg = MCOperand_getReg(Op);
		SStream_concat(O, "%%%s", getRegisterName(reg));

		if (MI->csh->detail) {
			MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].type = TRICORE_OP_REG;
			MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].reg = (uint8_t)TriCore_map_register(reg);
			MI->flat_insn->detail->tricore.op_count++;
		}
	} else if (MCOperand_isImm(Op)) {
		int64_t Imm = MCOperand_getImm(Op);

		if (Imm >= 0) {
			if (Imm > HEX_THRESHOLD)
				SStream_concat(O, "0x%"PRIx64, Imm);
			else
				SStream_concat(O, "%"PRIu64, Imm);
		} else {
			if (Imm < -HEX_THRESHOLD)
				SStream_concat(O, "-0x%"PRIx64, -Imm);
			else
				SStream_concat(O, "-%"PRIu64, -Imm);
		}

		if (MI->csh->detail) {
			MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].type = TRICORE_OP_IMM;
			MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].imm = Imm;
			MI->flat_insn->detail->tricore.op_count++;
		}
	}
}

static void printPairAddrRegsOperand(MCInst *MI, unsigned OpNum, SStream *O,
		MCRegisterInfo *MRI)
{
	unsigned Reg = MCOperand_getReg(MCInst_getOperand(MI, OpNum));
	SStream_concat0(O, "[");
	SStream_concat(O, "%%%s", getRegisterName(MCRegisterInfo_getSubReg(MRI, Reg, TriCore_subreg_even)));
	if (MI->csh->detail) {
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].type = TRICORE_OP_REG;
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].reg = (uint8_t)TriCore_map_register(MCRegisterInfo_getSubReg(MRI, Reg, TriCore_subreg_even));
		MI->flat_insn->detail->tricore.op_count++;
	}
	SStream_concat0(O, "/");
	SStream_concat(O, "%%%s", getRegisterName(MCRegisterInfo_getSubReg(MRI, Reg, TriCore_subreg_odd)));
	if (MI->csh->detail) {
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].type = TRICORE_OP_REG;
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].reg = (uint8_t)TriCore_map_register(MCRegisterInfo_getSubReg(MRI, Reg, TriCore_subreg_odd));
		MI->flat_insn->detail->tricore.op_count++;
	}
	SStream_concat0(O, "]");
}

static void printSExtImm(MCInst *MI, int OpNum, SStream *O)
{
	MCOperand *MO = MCInst_getOperand(MI, OpNum);
	if (MCOperand_isImm(MO)) {
		int64_t imm = MCOperand_getImm(MO);
		if (imm >= 0) {
			if (imm > HEX_THRESHOLD)
				SStream_concat(O, "0x%x", (unsigned short int)imm);
			else
				SStream_concat(O, "%u", (unsigned short int)imm);
		} else {
			if (imm < -HEX_THRESHOLD)
				SStream_concat(O, "-0x%x", (short int)-imm);
			else
				SStream_concat(O, "-%u", (short int)-imm);
		}
		if (MI->csh->detail) {
			MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].type = TRICORE_OP_IMM;
			MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].imm = (unsigned short int)imm;
			MI->flat_insn->detail->tricore.op_count++;
		}
	} else
		printOperand(MI, OpNum, O);
}

static void printZExtImm(MCInst *MI, int OpNum, SStream *O)
{
	MCOperand *MO = MCInst_getOperand(MI, OpNum);
	if (MCOperand_isImm(MO)) {
		unsigned imm = (unsigned)MCOperand_getImm(MO);
		if (imm > HEX_THRESHOLD)
			SStream_concat(O, "0x%x", imm);
		else
			SStream_concat(O, "%u", imm);
		if (MI->csh->detail) {
			MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].type = TRICORE_OP_IMM;
			MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].imm = imm;
			MI->flat_insn->detail->tricore.op_count++;
		}
	} else
		printOperand(MI, OpNum, O);
}

static void printPCRelImmOperand(MCInst *MI, int OpNum, SStream *O) {
	MCOperand *Op = MCInst_getOperand(MI, OpNum);
	if (MCOperand_isImm(Op)) {
		unsigned imm = (unsigned)MCOperand_getImm(Op);
		if (imm > HEX_THRESHOLD)
			SStream_concat(O, "0x%x", imm);
		else
			SStream_concat(O, "%u", imm);
	}
	else
		printOperand(MI, OpNum, O);
}

// Print a 'bo' operand which is an addressing mode
// Base+Offset
static void printAddrBO(MCInst *MI, int OpNum, SStream *O) {

	unsigned Base = MCOperand_getReg(MCInst_getOperand(MI, OpNum));
	uint64_t Disp = (uint64_t)MCOperand_getImm(MCInst_getOperand(MI, OpNum + 1));

	SStream_concat(O, "[");
	SStream_concat(O, "%%%s", getRegisterName(Base));
	SStream_concat(O, "] ");

	if (Disp > HEX_THRESHOLD)
		SStream_concat(O, "0x%"PRIx64, Disp);
	else
		SStream_concat(O, "%"PRIu64, Disp);

	if (MI->csh->detail) {
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].type = TRICORE_OP_MEM;
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].mem.base = (uint8_t)TriCore_map_register(Base);
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].mem.disp = Disp;
		MI->flat_insn->detail->tricore.op_count++;
	}
}

// Print a 'preincbo' operand which is an addressing mode
// Pre-increment Base+Offset
static void printAddrPreIncBO(MCInst *MI, int OpNum, SStream *O) {

	unsigned Base = MCOperand_getReg(MCInst_getOperand(MI, OpNum));
	uint64_t Disp = (uint64_t)MCOperand_getImm(MCInst_getOperand(MI, OpNum + 1));

	SStream_concat(O, "[+");
	SStream_concat(O, "%%%s", getRegisterName(Base));
	SStream_concat(O, "] ");

	if (Disp > HEX_THRESHOLD)
		SStream_concat(O, "0x%"PRIx64, Disp);
	else
		SStream_concat(O, "%"PRIu64, Disp);

	if (MI->csh->detail) {
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].type = TRICORE_OP_MEM;
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].mem.base = (uint8_t)TriCore_map_register(Base);
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].mem.disp = Disp;
		MI->flat_insn->detail->tricore.op_count++;
	}
}

// Print a 'postincbo' operand which is an addressing mode
// Post-increment Base+Offset
static void printAddrPostIncBO(MCInst *MI, int OpNum, SStream *O) {

	unsigned Base = MCOperand_getReg(MCInst_getOperand(MI, OpNum));
	uint64_t Disp = (uint64_t)MCOperand_getImm(MCInst_getOperand(MI, OpNum + 1));

	SStream_concat(O, "[");
	SStream_concat(O, "%%%s", getRegisterName(Base));
	SStream_concat(O, "+] ");

	if (Disp > HEX_THRESHOLD)
		SStream_concat(O, "0x%"PRIx64, Disp);
	else
		SStream_concat(O, "%"PRIu64, Disp);

	if (MI->csh->detail) {
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].type = TRICORE_OP_MEM;
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].mem.base = (uint8_t)TriCore_map_register(Base);
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].mem.disp = Disp;
		MI->flat_insn->detail->tricore.op_count++;
	}
}

// Print a 'circbo' operand which is an addressing mode
// Circular Base+Offset
static void printAddrCircBO(MCInst *MI, unsigned OpNum, SStream *O,
		MCRegisterInfo *MRI)
{
	unsigned Base = MCOperand_getReg(MCInst_getOperand(MI, OpNum));
	uint64_t Disp = (uint64_t)MCOperand_getImm(MCInst_getOperand(MI, OpNum + 1));

	SStream_concat0(O, "[");
	SStream_concat(O, "%%%s", getRegisterName(MCRegisterInfo_getSubReg(MRI, Base, TriCore_subreg_even)));
	if (MI->csh->detail) {
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].type = TRICORE_OP_REG;
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].reg = (uint8_t)TriCore_map_register(MCRegisterInfo_getSubReg(MRI, Base, TriCore_subreg_even));
		MI->flat_insn->detail->tricore.op_count++;
	}
	SStream_concat0(O, "/");
	SStream_concat(O, "%%%s", getRegisterName(MCRegisterInfo_getSubReg(MRI, Base, TriCore_subreg_odd)));
	if (MI->csh->detail) {
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].type = TRICORE_OP_REG;
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].reg = (uint8_t)TriCore_map_register(MCRegisterInfo_getSubReg(MRI, Base, TriCore_subreg_odd));
		MI->flat_insn->detail->tricore.op_count++;
	}
	SStream_concat0(O, "+c] ");

	if (Disp > HEX_THRESHOLD)
		SStream_concat(O, "0x%"PRIx64, Disp);
	else
		SStream_concat(O, "%"PRIu64, Disp);

	if (MI->csh->detail) {
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].type = TRICORE_OP_MEM;
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].mem.base = (uint8_t)TriCore_map_register(Base);
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].mem.disp = Disp;
		MI->flat_insn->detail->tricore.op_count++;
	}
}

// Print a 'bitrevbo' operand which is an addressing mode
// Bit-Reverse Base+Offset
static void printAddrBitRevBO(MCInst *MI, unsigned OpNum, SStream *O,
		MCRegisterInfo *MRI)
{

	unsigned Base = MCOperand_getReg(MCInst_getOperand(MI, OpNum));

	SStream_concat0(O, "[");
	SStream_concat(O, "%%%s", getRegisterName(MCRegisterInfo_getSubReg(MRI, Base, TriCore_subreg_even)));
	if (MI->csh->detail) {
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].type = TRICORE_OP_REG;
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].reg = (uint8_t)TriCore_map_register(MCRegisterInfo_getSubReg(MRI, Base, TriCore_subreg_even));
		MI->flat_insn->detail->tricore.op_count++;
	}
	SStream_concat0(O, "/");
	SStream_concat(O, "%%%s", getRegisterName(MCRegisterInfo_getSubReg(MRI, Base, TriCore_subreg_odd)));
	if (MI->csh->detail) {
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].type = TRICORE_OP_REG;
		MI->flat_insn->detail->tricore.operands[MI->flat_insn->detail->tricore.op_count].reg = (uint8_t)TriCore_map_register(MCRegisterInfo_getSubReg(MRI, Base, TriCore_subreg_odd));
		MI->flat_insn->detail->tricore.op_count++;
	}
	SStream_concat0(O, "+r]");
}

#define PRINT_ALIAS_INSTR
#include "TriCoreGenAsmWriter.inc"

void TriCore_printInst(MCInst *MI, SStream *O, void *Info)
{
	MCRegisterInfo *MRI = (MCRegisterInfo *)Info;

	unsigned Opcode = MCInst_getOpcode(MI), i;

	switch(Opcode) {
		// Combine 2 AddrRegs from disassember into a PairAddrRegs to match
		// with instr def. load/store require even/odd AddrReg pair. To enforce
		// this constraint, a single PairAddrRegs reg operand is used in the .td
		// file to replace the two AddrRegs. However, when decoding them, the two
		// AddrRegs cannot be automatically expressed as a PairAddrRegs, so we
		// have to manually merge them.
		// FIXME: We would really like to be able to tablegen'erate this.
		case TriCore_LD_DAabs:
		case TriCore_LD_DAbo:
		case TriCore_LD_DApreincbo:
		case TriCore_LD_DApostincbo:
		case TriCore_ST_Bcircbo:
		case TriCore_ST_Hcircbo:
		case TriCore_ST_Wcircbo:
		case TriCore_ST_Dcircbo:
		case TriCore_ST_Qcircbo:
		case TriCore_ST_Acircbo:
		case TriCore_ST_Bbitrevbo:
		case TriCore_ST_Hbitrevbo:
		case TriCore_ST_Wbitrevbo:
		case TriCore_ST_Dbitrevbo:
		case TriCore_ST_Qbitrevbo:
		case TriCore_ST_Abitrevbo: {
			MCRegisterClass* MRC = MCRegisterInfo_getRegClass(MRI, TriCore_AddrRegsRegClassID);

			unsigned Reg = MCOperand_getReg(MCInst_getOperand(MI, 0));
			if (MCRegisterClass_contains(MRC, Reg)) {
				MCInst NewMI;

				MCInst_Init(&NewMI);
				MCInst_setOpcode(&NewMI, Opcode);

				MCOperand_CreateReg0(&NewMI, MCRegisterInfo_getMatchingSuperReg(MRI, Reg, TriCore_subreg_even,
							MCRegisterInfo_getRegClass(MRI, TriCore_PairAddrRegsRegClassID)));

				// Copy the rest operands into NewMI.
				for(i = 2; i < MCInst_getNumOperands(MI); ++i)
					MCInst_addOperand2(&NewMI, MCInst_getOperand(MI, i));

				printInstruction(&NewMI, O, MRI);
				return;
			}
		}
		case TriCore_ST_DAabs:
		case TriCore_ST_DAbo:
		case TriCore_ST_DApreincbo:
		case TriCore_ST_DApostincbo:
		case TriCore_LD_Bcircbo:
		case TriCore_LD_BUcircbo:
		case TriCore_LD_Hcircbo:
		case TriCore_LD_HUcircbo:
		case TriCore_LD_Wcircbo:
		case TriCore_LD_Dcircbo:
		case TriCore_LD_Acircbo:
		case TriCore_LD_Bbitrevbo:
		case TriCore_LD_BUbitrevbo:
		case TriCore_LD_Hbitrevbo:
		case TriCore_LD_HUbitrevbo:
		case TriCore_LD_Wbitrevbo:
		case TriCore_LD_Dbitrevbo:
		case TriCore_LD_Abitrevbo: {
			MCRegisterClass* MRC = MCRegisterInfo_getRegClass(MRI, TriCore_AddrRegsRegClassID);

			unsigned Reg = MCOperand_getReg(MCInst_getOperand(MI, 1));
			if (MCRegisterClass_contains(MRC, Reg)) {
				MCInst NewMI;

				MCInst_Init(&NewMI);
				MCInst_setOpcode(&NewMI, Opcode);

				MCInst_addOperand2(&NewMI, MCInst_getOperand(MI, 0));

				MCOperand_CreateReg0(&NewMI, MCRegisterInfo_getMatchingSuperReg(MRI, Reg, TriCore_subreg_even,
							MCRegisterInfo_getRegClass(MRI, TriCore_PairAddrRegsRegClassID)));

				// Copy the rest operands into NewMI.
				for(i = 3; i < MCInst_getNumOperands(MI); ++i)
					MCInst_addOperand2(&NewMI, MCInst_getOperand(MI, i));

				printInstruction(&NewMI, O, MRI);
				return;
			}
		}
		case TriCore_LD_DAcircbo:
		case TriCore_ST_DAcircbo:
		case TriCore_LD_DAbitrevbo:
		case TriCore_ST_DAbitrevbo: {
			MCRegisterClass* MRC = MCRegisterInfo_getRegClass(MRI, TriCore_AddrRegsRegClassID);

			unsigned Reg1 = MCOperand_getReg(MCInst_getOperand(MI, 0));
			unsigned Reg2 = MCOperand_getReg(MCInst_getOperand(MI, 2));
			if (MCRegisterClass_contains(MRC, Reg2)) {
				MCInst NewMI;

				MCInst_Init(&NewMI);
				MCInst_setOpcode(&NewMI, Opcode);

				MCOperand_CreateReg0(&NewMI, MCRegisterInfo_getMatchingSuperReg(MRI, Reg1, TriCore_subreg_even,
							MCRegisterInfo_getRegClass(MRI, TriCore_PairAddrRegsRegClassID)));

				MCOperand_CreateReg0(&NewMI, MCRegisterInfo_getMatchingSuperReg(MRI, Reg2, TriCore_subreg_even,
							MCRegisterInfo_getRegClass(MRI, TriCore_PairAddrRegsRegClassID)));

				// Copy the rest operands into NewMI.
				for(i = 4; i < MCInst_getNumOperands(MI); ++i)
					MCInst_addOperand2(&NewMI, MCInst_getOperand(MI, i));

				printInstruction(&NewMI, O, MRI);
				return;
			}
		}
	}
	printInstruction(MI, O, Info);
}

#endif

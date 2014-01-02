//===-- MipsInstPrinter.cpp - Convert Mips MCInst to assembly syntax ------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This class prints an Mips MCInst to a .s file.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>	// debug
#include <string.h>

#include "MipsInstPrinter.h"
#include "../../MCInst.h"
#include "../../cs_priv.h"
#include "../../SStream.h"
#include "../../MCRegisterInfo.h"
#include "../../utils.h"
#include "mapping.h"

#include "MipsInstPrinter.h"

static bool printAliasInstr(MCInst *MI, SStream *O, void *info);
static bool printAlias(MCInst *MI, SStream *OS);

// These enumeration declarations were originally in MipsInstrInfo.h but
// had to be moved here to avoid circular dependencies between
// LLVMMipsCodeGen and LLVMMipsAsmPrinter.

// Mips Condition Codes
typedef enum Mips_CondCode {
	// To be used with float branch True
	Mips_FCOND_F,
	Mips_FCOND_UN,
	Mips_FCOND_OEQ,
	Mips_FCOND_UEQ,
	Mips_FCOND_OLT,
	Mips_FCOND_ULT,
	Mips_FCOND_OLE,
	Mips_FCOND_ULE,
	Mips_FCOND_SF,
	Mips_FCOND_NGLE,
	Mips_FCOND_SEQ,
	Mips_FCOND_NGL,
	Mips_FCOND_LT,
	Mips_FCOND_NGE,
	Mips_FCOND_LE,
	Mips_FCOND_NGT,

	// To be used with float branch False
	// This conditions have the same mnemonic as the
	// above ones, but are used with a branch False;
	Mips_FCOND_T,
	Mips_FCOND_OR,
	Mips_FCOND_UNE,
	Mips_FCOND_ONE,
	Mips_FCOND_UGE,
	Mips_FCOND_OGE,
	Mips_FCOND_UGT,
	Mips_FCOND_OGT,
	Mips_FCOND_ST,
	Mips_FCOND_GLE,
	Mips_FCOND_SNE,
	Mips_FCOND_GL,
	Mips_FCOND_NLT,
	Mips_FCOND_GE,
	Mips_FCOND_NLE,
	Mips_FCOND_GT
} Mips_CondCode;

#define GET_INSTRINFO_ENUM
#include "MipsGenInstrInfo.inc"

static char *getRegisterName(unsigned RegNo);
static void printInstruction(MCInst *MI, SStream *O);

static void set_mem_access(MCInst *MI, bool status)
{
	MI->csh->doing_mem = status;

	if (MI->csh->detail != CS_OPT_ON)
		return;

	if (status) {
		MI->flat_insn.mips.operands[MI->flat_insn.mips.op_count].type = MIPS_OP_MEM;
		MI->flat_insn.mips.operands[MI->flat_insn.mips.op_count].mem.base = MIPS_REG_INVALID;
		MI->flat_insn.mips.operands[MI->flat_insn.mips.op_count].mem.disp = 0;
	} else {
		// done, create the next operand slot
		MI->flat_insn.mips.op_count++;
	}
}

static bool isReg(MCInst *MI, unsigned OpNo, unsigned R)
{
	return (MCOperand_isReg(MCInst_getOperand(MI, OpNo)) &&
			MCOperand_getReg(MCInst_getOperand(MI, OpNo)) == R);
}

static char* MipsFCCToString(Mips_CondCode CC)
{
	switch (CC) {
		default: return 0;	// never reach
		case Mips_FCOND_F:
		case Mips_FCOND_T:   return "f";
		case Mips_FCOND_UN:
		case Mips_FCOND_OR:  return "un";
		case Mips_FCOND_OEQ:
		case Mips_FCOND_UNE: return "eq";
		case Mips_FCOND_UEQ:
		case Mips_FCOND_ONE: return "ueq";
		case Mips_FCOND_OLT:
		case Mips_FCOND_UGE: return "olt";
		case Mips_FCOND_ULT:
		case Mips_FCOND_OGE: return "ult";
		case Mips_FCOND_OLE:
		case Mips_FCOND_UGT: return "ole";
		case Mips_FCOND_ULE:
		case Mips_FCOND_OGT: return "ule";
		case Mips_FCOND_SF:
		case Mips_FCOND_ST:  return "sf";
		case Mips_FCOND_NGLE:
		case Mips_FCOND_GLE: return "ngle";
		case Mips_FCOND_SEQ:
		case Mips_FCOND_SNE: return "seq";
		case Mips_FCOND_NGL:
		case Mips_FCOND_GL:  return "ngl";
		case Mips_FCOND_LT:
		case Mips_FCOND_NLT: return "lt";
		case Mips_FCOND_NGE:
		case Mips_FCOND_GE:  return "nge";
		case Mips_FCOND_LE:
		case Mips_FCOND_NLE: return "le";
		case Mips_FCOND_NGT:
		case Mips_FCOND_GT:  return "ngt";
	}
}

static void printRegName(SStream *OS, unsigned RegNo)
{
	SStream_concat(OS, "$%s", getRegisterName(RegNo));
}

void Mips_printInst(MCInst *MI, SStream *O, void *info)
{
	switch (MCInst_getOpcode(MI)) {
		default: break;
		case Mips_RDHWR:
		case Mips_RDHWR64:
			SStream_concat(O, ".set\tpush\n");
			SStream_concat(O, ".set\tmips32r2\n");
			break;
	}

	// Try to print any aliases first.
	if (!printAliasInstr(MI, O, info) && !printAlias(MI, O))
		printInstruction(MI, O);
	else {
		// fixup instruction id due to the change in alias instruction
		char *mnem = strdup(O->buffer);
		char *tab = strchr(mnem, '\t');
		if (tab)
			*tab = '\0';

		// reflect the new insn name (alias) in the opcode
		unsigned id = Mips_map_insn(mnem);
		MCInst_setOpcode(MI, Mips_get_insn_id2(id));
		MCInst_setOpcodePub(MI, id);
		free(mnem);
	}

	switch (MCInst_getOpcode(MI)) {
		default: break;
		case Mips_RDHWR:
		case Mips_RDHWR64:
			SStream_concat(O, "\n.set\tpop");
			break;
	}
}

static void printOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	MCOperand *Op = MCInst_getOperand(MI, OpNo);
	if (MCOperand_isReg(Op)) {
		unsigned int reg = MCOperand_getReg(Op);
		printRegName(O, reg);
		reg = Mips_map_register(reg);
		if (MI->csh->detail) {
			if (MI->csh->doing_mem) {
				MI->flat_insn.mips.operands[MI->flat_insn.mips.op_count].mem.base = reg;
			} else {
				MI->flat_insn.mips.operands[MI->flat_insn.mips.op_count].type = MIPS_OP_REG;
				MI->flat_insn.mips.operands[MI->flat_insn.mips.op_count].reg = reg;
				MI->flat_insn.mips.op_count++;
			}
		}
	}

	if (MCOperand_isImm(Op)) {
		int64_t imm = MCOperand_getImm(Op);
		if (MI->csh->doing_mem) {
			if (imm) {	// only print Imm offset if it is not 0
				if (imm >= 0) {
					if (imm > HEX_THRESHOLD)
						SStream_concat(O, "0x%"PRIx64, imm);
					else
						SStream_concat(O, "%"PRIu64, imm);
				} else {
					if (imm <= -HEX_THRESHOLD)
						SStream_concat(O, "-0x%"PRIx64, -imm);
					else
						SStream_concat(O, "-%"PRIu64, -imm);
				}
			}
			if (MI->csh->detail)
				MI->flat_insn.mips.operands[MI->flat_insn.mips.op_count].mem.disp = imm;
		} else {
			if (imm >= 0) {
				if (imm > HEX_THRESHOLD)
					SStream_concat(O, "0x%"PRIx64, imm);
				else
					SStream_concat(O, "%"PRIu64, imm);
			} else {
				if (imm <= -HEX_THRESHOLD)
					SStream_concat(O, "-0x%"PRIx64, -imm);
				else
					SStream_concat(O, "-%"PRIu64, -imm);
			}

			if (MI->csh->detail) {
				MI->flat_insn.mips.operands[MI->flat_insn.mips.op_count].type = MIPS_OP_IMM;
				MI->flat_insn.mips.operands[MI->flat_insn.mips.op_count].imm = imm;
				MI->flat_insn.mips.op_count++;
			}
		}
	}
}

static void printUnsignedImm(MCInst *MI, int opNum, SStream *O)
{
	MCOperand *MO = MCInst_getOperand(MI, opNum);
	if (MCOperand_isImm(MO)) {
		int64_t imm = MCOperand_getImm(MO);
		if (imm >= 0) {
			if (imm > HEX_THRESHOLD)
				SStream_concat(O, "0x%x", (unsigned short int)imm);
			else
				SStream_concat(O, "%u", (unsigned short int)imm);
		} else {
			if (imm <= -HEX_THRESHOLD)
				SStream_concat(O, "-0x%x", (short int)-imm);
			else
				SStream_concat(O, "-%u", (short int)-imm);
		}
		if (MI->csh->detail) {
			MI->flat_insn.mips.operands[MI->flat_insn.mips.op_count].type = MIPS_OP_IMM;
			MI->flat_insn.mips.operands[MI->flat_insn.mips.op_count].imm = (unsigned short int)imm;
			MI->flat_insn.mips.op_count++;
		}
	} else
		printOperand(MI, opNum, O);
}

static void printUnsignedImm8(MCInst *MI, int opNum, SStream *O)
{
	MCOperand *MO = MCInst_getOperand(MI, opNum);
	if (MCOperand_isImm(MO)) {
		uint8_t imm = (uint8_t)MCOperand_getImm(MO);
		if (imm > HEX_THRESHOLD)
			SStream_concat(O, "0x%x", imm);
		else
			SStream_concat(O, "%u", imm);
		if (MI->csh->detail) {
			MI->flat_insn.mips.operands[MI->flat_insn.mips.op_count].type = MIPS_OP_IMM;
			MI->flat_insn.mips.operands[MI->flat_insn.mips.op_count].imm = imm;
			MI->flat_insn.mips.op_count++;
		}
	} else
		printOperand(MI, opNum, O);
}

static void printMemOperand(MCInst *MI, int opNum, SStream *O)
{
	// Load/Store memory operands -- imm($reg)
	// If PIC target the target is loaded as the
	// pattern lw $25,%call16($28)
	set_mem_access(MI, true);
	printOperand(MI, opNum + 1, O);
	SStream_concat(O, "(");
	printOperand(MI, opNum, O);
	SStream_concat(O, ")");
	set_mem_access(MI, false);
}

// TODO???
static void printMemOperandEA(MCInst *MI, int opNum, SStream *O)
{
	// when using stack locations for not load/store instructions
	// print the same way as all normal 3 operand instructions.
	printOperand(MI, opNum, O);
	SStream_concat(O, ", ");
	printOperand(MI, opNum + 1, O);
	return;
}

static void printFCCOperand(MCInst *MI, int opNum, SStream *O)
{
	MCOperand *MO = MCInst_getOperand(MI, opNum);
	SStream_concat(O, MipsFCCToString((Mips_CondCode)MCOperand_getImm(MO)));
}

static bool printAlias1(char *Str, MCInst *MI, unsigned OpNo, SStream *OS)
{
	SStream_concat(OS, "%s\t", Str);
	printOperand(MI, OpNo, OS);
	return true;
}

static bool printAlias2(char *Str, MCInst *MI,
		unsigned OpNo0, unsigned OpNo1, SStream *OS)
{
	printAlias1(Str, MI, OpNo0, OS);
	SStream_concat(OS, ", ");
	printOperand(MI, OpNo1, OS);
	return true;
}

#define GET_REGINFO_ENUM
#include "MipsGenRegisterInfo.inc"

static bool printAlias(MCInst *MI, SStream *OS)
{
	switch (MCInst_getOpcode(MI)) {
		case Mips_BEQ:
			// beq $zero, $zero, $L2 => b $L2
			// beq $r0, $zero, $L2 => beqz $r0, $L2
			return (isReg(MI, 0, Mips_ZERO) && isReg(MI, 1, Mips_ZERO) &&
					printAlias1("b", MI, 2, OS)) ||
				(isReg(MI, 1, Mips_ZERO) && printAlias2("beqz", MI, 0, 2, OS));
		case Mips_BEQ64:
			// beq $r0, $zero, $L2 => beqz $r0, $L2
			return isReg(MI, 1, Mips_ZERO_64) && printAlias2("beqz", MI, 0, 2, OS);
		case Mips_BNE:
			// bne $r0, $zero, $L2 => bnez $r0, $L2
			return isReg(MI, 1, Mips_ZERO) && printAlias2("bnez", MI, 0, 2, OS);
		case Mips_BNE64:
			// bne $r0, $zero, $L2 => bnez $r0, $L2
			return isReg(MI, 1, Mips_ZERO_64) && printAlias2("bnez", MI, 0, 2, OS);
		case Mips_BGEZAL:
			// bgezal $zero, $L1 => bal $L1
			return isReg(MI, 0, Mips_ZERO) && printAlias1("bal", MI, 1, OS);
		case Mips_BC1T:
			// bc1t $fcc0, $L1 => bc1t $L1
			return isReg(MI, 0, Mips_FCC0) && printAlias1("bc1t", MI, 1, OS);
		case Mips_BC1F:
			// bc1f $fcc0, $L1 => bc1f $L1
			return isReg(MI, 0, Mips_FCC0) && printAlias1("bc1f", MI, 1, OS);
		case Mips_JALR:
			// jalr $ra, $r1 => jalr $r1
			return isReg(MI, 0, Mips_RA) && printAlias1("jalr", MI, 1, OS);
		case Mips_JALR64:
			// jalr $ra, $r1 => jalr $r1
			return isReg(MI, 0, Mips_RA_64) && printAlias1("jalr", MI, 1, OS);
		case Mips_NOR:
		case Mips_NOR_MM:
			// nor $r0, $r1, $zero => not $r0, $r1
			return isReg(MI, 2, Mips_ZERO) && printAlias2("not", MI, 0, 1, OS);
		case Mips_NOR64:
			// nor $r0, $r1, $zero => not $r0, $r1
			return isReg(MI, 2, Mips_ZERO_64) && printAlias2("not", MI, 0, 1, OS);
		case Mips_OR:
			// or $r0, $r1, $zero => move $r0, $r1
			return isReg(MI, 2, Mips_ZERO) && printAlias2("move", MI, 0, 1, OS);
		default: return false;
	}
}

#define PRINT_ALIAS_INSTR
#include "MipsGenAsmWriter.inc"


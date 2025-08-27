/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/*    Rot127 <unisono@quyllur.org> 2022-2023 */
/* Automatically translated source file from LLVM. */

/* LLVM-commit: <commit> */
/* LLVM-tag: <tag> */

/* Only small edits allowed. */
/* For multiple similar edits, please create a Patch for the translator. */

/* Capstone's C++ file translator: */
/* https://github.com/capstone-engine/capstone/tree/next/suite/auto-sync */

//===-- MipsInstPrinter.cpp - Convert Mips MCInst to assembly syntax ------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This class prints an Mips MCInst to a .s file.
//
//===----------------------------------------------------------------------===//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "MipsMapping.h"
#include "MipsInstPrinter.h"

#define GET_SUBTARGETINFO_ENUM
#include "MipsGenSubtargetInfo.inc"

#define GET_INSTRINFO_ENUM
#include "MipsGenInstrInfo.inc"

#define GET_REGINFO_ENUM
#include "MipsGenRegisterInfo.inc"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

#define DEBUG_TYPE "asm-printer"

#define PRINT_ALIAS_INSTR
#include "MipsGenAsmWriter.inc"

static bool isReg(const MCInst *MI, unsigned OpNo, unsigned R)
{
	return MCOperand_getReg(MCInst_getOperand((MCInst *)MI, (OpNo))) == R;
}

static const char *MipsFCCToString(Mips_CondCode CC)
{
	switch (CC) {
	case Mips_FCOND_F:
	case Mips_FCOND_T:
		return "f";
	case Mips_FCOND_UN:
	case Mips_FCOND_OR:
		return "un";
	case Mips_FCOND_OEQ:
	case Mips_FCOND_UNE:
		return "eq";
	case Mips_FCOND_UEQ:
	case Mips_FCOND_ONE:
		return "ueq";
	case Mips_FCOND_OLT:
	case Mips_FCOND_UGE:
		return "olt";
	case Mips_FCOND_ULT:
	case Mips_FCOND_OGE:
		return "ult";
	case Mips_FCOND_OLE:
	case Mips_FCOND_UGT:
		return "ole";
	case Mips_FCOND_ULE:
	case Mips_FCOND_OGT:
		return "ule";
	case Mips_FCOND_SF:
	case Mips_FCOND_ST:
		return "sf";
	case Mips_FCOND_NGLE:
	case Mips_FCOND_GLE:
		return "ngle";
	case Mips_FCOND_SEQ:
	case Mips_FCOND_SNE:
		return "seq";
	case Mips_FCOND_NGL:
	case Mips_FCOND_GL:
		return "ngl";
	case Mips_FCOND_LT:
	case Mips_FCOND_NLT:
		return "lt";
	case Mips_FCOND_NGE:
	case Mips_FCOND_GE:
		return "nge";
	case Mips_FCOND_LE:
	case Mips_FCOND_NLE:
		return "le";
	case Mips_FCOND_NGT:
	case Mips_FCOND_GT:
		return "ngt";
	}
	CS_ASSERT_RET_VAL(0 && "Impossible condition code!", NULL);
	return "";
}

const char *Mips_LLVM_getRegisterName(unsigned RegNo, bool noRegName);

static void printRegName(MCInst *MI, SStream *OS, MCRegister Reg)
{
	int syntax_opt = MI->csh->syntax;
	if (!(syntax_opt & CS_OPT_SYNTAX_NO_DOLLAR)) {
		SStream_concat1(OS, '$');
	}
	SStream_concat0(OS, Mips_LLVM_getRegisterName(
				    Reg, syntax_opt & CS_OPT_SYNTAX_NOREGNAME));
}

static void patch_cs_printer(MCInst *MI, SStream *O)
{
	// replace '# 16 bit inst' to empty.
	SStream_replc(O, '#', 0);
	SStream_trimls(O);

	if (MI->csh->syntax & CS_OPT_SYNTAX_NO_DOLLAR) {
		char *dollar = strchr(O->buffer, '$');
		if (!dollar) {
			return;
		}
		size_t dollar_len = strlen(dollar + 1);
		// to include `\0`
		memmove(dollar, dollar + 1, dollar_len + 1);
	}
}

static void patch_cs_detail_operand_reg(cs_mips_op *op, unsigned reg,
					unsigned access)
{
	op->type = MIPS_OP_REG;
	op->reg = reg;
	op->is_reglist = false;
	op->access = access;
}

static void patch_cs_details(MCInst *MI)
{
	if (!detail_is_set(MI))
		return;

	cs_mips_op *op0 = NULL, *op1 = NULL, *op2 = NULL;
	unsigned opcode = MCInst_getOpcode(MI);
	unsigned n_ops = MCInst_getNumOperands(MI);

	switch (opcode) {
	/* mips r2 to r5 only 64bit */
	case Mips_DSDIV: /// ddiv $$zero, $rs, $rt
		/* fall-thru */
	case Mips_DUDIV: /// ddivu $$zero, $rs, $rt
		if (n_ops != 2) {
			return;
		}
		Mips_inc_op_count(MI);
		op0 = Mips_get_detail_op(MI, -3);
		op1 = Mips_get_detail_op(MI, -2);
		op2 = Mips_get_detail_op(MI, -1);
		// move all details by one and add $zero reg
		*op2 = *op1;
		*op1 = *op0;
		patch_cs_detail_operand_reg(op0, MIPS_REG_ZERO_64, CS_AC_WRITE);
		return;

	/* mips r2 to r5 only */
	case Mips_SDIV: /// div $$zero, $rs, $rt
		/* fall-thru */
	case Mips_UDIV: /// divu $$zero, $rs, $rt
		/* fall-thru */
	/* microMIPS only */
	case Mips_SDIV_MM: /// div $$zero, $rs, $rt
		/* fall-thru */
	case Mips_UDIV_MM: /// divu $$zero, $rs, $rt
		/* fall-thru */

	/* MIPS16 only */
	case Mips_DivRxRy16: /// div $$zero, $rx, $ry
		/* fall-thru */
	case Mips_DivuRxRy16: /// divu $$zero, $rx, $ry
		if (n_ops != 2) {
			return;
		}
		Mips_inc_op_count(MI);
		op0 = Mips_get_detail_op(MI, -3);
		op1 = Mips_get_detail_op(MI, -2);
		op2 = Mips_get_detail_op(MI, -1);
		// move all details by one and add $zero reg
		*op2 = *op1;
		*op1 = *op0;
		patch_cs_detail_operand_reg(op0, MIPS_REG_ZERO, CS_AC_WRITE);
		return;
	case Mips_AddiuSpImm16: /// addiu $$sp, imm8
		/* fall-thru */
	case Mips_AddiuSpImmX16: /// addiu $$sp, imm8
		if (n_ops != 1) {
			return;
		}
		Mips_inc_op_count(MI);
		op0 = Mips_get_detail_op(MI, -2);
		op1 = Mips_get_detail_op(MI, -1);
		// move all details by one and add $sp reg
		*op1 = *op0;
		patch_cs_detail_operand_reg(op0, MIPS_REG_SP, CS_AC_READ_WRITE);
		return;
	case Mips_JrcRa16: /// jrc $ra
		/* fall-thru */
	case Mips_JrRa16: /// jr $ra
		if (n_ops > 0) {
			return;
		}
		Mips_inc_op_count(MI);
		op0 = Mips_get_detail_op(MI, -1);
		patch_cs_detail_operand_reg(op0, MIPS_REG_RA, CS_AC_READ);
		return;
	default:
		return;
	}
}

void Mips_LLVM_printInst(MCInst *MI, uint64_t Address, SStream *O)
{
	bool useAliasDetails = map_use_alias_details(MI);
	if (!useAliasDetails) {
		SStream_Close(O);
		printInstruction(MI, Address, O);
		SStream_Open(O);
		map_set_fill_detail_ops(MI, false);
	}

	if (printAliasInstr(MI, Address, O) || printAlias4(MI, Address, O)) {
		MCInst_setIsAlias(MI, true);
	} else {
		printInstruction(MI, Address, O);
	}

	patch_cs_printer(MI, O);
	patch_cs_details(MI);

	if (!useAliasDetails) {
		map_set_fill_detail_ops(MI, true);
	}
}

void printOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	switch (MCInst_getOpcode(MI)) {
	default:
		break;
	case Mips_AND16_NM:
	case Mips_XOR16_NM:
	case Mips_OR16_NM:
		if (MCInst_getNumOperands(MI) == 2 && OpNo == 2)
			OpNo = 0; // rt, rs -> rt, rs, rt
		break;
	case Mips_ADDu4x4_NM:
	case Mips_MUL4x4_NM:
		if (MCInst_getNumOperands(MI) == 2 && OpNo > 0)
			OpNo = OpNo - 1; // rt, rs -> rt, rt, rs
		break;
	}

	MCOperand *Op = MCInst_getOperand(MI, (OpNo));
	if (MCOperand_isReg(Op)) {
		add_cs_detail(MI, Mips_OP_GROUP_Operand, OpNo);
		printRegName(MI, O, MCOperand_getReg(Op));
		return;
	}

	if (MCOperand_isImm(Op)) {
		switch (MCInst_getOpcode(MI)) {
		case Mips_LI48_NM:
		case Mips_ANDI16_NM:
		case Mips_ANDI_NM:
		case Mips_ORI_NM:
		case Mips_XORI_NM:
		case Mips_TEQ_NM:
		case Mips_TNE_NM:
		case Mips_SIGRIE_NM:
		case Mips_SDBBP_NM:
		case Mips_SDBBP16_NM:
		case Mips_BREAK_NM:
		case Mips_BREAK16_NM:
		case Mips_SYSCALL_NM:
		case Mips_SYSCALL16_NM:
		case Mips_WAIT_NM:
			CONCAT(printUImm, CONCAT(32, 0))
			(MI, OpNo, O);
			break;
		default:
			add_cs_detail(MI, Mips_OP_GROUP_Operand, OpNo);
			printInt64(O, MCOperand_getImm(Op));
			break;
		}
		return;
	}
}

static void printJumpOperand(MCInst *MI, unsigned OpNo, SStream *O)
{
	add_cs_detail(MI, Mips_OP_GROUP_JumpOperand, OpNo);
	MCOperand *Op = MCInst_getOperand(MI, (OpNo));
	if (MCOperand_isReg(Op))
		return printRegName(MI, O, MCOperand_getReg(Op));

	// only the upper bits are needed.
	uint64_t Base = MI->address & ~0x0fffffffull;
	uint64_t Target = MCOperand_getImm(Op);
	printInt64(O, Base | Target);
}

static void printBranchOperand(MCInst *MI, uint64_t Address, unsigned OpNo,
			       SStream *O)
{
	add_cs_detail(MI, Mips_OP_GROUP_BranchOperand, OpNo);
	MCOperand *Op = MCInst_getOperand(MI, (OpNo));
	if (MCOperand_isReg(Op))
		return printRegName(MI, O, MCOperand_getReg(Op));

	uint64_t Target = Address + MCOperand_getImm(Op);
	printInt64(O, Target);
}

#define DEFINE_printUImm(Bits) \
	static void CONCAT(printUImm, CONCAT(Bits, 0))(MCInst * MI, int opNum, \
						       SStream *O) \
	{ \
		add_cs_detail(MI, CONCAT(Mips_OP_GROUP_UImm, CONCAT(Bits, 0)), \
			      opNum); \
		MCOperand *MO = MCInst_getOperand(MI, (opNum)); \
		if (MCOperand_isImm(MO)) { \
			uint64_t Imm = MCOperand_getImm(MO); \
			Imm &= (((uint64_t)1) << Bits) - 1; \
			printUInt64(O, Imm); \
			return; \
		} \
		MCOperand *Op = MCInst_getOperand(MI, (opNum)); \
		printRegName(MI, O, MCOperand_getReg(Op)); \
	}

#define DEFINE_printUImm_2(Bits, Offset) \
	static void CONCAT(printUImm, CONCAT(Bits, Offset))( \
		MCInst * MI, int opNum, SStream *O) \
	{ \
		add_cs_detail( \
			MI, CONCAT(Mips_OP_GROUP_UImm, CONCAT(Bits, Offset)), \
			opNum); \
		MCOperand *MO = MCInst_getOperand(MI, (opNum)); \
		if (MCOperand_isImm(MO)) { \
			uint64_t Imm = MCOperand_getImm(MO); \
			Imm -= Offset; \
			Imm &= (1 << Bits) - 1; \
			Imm += Offset; \
			printUInt64(O, Imm); \
			return; \
		} \
		MCOperand *Op = MCInst_getOperand(MI, (opNum)); \
		printRegName(MI, O, MCOperand_getReg(Op)); \
	}

DEFINE_printUImm(0);
DEFINE_printUImm(1);
DEFINE_printUImm(10);
DEFINE_printUImm(12);
DEFINE_printUImm(16);
DEFINE_printUImm(2);
DEFINE_printUImm(20);
DEFINE_printUImm(26);
DEFINE_printUImm(3);
DEFINE_printUImm(32);
DEFINE_printUImm(4);
DEFINE_printUImm(5);
DEFINE_printUImm(6);
DEFINE_printUImm(7);
DEFINE_printUImm(8);
DEFINE_printUImm_2(2, 1);
DEFINE_printUImm_2(5, 1);
DEFINE_printUImm_2(5, 32);
DEFINE_printUImm_2(5, 33);
DEFINE_printUImm_2(6, 1);
DEFINE_printUImm_2(6, 2);

static void printMemOperand(MCInst *MI, int opNum, SStream *O)
{
	// Load/Store memory operands -- imm($reg)
	// If PIC target the target is loaded as the
	// pattern lw $25,%call16($28)

	// opNum can be invalid if instruction had reglist as operand.
	// MemOperand is always last operand of instruction (base + offset).
	switch (MCInst_getOpcode(MI)) {
	default:
		break;
	case Mips_SWM32_MM:
	case Mips_LWM32_MM:
	case Mips_SWM16_MM:
	case Mips_SWM16_MMR6:
	case Mips_LWM16_MM:
	case Mips_LWM16_MMR6:
		opNum = MCInst_getNumOperands(MI) - 2;
		break;
	}

	set_mem_access(MI, true);
	// Index register is encoded as immediate value
	// in case of nanoMIPS indexed instructions
	switch (MCInst_getOpcode(MI)) {
	// No offset needed for paired LL/SC
	case Mips_LLWP_NM:
	case Mips_SCWP_NM:
		break;
	case Mips_LWX_NM:
	case Mips_LWXS_NM:
	case Mips_LWXS16_NM:
	case Mips_LBX_NM:
	case Mips_LBUX_NM:
	case Mips_LHX_NM:
	case Mips_LHUX_NM:
	case Mips_LHXS_NM:
	case Mips_LHUXS_NM:
	case Mips_SWX_NM:
	case Mips_SWXS_NM:
	case Mips_SBX_NM:
	case Mips_SHX_NM:
	case Mips_SHXS_NM:
		if (!MCOperand_isReg(MCInst_getOperand(MI, (opNum + 1)))) {
			add_cs_detail(MI, Mips_OP_GROUP_MemOperand,
				      (opNum + 1));
			printRegName(MI, O,
				     MCOperand_getImm(MCInst_getOperand(
					     MI, (opNum + 1))));
			break;
		}
		// Fall through
	default:
		printOperand((MCInst *)MI, opNum + 1, O);
		break;
	}
	SStream_concat0(O, "(");
	printOperand((MCInst *)MI, opNum, O);
	SStream_concat0(O, ")");
	set_mem_access(MI, false);
}

static void printMemOperandEA(MCInst *MI, int opNum, SStream *O)
{
	// when using stack locations for not load/store instructions
	// print the same way as all normal 3 operand instructions.
	printOperand((MCInst *)MI, opNum, O);
	SStream_concat0(O, ", ");
	printOperand((MCInst *)MI, opNum + 1, O);
}

static void printFCCOperand(MCInst *MI, int opNum, SStream *O)
{
	MCOperand *MO = MCInst_getOperand(MI, (opNum));
	SStream_concat0(O,
			MipsFCCToString((Mips_CondCode)MCOperand_getImm(MO)));
}

static bool printAlias(const char *Str, const MCInst *MI, uint64_t Address,
		       unsigned OpNo, SStream *OS, bool IsBranch)
{
	SStream_concat(OS, "%s%s", "\t", Str);
	SStream_concat0(OS, "\t");
	if (IsBranch)
		printBranchOperand((MCInst *)MI, Address, OpNo, OS);
	else
		printOperand((MCInst *)MI, OpNo, OS);
	return true;
}

static bool printAlias2(const char *Str, const MCInst *MI, uint64_t Address,
			unsigned OpNo0, unsigned OpNo1, SStream *OS,
			bool IsBranch)
{
	printAlias(Str, MI, Address, OpNo0, OS, IsBranch);
	SStream_concat0(OS, ", ");
	if (IsBranch)
		printBranchOperand((MCInst *)MI, Address, OpNo1, OS);
	else
		printOperand((MCInst *)MI, OpNo1, OS);
	return true;
}

static bool printAlias3(const char *Str, const MCInst *MI, uint64_t Address,
			unsigned OpNo0, unsigned OpNo1, unsigned OpNo2,
			SStream *OS)
{
	printAlias(Str, MI, Address, OpNo0, OS, false);
	SStream_concat0(OS, ", ");
	printOperand((MCInst *)MI, OpNo1, OS);
	SStream_concat0(OS, ", ");
	printOperand((MCInst *)MI, OpNo2, OS);
	return true;
}

static bool printAlias4(const MCInst *MI, uint64_t Address, SStream *OS)
{
	switch (MCInst_getOpcode(MI)) {
	case Mips_BEQ:
	case Mips_BEQ_MM:
		// beq $zero, $zero, $L2 => b $L2
		// beq $r0, $zero, $L2 => beqz $r0, $L2
		return (isReg(MI, 0, Mips_ZERO) && isReg(MI, 1, Mips_ZERO) &&
			printAlias("b", MI, Address, 2, OS, true)) ||
		       (isReg(MI, 1, Mips_ZERO) &&
			printAlias2("beqz", MI, Address, 0, 2, OS, true));
	case Mips_BEQ64:
		// beq $r0, $zero, $L2 => beqz $r0, $L2
		return isReg(MI, 1, Mips_ZERO_64) &&
		       printAlias2("beqz", MI, Address, 0, 2, OS, true);
	case Mips_BNE:
	case Mips_BNE_MM:
		// bne $r0, $zero, $L2 => bnez $r0, $L2
		return isReg(MI, 1, Mips_ZERO) &&
		       printAlias2("bnez", MI, Address, 0, 2, OS, true);
	case Mips_BNE64:
		// bne $r0, $zero, $L2 => bnez $r0, $L2
		return isReg(MI, 1, Mips_ZERO_64) &&
		       printAlias2("bnez", MI, Address, 0, 2, OS, true);
	case Mips_BGEZAL:
		// bgezal $zero, $L1 => bal $L1
		return isReg(MI, 0, Mips_ZERO) &&
		       printAlias("bal", MI, Address, 1, OS, true);
	case Mips_BC1T:
		// bc1t $fcc0, $L1 => bc1t $L1
		return isReg(MI, 0, Mips_FCC0) &&
		       printAlias("bc1t", MI, Address, 1, OS, true);
	case Mips_BC1F:
		// bc1f $fcc0, $L1 => bc1f $L1
		return isReg(MI, 0, Mips_FCC0) &&
		       printAlias("bc1f", MI, Address, 1, OS, true);
	case Mips_JALR:
		// jalr $zero, $r1 => jr $r1
		// jalr $ra, $r1 => jalr $r1
		return (isReg(MI, 0, Mips_ZERO) &&
			printAlias("jr", MI, Address, 1, OS, false)) ||
		       (isReg(MI, 0, Mips_RA) &&
			printAlias("jalr", MI, Address, 1, OS, false));
	case Mips_JALR64:
		// jalr $zero, $r1 => jr $r1
		// jalr $ra, $r1 => jalr $r1
		return (isReg(MI, 0, Mips_ZERO_64) &&
			printAlias("jr", MI, Address, 1, OS, false)) ||
		       (isReg(MI, 0, Mips_RA_64) &&
			printAlias("jalr", MI, Address, 1, OS, false));
	case Mips_NOR:
	case Mips_NOR_MM:
	case Mips_NOR_MMR6:
		// nor $r0, $r1, $zero => not $r0, $r1
		return isReg(MI, 2, Mips_ZERO) &&
		       printAlias2("not", MI, Address, 0, 1, OS, false);
	case Mips_NOR64:
		// nor $r0, $r1, $zero => not $r0, $r1
		return isReg(MI, 2, Mips_ZERO_64) &&
		       printAlias2("not", MI, Address, 0, 1, OS, false);
	case Mips_OR:
	case Mips_ADDu:
		// or $r0, $r1, $zero => move $r0, $r1
		// addu $r0, $r1, $zero => move $r0, $r1
		return isReg(MI, 2, Mips_ZERO) &&
		       printAlias2("move", MI, Address, 0, 1, OS, false);
	case Mips_LI48_NM:
	case Mips_LI16_NM:
		// li[16/48] $r0, imm => li $r0, imm
		return printAlias2("li", MI, Address, 0, 1, OS, false);
	case Mips_ADDIU_NM:
	case Mips_ADDIUNEG_NM:
		if (isReg(MI, 1, Mips_ZERO_NM))
			return printAlias2("li", MI, Address, 0, 2, OS, false);
		else
			return printAlias3("addiu", MI, Address, 0, 1, 2, OS);
	case Mips_ADDIU48_NM:
	case Mips_ADDIURS5_NM:
	case Mips_ADDIUR1SP_NM:
	case Mips_ADDIUR2_NM:
	case Mips_ADDIUGPB_NM:
	case Mips_ADDIUGPW_NM:
		return printAlias3("addiu", MI, Address, 0, 1, 2, OS);
	case Mips_ANDI16_NM:
	case Mips_ANDI_NM:
		// andi[16/32] $r0, $r1, imm => andi $r0, $r1, imm
		return printAlias3("andi", MI, Address, 0, 1, 2, OS);
	default:
		return false;
	}
}

static void printRegisterList(MCInst *MI, int opNum, SStream *O)
{
	// - 2 because register List is always first operand of instruction and it is
	// always followed by memory operand (base + offset).
	add_cs_detail(MI, Mips_OP_GROUP_RegisterList, opNum);
	for (int i = opNum, e = MCInst_getNumOperands(MI) - 2; i != e; ++i) {
		if (i != opNum)
			SStream_concat0(O, ", ");
		printRegName(MI, O,
			     MCOperand_getReg(MCInst_getOperand(MI, (i))));
	}
}

static void printNanoMipsRegisterList(MCInst *MI, int OpNum, SStream *O)
{
	add_cs_detail(MI, Mips_OP_GROUP_NanoMipsRegisterList, OpNum);
	for (unsigned I = OpNum; I < MCInst_getNumOperands(MI); I++) {
		SStream_concat0(O, ", ");
		printRegName(MI, O,
			     MCOperand_getReg(MCInst_getOperand(MI, (I))));
	}
}

static void printHi20(MCInst *MI, int OpNum, SStream *O)
{
	MCOperand *MO = MCInst_getOperand(MI, (OpNum));
	if (MCOperand_isImm(MO)) {
		add_cs_detail(MI, Mips_OP_GROUP_Hi20, OpNum);
		SStream_concat0(O, "%hi(");
		printUInt64(O, MCOperand_getImm(MO));
		SStream_concat0(O, ")");
	} else
		printOperand(MI, OpNum, O);
}

static void printHi20PCRel(MCInst *MI, uint64_t Address, int OpNum, SStream *O)
{
	MCOperand *MO = MCInst_getOperand(MI, (OpNum));
	if (MCOperand_isImm(MO)) {
		add_cs_detail(MI, Mips_OP_GROUP_Hi20PCRel, OpNum);
		SStream_concat0(O, "%pcrel_hi(");
		printUInt64(O, MCOperand_getImm(MO) + Address);
		SStream_concat0(O, ")");
	} else
		printOperand(MI, OpNum, O);
}

static void printPCRel(MCInst *MI, uint64_t Address, int OpNum, SStream *O)
{
	MCOperand *MO = MCInst_getOperand(MI, (OpNum));
	if (MCOperand_isImm(MO)) {
		add_cs_detail(MI, Mips_OP_GROUP_PCRel, OpNum);
		printUInt64(O, MCOperand_getImm(MO) + Address);
	} else
		printOperand(MI, OpNum, O);
}

const char *Mips_LLVM_getRegisterName(unsigned RegNo, bool noRegName)
{
	if (!RegNo || RegNo >= MIPS_REG_ENDING) {
		return NULL;
	}
	if (noRegName) {
		return getRegisterName(RegNo);
	}
	switch (RegNo) {
	case MIPS_REG_AT:
	case MIPS_REG_AT_64:
		return "at";
	case MIPS_REG_A0:
	case MIPS_REG_A0_64:
		return "a0";
	case MIPS_REG_A1:
	case MIPS_REG_A1_64:
		return "a1";
	case MIPS_REG_A2:
	case MIPS_REG_A2_64:
		return "a2";
	case MIPS_REG_A3:
	case MIPS_REG_A3_64:
		return "a3";
	case MIPS_REG_K0:
	case MIPS_REG_K0_64:
		return "k0";
	case MIPS_REG_K1:
	case MIPS_REG_K1_64:
		return "k1";
	case MIPS_REG_S0:
	case MIPS_REG_S0_64:
		return "s0";
	case MIPS_REG_S1:
	case MIPS_REG_S1_64:
		return "s1";
	case MIPS_REG_S2:
	case MIPS_REG_S2_64:
		return "s2";
	case MIPS_REG_S3:
	case MIPS_REG_S3_64:
		return "s3";
	case MIPS_REG_S4:
	case MIPS_REG_S4_64:
		return "s4";
	case MIPS_REG_S5:
	case MIPS_REG_S5_64:
		return "s5";
	case MIPS_REG_S6:
	case MIPS_REG_S6_64:
		return "s6";
	case MIPS_REG_S7:
	case MIPS_REG_S7_64:
		return "s7";
	case MIPS_REG_T0:
	case MIPS_REG_T0_64:
		return "t0";
	case MIPS_REG_T1:
	case MIPS_REG_T1_64:
		return "t1";
	case MIPS_REG_T2:
	case MIPS_REG_T2_64:
		return "t2";
	case MIPS_REG_T3:
	case MIPS_REG_T3_64:
		return "t3";
	case MIPS_REG_T4:
	case MIPS_REG_T4_64:
		return "t4";
	case MIPS_REG_T5:
	case MIPS_REG_T5_64:
		return "t5";
	case MIPS_REG_T6:
	case MIPS_REG_T6_64:
		return "t6";
	case MIPS_REG_T7:
	case MIPS_REG_T7_64:
		return "t7";
	case MIPS_REG_T8:
	case MIPS_REG_T8_64:
		return "t8";
	case MIPS_REG_T9:
	case MIPS_REG_T9_64:
		return "t9";
	case MIPS_REG_V0:
	case MIPS_REG_V0_64:
		return "v0";
	case MIPS_REG_V1:
	case MIPS_REG_V1_64:
		return "v1";
	default:
		return getRegisterName(RegNo);
	}
}

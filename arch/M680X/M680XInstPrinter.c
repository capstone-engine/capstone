/* Capstone Disassembly Engine */
/* M680X Backend by Wolfgang Schwotzer <wolfgang.schwotzer@gmx.net> 2017 */

#ifdef CAPSTONE_HAS_M680X
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <capstone/platform.h>

#include "../../MCInst.h"
#include "../../SStream.h"
#include "../../MCRegisterInfo.h"
#include "../../utils.h"
#include "M680XInstPrinter.h"
#include "M680XDisassembler.h"
#include "M680XDisassemblerInternals.h"

#ifndef CAPSTONE_DIET
static const char s_reg_names[][10] = {
	"<invalid>", "A", "B", "E", "F", "0", "D", "W", "CC", "DP", "MD",
	"X", "Y", "S", "U", "V", "Q", "PC",
};

static const char s_instruction_names[][6] = {
	"INVLD", "ABA", "ABX", "ADCA", "ADCB", "ADCD",
	"ADDA", "ADDB", "ADDD", "ADDE", "ADDF", "ADDR", "ADDW",
	"AIM", "ANDA", "ANDB", "ANDCC", "ANDD", "ANDR",
	"ASL", "ASLA", "ASLB", "ASLD",
	"ASR", "ASRA", "ASRB",
	"BAND",
	"BCC", "BCS", "BEOR", "BEQ", "BGE", "BGT", "BHI", "BIAND", "BIEOR",
	"BIOR", "BITA", "BITB", "BITD", "BITMD", "BLE", "BLS", "BLT", "BMI",
	"BNE", "BOR", "BPL", "BRA", "BRN", "BSR", "BVC", "BVS",
	"CBA", "CLC", "CLI",
	"CLR", "CLRA", "CLRB", "CLRD", "CLRE", "CLRF", "CLRW",
	"CLV",
	"CMPA", "CMPB", "CMPD", "CMPE", "CMPF", "CMPR", "CMPS", "CMPU", "CMPW",
	"CMPX", "CMPY",
	"COM", "COMA", "COMB", "COMD", "COME", "COMF", "COMW",
	"CPX",
	"CWAI", "DAA", "DEC", "DECA", "DECB", "DECD", "DECE", "DECF", "DECW",
	"DES", "DEX",
	"DIVD", "DIVQ", "EIM", "EORA", "EORB", "EORD", "EORR",
	"EXG", "ILLGL", "INC", "INCA", "INCB", "INCD", "INCE", "INCF", "INCW",
	"INS", "INX",
	"JMP", "JSR",
	"LBCC", "LBCS", "LBEQ", "LBGE", "LBGT", "LBHI", "LBLE", "LBLS", "LBLT",
	"LBMI", "LBNE", "LBPL", "LBRA", "LBRN", "LBSR", "LBVC", "LBVS",
	"LDA", "LDAA", "LDAB", "LDB", "LDBT", "LDD", "LDE", "LDF", "LDMD",
	"LDQ", "LDS", "LDU", "LDW", "LDX", "LDY",
	"LEAS", "LEAU", "LEAX", "LEAY",
	"LSL", "LSLA", "LSLB",
	"LSR", "LSRA", "LSRB", "LSRD", "LSRW",
	"MUL", "MULD",
	"NEG", "NEGA", "NEGB", "NEGD",
	"NOP", "OIM", "ORA", "ORAA", "ORAB", "ORB", "ORCC", "ORD", "ORR",
	"PSHA", "PSHB", "PSHS", "PSHSW", "PSHU", "PSHUW", "PSHX",
	"PULA", "PULB", "PULS", "PULSW", "PULU", "PULUW", "PULX",
	"ROL", "ROLA", "ROLB", "ROLD", "ROLW",
	"ROR", "RORA", "RORB", "RORD", "RORW",
	"RTI", "RTS", "SBA", "SBCA", "SBCB", "SBCD", "SBCR",
	"SEC", "SEI", "SEV", "SEX", "SEXW", "STA", "STAA", "STAB", "STB",
	"STBT", "STD", "STE", "STF", "STQ", "STS", "STU", "STW", "STX", "STY",
	"SUBA", "SUBB", "SUBD", "SUBE", "SUBF", "SUBR", "SUBW",
	"SWI", "SWI2", "SWI3",
	"SYNC", "TAB", "TAP", "TBA", "TPA", "TFM", "TFR", "TIM",
	"TST", "TSTA", "TSTB", "TSTD", "TSTE", "TSTF", "TSTW",
	"TSX", "TXS", "WAI", "XGDX",
};

static name_map s_group_names[] = {
	{ M680X_GRP_INVALID, "<invalid>" },
	{ M680X_GRP_JUMP,  "JUMP" },
	{ M680X_GRP_CALL,  "CALL" },
	{ M680X_GRP_RET, "RET" },
	{ M680X_GRP_INT, "INT" },
	{ M680X_GRP_IRET,  "IRET" },
	{ M680X_GRP_PRIV,  "PRIVILEGED" },
	{ M680X_GRP_BRAREL,  "BRANCH RELATIVE" },
};
#endif

static void printRegName(cs_struct *handle, SStream *OS, unsigned int reg)
{
#ifndef CAPSTONE_DIET
	SStream_concat(OS, handle->reg_name((csh)handle, reg));
#endif
}

static void printInstructionName(cs_struct *handle, SStream *OS,
	unsigned int insn)
{
#ifndef CAPSTONE_DIET
	SStream_concat(OS, handle->insn_name((csh)handle, insn));
#endif
}

static void printOperand(MCInst *MI, SStream *O, cs_m680x_op *op)
{
	switch (op->type) {
	case M680X_OP_REGISTER:
		printRegName(MI->csh, O, op->reg);
		break;

	case M680X_OP_IMMEDIATE:
		if (MI->csh->imm_unsigned)
			SStream_concat(O, "#%u", op->imm);
		else
			SStream_concat(O, "#%d", (int16_t)op->imm);

		break;

	case M680X_OP_INDEXED_00:
		if (op->idx.offset_bits > 0 && op->idx.offset != 0)
			SStream_concat(O, "%d", op->idx.offset);

		SStream_concat(O, ",", op->idx.offset);

		printRegName(MI->csh, O, op->idx.base_reg);
		break;

	case M680X_OP_INDEXED_09:
		if (op->idx.indirect)
			SStream_concat(O, "[");

		if (op->idx.offset_reg != M680X_REG_INVALID)
			printRegName(MI->csh, O, op->idx.offset_reg);
		else if (op->idx.offset_bits > 0) {
			if (op->idx.base_reg == M680X_REG_PC)
				SStream_concat(O, "$%04X", op->idx.offset_addr);
			else
				SStream_concat(O, "%d", op->idx.offset);
		}

		SStream_concat(O, ",");

		if (op->idx.inc_dec == M680X_PRE_DEC_1)
			SStream_concat(O, "-");
		else if (op->idx.inc_dec == M680X_PRE_DEC_2)
			SStream_concat(O, "--");

		printRegName(MI->csh, O, op->idx.base_reg);

		if (op->idx.base_reg == M680X_REG_PC)
			SStream_concat(O, "R");

		if (op->idx.inc_dec == M680X_POST_INC_1)
			SStream_concat(O, "+");

		else if (op->idx.inc_dec == M680X_POST_INC_2)
			SStream_concat(O, "++");

		if (op->idx.indirect)
			SStream_concat(O, "]");

		break;

	case M680X_OP_RELATIVE:
		SStream_concat(O, "$%04X", op->rel.address);
		break;

	case M680X_OP_DIRECT:
		SStream_concat(O, "<$%02X", op->direct_addr);
		break;

	case M680X_OP_EXTENDED:
		if (op->ext.indirect)
			SStream_concat(O, "[$%04X]", op->ext.address);
		else {
			if (op->ext.address < 256) {
				SStream_concat(O, ">$%04X", op->ext.address);
			}
			else {
				SStream_concat(O, "$%04X", op->ext.address);
			}
		}

		break;

	default:
		SStream_concat(O, "<invalid_operand>");
		break;
	}
}

static const char *getDelimiter(cs_m680x *m680x)
{
	bool indexed = false;
	int count = 0;
	int i;

	if (m680x->op_count > 1) {
		for (i  = 0; i < m680x->op_count; ++i) {
			if ((m680x->operands[i].type == M680X_OP_INDEXED_00) ||
				(m680x->operands[i].type ==
					M680X_OP_INDEXED_00))
				indexed = true;

			if (m680x->operands[i].type != M680X_OP_REGISTER)
				count++;
		}
	}

	return (indexed && (count > 1)) ? ";" : ",";
};

void M680X_printInst(MCInst *MI, SStream *O, void *PrinterInfo)
{
	m680x_info *info = (m680x_info *)PrinterInfo;
	cs_m680x *m680x = &info->m680x;
	cs_detail *detail = MI->flat_insn->detail;
	bool is_reg_in_opcode = false;
	const char *delimiter = getDelimiter(m680x);
	int i;

	if (detail != NULL)
		memcpy(&detail->m680x, m680x, sizeof(cs_m680x));

	if (info->insn == M680X_INS_INVLD || info->insn == M680X_INS_ILLGL) {
		if (m680x->op_count)
			SStream_concat(O, "FCB $%02X", m680x->operands[0].imm);
		else
			SStream_concat(O, "FCB $<unknown>");

		return;
	}

	printInstructionName(MI->csh, O, info->insn);
	SStream_concat(O, " ");

	is_reg_in_opcode = (m680x->flags & M680X_FIRST_OP_IN_MNEM) != 0;

	for (i  = 0; i < m680x->op_count; ++i) {
		if (i > 0 || (i == 0 && !is_reg_in_opcode)) {
			printOperand(MI, O, &m680x->operands[i]);

			if ((i + 1) != m680x->op_count)
				SStream_concat(O, delimiter);
		}
	}
}

const char *M680X_reg_name(csh handle, unsigned int reg)
{
#ifndef CAPSTONE_DIET

	if (reg >= M680X_REG_ENDING)
		return NULL;

	return s_reg_names[(int)reg];
#else
	return NULL;
#endif
}

const char *M680X_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET

	if (id >= ARR_SIZE(s_instruction_names))
		return NULL;
	else
		return s_instruction_names[(int)id];

#else
	return NULL;
#endif
}

const char *M680X_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(s_group_names, ARR_SIZE(s_group_names), id);
#else
	return NULL;
#endif
}

cs_err M680X_instprinter_init(cs_struct *ud)
{
#ifndef CAPSTONE_DIET

	if (M680X_REG_ENDING != ARR_SIZE(s_reg_names)) {
		fprintf(stderr, "Internal error: Size mismatch in enum "
			"m680x_reg and s_reg_names\n");

		return CS_ERR_MODE;
	}

	if (M680X_INS_ENDING != ARR_SIZE(s_instruction_names)) {
		fprintf(stderr, "Internal error: Size mismatch in enum "
			"m680x_insn and s_instruction_names\n");

		return CS_ERR_MODE;
	}

	if (M680X_GRP_ENDING != ARR_SIZE(s_group_names)) {
		fprintf(stderr, "Internal error: Size mismatch in enum "
			"m680x_group_type and s_group_names\n");

		return CS_ERR_MODE;
	}

#endif

	return CS_ERR_OK;
}

#endif


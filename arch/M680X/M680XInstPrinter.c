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
	"HX", "H", "X", "Y", "S", "U", "V", "Q", "PC", "TMP2", "TMP3",
};

static const char s_instruction_names[][6] = {
	"INVLD", "ABA", "ABX", "ABY", "ADC", "ADCA", "ADCB", "ADCD", "ADCR",
	"ADD", "ADDA", "ADDB", "ADDD", "ADDE", "ADDF", "ADDR", "ADDW",
	"AIM", "AIS", "AIX", "AND", "ANDA", "ANDB", "ANDCC", "ANDD", "ANDR",
	"ASL", "ASLA", "ASLB", "ASLD",
	"ASR", "ASRA", "ASRB", "ASRD", "ASRX",
	"BAND",
	"BCC", "BCLR", "BCS", "BEOR", "BEQ", "BGE", "BGND", "BGT", "BHCC",
	"BHCS", "BHI",
	"BIAND", "BIEOR", "BIH", "BIL",
	"BIOR", "BIT", "BITA", "BITB", "BITD", "BITMD", "BLE", "BLS", "BLT",
	"BMC",
	"BMI", "BMS",
	"BNE", "BOR", "BPL", "BRCLR", "BRSET", "BRA", "BRN", "BSET", "BSR",
	"BVC", "BVS",
	"CALL", "CBA", "CBEQ", "CBEQA", "CBEQX", "CLC", "CLI",
	"CLR", "CLRA", "CLRB", "CLRD", "CLRE", "CLRF", "CLRH", "CLRW", "CLRX",
	"CLV", "CMP",
	"CMPA", "CMPB", "CMPD", "CMPE", "CMPF", "CMPR", "CMPS", "CMPU", "CMPW",
	"CMPX", "CMPY",
	"COM", "COMA", "COMB", "COMD", "COME", "COMF", "COMW", "COMX", "CPD",
	"CPHX", "CPS", "CPX", "CPY",
	"CWAI", "DAA", "DBEQ", "DBNE", "DBNZ", "DBNZA", "DBNZX",
	"DEC", "DECA", "DECB", "DECD", "DECE", "DECF", "DECW",
	"DECX", "DES", "DEX", "DEY",
	"DIV", "DIVD", "DIVQ", "EDIV", "EDIVS", "EIM", "EMACS", "EMAXD",
	"EMAXM", "EMIND", "EMINM", "EMUL", "EMULS",
	"EOR", "EORA", "EORB", "EORD", "EORR", "ETBL",
	"EXG", "FDIV", "IBEQ", "IBNE", "IDIV", "IDIVS", "ILLGL",
	"INC", "INCA", "INCB", "INCD", "INCE", "INCF", "INCW", "INCX",
	"INS", "INX", "INY",
	"JMP", "JSR",
	"LBCC", "LBCS", "LBEQ", "LBGE", "LBGT", "LBHI", "LBLE", "LBLS", "LBLT",
	"LBMI", "LBNE", "LBPL", "LBRA", "LBRN", "LBSR", "LBVC", "LBVS",
	"LDA", "LDAA", "LDAB", "LDB", "LDBT", "LDD", "LDE", "LDF", "LDHX",
	"LDMD",
	"LDQ", "LDS", "LDU", "LDW", "LDX", "LDY",
	"LEAS", "LEAU", "LEAX", "LEAY",
	"LSL", "LSLA", "LSLB", "LSLD", "LSLX",
	"LSR", "LSRA", "LSRB", "LSRD", "LSRW", "LSRX",
	"MAXA", "MAXM", "MEM", "MINA", "MINM", "MOV", "MOVB", "MOVW", "MUL",
	"MULD",
	"NEG", "NEGA", "NEGB", "NEGD", "NEGX",
	"NOP", "NSA", "OIM", "ORA", "ORAA", "ORAB", "ORB", "ORCC", "ORD", "ORR",
	"PSHA", "PSHB", "PSHC", "PSHD", "PSHH", "PSHS", "PSHSW", "PSHU",
	"PSHUW", "PSHX", "PSHY",
	"PULA", "PULB", "PULC", "PULD", "PULH", "PULS", "PULSW", "PULU",
	"PULUW", "PULX", "PULY", "REV", "REVW",
	"ROL", "ROLA", "ROLB", "ROLD", "ROLW", "ROLX",
	"ROR", "RORA", "RORB", "RORD", "RORW", "RORX",
	"RSP", "RTC", "RTI", "RTS", "SBA", "SBC", "SBCA", "SBCB", "SBCD",
	"SBCR",
	"SEC", "SEI", "SEV", "SEX", "SEXW", "SLP", "STA", "STAA", "STAB", "STB",
	"STBT", "STD", "STE", "STF", "STOP", "STHX",
	"STQ", "STS", "STU", "STW", "STX", "STY",
	"SUB", "SUBA", "SUBB", "SUBD", "SUBE", "SUBF", "SUBR", "SUBW",
	"SWI", "SWI2", "SWI3",
	"SYNC", "TAB", "TAP", "TAX", "TBA", "TBEQ", "TBL", "TBNE", "TEST",
	"TFM", "TFR",
	"TIM", "TPA",
	"TST", "TSTA", "TSTB", "TSTD", "TSTE", "TSTF", "TSTW", "TSTX",
	"TSX", "TSY", "TXA", "TXS", "TYS", "WAI", "WAIT", "WAV", "WAVR",
	"XGDX", "XGDY",
};

static name_map s_group_names[] = {
	{ M680X_GRP_INVALID, "<invalid>" },
	{ M680X_GRP_JUMP,  "JUMP" },
	{ M680X_GRP_CALL,  "CALL" },
	{ M680X_GRP_RET, "RETURN" },
	{ M680X_GRP_INT, "INTERRUPT" },
	{ M680X_GRP_IRET,  "INTERRUPT_RETURN" },
	{ M680X_GRP_PRIV,  "PRIVILEGED" },
	{ M680X_GRP_BRAREL,  "BRANCH_RELATIVE" },
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

static uint32_t get_unsigned(int32_t value, int byte_size)
{
	switch (byte_size) {
	case 1:
		return (uint32_t)(value & 0xff);

	case 2:
		return (uint32_t)(value & 0xffff);

	default:
	case 4:
		return (uint32_t)value;
	}
}

static void printIncDec(bool isPost, SStream *O, m680x_info *info,
	cs_m680x_op *op)
{
	static const char s_inc_dec[][3] = { "--", "-", "", "+", "++" };

	if (!op->idx.inc_dec)
		return;

	if ((!isPost && !(op->idx.flags & M680X_IDX_POST_INC_DEC)) ||
		(isPost && (op->idx.flags & M680X_IDX_POST_INC_DEC))) {
		char *prePostfix = "";

		if (info->cpu_type == M680X_CPU_TYPE_CPU12)
			prePostfix = (op->idx.inc_dec < 0) ? "-" : "+";
		else if (op->idx.inc_dec >= -2 && (op->idx.inc_dec <= 2)) {
			prePostfix = (char *)s_inc_dec[op->idx.inc_dec + 2];
		}

		SStream_concat(O, prePostfix);
	}
}

static void printOperand(MCInst *MI, SStream *O, m680x_info *info,
	cs_m680x_op *op)
{
	switch (op->type) {
	case M680X_OP_REGISTER:
		printRegName(MI->csh, O, op->reg);
		break;

	case M680X_OP_CONSTANT:
		SStream_concat(O, "%u", op->const_val);
		break;

	case M680X_OP_IMMEDIATE:
		if (MI->csh->imm_unsigned)
			SStream_concat(O, "#%u",
				get_unsigned(op->imm, op->size));
		else
			SStream_concat(O, "#%d", op->imm);

		break;

	case M680X_OP_INDEXED:
		if (op->idx.flags & M680X_IDX_INDIRECT)
			SStream_concat(O, "[");

		if (op->idx.offset_reg != M680X_REG_INVALID)
			printRegName(MI->csh, O, op->idx.offset_reg);
		else if (op->idx.offset_bits > 0) {
			if (op->idx.base_reg == M680X_REG_PC)
				SStream_concat(O, "$%04X", op->idx.offset_addr);
			else
				SStream_concat(O, "%d", op->idx.offset);
		}
		else if (op->idx.inc_dec != 0 &&
			info->cpu_type == M680X_CPU_TYPE_CPU12)
			SStream_concat(O, "%d", abs(op->idx.inc_dec));

		if (!(op->idx.flags & M680X_IDX_NO_COMMA))
			SStream_concat(O, ",");

		printIncDec(false, O, info, op);

		printRegName(MI->csh, O, op->idx.base_reg);

		if (op->idx.base_reg == M680X_REG_PC &&
			(op->idx.offset_bits > 0))
			SStream_concat(O, "R");

		printIncDec(true, O, info, op);

		if (op->idx.flags & M680X_IDX_INDIRECT)
			SStream_concat(O, "]");

		break;

	case M680X_OP_RELATIVE:
		SStream_concat(O, "$%04X", op->rel.address);
		break;

	case M680X_OP_DIRECT:
		SStream_concat(O, "$%02X", op->direct_addr);
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

static const char *getDelimiter(m680x_info *info, cs_m680x *m680x)
{
	bool indexed = false;
	int count = 0;
	int i;

	if (info->insn == M680X_INS_TFM)
		return ",";

	if (m680x->op_count > 1) {
		for (i  = 0; i < m680x->op_count; ++i) {
			if (m680x->operands[i].type == M680X_OP_INDEXED)
				indexed = true;

			if (m680x->operands[i].type != M680X_OP_REGISTER)
				count++;
		}
	}

	return (indexed && (count >= 1)) ? ";" : ",";
};

void M680X_printInst(MCInst *MI, SStream *O, void *PrinterInfo)
{
	m680x_info *info = (m680x_info *)PrinterInfo;
	cs_m680x *m680x = &info->m680x;
	cs_detail *detail = MI->flat_insn->detail;
	int suppress_operands = 0;
	const char *delimiter = getDelimiter(info, m680x);
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

	if ((m680x->flags & M680X_FIRST_OP_IN_MNEM) != 0)
		suppress_operands++;

	if ((m680x->flags & M680X_SECOND_OP_IN_MNEM) != 0)
		suppress_operands++;

	for (i  = 0; i < m680x->op_count; ++i) {
		if (i >= suppress_operands) {
			printOperand(MI, O, info, &m680x->operands[i]);

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


/* Capstone Disassembly Engine */
/* By Alexander Nutz, 2025 */

#include "EtcaDisassembler.h"
#include "capstone/etca.h"
#include "../../Mapping.h"
#include "EtcaInstPrinter.h"

const char *Etca_reg_name(csh handle, unsigned int reg)
{
#ifdef CAPSTONE_DIET
	return NULL;
#else
	if (reg >= ETCA_REG_ENDING)
		reg = ETCA_REG_INVALID;

	switch ((cs_etca_reg)reg) {
	case ETCA_REG_INVALID:
	case ETCA_REG_ENDING:
		return "<invalid>";

	case ETCA_REG_R0:
		return "r0";
	case ETCA_REG_R1:
		return "r1";
	case ETCA_REG_R2:
		return "r2";
	case ETCA_REG_R3:
		return "r3";
	case ETCA_REG_R4:
		return "r4";
	case ETCA_REG_R5:
		return "r5";
	case ETCA_REG_R6:
		return "r6";
	case ETCA_REG_R7:
		return "r7";

	case ETCA_REG_R8:
		return "r8";
	case ETCA_REG_R9:
		return "r9";
	case ETCA_REG_R10:
		return "r10";
	case ETCA_REG_R11:
		return "r11";
	case ETCA_REG_R12:
		return "r12";
	case ETCA_REG_R13:
		return "r13";
	case ETCA_REG_R14:
		return "r14";
	case ETCA_REG_R15:
		return "r15";
	}
#endif
}

void Etca_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	insn->id = id; // These id's matches for etca
}

const char *Etca_insn_name(csh handle, unsigned int id)
{
#ifdef CAPSTONE_DIET
	return NULL;
#else
	if (id >= ETCA_INS_ENDING)
		id = ETCA_INS_INVALID;

	switch ((etca_insn)id) {
	case ETCA_INS_INVALID:
	case ETCA_INS_ENDING:
		return "<invalid>";

	case ETCA_INS_NOP:
		return "nop";

	case ETCA_INS_REL_JMP:
		return "jmp";
	case ETCA_INS_ABS_JMP:
		return "jmp";
	case ETCA_INS_REL_CALL:
		return "call";
	case ETCA_INS_ABS_CALL:
		return "call";

	case ETCA_INS_ADD:
		return "add";
	case ETCA_INS_SUB:
		return "sub";
	case ETCA_INS_RSUB:
		return "rsub";
	case ETCA_INS_CMP:
		return "cmp";
	case ETCA_INS_OR:
		return "or";
	case ETCA_INS_XOR:
		return "xor";
	case ETCA_INS_AND:
		return "and";
	case ETCA_INS_TEST:
		return "test";
	case ETCA_INS_MOVZ:
		return "movz";
	case ETCA_INS_MOVS:
		return "movs";
	case ETCA_INS_LOAD:
		return "load";
	case ETCA_INS_STORE:
		return "store";
	case ETCA_INS_SLO:
		return "slo";

	case ETCA_INS_READCR:
		return "readcr";
	case ETCA_INS_WRITECR:
		return "writecr";
	case ETCA_INS_SYSCALL:
		return "syscall";
	case ETCA_INS_ERET:
		return "eret";
	case ETCA_INS_WAIT:
		return "wait";

	case ETCA_INS_PUSH:
		return "push";
	case ETCA_INS_POP:
		return "pop";
	case ETCA_INS_LEA:
		return "lea";
	case ETCA_INS_ADC:
		return "adc";
	case ETCA_INS_SBB:
		return "sbb";
	case ETCA_INS_RSBB:
		return "rsbb";
	case ETCA_INS_ASR:
		return "asr";
	case ETCA_INS_ROL:
		return "rol";
	case ETCA_INS_ROR:
		return "ror";
	case ETCA_INS_SHL:
		return "shl";
	case ETCA_INS_SHR:
		return "shr";
	case ETCA_INS_RCL:
		return "rcl";
	case ETCA_INS_RCR:
		return "rcr";
	case ETCA_INS_POPCNT:
		return "popcnt";
	case ETCA_INS_GREV:
		return "grev";
	case ETCA_INS_CTZ:
		return "ctz";
	case ETCA_INS_CLZ:
		return "clz";
	case ETCA_INS_NOT:
		return "not";
	case ETCA_INS_ANDN:
		return "andn";
	case ETCA_INS_UDIV:
		return "udiv";
	case ETCA_INS_SDIV:
		return "sdiv";
	case ETCA_INS_UREM:
		return "urem";
	case ETCA_INS_SREM:
		return "srem";
	case ETCA_INS_UMUL:
		return "umul";
	case ETCA_INS_SMUL:
		return "smul";
	case ETCA_INS_UHMUL:
		return "uhmul";
	case ETCA_INS_SHMUL:
		return "shmul";
	case ETCA_INS_LSB:
		return "lsb";
	case ETCA_INS_LSBMSK:
		return "lsmsk";
	case ETCA_INS_RLSB:
		return "rlsb";
	case ETCA_INS_ZHIB:
		return "zhib";

	case ETCA_INS_CACHE_FLUSH_ALL:
		return "cache_flush_all";
	case ETCA_INS_DATA_PREFETCH:
		return "data_prefetch";
	case ETCA_INS_INSTRUCTION_PREFETCH:
		return "instruction_prefetch";
	case ETCA_INS_DCACHE_FLUSH:
		return "dcache_flush";
	case ETCA_INS_ICACHE_INVALIDATE:
		return "icache_invalidate";
	case ETCA_INS_CACHE_INVALIDATE_ALL:
		return "cache_invalidate_all";
	case ETCA_INS_DCACHE_INVALIDATE:
		return "dcache_invalidate";
	case ETCA_INS_ALLOC_ZERO:
		return "alloc_zero";
	}
#endif
}

const char *cs_etca_cond_name(uint8_t cond)
{
	switch (cond) {
	case ETCA_COND_Z:
		return "z";
	case ETCA_COND_N:
		return "n";
	case ETCA_COND_C:
		return "c";
	case ETCA_COND_O:
		return "o";
	case ETCA_COND_BE:
		return "be";
	case ETCA_COND_L:
		return "l";
	case ETCA_COND_LE:
		return "le";
	case ETCA_COND_ALWAYS:
		return "always";

	case ETCA_COND_NZ:
		return "nz";
	case ETCA_COND_NN:
		return "nn";
	case ETCA_COND_NC:
		return "nc";
	case ETCA_COND_NO:
		return "no";
	case ETCA_COND_A:
		return "a";
	case ETCA_COND_GE:
		return "ge";
	case ETCA_COND_G:
		return "u";
	case ETCA_COND_NEVER:
		return "never";

	default:
		return NULL;
	}
}

const char *cs_etca_cr_name(cs_etca_cr cr)
{
	switch (cr) {
	case ETCA_CR_CPUID1:
		return "cpuid1";
	case ETCA_CR_CPUID2:
		return "cpuid2";
	case ETCA_CR_FEAT:
		return "feat";
	case ETCA_CR_FLAGS:
		return "flags";
	case ETCA_CR_INT_PC:
		return "int_pc";
	case ETCA_CR_INT_RET_PC:
		return "int_ret_pc";
	case ETCA_CR_INT_MASK:
		return "int_mask";
	case ETCA_CR_INT_PENDING:
		return "int_pending";
	case ETCA_CR_INT_CAUSE:
		return "int_cause";
	case ETCA_CR_INT_DATA:
		return "int_data";
	case ETCA_CR_INT_SCRATCH_0:
		return "int_scratch_0";
	case ETCA_CR_INT_SCRATCH_1:
		return "int_scratch_1";
	case ETCA_CR_PRIV:
		return "priv";
	case ETCA_CR_INT_RET_PRIV:
		return "int_ret_priv";
	case ETCA_CR_CACHE_LINE_SIZE:
		return "cache_line_size";
	case ETCA_CR_NO_CACHE_START:
		return "no_cache_start";
	case ETCA_CR_NO_CACHE_END:
		return "no_cache_end";
	case ETCA_CR_MODE:
		return "mode";
	}
	return NULL;
}

#ifndef CAPSTONE_DIET
static void printReg(SStream *O, cs_etca_reg reg)
{
	SStream_concat1(O, '%');
	SStream_concat0(O, Etca_reg_name(0, reg));
}
#endif

#ifndef CAPSTONE_DIET
static void printMemOp(SStream *O, const cs_etca_op_mem *op)
{
	bool first = true;
	SStream_concat1(O, '[');

	if (op->base.enabled) {
		printReg(O, op->base.base);
	}

	if (op->index.enabled) {
		if (!first) {
			SStream_concat0(O, " + ");
		}
		first = false;

		printUInt8(O, 1 << op->index.index_multiplier_log2);
		SStream_concat1(O, '*');
		printReg(O, op->index.index);
	}

	if (op->displacement) {
		if (!first) {
			SStream_concat0(O, " + ");
		}
		first = false;

		printInt64(O, op->displacement);
	}

	SStream_concat1(O, ']');
}
#endif

#ifndef CAPSTONE_DIET
static void printOp(SStream *O, const cs_etca_op *op, etca_insn insn)
{
	switch (op->type) {
	case ETCA_OP_INVALID:
		SStream_concat0(O, "<invalid>");
		break;

	case ETCA_OP_REG:
		printReg(O, op->reg);
		break;

	case ETCA_OP_IMM:
		if ((int64_t)op->imm < 0 &&
		    (insn == ETCA_INS_REL_JMP || insn == ETCA_INS_REL_CALL ||
		     (int64_t)op->imm >= -63)) {
			SStream_concat1(O, '-');
			printUInt64(O, -op->imm);
		} else {
			printUInt64(O, op->imm);
		}
		break;

	case ETCA_OP_MEM:
		printMemOp(O, &op->mem);
		break;
	}
}
#endif

#ifndef CAPSTONE_DIET
static bool isSizedInsn(etca_insn insn)
{
	switch (insn) {
	case ETCA_INS_INVALID:
	case ETCA_INS_NOP:
	case ETCA_INS_ENDING:
	case ETCA_INS_REL_JMP:
	case ETCA_INS_ABS_JMP:
	case ETCA_INS_REL_CALL:
	case ETCA_INS_ABS_CALL:
	case ETCA_INS_ERET:
	case ETCA_INS_SYSCALL:
	case ETCA_INS_WAIT:
	case ETCA_INS_CACHE_FLUSH_ALL:
	case ETCA_INS_DATA_PREFETCH:
	case ETCA_INS_INSTRUCTION_PREFETCH:
	case ETCA_INS_DCACHE_FLUSH:
	case ETCA_INS_ICACHE_INVALIDATE:
	case ETCA_INS_CACHE_INVALIDATE_ALL:
	case ETCA_INS_DCACHE_INVALIDATE:
	case ETCA_INS_ALLOC_ZERO:
		return false;

	case ETCA_INS_ADD:
	case ETCA_INS_SUB:
	case ETCA_INS_RSUB:
	case ETCA_INS_CMP:
	case ETCA_INS_OR:
	case ETCA_INS_XOR:
	case ETCA_INS_AND:
	case ETCA_INS_TEST:
	case ETCA_INS_MOVZ:
	case ETCA_INS_MOVS:
	case ETCA_INS_LOAD:
	case ETCA_INS_STORE:
	case ETCA_INS_SLO:
	case ETCA_INS_READCR:
	case ETCA_INS_WRITECR:
	case ETCA_INS_PUSH:
	case ETCA_INS_POP:
	case ETCA_INS_LEA:
	case ETCA_INS_ADC:
	case ETCA_INS_SBB:
	case ETCA_INS_RSBB:
	case ETCA_INS_ASR:
	case ETCA_INS_ROL:
	case ETCA_INS_ROR:
	case ETCA_INS_SHL:
	case ETCA_INS_SHR:
	case ETCA_INS_RCL:
	case ETCA_INS_RCR:
	case ETCA_INS_POPCNT:
	case ETCA_INS_GREV:
	case ETCA_INS_CTZ:
	case ETCA_INS_CLZ:
	case ETCA_INS_NOT:
	case ETCA_INS_ANDN:
	case ETCA_INS_UDIV:
	case ETCA_INS_SDIV:
	case ETCA_INS_UREM:
	case ETCA_INS_SREM:
	case ETCA_INS_UMUL:
	case ETCA_INS_SMUL:
	case ETCA_INS_UHMUL:
	case ETCA_INS_SHMUL:
	case ETCA_INS_LSB:
	case ETCA_INS_LSBMSK:
	case ETCA_INS_RLSB:
	case ETCA_INS_ZHIB:
		return true;
	}
}
#endif

static inline bool op_is_reg(const cs_etca_op *op, cs_etca_reg reg)
{
	return op->type == ETCA_OP_REG && op->reg == reg;
}

void Etca_printInst(MCInst *MI, SStream *O, void *infoIn)
{
#ifndef CAPSTONE_DIET
	etca_info *info = (etca_info *)infoIn;

	// first word in buffer has to be mnemonic because of SStream_extract_mnem_opstr!!

	if ((info->op.insn == ETCA_INS_ABS_JMP ||
	     info->op.insn == ETCA_INS_REL_JMP) &&
	    info->op.cond != ETCA_COND_ALWAYS) {
		SStream_concat1(O, 'j');
		SStream_concat0(O, cs_etca_cond_name(info->op.cond));
	} else {
		SStream_concat0(O, Etca_insn_name(0, info->op.insn));
		if (info->op.cond != ETCA_COND_ALWAYS) {
			if (info->op.insn == ETCA_INS_ABS_CALL ||
			    info->op.insn == ETCA_INS_REL_CALL) {
				SStream_concat0(
					O, cs_etca_cond_name(info->op.cond));
			} else {
				SStream_concat(
					O, " when %s, ",
					cs_etca_cond_name(info->op.cond));
			}
		}
	}

	if (isSizedInsn(info->op.insn)) {
		char s = "hxdq"[info->op.ss & 3];
		SStream_concat1(O, s);
	}

	int numPrinted = 0;
	for (int i = 0; i < info->op.op_count; i++) {
		const cs_etca_op *op = &info->op.operands[i];

		/* don't print sp reg if it's the default */
		if (i == 1 && info->op.insn == ETCA_INS_POP &&
		    op_is_reg(op, ETCA_REG_R6))
			continue;
		if (i == 0 && info->op.insn == ETCA_INS_PUSH &&
		    op_is_reg(op, ETCA_REG_R6))
			continue;

		if (numPrinted != 0) {
			SStream_concat0(O, ",");
		}
		SStream_concat0(O, " ");

		const char *crname;
		if (i == 1 &&
		    (info->op.insn == ETCA_INS_READCR ||
		     info->op.insn == ETCA_INS_WRITECR) &&
		    (crname = cs_etca_cr_name(op->imm))) {
			SStream_concat0(O, crname);
		} else {
			printOp(O, op, info->op.insn);
		}

		numPrinted++;
	}
#endif
}

const char *Etca_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	if (id >= ETCA_GRP_ENDING)
		id = ETCA_GRP_ENDING;

	switch ((cs_etca_insn_group)id) {
	case ETCA_GRP_ENDING:
	case ETCA_GRP_INVALID:
		return "<invalid>";

	case ETCA_GRP_JUMP:
		return "jump";
	case ETCA_GRP_CALL:
		return "call";
	case ETCA_GRP_PRIV:
		return "privileged";
	}
#else
	return NULL;
#endif
}

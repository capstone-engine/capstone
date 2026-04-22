/* Capstone Disassembly Engine */
/* By Alexander Nutz, 2025 */

#include "capstone/capstone.h"
#include "capstone/etca.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include "../../cs_priv.h"
#include "../../MCInst.h"
#include "../../MathExtras.h"
#include "EtcaDisassembler.h"

typedef struct {
	struct {
		bool present;
	} pfx_cond;

	uint8_t cond : 4;

	struct {
		bool present;
		bool q : 1;
		bool a : 1;
		bool b : 1;
		bool x : 1;
	} pfx_rex;

	struct {
		bool present;
		uint8_t a : 3;
	} single_reg;

	struct {
		bool present;
		uint8_t a : 3;
		uint8_t b : 3;
		uint8_t m : 3;
	} abm;

	struct {
		bool present;
		uint8_t r : 3;
		uint64_t imm;
	} ri;

	struct {
		bool present;
		uint64_t extended;
	} rel;

	union {
		struct {
			uint8_t sib;
			uint64_t extended_disp;
		} mo1;

		struct {
			uint8_t sib;
			uint64_t extended_disp;
			uint64_t imm;
		} mo2;
	} x;

	uint8_t ss : 2;
	etca_insn insn;
} DecodeIsntCtx;

static bool doesSignExtend(etca_insn insn)
{
	switch (insn) {
	case ETCA_INS_INVALID:
	case ETCA_INS_NOP:
	case ETCA_INS_ENDING:
	case ETCA_INS_SYSCALL:
	case ETCA_INS_ERET:
	case ETCA_INS_WAIT:
	case ETCA_INS_REL_JMP:
	case ETCA_INS_ABS_JMP:
	case ETCA_INS_REL_CALL:
	case ETCA_INS_ABS_CALL:
	case ETCA_INS_LEA:
	case ETCA_INS_CACHE_FLUSH_ALL:
	case ETCA_INS_DATA_PREFETCH:
	case ETCA_INS_INSTRUCTION_PREFETCH:
	case ETCA_INS_DCACHE_FLUSH:
	case ETCA_INS_ICACHE_INVALIDATE:
	case ETCA_INS_CACHE_INVALIDATE_ALL:
	case ETCA_INS_DCACHE_INVALIDATE:
	case ETCA_INS_ALLOC_ZERO:
		return false; /* not applicable */

	case ETCA_INS_ADD:
	case ETCA_INS_SUB:
	case ETCA_INS_RSUB:
	case ETCA_INS_CMP:
	case ETCA_INS_OR:
	case ETCA_INS_XOR:
	case ETCA_INS_AND:
	case ETCA_INS_TEST:
	case ETCA_INS_MOVS:
		return true; /* sign extend */

	case ETCA_INS_MOVZ:
	case ETCA_INS_LOAD:
	case ETCA_INS_STORE:
	case ETCA_INS_SLO:
	case ETCA_INS_READCR:
	case ETCA_INS_WRITECR:
		return false; /* zero extend */

	case ETCA_INS_PUSH:
	case ETCA_INS_POP:
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
		return true; /* TODO: this makes no sense */
	}
}

static void parseABM(DecodeIsntCtx *ctx, uint8_t byte)
{
	ctx->abm.present = true;
	ctx->abm.a = byte >> 5;
	ctx->abm.b = (byte >> 3) & (7 /* 0b111 */);
	ctx->abm.m = byte & 3;
}

static void parseRI(DecodeIsntCtx *ctx, uint8_t byte, etca_insn insn)
{
	ctx->ri.present = true;
	ctx->ri.r = byte >> 5;
	ctx->ri.imm = byte & 31 /* 0b11111 */;
	if (doesSignExtend(insn))
		ctx->ri.imm = SignExtend64(ctx->ri.imm, 5);
}

static etca_insn parseExopOpcode(uint16_t opc)
{
	// clang-format off
	switch (opc)
	{
	/* exop */
	case 0: return ETCA_INS_ADC;
	case 1: return ETCA_INS_SBB;
	case 2: return ETCA_INS_RSBB;
	case 3: return ETCA_INS_ASR;
	case 4: return ETCA_INS_ROL;
	case 5: return ETCA_INS_ROR;
	case 6: return ETCA_INS_SHL;
	case 7: return ETCA_INS_SHR;

	/* bmi1 */
	case 8: return ETCA_INS_RCL;
	case 9: return ETCA_INS_RCR;
	case 10: return ETCA_INS_POPCNT;
	case 11: return ETCA_INS_GREV;
	case 12: return ETCA_INS_CTZ;
	case 13: return ETCA_INS_CLZ;
	case 14: return ETCA_INS_NOT;
	case 15: return ETCA_INS_ANDN;
	case 0x18: return ETCA_INS_LSB;
	case 0x19: return ETCA_INS_LSBMSK;
	case 0x1a: return ETCA_INS_RLSB;
	case 0x1b: return ETCA_INS_ZHIB;

	/* md */
	case 0x10: return ETCA_INS_UDIV;
	case 0x11: return ETCA_INS_SDIV;
	case 0x12: return ETCA_INS_UREM;
	case 0x13: return ETCA_INS_SREM;
	case 0x14: return ETCA_INS_UMUL;
	case 0x15: return ETCA_INS_SMUL;
	case 0x16: return ETCA_INS_UHMUL;
	case 0x17: return ETCA_INS_SHMUL;
	}
	// clang-format on

	return ETCA_INS_INVALID;
}

static etca_insn parseBaseOpcode(uint8_t opc, bool imm)
{
	// clang-format off
	switch (opc)
	{
	case  0: return ETCA_INS_ADD;
	case  1: return ETCA_INS_SUB;
	case  2: return ETCA_INS_RSUB;
	case  3: return ETCA_INS_CMP;
	case  4: return ETCA_INS_OR;
	case  5: return ETCA_INS_XOR;
	case  6: return ETCA_INS_AND;
	case  7: return ETCA_INS_TEST;
	case  8: return ETCA_INS_MOVZ;
	case  9: return ETCA_INS_MOVS;
	case 10: return ETCA_INS_LOAD;
	case 11: return ETCA_INS_STORE;
	case 12: return imm ? ETCA_INS_SLO : ETCA_INS_INVALID;
	case 14: return imm ? ETCA_INS_READCR : ETCA_INS_INVALID;
	case 15: return imm ? ETCA_INS_WRITECR : ETCA_INS_INVALID;
	}
	// clang-format on

	return ETCA_INS_INVALID;
}

static bool parseCoreOp(DecodeIsntCtx *ctx, const uint8_t **code_p,
			size_t *code_len_p, uint16_t *size)
{
	const uint8_t *code = *code_p;
	size_t code_len = *code_len_p;

	if (code_len >= 3 && code[0] >> 4 == 2 + 4 + 8 /* 0b1110 */) {
		uint16_t opc = (code[0] & 0xF) << 5;
		opc |= (code[1] >> 7) << 4;
		opc |= code[1] & 0xF;
		ctx->insn = parseExopOpcode(opc);
		if (ctx->insn == ETCA_INS_INVALID)
			return false;

		ctx->ss = (code[1] >> 4) & 3;

		if (code[1] & (1 << 6)) {
			parseRI(ctx, code[2], ctx->insn);
		} else {
			parseABM(ctx, code[2]);
		}

		code += 3;
		code_len -= 3;
		(*size) += 3;
	} else if (code_len >= 2 && code[0] == 0x2F && code[1] == 0x11) {
		ctx->insn = ETCA_INS_WAIT;

		code += 2;
		code_len -= 2;
		(*size) += 2;
	} else if (code_len >= 2 && code[0] == 0x0F && code[1] == 0x11) {
		ctx->insn = ETCA_INS_SYSCALL;

		code += 2;
		code_len -= 2;
		(*size) += 2;
	} else if (code_len >= 2 && code[0] == 0x1F && code[1] == 0x11) {
		ctx->insn = ETCA_INS_ERET;

		code += 2;
		code_len -= 2;
		(*size) += 2;
	} else if (code_len >= 2 && code[0] >> 6 == 0 &&
		   (code[0] & 0xF) == 0xF && (code[1] << 3) >> 3 == 0) {
		ctx->insn = ETCA_INS_ALLOC_ZERO;
		ctx->single_reg.present = true;
		ctx->single_reg.a = code[1] >> 5;

		code += 2;
		code_len -= 2;
		(*size) += 2;
	} else if (code_len >= 2 && code[0] >> 6 == 0 &&
		   (code[0] & 0xF) == 0xF && (code[1] << 3) >> 3 == 4) {
		ctx->insn = ETCA_INS_DCACHE_INVALIDATE;
		ctx->single_reg.present = true;
		ctx->single_reg.a = code[1] >> 5;

		code += 2;
		code_len -= 2;
		(*size) += 2;
	} else if (code_len >= 2 && code[0] == 0x3F && code[1] == 0x11) {
		ctx->insn = ETCA_INS_CACHE_INVALIDATE_ALL;

		code += 2;
		code_len -= 2;
		(*size) += 2;
	} else if (code_len >= 2 && code[0] == 0x8F && code[1] == 0x01) {
		ctx->insn = ETCA_INS_CACHE_FLUSH_ALL;

		code += 2;
		code_len -= 2;
		(*size) += 2;
	} else if (code_len >= 2 && code[0] >> 6 == 0 &&
		   (code[0] & 0xF) == 0xc) {
		ctx->ss = (code[0] >> 4) & 3;
		ctx->insn = ETCA_INS_POP;
		parseABM(ctx, code[1]);

		code += 2;
		code_len -= 2;
		(*size) += 2;
	} else if (code_len >= 2 && code[0] >> 6 == 0 &&
		   (code[0] & 0xF) == 0xd) {
		ctx->ss = (code[0] >> 4) & 3;
		ctx->insn = ETCA_INS_PUSH;
		parseABM(ctx, code[1]);

		code += 2;
		code_len -= 2;
		(*size) += 2;
	} else if (code_len >= 2 && code[0] >> 6 == 1 &&
		   (code[0] & 0xF) == 0xd) {
		ctx->ss = (code[0] >> 4) & 3;
		ctx->insn = ETCA_INS_PUSH;
		parseRI(ctx, code[1], ctx->insn);

		code += 2;
		code_len -= 2;
		(*size) += 2;
	} else if (code_len >= 2 && code[0] == 0x9F &&
		   ((code[1] >> 2) & 3) == 0) {
		// clang-format off
		switch (code[1] & 3)
		{
		case 0: ctx->insn = ETCA_INS_DATA_PREFETCH; break;
		case 1: ctx->insn = ETCA_INS_INSTRUCTION_PREFETCH; break;
		case 2: ctx->insn = ETCA_INS_DCACHE_FLUSH; break;
		case 3: ctx->insn = ETCA_INS_DCACHE_INVALIDATE; break;
		}
		// clang-format on

		ctx->single_reg.present = true;
		ctx->single_reg.a = code[1] >> 5;

		code += 2;
		code_len -= 2;
		(*size) += 2;
	} else if (code_len >= 2 && code[0] == 0xaf) {
		if ((code[1] >> 4) & 1)
			ctx->insn = ETCA_INS_ABS_CALL;
		else
			ctx->insn = ETCA_INS_ABS_JMP;

		if (ctx->pfx_cond.present)
			return false;

		ctx->cond = code[1] & 0xF;

		ctx->single_reg.present = true;
		ctx->single_reg.a = code[1] >> 5;

		code += 2;
		code_len -= 2;
		(*size) += 2;
	} else if (code_len >= 2 && code[0] >> 4 == 0xb) {
		ctx->insn = ETCA_INS_REL_CALL;

		uint64_t d = (code[0] & 0xF) << 8 | code[1];
		d = SignExtend64(d, 12);
		ctx->rel.present = true;
		ctx->rel.extended = d;

		code += 2;
		code_len -= 2;
		(*size) += 2;
	} else if (code_len >= 2 && code[0] >> 5 == 4) {
		ctx->insn = ETCA_INS_REL_JMP;

		if (ctx->pfx_cond.present)
			return false;

		ctx->cond = code[0] & 0xF;

		uint64_t d = ((code[0] >> 4) & 1) << 8 | code[1];
		d = SignExtend64(d, 9);
		ctx->rel.present = true;
		ctx->rel.extended = d;

		code += 2;
		code_len -= 2;
		(*size) += 2;
	} else if (code_len && code[0] >> 4 == 0xF &&
		   code_len >= 1 + (1 << (code[0] & 3))) {
		ctx->ss = code[0] & 3;
		int sz = 1 << ctx->ss;

		uint64_t d = 0;
		for (int i = 0; i < sz; i++) {
			d <<= 8;
			d |= code[i + 1];
		}
		ctx->rel.present = true;
		ctx->rel.extended = d;

		// clang-format off
		switch ((code[0] >> 2) & 3) {
		case 0: ctx->insn = ETCA_INS_REL_JMP; break;
		case 1: ctx->insn = ETCA_INS_ABS_JMP; break;
		case 2: ctx->insn = ETCA_INS_REL_CALL; break;
		case 3: ctx->insn = ETCA_INS_ABS_CALL; break;
		}
		// clang-format on

		if (ctx->insn == ETCA_INS_REL_JMP ||
		    ctx->insn == ETCA_INS_REL_CALL)
			d = SignExtend64(d, sz * 8);

		code += sz + 1;
		code_len -= sz + 1;
		(*size) += sz + 1;
	} else if (code_len >= 2 && code[0] >> 7 == 0 &&
		   code[0] >> 2 != 7 /* 0b111 */) {
		bool imm = code[0] & (1 << 6);

		if (imm) {
			parseRI(ctx, code[1], ctx->insn);
		} else {
			parseABM(ctx, code[1]);
		}

		/* abm with fi is treated as imm */
		if (!imm && ctx->abm.m == 1 &&
		    (ctx->abm.b == 2 || ctx->abm.b == 3)) {
			imm = true;
		}

		ctx->insn = parseBaseOpcode(code[0] & 0xF, imm);
		if (ctx->insn == ETCA_INS_INVALID)
			return false;

		ctx->ss = (code[0] >> 4) & 3;

		code += 2;
		code_len -= 2;
		(*size) += 2;
	} else {
		return false;
	}

	*code_len_p = code_len;
	*code_p = code;

	return true;
}

typedef struct {
	uint8_t scale : 2;
	uint8_t index : 3;
	uint8_t base : 3;
} sib_byte;

static sib_byte parseSib(uint8_t b)
{
	return (sib_byte){ b >> 6, (b >> 3) & 3, b & 3 };
}

static uint64_t parseMultiByteUInt(const uint8_t *code, size_t nb)
{
	uint64_t imm = 0;
	for (size_t i = 0; i < nb; i++) {
		imm <<= 8;
		imm |= code[i];
	}
	return imm;
}

static bool parseM(etca_info *info, size_t ptrWidthB, DecodeIsntCtx *ctx,
		   const uint8_t **code_p, size_t *code_len_p, uint16_t *size)
{
	const uint8_t *code = *code_p;
	size_t code_len = *code_len_p;

	if (ctx->abm.m == 0) {
		/* base */
	} else if (ctx->abm.m == 1 && ctx->abm.b == 0 && ctx->abm.a != 0 &&
		   ctx->abm.a != 4) {
		/* from mo2 */

		if (!code_len)
			return false;
		sib_byte sib = parseSib(code[0]);

		if (ctx->abm.a == 1) {
			/* sib, dP, i8 || [dP], i8 */

			size_t dPWidth = ptrWidthB;
			if (dPWidth == 8 &&
			    !(ctx->pfx_rex.present && ctx->pfx_rex.q))
				dPWidth = 4;

			if (!(code_len >= dPWidth + 2))
				return false;

			uint64_t dP = parseMultiByteUInt(&code[1], dPWidth);
			uint8_t i8 = code[1 + dPWidth];

			cs_etca_op_mem memop = { 0 };
			memop.displacement = dP;

			info->op.operands[0].type = ETCA_OP_MEM;
			info->op.operands[0].mem = memop;

			info->op.operands[1].type = ETCA_OP_IMM;
			info->op.operands[1].imm = i8;

			code += 2 + ptrWidthB;
			code_len -= 2 + ptrWidthB;
			(*size) += 2 + ptrWidthB;
		} else if (ctx->abm.a == 2) {
			/* sib, i8 || [sib.b], i8 */

			if (!(code_len >= 2))
				return false;

			uint8_t i8 = code[1];

			cs_etca_op_mem memop = { 0 };
			memop.base.enabled = true;
			memop.base.base = sib.base;

			info->op.operands[0].type = ETCA_OP_MEM;
			info->op.operands[0].mem = memop;

			info->op.operands[1].type = ETCA_OP_IMM;
			info->op.operands[1].imm = i8;

			code += 2;
			code_len -= 2;
			(*size) += 2;
		} else if (ctx->abm.a == 3) {
			/* sib, dP, i8 || [sib.b + dP], i8 */

			size_t dPWidth = ptrWidthB;
			if (dPWidth == 8 &&
			    !(ctx->pfx_rex.present && ctx->pfx_rex.q))
				dPWidth = 4;

			if (!(code_len >= dPWidth + 2))
				return false;

			uint64_t dP = parseMultiByteUInt(&code[1], dPWidth);
			uint8_t i8 = code[1 + dPWidth];

			cs_etca_op_mem memop = { 0 };
			memop.base.enabled = true;
			memop.base.base = sib.base;
			memop.displacement = dP;

			info->op.operands[0].type = ETCA_OP_MEM;
			info->op.operands[0].mem = memop;

			info->op.operands[1].type = ETCA_OP_IMM;
			info->op.operands[1].imm = i8;

			code += 2 + ptrWidthB;
			code_len -= 2 + ptrWidthB;
			(*size) += 2 + ptrWidthB;
		} else if (ctx->abm.a == 5) {
			/* sib, dP, i8 || [2^sib.s*sib.x + dP], i8 */

			size_t dPWidth = ptrWidthB;
			if (dPWidth == 8 &&
			    !(ctx->pfx_rex.present && ctx->pfx_rex.q))
				dPWidth = 4;

			if (!(code_len >= dPWidth + 2))
				return false;

			uint64_t dP = parseMultiByteUInt(&code[1], dPWidth);
			uint8_t i8 = code[1 + dPWidth];

			cs_etca_op_mem memop = { 0 };
			memop.index.enabled = true;
			memop.index.index = sib.index;
			memop.index.index_multiplier_log2 = sib.scale;
			memop.displacement = dP;

			info->op.operands[0].type = ETCA_OP_MEM;
			info->op.operands[0].mem = memop;

			info->op.operands[1].type = ETCA_OP_IMM;
			info->op.operands[1].imm = i8;

			code += 2 + ptrWidthB;
			code_len -= 2 + ptrWidthB;
			(*size) += 2 + ptrWidthB;
		} else if (ctx->abm.a == 6) {
			/* sib, i8 || [2^sib.s*sib.x + sib.b], i8 */

			if (!(code_len >= 2))
				return false;

			uint8_t i8 = code[1];

			cs_etca_op_mem memop = { 0 };
			memop.index.enabled = true;
			memop.index.index = sib.index;
			memop.index.index_multiplier_log2 = sib.scale;
			memop.base.enabled = true;
			memop.base.base = sib.base;

			info->op.operands[0].type = ETCA_OP_MEM;
			info->op.operands[0].mem = memop;

			info->op.operands[1].type = ETCA_OP_IMM;
			info->op.operands[1].imm = i8;

			code += 2 + ptrWidthB;
			code_len -= 2 + ptrWidthB;
			(*size) += 2 + ptrWidthB;
		} else if (ctx->abm.a == 7) {
			/* sib, dP, i8 || [2^sib.s*sib.x + sib.b + dP], i8 */

			size_t dPWidth = ptrWidthB;
			if (dPWidth == 8 &&
			    !(ctx->pfx_rex.present && ctx->pfx_rex.q))
				dPWidth = 4;

			if (!(code_len >= dPWidth + 2))
				return false;

			uint64_t dP = parseMultiByteUInt(&code[1], dPWidth);
			uint8_t i8 = code[1 + dPWidth];

			cs_etca_op_mem memop = { 0 };
			memop.index.enabled = true;
			memop.index.index = sib.index;
			memop.index.index_multiplier_log2 = sib.scale;
			memop.base.enabled = true;
			memop.base.base = sib.base;
			memop.displacement = dP;

			info->op.operands[0].type = ETCA_OP_MEM;
			info->op.operands[0].mem = memop;

			info->op.operands[1].type = ETCA_OP_IMM;
			info->op.operands[1].imm = i8;

			code += 2 + ptrWidthB;
			code_len -= 2 + ptrWidthB;
			(*size) += 2 + ptrWidthB;
		}
	}
	// TODO: finish mo2; mo1
	else
		return false;

	*code_len_p = code_len;
	*code_p = code;

	return true;
}

// returns true if valid
bool Etca_getInstruction(csh ud, const uint8_t *code, size_t code_len,
			 MCInst *mcInstr, uint16_t * /* out */ size,
			 uint64_t address, void *infoIn)
{
	etca_info *info = infoIn;
	// cs_detail *detail = mcInstr->flat_insn->detail;

	size_t ptrWidthLog2;
	// clang-format off
	switch (mcInstr->csh->mode) {
	case CS_MODE_ETCA16: ptrWidthLog2 = 1; break;
	case CS_MODE_ETCA32: ptrWidthLog2 = 2; break;
	case CS_MODE_ETCA64: ptrWidthLog2 = 3; break;
	default: ptrWidthLog2 = 1; break;
	}
	// clang-format on
	size_t ptrWidthB = 1 << ptrWidthLog2;

	DecodeIsntCtx ctx = { 0 };
	ctx.insn = ETCA_INS_INVALID;
	ctx.cond = ETCA_COND_ALWAYS;
	*size = 0;

	/* conditional prefix */
	if (code_len && code[0] >> 4 == 2 + 8 /* 0b1010 */ &&
	    (code[0] & 0xF) < 14) {
		// cond prefix of always / never isn't allowed
		ctx.pfx_cond.present = true;
		ctx.cond = code[0] & 0xF;
		code++;
		code_len--;
		(*size)++;
	}

	/* register expansion prefix */
	if (code_len && code[0] >> 4 == 4 + 8 /* 0b1100 */) {
		ctx.pfx_rex.present = true;
		ctx.pfx_rex.q = (code[0] >> 3) & 1;
		ctx.pfx_rex.a = (code[0] >> 2) & 1;
		ctx.pfx_rex.b = (code[0] >> 1) & 1;
		ctx.pfx_rex.x = (code[0] >> 0) & 1;
		code++;
		code_len--;
		(*size)++;
	}

	// if (code_len && code[0] >> 4 == 1 + 4 + 8 /* 0b1101 */)
	//    unused prefix

	if (!parseCoreOp(&ctx, &code, &code_len, size))
		return false;

	if (ctx.abm.present && ctx.abm.m == 1 && ctx.abm.b == 2) {
		/* 1B full immediate */
		if (!(code_len >= 1))
			return false;
		ctx.abm.present = false;
		ctx.ri.present = true;
		ctx.ri.r = ctx.abm.a;
		ctx.ri.imm = code[0];

		code += 1;
		code_len -= 1;
		(*size) += 1;
	} else if (ctx.abm.present && ctx.abm.m == 1 && ctx.abm.b == 3) {
		/* nB full immediate */
		size_t sz = 1 << ctx.ss;
		if (sz == 8 && !(ctx.pfx_rex.present && ctx.pfx_rex.q))
			sz = 4;

		if (!(code_len >= sz))
			return false;
		ctx.abm.present = false;
		ctx.ri.present = true;
		ctx.ri.r = ctx.abm.a;
		ctx.ri.imm = parseMultiByteUInt(code, sz);

		code += sz;
		code_len -= sz;
		(*size) += sz;
	}

	memset(info, 0, sizeof(*info));
	info->op.cond = ctx.cond;
	info->op.insn = ctx.insn;
	info->op.ss = ctx.ss;

	if (ctx.rel.present) {
		info->op.op_count = 1;

		cs_etca_op *rel = &info->op.operands[0];
		rel->type = ETCA_OP_IMM;
		rel->imm = ctx.rel.extended;
	} else if (ctx.ri.present) {
		info->op.op_count = 2;

		info->op.operands[0].type = ETCA_OP_REG;
		info->op.operands[0].reg =
			((ctx.pfx_rex.present && ctx.pfx_rex.a) ?
				 ETCA_REG_FIRST_REX :
				 ETCA_REG_FIRST_BASE) +
			ctx.ri.r;

		info->op.operands[1].type = ETCA_OP_IMM;
		info->op.operands[1].imm = ctx.ri.imm;
	} else if (ctx.abm.present) {
		info->op.op_count = 2;

		info->op.operands[0].type = ETCA_OP_REG;
		info->op.operands[0].reg =
			((ctx.pfx_rex.present && ctx.pfx_rex.a) ?
				 ETCA_REG_FIRST_REX :
				 ETCA_REG_FIRST_BASE) +
			ctx.abm.a;

		info->op.operands[1].type = ETCA_OP_REG;
		info->op.operands[1].reg =
			((ctx.pfx_rex.present && ctx.pfx_rex.a) ?
				 ETCA_REG_FIRST_REX :
				 ETCA_REG_FIRST_BASE) +
			ctx.abm.b;

		if (!parseM(info, ptrWidthB, &ctx, &code, &code_len, size))
			return false;
	} else if (ctx.single_reg.present) {
		info->op.op_count = 1;

		info->op.operands[0].type = ETCA_OP_REG;
		info->op.operands[0].reg =
			((ctx.pfx_rex.present && ctx.pfx_rex.a) ?
				 ETCA_REG_FIRST_REX :
				 ETCA_REG_FIRST_BASE) +
			ctx.single_reg.a;
	}

	// TODO: add_group

	return true;
}

#ifndef CAPSTONE_DIET
void Etca_reg_access(const cs_insn *insn, cs_regs regs_read,
		     uint8_t *regs_read_count, cs_regs regs_write,
		     uint8_t *regs_write_count)
{
	*regs_read_count = 0;
	*regs_write_count = 0;
	// TODO
}
#endif

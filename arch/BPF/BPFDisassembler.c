/* Capstone Disassembly Engine */
/* BPF Backend by david942j <david942j@gmail.com>, 2019 */
/* SPDX-FileCopyrightText: 2024 Roee Toledano <roeetoledano10@gmail.com> */
/* SPDX-License-Identifier: BSD-3 */

#ifdef CAPSTONE_HAS_BPF

#include <string.h>
#include <stddef.h> // offsetof macro

#include "BPFConstants.h"
#include "BPFDisassembler.h"
#include "BPFMapping.h"
#include "../../Mapping.h"
#include "../../cs_priv.h"
#include "../../utils.h"

///< Malloc bpf_internal, also checks if code_len is large enough.
static bpf_internal *alloc_bpf_internal(const size_t code_len)
{
	bpf_internal *bpf;

	if (code_len < 8)
		return NULL;
	bpf = cs_mem_malloc(sizeof(bpf_internal));
	if (bpf == NULL)
		return NULL;
	/* default value */
	bpf->insn_size = 8;
	return bpf;
}

///< Fetch a cBPF structure from code
static bpf_internal *fetch_cbpf(MCInst *instr, const uint8_t *code,
				const size_t code_len)
{
	bpf_internal *bpf;

	bpf = alloc_bpf_internal(code_len);
	if (bpf == NULL)
		return NULL;

	bpf->op = readBytes16(instr, code);
	bpf->jt = code[2];
	bpf->jf = code[3];
	bpf->k = readBytes32(instr, code + 4);
	return bpf;
}

///< Fetch an eBPF structure from code
static bpf_internal *fetch_ebpf(MCInst *instr, const uint8_t *code,
				const size_t code_len)
{
	bpf_internal *bpf;

	bpf = alloc_bpf_internal(code_len);
	if (bpf == NULL)
		return NULL;

	bpf->op = (uint16_t)code[0];
	bpf->dst = code[1] & 0xf;
	bpf->src = (code[1] & 0xf0) >> 4;

	// eBPF has one 16-byte instruction: BPF_LD | BPF_DW | BPF_IMM,
	// in this case imm is combined with the next block's imm.
	if (bpf->op == (BPF_CLASS_LD | BPF_SIZE_DW | BPF_MODE_IMM)) {
		if (code_len < 16) {
			cs_mem_free(bpf);
			return NULL;
		}
		bpf->k = readBytes32(instr, code + 4) |
			 (((uint64_t)readBytes32(instr, code + 12)) << 32);
		bpf->insn_size = 16;
	} else {
		bpf->offset = readBytes16(instr, code + 2);
		bpf->k = readBytes32(instr, code + 4);
	}
	return bpf;
}

#define CHECK_READABLE_REG(ud, reg) \
	do { \
		if (!((reg) >= BPF_REG_R0 && (reg) <= BPF_REG_R10)) \
			return false; \
	} while (0)

#define CHECK_WRITEABLE_REG(ud, reg) \
	do { \
		if (!((reg) >= BPF_REG_R0 && (reg) < BPF_REG_R10)) \
			return false; \
	} while (0)

#define CHECK_READABLE_AND_PUSH(ud, MI, r) \
	do { \
		CHECK_READABLE_REG(ud, r + BPF_REG_R0); \
		MCOperand_CreateReg0(MI, r + BPF_REG_R0); \
	} while (0)

#define CHECK_WRITABLE_AND_PUSH(ud, MI, r) \
	do { \
		CHECK_WRITEABLE_REG(ud, r + BPF_REG_R0); \
		MCOperand_CreateReg0(MI, r + BPF_REG_R0); \
	} while (0)

static bool decodeLoad(MCInst *MI, bpf_internal *bpf)
{
	if (!EBPF_MODE(MI->csh->mode)) {
		/*
		 *  +-----+-----------+--------------------+
		 *  | ldb |    [k]    |       [x+k]        |
		 *  | ldh |    [k]    |       [x+k]        |
		 *  +-----+-----------+--------------------+
		 */
		if (BPF_SIZE(bpf->op) == BPF_SIZE_DW)
			return false;
		if (BPF_SIZE(bpf->op) == BPF_SIZE_B ||
		    BPF_SIZE(bpf->op) == BPF_SIZE_H) {
			/* no ldx */
			if (BPF_CLASS(bpf->op) != BPF_CLASS_LD)
				return false;
			/* can only be BPF_ABS and BPF_IND */
			if (BPF_MODE(bpf->op) == BPF_MODE_ABS) {
				MCOperand_CreateImm0(MI, bpf->k);
				return true;
			} else if (BPF_MODE(bpf->op) == BPF_MODE_IND) {
				MCOperand_CreateReg0(MI, BPF_REG_X);
				MCOperand_CreateImm0(MI, bpf->k);
				return true;
			}
			return false;
		}
		/*
		 *  +-----+----+------+------+-----+-------+
		 *  | ld  | #k | #len | M[k] | [k] | [x+k] |
		 *  +-----+----+------+------+-----+-------+
		 *  | ldx | #k | #len | M[k] | 4*([k]&0xf) |
		 *  +-----+----+------+------+-------------+
		 */
		switch (BPF_MODE(bpf->op)) {
		default:
			break;
		case BPF_MODE_IMM:
			MCOperand_CreateImm0(MI, bpf->k);
			return true;
		case BPF_MODE_LEN:
			return true;
		case BPF_MODE_MEM:
			MCOperand_CreateImm0(MI, bpf->k);
			return true;
		}
		if (BPF_CLASS(bpf->op) == BPF_CLASS_LD) {
			if (BPF_MODE(bpf->op) == BPF_MODE_ABS) {
				MCOperand_CreateImm0(MI, bpf->k);
				return true;
			} else if (BPF_MODE(bpf->op) == BPF_MODE_IND) {
				MCOperand_CreateReg0(MI, BPF_REG_X);
				MCOperand_CreateImm0(MI, bpf->k);
				return true;
			}
		} else { /* LDX */
			if (BPF_MODE(bpf->op) == BPF_MODE_MSH) {
				MCOperand_CreateImm0(MI, bpf->k);
				return true;
			}
		}
		return false;
	}

	/* eBPF mode */
	/*
	 * - IMM: lddw dst, imm64
	 * - ABS: ld{w,h,b} [k]
	 * - IND: ld{w,h,b} [src]
	 * - MEM: ldx{w,h,b,dw} dst, [src+off]
	 */
	if (BPF_CLASS(bpf->op) == BPF_CLASS_LD) {
		switch (BPF_MODE(bpf->op)) {
		case BPF_MODE_IMM:
			if (bpf->op !=
			    (BPF_CLASS_LD | BPF_SIZE_DW | BPF_MODE_IMM))
				return false;
			CHECK_WRITABLE_AND_PUSH(ud, MI, bpf->dst);
			MCOperand_CreateImm0(MI, bpf->k);
			return true;
		case BPF_MODE_ABS:
			MCOperand_CreateImm0(MI, bpf->k);
			return true;
		case BPF_MODE_IND:
			CHECK_READABLE_AND_PUSH(ud, MI, bpf->src);
			return true;
		}
		return false;
	}
	/* LDX */
	if (BPF_MODE(bpf->op) == BPF_MODE_MEM) {
		CHECK_WRITABLE_AND_PUSH(ud, MI, bpf->dst);
		CHECK_READABLE_AND_PUSH(ud, MI, bpf->src);
		MCOperand_CreateImm0(MI, bpf->offset);
		return true;
	}
	return false;
}

static bool decodeStore(MCInst *MI, bpf_internal *bpf)
{
	/* in cBPF, only BPF_ST* | BPF_MEM | BPF_W is valid
	 * while in eBPF:
	 * - BPF_STX | BPF_XADD | BPF_{W,DW}
	 * - BPF_ST* | BPF_MEM | BPF_{W,H,B,DW}
	 * are valid
	 */
	if (!EBPF_MODE(MI->csh->mode)) {
		/* can only store to M[] */
		if (bpf->op != (BPF_CLASS(bpf->op) | BPF_MODE_MEM | BPF_SIZE_W))
			return false;
		MCOperand_CreateImm0(MI, bpf->k);
		return true;
	}

	/* eBPF */
	if (BPF_MODE(bpf->op) == BPF_MODE_ATOMIC) {
		if (BPF_CLASS(bpf->op) != BPF_CLASS_STX)
			return false;
		if (BPF_SIZE(bpf->op) != BPF_SIZE_W &&
		    BPF_SIZE(bpf->op) != BPF_SIZE_DW)
			return false;
		/* xadd [dst + off], src */
		CHECK_READABLE_AND_PUSH(ud, MI, bpf->dst);
		MCOperand_CreateImm0(MI, bpf->offset);
		CHECK_READABLE_AND_PUSH(ud, MI, bpf->src);
		return true;
	}

	if (BPF_MODE(bpf->op) != BPF_MODE_MEM)
		return false;

	/* st [dst + off], src */
	CHECK_READABLE_AND_PUSH(ud, MI, bpf->dst);
	MCOperand_CreateImm0(MI, bpf->offset);
	if (BPF_CLASS(bpf->op) == BPF_CLASS_ST)
		MCOperand_CreateImm0(MI, bpf->k);
	else
		CHECK_READABLE_AND_PUSH(ud, MI, bpf->src);
	return true;
}

static bool decodeALU(MCInst *MI, bpf_internal *bpf)
{
	/* Set MI->Operands */

	/* cBPF */
	if (!EBPF_MODE(MI->csh->mode)) {
		if (BPF_OP(bpf->op) > BPF_ALU_XOR)
			return false;
		/* cBPF's NEG has no operands */
		if (BPF_OP(bpf->op) == BPF_ALU_NEG)
			return true;
		if (BPF_SRC(bpf->op) == BPF_SRC_K)
			MCOperand_CreateImm0(MI, bpf->k);
		else /* BPF_SRC_X */
			MCOperand_CreateReg0(MI, BPF_REG_X);
		return true;
	}

	/* eBPF */

	if (BPF_OP(bpf->op) > BPF_ALU_END)
		return false;
	/* ENDian's imm must be one of 16, 32, 64 */
	if (BPF_OP(bpf->op) == BPF_ALU_END) {
		if (bpf->k != 16 && bpf->k != 32 && bpf->k != 64)
			return false;
		if (BPF_CLASS(bpf->op) == BPF_CLASS_ALU64 &&
		    BPF_SRC(bpf->op) != BPF_SRC_LITTLE)
			return false;
	}

	/* - op dst, imm
	 * - op dst, src
	 * - neg dst
	 * - le<imm> dst
	 */
	/* every ALU instructions have dst op */
	CHECK_WRITABLE_AND_PUSH(ud, MI, bpf->dst);

	/* special cases */
	if (BPF_OP(bpf->op) == BPF_ALU_NEG)
		return true;
	if (BPF_OP(bpf->op) == BPF_ALU_END) {
		/* bpf->k must be one of 16, 32, 64 */
		bpf->op |= ((uint32_t)bpf->k << 4);
		return true;
	}

	/* normal cases */
	if (BPF_SRC(bpf->op) == BPF_SRC_K) {
		MCOperand_CreateImm0(MI, bpf->k);
	} else { /* BPF_SRC_X */
		CHECK_READABLE_AND_PUSH(ud, MI, bpf->src);
	}
	return true;
}

static bool decodeJump(MCInst *MI, bpf_internal *bpf)
{
	/* cBPF and eBPF are very different in class jump */
	if (!EBPF_MODE(MI->csh->mode)) {
		if (BPF_OP(bpf->op) > BPF_JUMP_JSET)
			return false;

		/* ja is a special case of jumps */
		if (BPF_OP(bpf->op) == BPF_JUMP_JA) {
			MCOperand_CreateImm0(MI, bpf->k);
			return true;
		}

		if (BPF_SRC(bpf->op) == BPF_SRC_K)
			MCOperand_CreateImm0(MI, bpf->k);
		else /* BPF_SRC_X */
			MCOperand_CreateReg0(MI, BPF_REG_X);
		MCOperand_CreateImm0(MI, bpf->jt);
		MCOperand_CreateImm0(MI, bpf->jf);
	} else {
		if (BPF_OP(bpf->op) > BPF_JUMP_JSLE)
			return false;

		/* JMP32 has no CALL/EXIT instruction */
		/* No operands for exit */
		if (BPF_OP(bpf->op) == BPF_JUMP_EXIT)
			return bpf->op == (BPF_CLASS_JMP | BPF_JUMP_EXIT);
		if (BPF_OP(bpf->op) == BPF_JUMP_CALL) {
			if (bpf->op == (BPF_CLASS_JMP | BPF_JUMP_CALL)) {
				MCOperand_CreateImm0(MI, bpf->k);
				return true;
			}
			if (bpf->op ==
			    (BPF_CLASS_JMP | BPF_JUMP_CALL | BPF_SRC_X)) {
				CHECK_READABLE_AND_PUSH(ud, MI, bpf->k);
				return true;
			}
			return false;
		}

		/* ja is a special case of jumps */
		if (BPF_OP(bpf->op) == BPF_JUMP_JA) {
			if (BPF_SRC(bpf->op) != BPF_SRC_K)
				return false;
			if (BPF_CLASS(bpf->op) == BPF_CLASS_JMP)
				MCOperand_CreateImm0(MI, bpf->offset);
			else
				MCOperand_CreateImm0(MI, bpf->k);

			return true;
		}

		/* <j>  dst, src, +off */
		CHECK_READABLE_AND_PUSH(ud, MI, bpf->dst);
		if (BPF_SRC(bpf->op) == BPF_SRC_K)
			MCOperand_CreateImm0(MI, bpf->k);
		else
			CHECK_READABLE_AND_PUSH(ud, MI, bpf->src);
		MCOperand_CreateImm0(MI, bpf->offset);
	}
	return true;
}

static bool decodeReturn(MCInst *MI, bpf_internal *bpf)
{
	/* Here only handles the BPF_RET class in cBPF */
	switch (BPF_RVAL(bpf->op)) {
	case BPF_SRC_K:
		MCOperand_CreateImm0(MI, bpf->k);
		return true;
	case BPF_SRC_X:
		MCOperand_CreateReg0(MI, BPF_REG_X);
		return true;
	case BPF_SRC_A:
		MCOperand_CreateReg0(MI, BPF_REG_A);
		return true;
	}
	return false;
}

static bool decodeMISC(MCInst *MI, bpf_internal *bpf)
{
	uint16_t op = bpf->op ^ BPF_CLASS_MISC;
	return op == BPF_MISCOP_TAX || op == BPF_MISCOP_TXA;
}

///< 1. Check if the instruction is valid
///< 2. Set MI->opcode
///< 3. Set MI->Operands
static bool getInstruction(MCInst *MI, bpf_internal *bpf)
{
	cs_detail *detail;

	detail = MI->flat_insn->detail;
	// initialize detail
	if (detail) {
		memset(detail, 0, offsetof(cs_detail, bpf) + sizeof(cs_bpf));
	}

	MCInst_clear(MI);

	switch (BPF_CLASS(bpf->op)) {
	default: /* should never happen */
		return false;
	case BPF_CLASS_LD:
	case BPF_CLASS_LDX:
		return decodeLoad(MI, bpf);
	case BPF_CLASS_ST:
	case BPF_CLASS_STX:
		return decodeStore(MI, bpf);
	case BPF_CLASS_ALU:
		return decodeALU(MI, bpf);
	case BPF_CLASS_JMP:
		return decodeJump(MI, bpf);
	case BPF_CLASS_RET:
		/* case BPF_CLASS_JMP32: */
		if (EBPF_MODE(MI->csh->mode))
			return decodeJump(MI, bpf);
		else
			return decodeReturn(MI, bpf);
	case BPF_CLASS_MISC:
		/* case BPF_CLASS_ALU64: */
		if (EBPF_MODE(MI->csh->mode))
			return decodeALU(MI, bpf);
		else
			return decodeMISC(MI, bpf);
	}
}

// Check for regular load instructions
#define REG_LOAD_CASE(c) \
	case BPF_SIZE_##c: \
		if (BPF_CLASS(opcode) == BPF_CLASS_LD) \
			return BPF_INS_LD##c; \
		else \
			return BPF_INS_LDX##c;

static bpf_insn op2insn_ld_cbpf(unsigned opcode)
{
	switch (BPF_SIZE(opcode)) {
		REG_LOAD_CASE(W);
		REG_LOAD_CASE(H);
		REG_LOAD_CASE(B);
		REG_LOAD_CASE(DW);
	}

	return BPF_INS_INVALID;
}
#undef REG_LOAD_CASE

// Check for packet load instructions
#define PACKET_LOAD_CASE(c) \
	case BPF_SIZE_##c: \
		if (BPF_MODE(opcode) == BPF_MODE_ABS) \
			return BPF_INS_LDABS##c; \
		else if (BPF_MODE(opcode) == BPF_MODE_IND) \
			return BPF_INS_LDIND##c; \
		else \
			return BPF_INS_INVALID;

static bpf_insn op2insn_ld_ebpf(unsigned opcode)
{
	if (BPF_CLASS(opcode) == BPF_CLASS_LD) {
		switch (BPF_SIZE(opcode)) {
			PACKET_LOAD_CASE(W);
			PACKET_LOAD_CASE(H);
			PACKET_LOAD_CASE(B);
		}
	}

	// If it's not a packet load instruction, it must be a regular load instruction
	return op2insn_ld_cbpf(opcode);
}
#undef PACKET_LOAD_CASE

/* During parsing we already checked to make sure the size is D/DW and 
 * mode is STX and not ST, so we don't need to check again*/
#define ALU_CASE_REG(c) \
	case BPF_ALU_##c: \
		if (BPF_SIZE(opcode) == BPF_SIZE_W) \
			return BPF_INS_A##c; \
		else \
			return BPF_INS_A##c##64;

#define ALU_CASE_FETCH(c) \
	case BPF_ALU_##c | BPF_MODE_FETCH: \
		if (BPF_SIZE(opcode) == BPF_SIZE_W) \
			return BPF_INS_AF##c; \
		else \
			return BPF_INS_AF##c##64;

#define COMPLEX_CASE(c) \
	case BPF_ATOMIC_##c | BPF_MODE_FETCH: \
		if (BPF_SIZE(opcode) == BPF_SIZE_DW) \
			return BPF_INS_A##c##64; \
		else \
			return BPF_INS_INVALID;

#define CASE(c) \
	case BPF_SIZE_##c: \
		if (BPF_CLASS(opcode) == BPF_CLASS_ST) \
			return BPF_INS_ST##c; \
		else \
			return BPF_INS_STX##c;

static bpf_insn op2insn_st(unsigned opcode, const uint32_t imm)
{
	/*
	 * - BPF_STX | ALU atomic operations | BPF_{W,DW}
	 * - BPF_STX | Complex atomic operations | BPF_{DW}
	 * - BPF_ST* | BPF_MEM | BPF_{W,H,B,DW}
	 */

	if (BPF_MODE(opcode) == BPF_MODE_ATOMIC) {
		switch (imm) {
			ALU_CASE_REG(ADD);
			ALU_CASE_REG(OR);
			ALU_CASE_REG(AND);
			ALU_CASE_REG(XOR);
			ALU_CASE_FETCH(ADD);
			ALU_CASE_FETCH(OR);
			ALU_CASE_FETCH(AND);
			ALU_CASE_FETCH(XOR);
			COMPLEX_CASE(XCHG);
			COMPLEX_CASE(CMPXCHG);
		default: // Reached if complex atomic operation is used without fetch modifier
			return BPF_INS_INVALID;
		}
	}

	/* should be BPF_MEM */
	switch (BPF_SIZE(opcode)) {
		CASE(W);
		CASE(H);
		CASE(B);
		CASE(DW);
	}

	return BPF_INS_INVALID;
}
#undef CASE

#define CASE(c) \
	case BPF_ALU_##c: \
		CASE_IF(c)

#define CASE_IF(c) \
	do { \
		if (BPF_CLASS(opcode) == BPF_CLASS_ALU) \
			return BPF_INS_##c; \
		else \
			return BPF_INS_##c##64; \
	} while (0)

static bpf_insn op2insn_alu(unsigned opcode, const uint16_t off,
			    const bool is_ebpf)
{
	/* Endian is a special case */
	if (BPF_OP(opcode) == BPF_ALU_END) {
		if (BPF_CLASS(opcode) == BPF_CLASS_ALU64) {
			switch (opcode ^ BPF_CLASS_ALU64 ^ BPF_ALU_END ^
				BPF_SRC_LITTLE) {
			case (16 << 4):
				return BPF_INS_BSWAP16;
			case (32 << 4):
				return BPF_INS_BSWAP32;
			case (64 << 4):
				return BPF_INS_BSWAP64;
			default:
				return BPF_INS_INVALID;
			}
		}

		switch (opcode ^ BPF_CLASS_ALU ^ BPF_ALU_END) {
		case BPF_SRC_LITTLE | (16 << 4):
			return BPF_INS_LE16;
		case BPF_SRC_LITTLE | (32 << 4):
			return BPF_INS_LE32;
		case BPF_SRC_LITTLE | (64 << 4):
			return BPF_INS_LE64;
		case BPF_SRC_BIG | (16 << 4):
			return BPF_INS_BE16;
		case BPF_SRC_BIG | (32 << 4):
			return BPF_INS_BE32;
		case BPF_SRC_BIG | (64 << 4):
			return BPF_INS_BE64;
		}
		return BPF_INS_INVALID;
	}

	switch (BPF_OP(opcode)) {
		CASE(ADD);
		CASE(SUB);
		CASE(MUL);
		CASE(OR);
		CASE(AND);
		CASE(LSH);
		CASE(RSH);
		CASE(NEG);
		CASE(XOR);
		CASE(ARSH);
	case BPF_ALU_DIV:
		if (!is_ebpf || off == 0)
			CASE_IF(DIV);
		else if (off == 1)
			CASE_IF(SDIV);
		else
			return BPF_INS_INVALID;
	case BPF_ALU_MOD:
		if (!is_ebpf || off == 0)
			CASE_IF(MOD);
		else if (off == 1)
			CASE_IF(SMOD);
		else
			return BPF_INS_INVALID;
	case BPF_ALU_MOV:
		/* BPF_CLASS_ALU can have: mov, mov8s, mov16s
		 * BPF_CLASS_ALU64 can have: mov, mov8s, mov16s, mov32s
		 * */
		if (off == 0)
			CASE_IF(MOV);
		else if (off == 8)
			CASE_IF(MOVSB);
		else if (off == 16)
			CASE_IF(MOVSH);
		else if (off == 32 && BPF_CLASS(opcode) == BPF_CLASS_ALU64)
			return BPF_INS_MOVSW64;
		else
			return BPF_INS_INVALID;
	}

	return BPF_INS_INVALID;
}
#undef CASE_IF
#undef CASE

#define BPF_CALLX (BPF_CLASS_JMP | BPF_JUMP_CALL | BPF_SRC_X)

#define CASE(c) \
	case BPF_JUMP_##c: \
		if (BPF_CLASS(opcode) == BPF_CLASS_JMP) \
			return BPF_INS_##c; \
		else \
			return BPF_INS_##c##32;

#define SPEC_CASE(c) \
	case BPF_JUMP_##c: \
		if (BPF_CLASS(opcode) == BPF_CLASS_JMP) \
			return BPF_INS_##c; \
		else \
			return BPF_INS_INVALID;

static bpf_insn op2insn_jmp(unsigned opcode)
{
	if (opcode == BPF_CALLX) {
		return BPF_INS_CALLX;
	}

	switch (BPF_OP(opcode)) {
	case BPF_JUMP_JA:
		if (BPF_CLASS(opcode) == BPF_CLASS_JMP)
			return BPF_INS_JA;
		else
			return BPF_INS_JAL;
		CASE(JEQ);
		CASE(JGT);
		CASE(JGE);
		CASE(JSET);
		CASE(JNE);
		CASE(JSGT);
		CASE(JSGE);
		SPEC_CASE(CALL);
		SPEC_CASE(EXIT);
		CASE(JLT);
		CASE(JLE);
		CASE(JSLT);
		CASE(JSLE);
	}

	return BPF_INS_INVALID;
}
#undef SPEC_CASE
#undef CASE
#undef BPF_CALLX

#ifndef CAPSTONE_DIET

static void update_regs_access(MCInst *MI, cs_detail *detail, bpf_insn insn_id,
			       unsigned int opcode)
{
	if (insn_id == BPF_INS_INVALID)
		return;
	/*
	 * In eBPF mode, only these instructions have implicit registers access:
	 * - legacy ld{w,h,b,dw} * // w: r0
	 * - exit // r: r0
	 */
	if (EBPF_MODE(MI->csh->mode)) {
		switch (insn_id) {
		default:
			break;
		case BPF_INS_LDABSW:
		case BPF_INS_LDABSH:
		case BPF_INS_LDABSB:
		case BPF_INS_LDINDW:
		case BPF_INS_LDINDH:
		case BPF_INS_LDINDB:
		case BPF_INS_LDDW:
			if (BPF_MODE(opcode) == BPF_MODE_ABS ||
			    BPF_MODE(opcode) == BPF_MODE_IND)
				map_add_implicit_write(MI, BPF_REG_R0);
			break;
		case BPF_INS_EXIT:
			map_add_implicit_read(MI, BPF_REG_R0);
			break;
		}
		return;
	}

	/* cBPF mode */
	switch (BPF_CLASS(opcode)) {
	default:
		break;
	case BPF_CLASS_LD:
		map_add_implicit_write(MI, BPF_REG_A);
		break;
	case BPF_CLASS_LDX:
		map_add_implicit_write(MI, BPF_REG_X);
		break;
	case BPF_CLASS_ST:
		map_add_implicit_read(MI, BPF_REG_A);
		break;
	case BPF_CLASS_STX:
		map_add_implicit_read(MI, BPF_REG_X);
		break;
	case BPF_CLASS_ALU:
		map_add_implicit_read(MI, BPF_REG_A);
		map_add_implicit_write(MI, BPF_REG_A);
		break;
	case BPF_CLASS_JMP:
		if (insn_id != BPF_INS_JA) // except the unconditional jump
			map_add_implicit_read(MI, BPF_REG_A);
		break;
	/* case BPF_CLASS_RET: */
	case BPF_CLASS_MISC:
		if (insn_id == BPF_INS_TAX) {
			map_add_implicit_read(MI, BPF_REG_A);
			map_add_implicit_write(MI, BPF_REG_X);
		} else {
			map_add_implicit_read(MI, BPF_REG_X);
			map_add_implicit_write(MI, BPF_REG_A);
		}
		break;
	}
}
#endif

static bool setFinalOpcode(MCInst *MI, const bpf_internal *bpf)
{
	bpf_insn id = BPF_INS_INVALID;
#ifndef CAPSTONE_DIET
	cs_detail *detail;

	detail = get_detail(MI);
#endif

	const uint16_t opcode = bpf->op;
	switch (BPF_CLASS(opcode)) {
	default: // will never happen
		break;
	case BPF_CLASS_LD:
	case BPF_CLASS_LDX:
		if (EBPF_MODE(MI->csh->mode))
			id = op2insn_ld_ebpf(opcode);
		else
			id = op2insn_ld_cbpf(opcode);
		add_group(MI, BPF_GRP_LOAD);
		break;
	case BPF_CLASS_ST:
	case BPF_CLASS_STX:
		id = op2insn_st(opcode, bpf->k);
		add_group(MI, BPF_GRP_STORE);
		break;
	case BPF_CLASS_ALU:
		id = op2insn_alu(opcode, bpf->offset, EBPF_MODE(MI->csh->mode));
		add_group(MI, BPF_GRP_ALU);
		break;
	case BPF_CLASS_JMP:
		id = op2insn_jmp(opcode);
#ifndef CAPSTONE_DIET
		if (id == BPF_INS_CALL || id == BPF_INS_CALLX)
			add_group(MI, BPF_GRP_CALL);
		else if (id == BPF_INS_EXIT)
			add_group(MI, BPF_GRP_RETURN);
		else
			add_group(MI, BPF_GRP_JUMP);
#endif
		break;
	case BPF_CLASS_RET:
		/* case BPF_CLASS_JMP32: */
		if (EBPF_MODE(MI->csh->mode)) {
			id = op2insn_jmp(opcode);
			add_group(MI, BPF_GRP_JUMP);
		} else {
			id = BPF_INS_RET;
			add_group(MI, BPF_GRP_RETURN);
		}
		break;
	// BPF_CLASS_MISC and BPF_CLASS_ALU64 have exactly same value
	case BPF_CLASS_MISC:
		/* case BPF_CLASS_ALU64: */
		if (EBPF_MODE(MI->csh->mode)) {
			// ALU64 in eBPF
			id = op2insn_alu(opcode, bpf->offset, true);
			add_group(MI, BPF_GRP_ALU);
		} else {
			if (BPF_MISCOP(opcode) == BPF_MISCOP_TXA)
				id = BPF_INS_TXA;
			else
				id = BPF_INS_TAX;
			add_group(MI, BPF_GRP_MISC);
		}
		break;
	}

	if (id == BPF_INS_INVALID)
		return false;

	MCInst_setOpcodePub(MI, id);
#undef PUSH_GROUP

#ifndef CAPSTONE_DIET
	if (detail) {
		update_regs_access(MI, detail, id, opcode);
	}
#endif
	return true;
}

bool BPF_getInstruction(csh ud, const uint8_t *code, size_t code_len,
			MCInst *instr, uint16_t *size, uint64_t address,
			void *info)
{
	bpf_internal *bpf;

	if (EBPF_MODE(instr->csh->mode))
		bpf = fetch_ebpf(instr, code, code_len);
	else
		bpf = fetch_cbpf(instr, code, code_len);
	if (bpf == NULL)
		return false;
	if (!getInstruction(instr, bpf) || !setFinalOpcode(instr, bpf)) {
		cs_mem_free(bpf);
		return false;
	}
	MCInst_setOpcode(instr, bpf->op);

	*size = bpf->insn_size;
	cs_mem_free(bpf);

	return true;
}

#endif

/* Capstone Disassembly Engine */
/* BPF Backend by david942j <david942j@gmail.com>, 2019 */

#ifdef CAPSTONE_HAS_BPF

#include <string.h>
#include <stddef.h> // offsetof macro

#include "BPFConstants.h"
#include "BPFDisassembler.h"
#include "BPFMapping.h"
#include "../../cs_priv.h"

static uint16_t read_u16(cs_struct *ud, const uint8_t *code)
{
	if (MODE_IS_BIG_ENDIAN(ud->mode))
		return (((uint16_t)code[0] << 8) | code[1]);
	else
		return (((uint16_t)code[1] << 8) | code[0]);
}

static uint32_t read_u32(cs_struct *ud, const uint8_t *code)
{
	if (MODE_IS_BIG_ENDIAN(ud->mode))
		return ((uint32_t)read_u16(ud, code) << 16) | read_u16(ud, code + 2);
	else
		return ((uint32_t)read_u16(ud, code + 2) << 16) | read_u16(ud, code);
}

static uint64_t read_u64(cs_struct *ud, const uint8_t *code)
{
	if (MODE_IS_BIG_ENDIAN(ud->mode))
		return ((uint64_t)read_u32(ud, code) << 32) | read_u32(ud, code + 4);
	else
		return ((uint64_t)read_u32(ud, code + 4) << 32) | read_u32(ud, code);
}

///< Malloc bpf_internal, also checks if code_len is large enough.
static bpf_internal *alloc_bpf_internal(size_t code_len)
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
static bpf_internal* fetch_cbpf(cs_struct *ud, const uint8_t *code,
		size_t code_len)
{
	bpf_internal *bpf;

	bpf = alloc_bpf_internal(code_len);
	if (bpf == NULL)
		return NULL;

	bpf->op = read_u16(ud, code);
	bpf->jt = code[2];
	bpf->jf = code[3];
	bpf->k = read_u32(ud, code + 4);
	return bpf;
}

///< Fetch an eBPF structure from code
static bpf_internal* fetch_ebpf(cs_struct *ud, const uint8_t *code,
		size_t code_len)
{
	bpf_internal *bpf;

	bpf = alloc_bpf_internal(code_len);
	if (bpf == NULL)
		return NULL;

	bpf->op = (uint16_t)code[0];

	// eBPF has one 16-byte instruction: BPF_LD | BPF_DW | BPF_IMM,
	// in this case imm is fetched from the next 8-byte block.
	if (bpf->op == (BPF_CLASS_LD | BPF_SIZE_DW | BPF_MODE_IMM)) {
		if (code_len < 16) {
			cs_mem_free(bpf);
			return NULL;
		}
		bpf->k = read_u64(ud, code + 8);
		bpf->insn_size = 16;
	}
	else {
		bpf->dst = code[1] & 0xf;
		bpf->src = (code[1] & 0xf0) >> 4;
		bpf->offset = read_u16(ud, code + 2);
		bpf->k = read_u32(ud, code + 4);
	}
	return bpf;
}

#define CHECK_READABLE_REG(ud, reg) do { \
		if (! ((reg) >= BPF_REG_R0 && (reg) <= BPF_REG_R10)) \
			return false; \
	} while (0)

#define CHECK_WRITABLE_REG(ud, reg) do { \
		if (! ((reg) >= BPF_REG_R0 && (reg) < BPF_REG_R10)) \
			return false; \
	} while (0)

static bool decodeLoad(cs_struct *ud, MCInst *MI, bpf_internal *bpf)
{
	return true;
}

static bool decodeStore(cs_struct *ud, MCInst *MI, bpf_internal *bpf)
{
	return true;
}

static bool decodeALU(cs_struct *ud, MCInst *MI, bpf_internal *bpf)
{
	/*
	 *  +----------------+--------+--------------------+
	 *  |   4 bits       |  1 bit |   3 bits           |
	 *  | operation code | source | instruction class  |
	 *  +----------------+--------+--------------------+
	 *  (MSB)                                      (LSB)
	 */

	if (!EBPF_MODE(ud)) {
		if (BPF_OP(bpf->op) > BPF_ALU_XOR)
			return false;
	}
	else {
		if (BPF_OP(bpf->op) > BPF_ALU_END)
			return false;
	}

	/* NEG's source must be BPF_SRC_X */
	if (BPF_OP(bpf->op) == BPF_ALU_NEG && BPF_SRC(bpf->op) != BPF_SRC_X)
		return false;
	/* ALU64 class doesn't have ENDian */
	/* ENDian's imm must be one of 16, 32, 64 */
	if (BPF_OP(bpf->op) == BPF_ALU_END) {
		if (BPF_CLASS(bpf->op) == BPF_CLASS_ALU64)
			return false;
		if (bpf->k != 16 && bpf->k != 32 && bpf->k != 64)
			return false;
	}

	/* Set MI->Operands */

	/* cBPF */
	if (!EBPF_MODE(ud)) {
		if (BPF_SRC(bpf->op) == BPF_SRC_K)
			MCOperand_CreateImm0(MI, (int64_t)bpf->k);
		else /* BPF_SRC_X */
			MCOperand_CreateReg0(MI, BPF_REG_X);
		return true;
	}

	/* eBPF */

	/* - op dst, imm
	 * - op dst, src
	 * - neg dst
	 * - le<imm> dst
	 */
	/* every ALU instructions have dst op */
	CHECK_WRITABLE_REG(ud, bpf->dst + BPF_REG_R0);
	MCOperand_CreateReg0(MI, bpf->dst + BPF_REG_R0);

	/* special cases */
	if (BPF_OP(bpf->op) == BPF_ALU_NEG)
		return true;
	if (BPF_OP(bpf->op) == BPF_ALU_END) {
		/* ENDian instructions use BPF_SRC to decide using little or big endian */
		MCInst_setOpcode(MI, MCInst_getOpcode(MI) | (bpf->k << 4));
		return true;
	}

	/* normal cases */
	if (BPF_SRC(bpf->op) == BPF_SRC_K) {
		MCOperand_CreateImm0(MI, (int64_t)bpf->k);
	}
	else { /* BPF_SRC_X */
		CHECK_READABLE_REG(ud, bpf->src + BPF_REG_R0);
		MCOperand_CreateReg0(MI, bpf->src + BPF_REG_R0);
	}
	return true;
}

static bool decodeJump(cs_struct *ud, MCInst *MI, bpf_internal *bpf)
{
	return true;
}

static bool decodeReturn(cs_struct *ud, MCInst *MI, bpf_internal *bpf)
{
	/* Here only handles the BPF_RET class in cBPF */
	switch (BPF_SRC_OLD(bpf->op)) {
	default:
		return false;
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
}

static bool decodeMISC(cs_struct *ud, MCInst *MI, bpf_internal *bpf)
{
	uint16_t op = bpf->op ^ BPF_CLASS_MISC;
	return op == BPF_MISCOP_TAX || op == BPF_MISCOP_TXA;
}

///< 1. Check if the instruction is valid
///< 2. Set MI->opcode
///< 3. Set MI->Operands
static bool getInstruction(cs_struct *ud, MCInst *MI, bpf_internal *bpf)
{
	cs_detail *detail;
	uint8_t opcode;

	detail = MI->flat_insn->detail;
	// initialize detail
	if (detail) {
		memset(detail, 0, offsetof(cs_detail, bpf) + sizeof(cs_bpf));
	}

	opcode = bpf->op;

	MCInst_clear(MI);
	MCInst_setOpcode(MI, opcode);

	switch (BPF_CLASS(opcode)) {
	default: /* should never happen */
		return false;
	case BPF_CLASS_LD:
	case BPF_CLASS_LDX:
		return decodeLoad(ud, MI, bpf);
	case BPF_CLASS_ST:
	case BPF_CLASS_STX:
		return decodeStore(ud, MI, bpf);
	case BPF_CLASS_ALU:
		return decodeALU(ud, MI, bpf);
	case BPF_CLASS_JMP:
		return decodeJump(ud, MI, bpf);
	case BPF_CLASS_RET:
		/* eBPF doesn't have this class */
		if (EBPF_MODE(ud))
			return false;
		return decodeReturn(ud, MI, bpf);
	case BPF_CLASS_MISC:
	/* case BPF_CLASS_ALU64: */
		if (EBPF_MODE(ud))
			return decodeALU(ud, MI, bpf);
		else
			return decodeMISC(ud, MI, bpf);
	}
}

bool BPF_getInstruction(csh ud, const uint8_t *code, size_t code_len,
		MCInst *instr, uint16_t *size, uint64_t _address, void *info)
{
	cs_struct *cs;
	bpf_internal *bpf;

	cs = (cs_struct*)ud;
	if (EBPF_MODE(cs))
		bpf = fetch_ebpf(cs, code, code_len);
	else
		bpf = fetch_cbpf(cs, code, code_len);
	if (bpf == NULL)
		return false;
	if (!getInstruction((cs_struct*)ud, instr, bpf)) {
		cs_mem_free(bpf);
		return false;
	}

	*size = bpf->insn_size;
	cs_mem_free(bpf);

	return true;
}

#endif

/* Capstone Disassembly Engine */
/* BPF Backend by david942j <david942j@gmail.com>, 2019 */
/* SPDX-FileCopyrightText: 2024 Roee Toledano <roeetoledano10@gmail.com> */
/* SPDX-License-Identifier: BSD-3 */

#include <string.h>

#include "BPFConstants.h"
#include "BPFMapping.h"
#include "../../Mapping.h"
#include "../../utils.h"

#ifndef CAPSTONE_DIET
static const name_map group_name_maps[] = {
	{ BPF_GRP_INVALID, NULL },

	{ BPF_GRP_LOAD, "load" },  { BPF_GRP_STORE, "store" },
	{ BPF_GRP_ALU, "alu" },	   { BPF_GRP_JUMP, "jump" },
	{ BPF_GRP_CALL, "call" },  { BPF_GRP_RETURN, "return" },
	{ BPF_GRP_MISC, "misc" },
};
#endif

const char *BPF_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
#else
	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
static const name_map insn_name_maps[BPF_INS_ENDING] = {
	{ BPF_INS_INVALID, NULL },

	{ BPF_INS_ADD, "add" },		{ BPF_INS_SUB, "sub" },
	{ BPF_INS_MUL, "mul" },		{ BPF_INS_DIV, "div" },
	{ BPF_INS_SDIV, "sdiv" },	{ BPF_INS_OR, "or" },
	{ BPF_INS_AND, "and" },		{ BPF_INS_LSH, "lsh" },
	{ BPF_INS_RSH, "rsh" },		{ BPF_INS_NEG, "neg" },
	{ BPF_INS_MOD, "mod" },		{ BPF_INS_SMOD, "smod" },
	{ BPF_INS_XOR, "xor" },		{ BPF_INS_MOV, "mov" },
	{ BPF_INS_MOVSB, "movsb" },	{ BPF_INS_MOVSH, "movsh" },
	{ BPF_INS_ARSH, "arsh" },

	{ BPF_INS_ADD64, "add64" },	{ BPF_INS_SUB64, "sub64" },
	{ BPF_INS_MUL64, "mul64" },	{ BPF_INS_DIV64, "div64" },
	{ BPF_INS_SDIV64, "sdiv64" },	{ BPF_INS_OR64, "or64" },
	{ BPF_INS_AND64, "and64" },	{ BPF_INS_LSH64, "lsh64" },
	{ BPF_INS_RSH64, "rsh64" },	{ BPF_INS_NEG64, "neg64" },
	{ BPF_INS_MOD64, "mod64" },	{ BPF_INS_SMOD64, "smod64" },
	{ BPF_INS_XOR64, "xor64" },	{ BPF_INS_MOV64, "mov64" },
	{ BPF_INS_MOVSB64, "movsb64" }, { BPF_INS_MOVSH64, "movsh64" },
	{ BPF_INS_MOVSW64, "movsw64" }, { BPF_INS_ARSH64, "arsh64" },

	{ BPF_INS_LE16, "le16" },	{ BPF_INS_LE32, "le32" },
	{ BPF_INS_LE64, "le64" },	{ BPF_INS_BE16, "be16" },
	{ BPF_INS_BE32, "be32" },	{ BPF_INS_BE64, "be64" },
	{ BPF_INS_BSWAP16, "bswap16" }, { BPF_INS_BSWAP32, "bswap32" },
	{ BPF_INS_BSWAP64, "bswap64" },

	{ BPF_INS_LDW, "ldw" },		{ BPF_INS_LDH, "ldh" },
	{ BPF_INS_LDB, "ldb" },		{ BPF_INS_LDDW, "lddw" },
	{ BPF_INS_LDXW, "ldxw" },	{ BPF_INS_LDXH, "ldxh" },
	{ BPF_INS_LDXB, "ldxb" },	{ BPF_INS_LDXDW, "ldxdw" },
	{ BPF_INS_LDABSW, "ldabsw" },	{ BPF_INS_LDABSH, "ldabsh" },
	{ BPF_INS_LDABSB, "ldabsb" },	{ BPF_INS_LDINDW, "ldindw" },
	{ BPF_INS_LDINDH, "ldindh" },	{ BPF_INS_LDINDB, "ldindb" },

	{ BPF_INS_STW, "stw" },		{ BPF_INS_STH, "sth" },
	{ BPF_INS_STB, "stb" },		{ BPF_INS_STDW, "stdw" },
	{ BPF_INS_STXW, "stxw" },	{ BPF_INS_STXH, "stxh" },
	{ BPF_INS_STXB, "stxb" },	{ BPF_INS_STXDW, "stxdw" },
	{ BPF_INS_XADDW, "xaddw" },	{ BPF_INS_XADDDW, "xadddw" },

	{ BPF_INS_JA, "ja" },		{ BPF_INS_JEQ, "jeq" },
	{ BPF_INS_JGT, "jgt" },		{ BPF_INS_JGE, "jge" },
	{ BPF_INS_JSET, "jset" },	{ BPF_INS_JNE, "jne" },
	{ BPF_INS_JSGT, "jsgt" },	{ BPF_INS_JSGE, "jsge" },
	{ BPF_INS_CALL, "call" },	{ BPF_INS_CALLX, "callx" },
	{ BPF_INS_EXIT, "exit" },	{ BPF_INS_JLT, "jlt" },
	{ BPF_INS_JLE, "jle" },		{ BPF_INS_JSLT, "jslt" },
	{ BPF_INS_JSLE, "jsle" },

	{ BPF_INS_JAL, "jal" },		{ BPF_INS_JEQ32, "jeq32" },
	{ BPF_INS_JGT32, "jgt32" },	{ BPF_INS_JGE32, "jge32" },
	{ BPF_INS_JSET32, "jset32" },	{ BPF_INS_JNE32, "jne32" },
	{ BPF_INS_JSGT32, "jsgt32" },	{ BPF_INS_JSGE32, "jsge32" },
	{ BPF_INS_JLT32, "jlt32" },	{ BPF_INS_JLE32, "jle32" },
	{ BPF_INS_JSLT32, "jslt32" },	{ BPF_INS_JSLE32, "jsle32" },

	{ BPF_INS_RET, "ret" },

	{ BPF_INS_AADD, "aadd" },	{ BPF_INS_AOR, "aor" },
	{ BPF_INS_AAND, "aand" },	{ BPF_INS_AXOR, "axor" },
	{ BPF_INS_AFADD, "afadd" },	{ BPF_INS_AFOR, "afor" },
	{ BPF_INS_AFAND, "afand" },	{ BPF_INS_AFXOR, "afxor" },

	{ BPF_INS_AXCHG64, "axchg64" }, { BPF_INS_ACMPXCHG64, "acmpxchg64" },
	{ BPF_INS_AADD64, "aadd64" },	{ BPF_INS_AOR64, "aor64" },
	{ BPF_INS_AAND64, "aand64" },	{ BPF_INS_AXOR64, "axor64" },
	{ BPF_INS_AFADD64, "afadd64" }, { BPF_INS_AFOR64, "afor64" },
	{ BPF_INS_AFAND64, "afand64" }, { BPF_INS_AFXOR64, "afxor64" },

	{ BPF_INS_TAX, "tax" },		{ BPF_INS_TXA, "txa" },
};
#endif

bool BPF_getFeature(const cs_mode mode, const cs_mode feature)
{
	return (mode & feature);
}

const char *BPF_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	/* We have some special cases because 'ld' in cBPF is equivalent to 'ldw'
	 * in eBPF, and we don't want to see 'ldw' appears in cBPF mode.
	 */
	if (!EBPF_MODE(((cs_struct *)handle)->mode)) {
		switch (id) {
		case BPF_INS_LD:
			return "ld";
		case BPF_INS_LDX:
			return "ldx";
		case BPF_INS_ST:
			return "st";
		case BPF_INS_STX:
			return "stx";
		}
	}
	return id2name(insn_name_maps, ARR_SIZE(insn_name_maps), id);
#else
	return NULL;
#endif
}

const char *BPF_reg_name(csh handle, unsigned int reg)
{
#ifndef CAPSTONE_DIET
	if (EBPF_MODE(((cs_struct *)handle)->mode)) {
		if (reg < BPF_REG_R0 || reg > BPF_REG_R10)
			return NULL;
		static const char reg_names[11][4] = { "r0", "r1", "r2", "r3",
						       "r4", "r5", "r6", "r7",
						       "r8", "r9", "r10" };
		return reg_names[reg - BPF_REG_R0];
	}

	/* cBPF mode */
	if (reg == BPF_REG_A)
		return "a";
	else if (reg == BPF_REG_X)
		return "x";
	else
		return NULL;
#else
	return NULL;
#endif
}

void BPF_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	// Not used by BPF. Information is set after disassembly.
}

static void sort_and_uniq(cs_regs arr, uint8_t n, uint8_t *new_n)
{
	/* arr is always a tiny (usually n < 3) array,
	 * a simple O(n^2) sort is efficient enough. */
	size_t iMin;
	size_t tmp;

	/* a modified selection sort for sorting and making unique */
	for (size_t j = 0; j < n; j++) {
		/* arr[iMin] will be min(arr[j .. n-1]) */
		iMin = j;
		for (size_t i = j + 1; i < n; i++) {
			if (arr[i] < arr[iMin])
				iMin = i;
		}
		if (j != 0 && arr[iMin] == arr[j - 1]) { // duplicate ele found
			arr[iMin] = arr[n - 1];
			--n;
		} else {
			tmp = arr[iMin];
			arr[iMin] = arr[j];
			arr[j] = tmp;
		}
	}

	*new_n = n;
}
void BPF_reg_access(const cs_insn *insn, cs_regs regs_read,
		    uint8_t *regs_read_count, cs_regs regs_write,
		    uint8_t *regs_write_count)
{
	unsigned i;
	uint8_t read_count, write_count;
	const cs_bpf *bpf = &(insn->detail->bpf);

	read_count = insn->detail->regs_read_count;
	write_count = insn->detail->regs_write_count;

	// implicit registers
	memcpy(regs_read, insn->detail->regs_read,
	       read_count * sizeof(insn->detail->regs_read[0]));
	memcpy(regs_write, insn->detail->regs_write,
	       write_count * sizeof(insn->detail->regs_write[0]));

	for (i = 0; i < bpf->op_count; i++) {
		const cs_bpf_op *op = &(bpf->operands[i]);
		switch (op->type) {
		default:
			break;
		case BPF_OP_REG:
			if (op->access & CS_AC_READ) {
				regs_read[read_count] = op->reg;
				read_count++;
			}
			if (op->access & CS_AC_WRITE) {
				regs_write[write_count] = op->reg;
				write_count++;
			}
			break;
		case BPF_OP_MEM:
			if (op->mem.base != BPF_REG_INVALID) {
				regs_read[read_count] = op->mem.base;
				read_count++;
			}
			break;
		}
	}

	sort_and_uniq(regs_read, read_count, regs_read_count);
	sort_and_uniq(regs_write, write_count, regs_write_count);
}

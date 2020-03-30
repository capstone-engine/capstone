/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifdef CAPSTONE_HAS_ARM64

#include <stdio.h>	// debug
#include <string.h>

#include "../../utils.h"

#include "AArch64Mapping.h"

#define GET_INSTRINFO_ENUM
#include "AArch64GenInstrInfo.inc"

#ifndef CAPSTONE_DIET
// NOTE: this reg_name_maps[] reflects the order of registers in arm64_reg
static const char * const reg_name_maps[] = {
	NULL, /* ARM64_REG_INVALID */

	"ffr",
	"fp",
	"lr",
	"nzcv",
	"sp",
	"wsp",
	"wzr",
	"xzr",

	"b0",
	"b1",
	"b2",
	"b3",
	"b4",
	"b5",
	"b6",
	"b7",
	"b8",
	"b9",
	"b10",
	"b11",
	"b12",
	"b13",
	"b14",
	"b15",
	"b16",
	"b17",
	"b18",
	"b19",
	"b20",
	"b21",
	"b22",
	"b23",
	"b24",
	"b25",
	"b26",
	"b27",
	"b28",
	"b29",
	"b30",
	"b31",

	"d0",
	"d1",
	"d2",
	"d3",
	"d4",
	"d5",
	"d6",
	"d7",
	"d8",
	"d9",
	"d10",
	"d11",
	"d12",
	"d13",
	"d14",
	"d15",
	"d16",
	"d17",
	"d18",
	"d19",
	"d20",
	"d21",
	"d22",
	"d23",
	"d24",
	"d25",
	"d26",
	"d27",
	"d28",
	"d29",
	"d30",
	"d31",

	"h0",
	"h1",
	"h2",
	"h3",
	"h4",
	"h5",
	"h6",
	"h7",
	"h8",
	"h9",
	"h10",
	"h11",
	"h12",
	"h13",
	"h14",
	"h15",
	"h16",
	"h17",
	"h18",
	"h19",
	"h20",
	"h21",
	"h22",
	"h23",
	"h24",
	"h25",
	"h26",
	"h27",
	"h28",
	"h29",
	"h30",
	"h31",

	"p0",
	"p1",
	"p2",
	"p3",
	"p4",
	"p5",
	"p6",
	"p7",
	"p8",
	"p9",
	"p10",
	"p11",
	"p12",
	"p13",
	"p14",
	"p15",

	"q0",
	"q1",
	"q2",
	"q3",
	"q4",
	"q5",
	"q6",
	"q7",
	"q8",
	"q9",
	"q10",
	"q11",
	"q12",
	"q13",
	"q14",
	"q15",
	"q16",
	"q17",
	"q18",
	"q19",
	"q20",
	"q21",
	"q22",
	"q23",
	"q24",
	"q25",
	"q26",
	"q27",
	"q28",
	"q29",
	"q30",
	"q31",
	"s0",
	"s1",
	"s2",
	"s3",
	"s4",
	"s5",
	"s6",
	"s7",
	"s8",
	"s9",
	"s10",
	"s11",
	"s12",
	"s13",
	"s14",
	"s15",
	"s16",
	"s17",
	"s18",
	"s19",
	"s20",
	"s21",
	"s22",
	"s23",
	"s24",
	"s25",
	"s26",
	"s27",
	"s28",
	"s29",
	"s30",
	"s31",

	"w0",
	"w1",
	"w2",
	"w3",
	"w4",
	"w5",
	"w6",
	"w7",
	"w8",
	"w9",
	"w10",
	"w11",
	"w12",
	"w13",
	"w14",
	"w15",
	"w16",
	"w17",
	"w18",
	"w19",
	"w20",
	"w21",
	"w22",
	"w23",
	"w24",
	"w25",
	"w26",
	"w27",
	"w28",
	"w29",
	"w30",

	"x0",
	"x1",
	"x2",
	"x3",
	"x4",
	"x5",
	"x6",
	"x7",
	"x8",
	"x9",
	"x10",
	"x11",
	"x12",
	"x13",
	"x14",
	"x15",
	"x16",
	"x17",
	"x18",
	"x19",
	"x20",
	"x21",
	"x22",
	"x23",
	"x24",
	"x25",
	"x26",
	"x27",
	"x28",

	"z0",
	"z1",
	"z2",
	"z3",
	"z4",
	"z5",
	"z6",
	"z7",
	"z8",
	"z9",
	"z10",
	"z11",
	"z12",
	"z13",
	"z14",
	"z15",
	"z16",
	"z17",
	"z18",
	"z19",
	"z20",
	"z21",
	"z22",
	"z23",
	"z24",
	"z25",
	"z26",
	"z27",
	"z28",
	"z29",
	"z30",
	"z31",

	"v0",
	"v1",
	"v2",
	"v3",
	"v4",
	"v5",
	"v6",
	"v7",
	"v8",
	"v9",
	"v10",
	"v11",
	"v12",
	"v13",
	"v14",
	"v15",
	"v16",
	"v17",
	"v18",
	"v19",
	"v20",
	"v21",
	"v22",
	"v23",
	"v24",
	"v25",
	"v26",
	"v27",
	"v28",
	"v29",
	"v30",
	"v31",
};
#endif

const char *AArch64_reg_name(csh handle, unsigned int reg)
{
#ifndef CAPSTONE_DIET
	if (reg >= ARR_SIZE(reg_name_maps))
		return NULL;

	return reg_name_maps[reg];
#else
	return NULL;
#endif
}

static const insn_map insns[] = {
	// dummy item
	{
		0, 0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},

#include "AArch64MappingInsn.inc"
};

// given internal insn id, return public instruction info
void AArch64_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	int i = insn_find(insns, ARR_SIZE(insns), id, &h->insn_cache);
	if (i != 0) {
		insn->id = insns[i].mapid;

		if (h->detail) {
#ifndef CAPSTONE_DIET
			cs_struct handle;
			handle.detail = h->detail;

			memcpy(insn->detail->regs_read, insns[i].regs_use, sizeof(insns[i].regs_use));
			insn->detail->regs_read_count = (uint8_t)count_positive(insns[i].regs_use);

			memcpy(insn->detail->regs_write, insns[i].regs_mod, sizeof(insns[i].regs_mod));
			insn->detail->regs_write_count = (uint8_t)count_positive(insns[i].regs_mod);

			memcpy(insn->detail->groups, insns[i].groups, sizeof(insns[i].groups));
			insn->detail->groups_count = (uint8_t)count_positive8(insns[i].groups);

			insn->detail->arm64.update_flags = cs_reg_write((csh)&handle, insn, ARM64_REG_NZCV);
#endif
		}
	}
}

static const char * const insn_name_maps[] = {
	NULL, // ARM64_INS_INVALID
#include "AArch64MappingInsnName.inc"
	"sbfiz",
	"ubfiz",
	"sbfx",
	"ubfx",
	"bfi",
	"bfxil",
	"ic",
	"dc",
	"at",
	"tlbi",
};

const char *AArch64_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	if (id >= ARM64_INS_ENDING)
		return NULL;

	if (id < ARR_SIZE(insn_name_maps))
		return insn_name_maps[id];

	// not found
	return NULL;
#else
	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
static const name_map group_name_maps[] = {
	// generic groups
	{ ARM64_GRP_INVALID, NULL },
	{ ARM64_GRP_JUMP, "jump" },
	{ ARM64_GRP_CALL, "call" },
	{ ARM64_GRP_RET, "return" },
	{ ARM64_GRP_PRIVILEGE, "privilege" },
	{ ARM64_GRP_INT, "int" },
	{ ARM64_GRP_BRANCH_RELATIVE, "branch_relative" },
	{ ARM64_GRP_PAC, "pointer authentication" },

	// architecture-specific groups
	{ ARM64_GRP_CRYPTO, "crypto" },
	{ ARM64_GRP_FPARMV8, "fparmv8" },
	{ ARM64_GRP_NEON, "neon" },
	{ ARM64_GRP_CRC, "crc" },

	{ ARM64_GRP_AES, "aes" },
	{ ARM64_GRP_DOTPROD, "dotprod" },
	{ ARM64_GRP_FULLFP16, "fullfp16" },
	{ ARM64_GRP_LSE, "lse" },
	{ ARM64_GRP_RCPC, "rcpc" },
	{ ARM64_GRP_RDM, "rdm" },
	{ ARM64_GRP_SHA2, "sha2" },
	{ ARM64_GRP_SHA3, "sha3" },
	{ ARM64_GRP_SM4, "sm4" },
	{ ARM64_GRP_SVE, "sve" },
	{ ARM64_GRP_V8_1A, "v8_1a" },
	{ ARM64_GRP_V8_3A, "v8_3a" },
	{ ARM64_GRP_V8_4A, "v8_4a" },
};
#endif

const char *AArch64_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
#else
	return NULL;
#endif
}

// map instruction name to public instruction ID
arm64_insn AArch64_map_insn(const char *name)
{
	unsigned int i;

	for(i = 1; i < ARR_SIZE(insn_name_maps); i++) {
		if (!strcmp(name, insn_name_maps[i]))
			return i;
	}

	// not found
	return ARM64_INS_INVALID;
}

// map internal raw vregister to 'public' register
arm64_reg AArch64_map_vregister(unsigned int r)
{
	static const unsigned short RegAsmOffsetvreg[] = {
#include "AArch64GenRegisterV.inc"
	};

	if (r < ARR_SIZE(RegAsmOffsetvreg))
		return RegAsmOffsetvreg[r - 1];

	// cannot find this register
	return 0;
}

void arm64_op_addVectorArrSpecifier(MCInst * MI, int sp)
{
	if (MI->csh->detail) {
		MI->flat_insn->detail->arm64.operands[MI->flat_insn->detail->arm64.op_count - 1].vas = sp;
	}
}

void arm64_op_addFP(MCInst *MI, float fp)
{
	if (MI->csh->detail) {
		MI->flat_insn->detail->arm64.operands[MI->flat_insn->detail->arm64.op_count].type = ARM64_OP_FP;
		MI->flat_insn->detail->arm64.operands[MI->flat_insn->detail->arm64.op_count].fp = fp;
		MI->flat_insn->detail->arm64.op_count++;
	}
}

void arm64_op_addImm(MCInst *MI, int64_t imm)
{
	if (MI->csh->detail) {
		MI->flat_insn->detail->arm64.operands[MI->flat_insn->detail->arm64.op_count].type = ARM64_OP_IMM;
		MI->flat_insn->detail->arm64.operands[MI->flat_insn->detail->arm64.op_count].imm = (int)imm;
		MI->flat_insn->detail->arm64.op_count++;
	}
}

#ifndef CAPSTONE_DIET

// map instruction to its characteristics
typedef struct insn_op {
	unsigned int eflags_update;	// how this instruction update status flags
	uint8_t access[5];
} insn_op;

static const insn_op insn_ops[] = {
    {
         /* NULL item */
        0, { 0 }
    },

#include "AArch64MappingInsnOp.inc"
};

// given internal insn id, return operand access info
const uint8_t *AArch64_get_op_access(cs_struct *h, unsigned int id)
{
	int i = insn_find(insns, ARR_SIZE(insns), id, &h->insn_cache);
	if (i != 0) {
		return insn_ops[i].access;
	}

	return NULL;
}

void AArch64_reg_access(const cs_insn *insn,
		cs_regs regs_read, uint8_t *regs_read_count,
		cs_regs regs_write, uint8_t *regs_write_count)
{
	uint8_t i;
	uint8_t read_count, write_count;
	cs_arm64 *arm64 = &(insn->detail->arm64);

	read_count = insn->detail->regs_read_count;
	write_count = insn->detail->regs_write_count;

	// implicit registers
	memcpy(regs_read, insn->detail->regs_read, read_count * sizeof(insn->detail->regs_read[0]));
	memcpy(regs_write, insn->detail->regs_write, write_count * sizeof(insn->detail->regs_write[0]));

	// explicit registers
	for (i = 0; i < arm64->op_count; i++) {
		cs_arm64_op *op = &(arm64->operands[i]);
		switch((int)op->type) {
			case ARM64_OP_REG:
				if ((op->access & CS_AC_READ) && !arr_exist(regs_read, read_count, op->reg)) {
					regs_read[read_count] = (uint16_t)op->reg;
					read_count++;
				}
				if ((op->access & CS_AC_WRITE) && !arr_exist(regs_write, write_count, op->reg)) {
					regs_write[write_count] = (uint16_t)op->reg;
					write_count++;
				}
				break;
			case ARM_OP_MEM:
				// registers appeared in memory references always being read
				if ((op->mem.base != ARM64_REG_INVALID) && !arr_exist(regs_read, read_count, op->mem.base)) {
					regs_read[read_count] = (uint16_t)op->mem.base;
					read_count++;
				}
				if ((op->mem.index != ARM64_REG_INVALID) && !arr_exist(regs_read, read_count, op->mem.index)) {
					regs_read[read_count] = (uint16_t)op->mem.index;
					read_count++;
				}
				if ((arm64->writeback) && (op->mem.base != ARM64_REG_INVALID) && !arr_exist(regs_write, write_count, op->mem.base)) {
					regs_write[write_count] = (uint16_t)op->mem.base;
					write_count++;
				}
			default:
				break;
		}
	}

	*regs_read_count = read_count;
	*regs_write_count = write_count;
}
#endif

#endif

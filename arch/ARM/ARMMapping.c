/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#ifdef CAPSTONE_HAS_ARM

#include <stdio.h>	// debug
#include <string.h>

#include "../../cs_priv.h"

#include "ARMMapping.h"

#define GET_INSTRINFO_ENUM
#define GET_REGINFO_ENUM
#include "ARMGenDisassemblerTables.inc"

#ifndef CAPSTONE_DIET

static const name_map reg_name_maps[] = {
	{ ARM_REG_INVALID, NULL },
	{ ARM_APSR, "apsr"},
	{ ARM_APSR_NZCV, "apsr_nzcv"},
	{ ARM_CPSR, "cpsr"},
	{ ARM_FPEXC, "fpexc"},
	{ ARM_FPINST, "fpinst"},
	{ ARM_FPSCR, "fpscr"},
	{ ARM_FPSCR_NZCV, "fpscr_nzcv"},
	{ ARM_FPSID, "fpsid"},
	{ ARM_ITSTATE, "itstate"},
	{ ARM_LR, "lr"},
	{ ARM_PC, "pc"},
	{ ARM_SP, "sp"},
	{ ARM_SPSR, "spsr"},
	{ ARM_D0, "d0"},
	{ ARM_D1, "d1"},
	{ ARM_D2, "d2"},
	{ ARM_D3, "d3"},
	{ ARM_D4, "d4"},
	{ ARM_D5, "d5"},
	{ ARM_D6, "d6"},
	{ ARM_D7, "d7"},
	{ ARM_D8, "d8"},
	{ ARM_D9, "d9"},
	{ ARM_D10, "d10"},
	{ ARM_D11, "d11"},
	{ ARM_D12, "d12"},
	{ ARM_D13, "d13"},
	{ ARM_D14, "d14"},
	{ ARM_D15, "d15"},
	{ ARM_D16, "d16"},
	{ ARM_D17, "d17"},
	{ ARM_D18, "d18"},
	{ ARM_D19, "d19"},
	{ ARM_D20, "d20"},
	{ ARM_D21, "d21"},
	{ ARM_D22, "d22"},
	{ ARM_D23, "d23"},
	{ ARM_D24, "d24"},
	{ ARM_D25, "d25"},
	{ ARM_D26, "d26"},
	{ ARM_D27, "d27"},
	{ ARM_D28, "d28"},
	{ ARM_D29, "d29"},
	{ ARM_D30, "d30"},
	{ ARM_D31, "d31"},
	{ ARM_FPINST2, "fpinst2"},
	{ ARM_MVFR0, "mvfr0"},
	{ ARM_MVFR1, "mvfr1"},
	{ ARM_MVFR2, "mvfr2"},
	{ ARM_Q0, "q0"},
	{ ARM_Q1, "q1"},
	{ ARM_Q2, "q2"},
	{ ARM_Q3, "q3"},
	{ ARM_Q4, "q4"},
	{ ARM_Q5, "q5"},
	{ ARM_Q6, "q6"},
	{ ARM_Q7, "q7"},
	{ ARM_Q8, "q8"},
	{ ARM_Q9, "q9"},
	{ ARM_Q10, "q10"},
	{ ARM_Q11, "q11"},
	{ ARM_Q12, "q12"},
	{ ARM_Q13, "q13"},
	{ ARM_Q14, "q14"},
	{ ARM_Q15, "q15"},
	{ ARM_R0, "r0"},
	{ ARM_R1, "r1"},
	{ ARM_R2, "r2"},
	{ ARM_R3, "r3"},
	{ ARM_R4, "r4"},
	{ ARM_R5, "r5"},
	{ ARM_R6, "r6"},
	{ ARM_R7, "r7"},
	{ ARM_R8, "r8"},
	{ ARM_R9, "sb"},
	{ ARM_R10, "sl"},
	{ ARM_R11, "fp"},
	{ ARM_R12, "ip"},
	{ ARM_S0, "s0"},
	{ ARM_S1, "s1"},
	{ ARM_S2, "s2"},
	{ ARM_S3, "s3"},
	{ ARM_S4, "s4"},
	{ ARM_S5, "s5"},
	{ ARM_S6, "s6"},
	{ ARM_S7, "s7"},
	{ ARM_S8, "s8"},
	{ ARM_S9, "s9"},
	{ ARM_S10, "s10"},
	{ ARM_S11, "s11"},
	{ ARM_S12, "s12"},
	{ ARM_S13, "s13"},
	{ ARM_S14, "s14"},
	{ ARM_S15, "s15"},
	{ ARM_S16, "s16"},
	{ ARM_S17, "s17"},
	{ ARM_S18, "s18"},
	{ ARM_S19, "s19"},
	{ ARM_S20, "s20"},
	{ ARM_S21, "s21"},
	{ ARM_S22, "s22"},
	{ ARM_S23, "s23"},
	{ ARM_S24, "s24"},
	{ ARM_S25, "s25"},
	{ ARM_S26, "s26"},
	{ ARM_S27, "s27"},
	{ ARM_S28, "s28"},
	{ ARM_S29, "s29"},
	{ ARM_S30, "s30"},
	{ ARM_S31, "s31"},
};
static const name_map reg_name_maps2[] = {
	{ ARM_REG_INVALID, NULL },
	{ ARM_APSR, "apsr"},
	{ ARM_APSR_NZCV, "apsr_nzcv"},
	{ ARM_CPSR, "cpsr"},
	{ ARM_FPEXC, "fpexc"},
	{ ARM_FPINST, "fpinst"},
	{ ARM_FPSCR, "fpscr"},
	{ ARM_FPSCR_NZCV, "fpscr_nzcv"},
	{ ARM_FPSID, "fpsid"},
	{ ARM_ITSTATE, "itstate"},
	{ ARM_LR, "lr"},
	{ ARM_PC, "pc"},
	{ ARM_SP, "sp"},
	{ ARM_SPSR, "spsr"},
	{ ARM_D0, "d0"},
	{ ARM_D1, "d1"},
	{ ARM_D2, "d2"},
	{ ARM_D3, "d3"},
	{ ARM_D4, "d4"},
	{ ARM_D5, "d5"},
	{ ARM_D6, "d6"},
	{ ARM_D7, "d7"},
	{ ARM_D8, "d8"},
	{ ARM_D9, "d9"},
	{ ARM_D10, "d10"},
	{ ARM_D11, "d11"},
	{ ARM_D12, "d12"},
	{ ARM_D13, "d13"},
	{ ARM_D14, "d14"},
	{ ARM_D15, "d15"},
	{ ARM_D16, "d16"},
	{ ARM_D17, "d17"},
	{ ARM_D18, "d18"},
	{ ARM_D19, "d19"},
	{ ARM_D20, "d20"},
	{ ARM_D21, "d21"},
	{ ARM_D22, "d22"},
	{ ARM_D23, "d23"},
	{ ARM_D24, "d24"},
	{ ARM_D25, "d25"},
	{ ARM_D26, "d26"},
	{ ARM_D27, "d27"},
	{ ARM_D28, "d28"},
	{ ARM_D29, "d29"},
	{ ARM_D30, "d30"},
	{ ARM_D31, "d31"},
	{ ARM_FPINST2, "fpinst2"},
	{ ARM_MVFR0, "mvfr0"},
	{ ARM_MVFR1, "mvfr1"},
	{ ARM_MVFR2, "mvfr2"},
	{ ARM_Q0, "q0"},
	{ ARM_Q1, "q1"},
	{ ARM_Q2, "q2"},
	{ ARM_Q3, "q3"},
	{ ARM_Q4, "q4"},
	{ ARM_Q5, "q5"},
	{ ARM_Q6, "q6"},
	{ ARM_Q7, "q7"},
	{ ARM_Q8, "q8"},
	{ ARM_Q9, "q9"},
	{ ARM_Q10, "q10"},
	{ ARM_Q11, "q11"},
	{ ARM_Q12, "q12"},
	{ ARM_Q13, "q13"},
	{ ARM_Q14, "q14"},
	{ ARM_Q15, "q15"},
	{ ARM_R0, "r0"},
	{ ARM_R1, "r1"},
	{ ARM_R2, "r2"},
	{ ARM_R3, "r3"},
	{ ARM_R4, "r4"},
	{ ARM_R5, "r5"},
	{ ARM_R6, "r6"},
	{ ARM_R7, "r7"},
	{ ARM_R8, "r8"},
	{ ARM_R9, "r9"},
	{ ARM_R10, "r10"},
	{ ARM_R11, "r11"},
	{ ARM_R12, "r12"},
	{ ARM_S0, "s0"},
	{ ARM_S1, "s1"},
	{ ARM_S2, "s2"},
	{ ARM_S3, "s3"},
	{ ARM_S4, "s4"},
	{ ARM_S5, "s5"},
	{ ARM_S6, "s6"},
	{ ARM_S7, "s7"},
	{ ARM_S8, "s8"},
	{ ARM_S9, "s9"},
	{ ARM_S10, "s10"},
	{ ARM_S11, "s11"},
	{ ARM_S12, "s12"},
	{ ARM_S13, "s13"},
	{ ARM_S14, "s14"},
	{ ARM_S15, "s15"},
	{ ARM_S16, "s16"},
	{ ARM_S17, "s17"},
	{ ARM_S18, "s18"},
	{ ARM_S19, "s19"},
	{ ARM_S20, "s20"},
	{ ARM_S21, "s21"},
	{ ARM_S22, "s22"},
	{ ARM_S23, "s23"},
	{ ARM_S24, "s24"},
	{ ARM_S25, "s25"},
	{ ARM_S26, "s26"},
	{ ARM_S27, "s27"},
	{ ARM_S28, "s28"},
	{ ARM_S29, "s29"},
	{ ARM_S30, "s30"},
	{ ARM_S31, "s31"},
};
#endif

const char *ARM_reg_name(csh handle, unsigned int reg)
{
#ifndef CAPSTONE_DIET

        for(int i = 0; i < ARR_SIZE(reg_name_maps); i ++) {
          if(reg_name_maps[i].id == reg) {
            return reg_name_maps[i].name;
          }
        }

        // invalid
	return "invalid";
#else
	return NULL;
#endif
}

const char *ARM_reg_name2(csh handle, unsigned int reg)
{
#ifndef CAPSTONE_DIET
  for(int i = 0; i < ARR_SIZE(reg_name_maps2); i ++) {
    if(reg_name_maps2[i].id == reg) {
      return reg_name_maps2[i].name;
    }
  }

  // invalid
  return NULL;
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
#include "ARMMappingInsn.inc"
};

// look for @id in @insns
// return -1 if not found
static unsigned int find_insn(unsigned int id)
{
	// binary searching since the IDs are sorted in order
	unsigned int left, right, m;
	unsigned int max = ARR_SIZE(insns);

	right = max - 1;

	if (id < insns[0].id || id > insns[right].id)
		// not found
		return -1;

	left = 0;

	while(left <= right) {
		m = (left + right) / 2;
		if (id == insns[m].id) {
			return m;
		}

		if (id < insns[m].id)
			right = m - 1;
		else
			left = m + 1;
	}

	// not found
	// printf("NOT FOUNDDDDDDDDDDDDDDD id = %u\n", id);
	return -1;
}

void ARM_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	unsigned int i = find_insn(id);
	if (i != -1) {
		insn->id = insns[i].mapid;

		// printf("id = %u, mapid = %u\n", id, insn->id);

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

			insn->detail->arm.update_flags = cs_reg_write((csh)&handle, insn, ARM_REG_CPSR);

			if (insns[i].branch || insns[i].indirect_branch) {
				// this insn also belongs to JUMP group. add JUMP group
				insn->detail->groups[insn->detail->groups_count] = ARM_GRP_JUMP;
				insn->detail->groups_count++;
			}
#endif
		}
	}
}

#ifndef CAPSTONE_DIET
static const char * const insn_name_maps[] = {
	NULL, // ARM_INS_INVALID
#include "ARMMappingInsnName.inc"
};
#endif

const char *ARM_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	if (id >= ARM_INS_ENDING)
		return NULL;

	return insn_name_maps[id];
#else
	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
static const name_map group_name_maps[] = {
	// generic groups
	{ ARM_GRP_INVALID, NULL },
	{ ARM_GRP_JUMP,	"jump" },
	{ ARM_GRP_CALL,	"call" },
	{ ARM_GRP_INT,	"int" },
	{ ARM_GRP_PRIVILEGE, "privilege" },
	{ ARM_GRP_BRANCH_RELATIVE, "branch_relative" },

	// architecture-specific groups
	{ ARM_GRP_CRYPTO, "crypto" },
	{ ARM_GRP_DATABARRIER, "databarrier" },
	{ ARM_GRP_DIVIDE, "divide" },
	{ ARM_GRP_FPARMV8, "fparmv8" },
	{ ARM_GRP_MULTPRO, "multpro" },
	{ ARM_GRP_NEON, "neon" },
	{ ARM_GRP_T2EXTRACTPACK, "T2EXTRACTPACK" },
	{ ARM_GRP_THUMB2DSP, "THUMB2DSP" },
	{ ARM_GRP_TRUSTZONE, "TRUSTZONE" },
	{ ARM_GRP_V4T, "v4t" },
	{ ARM_GRP_V5T, "v5t" },
	{ ARM_GRP_V5TE, "v5te" },
	{ ARM_GRP_V6, "v6" },
	{ ARM_GRP_V6T2, "v6t2" },
	{ ARM_GRP_V7, "v7" },
	{ ARM_GRP_V8, "v8" },
	{ ARM_GRP_VFP2, "vfp2" },
	{ ARM_GRP_VFP3, "vfp3" },
	{ ARM_GRP_VFP4, "vfp4" },
	{ ARM_GRP_ARM, "arm" },
	{ ARM_GRP_MCLASS, "mclass" },
	{ ARM_GRP_NOTMCLASS, "notmclass" },
	{ ARM_GRP_THUMB, "thumb" },
	{ ARM_GRP_THUMB1ONLY, "thumb1only" },
	{ ARM_GRP_THUMB2, "thumb2" },
	{ ARM_GRP_PREV8, "prev8" },
	{ ARM_GRP_FPVMLX, "fpvmlx" },
	{ ARM_GRP_MULOPS, "mulops" },
	{ ARM_GRP_CRC, "crc" },
	{ ARM_GRP_DPVFP, "dpvfp" },
	{ ARM_GRP_V6M, "v6m" },
	{ ARM_GRP_VIRTUALIZATION, "virtualization" },
};
#endif

const char *ARM_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
#else
	return NULL;
#endif
}

// list all relative branch instructions
// ie: insns[i].branch && !insns[i].indirect_branch
static const unsigned int insn_rel[] = {
	ARM_BL,
	ARM_BLX_pred,
	ARM_Bcc,
	ARM_t2B,
	ARM_t2Bcc,
	ARM_tB,
	ARM_tBcc,
	ARM_tCBNZ,
	ARM_tCBZ,
	ARM_BL_pred,
	ARM_BLXi,
	ARM_tBL,
	ARM_tBLXi,
	0
};

static const unsigned int insn_blx_rel_to_arm[] = {
	ARM_tBLXi,
	0
};

// check if this insn is relative branch
bool ARM_rel_branch(cs_struct *h, unsigned int id)
{
	int i;

	for (i = 0; insn_rel[i]; i++) {
		if (id == insn_rel[i]) {
			return true;
		}
	}

	// not found
	return false;
}

bool ARM_blx_to_arm_mode(cs_struct *h, unsigned int id) {
	int i;

	for (i = 0; insn_blx_rel_to_arm[i]; i++)
		if (id == insn_blx_rel_to_arm[i])
			return true;

	// not found
	return false;

}

#ifndef CAPSTONE_DIET
// map instruction to its characteristics
typedef struct insn_op {
	uint8_t access[7];
} insn_op;

static const insn_op insn_ops[] = {
	{
		// NULL item
		{ 0 }
	},

#include "ARMMappingInsnOp.inc"
};

// given internal insn id, return operand access info
const uint8_t *ARM_get_op_access(cs_struct *h, unsigned int id)
{
	int i = insn_find(insns, ARR_SIZE(insns), id, &h->insn_cache);
	if (i != 0) {
		return insn_ops[i].access;
	}

	return NULL;
}

void ARM_reg_access(const cs_insn *insn,
		cs_regs regs_read, uint8_t *regs_read_count,
		cs_regs regs_write, uint8_t *regs_write_count)
{
	uint8_t i;
	uint8_t read_count, write_count;
	cs_arm *arm = &(insn->detail->arm);

	read_count = insn->detail->regs_read_count;
	write_count = insn->detail->regs_write_count;

	// implicit registers
	memcpy(regs_read, insn->detail->regs_read, read_count * sizeof(insn->detail->regs_read[0]));
	memcpy(regs_write, insn->detail->regs_write, write_count * sizeof(insn->detail->regs_write[0]));

	// explicit registers
	for (i = 0; i < arm->op_count; i++) {
		cs_arm_op *op = &(arm->operands[i]);
		switch((int)op->type) {
			case ARM_OP_REG:
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
				if ((op->mem.base != ARM_REG_INVALID) && !arr_exist(regs_read, read_count, op->mem.base)) {
					regs_read[read_count] = (uint16_t)op->mem.base;
					read_count++;
				}
				if ((op->mem.index != ARM_REG_INVALID) && !arr_exist(regs_read, read_count, op->mem.index)) {
					regs_read[read_count] = (uint16_t)op->mem.index;
					read_count++;
				}
				if ((arm->writeback) && (op->mem.base != ARM_REG_INVALID) && !arr_exist(regs_write, write_count, op->mem.base)) {
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


#ifdef CAPSTONE_HAS_RISCV

#include <stdio.h>		// debug
#include <string.h>

#include "../../Mapping.h"
#include "../../utils.h"
#include "../../cs_simple_types.h"

#include "RISCVMapping.h"
#include "RISCVInstPrinter.h"

#define GET_INSTRINFO_ENUM
#include "RISCVGenInstrInfo.inc"

#define GET_REGINFO_ENUM
#define GET_REGINFO_MC_DESC
#include "RISCVGenRegisterInfo.inc"

#ifndef CAPSTONE_DIET
static const name_map reg_name_maps[] = {
	{ RISCV_REG_INVALID, NULL },

	{ RISCV_REG_X0, "zero" },
	{ RISCV_REG_X1, "ra" },
	{ RISCV_REG_X2, "sp" },
	{ RISCV_REG_X3, "gp" },
	{ RISCV_REG_X4, "tp" },
	{ RISCV_REG_X5, "t0" },
	{ RISCV_REG_X6, "t1" },
	{ RISCV_REG_X7, "t2" },
	{ RISCV_REG_X8, "s0" },
	{ RISCV_REG_X9, "s1" },
	{ RISCV_REG_X10, "a0" },
	{ RISCV_REG_X11, "a1" },
	{ RISCV_REG_X12, "a2" },
	{ RISCV_REG_X13, "a3" },
	{ RISCV_REG_X14, "a4" },
	{ RISCV_REG_X15, "a5" },
	{ RISCV_REG_X16, "a6" },
	{ RISCV_REG_X17, "a7" },
	{ RISCV_REG_X18, "s2" },
	{ RISCV_REG_X19, "s3" },
	{ RISCV_REG_X20, "s4" },
	{ RISCV_REG_X21, "s5" },
	{ RISCV_REG_X22, "s6" },
	{ RISCV_REG_X23, "s7" },
	{ RISCV_REG_X24, "s8" },
	{ RISCV_REG_X25, "s9" },
	{ RISCV_REG_X26, "s10" },
	{ RISCV_REG_X27, "s11" },
	{ RISCV_REG_X28, "t3" },
	{ RISCV_REG_X29, "t4" },
	{ RISCV_REG_X30, "t5" },
	{ RISCV_REG_X31, "t6" },

	{ RISCV_REG_F0_F, "ft0" },
	{ RISCV_REG_F0_D, "ft0" },
	{ RISCV_REG_F1_F, "ft1" },
	{ RISCV_REG_F1_D, "ft1" },
	{ RISCV_REG_F2_F, "ft2" },
	{ RISCV_REG_F2_D, "ft2" },
	{ RISCV_REG_F3_F, "ft3" },
	{ RISCV_REG_F3_D, "ft3" },
	{ RISCV_REG_F4_F, "ft4" },
	{ RISCV_REG_F4_D, "ft4" },
	{ RISCV_REG_F5_F, "ft5" },
	{ RISCV_REG_F5_D, "ft5" },
	{ RISCV_REG_F6_F, "ft6" },
	{ RISCV_REG_F6_D, "ft6" },
	{ RISCV_REG_F7_F, "ft7" },
	{ RISCV_REG_F7_D, "ft7" },
	{ RISCV_REG_F8_F, "fs0" },
	{ RISCV_REG_F8_D, "fs0" },
	{ RISCV_REG_F9_F, "fs1" },
	{ RISCV_REG_F9_D, "fs1" },
	{ RISCV_REG_F10_F, "fa0" },
	{ RISCV_REG_F10_D, "fa0" },
	{ RISCV_REG_F11_F, "fa1" },
	{ RISCV_REG_F11_D, "fa1" },
	{ RISCV_REG_F12_F, "fa2" },
	{ RISCV_REG_F12_D, "fa2" },
	{ RISCV_REG_F13_F, "fa3" },
	{ RISCV_REG_F13_D, "fa3" },
	{ RISCV_REG_F14_F, "fa4" },
	{ RISCV_REG_F14_D, "fa4" },
	{ RISCV_REG_F15_F, "fa5" },
	{ RISCV_REG_F15_D, "fa5" },
	{ RISCV_REG_F16_F, "fa6" },
	{ RISCV_REG_F16_D, "fa6" },
	{ RISCV_REG_F17_F, "fa7" },
	{ RISCV_REG_F17_D, "fa7" },
	{ RISCV_REG_F18_F, "fs2" },
	{ RISCV_REG_F18_D, "fs2" },
	{ RISCV_REG_F19_F, "fs3" },
	{ RISCV_REG_F19_D, "fs3" },
	{ RISCV_REG_F20_F, "fs4" },
	{ RISCV_REG_F20_D, "fs4" },
	{ RISCV_REG_F21_F, "fs5" },
	{ RISCV_REG_F21_D, "fs5" },
	{ RISCV_REG_F22_F, "fs6" },
	{ RISCV_REG_F22_D, "fs6" },
	{ RISCV_REG_F23_F, "fs7" },
	{ RISCV_REG_F23_D, "fs7" },
	{ RISCV_REG_F24_F, "fs8" },
	{ RISCV_REG_F24_D, "fs8" },
	{ RISCV_REG_F25_F, "fs9" },
	{ RISCV_REG_F25_D, "fs9" },
	{ RISCV_REG_F26_F, "fs10" },
	{ RISCV_REG_F26_D, "fs10" },
	{ RISCV_REG_F27_F, "fs11" },
	{ RISCV_REG_F27_D, "fs11" },
	{ RISCV_REG_F28_F, "ft8" },
	{ RISCV_REG_F28_D, "ft8" },
	{ RISCV_REG_F29_F, "ft9" },
	{ RISCV_REG_F29_D, "ft9" },
	{ RISCV_REG_F30_F, "ft10" },
	{ RISCV_REG_F30_D, "ft10" },
	{ RISCV_REG_F31_F, "ft11" },
	{ RISCV_REG_F31_D, "ft11" },
};
#endif

const char *RISCV_reg_name(csh handle, unsigned int reg)
{
#ifndef CAPSTONE_DIET
	if (reg >= RISCV_REG_ENDING)
		return NULL;
	return reg_name_maps[reg].name;
#else
	return NULL;
#endif
}

static const insn_map insns[] = {
	// dummy item
	{
	 0, 0,
#ifndef CAPSTONE_DIET
	 {0}, {0}, {0}, 0, 0
#endif
	 },

#include "RISCVMappingInsn.inc"
};

#ifndef CAPSTONE_DIET

static const map_insn_ops insn_operands[] = {
#include "RISCVMappingInsnOp.inc"
};

#endif

void RISCV_add_cs_detail(MCInst *MI, unsigned OpNum) {
	if (!detail_is_set(MI))
		return;

	cs_op_type op_type = map_get_op_type(MI, OpNum);

	if (op_type == CS_OP_IMM) {
		RISCV_get_detail_op(MI, 0)->type = RISCV_OP_IMM;
		RISCV_get_detail_op(MI, 0)->imm = MCInst_getOpVal(MI, OpNum);
		RISCV_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
		RISCV_inc_op_count(MI);
	}
	else if (op_type == CS_OP_REG) {
		RISCV_get_detail_op(MI, 0)->type = RISCV_OP_REG;
		RISCV_get_detail_op(MI, 0)->reg = MCInst_getOpVal(MI, OpNum);
		RISCV_get_detail_op(MI, 0)->access = map_get_op_access(MI, OpNum);
		RISCV_inc_op_count(MI);
	}
	else {
		CS_ASSERT(0 && "Op type not handled.");
	}
}

void RISCV_add_cs_detail_0(MCInst *MI, riscv_op_group opgroup, unsigned OpNum)
{
	// do nothing for now
}

// given internal insn id, return public instruction info
void RISCV_get_insn_id(cs_struct * h, cs_insn * insn, unsigned int id) 
{
  	unsigned int i;

  	i = insn_find(insns, ARR_SIZE(insns), id, &h->insn_cache);
  	if (i != 0) {
    		insn->id = insns[i].mapid;

    		if (h->detail_opt) {
#ifndef CAPSTONE_DIET
      			memcpy(insn->detail->regs_read,
      			insns[i].regs_use, sizeof(insns[i].regs_use));
      			insn->detail->regs_read_count = (uint8_t)count_positive(insns[i].regs_use);

      			memcpy(insn->detail->regs_write, insns[i].regs_mod, sizeof(insns[i].regs_mod));
      			insn->detail->regs_write_count = (uint8_t)count_positive(insns[i].regs_mod);

     			memcpy(insn->detail->groups, insns[i].groups, sizeof(insns[i].groups));
      			insn->detail->groups_count = (uint8_t)count_positive8(insns[i].groups);

      			if (insns[i].branch || insns[i].indirect_branch) {
        			// this insn also belongs to JUMP group. add JUMP group
        			insn->detail->groups[insn->detail->groups_count] = RISCV_GRP_JUMP;
        			insn->detail->groups_count++;
      			}
#endif
    		}
  	}
}

static const char *const insn_name_maps[] = {
  	/*RISCV_INS_INVALID:*/ NULL,

#include "RISCVGenCSMappingInsnName.inc"
};

const char *RISCV_insn_name(csh handle, unsigned int id) 
{
#ifndef CAPSTONE_DIET
  	if (id >= RISCV_INS_ENDING)
    		return NULL;

  	return insn_name_maps[id];
#else
  	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
static const name_map group_name_maps[] = {
  	// generic groups
  	{ RISCV_GRP_INVALID,    NULL },
  	{ RISCV_GRP_JUMP,       "jump" },
  	{ RISCV_GRP_CALL,       "call" },
  	{ RISCV_GRP_RET,        "ret" },
  	{ RISCV_GRP_INT,        "int" },
  	{ RISCV_GRP_IRET,       "iret" },
  	{ RISCV_GRP_PRIVILEGE,  "privileged" },
  	{ RISCV_GRP_BRANCH_RELATIVE, "branch_relative" },
  
  	// architecture specific
  	{ RISCV_FEATURE_ISRV32,     "isrv32" },
  	{ RISCV_FEATURE_ISRV64,     "isrv64" },
  	{ RISCV_FEATURE_HASSTDEXTA, "hasStdExtA" },
  	{ RISCV_FEATURE_HASSTDEXTC, "hasStdExtC" },
  	{ RISCV_FEATURE_HASSTDEXTD, "hasStdExtD" },
  	{ RISCV_FEATURE_HASSTDEXTF, "hasStdExtF" },
  	{ RISCV_FEATURE_HASSTDEXTM, "hasStdExtM" },
  
  	/*
  	{ RISCV_GRP_ISRVA,      "isrva" },
  	{ RISCV_GRP_ISRVC,      "isrvc" },
  	{ RISCV_GRP_ISRVD,      "isrvd" },
  	{ RISCV_GRP_ISRVCD,     "isrvcd" },
  	{ RISCV_GRP_ISRVF,      "isrvf" },
  	{ RISCV_GRP_ISRV32C,    "isrv32c" },
  	{ RISCV_GRP_ISRV32CF,   "isrv32cf" },
  	{ RISCV_GRP_ISRVM,      "isrvm" },
  	{ RISCV_GRP_ISRV64A,    "isrv64a" },
  	{ RISCV_GRP_ISRV64C,    "isrv64c" },
  	{ RISCV_GRP_ISRV64D,    "isrv64d" },
  	{ RISCV_GRP_ISRV64F,    "isrv64f" },
  	{ RISCV_GRP_ISRV64M,    "isrv64m" }
  	*/
  	{ RISCV_GRP_ENDING,     NULL }
};
#endif

const char *RISCV_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	// verify group id
	if (id >= RISCV_GRP_ENDING || 
            (id > RISCV_GRP_BRANCH_RELATIVE && id < RISCV_FEATURE_ISRV32))
		return NULL;
	return id2name(group_name_maps, ARR_SIZE(group_name_maps), id);
#else
	return NULL;
#endif
}

// map instruction name to public instruction ID
riscv_insn RISCV_map_insn(const char *name)
{
	// handle special alias first
	unsigned int i;
	for (i = 1; i < ARR_SIZE(insn_name_maps); i++) {
		if (!strcmp(name, insn_name_maps[i]))
			return i;
	}
	return RISCV_INS_INVALID;
}

// map internal raw register to 'public' register
riscv_reg RISCV_map_register(unsigned int r)
{
	static const unsigned int map[] = { 0,
		RISCV_REG_X0,
		RISCV_REG_X1,
		RISCV_REG_X2,
		RISCV_REG_X3,
		RISCV_REG_X4,
		RISCV_REG_X5,
		RISCV_REG_X6,
		RISCV_REG_X7,
		RISCV_REG_X8,
		RISCV_REG_X9,
		RISCV_REG_X10,
		RISCV_REG_X11,
		RISCV_REG_X12,
		RISCV_REG_X13,
		RISCV_REG_X14,
		RISCV_REG_X15,
		RISCV_REG_X16,
		RISCV_REG_X17,
		RISCV_REG_X18,
		RISCV_REG_X19,
		RISCV_REG_X20,
		RISCV_REG_X21,
		RISCV_REG_X22,
		RISCV_REG_X23,
		RISCV_REG_X24,
		RISCV_REG_X25,
		RISCV_REG_X26,
		RISCV_REG_X27,
		RISCV_REG_X28,
		RISCV_REG_X29,
		RISCV_REG_X30,
		RISCV_REG_X31,

		RISCV_REG_F0_F,
		RISCV_REG_F0_D,
		RISCV_REG_F1_F,
		RISCV_REG_F1_D,
		RISCV_REG_F2_F,
		RISCV_REG_F2_D,
		RISCV_REG_F3_F,
		RISCV_REG_F3_D,
		RISCV_REG_F4_F,
		RISCV_REG_F4_D,
		RISCV_REG_F5_F,
		RISCV_REG_F5_D,
		RISCV_REG_F6_F,
		RISCV_REG_F6_D,
		RISCV_REG_F7_F,
		RISCV_REG_F7_D,
		RISCV_REG_F8_F,
		RISCV_REG_F8_D,
		RISCV_REG_F9_F,
		RISCV_REG_F9_D,
		RISCV_REG_F10_F,
		RISCV_REG_F10_D,
		RISCV_REG_F11_F,
		RISCV_REG_F11_D,
		RISCV_REG_F12_F,
		RISCV_REG_F12_D,
		RISCV_REG_F13_F,
		RISCV_REG_F13_D,
		RISCV_REG_F14_F,
		RISCV_REG_F14_D,
		RISCV_REG_F15_F,
		RISCV_REG_F15_D,
		RISCV_REG_F16_F,
		RISCV_REG_F16_D,
		RISCV_REG_F17_F,
		RISCV_REG_F17_D,
		RISCV_REG_F18_F,
		RISCV_REG_F18_D,
		RISCV_REG_F19_F,
		RISCV_REG_F19_D,
		RISCV_REG_F20_F,
		RISCV_REG_F20_D,
		RISCV_REG_F21_F,
		RISCV_REG_F21_D,
		RISCV_REG_F22_F,
		RISCV_REG_F22_D,
		RISCV_REG_F23_F,
		RISCV_REG_F23_D,
		RISCV_REG_F24_F,
		RISCV_REG_F24_D,
		RISCV_REG_F25_F,
		RISCV_REG_F25_D,
		RISCV_REG_F26_F,
		RISCV_REG_F26_D,
		RISCV_REG_F27_F,
		RISCV_REG_F27_D,
		RISCV_REG_F28_F,
		RISCV_REG_F28_D,
		RISCV_REG_F29_F,
		RISCV_REG_F29_D,
		RISCV_REG_F30_F,
		RISCV_REG_F30_D,
		RISCV_REG_F31_F,
		RISCV_REG_F31_D,
	};

	if (r < ARR_SIZE(map))
		return map[r];

	// cannot find this register
	return 0;
}

void RISCV_init(MCRegisterInfo *MRI)
{
	MCRegisterInfo_InitMCRegisterInfo(
		MRI, RISCVRegDesc, RISCV_REG_ENDING, 0, 0,
		RISCVMCRegisterClasses, ARR_SIZE(RISCVMCRegisterClasses), 0,
		0, RISCVRegDiffLists, 0, RISCVSubRegIdxLists,
		ARR_SIZE(RISCVSubRegIdxLists), 0);
}

#endif

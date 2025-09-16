
#include "capstone/riscv.h"
#include <stdint.h>
#ifdef CAPSTONE_HAS_RISCV

#include <stdio.h>		// debug
#include <string.h>

#include "../../Mapping.h"
#include "../../utils.h"

#include "RISCVMapping.h"

#include "../../cs_simple_types.h"

#define GET_INSTRINFO_ENUM
#include "RISCVGenInstrInfo.inc"

#define GET_REGINFO_ENUM
#define GET_REGINFO_MC_DESC
#include "RISCVGenRegisterInfo.inc"

#ifndef CAPSTONE_DIET
static const name_map reg_name_maps[] = {
	{ RISCV_REG_INVALID, NULL },

	{ RISCV_REG_FFLAGS, ""},
	{ RISCV_REG_FRM, "frm"},
	{ RISCV_REG_SSP, ""},
	{ RISCV_REG_VL, ""},
	{ RISCV_REG_VLENB, ""},
	{ RISCV_REG_VTYPE, ""},
	{ RISCV_REG_VXRM, ""},
	{ RISCV_REG_VXSAT, ""},
	{ RISCV_REG_DUMMY_REG_PAIR_WITH_X0, ""},

	{ RISCV_REG_V0, ""},
	{ RISCV_REG_V1, ""},
	{ RISCV_REG_V2, ""},
	{ RISCV_REG_V3, ""},
	{ RISCV_REG_V4, ""},
	{ RISCV_REG_V5, ""},
	{ RISCV_REG_V6, ""},
	{ RISCV_REG_V7, ""},
	{ RISCV_REG_V8, ""},
	{ RISCV_REG_V9, ""},
	{ RISCV_REG_V10, ""},
	{ RISCV_REG_V11, ""},
	{ RISCV_REG_V12, ""},
	{ RISCV_REG_V13, ""},
	{ RISCV_REG_V14, ""},
	{ RISCV_REG_V15, ""},
	{ RISCV_REG_V16, ""},
	{ RISCV_REG_V17, ""},
	{ RISCV_REG_V18, ""},
	{ RISCV_REG_V19, ""},
	{ RISCV_REG_V20, ""},
	{ RISCV_REG_V21, ""},
	{ RISCV_REG_V22, ""},
	{ RISCV_REG_V23, ""},
	{ RISCV_REG_V24, ""},
	{ RISCV_REG_V25, ""},
	{ RISCV_REG_V26, ""},
	{ RISCV_REG_V27, ""},
	{ RISCV_REG_V28, ""},
	{ RISCV_REG_V29, ""},
	{ RISCV_REG_V30, ""},
	{ RISCV_REG_V31, ""},

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

	{ RISCV_REG_F0_D, "ft0" },
	{ RISCV_REG_F1_D, "ft1" },
	{ RISCV_REG_F2_D, "ft2" },
	{ RISCV_REG_F3_D, "ft3" },
	{ RISCV_REG_F4_D, "ft4" },
	{ RISCV_REG_F5_D, "ft5" },
	{ RISCV_REG_F6_D, "ft6" },
	{ RISCV_REG_F7_D, "ft7" },
	{ RISCV_REG_F8_D, "fs0" },
	{ RISCV_REG_F9_D, "fs1" },
	{ RISCV_REG_F10_D, "fa0" },
	{ RISCV_REG_F11_D, "fa1" },
	{ RISCV_REG_F12_D, "fa2" },
	{ RISCV_REG_F13_D, "fa3" },
	{ RISCV_REG_F14_D, "fa4" },
	{ RISCV_REG_F15_D, "fa5" },
	{ RISCV_REG_F16_D, "fa6" },
	{ RISCV_REG_F17_D, "fa7" },
	{ RISCV_REG_F18_D, "fs2" },
	{ RISCV_REG_F19_D, "fs3" },
	{ RISCV_REG_F20_D, "fs4" },
	{ RISCV_REG_F21_D, "fs5" },
	{ RISCV_REG_F22_D, "fs6" },
	{ RISCV_REG_F23_D, "fs7" },
	{ RISCV_REG_F24_D, "fs8" },
	{ RISCV_REG_F25_D, "fs9" },
	{ RISCV_REG_F26_D, "fs10" },
	{ RISCV_REG_F27_D, "fs11" },
	{ RISCV_REG_F28_D, "ft8" },
	{ RISCV_REG_F29_D, "ft9" },
	{ RISCV_REG_F30_D, "ft10" },
	{ RISCV_REG_F31_D, "ft11" },

	{ RISCV_REG_F0_F, "ft0" },
	{ RISCV_REG_F1_F, "ft1" },
	{ RISCV_REG_F2_F, "ft2" },
	{ RISCV_REG_F3_F, "ft3" },
	{ RISCV_REG_F4_F, "ft4" },
	{ RISCV_REG_F5_F, "ft5" },
	{ RISCV_REG_F6_F, "ft6" },
	{ RISCV_REG_F7_F, "ft7" },
	{ RISCV_REG_F8_F, "fs0" },
	{ RISCV_REG_F9_F, "fs1" },
	{ RISCV_REG_F10_F, "fa0" },
	{ RISCV_REG_F11_F, "fa1" },
	{ RISCV_REG_F12_F, "fa2" },
	{ RISCV_REG_F13_F, "fa3" },
	{ RISCV_REG_F14_F, "fa4" },
	{ RISCV_REG_F15_F, "fa5" },
	{ RISCV_REG_F16_F, "fa6" },
	{ RISCV_REG_F17_F, "fa7" },
	{ RISCV_REG_F18_F, "fs2" },
	{ RISCV_REG_F19_F, "fs3" },
	{ RISCV_REG_F20_F, "fs4" },
	{ RISCV_REG_F21_F, "fs5" },
	{ RISCV_REG_F22_F, "fs6" },
	{ RISCV_REG_F23_F, "fs7" },
	{ RISCV_REG_F24_F, "fs8" },
	{ RISCV_REG_F25_F, "fs9" },
	{ RISCV_REG_F26_F, "fs10" },
	{ RISCV_REG_F27_F, "fs11" },
	{ RISCV_REG_F28_F, "ft8" },
	{ RISCV_REG_F29_F, "ft9" },
	{ RISCV_REG_F30_F, "ft10" },
	{ RISCV_REG_F31_F, "ft11" },

	{ RISCV_REG_F0_H, "ft0" },
	{ RISCV_REG_F1_H, "ft1" },
	{ RISCV_REG_F2_H, "ft2" },
	{ RISCV_REG_F3_H, "ft3" },
	{ RISCV_REG_F4_H, "ft4" },
	{ RISCV_REG_F5_H, "ft5" },
	{ RISCV_REG_F6_H, "ft6" },
	{ RISCV_REG_F7_H, "ft7" },
	{ RISCV_REG_F8_H, "fs0" },
	{ RISCV_REG_F9_H, "fs1" },
	{ RISCV_REG_F10_H, "fa0" },
	{ RISCV_REG_F11_H, "fa1" },
	{ RISCV_REG_F12_H, "fa2" },
	{ RISCV_REG_F13_H, "fa3" },
	{ RISCV_REG_F14_H, "fa4" },
	{ RISCV_REG_F15_H, "fa5" },
	{ RISCV_REG_F16_H, "fa6" },
	{ RISCV_REG_F17_H, "fa7" },
	{ RISCV_REG_F18_H, "fs2" },
	{ RISCV_REG_F19_H, "fs3" },
	{ RISCV_REG_F20_H, "fs4" },
	{ RISCV_REG_F21_H, "fs5" },
	{ RISCV_REG_F22_H, "fs6" },
	{ RISCV_REG_F23_H, "fs7" },
	{ RISCV_REG_F24_H, "fs8" },
	{ RISCV_REG_F25_H, "fs9" },
	{ RISCV_REG_F26_H, "fs10" },
	{ RISCV_REG_F27_H, "fs11" },
	{ RISCV_REG_F28_H, "ft8" },
	{ RISCV_REG_F29_H, "ft9" },
	{ RISCV_REG_F30_H, "ft10" },
	{ RISCV_REG_F31_H, "ft11" },

	{ RISCV_REG_X0_PAIR, "" },
	{ RISCV_REG_V0M2, "v0m2" },
	{ RISCV_REG_V0M4, "v0m4" },
    { RISCV_REG_V0M8, "v0m8" },
	{ RISCV_REG_V2M2, "v2m2" },
    { RISCV_REG_V4M2, "v4m2" },
	{ RISCV_REG_V4M4, "v4m4" },
	{ RISCV_REG_V6M2, "v6m2" },
	{ RISCV_REG_V8M2, "v8m2" },
	{ RISCV_REG_V8M4, "v8m4" },
	{ RISCV_REG_V8M8, "v8m8" },
	{ RISCV_REG_V10M2, "v10m2" },
	{ RISCV_REG_V12M2, "v12m2" },
	{ RISCV_REG_V12M4, "v12m4" },
	{ RISCV_REG_V14M2, "v14m2" },
	{ RISCV_REG_V16M2, "v16m2" },
	{ RISCV_REG_V16M4, "v16m4" },
	{ RISCV_REG_V16M8, "v16m8" },
	{ RISCV_REG_V18M2, "v18m2" },
	{ RISCV_REG_V20M2, "v20m2" },
	{ RISCV_REG_V20M4, "v20m4" },
	{ RISCV_REG_V22M2, "v22m2" },
	{ RISCV_REG_V24M2, "v24m2" },
	{ RISCV_REG_V24M4, "v24m4" },
	{ RISCV_REG_V24M8, "v24m8" },
	{ RISCV_REG_V26M2, "v26m2" },
	{ RISCV_REG_V28M2, "v28m2" },
	{ RISCV_REG_V28M4, "v28m4" },
	{ RISCV_REG_V30M2, "v30m2" },

	{ RISCV_REG_X2_X3, "" },
	{ RISCV_REG_X4_X5, "" },
	{ RISCV_REG_X6_X7, "" },
	{ RISCV_REG_X8_X9, "" },
	{ RISCV_REG_X10_X11, "" },
	{ RISCV_REG_X12_X13, "" },
	{ RISCV_REG_X14_X15, "" },
	{ RISCV_REG_X16_X17, "" },
	{ RISCV_REG_X18_X19, "" },
	{ RISCV_REG_X20_X21, "" },
	{ RISCV_REG_X22_X23, "" },
	{ RISCV_REG_X24_X25, "" },
	{ RISCV_REG_X26_X27, "" },
	{ RISCV_REG_X28_X29, "" },
	{ RISCV_REG_X30_X31, "" },
	
	{ RISCV_REG_V1_V2, "" },
	{ RISCV_REG_V2_V3, "" },
	{ RISCV_REG_V3_V4, "" },
	{ RISCV_REG_V4_V5, "" },
	{ RISCV_REG_V5_V6, "" },
	{ RISCV_REG_V6_V7, "" },
	{ RISCV_REG_V7_V8, "" },
	{ RISCV_REG_V8_V9, "" },
	{ RISCV_REG_V9_V10, "" },
	{ RISCV_REG_V10_V11, "" },
	{ RISCV_REG_V11_V12, "" },
	{ RISCV_REG_V12_V13, "" },
	{ RISCV_REG_V13_V14, "" },
	{ RISCV_REG_V14_V15, "" },
	{ RISCV_REG_V15_V16, "" },
	{ RISCV_REG_V16_V17, "" },
	{ RISCV_REG_V17_V18, "" },
	{ RISCV_REG_V18_V19, "" },
	{ RISCV_REG_V19_V20, "" },
	{ RISCV_REG_V20_V21, "" },
	{ RISCV_REG_V21_V22, "" },
	{ RISCV_REG_V22_V23, "" },
	{ RISCV_REG_V23_V24, "" },
	{ RISCV_REG_V24_V25, "" },
	{ RISCV_REG_V25_V26, "" },
	{ RISCV_REG_V26_V27, "" },
	{ RISCV_REG_V27_V28, "" },
	{ RISCV_REG_V28_V29, "" },
	{ RISCV_REG_V29_V30, "" },
	{ RISCV_REG_V30_V31, "" },
	{ RISCV_REG_V0_V1, "" },

	{ RISCV_REG_V2M2_V4M2, "" },
	{ RISCV_REG_V4M2_V6M2, "" },
	{ RISCV_REG_V6M2_V8M2, "" },
	{ RISCV_REG_V8M2_V10M2, "" },
	{ RISCV_REG_V10M2_V12M2, "" },
	{ RISCV_REG_V12M2_V14M2, "" },
	{ RISCV_REG_V14M2_V16M2, "" },
	{ RISCV_REG_V16M2_V18M2, "" },
	{ RISCV_REG_V18M2_V20M2, "" },
	{ RISCV_REG_V20M2_V22M2, "" },
	{ RISCV_REG_V22M2_V24M2, "" },
	{ RISCV_REG_V24M2_V26M2, "" },
	{ RISCV_REG_V26M2_V28M2, "" },
	{ RISCV_REG_V28M2_V30M2, "" },
	{ RISCV_REG_V0M2_V2M2, "" },
	{ RISCV_REG_V4M4_V8M4, "" },
	{ RISCV_REG_V8M4_V12M4, "" },
	{ RISCV_REG_V12M4_V16M4, "" },
	{ RISCV_REG_V16M4_V20M4, "" },
	{ RISCV_REG_V20M4_V24M4, "" },
	{ RISCV_REG_V24M4_V28M4, "" },
	{ RISCV_REG_V0M4_V4M4, "" },

	{ RISCV_REG_V1_V2_V3, "" },
	{ RISCV_REG_V2_V3_V4, "" },
	{ RISCV_REG_V3_V4_V5, "" },
	{ RISCV_REG_V4_V5_V6, "" },
	{ RISCV_REG_V5_V6_V7, "" },
	{ RISCV_REG_V6_V7_V8, "" },
	{ RISCV_REG_V7_V8_V9, "" },
	{ RISCV_REG_V8_V9_V10, "" },
	{ RISCV_REG_V9_V10_V11, "" },
	{ RISCV_REG_V10_V11_V12, "" },
	{ RISCV_REG_V11_V12_V13, "" },
	{ RISCV_REG_V12_V13_V14, "" },
	{ RISCV_REG_V13_V14_V15, "" },
	{ RISCV_REG_V14_V15_V16, "" },
	{ RISCV_REG_V15_V16_V17, "" },
	{ RISCV_REG_V16_V17_V18, "" },
	{ RISCV_REG_V17_V18_V19, "" },
	{ RISCV_REG_V18_V19_V20, "" },
	{ RISCV_REG_V19_V20_V21, "" },
	{ RISCV_REG_V20_V21_V22, "" },
	{ RISCV_REG_V21_V22_V23, "" },
	{ RISCV_REG_V22_V23_V24, "" },
	{ RISCV_REG_V23_V24_V25, "" },
	{ RISCV_REG_V24_V25_V26, "" },
	{ RISCV_REG_V25_V26_V27, "" },
	{ RISCV_REG_V26_V27_V28, "" },
	{ RISCV_REG_V27_V28_V29, "" },
	{ RISCV_REG_V28_V29_V30, "" },
	{ RISCV_REG_V29_V30_V31, "" },
	{ RISCV_REG_V0_V1_V2, "" },

	{ RISCV_REG_V2M2_V4M2_V6M2, "" },
	{ RISCV_REG_V4M2_V6M2_V8M2, "" },
	{ RISCV_REG_V6M2_V8M2_V10M2, "" },
	{ RISCV_REG_V8M2_V10M2_V12M2, "" },
	{ RISCV_REG_V10M2_V12M2_V14M2, "" },
	{ RISCV_REG_V12M2_V14M2_V16M2, "" },
	{ RISCV_REG_V14M2_V16M2_V18M2, "" },
	{ RISCV_REG_V16M2_V18M2_V20M2, "" },
	{ RISCV_REG_V18M2_V20M2_V22M2, "" },
	{ RISCV_REG_V20M2_V22M2_V24M2, "" },
	{ RISCV_REG_V22M2_V24M2_V26M2, "" },
	{ RISCV_REG_V24M2_V26M2_V28M2, "" },
	{ RISCV_REG_V26M2_V28M2_V30M2, "" },
	{ RISCV_REG_V0M2_V2M2_V4M2, "" },

	{ RISCV_REG_V1_V2_V3_V4, "" },
	{ RISCV_REG_V2_V3_V4_V5, "" },
	{ RISCV_REG_V3_V4_V5_V6, "" },
	{ RISCV_REG_V4_V5_V6_V7, "" },
	{ RISCV_REG_V5_V6_V7_V8, "" },
	{ RISCV_REG_V6_V7_V8_V9, "" },
	{ RISCV_REG_V7_V8_V9_V10, "" },
	{ RISCV_REG_V8_V9_V10_V11, "" },
	{ RISCV_REG_V9_V10_V11_V12, "" },
	{ RISCV_REG_V10_V11_V12_V13, "" },
	{ RISCV_REG_V11_V12_V13_V14, "" },
	{ RISCV_REG_V12_V13_V14_V15, "" },
	{ RISCV_REG_V13_V14_V15_V16, "" },
	{ RISCV_REG_V14_V15_V16_V17, "" },
	{ RISCV_REG_V15_V16_V17_V18, "" },
	{ RISCV_REG_V16_V17_V18_V19, "" },
	{ RISCV_REG_V17_V18_V19_V20, "" },
	{ RISCV_REG_V18_V19_V20_V21, "" },
	{ RISCV_REG_V19_V20_V21_V22, "" },
	{ RISCV_REG_V20_V21_V22_V23, "" },
	{ RISCV_REG_V21_V22_V23_V24, "" },
	{ RISCV_REG_V22_V23_V24_V25, "" },
	{ RISCV_REG_V23_V24_V25_V26, "" },
	{ RISCV_REG_V24_V25_V26_V27, "" },
	{ RISCV_REG_V25_V26_V27_V28, "" },
	{ RISCV_REG_V26_V27_V28_V29, "" },
	{ RISCV_REG_V27_V28_V29_V30, "" },
	{ RISCV_REG_V28_V29_V30_V31, "" },
	{ RISCV_REG_V0_V1_V2_V3, "" },

	{ RISCV_REG_V2M2_V4M2_V6M2_V8M2, "" },
	{ RISCV_REG_V4M2_V6M2_V8M2_V10M2, "" },
	{ RISCV_REG_V6M2_V8M2_V10M2_V12M2, "" },
	{ RISCV_REG_V8M2_V10M2_V12M2_V14M2, "" },
	{ RISCV_REG_V10M2_V12M2_V14M2_V16M2, "" },
	{ RISCV_REG_V12M2_V14M2_V16M2_V18M2, "" },
	{ RISCV_REG_V14M2_V16M2_V18M2_V20M2, "" },
	{ RISCV_REG_V16M2_V18M2_V20M2_V22M2, "" },
	{ RISCV_REG_V18M2_V20M2_V22M2_V24M2, "" },
	{ RISCV_REG_V20M2_V22M2_V24M2_V26M2, "" },
	{ RISCV_REG_V22M2_V24M2_V26M2_V28M2, "" },
	{ RISCV_REG_V24M2_V26M2_V28M2_V30M2, "" },
	{ RISCV_REG_V0M2_V2M2_V4M2_V6M2, "" },

	{ RISCV_REG_V1_V2_V3_V4_V5, "" },
	{ RISCV_REG_V2_V3_V4_V5_V6, "" },
	{ RISCV_REG_V3_V4_V5_V6_V7, "" },
	{ RISCV_REG_V4_V5_V6_V7_V8, "" },
	{ RISCV_REG_V5_V6_V7_V8_V9, "" },
	{ RISCV_REG_V6_V7_V8_V9_V10, "" },
	{ RISCV_REG_V7_V8_V9_V10_V11, "" },
	{ RISCV_REG_V8_V9_V10_V11_V12, "" },
	{ RISCV_REG_V9_V10_V11_V12_V13, "" },
	{ RISCV_REG_V10_V11_V12_V13_V14, "" },
	{ RISCV_REG_V11_V12_V13_V14_V15, "" },
	{ RISCV_REG_V12_V13_V14_V15_V16, "" },
	{ RISCV_REG_V13_V14_V15_V16_V17, "" },
	{ RISCV_REG_V14_V15_V16_V17_V18, "" },
	{ RISCV_REG_V15_V16_V17_V18_V19, "" },
	{ RISCV_REG_V16_V17_V18_V19_V20, "" },
	{ RISCV_REG_V17_V18_V19_V20_V21, "" },
	{ RISCV_REG_V18_V19_V20_V21_V22, "" },
	{ RISCV_REG_V19_V20_V21_V22_V23, "" },
	{ RISCV_REG_V20_V21_V22_V23_V24, "" },
	{ RISCV_REG_V21_V22_V23_V24_V25, "" },
	{ RISCV_REG_V22_V23_V24_V25_V26, "" },
	{ RISCV_REG_V23_V24_V25_V26_V27, "" },
	{ RISCV_REG_V24_V25_V26_V27_V28, "" },
	{ RISCV_REG_V25_V26_V27_V28_V29, "" },
	{ RISCV_REG_V26_V27_V28_V29_V30, "" },
	{ RISCV_REG_V27_V28_V29_V30_V31, "" },
	{ RISCV_REG_V0_V1_V2_V3_V4, "" },
	
	{ RISCV_REG_V1_V2_V3_V4_V5_V6, "" },
	{ RISCV_REG_V2_V3_V4_V5_V6_V7, "" },
	{ RISCV_REG_V3_V4_V5_V6_V7_V8, "" },
	{ RISCV_REG_V4_V5_V6_V7_V8_V9, "" },
	{ RISCV_REG_V5_V6_V7_V8_V9_V10, "" },
	{ RISCV_REG_V6_V7_V8_V9_V10_V11, "" },
	{ RISCV_REG_V7_V8_V9_V10_V11_V12, "" },
	{ RISCV_REG_V8_V9_V10_V11_V12_V13, "" },
	{ RISCV_REG_V9_V10_V11_V12_V13_V14, "" },
	{ RISCV_REG_V10_V11_V12_V13_V14_V15, "" },
	{ RISCV_REG_V11_V12_V13_V14_V15_V16, "" },
	{ RISCV_REG_V12_V13_V14_V15_V16_V17, "" },
	{ RISCV_REG_V13_V14_V15_V16_V17_V18, "" },
	{ RISCV_REG_V14_V15_V16_V17_V18_V19, "" },
	{ RISCV_REG_V15_V16_V17_V18_V19_V20, "" },
	{ RISCV_REG_V16_V17_V18_V19_V20_V21, "" },
	{ RISCV_REG_V17_V18_V19_V20_V21_V22, "" },
	{ RISCV_REG_V18_V19_V20_V21_V22_V23, "" },
	{ RISCV_REG_V19_V20_V21_V22_V23_V24, "" },
	{ RISCV_REG_V20_V21_V22_V23_V24_V25, "" },
	{ RISCV_REG_V21_V22_V23_V24_V25_V26, "" },
	{ RISCV_REG_V22_V23_V24_V25_V26_V27, "" },
	{ RISCV_REG_V23_V24_V25_V26_V27_V28, "" },
	{ RISCV_REG_V24_V25_V26_V27_V28_V29, "" },
	{ RISCV_REG_V25_V26_V27_V28_V29_V30, "" },
	{ RISCV_REG_V26_V27_V28_V29_V30_V31, "" },
	{ RISCV_REG_V0_V1_V2_V3_V4_V5, "" },

	{ RISCV_REG_V1_V2_V3_V4_V5_V6_V7, "" },
	{ RISCV_REG_V2_V3_V4_V5_V6_V7_V8, "" },
	{ RISCV_REG_V3_V4_V5_V6_V7_V8_V9, "" },
	{ RISCV_REG_V4_V5_V6_V7_V8_V9_V10, "" },
	{ RISCV_REG_V5_V6_V7_V8_V9_V10_V11, "" },
	{ RISCV_REG_V6_V7_V8_V9_V10_V11_V12, "" },
	{ RISCV_REG_V7_V8_V9_V10_V11_V12_V13, "" },
	{ RISCV_REG_V8_V9_V10_V11_V12_V13_V14, "" },
	{ RISCV_REG_V9_V10_V11_V12_V13_V14_V15, "" },
	{ RISCV_REG_V10_V11_V12_V13_V14_V15_V16, "" },
	{ RISCV_REG_V11_V12_V13_V14_V15_V16_V17, "" },
	{ RISCV_REG_V12_V13_V14_V15_V16_V17_V18, "" },
	{ RISCV_REG_V13_V14_V15_V16_V17_V18_V19, "" },
	{ RISCV_REG_V14_V15_V16_V17_V18_V19_V20, "" },
	{ RISCV_REG_V15_V16_V17_V18_V19_V20_V21, "" },
	{ RISCV_REG_V16_V17_V18_V19_V20_V21_V22, "" },
	{ RISCV_REG_V17_V18_V19_V20_V21_V22_V23, "" },
	{ RISCV_REG_V18_V19_V20_V21_V22_V23_V24, "" },
	{ RISCV_REG_V19_V20_V21_V22_V23_V24_V25, "" },
	{ RISCV_REG_V20_V21_V22_V23_V24_V25_V26, "" },
	{ RISCV_REG_V21_V22_V23_V24_V25_V26_V27, "" },
	{ RISCV_REG_V22_V23_V24_V25_V26_V27_V28, "" },
	{ RISCV_REG_V23_V24_V25_V26_V27_V28_V29, "" },
	{ RISCV_REG_V24_V25_V26_V27_V28_V29_V30, "" },
	{ RISCV_REG_V25_V26_V27_V28_V29_V30_V31, "" },
	{ RISCV_REG_V0_V1_V2_V3_V4_V5_V6, "" },

	{ RISCV_REG_V1_V2_V3_V4_V5_V6_V7_V8, "" },
	{ RISCV_REG_V2_V3_V4_V5_V6_V7_V8_V9, "" },
	{ RISCV_REG_V3_V4_V5_V6_V7_V8_V9_V10, "" },
	{ RISCV_REG_V4_V5_V6_V7_V8_V9_V10_V11, "" },
	{ RISCV_REG_V5_V6_V7_V8_V9_V10_V11_V12, "" },
	{ RISCV_REG_V6_V7_V8_V9_V10_V11_V12_V13, "" },
	{ RISCV_REG_V7_V8_V9_V10_V11_V12_V13_V14, "" },
	{ RISCV_REG_V8_V9_V10_V11_V12_V13_V14_V15, "" },
	{ RISCV_REG_V9_V10_V11_V12_V13_V14_V15_V16, "" },
	{ RISCV_REG_V10_V11_V12_V13_V14_V15_V16_V17, "" },
	{ RISCV_REG_V11_V12_V13_V14_V15_V16_V17_V18, "" },
	{ RISCV_REG_V12_V13_V14_V15_V16_V17_V18_V19, "" },
	{ RISCV_REG_V13_V14_V15_V16_V17_V18_V19_V20, "" },
	{ RISCV_REG_V14_V15_V16_V17_V18_V19_V20_V21, "" },
	{ RISCV_REG_V15_V16_V17_V18_V19_V20_V21_V22, "" },
	{ RISCV_REG_V16_V17_V18_V19_V20_V21_V22_V23, "" },
	{ RISCV_REG_V17_V18_V19_V20_V21_V22_V23_V24, "" },
	{ RISCV_REG_V18_V19_V20_V21_V22_V23_V24_V25, "" },
	{ RISCV_REG_V19_V20_V21_V22_V23_V24_V25_V26, "" },
	{ RISCV_REG_V20_V21_V22_V23_V24_V25_V26_V27, "" },
	{ RISCV_REG_V21_V22_V23_V24_V25_V26_V27_V28, "" },
	{ RISCV_REG_V22_V23_V24_V25_V26_V27_V28_V29, "" },
	{ RISCV_REG_V23_V24_V25_V26_V27_V28_V29_V30, "" },
	{ RISCV_REG_V24_V25_V26_V27_V28_V29_V30_V31, "" },
	{ RISCV_REG_V0_V1_V2_V3_V4_V5_V6_V7, "" },
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
#include "RISCVGenCSMappingInsn.inc"
};

#ifndef CAPSTONE_DIET

static const map_insn_ops insn_operands[] = {
#include "RISCVGenCSMappingInsnOp.inc"
};

#endif

void RISCV_add_cs_detail_0(MCInst *MI, riscv_op_group opgroup, unsigned OpNum)
{
	printf("========== OP: %d, (CODE: %d)", OpNum, MI->Opcode);
	switch (opgroup) {

		case RISCV_OP_GROUP_Operand: printf("\n RISCV_OP_GROUP_Operand"); break;
		case RISCV_OP_GROUP_BranchOperand:printf("\n RISCV_OP_GROUP_BranchOperand"); break;
		case RISCV_OP_GROUP_VMaskReg:printf("\n RISCV_OP_GROUP_VMaskReg"); break;
		case RISCV_OP_GROUP_VTypeI:printf("\n RISCV_OP_GROUP_VTypeI "); break;
		case RISCV_OP_GROUP_ZeroOffsetMemOp:printf("\nRISCV_OP_GROUP_ZeroOffsetMemOp"); break;
		case RISCV_OP_GROUP_Rlist:printf("\nRISCV_OP_GROUP_Rlist"); break;
		case RISCV_OP_GROUP_Spimm:printf("\nRISCV_OP_GROUP_Spimm"); break;
		case RISCV_OP_GROUP_CSRSystemRegister:printf("\n RISCV_OP_GROUP_CSRSystemRegister"); break;
		case RISCV_OP_GROUP_RegReg:printf("\nRISCV_OP_GROUP_RegReg"); break;
		case RISCV_OP_GROUP_FRMArg:printf("\nRISCV_OP_GROUP_FRMArg"); break;
		case RISCV_OP_GROUP_FRMArgLegacy:printf("\nRISCV_OP_GROUP_FRMArgLegacy"); break;
		case RISCV_OP_GROUP_FenceArg:printf("\nRISCV_OP_GROUP_FenceArg"); break;
		case RISCV_OP_GROUP_FPImmOperand:printf("\nRISCV_OP_GROUP_FPImmOperand"); break;
	}
	printf("\n================================================================== %d\n", insn_operands[0].ops[0].type);
	if (!detail_is_set(MI))
		return;
	
	cs_detail *details = MI->flat_insn->detail;
	cs_riscv *riscv_details = &(details->riscv);
	cs_riscv_op *op = &(riscv_details->operands[riscv_details->op_count]);
	op->type = (riscv_op_type) map_get_op_type(MI, OpNum);
	op->access = (cs_ac_type) map_get_op_access(MI, OpNum);

	switch (map_get_op_type(MI, OpNum)) {
		case CS_OP_REG:
			op->reg = MCInst_getOperand(MI, OpNum)->RegVal;
			printf("\n *******************  REG %d: %d\n", OpNum, op->reg);
			break;
		case CS_OP_MEM:
			op->mem.base = 0;
			op->mem.disp = MCInst_getOperand(MI, OpNum)->ImmVal;
			printf("\n *******************  REG %d: %d\n", OpNum, op->reg);
			break;
		case CS_OP_IMM:
			op->imm = MCInst_getOperand(MI, OpNum)->ImmVal;
			printf("\n *******************  REG %d: %d\n", OpNum, op->reg);
			break;
		case CS_OP_MEM | CS_OP_REG:
		case CS_OP_MEM | CS_OP_IMM:
			break; // handle the weird combination later 
		case CS_OP_INVALID: break;
		default: {
				FILE *fptr;
				fptr = fopen("output.txt", "w"); // Opens "output.txt" for writing 
			    fprintf(fptr, "PROBLEMTIC OPERAND %d", op->type);
				fclose(fptr);
			CS_ASSERT(0 && "unhandled operand type");	
		}		
	}
	// annoying: the callback is called per operand but the groups are the same every time
	if (OpNum == 0) {
		details->groups_count = 0;
		while (insns[MI->Opcode].groups[details->groups_count] != 0) {
			printf("\n ADDING GROUP %d, FOUND OPCODE %d (i.e. %d) \n", 
				insns[MI->Opcode].groups[details->groups_count],
			 	insns[MI->Opcode].id,
				insns[MI->Opcode].mapid);
			details->groups[details->groups_count] = insns[MI->Opcode].groups[details->groups_count];
			details->groups_count++;
		}
	}
	// add Capstone-specific non-extension groups, LLVM code can't because LLVM doesn't know about them
	// if (array_contains(return_instructions, MI)) {

	// }

	// ===================================================================================
	// switch (opgroup) {
	// 	case RISCV_OP_GROUP_Operand: 
	// 		break;
	// 	case RISCV_OP_GROUP_BranchOperand:
	// 		break;
	// 	case RISCV_OP_GROUP_VMaskReg:
	// 		printf("\n RISCV_OP_GROUP_VMaskReg"); break;
	// 	case RISCV_OP_GROUP_VTypeI:
	// 		printf("\n RISCV_OP_GROUP_VTypeI "); 
	// 		break;
			
	// 	case RISCV_OP_GROUP_ZeroOffsetMemOp:
	// 		op->type = RISCV_OP_MEM;
	// 		printf("\nRISCV_OP_GROUP_ZeroOffsetMemOp"); 
	// 		break;
	// 	case RISCV_OP_GROUP_Rlist:
	// 		printf("\nRISCV_OP_GROUP_Rlist"); 
	// 		break;
	// 	case RISCV_OP_GROUP_Spimm:
	// 		printf("\nRISCV_OP_GROUP_Spimm"); break;
	// 	case RISCV_OP_GROUP_CSRSystemRegister:
	// 		printf("\n RISCV_OP_GROUP_CSRSystemRegister"); 
	// 		break;
	// 	case RISCV_OP_GROUP_RegReg:
	// 		printf("\nRISCV_OP_GROUP_RegReg"); 
	// 		break;
	// 	case RISCV_OP_GROUP_FRMArg:
	// 		printf("\nRISCV_OP_GROUP_FRMArg"); 
	// 		break;
	// 	case RISCV_OP_GROUP_FRMArgLegacy:
	// 		printf("\nRISCV_OP_GROUP_FRMArgLegacy"); 
	// 		break;
	// 	case RISCV_OP_GROUP_FenceArg:
	// 		printf("\nRISCV_OP_GROUP_FenceArg"); 
	// 		break;
	// 	case RISCV_OP_GROUP_FPImmOperand:
	// 		printf("\nRISCV_OP_GROUP_FPImmOperand"); 
	// 		break;
	// 	default:
	// 		CS_ASSERT(0 && "Unhandled operand type in RISCV_add_cs_detail_0");
	// }
	riscv_details->op_count++;
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
  	#include "RISCVGenCSFeatureName.inc"
  
  	{ RISCV_GRP_ENDING,     NULL }
};
#endif

const char *RISCV_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	// verify group id
	printf("GROUP ID: %d\n", id);
	// if past the end
	if (id >= RISCV_GRP_ENDING ||
			// or in the encoding gap between generic groups and arch-specific groups 
            (id > RISCV_GRP_BRANCH_RELATIVE && id < RISCV_FEATURE_HASSTDEXTI))
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

static const insn_map insns[] = {
	// dummy item
	{
		0, 0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},

	{
 /* abs */
		Mips_ABSMacro, MIPS_INS_ABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* abs.d */
		Mips_FABS_D32, MIPS_INS_ABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* abs.d */
		Mips_FABS_D32_MM, MIPS_INS_ABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* abs.d */
		Mips_FABS_D64, MIPS_INS_ABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* abs.d */
		Mips_FABS_D64_MM, MIPS_INS_ABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* abs.s */
		Mips_FABS_S, MIPS_INS_ABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* abs.s */
		Mips_FABS_S_MM, MIPS_INS_ABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* absq_s.ph */
		Mips_ABSQ_S_PH_MM, MIPS_INS_ABSQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* absq_s.ph */
		Mips_ABSQ_S_PH, MIPS_INS_ABSQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* absq_s.qb */
		Mips_ABSQ_S_QB_MMR2, MIPS_INS_ABSQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* absq_s.qb */
		Mips_ABSQ_S_QB, MIPS_INS_ABSQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* absq_s.w */
		Mips_ABSQ_S_W_MM, MIPS_INS_ABSQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* absq_s.w */
		Mips_ABSQ_S_W, MIPS_INS_ABSQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* add */
		Mips_ADD, MIPS_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* add */
		Mips_ADD_MM, MIPS_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* add */
		Mips_ADD_MMR6, MIPS_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* add */
		Mips_ADDi, MIPS_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* add */
		Mips_ADDi_MM, MIPS_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* add */
		Mips_ADD, MIPS_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* add */
		Mips_ADD_MM, MIPS_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* add */
		Mips_ADD_MMR6, MIPS_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* add */
		Mips_ADDi, MIPS_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* add */
		Mips_ADDi_MM, MIPS_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* add.d */
		Mips_FADD_D32, MIPS_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* add.d */
		Mips_FADD_D32_MM, MIPS_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* add.d */
		Mips_FADD_D64, MIPS_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* add.d */
		Mips_FADD_D64_MM, MIPS_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* add.ps */
		Mips_FADD_PS64, MIPS_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* add.s */
		Mips_FADD_S, MIPS_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* add.s */
		Mips_FADD_S_MMR6, MIPS_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* add.s */
		Mips_FADD_S_MM, MIPS_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* add_a.b */
		Mips_ADD_A_B, MIPS_INS_ADD_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* add_a.d */
		Mips_ADD_A_D, MIPS_INS_ADD_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* add_a.h */
		Mips_ADD_A_H, MIPS_INS_ADD_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* add_a.w */
		Mips_ADD_A_W, MIPS_INS_ADD_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* addi */
		Mips_ADDi_MM, MIPS_INS_ADDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* addi */
		Mips_ADDi, MIPS_INS_ADDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* addi */
		Mips_ADDi_MM, MIPS_INS_ADDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* addi */
		Mips_ADDi, MIPS_INS_ADDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* addiu */
		Mips_AddiuSpImmX16, MIPS_INS_ADDIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* addiu */
		Mips_AddiuRxImmX16, MIPS_INS_ADDIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* addiu */
		Mips_ADDIU_MMR6, MIPS_INS_ADDIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* addiu */
		Mips_ADDiu_MM, MIPS_INS_ADDIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* addiu */
		Mips_ADDiu, MIPS_INS_ADDIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* addiu */
		Mips_AddiuRxPcImmX16, MIPS_INS_ADDIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* addiu */
		Mips_AddiuRxRyOffMemX16, MIPS_INS_ADDIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* addiu */
		Mips_ADDIU_MMR6, MIPS_INS_ADDIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* addiu */
		Mips_ADDiu_MM, MIPS_INS_ADDIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* addiu */
		Mips_ADDiu, MIPS_INS_ADDIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* addiu */
		Mips_AddiuSpImm16, MIPS_INS_ADDIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* addiu */
		Mips_AddiuRxRxImm16, MIPS_INS_ADDIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* addiupc */
		Mips_ADDIUPC, MIPS_INS_ADDIUPC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* addiupc */
		Mips_ADDIUPC_MMR6, MIPS_INS_ADDIUPC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* addiupc */
		Mips_ADDIUPC_MM, MIPS_INS_ADDIUPC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* addiur1sp */
		Mips_ADDIUR1SP_MM, MIPS_INS_ADDIUR1SP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* addiur2 */
		Mips_ADDIUR2_MM, MIPS_INS_ADDIUR2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* addius5 */
		Mips_ADDIUS5_MM, MIPS_INS_ADDIUS5,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* addiusp */
		Mips_ADDIUSP_MM, MIPS_INS_ADDIUSP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* addq.ph */
		Mips_ADDQ_PH_MM, MIPS_INS_ADDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* addq.ph */
		Mips_ADDQ_PH, MIPS_INS_ADDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* addq_s.ph */
		Mips_ADDQ_S_PH_MM, MIPS_INS_ADDQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* addq_s.ph */
		Mips_ADDQ_S_PH, MIPS_INS_ADDQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* addq_s.w */
		Mips_ADDQ_S_W_MM, MIPS_INS_ADDQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* addq_s.w */
		Mips_ADDQ_S_W, MIPS_INS_ADDQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* addqh.ph */
		Mips_ADDQH_PH_MMR2, MIPS_INS_ADDQH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* addqh.ph */
		Mips_ADDQH_PH, MIPS_INS_ADDQH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* addqh.w */
		Mips_ADDQH_W_MMR2, MIPS_INS_ADDQH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* addqh.w */
		Mips_ADDQH_W, MIPS_INS_ADDQH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* addqh_r.ph */
		Mips_ADDQH_R_PH_MMR2, MIPS_INS_ADDQH_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* addqh_r.ph */
		Mips_ADDQH_R_PH, MIPS_INS_ADDQH_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* addqh_r.w */
		Mips_ADDQH_R_W_MMR2, MIPS_INS_ADDQH_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* addqh_r.w */
		Mips_ADDQH_R_W, MIPS_INS_ADDQH_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* addr.ps */
		Mips_ADDR_PS64, MIPS_INS_ADDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_MIPS3D, 0 }, 0, 0
#endif
	},
	{
 /* adds_a.b */
		Mips_ADDS_A_B, MIPS_INS_ADDS_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* adds_a.d */
		Mips_ADDS_A_D, MIPS_INS_ADDS_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* adds_a.h */
		Mips_ADDS_A_H, MIPS_INS_ADDS_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* adds_a.w */
		Mips_ADDS_A_W, MIPS_INS_ADDS_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* adds_s.b */
		Mips_ADDS_S_B, MIPS_INS_ADDS_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* adds_s.d */
		Mips_ADDS_S_D, MIPS_INS_ADDS_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* adds_s.h */
		Mips_ADDS_S_H, MIPS_INS_ADDS_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* adds_s.w */
		Mips_ADDS_S_W, MIPS_INS_ADDS_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* adds_u.b */
		Mips_ADDS_U_B, MIPS_INS_ADDS_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* adds_u.d */
		Mips_ADDS_U_D, MIPS_INS_ADDS_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* adds_u.h */
		Mips_ADDS_U_H, MIPS_INS_ADDS_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* adds_u.w */
		Mips_ADDS_U_W, MIPS_INS_ADDS_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* addsc */
		Mips_ADDSC_MM, MIPS_INS_ADDSC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* addsc */
		Mips_ADDSC, MIPS_INS_ADDSC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* addu */
		Mips_ADDU_MMR6, MIPS_INS_ADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* addu */
		Mips_ADDu, MIPS_INS_ADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* addu */
		Mips_ADDu_MM, MIPS_INS_ADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* addu */
		Mips_ADDiu, MIPS_INS_ADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* addu */
		Mips_ADDiu_MM, MIPS_INS_ADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* addu */
		Mips_AdduRxRyRz16, MIPS_INS_ADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* addu */
		Mips_ADDU_MMR6, MIPS_INS_ADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* addu */
		Mips_ADDu, MIPS_INS_ADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* addu */
		Mips_ADDu_MM, MIPS_INS_ADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* addu */
		Mips_ADDiu, MIPS_INS_ADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* addu */
		Mips_ADDiu_MM, MIPS_INS_ADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* addu.ph */
		Mips_ADDU_PH_MMR2, MIPS_INS_ADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* addu.ph */
		Mips_ADDU_PH, MIPS_INS_ADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* addu.qb */
		Mips_ADDU_QB_MM, MIPS_INS_ADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* addu.qb */
		Mips_ADDU_QB, MIPS_INS_ADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* addu16 */
		Mips_ADDU16_MM, MIPS_INS_ADDU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* addu16 */
		Mips_ADDU16_MMR6, MIPS_INS_ADDU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* addu_s.ph */
		Mips_ADDU_S_PH_MMR2, MIPS_INS_ADDU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* addu_s.ph */
		Mips_ADDU_S_PH, MIPS_INS_ADDU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* addu_s.qb */
		Mips_ADDU_S_QB_MM, MIPS_INS_ADDU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* addu_s.qb */
		Mips_ADDU_S_QB, MIPS_INS_ADDU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* adduh.qb */
		Mips_ADDUH_QB_MMR2, MIPS_INS_ADDUH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* adduh.qb */
		Mips_ADDUH_QB, MIPS_INS_ADDUH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* adduh_r.qb */
		Mips_ADDUH_R_QB_MMR2, MIPS_INS_ADDUH_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* adduh_r.qb */
		Mips_ADDUH_R_QB, MIPS_INS_ADDUH_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* addv.b */
		Mips_ADDV_B, MIPS_INS_ADDV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* addv.d */
		Mips_ADDV_D, MIPS_INS_ADDV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* addv.h */
		Mips_ADDV_H, MIPS_INS_ADDV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* addv.w */
		Mips_ADDV_W, MIPS_INS_ADDV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* addvi.b */
		Mips_ADDVI_B, MIPS_INS_ADDVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* addvi.d */
		Mips_ADDVI_D, MIPS_INS_ADDVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* addvi.h */
		Mips_ADDVI_H, MIPS_INS_ADDVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* addvi.w */
		Mips_ADDVI_W, MIPS_INS_ADDVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* addwc */
		Mips_ADDWC_MM, MIPS_INS_ADDWC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* addwc */
		Mips_ADDWC, MIPS_INS_ADDWC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* align */
		Mips_ALIGN, MIPS_INS_ALIGN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* align */
		Mips_ALIGN_MMR6, MIPS_INS_ALIGN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* aluipc */
		Mips_ALUIPC, MIPS_INS_ALUIPC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* aluipc */
		Mips_ALUIPC_MMR6, MIPS_INS_ALUIPC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* and */
		Mips_AndRxRxRy16, MIPS_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* and */
		Mips_AND, MIPS_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* and */
		Mips_AND_MM, MIPS_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* and */
		Mips_AND_MMR6, MIPS_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* and */
		Mips_ANDI_MMR6, MIPS_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* and */
		Mips_ANDi, MIPS_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP32BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* and */
		Mips_ANDi_MM, MIPS_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* and */
		Mips_ANDi64, MIPS_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* and */
		Mips_AND, MIPS_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* and */
		Mips_AND_MM, MIPS_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* and */
		Mips_AND_MMR6, MIPS_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* and */
		Mips_ANDI_MMR6, MIPS_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* and */
		Mips_ANDi, MIPS_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP32BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* and */
		Mips_ANDi_MM, MIPS_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* and */
		Mips_ANDi64, MIPS_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* and.v */
		Mips_AND_V, MIPS_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* and16 */
		Mips_AND16_MM, MIPS_INS_AND16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* and16 */
		Mips_AND16_MMR6, MIPS_INS_AND16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* andi */
		Mips_ANDI_MMR6, MIPS_INS_ANDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* andi */
		Mips_ANDi, MIPS_INS_ANDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* andi */
		Mips_ANDi_MM, MIPS_INS_ANDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* andi */
		Mips_ANDI_MMR6, MIPS_INS_ANDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* andi */
		Mips_ANDi, MIPS_INS_ANDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* andi */
		Mips_ANDi_MM, MIPS_INS_ANDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* andi.b */
		Mips_ANDI_B, MIPS_INS_ANDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* andi16 */
		Mips_ANDI16_MM, MIPS_INS_ANDI16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* andi16 */
		Mips_ANDI16_MMR6, MIPS_INS_ANDI16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* append */
		Mips_APPEND_MMR2, MIPS_INS_APPEND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* append */
		Mips_APPEND, MIPS_INS_APPEND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* asub_s.b */
		Mips_ASUB_S_B, MIPS_INS_ASUB_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* asub_s.d */
		Mips_ASUB_S_D, MIPS_INS_ASUB_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* asub_s.h */
		Mips_ASUB_S_H, MIPS_INS_ASUB_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* asub_s.w */
		Mips_ASUB_S_W, MIPS_INS_ASUB_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* asub_u.b */
		Mips_ASUB_U_B, MIPS_INS_ASUB_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* asub_u.d */
		Mips_ASUB_U_D, MIPS_INS_ASUB_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* asub_u.h */
		Mips_ASUB_U_H, MIPS_INS_ASUB_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* asub_u.w */
		Mips_ASUB_U_W, MIPS_INS_ASUB_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* aui */
		Mips_AUI, MIPS_INS_AUI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* aui */
		Mips_AUI_MMR6, MIPS_INS_AUI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* auipc */
		Mips_AUIPC, MIPS_INS_AUIPC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* auipc */
		Mips_AUIPC_MMR6, MIPS_INS_AUIPC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* ave_s.b */
		Mips_AVE_S_B, MIPS_INS_AVE_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ave_s.d */
		Mips_AVE_S_D, MIPS_INS_AVE_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ave_s.h */
		Mips_AVE_S_H, MIPS_INS_AVE_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ave_s.w */
		Mips_AVE_S_W, MIPS_INS_AVE_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ave_u.b */
		Mips_AVE_U_B, MIPS_INS_AVE_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ave_u.d */
		Mips_AVE_U_D, MIPS_INS_AVE_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ave_u.h */
		Mips_AVE_U_H, MIPS_INS_AVE_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ave_u.w */
		Mips_AVE_U_W, MIPS_INS_AVE_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* aver_s.b */
		Mips_AVER_S_B, MIPS_INS_AVER_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* aver_s.d */
		Mips_AVER_S_D, MIPS_INS_AVER_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* aver_s.h */
		Mips_AVER_S_H, MIPS_INS_AVER_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* aver_s.w */
		Mips_AVER_S_W, MIPS_INS_AVER_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* aver_u.b */
		Mips_AVER_U_B, MIPS_INS_AVER_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* aver_u.d */
		Mips_AVER_U_D, MIPS_INS_AVER_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* aver_u.h */
		Mips_AVER_U_H, MIPS_INS_AVER_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* aver_u.w */
		Mips_AVER_U_W, MIPS_INS_AVER_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* b */
		Mips_BEQ, MIPS_INS_B,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* b */
		Mips_B_MM_Pseudo, MIPS_INS_B,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* b */
		Mips_BimmX16, MIPS_INS_B,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 1, 0
#endif
	},
	{
 /* b */
		Mips_B_MMR6_Pseudo, MIPS_INS_B,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* b */
		Mips_Bimm16, MIPS_INS_B,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 1, 0
#endif
	},
	{
 /* b16 */
		Mips_BC16_MMR6, MIPS_INS_B16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* b16 */
		Mips_B16_MM, MIPS_INS_B16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* baddu */
		Mips_BADDu, MIPS_INS_BADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* baddu */
		Mips_BADDu, MIPS_INS_BADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* bal */
		Mips_BGEZAL, MIPS_INS_BAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* bal */
		Mips_BAL, MIPS_INS_BAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bal */
		Mips_BGEZAL_MM, MIPS_INS_BAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* balc */
		Mips_BALC, MIPS_INS_BALC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* balc */
		Mips_BALC_MMR6, MIPS_INS_BALC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* balign */
		Mips_BALIGN_MMR2, MIPS_INS_BALIGN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* balign */
		Mips_BALIGN, MIPS_INS_BALIGN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* bbit0 */
		Mips_BBIT032, MIPS_INS_BBIT0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bbit0 */
		Mips_BBIT0, MIPS_INS_BBIT0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bbit032 */
		Mips_BBIT032, MIPS_INS_BBIT032,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bbit1 */
		Mips_BBIT132, MIPS_INS_BBIT1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bbit1 */
		Mips_BBIT1, MIPS_INS_BBIT1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bbit132 */
		Mips_BBIT132, MIPS_INS_BBIT132,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bc */
		Mips_BC, MIPS_INS_BC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bc */
		Mips_BC_MMR6, MIPS_INS_BC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bc16 */
		Mips_BC16_MMR6, MIPS_INS_BC16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bc1eqz */
		Mips_BC1EQZ, MIPS_INS_BC1EQZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bc1eqzc */
		Mips_BC1EQZC_MMR6, MIPS_INS_BC1EQZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 1, 0
#endif
	},
	{
 /* bc1f */
		Mips_BC1F, MIPS_INS_BC1F,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bc1f */
		Mips_BC1F_MM, MIPS_INS_BC1F,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 1, 0
#endif
	},
	{
 /* bc1f */
		Mips_BC1F, MIPS_INS_BC1F,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bc1f */
		Mips_BC1F_MM, MIPS_INS_BC1F,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 1, 0
#endif
	},
	{
 /* bc1fl */
		Mips_BC1FL, MIPS_INS_BC1FL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bc1fl */
		Mips_BC1FL, MIPS_INS_BC1FL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bc1nez */
		Mips_BC1NEZ, MIPS_INS_BC1NEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bc1nezc */
		Mips_BC1NEZC_MMR6, MIPS_INS_BC1NEZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 1, 0
#endif
	},
	{
 /* bc1t */
		Mips_BC1T, MIPS_INS_BC1T,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bc1t */
		Mips_BC1T_MM, MIPS_INS_BC1T,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 1, 0
#endif
	},
	{
 /* bc1t */
		Mips_BC1T, MIPS_INS_BC1T,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bc1t */
		Mips_BC1T_MM, MIPS_INS_BC1T,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 1, 0
#endif
	},
	{
 /* bc1tl */
		Mips_BC1TL, MIPS_INS_BC1TL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bc1tl */
		Mips_BC1TL, MIPS_INS_BC1TL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bc2eqz */
		Mips_BC2EQZ, MIPS_INS_BC2EQZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bc2eqzc */
		Mips_BC2EQZC_MMR6, MIPS_INS_BC2EQZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bc2nez */
		Mips_BC2NEZ, MIPS_INS_BC2NEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bc2nezc */
		Mips_BC2NEZC_MMR6, MIPS_INS_BC2NEZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bclr.b */
		Mips_BCLR_B, MIPS_INS_BCLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bclr.d */
		Mips_BCLR_D, MIPS_INS_BCLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bclr.h */
		Mips_BCLR_H, MIPS_INS_BCLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bclr.w */
		Mips_BCLR_W, MIPS_INS_BCLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bclri.b */
		Mips_BCLRI_B, MIPS_INS_BCLRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bclri.d */
		Mips_BCLRI_D, MIPS_INS_BCLRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bclri.h */
		Mips_BCLRI_H, MIPS_INS_BCLRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bclri.w */
		Mips_BCLRI_W, MIPS_INS_BCLRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* beq */
		Mips_BEQ, MIPS_INS_BEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* beq */
		Mips_BEQ_MM, MIPS_INS_BEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* beq */
		Mips_BeqImm, MIPS_INS_BEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* beqc */
		Mips_BEQC, MIPS_INS_BEQC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* beqc */
		Mips_BEQC_MMR6, MIPS_INS_BEQC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* beqc */
		Mips_BEQC64, MIPS_INS_BEQC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS64R6, 0 }, 1, 0
#endif
	},
	{
 /* beql */
		Mips_BEQL, MIPS_INS_BEQL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* beql */
		Mips_BEQLImmMacro, MIPS_INS_BEQL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* beqz */
		Mips_BeqzRxImmX16, MIPS_INS_BEQZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 1, 0
#endif
	},
	{
 /* beqz */
		Mips_BEQ, MIPS_INS_BEQZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* beqz */
		Mips_BEQ_MM, MIPS_INS_BEQZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* beqz */
		Mips_BeqzRxImm16, MIPS_INS_BEQZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 1, 0
#endif
	},
	{
 /* beqz16 */
		Mips_BEQZ16_MM, MIPS_INS_BEQZ16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* beqz16 */
		Mips_BEQZC16_MMR6, MIPS_INS_BEQZ16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* beqzalc */
		Mips_BEQZALC, MIPS_INS_BEQZALC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* beqzalc */
		Mips_BEQZALC_MMR6, MIPS_INS_BEQZALC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* beqzc */
		Mips_BEQZC, MIPS_INS_BEQZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* beqzc */
		Mips_BEQZC_MM, MIPS_INS_BEQZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* beqzc */
		Mips_BEQZC_MMR6, MIPS_INS_BEQZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* beqzc */
		Mips_BEQZC64, MIPS_INS_BEQZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS64R6, 0 }, 1, 0
#endif
	},
	{
 /* beqzc16 */
		Mips_BEQZC16_MMR6, MIPS_INS_BEQZC16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* beqzl */
		Mips_BEQL, MIPS_INS_BEQZL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bge */
		Mips_BGE, MIPS_INS_BGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* bge */
		Mips_BGEImmMacro, MIPS_INS_BGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* bgec */
		Mips_BGEC, MIPS_INS_BGEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bgec */
		Mips_BGEC_MMR6, MIPS_INS_BGEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bgec */
		Mips_BGEC64, MIPS_INS_BGEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS64R6, 0 }, 1, 0
#endif
	},
	{
 /* bgel */
		Mips_BGEL, MIPS_INS_BGEL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* bgel */
		Mips_BGELImmMacro, MIPS_INS_BGEL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* bgeu */
		Mips_BGEU, MIPS_INS_BGEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* bgeu */
		Mips_BGEUImmMacro, MIPS_INS_BGEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* bgeuc */
		Mips_BGEUC, MIPS_INS_BGEUC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bgeuc */
		Mips_BGEUC_MMR6, MIPS_INS_BGEUC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bgeuc */
		Mips_BGEUC64, MIPS_INS_BGEUC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS64R6, 0 }, 1, 0
#endif
	},
	{
 /* bgeul */
		Mips_BGEUL, MIPS_INS_BGEUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* bgeul */
		Mips_BGEULImmMacro, MIPS_INS_BGEUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* bgez */
		Mips_BGEZ, MIPS_INS_BGEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bgez */
		Mips_BGEZ_MM, MIPS_INS_BGEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bgezal */
		Mips_BGEZAL, MIPS_INS_BGEZAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* bgezal */
		Mips_BGEZAL_MM, MIPS_INS_BGEZAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* bgezalc */
		Mips_BGEZALC, MIPS_INS_BGEZALC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bgezalc */
		Mips_BGEZALC_MMR6, MIPS_INS_BGEZALC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bgezall */
		Mips_BGEZALL, MIPS_INS_BGEZALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* bgezals */
		Mips_BGEZALS_MM, MIPS_INS_BGEZALS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* bgezc */
		Mips_BGEZC, MIPS_INS_BGEZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bgezc */
		Mips_BGEZC_MMR6, MIPS_INS_BGEZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bgezc */
		Mips_BGEZC64, MIPS_INS_BGEZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS64R6, 0 }, 1, 0
#endif
	},
	{
 /* bgezl */
		Mips_BGEZL, MIPS_INS_BGEZL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bgt */
		Mips_BGT, MIPS_INS_BGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* bgt */
		Mips_BGTImmMacro, MIPS_INS_BGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* bgtl */
		Mips_BGTL, MIPS_INS_BGTL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* bgtl */
		Mips_BGTLImmMacro, MIPS_INS_BGTL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* bgtu */
		Mips_BGTU, MIPS_INS_BGTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* bgtu */
		Mips_BGTUImmMacro, MIPS_INS_BGTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* bgtul */
		Mips_BGTUL, MIPS_INS_BGTUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* bgtul */
		Mips_BGTULImmMacro, MIPS_INS_BGTUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* bgtz */
		Mips_BGTZ, MIPS_INS_BGTZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bgtz */
		Mips_BGTZ_MM, MIPS_INS_BGTZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bgtzalc */
		Mips_BGTZALC, MIPS_INS_BGTZALC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bgtzalc */
		Mips_BGTZALC_MMR6, MIPS_INS_BGTZALC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bgtzc */
		Mips_BGTZC, MIPS_INS_BGTZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bgtzc */
		Mips_BGTZC_MMR6, MIPS_INS_BGTZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bgtzc */
		Mips_BGTZC64, MIPS_INS_BGTZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS64R6, 0 }, 1, 0
#endif
	},
	{
 /* bgtzl */
		Mips_BGTZL, MIPS_INS_BGTZL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* binsl.b */
		Mips_BINSL_B, MIPS_INS_BINSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* binsl.d */
		Mips_BINSL_D, MIPS_INS_BINSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* binsl.h */
		Mips_BINSL_H, MIPS_INS_BINSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* binsl.w */
		Mips_BINSL_W, MIPS_INS_BINSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* binsli.b */
		Mips_BINSLI_B, MIPS_INS_BINSLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* binsli.d */
		Mips_BINSLI_D, MIPS_INS_BINSLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* binsli.h */
		Mips_BINSLI_H, MIPS_INS_BINSLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* binsli.w */
		Mips_BINSLI_W, MIPS_INS_BINSLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* binsr.b */
		Mips_BINSR_B, MIPS_INS_BINSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* binsr.d */
		Mips_BINSR_D, MIPS_INS_BINSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* binsr.h */
		Mips_BINSR_H, MIPS_INS_BINSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* binsr.w */
		Mips_BINSR_W, MIPS_INS_BINSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* binsri.b */
		Mips_BINSRI_B, MIPS_INS_BINSRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* binsri.d */
		Mips_BINSRI_D, MIPS_INS_BINSRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* binsri.h */
		Mips_BINSRI_H, MIPS_INS_BINSRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* binsri.w */
		Mips_BINSRI_W, MIPS_INS_BINSRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bitrev */
		Mips_BITREV_MM, MIPS_INS_BITREV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* bitrev */
		Mips_BITREV, MIPS_INS_BITREV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* bitswap */
		Mips_BITSWAP, MIPS_INS_BITSWAP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* bitswap */
		Mips_BITSWAP_MMR6, MIPS_INS_BITSWAP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* ble */
		Mips_BLE, MIPS_INS_BLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* ble */
		Mips_BLEImmMacro, MIPS_INS_BLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* blel */
		Mips_BLEL, MIPS_INS_BLEL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* blel */
		Mips_BLELImmMacro, MIPS_INS_BLEL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* bleu */
		Mips_BLEU, MIPS_INS_BLEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* bleu */
		Mips_BLEUImmMacro, MIPS_INS_BLEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* bleul */
		Mips_BLEUL, MIPS_INS_BLEUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* bleul */
		Mips_BLEULImmMacro, MIPS_INS_BLEUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* blez */
		Mips_BLEZ, MIPS_INS_BLEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* blez */
		Mips_BLEZ_MM, MIPS_INS_BLEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* blezalc */
		Mips_BLEZALC, MIPS_INS_BLEZALC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* blezalc */
		Mips_BLEZALC_MMR6, MIPS_INS_BLEZALC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* blezc */
		Mips_BLEZC, MIPS_INS_BLEZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* blezc */
		Mips_BLEZC_MMR6, MIPS_INS_BLEZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* blezc */
		Mips_BLEZC64, MIPS_INS_BLEZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS64R6, 0 }, 1, 0
#endif
	},
	{
 /* blezl */
		Mips_BLEZL, MIPS_INS_BLEZL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* blt */
		Mips_BLT, MIPS_INS_BLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* blt */
		Mips_BLTImmMacro, MIPS_INS_BLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* bltc */
		Mips_BLTC, MIPS_INS_BLTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bltc */
		Mips_BLTC_MMR6, MIPS_INS_BLTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bltc */
		Mips_BLTC64, MIPS_INS_BLTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS64R6, 0 }, 1, 0
#endif
	},
	{
 /* bltl */
		Mips_BLTL, MIPS_INS_BLTL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* bltl */
		Mips_BLTLImmMacro, MIPS_INS_BLTL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* bltu */
		Mips_BLTU, MIPS_INS_BLTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* bltu */
		Mips_BLTUImmMacro, MIPS_INS_BLTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* bltuc */
		Mips_BLTUC, MIPS_INS_BLTUC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bltuc */
		Mips_BLTUC_MMR6, MIPS_INS_BLTUC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bltuc */
		Mips_BLTUC64, MIPS_INS_BLTUC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS64R6, 0 }, 1, 0
#endif
	},
	{
 /* bltul */
		Mips_BLTUL, MIPS_INS_BLTUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* bltul */
		Mips_BLTULImmMacro, MIPS_INS_BLTUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* bltz */
		Mips_BLTZ, MIPS_INS_BLTZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bltz */
		Mips_BLTZ_MM, MIPS_INS_BLTZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bltzal */
		Mips_BLTZAL, MIPS_INS_BLTZAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* bltzal */
		Mips_BLTZAL_MM, MIPS_INS_BLTZAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* bltzalc */
		Mips_BLTZALC, MIPS_INS_BLTZALC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bltzalc */
		Mips_BLTZALC_MMR6, MIPS_INS_BLTZALC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bltzall */
		Mips_BLTZALL, MIPS_INS_BLTZALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* bltzals */
		Mips_BLTZALS_MM, MIPS_INS_BLTZALS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* bltzc */
		Mips_BLTZC, MIPS_INS_BLTZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bltzc */
		Mips_BLTZC_MMR6, MIPS_INS_BLTZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bltzc */
		Mips_BLTZC64, MIPS_INS_BLTZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS64R6, 0 }, 1, 0
#endif
	},
	{
 /* bltzl */
		Mips_BLTZL, MIPS_INS_BLTZL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bmnz.v */
		Mips_BMNZ_V, MIPS_INS_BMNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bmnzi.b */
		Mips_BMNZI_B, MIPS_INS_BMNZI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bmz.v */
		Mips_BMZ_V, MIPS_INS_BMZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bmzi.b */
		Mips_BMZI_B, MIPS_INS_BMZI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bne */
		Mips_BNE, MIPS_INS_BNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bne */
		Mips_BNE_MM, MIPS_INS_BNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bne */
		Mips_BneImm, MIPS_INS_BNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* bnec */
		Mips_BNEC, MIPS_INS_BNEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bnec */
		Mips_BNEC_MMR6, MIPS_INS_BNEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bnec */
		Mips_BNEC64, MIPS_INS_BNEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS64R6, 0 }, 1, 0
#endif
	},
	{
 /* bneg.b */
		Mips_BNEG_B, MIPS_INS_BNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bneg.d */
		Mips_BNEG_D, MIPS_INS_BNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bneg.h */
		Mips_BNEG_H, MIPS_INS_BNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bneg.w */
		Mips_BNEG_W, MIPS_INS_BNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bnegi.b */
		Mips_BNEGI_B, MIPS_INS_BNEGI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bnegi.d */
		Mips_BNEGI_D, MIPS_INS_BNEGI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bnegi.h */
		Mips_BNEGI_H, MIPS_INS_BNEGI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bnegi.w */
		Mips_BNEGI_W, MIPS_INS_BNEGI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bnel */
		Mips_BNEL, MIPS_INS_BNEL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bnel */
		Mips_BNELImmMacro, MIPS_INS_BNEL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* bnez */
		Mips_BnezRxImmX16, MIPS_INS_BNEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 1, 0
#endif
	},
	{
 /* bnez */
		Mips_BNE, MIPS_INS_BNEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bnez */
		Mips_BNE_MM, MIPS_INS_BNEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bnez */
		Mips_BnezRxImm16, MIPS_INS_BNEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 1, 0
#endif
	},
	{
 /* bnez16 */
		Mips_BNEZ16_MM, MIPS_INS_BNEZ16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bnez16 */
		Mips_BNEZC16_MMR6, MIPS_INS_BNEZ16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bnezalc */
		Mips_BNEZALC, MIPS_INS_BNEZALC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bnezalc */
		Mips_BNEZALC_MMR6, MIPS_INS_BNEZALC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bnezc */
		Mips_BNEZC, MIPS_INS_BNEZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bnezc */
		Mips_BNEZC_MM, MIPS_INS_BNEZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bnezc */
		Mips_BNEZC_MMR6, MIPS_INS_BNEZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bnezc */
		Mips_BNEZC64, MIPS_INS_BNEZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS64R6, 0 }, 1, 0
#endif
	},
	{
 /* bnezc16 */
		Mips_BNEZC16_MMR6, MIPS_INS_BNEZC16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bnezl */
		Mips_BNEL, MIPS_INS_BNEZL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bnvc */
		Mips_BNVC, MIPS_INS_BNVC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bnvc */
		Mips_BNVC_MMR6, MIPS_INS_BNVC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bnz.b */
		Mips_BNZ_B, MIPS_INS_BNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 1, 0
#endif
	},
	{
 /* bnz.d */
		Mips_BNZ_D, MIPS_INS_BNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 1, 0
#endif
	},
	{
 /* bnz.h */
		Mips_BNZ_H, MIPS_INS_BNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 1, 0
#endif
	},
	{
 /* bnz.v */
		Mips_BNZ_V, MIPS_INS_BNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 1, 0
#endif
	},
	{
 /* bnz.w */
		Mips_BNZ_W, MIPS_INS_BNZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 1, 0
#endif
	},
	{
 /* bovc */
		Mips_BOVC, MIPS_INS_BOVC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bovc */
		Mips_BOVC_MMR6, MIPS_INS_BOVC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* bposge32 */
		Mips_BPOSGE32_MM, MIPS_INS_BPOSGE32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_DSP, 0 }, 1, 0
#endif
	},
	{
 /* bposge32 */
		Mips_BPOSGE32, MIPS_INS_BPOSGE32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* bposge32c */
		Mips_BPOSGE32C_MMR3, MIPS_INS_BPOSGE32C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR3, 0 }, 1, 0
#endif
	},
	{
 /* break */
		Mips_BREAK, MIPS_INS_BREAK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* break */
		Mips_BREAK_MM, MIPS_INS_BREAK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* break */
		Mips_Break16, MIPS_INS_BREAK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* break */
		Mips_BREAK, MIPS_INS_BREAK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* break */
		Mips_BREAK_MM, MIPS_INS_BREAK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* break */
		Mips_BREAK, MIPS_INS_BREAK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* break */
		Mips_BREAK_MMR6, MIPS_INS_BREAK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* break */
		Mips_BREAK_MM, MIPS_INS_BREAK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* break16 */
		Mips_BREAK16_MM, MIPS_INS_BREAK16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* break16 */
		Mips_BREAK16_MMR6, MIPS_INS_BREAK16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* bsel.v */
		Mips_BSEL_V, MIPS_INS_BSEL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bseli.b */
		Mips_BSELI_B, MIPS_INS_BSELI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bset.b */
		Mips_BSET_B, MIPS_INS_BSET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bset.d */
		Mips_BSET_D, MIPS_INS_BSET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bset.h */
		Mips_BSET_H, MIPS_INS_BSET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bset.w */
		Mips_BSET_W, MIPS_INS_BSET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bseti.b */
		Mips_BSETI_B, MIPS_INS_BSETI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bseti.d */
		Mips_BSETI_D, MIPS_INS_BSETI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bseti.h */
		Mips_BSETI_H, MIPS_INS_BSETI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bseti.w */
		Mips_BSETI_W, MIPS_INS_BSETI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* bteqz */
		Mips_BteqzX16, MIPS_INS_BTEQZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 1, 0
#endif
	},
	{
 /* bteqz */
		Mips_Bteqz16, MIPS_INS_BTEQZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 1, 0
#endif
	},
	{
 /* btnez */
		Mips_BtnezX16, MIPS_INS_BTNEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 1, 0
#endif
	},
	{
 /* btnez */
		Mips_Btnez16, MIPS_INS_BTNEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 1, 0
#endif
	},
	{
 /* bz.b */
		Mips_BZ_B, MIPS_INS_BZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 1, 0
#endif
	},
	{
 /* bz.d */
		Mips_BZ_D, MIPS_INS_BZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 1, 0
#endif
	},
	{
 /* bz.h */
		Mips_BZ_H, MIPS_INS_BZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 1, 0
#endif
	},
	{
 /* bz.v */
		Mips_BZ_V, MIPS_INS_BZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 1, 0
#endif
	},
	{
 /* bz.w */
		Mips_BZ_W, MIPS_INS_BZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 1, 0
#endif
	},
	{
 /* c.eq.d */
		Mips_C_EQ_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.eq.d */
		Mips_C_EQ_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.eq.d */
		Mips_C_EQ_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.eq.d */
		Mips_C_EQ_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.eq.d */
		Mips_C_EQ_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.eq.d */
		Mips_C_EQ_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.eq.d */
		Mips_C_EQ_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.eq.d */
		Mips_C_EQ_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.eq.s */
		Mips_C_EQ_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.eq.s */
		Mips_C_EQ_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.eq.s */
		Mips_C_EQ_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.eq.s */
		Mips_C_EQ_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.f.d */
		Mips_C_F_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.f.d */
		Mips_C_F_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.f.d */
		Mips_C_F_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.f.d */
		Mips_C_F_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.f.d */
		Mips_C_F_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.f.d */
		Mips_C_F_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.f.d */
		Mips_C_F_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.f.d */
		Mips_C_F_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.f.s */
		Mips_C_F_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.f.s */
		Mips_C_F_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.f.s */
		Mips_C_F_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.f.s */
		Mips_C_F_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.le.d */
		Mips_C_LE_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.le.d */
		Mips_C_LE_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.le.d */
		Mips_C_LE_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.le.d */
		Mips_C_LE_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.le.d */
		Mips_C_LE_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.le.d */
		Mips_C_LE_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.le.d */
		Mips_C_LE_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.le.d */
		Mips_C_LE_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.le.s */
		Mips_C_LE_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.le.s */
		Mips_C_LE_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.le.s */
		Mips_C_LE_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.le.s */
		Mips_C_LE_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.lt.d */
		Mips_C_LT_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.lt.d */
		Mips_C_LT_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.lt.d */
		Mips_C_LT_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.lt.d */
		Mips_C_LT_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.lt.d */
		Mips_C_LT_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.lt.d */
		Mips_C_LT_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.lt.d */
		Mips_C_LT_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.lt.d */
		Mips_C_LT_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.lt.s */
		Mips_C_LT_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.lt.s */
		Mips_C_LT_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.lt.s */
		Mips_C_LT_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.lt.s */
		Mips_C_LT_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.nge.d */
		Mips_C_NGE_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.nge.d */
		Mips_C_NGE_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.nge.d */
		Mips_C_NGE_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.nge.d */
		Mips_C_NGE_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.nge.d */
		Mips_C_NGE_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.nge.d */
		Mips_C_NGE_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.nge.d */
		Mips_C_NGE_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.nge.d */
		Mips_C_NGE_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.nge.s */
		Mips_C_NGE_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.nge.s */
		Mips_C_NGE_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.nge.s */
		Mips_C_NGE_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.nge.s */
		Mips_C_NGE_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ngl.d */
		Mips_C_NGL_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ngl.d */
		Mips_C_NGL_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ngl.d */
		Mips_C_NGL_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ngl.d */
		Mips_C_NGL_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ngl.d */
		Mips_C_NGL_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ngl.d */
		Mips_C_NGL_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ngl.d */
		Mips_C_NGL_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ngl.d */
		Mips_C_NGL_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ngl.s */
		Mips_C_NGL_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ngl.s */
		Mips_C_NGL_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ngl.s */
		Mips_C_NGL_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ngl.s */
		Mips_C_NGL_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ngle.d */
		Mips_C_NGLE_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ngle.d */
		Mips_C_NGLE_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ngle.d */
		Mips_C_NGLE_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ngle.d */
		Mips_C_NGLE_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ngle.d */
		Mips_C_NGLE_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ngle.d */
		Mips_C_NGLE_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ngle.d */
		Mips_C_NGLE_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ngle.d */
		Mips_C_NGLE_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ngle.s */
		Mips_C_NGLE_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ngle.s */
		Mips_C_NGLE_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ngle.s */
		Mips_C_NGLE_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ngle.s */
		Mips_C_NGLE_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ngt.d */
		Mips_C_NGT_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ngt.d */
		Mips_C_NGT_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ngt.d */
		Mips_C_NGT_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ngt.d */
		Mips_C_NGT_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ngt.d */
		Mips_C_NGT_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ngt.d */
		Mips_C_NGT_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ngt.d */
		Mips_C_NGT_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ngt.d */
		Mips_C_NGT_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ngt.s */
		Mips_C_NGT_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ngt.s */
		Mips_C_NGT_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ngt.s */
		Mips_C_NGT_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ngt.s */
		Mips_C_NGT_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ole.d */
		Mips_C_OLE_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ole.d */
		Mips_C_OLE_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ole.d */
		Mips_C_OLE_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ole.d */
		Mips_C_OLE_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ole.d */
		Mips_C_OLE_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ole.d */
		Mips_C_OLE_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ole.d */
		Mips_C_OLE_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ole.d */
		Mips_C_OLE_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ole.s */
		Mips_C_OLE_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ole.s */
		Mips_C_OLE_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ole.s */
		Mips_C_OLE_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ole.s */
		Mips_C_OLE_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.olt.d */
		Mips_C_OLT_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.olt.d */
		Mips_C_OLT_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.olt.d */
		Mips_C_OLT_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.olt.d */
		Mips_C_OLT_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.olt.d */
		Mips_C_OLT_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.olt.d */
		Mips_C_OLT_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.olt.d */
		Mips_C_OLT_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.olt.d */
		Mips_C_OLT_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.olt.s */
		Mips_C_OLT_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.olt.s */
		Mips_C_OLT_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.olt.s */
		Mips_C_OLT_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.olt.s */
		Mips_C_OLT_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.seq.d */
		Mips_C_SEQ_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.seq.d */
		Mips_C_SEQ_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.seq.d */
		Mips_C_SEQ_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.seq.d */
		Mips_C_SEQ_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.seq.d */
		Mips_C_SEQ_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.seq.d */
		Mips_C_SEQ_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.seq.d */
		Mips_C_SEQ_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.seq.d */
		Mips_C_SEQ_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.seq.s */
		Mips_C_SEQ_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.seq.s */
		Mips_C_SEQ_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.seq.s */
		Mips_C_SEQ_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.seq.s */
		Mips_C_SEQ_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.sf.d */
		Mips_C_SF_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.sf.d */
		Mips_C_SF_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.sf.d */
		Mips_C_SF_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.sf.d */
		Mips_C_SF_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.sf.d */
		Mips_C_SF_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.sf.d */
		Mips_C_SF_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.sf.d */
		Mips_C_SF_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.sf.d */
		Mips_C_SF_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.sf.s */
		Mips_C_SF_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.sf.s */
		Mips_C_SF_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.sf.s */
		Mips_C_SF_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.sf.s */
		Mips_C_SF_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ueq.d */
		Mips_C_UEQ_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ueq.d */
		Mips_C_UEQ_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ueq.d */
		Mips_C_UEQ_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ueq.d */
		Mips_C_UEQ_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ueq.d */
		Mips_C_UEQ_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ueq.d */
		Mips_C_UEQ_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ueq.d */
		Mips_C_UEQ_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ueq.d */
		Mips_C_UEQ_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ueq.s */
		Mips_C_UEQ_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ueq.s */
		Mips_C_UEQ_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ueq.s */
		Mips_C_UEQ_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ueq.s */
		Mips_C_UEQ_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ule.d */
		Mips_C_ULE_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ule.d */
		Mips_C_ULE_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ule.d */
		Mips_C_ULE_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ule.d */
		Mips_C_ULE_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ule.d */
		Mips_C_ULE_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ule.d */
		Mips_C_ULE_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ule.d */
		Mips_C_ULE_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ule.d */
		Mips_C_ULE_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ule.s */
		Mips_C_ULE_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ule.s */
		Mips_C_ULE_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ule.s */
		Mips_C_ULE_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ule.s */
		Mips_C_ULE_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ult.d */
		Mips_C_ULT_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ult.d */
		Mips_C_ULT_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ult.d */
		Mips_C_ULT_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ult.d */
		Mips_C_ULT_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ult.d */
		Mips_C_ULT_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ult.d */
		Mips_C_ULT_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ult.d */
		Mips_C_ULT_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ult.d */
		Mips_C_ULT_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ult.s */
		Mips_C_ULT_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ult.s */
		Mips_C_ULT_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.ult.s */
		Mips_C_ULT_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.ult.s */
		Mips_C_ULT_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.un.d */
		Mips_C_UN_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.un.d */
		Mips_C_UN_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.un.d */
		Mips_C_UN_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.un.d */
		Mips_C_UN_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.un.d */
		Mips_C_UN_D32, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.un.d */
		Mips_C_UN_D32_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.un.d */
		Mips_C_UN_D64, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.un.d */
		Mips_C_UN_D64_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.un.s */
		Mips_C_UN_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.un.s */
		Mips_C_UN_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* c.un.s */
		Mips_C_UN_S, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* c.un.s */
		Mips_C_UN_S_MM, MIPS_INS_C,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cache */
		Mips_CACHE_R6, MIPS_INS_CACHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cache */
		Mips_CACHE, MIPS_INS_CACHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cache */
		Mips_CACHE_MM, MIPS_INS_CACHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* cache */
		Mips_CACHE_MMR6, MIPS_INS_CACHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* cachee */
		Mips_CACHEE, MIPS_INS_CACHEE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_EVA, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cachee */
		Mips_CACHEE_MM, MIPS_INS_CACHEE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_EVA, 0 }, 0, 0
#endif
	},
	{
 /* ceil.l.d */
		Mips_CEIL_L_D64, MIPS_INS_CEIL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS3_32, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ceil.l.d */
		Mips_CEIL_L_D_MMR6, MIPS_INS_CEIL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* ceil.l.s */
		Mips_CEIL_L_S, MIPS_INS_CEIL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ceil.l.s */
		Mips_CEIL_L_S_MMR6, MIPS_INS_CEIL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* ceil.w.d */
		Mips_CEIL_W_D32, MIPS_INS_CEIL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ceil.w.d */
		Mips_CEIL_W_D_MMR6, MIPS_INS_CEIL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* ceil.w.d */
		Mips_CEIL_W_MM, MIPS_INS_CEIL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* ceil.w.d */
		Mips_CEIL_W_D64, MIPS_INS_CEIL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ceil.w.s */
		Mips_CEIL_W_S, MIPS_INS_CEIL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ceil.w.s */
		Mips_CEIL_W_S_MMR6, MIPS_INS_CEIL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* ceil.w.s */
		Mips_CEIL_W_S_MM, MIPS_INS_CEIL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* ceq.b */
		Mips_CEQ_B, MIPS_INS_CEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ceq.d */
		Mips_CEQ_D, MIPS_INS_CEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ceq.h */
		Mips_CEQ_H, MIPS_INS_CEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ceq.w */
		Mips_CEQ_W, MIPS_INS_CEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ceqi.b */
		Mips_CEQI_B, MIPS_INS_CEQI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ceqi.d */
		Mips_CEQI_D, MIPS_INS_CEQI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ceqi.h */
		Mips_CEQI_H, MIPS_INS_CEQI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ceqi.w */
		Mips_CEQI_W, MIPS_INS_CEQI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* cfc1 */
		Mips_CFC1, MIPS_INS_CFC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cfc1 */
		Mips_CFC1_MM, MIPS_INS_CFC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cfc2 */
		Mips_CFC2_MM, MIPS_INS_CFC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cfcmsa */
		Mips_CFCMSA, MIPS_INS_CFCMSA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* cftc1 */
		Mips_CFTC1, MIPS_INS_CFTC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, 0 }, 0, 0
#endif
	},
	{
 /* cins */
		Mips_CINS, MIPS_INS_CINS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS64, MIPS_GRP_CNMIPS, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cins */
		Mips_CINS32, MIPS_INS_CINS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS64, MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cins */
		Mips_CINS, MIPS_INS_CINS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS64, MIPS_GRP_CNMIPS, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cins */
		Mips_CINS32, MIPS_INS_CINS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS64, MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cins32 */
		Mips_CINS32, MIPS_INS_CINS32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS64, MIPS_GRP_CNMIPS, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cins32 */
		Mips_CINS32, MIPS_INS_CINS32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS64, MIPS_GRP_CNMIPS, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* class.d */
		Mips_CLASS_D, MIPS_INS_CLASS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* class.d */
		Mips_CLASS_D_MMR6, MIPS_INS_CLASS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* class.s */
		Mips_CLASS_S, MIPS_INS_CLASS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* class.s */
		Mips_CLASS_S_MMR6, MIPS_INS_CLASS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* cle_s.b */
		Mips_CLE_S_B, MIPS_INS_CLE_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* cle_s.d */
		Mips_CLE_S_D, MIPS_INS_CLE_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* cle_s.h */
		Mips_CLE_S_H, MIPS_INS_CLE_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* cle_s.w */
		Mips_CLE_S_W, MIPS_INS_CLE_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* cle_u.b */
		Mips_CLE_U_B, MIPS_INS_CLE_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* cle_u.d */
		Mips_CLE_U_D, MIPS_INS_CLE_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* cle_u.h */
		Mips_CLE_U_H, MIPS_INS_CLE_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* cle_u.w */
		Mips_CLE_U_W, MIPS_INS_CLE_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* clei_s.b */
		Mips_CLEI_S_B, MIPS_INS_CLEI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* clei_s.d */
		Mips_CLEI_S_D, MIPS_INS_CLEI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* clei_s.h */
		Mips_CLEI_S_H, MIPS_INS_CLEI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* clei_s.w */
		Mips_CLEI_S_W, MIPS_INS_CLEI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* clei_u.b */
		Mips_CLEI_U_B, MIPS_INS_CLEI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* clei_u.d */
		Mips_CLEI_U_D, MIPS_INS_CLEI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* clei_u.h */
		Mips_CLEI_U_H, MIPS_INS_CLEI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* clei_u.w */
		Mips_CLEI_U_W, MIPS_INS_CLEI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* clo */
		Mips_CLO, MIPS_INS_CLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* clo */
		Mips_CLO_MMR6, MIPS_INS_CLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* clo */
		Mips_CLO_R6, MIPS_INS_CLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* clo */
		Mips_CLO_MM, MIPS_INS_CLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* clt_s.b */
		Mips_CLT_S_B, MIPS_INS_CLT_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* clt_s.d */
		Mips_CLT_S_D, MIPS_INS_CLT_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* clt_s.h */
		Mips_CLT_S_H, MIPS_INS_CLT_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* clt_s.w */
		Mips_CLT_S_W, MIPS_INS_CLT_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* clt_u.b */
		Mips_CLT_U_B, MIPS_INS_CLT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* clt_u.d */
		Mips_CLT_U_D, MIPS_INS_CLT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* clt_u.h */
		Mips_CLT_U_H, MIPS_INS_CLT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* clt_u.w */
		Mips_CLT_U_W, MIPS_INS_CLT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* clti_s.b */
		Mips_CLTI_S_B, MIPS_INS_CLTI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* clti_s.d */
		Mips_CLTI_S_D, MIPS_INS_CLTI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* clti_s.h */
		Mips_CLTI_S_H, MIPS_INS_CLTI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* clti_s.w */
		Mips_CLTI_S_W, MIPS_INS_CLTI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* clti_u.b */
		Mips_CLTI_U_B, MIPS_INS_CLTI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* clti_u.d */
		Mips_CLTI_U_D, MIPS_INS_CLTI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* clti_u.h */
		Mips_CLTI_U_H, MIPS_INS_CLTI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* clti_u.w */
		Mips_CLTI_U_W, MIPS_INS_CLTI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* clz */
		Mips_CLZ, MIPS_INS_CLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* clz */
		Mips_CLZ_MMR6, MIPS_INS_CLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* clz */
		Mips_CLZ_R6, MIPS_INS_CLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* clz */
		Mips_CLZ_MM, MIPS_INS_CLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp */
		Mips_CmpRxRy16, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* cmp.af.d */
		Mips_CMP_F_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.af.d */
		Mips_CMP_AF_D_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.af.s */
		Mips_CMP_F_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.af.s */
		Mips_CMP_AF_S_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.eq.d */
		Mips_CMP_EQ_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.eq.d */
		Mips_CMP_EQ_D_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.eq.ph */
		Mips_CMP_EQ_PH_MM, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* cmp.eq.ph */
		Mips_CMP_EQ_PH, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* cmp.eq.s */
		Mips_CMP_EQ_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.eq.s */
		Mips_CMP_EQ_S_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.le.d */
		Mips_CMP_LE_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.le.d */
		Mips_CMP_LE_D_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.le.ph */
		Mips_CMP_LE_PH_MM, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* cmp.le.ph */
		Mips_CMP_LE_PH, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* cmp.le.s */
		Mips_CMP_LE_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.le.s */
		Mips_CMP_LE_S_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.lt.d */
		Mips_CMP_LT_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.lt.d */
		Mips_CMP_LT_D_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.lt.ph */
		Mips_CMP_LT_PH_MM, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* cmp.lt.ph */
		Mips_CMP_LT_PH, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* cmp.lt.s */
		Mips_CMP_LT_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.lt.s */
		Mips_CMP_LT_S_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.saf.d */
		Mips_CMP_SAF_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.saf.d */
		Mips_CMP_SAF_D_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.saf.s */
		Mips_CMP_SAF_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.saf.s */
		Mips_CMP_SAF_S_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.seq.d */
		Mips_CMP_SEQ_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.seq.d */
		Mips_CMP_SEQ_D_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.seq.s */
		Mips_CMP_SEQ_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.seq.s */
		Mips_CMP_SEQ_S_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.sle.d */
		Mips_CMP_SLE_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.sle.d */
		Mips_CMP_SLE_D_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.sle.s */
		Mips_CMP_SLE_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.sle.s */
		Mips_CMP_SLE_S_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.slt.d */
		Mips_CMP_SLT_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.slt.d */
		Mips_CMP_SLT_D_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.slt.s */
		Mips_CMP_SLT_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.slt.s */
		Mips_CMP_SLT_S_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.sueq.d */
		Mips_CMP_SUEQ_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.sueq.d */
		Mips_CMP_SUEQ_D_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.sueq.s */
		Mips_CMP_SUEQ_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.sueq.s */
		Mips_CMP_SUEQ_S_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.sule.d */
		Mips_CMP_SULE_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.sule.d */
		Mips_CMP_SULE_D_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.sule.s */
		Mips_CMP_SULE_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.sule.s */
		Mips_CMP_SULE_S_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.sult.d */
		Mips_CMP_SULT_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.sult.d */
		Mips_CMP_SULT_D_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.sult.s */
		Mips_CMP_SULT_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.sult.s */
		Mips_CMP_SULT_S_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.sun.d */
		Mips_CMP_SUN_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.sun.d */
		Mips_CMP_SUN_D_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.sun.s */
		Mips_CMP_SUN_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.sun.s */
		Mips_CMP_SUN_S_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.ueq.d */
		Mips_CMP_UEQ_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.ueq.d */
		Mips_CMP_UEQ_D_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.ueq.s */
		Mips_CMP_UEQ_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.ueq.s */
		Mips_CMP_UEQ_S_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.ule.d */
		Mips_CMP_ULE_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.ule.d */
		Mips_CMP_ULE_D_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.ule.s */
		Mips_CMP_ULE_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.ule.s */
		Mips_CMP_ULE_S_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.ult.d */
		Mips_CMP_ULT_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.ult.d */
		Mips_CMP_ULT_D_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.ult.s */
		Mips_CMP_ULT_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.ult.s */
		Mips_CMP_ULT_S_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.un.d */
		Mips_CMP_UN_D, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.un.d */
		Mips_CMP_UN_D_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmp.un.s */
		Mips_CMP_UN_S, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cmp.un.s */
		Mips_CMP_UN_S_MMR6, MIPS_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cmpgdu.eq.qb */
		Mips_CMPGDU_EQ_QB_MMR2, MIPS_INS_CMPGDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* cmpgdu.eq.qb */
		Mips_CMPGDU_EQ_QB, MIPS_INS_CMPGDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* cmpgdu.le.qb */
		Mips_CMPGDU_LE_QB_MMR2, MIPS_INS_CMPGDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* cmpgdu.le.qb */
		Mips_CMPGDU_LE_QB, MIPS_INS_CMPGDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* cmpgdu.lt.qb */
		Mips_CMPGDU_LT_QB_MMR2, MIPS_INS_CMPGDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* cmpgdu.lt.qb */
		Mips_CMPGDU_LT_QB, MIPS_INS_CMPGDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* cmpgu.eq.qb */
		Mips_CMPGU_EQ_QB_MM, MIPS_INS_CMPGU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* cmpgu.eq.qb */
		Mips_CMPGU_EQ_QB, MIPS_INS_CMPGU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* cmpgu.le.qb */
		Mips_CMPGU_LE_QB_MM, MIPS_INS_CMPGU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* cmpgu.le.qb */
		Mips_CMPGU_LE_QB, MIPS_INS_CMPGU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* cmpgu.lt.qb */
		Mips_CMPGU_LT_QB_MM, MIPS_INS_CMPGU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* cmpgu.lt.qb */
		Mips_CMPGU_LT_QB, MIPS_INS_CMPGU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* cmpi */
		Mips_CmpiRxImmX16, MIPS_INS_CMPI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* cmpi */
		Mips_CmpiRxImm16, MIPS_INS_CMPI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* cmpu.eq.qb */
		Mips_CMPU_EQ_QB_MM, MIPS_INS_CMPU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* cmpu.eq.qb */
		Mips_CMPU_EQ_QB, MIPS_INS_CMPU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* cmpu.le.qb */
		Mips_CMPU_LE_QB_MM, MIPS_INS_CMPU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* cmpu.le.qb */
		Mips_CMPU_LE_QB, MIPS_INS_CMPU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* cmpu.lt.qb */
		Mips_CMPU_LT_QB_MM, MIPS_INS_CMPU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* cmpu.lt.qb */
		Mips_CMPU_LT_QB, MIPS_INS_CMPU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* copy_s.b */
		Mips_COPY_S_B, MIPS_INS_COPY_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* copy_s.d */
		Mips_COPY_S_D, MIPS_INS_COPY_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, MIPS_GRP_MIPS64, 0 }, 0, 0
#endif
	},
	{
 /* copy_s.h */
		Mips_COPY_S_H, MIPS_INS_COPY_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* copy_s.w */
		Mips_COPY_S_W, MIPS_INS_COPY_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* copy_u.b */
		Mips_COPY_U_B, MIPS_INS_COPY_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* copy_u.h */
		Mips_COPY_U_H, MIPS_INS_COPY_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* copy_u.w */
		Mips_COPY_U_W, MIPS_INS_COPY_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, MIPS_GRP_MIPS64, 0 }, 0, 0
#endif
	},
	{
 /* crc32b */
		Mips_CRC32B, MIPS_INS_CRC32B,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_CRC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* crc32cb */
		Mips_CRC32CB, MIPS_INS_CRC32CB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_CRC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* crc32cd */
		Mips_CRC32CD, MIPS_INS_CRC32CD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, MIPS_GRP_CRC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* crc32ch */
		Mips_CRC32CH, MIPS_INS_CRC32CH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_CRC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* crc32cw */
		Mips_CRC32CW, MIPS_INS_CRC32CW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_CRC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* crc32d */
		Mips_CRC32D, MIPS_INS_CRC32D,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, MIPS_GRP_CRC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* crc32h */
		Mips_CRC32H, MIPS_INS_CRC32H,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_CRC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* crc32w */
		Mips_CRC32W, MIPS_INS_CRC32W,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_CRC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ctc1 */
		Mips_CTC1, MIPS_INS_CTC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ctc1 */
		Mips_CTC1_MM, MIPS_INS_CTC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* ctc2 */
		Mips_CTC2_MM, MIPS_INS_CTC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ctcmsa */
		Mips_CTCMSA, MIPS_INS_CTCMSA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* cttc1 */
		Mips_CTTC1, MIPS_INS_CTTC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, 0 }, 0, 0
#endif
	},
	{
 /* cvt.d.l */
		Mips_CVT_D64_L, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS3_32R2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cvt.d.l */
		Mips_CVT_D_L_MMR6, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cvt.d.s */
		Mips_CVT_D32_S, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cvt.d.s */
		Mips_CVT_D32_S_MM, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cvt.d.s */
		Mips_CVT_D64_S, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cvt.d.s */
		Mips_CVT_D64_S_MM, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cvt.d.w */
		Mips_CVT_D32_W, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cvt.d.w */
		Mips_CVT_D32_W_MM, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cvt.d.w */
		Mips_CVT_D64_W, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cvt.d.w */
		Mips_CVT_D64_W_MM, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cvt.l.d */
		Mips_CVT_L_D64, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3_32R2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cvt.l.d */
		Mips_CVT_L_D64_MM, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cvt.l.d */
		Mips_CVT_L_D_MMR6, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cvt.l.s */
		Mips_CVT_L_S, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3_32R2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cvt.l.s */
		Mips_CVT_L_S_MM, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cvt.l.s */
		Mips_CVT_L_S_MMR6, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cvt.ps.pw */
		Mips_CVT_PS_PW64, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_MIPS3D, 0 }, 0, 0
#endif
	},
	{
 /* cvt.ps.s */
		Mips_CVT_PS_S64, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cvt.pw.ps */
		Mips_CVT_PW_PS64, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_MIPS3D, 0 }, 0, 0
#endif
	},
	{
 /* cvt.s.d */
		Mips_CVT_S_D32, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cvt.s.d */
		Mips_CVT_S_D32_MM, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cvt.s.d */
		Mips_CVT_S_D64, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cvt.s.d */
		Mips_CVT_S_D64_MM, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cvt.s.l */
		Mips_CVT_S_L, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS3_32R2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cvt.s.l */
		Mips_CVT_S_L_MMR6, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cvt.s.pl */
		Mips_CVT_S_PL64, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cvt.s.pu */
		Mips_CVT_S_PU64, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cvt.s.w */
		Mips_CVT_S_W, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cvt.s.w */
		Mips_CVT_S_W_MMR6, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cvt.s.w */
		Mips_CVT_S_W_MM, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cvt.w.d */
		Mips_CVT_W_D32, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cvt.w.d */
		Mips_CVT_W_D32_MM, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cvt.w.d */
		Mips_CVT_W_D64, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cvt.w.d */
		Mips_CVT_W_D64_MM, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cvt.w.s */
		Mips_CVT_W_S, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* cvt.w.s */
		Mips_CVT_W_S_MMR6, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* cvt.w.s */
		Mips_CVT_W_S_MM, MIPS_INS_CVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* dadd */
		Mips_DADD, MIPS_INS_DADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dadd */
		Mips_DADDi, MIPS_INS_DADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dadd */
		Mips_DADD, MIPS_INS_DADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dadd */
		Mips_DADDi, MIPS_INS_DADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* daddi */
		Mips_DADDi, MIPS_INS_DADDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* daddi */
		Mips_DADDi, MIPS_INS_DADDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* daddiu */
		Mips_DADDiu, MIPS_INS_DADDIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* daddiu */
		Mips_DADDiu, MIPS_INS_DADDIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* daddu */
		Mips_DADDu, MIPS_INS_DADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* daddu */
		Mips_DADDiu, MIPS_INS_DADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* daddu */
		Mips_DADDu, MIPS_INS_DADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* daddu */
		Mips_DADDiu, MIPS_INS_DADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dahi */
		Mips_DAHI, MIPS_INS_DAHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dalign */
		Mips_DALIGN, MIPS_INS_DALIGN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dati */
		Mips_DATI, MIPS_INS_DATI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* daui */
		Mips_DAUI, MIPS_INS_DAUI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dbitswap */
		Mips_DBITSWAP, MIPS_INS_DBITSWAP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dclo */
		Mips_DCLO, MIPS_INS_DCLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS64, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dclo */
		Mips_DCLO_R6, MIPS_INS_DCLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dclz */
		Mips_DCLZ, MIPS_INS_DCLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS64, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dclz */
		Mips_DCLZ_R6, MIPS_INS_DCLZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ddiv */
		Mips_DSDivMacro, MIPS_INS_DDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ddiv */
		Mips_DSDivIMacro, MIPS_INS_DDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ddiv */
		Mips_DSDIV, MIPS_INS_DDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ddiv */
		Mips_DSDivMacro, MIPS_INS_DDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ddiv */
		Mips_DDIV, MIPS_INS_DDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ddiv */
		Mips_DSDivIMacro, MIPS_INS_DDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ddivu */
		Mips_DUDivMacro, MIPS_INS_DDIVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ddivu */
		Mips_DUDivIMacro, MIPS_INS_DDIVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ddivu */
		Mips_DUDIV, MIPS_INS_DDIVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ddivu */
		Mips_DUDivMacro, MIPS_INS_DDIVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ddivu */
		Mips_DDIVU, MIPS_INS_DDIVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ddivu */
		Mips_DUDivIMacro, MIPS_INS_DDIVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* deret */
		Mips_DERET, MIPS_INS_DERET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* deret */
		Mips_DERET_MMR6, MIPS_INS_DERET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* deret */
		Mips_DERET_MM, MIPS_INS_DERET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dext */
		Mips_DEXTM, MIPS_INS_DEXT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dext */
		Mips_DEXTU, MIPS_INS_DEXT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dext */
		Mips_DEXT, MIPS_INS_DEXT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dextm */
		Mips_DEXTM, MIPS_INS_DEXTM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dextu */
		Mips_DEXTU, MIPS_INS_DEXTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* di */
		Mips_DI, MIPS_INS_DI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* di */
		Mips_DI_MMR6, MIPS_INS_DI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* di */
		Mips_DI_MM, MIPS_INS_DI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* di */
		Mips_DI, MIPS_INS_DI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* di */
		Mips_DI_MMR6, MIPS_INS_DI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* di */
		Mips_DI_MM, MIPS_INS_DI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dins */
		Mips_DINSM, MIPS_INS_DINS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dins */
		Mips_DINSU, MIPS_INS_DINS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dins */
		Mips_DINS, MIPS_INS_DINS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dinsm */
		Mips_DINSM, MIPS_INS_DINSM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dinsu */
		Mips_DINSU, MIPS_INS_DINSU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* div */
		Mips_DIV, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* div */
		Mips_SDivIMacro, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* div */
		Mips_SDivMacro, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* div */
		Mips_SDIV, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* div */
		Mips_DivRxRy16, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* div */
		Mips_SDIV, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* div */
		Mips_SDIV_MM, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* div */
		Mips_DIV, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* div */
		Mips_DIV_MMR6, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* div */
		Mips_SDivIMacro, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* div */
		Mips_SDivMacro, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* div.d */
		Mips_FDIV_D32, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* div.d */
		Mips_FDIV_D32_MM, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* div.d */
		Mips_FDIV_D64, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* div.d */
		Mips_FDIV_D64_MM, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* div.s */
		Mips_FDIV_S, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* div.s */
		Mips_FDIV_S_MMR6, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* div.s */
		Mips_FDIV_S_MM, MIPS_INS_DIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* div_s.b */
		Mips_DIV_S_B, MIPS_INS_DIV_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* div_s.d */
		Mips_DIV_S_D, MIPS_INS_DIV_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* div_s.h */
		Mips_DIV_S_H, MIPS_INS_DIV_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* div_s.w */
		Mips_DIV_S_W, MIPS_INS_DIV_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* div_u.b */
		Mips_DIV_U_B, MIPS_INS_DIV_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* div_u.d */
		Mips_DIV_U_D, MIPS_INS_DIV_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* div_u.h */
		Mips_DIV_U_H, MIPS_INS_DIV_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* div_u.w */
		Mips_DIV_U_W, MIPS_INS_DIV_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* divu */
		Mips_DIVU, MIPS_INS_DIVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* divu */
		Mips_UDivIMacro, MIPS_INS_DIVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* divu */
		Mips_UDivMacro, MIPS_INS_DIVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* divu */
		Mips_UDIV, MIPS_INS_DIVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* divu */
		Mips_DivuRxRy16, MIPS_INS_DIVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* divu */
		Mips_UDIV, MIPS_INS_DIVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* divu */
		Mips_UDIV_MM, MIPS_INS_DIVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* divu */
		Mips_UDivMacro, MIPS_INS_DIVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* divu */
		Mips_DIVU, MIPS_INS_DIVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* divu */
		Mips_DIVU_MMR6, MIPS_INS_DIVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* divu */
		Mips_UDivIMacro, MIPS_INS_DIVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* dla */
		Mips_LoadAddrImm64, MIPS_INS_DLA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* dla */
		Mips_LoadAddrReg64, MIPS_INS_DLA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* dli */
		Mips_LoadImm64, MIPS_INS_DLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* dlsa */
		Mips_DLSA, MIPS_INS_DLSA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, MIPS_GRP_MIPS64, 0 }, 0, 0
#endif
	},
	{
 /* dlsa */
		Mips_DLSA_R6, MIPS_INS_DLSA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dmfc0 */
		Mips_DMFC0, MIPS_INS_DMFC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dmfc0 */
		Mips_DMFC0, MIPS_INS_DMFC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS3, 0 }, 0, 0
#endif
	},
	{
 /* dmfc1 */
		Mips_DMFC1, MIPS_INS_DMFC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dmfc2 */
		Mips_DMFC2, MIPS_INS_DMFC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* dmfc2 */
		Mips_DMFC2_OCTEON, MIPS_INS_DMFC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dmfc2 */
		Mips_DMFC2, MIPS_INS_DMFC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS3, 0 }, 0, 0
#endif
	},
	{
 /* dmfgc0 */
		Mips_DMFGC0, MIPS_INS_DMFGC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R5, MIPS_GRP_VIRT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dmfgc0 */
		Mips_DMFGC0, MIPS_INS_DMFGC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R5, MIPS_GRP_VIRT, 0 }, 0, 0
#endif
	},
	{
 /* dmod */
		Mips_DMOD, MIPS_INS_DMOD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dmodu */
		Mips_DMODU, MIPS_INS_DMODU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dmt */
		Mips_DMT, MIPS_INS_DMT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dmt */
		Mips_DMT, MIPS_INS_DMT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dmtc0 */
		Mips_DMTC0, MIPS_INS_DMTC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dmtc0 */
		Mips_DMTC0, MIPS_INS_DMTC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS3, 0 }, 0, 0
#endif
	},
	{
 /* dmtc1 */
		Mips_DMTC1, MIPS_INS_DMTC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dmtc2 */
		Mips_DMTC2, MIPS_INS_DMTC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* dmtc2 */
		Mips_DMTC2_OCTEON, MIPS_INS_DMTC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dmtc2 */
		Mips_DMTC2, MIPS_INS_DMTC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS3, 0 }, 0, 0
#endif
	},
	{
 /* dmtgc0 */
		Mips_DMTGC0, MIPS_INS_DMTGC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R5, MIPS_GRP_VIRT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dmtgc0 */
		Mips_DMTGC0, MIPS_INS_DMTGC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R5, MIPS_GRP_VIRT, 0 }, 0, 0
#endif
	},
	{
 /* dmuh */
		Mips_DMUH, MIPS_INS_DMUH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dmuhu */
		Mips_DMUHU, MIPS_INS_DMUHU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dmul */
		Mips_DMUL, MIPS_INS_DMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dmul */
		Mips_DMULMacro, MIPS_INS_DMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTCNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dmul */
		Mips_DMUL_R6, MIPS_INS_DMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dmul */
		Mips_DMUL, MIPS_INS_DMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dmul */
		Mips_DMULImmMacro, MIPS_INS_DMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* dmulo */
		Mips_DMULOMacro, MIPS_INS_DMULO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* dmulou */
		Mips_DMULOUMacro, MIPS_INS_DMULOU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* dmult */
		Mips_DMULT, MIPS_INS_DMULT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dmultu */
		Mips_DMULTu, MIPS_INS_DMULTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dmulu */
		Mips_DMULU, MIPS_INS_DMULU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dneg */
		Mips_DSUB, MIPS_INS_DNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dneg */
		Mips_DSUB, MIPS_INS_DNEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dnegu */
		Mips_DSUBu, MIPS_INS_DNEGU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dnegu */
		Mips_DSUBu, MIPS_INS_DNEGU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dotp_s.d */
		Mips_DOTP_S_D, MIPS_INS_DOTP_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* dotp_s.h */
		Mips_DOTP_S_H, MIPS_INS_DOTP_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* dotp_s.w */
		Mips_DOTP_S_W, MIPS_INS_DOTP_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* dotp_u.d */
		Mips_DOTP_U_D, MIPS_INS_DOTP_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* dotp_u.h */
		Mips_DOTP_U_H, MIPS_INS_DOTP_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* dotp_u.w */
		Mips_DOTP_U_W, MIPS_INS_DOTP_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* dpa.w.ph */
		Mips_DPA_W_PH_MMR2, MIPS_INS_DPA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* dpa.w.ph */
		Mips_DPA_W_PH, MIPS_INS_DPA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* dpadd_s.d */
		Mips_DPADD_S_D, MIPS_INS_DPADD_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* dpadd_s.h */
		Mips_DPADD_S_H, MIPS_INS_DPADD_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* dpadd_s.w */
		Mips_DPADD_S_W, MIPS_INS_DPADD_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* dpadd_u.d */
		Mips_DPADD_U_D, MIPS_INS_DPADD_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* dpadd_u.h */
		Mips_DPADD_U_H, MIPS_INS_DPADD_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* dpadd_u.w */
		Mips_DPADD_U_W, MIPS_INS_DPADD_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* dpaq_s.w.ph */
		Mips_DPAQ_S_W_PH_MM, MIPS_INS_DPAQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* dpaq_s.w.ph */
		Mips_DPAQ_S_W_PH, MIPS_INS_DPAQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* dpaq_sa.l.w */
		Mips_DPAQ_SA_L_W_MM, MIPS_INS_DPAQ_SA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* dpaq_sa.l.w */
		Mips_DPAQ_SA_L_W, MIPS_INS_DPAQ_SA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* dpaqx_s.w.ph */
		Mips_DPAQX_S_W_PH_MMR2, MIPS_INS_DPAQX_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* dpaqx_s.w.ph */
		Mips_DPAQX_S_W_PH, MIPS_INS_DPAQX_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* dpaqx_sa.w.ph */
		Mips_DPAQX_SA_W_PH_MMR2, MIPS_INS_DPAQX_SA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* dpaqx_sa.w.ph */
		Mips_DPAQX_SA_W_PH, MIPS_INS_DPAQX_SA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* dpau.h.qbl */
		Mips_DPAU_H_QBL_MM, MIPS_INS_DPAU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* dpau.h.qbl */
		Mips_DPAU_H_QBL, MIPS_INS_DPAU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* dpau.h.qbr */
		Mips_DPAU_H_QBR_MM, MIPS_INS_DPAU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* dpau.h.qbr */
		Mips_DPAU_H_QBR, MIPS_INS_DPAU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* dpax.w.ph */
		Mips_DPAX_W_PH_MMR2, MIPS_INS_DPAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* dpax.w.ph */
		Mips_DPAX_W_PH, MIPS_INS_DPAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* dpop */
		Mips_DPOP, MIPS_INS_DPOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dpop */
		Mips_DPOP, MIPS_INS_DPOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dps.w.ph */
		Mips_DPS_W_PH_MMR2, MIPS_INS_DPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* dps.w.ph */
		Mips_DPS_W_PH, MIPS_INS_DPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* dpsq_s.w.ph */
		Mips_DPSQ_S_W_PH_MM, MIPS_INS_DPSQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* dpsq_s.w.ph */
		Mips_DPSQ_S_W_PH, MIPS_INS_DPSQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* dpsq_sa.l.w */
		Mips_DPSQ_SA_L_W_MM, MIPS_INS_DPSQ_SA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* dpsq_sa.l.w */
		Mips_DPSQ_SA_L_W, MIPS_INS_DPSQ_SA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* dpsqx_s.w.ph */
		Mips_DPSQX_S_W_PH_MMR2, MIPS_INS_DPSQX_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* dpsqx_s.w.ph */
		Mips_DPSQX_S_W_PH, MIPS_INS_DPSQX_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* dpsqx_sa.w.ph */
		Mips_DPSQX_SA_W_PH_MMR2, MIPS_INS_DPSQX_SA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* dpsqx_sa.w.ph */
		Mips_DPSQX_SA_W_PH, MIPS_INS_DPSQX_SA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* dpsu.h.qbl */
		Mips_DPSU_H_QBL_MM, MIPS_INS_DPSU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* dpsu.h.qbl */
		Mips_DPSU_H_QBL, MIPS_INS_DPSU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* dpsu.h.qbr */
		Mips_DPSU_H_QBR_MM, MIPS_INS_DPSU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* dpsu.h.qbr */
		Mips_DPSU_H_QBR, MIPS_INS_DPSU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* dpsub_s.d */
		Mips_DPSUB_S_D, MIPS_INS_DPSUB_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* dpsub_s.h */
		Mips_DPSUB_S_H, MIPS_INS_DPSUB_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* dpsub_s.w */
		Mips_DPSUB_S_W, MIPS_INS_DPSUB_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* dpsub_u.d */
		Mips_DPSUB_U_D, MIPS_INS_DPSUB_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* dpsub_u.h */
		Mips_DPSUB_U_H, MIPS_INS_DPSUB_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* dpsub_u.w */
		Mips_DPSUB_U_W, MIPS_INS_DPSUB_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* dpsx.w.ph */
		Mips_DPSX_W_PH_MMR2, MIPS_INS_DPSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* dpsx.w.ph */
		Mips_DPSX_W_PH, MIPS_INS_DPSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* drem */
		Mips_DSRemMacro, MIPS_INS_DREM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* drem */
		Mips_DSRemIMacro, MIPS_INS_DREM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* drem */
		Mips_DSRemMacro, MIPS_INS_DREM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* drem */
		Mips_DSRemIMacro, MIPS_INS_DREM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dremu */
		Mips_DURemMacro, MIPS_INS_DREMU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dremu */
		Mips_DURemIMacro, MIPS_INS_DREMU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dremu */
		Mips_DURemMacro, MIPS_INS_DREMU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dremu */
		Mips_DURemIMacro, MIPS_INS_DREMU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* drol */
		Mips_DROL, MIPS_INS_DROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64, 0 }, 0, 0
#endif
	},
	{
 /* drol */
		Mips_DROLImm, MIPS_INS_DROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64, 0 }, 0, 0
#endif
	},
	{
 /* drol */
		Mips_DROL, MIPS_INS_DROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64, 0 }, 0, 0
#endif
	},
	{
 /* drol */
		Mips_DROLImm, MIPS_INS_DROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64, 0 }, 0, 0
#endif
	},
	{
 /* dror */
		Mips_DROR, MIPS_INS_DROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64, 0 }, 0, 0
#endif
	},
	{
 /* dror */
		Mips_DRORImm, MIPS_INS_DROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64, 0 }, 0, 0
#endif
	},
	{
 /* dror */
		Mips_DROR, MIPS_INS_DROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64, 0 }, 0, 0
#endif
	},
	{
 /* dror */
		Mips_DRORImm, MIPS_INS_DROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64, 0 }, 0, 0
#endif
	},
	{
 /* drotr */
		Mips_DROTR, MIPS_INS_DROTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* drotr */
		Mips_DROTR, MIPS_INS_DROTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* drotr32 */
		Mips_DROTR32, MIPS_INS_DROTR32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* drotr32 */
		Mips_DROTR32, MIPS_INS_DROTR32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* drotrv */
		Mips_DROTRV, MIPS_INS_DROTRV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsbh */
		Mips_DSBH, MIPS_INS_DSBH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dshd */
		Mips_DSHD, MIPS_INS_DSHD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsll */
		Mips_DSLLV, MIPS_INS_DSLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsll */
		Mips_DSLL, MIPS_INS_DSLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsll */
		Mips_DSLLV, MIPS_INS_DSLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsll */
		Mips_DSLL, MIPS_INS_DSLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsll32 */
		Mips_DSLL32, MIPS_INS_DSLL32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsll32 */
		Mips_DSLL32, MIPS_INS_DSLL32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsllv */
		Mips_DSLLV, MIPS_INS_DSLLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsra */
		Mips_DSRA, MIPS_INS_DSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsra */
		Mips_DSRAV, MIPS_INS_DSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, 0 }, 0, 0
#endif
	},
	{
 /* dsra */
		Mips_DSRA, MIPS_INS_DSRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsra32 */
		Mips_DSRA32, MIPS_INS_DSRA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsra32 */
		Mips_DSRA32, MIPS_INS_DSRA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsrav */
		Mips_DSRAV, MIPS_INS_DSRAV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsrl */
		Mips_DSRLV, MIPS_INS_DSRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsrl */
		Mips_DSRL, MIPS_INS_DSRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsrl */
		Mips_DSRLV, MIPS_INS_DSRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsrl */
		Mips_DSRL, MIPS_INS_DSRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsrl32 */
		Mips_DSRL32, MIPS_INS_DSRL32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsrl32 */
		Mips_DSRL32, MIPS_INS_DSRL32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsrlv */
		Mips_DSRLV, MIPS_INS_DSRLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsub */
		Mips_DSUB, MIPS_INS_DSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsub */
		Mips_DADDi, MIPS_INS_DSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* dsub */
		Mips_DSUB, MIPS_INS_DSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsub */
		Mips_DADDi, MIPS_INS_DSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* dsubi */
		Mips_DADDi, MIPS_INS_DSUBI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* dsubi */
		Mips_DADDi, MIPS_INS_DSUBI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* dsubu */
		Mips_DSUBu, MIPS_INS_DSUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsubu */
		Mips_DADDiu, MIPS_INS_DSUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsubu */
		Mips_DSUBu, MIPS_INS_DSUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dsubu */
		Mips_DADDiu, MIPS_INS_DSUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dvp */
		Mips_DVP, MIPS_INS_DVP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* dvp */
		Mips_DVP_MMR6, MIPS_INS_DVP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* dvp */
		Mips_DVP, MIPS_INS_DVP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* dvp */
		Mips_DVP_MMR6, MIPS_INS_DVP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* dvpe */
		Mips_DVPE, MIPS_INS_DVPE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* dvpe */
		Mips_DVPE, MIPS_INS_DVPE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ehb */
		Mips_EHB, MIPS_INS_EHB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ehb */
		Mips_EHB_MMR6, MIPS_INS_EHB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* ehb */
		Mips_EHB_MM, MIPS_INS_EHB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ei */
		Mips_EI, MIPS_INS_EI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ei */
		Mips_EI_MMR6, MIPS_INS_EI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* ei */
		Mips_EI_MM, MIPS_INS_EI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ei */
		Mips_EI, MIPS_INS_EI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ei */
		Mips_EI_MMR6, MIPS_INS_EI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* ei */
		Mips_EI_MM, MIPS_INS_EI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* emt */
		Mips_EMT, MIPS_INS_EMT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* emt */
		Mips_EMT, MIPS_INS_EMT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* eret */
		Mips_ERET, MIPS_INS_ERET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3_32, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* eret */
		Mips_ERET_MMR6, MIPS_INS_ERET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* eret */
		Mips_ERET_MM, MIPS_INS_ERET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* eretnc */
		Mips_ERETNC, MIPS_INS_ERETNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R5, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* eretnc */
		Mips_ERETNC_MMR6, MIPS_INS_ERETNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* evp */
		Mips_EVP, MIPS_INS_EVP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* evp */
		Mips_EVP_MMR6, MIPS_INS_EVP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* evp */
		Mips_EVP, MIPS_INS_EVP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* evp */
		Mips_EVP_MMR6, MIPS_INS_EVP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* evpe */
		Mips_EVPE, MIPS_INS_EVPE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* evpe */
		Mips_EVPE, MIPS_INS_EVPE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ext */
		Mips_EXT, MIPS_INS_EXT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ext */
		Mips_EXT_MM, MIPS_INS_EXT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* ext */
		Mips_EXT_MMR6, MIPS_INS_EXT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* extp */
		Mips_EXTP_MM, MIPS_INS_EXTP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* extp */
		Mips_EXTP, MIPS_INS_EXTP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* extpdp */
		Mips_EXTPDP_MM, MIPS_INS_EXTPDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* extpdp */
		Mips_EXTPDP, MIPS_INS_EXTPDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* extpdpv */
		Mips_EXTPDPV_MM, MIPS_INS_EXTPDPV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* extpdpv */
		Mips_EXTPDPV, MIPS_INS_EXTPDPV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* extpv */
		Mips_EXTPV_MM, MIPS_INS_EXTPV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* extpv */
		Mips_EXTPV, MIPS_INS_EXTPV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* extr.w */
		Mips_EXTR_W_MM, MIPS_INS_EXTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* extr.w */
		Mips_EXTR_W, MIPS_INS_EXTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* extr_r.w */
		Mips_EXTR_R_W_MM, MIPS_INS_EXTR_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* extr_r.w */
		Mips_EXTR_R_W, MIPS_INS_EXTR_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* extr_rs.w */
		Mips_EXTR_RS_W_MM, MIPS_INS_EXTR_RS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* extr_rs.w */
		Mips_EXTR_RS_W, MIPS_INS_EXTR_RS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* extr_s.h */
		Mips_EXTR_S_H_MM, MIPS_INS_EXTR_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* extr_s.h */
		Mips_EXTR_S_H, MIPS_INS_EXTR_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* extrv.w */
		Mips_EXTRV_W_MM, MIPS_INS_EXTRV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* extrv.w */
		Mips_EXTRV_W, MIPS_INS_EXTRV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* extrv_r.w */
		Mips_EXTRV_R_W_MM, MIPS_INS_EXTRV_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* extrv_r.w */
		Mips_EXTRV_R_W, MIPS_INS_EXTRV_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* extrv_rs.w */
		Mips_EXTRV_RS_W_MM, MIPS_INS_EXTRV_RS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* extrv_rs.w */
		Mips_EXTRV_RS_W, MIPS_INS_EXTRV_RS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* extrv_s.h */
		Mips_EXTRV_S_H_MM, MIPS_INS_EXTRV_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* extrv_s.h */
		Mips_EXTRV_S_H, MIPS_INS_EXTRV_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* exts */
		Mips_EXTS, MIPS_INS_EXTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS64, MIPS_GRP_CNMIPS, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* exts */
		Mips_EXTS32, MIPS_INS_EXTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS64, MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* exts */
		Mips_EXTS, MIPS_INS_EXTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS64, MIPS_GRP_CNMIPS, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* exts */
		Mips_EXTS32, MIPS_INS_EXTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS64, MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* exts32 */
		Mips_EXTS32, MIPS_INS_EXTS32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS64, MIPS_GRP_CNMIPS, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* exts32 */
		Mips_EXTS32, MIPS_INS_EXTS32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS64, MIPS_GRP_CNMIPS, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* fadd.d */
		Mips_FADD_D, MIPS_INS_FADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fadd.w */
		Mips_FADD_W, MIPS_INS_FADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fcaf.d */
		Mips_FCAF_D, MIPS_INS_FCAF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fcaf.w */
		Mips_FCAF_W, MIPS_INS_FCAF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fceq.d */
		Mips_FCEQ_D, MIPS_INS_FCEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fceq.w */
		Mips_FCEQ_W, MIPS_INS_FCEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fclass.d */
		Mips_FCLASS_D, MIPS_INS_FCLASS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fclass.w */
		Mips_FCLASS_W, MIPS_INS_FCLASS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fcle.d */
		Mips_FCLE_D, MIPS_INS_FCLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fcle.w */
		Mips_FCLE_W, MIPS_INS_FCLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fclt.d */
		Mips_FCLT_D, MIPS_INS_FCLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fclt.w */
		Mips_FCLT_W, MIPS_INS_FCLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fcne.d */
		Mips_FCNE_D, MIPS_INS_FCNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fcne.w */
		Mips_FCNE_W, MIPS_INS_FCNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fcor.d */
		Mips_FCOR_D, MIPS_INS_FCOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fcor.w */
		Mips_FCOR_W, MIPS_INS_FCOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fcueq.d */
		Mips_FCUEQ_D, MIPS_INS_FCUEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fcueq.w */
		Mips_FCUEQ_W, MIPS_INS_FCUEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fcule.d */
		Mips_FCULE_D, MIPS_INS_FCULE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fcule.w */
		Mips_FCULE_W, MIPS_INS_FCULE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fcult.d */
		Mips_FCULT_D, MIPS_INS_FCULT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fcult.w */
		Mips_FCULT_W, MIPS_INS_FCULT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fcun.d */
		Mips_FCUN_D, MIPS_INS_FCUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fcun.w */
		Mips_FCUN_W, MIPS_INS_FCUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fcune.d */
		Mips_FCUNE_D, MIPS_INS_FCUNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fcune.w */
		Mips_FCUNE_W, MIPS_INS_FCUNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fdiv.d */
		Mips_FDIV_D, MIPS_INS_FDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fdiv.w */
		Mips_FDIV_W, MIPS_INS_FDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fexdo.h */
		Mips_FEXDO_H, MIPS_INS_FEXDO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fexdo.w */
		Mips_FEXDO_W, MIPS_INS_FEXDO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fexp2.d */
		Mips_FEXP2_D, MIPS_INS_FEXP2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fexp2.w */
		Mips_FEXP2_W, MIPS_INS_FEXP2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fexupl.d */
		Mips_FEXUPL_D, MIPS_INS_FEXUPL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fexupl.w */
		Mips_FEXUPL_W, MIPS_INS_FEXUPL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fexupr.d */
		Mips_FEXUPR_D, MIPS_INS_FEXUPR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fexupr.w */
		Mips_FEXUPR_W, MIPS_INS_FEXUPR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ffint_s.d */
		Mips_FFINT_S_D, MIPS_INS_FFINT_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ffint_s.w */
		Mips_FFINT_S_W, MIPS_INS_FFINT_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ffint_u.d */
		Mips_FFINT_U_D, MIPS_INS_FFINT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ffint_u.w */
		Mips_FFINT_U_W, MIPS_INS_FFINT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ffql.d */
		Mips_FFQL_D, MIPS_INS_FFQL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ffql.w */
		Mips_FFQL_W, MIPS_INS_FFQL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ffqr.d */
		Mips_FFQR_D, MIPS_INS_FFQR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ffqr.w */
		Mips_FFQR_W, MIPS_INS_FFQR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fill.b */
		Mips_FILL_B, MIPS_INS_FILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fill.d */
		Mips_FILL_D, MIPS_INS_FILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, MIPS_GRP_MIPS64, 0 }, 0, 0
#endif
	},
	{
 /* fill.h */
		Mips_FILL_H, MIPS_INS_FILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fill.w */
		Mips_FILL_W, MIPS_INS_FILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* flog2.d */
		Mips_FLOG2_D, MIPS_INS_FLOG2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* flog2.w */
		Mips_FLOG2_W, MIPS_INS_FLOG2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* floor.l.d */
		Mips_FLOOR_L_D64, MIPS_INS_FLOOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS3_32, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* floor.l.d */
		Mips_FLOOR_L_D_MMR6, MIPS_INS_FLOOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* floor.l.s */
		Mips_FLOOR_L_S, MIPS_INS_FLOOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* floor.l.s */
		Mips_FLOOR_L_S_MMR6, MIPS_INS_FLOOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* floor.w.d */
		Mips_FLOOR_W_D32, MIPS_INS_FLOOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* floor.w.d */
		Mips_FLOOR_W_D_MMR6, MIPS_INS_FLOOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* floor.w.d */
		Mips_FLOOR_W_MM, MIPS_INS_FLOOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* floor.w.d */
		Mips_FLOOR_W_D64, MIPS_INS_FLOOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* floor.w.s */
		Mips_FLOOR_W_S, MIPS_INS_FLOOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* floor.w.s */
		Mips_FLOOR_W_S_MMR6, MIPS_INS_FLOOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* floor.w.s */
		Mips_FLOOR_W_S_MM, MIPS_INS_FLOOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* fmadd.d */
		Mips_FMADD_D, MIPS_INS_FMADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fmadd.w */
		Mips_FMADD_W, MIPS_INS_FMADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fmax.d */
		Mips_FMAX_D, MIPS_INS_FMAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fmax.w */
		Mips_FMAX_W, MIPS_INS_FMAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fmax_a.d */
		Mips_FMAX_A_D, MIPS_INS_FMAX_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fmax_a.w */
		Mips_FMAX_A_W, MIPS_INS_FMAX_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fmin.d */
		Mips_FMIN_D, MIPS_INS_FMIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fmin.w */
		Mips_FMIN_W, MIPS_INS_FMIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fmin_a.d */
		Mips_FMIN_A_D, MIPS_INS_FMIN_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fmin_a.w */
		Mips_FMIN_A_W, MIPS_INS_FMIN_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fmsub.d */
		Mips_FMSUB_D, MIPS_INS_FMSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fmsub.w */
		Mips_FMSUB_W, MIPS_INS_FMSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fmul.d */
		Mips_FMUL_D, MIPS_INS_FMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fmul.w */
		Mips_FMUL_W, MIPS_INS_FMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fork */
		Mips_FORK, MIPS_INS_FORK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* frcp.d */
		Mips_FRCP_D, MIPS_INS_FRCP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* frcp.w */
		Mips_FRCP_W, MIPS_INS_FRCP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* frint.d */
		Mips_FRINT_D, MIPS_INS_FRINT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* frint.w */
		Mips_FRINT_W, MIPS_INS_FRINT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* frsqrt.d */
		Mips_FRSQRT_D, MIPS_INS_FRSQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* frsqrt.w */
		Mips_FRSQRT_W, MIPS_INS_FRSQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fsaf.d */
		Mips_FSAF_D, MIPS_INS_FSAF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fsaf.w */
		Mips_FSAF_W, MIPS_INS_FSAF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fseq.d */
		Mips_FSEQ_D, MIPS_INS_FSEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fseq.w */
		Mips_FSEQ_W, MIPS_INS_FSEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fsle.d */
		Mips_FSLE_D, MIPS_INS_FSLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fsle.w */
		Mips_FSLE_W, MIPS_INS_FSLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fslt.d */
		Mips_FSLT_D, MIPS_INS_FSLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fslt.w */
		Mips_FSLT_W, MIPS_INS_FSLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fsne.d */
		Mips_FSNE_D, MIPS_INS_FSNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fsne.w */
		Mips_FSNE_W, MIPS_INS_FSNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fsor.d */
		Mips_FSOR_D, MIPS_INS_FSOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fsor.w */
		Mips_FSOR_W, MIPS_INS_FSOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fsqrt.d */
		Mips_FSQRT_D, MIPS_INS_FSQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fsqrt.w */
		Mips_FSQRT_W, MIPS_INS_FSQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fsub.d */
		Mips_FSUB_D, MIPS_INS_FSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fsub.w */
		Mips_FSUB_W, MIPS_INS_FSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fsueq.d */
		Mips_FSUEQ_D, MIPS_INS_FSUEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fsueq.w */
		Mips_FSUEQ_W, MIPS_INS_FSUEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fsule.d */
		Mips_FSULE_D, MIPS_INS_FSULE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fsule.w */
		Mips_FSULE_W, MIPS_INS_FSULE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fsult.d */
		Mips_FSULT_D, MIPS_INS_FSULT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fsult.w */
		Mips_FSULT_W, MIPS_INS_FSULT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fsun.d */
		Mips_FSUN_D, MIPS_INS_FSUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fsun.w */
		Mips_FSUN_W, MIPS_INS_FSUN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fsune.d */
		Mips_FSUNE_D, MIPS_INS_FSUNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* fsune.w */
		Mips_FSUNE_W, MIPS_INS_FSUNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ftint_s.d */
		Mips_FTINT_S_D, MIPS_INS_FTINT_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ftint_s.w */
		Mips_FTINT_S_W, MIPS_INS_FTINT_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ftint_u.d */
		Mips_FTINT_U_D, MIPS_INS_FTINT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ftint_u.w */
		Mips_FTINT_U_W, MIPS_INS_FTINT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ftq.h */
		Mips_FTQ_H, MIPS_INS_FTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ftq.w */
		Mips_FTQ_W, MIPS_INS_FTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ftrunc_s.d */
		Mips_FTRUNC_S_D, MIPS_INS_FTRUNC_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ftrunc_s.w */
		Mips_FTRUNC_S_W, MIPS_INS_FTRUNC_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ftrunc_u.d */
		Mips_FTRUNC_U_D, MIPS_INS_FTRUNC_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ftrunc_u.w */
		Mips_FTRUNC_U_W, MIPS_INS_FTRUNC_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ginvi */
		Mips_GINVI, MIPS_INS_GINVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_GINV, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ginvi */
		Mips_GINVI_MMR6, MIPS_INS_GINVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_GINV, 0 }, 0, 0
#endif
	},
	{
 /* ginvt */
		Mips_GINVT, MIPS_INS_GINVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_GINV, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ginvt */
		Mips_GINVT_MMR6, MIPS_INS_GINVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_GINV, 0 }, 0, 0
#endif
	},
	{
 /* hadd_s.d */
		Mips_HADD_S_D, MIPS_INS_HADD_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* hadd_s.h */
		Mips_HADD_S_H, MIPS_INS_HADD_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* hadd_s.w */
		Mips_HADD_S_W, MIPS_INS_HADD_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* hadd_u.d */
		Mips_HADD_U_D, MIPS_INS_HADD_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* hadd_u.h */
		Mips_HADD_U_H, MIPS_INS_HADD_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* hadd_u.w */
		Mips_HADD_U_W, MIPS_INS_HADD_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* hsub_s.d */
		Mips_HSUB_S_D, MIPS_INS_HSUB_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* hsub_s.h */
		Mips_HSUB_S_H, MIPS_INS_HSUB_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* hsub_s.w */
		Mips_HSUB_S_W, MIPS_INS_HSUB_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* hsub_u.d */
		Mips_HSUB_U_D, MIPS_INS_HSUB_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* hsub_u.h */
		Mips_HSUB_U_H, MIPS_INS_HSUB_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* hsub_u.w */
		Mips_HSUB_U_W, MIPS_INS_HSUB_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* hypcall */
		Mips_HYPCALL, MIPS_INS_HYPCALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* hypcall */
		Mips_HYPCALL_MM, MIPS_INS_HYPCALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, 0 }, 0, 0
#endif
	},
	{
 /* hypcall */
		Mips_HYPCALL, MIPS_INS_HYPCALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* hypcall */
		Mips_HYPCALL_MM, MIPS_INS_HYPCALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, 0 }, 0, 0
#endif
	},
	{
 /* ilvev.b */
		Mips_ILVEV_B, MIPS_INS_ILVEV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ilvev.d */
		Mips_ILVEV_D, MIPS_INS_ILVEV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ilvev.h */
		Mips_ILVEV_H, MIPS_INS_ILVEV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ilvev.w */
		Mips_ILVEV_W, MIPS_INS_ILVEV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ilvl.b */
		Mips_ILVL_B, MIPS_INS_ILVL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ilvl.d */
		Mips_ILVL_D, MIPS_INS_ILVL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ilvl.h */
		Mips_ILVL_H, MIPS_INS_ILVL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ilvl.w */
		Mips_ILVL_W, MIPS_INS_ILVL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ilvod.b */
		Mips_ILVOD_B, MIPS_INS_ILVOD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ilvod.d */
		Mips_ILVOD_D, MIPS_INS_ILVOD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ilvod.h */
		Mips_ILVOD_H, MIPS_INS_ILVOD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ilvod.w */
		Mips_ILVOD_W, MIPS_INS_ILVOD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ilvr.b */
		Mips_ILVR_B, MIPS_INS_ILVR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ilvr.d */
		Mips_ILVR_D, MIPS_INS_ILVR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ilvr.h */
		Mips_ILVR_H, MIPS_INS_ILVR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ilvr.w */
		Mips_ILVR_W, MIPS_INS_ILVR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ins */
		Mips_INS, MIPS_INS_INS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ins */
		Mips_INS_MM, MIPS_INS_INS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* ins */
		Mips_INS_MMR6, MIPS_INS_INS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* insert.b */
		Mips_INSERT_B, MIPS_INS_INSERT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* insert.d */
		Mips_INSERT_D, MIPS_INS_INSERT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, MIPS_GRP_MIPS64, 0 }, 0, 0
#endif
	},
	{
 /* insert.h */
		Mips_INSERT_H, MIPS_INS_INSERT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* insert.w */
		Mips_INSERT_W, MIPS_INS_INSERT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* insv */
		Mips_INSV_MM, MIPS_INS_INSV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* insv */
		Mips_INSV, MIPS_INS_INSV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* insve.b */
		Mips_INSVE_B, MIPS_INS_INSVE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* insve.d */
		Mips_INSVE_D, MIPS_INS_INSVE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* insve.h */
		Mips_INSVE_H, MIPS_INS_INSVE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* insve.w */
		Mips_INSVE_W, MIPS_INS_INSVE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* j */
		Mips_JR, MIPS_INS_J,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 1
#endif
	},
	{
 /* j */
		Mips_JR_MM, MIPS_INS_J,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 1, 1
#endif
	},
	{
 /* j */
		Mips_J_MM, MIPS_INS_J,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* j */
		Mips_J, MIPS_INS_J,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 0
#endif
	},
	{
 /* jal */
		Mips_JalOneReg, MIPS_INS_JAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* jal */
		Mips_JAL_MM, MIPS_INS_JAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* jal */
		Mips_JAL, MIPS_INS_JAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* jal */
		Mips_BALC_MMR6, MIPS_INS_JAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 0
#endif
	},
	{
 /* jal */
		Mips_JalTwoReg, MIPS_INS_JAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* jalr */
		Mips_JALR16_MM, MIPS_INS_JALR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* jalr */
		Mips_JALRC16_MMR6, MIPS_INS_JALR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* jalr */
		Mips_JALR, MIPS_INS_JALR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* jalr */
		Mips_JALR, MIPS_INS_JALR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, MIPS_GRP_NOINDIRECTJUMPGUARDS, 0 }, 0, 0
#endif
	},
	{
 /* jalr */
		Mips_JALR_MM, MIPS_INS_JALR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* jalr */
		Mips_JALR64, MIPS_INS_JALR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_NOTINMIPS16MODE, MIPS_GRP_PTR64BIT, 0 }, 0, 0
#endif
	},
	{
 /* jalr.hb */
		Mips_JALR_HB, MIPS_INS_JALR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 1
#endif
	},
	{
 /* jalr.hb */
		Mips_JALR_HB64, MIPS_INS_JALR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 1
#endif
	},
	{
 /* jalr.hb */
		Mips_JALR_HB, MIPS_INS_JALR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32, 0 }, 0, 1
#endif
	},
	{
 /* jalr.hb */
		Mips_JALR_HB64, MIPS_INS_JALR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 1
#endif
	},
	{
 /* jalrc */
		Mips_JumpLinkReg16, MIPS_INS_JALRC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* jalrc */
		Mips_JIALC, MIPS_INS_JALRC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP32BIT, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 1
#endif
	},
	{
 /* jalrc */
		Mips_JALRC_MMR6, MIPS_INS_JALRC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* jalrc */
		Mips_JIALC64, MIPS_INS_JALRC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, 0 }, 1, 1
#endif
	},
	{
 /* jalrc */
		Mips_JALRC_MMR6, MIPS_INS_JALRC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* jalrc.hb */
		Mips_JALRC_HB_MMR6, MIPS_INS_JALRC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 1
#endif
	},
	{
 /* jalrc.hb */
		Mips_JALRC_HB_MMR6, MIPS_INS_JALRC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 1
#endif
	},
	{
 /* jalrs */
		Mips_JALRS_MM, MIPS_INS_JALRS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* jalrs16 */
		Mips_JALRS16_MM, MIPS_INS_JALRS16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* jals */
		Mips_JALS_MM, MIPS_INS_JALS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* jalx */
		Mips_JALX, MIPS_INS_JALX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* jalx */
		Mips_JALX_MM, MIPS_INS_JALX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* jialc */
		Mips_JIALC, MIPS_INS_JIALC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 1
#endif
	},
	{
 /* jialc */
		Mips_JIALC_MMR6, MIPS_INS_JIALC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* jialc */
		Mips_JIALC64, MIPS_INS_JIALC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS64R6, 0 }, 1, 1
#endif
	},
	{
 /* jic */
		Mips_JIC, MIPS_INS_JIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 1
#endif
	},
	{
 /* jic */
		Mips_JIC_MMR6, MIPS_INS_JIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* jic */
		Mips_JIC64, MIPS_INS_JIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS64R6, 0 }, 1, 1
#endif
	},
	{
 /* jr */
		Mips_JrRa16, MIPS_INS_JR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 1, 1
#endif
	},
	{
 /* jr */
		Mips_JR, MIPS_INS_JR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 1
#endif
	},
	{
 /* jr */
		Mips_JALR, MIPS_INS_JR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP32BIT, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* jr */
		Mips_JR_MM, MIPS_INS_JR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 1, 1
#endif
	},
	{
 /* jr */
		Mips_JR64, MIPS_INS_JR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_NOTINMIPS16MODE, MIPS_GRP_PTR64BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 1
#endif
	},
	{
 /* jr */
		Mips_JALR64, MIPS_INS_JR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* jr.hb */
		Mips_JR_HB, MIPS_INS_JR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 1, 1
#endif
	},
	{
 /* jr.hb */
		Mips_JR_HB_R6, MIPS_INS_JR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 1
#endif
	},
	{
 /* jr.hb */
		Mips_JR_HB64, MIPS_INS_JR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 1, 1
#endif
	},
	{
 /* jr.hb */
		Mips_JR_HB64_R6, MIPS_INS_JR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 1, 1
#endif
	},
	{
 /* jr16 */
		Mips_JR16_MM, MIPS_INS_JR16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 1, 1
#endif
	},
	{
 /* jraddiusp */
		Mips_JRADDIUSP, MIPS_INS_JRADDIUSP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 1, 1
#endif
	},
	{
 /* jrc */
		Mips_JrcRa16, MIPS_INS_JRC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 1, 1
#endif
	},
	{
 /* jrc */
		Mips_JrcRx16, MIPS_INS_JRC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 1, 1
#endif
	},
	{
 /* jrc */
		Mips_JIC, MIPS_INS_JRC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP32BIT, MIPS_GRP_MIPS32R6, 0 }, 1, 1
#endif
	},
	{
 /* jrc */
		Mips_JRC16_MM, MIPS_INS_JRC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 1, 1
#endif
	},
	{
 /* jrc */
		Mips_JIC64, MIPS_INS_JRC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, 0 }, 1, 1
#endif
	},
	{
 /* jrc16 */
		Mips_JRC16_MMR6, MIPS_INS_JRC16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 1
#endif
	},
	{
 /* jrcaddiusp */
		Mips_JRCADDIUSP_MMR6, MIPS_INS_JRCADDIUSP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 1, 1
#endif
	},
	{
 /* l.d */
		Mips_LDC1, MIPS_INS_L,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* l.d */
		Mips_LDC164, MIPS_INS_L,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* l.s */
		Mips_LWC1, MIPS_INS_L,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* la */
		Mips_LoadAddrImm32, MIPS_INS_LA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* la */
		Mips_LoadAddrReg32, MIPS_INS_LA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* lapc */
		Mips_ADDIUPC, MIPS_INS_LAPC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* lapc */
		Mips_ADDIUPC_MMR6, MIPS_INS_LAPC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* lb */
		Mips_LB, MIPS_INS_LB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lb */
		Mips_LB_MMR6, MIPS_INS_LB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* lb */
		Mips_LB_MM, MIPS_INS_LB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lbe */
		Mips_LBE, MIPS_INS_LBE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_EVA, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lbe */
		Mips_LBE_MM, MIPS_INS_LBE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_EVA, 0 }, 0, 0
#endif
	},
	{
 /* lbu */
		Mips_LBu, MIPS_INS_LBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lbu */
		Mips_LBU_MMR6, MIPS_INS_LBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* lbu */
		Mips_LBu_MM, MIPS_INS_LBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lbu16 */
		Mips_LBU16_MM, MIPS_INS_LBU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lbue */
		Mips_LBuE, MIPS_INS_LBUE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_EVA, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lbue */
		Mips_LBuE_MM, MIPS_INS_LBUE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_EVA, 0 }, 0, 0
#endif
	},
	{
 /* lbux */
		Mips_LBUX_MM, MIPS_INS_LBUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* lbux */
		Mips_LBUX, MIPS_INS_LBUX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* ld */
		Mips_LDMacro, MIPS_INS_LD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS3, 0 }, 0, 0
#endif
	},
	{
 /* ld */
		Mips_LD, MIPS_INS_LD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ld.b */
		Mips_LD_B, MIPS_INS_LD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ld.d */
		Mips_LD_D, MIPS_INS_LD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ld.h */
		Mips_LD_H, MIPS_INS_LD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ld.w */
		Mips_LD_W, MIPS_INS_LD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ldc1 */
		Mips_LDC1, MIPS_INS_LDC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ldc1 */
		Mips_LDC1_MM, MIPS_INS_LDC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* ldc1 */
		Mips_LDC164, MIPS_INS_LDC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ldc1 */
		Mips_LDC1_D64_MMR6, MIPS_INS_LDC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* ldc2 */
		Mips_LDC2_R6, MIPS_INS_LDC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ldc2 */
		Mips_LDC2_MMR6, MIPS_INS_LDC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* ldc2 */
		Mips_LDC2, MIPS_INS_LDC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ldc3 */
		Mips_LDC3, MIPS_INS_LDC3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTCNMIPS, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ldi.b */
		Mips_LDI_B, MIPS_INS_LDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ldi.d */
		Mips_LDI_D, MIPS_INS_LDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ldi.h */
		Mips_LDI_H, MIPS_INS_LDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ldi.w */
		Mips_LDI_W, MIPS_INS_LDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* ldl */
		Mips_LDL, MIPS_INS_LDL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* ldpc */
		Mips_LDPC, MIPS_INS_LDPC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* ldr */
		Mips_LDR, MIPS_INS_LDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* ldxc1 */
		Mips_LDXC1, MIPS_INS_LDXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ldxc1 */
		Mips_LDXC164, MIPS_INS_LDXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* lh */
		Mips_LH, MIPS_INS_LH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lh */
		Mips_LH_MM, MIPS_INS_LH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lhe */
		Mips_LHE, MIPS_INS_LHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_EVA, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lhe */
		Mips_LHE_MM, MIPS_INS_LHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_EVA, 0 }, 0, 0
#endif
	},
	{
 /* lhu */
		Mips_LHu, MIPS_INS_LHU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lhu */
		Mips_LHu_MM, MIPS_INS_LHU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lhu16 */
		Mips_LHU16_MM, MIPS_INS_LHU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lhue */
		Mips_LHuE, MIPS_INS_LHUE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_EVA, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lhue */
		Mips_LHuE_MM, MIPS_INS_LHUE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_EVA, 0 }, 0, 0
#endif
	},
	{
 /* lhx */
		Mips_LHX_MM, MIPS_INS_LHX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* lhx */
		Mips_LHX, MIPS_INS_LHX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* li */
		Mips_LiRxImmX16, MIPS_INS_LI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* li */
		Mips_LoadImm32, MIPS_INS_LI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* li */
		Mips_LiRxImm16, MIPS_INS_LI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* li.d */
		Mips_LoadImmDoubleGPR, MIPS_INS_LI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* li.d */
		Mips_LoadImmDoubleFGR_32, MIPS_INS_LI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* li.d */
		Mips_LoadImmDoubleFGR, MIPS_INS_LI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* li.s */
		Mips_LoadImmSingleGPR, MIPS_INS_LI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* li.s */
		Mips_LoadImmSingleFGR, MIPS_INS_LI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* li16 */
		Mips_LI16_MM, MIPS_INS_LI16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* li16 */
		Mips_LI16_MMR6, MIPS_INS_LI16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* ll */
		Mips_LL64_R6, MIPS_INS_LL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_PTR64BIT, MIPS_GRP_MIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ll */
		Mips_LL_R6, MIPS_INS_LL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_PTR32BIT, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ll */
		Mips_LL_MMR6, MIPS_INS_LL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* ll */
		Mips_LL, MIPS_INS_LL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_PTR32BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ll */
		Mips_LL64, MIPS_INS_LL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_PTR64BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ll */
		Mips_LL_MM, MIPS_INS_LL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* lld */
		Mips_LLD, MIPS_INS_LLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lld */
		Mips_LLD_R6, MIPS_INS_LLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lle */
		Mips_LLE, MIPS_INS_LLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_EVA, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lle */
		Mips_LLE_MM, MIPS_INS_LLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_EVA, 0 }, 0, 0
#endif
	},
	{
 /* lsa */
		Mips_LSA, MIPS_INS_LSA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* lsa */
		Mips_LSA_MMR6, MIPS_INS_LSA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* lsa */
		Mips_LSA_R6, MIPS_INS_LSA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* lui */
		Mips_LUI_MMR6, MIPS_INS_LUI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* lui */
		Mips_LUi, MIPS_INS_LUI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lui */
		Mips_LUi_MM, MIPS_INS_LUI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* luxc1 */
		Mips_LUXC1, MIPS_INS_LUXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS5_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* luxc1 */
		Mips_LUXC164, MIPS_INS_LUXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS5_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* luxc1 */
		Mips_LUXC1_MM, MIPS_INS_LUXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* lw */
		Mips_LwRxPcTcpX16, MIPS_INS_LW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* lw */
		Mips_LWSP_MM, MIPS_INS_LW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lw */
		Mips_LW, MIPS_INS_LW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lw */
		Mips_LWDSP, MIPS_INS_LW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_NOTINMIPS16MODE, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* lw */
		Mips_LWDSP_MM, MIPS_INS_LW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* lw */
		Mips_LW_MMR6, MIPS_INS_LW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* lw */
		Mips_LW_MM, MIPS_INS_LW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lw */
		Mips_LWGP_MM, MIPS_INS_LW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lw */
		Mips_LwRxSpImmX16, MIPS_INS_LW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* lw */
		Mips_LwRxPcTcp16, MIPS_INS_LW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* lw16 */
		Mips_LW16_MM, MIPS_INS_LW16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lwc1 */
		Mips_LWC1, MIPS_INS_LWC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lwc1 */
		Mips_LWC1_MM, MIPS_INS_LWC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* lwc2 */
		Mips_LWC2_R6, MIPS_INS_LWC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lwc2 */
		Mips_LWC2_MMR6, MIPS_INS_LWC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* lwc2 */
		Mips_LWC2, MIPS_INS_LWC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lwc3 */
		Mips_LWC3, MIPS_INS_LWC3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTCNMIPS, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lwe */
		Mips_LWE, MIPS_INS_LWE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_EVA, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lwe */
		Mips_LWE_MM, MIPS_INS_LWE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_EVA, 0 }, 0, 0
#endif
	},
	{
 /* lwl */
		Mips_LWL, MIPS_INS_LWL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lwl */
		Mips_LWL_MM, MIPS_INS_LWL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* lwle */
		Mips_LWLE, MIPS_INS_LWLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_EVA, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lwle */
		Mips_LWLE_MM, MIPS_INS_LWLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_EVA, 0 }, 0, 0
#endif
	},
	{
 /* lwm */
		Mips_LWM_MM, MIPS_INS_LWM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lwm16 */
		Mips_LWM16_MM, MIPS_INS_LWM16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* lwm16 */
		Mips_LWM16_MMR6, MIPS_INS_LWM16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* lwm32 */
		Mips_LWM32_MM, MIPS_INS_LWM32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lwp */
		Mips_LWP_MM, MIPS_INS_LWP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lwpc */
		Mips_LWPC, MIPS_INS_LWPC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* lwpc */
		Mips_LWPC_MMR6, MIPS_INS_LWPC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* lwr */
		Mips_LWR, MIPS_INS_LWR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lwr */
		Mips_LWR_MM, MIPS_INS_LWR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* lwre */
		Mips_LWRE, MIPS_INS_LWRE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_EVA, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lwre */
		Mips_LWRE_MM, MIPS_INS_LWRE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_EVA, 0 }, 0, 0
#endif
	},
	{
 /* lwu */
		Mips_LWU_MM, MIPS_INS_LWU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* lwu */
		Mips_LWu, MIPS_INS_LWU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* lwupc */
		Mips_LWUPC, MIPS_INS_LWUPC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* lwx */
		Mips_LWX_MM, MIPS_INS_LWX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* lwx */
		Mips_LWX, MIPS_INS_LWX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* lwxc1 */
		Mips_LWXC1, MIPS_INS_LWXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* lwxc1 */
		Mips_LWXC1_MM, MIPS_INS_LWXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* lwxs */
		Mips_LWXS_MM, MIPS_INS_LWXS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* madd */
		Mips_MADD, MIPS_INS_MADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* madd */
		Mips_MADD_MM, MIPS_INS_MADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* madd */
		Mips_MADD_DSP_MM, MIPS_INS_MADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* madd */
		Mips_MADD_DSP, MIPS_INS_MADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* madd.d */
		Mips_MADD_D32, MIPS_INS_MADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* madd.d */
		Mips_MADD_D32_MM, MIPS_INS_MADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_MADD4, 0 }, 0, 0
#endif
	},
	{
 /* madd.d */
		Mips_MADD_D64, MIPS_INS_MADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, MIPS_GRP_MADD4, 0 }, 0, 0
#endif
	},
	{
 /* madd.s */
		Mips_MADD_S, MIPS_INS_MADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, MIPS_GRP_MADD4, 0 }, 0, 0
#endif
	},
	{
 /* madd.s */
		Mips_MADD_S_MM, MIPS_INS_MADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_MADD4, 0 }, 0, 0
#endif
	},
	{
 /* madd_q.h */
		Mips_MADD_Q_H, MIPS_INS_MADD_Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* madd_q.w */
		Mips_MADD_Q_W, MIPS_INS_MADD_Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* maddf.d */
		Mips_MADDF_D, MIPS_INS_MADDF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* maddf.d */
		Mips_MADDF_D_MMR6, MIPS_INS_MADDF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* maddf.s */
		Mips_MADDF_S, MIPS_INS_MADDF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* maddf.s */
		Mips_MADDF_S_MMR6, MIPS_INS_MADDF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* maddr_q.h */
		Mips_MADDR_Q_H, MIPS_INS_MADDR_Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* maddr_q.w */
		Mips_MADDR_Q_W, MIPS_INS_MADDR_Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* maddu */
		Mips_MADDU, MIPS_INS_MADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* maddu */
		Mips_MADDU_MM, MIPS_INS_MADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* maddu */
		Mips_MADDU_DSP_MM, MIPS_INS_MADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* maddu */
		Mips_MADDU_DSP, MIPS_INS_MADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* maddv.b */
		Mips_MADDV_B, MIPS_INS_MADDV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* maddv.d */
		Mips_MADDV_D, MIPS_INS_MADDV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* maddv.h */
		Mips_MADDV_H, MIPS_INS_MADDV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* maddv.w */
		Mips_MADDV_W, MIPS_INS_MADDV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* maq_s.w.phl */
		Mips_MAQ_S_W_PHL_MM, MIPS_INS_MAQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* maq_s.w.phl */
		Mips_MAQ_S_W_PHL, MIPS_INS_MAQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* maq_s.w.phr */
		Mips_MAQ_S_W_PHR_MM, MIPS_INS_MAQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* maq_s.w.phr */
		Mips_MAQ_S_W_PHR, MIPS_INS_MAQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* maq_sa.w.phl */
		Mips_MAQ_SA_W_PHL_MM, MIPS_INS_MAQ_SA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* maq_sa.w.phl */
		Mips_MAQ_SA_W_PHL, MIPS_INS_MAQ_SA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* maq_sa.w.phr */
		Mips_MAQ_SA_W_PHR_MM, MIPS_INS_MAQ_SA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* maq_sa.w.phr */
		Mips_MAQ_SA_W_PHR, MIPS_INS_MAQ_SA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* max.d */
		Mips_MAX_D, MIPS_INS_MAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* max.d */
		Mips_MAX_D_MMR6, MIPS_INS_MAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* max.s */
		Mips_MAX_S, MIPS_INS_MAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* max.s */
		Mips_MAX_S_MMR6, MIPS_INS_MAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* max_a.b */
		Mips_MAX_A_B, MIPS_INS_MAX_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* max_a.d */
		Mips_MAX_A_D, MIPS_INS_MAX_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* max_a.h */
		Mips_MAX_A_H, MIPS_INS_MAX_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* max_a.w */
		Mips_MAX_A_W, MIPS_INS_MAX_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* max_s.b */
		Mips_MAX_S_B, MIPS_INS_MAX_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* max_s.d */
		Mips_MAX_S_D, MIPS_INS_MAX_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* max_s.h */
		Mips_MAX_S_H, MIPS_INS_MAX_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* max_s.w */
		Mips_MAX_S_W, MIPS_INS_MAX_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* max_u.b */
		Mips_MAX_U_B, MIPS_INS_MAX_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* max_u.d */
		Mips_MAX_U_D, MIPS_INS_MAX_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* max_u.h */
		Mips_MAX_U_H, MIPS_INS_MAX_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* max_u.w */
		Mips_MAX_U_W, MIPS_INS_MAX_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* maxa.d */
		Mips_MAXA_D, MIPS_INS_MAXA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* maxa.d */
		Mips_MAXA_D_MMR6, MIPS_INS_MAXA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* maxa.s */
		Mips_MAXA_S, MIPS_INS_MAXA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* maxa.s */
		Mips_MAXA_S_MMR6, MIPS_INS_MAXA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* maxi_s.b */
		Mips_MAXI_S_B, MIPS_INS_MAXI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* maxi_s.d */
		Mips_MAXI_S_D, MIPS_INS_MAXI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* maxi_s.h */
		Mips_MAXI_S_H, MIPS_INS_MAXI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* maxi_s.w */
		Mips_MAXI_S_W, MIPS_INS_MAXI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* maxi_u.b */
		Mips_MAXI_U_B, MIPS_INS_MAXI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* maxi_u.d */
		Mips_MAXI_U_D, MIPS_INS_MAXI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* maxi_u.h */
		Mips_MAXI_U_H, MIPS_INS_MAXI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* maxi_u.w */
		Mips_MAXI_U_W, MIPS_INS_MAXI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* mfc0 */
		Mips_MFC0, MIPS_INS_MFC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mfc0 */
		Mips_MFC0_MMR6, MIPS_INS_MFC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mfc0 */
		Mips_MFC0, MIPS_INS_MFC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mfc0 */
		Mips_MFC0_MMR6, MIPS_INS_MFC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mfc1 */
		Mips_MFC1, MIPS_INS_MFC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mfc1 */
		Mips_MFC1_MMR6, MIPS_INS_MFC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* mfc1 */
		Mips_MFC1_MM, MIPS_INS_MFC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* mfc1 */
		Mips_MFC1_D64, MIPS_INS_MFC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mfc2 */
		Mips_MFC2_MMR6, MIPS_INS_MFC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mfc2 */
		Mips_MFC2, MIPS_INS_MFC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mfc2 */
		Mips_MFC2, MIPS_INS_MFC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mfgc0 */
		Mips_MFGC0, MIPS_INS_MFGC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mfgc0 */
		Mips_MFGC0_MM, MIPS_INS_MFGC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, 0 }, 0, 0
#endif
	},
	{
 /* mfgc0 */
		Mips_MFGC0, MIPS_INS_MFGC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mfgc0 */
		Mips_MFGC0_MM, MIPS_INS_MFGC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, 0 }, 0, 0
#endif
	},
	{
 /* mfhc0 */
		Mips_MFHC0_MMR6, MIPS_INS_MFHC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mfhc0 */
		Mips_MFHC0_MMR6, MIPS_INS_MFHC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mfhc1 */
		Mips_MFHC1_D32, MIPS_INS_MFHC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mfhc1 */
		Mips_MFHC1_D32_MM, MIPS_INS_MFHC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* mfhc1 */
		Mips_MFHC1_D64, MIPS_INS_MFHC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mfhc1 */
		Mips_MFHC1_D64_MM, MIPS_INS_MFHC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* mfhc2 */
		Mips_MFHC2_MMR6, MIPS_INS_MFHC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mfhgc0 */
		Mips_MFHGC0, MIPS_INS_MFHGC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mfhgc0 */
		Mips_MFHGC0_MM, MIPS_INS_MFHGC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, 0 }, 0, 0
#endif
	},
	{
 /* mfhgc0 */
		Mips_MFHGC0, MIPS_INS_MFHGC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mfhgc0 */
		Mips_MFHGC0_MM, MIPS_INS_MFHGC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, 0 }, 0, 0
#endif
	},
	{
 /* mfhi */
		Mips_Mfhi16, MIPS_INS_MFHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* mfhi */
		Mips_MFHI, MIPS_INS_MFHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mfhi */
		Mips_MFHI_MM, MIPS_INS_MFHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mfhi */
		Mips_MFHI_DSP_MM, MIPS_INS_MFHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* mfhi */
		Mips_MFHI_DSP, MIPS_INS_MFHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* mfhi16 */
		Mips_MFHI16_MM, MIPS_INS_MFHI16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mflo */
		Mips_Mflo16, MIPS_INS_MFLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* mflo */
		Mips_MFLO, MIPS_INS_MFLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mflo */
		Mips_MFLO_MM, MIPS_INS_MFLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mflo */
		Mips_MFLO_DSP_MM, MIPS_INS_MFLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* mflo */
		Mips_MFLO_DSP, MIPS_INS_MFLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* mflo16 */
		Mips_MFLO16_MM, MIPS_INS_MFLO16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mftacx */
		Mips_MFTACX, MIPS_INS_MFTACX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mftacx */
		Mips_MFTACX, MIPS_INS_MFTACX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, 0 }, 0, 0
#endif
	},
	{
 /* mftc0 */
		Mips_MFTC0, MIPS_INS_MFTC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mftc0 */
		Mips_MFTC0, MIPS_INS_MFTC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, 0 }, 0, 0
#endif
	},
	{
 /* mftc1 */
		Mips_MFTC1, MIPS_INS_MFTC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, 0 }, 0, 0
#endif
	},
	{
 /* mftdsp */
		Mips_MFTDSP, MIPS_INS_MFTDSP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, 0 }, 0, 0
#endif
	},
	{
 /* mftgpr */
		Mips_MFTGPR, MIPS_INS_MFTGPR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, 0 }, 0, 0
#endif
	},
	{
 /* mfthc1 */
		Mips_MFTHC1, MIPS_INS_MFTHC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, 0 }, 0, 0
#endif
	},
	{
 /* mfthi */
		Mips_MFTHI, MIPS_INS_MFTHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mfthi */
		Mips_MFTHI, MIPS_INS_MFTHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, 0 }, 0, 0
#endif
	},
	{
 /* mftlo */
		Mips_MFTLO, MIPS_INS_MFTLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mftlo */
		Mips_MFTLO, MIPS_INS_MFTLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, 0 }, 0, 0
#endif
	},
	{
 /* mftr */
		Mips_MFTR, MIPS_INS_MFTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* min.d */
		Mips_MIN_D, MIPS_INS_MIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* min.d */
		Mips_MIN_D_MMR6, MIPS_INS_MIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* min.s */
		Mips_MIN_S, MIPS_INS_MIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* min.s */
		Mips_MIN_S_MMR6, MIPS_INS_MIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* min_a.b */
		Mips_MIN_A_B, MIPS_INS_MIN_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* min_a.d */
		Mips_MIN_A_D, MIPS_INS_MIN_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* min_a.h */
		Mips_MIN_A_H, MIPS_INS_MIN_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* min_a.w */
		Mips_MIN_A_W, MIPS_INS_MIN_A,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* min_s.b */
		Mips_MIN_S_B, MIPS_INS_MIN_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* min_s.d */
		Mips_MIN_S_D, MIPS_INS_MIN_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* min_s.h */
		Mips_MIN_S_H, MIPS_INS_MIN_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* min_s.w */
		Mips_MIN_S_W, MIPS_INS_MIN_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* min_u.b */
		Mips_MIN_U_B, MIPS_INS_MIN_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* min_u.d */
		Mips_MIN_U_D, MIPS_INS_MIN_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* min_u.h */
		Mips_MIN_U_H, MIPS_INS_MIN_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* min_u.w */
		Mips_MIN_U_W, MIPS_INS_MIN_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* mina.d */
		Mips_MINA_D, MIPS_INS_MINA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mina.d */
		Mips_MINA_D_MMR6, MIPS_INS_MINA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* mina.s */
		Mips_MINA_S, MIPS_INS_MINA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mina.s */
		Mips_MINA_S_MMR6, MIPS_INS_MINA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* mini_s.b */
		Mips_MINI_S_B, MIPS_INS_MINI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* mini_s.d */
		Mips_MINI_S_D, MIPS_INS_MINI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* mini_s.h */
		Mips_MINI_S_H, MIPS_INS_MINI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* mini_s.w */
		Mips_MINI_S_W, MIPS_INS_MINI_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* mini_u.b */
		Mips_MINI_U_B, MIPS_INS_MINI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* mini_u.d */
		Mips_MINI_U_D, MIPS_INS_MINI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* mini_u.h */
		Mips_MINI_U_H, MIPS_INS_MINI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* mini_u.w */
		Mips_MINI_U_W, MIPS_INS_MINI_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* mod */
		Mips_MOD, MIPS_INS_MOD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mod */
		Mips_MOD_MMR6, MIPS_INS_MOD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mod_s.b */
		Mips_MOD_S_B, MIPS_INS_MOD_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* mod_s.d */
		Mips_MOD_S_D, MIPS_INS_MOD_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* mod_s.h */
		Mips_MOD_S_H, MIPS_INS_MOD_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* mod_s.w */
		Mips_MOD_S_W, MIPS_INS_MOD_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* mod_u.b */
		Mips_MOD_U_B, MIPS_INS_MOD_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* mod_u.d */
		Mips_MOD_U_D, MIPS_INS_MOD_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* mod_u.h */
		Mips_MOD_U_H, MIPS_INS_MOD_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* mod_u.w */
		Mips_MOD_U_W, MIPS_INS_MOD_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* modsub */
		Mips_MODSUB_MM, MIPS_INS_MODSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* modsub */
		Mips_MODSUB, MIPS_INS_MODSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* modu */
		Mips_MODU, MIPS_INS_MODU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* modu */
		Mips_MODU_MMR6, MIPS_INS_MODU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mov.d */
		Mips_FMOV_D32, MIPS_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mov.d */
		Mips_FMOV_D32_MM, MIPS_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* mov.d */
		Mips_FMOV_D64, MIPS_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mov.d */
		Mips_FMOV_D64_MM, MIPS_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* mov.d */
		Mips_FMOV_D_MMR6, MIPS_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* mov.s */
		Mips_FMOV_S, MIPS_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mov.s */
		Mips_FMOV_S_MMR6, MIPS_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* mov.s */
		Mips_FMOV_S_MM, MIPS_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* move */
		Mips_MoveR3216, MIPS_INS_MOVE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* move */
		Mips_Move32R16, MIPS_INS_MOVE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* move */
		Mips_OR, MIPS_INS_MOVE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP32BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* move */
		Mips_ADDu, MIPS_INS_MOVE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP32BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* move */
		Mips_MOVE16_MM, MIPS_INS_MOVE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* move */
		Mips_OR64, MIPS_INS_MOVE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP64BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* move */
		Mips_DADDu, MIPS_INS_MOVE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP64BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* move.v */
		Mips_MOVE_V, MIPS_INS_MOVE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* move16 */
		Mips_MOVE16_MMR6, MIPS_INS_MOVE16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* movep */
		Mips_MOVEP_MM, MIPS_INS_MOVEP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* movep */
		Mips_MOVEP_MMR6, MIPS_INS_MOVEP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* movf */
		Mips_MOVF_I, MIPS_INS_MOVF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* movf */
		Mips_MOVF_I_MM, MIPS_INS_MOVF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* movf.d */
		Mips_MOVF_D32, MIPS_INS_MOVF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* movf.d */
		Mips_MOVF_D32_MM, MIPS_INS_MOVF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* movf.d */
		Mips_MOVF_D64, MIPS_INS_MOVF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* movf.s */
		Mips_MOVF_S, MIPS_INS_MOVF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* movf.s */
		Mips_MOVF_S_MM, MIPS_INS_MOVF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* movn */
		Mips_MOVN_I_I, MIPS_INS_MOVN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* movn */
		Mips_MOVN_I_MM, MIPS_INS_MOVN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* movn.d */
		Mips_MOVN_I_D32, MIPS_INS_MOVN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* movn.d */
		Mips_MOVN_I_D32_MM, MIPS_INS_MOVN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* movn.d */
		Mips_MOVN_I_D64, MIPS_INS_MOVN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* movn.s */
		Mips_MOVN_I_S, MIPS_INS_MOVN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* movn.s */
		Mips_MOVN_I_S_MM, MIPS_INS_MOVN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* movt */
		Mips_MOVT_I, MIPS_INS_MOVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* movt */
		Mips_MOVT_I_MM, MIPS_INS_MOVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* movt.d */
		Mips_MOVT_D32, MIPS_INS_MOVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* movt.d */
		Mips_MOVT_D32_MM, MIPS_INS_MOVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* movt.d */
		Mips_MOVT_D64, MIPS_INS_MOVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* movt.s */
		Mips_MOVT_S, MIPS_INS_MOVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* movt.s */
		Mips_MOVT_S_MM, MIPS_INS_MOVT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* movz */
		Mips_MOVZ_I_I, MIPS_INS_MOVZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* movz */
		Mips_MOVZ_I_MM, MIPS_INS_MOVZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* movz.d */
		Mips_MOVZ_I_D32, MIPS_INS_MOVZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* movz.d */
		Mips_MOVZ_I_D32_MM, MIPS_INS_MOVZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* movz.d */
		Mips_MOVZ_I_D64, MIPS_INS_MOVZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* movz.s */
		Mips_MOVZ_I_S, MIPS_INS_MOVZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* movz.s */
		Mips_MOVZ_I_S_MM, MIPS_INS_MOVZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* msub */
		Mips_MSUB, MIPS_INS_MSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* msub */
		Mips_MSUB_MM, MIPS_INS_MSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* msub */
		Mips_MSUB_DSP_MM, MIPS_INS_MSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* msub */
		Mips_MSUB_DSP, MIPS_INS_MSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* msub.d */
		Mips_MSUB_D32, MIPS_INS_MSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, MIPS_GRP_MADD4, 0 }, 0, 0
#endif
	},
	{
 /* msub.d */
		Mips_MSUB_D32_MM, MIPS_INS_MSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_MADD4, 0 }, 0, 0
#endif
	},
	{
 /* msub.d */
		Mips_MSUB_D64, MIPS_INS_MSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, MIPS_GRP_MADD4, 0 }, 0, 0
#endif
	},
	{
 /* msub.s */
		Mips_MSUB_S, MIPS_INS_MSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, MIPS_GRP_MADD4, 0 }, 0, 0
#endif
	},
	{
 /* msub.s */
		Mips_MSUB_S_MM, MIPS_INS_MSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_MADD4, 0 }, 0, 0
#endif
	},
	{
 /* msub_q.h */
		Mips_MSUB_Q_H, MIPS_INS_MSUB_Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* msub_q.w */
		Mips_MSUB_Q_W, MIPS_INS_MSUB_Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* msubf.d */
		Mips_MSUBF_D, MIPS_INS_MSUBF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* msubf.d */
		Mips_MSUBF_D_MMR6, MIPS_INS_MSUBF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* msubf.s */
		Mips_MSUBF_S, MIPS_INS_MSUBF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* msubf.s */
		Mips_MSUBF_S_MMR6, MIPS_INS_MSUBF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* msubr_q.h */
		Mips_MSUBR_Q_H, MIPS_INS_MSUBR_Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* msubr_q.w */
		Mips_MSUBR_Q_W, MIPS_INS_MSUBR_Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* msubu */
		Mips_MSUBU, MIPS_INS_MSUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* msubu */
		Mips_MSUBU_MM, MIPS_INS_MSUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* msubu */
		Mips_MSUBU_DSP_MM, MIPS_INS_MSUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* msubu */
		Mips_MSUBU_DSP, MIPS_INS_MSUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* msubv.b */
		Mips_MSUBV_B, MIPS_INS_MSUBV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* msubv.d */
		Mips_MSUBV_D, MIPS_INS_MSUBV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* msubv.h */
		Mips_MSUBV_H, MIPS_INS_MSUBV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* msubv.w */
		Mips_MSUBV_W, MIPS_INS_MSUBV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* mtc0 */
		Mips_MTC0, MIPS_INS_MTC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mtc0 */
		Mips_MTC0_MMR6, MIPS_INS_MTC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mtc0 */
		Mips_MTC0, MIPS_INS_MTC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mtc0 */
		Mips_MTC0_MMR6, MIPS_INS_MTC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mtc1 */
		Mips_MTC1, MIPS_INS_MTC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mtc1 */
		Mips_MTC1_MMR6, MIPS_INS_MTC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* mtc1 */
		Mips_MTC1_MM, MIPS_INS_MTC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* mtc1 */
		Mips_MTC1_D64, MIPS_INS_MTC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mtc1 */
		Mips_MTC1_D64_MM, MIPS_INS_MTC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* mtc2 */
		Mips_MTC2_MMR6, MIPS_INS_MTC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mtc2 */
		Mips_MTC2, MIPS_INS_MTC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mtc2 */
		Mips_MTC2, MIPS_INS_MTC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mtgc0 */
		Mips_MTGC0, MIPS_INS_MTGC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mtgc0 */
		Mips_MTGC0_MM, MIPS_INS_MTGC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, 0 }, 0, 0
#endif
	},
	{
 /* mtgc0 */
		Mips_MTGC0, MIPS_INS_MTGC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mtgc0 */
		Mips_MTGC0_MM, MIPS_INS_MTGC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, 0 }, 0, 0
#endif
	},
	{
 /* mthc0 */
		Mips_MTHC0_MMR6, MIPS_INS_MTHC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mthc0 */
		Mips_MTHC0_MMR6, MIPS_INS_MTHC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mthc1 */
		Mips_MTHC1_D32, MIPS_INS_MTHC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mthc1 */
		Mips_MTHC1_D32_MM, MIPS_INS_MTHC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* mthc1 */
		Mips_MTHC1_D64, MIPS_INS_MTHC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mthc1 */
		Mips_MTHC1_D64_MM, MIPS_INS_MTHC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* mthc2 */
		Mips_MTHC2_MMR6, MIPS_INS_MTHC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mthgc0 */
		Mips_MTHGC0, MIPS_INS_MTHGC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mthgc0 */
		Mips_MTHGC0_MM, MIPS_INS_MTHGC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, 0 }, 0, 0
#endif
	},
	{
 /* mthgc0 */
		Mips_MTHGC0, MIPS_INS_MTHGC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mthgc0 */
		Mips_MTHGC0_MM, MIPS_INS_MTHGC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, 0 }, 0, 0
#endif
	},
	{
 /* mthi */
		Mips_MTHI, MIPS_INS_MTHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mthi */
		Mips_MTHI_MM, MIPS_INS_MTHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mthi */
		Mips_MTHI_DSP_MM, MIPS_INS_MTHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* mthi */
		Mips_MTHI_DSP, MIPS_INS_MTHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* mthlip */
		Mips_MTHLIP_MM, MIPS_INS_MTHLIP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* mthlip */
		Mips_MTHLIP, MIPS_INS_MTHLIP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* mtlo */
		Mips_MTLO, MIPS_INS_MTLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mtlo */
		Mips_MTLO_MM, MIPS_INS_MTLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mtlo */
		Mips_MTLO_DSP_MM, MIPS_INS_MTLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* mtlo */
		Mips_MTLO_DSP, MIPS_INS_MTLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* mtm0 */
		Mips_MTM0, MIPS_INS_MTM0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mtm1 */
		Mips_MTM1, MIPS_INS_MTM1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mtm2 */
		Mips_MTM2, MIPS_INS_MTM2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mtp0 */
		Mips_MTP0, MIPS_INS_MTP0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mtp1 */
		Mips_MTP1, MIPS_INS_MTP1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mtp2 */
		Mips_MTP2, MIPS_INS_MTP2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mttacx */
		Mips_MTTACX, MIPS_INS_MTTACX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mttacx */
		Mips_MTTACX, MIPS_INS_MTTACX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, 0 }, 0, 0
#endif
	},
	{
 /* mttc0 */
		Mips_MTTC0, MIPS_INS_MTTC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mttc0 */
		Mips_MTTC0, MIPS_INS_MTTC0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, 0 }, 0, 0
#endif
	},
	{
 /* mttc1 */
		Mips_MTTC1, MIPS_INS_MTTC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, 0 }, 0, 0
#endif
	},
	{
 /* mttdsp */
		Mips_MTTDSP, MIPS_INS_MTTDSP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, 0 }, 0, 0
#endif
	},
	{
 /* mttgpr */
		Mips_MTTGPR, MIPS_INS_MTTGPR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, 0 }, 0, 0
#endif
	},
	{
 /* mtthc1 */
		Mips_MTTHC1, MIPS_INS_MTTHC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, 0 }, 0, 0
#endif
	},
	{
 /* mtthi */
		Mips_MTTHI, MIPS_INS_MTTHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mtthi */
		Mips_MTTHI, MIPS_INS_MTTHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, 0 }, 0, 0
#endif
	},
	{
 /* mttlo */
		Mips_MTTLO, MIPS_INS_MTTLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mttlo */
		Mips_MTTLO, MIPS_INS_MTTLO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, 0 }, 0, 0
#endif
	},
	{
 /* mttr */
		Mips_MTTR, MIPS_INS_MTTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* muh */
		Mips_MUH_MMR6, MIPS_INS_MUH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* muh */
		Mips_MUH, MIPS_INS_MUH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* muh */
		Mips_MUH_MMR6, MIPS_INS_MUH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* muhu */
		Mips_MUHU_MMR6, MIPS_INS_MUHU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* muhu */
		Mips_MUHU, MIPS_INS_MUHU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* muhu */
		Mips_MUHU_MMR6, MIPS_INS_MUHU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mul */
		Mips_MUL, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mul */
		Mips_MUL_MM, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mul */
		Mips_MUL_MMR6, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mul */
		Mips_MUL, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mul */
		Mips_MUL_R6, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mul */
		Mips_MUL_MM, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mul */
		Mips_MUL_MMR6, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mul */
		Mips_MULImmMacro, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* mul.d */
		Mips_FMUL_D32, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mul.d */
		Mips_FMUL_D32_MM, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* mul.d */
		Mips_FMUL_D64, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mul.d */
		Mips_FMUL_D64_MM, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* mul.ph */
		Mips_MUL_PH_MMR2, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* mul.ph */
		Mips_MUL_PH, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* mul.ps */
		Mips_FMUL_PS64, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mul.s */
		Mips_FMUL_S, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mul.s */
		Mips_FMUL_S_MMR6, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* mul.s */
		Mips_FMUL_S_MM, MIPS_INS_MUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* mul_q.h */
		Mips_MUL_Q_H, MIPS_INS_MUL_Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* mul_q.w */
		Mips_MUL_Q_W, MIPS_INS_MUL_Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* mul_s.ph */
		Mips_MUL_S_PH_MMR2, MIPS_INS_MUL_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* mul_s.ph */
		Mips_MUL_S_PH, MIPS_INS_MUL_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* muleq_s.w.phl */
		Mips_MULEQ_S_W_PHL_MM, MIPS_INS_MULEQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* muleq_s.w.phl */
		Mips_MULEQ_S_W_PHL, MIPS_INS_MULEQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* muleq_s.w.phr */
		Mips_MULEQ_S_W_PHR_MM, MIPS_INS_MULEQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* muleq_s.w.phr */
		Mips_MULEQ_S_W_PHR, MIPS_INS_MULEQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* muleu_s.ph.qbl */
		Mips_MULEU_S_PH_QBL_MM, MIPS_INS_MULEU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* muleu_s.ph.qbl */
		Mips_MULEU_S_PH_QBL, MIPS_INS_MULEU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* muleu_s.ph.qbr */
		Mips_MULEU_S_PH_QBR_MM, MIPS_INS_MULEU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* muleu_s.ph.qbr */
		Mips_MULEU_S_PH_QBR, MIPS_INS_MULEU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* mulo */
		Mips_MULOMacro, MIPS_INS_MULO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* mulo */
		Mips_MULOMacro, MIPS_INS_MULO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* mulou */
		Mips_MULOUMacro, MIPS_INS_MULOU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* mulou */
		Mips_MULOUMacro, MIPS_INS_MULOU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* mulq_rs.ph */
		Mips_MULQ_RS_PH_MM, MIPS_INS_MULQ_RS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* mulq_rs.ph */
		Mips_MULQ_RS_PH, MIPS_INS_MULQ_RS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* mulq_rs.w */
		Mips_MULQ_RS_W_MMR2, MIPS_INS_MULQ_RS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* mulq_rs.w */
		Mips_MULQ_RS_W, MIPS_INS_MULQ_RS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* mulq_s.ph */
		Mips_MULQ_S_PH_MMR2, MIPS_INS_MULQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* mulq_s.ph */
		Mips_MULQ_S_PH, MIPS_INS_MULQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* mulq_s.w */
		Mips_MULQ_S_W_MMR2, MIPS_INS_MULQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* mulq_s.w */
		Mips_MULQ_S_W, MIPS_INS_MULQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* mulr.ps */
		Mips_MULR_PS64, MIPS_INS_MULR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_MIPS3D, 0 }, 0, 0
#endif
	},
	{
 /* mulr_q.h */
		Mips_MULR_Q_H, MIPS_INS_MULR_Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* mulr_q.w */
		Mips_MULR_Q_W, MIPS_INS_MULR_Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* mulsa.w.ph */
		Mips_MULSA_W_PH_MMR2, MIPS_INS_MULSA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* mulsa.w.ph */
		Mips_MULSA_W_PH, MIPS_INS_MULSA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* mulsaq_s.w.ph */
		Mips_MULSAQ_S_W_PH_MM, MIPS_INS_MULSAQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* mulsaq_s.w.ph */
		Mips_MULSAQ_S_W_PH, MIPS_INS_MULSAQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* mult */
		Mips_MULT, MIPS_INS_MULT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mult */
		Mips_MULT_MM, MIPS_INS_MULT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mult */
		Mips_MULT_DSP_MM, MIPS_INS_MULT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* mult */
		Mips_MULT_DSP, MIPS_INS_MULT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* multu */
		Mips_MULTu, MIPS_INS_MULTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* multu */
		Mips_MULTu_MM, MIPS_INS_MULTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* multu */
		Mips_MULTU_DSP_MM, MIPS_INS_MULTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* multu */
		Mips_MULTU_DSP, MIPS_INS_MULTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* mulu */
		Mips_MULU_MMR6, MIPS_INS_MULU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mulu */
		Mips_MULU, MIPS_INS_MULU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* mulu */
		Mips_MULU_MMR6, MIPS_INS_MULU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* mulv.b */
		Mips_MULV_B, MIPS_INS_MULV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* mulv.d */
		Mips_MULV_D, MIPS_INS_MULV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* mulv.h */
		Mips_MULV_H, MIPS_INS_MULV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* mulv.w */
		Mips_MULV_W, MIPS_INS_MULV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* neg */
		Mips_SUB, MIPS_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* neg */
		Mips_SUB_MM, MIPS_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* neg */
		Mips_SUB_MMR6, MIPS_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* neg */
		Mips_NegRxRy16, MIPS_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* neg */
		Mips_SUB, MIPS_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* neg */
		Mips_SUB_MM, MIPS_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* neg */
		Mips_SUB_MMR6, MIPS_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* neg.d */
		Mips_FNEG_D32, MIPS_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* neg.d */
		Mips_FNEG_D32_MM, MIPS_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* neg.d */
		Mips_FNEG_D64, MIPS_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* neg.d */
		Mips_FNEG_D64_MM, MIPS_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* neg.s */
		Mips_FNEG_S_MMR6, MIPS_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* neg.s */
		Mips_FNEG_S, MIPS_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* neg.s */
		Mips_FNEG_S_MM, MIPS_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* negu */
		Mips_SUBu, MIPS_INS_NEGU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* negu */
		Mips_SUBu_MM, MIPS_INS_NEGU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* negu */
		Mips_SUBU_MMR6, MIPS_INS_NEGU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* negu */
		Mips_SUBu, MIPS_INS_NEGU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* negu */
		Mips_SUBu_MM, MIPS_INS_NEGU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* negu */
		Mips_SUBU_MMR6, MIPS_INS_NEGU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* nloc.b */
		Mips_NLOC_B, MIPS_INS_NLOC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* nloc.d */
		Mips_NLOC_D, MIPS_INS_NLOC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* nloc.h */
		Mips_NLOC_H, MIPS_INS_NLOC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* nloc.w */
		Mips_NLOC_W, MIPS_INS_NLOC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* nlzc.b */
		Mips_NLZC_B, MIPS_INS_NLZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* nlzc.d */
		Mips_NLZC_D, MIPS_INS_NLZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* nlzc.h */
		Mips_NLZC_H, MIPS_INS_NLZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* nlzc.w */
		Mips_NLZC_W, MIPS_INS_NLZC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* nmadd.d */
		Mips_NMADD_D32, MIPS_INS_NMADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_MADD4, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* nmadd.d */
		Mips_NMADD_D32_MM, MIPS_INS_NMADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_MADD4, 0 }, 0, 0
#endif
	},
	{
 /* nmadd.d */
		Mips_NMADD_D64, MIPS_INS_NMADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_MADD4, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* nmadd.s */
		Mips_NMADD_S, MIPS_INS_NMADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_MADD4, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* nmadd.s */
		Mips_NMADD_S_MM, MIPS_INS_NMADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_MADD4, 0 }, 0, 0
#endif
	},
	{
 /* nmsub.d */
		Mips_NMSUB_D32, MIPS_INS_NMSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_MADD4, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* nmsub.d */
		Mips_NMSUB_D32_MM, MIPS_INS_NMSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_MADD4, 0 }, 0, 0
#endif
	},
	{
 /* nmsub.d */
		Mips_NMSUB_D64, MIPS_INS_NMSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_MADD4, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* nmsub.s */
		Mips_NMSUB_S, MIPS_INS_NMSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_MADD4, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* nmsub.s */
		Mips_NMSUB_S_MM, MIPS_INS_NMSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_MADD4, 0 }, 0, 0
#endif
	},
	{
 /* nop */
		Mips_SLL, MIPS_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* nop */
		Mips_SLL_MMR6, MIPS_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* nop */
		Mips_Move32R16, MIPS_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* nop */
		Mips_SLL_MM, MIPS_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* nop */
		Mips_MOVE16_MM, MIPS_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* nor */
		Mips_NORImm, MIPS_INS_NOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP32BIT, 0 }, 0, 0
#endif
	},
	{
 /* nor */
		Mips_NORImm64, MIPS_INS_NOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP64BIT, 0 }, 0, 0
#endif
	},
	{
 /* nor */
		Mips_NOR, MIPS_INS_NOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* nor */
		Mips_NOR_MM, MIPS_INS_NOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* nor */
		Mips_NOR_MMR6, MIPS_INS_NOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* nor */
		Mips_NORImm, MIPS_INS_NOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP32BIT, 0 }, 0, 0
#endif
	},
	{
 /* nor */
		Mips_NORImm64, MIPS_INS_NOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP64BIT, 0 }, 0, 0
#endif
	},
	{
 /* nor.v */
		Mips_NOR_V, MIPS_INS_NOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* nori.b */
		Mips_NORI_B, MIPS_INS_NORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* not */
		Mips_NOR, MIPS_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* not */
		Mips_NOR_MM, MIPS_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* not */
		Mips_NOR_MMR6, MIPS_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* not */
		Mips_NotRxRy16, MIPS_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* not */
		Mips_NOR, MIPS_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* not */
		Mips_NOR_MM, MIPS_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* not */
		Mips_NOR_MMR6, MIPS_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* not16 */
		Mips_NOT16_MM, MIPS_INS_NOT16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* not16 */
		Mips_NOT16_MMR6, MIPS_INS_NOT16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* or */
		Mips_OrRxRxRy16, MIPS_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* or */
		Mips_OR, MIPS_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* or */
		Mips_OR_MM, MIPS_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* or */
		Mips_OR_MMR6, MIPS_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* or */
		Mips_ORI_MMR6, MIPS_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* or */
		Mips_ORi, MIPS_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP32BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* or */
		Mips_ORi_MM, MIPS_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* or */
		Mips_ORi64, MIPS_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* or */
		Mips_OR, MIPS_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* or */
		Mips_OR_MM, MIPS_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* or */
		Mips_OR_MMR6, MIPS_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* or */
		Mips_ORI_MMR6, MIPS_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* or */
		Mips_ORi, MIPS_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP32BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* or */
		Mips_ORi_MM, MIPS_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* or */
		Mips_ORi64, MIPS_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* or.v */
		Mips_OR_V, MIPS_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* or16 */
		Mips_OR16_MM, MIPS_INS_OR16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* or16 */
		Mips_OR16_MMR6, MIPS_INS_OR16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* ori */
		Mips_ORI_MMR6, MIPS_INS_ORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* ori */
		Mips_ORi, MIPS_INS_ORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ori */
		Mips_ORi_MM, MIPS_INS_ORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* ori */
		Mips_ORI_MMR6, MIPS_INS_ORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* ori */
		Mips_ORi, MIPS_INS_ORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ori */
		Mips_ORi_MM, MIPS_INS_ORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* ori.b */
		Mips_ORI_B, MIPS_INS_ORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* packrl.ph */
		Mips_PACKRL_PH_MM, MIPS_INS_PACKRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* packrl.ph */
		Mips_PACKRL_PH, MIPS_INS_PACKRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* pause */
		Mips_PAUSE, MIPS_INS_PAUSE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* pause */
		Mips_PAUSE_MMR6, MIPS_INS_PAUSE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* pause */
		Mips_PAUSE_MM, MIPS_INS_PAUSE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* pckev.b */
		Mips_PCKEV_B, MIPS_INS_PCKEV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* pckev.d */
		Mips_PCKEV_D, MIPS_INS_PCKEV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* pckev.h */
		Mips_PCKEV_H, MIPS_INS_PCKEV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* pckev.w */
		Mips_PCKEV_W, MIPS_INS_PCKEV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* pckod.b */
		Mips_PCKOD_B, MIPS_INS_PCKOD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* pckod.d */
		Mips_PCKOD_D, MIPS_INS_PCKOD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* pckod.h */
		Mips_PCKOD_H, MIPS_INS_PCKOD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* pckod.w */
		Mips_PCKOD_W, MIPS_INS_PCKOD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* pcnt.b */
		Mips_PCNT_B, MIPS_INS_PCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* pcnt.d */
		Mips_PCNT_D, MIPS_INS_PCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* pcnt.h */
		Mips_PCNT_H, MIPS_INS_PCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* pcnt.w */
		Mips_PCNT_W, MIPS_INS_PCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* pick.ph */
		Mips_PICK_PH_MM, MIPS_INS_PICK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* pick.ph */
		Mips_PICK_PH, MIPS_INS_PICK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* pick.qb */
		Mips_PICK_QB_MM, MIPS_INS_PICK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* pick.qb */
		Mips_PICK_QB, MIPS_INS_PICK,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* pll.ps */
		Mips_PLL_PS64, MIPS_INS_PLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* plu.ps */
		Mips_PLU_PS64, MIPS_INS_PLU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* pop */
		Mips_POP, MIPS_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* pop */
		Mips_POP, MIPS_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* preceq.w.phl */
		Mips_PRECEQ_W_PHL_MM, MIPS_INS_PRECEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* preceq.w.phl */
		Mips_PRECEQ_W_PHL, MIPS_INS_PRECEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* preceq.w.phr */
		Mips_PRECEQ_W_PHR_MM, MIPS_INS_PRECEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* preceq.w.phr */
		Mips_PRECEQ_W_PHR, MIPS_INS_PRECEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* precequ.ph.qbl */
		Mips_PRECEQU_PH_QBL_MM, MIPS_INS_PRECEQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* precequ.ph.qbl */
		Mips_PRECEQU_PH_QBL, MIPS_INS_PRECEQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* precequ.ph.qbla */
		Mips_PRECEQU_PH_QBLA_MM, MIPS_INS_PRECEQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* precequ.ph.qbla */
		Mips_PRECEQU_PH_QBLA, MIPS_INS_PRECEQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* precequ.ph.qbr */
		Mips_PRECEQU_PH_QBR_MM, MIPS_INS_PRECEQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* precequ.ph.qbr */
		Mips_PRECEQU_PH_QBR, MIPS_INS_PRECEQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* precequ.ph.qbra */
		Mips_PRECEQU_PH_QBRA_MM, MIPS_INS_PRECEQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* precequ.ph.qbra */
		Mips_PRECEQU_PH_QBRA, MIPS_INS_PRECEQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* preceu.ph.qbl */
		Mips_PRECEU_PH_QBL_MM, MIPS_INS_PRECEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* preceu.ph.qbl */
		Mips_PRECEU_PH_QBL, MIPS_INS_PRECEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* preceu.ph.qbla */
		Mips_PRECEU_PH_QBLA_MM, MIPS_INS_PRECEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* preceu.ph.qbla */
		Mips_PRECEU_PH_QBLA, MIPS_INS_PRECEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* preceu.ph.qbr */
		Mips_PRECEU_PH_QBR_MM, MIPS_INS_PRECEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* preceu.ph.qbr */
		Mips_PRECEU_PH_QBR, MIPS_INS_PRECEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* preceu.ph.qbra */
		Mips_PRECEU_PH_QBRA_MM, MIPS_INS_PRECEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* preceu.ph.qbra */
		Mips_PRECEU_PH_QBRA, MIPS_INS_PRECEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* precr.qb.ph */
		Mips_PRECR_QB_PH_MMR2, MIPS_INS_PRECR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* precr.qb.ph */
		Mips_PRECR_QB_PH, MIPS_INS_PRECR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* precr_sra.ph.w */
		Mips_PRECR_SRA_PH_W_MMR2, MIPS_INS_PRECR_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* precr_sra.ph.w */
		Mips_PRECR_SRA_PH_W, MIPS_INS_PRECR_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* precr_sra_r.ph.w */
		Mips_PRECR_SRA_R_PH_W_MMR2, MIPS_INS_PRECR_SRA_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* precr_sra_r.ph.w */
		Mips_PRECR_SRA_R_PH_W, MIPS_INS_PRECR_SRA_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* precrq.ph.w */
		Mips_PRECRQ_PH_W_MM, MIPS_INS_PRECRQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* precrq.ph.w */
		Mips_PRECRQ_PH_W, MIPS_INS_PRECRQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* precrq.qb.ph */
		Mips_PRECRQ_QB_PH_MM, MIPS_INS_PRECRQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* precrq.qb.ph */
		Mips_PRECRQ_QB_PH, MIPS_INS_PRECRQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* precrq_rs.ph.w */
		Mips_PRECRQ_RS_PH_W_MM, MIPS_INS_PRECRQ_RS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* precrq_rs.ph.w */
		Mips_PRECRQ_RS_PH_W, MIPS_INS_PRECRQ_RS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* precrqu_s.qb.ph */
		Mips_PRECRQU_S_QB_PH_MM, MIPS_INS_PRECRQU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* precrqu_s.qb.ph */
		Mips_PRECRQU_S_QB_PH, MIPS_INS_PRECRQU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* pref */
		Mips_PREF_R6, MIPS_INS_PREF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* pref */
		Mips_PREF, MIPS_INS_PREF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3_32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* pref */
		Mips_PREF_MM, MIPS_INS_PREF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* pref */
		Mips_PREF_MMR6, MIPS_INS_PREF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* prefe */
		Mips_PREFE, MIPS_INS_PREFE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_EVA, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* prefe */
		Mips_PREFE_MM, MIPS_INS_PREFE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_EVA, 0 }, 0, 0
#endif
	},
	{
 /* prefx */
		Mips_PREFX_MM, MIPS_INS_PREFX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* prepend */
		Mips_PREPEND_MMR2, MIPS_INS_PREPEND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* prepend */
		Mips_PREPEND, MIPS_INS_PREPEND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* pul.ps */
		Mips_PUL_PS64, MIPS_INS_PUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* puu.ps */
		Mips_PUU_PS64, MIPS_INS_PUU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* raddu.w.qb */
		Mips_RADDU_W_QB_MM, MIPS_INS_RADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* raddu.w.qb */
		Mips_RADDU_W_QB, MIPS_INS_RADDU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* rddsp */
		Mips_RDDSP_MM, MIPS_INS_RDDSP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* rddsp */
		Mips_RDDSP, MIPS_INS_RDDSP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* rdhwr */
		Mips_RDHWR, MIPS_INS_RDHWR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* rdhwr */
		Mips_RDHWR_MM, MIPS_INS_RDHWR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* rdhwr */
		Mips_RDHWR_MMR6, MIPS_INS_RDHWR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* rdhwr */
		Mips_RDHWR64, MIPS_INS_RDHWR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP64BIT, 0 }, 0, 0
#endif
	},
	{
 /* rdhwr */
		Mips_RDHWR_MMR6, MIPS_INS_RDHWR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* rdhwr */
		Mips_RDHWR, MIPS_INS_RDHWR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* rdhwr */
		Mips_RDHWR_MM, MIPS_INS_RDHWR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* rdpgpr */
		Mips_RDPGPR_MMR6, MIPS_INS_RDPGPR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* recip.d */
		Mips_RECIP_D32, MIPS_INS_RECIP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* recip.d */
		Mips_RECIP_D32_MM, MIPS_INS_RECIP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* recip.d */
		Mips_RECIP_D64, MIPS_INS_RECIP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* recip.d */
		Mips_RECIP_D64_MM, MIPS_INS_RECIP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* recip.s */
		Mips_RECIP_S, MIPS_INS_RECIP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* recip.s */
		Mips_RECIP_S_MM, MIPS_INS_RECIP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* rem */
		Mips_SRemMacro, MIPS_INS_REM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* rem */
		Mips_SRemIMacro, MIPS_INS_REM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* rem */
		Mips_SRemMacro, MIPS_INS_REM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* rem */
		Mips_SRemIMacro, MIPS_INS_REM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* remu */
		Mips_URemMacro, MIPS_INS_REMU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* remu */
		Mips_URemIMacro, MIPS_INS_REMU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* remu */
		Mips_URemMacro, MIPS_INS_REMU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* remu */
		Mips_URemIMacro, MIPS_INS_REMU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* repl.ph */
		Mips_REPL_PH_MM, MIPS_INS_REPL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* repl.ph */
		Mips_REPL_PH, MIPS_INS_REPL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* repl.qb */
		Mips_REPL_QB_MM, MIPS_INS_REPL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* repl.qb */
		Mips_REPL_QB, MIPS_INS_REPL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* replv.ph */
		Mips_REPLV_PH_MM, MIPS_INS_REPLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* replv.ph */
		Mips_REPLV_PH, MIPS_INS_REPLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* replv.qb */
		Mips_REPLV_QB_MM, MIPS_INS_REPLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* replv.qb */
		Mips_REPLV_QB, MIPS_INS_REPLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* rint.d */
		Mips_RINT_D, MIPS_INS_RINT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* rint.d */
		Mips_RINT_D_MMR6, MIPS_INS_RINT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* rint.s */
		Mips_RINT_S, MIPS_INS_RINT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* rint.s */
		Mips_RINT_S_MMR6, MIPS_INS_RINT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* rol */
		Mips_ROL, MIPS_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* rol */
		Mips_ROLImm, MIPS_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* rol */
		Mips_ROL, MIPS_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* rol */
		Mips_ROLImm, MIPS_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* ror */
		Mips_ROR, MIPS_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* ror */
		Mips_RORImm, MIPS_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* ror */
		Mips_ROR, MIPS_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* ror */
		Mips_RORImm, MIPS_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* rotr */
		Mips_ROTR, MIPS_INS_ROTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* rotr */
		Mips_ROTR_MM, MIPS_INS_ROTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* rotr */
		Mips_ROTR_MM, MIPS_INS_ROTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* rotr */
		Mips_ROTR, MIPS_INS_ROTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* rotr */
		Mips_ROTR_MM, MIPS_INS_ROTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* rotrv */
		Mips_ROTRV, MIPS_INS_ROTRV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* rotrv */
		Mips_ROTRV_MM, MIPS_INS_ROTRV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* round.l.d */
		Mips_ROUND_L_D64, MIPS_INS_ROUND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS3_32, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* round.l.d */
		Mips_ROUND_L_D_MMR6, MIPS_INS_ROUND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* round.l.s */
		Mips_ROUND_L_S, MIPS_INS_ROUND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* round.l.s */
		Mips_ROUND_L_S_MMR6, MIPS_INS_ROUND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* round.w.d */
		Mips_ROUND_W_D32, MIPS_INS_ROUND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* round.w.d */
		Mips_ROUND_W_MM, MIPS_INS_ROUND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* round.w.d */
		Mips_ROUND_W_D64, MIPS_INS_ROUND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* round.w.d */
		Mips_ROUND_W_D_MMR6, MIPS_INS_ROUND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* round.w.s */
		Mips_ROUND_W_S, MIPS_INS_ROUND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* round.w.s */
		Mips_ROUND_W_S_MMR6, MIPS_INS_ROUND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* round.w.s */
		Mips_ROUND_W_S_MM, MIPS_INS_ROUND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* rsqrt.d */
		Mips_RSQRT_D32, MIPS_INS_RSQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* rsqrt.d */
		Mips_RSQRT_D32_MM, MIPS_INS_RSQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* rsqrt.d */
		Mips_RSQRT_D64, MIPS_INS_RSQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* rsqrt.d */
		Mips_RSQRT_D64_MM, MIPS_INS_RSQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* rsqrt.s */
		Mips_RSQRT_S, MIPS_INS_RSQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* rsqrt.s */
		Mips_RSQRT_S_MM, MIPS_INS_RSQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* s.d */
		Mips_SDC1, MIPS_INS_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* s.d */
		Mips_SDC1_M1, MIPS_INS_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* s.d */
		Mips_SDC1_M1, MIPS_INS_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* s.d */
		Mips_SDC164, MIPS_INS_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* s.s */
		Mips_SWC1, MIPS_INS_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* saa */
		Mips_SaaAddr, MIPS_INS_SAA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPSP, 0 }, 0, 0
#endif
	},
	{
 /* saa */
		Mips_SAA, MIPS_INS_SAA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPSP, 0 }, 0, 0
#endif
	},
	{
 /* saad */
		Mips_SaadAddr, MIPS_INS_SAAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPSP, 0 }, 0, 0
#endif
	},
	{
 /* saad */
		Mips_SAAD, MIPS_INS_SAAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPSP, 0 }, 0, 0
#endif
	},
	{
 /* sat_s.b */
		Mips_SAT_S_B, MIPS_INS_SAT_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sat_s.d */
		Mips_SAT_S_D, MIPS_INS_SAT_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sat_s.h */
		Mips_SAT_S_H, MIPS_INS_SAT_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sat_s.w */
		Mips_SAT_S_W, MIPS_INS_SAT_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sat_u.b */
		Mips_SAT_U_B, MIPS_INS_SAT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sat_u.d */
		Mips_SAT_U_D, MIPS_INS_SAT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sat_u.h */
		Mips_SAT_U_H, MIPS_INS_SAT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sat_u.w */
		Mips_SAT_U_W, MIPS_INS_SAT_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sb */
		Mips_SB, MIPS_INS_SB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sb */
		Mips_SB_MMR6, MIPS_INS_SB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sb */
		Mips_SB_MM, MIPS_INS_SB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sb */
		Mips_SbRxRyOffMemX16, MIPS_INS_SB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* sb16 */
		Mips_SB16_MM, MIPS_INS_SB16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sb16 */
		Mips_SB16_MMR6, MIPS_INS_SB16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sbe */
		Mips_SBE, MIPS_INS_SBE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_EVA, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sbe */
		Mips_SBE_MM, MIPS_INS_SBE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_EVA, 0 }, 0, 0
#endif
	},
	{
 /* sc */
		Mips_SC64_R6, MIPS_INS_SC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_PTR64BIT, MIPS_GRP_MIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sc */
		Mips_SC_R6, MIPS_INS_SC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_PTR32BIT, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sc */
		Mips_SC_MMR6, MIPS_INS_SC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sc */
		Mips_SC, MIPS_INS_SC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_PTR32BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sc */
		Mips_SC64, MIPS_INS_SC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_PTR64BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sc */
		Mips_SC_MM, MIPS_INS_SC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* scd */
		Mips_SCD_R6, MIPS_INS_SCD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* scd */
		Mips_SCD, MIPS_INS_SCD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* sce */
		Mips_SCE, MIPS_INS_SCE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_EVA, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sce */
		Mips_SCE_MM, MIPS_INS_SCE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_EVA, 0 }, 0, 0
#endif
	},
	{
 /* sd */
		Mips_SDMacro, MIPS_INS_SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS3, 0 }, 0, 0
#endif
	},
	{
 /* sd */
		Mips_SD, MIPS_INS_SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sdbbp */
		Mips_SDBBP, MIPS_INS_SDBBP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* sdbbp */
		Mips_SDBBP_R6, MIPS_INS_SDBBP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sdbbp */
		Mips_SDBBP_MMR6, MIPS_INS_SDBBP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sdbbp */
		Mips_SDBBP_MM, MIPS_INS_SDBBP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sdbbp */
		Mips_SDBBP, MIPS_INS_SDBBP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sdbbp */
		Mips_SDBBP_R6, MIPS_INS_SDBBP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sdbbp */
		Mips_SDBBP_MMR6, MIPS_INS_SDBBP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sdbbp16 */
		Mips_SDBBP16_MM, MIPS_INS_SDBBP16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sdbbp16 */
		Mips_SDBBP16_MMR6, MIPS_INS_SDBBP16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sdc1 */
		Mips_SDC1, MIPS_INS_SDC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sdc1 */
		Mips_SDC1_MM, MIPS_INS_SDC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* sdc1 */
		Mips_SDC164, MIPS_INS_SDC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sdc1 */
		Mips_SDC1_D64_MMR6, MIPS_INS_SDC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* sdc2 */
		Mips_SDC2_R6, MIPS_INS_SDC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sdc2 */
		Mips_SDC2_MMR6, MIPS_INS_SDC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sdc2 */
		Mips_SDC2, MIPS_INS_SDC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sdc3 */
		Mips_SDC3, MIPS_INS_SDC3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTCNMIPS, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sdl */
		Mips_SDL, MIPS_INS_SDL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* sdr */
		Mips_SDR, MIPS_INS_SDR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* sdxc1 */
		Mips_SDXC1, MIPS_INS_SDXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sdxc1 */
		Mips_SDXC164, MIPS_INS_SDXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* seb */
		Mips_SebRx16, MIPS_INS_SEB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* seb */
		Mips_SEB, MIPS_INS_SEB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* seb */
		Mips_SEB_MM, MIPS_INS_SEB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* seb */
		Mips_SEB, MIPS_INS_SEB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* seb */
		Mips_SEB_MM, MIPS_INS_SEB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* seh */
		Mips_SehRx16, MIPS_INS_SEH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* seh */
		Mips_SEH, MIPS_INS_SEH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* seh */
		Mips_SEH_MM, MIPS_INS_SEH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* seh */
		Mips_SEH, MIPS_INS_SEH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* seh */
		Mips_SEH_MM, MIPS_INS_SEH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sel.d */
		Mips_SEL_D, MIPS_INS_SEL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sel.d */
		Mips_SEL_D_MMR6, MIPS_INS_SEL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sel.s */
		Mips_SEL_S, MIPS_INS_SEL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sel.s */
		Mips_SEL_S_MMR6, MIPS_INS_SEL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* seleqz */
		Mips_SELEQZ, MIPS_INS_SELEQZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP32BIT, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* seleqz */
		Mips_SELEQZ_MMR6, MIPS_INS_SELEQZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* seleqz */
		Mips_SELEQZ64, MIPS_INS_SELEQZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* seleqz.d */
		Mips_SELEQZ_D, MIPS_INS_SELEQZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* seleqz.d */
		Mips_SELEQZ_D_MMR6, MIPS_INS_SELEQZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* seleqz.s */
		Mips_SELEQZ_S, MIPS_INS_SELEQZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* seleqz.s */
		Mips_SELEQZ_S_MMR6, MIPS_INS_SELEQZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* selnez */
		Mips_SELNEZ, MIPS_INS_SELNEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP32BIT, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* selnez */
		Mips_SELNEZ_MMR6, MIPS_INS_SELNEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* selnez */
		Mips_SELNEZ64, MIPS_INS_SELNEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* selnez.d */
		Mips_SELNEZ_D, MIPS_INS_SELNEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* selnez.d */
		Mips_SELNEZ_D_MMR6, MIPS_INS_SELNEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* selnez.s */
		Mips_SELNEZ_S, MIPS_INS_SELNEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* selnez.s */
		Mips_SELNEZ_S_MMR6, MIPS_INS_SELNEZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* seq */
		Mips_SEQMacro, MIPS_INS_SEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_NOTCNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* seq */
		Mips_SEQIMacro, MIPS_INS_SEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_NOTCNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* seq */
		Mips_SEQ, MIPS_INS_SEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* seq */
		Mips_SEQMacro, MIPS_INS_SEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_NOTCNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* seq */
		Mips_SEQIMacro, MIPS_INS_SEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_NOTCNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* seq */
		Mips_SEQ, MIPS_INS_SEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* seqi */
		Mips_SEQi, MIPS_INS_SEQI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* seqi */
		Mips_SEQi, MIPS_INS_SEQI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sge */
		Mips_SGE, MIPS_INS_SGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sge */
		Mips_SGEImm, MIPS_INS_SGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP32BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sge */
		Mips_SGEImm64, MIPS_INS_SGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP64BIT, 0 }, 0, 0
#endif
	},
	{
 /* sge */
		Mips_SGE, MIPS_INS_SGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sge */
		Mips_SGEImm, MIPS_INS_SGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP32BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sge */
		Mips_SGEImm64, MIPS_INS_SGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP64BIT, 0 }, 0, 0
#endif
	},
	{
 /* sgeu */
		Mips_SGEU, MIPS_INS_SGEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sgeu */
		Mips_SGEUImm, MIPS_INS_SGEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP32BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sgeu */
		Mips_SGEUImm64, MIPS_INS_SGEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP64BIT, 0 }, 0, 0
#endif
	},
	{
 /* sgeu */
		Mips_SGEU, MIPS_INS_SGEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sgeu */
		Mips_SGEUImm, MIPS_INS_SGEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP32BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sgeu */
		Mips_SGEUImm64, MIPS_INS_SGEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP64BIT, 0 }, 0, 0
#endif
	},
	{
 /* sgt */
		Mips_SLT, MIPS_INS_SGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sgt */
		Mips_SLT_MM, MIPS_INS_SGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sgt */
		Mips_SGTImm, MIPS_INS_SGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP32BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sgt */
		Mips_SGTImm64, MIPS_INS_SGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP64BIT, 0 }, 0, 0
#endif
	},
	{
 /* sgt */
		Mips_SLT, MIPS_INS_SGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sgt */
		Mips_SLT_MM, MIPS_INS_SGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sgt */
		Mips_SGTImm, MIPS_INS_SGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP32BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sgt */
		Mips_SGTImm64, MIPS_INS_SGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP64BIT, 0 }, 0, 0
#endif
	},
	{
 /* sgtu */
		Mips_SLTu, MIPS_INS_SGTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sgtu */
		Mips_SLTu_MM, MIPS_INS_SGTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sgtu */
		Mips_SGTUImm, MIPS_INS_SGTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP32BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sgtu */
		Mips_SGTUImm64, MIPS_INS_SGTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP64BIT, 0 }, 0, 0
#endif
	},
	{
 /* sgtu */
		Mips_SLTu, MIPS_INS_SGTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sgtu */
		Mips_SLTu_MM, MIPS_INS_SGTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sgtu */
		Mips_SGTUImm, MIPS_INS_SGTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP32BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sgtu */
		Mips_SGTUImm64, MIPS_INS_SGTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP64BIT, 0 }, 0, 0
#endif
	},
	{
 /* sh */
		Mips_SH, MIPS_INS_SH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sh */
		Mips_SH_MMR6, MIPS_INS_SH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sh */
		Mips_SH_MM, MIPS_INS_SH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sh */
		Mips_ShRxRyOffMemX16, MIPS_INS_SH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* sh16 */
		Mips_SH16_MM, MIPS_INS_SH16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sh16 */
		Mips_SH16_MMR6, MIPS_INS_SH16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* she */
		Mips_SHE, MIPS_INS_SHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_EVA, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* she */
		Mips_SHE_MM, MIPS_INS_SHE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_EVA, 0 }, 0, 0
#endif
	},
	{
 /* shf.b */
		Mips_SHF_B, MIPS_INS_SHF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* shf.h */
		Mips_SHF_H, MIPS_INS_SHF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* shf.w */
		Mips_SHF_W, MIPS_INS_SHF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* shilo */
		Mips_SHILO_MM, MIPS_INS_SHILO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shilo */
		Mips_SHILO, MIPS_INS_SHILO,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shilov */
		Mips_SHILOV_MM, MIPS_INS_SHILOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shilov */
		Mips_SHILOV, MIPS_INS_SHILOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shll.ph */
		Mips_SHLL_PH_MM, MIPS_INS_SHLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shll.ph */
		Mips_SHLL_PH, MIPS_INS_SHLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shll.qb */
		Mips_SHLL_QB_MM, MIPS_INS_SHLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shll.qb */
		Mips_SHLL_QB, MIPS_INS_SHLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shll_s.ph */
		Mips_SHLL_S_PH_MM, MIPS_INS_SHLL_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shll_s.ph */
		Mips_SHLL_S_PH, MIPS_INS_SHLL_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shll_s.w */
		Mips_SHLL_S_W_MM, MIPS_INS_SHLL_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shll_s.w */
		Mips_SHLL_S_W, MIPS_INS_SHLL_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shllv.ph */
		Mips_SHLLV_PH_MM, MIPS_INS_SHLLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shllv.ph */
		Mips_SHLLV_PH, MIPS_INS_SHLLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shllv.qb */
		Mips_SHLLV_QB_MM, MIPS_INS_SHLLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shllv.qb */
		Mips_SHLLV_QB, MIPS_INS_SHLLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shllv_s.ph */
		Mips_SHLLV_S_PH_MM, MIPS_INS_SHLLV_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shllv_s.ph */
		Mips_SHLLV_S_PH, MIPS_INS_SHLLV_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shllv_s.w */
		Mips_SHLLV_S_W_MM, MIPS_INS_SHLLV_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shllv_s.w */
		Mips_SHLLV_S_W, MIPS_INS_SHLLV_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shra.ph */
		Mips_SHRA_PH_MM, MIPS_INS_SHRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shra.ph */
		Mips_SHRA_PH, MIPS_INS_SHRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shra.qb */
		Mips_SHRA_QB_MMR2, MIPS_INS_SHRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* shra.qb */
		Mips_SHRA_QB, MIPS_INS_SHRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* shra_r.ph */
		Mips_SHRA_R_PH_MM, MIPS_INS_SHRA_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shra_r.ph */
		Mips_SHRA_R_PH, MIPS_INS_SHRA_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shra_r.qb */
		Mips_SHRA_R_QB_MMR2, MIPS_INS_SHRA_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* shra_r.qb */
		Mips_SHRA_R_QB, MIPS_INS_SHRA_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* shra_r.w */
		Mips_SHRA_R_W_MM, MIPS_INS_SHRA_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shra_r.w */
		Mips_SHRA_R_W, MIPS_INS_SHRA_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shrav.ph */
		Mips_SHRAV_PH_MM, MIPS_INS_SHRAV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shrav.ph */
		Mips_SHRAV_PH, MIPS_INS_SHRAV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shrav.qb */
		Mips_SHRAV_QB_MMR2, MIPS_INS_SHRAV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* shrav.qb */
		Mips_SHRAV_QB, MIPS_INS_SHRAV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* shrav_r.ph */
		Mips_SHRAV_R_PH_MM, MIPS_INS_SHRAV_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shrav_r.ph */
		Mips_SHRAV_R_PH, MIPS_INS_SHRAV_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shrav_r.qb */
		Mips_SHRAV_R_QB_MMR2, MIPS_INS_SHRAV_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* shrav_r.qb */
		Mips_SHRAV_R_QB, MIPS_INS_SHRAV_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* shrav_r.w */
		Mips_SHRAV_R_W_MM, MIPS_INS_SHRAV_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shrav_r.w */
		Mips_SHRAV_R_W, MIPS_INS_SHRAV_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shrl.ph */
		Mips_SHRL_PH_MMR2, MIPS_INS_SHRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* shrl.ph */
		Mips_SHRL_PH, MIPS_INS_SHRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* shrl.qb */
		Mips_SHRL_QB_MM, MIPS_INS_SHRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shrl.qb */
		Mips_SHRL_QB, MIPS_INS_SHRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shrlv.ph */
		Mips_SHRLV_PH_MMR2, MIPS_INS_SHRLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* shrlv.ph */
		Mips_SHRLV_PH, MIPS_INS_SHRLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* shrlv.qb */
		Mips_SHRLV_QB_MM, MIPS_INS_SHRLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* shrlv.qb */
		Mips_SHRLV_QB, MIPS_INS_SHRLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* sigrie */
		Mips_SIGRIE, MIPS_INS_SIGRIE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sigrie */
		Mips_SIGRIE_MMR6, MIPS_INS_SIGRIE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sigrie */
		Mips_SIGRIE, MIPS_INS_SIGRIE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sigrie */
		Mips_SIGRIE_MMR6, MIPS_INS_SIGRIE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sld.b */
		Mips_SLD_B, MIPS_INS_SLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sld.d */
		Mips_SLD_D, MIPS_INS_SLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sld.h */
		Mips_SLD_H, MIPS_INS_SLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sld.w */
		Mips_SLD_W, MIPS_INS_SLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sldi.b */
		Mips_SLDI_B, MIPS_INS_SLDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sldi.d */
		Mips_SLDI_D, MIPS_INS_SLDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sldi.h */
		Mips_SLDI_H, MIPS_INS_SLDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sldi.w */
		Mips_SLDI_W, MIPS_INS_SLDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sle */
		Mips_SLE, MIPS_INS_SLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sle */
		Mips_SLEImm, MIPS_INS_SLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP32BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sle */
		Mips_SLEImm64, MIPS_INS_SLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP64BIT, 0 }, 0, 0
#endif
	},
	{
 /* sle */
		Mips_SLE, MIPS_INS_SLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sle */
		Mips_SLEImm, MIPS_INS_SLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP32BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sle */
		Mips_SLEImm64, MIPS_INS_SLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP64BIT, 0 }, 0, 0
#endif
	},
	{
 /* sleu */
		Mips_SLEU, MIPS_INS_SLEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sleu */
		Mips_SLEUImm, MIPS_INS_SLEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP32BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sleu */
		Mips_SLEUImm64, MIPS_INS_SLEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP64BIT, 0 }, 0, 0
#endif
	},
	{
 /* sleu */
		Mips_SLEU, MIPS_INS_SLEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sleu */
		Mips_SLEUImm, MIPS_INS_SLEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP32BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sleu */
		Mips_SLEUImm64, MIPS_INS_SLEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP64BIT, 0 }, 0, 0
#endif
	},
	{
 /* sll */
		Mips_SLLV, MIPS_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sll */
		Mips_SLLV_MM, MIPS_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sll */
		Mips_SLL, MIPS_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sll */
		Mips_SLL_MMR6, MIPS_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sll */
		Mips_SLL_MM, MIPS_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sll */
		Mips_SLL_MM, MIPS_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sll */
		Mips_SllX16, MIPS_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* sll */
		Mips_SLLV, MIPS_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sll */
		Mips_SLLV_MM, MIPS_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sll */
		Mips_SLL, MIPS_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sll */
		Mips_SLL_MMR6, MIPS_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sll */
		Mips_SLL_MM, MIPS_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sll.b */
		Mips_SLL_B, MIPS_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sll.d */
		Mips_SLL_D, MIPS_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sll.h */
		Mips_SLL_H, MIPS_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sll.w */
		Mips_SLL_W, MIPS_INS_SLL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sll16 */
		Mips_SLL16_MM, MIPS_INS_SLL16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sll16 */
		Mips_SLL16_MMR6, MIPS_INS_SLL16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* slli.b */
		Mips_SLLI_B, MIPS_INS_SLLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* slli.d */
		Mips_SLLI_D, MIPS_INS_SLLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* slli.h */
		Mips_SLLI_H, MIPS_INS_SLLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* slli.w */
		Mips_SLLI_W, MIPS_INS_SLLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sllv */
		Mips_SllvRxRy16, MIPS_INS_SLLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* sllv */
		Mips_SLLV, MIPS_INS_SLLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sllv */
		Mips_SLLV_MM, MIPS_INS_SLLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* slt */
		Mips_SltRxRy16, MIPS_INS_SLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* slt */
		Mips_SLTi, MIPS_INS_SLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP32BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* slt */
		Mips_SLTi_MM, MIPS_INS_SLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* slt */
		Mips_SLTImm64, MIPS_INS_SLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP64BIT, 0 }, 0, 0
#endif
	},
	{
 /* slt */
		Mips_SLT, MIPS_INS_SLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* slt */
		Mips_SLT_MM, MIPS_INS_SLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* slt */
		Mips_SLTi, MIPS_INS_SLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP32BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* slt */
		Mips_SLTi_MM, MIPS_INS_SLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* slt */
		Mips_SLTImm64, MIPS_INS_SLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP64BIT, 0 }, 0, 0
#endif
	},
	{
 /* slti */
		Mips_SltiRxImmX16, MIPS_INS_SLTI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* slti */
		Mips_SLTi, MIPS_INS_SLTI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* slti */
		Mips_SLTi_MM, MIPS_INS_SLTI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* slti */
		Mips_SltiRxImm16, MIPS_INS_SLTI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* sltiu */
		Mips_SltiuRxImmX16, MIPS_INS_SLTIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* sltiu */
		Mips_SLTiu, MIPS_INS_SLTIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sltiu */
		Mips_SLTiu_MM, MIPS_INS_SLTIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sltiu */
		Mips_SltiuRxImm16, MIPS_INS_SLTIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* sltu */
		Mips_SltuRxRy16, MIPS_INS_SLTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* sltu */
		Mips_SLTiu, MIPS_INS_SLTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP32BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sltu */
		Mips_SLTiu_MM, MIPS_INS_SLTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sltu */
		Mips_SLTUImm64, MIPS_INS_SLTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP64BIT, 0 }, 0, 0
#endif
	},
	{
 /* sltu */
		Mips_SLTu, MIPS_INS_SLTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sltu */
		Mips_SLTu_MM, MIPS_INS_SLTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sltu */
		Mips_SLTiu, MIPS_INS_SLTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP32BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sltu */
		Mips_SLTiu_MM, MIPS_INS_SLTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sltu */
		Mips_SLTUImm64, MIPS_INS_SLTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_GP64BIT, 0 }, 0, 0
#endif
	},
	{
 /* sne */
		Mips_SNEMacro, MIPS_INS_SNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_NOTCNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sne */
		Mips_SNEIMacro, MIPS_INS_SNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_NOTCNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sne */
		Mips_SNE, MIPS_INS_SNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sne */
		Mips_SNEMacro, MIPS_INS_SNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_NOTCNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sne */
		Mips_SNEIMacro, MIPS_INS_SNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_NOTCNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sne */
		Mips_SNE, MIPS_INS_SNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* snei */
		Mips_SNEi, MIPS_INS_SNEI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* snei */
		Mips_SNEi, MIPS_INS_SNEI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* splat.b */
		Mips_SPLAT_B, MIPS_INS_SPLAT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* splat.d */
		Mips_SPLAT_D, MIPS_INS_SPLAT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* splat.h */
		Mips_SPLAT_H, MIPS_INS_SPLAT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* splat.w */
		Mips_SPLAT_W, MIPS_INS_SPLAT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* splati.b */
		Mips_SPLATI_B, MIPS_INS_SPLATI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* splati.d */
		Mips_SPLATI_D, MIPS_INS_SPLATI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* splati.h */
		Mips_SPLATI_H, MIPS_INS_SPLATI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* splati.w */
		Mips_SPLATI_W, MIPS_INS_SPLATI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sqrt.d */
		Mips_FSQRT_D32, MIPS_INS_SQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sqrt.d */
		Mips_FSQRT_D32_MM, MIPS_INS_SQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* sqrt.d */
		Mips_FSQRT_D64, MIPS_INS_SQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sqrt.d */
		Mips_FSQRT_D64_MM, MIPS_INS_SQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* sqrt.s */
		Mips_FSQRT_S, MIPS_INS_SQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sqrt.s */
		Mips_FSQRT_S_MM, MIPS_INS_SQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* sra */
		Mips_SRAV, MIPS_INS_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sra */
		Mips_SRAV_MM, MIPS_INS_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sra */
		Mips_SRA, MIPS_INS_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sra */
		Mips_SRA_MM, MIPS_INS_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sra */
		Mips_SRA_MM, MIPS_INS_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sra */
		Mips_SraX16, MIPS_INS_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* sra */
		Mips_SRAV, MIPS_INS_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sra */
		Mips_SRAV_MM, MIPS_INS_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sra */
		Mips_SRA, MIPS_INS_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sra */
		Mips_SRA_MM, MIPS_INS_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sra.b */
		Mips_SRA_B, MIPS_INS_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sra.d */
		Mips_SRA_D, MIPS_INS_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sra.h */
		Mips_SRA_H, MIPS_INS_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sra.w */
		Mips_SRA_W, MIPS_INS_SRA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srai.b */
		Mips_SRAI_B, MIPS_INS_SRAI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srai.d */
		Mips_SRAI_D, MIPS_INS_SRAI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srai.h */
		Mips_SRAI_H, MIPS_INS_SRAI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srai.w */
		Mips_SRAI_W, MIPS_INS_SRAI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srar.b */
		Mips_SRAR_B, MIPS_INS_SRAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srar.d */
		Mips_SRAR_D, MIPS_INS_SRAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srar.h */
		Mips_SRAR_H, MIPS_INS_SRAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srar.w */
		Mips_SRAR_W, MIPS_INS_SRAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srari.b */
		Mips_SRARI_B, MIPS_INS_SRARI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srari.d */
		Mips_SRARI_D, MIPS_INS_SRARI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srari.h */
		Mips_SRARI_H, MIPS_INS_SRARI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srari.w */
		Mips_SRARI_W, MIPS_INS_SRARI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srav */
		Mips_SravRxRy16, MIPS_INS_SRAV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* srav */
		Mips_SRAV, MIPS_INS_SRAV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* srav */
		Mips_SRAV_MM, MIPS_INS_SRAV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* srl */
		Mips_SRLV, MIPS_INS_SRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* srl */
		Mips_SRLV_MM, MIPS_INS_SRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* srl */
		Mips_SRL, MIPS_INS_SRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* srl */
		Mips_SRL_MM, MIPS_INS_SRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* srl */
		Mips_SRL_MM, MIPS_INS_SRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* srl */
		Mips_SrlX16, MIPS_INS_SRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* srl */
		Mips_SRLV, MIPS_INS_SRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* srl */
		Mips_SRLV_MM, MIPS_INS_SRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* srl */
		Mips_SRL, MIPS_INS_SRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* srl */
		Mips_SRL_MM, MIPS_INS_SRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* srl.b */
		Mips_SRL_B, MIPS_INS_SRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srl.d */
		Mips_SRL_D, MIPS_INS_SRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srl.h */
		Mips_SRL_H, MIPS_INS_SRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srl.w */
		Mips_SRL_W, MIPS_INS_SRL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srl16 */
		Mips_SRL16_MM, MIPS_INS_SRL16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* srl16 */
		Mips_SRL16_MMR6, MIPS_INS_SRL16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* srli.b */
		Mips_SRLI_B, MIPS_INS_SRLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srli.d */
		Mips_SRLI_D, MIPS_INS_SRLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srli.h */
		Mips_SRLI_H, MIPS_INS_SRLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srli.w */
		Mips_SRLI_W, MIPS_INS_SRLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srlr.b */
		Mips_SRLR_B, MIPS_INS_SRLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srlr.d */
		Mips_SRLR_D, MIPS_INS_SRLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srlr.h */
		Mips_SRLR_H, MIPS_INS_SRLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srlr.w */
		Mips_SRLR_W, MIPS_INS_SRLR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srlri.b */
		Mips_SRLRI_B, MIPS_INS_SRLRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srlri.d */
		Mips_SRLRI_D, MIPS_INS_SRLRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srlri.h */
		Mips_SRLRI_H, MIPS_INS_SRLRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srlri.w */
		Mips_SRLRI_W, MIPS_INS_SRLRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* srlv */
		Mips_SrlvRxRy16, MIPS_INS_SRLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* srlv */
		Mips_SRLV, MIPS_INS_SRLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* srlv */
		Mips_SRLV_MM, MIPS_INS_SRLV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ssnop */
		Mips_SSNOP, MIPS_INS_SSNOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* ssnop */
		Mips_SSNOP_MMR6, MIPS_INS_SSNOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* ssnop */
		Mips_SSNOP_MM, MIPS_INS_SSNOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* st.b */
		Mips_ST_B, MIPS_INS_ST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* st.d */
		Mips_ST_D, MIPS_INS_ST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* st.h */
		Mips_ST_H, MIPS_INS_ST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* st.w */
		Mips_ST_W, MIPS_INS_ST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* sub */
		Mips_SUB, MIPS_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sub */
		Mips_SUB_MM, MIPS_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sub */
		Mips_SUB_MMR6, MIPS_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sub */
		Mips_ADDi, MIPS_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* sub */
		Mips_SUB, MIPS_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sub */
		Mips_SUB_MM, MIPS_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sub */
		Mips_SUB_MMR6, MIPS_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sub */
		Mips_ADDi, MIPS_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, 0 }, 0, 0
#endif
	},
	{
 /* sub.d */
		Mips_FSUB_D32, MIPS_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sub.d */
		Mips_FSUB_D32_MM, MIPS_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* sub.d */
		Mips_FSUB_D64, MIPS_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sub.d */
		Mips_FSUB_D64_MM, MIPS_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* sub.ps */
		Mips_FSUB_PS64, MIPS_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sub.s */
		Mips_FSUB_S, MIPS_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sub.s */
		Mips_FSUB_S_MMR6, MIPS_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* sub.s */
		Mips_FSUB_S_MM, MIPS_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* subq.ph */
		Mips_SUBQ_PH_MM, MIPS_INS_SUBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* subq.ph */
		Mips_SUBQ_PH, MIPS_INS_SUBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* subq_s.ph */
		Mips_SUBQ_S_PH_MM, MIPS_INS_SUBQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* subq_s.ph */
		Mips_SUBQ_S_PH, MIPS_INS_SUBQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* subq_s.w */
		Mips_SUBQ_S_W_MM, MIPS_INS_SUBQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* subq_s.w */
		Mips_SUBQ_S_W, MIPS_INS_SUBQ_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* subqh.ph */
		Mips_SUBQH_PH_MMR2, MIPS_INS_SUBQH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* subqh.ph */
		Mips_SUBQH_PH, MIPS_INS_SUBQH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* subqh.w */
		Mips_SUBQH_W_MMR2, MIPS_INS_SUBQH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* subqh.w */
		Mips_SUBQH_W, MIPS_INS_SUBQH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* subqh_r.ph */
		Mips_SUBQH_R_PH_MMR2, MIPS_INS_SUBQH_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* subqh_r.ph */
		Mips_SUBQH_R_PH, MIPS_INS_SUBQH_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* subqh_r.w */
		Mips_SUBQH_R_W_MMR2, MIPS_INS_SUBQH_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* subqh_r.w */
		Mips_SUBQH_R_W, MIPS_INS_SUBQH_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* subs_s.b */
		Mips_SUBS_S_B, MIPS_INS_SUBS_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* subs_s.d */
		Mips_SUBS_S_D, MIPS_INS_SUBS_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* subs_s.h */
		Mips_SUBS_S_H, MIPS_INS_SUBS_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* subs_s.w */
		Mips_SUBS_S_W, MIPS_INS_SUBS_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* subs_u.b */
		Mips_SUBS_U_B, MIPS_INS_SUBS_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* subs_u.d */
		Mips_SUBS_U_D, MIPS_INS_SUBS_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* subs_u.h */
		Mips_SUBS_U_H, MIPS_INS_SUBS_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* subs_u.w */
		Mips_SUBS_U_W, MIPS_INS_SUBS_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* subsus_u.b */
		Mips_SUBSUS_U_B, MIPS_INS_SUBSUS_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* subsus_u.d */
		Mips_SUBSUS_U_D, MIPS_INS_SUBSUS_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* subsus_u.h */
		Mips_SUBSUS_U_H, MIPS_INS_SUBSUS_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* subsus_u.w */
		Mips_SUBSUS_U_W, MIPS_INS_SUBSUS_U,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* subsuu_s.b */
		Mips_SUBSUU_S_B, MIPS_INS_SUBSUU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* subsuu_s.d */
		Mips_SUBSUU_S_D, MIPS_INS_SUBSUU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* subsuu_s.h */
		Mips_SUBSUU_S_H, MIPS_INS_SUBSUU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* subsuu_s.w */
		Mips_SUBSUU_S_W, MIPS_INS_SUBSUU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* subu */
		Mips_SUBU_MMR6, MIPS_INS_SUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* subu */
		Mips_SUBu, MIPS_INS_SUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* subu */
		Mips_SUBu_MM, MIPS_INS_SUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* subu */
		Mips_ADDiu, MIPS_INS_SUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* subu */
		Mips_SubuRxRyRz16, MIPS_INS_SUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* subu */
		Mips_SUBU_MMR6, MIPS_INS_SUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* subu */
		Mips_SUBu, MIPS_INS_SUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* subu */
		Mips_SUBu_MM, MIPS_INS_SUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* subu */
		Mips_ADDiu, MIPS_INS_SUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* subu.ph */
		Mips_SUBU_PH_MMR2, MIPS_INS_SUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* subu.ph */
		Mips_SUBU_PH, MIPS_INS_SUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* subu.qb */
		Mips_SUBU_QB_MM, MIPS_INS_SUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* subu.qb */
		Mips_SUBU_QB, MIPS_INS_SUBU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* subu16 */
		Mips_SUBU16_MM, MIPS_INS_SUBU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* subu16 */
		Mips_SUBU16_MMR6, MIPS_INS_SUBU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* subu_s.ph */
		Mips_SUBU_S_PH_MMR2, MIPS_INS_SUBU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* subu_s.ph */
		Mips_SUBU_S_PH, MIPS_INS_SUBU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* subu_s.qb */
		Mips_SUBU_S_QB_MM, MIPS_INS_SUBU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* subu_s.qb */
		Mips_SUBU_S_QB, MIPS_INS_SUBU_S,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* subuh.qb */
		Mips_SUBUH_QB_MMR2, MIPS_INS_SUBUH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* subuh.qb */
		Mips_SUBUH_QB, MIPS_INS_SUBUH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* subuh_r.qb */
		Mips_SUBUH_R_QB_MMR2, MIPS_INS_SUBUH_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* subuh_r.qb */
		Mips_SUBUH_R_QB, MIPS_INS_SUBUH_R,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSPR2, 0 }, 0, 0
#endif
	},
	{
 /* subv.b */
		Mips_SUBV_B, MIPS_INS_SUBV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* subv.d */
		Mips_SUBV_D, MIPS_INS_SUBV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* subv.h */
		Mips_SUBV_H, MIPS_INS_SUBV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* subv.w */
		Mips_SUBV_W, MIPS_INS_SUBV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* subvi.b */
		Mips_SUBVI_B, MIPS_INS_SUBVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* subvi.d */
		Mips_SUBVI_D, MIPS_INS_SUBVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* subvi.h */
		Mips_SUBVI_H, MIPS_INS_SUBVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* subvi.w */
		Mips_SUBVI_W, MIPS_INS_SUBVI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* suxc1 */
		Mips_SUXC1, MIPS_INS_SUXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS5_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* suxc1 */
		Mips_SUXC164, MIPS_INS_SUXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS5_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* suxc1 */
		Mips_SUXC1_MM, MIPS_INS_SUXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_FP64BIT, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* sw */
		Mips_SWSP_MMR6, MIPS_INS_SW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sw */
		Mips_SWSP_MM, MIPS_INS_SW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sw */
		Mips_SW, MIPS_INS_SW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sw */
		Mips_SWDSP, MIPS_INS_SW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_NOTINMIPS16MODE, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* sw */
		Mips_SWDSP_MM, MIPS_INS_SW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* sw */
		Mips_SW_MMR6, MIPS_INS_SW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sw */
		Mips_SW_MM, MIPS_INS_SW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sw */
		Mips_SwRxRyOffMemX16, MIPS_INS_SW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* sw */
		Mips_SwRxSpImmX16, MIPS_INS_SW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* sw16 */
		Mips_SW16_MM, MIPS_INS_SW16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sw16 */
		Mips_SW16_MMR6, MIPS_INS_SW16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* swc1 */
		Mips_SWC1, MIPS_INS_SWC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* swc1 */
		Mips_SWC1_MM, MIPS_INS_SWC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* swc2 */
		Mips_SWC2_R6, MIPS_INS_SWC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* swc2 */
		Mips_SWC2_MMR6, MIPS_INS_SWC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* swc2 */
		Mips_SWC2, MIPS_INS_SWC2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* swc3 */
		Mips_SWC3, MIPS_INS_SWC3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTCNMIPS, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* swe */
		Mips_SWE, MIPS_INS_SWE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_EVA, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* swe */
		Mips_SWE_MM, MIPS_INS_SWE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_EVA, 0 }, 0, 0
#endif
	},
	{
 /* swl */
		Mips_SWL, MIPS_INS_SWL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* swl */
		Mips_SWL_MM, MIPS_INS_SWL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* swle */
		Mips_SWLE, MIPS_INS_SWLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_EVA, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* swle */
		Mips_SWLE_MM, MIPS_INS_SWLE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_EVA, 0 }, 0, 0
#endif
	},
	{
 /* swm */
		Mips_SWM_MM, MIPS_INS_SWM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* swm16 */
		Mips_SWM16_MM, MIPS_INS_SWM16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* swm16 */
		Mips_SWM16_MMR6, MIPS_INS_SWM16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* swm32 */
		Mips_SWM32_MM, MIPS_INS_SWM32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* swp */
		Mips_SWP_MM, MIPS_INS_SWP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* swr */
		Mips_SWR, MIPS_INS_SWR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* swr */
		Mips_SWR_MM, MIPS_INS_SWR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* swre */
		Mips_SWRE, MIPS_INS_SWRE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_EVA, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* swre */
		Mips_SWRE_MM, MIPS_INS_SWRE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_EVA, 0 }, 0, 0
#endif
	},
	{
 /* swsp */
		Mips_SWSP_MM, MIPS_INS_SWSP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* swxc1 */
		Mips_SWXC1, MIPS_INS_SWXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS4_32R2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* swxc1 */
		Mips_SWXC1_MM, MIPS_INS_SWXC1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* sync */
		Mips_SYNC, MIPS_INS_SYNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sync */
		Mips_SYNC_MMR6, MIPS_INS_SYNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sync */
		Mips_SYNC_MM, MIPS_INS_SYNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sync */
		Mips_SYNC, MIPS_INS_SYNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* sync */
		Mips_SYNC_MMR6, MIPS_INS_SYNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* sync */
		Mips_SYNC_MM, MIPS_INS_SYNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* synci */
		Mips_SYNCI, MIPS_INS_SYNCI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* synci */
		Mips_SYNCI_MM, MIPS_INS_SYNCI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* synci */
		Mips_SYNCI_MMR6, MIPS_INS_SYNCI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* synciobdma */
		Mips_SYNC, MIPS_INS_SYNCIOBDMA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS64, MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* syncs */
		Mips_SYNC, MIPS_INS_SYNCS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS64, MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* syncw */
		Mips_SYNC, MIPS_INS_SYNCW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS64, MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* syncws */
		Mips_SYNC, MIPS_INS_SYNCWS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS64, MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* syscall */
		Mips_SYSCALL, MIPS_INS_SYSCALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* syscall */
		Mips_SYSCALL_MM, MIPS_INS_SYSCALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* syscall */
		Mips_SYSCALL_MM, MIPS_INS_SYSCALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* syscall */
		Mips_SYSCALL, MIPS_INS_SYSCALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* teq */
		Mips_TEQ, MIPS_INS_TEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* teq */
		Mips_TEQ_MM, MIPS_INS_TEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* teq */
		Mips_TEQ_MM, MIPS_INS_TEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* teq */
		Mips_TEQ, MIPS_INS_TEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* teqi */
		Mips_TEQI, MIPS_INS_TEQI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* teqi */
		Mips_TEQI_MM, MIPS_INS_TEQI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* tge */
		Mips_TGE, MIPS_INS_TGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tge */
		Mips_TGE_MM, MIPS_INS_TGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tge */
		Mips_TGE_MM, MIPS_INS_TGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tge */
		Mips_TGE, MIPS_INS_TGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tgei */
		Mips_TGEI, MIPS_INS_TGEI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tgei */
		Mips_TGEI_MM, MIPS_INS_TGEI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* tgeiu */
		Mips_TGEIU, MIPS_INS_TGEIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tgeiu */
		Mips_TGEIU_MM, MIPS_INS_TGEIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* tgeu */
		Mips_TGEU, MIPS_INS_TGEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tgeu */
		Mips_TGEU_MM, MIPS_INS_TGEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tgeu */
		Mips_TGEU_MM, MIPS_INS_TGEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tgeu */
		Mips_TGEU, MIPS_INS_TGEU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tlbginv */
		Mips_TLBGINV, MIPS_INS_TLBGINV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tlbginv */
		Mips_TLBGINV_MM, MIPS_INS_TLBGINV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, 0 }, 0, 0
#endif
	},
	{
 /* tlbginvf */
		Mips_TLBGINVF, MIPS_INS_TLBGINVF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tlbginvf */
		Mips_TLBGINVF_MM, MIPS_INS_TLBGINVF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, 0 }, 0, 0
#endif
	},
	{
 /* tlbgp */
		Mips_TLBGP, MIPS_INS_TLBGP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tlbgp */
		Mips_TLBGP_MM, MIPS_INS_TLBGP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, 0 }, 0, 0
#endif
	},
	{
 /* tlbgr */
		Mips_TLBGR, MIPS_INS_TLBGR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tlbgr */
		Mips_TLBGR_MM, MIPS_INS_TLBGR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, 0 }, 0, 0
#endif
	},
	{
 /* tlbgwi */
		Mips_TLBGWI, MIPS_INS_TLBGWI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tlbgwi */
		Mips_TLBGWI_MM, MIPS_INS_TLBGWI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, 0 }, 0, 0
#endif
	},
	{
 /* tlbgwr */
		Mips_TLBGWR, MIPS_INS_TLBGWR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tlbgwr */
		Mips_TLBGWR_MM, MIPS_INS_TLBGWR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R5, MIPS_GRP_VIRT, 0 }, 0, 0
#endif
	},
	{
 /* tlbinv */
		Mips_TLBINV, MIPS_INS_TLBINV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_EVA, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tlbinv */
		Mips_TLBINV_MMR6, MIPS_INS_TLBINV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* tlbinvf */
		Mips_TLBINVF, MIPS_INS_TLBINVF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_EVA, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tlbinvf */
		Mips_TLBINVF_MMR6, MIPS_INS_TLBINVF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* tlbp */
		Mips_TLBP, MIPS_INS_TLBP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tlbp */
		Mips_TLBP_MM, MIPS_INS_TLBP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tlbr */
		Mips_TLBR, MIPS_INS_TLBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tlbr */
		Mips_TLBR_MM, MIPS_INS_TLBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tlbwi */
		Mips_TLBWI, MIPS_INS_TLBWI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tlbwi */
		Mips_TLBWI_MM, MIPS_INS_TLBWI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tlbwr */
		Mips_TLBWR, MIPS_INS_TLBWR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tlbwr */
		Mips_TLBWR_MM, MIPS_INS_TLBWR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tlt */
		Mips_TLT, MIPS_INS_TLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tlt */
		Mips_TLT_MM, MIPS_INS_TLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tlt */
		Mips_TLT_MM, MIPS_INS_TLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tlt */
		Mips_TLT, MIPS_INS_TLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tlti */
		Mips_TLTI, MIPS_INS_TLTI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tlti */
		Mips_TLTI_MM, MIPS_INS_TLTI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* tltiu */
		Mips_TTLTIU, MIPS_INS_TLTIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tltiu */
		Mips_TLTIU_MM, MIPS_INS_TLTIU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* tltu */
		Mips_TLTU, MIPS_INS_TLTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tltu */
		Mips_TLTU_MM, MIPS_INS_TLTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tltu */
		Mips_TLTU_MM, MIPS_INS_TLTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tltu */
		Mips_TLTU, MIPS_INS_TLTU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tne */
		Mips_TNE, MIPS_INS_TNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tne */
		Mips_TNE_MM, MIPS_INS_TNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tne */
		Mips_TNE_MM, MIPS_INS_TNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tne */
		Mips_TNE, MIPS_INS_TNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tnei */
		Mips_TNEI, MIPS_INS_TNEI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTMIPS32R6, MIPS_GRP_NOTMIPS64R6, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* tnei */
		Mips_TNEI_MM, MIPS_INS_TNEI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* trunc.l.d */
		Mips_TRUNC_L_D64, MIPS_INS_TRUNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS3_32, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* trunc.l.d */
		Mips_TRUNC_L_D_MMR6, MIPS_INS_TRUNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* trunc.l.s */
		Mips_TRUNC_L_S, MIPS_INS_TRUNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* trunc.l.s */
		Mips_TRUNC_L_S_MMR6, MIPS_INS_TRUNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* trunc.w.d */
		Mips_TRUNC_W_D32, MIPS_INS_TRUNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTFP64BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* trunc.w.d */
		Mips_TRUNC_W_MM, MIPS_INS_TRUNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* trunc.w.d */
		Mips_TRUNC_W_D64, MIPS_INS_TRUNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_FP64BIT, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* trunc.w.d */
		Mips_TRUNC_W_D_MMR6, MIPS_INS_TRUNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* trunc.w.d */
		Mips_PseudoTRUNC_W_D32, MIPS_INS_TRUNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_NOTFP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* trunc.w.d */
		Mips_PseudoTRUNC_W_D, MIPS_INS_TRUNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_FP64BIT, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* trunc.w.s */
		Mips_TRUNC_W_S, MIPS_INS_TRUNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS2, MIPS_GRP_NOTSOFTFLOAT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* trunc.w.s */
		Mips_TRUNC_W_S_MMR6, MIPS_INS_TRUNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* trunc.w.s */
		Mips_TRUNC_W_S_MM, MIPS_INS_TRUNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTSOFTFLOAT, 0 }, 0, 0
#endif
	},
	{
 /* trunc.w.s */
		Mips_PseudoTRUNC_W_S, MIPS_INS_TRUNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* ulh */
		Mips_Ulh, MIPS_INS_ULH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* ulhu */
		Mips_Ulhu, MIPS_INS_ULHU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* ulw */
		Mips_Ulw, MIPS_INS_ULW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* ush */
		Mips_Ush, MIPS_INS_USH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* usw */
		Mips_Usw, MIPS_INS_USW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ 0 }, 0, 0
#endif
	},
	{
 /* v3mulu */
		Mips_V3MULU, MIPS_INS_V3MULU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* v3mulu */
		Mips_V3MULU, MIPS_INS_V3MULU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* vmm0 */
		Mips_VMM0, MIPS_INS_VMM0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* vmm0 */
		Mips_VMM0, MIPS_INS_VMM0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* vmulu */
		Mips_VMULU, MIPS_INS_VMULU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* vmulu */
		Mips_VMULU, MIPS_INS_VMULU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_CNMIPS, 0 }, 0, 0
#endif
	},
	{
 /* vshf.b */
		Mips_VSHF_B, MIPS_INS_VSHF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* vshf.d */
		Mips_VSHF_D, MIPS_INS_VSHF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* vshf.h */
		Mips_VSHF_H, MIPS_INS_VSHF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* vshf.w */
		Mips_VSHF_W, MIPS_INS_VSHF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* wait */
		Mips_WAIT, MIPS_INS_WAIT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS3_32, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* wait */
		Mips_WAIT_MM, MIPS_INS_WAIT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* wait */
		Mips_WAIT_MMR6, MIPS_INS_WAIT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* wait */
		Mips_WAIT_MM, MIPS_INS_WAIT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* wrdsp */
		Mips_WRDSP, MIPS_INS_WRDSP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* wrdsp */
		Mips_WRDSP_MM, MIPS_INS_WRDSP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* wrdsp */
		Mips_WRDSP_MM, MIPS_INS_WRDSP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_DSP, 0 }, 0, 0
#endif
	},
	{
 /* wrdsp */
		Mips_WRDSP, MIPS_INS_WRDSP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_DSP, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* wrpgpr */
		Mips_WRPGPR_MMR6, MIPS_INS_WRPGPR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* wsbh */
		Mips_WSBH, MIPS_INS_WSBH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MIPS32R2, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* wsbh */
		Mips_WSBH_MMR6, MIPS_INS_WSBH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* wsbh */
		Mips_WSBH_MM, MIPS_INS_WSBH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* xor */
		Mips_XorRxRxRy16, MIPS_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MIPS16MODE, 0 }, 0, 0
#endif
	},
	{
 /* xor */
		Mips_XOR, MIPS_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* xor */
		Mips_XOR_MM, MIPS_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* xor */
		Mips_XOR_MMR6, MIPS_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* xor */
		Mips_XORI_MMR6, MIPS_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* xor */
		Mips_XORi, MIPS_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP32BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* xor */
		Mips_XORi_MM, MIPS_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* xor */
		Mips_XORi64, MIPS_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* xor */
		Mips_XOR, MIPS_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* xor */
		Mips_XOR_MM, MIPS_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* xor */
		Mips_XOR_MMR6, MIPS_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* xor */
		Mips_XORI_MMR6, MIPS_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* xor */
		Mips_XORi, MIPS_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP32BIT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* xor */
		Mips_XORi_MM, MIPS_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* xor */
		Mips_XORi64, MIPS_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_GP64BIT, MIPS_GRP_MIPS3, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* xor.v */
		Mips_XOR_V, MIPS_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* xor16 */
		Mips_XOR16_MM, MIPS_INS_XOR16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* xor16 */
		Mips_XOR16_MMR6, MIPS_INS_XOR16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* xori */
		Mips_XORI_MMR6, MIPS_INS_XORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* xori */
		Mips_XORi, MIPS_INS_XORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* xori */
		Mips_XORi_MM, MIPS_INS_XORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* xori */
		Mips_XORI_MMR6, MIPS_INS_XORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_MIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* xori */
		Mips_XORi, MIPS_INS_XORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* xori */
		Mips_XORi_MM, MIPS_INS_XORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MICROMIPS, MIPS_GRP_NOTMIPS32R6, 0 }, 0, 0
#endif
	},
	{
 /* xori.b */
		Mips_XORI_B, MIPS_INS_XORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MSA, 0 }, 0, 0
#endif
	},
	{
 /* yield */
		Mips_YIELD, MIPS_INS_YIELD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_MT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
	{
 /* yield */
		Mips_YIELD, MIPS_INS_YIELD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 },{ MIPS_GRP_STDENC, MIPS_GRP_MT, MIPS_GRP_NOTINMICROMIPS, 0 }, 0, 0
#endif
	},
};



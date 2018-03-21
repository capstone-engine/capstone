
#ifdef CAPSTONE_HAS_RISCV

#include <stdio.h>	// debug
#include <string.h>

#include "../../utils.h"

#include "RISCVMapping.h"

#define GET_INSTRINFO_ENUM
#include "RISCVGenInstrInfo.inc"

#ifndef CAPSTONE_DIET
static const name_map reg_name_maps[] = {
	{ RISCV_REG_INVALID, NULL },

	{ RISCV_REG_X0, "zero"},
	{ RISCV_REG_X1, "ra"},
	{ RISCV_REG_X2, "sp"},
	{ RISCV_REG_X3, "gp"},
	{ RISCV_REG_X4, "tp"},
	{ RISCV_REG_X5, "t0"},
	{ RISCV_REG_X6, "t1"},
	{ RISCV_REG_X7, "t2"},
	{ RISCV_REG_X8, "s0"},
	{ RISCV_REG_X9, "s1"},
	{ RISCV_REG_X10, "a0"},
	{ RISCV_REG_X11, "a1"},
	{ RISCV_REG_X12, "a2"},
	{ RISCV_REG_X13, "a3"},
	{ RISCV_REG_X14, "a4"},
	{ RISCV_REG_X15, "a5"},
	{ RISCV_REG_X16, "a6"},
	{ RISCV_REG_X17, "a7"},
	{ RISCV_REG_X18, "s2"},
	{ RISCV_REG_X19, "s3"},
	{ RISCV_REG_X20, "s4"},
	{ RISCV_REG_X21, "s5"},
	{ RISCV_REG_X22, "s6"},
	{ RISCV_REG_X23, "s7"},
	{ RISCV_REG_X24, "s8"},
	{ RISCV_REG_X25, "s9"},
	{ RISCV_REG_X26, "s10"},
	{ RISCV_REG_X27, "s11"},
	{ RISCV_REG_X28, "t3"},
	{ RISCV_REG_X29, "t4"},
	{ RISCV_REG_X30, "t5"},
	{ RISCV_REG_X31, "t6"},

	{ RISCV_REG_F0_32, "ft0"},
	{ RISCV_REG_F1_32, "ft1"},
	{ RISCV_REG_F2_32, "ft2"},
	{ RISCV_REG_F3_32, "ft3"},
	{ RISCV_REG_F4_32, "ft4"},
	{ RISCV_REG_F5_32, "ft5"},
	{ RISCV_REG_F6_32, "ft6"},
	{ RISCV_REG_F7_32, "ft7"},
	{ RISCV_REG_F8_32, "fs0"},
	{ RISCV_REG_F9_32, "fs1"},
	{ RISCV_REG_F10_32, "fa0"},
	{ RISCV_REG_F11_32, "fa1"},
	{ RISCV_REG_F12_32, "fa2"},
	{ RISCV_REG_F13_32, "fa3"},
	{ RISCV_REG_F14_32, "fa4"},
	{ RISCV_REG_F15_32, "fa5"},
	{ RISCV_REG_F16_32, "fa6"},
	{ RISCV_REG_F17_32, "fa7"},
	{ RISCV_REG_F18_32, "fs2"},
	{ RISCV_REG_F19_32, "fs3"}, 
	{ RISCV_REG_F20_32, "fs4"},
	{ RISCV_REG_F21_32, "fs5"},
	{ RISCV_REG_F22_32, "fs6"},
	{ RISCV_REG_F23_32, "fs7"},
	{ RISCV_REG_F24_32, "fs8"},
	{ RISCV_REG_F25_32, "fs9"},
	{ RISCV_REG_F26_32, "fs10"},
	{ RISCV_REG_F27_32, "fs11"},
	{ RISCV_REG_F28_32, "ft8"},
	{ RISCV_REG_F29_32, "ft9"},
	{ RISCV_REG_F30_32, "ft10"},
	{ RISCV_REG_F31_32, "ft11"},

	{ RISCV_REG_F0_64, "ft0"},
	{ RISCV_REG_F1_64, "ft1"},
	{ RISCV_REG_F2_64, "ft2"},
	{ RISCV_REG_F3_64, "ft3"},
	{ RISCV_REG_F4_64, "ft4"},
	{ RISCV_REG_F5_64, "ft5"},
	{ RISCV_REG_F6_64, "ft6"},
	{ RISCV_REG_F7_64, "ft7"},
	{ RISCV_REG_F8_64, "fs0"},
	{ RISCV_REG_F9_64, "fs1"},
	{ RISCV_REG_F10_64, "fa0"}, 
	{ RISCV_REG_F11_64, "fa1"}, 
	{ RISCV_REG_F12_64, "fa2"}, 
	{ RISCV_REG_F13_64, "fa3"}, 
	{ RISCV_REG_F14_64, "fa4"}, 
	{ RISCV_REG_F15_64, "fa5"}, 
	{ RISCV_REG_F16_64, "fa6"}, 
	{ RISCV_REG_F17_64, "fa7"}, 
	{ RISCV_REG_F18_64, "fs2"}, 
	{ RISCV_REG_F19_64, "fs3"},  
	{ RISCV_REG_F20_64, "fs4"},
	{ RISCV_REG_F21_64, "fs5"},
	{ RISCV_REG_F22_64, "fs6"},
	{ RISCV_REG_F23_64, "fs7"},
	{ RISCV_REG_F24_64, "fs8"},
	{ RISCV_REG_F25_64, "fs9"},
	{ RISCV_REG_F26_64, "fs10"},
	{ RISCV_REG_F27_64, "fs11"},
	{ RISCV_REG_F28_64, "ft8"},
	{ RISCV_REG_F29_64, "ft9"},
	{ RISCV_REG_F30_64, "ft10"},
	{ RISCV_REG_F31_64, "ft11"},
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
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},

	{
		RISCV_ADD, RISCV_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_ADDI, RISCV_INS_ADDI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
        RISCV_ADDIW, RISCV_INS_ADDIW,              
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64I, 0 }, 0, 0
#endif
	},
	{
		RISCV_ADDW, RISCV_INS_ADDW,           
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64I, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOADD_D, RISCV_INS_AMOADD_D,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOADD_D_AQ, RISCV_INS_AMOADD_D_AQ,    
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOADD_D_AQ_RL, RISCV_INS_AMOADD_D_AQ_RL, 
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOADD_D_RL, RISCV_INS_AMOADD_D_RL,    
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOADD_W, RISCV_INS_AMOADD_W,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOADD_W_AQ, RISCV_INS_AMOADD_W_AQ,    
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOADD_W_AQ_RL, RISCV_INS_AMOADD_W_AQ_RL, 
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOADD_W_RL, RISCV_INS_AMOADD_W_RL,    
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOAND_D, RISCV_INS_AMOAND_D,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOAND_D_AQ, RISCV_INS_AMOAND_D_AQ,    
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOAND_D_AQ_RL, RISCV_INS_AMOAND_D_AQ_RL, 
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOAND_D_RL, RISCV_INS_AMOAND_D_RL,    
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOAND_W, RISCV_INS_AMOAND_W,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOAND_W_AQ, RISCV_INS_AMOAND_W_AQ,    
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOAND_W_AQ_RL, RISCV_INS_AMOAND_W_AQ_RL, 
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOAND_W_RL, RISCV_INS_AMOAND_W_RL,    
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMAXU_D, RISCV_INS_AMOMAXU_D,      
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMAXU_D_AQ, RISCV_INS_AMOMAXU_D_AQ,   
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMAXU_D_AQ_RL, RISCV_INS_AMOMAXU_D_AQ_RL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMAXU_D_RL, RISCV_INS_AMOMAXU_D_RL,   
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMAXU_W, RISCV_INS_AMOMAXU_W,      
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMAXU_W_AQ, RISCV_INS_AMOMAXU_W_AQ,   
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMAXU_W_AQ_RL, RISCV_INS_AMOMAXU_W_AQ_RL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMAXU_W_RL, RISCV_INS_AMOMAXU_W_RL,   
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMAX_D, RISCV_INS_AMOMAX_D,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMAX_D_AQ, RISCV_INS_AMOMAX_D_AQ,    
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMAX_D_AQ_RL, RISCV_INS_AMOMAX_D_AQ_RL, 
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMAX_D_RL, RISCV_INS_AMOMAX_D_RL,    
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMAX_W, RISCV_INS_AMOMAX_W,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMAX_W_AQ, RISCV_INS_AMOMAX_W_AQ,    
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMAX_W_AQ_RL, RISCV_INS_AMOMAX_W_AQ_RL, 
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMAX_W_RL, RISCV_INS_AMOMAX_W_RL,    
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMINU_D, RISCV_INS_AMOMINU_D,      
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMINU_D_AQ, RISCV_INS_AMOMINU_D_AQ,   
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMINU_D_AQ_RL, RISCV_INS_AMOMINU_D_AQ_RL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMINU_D_RL, RISCV_INS_AMOMINU_D_RL,   
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMINU_W, RISCV_INS_AMOMINU_W,      
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMINU_W_AQ, RISCV_INS_AMOMINU_W_AQ,   
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMINU_W_AQ_RL, RISCV_INS_AMOMINU_W_AQ_RL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMINU_W_RL, RISCV_INS_AMOMINU_W_RL,   
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMIN_D, RISCV_INS_AMOMIN_D,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMIN_D_AQ, RISCV_INS_AMOMIN_D_AQ,    
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMIN_D_AQ_RL, RISCV_INS_AMOMIN_D_AQ_RL, 
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMIN_D_RL, RISCV_INS_AMOMIN_D_RL,    
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMIN_W, RISCV_INS_AMOMIN_W,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMIN_W_AQ, RISCV_INS_AMOMIN_W_AQ,    
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMIN_W_AQ_RL, RISCV_INS_AMOMIN_W_AQ_RL, 
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOMIN_W_RL, RISCV_INS_AMOMIN_W_RL,    
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOOR_D, RISCV_INS_AMOOR_D,        
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOOR_D_AQ, RISCV_INS_AMOOR_D_AQ,     
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOOR_D_AQ_RL, RISCV_INS_AMOOR_D_AQ_RL,  
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOOR_D_RL, RISCV_INS_AMOOR_D_RL,     
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOOR_W, RISCV_INS_AMOOR_W,        
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOOR_W_AQ, RISCV_INS_AMOOR_W_AQ,     
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOOR_W_AQ_RL, RISCV_INS_AMOOR_W_AQ_RL,  
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOOR_W_RL, RISCV_INS_AMOOR_W_RL,     
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOSWAP_D, RISCV_INS_AMOSWAP_D,      
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOSWAP_D_AQ, RISCV_INS_AMOSWAP_D_AQ,   
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOSWAP_D_AQ_RL, RISCV_INS_AMOSWAP_D_AQ_RL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOSWAP_D_RL, RISCV_INS_AMOSWAP_D_RL,   
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOSWAP_W, RISCV_INS_AMOSWAP_W,      
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOSWAP_W_AQ, RISCV_INS_AMOSWAP_W_AQ,   
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOSWAP_W_AQ_RL, RISCV_INS_AMOSWAP_W_AQ_RL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOSWAP_W_RL, RISCV_INS_AMOSWAP_W_RL,   
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOXOR_D, RISCV_INS_AMOXOR_D,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOXOR_D_AQ, RISCV_INS_AMOXOR_D_AQ,    
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOXOR_D_AQ_RL, RISCV_INS_AMOXOR_D_AQ_RL, 
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOXOR_D_RL, RISCV_INS_AMOXOR_D_RL,    
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOXOR_W, RISCV_INS_AMOXOR_W,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOXOR_W_AQ, RISCV_INS_AMOXOR_W_AQ,    
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOXOR_W_AQ_RL, RISCV_INS_AMOXOR_W_AQ_RL, 
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AMOXOR_W_RL, RISCV_INS_AMOXOR_W_RL,    
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_AND, RISCV_INS_AND,            
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_ANDI, RISCV_INS_ANDI,           
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_AUIPC, RISCV_INS_AUIPC,          
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_BEQ, RISCV_INS_BEQ,            
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 1, 0
#endif
	},
	{
		RISCV_BGE, RISCV_INS_BGE,            
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 1, 0
#endif
	},
	{
		RISCV_BGEU, RISCV_INS_BGEU,           
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 1, 0
#endif
	},
	{
		RISCV_BLT, RISCV_INS_BLT,            
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 1, 0
#endif
	},
	{
		RISCV_BLTU, RISCV_INS_BLTU,           
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 1, 0
#endif
	},
	{
		RISCV_BNE, RISCV_INS_BNE,            
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 1, 0
#endif
	},
	{
		RISCV_CSRRC, RISCV_INS_CSRRC,          
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_CSRRCI, RISCV_INS_CSRRCI,         
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_CSRRS, RISCV_INS_CSRRS,          
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_CSRRSI, RISCV_INS_CSRRSI,         
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_CSRRW, RISCV_INS_CSRRW,          
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_CSRRWI, RISCV_INS_CSRRWI,         
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_DIV, RISCV_INS_DIV,            
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32M, 0 }, 0, 0
#endif
	},
	{
		RISCV_DIVU, RISCV_INS_DIVU,           
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32M, 0 }, 0, 0
#endif
	},
	{
		RISCV_DIVUW, RISCV_INS_DIVUW,          
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64M, 0 }, 0, 0
#endif
	},
	{
		RISCV_DIVW, RISCV_INS_DIVW,           
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64M, 0 }, 0, 0
#endif
	},
	{
		RISCV_EBREAK, RISCV_INS_EBREAK,         
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_ECALL, RISCV_INS_ECALL,          
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_FADD_D, RISCV_INS_FADD_D,         
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FADD_S, RISCV_INS_FADD_S,         
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FCLASS_D, RISCV_INS_FCLASS_D,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FCLASS_S, RISCV_INS_FCLASS_S,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FCVT_D_L, RISCV_INS_FCVT_D_L,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FCVT_D_LU, RISCV_INS_FCVT_D_LU,      
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FCVT_D_S, RISCV_INS_FCVT_D_S,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FCVT_D_W, RISCV_INS_FCVT_D_W,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FCVT_D_WU, RISCV_INS_FCVT_D_WU,      
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FCVT_LU_D, RISCV_INS_FCVT_LU_D,      
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FCVT_LU_S, RISCV_INS_FCVT_LU_S,      
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FCVT_L_D, RISCV_INS_FCVT_L_D,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FCVT_L_S, RISCV_INS_FCVT_L_S,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FCVT_S_D, RISCV_INS_FCVT_S_D,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FCVT_S_L, RISCV_INS_FCVT_S_L,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FCVT_S_LU, RISCV_INS_FCVT_S_LU,      
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FCVT_S_W, RISCV_INS_FCVT_S_W,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FCVT_S_WU, RISCV_INS_FCVT_S_WU,      
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FCVT_WU_D, RISCV_INS_FCVT_WU_D,      
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FCVT_WU_S, RISCV_INS_FCVT_WU_S,      
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FCVT_W_D, RISCV_INS_FCVT_W_D,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FCVT_W_S, RISCV_INS_FCVT_W_S,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FDIV_D, RISCV_INS_FDIV_D,         
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FDIV_S, RISCV_INS_FDIV_S,         
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FENCE, RISCV_INS_FENCE,          
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_FENCE_I, RISCV_INS_FENCE_I,        
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_FEQ_D, RISCV_INS_FEQ_D,          
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_FEQ_S, RISCV_INS_FEQ_S,          
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FLD, RISCV_INS_FLD,            
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FLE_D, RISCV_INS_FLE_D,          
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FLE_S, RISCV_INS_FLE_S,          
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FLT_D, RISCV_INS_FLT_D,          
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FLT_S, RISCV_INS_FLT_S,          
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FLW, RISCV_INS_FLW,            
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FMADD_D, RISCV_INS_FMADD_D,        
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FMADD_S, RISCV_INS_FMADD_S,        
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FMAX_D, RISCV_INS_FMAX_D,         
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FMAX_S, RISCV_INS_FMAX_S,         
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FMIN_D, RISCV_INS_FMIN_D,         
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FMIN_S, RISCV_INS_FMIN_S,         
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FMSUB_D, RISCV_INS_FMSUB_D,        
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FMSUB_S, RISCV_INS_FMSUB_S,        
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FMUL_D, RISCV_INS_FMUL_D,         
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FMUL_S, RISCV_INS_FMUL_S,         
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FMV_D_X, RISCV_INS_FMV_D_X,        
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FMV_W_X, RISCV_INS_FMV_W_X,        
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FMV_X_D, RISCV_INS_FMV_X_D,        
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FMV_X_W, RISCV_INS_FMV_X_W,        
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FNMADD_D, RISCV_INS_FNMADD_D,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FNMADD_S, RISCV_INS_FNMADD_S,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FNMSUB_D, RISCV_INS_FNMSUB_D,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FNMSUB_S, RISCV_INS_FNMSUB_S,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FSD, RISCV_INS_FSD,            
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FSGNJN_D, RISCV_INS_FSGNJN_D,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FSGNJN_S, RISCV_INS_FSGNJN_S,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FSGNJX_D, RISCV_INS_FSGNJX_D,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FSGNJX_S, RISCV_INS_FSGNJX_S,       
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FSGNJ_D, RISCV_INS_FSGNJ_D,        
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FSGNJ_S, RISCV_INS_FSGNJ_S,        
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FSQRT_D, RISCV_INS_FSQRT_D,        
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FSQRT_S, RISCV_INS_FSQRT_S,        
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FSUB_D, RISCV_INS_FSUB_D,         
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32D, 0 }, 0, 0
#endif
	},
	{
		RISCV_FSUB_S, RISCV_INS_FSUB_S,         
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_FSW, RISCV_INS_FSW,            
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32F, 0 }, 0, 0
#endif
	},
	{
		RISCV_JAL, RISCV_INS_JAL,            
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 1, 0
#endif
	},
	{
		RISCV_JALR, RISCV_INS_JALR,           
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 1, 0
#endif
	},
	{
		RISCV_LB, RISCV_INS_LB,             
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_LBU, RISCV_INS_LBU,            
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_LD, RISCV_INS_LD,             
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_LH, RISCV_INS_LH,             
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_LHU, RISCV_INS_LHU,            
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_LR_D, RISCV_INS_LR_D,           
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_LR_D_AQ, RISCV_INS_LR_D_AQ,        
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_LR_D_AQ_RL, RISCV_INS_LR_D_AQ_RL,     
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_LR_D_RL, RISCV_INS_LR_D_RL,        
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_LR_W, RISCV_INS_LR_W,           
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_LR_W_AQ, RISCV_INS_LR_W_AQ,        
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_LR_W_AQ_RL, RISCV_INS_LR_W_AQ_RL,     
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_LR_W_RL, RISCV_INS_LR_W_RL,        
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_LUI, RISCV_INS_LUI,            
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_LW, RISCV_INS_LW,             
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_LWU, RISCV_INS_LWU,            
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_MUL, RISCV_INS_MUL,            
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32M, 0 }, 0, 0
#endif
	},
	{
		RISCV_MULH, RISCV_INS_MULH,           
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32M, 0 }, 0, 0
#endif
	},
	{
		RISCV_MULHSU, RISCV_INS_MULHSU,         
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32M, 0 }, 0, 0
#endif
	},
	{
		RISCV_MULHU, RISCV_INS_MULHU,          
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32M, 0 }, 0, 0
#endif
	},
	{
		RISCV_MULW, RISCV_INS_MULW,           
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64M, 0 }, 0, 0
#endif
	},
	{
		RISCV_OR, RISCV_INS_OR,             
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_ORI, RISCV_INS_ORI,            
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_REM, RISCV_INS_REM,            
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32M, 0 }, 0, 0
#endif
	},
	{
		RISCV_REMU, RISCV_INS_REMU,           
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32M, 0 }, 0, 0
#endif
	},
	{
		RISCV_REMUW, RISCV_INS_REMUW,          
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64M, 0 }, 0, 0
#endif
	},
	{
		RISCV_REMW, RISCV_INS_REMW,           
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64M, 0 }, 0, 0
#endif
	},
	{
		RISCV_SB, RISCV_INS_SB,             
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_SC_D, RISCV_INS_SC_D,           
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_SC_D_AQ, RISCV_INS_SC_D_AQ,        
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_SC_D_AQ_RL, RISCV_INS_SC_D_AQ_RL,     
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_SC_D_RL, RISCV_INS_SC_D_RL,        
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64A, 0 }, 0, 0
#endif
	},
	{
		RISCV_SC_W, RISCV_INS_SC_W,           
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_SC_W_AQ, RISCV_INS_SC_W_AQ,        
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_SC_W_AQ_RL, RISCV_INS_SC_W_AQ_RL,     
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_SC_W_RL, RISCV_INS_SC_W_RL,        
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32A, 0 }, 0, 0
#endif
	},
	{
		RISCV_SD, RISCV_INS_SD,             
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64I, 0 }, 0, 0
#endif
	},
	{
		RISCV_SH, RISCV_INS_SH,             
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_SLL, RISCV_INS_SLL,            
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_SLLI, RISCV_INS_SLLI,           
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_SLLIW, RISCV_INS_SLLIW,          
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64I, 0 }, 0, 0
#endif
	},
	{
		RISCV_SLLW, RISCV_INS_SLLW,           
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64I, 0 }, 0, 0
#endif
	},
	{
		RISCV_SLT, RISCV_INS_SLT,            
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_SLTI, RISCV_INS_SLTI,           
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_SLTIU, RISCV_INS_SLTIU,          
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_SLTU, RISCV_INS_SLTU,           
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_SRA, RISCV_INS_SRA,            
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_SRAI, RISCV_INS_SRAI,           
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_SRAIW, RISCV_INS_SRAIW,          
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64I, 0 }, 0, 0
#endif
	},
	{
		RISCV_SRAW, RISCV_INS_SRAW,           
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64I, 0 }, 0, 0
#endif
	},
	{
		RISCV_SRL, RISCV_INS_SRL,            
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_SRLI, RISCV_INS_SRLI,           
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_SRLIW, RISCV_INS_SRLIW,          
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64I, 0 }, 0, 0
#endif
	},
	{
		RISCV_SRLW, RISCV_INS_SRLW,           
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64I, 0 }, 0, 0
#endif
	},
	{
		RISCV_SUB, RISCV_INS_SUB,            
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_SUBW, RISCV_INS_SUBW,           
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV64I, 0 }, 0, 0
#endif
	},
	{
		RISCV_SW, RISCV_INS_SW,             
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_XOR, RISCV_INS_XOR,            
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	{
		RISCV_XORI, RISCV_INS_XORI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { RISCV_GRP_RV32I, 0 }, 0, 0
#endif
	},
	
};

// given internal insn id, return public instruction info
void RISCV_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	unsigned int i;

	i = insn_find(insns, ARR_SIZE(insns), id, &h->insn_cache);
	if (i != 0) {
		insn->id = insns[i].mapid;

		if (h->detail) {
#ifndef CAPSTONE_DIET
			memcpy(insn->detail->regs_read, insns[i].regs_use, sizeof(insns[i].regs_use));
			insn->detail->regs_read_count = (uint8_t)count_positive(insns[i].regs_use);

			memcpy(insn->detail->regs_write, insns[i].regs_mod, sizeof(insns[i].regs_mod));
			insn->detail->regs_write_count = (uint8_t)count_positive(insns[i].regs_mod);

			memcpy(insn->detail->groups, insns[i].groups, sizeof(insns[i].groups));
			insn->detail->groups_count = (uint8_t)count_positive(insns[i].groups);

			if (insns[i].branch || insns[i].indirect_branch) {
				// this insn also belongs to JUMP group. add JUMP group
				insn->detail->groups[insn->detail->groups_count] = RISCV_GRP_JUMP;
				insn->detail->groups_count++;
			}
#endif
		}
	}
}

static const name_map insn_name_maps[] = {
	{ RISCV_INS_INVALID, NULL },

	{ RISCV_INS_ADD, "add" },
	{ RISCV_INS_ADDI, "addi" },
	{ RISCV_INS_ADDIW, "addiw" },
	{ RISCV_INS_ADDW, "addw" },
	{ RISCV_INS_AMOADD_D, "amoadd.d" },
	{ RISCV_INS_AMOADD_D_AQ, "amoadd.d.aq" },
	{ RISCV_INS_AMOADD_D_AQ_RL, "amoadd.d.aq.rl" },
	{ RISCV_INS_AMOADD_D_RL, "amoadd.d.rl" },
	{ RISCV_INS_AMOADD_W, "amoadd.w" },
	{ RISCV_INS_AMOADD_W_AQ, "amoadd.w.aq" },
	{ RISCV_INS_AMOADD_W_AQ_RL, "amoadd.w.aq.rl" },
	{ RISCV_INS_AMOADD_W_RL, "amoadd.w.rl" },
	{ RISCV_INS_AMOAND_D, "amoand.d" },
	{ RISCV_INS_AMOAND_D_AQ, "amoand.d.aq" },
	{ RISCV_INS_AMOAND_D_AQ_RL, "amoand.d.aq.rl" },
	{ RISCV_INS_AMOAND_D_RL, "amoand.d.rl" },
	{ RISCV_INS_AMOAND_W, "amoand.w" },
	{ RISCV_INS_AMOAND_W_AQ, "amoand.w.aq" },
	{ RISCV_INS_AMOAND_W_AQ_RL, "amoand.w.aq.rl" },
	{ RISCV_INS_AMOAND_W_RL, "amoand.w.rl" },
	{ RISCV_INS_AMOMAXU_D, "amomaxu.d" },
	{ RISCV_INS_AMOMAXU_D_AQ, "amomaxu.d.aq" },
	{ RISCV_INS_AMOMAXU_D_AQ_RL, "amomaxu.d.aq.rl" },
	{ RISCV_INS_AMOMAXU_D_RL, "amomaxu.d.rl" },
	{ RISCV_INS_AMOMAXU_W, "amomaxu.w" },
	{ RISCV_INS_AMOMAXU_W_AQ, "amomaxu.w.aq" },
	{ RISCV_INS_AMOMAXU_W_AQ_RL, "amomaxu.w.aq.rl" },
	{ RISCV_INS_AMOMAXU_W_RL, "amomaxu.w.rl" },
	{ RISCV_INS_AMOMAX_D, "amomax.d" },
	{ RISCV_INS_AMOMAX_D_AQ, "amomax.d.aq" },
	{ RISCV_INS_AMOMAX_D_AQ_RL, "amomax.d.aq.rl" },
	{ RISCV_INS_AMOMAX_D_RL, "amomax.d.rl" },
	{ RISCV_INS_AMOMAX_W, "amomax.w" },
	{ RISCV_INS_AMOMAX_W_AQ, "amomax.w.aq" },
	{ RISCV_INS_AMOMAX_W_AQ_RL, "amomax.w.aq.rl" },
	{ RISCV_INS_AMOMAX_W_RL, "amomax.w.rl" },
	{ RISCV_INS_AMOMINU_D, "amominu.d" },
	{ RISCV_INS_AMOMINU_D_AQ, "amominu.d.aq" },
	{ RISCV_INS_AMOMINU_D_AQ_RL, "amominu.d.aq.rl" },
	{ RISCV_INS_AMOMINU_D_RL, "amominu.d.rl" },
	{ RISCV_INS_AMOMINU_W, "amominu.w" },
	{ RISCV_INS_AMOMINU_W_AQ, "amominu.w.aq" },
	{ RISCV_INS_AMOMINU_W_AQ_RL, "amominu.w.aq.rl" },
	{ RISCV_INS_AMOMINU_W_RL, "amominu.w.rl" },
	{ RISCV_INS_AMOMIN_D, "amomin.d" },
	{ RISCV_INS_AMOMIN_D_AQ, "amomin.d.aq" },
	{ RISCV_INS_AMOMIN_D_AQ_RL, "amomin.d.aq.rl" },
	{ RISCV_INS_AMOMIN_D_RL, "amomin.d.rl" },
	{ RISCV_INS_AMOMIN_W, "amomin.w" },
	{ RISCV_INS_AMOMIN_W_AQ, "amomin.w.aq" },
	{ RISCV_INS_AMOMIN_W_AQ_RL, "amomin.w.aq.rl" },
	{ RISCV_INS_AMOMIN_W_RL, "amomin.w.rl" },
	{ RISCV_INS_AMOOR_D, "amoor.d" },
	{ RISCV_INS_AMOOR_D_AQ, "amoor.d.aq" },
	{ RISCV_INS_AMOOR_D_AQ_RL, "amoor.d.aq.rl" },
	{ RISCV_INS_AMOOR_D_RL, "amoor.d.rl" },
	{ RISCV_INS_AMOOR_W, "amoor.w" },
	{ RISCV_INS_AMOOR_W_AQ, "amoor.w.aq" },
	{ RISCV_INS_AMOOR_W_AQ_RL, "amoor.w.aq.rl" },
	{ RISCV_INS_AMOOR_W_RL, "amoor.w.rl" },
	{ RISCV_INS_AMOSWAP_D, "amoswap.d" },
	{ RISCV_INS_AMOSWAP_D_AQ, "amoswap.d.aq" },
	{ RISCV_INS_AMOSWAP_D_AQ_RL, "amoswap.d.aq.rl" },
	{ RISCV_INS_AMOSWAP_D_RL, "amoswap.d.rl" },
	{ RISCV_INS_AMOSWAP_W, "amoswap.w" },
	{ RISCV_INS_AMOSWAP_W_AQ, "amoswap.w.aq" },
	{ RISCV_INS_AMOSWAP_W_AQ_RL, "amoswap.w.aq.rl" },
	{ RISCV_INS_AMOSWAP_W_RL, "amoswap.w.rl" },
	{ RISCV_INS_AMOXOR_D, "amoxor.d" },
	{ RISCV_INS_AMOXOR_D_AQ, "amoxor.d.aq" },
	{ RISCV_INS_AMOXOR_D_AQ_RL, "amoxor.d.aq.rl" },
	{ RISCV_INS_AMOXOR_D_RL, "amoxor.d.rl" },
	{ RISCV_INS_AMOXOR_W, "amoxor.w" },
	{ RISCV_INS_AMOXOR_W_AQ, "amoxor.w.aq" },
	{ RISCV_INS_AMOXOR_W_AQ_RL, "amoxor.w.aq.rl" },
	{ RISCV_INS_AMOXOR_W_RL, "amoxor.w.rl" },
	{ RISCV_INS_AND, "and" },
	{ RISCV_INS_ANDI, "andi" },
	{ RISCV_INS_AUIPC, "auipc" },
	{ RISCV_INS_BEQ, "beq" },
	{ RISCV_INS_BGE, "bge" },
	{ RISCV_INS_BGEU, "bgeu" },
	{ RISCV_INS_BLT, "blt" },
	{ RISCV_INS_BLTU, "bltu" },
	{ RISCV_INS_BNE, "bne" },
	{ RISCV_INS_CSRRC, "csrrc" },
	{ RISCV_INS_CSRRCI, "csrrci" },
	{ RISCV_INS_CSRRS, "csrrs" },
	{ RISCV_INS_CSRRSI, "csrrsi" },
	{ RISCV_INS_CSRRW, "csrrw" },
	{ RISCV_INS_CSRRWI, "csrrwi" },
	{ RISCV_INS_DIV, "div" },
	{ RISCV_INS_DIVU, "divu" },
	{ RISCV_INS_DIVUW, "divuw" },
	{ RISCV_INS_DIVW, "divw" },
	{ RISCV_INS_EBREAK, "ebreak" },
	{ RISCV_INS_ECALL, "ecall" },
	{ RISCV_INS_FADD_D, "fadd.d" },
	{ RISCV_INS_FADD_S, "fadd.s" },
	{ RISCV_INS_FCLASS_D, "fclass.d" },
	{ RISCV_INS_FCLASS_S, "fclass.s" },
	{ RISCV_INS_FCVT_D_L, "fcvt.d.l" },
	{ RISCV_INS_FCVT_D_LU, "fcvt.d.lu" },
	{ RISCV_INS_FCVT_D_S, "fcvt.d.s" },
	{ RISCV_INS_FCVT_D_W, "fcvt.d.w" },
	{ RISCV_INS_FCVT_D_WU, "fcvt.d.wu" },
	{ RISCV_INS_FCVT_LU_D, "fcvt.lu.d" },
	{ RISCV_INS_FCVT_LU_S, "fcvt.lu.s" },
	{ RISCV_INS_FCVT_L_D, "fcvt.l.d" },
	{ RISCV_INS_FCVT_L_S, "fcvt.l.s" },
	{ RISCV_INS_FCVT_S_D, "fcvt.s.d" },
	{ RISCV_INS_FCVT_S_L, "fcvt.s.l" },
	{ RISCV_INS_FCVT_S_LU, "fcvt.s.lu" },
	{ RISCV_INS_FCVT_S_W, "fcvt.s.w" },
	{ RISCV_INS_FCVT_S_WU, "fcvt.s.wu" },
	{ RISCV_INS_FCVT_WU_D, "fcvt.wu.d" },
	{ RISCV_INS_FCVT_WU_S, "fcvt.wu.s" },
	{ RISCV_INS_FCVT_W_D, "fcvt.w.d" },
	{ RISCV_INS_FCVT_W_S, "fcvt.w.s" },
	{ RISCV_INS_FDIV_D, "fdiv.d" },
	{ RISCV_INS_FDIV_S, "fdiv.s" },
	{ RISCV_INS_FENCE, "fence" },
	{ RISCV_INS_FENCE_I, "fence.i" },
	{ RISCV_INS_FEQ_D, "feq.d" },
	{ RISCV_INS_FEQ_S, "feq.s" },
	{ RISCV_INS_FLD, "fld" },
	{ RISCV_INS_FLE_D, "fle.d" },
	{ RISCV_INS_FLE_S, "fle.s" },
	{ RISCV_INS_FLT_D, "flt.d" },
	{ RISCV_INS_FLT_S, "flt.s" },
	{ RISCV_INS_FLW, "flw" },
	{ RISCV_INS_FMADD_D, "fmadd.d" },
	{ RISCV_INS_FMADD_S, "fmadd.s" },
	{ RISCV_INS_FMAX_D, "fmax.d" },
	{ RISCV_INS_FMAX_S, "fmax.s" },
	{ RISCV_INS_FMIN_D, "fmin.d" },
	{ RISCV_INS_FMIN_S, "fmin.s" },
	{ RISCV_INS_FMSUB_D, "fmsub.d" },
	{ RISCV_INS_FMSUB_S, "fmsub.s" },
	{ RISCV_INS_FMUL_D, "fmul.d" },
	{ RISCV_INS_FMUL_S, "fmul.s" },
	{ RISCV_INS_FMV_D_X, "fmv.d.x" },
	{ RISCV_INS_FMV_W_X, "fmv.w.x" },
	{ RISCV_INS_FMV_X_D, "fmv.x.d" },
	{ RISCV_INS_FMV_X_W, "fmv.x.w" },
	{ RISCV_INS_FNMADD_D, "fnmadd.d" },
	{ RISCV_INS_FNMADD_S, "fnmadd.s" },
	{ RISCV_INS_FNMSUB_D, "fnmsub.d" },
	{ RISCV_INS_FNMSUB_S, "fnmsub.s" },
	{ RISCV_INS_FSD, "fsd" },
	{ RISCV_INS_FSGNJN_D, "fsgnjn.d" },
	{ RISCV_INS_FSGNJN_S, "fsgnjn.s" },
	{ RISCV_INS_FSGNJX_D, "fsgnjx.d" },
	{ RISCV_INS_FSGNJX_S, "fsgnjx.s" },
	{ RISCV_INS_FSGNJ_D, "fsgnj.d" },
	{ RISCV_INS_FSGNJ_S, "fsgnj.s" },
	{ RISCV_INS_FSQRT_D, "fsqrt.d" },
	{ RISCV_INS_FSQRT_S, "fsqrt.s" },
	{ RISCV_INS_FSUB_D, "fsub.d" },
	{ RISCV_INS_FSUB_S, "fsub.s" },
	{ RISCV_INS_FSW, "fsw" },
	{ RISCV_INS_JAL, "jal" },
	{ RISCV_INS_JALR, "jalr" },
	{ RISCV_INS_LB, "lb" },
	{ RISCV_INS_LBU, "lbu" },
	{ RISCV_INS_LD, "ld" },
	{ RISCV_INS_LH, "lh" },
	{ RISCV_INS_LHU, "lhu" },
	{ RISCV_INS_LR_D, "lr.d" },
	{ RISCV_INS_LR_D_AQ, "lr.d.aq" },
	{ RISCV_INS_LR_D_AQ_RL, "lr.d.aq.rl" },
	{ RISCV_INS_LR_D_RL, "lr.d.rl" },
	{ RISCV_INS_LR_W, "lr.w" },
	{ RISCV_INS_LR_W_AQ, "lr.w.aq" },
	{ RISCV_INS_LR_W_AQ_RL, "lr.w.aq.rl" },
	{ RISCV_INS_LR_W_RL, "lr.w.rl" },
	{ RISCV_INS_LUI, "lui" },
	{ RISCV_INS_LW, "lw" },
	{ RISCV_INS_LWU, "lwu" },
	{ RISCV_INS_MUL, "mul" },
	{ RISCV_INS_MULH, "mulh" },
	{ RISCV_INS_MULHSU, "mulhsu" },
	{ RISCV_INS_MULHU, "mulhu" },
	{ RISCV_INS_MULW, "mulw" },
	{ RISCV_INS_OR, "or" },
	{ RISCV_INS_ORI, "ori" },
	{ RISCV_INS_REM, "rem" },
	{ RISCV_INS_REMU, "remu" },
	{ RISCV_INS_REMUW, "remuw" },
	{ RISCV_INS_REMW, "remw" },
	{ RISCV_INS_SB, "sb" },
	{ RISCV_INS_SC_D, "sc.d" },
	{ RISCV_INS_SC_D_AQ, "sc.d.aq" },
	{ RISCV_INS_SC_D_AQ_RL, "sc.d.aq.rl" },
	{ RISCV_INS_SC_D_RL, "sc.d.rl" },
	{ RISCV_INS_SC_W, "sc.w" },
	{ RISCV_INS_SC_W_AQ, "sc.w.aq" },
	{ RISCV_INS_SC_W_AQ_RL, "sc.w.aq.rl" },
	{ RISCV_INS_SC_W_RL, "sc.w.rl" },
	{ RISCV_INS_SD, "sd" },
	{ RISCV_INS_SH, "sh" },
	{ RISCV_INS_SLL, "sll" },
	{ RISCV_INS_SLLI, "slli" },
	{ RISCV_INS_SLLIW, "slliw" },
	{ RISCV_INS_SLLW, "sllw" },
	{ RISCV_INS_SLT, "slt" },
	{ RISCV_INS_SLTI, "slti" },
	{ RISCV_INS_SLTIU, "sltiu" },
	{ RISCV_INS_SLTU, "sltu" },
	{ RISCV_INS_SRA, "sra" },
	{ RISCV_INS_SRAI, "srai" },
	{ RISCV_INS_SRAIW, "sraiw" },
	{ RISCV_INS_SRAW, "sraw" },
	{ RISCV_INS_SRL, "srl" },
	{ RISCV_INS_SRLI, "srli" },
	{ RISCV_INS_SRLIW, "srliw" },
	{ RISCV_INS_SRLW, "srlw" },
	{ RISCV_INS_SUB, "sub" },
	{ RISCV_INS_SUBW, "subw" },
	{ RISCV_INS_SW, "sw" },
	{ RISCV_INS_XOR, "xor" },
	{ RISCV_INS_XORI, "xori" },
	
	// pseudo instructions	
	{ RISCV_INS_PseudoCALL, "call" },
	{ RISCV_INS_PseudoRET, "ret" },

};

const char *RISCV_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	if (id >= RISCV_INS_ENDING)
		return NULL;

	return insn_name_maps[id].name;
#else
	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
static const name_map group_name_maps[] = {
	// generic groups
	{ RISCV_GRP_INVALID, NULL },
	{ RISCV_GRP_JUMP, "jump" },

	// architecture-specific groups
	{ RISCV_GRP_RV32I, "rv32i" },
	{ RISCV_GRP_RV64I, "rv64i" },
	{ RISCV_GRP_RV32M, "rv32m" },
	{ RISCV_GRP_RV64M, "rv64m" },
	{ RISCV_GRP_RV32A, "rv32a" },
	{ RISCV_GRP_RV64A, "rv64a" },
	{ RISCV_GRP_RV32F, "rv32f" },
	{ RISCV_GRP_RV64F, "rv64f" },
	{ RISCV_GRP_RV32D, "rv32d" },
	{ RISCV_GRP_RV64D, "rv64d" },
};
#endif

const char *RISCV_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	// verify group id
	if (id >= RISCV_GRP_ENDING || (id > RISCV_GRP_JUMP && id < RISCV_GRP_RV32I))
		return NULL;

	// NOTE: when new generic groups are added, 2 must be changed accordingly
	if (id >= 128)
		return group_name_maps[id - 128 + 2].name;
	else
		return group_name_maps[id].name;
#else
	return NULL;
#endif
}

// map instruction name to public instruction ID
riscv_reg RISCV_map_insn(const char *name)
{
	// handle special alias first
	unsigned int i;

	// NOTE: skip first NULL name in insn_name_maps
	i = name2id(&insn_name_maps[1], ARR_SIZE(insn_name_maps) - 1, name);

	return (i != -1)? i : RISCV_REG_INVALID;
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
									   
		RISCV_REG_F0_32, 
		RISCV_REG_F1_32, 
		RISCV_REG_F2_32, 
		RISCV_REG_F3_32, 
		RISCV_REG_F4_32, 
		RISCV_REG_F5_32, 
		RISCV_REG_F6_32, 
		RISCV_REG_F7_32, 
		RISCV_REG_F8_32, 
		RISCV_REG_F9_32,
		RISCV_REG_F10_32, 
		RISCV_REG_F11_32, 
		RISCV_REG_F12_32, 
		RISCV_REG_F13_32, 
		RISCV_REG_F14_32, 
		RISCV_REG_F15_32, 
		RISCV_REG_F16_32, 
		RISCV_REG_F17_32, 
		RISCV_REG_F18_32, 
		RISCV_REG_F19_32,  
		RISCV_REG_F20_32,
		RISCV_REG_F21_32,
		RISCV_REG_F22_32,
		RISCV_REG_F23_32,
		RISCV_REG_F24_32,
		RISCV_REG_F25_32,
		RISCV_REG_F26_32,
		RISCV_REG_F27_32,
		RISCV_REG_F28_32,
		RISCV_REG_F29_32,
		RISCV_REG_F30_32,
		RISCV_REG_F31_32,
									   
		RISCV_REG_F0_64, 
		RISCV_REG_F1_64, 
		RISCV_REG_F2_64, 
		RISCV_REG_F3_64, 
		RISCV_REG_F4_64, 
		RISCV_REG_F5_64, 
		RISCV_REG_F6_64, 
		RISCV_REG_F7_64, 
		RISCV_REG_F8_64, 
		RISCV_REG_F9_64,
		RISCV_REG_F10_64, 
		RISCV_REG_F11_64, 
		RISCV_REG_F12_64, 
		RISCV_REG_F13_64, 
		RISCV_REG_F14_64, 
		RISCV_REG_F15_64, 
		RISCV_REG_F16_64, 
		RISCV_REG_F17_64, 
		RISCV_REG_F18_64, 
		RISCV_REG_F19_64,  
		RISCV_REG_F20_64,
		RISCV_REG_F21_64,
		RISCV_REG_F22_64,
		RISCV_REG_F23_64,
		RISCV_REG_F24_64,
		RISCV_REG_F25_64,
		RISCV_REG_F26_64,
		RISCV_REG_F27_64,
		RISCV_REG_F28_64,
		RISCV_REG_F29_64,
		RISCV_REG_F30_64,
		RISCV_REG_F31_64,
	};

	if (r < ARR_SIZE(map))
		return map[r];

	// cannot find this register
	return 0;
}

#endif

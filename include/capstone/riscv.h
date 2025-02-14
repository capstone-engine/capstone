#ifndef CAPSTONE_RISCV_H
#define CAPSTONE_RISCV_H

/* Capstone Disassembly Engine */
/* RISC-V Backend By Rodrigo Cortes Porto <porto703@gmail.com> & 
   Shawn Chang <citypw@gmail.com>, HardenedLinux@2018 */

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_MSC_VER) || !defined(_KERNEL_MODE)
#include <stdint.h>
#endif

#include "platform.h"
// GCC MIPS toolchain has a default macro called "mips" which breaks
// compilation
//#undef riscv

#ifdef _MSC_VER
#pragma warning(disable:4201)
#endif

//> Operand type for instruction's operands
typedef enum riscv_op_type {
	RISCV_OP_INVALID = 0, // = CS_OP_INVALID (Uninitialized).
	RISCV_OP_REG, // = CS_OP_REG (Register operand).
	RISCV_OP_IMM, // = CS_OP_IMM (Immediate operand).
	RISCV_OP_MEM, // = CS_OP_MEM (Memory operand).
} riscv_op_type;

// Instruction's operand referring to memory
// This is associated with RISCV_OP_MEM operand type above
typedef struct riscv_op_mem {
	unsigned int base;	// base register
	int64_t disp;	// displacement/offset value
} riscv_op_mem;

// Instruction operand
typedef struct cs_riscv_op {
	riscv_op_type type;	// operand type
	union {
		unsigned int reg;	// register value for REG operand
		int64_t imm;		// immediate value for IMM operand
		riscv_op_mem mem;	// base/disp value for MEM operand
	};
	uint8_t access; ///< How is this operand accessed? (READ, WRITE or READ|WRITE)
} cs_riscv_op;

#define NUM_RISCV_OPS 8

// Instruction structure
typedef struct cs_riscv {
	// Does this instruction need effective address or not.
	bool need_effective_addr;
	// Number of operands of this instruction, 
	// or 0 when instruction has no operand.
	uint8_t op_count;
	cs_riscv_op operands[NUM_RISCV_OPS]; // operands for this instruction.
} cs_riscv;

//> RISCV registers
typedef enum riscv_reg {
	RISCV_REG_INVALID = 0,
	//> General purpose registers
	RISCV_REG_X0,			// "zero" 
	RISCV_REG_ZERO = RISCV_REG_X0, 	// "zero" 
	RISCV_REG_X1, 			// "ra"
	RISCV_REG_RA   = RISCV_REG_X1, 	// "ra"
	RISCV_REG_X2, 			// "sp"
	RISCV_REG_SP   = RISCV_REG_X2, 	// "sp"
	RISCV_REG_X3, 			// "gp"
	RISCV_REG_GP   = RISCV_REG_X3, 	// "gp"
	RISCV_REG_X4, 			// "tp"
	RISCV_REG_TP   = RISCV_REG_X4,	// "tp"
	RISCV_REG_X5, 			// "t0"
	RISCV_REG_T0   = RISCV_REG_X5, 	// "t0"
	RISCV_REG_X6, 			// "t1"
	RISCV_REG_T1   = RISCV_REG_X6, 	// "t1"
	RISCV_REG_X7, 			// "t2"
	RISCV_REG_T2   = RISCV_REG_X7, 	// "t2"
	RISCV_REG_X8, 			// "s0/fp"
	RISCV_REG_S0   = RISCV_REG_X8,	// "s0"
	RISCV_REG_FP   = RISCV_REG_X8,	// "fp"
	RISCV_REG_X9, 			// "s1"
	RISCV_REG_S1   = RISCV_REG_X9, 	// "s1"
	RISCV_REG_X10,			// "a0"
	RISCV_REG_A0   = RISCV_REG_X10,	// "a0"
	RISCV_REG_X11,			// "a1"
	RISCV_REG_A1   = RISCV_REG_X11,	// "a1"
	RISCV_REG_X12,			// "a2"
	RISCV_REG_A2   = RISCV_REG_X12,	// "a2"
	RISCV_REG_X13,			// "a3"
	RISCV_REG_A3   = RISCV_REG_X13,	// "a3"
	RISCV_REG_X14,			// "a4"
	RISCV_REG_A4   = RISCV_REG_X14,	// "a4"
	RISCV_REG_X15,			// "a5"
	RISCV_REG_A5   = RISCV_REG_X15, // "a5"
	RISCV_REG_X16,			// "a6"
	RISCV_REG_A6   = RISCV_REG_X16,	// "a6"
	RISCV_REG_X17,			// "a7"
	RISCV_REG_A7   = RISCV_REG_X17,	// "a7"
	RISCV_REG_X18,			// "s2"
	RISCV_REG_S2   = RISCV_REG_X18,	// "s2"
	RISCV_REG_X19,			// "s3"
	RISCV_REG_S3   = RISCV_REG_X19, // "s3"
	RISCV_REG_X20,			// "s4"
	RISCV_REG_S4   = RISCV_REG_X20,	// "s4"
	RISCV_REG_X21,			// "s5"
	RISCV_REG_S5   = RISCV_REG_X21,	// "s5"
	RISCV_REG_X22,			// "s6"
	RISCV_REG_S6   = RISCV_REG_X22,	// "s6"
	RISCV_REG_X23,			// "s7"
	RISCV_REG_S7   = RISCV_REG_X23,	// "s7"
	RISCV_REG_X24,			// "s8"
	RISCV_REG_S8   = RISCV_REG_X24,	// "s8"
	RISCV_REG_X25,			// "s9"
	RISCV_REG_S9   = RISCV_REG_X25,	// "s9"
	RISCV_REG_X26,			// "s10"
	RISCV_REG_S10  = RISCV_REG_X26,	// "s10"
	RISCV_REG_X27,			// "s11"
	RISCV_REG_S11  = RISCV_REG_X27, // "s11"
	RISCV_REG_X28,			// "t3"
	RISCV_REG_T3   = RISCV_REG_X28,	// "t3"
	RISCV_REG_X29,			// "t4"
	RISCV_REG_T4   = RISCV_REG_X29, // "t4"
	RISCV_REG_X30,			// "t5"
	RISCV_REG_T5   = RISCV_REG_X30,	// "t5"
	RISCV_REG_X31,			// "t6"
	RISCV_REG_T6   = RISCV_REG_X31,	// "t6"
	
	//> Floating-point registers
	RISCV_REG_F0_32,		// "ft0"
	RISCV_REG_F0_64,		// "ft0"
	RISCV_REG_F1_32,		// "ft1"
	RISCV_REG_F1_64,		// "ft1"
	RISCV_REG_F2_32,		// "ft2"
	RISCV_REG_F2_64,		// "ft2"
	RISCV_REG_F3_32,		// "ft3"
	RISCV_REG_F3_64,		// "ft3"
	RISCV_REG_F4_32,		// "ft4"
	RISCV_REG_F4_64,		// "ft4"
	RISCV_REG_F5_32,		// "ft5"
	RISCV_REG_F5_64,		// "ft5"
	RISCV_REG_F6_32,		// "ft6"
	RISCV_REG_F6_64,		// "ft6"
	RISCV_REG_F7_32,		// "ft7"
	RISCV_REG_F7_64,		// "ft7"
	RISCV_REG_F8_32,		// "fs0"
	RISCV_REG_F8_64,		// "fs0"
	RISCV_REG_F9_32,		// "fs1"
	RISCV_REG_F9_64,		// "fs1"
	RISCV_REG_F10_32,		// "fa0"
	RISCV_REG_F10_64,		// "fa0"
	RISCV_REG_F11_32,		// "fa1"
	RISCV_REG_F11_64,		// "fa1"
	RISCV_REG_F12_32,		// "fa2"
	RISCV_REG_F12_64,		// "fa2"
	RISCV_REG_F13_32,		// "fa3"
	RISCV_REG_F13_64,		// "fa3"
	RISCV_REG_F14_32,		// "fa4"
	RISCV_REG_F14_64,		// "fa4"
	RISCV_REG_F15_32,		// "fa5"
	RISCV_REG_F15_64,		// "fa5"
	RISCV_REG_F16_32,		// "fa6"
	RISCV_REG_F16_64,		// "fa6"
	RISCV_REG_F17_32,		// "fa7"
	RISCV_REG_F17_64,		// "fa7"
	RISCV_REG_F18_32,		// "fs2"
	RISCV_REG_F18_64,		// "fs2"
	RISCV_REG_F19_32,		// "fs3"
	RISCV_REG_F19_64,		// "fs3"
	RISCV_REG_F20_32,		// "fs4"
	RISCV_REG_F20_64,		// "fs4"
	RISCV_REG_F21_32,		// "fs5"
	RISCV_REG_F21_64,		// "fs5"
	RISCV_REG_F22_32,		// "fs6"
	RISCV_REG_F22_64,		// "fs6"
	RISCV_REG_F23_32,		// "fs7"
	RISCV_REG_F23_64,		// "fs7"
	RISCV_REG_F24_32,		// "fs8"
	RISCV_REG_F24_64,		// "fs8"
	RISCV_REG_F25_32,		// "fs9"
	RISCV_REG_F25_64,		// "fs9"
	RISCV_REG_F26_32,		// "fs10"
	RISCV_REG_F26_64,		// "fs10"
	RISCV_REG_F27_32,		// "fs11"
	RISCV_REG_F27_64,		// "fs11"
	RISCV_REG_F28_32,		// "ft8"
	RISCV_REG_F28_64,		// "ft8"
	RISCV_REG_F29_32,		// "ft9"
	RISCV_REG_F29_64,		// "ft9"
	RISCV_REG_F30_32,		// "ft10"
	RISCV_REG_F30_64,		// "ft10"
	RISCV_REG_F31_32,		// "ft11"
	RISCV_REG_F31_64,		// "ft11"
	
	RISCV_REG_ENDING,		// <-- mark the end of the list or registers
} riscv_reg;

//> RISCV instruction
/*=======================================================================*/
/* This code was generated by the tool auto-sync-sail*/
/* (see https://github.com/rizinorg/capstone-autosync-sail)*/
/* from the sail model of RISC-V*/
/* (see https://github.com/riscv/sail-riscv) @ version
 * 8a75b297b116a1ffd8c62e98a7f43e2d93761d15.*/
/* DO NOT MODIFY THIS CODE MANUALLY. ANY MANUAL EDITS ARE OVERWRITTEN.*/
/* ------------------------------------------------------------------- */
/* Copyright © 2024-2025 moste00 <ubermenchun@gmail.com>*/
/* SPDX-License-Identifier: BSD-3-Clause*/
/*=======================================================================*/

#ifndef __RISCVINSN_GEN_INC__
#define __RISCVINSN_GEN_INC__
#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum riscv_insn {
  //--------------------- RISCV_REV8---------------------
  RISCV_INSN_REV8,
  //--------------------- RISCV_WXTYPE---------------------
  RISCV_INSN_WX_VSUBU,
  RISCV_INSN_WX_VSUB,
  RISCV_INSN_WX_VADDU,
  RISCV_INSN_WX_VADD,
  //--------------------- RISCV_C_SRLI_HINT---------------------
  RISCV_INSN_C_SRLI_HINT,
  //--------------------- RISCV_AES64DS---------------------
  RISCV_INSN_AES64DS,
  //--------------------- RISCV_VMSBF_M---------------------
  RISCV_INSN_VMSBF_M,
  //--------------------- RISCV_RTYPE---------------------
  RISCV_INSN_XOR,
  RISCV_INSN_SUB,
  RISCV_INSN_SRL,
  RISCV_INSN_SRA,
  RISCV_INSN_SLTU,
  RISCV_INSN_SLT,
  RISCV_INSN_SLL,
  RISCV_INSN_OR,
  RISCV_INSN_AND,
  RISCV_INSN_ADD,
  //--------------------- RISCV_VFMERGE---------------------
  RISCV_INSN_VFMERGE,
  //--------------------- RISCV_RIVVTYPE---------------------
  RISCV_INSN_IVV_VWREDSUMU,
  RISCV_INSN_IVV_VWREDSUM,
  //--------------------- RISCV_C_ZEXT_W---------------------
  RISCV_INSN_C_ZEXT_W,
  //--------------------- RISCV_SFENCE_INVAL_IR---------------------
  RISCV_INSN_SFENCE_INVAL_IR,
  //--------------------- RISCV_XPERM4---------------------
  RISCV_INSN_XPERM4,
  //--------------------- RISCV_C_AND---------------------
  RISCV_INSN_C_AND,
  //--------------------- RISCV_AES32DSI---------------------
  RISCV_INSN_AES32DSI,
  //--------------------- RISCV_RORI---------------------
  RISCV_INSN_RORI,
  //--------------------- RISCV_JALR---------------------
  RISCV_INSN_JALR,
  //--------------------- RISCV_VMSIF_M---------------------
  RISCV_INSN_VMSIF_M,
  //--------------------- RISCV_VLSSEGTYPE---------------------
  RISCV_INSN_VLSSEGTYPE,
  //--------------------- RISCV_SHA512SIG1H---------------------
  RISCV_INSN_SHA512SIG1H,
  //--------------------- RISCV_FLTQ_S---------------------
  RISCV_INSN_FLTQ_S,
  //--------------------- RISCV_VXSG---------------------
  RISCV_INSN_VX_VSLIDEUP,
  RISCV_INSN_VX_VSLIDEDOWN,
  RISCV_INSN_VX_VRGATHER,
  //--------------------- RISCV_VXCMPTYPE---------------------
  RISCV_INSN_VXCMP_VMSNE,
  RISCV_INSN_VXCMP_VMSLTU,
  RISCV_INSN_VXCMP_VMSLT,
  RISCV_INSN_VXCMP_VMSLEU,
  RISCV_INSN_VXCMP_VMSLE,
  RISCV_INSN_VXCMP_VMSGTU,
  RISCV_INSN_VXCMP_VMSGT,
  RISCV_INSN_VXCMP_VMSEQ,
  //--------------------- RISCV_C_LHU---------------------
  RISCV_INSN_C_LHU,
  //--------------------- RISCV_JAL---------------------
  RISCV_INSN_JAL,
  //--------------------- RISCV_ECALL---------------------
  RISCV_INSN_ECALL,
  //--------------------- RISCV_C_FSWSP---------------------
  RISCV_INSN_C_FSWSP,
  //--------------------- RISCV_VMVXS---------------------
  RISCV_INSN_VMVXS,
  //--------------------- RISCV_C_FLD---------------------
  RISCV_INSN_C_FLD,
  //--------------------- RISCV_SHIFTIWOP---------------------
  RISCV_INSN_SRLIW,
  RISCV_INSN_SRAIW,
  RISCV_INSN_SLLIW,
  //--------------------- RISCV_UNZIP---------------------
  RISCV_INSN_UNZIP,
  //--------------------- RISCV_ZICBOM---------------------
  RISCV_INSN_CBO_INVAL,
  RISCV_INSN_CBO_FLUSH,
  RISCV_INSN_CBO_CLEAN,
  //--------------------- RISCV_SHA512SIG1---------------------
  RISCV_INSN_SHA512SIG1,
  //--------------------- RISCV_NITYPE---------------------
  RISCV_INSN_NI_VNCLIPU,
  RISCV_INSN_NI_VNCLIP,
  //--------------------- RISCV_WFI---------------------
  RISCV_INSN_WFI,
  //--------------------- RISCV_VVMTYPE---------------------
  RISCV_INSN_VVM_VMSBC,
  RISCV_INSN_VVM_VMADC,
  //--------------------- RISCV_MVXMATYPE---------------------
  RISCV_INSN_MVX_VNMSUB,
  RISCV_INSN_MVX_VNMSAC,
  RISCV_INSN_MVX_VMADD,
  RISCV_INSN_MVX_VMACC,
  //--------------------- RISCV_FLI_D---------------------
  RISCV_INSN_FLI_D,
  //--------------------- RISCV_C_ADDI_HINT---------------------
  RISCV_INSN_C_ADDI_HINT,
  //--------------------- RISCV_MASKTYPEX---------------------
  RISCV_INSN_MASKTYPEX,
  //--------------------- RISCV_FROUNDNX_D---------------------
  RISCV_INSN_FROUNDNX_D,
  //--------------------- RISCV_FROUND_D---------------------
  RISCV_INSN_FROUND_D,
  //--------------------- RISCV_VSETIVLI---------------------
  RISCV_INSN_VSETIVLI,
  //--------------------- RISCV_FMAXM_D---------------------
  RISCV_INSN_FMAXM_D,
  //--------------------- RISCV_C_SD---------------------
  RISCV_INSN_C_SD,
  //--------------------- RISCV_F_BIN_TYPE_H---------------------
  RISCV_INSN_FSGNJ_H,
  RISCV_INSN_FSGNJX_H,
  RISCV_INSN_FSGNJN_H,
  RISCV_INSN_FMIN_H,
  RISCV_INSN_FMAX_H,
  RISCV_INSN_FLT_H,
  RISCV_INSN_FLE_H,
  RISCV_INSN_FEQ_H,
  //--------------------- RISCV_ZBKB_PACKW---------------------
  RISCV_INSN_ZBKB_PACKW,
  //--------------------- RISCV_FVVMTYPE---------------------
  RISCV_INSN_FVVM_VMFNE,
  RISCV_INSN_FVVM_VMFLT,
  RISCV_INSN_FVVM_VMFLE,
  RISCV_INSN_FVVM_VMFEQ,
  //--------------------- RISCV_VMVSX---------------------
  RISCV_INSN_VMVSX,
  //--------------------- RISCV_F_UN_RM_TYPE_D---------------------
  RISCV_INSN_FSQRT_D,
  RISCV_INSN_FCVT_W_D,
  RISCV_INSN_FCVT_WU_D,
  RISCV_INSN_FCVT_S_D,
  RISCV_INSN_FCVT_L_D,
  RISCV_INSN_FCVT_LU_D,
  RISCV_INSN_FCVT_D_WU,
  RISCV_INSN_FCVT_D_W,
  RISCV_INSN_FCVT_D_S,
  RISCV_INSN_FCVT_D_LU,
  RISCV_INSN_FCVT_D_L,
  //--------------------- RISCV_ORCB---------------------
  RISCV_INSN_ORCB,
  //--------------------- RISCV_C_MUL---------------------
  RISCV_INSN_C_MUL,
  //--------------------- RISCV_SM3P1---------------------
  RISCV_INSN_SM3P1,
  //--------------------- RISCV_CLMUL---------------------
  RISCV_INSN_CLMUL,
  //--------------------- RISCV_FLEQ_S---------------------
  RISCV_INSN_FLEQ_S,
  //--------------------- RISCV_WVXTYPE---------------------
  RISCV_INSN_WVX_VWMULU,
  RISCV_INSN_WVX_VWMULSU,
  RISCV_INSN_WVX_VWMUL,
  RISCV_INSN_WVX_VSUBU,
  RISCV_INSN_WVX_VSUB,
  RISCV_INSN_WVX_VADDU,
  RISCV_INSN_WVX_VADD,
  //--------------------- RISCV_FMAXM_S---------------------
  RISCV_INSN_FMAXM_S,
  //--------------------- RISCV_C_ILLEGAL---------------------
  RISCV_INSN_C_ILLEGAL,
  //--------------------- RISCV_NXSTYPE---------------------
  RISCV_INSN_NXS_VNSRL,
  RISCV_INSN_NXS_VNSRA,
  //--------------------- RISCV_VSOXSEGTYPE---------------------
  RISCV_INSN_VSOXSEGTYPE,
  //--------------------- RISCV_C_NOP---------------------
  RISCV_INSN_C_NOP,
  //--------------------- RISCV_VXMCTYPE---------------------
  RISCV_INSN_VXMC_VMSBC,
  RISCV_INSN_VXMC_VMADC,
  //--------------------- RISCV_MMTYPE---------------------
  RISCV_INSN_MM_VMXOR,
  RISCV_INSN_MM_VMXNOR,
  RISCV_INSN_MM_VMORN,
  RISCV_INSN_MM_VMOR,
  RISCV_INSN_MM_VMNOR,
  RISCV_INSN_MM_VMNAND,
  RISCV_INSN_MM_VMANDN,
  RISCV_INSN_MM_VMAND,
  //--------------------- RISCV_F_UN_TYPE_S---------------------
  RISCV_INSN_FMV_X_W,
  RISCV_INSN_FMV_W_X,
  RISCV_INSN_FCLASS_S,
  //--------------------- RISCV_NVTYPE---------------------
  RISCV_INSN_NV_VNCLIPU,
  RISCV_INSN_NV_VNCLIP,
  //--------------------- RISCV_AES64KS2---------------------
  RISCV_INSN_AES64KS2,
  //--------------------- RISCV_AES32ESMI---------------------
  RISCV_INSN_AES32ESMI,
  //--------------------- RISCV_F_MADD_TYPE_H---------------------
  RISCV_INSN_FNMSUB_H,
  RISCV_INSN_FNMADD_H,
  RISCV_INSN_FMSUB_H,
  RISCV_INSN_FMADD_H,
  //--------------------- RISCV_FROUNDNX_H---------------------
  RISCV_INSN_FROUNDNX_H,
  //--------------------- RISCV_MOVETYPEI---------------------
  RISCV_INSN_MOVETYPEI,
  //--------------------- RISCV_FLTQ_H---------------------
  RISCV_INSN_FLTQ_H,
  //--------------------- RISCV_C_LW---------------------
  RISCV_INSN_C_LW,
  //--------------------- RISCV_C_LWSP---------------------
  RISCV_INSN_C_LWSP,
  //--------------------- RISCV_C_ADDI16SP---------------------
  RISCV_INSN_C_ADDI16SP,
  //--------------------- RISCV_SHA512SIG0L---------------------
  RISCV_INSN_SHA512SIG0L,
  //--------------------- RISCV_SM3P0---------------------
  RISCV_INSN_SM3P0,
  //--------------------- RISCV_SM4ED---------------------
  RISCV_INSN_SM4ED,
  //--------------------- RISCV_FMINM_D---------------------
  RISCV_INSN_FMINM_D,
  //--------------------- RISCV_AES64IM---------------------
  RISCV_INSN_AES64IM,
  //--------------------- RISCV_VLRETYPE---------------------
  RISCV_INSN_VLRETYPE,
  //--------------------- RISCV_VFMVFS---------------------
  RISCV_INSN_VFMVFS,
  //--------------------- RISCV_CTZ---------------------
  RISCV_INSN_CTZ,
  //--------------------- RISCV_FMVH_X_D---------------------
  RISCV_INSN_FMVH_X_D,
  //--------------------- RISCV_SLLIUW---------------------
  RISCV_INSN_SLLIUW,
  //--------------------- RISCV_FMINM_S---------------------
  RISCV_INSN_FMINM_S,
  //--------------------- RISCV_ZBA_RTYPEUW---------------------
  RISCV_INSN_SH3ADDUW,
  RISCV_INSN_SH2ADDUW,
  RISCV_INSN_SH1ADDUW,
  RISCV_INSN_ADDUW,
  //--------------------- RISCV_F_BIN_RM_TYPE_D---------------------
  RISCV_INSN_FSUB_D,
  RISCV_INSN_FMUL_D,
  RISCV_INSN_FDIV_D,
  RISCV_INSN_FADD_D,
  //--------------------- RISCV_C_ADD_HINT---------------------
  RISCV_INSN_C_ADD_HINT,
  //--------------------- RISCV_F_MADD_TYPE_S---------------------
  RISCV_INSN_FNMSUB_S,
  RISCV_INSN_FNMADD_S,
  RISCV_INSN_FMSUB_S,
  RISCV_INSN_FMADD_S,
  //--------------------- RISCV_ZIP---------------------
  RISCV_INSN_ZIP,
  //--------------------- RISCV_SHA512SUM1---------------------
  RISCV_INSN_SHA512SUM1,
  //--------------------- RISCV_C_LDSP---------------------
  RISCV_INSN_C_LDSP,
  //--------------------- RISCV_F_UN_RM_TYPE_H---------------------
  RISCV_INSN_FSQRT_H,
  RISCV_INSN_FCVT_W_H,
  RISCV_INSN_FCVT_WU_H,
  RISCV_INSN_FCVT_S_H,
  RISCV_INSN_FCVT_L_H,
  RISCV_INSN_FCVT_LU_H,
  RISCV_INSN_FCVT_H_WU,
  RISCV_INSN_FCVT_H_W,
  RISCV_INSN_FCVT_H_S,
  RISCV_INSN_FCVT_H_LU,
  RISCV_INSN_FCVT_H_L,
  RISCV_INSN_FCVT_H_D,
  RISCV_INSN_FCVT_D_H,
  //--------------------- RISCV_CPOP---------------------
  RISCV_INSN_CPOP,
  //--------------------- RISCV_FWFTYPE---------------------
  RISCV_INSN_FWF_VSUB,
  RISCV_INSN_FWF_VADD,
  //--------------------- RISCV_FWVTYPE---------------------
  RISCV_INSN_FWV_VSUB,
  RISCV_INSN_FWV_VADD,
  //--------------------- RISCV_ZBB_RTYPE---------------------
  RISCV_INSN_XNOR,
  RISCV_INSN_ROR,
  RISCV_INSN_ROL,
  RISCV_INSN_ORN,
  RISCV_INSN_MINU,
  RISCV_INSN_MIN,
  RISCV_INSN_MAXU,
  RISCV_INSN_MAX,
  RISCV_INSN_ANDN,
  //--------------------- RISCV_SM4KS---------------------
  RISCV_INSN_SM4KS,
  //--------------------- RISCV_RORIW---------------------
  RISCV_INSN_RORIW,
  //--------------------- RISCV_NXTYPE---------------------
  RISCV_INSN_NX_VNCLIPU,
  RISCV_INSN_NX_VNCLIP,
  //--------------------- RISCV_C_ADDIW---------------------
  RISCV_INSN_C_ADDIW,
  //--------------------- RISCV_C_LD---------------------
  RISCV_INSN_C_LD,
  //--------------------- RISCV_CTZW---------------------
  RISCV_INSN_CTZW,
  //--------------------- RISCV_XPERM8---------------------
  RISCV_INSN_XPERM8,
  //--------------------- RISCV_ITYPE---------------------
  RISCV_INSN_XORI,
  RISCV_INSN_SLTIU,
  RISCV_INSN_SLTI,
  RISCV_INSN_ORI,
  RISCV_INSN_ANDI,
  RISCV_INSN_ADDI,
  //--------------------- RISCV_VID_V---------------------
  RISCV_INSN_VID_V,
  //--------------------- RISCV_FENCE---------------------
  RISCV_INSN_FENCE,
  //--------------------- RISCV_C_FLWSP---------------------
  RISCV_INSN_C_FLWSP,
  //--------------------- RISCV_STORE---------------------
  RISCV_INSN_STORE,
  //--------------------- RISCV_F_BIN_TYPE_S---------------------
  RISCV_INSN_FSGNJ_S,
  RISCV_INSN_FSGNJX_S,
  RISCV_INSN_FSGNJN_S,
  RISCV_INSN_FMIN_S,
  RISCV_INSN_FMAX_S,
  RISCV_INSN_FLT_S,
  RISCV_INSN_FLE_S,
  RISCV_INSN_FEQ_S,
  //--------------------- RISCV_VSSEGTYPE---------------------
  RISCV_INSN_VSSEGTYPE,
  //--------------------- RISCV_F_BIN_TYPE_D---------------------
  RISCV_INSN_FSGNJ_D,
  RISCV_INSN_FSGNJX_D,
  RISCV_INSN_FSGNJN_D,
  RISCV_INSN_FMIN_D,
  RISCV_INSN_FMAX_D,
  RISCV_INSN_FLT_D,
  RISCV_INSN_FLE_D,
  RISCV_INSN_FEQ_D,
  //--------------------- RISCV_ZICOND_RTYPE---------------------
  RISCV_INSN_CZERO_NEZ,
  RISCV_INSN_CZERO_EQZ,
  //--------------------- RISCV_C_FSDSP---------------------
  RISCV_INSN_C_FSDSP,
  //--------------------- RISCV_SRET---------------------
  RISCV_INSN_SRET,
  //--------------------- RISCV_STORE_FP---------------------
  RISCV_INSN_STORE_FP,
  //--------------------- RISCV_C_JALR---------------------
  RISCV_INSN_C_JALR,
  //--------------------- RISCV_FENCE_TSO---------------------
  RISCV_INSN_FENCE_TSO,
  //--------------------- RISCV_SHA512SIG0---------------------
  RISCV_INSN_SHA512SIG0,
  //--------------------- RISCV_FLI_S---------------------
  RISCV_INSN_FLI_S,
  //--------------------- RISCV_C_SB---------------------
  RISCV_INSN_C_SB,
  //--------------------- RISCV_ZBB_RTYPEW---------------------
  RISCV_INSN_RORW,
  RISCV_INSN_ROLW,
  //--------------------- RISCV_C_FLDSP---------------------
  RISCV_INSN_C_FLDSP,
  //--------------------- RISCV_C_MV_HINT---------------------
  RISCV_INSN_C_MV_HINT,
  //--------------------- RISCV_FCVTMOD_W_D---------------------
  RISCV_INSN_FCVTMOD_W_D,
  //--------------------- RISCV_RFVVTYPE---------------------
  RISCV_INSN_FVV_VFWREDUSUM,
  RISCV_INSN_FVV_VFWREDOSUM,
  RISCV_INSN_FVV_VFREDUSUM,
  RISCV_INSN_FVV_VFREDOSUM,
  RISCV_INSN_FVV_VFREDMIN,
  RISCV_INSN_FVV_VFREDMAX,
  //--------------------- RISCV_SHA512SIG0H---------------------
  RISCV_INSN_SHA512SIG0H,
  //--------------------- RISCV_AMO---------------------
  RISCV_INSN_AMOXOR,
  RISCV_INSN_AMOSWAP,
  RISCV_INSN_AMOOR,
  RISCV_INSN_AMOMINU,
  RISCV_INSN_AMOMIN,
  RISCV_INSN_AMOMAXU,
  RISCV_INSN_AMOMAX,
  RISCV_INSN_AMOAND,
  RISCV_INSN_AMOADD,
  //--------------------- RISCV_LOAD_FP---------------------
  RISCV_INSN_LOAD_FP,
  //--------------------- RISCV_VVMSTYPE---------------------
  RISCV_INSN_VVMS_VSBC,
  RISCV_INSN_VVMS_VADC,
  //--------------------- RISCV_FVVMATYPE---------------------
  RISCV_INSN_FVV_VNMSUB,
  RISCV_INSN_FVV_VNMSAC,
  RISCV_INSN_FVV_VNMADD,
  RISCV_INSN_FVV_VNMACC,
  RISCV_INSN_FVV_VMSUB,
  RISCV_INSN_FVV_VMSAC,
  RISCV_INSN_FVV_VMADD,
  RISCV_INSN_FVV_VMACC,
  //--------------------- RISCV_VEXT2TYPE---------------------
  RISCV_INSN_VEXT2_ZVF2,
  RISCV_INSN_VEXT2_SVF2,
  //--------------------- RISCV_EBREAK---------------------
  RISCV_INSN_EBREAK,
  //--------------------- RISCV_C_LUI---------------------
  RISCV_INSN_C_LUI,
  //--------------------- RISCV_F_MADD_TYPE_D---------------------
  RISCV_INSN_FNMSUB_D,
  RISCV_INSN_FNMADD_D,
  RISCV_INSN_FMSUB_D,
  RISCV_INSN_FMADD_D,
  //--------------------- RISCV_C_ZEXT_H---------------------
  RISCV_INSN_C_ZEXT_H,
  //--------------------- RISCV_SHA512SIG1L---------------------
  RISCV_INSN_SHA512SIG1L,
  //--------------------- RISCV_VLSEGTYPE---------------------
  RISCV_INSN_VLSEGTYPE,
  //--------------------- RISCV_SHA256SIG0---------------------
  RISCV_INSN_SHA256SIG0,
  //--------------------- RISCV_F_UN_TYPE_H---------------------
  RISCV_INSN_FMV_X_H,
  RISCV_INSN_FMV_H_X,
  RISCV_INSN_FCLASS_H,
  //--------------------- RISCV_C_ADDI4SPN---------------------
  RISCV_INSN_C_ADDI4SPN,
  //--------------------- RISCV_VVTYPE---------------------
  RISCV_INSN_VV_VXOR,
  RISCV_INSN_VV_VSUB,
  RISCV_INSN_VV_VSSUBU,
  RISCV_INSN_VV_VSSUB,
  RISCV_INSN_VV_VSSRL,
  RISCV_INSN_VV_VSSRA,
  RISCV_INSN_VV_VSRL,
  RISCV_INSN_VV_VSRA,
  RISCV_INSN_VV_VSMUL,
  RISCV_INSN_VV_VSLL,
  RISCV_INSN_VV_VSADDU,
  RISCV_INSN_VV_VSADD,
  RISCV_INSN_VV_VRGATHEREI16,
  RISCV_INSN_VV_VRGATHER,
  RISCV_INSN_VV_VOR,
  RISCV_INSN_VV_VMINU,
  RISCV_INSN_VV_VMIN,
  RISCV_INSN_VV_VMAXU,
  RISCV_INSN_VV_VMAX,
  RISCV_INSN_VV_VAND,
  RISCV_INSN_VV_VADD,
  //--------------------- RISCV_FLEQ_H---------------------
  RISCV_INSN_FLEQ_H,
  //--------------------- RISCV_VICMPTYPE---------------------
  RISCV_INSN_VICMP_VMSNE,
  RISCV_INSN_VICMP_VMSLEU,
  RISCV_INSN_VICMP_VMSLE,
  RISCV_INSN_VICMP_VMSGTU,
  RISCV_INSN_VICMP_VMSGT,
  RISCV_INSN_VICMP_VMSEQ,
  //--------------------- RISCV_C_FLW---------------------
  RISCV_INSN_C_FLW,
  //--------------------- RISCV_C_SWSP---------------------
  RISCV_INSN_C_SWSP,
  //--------------------- RISCV_FLTQ_D---------------------
  RISCV_INSN_FLTQ_D,
  //--------------------- RISCV_AES64ES---------------------
  RISCV_INSN_AES64ES,
  //--------------------- RISCV_C_SRAI_HINT---------------------
  RISCV_INSN_C_SRAI_HINT,
  //--------------------- RISCV_DIV---------------------
  RISCV_INSN_DIV,
  //--------------------- RISCV_F_UN_TYPE_D---------------------
  RISCV_INSN_FMV_X_D,
  RISCV_INSN_FMV_D_X,
  RISCV_INSN_FCLASS_D,
  //--------------------- RISCV_C_LH---------------------
  RISCV_INSN_C_LH,
  //--------------------- RISCV_C_NOP_HINT---------------------
  RISCV_INSN_C_NOP_HINT,
  //--------------------- RISCV_VFIRST_M---------------------
  RISCV_INSN_VFIRST_M,
  //--------------------- RISCV_MVVMATYPE---------------------
  RISCV_INSN_MVV_VNMSUB,
  RISCV_INSN_MVV_VNMSAC,
  RISCV_INSN_MVV_VMADD,
  RISCV_INSN_MVV_VMACC,
  //--------------------- RISCV_FENCEI_RESERVED---------------------
  RISCV_INSN_FENCEI_RESERVED,
  //--------------------- RISCV_C_ADDI---------------------
  RISCV_INSN_C_ADDI,
  //--------------------- RISCV_VLOXSEGTYPE---------------------
  RISCV_INSN_VLOXSEGTYPE,
  //--------------------- RISCV_MUL---------------------
  RISCV_INSN_MUL,
  //--------------------- RISCV_VMSOF_M---------------------
  RISCV_INSN_VMSOF_M,
  //--------------------- RISCV_FLEQ_D---------------------
  RISCV_INSN_FLEQ_D,
  //--------------------- RISCV_VSSSEGTYPE---------------------
  RISCV_INSN_VSSSEGTYPE,
  //--------------------- RISCV_VXTYPE---------------------
  RISCV_INSN_VX_VXOR,
  RISCV_INSN_VX_VSUB,
  RISCV_INSN_VX_VSSUBU,
  RISCV_INSN_VX_VSSUB,
  RISCV_INSN_VX_VSSRL,
  RISCV_INSN_VX_VSSRA,
  RISCV_INSN_VX_VSRL,
  RISCV_INSN_VX_VSRA,
  RISCV_INSN_VX_VSMUL,
  RISCV_INSN_VX_VSLL,
  RISCV_INSN_VX_VSADDU,
  RISCV_INSN_VX_VSADD,
  RISCV_INSN_VX_VRSUB,
  RISCV_INSN_VX_VOR,
  RISCV_INSN_VX_VMINU,
  RISCV_INSN_VX_VMIN,
  RISCV_INSN_VX_VMAXU,
  RISCV_INSN_VX_VMAX,
  RISCV_INSN_VX_VAND,
  RISCV_INSN_VX_VADD,
  //--------------------- RISCV_BTYPE---------------------
  RISCV_INSN_BNE,
  RISCV_INSN_BLTU,
  RISCV_INSN_BLT,
  RISCV_INSN_BGEU,
  RISCV_INSN_BGE,
  RISCV_INSN_BEQ,
  //--------------------- RISCV_LOAD---------------------
  RISCV_INSN_LOAD,
  //--------------------- RISCV_VIOTA_M---------------------
  RISCV_INSN_VIOTA_M,
  //--------------------- RISCV_CLMULR---------------------
  RISCV_INSN_CLMULR,
  //--------------------- RISCV_VXMSTYPE---------------------
  RISCV_INSN_VXMS_VSBC,
  RISCV_INSN_VXMS_VADC,
  //--------------------- RISCV_CLZ---------------------
  RISCV_INSN_CLZ,
  //--------------------- RISCV_UTYPE---------------------
  RISCV_INSN_LUI,
  RISCV_INSN_AUIPC,
  //--------------------- RISCV_CLMULH---------------------
  RISCV_INSN_CLMULH,
  //--------------------- RISCV_FLI_H---------------------
  RISCV_INSN_FLI_H,
  //--------------------- RISCV_F_BIN_RM_TYPE_H---------------------
  RISCV_INSN_FSUB_H,
  RISCV_INSN_FMUL_H,
  RISCV_INSN_FDIV_H,
  RISCV_INSN_FADD_H,
  //--------------------- RISCV_VSETVLI---------------------
  RISCV_INSN_VSETVLI,
  //--------------------- RISCV_C_SEXT_B---------------------
  RISCV_INSN_C_SEXT_B,
  //--------------------- RISCV_VLUXSEGTYPE---------------------
  RISCV_INSN_VLUXSEGTYPE,
  //--------------------- RISCV_SHA512SUM1R---------------------
  RISCV_INSN_SHA512SUM1R,
  //--------------------- RISCV_VITYPE---------------------
  RISCV_INSN_VI_VXOR,
  RISCV_INSN_VI_VSSRL,
  RISCV_INSN_VI_VSSRA,
  RISCV_INSN_VI_VSRL,
  RISCV_INSN_VI_VSRA,
  RISCV_INSN_VI_VSLL,
  RISCV_INSN_VI_VSADDU,
  RISCV_INSN_VI_VSADD,
  RISCV_INSN_VI_VRSUB,
  RISCV_INSN_VI_VOR,
  RISCV_INSN_VI_VAND,
  RISCV_INSN_VI_VADD,
  //--------------------- RISCV_STORECON---------------------
  RISCV_INSN_STORECON,
  //--------------------- RISCV_VMVRTYPE---------------------
  RISCV_INSN_VMVRTYPE,
  //--------------------- RISCV_ZBKB_RTYPE---------------------
  RISCV_INSN_PACKH,
  RISCV_INSN_PACK,
  //--------------------- RISCV_VISG---------------------
  RISCV_INSN_VI_VSLIDEUP,
  RISCV_INSN_VI_VSLIDEDOWN,
  RISCV_INSN_VI_VRGATHER,
  //--------------------- RISCV_C_ADD---------------------
  RISCV_INSN_C_ADD,
  //--------------------- RISCV_FVFTYPE---------------------
  RISCV_INSN_VF_VSUB,
  RISCV_INSN_VF_VSLIDE1UP,
  RISCV_INSN_VF_VSLIDE1DOWN,
  RISCV_INSN_VF_VSGNJX,
  RISCV_INSN_VF_VSGNJN,
  RISCV_INSN_VF_VSGNJ,
  RISCV_INSN_VF_VRSUB,
  RISCV_INSN_VF_VRDIV,
  RISCV_INSN_VF_VMUL,
  RISCV_INSN_VF_VMIN,
  RISCV_INSN_VF_VMAX,
  RISCV_INSN_VF_VDIV,
  RISCV_INSN_VF_VADD,
  //--------------------- RISCV_FENCE_RESERVED---------------------
  RISCV_INSN_FENCE_RESERVED,
  //--------------------- RISCV_MASKTYPEI---------------------
  RISCV_INSN_MASKTYPEI,
  //--------------------- RISCV_FVVTYPE---------------------
  RISCV_INSN_FVV_VSUB,
  RISCV_INSN_FVV_VSGNJX,
  RISCV_INSN_FVV_VSGNJN,
  RISCV_INSN_FVV_VSGNJ,
  RISCV_INSN_FVV_VMUL,
  RISCV_INSN_FVV_VMIN,
  RISCV_INSN_FVV_VMAX,
  RISCV_INSN_FVV_VDIV,
  RISCV_INSN_FVV_VADD,
  //--------------------- RISCV_CPOPW---------------------
  RISCV_INSN_CPOPW,
  //--------------------- RISCV_C_LI_HINT---------------------
  RISCV_INSN_C_LI_HINT,
  //--------------------- RISCV_SHA256SUM1---------------------
  RISCV_INSN_SHA256SUM1,
  //--------------------- RISCV_VSUXSEGTYPE---------------------
  RISCV_INSN_VSUXSEGTYPE,
  //--------------------- RISCV_VIMCTYPE---------------------
  RISCV_INSN_VIMC_VMADC,
  //--------------------- RISCV_VIMSTYPE---------------------
  RISCV_INSN_VIMS_VADC,
  //--------------------- RISCV_MASKTYPEV---------------------
  RISCV_INSN_MASKTYPEV,
  //--------------------- RISCV_FVFMTYPE---------------------
  RISCV_INSN_VFM_VMFNE,
  RISCV_INSN_VFM_VMFLT,
  RISCV_INSN_VFM_VMFLE,
  RISCV_INSN_VFM_VMFGT,
  RISCV_INSN_VFM_VMFGE,
  RISCV_INSN_VFM_VMFEQ,
  //--------------------- RISCV_ADDIW---------------------
  RISCV_INSN_ADDIW,
  //--------------------- RISCV_MRET---------------------
  RISCV_INSN_MRET,
  //--------------------- RISCV_VLSEGFFTYPE---------------------
  RISCV_INSN_VLSEGFFTYPE,
  //--------------------- RISCV_C_ANDI---------------------
  RISCV_INSN_C_ANDI,
  //--------------------- RISCV_WVTYPE---------------------
  RISCV_INSN_WV_VSUBU,
  RISCV_INSN_WV_VSUB,
  RISCV_INSN_WV_VADDU,
  RISCV_INSN_WV_VADD,
  //--------------------- RISCV_C_SDSP---------------------
  RISCV_INSN_C_SDSP,
  //--------------------- RISCV_C_SUBW---------------------
  RISCV_INSN_C_SUBW,
  //--------------------- RISCV_VEXT4TYPE---------------------
  RISCV_INSN_VEXT4_ZVF4,
  RISCV_INSN_VEXT4_SVF4,
  //--------------------- RISCV_VSETVL---------------------
  RISCV_INSN_VSETVL,
  //--------------------- RISCV_C_SH---------------------
  RISCV_INSN_C_SH,
  //--------------------- RISCV_MVVCOMPRESS---------------------
  RISCV_INSN_MVVCOMPRESS,
  //--------------------- RISCV_FWVVTYPE---------------------
  RISCV_INSN_FWVV_VSUB,
  RISCV_INSN_FWVV_VMUL,
  RISCV_INSN_FWVV_VADD,
  //--------------------- RISCV_VMTYPE---------------------
  RISCV_INSN_VSM,
  RISCV_INSN_VLM,
  //--------------------- RISCV_FROUND_H---------------------
  RISCV_INSN_FROUND_H,
  //--------------------- RISCV_C_JAL---------------------
  RISCV_INSN_C_JAL,
  //--------------------- RISCV_SFENCE_VMA---------------------
  RISCV_INSN_SFENCE_VMA,
  //--------------------- RISCV_NVSTYPE---------------------
  RISCV_INSN_NVS_VNSRL,
  RISCV_INSN_NVS_VNSRA,
  //--------------------- RISCV_FROUND_S---------------------
  RISCV_INSN_FROUND_S,
  //--------------------- RISCV_NISTYPE---------------------
  RISCV_INSN_NIS_VNSRL,
  RISCV_INSN_NIS_VNSRA,
  //--------------------- RISCV_C_SLLI---------------------
  RISCV_INSN_C_SLLI,
  //--------------------- RISCV_VXMTYPE---------------------
  RISCV_INSN_VXM_VMSBC,
  RISCV_INSN_VXM_VMADC,
  //--------------------- RISCV_FENCEI---------------------
  RISCV_INSN_FENCEI,
  //--------------------- RISCV_VFMVSF---------------------
  RISCV_INSN_VFMVSF,
  //--------------------- RISCV_VEXT8TYPE---------------------
  RISCV_INSN_VEXT8_ZVF8,
  RISCV_INSN_VEXT8_SVF8,
  //--------------------- RISCV_C_OR---------------------
  RISCV_INSN_C_OR,
  //--------------------- RISCV_FWVFMATYPE---------------------
  RISCV_INSN_FWVF_VNMSAC,
  RISCV_INSN_FWVF_VNMACC,
  RISCV_INSN_FWVF_VMSAC,
  RISCV_INSN_FWVF_VMACC,
  //--------------------- RISCV_SHIFTIOP---------------------
  RISCV_INSN_SRLI,
  RISCV_INSN_SRAI,
  RISCV_INSN_SLLI,
  //--------------------- RISCV_DIVW---------------------
  RISCV_INSN_DIVW,
  //--------------------- RISCV_C_ZEXT_B---------------------
  RISCV_INSN_C_ZEXT_B,
  //--------------------- RISCV_C_MV---------------------
  RISCV_INSN_C_MV,
  //--------------------- RISCV_VIMTYPE---------------------
  RISCV_INSN_VIM_VMADC,
  //--------------------- RISCV_LOADRES---------------------
  RISCV_INSN_LOADRES,
  //--------------------- RISCV_C_J---------------------
  RISCV_INSN_C_J,
  //--------------------- RISCV_AES32ESI---------------------
  RISCV_INSN_AES32ESI,
  //--------------------- RISCV_C_BEQZ---------------------
  RISCV_INSN_C_BEQZ,
  //--------------------- RISCV_SHA512SUM0---------------------
  RISCV_INSN_SHA512SUM0,
  //--------------------- RISCV_SHA512SUM0R---------------------
  RISCV_INSN_SHA512SUM0R,
  //--------------------- RISCV_REMW---------------------
  RISCV_INSN_REMW,
  //--------------------- RISCV_VFMV---------------------
  RISCV_INSN_VFMV,
  //--------------------- RISCV_C_SEXT_H---------------------
  RISCV_INSN_C_SEXT_H,
  //--------------------- RISCV_WMVXTYPE---------------------
  RISCV_INSN_WMVX_VWMACCUS,
  RISCV_INSN_WMVX_VWMACCU,
  RISCV_INSN_WMVX_VWMACCSU,
  RISCV_INSN_WMVX_VWMACC,
  //--------------------- RISCV_C_FSW---------------------
  RISCV_INSN_C_FSW,
  //--------------------- RISCV_C_SW---------------------
  RISCV_INSN_C_SW,
  //--------------------- RISCV_ZBS_RTYPE---------------------
  RISCV_INSN_BSET,
  RISCV_INSN_BINV,
  RISCV_INSN_BEXT,
  RISCV_INSN_BCLR,
  //--------------------- RISCV_C_SUB---------------------
  RISCV_INSN_C_SUB,
  //--------------------- RISCV_VFUNARY0---------------------
  RISCV_INSN_FV_CVT_X_F,
  RISCV_INSN_FV_CVT_XU_F,
  RISCV_INSN_FV_CVT_RTZ_X_F,
  RISCV_INSN_FV_CVT_RTZ_XU_F,
  RISCV_INSN_FV_CVT_F_XU,
  RISCV_INSN_FV_CVT_F_X,
  //--------------------- RISCV_FROUNDNX_S---------------------
  RISCV_INSN_FROUNDNX_S,
  //--------------------- RISCV_ZICBOZ---------------------
  RISCV_INSN_ZICBOZ,
  //--------------------- RISCV_SFENCE_W_INVAL---------------------
  RISCV_INSN_SFENCE_W_INVAL,
  //--------------------- RISCV_C_JR---------------------
  RISCV_INSN_C_JR,
  //--------------------- RISCV_C_NOT---------------------
  RISCV_INSN_C_NOT,
  //--------------------- RISCV_ZBB_EXTOP---------------------
  RISCV_INSN_ZEXTH,
  RISCV_INSN_SEXTH,
  RISCV_INSN_SEXTB,
  //--------------------- RISCV_MVVTYPE---------------------
  RISCV_INSN_MVV_VREMU,
  RISCV_INSN_MVV_VREM,
  RISCV_INSN_MVV_VMULHU,
  RISCV_INSN_MVV_VMULHSU,
  RISCV_INSN_MVV_VMULH,
  RISCV_INSN_MVV_VMUL,
  RISCV_INSN_MVV_VDIVU,
  RISCV_INSN_MVV_VDIV,
  RISCV_INSN_MVV_VASUBU,
  RISCV_INSN_MVV_VASUB,
  RISCV_INSN_MVV_VAADDU,
  RISCV_INSN_MVV_VAADD,
  //--------------------- RISCV_FVFMATYPE---------------------
  RISCV_INSN_VF_VNMSUB,
  RISCV_INSN_VF_VNMSAC,
  RISCV_INSN_VF_VNMADD,
  RISCV_INSN_VF_VNMACC,
  RISCV_INSN_VF_VMSUB,
  RISCV_INSN_VF_VMSAC,
  RISCV_INSN_VF_VMADD,
  RISCV_INSN_VF_VMACC,
  //--------------------- RISCV_FMAXM_H---------------------
  RISCV_INSN_FMAXM_H,
  //--------------------- RISCV_SHA256SUM0---------------------
  RISCV_INSN_SHA256SUM0,
  //--------------------- RISCV_ZBS_IOP---------------------
  RISCV_INSN_BSETI,
  RISCV_INSN_BINVI,
  RISCV_INSN_BEXTI,
  RISCV_INSN_BCLRI,
  //--------------------- RISCV_C_XOR---------------------
  RISCV_INSN_C_XOR,
  //--------------------- RISCV_FMINM_H---------------------
  RISCV_INSN_FMINM_H,
  //--------------------- RISCV_C_LUI_HINT---------------------
  RISCV_INSN_C_LUI_HINT,
  //--------------------- RISCV_VVMCTYPE---------------------
  RISCV_INSN_VVMC_VMSBC,
  RISCV_INSN_VVMC_VMADC,
  //--------------------- RISCV_F_BIN_RM_TYPE_S---------------------
  RISCV_INSN_FSUB_S,
  RISCV_INSN_FMUL_S,
  RISCV_INSN_FDIV_S,
  RISCV_INSN_FADD_S,
  //--------------------- RISCV_SINVAL_VMA---------------------
  RISCV_INSN_SINVAL_VMA,
  //--------------------- RISCV_MOVETYPEX---------------------
  RISCV_INSN_MOVETYPEX,
  //--------------------- RISCV_C_BNEZ---------------------
  RISCV_INSN_C_BNEZ,
  //--------------------- RISCV_FWVVMATYPE---------------------
  RISCV_INSN_FWVV_VNMSAC,
  RISCV_INSN_FWVV_VNMACC,
  RISCV_INSN_FWVV_VMSAC,
  RISCV_INSN_FWVV_VMACC,
  //--------------------- RISCV_AES64KS1I---------------------
  RISCV_INSN_AES64KS1I,
  //--------------------- RISCV_RMVVTYPE---------------------
  RISCV_INSN_MVV_VREDXOR,
  RISCV_INSN_MVV_VREDSUM,
  RISCV_INSN_MVV_VREDOR,
  RISCV_INSN_MVV_VREDMINU,
  RISCV_INSN_MVV_VREDMIN,
  RISCV_INSN_MVV_VREDMAXU,
  RISCV_INSN_MVV_VREDMAX,
  RISCV_INSN_MVV_VREDAND,
  //--------------------- RISCV_CLZW---------------------
  RISCV_INSN_CLZW,
  //--------------------- RISCV_REM---------------------
  RISCV_INSN_REM,
  //--------------------- RISCV_C_EBREAK---------------------
  RISCV_INSN_C_EBREAK,
  //--------------------- RISCV_AES64ESM---------------------
  RISCV_INSN_AES64ESM,
  //--------------------- RISCV_VFNUNARY0---------------------
  RISCV_INSN_FNV_CVT_X_F,
  RISCV_INSN_FNV_CVT_XU_F,
  RISCV_INSN_FNV_CVT_RTZ_X_F,
  RISCV_INSN_FNV_CVT_RTZ_XU_F,
  RISCV_INSN_FNV_CVT_ROD_F_F,
  RISCV_INSN_FNV_CVT_F_XU,
  RISCV_INSN_FNV_CVT_F_X,
  RISCV_INSN_FNV_CVT_F_F,
  //--------------------- RISCV_VFWUNARY0---------------------
  RISCV_INSN_FWV_CVT_X_F,
  RISCV_INSN_FWV_CVT_XU_F,
  RISCV_INSN_FWV_CVT_RTZ_X_F,
  RISCV_INSN_FWV_CVT_RTZ_XU_F,
  RISCV_INSN_FWV_CVT_F_XU,
  RISCV_INSN_FWV_CVT_F_X,
  RISCV_INSN_FWV_CVT_F_F,
  //--------------------- RISCV_MOVETYPEV---------------------
  RISCV_INSN_MOVETYPEV,
  //--------------------- RISCV_VFUNARY1---------------------
  RISCV_INSN_FVV_VSQRT,
  RISCV_INSN_FVV_VRSQRT7,
  RISCV_INSN_FVV_VREC7,
  RISCV_INSN_FVV_VCLASS,
  //--------------------- RISCV_FWVFTYPE---------------------
  RISCV_INSN_FWVF_VSUB,
  RISCV_INSN_FWVF_VMUL,
  RISCV_INSN_FWVF_VADD,
  //--------------------- RISCV_ZBA_RTYPE---------------------
  RISCV_INSN_SH3ADD,
  RISCV_INSN_SH2ADD,
  RISCV_INSN_SH1ADD,
  //--------------------- RISCV_C_SRLI---------------------
  RISCV_INSN_C_SRLI,
  //--------------------- RISCV_VSRETYPE---------------------
  RISCV_INSN_VSRETYPE,
  //--------------------- RISCV_C_SLLI_HINT---------------------
  RISCV_INSN_C_SLLI_HINT,
  //--------------------- RISCV_WVVTYPE---------------------
  RISCV_INSN_WVV_VWMULU,
  RISCV_INSN_WVV_VWMULSU,
  RISCV_INSN_WVV_VWMUL,
  RISCV_INSN_WVV_VSUBU,
  RISCV_INSN_WVV_VSUB,
  RISCV_INSN_WVV_VADDU,
  RISCV_INSN_WVV_VADD,
  //--------------------- RISCV_AES64DSM---------------------
  RISCV_INSN_AES64DSM,
  //--------------------- RISCV_C_LI---------------------
  RISCV_INSN_C_LI,
  //--------------------- RISCV_CSR---------------------
  RISCV_INSN_CSRRW,
  RISCV_INSN_CSRRS,
  RISCV_INSN_CSRRC,
  //--------------------- RISCV_C_SRAI---------------------
  RISCV_INSN_C_SRAI,
  //--------------------- RISCV_FMVP_D_X---------------------
  RISCV_INSN_FMVP_D_X,
  //--------------------- RISCV_C_LBU---------------------
  RISCV_INSN_C_LBU,
  //--------------------- RISCV_F_UN_RM_TYPE_S---------------------
  RISCV_INSN_FSQRT_S,
  RISCV_INSN_FCVT_W_S,
  RISCV_INSN_FCVT_WU_S,
  RISCV_INSN_FCVT_S_WU,
  RISCV_INSN_FCVT_S_W,
  RISCV_INSN_FCVT_S_LU,
  RISCV_INSN_FCVT_S_L,
  RISCV_INSN_FCVT_L_S,
  RISCV_INSN_FCVT_LU_S,
  //--------------------- RISCV_RTYPEW---------------------
  RISCV_INSN_SUBW,
  RISCV_INSN_SRLW,
  RISCV_INSN_SRAW,
  RISCV_INSN_SLLW,
  RISCV_INSN_ADDW,
  //--------------------- RISCV_WMVVTYPE---------------------
  RISCV_INSN_WMVV_VWMACCU,
  RISCV_INSN_WMVV_VWMACCSU,
  RISCV_INSN_WMVV_VWMACC,
  //--------------------- RISCV_MULW---------------------
  RISCV_INSN_MULW,
  //--------------------- RISCV_VVCMPTYPE---------------------
  RISCV_INSN_VVCMP_VMSNE,
  RISCV_INSN_VVCMP_VMSLTU,
  RISCV_INSN_VVCMP_VMSLT,
  RISCV_INSN_VVCMP_VMSLEU,
  RISCV_INSN_VVCMP_VMSLE,
  RISCV_INSN_VVCMP_VMSEQ,
  //--------------------- RISCV_ILLEGAL---------------------
  RISCV_INSN_ILLEGAL,
  //--------------------- RISCV_BREV8---------------------
  RISCV_INSN_BREV8,
  //--------------------- RISCV_AES32DSMI---------------------
  RISCV_INSN_AES32DSMI,
  //--------------------- RISCV_C_FSD---------------------
  RISCV_INSN_C_FSD,
  //--------------------- RISCV_C_ADDW---------------------
  RISCV_INSN_C_ADDW,
  //--------------------- RISCV_VCPOP_M---------------------
  RISCV_INSN_VCPOP_M,
  //--------------------- RISCV_SHA256SIG1---------------------
  RISCV_INSN_SHA256SIG1,
  //--------------------- RISCV_MVXTYPE---------------------
  RISCV_INSN_MVX_VSLIDE1UP,
  RISCV_INSN_MVX_VSLIDE1DOWN,
  RISCV_INSN_MVX_VREMU,
  RISCV_INSN_MVX_VREM,
  RISCV_INSN_MVX_VMULHU,
  RISCV_INSN_MVX_VMULHSU,
  RISCV_INSN_MVX_VMULH,
  RISCV_INSN_MVX_VMUL,
  RISCV_INSN_MVX_VDIVU,
  RISCV_INSN_MVX_VDIV,
  RISCV_INSN_MVX_VASUBU,
  RISCV_INSN_MVX_VASUB,
  RISCV_INSN_MVX_VAADDU,
  RISCV_INSN_MVX_VAADD,
};
#endif


//> Group of RISCV instructions
typedef enum riscv_insn_group {
  	RISCV_GRP_INVALID = 0, ///< = CS_GRP_INVALID

  	// Generic groups
  	// all jump instructions (conditional+direct+indirect jumps)
  	RISCV_GRP_JUMP,	///< = CS_GRP_JUMP
  	// all call instructions
  	RISCV_GRP_CALL,	///< = CS_GRP_CALL
  	// all return instructions
  	RISCV_GRP_RET,	///< = CS_GRP_RET
  	// all interrupt instructions (int+syscall)
  	RISCV_GRP_INT,	///< = CS_GRP_INT
  	// all interrupt return instructions
  	RISCV_GRP_IRET,	///< = CS_GRP_IRET
  	// all privileged instructions
  	RISCV_GRP_PRIVILEGE,	///< = CS_GRP_PRIVILEGE
  	// all relative branching instructions
  	RISCV_GRP_BRANCH_RELATIVE, ///< = CS_GRP_BRANCH_RELATIVE
  
  	// Architecture-specific groups
  	RISCV_GRP_ISRV32 = 128,
  	RISCV_GRP_ISRV64,
  	RISCV_GRP_HASSTDEXTA,
  	RISCV_GRP_HASSTDEXTC,
  	RISCV_GRP_HASSTDEXTD,
  	RISCV_GRP_HASSTDEXTF,
  	RISCV_GRP_HASSTDEXTM,
  	/*
  	RISCV_GRP_ISRVA,
  	RISCV_GRP_ISRVC,
  	RISCV_GRP_ISRVD,
  	RISCV_GRP_ISRVCD,
  	RISCV_GRP_ISRVF,
  	RISCV_GRP_ISRV32C,
  	RISCV_GRP_ISRV32CF,
  	RISCV_GRP_ISRVM,
  	RISCV_GRP_ISRV64A,
  	RISCV_GRP_ISRV64C,
  	RISCV_GRP_ISRV64D,
  	RISCV_GRP_ISRV64F,
  	RISCV_GRP_ISRV64M,
  	*/
  	RISCV_GRP_ENDING,
} riscv_insn_group;

#ifdef __cplusplus
}
#endif

#endif


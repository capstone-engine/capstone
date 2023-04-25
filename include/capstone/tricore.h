#ifndef CAPSTONE_TRICORE_H
#define CAPSTONE_TRICORE_H

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2014 */

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_MSC_VER) || !defined(_KERNEL_MODE)
#include <stdint.h>
#endif

#include "platform.h"

#ifdef _MSC_VER
#pragma warning(disable : 4201)
#endif

//> Operand type for instruction's operands
typedef enum tricore_op_type {
	TRICORE_OP_INVALID = 0, // = CS_OP_INVALID (Uninitialized).
	TRICORE_OP_REG, // = CS_OP_REG (Register operand).
	TRICORE_OP_IMM, // = CS_OP_IMM (Immediate operand).
	TRICORE_OP_MEM, // = CS_OP_MEM (Memory operand).
} tricore_op_type;

// Instruction's operand referring to memory
// This is associated with TRICORE_OP_MEM operand type above
typedef struct tricore_op_mem {
	uint8_t base; // base register
	int32_t disp; // displacement/offset value
} tricore_op_mem;

// Instruction operand
typedef struct cs_tricore_op {
	tricore_op_type type; // operand type
	union {
		unsigned int reg; // register value for REG operand
		int32_t imm; // immediate value for IMM operand
		tricore_op_mem mem; // base/disp value for MEM operand
	};
} cs_tricore_op;

// Instruction structure
typedef struct cs_tricore {
	// Number of operands of this instruction,
	// or 0 when instruction has no operand.
	uint8_t op_count;
	cs_tricore_op operands[8]; // operands for this instruction.
} cs_tricore;

//> TriCore registers
typedef enum tricore_reg {
	// generate content <TriCoreGenCSRegEnum.inc> begin
	// clang-format off

/* Capstone Disassembly Engine, https://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */
/* By Rot127 <unisono@quyllur.org>, 2023 */

/* Auto generated file. Do not edit. */
/* Code generator: https://github.com/capstone-engine/capstone/tree/next/suite/auto-sync */

	TriCore_REG_INVALID = 0,
	TriCore_REG_FCX = 1,
	TriCore_REG_PC = 2,
	TriCore_REG_PCXI = 3,
	TriCore_REG_PSW = 4,
	TriCore_REG_A0 = 5,
	TriCore_REG_A1 = 6,
	TriCore_REG_A2 = 7,
	TriCore_REG_A3 = 8,
	TriCore_REG_A4 = 9,
	TriCore_REG_A5 = 10,
	TriCore_REG_A6 = 11,
	TriCore_REG_A7 = 12,
	TriCore_REG_A8 = 13,
	TriCore_REG_A9 = 14,
	TriCore_REG_A10 = 15,
	TriCore_REG_A11 = 16,
	TriCore_REG_A12 = 17,
	TriCore_REG_A13 = 18,
	TriCore_REG_A14 = 19,
	TriCore_REG_A15 = 20,
	TriCore_REG_D0 = 21,
	TriCore_REG_D1 = 22,
	TriCore_REG_D2 = 23,
	TriCore_REG_D3 = 24,
	TriCore_REG_D4 = 25,
	TriCore_REG_D5 = 26,
	TriCore_REG_D6 = 27,
	TriCore_REG_D7 = 28,
	TriCore_REG_D8 = 29,
	TriCore_REG_D9 = 30,
	TriCore_REG_D10 = 31,
	TriCore_REG_D11 = 32,
	TriCore_REG_D12 = 33,
	TriCore_REG_D13 = 34,
	TriCore_REG_D14 = 35,
	TriCore_REG_D15 = 36,
	TriCore_REG_E0 = 37,
	TriCore_REG_E2 = 38,
	TriCore_REG_E4 = 39,
	TriCore_REG_E6 = 40,
	TriCore_REG_E8 = 41,
	TriCore_REG_E10 = 42,
	TriCore_REG_E12 = 43,
	TriCore_REG_E14 = 44,
	TriCore_REG_P0 = 45,
	TriCore_REG_P2 = 46,
	TriCore_REG_P4 = 47,
	TriCore_REG_P6 = 48,
	TriCore_REG_P8 = 49,
	TriCore_REG_P10 = 50,
	TriCore_REG_P12 = 51,
	TriCore_REG_P14 = 52,
	TriCore_REG_A0_A1 = 53,
	TriCore_REG_A2_A3 = 54,
	TriCore_REG_A4_A5 = 55,
	TriCore_REG_A6_A7 = 56,
	TriCore_REG_A8_A9 = 57,
	TriCore_REG_A10_A11 = 58,
	TriCore_REG_A12_A13 = 59,
	TriCore_REG_A14_A15 = 60,
	TriCore_REG_ENDING, // 61

	// clang-format on
	// generate content <TriCoreGenCSRegEnum.inc> end
} tricore_reg;

//> TriCore instruction
typedef enum tricore_insn {
	TriCore_INS_INVALID = 0,
	// generate content <TriCoreGenCSInsnEnum.inc> begin
	// clang-format off

/* Capstone Disassembly Engine, https://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */
/* By Rot127 <unisono@quyllur.org>, 2023 */

/* Auto generated file. Do not edit. */
/* Code generator: https://github.com/capstone-engine/capstone/tree/next/suite/auto-sync */

  TriCore_INS_XOR_T,
  TriCore_INS_ABSDIFS_B,
  TriCore_INS_ABSDIFS_H,
  TriCore_INS_ABSDIFS,
  TriCore_INS_ABSDIF_B,
  TriCore_INS_ABSDIF_H,
  TriCore_INS_ABSDIF,
  TriCore_INS_ABSS_B,
  TriCore_INS_ABSS_H,
  TriCore_INS_ABSS,
  TriCore_INS_ABS_B,
  TriCore_INS_ABS_H,
  TriCore_INS_ABS,
  TriCore_INS_ADDC,
  TriCore_INS_ADDIH_A,
  TriCore_INS_ADDIH,
  TriCore_INS_ADDI,
  TriCore_INS_ADDSC_AT,
  TriCore_INS_ADDSC_A,
  TriCore_INS_ADDS_BU,
  TriCore_INS_ADDS_B,
  TriCore_INS_ADDS_H,
  TriCore_INS_ADDS_HU,
  TriCore_INS_ADDS_U,
  TriCore_INS_ADDS,
  TriCore_INS_ADDX,
  TriCore_INS_ADD_A,
  TriCore_INS_ADD_B,
  TriCore_INS_ADD_F,
  TriCore_INS_ADD_H,
  TriCore_INS_ADD,
  TriCore_INS_ANDN_T,
  TriCore_INS_ANDN,
  TriCore_INS_AND_ANDN_T,
  TriCore_INS_AND_AND_T,
  TriCore_INS_AND_EQ,
  TriCore_INS_AND_GE_U,
  TriCore_INS_AND_GE,
  TriCore_INS_AND_LT_U,
  TriCore_INS_AND_LT,
  TriCore_INS_AND_NE,
  TriCore_INS_AND_NOR_T,
  TriCore_INS_AND_OR_T,
  TriCore_INS_AND_T,
  TriCore_INS_AND,
  TriCore_INS_BISR,
  TriCore_INS_BMERGE,
  TriCore_INS_BSPLIT,
  TriCore_INS_CACHEA_I,
  TriCore_INS_CACHEA_WI,
  TriCore_INS_CACHEA_W,
  TriCore_INS_CACHEI_I,
  TriCore_INS_CACHEI_WI,
  TriCore_INS_CACHEI_W,
  TriCore_INS_CADDN_A,
  TriCore_INS_CADDN,
  TriCore_INS_CADD_A,
  TriCore_INS_CADD,
  TriCore_INS_CALLA,
  TriCore_INS_CALLI,
  TriCore_INS_CALL,
  TriCore_INS_CLO_B,
  TriCore_INS_CLO_H,
  TriCore_INS_CLO,
  TriCore_INS_CLS_B,
  TriCore_INS_CLS_H,
  TriCore_INS_CLS,
  TriCore_INS_CLZ_B,
  TriCore_INS_CLZ_H,
  TriCore_INS_CLZ,
  TriCore_INS_CMOVN,
  TriCore_INS_CMOV,
  TriCore_INS_CMPSWAP_W,
  TriCore_INS_CMP_F,
  TriCore_INS_CRC32B_W,
  TriCore_INS_CRC32L_W,
  TriCore_INS_CRC32_B,
  TriCore_INS_CRCN,
  TriCore_INS_CSUBN_A,
  TriCore_INS_CSUBN,
  TriCore_INS_CSUB_A,
  TriCore_INS_CSUB,
  TriCore_INS_DEBUG,
  TriCore_INS_DEXTR,
  TriCore_INS_DIFSC_A,
  TriCore_INS_DISABLE,
  TriCore_INS_DIV_F,
  TriCore_INS_DIV_U,
  TriCore_INS_DIV,
  TriCore_INS_DSYNC,
  TriCore_INS_DVADJ,
  TriCore_INS_DVINIT_BU,
  TriCore_INS_DVINIT_B,
  TriCore_INS_DVINIT_HU,
  TriCore_INS_DVINIT_H,
  TriCore_INS_DVINIT_U,
  TriCore_INS_DVINIT,
  TriCore_INS_DVSTEP_U,
  TriCore_INS_DVSTEP,
  TriCore_INS_ENABLE,
  TriCore_INS_EQANY_B,
  TriCore_INS_EQANY_H,
  TriCore_INS_EQZ_A,
  TriCore_INS_EQ_A,
  TriCore_INS_EQ_B,
  TriCore_INS_EQ_H,
  TriCore_INS_EQ_W,
  TriCore_INS_EQ,
  TriCore_INS_EXTR_U,
  TriCore_INS_EXTR,
  TriCore_INS_FCALLA,
  TriCore_INS_FCALLI,
  TriCore_INS_FCALL,
  TriCore_INS_FRET,
  TriCore_INS_FTOHP,
  TriCore_INS_FTOIZ,
  TriCore_INS_FTOI,
  TriCore_INS_FTOQ31Z,
  TriCore_INS_FTOQ31,
  TriCore_INS_FTOUZ,
  TriCore_INS_FTOU,
  TriCore_INS_GE_A,
  TriCore_INS_GE_U,
  TriCore_INS_GE,
  TriCore_INS_HPTOF,
  TriCore_INS_IMASK,
  TriCore_INS_INSERT,
  TriCore_INS_INSN_T,
  TriCore_INS_INS_T,
  TriCore_INS_ISYNC,
  TriCore_INS_ITOF,
  TriCore_INS_IXMAX_U,
  TriCore_INS_IXMAX,
  TriCore_INS_IXMIN_U,
  TriCore_INS_IXMIN,
  TriCore_INS_JA,
  TriCore_INS_JEQ_A,
  TriCore_INS_JEQ,
  TriCore_INS_JGEZ,
  TriCore_INS_JGE_U,
  TriCore_INS_JGE,
  TriCore_INS_JGTZ,
  TriCore_INS_JI,
  TriCore_INS_JLA,
  TriCore_INS_JLEZ,
  TriCore_INS_JLI,
  TriCore_INS_JLTZ,
  TriCore_INS_JLT_U,
  TriCore_INS_JLT,
  TriCore_INS_JL,
  TriCore_INS_JNED,
  TriCore_INS_JNEI,
  TriCore_INS_JNE_A,
  TriCore_INS_JNE,
  TriCore_INS_JNZ_A,
  TriCore_INS_JNZ_T,
  TriCore_INS_JNZ,
  TriCore_INS_JZ_A,
  TriCore_INS_JZ_T,
  TriCore_INS_JZ,
  TriCore_INS_J,
  TriCore_INS_LDLCX,
  TriCore_INS_LDMST,
  TriCore_INS_LDUCX,
  TriCore_INS_LD_A,
  TriCore_INS_LD_BU,
  TriCore_INS_LD_B,
  TriCore_INS_LD_DA,
  TriCore_INS_LD_D,
  TriCore_INS_LD_HU,
  TriCore_INS_LD_H,
  TriCore_INS_LD_Q,
  TriCore_INS_LD_W,
  TriCore_INS_LEA,
  TriCore_INS_LHA,
  TriCore_INS_LOOPU,
  TriCore_INS_LOOP,
  TriCore_INS_LT_A,
  TriCore_INS_LT_B,
  TriCore_INS_LT_BU,
  TriCore_INS_LT_H,
  TriCore_INS_LT_HU,
  TriCore_INS_LT_U,
  TriCore_INS_LT_W,
  TriCore_INS_LT_WU,
  TriCore_INS_LT,
  TriCore_INS_MADDMS_H,
  TriCore_INS_MADDMS_U,
  TriCore_INS_MADDMS,
  TriCore_INS_MADDM_H,
  TriCore_INS_MADDM_Q,
  TriCore_INS_MADDM_U,
  TriCore_INS_MADDM,
  TriCore_INS_MADDRS_H,
  TriCore_INS_MADDRS_Q,
  TriCore_INS_MADDR_H,
  TriCore_INS_MADDR_Q,
  TriCore_INS_MADDSUMS_H,
  TriCore_INS_MADDSUM_H,
  TriCore_INS_MADDSURS_H,
  TriCore_INS_MADDSUR_H,
  TriCore_INS_MADDSUS_H,
  TriCore_INS_MADDSU_H,
  TriCore_INS_MADDS_H,
  TriCore_INS_MADDS_Q,
  TriCore_INS_MADDS_U,
  TriCore_INS_MADDS,
  TriCore_INS_MADD_F,
  TriCore_INS_MADD_H,
  TriCore_INS_MADD_Q,
  TriCore_INS_MADD_U,
  TriCore_INS_MADD,
  TriCore_INS_MAX_B,
  TriCore_INS_MAX_BU,
  TriCore_INS_MAX_H,
  TriCore_INS_MAX_HU,
  TriCore_INS_MAX_U,
  TriCore_INS_MAX,
  TriCore_INS_MFCR,
  TriCore_INS_MIN_B,
  TriCore_INS_MIN_BU,
  TriCore_INS_MIN_H,
  TriCore_INS_MIN_HU,
  TriCore_INS_MIN_U,
  TriCore_INS_MIN,
  TriCore_INS_MOVH_A,
  TriCore_INS_MOVH,
  TriCore_INS_MOVZ_A,
  TriCore_INS_MOV_AA,
  TriCore_INS_MOV_A,
  TriCore_INS_MOV_D,
  TriCore_INS_MOV_U,
  TriCore_INS_MOV,
  TriCore_INS_MSUBADMS_H,
  TriCore_INS_MSUBADM_H,
  TriCore_INS_MSUBADRS_H,
  TriCore_INS_MSUBADR_H,
  TriCore_INS_MSUBADS_H,
  TriCore_INS_MSUBAD_H,
  TriCore_INS_MSUBMS_H,
  TriCore_INS_MSUBMS_U,
  TriCore_INS_MSUBMS,
  TriCore_INS_MSUBM_H,
  TriCore_INS_MSUBM_Q,
  TriCore_INS_MSUBM_U,
  TriCore_INS_MSUBM,
  TriCore_INS_MSUBRS_H,
  TriCore_INS_MSUBRS_Q,
  TriCore_INS_MSUBR_H,
  TriCore_INS_MSUBR_Q,
  TriCore_INS_MSUBS_H,
  TriCore_INS_MSUBS_Q,
  TriCore_INS_MSUBS_U,
  TriCore_INS_MSUBS,
  TriCore_INS_MSUB_F,
  TriCore_INS_MSUB_H,
  TriCore_INS_MSUB_Q,
  TriCore_INS_MSUB_U,
  TriCore_INS_MSUB,
  TriCore_INS_MTCR,
  TriCore_INS_MULMS_H,
  TriCore_INS_MULM_H,
  TriCore_INS_MULM_U,
  TriCore_INS_MULM,
  TriCore_INS_MULR_H,
  TriCore_INS_MULR_Q,
  TriCore_INS_MULS_U,
  TriCore_INS_MULS,
  TriCore_INS_MUL_F,
  TriCore_INS_MUL_H,
  TriCore_INS_MUL_Q,
  TriCore_INS_MUL_U,
  TriCore_INS_MUL,
  TriCore_INS_NAND_T,
  TriCore_INS_NAND,
  TriCore_INS_NEZ_A,
  TriCore_INS_NE_A,
  TriCore_INS_NE,
  TriCore_INS_NOP,
  TriCore_INS_NOR_T,
  TriCore_INS_NOR,
  TriCore_INS_NOT,
  TriCore_INS_ORN_T,
  TriCore_INS_ORN,
  TriCore_INS_OR_ANDN_T,
  TriCore_INS_OR_AND_T,
  TriCore_INS_OR_EQ,
  TriCore_INS_OR_GE_U,
  TriCore_INS_OR_GE,
  TriCore_INS_OR_LT_U,
  TriCore_INS_OR_LT,
  TriCore_INS_OR_NE,
  TriCore_INS_OR_NOR_T,
  TriCore_INS_OR_OR_T,
  TriCore_INS_OR_T,
  TriCore_INS_OR,
  TriCore_INS_PACK,
  TriCore_INS_PARITY,
  TriCore_INS_POPCNT_W,
  TriCore_INS_Q31TOF,
  TriCore_INS_QSEED_F,
  TriCore_INS_RESTORE,
  TriCore_INS_RET,
  TriCore_INS_RFE,
  TriCore_INS_RFM,
  TriCore_INS_RSLCX,
  TriCore_INS_RSTV,
  TriCore_INS_RSUBS_U,
  TriCore_INS_RSUBS,
  TriCore_INS_RSUB,
  TriCore_INS_SAT_BU,
  TriCore_INS_SAT_B,
  TriCore_INS_SAT_HU,
  TriCore_INS_SAT_H,
  TriCore_INS_SELN_A,
  TriCore_INS_SELN,
  TriCore_INS_SEL_A,
  TriCore_INS_SEL,
  TriCore_INS_SHAS,
  TriCore_INS_SHA_B,
  TriCore_INS_SHA_H,
  TriCore_INS_SHA,
  TriCore_INS_SHUFFLE,
  TriCore_INS_SH_ANDN_T,
  TriCore_INS_SH_AND_T,
  TriCore_INS_SH_B,
  TriCore_INS_SH_EQ,
  TriCore_INS_SH_GE_U,
  TriCore_INS_SH_GE,
  TriCore_INS_SH_H,
  TriCore_INS_SH_LT_U,
  TriCore_INS_SH_LT,
  TriCore_INS_SH_NAND_T,
  TriCore_INS_SH_NE,
  TriCore_INS_SH_NOR_T,
  TriCore_INS_SH_ORN_T,
  TriCore_INS_SH_OR_T,
  TriCore_INS_SH_XNOR_T,
  TriCore_INS_SH_XOR_T,
  TriCore_INS_SH,
  TriCore_INS_STLCX,
  TriCore_INS_STUCX,
  TriCore_INS_ST_A,
  TriCore_INS_ST_B,
  TriCore_INS_ST_DA,
  TriCore_INS_ST_D,
  TriCore_INS_ST_H,
  TriCore_INS_ST_Q,
  TriCore_INS_ST_T,
  TriCore_INS_ST_W,
  TriCore_INS_SUBC,
  TriCore_INS_SUBSC_A,
  TriCore_INS_SUBS_BU,
  TriCore_INS_SUBS_B,
  TriCore_INS_SUBS_HU,
  TriCore_INS_SUBS_H,
  TriCore_INS_SUBS_U,
  TriCore_INS_SUBS,
  TriCore_INS_SUBX,
  TriCore_INS_SUB_A,
  TriCore_INS_SUB_B,
  TriCore_INS_SUB_F,
  TriCore_INS_SUB_H,
  TriCore_INS_SUB,
  TriCore_INS_SVLCX,
  TriCore_INS_SWAPMSK_W,
  TriCore_INS_SWAP_A,
  TriCore_INS_SWAP_W,
  TriCore_INS_SYSCALL,
  TriCore_INS_TLBDEMAP,
  TriCore_INS_TLBFLUSH_A,
  TriCore_INS_TLBFLUSH_B,
  TriCore_INS_TLBMAP,
  TriCore_INS_TLBPROBE_A,
  TriCore_INS_TLBPROBE_I,
  TriCore_INS_TRAPSV,
  TriCore_INS_TRAPV,
  TriCore_INS_UNPACK,
  TriCore_INS_UPDFL,
  TriCore_INS_UTOF,
  TriCore_INS_WAIT,
  TriCore_INS_XNOR_T,
  TriCore_INS_XNOR,
  TriCore_INS_XOR_EQ,
  TriCore_INS_XOR_GE_U,
  TriCore_INS_XOR_GE,
  TriCore_INS_XOR_LT_U,
  TriCore_INS_XOR_LT,
  TriCore_INS_XOR_NE,
  TriCore_INS_XOR,

	// clang-format on
	// generate content <TriCoreGenCSInsnEnum.inc> end
	TriCore_INS_ENDING, // <-- mark the end of the list of instructions
} tricore_insn;

//> Group of TriCore instructions
typedef enum tricore_insn_group {
	TriCore_GRP_INVALID, ///< = CS_GRP_INVALID
	//> Generic groups
	TriCore_GRP_CALL, ///< = CS_GRP_CALL
	TriCore_GRP_JUMP, ///< = CS_GRP_JUMP
	TriCore_GRP_ENDING, ///< = mark the end of the list of groups
} tricore_insn_group;

typedef enum tricore_feature_t {

	TriCore_FEATURE_INVALID = 0,
	// generate content <TriCoreGenCSFeatureEnum.inc> begin
	// clang-format off

/* Capstone Disassembly Engine, https://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */
/* By Rot127 <unisono@quyllur.org>, 2023 */

/* Auto generated file. Do not edit. */
/* Code generator: https://github.com/capstone-engine/capstone/tree/next/suite/auto-sync */
TriCore_FEATURE_HasV110 = 128,
TriCore_FEATURE_HasV120_UP,
TriCore_FEATURE_HasV130_UP,
TriCore_FEATURE_HasV161,
TriCore_FEATURE_HasV160_UP,
TriCore_FEATURE_HasV131_UP,
TriCore_FEATURE_HasV161_UP,
TriCore_FEATURE_HasV162,
TriCore_FEATURE_HasV162_UP,

	// clang-format on
	// generate content <TriCoreGenCSFeatureEnum.inc> end
	TriCore_FEATURE_ENDING, // <-- mark the end of the list of features
} tricore_feature;

#ifdef __cplusplus
}
#endif

#endif

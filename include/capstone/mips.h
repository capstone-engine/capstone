#ifndef CAPSTONE_MIPS_H
#define CAPSTONE_MIPS_H

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifdef __cplusplus
extern "C" {
#endif

#include "platform.h"

// GCC MIPS toolchain has a default macro called "mips" which breaks
// compilation
#undef mips

#ifdef _MSC_VER
#pragma warning(disable : 4201)
#endif

/// Operand type for instruction's operands
typedef enum mips_op_type {
  MIPS_OP_INVALID = 0, ///< = CS_OP_INVALID (Uninitialized).
  MIPS_OP_REG,	 ///< = CS_OP_REG (Register operand).
  MIPS_OP_IMM,	 ///< = CS_OP_IMM (Immediate operand).
  MIPS_OP_MEM,	 ///< = CS_OP_MEM (Memory operand).
} mips_op_type;

/// MIPS registers
typedef enum mips_reg {
  MIPS_REG_INVALID = 0,
  // General purpose registers
  MIPS_REG_PC,

  MIPS_REG_0,
  MIPS_REG_1,
  MIPS_REG_2,
  MIPS_REG_3,
  MIPS_REG_4,
  MIPS_REG_5,
  MIPS_REG_6,
  MIPS_REG_7,
  MIPS_REG_8,
  MIPS_REG_9,
  MIPS_REG_10,
  MIPS_REG_11,
  MIPS_REG_12,
  MIPS_REG_13,
  MIPS_REG_14,
  MIPS_REG_15,
  MIPS_REG_16,
  MIPS_REG_17,
  MIPS_REG_18,
  MIPS_REG_19,
  MIPS_REG_20,
  MIPS_REG_21,
  MIPS_REG_22,
  MIPS_REG_23,
  MIPS_REG_24,
  MIPS_REG_25,
  MIPS_REG_26,
  MIPS_REG_27,
  MIPS_REG_28,
  MIPS_REG_29,
  MIPS_REG_30,
  MIPS_REG_31,

  // DSP registers
  MIPS_REG_DSPCCOND,
  MIPS_REG_DSPCARRY,
  MIPS_REG_DSPEFI,
  MIPS_REG_DSPOUTFLAG,
  MIPS_REG_DSPOUTFLAG16_19,
  MIPS_REG_DSPOUTFLAG20,
  MIPS_REG_DSPOUTFLAG21,
  MIPS_REG_DSPOUTFLAG22,
  MIPS_REG_DSPOUTFLAG23,
  MIPS_REG_DSPPOS,
  MIPS_REG_DSPSCOUNT,

  // ACC registers
  MIPS_REG_AC0,
  MIPS_REG_AC1,
  MIPS_REG_AC2,
  MIPS_REG_AC3,

  // COP registers
  MIPS_REG_CC0,
  MIPS_REG_CC1,
  MIPS_REG_CC2,
  MIPS_REG_CC3,
  MIPS_REG_CC4,
  MIPS_REG_CC5,
  MIPS_REG_CC6,
  MIPS_REG_CC7,

  // FPU registers
  MIPS_REG_F0,
  MIPS_REG_F1,
  MIPS_REG_F2,
  MIPS_REG_F3,
  MIPS_REG_F4,
  MIPS_REG_F5,
  MIPS_REG_F6,
  MIPS_REG_F7,
  MIPS_REG_F8,
  MIPS_REG_F9,
  MIPS_REG_F10,
  MIPS_REG_F11,
  MIPS_REG_F12,
  MIPS_REG_F13,
  MIPS_REG_F14,
  MIPS_REG_F15,
  MIPS_REG_F16,
  MIPS_REG_F17,
  MIPS_REG_F18,
  MIPS_REG_F19,
  MIPS_REG_F20,
  MIPS_REG_F21,
  MIPS_REG_F22,
  MIPS_REG_F23,
  MIPS_REG_F24,
  MIPS_REG_F25,
  MIPS_REG_F26,
  MIPS_REG_F27,
  MIPS_REG_F28,
  MIPS_REG_F29,
  MIPS_REG_F30,
  MIPS_REG_F31,

  MIPS_REG_FCC0,
  MIPS_REG_FCC1,
  MIPS_REG_FCC2,
  MIPS_REG_FCC3,
  MIPS_REG_FCC4,
  MIPS_REG_FCC5,
  MIPS_REG_FCC6,
  MIPS_REG_FCC7,

  // AFPR128
  MIPS_REG_W0,
  MIPS_REG_W1,
  MIPS_REG_W2,
  MIPS_REG_W3,
  MIPS_REG_W4,
  MIPS_REG_W5,
  MIPS_REG_W6,
  MIPS_REG_W7,
  MIPS_REG_W8,
  MIPS_REG_W9,
  MIPS_REG_W10,
  MIPS_REG_W11,
  MIPS_REG_W12,
  MIPS_REG_W13,
  MIPS_REG_W14,
  MIPS_REG_W15,
  MIPS_REG_W16,
  MIPS_REG_W17,
  MIPS_REG_W18,
  MIPS_REG_W19,
  MIPS_REG_W20,
  MIPS_REG_W21,
  MIPS_REG_W22,
  MIPS_REG_W23,
  MIPS_REG_W24,
  MIPS_REG_W25,
  MIPS_REG_W26,
  MIPS_REG_W27,
  MIPS_REG_W28,
  MIPS_REG_W29,
  MIPS_REG_W30,
  MIPS_REG_W31,

  MIPS_REG_HI,
  MIPS_REG_LO,

  MIPS_REG_P0,
  MIPS_REG_P1,
  MIPS_REG_P2,

  MIPS_REG_MPL0,
  MIPS_REG_MPL1,
  MIPS_REG_MPL2,

  MIPS_REG_ENDING, // <-- mark the end of the list or registers

  // alias registers
  MIPS_REG_ZERO = MIPS_REG_0,
  MIPS_REG_AT = MIPS_REG_1,
  MIPS_REG_V0 = MIPS_REG_2,
  MIPS_REG_V1 = MIPS_REG_3,
  MIPS_REG_A0 = MIPS_REG_4,
  MIPS_REG_A1 = MIPS_REG_5,
  MIPS_REG_A2 = MIPS_REG_6,
  MIPS_REG_A3 = MIPS_REG_7,
  MIPS_REG_T0 = MIPS_REG_8,
  MIPS_REG_T1 = MIPS_REG_9,
  MIPS_REG_T2 = MIPS_REG_10,
  MIPS_REG_T3 = MIPS_REG_11,
  MIPS_REG_T4 = MIPS_REG_12,
  MIPS_REG_T5 = MIPS_REG_13,
  MIPS_REG_T6 = MIPS_REG_14,
  MIPS_REG_T7 = MIPS_REG_15,
  MIPS_REG_S0 = MIPS_REG_16,
  MIPS_REG_S1 = MIPS_REG_17,
  MIPS_REG_S2 = MIPS_REG_18,
  MIPS_REG_S3 = MIPS_REG_19,
  MIPS_REG_S4 = MIPS_REG_20,
  MIPS_REG_S5 = MIPS_REG_21,
  MIPS_REG_S6 = MIPS_REG_22,
  MIPS_REG_S7 = MIPS_REG_23,
  MIPS_REG_T8 = MIPS_REG_24,
  MIPS_REG_T9 = MIPS_REG_25,
  MIPS_REG_K0 = MIPS_REG_26,
  MIPS_REG_K1 = MIPS_REG_27,
  MIPS_REG_GP = MIPS_REG_28,
  MIPS_REG_SP = MIPS_REG_29,
  MIPS_REG_FP = MIPS_REG_30,
  MIPS_REG_S8 = MIPS_REG_30,
  MIPS_REG_RA = MIPS_REG_31,

  MIPS_REG_HI0 = MIPS_REG_AC0,
  MIPS_REG_HI1 = MIPS_REG_AC1,
  MIPS_REG_HI2 = MIPS_REG_AC2,
  MIPS_REG_HI3 = MIPS_REG_AC3,

  MIPS_REG_LO0 = MIPS_REG_HI0,
  MIPS_REG_LO1 = MIPS_REG_HI1,
  MIPS_REG_LO2 = MIPS_REG_HI2,
  MIPS_REG_LO3 = MIPS_REG_HI3,
} mips_reg;

/// Instruction's operand referring to memory
/// This is associated with MIPS_OP_MEM operand type above
typedef struct mips_op_mem {
  mips_reg base; ///< base register
  int64_t disp;  ///< displacement/offset value
} mips_op_mem;

/// Instruction operand
typedef struct cs_mips_op {
  mips_op_type type; ///< operand type
  union {
    mips_reg reg;    ///< register id for REG operand
    int64_t imm;     ///< immediate value for IMM operand
    mips_op_mem mem; ///< base/index/scale/disp value for MEM operand
  };
} cs_mips_op;

/// Instruction structure
typedef struct cs_mips {
  /// Number of operands of this instruction,
  /// or 0 when instruction has no operand.
  uint8_t op_count;
  cs_mips_op operands[10]; ///< operands for this instruction.
} cs_mips;

/// MIPS instruction
typedef enum mips_insn {
  MIPS_INS_INVALID = 0,
  MIPS_INS_ABS,
  MIPS_INS_ABSQ_S,
  MIPS_INS_ADD,
  MIPS_INS_ADDI,
  MIPS_INS_ADDIU,
  MIPS_INS_ADDIUPC,
  MIPS_INS_ADDIUR1SP,
  MIPS_INS_ADDIUR2,
  MIPS_INS_ADDIUS5,
  MIPS_INS_ADDIUSP,
  MIPS_INS_ADDQ,
  MIPS_INS_ADDQH,
  MIPS_INS_ADDQH_R,
  MIPS_INS_ADDQ_S,
  MIPS_INS_ADDR,
  MIPS_INS_ADDSC,
  MIPS_INS_ADDS_A,
  MIPS_INS_ADDS_S,
  MIPS_INS_ADDS_U,
  MIPS_INS_ADDU,
  MIPS_INS_ADDU16,
  MIPS_INS_ADDUH,
  MIPS_INS_ADDUH_R,
  MIPS_INS_ADDU_S,
  MIPS_INS_ADDV,
  MIPS_INS_ADDVI,
  MIPS_INS_ADDWC,
  MIPS_INS_ADD_A,
  MIPS_INS_ALIGN,
  MIPS_INS_ALUIPC,
  MIPS_INS_AND,
  MIPS_INS_AND16,
  MIPS_INS_ANDI,
  MIPS_INS_ANDI16,
  MIPS_INS_APPEND,
  MIPS_INS_ASUB_S,
  MIPS_INS_ASUB_U,
  MIPS_INS_AUI,
  MIPS_INS_AUIPC,
  MIPS_INS_AVER_S,
  MIPS_INS_AVER_U,
  MIPS_INS_AVE_S,
  MIPS_INS_AVE_U,
  MIPS_INS_B,
  MIPS_INS_B16,
  MIPS_INS_BADDU,
  MIPS_INS_BAL,
  MIPS_INS_BALC,
  MIPS_INS_BALIGN,
  MIPS_INS_BBIT0,
  MIPS_INS_BBIT032,
  MIPS_INS_BBIT1,
  MIPS_INS_BBIT132,
  MIPS_INS_BC,
  MIPS_INS_BC16,
  MIPS_INS_BC1EQZ,
  MIPS_INS_BC1EQZC,
  MIPS_INS_BC1F,
  MIPS_INS_BC1FL,
  MIPS_INS_BC1NEZ,
  MIPS_INS_BC1NEZC,
  MIPS_INS_BC1T,
  MIPS_INS_BC1TL,
  MIPS_INS_BC2EQZ,
  MIPS_INS_BC2EQZC,
  MIPS_INS_BC2NEZ,
  MIPS_INS_BC2NEZC,
  MIPS_INS_BCLR,
  MIPS_INS_BCLRI,
  MIPS_INS_BEQ,
  MIPS_INS_BEQC,
  MIPS_INS_BEQL,
  MIPS_INS_BEQZ,
  MIPS_INS_BEQZ16,
  MIPS_INS_BEQZALC,
  MIPS_INS_BEQZC,
  MIPS_INS_BEQZC16,
  MIPS_INS_BEQZL,
  MIPS_INS_BGE,
  MIPS_INS_BGEC,
  MIPS_INS_BGEL,
  MIPS_INS_BGEU,
  MIPS_INS_BGEUC,
  MIPS_INS_BGEUL,
  MIPS_INS_BGEZ,
  MIPS_INS_BGEZAL,
  MIPS_INS_BGEZALC,
  MIPS_INS_BGEZALL,
  MIPS_INS_BGEZALS,
  MIPS_INS_BGEZC,
  MIPS_INS_BGEZL,
  MIPS_INS_BGT,
  MIPS_INS_BGTL,
  MIPS_INS_BGTU,
  MIPS_INS_BGTUL,
  MIPS_INS_BGTZ,
  MIPS_INS_BGTZALC,
  MIPS_INS_BGTZC,
  MIPS_INS_BGTZL,
  MIPS_INS_BINSL,
  MIPS_INS_BINSLI,
  MIPS_INS_BINSR,
  MIPS_INS_BINSRI,
  MIPS_INS_BITREV,
  MIPS_INS_BITSWAP,
  MIPS_INS_BLE,
  MIPS_INS_BLEL,
  MIPS_INS_BLEU,
  MIPS_INS_BLEUL,
  MIPS_INS_BLEZ,
  MIPS_INS_BLEZALC,
  MIPS_INS_BLEZC,
  MIPS_INS_BLEZL,
  MIPS_INS_BLT,
  MIPS_INS_BLTC,
  MIPS_INS_BLTL,
  MIPS_INS_BLTU,
  MIPS_INS_BLTUC,
  MIPS_INS_BLTUL,
  MIPS_INS_BLTZ,
  MIPS_INS_BLTZAL,
  MIPS_INS_BLTZALC,
  MIPS_INS_BLTZALL,
  MIPS_INS_BLTZALS,
  MIPS_INS_BLTZC,
  MIPS_INS_BLTZL,
  MIPS_INS_BMNZ,
  MIPS_INS_BMNZI,
  MIPS_INS_BMZ,
  MIPS_INS_BMZI,
  MIPS_INS_BNE,
  MIPS_INS_BNEC,
  MIPS_INS_BNEG,
  MIPS_INS_BNEGI,
  MIPS_INS_BNEL,
  MIPS_INS_BNEZ,
  MIPS_INS_BNEZ16,
  MIPS_INS_BNEZALC,
  MIPS_INS_BNEZC,
  MIPS_INS_BNEZC16,
  MIPS_INS_BNEZL,
  MIPS_INS_BNVC,
  MIPS_INS_BNZ,
  MIPS_INS_BOVC,
  MIPS_INS_BPOSGE32,
  MIPS_INS_BPOSGE32C,
  MIPS_INS_BREAK,
  MIPS_INS_BREAK16,
  MIPS_INS_BSEL,
  MIPS_INS_BSELI,
  MIPS_INS_BSET,
  MIPS_INS_BSETI,
  MIPS_INS_BTEQZ,
  MIPS_INS_BTNEZ,
  MIPS_INS_BZ,
  MIPS_INS_C,
  MIPS_INS_CACHE,
  MIPS_INS_CACHEE,
  MIPS_INS_CEIL,
  MIPS_INS_CEQ,
  MIPS_INS_CEQI,
  MIPS_INS_CFC1,
  MIPS_INS_CFC2,
  MIPS_INS_CFCMSA,
  MIPS_INS_CFTC1,
  MIPS_INS_CINS,
  MIPS_INS_CINS32,
  MIPS_INS_CLASS,
  MIPS_INS_CLEI_S,
  MIPS_INS_CLEI_U,
  MIPS_INS_CLE_S,
  MIPS_INS_CLE_U,
  MIPS_INS_CLO,
  MIPS_INS_CLTI_S,
  MIPS_INS_CLTI_U,
  MIPS_INS_CLT_S,
  MIPS_INS_CLT_U,
  MIPS_INS_CLZ,
  MIPS_INS_CMP,
  MIPS_INS_CMPGDU,
  MIPS_INS_CMPGU,
  MIPS_INS_CMPI,
  MIPS_INS_CMPU,
  MIPS_INS_COPY_S,
  MIPS_INS_COPY_U,
  MIPS_INS_CRC32B,
  MIPS_INS_CRC32CB,
  MIPS_INS_CRC32CD,
  MIPS_INS_CRC32CH,
  MIPS_INS_CRC32CW,
  MIPS_INS_CRC32D,
  MIPS_INS_CRC32H,
  MIPS_INS_CRC32W,
  MIPS_INS_CTC1,
  MIPS_INS_CTC2,
  MIPS_INS_CTCMSA,
  MIPS_INS_CTTC1,
  MIPS_INS_CVT,
  MIPS_INS_DADD,
  MIPS_INS_DADDI,
  MIPS_INS_DADDIU,
  MIPS_INS_DADDU,
  MIPS_INS_DAHI,
  MIPS_INS_DALIGN,
  MIPS_INS_DATI,
  MIPS_INS_DAUI,
  MIPS_INS_DBITSWAP,
  MIPS_INS_DCLO,
  MIPS_INS_DCLZ,
  MIPS_INS_DDIV,
  MIPS_INS_DDIVU,
  MIPS_INS_DERET,
  MIPS_INS_DEXT,
  MIPS_INS_DEXTM,
  MIPS_INS_DEXTU,
  MIPS_INS_DI,
  MIPS_INS_DINS,
  MIPS_INS_DINSM,
  MIPS_INS_DINSU,
  MIPS_INS_DIV,
  MIPS_INS_DIVU,
  MIPS_INS_DIV_S,
  MIPS_INS_DIV_U,
  MIPS_INS_DLA,
  MIPS_INS_DLI,
  MIPS_INS_DLSA,
  MIPS_INS_DMFC0,
  MIPS_INS_DMFC1,
  MIPS_INS_DMFC2,
  MIPS_INS_DMFGC0,
  MIPS_INS_DMOD,
  MIPS_INS_DMODU,
  MIPS_INS_DMT,
  MIPS_INS_DMTC0,
  MIPS_INS_DMTC1,
  MIPS_INS_DMTC2,
  MIPS_INS_DMTGC0,
  MIPS_INS_DMUH,
  MIPS_INS_DMUHU,
  MIPS_INS_DMUL,
  MIPS_INS_DMULO,
  MIPS_INS_DMULOU,
  MIPS_INS_DMULT,
  MIPS_INS_DMULTU,
  MIPS_INS_DMULU,
  MIPS_INS_DNEG,
  MIPS_INS_DNEGU,
  MIPS_INS_DOTP_S,
  MIPS_INS_DOTP_U,
  MIPS_INS_DPA,
  MIPS_INS_DPADD_S,
  MIPS_INS_DPADD_U,
  MIPS_INS_DPAQX_S,
  MIPS_INS_DPAQX_SA,
  MIPS_INS_DPAQ_S,
  MIPS_INS_DPAQ_SA,
  MIPS_INS_DPAU,
  MIPS_INS_DPAX,
  MIPS_INS_DPOP,
  MIPS_INS_DPS,
  MIPS_INS_DPSQX_S,
  MIPS_INS_DPSQX_SA,
  MIPS_INS_DPSQ_S,
  MIPS_INS_DPSQ_SA,
  MIPS_INS_DPSU,
  MIPS_INS_DPSUB_S,
  MIPS_INS_DPSUB_U,
  MIPS_INS_DPSX,
  MIPS_INS_DREM,
  MIPS_INS_DREMU,
  MIPS_INS_DROL,
  MIPS_INS_DROR,
  MIPS_INS_DROTR,
  MIPS_INS_DROTR32,
  MIPS_INS_DROTRV,
  MIPS_INS_DSBH,
  MIPS_INS_DSHD,
  MIPS_INS_DSLL,
  MIPS_INS_DSLL32,
  MIPS_INS_DSLLV,
  MIPS_INS_DSRA,
  MIPS_INS_DSRA32,
  MIPS_INS_DSRAV,
  MIPS_INS_DSRL,
  MIPS_INS_DSRL32,
  MIPS_INS_DSRLV,
  MIPS_INS_DSUB,
  MIPS_INS_DSUBI,
  MIPS_INS_DSUBU,
  MIPS_INS_DVP,
  MIPS_INS_DVPE,
  MIPS_INS_EHB,
  MIPS_INS_EI,
  MIPS_INS_EMT,
  MIPS_INS_ERET,
  MIPS_INS_ERETNC,
  MIPS_INS_EVP,
  MIPS_INS_EVPE,
  MIPS_INS_EXT,
  MIPS_INS_EXTP,
  MIPS_INS_EXTPDP,
  MIPS_INS_EXTPDPV,
  MIPS_INS_EXTPV,
  MIPS_INS_EXTR,
  MIPS_INS_EXTRV,
  MIPS_INS_EXTRV_R,
  MIPS_INS_EXTRV_RS,
  MIPS_INS_EXTRV_S,
  MIPS_INS_EXTR_R,
  MIPS_INS_EXTR_RS,
  MIPS_INS_EXTR_S,
  MIPS_INS_EXTS,
  MIPS_INS_EXTS32,
  MIPS_INS_FADD,
  MIPS_INS_FCAF,
  MIPS_INS_FCEQ,
  MIPS_INS_FCLASS,
  MIPS_INS_FCLE,
  MIPS_INS_FCLT,
  MIPS_INS_FCNE,
  MIPS_INS_FCOR,
  MIPS_INS_FCUEQ,
  MIPS_INS_FCULE,
  MIPS_INS_FCULT,
  MIPS_INS_FCUN,
  MIPS_INS_FCUNE,
  MIPS_INS_FDIV,
  MIPS_INS_FEXDO,
  MIPS_INS_FEXP2,
  MIPS_INS_FEXUPL,
  MIPS_INS_FEXUPR,
  MIPS_INS_FFINT_S,
  MIPS_INS_FFINT_U,
  MIPS_INS_FFQL,
  MIPS_INS_FFQR,
  MIPS_INS_FILL,
  MIPS_INS_FLOG2,
  MIPS_INS_FLOOR,
  MIPS_INS_FMADD,
  MIPS_INS_FMAX,
  MIPS_INS_FMAX_A,
  MIPS_INS_FMIN,
  MIPS_INS_FMIN_A,
  MIPS_INS_FMSUB,
  MIPS_INS_FMUL,
  MIPS_INS_FORK,
  MIPS_INS_FRCP,
  MIPS_INS_FRINT,
  MIPS_INS_FRSQRT,
  MIPS_INS_FSAF,
  MIPS_INS_FSEQ,
  MIPS_INS_FSLE,
  MIPS_INS_FSLT,
  MIPS_INS_FSNE,
  MIPS_INS_FSOR,
  MIPS_INS_FSQRT,
  MIPS_INS_FSUB,
  MIPS_INS_FSUEQ,
  MIPS_INS_FSULE,
  MIPS_INS_FSULT,
  MIPS_INS_FSUN,
  MIPS_INS_FSUNE,
  MIPS_INS_FTINT_S,
  MIPS_INS_FTINT_U,
  MIPS_INS_FTQ,
  MIPS_INS_FTRUNC_S,
  MIPS_INS_FTRUNC_U,
  MIPS_INS_GINVI,
  MIPS_INS_GINVT,
  MIPS_INS_HADD_S,
  MIPS_INS_HADD_U,
  MIPS_INS_HSUB_S,
  MIPS_INS_HSUB_U,
  MIPS_INS_HYPCALL,
  MIPS_INS_ILVEV,
  MIPS_INS_ILVL,
  MIPS_INS_ILVOD,
  MIPS_INS_ILVR,
  MIPS_INS_INS,
  MIPS_INS_INSERT,
  MIPS_INS_INSV,
  MIPS_INS_INSVE,
  MIPS_INS_J,
  MIPS_INS_JAL,
  MIPS_INS_JALR,
  MIPS_INS_JALRC,
  MIPS_INS_JALRS,
  MIPS_INS_JALRS16,
  MIPS_INS_JALS,
  MIPS_INS_JALX,
  MIPS_INS_JIALC,
  MIPS_INS_JIC,
  MIPS_INS_JR,
  MIPS_INS_JR16,
  MIPS_INS_JRADDIUSP,
  MIPS_INS_JRC,
  MIPS_INS_JRC16,
  MIPS_INS_JRCADDIUSP,
  MIPS_INS_L,
  MIPS_INS_LA,
  MIPS_INS_LAPC,
  MIPS_INS_LB,
  MIPS_INS_LBE,
  MIPS_INS_LBU,
  MIPS_INS_LBU16,
  MIPS_INS_LBUE,
  MIPS_INS_LBUX,
  MIPS_INS_LD,
  MIPS_INS_LDC1,
  MIPS_INS_LDC2,
  MIPS_INS_LDC3,
  MIPS_INS_LDI,
  MIPS_INS_LDL,
  MIPS_INS_LDPC,
  MIPS_INS_LDR,
  MIPS_INS_LDXC1,
  MIPS_INS_LH,
  MIPS_INS_LHE,
  MIPS_INS_LHU,
  MIPS_INS_LHU16,
  MIPS_INS_LHUE,
  MIPS_INS_LHX,
  MIPS_INS_LI,
  MIPS_INS_LI16,
  MIPS_INS_LL,
  MIPS_INS_LLD,
  MIPS_INS_LLE,
  MIPS_INS_LSA,
  MIPS_INS_LUI,
  MIPS_INS_LUXC1,
  MIPS_INS_LW,
  MIPS_INS_LW16,
  MIPS_INS_LWC1,
  MIPS_INS_LWC2,
  MIPS_INS_LWC3,
  MIPS_INS_LWE,
  MIPS_INS_LWL,
  MIPS_INS_LWLE,
  MIPS_INS_LWM,
  MIPS_INS_LWM16,
  MIPS_INS_LWM32,
  MIPS_INS_LWP,
  MIPS_INS_LWPC,
  MIPS_INS_LWR,
  MIPS_INS_LWRE,
  MIPS_INS_LWU,
  MIPS_INS_LWUPC,
  MIPS_INS_LWX,
  MIPS_INS_LWXC1,
  MIPS_INS_LWXS,
  MIPS_INS_MADD,
  MIPS_INS_MADDF,
  MIPS_INS_MADDR_Q,
  MIPS_INS_MADDU,
  MIPS_INS_MADDV,
  MIPS_INS_MADD_Q,
  MIPS_INS_MAQ_S,
  MIPS_INS_MAQ_SA,
  MIPS_INS_MAX,
  MIPS_INS_MAXA,
  MIPS_INS_MAXI_S,
  MIPS_INS_MAXI_U,
  MIPS_INS_MAX_A,
  MIPS_INS_MAX_S,
  MIPS_INS_MAX_U,
  MIPS_INS_MFC0,
  MIPS_INS_MFC1,
  MIPS_INS_MFC2,
  MIPS_INS_MFGC0,
  MIPS_INS_MFHC0,
  MIPS_INS_MFHC1,
  MIPS_INS_MFHC2,
  MIPS_INS_MFHGC0,
  MIPS_INS_MFHI,
  MIPS_INS_MFHI16,
  MIPS_INS_MFLO,
  MIPS_INS_MFLO16,
  MIPS_INS_MFTACX,
  MIPS_INS_MFTC0,
  MIPS_INS_MFTC1,
  MIPS_INS_MFTDSP,
  MIPS_INS_MFTGPR,
  MIPS_INS_MFTHC1,
  MIPS_INS_MFTHI,
  MIPS_INS_MFTLO,
  MIPS_INS_MFTR,
  MIPS_INS_MIN,
  MIPS_INS_MINA,
  MIPS_INS_MINI_S,
  MIPS_INS_MINI_U,
  MIPS_INS_MIN_A,
  MIPS_INS_MIN_S,
  MIPS_INS_MIN_U,
  MIPS_INS_MOD,
  MIPS_INS_MODSUB,
  MIPS_INS_MODU,
  MIPS_INS_MOD_S,
  MIPS_INS_MOD_U,
  MIPS_INS_MOV,
  MIPS_INS_MOVE,
  MIPS_INS_MOVE16,
  MIPS_INS_MOVEP,
  MIPS_INS_MOVF,
  MIPS_INS_MOVN,
  MIPS_INS_MOVT,
  MIPS_INS_MOVZ,
  MIPS_INS_MSUB,
  MIPS_INS_MSUBF,
  MIPS_INS_MSUBR_Q,
  MIPS_INS_MSUBU,
  MIPS_INS_MSUBV,
  MIPS_INS_MSUB_Q,
  MIPS_INS_MTC0,
  MIPS_INS_MTC1,
  MIPS_INS_MTC2,
  MIPS_INS_MTGC0,
  MIPS_INS_MTHC0,
  MIPS_INS_MTHC1,
  MIPS_INS_MTHC2,
  MIPS_INS_MTHGC0,
  MIPS_INS_MTHI,
  MIPS_INS_MTHLIP,
  MIPS_INS_MTLO,
  MIPS_INS_MTM0,
  MIPS_INS_MTM1,
  MIPS_INS_MTM2,
  MIPS_INS_MTP0,
  MIPS_INS_MTP1,
  MIPS_INS_MTP2,
  MIPS_INS_MTTACX,
  MIPS_INS_MTTC0,
  MIPS_INS_MTTC1,
  MIPS_INS_MTTDSP,
  MIPS_INS_MTTGPR,
  MIPS_INS_MTTHC1,
  MIPS_INS_MTTHI,
  MIPS_INS_MTTLO,
  MIPS_INS_MTTR,
  MIPS_INS_MUH,
  MIPS_INS_MUHU,
  MIPS_INS_MUL,
  MIPS_INS_MULEQ_S,
  MIPS_INS_MULEU_S,
  MIPS_INS_MULO,
  MIPS_INS_MULOU,
  MIPS_INS_MULQ_RS,
  MIPS_INS_MULQ_S,
  MIPS_INS_MULR,
  MIPS_INS_MULR_Q,
  MIPS_INS_MULSA,
  MIPS_INS_MULSAQ_S,
  MIPS_INS_MULT,
  MIPS_INS_MULTU,
  MIPS_INS_MULU,
  MIPS_INS_MULV,
  MIPS_INS_MUL_Q,
  MIPS_INS_MUL_S,
  MIPS_INS_NEG,
  MIPS_INS_NEGU,
  MIPS_INS_NLOC,
  MIPS_INS_NLZC,
  MIPS_INS_NMADD,
  MIPS_INS_NMSUB,
  MIPS_INS_NOP,
  MIPS_INS_NOR,
  MIPS_INS_NORI,
  MIPS_INS_NOT,
  MIPS_INS_NOT16,
  MIPS_INS_OR,
  MIPS_INS_OR16,
  MIPS_INS_ORI,
  MIPS_INS_PACKRL,
  MIPS_INS_PAUSE,
  MIPS_INS_PCKEV,
  MIPS_INS_PCKOD,
  MIPS_INS_PCNT,
  MIPS_INS_PICK,
  MIPS_INS_PLL,
  MIPS_INS_PLU,
  MIPS_INS_POP,
  MIPS_INS_PRECEQ,
  MIPS_INS_PRECEQU,
  MIPS_INS_PRECEU,
  MIPS_INS_PRECR,
  MIPS_INS_PRECRQ,
  MIPS_INS_PRECRQU_S,
  MIPS_INS_PRECRQ_RS,
  MIPS_INS_PRECR_SRA,
  MIPS_INS_PRECR_SRA_R,
  MIPS_INS_PREF,
  MIPS_INS_PREFE,
  MIPS_INS_PREFX,
  MIPS_INS_PREPEND,
  MIPS_INS_PUL,
  MIPS_INS_PUU,
  MIPS_INS_RADDU,
  MIPS_INS_RDDSP,
  MIPS_INS_RDHWR,
  MIPS_INS_RDPGPR,
  MIPS_INS_RECIP,
  MIPS_INS_REM,
  MIPS_INS_REMU,
  MIPS_INS_REPL,
  MIPS_INS_REPLV,
  MIPS_INS_RINT,
  MIPS_INS_ROL,
  MIPS_INS_ROR,
  MIPS_INS_ROTR,
  MIPS_INS_ROTRV,
  MIPS_INS_ROUND,
  MIPS_INS_RSQRT,
  MIPS_INS_S,
  MIPS_INS_SAA,
  MIPS_INS_SAAD,
  MIPS_INS_SAT_S,
  MIPS_INS_SAT_U,
  MIPS_INS_SB,
  MIPS_INS_SB16,
  MIPS_INS_SBE,
  MIPS_INS_SC,
  MIPS_INS_SCD,
  MIPS_INS_SCE,
  MIPS_INS_SD,
  MIPS_INS_SDBBP,
  MIPS_INS_SDBBP16,
  MIPS_INS_SDC1,
  MIPS_INS_SDC2,
  MIPS_INS_SDC3,
  MIPS_INS_SDL,
  MIPS_INS_SDR,
  MIPS_INS_SDXC1,
  MIPS_INS_SEB,
  MIPS_INS_SEH,
  MIPS_INS_SEL,
  MIPS_INS_SELEQZ,
  MIPS_INS_SELNEZ,
  MIPS_INS_SEQ,
  MIPS_INS_SEQI,
  MIPS_INS_SGE,
  MIPS_INS_SGEU,
  MIPS_INS_SGT,
  MIPS_INS_SGTU,
  MIPS_INS_SH,
  MIPS_INS_SH16,
  MIPS_INS_SHE,
  MIPS_INS_SHF,
  MIPS_INS_SHILO,
  MIPS_INS_SHILOV,
  MIPS_INS_SHLL,
  MIPS_INS_SHLLV,
  MIPS_INS_SHLLV_S,
  MIPS_INS_SHLL_S,
  MIPS_INS_SHRA,
  MIPS_INS_SHRAV,
  MIPS_INS_SHRAV_R,
  MIPS_INS_SHRA_R,
  MIPS_INS_SHRL,
  MIPS_INS_SHRLV,
  MIPS_INS_SIGRIE,
  MIPS_INS_SLD,
  MIPS_INS_SLDI,
  MIPS_INS_SLE,
  MIPS_INS_SLEU,
  MIPS_INS_SLL,
  MIPS_INS_SLL16,
  MIPS_INS_SLLI,
  MIPS_INS_SLLV,
  MIPS_INS_SLT,
  MIPS_INS_SLTI,
  MIPS_INS_SLTIU,
  MIPS_INS_SLTU,
  MIPS_INS_SNE,
  MIPS_INS_SNEI,
  MIPS_INS_SPLAT,
  MIPS_INS_SPLATI,
  MIPS_INS_SQRT,
  MIPS_INS_SRA,
  MIPS_INS_SRAI,
  MIPS_INS_SRAR,
  MIPS_INS_SRARI,
  MIPS_INS_SRAV,
  MIPS_INS_SRL,
  MIPS_INS_SRL16,
  MIPS_INS_SRLI,
  MIPS_INS_SRLR,
  MIPS_INS_SRLRI,
  MIPS_INS_SRLV,
  MIPS_INS_SSNOP,
  MIPS_INS_ST,
  MIPS_INS_SUB,
  MIPS_INS_SUBQ,
  MIPS_INS_SUBQH,
  MIPS_INS_SUBQH_R,
  MIPS_INS_SUBQ_S,
  MIPS_INS_SUBSUS_U,
  MIPS_INS_SUBSUU_S,
  MIPS_INS_SUBS_S,
  MIPS_INS_SUBS_U,
  MIPS_INS_SUBU,
  MIPS_INS_SUBU16,
  MIPS_INS_SUBUH,
  MIPS_INS_SUBUH_R,
  MIPS_INS_SUBU_S,
  MIPS_INS_SUBV,
  MIPS_INS_SUBVI,
  MIPS_INS_SUXC1,
  MIPS_INS_SW,
  MIPS_INS_SW16,
  MIPS_INS_SWC1,
  MIPS_INS_SWC2,
  MIPS_INS_SWC3,
  MIPS_INS_SWE,
  MIPS_INS_SWL,
  MIPS_INS_SWLE,
  MIPS_INS_SWM,
  MIPS_INS_SWM16,
  MIPS_INS_SWM32,
  MIPS_INS_SWP,
  MIPS_INS_SWR,
  MIPS_INS_SWRE,
  MIPS_INS_SWSP,
  MIPS_INS_SWXC1,
  MIPS_INS_SYNC,
  MIPS_INS_SYNCI,
  MIPS_INS_SYNCIOBDMA,
  MIPS_INS_SYNCS,
  MIPS_INS_SYNCW,
  MIPS_INS_SYNCWS,
  MIPS_INS_SYSCALL,
  MIPS_INS_TEQ,
  MIPS_INS_TEQI,
  MIPS_INS_TGE,
  MIPS_INS_TGEI,
  MIPS_INS_TGEIU,
  MIPS_INS_TGEU,
  MIPS_INS_TLBGINV,
  MIPS_INS_TLBGINVF,
  MIPS_INS_TLBGP,
  MIPS_INS_TLBGR,
  MIPS_INS_TLBGWI,
  MIPS_INS_TLBGWR,
  MIPS_INS_TLBINV,
  MIPS_INS_TLBINVF,
  MIPS_INS_TLBP,
  MIPS_INS_TLBR,
  MIPS_INS_TLBWI,
  MIPS_INS_TLBWR,
  MIPS_INS_TLT,
  MIPS_INS_TLTI,
  MIPS_INS_TLTIU,
  MIPS_INS_TLTU,
  MIPS_INS_TNE,
  MIPS_INS_TNEI,
  MIPS_INS_TRUNC,
  MIPS_INS_ULH,
  MIPS_INS_ULHU,
  MIPS_INS_ULW,
  MIPS_INS_USH,
  MIPS_INS_USW,
  MIPS_INS_V3MULU,
  MIPS_INS_VMM0,
  MIPS_INS_VMULU,
  MIPS_INS_VSHF,
  MIPS_INS_WAIT,
  MIPS_INS_WRDSP,
  MIPS_INS_WRPGPR,
  MIPS_INS_WSBH,
  MIPS_INS_XOR,
  MIPS_INS_XOR16,
  MIPS_INS_XORI,
  MIPS_INS_YIELD,

  MIPS_INS_ENDING,
} mips_insn;

/// Group of MIPS instructions
typedef enum mips_insn_group {
  MIPS_GRP_INVALID = 0, ///< = CS_GRP_INVALID

  // Generic groups
  // all jump instructions (conditional+direct+indirect jumps)
  MIPS_GRP_JUMP, ///< = CS_GRP_JUMP
  // all call instructions
  MIPS_GRP_CALL, ///< = CS_GRP_CALL
  // all return instructions
  MIPS_GRP_RET, ///< = CS_GRP_RET
  // all interrupt instructions (int+syscall)
  MIPS_GRP_INT, ///< = CS_GRP_INT
  // all interrupt return instructions
  MIPS_GRP_IRET, ///< = CS_GRP_IRET
  // all privileged instructions
  MIPS_GRP_PRIVILEGE, ///< = CS_GRP_PRIVILEGE
  // all relative branching instructions
  MIPS_GRP_BRANCH_RELATIVE, ///< = CS_GRP_BRANCH_RELATIVE

  // Architecture-specific groups
  MIPS_GRP_BITCOUNT = 128,
  MIPS_GRP_DSP,
  MIPS_GRP_DSPR2,
  MIPS_GRP_FPIDX,
  MIPS_GRP_MSA,
  MIPS_GRP_MIPS32R2,
  MIPS_GRP_MIPS64,
  MIPS_GRP_MIPS64R2,
  MIPS_GRP_SEINREG,
  MIPS_GRP_STDENC,
  MIPS_GRP_SWAP,
  MIPS_GRP_MICROMIPS,
  MIPS_GRP_MIPS16MODE,
  MIPS_GRP_FP64BIT,
  MIPS_GRP_NONANSFPMATH,
  MIPS_GRP_NOTFP64BIT,
  MIPS_GRP_NOTINMICROMIPS,
  MIPS_GRP_NOTNACL,
  MIPS_GRP_NOTMIPS32R6,
  MIPS_GRP_NOTMIPS64R6,
  MIPS_GRP_CNMIPS,
  MIPS_GRP_MIPS32,
  MIPS_GRP_MIPS32R6,
  MIPS_GRP_MIPS64R6,
  MIPS_GRP_MIPS2,
  MIPS_GRP_MIPS3,
  MIPS_GRP_MIPS3_32,
  MIPS_GRP_MIPS3_32R2,
  MIPS_GRP_MIPS4_32,
  MIPS_GRP_MIPS4_32R2,
  MIPS_GRP_MIPS5_32R2,
  MIPS_GRP_GP32BIT,
  MIPS_GRP_GP64BIT,

  MIPS_GRP_MIPS3D,
  MIPS_GRP_DSPR3,
  MIPS_GRP_EVA,
  MIPS_GRP_CRC,
  MIPS_GRP_MT,
  MIPS_GRP_MIPS64R5,
  MIPS_GRP_VIRT,
  MIPS_GRP_NOTSOFTFLOAT,
  MIPS_GRP_NOTCNMIPS,
  MIPS_GRP_MIPS32R5,
  MIPS_GRP_GINV,
  MIPS_GRP_NOINDIRECTJUMPGUARDS,
  MIPS_GRP_NOTINMIPS16MODE,
  MIPS_GRP_MADD4,
  MIPS_GRP_PTR32BIT,
  MIPS_GRP_PTR64BIT,
  MIPS_GRP_NOTMIPS3,
  MIPS_GRP_CNMIPSP,

  MIPS_GRP_ENDING,
} mips_insn_group;

#ifdef __cplusplus
}
#endif

#endif

#ifndef CAPSTONE_ARM_H
#define CAPSTONE_ARM_H

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */
/*    Rot127 <unisono@quyllur.org>, 2022-2023 */

#ifdef __cplusplus
extern "C" {
#endif

#include <assert.h>
#include <string.h>

#include "cs_operand.h"
#include "platform.h"

#ifdef _MSC_VER
#pragma warning(disable:4201)
#endif

// Enums corresponding to ARM condition codes
// The CondCodes constants map directly to the 4-bit encoding of the
// condition field for predicated instructions.
typedef enum CondCodes {
  // Meaning (integer)          Meaning (floating-point)
  ARMCC_EQ, // Equal                      Equal
  ARMCC_NE, // Not equal                  Not equal, or unordered
  ARMCC_HS, // Carry set                  >, ==, or unordered
  ARMCC_LO, // Carry clear                Less than
  ARMCC_MI, // Minus, negative            Less than
  ARMCC_PL, // Plus, positive or zero     >, ==, or unordered
  ARMCC_VS, // Overflow                   Unordered
  ARMCC_VC, // No overflow                Not unordered
  ARMCC_HI, // Unsigned higher            Greater than, or unordered
  ARMCC_LS, // Unsigned lower or same     Less than or equal
  ARMCC_GE, // Greater than or equal      Greater than or equal
  ARMCC_LT, // Less than                  Less than, or unordered
  ARMCC_GT, // Greater than               Greater than
  ARMCC_LE, // Less than or equal         <, ==, or unordered
  ARMCC_AL, // Always (unconditional)     Always (unconditional)
  ARMCC_UNDEF = 15, // Undefined
  ARMCC_Invalid = 16, // Invalid
} ARMCC_CondCodes;

inline static ARMCC_CondCodes ARMCC_getOppositeCondition(ARMCC_CondCodes CC)
{
  switch (CC) {
  default:
    // llvm_unreachable("Unknown condition code");
    assert(0);
  case ARMCC_EQ:
    return ARMCC_NE;
  case ARMCC_NE:
    return ARMCC_EQ;
  case ARMCC_HS:
    return ARMCC_LO;
  case ARMCC_LO:
    return ARMCC_HS;
  case ARMCC_MI:
    return ARMCC_PL;
  case ARMCC_PL:
    return ARMCC_MI;
  case ARMCC_VS:
    return ARMCC_VC;
  case ARMCC_VC:
    return ARMCC_VS;
  case ARMCC_HI:
    return ARMCC_LS;
  case ARMCC_LS:
    return ARMCC_HI;
  case ARMCC_GE:
    return ARMCC_LT;
  case ARMCC_LT:
    return ARMCC_GE;
  case ARMCC_GT:
    return ARMCC_LE;
  case ARMCC_LE:
    return ARMCC_GT;
  }
}

/// getSwappedCondition - assume the flags are set by MI(a,b), return
/// the condition code if we modify the instructions such that flags are
/// set by MI(b,a).
inline static ARMCC_CondCodes ARMCC_getSwappedCondition(ARMCC_CondCodes CC)
{
  switch (CC) {
  default:
    return ARMCC_AL;
  case ARMCC_EQ:
    return ARMCC_EQ;
  case ARMCC_NE:
    return ARMCC_NE;
  case ARMCC_HS:
    return ARMCC_LS;
  case ARMCC_LO:
    return ARMCC_HI;
  case ARMCC_HI:
    return ARMCC_LO;
  case ARMCC_LS:
    return ARMCC_HS;
  case ARMCC_GE:
    return ARMCC_LE;
  case ARMCC_LT:
    return ARMCC_GT;
  case ARMCC_GT:
    return ARMCC_LT;
  case ARMCC_LE:
    return ARMCC_GE;
  }
}

typedef enum VPTCodes {
  ARMVCC_None = 0,
  ARMVCC_Then,
  ARMVCC_Else
} ARMVCC_VPTCodes;

/// Mask values for IT and VPT Blocks, to be used by MCOperands.
/// Note that this is different from the "real" encoding used by the
/// instructions. In this encoding, the lowest set bit indicates the end of
/// the encoding, and above that, "1" indicates an else, while "0" indicates
/// a then.
///   Tx = x100
///   Txy = xy10
///   Txyz = xyz1
typedef enum PredBlockMask {
  ARM_PredBlockMaskInvalid = 0,
  ARM_T = 0x8, // 0b1000
  ARM_TT = 0x4, // 0b0100
  ARM_TE = 0xc, // 0b1100
  ARM_TTT = 0x2, // 0b0010
  ARM_TTE = 0x6, // 0b0110
  ARM_TEE = 0xe, // 0b1110
  ARM_TET = 0xa, // 0b1010
  ARM_TTTT = 0x1, // 0b0001
  ARM_TTTE = 0x3, // 0b0011
  ARM_TTEE = 0x7, // 0b0111
  ARM_TTET = 0x5, // 0b0101
  ARM_TEEE = 0xf, // 0b1111
  ARM_TEET = 0xd, // 0b1101
  ARM_TETT = 0x9, // 0b1001
  ARM_TETE = 0xb, // 0b1011
} ARM_PredBlockMask;

// Expands a PredBlockMask by adding an E or a T at the end, depending on Kind.
// e.g ExpandPredBlockMask(T, Then) = TT, ExpandPredBlockMask(TT, Else) = TTE,
// and so on.
inline static const char *ARMVPTPredToString(ARMVCC_VPTCodes CC)
{
  switch (CC) {
  case ARMVCC_None:
    return "none";
  case ARMVCC_Then:
    return "t";
  case ARMVCC_Else:
    return "e";
  }
  assert(0 && "Unknown VPT code");
  return "";
}

inline static unsigned ARMVectorCondCodeFromString(const char CC)
{
  switch (CC) {
  default:
    return ~0U;
  case 't':
    return ARMVCC_Then;
  case 'e':
    return ARMVCC_Else;
  }
}

inline static const char *ARMCondCodeToString(ARMCC_CondCodes CC)
{
  switch (CC) {
  default:
    assert(0 && "Unknown condition code");
  case ARMCC_EQ:
    return "eq";
  case ARMCC_NE:
    return "ne";
  case ARMCC_HS:
    return "hs";
  case ARMCC_LO:
    return "lo";
  case ARMCC_MI:
    return "mi";
  case ARMCC_PL:
    return "pl";
  case ARMCC_VS:
    return "vs";
  case ARMCC_VC:
    return "vc";
  case ARMCC_HI:
    return "hi";
  case ARMCC_LS:
    return "ls";
  case ARMCC_GE:
    return "ge";
  case ARMCC_LT:
    return "lt";
  case ARMCC_GT:
    return "gt";
  case ARMCC_LE:
    return "le";
  case ARMCC_AL:
    return "al";
  }
}

inline static unsigned ARMCondCodeFromString(const char *CC)
{
  if (strcmp("eq", CC) == 0)
    return ARMCC_EQ;
  else if (strcmp("ne", CC) == 0)
    return ARMCC_NE;
  else if (strcmp("hs", CC) == 0)
    return ARMCC_HS;
  else if (strcmp("cs", CC) == 0)
    return ARMCC_HS;
  else if (strcmp("lo", CC) == 0)
    return ARMCC_LO;
  else if (strcmp("cc", CC) == 0)
    return ARMCC_LO;
  else if (strcmp("mi", CC) == 0)
    return ARMCC_MI;
  else if (strcmp("pl", CC) == 0)
    return ARMCC_PL;
  else if (strcmp("vs", CC) == 0)
    return ARMCC_VS;
  else if (strcmp("vc", CC) == 0)
    return ARMCC_VC;
  else if (strcmp("hi", CC) == 0)
    return ARMCC_HI;
  else if (strcmp("ls", CC) == 0)
    return ARMCC_LS;
  else if (strcmp("ge", CC) == 0)
    return ARMCC_GE;
  else if (strcmp("lt", CC) == 0)
    return ARMCC_LT;
  else if (strcmp("gt", CC) == 0)
    return ARMCC_GT;
  else if (strcmp("le", CC) == 0)
    return ARMCC_LE;
  else if (strcmp("al", CC) == 0)
    return ARMCC_AL;
  return (~0U);
}

/// ARM shift type
typedef enum arm_shifter {
	ARM_SFT_INVALID = 0,
	ARM_SFT_ASR,
	ARM_SFT_LSL,
	ARM_SFT_LSR,
	ARM_SFT_ROR,
	ARM_SFT_RRX,
	ARM_SFT_UXTW,

	// Added by Capstone to signal that the shift amount is stored in a register.
	// shift.val should be interpreted as register id.
	ARM_SFT_REG,
	ARM_SFT_ASR_REG,
	ARM_SFT_LSL_REG,
	ARM_SFT_LSR_REG,
	ARM_SFT_ROR_REG,
	// Others are not defined in the ISA.
} arm_shifter;

/// The memory barrier constants map directly to the 4-bit encoding of
/// the option field for Memory Barrier operations.
typedef enum MemBOpt {
	ARM_MB_RESERVED_0,
	ARM_MB_OSHLD,
	ARM_MB_OSHST,
	ARM_MB_OSH,
	ARM_MB_RESERVED_4,
	ARM_MB_NSHLD,
	ARM_MB_NSHST,
	ARM_MB_NSH,
	ARM_MB_RESERVED_8,
	ARM_MB_ISHLD,
	ARM_MB_ISHST,
	ARM_MB_ISH,
	ARM_MB_RESERVED_12,
	ARM_MB_LD,
	ARM_MB_ST,
	ARM_MB_SY,
} arm_mem_bo_opt;

typedef enum {
	// SPSR* field flags can be OR combined
	ARM_FIELD_SPSR_C = 1,
	ARM_FIELD_SPSR_X = 2,
	ARM_FIELD_SPSR_S = 4,
	ARM_FIELD_SPSR_F = 8,

	// CPSR* field flags can be OR combined
	ARM_FIELD_CPSR_C = 16,
	ARM_FIELD_CPSR_X = 32,
	ARM_FIELD_CPSR_S = 64,
	ARM_FIELD_CPSR_F = 128,
} arm_spsr_cspr_bits;

// From LLVM docs:
// The values here come from B9.2.3 of the ARM ARM, where bits 4-0 are SysM field
// and bit 5 is R.
typedef enum {
	// generated content <ARMGenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_BankedReg> begin
	// clang-format off

	ARM_BANKEDREG_ELR_HYP = 0x1e,
	ARM_BANKEDREG_LR_ABT = 0x14,
	ARM_BANKEDREG_LR_FIQ = 0xe,
	ARM_BANKEDREG_LR_IRQ = 0x10,
	ARM_BANKEDREG_LR_MON = 0x1c,
	ARM_BANKEDREG_LR_SVC = 0x12,
	ARM_BANKEDREG_LR_UND = 0x16,
	ARM_BANKEDREG_LR_USR = 0x6,
	ARM_BANKEDREG_R10_FIQ = 0xa,
	ARM_BANKEDREG_R10_USR = 0x2,
	ARM_BANKEDREG_R11_FIQ = 0xb,
	ARM_BANKEDREG_R11_USR = 0x3,
	ARM_BANKEDREG_R12_FIQ = 0xc,
	ARM_BANKEDREG_R12_USR = 0x4,
	ARM_BANKEDREG_R8_FIQ = 0x8,
	ARM_BANKEDREG_R8_USR = 0x0,
	ARM_BANKEDREG_R9_FIQ = 0x9,
	ARM_BANKEDREG_R9_USR = 0x1,
	ARM_BANKEDREG_SPSR_ABT = 0x34,
	ARM_BANKEDREG_SPSR_FIQ = 0x2e,
	ARM_BANKEDREG_SPSR_HYP = 0x3e,
	ARM_BANKEDREG_SPSR_IRQ = 0x30,
	ARM_BANKEDREG_SPSR_MON = 0x3c,
	ARM_BANKEDREG_SPSR_SVC = 0x32,
	ARM_BANKEDREG_SPSR_UND = 0x36,
	ARM_BANKEDREG_SP_ABT = 0x15,
	ARM_BANKEDREG_SP_FIQ = 0xd,
	ARM_BANKEDREG_SP_HYP = 0x1f,
	ARM_BANKEDREG_SP_IRQ = 0x11,
	ARM_BANKEDREG_SP_MON = 0x1d,
	ARM_BANKEDREG_SP_SVC = 0x13,
	ARM_BANKEDREG_SP_UND = 0x17,
	ARM_BANKEDREG_SP_USR = 0x5,

	// clang-format on
	// generated content <ARMGenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_BankedReg> end
} arm_bankedreg;

typedef enum {
	// generated content <ARMGenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_MClassSysReg> begin
	// clang-format off

	ARM_MCLASSSYSREG_APSR = 0x800,
	ARM_MCLASSSYSREG_APSR_G = 0x400,
	ARM_MCLASSSYSREG_APSR_NZCVQ = 0x800,
	ARM_MCLASSSYSREG_APSR_NZCVQG = 0xc00,
	ARM_MCLASSSYSREG_BASEPRI = 0x811,
	ARM_MCLASSSYSREG_BASEPRI_MAX = 0x812,
	ARM_MCLASSSYSREG_BASEPRI_NS = 0x891,
	ARM_MCLASSSYSREG_CONTROL = 0x814,
	ARM_MCLASSSYSREG_CONTROL_NS = 0x894,
	ARM_MCLASSSYSREG_EAPSR = 0x802,
	ARM_MCLASSSYSREG_EAPSR_G = 0x402,
	ARM_MCLASSSYSREG_EAPSR_NZCVQ = 0x802,
	ARM_MCLASSSYSREG_EAPSR_NZCVQG = 0xc02,
	ARM_MCLASSSYSREG_EPSR = 0x806,
	ARM_MCLASSSYSREG_FAULTMASK = 0x813,
	ARM_MCLASSSYSREG_FAULTMASK_NS = 0x893,
	ARM_MCLASSSYSREG_IAPSR = 0x801,
	ARM_MCLASSSYSREG_IAPSR_G = 0x401,
	ARM_MCLASSSYSREG_IAPSR_NZCVQ = 0x801,
	ARM_MCLASSSYSREG_IAPSR_NZCVQG = 0xc01,
	ARM_MCLASSSYSREG_IEPSR = 0x807,
	ARM_MCLASSSYSREG_IPSR = 0x805,
	ARM_MCLASSSYSREG_MSP = 0x808,
	ARM_MCLASSSYSREG_MSPLIM = 0x80a,
	ARM_MCLASSSYSREG_MSPLIM_NS = 0x88a,
	ARM_MCLASSSYSREG_MSP_NS = 0x888,
	ARM_MCLASSSYSREG_PAC_KEY_P_0 = 0x820,
	ARM_MCLASSSYSREG_PAC_KEY_P_0_NS = 0x8a0,
	ARM_MCLASSSYSREG_PAC_KEY_P_1 = 0x821,
	ARM_MCLASSSYSREG_PAC_KEY_P_1_NS = 0x8a1,
	ARM_MCLASSSYSREG_PAC_KEY_P_2 = 0x822,
	ARM_MCLASSSYSREG_PAC_KEY_P_2_NS = 0x8a2,
	ARM_MCLASSSYSREG_PAC_KEY_P_3 = 0x823,
	ARM_MCLASSSYSREG_PAC_KEY_P_3_NS = 0x8a3,
	ARM_MCLASSSYSREG_PAC_KEY_U_0 = 0x824,
	ARM_MCLASSSYSREG_PAC_KEY_U_0_NS = 0x8a4,
	ARM_MCLASSSYSREG_PAC_KEY_U_1 = 0x825,
	ARM_MCLASSSYSREG_PAC_KEY_U_1_NS = 0x8a5,
	ARM_MCLASSSYSREG_PAC_KEY_U_2 = 0x826,
	ARM_MCLASSSYSREG_PAC_KEY_U_2_NS = 0x8a6,
	ARM_MCLASSSYSREG_PAC_KEY_U_3 = 0x827,
	ARM_MCLASSSYSREG_PAC_KEY_U_3_NS = 0x8a7,
	ARM_MCLASSSYSREG_PRIMASK = 0x810,
	ARM_MCLASSSYSREG_PRIMASK_NS = 0x890,
	ARM_MCLASSSYSREG_PSP = 0x809,
	ARM_MCLASSSYSREG_PSPLIM = 0x80b,
	ARM_MCLASSSYSREG_PSPLIM_NS = 0x88b,
	ARM_MCLASSSYSREG_PSP_NS = 0x889,
	ARM_MCLASSSYSREG_SP_NS = 0x898,
	ARM_MCLASSSYSREG_XPSR = 0x803,
	ARM_MCLASSSYSREG_XPSR_G = 0x403,
	ARM_MCLASSSYSREG_XPSR_NZCVQ = 0x803,
	ARM_MCLASSSYSREG_XPSR_NZCVQG = 0xc03,

	// clang-format on
	// generated content <ARMGenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_MClassSysReg> end
} arm_sysreg;

typedef union {
  arm_sysreg mclasssysreg;
  arm_bankedreg bankedreg;
  int raw_val; ///< Raw value for assignment in generated files.
} arm_sysop_reg;

/// Operand type for instruction's operands
typedef enum arm_op_type {
	ARM_OP_INVALID = CS_OP_INVALID, ///< Invalid
	ARM_OP_REG = CS_OP_REG, ///< Register operand
	ARM_OP_IMM = CS_OP_IMM, ///< Immediate operand
	ARM_OP_FP = CS_OP_FP,  ///< Floating-Point operand
	ARM_OP_PRED = CS_OP_PRED, ///< Predicate
	ARM_OP_CIMM = CS_OP_SPECIAL + 0, ///< C-Immediate (coprocessor registers)
	ARM_OP_PIMM = CS_OP_SPECIAL + 1, ///< P-Immediate (coprocessor registers)
	ARM_OP_SETEND = CS_OP_SPECIAL + 2,	///< operand for SETEND instruction
	ARM_OP_SYSREG = CS_OP_SPECIAL + 3,	///< MSR/MRS special register operand
	ARM_OP_BANKEDREG = CS_OP_SPECIAL + 4,	///< Banked register operand
	ARM_OP_SPSR = CS_OP_SPECIAL + 5,	///< Collection of SPSR bits
	ARM_OP_CPSR = CS_OP_SPECIAL + 6,	///< Collection of CPSR bits
	ARM_OP_SYSM = CS_OP_SPECIAL + 7,	///< Raw SYSm field
	ARM_OP_VPRED_R = CS_OP_SPECIAL + 8, ///< Vector predicate. Leaves inactive lanes of output vector register unchanged.
	ARM_OP_VPRED_N = CS_OP_SPECIAL + 9, ///< Vector predicate. Don't preserved inactive lanes of output register.
	ARM_OP_MEM = CS_OP_MEM, ///< Memory operand
} arm_op_type;

/// Operand type for SETEND instruction
typedef enum arm_setend_type {
	ARM_SETEND_INVALID = 0,	///< Uninitialized.
	ARM_SETEND_BE,	///< BE operand.
	ARM_SETEND_LE, ///< LE operand
} arm_setend_type;

typedef enum arm_cpsmode_type {
	ARM_CPSMODE_INVALID = 0,
	ARM_CPSMODE_IE = 2,
	ARM_CPSMODE_ID = 3
} arm_cpsmode_type;

/// Operand type for SETEND instruction
typedef enum arm_cpsflag_type {
	ARM_CPSFLAG_INVALID = 0,
	ARM_CPSFLAG_F = 1,
	ARM_CPSFLAG_I = 2,
	ARM_CPSFLAG_A = 4,
	ARM_CPSFLAG_NONE = 16,	///< no flag
} arm_cpsflag_type;

/// Data type for elements of vector instructions.
typedef enum arm_vectordata_type {
	ARM_VECTORDATA_INVALID = 0,

	// Integer type
	ARM_VECTORDATA_I8,
	ARM_VECTORDATA_I16,
	ARM_VECTORDATA_I32,
	ARM_VECTORDATA_I64,

	// Signed integer type
	ARM_VECTORDATA_S8,
	ARM_VECTORDATA_S16,
	ARM_VECTORDATA_S32,
	ARM_VECTORDATA_S64,

	// Unsigned integer type
	ARM_VECTORDATA_U8,
	ARM_VECTORDATA_U16,
	ARM_VECTORDATA_U32,
	ARM_VECTORDATA_U64,

	// Data type for VMUL/VMULL
	ARM_VECTORDATA_P8,
	ARM_VECTORDATA_P16,

	// Floating type
	ARM_VECTORDATA_F16,
	ARM_VECTORDATA_F32,
	ARM_VECTORDATA_F64,

	// Convert float <-> float
	ARM_VECTORDATA_F16F64, // f16.f64
	ARM_VECTORDATA_F64F16, // f64.f16
	ARM_VECTORDATA_F32F16, // f32.f16
	ARM_VECTORDATA_F16F32, // f32.f16
	ARM_VECTORDATA_F64F32, // f64.f32
	ARM_VECTORDATA_F32F64, // f32.f64

	// Convert integer <-> float
	ARM_VECTORDATA_S32F32, // s32.f32
	ARM_VECTORDATA_U32F32, // u32.f32
	ARM_VECTORDATA_F32S32, // f32.s32
	ARM_VECTORDATA_F32U32, // f32.u32
	ARM_VECTORDATA_F64S16, // f64.s16
	ARM_VECTORDATA_F32S16, // f32.s16
	ARM_VECTORDATA_F64S32, // f64.s32
	ARM_VECTORDATA_S16F64, // s16.f64
	ARM_VECTORDATA_S16F32, // s16.f64
	ARM_VECTORDATA_S32F64, // s32.f64
	ARM_VECTORDATA_U16F64, // u16.f64
	ARM_VECTORDATA_U16F32, // u16.f32
	ARM_VECTORDATA_U32F64, // u32.f64
	ARM_VECTORDATA_F64U16, // f64.u16
	ARM_VECTORDATA_F32U16, // f32.u16
	ARM_VECTORDATA_F64U32, // f64.u32
	ARM_VECTORDATA_F16U16, // f16.u16
	ARM_VECTORDATA_U16F16, // u16.f16
	ARM_VECTORDATA_F16U32, // f16.u32
	ARM_VECTORDATA_U32F16, // u32.f16
	ARM_VECTORDATA_F16S16,
	ARM_VECTORDATA_S16F16,
	ARM_VECTORDATA_F16S32,
	ARM_VECTORDATA_S32F16,
} arm_vectordata_type;

/// ARM registers
typedef enum arm_reg {
	// generated content <ARMGenCSRegEnum.inc> begin
	// clang-format off

	ARM_REG_INVALID = 0,
	ARM_REG_APSR = 1,
	ARM_REG_APSR_NZCV = 2,
	ARM_REG_CPSR = 3,
	ARM_REG_FPCXTNS = 4,
	ARM_REG_FPCXTS = 5,
	ARM_REG_FPEXC = 6,
	ARM_REG_FPINST = 7,
	ARM_REG_FPSCR = 8,
	ARM_REG_FPSCR_NZCV = 9,
	ARM_REG_FPSCR_NZCVQC = 10,
	ARM_REG_FPSID = 11,
	ARM_REG_ITSTATE = 12,
	ARM_REG_LR = 13,
	ARM_REG_PC = 14,
	ARM_REG_RA_AUTH_CODE = 15,
	ARM_REG_SP = 16,
	ARM_REG_SPSR = 17,
	ARM_REG_VPR = 18,
	ARM_REG_ZR = 19,
	ARM_REG_D0 = 20,
	ARM_REG_D1 = 21,
	ARM_REG_D2 = 22,
	ARM_REG_D3 = 23,
	ARM_REG_D4 = 24,
	ARM_REG_D5 = 25,
	ARM_REG_D6 = 26,
	ARM_REG_D7 = 27,
	ARM_REG_D8 = 28,
	ARM_REG_D9 = 29,
	ARM_REG_D10 = 30,
	ARM_REG_D11 = 31,
	ARM_REG_D12 = 32,
	ARM_REG_D13 = 33,
	ARM_REG_D14 = 34,
	ARM_REG_D15 = 35,
	ARM_REG_D16 = 36,
	ARM_REG_D17 = 37,
	ARM_REG_D18 = 38,
	ARM_REG_D19 = 39,
	ARM_REG_D20 = 40,
	ARM_REG_D21 = 41,
	ARM_REG_D22 = 42,
	ARM_REG_D23 = 43,
	ARM_REG_D24 = 44,
	ARM_REG_D25 = 45,
	ARM_REG_D26 = 46,
	ARM_REG_D27 = 47,
	ARM_REG_D28 = 48,
	ARM_REG_D29 = 49,
	ARM_REG_D30 = 50,
	ARM_REG_D31 = 51,
	ARM_REG_FPINST2 = 52,
	ARM_REG_MVFR0 = 53,
	ARM_REG_MVFR1 = 54,
	ARM_REG_MVFR2 = 55,
	ARM_REG_P0 = 56,
	ARM_REG_Q0 = 57,
	ARM_REG_Q1 = 58,
	ARM_REG_Q2 = 59,
	ARM_REG_Q3 = 60,
	ARM_REG_Q4 = 61,
	ARM_REG_Q5 = 62,
	ARM_REG_Q6 = 63,
	ARM_REG_Q7 = 64,
	ARM_REG_Q8 = 65,
	ARM_REG_Q9 = 66,
	ARM_REG_Q10 = 67,
	ARM_REG_Q11 = 68,
	ARM_REG_Q12 = 69,
	ARM_REG_Q13 = 70,
	ARM_REG_Q14 = 71,
	ARM_REG_Q15 = 72,
	ARM_REG_R0 = 73,
	ARM_REG_R1 = 74,
	ARM_REG_R2 = 75,
	ARM_REG_R3 = 76,
	ARM_REG_R4 = 77,
	ARM_REG_R5 = 78,
	ARM_REG_R6 = 79,
	ARM_REG_R7 = 80,
	ARM_REG_R8 = 81,
	ARM_REG_R9 = 82,
	ARM_REG_R10 = 83,
	ARM_REG_R11 = 84,
	ARM_REG_R12 = 85,
	ARM_REG_S0 = 86,
	ARM_REG_S1 = 87,
	ARM_REG_S2 = 88,
	ARM_REG_S3 = 89,
	ARM_REG_S4 = 90,
	ARM_REG_S5 = 91,
	ARM_REG_S6 = 92,
	ARM_REG_S7 = 93,
	ARM_REG_S8 = 94,
	ARM_REG_S9 = 95,
	ARM_REG_S10 = 96,
	ARM_REG_S11 = 97,
	ARM_REG_S12 = 98,
	ARM_REG_S13 = 99,
	ARM_REG_S14 = 100,
	ARM_REG_S15 = 101,
	ARM_REG_S16 = 102,
	ARM_REG_S17 = 103,
	ARM_REG_S18 = 104,
	ARM_REG_S19 = 105,
	ARM_REG_S20 = 106,
	ARM_REG_S21 = 107,
	ARM_REG_S22 = 108,
	ARM_REG_S23 = 109,
	ARM_REG_S24 = 110,
	ARM_REG_S25 = 111,
	ARM_REG_S26 = 112,
	ARM_REG_S27 = 113,
	ARM_REG_S28 = 114,
	ARM_REG_S29 = 115,
	ARM_REG_S30 = 116,
	ARM_REG_S31 = 117,
	ARM_REG_D0_D2 = 118,
	ARM_REG_D1_D3 = 119,
	ARM_REG_D2_D4 = 120,
	ARM_REG_D3_D5 = 121,
	ARM_REG_D4_D6 = 122,
	ARM_REG_D5_D7 = 123,
	ARM_REG_D6_D8 = 124,
	ARM_REG_D7_D9 = 125,
	ARM_REG_D8_D10 = 126,
	ARM_REG_D9_D11 = 127,
	ARM_REG_D10_D12 = 128,
	ARM_REG_D11_D13 = 129,
	ARM_REG_D12_D14 = 130,
	ARM_REG_D13_D15 = 131,
	ARM_REG_D14_D16 = 132,
	ARM_REG_D15_D17 = 133,
	ARM_REG_D16_D18 = 134,
	ARM_REG_D17_D19 = 135,
	ARM_REG_D18_D20 = 136,
	ARM_REG_D19_D21 = 137,
	ARM_REG_D20_D22 = 138,
	ARM_REG_D21_D23 = 139,
	ARM_REG_D22_D24 = 140,
	ARM_REG_D23_D25 = 141,
	ARM_REG_D24_D26 = 142,
	ARM_REG_D25_D27 = 143,
	ARM_REG_D26_D28 = 144,
	ARM_REG_D27_D29 = 145,
	ARM_REG_D28_D30 = 146,
	ARM_REG_D29_D31 = 147,
	ARM_REG_Q0_Q1 = 148,
	ARM_REG_Q1_Q2 = 149,
	ARM_REG_Q2_Q3 = 150,
	ARM_REG_Q3_Q4 = 151,
	ARM_REG_Q4_Q5 = 152,
	ARM_REG_Q5_Q6 = 153,
	ARM_REG_Q6_Q7 = 154,
	ARM_REG_Q7_Q8 = 155,
	ARM_REG_Q8_Q9 = 156,
	ARM_REG_Q9_Q10 = 157,
	ARM_REG_Q10_Q11 = 158,
	ARM_REG_Q11_Q12 = 159,
	ARM_REG_Q12_Q13 = 160,
	ARM_REG_Q13_Q14 = 161,
	ARM_REG_Q14_Q15 = 162,
	ARM_REG_Q0_Q1_Q2_Q3 = 163,
	ARM_REG_Q1_Q2_Q3_Q4 = 164,
	ARM_REG_Q2_Q3_Q4_Q5 = 165,
	ARM_REG_Q3_Q4_Q5_Q6 = 166,
	ARM_REG_Q4_Q5_Q6_Q7 = 167,
	ARM_REG_Q5_Q6_Q7_Q8 = 168,
	ARM_REG_Q6_Q7_Q8_Q9 = 169,
	ARM_REG_Q7_Q8_Q9_Q10 = 170,
	ARM_REG_Q8_Q9_Q10_Q11 = 171,
	ARM_REG_Q9_Q10_Q11_Q12 = 172,
	ARM_REG_Q10_Q11_Q12_Q13 = 173,
	ARM_REG_Q11_Q12_Q13_Q14 = 174,
	ARM_REG_Q12_Q13_Q14_Q15 = 175,
	ARM_REG_R0_R1 = 176,
	ARM_REG_R2_R3 = 177,
	ARM_REG_R4_R5 = 178,
	ARM_REG_R6_R7 = 179,
	ARM_REG_R8_R9 = 180,
	ARM_REG_R10_R11 = 181,
	ARM_REG_R12_SP = 182,
	ARM_REG_D0_D1_D2 = 183,
	ARM_REG_D1_D2_D3 = 184,
	ARM_REG_D2_D3_D4 = 185,
	ARM_REG_D3_D4_D5 = 186,
	ARM_REG_D4_D5_D6 = 187,
	ARM_REG_D5_D6_D7 = 188,
	ARM_REG_D6_D7_D8 = 189,
	ARM_REG_D7_D8_D9 = 190,
	ARM_REG_D8_D9_D10 = 191,
	ARM_REG_D9_D10_D11 = 192,
	ARM_REG_D10_D11_D12 = 193,
	ARM_REG_D11_D12_D13 = 194,
	ARM_REG_D12_D13_D14 = 195,
	ARM_REG_D13_D14_D15 = 196,
	ARM_REG_D14_D15_D16 = 197,
	ARM_REG_D15_D16_D17 = 198,
	ARM_REG_D16_D17_D18 = 199,
	ARM_REG_D17_D18_D19 = 200,
	ARM_REG_D18_D19_D20 = 201,
	ARM_REG_D19_D20_D21 = 202,
	ARM_REG_D20_D21_D22 = 203,
	ARM_REG_D21_D22_D23 = 204,
	ARM_REG_D22_D23_D24 = 205,
	ARM_REG_D23_D24_D25 = 206,
	ARM_REG_D24_D25_D26 = 207,
	ARM_REG_D25_D26_D27 = 208,
	ARM_REG_D26_D27_D28 = 209,
	ARM_REG_D27_D28_D29 = 210,
	ARM_REG_D28_D29_D30 = 211,
	ARM_REG_D29_D30_D31 = 212,
	ARM_REG_D0_D2_D4 = 213,
	ARM_REG_D1_D3_D5 = 214,
	ARM_REG_D2_D4_D6 = 215,
	ARM_REG_D3_D5_D7 = 216,
	ARM_REG_D4_D6_D8 = 217,
	ARM_REG_D5_D7_D9 = 218,
	ARM_REG_D6_D8_D10 = 219,
	ARM_REG_D7_D9_D11 = 220,
	ARM_REG_D8_D10_D12 = 221,
	ARM_REG_D9_D11_D13 = 222,
	ARM_REG_D10_D12_D14 = 223,
	ARM_REG_D11_D13_D15 = 224,
	ARM_REG_D12_D14_D16 = 225,
	ARM_REG_D13_D15_D17 = 226,
	ARM_REG_D14_D16_D18 = 227,
	ARM_REG_D15_D17_D19 = 228,
	ARM_REG_D16_D18_D20 = 229,
	ARM_REG_D17_D19_D21 = 230,
	ARM_REG_D18_D20_D22 = 231,
	ARM_REG_D19_D21_D23 = 232,
	ARM_REG_D20_D22_D24 = 233,
	ARM_REG_D21_D23_D25 = 234,
	ARM_REG_D22_D24_D26 = 235,
	ARM_REG_D23_D25_D27 = 236,
	ARM_REG_D24_D26_D28 = 237,
	ARM_REG_D25_D27_D29 = 238,
	ARM_REG_D26_D28_D30 = 239,
	ARM_REG_D27_D29_D31 = 240,
	ARM_REG_D0_D2_D4_D6 = 241,
	ARM_REG_D1_D3_D5_D7 = 242,
	ARM_REG_D2_D4_D6_D8 = 243,
	ARM_REG_D3_D5_D7_D9 = 244,
	ARM_REG_D4_D6_D8_D10 = 245,
	ARM_REG_D5_D7_D9_D11 = 246,
	ARM_REG_D6_D8_D10_D12 = 247,
	ARM_REG_D7_D9_D11_D13 = 248,
	ARM_REG_D8_D10_D12_D14 = 249,
	ARM_REG_D9_D11_D13_D15 = 250,
	ARM_REG_D10_D12_D14_D16 = 251,
	ARM_REG_D11_D13_D15_D17 = 252,
	ARM_REG_D12_D14_D16_D18 = 253,
	ARM_REG_D13_D15_D17_D19 = 254,
	ARM_REG_D14_D16_D18_D20 = 255,
	ARM_REG_D15_D17_D19_D21 = 256,
	ARM_REG_D16_D18_D20_D22 = 257,
	ARM_REG_D17_D19_D21_D23 = 258,
	ARM_REG_D18_D20_D22_D24 = 259,
	ARM_REG_D19_D21_D23_D25 = 260,
	ARM_REG_D20_D22_D24_D26 = 261,
	ARM_REG_D21_D23_D25_D27 = 262,
	ARM_REG_D22_D24_D26_D28 = 263,
	ARM_REG_D23_D25_D27_D29 = 264,
	ARM_REG_D24_D26_D28_D30 = 265,
	ARM_REG_D25_D27_D29_D31 = 266,
	ARM_REG_D1_D2 = 267,
	ARM_REG_D3_D4 = 268,
	ARM_REG_D5_D6 = 269,
	ARM_REG_D7_D8 = 270,
	ARM_REG_D9_D10 = 271,
	ARM_REG_D11_D12 = 272,
	ARM_REG_D13_D14 = 273,
	ARM_REG_D15_D16 = 274,
	ARM_REG_D17_D18 = 275,
	ARM_REG_D19_D20 = 276,
	ARM_REG_D21_D22 = 277,
	ARM_REG_D23_D24 = 278,
	ARM_REG_D25_D26 = 279,
	ARM_REG_D27_D28 = 280,
	ARM_REG_D29_D30 = 281,
	ARM_REG_D1_D2_D3_D4 = 282,
	ARM_REG_D3_D4_D5_D6 = 283,
	ARM_REG_D5_D6_D7_D8 = 284,
	ARM_REG_D7_D8_D9_D10 = 285,
	ARM_REG_D9_D10_D11_D12 = 286,
	ARM_REG_D11_D12_D13_D14 = 287,
	ARM_REG_D13_D14_D15_D16 = 288,
	ARM_REG_D15_D16_D17_D18 = 289,
	ARM_REG_D17_D18_D19_D20 = 290,
	ARM_REG_D19_D20_D21_D22 = 291,
	ARM_REG_D21_D22_D23_D24 = 292,
	ARM_REG_D23_D24_D25_D26 = 293,
	ARM_REG_D25_D26_D27_D28 = 294,
	ARM_REG_D27_D28_D29_D30 = 295,
	ARM_REG_ENDING, // 296

	// clang-format on
	// generated content <ARMGenCSRegEnum.inc> end

	// alias registers
	ARM_REG_R13 = ARM_REG_SP,
	ARM_REG_R14 = ARM_REG_LR,
	ARM_REG_R15 = ARM_REG_PC,

	ARM_REG_SB = ARM_REG_R9,
	ARM_REG_SL = ARM_REG_R10,
	ARM_REG_FP = ARM_REG_R11,
	ARM_REG_IP = ARM_REG_R12,
} arm_reg;

/// Instruction's operand referring to memory
/// This is associated with ARM_OP_MEM operand type above
typedef struct arm_op_mem {
	arm_reg base;	///< base register
	arm_reg index;	///< index register
	int scale;	///< scale for index register. Can be 1 if index reg is added, -1 if it is subtracted or 0 if unset.
	int disp;	///< displacement/offset value
  unsigned align; ///< Alignment of base register. 0 If not set.
} arm_op_mem;

typedef struct {
  arm_sysop_reg reg; ///< The system or banked register.
  arm_spsr_cspr_bits psr_bits; ///< SPSR/CPSR bits.
  uint16_t sysm; ///< Raw SYSm field. UINT16_MAX if unset.
  uint8_t msr_mask; ///< Mask of MSR instructions. UINT8_MAX if invalid.
} arm_sysop;

/// Instruction operand
typedef struct cs_arm_op {
	int vector_index;	///< Vector Index for some vector operands (or -1 if irrelevant)

	struct {
		arm_shifter type; ///< The shift type
		unsigned int value; ///< The amount to shift. If shift.type > ARM_SFT_REG, the value must be interpreted as register id.
	} shift;

	arm_op_type type;	///< operand type

	union {
		int reg;	///< register value for REG
		arm_sysop sysop;  ///< System operand.
		int64_t imm;			///< immediate value for C-IMM, P-IMM or IMM operand
		int pred;			///< Predicate operand value.
		double fp;			///< floating point value for FP operand
		arm_op_mem mem;		///< base/index/scale/disp value for MEM operand
		arm_setend_type setend; ///< SETEND instruction's operand type
	};

	/// in some instructions, an operand can be subtracted or added to
	/// the base register,
	/// if TRUE, this operand is subtracted. otherwise, it is added.
	bool subtracted;

	/// How is this operand accessed? (READ, WRITE or READ|WRITE)
	/// This field is combined of cs_ac_type.
	/// NOTE: this field is irrelevant if engine is compiled in DIET mode.
	uint8_t access;

	/// Neon lane index for NEON instructions (or -1 if irrelevant)
	int8_t neon_lane;
} cs_arm_op;

typedef struct {
	cs_ac_type mem_acc; ///< CGI memory access according to mayLoad and mayStore
} arm_suppl_info;

#define NUM_ARM_OPS 36

/// Instruction structure
typedef struct cs_arm {
	bool usermode;	///< User-mode registers to be loaded (for LDM/STM instructions)
	int vector_size; 	///< Scalar size for vector instructions
	arm_vectordata_type vector_data; ///< Data type for elements of vector instructions
	arm_cpsmode_type cps_mode;	///< CPS mode for CPS instruction
	arm_cpsflag_type cps_flag;	///< CPS mode for CPS instruction
	ARMCC_CondCodes cc;		///< conditional code for this insn
	ARMVCC_VPTCodes vcc;	///< Vector conditional code for this instruction.
	bool update_flags;	///< does this insn update flags?
	bool post_index;	///< only set if writeback is 'True', if 'False' pre-index, otherwise post.
	arm_mem_bo_opt mem_barrier; ///< Option for some memory barrier instructions
	// Check ARM_PredBlockMask for encoding details.
	uint8_t /* ARM_PredBlockMask */ pred_mask;	///< Used by IT/VPT block instructions.
	/// Number of operands of this instruction,
	/// or 0 when instruction has no operand.
	uint8_t op_count;

	cs_arm_op operands[NUM_ARM_OPS];	///< operands for this instruction.
} cs_arm;

/// ARM instruction
typedef enum arm_insn {
	// generated content <ARMGenCSInsnEnum.inc> begin
	// clang-format off

	ARM_INS_INVALID,
	ARM_INS_ASR,
	ARM_INS_IT,
	ARM_INS_LDRBT,
	ARM_INS_LDR,
	ARM_INS_LDRHT,
	ARM_INS_LDRSBT,
	ARM_INS_LDRSHT,
	ARM_INS_LDRT,
	ARM_INS_LSL,
	ARM_INS_LSR,
	ARM_INS_ROR,
	ARM_INS_RRX,
	ARM_INS_STRBT,
	ARM_INS_STRT,
	ARM_INS_VLD1,
	ARM_INS_VLD2,
	ARM_INS_VLD3,
	ARM_INS_VLD4,
	ARM_INS_VST1,
	ARM_INS_VST2,
	ARM_INS_VST3,
	ARM_INS_VST4,
	ARM_INS_LDRB,
	ARM_INS_LDRH,
	ARM_INS_LDRSB,
	ARM_INS_LDRSH,
	ARM_INS_MOVS,
	ARM_INS_MOV,
	ARM_INS_STRB,
	ARM_INS_STRH,
	ARM_INS_STR,
	ARM_INS_ADC,
	ARM_INS_ADD,
	ARM_INS_ADR,
	ARM_INS_AESD,
	ARM_INS_AESE,
	ARM_INS_AESIMC,
	ARM_INS_AESMC,
	ARM_INS_AND,
	ARM_INS_VDOT,
	ARM_INS_VCVT,
	ARM_INS_VCVTB,
	ARM_INS_VCVTT,
	ARM_INS_BFC,
	ARM_INS_BFI,
	ARM_INS_BIC,
	ARM_INS_BKPT,
	ARM_INS_BL,
	ARM_INS_BLX,
	ARM_INS_BX,
	ARM_INS_BXJ,
	ARM_INS_B,
	ARM_INS_CX1,
	ARM_INS_CX1A,
	ARM_INS_CX1D,
	ARM_INS_CX1DA,
	ARM_INS_CX2,
	ARM_INS_CX2A,
	ARM_INS_CX2D,
	ARM_INS_CX2DA,
	ARM_INS_CX3,
	ARM_INS_CX3A,
	ARM_INS_CX3D,
	ARM_INS_CX3DA,
	ARM_INS_VCX1A,
	ARM_INS_VCX1,
	ARM_INS_VCX2A,
	ARM_INS_VCX2,
	ARM_INS_VCX3A,
	ARM_INS_VCX3,
	ARM_INS_CDP,
	ARM_INS_CDP2,
	ARM_INS_CLREX,
	ARM_INS_CLZ,
	ARM_INS_CMN,
	ARM_INS_CMP,
	ARM_INS_CPS,
	ARM_INS_CRC32B,
	ARM_INS_CRC32CB,
	ARM_INS_CRC32CH,
	ARM_INS_CRC32CW,
	ARM_INS_CRC32H,
	ARM_INS_CRC32W,
	ARM_INS_DBG,
	ARM_INS_DMB,
	ARM_INS_DSB,
	ARM_INS_EOR,
	ARM_INS_ERET,
	ARM_INS_VMOV,
	ARM_INS_FLDMDBX,
	ARM_INS_FLDMIAX,
	ARM_INS_VMRS,
	ARM_INS_FSTMDBX,
	ARM_INS_FSTMIAX,
	ARM_INS_HINT,
	ARM_INS_HLT,
	ARM_INS_HVC,
	ARM_INS_ISB,
	ARM_INS_LDA,
	ARM_INS_LDAB,
	ARM_INS_LDAEX,
	ARM_INS_LDAEXB,
	ARM_INS_LDAEXD,
	ARM_INS_LDAEXH,
	ARM_INS_LDAH,
	ARM_INS_LDC2L,
	ARM_INS_LDC2,
	ARM_INS_LDCL,
	ARM_INS_LDC,
	ARM_INS_LDMDA,
	ARM_INS_LDMDB,
	ARM_INS_LDM,
	ARM_INS_LDMIB,
	ARM_INS_LDRD,
	ARM_INS_LDREX,
	ARM_INS_LDREXB,
	ARM_INS_LDREXD,
	ARM_INS_LDREXH,
	ARM_INS_MCR,
	ARM_INS_MCR2,
	ARM_INS_MCRR,
	ARM_INS_MCRR2,
	ARM_INS_MLA,
	ARM_INS_MLS,
	ARM_INS_MOVT,
	ARM_INS_MOVW,
	ARM_INS_MRC,
	ARM_INS_MRC2,
	ARM_INS_MRRC,
	ARM_INS_MRRC2,
	ARM_INS_MRS,
	ARM_INS_MSR,
	ARM_INS_MUL,
	ARM_INS_ASRL,
	ARM_INS_DLSTP,
	ARM_INS_LCTP,
	ARM_INS_LETP,
	ARM_INS_LSLL,
	ARM_INS_LSRL,
	ARM_INS_SQRSHR,
	ARM_INS_SQRSHRL,
	ARM_INS_SQSHL,
	ARM_INS_SQSHLL,
	ARM_INS_SRSHR,
	ARM_INS_SRSHRL,
	ARM_INS_UQRSHL,
	ARM_INS_UQRSHLL,
	ARM_INS_UQSHL,
	ARM_INS_UQSHLL,
	ARM_INS_URSHR,
	ARM_INS_URSHRL,
	ARM_INS_VABAV,
	ARM_INS_VABD,
	ARM_INS_VABS,
	ARM_INS_VADC,
	ARM_INS_VADCI,
	ARM_INS_VADDLVA,
	ARM_INS_VADDLV,
	ARM_INS_VADDVA,
	ARM_INS_VADDV,
	ARM_INS_VADD,
	ARM_INS_VAND,
	ARM_INS_VBIC,
	ARM_INS_VBRSR,
	ARM_INS_VCADD,
	ARM_INS_VCLS,
	ARM_INS_VCLZ,
	ARM_INS_VCMLA,
	ARM_INS_VCMP,
	ARM_INS_VCMUL,
	ARM_INS_VCTP,
	ARM_INS_VCVTA,
	ARM_INS_VCVTM,
	ARM_INS_VCVTN,
	ARM_INS_VCVTP,
	ARM_INS_VDDUP,
	ARM_INS_VDUP,
	ARM_INS_VDWDUP,
	ARM_INS_VEOR,
	ARM_INS_VFMAS,
	ARM_INS_VFMA,
	ARM_INS_VFMS,
	ARM_INS_VHADD,
	ARM_INS_VHCADD,
	ARM_INS_VHSUB,
	ARM_INS_VIDUP,
	ARM_INS_VIWDUP,
	ARM_INS_VLD20,
	ARM_INS_VLD21,
	ARM_INS_VLD40,
	ARM_INS_VLD41,
	ARM_INS_VLD42,
	ARM_INS_VLD43,
	ARM_INS_VLDRB,
	ARM_INS_VLDRD,
	ARM_INS_VLDRH,
	ARM_INS_VLDRW,
	ARM_INS_VMAXAV,
	ARM_INS_VMAXA,
	ARM_INS_VMAXNMAV,
	ARM_INS_VMAXNMA,
	ARM_INS_VMAXNMV,
	ARM_INS_VMAXNM,
	ARM_INS_VMAXV,
	ARM_INS_VMAX,
	ARM_INS_VMINAV,
	ARM_INS_VMINA,
	ARM_INS_VMINNMAV,
	ARM_INS_VMINNMA,
	ARM_INS_VMINNMV,
	ARM_INS_VMINNM,
	ARM_INS_VMINV,
	ARM_INS_VMIN,
	ARM_INS_VMLADAVA,
	ARM_INS_VMLADAVAX,
	ARM_INS_VMLADAV,
	ARM_INS_VMLADAVX,
	ARM_INS_VMLALDAVA,
	ARM_INS_VMLALDAVAX,
	ARM_INS_VMLALDAV,
	ARM_INS_VMLALDAVX,
	ARM_INS_VMLAS,
	ARM_INS_VMLA,
	ARM_INS_VMLSDAVA,
	ARM_INS_VMLSDAVAX,
	ARM_INS_VMLSDAV,
	ARM_INS_VMLSDAVX,
	ARM_INS_VMLSLDAVA,
	ARM_INS_VMLSLDAVAX,
	ARM_INS_VMLSLDAV,
	ARM_INS_VMLSLDAVX,
	ARM_INS_VMOVLB,
	ARM_INS_VMOVLT,
	ARM_INS_VMOVNB,
	ARM_INS_VMOVNT,
	ARM_INS_VMULH,
	ARM_INS_VMULLB,
	ARM_INS_VMULLT,
	ARM_INS_VMUL,
	ARM_INS_VMVN,
	ARM_INS_VNEG,
	ARM_INS_VORN,
	ARM_INS_VORR,
	ARM_INS_VPNOT,
	ARM_INS_VPSEL,
	ARM_INS_VPST,
	ARM_INS_VPT,
	ARM_INS_VQABS,
	ARM_INS_VQADD,
	ARM_INS_VQDMLADHX,
	ARM_INS_VQDMLADH,
	ARM_INS_VQDMLAH,
	ARM_INS_VQDMLASH,
	ARM_INS_VQDMLSDHX,
	ARM_INS_VQDMLSDH,
	ARM_INS_VQDMULH,
	ARM_INS_VQDMULLB,
	ARM_INS_VQDMULLT,
	ARM_INS_VQMOVNB,
	ARM_INS_VQMOVNT,
	ARM_INS_VQMOVUNB,
	ARM_INS_VQMOVUNT,
	ARM_INS_VQNEG,
	ARM_INS_VQRDMLADHX,
	ARM_INS_VQRDMLADH,
	ARM_INS_VQRDMLAH,
	ARM_INS_VQRDMLASH,
	ARM_INS_VQRDMLSDHX,
	ARM_INS_VQRDMLSDH,
	ARM_INS_VQRDMULH,
	ARM_INS_VQRSHL,
	ARM_INS_VQRSHRNB,
	ARM_INS_VQRSHRNT,
	ARM_INS_VQRSHRUNB,
	ARM_INS_VQRSHRUNT,
	ARM_INS_VQSHLU,
	ARM_INS_VQSHL,
	ARM_INS_VQSHRNB,
	ARM_INS_VQSHRNT,
	ARM_INS_VQSHRUNB,
	ARM_INS_VQSHRUNT,
	ARM_INS_VQSUB,
	ARM_INS_VREV16,
	ARM_INS_VREV32,
	ARM_INS_VREV64,
	ARM_INS_VRHADD,
	ARM_INS_VRINTA,
	ARM_INS_VRINTM,
	ARM_INS_VRINTN,
	ARM_INS_VRINTP,
	ARM_INS_VRINTX,
	ARM_INS_VRINTZ,
	ARM_INS_VRMLALDAVHA,
	ARM_INS_VRMLALDAVHAX,
	ARM_INS_VRMLALDAVH,
	ARM_INS_VRMLALDAVHX,
	ARM_INS_VRMLSLDAVHA,
	ARM_INS_VRMLSLDAVHAX,
	ARM_INS_VRMLSLDAVH,
	ARM_INS_VRMLSLDAVHX,
	ARM_INS_VRMULH,
	ARM_INS_VRSHL,
	ARM_INS_VRSHRNB,
	ARM_INS_VRSHRNT,
	ARM_INS_VRSHR,
	ARM_INS_VSBC,
	ARM_INS_VSBCI,
	ARM_INS_VSHLC,
	ARM_INS_VSHLLB,
	ARM_INS_VSHLLT,
	ARM_INS_VSHL,
	ARM_INS_VSHRNB,
	ARM_INS_VSHRNT,
	ARM_INS_VSHR,
	ARM_INS_VSLI,
	ARM_INS_VSRI,
	ARM_INS_VST20,
	ARM_INS_VST21,
	ARM_INS_VST40,
	ARM_INS_VST41,
	ARM_INS_VST42,
	ARM_INS_VST43,
	ARM_INS_VSTRB,
	ARM_INS_VSTRD,
	ARM_INS_VSTRH,
	ARM_INS_VSTRW,
	ARM_INS_VSUB,
	ARM_INS_WLSTP,
	ARM_INS_MVN,
	ARM_INS_ORR,
	ARM_INS_PKHBT,
	ARM_INS_PKHTB,
	ARM_INS_PLDW,
	ARM_INS_PLD,
	ARM_INS_PLI,
	ARM_INS_QADD,
	ARM_INS_QADD16,
	ARM_INS_QADD8,
	ARM_INS_QASX,
	ARM_INS_QDADD,
	ARM_INS_QDSUB,
	ARM_INS_QSAX,
	ARM_INS_QSUB,
	ARM_INS_QSUB16,
	ARM_INS_QSUB8,
	ARM_INS_RBIT,
	ARM_INS_REV,
	ARM_INS_REV16,
	ARM_INS_REVSH,
	ARM_INS_RFEDA,
	ARM_INS_RFEDB,
	ARM_INS_RFEIA,
	ARM_INS_RFEIB,
	ARM_INS_RSB,
	ARM_INS_RSC,
	ARM_INS_SADD16,
	ARM_INS_SADD8,
	ARM_INS_SASX,
	ARM_INS_SB,
	ARM_INS_SBC,
	ARM_INS_SBFX,
	ARM_INS_SDIV,
	ARM_INS_SEL,
	ARM_INS_SETEND,
	ARM_INS_SETPAN,
	ARM_INS_SHA1C,
	ARM_INS_SHA1H,
	ARM_INS_SHA1M,
	ARM_INS_SHA1P,
	ARM_INS_SHA1SU0,
	ARM_INS_SHA1SU1,
	ARM_INS_SHA256H,
	ARM_INS_SHA256H2,
	ARM_INS_SHA256SU0,
	ARM_INS_SHA256SU1,
	ARM_INS_SHADD16,
	ARM_INS_SHADD8,
	ARM_INS_SHASX,
	ARM_INS_SHSAX,
	ARM_INS_SHSUB16,
	ARM_INS_SHSUB8,
	ARM_INS_SMC,
	ARM_INS_SMLABB,
	ARM_INS_SMLABT,
	ARM_INS_SMLAD,
	ARM_INS_SMLADX,
	ARM_INS_SMLAL,
	ARM_INS_SMLALBB,
	ARM_INS_SMLALBT,
	ARM_INS_SMLALD,
	ARM_INS_SMLALDX,
	ARM_INS_SMLALTB,
	ARM_INS_SMLALTT,
	ARM_INS_SMLATB,
	ARM_INS_SMLATT,
	ARM_INS_SMLAWB,
	ARM_INS_SMLAWT,
	ARM_INS_SMLSD,
	ARM_INS_SMLSDX,
	ARM_INS_SMLSLD,
	ARM_INS_SMLSLDX,
	ARM_INS_SMMLA,
	ARM_INS_SMMLAR,
	ARM_INS_SMMLS,
	ARM_INS_SMMLSR,
	ARM_INS_SMMUL,
	ARM_INS_SMMULR,
	ARM_INS_SMUAD,
	ARM_INS_SMUADX,
	ARM_INS_SMULBB,
	ARM_INS_SMULBT,
	ARM_INS_SMULL,
	ARM_INS_SMULTB,
	ARM_INS_SMULTT,
	ARM_INS_SMULWB,
	ARM_INS_SMULWT,
	ARM_INS_SMUSD,
	ARM_INS_SMUSDX,
	ARM_INS_SRSDA,
	ARM_INS_SRSDB,
	ARM_INS_SRSIA,
	ARM_INS_SRSIB,
	ARM_INS_SSAT,
	ARM_INS_SSAT16,
	ARM_INS_SSAX,
	ARM_INS_SSUB16,
	ARM_INS_SSUB8,
	ARM_INS_STC2L,
	ARM_INS_STC2,
	ARM_INS_STCL,
	ARM_INS_STC,
	ARM_INS_STL,
	ARM_INS_STLB,
	ARM_INS_STLEX,
	ARM_INS_STLEXB,
	ARM_INS_STLEXD,
	ARM_INS_STLEXH,
	ARM_INS_STLH,
	ARM_INS_STMDA,
	ARM_INS_STMDB,
	ARM_INS_STM,
	ARM_INS_STMIB,
	ARM_INS_STRD,
	ARM_INS_STREX,
	ARM_INS_STREXB,
	ARM_INS_STREXD,
	ARM_INS_STREXH,
	ARM_INS_STRHT,
	ARM_INS_SUB,
	ARM_INS_SVC,
	ARM_INS_SWP,
	ARM_INS_SWPB,
	ARM_INS_SXTAB,
	ARM_INS_SXTAB16,
	ARM_INS_SXTAH,
	ARM_INS_SXTB,
	ARM_INS_SXTB16,
	ARM_INS_SXTH,
	ARM_INS_TEQ,
	ARM_INS_TRAP,
	ARM_INS_TSB,
	ARM_INS_TST,
	ARM_INS_UADD16,
	ARM_INS_UADD8,
	ARM_INS_UASX,
	ARM_INS_UBFX,
	ARM_INS_UDF,
	ARM_INS_UDIV,
	ARM_INS_UHADD16,
	ARM_INS_UHADD8,
	ARM_INS_UHASX,
	ARM_INS_UHSAX,
	ARM_INS_UHSUB16,
	ARM_INS_UHSUB8,
	ARM_INS_UMAAL,
	ARM_INS_UMLAL,
	ARM_INS_UMULL,
	ARM_INS_UQADD16,
	ARM_INS_UQADD8,
	ARM_INS_UQASX,
	ARM_INS_UQSAX,
	ARM_INS_UQSUB16,
	ARM_INS_UQSUB8,
	ARM_INS_USAD8,
	ARM_INS_USADA8,
	ARM_INS_USAT,
	ARM_INS_USAT16,
	ARM_INS_USAX,
	ARM_INS_USUB16,
	ARM_INS_USUB8,
	ARM_INS_UXTAB,
	ARM_INS_UXTAB16,
	ARM_INS_UXTAH,
	ARM_INS_UXTB,
	ARM_INS_UXTB16,
	ARM_INS_UXTH,
	ARM_INS_VABAL,
	ARM_INS_VABA,
	ARM_INS_VABDL,
	ARM_INS_VACGE,
	ARM_INS_VACGT,
	ARM_INS_VADDHN,
	ARM_INS_VADDL,
	ARM_INS_VADDW,
	ARM_INS_VFMAB,
	ARM_INS_VFMAT,
	ARM_INS_VBIF,
	ARM_INS_VBIT,
	ARM_INS_VBSL,
	ARM_INS_VCEQ,
	ARM_INS_VCGE,
	ARM_INS_VCGT,
	ARM_INS_VCLE,
	ARM_INS_VCLT,
	ARM_INS_VCMPE,
	ARM_INS_VCNT,
	ARM_INS_VDIV,
	ARM_INS_VEXT,
	ARM_INS_VFMAL,
	ARM_INS_VFMSL,
	ARM_INS_VFNMA,
	ARM_INS_VFNMS,
	ARM_INS_VINS,
	ARM_INS_VJCVT,
	ARM_INS_VLDMDB,
	ARM_INS_VLDMIA,
	ARM_INS_VLDR,
	ARM_INS_VLLDM,
	ARM_INS_VLSTM,
	ARM_INS_VMLAL,
	ARM_INS_VMLS,
	ARM_INS_VMLSL,
	ARM_INS_VMMLA,
	ARM_INS_VMOVX,
	ARM_INS_VMOVL,
	ARM_INS_VMOVN,
	ARM_INS_VMSR,
	ARM_INS_VMULL,
	ARM_INS_VNMLA,
	ARM_INS_VNMLS,
	ARM_INS_VNMUL,
	ARM_INS_VPADAL,
	ARM_INS_VPADDL,
	ARM_INS_VPADD,
	ARM_INS_VPMAX,
	ARM_INS_VPMIN,
	ARM_INS_VQDMLAL,
	ARM_INS_VQDMLSL,
	ARM_INS_VQDMULL,
	ARM_INS_VQMOVUN,
	ARM_INS_VQMOVN,
	ARM_INS_VQRDMLSH,
	ARM_INS_VQRSHRN,
	ARM_INS_VQRSHRUN,
	ARM_INS_VQSHRN,
	ARM_INS_VQSHRUN,
	ARM_INS_VRADDHN,
	ARM_INS_VRECPE,
	ARM_INS_VRECPS,
	ARM_INS_VRINTR,
	ARM_INS_VRSHRN,
	ARM_INS_VRSQRTE,
	ARM_INS_VRSQRTS,
	ARM_INS_VRSRA,
	ARM_INS_VRSUBHN,
	ARM_INS_VSCCLRM,
	ARM_INS_VSDOT,
	ARM_INS_VSELEQ,
	ARM_INS_VSELGE,
	ARM_INS_VSELGT,
	ARM_INS_VSELVS,
	ARM_INS_VSHLL,
	ARM_INS_VSHRN,
	ARM_INS_VSMMLA,
	ARM_INS_VSQRT,
	ARM_INS_VSRA,
	ARM_INS_VSTMDB,
	ARM_INS_VSTMIA,
	ARM_INS_VSTR,
	ARM_INS_VSUBHN,
	ARM_INS_VSUBL,
	ARM_INS_VSUBW,
	ARM_INS_VSUDOT,
	ARM_INS_VSWP,
	ARM_INS_VTBL,
	ARM_INS_VTBX,
	ARM_INS_VCVTR,
	ARM_INS_VTRN,
	ARM_INS_VTST,
	ARM_INS_VUDOT,
	ARM_INS_VUMMLA,
	ARM_INS_VUSDOT,
	ARM_INS_VUSMMLA,
	ARM_INS_VUZP,
	ARM_INS_VZIP,
	ARM_INS_ADDW,
	ARM_INS_AUT,
	ARM_INS_AUTG,
	ARM_INS_BFL,
	ARM_INS_BFLX,
	ARM_INS_BF,
	ARM_INS_BFCSEL,
	ARM_INS_BFX,
	ARM_INS_BTI,
	ARM_INS_BXAUT,
	ARM_INS_CLRM,
	ARM_INS_CSEL,
	ARM_INS_CSINC,
	ARM_INS_CSINV,
	ARM_INS_CSNEG,
	ARM_INS_DCPS1,
	ARM_INS_DCPS2,
	ARM_INS_DCPS3,
	ARM_INS_DLS,
	ARM_INS_LE,
	ARM_INS_ORN,
	ARM_INS_PAC,
	ARM_INS_PACBTI,
	ARM_INS_PACG,
	ARM_INS_SG,
	ARM_INS_SUBS,
	ARM_INS_SUBW,
	ARM_INS_TBB,
	ARM_INS_TBH,
	ARM_INS_TT,
	ARM_INS_TTA,
	ARM_INS_TTAT,
	ARM_INS_TTT,
	ARM_INS_WLS,
	ARM_INS_BLXNS,
	ARM_INS_BXNS,
	ARM_INS_CBNZ,
	ARM_INS_CBZ,
	ARM_INS_POP,
	ARM_INS_PUSH,
	ARM_INS___BRKDIV0,

	// clang-format on
	// generated content <ARMGenCSInsnEnum.inc> end

	ARM_INS_ENDING,	// <-- mark the end of the list of instructions

	ARM_INS_ALIAS_BEGIN,
	// generated content <ARMGenCSAliasEnum.inc> begin
	// clang-format off

	ARM_INS_ALIAS_VMOV, // Real instr.: ARM_MVE_VORR
	ARM_INS_ALIAS_NOP, // Real instr.: ARM_HINT
	ARM_INS_ALIAS_YIELD, // Real instr.: ARM_HINT
	ARM_INS_ALIAS_WFE, // Real instr.: ARM_HINT
	ARM_INS_ALIAS_WFI, // Real instr.: ARM_HINT
	ARM_INS_ALIAS_SEV, // Real instr.: ARM_HINT
	ARM_INS_ALIAS_SEVL, // Real instr.: ARM_HINT
	ARM_INS_ALIAS_ESB, // Real instr.: ARM_HINT
	ARM_INS_ALIAS_CSDB, // Real instr.: ARM_HINT
	ARM_INS_ALIAS_CLRBHB, // Real instr.: ARM_HINT
	ARM_INS_ALIAS_PACBTI, // Real instr.: ARM_t2HINT
	ARM_INS_ALIAS_BTI, // Real instr.: ARM_t2HINT
	ARM_INS_ALIAS_PAC, // Real instr.: ARM_t2HINT
	ARM_INS_ALIAS_AUT, // Real instr.: ARM_t2HINT
	ARM_INS_ALIAS_SSBB, // Real instr.: ARM_t2DSB
	ARM_INS_ALIAS_PSSBB, // Real instr.: ARM_t2DSB
	ARM_INS_ALIAS_DFB, // Real instr.: ARM_t2DSB
	ARM_INS_ALIAS_CSETM, // Real instr.: ARM_t2CSINV
	ARM_INS_ALIAS_CSET, // Real instr.: ARM_t2CSINC
	ARM_INS_ALIAS_CINC, // Real instr.: ARM_t2CSINC
	ARM_INS_ALIAS_CINV, // Real instr.: ARM_t2CSINV
	ARM_INS_ALIAS_CNEG, // Real instr.: ARM_t2CSNEG
	ARM_INS_ALIAS_VMLAV, // Real instr.: ARM_MVE_VMLADAVs8
	ARM_INS_ALIAS_VMLAVA, // Real instr.: ARM_MVE_VMLADAVas8
	ARM_INS_ALIAS_VRMLALVH, // Real instr.: ARM_MVE_VRMLALDAVHs32
	ARM_INS_ALIAS_VRMLALVHA, // Real instr.: ARM_MVE_VRMLALDAVHas32
	ARM_INS_ALIAS_VMLALV, // Real instr.: ARM_MVE_VMLALDAVs16
	ARM_INS_ALIAS_VMLALVA, // Real instr.: ARM_MVE_VMLALDAVas16
	ARM_INS_ALIAS_VBIC, // Real instr.: ARM_MVE_VBIC
	ARM_INS_ALIAS_VEOR, // Real instr.: ARM_MVE_VEOR
	ARM_INS_ALIAS_VORN, // Real instr.: ARM_MVE_VORN
	ARM_INS_ALIAS_VORR, // Real instr.: ARM_MVE_VORR
	ARM_INS_ALIAS_VAND, // Real instr.: ARM_MVE_VAND
	ARM_INS_ALIAS_VPSEL, // Real instr.: ARM_MVE_VPSEL
	ARM_INS_ALIAS_ERET, // Real instr.: ARM_t2SUBS_PC_LR

	// clang-format on
	// generated content <ARMGenCSAliasEnum.inc> end

	// Hardcoded in LLVM printer
	ARM_INS_ALIAS_ASR,
	ARM_INS_ALIAS_LSL,
	ARM_INS_ALIAS_LSR,
	ARM_INS_ALIAS_ROR,
	ARM_INS_ALIAS_RRX,
	ARM_INS_ALIAS_UXTW,
	ARM_INS_ALIAS_LDM,
	ARM_INS_ALIAS_POP,
	ARM_INS_ALIAS_PUSH,
	ARM_INS_ALIAS_POPW,
	ARM_INS_ALIAS_PUSHW,
	ARM_INS_ALIAS_VPOP,
	ARM_INS_ALIAS_VPUSH,

	ARM_INS_ALIAS_END,
} arm_insn;

/// Group of ARM instructions
typedef enum arm_insn_group {
	ARM_GRP_INVALID = 0, ///< = CS_GRP_INVALID

	// Generic groups
	// all jump instructions (conditional+direct+indirect jumps)
	ARM_GRP_JUMP,	///< = CS_GRP_JUMP
	ARM_GRP_CALL,	///< = CS_GRP_CALL
	ARM_GRP_RET, ///<  = CS_GRP_RET
	ARM_GRP_INT = 4, ///< = CS_GRP_INT
	ARM_GRP_PRIVILEGE = 6, ///< = CS_GRP_PRIVILEGE
	ARM_GRP_BRANCH_RELATIVE, ///< = CS_GRP_BRANCH_RELATIVE

	// Architecture-specific groups
	// generated content <ARMGenCSFeatureEnum.inc> begin
	// clang-format off

	ARM_FEATURE_HASV4T = 128,
	ARM_FEATURE_HASV5T,
	ARM_FEATURE_HASV5TE,
	ARM_FEATURE_HASV6,
	ARM_FEATURE_HASV6M,
	ARM_FEATURE_HASV8MBASELINE,
	ARM_FEATURE_HASV8MMAINLINE,
	ARM_FEATURE_HASV8_1MMAINLINE,
	ARM_FEATURE_HASMVEINT,
	ARM_FEATURE_HASMVEFLOAT,
	ARM_FEATURE_HASCDE,
	ARM_FEATURE_HASFPREGS,
	ARM_FEATURE_HASFPREGS16,
	ARM_FEATURE_HASNOFPREGS16,
	ARM_FEATURE_HASFPREGS64,
	ARM_FEATURE_HASFPREGSV8_1M,
	ARM_FEATURE_HASV6T2,
	ARM_FEATURE_HASV6K,
	ARM_FEATURE_HASV7,
	ARM_FEATURE_HASV8,
	ARM_FEATURE_PREV8,
	ARM_FEATURE_HASV8_1A,
	ARM_FEATURE_HASV8_2A,
	ARM_FEATURE_HASV8_3A,
	ARM_FEATURE_HASV8_4A,
	ARM_FEATURE_HASV8_5A,
	ARM_FEATURE_HASV8_6A,
	ARM_FEATURE_HASV8_7A,
	ARM_FEATURE_HASVFP2,
	ARM_FEATURE_HASVFP3,
	ARM_FEATURE_HASVFP4,
	ARM_FEATURE_HASDPVFP,
	ARM_FEATURE_HASFPARMV8,
	ARM_FEATURE_HASNEON,
	ARM_FEATURE_HASSHA2,
	ARM_FEATURE_HASAES,
	ARM_FEATURE_HASCRYPTO,
	ARM_FEATURE_HASDOTPROD,
	ARM_FEATURE_HASCRC,
	ARM_FEATURE_HASRAS,
	ARM_FEATURE_HASLOB,
	ARM_FEATURE_HASPACBTI,
	ARM_FEATURE_HASFP16,
	ARM_FEATURE_HASFULLFP16,
	ARM_FEATURE_HASFP16FML,
	ARM_FEATURE_HASBF16,
	ARM_FEATURE_HASMATMULINT8,
	ARM_FEATURE_HASDIVIDEINTHUMB,
	ARM_FEATURE_HASDIVIDEINARM,
	ARM_FEATURE_HASDSP,
	ARM_FEATURE_HASDB,
	ARM_FEATURE_HASDFB,
	ARM_FEATURE_HASV7CLREX,
	ARM_FEATURE_HASACQUIRERELEASE,
	ARM_FEATURE_HASMP,
	ARM_FEATURE_HASVIRTUALIZATION,
	ARM_FEATURE_HASTRUSTZONE,
	ARM_FEATURE_HAS8MSECEXT,
	ARM_FEATURE_ISTHUMB,
	ARM_FEATURE_ISTHUMB2,
	ARM_FEATURE_ISMCLASS,
	ARM_FEATURE_ISNOTMCLASS,
	ARM_FEATURE_ISARM,
	ARM_FEATURE_USENACLTRAP,
	ARM_FEATURE_USENEGATIVEIMMEDIATES,
	ARM_FEATURE_HASSB,
	ARM_FEATURE_HASCLRBHB,

	// clang-format on
	// generated content <ARMGenCSFeatureEnum.inc> end

	ARM_GRP_ENDING,
} arm_insn_group;

#ifdef CAPSTONE_ARM_COMPAT_HEADER
#define arm_cc ARMCC_CondCodes
#define ARM_CC_EQ ARMCC_EQ
#define ARM_CC_NE ARMCC_NE
#define ARM_CC_HS ARMCC_HS
#define ARM_CC_LO ARMCC_LO
#define ARM_CC_MI ARMCC_MI
#define ARM_CC_PL ARMCC_PL
#define ARM_CC_VS ARMCC_VS
#define ARM_CC_VC ARMCC_VC
#define ARM_CC_HI ARMCC_HI
#define ARM_CC_LS ARMCC_LS
#define ARM_CC_GE ARMCC_GE
#define ARM_CC_LT ARMCC_LT
#define ARM_CC_GT ARMCC_GT
#define ARM_CC_LE ARMCC_LE
#define ARM_CC_AL ARMCC_AL
#define ARM_CC_INVALID ARMCC_Invalid
#endif

#ifdef __cplusplus
}
#endif

#endif

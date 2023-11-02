#ifndef CAPSTONE_AARCH64_H
#define CAPSTONE_AARCH64_H

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifdef __cplusplus
extern "C" {
#endif

#include "cs_operand.h"
#include "platform.h"

#include <assert.h>

#ifdef _MSC_VER
#pragma warning(disable : 4201)
#endif

/// Macro for meta programming.
/// Meant for projects using Capstone and need to support multiple
/// versions of it.
/// These macros replace several instances of the old "ARM64" with
/// the new "AArch64" name depending on the CS version.
#if CS_NEXT_VERSION < 6
#define CS_AARCH64(x) ARM64##x
#else
#define CS_AARCH64(x) AArch64##x
#endif

#if CS_NEXT_VERSION < 6
#define CS_AARCH64pre(x) x##ARM64
#else
#define CS_AARCH64pre(x) x##AARCH64
#endif

#if CS_NEXT_VERSION < 6
#define CS_AARCH64CC(x) ARM64_CC##x
#else
#define CS_AARCH64CC(x) AArch64CC##x
#endif

#if CS_NEXT_VERSION < 6
#define CS_AARCH64_VL_(x) ARM64_VAS_##x
#else
#define CS_AARCH64_VL_(x) AArch64Layout_VL_##x
#endif

#if CS_NEXT_VERSION < 6
#define CS_aarch64(x) arm64##x
#else
#define CS_aarch64(x) aarch64##x
#endif

#if CS_NEXT_VERSION < 6
#define CS_aarch64_op() cs_arm64_op
#define CS_aarch64_reg() arm64_reg
#define CS_aarch64_cc() arm64_cc
#define CS_cs_aarch64() cs_arm64
#define CS_aarch64_extender() arm64_extender
#define CS_aarch64_shifter() arm64_shifter
#define CS_aarch64_vas() arm64_vas
#else
#define CS_aarch64_op() cs_aarch64_op
#define CS_aarch64_reg() aarch64_reg
#define CS_aarch64_cc() AArch64CC_CondCode
#define CS_cs_aarch64() cs_aarch64
#define CS_aarch64_extender() aarch64_extender
#define CS_aarch64_shifter() aarch64_shifter
#define CS_aarch64_vas() AArch64Layout_VectorLayout
#endif

/// AArch64 shift type
typedef enum aarch64_shifter {
  AArch64_SFT_INVALID = 0,
  AArch64_SFT_LSL = 1,
  AArch64_SFT_MSL = 2,
  AArch64_SFT_LSR = 3,
  AArch64_SFT_ASR = 4,
  AArch64_SFT_ROR = 5,
} aarch64_shifter;

/// AArch64 extender type
typedef enum aarch64_extender {
  AArch64_EXT_INVALID = 0,
  AArch64_EXT_UXTB = 1,
  AArch64_EXT_UXTH = 2,
  AArch64_EXT_UXTW = 3,
  AArch64_EXT_UXTX = 4,
  AArch64_EXT_SXTB = 5,
  AArch64_EXT_SXTH = 6,
  AArch64_EXT_SXTW = 7,
  AArch64_EXT_SXTX = 8,
} aarch64_extender;

// Moved from AArch64BaseInfo.h and modified
// With extension of Q
typedef enum VectorLayout {
	AArch64Layout_Invalid = 0,
	// Bare layout for the 128-bit vector
	// (only show ".b", ".h", ".s", ".d" without vector number)
	AArch64Layout_VL_B = 8,
	AArch64Layout_VL_H = 16,
	AArch64Layout_VL_S = 32,
	AArch64Layout_VL_D = 64,
	AArch64Layout_VL_Q = 128,

	AArch64Layout_VL_4B = (4 << 8) | AArch64Layout_VL_B,
	AArch64Layout_VL_2H = (2 << 8) | AArch64Layout_VL_H,
	AArch64Layout_VL_1S = (1 << 8) | AArch64Layout_VL_S,

	AArch64Layout_VL_8B = (8 << 8) | AArch64Layout_VL_B,
	AArch64Layout_VL_4H = (4 << 8) | AArch64Layout_VL_H,
	AArch64Layout_VL_2S = (2 << 8) | AArch64Layout_VL_S,
	AArch64Layout_VL_1D = (1 << 8) | AArch64Layout_VL_D,

	AArch64Layout_VL_16B = (16 << 8) | AArch64Layout_VL_B,
	AArch64Layout_VL_8H = (8 << 8) | AArch64Layout_VL_H,
	AArch64Layout_VL_4S = (4 << 8) | AArch64Layout_VL_S,
	AArch64Layout_VL_2D = (2 << 8) | AArch64Layout_VL_D,
	AArch64Layout_VL_1Q = (1 << 8) | AArch64Layout_VL_Q,

	AArch64Layout_VL_64B = (64 << 8) | AArch64Layout_VL_B,
	AArch64Layout_VL_32H = (32 << 8) | AArch64Layout_VL_H,
	AArch64Layout_VL_16S = (16 << 8) | AArch64Layout_VL_S,
	AArch64Layout_VL_8D = (8 << 8) | AArch64Layout_VL_D,

	AArch64Layout_VL_Complete, ///< Indicates that the complete matrix is used.
} AArch64Layout_VectorLayout;

// begin namespace AArch64CC

// Moved from AArch64BaseInfo.h
// The CondCodes constants map directly to the 4-bit encoding of the condition
// field for predicated instructions.
typedef enum CondCode { // Meaning (integer)          Meaning (floating-point)
	AArch64CC_EQ = 0x0, // Equal                      Equal
	AArch64CC_NE = 0x1, // Not equal                  Not equal, or unordered
	AArch64CC_HS = 0x2, // Unsigned higher or same    >, ==, or unordered
	AArch64CC_LO = 0x3, // Unsigned lower             Less than
	AArch64CC_MI = 0x4, // Minus, negative            Less than
	AArch64CC_PL = 0x5, // Plus, positive or zero     >, ==, or unordered
	AArch64CC_VS = 0x6, // Overflow                   Unordered
	AArch64CC_VC = 0x7, // No overflow                Not unordered
	AArch64CC_HI = 0x8, // Unsigned higher            Greater than, or unordered
	AArch64CC_LS = 0x9, // Unsigned lower or same     Less than or equal
	AArch64CC_GE = 0xa, // Greater than or equal      Greater than or equal
	AArch64CC_LT = 0xb, // Less than                  Less than, or unordered
	AArch64CC_GT = 0xc, // Greater than               Greater than
	AArch64CC_LE = 0xd, // Less than or equal         <, ==, or unordered
	AArch64CC_AL = 0xe, // Always (unconditional)     Always (unconditional)
	AArch64CC_NV = 0xf, // Always (unconditional)     Always (unconditional)
	// Note the NV exists purely to disassemble 0b1111. Execution is "always".
	AArch64CC_Invalid,

	// Common aliases used for SVE.
	AArch64CC_ANY_ACTIVE = AArch64CC_NE,	 // (!Z)
	AArch64CC_FIRST_ACTIVE = AArch64CC_MI, // ( N)
	AArch64CC_LAST_ACTIVE = AArch64CC_LO,	 // (!C)
	AArch64CC_NONE_ACTIVE = AArch64CC_EQ	 // ( Z)
} AArch64CC_CondCode;

inline static const char *AArch64CC_getCondCodeName(AArch64CC_CondCode Code)
{
	switch (Code) {
	default:
		assert(0 && "Unknown condition code");
	case AArch64CC_EQ:
		return "eq";
	case AArch64CC_NE:
		return "ne";
	case AArch64CC_HS:
		return "hs";
	case AArch64CC_LO:
		return "lo";
	case AArch64CC_MI:
		return "mi";
	case AArch64CC_PL:
		return "pl";
	case AArch64CC_VS:
		return "vs";
	case AArch64CC_VC:
		return "vc";
	case AArch64CC_HI:
		return "hi";
	case AArch64CC_LS:
		return "ls";
	case AArch64CC_GE:
		return "ge";
	case AArch64CC_LT:
		return "lt";
	case AArch64CC_GT:
		return "gt";
	case AArch64CC_LE:
		return "le";
	case AArch64CC_AL:
		return "al";
	case AArch64CC_NV:
		return "nv";
	}
}

inline static AArch64CC_CondCode AArch64CC_getInvertedCondCode(AArch64CC_CondCode Code)
{
	// To reverse a condition it's necessary to only invert the low bit:

	return (AArch64CC_CondCode)((unsigned)(Code) ^ 0x1);
}

/// Given a condition code, return NZCV flags that would satisfy that condition.
/// The flag bits are in the format expected by the ccmp instructions.
/// Note that many different flag settings can satisfy a given condition code,
/// this function just returns one of them.
inline static unsigned AArch64CC_getNZCVToSatisfyCondCode(AArch64CC_CondCode Code)
{
	// NZCV flags encoded as expected by ccmp instructions, ARMv8 ISA 5.5.7.
	enum { N = 8, Z = 4, C = 2, V = 1 };
	switch (Code) {
	default:
		assert(0 && "Unknown condition code");
	case AArch64CC_EQ:
		return Z; // Z == 1
	case AArch64CC_NE:
		return 0; // Z == 0
	case AArch64CC_HS:
		return C; // C == 1
	case AArch64CC_LO:
		return 0; // C == 0
	case AArch64CC_MI:
		return N; // N == 1
	case AArch64CC_PL:
		return 0; // N == 0
	case AArch64CC_VS:
		return V; // V == 1
	case AArch64CC_VC:
		return 0; // V == 0
	case AArch64CC_HI:
		return C; // C == 1 && Z == 0
	case AArch64CC_LS:
		return 0; // C == 0 || Z == 1
	case AArch64CC_GE:
		return 0; // N == V
	case AArch64CC_LT:
		return N; // N != V
	case AArch64CC_GT:
		return 0; // Z == 0 && N == V
	case AArch64CC_LE:
		return Z; // Z == 1 || N != V
	}
}

/// Return true if Code is a reflexive relationship:
/// forall x. (CSET Code (CMP x x)) == 1
inline static bool AArch64CC_isReflexive(AArch64CC_CondCode Code)
{
	switch (Code) {
	case AArch64CC_EQ:
	case AArch64CC_HS:
	case AArch64CC_PL:
	case AArch64CC_LS:
	case AArch64CC_GE:
	case AArch64CC_LE:
	case AArch64CC_AL:
	case AArch64CC_NV:
		return true;
	default:
		return false;
	}
}

/// Return true if Code is an irreflexive relationship:
/// forall x. (CSET Code (CMP x x)) == 0
inline static bool AArch64CC_isIrreflexive(AArch64CC_CondCode Code)
{
	switch (Code) {
	case AArch64CC_NE:
	case AArch64CC_LO:
	case AArch64CC_MI:
	case AArch64CC_HI:
	case AArch64CC_LT:
	case AArch64CC_GT:
		return true;
	default:
		return false;
	}
}

// end namespace AArch64CC

typedef enum {
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_TLBI> begin
	// clang-format off

	AArch64_TLBI_ALLE1 = 0x243c,
	AArch64_TLBI_ALLE1IS = 0x241c,
	AArch64_TLBI_ALLE1ISNXS = 0x249c,
	AArch64_TLBI_ALLE1NXS = 0x24bc,
	AArch64_TLBI_ALLE1OS = 0x240c,
	AArch64_TLBI_ALLE1OSNXS = 0x248c,
	AArch64_TLBI_ALLE2 = 0x2438,
	AArch64_TLBI_ALLE2IS = 0x2418,
	AArch64_TLBI_ALLE2ISNXS = 0x2498,
	AArch64_TLBI_ALLE2NXS = 0x24b8,
	AArch64_TLBI_ALLE2OS = 0x2408,
	AArch64_TLBI_ALLE2OSNXS = 0x2488,
	AArch64_TLBI_ALLE3 = 0x3438,
	AArch64_TLBI_ALLE3IS = 0x3418,
	AArch64_TLBI_ALLE3ISNXS = 0x3498,
	AArch64_TLBI_ALLE3NXS = 0x34b8,
	AArch64_TLBI_ALLE3OS = 0x3408,
	AArch64_TLBI_ALLE3OSNXS = 0x3488,
	AArch64_TLBI_ASIDE1 = 0x43a,
	AArch64_TLBI_ASIDE1IS = 0x41a,
	AArch64_TLBI_ASIDE1ISNXS = 0x49a,
	AArch64_TLBI_ASIDE1NXS = 0x4ba,
	AArch64_TLBI_ASIDE1OS = 0x40a,
	AArch64_TLBI_ASIDE1OSNXS = 0x48a,
	AArch64_TLBI_IPAS2E1 = 0x2421,
	AArch64_TLBI_IPAS2E1IS = 0x2401,
	AArch64_TLBI_IPAS2E1ISNXS = 0x2481,
	AArch64_TLBI_IPAS2E1NXS = 0x24a1,
	AArch64_TLBI_IPAS2E1OS = 0x2420,
	AArch64_TLBI_IPAS2E1OSNXS = 0x24a0,
	AArch64_TLBI_IPAS2LE1 = 0x2425,
	AArch64_TLBI_IPAS2LE1IS = 0x2405,
	AArch64_TLBI_IPAS2LE1ISNXS = 0x2485,
	AArch64_TLBI_IPAS2LE1NXS = 0x24a5,
	AArch64_TLBI_IPAS2LE1OS = 0x2424,
	AArch64_TLBI_IPAS2LE1OSNXS = 0x24a4,
	AArch64_TLBI_PAALL = 0x343c,
	AArch64_TLBI_PAALLNXS = 0x34bc,
	AArch64_TLBI_PAALLOS = 0x340c,
	AArch64_TLBI_PAALLOSNXS = 0x348c,
	AArch64_TLBI_RIPAS2E1 = 0x2422,
	AArch64_TLBI_RIPAS2E1IS = 0x2402,
	AArch64_TLBI_RIPAS2E1ISNXS = 0x2482,
	AArch64_TLBI_RIPAS2E1NXS = 0x24a2,
	AArch64_TLBI_RIPAS2E1OS = 0x2423,
	AArch64_TLBI_RIPAS2E1OSNXS = 0x24a3,
	AArch64_TLBI_RIPAS2LE1 = 0x2426,
	AArch64_TLBI_RIPAS2LE1IS = 0x2406,
	AArch64_TLBI_RIPAS2LE1ISNXS = 0x2486,
	AArch64_TLBI_RIPAS2LE1NXS = 0x24a6,
	AArch64_TLBI_RIPAS2LE1OS = 0x2427,
	AArch64_TLBI_RIPAS2LE1OSNXS = 0x24a7,
	AArch64_TLBI_RPALOS = 0x3427,
	AArch64_TLBI_RPALOSNXS = 0x34a7,
	AArch64_TLBI_RPAOS = 0x3423,
	AArch64_TLBI_RPAOSNXS = 0x34a3,
	AArch64_TLBI_RVAAE1 = 0x433,
	AArch64_TLBI_RVAAE1IS = 0x413,
	AArch64_TLBI_RVAAE1ISNXS = 0x493,
	AArch64_TLBI_RVAAE1NXS = 0x4b3,
	AArch64_TLBI_RVAAE1OS = 0x42b,
	AArch64_TLBI_RVAAE1OSNXS = 0x4ab,
	AArch64_TLBI_RVAALE1 = 0x437,
	AArch64_TLBI_RVAALE1IS = 0x417,
	AArch64_TLBI_RVAALE1ISNXS = 0x497,
	AArch64_TLBI_RVAALE1NXS = 0x4b7,
	AArch64_TLBI_RVAALE1OS = 0x42f,
	AArch64_TLBI_RVAALE1OSNXS = 0x4af,
	AArch64_TLBI_RVAE1 = 0x431,
	AArch64_TLBI_RVAE1IS = 0x411,
	AArch64_TLBI_RVAE1ISNXS = 0x491,
	AArch64_TLBI_RVAE1NXS = 0x4b1,
	AArch64_TLBI_RVAE1OS = 0x429,
	AArch64_TLBI_RVAE1OSNXS = 0x4a9,
	AArch64_TLBI_RVAE2 = 0x2431,
	AArch64_TLBI_RVAE2IS = 0x2411,
	AArch64_TLBI_RVAE2ISNXS = 0x2491,
	AArch64_TLBI_RVAE2NXS = 0x24b1,
	AArch64_TLBI_RVAE2OS = 0x2429,
	AArch64_TLBI_RVAE2OSNXS = 0x24a9,
	AArch64_TLBI_RVAE3 = 0x3431,
	AArch64_TLBI_RVAE3IS = 0x3411,
	AArch64_TLBI_RVAE3ISNXS = 0x3491,
	AArch64_TLBI_RVAE3NXS = 0x34b1,
	AArch64_TLBI_RVAE3OS = 0x3429,
	AArch64_TLBI_RVAE3OSNXS = 0x34a9,
	AArch64_TLBI_RVALE1 = 0x435,
	AArch64_TLBI_RVALE1IS = 0x415,
	AArch64_TLBI_RVALE1ISNXS = 0x495,
	AArch64_TLBI_RVALE1NXS = 0x4b5,
	AArch64_TLBI_RVALE1OS = 0x42d,
	AArch64_TLBI_RVALE1OSNXS = 0x4ad,
	AArch64_TLBI_RVALE2 = 0x2435,
	AArch64_TLBI_RVALE2IS = 0x2415,
	AArch64_TLBI_RVALE2ISNXS = 0x2495,
	AArch64_TLBI_RVALE2NXS = 0x24b5,
	AArch64_TLBI_RVALE2OS = 0x242d,
	AArch64_TLBI_RVALE2OSNXS = 0x24ad,
	AArch64_TLBI_RVALE3 = 0x3435,
	AArch64_TLBI_RVALE3IS = 0x3415,
	AArch64_TLBI_RVALE3ISNXS = 0x3495,
	AArch64_TLBI_RVALE3NXS = 0x34b5,
	AArch64_TLBI_RVALE3OS = 0x342d,
	AArch64_TLBI_RVALE3OSNXS = 0x34ad,
	AArch64_TLBI_VAAE1 = 0x43b,
	AArch64_TLBI_VAAE1IS = 0x41b,
	AArch64_TLBI_VAAE1ISNXS = 0x49b,
	AArch64_TLBI_VAAE1NXS = 0x4bb,
	AArch64_TLBI_VAAE1OS = 0x40b,
	AArch64_TLBI_VAAE1OSNXS = 0x48b,
	AArch64_TLBI_VAALE1 = 0x43f,
	AArch64_TLBI_VAALE1IS = 0x41f,
	AArch64_TLBI_VAALE1ISNXS = 0x49f,
	AArch64_TLBI_VAALE1NXS = 0x4bf,
	AArch64_TLBI_VAALE1OS = 0x40f,
	AArch64_TLBI_VAALE1OSNXS = 0x48f,
	AArch64_TLBI_VAE1 = 0x439,
	AArch64_TLBI_VAE1IS = 0x419,
	AArch64_TLBI_VAE1ISNXS = 0x499,
	AArch64_TLBI_VAE1NXS = 0x4b9,
	AArch64_TLBI_VAE1OS = 0x409,
	AArch64_TLBI_VAE1OSNXS = 0x489,
	AArch64_TLBI_VAE2 = 0x2439,
	AArch64_TLBI_VAE2IS = 0x2419,
	AArch64_TLBI_VAE2ISNXS = 0x2499,
	AArch64_TLBI_VAE2NXS = 0x24b9,
	AArch64_TLBI_VAE2OS = 0x2409,
	AArch64_TLBI_VAE2OSNXS = 0x2489,
	AArch64_TLBI_VAE3 = 0x3439,
	AArch64_TLBI_VAE3IS = 0x3419,
	AArch64_TLBI_VAE3ISNXS = 0x3499,
	AArch64_TLBI_VAE3NXS = 0x34b9,
	AArch64_TLBI_VAE3OS = 0x3409,
	AArch64_TLBI_VAE3OSNXS = 0x3489,
	AArch64_TLBI_VALE1 = 0x43d,
	AArch64_TLBI_VALE1IS = 0x41d,
	AArch64_TLBI_VALE1ISNXS = 0x49d,
	AArch64_TLBI_VALE1NXS = 0x4bd,
	AArch64_TLBI_VALE1OS = 0x40d,
	AArch64_TLBI_VALE1OSNXS = 0x48d,
	AArch64_TLBI_VALE2 = 0x243d,
	AArch64_TLBI_VALE2IS = 0x241d,
	AArch64_TLBI_VALE2ISNXS = 0x249d,
	AArch64_TLBI_VALE2NXS = 0x24bd,
	AArch64_TLBI_VALE2OS = 0x240d,
	AArch64_TLBI_VALE2OSNXS = 0x248d,
	AArch64_TLBI_VALE3 = 0x343d,
	AArch64_TLBI_VALE3IS = 0x341d,
	AArch64_TLBI_VALE3ISNXS = 0x349d,
	AArch64_TLBI_VALE3NXS = 0x34bd,
	AArch64_TLBI_VALE3OS = 0x340d,
	AArch64_TLBI_VALE3OSNXS = 0x348d,
	AArch64_TLBI_VMALLE1 = 0x438,
	AArch64_TLBI_VMALLE1IS = 0x418,
	AArch64_TLBI_VMALLE1ISNXS = 0x498,
	AArch64_TLBI_VMALLE1NXS = 0x4b8,
	AArch64_TLBI_VMALLE1OS = 0x408,
	AArch64_TLBI_VMALLE1OSNXS = 0x488,
	AArch64_TLBI_VMALLS12E1 = 0x243e,
	AArch64_TLBI_VMALLS12E1IS = 0x241e,
	AArch64_TLBI_VMALLS12E1ISNXS = 0x249e,
	AArch64_TLBI_VMALLS12E1NXS = 0x24be,
	AArch64_TLBI_VMALLS12E1OS = 0x240e,
	AArch64_TLBI_VMALLS12E1OSNXS = 0x248e,

	// clang-format on
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_TLBI> end
	AArch64_TLBI_ENDING,
} aarch64_tlbi;

typedef enum {
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_AT> begin
	// clang-format off

	AArch64_AT_S12E0R = 0x23c6,
	AArch64_AT_S12E0W = 0x23c7,
	AArch64_AT_S12E1R = 0x23c4,
	AArch64_AT_S12E1W = 0x23c5,
	AArch64_AT_S1E0R = 0x3c2,
	AArch64_AT_S1E0W = 0x3c3,
	AArch64_AT_S1E1R = 0x3c0,
	AArch64_AT_S1E1RP = 0x3c8,
	AArch64_AT_S1E1W = 0x3c1,
	AArch64_AT_S1E1WP = 0x3c9,
	AArch64_AT_S1E2R = 0x23c0,
	AArch64_AT_S1E2W = 0x23c1,
	AArch64_AT_S1E3R = 0x33c0,
	AArch64_AT_S1E3W = 0x33c1,

	// clang-format on
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_AT> end
	AArch64_AT_ENDING,
} aarch64_at;

typedef enum {
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_BTI> begin
	// clang-format off

	AArch64_BTI_C = 0x2,
	AArch64_BTI_J = 0x4,
	AArch64_BTI_JC = 0x6,

	// clang-format on
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_BTI> end
	AArch64_BTI_ENDING,
} aarch64_bti;

typedef enum {
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_DB> begin
	// clang-format off

	AArch64_DB_ISH = 0xb,
	AArch64_DB_ISHLD = 0x9,
	AArch64_DB_ISHST = 0xa,
	AArch64_DB_LD = 0xd,
	AArch64_DB_NSH = 0x7,
	AArch64_DB_NSHLD = 0x5,
	AArch64_DB_NSHST = 0x6,
	AArch64_DB_OSH = 0x3,
	AArch64_DB_OSHLD = 0x1,
	AArch64_DB_OSHST = 0x2,
	AArch64_DB_ST = 0xe,
	AArch64_DB_SY = 0xf,

	// clang-format on
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_DB> end
	AArch64_DB_ENDING,
} aarch64_db;

typedef enum {
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_DBnXS> begin
	// clang-format off

	AArch64_DBNXS_ISHNXS = 0xb,
	AArch64_DBNXS_NSHNXS = 0x7,
	AArch64_DBNXS_OSHNXS = 0x3,
	AArch64_DBNXS_SYNXS = 0xf,

	// clang-format on
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_DBnXS> end
	AArch64_DBNXS_ENDING,
} aarch64_dbnxs;

typedef enum {
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_DC> begin
	// clang-format off

	AArch64_DC_CGDSW = 0x3d6,
	AArch64_DC_CGDVAC = 0x1bd5,
	AArch64_DC_CGDVADP = 0x1bed,
	AArch64_DC_CGDVAP = 0x1be5,
	AArch64_DC_CGSW = 0x3d4,
	AArch64_DC_CGVAC = 0x1bd3,
	AArch64_DC_CGVADP = 0x1beb,
	AArch64_DC_CGVAP = 0x1be3,
	AArch64_DC_CIGDPAE = 0x23f7,
	AArch64_DC_CIGDSW = 0x3f6,
	AArch64_DC_CIGDVAC = 0x1bf5,
	AArch64_DC_CIGSW = 0x3f4,
	AArch64_DC_CIGVAC = 0x1bf3,
	AArch64_DC_CIPAE = 0x23f0,
	AArch64_DC_CISW = 0x3f2,
	AArch64_DC_CIVAC = 0x1bf1,
	AArch64_DC_CSW = 0x3d2,
	AArch64_DC_CVAC = 0x1bd1,
	AArch64_DC_CVADP = 0x1be9,
	AArch64_DC_CVAP = 0x1be1,
	AArch64_DC_CVAU = 0x1bd9,
	AArch64_DC_GVA = 0x1ba3,
	AArch64_DC_GZVA = 0x1ba4,
	AArch64_DC_IGDSW = 0x3b6,
	AArch64_DC_IGDVAC = 0x3b5,
	AArch64_DC_IGSW = 0x3b4,
	AArch64_DC_IGVAC = 0x3b3,
	AArch64_DC_ISW = 0x3b2,
	AArch64_DC_IVAC = 0x3b1,
	AArch64_DC_ZVA = 0x1ba1,

	// clang-format on
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_DC> end
	AArch64_DC_ENDING,
} aarch64_dc;

typedef enum {
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_ExactFPImm> begin
	// clang-format off

	AArch64_EXACTFPIMM_HALF = 0x1,
	AArch64_EXACTFPIMM_ONE = 0x2,
	AArch64_EXACTFPIMM_TWO = 0x3,
	AArch64_EXACTFPIMM_ZERO = 0x0,

	// clang-format on
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_ExactFPImm> end
	AArch64_EXACTFPIMM_ENDING,
} aarch64_exactfpimm;

typedef enum {
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_IC> begin
	// clang-format off

	AArch64_IC_IALLU = 0x3a8,
	AArch64_IC_IALLUIS = 0x388,
	AArch64_IC_IVAU = 0x1ba9,

	// clang-format on
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_IC> end
	AArch64_IC_ENDING,
} aarch64_ic;

typedef enum {
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_ISB> begin
	// clang-format off

	AArch64_ISB_SY = 0xf,

	// clang-format on
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_ISB> end
	AArch64_ISB_ENDING,
} aarch64_isb;

typedef enum {
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_PRFM> begin
	// clang-format off

	AArch64_PRFM_PLDL1KEEP = 0x0,
	AArch64_PRFM_PLDL1STRM = 0x1,
	AArch64_PRFM_PLDL2KEEP = 0x2,
	AArch64_PRFM_PLDL2STRM = 0x3,
	AArch64_PRFM_PLDL3KEEP = 0x4,
	AArch64_PRFM_PLDL3STRM = 0x5,
	AArch64_PRFM_PLDSLCKEEP = 0x6,
	AArch64_PRFM_PLDSLCSTRM = 0x7,
	AArch64_PRFM_PLIL1KEEP = 0x8,
	AArch64_PRFM_PLIL1STRM = 0x9,
	AArch64_PRFM_PLIL2KEEP = 0xa,
	AArch64_PRFM_PLIL2STRM = 0xb,
	AArch64_PRFM_PLIL3KEEP = 0xc,
	AArch64_PRFM_PLIL3STRM = 0xd,
	AArch64_PRFM_PLISLCKEEP = 0xe,
	AArch64_PRFM_PLISLCSTRM = 0xf,
	AArch64_PRFM_PSTL1KEEP = 0x10,
	AArch64_PRFM_PSTL1STRM = 0x11,
	AArch64_PRFM_PSTL2KEEP = 0x12,
	AArch64_PRFM_PSTL2STRM = 0x13,
	AArch64_PRFM_PSTL3KEEP = 0x14,
	AArch64_PRFM_PSTL3STRM = 0x15,
	AArch64_PRFM_PSTSLCKEEP = 0x16,
	AArch64_PRFM_PSTSLCSTRM = 0x17,

	// clang-format on
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_PRFM> end
	AArch64_PRFM_ENDING,
} aarch64_prfm;

typedef enum {
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_PSB> begin
	// clang-format off

	AArch64_PSB_CSYNC = 0x11,

	// clang-format on
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_PSB> end
	AArch64_PSB_ENDING,
} aarch64_psb;

typedef enum {
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_PStateImm0_1> begin
	// clang-format off

	AArch64_PSTATEIMM0_1_ALLINT = 0x8,
	AArch64_PSTATEIMM0_1_PM = 0x48,

	// clang-format on
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_PStateImm0_1> end
	AArch64_PSTATEIMM0_1_ENDING,
} aarch64_pstateimm0_1;

typedef enum {
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_PStateImm0_15> begin
	// clang-format off

	AArch64_PSTATEIMM0_15_DAIFCLR = 0x1f,
	AArch64_PSTATEIMM0_15_DAIFSET = 0x1e,
	AArch64_PSTATEIMM0_15_DIT = 0x1a,
	AArch64_PSTATEIMM0_15_PAN = 0x4,
	AArch64_PSTATEIMM0_15_SPSEL = 0x5,
	AArch64_PSTATEIMM0_15_SSBS = 0x19,
	AArch64_PSTATEIMM0_15_TCO = 0x1c,
	AArch64_PSTATEIMM0_15_UAO = 0x3,

	// clang-format on
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_PStateImm0_15> end
	AArch64_PSTATEIMM0_15_ENDING,
} aarch64_pstateimm0_15;

typedef enum {
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_RPRFM> begin
	// clang-format off

	AArch64_RPRFM_PLDKEEP = 0x0,
	AArch64_RPRFM_PLDSTRM = 0x4,
	AArch64_RPRFM_PSTKEEP = 0x1,
	AArch64_RPRFM_PSTSTRM = 0x5,

	// clang-format on
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_RPRFM> end
	AArch64_RPRFM_ENDING,
} aarch64_rprfm;

typedef enum {
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_SVCR> begin
	// clang-format off

	AArch64_SVCR_SVCRSM = 0x1,
	AArch64_SVCR_SVCRSMZA = 0x3,
	AArch64_SVCR_SVCRZA = 0x2,

	// clang-format on
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_SVCR> end
	AArch64_SVCR_ENDING,
} aarch64_svcr;

typedef enum {
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_SVEPREDPAT> begin
	// clang-format off

	AArch64_SVEPREDPAT_ALL = 0x1f,
	AArch64_SVEPREDPAT_MUL3 = 0x1e,
	AArch64_SVEPREDPAT_MUL4 = 0x1d,
	AArch64_SVEPREDPAT_POW2 = 0x0,
	AArch64_SVEPREDPAT_VL1 = 0x1,
	AArch64_SVEPREDPAT_VL128 = 0xc,
	AArch64_SVEPREDPAT_VL16 = 0x9,
	AArch64_SVEPREDPAT_VL2 = 0x2,
	AArch64_SVEPREDPAT_VL256 = 0xd,
	AArch64_SVEPREDPAT_VL3 = 0x3,
	AArch64_SVEPREDPAT_VL32 = 0xa,
	AArch64_SVEPREDPAT_VL4 = 0x4,
	AArch64_SVEPREDPAT_VL5 = 0x5,
	AArch64_SVEPREDPAT_VL6 = 0x6,
	AArch64_SVEPREDPAT_VL64 = 0xb,
	AArch64_SVEPREDPAT_VL7 = 0x7,
	AArch64_SVEPREDPAT_VL8 = 0x8,

	// clang-format on
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_SVEPREDPAT> end
	AArch64_SVEPREDPAT_ENDING,
} aarch64_svepredpat;

typedef enum {
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_SVEPRFM> begin
	// clang-format off

	AArch64_SVEPRFM_PLDL1KEEP = 0x0,
	AArch64_SVEPRFM_PLDL1STRM = 0x1,
	AArch64_SVEPRFM_PLDL2KEEP = 0x2,
	AArch64_SVEPRFM_PLDL2STRM = 0x3,
	AArch64_SVEPRFM_PLDL3KEEP = 0x4,
	AArch64_SVEPRFM_PLDL3STRM = 0x5,
	AArch64_SVEPRFM_PSTL1KEEP = 0x8,
	AArch64_SVEPRFM_PSTL1STRM = 0x9,
	AArch64_SVEPRFM_PSTL2KEEP = 0xa,
	AArch64_SVEPRFM_PSTL2STRM = 0xb,
	AArch64_SVEPRFM_PSTL3KEEP = 0xc,
	AArch64_SVEPRFM_PSTL3STRM = 0xd,

	// clang-format on
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_SVEPRFM> end
	AArch64_SVEPRFM_ENDING,
} aarch64_sveprfm;

typedef enum {
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_SVEVECLENSPECIFIER> begin
	// clang-format off

	AArch64_SVEVECLENSPECIFIER_VLX2 = 0x0,
	AArch64_SVEVECLENSPECIFIER_VLX4 = 0x1,

	// clang-format on
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_SVEVECLENSPECIFIER> end
	AArch64_SVEVECLENSPECIFIER_ENDING,
} aarch64_sveveclenspecifier;

typedef enum {
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_SysReg> begin
	// clang-format off

	AArch64_SYSREG_ACCDATA_EL1 = 0xc685,
	AArch64_SYSREG_ACTLR_EL1 = 0xc081,
	AArch64_SYSREG_ACTLR_EL2 = 0xe081,
	AArch64_SYSREG_ACTLR_EL3 = 0xf081,
	AArch64_SYSREG_AFSR0_EL1 = 0xc288,
	AArch64_SYSREG_AFSR0_EL12 = 0xea88,
	AArch64_SYSREG_AFSR0_EL2 = 0xe288,
	AArch64_SYSREG_AFSR0_EL3 = 0xf288,
	AArch64_SYSREG_AFSR1_EL1 = 0xc289,
	AArch64_SYSREG_AFSR1_EL12 = 0xea89,
	AArch64_SYSREG_AFSR1_EL2 = 0xe289,
	AArch64_SYSREG_AFSR1_EL3 = 0xf289,
	AArch64_SYSREG_AIDR_EL1 = 0xc807,
	AArch64_SYSREG_ALLINT = 0xc218,
	AArch64_SYSREG_AMAIR2_EL1 = 0xc519,
	AArch64_SYSREG_AMAIR2_EL12 = 0xed19,
	AArch64_SYSREG_AMAIR2_EL2 = 0xe519,
	AArch64_SYSREG_AMAIR2_EL3 = 0xf519,
	AArch64_SYSREG_AMAIR_EL1 = 0xc518,
	AArch64_SYSREG_AMAIR_EL12 = 0xed18,
	AArch64_SYSREG_AMAIR_EL2 = 0xe518,
	AArch64_SYSREG_AMAIR_EL3 = 0xf518,
	AArch64_SYSREG_AMCFGR_EL0 = 0xde91,
	AArch64_SYSREG_AMCG1IDR_EL0 = 0xde96,
	AArch64_SYSREG_AMCGCR_EL0 = 0xde92,
	AArch64_SYSREG_AMCNTENCLR0_EL0 = 0xde94,
	AArch64_SYSREG_AMCNTENCLR1_EL0 = 0xde98,
	AArch64_SYSREG_AMCNTENSET0_EL0 = 0xde95,
	AArch64_SYSREG_AMCNTENSET1_EL0 = 0xde99,
	AArch64_SYSREG_AMCR_EL0 = 0xde90,
	AArch64_SYSREG_AMEVCNTR00_EL0 = 0xdea0,
	AArch64_SYSREG_AMEVCNTR01_EL0 = 0xdea1,
	AArch64_SYSREG_AMEVCNTR02_EL0 = 0xdea2,
	AArch64_SYSREG_AMEVCNTR03_EL0 = 0xdea3,
	AArch64_SYSREG_AMEVCNTR10_EL0 = 0xdee0,
	AArch64_SYSREG_AMEVCNTR110_EL0 = 0xdeea,
	AArch64_SYSREG_AMEVCNTR111_EL0 = 0xdeeb,
	AArch64_SYSREG_AMEVCNTR112_EL0 = 0xdeec,
	AArch64_SYSREG_AMEVCNTR113_EL0 = 0xdeed,
	AArch64_SYSREG_AMEVCNTR114_EL0 = 0xdeee,
	AArch64_SYSREG_AMEVCNTR115_EL0 = 0xdeef,
	AArch64_SYSREG_AMEVCNTR11_EL0 = 0xdee1,
	AArch64_SYSREG_AMEVCNTR12_EL0 = 0xdee2,
	AArch64_SYSREG_AMEVCNTR13_EL0 = 0xdee3,
	AArch64_SYSREG_AMEVCNTR14_EL0 = 0xdee4,
	AArch64_SYSREG_AMEVCNTR15_EL0 = 0xdee5,
	AArch64_SYSREG_AMEVCNTR16_EL0 = 0xdee6,
	AArch64_SYSREG_AMEVCNTR17_EL0 = 0xdee7,
	AArch64_SYSREG_AMEVCNTR18_EL0 = 0xdee8,
	AArch64_SYSREG_AMEVCNTR19_EL0 = 0xdee9,
	AArch64_SYSREG_AMEVCNTVOFF00_EL2 = 0xe6c0,
	AArch64_SYSREG_AMEVCNTVOFF010_EL2 = 0xe6ca,
	AArch64_SYSREG_AMEVCNTVOFF011_EL2 = 0xe6cb,
	AArch64_SYSREG_AMEVCNTVOFF012_EL2 = 0xe6cc,
	AArch64_SYSREG_AMEVCNTVOFF013_EL2 = 0xe6cd,
	AArch64_SYSREG_AMEVCNTVOFF014_EL2 = 0xe6ce,
	AArch64_SYSREG_AMEVCNTVOFF015_EL2 = 0xe6cf,
	AArch64_SYSREG_AMEVCNTVOFF01_EL2 = 0xe6c1,
	AArch64_SYSREG_AMEVCNTVOFF02_EL2 = 0xe6c2,
	AArch64_SYSREG_AMEVCNTVOFF03_EL2 = 0xe6c3,
	AArch64_SYSREG_AMEVCNTVOFF04_EL2 = 0xe6c4,
	AArch64_SYSREG_AMEVCNTVOFF05_EL2 = 0xe6c5,
	AArch64_SYSREG_AMEVCNTVOFF06_EL2 = 0xe6c6,
	AArch64_SYSREG_AMEVCNTVOFF07_EL2 = 0xe6c7,
	AArch64_SYSREG_AMEVCNTVOFF08_EL2 = 0xe6c8,
	AArch64_SYSREG_AMEVCNTVOFF09_EL2 = 0xe6c9,
	AArch64_SYSREG_AMEVCNTVOFF10_EL2 = 0xe6d0,
	AArch64_SYSREG_AMEVCNTVOFF110_EL2 = 0xe6da,
	AArch64_SYSREG_AMEVCNTVOFF111_EL2 = 0xe6db,
	AArch64_SYSREG_AMEVCNTVOFF112_EL2 = 0xe6dc,
	AArch64_SYSREG_AMEVCNTVOFF113_EL2 = 0xe6dd,
	AArch64_SYSREG_AMEVCNTVOFF114_EL2 = 0xe6de,
	AArch64_SYSREG_AMEVCNTVOFF115_EL2 = 0xe6df,
	AArch64_SYSREG_AMEVCNTVOFF11_EL2 = 0xe6d1,
	AArch64_SYSREG_AMEVCNTVOFF12_EL2 = 0xe6d2,
	AArch64_SYSREG_AMEVCNTVOFF13_EL2 = 0xe6d3,
	AArch64_SYSREG_AMEVCNTVOFF14_EL2 = 0xe6d4,
	AArch64_SYSREG_AMEVCNTVOFF15_EL2 = 0xe6d5,
	AArch64_SYSREG_AMEVCNTVOFF16_EL2 = 0xe6d6,
	AArch64_SYSREG_AMEVCNTVOFF17_EL2 = 0xe6d7,
	AArch64_SYSREG_AMEVCNTVOFF18_EL2 = 0xe6d8,
	AArch64_SYSREG_AMEVCNTVOFF19_EL2 = 0xe6d9,
	AArch64_SYSREG_AMEVTYPER00_EL0 = 0xdeb0,
	AArch64_SYSREG_AMEVTYPER01_EL0 = 0xdeb1,
	AArch64_SYSREG_AMEVTYPER02_EL0 = 0xdeb2,
	AArch64_SYSREG_AMEVTYPER03_EL0 = 0xdeb3,
	AArch64_SYSREG_AMEVTYPER10_EL0 = 0xdef0,
	AArch64_SYSREG_AMEVTYPER110_EL0 = 0xdefa,
	AArch64_SYSREG_AMEVTYPER111_EL0 = 0xdefb,
	AArch64_SYSREG_AMEVTYPER112_EL0 = 0xdefc,
	AArch64_SYSREG_AMEVTYPER113_EL0 = 0xdefd,
	AArch64_SYSREG_AMEVTYPER114_EL0 = 0xdefe,
	AArch64_SYSREG_AMEVTYPER115_EL0 = 0xdeff,
	AArch64_SYSREG_AMEVTYPER11_EL0 = 0xdef1,
	AArch64_SYSREG_AMEVTYPER12_EL0 = 0xdef2,
	AArch64_SYSREG_AMEVTYPER13_EL0 = 0xdef3,
	AArch64_SYSREG_AMEVTYPER14_EL0 = 0xdef4,
	AArch64_SYSREG_AMEVTYPER15_EL0 = 0xdef5,
	AArch64_SYSREG_AMEVTYPER16_EL0 = 0xdef6,
	AArch64_SYSREG_AMEVTYPER17_EL0 = 0xdef7,
	AArch64_SYSREG_AMEVTYPER18_EL0 = 0xdef8,
	AArch64_SYSREG_AMEVTYPER19_EL0 = 0xdef9,
	AArch64_SYSREG_AMUSERENR_EL0 = 0xde93,
	AArch64_SYSREG_APDAKEYHI_EL1 = 0xc111,
	AArch64_SYSREG_APDAKEYLO_EL1 = 0xc110,
	AArch64_SYSREG_APDBKEYHI_EL1 = 0xc113,
	AArch64_SYSREG_APDBKEYLO_EL1 = 0xc112,
	AArch64_SYSREG_APGAKEYHI_EL1 = 0xc119,
	AArch64_SYSREG_APGAKEYLO_EL1 = 0xc118,
	AArch64_SYSREG_APIAKEYHI_EL1 = 0xc109,
	AArch64_SYSREG_APIAKEYLO_EL1 = 0xc108,
	AArch64_SYSREG_APIBKEYHI_EL1 = 0xc10b,
	AArch64_SYSREG_APIBKEYLO_EL1 = 0xc10a,
	AArch64_SYSREG_BRBCR_EL1 = 0x8c80,
	AArch64_SYSREG_BRBCR_EL12 = 0xac80,
	AArch64_SYSREG_BRBCR_EL2 = 0xa480,
	AArch64_SYSREG_BRBFCR_EL1 = 0x8c81,
	AArch64_SYSREG_BRBIDR0_EL1 = 0x8c90,
	AArch64_SYSREG_BRBINF0_EL1 = 0x8c00,
	AArch64_SYSREG_BRBINF10_EL1 = 0x8c50,
	AArch64_SYSREG_BRBINF11_EL1 = 0x8c58,
	AArch64_SYSREG_BRBINF12_EL1 = 0x8c60,
	AArch64_SYSREG_BRBINF13_EL1 = 0x8c68,
	AArch64_SYSREG_BRBINF14_EL1 = 0x8c70,
	AArch64_SYSREG_BRBINF15_EL1 = 0x8c78,
	AArch64_SYSREG_BRBINF16_EL1 = 0x8c04,
	AArch64_SYSREG_BRBINF17_EL1 = 0x8c0c,
	AArch64_SYSREG_BRBINF18_EL1 = 0x8c14,
	AArch64_SYSREG_BRBINF19_EL1 = 0x8c1c,
	AArch64_SYSREG_BRBINF1_EL1 = 0x8c08,
	AArch64_SYSREG_BRBINF20_EL1 = 0x8c24,
	AArch64_SYSREG_BRBINF21_EL1 = 0x8c2c,
	AArch64_SYSREG_BRBINF22_EL1 = 0x8c34,
	AArch64_SYSREG_BRBINF23_EL1 = 0x8c3c,
	AArch64_SYSREG_BRBINF24_EL1 = 0x8c44,
	AArch64_SYSREG_BRBINF25_EL1 = 0x8c4c,
	AArch64_SYSREG_BRBINF26_EL1 = 0x8c54,
	AArch64_SYSREG_BRBINF27_EL1 = 0x8c5c,
	AArch64_SYSREG_BRBINF28_EL1 = 0x8c64,
	AArch64_SYSREG_BRBINF29_EL1 = 0x8c6c,
	AArch64_SYSREG_BRBINF2_EL1 = 0x8c10,
	AArch64_SYSREG_BRBINF30_EL1 = 0x8c74,
	AArch64_SYSREG_BRBINF31_EL1 = 0x8c7c,
	AArch64_SYSREG_BRBINF3_EL1 = 0x8c18,
	AArch64_SYSREG_BRBINF4_EL1 = 0x8c20,
	AArch64_SYSREG_BRBINF5_EL1 = 0x8c28,
	AArch64_SYSREG_BRBINF6_EL1 = 0x8c30,
	AArch64_SYSREG_BRBINF7_EL1 = 0x8c38,
	AArch64_SYSREG_BRBINF8_EL1 = 0x8c40,
	AArch64_SYSREG_BRBINF9_EL1 = 0x8c48,
	AArch64_SYSREG_BRBINFINJ_EL1 = 0x8c88,
	AArch64_SYSREG_BRBSRC0_EL1 = 0x8c01,
	AArch64_SYSREG_BRBSRC10_EL1 = 0x8c51,
	AArch64_SYSREG_BRBSRC11_EL1 = 0x8c59,
	AArch64_SYSREG_BRBSRC12_EL1 = 0x8c61,
	AArch64_SYSREG_BRBSRC13_EL1 = 0x8c69,
	AArch64_SYSREG_BRBSRC14_EL1 = 0x8c71,
	AArch64_SYSREG_BRBSRC15_EL1 = 0x8c79,
	AArch64_SYSREG_BRBSRC16_EL1 = 0x8c05,
	AArch64_SYSREG_BRBSRC17_EL1 = 0x8c0d,
	AArch64_SYSREG_BRBSRC18_EL1 = 0x8c15,
	AArch64_SYSREG_BRBSRC19_EL1 = 0x8c1d,
	AArch64_SYSREG_BRBSRC1_EL1 = 0x8c09,
	AArch64_SYSREG_BRBSRC20_EL1 = 0x8c25,
	AArch64_SYSREG_BRBSRC21_EL1 = 0x8c2d,
	AArch64_SYSREG_BRBSRC22_EL1 = 0x8c35,
	AArch64_SYSREG_BRBSRC23_EL1 = 0x8c3d,
	AArch64_SYSREG_BRBSRC24_EL1 = 0x8c45,
	AArch64_SYSREG_BRBSRC25_EL1 = 0x8c4d,
	AArch64_SYSREG_BRBSRC26_EL1 = 0x8c55,
	AArch64_SYSREG_BRBSRC27_EL1 = 0x8c5d,
	AArch64_SYSREG_BRBSRC28_EL1 = 0x8c65,
	AArch64_SYSREG_BRBSRC29_EL1 = 0x8c6d,
	AArch64_SYSREG_BRBSRC2_EL1 = 0x8c11,
	AArch64_SYSREG_BRBSRC30_EL1 = 0x8c75,
	AArch64_SYSREG_BRBSRC31_EL1 = 0x8c7d,
	AArch64_SYSREG_BRBSRC3_EL1 = 0x8c19,
	AArch64_SYSREG_BRBSRC4_EL1 = 0x8c21,
	AArch64_SYSREG_BRBSRC5_EL1 = 0x8c29,
	AArch64_SYSREG_BRBSRC6_EL1 = 0x8c31,
	AArch64_SYSREG_BRBSRC7_EL1 = 0x8c39,
	AArch64_SYSREG_BRBSRC8_EL1 = 0x8c41,
	AArch64_SYSREG_BRBSRC9_EL1 = 0x8c49,
	AArch64_SYSREG_BRBSRCINJ_EL1 = 0x8c89,
	AArch64_SYSREG_BRBTGT0_EL1 = 0x8c02,
	AArch64_SYSREG_BRBTGT10_EL1 = 0x8c52,
	AArch64_SYSREG_BRBTGT11_EL1 = 0x8c5a,
	AArch64_SYSREG_BRBTGT12_EL1 = 0x8c62,
	AArch64_SYSREG_BRBTGT13_EL1 = 0x8c6a,
	AArch64_SYSREG_BRBTGT14_EL1 = 0x8c72,
	AArch64_SYSREG_BRBTGT15_EL1 = 0x8c7a,
	AArch64_SYSREG_BRBTGT16_EL1 = 0x8c06,
	AArch64_SYSREG_BRBTGT17_EL1 = 0x8c0e,
	AArch64_SYSREG_BRBTGT18_EL1 = 0x8c16,
	AArch64_SYSREG_BRBTGT19_EL1 = 0x8c1e,
	AArch64_SYSREG_BRBTGT1_EL1 = 0x8c0a,
	AArch64_SYSREG_BRBTGT20_EL1 = 0x8c26,
	AArch64_SYSREG_BRBTGT21_EL1 = 0x8c2e,
	AArch64_SYSREG_BRBTGT22_EL1 = 0x8c36,
	AArch64_SYSREG_BRBTGT23_EL1 = 0x8c3e,
	AArch64_SYSREG_BRBTGT24_EL1 = 0x8c46,
	AArch64_SYSREG_BRBTGT25_EL1 = 0x8c4e,
	AArch64_SYSREG_BRBTGT26_EL1 = 0x8c56,
	AArch64_SYSREG_BRBTGT27_EL1 = 0x8c5e,
	AArch64_SYSREG_BRBTGT28_EL1 = 0x8c66,
	AArch64_SYSREG_BRBTGT29_EL1 = 0x8c6e,
	AArch64_SYSREG_BRBTGT2_EL1 = 0x8c12,
	AArch64_SYSREG_BRBTGT30_EL1 = 0x8c76,
	AArch64_SYSREG_BRBTGT31_EL1 = 0x8c7e,
	AArch64_SYSREG_BRBTGT3_EL1 = 0x8c1a,
	AArch64_SYSREG_BRBTGT4_EL1 = 0x8c22,
	AArch64_SYSREG_BRBTGT5_EL1 = 0x8c2a,
	AArch64_SYSREG_BRBTGT6_EL1 = 0x8c32,
	AArch64_SYSREG_BRBTGT7_EL1 = 0x8c3a,
	AArch64_SYSREG_BRBTGT8_EL1 = 0x8c42,
	AArch64_SYSREG_BRBTGT9_EL1 = 0x8c4a,
	AArch64_SYSREG_BRBTGTINJ_EL1 = 0x8c8a,
	AArch64_SYSREG_BRBTS_EL1 = 0x8c82,
	AArch64_SYSREG_CCSIDR2_EL1 = 0xc802,
	AArch64_SYSREG_CCSIDR_EL1 = 0xc800,
	AArch64_SYSREG_CLIDR_EL1 = 0xc801,
	AArch64_SYSREG_CNTFRQ_EL0 = 0xdf00,
	AArch64_SYSREG_CNTHCTL_EL2 = 0xe708,
	AArch64_SYSREG_CNTHPS_CTL_EL2 = 0xe729,
	AArch64_SYSREG_CNTHPS_CVAL_EL2 = 0xe72a,
	AArch64_SYSREG_CNTHPS_TVAL_EL2 = 0xe728,
	AArch64_SYSREG_CNTHP_CTL_EL2 = 0xe711,
	AArch64_SYSREG_CNTHP_CVAL_EL2 = 0xe712,
	AArch64_SYSREG_CNTHP_TVAL_EL2 = 0xe710,
	AArch64_SYSREG_CNTHVS_CTL_EL2 = 0xe721,
	AArch64_SYSREG_CNTHVS_CVAL_EL2 = 0xe722,
	AArch64_SYSREG_CNTHVS_TVAL_EL2 = 0xe720,
	AArch64_SYSREG_CNTHV_CTL_EL2 = 0xe719,
	AArch64_SYSREG_CNTHV_CVAL_EL2 = 0xe71a,
	AArch64_SYSREG_CNTHV_TVAL_EL2 = 0xe718,
	AArch64_SYSREG_CNTISCALE_EL2 = 0xe705,
	AArch64_SYSREG_CNTKCTL_EL1 = 0xc708,
	AArch64_SYSREG_CNTKCTL_EL12 = 0xef08,
	AArch64_SYSREG_CNTPCTSS_EL0 = 0xdf05,
	AArch64_SYSREG_CNTPCT_EL0 = 0xdf01,
	AArch64_SYSREG_CNTPOFF_EL2 = 0xe706,
	AArch64_SYSREG_CNTPS_CTL_EL1 = 0xff11,
	AArch64_SYSREG_CNTPS_CVAL_EL1 = 0xff12,
	AArch64_SYSREG_CNTPS_TVAL_EL1 = 0xff10,
	AArch64_SYSREG_CNTP_CTL_EL0 = 0xdf11,
	AArch64_SYSREG_CNTP_CTL_EL02 = 0xef11,
	AArch64_SYSREG_CNTP_CVAL_EL0 = 0xdf12,
	AArch64_SYSREG_CNTP_CVAL_EL02 = 0xef12,
	AArch64_SYSREG_CNTP_TVAL_EL0 = 0xdf10,
	AArch64_SYSREG_CNTP_TVAL_EL02 = 0xef10,
	AArch64_SYSREG_CNTSCALE_EL2 = 0xe704,
	AArch64_SYSREG_CNTVCTSS_EL0 = 0xdf06,
	AArch64_SYSREG_CNTVCT_EL0 = 0xdf02,
	AArch64_SYSREG_CNTVFRQ_EL2 = 0xe707,
	AArch64_SYSREG_CNTVOFF_EL2 = 0xe703,
	AArch64_SYSREG_CNTV_CTL_EL0 = 0xdf19,
	AArch64_SYSREG_CNTV_CTL_EL02 = 0xef19,
	AArch64_SYSREG_CNTV_CVAL_EL0 = 0xdf1a,
	AArch64_SYSREG_CNTV_CVAL_EL02 = 0xef1a,
	AArch64_SYSREG_CNTV_TVAL_EL0 = 0xdf18,
	AArch64_SYSREG_CNTV_TVAL_EL02 = 0xef18,
	AArch64_SYSREG_CONTEXTIDR_EL1 = 0xc681,
	AArch64_SYSREG_CONTEXTIDR_EL12 = 0xee81,
	AArch64_SYSREG_CONTEXTIDR_EL2 = 0xe681,
	AArch64_SYSREG_CPACR_EL1 = 0xc082,
	AArch64_SYSREG_CPACR_EL12 = 0xe882,
	AArch64_SYSREG_CPM_IOACC_CTL_EL3 = 0xff90,
	AArch64_SYSREG_CPTR_EL2 = 0xe08a,
	AArch64_SYSREG_CPTR_EL3 = 0xf08a,
	AArch64_SYSREG_CSSELR_EL1 = 0xd000,
	AArch64_SYSREG_CTR_EL0 = 0xd801,
	AArch64_SYSREG_CURRENTEL = 0xc212,
	AArch64_SYSREG_DACR32_EL2 = 0xe180,
	AArch64_SYSREG_DAIF = 0xda11,
	AArch64_SYSREG_DBGAUTHSTATUS_EL1 = 0x83f6,
	AArch64_SYSREG_DBGBCR0_EL1 = 0x8005,
	AArch64_SYSREG_DBGBCR10_EL1 = 0x8055,
	AArch64_SYSREG_DBGBCR11_EL1 = 0x805d,
	AArch64_SYSREG_DBGBCR12_EL1 = 0x8065,
	AArch64_SYSREG_DBGBCR13_EL1 = 0x806d,
	AArch64_SYSREG_DBGBCR14_EL1 = 0x8075,
	AArch64_SYSREG_DBGBCR15_EL1 = 0x807d,
	AArch64_SYSREG_DBGBCR1_EL1 = 0x800d,
	AArch64_SYSREG_DBGBCR2_EL1 = 0x8015,
	AArch64_SYSREG_DBGBCR3_EL1 = 0x801d,
	AArch64_SYSREG_DBGBCR4_EL1 = 0x8025,
	AArch64_SYSREG_DBGBCR5_EL1 = 0x802d,
	AArch64_SYSREG_DBGBCR6_EL1 = 0x8035,
	AArch64_SYSREG_DBGBCR7_EL1 = 0x803d,
	AArch64_SYSREG_DBGBCR8_EL1 = 0x8045,
	AArch64_SYSREG_DBGBCR9_EL1 = 0x804d,
	AArch64_SYSREG_DBGBVR0_EL1 = 0x8004,
	AArch64_SYSREG_DBGBVR10_EL1 = 0x8054,
	AArch64_SYSREG_DBGBVR11_EL1 = 0x805c,
	AArch64_SYSREG_DBGBVR12_EL1 = 0x8064,
	AArch64_SYSREG_DBGBVR13_EL1 = 0x806c,
	AArch64_SYSREG_DBGBVR14_EL1 = 0x8074,
	AArch64_SYSREG_DBGBVR15_EL1 = 0x807c,
	AArch64_SYSREG_DBGBVR1_EL1 = 0x800c,
	AArch64_SYSREG_DBGBVR2_EL1 = 0x8014,
	AArch64_SYSREG_DBGBVR3_EL1 = 0x801c,
	AArch64_SYSREG_DBGBVR4_EL1 = 0x8024,
	AArch64_SYSREG_DBGBVR5_EL1 = 0x802c,
	AArch64_SYSREG_DBGBVR6_EL1 = 0x8034,
	AArch64_SYSREG_DBGBVR7_EL1 = 0x803c,
	AArch64_SYSREG_DBGBVR8_EL1 = 0x8044,
	AArch64_SYSREG_DBGBVR9_EL1 = 0x804c,
	AArch64_SYSREG_DBGCLAIMCLR_EL1 = 0x83ce,
	AArch64_SYSREG_DBGCLAIMSET_EL1 = 0x83c6,
	AArch64_SYSREG_DBGDTRRX_EL0 = 0x9828,
	AArch64_SYSREG_DBGDTRTX_EL0 = 0x9828,
	AArch64_SYSREG_DBGDTR_EL0 = 0x9820,
	AArch64_SYSREG_DBGPRCR_EL1 = 0x80a4,
	AArch64_SYSREG_DBGVCR32_EL2 = 0xa038,
	AArch64_SYSREG_DBGWCR0_EL1 = 0x8007,
	AArch64_SYSREG_DBGWCR10_EL1 = 0x8057,
	AArch64_SYSREG_DBGWCR11_EL1 = 0x805f,
	AArch64_SYSREG_DBGWCR12_EL1 = 0x8067,
	AArch64_SYSREG_DBGWCR13_EL1 = 0x806f,
	AArch64_SYSREG_DBGWCR14_EL1 = 0x8077,
	AArch64_SYSREG_DBGWCR15_EL1 = 0x807f,
	AArch64_SYSREG_DBGWCR1_EL1 = 0x800f,
	AArch64_SYSREG_DBGWCR2_EL1 = 0x8017,
	AArch64_SYSREG_DBGWCR3_EL1 = 0x801f,
	AArch64_SYSREG_DBGWCR4_EL1 = 0x8027,
	AArch64_SYSREG_DBGWCR5_EL1 = 0x802f,
	AArch64_SYSREG_DBGWCR6_EL1 = 0x8037,
	AArch64_SYSREG_DBGWCR7_EL1 = 0x803f,
	AArch64_SYSREG_DBGWCR8_EL1 = 0x8047,
	AArch64_SYSREG_DBGWCR9_EL1 = 0x804f,
	AArch64_SYSREG_DBGWVR0_EL1 = 0x8006,
	AArch64_SYSREG_DBGWVR10_EL1 = 0x8056,
	AArch64_SYSREG_DBGWVR11_EL1 = 0x805e,
	AArch64_SYSREG_DBGWVR12_EL1 = 0x8066,
	AArch64_SYSREG_DBGWVR13_EL1 = 0x806e,
	AArch64_SYSREG_DBGWVR14_EL1 = 0x8076,
	AArch64_SYSREG_DBGWVR15_EL1 = 0x807e,
	AArch64_SYSREG_DBGWVR1_EL1 = 0x800e,
	AArch64_SYSREG_DBGWVR2_EL1 = 0x8016,
	AArch64_SYSREG_DBGWVR3_EL1 = 0x801e,
	AArch64_SYSREG_DBGWVR4_EL1 = 0x8026,
	AArch64_SYSREG_DBGWVR5_EL1 = 0x802e,
	AArch64_SYSREG_DBGWVR6_EL1 = 0x8036,
	AArch64_SYSREG_DBGWVR7_EL1 = 0x803e,
	AArch64_SYSREG_DBGWVR8_EL1 = 0x8046,
	AArch64_SYSREG_DBGWVR9_EL1 = 0x804e,
	AArch64_SYSREG_DCZID_EL0 = 0xd807,
	AArch64_SYSREG_DISR_EL1 = 0xc609,
	AArch64_SYSREG_DIT = 0xda15,
	AArch64_SYSREG_DLR_EL0 = 0xda29,
	AArch64_SYSREG_DSPSR_EL0 = 0xda28,
	AArch64_SYSREG_ELR_EL1 = 0xc201,
	AArch64_SYSREG_ELR_EL12 = 0xea01,
	AArch64_SYSREG_ELR_EL2 = 0xe201,
	AArch64_SYSREG_ELR_EL3 = 0xf201,
	AArch64_SYSREG_ERRIDR_EL1 = 0xc298,
	AArch64_SYSREG_ERRSELR_EL1 = 0xc299,
	AArch64_SYSREG_ERXADDR_EL1 = 0xc2a3,
	AArch64_SYSREG_ERXCTLR_EL1 = 0xc2a1,
	AArch64_SYSREG_ERXFR_EL1 = 0xc2a0,
	AArch64_SYSREG_ERXGSR_EL1 = 0xc29a,
	AArch64_SYSREG_ERXMISC0_EL1 = 0xc2a8,
	AArch64_SYSREG_ERXMISC1_EL1 = 0xc2a9,
	AArch64_SYSREG_ERXMISC2_EL1 = 0xc2aa,
	AArch64_SYSREG_ERXMISC3_EL1 = 0xc2ab,
	AArch64_SYSREG_ERXPFGCDN_EL1 = 0xc2a6,
	AArch64_SYSREG_ERXPFGCTL_EL1 = 0xc2a5,
	AArch64_SYSREG_ERXPFGF_EL1 = 0xc2a4,
	AArch64_SYSREG_ERXSTATUS_EL1 = 0xc2a2,
	AArch64_SYSREG_ESR_EL1 = 0xc290,
	AArch64_SYSREG_ESR_EL12 = 0xea90,
	AArch64_SYSREG_ESR_EL2 = 0xe290,
	AArch64_SYSREG_ESR_EL3 = 0xf290,
	AArch64_SYSREG_FAR_EL1 = 0xc300,
	AArch64_SYSREG_FAR_EL12 = 0xeb00,
	AArch64_SYSREG_FAR_EL2 = 0xe300,
	AArch64_SYSREG_FAR_EL3 = 0xf300,
	AArch64_SYSREG_FPCR = 0xda20,
	AArch64_SYSREG_FPEXC32_EL2 = 0xe298,
	AArch64_SYSREG_FPSR = 0xda21,
	AArch64_SYSREG_GCR_EL1 = 0xc086,
	AArch64_SYSREG_GMID_EL1 = 0xc804,
	AArch64_SYSREG_GPCCR_EL3 = 0xf10e,
	AArch64_SYSREG_GPTBR_EL3 = 0xf10c,
	AArch64_SYSREG_HACR_EL2 = 0xe08f,
	AArch64_SYSREG_HAFGRTR_EL2 = 0xe18e,
	AArch64_SYSREG_HCRX_EL2 = 0xe092,
	AArch64_SYSREG_HCR_EL2 = 0xe088,
	AArch64_SYSREG_HDFGRTR2_EL2 = 0xe188,
	AArch64_SYSREG_HDFGRTR_EL2 = 0xe18c,
	AArch64_SYSREG_HDFGWTR2_EL2 = 0xe189,
	AArch64_SYSREG_HDFGWTR_EL2 = 0xe18d,
	AArch64_SYSREG_HFGITR2_EL2 = 0xe18f,
	AArch64_SYSREG_HFGITR_EL2 = 0xe08e,
	AArch64_SYSREG_HFGRTR2_EL2 = 0xe18a,
	AArch64_SYSREG_HFGRTR_EL2 = 0xe08c,
	AArch64_SYSREG_HFGWTR2_EL2 = 0xe18b,
	AArch64_SYSREG_HFGWTR_EL2 = 0xe08d,
	AArch64_SYSREG_HPFAR_EL2 = 0xe304,
	AArch64_SYSREG_HSTR_EL2 = 0xe08b,
	AArch64_SYSREG_ICC_AP0R0_EL1 = 0xc644,
	AArch64_SYSREG_ICC_AP0R1_EL1 = 0xc645,
	AArch64_SYSREG_ICC_AP0R2_EL1 = 0xc646,
	AArch64_SYSREG_ICC_AP0R3_EL1 = 0xc647,
	AArch64_SYSREG_ICC_AP1R0_EL1 = 0xc648,
	AArch64_SYSREG_ICC_AP1R1_EL1 = 0xc649,
	AArch64_SYSREG_ICC_AP1R2_EL1 = 0xc64a,
	AArch64_SYSREG_ICC_AP1R3_EL1 = 0xc64b,
	AArch64_SYSREG_ICC_ASGI1R_EL1 = 0xc65e,
	AArch64_SYSREG_ICC_BPR0_EL1 = 0xc643,
	AArch64_SYSREG_ICC_BPR1_EL1 = 0xc663,
	AArch64_SYSREG_ICC_CTLR_EL1 = 0xc664,
	AArch64_SYSREG_ICC_CTLR_EL3 = 0xf664,
	AArch64_SYSREG_ICC_DIR_EL1 = 0xc659,
	AArch64_SYSREG_ICC_EOIR0_EL1 = 0xc641,
	AArch64_SYSREG_ICC_EOIR1_EL1 = 0xc661,
	AArch64_SYSREG_ICC_HPPIR0_EL1 = 0xc642,
	AArch64_SYSREG_ICC_HPPIR1_EL1 = 0xc662,
	AArch64_SYSREG_ICC_IAR0_EL1 = 0xc640,
	AArch64_SYSREG_ICC_IAR1_EL1 = 0xc660,
	AArch64_SYSREG_ICC_IGRPEN0_EL1 = 0xc666,
	AArch64_SYSREG_ICC_IGRPEN1_EL1 = 0xc667,
	AArch64_SYSREG_ICC_IGRPEN1_EL3 = 0xf667,
	AArch64_SYSREG_ICC_NMIAR1_EL1 = 0xc64d,
	AArch64_SYSREG_ICC_PMR_EL1 = 0xc230,
	AArch64_SYSREG_ICC_RPR_EL1 = 0xc65b,
	AArch64_SYSREG_ICC_SGI0R_EL1 = 0xc65f,
	AArch64_SYSREG_ICC_SGI1R_EL1 = 0xc65d,
	AArch64_SYSREG_ICC_SRE_EL1 = 0xc665,
	AArch64_SYSREG_ICC_SRE_EL2 = 0xe64d,
	AArch64_SYSREG_ICC_SRE_EL3 = 0xf665,
	AArch64_SYSREG_ICH_AP0R0_EL2 = 0xe640,
	AArch64_SYSREG_ICH_AP0R1_EL2 = 0xe641,
	AArch64_SYSREG_ICH_AP0R2_EL2 = 0xe642,
	AArch64_SYSREG_ICH_AP0R3_EL2 = 0xe643,
	AArch64_SYSREG_ICH_AP1R0_EL2 = 0xe648,
	AArch64_SYSREG_ICH_AP1R1_EL2 = 0xe649,
	AArch64_SYSREG_ICH_AP1R2_EL2 = 0xe64a,
	AArch64_SYSREG_ICH_AP1R3_EL2 = 0xe64b,
	AArch64_SYSREG_ICH_EISR_EL2 = 0xe65b,
	AArch64_SYSREG_ICH_ELRSR_EL2 = 0xe65d,
	AArch64_SYSREG_ICH_HCR_EL2 = 0xe658,
	AArch64_SYSREG_ICH_LR0_EL2 = 0xe660,
	AArch64_SYSREG_ICH_LR10_EL2 = 0xe66a,
	AArch64_SYSREG_ICH_LR11_EL2 = 0xe66b,
	AArch64_SYSREG_ICH_LR12_EL2 = 0xe66c,
	AArch64_SYSREG_ICH_LR13_EL2 = 0xe66d,
	AArch64_SYSREG_ICH_LR14_EL2 = 0xe66e,
	AArch64_SYSREG_ICH_LR15_EL2 = 0xe66f,
	AArch64_SYSREG_ICH_LR1_EL2 = 0xe661,
	AArch64_SYSREG_ICH_LR2_EL2 = 0xe662,
	AArch64_SYSREG_ICH_LR3_EL2 = 0xe663,
	AArch64_SYSREG_ICH_LR4_EL2 = 0xe664,
	AArch64_SYSREG_ICH_LR5_EL2 = 0xe665,
	AArch64_SYSREG_ICH_LR6_EL2 = 0xe666,
	AArch64_SYSREG_ICH_LR7_EL2 = 0xe667,
	AArch64_SYSREG_ICH_LR8_EL2 = 0xe668,
	AArch64_SYSREG_ICH_LR9_EL2 = 0xe669,
	AArch64_SYSREG_ICH_MISR_EL2 = 0xe65a,
	AArch64_SYSREG_ICH_VMCR_EL2 = 0xe65f,
	AArch64_SYSREG_ICH_VTR_EL2 = 0xe659,
	AArch64_SYSREG_ID_AA64AFR0_EL1 = 0xc02c,
	AArch64_SYSREG_ID_AA64AFR1_EL1 = 0xc02d,
	AArch64_SYSREG_ID_AA64DFR0_EL1 = 0xc028,
	AArch64_SYSREG_ID_AA64DFR1_EL1 = 0xc029,
	AArch64_SYSREG_ID_AA64ISAR0_EL1 = 0xc030,
	AArch64_SYSREG_ID_AA64ISAR1_EL1 = 0xc031,
	AArch64_SYSREG_ID_AA64ISAR2_EL1 = 0xc032,
	AArch64_SYSREG_ID_AA64MMFR0_EL1 = 0xc038,
	AArch64_SYSREG_ID_AA64MMFR1_EL1 = 0xc039,
	AArch64_SYSREG_ID_AA64MMFR2_EL1 = 0xc03a,
	AArch64_SYSREG_ID_AA64MMFR3_EL1 = 0xc03b,
	AArch64_SYSREG_ID_AA64MMFR4_EL1 = 0xc03c,
	AArch64_SYSREG_ID_AA64PFR0_EL1 = 0xc020,
	AArch64_SYSREG_ID_AA64PFR1_EL1 = 0xc021,
	AArch64_SYSREG_ID_AA64PFR2_EL1 = 0xc022,
	AArch64_SYSREG_ID_AA64SMFR0_EL1 = 0xc025,
	AArch64_SYSREG_ID_AA64ZFR0_EL1 = 0xc024,
	AArch64_SYSREG_ID_AFR0_EL1 = 0xc00b,
	AArch64_SYSREG_ID_DFR0_EL1 = 0xc00a,
	AArch64_SYSREG_ID_DFR1_EL1 = 0xc01d,
	AArch64_SYSREG_ID_ISAR0_EL1 = 0xc010,
	AArch64_SYSREG_ID_ISAR1_EL1 = 0xc011,
	AArch64_SYSREG_ID_ISAR2_EL1 = 0xc012,
	AArch64_SYSREG_ID_ISAR3_EL1 = 0xc013,
	AArch64_SYSREG_ID_ISAR4_EL1 = 0xc014,
	AArch64_SYSREG_ID_ISAR5_EL1 = 0xc015,
	AArch64_SYSREG_ID_ISAR6_EL1 = 0xc017,
	AArch64_SYSREG_ID_MMFR0_EL1 = 0xc00c,
	AArch64_SYSREG_ID_MMFR1_EL1 = 0xc00d,
	AArch64_SYSREG_ID_MMFR2_EL1 = 0xc00e,
	AArch64_SYSREG_ID_MMFR3_EL1 = 0xc00f,
	AArch64_SYSREG_ID_MMFR4_EL1 = 0xc016,
	AArch64_SYSREG_ID_MMFR5_EL1 = 0xc01e,
	AArch64_SYSREG_ID_PFR0_EL1 = 0xc008,
	AArch64_SYSREG_ID_PFR1_EL1 = 0xc009,
	AArch64_SYSREG_ID_PFR2_EL1 = 0xc01c,
	AArch64_SYSREG_IFSR32_EL2 = 0xe281,
	AArch64_SYSREG_ISR_EL1 = 0xc608,
	AArch64_SYSREG_LORC_EL1 = 0xc523,
	AArch64_SYSREG_LOREA_EL1 = 0xc521,
	AArch64_SYSREG_LORID_EL1 = 0xc527,
	AArch64_SYSREG_LORN_EL1 = 0xc522,
	AArch64_SYSREG_LORSA_EL1 = 0xc520,
	AArch64_SYSREG_MAIR2_EL1 = 0xc511,
	AArch64_SYSREG_MAIR2_EL12 = 0xed11,
	AArch64_SYSREG_MAIR2_EL2 = 0xe509,
	AArch64_SYSREG_MAIR2_EL3 = 0xf509,
	AArch64_SYSREG_MAIR_EL1 = 0xc510,
	AArch64_SYSREG_MAIR_EL12 = 0xed10,
	AArch64_SYSREG_MAIR_EL2 = 0xe510,
	AArch64_SYSREG_MAIR_EL3 = 0xf510,
	AArch64_SYSREG_MDCCINT_EL1 = 0x8010,
	AArch64_SYSREG_MDCCSR_EL0 = 0x9808,
	AArch64_SYSREG_MDCR_EL2 = 0xe089,
	AArch64_SYSREG_MDCR_EL3 = 0xf099,
	AArch64_SYSREG_MDRAR_EL1 = 0x8080,
	AArch64_SYSREG_MDSCR_EL1 = 0x8012,
	AArch64_SYSREG_MDSELR_EL1 = 0x8022,
	AArch64_SYSREG_MECIDR_EL2 = 0xe547,
	AArch64_SYSREG_MECID_A0_EL2 = 0xe541,
	AArch64_SYSREG_MECID_A1_EL2 = 0xe543,
	AArch64_SYSREG_MECID_P0_EL2 = 0xe540,
	AArch64_SYSREG_MECID_P1_EL2 = 0xe542,
	AArch64_SYSREG_MECID_RL_A_EL3 = 0xf551,
	AArch64_SYSREG_MFAR_EL3 = 0xf305,
	AArch64_SYSREG_MIDR_EL1 = 0xc000,
	AArch64_SYSREG_MPAM0_EL1 = 0xc529,
	AArch64_SYSREG_MPAM1_EL1 = 0xc528,
	AArch64_SYSREG_MPAM1_EL12 = 0xed28,
	AArch64_SYSREG_MPAM2_EL2 = 0xe528,
	AArch64_SYSREG_MPAM3_EL3 = 0xf528,
	AArch64_SYSREG_MPAMHCR_EL2 = 0xe520,
	AArch64_SYSREG_MPAMIDR_EL1 = 0xc524,
	AArch64_SYSREG_MPAMSM_EL1 = 0xc52b,
	AArch64_SYSREG_MPAMVPM0_EL2 = 0xe530,
	AArch64_SYSREG_MPAMVPM1_EL2 = 0xe531,
	AArch64_SYSREG_MPAMVPM2_EL2 = 0xe532,
	AArch64_SYSREG_MPAMVPM3_EL2 = 0xe533,
	AArch64_SYSREG_MPAMVPM4_EL2 = 0xe534,
	AArch64_SYSREG_MPAMVPM5_EL2 = 0xe535,
	AArch64_SYSREG_MPAMVPM6_EL2 = 0xe536,
	AArch64_SYSREG_MPAMVPM7_EL2 = 0xe537,
	AArch64_SYSREG_MPAMVPMV_EL2 = 0xe521,
	AArch64_SYSREG_MPIDR_EL1 = 0xc005,
	AArch64_SYSREG_MPUIR_EL1 = 0xc004,
	AArch64_SYSREG_MPUIR_EL2 = 0xe004,
	AArch64_SYSREG_MVFR0_EL1 = 0xc018,
	AArch64_SYSREG_MVFR1_EL1 = 0xc019,
	AArch64_SYSREG_MVFR2_EL1 = 0xc01a,
	AArch64_SYSREG_NZCV = 0xda10,
	AArch64_SYSREG_OSDLR_EL1 = 0x809c,
	AArch64_SYSREG_OSDTRRX_EL1 = 0x8002,
	AArch64_SYSREG_OSDTRTX_EL1 = 0x801a,
	AArch64_SYSREG_OSECCR_EL1 = 0x8032,
	AArch64_SYSREG_OSLAR_EL1 = 0x8084,
	AArch64_SYSREG_OSLSR_EL1 = 0x808c,
	AArch64_SYSREG_PAN = 0xc213,
	AArch64_SYSREG_PAR_EL1 = 0xc3a0,
	AArch64_SYSREG_PFAR_EL1 = 0xc305,
	AArch64_SYSREG_PFAR_EL12 = 0xeb05,
	AArch64_SYSREG_PFAR_EL2 = 0xe305,
	AArch64_SYSREG_PIRE0_EL1 = 0xc512,
	AArch64_SYSREG_PIRE0_EL12 = 0xed12,
	AArch64_SYSREG_PIRE0_EL2 = 0xe512,
	AArch64_SYSREG_PIR_EL1 = 0xc513,
	AArch64_SYSREG_PIR_EL12 = 0xed13,
	AArch64_SYSREG_PIR_EL2 = 0xe513,
	AArch64_SYSREG_PIR_EL3 = 0xf513,
	AArch64_SYSREG_PM = 0xc219,
	AArch64_SYSREG_PMBIDR_EL1 = 0xc4d7,
	AArch64_SYSREG_PMBLIMITR_EL1 = 0xc4d0,
	AArch64_SYSREG_PMBPTR_EL1 = 0xc4d1,
	AArch64_SYSREG_PMBSR_EL1 = 0xc4d3,
	AArch64_SYSREG_PMCCFILTR_EL0 = 0xdf7f,
	AArch64_SYSREG_PMCCNTR_EL0 = 0xdce8,
	AArch64_SYSREG_PMCCNTSVR_EL1 = 0x875f,
	AArch64_SYSREG_PMCEID0_EL0 = 0xdce6,
	AArch64_SYSREG_PMCEID1_EL0 = 0xdce7,
	AArch64_SYSREG_PMCNTENCLR_EL0 = 0xdce2,
	AArch64_SYSREG_PMCNTENSET_EL0 = 0xdce1,
	AArch64_SYSREG_PMCR_EL0 = 0xdce0,
	AArch64_SYSREG_PMECR_EL1 = 0xc4f5,
	AArch64_SYSREG_PMEVCNTR0_EL0 = 0xdf40,
	AArch64_SYSREG_PMEVCNTR10_EL0 = 0xdf4a,
	AArch64_SYSREG_PMEVCNTR11_EL0 = 0xdf4b,
	AArch64_SYSREG_PMEVCNTR12_EL0 = 0xdf4c,
	AArch64_SYSREG_PMEVCNTR13_EL0 = 0xdf4d,
	AArch64_SYSREG_PMEVCNTR14_EL0 = 0xdf4e,
	AArch64_SYSREG_PMEVCNTR15_EL0 = 0xdf4f,
	AArch64_SYSREG_PMEVCNTR16_EL0 = 0xdf50,
	AArch64_SYSREG_PMEVCNTR17_EL0 = 0xdf51,
	AArch64_SYSREG_PMEVCNTR18_EL0 = 0xdf52,
	AArch64_SYSREG_PMEVCNTR19_EL0 = 0xdf53,
	AArch64_SYSREG_PMEVCNTR1_EL0 = 0xdf41,
	AArch64_SYSREG_PMEVCNTR20_EL0 = 0xdf54,
	AArch64_SYSREG_PMEVCNTR21_EL0 = 0xdf55,
	AArch64_SYSREG_PMEVCNTR22_EL0 = 0xdf56,
	AArch64_SYSREG_PMEVCNTR23_EL0 = 0xdf57,
	AArch64_SYSREG_PMEVCNTR24_EL0 = 0xdf58,
	AArch64_SYSREG_PMEVCNTR25_EL0 = 0xdf59,
	AArch64_SYSREG_PMEVCNTR26_EL0 = 0xdf5a,
	AArch64_SYSREG_PMEVCNTR27_EL0 = 0xdf5b,
	AArch64_SYSREG_PMEVCNTR28_EL0 = 0xdf5c,
	AArch64_SYSREG_PMEVCNTR29_EL0 = 0xdf5d,
	AArch64_SYSREG_PMEVCNTR2_EL0 = 0xdf42,
	AArch64_SYSREG_PMEVCNTR30_EL0 = 0xdf5e,
	AArch64_SYSREG_PMEVCNTR3_EL0 = 0xdf43,
	AArch64_SYSREG_PMEVCNTR4_EL0 = 0xdf44,
	AArch64_SYSREG_PMEVCNTR5_EL0 = 0xdf45,
	AArch64_SYSREG_PMEVCNTR6_EL0 = 0xdf46,
	AArch64_SYSREG_PMEVCNTR7_EL0 = 0xdf47,
	AArch64_SYSREG_PMEVCNTR8_EL0 = 0xdf48,
	AArch64_SYSREG_PMEVCNTR9_EL0 = 0xdf49,
	AArch64_SYSREG_PMEVCNTSVR0_EL1 = 0x8740,
	AArch64_SYSREG_PMEVCNTSVR10_EL1 = 0x874a,
	AArch64_SYSREG_PMEVCNTSVR11_EL1 = 0x874b,
	AArch64_SYSREG_PMEVCNTSVR12_EL1 = 0x874c,
	AArch64_SYSREG_PMEVCNTSVR13_EL1 = 0x874d,
	AArch64_SYSREG_PMEVCNTSVR14_EL1 = 0x874e,
	AArch64_SYSREG_PMEVCNTSVR15_EL1 = 0x874f,
	AArch64_SYSREG_PMEVCNTSVR16_EL1 = 0x8750,
	AArch64_SYSREG_PMEVCNTSVR17_EL1 = 0x8751,
	AArch64_SYSREG_PMEVCNTSVR18_EL1 = 0x8752,
	AArch64_SYSREG_PMEVCNTSVR19_EL1 = 0x8753,
	AArch64_SYSREG_PMEVCNTSVR1_EL1 = 0x8741,
	AArch64_SYSREG_PMEVCNTSVR20_EL1 = 0x8754,
	AArch64_SYSREG_PMEVCNTSVR21_EL1 = 0x8755,
	AArch64_SYSREG_PMEVCNTSVR22_EL1 = 0x8756,
	AArch64_SYSREG_PMEVCNTSVR23_EL1 = 0x8757,
	AArch64_SYSREG_PMEVCNTSVR24_EL1 = 0x8758,
	AArch64_SYSREG_PMEVCNTSVR25_EL1 = 0x8759,
	AArch64_SYSREG_PMEVCNTSVR26_EL1 = 0x875a,
	AArch64_SYSREG_PMEVCNTSVR27_EL1 = 0x875b,
	AArch64_SYSREG_PMEVCNTSVR28_EL1 = 0x875c,
	AArch64_SYSREG_PMEVCNTSVR29_EL1 = 0x875d,
	AArch64_SYSREG_PMEVCNTSVR2_EL1 = 0x8742,
	AArch64_SYSREG_PMEVCNTSVR30_EL1 = 0x875e,
	AArch64_SYSREG_PMEVCNTSVR3_EL1 = 0x8743,
	AArch64_SYSREG_PMEVCNTSVR4_EL1 = 0x8744,
	AArch64_SYSREG_PMEVCNTSVR5_EL1 = 0x8745,
	AArch64_SYSREG_PMEVCNTSVR6_EL1 = 0x8746,
	AArch64_SYSREG_PMEVCNTSVR7_EL1 = 0x8747,
	AArch64_SYSREG_PMEVCNTSVR8_EL1 = 0x8748,
	AArch64_SYSREG_PMEVCNTSVR9_EL1 = 0x8749,
	AArch64_SYSREG_PMEVTYPER0_EL0 = 0xdf60,
	AArch64_SYSREG_PMEVTYPER10_EL0 = 0xdf6a,
	AArch64_SYSREG_PMEVTYPER11_EL0 = 0xdf6b,
	AArch64_SYSREG_PMEVTYPER12_EL0 = 0xdf6c,
	AArch64_SYSREG_PMEVTYPER13_EL0 = 0xdf6d,
	AArch64_SYSREG_PMEVTYPER14_EL0 = 0xdf6e,
	AArch64_SYSREG_PMEVTYPER15_EL0 = 0xdf6f,
	AArch64_SYSREG_PMEVTYPER16_EL0 = 0xdf70,
	AArch64_SYSREG_PMEVTYPER17_EL0 = 0xdf71,
	AArch64_SYSREG_PMEVTYPER18_EL0 = 0xdf72,
	AArch64_SYSREG_PMEVTYPER19_EL0 = 0xdf73,
	AArch64_SYSREG_PMEVTYPER1_EL0 = 0xdf61,
	AArch64_SYSREG_PMEVTYPER20_EL0 = 0xdf74,
	AArch64_SYSREG_PMEVTYPER21_EL0 = 0xdf75,
	AArch64_SYSREG_PMEVTYPER22_EL0 = 0xdf76,
	AArch64_SYSREG_PMEVTYPER23_EL0 = 0xdf77,
	AArch64_SYSREG_PMEVTYPER24_EL0 = 0xdf78,
	AArch64_SYSREG_PMEVTYPER25_EL0 = 0xdf79,
	AArch64_SYSREG_PMEVTYPER26_EL0 = 0xdf7a,
	AArch64_SYSREG_PMEVTYPER27_EL0 = 0xdf7b,
	AArch64_SYSREG_PMEVTYPER28_EL0 = 0xdf7c,
	AArch64_SYSREG_PMEVTYPER29_EL0 = 0xdf7d,
	AArch64_SYSREG_PMEVTYPER2_EL0 = 0xdf62,
	AArch64_SYSREG_PMEVTYPER30_EL0 = 0xdf7e,
	AArch64_SYSREG_PMEVTYPER3_EL0 = 0xdf63,
	AArch64_SYSREG_PMEVTYPER4_EL0 = 0xdf64,
	AArch64_SYSREG_PMEVTYPER5_EL0 = 0xdf65,
	AArch64_SYSREG_PMEVTYPER6_EL0 = 0xdf66,
	AArch64_SYSREG_PMEVTYPER7_EL0 = 0xdf67,
	AArch64_SYSREG_PMEVTYPER8_EL0 = 0xdf68,
	AArch64_SYSREG_PMEVTYPER9_EL0 = 0xdf69,
	AArch64_SYSREG_PMIAR_EL1 = 0xc4f7,
	AArch64_SYSREG_PMICFILTR_EL0 = 0xdcb0,
	AArch64_SYSREG_PMICNTR_EL0 = 0xdca0,
	AArch64_SYSREG_PMICNTSVR_EL1 = 0x8760,
	AArch64_SYSREG_PMINTENCLR_EL1 = 0xc4f2,
	AArch64_SYSREG_PMINTENSET_EL1 = 0xc4f1,
	AArch64_SYSREG_PMMIR_EL1 = 0xc4f6,
	AArch64_SYSREG_PMOVSCLR_EL0 = 0xdce3,
	AArch64_SYSREG_PMOVSSET_EL0 = 0xdcf3,
	AArch64_SYSREG_PMSCR_EL1 = 0xc4c8,
	AArch64_SYSREG_PMSCR_EL12 = 0xecc8,
	AArch64_SYSREG_PMSCR_EL2 = 0xe4c8,
	AArch64_SYSREG_PMSDSFR_EL1 = 0xc4d4,
	AArch64_SYSREG_PMSELR_EL0 = 0xdce5,
	AArch64_SYSREG_PMSEVFR_EL1 = 0xc4cd,
	AArch64_SYSREG_PMSFCR_EL1 = 0xc4cc,
	AArch64_SYSREG_PMSICR_EL1 = 0xc4ca,
	AArch64_SYSREG_PMSIDR_EL1 = 0xc4cf,
	AArch64_SYSREG_PMSIRR_EL1 = 0xc4cb,
	AArch64_SYSREG_PMSLATFR_EL1 = 0xc4ce,
	AArch64_SYSREG_PMSNEVFR_EL1 = 0xc4c9,
	AArch64_SYSREG_PMSSCR_EL1 = 0xc4eb,
	AArch64_SYSREG_PMSWINC_EL0 = 0xdce4,
	AArch64_SYSREG_PMUACR_EL1 = 0xc4f4,
	AArch64_SYSREG_PMUSERENR_EL0 = 0xdcf0,
	AArch64_SYSREG_PMXEVCNTR_EL0 = 0xdcea,
	AArch64_SYSREG_PMXEVTYPER_EL0 = 0xdce9,
	AArch64_SYSREG_PMZR_EL0 = 0xdcec,
	AArch64_SYSREG_POR_EL0 = 0xdd14,
	AArch64_SYSREG_POR_EL1 = 0xc514,
	AArch64_SYSREG_POR_EL12 = 0xed14,
	AArch64_SYSREG_POR_EL2 = 0xe514,
	AArch64_SYSREG_POR_EL3 = 0xf514,
	AArch64_SYSREG_PRBAR10_EL1 = 0xc368,
	AArch64_SYSREG_PRBAR10_EL2 = 0xe368,
	AArch64_SYSREG_PRBAR11_EL1 = 0xc36c,
	AArch64_SYSREG_PRBAR11_EL2 = 0xe36c,
	AArch64_SYSREG_PRBAR12_EL1 = 0xc370,
	AArch64_SYSREG_PRBAR12_EL2 = 0xe370,
	AArch64_SYSREG_PRBAR13_EL1 = 0xc374,
	AArch64_SYSREG_PRBAR13_EL2 = 0xe374,
	AArch64_SYSREG_PRBAR14_EL1 = 0xc378,
	AArch64_SYSREG_PRBAR14_EL2 = 0xe378,
	AArch64_SYSREG_PRBAR15_EL1 = 0xc37c,
	AArch64_SYSREG_PRBAR15_EL2 = 0xe37c,
	AArch64_SYSREG_PRBAR1_EL1 = 0xc344,
	AArch64_SYSREG_PRBAR1_EL2 = 0xe344,
	AArch64_SYSREG_PRBAR2_EL1 = 0xc348,
	AArch64_SYSREG_PRBAR2_EL2 = 0xe348,
	AArch64_SYSREG_PRBAR3_EL1 = 0xc34c,
	AArch64_SYSREG_PRBAR3_EL2 = 0xe34c,
	AArch64_SYSREG_PRBAR4_EL1 = 0xc350,
	AArch64_SYSREG_PRBAR4_EL2 = 0xe350,
	AArch64_SYSREG_PRBAR5_EL1 = 0xc354,
	AArch64_SYSREG_PRBAR5_EL2 = 0xe354,
	AArch64_SYSREG_PRBAR6_EL1 = 0xc358,
	AArch64_SYSREG_PRBAR6_EL2 = 0xe358,
	AArch64_SYSREG_PRBAR7_EL1 = 0xc35c,
	AArch64_SYSREG_PRBAR7_EL2 = 0xe35c,
	AArch64_SYSREG_PRBAR8_EL1 = 0xc360,
	AArch64_SYSREG_PRBAR8_EL2 = 0xe360,
	AArch64_SYSREG_PRBAR9_EL1 = 0xc364,
	AArch64_SYSREG_PRBAR9_EL2 = 0xe364,
	AArch64_SYSREG_PRBAR_EL1 = 0xc340,
	AArch64_SYSREG_PRBAR_EL2 = 0xe340,
	AArch64_SYSREG_PRENR_EL1 = 0xc309,
	AArch64_SYSREG_PRENR_EL2 = 0xe309,
	AArch64_SYSREG_PRLAR10_EL1 = 0xc369,
	AArch64_SYSREG_PRLAR10_EL2 = 0xe369,
	AArch64_SYSREG_PRLAR11_EL1 = 0xc36d,
	AArch64_SYSREG_PRLAR11_EL2 = 0xe36d,
	AArch64_SYSREG_PRLAR12_EL1 = 0xc371,
	AArch64_SYSREG_PRLAR12_EL2 = 0xe371,
	AArch64_SYSREG_PRLAR13_EL1 = 0xc375,
	AArch64_SYSREG_PRLAR13_EL2 = 0xe375,
	AArch64_SYSREG_PRLAR14_EL1 = 0xc379,
	AArch64_SYSREG_PRLAR14_EL2 = 0xe379,
	AArch64_SYSREG_PRLAR15_EL1 = 0xc37d,
	AArch64_SYSREG_PRLAR15_EL2 = 0xe37d,
	AArch64_SYSREG_PRLAR1_EL1 = 0xc345,
	AArch64_SYSREG_PRLAR1_EL2 = 0xe345,
	AArch64_SYSREG_PRLAR2_EL1 = 0xc349,
	AArch64_SYSREG_PRLAR2_EL2 = 0xe349,
	AArch64_SYSREG_PRLAR3_EL1 = 0xc34d,
	AArch64_SYSREG_PRLAR3_EL2 = 0xe34d,
	AArch64_SYSREG_PRLAR4_EL1 = 0xc351,
	AArch64_SYSREG_PRLAR4_EL2 = 0xe351,
	AArch64_SYSREG_PRLAR5_EL1 = 0xc355,
	AArch64_SYSREG_PRLAR5_EL2 = 0xe355,
	AArch64_SYSREG_PRLAR6_EL1 = 0xc359,
	AArch64_SYSREG_PRLAR6_EL2 = 0xe359,
	AArch64_SYSREG_PRLAR7_EL1 = 0xc35d,
	AArch64_SYSREG_PRLAR7_EL2 = 0xe35d,
	AArch64_SYSREG_PRLAR8_EL1 = 0xc361,
	AArch64_SYSREG_PRLAR8_EL2 = 0xe361,
	AArch64_SYSREG_PRLAR9_EL1 = 0xc365,
	AArch64_SYSREG_PRLAR9_EL2 = 0xe365,
	AArch64_SYSREG_PRLAR_EL1 = 0xc341,
	AArch64_SYSREG_PRLAR_EL2 = 0xe341,
	AArch64_SYSREG_PRSELR_EL1 = 0xc311,
	AArch64_SYSREG_PRSELR_EL2 = 0xe311,
	AArch64_SYSREG_RCWMASK_EL1 = 0xc686,
	AArch64_SYSREG_RCWSMASK_EL1 = 0xc683,
	AArch64_SYSREG_REVIDR_EL1 = 0xc006,
	AArch64_SYSREG_RGSR_EL1 = 0xc085,
	AArch64_SYSREG_RMR_EL1 = 0xc602,
	AArch64_SYSREG_RMR_EL2 = 0xe602,
	AArch64_SYSREG_RMR_EL3 = 0xf602,
	AArch64_SYSREG_RNDR = 0xd920,
	AArch64_SYSREG_RNDRRS = 0xd921,
	AArch64_SYSREG_RVBAR_EL1 = 0xc601,
	AArch64_SYSREG_RVBAR_EL2 = 0xe601,
	AArch64_SYSREG_RVBAR_EL3 = 0xf601,
	AArch64_SYSREG_S2PIR_EL2 = 0xe515,
	AArch64_SYSREG_S2POR_EL1 = 0xc515,
	AArch64_SYSREG_SCR_EL3 = 0xf088,
	AArch64_SYSREG_SCTLR2_EL1 = 0xc083,
	AArch64_SYSREG_SCTLR2_EL12 = 0xe883,
	AArch64_SYSREG_SCTLR2_EL2 = 0xe083,
	AArch64_SYSREG_SCTLR2_EL3 = 0xf083,
	AArch64_SYSREG_SCTLR_EL1 = 0xc080,
	AArch64_SYSREG_SCTLR_EL12 = 0xe880,
	AArch64_SYSREG_SCTLR_EL2 = 0xe080,
	AArch64_SYSREG_SCTLR_EL3 = 0xf080,
	AArch64_SYSREG_SCXTNUM_EL0 = 0xde87,
	AArch64_SYSREG_SCXTNUM_EL1 = 0xc687,
	AArch64_SYSREG_SCXTNUM_EL12 = 0xee87,
	AArch64_SYSREG_SCXTNUM_EL2 = 0xe687,
	AArch64_SYSREG_SCXTNUM_EL3 = 0xf687,
	AArch64_SYSREG_SDER32_EL2 = 0xe099,
	AArch64_SYSREG_SDER32_EL3 = 0xf089,
	AArch64_SYSREG_SMCR_EL1 = 0xc096,
	AArch64_SYSREG_SMCR_EL12 = 0xe896,
	AArch64_SYSREG_SMCR_EL2 = 0xe096,
	AArch64_SYSREG_SMCR_EL3 = 0xf096,
	AArch64_SYSREG_SMIDR_EL1 = 0xc806,
	AArch64_SYSREG_SMPRIMAP_EL2 = 0xe095,
	AArch64_SYSREG_SMPRI_EL1 = 0xc094,
	AArch64_SYSREG_SPMACCESSR_EL1 = 0x84eb,
	AArch64_SYSREG_SPMACCESSR_EL12 = 0xaceb,
	AArch64_SYSREG_SPMACCESSR_EL2 = 0xa4eb,
	AArch64_SYSREG_SPMACCESSR_EL3 = 0xb4eb,
	AArch64_SYSREG_SPMCFGR_EL1 = 0x84ef,
	AArch64_SYSREG_SPMCGCR0_EL1 = 0x84e8,
	AArch64_SYSREG_SPMCGCR1_EL1 = 0x84e9,
	AArch64_SYSREG_SPMCNTENCLR_EL0 = 0x9ce2,
	AArch64_SYSREG_SPMCNTENSET_EL0 = 0x9ce1,
	AArch64_SYSREG_SPMCR_EL0 = 0x9ce0,
	AArch64_SYSREG_SPMDEVAFF_EL1 = 0x84ee,
	AArch64_SYSREG_SPMDEVARCH_EL1 = 0x84ed,
	AArch64_SYSREG_SPMEVCNTR0_EL0 = 0x9f00,
	AArch64_SYSREG_SPMEVCNTR10_EL0 = 0x9f0a,
	AArch64_SYSREG_SPMEVCNTR11_EL0 = 0x9f0b,
	AArch64_SYSREG_SPMEVCNTR12_EL0 = 0x9f0c,
	AArch64_SYSREG_SPMEVCNTR13_EL0 = 0x9f0d,
	AArch64_SYSREG_SPMEVCNTR14_EL0 = 0x9f0e,
	AArch64_SYSREG_SPMEVCNTR15_EL0 = 0x9f0f,
	AArch64_SYSREG_SPMEVCNTR1_EL0 = 0x9f01,
	AArch64_SYSREG_SPMEVCNTR2_EL0 = 0x9f02,
	AArch64_SYSREG_SPMEVCNTR3_EL0 = 0x9f03,
	AArch64_SYSREG_SPMEVCNTR4_EL0 = 0x9f04,
	AArch64_SYSREG_SPMEVCNTR5_EL0 = 0x9f05,
	AArch64_SYSREG_SPMEVCNTR6_EL0 = 0x9f06,
	AArch64_SYSREG_SPMEVCNTR7_EL0 = 0x9f07,
	AArch64_SYSREG_SPMEVCNTR8_EL0 = 0x9f08,
	AArch64_SYSREG_SPMEVCNTR9_EL0 = 0x9f09,
	AArch64_SYSREG_SPMEVFILT2R0_EL0 = 0x9f30,
	AArch64_SYSREG_SPMEVFILT2R10_EL0 = 0x9f3a,
	AArch64_SYSREG_SPMEVFILT2R11_EL0 = 0x9f3b,
	AArch64_SYSREG_SPMEVFILT2R12_EL0 = 0x9f3c,
	AArch64_SYSREG_SPMEVFILT2R13_EL0 = 0x9f3d,
	AArch64_SYSREG_SPMEVFILT2R14_EL0 = 0x9f3e,
	AArch64_SYSREG_SPMEVFILT2R15_EL0 = 0x9f3f,
	AArch64_SYSREG_SPMEVFILT2R1_EL0 = 0x9f31,
	AArch64_SYSREG_SPMEVFILT2R2_EL0 = 0x9f32,
	AArch64_SYSREG_SPMEVFILT2R3_EL0 = 0x9f33,
	AArch64_SYSREG_SPMEVFILT2R4_EL0 = 0x9f34,
	AArch64_SYSREG_SPMEVFILT2R5_EL0 = 0x9f35,
	AArch64_SYSREG_SPMEVFILT2R6_EL0 = 0x9f36,
	AArch64_SYSREG_SPMEVFILT2R7_EL0 = 0x9f37,
	AArch64_SYSREG_SPMEVFILT2R8_EL0 = 0x9f38,
	AArch64_SYSREG_SPMEVFILT2R9_EL0 = 0x9f39,
	AArch64_SYSREG_SPMEVFILTR0_EL0 = 0x9f20,
	AArch64_SYSREG_SPMEVFILTR10_EL0 = 0x9f2a,
	AArch64_SYSREG_SPMEVFILTR11_EL0 = 0x9f2b,
	AArch64_SYSREG_SPMEVFILTR12_EL0 = 0x9f2c,
	AArch64_SYSREG_SPMEVFILTR13_EL0 = 0x9f2d,
	AArch64_SYSREG_SPMEVFILTR14_EL0 = 0x9f2e,
	AArch64_SYSREG_SPMEVFILTR15_EL0 = 0x9f2f,
	AArch64_SYSREG_SPMEVFILTR1_EL0 = 0x9f21,
	AArch64_SYSREG_SPMEVFILTR2_EL0 = 0x9f22,
	AArch64_SYSREG_SPMEVFILTR3_EL0 = 0x9f23,
	AArch64_SYSREG_SPMEVFILTR4_EL0 = 0x9f24,
	AArch64_SYSREG_SPMEVFILTR5_EL0 = 0x9f25,
	AArch64_SYSREG_SPMEVFILTR6_EL0 = 0x9f26,
	AArch64_SYSREG_SPMEVFILTR7_EL0 = 0x9f27,
	AArch64_SYSREG_SPMEVFILTR8_EL0 = 0x9f28,
	AArch64_SYSREG_SPMEVFILTR9_EL0 = 0x9f29,
	AArch64_SYSREG_SPMEVTYPER0_EL0 = 0x9f10,
	AArch64_SYSREG_SPMEVTYPER10_EL0 = 0x9f1a,
	AArch64_SYSREG_SPMEVTYPER11_EL0 = 0x9f1b,
	AArch64_SYSREG_SPMEVTYPER12_EL0 = 0x9f1c,
	AArch64_SYSREG_SPMEVTYPER13_EL0 = 0x9f1d,
	AArch64_SYSREG_SPMEVTYPER14_EL0 = 0x9f1e,
	AArch64_SYSREG_SPMEVTYPER15_EL0 = 0x9f1f,
	AArch64_SYSREG_SPMEVTYPER1_EL0 = 0x9f11,
	AArch64_SYSREG_SPMEVTYPER2_EL0 = 0x9f12,
	AArch64_SYSREG_SPMEVTYPER3_EL0 = 0x9f13,
	AArch64_SYSREG_SPMEVTYPER4_EL0 = 0x9f14,
	AArch64_SYSREG_SPMEVTYPER5_EL0 = 0x9f15,
	AArch64_SYSREG_SPMEVTYPER6_EL0 = 0x9f16,
	AArch64_SYSREG_SPMEVTYPER7_EL0 = 0x9f17,
	AArch64_SYSREG_SPMEVTYPER8_EL0 = 0x9f18,
	AArch64_SYSREG_SPMEVTYPER9_EL0 = 0x9f19,
	AArch64_SYSREG_SPMIIDR_EL1 = 0x84ec,
	AArch64_SYSREG_SPMINTENCLR_EL1 = 0x84f2,
	AArch64_SYSREG_SPMINTENSET_EL1 = 0x84f1,
	AArch64_SYSREG_SPMOVSCLR_EL0 = 0x9ce3,
	AArch64_SYSREG_SPMOVSSET_EL0 = 0x9cf3,
	AArch64_SYSREG_SPMROOTCR_EL3 = 0xb4f7,
	AArch64_SYSREG_SPMSCR_EL1 = 0xbcf7,
	AArch64_SYSREG_SPMSELR_EL0 = 0x9ce5,
	AArch64_SYSREG_SPSEL = 0xc210,
	AArch64_SYSREG_SPSR_ABT = 0xe219,
	AArch64_SYSREG_SPSR_EL1 = 0xc200,
	AArch64_SYSREG_SPSR_EL12 = 0xea00,
	AArch64_SYSREG_SPSR_EL2 = 0xe200,
	AArch64_SYSREG_SPSR_EL3 = 0xf200,
	AArch64_SYSREG_SPSR_FIQ = 0xe21b,
	AArch64_SYSREG_SPSR_IRQ = 0xe218,
	AArch64_SYSREG_SPSR_UND = 0xe21a,
	AArch64_SYSREG_SP_EL0 = 0xc208,
	AArch64_SYSREG_SP_EL1 = 0xe208,
	AArch64_SYSREG_SP_EL2 = 0xf208,
	AArch64_SYSREG_SSBS = 0xda16,
	AArch64_SYSREG_SVCR = 0xda12,
	AArch64_SYSREG_TCO = 0xda17,
	AArch64_SYSREG_TCR2_EL1 = 0xc103,
	AArch64_SYSREG_TCR2_EL12 = 0xe903,
	AArch64_SYSREG_TCR2_EL2 = 0xe103,
	AArch64_SYSREG_TCR_EL1 = 0xc102,
	AArch64_SYSREG_TCR_EL12 = 0xe902,
	AArch64_SYSREG_TCR_EL2 = 0xe102,
	AArch64_SYSREG_TCR_EL3 = 0xf102,
	AArch64_SYSREG_TEECR32_EL1 = 0x9000,
	AArch64_SYSREG_TEEHBR32_EL1 = 0x9080,
	AArch64_SYSREG_TFSRE0_EL1 = 0xc2b1,
	AArch64_SYSREG_TFSR_EL1 = 0xc2b0,
	AArch64_SYSREG_TFSR_EL12 = 0xeab0,
	AArch64_SYSREG_TFSR_EL2 = 0xe2b0,
	AArch64_SYSREG_TFSR_EL3 = 0xf2b0,
	AArch64_SYSREG_TPIDR2_EL0 = 0xde85,
	AArch64_SYSREG_TPIDRRO_EL0 = 0xde83,
	AArch64_SYSREG_TPIDR_EL0 = 0xde82,
	AArch64_SYSREG_TPIDR_EL1 = 0xc684,
	AArch64_SYSREG_TPIDR_EL2 = 0xe682,
	AArch64_SYSREG_TPIDR_EL3 = 0xf682,
	AArch64_SYSREG_TRBBASER_EL1 = 0xc4da,
	AArch64_SYSREG_TRBIDR_EL1 = 0xc4df,
	AArch64_SYSREG_TRBLIMITR_EL1 = 0xc4d8,
	AArch64_SYSREG_TRBMAR_EL1 = 0xc4dc,
	AArch64_SYSREG_TRBPTR_EL1 = 0xc4d9,
	AArch64_SYSREG_TRBSR_EL1 = 0xc4db,
	AArch64_SYSREG_TRBTRG_EL1 = 0xc4de,
	AArch64_SYSREG_TRCACATR0 = 0x8902,
	AArch64_SYSREG_TRCACATR1 = 0x8912,
	AArch64_SYSREG_TRCACATR10 = 0x8923,
	AArch64_SYSREG_TRCACATR11 = 0x8933,
	AArch64_SYSREG_TRCACATR12 = 0x8943,
	AArch64_SYSREG_TRCACATR13 = 0x8953,
	AArch64_SYSREG_TRCACATR14 = 0x8963,
	AArch64_SYSREG_TRCACATR15 = 0x8973,
	AArch64_SYSREG_TRCACATR2 = 0x8922,
	AArch64_SYSREG_TRCACATR3 = 0x8932,
	AArch64_SYSREG_TRCACATR4 = 0x8942,
	AArch64_SYSREG_TRCACATR5 = 0x8952,
	AArch64_SYSREG_TRCACATR6 = 0x8962,
	AArch64_SYSREG_TRCACATR7 = 0x8972,
	AArch64_SYSREG_TRCACATR8 = 0x8903,
	AArch64_SYSREG_TRCACATR9 = 0x8913,
	AArch64_SYSREG_TRCACVR0 = 0x8900,
	AArch64_SYSREG_TRCACVR1 = 0x8910,
	AArch64_SYSREG_TRCACVR10 = 0x8921,
	AArch64_SYSREG_TRCACVR11 = 0x8931,
	AArch64_SYSREG_TRCACVR12 = 0x8941,
	AArch64_SYSREG_TRCACVR13 = 0x8951,
	AArch64_SYSREG_TRCACVR14 = 0x8961,
	AArch64_SYSREG_TRCACVR15 = 0x8971,
	AArch64_SYSREG_TRCACVR2 = 0x8920,
	AArch64_SYSREG_TRCACVR3 = 0x8930,
	AArch64_SYSREG_TRCACVR4 = 0x8940,
	AArch64_SYSREG_TRCACVR5 = 0x8950,
	AArch64_SYSREG_TRCACVR6 = 0x8960,
	AArch64_SYSREG_TRCACVR7 = 0x8970,
	AArch64_SYSREG_TRCACVR8 = 0x8901,
	AArch64_SYSREG_TRCACVR9 = 0x8911,
	AArch64_SYSREG_TRCAUTHSTATUS = 0x8bf6,
	AArch64_SYSREG_TRCAUXCTLR = 0x8830,
	AArch64_SYSREG_TRCBBCTLR = 0x8878,
	AArch64_SYSREG_TRCCCCTLR = 0x8870,
	AArch64_SYSREG_TRCCIDCCTLR0 = 0x8982,
	AArch64_SYSREG_TRCCIDCCTLR1 = 0x898a,
	AArch64_SYSREG_TRCCIDCVR0 = 0x8980,
	AArch64_SYSREG_TRCCIDCVR1 = 0x8990,
	AArch64_SYSREG_TRCCIDCVR2 = 0x89a0,
	AArch64_SYSREG_TRCCIDCVR3 = 0x89b0,
	AArch64_SYSREG_TRCCIDCVR4 = 0x89c0,
	AArch64_SYSREG_TRCCIDCVR5 = 0x89d0,
	AArch64_SYSREG_TRCCIDCVR6 = 0x89e0,
	AArch64_SYSREG_TRCCIDCVR7 = 0x89f0,
	AArch64_SYSREG_TRCCIDR0 = 0x8be7,
	AArch64_SYSREG_TRCCIDR1 = 0x8bef,
	AArch64_SYSREG_TRCCIDR2 = 0x8bf7,
	AArch64_SYSREG_TRCCIDR3 = 0x8bff,
	AArch64_SYSREG_TRCCLAIMCLR = 0x8bce,
	AArch64_SYSREG_TRCCLAIMSET = 0x8bc6,
	AArch64_SYSREG_TRCCNTCTLR0 = 0x8825,
	AArch64_SYSREG_TRCCNTCTLR1 = 0x882d,
	AArch64_SYSREG_TRCCNTCTLR2 = 0x8835,
	AArch64_SYSREG_TRCCNTCTLR3 = 0x883d,
	AArch64_SYSREG_TRCCNTRLDVR0 = 0x8805,
	AArch64_SYSREG_TRCCNTRLDVR1 = 0x880d,
	AArch64_SYSREG_TRCCNTRLDVR2 = 0x8815,
	AArch64_SYSREG_TRCCNTRLDVR3 = 0x881d,
	AArch64_SYSREG_TRCCNTVR0 = 0x8845,
	AArch64_SYSREG_TRCCNTVR1 = 0x884d,
	AArch64_SYSREG_TRCCNTVR2 = 0x8855,
	AArch64_SYSREG_TRCCNTVR3 = 0x885d,
	AArch64_SYSREG_TRCCONFIGR = 0x8820,
	AArch64_SYSREG_TRCDEVAFF0 = 0x8bd6,
	AArch64_SYSREG_TRCDEVAFF1 = 0x8bde,
	AArch64_SYSREG_TRCDEVARCH = 0x8bfe,
	AArch64_SYSREG_TRCDEVID = 0x8b97,
	AArch64_SYSREG_TRCDEVTYPE = 0x8b9f,
	AArch64_SYSREG_TRCDVCMR0 = 0x8906,
	AArch64_SYSREG_TRCDVCMR1 = 0x8926,
	AArch64_SYSREG_TRCDVCMR2 = 0x8946,
	AArch64_SYSREG_TRCDVCMR3 = 0x8966,
	AArch64_SYSREG_TRCDVCMR4 = 0x8907,
	AArch64_SYSREG_TRCDVCMR5 = 0x8927,
	AArch64_SYSREG_TRCDVCMR6 = 0x8947,
	AArch64_SYSREG_TRCDVCMR7 = 0x8967,
	AArch64_SYSREG_TRCDVCVR0 = 0x8904,
	AArch64_SYSREG_TRCDVCVR1 = 0x8924,
	AArch64_SYSREG_TRCDVCVR2 = 0x8944,
	AArch64_SYSREG_TRCDVCVR3 = 0x8964,
	AArch64_SYSREG_TRCDVCVR4 = 0x8905,
	AArch64_SYSREG_TRCDVCVR5 = 0x8925,
	AArch64_SYSREG_TRCDVCVR6 = 0x8945,
	AArch64_SYSREG_TRCDVCVR7 = 0x8965,
	AArch64_SYSREG_TRCEVENTCTL0R = 0x8840,
	AArch64_SYSREG_TRCEVENTCTL1R = 0x8848,
	AArch64_SYSREG_TRCEXTINSELR = 0x8844,
	AArch64_SYSREG_TRCEXTINSELR0 = 0x8844,
	AArch64_SYSREG_TRCEXTINSELR1 = 0x884c,
	AArch64_SYSREG_TRCEXTINSELR2 = 0x8854,
	AArch64_SYSREG_TRCEXTINSELR3 = 0x885c,
	AArch64_SYSREG_TRCIDR0 = 0x8847,
	AArch64_SYSREG_TRCIDR1 = 0x884f,
	AArch64_SYSREG_TRCIDR10 = 0x8816,
	AArch64_SYSREG_TRCIDR11 = 0x881e,
	AArch64_SYSREG_TRCIDR12 = 0x8826,
	AArch64_SYSREG_TRCIDR13 = 0x882e,
	AArch64_SYSREG_TRCIDR2 = 0x8857,
	AArch64_SYSREG_TRCIDR3 = 0x885f,
	AArch64_SYSREG_TRCIDR4 = 0x8867,
	AArch64_SYSREG_TRCIDR5 = 0x886f,
	AArch64_SYSREG_TRCIDR6 = 0x8877,
	AArch64_SYSREG_TRCIDR7 = 0x887f,
	AArch64_SYSREG_TRCIDR8 = 0x8806,
	AArch64_SYSREG_TRCIDR9 = 0x880e,
	AArch64_SYSREG_TRCIMSPEC0 = 0x8807,
	AArch64_SYSREG_TRCIMSPEC1 = 0x880f,
	AArch64_SYSREG_TRCIMSPEC2 = 0x8817,
	AArch64_SYSREG_TRCIMSPEC3 = 0x881f,
	AArch64_SYSREG_TRCIMSPEC4 = 0x8827,
	AArch64_SYSREG_TRCIMSPEC5 = 0x882f,
	AArch64_SYSREG_TRCIMSPEC6 = 0x8837,
	AArch64_SYSREG_TRCIMSPEC7 = 0x883f,
	AArch64_SYSREG_TRCITCTRL = 0x8b84,
	AArch64_SYSREG_TRCITECR_EL1 = 0xc093,
	AArch64_SYSREG_TRCITECR_EL12 = 0xe893,
	AArch64_SYSREG_TRCITECR_EL2 = 0xe093,
	AArch64_SYSREG_TRCITEEDCR = 0x8811,
	AArch64_SYSREG_TRCLAR = 0x8be6,
	AArch64_SYSREG_TRCLSR = 0x8bee,
	AArch64_SYSREG_TRCOSLAR = 0x8884,
	AArch64_SYSREG_TRCOSLSR = 0x888c,
	AArch64_SYSREG_TRCPDCR = 0x88a4,
	AArch64_SYSREG_TRCPDSR = 0x88ac,
	AArch64_SYSREG_TRCPIDR0 = 0x8bc7,
	AArch64_SYSREG_TRCPIDR1 = 0x8bcf,
	AArch64_SYSREG_TRCPIDR2 = 0x8bd7,
	AArch64_SYSREG_TRCPIDR3 = 0x8bdf,
	AArch64_SYSREG_TRCPIDR4 = 0x8ba7,
	AArch64_SYSREG_TRCPIDR5 = 0x8baf,
	AArch64_SYSREG_TRCPIDR6 = 0x8bb7,
	AArch64_SYSREG_TRCPIDR7 = 0x8bbf,
	AArch64_SYSREG_TRCPRGCTLR = 0x8808,
	AArch64_SYSREG_TRCPROCSELR = 0x8810,
	AArch64_SYSREG_TRCQCTLR = 0x8809,
	AArch64_SYSREG_TRCRSCTLR10 = 0x88d0,
	AArch64_SYSREG_TRCRSCTLR11 = 0x88d8,
	AArch64_SYSREG_TRCRSCTLR12 = 0x88e0,
	AArch64_SYSREG_TRCRSCTLR13 = 0x88e8,
	AArch64_SYSREG_TRCRSCTLR14 = 0x88f0,
	AArch64_SYSREG_TRCRSCTLR15 = 0x88f8,
	AArch64_SYSREG_TRCRSCTLR16 = 0x8881,
	AArch64_SYSREG_TRCRSCTLR17 = 0x8889,
	AArch64_SYSREG_TRCRSCTLR18 = 0x8891,
	AArch64_SYSREG_TRCRSCTLR19 = 0x8899,
	AArch64_SYSREG_TRCRSCTLR2 = 0x8890,
	AArch64_SYSREG_TRCRSCTLR20 = 0x88a1,
	AArch64_SYSREG_TRCRSCTLR21 = 0x88a9,
	AArch64_SYSREG_TRCRSCTLR22 = 0x88b1,
	AArch64_SYSREG_TRCRSCTLR23 = 0x88b9,
	AArch64_SYSREG_TRCRSCTLR24 = 0x88c1,
	AArch64_SYSREG_TRCRSCTLR25 = 0x88c9,
	AArch64_SYSREG_TRCRSCTLR26 = 0x88d1,
	AArch64_SYSREG_TRCRSCTLR27 = 0x88d9,
	AArch64_SYSREG_TRCRSCTLR28 = 0x88e1,
	AArch64_SYSREG_TRCRSCTLR29 = 0x88e9,
	AArch64_SYSREG_TRCRSCTLR3 = 0x8898,
	AArch64_SYSREG_TRCRSCTLR30 = 0x88f1,
	AArch64_SYSREG_TRCRSCTLR31 = 0x88f9,
	AArch64_SYSREG_TRCRSCTLR4 = 0x88a0,
	AArch64_SYSREG_TRCRSCTLR5 = 0x88a8,
	AArch64_SYSREG_TRCRSCTLR6 = 0x88b0,
	AArch64_SYSREG_TRCRSCTLR7 = 0x88b8,
	AArch64_SYSREG_TRCRSCTLR8 = 0x88c0,
	AArch64_SYSREG_TRCRSCTLR9 = 0x88c8,
	AArch64_SYSREG_TRCRSR = 0x8850,
	AArch64_SYSREG_TRCSEQEVR0 = 0x8804,
	AArch64_SYSREG_TRCSEQEVR1 = 0x880c,
	AArch64_SYSREG_TRCSEQEVR2 = 0x8814,
	AArch64_SYSREG_TRCSEQRSTEVR = 0x8834,
	AArch64_SYSREG_TRCSEQSTR = 0x883c,
	AArch64_SYSREG_TRCSSCCR0 = 0x8882,
	AArch64_SYSREG_TRCSSCCR1 = 0x888a,
	AArch64_SYSREG_TRCSSCCR2 = 0x8892,
	AArch64_SYSREG_TRCSSCCR3 = 0x889a,
	AArch64_SYSREG_TRCSSCCR4 = 0x88a2,
	AArch64_SYSREG_TRCSSCCR5 = 0x88aa,
	AArch64_SYSREG_TRCSSCCR6 = 0x88b2,
	AArch64_SYSREG_TRCSSCCR7 = 0x88ba,
	AArch64_SYSREG_TRCSSCSR0 = 0x88c2,
	AArch64_SYSREG_TRCSSCSR1 = 0x88ca,
	AArch64_SYSREG_TRCSSCSR2 = 0x88d2,
	AArch64_SYSREG_TRCSSCSR3 = 0x88da,
	AArch64_SYSREG_TRCSSCSR4 = 0x88e2,
	AArch64_SYSREG_TRCSSCSR5 = 0x88ea,
	AArch64_SYSREG_TRCSSCSR6 = 0x88f2,
	AArch64_SYSREG_TRCSSCSR7 = 0x88fa,
	AArch64_SYSREG_TRCSSPCICR0 = 0x8883,
	AArch64_SYSREG_TRCSSPCICR1 = 0x888b,
	AArch64_SYSREG_TRCSSPCICR2 = 0x8893,
	AArch64_SYSREG_TRCSSPCICR3 = 0x889b,
	AArch64_SYSREG_TRCSSPCICR4 = 0x88a3,
	AArch64_SYSREG_TRCSSPCICR5 = 0x88ab,
	AArch64_SYSREG_TRCSSPCICR6 = 0x88b3,
	AArch64_SYSREG_TRCSSPCICR7 = 0x88bb,
	AArch64_SYSREG_TRCSTALLCTLR = 0x8858,
	AArch64_SYSREG_TRCSTATR = 0x8818,
	AArch64_SYSREG_TRCSYNCPR = 0x8868,
	AArch64_SYSREG_TRCTRACEIDR = 0x8801,
	AArch64_SYSREG_TRCTSCTLR = 0x8860,
	AArch64_SYSREG_TRCVDARCCTLR = 0x8852,
	AArch64_SYSREG_TRCVDCTLR = 0x8842,
	AArch64_SYSREG_TRCVDSACCTLR = 0x884a,
	AArch64_SYSREG_TRCVICTLR = 0x8802,
	AArch64_SYSREG_TRCVIIECTLR = 0x880a,
	AArch64_SYSREG_TRCVIPCSSCTLR = 0x881a,
	AArch64_SYSREG_TRCVISSCTLR = 0x8812,
	AArch64_SYSREG_TRCVMIDCCTLR0 = 0x8992,
	AArch64_SYSREG_TRCVMIDCCTLR1 = 0x899a,
	AArch64_SYSREG_TRCVMIDCVR0 = 0x8981,
	AArch64_SYSREG_TRCVMIDCVR1 = 0x8991,
	AArch64_SYSREG_TRCVMIDCVR2 = 0x89a1,
	AArch64_SYSREG_TRCVMIDCVR3 = 0x89b1,
	AArch64_SYSREG_TRCVMIDCVR4 = 0x89c1,
	AArch64_SYSREG_TRCVMIDCVR5 = 0x89d1,
	AArch64_SYSREG_TRCVMIDCVR6 = 0x89e1,
	AArch64_SYSREG_TRCVMIDCVR7 = 0x89f1,
	AArch64_SYSREG_TRFCR_EL1 = 0xc091,
	AArch64_SYSREG_TRFCR_EL12 = 0xe891,
	AArch64_SYSREG_TRFCR_EL2 = 0xe091,
	AArch64_SYSREG_TTBR0_EL1 = 0xc100,
	AArch64_SYSREG_TTBR0_EL12 = 0xe900,
	AArch64_SYSREG_TTBR0_EL2 = 0xe100,
	AArch64_SYSREG_VSCTLR_EL2 = 0xe100,
	AArch64_SYSREG_TTBR0_EL3 = 0xf100,
	AArch64_SYSREG_TTBR1_EL1 = 0xc101,
	AArch64_SYSREG_TTBR1_EL12 = 0xe901,
	AArch64_SYSREG_TTBR1_EL2 = 0xe101,
	AArch64_SYSREG_UAO = 0xc214,
	AArch64_SYSREG_VBAR_EL1 = 0xc600,
	AArch64_SYSREG_VBAR_EL12 = 0xee00,
	AArch64_SYSREG_VBAR_EL2 = 0xe600,
	AArch64_SYSREG_VBAR_EL3 = 0xf600,
	AArch64_SYSREG_VDISR_EL2 = 0xe609,
	AArch64_SYSREG_VMECID_A_EL2 = 0xe549,
	AArch64_SYSREG_VMECID_P_EL2 = 0xe548,
	AArch64_SYSREG_VMPIDR_EL2 = 0xe005,
	AArch64_SYSREG_VNCR_EL2 = 0xe110,
	AArch64_SYSREG_VPIDR_EL2 = 0xe000,
	AArch64_SYSREG_VSESR_EL2 = 0xe293,
	AArch64_SYSREG_VSTCR_EL2 = 0xe132,
	AArch64_SYSREG_VSTTBR_EL2 = 0xe130,
	AArch64_SYSREG_VTCR_EL2 = 0xe10a,
	AArch64_SYSREG_VTTBR_EL2 = 0xe108,
	AArch64_SYSREG_ZCR_EL1 = 0xc090,
	AArch64_SYSREG_ZCR_EL12 = 0xe890,
	AArch64_SYSREG_ZCR_EL2 = 0xe090,
	AArch64_SYSREG_ZCR_EL3 = 0xf090,

	// clang-format on
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_SysReg> end
	AArch64_SYSREG_ENDING = UINT16_MAX,
} aarch64_sysreg;

typedef enum {
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_TSB> begin
	// clang-format off

	AArch64_TSB_CSYNC = 0x0,

	// clang-format on
	// generated content <AArch64GenCSSystemOperandsEnum.inc:GET_ENUM_VALUES_TSB> end
	AArch64_TSB_ENDING,
} aarch64_tsb;

typedef union {
	aarch64_sysreg sysreg;
	aarch64_tlbi tlbi;
	aarch64_ic ic;
	uint64_t raw_val;
} aarch64_sysop_reg;

typedef union {
	aarch64_dbnxs dbnxs;
	aarch64_exactfpimm exactfpimm;
	uint64_t raw_val;
} aarch64_sysop_imm;

typedef union {
	aarch64_svcr svcr;
	aarch64_at at;
	aarch64_db db;
	aarch64_dc dc;
	aarch64_isb isb;
	aarch64_tsb tsb;
	aarch64_prfm prfm;
	aarch64_sveprfm sveprfm;
	aarch64_rprfm rprfm;
	aarch64_pstateimm0_15 pstateimm0_15;
	aarch64_pstateimm0_1 pstateimm0_1;
	aarch64_psb psb;
	aarch64_bti bti;
	aarch64_svepredpat svepredpat;
	aarch64_sveveclenspecifier sveveclenspecifier;
	uint64_t raw_val;
} aarch64_sysop_alias;

/// Operand type for instruction's operands
typedef enum aarch64_op_type {
  AArch64_OP_INVALID = CS_OP_INVALID, ///< = CS_OP_INVALID (Uninitialized).
  AArch64_OP_REG = CS_OP_REG,		///< = CS_OP_REG (Register operand).
  AArch64_OP_IMM = CS_OP_IMM,		///< = CS_OP_IMM (Immediate operand).
  AArch64_OP_MEM_REG = CS_OP_MEM_REG,		///< Register which references memory.
  AArch64_OP_MEM_IMM = CS_OP_MEM_IMM,		///< = Immediate value which references memory.
  AArch64_OP_MEM = CS_OP_MEM,		///< = CS_OP_MEM (Memory operand).
  AArch64_OP_FP = CS_OP_FP,		///< = CS_OP_FP (Floating-Point operand).
  AArch64_OP_CIMM = CS_OP_SPECIAL + 0,	///< C-Immediate
  AArch64_OP_REG_MRS = CS_OP_SPECIAL + 1,	///< MRS register operand.
  AArch64_OP_REG_MSR = CS_OP_SPECIAL + 2,	///< MSR register operand.
  AArch64_OP_IMPLICIT_IMM_0 = CS_OP_SPECIAL + 3, ///< Implicit immediate operand 0
	// Different system operands.
	AArch64_OP_SVCR = CS_OP_SPECIAL + 4,
	AArch64_OP_AT = CS_OP_SPECIAL + 5,
	AArch64_OP_DB = CS_OP_SPECIAL + 6,
	AArch64_OP_DC = CS_OP_SPECIAL + 7,
	AArch64_OP_ISB = CS_OP_SPECIAL + 8,
	AArch64_OP_TSB = CS_OP_SPECIAL + 9,
	AArch64_OP_PRFM = CS_OP_SPECIAL + 10,
	AArch64_OP_SVEPRFM = CS_OP_SPECIAL + 11,
	AArch64_OP_RPRFM = CS_OP_SPECIAL + 12,
	AArch64_OP_PSTATEIMM0_15 = CS_OP_SPECIAL + 13,
	AArch64_OP_PSTATEIMM0_1 = CS_OP_SPECIAL + 14,
	AArch64_OP_PSB = CS_OP_SPECIAL + 15,
	AArch64_OP_BTI = CS_OP_SPECIAL + 16,
	AArch64_OP_SVEPREDPAT = CS_OP_SPECIAL + 17,
	AArch64_OP_SVEVECLENSPECIFIER = CS_OP_SPECIAL + 18,
	AArch64_OP_SME_MATRIX = CS_OP_SPECIAL + 19,
	AArch64_OP_IMM_RANGE = CS_OP_SPECIAL + 20,
	AArch64_OP_TLBI = CS_OP_SPECIAL + 21,
	AArch64_OP_IC = CS_OP_SPECIAL + 22,
	AArch64_OP_DBNXS = CS_OP_SPECIAL + 23,
	AArch64_OP_EXACTFPIMM = CS_OP_SPECIAL + 24,
	AArch64_OP_SYSREG = CS_OP_SPECIAL + 25,
	AArch64_OP_SYSIMM = CS_OP_SPECIAL + 26,
	AArch64_OP_SYSALIAS = CS_OP_SPECIAL + 27,
} aarch64_op_type;

typedef struct {
	aarch64_sysop_reg reg;
	aarch64_sysop_imm imm;
	aarch64_sysop_alias alias;
	aarch64_op_type sub_type; ///< Specifies which field is set.
} aarch64_sysop;

/// AArch64 registers
typedef enum aarch64_reg {
	// generated content <AArch64GenCSRegEnum.inc> begin
	// clang-format off

	AArch64_REG_INVALID = 0,
	AArch64_REG_FFR = 1,
	AArch64_REG_FP = 2,
	AArch64_REG_FPCR = 3,
	AArch64_REG_LR = 4,
	AArch64_REG_NZCV = 5,
	AArch64_REG_SP = 6,
	AArch64_REG_VG = 7,
	AArch64_REG_WSP = 8,
	AArch64_REG_WZR = 9,
	AArch64_REG_XZR = 10,
	AArch64_REG_ZA = 11,
	AArch64_REG_B0 = 12,
	AArch64_REG_B1 = 13,
	AArch64_REG_B2 = 14,
	AArch64_REG_B3 = 15,
	AArch64_REG_B4 = 16,
	AArch64_REG_B5 = 17,
	AArch64_REG_B6 = 18,
	AArch64_REG_B7 = 19,
	AArch64_REG_B8 = 20,
	AArch64_REG_B9 = 21,
	AArch64_REG_B10 = 22,
	AArch64_REG_B11 = 23,
	AArch64_REG_B12 = 24,
	AArch64_REG_B13 = 25,
	AArch64_REG_B14 = 26,
	AArch64_REG_B15 = 27,
	AArch64_REG_B16 = 28,
	AArch64_REG_B17 = 29,
	AArch64_REG_B18 = 30,
	AArch64_REG_B19 = 31,
	AArch64_REG_B20 = 32,
	AArch64_REG_B21 = 33,
	AArch64_REG_B22 = 34,
	AArch64_REG_B23 = 35,
	AArch64_REG_B24 = 36,
	AArch64_REG_B25 = 37,
	AArch64_REG_B26 = 38,
	AArch64_REG_B27 = 39,
	AArch64_REG_B28 = 40,
	AArch64_REG_B29 = 41,
	AArch64_REG_B30 = 42,
	AArch64_REG_B31 = 43,
	AArch64_REG_D0 = 44,
	AArch64_REG_D1 = 45,
	AArch64_REG_D2 = 46,
	AArch64_REG_D3 = 47,
	AArch64_REG_D4 = 48,
	AArch64_REG_D5 = 49,
	AArch64_REG_D6 = 50,
	AArch64_REG_D7 = 51,
	AArch64_REG_D8 = 52,
	AArch64_REG_D9 = 53,
	AArch64_REG_D10 = 54,
	AArch64_REG_D11 = 55,
	AArch64_REG_D12 = 56,
	AArch64_REG_D13 = 57,
	AArch64_REG_D14 = 58,
	AArch64_REG_D15 = 59,
	AArch64_REG_D16 = 60,
	AArch64_REG_D17 = 61,
	AArch64_REG_D18 = 62,
	AArch64_REG_D19 = 63,
	AArch64_REG_D20 = 64,
	AArch64_REG_D21 = 65,
	AArch64_REG_D22 = 66,
	AArch64_REG_D23 = 67,
	AArch64_REG_D24 = 68,
	AArch64_REG_D25 = 69,
	AArch64_REG_D26 = 70,
	AArch64_REG_D27 = 71,
	AArch64_REG_D28 = 72,
	AArch64_REG_D29 = 73,
	AArch64_REG_D30 = 74,
	AArch64_REG_D31 = 75,
	AArch64_REG_H0 = 76,
	AArch64_REG_H1 = 77,
	AArch64_REG_H2 = 78,
	AArch64_REG_H3 = 79,
	AArch64_REG_H4 = 80,
	AArch64_REG_H5 = 81,
	AArch64_REG_H6 = 82,
	AArch64_REG_H7 = 83,
	AArch64_REG_H8 = 84,
	AArch64_REG_H9 = 85,
	AArch64_REG_H10 = 86,
	AArch64_REG_H11 = 87,
	AArch64_REG_H12 = 88,
	AArch64_REG_H13 = 89,
	AArch64_REG_H14 = 90,
	AArch64_REG_H15 = 91,
	AArch64_REG_H16 = 92,
	AArch64_REG_H17 = 93,
	AArch64_REG_H18 = 94,
	AArch64_REG_H19 = 95,
	AArch64_REG_H20 = 96,
	AArch64_REG_H21 = 97,
	AArch64_REG_H22 = 98,
	AArch64_REG_H23 = 99,
	AArch64_REG_H24 = 100,
	AArch64_REG_H25 = 101,
	AArch64_REG_H26 = 102,
	AArch64_REG_H27 = 103,
	AArch64_REG_H28 = 104,
	AArch64_REG_H29 = 105,
	AArch64_REG_H30 = 106,
	AArch64_REG_H31 = 107,
	AArch64_REG_P0 = 108,
	AArch64_REG_P1 = 109,
	AArch64_REG_P2 = 110,
	AArch64_REG_P3 = 111,
	AArch64_REG_P4 = 112,
	AArch64_REG_P5 = 113,
	AArch64_REG_P6 = 114,
	AArch64_REG_P7 = 115,
	AArch64_REG_P8 = 116,
	AArch64_REG_P9 = 117,
	AArch64_REG_P10 = 118,
	AArch64_REG_P11 = 119,
	AArch64_REG_P12 = 120,
	AArch64_REG_P13 = 121,
	AArch64_REG_P14 = 122,
	AArch64_REG_P15 = 123,
	AArch64_REG_Q0 = 124,
	AArch64_REG_Q1 = 125,
	AArch64_REG_Q2 = 126,
	AArch64_REG_Q3 = 127,
	AArch64_REG_Q4 = 128,
	AArch64_REG_Q5 = 129,
	AArch64_REG_Q6 = 130,
	AArch64_REG_Q7 = 131,
	AArch64_REG_Q8 = 132,
	AArch64_REG_Q9 = 133,
	AArch64_REG_Q10 = 134,
	AArch64_REG_Q11 = 135,
	AArch64_REG_Q12 = 136,
	AArch64_REG_Q13 = 137,
	AArch64_REG_Q14 = 138,
	AArch64_REG_Q15 = 139,
	AArch64_REG_Q16 = 140,
	AArch64_REG_Q17 = 141,
	AArch64_REG_Q18 = 142,
	AArch64_REG_Q19 = 143,
	AArch64_REG_Q20 = 144,
	AArch64_REG_Q21 = 145,
	AArch64_REG_Q22 = 146,
	AArch64_REG_Q23 = 147,
	AArch64_REG_Q24 = 148,
	AArch64_REG_Q25 = 149,
	AArch64_REG_Q26 = 150,
	AArch64_REG_Q27 = 151,
	AArch64_REG_Q28 = 152,
	AArch64_REG_Q29 = 153,
	AArch64_REG_Q30 = 154,
	AArch64_REG_Q31 = 155,
	AArch64_REG_S0 = 156,
	AArch64_REG_S1 = 157,
	AArch64_REG_S2 = 158,
	AArch64_REG_S3 = 159,
	AArch64_REG_S4 = 160,
	AArch64_REG_S5 = 161,
	AArch64_REG_S6 = 162,
	AArch64_REG_S7 = 163,
	AArch64_REG_S8 = 164,
	AArch64_REG_S9 = 165,
	AArch64_REG_S10 = 166,
	AArch64_REG_S11 = 167,
	AArch64_REG_S12 = 168,
	AArch64_REG_S13 = 169,
	AArch64_REG_S14 = 170,
	AArch64_REG_S15 = 171,
	AArch64_REG_S16 = 172,
	AArch64_REG_S17 = 173,
	AArch64_REG_S18 = 174,
	AArch64_REG_S19 = 175,
	AArch64_REG_S20 = 176,
	AArch64_REG_S21 = 177,
	AArch64_REG_S22 = 178,
	AArch64_REG_S23 = 179,
	AArch64_REG_S24 = 180,
	AArch64_REG_S25 = 181,
	AArch64_REG_S26 = 182,
	AArch64_REG_S27 = 183,
	AArch64_REG_S28 = 184,
	AArch64_REG_S29 = 185,
	AArch64_REG_S30 = 186,
	AArch64_REG_S31 = 187,
	AArch64_REG_W0 = 188,
	AArch64_REG_W1 = 189,
	AArch64_REG_W2 = 190,
	AArch64_REG_W3 = 191,
	AArch64_REG_W4 = 192,
	AArch64_REG_W5 = 193,
	AArch64_REG_W6 = 194,
	AArch64_REG_W7 = 195,
	AArch64_REG_W8 = 196,
	AArch64_REG_W9 = 197,
	AArch64_REG_W10 = 198,
	AArch64_REG_W11 = 199,
	AArch64_REG_W12 = 200,
	AArch64_REG_W13 = 201,
	AArch64_REG_W14 = 202,
	AArch64_REG_W15 = 203,
	AArch64_REG_W16 = 204,
	AArch64_REG_W17 = 205,
	AArch64_REG_W18 = 206,
	AArch64_REG_W19 = 207,
	AArch64_REG_W20 = 208,
	AArch64_REG_W21 = 209,
	AArch64_REG_W22 = 210,
	AArch64_REG_W23 = 211,
	AArch64_REG_W24 = 212,
	AArch64_REG_W25 = 213,
	AArch64_REG_W26 = 214,
	AArch64_REG_W27 = 215,
	AArch64_REG_W28 = 216,
	AArch64_REG_W29 = 217,
	AArch64_REG_W30 = 218,
	AArch64_REG_X0 = 219,
	AArch64_REG_X1 = 220,
	AArch64_REG_X2 = 221,
	AArch64_REG_X3 = 222,
	AArch64_REG_X4 = 223,
	AArch64_REG_X5 = 224,
	AArch64_REG_X6 = 225,
	AArch64_REG_X7 = 226,
	AArch64_REG_X8 = 227,
	AArch64_REG_X9 = 228,
	AArch64_REG_X10 = 229,
	AArch64_REG_X11 = 230,
	AArch64_REG_X12 = 231,
	AArch64_REG_X13 = 232,
	AArch64_REG_X14 = 233,
	AArch64_REG_X15 = 234,
	AArch64_REG_X16 = 235,
	AArch64_REG_X17 = 236,
	AArch64_REG_X18 = 237,
	AArch64_REG_X19 = 238,
	AArch64_REG_X20 = 239,
	AArch64_REG_X21 = 240,
	AArch64_REG_X22 = 241,
	AArch64_REG_X23 = 242,
	AArch64_REG_X24 = 243,
	AArch64_REG_X25 = 244,
	AArch64_REG_X26 = 245,
	AArch64_REG_X27 = 246,
	AArch64_REG_X28 = 247,
	AArch64_REG_Z0 = 248,
	AArch64_REG_Z1 = 249,
	AArch64_REG_Z2 = 250,
	AArch64_REG_Z3 = 251,
	AArch64_REG_Z4 = 252,
	AArch64_REG_Z5 = 253,
	AArch64_REG_Z6 = 254,
	AArch64_REG_Z7 = 255,
	AArch64_REG_Z8 = 256,
	AArch64_REG_Z9 = 257,
	AArch64_REG_Z10 = 258,
	AArch64_REG_Z11 = 259,
	AArch64_REG_Z12 = 260,
	AArch64_REG_Z13 = 261,
	AArch64_REG_Z14 = 262,
	AArch64_REG_Z15 = 263,
	AArch64_REG_Z16 = 264,
	AArch64_REG_Z17 = 265,
	AArch64_REG_Z18 = 266,
	AArch64_REG_Z19 = 267,
	AArch64_REG_Z20 = 268,
	AArch64_REG_Z21 = 269,
	AArch64_REG_Z22 = 270,
	AArch64_REG_Z23 = 271,
	AArch64_REG_Z24 = 272,
	AArch64_REG_Z25 = 273,
	AArch64_REG_Z26 = 274,
	AArch64_REG_Z27 = 275,
	AArch64_REG_Z28 = 276,
	AArch64_REG_Z29 = 277,
	AArch64_REG_Z30 = 278,
	AArch64_REG_Z31 = 279,
	AArch64_REG_ZAB0 = 280,
	AArch64_REG_ZAD0 = 281,
	AArch64_REG_ZAD1 = 282,
	AArch64_REG_ZAD2 = 283,
	AArch64_REG_ZAD3 = 284,
	AArch64_REG_ZAD4 = 285,
	AArch64_REG_ZAD5 = 286,
	AArch64_REG_ZAD6 = 287,
	AArch64_REG_ZAD7 = 288,
	AArch64_REG_ZAH0 = 289,
	AArch64_REG_ZAH1 = 290,
	AArch64_REG_ZAQ0 = 291,
	AArch64_REG_ZAQ1 = 292,
	AArch64_REG_ZAQ2 = 293,
	AArch64_REG_ZAQ3 = 294,
	AArch64_REG_ZAQ4 = 295,
	AArch64_REG_ZAQ5 = 296,
	AArch64_REG_ZAQ6 = 297,
	AArch64_REG_ZAQ7 = 298,
	AArch64_REG_ZAQ8 = 299,
	AArch64_REG_ZAQ9 = 300,
	AArch64_REG_ZAQ10 = 301,
	AArch64_REG_ZAQ11 = 302,
	AArch64_REG_ZAQ12 = 303,
	AArch64_REG_ZAQ13 = 304,
	AArch64_REG_ZAQ14 = 305,
	AArch64_REG_ZAQ15 = 306,
	AArch64_REG_ZAS0 = 307,
	AArch64_REG_ZAS1 = 308,
	AArch64_REG_ZAS2 = 309,
	AArch64_REG_ZAS3 = 310,
	AArch64_REG_ZT0 = 311,
	AArch64_REG_Z0_HI = 312,
	AArch64_REG_Z1_HI = 313,
	AArch64_REG_Z2_HI = 314,
	AArch64_REG_Z3_HI = 315,
	AArch64_REG_Z4_HI = 316,
	AArch64_REG_Z5_HI = 317,
	AArch64_REG_Z6_HI = 318,
	AArch64_REG_Z7_HI = 319,
	AArch64_REG_Z8_HI = 320,
	AArch64_REG_Z9_HI = 321,
	AArch64_REG_Z10_HI = 322,
	AArch64_REG_Z11_HI = 323,
	AArch64_REG_Z12_HI = 324,
	AArch64_REG_Z13_HI = 325,
	AArch64_REG_Z14_HI = 326,
	AArch64_REG_Z15_HI = 327,
	AArch64_REG_Z16_HI = 328,
	AArch64_REG_Z17_HI = 329,
	AArch64_REG_Z18_HI = 330,
	AArch64_REG_Z19_HI = 331,
	AArch64_REG_Z20_HI = 332,
	AArch64_REG_Z21_HI = 333,
	AArch64_REG_Z22_HI = 334,
	AArch64_REG_Z23_HI = 335,
	AArch64_REG_Z24_HI = 336,
	AArch64_REG_Z25_HI = 337,
	AArch64_REG_Z26_HI = 338,
	AArch64_REG_Z27_HI = 339,
	AArch64_REG_Z28_HI = 340,
	AArch64_REG_Z29_HI = 341,
	AArch64_REG_Z30_HI = 342,
	AArch64_REG_Z31_HI = 343,
	AArch64_REG_D0_D1 = 344,
	AArch64_REG_D1_D2 = 345,
	AArch64_REG_D2_D3 = 346,
	AArch64_REG_D3_D4 = 347,
	AArch64_REG_D4_D5 = 348,
	AArch64_REG_D5_D6 = 349,
	AArch64_REG_D6_D7 = 350,
	AArch64_REG_D7_D8 = 351,
	AArch64_REG_D8_D9 = 352,
	AArch64_REG_D9_D10 = 353,
	AArch64_REG_D10_D11 = 354,
	AArch64_REG_D11_D12 = 355,
	AArch64_REG_D12_D13 = 356,
	AArch64_REG_D13_D14 = 357,
	AArch64_REG_D14_D15 = 358,
	AArch64_REG_D15_D16 = 359,
	AArch64_REG_D16_D17 = 360,
	AArch64_REG_D17_D18 = 361,
	AArch64_REG_D18_D19 = 362,
	AArch64_REG_D19_D20 = 363,
	AArch64_REG_D20_D21 = 364,
	AArch64_REG_D21_D22 = 365,
	AArch64_REG_D22_D23 = 366,
	AArch64_REG_D23_D24 = 367,
	AArch64_REG_D24_D25 = 368,
	AArch64_REG_D25_D26 = 369,
	AArch64_REG_D26_D27 = 370,
	AArch64_REG_D27_D28 = 371,
	AArch64_REG_D28_D29 = 372,
	AArch64_REG_D29_D30 = 373,
	AArch64_REG_D30_D31 = 374,
	AArch64_REG_D31_D0 = 375,
	AArch64_REG_D0_D1_D2_D3 = 376,
	AArch64_REG_D1_D2_D3_D4 = 377,
	AArch64_REG_D2_D3_D4_D5 = 378,
	AArch64_REG_D3_D4_D5_D6 = 379,
	AArch64_REG_D4_D5_D6_D7 = 380,
	AArch64_REG_D5_D6_D7_D8 = 381,
	AArch64_REG_D6_D7_D8_D9 = 382,
	AArch64_REG_D7_D8_D9_D10 = 383,
	AArch64_REG_D8_D9_D10_D11 = 384,
	AArch64_REG_D9_D10_D11_D12 = 385,
	AArch64_REG_D10_D11_D12_D13 = 386,
	AArch64_REG_D11_D12_D13_D14 = 387,
	AArch64_REG_D12_D13_D14_D15 = 388,
	AArch64_REG_D13_D14_D15_D16 = 389,
	AArch64_REG_D14_D15_D16_D17 = 390,
	AArch64_REG_D15_D16_D17_D18 = 391,
	AArch64_REG_D16_D17_D18_D19 = 392,
	AArch64_REG_D17_D18_D19_D20 = 393,
	AArch64_REG_D18_D19_D20_D21 = 394,
	AArch64_REG_D19_D20_D21_D22 = 395,
	AArch64_REG_D20_D21_D22_D23 = 396,
	AArch64_REG_D21_D22_D23_D24 = 397,
	AArch64_REG_D22_D23_D24_D25 = 398,
	AArch64_REG_D23_D24_D25_D26 = 399,
	AArch64_REG_D24_D25_D26_D27 = 400,
	AArch64_REG_D25_D26_D27_D28 = 401,
	AArch64_REG_D26_D27_D28_D29 = 402,
	AArch64_REG_D27_D28_D29_D30 = 403,
	AArch64_REG_D28_D29_D30_D31 = 404,
	AArch64_REG_D29_D30_D31_D0 = 405,
	AArch64_REG_D30_D31_D0_D1 = 406,
	AArch64_REG_D31_D0_D1_D2 = 407,
	AArch64_REG_D0_D1_D2 = 408,
	AArch64_REG_D1_D2_D3 = 409,
	AArch64_REG_D2_D3_D4 = 410,
	AArch64_REG_D3_D4_D5 = 411,
	AArch64_REG_D4_D5_D6 = 412,
	AArch64_REG_D5_D6_D7 = 413,
	AArch64_REG_D6_D7_D8 = 414,
	AArch64_REG_D7_D8_D9 = 415,
	AArch64_REG_D8_D9_D10 = 416,
	AArch64_REG_D9_D10_D11 = 417,
	AArch64_REG_D10_D11_D12 = 418,
	AArch64_REG_D11_D12_D13 = 419,
	AArch64_REG_D12_D13_D14 = 420,
	AArch64_REG_D13_D14_D15 = 421,
	AArch64_REG_D14_D15_D16 = 422,
	AArch64_REG_D15_D16_D17 = 423,
	AArch64_REG_D16_D17_D18 = 424,
	AArch64_REG_D17_D18_D19 = 425,
	AArch64_REG_D18_D19_D20 = 426,
	AArch64_REG_D19_D20_D21 = 427,
	AArch64_REG_D20_D21_D22 = 428,
	AArch64_REG_D21_D22_D23 = 429,
	AArch64_REG_D22_D23_D24 = 430,
	AArch64_REG_D23_D24_D25 = 431,
	AArch64_REG_D24_D25_D26 = 432,
	AArch64_REG_D25_D26_D27 = 433,
	AArch64_REG_D26_D27_D28 = 434,
	AArch64_REG_D27_D28_D29 = 435,
	AArch64_REG_D28_D29_D30 = 436,
	AArch64_REG_D29_D30_D31 = 437,
	AArch64_REG_D30_D31_D0 = 438,
	AArch64_REG_D31_D0_D1 = 439,
	AArch64_REG_P0_P1 = 440,
	AArch64_REG_P1_P2 = 441,
	AArch64_REG_P2_P3 = 442,
	AArch64_REG_P3_P4 = 443,
	AArch64_REG_P4_P5 = 444,
	AArch64_REG_P5_P6 = 445,
	AArch64_REG_P6_P7 = 446,
	AArch64_REG_P7_P8 = 447,
	AArch64_REG_P8_P9 = 448,
	AArch64_REG_P9_P10 = 449,
	AArch64_REG_P10_P11 = 450,
	AArch64_REG_P11_P12 = 451,
	AArch64_REG_P12_P13 = 452,
	AArch64_REG_P13_P14 = 453,
	AArch64_REG_P14_P15 = 454,
	AArch64_REG_P15_P0 = 455,
	AArch64_REG_Q0_Q1 = 456,
	AArch64_REG_Q1_Q2 = 457,
	AArch64_REG_Q2_Q3 = 458,
	AArch64_REG_Q3_Q4 = 459,
	AArch64_REG_Q4_Q5 = 460,
	AArch64_REG_Q5_Q6 = 461,
	AArch64_REG_Q6_Q7 = 462,
	AArch64_REG_Q7_Q8 = 463,
	AArch64_REG_Q8_Q9 = 464,
	AArch64_REG_Q9_Q10 = 465,
	AArch64_REG_Q10_Q11 = 466,
	AArch64_REG_Q11_Q12 = 467,
	AArch64_REG_Q12_Q13 = 468,
	AArch64_REG_Q13_Q14 = 469,
	AArch64_REG_Q14_Q15 = 470,
	AArch64_REG_Q15_Q16 = 471,
	AArch64_REG_Q16_Q17 = 472,
	AArch64_REG_Q17_Q18 = 473,
	AArch64_REG_Q18_Q19 = 474,
	AArch64_REG_Q19_Q20 = 475,
	AArch64_REG_Q20_Q21 = 476,
	AArch64_REG_Q21_Q22 = 477,
	AArch64_REG_Q22_Q23 = 478,
	AArch64_REG_Q23_Q24 = 479,
	AArch64_REG_Q24_Q25 = 480,
	AArch64_REG_Q25_Q26 = 481,
	AArch64_REG_Q26_Q27 = 482,
	AArch64_REG_Q27_Q28 = 483,
	AArch64_REG_Q28_Q29 = 484,
	AArch64_REG_Q29_Q30 = 485,
	AArch64_REG_Q30_Q31 = 486,
	AArch64_REG_Q31_Q0 = 487,
	AArch64_REG_Q0_Q1_Q2_Q3 = 488,
	AArch64_REG_Q1_Q2_Q3_Q4 = 489,
	AArch64_REG_Q2_Q3_Q4_Q5 = 490,
	AArch64_REG_Q3_Q4_Q5_Q6 = 491,
	AArch64_REG_Q4_Q5_Q6_Q7 = 492,
	AArch64_REG_Q5_Q6_Q7_Q8 = 493,
	AArch64_REG_Q6_Q7_Q8_Q9 = 494,
	AArch64_REG_Q7_Q8_Q9_Q10 = 495,
	AArch64_REG_Q8_Q9_Q10_Q11 = 496,
	AArch64_REG_Q9_Q10_Q11_Q12 = 497,
	AArch64_REG_Q10_Q11_Q12_Q13 = 498,
	AArch64_REG_Q11_Q12_Q13_Q14 = 499,
	AArch64_REG_Q12_Q13_Q14_Q15 = 500,
	AArch64_REG_Q13_Q14_Q15_Q16 = 501,
	AArch64_REG_Q14_Q15_Q16_Q17 = 502,
	AArch64_REG_Q15_Q16_Q17_Q18 = 503,
	AArch64_REG_Q16_Q17_Q18_Q19 = 504,
	AArch64_REG_Q17_Q18_Q19_Q20 = 505,
	AArch64_REG_Q18_Q19_Q20_Q21 = 506,
	AArch64_REG_Q19_Q20_Q21_Q22 = 507,
	AArch64_REG_Q20_Q21_Q22_Q23 = 508,
	AArch64_REG_Q21_Q22_Q23_Q24 = 509,
	AArch64_REG_Q22_Q23_Q24_Q25 = 510,
	AArch64_REG_Q23_Q24_Q25_Q26 = 511,
	AArch64_REG_Q24_Q25_Q26_Q27 = 512,
	AArch64_REG_Q25_Q26_Q27_Q28 = 513,
	AArch64_REG_Q26_Q27_Q28_Q29 = 514,
	AArch64_REG_Q27_Q28_Q29_Q30 = 515,
	AArch64_REG_Q28_Q29_Q30_Q31 = 516,
	AArch64_REG_Q29_Q30_Q31_Q0 = 517,
	AArch64_REG_Q30_Q31_Q0_Q1 = 518,
	AArch64_REG_Q31_Q0_Q1_Q2 = 519,
	AArch64_REG_Q0_Q1_Q2 = 520,
	AArch64_REG_Q1_Q2_Q3 = 521,
	AArch64_REG_Q2_Q3_Q4 = 522,
	AArch64_REG_Q3_Q4_Q5 = 523,
	AArch64_REG_Q4_Q5_Q6 = 524,
	AArch64_REG_Q5_Q6_Q7 = 525,
	AArch64_REG_Q6_Q7_Q8 = 526,
	AArch64_REG_Q7_Q8_Q9 = 527,
	AArch64_REG_Q8_Q9_Q10 = 528,
	AArch64_REG_Q9_Q10_Q11 = 529,
	AArch64_REG_Q10_Q11_Q12 = 530,
	AArch64_REG_Q11_Q12_Q13 = 531,
	AArch64_REG_Q12_Q13_Q14 = 532,
	AArch64_REG_Q13_Q14_Q15 = 533,
	AArch64_REG_Q14_Q15_Q16 = 534,
	AArch64_REG_Q15_Q16_Q17 = 535,
	AArch64_REG_Q16_Q17_Q18 = 536,
	AArch64_REG_Q17_Q18_Q19 = 537,
	AArch64_REG_Q18_Q19_Q20 = 538,
	AArch64_REG_Q19_Q20_Q21 = 539,
	AArch64_REG_Q20_Q21_Q22 = 540,
	AArch64_REG_Q21_Q22_Q23 = 541,
	AArch64_REG_Q22_Q23_Q24 = 542,
	AArch64_REG_Q23_Q24_Q25 = 543,
	AArch64_REG_Q24_Q25_Q26 = 544,
	AArch64_REG_Q25_Q26_Q27 = 545,
	AArch64_REG_Q26_Q27_Q28 = 546,
	AArch64_REG_Q27_Q28_Q29 = 547,
	AArch64_REG_Q28_Q29_Q30 = 548,
	AArch64_REG_Q29_Q30_Q31 = 549,
	AArch64_REG_Q30_Q31_Q0 = 550,
	AArch64_REG_Q31_Q0_Q1 = 551,
	AArch64_REG_X22_X23_X24_X25_X26_X27_X28_FP = 552,
	AArch64_REG_X0_X1_X2_X3_X4_X5_X6_X7 = 553,
	AArch64_REG_X2_X3_X4_X5_X6_X7_X8_X9 = 554,
	AArch64_REG_X4_X5_X6_X7_X8_X9_X10_X11 = 555,
	AArch64_REG_X6_X7_X8_X9_X10_X11_X12_X13 = 556,
	AArch64_REG_X8_X9_X10_X11_X12_X13_X14_X15 = 557,
	AArch64_REG_X10_X11_X12_X13_X14_X15_X16_X17 = 558,
	AArch64_REG_X12_X13_X14_X15_X16_X17_X18_X19 = 559,
	AArch64_REG_X14_X15_X16_X17_X18_X19_X20_X21 = 560,
	AArch64_REG_X16_X17_X18_X19_X20_X21_X22_X23 = 561,
	AArch64_REG_X18_X19_X20_X21_X22_X23_X24_X25 = 562,
	AArch64_REG_X20_X21_X22_X23_X24_X25_X26_X27 = 563,
	AArch64_REG_W30_WZR = 564,
	AArch64_REG_W0_W1 = 565,
	AArch64_REG_W2_W3 = 566,
	AArch64_REG_W4_W5 = 567,
	AArch64_REG_W6_W7 = 568,
	AArch64_REG_W8_W9 = 569,
	AArch64_REG_W10_W11 = 570,
	AArch64_REG_W12_W13 = 571,
	AArch64_REG_W14_W15 = 572,
	AArch64_REG_W16_W17 = 573,
	AArch64_REG_W18_W19 = 574,
	AArch64_REG_W20_W21 = 575,
	AArch64_REG_W22_W23 = 576,
	AArch64_REG_W24_W25 = 577,
	AArch64_REG_W26_W27 = 578,
	AArch64_REG_W28_W29 = 579,
	AArch64_REG_LR_XZR = 580,
	AArch64_REG_X28_FP = 581,
	AArch64_REG_X0_X1 = 582,
	AArch64_REG_X2_X3 = 583,
	AArch64_REG_X4_X5 = 584,
	AArch64_REG_X6_X7 = 585,
	AArch64_REG_X8_X9 = 586,
	AArch64_REG_X10_X11 = 587,
	AArch64_REG_X12_X13 = 588,
	AArch64_REG_X14_X15 = 589,
	AArch64_REG_X16_X17 = 590,
	AArch64_REG_X18_X19 = 591,
	AArch64_REG_X20_X21 = 592,
	AArch64_REG_X22_X23 = 593,
	AArch64_REG_X24_X25 = 594,
	AArch64_REG_X26_X27 = 595,
	AArch64_REG_Z0_Z1 = 596,
	AArch64_REG_Z1_Z2 = 597,
	AArch64_REG_Z2_Z3 = 598,
	AArch64_REG_Z3_Z4 = 599,
	AArch64_REG_Z4_Z5 = 600,
	AArch64_REG_Z5_Z6 = 601,
	AArch64_REG_Z6_Z7 = 602,
	AArch64_REG_Z7_Z8 = 603,
	AArch64_REG_Z8_Z9 = 604,
	AArch64_REG_Z9_Z10 = 605,
	AArch64_REG_Z10_Z11 = 606,
	AArch64_REG_Z11_Z12 = 607,
	AArch64_REG_Z12_Z13 = 608,
	AArch64_REG_Z13_Z14 = 609,
	AArch64_REG_Z14_Z15 = 610,
	AArch64_REG_Z15_Z16 = 611,
	AArch64_REG_Z16_Z17 = 612,
	AArch64_REG_Z17_Z18 = 613,
	AArch64_REG_Z18_Z19 = 614,
	AArch64_REG_Z19_Z20 = 615,
	AArch64_REG_Z20_Z21 = 616,
	AArch64_REG_Z21_Z22 = 617,
	AArch64_REG_Z22_Z23 = 618,
	AArch64_REG_Z23_Z24 = 619,
	AArch64_REG_Z24_Z25 = 620,
	AArch64_REG_Z25_Z26 = 621,
	AArch64_REG_Z26_Z27 = 622,
	AArch64_REG_Z27_Z28 = 623,
	AArch64_REG_Z28_Z29 = 624,
	AArch64_REG_Z29_Z30 = 625,
	AArch64_REG_Z30_Z31 = 626,
	AArch64_REG_Z31_Z0 = 627,
	AArch64_REG_Z0_Z1_Z2_Z3 = 628,
	AArch64_REG_Z1_Z2_Z3_Z4 = 629,
	AArch64_REG_Z2_Z3_Z4_Z5 = 630,
	AArch64_REG_Z3_Z4_Z5_Z6 = 631,
	AArch64_REG_Z4_Z5_Z6_Z7 = 632,
	AArch64_REG_Z5_Z6_Z7_Z8 = 633,
	AArch64_REG_Z6_Z7_Z8_Z9 = 634,
	AArch64_REG_Z7_Z8_Z9_Z10 = 635,
	AArch64_REG_Z8_Z9_Z10_Z11 = 636,
	AArch64_REG_Z9_Z10_Z11_Z12 = 637,
	AArch64_REG_Z10_Z11_Z12_Z13 = 638,
	AArch64_REG_Z11_Z12_Z13_Z14 = 639,
	AArch64_REG_Z12_Z13_Z14_Z15 = 640,
	AArch64_REG_Z13_Z14_Z15_Z16 = 641,
	AArch64_REG_Z14_Z15_Z16_Z17 = 642,
	AArch64_REG_Z15_Z16_Z17_Z18 = 643,
	AArch64_REG_Z16_Z17_Z18_Z19 = 644,
	AArch64_REG_Z17_Z18_Z19_Z20 = 645,
	AArch64_REG_Z18_Z19_Z20_Z21 = 646,
	AArch64_REG_Z19_Z20_Z21_Z22 = 647,
	AArch64_REG_Z20_Z21_Z22_Z23 = 648,
	AArch64_REG_Z21_Z22_Z23_Z24 = 649,
	AArch64_REG_Z22_Z23_Z24_Z25 = 650,
	AArch64_REG_Z23_Z24_Z25_Z26 = 651,
	AArch64_REG_Z24_Z25_Z26_Z27 = 652,
	AArch64_REG_Z25_Z26_Z27_Z28 = 653,
	AArch64_REG_Z26_Z27_Z28_Z29 = 654,
	AArch64_REG_Z27_Z28_Z29_Z30 = 655,
	AArch64_REG_Z28_Z29_Z30_Z31 = 656,
	AArch64_REG_Z29_Z30_Z31_Z0 = 657,
	AArch64_REG_Z30_Z31_Z0_Z1 = 658,
	AArch64_REG_Z31_Z0_Z1_Z2 = 659,
	AArch64_REG_Z0_Z1_Z2 = 660,
	AArch64_REG_Z1_Z2_Z3 = 661,
	AArch64_REG_Z2_Z3_Z4 = 662,
	AArch64_REG_Z3_Z4_Z5 = 663,
	AArch64_REG_Z4_Z5_Z6 = 664,
	AArch64_REG_Z5_Z6_Z7 = 665,
	AArch64_REG_Z6_Z7_Z8 = 666,
	AArch64_REG_Z7_Z8_Z9 = 667,
	AArch64_REG_Z8_Z9_Z10 = 668,
	AArch64_REG_Z9_Z10_Z11 = 669,
	AArch64_REG_Z10_Z11_Z12 = 670,
	AArch64_REG_Z11_Z12_Z13 = 671,
	AArch64_REG_Z12_Z13_Z14 = 672,
	AArch64_REG_Z13_Z14_Z15 = 673,
	AArch64_REG_Z14_Z15_Z16 = 674,
	AArch64_REG_Z15_Z16_Z17 = 675,
	AArch64_REG_Z16_Z17_Z18 = 676,
	AArch64_REG_Z17_Z18_Z19 = 677,
	AArch64_REG_Z18_Z19_Z20 = 678,
	AArch64_REG_Z19_Z20_Z21 = 679,
	AArch64_REG_Z20_Z21_Z22 = 680,
	AArch64_REG_Z21_Z22_Z23 = 681,
	AArch64_REG_Z22_Z23_Z24 = 682,
	AArch64_REG_Z23_Z24_Z25 = 683,
	AArch64_REG_Z24_Z25_Z26 = 684,
	AArch64_REG_Z25_Z26_Z27 = 685,
	AArch64_REG_Z26_Z27_Z28 = 686,
	AArch64_REG_Z27_Z28_Z29 = 687,
	AArch64_REG_Z28_Z29_Z30 = 688,
	AArch64_REG_Z29_Z30_Z31 = 689,
	AArch64_REG_Z30_Z31_Z0 = 690,
	AArch64_REG_Z31_Z0_Z1 = 691,
	AArch64_REG_Z16_Z24 = 692,
	AArch64_REG_Z17_Z25 = 693,
	AArch64_REG_Z18_Z26 = 694,
	AArch64_REG_Z19_Z27 = 695,
	AArch64_REG_Z20_Z28 = 696,
	AArch64_REG_Z21_Z29 = 697,
	AArch64_REG_Z22_Z30 = 698,
	AArch64_REG_Z23_Z31 = 699,
	AArch64_REG_Z0_Z8 = 700,
	AArch64_REG_Z1_Z9 = 701,
	AArch64_REG_Z2_Z10 = 702,
	AArch64_REG_Z3_Z11 = 703,
	AArch64_REG_Z4_Z12 = 704,
	AArch64_REG_Z5_Z13 = 705,
	AArch64_REG_Z6_Z14 = 706,
	AArch64_REG_Z7_Z15 = 707,
	AArch64_REG_Z16_Z20_Z24_Z28 = 708,
	AArch64_REG_Z17_Z21_Z25_Z29 = 709,
	AArch64_REG_Z18_Z22_Z26_Z30 = 710,
	AArch64_REG_Z19_Z23_Z27_Z31 = 711,
	AArch64_REG_Z0_Z4_Z8_Z12 = 712,
	AArch64_REG_Z1_Z5_Z9_Z13 = 713,
	AArch64_REG_Z2_Z6_Z10_Z14 = 714,
	AArch64_REG_Z3_Z7_Z11_Z15 = 715,
	AArch64_REG_ENDING, // 716

	// clang-format on
	// generated content <AArch64GenCSRegEnum.inc> end

  // alias registers
  AArch64_REG_IP0 = AArch64_REG_X16,
  AArch64_REG_IP1 = AArch64_REG_X17,
  AArch64_REG_X29 = AArch64_REG_FP,
  AArch64_REG_X30 = AArch64_REG_LR,
} aarch64_reg;

/// Instruction's operand referring to memory
typedef struct aarch64_op_mem {
  aarch64_reg base;  ///< base register
  aarch64_reg index; ///< index register
  int32_t disp;	   ///< displacement/offset value
} aarch64_op_mem;

/// Components of an SME matrix.
/// Used when an sme operand is set to signal which part should be set.
typedef enum {
	AArch64_SME_MATRIX_TILE,
	AArch64_SME_MATRIX_TILE_LIST,
	AArch64_SME_MATRIX_SLICE_REG,
	AArch64_SME_MATRIX_SLICE_OFF,
	AArch64_SME_MATRIX_SLICE_OFF_RANGE,
} aarch64_sme_op_part;

typedef enum {
	AArch64_SME_OP_INVALID,
	AArch64_SME_OP_TILE, ///< SME operand is a single tile.
	AArch64_SME_OP_TILE_VEC, ///< SME operand is a tile indexed by a register and/or immediate
} aarch64_sme_op_type;

typedef struct {
	int8_t first;
	int8_t offset;
} aarch64_imm_range;

/// SME Instruction's operand has index
typedef struct aarch64_op_sme {
  aarch64_sme_op_type type; ///< AArch64_SME_OP_TILE, AArch64_SME_OP_TILE_VEC
  aarch64_reg tile; ///< Matrix tile register
  aarch64_reg slice_reg; ///< slice index reg
	union {
		int8_t imm;
		aarch64_imm_range imm_range;
	} slice_offset; ///< slice index offset. Is set to -1 if invalid.
	bool has_range_offset; ///< If true, the offset is a range.
  bool is_vertical;	///< Flag if slice is vertical or horizontal
} aarch64_op_sme;

/// Instruction operand
typedef struct cs_aarch64_op {
  int vector_index; ///< Vector Index for some vector operands (or -1 if
		    ///< irrelevant)
  AArch64Layout_VectorLayout vas;    ///< Vector Arrangement Specifier
  struct {
    aarch64_shifter type; ///< shifter type of this operand
    unsigned int value; ///< shifter value of this operand
  } shift;
  aarch64_extender ext; ///< extender type of this operand
  aarch64_op_type type; ///< operand type
  union {
    aarch64_reg reg;	 ///< register value for REG operand
    int64_t imm;	 ///< immediate value, or index for C-IMM or IMM operand
		aarch64_imm_range imm_range; ///< An immediate range
    double fp;		 ///< floating point value for FP operand
    aarch64_op_mem mem;	 ///< base/index/scale/disp value for MEM operand
		aarch64_sysop sysop; ///< System operand
    aarch64_op_sme sme; ///< SME matrix operand
  };

  /// How is this operand accessed? (READ, WRITE or READ|WRITE)
  /// This field is combined of cs_ac_type.
  /// NOTE: this field is irrelevant if engine is compiled in DIET mode.
  uint8_t access;
  bool is_list_member; ///< True if this operand is part of a register or vector list.
} cs_aarch64_op;

#define MAX_AARCH64_OPS 8

/// Instruction structure
typedef struct cs_aarch64 {
  AArch64CC_CondCode cc;	     ///< conditional code for this insn
  bool update_flags; ///< does this insn update flags?
  bool post_index;   ///< only set if writeback is 'True', if 'False' pre-index, otherwise post.
  bool is_doing_sme; ///< True if a SME operand is currently edited.

  /// Number of operands of this instruction,
  /// or 0 when instruction has no operand.
  uint8_t op_count;

  cs_aarch64_op operands[MAX_AARCH64_OPS]; ///< operands for this instruction.
} cs_aarch64;

/// AArch64 instruction
typedef enum aarch64_insn {
	// generated content <AArch64GenCSInsnEnum.inc> begin
	// clang-format off

	AArch64_INS_INVALID,
	AArch64_INS_ABS,
	AArch64_INS_ADCLB,
	AArch64_INS_ADCLT,
	AArch64_INS_ADCS,
	AArch64_INS_ADC,
	AArch64_INS_ADDG,
	AArch64_INS_ADDHA,
	AArch64_INS_ADDHNB,
	AArch64_INS_ADDHNT,
	AArch64_INS_ADDHN,
	AArch64_INS_ADDHN2,
	AArch64_INS_ADDPL,
	AArch64_INS_ADDP,
	AArch64_INS_ADDQV,
	AArch64_INS_ADDSPL,
	AArch64_INS_ADDSVL,
	AArch64_INS_ADDS,
	AArch64_INS_ADDVA,
	AArch64_INS_ADDVL,
	AArch64_INS_ADDV,
	AArch64_INS_ADD,
	AArch64_INS_ADR,
	AArch64_INS_ADRP,
	AArch64_INS_AESD,
	AArch64_INS_AESE,
	AArch64_INS_AESIMC,
	AArch64_INS_AESMC,
	AArch64_INS_ANDQV,
	AArch64_INS_ANDS,
	AArch64_INS_ANDV,
	AArch64_INS_AND,
	AArch64_INS_ASRD,
	AArch64_INS_ASRR,
	AArch64_INS_ASR,
	AArch64_INS_AUTDA,
	AArch64_INS_AUTDB,
	AArch64_INS_AUTDZA,
	AArch64_INS_AUTDZB,
	AArch64_INS_AUTIA,
	AArch64_INS_HINT,
	AArch64_INS_AUTIB,
	AArch64_INS_AUTIZA,
	AArch64_INS_AUTIZB,
	AArch64_INS_AXFLAG,
	AArch64_INS_B,
	AArch64_INS_BCAX,
	AArch64_INS_BC,
	AArch64_INS_BDEP,
	AArch64_INS_BEXT,
	AArch64_INS_BFDOT,
	AArch64_INS_BFADD,
	AArch64_INS_BFCLAMP,
	AArch64_INS_BFCVT,
	AArch64_INS_BFCVTN,
	AArch64_INS_BFCVTN2,
	AArch64_INS_BFCVTNT,
	AArch64_INS_BFMAXNM,
	AArch64_INS_BFMAX,
	AArch64_INS_BFMINNM,
	AArch64_INS_BFMIN,
	AArch64_INS_BFMLALB,
	AArch64_INS_BFMLALT,
	AArch64_INS_BFMLAL,
	AArch64_INS_BFMLA,
	AArch64_INS_BFMLSLB,
	AArch64_INS_BFMLSLT,
	AArch64_INS_BFMLSL,
	AArch64_INS_BFMLS,
	AArch64_INS_BFMMLA,
	AArch64_INS_BFMOPA,
	AArch64_INS_BFMOPS,
	AArch64_INS_BFMUL,
	AArch64_INS_BFM,
	AArch64_INS_BFSUB,
	AArch64_INS_BFVDOT,
	AArch64_INS_BGRP,
	AArch64_INS_BICS,
	AArch64_INS_BIC,
	AArch64_INS_BIF,
	AArch64_INS_BIT,
	AArch64_INS_BL,
	AArch64_INS_BLR,
	AArch64_INS_BLRAA,
	AArch64_INS_BLRAAZ,
	AArch64_INS_BLRAB,
	AArch64_INS_BLRABZ,
	AArch64_INS_BMOPA,
	AArch64_INS_BMOPS,
	AArch64_INS_BR,
	AArch64_INS_BRAA,
	AArch64_INS_BRAAZ,
	AArch64_INS_BRAB,
	AArch64_INS_BRABZ,
	AArch64_INS_BRB,
	AArch64_INS_BRK,
	AArch64_INS_BRKAS,
	AArch64_INS_BRKA,
	AArch64_INS_BRKBS,
	AArch64_INS_BRKB,
	AArch64_INS_BRKNS,
	AArch64_INS_BRKN,
	AArch64_INS_BRKPAS,
	AArch64_INS_BRKPA,
	AArch64_INS_BRKPBS,
	AArch64_INS_BRKPB,
	AArch64_INS_BSL1N,
	AArch64_INS_BSL2N,
	AArch64_INS_BSL,
	AArch64_INS_CADD,
	AArch64_INS_CASAB,
	AArch64_INS_CASAH,
	AArch64_INS_CASALB,
	AArch64_INS_CASALH,
	AArch64_INS_CASAL,
	AArch64_INS_CASA,
	AArch64_INS_CASB,
	AArch64_INS_CASH,
	AArch64_INS_CASLB,
	AArch64_INS_CASLH,
	AArch64_INS_CASL,
	AArch64_INS_CASPAL,
	AArch64_INS_CASPA,
	AArch64_INS_CASPL,
	AArch64_INS_CASP,
	AArch64_INS_CAS,
	AArch64_INS_CBNZ,
	AArch64_INS_CBZ,
	AArch64_INS_CCMN,
	AArch64_INS_CCMP,
	AArch64_INS_CDOT,
	AArch64_INS_CFINV,
	AArch64_INS_CLASTA,
	AArch64_INS_CLASTB,
	AArch64_INS_CLREX,
	AArch64_INS_CLS,
	AArch64_INS_CLZ,
	AArch64_INS_CMEQ,
	AArch64_INS_CMGE,
	AArch64_INS_CMGT,
	AArch64_INS_CMHI,
	AArch64_INS_CMHS,
	AArch64_INS_CMLA,
	AArch64_INS_CMLE,
	AArch64_INS_CMLT,
	AArch64_INS_CMPEQ,
	AArch64_INS_CMPGE,
	AArch64_INS_CMPGT,
	AArch64_INS_CMPHI,
	AArch64_INS_CMPHS,
	AArch64_INS_CMPLE,
	AArch64_INS_CMPLO,
	AArch64_INS_CMPLS,
	AArch64_INS_CMPLT,
	AArch64_INS_CMPNE,
	AArch64_INS_CMTST,
	AArch64_INS_CNOT,
	AArch64_INS_CNTB,
	AArch64_INS_CNTD,
	AArch64_INS_CNTH,
	AArch64_INS_CNTP,
	AArch64_INS_CNTW,
	AArch64_INS_CNT,
	AArch64_INS_COMPACT,
	AArch64_INS_CPYE,
	AArch64_INS_CPYEN,
	AArch64_INS_CPYERN,
	AArch64_INS_CPYERT,
	AArch64_INS_CPYERTN,
	AArch64_INS_CPYERTRN,
	AArch64_INS_CPYERTWN,
	AArch64_INS_CPYET,
	AArch64_INS_CPYETN,
	AArch64_INS_CPYETRN,
	AArch64_INS_CPYETWN,
	AArch64_INS_CPYEWN,
	AArch64_INS_CPYEWT,
	AArch64_INS_CPYEWTN,
	AArch64_INS_CPYEWTRN,
	AArch64_INS_CPYEWTWN,
	AArch64_INS_CPYFE,
	AArch64_INS_CPYFEN,
	AArch64_INS_CPYFERN,
	AArch64_INS_CPYFERT,
	AArch64_INS_CPYFERTN,
	AArch64_INS_CPYFERTRN,
	AArch64_INS_CPYFERTWN,
	AArch64_INS_CPYFET,
	AArch64_INS_CPYFETN,
	AArch64_INS_CPYFETRN,
	AArch64_INS_CPYFETWN,
	AArch64_INS_CPYFEWN,
	AArch64_INS_CPYFEWT,
	AArch64_INS_CPYFEWTN,
	AArch64_INS_CPYFEWTRN,
	AArch64_INS_CPYFEWTWN,
	AArch64_INS_CPYFM,
	AArch64_INS_CPYFMN,
	AArch64_INS_CPYFMRN,
	AArch64_INS_CPYFMRT,
	AArch64_INS_CPYFMRTN,
	AArch64_INS_CPYFMRTRN,
	AArch64_INS_CPYFMRTWN,
	AArch64_INS_CPYFMT,
	AArch64_INS_CPYFMTN,
	AArch64_INS_CPYFMTRN,
	AArch64_INS_CPYFMTWN,
	AArch64_INS_CPYFMWN,
	AArch64_INS_CPYFMWT,
	AArch64_INS_CPYFMWTN,
	AArch64_INS_CPYFMWTRN,
	AArch64_INS_CPYFMWTWN,
	AArch64_INS_CPYFP,
	AArch64_INS_CPYFPN,
	AArch64_INS_CPYFPRN,
	AArch64_INS_CPYFPRT,
	AArch64_INS_CPYFPRTN,
	AArch64_INS_CPYFPRTRN,
	AArch64_INS_CPYFPRTWN,
	AArch64_INS_CPYFPT,
	AArch64_INS_CPYFPTN,
	AArch64_INS_CPYFPTRN,
	AArch64_INS_CPYFPTWN,
	AArch64_INS_CPYFPWN,
	AArch64_INS_CPYFPWT,
	AArch64_INS_CPYFPWTN,
	AArch64_INS_CPYFPWTRN,
	AArch64_INS_CPYFPWTWN,
	AArch64_INS_CPYM,
	AArch64_INS_CPYMN,
	AArch64_INS_CPYMRN,
	AArch64_INS_CPYMRT,
	AArch64_INS_CPYMRTN,
	AArch64_INS_CPYMRTRN,
	AArch64_INS_CPYMRTWN,
	AArch64_INS_CPYMT,
	AArch64_INS_CPYMTN,
	AArch64_INS_CPYMTRN,
	AArch64_INS_CPYMTWN,
	AArch64_INS_CPYMWN,
	AArch64_INS_CPYMWT,
	AArch64_INS_CPYMWTN,
	AArch64_INS_CPYMWTRN,
	AArch64_INS_CPYMWTWN,
	AArch64_INS_CPYP,
	AArch64_INS_CPYPN,
	AArch64_INS_CPYPRN,
	AArch64_INS_CPYPRT,
	AArch64_INS_CPYPRTN,
	AArch64_INS_CPYPRTRN,
	AArch64_INS_CPYPRTWN,
	AArch64_INS_CPYPT,
	AArch64_INS_CPYPTN,
	AArch64_INS_CPYPTRN,
	AArch64_INS_CPYPTWN,
	AArch64_INS_CPYPWN,
	AArch64_INS_CPYPWT,
	AArch64_INS_CPYPWTN,
	AArch64_INS_CPYPWTRN,
	AArch64_INS_CPYPWTWN,
	AArch64_INS_CPY,
	AArch64_INS_CRC32B,
	AArch64_INS_CRC32CB,
	AArch64_INS_CRC32CH,
	AArch64_INS_CRC32CW,
	AArch64_INS_CRC32CX,
	AArch64_INS_CRC32H,
	AArch64_INS_CRC32W,
	AArch64_INS_CRC32X,
	AArch64_INS_CSEL,
	AArch64_INS_CSINC,
	AArch64_INS_CSINV,
	AArch64_INS_CSNEG,
	AArch64_INS_CTERMEQ,
	AArch64_INS_CTERMNE,
	AArch64_INS_CTZ,
	AArch64_INS_DCPS1,
	AArch64_INS_DCPS2,
	AArch64_INS_DCPS3,
	AArch64_INS_DECB,
	AArch64_INS_DECD,
	AArch64_INS_DECH,
	AArch64_INS_DECP,
	AArch64_INS_DECW,
	AArch64_INS_DMB,
	AArch64_INS_DRPS,
	AArch64_INS_DSB,
	AArch64_INS_DUPM,
	AArch64_INS_DUPQ,
	AArch64_INS_DUP,
	AArch64_INS_MOV,
	AArch64_INS_EON,
	AArch64_INS_EOR3,
	AArch64_INS_EORBT,
	AArch64_INS_EORQV,
	AArch64_INS_EORS,
	AArch64_INS_EORTB,
	AArch64_INS_EORV,
	AArch64_INS_EOR,
	AArch64_INS_ERET,
	AArch64_INS_ERETAA,
	AArch64_INS_ERETAB,
	AArch64_INS_EXTQ,
	AArch64_INS_MOVA,
	AArch64_INS_EXTR,
	AArch64_INS_EXT,
	AArch64_INS_FABD,
	AArch64_INS_FABS,
	AArch64_INS_FACGE,
	AArch64_INS_FACGT,
	AArch64_INS_FADDA,
	AArch64_INS_FADD,
	AArch64_INS_FADDP,
	AArch64_INS_FADDQV,
	AArch64_INS_FADDV,
	AArch64_INS_FCADD,
	AArch64_INS_FCCMP,
	AArch64_INS_FCCMPE,
	AArch64_INS_FCLAMP,
	AArch64_INS_FCMEQ,
	AArch64_INS_FCMGE,
	AArch64_INS_FCMGT,
	AArch64_INS_FCMLA,
	AArch64_INS_FCMLE,
	AArch64_INS_FCMLT,
	AArch64_INS_FCMNE,
	AArch64_INS_FCMP,
	AArch64_INS_FCMPE,
	AArch64_INS_FCMUO,
	AArch64_INS_FCPY,
	AArch64_INS_FCSEL,
	AArch64_INS_FCVTAS,
	AArch64_INS_FCVTAU,
	AArch64_INS_FCVT,
	AArch64_INS_FCVTLT,
	AArch64_INS_FCVTL,
	AArch64_INS_FCVTL2,
	AArch64_INS_FCVTMS,
	AArch64_INS_FCVTMU,
	AArch64_INS_FCVTNS,
	AArch64_INS_FCVTNT,
	AArch64_INS_FCVTNU,
	AArch64_INS_FCVTN,
	AArch64_INS_FCVTN2,
	AArch64_INS_FCVTPS,
	AArch64_INS_FCVTPU,
	AArch64_INS_FCVTXNT,
	AArch64_INS_FCVTXN,
	AArch64_INS_FCVTXN2,
	AArch64_INS_FCVTX,
	AArch64_INS_FCVTZS,
	AArch64_INS_FCVTZU,
	AArch64_INS_FDIV,
	AArch64_INS_FDIVR,
	AArch64_INS_FDOT,
	AArch64_INS_FDUP,
	AArch64_INS_FEXPA,
	AArch64_INS_FJCVTZS,
	AArch64_INS_FLOGB,
	AArch64_INS_FMADD,
	AArch64_INS_FMAD,
	AArch64_INS_FMAX,
	AArch64_INS_FMAXNM,
	AArch64_INS_FMAXNMP,
	AArch64_INS_FMAXNMQV,
	AArch64_INS_FMAXNMV,
	AArch64_INS_FMAXP,
	AArch64_INS_FMAXQV,
	AArch64_INS_FMAXV,
	AArch64_INS_FMIN,
	AArch64_INS_FMINNM,
	AArch64_INS_FMINNMP,
	AArch64_INS_FMINNMQV,
	AArch64_INS_FMINNMV,
	AArch64_INS_FMINP,
	AArch64_INS_FMINQV,
	AArch64_INS_FMINV,
	AArch64_INS_FMLAL2,
	AArch64_INS_FMLALB,
	AArch64_INS_FMLALT,
	AArch64_INS_FMLAL,
	AArch64_INS_FMLA,
	AArch64_INS_FMLSL2,
	AArch64_INS_FMLSLB,
	AArch64_INS_FMLSLT,
	AArch64_INS_FMLSL,
	AArch64_INS_FMLS,
	AArch64_INS_FMMLA,
	AArch64_INS_FMOPA,
	AArch64_INS_FMOPS,
	AArch64_INS_FMOV,
	AArch64_INS_FMSB,
	AArch64_INS_FMSUB,
	AArch64_INS_FMUL,
	AArch64_INS_FMULX,
	AArch64_INS_FNEG,
	AArch64_INS_FNMADD,
	AArch64_INS_FNMAD,
	AArch64_INS_FNMLA,
	AArch64_INS_FNMLS,
	AArch64_INS_FNMSB,
	AArch64_INS_FNMSUB,
	AArch64_INS_FNMUL,
	AArch64_INS_FRECPE,
	AArch64_INS_FRECPS,
	AArch64_INS_FRECPX,
	AArch64_INS_FRINT32X,
	AArch64_INS_FRINT32Z,
	AArch64_INS_FRINT64X,
	AArch64_INS_FRINT64Z,
	AArch64_INS_FRINTA,
	AArch64_INS_FRINTI,
	AArch64_INS_FRINTM,
	AArch64_INS_FRINTN,
	AArch64_INS_FRINTP,
	AArch64_INS_FRINTX,
	AArch64_INS_FRINTZ,
	AArch64_INS_FRSQRTE,
	AArch64_INS_FRSQRTS,
	AArch64_INS_FSCALE,
	AArch64_INS_FSQRT,
	AArch64_INS_FSUB,
	AArch64_INS_FSUBR,
	AArch64_INS_FTMAD,
	AArch64_INS_FTSMUL,
	AArch64_INS_FTSSEL,
	AArch64_INS_FVDOT,
	AArch64_INS_LD1B,
	AArch64_INS_LD1D,
	AArch64_INS_LD1H,
	AArch64_INS_LD1Q,
	AArch64_INS_LD1SB,
	AArch64_INS_LD1SH,
	AArch64_INS_LD1SW,
	AArch64_INS_LD1W,
	AArch64_INS_LDFF1B,
	AArch64_INS_LDFF1D,
	AArch64_INS_LDFF1H,
	AArch64_INS_LDFF1SB,
	AArch64_INS_LDFF1SH,
	AArch64_INS_LDFF1SW,
	AArch64_INS_LDFF1W,
	AArch64_INS_GMI,
	AArch64_INS_HISTCNT,
	AArch64_INS_HISTSEG,
	AArch64_INS_HLT,
	AArch64_INS_HVC,
	AArch64_INS_INCB,
	AArch64_INS_INCD,
	AArch64_INS_INCH,
	AArch64_INS_INCP,
	AArch64_INS_INCW,
	AArch64_INS_INDEX,
	AArch64_INS_INSR,
	AArch64_INS_INS,
	AArch64_INS_IRG,
	AArch64_INS_ISB,
	AArch64_INS_LASTA,
	AArch64_INS_LASTB,
	AArch64_INS_LD1,
	AArch64_INS_LD1RB,
	AArch64_INS_LD1RD,
	AArch64_INS_LD1RH,
	AArch64_INS_LD1ROB,
	AArch64_INS_LD1ROD,
	AArch64_INS_LD1ROH,
	AArch64_INS_LD1ROW,
	AArch64_INS_LD1RQB,
	AArch64_INS_LD1RQD,
	AArch64_INS_LD1RQH,
	AArch64_INS_LD1RQW,
	AArch64_INS_LD1RSB,
	AArch64_INS_LD1RSH,
	AArch64_INS_LD1RSW,
	AArch64_INS_LD1RW,
	AArch64_INS_LD1R,
	AArch64_INS_LD2B,
	AArch64_INS_LD2D,
	AArch64_INS_LD2H,
	AArch64_INS_LD2Q,
	AArch64_INS_LD2R,
	AArch64_INS_LD2,
	AArch64_INS_LD2W,
	AArch64_INS_LD3B,
	AArch64_INS_LD3D,
	AArch64_INS_LD3H,
	AArch64_INS_LD3Q,
	AArch64_INS_LD3R,
	AArch64_INS_LD3,
	AArch64_INS_LD3W,
	AArch64_INS_LD4B,
	AArch64_INS_LD4D,
	AArch64_INS_LD4,
	AArch64_INS_LD4H,
	AArch64_INS_LD4Q,
	AArch64_INS_LD4R,
	AArch64_INS_LD4W,
	AArch64_INS_LD64B,
	AArch64_INS_LDADDAB,
	AArch64_INS_LDADDAH,
	AArch64_INS_LDADDALB,
	AArch64_INS_LDADDALH,
	AArch64_INS_LDADDAL,
	AArch64_INS_LDADDA,
	AArch64_INS_LDADDB,
	AArch64_INS_LDADDH,
	AArch64_INS_LDADDLB,
	AArch64_INS_LDADDLH,
	AArch64_INS_LDADDL,
	AArch64_INS_LDADD,
	AArch64_INS_LDAP1,
	AArch64_INS_LDAPRB,
	AArch64_INS_LDAPRH,
	AArch64_INS_LDAPR,
	AArch64_INS_LDAPURB,
	AArch64_INS_LDAPURH,
	AArch64_INS_LDAPURSB,
	AArch64_INS_LDAPURSH,
	AArch64_INS_LDAPURSW,
	AArch64_INS_LDAPUR,
	AArch64_INS_LDARB,
	AArch64_INS_LDARH,
	AArch64_INS_LDAR,
	AArch64_INS_LDAXP,
	AArch64_INS_LDAXRB,
	AArch64_INS_LDAXRH,
	AArch64_INS_LDAXR,
	AArch64_INS_LDCLRAB,
	AArch64_INS_LDCLRAH,
	AArch64_INS_LDCLRALB,
	AArch64_INS_LDCLRALH,
	AArch64_INS_LDCLRAL,
	AArch64_INS_LDCLRA,
	AArch64_INS_LDCLRB,
	AArch64_INS_LDCLRH,
	AArch64_INS_LDCLRLB,
	AArch64_INS_LDCLRLH,
	AArch64_INS_LDCLRL,
	AArch64_INS_LDCLRP,
	AArch64_INS_LDCLRPA,
	AArch64_INS_LDCLRPAL,
	AArch64_INS_LDCLRPL,
	AArch64_INS_LDCLR,
	AArch64_INS_LDEORAB,
	AArch64_INS_LDEORAH,
	AArch64_INS_LDEORALB,
	AArch64_INS_LDEORALH,
	AArch64_INS_LDEORAL,
	AArch64_INS_LDEORA,
	AArch64_INS_LDEORB,
	AArch64_INS_LDEORH,
	AArch64_INS_LDEORLB,
	AArch64_INS_LDEORLH,
	AArch64_INS_LDEORL,
	AArch64_INS_LDEOR,
	AArch64_INS_LDG,
	AArch64_INS_LDGM,
	AArch64_INS_LDIAPP,
	AArch64_INS_LDLARB,
	AArch64_INS_LDLARH,
	AArch64_INS_LDLAR,
	AArch64_INS_LDNF1B,
	AArch64_INS_LDNF1D,
	AArch64_INS_LDNF1H,
	AArch64_INS_LDNF1SB,
	AArch64_INS_LDNF1SH,
	AArch64_INS_LDNF1SW,
	AArch64_INS_LDNF1W,
	AArch64_INS_LDNP,
	AArch64_INS_LDNT1B,
	AArch64_INS_LDNT1D,
	AArch64_INS_LDNT1H,
	AArch64_INS_LDNT1SB,
	AArch64_INS_LDNT1SH,
	AArch64_INS_LDNT1SW,
	AArch64_INS_LDNT1W,
	AArch64_INS_LDP,
	AArch64_INS_LDPSW,
	AArch64_INS_LDRAA,
	AArch64_INS_LDRAB,
	AArch64_INS_LDRB,
	AArch64_INS_LDR,
	AArch64_INS_LDRH,
	AArch64_INS_LDRSB,
	AArch64_INS_LDRSH,
	AArch64_INS_LDRSW,
	AArch64_INS_LDSETAB,
	AArch64_INS_LDSETAH,
	AArch64_INS_LDSETALB,
	AArch64_INS_LDSETALH,
	AArch64_INS_LDSETAL,
	AArch64_INS_LDSETA,
	AArch64_INS_LDSETB,
	AArch64_INS_LDSETH,
	AArch64_INS_LDSETLB,
	AArch64_INS_LDSETLH,
	AArch64_INS_LDSETL,
	AArch64_INS_LDSETP,
	AArch64_INS_LDSETPA,
	AArch64_INS_LDSETPAL,
	AArch64_INS_LDSETPL,
	AArch64_INS_LDSET,
	AArch64_INS_LDSMAXAB,
	AArch64_INS_LDSMAXAH,
	AArch64_INS_LDSMAXALB,
	AArch64_INS_LDSMAXALH,
	AArch64_INS_LDSMAXAL,
	AArch64_INS_LDSMAXA,
	AArch64_INS_LDSMAXB,
	AArch64_INS_LDSMAXH,
	AArch64_INS_LDSMAXLB,
	AArch64_INS_LDSMAXLH,
	AArch64_INS_LDSMAXL,
	AArch64_INS_LDSMAX,
	AArch64_INS_LDSMINAB,
	AArch64_INS_LDSMINAH,
	AArch64_INS_LDSMINALB,
	AArch64_INS_LDSMINALH,
	AArch64_INS_LDSMINAL,
	AArch64_INS_LDSMINA,
	AArch64_INS_LDSMINB,
	AArch64_INS_LDSMINH,
	AArch64_INS_LDSMINLB,
	AArch64_INS_LDSMINLH,
	AArch64_INS_LDSMINL,
	AArch64_INS_LDSMIN,
	AArch64_INS_LDTRB,
	AArch64_INS_LDTRH,
	AArch64_INS_LDTRSB,
	AArch64_INS_LDTRSH,
	AArch64_INS_LDTRSW,
	AArch64_INS_LDTR,
	AArch64_INS_LDUMAXAB,
	AArch64_INS_LDUMAXAH,
	AArch64_INS_LDUMAXALB,
	AArch64_INS_LDUMAXALH,
	AArch64_INS_LDUMAXAL,
	AArch64_INS_LDUMAXA,
	AArch64_INS_LDUMAXB,
	AArch64_INS_LDUMAXH,
	AArch64_INS_LDUMAXLB,
	AArch64_INS_LDUMAXLH,
	AArch64_INS_LDUMAXL,
	AArch64_INS_LDUMAX,
	AArch64_INS_LDUMINAB,
	AArch64_INS_LDUMINAH,
	AArch64_INS_LDUMINALB,
	AArch64_INS_LDUMINALH,
	AArch64_INS_LDUMINAL,
	AArch64_INS_LDUMINA,
	AArch64_INS_LDUMINB,
	AArch64_INS_LDUMINH,
	AArch64_INS_LDUMINLB,
	AArch64_INS_LDUMINLH,
	AArch64_INS_LDUMINL,
	AArch64_INS_LDUMIN,
	AArch64_INS_LDURB,
	AArch64_INS_LDUR,
	AArch64_INS_LDURH,
	AArch64_INS_LDURSB,
	AArch64_INS_LDURSH,
	AArch64_INS_LDURSW,
	AArch64_INS_LDXP,
	AArch64_INS_LDXRB,
	AArch64_INS_LDXRH,
	AArch64_INS_LDXR,
	AArch64_INS_LSLR,
	AArch64_INS_LSL,
	AArch64_INS_LSRR,
	AArch64_INS_LSR,
	AArch64_INS_LUTI2,
	AArch64_INS_LUTI4,
	AArch64_INS_MADD,
	AArch64_INS_MAD,
	AArch64_INS_MATCH,
	AArch64_INS_MLA,
	AArch64_INS_MLS,
	AArch64_INS_SETGE,
	AArch64_INS_SETGEN,
	AArch64_INS_SETGET,
	AArch64_INS_SETGETN,
	AArch64_INS_MOVAZ,
	AArch64_INS_MOVI,
	AArch64_INS_MOVK,
	AArch64_INS_MOVN,
	AArch64_INS_MOVPRFX,
	AArch64_INS_MOVT,
	AArch64_INS_MOVZ,
	AArch64_INS_MRRS,
	AArch64_INS_MRS,
	AArch64_INS_MSB,
	AArch64_INS_MSR,
	AArch64_INS_MSRR,
	AArch64_INS_MSUB,
	AArch64_INS_MUL,
	AArch64_INS_MVNI,
	AArch64_INS_NANDS,
	AArch64_INS_NAND,
	AArch64_INS_NBSL,
	AArch64_INS_NEG,
	AArch64_INS_NMATCH,
	AArch64_INS_NORS,
	AArch64_INS_NOR,
	AArch64_INS_NOT,
	AArch64_INS_ORNS,
	AArch64_INS_ORN,
	AArch64_INS_ORQV,
	AArch64_INS_ORRS,
	AArch64_INS_ORR,
	AArch64_INS_ORV,
	AArch64_INS_PACDA,
	AArch64_INS_PACDB,
	AArch64_INS_PACDZA,
	AArch64_INS_PACDZB,
	AArch64_INS_PACGA,
	AArch64_INS_PACIA,
	AArch64_INS_PACIB,
	AArch64_INS_PACIZA,
	AArch64_INS_PACIZB,
	AArch64_INS_PEXT,
	AArch64_INS_PFALSE,
	AArch64_INS_PFIRST,
	AArch64_INS_PMOV,
	AArch64_INS_PMULLB,
	AArch64_INS_PMULLT,
	AArch64_INS_PMULL2,
	AArch64_INS_PMULL,
	AArch64_INS_PMUL,
	AArch64_INS_PNEXT,
	AArch64_INS_PRFB,
	AArch64_INS_PRFD,
	AArch64_INS_PRFH,
	AArch64_INS_PRFM,
	AArch64_INS_PRFUM,
	AArch64_INS_PRFW,
	AArch64_INS_PSEL,
	AArch64_INS_PTEST,
	AArch64_INS_PTRUES,
	AArch64_INS_PTRUE,
	AArch64_INS_PUNPKHI,
	AArch64_INS_PUNPKLO,
	AArch64_INS_RADDHNB,
	AArch64_INS_RADDHNT,
	AArch64_INS_RADDHN,
	AArch64_INS_RADDHN2,
	AArch64_INS_RAX1,
	AArch64_INS_RBIT,
	AArch64_INS_RCWCAS,
	AArch64_INS_RCWCASA,
	AArch64_INS_RCWCASAL,
	AArch64_INS_RCWCASL,
	AArch64_INS_RCWCASP,
	AArch64_INS_RCWCASPA,
	AArch64_INS_RCWCASPAL,
	AArch64_INS_RCWCASPL,
	AArch64_INS_RCWCLR,
	AArch64_INS_RCWCLRA,
	AArch64_INS_RCWCLRAL,
	AArch64_INS_RCWCLRL,
	AArch64_INS_RCWCLRP,
	AArch64_INS_RCWCLRPA,
	AArch64_INS_RCWCLRPAL,
	AArch64_INS_RCWCLRPL,
	AArch64_INS_RCWSCLR,
	AArch64_INS_RCWSCLRA,
	AArch64_INS_RCWSCLRAL,
	AArch64_INS_RCWSCLRL,
	AArch64_INS_RCWSCLRP,
	AArch64_INS_RCWSCLRPA,
	AArch64_INS_RCWSCLRPAL,
	AArch64_INS_RCWSCLRPL,
	AArch64_INS_RCWSCAS,
	AArch64_INS_RCWSCASA,
	AArch64_INS_RCWSCASAL,
	AArch64_INS_RCWSCASL,
	AArch64_INS_RCWSCASP,
	AArch64_INS_RCWSCASPA,
	AArch64_INS_RCWSCASPAL,
	AArch64_INS_RCWSCASPL,
	AArch64_INS_RCWSET,
	AArch64_INS_RCWSETA,
	AArch64_INS_RCWSETAL,
	AArch64_INS_RCWSETL,
	AArch64_INS_RCWSETP,
	AArch64_INS_RCWSETPA,
	AArch64_INS_RCWSETPAL,
	AArch64_INS_RCWSETPL,
	AArch64_INS_RCWSSET,
	AArch64_INS_RCWSSETA,
	AArch64_INS_RCWSSETAL,
	AArch64_INS_RCWSSETL,
	AArch64_INS_RCWSSETP,
	AArch64_INS_RCWSSETPA,
	AArch64_INS_RCWSSETPAL,
	AArch64_INS_RCWSSETPL,
	AArch64_INS_RCWSWP,
	AArch64_INS_RCWSWPA,
	AArch64_INS_RCWSWPAL,
	AArch64_INS_RCWSWPL,
	AArch64_INS_RCWSWPP,
	AArch64_INS_RCWSWPPA,
	AArch64_INS_RCWSWPPAL,
	AArch64_INS_RCWSWPPL,
	AArch64_INS_RCWSSWP,
	AArch64_INS_RCWSSWPA,
	AArch64_INS_RCWSSWPAL,
	AArch64_INS_RCWSSWPL,
	AArch64_INS_RCWSSWPP,
	AArch64_INS_RCWSSWPPA,
	AArch64_INS_RCWSSWPPAL,
	AArch64_INS_RCWSSWPPL,
	AArch64_INS_RDFFRS,
	AArch64_INS_RDFFR,
	AArch64_INS_RDSVL,
	AArch64_INS_RDVL,
	AArch64_INS_RET,
	AArch64_INS_RETAA,
	AArch64_INS_RETAB,
	AArch64_INS_REV16,
	AArch64_INS_REV32,
	AArch64_INS_REV64,
	AArch64_INS_REVB,
	AArch64_INS_REVD,
	AArch64_INS_REVH,
	AArch64_INS_REVW,
	AArch64_INS_REV,
	AArch64_INS_RMIF,
	AArch64_INS_ROR,
	AArch64_INS_RPRFM,
	AArch64_INS_RSHRNB,
	AArch64_INS_RSHRNT,
	AArch64_INS_RSHRN2,
	AArch64_INS_RSHRN,
	AArch64_INS_RSUBHNB,
	AArch64_INS_RSUBHNT,
	AArch64_INS_RSUBHN,
	AArch64_INS_RSUBHN2,
	AArch64_INS_SABALB,
	AArch64_INS_SABALT,
	AArch64_INS_SABAL2,
	AArch64_INS_SABAL,
	AArch64_INS_SABA,
	AArch64_INS_SABDLB,
	AArch64_INS_SABDLT,
	AArch64_INS_SABDL2,
	AArch64_INS_SABDL,
	AArch64_INS_SABD,
	AArch64_INS_SADALP,
	AArch64_INS_SADDLBT,
	AArch64_INS_SADDLB,
	AArch64_INS_SADDLP,
	AArch64_INS_SADDLT,
	AArch64_INS_SADDLV,
	AArch64_INS_SADDL2,
	AArch64_INS_SADDL,
	AArch64_INS_SADDV,
	AArch64_INS_SADDWB,
	AArch64_INS_SADDWT,
	AArch64_INS_SADDW2,
	AArch64_INS_SADDW,
	AArch64_INS_SB,
	AArch64_INS_SBCLB,
	AArch64_INS_SBCLT,
	AArch64_INS_SBCS,
	AArch64_INS_SBC,
	AArch64_INS_SBFM,
	AArch64_INS_SCLAMP,
	AArch64_INS_SCVTF,
	AArch64_INS_SDIVR,
	AArch64_INS_SDIV,
	AArch64_INS_SDOT,
	AArch64_INS_SEL,
	AArch64_INS_SETE,
	AArch64_INS_SETEN,
	AArch64_INS_SETET,
	AArch64_INS_SETETN,
	AArch64_INS_SETF16,
	AArch64_INS_SETF8,
	AArch64_INS_SETFFR,
	AArch64_INS_SETGM,
	AArch64_INS_SETGMN,
	AArch64_INS_SETGMT,
	AArch64_INS_SETGMTN,
	AArch64_INS_SETGP,
	AArch64_INS_SETGPN,
	AArch64_INS_SETGPT,
	AArch64_INS_SETGPTN,
	AArch64_INS_SETM,
	AArch64_INS_SETMN,
	AArch64_INS_SETMT,
	AArch64_INS_SETMTN,
	AArch64_INS_SETP,
	AArch64_INS_SETPN,
	AArch64_INS_SETPT,
	AArch64_INS_SETPTN,
	AArch64_INS_SHA1C,
	AArch64_INS_SHA1H,
	AArch64_INS_SHA1M,
	AArch64_INS_SHA1P,
	AArch64_INS_SHA1SU0,
	AArch64_INS_SHA1SU1,
	AArch64_INS_SHA256H2,
	AArch64_INS_SHA256H,
	AArch64_INS_SHA256SU0,
	AArch64_INS_SHA256SU1,
	AArch64_INS_SHA512H,
	AArch64_INS_SHA512H2,
	AArch64_INS_SHA512SU0,
	AArch64_INS_SHA512SU1,
	AArch64_INS_SHADD,
	AArch64_INS_SHLL2,
	AArch64_INS_SHLL,
	AArch64_INS_SHL,
	AArch64_INS_SHRNB,
	AArch64_INS_SHRNT,
	AArch64_INS_SHRN2,
	AArch64_INS_SHRN,
	AArch64_INS_SHSUBR,
	AArch64_INS_SHSUB,
	AArch64_INS_SLI,
	AArch64_INS_SM3PARTW1,
	AArch64_INS_SM3PARTW2,
	AArch64_INS_SM3SS1,
	AArch64_INS_SM3TT1A,
	AArch64_INS_SM3TT1B,
	AArch64_INS_SM3TT2A,
	AArch64_INS_SM3TT2B,
	AArch64_INS_SM4E,
	AArch64_INS_SM4EKEY,
	AArch64_INS_SMADDL,
	AArch64_INS_SMAXP,
	AArch64_INS_SMAXQV,
	AArch64_INS_SMAXV,
	AArch64_INS_SMAX,
	AArch64_INS_SMC,
	AArch64_INS_SMINP,
	AArch64_INS_SMINQV,
	AArch64_INS_SMINV,
	AArch64_INS_SMIN,
	AArch64_INS_SMLALB,
	AArch64_INS_SMLALL,
	AArch64_INS_SMLALT,
	AArch64_INS_SMLAL,
	AArch64_INS_SMLAL2,
	AArch64_INS_SMLSLB,
	AArch64_INS_SMLSLL,
	AArch64_INS_SMLSLT,
	AArch64_INS_SMLSL,
	AArch64_INS_SMLSL2,
	AArch64_INS_SMMLA,
	AArch64_INS_SMOPA,
	AArch64_INS_SMOPS,
	AArch64_INS_SMOV,
	AArch64_INS_SMSUBL,
	AArch64_INS_SMULH,
	AArch64_INS_SMULLB,
	AArch64_INS_SMULLT,
	AArch64_INS_SMULL2,
	AArch64_INS_SMULL,
	AArch64_INS_SPLICE,
	AArch64_INS_SQABS,
	AArch64_INS_SQADD,
	AArch64_INS_SQCADD,
	AArch64_INS_SQCVTN,
	AArch64_INS_SQCVTUN,
	AArch64_INS_SQCVTU,
	AArch64_INS_SQCVT,
	AArch64_INS_SQDECB,
	AArch64_INS_SQDECD,
	AArch64_INS_SQDECH,
	AArch64_INS_SQDECP,
	AArch64_INS_SQDECW,
	AArch64_INS_SQDMLALBT,
	AArch64_INS_SQDMLALB,
	AArch64_INS_SQDMLALT,
	AArch64_INS_SQDMLAL,
	AArch64_INS_SQDMLAL2,
	AArch64_INS_SQDMLSLBT,
	AArch64_INS_SQDMLSLB,
	AArch64_INS_SQDMLSLT,
	AArch64_INS_SQDMLSL,
	AArch64_INS_SQDMLSL2,
	AArch64_INS_SQDMULH,
	AArch64_INS_SQDMULLB,
	AArch64_INS_SQDMULLT,
	AArch64_INS_SQDMULL,
	AArch64_INS_SQDMULL2,
	AArch64_INS_SQINCB,
	AArch64_INS_SQINCD,
	AArch64_INS_SQINCH,
	AArch64_INS_SQINCP,
	AArch64_INS_SQINCW,
	AArch64_INS_SQNEG,
	AArch64_INS_SQRDCMLAH,
	AArch64_INS_SQRDMLAH,
	AArch64_INS_SQRDMLSH,
	AArch64_INS_SQRDMULH,
	AArch64_INS_SQRSHLR,
	AArch64_INS_SQRSHL,
	AArch64_INS_SQRSHRNB,
	AArch64_INS_SQRSHRNT,
	AArch64_INS_SQRSHRN,
	AArch64_INS_SQRSHRN2,
	AArch64_INS_SQRSHRUNB,
	AArch64_INS_SQRSHRUNT,
	AArch64_INS_SQRSHRUN,
	AArch64_INS_SQRSHRUN2,
	AArch64_INS_SQRSHRU,
	AArch64_INS_SQRSHR,
	AArch64_INS_SQSHLR,
	AArch64_INS_SQSHLU,
	AArch64_INS_SQSHL,
	AArch64_INS_SQSHRNB,
	AArch64_INS_SQSHRNT,
	AArch64_INS_SQSHRN,
	AArch64_INS_SQSHRN2,
	AArch64_INS_SQSHRUNB,
	AArch64_INS_SQSHRUNT,
	AArch64_INS_SQSHRUN,
	AArch64_INS_SQSHRUN2,
	AArch64_INS_SQSUBR,
	AArch64_INS_SQSUB,
	AArch64_INS_SQXTNB,
	AArch64_INS_SQXTNT,
	AArch64_INS_SQXTN2,
	AArch64_INS_SQXTN,
	AArch64_INS_SQXTUNB,
	AArch64_INS_SQXTUNT,
	AArch64_INS_SQXTUN2,
	AArch64_INS_SQXTUN,
	AArch64_INS_SRHADD,
	AArch64_INS_SRI,
	AArch64_INS_SRSHLR,
	AArch64_INS_SRSHL,
	AArch64_INS_SRSHR,
	AArch64_INS_SRSRA,
	AArch64_INS_SSHLLB,
	AArch64_INS_SSHLLT,
	AArch64_INS_SSHLL2,
	AArch64_INS_SSHLL,
	AArch64_INS_SSHL,
	AArch64_INS_SSHR,
	AArch64_INS_SSRA,
	AArch64_INS_ST1B,
	AArch64_INS_ST1D,
	AArch64_INS_ST1H,
	AArch64_INS_ST1Q,
	AArch64_INS_ST1W,
	AArch64_INS_SSUBLBT,
	AArch64_INS_SSUBLB,
	AArch64_INS_SSUBLTB,
	AArch64_INS_SSUBLT,
	AArch64_INS_SSUBL2,
	AArch64_INS_SSUBL,
	AArch64_INS_SSUBWB,
	AArch64_INS_SSUBWT,
	AArch64_INS_SSUBW2,
	AArch64_INS_SSUBW,
	AArch64_INS_ST1,
	AArch64_INS_ST2B,
	AArch64_INS_ST2D,
	AArch64_INS_ST2G,
	AArch64_INS_ST2H,
	AArch64_INS_ST2Q,
	AArch64_INS_ST2,
	AArch64_INS_ST2W,
	AArch64_INS_ST3B,
	AArch64_INS_ST3D,
	AArch64_INS_ST3H,
	AArch64_INS_ST3Q,
	AArch64_INS_ST3,
	AArch64_INS_ST3W,
	AArch64_INS_ST4B,
	AArch64_INS_ST4D,
	AArch64_INS_ST4,
	AArch64_INS_ST4H,
	AArch64_INS_ST4Q,
	AArch64_INS_ST4W,
	AArch64_INS_ST64B,
	AArch64_INS_ST64BV,
	AArch64_INS_ST64BV0,
	AArch64_INS_STGM,
	AArch64_INS_STG,
	AArch64_INS_STGP,
	AArch64_INS_STILP,
	AArch64_INS_STL1,
	AArch64_INS_STLLRB,
	AArch64_INS_STLLRH,
	AArch64_INS_STLLR,
	AArch64_INS_STLRB,
	AArch64_INS_STLRH,
	AArch64_INS_STLR,
	AArch64_INS_STLURB,
	AArch64_INS_STLURH,
	AArch64_INS_STLUR,
	AArch64_INS_STLXP,
	AArch64_INS_STLXRB,
	AArch64_INS_STLXRH,
	AArch64_INS_STLXR,
	AArch64_INS_STNP,
	AArch64_INS_STNT1B,
	AArch64_INS_STNT1D,
	AArch64_INS_STNT1H,
	AArch64_INS_STNT1W,
	AArch64_INS_STP,
	AArch64_INS_STRB,
	AArch64_INS_STR,
	AArch64_INS_STRH,
	AArch64_INS_STTRB,
	AArch64_INS_STTRH,
	AArch64_INS_STTR,
	AArch64_INS_STURB,
	AArch64_INS_STUR,
	AArch64_INS_STURH,
	AArch64_INS_STXP,
	AArch64_INS_STXRB,
	AArch64_INS_STXRH,
	AArch64_INS_STXR,
	AArch64_INS_STZ2G,
	AArch64_INS_STZGM,
	AArch64_INS_STZG,
	AArch64_INS_SUBG,
	AArch64_INS_SUBHNB,
	AArch64_INS_SUBHNT,
	AArch64_INS_SUBHN,
	AArch64_INS_SUBHN2,
	AArch64_INS_SUBP,
	AArch64_INS_SUBPS,
	AArch64_INS_SUBR,
	AArch64_INS_SUBS,
	AArch64_INS_SUB,
	AArch64_INS_SUDOT,
	AArch64_INS_SUMLALL,
	AArch64_INS_SUMOPA,
	AArch64_INS_SUMOPS,
	AArch64_INS_SUNPKHI,
	AArch64_INS_SUNPKLO,
	AArch64_INS_SUNPK,
	AArch64_INS_SUQADD,
	AArch64_INS_SUVDOT,
	AArch64_INS_SVC,
	AArch64_INS_SVDOT,
	AArch64_INS_SWPAB,
	AArch64_INS_SWPAH,
	AArch64_INS_SWPALB,
	AArch64_INS_SWPALH,
	AArch64_INS_SWPAL,
	AArch64_INS_SWPA,
	AArch64_INS_SWPB,
	AArch64_INS_SWPH,
	AArch64_INS_SWPLB,
	AArch64_INS_SWPLH,
	AArch64_INS_SWPL,
	AArch64_INS_SWPP,
	AArch64_INS_SWPPA,
	AArch64_INS_SWPPAL,
	AArch64_INS_SWPPL,
	AArch64_INS_SWP,
	AArch64_INS_SXTB,
	AArch64_INS_SXTH,
	AArch64_INS_SXTW,
	AArch64_INS_SYSL,
	AArch64_INS_SYSP,
	AArch64_INS_SYS,
	AArch64_INS_TBLQ,
	AArch64_INS_TBL,
	AArch64_INS_TBNZ,
	AArch64_INS_TBXQ,
	AArch64_INS_TBX,
	AArch64_INS_TBZ,
	AArch64_INS_TCANCEL,
	AArch64_INS_TCOMMIT,
	AArch64_INS_TRCIT,
	AArch64_INS_TRN1,
	AArch64_INS_TRN2,
	AArch64_INS_TSB,
	AArch64_INS_TSTART,
	AArch64_INS_TTEST,
	AArch64_INS_UABALB,
	AArch64_INS_UABALT,
	AArch64_INS_UABAL2,
	AArch64_INS_UABAL,
	AArch64_INS_UABA,
	AArch64_INS_UABDLB,
	AArch64_INS_UABDLT,
	AArch64_INS_UABDL2,
	AArch64_INS_UABDL,
	AArch64_INS_UABD,
	AArch64_INS_UADALP,
	AArch64_INS_UADDLB,
	AArch64_INS_UADDLP,
	AArch64_INS_UADDLT,
	AArch64_INS_UADDLV,
	AArch64_INS_UADDL2,
	AArch64_INS_UADDL,
	AArch64_INS_UADDV,
	AArch64_INS_UADDWB,
	AArch64_INS_UADDWT,
	AArch64_INS_UADDW2,
	AArch64_INS_UADDW,
	AArch64_INS_UBFM,
	AArch64_INS_UCLAMP,
	AArch64_INS_UCVTF,
	AArch64_INS_UDF,
	AArch64_INS_UDIVR,
	AArch64_INS_UDIV,
	AArch64_INS_UDOT,
	AArch64_INS_UHADD,
	AArch64_INS_UHSUBR,
	AArch64_INS_UHSUB,
	AArch64_INS_UMADDL,
	AArch64_INS_UMAXP,
	AArch64_INS_UMAXQV,
	AArch64_INS_UMAXV,
	AArch64_INS_UMAX,
	AArch64_INS_UMINP,
	AArch64_INS_UMINQV,
	AArch64_INS_UMINV,
	AArch64_INS_UMIN,
	AArch64_INS_UMLALB,
	AArch64_INS_UMLALL,
	AArch64_INS_UMLALT,
	AArch64_INS_UMLAL,
	AArch64_INS_UMLAL2,
	AArch64_INS_UMLSLB,
	AArch64_INS_UMLSLL,
	AArch64_INS_UMLSLT,
	AArch64_INS_UMLSL,
	AArch64_INS_UMLSL2,
	AArch64_INS_UMMLA,
	AArch64_INS_UMOPA,
	AArch64_INS_UMOPS,
	AArch64_INS_UMOV,
	AArch64_INS_UMSUBL,
	AArch64_INS_UMULH,
	AArch64_INS_UMULLB,
	AArch64_INS_UMULLT,
	AArch64_INS_UMULL2,
	AArch64_INS_UMULL,
	AArch64_INS_UQADD,
	AArch64_INS_UQCVTN,
	AArch64_INS_UQCVT,
	AArch64_INS_UQDECB,
	AArch64_INS_UQDECD,
	AArch64_INS_UQDECH,
	AArch64_INS_UQDECP,
	AArch64_INS_UQDECW,
	AArch64_INS_UQINCB,
	AArch64_INS_UQINCD,
	AArch64_INS_UQINCH,
	AArch64_INS_UQINCP,
	AArch64_INS_UQINCW,
	AArch64_INS_UQRSHLR,
	AArch64_INS_UQRSHL,
	AArch64_INS_UQRSHRNB,
	AArch64_INS_UQRSHRNT,
	AArch64_INS_UQRSHRN,
	AArch64_INS_UQRSHRN2,
	AArch64_INS_UQRSHR,
	AArch64_INS_UQSHLR,
	AArch64_INS_UQSHL,
	AArch64_INS_UQSHRNB,
	AArch64_INS_UQSHRNT,
	AArch64_INS_UQSHRN,
	AArch64_INS_UQSHRN2,
	AArch64_INS_UQSUBR,
	AArch64_INS_UQSUB,
	AArch64_INS_UQXTNB,
	AArch64_INS_UQXTNT,
	AArch64_INS_UQXTN2,
	AArch64_INS_UQXTN,
	AArch64_INS_URECPE,
	AArch64_INS_URHADD,
	AArch64_INS_URSHLR,
	AArch64_INS_URSHL,
	AArch64_INS_URSHR,
	AArch64_INS_URSQRTE,
	AArch64_INS_URSRA,
	AArch64_INS_USDOT,
	AArch64_INS_USHLLB,
	AArch64_INS_USHLLT,
	AArch64_INS_USHLL2,
	AArch64_INS_USHLL,
	AArch64_INS_USHL,
	AArch64_INS_USHR,
	AArch64_INS_USMLALL,
	AArch64_INS_USMMLA,
	AArch64_INS_USMOPA,
	AArch64_INS_USMOPS,
	AArch64_INS_USQADD,
	AArch64_INS_USRA,
	AArch64_INS_USUBLB,
	AArch64_INS_USUBLT,
	AArch64_INS_USUBL2,
	AArch64_INS_USUBL,
	AArch64_INS_USUBWB,
	AArch64_INS_USUBWT,
	AArch64_INS_USUBW2,
	AArch64_INS_USUBW,
	AArch64_INS_USVDOT,
	AArch64_INS_UUNPKHI,
	AArch64_INS_UUNPKLO,
	AArch64_INS_UUNPK,
	AArch64_INS_UVDOT,
	AArch64_INS_UXTB,
	AArch64_INS_UXTH,
	AArch64_INS_UXTW,
	AArch64_INS_UZP1,
	AArch64_INS_UZP2,
	AArch64_INS_UZPQ1,
	AArch64_INS_UZPQ2,
	AArch64_INS_UZP,
	AArch64_INS_WFET,
	AArch64_INS_WFIT,
	AArch64_INS_WHILEGE,
	AArch64_INS_WHILEGT,
	AArch64_INS_WHILEHI,
	AArch64_INS_WHILEHS,
	AArch64_INS_WHILELE,
	AArch64_INS_WHILELO,
	AArch64_INS_WHILELS,
	AArch64_INS_WHILELT,
	AArch64_INS_WHILERW,
	AArch64_INS_WHILEWR,
	AArch64_INS_WRFFR,
	AArch64_INS_XAFLAG,
	AArch64_INS_XAR,
	AArch64_INS_XPACD,
	AArch64_INS_XPACI,
	AArch64_INS_XTN2,
	AArch64_INS_XTN,
	AArch64_INS_ZERO,
	AArch64_INS_ZIP1,
	AArch64_INS_ZIP2,
	AArch64_INS_ZIPQ1,
	AArch64_INS_ZIPQ2,
	AArch64_INS_ZIP,

	// clang-format on
	// generated content <AArch64GenCSInsnEnum.inc> end

  AArch64_INS_ENDING, // <-- mark the end of the list of insn

	AArch64_INS_ALIAS_BEGIN,
	// generated content <AArch64GenCSAliasEnum.inc> begin
	// clang-format off

	AArch64_INS_ALIAS_LDAPUR, // Real instr.: AArch64_LDAPURbi
	AArch64_INS_ALIAS_STLLRB, // Real instr.: AArch64_STLLRB
	AArch64_INS_ALIAS_STLLRH, // Real instr.: AArch64_STLLRH
	AArch64_INS_ALIAS_STLLR, // Real instr.: AArch64_STLLRW
	AArch64_INS_ALIAS_STLRB, // Real instr.: AArch64_STLRB
	AArch64_INS_ALIAS_STLRH, // Real instr.: AArch64_STLRH
	AArch64_INS_ALIAS_STLR, // Real instr.: AArch64_STLRW
	AArch64_INS_ALIAS_STLUR, // Real instr.: AArch64_STLURbi
	AArch64_INS_ALIAS_EOR, // Real instr.: AArch64_EOR_ZI
	AArch64_INS_ALIAS_AND, // Real instr.: AArch64_AND_ZI
	AArch64_INS_ALIAS_MOV, // Real instr.: AArch64_CPY_ZPmI_H
	AArch64_INS_ALIAS_LD1B, // Real instr.: AArch64_LD1B_H_IMM_REAL
	AArch64_INS_ALIAS_LD1SW, // Real instr.: AArch64_LD1SW_D_IMM_REAL
	AArch64_INS_ALIAS_LD1H, // Real instr.: AArch64_LD1H_IMM_REAL
	AArch64_INS_ALIAS_LD1SH, // Real instr.: AArch64_LD1SH_D_IMM_REAL
	AArch64_INS_ALIAS_LD1W, // Real instr.: AArch64_LD1W_IMM_REAL
	AArch64_INS_ALIAS_LD1SB, // Real instr.: AArch64_LD1SB_D_IMM_REAL
	AArch64_INS_ALIAS_LD1D, // Real instr.: AArch64_LD1D_IMM_REAL
	AArch64_INS_ALIAS_LD1RB, // Real instr.: AArch64_LD1RB_H_IMM
	AArch64_INS_ALIAS_LD1RSW, // Real instr.: AArch64_LD1RSW_IMM
	AArch64_INS_ALIAS_LD1RH, // Real instr.: AArch64_LD1RH_IMM
	AArch64_INS_ALIAS_LD1RSH, // Real instr.: AArch64_LD1RSH_D_IMM
	AArch64_INS_ALIAS_LD1RW, // Real instr.: AArch64_LD1RW_IMM
	AArch64_INS_ALIAS_LD1RSB, // Real instr.: AArch64_LD1RSB_D_IMM
	AArch64_INS_ALIAS_LD1RD, // Real instr.: AArch64_LD1RD_IMM
	AArch64_INS_ALIAS_LD1RQH, // Real instr.: AArch64_LD1RQ_H_IMM
	AArch64_INS_ALIAS_LD1RQW, // Real instr.: AArch64_LD1RQ_W_IMM
	AArch64_INS_ALIAS_LD1RQD, // Real instr.: AArch64_LD1RQ_D_IMM
	AArch64_INS_ALIAS_LDNF1B, // Real instr.: AArch64_LDNF1B_IMM_REAL
	AArch64_INS_ALIAS_LDNF1SW, // Real instr.: AArch64_LDNF1SW_D_IMM_REAL
	AArch64_INS_ALIAS_LDNF1H, // Real instr.: AArch64_LDNF1H_IMM_REAL
	AArch64_INS_ALIAS_LDNF1SH, // Real instr.: AArch64_LDNF1SH_D_IMM_REAL
	AArch64_INS_ALIAS_LDNF1W, // Real instr.: AArch64_LDNF1W_IMM_REAL
	AArch64_INS_ALIAS_LDNF1SB, // Real instr.: AArch64_LDNF1SB_D_IMM_REAL
	AArch64_INS_ALIAS_LDNF1D, // Real instr.: AArch64_LDNF1D_IMM_REAL
	AArch64_INS_ALIAS_LDFF1B, // Real instr.: AArch64_LDFF1B_H_REAL
	AArch64_INS_ALIAS_LDFF1SW, // Real instr.: AArch64_LDFF1SW_D_REAL
	AArch64_INS_ALIAS_LDFF1H, // Real instr.: AArch64_LDFF1H_REAL
	AArch64_INS_ALIAS_LDFF1SH, // Real instr.: AArch64_LDFF1SH_D_REAL
	AArch64_INS_ALIAS_LDFF1W, // Real instr.: AArch64_LDFF1W_REAL
	AArch64_INS_ALIAS_LDFF1SB, // Real instr.: AArch64_LDFF1SB_D_REAL
	AArch64_INS_ALIAS_LDFF1D, // Real instr.: AArch64_LDFF1D_REAL
	AArch64_INS_ALIAS_LD3B, // Real instr.: AArch64_LD3B_IMM
	AArch64_INS_ALIAS_LD4B, // Real instr.: AArch64_LD4B_IMM
	AArch64_INS_ALIAS_LD2H, // Real instr.: AArch64_LD2H_IMM
	AArch64_INS_ALIAS_LD3H, // Real instr.: AArch64_LD3H_IMM
	AArch64_INS_ALIAS_LD4H, // Real instr.: AArch64_LD4H_IMM
	AArch64_INS_ALIAS_LD2W, // Real instr.: AArch64_LD2W_IMM
	AArch64_INS_ALIAS_LD3W, // Real instr.: AArch64_LD3W_IMM
	AArch64_INS_ALIAS_LD4W, // Real instr.: AArch64_LD4W_IMM
	AArch64_INS_ALIAS_LD2D, // Real instr.: AArch64_LD2D_IMM
	AArch64_INS_ALIAS_LD3D, // Real instr.: AArch64_LD3D_IMM
	AArch64_INS_ALIAS_LD4D, // Real instr.: AArch64_LD4D_IMM
	AArch64_INS_ALIAS_LD2Q, // Real instr.: AArch64_LD2Q_IMM
	AArch64_INS_ALIAS_LD3Q, // Real instr.: AArch64_LD3Q_IMM
	AArch64_INS_ALIAS_LD4Q, // Real instr.: AArch64_LD4Q_IMM
	AArch64_INS_ALIAS_LDNT1H, // Real instr.: AArch64_LDNT1H_ZRI
	AArch64_INS_ALIAS_LDNT1W, // Real instr.: AArch64_LDNT1W_ZRI
	AArch64_INS_ALIAS_LDNT1D, // Real instr.: AArch64_LDNT1D_ZRI
	AArch64_INS_ALIAS_ST1B, // Real instr.: AArch64_ST1B_H_IMM
	AArch64_INS_ALIAS_ST1H, // Real instr.: AArch64_ST1H_IMM
	AArch64_INS_ALIAS_ST1W, // Real instr.: AArch64_ST1W_IMM
	AArch64_INS_ALIAS_ST1D, // Real instr.: AArch64_ST1D_IMM
	AArch64_INS_ALIAS_ST3B, // Real instr.: AArch64_ST3B_IMM
	AArch64_INS_ALIAS_ST4B, // Real instr.: AArch64_ST4B_IMM
	AArch64_INS_ALIAS_ST2H, // Real instr.: AArch64_ST2H_IMM
	AArch64_INS_ALIAS_ST3H, // Real instr.: AArch64_ST3H_IMM
	AArch64_INS_ALIAS_ST4H, // Real instr.: AArch64_ST4H_IMM
	AArch64_INS_ALIAS_ST2W, // Real instr.: AArch64_ST2W_IMM
	AArch64_INS_ALIAS_ST3W, // Real instr.: AArch64_ST3W_IMM
	AArch64_INS_ALIAS_ST4W, // Real instr.: AArch64_ST4W_IMM
	AArch64_INS_ALIAS_ST2D, // Real instr.: AArch64_ST2D_IMM
	AArch64_INS_ALIAS_ST3D, // Real instr.: AArch64_ST3D_IMM
	AArch64_INS_ALIAS_ST4D, // Real instr.: AArch64_ST4D_IMM
	AArch64_INS_ALIAS_ST3Q, // Real instr.: AArch64_ST3Q_IMM
	AArch64_INS_ALIAS_ST4Q, // Real instr.: AArch64_ST4Q_IMM
	AArch64_INS_ALIAS_STNT1H, // Real instr.: AArch64_STNT1H_ZRI
	AArch64_INS_ALIAS_STNT1W, // Real instr.: AArch64_STNT1W_ZRI
	AArch64_INS_ALIAS_STNT1D, // Real instr.: AArch64_STNT1D_ZRI
	AArch64_INS_ALIAS_PRFH, // Real instr.: AArch64_PRFH_PRI
	AArch64_INS_ALIAS_PRFW, // Real instr.: AArch64_PRFW_PRI
	AArch64_INS_ALIAS_PRFD, // Real instr.: AArch64_PRFD_PRI
	AArch64_INS_ALIAS_CNTH, // Real instr.: AArch64_CNTH_XPiI
	AArch64_INS_ALIAS_CNTW, // Real instr.: AArch64_CNTW_XPiI
	AArch64_INS_ALIAS_CNTD, // Real instr.: AArch64_CNTD_XPiI
	AArch64_INS_ALIAS_DECB, // Real instr.: AArch64_DECB_XPiI
	AArch64_INS_ALIAS_INCH, // Real instr.: AArch64_INCH_XPiI
	AArch64_INS_ALIAS_DECH, // Real instr.: AArch64_DECH_XPiI
	AArch64_INS_ALIAS_INCW, // Real instr.: AArch64_INCW_XPiI
	AArch64_INS_ALIAS_DECW, // Real instr.: AArch64_DECW_XPiI
	AArch64_INS_ALIAS_INCD, // Real instr.: AArch64_INCD_XPiI
	AArch64_INS_ALIAS_DECD, // Real instr.: AArch64_DECD_XPiI
	AArch64_INS_ALIAS_SQDECB, // Real instr.: AArch64_SQDECB_XPiWdI
	AArch64_INS_ALIAS_UQDECB, // Real instr.: AArch64_UQDECB_WPiI
	AArch64_INS_ALIAS_UQINCB, // Real instr.: AArch64_UQINCB_XPiI
	AArch64_INS_ALIAS_SQINCH, // Real instr.: AArch64_SQINCH_XPiWdI
	AArch64_INS_ALIAS_UQINCH, // Real instr.: AArch64_UQINCH_WPiI
	AArch64_INS_ALIAS_SQDECH, // Real instr.: AArch64_SQDECH_XPiWdI
	AArch64_INS_ALIAS_UQDECH, // Real instr.: AArch64_UQDECH_WPiI
	AArch64_INS_ALIAS_SQINCW, // Real instr.: AArch64_SQINCW_XPiWdI
	AArch64_INS_ALIAS_UQINCW, // Real instr.: AArch64_UQINCW_WPiI
	AArch64_INS_ALIAS_SQDECW, // Real instr.: AArch64_SQDECW_XPiWdI
	AArch64_INS_ALIAS_UQDECW, // Real instr.: AArch64_UQDECW_WPiI
	AArch64_INS_ALIAS_SQINCD, // Real instr.: AArch64_SQINCD_XPiWdI
	AArch64_INS_ALIAS_UQINCD, // Real instr.: AArch64_UQINCD_WPiI
	AArch64_INS_ALIAS_SQDECD, // Real instr.: AArch64_SQDECD_XPiWdI
	AArch64_INS_ALIAS_UQDECD, // Real instr.: AArch64_UQDECD_WPiI
	AArch64_INS_ALIAS_MOVS, // Real instr.: AArch64_ORRS_PPzPP
	AArch64_INS_ALIAS_NOT, // Real instr.: AArch64_EOR_PPzPP
	AArch64_INS_ALIAS_NOTS, // Real instr.: AArch64_EORS_PPzPP
	AArch64_INS_ALIAS_LD1ROH, // Real instr.: AArch64_LD1RO_H_IMM
	AArch64_INS_ALIAS_LD1ROW, // Real instr.: AArch64_LD1RO_W_IMM
	AArch64_INS_ALIAS_LD1ROD, // Real instr.: AArch64_LD1RO_D_IMM
	AArch64_INS_ALIAS_BCAX, // Real instr.: AArch64_BCAX_ZZZZ
	AArch64_INS_ALIAS_BSL, // Real instr.: AArch64_BSL_ZZZZ
	AArch64_INS_ALIAS_BSL1N, // Real instr.: AArch64_BSL1N_ZZZZ
	AArch64_INS_ALIAS_BSL2N, // Real instr.: AArch64_BSL2N_ZZZZ
	AArch64_INS_ALIAS_NBSL, // Real instr.: AArch64_NBSL_ZZZZ
	AArch64_INS_ALIAS_LDNT1B, // Real instr.: AArch64_LDNT1B_ZZR_S_REAL
	AArch64_INS_ALIAS_LDNT1SH, // Real instr.: AArch64_LDNT1SH_ZZR_S_REAL
	AArch64_INS_ALIAS_LDNT1SW, // Real instr.: AArch64_LDNT1SW_ZZR_D_REAL
	AArch64_INS_ALIAS_STNT1B, // Real instr.: AArch64_STNT1B_2Z_IMM
	AArch64_INS_ALIAS_LD1Q, // Real instr.: AArch64_LD1_MXIPXX_H_Q
	AArch64_INS_ALIAS_ST1Q, // Real instr.: AArch64_ST1_MXIPXX_H_Q
	AArch64_INS_ALIAS_SMSTART, // Real instr.: AArch64_MSRpstatesvcrImm1
	AArch64_INS_ALIAS_SMSTOP, // Real instr.: AArch64_MSRpstatesvcrImm1
	AArch64_INS_ALIAS_LDRAA, // Real instr.: AArch64_LDRAAindexed
	AArch64_INS_ALIAS_ADD, // Real instr.: AArch64_ADDWrs
	AArch64_INS_ALIAS_CMN, // Real instr.: AArch64_ADDSWri
	AArch64_INS_ALIAS_ADDS, // Real instr.: AArch64_ADDSWrs
	AArch64_INS_ALIAS_ANDS, // Real instr.: AArch64_ANDSWrs
	AArch64_INS_ALIAS_LDR, // Real instr.: AArch64_LDRXui
	AArch64_INS_ALIAS_STR, // Real instr.: AArch64_STRBui
	AArch64_INS_ALIAS_LDRB, // Real instr.: AArch64_LDRBBroX
	AArch64_INS_ALIAS_STRB, // Real instr.: AArch64_STRBBroX
	AArch64_INS_ALIAS_LDRH, // Real instr.: AArch64_LDRHHroX
	AArch64_INS_ALIAS_STRH, // Real instr.: AArch64_STRHHroX
	AArch64_INS_ALIAS_PRFM, // Real instr.: AArch64_PRFMroX
	AArch64_INS_ALIAS_LDAPURB, // Real instr.: AArch64_LDAPURBi
	AArch64_INS_ALIAS_STLURB, // Real instr.: AArch64_STLURBi
	AArch64_INS_ALIAS_LDUR, // Real instr.: AArch64_LDURXi
	AArch64_INS_ALIAS_STUR, // Real instr.: AArch64_STURXi
	AArch64_INS_ALIAS_PRFUM, // Real instr.: AArch64_PRFUMi
	AArch64_INS_ALIAS_LDTR, // Real instr.: AArch64_LDTRXi
	AArch64_INS_ALIAS_STTR, // Real instr.: AArch64_STTRWi
	AArch64_INS_ALIAS_LDP, // Real instr.: AArch64_LDPWi
	AArch64_INS_ALIAS_STGP, // Real instr.: AArch64_STGPi
	AArch64_INS_ALIAS_LDNP, // Real instr.: AArch64_LDNPWi
	AArch64_INS_ALIAS_STNP, // Real instr.: AArch64_STNPWi
	AArch64_INS_ALIAS_STG, // Real instr.: AArch64_STGOffset
	AArch64_INS_ALIAS_LD1, // Real instr.: AArch64_LD1Onev16b_POST
	AArch64_INS_ALIAS_LD1R, // Real instr.: AArch64_LD1Rv8b_POST
	AArch64_INS_ALIAS_STADDLB, // Real instr.: AArch64_LDADDLB
	AArch64_INS_ALIAS_STADDLH, // Real instr.: AArch64_LDADDLH
	AArch64_INS_ALIAS_STADDL, // Real instr.: AArch64_LDADDLW
	AArch64_INS_ALIAS_STADDB, // Real instr.: AArch64_LDADDB
	AArch64_INS_ALIAS_STADDH, // Real instr.: AArch64_LDADDH
	AArch64_INS_ALIAS_STADD, // Real instr.: AArch64_LDADDW
	AArch64_INS_ALIAS_PTRUE, // Real instr.: AArch64_PTRUE_B
	AArch64_INS_ALIAS_PTRUES, // Real instr.: AArch64_PTRUES_B
	AArch64_INS_ALIAS_CNTB, // Real instr.: AArch64_CNTB_XPiI
	AArch64_INS_ALIAS_INCB, // Real instr.: AArch64_INCB_XPiI
	AArch64_INS_ALIAS_SQINCB, // Real instr.: AArch64_SQINCB_XPiWdI
	AArch64_INS_ALIAS_ORR, // Real instr.: AArch64_ORR_ZI
	AArch64_INS_ALIAS_DUPM, // Real instr.: AArch64_DUPM_ZI
	AArch64_INS_ALIAS_FMOV, // Real instr.: AArch64_DUP_ZI_H
	AArch64_INS_ALIAS_EOR3, // Real instr.: AArch64_EOR3_ZZZZ
	AArch64_INS_ALIAS_ST2B, // Real instr.: AArch64_ST2B_IMM
	AArch64_INS_ALIAS_ST2Q, // Real instr.: AArch64_ST2Q_IMM
	AArch64_INS_ALIAS_LD1RQB, // Real instr.: AArch64_LD1RQ_B_IMM
	AArch64_INS_ALIAS_LD2B, // Real instr.: AArch64_LD2B_IMM
	AArch64_INS_ALIAS_PRFB, // Real instr.: AArch64_PRFB_PRI
	AArch64_INS_ALIAS_LDNT1SB, // Real instr.: AArch64_LDNT1SB_ZZR_S_REAL
	AArch64_INS_ALIAS_LD1ROB, // Real instr.: AArch64_LD1RO_B_IMM
	AArch64_INS_ALIAS_PMOV, // Real instr.: AArch64_PMOV_PZI_B
	AArch64_INS_ALIAS_ZERO, // Real instr.: AArch64_ZERO_M
	AArch64_INS_ALIAS_NOP, // Real instr.: AArch64_HINT
	AArch64_INS_ALIAS_YIELD, // Real instr.: AArch64_HINT
	AArch64_INS_ALIAS_WFE, // Real instr.: AArch64_HINT
	AArch64_INS_ALIAS_WFI, // Real instr.: AArch64_HINT
	AArch64_INS_ALIAS_SEV, // Real instr.: AArch64_HINT
	AArch64_INS_ALIAS_SEVL, // Real instr.: AArch64_HINT
	AArch64_INS_ALIAS_DGH, // Real instr.: AArch64_HINT
	AArch64_INS_ALIAS_ESB, // Real instr.: AArch64_HINT
	AArch64_INS_ALIAS_CSDB, // Real instr.: AArch64_HINT
	AArch64_INS_ALIAS_BTI, // Real instr.: AArch64_HINT
	AArch64_INS_ALIAS_PSB, // Real instr.: AArch64_HINT
	AArch64_INS_ALIAS_PACIAZ, // Real instr.: AArch64_PACIAZ
	AArch64_INS_ALIAS_PACIBZ, // Real instr.: AArch64_PACIBZ
	AArch64_INS_ALIAS_AUTIAZ, // Real instr.: AArch64_AUTIAZ
	AArch64_INS_ALIAS_AUTIBZ, // Real instr.: AArch64_AUTIBZ
	AArch64_INS_ALIAS_PACIASP, // Real instr.: AArch64_PACIASP
	AArch64_INS_ALIAS_PACIBSP, // Real instr.: AArch64_PACIBSP
	AArch64_INS_ALIAS_AUTIASP, // Real instr.: AArch64_AUTIASP
	AArch64_INS_ALIAS_AUTIBSP, // Real instr.: AArch64_AUTIBSP
	AArch64_INS_ALIAS_PACIA1716, // Real instr.: AArch64_PACIA1716
	AArch64_INS_ALIAS_PACIB1716, // Real instr.: AArch64_PACIB1716
	AArch64_INS_ALIAS_AUTIA1716, // Real instr.: AArch64_AUTIA1716
	AArch64_INS_ALIAS_AUTIB1716, // Real instr.: AArch64_AUTIB1716
	AArch64_INS_ALIAS_XPACLRI, // Real instr.: AArch64_XPACLRI
	AArch64_INS_ALIAS_LDRAB, // Real instr.: AArch64_LDRABindexed
	AArch64_INS_ALIAS_CLREX, // Real instr.: AArch64_CLREX
	AArch64_INS_ALIAS_ISB, // Real instr.: AArch64_ISB
	AArch64_INS_ALIAS_SSBB, // Real instr.: AArch64_DSB
	AArch64_INS_ALIAS_PSSBB, // Real instr.: AArch64_DSB
	AArch64_INS_ALIAS_DFB, // Real instr.: AArch64_DSB
	AArch64_INS_ALIAS_SYS, // Real instr.: AArch64_SYSxt
	AArch64_INS_ALIAS_MOVN, // Real instr.: AArch64_MOVNWi
	AArch64_INS_ALIAS_MOVZ, // Real instr.: AArch64_MOVZWi
	AArch64_INS_ALIAS_NGC, // Real instr.: AArch64_SBCWr
	AArch64_INS_ALIAS_NGCS, // Real instr.: AArch64_SBCSWr
	AArch64_INS_ALIAS_SUB, // Real instr.: AArch64_SUBWrs
	AArch64_INS_ALIAS_CMP, // Real instr.: AArch64_SUBSWri
	AArch64_INS_ALIAS_SUBS, // Real instr.: AArch64_SUBSWrs
	AArch64_INS_ALIAS_NEG, // Real instr.: AArch64_SUBWrs
	AArch64_INS_ALIAS_NEGS, // Real instr.: AArch64_SUBSWrs
	AArch64_INS_ALIAS_MUL, // Real instr.: AArch64_MADDWrrr
	AArch64_INS_ALIAS_MNEG, // Real instr.: AArch64_MSUBWrrr
	AArch64_INS_ALIAS_SMULL, // Real instr.: AArch64_SMADDLrrr
	AArch64_INS_ALIAS_SMNEGL, // Real instr.: AArch64_SMSUBLrrr
	AArch64_INS_ALIAS_UMULL, // Real instr.: AArch64_UMADDLrrr
	AArch64_INS_ALIAS_UMNEGL, // Real instr.: AArch64_UMSUBLrrr
	AArch64_INS_ALIAS_STCLRLB, // Real instr.: AArch64_LDCLRLB
	AArch64_INS_ALIAS_STCLRLH, // Real instr.: AArch64_LDCLRLH
	AArch64_INS_ALIAS_STCLRL, // Real instr.: AArch64_LDCLRLW
	AArch64_INS_ALIAS_STCLRB, // Real instr.: AArch64_LDCLRB
	AArch64_INS_ALIAS_STCLRH, // Real instr.: AArch64_LDCLRH
	AArch64_INS_ALIAS_STCLR, // Real instr.: AArch64_LDCLRW
	AArch64_INS_ALIAS_STEORLB, // Real instr.: AArch64_LDEORLB
	AArch64_INS_ALIAS_STEORLH, // Real instr.: AArch64_LDEORLH
	AArch64_INS_ALIAS_STEORL, // Real instr.: AArch64_LDEORLW
	AArch64_INS_ALIAS_STEORB, // Real instr.: AArch64_LDEORB
	AArch64_INS_ALIAS_STEORH, // Real instr.: AArch64_LDEORH
	AArch64_INS_ALIAS_STEOR, // Real instr.: AArch64_LDEORW
	AArch64_INS_ALIAS_STSETLB, // Real instr.: AArch64_LDSETLB
	AArch64_INS_ALIAS_STSETLH, // Real instr.: AArch64_LDSETLH
	AArch64_INS_ALIAS_STSETL, // Real instr.: AArch64_LDSETLW
	AArch64_INS_ALIAS_STSETB, // Real instr.: AArch64_LDSETB
	AArch64_INS_ALIAS_STSETH, // Real instr.: AArch64_LDSETH
	AArch64_INS_ALIAS_STSET, // Real instr.: AArch64_LDSETW
	AArch64_INS_ALIAS_STSMAXLB, // Real instr.: AArch64_LDSMAXLB
	AArch64_INS_ALIAS_STSMAXLH, // Real instr.: AArch64_LDSMAXLH
	AArch64_INS_ALIAS_STSMAXL, // Real instr.: AArch64_LDSMAXLW
	AArch64_INS_ALIAS_STSMAXB, // Real instr.: AArch64_LDSMAXB
	AArch64_INS_ALIAS_STSMAXH, // Real instr.: AArch64_LDSMAXH
	AArch64_INS_ALIAS_STSMAX, // Real instr.: AArch64_LDSMAXW
	AArch64_INS_ALIAS_STSMINLB, // Real instr.: AArch64_LDSMINLB
	AArch64_INS_ALIAS_STSMINLH, // Real instr.: AArch64_LDSMINLH
	AArch64_INS_ALIAS_STSMINL, // Real instr.: AArch64_LDSMINLW
	AArch64_INS_ALIAS_STSMINB, // Real instr.: AArch64_LDSMINB
	AArch64_INS_ALIAS_STSMINH, // Real instr.: AArch64_LDSMINH
	AArch64_INS_ALIAS_STSMIN, // Real instr.: AArch64_LDSMINW
	AArch64_INS_ALIAS_STUMAXLB, // Real instr.: AArch64_LDUMAXLB
	AArch64_INS_ALIAS_STUMAXLH, // Real instr.: AArch64_LDUMAXLH
	AArch64_INS_ALIAS_STUMAXL, // Real instr.: AArch64_LDUMAXLW
	AArch64_INS_ALIAS_STUMAXB, // Real instr.: AArch64_LDUMAXB
	AArch64_INS_ALIAS_STUMAXH, // Real instr.: AArch64_LDUMAXH
	AArch64_INS_ALIAS_STUMAX, // Real instr.: AArch64_LDUMAXW
	AArch64_INS_ALIAS_STUMINLB, // Real instr.: AArch64_LDUMINLB
	AArch64_INS_ALIAS_STUMINLH, // Real instr.: AArch64_LDUMINLH
	AArch64_INS_ALIAS_STUMINL, // Real instr.: AArch64_LDUMINLW
	AArch64_INS_ALIAS_STUMINB, // Real instr.: AArch64_LDUMINB
	AArch64_INS_ALIAS_STUMINH, // Real instr.: AArch64_LDUMINH
	AArch64_INS_ALIAS_STUMIN, // Real instr.: AArch64_LDUMINW
	AArch64_INS_ALIAS_IRG, // Real instr.: AArch64_IRG
	AArch64_INS_ALIAS_LDG, // Real instr.: AArch64_LDG
	AArch64_INS_ALIAS_STZG, // Real instr.: AArch64_STZGOffset
	AArch64_INS_ALIAS_ST2G, // Real instr.: AArch64_ST2GOffset
	AArch64_INS_ALIAS_STZ2G, // Real instr.: AArch64_STZ2GOffset
	AArch64_INS_ALIAS_BICS, // Real instr.: AArch64_BICSWrs
	AArch64_INS_ALIAS_BIC, // Real instr.: AArch64_BICWrs
	AArch64_INS_ALIAS_EON, // Real instr.: AArch64_EONWrs
	AArch64_INS_ALIAS_ORN, // Real instr.: AArch64_ORNWrs
	AArch64_INS_ALIAS_MVN, // Real instr.: AArch64_ORNWrs
	AArch64_INS_ALIAS_TST, // Real instr.: AArch64_ANDSWri
	AArch64_INS_ALIAS_ROR, // Real instr.: AArch64_EXTRWrri
	AArch64_INS_ALIAS_ASR, // Real instr.: AArch64_SBFMWri
	AArch64_INS_ALIAS_SXTB, // Real instr.: AArch64_SBFMWri
	AArch64_INS_ALIAS_SXTH, // Real instr.: AArch64_SBFMWri
	AArch64_INS_ALIAS_SXTW, // Real instr.: AArch64_SBFMXri
	AArch64_INS_ALIAS_LSR, // Real instr.: AArch64_UBFMWri
	AArch64_INS_ALIAS_UXTB, // Real instr.: AArch64_UBFMWri
	AArch64_INS_ALIAS_UXTH, // Real instr.: AArch64_UBFMWri
	AArch64_INS_ALIAS_UXTW, // Real instr.: AArch64_UBFMXri
	AArch64_INS_ALIAS_CSET, // Real instr.: AArch64_CSINCWr
	AArch64_INS_ALIAS_CSETM, // Real instr.: AArch64_CSINVWr
	AArch64_INS_ALIAS_CINC, // Real instr.: AArch64_CSINCWr
	AArch64_INS_ALIAS_CINV, // Real instr.: AArch64_CSINVWr
	AArch64_INS_ALIAS_CNEG, // Real instr.: AArch64_CSNEGWr
	AArch64_INS_ALIAS_RET, // Real instr.: AArch64_RET
	AArch64_INS_ALIAS_DCPS1, // Real instr.: AArch64_DCPS1
	AArch64_INS_ALIAS_DCPS2, // Real instr.: AArch64_DCPS2
	AArch64_INS_ALIAS_DCPS3, // Real instr.: AArch64_DCPS3
	AArch64_INS_ALIAS_LDPSW, // Real instr.: AArch64_LDPSWi
	AArch64_INS_ALIAS_LDRSH, // Real instr.: AArch64_LDRSHWroX
	AArch64_INS_ALIAS_LDRSB, // Real instr.: AArch64_LDRSBWroX
	AArch64_INS_ALIAS_LDRSW, // Real instr.: AArch64_LDRSWroX
	AArch64_INS_ALIAS_LDURH, // Real instr.: AArch64_LDURHHi
	AArch64_INS_ALIAS_LDURB, // Real instr.: AArch64_LDURBBi
	AArch64_INS_ALIAS_LDURSH, // Real instr.: AArch64_LDURSHWi
	AArch64_INS_ALIAS_LDURSB, // Real instr.: AArch64_LDURSBWi
	AArch64_INS_ALIAS_LDURSW, // Real instr.: AArch64_LDURSWi
	AArch64_INS_ALIAS_LDTRH, // Real instr.: AArch64_LDTRHi
	AArch64_INS_ALIAS_LDTRB, // Real instr.: AArch64_LDTRBi
	AArch64_INS_ALIAS_LDTRSH, // Real instr.: AArch64_LDTRSHWi
	AArch64_INS_ALIAS_LDTRSB, // Real instr.: AArch64_LDTRSBWi
	AArch64_INS_ALIAS_LDTRSW, // Real instr.: AArch64_LDTRSWi
	AArch64_INS_ALIAS_STP, // Real instr.: AArch64_STPWi
	AArch64_INS_ALIAS_STURH, // Real instr.: AArch64_STURHHi
	AArch64_INS_ALIAS_STURB, // Real instr.: AArch64_STURBBi
	AArch64_INS_ALIAS_STLURH, // Real instr.: AArch64_STLURHi
	AArch64_INS_ALIAS_LDAPURSB, // Real instr.: AArch64_LDAPURSBWi
	AArch64_INS_ALIAS_LDAPURH, // Real instr.: AArch64_LDAPURHi
	AArch64_INS_ALIAS_LDAPURSH, // Real instr.: AArch64_LDAPURSHWi
	AArch64_INS_ALIAS_LDAPURSW, // Real instr.: AArch64_LDAPURSWi
	AArch64_INS_ALIAS_STTRH, // Real instr.: AArch64_STTRHi
	AArch64_INS_ALIAS_STTRB, // Real instr.: AArch64_STTRBi
	AArch64_INS_ALIAS_BIC_4H, // Real instr.: AArch64_BICv4i16
	AArch64_INS_ALIAS_BIC_8H, // Real instr.: AArch64_BICv8i16
	AArch64_INS_ALIAS_BIC_2S, // Real instr.: AArch64_BICv2i32
	AArch64_INS_ALIAS_BIC_4S, // Real instr.: AArch64_BICv4i32
	AArch64_INS_ALIAS_ORR_4H, // Real instr.: AArch64_ORRv4i16
	AArch64_INS_ALIAS_ORR_8H, // Real instr.: AArch64_ORRv8i16
	AArch64_INS_ALIAS_ORR_2S, // Real instr.: AArch64_ORRv2i32
	AArch64_INS_ALIAS_ORR_4S, // Real instr.: AArch64_ORRv4i32
	AArch64_INS_ALIAS_SXTL_8H, // Real instr.: AArch64_SSHLLv8i8_shift
	AArch64_INS_ALIAS_SXTL, // Real instr.: AArch64_SSHLLv8i8_shift
	AArch64_INS_ALIAS_SXTL_4S, // Real instr.: AArch64_SSHLLv4i16_shift
	AArch64_INS_ALIAS_SXTL_2D, // Real instr.: AArch64_SSHLLv2i32_shift
	AArch64_INS_ALIAS_SXTL2_8H, // Real instr.: AArch64_SSHLLv16i8_shift
	AArch64_INS_ALIAS_SXTL2, // Real instr.: AArch64_SSHLLv16i8_shift
	AArch64_INS_ALIAS_SXTL2_4S, // Real instr.: AArch64_SSHLLv8i16_shift
	AArch64_INS_ALIAS_SXTL2_2D, // Real instr.: AArch64_SSHLLv4i32_shift
	AArch64_INS_ALIAS_UXTL_8H, // Real instr.: AArch64_USHLLv8i8_shift
	AArch64_INS_ALIAS_UXTL, // Real instr.: AArch64_USHLLv8i8_shift
	AArch64_INS_ALIAS_UXTL_4S, // Real instr.: AArch64_USHLLv4i16_shift
	AArch64_INS_ALIAS_UXTL_2D, // Real instr.: AArch64_USHLLv2i32_shift
	AArch64_INS_ALIAS_UXTL2_8H, // Real instr.: AArch64_USHLLv16i8_shift
	AArch64_INS_ALIAS_UXTL2, // Real instr.: AArch64_USHLLv16i8_shift
	AArch64_INS_ALIAS_UXTL2_4S, // Real instr.: AArch64_USHLLv8i16_shift
	AArch64_INS_ALIAS_UXTL2_2D, // Real instr.: AArch64_USHLLv4i32_shift
	AArch64_INS_ALIAS_LD2, // Real instr.: AArch64_LD2Twov16b_POST
	AArch64_INS_ALIAS_LD3, // Real instr.: AArch64_LD3Threev16b_POST
	AArch64_INS_ALIAS_LD4, // Real instr.: AArch64_LD4Fourv16b_POST
	AArch64_INS_ALIAS_ST1, // Real instr.: AArch64_ST1Onev16b_POST
	AArch64_INS_ALIAS_ST2, // Real instr.: AArch64_ST2Twov16b_POST
	AArch64_INS_ALIAS_ST3, // Real instr.: AArch64_ST3Threev16b_POST
	AArch64_INS_ALIAS_ST4, // Real instr.: AArch64_ST4Fourv16b_POST
	AArch64_INS_ALIAS_LD2R, // Real instr.: AArch64_LD2Rv8b_POST
	AArch64_INS_ALIAS_LD3R, // Real instr.: AArch64_LD3Rv8b_POST
	AArch64_INS_ALIAS_LD4R, // Real instr.: AArch64_LD4Rv8b_POST
	AArch64_INS_ALIAS_CLRBHB, // Real instr.: AArch64_HINT
	AArch64_INS_ALIAS_STILP, // Real instr.: AArch64_STILPW
	AArch64_INS_ALIAS_STL1, // Real instr.: AArch64_STL1
	AArch64_INS_ALIAS_SYSP, // Real instr.: AArch64_SYSPxt_XZR

	// clang-format on
	// generated content <AArch64GenCSAliasEnum.inc> end

	// Hardcoded in LLVM printer
	AArch64_INS_ALIAS_CFP,
	AArch64_INS_ALIAS_DVP,
	AArch64_INS_ALIAS_COSP,
	AArch64_INS_ALIAS_CPP,
	AArch64_INS_ALIAS_IC,
	AArch64_INS_ALIAS_DC,
	AArch64_INS_ALIAS_AT,
	AArch64_INS_ALIAS_TLBI,
	AArch64_INS_ALIAS_TLBIP,
	AArch64_INS_ALIAS_RPRFM,
	AArch64_INS_ALIAS_LSL,
	AArch64_INS_ALIAS_SBFX,
	AArch64_INS_ALIAS_UBFX,
	AArch64_INS_ALIAS_SBFIZ,
	AArch64_INS_ALIAS_UBFIZ,
	AArch64_INS_ALIAS_BFC,
	AArch64_INS_ALIAS_BFI,
	AArch64_INS_ALIAS_BFXIL,

	AArch64_INS_ALIAS_END,
} aarch64_insn;

/// Group of AArch64 instructions
typedef enum aarch64_insn_group {
  AArch64_GRP_INVALID = 0, ///< = CS_GRP_INVALID

  // Generic groups
  // all jump instructions (conditional+direct+indirect jumps)
  AArch64_GRP_JUMP, ///< = CS_GRP_JUMP
  AArch64_GRP_CALL,
  AArch64_GRP_RET,
  AArch64_GRP_INT,
  AArch64_GRP_PRIVILEGE = 6,   ///< = CS_GRP_PRIVILEGE
  AArch64_GRP_BRANCH_RELATIVE, ///< = CS_GRP_BRANCH_RELATIVE
	// generated content <AArch64GenCSFeatureEnum.inc> begin
	// clang-format off

	AArch64_FEATURE_HasV8_0a = 128,
	AArch64_FEATURE_HasV8_1a,
	AArch64_FEATURE_HasV8_2a,
	AArch64_FEATURE_HasV8_3a,
	AArch64_FEATURE_HasV8_4a,
	AArch64_FEATURE_HasV8_5a,
	AArch64_FEATURE_HasV8_6a,
	AArch64_FEATURE_HasV8_7a,
	AArch64_FEATURE_HasV8_8a,
	AArch64_FEATURE_HasV8_9a,
	AArch64_FEATURE_HasV9_0a,
	AArch64_FEATURE_HasV9_1a,
	AArch64_FEATURE_HasV9_2a,
	AArch64_FEATURE_HasV9_3a,
	AArch64_FEATURE_HasV9_4a,
	AArch64_FEATURE_HasV8_0r,
	AArch64_FEATURE_HasEL2VMSA,
	AArch64_FEATURE_HasEL3,
	AArch64_FEATURE_HasVH,
	AArch64_FEATURE_HasLOR,
	AArch64_FEATURE_HasPAuth,
	AArch64_FEATURE_HasJS,
	AArch64_FEATURE_HasCCIDX,
	AArch64_FEATURE_HasComplxNum,
	AArch64_FEATURE_HasNV,
	AArch64_FEATURE_HasMPAM,
	AArch64_FEATURE_HasDIT,
	AArch64_FEATURE_HasTRACEV8_4,
	AArch64_FEATURE_HasAM,
	AArch64_FEATURE_HasSEL2,
	AArch64_FEATURE_HasTLB_RMI,
	AArch64_FEATURE_HasFlagM,
	AArch64_FEATURE_HasRCPC_IMMO,
	AArch64_FEATURE_HasFPARMv8,
	AArch64_FEATURE_HasNEON,
	AArch64_FEATURE_HasCrypto,
	AArch64_FEATURE_HasSM4,
	AArch64_FEATURE_HasSHA3,
	AArch64_FEATURE_HasSHA2,
	AArch64_FEATURE_HasAES,
	AArch64_FEATURE_HasDotProd,
	AArch64_FEATURE_HasCRC,
	AArch64_FEATURE_HasCSSC,
	AArch64_FEATURE_HasLSE,
	AArch64_FEATURE_HasRAS,
	AArch64_FEATURE_HasRDM,
	AArch64_FEATURE_HasFullFP16,
	AArch64_FEATURE_HasFP16FML,
	AArch64_FEATURE_HasSPE,
	AArch64_FEATURE_HasFuseAES,
	AArch64_FEATURE_HasSVE,
	AArch64_FEATURE_HasSVE2,
	AArch64_FEATURE_HasSVE2p1,
	AArch64_FEATURE_HasSVE2AES,
	AArch64_FEATURE_HasSVE2SM4,
	AArch64_FEATURE_HasSVE2SHA3,
	AArch64_FEATURE_HasSVE2BitPerm,
	AArch64_FEATURE_HasB16B16,
	AArch64_FEATURE_HasSME,
	AArch64_FEATURE_HasSMEF64F64,
	AArch64_FEATURE_HasSMEF16F16,
	AArch64_FEATURE_HasSMEI16I64,
	AArch64_FEATURE_HasSME2,
	AArch64_FEATURE_HasSME2p1,
	AArch64_FEATURE_HasSVEorSME,
	AArch64_FEATURE_HasSVE2orSME,
	AArch64_FEATURE_HasSVE2p1_or_HasSME,
	AArch64_FEATURE_HasSVE2p1_or_HasSME2,
	AArch64_FEATURE_HasSVE2p1_or_HasSME2p1,
	AArch64_FEATURE_HasNEONorSME,
	AArch64_FEATURE_HasRCPC,
	AArch64_FEATURE_HasAltNZCV,
	AArch64_FEATURE_HasFRInt3264,
	AArch64_FEATURE_HasSB,
	AArch64_FEATURE_HasPredRes,
	AArch64_FEATURE_HasCCDP,
	AArch64_FEATURE_HasBTI,
	AArch64_FEATURE_HasMTE,
	AArch64_FEATURE_HasTME,
	AArch64_FEATURE_HasETE,
	AArch64_FEATURE_HasTRBE,
	AArch64_FEATURE_HasBF16,
	AArch64_FEATURE_HasMatMulInt8,
	AArch64_FEATURE_HasMatMulFP32,
	AArch64_FEATURE_HasMatMulFP64,
	AArch64_FEATURE_HasXS,
	AArch64_FEATURE_HasWFxT,
	AArch64_FEATURE_HasLS64,
	AArch64_FEATURE_HasBRBE,
	AArch64_FEATURE_HasSPE_EEF,
	AArch64_FEATURE_HasHBC,
	AArch64_FEATURE_HasMOPS,
	AArch64_FEATURE_HasCLRBHB,
	AArch64_FEATURE_HasSPECRES2,
	AArch64_FEATURE_HasITE,
	AArch64_FEATURE_HasTHE,
	AArch64_FEATURE_HasRCPC3,
	AArch64_FEATURE_HasLSE128,
	AArch64_FEATURE_HasD128,
	AArch64_FEATURE_UseNegativeImmediates,
	AArch64_FEATURE_HasCCPP,
	AArch64_FEATURE_HasPAN,
	AArch64_FEATURE_HasPsUAO,
	AArch64_FEATURE_HasPAN_RWV,
	AArch64_FEATURE_HasCONTEXTIDREL2,

	// clang-format on
	// generated content <AArch64GenCSFeatureEnum.inc> end

  AArch64_GRP_ENDING, // <-- mark the end of the list of groups
} aarch64_insn_group;

#ifdef __cplusplus
}
#endif

#endif

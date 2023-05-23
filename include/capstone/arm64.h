#ifndef CAPSTONE_ARM64_H
#define CAPSTONE_ARM64_H

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifdef __cplusplus
extern "C" {
#endif

#include "platform.h"

#ifdef _MSC_VER
#pragma warning(disable : 4201)
#endif

/// ARM64 shift type
typedef enum arm64_shifter {
  ARM64_SFT_INVALID = 0,
  ARM64_SFT_LSL = 1,
  ARM64_SFT_MSL = 2,
  ARM64_SFT_LSR = 3,
  ARM64_SFT_ASR = 4,
  ARM64_SFT_ROR = 5,
} arm64_shifter;

/// ARM64 extender type
typedef enum arm64_extender {
  ARM64_EXT_INVALID = 0,
  ARM64_EXT_UXTB = 1,
  ARM64_EXT_UXTH = 2,
  ARM64_EXT_UXTW = 3,
  ARM64_EXT_UXTX = 4,
  ARM64_EXT_SXTB = 5,
  ARM64_EXT_SXTH = 6,
  ARM64_EXT_SXTW = 7,
  ARM64_EXT_SXTX = 8,
} arm64_extender;

/// ARM64 condition code
typedef enum arm64_cc {
  ARM64_CC_INVALID = 0,
  ARM64_CC_EQ = 1,  ///< Equal
  ARM64_CC_NE = 2,  ///< Not equal:                 Not equal, or unordered
  ARM64_CC_HS = 3,  ///< Unsigned higher or same:   >, ==, or unordered
  ARM64_CC_LO = 4,  ///< Unsigned lower or same:    Less than
  ARM64_CC_MI = 5,  ///< Minus, negative:           Less than
  ARM64_CC_PL = 6,  ///< Plus, positive or zero:    >, ==, or unordered
  ARM64_CC_VS = 7,  ///< Overflow:                  Unordered
  ARM64_CC_VC = 8,  ///< No overflow:               Ordered
  ARM64_CC_HI = 9,  ///< Unsigned higher:           Greater than, or unordered
  ARM64_CC_LS = 10, ///< Unsigned lower or same:    Less than or equal
  ARM64_CC_GE = 11, ///< Greater than or equal:     Greater than or equal
  ARM64_CC_LT = 12, ///< Less than:                 Less than, or unordered
  ARM64_CC_GT = 13, ///< Signed greater than:       Greater than
  ARM64_CC_LE = 14, ///< Signed less than or equal: <, ==, or unordered
  ARM64_CC_AL = 15, ///< Always (unconditional):    Always (unconditional)
  ARM64_CC_NV = 16, ///< Always (unconditional):   Always (unconditional)
  //< Note the NV exists purely to disassemble 0b1111. Execution is "always".
} arm64_cc;

/// System registers
typedef enum arm64_sysreg {
	// generated content <AArch64GenCSSystemRegisterEnum.inc> begin
	// clang-format off

	AARCH64_SYSREG_S1E1R = 0x3c0, // Group: ATValues
	AARCH64_SYSREG_S1E2R = 0x23c0, // Group: ATValues
	AARCH64_SYSREG_S1E3R = 0x33c0, // Group: ATValues
	AARCH64_SYSREG_S1E1W = 0x3c1, // Group: ATValues
	AARCH64_SYSREG_S1E2W = 0x23c1, // Group: ATValues
	AARCH64_SYSREG_S1E3W = 0x33c1, // Group: ATValues
	AARCH64_SYSREG_S1E0R = 0x3c2, // Group: ATValues
	AARCH64_SYSREG_S1E0W = 0x3c3, // Group: ATValues
	AARCH64_SYSREG_S12E1R = 0x23c4, // Group: ATValues
	AARCH64_SYSREG_S12E1W = 0x23c5, // Group: ATValues
	AARCH64_SYSREG_S12E0R = 0x23c6, // Group: ATValues
	AARCH64_SYSREG_S12E0W = 0x23c7, // Group: ATValues
	AARCH64_SYSREG_S1E1RP = 0x3c8, // Group: ATValues
	AARCH64_SYSREG_S1E1WP = 0x3c9, // Group: ATValues
	AARCH64_SYSREG_C = 0x2, // Group: BTIValues
	AARCH64_SYSREG_J = 0x4, // Group: BTIValues
	AARCH64_SYSREG_JC = 0x6, // Group: BTIValues
	AARCH64_SYSREG_OSHLD = 0x1, // Group: DBValues
	AARCH64_SYSREG_OSHST = 0x2, // Group: DBValues
	AARCH64_SYSREG_OSH = 0x3, // Group: DBValues
	AARCH64_SYSREG_NSHLD = 0x5, // Group: DBValues
	AARCH64_SYSREG_NSHST = 0x6, // Group: DBValues
	AARCH64_SYSREG_NSH = 0x7, // Group: DBValues
	AARCH64_SYSREG_ISHLD = 0x9, // Group: DBValues
	AARCH64_SYSREG_ISHST = 0xa, // Group: DBValues
	AARCH64_SYSREG_ISH = 0xb, // Group: DBValues
	AARCH64_SYSREG_LD = 0xd, // Group: DBValues
	AARCH64_SYSREG_ST = 0xe, // Group: DBValues
	AARCH64_SYSREG_SY = 0xf, // Group: DBValues
	AARCH64_SYSREG_OSHNXS = 0x3, // Group: DBnXSValues
	AARCH64_SYSREG_NSHNXS = 0x7, // Group: DBnXSValues
	AARCH64_SYSREG_ISHNXS = 0xb, // Group: DBnXSValues
	AARCH64_SYSREG_SYNXS = 0xf, // Group: DBnXSValues
	AARCH64_SYSREG_ZVA = 0x1ba1, // Group: DCValues
	AARCH64_SYSREG_IVAC = 0x3b1, // Group: DCValues
	AARCH64_SYSREG_ISW = 0x3b2, // Group: DCValues
	AARCH64_SYSREG_CVAC = 0x1bd1, // Group: DCValues
	AARCH64_SYSREG_CSW = 0x3d2, // Group: DCValues
	AARCH64_SYSREG_CVAU = 0x1bd9, // Group: DCValues
	AARCH64_SYSREG_CIVAC = 0x1bf1, // Group: DCValues
	AARCH64_SYSREG_CISW = 0x3f2, // Group: DCValues
	AARCH64_SYSREG_CVAP = 0x1be1, // Group: DCValues
	AARCH64_SYSREG_CVADP = 0x1be9, // Group: DCValues
	AARCH64_SYSREG_IGVAC = 0x3b3, // Group: DCValues
	AARCH64_SYSREG_IGSW = 0x3b4, // Group: DCValues
	AARCH64_SYSREG_CGSW = 0x3d4, // Group: DCValues
	AARCH64_SYSREG_CIGSW = 0x3f4, // Group: DCValues
	AARCH64_SYSREG_CGVAC = 0x1bd3, // Group: DCValues
	AARCH64_SYSREG_CGVAP = 0x1be3, // Group: DCValues
	AARCH64_SYSREG_CGVADP = 0x1beb, // Group: DCValues
	AARCH64_SYSREG_CIGVAC = 0x1bf3, // Group: DCValues
	AARCH64_SYSREG_GVA = 0x1ba3, // Group: DCValues
	AARCH64_SYSREG_IGDVAC = 0x3b5, // Group: DCValues
	AARCH64_SYSREG_IGDSW = 0x3b6, // Group: DCValues
	AARCH64_SYSREG_CGDSW = 0x3d6, // Group: DCValues
	AARCH64_SYSREG_CIGDSW = 0x3f6, // Group: DCValues
	AARCH64_SYSREG_CGDVAC = 0x1bd5, // Group: DCValues
	AARCH64_SYSREG_CGDVAP = 0x1be5, // Group: DCValues
	AARCH64_SYSREG_CGDVADP = 0x1bed, // Group: DCValues
	AARCH64_SYSREG_CIGDVAC = 0x1bf5, // Group: DCValues
	AARCH64_SYSREG_GZVA = 0x1ba4, // Group: DCValues
	AARCH64_SYSREG_CIPAE = 0x23f0, // Group: DCValues
	AARCH64_SYSREG_CIGDPAE = 0x23f7, // Group: DCValues
	AARCH64_SYSREG_ZERO = 0x0, // Group: ExactFPImmValues
	AARCH64_SYSREG_HALF = 0x1, // Group: ExactFPImmValues
	AARCH64_SYSREG_ONE = 0x2, // Group: ExactFPImmValues
	AARCH64_SYSREG_TWO = 0x3, // Group: ExactFPImmValues
	AARCH64_SYSREG_IALLUIS = 0x388, // Group: ICValues
	AARCH64_SYSREG_IALLU = 0x3a8, // Group: ICValues
	AARCH64_SYSREG_IVAU = 0x1ba9, // Group: ICValues
	AARCH64_SYSREG_SY_ISBValues = 0xf, // Group: ISBValues - also encoded as: AARCH64_SYSREG_SY
	AARCH64_SYSREG_PLDL1KEEP = 0x0, // Group: PRFMValues
	AARCH64_SYSREG_PLDL1STRM = 0x1, // Group: PRFMValues
	AARCH64_SYSREG_PLDL2KEEP = 0x2, // Group: PRFMValues
	AARCH64_SYSREG_PLDL2STRM = 0x3, // Group: PRFMValues
	AARCH64_SYSREG_PLDL3KEEP = 0x4, // Group: PRFMValues
	AARCH64_SYSREG_PLDL3STRM = 0x5, // Group: PRFMValues
	AARCH64_SYSREG_PLDSLCKEEP = 0x6, // Group: PRFMValues
	AARCH64_SYSREG_PLDSLCSTRM = 0x7, // Group: PRFMValues
	AARCH64_SYSREG_PLIL1KEEP = 0x8, // Group: PRFMValues
	AARCH64_SYSREG_PLIL1STRM = 0x9, // Group: PRFMValues
	AARCH64_SYSREG_PLIL2KEEP = 0xa, // Group: PRFMValues
	AARCH64_SYSREG_PLIL2STRM = 0xb, // Group: PRFMValues
	AARCH64_SYSREG_PLIL3KEEP = 0xc, // Group: PRFMValues
	AARCH64_SYSREG_PLIL3STRM = 0xd, // Group: PRFMValues
	AARCH64_SYSREG_PLISLCKEEP = 0xe, // Group: PRFMValues
	AARCH64_SYSREG_PLISLCSTRM = 0xf, // Group: PRFMValues
	AARCH64_SYSREG_PSTL1KEEP = 0x10, // Group: PRFMValues
	AARCH64_SYSREG_PSTL1STRM = 0x11, // Group: PRFMValues
	AARCH64_SYSREG_PSTL2KEEP = 0x12, // Group: PRFMValues
	AARCH64_SYSREG_PSTL2STRM = 0x13, // Group: PRFMValues
	AARCH64_SYSREG_PSTL3KEEP = 0x14, // Group: PRFMValues
	AARCH64_SYSREG_PSTL3STRM = 0x15, // Group: PRFMValues
	AARCH64_SYSREG_PSTSLCKEEP = 0x16, // Group: PRFMValues
	AARCH64_SYSREG_PSTSLCSTRM = 0x17, // Group: PRFMValues
	AARCH64_SYSREG_CSYNC = 0x11, // Group: PSBValues
	AARCH64_SYSREG_ALLINT = 0x8, // Group: PStateImm0_1Values
	AARCH64_SYSREG_PM = 0x48, // Group: PStateImm0_1Values
	AARCH64_SYSREG_SPSEL = 0x5, // Group: PStateImm0_15Values
	AARCH64_SYSREG_DAIFSET = 0x1e, // Group: PStateImm0_15Values
	AARCH64_SYSREG_DAIFCLR = 0x1f, // Group: PStateImm0_15Values
	AARCH64_SYSREG_PAN = 0x4, // Group: PStateImm0_15Values
	AARCH64_SYSREG_UAO = 0x3, // Group: PStateImm0_15Values
	AARCH64_SYSREG_DIT = 0x1a, // Group: PStateImm0_15Values
	AARCH64_SYSREG_SSBS = 0x19, // Group: PStateImm0_15Values
	AARCH64_SYSREG_TCO = 0x1c, // Group: PStateImm0_15Values
	AARCH64_SYSREG_PLDKEEP = 0x0, // Group: RPRFMValues
	AARCH64_SYSREG_PSTKEEP = 0x1, // Group: RPRFMValues
	AARCH64_SYSREG_PLDSTRM = 0x4, // Group: RPRFMValues
	AARCH64_SYSREG_PSTSTRM = 0x5, // Group: RPRFMValues
	AARCH64_SYSREG_SVCRSM = 0x1, // Group: SVCRValues
	AARCH64_SYSREG_SVCRZA = 0x2, // Group: SVCRValues
	AARCH64_SYSREG_SVCRSMZA = 0x3, // Group: SVCRValues
	AARCH64_SYSREG_POW2 = 0x0, // Group: SVEPREDPATValues
	AARCH64_SYSREG_VL1 = 0x1, // Group: SVEPREDPATValues
	AARCH64_SYSREG_VL2 = 0x2, // Group: SVEPREDPATValues
	AARCH64_SYSREG_VL3 = 0x3, // Group: SVEPREDPATValues
	AARCH64_SYSREG_VL4 = 0x4, // Group: SVEPREDPATValues
	AARCH64_SYSREG_VL5 = 0x5, // Group: SVEPREDPATValues
	AARCH64_SYSREG_VL6 = 0x6, // Group: SVEPREDPATValues
	AARCH64_SYSREG_VL7 = 0x7, // Group: SVEPREDPATValues
	AARCH64_SYSREG_VL8 = 0x8, // Group: SVEPREDPATValues
	AARCH64_SYSREG_VL16 = 0x9, // Group: SVEPREDPATValues
	AARCH64_SYSREG_VL32 = 0xa, // Group: SVEPREDPATValues
	AARCH64_SYSREG_VL64 = 0xb, // Group: SVEPREDPATValues
	AARCH64_SYSREG_VL128 = 0xc, // Group: SVEPREDPATValues
	AARCH64_SYSREG_VL256 = 0xd, // Group: SVEPREDPATValues
	AARCH64_SYSREG_MUL4 = 0x1d, // Group: SVEPREDPATValues
	AARCH64_SYSREG_MUL3 = 0x1e, // Group: SVEPREDPATValues
	AARCH64_SYSREG_ALL = 0x1f, // Group: SVEPREDPATValues
	AARCH64_SYSREG_PLDL1KEEP_SVEPRFMValues = 0x0, // Group: SVEPRFMValues - also encoded as: AARCH64_SYSREG_PLDL1KEEP
	AARCH64_SYSREG_PLDL1STRM_SVEPRFMValues = 0x1, // Group: SVEPRFMValues - also encoded as: AARCH64_SYSREG_PLDL1STRM
	AARCH64_SYSREG_PLDL2KEEP_SVEPRFMValues = 0x2, // Group: SVEPRFMValues - also encoded as: AARCH64_SYSREG_PLDL2KEEP
	AARCH64_SYSREG_PLDL2STRM_SVEPRFMValues = 0x3, // Group: SVEPRFMValues - also encoded as: AARCH64_SYSREG_PLDL2STRM
	AARCH64_SYSREG_PLDL3KEEP_SVEPRFMValues = 0x4, // Group: SVEPRFMValues - also encoded as: AARCH64_SYSREG_PLDL3KEEP
	AARCH64_SYSREG_PLDL3STRM_SVEPRFMValues = 0x5, // Group: SVEPRFMValues - also encoded as: AARCH64_SYSREG_PLDL3STRM
	AARCH64_SYSREG_PSTL1KEEP_SVEPRFMValues = 0x8, // Group: SVEPRFMValues - also encoded as: AARCH64_SYSREG_PSTL1KEEP
	AARCH64_SYSREG_PSTL1STRM_SVEPRFMValues = 0x9, // Group: SVEPRFMValues - also encoded as: AARCH64_SYSREG_PSTL1STRM
	AARCH64_SYSREG_PSTL2KEEP_SVEPRFMValues = 0xa, // Group: SVEPRFMValues - also encoded as: AARCH64_SYSREG_PSTL2KEEP
	AARCH64_SYSREG_PSTL2STRM_SVEPRFMValues = 0xb, // Group: SVEPRFMValues - also encoded as: AARCH64_SYSREG_PSTL2STRM
	AARCH64_SYSREG_PSTL3KEEP_SVEPRFMValues = 0xc, // Group: SVEPRFMValues - also encoded as: AARCH64_SYSREG_PSTL3KEEP
	AARCH64_SYSREG_PSTL3STRM_SVEPRFMValues = 0xd, // Group: SVEPRFMValues - also encoded as: AARCH64_SYSREG_PSTL3STRM
	AARCH64_SYSREG_VLX2 = 0x0, // Group: SVEVECLENSPECIFIERValues
	AARCH64_SYSREG_VLX4 = 0x1, // Group: SVEVECLENSPECIFIERValues
	AARCH64_SYSREG_MDCCSR_EL0 = 0x9808, // Group: SysRegValues
	AARCH64_SYSREG_DBGDTRRX_EL0 = 0x9828, // Group: SysRegValues
	AARCH64_SYSREG_MDRAR_EL1 = 0x8080, // Group: SysRegValues
	AARCH64_SYSREG_OSLSR_EL1 = 0x808c, // Group: SysRegValues
	AARCH64_SYSREG_DBGAUTHSTATUS_EL1 = 0x83f6, // Group: SysRegValues
	AARCH64_SYSREG_PMCEID0_EL0 = 0xdce6, // Group: SysRegValues
	AARCH64_SYSREG_PMCEID1_EL0 = 0xdce7, // Group: SysRegValues
	AARCH64_SYSREG_PMMIR_EL1 = 0xc4f6, // Group: SysRegValues
	AARCH64_SYSREG_MIDR_EL1 = 0xc000, // Group: SysRegValues
	AARCH64_SYSREG_CCSIDR_EL1 = 0xc800, // Group: SysRegValues
	AARCH64_SYSREG_CCSIDR2_EL1 = 0xc802, // Group: SysRegValues
	AARCH64_SYSREG_CLIDR_EL1 = 0xc801, // Group: SysRegValues
	AARCH64_SYSREG_CTR_EL0 = 0xd801, // Group: SysRegValues
	AARCH64_SYSREG_MPIDR_EL1 = 0xc005, // Group: SysRegValues
	AARCH64_SYSREG_REVIDR_EL1 = 0xc006, // Group: SysRegValues
	AARCH64_SYSREG_AIDR_EL1 = 0xc807, // Group: SysRegValues
	AARCH64_SYSREG_DCZID_EL0 = 0xd807, // Group: SysRegValues
	AARCH64_SYSREG_ID_PFR0_EL1 = 0xc008, // Group: SysRegValues
	AARCH64_SYSREG_ID_PFR1_EL1 = 0xc009, // Group: SysRegValues
	AARCH64_SYSREG_ID_PFR2_EL1 = 0xc01c, // Group: SysRegValues
	AARCH64_SYSREG_ID_DFR0_EL1 = 0xc00a, // Group: SysRegValues
	AARCH64_SYSREG_ID_DFR1_EL1 = 0xc01d, // Group: SysRegValues
	AARCH64_SYSREG_ID_AFR0_EL1 = 0xc00b, // Group: SysRegValues
	AARCH64_SYSREG_ID_MMFR0_EL1 = 0xc00c, // Group: SysRegValues
	AARCH64_SYSREG_ID_MMFR1_EL1 = 0xc00d, // Group: SysRegValues
	AARCH64_SYSREG_ID_MMFR2_EL1 = 0xc00e, // Group: SysRegValues
	AARCH64_SYSREG_ID_MMFR3_EL1 = 0xc00f, // Group: SysRegValues
	AARCH64_SYSREG_ID_ISAR0_EL1 = 0xc010, // Group: SysRegValues
	AARCH64_SYSREG_ID_ISAR1_EL1 = 0xc011, // Group: SysRegValues
	AARCH64_SYSREG_ID_ISAR2_EL1 = 0xc012, // Group: SysRegValues
	AARCH64_SYSREG_ID_ISAR3_EL1 = 0xc013, // Group: SysRegValues
	AARCH64_SYSREG_ID_ISAR4_EL1 = 0xc014, // Group: SysRegValues
	AARCH64_SYSREG_ID_ISAR5_EL1 = 0xc015, // Group: SysRegValues
	AARCH64_SYSREG_ID_ISAR6_EL1 = 0xc017, // Group: SysRegValues
	AARCH64_SYSREG_ID_AA64PFR0_EL1 = 0xc020, // Group: SysRegValues
	AARCH64_SYSREG_ID_AA64PFR1_EL1 = 0xc021, // Group: SysRegValues
	AARCH64_SYSREG_ID_AA64PFR2_EL1 = 0xc022, // Group: SysRegValues
	AARCH64_SYSREG_ID_AA64DFR0_EL1 = 0xc028, // Group: SysRegValues
	AARCH64_SYSREG_ID_AA64DFR1_EL1 = 0xc029, // Group: SysRegValues
	AARCH64_SYSREG_ID_AA64AFR0_EL1 = 0xc02c, // Group: SysRegValues
	AARCH64_SYSREG_ID_AA64AFR1_EL1 = 0xc02d, // Group: SysRegValues
	AARCH64_SYSREG_ID_AA64ISAR0_EL1 = 0xc030, // Group: SysRegValues
	AARCH64_SYSREG_ID_AA64ISAR1_EL1 = 0xc031, // Group: SysRegValues
	AARCH64_SYSREG_ID_AA64ISAR2_EL1 = 0xc032, // Group: SysRegValues
	AARCH64_SYSREG_ID_AA64MMFR0_EL1 = 0xc038, // Group: SysRegValues
	AARCH64_SYSREG_ID_AA64MMFR1_EL1 = 0xc039, // Group: SysRegValues
	AARCH64_SYSREG_ID_AA64MMFR2_EL1 = 0xc03a, // Group: SysRegValues
	AARCH64_SYSREG_ID_AA64MMFR3_EL1 = 0xc03b, // Group: SysRegValues
	AARCH64_SYSREG_ID_AA64MMFR4_EL1 = 0xc03c, // Group: SysRegValues
	AARCH64_SYSREG_MVFR0_EL1 = 0xc018, // Group: SysRegValues
	AARCH64_SYSREG_MVFR1_EL1 = 0xc019, // Group: SysRegValues
	AARCH64_SYSREG_MVFR2_EL1 = 0xc01a, // Group: SysRegValues
	AARCH64_SYSREG_RVBAR_EL1 = 0xc601, // Group: SysRegValues
	AARCH64_SYSREG_RVBAR_EL2 = 0xe601, // Group: SysRegValues
	AARCH64_SYSREG_RVBAR_EL3 = 0xf601, // Group: SysRegValues
	AARCH64_SYSREG_ISR_EL1 = 0xc608, // Group: SysRegValues
	AARCH64_SYSREG_CNTPCT_EL0 = 0xdf01, // Group: SysRegValues
	AARCH64_SYSREG_CNTVCT_EL0 = 0xdf02, // Group: SysRegValues
	AARCH64_SYSREG_ID_MMFR4_EL1 = 0xc016, // Group: SysRegValues
	AARCH64_SYSREG_ID_MMFR5_EL1 = 0xc01e, // Group: SysRegValues
	AARCH64_SYSREG_TRCSTATR = 0x8818, // Group: SysRegValues
	AARCH64_SYSREG_TRCIDR8 = 0x8806, // Group: SysRegValues
	AARCH64_SYSREG_TRCIDR9 = 0x880e, // Group: SysRegValues
	AARCH64_SYSREG_TRCIDR10 = 0x8816, // Group: SysRegValues
	AARCH64_SYSREG_TRCIDR11 = 0x881e, // Group: SysRegValues
	AARCH64_SYSREG_TRCIDR12 = 0x8826, // Group: SysRegValues
	AARCH64_SYSREG_TRCIDR13 = 0x882e, // Group: SysRegValues
	AARCH64_SYSREG_TRCIDR0 = 0x8847, // Group: SysRegValues
	AARCH64_SYSREG_TRCIDR1 = 0x884f, // Group: SysRegValues
	AARCH64_SYSREG_TRCIDR2 = 0x8857, // Group: SysRegValues
	AARCH64_SYSREG_TRCIDR3 = 0x885f, // Group: SysRegValues
	AARCH64_SYSREG_TRCIDR4 = 0x8867, // Group: SysRegValues
	AARCH64_SYSREG_TRCIDR5 = 0x886f, // Group: SysRegValues
	AARCH64_SYSREG_TRCIDR6 = 0x8877, // Group: SysRegValues
	AARCH64_SYSREG_TRCIDR7 = 0x887f, // Group: SysRegValues
	AARCH64_SYSREG_TRCOSLSR = 0x888c, // Group: SysRegValues
	AARCH64_SYSREG_TRCPDSR = 0x88ac, // Group: SysRegValues
	AARCH64_SYSREG_TRCDEVAFF0 = 0x8bd6, // Group: SysRegValues
	AARCH64_SYSREG_TRCDEVAFF1 = 0x8bde, // Group: SysRegValues
	AARCH64_SYSREG_TRCLSR = 0x8bee, // Group: SysRegValues
	AARCH64_SYSREG_TRCAUTHSTATUS = 0x8bf6, // Group: SysRegValues
	AARCH64_SYSREG_TRCDEVARCH = 0x8bfe, // Group: SysRegValues
	AARCH64_SYSREG_TRCDEVID = 0x8b97, // Group: SysRegValues
	AARCH64_SYSREG_TRCDEVTYPE = 0x8b9f, // Group: SysRegValues
	AARCH64_SYSREG_TRCPIDR4 = 0x8ba7, // Group: SysRegValues
	AARCH64_SYSREG_TRCPIDR5 = 0x8baf, // Group: SysRegValues
	AARCH64_SYSREG_TRCPIDR6 = 0x8bb7, // Group: SysRegValues
	AARCH64_SYSREG_TRCPIDR7 = 0x8bbf, // Group: SysRegValues
	AARCH64_SYSREG_TRCPIDR0 = 0x8bc7, // Group: SysRegValues
	AARCH64_SYSREG_TRCPIDR1 = 0x8bcf, // Group: SysRegValues
	AARCH64_SYSREG_TRCPIDR2 = 0x8bd7, // Group: SysRegValues
	AARCH64_SYSREG_TRCPIDR3 = 0x8bdf, // Group: SysRegValues
	AARCH64_SYSREG_TRCCIDR0 = 0x8be7, // Group: SysRegValues
	AARCH64_SYSREG_TRCCIDR1 = 0x8bef, // Group: SysRegValues
	AARCH64_SYSREG_TRCCIDR2 = 0x8bf7, // Group: SysRegValues
	AARCH64_SYSREG_TRCCIDR3 = 0x8bff, // Group: SysRegValues
	AARCH64_SYSREG_ICC_IAR1_EL1 = 0xc660, // Group: SysRegValues
	AARCH64_SYSREG_ICC_IAR0_EL1 = 0xc640, // Group: SysRegValues
	AARCH64_SYSREG_ICC_HPPIR1_EL1 = 0xc662, // Group: SysRegValues
	AARCH64_SYSREG_ICC_HPPIR0_EL1 = 0xc642, // Group: SysRegValues
	AARCH64_SYSREG_ICC_RPR_EL1 = 0xc65b, // Group: SysRegValues
	AARCH64_SYSREG_ICH_VTR_EL2 = 0xe659, // Group: SysRegValues
	AARCH64_SYSREG_ICH_EISR_EL2 = 0xe65b, // Group: SysRegValues
	AARCH64_SYSREG_ICH_ELRSR_EL2 = 0xe65d, // Group: SysRegValues
	AARCH64_SYSREG_ID_AA64ZFR0_EL1 = 0xc024, // Group: SysRegValues
	AARCH64_SYSREG_LORID_EL1 = 0xc527, // Group: SysRegValues
	AARCH64_SYSREG_ERRIDR_EL1 = 0xc298, // Group: SysRegValues
	AARCH64_SYSREG_ERXFR_EL1 = 0xc2a0, // Group: SysRegValues
	AARCH64_SYSREG_RNDR = 0xd920, // Group: SysRegValues
	AARCH64_SYSREG_RNDRRS = 0xd921, // Group: SysRegValues
	AARCH64_SYSREG_SCXTNUM_EL0 = 0xde87, // Group: SysRegValues
	AARCH64_SYSREG_SCXTNUM_EL1 = 0xc687, // Group: SysRegValues
	AARCH64_SYSREG_SCXTNUM_EL2 = 0xe687, // Group: SysRegValues
	AARCH64_SYSREG_SCXTNUM_EL3 = 0xf687, // Group: SysRegValues
	AARCH64_SYSREG_SCXTNUM_EL12 = 0xee87, // Group: SysRegValues
	AARCH64_SYSREG_GPCCR_EL3 = 0xf10e, // Group: SysRegValues
	AARCH64_SYSREG_GPTBR_EL3 = 0xf10c, // Group: SysRegValues
	AARCH64_SYSREG_MFAR_EL3 = 0xf305, // Group: SysRegValues
	AARCH64_SYSREG_MECIDR_EL2 = 0xe547, // Group: SysRegValues
	AARCH64_SYSREG_MECID_P0_EL2 = 0xe540, // Group: SysRegValues
	AARCH64_SYSREG_MECID_A0_EL2 = 0xe541, // Group: SysRegValues
	AARCH64_SYSREG_MECID_P1_EL2 = 0xe542, // Group: SysRegValues
	AARCH64_SYSREG_MECID_A1_EL2 = 0xe543, // Group: SysRegValues
	AARCH64_SYSREG_VMECID_P_EL2 = 0xe548, // Group: SysRegValues
	AARCH64_SYSREG_VMECID_A_EL2 = 0xe549, // Group: SysRegValues
	AARCH64_SYSREG_MECID_RL_A_EL3 = 0xf551, // Group: SysRegValues
	AARCH64_SYSREG_ID_AA64SMFR0_EL1 = 0xc025, // Group: SysRegValues
	AARCH64_SYSREG_DBGDTRTX_EL0 = 0x9828, // Group: SysRegValues
	AARCH64_SYSREG_OSLAR_EL1 = 0x8084, // Group: SysRegValues
	AARCH64_SYSREG_PMSWINC_EL0 = 0xdce4, // Group: SysRegValues
	AARCH64_SYSREG_TRCOSLAR = 0x8884, // Group: SysRegValues
	AARCH64_SYSREG_TRCLAR = 0x8be6, // Group: SysRegValues
	AARCH64_SYSREG_ICC_EOIR1_EL1 = 0xc661, // Group: SysRegValues
	AARCH64_SYSREG_ICC_EOIR0_EL1 = 0xc641, // Group: SysRegValues
	AARCH64_SYSREG_ICC_DIR_EL1 = 0xc659, // Group: SysRegValues
	AARCH64_SYSREG_ICC_SGI1R_EL1 = 0xc65d, // Group: SysRegValues
	AARCH64_SYSREG_ICC_ASGI1R_EL1 = 0xc65e, // Group: SysRegValues
	AARCH64_SYSREG_ICC_SGI0R_EL1 = 0xc65f, // Group: SysRegValues
	AARCH64_SYSREG_OSDTRRX_EL1 = 0x8002, // Group: SysRegValues
	AARCH64_SYSREG_OSDTRTX_EL1 = 0x801a, // Group: SysRegValues
	AARCH64_SYSREG_TEECR32_EL1 = 0x9000, // Group: SysRegValues
	AARCH64_SYSREG_MDCCINT_EL1 = 0x8010, // Group: SysRegValues
	AARCH64_SYSREG_MDSCR_EL1 = 0x8012, // Group: SysRegValues
	AARCH64_SYSREG_DBGDTR_EL0 = 0x9820, // Group: SysRegValues
	AARCH64_SYSREG_OSECCR_EL1 = 0x8032, // Group: SysRegValues
	AARCH64_SYSREG_DBGVCR32_EL2 = 0xa038, // Group: SysRegValues
	AARCH64_SYSREG_DBGBVR0_EL1 = 0x8004, // Group: SysRegValues
	AARCH64_SYSREG_DBGBCR0_EL1 = 0x8005, // Group: SysRegValues
	AARCH64_SYSREG_DBGWVR0_EL1 = 0x8006, // Group: SysRegValues
	AARCH64_SYSREG_DBGWCR0_EL1 = 0x8007, // Group: SysRegValues
	AARCH64_SYSREG_DBGBVR1_EL1 = 0x800c, // Group: SysRegValues
	AARCH64_SYSREG_DBGBCR1_EL1 = 0x800d, // Group: SysRegValues
	AARCH64_SYSREG_DBGWVR1_EL1 = 0x800e, // Group: SysRegValues
	AARCH64_SYSREG_DBGWCR1_EL1 = 0x800f, // Group: SysRegValues
	AARCH64_SYSREG_DBGBVR2_EL1 = 0x8014, // Group: SysRegValues
	AARCH64_SYSREG_DBGBCR2_EL1 = 0x8015, // Group: SysRegValues
	AARCH64_SYSREG_DBGWVR2_EL1 = 0x8016, // Group: SysRegValues
	AARCH64_SYSREG_DBGWCR2_EL1 = 0x8017, // Group: SysRegValues
	AARCH64_SYSREG_DBGBVR3_EL1 = 0x801c, // Group: SysRegValues
	AARCH64_SYSREG_DBGBCR3_EL1 = 0x801d, // Group: SysRegValues
	AARCH64_SYSREG_DBGWVR3_EL1 = 0x801e, // Group: SysRegValues
	AARCH64_SYSREG_DBGWCR3_EL1 = 0x801f, // Group: SysRegValues
	AARCH64_SYSREG_DBGBVR4_EL1 = 0x8024, // Group: SysRegValues
	AARCH64_SYSREG_DBGBCR4_EL1 = 0x8025, // Group: SysRegValues
	AARCH64_SYSREG_DBGWVR4_EL1 = 0x8026, // Group: SysRegValues
	AARCH64_SYSREG_DBGWCR4_EL1 = 0x8027, // Group: SysRegValues
	AARCH64_SYSREG_DBGBVR5_EL1 = 0x802c, // Group: SysRegValues
	AARCH64_SYSREG_DBGBCR5_EL1 = 0x802d, // Group: SysRegValues
	AARCH64_SYSREG_DBGWVR5_EL1 = 0x802e, // Group: SysRegValues
	AARCH64_SYSREG_DBGWCR5_EL1 = 0x802f, // Group: SysRegValues
	AARCH64_SYSREG_DBGBVR6_EL1 = 0x8034, // Group: SysRegValues
	AARCH64_SYSREG_DBGBCR6_EL1 = 0x8035, // Group: SysRegValues
	AARCH64_SYSREG_DBGWVR6_EL1 = 0x8036, // Group: SysRegValues
	AARCH64_SYSREG_DBGWCR6_EL1 = 0x8037, // Group: SysRegValues
	AARCH64_SYSREG_DBGBVR7_EL1 = 0x803c, // Group: SysRegValues
	AARCH64_SYSREG_DBGBCR7_EL1 = 0x803d, // Group: SysRegValues
	AARCH64_SYSREG_DBGWVR7_EL1 = 0x803e, // Group: SysRegValues
	AARCH64_SYSREG_DBGWCR7_EL1 = 0x803f, // Group: SysRegValues
	AARCH64_SYSREG_DBGBVR8_EL1 = 0x8044, // Group: SysRegValues
	AARCH64_SYSREG_DBGBCR8_EL1 = 0x8045, // Group: SysRegValues
	AARCH64_SYSREG_DBGWVR8_EL1 = 0x8046, // Group: SysRegValues
	AARCH64_SYSREG_DBGWCR8_EL1 = 0x8047, // Group: SysRegValues
	AARCH64_SYSREG_DBGBVR9_EL1 = 0x804c, // Group: SysRegValues
	AARCH64_SYSREG_DBGBCR9_EL1 = 0x804d, // Group: SysRegValues
	AARCH64_SYSREG_DBGWVR9_EL1 = 0x804e, // Group: SysRegValues
	AARCH64_SYSREG_DBGWCR9_EL1 = 0x804f, // Group: SysRegValues
	AARCH64_SYSREG_DBGBVR10_EL1 = 0x8054, // Group: SysRegValues
	AARCH64_SYSREG_DBGBCR10_EL1 = 0x8055, // Group: SysRegValues
	AARCH64_SYSREG_DBGWVR10_EL1 = 0x8056, // Group: SysRegValues
	AARCH64_SYSREG_DBGWCR10_EL1 = 0x8057, // Group: SysRegValues
	AARCH64_SYSREG_DBGBVR11_EL1 = 0x805c, // Group: SysRegValues
	AARCH64_SYSREG_DBGBCR11_EL1 = 0x805d, // Group: SysRegValues
	AARCH64_SYSREG_DBGWVR11_EL1 = 0x805e, // Group: SysRegValues
	AARCH64_SYSREG_DBGWCR11_EL1 = 0x805f, // Group: SysRegValues
	AARCH64_SYSREG_DBGBVR12_EL1 = 0x8064, // Group: SysRegValues
	AARCH64_SYSREG_DBGBCR12_EL1 = 0x8065, // Group: SysRegValues
	AARCH64_SYSREG_DBGWVR12_EL1 = 0x8066, // Group: SysRegValues
	AARCH64_SYSREG_DBGWCR12_EL1 = 0x8067, // Group: SysRegValues
	AARCH64_SYSREG_DBGBVR13_EL1 = 0x806c, // Group: SysRegValues
	AARCH64_SYSREG_DBGBCR13_EL1 = 0x806d, // Group: SysRegValues
	AARCH64_SYSREG_DBGWVR13_EL1 = 0x806e, // Group: SysRegValues
	AARCH64_SYSREG_DBGWCR13_EL1 = 0x806f, // Group: SysRegValues
	AARCH64_SYSREG_DBGBVR14_EL1 = 0x8074, // Group: SysRegValues
	AARCH64_SYSREG_DBGBCR14_EL1 = 0x8075, // Group: SysRegValues
	AARCH64_SYSREG_DBGWVR14_EL1 = 0x8076, // Group: SysRegValues
	AARCH64_SYSREG_DBGWCR14_EL1 = 0x8077, // Group: SysRegValues
	AARCH64_SYSREG_DBGBVR15_EL1 = 0x807c, // Group: SysRegValues
	AARCH64_SYSREG_DBGBCR15_EL1 = 0x807d, // Group: SysRegValues
	AARCH64_SYSREG_DBGWVR15_EL1 = 0x807e, // Group: SysRegValues
	AARCH64_SYSREG_DBGWCR15_EL1 = 0x807f, // Group: SysRegValues
	AARCH64_SYSREG_TEEHBR32_EL1 = 0x9080, // Group: SysRegValues
	AARCH64_SYSREG_OSDLR_EL1 = 0x809c, // Group: SysRegValues
	AARCH64_SYSREG_DBGPRCR_EL1 = 0x80a4, // Group: SysRegValues
	AARCH64_SYSREG_DBGCLAIMSET_EL1 = 0x83c6, // Group: SysRegValues
	AARCH64_SYSREG_DBGCLAIMCLR_EL1 = 0x83ce, // Group: SysRegValues
	AARCH64_SYSREG_CSSELR_EL1 = 0xd000, // Group: SysRegValues
	AARCH64_SYSREG_VPIDR_EL2 = 0xe000, // Group: SysRegValues
	AARCH64_SYSREG_VMPIDR_EL2 = 0xe005, // Group: SysRegValues
	AARCH64_SYSREG_CPACR_EL1 = 0xc082, // Group: SysRegValues
	AARCH64_SYSREG_SCTLR_EL1 = 0xc080, // Group: SysRegValues
	AARCH64_SYSREG_SCTLR_EL2 = 0xe080, // Group: SysRegValues
	AARCH64_SYSREG_SCTLR_EL3 = 0xf080, // Group: SysRegValues
	AARCH64_SYSREG_ACTLR_EL1 = 0xc081, // Group: SysRegValues
	AARCH64_SYSREG_ACTLR_EL2 = 0xe081, // Group: SysRegValues
	AARCH64_SYSREG_ACTLR_EL3 = 0xf081, // Group: SysRegValues
	AARCH64_SYSREG_HCR_EL2 = 0xe088, // Group: SysRegValues
	AARCH64_SYSREG_HCRX_EL2 = 0xe092, // Group: SysRegValues
	AARCH64_SYSREG_SCR_EL3 = 0xf088, // Group: SysRegValues
	AARCH64_SYSREG_MDCR_EL2 = 0xe089, // Group: SysRegValues
	AARCH64_SYSREG_SDER32_EL3 = 0xf089, // Group: SysRegValues
	AARCH64_SYSREG_CPTR_EL2 = 0xe08a, // Group: SysRegValues
	AARCH64_SYSREG_CPTR_EL3 = 0xf08a, // Group: SysRegValues
	AARCH64_SYSREG_HSTR_EL2 = 0xe08b, // Group: SysRegValues
	AARCH64_SYSREG_HACR_EL2 = 0xe08f, // Group: SysRegValues
	AARCH64_SYSREG_MDCR_EL3 = 0xf099, // Group: SysRegValues
	AARCH64_SYSREG_TTBR0_EL1 = 0xc100, // Group: SysRegValues
	AARCH64_SYSREG_TTBR0_EL3 = 0xf100, // Group: SysRegValues
	AARCH64_SYSREG_TTBR0_EL2 = 0xe100, // Group: SysRegValues
	AARCH64_SYSREG_VTTBR_EL2 = 0xe108, // Group: SysRegValues
	AARCH64_SYSREG_TTBR1_EL1 = 0xc101, // Group: SysRegValues
	AARCH64_SYSREG_TCR_EL1 = 0xc102, // Group: SysRegValues
	AARCH64_SYSREG_TCR_EL2 = 0xe102, // Group: SysRegValues
	AARCH64_SYSREG_TCR_EL3 = 0xf102, // Group: SysRegValues
	AARCH64_SYSREG_VTCR_EL2 = 0xe10a, // Group: SysRegValues
	AARCH64_SYSREG_DACR32_EL2 = 0xe180, // Group: SysRegValues
	AARCH64_SYSREG_SPSR_EL1 = 0xc200, // Group: SysRegValues
	AARCH64_SYSREG_SPSR_EL2 = 0xe200, // Group: SysRegValues
	AARCH64_SYSREG_SPSR_EL3 = 0xf200, // Group: SysRegValues
	AARCH64_SYSREG_ELR_EL1 = 0xc201, // Group: SysRegValues
	AARCH64_SYSREG_ELR_EL2 = 0xe201, // Group: SysRegValues
	AARCH64_SYSREG_ELR_EL3 = 0xf201, // Group: SysRegValues
	AARCH64_SYSREG_SP_EL0 = 0xc208, // Group: SysRegValues
	AARCH64_SYSREG_SP_EL1 = 0xe208, // Group: SysRegValues
	AARCH64_SYSREG_SP_EL2 = 0xf208, // Group: SysRegValues
	AARCH64_SYSREG_SPSEL_SysRegValues = 0xc210, // Group: SysRegValues - also encoded as: AARCH64_SYSREG_SPSEL
	AARCH64_SYSREG_NZCV = 0xda10, // Group: SysRegValues
	AARCH64_SYSREG_DAIF = 0xda11, // Group: SysRegValues
	AARCH64_SYSREG_CURRENTEL = 0xc212, // Group: SysRegValues
	AARCH64_SYSREG_SPSR_IRQ = 0xe218, // Group: SysRegValues
	AARCH64_SYSREG_SPSR_ABT = 0xe219, // Group: SysRegValues
	AARCH64_SYSREG_SPSR_UND = 0xe21a, // Group: SysRegValues
	AARCH64_SYSREG_SPSR_FIQ = 0xe21b, // Group: SysRegValues
	AARCH64_SYSREG_FPCR = 0xda20, // Group: SysRegValues
	AARCH64_SYSREG_FPSR = 0xda21, // Group: SysRegValues
	AARCH64_SYSREG_DSPSR_EL0 = 0xda28, // Group: SysRegValues
	AARCH64_SYSREG_DLR_EL0 = 0xda29, // Group: SysRegValues
	AARCH64_SYSREG_IFSR32_EL2 = 0xe281, // Group: SysRegValues
	AARCH64_SYSREG_AFSR0_EL1 = 0xc288, // Group: SysRegValues
	AARCH64_SYSREG_AFSR0_EL2 = 0xe288, // Group: SysRegValues
	AARCH64_SYSREG_AFSR0_EL3 = 0xf288, // Group: SysRegValues
	AARCH64_SYSREG_AFSR1_EL1 = 0xc289, // Group: SysRegValues
	AARCH64_SYSREG_AFSR1_EL2 = 0xe289, // Group: SysRegValues
	AARCH64_SYSREG_AFSR1_EL3 = 0xf289, // Group: SysRegValues
	AARCH64_SYSREG_ESR_EL1 = 0xc290, // Group: SysRegValues
	AARCH64_SYSREG_ESR_EL2 = 0xe290, // Group: SysRegValues
	AARCH64_SYSREG_ESR_EL3 = 0xf290, // Group: SysRegValues
	AARCH64_SYSREG_FPEXC32_EL2 = 0xe298, // Group: SysRegValues
	AARCH64_SYSREG_FAR_EL1 = 0xc300, // Group: SysRegValues
	AARCH64_SYSREG_FAR_EL2 = 0xe300, // Group: SysRegValues
	AARCH64_SYSREG_FAR_EL3 = 0xf300, // Group: SysRegValues
	AARCH64_SYSREG_HPFAR_EL2 = 0xe304, // Group: SysRegValues
	AARCH64_SYSREG_PAR_EL1 = 0xc3a0, // Group: SysRegValues
	AARCH64_SYSREG_PMCR_EL0 = 0xdce0, // Group: SysRegValues
	AARCH64_SYSREG_PMCNTENSET_EL0 = 0xdce1, // Group: SysRegValues
	AARCH64_SYSREG_PMCNTENCLR_EL0 = 0xdce2, // Group: SysRegValues
	AARCH64_SYSREG_PMOVSCLR_EL0 = 0xdce3, // Group: SysRegValues
	AARCH64_SYSREG_PMSELR_EL0 = 0xdce5, // Group: SysRegValues
	AARCH64_SYSREG_PMCCNTR_EL0 = 0xdce8, // Group: SysRegValues
	AARCH64_SYSREG_PMXEVTYPER_EL0 = 0xdce9, // Group: SysRegValues
	AARCH64_SYSREG_PMXEVCNTR_EL0 = 0xdcea, // Group: SysRegValues
	AARCH64_SYSREG_PMUSERENR_EL0 = 0xdcf0, // Group: SysRegValues
	AARCH64_SYSREG_PMINTENSET_EL1 = 0xc4f1, // Group: SysRegValues
	AARCH64_SYSREG_PMINTENCLR_EL1 = 0xc4f2, // Group: SysRegValues
	AARCH64_SYSREG_PMOVSSET_EL0 = 0xdcf3, // Group: SysRegValues
	AARCH64_SYSREG_MAIR_EL1 = 0xc510, // Group: SysRegValues
	AARCH64_SYSREG_MAIR_EL2 = 0xe510, // Group: SysRegValues
	AARCH64_SYSREG_MAIR_EL3 = 0xf510, // Group: SysRegValues
	AARCH64_SYSREG_AMAIR_EL1 = 0xc518, // Group: SysRegValues
	AARCH64_SYSREG_AMAIR_EL2 = 0xe518, // Group: SysRegValues
	AARCH64_SYSREG_AMAIR_EL3 = 0xf518, // Group: SysRegValues
	AARCH64_SYSREG_VBAR_EL1 = 0xc600, // Group: SysRegValues
	AARCH64_SYSREG_VBAR_EL2 = 0xe600, // Group: SysRegValues
	AARCH64_SYSREG_VBAR_EL3 = 0xf600, // Group: SysRegValues
	AARCH64_SYSREG_RMR_EL1 = 0xc602, // Group: SysRegValues
	AARCH64_SYSREG_RMR_EL2 = 0xe602, // Group: SysRegValues
	AARCH64_SYSREG_RMR_EL3 = 0xf602, // Group: SysRegValues
	AARCH64_SYSREG_CONTEXTIDR_EL1 = 0xc681, // Group: SysRegValues
	AARCH64_SYSREG_TPIDR_EL0 = 0xde82, // Group: SysRegValues
	AARCH64_SYSREG_TPIDR_EL2 = 0xe682, // Group: SysRegValues
	AARCH64_SYSREG_TPIDR_EL3 = 0xf682, // Group: SysRegValues
	AARCH64_SYSREG_TPIDRRO_EL0 = 0xde83, // Group: SysRegValues
	AARCH64_SYSREG_TPIDR_EL1 = 0xc684, // Group: SysRegValues
	AARCH64_SYSREG_CNTFRQ_EL0 = 0xdf00, // Group: SysRegValues
	AARCH64_SYSREG_CNTVOFF_EL2 = 0xe703, // Group: SysRegValues
	AARCH64_SYSREG_CNTKCTL_EL1 = 0xc708, // Group: SysRegValues
	AARCH64_SYSREG_CNTHCTL_EL2 = 0xe708, // Group: SysRegValues
	AARCH64_SYSREG_CNTP_TVAL_EL0 = 0xdf10, // Group: SysRegValues
	AARCH64_SYSREG_CNTHP_TVAL_EL2 = 0xe710, // Group: SysRegValues
	AARCH64_SYSREG_CNTPS_TVAL_EL1 = 0xff10, // Group: SysRegValues
	AARCH64_SYSREG_CNTP_CTL_EL0 = 0xdf11, // Group: SysRegValues
	AARCH64_SYSREG_CNTHP_CTL_EL2 = 0xe711, // Group: SysRegValues
	AARCH64_SYSREG_CNTPS_CTL_EL1 = 0xff11, // Group: SysRegValues
	AARCH64_SYSREG_CNTP_CVAL_EL0 = 0xdf12, // Group: SysRegValues
	AARCH64_SYSREG_CNTHP_CVAL_EL2 = 0xe712, // Group: SysRegValues
	AARCH64_SYSREG_CNTPS_CVAL_EL1 = 0xff12, // Group: SysRegValues
	AARCH64_SYSREG_CNTV_TVAL_EL0 = 0xdf18, // Group: SysRegValues
	AARCH64_SYSREG_CNTV_CTL_EL0 = 0xdf19, // Group: SysRegValues
	AARCH64_SYSREG_CNTV_CVAL_EL0 = 0xdf1a, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR0_EL0 = 0xdf40, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR1_EL0 = 0xdf41, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR2_EL0 = 0xdf42, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR3_EL0 = 0xdf43, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR4_EL0 = 0xdf44, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR5_EL0 = 0xdf45, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR6_EL0 = 0xdf46, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR7_EL0 = 0xdf47, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR8_EL0 = 0xdf48, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR9_EL0 = 0xdf49, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR10_EL0 = 0xdf4a, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR11_EL0 = 0xdf4b, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR12_EL0 = 0xdf4c, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR13_EL0 = 0xdf4d, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR14_EL0 = 0xdf4e, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR15_EL0 = 0xdf4f, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR16_EL0 = 0xdf50, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR17_EL0 = 0xdf51, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR18_EL0 = 0xdf52, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR19_EL0 = 0xdf53, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR20_EL0 = 0xdf54, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR21_EL0 = 0xdf55, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR22_EL0 = 0xdf56, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR23_EL0 = 0xdf57, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR24_EL0 = 0xdf58, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR25_EL0 = 0xdf59, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR26_EL0 = 0xdf5a, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR27_EL0 = 0xdf5b, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR28_EL0 = 0xdf5c, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR29_EL0 = 0xdf5d, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTR30_EL0 = 0xdf5e, // Group: SysRegValues
	AARCH64_SYSREG_PMCCFILTR_EL0 = 0xdf7f, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER0_EL0 = 0xdf60, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER1_EL0 = 0xdf61, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER2_EL0 = 0xdf62, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER3_EL0 = 0xdf63, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER4_EL0 = 0xdf64, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER5_EL0 = 0xdf65, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER6_EL0 = 0xdf66, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER7_EL0 = 0xdf67, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER8_EL0 = 0xdf68, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER9_EL0 = 0xdf69, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER10_EL0 = 0xdf6a, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER11_EL0 = 0xdf6b, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER12_EL0 = 0xdf6c, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER13_EL0 = 0xdf6d, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER14_EL0 = 0xdf6e, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER15_EL0 = 0xdf6f, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER16_EL0 = 0xdf70, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER17_EL0 = 0xdf71, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER18_EL0 = 0xdf72, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER19_EL0 = 0xdf73, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER20_EL0 = 0xdf74, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER21_EL0 = 0xdf75, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER22_EL0 = 0xdf76, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER23_EL0 = 0xdf77, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER24_EL0 = 0xdf78, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER25_EL0 = 0xdf79, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER26_EL0 = 0xdf7a, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER27_EL0 = 0xdf7b, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER28_EL0 = 0xdf7c, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER29_EL0 = 0xdf7d, // Group: SysRegValues
	AARCH64_SYSREG_PMEVTYPER30_EL0 = 0xdf7e, // Group: SysRegValues
	AARCH64_SYSREG_TRCPRGCTLR = 0x8808, // Group: SysRegValues
	AARCH64_SYSREG_TRCPROCSELR = 0x8810, // Group: SysRegValues
	AARCH64_SYSREG_TRCCONFIGR = 0x8820, // Group: SysRegValues
	AARCH64_SYSREG_TRCAUXCTLR = 0x8830, // Group: SysRegValues
	AARCH64_SYSREG_TRCEVENTCTL0R = 0x8840, // Group: SysRegValues
	AARCH64_SYSREG_TRCEVENTCTL1R = 0x8848, // Group: SysRegValues
	AARCH64_SYSREG_TRCSTALLCTLR = 0x8858, // Group: SysRegValues
	AARCH64_SYSREG_TRCTSCTLR = 0x8860, // Group: SysRegValues
	AARCH64_SYSREG_TRCSYNCPR = 0x8868, // Group: SysRegValues
	AARCH64_SYSREG_TRCCCCTLR = 0x8870, // Group: SysRegValues
	AARCH64_SYSREG_TRCBBCTLR = 0x8878, // Group: SysRegValues
	AARCH64_SYSREG_TRCTRACEIDR = 0x8801, // Group: SysRegValues
	AARCH64_SYSREG_TRCQCTLR = 0x8809, // Group: SysRegValues
	AARCH64_SYSREG_TRCVICTLR = 0x8802, // Group: SysRegValues
	AARCH64_SYSREG_TRCVIIECTLR = 0x880a, // Group: SysRegValues
	AARCH64_SYSREG_TRCVISSCTLR = 0x8812, // Group: SysRegValues
	AARCH64_SYSREG_TRCVIPCSSCTLR = 0x881a, // Group: SysRegValues
	AARCH64_SYSREG_TRCVDCTLR = 0x8842, // Group: SysRegValues
	AARCH64_SYSREG_TRCVDSACCTLR = 0x884a, // Group: SysRegValues
	AARCH64_SYSREG_TRCVDARCCTLR = 0x8852, // Group: SysRegValues
	AARCH64_SYSREG_TRCSEQEVR0 = 0x8804, // Group: SysRegValues
	AARCH64_SYSREG_TRCSEQEVR1 = 0x880c, // Group: SysRegValues
	AARCH64_SYSREG_TRCSEQEVR2 = 0x8814, // Group: SysRegValues
	AARCH64_SYSREG_TRCSEQRSTEVR = 0x8834, // Group: SysRegValues
	AARCH64_SYSREG_TRCSEQSTR = 0x883c, // Group: SysRegValues
	AARCH64_SYSREG_TRCEXTINSELR = 0x8844, // Group: SysRegValues
	AARCH64_SYSREG_TRCCNTRLDVR0 = 0x8805, // Group: SysRegValues
	AARCH64_SYSREG_TRCCNTRLDVR1 = 0x880d, // Group: SysRegValues
	AARCH64_SYSREG_TRCCNTRLDVR2 = 0x8815, // Group: SysRegValues
	AARCH64_SYSREG_TRCCNTRLDVR3 = 0x881d, // Group: SysRegValues
	AARCH64_SYSREG_TRCCNTCTLR0 = 0x8825, // Group: SysRegValues
	AARCH64_SYSREG_TRCCNTCTLR1 = 0x882d, // Group: SysRegValues
	AARCH64_SYSREG_TRCCNTCTLR2 = 0x8835, // Group: SysRegValues
	AARCH64_SYSREG_TRCCNTCTLR3 = 0x883d, // Group: SysRegValues
	AARCH64_SYSREG_TRCCNTVR0 = 0x8845, // Group: SysRegValues
	AARCH64_SYSREG_TRCCNTVR1 = 0x884d, // Group: SysRegValues
	AARCH64_SYSREG_TRCCNTVR2 = 0x8855, // Group: SysRegValues
	AARCH64_SYSREG_TRCCNTVR3 = 0x885d, // Group: SysRegValues
	AARCH64_SYSREG_TRCIMSPEC0 = 0x8807, // Group: SysRegValues
	AARCH64_SYSREG_TRCIMSPEC1 = 0x880f, // Group: SysRegValues
	AARCH64_SYSREG_TRCIMSPEC2 = 0x8817, // Group: SysRegValues
	AARCH64_SYSREG_TRCIMSPEC3 = 0x881f, // Group: SysRegValues
	AARCH64_SYSREG_TRCIMSPEC4 = 0x8827, // Group: SysRegValues
	AARCH64_SYSREG_TRCIMSPEC5 = 0x882f, // Group: SysRegValues
	AARCH64_SYSREG_TRCIMSPEC6 = 0x8837, // Group: SysRegValues
	AARCH64_SYSREG_TRCIMSPEC7 = 0x883f, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR2 = 0x8890, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR3 = 0x8898, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR4 = 0x88a0, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR5 = 0x88a8, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR6 = 0x88b0, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR7 = 0x88b8, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR8 = 0x88c0, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR9 = 0x88c8, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR10 = 0x88d0, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR11 = 0x88d8, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR12 = 0x88e0, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR13 = 0x88e8, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR14 = 0x88f0, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR15 = 0x88f8, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR16 = 0x8881, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR17 = 0x8889, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR18 = 0x8891, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR19 = 0x8899, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR20 = 0x88a1, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR21 = 0x88a9, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR22 = 0x88b1, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR23 = 0x88b9, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR24 = 0x88c1, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR25 = 0x88c9, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR26 = 0x88d1, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR27 = 0x88d9, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR28 = 0x88e1, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR29 = 0x88e9, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR30 = 0x88f1, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSCTLR31 = 0x88f9, // Group: SysRegValues
	AARCH64_SYSREG_TRCSSCCR0 = 0x8882, // Group: SysRegValues
	AARCH64_SYSREG_TRCSSCCR1 = 0x888a, // Group: SysRegValues
	AARCH64_SYSREG_TRCSSCCR2 = 0x8892, // Group: SysRegValues
	AARCH64_SYSREG_TRCSSCCR3 = 0x889a, // Group: SysRegValues
	AARCH64_SYSREG_TRCSSCCR4 = 0x88a2, // Group: SysRegValues
	AARCH64_SYSREG_TRCSSCCR5 = 0x88aa, // Group: SysRegValues
	AARCH64_SYSREG_TRCSSCCR6 = 0x88b2, // Group: SysRegValues
	AARCH64_SYSREG_TRCSSCCR7 = 0x88ba, // Group: SysRegValues
	AARCH64_SYSREG_TRCSSCSR0 = 0x88c2, // Group: SysRegValues
	AARCH64_SYSREG_TRCSSCSR1 = 0x88ca, // Group: SysRegValues
	AARCH64_SYSREG_TRCSSCSR2 = 0x88d2, // Group: SysRegValues
	AARCH64_SYSREG_TRCSSCSR3 = 0x88da, // Group: SysRegValues
	AARCH64_SYSREG_TRCSSCSR4 = 0x88e2, // Group: SysRegValues
	AARCH64_SYSREG_TRCSSCSR5 = 0x88ea, // Group: SysRegValues
	AARCH64_SYSREG_TRCSSCSR6 = 0x88f2, // Group: SysRegValues
	AARCH64_SYSREG_TRCSSCSR7 = 0x88fa, // Group: SysRegValues
	AARCH64_SYSREG_TRCSSPCICR0 = 0x8883, // Group: SysRegValues
	AARCH64_SYSREG_TRCSSPCICR1 = 0x888b, // Group: SysRegValues
	AARCH64_SYSREG_TRCSSPCICR2 = 0x8893, // Group: SysRegValues
	AARCH64_SYSREG_TRCSSPCICR3 = 0x889b, // Group: SysRegValues
	AARCH64_SYSREG_TRCSSPCICR4 = 0x88a3, // Group: SysRegValues
	AARCH64_SYSREG_TRCSSPCICR5 = 0x88ab, // Group: SysRegValues
	AARCH64_SYSREG_TRCSSPCICR6 = 0x88b3, // Group: SysRegValues
	AARCH64_SYSREG_TRCSSPCICR7 = 0x88bb, // Group: SysRegValues
	AARCH64_SYSREG_TRCPDCR = 0x88a4, // Group: SysRegValues
	AARCH64_SYSREG_TRCACVR0 = 0x8900, // Group: SysRegValues
	AARCH64_SYSREG_TRCACVR1 = 0x8910, // Group: SysRegValues
	AARCH64_SYSREG_TRCACVR2 = 0x8920, // Group: SysRegValues
	AARCH64_SYSREG_TRCACVR3 = 0x8930, // Group: SysRegValues
	AARCH64_SYSREG_TRCACVR4 = 0x8940, // Group: SysRegValues
	AARCH64_SYSREG_TRCACVR5 = 0x8950, // Group: SysRegValues
	AARCH64_SYSREG_TRCACVR6 = 0x8960, // Group: SysRegValues
	AARCH64_SYSREG_TRCACVR7 = 0x8970, // Group: SysRegValues
	AARCH64_SYSREG_TRCACVR8 = 0x8901, // Group: SysRegValues
	AARCH64_SYSREG_TRCACVR9 = 0x8911, // Group: SysRegValues
	AARCH64_SYSREG_TRCACVR10 = 0x8921, // Group: SysRegValues
	AARCH64_SYSREG_TRCACVR11 = 0x8931, // Group: SysRegValues
	AARCH64_SYSREG_TRCACVR12 = 0x8941, // Group: SysRegValues
	AARCH64_SYSREG_TRCACVR13 = 0x8951, // Group: SysRegValues
	AARCH64_SYSREG_TRCACVR14 = 0x8961, // Group: SysRegValues
	AARCH64_SYSREG_TRCACVR15 = 0x8971, // Group: SysRegValues
	AARCH64_SYSREG_TRCACATR0 = 0x8902, // Group: SysRegValues
	AARCH64_SYSREG_TRCACATR1 = 0x8912, // Group: SysRegValues
	AARCH64_SYSREG_TRCACATR2 = 0x8922, // Group: SysRegValues
	AARCH64_SYSREG_TRCACATR3 = 0x8932, // Group: SysRegValues
	AARCH64_SYSREG_TRCACATR4 = 0x8942, // Group: SysRegValues
	AARCH64_SYSREG_TRCACATR5 = 0x8952, // Group: SysRegValues
	AARCH64_SYSREG_TRCACATR6 = 0x8962, // Group: SysRegValues
	AARCH64_SYSREG_TRCACATR7 = 0x8972, // Group: SysRegValues
	AARCH64_SYSREG_TRCACATR8 = 0x8903, // Group: SysRegValues
	AARCH64_SYSREG_TRCACATR9 = 0x8913, // Group: SysRegValues
	AARCH64_SYSREG_TRCACATR10 = 0x8923, // Group: SysRegValues
	AARCH64_SYSREG_TRCACATR11 = 0x8933, // Group: SysRegValues
	AARCH64_SYSREG_TRCACATR12 = 0x8943, // Group: SysRegValues
	AARCH64_SYSREG_TRCACATR13 = 0x8953, // Group: SysRegValues
	AARCH64_SYSREG_TRCACATR14 = 0x8963, // Group: SysRegValues
	AARCH64_SYSREG_TRCACATR15 = 0x8973, // Group: SysRegValues
	AARCH64_SYSREG_TRCDVCVR0 = 0x8904, // Group: SysRegValues
	AARCH64_SYSREG_TRCDVCVR1 = 0x8924, // Group: SysRegValues
	AARCH64_SYSREG_TRCDVCVR2 = 0x8944, // Group: SysRegValues
	AARCH64_SYSREG_TRCDVCVR3 = 0x8964, // Group: SysRegValues
	AARCH64_SYSREG_TRCDVCVR4 = 0x8905, // Group: SysRegValues
	AARCH64_SYSREG_TRCDVCVR5 = 0x8925, // Group: SysRegValues
	AARCH64_SYSREG_TRCDVCVR6 = 0x8945, // Group: SysRegValues
	AARCH64_SYSREG_TRCDVCVR7 = 0x8965, // Group: SysRegValues
	AARCH64_SYSREG_TRCDVCMR0 = 0x8906, // Group: SysRegValues
	AARCH64_SYSREG_TRCDVCMR1 = 0x8926, // Group: SysRegValues
	AARCH64_SYSREG_TRCDVCMR2 = 0x8946, // Group: SysRegValues
	AARCH64_SYSREG_TRCDVCMR3 = 0x8966, // Group: SysRegValues
	AARCH64_SYSREG_TRCDVCMR4 = 0x8907, // Group: SysRegValues
	AARCH64_SYSREG_TRCDVCMR5 = 0x8927, // Group: SysRegValues
	AARCH64_SYSREG_TRCDVCMR6 = 0x8947, // Group: SysRegValues
	AARCH64_SYSREG_TRCDVCMR7 = 0x8967, // Group: SysRegValues
	AARCH64_SYSREG_TRCCIDCVR0 = 0x8980, // Group: SysRegValues
	AARCH64_SYSREG_TRCCIDCVR1 = 0x8990, // Group: SysRegValues
	AARCH64_SYSREG_TRCCIDCVR2 = 0x89a0, // Group: SysRegValues
	AARCH64_SYSREG_TRCCIDCVR3 = 0x89b0, // Group: SysRegValues
	AARCH64_SYSREG_TRCCIDCVR4 = 0x89c0, // Group: SysRegValues
	AARCH64_SYSREG_TRCCIDCVR5 = 0x89d0, // Group: SysRegValues
	AARCH64_SYSREG_TRCCIDCVR6 = 0x89e0, // Group: SysRegValues
	AARCH64_SYSREG_TRCCIDCVR7 = 0x89f0, // Group: SysRegValues
	AARCH64_SYSREG_TRCVMIDCVR0 = 0x8981, // Group: SysRegValues
	AARCH64_SYSREG_TRCVMIDCVR1 = 0x8991, // Group: SysRegValues
	AARCH64_SYSREG_TRCVMIDCVR2 = 0x89a1, // Group: SysRegValues
	AARCH64_SYSREG_TRCVMIDCVR3 = 0x89b1, // Group: SysRegValues
	AARCH64_SYSREG_TRCVMIDCVR4 = 0x89c1, // Group: SysRegValues
	AARCH64_SYSREG_TRCVMIDCVR5 = 0x89d1, // Group: SysRegValues
	AARCH64_SYSREG_TRCVMIDCVR6 = 0x89e1, // Group: SysRegValues
	AARCH64_SYSREG_TRCVMIDCVR7 = 0x89f1, // Group: SysRegValues
	AARCH64_SYSREG_TRCCIDCCTLR0 = 0x8982, // Group: SysRegValues
	AARCH64_SYSREG_TRCCIDCCTLR1 = 0x898a, // Group: SysRegValues
	AARCH64_SYSREG_TRCVMIDCCTLR0 = 0x8992, // Group: SysRegValues
	AARCH64_SYSREG_TRCVMIDCCTLR1 = 0x899a, // Group: SysRegValues
	AARCH64_SYSREG_TRCITCTRL = 0x8b84, // Group: SysRegValues
	AARCH64_SYSREG_TRCCLAIMSET = 0x8bc6, // Group: SysRegValues
	AARCH64_SYSREG_TRCCLAIMCLR = 0x8bce, // Group: SysRegValues
	AARCH64_SYSREG_ICC_BPR1_EL1 = 0xc663, // Group: SysRegValues
	AARCH64_SYSREG_ICC_BPR0_EL1 = 0xc643, // Group: SysRegValues
	AARCH64_SYSREG_ICC_PMR_EL1 = 0xc230, // Group: SysRegValues
	AARCH64_SYSREG_ICC_CTLR_EL1 = 0xc664, // Group: SysRegValues
	AARCH64_SYSREG_ICC_CTLR_EL3 = 0xf664, // Group: SysRegValues
	AARCH64_SYSREG_ICC_SRE_EL1 = 0xc665, // Group: SysRegValues
	AARCH64_SYSREG_ICC_SRE_EL2 = 0xe64d, // Group: SysRegValues
	AARCH64_SYSREG_ICC_SRE_EL3 = 0xf665, // Group: SysRegValues
	AARCH64_SYSREG_ICC_IGRPEN0_EL1 = 0xc666, // Group: SysRegValues
	AARCH64_SYSREG_ICC_IGRPEN1_EL1 = 0xc667, // Group: SysRegValues
	AARCH64_SYSREG_ICC_IGRPEN1_EL3 = 0xf667, // Group: SysRegValues
	AARCH64_SYSREG_ICC_AP0R0_EL1 = 0xc644, // Group: SysRegValues
	AARCH64_SYSREG_ICC_AP0R1_EL1 = 0xc645, // Group: SysRegValues
	AARCH64_SYSREG_ICC_AP0R2_EL1 = 0xc646, // Group: SysRegValues
	AARCH64_SYSREG_ICC_AP0R3_EL1 = 0xc647, // Group: SysRegValues
	AARCH64_SYSREG_ICC_AP1R0_EL1 = 0xc648, // Group: SysRegValues
	AARCH64_SYSREG_ICC_AP1R1_EL1 = 0xc649, // Group: SysRegValues
	AARCH64_SYSREG_ICC_AP1R2_EL1 = 0xc64a, // Group: SysRegValues
	AARCH64_SYSREG_ICC_AP1R3_EL1 = 0xc64b, // Group: SysRegValues
	AARCH64_SYSREG_ICH_AP0R0_EL2 = 0xe640, // Group: SysRegValues
	AARCH64_SYSREG_ICH_AP0R1_EL2 = 0xe641, // Group: SysRegValues
	AARCH64_SYSREG_ICH_AP0R2_EL2 = 0xe642, // Group: SysRegValues
	AARCH64_SYSREG_ICH_AP0R3_EL2 = 0xe643, // Group: SysRegValues
	AARCH64_SYSREG_ICH_AP1R0_EL2 = 0xe648, // Group: SysRegValues
	AARCH64_SYSREG_ICH_AP1R1_EL2 = 0xe649, // Group: SysRegValues
	AARCH64_SYSREG_ICH_AP1R2_EL2 = 0xe64a, // Group: SysRegValues
	AARCH64_SYSREG_ICH_AP1R3_EL2 = 0xe64b, // Group: SysRegValues
	AARCH64_SYSREG_ICH_HCR_EL2 = 0xe658, // Group: SysRegValues
	AARCH64_SYSREG_ICH_MISR_EL2 = 0xe65a, // Group: SysRegValues
	AARCH64_SYSREG_ICH_VMCR_EL2 = 0xe65f, // Group: SysRegValues
	AARCH64_SYSREG_ICH_LR0_EL2 = 0xe660, // Group: SysRegValues
	AARCH64_SYSREG_ICH_LR1_EL2 = 0xe661, // Group: SysRegValues
	AARCH64_SYSREG_ICH_LR2_EL2 = 0xe662, // Group: SysRegValues
	AARCH64_SYSREG_ICH_LR3_EL2 = 0xe663, // Group: SysRegValues
	AARCH64_SYSREG_ICH_LR4_EL2 = 0xe664, // Group: SysRegValues
	AARCH64_SYSREG_ICH_LR5_EL2 = 0xe665, // Group: SysRegValues
	AARCH64_SYSREG_ICH_LR6_EL2 = 0xe666, // Group: SysRegValues
	AARCH64_SYSREG_ICH_LR7_EL2 = 0xe667, // Group: SysRegValues
	AARCH64_SYSREG_ICH_LR8_EL2 = 0xe668, // Group: SysRegValues
	AARCH64_SYSREG_ICH_LR9_EL2 = 0xe669, // Group: SysRegValues
	AARCH64_SYSREG_ICH_LR10_EL2 = 0xe66a, // Group: SysRegValues
	AARCH64_SYSREG_ICH_LR11_EL2 = 0xe66b, // Group: SysRegValues
	AARCH64_SYSREG_ICH_LR12_EL2 = 0xe66c, // Group: SysRegValues
	AARCH64_SYSREG_ICH_LR13_EL2 = 0xe66d, // Group: SysRegValues
	AARCH64_SYSREG_ICH_LR14_EL2 = 0xe66e, // Group: SysRegValues
	AARCH64_SYSREG_ICH_LR15_EL2 = 0xe66f, // Group: SysRegValues
	AARCH64_SYSREG_VSCTLR_EL2 = 0xe100, // Group: SysRegValues
	AARCH64_SYSREG_MPUIR_EL1 = 0xc004, // Group: SysRegValues
	AARCH64_SYSREG_MPUIR_EL2 = 0xe004, // Group: SysRegValues
	AARCH64_SYSREG_PRENR_EL1 = 0xc309, // Group: SysRegValues
	AARCH64_SYSREG_PRENR_EL2 = 0xe309, // Group: SysRegValues
	AARCH64_SYSREG_PRSELR_EL1 = 0xc311, // Group: SysRegValues
	AARCH64_SYSREG_PRSELR_EL2 = 0xe311, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR_EL1 = 0xc340, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR_EL2 = 0xe340, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR_EL1 = 0xc341, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR_EL2 = 0xe341, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR1_EL1 = 0xc344, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR1_EL1 = 0xc345, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR1_EL2 = 0xe344, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR1_EL2 = 0xe345, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR2_EL1 = 0xc348, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR2_EL1 = 0xc349, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR2_EL2 = 0xe348, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR2_EL2 = 0xe349, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR3_EL1 = 0xc34c, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR3_EL1 = 0xc34d, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR3_EL2 = 0xe34c, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR3_EL2 = 0xe34d, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR4_EL1 = 0xc350, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR4_EL1 = 0xc351, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR4_EL2 = 0xe350, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR4_EL2 = 0xe351, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR5_EL1 = 0xc354, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR5_EL1 = 0xc355, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR5_EL2 = 0xe354, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR5_EL2 = 0xe355, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR6_EL1 = 0xc358, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR6_EL1 = 0xc359, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR6_EL2 = 0xe358, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR6_EL2 = 0xe359, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR7_EL1 = 0xc35c, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR7_EL1 = 0xc35d, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR7_EL2 = 0xe35c, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR7_EL2 = 0xe35d, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR8_EL1 = 0xc360, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR8_EL1 = 0xc361, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR8_EL2 = 0xe360, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR8_EL2 = 0xe361, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR9_EL1 = 0xc364, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR9_EL1 = 0xc365, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR9_EL2 = 0xe364, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR9_EL2 = 0xe365, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR10_EL1 = 0xc368, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR10_EL1 = 0xc369, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR10_EL2 = 0xe368, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR10_EL2 = 0xe369, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR11_EL1 = 0xc36c, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR11_EL1 = 0xc36d, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR11_EL2 = 0xe36c, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR11_EL2 = 0xe36d, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR12_EL1 = 0xc370, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR12_EL1 = 0xc371, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR12_EL2 = 0xe370, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR12_EL2 = 0xe371, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR13_EL1 = 0xc374, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR13_EL1 = 0xc375, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR13_EL2 = 0xe374, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR13_EL2 = 0xe375, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR14_EL1 = 0xc378, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR14_EL1 = 0xc379, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR14_EL2 = 0xe378, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR14_EL2 = 0xe379, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR15_EL1 = 0xc37c, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR15_EL1 = 0xc37d, // Group: SysRegValues
	AARCH64_SYSREG_PRBAR15_EL2 = 0xe37c, // Group: SysRegValues
	AARCH64_SYSREG_PRLAR15_EL2 = 0xe37d, // Group: SysRegValues
	AARCH64_SYSREG_PAN_SysRegValues = 0xc213, // Group: SysRegValues - also encoded as: AARCH64_SYSREG_PAN
	AARCH64_SYSREG_LORSA_EL1 = 0xc520, // Group: SysRegValues
	AARCH64_SYSREG_LOREA_EL1 = 0xc521, // Group: SysRegValues
	AARCH64_SYSREG_LORN_EL1 = 0xc522, // Group: SysRegValues
	AARCH64_SYSREG_LORC_EL1 = 0xc523, // Group: SysRegValues
	AARCH64_SYSREG_TTBR1_EL2 = 0xe101, // Group: SysRegValues
	AARCH64_SYSREG_CNTHV_TVAL_EL2 = 0xe718, // Group: SysRegValues
	AARCH64_SYSREG_CNTHV_CVAL_EL2 = 0xe71a, // Group: SysRegValues
	AARCH64_SYSREG_CNTHV_CTL_EL2 = 0xe719, // Group: SysRegValues
	AARCH64_SYSREG_SCTLR_EL12 = 0xe880, // Group: SysRegValues
	AARCH64_SYSREG_CPACR_EL12 = 0xe882, // Group: SysRegValues
	AARCH64_SYSREG_TTBR0_EL12 = 0xe900, // Group: SysRegValues
	AARCH64_SYSREG_TTBR1_EL12 = 0xe901, // Group: SysRegValues
	AARCH64_SYSREG_TCR_EL12 = 0xe902, // Group: SysRegValues
	AARCH64_SYSREG_AFSR0_EL12 = 0xea88, // Group: SysRegValues
	AARCH64_SYSREG_AFSR1_EL12 = 0xea89, // Group: SysRegValues
	AARCH64_SYSREG_ESR_EL12 = 0xea90, // Group: SysRegValues
	AARCH64_SYSREG_FAR_EL12 = 0xeb00, // Group: SysRegValues
	AARCH64_SYSREG_MAIR_EL12 = 0xed10, // Group: SysRegValues
	AARCH64_SYSREG_AMAIR_EL12 = 0xed18, // Group: SysRegValues
	AARCH64_SYSREG_VBAR_EL12 = 0xee00, // Group: SysRegValues
	AARCH64_SYSREG_CONTEXTIDR_EL12 = 0xee81, // Group: SysRegValues
	AARCH64_SYSREG_CNTKCTL_EL12 = 0xef08, // Group: SysRegValues
	AARCH64_SYSREG_CNTP_TVAL_EL02 = 0xef10, // Group: SysRegValues
	AARCH64_SYSREG_CNTP_CTL_EL02 = 0xef11, // Group: SysRegValues
	AARCH64_SYSREG_CNTP_CVAL_EL02 = 0xef12, // Group: SysRegValues
	AARCH64_SYSREG_CNTV_TVAL_EL02 = 0xef18, // Group: SysRegValues
	AARCH64_SYSREG_CNTV_CTL_EL02 = 0xef19, // Group: SysRegValues
	AARCH64_SYSREG_CNTV_CVAL_EL02 = 0xef1a, // Group: SysRegValues
	AARCH64_SYSREG_SPSR_EL12 = 0xea00, // Group: SysRegValues
	AARCH64_SYSREG_ELR_EL12 = 0xea01, // Group: SysRegValues
	AARCH64_SYSREG_CONTEXTIDR_EL2 = 0xe681, // Group: SysRegValues
	AARCH64_SYSREG_UAO_SysRegValues = 0xc214, // Group: SysRegValues - also encoded as: AARCH64_SYSREG_UAO
	AARCH64_SYSREG_PMBLIMITR_EL1 = 0xc4d0, // Group: SysRegValues
	AARCH64_SYSREG_PMBPTR_EL1 = 0xc4d1, // Group: SysRegValues
	AARCH64_SYSREG_PMBSR_EL1 = 0xc4d3, // Group: SysRegValues
	AARCH64_SYSREG_PMBIDR_EL1 = 0xc4d7, // Group: SysRegValues
	AARCH64_SYSREG_PMSCR_EL2 = 0xe4c8, // Group: SysRegValues
	AARCH64_SYSREG_PMSCR_EL12 = 0xecc8, // Group: SysRegValues
	AARCH64_SYSREG_PMSCR_EL1 = 0xc4c8, // Group: SysRegValues
	AARCH64_SYSREG_PMSICR_EL1 = 0xc4ca, // Group: SysRegValues
	AARCH64_SYSREG_PMSIRR_EL1 = 0xc4cb, // Group: SysRegValues
	AARCH64_SYSREG_PMSFCR_EL1 = 0xc4cc, // Group: SysRegValues
	AARCH64_SYSREG_PMSEVFR_EL1 = 0xc4cd, // Group: SysRegValues
	AARCH64_SYSREG_PMSLATFR_EL1 = 0xc4ce, // Group: SysRegValues
	AARCH64_SYSREG_PMSIDR_EL1 = 0xc4cf, // Group: SysRegValues
	AARCH64_SYSREG_ERRSELR_EL1 = 0xc299, // Group: SysRegValues
	AARCH64_SYSREG_ERXCTLR_EL1 = 0xc2a1, // Group: SysRegValues
	AARCH64_SYSREG_ERXSTATUS_EL1 = 0xc2a2, // Group: SysRegValues
	AARCH64_SYSREG_ERXADDR_EL1 = 0xc2a3, // Group: SysRegValues
	AARCH64_SYSREG_ERXMISC0_EL1 = 0xc2a8, // Group: SysRegValues
	AARCH64_SYSREG_ERXMISC1_EL1 = 0xc2a9, // Group: SysRegValues
	AARCH64_SYSREG_DISR_EL1 = 0xc609, // Group: SysRegValues
	AARCH64_SYSREG_VDISR_EL2 = 0xe609, // Group: SysRegValues
	AARCH64_SYSREG_VSESR_EL2 = 0xe293, // Group: SysRegValues
	AARCH64_SYSREG_APIAKEYLO_EL1 = 0xc108, // Group: SysRegValues
	AARCH64_SYSREG_APIAKEYHI_EL1 = 0xc109, // Group: SysRegValues
	AARCH64_SYSREG_APIBKEYLO_EL1 = 0xc10a, // Group: SysRegValues
	AARCH64_SYSREG_APIBKEYHI_EL1 = 0xc10b, // Group: SysRegValues
	AARCH64_SYSREG_APDAKEYLO_EL1 = 0xc110, // Group: SysRegValues
	AARCH64_SYSREG_APDAKEYHI_EL1 = 0xc111, // Group: SysRegValues
	AARCH64_SYSREG_APDBKEYLO_EL1 = 0xc112, // Group: SysRegValues
	AARCH64_SYSREG_APDBKEYHI_EL1 = 0xc113, // Group: SysRegValues
	AARCH64_SYSREG_APGAKEYLO_EL1 = 0xc118, // Group: SysRegValues
	AARCH64_SYSREG_APGAKEYHI_EL1 = 0xc119, // Group: SysRegValues
	AARCH64_SYSREG_VSTCR_EL2 = 0xe132, // Group: SysRegValues
	AARCH64_SYSREG_VSTTBR_EL2 = 0xe130, // Group: SysRegValues
	AARCH64_SYSREG_CNTHVS_TVAL_EL2 = 0xe720, // Group: SysRegValues
	AARCH64_SYSREG_CNTHVS_CVAL_EL2 = 0xe722, // Group: SysRegValues
	AARCH64_SYSREG_CNTHVS_CTL_EL2 = 0xe721, // Group: SysRegValues
	AARCH64_SYSREG_CNTHPS_TVAL_EL2 = 0xe728, // Group: SysRegValues
	AARCH64_SYSREG_CNTHPS_CVAL_EL2 = 0xe72a, // Group: SysRegValues
	AARCH64_SYSREG_CNTHPS_CTL_EL2 = 0xe729, // Group: SysRegValues
	AARCH64_SYSREG_SDER32_EL2 = 0xe099, // Group: SysRegValues
	AARCH64_SYSREG_ERXPFGCTL_EL1 = 0xc2a5, // Group: SysRegValues
	AARCH64_SYSREG_ERXPFGCDN_EL1 = 0xc2a6, // Group: SysRegValues
	AARCH64_SYSREG_ERXMISC2_EL1 = 0xc2aa, // Group: SysRegValues
	AARCH64_SYSREG_ERXMISC3_EL1 = 0xc2ab, // Group: SysRegValues
	AARCH64_SYSREG_ERXPFGF_EL1 = 0xc2a4, // Group: SysRegValues
	AARCH64_SYSREG_MPAM0_EL1 = 0xc529, // Group: SysRegValues
	AARCH64_SYSREG_MPAM1_EL1 = 0xc528, // Group: SysRegValues
	AARCH64_SYSREG_MPAM2_EL2 = 0xe528, // Group: SysRegValues
	AARCH64_SYSREG_MPAM3_EL3 = 0xf528, // Group: SysRegValues
	AARCH64_SYSREG_MPAM1_EL12 = 0xed28, // Group: SysRegValues
	AARCH64_SYSREG_MPAMHCR_EL2 = 0xe520, // Group: SysRegValues
	AARCH64_SYSREG_MPAMVPMV_EL2 = 0xe521, // Group: SysRegValues
	AARCH64_SYSREG_MPAMVPM0_EL2 = 0xe530, // Group: SysRegValues
	AARCH64_SYSREG_MPAMVPM1_EL2 = 0xe531, // Group: SysRegValues
	AARCH64_SYSREG_MPAMVPM2_EL2 = 0xe532, // Group: SysRegValues
	AARCH64_SYSREG_MPAMVPM3_EL2 = 0xe533, // Group: SysRegValues
	AARCH64_SYSREG_MPAMVPM4_EL2 = 0xe534, // Group: SysRegValues
	AARCH64_SYSREG_MPAMVPM5_EL2 = 0xe535, // Group: SysRegValues
	AARCH64_SYSREG_MPAMVPM6_EL2 = 0xe536, // Group: SysRegValues
	AARCH64_SYSREG_MPAMVPM7_EL2 = 0xe537, // Group: SysRegValues
	AARCH64_SYSREG_MPAMIDR_EL1 = 0xc524, // Group: SysRegValues
	AARCH64_SYSREG_AMCR_EL0 = 0xde90, // Group: SysRegValues
	AARCH64_SYSREG_AMCFGR_EL0 = 0xde91, // Group: SysRegValues
	AARCH64_SYSREG_AMCGCR_EL0 = 0xde92, // Group: SysRegValues
	AARCH64_SYSREG_AMUSERENR_EL0 = 0xde93, // Group: SysRegValues
	AARCH64_SYSREG_AMCNTENCLR0_EL0 = 0xde94, // Group: SysRegValues
	AARCH64_SYSREG_AMCNTENSET0_EL0 = 0xde95, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTR00_EL0 = 0xdea0, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTR01_EL0 = 0xdea1, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTR02_EL0 = 0xdea2, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTR03_EL0 = 0xdea3, // Group: SysRegValues
	AARCH64_SYSREG_AMEVTYPER00_EL0 = 0xdeb0, // Group: SysRegValues
	AARCH64_SYSREG_AMEVTYPER01_EL0 = 0xdeb1, // Group: SysRegValues
	AARCH64_SYSREG_AMEVTYPER02_EL0 = 0xdeb2, // Group: SysRegValues
	AARCH64_SYSREG_AMEVTYPER03_EL0 = 0xdeb3, // Group: SysRegValues
	AARCH64_SYSREG_AMCNTENCLR1_EL0 = 0xde98, // Group: SysRegValues
	AARCH64_SYSREG_AMCNTENSET1_EL0 = 0xde99, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTR10_EL0 = 0xdee0, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTR11_EL0 = 0xdee1, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTR12_EL0 = 0xdee2, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTR13_EL0 = 0xdee3, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTR14_EL0 = 0xdee4, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTR15_EL0 = 0xdee5, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTR16_EL0 = 0xdee6, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTR17_EL0 = 0xdee7, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTR18_EL0 = 0xdee8, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTR19_EL0 = 0xdee9, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTR110_EL0 = 0xdeea, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTR111_EL0 = 0xdeeb, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTR112_EL0 = 0xdeec, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTR113_EL0 = 0xdeed, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTR114_EL0 = 0xdeee, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTR115_EL0 = 0xdeef, // Group: SysRegValues
	AARCH64_SYSREG_AMEVTYPER10_EL0 = 0xdef0, // Group: SysRegValues
	AARCH64_SYSREG_AMEVTYPER11_EL0 = 0xdef1, // Group: SysRegValues
	AARCH64_SYSREG_AMEVTYPER12_EL0 = 0xdef2, // Group: SysRegValues
	AARCH64_SYSREG_AMEVTYPER13_EL0 = 0xdef3, // Group: SysRegValues
	AARCH64_SYSREG_AMEVTYPER14_EL0 = 0xdef4, // Group: SysRegValues
	AARCH64_SYSREG_AMEVTYPER15_EL0 = 0xdef5, // Group: SysRegValues
	AARCH64_SYSREG_AMEVTYPER16_EL0 = 0xdef6, // Group: SysRegValues
	AARCH64_SYSREG_AMEVTYPER17_EL0 = 0xdef7, // Group: SysRegValues
	AARCH64_SYSREG_AMEVTYPER18_EL0 = 0xdef8, // Group: SysRegValues
	AARCH64_SYSREG_AMEVTYPER19_EL0 = 0xdef9, // Group: SysRegValues
	AARCH64_SYSREG_AMEVTYPER110_EL0 = 0xdefa, // Group: SysRegValues
	AARCH64_SYSREG_AMEVTYPER111_EL0 = 0xdefb, // Group: SysRegValues
	AARCH64_SYSREG_AMEVTYPER112_EL0 = 0xdefc, // Group: SysRegValues
	AARCH64_SYSREG_AMEVTYPER113_EL0 = 0xdefd, // Group: SysRegValues
	AARCH64_SYSREG_AMEVTYPER114_EL0 = 0xdefe, // Group: SysRegValues
	AARCH64_SYSREG_AMEVTYPER115_EL0 = 0xdeff, // Group: SysRegValues
	AARCH64_SYSREG_TRFCR_EL1 = 0xc091, // Group: SysRegValues
	AARCH64_SYSREG_TRFCR_EL2 = 0xe091, // Group: SysRegValues
	AARCH64_SYSREG_TRFCR_EL12 = 0xe891, // Group: SysRegValues
	AARCH64_SYSREG_DIT_SysRegValues = 0xda15, // Group: SysRegValues - also encoded as: AARCH64_SYSREG_DIT
	AARCH64_SYSREG_VNCR_EL2 = 0xe110, // Group: SysRegValues
	AARCH64_SYSREG_ZCR_EL1 = 0xc090, // Group: SysRegValues
	AARCH64_SYSREG_ZCR_EL2 = 0xe090, // Group: SysRegValues
	AARCH64_SYSREG_ZCR_EL3 = 0xf090, // Group: SysRegValues
	AARCH64_SYSREG_ZCR_EL12 = 0xe890, // Group: SysRegValues
	AARCH64_SYSREG_SSBS_SysRegValues = 0xda16, // Group: SysRegValues - also encoded as: AARCH64_SYSREG_SSBS
	AARCH64_SYSREG_TCO_SysRegValues = 0xda17, // Group: SysRegValues - also encoded as: AARCH64_SYSREG_TCO
	AARCH64_SYSREG_GCR_EL1 = 0xc086, // Group: SysRegValues
	AARCH64_SYSREG_RGSR_EL1 = 0xc085, // Group: SysRegValues
	AARCH64_SYSREG_TFSR_EL1 = 0xc2b0, // Group: SysRegValues
	AARCH64_SYSREG_TFSR_EL2 = 0xe2b0, // Group: SysRegValues
	AARCH64_SYSREG_TFSR_EL3 = 0xf2b0, // Group: SysRegValues
	AARCH64_SYSREG_TFSR_EL12 = 0xeab0, // Group: SysRegValues
	AARCH64_SYSREG_TFSRE0_EL1 = 0xc2b1, // Group: SysRegValues
	AARCH64_SYSREG_GMID_EL1 = 0xc804, // Group: SysRegValues
	AARCH64_SYSREG_TRCRSR = 0x8850, // Group: SysRegValues
	AARCH64_SYSREG_TRCEXTINSELR0 = 0x8844, // Group: SysRegValues
	AARCH64_SYSREG_TRCEXTINSELR1 = 0x884c, // Group: SysRegValues
	AARCH64_SYSREG_TRCEXTINSELR2 = 0x8854, // Group: SysRegValues
	AARCH64_SYSREG_TRCEXTINSELR3 = 0x885c, // Group: SysRegValues
	AARCH64_SYSREG_TRBLIMITR_EL1 = 0xc4d8, // Group: SysRegValues
	AARCH64_SYSREG_TRBPTR_EL1 = 0xc4d9, // Group: SysRegValues
	AARCH64_SYSREG_TRBBASER_EL1 = 0xc4da, // Group: SysRegValues
	AARCH64_SYSREG_TRBSR_EL1 = 0xc4db, // Group: SysRegValues
	AARCH64_SYSREG_TRBMAR_EL1 = 0xc4dc, // Group: SysRegValues
	AARCH64_SYSREG_TRBTRG_EL1 = 0xc4de, // Group: SysRegValues
	AARCH64_SYSREG_TRBIDR_EL1 = 0xc4df, // Group: SysRegValues
	AARCH64_SYSREG_AMCG1IDR_EL0 = 0xde96, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF00_EL2 = 0xe6c0, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF10_EL2 = 0xe6d0, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF01_EL2 = 0xe6c1, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF11_EL2 = 0xe6d1, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF02_EL2 = 0xe6c2, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF12_EL2 = 0xe6d2, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF03_EL2 = 0xe6c3, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF13_EL2 = 0xe6d3, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF04_EL2 = 0xe6c4, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF14_EL2 = 0xe6d4, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF05_EL2 = 0xe6c5, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF15_EL2 = 0xe6d5, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF06_EL2 = 0xe6c6, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF16_EL2 = 0xe6d6, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF07_EL2 = 0xe6c7, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF17_EL2 = 0xe6d7, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF08_EL2 = 0xe6c8, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF18_EL2 = 0xe6d8, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF09_EL2 = 0xe6c9, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF19_EL2 = 0xe6d9, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF010_EL2 = 0xe6ca, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF110_EL2 = 0xe6da, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF011_EL2 = 0xe6cb, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF111_EL2 = 0xe6db, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF012_EL2 = 0xe6cc, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF112_EL2 = 0xe6dc, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF013_EL2 = 0xe6cd, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF113_EL2 = 0xe6dd, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF014_EL2 = 0xe6ce, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF114_EL2 = 0xe6de, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF015_EL2 = 0xe6cf, // Group: SysRegValues
	AARCH64_SYSREG_AMEVCNTVOFF115_EL2 = 0xe6df, // Group: SysRegValues
	AARCH64_SYSREG_HFGRTR_EL2 = 0xe08c, // Group: SysRegValues
	AARCH64_SYSREG_HFGWTR_EL2 = 0xe08d, // Group: SysRegValues
	AARCH64_SYSREG_HFGITR_EL2 = 0xe08e, // Group: SysRegValues
	AARCH64_SYSREG_HDFGRTR_EL2 = 0xe18c, // Group: SysRegValues
	AARCH64_SYSREG_HDFGWTR_EL2 = 0xe18d, // Group: SysRegValues
	AARCH64_SYSREG_HAFGRTR_EL2 = 0xe18e, // Group: SysRegValues
	AARCH64_SYSREG_HDFGRTR2_EL2 = 0xe188, // Group: SysRegValues
	AARCH64_SYSREG_HDFGWTR2_EL2 = 0xe189, // Group: SysRegValues
	AARCH64_SYSREG_HFGRTR2_EL2 = 0xe18a, // Group: SysRegValues
	AARCH64_SYSREG_HFGWTR2_EL2 = 0xe18b, // Group: SysRegValues
	AARCH64_SYSREG_HFGITR2_EL2 = 0xe18f, // Group: SysRegValues
	AARCH64_SYSREG_CNTSCALE_EL2 = 0xe704, // Group: SysRegValues
	AARCH64_SYSREG_CNTISCALE_EL2 = 0xe705, // Group: SysRegValues
	AARCH64_SYSREG_CNTPOFF_EL2 = 0xe706, // Group: SysRegValues
	AARCH64_SYSREG_CNTVFRQ_EL2 = 0xe707, // Group: SysRegValues
	AARCH64_SYSREG_CNTPCTSS_EL0 = 0xdf05, // Group: SysRegValues
	AARCH64_SYSREG_CNTVCTSS_EL0 = 0xdf06, // Group: SysRegValues
	AARCH64_SYSREG_ACCDATA_EL1 = 0xc685, // Group: SysRegValues
	AARCH64_SYSREG_BRBCR_EL1 = 0x8c80, // Group: SysRegValues
	AARCH64_SYSREG_BRBCR_EL12 = 0xac80, // Group: SysRegValues
	AARCH64_SYSREG_BRBCR_EL2 = 0xa480, // Group: SysRegValues
	AARCH64_SYSREG_BRBFCR_EL1 = 0x8c81, // Group: SysRegValues
	AARCH64_SYSREG_BRBIDR0_EL1 = 0x8c90, // Group: SysRegValues
	AARCH64_SYSREG_BRBINFINJ_EL1 = 0x8c88, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRCINJ_EL1 = 0x8c89, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGTINJ_EL1 = 0x8c8a, // Group: SysRegValues
	AARCH64_SYSREG_BRBTS_EL1 = 0x8c82, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF0_EL1 = 0x8c00, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC0_EL1 = 0x8c01, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT0_EL1 = 0x8c02, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF1_EL1 = 0x8c08, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC1_EL1 = 0x8c09, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT1_EL1 = 0x8c0a, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF2_EL1 = 0x8c10, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC2_EL1 = 0x8c11, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT2_EL1 = 0x8c12, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF3_EL1 = 0x8c18, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC3_EL1 = 0x8c19, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT3_EL1 = 0x8c1a, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF4_EL1 = 0x8c20, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC4_EL1 = 0x8c21, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT4_EL1 = 0x8c22, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF5_EL1 = 0x8c28, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC5_EL1 = 0x8c29, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT5_EL1 = 0x8c2a, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF6_EL1 = 0x8c30, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC6_EL1 = 0x8c31, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT6_EL1 = 0x8c32, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF7_EL1 = 0x8c38, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC7_EL1 = 0x8c39, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT7_EL1 = 0x8c3a, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF8_EL1 = 0x8c40, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC8_EL1 = 0x8c41, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT8_EL1 = 0x8c42, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF9_EL1 = 0x8c48, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC9_EL1 = 0x8c49, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT9_EL1 = 0x8c4a, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF10_EL1 = 0x8c50, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC10_EL1 = 0x8c51, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT10_EL1 = 0x8c52, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF11_EL1 = 0x8c58, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC11_EL1 = 0x8c59, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT11_EL1 = 0x8c5a, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF12_EL1 = 0x8c60, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC12_EL1 = 0x8c61, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT12_EL1 = 0x8c62, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF13_EL1 = 0x8c68, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC13_EL1 = 0x8c69, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT13_EL1 = 0x8c6a, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF14_EL1 = 0x8c70, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC14_EL1 = 0x8c71, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT14_EL1 = 0x8c72, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF15_EL1 = 0x8c78, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC15_EL1 = 0x8c79, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT15_EL1 = 0x8c7a, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF16_EL1 = 0x8c04, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC16_EL1 = 0x8c05, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT16_EL1 = 0x8c06, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF17_EL1 = 0x8c0c, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC17_EL1 = 0x8c0d, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT17_EL1 = 0x8c0e, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF18_EL1 = 0x8c14, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC18_EL1 = 0x8c15, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT18_EL1 = 0x8c16, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF19_EL1 = 0x8c1c, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC19_EL1 = 0x8c1d, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT19_EL1 = 0x8c1e, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF20_EL1 = 0x8c24, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC20_EL1 = 0x8c25, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT20_EL1 = 0x8c26, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF21_EL1 = 0x8c2c, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC21_EL1 = 0x8c2d, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT21_EL1 = 0x8c2e, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF22_EL1 = 0x8c34, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC22_EL1 = 0x8c35, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT22_EL1 = 0x8c36, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF23_EL1 = 0x8c3c, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC23_EL1 = 0x8c3d, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT23_EL1 = 0x8c3e, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF24_EL1 = 0x8c44, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC24_EL1 = 0x8c45, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT24_EL1 = 0x8c46, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF25_EL1 = 0x8c4c, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC25_EL1 = 0x8c4d, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT25_EL1 = 0x8c4e, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF26_EL1 = 0x8c54, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC26_EL1 = 0x8c55, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT26_EL1 = 0x8c56, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF27_EL1 = 0x8c5c, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC27_EL1 = 0x8c5d, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT27_EL1 = 0x8c5e, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF28_EL1 = 0x8c64, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC28_EL1 = 0x8c65, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT28_EL1 = 0x8c66, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF29_EL1 = 0x8c6c, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC29_EL1 = 0x8c6d, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT29_EL1 = 0x8c6e, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF30_EL1 = 0x8c74, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC30_EL1 = 0x8c75, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT30_EL1 = 0x8c76, // Group: SysRegValues
	AARCH64_SYSREG_BRBINF31_EL1 = 0x8c7c, // Group: SysRegValues
	AARCH64_SYSREG_BRBSRC31_EL1 = 0x8c7d, // Group: SysRegValues
	AARCH64_SYSREG_BRBTGT31_EL1 = 0x8c7e, // Group: SysRegValues
	AARCH64_SYSREG_PMSNEVFR_EL1 = 0xc4c9, // Group: SysRegValues
	AARCH64_SYSREG_CPM_IOACC_CTL_EL3 = 0xff90, // Group: SysRegValues
	AARCH64_SYSREG_SMCR_EL1 = 0xc096, // Group: SysRegValues
	AARCH64_SYSREG_SMCR_EL2 = 0xe096, // Group: SysRegValues
	AARCH64_SYSREG_SMCR_EL3 = 0xf096, // Group: SysRegValues
	AARCH64_SYSREG_SMCR_EL12 = 0xe896, // Group: SysRegValues
	AARCH64_SYSREG_SVCR = 0xda12, // Group: SysRegValues
	AARCH64_SYSREG_SMPRI_EL1 = 0xc094, // Group: SysRegValues
	AARCH64_SYSREG_SMPRIMAP_EL2 = 0xe095, // Group: SysRegValues
	AARCH64_SYSREG_SMIDR_EL1 = 0xc806, // Group: SysRegValues
	AARCH64_SYSREG_TPIDR2_EL0 = 0xde85, // Group: SysRegValues
	AARCH64_SYSREG_MPAMSM_EL1 = 0xc52b, // Group: SysRegValues
	AARCH64_SYSREG_ALLINT_SysRegValues = 0xc218, // Group: SysRegValues - also encoded as: AARCH64_SYSREG_ALLINT
	AARCH64_SYSREG_ICC_NMIAR1_EL1 = 0xc64d, // Group: SysRegValues
	AARCH64_SYSREG_AMAIR2_EL1 = 0xc519, // Group: SysRegValues
	AARCH64_SYSREG_AMAIR2_EL12 = 0xed19, // Group: SysRegValues
	AARCH64_SYSREG_AMAIR2_EL2 = 0xe519, // Group: SysRegValues
	AARCH64_SYSREG_AMAIR2_EL3 = 0xf519, // Group: SysRegValues
	AARCH64_SYSREG_MAIR2_EL1 = 0xc511, // Group: SysRegValues
	AARCH64_SYSREG_MAIR2_EL12 = 0xed11, // Group: SysRegValues
	AARCH64_SYSREG_MAIR2_EL2 = 0xe509, // Group: SysRegValues
	AARCH64_SYSREG_MAIR2_EL3 = 0xf509, // Group: SysRegValues
	AARCH64_SYSREG_PIRE0_EL1 = 0xc512, // Group: SysRegValues
	AARCH64_SYSREG_PIRE0_EL12 = 0xed12, // Group: SysRegValues
	AARCH64_SYSREG_PIRE0_EL2 = 0xe512, // Group: SysRegValues
	AARCH64_SYSREG_PIR_EL1 = 0xc513, // Group: SysRegValues
	AARCH64_SYSREG_PIR_EL12 = 0xed13, // Group: SysRegValues
	AARCH64_SYSREG_PIR_EL2 = 0xe513, // Group: SysRegValues
	AARCH64_SYSREG_PIR_EL3 = 0xf513, // Group: SysRegValues
	AARCH64_SYSREG_S2PIR_EL2 = 0xe515, // Group: SysRegValues
	AARCH64_SYSREG_POR_EL0 = 0xdd14, // Group: SysRegValues
	AARCH64_SYSREG_POR_EL1 = 0xc514, // Group: SysRegValues
	AARCH64_SYSREG_POR_EL12 = 0xed14, // Group: SysRegValues
	AARCH64_SYSREG_POR_EL2 = 0xe514, // Group: SysRegValues
	AARCH64_SYSREG_POR_EL3 = 0xf514, // Group: SysRegValues
	AARCH64_SYSREG_S2POR_EL1 = 0xc515, // Group: SysRegValues
	AARCH64_SYSREG_SCTLR2_EL1 = 0xc083, // Group: SysRegValues
	AARCH64_SYSREG_SCTLR2_EL12 = 0xe883, // Group: SysRegValues
	AARCH64_SYSREG_SCTLR2_EL2 = 0xe083, // Group: SysRegValues
	AARCH64_SYSREG_SCTLR2_EL3 = 0xf083, // Group: SysRegValues
	AARCH64_SYSREG_TCR2_EL1 = 0xc103, // Group: SysRegValues
	AARCH64_SYSREG_TCR2_EL12 = 0xe903, // Group: SysRegValues
	AARCH64_SYSREG_TCR2_EL2 = 0xe103, // Group: SysRegValues
	AARCH64_SYSREG_RCWMASK_EL1 = 0xc686, // Group: SysRegValues
	AARCH64_SYSREG_RCWSMASK_EL1 = 0xc683, // Group: SysRegValues
	AARCH64_SYSREG_MDSELR_EL1 = 0x8022, // Group: SysRegValues
	AARCH64_SYSREG_PMUACR_EL1 = 0xc4f4, // Group: SysRegValues
	AARCH64_SYSREG_PMCCNTSVR_EL1 = 0x875f, // Group: SysRegValues
	AARCH64_SYSREG_PMICNTSVR_EL1 = 0x8760, // Group: SysRegValues
	AARCH64_SYSREG_PMSSCR_EL1 = 0xc4eb, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR0_EL1 = 0x8740, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR1_EL1 = 0x8741, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR2_EL1 = 0x8742, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR3_EL1 = 0x8743, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR4_EL1 = 0x8744, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR5_EL1 = 0x8745, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR6_EL1 = 0x8746, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR7_EL1 = 0x8747, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR8_EL1 = 0x8748, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR9_EL1 = 0x8749, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR10_EL1 = 0x874a, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR11_EL1 = 0x874b, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR12_EL1 = 0x874c, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR13_EL1 = 0x874d, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR14_EL1 = 0x874e, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR15_EL1 = 0x874f, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR16_EL1 = 0x8750, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR17_EL1 = 0x8751, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR18_EL1 = 0x8752, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR19_EL1 = 0x8753, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR20_EL1 = 0x8754, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR21_EL1 = 0x8755, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR22_EL1 = 0x8756, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR23_EL1 = 0x8757, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR24_EL1 = 0x8758, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR25_EL1 = 0x8759, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR26_EL1 = 0x875a, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR27_EL1 = 0x875b, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR28_EL1 = 0x875c, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR29_EL1 = 0x875d, // Group: SysRegValues
	AARCH64_SYSREG_PMEVCNTSVR30_EL1 = 0x875e, // Group: SysRegValues
	AARCH64_SYSREG_PMICNTR_EL0 = 0xdca0, // Group: SysRegValues
	AARCH64_SYSREG_PMICFILTR_EL0 = 0xdcb0, // Group: SysRegValues
	AARCH64_SYSREG_PMZR_EL0 = 0xdcec, // Group: SysRegValues
	AARCH64_SYSREG_PMECR_EL1 = 0xc4f5, // Group: SysRegValues
	AARCH64_SYSREG_PMIAR_EL1 = 0xc4f7, // Group: SysRegValues
	AARCH64_SYSREG_SPMACCESSR_EL1 = 0x84eb, // Group: SysRegValues
	AARCH64_SYSREG_SPMACCESSR_EL12 = 0xaceb, // Group: SysRegValues
	AARCH64_SYSREG_SPMACCESSR_EL2 = 0xa4eb, // Group: SysRegValues
	AARCH64_SYSREG_SPMACCESSR_EL3 = 0xb4eb, // Group: SysRegValues
	AARCH64_SYSREG_SPMCNTENCLR_EL0 = 0x9ce2, // Group: SysRegValues
	AARCH64_SYSREG_SPMCNTENSET_EL0 = 0x9ce1, // Group: SysRegValues
	AARCH64_SYSREG_SPMCR_EL0 = 0x9ce0, // Group: SysRegValues
	AARCH64_SYSREG_SPMDEVAFF_EL1 = 0x84ee, // Group: SysRegValues
	AARCH64_SYSREG_SPMDEVARCH_EL1 = 0x84ed, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVCNTR0_EL0 = 0x9f00, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILT2R0_EL0 = 0x9f30, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILTR0_EL0 = 0x9f20, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVTYPER0_EL0 = 0x9f10, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVCNTR1_EL0 = 0x9f01, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILT2R1_EL0 = 0x9f31, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILTR1_EL0 = 0x9f21, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVTYPER1_EL0 = 0x9f11, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVCNTR2_EL0 = 0x9f02, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILT2R2_EL0 = 0x9f32, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILTR2_EL0 = 0x9f22, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVTYPER2_EL0 = 0x9f12, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVCNTR3_EL0 = 0x9f03, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILT2R3_EL0 = 0x9f33, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILTR3_EL0 = 0x9f23, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVTYPER3_EL0 = 0x9f13, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVCNTR4_EL0 = 0x9f04, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILT2R4_EL0 = 0x9f34, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILTR4_EL0 = 0x9f24, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVTYPER4_EL0 = 0x9f14, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVCNTR5_EL0 = 0x9f05, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILT2R5_EL0 = 0x9f35, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILTR5_EL0 = 0x9f25, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVTYPER5_EL0 = 0x9f15, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVCNTR6_EL0 = 0x9f06, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILT2R6_EL0 = 0x9f36, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILTR6_EL0 = 0x9f26, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVTYPER6_EL0 = 0x9f16, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVCNTR7_EL0 = 0x9f07, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILT2R7_EL0 = 0x9f37, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILTR7_EL0 = 0x9f27, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVTYPER7_EL0 = 0x9f17, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVCNTR8_EL0 = 0x9f08, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILT2R8_EL0 = 0x9f38, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILTR8_EL0 = 0x9f28, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVTYPER8_EL0 = 0x9f18, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVCNTR9_EL0 = 0x9f09, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILT2R9_EL0 = 0x9f39, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILTR9_EL0 = 0x9f29, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVTYPER9_EL0 = 0x9f19, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVCNTR10_EL0 = 0x9f0a, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILT2R10_EL0 = 0x9f3a, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILTR10_EL0 = 0x9f2a, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVTYPER10_EL0 = 0x9f1a, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVCNTR11_EL0 = 0x9f0b, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILT2R11_EL0 = 0x9f3b, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILTR11_EL0 = 0x9f2b, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVTYPER11_EL0 = 0x9f1b, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVCNTR12_EL0 = 0x9f0c, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILT2R12_EL0 = 0x9f3c, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILTR12_EL0 = 0x9f2c, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVTYPER12_EL0 = 0x9f1c, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVCNTR13_EL0 = 0x9f0d, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILT2R13_EL0 = 0x9f3d, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILTR13_EL0 = 0x9f2d, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVTYPER13_EL0 = 0x9f1d, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVCNTR14_EL0 = 0x9f0e, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILT2R14_EL0 = 0x9f3e, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILTR14_EL0 = 0x9f2e, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVTYPER14_EL0 = 0x9f1e, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVCNTR15_EL0 = 0x9f0f, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILT2R15_EL0 = 0x9f3f, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVFILTR15_EL0 = 0x9f2f, // Group: SysRegValues
	AARCH64_SYSREG_SPMEVTYPER15_EL0 = 0x9f1f, // Group: SysRegValues
	AARCH64_SYSREG_SPMIIDR_EL1 = 0x84ec, // Group: SysRegValues
	AARCH64_SYSREG_SPMINTENCLR_EL1 = 0x84f2, // Group: SysRegValues
	AARCH64_SYSREG_SPMINTENSET_EL1 = 0x84f1, // Group: SysRegValues
	AARCH64_SYSREG_SPMOVSCLR_EL0 = 0x9ce3, // Group: SysRegValues
	AARCH64_SYSREG_SPMOVSSET_EL0 = 0x9cf3, // Group: SysRegValues
	AARCH64_SYSREG_SPMSELR_EL0 = 0x9ce5, // Group: SysRegValues
	AARCH64_SYSREG_SPMCGCR0_EL1 = 0x84e8, // Group: SysRegValues
	AARCH64_SYSREG_SPMCGCR1_EL1 = 0x84e9, // Group: SysRegValues
	AARCH64_SYSREG_SPMCFGR_EL1 = 0x84ef, // Group: SysRegValues
	AARCH64_SYSREG_SPMROOTCR_EL3 = 0xb4f7, // Group: SysRegValues
	AARCH64_SYSREG_SPMSCR_EL1 = 0xbcf7, // Group: SysRegValues
	AARCH64_SYSREG_TRCITEEDCR = 0x8811, // Group: SysRegValues
	AARCH64_SYSREG_TRCITECR_EL1 = 0xc093, // Group: SysRegValues
	AARCH64_SYSREG_TRCITECR_EL12 = 0xe893, // Group: SysRegValues
	AARCH64_SYSREG_TRCITECR_EL2 = 0xe093, // Group: SysRegValues
	AARCH64_SYSREG_PMSDSFR_EL1 = 0xc4d4, // Group: SysRegValues
	AARCH64_SYSREG_ERXGSR_EL1 = 0xc29a, // Group: SysRegValues
	AARCH64_SYSREG_PFAR_EL1 = 0xc305, // Group: SysRegValues
	AARCH64_SYSREG_PFAR_EL12 = 0xeb05, // Group: SysRegValues
	AARCH64_SYSREG_PFAR_EL2 = 0xe305, // Group: SysRegValues
	AARCH64_SYSREG_PM_SysRegValues = 0xc219, // Group: SysRegValues - also encoded as: AARCH64_SYSREG_PM
	AARCH64_SYSREG_CSYNC_TSBValues = 0x0, // Group: TSBValues - also encoded as: AARCH64_SYSREG_CSYNC

	// clang-format on
	// generated content <AArch64GenCSSystemRegisterEnum.inc> end
} arm64_sysreg;

/// System PState Field (MSR instruction)
typedef enum arm64_pstate {
  ARM64_PSTATE_INVALID = 0,
  ARM64_PSTATE_SPSEL = 0x05,
  ARM64_PSTATE_DAIFSET = 0x1e,
  ARM64_PSTATE_DAIFCLR = 0x1f,
  ARM64_PSTATE_PAN = 0x4,
  ARM64_PSTATE_UAO = 0x3,
  ARM64_PSTATE_DIT = 0x1a,
} arm64_pstate;

/// Vector arrangement specifier (for FloatingPoint/Advanced SIMD insn)
typedef enum arm64_vas {
  ARM64_VAS_INVALID = 0,
  ARM64_VAS_16B,
  ARM64_VAS_8B,
  ARM64_VAS_4B,
  ARM64_VAS_1B,
  ARM64_VAS_8H,
  ARM64_VAS_4H,
  ARM64_VAS_2H,
  ARM64_VAS_1H,
  ARM64_VAS_4S,
  ARM64_VAS_2S,
  ARM64_VAS_1S,
  ARM64_VAS_2D,
  ARM64_VAS_1D,
  ARM64_VAS_1Q,
} arm64_vas;

/// Memory barrier operands
typedef enum arm64_barrier_op {
  ARM64_BARRIER_INVALID = 0,
  ARM64_BARRIER_OSHLD = 0x1,
  ARM64_BARRIER_OSHST = 0x2,
  ARM64_BARRIER_OSH = 0x3,
  ARM64_BARRIER_NSHLD = 0x5,
  ARM64_BARRIER_NSHST = 0x6,
  ARM64_BARRIER_NSH = 0x7,
  ARM64_BARRIER_ISHLD = 0x9,
  ARM64_BARRIER_ISHST = 0xa,
  ARM64_BARRIER_ISH = 0xb,
  ARM64_BARRIER_LD = 0xd,
  ARM64_BARRIER_ST = 0xe,
  ARM64_BARRIER_SY = 0xf
} arm64_barrier_op;

/// Operand type for instruction's operands
typedef enum arm64_op_type {
  ARM64_OP_INVALID = 0, ///< = CS_OP_INVALID (Uninitialized).
  ARM64_OP_REG,		///< = CS_OP_REG (Register operand).
  ARM64_OP_IMM,		///< = CS_OP_IMM (Immediate operand).
  ARM64_OP_MEM,		///< = CS_OP_MEM (Memory operand).
  ARM64_OP_FP,		///< = CS_OP_FP (Floating-Point operand).
  ARM64_OP_CIMM = 64,	///< C-Immediate
  ARM64_OP_REG_MRS,	///< MRS register operand.
  ARM64_OP_REG_MSR,	///< MSR register operand.
  ARM64_OP_PSTATE,	///< PState operand.
  ARM64_OP_SYS,		///< SYS operand for IC/DC/AT/TLBI instructions.
  ARM64_OP_SVCR,	///< SVCR operand for MSR SVCR instructions.
  ARM64_OP_PREFETCH,	///< Prefetch operand (PRFM).
  ARM64_OP_BARRIER,	///< Memory barrier operand (ISB/DMB/DSB instructions).
  ARM64_OP_SME_INDEX,	///< SME instruction operand with with index.
} arm64_op_type;

/// SYS operands (IC/DC/AC/TLBI)
typedef enum arm64_sys_op {
  ARM64_SYS_INVALID = 0,

  /// TLBI operations
  ARM64_TLBI_ALLE1,
  ARM64_TLBI_ALLE1IS,
  ARM64_TLBI_ALLE1ISNXS,
  ARM64_TLBI_ALLE1NXS,
  ARM64_TLBI_ALLE1OS,
  ARM64_TLBI_ALLE1OSNXS,
  ARM64_TLBI_ALLE2,
  ARM64_TLBI_ALLE2IS,
  ARM64_TLBI_ALLE2ISNXS,
  ARM64_TLBI_ALLE2NXS,
  ARM64_TLBI_ALLE2OS,
  ARM64_TLBI_ALLE2OSNXS,
  ARM64_TLBI_ALLE3,
  ARM64_TLBI_ALLE3IS,
  ARM64_TLBI_ALLE3ISNXS,
  ARM64_TLBI_ALLE3NXS,
  ARM64_TLBI_ALLE3OS,
  ARM64_TLBI_ALLE3OSNXS,
  ARM64_TLBI_ASIDE1,
  ARM64_TLBI_ASIDE1IS,
  ARM64_TLBI_ASIDE1ISNXS,
  ARM64_TLBI_ASIDE1NXS,
  ARM64_TLBI_ASIDE1OS,
  ARM64_TLBI_ASIDE1OSNXS,
  ARM64_TLBI_IPAS2E1,
  ARM64_TLBI_IPAS2E1IS,
  ARM64_TLBI_IPAS2E1ISNXS,
  ARM64_TLBI_IPAS2E1NXS,
  ARM64_TLBI_IPAS2E1OS,
  ARM64_TLBI_IPAS2E1OSNXS,
  ARM64_TLBI_IPAS2LE1,
  ARM64_TLBI_IPAS2LE1IS,
  ARM64_TLBI_IPAS2LE1ISNXS,
  ARM64_TLBI_IPAS2LE1NXS,
  ARM64_TLBI_IPAS2LE1OS,
  ARM64_TLBI_IPAS2LE1OSNXS,
  ARM64_TLBI_PAALL,
  ARM64_TLBI_PAALLNXS,
  ARM64_TLBI_PAALLOS,
  ARM64_TLBI_PAALLOSNXS,
  ARM64_TLBI_RIPAS2E1,
  ARM64_TLBI_RIPAS2E1IS,
  ARM64_TLBI_RIPAS2E1ISNXS,
  ARM64_TLBI_RIPAS2E1NXS,
  ARM64_TLBI_RIPAS2E1OS,
  ARM64_TLBI_RIPAS2E1OSNXS,
  ARM64_TLBI_RIPAS2LE1,
  ARM64_TLBI_RIPAS2LE1IS,
  ARM64_TLBI_RIPAS2LE1ISNXS,
  ARM64_TLBI_RIPAS2LE1NXS,
  ARM64_TLBI_RIPAS2LE1OS,
  ARM64_TLBI_RIPAS2LE1OSNXS,
  ARM64_TLBI_RPALOS,
  ARM64_TLBI_RPALOSNXS,
  ARM64_TLBI_RPAOS,
  ARM64_TLBI_RPAOSNXS,
  ARM64_TLBI_RVAAE1,
  ARM64_TLBI_RVAAE1IS,
  ARM64_TLBI_RVAAE1ISNXS,
  ARM64_TLBI_RVAAE1NXS,
  ARM64_TLBI_RVAAE1OS,
  ARM64_TLBI_RVAAE1OSNXS,
  ARM64_TLBI_RVAALE1,
  ARM64_TLBI_RVAALE1IS,
  ARM64_TLBI_RVAALE1ISNXS,
  ARM64_TLBI_RVAALE1NXS,
  ARM64_TLBI_RVAALE1OS,
  ARM64_TLBI_RVAALE1OSNXS,
  ARM64_TLBI_RVAE1,
  ARM64_TLBI_RVAE1IS,
  ARM64_TLBI_RVAE1ISNXS,
  ARM64_TLBI_RVAE1NXS,
  ARM64_TLBI_RVAE1OS,
  ARM64_TLBI_RVAE1OSNXS,
  ARM64_TLBI_RVAE2,
  ARM64_TLBI_RVAE2IS,
  ARM64_TLBI_RVAE2ISNXS,
  ARM64_TLBI_RVAE2NXS,
  ARM64_TLBI_RVAE2OS,
  ARM64_TLBI_RVAE2OSNXS,
  ARM64_TLBI_RVAE3,
  ARM64_TLBI_RVAE3IS,
  ARM64_TLBI_RVAE3ISNXS,
  ARM64_TLBI_RVAE3NXS,
  ARM64_TLBI_RVAE3OS,
  ARM64_TLBI_RVAE3OSNXS,
  ARM64_TLBI_RVALE1,
  ARM64_TLBI_RVALE1IS,
  ARM64_TLBI_RVALE1ISNXS,
  ARM64_TLBI_RVALE1NXS,
  ARM64_TLBI_RVALE1OS,
  ARM64_TLBI_RVALE1OSNXS,
  ARM64_TLBI_RVALE2,
  ARM64_TLBI_RVALE2IS,
  ARM64_TLBI_RVALE2ISNXS,
  ARM64_TLBI_RVALE2NXS,
  ARM64_TLBI_RVALE2OS,
  ARM64_TLBI_RVALE2OSNXS,
  ARM64_TLBI_RVALE3,
  ARM64_TLBI_RVALE3IS,
  ARM64_TLBI_RVALE3ISNXS,
  ARM64_TLBI_RVALE3NXS,
  ARM64_TLBI_RVALE3OS,
  ARM64_TLBI_RVALE3OSNXS,
  ARM64_TLBI_VAAE1,
  ARM64_TLBI_VAAE1IS,
  ARM64_TLBI_VAAE1ISNXS,
  ARM64_TLBI_VAAE1NXS,
  ARM64_TLBI_VAAE1OS,
  ARM64_TLBI_VAAE1OSNXS,
  ARM64_TLBI_VAALE1,
  ARM64_TLBI_VAALE1IS,
  ARM64_TLBI_VAALE1ISNXS,
  ARM64_TLBI_VAALE1NXS,
  ARM64_TLBI_VAALE1OS,
  ARM64_TLBI_VAALE1OSNXS,
  ARM64_TLBI_VAE1,
  ARM64_TLBI_VAE1IS,
  ARM64_TLBI_VAE1ISNXS,
  ARM64_TLBI_VAE1NXS,
  ARM64_TLBI_VAE1OS,
  ARM64_TLBI_VAE1OSNXS,
  ARM64_TLBI_VAE2,
  ARM64_TLBI_VAE2IS,
  ARM64_TLBI_VAE2ISNXS,
  ARM64_TLBI_VAE2NXS,
  ARM64_TLBI_VAE2OS,
  ARM64_TLBI_VAE2OSNXS,
  ARM64_TLBI_VAE3,
  ARM64_TLBI_VAE3IS,
  ARM64_TLBI_VAE3ISNXS,
  ARM64_TLBI_VAE3NXS,
  ARM64_TLBI_VAE3OS,
  ARM64_TLBI_VAE3OSNXS,
  ARM64_TLBI_VALE1,
  ARM64_TLBI_VALE1IS,
  ARM64_TLBI_VALE1ISNXS,
  ARM64_TLBI_VALE1NXS,
  ARM64_TLBI_VALE1OS,
  ARM64_TLBI_VALE1OSNXS,
  ARM64_TLBI_VALE2,
  ARM64_TLBI_VALE2IS,
  ARM64_TLBI_VALE2ISNXS,
  ARM64_TLBI_VALE2NXS,
  ARM64_TLBI_VALE2OS,
  ARM64_TLBI_VALE2OSNXS,
  ARM64_TLBI_VALE3,
  ARM64_TLBI_VALE3IS,
  ARM64_TLBI_VALE3ISNXS,
  ARM64_TLBI_VALE3NXS,
  ARM64_TLBI_VALE3OS,
  ARM64_TLBI_VALE3OSNXS,
  ARM64_TLBI_VMALLE1,
  ARM64_TLBI_VMALLE1IS,
  ARM64_TLBI_VMALLE1ISNXS,
  ARM64_TLBI_VMALLE1NXS,
  ARM64_TLBI_VMALLE1OS,
  ARM64_TLBI_VMALLE1OSNXS,
  ARM64_TLBI_VMALLS12E1,
  ARM64_TLBI_VMALLS12E1IS,
  ARM64_TLBI_VMALLS12E1ISNXS,
  ARM64_TLBI_VMALLS12E1NXS,
  ARM64_TLBI_VMALLS12E1OS,
  ARM64_TLBI_VMALLS12E1OSNXS,

  /// AT operations
  ARM64_AT_S1E1R,
  ARM64_AT_S1E2R,
  ARM64_AT_S1E3R,
  ARM64_AT_S1E1W,
  ARM64_AT_S1E2W,
  ARM64_AT_S1E3W,
  ARM64_AT_S1E0R,
  ARM64_AT_S1E0W,
  ARM64_AT_S12E1R,
  ARM64_AT_S12E1W,
  ARM64_AT_S12E0R,
  ARM64_AT_S12E0W,
  ARM64_AT_S1E1RP,
  ARM64_AT_S1E1WP,

  /// DC operations
  ARM64_DC_CGDSW,
  ARM64_DC_CGDVAC,
  ARM64_DC_CGDVADP,
  ARM64_DC_CGDVAP,
  ARM64_DC_CGSW,
  ARM64_DC_CGVAC,
  ARM64_DC_CGVADP,
  ARM64_DC_CGVAP,
  ARM64_DC_CIGDSW,
  ARM64_DC_CIGDVAC,
  ARM64_DC_CIGSW,
  ARM64_DC_CIGVAC,
  ARM64_DC_CISW,
  ARM64_DC_CIVAC,
  ARM64_DC_CSW,
  ARM64_DC_CVAC,
  ARM64_DC_CVADP,
  ARM64_DC_CVAP,
  ARM64_DC_CVAU,
  ARM64_DC_GVA,
  ARM64_DC_GZVA,
  ARM64_DC_IGDSW,
  ARM64_DC_IGDVAC,
  ARM64_DC_IGSW,
  ARM64_DC_IGVAC,
  ARM64_DC_ISW,
  ARM64_DC_IVAC,
  ARM64_DC_ZVA,

  /// IC operations
  ARM64_IC_IALLUIS,
  ARM64_IC_IALLU,
  ARM64_IC_IVAU,
} arm64_sys_op;

/// SVCR operands
typedef enum arm64_svcr_op {
  ARM64_SVCR_INVALID = 0,

  ARM64_SVCR_SVCRSM = 0x1,
  ARM64_SVCR_SVCRSMZA = 0x3,
  ARM64_SVCR_SVCRZA = 0x2,
} arm64_svcr_op;

/// Prefetch operations (PRFM)
typedef enum arm64_prefetch_op {
  ARM64_PRFM_INVALID = 0,
  ARM64_PRFM_PLDL1KEEP = 0x00 + 1,
  ARM64_PRFM_PLDL1STRM = 0x01 + 1,
  ARM64_PRFM_PLDL2KEEP = 0x02 + 1,
  ARM64_PRFM_PLDL2STRM = 0x03 + 1,
  ARM64_PRFM_PLDL3KEEP = 0x04 + 1,
  ARM64_PRFM_PLDL3STRM = 0x05 + 1,
  ARM64_PRFM_PLIL1KEEP = 0x08 + 1,
  ARM64_PRFM_PLIL1STRM = 0x09 + 1,
  ARM64_PRFM_PLIL2KEEP = 0x0a + 1,
  ARM64_PRFM_PLIL2STRM = 0x0b + 1,
  ARM64_PRFM_PLIL3KEEP = 0x0c + 1,
  ARM64_PRFM_PLIL3STRM = 0x0d + 1,
  ARM64_PRFM_PSTL1KEEP = 0x10 + 1,
  ARM64_PRFM_PSTL1STRM = 0x11 + 1,
  ARM64_PRFM_PSTL2KEEP = 0x12 + 1,
  ARM64_PRFM_PSTL2STRM = 0x13 + 1,
  ARM64_PRFM_PSTL3KEEP = 0x14 + 1,
  ARM64_PRFM_PSTL3STRM = 0x15 + 1,
} arm64_prefetch_op;

/// ARM64 registers
typedef enum arm64_reg {
	// generated content <AArch64GenCSRegEnum.inc> begin
	// clang-format off

	AARCH64_REG_INVALID = 0,
	AARCH64_REG_FFR = 1,
	AARCH64_REG_FP = 2,
	AARCH64_REG_FPCR = 3,
	AARCH64_REG_LR = 4,
	AARCH64_REG_NZCV = 5,
	AARCH64_REG_SP = 6,
	AARCH64_REG_VG = 7,
	AARCH64_REG_WSP = 8,
	AARCH64_REG_WZR = 9,
	AARCH64_REG_XZR = 10,
	AARCH64_REG_ZA = 11,
	AARCH64_REG_B0 = 12,
	AARCH64_REG_B1 = 13,
	AARCH64_REG_B2 = 14,
	AARCH64_REG_B3 = 15,
	AARCH64_REG_B4 = 16,
	AARCH64_REG_B5 = 17,
	AARCH64_REG_B6 = 18,
	AARCH64_REG_B7 = 19,
	AARCH64_REG_B8 = 20,
	AARCH64_REG_B9 = 21,
	AARCH64_REG_B10 = 22,
	AARCH64_REG_B11 = 23,
	AARCH64_REG_B12 = 24,
	AARCH64_REG_B13 = 25,
	AARCH64_REG_B14 = 26,
	AARCH64_REG_B15 = 27,
	AARCH64_REG_B16 = 28,
	AARCH64_REG_B17 = 29,
	AARCH64_REG_B18 = 30,
	AARCH64_REG_B19 = 31,
	AARCH64_REG_B20 = 32,
	AARCH64_REG_B21 = 33,
	AARCH64_REG_B22 = 34,
	AARCH64_REG_B23 = 35,
	AARCH64_REG_B24 = 36,
	AARCH64_REG_B25 = 37,
	AARCH64_REG_B26 = 38,
	AARCH64_REG_B27 = 39,
	AARCH64_REG_B28 = 40,
	AARCH64_REG_B29 = 41,
	AARCH64_REG_B30 = 42,
	AARCH64_REG_B31 = 43,
	AARCH64_REG_D0 = 44,
	AARCH64_REG_D1 = 45,
	AARCH64_REG_D2 = 46,
	AARCH64_REG_D3 = 47,
	AARCH64_REG_D4 = 48,
	AARCH64_REG_D5 = 49,
	AARCH64_REG_D6 = 50,
	AARCH64_REG_D7 = 51,
	AARCH64_REG_D8 = 52,
	AARCH64_REG_D9 = 53,
	AARCH64_REG_D10 = 54,
	AARCH64_REG_D11 = 55,
	AARCH64_REG_D12 = 56,
	AARCH64_REG_D13 = 57,
	AARCH64_REG_D14 = 58,
	AARCH64_REG_D15 = 59,
	AARCH64_REG_D16 = 60,
	AARCH64_REG_D17 = 61,
	AARCH64_REG_D18 = 62,
	AARCH64_REG_D19 = 63,
	AARCH64_REG_D20 = 64,
	AARCH64_REG_D21 = 65,
	AARCH64_REG_D22 = 66,
	AARCH64_REG_D23 = 67,
	AARCH64_REG_D24 = 68,
	AARCH64_REG_D25 = 69,
	AARCH64_REG_D26 = 70,
	AARCH64_REG_D27 = 71,
	AARCH64_REG_D28 = 72,
	AARCH64_REG_D29 = 73,
	AARCH64_REG_D30 = 74,
	AARCH64_REG_D31 = 75,
	AARCH64_REG_H0 = 76,
	AARCH64_REG_H1 = 77,
	AARCH64_REG_H2 = 78,
	AARCH64_REG_H3 = 79,
	AARCH64_REG_H4 = 80,
	AARCH64_REG_H5 = 81,
	AARCH64_REG_H6 = 82,
	AARCH64_REG_H7 = 83,
	AARCH64_REG_H8 = 84,
	AARCH64_REG_H9 = 85,
	AARCH64_REG_H10 = 86,
	AARCH64_REG_H11 = 87,
	AARCH64_REG_H12 = 88,
	AARCH64_REG_H13 = 89,
	AARCH64_REG_H14 = 90,
	AARCH64_REG_H15 = 91,
	AARCH64_REG_H16 = 92,
	AARCH64_REG_H17 = 93,
	AARCH64_REG_H18 = 94,
	AARCH64_REG_H19 = 95,
	AARCH64_REG_H20 = 96,
	AARCH64_REG_H21 = 97,
	AARCH64_REG_H22 = 98,
	AARCH64_REG_H23 = 99,
	AARCH64_REG_H24 = 100,
	AARCH64_REG_H25 = 101,
	AARCH64_REG_H26 = 102,
	AARCH64_REG_H27 = 103,
	AARCH64_REG_H28 = 104,
	AARCH64_REG_H29 = 105,
	AARCH64_REG_H30 = 106,
	AARCH64_REG_H31 = 107,
	AARCH64_REG_P0 = 108,
	AARCH64_REG_P1 = 109,
	AARCH64_REG_P2 = 110,
	AARCH64_REG_P3 = 111,
	AARCH64_REG_P4 = 112,
	AARCH64_REG_P5 = 113,
	AARCH64_REG_P6 = 114,
	AARCH64_REG_P7 = 115,
	AARCH64_REG_P8 = 116,
	AARCH64_REG_P9 = 117,
	AARCH64_REG_P10 = 118,
	AARCH64_REG_P11 = 119,
	AARCH64_REG_P12 = 120,
	AARCH64_REG_P13 = 121,
	AARCH64_REG_P14 = 122,
	AARCH64_REG_P15 = 123,
	AARCH64_REG_Q0 = 124,
	AARCH64_REG_Q1 = 125,
	AARCH64_REG_Q2 = 126,
	AARCH64_REG_Q3 = 127,
	AARCH64_REG_Q4 = 128,
	AARCH64_REG_Q5 = 129,
	AARCH64_REG_Q6 = 130,
	AARCH64_REG_Q7 = 131,
	AARCH64_REG_Q8 = 132,
	AARCH64_REG_Q9 = 133,
	AARCH64_REG_Q10 = 134,
	AARCH64_REG_Q11 = 135,
	AARCH64_REG_Q12 = 136,
	AARCH64_REG_Q13 = 137,
	AARCH64_REG_Q14 = 138,
	AARCH64_REG_Q15 = 139,
	AARCH64_REG_Q16 = 140,
	AARCH64_REG_Q17 = 141,
	AARCH64_REG_Q18 = 142,
	AARCH64_REG_Q19 = 143,
	AARCH64_REG_Q20 = 144,
	AARCH64_REG_Q21 = 145,
	AARCH64_REG_Q22 = 146,
	AARCH64_REG_Q23 = 147,
	AARCH64_REG_Q24 = 148,
	AARCH64_REG_Q25 = 149,
	AARCH64_REG_Q26 = 150,
	AARCH64_REG_Q27 = 151,
	AARCH64_REG_Q28 = 152,
	AARCH64_REG_Q29 = 153,
	AARCH64_REG_Q30 = 154,
	AARCH64_REG_Q31 = 155,
	AARCH64_REG_S0 = 156,
	AARCH64_REG_S1 = 157,
	AARCH64_REG_S2 = 158,
	AARCH64_REG_S3 = 159,
	AARCH64_REG_S4 = 160,
	AARCH64_REG_S5 = 161,
	AARCH64_REG_S6 = 162,
	AARCH64_REG_S7 = 163,
	AARCH64_REG_S8 = 164,
	AARCH64_REG_S9 = 165,
	AARCH64_REG_S10 = 166,
	AARCH64_REG_S11 = 167,
	AARCH64_REG_S12 = 168,
	AARCH64_REG_S13 = 169,
	AARCH64_REG_S14 = 170,
	AARCH64_REG_S15 = 171,
	AARCH64_REG_S16 = 172,
	AARCH64_REG_S17 = 173,
	AARCH64_REG_S18 = 174,
	AARCH64_REG_S19 = 175,
	AARCH64_REG_S20 = 176,
	AARCH64_REG_S21 = 177,
	AARCH64_REG_S22 = 178,
	AARCH64_REG_S23 = 179,
	AARCH64_REG_S24 = 180,
	AARCH64_REG_S25 = 181,
	AARCH64_REG_S26 = 182,
	AARCH64_REG_S27 = 183,
	AARCH64_REG_S28 = 184,
	AARCH64_REG_S29 = 185,
	AARCH64_REG_S30 = 186,
	AARCH64_REG_S31 = 187,
	AARCH64_REG_W0 = 188,
	AARCH64_REG_W1 = 189,
	AARCH64_REG_W2 = 190,
	AARCH64_REG_W3 = 191,
	AARCH64_REG_W4 = 192,
	AARCH64_REG_W5 = 193,
	AARCH64_REG_W6 = 194,
	AARCH64_REG_W7 = 195,
	AARCH64_REG_W8 = 196,
	AARCH64_REG_W9 = 197,
	AARCH64_REG_W10 = 198,
	AARCH64_REG_W11 = 199,
	AARCH64_REG_W12 = 200,
	AARCH64_REG_W13 = 201,
	AARCH64_REG_W14 = 202,
	AARCH64_REG_W15 = 203,
	AARCH64_REG_W16 = 204,
	AARCH64_REG_W17 = 205,
	AARCH64_REG_W18 = 206,
	AARCH64_REG_W19 = 207,
	AARCH64_REG_W20 = 208,
	AARCH64_REG_W21 = 209,
	AARCH64_REG_W22 = 210,
	AARCH64_REG_W23 = 211,
	AARCH64_REG_W24 = 212,
	AARCH64_REG_W25 = 213,
	AARCH64_REG_W26 = 214,
	AARCH64_REG_W27 = 215,
	AARCH64_REG_W28 = 216,
	AARCH64_REG_W29 = 217,
	AARCH64_REG_W30 = 218,
	AARCH64_REG_X0 = 219,
	AARCH64_REG_X1 = 220,
	AARCH64_REG_X2 = 221,
	AARCH64_REG_X3 = 222,
	AARCH64_REG_X4 = 223,
	AARCH64_REG_X5 = 224,
	AARCH64_REG_X6 = 225,
	AARCH64_REG_X7 = 226,
	AARCH64_REG_X8 = 227,
	AARCH64_REG_X9 = 228,
	AARCH64_REG_X10 = 229,
	AARCH64_REG_X11 = 230,
	AARCH64_REG_X12 = 231,
	AARCH64_REG_X13 = 232,
	AARCH64_REG_X14 = 233,
	AARCH64_REG_X15 = 234,
	AARCH64_REG_X16 = 235,
	AARCH64_REG_X17 = 236,
	AARCH64_REG_X18 = 237,
	AARCH64_REG_X19 = 238,
	AARCH64_REG_X20 = 239,
	AARCH64_REG_X21 = 240,
	AARCH64_REG_X22 = 241,
	AARCH64_REG_X23 = 242,
	AARCH64_REG_X24 = 243,
	AARCH64_REG_X25 = 244,
	AARCH64_REG_X26 = 245,
	AARCH64_REG_X27 = 246,
	AARCH64_REG_X28 = 247,
	AARCH64_REG_Z0 = 248,
	AARCH64_REG_Z1 = 249,
	AARCH64_REG_Z2 = 250,
	AARCH64_REG_Z3 = 251,
	AARCH64_REG_Z4 = 252,
	AARCH64_REG_Z5 = 253,
	AARCH64_REG_Z6 = 254,
	AARCH64_REG_Z7 = 255,
	AARCH64_REG_Z8 = 256,
	AARCH64_REG_Z9 = 257,
	AARCH64_REG_Z10 = 258,
	AARCH64_REG_Z11 = 259,
	AARCH64_REG_Z12 = 260,
	AARCH64_REG_Z13 = 261,
	AARCH64_REG_Z14 = 262,
	AARCH64_REG_Z15 = 263,
	AARCH64_REG_Z16 = 264,
	AARCH64_REG_Z17 = 265,
	AARCH64_REG_Z18 = 266,
	AARCH64_REG_Z19 = 267,
	AARCH64_REG_Z20 = 268,
	AARCH64_REG_Z21 = 269,
	AARCH64_REG_Z22 = 270,
	AARCH64_REG_Z23 = 271,
	AARCH64_REG_Z24 = 272,
	AARCH64_REG_Z25 = 273,
	AARCH64_REG_Z26 = 274,
	AARCH64_REG_Z27 = 275,
	AARCH64_REG_Z28 = 276,
	AARCH64_REG_Z29 = 277,
	AARCH64_REG_Z30 = 278,
	AARCH64_REG_Z31 = 279,
	AARCH64_REG_ZAB0 = 280,
	AARCH64_REG_ZAD0 = 281,
	AARCH64_REG_ZAD1 = 282,
	AARCH64_REG_ZAD2 = 283,
	AARCH64_REG_ZAD3 = 284,
	AARCH64_REG_ZAD4 = 285,
	AARCH64_REG_ZAD5 = 286,
	AARCH64_REG_ZAD6 = 287,
	AARCH64_REG_ZAD7 = 288,
	AARCH64_REG_ZAH0 = 289,
	AARCH64_REG_ZAH1 = 290,
	AARCH64_REG_ZAQ0 = 291,
	AARCH64_REG_ZAQ1 = 292,
	AARCH64_REG_ZAQ2 = 293,
	AARCH64_REG_ZAQ3 = 294,
	AARCH64_REG_ZAQ4 = 295,
	AARCH64_REG_ZAQ5 = 296,
	AARCH64_REG_ZAQ6 = 297,
	AARCH64_REG_ZAQ7 = 298,
	AARCH64_REG_ZAQ8 = 299,
	AARCH64_REG_ZAQ9 = 300,
	AARCH64_REG_ZAQ10 = 301,
	AARCH64_REG_ZAQ11 = 302,
	AARCH64_REG_ZAQ12 = 303,
	AARCH64_REG_ZAQ13 = 304,
	AARCH64_REG_ZAQ14 = 305,
	AARCH64_REG_ZAQ15 = 306,
	AARCH64_REG_ZAS0 = 307,
	AARCH64_REG_ZAS1 = 308,
	AARCH64_REG_ZAS2 = 309,
	AARCH64_REG_ZAS3 = 310,
	AARCH64_REG_ZT0 = 311,
	AARCH64_REG_Z0_HI = 312,
	AARCH64_REG_Z1_HI = 313,
	AARCH64_REG_Z2_HI = 314,
	AARCH64_REG_Z3_HI = 315,
	AARCH64_REG_Z4_HI = 316,
	AARCH64_REG_Z5_HI = 317,
	AARCH64_REG_Z6_HI = 318,
	AARCH64_REG_Z7_HI = 319,
	AARCH64_REG_Z8_HI = 320,
	AARCH64_REG_Z9_HI = 321,
	AARCH64_REG_Z10_HI = 322,
	AARCH64_REG_Z11_HI = 323,
	AARCH64_REG_Z12_HI = 324,
	AARCH64_REG_Z13_HI = 325,
	AARCH64_REG_Z14_HI = 326,
	AARCH64_REG_Z15_HI = 327,
	AARCH64_REG_Z16_HI = 328,
	AARCH64_REG_Z17_HI = 329,
	AARCH64_REG_Z18_HI = 330,
	AARCH64_REG_Z19_HI = 331,
	AARCH64_REG_Z20_HI = 332,
	AARCH64_REG_Z21_HI = 333,
	AARCH64_REG_Z22_HI = 334,
	AARCH64_REG_Z23_HI = 335,
	AARCH64_REG_Z24_HI = 336,
	AARCH64_REG_Z25_HI = 337,
	AARCH64_REG_Z26_HI = 338,
	AARCH64_REG_Z27_HI = 339,
	AARCH64_REG_Z28_HI = 340,
	AARCH64_REG_Z29_HI = 341,
	AARCH64_REG_Z30_HI = 342,
	AARCH64_REG_Z31_HI = 343,
	AARCH64_REG_D0_D1 = 344,
	AARCH64_REG_D1_D2 = 345,
	AARCH64_REG_D2_D3 = 346,
	AARCH64_REG_D3_D4 = 347,
	AARCH64_REG_D4_D5 = 348,
	AARCH64_REG_D5_D6 = 349,
	AARCH64_REG_D6_D7 = 350,
	AARCH64_REG_D7_D8 = 351,
	AARCH64_REG_D8_D9 = 352,
	AARCH64_REG_D9_D10 = 353,
	AARCH64_REG_D10_D11 = 354,
	AARCH64_REG_D11_D12 = 355,
	AARCH64_REG_D12_D13 = 356,
	AARCH64_REG_D13_D14 = 357,
	AARCH64_REG_D14_D15 = 358,
	AARCH64_REG_D15_D16 = 359,
	AARCH64_REG_D16_D17 = 360,
	AARCH64_REG_D17_D18 = 361,
	AARCH64_REG_D18_D19 = 362,
	AARCH64_REG_D19_D20 = 363,
	AARCH64_REG_D20_D21 = 364,
	AARCH64_REG_D21_D22 = 365,
	AARCH64_REG_D22_D23 = 366,
	AARCH64_REG_D23_D24 = 367,
	AARCH64_REG_D24_D25 = 368,
	AARCH64_REG_D25_D26 = 369,
	AARCH64_REG_D26_D27 = 370,
	AARCH64_REG_D27_D28 = 371,
	AARCH64_REG_D28_D29 = 372,
	AARCH64_REG_D29_D30 = 373,
	AARCH64_REG_D30_D31 = 374,
	AARCH64_REG_D31_D0 = 375,
	AARCH64_REG_D0_D1_D2_D3 = 376,
	AARCH64_REG_D1_D2_D3_D4 = 377,
	AARCH64_REG_D2_D3_D4_D5 = 378,
	AARCH64_REG_D3_D4_D5_D6 = 379,
	AARCH64_REG_D4_D5_D6_D7 = 380,
	AARCH64_REG_D5_D6_D7_D8 = 381,
	AARCH64_REG_D6_D7_D8_D9 = 382,
	AARCH64_REG_D7_D8_D9_D10 = 383,
	AARCH64_REG_D8_D9_D10_D11 = 384,
	AARCH64_REG_D9_D10_D11_D12 = 385,
	AARCH64_REG_D10_D11_D12_D13 = 386,
	AARCH64_REG_D11_D12_D13_D14 = 387,
	AARCH64_REG_D12_D13_D14_D15 = 388,
	AARCH64_REG_D13_D14_D15_D16 = 389,
	AARCH64_REG_D14_D15_D16_D17 = 390,
	AARCH64_REG_D15_D16_D17_D18 = 391,
	AARCH64_REG_D16_D17_D18_D19 = 392,
	AARCH64_REG_D17_D18_D19_D20 = 393,
	AARCH64_REG_D18_D19_D20_D21 = 394,
	AARCH64_REG_D19_D20_D21_D22 = 395,
	AARCH64_REG_D20_D21_D22_D23 = 396,
	AARCH64_REG_D21_D22_D23_D24 = 397,
	AARCH64_REG_D22_D23_D24_D25 = 398,
	AARCH64_REG_D23_D24_D25_D26 = 399,
	AARCH64_REG_D24_D25_D26_D27 = 400,
	AARCH64_REG_D25_D26_D27_D28 = 401,
	AARCH64_REG_D26_D27_D28_D29 = 402,
	AARCH64_REG_D27_D28_D29_D30 = 403,
	AARCH64_REG_D28_D29_D30_D31 = 404,
	AARCH64_REG_D29_D30_D31_D0 = 405,
	AARCH64_REG_D30_D31_D0_D1 = 406,
	AARCH64_REG_D31_D0_D1_D2 = 407,
	AARCH64_REG_D0_D1_D2 = 408,
	AARCH64_REG_D1_D2_D3 = 409,
	AARCH64_REG_D2_D3_D4 = 410,
	AARCH64_REG_D3_D4_D5 = 411,
	AARCH64_REG_D4_D5_D6 = 412,
	AARCH64_REG_D5_D6_D7 = 413,
	AARCH64_REG_D6_D7_D8 = 414,
	AARCH64_REG_D7_D8_D9 = 415,
	AARCH64_REG_D8_D9_D10 = 416,
	AARCH64_REG_D9_D10_D11 = 417,
	AARCH64_REG_D10_D11_D12 = 418,
	AARCH64_REG_D11_D12_D13 = 419,
	AARCH64_REG_D12_D13_D14 = 420,
	AARCH64_REG_D13_D14_D15 = 421,
	AARCH64_REG_D14_D15_D16 = 422,
	AARCH64_REG_D15_D16_D17 = 423,
	AARCH64_REG_D16_D17_D18 = 424,
	AARCH64_REG_D17_D18_D19 = 425,
	AARCH64_REG_D18_D19_D20 = 426,
	AARCH64_REG_D19_D20_D21 = 427,
	AARCH64_REG_D20_D21_D22 = 428,
	AARCH64_REG_D21_D22_D23 = 429,
	AARCH64_REG_D22_D23_D24 = 430,
	AARCH64_REG_D23_D24_D25 = 431,
	AARCH64_REG_D24_D25_D26 = 432,
	AARCH64_REG_D25_D26_D27 = 433,
	AARCH64_REG_D26_D27_D28 = 434,
	AARCH64_REG_D27_D28_D29 = 435,
	AARCH64_REG_D28_D29_D30 = 436,
	AARCH64_REG_D29_D30_D31 = 437,
	AARCH64_REG_D30_D31_D0 = 438,
	AARCH64_REG_D31_D0_D1 = 439,
	AARCH64_REG_P0_P1 = 440,
	AARCH64_REG_P1_P2 = 441,
	AARCH64_REG_P2_P3 = 442,
	AARCH64_REG_P3_P4 = 443,
	AARCH64_REG_P4_P5 = 444,
	AARCH64_REG_P5_P6 = 445,
	AARCH64_REG_P6_P7 = 446,
	AARCH64_REG_P7_P8 = 447,
	AARCH64_REG_P8_P9 = 448,
	AARCH64_REG_P9_P10 = 449,
	AARCH64_REG_P10_P11 = 450,
	AARCH64_REG_P11_P12 = 451,
	AARCH64_REG_P12_P13 = 452,
	AARCH64_REG_P13_P14 = 453,
	AARCH64_REG_P14_P15 = 454,
	AARCH64_REG_P15_P0 = 455,
	AARCH64_REG_Q0_Q1 = 456,
	AARCH64_REG_Q1_Q2 = 457,
	AARCH64_REG_Q2_Q3 = 458,
	AARCH64_REG_Q3_Q4 = 459,
	AARCH64_REG_Q4_Q5 = 460,
	AARCH64_REG_Q5_Q6 = 461,
	AARCH64_REG_Q6_Q7 = 462,
	AARCH64_REG_Q7_Q8 = 463,
	AARCH64_REG_Q8_Q9 = 464,
	AARCH64_REG_Q9_Q10 = 465,
	AARCH64_REG_Q10_Q11 = 466,
	AARCH64_REG_Q11_Q12 = 467,
	AARCH64_REG_Q12_Q13 = 468,
	AARCH64_REG_Q13_Q14 = 469,
	AARCH64_REG_Q14_Q15 = 470,
	AARCH64_REG_Q15_Q16 = 471,
	AARCH64_REG_Q16_Q17 = 472,
	AARCH64_REG_Q17_Q18 = 473,
	AARCH64_REG_Q18_Q19 = 474,
	AARCH64_REG_Q19_Q20 = 475,
	AARCH64_REG_Q20_Q21 = 476,
	AARCH64_REG_Q21_Q22 = 477,
	AARCH64_REG_Q22_Q23 = 478,
	AARCH64_REG_Q23_Q24 = 479,
	AARCH64_REG_Q24_Q25 = 480,
	AARCH64_REG_Q25_Q26 = 481,
	AARCH64_REG_Q26_Q27 = 482,
	AARCH64_REG_Q27_Q28 = 483,
	AARCH64_REG_Q28_Q29 = 484,
	AARCH64_REG_Q29_Q30 = 485,
	AARCH64_REG_Q30_Q31 = 486,
	AARCH64_REG_Q31_Q0 = 487,
	AARCH64_REG_Q0_Q1_Q2_Q3 = 488,
	AARCH64_REG_Q1_Q2_Q3_Q4 = 489,
	AARCH64_REG_Q2_Q3_Q4_Q5 = 490,
	AARCH64_REG_Q3_Q4_Q5_Q6 = 491,
	AARCH64_REG_Q4_Q5_Q6_Q7 = 492,
	AARCH64_REG_Q5_Q6_Q7_Q8 = 493,
	AARCH64_REG_Q6_Q7_Q8_Q9 = 494,
	AARCH64_REG_Q7_Q8_Q9_Q10 = 495,
	AARCH64_REG_Q8_Q9_Q10_Q11 = 496,
	AARCH64_REG_Q9_Q10_Q11_Q12 = 497,
	AARCH64_REG_Q10_Q11_Q12_Q13 = 498,
	AARCH64_REG_Q11_Q12_Q13_Q14 = 499,
	AARCH64_REG_Q12_Q13_Q14_Q15 = 500,
	AARCH64_REG_Q13_Q14_Q15_Q16 = 501,
	AARCH64_REG_Q14_Q15_Q16_Q17 = 502,
	AARCH64_REG_Q15_Q16_Q17_Q18 = 503,
	AARCH64_REG_Q16_Q17_Q18_Q19 = 504,
	AARCH64_REG_Q17_Q18_Q19_Q20 = 505,
	AARCH64_REG_Q18_Q19_Q20_Q21 = 506,
	AARCH64_REG_Q19_Q20_Q21_Q22 = 507,
	AARCH64_REG_Q20_Q21_Q22_Q23 = 508,
	AARCH64_REG_Q21_Q22_Q23_Q24 = 509,
	AARCH64_REG_Q22_Q23_Q24_Q25 = 510,
	AARCH64_REG_Q23_Q24_Q25_Q26 = 511,
	AARCH64_REG_Q24_Q25_Q26_Q27 = 512,
	AARCH64_REG_Q25_Q26_Q27_Q28 = 513,
	AARCH64_REG_Q26_Q27_Q28_Q29 = 514,
	AARCH64_REG_Q27_Q28_Q29_Q30 = 515,
	AARCH64_REG_Q28_Q29_Q30_Q31 = 516,
	AARCH64_REG_Q29_Q30_Q31_Q0 = 517,
	AARCH64_REG_Q30_Q31_Q0_Q1 = 518,
	AARCH64_REG_Q31_Q0_Q1_Q2 = 519,
	AARCH64_REG_Q0_Q1_Q2 = 520,
	AARCH64_REG_Q1_Q2_Q3 = 521,
	AARCH64_REG_Q2_Q3_Q4 = 522,
	AARCH64_REG_Q3_Q4_Q5 = 523,
	AARCH64_REG_Q4_Q5_Q6 = 524,
	AARCH64_REG_Q5_Q6_Q7 = 525,
	AARCH64_REG_Q6_Q7_Q8 = 526,
	AARCH64_REG_Q7_Q8_Q9 = 527,
	AARCH64_REG_Q8_Q9_Q10 = 528,
	AARCH64_REG_Q9_Q10_Q11 = 529,
	AARCH64_REG_Q10_Q11_Q12 = 530,
	AARCH64_REG_Q11_Q12_Q13 = 531,
	AARCH64_REG_Q12_Q13_Q14 = 532,
	AARCH64_REG_Q13_Q14_Q15 = 533,
	AARCH64_REG_Q14_Q15_Q16 = 534,
	AARCH64_REG_Q15_Q16_Q17 = 535,
	AARCH64_REG_Q16_Q17_Q18 = 536,
	AARCH64_REG_Q17_Q18_Q19 = 537,
	AARCH64_REG_Q18_Q19_Q20 = 538,
	AARCH64_REG_Q19_Q20_Q21 = 539,
	AARCH64_REG_Q20_Q21_Q22 = 540,
	AARCH64_REG_Q21_Q22_Q23 = 541,
	AARCH64_REG_Q22_Q23_Q24 = 542,
	AARCH64_REG_Q23_Q24_Q25 = 543,
	AARCH64_REG_Q24_Q25_Q26 = 544,
	AARCH64_REG_Q25_Q26_Q27 = 545,
	AARCH64_REG_Q26_Q27_Q28 = 546,
	AARCH64_REG_Q27_Q28_Q29 = 547,
	AARCH64_REG_Q28_Q29_Q30 = 548,
	AARCH64_REG_Q29_Q30_Q31 = 549,
	AARCH64_REG_Q30_Q31_Q0 = 550,
	AARCH64_REG_Q31_Q0_Q1 = 551,
	AARCH64_REG_X22_X23_X24_X25_X26_X27_X28_FP = 552,
	AARCH64_REG_X0_X1_X2_X3_X4_X5_X6_X7 = 553,
	AARCH64_REG_X2_X3_X4_X5_X6_X7_X8_X9 = 554,
	AARCH64_REG_X4_X5_X6_X7_X8_X9_X10_X11 = 555,
	AARCH64_REG_X6_X7_X8_X9_X10_X11_X12_X13 = 556,
	AARCH64_REG_X8_X9_X10_X11_X12_X13_X14_X15 = 557,
	AARCH64_REG_X10_X11_X12_X13_X14_X15_X16_X17 = 558,
	AARCH64_REG_X12_X13_X14_X15_X16_X17_X18_X19 = 559,
	AARCH64_REG_X14_X15_X16_X17_X18_X19_X20_X21 = 560,
	AARCH64_REG_X16_X17_X18_X19_X20_X21_X22_X23 = 561,
	AARCH64_REG_X18_X19_X20_X21_X22_X23_X24_X25 = 562,
	AARCH64_REG_X20_X21_X22_X23_X24_X25_X26_X27 = 563,
	AARCH64_REG_W30_WZR = 564,
	AARCH64_REG_W0_W1 = 565,
	AARCH64_REG_W2_W3 = 566,
	AARCH64_REG_W4_W5 = 567,
	AARCH64_REG_W6_W7 = 568,
	AARCH64_REG_W8_W9 = 569,
	AARCH64_REG_W10_W11 = 570,
	AARCH64_REG_W12_W13 = 571,
	AARCH64_REG_W14_W15 = 572,
	AARCH64_REG_W16_W17 = 573,
	AARCH64_REG_W18_W19 = 574,
	AARCH64_REG_W20_W21 = 575,
	AARCH64_REG_W22_W23 = 576,
	AARCH64_REG_W24_W25 = 577,
	AARCH64_REG_W26_W27 = 578,
	AARCH64_REG_W28_W29 = 579,
	AARCH64_REG_LR_XZR = 580,
	AARCH64_REG_X28_FP = 581,
	AARCH64_REG_X0_X1 = 582,
	AARCH64_REG_X2_X3 = 583,
	AARCH64_REG_X4_X5 = 584,
	AARCH64_REG_X6_X7 = 585,
	AARCH64_REG_X8_X9 = 586,
	AARCH64_REG_X10_X11 = 587,
	AARCH64_REG_X12_X13 = 588,
	AARCH64_REG_X14_X15 = 589,
	AARCH64_REG_X16_X17 = 590,
	AARCH64_REG_X18_X19 = 591,
	AARCH64_REG_X20_X21 = 592,
	AARCH64_REG_X22_X23 = 593,
	AARCH64_REG_X24_X25 = 594,
	AARCH64_REG_X26_X27 = 595,
	AARCH64_REG_Z0_Z1 = 596,
	AARCH64_REG_Z1_Z2 = 597,
	AARCH64_REG_Z2_Z3 = 598,
	AARCH64_REG_Z3_Z4 = 599,
	AARCH64_REG_Z4_Z5 = 600,
	AARCH64_REG_Z5_Z6 = 601,
	AARCH64_REG_Z6_Z7 = 602,
	AARCH64_REG_Z7_Z8 = 603,
	AARCH64_REG_Z8_Z9 = 604,
	AARCH64_REG_Z9_Z10 = 605,
	AARCH64_REG_Z10_Z11 = 606,
	AARCH64_REG_Z11_Z12 = 607,
	AARCH64_REG_Z12_Z13 = 608,
	AARCH64_REG_Z13_Z14 = 609,
	AARCH64_REG_Z14_Z15 = 610,
	AARCH64_REG_Z15_Z16 = 611,
	AARCH64_REG_Z16_Z17 = 612,
	AARCH64_REG_Z17_Z18 = 613,
	AARCH64_REG_Z18_Z19 = 614,
	AARCH64_REG_Z19_Z20 = 615,
	AARCH64_REG_Z20_Z21 = 616,
	AARCH64_REG_Z21_Z22 = 617,
	AARCH64_REG_Z22_Z23 = 618,
	AARCH64_REG_Z23_Z24 = 619,
	AARCH64_REG_Z24_Z25 = 620,
	AARCH64_REG_Z25_Z26 = 621,
	AARCH64_REG_Z26_Z27 = 622,
	AARCH64_REG_Z27_Z28 = 623,
	AARCH64_REG_Z28_Z29 = 624,
	AARCH64_REG_Z29_Z30 = 625,
	AARCH64_REG_Z30_Z31 = 626,
	AARCH64_REG_Z31_Z0 = 627,
	AARCH64_REG_Z0_Z1_Z2_Z3 = 628,
	AARCH64_REG_Z1_Z2_Z3_Z4 = 629,
	AARCH64_REG_Z2_Z3_Z4_Z5 = 630,
	AARCH64_REG_Z3_Z4_Z5_Z6 = 631,
	AARCH64_REG_Z4_Z5_Z6_Z7 = 632,
	AARCH64_REG_Z5_Z6_Z7_Z8 = 633,
	AARCH64_REG_Z6_Z7_Z8_Z9 = 634,
	AARCH64_REG_Z7_Z8_Z9_Z10 = 635,
	AARCH64_REG_Z8_Z9_Z10_Z11 = 636,
	AARCH64_REG_Z9_Z10_Z11_Z12 = 637,
	AARCH64_REG_Z10_Z11_Z12_Z13 = 638,
	AARCH64_REG_Z11_Z12_Z13_Z14 = 639,
	AARCH64_REG_Z12_Z13_Z14_Z15 = 640,
	AARCH64_REG_Z13_Z14_Z15_Z16 = 641,
	AARCH64_REG_Z14_Z15_Z16_Z17 = 642,
	AARCH64_REG_Z15_Z16_Z17_Z18 = 643,
	AARCH64_REG_Z16_Z17_Z18_Z19 = 644,
	AARCH64_REG_Z17_Z18_Z19_Z20 = 645,
	AARCH64_REG_Z18_Z19_Z20_Z21 = 646,
	AARCH64_REG_Z19_Z20_Z21_Z22 = 647,
	AARCH64_REG_Z20_Z21_Z22_Z23 = 648,
	AARCH64_REG_Z21_Z22_Z23_Z24 = 649,
	AARCH64_REG_Z22_Z23_Z24_Z25 = 650,
	AARCH64_REG_Z23_Z24_Z25_Z26 = 651,
	AARCH64_REG_Z24_Z25_Z26_Z27 = 652,
	AARCH64_REG_Z25_Z26_Z27_Z28 = 653,
	AARCH64_REG_Z26_Z27_Z28_Z29 = 654,
	AARCH64_REG_Z27_Z28_Z29_Z30 = 655,
	AARCH64_REG_Z28_Z29_Z30_Z31 = 656,
	AARCH64_REG_Z29_Z30_Z31_Z0 = 657,
	AARCH64_REG_Z30_Z31_Z0_Z1 = 658,
	AARCH64_REG_Z31_Z0_Z1_Z2 = 659,
	AARCH64_REG_Z0_Z1_Z2 = 660,
	AARCH64_REG_Z1_Z2_Z3 = 661,
	AARCH64_REG_Z2_Z3_Z4 = 662,
	AARCH64_REG_Z3_Z4_Z5 = 663,
	AARCH64_REG_Z4_Z5_Z6 = 664,
	AARCH64_REG_Z5_Z6_Z7 = 665,
	AARCH64_REG_Z6_Z7_Z8 = 666,
	AARCH64_REG_Z7_Z8_Z9 = 667,
	AARCH64_REG_Z8_Z9_Z10 = 668,
	AARCH64_REG_Z9_Z10_Z11 = 669,
	AARCH64_REG_Z10_Z11_Z12 = 670,
	AARCH64_REG_Z11_Z12_Z13 = 671,
	AARCH64_REG_Z12_Z13_Z14 = 672,
	AARCH64_REG_Z13_Z14_Z15 = 673,
	AARCH64_REG_Z14_Z15_Z16 = 674,
	AARCH64_REG_Z15_Z16_Z17 = 675,
	AARCH64_REG_Z16_Z17_Z18 = 676,
	AARCH64_REG_Z17_Z18_Z19 = 677,
	AARCH64_REG_Z18_Z19_Z20 = 678,
	AARCH64_REG_Z19_Z20_Z21 = 679,
	AARCH64_REG_Z20_Z21_Z22 = 680,
	AARCH64_REG_Z21_Z22_Z23 = 681,
	AARCH64_REG_Z22_Z23_Z24 = 682,
	AARCH64_REG_Z23_Z24_Z25 = 683,
	AARCH64_REG_Z24_Z25_Z26 = 684,
	AARCH64_REG_Z25_Z26_Z27 = 685,
	AARCH64_REG_Z26_Z27_Z28 = 686,
	AARCH64_REG_Z27_Z28_Z29 = 687,
	AARCH64_REG_Z28_Z29_Z30 = 688,
	AARCH64_REG_Z29_Z30_Z31 = 689,
	AARCH64_REG_Z30_Z31_Z0 = 690,
	AARCH64_REG_Z31_Z0_Z1 = 691,
	AARCH64_REG_Z16_Z24 = 692,
	AARCH64_REG_Z17_Z25 = 693,
	AARCH64_REG_Z18_Z26 = 694,
	AARCH64_REG_Z19_Z27 = 695,
	AARCH64_REG_Z20_Z28 = 696,
	AARCH64_REG_Z21_Z29 = 697,
	AARCH64_REG_Z22_Z30 = 698,
	AARCH64_REG_Z23_Z31 = 699,
	AARCH64_REG_Z0_Z8 = 700,
	AARCH64_REG_Z1_Z9 = 701,
	AARCH64_REG_Z2_Z10 = 702,
	AARCH64_REG_Z3_Z11 = 703,
	AARCH64_REG_Z4_Z12 = 704,
	AARCH64_REG_Z5_Z13 = 705,
	AARCH64_REG_Z6_Z14 = 706,
	AARCH64_REG_Z7_Z15 = 707,
	AARCH64_REG_Z16_Z20_Z24_Z28 = 708,
	AARCH64_REG_Z17_Z21_Z25_Z29 = 709,
	AARCH64_REG_Z18_Z22_Z26_Z30 = 710,
	AARCH64_REG_Z19_Z23_Z27_Z31 = 711,
	AARCH64_REG_Z0_Z4_Z8_Z12 = 712,
	AARCH64_REG_Z1_Z5_Z9_Z13 = 713,
	AARCH64_REG_Z2_Z6_Z10_Z14 = 714,
	AARCH64_REG_Z3_Z7_Z11_Z15 = 715,
	AARCH64_REG_ENDING, // 716

	// clang-format on
	// generated content <AArch64GenCSRegEnum.inc> end

  // alias registers
  ARM64_REG_IP0 = AARCH64_REG_X16,
  ARM64_REG_IP1 = AARCH64_REG_X17,
  ARM64_REG_X29 = AARCH64_REG_FP,
  ARM64_REG_X30 = AARCH64_REG_LR,
} arm64_reg;

/// Instruction's operand referring to memory
/// This is associated with ARM64_OP_MEM operand type above
typedef struct arm64_op_mem {
  arm64_reg base;  ///< base register
  arm64_reg index; ///< index register
  int32_t disp;	   ///< displacement/offset value
} arm64_op_mem;

/// SME Instruction's operand has index
/// This is associated with ARM64_OP_SME_INDEX operand type above
typedef struct arm64_op_sme_index {
  arm64_reg reg;  ///< register being indexed
  arm64_reg base; ///< base register
  int32_t disp;	  ///< displacement/offset value
} arm64_op_sme_index;

/// Instruction operand
typedef struct cs_arm64_op {
  int vector_index; ///< Vector Index for some vector operands (or -1 if
		    ///< irrelevant)
  arm64_vas vas;    ///< Vector Arrangement Specifier
  struct {
    arm64_shifter type; ///< shifter type of this operand
    unsigned int value; ///< shifter value of this operand
  } shift;
  arm64_extender ext; ///< extender type of this operand
  arm64_op_type type; ///< operand type
  arm64_svcr_op svcr; ///< MSR/MRS SVCR instruction variant.
  union {
    arm64_reg reg;	 ///< register value for REG operand
    int64_t imm;	 ///< immediate value, or index for C-IMM or IMM operand
    double fp;		 ///< floating point value for FP operand
    arm64_op_mem mem;	 ///< base/index/scale/disp value for MEM operand
    arm64_pstate pstate; ///< PState field of MSR instruction.
    arm64_sys_op sys;	 ///< IC/DC/AT/TLBI operation (see arm64_ic_op,
		      ///< arm64_dc_op, arm64_at_op, arm64_tlbi_op)
    arm64_prefetch_op prefetch; ///< PRFM operation.
    arm64_barrier_op
	barrier; ///< Memory barrier operation (ISB/DMB/DSB instructions).
    arm64_op_sme_index sme_index; ///< base/disp value for matrix tile slice
				  ///< instructions.
  };

  /// How is this operand accessed? (READ, WRITE or READ|WRITE)
  /// This field is combined of cs_ac_type.
  /// NOTE: this field is irrelevant if engine is compiled in DIET mode.
  uint8_t access;
} cs_arm64_op;

/// Instruction structure
typedef struct cs_arm64 {
  arm64_cc cc;	     ///< conditional code for this insn
  bool update_flags; ///< does this insn update flags?
  bool writeback;    ///< does this insn request writeback? 'True' means 'yes'
  bool post_index;   ///< only set if writeback is 'True', if 'False' pre-index, otherwise post.

  /// Number of operands of this instruction,
  /// or 0 when instruction has no operand.
  uint8_t op_count;

  cs_arm64_op operands[8]; ///< operands for this instruction.
} cs_arm64;

/// ARM64 instruction
typedef enum arm64_insn {
	// generated content <AArch64GenCSInsnEnum.inc> begin
	// clang-format off

	AARCH64_INS_INVALID,
	AARCH64_INS_ABS,
	AARCH64_INS_ADCLB,
	AARCH64_INS_ADCLT,
	AARCH64_INS_ADCS,
	AARCH64_INS_ADC,
	AARCH64_INS_ADDG,
	AARCH64_INS_ADDHA,
	AARCH64_INS_ADDHNB,
	AARCH64_INS_ADDHNT,
	AARCH64_INS_ADDHN,
	AARCH64_INS_ADDHN2,
	AARCH64_INS_ADDPL,
	AARCH64_INS_ADDP,
	AARCH64_INS_ADDQV,
	AARCH64_INS_ADDSPL,
	AARCH64_INS_ADDSVL,
	AARCH64_INS_ADDS,
	AARCH64_INS_ADDVA,
	AARCH64_INS_ADDVL,
	AARCH64_INS_ADDV,
	AARCH64_INS_ADD,
	AARCH64_INS_ADR,
	AARCH64_INS_ADRP,
	AARCH64_INS_AESD,
	AARCH64_INS_AESE,
	AARCH64_INS_AESIMC,
	AARCH64_INS_AESMC,
	AARCH64_INS_ANDQV,
	AARCH64_INS_ANDS,
	AARCH64_INS_ANDV,
	AARCH64_INS_AND,
	AARCH64_INS_ASRD,
	AARCH64_INS_ASRR,
	AARCH64_INS_ASR,
	AARCH64_INS_AUTDA,
	AARCH64_INS_AUTDB,
	AARCH64_INS_AUTDZA,
	AARCH64_INS_AUTDZB,
	AARCH64_INS_AUTIA,
	AARCH64_INS_HINT,
	AARCH64_INS_AUTIB,
	AARCH64_INS_AUTIZA,
	AARCH64_INS_AUTIZB,
	AARCH64_INS_AXFLAG,
	AARCH64_INS_B,
	AARCH64_INS_BCAX,
	AARCH64_INS_BC,
	AARCH64_INS_BDEP,
	AARCH64_INS_BEXT,
	AARCH64_INS_BFDOT,
	AARCH64_INS_BFADD,
	AARCH64_INS_BFCLAMP,
	AARCH64_INS_BFCVT,
	AARCH64_INS_BFCVTN,
	AARCH64_INS_BFCVTN2,
	AARCH64_INS_BFCVTNT,
	AARCH64_INS_BFMAXNM,
	AARCH64_INS_BFMAX,
	AARCH64_INS_BFMINNM,
	AARCH64_INS_BFMIN,
	AARCH64_INS_BFMLALB,
	AARCH64_INS_BFMLALT,
	AARCH64_INS_BFMLAL,
	AARCH64_INS_BFMLA,
	AARCH64_INS_BFMLSLB,
	AARCH64_INS_BFMLSLT,
	AARCH64_INS_BFMLSL,
	AARCH64_INS_BFMLS,
	AARCH64_INS_BFMMLA,
	AARCH64_INS_BFMOPA,
	AARCH64_INS_BFMOPS,
	AARCH64_INS_BFMUL,
	AARCH64_INS_BFM,
	AARCH64_INS_BFSUB,
	AARCH64_INS_BFVDOT,
	AARCH64_INS_BGRP,
	AARCH64_INS_BICS,
	AARCH64_INS_BIC,
	AARCH64_INS_BIF,
	AARCH64_INS_BIT,
	AARCH64_INS_BL,
	AARCH64_INS_BLR,
	AARCH64_INS_BLRAA,
	AARCH64_INS_BLRAAZ,
	AARCH64_INS_BLRAB,
	AARCH64_INS_BLRABZ,
	AARCH64_INS_BMOPA,
	AARCH64_INS_BMOPS,
	AARCH64_INS_BR,
	AARCH64_INS_BRAA,
	AARCH64_INS_BRAAZ,
	AARCH64_INS_BRAB,
	AARCH64_INS_BRABZ,
	AARCH64_INS_BRB,
	AARCH64_INS_BRK,
	AARCH64_INS_BRKAS,
	AARCH64_INS_BRKA,
	AARCH64_INS_BRKBS,
	AARCH64_INS_BRKB,
	AARCH64_INS_BRKNS,
	AARCH64_INS_BRKN,
	AARCH64_INS_BRKPAS,
	AARCH64_INS_BRKPA,
	AARCH64_INS_BRKPBS,
	AARCH64_INS_BRKPB,
	AARCH64_INS_BSL1N,
	AARCH64_INS_BSL2N,
	AARCH64_INS_BSL,
	AARCH64_INS_CADD,
	AARCH64_INS_CASAB,
	AARCH64_INS_CASAH,
	AARCH64_INS_CASALB,
	AARCH64_INS_CASALH,
	AARCH64_INS_CASAL,
	AARCH64_INS_CASA,
	AARCH64_INS_CASB,
	AARCH64_INS_CASH,
	AARCH64_INS_CASLB,
	AARCH64_INS_CASLH,
	AARCH64_INS_CASL,
	AARCH64_INS_CASPAL,
	AARCH64_INS_CASPA,
	AARCH64_INS_CASPL,
	AARCH64_INS_CASP,
	AARCH64_INS_CAS,
	AARCH64_INS_CBNZ,
	AARCH64_INS_CBZ,
	AARCH64_INS_CCMN,
	AARCH64_INS_CCMP,
	AARCH64_INS_CDOT,
	AARCH64_INS_CFINV,
	AARCH64_INS_CLASTA,
	AARCH64_INS_CLASTB,
	AARCH64_INS_CLREX,
	AARCH64_INS_CLS,
	AARCH64_INS_CLZ,
	AARCH64_INS_CMEQ,
	AARCH64_INS_CMGE,
	AARCH64_INS_CMGT,
	AARCH64_INS_CMHI,
	AARCH64_INS_CMHS,
	AARCH64_INS_CMLA,
	AARCH64_INS_CMLE,
	AARCH64_INS_CMLT,
	AARCH64_INS_CMPEQ,
	AARCH64_INS_CMPGE,
	AARCH64_INS_CMPGT,
	AARCH64_INS_CMPHI,
	AARCH64_INS_CMPHS,
	AARCH64_INS_CMPLE,
	AARCH64_INS_CMPLO,
	AARCH64_INS_CMPLS,
	AARCH64_INS_CMPLT,
	AARCH64_INS_CMPNE,
	AARCH64_INS_CMTST,
	AARCH64_INS_CNOT,
	AARCH64_INS_CNTB,
	AARCH64_INS_CNTD,
	AARCH64_INS_CNTH,
	AARCH64_INS_CNTP,
	AARCH64_INS_CNTW,
	AARCH64_INS_CNT,
	AARCH64_INS_COMPACT,
	AARCH64_INS_CPYE,
	AARCH64_INS_CPYEN,
	AARCH64_INS_CPYERN,
	AARCH64_INS_CPYERT,
	AARCH64_INS_CPYERTN,
	AARCH64_INS_CPYERTRN,
	AARCH64_INS_CPYERTWN,
	AARCH64_INS_CPYET,
	AARCH64_INS_CPYETN,
	AARCH64_INS_CPYETRN,
	AARCH64_INS_CPYETWN,
	AARCH64_INS_CPYEWN,
	AARCH64_INS_CPYEWT,
	AARCH64_INS_CPYEWTN,
	AARCH64_INS_CPYEWTRN,
	AARCH64_INS_CPYEWTWN,
	AARCH64_INS_CPYFE,
	AARCH64_INS_CPYFEN,
	AARCH64_INS_CPYFERN,
	AARCH64_INS_CPYFERT,
	AARCH64_INS_CPYFERTN,
	AARCH64_INS_CPYFERTRN,
	AARCH64_INS_CPYFERTWN,
	AARCH64_INS_CPYFET,
	AARCH64_INS_CPYFETN,
	AARCH64_INS_CPYFETRN,
	AARCH64_INS_CPYFETWN,
	AARCH64_INS_CPYFEWN,
	AARCH64_INS_CPYFEWT,
	AARCH64_INS_CPYFEWTN,
	AARCH64_INS_CPYFEWTRN,
	AARCH64_INS_CPYFEWTWN,
	AARCH64_INS_CPYFM,
	AARCH64_INS_CPYFMN,
	AARCH64_INS_CPYFMRN,
	AARCH64_INS_CPYFMRT,
	AARCH64_INS_CPYFMRTN,
	AARCH64_INS_CPYFMRTRN,
	AARCH64_INS_CPYFMRTWN,
	AARCH64_INS_CPYFMT,
	AARCH64_INS_CPYFMTN,
	AARCH64_INS_CPYFMTRN,
	AARCH64_INS_CPYFMTWN,
	AARCH64_INS_CPYFMWN,
	AARCH64_INS_CPYFMWT,
	AARCH64_INS_CPYFMWTN,
	AARCH64_INS_CPYFMWTRN,
	AARCH64_INS_CPYFMWTWN,
	AARCH64_INS_CPYFP,
	AARCH64_INS_CPYFPN,
	AARCH64_INS_CPYFPRN,
	AARCH64_INS_CPYFPRT,
	AARCH64_INS_CPYFPRTN,
	AARCH64_INS_CPYFPRTRN,
	AARCH64_INS_CPYFPRTWN,
	AARCH64_INS_CPYFPT,
	AARCH64_INS_CPYFPTN,
	AARCH64_INS_CPYFPTRN,
	AARCH64_INS_CPYFPTWN,
	AARCH64_INS_CPYFPWN,
	AARCH64_INS_CPYFPWT,
	AARCH64_INS_CPYFPWTN,
	AARCH64_INS_CPYFPWTRN,
	AARCH64_INS_CPYFPWTWN,
	AARCH64_INS_CPYM,
	AARCH64_INS_CPYMN,
	AARCH64_INS_CPYMRN,
	AARCH64_INS_CPYMRT,
	AARCH64_INS_CPYMRTN,
	AARCH64_INS_CPYMRTRN,
	AARCH64_INS_CPYMRTWN,
	AARCH64_INS_CPYMT,
	AARCH64_INS_CPYMTN,
	AARCH64_INS_CPYMTRN,
	AARCH64_INS_CPYMTWN,
	AARCH64_INS_CPYMWN,
	AARCH64_INS_CPYMWT,
	AARCH64_INS_CPYMWTN,
	AARCH64_INS_CPYMWTRN,
	AARCH64_INS_CPYMWTWN,
	AARCH64_INS_CPYP,
	AARCH64_INS_CPYPN,
	AARCH64_INS_CPYPRN,
	AARCH64_INS_CPYPRT,
	AARCH64_INS_CPYPRTN,
	AARCH64_INS_CPYPRTRN,
	AARCH64_INS_CPYPRTWN,
	AARCH64_INS_CPYPT,
	AARCH64_INS_CPYPTN,
	AARCH64_INS_CPYPTRN,
	AARCH64_INS_CPYPTWN,
	AARCH64_INS_CPYPWN,
	AARCH64_INS_CPYPWT,
	AARCH64_INS_CPYPWTN,
	AARCH64_INS_CPYPWTRN,
	AARCH64_INS_CPYPWTWN,
	AARCH64_INS_CPY,
	AARCH64_INS_CRC32B,
	AARCH64_INS_CRC32CB,
	AARCH64_INS_CRC32CH,
	AARCH64_INS_CRC32CW,
	AARCH64_INS_CRC32CX,
	AARCH64_INS_CRC32H,
	AARCH64_INS_CRC32W,
	AARCH64_INS_CRC32X,
	AARCH64_INS_CSEL,
	AARCH64_INS_CSINC,
	AARCH64_INS_CSINV,
	AARCH64_INS_CSNEG,
	AARCH64_INS_CTERMEQ,
	AARCH64_INS_CTERMNE,
	AARCH64_INS_CTZ,
	AARCH64_INS_DCPS1,
	AARCH64_INS_DCPS2,
	AARCH64_INS_DCPS3,
	AARCH64_INS_DECB,
	AARCH64_INS_DECD,
	AARCH64_INS_DECH,
	AARCH64_INS_DECP,
	AARCH64_INS_DECW,
	AARCH64_INS_DMB,
	AARCH64_INS_DRPS,
	AARCH64_INS_DSB,
	AARCH64_INS_DUPM,
	AARCH64_INS_DUPQ,
	AARCH64_INS_DUP,
	AARCH64_INS_MOV,
	AARCH64_INS_EON,
	AARCH64_INS_EOR3,
	AARCH64_INS_EORBT,
	AARCH64_INS_EORQV,
	AARCH64_INS_EORS,
	AARCH64_INS_EORTB,
	AARCH64_INS_EORV,
	AARCH64_INS_EOR,
	AARCH64_INS_ERET,
	AARCH64_INS_ERETAA,
	AARCH64_INS_ERETAB,
	AARCH64_INS_EXTQ,
	AARCH64_INS_MOVA,
	AARCH64_INS_EXTR,
	AARCH64_INS_EXT,
	AARCH64_INS_FABD,
	AARCH64_INS_FABS,
	AARCH64_INS_FACGE,
	AARCH64_INS_FACGT,
	AARCH64_INS_FADDA,
	AARCH64_INS_FADD,
	AARCH64_INS_FADDP,
	AARCH64_INS_FADDQV,
	AARCH64_INS_FADDV,
	AARCH64_INS_FCADD,
	AARCH64_INS_FCCMP,
	AARCH64_INS_FCCMPE,
	AARCH64_INS_FCLAMP,
	AARCH64_INS_FCMEQ,
	AARCH64_INS_FCMGE,
	AARCH64_INS_FCMGT,
	AARCH64_INS_FCMLA,
	AARCH64_INS_FCMLE,
	AARCH64_INS_FCMLT,
	AARCH64_INS_FCMNE,
	AARCH64_INS_FCMP,
	AARCH64_INS_FCMPE,
	AARCH64_INS_FCMUO,
	AARCH64_INS_FCPY,
	AARCH64_INS_FCSEL,
	AARCH64_INS_FCVTAS,
	AARCH64_INS_FCVTAU,
	AARCH64_INS_FCVT,
	AARCH64_INS_FCVTLT,
	AARCH64_INS_FCVTL,
	AARCH64_INS_FCVTL2,
	AARCH64_INS_FCVTMS,
	AARCH64_INS_FCVTMU,
	AARCH64_INS_FCVTNS,
	AARCH64_INS_FCVTNT,
	AARCH64_INS_FCVTNU,
	AARCH64_INS_FCVTN,
	AARCH64_INS_FCVTN2,
	AARCH64_INS_FCVTPS,
	AARCH64_INS_FCVTPU,
	AARCH64_INS_FCVTXNT,
	AARCH64_INS_FCVTXN,
	AARCH64_INS_FCVTXN2,
	AARCH64_INS_FCVTX,
	AARCH64_INS_FCVTZS,
	AARCH64_INS_FCVTZU,
	AARCH64_INS_FDIV,
	AARCH64_INS_FDIVR,
	AARCH64_INS_FDOT,
	AARCH64_INS_FDUP,
	AARCH64_INS_FEXPA,
	AARCH64_INS_FJCVTZS,
	AARCH64_INS_FLOGB,
	AARCH64_INS_FMADD,
	AARCH64_INS_FMAD,
	AARCH64_INS_FMAX,
	AARCH64_INS_FMAXNM,
	AARCH64_INS_FMAXNMP,
	AARCH64_INS_FMAXNMQV,
	AARCH64_INS_FMAXNMV,
	AARCH64_INS_FMAXP,
	AARCH64_INS_FMAXQV,
	AARCH64_INS_FMAXV,
	AARCH64_INS_FMIN,
	AARCH64_INS_FMINNM,
	AARCH64_INS_FMINNMP,
	AARCH64_INS_FMINNMQV,
	AARCH64_INS_FMINNMV,
	AARCH64_INS_FMINP,
	AARCH64_INS_FMINQV,
	AARCH64_INS_FMINV,
	AARCH64_INS_FMLAL2,
	AARCH64_INS_FMLALB,
	AARCH64_INS_FMLALT,
	AARCH64_INS_FMLAL,
	AARCH64_INS_FMLA,
	AARCH64_INS_FMLSL2,
	AARCH64_INS_FMLSLB,
	AARCH64_INS_FMLSLT,
	AARCH64_INS_FMLSL,
	AARCH64_INS_FMLS,
	AARCH64_INS_FMMLA,
	AARCH64_INS_FMOPA,
	AARCH64_INS_FMOPS,
	AARCH64_INS_FMOV,
	AARCH64_INS_FMSB,
	AARCH64_INS_FMSUB,
	AARCH64_INS_FMUL,
	AARCH64_INS_FMULX,
	AARCH64_INS_FNEG,
	AARCH64_INS_FNMADD,
	AARCH64_INS_FNMAD,
	AARCH64_INS_FNMLA,
	AARCH64_INS_FNMLS,
	AARCH64_INS_FNMSB,
	AARCH64_INS_FNMSUB,
	AARCH64_INS_FNMUL,
	AARCH64_INS_FRECPE,
	AARCH64_INS_FRECPS,
	AARCH64_INS_FRECPX,
	AARCH64_INS_FRINT32X,
	AARCH64_INS_FRINT32Z,
	AARCH64_INS_FRINT64X,
	AARCH64_INS_FRINT64Z,
	AARCH64_INS_FRINTA,
	AARCH64_INS_FRINTI,
	AARCH64_INS_FRINTM,
	AARCH64_INS_FRINTN,
	AARCH64_INS_FRINTP,
	AARCH64_INS_FRINTX,
	AARCH64_INS_FRINTZ,
	AARCH64_INS_FRSQRTE,
	AARCH64_INS_FRSQRTS,
	AARCH64_INS_FSCALE,
	AARCH64_INS_FSQRT,
	AARCH64_INS_FSUB,
	AARCH64_INS_FSUBR,
	AARCH64_INS_FTMAD,
	AARCH64_INS_FTSMUL,
	AARCH64_INS_FTSSEL,
	AARCH64_INS_FVDOT,
	AARCH64_INS_LD1B,
	AARCH64_INS_LD1D,
	AARCH64_INS_LD1H,
	AARCH64_INS_LD1Q,
	AARCH64_INS_LD1SB,
	AARCH64_INS_LD1SH,
	AARCH64_INS_LD1SW,
	AARCH64_INS_LD1W,
	AARCH64_INS_LDFF1B,
	AARCH64_INS_LDFF1D,
	AARCH64_INS_LDFF1H,
	AARCH64_INS_LDFF1SB,
	AARCH64_INS_LDFF1SH,
	AARCH64_INS_LDFF1SW,
	AARCH64_INS_LDFF1W,
	AARCH64_INS_GMI,
	AARCH64_INS_HISTCNT,
	AARCH64_INS_HISTSEG,
	AARCH64_INS_HLT,
	AARCH64_INS_HVC,
	AARCH64_INS_INCB,
	AARCH64_INS_INCD,
	AARCH64_INS_INCH,
	AARCH64_INS_INCP,
	AARCH64_INS_INCW,
	AARCH64_INS_INDEX,
	AARCH64_INS_INSR,
	AARCH64_INS_INS,
	AARCH64_INS_IRG,
	AARCH64_INS_ISB,
	AARCH64_INS_LASTA,
	AARCH64_INS_LASTB,
	AARCH64_INS_LD1,
	AARCH64_INS_LD1RB,
	AARCH64_INS_LD1RD,
	AARCH64_INS_LD1RH,
	AARCH64_INS_LD1ROB,
	AARCH64_INS_LD1ROD,
	AARCH64_INS_LD1ROH,
	AARCH64_INS_LD1ROW,
	AARCH64_INS_LD1RQB,
	AARCH64_INS_LD1RQD,
	AARCH64_INS_LD1RQH,
	AARCH64_INS_LD1RQW,
	AARCH64_INS_LD1RSB,
	AARCH64_INS_LD1RSH,
	AARCH64_INS_LD1RSW,
	AARCH64_INS_LD1RW,
	AARCH64_INS_LD1R,
	AARCH64_INS_LD2B,
	AARCH64_INS_LD2D,
	AARCH64_INS_LD2H,
	AARCH64_INS_LD2Q,
	AARCH64_INS_LD2R,
	AARCH64_INS_LD2,
	AARCH64_INS_LD2W,
	AARCH64_INS_LD3B,
	AARCH64_INS_LD3D,
	AARCH64_INS_LD3H,
	AARCH64_INS_LD3Q,
	AARCH64_INS_LD3R,
	AARCH64_INS_LD3,
	AARCH64_INS_LD3W,
	AARCH64_INS_LD4B,
	AARCH64_INS_LD4D,
	AARCH64_INS_LD4,
	AARCH64_INS_LD4H,
	AARCH64_INS_LD4Q,
	AARCH64_INS_LD4R,
	AARCH64_INS_LD4W,
	AARCH64_INS_LD64B,
	AARCH64_INS_LDADDAB,
	AARCH64_INS_LDADDAH,
	AARCH64_INS_LDADDALB,
	AARCH64_INS_LDADDALH,
	AARCH64_INS_LDADDAL,
	AARCH64_INS_LDADDA,
	AARCH64_INS_LDADDB,
	AARCH64_INS_LDADDH,
	AARCH64_INS_LDADDLB,
	AARCH64_INS_LDADDLH,
	AARCH64_INS_LDADDL,
	AARCH64_INS_LDADD,
	AARCH64_INS_LDAP1,
	AARCH64_INS_LDAPRB,
	AARCH64_INS_LDAPRH,
	AARCH64_INS_LDAPR,
	AARCH64_INS_LDAPURB,
	AARCH64_INS_LDAPURH,
	AARCH64_INS_LDAPURSB,
	AARCH64_INS_LDAPURSH,
	AARCH64_INS_LDAPURSW,
	AARCH64_INS_LDAPUR,
	AARCH64_INS_LDARB,
	AARCH64_INS_LDARH,
	AARCH64_INS_LDAR,
	AARCH64_INS_LDAXP,
	AARCH64_INS_LDAXRB,
	AARCH64_INS_LDAXRH,
	AARCH64_INS_LDAXR,
	AARCH64_INS_LDCLRAB,
	AARCH64_INS_LDCLRAH,
	AARCH64_INS_LDCLRALB,
	AARCH64_INS_LDCLRALH,
	AARCH64_INS_LDCLRAL,
	AARCH64_INS_LDCLRA,
	AARCH64_INS_LDCLRB,
	AARCH64_INS_LDCLRH,
	AARCH64_INS_LDCLRLB,
	AARCH64_INS_LDCLRLH,
	AARCH64_INS_LDCLRL,
	AARCH64_INS_LDCLRP,
	AARCH64_INS_LDCLRPA,
	AARCH64_INS_LDCLRPAL,
	AARCH64_INS_LDCLRPL,
	AARCH64_INS_LDCLR,
	AARCH64_INS_LDEORAB,
	AARCH64_INS_LDEORAH,
	AARCH64_INS_LDEORALB,
	AARCH64_INS_LDEORALH,
	AARCH64_INS_LDEORAL,
	AARCH64_INS_LDEORA,
	AARCH64_INS_LDEORB,
	AARCH64_INS_LDEORH,
	AARCH64_INS_LDEORLB,
	AARCH64_INS_LDEORLH,
	AARCH64_INS_LDEORL,
	AARCH64_INS_LDEOR,
	AARCH64_INS_LDG,
	AARCH64_INS_LDGM,
	AARCH64_INS_LDIAPP,
	AARCH64_INS_LDLARB,
	AARCH64_INS_LDLARH,
	AARCH64_INS_LDLAR,
	AARCH64_INS_LDNF1B,
	AARCH64_INS_LDNF1D,
	AARCH64_INS_LDNF1H,
	AARCH64_INS_LDNF1SB,
	AARCH64_INS_LDNF1SH,
	AARCH64_INS_LDNF1SW,
	AARCH64_INS_LDNF1W,
	AARCH64_INS_LDNP,
	AARCH64_INS_LDNT1B,
	AARCH64_INS_LDNT1D,
	AARCH64_INS_LDNT1H,
	AARCH64_INS_LDNT1SB,
	AARCH64_INS_LDNT1SH,
	AARCH64_INS_LDNT1SW,
	AARCH64_INS_LDNT1W,
	AARCH64_INS_LDP,
	AARCH64_INS_LDPSW,
	AARCH64_INS_LDRAA,
	AARCH64_INS_LDRAB,
	AARCH64_INS_LDRB,
	AARCH64_INS_LDR,
	AARCH64_INS_LDRH,
	AARCH64_INS_LDRSB,
	AARCH64_INS_LDRSH,
	AARCH64_INS_LDRSW,
	AARCH64_INS_LDSETAB,
	AARCH64_INS_LDSETAH,
	AARCH64_INS_LDSETALB,
	AARCH64_INS_LDSETALH,
	AARCH64_INS_LDSETAL,
	AARCH64_INS_LDSETA,
	AARCH64_INS_LDSETB,
	AARCH64_INS_LDSETH,
	AARCH64_INS_LDSETLB,
	AARCH64_INS_LDSETLH,
	AARCH64_INS_LDSETL,
	AARCH64_INS_LDSETP,
	AARCH64_INS_LDSETPA,
	AARCH64_INS_LDSETPAL,
	AARCH64_INS_LDSETPL,
	AARCH64_INS_LDSET,
	AARCH64_INS_LDSMAXAB,
	AARCH64_INS_LDSMAXAH,
	AARCH64_INS_LDSMAXALB,
	AARCH64_INS_LDSMAXALH,
	AARCH64_INS_LDSMAXAL,
	AARCH64_INS_LDSMAXA,
	AARCH64_INS_LDSMAXB,
	AARCH64_INS_LDSMAXH,
	AARCH64_INS_LDSMAXLB,
	AARCH64_INS_LDSMAXLH,
	AARCH64_INS_LDSMAXL,
	AARCH64_INS_LDSMAX,
	AARCH64_INS_LDSMINAB,
	AARCH64_INS_LDSMINAH,
	AARCH64_INS_LDSMINALB,
	AARCH64_INS_LDSMINALH,
	AARCH64_INS_LDSMINAL,
	AARCH64_INS_LDSMINA,
	AARCH64_INS_LDSMINB,
	AARCH64_INS_LDSMINH,
	AARCH64_INS_LDSMINLB,
	AARCH64_INS_LDSMINLH,
	AARCH64_INS_LDSMINL,
	AARCH64_INS_LDSMIN,
	AARCH64_INS_LDTRB,
	AARCH64_INS_LDTRH,
	AARCH64_INS_LDTRSB,
	AARCH64_INS_LDTRSH,
	AARCH64_INS_LDTRSW,
	AARCH64_INS_LDTR,
	AARCH64_INS_LDUMAXAB,
	AARCH64_INS_LDUMAXAH,
	AARCH64_INS_LDUMAXALB,
	AARCH64_INS_LDUMAXALH,
	AARCH64_INS_LDUMAXAL,
	AARCH64_INS_LDUMAXA,
	AARCH64_INS_LDUMAXB,
	AARCH64_INS_LDUMAXH,
	AARCH64_INS_LDUMAXLB,
	AARCH64_INS_LDUMAXLH,
	AARCH64_INS_LDUMAXL,
	AARCH64_INS_LDUMAX,
	AARCH64_INS_LDUMINAB,
	AARCH64_INS_LDUMINAH,
	AARCH64_INS_LDUMINALB,
	AARCH64_INS_LDUMINALH,
	AARCH64_INS_LDUMINAL,
	AARCH64_INS_LDUMINA,
	AARCH64_INS_LDUMINB,
	AARCH64_INS_LDUMINH,
	AARCH64_INS_LDUMINLB,
	AARCH64_INS_LDUMINLH,
	AARCH64_INS_LDUMINL,
	AARCH64_INS_LDUMIN,
	AARCH64_INS_LDURB,
	AARCH64_INS_LDUR,
	AARCH64_INS_LDURH,
	AARCH64_INS_LDURSB,
	AARCH64_INS_LDURSH,
	AARCH64_INS_LDURSW,
	AARCH64_INS_LDXP,
	AARCH64_INS_LDXRB,
	AARCH64_INS_LDXRH,
	AARCH64_INS_LDXR,
	AARCH64_INS_LSLR,
	AARCH64_INS_LSL,
	AARCH64_INS_LSRR,
	AARCH64_INS_LSR,
	AARCH64_INS_LUTI2,
	AARCH64_INS_LUTI4,
	AARCH64_INS_MADD,
	AARCH64_INS_MAD,
	AARCH64_INS_MATCH,
	AARCH64_INS_MLA,
	AARCH64_INS_MLS,
	AARCH64_INS_SETGE,
	AARCH64_INS_SETGEN,
	AARCH64_INS_SETGET,
	AARCH64_INS_SETGETN,
	AARCH64_INS_MOVAZ,
	AARCH64_INS_MOVI,
	AARCH64_INS_MOVK,
	AARCH64_INS_MOVN,
	AARCH64_INS_MOVPRFX,
	AARCH64_INS_MOVT,
	AARCH64_INS_MOVZ,
	AARCH64_INS_MRRS,
	AARCH64_INS_MRS,
	AARCH64_INS_MSB,
	AARCH64_INS_MSR,
	AARCH64_INS_MSRR,
	AARCH64_INS_MSUB,
	AARCH64_INS_MUL,
	AARCH64_INS_MVNI,
	AARCH64_INS_NANDS,
	AARCH64_INS_NAND,
	AARCH64_INS_NBSL,
	AARCH64_INS_NEG,
	AARCH64_INS_NMATCH,
	AARCH64_INS_NORS,
	AARCH64_INS_NOR,
	AARCH64_INS_NOT,
	AARCH64_INS_ORNS,
	AARCH64_INS_ORN,
	AARCH64_INS_ORQV,
	AARCH64_INS_ORRS,
	AARCH64_INS_ORR,
	AARCH64_INS_ORV,
	AARCH64_INS_PACDA,
	AARCH64_INS_PACDB,
	AARCH64_INS_PACDZA,
	AARCH64_INS_PACDZB,
	AARCH64_INS_PACGA,
	AARCH64_INS_PACIA,
	AARCH64_INS_PACIB,
	AARCH64_INS_PACIZA,
	AARCH64_INS_PACIZB,
	AARCH64_INS_PEXT,
	AARCH64_INS_PFALSE,
	AARCH64_INS_PFIRST,
	AARCH64_INS_PMOV,
	AARCH64_INS_PMULLB,
	AARCH64_INS_PMULLT,
	AARCH64_INS_PMULL2,
	AARCH64_INS_PMULL,
	AARCH64_INS_PMUL,
	AARCH64_INS_PNEXT,
	AARCH64_INS_PRFB,
	AARCH64_INS_PRFD,
	AARCH64_INS_PRFH,
	AARCH64_INS_PRFM,
	AARCH64_INS_PRFUM,
	AARCH64_INS_PRFW,
	AARCH64_INS_PSEL,
	AARCH64_INS_PTEST,
	AARCH64_INS_PTRUES,
	AARCH64_INS_PTRUE,
	AARCH64_INS_PUNPKHI,
	AARCH64_INS_PUNPKLO,
	AARCH64_INS_RADDHNB,
	AARCH64_INS_RADDHNT,
	AARCH64_INS_RADDHN,
	AARCH64_INS_RADDHN2,
	AARCH64_INS_RAX1,
	AARCH64_INS_RBIT,
	AARCH64_INS_RCWCAS,
	AARCH64_INS_RCWCASA,
	AARCH64_INS_RCWCASAL,
	AARCH64_INS_RCWCASL,
	AARCH64_INS_RCWCASP,
	AARCH64_INS_RCWCASPA,
	AARCH64_INS_RCWCASPAL,
	AARCH64_INS_RCWCASPL,
	AARCH64_INS_RCWCLR,
	AARCH64_INS_RCWCLRA,
	AARCH64_INS_RCWCLRAL,
	AARCH64_INS_RCWCLRL,
	AARCH64_INS_RCWCLRP,
	AARCH64_INS_RCWCLRPA,
	AARCH64_INS_RCWCLRPAL,
	AARCH64_INS_RCWCLRPL,
	AARCH64_INS_RCWSCLR,
	AARCH64_INS_RCWSCLRA,
	AARCH64_INS_RCWSCLRAL,
	AARCH64_INS_RCWSCLRL,
	AARCH64_INS_RCWSCLRP,
	AARCH64_INS_RCWSCLRPA,
	AARCH64_INS_RCWSCLRPAL,
	AARCH64_INS_RCWSCLRPL,
	AARCH64_INS_RCWSCAS,
	AARCH64_INS_RCWSCASA,
	AARCH64_INS_RCWSCASAL,
	AARCH64_INS_RCWSCASL,
	AARCH64_INS_RCWSCASP,
	AARCH64_INS_RCWSCASPA,
	AARCH64_INS_RCWSCASPAL,
	AARCH64_INS_RCWSCASPL,
	AARCH64_INS_RCWSET,
	AARCH64_INS_RCWSETA,
	AARCH64_INS_RCWSETAL,
	AARCH64_INS_RCWSETL,
	AARCH64_INS_RCWSETP,
	AARCH64_INS_RCWSETPA,
	AARCH64_INS_RCWSETPAL,
	AARCH64_INS_RCWSETPL,
	AARCH64_INS_RCWSSET,
	AARCH64_INS_RCWSSETA,
	AARCH64_INS_RCWSSETAL,
	AARCH64_INS_RCWSSETL,
	AARCH64_INS_RCWSSETP,
	AARCH64_INS_RCWSSETPA,
	AARCH64_INS_RCWSSETPAL,
	AARCH64_INS_RCWSSETPL,
	AARCH64_INS_RCWSWP,
	AARCH64_INS_RCWSWPA,
	AARCH64_INS_RCWSWPAL,
	AARCH64_INS_RCWSWPL,
	AARCH64_INS_RCWSWPP,
	AARCH64_INS_RCWSWPPA,
	AARCH64_INS_RCWSWPPAL,
	AARCH64_INS_RCWSWPPL,
	AARCH64_INS_RCWSSWP,
	AARCH64_INS_RCWSSWPA,
	AARCH64_INS_RCWSSWPAL,
	AARCH64_INS_RCWSSWPL,
	AARCH64_INS_RCWSSWPP,
	AARCH64_INS_RCWSSWPPA,
	AARCH64_INS_RCWSSWPPAL,
	AARCH64_INS_RCWSSWPPL,
	AARCH64_INS_RDFFRS,
	AARCH64_INS_RDFFR,
	AARCH64_INS_RDSVL,
	AARCH64_INS_RDVL,
	AARCH64_INS_RET,
	AARCH64_INS_RETAA,
	AARCH64_INS_RETAB,
	AARCH64_INS_REV16,
	AARCH64_INS_REV32,
	AARCH64_INS_REV64,
	AARCH64_INS_REVB,
	AARCH64_INS_REVD,
	AARCH64_INS_REVH,
	AARCH64_INS_REVW,
	AARCH64_INS_REV,
	AARCH64_INS_RMIF,
	AARCH64_INS_ROR,
	AARCH64_INS_RPRFM,
	AARCH64_INS_RSHRNB,
	AARCH64_INS_RSHRNT,
	AARCH64_INS_RSHRN2,
	AARCH64_INS_RSHRN,
	AARCH64_INS_RSUBHNB,
	AARCH64_INS_RSUBHNT,
	AARCH64_INS_RSUBHN,
	AARCH64_INS_RSUBHN2,
	AARCH64_INS_SABALB,
	AARCH64_INS_SABALT,
	AARCH64_INS_SABAL2,
	AARCH64_INS_SABAL,
	AARCH64_INS_SABA,
	AARCH64_INS_SABDLB,
	AARCH64_INS_SABDLT,
	AARCH64_INS_SABDL2,
	AARCH64_INS_SABDL,
	AARCH64_INS_SABD,
	AARCH64_INS_SADALP,
	AARCH64_INS_SADDLBT,
	AARCH64_INS_SADDLB,
	AARCH64_INS_SADDLP,
	AARCH64_INS_SADDLT,
	AARCH64_INS_SADDLV,
	AARCH64_INS_SADDL2,
	AARCH64_INS_SADDL,
	AARCH64_INS_SADDV,
	AARCH64_INS_SADDWB,
	AARCH64_INS_SADDWT,
	AARCH64_INS_SADDW2,
	AARCH64_INS_SADDW,
	AARCH64_INS_SB,
	AARCH64_INS_SBCLB,
	AARCH64_INS_SBCLT,
	AARCH64_INS_SBCS,
	AARCH64_INS_SBC,
	AARCH64_INS_SBFM,
	AARCH64_INS_SCLAMP,
	AARCH64_INS_SCVTF,
	AARCH64_INS_SDIVR,
	AARCH64_INS_SDIV,
	AARCH64_INS_SDOT,
	AARCH64_INS_SEL,
	AARCH64_INS_SETE,
	AARCH64_INS_SETEN,
	AARCH64_INS_SETET,
	AARCH64_INS_SETETN,
	AARCH64_INS_SETF16,
	AARCH64_INS_SETF8,
	AARCH64_INS_SETFFR,
	AARCH64_INS_SETGM,
	AARCH64_INS_SETGMN,
	AARCH64_INS_SETGMT,
	AARCH64_INS_SETGMTN,
	AARCH64_INS_SETGP,
	AARCH64_INS_SETGPN,
	AARCH64_INS_SETGPT,
	AARCH64_INS_SETGPTN,
	AARCH64_INS_SETM,
	AARCH64_INS_SETMN,
	AARCH64_INS_SETMT,
	AARCH64_INS_SETMTN,
	AARCH64_INS_SETP,
	AARCH64_INS_SETPN,
	AARCH64_INS_SETPT,
	AARCH64_INS_SETPTN,
	AARCH64_INS_SHA1C,
	AARCH64_INS_SHA1H,
	AARCH64_INS_SHA1M,
	AARCH64_INS_SHA1P,
	AARCH64_INS_SHA1SU0,
	AARCH64_INS_SHA1SU1,
	AARCH64_INS_SHA256H2,
	AARCH64_INS_SHA256H,
	AARCH64_INS_SHA256SU0,
	AARCH64_INS_SHA256SU1,
	AARCH64_INS_SHA512H,
	AARCH64_INS_SHA512H2,
	AARCH64_INS_SHA512SU0,
	AARCH64_INS_SHA512SU1,
	AARCH64_INS_SHADD,
	AARCH64_INS_SHLL2,
	AARCH64_INS_SHLL,
	AARCH64_INS_SHL,
	AARCH64_INS_SHRNB,
	AARCH64_INS_SHRNT,
	AARCH64_INS_SHRN2,
	AARCH64_INS_SHRN,
	AARCH64_INS_SHSUBR,
	AARCH64_INS_SHSUB,
	AARCH64_INS_SLI,
	AARCH64_INS_SM3PARTW1,
	AARCH64_INS_SM3PARTW2,
	AARCH64_INS_SM3SS1,
	AARCH64_INS_SM3TT1A,
	AARCH64_INS_SM3TT1B,
	AARCH64_INS_SM3TT2A,
	AARCH64_INS_SM3TT2B,
	AARCH64_INS_SM4E,
	AARCH64_INS_SM4EKEY,
	AARCH64_INS_SMADDL,
	AARCH64_INS_SMAXP,
	AARCH64_INS_SMAXQV,
	AARCH64_INS_SMAXV,
	AARCH64_INS_SMAX,
	AARCH64_INS_SMC,
	AARCH64_INS_SMINP,
	AARCH64_INS_SMINQV,
	AARCH64_INS_SMINV,
	AARCH64_INS_SMIN,
	AARCH64_INS_SMLALB,
	AARCH64_INS_SMLALL,
	AARCH64_INS_SMLALT,
	AARCH64_INS_SMLAL,
	AARCH64_INS_SMLAL2,
	AARCH64_INS_SMLSLB,
	AARCH64_INS_SMLSLL,
	AARCH64_INS_SMLSLT,
	AARCH64_INS_SMLSL,
	AARCH64_INS_SMLSL2,
	AARCH64_INS_SMMLA,
	AARCH64_INS_SMOPA,
	AARCH64_INS_SMOPS,
	AARCH64_INS_SMOV,
	AARCH64_INS_SMSUBL,
	AARCH64_INS_SMULH,
	AARCH64_INS_SMULLB,
	AARCH64_INS_SMULLT,
	AARCH64_INS_SMULL2,
	AARCH64_INS_SMULL,
	AARCH64_INS_SPLICE,
	AARCH64_INS_SQABS,
	AARCH64_INS_SQADD,
	AARCH64_INS_SQCADD,
	AARCH64_INS_SQCVTN,
	AARCH64_INS_SQCVTUN,
	AARCH64_INS_SQCVTU,
	AARCH64_INS_SQCVT,
	AARCH64_INS_SQDECB,
	AARCH64_INS_SQDECD,
	AARCH64_INS_SQDECH,
	AARCH64_INS_SQDECP,
	AARCH64_INS_SQDECW,
	AARCH64_INS_SQDMLALBT,
	AARCH64_INS_SQDMLALB,
	AARCH64_INS_SQDMLALT,
	AARCH64_INS_SQDMLAL,
	AARCH64_INS_SQDMLAL2,
	AARCH64_INS_SQDMLSLBT,
	AARCH64_INS_SQDMLSLB,
	AARCH64_INS_SQDMLSLT,
	AARCH64_INS_SQDMLSL,
	AARCH64_INS_SQDMLSL2,
	AARCH64_INS_SQDMULH,
	AARCH64_INS_SQDMULLB,
	AARCH64_INS_SQDMULLT,
	AARCH64_INS_SQDMULL,
	AARCH64_INS_SQDMULL2,
	AARCH64_INS_SQINCB,
	AARCH64_INS_SQINCD,
	AARCH64_INS_SQINCH,
	AARCH64_INS_SQINCP,
	AARCH64_INS_SQINCW,
	AARCH64_INS_SQNEG,
	AARCH64_INS_SQRDCMLAH,
	AARCH64_INS_SQRDMLAH,
	AARCH64_INS_SQRDMLSH,
	AARCH64_INS_SQRDMULH,
	AARCH64_INS_SQRSHLR,
	AARCH64_INS_SQRSHL,
	AARCH64_INS_SQRSHRNB,
	AARCH64_INS_SQRSHRNT,
	AARCH64_INS_SQRSHRN,
	AARCH64_INS_SQRSHRN2,
	AARCH64_INS_SQRSHRUNB,
	AARCH64_INS_SQRSHRUNT,
	AARCH64_INS_SQRSHRUN,
	AARCH64_INS_SQRSHRUN2,
	AARCH64_INS_SQRSHRU,
	AARCH64_INS_SQRSHR,
	AARCH64_INS_SQSHLR,
	AARCH64_INS_SQSHLU,
	AARCH64_INS_SQSHL,
	AARCH64_INS_SQSHRNB,
	AARCH64_INS_SQSHRNT,
	AARCH64_INS_SQSHRN,
	AARCH64_INS_SQSHRN2,
	AARCH64_INS_SQSHRUNB,
	AARCH64_INS_SQSHRUNT,
	AARCH64_INS_SQSHRUN,
	AARCH64_INS_SQSHRUN2,
	AARCH64_INS_SQSUBR,
	AARCH64_INS_SQSUB,
	AARCH64_INS_SQXTNB,
	AARCH64_INS_SQXTNT,
	AARCH64_INS_SQXTN2,
	AARCH64_INS_SQXTN,
	AARCH64_INS_SQXTUNB,
	AARCH64_INS_SQXTUNT,
	AARCH64_INS_SQXTUN2,
	AARCH64_INS_SQXTUN,
	AARCH64_INS_SRHADD,
	AARCH64_INS_SRI,
	AARCH64_INS_SRSHLR,
	AARCH64_INS_SRSHL,
	AARCH64_INS_SRSHR,
	AARCH64_INS_SRSRA,
	AARCH64_INS_SSHLLB,
	AARCH64_INS_SSHLLT,
	AARCH64_INS_SSHLL2,
	AARCH64_INS_SSHLL,
	AARCH64_INS_SSHL,
	AARCH64_INS_SSHR,
	AARCH64_INS_SSRA,
	AARCH64_INS_ST1B,
	AARCH64_INS_ST1D,
	AARCH64_INS_ST1H,
	AARCH64_INS_ST1Q,
	AARCH64_INS_ST1W,
	AARCH64_INS_SSUBLBT,
	AARCH64_INS_SSUBLB,
	AARCH64_INS_SSUBLTB,
	AARCH64_INS_SSUBLT,
	AARCH64_INS_SSUBL2,
	AARCH64_INS_SSUBL,
	AARCH64_INS_SSUBWB,
	AARCH64_INS_SSUBWT,
	AARCH64_INS_SSUBW2,
	AARCH64_INS_SSUBW,
	AARCH64_INS_ST1,
	AARCH64_INS_ST2B,
	AARCH64_INS_ST2D,
	AARCH64_INS_ST2G,
	AARCH64_INS_ST2H,
	AARCH64_INS_ST2Q,
	AARCH64_INS_ST2,
	AARCH64_INS_ST2W,
	AARCH64_INS_ST3B,
	AARCH64_INS_ST3D,
	AARCH64_INS_ST3H,
	AARCH64_INS_ST3Q,
	AARCH64_INS_ST3,
	AARCH64_INS_ST3W,
	AARCH64_INS_ST4B,
	AARCH64_INS_ST4D,
	AARCH64_INS_ST4,
	AARCH64_INS_ST4H,
	AARCH64_INS_ST4Q,
	AARCH64_INS_ST4W,
	AARCH64_INS_ST64B,
	AARCH64_INS_ST64BV,
	AARCH64_INS_ST64BV0,
	AARCH64_INS_STGM,
	AARCH64_INS_STG,
	AARCH64_INS_STGP,
	AARCH64_INS_STILP,
	AARCH64_INS_STL1,
	AARCH64_INS_STLLRB,
	AARCH64_INS_STLLRH,
	AARCH64_INS_STLLR,
	AARCH64_INS_STLRB,
	AARCH64_INS_STLRH,
	AARCH64_INS_STLR,
	AARCH64_INS_STLURB,
	AARCH64_INS_STLURH,
	AARCH64_INS_STLUR,
	AARCH64_INS_STLXP,
	AARCH64_INS_STLXRB,
	AARCH64_INS_STLXRH,
	AARCH64_INS_STLXR,
	AARCH64_INS_STNP,
	AARCH64_INS_STNT1B,
	AARCH64_INS_STNT1D,
	AARCH64_INS_STNT1H,
	AARCH64_INS_STNT1W,
	AARCH64_INS_STP,
	AARCH64_INS_STRB,
	AARCH64_INS_STR,
	AARCH64_INS_STRH,
	AARCH64_INS_STTRB,
	AARCH64_INS_STTRH,
	AARCH64_INS_STTR,
	AARCH64_INS_STURB,
	AARCH64_INS_STUR,
	AARCH64_INS_STURH,
	AARCH64_INS_STXP,
	AARCH64_INS_STXRB,
	AARCH64_INS_STXRH,
	AARCH64_INS_STXR,
	AARCH64_INS_STZ2G,
	AARCH64_INS_STZGM,
	AARCH64_INS_STZG,
	AARCH64_INS_SUBG,
	AARCH64_INS_SUBHNB,
	AARCH64_INS_SUBHNT,
	AARCH64_INS_SUBHN,
	AARCH64_INS_SUBHN2,
	AARCH64_INS_SUBP,
	AARCH64_INS_SUBPS,
	AARCH64_INS_SUBR,
	AARCH64_INS_SUBS,
	AARCH64_INS_SUB,
	AARCH64_INS_SUDOT,
	AARCH64_INS_SUMLALL,
	AARCH64_INS_SUMOPA,
	AARCH64_INS_SUMOPS,
	AARCH64_INS_SUNPKHI,
	AARCH64_INS_SUNPKLO,
	AARCH64_INS_SUNPK,
	AARCH64_INS_SUQADD,
	AARCH64_INS_SUVDOT,
	AARCH64_INS_SVC,
	AARCH64_INS_SVDOT,
	AARCH64_INS_SWPAB,
	AARCH64_INS_SWPAH,
	AARCH64_INS_SWPALB,
	AARCH64_INS_SWPALH,
	AARCH64_INS_SWPAL,
	AARCH64_INS_SWPA,
	AARCH64_INS_SWPB,
	AARCH64_INS_SWPH,
	AARCH64_INS_SWPLB,
	AARCH64_INS_SWPLH,
	AARCH64_INS_SWPL,
	AARCH64_INS_SWPP,
	AARCH64_INS_SWPPA,
	AARCH64_INS_SWPPAL,
	AARCH64_INS_SWPPL,
	AARCH64_INS_SWP,
	AARCH64_INS_SXTB,
	AARCH64_INS_SXTH,
	AARCH64_INS_SXTW,
	AARCH64_INS_SYSL,
	AARCH64_INS_SYSP,
	AARCH64_INS_SYS,
	AARCH64_INS_TBLQ,
	AARCH64_INS_TBL,
	AARCH64_INS_TBNZ,
	AARCH64_INS_TBXQ,
	AARCH64_INS_TBX,
	AARCH64_INS_TBZ,
	AARCH64_INS_TCANCEL,
	AARCH64_INS_TCOMMIT,
	AARCH64_INS_TRCIT,
	AARCH64_INS_TRN1,
	AARCH64_INS_TRN2,
	AARCH64_INS_TSB,
	AARCH64_INS_TSTART,
	AARCH64_INS_TTEST,
	AARCH64_INS_UABALB,
	AARCH64_INS_UABALT,
	AARCH64_INS_UABAL2,
	AARCH64_INS_UABAL,
	AARCH64_INS_UABA,
	AARCH64_INS_UABDLB,
	AARCH64_INS_UABDLT,
	AARCH64_INS_UABDL2,
	AARCH64_INS_UABDL,
	AARCH64_INS_UABD,
	AARCH64_INS_UADALP,
	AARCH64_INS_UADDLB,
	AARCH64_INS_UADDLP,
	AARCH64_INS_UADDLT,
	AARCH64_INS_UADDLV,
	AARCH64_INS_UADDL2,
	AARCH64_INS_UADDL,
	AARCH64_INS_UADDV,
	AARCH64_INS_UADDWB,
	AARCH64_INS_UADDWT,
	AARCH64_INS_UADDW2,
	AARCH64_INS_UADDW,
	AARCH64_INS_UBFM,
	AARCH64_INS_UCLAMP,
	AARCH64_INS_UCVTF,
	AARCH64_INS_UDF,
	AARCH64_INS_UDIVR,
	AARCH64_INS_UDIV,
	AARCH64_INS_UDOT,
	AARCH64_INS_UHADD,
	AARCH64_INS_UHSUBR,
	AARCH64_INS_UHSUB,
	AARCH64_INS_UMADDL,
	AARCH64_INS_UMAXP,
	AARCH64_INS_UMAXQV,
	AARCH64_INS_UMAXV,
	AARCH64_INS_UMAX,
	AARCH64_INS_UMINP,
	AARCH64_INS_UMINQV,
	AARCH64_INS_UMINV,
	AARCH64_INS_UMIN,
	AARCH64_INS_UMLALB,
	AARCH64_INS_UMLALL,
	AARCH64_INS_UMLALT,
	AARCH64_INS_UMLAL,
	AARCH64_INS_UMLAL2,
	AARCH64_INS_UMLSLB,
	AARCH64_INS_UMLSLL,
	AARCH64_INS_UMLSLT,
	AARCH64_INS_UMLSL,
	AARCH64_INS_UMLSL2,
	AARCH64_INS_UMMLA,
	AARCH64_INS_UMOPA,
	AARCH64_INS_UMOPS,
	AARCH64_INS_UMOV,
	AARCH64_INS_UMSUBL,
	AARCH64_INS_UMULH,
	AARCH64_INS_UMULLB,
	AARCH64_INS_UMULLT,
	AARCH64_INS_UMULL2,
	AARCH64_INS_UMULL,
	AARCH64_INS_UQADD,
	AARCH64_INS_UQCVTN,
	AARCH64_INS_UQCVT,
	AARCH64_INS_UQDECB,
	AARCH64_INS_UQDECD,
	AARCH64_INS_UQDECH,
	AARCH64_INS_UQDECP,
	AARCH64_INS_UQDECW,
	AARCH64_INS_UQINCB,
	AARCH64_INS_UQINCD,
	AARCH64_INS_UQINCH,
	AARCH64_INS_UQINCP,
	AARCH64_INS_UQINCW,
	AARCH64_INS_UQRSHLR,
	AARCH64_INS_UQRSHL,
	AARCH64_INS_UQRSHRNB,
	AARCH64_INS_UQRSHRNT,
	AARCH64_INS_UQRSHRN,
	AARCH64_INS_UQRSHRN2,
	AARCH64_INS_UQRSHR,
	AARCH64_INS_UQSHLR,
	AARCH64_INS_UQSHL,
	AARCH64_INS_UQSHRNB,
	AARCH64_INS_UQSHRNT,
	AARCH64_INS_UQSHRN,
	AARCH64_INS_UQSHRN2,
	AARCH64_INS_UQSUBR,
	AARCH64_INS_UQSUB,
	AARCH64_INS_UQXTNB,
	AARCH64_INS_UQXTNT,
	AARCH64_INS_UQXTN2,
	AARCH64_INS_UQXTN,
	AARCH64_INS_URECPE,
	AARCH64_INS_URHADD,
	AARCH64_INS_URSHLR,
	AARCH64_INS_URSHL,
	AARCH64_INS_URSHR,
	AARCH64_INS_URSQRTE,
	AARCH64_INS_URSRA,
	AARCH64_INS_USDOT,
	AARCH64_INS_USHLLB,
	AARCH64_INS_USHLLT,
	AARCH64_INS_USHLL2,
	AARCH64_INS_USHLL,
	AARCH64_INS_USHL,
	AARCH64_INS_USHR,
	AARCH64_INS_USMLALL,
	AARCH64_INS_USMMLA,
	AARCH64_INS_USMOPA,
	AARCH64_INS_USMOPS,
	AARCH64_INS_USQADD,
	AARCH64_INS_USRA,
	AARCH64_INS_USUBLB,
	AARCH64_INS_USUBLT,
	AARCH64_INS_USUBL2,
	AARCH64_INS_USUBL,
	AARCH64_INS_USUBWB,
	AARCH64_INS_USUBWT,
	AARCH64_INS_USUBW2,
	AARCH64_INS_USUBW,
	AARCH64_INS_USVDOT,
	AARCH64_INS_UUNPKHI,
	AARCH64_INS_UUNPKLO,
	AARCH64_INS_UUNPK,
	AARCH64_INS_UVDOT,
	AARCH64_INS_UXTB,
	AARCH64_INS_UXTH,
	AARCH64_INS_UXTW,
	AARCH64_INS_UZP1,
	AARCH64_INS_UZP2,
	AARCH64_INS_UZPQ1,
	AARCH64_INS_UZPQ2,
	AARCH64_INS_UZP,
	AARCH64_INS_WFET,
	AARCH64_INS_WFIT,
	AARCH64_INS_WHILEGE,
	AARCH64_INS_WHILEGT,
	AARCH64_INS_WHILEHI,
	AARCH64_INS_WHILEHS,
	AARCH64_INS_WHILELE,
	AARCH64_INS_WHILELO,
	AARCH64_INS_WHILELS,
	AARCH64_INS_WHILELT,
	AARCH64_INS_WHILERW,
	AARCH64_INS_WHILEWR,
	AARCH64_INS_WRFFR,
	AARCH64_INS_XAFLAG,
	AARCH64_INS_XAR,
	AARCH64_INS_XPACD,
	AARCH64_INS_XPACI,
	AARCH64_INS_XTN2,
	AARCH64_INS_XTN,
	AARCH64_INS_ZERO,
	AARCH64_INS_ZIP1,
	AARCH64_INS_ZIP2,
	AARCH64_INS_ZIPQ1,
	AARCH64_INS_ZIPQ2,
	AARCH64_INS_ZIP,

	// clang-format on
	// generated content <AArch64GenCSInsnEnum.inc> end

  ARM64_INS_ENDING, // <-- mark the end of the list of insn
} arm64_insn;

/// Group of ARM64 instructions
typedef enum arm64_insn_group {
  ARM64_GRP_INVALID = 0, ///< = CS_GRP_INVALID

  // Generic groups
  // all jump instructions (conditional+direct+indirect jumps)
  ARM64_GRP_JUMP, ///< = CS_GRP_JUMP
  ARM64_GRP_CALL,
  ARM64_GRP_RET,
  ARM64_GRP_INT,
  ARM64_GRP_PRIVILEGE = 6,   ///< = CS_GRP_PRIVILEGE
  ARM64_GRP_BRANCH_RELATIVE, ///< = CS_GRP_BRANCH_RELATIVE

	// generated content <AArch64GenCSFeatureEnum.inc> begin
	// clang-format off

	AARCH64_FEATURE_HasSVEorSME = 128,
	AARCH64_FEATURE_HasSMEI16I64,
	AARCH64_FEATURE_HasSME,
	AARCH64_FEATURE_HasSME2,
	AARCH64_FEATURE_HasSME2p1,
	AARCH64_FEATURE_HasB16B16,
	AARCH64_FEATURE_HasNEON,
	AARCH64_FEATURE_HasSVE,
	AARCH64_FEATURE_HasSMEF64F64,
	AARCH64_FEATURE_HasSMEF16F16,
	AARCH64_FEATURE_HasFullFP16,
	AARCH64_FEATURE_HasMTE,
	AARCH64_FEATURE_HasMOPS,
	AARCH64_FEATURE_HasSVE2orSME,
	AARCH64_FEATURE_HasCSSC,
	AARCH64_FEATURE_HasSVE2p1_or_HasSME2p1,
	AARCH64_FEATURE_HasSVE2AES,
	AARCH64_FEATURE_HasAES,
	AARCH64_FEATURE_HasPAuth,
	AARCH64_FEATURE_HasAltNZCV,
	AARCH64_FEATURE_HasSHA3,
	AARCH64_FEATURE_HasHBC,
	AARCH64_FEATURE_HasSVE2BitPerm,
	AARCH64_FEATURE_HasBF16,
	AARCH64_FEATURE_HasNEONorSME,
	AARCH64_FEATURE_HasSVE2p1_or_HasSME2,
	AARCH64_FEATURE_HasBRBE,
	AARCH64_FEATURE_HasLSE,
	AARCH64_FEATURE_HasFlagM,
	AARCH64_FEATURE_HasCRC,
	AARCH64_FEATURE_HasEL3,
	AARCH64_FEATURE_HasXS,
	AARCH64_FEATURE_HasFPARMv8,
	AARCH64_FEATURE_HasComplxNum,
	AARCH64_FEATURE_HasJS,
	AARCH64_FEATURE_HasFP16FML,
	AARCH64_FEATURE_HasMatMulFP64,
	AARCH64_FEATURE_HasMatMulFP32,
	AARCH64_FEATURE_HasFRInt3264,
	AARCH64_FEATURE_HasSVE2p1,
	AARCH64_FEATURE_HasSVE2,
	AARCH64_FEATURE_HasLS64,
	AARCH64_FEATURE_HasRCPC3,
	AARCH64_FEATURE_HasRCPC,
	AARCH64_FEATURE_HasRCPC_IMMO,
	AARCH64_FEATURE_HasLSE128,
	AARCH64_FEATURE_HasLOR,
	AARCH64_FEATURE_HasD128,
	AARCH64_FEATURE_HasSVE2p1_or_HasSME,
	AARCH64_FEATURE_HasSVE2SHA3,
	AARCH64_FEATURE_HasTHE,
	AARCH64_FEATURE_HasSB,
	AARCH64_FEATURE_HasDotProd,
	AARCH64_FEATURE_HasSHA2,
	AARCH64_FEATURE_HasSM4,
	AARCH64_FEATURE_HasSVE2SM4,
	AARCH64_FEATURE_HasMatMulInt8,
	AARCH64_FEATURE_HasRDM,
	AARCH64_FEATURE_HasTME,
	AARCH64_FEATURE_HasITE,
	AARCH64_FEATURE_HasTRACEV8_4,
	AARCH64_FEATURE_HasWFxT,

	// clang-format on
	// generated content <AArch64GenCSFeatureEnum.inc> end

  ARM64_GRP_ENDING, // <-- mark the end of the list of groups
} arm64_insn_group;

#ifdef __cplusplus
}
#endif

#endif

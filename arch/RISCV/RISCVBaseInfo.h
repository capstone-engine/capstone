//===-- RISCVBaseInfo.h - Top level definitions for RISCV MC ----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains small standalone enum definitions for the RISCV target
// useful for the compiler back-end and the MC libraries.
//
//===----------------------------------------------------------------------===//
#ifndef CS_RISCVBASEINFO_H
#define CS_RISCVBASEINFO_H

//#include "RISCVMCTargetDesc.h"

// RISCVII - This namespace holds all of the target specific flags that
// instruction info tracks. All definitions must match RISCVInstrFormats.td.
enum
{
	RISCVII_InstFormatPseudo = 0,
	RISCVII_InstFormatR = 1,
	RISCVII_InstFormatR4 = 2,
	RISCVII_InstFormatI = 3,
	RISCVII_InstFormatS = 4,
	RISCVII_InstFormatB = 5,
	RISCVII_InstFormatU = 6,
	RISCVII_InstFormatJ = 7,
	RISCVII_InstFormatOther = 8,

	RISCVII_InstFormatMask = 15
};

enum
{
	RISCVII_MO_None,
	RISCVII_MO_LO,
	RISCVII_MO_HI,
	RISCVII_MO_PCREL_HI,
};

// Describes the predecessor/successor bits used in the FENCE instruction.
enum FenceField
{
	RISCVFenceField_I = 8,
	RISCVFenceField_O = 4,
	RISCVFenceField_R = 2,
	RISCVFenceField_W = 1
};

//Todo_rod: Not including this since so far it is used by printFRMArg from InstPrinter which I ahvent included yet.
// Describes the supported floating point rounding mode encodings.
/*namespace RISCVFPRndMode {
enum RoundingMode {
  RISCVFPRndMode_RNE = 0,
  RISCVFPRndMode_RTZ = 1,
  RISCVFPRndMode_RDN = 2,
  RISCVFPRndMode_RUP = 3,
  RISCVFPRndMode_RMM = 4,
  RISCVFPRndMode_DYN = 7,
  RISCVFPRndMode_Invalid
};

inline static StringRef roundingModeToString(RoundingMode RndMode) {
  switch (RndMode) {
  default:
    llvm_unreachable("Unknown floating point rounding mode");
  case RISCVFPRndMode::RNE:
    return "rne";
  case RISCVFPRndMode::RTZ:
    return "rtz";
  case RISCVFPRndMode::RDN:
    return "rdn";
  case RISCVFPRndMode::RUP:
    return "rup";
  case RISCVFPRndMode::RMM:
    return "rmm";
  case RISCVFPRndMode::DYN:
    return "dyn";
  }
}

inline static RoundingMode stringToRoundingMode(StringRef Str) {
  return StringSwitch<RoundingMode>(Str)
      .Case("rne", RISCVFPRndMode::RNE)
      .Case("rtz", RISCVFPRndMode::RTZ)
      .Case("rdn", RISCVFPRndMode::RDN)
      .Case("rup", RISCVFPRndMode::RUP)
      .Case("rmm", RISCVFPRndMode::RMM)
      .Case("dyn", RISCVFPRndMode::DYN)
      .Default(RISCVFPRndMode::Invalid);
}
} // namespace RISCVFPRndMode
*/

#endif

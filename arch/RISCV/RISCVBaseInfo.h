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
enum {
  IRISCVII_InstFormatPseudo = 0,
  IRISCVII_InstFormatR = 1,
  IRISCVII_InstFormatR4 = 2,
  IRISCVII_InstFormatI = 3,
  IRISCVII_InstFormatS = 4,
  IRISCVII_InstFormatB = 5,
  IRISCVII_InstFormatU = 6,
  IRISCVII_InstFormatJ = 7,
  IRISCVII_InstFormatCR = 8,
  IRISCVII_InstFormatCI = 9,
  IRISCVII_InstFormatCSS = 10,
  IRISCVII_InstFormatCIW = 11,
  IRISCVII_InstFormatCL = 12,
  IRISCVII_InstFormatCS = 13,
  IRISCVII_InstFormatCA = 14,
  IRISCVII_InstFormatCB = 15,
  IRISCVII_InstFormatCJ = 16,
  IRISCVII_InstFormatOther = 17,

  IRISCVII_InstFormatMask = 31	
};

enum {
  RISCVII_MO_None,
  RISCVII_MO_LO,
  RISCVII_MO_HI,
  RISCVII_MO_PCREL_HI,
};

// Describes the predecessor/successor bits used in the FENCE instruction.
enum FenceField {
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

inline static StringRef roundingModeToString(RoundingMode RndMode) 
{	
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

inline static RoundingMode stringToRoundingMode(StringRef Str) 
{
	return StringSwitch <RoundingMode>(Str)
	    .Case("rne", RISCVFPRndMode::RNE)
	    .Case("rtz", RISCVFPRndMode::RTZ)
	    .Case("rdn", RISCVFPRndMode::RDN)
	    .Case("rup", RISCVFPRndMode::RUP)
	    .Case("rmm", RISCVFPRndMode::RMM)
	    .Case("dyn", RISCVFPRndMode::DYN)
	    .Default(RISCVFPRndMode::Invalid);
}
}				// namespace RISCVFPRndMode
*/
#endif

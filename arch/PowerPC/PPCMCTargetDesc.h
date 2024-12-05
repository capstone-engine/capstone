

/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/*    Rot127 <unisono@quyllur.org> 2022-2023 */
/* Automatically translated source file from LLVM. */

/* LLVM-commit: <commit> */
/* LLVM-tag: <tag> */

/* Only small edits allowed. */
/* For multiple similar edits, please create a Patch for the translator. */

/* Capstone's C++ file translator: */
/* https://github.com/capstone-engine/capstone/tree/next/suite/auto-sync */

//===-- PPCMCTargetDesc.h - PowerPC Target Descriptions ---------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file provides PowerPC specific target descriptions.
//
//===----------------------------------------------------------------------===//

#ifndef CS_PPC_MCTARGETDESC_H
#define CS_PPC_MCTARGETDESC_H

// GCC #defines PPC on Linux but we use it as our namespace name
#undef PPC

#include <capstone/platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../LEB128.h"
#include "../../MathExtras.h"
#include "../../MCInst.h"
#include "../../MCInstrDesc.h"
#include "../../MCRegisterInfo.h"
#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

/// Returns true iff Val consists of one contiguous run of 1s with any number of
/// 0s on either side.  The 1s are allowed to wrap from LSB to MSB, so
/// 0x000FFF0, 0x0000FFFF, and 0xFF0000FF are all runs.  0x0F0F0000 is not,
/// since all 1s are not contiguous.
static inline bool isRunOfOnes(unsigned Val, unsigned *MB, unsigned *ME)
{
	if (!Val)
		return false;

	if (isShiftedMask_32(Val)) {
		// look for the first non-zero bit
		*MB = countLeadingZeros(Val);
		// look for the first zero bit after the run of ones
		*ME = countLeadingZeros((Val - 1) ^ Val);
		return true;
	} else {
		Val = ~Val; // invert mask
		if (isShiftedMask_32(Val)) {
			// effectively look for the first zero bit
			*ME = countLeadingZeros(Val) - 1;
			// effectively look for the first one bit after the run of zeros
			*MB = countLeadingZeros((Val - 1) ^ Val) + 1;
			return true;
		}
	}
	// no run present
	return false;
}

static inline bool isRunOfOnes64(uint64_t Val, unsigned *MB, unsigned *ME)
{
	if (!Val)
		return false;

	if (isShiftedMask_64(Val)) {
		// look for the first non-zero bit
		*MB = countLeadingZeros(Val);
		// look for the first zero bit after the run of ones
		*ME = countLeadingZeros((Val - 1) ^ Val);
		return true;
	} else {
		Val = ~Val; // invert mask
		if (isShiftedMask_64(Val)) {
			// effectively look for the first zero bit
			*ME = countLeadingZeros(Val) - 1;
			// effectively look for the first one bit after the run of zeros
			*MB = countLeadingZeros((Val - 1) ^ Val) + 1;
			return true;
		}
	}
	// no run present
	return false;
}

// end namespace llvm

// Generated files will use "namespace PPC". To avoid symbol clash,
// undefine PPC here. PPC may be predefined on some hosts.
#undef PPC

// Defines symbolic names for PowerPC registers.  This defines a mapping from
// register name to register number.
//
#define GET_REGINFO_ENUM
#include "PPCGenRegisterInfo.inc"

// Defines symbolic names for the PowerPC instructions.
//
#define GET_INSTRINFO_ENUM
#define GET_INSTRINFO_SCHED_ENUM
#define GET_INSTRINFO_MC_HELPER_DECLS
#define GET_INSTRINFO_MC_DESC
#include "PPCGenInstrInfo.inc"

#define GET_SUBTARGETINFO_ENUM
#include "PPCGenSubtargetInfo.inc"

#define PPC_REGS0_7(X) { X##0, X##1, X##2, X##3, X##4, X##5, X##6, X##7 }

#define PPC_REGS0_31(X) \
	{ X##0,	 X##1,	X##2,  X##3,  X##4,  X##5,  X##6,  X##7, \
	  X##8,	 X##9,	X##10, X##11, X##12, X##13, X##14, X##15, \
	  X##16, X##17, X##18, X##19, X##20, X##21, X##22, X##23, \
	  X##24, X##25, X##26, X##27, X##28, X##29, X##30, X##31 }

#define PPC_REGS_EVEN0_30(X) \
	{ X##0,	 X##2,	X##4,  X##6,  X##8,  X##10, X##12, X##14, \
	  X##16, X##18, X##20, X##22, X##24, X##26, X##28, X##30 }

#define PPC_REGS0_63(X) \
	{ \
		X##0,  X##1,  X##2,  X##3,  X##4,  X##5,  X##6,	 X##7, \
		X##8,  X##9,  X##10, X##11, X##12, X##13, X##14, X##15, \
		X##16, X##17, X##18, X##19, X##20, X##21, X##22, X##23, \
		X##24, X##25, X##26, X##27, X##28, X##29, X##30, X##31, \
		X##32, X##33, X##34, X##35, X##36, X##37, X##38, X##39, \
		X##40, X##41, X##42, X##43, X##44, X##45, X##46, X##47, \
		X##48, X##49, X##50, X##51, X##52, X##53, X##54, X##55, \
		X##56, X##57, X##58, X##59, X##60, X##61, X##62, X##63 \
	}

#define PPC_REGS_NO0_31(Z, X) \
	{ Z,	 X##1,	X##2,  X##3,  X##4,  X##5,  X##6,  X##7, \
	  X##8,	 X##9,	X##10, X##11, X##12, X##13, X##14, X##15, \
	  X##16, X##17, X##18, X##19, X##20, X##21, X##22, X##23, \
	  X##24, X##25, X##26, X##27, X##28, X##29, X##30, X##31 }

#define PPC_REGS_LO_HI(LO, HI) \
	{ LO##0,  LO##1,  LO##2,  LO##3,  LO##4,  LO##5,  LO##6,  LO##7, \
	  LO##8,  LO##9,  LO##10, LO##11, LO##12, LO##13, LO##14, LO##15, \
	  LO##16, LO##17, LO##18, LO##19, LO##20, LO##21, LO##22, LO##23, \
	  LO##24, LO##25, LO##26, LO##27, LO##28, LO##29, LO##30, LO##31, \
	  HI##0,  HI##1,  HI##2,  HI##3,  HI##4,  HI##5,  HI##6,  HI##7, \
	  HI##8,  HI##9,  HI##10, HI##11, HI##12, HI##13, HI##14, HI##15, \
	  HI##16, HI##17, HI##18, HI##19, HI##20, HI##21, HI##22, HI##23, \
	  HI##24, HI##25, HI##26, HI##27, HI##28, HI##29, HI##30, HI##31 }

#define PPC_REGS0_7(X) { X##0, X##1, X##2, X##3, X##4, X##5, X##6, X##7 }

#define PPC_REGS0_3(X) { X##0, X##1, X##2, X##3 }

#define DEFINE_PPC_REGCLASSES \
	static const MCPhysReg RRegs[32] = PPC_REGS0_31(PPC_R); \
	static const MCPhysReg XRegs[32] = PPC_REGS0_31(PPC_X); \
	static const MCPhysReg FRegs[32] = PPC_REGS0_31(PPC_F); \
	static const MCPhysReg FpRegs[16] = PPC_REGS_EVEN0_30(PPC_Fpair); \
	static const MCPhysReg VSRpRegs[32] = PPC_REGS0_31(PPC_VSRp); \
	static const MCPhysReg SPERegs[32] = PPC_REGS0_31(PPC_S); \
	static const MCPhysReg VFRegs[32] = PPC_REGS0_31(PPC_VF); \
	static const MCPhysReg VRegs[32] = PPC_REGS0_31(PPC_V); \
	static const MCPhysReg RRegsNoR0[32] = \
		PPC_REGS_NO0_31(PPC_ZERO, PPC_R); \
	static const MCPhysReg XRegsNoX0[32] = \
		PPC_REGS_NO0_31(PPC_ZERO8, PPC_X); \
	static const MCPhysReg VSRegs[64] = PPC_REGS_LO_HI(PPC_VSL, PPC_V); \
	static const MCPhysReg VSFRegs[64] = PPC_REGS_LO_HI(PPC_F, PPC_VF); \
	static const MCPhysReg VSSRegs[64] = PPC_REGS_LO_HI(PPC_F, PPC_VF); \
	static const MCPhysReg CRBITRegs[32] = { \
		PPC_CR0LT, PPC_CR0GT, PPC_CR0EQ, PPC_CR0UN, PPC_CR1LT, \
		PPC_CR1GT, PPC_CR1EQ, PPC_CR1UN, PPC_CR2LT, PPC_CR2GT, \
		PPC_CR2EQ, PPC_CR2UN, PPC_CR3LT, PPC_CR3GT, PPC_CR3EQ, \
		PPC_CR3UN, PPC_CR4LT, PPC_CR4GT, PPC_CR4EQ, PPC_CR4UN, \
		PPC_CR5LT, PPC_CR5GT, PPC_CR5EQ, PPC_CR5UN, PPC_CR6LT, \
		PPC_CR6GT, PPC_CR6EQ, PPC_CR6UN, PPC_CR7LT, PPC_CR7GT, \
		PPC_CR7EQ, PPC_CR7UN \
	}; \
	static const MCPhysReg CRRegs[8] = PPC_REGS0_7(PPC_CR); \
	static const MCPhysReg ACCRegs[8] = PPC_REGS0_7(PPC_ACC); \
	static const MCPhysReg WACCRegs[8] = PPC_REGS0_7(PPC_WACC); \
	static const MCPhysReg WACC_HIRegs[8] = PPC_REGS0_7(PPC_WACC_HI); \
	static const MCPhysReg DMRROWpRegs[32] = PPC_REGS0_31(PPC_DMRROWp); \
	static const MCPhysReg DMRROWRegs[64] = PPC_REGS0_63(PPC_DMRROW); \
	static const MCPhysReg DMRRegs[8] = PPC_REGS0_7(PPC_DMR); \
	static const MCPhysReg DMRpRegs[4] = PPC_REGS0_3(PPC_DMRp);

static const MCPhysReg QFRegs[] = {
	PPC_QF0,  PPC_QF1,  PPC_QF2,  PPC_QF3,	PPC_QF4,  PPC_QF5,  PPC_QF6,
	PPC_QF7,  PPC_QF8,  PPC_QF9,  PPC_QF10, PPC_QF11, PPC_QF12, PPC_QF13,
	PPC_QF14, PPC_QF15, PPC_QF16, PPC_QF17, PPC_QF18, PPC_QF19, PPC_QF20,
	PPC_QF21, PPC_QF22, PPC_QF23, PPC_QF24, PPC_QF25, PPC_QF26, PPC_QF27,
	PPC_QF28, PPC_QF29, PPC_QF30, PPC_QF31
};

#endif // CS_PPC_MCTARGETDESC_H

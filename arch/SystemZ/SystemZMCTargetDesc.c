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

//===-- SystemZMCTargetDesc.cpp - SystemZ target descriptions -------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "../../MCInst.h"
#include "../../MCRegisterInfo.h"
#include "SystemZMCTargetDesc.h"
#include "SystemZInstPrinter.h"

#define GET_INSTRINFO_MC_DESC
#define ENABLE_INSTR_PREDICATE_VERIFIER
#include "SystemZGenInstrInfo.inc"

#define GET_SUBTARGETINFO_MC_DESC
#include "SystemZGenSubtargetInfo.inc"

#define GET_REGINFO_MC_DESC
#include "SystemZGenRegisterInfo.inc"
#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

const unsigned SystemZMC_GR32Regs[16] = {
	SystemZ_R0L,  SystemZ_R1L,  SystemZ_R2L,  SystemZ_R3L,
	SystemZ_R4L,  SystemZ_R5L,  SystemZ_R6L,  SystemZ_R7L,
	SystemZ_R8L,  SystemZ_R9L,  SystemZ_R10L, SystemZ_R11L,
	SystemZ_R12L, SystemZ_R13L, SystemZ_R14L, SystemZ_R15L
};

const unsigned SystemZMC_GRH32Regs[16] = {
	SystemZ_R0H,  SystemZ_R1H,  SystemZ_R2H,  SystemZ_R3H,
	SystemZ_R4H,  SystemZ_R5H,  SystemZ_R6H,  SystemZ_R7H,
	SystemZ_R8H,  SystemZ_R9H,  SystemZ_R10H, SystemZ_R11H,
	SystemZ_R12H, SystemZ_R13H, SystemZ_R14H, SystemZ_R15H
};

const unsigned SystemZMC_GR64Regs[16] = {
	SystemZ_R0D,  SystemZ_R1D,  SystemZ_R2D,  SystemZ_R3D,
	SystemZ_R4D,  SystemZ_R5D,  SystemZ_R6D,  SystemZ_R7D,
	SystemZ_R8D,  SystemZ_R9D,  SystemZ_R10D, SystemZ_R11D,
	SystemZ_R12D, SystemZ_R13D, SystemZ_R14D, SystemZ_R15D
};

const unsigned SystemZMC_GR128Regs[16] = { SystemZ_R0Q,	 0, SystemZ_R2Q,  0,
					   SystemZ_R4Q,	 0, SystemZ_R6Q,  0,
					   SystemZ_R8Q,	 0, SystemZ_R10Q, 0,
					   SystemZ_R12Q, 0, SystemZ_R14Q, 0 };

const unsigned SystemZMC_FP32Regs[16] = {
	SystemZ_F0S,  SystemZ_F1S,  SystemZ_F2S,  SystemZ_F3S,
	SystemZ_F4S,  SystemZ_F5S,  SystemZ_F6S,  SystemZ_F7S,
	SystemZ_F8S,  SystemZ_F9S,  SystemZ_F10S, SystemZ_F11S,
	SystemZ_F12S, SystemZ_F13S, SystemZ_F14S, SystemZ_F15S
};

const unsigned SystemZMC_FP64Regs[16] = {
	SystemZ_F0D,  SystemZ_F1D,  SystemZ_F2D,  SystemZ_F3D,
	SystemZ_F4D,  SystemZ_F5D,  SystemZ_F6D,  SystemZ_F7D,
	SystemZ_F8D,  SystemZ_F9D,  SystemZ_F10D, SystemZ_F11D,
	SystemZ_F12D, SystemZ_F13D, SystemZ_F14D, SystemZ_F15D
};

const unsigned SystemZMC_FP128Regs[16] = { SystemZ_F0Q,	 SystemZ_F1Q,  0, 0,
					   SystemZ_F4Q,	 SystemZ_F5Q,  0, 0,
					   SystemZ_F8Q,	 SystemZ_F9Q,  0, 0,
					   SystemZ_F12Q, SystemZ_F13Q, 0, 0 };

const unsigned SystemZMC_VR32Regs[32] = {
	SystemZ_F0S,  SystemZ_F1S,  SystemZ_F2S,  SystemZ_F3S,	SystemZ_F4S,
	SystemZ_F5S,  SystemZ_F6S,  SystemZ_F7S,  SystemZ_F8S,	SystemZ_F9S,
	SystemZ_F10S, SystemZ_F11S, SystemZ_F12S, SystemZ_F13S, SystemZ_F14S,
	SystemZ_F15S, SystemZ_F16S, SystemZ_F17S, SystemZ_F18S, SystemZ_F19S,
	SystemZ_F20S, SystemZ_F21S, SystemZ_F22S, SystemZ_F23S, SystemZ_F24S,
	SystemZ_F25S, SystemZ_F26S, SystemZ_F27S, SystemZ_F28S, SystemZ_F29S,
	SystemZ_F30S, SystemZ_F31S
};

const unsigned SystemZMC_VR64Regs[32] = {
	SystemZ_F0D,  SystemZ_F1D,  SystemZ_F2D,  SystemZ_F3D,	SystemZ_F4D,
	SystemZ_F5D,  SystemZ_F6D,  SystemZ_F7D,  SystemZ_F8D,	SystemZ_F9D,
	SystemZ_F10D, SystemZ_F11D, SystemZ_F12D, SystemZ_F13D, SystemZ_F14D,
	SystemZ_F15D, SystemZ_F16D, SystemZ_F17D, SystemZ_F18D, SystemZ_F19D,
	SystemZ_F20D, SystemZ_F21D, SystemZ_F22D, SystemZ_F23D, SystemZ_F24D,
	SystemZ_F25D, SystemZ_F26D, SystemZ_F27D, SystemZ_F28D, SystemZ_F29D,
	SystemZ_F30D, SystemZ_F31D
};

const unsigned SystemZMC_VR128Regs[32] = {
	SystemZ_V0,  SystemZ_V1,  SystemZ_V2,  SystemZ_V3,  SystemZ_V4,
	SystemZ_V5,  SystemZ_V6,  SystemZ_V7,  SystemZ_V8,  SystemZ_V9,
	SystemZ_V10, SystemZ_V11, SystemZ_V12, SystemZ_V13, SystemZ_V14,
	SystemZ_V15, SystemZ_V16, SystemZ_V17, SystemZ_V18, SystemZ_V19,
	SystemZ_V20, SystemZ_V21, SystemZ_V22, SystemZ_V23, SystemZ_V24,
	SystemZ_V25, SystemZ_V26, SystemZ_V27, SystemZ_V28, SystemZ_V29,
	SystemZ_V30, SystemZ_V31
};

const unsigned SystemZMC_AR32Regs[16] = { SystemZ_A0,  SystemZ_A1,  SystemZ_A2,
					  SystemZ_A3,  SystemZ_A4,  SystemZ_A5,
					  SystemZ_A6,  SystemZ_A7,  SystemZ_A8,
					  SystemZ_A9,  SystemZ_A10, SystemZ_A11,
					  SystemZ_A12, SystemZ_A13, SystemZ_A14,
					  SystemZ_A15 };

const unsigned SystemZMC_CR64Regs[16] = { SystemZ_C0,  SystemZ_C1,  SystemZ_C2,
					  SystemZ_C3,  SystemZ_C4,  SystemZ_C5,
					  SystemZ_C6,  SystemZ_C7,  SystemZ_C8,
					  SystemZ_C9,  SystemZ_C10, SystemZ_C11,
					  SystemZ_C12, SystemZ_C13, SystemZ_C14,
					  SystemZ_C15 };

unsigned SystemZMC_getFirstReg(unsigned Reg)
{
	static unsigned Map[NUM_TARGET_REGS];
	static bool Initialized = false;
	if (!Initialized) {
		for (unsigned I = 0; I < 16; ++I) {
			Map[SystemZMC_GR32Regs[I]] = I;
			Map[SystemZMC_GRH32Regs[I]] = I;
			Map[SystemZMC_GR64Regs[I]] = I;
			Map[SystemZMC_GR128Regs[I]] = I;
			Map[SystemZMC_FP128Regs[I]] = I;
			Map[SystemZMC_AR32Regs[I]] = I;
		}
		for (unsigned I = 0; I < 32; ++I) {
			Map[SystemZMC_VR32Regs[I]] = I;
			Map[SystemZMC_VR64Regs[I]] = I;
			Map[SystemZMC_VR128Regs[I]] = I;
		}
	}
	CS_ASSERT((Reg < NUM_TARGET_REGS));
	return Map[Reg];
}

// end namespace

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

//===-- SystemZMCTargetDesc.h - SystemZ target descriptions -----*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_SYSTEMZ_MCTARGETDESC_SYSTEMZMCTARGETDESC_H
#define LLVM_LIB_TARGET_SYSTEMZ_MCTARGETDESC_SYSTEMZMCTARGETDESC_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "../../MCInstPrinter.h"
#include "../../cs_priv.h"
#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

// CS namespace begin: SystemZMC

// Maps of asm register numbers to LLVM register numbers, with 0 indicating
// an invalid register.  In principle we could use 32-bit and 64-bit register
// classes directly, provided that we relegated the GPR allocation order
// in SystemZRegisterInfo.td to an AltOrder and left the default order
// as %r0-%r15.  It seems better to provide the same interface for
// all classes though.
extern const unsigned SystemZMC_GR32Regs[16];

extern const unsigned SystemZMC_GRH32Regs[16];

extern const unsigned SystemZMC_GR64Regs[16];

extern const unsigned SystemZMC_GR128Regs[16];

extern const unsigned SystemZMC_FP32Regs[16];

extern const unsigned SystemZMC_FP64Regs[16];

extern const unsigned SystemZMC_FP128Regs[16];

extern const unsigned SystemZMC_VR32Regs[32];

extern const unsigned SystemZMC_VR64Regs[32];

extern const unsigned SystemZMC_VR128Regs[32];

extern const unsigned SystemZMC_AR32Regs[16];

extern const unsigned SystemZMC_CR64Regs[16];

// Return the 0-based number of the first architectural register that
// contains the given LLVM register.   E.g. R1D -> 1.
unsigned SystemZMC_getFirstReg(unsigned Reg);

// Return the given register as a GR64.
static inline unsigned SystemZMC_getRegAsGR64(unsigned Reg)
{
	return SystemZMC_GR64Regs[SystemZMC_getFirstReg(Reg)];
}

// Return the given register as a low GR32.
static inline unsigned SystemZMC_getRegAsGR32(unsigned Reg)
{
	return SystemZMC_GR32Regs[SystemZMC_getFirstReg(Reg)];
}

// Return the given register as a high GR32.
static inline unsigned SystemZMC_getRegAsGRH32(unsigned Reg)
{
	return SystemZMC_GRH32Regs[SystemZMC_getFirstReg(Reg)];
}

// Return the given register as a VR128.
static inline unsigned SystemZMC_getRegAsVR128(unsigned Reg)
{
	return SystemZMC_VR128Regs[SystemZMC_getFirstReg(Reg)];
}

// CS namespace end: SystemZMC

// end namespace SystemZMC

// Defines symbolic names for SystemZ registers.
// This defines a mapping from register name to register number.
#define GET_REGINFO_ENUM
#include "SystemZGenRegisterInfo.inc"

// Defines symbolic names for the SystemZ instructions.
#define GET_INSTRINFO_ENUM
#define GET_INSTRINFO_MC_HELPER_DECLS
#include "SystemZGenInstrInfo.inc"

#define GET_SUBTARGETINFO_ENUM
#include "SystemZGenSubtargetInfo.inc"

#endif

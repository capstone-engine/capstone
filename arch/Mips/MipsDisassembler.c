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

//===- MipsDisassembler.cpp - Disassembler for Mips -----------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is part of the Mips Disassembler.
//
//===----------------------------------------------------------------------===//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "../../MCInst.h"
#include "../../MathExtras.h"
#include "../../MCInstPrinter.h"
#include "../../MCDisassembler.h"
#include "../../MCRegisterInfo.h"
#include "../../MCFixedLenDisassembler.h"
#include "../../cs_priv.h"
#include "../../utils.h"
#define GET_SUBTARGETINFO_ENUM
#include "MipsGenSubtargetInfo.inc"

#define GET_INSTRINFO_ENUM
#include "MipsGenInstrInfo.inc"

#define GET_REGINFO_ENUM
#include "MipsGenRegisterInfo.inc"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

#define DEBUG_TYPE "mips-disassembler"

bool Mips_getFeatureBits(unsigned int mode, unsigned int feature)
{
	switch (feature) {
	case Mips_FeatureGP64Bit:
		return mode &
		       (CS_MODE_MIPS3 | CS_MODE_MIPS4 | CS_MODE_MIPS5 |
			CS_MODE_MIPS64 | CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 |
			CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 | CS_MODE_OCTEON |
			CS_MODE_OCTEONP);
	case Mips_FeatureFP64Bit:
		return mode &
		       (CS_MODE_MIPS32R6 | CS_MODE_MIPS3 | CS_MODE_MIPS4 |
			CS_MODE_MIPS5 | CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 |
			CS_MODE_MIPS32R5 | CS_MODE_MIPS64 | CS_MODE_MIPS64R2 |
			CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 |
			CS_MODE_OCTEON | CS_MODE_OCTEONP);
	case Mips_FeatureNaN2008:
		return mode & (CS_MODE_MIPS32R6 | CS_MODE_MIPS64R6);
	case Mips_FeatureAbs2008:
		return mode & (CS_MODE_MIPS32R6 | CS_MODE_MIPS64R6);
	case Mips_FeatureMips1:
		return mode &
		       (CS_MODE_MIPS1 | CS_MODE_MIPS2 | CS_MODE_MIPS32 |
			CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 | CS_MODE_MIPS32R5 |
			CS_MODE_MIPS32R6 | CS_MODE_MIPS3 | CS_MODE_MIPS4 |
			CS_MODE_MIPS5 | CS_MODE_MIPS64 | CS_MODE_MIPS64R2 |
			CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 |
			CS_MODE_OCTEON | CS_MODE_OCTEONP);
	case Mips_FeatureMips2:
		return mode &
		       (CS_MODE_MIPS2 | CS_MODE_MIPS32 | CS_MODE_MIPS32R2 |
			CS_MODE_MIPS32R3 | CS_MODE_MIPS32R5 | CS_MODE_MIPS32R6 |
			CS_MODE_MIPS3 | CS_MODE_MIPS4 | CS_MODE_MIPS5 |
			CS_MODE_MIPS64 | CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 |
			CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 | CS_MODE_OCTEON |
			CS_MODE_OCTEONP);
	case Mips_FeatureMips3_32:
		return mode &
		       (CS_MODE_MIPS32 | CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 |
			CS_MODE_MIPS32R5 | CS_MODE_MIPS32R6 | CS_MODE_MIPS3 |
			CS_MODE_MIPS4 | CS_MODE_MIPS5 | CS_MODE_MIPS64 |
			CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 |
			CS_MODE_MIPS64R6 | CS_MODE_OCTEON | CS_MODE_OCTEONP);
	case Mips_FeatureMips3_32r2:
		return mode &
		       (CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 | CS_MODE_MIPS32R5 |
			CS_MODE_MIPS32R6 | CS_MODE_MIPS3 | CS_MODE_MIPS4 |
			CS_MODE_MIPS5 | CS_MODE_MIPS64 | CS_MODE_MIPS64R2 |
			CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 |
			CS_MODE_OCTEON | CS_MODE_OCTEONP);
	case Mips_FeatureMips3:
		return mode &
		       (CS_MODE_MIPS3 | CS_MODE_MIPS4 | CS_MODE_MIPS5 |
			CS_MODE_MIPS64 | CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 |
			CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 | CS_MODE_OCTEON |
			CS_MODE_OCTEONP);
	case Mips_FeatureMips4_32:
		return mode &
		       (CS_MODE_MIPS32 | CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 |
			CS_MODE_MIPS32R5 | CS_MODE_MIPS32R6 | CS_MODE_MIPS4 |
			CS_MODE_MIPS5 | CS_MODE_MIPS64 | CS_MODE_MIPS64R2 |
			CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 |
			CS_MODE_OCTEON | CS_MODE_OCTEONP);
	case Mips_FeatureMips4_32r2:
		return mode &
		       (CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 | CS_MODE_MIPS32R5 |
			CS_MODE_MIPS32R6 | CS_MODE_MIPS4 | CS_MODE_MIPS5 |
			CS_MODE_MIPS64 | CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 |
			CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 | CS_MODE_OCTEON |
			CS_MODE_OCTEONP);
	case Mips_FeatureMips4:
		return mode &
		       (CS_MODE_MIPS4 | CS_MODE_MIPS5 | CS_MODE_MIPS64 |
			CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 |
			CS_MODE_MIPS64R6 | CS_MODE_OCTEON | CS_MODE_OCTEONP);
	case Mips_FeatureMips5_32r2:
		return mode &
		       (CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 | CS_MODE_MIPS32R5 |
			CS_MODE_MIPS32R6 | CS_MODE_MIPS5 | CS_MODE_MIPS64 |
			CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 |
			CS_MODE_MIPS64R6 | CS_MODE_OCTEON | CS_MODE_OCTEONP);
	case Mips_FeatureMips5:
		return mode &
		       (CS_MODE_MIPS5 | CS_MODE_MIPS64 | CS_MODE_MIPS64R2 |
			CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 |
			CS_MODE_OCTEON | CS_MODE_OCTEONP);
	case Mips_FeatureMips32:
		return mode &
		       (CS_MODE_MIPS32 | CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 |
			CS_MODE_MIPS32R5 | CS_MODE_MIPS32R6 | CS_MODE_MIPS64 |
			CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 |
			CS_MODE_MIPS64R6 | CS_MODE_OCTEON | CS_MODE_OCTEONP);
	case Mips_FeatureMips32r2:
		return mode &
		       (CS_MODE_MIPS32R2 | CS_MODE_MIPS32R3 | CS_MODE_MIPS32R5 |
			CS_MODE_MIPS32R6 | CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 |
			CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 | CS_MODE_OCTEON |
			CS_MODE_OCTEONP);
	case Mips_FeatureMips32r3:
		return mode &
		       (CS_MODE_MIPS32R3 | CS_MODE_MIPS32R5 | CS_MODE_MIPS32R6 |
			CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6);
	case Mips_FeatureMips32r5:
		return mode & (CS_MODE_MIPS32R5 | CS_MODE_MIPS32R6 |
			       CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6);
	case Mips_FeatureMips32r6:
		return mode & (CS_MODE_MIPS32R6 | CS_MODE_MIPS64R6);
	case Mips_FeatureMips64:
		return mode &
		       (CS_MODE_MIPS64 | CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 |
			CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6 | CS_MODE_OCTEON |
			CS_MODE_OCTEONP);
	case Mips_FeatureMips64r2:
		return mode &
		       (CS_MODE_MIPS64R2 | CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 |
			CS_MODE_MIPS64R6 | CS_MODE_OCTEON | CS_MODE_OCTEONP);
	case Mips_FeatureMips64r3:
		return mode &
		       (CS_MODE_MIPS64R3 | CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6);
	case Mips_FeatureMips64r5:
		return mode & (CS_MODE_MIPS64R5 | CS_MODE_MIPS64R6);
	case Mips_FeatureMips64r6:
		return mode & CS_MODE_MIPS64R6;
	case Mips_FeatureMips16:
		return mode & CS_MODE_MIPS16;
	case Mips_FeatureMicroMips:
		return mode & CS_MODE_MICRO;
	case Mips_FeatureNanoMips:
		return mode & (CS_MODE_NANOMIPS | CS_MODE_NMS1 | CS_MODE_I7200);
	case Mips_FeatureNMS1:
		return mode & CS_MODE_NMS1;
	case Mips_FeatureTLB:
		return mode & CS_MODE_I7200;
	case Mips_FeatureCnMips:
		return mode & (CS_MODE_OCTEON | CS_MODE_OCTEONP);
	case Mips_FeatureCnMipsP:
		return mode & CS_MODE_OCTEONP;
	case Mips_FeaturePTR64Bit:
		return mode & CS_MODE_MIPS_PTR64;
	case Mips_FeatureSoftFloat:
		return mode & CS_MODE_MIPS_NOFLOAT;
	case Mips_FeatureI7200:
		return mode & CS_MODE_I7200;
	// optional features always enabled
	case Mips_FeatureDSP: // Mips DSP ASE
		return true;
	case Mips_FeatureDSPR2: // Mips DSP-R2 ASE
		return true;
	case Mips_FeatureDSPR3: // Mips DSP-R3 ASE
		return true;
	case Mips_FeatureMips3D: // Mips 3D ASE
		return true;
	case Mips_FeatureMSA: // Mips MSA ASE
		return true;
	case Mips_FeatureEVA: { // Mips EVA ASE
		if (mode & CS_MODE_NANOMIPS) {
			return mode & CS_MODE_I7200;
		}
		return true;
	}
	case Mips_FeatureCRC: // Mips R6 CRC ASE
		return true;
	case Mips_FeatureVirt: // Mips Virtualization ASE
		return true;
	case Mips_FeatureGINV: // Mips Global Invalidate ASE
		return true;
	case Mips_FeatureMT: { // Mips MT ASE
		if (mode & CS_MODE_NANOMIPS) {
			return mode & CS_MODE_I7200;
		}
		return true;
	}
	default:
		return false;
	}
}

static DecodeStatus getInstruction(MCInst *Instr, uint64_t *Size,
				   const uint8_t *Bytes, size_t BytesLen,
				   uint64_t Address, SStream *CStream);

// end anonymous namespace

// Forward declare these because the autogenerated code will reference them.
// Definitions are further down.
static DecodeStatus DecodeGPR64RegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     const void *Decoder);

static DecodeStatus DecodeCPU16RegsRegisterClass(MCInst *Inst, unsigned RegNo,
						 uint64_t Address,
						 const void *Decoder);

static DecodeStatus DecodeGPRMM16RegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder);

static DecodeStatus DecodeGPRMM16ZeroRegisterClass(MCInst *Inst, unsigned RegNo,
						   uint64_t Address,
						   const void *Decoder);

static DecodeStatus DecodeGPRMM16MovePRegisterClass(MCInst *Inst,
						    unsigned RegNo,
						    uint64_t Address,
						    const void *Decoder);

static DecodeStatus DecodeGPR32RegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     const void *Decoder);

static DecodeStatus DecodeGPRNM3RegisterClass(MCInst *Inst, unsigned RegNo,
					      uint64_t Address,
					      const void *Decoder);

static DecodeStatus DecodeGPRNM4RegisterClass(MCInst *Inst, unsigned RegNo,
					      uint64_t Address,
					      const void *Decoder);

static DecodeStatus DecodeGPRNMRARegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder);

static DecodeStatus DecodeGPRNM3ZRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder);

static DecodeStatus DecodeGPRNM4ZRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder);

static DecodeStatus DecodeGPRNM32NZRegisterClass(MCInst *Inst, unsigned RegNo,
						 uint64_t Address,
						 const void *Decoder);

static DecodeStatus DecodeGPRNM32RegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder);

static DecodeStatus DecodeGPRNM2R1RegisterClass(MCInst *Inst, unsigned RegNo,
						uint64_t Address,
						const void *Decoder);

static DecodeStatus DecodeGPRNM1R1RegisterClass(MCInst *Inst, unsigned RegNo,
						uint64_t Address,
						const void *Decoder);

static DecodeStatus DecodePtrRegisterClass(MCInst *Inst, uint32_t Insn,
					   uint64_t Address,
					   const void *Decoder);

static DecodeStatus DecodeDSPRRegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    const void *Decoder);

static DecodeStatus DecodeFGR64RegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     const void *Decoder);

static DecodeStatus DecodeFGR32RegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     const void *Decoder);

static DecodeStatus DecodeCCRRegisterClass(MCInst *Inst, unsigned RegNo,
					   uint64_t Address,
					   const void *Decoder);

static DecodeStatus DecodeFCCRegisterClass(MCInst *Inst, unsigned RegNo,
					   uint64_t Address,
					   const void *Decoder);

static DecodeStatus DecodeFGRCCRegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     const void *Decoder);

static DecodeStatus DecodeHWRegsRegisterClass(MCInst *Inst, uint32_t Insn,
					      uint64_t Address,
					      const void *Decoder);

static DecodeStatus DecodeAFGR64RegisterClass(MCInst *Inst, unsigned RegNo,
					      uint64_t Address,
					      const void *Decoder);

static DecodeStatus DecodeACC64DSPRegisterClass(MCInst *Inst, unsigned RegNo,
						uint64_t Address,
						const void *Decoder);

static DecodeStatus DecodeHI32DSPRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder);

static DecodeStatus DecodeLO32DSPRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder);

static DecodeStatus DecodeMSA128BRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder);

static DecodeStatus DecodeMSA128HRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder);

static DecodeStatus DecodeMSA128WRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder);

static DecodeStatus DecodeMSA128DRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder);

static DecodeStatus DecodeMSACtrlRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder);

static DecodeStatus DecodeCOP0RegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    const void *Decoder);

static DecodeStatus DecodeCOP0SelRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder);

static DecodeStatus DecodeCOP2RegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    const void *Decoder);

static DecodeStatus DecodeBranchTarget(MCInst *Inst, unsigned Offset,
				       uint64_t Address, const void *Decoder);

static DecodeStatus DecodeBranchTarget1SImm16(MCInst *Inst, unsigned Offset,
					      uint64_t Address,
					      const void *Decoder);

static DecodeStatus DecodeJumpTarget(MCInst *Inst, uint32_t Insn,
				     uint64_t Address, const void *Decoder);

static DecodeStatus DecodeBranchTarget21(MCInst *Inst, unsigned Offset,
					 uint64_t Address, const void *Decoder);

static DecodeStatus DecodeBranchTarget21MM(MCInst *Inst, unsigned Offset,
					   uint64_t Address,
					   const void *Decoder);

static DecodeStatus DecodeBranchTarget26(MCInst *Inst, unsigned Offset,
					 uint64_t Address, const void *Decoder);

// DecodeBranchTarget7MM - Decode microMIPS branch offset, which is
// shifted left by 1 bit.
static DecodeStatus DecodeBranchTarget7MM(MCInst *Inst, unsigned Offset,
					  uint64_t Address,
					  const void *Decoder);

// DecodeBranchTarget10MM - Decode microMIPS branch offset, which is
// shifted left by 1 bit.
static DecodeStatus DecodeBranchTarget10MM(MCInst *Inst, unsigned Offset,
					   uint64_t Address,
					   const void *Decoder);

// DecodeBranchTargetMM - Decode microMIPS branch offset, which is
// shifted left by 1 bit.
static DecodeStatus DecodeBranchTargetMM(MCInst *Inst, unsigned Offset,
					 uint64_t Address, const void *Decoder);

// DecodeBranchTarget26MM - Decode microMIPS branch offset, which is
// shifted left by 1 bit.
static DecodeStatus DecodeBranchTarget26MM(MCInst *Inst, unsigned Offset,
					   uint64_t Address,
					   const void *Decoder);

// DecodeBranchTargetMM - Decode nanoMIPS branch offset, which is
// shifted left by 1 bit.
#define DECLARE_DecodeBranchTargetNM(bits) \
	static DecodeStatus CONCAT(DecodeBranchTargetNM, bits)( \
		MCInst * Inst, unsigned Offset, uint64_t Address, \
		const void *Decoder);
DECLARE_DecodeBranchTargetNM(10);
DECLARE_DecodeBranchTargetNM(7);
DECLARE_DecodeBranchTargetNM(21);
DECLARE_DecodeBranchTargetNM(25);
DECLARE_DecodeBranchTargetNM(14);
DECLARE_DecodeBranchTargetNM(11);
DECLARE_DecodeBranchTargetNM(5);

// DecodeJumpTargetMM - Decode microMIPS jump target, which is
// shifted left by 1 bit.
static DecodeStatus DecodeJumpTargetMM(MCInst *Inst, uint32_t Insn,
				       uint64_t Address, const void *Decoder);

// DecodeJumpTargetXMM - Decode microMIPS jump and link exchange target,
// which is shifted left by 2 bit.
static DecodeStatus DecodeJumpTargetXMM(MCInst *Inst, uint32_t Insn,
					uint64_t Address, const void *Decoder);

static DecodeStatus DecodeMem(MCInst *Inst, uint32_t Insn, uint64_t Address,
			      const void *Decoder);

#define DECLARE_DecodeMemNM(Offbits, isSigned, rt) \
	static DecodeStatus CONCAT(DecodeMemNM, \
				   CONCAT(Offbits, CONCAT(isSigned, rt)))( \
		MCInst * Inst, uint32_t Insn, uint64_t Address, \
		const void *Decoder);
DECLARE_DecodeMemNM(6, 0, Mips_GPRNM3RegClassID);
DECLARE_DecodeMemNM(7, 0, Mips_GPRNMSPRegClassID);
DECLARE_DecodeMemNM(9, 0, Mips_GPRNMGPRegClassID);
DECLARE_DecodeMemNM(2, 0, Mips_GPRNM3RegClassID);
DECLARE_DecodeMemNM(3, 0, Mips_GPRNM3RegClassID);
DECLARE_DecodeMemNM(21, 0, Mips_GPRNMGPRegClassID);
DECLARE_DecodeMemNM(18, 0, Mips_GPRNMGPRegClassID);
DECLARE_DecodeMemNM(12, 0, Mips_GPRNM32RegClassID);
DECLARE_DecodeMemNM(9, 1, Mips_GPRNM32RegClassID);

static DecodeStatus DecodeMemZeroNM(MCInst *Inst, uint32_t Insn,
				    uint64_t Address, const void *Decoder);

#define DECLARE_DecodeMemNMRX(rt) \
	static DecodeStatus CONCAT(DecodeMemNMRX, \
				   rt)(MCInst * Inst, uint32_t Insn, \
				       uint64_t Address, const void *Decoder);
DECLARE_DecodeMemNMRX(Mips_GPRNM3RegClassID);
DECLARE_DecodeMemNMRX(Mips_GPRNM32RegClassID);

static DecodeStatus DecodeMemNM4x4(MCInst *Inst, uint32_t Insn,
				   uint64_t Address, const void *Decoder);

static DecodeStatus DecodeMemEVA(MCInst *Inst, uint32_t Insn, uint64_t Address,
				 const void *Decoder);

static DecodeStatus DecodeLoadByte15(MCInst *Inst, uint32_t Insn,
				     uint64_t Address, const void *Decoder);

static DecodeStatus DecodeCacheOp(MCInst *Inst, uint32_t Insn, uint64_t Address,
				  const void *Decoder);

static DecodeStatus DecodeCacheeOp_CacheOpR6(MCInst *Inst, uint32_t Insn,
					     uint64_t Address,
					     const void *Decoder);

static DecodeStatus DecodeCacheOpMM(MCInst *Inst, uint32_t Insn,
				    uint64_t Address, const void *Decoder);

static DecodeStatus DecodePrefeOpMM(MCInst *Inst, uint32_t Insn,
				    uint64_t Address, const void *Decoder);

static DecodeStatus DecodeSyncI(MCInst *Inst, uint32_t Insn, uint64_t Address,
				const void *Decoder);

static DecodeStatus DecodeSyncI_MM(MCInst *Inst, uint32_t Insn,
				   uint64_t Address, const void *Decoder);

static DecodeStatus DecodeSynciR6(MCInst *Inst, uint32_t Insn, uint64_t Address,
				  const void *Decoder);

static DecodeStatus DecodeMSA128Mem(MCInst *Inst, uint32_t Insn,
				    uint64_t Address, const void *Decoder);

static DecodeStatus DecodeMemMMImm4(MCInst *Inst, uint32_t Insn,
				    uint64_t Address, const void *Decoder);

static DecodeStatus DecodeMemMMSPImm5Lsl2(MCInst *Inst, uint32_t Insn,
					  uint64_t Address,
					  const void *Decoder);

static DecodeStatus DecodeMemMMGPImm7Lsl2(MCInst *Inst, uint32_t Insn,
					  uint64_t Address,
					  const void *Decoder);

static DecodeStatus DecodeMemMMReglistImm4Lsl2(MCInst *Inst, uint32_t Insn,
					       uint64_t Address,
					       const void *Decoder);

static DecodeStatus DecodeMemMMImm9(MCInst *Inst, uint32_t Insn,
				    uint64_t Address, const void *Decoder);

static DecodeStatus DecodeMemMMImm12(MCInst *Inst, uint32_t Insn,
				     uint64_t Address, const void *Decoder);

static DecodeStatus DecodeMemMMImm16(MCInst *Inst, uint32_t Insn,
				     uint64_t Address, const void *Decoder);

static DecodeStatus DecodeFMem(MCInst *Inst, uint32_t Insn, uint64_t Address,
			       const void *Decoder);

static DecodeStatus DecodeFMemMMR2(MCInst *Inst, uint32_t Insn,
				   uint64_t Address, const void *Decoder);

static DecodeStatus DecodeFMem2(MCInst *Inst, uint32_t Insn, uint64_t Address,
				const void *Decoder);

static DecodeStatus DecodeFMem3(MCInst *Inst, uint32_t Insn, uint64_t Address,
				const void *Decoder);

static DecodeStatus DecodeFMemCop2R6(MCInst *Inst, uint32_t Insn,
				     uint64_t Address, const void *Decoder);

static DecodeStatus DecodeFMemCop2MMR6(MCInst *Inst, uint32_t Insn,
				       uint64_t Address, const void *Decoder);

static DecodeStatus DecodeSpecial3LlSc(MCInst *Inst, uint32_t Insn,
				       uint64_t Address, const void *Decoder);

static DecodeStatus DecodeAddiur2Simm7(MCInst *Inst, unsigned Value,
				       uint64_t Address, const void *Decoder);

static DecodeStatus DecodeLi16Imm(MCInst *Inst, unsigned Value,
				  uint64_t Address, const void *Decoder);

static DecodeStatus DecodePOOL16BEncodedField(MCInst *Inst, unsigned Value,
					      uint64_t Address,
					      const void *Decoder);

#define DECLARE_DecodeUImmWithOffsetAndScale(Bits, Offset, Scale) \
	static DecodeStatus CONCAT(DecodeUImmWithOffsetAndScale, \
				   CONCAT(Bits, CONCAT(Offset, Scale)))( \
		MCInst * Inst, unsigned Value, uint64_t Address, \
		const void *Decoder);
DECLARE_DecodeUImmWithOffsetAndScale(5, 0, 4);
DECLARE_DecodeUImmWithOffsetAndScale(6, 0, 4);
DECLARE_DecodeUImmWithOffsetAndScale(2, 1, 1);
DECLARE_DecodeUImmWithOffsetAndScale(5, 1, 1);
DECLARE_DecodeUImmWithOffsetAndScale(8, 0, 1);
DECLARE_DecodeUImmWithOffsetAndScale(18, 0, 1);
DECLARE_DecodeUImmWithOffsetAndScale(21, 0, 1);

#define DEFINE_DecodeUImmWithOffset(Bits, Offset) \
	static DecodeStatus CONCAT(DecodeUImmWithOffset, \
				   CONCAT(Bits, Offset))(MCInst * Inst, \
							 unsigned Value, \
							 uint64_t Address, \
							 const void *Decoder) \
	{ \
		return CONCAT(DecodeUImmWithOffsetAndScale, \
			      CONCAT(Bits, CONCAT(Offset, 1)))( \
			Inst, Value, Address, Decoder); \
	}
DEFINE_DecodeUImmWithOffset(5, 1);
DEFINE_DecodeUImmWithOffset(2, 1);

#define DECLARE_DecodeSImmWithOffsetAndScale(Bits, Offset, ScaleBy) \
	static DecodeStatus CONCAT(DecodeSImmWithOffsetAndScale, \
				   CONCAT(Bits, CONCAT(Offset, ScaleBy)))( \
		MCInst * Inst, unsigned Value, uint64_t Address, \
		const void *Decoder);

#define DECLARE_DecodeSImmWithOffsetAndScale_2(Bits, Offset) \
	DECLARE_DecodeSImmWithOffsetAndScale(Bits, Offset, 1)
#define DECLARE_DecodeSImmWithOffsetAndScale_3(Bits) \
	DECLARE_DecodeSImmWithOffsetAndScale(Bits, 0, 1)

DECLARE_DecodeSImmWithOffsetAndScale_3(16);
DECLARE_DecodeSImmWithOffsetAndScale_3(10);
DECLARE_DecodeSImmWithOffsetAndScale_3(4);
DECLARE_DecodeSImmWithOffsetAndScale_3(6);
DECLARE_DecodeSImmWithOffsetAndScale_3(32);

static DecodeStatus DecodeInsSize(MCInst *Inst, uint32_t Insn, uint64_t Address,
				  const void *Decoder);

static DecodeStatus DecodeImmM1To126(MCInst *Inst, unsigned Value,
				     uint64_t Address, const void *Decoder);

static DecodeStatus DecodeUImm4Mask(MCInst *Inst, unsigned Value,
				    uint64_t Address, const void *Decoder);

static DecodeStatus DecodeUImm3Shift(MCInst *Inst, unsigned Value,
				     uint64_t Address, const void *Decoder);

static DecodeStatus DecodeNMRegListOperand(MCInst *Inst, uint32_t Insn,
					   uint64_t Address,
					   const void *Decoder);

static DecodeStatus DecodeNMRegList16Operand(MCInst *Inst, uint32_t Insn,
					     uint64_t Address,
					     const void *Decoder);

static DecodeStatus DecodeNegImm12(MCInst *Inst, uint32_t Insn,
				   uint64_t Address, const void *Decoder);

#define DECLARE_DecodeSImmWithReg(Bits, Offset, Scale, RegNum) \
	static DecodeStatus CONCAT( \
		DecodeSImmWithReg, \
		CONCAT(Bits, CONCAT(Offset, CONCAT(Scale, RegNum))))( \
		MCInst * Inst, unsigned Value, uint64_t Address, \
		const void *Decoder);
DECLARE_DecodeSImmWithReg(32, 0, 1, Mips_GP_NM);

#define DECLARE_DecodeUImmWithReg(Bits, Offset, Scale, RegNum) \
	static DecodeStatus CONCAT( \
		DecodeUImmWithReg, \
		CONCAT(Bits, CONCAT(Offset, CONCAT(Scale, RegNum))))( \
		MCInst * Inst, unsigned Value, uint64_t Address, \
		const void *Decoder);
DECLARE_DecodeUImmWithReg(8, 0, 1, Mips_SP_NM);
DECLARE_DecodeUImmWithReg(21, 0, 1, Mips_GP_NM);
DECLARE_DecodeUImmWithReg(18, 0, 1, Mips_GP_NM);

static DecodeStatus DecodeSImm32s12(MCInst *Inst, uint32_t Insn,
				    uint64_t Address, const void *Decoder);

#define DECLARE_DecodeAddressPCRelNM(Bits) \
	static DecodeStatus CONCAT(DecodeAddressPCRelNM, Bits)( \
		MCInst * Inst, uint32_t Insn, uint64_t Address, \
		const void *Decoder);
DECLARE_DecodeAddressPCRelNM(22);
DECLARE_DecodeAddressPCRelNM(32);

static DecodeStatus DecodeBranchConflictNM(MCInst *Inst, uint32_t Insn,
					   uint64_t Address,
					   const void *Decoder);

static DecodeStatus DecodeSimm19Lsl2(MCInst *Inst, uint32_t Insn,
				     uint64_t Address, const void *Decoder);

static DecodeStatus DecodeSimm18Lsl3(MCInst *Inst, uint32_t Insn,
				     uint64_t Address, const void *Decoder);

static DecodeStatus DecodeSimm9SP(MCInst *Inst, uint32_t Insn, uint64_t Address,
				  const void *Decoder);

static DecodeStatus DecodeANDI16Imm(MCInst *Inst, uint32_t Insn,
				    uint64_t Address, const void *Decoder);

static DecodeStatus DecodeSimm23Lsl2(MCInst *Inst, uint32_t Insn,
				     uint64_t Address, const void *Decoder);

/// INSVE_[BHWD] have an implicit operand that the generated decoder doesn't
/// handle.
static DecodeStatus DecodeINSVE_DF(MCInst *MI, uint32_t insn, uint64_t Address,
				   const void *Decoder);

/*
static DecodeStatus DecodeDAHIDATIMMR6(MCInst *MI, uint32_t insn,
					  uint64_t Address, const void *Decoder);
*/

static DecodeStatus DecodeDAHIDATI(MCInst *MI, uint32_t insn, uint64_t Address,
				   const void *Decoder);

static DecodeStatus DecodeAddiGroupBranch(MCInst *MI, uint32_t insn,
					  uint64_t Address,
					  const void *Decoder);

static DecodeStatus DecodePOP35GroupBranchMMR6(MCInst *MI, uint32_t insn,
					       uint64_t Address,
					       const void *Decoder);

static DecodeStatus DecodeDaddiGroupBranch(MCInst *MI, uint32_t insn,
					   uint64_t Address,
					   const void *Decoder);

static DecodeStatus DecodePOP37GroupBranchMMR6(MCInst *MI, uint32_t insn,
					       uint64_t Address,
					       const void *Decoder);

static DecodeStatus DecodePOP65GroupBranchMMR6(MCInst *MI, uint32_t insn,
					       uint64_t Address,
					       const void *Decoder);

static DecodeStatus DecodePOP75GroupBranchMMR6(MCInst *MI, uint32_t insn,
					       uint64_t Address,
					       const void *Decoder);

static DecodeStatus DecodeBlezlGroupBranch(MCInst *MI, uint32_t insn,
					   uint64_t Address,
					   const void *Decoder);

static DecodeStatus DecodeBgtzlGroupBranch(MCInst *MI, uint32_t insn,
					   uint64_t Address,
					   const void *Decoder);

static DecodeStatus DecodeBgtzGroupBranch(MCInst *MI, uint32_t insn,
					  uint64_t Address,
					  const void *Decoder);

static DecodeStatus DecodeBlezGroupBranch(MCInst *MI, uint32_t insn,
					  uint64_t Address,
					  const void *Decoder);

static DecodeStatus DecodeBgtzGroupBranchMMR6(MCInst *MI, uint32_t insn,
					      uint64_t Address,
					      const void *Decoder);

static DecodeStatus DecodeBlezGroupBranchMMR6(MCInst *MI, uint32_t insn,
					      uint64_t Address,
					      const void *Decoder);

static DecodeStatus DecodeDINS(MCInst *MI, uint32_t Insn, uint64_t Address,
			       const void *Decoder);

static DecodeStatus DecodeDEXT(MCInst *MI, uint32_t Insn, uint64_t Address,
			       const void *Decoder);

static DecodeStatus DecodeCRC(MCInst *MI, uint32_t Insn, uint64_t Address,
			      const void *Decoder);

static DecodeStatus DecodeRegListOperand(MCInst *Inst, uint32_t Insn,
					 uint64_t Address, const void *Decoder);

static DecodeStatus DecodeRegListOperand16(MCInst *Inst, uint32_t Insn,
					   uint64_t Address,
					   const void *Decoder);

static DecodeStatus DecodeMovePRegPair(MCInst *Inst, unsigned RegPair,
				       uint64_t Address, const void *Decoder);

static DecodeStatus DecodeMovePOperands(MCInst *Inst, uint32_t Insn,
					uint64_t Address, const void *Decoder);

static DecodeStatus DecodeFIXMEInstruction(MCInst *Inst, uint32_t Insn,
					   uint64_t Address,
					   const void *Decoder);

#include "MipsGenDisassemblerTables.inc"

static unsigned getReg(const MCInst *Inst, unsigned RC, unsigned RegNo)
{
	const MCRegisterClass *c = MCRegisterInfo_getRegClass(Inst->MRI, RC);
	return MCRegisterClass_getRegister(c, RegNo);
}

typedef DecodeStatus (*DecodeFN)(MCInst *Inst, uint32_t Insn, uint64_t Address,
				 const void *Decoder);

static DecodeStatus DecodeINSVE_DF(MCInst *MI, uint32_t insn, uint64_t Address,
				   const void *Decoder)
{
	// The size of the n field depends on the element size
	// The register class also depends on this.
	uint32_t tmp = fieldFromInstruction_4(insn, 17, 5);
	unsigned NSize = 0;
	DecodeFN RegDecoder = NULL;
	if ((tmp & 0x18) == 0x00) { // INSVE_B
		NSize = 4;
		RegDecoder = DecodeMSA128BRegisterClass;
	} else if ((tmp & 0x1c) == 0x10) { // INSVE_H
		NSize = 3;
		RegDecoder = DecodeMSA128HRegisterClass;
	} else if ((tmp & 0x1e) == 0x18) { // INSVE_W
		NSize = 2;
		RegDecoder = DecodeMSA128WRegisterClass;
	} else if ((tmp & 0x1f) == 0x1c) { // INSVE_D
		NSize = 1;
		RegDecoder = DecodeMSA128DRegisterClass;
	} else {
		CS_ASSERT_RET_VAL(0 && "Invalid encoding", MCDisassembler_Fail);
		return MCDisassembler_Fail;
	}

	// $wd
	tmp = fieldFromInstruction_4(insn, 6, 5);
	if (RegDecoder(MI, tmp, Address, Decoder) == MCDisassembler_Fail)
		return MCDisassembler_Fail;
	// $wd_in
	if (RegDecoder(MI, tmp, Address, Decoder) == MCDisassembler_Fail)
		return MCDisassembler_Fail;
	// $n
	tmp = fieldFromInstruction_4(insn, 16, NSize);
	MCOperand_CreateImm0(MI, (tmp));
	// $ws
	tmp = fieldFromInstruction_4(insn, 11, 5);
	if (RegDecoder(MI, tmp, Address, Decoder) == MCDisassembler_Fail)
		return MCDisassembler_Fail;
	// $n2
	MCOperand_CreateImm0(MI, (0));

	return MCDisassembler_Success;
}

/*
static DecodeStatus DecodeDAHIDATIMMR6(MCInst *MI, uint32_t insn,
                                      uint64_t Address, const void *Decoder)
{
       uint32_t Rs = fieldFromInstruction_4(insn, 16, 5);
       uint32_t Imm = fieldFromInstruction_4(insn, 0, 16);
       MCOperand_CreateReg0(MI, (getReg(MI, Mips_GPR64RegClassID, Rs)));
       MCOperand_CreateReg0(MI, (getReg(MI, Mips_GPR64RegClassID, Rs)));
       MCOperand_CreateImm0(MI, (Imm));

       return MCDisassembler_Success;
}
*/

static DecodeStatus DecodeDAHIDATI(MCInst *MI, uint32_t insn, uint64_t Address,
				   const void *Decoder)
{
	uint32_t Rs = fieldFromInstruction_4(insn, 21, 5);
	uint32_t Imm = fieldFromInstruction_4(insn, 0, 16);
	MCOperand_CreateReg0(MI, (getReg(MI, Mips_GPR64RegClassID, Rs)));
	MCOperand_CreateReg0(MI, (getReg(MI, Mips_GPR64RegClassID, Rs)));
	MCOperand_CreateImm0(MI, (Imm));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeAddiGroupBranch(MCInst *MI, uint32_t insn,
					  uint64_t Address, const void *Decoder)
{
	// If we are called then we can assume that MIPS32r6/MIPS64r6 is enabled
	// (otherwise we would have matched the ADDI instruction from the earlier
	// ISA's instead).
	//
	// We have:
	//    0b001000 sssss ttttt iiiiiiiiiiiiiiii
	//      BOVC if rs >= rt
	//      BEQZALC if rs == 0 && rt != 0
	//      BEQC if rs < rt && rs != 0

	uint32_t Rs = fieldFromInstruction_4(insn, 21, 5);
	uint32_t Rt = fieldFromInstruction_4(insn, 16, 5);
	int64_t Imm =
		SignExtend64(fieldFromInstruction_4(insn, 0, 16), 16) * 4 + 4;
	bool HasRs = false;

	if (Rs >= Rt) {
		MCInst_setOpcode(MI, (Mips_BOVC));
		HasRs = true;
	} else if (Rs != 0 && Rs < Rt) {
		MCInst_setOpcode(MI, (Mips_BEQC));
		HasRs = true;
	} else
		MCInst_setOpcode(MI, (Mips_BEQZALC));

	if (HasRs)
		MCOperand_CreateReg0(MI,
				     (getReg(MI, Mips_GPR32RegClassID, Rs)));

	MCOperand_CreateReg0(MI, (getReg(MI, Mips_GPR32RegClassID, Rt)));
	MCOperand_CreateImm0(MI, (Imm));

	return MCDisassembler_Success;
}

static DecodeStatus DecodePOP35GroupBranchMMR6(MCInst *MI, uint32_t insn,
					       uint64_t Address,
					       const void *Decoder)
{
	uint32_t Rt = fieldFromInstruction_4(insn, 21, 5);
	uint32_t Rs = fieldFromInstruction_4(insn, 16, 5);
	int64_t Imm = 0;

	if (Rs >= Rt) {
		MCInst_setOpcode(MI, (Mips_BOVC_MMR6));
		MCOperand_CreateReg0(MI,
				     (getReg(MI, Mips_GPR32RegClassID, Rt)));
		MCOperand_CreateReg0(MI,
				     (getReg(MI, Mips_GPR32RegClassID, Rs)));
		Imm = SignExtend64(fieldFromInstruction_4(insn, 0, 16), 16) *
			      2 +
		      4;
	} else if (Rs != 0 && Rs < Rt) {
		MCInst_setOpcode(MI, (Mips_BEQC_MMR6));
		MCOperand_CreateReg0(MI,
				     (getReg(MI, Mips_GPR32RegClassID, Rs)));
		MCOperand_CreateReg0(MI,
				     (getReg(MI, Mips_GPR32RegClassID, Rt)));
		Imm = SignExtend64(fieldFromInstruction_4(insn, 0, 16), 16) *
			      4 +
		      4;
	} else {
		MCInst_setOpcode(MI, (Mips_BEQZALC_MMR6));
		MCOperand_CreateReg0(MI,
				     (getReg(MI, Mips_GPR32RegClassID, Rt)));
		Imm = SignExtend64(fieldFromInstruction_4(insn, 0, 16), 16) *
			      2 +
		      4;
	}

	MCOperand_CreateImm0(MI, (Imm));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeDaddiGroupBranch(MCInst *MI, uint32_t insn,
					   uint64_t Address,
					   const void *Decoder)
{
	// If we are called then we can assume that MIPS32r6/MIPS64r6 is enabled
	// (otherwise we would have matched the ADDI instruction from the earlier
	// ISA's instead).
	//
	// We have:
	//    0b011000 sssss ttttt iiiiiiiiiiiiiiii
	//      BNVC if rs >= rt
	//      BNEZALC if rs == 0 && rt != 0
	//      BNEC if rs < rt && rs != 0

	uint32_t Rs = fieldFromInstruction_4(insn, 21, 5);
	uint32_t Rt = fieldFromInstruction_4(insn, 16, 5);
	int64_t Imm =
		SignExtend64(fieldFromInstruction_4(insn, 0, 16), 16) * 4 + 4;
	bool HasRs = false;

	if (Rs >= Rt) {
		MCInst_setOpcode(MI, (Mips_BNVC));
		HasRs = true;
	} else if (Rs != 0 && Rs < Rt) {
		MCInst_setOpcode(MI, (Mips_BNEC));
		HasRs = true;
	} else
		MCInst_setOpcode(MI, (Mips_BNEZALC));

	if (HasRs)
		MCOperand_CreateReg0(MI,
				     (getReg(MI, Mips_GPR32RegClassID, Rs)));

	MCOperand_CreateReg0(MI, (getReg(MI, Mips_GPR32RegClassID, Rt)));
	MCOperand_CreateImm0(MI, (Imm));

	return MCDisassembler_Success;
}

static DecodeStatus DecodePOP37GroupBranchMMR6(MCInst *MI, uint32_t insn,
					       uint64_t Address,
					       const void *Decoder)
{
	uint32_t Rt = fieldFromInstruction_4(insn, 21, 5);
	uint32_t Rs = fieldFromInstruction_4(insn, 16, 5);
	int64_t Imm = 0;

	if (Rs >= Rt) {
		MCInst_setOpcode(MI, (Mips_BNVC_MMR6));
		MCOperand_CreateReg0(MI,
				     (getReg(MI, Mips_GPR32RegClassID, Rt)));
		MCOperand_CreateReg0(MI,
				     (getReg(MI, Mips_GPR32RegClassID, Rs)));
		Imm = SignExtend64(fieldFromInstruction_4(insn, 0, 16), 16) *
			      2 +
		      4;
	} else if (Rs != 0 && Rs < Rt) {
		MCInst_setOpcode(MI, (Mips_BNEC_MMR6));
		MCOperand_CreateReg0(MI,
				     (getReg(MI, Mips_GPR32RegClassID, Rs)));
		MCOperand_CreateReg0(MI,
				     (getReg(MI, Mips_GPR32RegClassID, Rt)));
		Imm = SignExtend64(fieldFromInstruction_4(insn, 0, 16), 16) *
			      4 +
		      4;
	} else {
		MCInst_setOpcode(MI, (Mips_BNEZALC_MMR6));
		MCOperand_CreateReg0(MI,
				     (getReg(MI, Mips_GPR32RegClassID, Rt)));
		Imm = SignExtend64(fieldFromInstruction_4(insn, 0, 16), 16) *
			      2 +
		      4;
	}

	MCOperand_CreateImm0(MI, (Imm));

	return MCDisassembler_Success;
}

static DecodeStatus DecodePOP65GroupBranchMMR6(MCInst *MI, uint32_t insn,
					       uint64_t Address,
					       const void *Decoder)
{
	// We have:
	//    0b110101 ttttt sssss iiiiiiiiiiiiiiii
	//      Invalid if rt == 0
	//      BGTZC_MMR6   if rs == 0  && rt != 0
	//      BLTZC_MMR6   if rs == rt && rt != 0
	//      BLTC_MMR6    if rs != rt && rs != 0  && rt != 0

	uint32_t Rt = fieldFromInstruction_4(insn, 21, 5);
	uint32_t Rs = fieldFromInstruction_4(insn, 16, 5);
	int64_t Imm =
		SignExtend64(fieldFromInstruction_4(insn, 0, 16), 16) * 4 + 4;
	bool HasRs = false;

	if (Rt == 0)
		return MCDisassembler_Fail;
	else if (Rs == 0)
		MCInst_setOpcode(MI, (Mips_BGTZC_MMR6));
	else if (Rs == Rt)
		MCInst_setOpcode(MI, (Mips_BLTZC_MMR6));
	else {
		MCInst_setOpcode(MI, (Mips_BLTC_MMR6));
		HasRs = true;
	}

	if (HasRs)
		MCOperand_CreateReg0(MI,
				     (getReg(MI, Mips_GPR32RegClassID, Rs)));

	MCOperand_CreateReg0(MI, (getReg(MI, Mips_GPR32RegClassID, Rt)));

	MCOperand_CreateImm0(MI, (Imm));

	return MCDisassembler_Success;
}

static DecodeStatus DecodePOP75GroupBranchMMR6(MCInst *MI, uint32_t insn,
					       uint64_t Address,
					       const void *Decoder)
{
	// We have:
	//    0b111101 ttttt sssss iiiiiiiiiiiiiiii
	//      Invalid if rt == 0
	//      BLEZC_MMR6   if rs == 0  && rt != 0
	//      BGEZC_MMR6   if rs == rt && rt != 0
	//      BGEC_MMR6    if rs != rt && rs != 0  && rt != 0

	uint32_t Rt = fieldFromInstruction_4(insn, 21, 5);
	uint32_t Rs = fieldFromInstruction_4(insn, 16, 5);
	int64_t Imm =
		SignExtend64(fieldFromInstruction_4(insn, 0, 16), 16) * 4 + 4;
	bool HasRs = false;

	if (Rt == 0)
		return MCDisassembler_Fail;
	else if (Rs == 0)
		MCInst_setOpcode(MI, (Mips_BLEZC_MMR6));
	else if (Rs == Rt)
		MCInst_setOpcode(MI, (Mips_BGEZC_MMR6));
	else {
		HasRs = true;
		MCInst_setOpcode(MI, (Mips_BGEC_MMR6));
	}

	if (HasRs)
		MCOperand_CreateReg0(MI,
				     (getReg(MI, Mips_GPR32RegClassID, Rs)));

	MCOperand_CreateReg0(MI, (getReg(MI, Mips_GPR32RegClassID, Rt)));

	MCOperand_CreateImm0(MI, (Imm));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeBlezlGroupBranch(MCInst *MI, uint32_t insn,
					   uint64_t Address,
					   const void *Decoder)
{
	// If we are called then we can assume that MIPS32r6/MIPS64r6 is enabled
	// (otherwise we would have matched the BLEZL instruction from the earlier
	// ISA's instead).
	//
	// We have:
	//    0b010110 sssss ttttt iiiiiiiiiiiiiiii
	//      Invalid if rs == 0
	//      BLEZC   if rs == 0  && rt != 0
	//      BGEZC   if rs == rt && rt != 0
	//      BGEC    if rs != rt && rs != 0  && rt != 0

	uint32_t Rs = fieldFromInstruction_4(insn, 21, 5);
	uint32_t Rt = fieldFromInstruction_4(insn, 16, 5);
	int64_t Imm =
		SignExtend64(fieldFromInstruction_4(insn, 0, 16), 16) * 4 + 4;
	bool HasRs = false;

	if (Rt == 0)
		return MCDisassembler_Fail;
	else if (Rs == 0)
		MCInst_setOpcode(MI, (Mips_BLEZC));
	else if (Rs == Rt)
		MCInst_setOpcode(MI, (Mips_BGEZC));
	else {
		HasRs = true;
		MCInst_setOpcode(MI, (Mips_BGEC));
	}

	if (HasRs)
		MCOperand_CreateReg0(MI,
				     (getReg(MI, Mips_GPR32RegClassID, Rs)));

	MCOperand_CreateReg0(MI, (getReg(MI, Mips_GPR32RegClassID, Rt)));

	MCOperand_CreateImm0(MI, (Imm));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeBgtzlGroupBranch(MCInst *MI, uint32_t insn,
					   uint64_t Address,
					   const void *Decoder)
{
	// If we are called then we can assume that MIPS32r6/MIPS64r6 is enabled
	// (otherwise we would have matched the BGTZL instruction from the earlier
	// ISA's instead).
	//
	// We have:
	//    0b010111 sssss ttttt iiiiiiiiiiiiiiii
	//      Invalid if rs == 0
	//      BGTZC   if rs == 0  && rt != 0
	//      BLTZC   if rs == rt && rt != 0
	//      BLTC    if rs != rt && rs != 0  && rt != 0

	bool HasRs = false;

	uint32_t Rs = fieldFromInstruction_4(insn, 21, 5);
	uint32_t Rt = fieldFromInstruction_4(insn, 16, 5);
	int64_t Imm =
		SignExtend64(fieldFromInstruction_4(insn, 0, 16), 16) * 4 + 4;

	if (Rt == 0)
		return MCDisassembler_Fail;
	else if (Rs == 0)
		MCInst_setOpcode(MI, (Mips_BGTZC));
	else if (Rs == Rt)
		MCInst_setOpcode(MI, (Mips_BLTZC));
	else {
		MCInst_setOpcode(MI, (Mips_BLTC));
		HasRs = true;
	}

	if (HasRs)
		MCOperand_CreateReg0(MI,
				     (getReg(MI, Mips_GPR32RegClassID, Rs)));

	MCOperand_CreateReg0(MI, (getReg(MI, Mips_GPR32RegClassID, Rt)));

	MCOperand_CreateImm0(MI, (Imm));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeBgtzGroupBranch(MCInst *MI, uint32_t insn,
					  uint64_t Address, const void *Decoder)
{
	// If we are called then we can assume that MIPS32r6/MIPS64r6 is enabled
	// (otherwise we would have matched the BGTZ instruction from the earlier
	// ISA's instead).
	//
	// We have:
	//    0b000111 sssss ttttt iiiiiiiiiiiiiiii
	//      BGTZ    if rt == 0
	//      BGTZALC if rs == 0 && rt != 0
	//      BLTZALC if rs != 0 && rs == rt
	//      BLTUC   if rs != 0 && rs != rt

	uint32_t Rs = fieldFromInstruction_4(insn, 21, 5);
	uint32_t Rt = fieldFromInstruction_4(insn, 16, 5);
	int64_t Imm =
		SignExtend64(fieldFromInstruction_4(insn, 0, 16), 16) * 4 + 4;
	bool HasRs = false;
	bool HasRt = false;

	if (Rt == 0) {
		MCInst_setOpcode(MI, (Mips_BGTZ));
		HasRs = true;
	} else if (Rs == 0) {
		MCInst_setOpcode(MI, (Mips_BGTZALC));
		HasRt = true;
	} else if (Rs == Rt) {
		MCInst_setOpcode(MI, (Mips_BLTZALC));
		HasRs = true;
	} else {
		MCInst_setOpcode(MI, (Mips_BLTUC));
		HasRs = true;
		HasRt = true;
	}

	if (HasRs)
		MCOperand_CreateReg0(MI,
				     (getReg(MI, Mips_GPR32RegClassID, Rs)));

	if (HasRt)
		MCOperand_CreateReg0(MI,
				     (getReg(MI, Mips_GPR32RegClassID, Rt)));

	MCOperand_CreateImm0(MI, (Imm));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeBlezGroupBranch(MCInst *MI, uint32_t insn,
					  uint64_t Address, const void *Decoder)
{
	// If we are called then we can assume that MIPS32r6/MIPS64r6 is enabled
	// (otherwise we would have matched the BLEZL instruction from the earlier
	// ISA's instead).
	//
	// We have:
	//    0b000110 sssss ttttt iiiiiiiiiiiiiiii
	//      Invalid   if rs == 0
	//      BLEZALC   if rs == 0  && rt != 0
	//      BGEZALC   if rs == rt && rt != 0
	//      BGEUC     if rs != rt && rs != 0  && rt != 0

	uint32_t Rs = fieldFromInstruction_4(insn, 21, 5);
	uint32_t Rt = fieldFromInstruction_4(insn, 16, 5);
	int64_t Imm =
		SignExtend64(fieldFromInstruction_4(insn, 0, 16), 16) * 4 + 4;
	bool HasRs = false;

	if (Rt == 0)
		return MCDisassembler_Fail;
	else if (Rs == 0)
		MCInst_setOpcode(MI, (Mips_BLEZALC));
	else if (Rs == Rt)
		MCInst_setOpcode(MI, (Mips_BGEZALC));
	else {
		HasRs = true;
		MCInst_setOpcode(MI, (Mips_BGEUC));
	}

	if (HasRs)
		MCOperand_CreateReg0(MI,
				     (getReg(MI, Mips_GPR32RegClassID, Rs)));
	MCOperand_CreateReg0(MI, (getReg(MI, Mips_GPR32RegClassID, Rt)));

	MCOperand_CreateImm0(MI, (Imm));

	return MCDisassembler_Success;
}

// Override the generated disassembler to produce DEXT all the time. This is
// for feature / behaviour parity with  binutils.
static DecodeStatus DecodeDEXT(MCInst *MI, uint32_t Insn, uint64_t Address,
			       const void *Decoder)
{
	unsigned Msbd = fieldFromInstruction_4(Insn, 11, 5);
	unsigned Lsb = fieldFromInstruction_4(Insn, 6, 5);
	unsigned Size = 0;
	unsigned Pos = 0;

	switch (MCInst_getOpcode(MI)) {
	case Mips_DEXT:
		Pos = Lsb;
		Size = Msbd + 1;
		break;
	case Mips_DEXTM:
		Pos = Lsb;
		Size = Msbd + 1 + 32;
		break;
	case Mips_DEXTU:
		Pos = Lsb + 32;
		Size = Msbd + 1;
		break;
	default:
		CS_ASSERT_RET_VAL(0 && "Unknown DEXT instruction!",
				  MCDisassembler_Fail);
		return MCDisassembler_Fail;
	}

	MCInst_setOpcode(MI, (Mips_DEXT));

	uint32_t Rs = fieldFromInstruction_4(Insn, 21, 5);
	uint32_t Rt = fieldFromInstruction_4(Insn, 16, 5);

	MCOperand_CreateReg0(MI, (getReg(MI, Mips_GPR64RegClassID, Rt)));
	MCOperand_CreateReg0(MI, (getReg(MI, Mips_GPR64RegClassID, Rs)));
	MCOperand_CreateImm0(MI, (Pos));
	MCOperand_CreateImm0(MI, (Size));

	return MCDisassembler_Success;
}

// Override the generated disassembler to produce DINS all the time. This is
// for feature / behaviour parity with binutils.
static DecodeStatus DecodeDINS(MCInst *MI, uint32_t Insn, uint64_t Address,
			       const void *Decoder)
{
	unsigned Msbd = fieldFromInstruction_4(Insn, 11, 5);
	unsigned Lsb = fieldFromInstruction_4(Insn, 6, 5);
	unsigned Size = 0;
	unsigned Pos = 0;

	switch (MCInst_getOpcode(MI)) {
	case Mips_DINS:
		Pos = Lsb;
		Size = Msbd + 1 - Pos;
		break;
	case Mips_DINSM:
		Pos = Lsb;
		Size = Msbd + 33 - Pos;
		break;
	case Mips_DINSU:
		Pos = Lsb + 32;
		// mbsd = pos + size - 33
		// mbsd - pos + 33 = size
		Size = Msbd + 33 - Pos;
		break;
	default:
		CS_ASSERT_RET_VAL(0 && "Unknown DINS instruction!",
				  MCDisassembler_Fail);
		return MCDisassembler_Fail;
	}

	uint32_t Rs = fieldFromInstruction_4(Insn, 21, 5);
	uint32_t Rt = fieldFromInstruction_4(Insn, 16, 5);

	MCInst_setOpcode(MI, (Mips_DINS));
	MCOperand_CreateReg0(MI, (getReg(MI, Mips_GPR64RegClassID, Rt)));
	MCOperand_CreateReg0(MI, (getReg(MI, Mips_GPR64RegClassID, Rs)));
	MCOperand_CreateImm0(MI, (Pos));
	MCOperand_CreateImm0(MI, (Size));

	return MCDisassembler_Success;
}

// Auto-generated decoder wouldn't add the third operand for CRC32*.
static DecodeStatus DecodeCRC(MCInst *MI, uint32_t Insn, uint64_t Address,
			      const void *Decoder)
{
	uint32_t Rs = fieldFromInstruction_4(Insn, 21, 5);
	uint32_t Rt = fieldFromInstruction_4(Insn, 16, 5);
	MCOperand_CreateReg0(MI, (getReg(MI, Mips_GPR32RegClassID, Rt)));
	MCOperand_CreateReg0(MI, (getReg(MI, Mips_GPR32RegClassID, Rs)));
	MCOperand_CreateReg0(MI, (getReg(MI, Mips_GPR32RegClassID, Rt)));
	return MCDisassembler_Success;
}

/// Read two bytes from the ArrayRef and return 16 bit halfword sorted
/// according to the given endianness.
static DecodeStatus readInstruction16(const uint8_t *Bytes, size_t BytesLen,
				      uint64_t Address, uint64_t *Size,
				      uint64_t *Insn, bool IsBigEndian)
{
	// We want to read exactly 2 Bytes of data.
	if (BytesLen < 2) {
		*Size = 0;
		return MCDisassembler_Fail;
	}

	if (IsBigEndian) {
		*Insn = (Bytes[0] << 8) | Bytes[1];
	} else {
		*Insn = (Bytes[1] << 8) | Bytes[0];
	}

	return MCDisassembler_Success;
}

/// Read four bytes from the ArrayRef and return 32 bit word sorted
/// according to the given endianness.
static DecodeStatus readInstruction32(const uint8_t *Bytes, size_t BytesLen,
				      uint64_t Address, uint64_t *Size,
				      uint64_t *Insn, bool IsBigEndian,
				      bool IsMicroMips)
{
	// We want to read exactly 4 Bytes of data.
	if (BytesLen < 4) {
		*Size = 0;
		return MCDisassembler_Fail;
	}

	// High 16 bits of a 32-bit microMIPS instruction (where the opcode is)
	// always precede the low 16 bits in the instruction stream (that is, they
	// are placed at lower addresses in the instruction stream).
	//
	// microMIPS byte ordering:
	//   Big-endian:    0 | 1 | 2 | 3
	//   Little-endian: 1 | 0 | 3 | 2

	if (IsBigEndian) {
		// Encoded as a big-endian 32-bit word in the stream.
		*Insn = (Bytes[3] << 0) | (Bytes[2] << 8) | (Bytes[1] << 16) |
			((unsigned)Bytes[0] << 24);
	} else {
		if (IsMicroMips) {
			*Insn = (Bytes[2] << 0) | (Bytes[3] << 8) |
				(Bytes[0] << 16) | ((unsigned)Bytes[1] << 24);
		} else {
			*Insn = (Bytes[0] << 0) | (Bytes[1] << 8) |
				(Bytes[2] << 16) | ((unsigned)Bytes[3] << 24);
		}
	}

	return MCDisassembler_Success;
}

/// Read 6 bytes from the ArrayRef and return in a 64-bit bit word sorted
/// according to the given endianness and encoding byte-order.
static DecodeStatus readInstruction48(const uint8_t *Bytes, size_t BytesLen,
				      uint64_t Address, uint64_t *Size,
				      uint64_t *Insn, bool IsBigEndian,
				      bool IsNanoMips)
{
	// We want to read exactly 6 Bytes of little-endian data in nanoMIPS mode.
	if (BytesLen < 6 || IsBigEndian || !IsNanoMips) {
		*Size = 0;
		return MCDisassembler_Fail;
	}

	// High 16 bits of a 32-bit nanoMIPS instruction (where the opcode is)
	// always precede the low 16 bits in the instruction stream (that is, they
	// are placed at lower addresses in the instruction stream).
	//
	// nanoMIPS byte ordering:
	//   Little-endian: 1 | 0 | 3 | 2 | 5 | 4

	*Insn = (Bytes[0] << 0) | (Bytes[1] << 8);
	*Insn = ((*Insn << 32) | (Bytes[4] << 0) | (Bytes[5] << 8) |
		 (Bytes[2] << 16) | ((unsigned)Bytes[3] << 24));
	return MCDisassembler_Success;
}

static DecodeStatus getInstruction(MCInst *Instr, uint64_t *Size,
				   const uint8_t *Bytes, size_t BytesLen,
				   uint64_t Address, SStream *CStream)
{
	uint64_t Insn;
	DecodeStatus Result;
	*Size = 0;

	cs_mode mode = Instr->csh->mode;
	bool IsBigEndian = mode & CS_MODE_BIG_ENDIAN;
	bool IsMicroMips = Mips_getFeatureBits(mode, Mips_FeatureMicroMips);
	bool IsNanoMips = Mips_getFeatureBits(mode, Mips_FeatureNanoMips);
	bool IsMips32r6 = Mips_getFeatureBits(mode, Mips_FeatureMips32r6);
	bool IsMips64r6 = Mips_getFeatureBits(mode, Mips_FeatureMips64r6);
	bool IsMips2 = Mips_getFeatureBits(mode, Mips_FeatureMips2);
	bool IsMips16 = Mips_getFeatureBits(mode, Mips_FeatureMips16);
	bool IsCnMips = Mips_getFeatureBits(mode, Mips_FeatureCnMips);
	bool IsCnMipsP = Mips_getFeatureBits(mode, Mips_FeatureCnMipsP);
	bool IsFP64 = Mips_getFeatureBits(mode, Mips_FeatureFP64Bit);
	bool IsGP64 = Mips_getFeatureBits(mode, Mips_FeatureGP64Bit);
	bool IsPTR64 = Mips_getFeatureBits(mode, Mips_FeaturePTR64Bit);
	// Only present in MIPS-I and MIPS-II
	bool HasCOP3 = !Mips_getFeatureBits(mode, Mips_FeatureMips32) &&
		       !Mips_getFeatureBits(mode, Mips_FeatureMips3);

	if (IsNanoMips) {
		uint64_t Insn2;
		Result = readInstruction48(Bytes, BytesLen, Address, Size,
					   &Insn2, IsBigEndian, IsNanoMips);
		if (Result != MCDisassembler_Fail) {
			// Calling the auto-generated decoder function.
			Result = decodeInstruction_8(DecoderTableNanoMips48,
						     Instr, Insn2, Address,
						     NULL);
			if (Result != MCDisassembler_Fail) {
				*Size = 6;
				return Result;
			}
		}

		Result = readInstruction32(Bytes, BytesLen, Address, Size,
					   &Insn, IsBigEndian, IsNanoMips);
		if (Result != MCDisassembler_Fail) {
			// Calling the auto-generated decoder function.
			Result = decodeInstruction_4(DecoderTableNanoMips32,
						     Instr, Insn, Address,
						     NULL);
			if (Result != MCDisassembler_Fail) {
				*Size = 4;
				return Result;
			}
		}

		Result = readInstruction16(Bytes, BytesLen, Address, Size,
					   &Insn, IsBigEndian);
		if (Result != MCDisassembler_Fail) {
			// Calling the auto-generated decoder function for NanoMips
			// 16-bit instructions.
			Result = decodeInstruction_2(DecoderTableNanoMips16,
						     Instr, Insn, Address,
						     NULL);
			if (Result != MCDisassembler_Fail) {
				*Size = 2;
				return Result;
			}

			Result = decodeInstruction_2(
				DecoderTableNanoMips_Conflict_Space16, Instr,
				Insn, Address, NULL);
			if (Result != MCDisassembler_Fail) {
				*Size = 2;
				return Result;
			}
		}

		// This is an invalid instruction. Claim that the Size is 2 bytes. Since
		// nanoMIPS instructions have a minimum alignment of 2, the next 2 bytes
		// could form a valid instruction.
		*Size = 2;
		return MCDisassembler_Fail;
	}

	if (IsMicroMips) {
		Result = readInstruction16(Bytes, BytesLen, Address, Size,
					   &Insn, IsBigEndian);
		if (Result == MCDisassembler_Fail)
			return MCDisassembler_Fail;

		if (IsMips32r6) {
			// Calling the auto-generated decoder function for microMIPS32R6
			// 16-bit instructions.
			Result = decodeInstruction_2(DecoderTableMicroMipsR616,
						     Instr, Insn, Address,
						     NULL);
			if (Result != MCDisassembler_Fail) {
				*Size = 2;
				return Result;
			}
		}

		// Calling the auto-generated decoder function for microMIPS 16-bit
		// instructions.
		Result = decodeInstruction_2(DecoderTableMicroMips16, Instr,
					     Insn, Address, NULL);
		if (Result != MCDisassembler_Fail) {
			*Size = 2;
			return Result;
		}

		Result = readInstruction32(Bytes, BytesLen, Address, Size,
					   &Insn, IsBigEndian, IsMicroMips);
		if (Result == MCDisassembler_Fail)
			return MCDisassembler_Fail;

		if (IsMips32r6) {
			// Calling the auto-generated decoder function.
			Result = decodeInstruction_4(
				DecoderTableMicroMipsR6_Ambiguous32, Instr,
				Insn, Address, NULL);
			if (Result != MCDisassembler_Fail) {
				*Size = 4;
				return Result;
			}

			Result = decodeInstruction_4(DecoderTableMicroMipsR632,
						     Instr, Insn, Address,
						     NULL);
			if (Result != MCDisassembler_Fail) {
				*Size = 4;
				return Result;
			}
		}

		// Calling the auto-generated decoder function.
		Result = decodeInstruction_4(DecoderTableMicroMips32, Instr,
					     Insn, Address, NULL);
		if (Result != MCDisassembler_Fail) {
			*Size = 4;
			return Result;
		}

		Result = decodeInstruction_4(DecoderTableMicroMipsDSP32, Instr,
					     Insn, Address, NULL);
		if (Result != MCDisassembler_Fail) {
			*Size = 4;
			return Result;
		}

		if (IsFP64) {
			Result =
				decodeInstruction_4(DecoderTableMicroMipsFP6432,
						    Instr, Insn, Address, NULL);
			if (Result != MCDisassembler_Fail) {
				*Size = 4;
				return Result;
			}
		}

		// This is an invalid instruction. Claim that the Size is 2 bytes. Since
		// microMIPS instructions have a minimum alignment of 2, the next 2 bytes
		// could form a valid instruction. The two bytes we rejected as an
		// instruction could have actually beeen an inline constant pool that is
		// unconditionally branched over.
		*Size = 2;
		return MCDisassembler_Fail;
	}

	if (IsMips16) {
		Result = readInstruction32(Bytes, BytesLen, Address, Size,
					   &Insn, IsBigEndian, IsMicroMips);
		if (Result != MCDisassembler_Fail) {
			Result = decodeInstruction_4(DecoderTable32, Instr,
						     Insn, Address, NULL);
			if (Result != MCDisassembler_Fail) {
				*Size = 4;
				return Result;
			}
		}

		Result = readInstruction16(Bytes, BytesLen, Address, Size,
					   &Insn, IsBigEndian);
		if (Result == MCDisassembler_Fail) {
			return MCDisassembler_Fail;
		}

		*Size = 2;
		return decodeInstruction_2(DecoderTable16, Instr, Insn, Address,
					   NULL);
	}

	// Attempt to read the instruction so that we can attempt to decode it. If
	// the buffer is not 4 bytes long, let the higher level logic figure out
	// what to do with a size of zero and MCDisassembler::Fail.
	Result = readInstruction32(Bytes, BytesLen, Address, Size, &Insn,
				   IsBigEndian, IsMicroMips);
	if (Result == MCDisassembler_Fail)
		return MCDisassembler_Fail;

	// The only instruction size for standard encoded MIPS.
	*Size = 4;

	if (HasCOP3) {
		Result = decodeInstruction_4(DecoderTableCOP3_32, Instr, Insn,
					     Address, NULL);
		if (Result != MCDisassembler_Fail)
			return Result;
	}

	if (IsMips32r6 && IsGP64) {
		Result = decodeInstruction_4(DecoderTableMips32r6_64r6_GP6432,
					     Instr, Insn, Address, NULL);
		if (Result != MCDisassembler_Fail)
			return Result;
	}

	if (IsMips32r6 && IsPTR64) {
		Result = decodeInstruction_4(DecoderTableMips32r6_64r6_PTR6432,
					     Instr, Insn, Address, NULL);
		if (Result != MCDisassembler_Fail)
			return Result;
	}

	if (IsMips32r6 || IsMips64r6) {
		Result = decodeInstruction_4(
			DecoderTableMips32r6_64r6_BranchZero32, Instr, Insn,
			Address, NULL);
		if (Result != MCDisassembler_Fail)
			return Result;

		Result = decodeInstruction_4(DecoderTableMips32r6_64r632, Instr,
					     Insn, Address, NULL);
		if (Result != MCDisassembler_Fail)
			return Result;

		Result = decodeInstruction_4(
			DecoderTableMips32r6_64r6_Ambiguous32, Instr, Insn,
			Address, NULL);
		if (Result != MCDisassembler_Fail)
			return Result;
	}

	if (IsMips2 && IsPTR64) {
		Result = decodeInstruction_4(DecoderTableMips32_64_PTR6432,
					     Instr, Insn, Address, NULL);
		if (Result != MCDisassembler_Fail)
			return Result;
	}

	if (IsCnMips) {
		Result = decodeInstruction_4(DecoderTableCnMips32, Instr, Insn,
					     Address, NULL);
		if (Result != MCDisassembler_Fail)
			return Result;
	}

	if (IsCnMipsP) {
		Result = decodeInstruction_4(DecoderTableCnMipsP32, Instr, Insn,
					     Address, NULL);
		if (Result != MCDisassembler_Fail)
			return Result;
	}

	if (IsGP64) {
		Result = decodeInstruction_4(DecoderTableMips6432, Instr, Insn,
					     Address, NULL);
		if (Result != MCDisassembler_Fail)
			return Result;
	}

	if (IsFP64) {
		Result = decodeInstruction_4(DecoderTableMipsFP6432, Instr,
					     Insn, Address, NULL);
		if (Result != MCDisassembler_Fail)
			return Result;
	}

	Result = decodeInstruction_4(DecoderTableMipsDSP32, Instr, Insn,
				     Address, NULL);
	if (Result != MCDisassembler_Fail)
		return Result;

	// Calling the auto-generated decoder function.
	Result = decodeInstruction_4(DecoderTableMips32, Instr, Insn, Address,
				     NULL);
	if (Result != MCDisassembler_Fail)
		return Result;

	return MCDisassembler_Fail;
}

static DecodeStatus DecodeCPU16RegsRegisterClass(MCInst *Inst, unsigned RegNo,
						 uint64_t Address,
						 const void *Decoder)
{
	if (RegNo > 7)
		return MCDisassembler_Fail;

	if (RegNo < 2)
		RegNo += 16;

	unsigned Reg = getReg(Inst, Mips_GPR32RegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeGPR64RegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;

	unsigned Reg = getReg(Inst, Mips_GPR64RegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeGPRMM16RegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	if (RegNo > 7)
		return MCDisassembler_Fail;
	unsigned Reg = getReg(Inst, Mips_GPRMM16RegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeGPRMM16ZeroRegisterClass(MCInst *Inst, unsigned RegNo,
						   uint64_t Address,
						   const void *Decoder)
{
	if (RegNo > 7)
		return MCDisassembler_Fail;
	unsigned Reg = getReg(Inst, Mips_GPRMM16ZeroRegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeGPRMM16MovePRegisterClass(MCInst *Inst,
						    unsigned RegNo,
						    uint64_t Address,
						    const void *Decoder)
{
	if (RegNo > 7)
		return MCDisassembler_Fail;
	unsigned Reg = getReg(Inst, Mips_GPRMM16MovePRegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeGPR32RegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;
	unsigned Reg = getReg(Inst, Mips_GPR32RegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeGPRNM3RegisterClass(MCInst *Inst, unsigned RegNo,
					      uint64_t Address,
					      const void *Decoder)
{
	if (RegNo > 7)
		return MCDisassembler_Fail;
	RegNo |= ((RegNo & 0x4) ^ 0x4) << 2;
	unsigned Reg = getReg(Inst, Mips_GPRNM32RegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeGPRNMRARegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	MCOperand_CreateReg0(Inst, (Mips_RA_NM));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeGPRNM3ZRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	if (RegNo > 7)
		return MCDisassembler_Fail;
	if (RegNo != 0)
		RegNo |= ((RegNo & 0x4) ^ 0x4) << 2;
	unsigned Reg = getReg(Inst, Mips_GPRNM32RegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeGPRNM4RegisterClass(MCInst *Inst, unsigned RegNo,
					      uint64_t Address,
					      const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;
	RegNo &= ~0x8;
	RegNo += (RegNo < 4 ? 8 : 0);
	unsigned Reg = getReg(Inst, Mips_GPRNM32RegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeGPRNM4ZRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;
	RegNo &= ~0x8;
	if (RegNo == 3)
		RegNo = 0;
	else
		RegNo += (RegNo < 3 ? 8 : 0);
	unsigned Reg = getReg(Inst, Mips_GPRNM32RegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeGPRNM32NZRegisterClass(MCInst *Inst, unsigned RegNo,
						 uint64_t Address,
						 const void *Decoder)
{
	if (RegNo == 0)
		return MCDisassembler_Fail;
	unsigned Reg = getReg(Inst, Mips_GPRNM32RegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeGPRNM32RegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;
	unsigned Reg = getReg(Inst, Mips_GPRNM32RegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeGPRNM2R1RegisterClass(MCInst *Inst, unsigned RegNo,
						uint64_t Address,
						const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;
	RegNo += 4;
	unsigned Reg = getReg(Inst, Mips_GPRNM32RegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	MCOperand_CreateReg0(Inst, (Reg + 1));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeGPRNM1R1RegisterClass(MCInst *Inst, unsigned RegNo,
						uint64_t Address,
						const void *Decoder)
{
	if (RegNo != 0 && RegNo != 1)
		return MCDisassembler_Fail;
	RegNo += 4;
	unsigned Reg = getReg(Inst, Mips_GPRNM32RegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodePtrRegisterClass(MCInst *Inst, unsigned RegNo,
					   uint64_t Address,
					   const void *Decoder)
{
	if (Mips_getFeatureBits(Inst->csh->mode, Mips_FeatureGP64Bit))
		return DecodeGPR64RegisterClass(Inst, RegNo, Address, Decoder);

	return DecodeGPR32RegisterClass(Inst, RegNo, Address, Decoder);
}

static DecodeStatus DecodeDSPRRegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    const void *Decoder)
{
	return DecodeGPR32RegisterClass(Inst, RegNo, Address, Decoder);
}

static DecodeStatus DecodeFGR64RegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;

	unsigned Reg = getReg(Inst, Mips_FGR64RegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeFGR32RegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;

	unsigned Reg = getReg(Inst, Mips_FGR32RegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeCCRRegisterClass(MCInst *Inst, unsigned RegNo,
					   uint64_t Address,
					   const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;
	unsigned Reg = getReg(Inst, Mips_CCRRegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeFCCRegisterClass(MCInst *Inst, unsigned RegNo,
					   uint64_t Address,
					   const void *Decoder)
{
	if (RegNo > 7)
		return MCDisassembler_Fail;
	unsigned Reg = getReg(Inst, Mips_FCCRegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeFGRCCRegisterClass(MCInst *Inst, unsigned RegNo,
					     uint64_t Address,
					     const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;

	unsigned Reg = getReg(Inst, Mips_FGRCCRegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeMem(MCInst *Inst, uint32_t Insn, uint64_t Address,
			      const void *Decoder)
{
	int Offset = SignExtend32((Insn & 0xffff), 16);
	unsigned Reg = fieldFromInstruction_4(Insn, 16, 5);
	unsigned Base = fieldFromInstruction_4(Insn, 21, 5);

	Reg = getReg(Inst, Mips_GPR32RegClassID, Reg);
	Base = getReg(Inst, Mips_GPR32RegClassID, Base);

	if (MCInst_getOpcode(Inst) == Mips_SC ||
	    MCInst_getOpcode(Inst) == Mips_SCD)
		MCOperand_CreateReg0(Inst, (Reg));

	MCOperand_CreateReg0(Inst, (Reg));
	MCOperand_CreateReg0(Inst, (Base));
	MCOperand_CreateImm0(Inst, (Offset));

	return MCDisassembler_Success;
}

#define DEFINE_DecodeMemNM(Offbits, isSigned, rt) \
	static DecodeStatus CONCAT(DecodeMemNM, \
				   CONCAT(Offbits, CONCAT(isSigned, rt)))( \
		MCInst * Inst, uint32_t Insn, uint64_t Address, \
		const void *Decoder) \
	{ \
		int Offset = (Insn & ((1 << Offbits) - 1)); \
		if (isSigned) \
			Offset = SignExtend32((Offset), Offbits); \
		unsigned Base; \
\
		switch (rt) { \
		case Mips_GPRNMGPRegClassID: \
		case Mips_GPRNMSPRegClassID: \
			Base = 0; \
			break; \
		case Mips_GPRNM3RegClassID: \
			Base = fieldFromInstruction_4(Insn, Offbits, 3); \
			break; \
		case Mips_GPRNM4RegClassID: \
		case Mips_GPRNM4ZRegClassID: \
\
			break; \
		default: \
			Base = fieldFromInstruction_4(Insn, Offbits, 5); \
		} \
		Base = getReg(Inst, rt, Base); \
\
		MCOperand_CreateReg0(Inst, (Base)); \
		MCOperand_CreateImm0(Inst, (Offset)); \
\
		return MCDisassembler_Success; \
	}
DEFINE_DecodeMemNM(6, 0, Mips_GPRNM3RegClassID);
DEFINE_DecodeMemNM(7, 0, Mips_GPRNMSPRegClassID);
DEFINE_DecodeMemNM(9, 0, Mips_GPRNMGPRegClassID);
DEFINE_DecodeMemNM(2, 0, Mips_GPRNM3RegClassID);
DEFINE_DecodeMemNM(3, 0, Mips_GPRNM3RegClassID);
DEFINE_DecodeMemNM(21, 0, Mips_GPRNMGPRegClassID);
DEFINE_DecodeMemNM(18, 0, Mips_GPRNMGPRegClassID);
DEFINE_DecodeMemNM(12, 0, Mips_GPRNM32RegClassID);
DEFINE_DecodeMemNM(9, 1, Mips_GPRNM32RegClassID);

static DecodeStatus DecodeMemZeroNM(MCInst *Inst, uint32_t Insn,
				    uint64_t Address, const void *Decoder)
{
	unsigned Base;
	Base = fieldFromInstruction_4(Insn, 0, 5);
	Base = getReg(Inst, Mips_GPRNM32RegClassID, Base);
	MCOperand_CreateReg0(Inst, (Base));

	return MCDisassembler_Success;
}

#define DEFINE_DecodeMemNMRX(RegClass) \
	static DecodeStatus CONCAT(DecodeMemNMRX, RegClass)( \
		MCInst * Inst, uint32_t Insn, uint64_t Address, \
		const void *Decoder) \
	{ \
		unsigned Offset; \
		unsigned Base; \
		Offset = fieldFromInstruction_4(Insn, 0, 5); \
		Base = fieldFromInstruction_4(Insn, 5, 5); \
\
		Base = getReg(Inst, RegClass, Base); \
		Offset = getReg(Inst, RegClass, Offset); \
		MCOperand_CreateReg0(Inst, (Base)); \
		MCOperand_CreateReg0(Inst, (Offset)); \
\
		return MCDisassembler_Success; \
	}
DEFINE_DecodeMemNMRX(Mips_GPRNM3RegClassID);
DEFINE_DecodeMemNMRX(Mips_GPRNM32RegClassID);

static DecodeStatus DecodeMemNM4x4(MCInst *Inst, uint32_t Insn,
				   uint64_t Address, const void *Decoder)
{
	int Offset = fieldFromInstruction_4(Insn, 0, 4);
	unsigned Base;

	Base = getReg(Inst, Mips_GPRNM32RegClassID,
		      fieldFromInstruction_4(Insn, 4, 5) & ~0x8);

	MCOperand_CreateReg0(Inst, (Base));
	MCOperand_CreateImm0(Inst, (Offset));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeMemEVA(MCInst *Inst, uint32_t Insn, uint64_t Address,
				 const void *Decoder)
{
	int Offset = SignExtend32((Insn >> 7), 9);
	unsigned Reg = fieldFromInstruction_4(Insn, 16, 5);
	unsigned Base = fieldFromInstruction_4(Insn, 21, 5);

	Reg = getReg(Inst, Mips_GPR32RegClassID, Reg);
	Base = getReg(Inst, Mips_GPR32RegClassID, Base);

	if (MCInst_getOpcode(Inst) == Mips_SCE)
		MCOperand_CreateReg0(Inst, (Reg));

	MCOperand_CreateReg0(Inst, (Reg));
	MCOperand_CreateReg0(Inst, (Base));
	MCOperand_CreateImm0(Inst, (Offset));

	return MCDisassembler_Success;
}

#include "MipsCP0RegisterMap.h"

static DecodeStatus DecodeCOP0SelRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	int Reg = COP0Map_getEncIndexMap(RegNo);

	if (Reg != -1) {
		Reg = getReg(Inst, Mips_COP0SelRegClassID, Reg);
		MCOperand_CreateReg0(Inst, (Reg));
	} else {
		// Not a named register encoding - print numeric register and select value
		switch (MCInst_getOpcode(Inst)) {
		case Mips_MFC0Sel_NM:
			MCInst_setOpcode(Inst, (Mips_MFC0_NM));
			break;
		case Mips_MFHC0Sel_NM:
			MCInst_setOpcode(Inst, (Mips_MFHC0_NM));
			break;
		case Mips_MTC0Sel_NM:
			MCInst_setOpcode(Inst, (Mips_MTC0_NM));
			break;
		case Mips_MTHC0Sel_NM:
			MCInst_setOpcode(Inst, (Mips_MTHC0_NM));
			break;
		default:
			CS_ASSERT_RET_VAL(0 && "Unknown instruction!",
					  MCDisassembler_Fail);
			return MCDisassembler_Fail;
		}
		Reg = getReg(Inst, Mips_COP0RegClassID, RegNo >> 5);
		MCOperand_CreateReg0(Inst, (Reg));
		MCOperand_CreateImm0(Inst, (RegNo & 0x1f));
	}
	return MCDisassembler_Success;
}

static DecodeStatus DecodeLoadByte15(MCInst *Inst, uint32_t Insn,
				     uint64_t Address, const void *Decoder)
{
	int Offset = SignExtend32((Insn & 0xffff), 16);
	unsigned Base = fieldFromInstruction_4(Insn, 16, 5);
	unsigned Reg = fieldFromInstruction_4(Insn, 21, 5);

	Base = getReg(Inst, Mips_GPR32RegClassID, Base);
	Reg = getReg(Inst, Mips_GPR32RegClassID, Reg);

	MCOperand_CreateReg0(Inst, (Reg));
	MCOperand_CreateReg0(Inst, (Base));
	MCOperand_CreateImm0(Inst, (Offset));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeCacheOp(MCInst *Inst, uint32_t Insn, uint64_t Address,
				  const void *Decoder)
{
	int Offset = SignExtend32((Insn & 0xffff), 16);
	unsigned Hint = fieldFromInstruction_4(Insn, 16, 5);
	unsigned Base = fieldFromInstruction_4(Insn, 21, 5);

	Base = getReg(Inst, Mips_GPR32RegClassID, Base);

	MCOperand_CreateReg0(Inst, (Base));
	MCOperand_CreateImm0(Inst, (Offset));
	MCOperand_CreateImm0(Inst, (Hint));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeCacheOpMM(MCInst *Inst, uint32_t Insn,
				    uint64_t Address, const void *Decoder)
{
	int Offset = SignExtend32((Insn & 0xfff), 12);
	unsigned Base = fieldFromInstruction_4(Insn, 16, 5);
	unsigned Hint = fieldFromInstruction_4(Insn, 21, 5);

	Base = getReg(Inst, Mips_GPR32RegClassID, Base);

	MCOperand_CreateReg0(Inst, (Base));
	MCOperand_CreateImm0(Inst, (Offset));
	MCOperand_CreateImm0(Inst, (Hint));

	return MCDisassembler_Success;
}

static DecodeStatus DecodePrefeOpMM(MCInst *Inst, uint32_t Insn,
				    uint64_t Address, const void *Decoder)
{
	int Offset = SignExtend32((Insn & 0x1ff), 9);
	unsigned Base = fieldFromInstruction_4(Insn, 16, 5);
	unsigned Hint = fieldFromInstruction_4(Insn, 21, 5);

	Base = getReg(Inst, Mips_GPR32RegClassID, Base);

	MCOperand_CreateReg0(Inst, (Base));
	MCOperand_CreateImm0(Inst, (Offset));
	MCOperand_CreateImm0(Inst, (Hint));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeCacheeOp_CacheOpR6(MCInst *Inst, uint32_t Insn,
					     uint64_t Address,
					     const void *Decoder)
{
	int Offset = SignExtend32((Insn >> 7), 9);
	unsigned Hint = fieldFromInstruction_4(Insn, 16, 5);
	unsigned Base = fieldFromInstruction_4(Insn, 21, 5);

	Base = getReg(Inst, Mips_GPR32RegClassID, Base);

	MCOperand_CreateReg0(Inst, (Base));
	MCOperand_CreateImm0(Inst, (Offset));
	MCOperand_CreateImm0(Inst, (Hint));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeSyncI(MCInst *Inst, uint32_t Insn, uint64_t Address,
				const void *Decoder)
{
	int Offset = SignExtend32((Insn & 0xffff), 16);
	unsigned Base = fieldFromInstruction_4(Insn, 21, 5);

	Base = getReg(Inst, Mips_GPR32RegClassID, Base);

	MCOperand_CreateReg0(Inst, (Base));
	MCOperand_CreateImm0(Inst, (Offset));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeSyncI_MM(MCInst *Inst, uint32_t Insn,
				   uint64_t Address, const void *Decoder)
{
	int Offset = SignExtend32((Insn & 0xffff), 16);
	unsigned Base = fieldFromInstruction_4(Insn, 16, 5);

	Base = getReg(Inst, Mips_GPR32RegClassID, Base);

	MCOperand_CreateReg0(Inst, (Base));
	MCOperand_CreateImm0(Inst, (Offset));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeSynciR6(MCInst *Inst, uint32_t Insn, uint64_t Address,
				  const void *Decoder)
{
	int Immediate = SignExtend32((Insn & 0xffff), 16);
	unsigned Base = fieldFromInstruction_4(Insn, 16, 5);

	Base = getReg(Inst, Mips_GPR32RegClassID, Base);

	MCOperand_CreateReg0(Inst, (Base));
	MCOperand_CreateImm0(Inst, (Immediate));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeMSA128Mem(MCInst *Inst, uint32_t Insn,
				    uint64_t Address, const void *Decoder)
{
	int Offset = SignExtend32((fieldFromInstruction_4(Insn, 16, 10)), 10);
	unsigned Reg = fieldFromInstruction_4(Insn, 6, 5);
	unsigned Base = fieldFromInstruction_4(Insn, 11, 5);

	Reg = getReg(Inst, Mips_MSA128BRegClassID, Reg);
	Base = getReg(Inst, Mips_GPR32RegClassID, Base);

	MCOperand_CreateReg0(Inst, (Reg));
	MCOperand_CreateReg0(Inst, (Base));

	// The immediate field of an LD/ST instruction is scaled which means it must
	// be multiplied (when decoding) by the size (in bytes) of the instructions'
	// data format.
	// .b - 1 byte
	// .h - 2 bytes
	// .w - 4 bytes
	// .d - 8 bytes
	switch (MCInst_getOpcode(Inst)) {
	default:

		return MCDisassembler_Fail;
		break;
	case Mips_LD_B:
	case Mips_ST_B:
		MCOperand_CreateImm0(Inst, (Offset));
		break;
	case Mips_LD_H:
	case Mips_ST_H:
		MCOperand_CreateImm0(Inst, (Offset * 2));
		break;
	case Mips_LD_W:
	case Mips_ST_W:
		MCOperand_CreateImm0(Inst, (Offset * 4));
		break;
	case Mips_LD_D:
	case Mips_ST_D:
		MCOperand_CreateImm0(Inst, (Offset * 8));
		break;
	}

	return MCDisassembler_Success;
}

static DecodeStatus DecodeMemMMImm4(MCInst *Inst, uint32_t Insn,
				    uint64_t Address, const void *Decoder)
{
	unsigned Offset = Insn & 0xf;
	unsigned Reg = fieldFromInstruction_4(Insn, 7, 3);
	unsigned Base = fieldFromInstruction_4(Insn, 4, 3);

	switch (MCInst_getOpcode(Inst)) {
	case Mips_LBU16_MM:
	case Mips_LHU16_MM:
	case Mips_LW16_MM:
		if (DecodeGPRMM16RegisterClass(Inst, Reg, Address, Decoder) ==
		    MCDisassembler_Fail)
			return MCDisassembler_Fail;
		break;
	case Mips_SB16_MM:
	case Mips_SB16_MMR6:
	case Mips_SH16_MM:
	case Mips_SH16_MMR6:
	case Mips_SW16_MM:
	case Mips_SW16_MMR6:
		if (DecodeGPRMM16ZeroRegisterClass(
			    Inst, Reg, Address, Decoder) == MCDisassembler_Fail)
			return MCDisassembler_Fail;
		break;
	}

	if (DecodeGPRMM16RegisterClass(Inst, Base, Address, Decoder) ==
	    MCDisassembler_Fail)
		return MCDisassembler_Fail;

	switch (MCInst_getOpcode(Inst)) {
	case Mips_LBU16_MM:
		if (Offset == 0xf)
			MCOperand_CreateImm0(Inst, (-1));
		else
			MCOperand_CreateImm0(Inst, (Offset));
		break;
	case Mips_SB16_MM:
	case Mips_SB16_MMR6:
		MCOperand_CreateImm0(Inst, (Offset));
		break;
	case Mips_LHU16_MM:
	case Mips_SH16_MM:
	case Mips_SH16_MMR6:
		MCOperand_CreateImm0(Inst, (Offset << 1));
		break;
	case Mips_LW16_MM:
	case Mips_SW16_MM:
	case Mips_SW16_MMR6:
		MCOperand_CreateImm0(Inst, (Offset << 2));
		break;
	}

	return MCDisassembler_Success;
}

static DecodeStatus DecodeMemMMSPImm5Lsl2(MCInst *Inst, uint32_t Insn,
					  uint64_t Address, const void *Decoder)
{
	unsigned Offset = Insn & 0x1F;
	unsigned Reg = fieldFromInstruction_4(Insn, 5, 5);

	Reg = getReg(Inst, Mips_GPR32RegClassID, Reg);

	MCOperand_CreateReg0(Inst, (Reg));
	MCOperand_CreateReg0(Inst, (Mips_SP));
	MCOperand_CreateImm0(Inst, (Offset << 2));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeMemMMGPImm7Lsl2(MCInst *Inst, uint32_t Insn,
					  uint64_t Address, const void *Decoder)
{
	unsigned Offset = Insn & 0x7F;
	unsigned Reg = fieldFromInstruction_4(Insn, 7, 3);

	Reg = getReg(Inst, Mips_GPR32RegClassID, Reg);

	MCOperand_CreateReg0(Inst, (Reg));
	MCOperand_CreateReg0(Inst, (Mips_GP));
	MCOperand_CreateImm0(Inst, (Offset << 2));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeMemMMReglistImm4Lsl2(MCInst *Inst, uint32_t Insn,
					       uint64_t Address,
					       const void *Decoder)
{
	int Offset;
	switch (MCInst_getOpcode(Inst)) {
	case Mips_LWM16_MMR6:
	case Mips_SWM16_MMR6:
		Offset = fieldFromInstruction_4(Insn, 4, 4);
		break;
	default:
		Offset = SignExtend32((Insn & 0xf), 4);
		break;
	}

	if (DecodeRegListOperand16(Inst, Insn, Address, Decoder) ==
	    MCDisassembler_Fail)
		return MCDisassembler_Fail;

	MCOperand_CreateReg0(Inst, (Mips_SP));
	MCOperand_CreateImm0(Inst, (Offset << 2));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeMemMMImm9(MCInst *Inst, uint32_t Insn,
				    uint64_t Address, const void *Decoder)
{
	int Offset = SignExtend32((Insn & 0x1ff), 9);
	unsigned Reg = fieldFromInstruction_4(Insn, 21, 5);
	unsigned Base = fieldFromInstruction_4(Insn, 16, 5);

	Reg = getReg(Inst, Mips_GPR32RegClassID, Reg);
	Base = getReg(Inst, Mips_GPR32RegClassID, Base);

	if (MCInst_getOpcode(Inst) == Mips_SCE_MM ||
	    MCInst_getOpcode(Inst) == Mips_SC_MMR6)
		MCOperand_CreateReg0(Inst, (Reg));

	MCOperand_CreateReg0(Inst, (Reg));
	MCOperand_CreateReg0(Inst, (Base));
	MCOperand_CreateImm0(Inst, (Offset));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeMemMMImm12(MCInst *Inst, uint32_t Insn,
				     uint64_t Address, const void *Decoder)
{
	int Offset = SignExtend32((Insn & 0x0fff), 12);
	unsigned Reg = fieldFromInstruction_4(Insn, 21, 5);
	unsigned Base = fieldFromInstruction_4(Insn, 16, 5);

	Reg = getReg(Inst, Mips_GPR32RegClassID, Reg);
	Base = getReg(Inst, Mips_GPR32RegClassID, Base);

	switch (MCInst_getOpcode(Inst)) {
	case Mips_SWM32_MM:
	case Mips_LWM32_MM:
		if (DecodeRegListOperand(Inst, Insn, Address, Decoder) ==
		    MCDisassembler_Fail)
			return MCDisassembler_Fail;
		MCOperand_CreateReg0(Inst, (Base));
		MCOperand_CreateImm0(Inst, (Offset));
		break;
	case Mips_SC_MM:
		MCOperand_CreateReg0(Inst, (Reg));
		// fall through
	default:
		MCOperand_CreateReg0(Inst, (Reg));
		if (MCInst_getOpcode(Inst) == Mips_LWP_MM ||
		    MCInst_getOpcode(Inst) == Mips_SWP_MM)
			MCOperand_CreateReg0(Inst, (Reg + 1));

		MCOperand_CreateReg0(Inst, (Base));
		MCOperand_CreateImm0(Inst, (Offset));
	}

	return MCDisassembler_Success;
}

static DecodeStatus DecodeMemMMImm16(MCInst *Inst, uint32_t Insn,
				     uint64_t Address, const void *Decoder)
{
	int Offset = SignExtend32((Insn & 0xffff), 16);
	unsigned Reg = fieldFromInstruction_4(Insn, 21, 5);
	unsigned Base = fieldFromInstruction_4(Insn, 16, 5);

	Reg = getReg(Inst, Mips_GPR32RegClassID, Reg);
	Base = getReg(Inst, Mips_GPR32RegClassID, Base);

	MCOperand_CreateReg0(Inst, (Reg));
	MCOperand_CreateReg0(Inst, (Base));
	MCOperand_CreateImm0(Inst, (Offset));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeFMem(MCInst *Inst, uint32_t Insn, uint64_t Address,
			       const void *Decoder)
{
	int Offset = SignExtend32((Insn & 0xffff), 16);
	unsigned Reg = fieldFromInstruction_4(Insn, 16, 5);
	unsigned Base = fieldFromInstruction_4(Insn, 21, 5);

	Reg = getReg(Inst, Mips_FGR64RegClassID, Reg);
	Base = getReg(Inst, Mips_GPR32RegClassID, Base);

	MCOperand_CreateReg0(Inst, (Reg));
	MCOperand_CreateReg0(Inst, (Base));
	MCOperand_CreateImm0(Inst, (Offset));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeFMemMMR2(MCInst *Inst, uint32_t Insn,
				   uint64_t Address, const void *Decoder)
{
	// This function is the same as DecodeFMem but with the Reg and Base fields
	// swapped according to microMIPS spec.
	int Offset = SignExtend32((Insn & 0xffff), 16);
	unsigned Base = fieldFromInstruction_4(Insn, 16, 5);
	unsigned Reg = fieldFromInstruction_4(Insn, 21, 5);

	Reg = getReg(Inst, Mips_FGR64RegClassID, Reg);
	Base = getReg(Inst, Mips_GPR32RegClassID, Base);

	MCOperand_CreateReg0(Inst, (Reg));
	MCOperand_CreateReg0(Inst, (Base));
	MCOperand_CreateImm0(Inst, (Offset));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeFMem2(MCInst *Inst, uint32_t Insn, uint64_t Address,
				const void *Decoder)
{
	int Offset = SignExtend32((Insn & 0xffff), 16);
	unsigned Reg = fieldFromInstruction_4(Insn, 16, 5);
	unsigned Base = fieldFromInstruction_4(Insn, 21, 5);

	Reg = getReg(Inst, Mips_COP2RegClassID, Reg);
	Base = getReg(Inst, Mips_GPR32RegClassID, Base);

	MCOperand_CreateReg0(Inst, (Reg));
	MCOperand_CreateReg0(Inst, (Base));
	MCOperand_CreateImm0(Inst, (Offset));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeFMem3(MCInst *Inst, uint32_t Insn, uint64_t Address,
				const void *Decoder)
{
	int Offset = SignExtend32((Insn & 0xffff), 16);
	unsigned Reg = fieldFromInstruction_4(Insn, 16, 5);
	unsigned Base = fieldFromInstruction_4(Insn, 21, 5);

	Reg = getReg(Inst, Mips_COP3RegClassID, Reg);
	Base = getReg(Inst, Mips_GPR32RegClassID, Base);

	MCOperand_CreateReg0(Inst, (Reg));
	MCOperand_CreateReg0(Inst, (Base));
	MCOperand_CreateImm0(Inst, (Offset));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeFMemCop2R6(MCInst *Inst, uint32_t Insn,
				     uint64_t Address, const void *Decoder)
{
	int Offset = SignExtend32((Insn & 0x07ff), 11);
	unsigned Reg = fieldFromInstruction_4(Insn, 16, 5);
	unsigned Base = fieldFromInstruction_4(Insn, 11, 5);

	Reg = getReg(Inst, Mips_COP2RegClassID, Reg);
	Base = getReg(Inst, Mips_GPR32RegClassID, Base);

	MCOperand_CreateReg0(Inst, (Reg));
	MCOperand_CreateReg0(Inst, (Base));
	MCOperand_CreateImm0(Inst, (Offset));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeFMemCop2MMR6(MCInst *Inst, uint32_t Insn,
				       uint64_t Address, const void *Decoder)
{
	int Offset = SignExtend32((Insn & 0x07ff), 11);
	unsigned Reg = fieldFromInstruction_4(Insn, 21, 5);
	unsigned Base = fieldFromInstruction_4(Insn, 16, 5);

	Reg = getReg(Inst, Mips_COP2RegClassID, Reg);
	Base = getReg(Inst, Mips_GPR32RegClassID, Base);

	MCOperand_CreateReg0(Inst, (Reg));
	MCOperand_CreateReg0(Inst, (Base));
	MCOperand_CreateImm0(Inst, (Offset));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeSpecial3LlSc(MCInst *Inst, uint32_t Insn,
				       uint64_t Address, const void *Decoder)
{
	int64_t Offset = SignExtend64(((Insn >> 7) & 0x1ff), 9);
	unsigned Rt = fieldFromInstruction_4(Insn, 16, 5);
	unsigned Base = fieldFromInstruction_4(Insn, 21, 5);

	Rt = getReg(Inst, Mips_GPR32RegClassID, Rt);
	Base = getReg(Inst, Mips_GPR32RegClassID, Base);

	if (MCInst_getOpcode(Inst) == Mips_SC_R6 ||
	    MCInst_getOpcode(Inst) == Mips_SCD_R6) {
		MCOperand_CreateReg0(Inst, (Rt));
	}

	MCOperand_CreateReg0(Inst, (Rt));
	MCOperand_CreateReg0(Inst, (Base));
	MCOperand_CreateImm0(Inst, (Offset));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeHWRegsRegisterClass(MCInst *Inst, unsigned RegNo,
					      uint64_t Address,
					      const void *Decoder)
{
	// Currently only hardware register 29 is supported.
	if (RegNo != 29)
		return MCDisassembler_Fail;
	MCOperand_CreateReg0(Inst, (Mips_HWR29));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeAFGR64RegisterClass(MCInst *Inst, unsigned RegNo,
					      uint64_t Address,
					      const void *Decoder)
{
	if (RegNo > 30 || RegNo % 2)
		return MCDisassembler_Fail;

	unsigned Reg = getReg(Inst, Mips_AFGR64RegClassID, RegNo / 2);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeACC64DSPRegisterClass(MCInst *Inst, unsigned RegNo,
						uint64_t Address,
						const void *Decoder)
{
	if (RegNo >= 4)
		return MCDisassembler_Fail;

	unsigned Reg = getReg(Inst, Mips_ACC64DSPRegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeHI32DSPRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	if (RegNo >= 4)
		return MCDisassembler_Fail;

	unsigned Reg = getReg(Inst, Mips_HI32DSPRegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeLO32DSPRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	if (RegNo >= 4)
		return MCDisassembler_Fail;

	unsigned Reg = getReg(Inst, Mips_LO32DSPRegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeMSA128BRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;

	unsigned Reg = getReg(Inst, Mips_MSA128BRegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeMSA128HRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;

	unsigned Reg = getReg(Inst, Mips_MSA128HRegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeMSA128WRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;

	unsigned Reg = getReg(Inst, Mips_MSA128WRegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeMSA128DRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;

	unsigned Reg = getReg(Inst, Mips_MSA128DRegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeMSACtrlRegisterClass(MCInst *Inst, unsigned RegNo,
					       uint64_t Address,
					       const void *Decoder)
{
	if (RegNo > 7)
		return MCDisassembler_Fail;

	unsigned Reg = getReg(Inst, Mips_MSACtrlRegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeCOP0RegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;

	unsigned Reg = getReg(Inst, Mips_COP0RegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeCOP2RegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;

	unsigned Reg = getReg(Inst, Mips_COP2RegClassID, RegNo);
	MCOperand_CreateReg0(Inst, (Reg));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeBranchTarget(MCInst *Inst, unsigned Offset,
				       uint64_t Address, const void *Decoder)
{
	int32_t BranchOffset = (SignExtend32((Offset), 16) * 4) + 4;
	MCOperand_CreateImm0(Inst, (BranchOffset));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeBranchTarget1SImm16(MCInst *Inst, unsigned Offset,
					      uint64_t Address,
					      const void *Decoder)
{
	int32_t BranchOffset = (SignExtend32((Offset), 16) * 2);
	MCOperand_CreateImm0(Inst, (BranchOffset));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeJumpTarget(MCInst *Inst, uint32_t Insn,
				     uint64_t Address, const void *Decoder)
{
	unsigned JumpOffset = fieldFromInstruction_4(Insn, 0, 26) << 2;
	MCOperand_CreateImm0(Inst, (JumpOffset));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeBranchTarget21(MCInst *Inst, unsigned Offset,
					 uint64_t Address, const void *Decoder)
{
	int32_t BranchOffset = SignExtend32((Offset), 21) * 4 + 4;

	MCOperand_CreateImm0(Inst, (BranchOffset));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeBranchTarget21MM(MCInst *Inst, unsigned Offset,
					   uint64_t Address,
					   const void *Decoder)
{
	int32_t BranchOffset = SignExtend32((Offset), 21) * 4 + 4;

	MCOperand_CreateImm0(Inst, (BranchOffset));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeBranchTarget26(MCInst *Inst, unsigned Offset,
					 uint64_t Address, const void *Decoder)
{
	int32_t BranchOffset = SignExtend32((Offset), 26) * 4 + 4;

	MCOperand_CreateImm0(Inst, (BranchOffset));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeBranchTarget7MM(MCInst *Inst, unsigned Offset,
					  uint64_t Address, const void *Decoder)
{
	int32_t BranchOffset = SignExtend32((Offset << 1), 8);
	MCOperand_CreateImm0(Inst, (BranchOffset));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeBranchTarget10MM(MCInst *Inst, unsigned Offset,
					   uint64_t Address,
					   const void *Decoder)
{
	int32_t BranchOffset = SignExtend32((Offset << 1), 11);
	MCOperand_CreateImm0(Inst, (BranchOffset));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeBranchTargetMM(MCInst *Inst, unsigned Offset,
					 uint64_t Address, const void *Decoder)
{
	int32_t BranchOffset = SignExtend32((Offset), 16) * 2 + 4;
	MCOperand_CreateImm0(Inst, (BranchOffset));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeBranchTarget26MM(MCInst *Inst, unsigned Offset,
					   uint64_t Address,
					   const void *Decoder)
{
	int32_t BranchOffset = SignExtend32((Offset << 1), 27);

	MCOperand_CreateImm0(Inst, (BranchOffset));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeJumpTargetMM(MCInst *Inst, uint32_t Insn,
				       uint64_t Address, const void *Decoder)
{
	unsigned JumpOffset = fieldFromInstruction_4(Insn, 0, 26) << 1;
	MCOperand_CreateImm0(Inst, (JumpOffset));
	return MCDisassembler_Success;
}

#define DEFINE_DecodeBranchTargetNM(Bits) \
	static DecodeStatus CONCAT(DecodeBranchTargetNM, Bits)( \
		MCInst * Inst, unsigned Offset, uint64_t Address, \
		const void *Decoder) \
	{ \
		uint32_t InsnSize = (Bits <= 10) ? 2 : 4; \
		int32_t BranchOffset = \
			SignExtend32((Offset), Bits + 1) + InsnSize; \
\
		MCOperand_CreateImm0(Inst, (BranchOffset)); \
		return MCDisassembler_Success; \
	}
DEFINE_DecodeBranchTargetNM(10);
DEFINE_DecodeBranchTargetNM(7);
DEFINE_DecodeBranchTargetNM(21);
DEFINE_DecodeBranchTargetNM(25);
DEFINE_DecodeBranchTargetNM(14);
DEFINE_DecodeBranchTargetNM(11);
DEFINE_DecodeBranchTargetNM(5);

static DecodeStatus DecodeJumpTargetXMM(MCInst *Inst, uint32_t Insn,
					uint64_t Address, const void *Decoder)
{
	unsigned JumpOffset = fieldFromInstruction_4(Insn, 0, 26) << 2;
	MCOperand_CreateImm0(Inst, (JumpOffset));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeAddiur2Simm7(MCInst *Inst, unsigned Value,
				       uint64_t Address, const void *Decoder)
{
	if (Value == 0)
		MCOperand_CreateImm0(Inst, (1));
	else if (Value == 0x7)
		MCOperand_CreateImm0(Inst, (-1));
	else
		MCOperand_CreateImm0(Inst, (Value << 2));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeLi16Imm(MCInst *Inst, unsigned Value,
				  uint64_t Address, const void *Decoder)
{
	if (Value == 0x7F)
		MCOperand_CreateImm0(Inst, (-1));
	else
		MCOperand_CreateImm0(Inst, (Value));
	return MCDisassembler_Success;
}

static DecodeStatus DecodePOOL16BEncodedField(MCInst *Inst, unsigned Value,
					      uint64_t Address,
					      const void *Decoder)
{
	MCOperand_CreateImm0(Inst, (Value == 0x0 ? 8 : Value));
	return MCDisassembler_Success;
}

#define DEFINE_DecodeUImmWithOffsetAndScale(Bits, Offset, Scale) \
	static DecodeStatus CONCAT(DecodeUImmWithOffsetAndScale, \
				   CONCAT(Bits, CONCAT(Offset, Scale)))( \
		MCInst * Inst, unsigned Value, uint64_t Address, \
		const void *Decoder) \
	{ \
		Value &= ((1 << Bits) - 1); \
		Value *= Scale; \
		MCOperand_CreateImm0(Inst, (Value + Offset)); \
		return MCDisassembler_Success; \
	}
DEFINE_DecodeUImmWithOffsetAndScale(5, 0, 4);
DEFINE_DecodeUImmWithOffsetAndScale(6, 0, 4);
DEFINE_DecodeUImmWithOffsetAndScale(2, 1, 1);
DEFINE_DecodeUImmWithOffsetAndScale(5, 1, 1);
DEFINE_DecodeUImmWithOffsetAndScale(8, 0, 1);
DEFINE_DecodeUImmWithOffsetAndScale(18, 0, 1);
DEFINE_DecodeUImmWithOffsetAndScale(21, 0, 1);

#define DEFINE_DecodeSImmWithOffsetAndScale(Bits, Offset, ScaleBy) \
	static DecodeStatus CONCAT(DecodeSImmWithOffsetAndScale, \
				   CONCAT(Bits, CONCAT(Offset, ScaleBy)))( \
		MCInst * Inst, unsigned Value, uint64_t Address, \
		const void *Decoder) \
	{ \
		int32_t Imm = SignExtend32((Value), Bits) * ScaleBy; \
		MCOperand_CreateImm0(Inst, (Imm + Offset)); \
		return MCDisassembler_Success; \
	}

#define DEFINE_DecodeSImmWithOffsetAndScale_2(Bits, Offset) \
	DEFINE_DecodeSImmWithOffsetAndScale(Bits, Offset, 1)
#define DEFINE_DecodeSImmWithOffsetAndScale_3(Bits) \
	DEFINE_DecodeSImmWithOffsetAndScale(Bits, 0, 1)

DEFINE_DecodeSImmWithOffsetAndScale_3(16);
DEFINE_DecodeSImmWithOffsetAndScale_3(10);
DEFINE_DecodeSImmWithOffsetAndScale_3(4);
DEFINE_DecodeSImmWithOffsetAndScale_3(6);
DEFINE_DecodeSImmWithOffsetAndScale_3(32);

static DecodeStatus DecodeInsSize(MCInst *Inst, uint32_t Insn, uint64_t Address,
				  const void *Decoder)
{
	// First we need to grab the pos(lsb) from MCInst.
	// This function only handles the 32 bit variants of ins, as dins
	// variants are handled differently.
	int Pos = MCOperand_getImm(MCInst_getOperand(Inst, (2)));
	int Size = (int)Insn - Pos + 1;
	MCOperand_CreateImm0(Inst, (SignExtend32((Size), 16)));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeSimm19Lsl2(MCInst *Inst, uint32_t Insn,
				     uint64_t Address, const void *Decoder)
{
	MCOperand_CreateImm0(Inst, (SignExtend32((Insn), 19) * 4));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeSimm18Lsl3(MCInst *Inst, uint32_t Insn,
				     uint64_t Address, const void *Decoder)
{
	MCOperand_CreateImm0(Inst, (SignExtend32((Insn), 18) * 8));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeSimm9SP(MCInst *Inst, uint32_t Insn, uint64_t Address,
				  const void *Decoder)
{
	int32_t DecodedValue;
	switch (Insn) {
	case 0:
		DecodedValue = 256;
		break;
	case 1:
		DecodedValue = 257;
		break;
	case 510:
		DecodedValue = -258;
		break;
	case 511:
		DecodedValue = -257;
		break;
	default:
		DecodedValue = SignExtend32((Insn), 9);
		break;
	}
	MCOperand_CreateImm0(Inst, (DecodedValue * 4));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeANDI16Imm(MCInst *Inst, uint32_t Insn,
				    uint64_t Address, const void *Decoder)
{
	// Insn must be >= 0, since it is unsigned that condition is always true.

	int32_t DecodedValues[] = { 128, 1,  2,	 3,  4,	 7,   8,     15,
				    16,	 31, 32, 63, 64, 255, 32768, 65535 };
	MCOperand_CreateImm0(Inst, (DecodedValues[Insn]));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeRegListOperand(MCInst *Inst, uint32_t Insn,
					 uint64_t Address, const void *Decoder)
{
	unsigned Regs[] = { Mips_S0, Mips_S1, Mips_S2, Mips_S3, Mips_S4,
			    Mips_S5, Mips_S6, Mips_S7, Mips_FP };
	unsigned RegNum;

	unsigned RegLst = fieldFromInstruction_4(Insn, 21, 5);

	// Empty register lists are not allowed.
	if (RegLst == 0)
		return MCDisassembler_Fail;

	RegNum = RegLst & 0xf;

	// RegLst values 10-15, and 26-31 are reserved.
	if (RegNum > 9)
		return MCDisassembler_Fail;

	for (unsigned i = 0; i < RegNum; i++)
		MCOperand_CreateReg0(Inst, (Regs[i]));

	if (RegLst & 0x10)
		MCOperand_CreateReg0(Inst, (Mips_RA));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeRegListOperand16(MCInst *Inst, uint32_t Insn,
					   uint64_t Address,
					   const void *Decoder)
{
	unsigned Regs[] = { Mips_S0, Mips_S1, Mips_S2, Mips_S3 };
	unsigned RegLst;
	switch (MCInst_getOpcode(Inst)) {
	default:
		RegLst = fieldFromInstruction_4(Insn, 4, 2);
		break;
	case Mips_LWM16_MMR6:
	case Mips_SWM16_MMR6:
		RegLst = fieldFromInstruction_4(Insn, 8, 2);
		break;
	}
	unsigned RegNum = RegLst & 0x3;

	for (unsigned i = 0; i <= RegNum; i++)
		MCOperand_CreateReg0(Inst, (Regs[i]));

	MCOperand_CreateReg0(Inst, (Mips_RA));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeMovePOperands(MCInst *Inst, uint32_t Insn,
					uint64_t Address, const void *Decoder)
{
	unsigned RegPair = fieldFromInstruction_4(Insn, 7, 3);
	if (DecodeMovePRegPair(Inst, RegPair, Address, Decoder) ==
	    MCDisassembler_Fail)
		return MCDisassembler_Fail;

	unsigned RegRs;
	if (Inst->csh->mode & CS_MODE_MIPS32R6)
		RegRs = fieldFromInstruction_4(Insn, 0, 2) |
			(fieldFromInstruction_4(Insn, 3, 1) << 2);
	else
		RegRs = fieldFromInstruction_4(Insn, 1, 3);
	if (DecodeGPRMM16MovePRegisterClass(Inst, RegRs, Address, Decoder) ==
	    MCDisassembler_Fail)
		return MCDisassembler_Fail;

	unsigned RegRt = fieldFromInstruction_4(Insn, 4, 3);
	if (DecodeGPRMM16MovePRegisterClass(Inst, RegRt, Address, Decoder) ==
	    MCDisassembler_Fail)
		return MCDisassembler_Fail;

	return MCDisassembler_Success;
}

static DecodeStatus DecodeMovePRegPair(MCInst *Inst, unsigned RegPair,
				       uint64_t Address, const void *Decoder)
{
	switch (RegPair) {
	default:
		return MCDisassembler_Fail;
	case 0:
		MCOperand_CreateReg0(Inst, (Mips_A1));
		MCOperand_CreateReg0(Inst, (Mips_A2));
		break;
	case 1:
		MCOperand_CreateReg0(Inst, (Mips_A1));
		MCOperand_CreateReg0(Inst, (Mips_A3));
		break;
	case 2:
		MCOperand_CreateReg0(Inst, (Mips_A2));
		MCOperand_CreateReg0(Inst, (Mips_A3));
		break;
	case 3:
		MCOperand_CreateReg0(Inst, (Mips_A0));
		MCOperand_CreateReg0(Inst, (Mips_S5));
		break;
	case 4:
		MCOperand_CreateReg0(Inst, (Mips_A0));
		MCOperand_CreateReg0(Inst, (Mips_S6));
		break;
	case 5:
		MCOperand_CreateReg0(Inst, (Mips_A0));
		MCOperand_CreateReg0(Inst, (Mips_A1));
		break;
	case 6:
		MCOperand_CreateReg0(Inst, (Mips_A0));
		MCOperand_CreateReg0(Inst, (Mips_A2));
		break;
	case 7:
		MCOperand_CreateReg0(Inst, (Mips_A0));
		MCOperand_CreateReg0(Inst, (Mips_A3));
		break;
	}

	return MCDisassembler_Success;
}

static DecodeStatus DecodeSimm23Lsl2(MCInst *Inst, uint32_t Insn,
				     uint64_t Address, const void *Decoder)
{
	MCOperand_CreateImm0(Inst, (SignExtend32((Insn << 2), 25)));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeBgtzGroupBranchMMR6(MCInst *MI, uint32_t insn,
					      uint64_t Address,
					      const void *Decoder)
{
	// We have:
	//    0b000111 ttttt sssss iiiiiiiiiiiiiiii
	//      Invalid      if rt == 0
	//      BGTZALC_MMR6 if rs == 0 && rt != 0
	//      BLTZALC_MMR6 if rs != 0 && rs == rt
	//      BLTUC_MMR6   if rs != 0 && rs != rt

	uint32_t Rt = fieldFromInstruction_4(insn, 21, 5);
	uint32_t Rs = fieldFromInstruction_4(insn, 16, 5);
	uint32_t Imm = 0;
	bool HasRs = false;
	bool HasRt = false;

	if (Rt == 0)
		return MCDisassembler_Fail;
	else if (Rs == 0) {
		MCInst_setOpcode(MI, (Mips_BGTZALC_MMR6));
		HasRt = true;
		Imm = SignExtend64(fieldFromInstruction_4(insn, 0, 16), 16) *
			      2 +
		      4;
	} else if (Rs == Rt) {
		MCInst_setOpcode(MI, (Mips_BLTZALC_MMR6));
		HasRs = true;
		Imm = SignExtend64(fieldFromInstruction_4(insn, 0, 16), 16) *
			      2 +
		      4;
	} else {
		MCInst_setOpcode(MI, (Mips_BLTUC_MMR6));
		HasRs = true;
		HasRt = true;
		Imm = SignExtend64(fieldFromInstruction_4(insn, 0, 16), 16) *
			      4 +
		      4;
	}

	if (HasRs)
		MCOperand_CreateReg0(MI,
				     (getReg(MI, Mips_GPR32RegClassID, Rs)));

	if (HasRt)
		MCOperand_CreateReg0(MI,
				     (getReg(MI, Mips_GPR32RegClassID, Rt)));

	MCOperand_CreateImm0(MI, (Imm));

	return MCDisassembler_Success;
}

static DecodeStatus DecodeBlezGroupBranchMMR6(MCInst *MI, uint32_t insn,
					      uint64_t Address,
					      const void *Decoder)
{
	// We have:
	//    0b000110 ttttt sssss iiiiiiiiiiiiiiii
	//      Invalid        if rt == 0
	//      BLEZALC_MMR6   if rs == 0  && rt != 0
	//      BGEZALC_MMR6   if rs == rt && rt != 0
	//      BGEUC_MMR6     if rs != rt && rs != 0  && rt != 0

	uint32_t Rt = fieldFromInstruction_4(insn, 21, 5);
	uint32_t Rs = fieldFromInstruction_4(insn, 16, 5);
	uint32_t Imm = 0;
	bool HasRs = false;

	if (Rt == 0)
		return MCDisassembler_Fail;
	else if (Rs == 0) {
		MCInst_setOpcode(MI, (Mips_BLEZALC_MMR6));
		Imm = SignExtend64(fieldFromInstruction_4(insn, 0, 16), 16) *
			      2 +
		      4;
	} else if (Rs == Rt) {
		MCInst_setOpcode(MI, (Mips_BGEZALC_MMR6));
		Imm = SignExtend64(fieldFromInstruction_4(insn, 0, 16), 16) *
			      2 +
		      4;
	} else {
		HasRs = true;
		MCInst_setOpcode(MI, (Mips_BGEUC_MMR6));
		Imm = SignExtend64(fieldFromInstruction_4(insn, 0, 16), 16) *
			      4 +
		      4;
	}

	if (HasRs)
		MCOperand_CreateReg0(MI,
				     (getReg(MI, Mips_GPR32RegClassID, Rs)));
	MCOperand_CreateReg0(MI, (getReg(MI, Mips_GPR32RegClassID, Rt)));

	MCOperand_CreateImm0(MI, (Imm));

	return MCDisassembler_Success;
}

// This instruction does not have a working decoder, and needs to be
// fixed. This "fixme" function was introduced to keep the backend compiling,
// while making changes to tablegen code.
static DecodeStatus DecodeFIXMEInstruction(MCInst *Inst, uint32_t Insn,
					   uint64_t Address,
					   const void *Decoder)
{
	return MCDisassembler_Fail;
}

static DecodeStatus DecodeImmM1To126(MCInst *Inst, unsigned Value,
				     uint64_t Address, const void *Decoder)
{
	if (Value == 127)
		MCOperand_CreateImm0(Inst, (-1));
	else
		MCOperand_CreateImm0(Inst, (Value));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeUImm4Mask(MCInst *Inst, unsigned Value,
				    uint64_t Address, const void *Decoder)
{
	if (Value == 12)
		MCOperand_CreateImm0(Inst, (0xff));
	else if (Value == 13)
		MCOperand_CreateImm0(Inst, (0xffff));
	else
		MCOperand_CreateImm0(Inst, (Value));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeUImm3Shift(MCInst *Inst, unsigned Value,
				     uint64_t Address, const void *Decoder)
{
	if (Value == 0)
		MCOperand_CreateImm0(Inst, (8));
	else
		MCOperand_CreateImm0(Inst, (Value));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeNMRegListOperand(MCInst *Inst, uint32_t Insn,
					   uint64_t Address,
					   const void *Decoder)
{
	unsigned RegStart = fieldFromInstruction_4(Insn, 5, 5);
	unsigned RegCount = fieldFromInstruction_4(Insn, 1, 4);
	unsigned GP_bit = fieldFromInstruction_4(Insn, 0, 1);
	unsigned i;
	unsigned RegNo;

	MCOperand_CreateReg0(Inst,
			     (getReg(Inst, Mips_GPRNM32RegClassID, RegStart)));
	for (i = RegStart + 1; i < RegStart + RegCount; i++) {
		if (i == RegStart + RegCount - 1 && GP_bit)
			RegNo = 28;
		else if (i > 31)
			RegNo = 16 + (i % 32); // $ra+1 wraps to $s0
		else
			RegNo = i;
		MCOperand_CreateReg0(
			Inst, (getReg(Inst, Mips_GPRNM32RegClassID, RegNo)));
	}
	return MCDisassembler_Success;
}

static DecodeStatus DecodeNMRegList16Operand(MCInst *Inst, uint32_t Insn,
					     uint64_t Address,
					     const void *Decoder)
{
	unsigned RegStart = 30 + fieldFromInstruction_4(Insn, 4, 1);
	unsigned RegCount = fieldFromInstruction_4(Insn, 0, 4);
	// Re-encode the parameters for 32-bit instruction operand
	// and call it's decoder
	return DecodeNMRegListOperand(Inst, (RegStart << 5) | (RegCount << 1),
				      Address, Decoder);
}

static DecodeStatus DecodeNegImm12(MCInst *Inst, uint32_t Insn,
				   uint64_t Address, const void *Decoder)
{
	int Imm = fieldFromInstruction_4(Insn, 0, 12);

	MCOperand_CreateImm0(Inst, (-Imm));
	return MCDisassembler_Success;
}

#define DEFINE_DecodeSImmWithReg(Bits, Offset, Scale, RegNum) \
	static DecodeStatus CONCAT( \
		DecodeSImmWithReg, \
		CONCAT(Bits, CONCAT(Offset, CONCAT(Scale, RegNum))))( \
		MCInst * Inst, unsigned Value, uint64_t Address, \
		const void *Decoder) \
	{ \
		MCOperand_CreateReg0(Inst, (RegNum)); \
		return CONCAT(DecodeSImmWithOffsetAndScale, \
			      CONCAT(Bits, CONCAT(Offset, Scale)))( \
			Inst, Value, Address, Decoder); \
	}
DEFINE_DecodeSImmWithReg(32, 0, 1, Mips_GP_NM);

#define DEFINE_DecodeUImmWithReg(Bits, Offset, Scale, RegNum) \
	static DecodeStatus CONCAT( \
		DecodeUImmWithReg, \
		CONCAT(Bits, CONCAT(Offset, CONCAT(Scale, RegNum))))( \
		MCInst * Inst, unsigned Value, uint64_t Address, \
		const void *Decoder) \
	{ \
		MCOperand_CreateReg0(Inst, (RegNum)); \
		return CONCAT(DecodeUImmWithOffsetAndScale, \
			      CONCAT(Bits, CONCAT(Offset, Scale)))( \
			Inst, Value, Address, Decoder); \
	}
DEFINE_DecodeUImmWithReg(8, 0, 1, Mips_SP_NM);
DEFINE_DecodeUImmWithReg(21, 0, 1, Mips_GP_NM);
DEFINE_DecodeUImmWithReg(18, 0, 1, Mips_GP_NM);

static DecodeStatus DecodeSImm32s12(MCInst *Inst, uint32_t Insn,
				    uint64_t Address, const void *Decoder)
{
	uint64_t Imm = ((uint64_t)Insn) << 12;
	MCOperand_CreateImm0(Inst, (Imm));
	return MCDisassembler_Success;
}

#define DEFINE_DecodeAddressPCRelNM(Bits) \
	static DecodeStatus CONCAT(DecodeAddressPCRelNM, Bits)( \
		MCInst * Inst, unsigned Offset, uint64_t Address, \
		const void *Decoder) \
	{ \
		uint32_t InsnSize = Bits == 32 ? 6 : 4; \
		int32_t BranchOffset = \
			SignExtend32((Offset), Bits) + InsnSize; \
\
		MCOperand_CreateImm0(Inst, (BranchOffset)); \
		return MCDisassembler_Success; \
	}
DEFINE_DecodeAddressPCRelNM(22);
DEFINE_DecodeAddressPCRelNM(32);

static DecodeStatus DecodeBranchConflictNM(MCInst *Inst, uint32_t Insn,
					   uint64_t Address,
					   const void *Decoder)
{
	unsigned Rt = fieldFromInstruction_4(Insn, 7, 3);
	unsigned Rs = fieldFromInstruction_4(Insn, 4, 3);
	unsigned Offset = fieldFromInstruction_4(Insn, 0, 4) << 1;
	if (Rs < Rt)
		MCInst_setOpcode(Inst, (Mips_BEQC16_NM));
	else
		MCInst_setOpcode(Inst, (Mips_BNEC16_NM));
	if (DecodeGPRNM3RegisterClass(Inst, Rt, Address, Decoder) ==
		    MCDisassembler_Success &&
	    DecodeGPRNM3RegisterClass(Inst, Rs, Address, Decoder) ==
		    MCDisassembler_Success)
		return CONCAT(DecodeBranchTargetNM, 5)(Inst, Offset, Address,
						       Decoder);
	else
		return MCDisassembler_Fail;
}

DecodeStatus Mips_LLVM_getInstruction(MCInst *Instr, uint64_t *Size,
				      const uint8_t *Bytes, size_t BytesLen,
				      uint64_t Address, SStream *CStream)
{
	return getInstruction(Instr, Size, Bytes, BytesLen, Address, CStream);
}

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

//===-- AArch64InstPrinter.h - Convert AArch64 MCInst to assembly syntax --===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This class prints an AArch64 MCInst to a .s file.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_AARCH64_MCTARGETDESC_AARCH64INSTPRINTER_H
#define LLVM_LIB_TARGET_AARCH64_MCTARGETDESC_AARCH64INSTPRINTER_H

#include <capstone/platform.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "AArch64Mapping.h"

#include "../../MCInst.h"
#include "../../MCInstPrinter.h"
#include "../../MCRegisterInfo.h"
#include "../../SStream.h"
#include "../../utils.h"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b
#define CHAR(c) #c[0]

void printInst(MCInst *MI, uint64_t Address, const char *Annot, SStream *O);
void printRegName(SStream *OS, unsigned Reg);
void printRegNameAlt(SStream *OS, unsigned Reg, unsigned AltIdx);
// Autogenerated by tblgen.
const char *getRegName(unsigned Reg);
bool printSysAlias(MCInst *MI, SStream *O);
bool printSyspAlias(MCInst *MI, SStream *O);
bool printRangePrefetchAlias(MCInst *MI, SStream *O, const char *Annot);
// Operand printers
void printOperand(MCInst *MI, unsigned OpNo, SStream *O);
void printImm(MCInst *MI, unsigned OpNo, SStream *O);
void printImmHex(MCInst *MI, unsigned OpNo, SStream *O);
#define DECLARE_printSImm(Size) \
	void CONCAT(printSImm, Size)(MCInst * MI, unsigned OpNo, SStream *O);
DECLARE_printSImm(16);
DECLARE_printSImm(8);

#define DECLARE_printImmSVE(T) void CONCAT(printImmSVE, T)(T Val, SStream * O);
DECLARE_printImmSVE(int16_t);
DECLARE_printImmSVE(int8_t);
DECLARE_printImmSVE(int64_t);
DECLARE_printImmSVE(int32_t);
DECLARE_printImmSVE(uint16_t);
DECLARE_printImmSVE(uint8_t);
DECLARE_printImmSVE(uint64_t);
DECLARE_printImmSVE(uint32_t);

void printPostIncOperand(MCInst *MI, unsigned OpNo, unsigned Imm, SStream *O);
#define DEFINE_printPostIncOperand(Amount) \
	static inline void CONCAT(printPostIncOperand, Amount)( \
		MCInst * MI, unsigned OpNo, SStream *O) \
	{ \
		add_cs_detail(MI, \
			      CONCAT(AArch64_OP_GROUP_PostIncOperand, Amount), \
			      OpNo, Amount); \
		printPostIncOperand(MI, OpNo, Amount, O); \
	}
DEFINE_printPostIncOperand(64);
DEFINE_printPostIncOperand(32);
DEFINE_printPostIncOperand(16);
DEFINE_printPostIncOperand(8);
DEFINE_printPostIncOperand(1);
DEFINE_printPostIncOperand(4);
DEFINE_printPostIncOperand(2);
DEFINE_printPostIncOperand(48);
DEFINE_printPostIncOperand(24);
DEFINE_printPostIncOperand(3);
DEFINE_printPostIncOperand(12);
DEFINE_printPostIncOperand(6);

void printVRegOperand(MCInst *MI, unsigned OpNo, SStream *O);
void printSysCROperand(MCInst *MI, unsigned OpNo, SStream *O);
void printAddSubImm(MCInst *MI, unsigned OpNum, SStream *O);
#define DECLARE_printLogicalImm(T) \
	void CONCAT(printLogicalImm, T)(MCInst * MI, unsigned OpNum, \
					SStream *O);
DECLARE_printLogicalImm(int64_t);
DECLARE_printLogicalImm(int32_t);
DECLARE_printLogicalImm(int8_t);
DECLARE_printLogicalImm(int16_t);

void printShifter(MCInst *MI, unsigned OpNum, SStream *O);
void printShiftedRegister(MCInst *MI, unsigned OpNum, SStream *O);
void printExtendedRegister(MCInst *MI, unsigned OpNum, SStream *O);
void printArithExtend(MCInst *MI, unsigned OpNum, SStream *O);

void printMemExtend(MCInst *MI, unsigned OpNum, SStream *O, char SrcRegKind,
		    unsigned Width);
void printMemExtend(MCInst *MI, unsigned OpNum, SStream *O, char SrcRegKind,
		    unsigned Width);
#define DEFINE_printMemExtend(SrcRegKind, Width) \
	static inline void CONCAT(printMemExtend, CONCAT(SrcRegKind, Width))( \
		MCInst * MI, unsigned OpNum, SStream *O) \
	{ \
		add_cs_detail( \
			MI, \
			CONCAT(CONCAT(AArch64_OP_GROUP_MemExtend, SrcRegKind), \
			       Width), \
			OpNum, CHAR(SrcRegKind), Width); \
		printMemExtend(MI, OpNum, O, CHAR(SrcRegKind), Width); \
	}
DEFINE_printMemExtend(w, 8);
DEFINE_printMemExtend(x, 8);
DEFINE_printMemExtend(w, 64);
DEFINE_printMemExtend(x, 64);
DEFINE_printMemExtend(w, 16);
DEFINE_printMemExtend(x, 16);
DEFINE_printMemExtend(w, 128);
DEFINE_printMemExtend(x, 128);
DEFINE_printMemExtend(w, 32);
DEFINE_printMemExtend(x, 32);

#define DECLARE_printRegWithShiftExtend(SignedExtend, ExtWidth, SrcRegKind, \
					Suffix) \
	void CONCAT(printRegWithShiftExtend, \
		    CONCAT(SignedExtend, \
			   CONCAT(ExtWidth, CONCAT(SrcRegKind, Suffix))))( \
		MCInst * MI, unsigned OpNum, SStream *O);
DECLARE_printRegWithShiftExtend(false, 8, x, d);
DECLARE_printRegWithShiftExtend(true, 8, w, d);
DECLARE_printRegWithShiftExtend(false, 8, w, d);
DECLARE_printRegWithShiftExtend(false, 8, x, 0);
DECLARE_printRegWithShiftExtend(true, 8, w, s);
DECLARE_printRegWithShiftExtend(false, 8, w, s);
DECLARE_printRegWithShiftExtend(false, 64, x, d);
DECLARE_printRegWithShiftExtend(true, 64, w, d);
DECLARE_printRegWithShiftExtend(false, 64, w, d);
DECLARE_printRegWithShiftExtend(false, 64, x, 0);
DECLARE_printRegWithShiftExtend(true, 64, w, s);
DECLARE_printRegWithShiftExtend(false, 64, w, s);
DECLARE_printRegWithShiftExtend(false, 16, x, d);
DECLARE_printRegWithShiftExtend(true, 16, w, d);
DECLARE_printRegWithShiftExtend(false, 16, w, d);
DECLARE_printRegWithShiftExtend(false, 16, x, 0);
DECLARE_printRegWithShiftExtend(true, 16, w, s);
DECLARE_printRegWithShiftExtend(false, 16, w, s);
DECLARE_printRegWithShiftExtend(false, 32, x, d);
DECLARE_printRegWithShiftExtend(true, 32, w, d);
DECLARE_printRegWithShiftExtend(false, 32, w, d);
DECLARE_printRegWithShiftExtend(false, 32, x, 0);
DECLARE_printRegWithShiftExtend(true, 32, w, s);
DECLARE_printRegWithShiftExtend(false, 32, w, s);
DECLARE_printRegWithShiftExtend(false, 8, x, s);
DECLARE_printRegWithShiftExtend(false, 16, x, s);
DECLARE_printRegWithShiftExtend(false, 32, x, s);
DECLARE_printRegWithShiftExtend(false, 64, x, s);
DECLARE_printRegWithShiftExtend(false, 128, x, 0);

void printCondCode(MCInst *MI, unsigned OpNum, SStream *O);
void printInverseCondCode(MCInst *MI, unsigned OpNum, SStream *O);
void printAlignedLabel(MCInst *MI, uint64_t Address, unsigned OpNum,
		       SStream *O);
void printUImm12Offset(MCInst *MI, unsigned OpNum, unsigned Scale, SStream *O);
void printAMIndexedWB(MCInst *MI, unsigned OpNum, unsigned Scale, SStream *O);
#define DEFINE_printUImm12Offset(Scale) \
	static inline void CONCAT(printUImm12Offset, Scale)( \
		MCInst * MI, unsigned OpNum, SStream *O) \
	{ \
		add_cs_detail(MI, \
			      CONCAT(AArch64_OP_GROUP_UImm12Offset, Scale), \
			      OpNum, Scale); \
		printUImm12Offset(MI, OpNum, Scale, O); \
	}
DEFINE_printUImm12Offset(1);
DEFINE_printUImm12Offset(8);
DEFINE_printUImm12Offset(2);
DEFINE_printUImm12Offset(16);
DEFINE_printUImm12Offset(4);

void printAMNoIndex(MCInst *MI, unsigned OpNum, SStream *O);
#define DECLARE_printImmScale(Scale) \
	void CONCAT(printImmScale, Scale)(MCInst * MI, unsigned OpNum, \
					  SStream *O);
DECLARE_printImmScale(8);
DECLARE_printImmScale(2);
DECLARE_printImmScale(4);
DECLARE_printImmScale(16);
DECLARE_printImmScale(32);
DECLARE_printImmScale(3);

#define DECLARE_printImmRangeScale(Scale, Offset) \
	void CONCAT(printImmRangeScale, CONCAT(Scale, Offset))( \
		MCInst * MI, unsigned OpNum, SStream *O);
DECLARE_printImmRangeScale(2, 1);
DECLARE_printImmRangeScale(4, 3);

#define DECLARE_printPrefetchOp(IsSVEPrefetch) \
	void CONCAT(printPrefetchOp, \
		    IsSVEPrefetch)(MCInst * MI, unsigned OpNum, SStream *O);
DECLARE_printPrefetchOp(true);
DECLARE_printPrefetchOp(false);

void printRPRFMOperand(MCInst *MI, unsigned OpNum, SStream *O);
void printPSBHintOp(MCInst *MI, unsigned OpNum, SStream *O);
void printBTIHintOp(MCInst *MI, unsigned OpNum, SStream *O);
void printVectorList(MCInst *MI, unsigned OpNum, SStream *O,
		     const char *LayoutSuffix);
void printMatrixTileList(MCInst *MI, unsigned OpNum, SStream *O);
/// (i.e. attached to the instruction rather than the registers).
/// Print a list of vector registers where the type suffix is implicit
void printImplicitlyTypedVectorList(MCInst *MI, unsigned OpNum, SStream *O);
#define DECLARE_printTypedVectorList(NumLanes, LaneKind) \
	void CONCAT(printTypedVectorList, CONCAT(NumLanes, LaneKind))( \
		MCInst * MI, unsigned OpNum, SStream *O);
DECLARE_printTypedVectorList(0, b);
DECLARE_printTypedVectorList(0, d);
DECLARE_printTypedVectorList(0, h);
DECLARE_printTypedVectorList(0, s);
DECLARE_printTypedVectorList(0, q);
DECLARE_printTypedVectorList(16, b);
DECLARE_printTypedVectorList(1, d);
DECLARE_printTypedVectorList(2, d);
DECLARE_printTypedVectorList(2, s);
DECLARE_printTypedVectorList(4, h);
DECLARE_printTypedVectorList(4, s);
DECLARE_printTypedVectorList(8, b);
DECLARE_printTypedVectorList(8, h);

#define DECLARE_printVectorIndex(Scale) \
	void CONCAT(printVectorIndex, Scale)(MCInst * MI, unsigned OpNum, \
					     SStream *O);
DECLARE_printVectorIndex(1);
DECLARE_printVectorIndex(8);

void printMatrixIndex(MCInst *MI, unsigned OpNum, SStream *O);
void printAdrLabel(MCInst *MI, uint64_t Address, unsigned OpNum, SStream *O);
void printAdrpLabel(MCInst *MI, uint64_t Address, unsigned OpNum, SStream *O);
void printBarrierOption(MCInst *MI, unsigned OpNum, SStream *O);
void printBarriernXSOption(MCInst *MI, unsigned OpNum, SStream *O);
void printMSRSystemRegister(MCInst *MI, unsigned OpNum, SStream *O);
void printMRSSystemRegister(MCInst *MI, unsigned OpNum, SStream *O);
void printSystemPStateField(MCInst *MI, unsigned OpNum, SStream *O);
void printSIMDType10Operand(MCInst *MI, unsigned OpNum, SStream *O);
#define DECLARE_printPredicateAsCounter(EltSize) \
	void CONCAT(printPredicateAsCounter, \
		    EltSize)(MCInst * MI, unsigned OpNum, SStream *O);
DECLARE_printPredicateAsCounter(8);
DECLARE_printPredicateAsCounter(64);
DECLARE_printPredicateAsCounter(16);
DECLARE_printPredicateAsCounter(32);
DECLARE_printPredicateAsCounter(0);

#define DECLARE_printGPRSeqPairsClassOperand(size) \
	void CONCAT(printGPRSeqPairsClassOperand, \
		    size)(MCInst * MI, unsigned OpNum, SStream *O);
DECLARE_printGPRSeqPairsClassOperand(32);
DECLARE_printGPRSeqPairsClassOperand(64);

#define DECLARE_printImm8OptLsl(T) \
	void CONCAT(printImm8OptLsl, T)(MCInst * MI, unsigned OpNum, \
					SStream *O);
DECLARE_printImm8OptLsl(int16_t);
DECLARE_printImm8OptLsl(int8_t);
DECLARE_printImm8OptLsl(int64_t);
DECLARE_printImm8OptLsl(int32_t);
DECLARE_printImm8OptLsl(uint16_t);
DECLARE_printImm8OptLsl(uint8_t);
DECLARE_printImm8OptLsl(uint64_t);
DECLARE_printImm8OptLsl(uint32_t);

#define DECLARE_printSVELogicalImm(T) \
	void CONCAT(printSVELogicalImm, T)(MCInst * MI, unsigned OpNum, \
					   SStream *O);
DECLARE_printSVELogicalImm(int16_t);
DECLARE_printSVELogicalImm(int32_t);
DECLARE_printSVELogicalImm(int64_t);

void printSVEPattern(MCInst *MI, unsigned OpNum, SStream *O);
void printSVEVecLenSpecifier(MCInst *MI, unsigned OpNum, SStream *O);
#define DECLARE_printMatrixTileVector(IsVertical) \
	void CONCAT(printMatrixTileVector, \
		    IsVertical)(MCInst * MI, unsigned OpNum, SStream *O);
DECLARE_printMatrixTileVector(0);
DECLARE_printMatrixTileVector(1);

void printMatrixTile(MCInst *MI, unsigned OpNum, SStream *O);
#define DECLARE_printMatrix(EltSize) \
	void CONCAT(printMatrix, EltSize)(MCInst * MI, unsigned OpNum, \
					  SStream *O);
DECLARE_printMatrix(64);
DECLARE_printMatrix(32);
DECLARE_printMatrix(16);
DECLARE_printMatrix(0);

void printSVCROp(MCInst *MI, unsigned OpNum, SStream *O);
#define DECLARE_printSVERegOp(char) \
	void CONCAT(printSVERegOp, char)(MCInst * MI, unsigned OpNum, \
					 SStream *O);
DECLARE_printSVERegOp(b);
DECLARE_printSVERegOp(d);
DECLARE_printSVERegOp(h);
DECLARE_printSVERegOp(s);
DECLARE_printSVERegOp(0);
DECLARE_printSVERegOp(q);

void printGPR64as32(MCInst *MI, unsigned OpNum, SStream *O);
void printGPR64x8(MCInst *MI, unsigned OpNum, SStream *O);
void printSyspXzrPair(MCInst *MI, unsigned OpNum, SStream *O);
#define DECLARE_printZPRasFPR(Width) \
	void CONCAT(printZPRasFPR, Width)(MCInst * MI, unsigned OpNum, \
					  SStream *O);
DECLARE_printZPRasFPR(8);
DECLARE_printZPRasFPR(64);
DECLARE_printZPRasFPR(16);
DECLARE_printZPRasFPR(32);
DECLARE_printZPRasFPR(128);

#define DECLARE_printExactFPImm(ImmIs0, ImmIs1) \
	void CONCAT(printExactFPImm, CONCAT(ImmIs0, ImmIs1))( \
		MCInst * MI, unsigned OpNum, SStream *O);
DECLARE_printExactFPImm(AArch64ExactFPImm_half, AArch64ExactFPImm_one);
DECLARE_printExactFPImm(AArch64ExactFPImm_zero, AArch64ExactFPImm_one);
DECLARE_printExactFPImm(AArch64ExactFPImm_half, AArch64ExactFPImm_two);

;

// end namespace llvm

#endif // LLVM_LIB_TARGET_AARCH64_MCTARGETDESC_AARCH64INSTPRINTER_H

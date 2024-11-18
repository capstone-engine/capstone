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

//===- XtensaInstPrinter.cpp - Convert Xtensa MCInst to asm syntax --------===//
//
//                     The LLVM Compiler Infrastructure
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This class prints an Xtensa MCInst to a .s file.
//
//===----------------------------------------------------------------------===//

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <capstone/platform.h>

#include "../../MCInstPrinter.h"
#include "../../SStream.h"
#include "./priv.h"
#include "../../Mapping.h"

#include "XtensaMapping.h"
#include "../../MathExtras.h"

#define CONCAT(a, b) CONCAT_(a, b)
#define CONCAT_(a, b) a##_##b

#define DEBUG_TYPE "asm-printer"
static MnemonicBitsInfo getMnemonic(MCInst *MI, SStream *O);
static const char *getRegisterName(unsigned RegNo);

typedef MCRegister Register;

static void printRegName(SStream *O, MCRegister Reg)
{
	SStream_concat0(O, getRegisterName(Reg));
}

static void printOp(MCInst *MI, MCOperand *MC, SStream *O)
{
	if (MCOperand_isReg(MC))
		SStream_concat0(O, getRegisterName(MCOperand_getReg(MC)));
	else if (MCOperand_isImm(MC))
		printInt64(O, MCOperand_getImm(MC));
	else if (MCOperand_isExpr(MC))
		printExpr(MCOperand_getExpr(MC), O);
	else
		CS_ASSERT("Invalid operand");
}

static void printOperand(MCInst *MI, const int op_num, SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Operand, op_num);
	printOp(MI, MCInst_getOperand(MI, op_num), O);
}

static inline void printMemOperand(MCInst *MI, int OpNum, SStream *OS)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_MemOperand, OpNum);
	SStream_concat0(OS, getRegisterName(MCOperand_getReg(
				    MCInst_getOperand(MI, (OpNum)))));
	SStream_concat0(OS, ", ");
	printOp(MI, MCInst_getOperand(MI, OpNum + 1), OS);
}

static inline void printBranchTarget(MCInst *MI, int OpNum, SStream *OS)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_BranchTarget, OpNum);
	MCOperand *MC = MCInst_getOperand(MI, (OpNum));
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Val = MCOperand_getImm(MC) + 4;
		SStream_concat0(OS, ". ");
		if (Val > 0)
			SStream_concat0(OS, "+");

		printInt64(OS, Val);
	} else if (MCOperand_isExpr(MC))
		CS_ASSERT_RET(0 && "unimplemented expr printing");
	else
		CS_ASSERT(0 && "Invalid operand");
}

static inline void printLoopTarget(MCInst *MI, int OpNum, SStream *OS)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_LoopTarget, OpNum);
	MCOperand *MC = MCInst_getOperand(MI, (OpNum));
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Val = MCOperand_getImm(MC) + 4;
		SStream_concat0(OS, ". ");
		if (Val > 0)
			SStream_concat0(OS, "+");

		printInt64(OS, Val);
	} else if (MCOperand_isExpr(MC))
		CS_ASSERT_RET(0 && "unimplemented expr printing");
	else
		CS_ASSERT(0 && "Invalid operand");
}

static inline void printJumpTarget(MCInst *MI, int OpNum, SStream *OS)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_JumpTarget, OpNum);
	MCOperand *MC = MCInst_getOperand(MI, (OpNum));
	if (MCOperand_isImm(MC)) {
		int64_t Val = MCOperand_getImm(MC) + 4;
		SStream_concat0(OS, ". ");
		if (Val > 0)
			SStream_concat0(OS, "+");

		printInt64(OS, Val);
	} else if (MCOperand_isExpr(MC))
		CS_ASSERT_RET(0 && "unimplemented expr printing");
	else
		CS_ASSERT(0 && "Invalid operand");
	;
}

static inline void printCallOperand(MCInst *MI, int OpNum, SStream *OS)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_CallOperand, OpNum);
	MCOperand *MC = MCInst_getOperand(MI, (OpNum));
	if (MCOperand_isImm(MC)) {
		int64_t Val = MCOperand_getImm(MC) + 4;
		SStream_concat0(OS, ". ");
		if (Val > 0)
			SStream_concat0(OS, "+");

		printInt64(OS, Val);
	} else if (MCOperand_isExpr(MC))
		CS_ASSERT_RET(0 && "unimplemented expr printing");
	else
		CS_ASSERT(0 && "Invalid operand");
}

static inline void printL32RTarget(MCInst *MI, int OpNum, SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_L32RTarget, OpNum);
	MCOperand *MC = MCInst_getOperand(MI, (OpNum));
	if (MCOperand_isImm(MC)) {
		SStream_concat0(O, ". ");
		printInt64(O, Xtensa_L32R_Value(MI, OpNum));
	} else if (MCOperand_isExpr(MC))
		CS_ASSERT_RET(0 && "unimplemented expr printing");
	else
		CS_ASSERT(0 && "Invalid operand");
}

static inline void printImm8_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Imm8_AsmOperand, OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT(
			isIntN(8, Value) &&
			"Invalid argument, value must be in ranges [-128,127]");
		printInt64(O, Value);
	} else {
		printOperand(MI, OpNum, O);
	}
}

static inline void printImm8_sh8_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Imm8_sh8_AsmOperand, OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT(
			(isIntN(16, Value) && ((Value & 0xFF) == 0)) &&
			"Invalid argument, value must be multiples of 256 in range "
			"[-32768,32512]");
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printImm12_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Imm12_AsmOperand, OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT(
			(Value >= -2048 && Value <= 2047) &&
			"Invalid argument, value must be in ranges [-2048,2047]");
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printImm12m_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Imm12m_AsmOperand, OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT(
			(Value >= -2048 && Value <= 2047) &&
			"Invalid argument, value must be in ranges [-2048,2047]");
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printUimm4_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Uimm4_AsmOperand, OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT((Value >= 0 && Value <= 15) && "Invalid argument");
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printUimm5_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Uimm5_AsmOperand, OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT((Value >= 0 && Value <= 31) && "Invalid argument");
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printShimm1_31_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Shimm1_31_AsmOperand, OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT((Value >= 1 && Value <= 31) &&
			  "Invalid argument, value must be in range [1,31]");
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printShimm0_31_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Shimm0_31_AsmOperand, OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT((Value >= 0 && Value <= 31) &&
			  "Invalid argument, value must be in range [0,31]");
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printImm1_16_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Imm1_16_AsmOperand, OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT((Value >= 1 && Value <= 16) &&
			  "Invalid argument, value must be in range [1,16]");
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printImm1n_15_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Imm1n_15_AsmOperand, OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT(
			(Value >= -1 && (Value != 0) && Value <= 15) &&
			"Invalid argument, value must be in ranges <-1,-1> or <1,15>");
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printImm32n_95_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Imm32n_95_AsmOperand, OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT((Value >= -32 && Value <= 95) &&
			  "Invalid argument, value must be in ranges <-32,95>");
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printImm8n_7_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Imm8n_7_AsmOperand, OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT((Value >= -8 && Value <= 7) &&
			  "Invalid argument, value must be in ranges <-8,7>");
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printImm64n_4n_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Imm64n_4n_AsmOperand, OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT((Value >= -64 && Value <= -4) &
				  ((Value & 0x3) == 0) &&
			  "Invalid argument, value must be in ranges <-64,-4>");
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printOffset8m32_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Offset8m32_AsmOperand,
			       OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT(
			(Value >= 0 && Value <= 1020 && ((Value & 0x3) == 0)) &&
			"Invalid argument, value must be multiples of four in range [0,1020]");
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printEntry_Imm12_AsmOperand(MCInst *MI, int OpNum,
					       SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Entry_Imm12_AsmOperand,
			       OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT(
			(Value >= 0 && Value <= 32760) &&
			"Invalid argument, value must be multiples of eight in range "
			"<0,32760>");
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printB4const_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_B4const_AsmOperand, OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));

		switch (Value) {
		case -1:
		case 1:
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 7:
		case 8:
		case 10:
		case 12:
		case 16:
		case 32:
		case 64:
		case 128:
		case 256:
			break;
		default:
			CS_ASSERT((0) && "Invalid B4const argument");
		}
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printB4constu_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_B4constu_AsmOperand, OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));

		switch (Value) {
		case 32768:
		case 65536:
		case 2:
		case 3:
		case 4:
		case 5:
		case 6:
		case 7:
		case 8:
		case 10:
		case 12:
		case 16:
		case 32:
		case 64:
		case 128:
		case 256:
			break;
		default:
			CS_ASSERT((0) && "Invalid B4constu argument");
		}
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printImm7_22_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Imm7_22_AsmOperand, OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT((Value >= 7 && Value <= 22) &&
			  "Invalid argument, value must be in range <7,22>");
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printSelect_2_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Select_2_AsmOperand, OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT((Value >= 0 && Value <= 1) &&
			  "Invalid argument, value must be in range [0,1]");
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printSelect_4_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Select_4_AsmOperand, OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT((Value >= 0 && Value <= 3) &&
			  "Invalid argument, value must be in range [0,3]");
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printSelect_8_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Select_8_AsmOperand, OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT((Value >= 0 && Value <= 7) &&
			  "Invalid argument, value must be in range [0,7]");
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printSelect_16_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Select_16_AsmOperand, OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT((Value >= 0 && Value <= 15) &&
			  "Invalid argument, value must be in range [0,15]");
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printSelect_256_AsmOperand(MCInst *MI, int OpNum, SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Select_256_AsmOperand,
			       OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT((Value >= 0 && Value <= 255) &&
			  "Invalid argument, value must be in range [0,255]");
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printOffset_16_16_AsmOperand(MCInst *MI, int OpNum,
						SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Offset_16_16_AsmOperand,
			       OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT(
			(Value >= -128 && Value <= 112 && (Value & 0xf) == 0) &&
			"Invalid argument, value must be in range [-128,112], first 4 bits "
			"should be zero");
		printInt64(O, Value);
	} else {
		printOperand(MI, OpNum, O);
	}
}

static inline void printOffset_256_8_AsmOperand(MCInst *MI, int OpNum,
						SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Offset_256_8_AsmOperand,
			       OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT(
			(Value >= -1024 && Value <= 1016 &&
			 (Value & 0x7) == 0) &&
			"Invalid argument, value must be in range [-1024,1016], first 3 "
			"bits should be zero");
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printOffset_256_16_AsmOperand(MCInst *MI, int OpNum,
						 SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Offset_256_16_AsmOperand,
			       OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT(
			(Value >= -2048 && Value <= 2032 &&
			 (Value & 0xf) == 0) &&
			"Invalid argument, value must be in range [-2048,2032], first 4 "
			"bits should be zero");
		printInt64(O, Value);
	} else {
		printOperand(MI, OpNum, O);
	}
}

static inline void printOffset_256_4_AsmOperand(MCInst *MI, int OpNum,
						SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Offset_256_4_AsmOperand,
			       OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT(
			(Value >= -512 && Value <= 508 && (Value & 0x3) == 0) &&
			"Invalid argument, value must be in range [-512,508], first 2 bits "
			"should be zero");
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printOffset_128_2_AsmOperand(MCInst *MI, int OpNum,
						SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Offset_128_2_AsmOperand,
			       OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT(
			(Value >= 0 && Value <= 254 && (Value & 0x1) == 0) &&
			"Invalid argument, value must be in range [0,254], first bit should "
			"be zero");
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printOffset_128_1_AsmOperand(MCInst *MI, int OpNum,
						SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Offset_128_1_AsmOperand,
			       OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT((Value >= 0 && Value <= 127) &&
			  "Invalid argument, value must be in range [0,127]");
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

static inline void printOffset_64_16_AsmOperand(MCInst *MI, int OpNum,
						SStream *O)
{
	Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_Offset_64_16_AsmOperand,
			       OpNum);
	if (MCOperand_isImm(MCInst_getOperand(MI, (OpNum)))) {
		int64_t Value =
			MCOperand_getImm(MCInst_getOperand(MI, (OpNum)));
		CS_ASSERT(
			(Value >= -512 && Value <= 496 && (Value & 0xf) == 0) &&
			"Invalid argument, value must be in range [-512,496], first 4 bits "
			"should be zero");
		printInt64(O, Value);
	} else
		printOperand(MI, OpNum, O);
}

#define IMPL_printImmOperand(N, L, H, S) \
	static void printImmOperand_##N(MCInst *MI, int OpNum, SStream *O) \
	{ \
		Xtensa_add_cs_detail_0(MI, Xtensa_OP_GROUP_ImmOperand_##N, \
				       OpNum); \
		MCOperand *MC = MCInst_getOperand(MI, (OpNum)); \
		if (MCOperand_isImm(MC)) { \
			int64_t Value = MCOperand_getImm(MC); \
			CS_ASSERT((Value >= L && Value <= H && \
				   ((Value % S) == 0)) && \
				  "Invalid argument"); \
			printInt64(O, Value); \
		} else { \
			printOperand(MI, OpNum, O); \
		} \
	}

IMPL_printImmOperand(minus64_56_8, -64, 56, 8);
IMPL_printImmOperand(minus32_28_4, -32, 28, 4);
IMPL_printImmOperand(minus16_47_1, -16, 47, 1);
IMPL_printImmOperand(minus16_14_2, -16, 14, 2);
IMPL_printImmOperand(0_56_8, 0, 56, 8);
IMPL_printImmOperand(0_3_1, 0, 3, 1);
IMPL_printImmOperand(0_63_1, 0, 63, 1);

#include "XtensaGenAsmWriter.inc"

static void printInst(MCInst *MI, uint64_t Address, const char *Annot,
		      SStream *O)
{
	unsigned Opcode = MCInst_getOpcode(MI);

	switch (Opcode) {
	case Xtensa_WSR: {
		// INTERRUPT mnemonic is read-only, so use INTSET mnemonic instead
		Register SR = MCOperand_getReg(MCInst_getOperand(MI, (0)));
		if (SR == Xtensa_INTERRUPT) {
			Register Reg =
				MCOperand_getReg(MCInst_getOperand(MI, (1)));
			SStream_concat1(O, '\t');
			SStream_concat(O, "%s", "wsr");
			SStream_concat0(O, "\t");

			printRegName(O, Reg);
			SStream_concat(O, "%s", ", ");
			SStream_concat0(O, "intset");
			;
			return;
		}
	}
	}
	printInstruction(MI, Address, O);
}

void Xtensa_LLVM_printInstruction(MCInst *MI, uint64_t Address, SStream *O)
{
	printInst(MI, Address, NULL, O);
}

const char *Xtensa_LLVM_getRegisterName(unsigned RegNo)
{
	return getRegisterName(RegNo);
}

//===-- llvm/MC/MCInst.h - MCInst class -------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains the declaration of the MCInst and MCOperand classes, which
// is the basic representation used to represent low-level machine code
// instructions.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#ifndef __CS_MC_MCINST_H
#define __CS_MC_MCINST_H

#include <stdint.h>
#include <stdbool.h>

#include "include/capstone.h"

typedef struct MCInst MCInst;
typedef struct MCOperand MCOperand;

/// MCOperand - Instances of this class represent operands of the MCInst class.
/// This is a simple discriminated union.
struct MCOperand {
	enum {
		kInvalid = 0,                 ///< Uninitialized.
		kRegister,                ///< Register operand.
		kImmediate,               ///< Immediate operand.
		kFPImmediate,             ///< Floating-point immediate operand.
	} MachineOperandType;
	unsigned char Kind;

	union {
		unsigned RegVal;
		int64_t ImmVal;
		double FPImmVal;
	};
};

bool MCOperand_isValid(const MCOperand *op);

bool MCOperand_isReg(const MCOperand *op);

bool MCOperand_isImm(const MCOperand *op);

bool MCOperand_isFPImm(const MCOperand *op);

bool MCOperand_isInst(const MCOperand *op);

void MCInst_clear(MCInst *m);

/// getReg - Returns the register number.
unsigned MCOperand_getReg(const MCOperand *op);

/// setReg - Set the register number.
void MCOperand_setReg(MCOperand *op, unsigned Reg);

int64_t MCOperand_getImm(MCOperand *op);

void MCOperand_setImm(MCOperand *op, int64_t Val);

double MCOperand_getFPImm(const MCOperand *op);

void MCOperand_setFPImm(MCOperand *op, double Val);

const MCInst *MCOperand_getInst(const MCOperand *op);

void MCOperand_setInst(MCOperand *op, const MCInst *Val);

MCOperand *MCOperand_CreateReg(unsigned Reg);

MCOperand *MCOperand_CreateImm(int64_t Val);

MCOperand *MCOperand_CreateFPImm(double Val);

/// MCInst - Instances of this class represent a single low-level machine
/// instruction.
struct MCInst {
	unsigned Opcode;
	MCOperand Operands[32];
	unsigned size;	// number of operands
	cs_insn pub_insn;	// insn to be exposed to public
	cs_mode mode;	// to be referenced by internal code
	unsigned OpcodePub;
	cs_opt_value detail;
	int insn_size;	// instruction size
	int x86_segment;	// remove when segment mem ref hack is redundant.
	uint64_t address;	// address of this insn
};

void MCInst_Init(MCInst *inst);

void MCInst_clear(MCInst *inst);

void MCInst_insert(MCInst *inst, int index, MCOperand *Op);

void MCInst_setOpcode(MCInst *inst, unsigned Op);

unsigned MCInst_getOpcode(const MCInst*);

void MCInst_setOpcodePub(MCInst *inst, unsigned Op);

unsigned MCInst_getOpcodePub(const MCInst*);

MCOperand *MCInst_getOperand(MCInst *inst, unsigned i);

unsigned MCInst_getNumOperands(const MCInst *inst);

int MCInst_addOperand(MCInst *inst, MCOperand *Op);

// This addOperand2 function doesnt free Op
int MCInst_addOperand2(MCInst *inst, MCOperand *Op);

#endif

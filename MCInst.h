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
typedef struct cs_struct cs_struct;
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

// NOTE: this structure is a flatten version of cs_insn struct
// Detail information of disassembled instruction
typedef struct cs_insn_flat {
	// Instruction ID
	// Find the instruction id from header file of corresponding architecture,
	// such as arm.h for ARM, x86.h for X86, etc...
	// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
	unsigned int id;

	// Address (EIP) of this instruction
	// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
	uint64_t address;

	// Size of this instruction
	// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
	uint16_t size;
	// Machine bytes of this instruction, with number of bytes indicated by @size above
	// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
	uint8_t bytes[16];

	// Ascii text of instruction mnemonic
	// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
	char mnemonic[32];

	// Ascii text of instruction operands
	// This information is available even when CS_OPT_DETAIL = CS_OPT_OFF
	char op_str[96];

	// NOTE: All information below is not available when CS_OPT_DETAIL = CS_OPT_OFF

	uint8_t regs_read[12]; // list of implicit registers read by this insn
	uint8_t regs_read_count; // number of implicit registers read by this insn

	uint8_t regs_write[20]; // list of implicit registers modified by this insn
	uint8_t regs_write_count; // number of implicit registers modified by this insn

	uint8_t groups[8]; // list of group this instruction belong to
	uint8_t groups_count; // number of groups this insn belongs to

	// Architecture-specific instruction info
	union {
		cs_x86 x86;	// X86 architecture, including 16-bit, 32-bit & 64-bit mode
		cs_arm64 arm64;	// ARM64 architecture (aka AArch64)
		cs_arm arm;		// ARM architecture (including Thumb/Thumb2)
		cs_mips mips;	// MIPS architecture
		cs_ppc ppc;	// PowerPC architecture
	};
} cs_insn_flat;

/// MCInst - Instances of this class represent a single low-level machine
/// instruction.
struct MCInst {
	unsigned Opcode;
	MCOperand Operands[32];
	unsigned size;	// number of operands
	cs_insn_flat flat_insn;	// insn to be exposed to public
	unsigned OpcodePub;
	int insn_size;	// instruction size
	int x86_segment;	// remove when segment mem ref hack is redundant.
	uint64_t address;	// address of this insn
	cs_struct *csh;	// save the main csh
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

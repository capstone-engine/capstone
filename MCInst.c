/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "MCInst.h"
#include "utils.h"

void MCInst_Init(MCInst *inst)
{
	memset(inst, 0, sizeof(*inst));
}

void MCInst_clear(MCInst *inst)
{
	inst->size = 0;
}

// NOTE: this will free @Op argument
void MCInst_insert(MCInst *inst, int index, MCOperand *Op)
{
	int i;

	for(i = inst->size; i > index; i--)
		//memcpy(&(inst->Operands[i]), &(inst->Operands[i-1]), sizeof(MCOperand));
		inst->Operands[i] = inst->Operands[i-1];

	inst->Operands[index] = *Op;
	inst->size++;

	cs_mem_free(Op);
}

void MCInst_setOpcode(MCInst *inst, unsigned Op)
{
	inst->Opcode = Op;
}

void MCInst_setOpcodePub(MCInst *inst, unsigned Op)
{
	inst->OpcodePub = Op;
}

unsigned MCInst_getOpcode(const MCInst *inst)
{
	return inst->Opcode;
}

unsigned MCInst_getOpcodePub(const MCInst *inst)
{
	return inst->OpcodePub;
}

MCOperand *MCInst_getOperand(MCInst *inst, unsigned i)
{
	return &inst->Operands[i];
}

unsigned MCInst_getNumOperands(const MCInst *inst)
{
	return inst->size;
}

// NOTE: this will free @Op argument
int MCInst_addOperand(MCInst *inst, MCOperand *Op)
{
	if (inst->size == ARR_SIZE(inst->Operands))
		// full
		return -1;

	inst->Operands[inst->size] = *Op;
	cs_mem_free(Op);

	inst->size++;

	return 0;
}

// This addOperand2 function doesnt free Op
int MCInst_addOperand2(MCInst *inst, MCOperand *Op)
{
	if (inst->size == ARR_SIZE(inst->Operands))
		// full
		return -1;

	inst->Operands[inst->size] = *Op;

	inst->size++;

	return 0;
}

void MCOperand_Init(MCOperand *op)
{
	op->Kind = kInvalid;
	op->FPImmVal = 0.0;
}

bool MCOperand_isValid(const MCOperand *op)
{
	return op->Kind != kInvalid;
}

bool MCOperand_isReg(const MCOperand *op)
{
	return op->Kind == kRegister;
}

bool MCOperand_isImm(const MCOperand *op)
{
	return op->Kind == kImmediate;
}

bool MCOperand_isFPImm(const MCOperand *op)
{
	return op->Kind == kFPImmediate;
}

/// getReg - Returns the register number.
unsigned MCOperand_getReg(const MCOperand *op)
{
	return op->RegVal;
}

/// setReg - Set the register number.
void MCOperand_setReg(MCOperand *op, unsigned Reg)
{
	op->RegVal = Reg;
}

int64_t MCOperand_getImm(MCOperand *op)
{
	return op->ImmVal;
}

void MCOperand_setImm(MCOperand *op, int64_t Val)
{
	op->ImmVal = Val;
}

double MCOperand_getFPImm(const MCOperand *op)
{
	return op->FPImmVal;
}

void MCOperand_setFPImm(MCOperand *op, double Val)
{
	op->FPImmVal = Val;
}

MCOperand *MCOperand_CreateReg(unsigned Reg)
{
	MCOperand *op = cs_mem_malloc(sizeof(*op));

	op->Kind = kRegister;
	op->RegVal = Reg;

	return op;
}

MCOperand *MCOperand_CreateImm(int64_t Val)
{
	MCOperand *op = cs_mem_malloc(sizeof(*op));

	op->Kind = kImmediate;
	op->ImmVal = Val;

	return op;
}

MCOperand *MCOperand_CreateFPImm(double Val)
{
	MCOperand *op = cs_mem_malloc(sizeof(*op));

	op->Kind = kFPImmediate;
	op->FPImmVal = Val;

	return op;
}

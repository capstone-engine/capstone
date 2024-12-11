/* Capstone Disassembly Engine */
/* BPF Backend by david942j <david942j@gmail.com>, 2019 */
/* SPDX-FileCopyrightText: 2024 Roee Toledano <roeetoledano10@gmail.com> */
/* SPDX-License-Identifier: BSD-3 */

#include <capstone/platform.h>

#include "BPFConstants.h"
#include "BPFInstPrinter.h"
#include "BPFMapping.h"
#include "../../Mapping.h"

static cs_bpf_op *expand_bpf_operands(cs_bpf *bpf)
{
	assert(bpf->op_count < 3);
	return &bpf->operands[bpf->op_count++];
}

static void push_op_reg(cs_bpf *bpf, bpf_op_type val, uint8_t ac_mode)
{
	cs_bpf_op *op = expand_bpf_operands(bpf);

	op->type = BPF_OP_REG;
	op->reg = val;
	op->access = ac_mode;
}

static void push_op_imm(cs_bpf *bpf, uint64_t val, const bool is_signed)
{
	cs_bpf_op *op = expand_bpf_operands(bpf);

	op->type = BPF_OP_IMM;
	op->imm = val;
	op->is_signed = is_signed;
}

static void push_op_off(cs_bpf *bpf, uint32_t val, const bool is_signed)
{
	cs_bpf_op *op = expand_bpf_operands(bpf);

	op->type = BPF_OP_OFF;
	op->off = val;
	op->is_signed = is_signed;
}

static void push_op_mem(cs_bpf *bpf, bpf_reg reg, uint32_t val,
			const bool is_signed, const bool is_pkt)
{
	cs_bpf_op *op = expand_bpf_operands(bpf);

	op->type = BPF_OP_MEM;
	op->mem.base = reg;
	op->mem.disp = val;
	op->is_signed = is_signed;
	op->is_pkt = is_pkt;
}

static void push_op_mmem(cs_bpf *bpf, uint32_t val)
{
	cs_bpf_op *op = expand_bpf_operands(bpf);

	op->type = BPF_OP_MMEM;
	op->mmem = val;
}

static void push_op_msh(cs_bpf *bpf, uint32_t val)
{
	cs_bpf_op *op = expand_bpf_operands(bpf);

	op->type = BPF_OP_MSH;
	op->msh = val;
}

static void push_op_ext(cs_bpf *bpf, bpf_ext_type val)
{
	cs_bpf_op *op = expand_bpf_operands(bpf);

	op->type = BPF_OP_EXT;
	op->ext = val;
}

static void convert_operands(MCInst *MI, cs_bpf *bpf)
{
	unsigned opcode = MCInst_getOpcode(MI);
	unsigned mc_op_count = MCInst_getNumOperands(MI);
	MCOperand *op;
	MCOperand *op2;

	bpf->op_count = 0;
	if (BPF_CLASS(opcode) == BPF_CLASS_LD ||
	    BPF_CLASS(opcode) == BPF_CLASS_LDX) {
		switch (BPF_MODE(opcode)) {
		case BPF_MODE_IMM:
			if (EBPF_MODE(MI->csh->mode)) {
				push_op_reg(bpf,
					    MCOperand_getReg(
						    MCInst_getOperand(MI, 0)),
					    CS_AC_WRITE);
				push_op_imm(bpf,
					    MCOperand_getImm(
						    MCInst_getOperand(MI, 1)),
					    false);
			} else {
				push_op_imm(bpf,
					    MCOperand_getImm(
						    MCInst_getOperand(MI, 0)),
					    false);
			}
			break;
		case BPF_MODE_ABS:
			op = MCInst_getOperand(MI, 0);
			push_op_mem(bpf, BPF_REG_INVALID,
				    (uint32_t)MCOperand_getImm(op), EBPF_MODE(MI->csh->mode), true);
			break;
		case BPF_MODE_IND:
			op = MCInst_getOperand(MI, 0);
			if (EBPF_MODE(MI->csh->mode))
				push_op_mem(bpf, MCOperand_getReg(op), 0x0,
					    true, true);
			else {
				op2 = MCInst_getOperand(MI, 1);
				push_op_mem(bpf, MCOperand_getReg(op),
					    (uint32_t)MCOperand_getImm(op2),
					    false, true);
			}
			break;
		case BPF_MODE_MEM:
			if (EBPF_MODE(MI->csh->mode)) {
				/* ldx{w,h,b,dw} dst, [src+off] */
				push_op_reg(bpf,
					    MCOperand_getReg(
						    MCInst_getOperand(MI, 0)),
					    CS_AC_WRITE);
				op = MCInst_getOperand(MI, 1);
				op2 = MCInst_getOperand(MI, 2);
				push_op_mem(bpf, MCOperand_getReg(op),
					    (uint32_t)MCOperand_getImm(op2),
					    true, false);
			} else {
				push_op_mmem(bpf,
					     (uint32_t)MCOperand_getImm(
						     MCInst_getOperand(MI, 0)));
			}
			break;
		case BPF_MODE_LEN:
			push_op_ext(bpf, BPF_EXT_LEN);
			break;
		case BPF_MODE_MSH:
			op = MCInst_getOperand(MI, 0);
			push_op_msh(bpf, (uint32_t)MCOperand_getImm(op));
			break;
			/* case BPF_MODE_XADD: // not exists */
		}
		return;
	}
	if (BPF_CLASS(opcode) == BPF_CLASS_ST ||
	    BPF_CLASS(opcode) == BPF_CLASS_STX) {
		if (!EBPF_MODE(MI->csh->mode)) {
			// cBPF has only one case - st* M[k]
			push_op_mmem(bpf, (uint32_t)MCOperand_getImm(
						  MCInst_getOperand(MI, 0)));
			return;
		}
		/* eBPF has two cases:
		 * - st [dst + off], src
		 * - xadd [dst + off], src
		 * they have same form of operands.
		 */
		op = MCInst_getOperand(MI, 0);
		op2 = MCInst_getOperand(MI, 1);
		push_op_mem(bpf, MCOperand_getReg(op),
			    (uint32_t)MCOperand_getImm(op2), true, false);

		op = MCInst_getOperand(MI, 2);
		if (MCOperand_isImm(op))
			push_op_imm(bpf, MCOperand_getImm(op), false);
		else if (MCOperand_isReg(op))
			push_op_reg(bpf, MCOperand_getReg(op), CS_AC_READ);
		return;
	}

	{
		const bool is_jmp32 = EBPF_MODE(MI->csh->mode) &&
				      (BPF_CLASS(opcode) == BPF_CLASS_JMP32);
		if (BPF_CLASS(opcode) == BPF_CLASS_JMP || is_jmp32) {
			for (size_t i = 0; i < mc_op_count; i++) {
				op = MCInst_getOperand(MI, i);
				if (MCOperand_isImm(op)) {
					/* Decide if we're using IMM or OFF here (and if OFF, then signed or unsigned):
					 *
					 * 1. any jump/jump32 + signed off (not including exit/call and ja on jump32) // eBPF 
					 * 2. exit/call/ja + k // eBPF
					 * 3. ja + unsigned off // cBPF (cBPF programs can only jump forwards) 
					 * 4. any jump {x,k}, +jt, +jf // cBPF 
					 * */

					if ((BPF_OP(opcode) == BPF_JUMP_JA &&
					     !is_jmp32) ||
					    (!EBPF_MODE(MI->csh->mode) &&
					     i >= 1) ||
					    (EBPF_MODE(MI->csh->mode) &&
					     i == 2))
						push_op_off(
							bpf,
							MCOperand_getImm(op),
							EBPF_MODE(
								MI->csh->mode));
					else
						push_op_imm(
							bpf,
							MCOperand_getImm(op),
							true);
				} else if (MCOperand_isReg(op)) {
					push_op_reg(bpf, MCOperand_getReg(op),
						    CS_AC_READ);
				}
			}
			return;
		}
	}

	if (!EBPF_MODE(MI->csh->mode)) {
		/* In cBPF mode, all registers in operands are accessed as read */
		for (size_t i = 0; i < mc_op_count; i++) {
			op = MCInst_getOperand(MI, i);
			if (MCOperand_isImm(op))
				push_op_imm(bpf, MCOperand_getImm(op), false);
			else if (MCOperand_isReg(op))
				push_op_reg(bpf, MCOperand_getReg(op),
					    CS_AC_READ);
		}
		return;
	}

	/* remain cases are: eBPF mode && ALU */
	/* if (BPF_CLASS(opcode) == BPF_CLASS_ALU || BPF_CLASS(opcode) == BPF_CLASS_ALU64) */

	/* We have three types:
	 * 1. {l,b}e dst               // dst = byteswap(dst)
	 * 2. neg dst                  // dst = -dst
	 * 3. <op> dst, {src_reg, imm} // dst = dst <op> src
	 * so we can simply check the number of operands,
	 * exactly one operand means we are in case 1. and 2.,
	 * otherwise in case 3.
	 */
	if (mc_op_count == 1) {
		op = MCInst_getOperand(MI, 0);
		push_op_reg(bpf, MCOperand_getReg(op),
			    CS_AC_READ | CS_AC_WRITE);
	} else { // if (mc_op_count == 2)
		op = MCInst_getOperand(MI, 0);
		push_op_reg(bpf, MCOperand_getReg(op),
			    CS_AC_READ | CS_AC_WRITE);

		op = MCInst_getOperand(MI, 1);
		if (MCOperand_isImm(op))
			push_op_imm(bpf, MCOperand_getImm(op), false);
		else if (MCOperand_isReg(op))
			push_op_reg(bpf, MCOperand_getReg(op), CS_AC_READ);
	}
}

static void print_operand(MCInst *MI, struct SStream *O, const cs_bpf_op *op)
{
	switch (op->type) {
	case BPF_OP_INVALID:
		SStream_concat(O, "invalid");
		break;
	case BPF_OP_REG:
		SStream_concat(O, BPF_reg_name((csh)MI->csh, op->reg));
		break;
	case BPF_OP_IMM:
		if (op->is_signed)
			printInt32Hex(O, op->imm);
		else
			SStream_concat(O, "0x%" PRIx64, op->imm);
		break;
	case BPF_OP_OFF:
		if (op->is_signed)
			printInt16HexOffset(O, op->off);
		else
			SStream_concat(O, "+0x%" PRIx32, op->off);
		break;
	case BPF_OP_MEM:
		SStream_concat(O, "[");

		if (op->is_pkt && EBPF_MODE(MI->csh->mode)) {
			SStream_concat(O, "skb");

			if (op->mem.base != BPF_REG_INVALID)
				SStream_concat(O, "+%s",
					       BPF_reg_name((csh)MI->csh,
							    op->mem.base));
			else {
				if (op->is_signed)
					printInt32HexOffset(O, op->mem.disp);
				else
					SStream_concat(O, "+0x%" PRIx32,
						       op->mem.disp);
			}
		} else {
			if (op->mem.base != BPF_REG_INVALID)
				SStream_concat(O, BPF_reg_name((csh)MI->csh,
							       op->mem.base));
			if (op->mem.disp != 0) {
				if (op->mem.base != BPF_REG_INVALID) {
					// if operation is signed, then it always uses off, not k
					if (op->is_signed)
						printInt16HexOffset(
							O, op->mem.disp);
					else if (op->is_pkt)
						SStream_concat(O, "+0x%" PRIx32,
							       op->mem.disp);
					else
						SStream_concat(O, "+0x%" PRIx16,
							       op->mem.disp);
				} else
					SStream_concat(O, "0x%" PRIx32,
						       op->mem.disp);
			}

			if (op->mem.base == BPF_REG_INVALID &&
			    op->mem.disp == 0)
				SStream_concat(O, "0x0");
		}

		SStream_concat(O, "]");
		break;
	case BPF_OP_MMEM:
		SStream_concat(O, "m[0x%x]", op->mmem);
		break;
	case BPF_OP_MSH:
		SStream_concat(O, "4*([0x%x]&0xf)", op->msh);
		break;
	case BPF_OP_EXT:
		switch (op->ext) {
		case BPF_EXT_LEN:
			SStream_concat(O, "#len");
			break;
		}
		break;
	}
}

/*
 * 1. human readable mnemonic
 * 2. set pubOpcode (BPF_INSN_*)
 * 3. set detail->bpf.operands
 * */
void BPF_printInst(MCInst *MI, struct SStream *O, void *PrinterInfo)
{
	cs_bpf bpf = { 0 };

	/* set pubOpcode as instruction id */
	SStream_concat(O, BPF_insn_name((csh)MI->csh, MCInst_getOpcodePub(MI)));
	convert_operands(MI, &bpf);
	for (size_t i = 0; i < bpf.op_count; i++) {
		if (i == 0)
			SStream_concat(O, "\t");
		else
			SStream_concat(O, ", ");
		print_operand(MI, O, &bpf.operands[i]);
	}

#ifndef CAPSTONE_DIET
	if (detail_is_set(MI)) {
		MI->flat_insn->detail->bpf = bpf;
	}
#endif
}

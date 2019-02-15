/* Capstone Disassembly Engine */
/* BPF Backend by david942j <david942j@gmail.com>, 2019 */

#include "BPFConstants.h"
#include "BPFInstPrinter.h"
#include "BPFMapping.h"

static cs_bpf_op *expand_bpf_operands(cs_bpf *bpf)
{
	bpf->op_count++;
	bpf->operands = cs_mem_realloc(bpf->operands, bpf->op_count * sizeof(cs_bpf_op));
	return &bpf->operands[bpf->op_count - 1];
}

static void push_bpf_imm(cs_bpf *bpf, uint64_t val) {
	cs_bpf_op *op = expand_bpf_operands(bpf);

	op->type = BPF_OP_IMM;
	op->imm = val;
}

static void push_bpf_reg(cs_bpf *bpf, unsigned val) {
	cs_bpf_op *op = expand_bpf_operands(bpf);

	op->type = BPF_OP_REG;
	op->reg = val;
}

static void push_bpf_mem(cs_bpf *bpf, bpf_reg reg, uint64_t val) {
	cs_bpf_op *op = expand_bpf_operands(bpf);

	op->type = BPF_OP_MEM;
	op->mem.base = reg;
	op->mem.disp = val;
}

static void push_bpf_mmem(cs_bpf *bpf, uint64_t val) {
	cs_bpf_op *op = expand_bpf_operands(bpf);

	op->type = BPF_OP_MMEM;
	op->imm = val;
}

static void push_bpf_msh(cs_bpf *bpf, uint64_t val) {
	cs_bpf_op *op = expand_bpf_operands(bpf);

	op->type = BPF_OP_MSH;
	op->imm = val;
}

static void push_bpf_ext(cs_bpf *bpf, bpf_ext_type val) {
	cs_bpf_op *op = expand_bpf_operands(bpf);

	op->type = BPF_OP_EXT;
	op->imm = val;
}

static void BPF_convertOperands(MCInst *MI, cs_bpf *bpf)
{
	unsigned opcode = MCInst_getOpcode(MI);
	unsigned mc_op_count = MCInst_getNumOperands(MI);
	MCOperand *op;
	MCOperand *op2;
	unsigned i;

	bpf->op_count = 0;
	bpf->operands = NULL;
	/* so sad cBPF and eBPF are very different in these case.. */
	if (BPF_CLASS(opcode) == BPF_CLASS_LD || BPF_CLASS(opcode) == BPF_CLASS_LDX) {
		switch (BPF_MODE(opcode)) {
		case BPF_MODE_IMM:
			push_bpf_imm(bpf, (uint64_t)MCOperand_getImm(MCInst_getOperand(MI, 0)));
			break;
		case BPF_MODE_ABS:
			op = MCInst_getOperand(MI, 0);
			push_bpf_mem(bpf, BPF_REG_INVALID, (uint64_t)MCOperand_getImm(op));
			break;
		case BPF_MODE_IND:
			op = MCInst_getOperand(MI, 0);
			op2 = MCInst_getOperand(MI, 1);
			push_bpf_mem(bpf, MCOperand_getReg(op), (uint64_t)MCOperand_getImm(op2));
			break;
		case BPF_MODE_MEM:
			if (EBPF_MODE(MI->csh)) {
				/* ldx{w,h,b,dw} dst, [src+off] */
				push_bpf_reg(bpf, MCOperand_getReg(MCInst_getOperand(MI, 0)));
				op = MCInst_getOperand(MI, 1);
				op2 = MCInst_getOperand(MI, 2);
				push_bpf_mem(bpf, MCOperand_getReg(op), (uint64_t)MCOperand_getImm(op2));
			}
			else {
				push_bpf_mmem(bpf, (uint64_t)MCOperand_getImm(MCInst_getOperand(MI, 0)));
			}
			break;
		case BPF_MODE_LEN:
			push_bpf_ext(bpf, BPF_EXT_LEN);
			break;
		case BPF_MODE_MSH:
			op = MCInst_getOperand(MI, 0);
			push_bpf_msh(bpf, (uint64_t)MCOperand_getImm(op));
			break;
		/* case BPF_MODE_XADD: // not exists */
		}
		return;
	}
	if (BPF_CLASS(opcode) == BPF_CLASS_ST || BPF_CLASS(opcode) == BPF_CLASS_STX) {
		if (!EBPF_MODE(MI->csh)) {
			// cBPF has only one case - st* M[k]
			push_bpf_mmem(bpf, (uint64_t)MCOperand_getImm(MCInst_getOperand(MI, 0)));
			return;
		}
		/* eBPF has two cases:
		 * - st [dst + off], src
		 * - xadd [dst + off], src
		 */
		op = MCInst_getOperand(MI, 0);
		op2 = MCInst_getOperand(MI, 1);
		push_bpf_mem(bpf, MCOperand_getReg(op), (uint64_t)MCOperand_getImm(op2));
		op = MCInst_getOperand(MI, 2);
		if (MCOperand_isImm(op))
			push_bpf_imm(bpf, (uint64_t)MCOperand_getImm(op));
		else if (MCOperand_isReg(op))
			push_bpf_reg(bpf, MCOperand_getReg(op));
		return;
	}
	/* convert 1-to-1 */
	for (i = 0; i < mc_op_count; i++) {
		op = MCInst_getOperand(MI, i);
		if (MCOperand_isImm(op))
			push_bpf_imm(bpf, (uint64_t)MCOperand_getImm(op));
		else if (MCOperand_isReg(op))
			push_bpf_reg(bpf, MCOperand_getReg(op));
	}
}

static void BPF_printOperand(MCInst *MI, struct SStream *O, const cs_bpf_op *op)
{
	char buf[32];
	unsigned opcode = MCInst_getOpcode(MI);

	if (op->type == BPF_OP_IMM) {
		if (BPF_CLASS(opcode) == BPF_CLASS_JMP)
			SStream_concat(O, "+");
		sprintf(buf, "0x%lx", op->imm);
		SStream_concat(O, buf);
	}
	else if (op->type == BPF_OP_REG) {
		SStream_concat(O, BPF_reg_name((csh)MI->csh, op->reg));
	}
	else if (op->type == BPF_OP_MEM) {
		SStream_concat(O, "[");
		if (op->mem.base != BPF_REG_INVALID)
			SStream_concat(O, BPF_reg_name((csh)MI->csh, op->mem.base));
		if (op->mem.disp != 0) {
			if (op->mem.base != BPF_REG_INVALID)
				SStream_concat(O, "+");
			sprintf(buf, "%#x", op->mem.disp);
			SStream_concat(O, buf);
		}
		SStream_concat(O, "]");
	}
	else if (op->type == BPF_OP_MMEM) {
		SStream_concat(O, "m[");
		sprintf(buf, "0x%lx", op->imm);
		SStream_concat(O, buf);
		SStream_concat(O, "]");
	}
	else if (op->type == BPF_OP_MSH) {
		sprintf(buf, "4*([0x%lx]&0xf)", op->imm);
		SStream_concat(O, buf);
	}
	else if (op->type == BPF_OP_EXT) {
		switch (op->imm) {
		case BPF_EXT_LEN:
			SStream_concat(O, "#len");
			break;
		}
	}
}

/*
 * 1. human readable mnemonic
 * 2. set pubOpcode (BPF_INSN_*)
 * 3. set detail->bpf.operands
 * */
void BPF_printInst(MCInst *MI, struct SStream *O, void *PrinterInfo)
{
	int i;
	cs_insn insn;
	cs_bpf bpf;

	/* set pubOpcode */
	insn.detail = NULL;
	BPF_get_insn_id((cs_struct*)MI->csh, &insn, MCInst_getOpcode(MI));
	MCInst_setOpcodePub(MI, insn.id);

	SStream_concat(O, BPF_insn_name((csh)MI->csh, insn.id));
	BPF_convertOperands(MI, &bpf);
	for (i = 0; i < bpf.op_count; i++) {
		if (i == 0)
			SStream_concat(O, "\t");
		else
			SStream_concat(O, ", ");
		BPF_printOperand(MI, O, &bpf.operands[i]);
	}

#ifndef CAPSTONE_DIET
	if (MI->flat_insn->detail) {
		/* MI->flat_insn->detail->bpf.op_count = MCInst_getNumOperands(MI); */
		MI->flat_insn->detail->bpf = bpf;
	}
#endif
}

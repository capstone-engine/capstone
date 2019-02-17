#include <stdio.h>

#include <capstone/capstone.h>

static char * ext_name[] = {
	[BPF_EXT_LEN] = "#len",
};

void print_insn_detail_bpf(csh handle, cs_insn *ins)
{
	cs_bpf *bpf;
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	bpf = &(ins->detail->bpf);

	int i;

	printf("\tOperand count: %u\n", bpf->op_count);

	for (i = 0; i < bpf->op_count; i++) {
		cs_bpf_op *op = &(bpf->operands[i]);
		switch (op->type) {
		case BPF_OP_INVALID:
			printf("\t\toperands[%u].type: INVALID\n", i);
			break;
		case BPF_OP_REG:
			printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
			break;
		case BPF_OP_IMM:
			printf("\t\toperands[%u].type: IMM = 0x%lx\n", i, op->imm);
			break;
		case BPF_OP_OFF:
			printf("\t\toperands[%u].type: OFF = +0x%x\n", i, op->off);
			break;
		case BPF_OP_MEM:
			printf("\t\toperands[%u].type: MEM\n", i);
			if (op->mem.base != BPF_REG_INVALID)
				printf("\t\t\toperands[%u].mem.base: REG = %s\n",
						i, cs_reg_name(handle, op->mem.base));
			printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);
			break;
		case BPF_OP_MMEM:
			printf("\t\toperands[%u].type: MMEM = M[0x%x]\n", i, op->mmem);
			break;
		case BPF_OP_MSH:
			printf("\t\toperands[%u].type: MSH = 4*([0x%x]&0xf)\n", i, op->msh);
			break;
		case BPF_OP_EXT:
			printf("\t\toperands[%u].type: EXT = %s\n", i, ext_name[op->ext]);
			break;
		}
	}

	/* print all registers that are involved in this instruction */
	if (!cs_regs_access(handle, ins,
			regs_read, &regs_read_count,
			regs_write, &regs_write_count)) {
		if (regs_read_count) {
			printf("\tRegisters read:");
			for(i = 0; i < regs_read_count; i++) {
				printf(" %s", cs_reg_name(handle, regs_read[i]));
			}
			printf("\n");
		}

		if (regs_write_count) {
			printf("\tRegisters modified:");
			for(i = 0; i < regs_write_count; i++) {
				printf(" %s", cs_reg_name(handle, regs_write[i]));
			}
			printf("\n");
		}
	}
}

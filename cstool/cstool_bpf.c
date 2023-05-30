#include <stdio.h>

#include <capstone/capstone.h>
#include <capstone/platform.h>
#include "cstool.h"

static const char * ext_name[] = {
	[BPF_EXT_LEN] = "#len",
};

void print_insn_detail_bpf(csh handle, cs_insn *ins)
{
	unsigned i;
	cs_bpf *bpf;
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	bpf = &(ins->detail->bpf);

	printf("\tOperand count: %u\n", bpf->op_count);

	for (i = 0; i < bpf->op_count; i++) {
		cs_bpf_op *op = &(bpf->operands[i]);
		printf("\t\toperands[%u].type: ", i);
		switch (op->type) {
		case BPF_OP_INVALID:
			printf("INVALID\n");
			break;
		case BPF_OP_REG:
			printf("REG = %s\n", cs_reg_name(handle, op->reg));
			break;
		case BPF_OP_IMM:
			printf("IMM = 0x%" PRIx64 "\n", op->imm);
			break;
		case BPF_OP_OFF:
			printf("OFF = +0x%x\n", op->off);
			break;
		case BPF_OP_MEM:
			printf("MEM\n");
			if (op->mem.base != BPF_REG_INVALID)
				printf("\t\t\toperands[%u].mem.base: REG = %s\n",
						i, cs_reg_name(handle, op->mem.base));
			printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);
			break;
		case BPF_OP_MMEM:
			printf("MMEM = M[0x%x]\n", op->mmem);
			break;
		case BPF_OP_MSH:
			printf("MSH = 4*([0x%x]&0xf)\n", op->msh);
			break;
		case BPF_OP_EXT:
			printf("EXT = %s\n", ext_name[op->ext]);
			break;
		}
	}

	/* print all registers that are involved in this instruction */
	if (!cs_regs_access(handle, ins,
			regs_read, &regs_read_count,
			regs_write, &regs_write_count)) {
		if (regs_read_count) {
			printf("\tRegisters read:");
			for(i = 0; i < regs_read_count; i++)
				printf(" %s", cs_reg_name(handle, regs_read[i]));
			printf("\n");
		}

		if (regs_write_count) {
			printf("\tRegisters modified:");
			for(i = 0; i < regs_write_count; i++)
				printf(" %s", cs_reg_name(handle, regs_write[i]));
			printf("\n");
		}
	}
}

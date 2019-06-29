/* Capstone testing regression */
/* By david942j <david942j@gmail.com>, 2019 */

#include <capstone/platform.h>

#include "factory.h"

static char * ext_name[] = {
	[BPF_EXT_LEN] = "#len",
};

char *get_detail_bpf(csh *handle, cs_mode mode, cs_insn *ins)
{
	cs_bpf *bpf;
	unsigned int i;
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;
	char *result;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';
	if (ins->detail == NULL)
		return result;

	bpf = &(ins->detail->bpf);

	if (bpf->op_count)
		add_str(&result, " ; op_count: %u", bpf->op_count);
	for (i = 0; i < bpf->op_count; i++) {
		cs_bpf_op *op = &(bpf->operands[i]);
		add_str(&result, " ; operands[%u].type: ", i);
		switch (op->type) {
		case BPF_OP_INVALID:
			add_str(&result, "INVALID");
			break;
		case BPF_OP_REG:
			add_str(&result, "REG = %s", cs_reg_name(*handle, op->reg));
			break;
		case BPF_OP_IMM:
			add_str(&result, "IMM = 0x%" PRIx64, op->imm);
			break;
		case BPF_OP_OFF:
			add_str(&result, "OFF = +0x%x", op->off);
			break;
		case BPF_OP_MEM:
			add_str(&result, "MEM [base=%s, disp=0x%x]", 
				cs_reg_name(*handle, op->mem.base), op->mem.disp);
			break;
		case BPF_OP_MMEM:
			add_str(&result, "MMEM = M[0x%x]", op->mmem);
			break;
		case BPF_OP_MSH:
			add_str(&result, "MSH = 4*([0x%x]&0xf)", op->msh);
			break;
		case BPF_OP_EXT:
			add_str(&result, "EXT = %s", ext_name[op->ext]);
			break;
		}
	}

	if (!cs_regs_access(*handle, ins,
			regs_read, &regs_read_count,
			regs_write, &regs_write_count)) {
		if (regs_read_count) {
			add_str(&result, " ; Registers read:");
			for(i = 0; i < regs_read_count; i++)
				add_str(&result, " %s", cs_reg_name(*handle, regs_read[i]));
		}

		if (regs_write_count) {
			add_str(&result, " ; Registers modified:");
			for(i = 0; i < regs_write_count; i++)
				add_str(&result, " %s", cs_reg_name(*handle, regs_write[i]));
		}
	}
	return result;
}

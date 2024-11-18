/* Capstone Disassembly Engine */
/* By billow <billow.fun@gmail.com>, 2024 */

#include <stdio.h>
#include <capstone/capstone.h>
#include <capstone/xtensa.h>

static const char *xtensa_insn_form_strs[] = {
	[XTENSA_INSN_FORM_INVALID] = "XTENSA_INSN_FORM_INVALID",
	[XTENSA_INSN_FORM_RRR] = "XTENSA_INSN_FORM_RRR",
	[XTENSA_INSN_FORM_RRI8] = "XTENSA_INSN_FORM_RRI8",
	[XTENSA_INSN_FORM_RRRN] = "XTENSA_INSN_FORM_RRRN",
	[XTENSA_INSN_FORM_AEINST24] = "XTENSA_INSN_FORM_AEINST24",
	[XTENSA_INSN_FORM_BRI12] = "XTENSA_INSN_FORM_BRI12",
	[XTENSA_INSN_FORM_CALL] = "XTENSA_INSN_FORM_CALL",
	[XTENSA_INSN_FORM_CALLX] = "XTENSA_INSN_FORM_CALLX",
	[XTENSA_INSN_FORM_EE_INST24] = "XTENSA_INSN_FORM_EE_INST24",
	[XTENSA_INSN_FORM_RRI4] = "XTENSA_INSN_FORM_RRI4",
	[XTENSA_INSN_FORM_RI16] = "XTENSA_INSN_FORM_RI16",
	[XTENSA_INSN_FORM_RI7] = "XTENSA_INSN_FORM_RI7",
	[XTENSA_INSN_FORM_RSR] = "XTENSA_INSN_FORM_RSR",
};

void print_insn_detail_xtensa(csh handle, cs_insn *ins)
{
	int i;
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	cs_xtensa *detail = &(ins->detail->xtensa);

	if (detail->format && detail->format < XTENSA_INSN_FORM_MAX) {
		printf("\tformat: %s\n", xtensa_insn_form_strs[detail->format]);
	}

	if (detail->op_count)
		printf("\top_count: %u\n", detail->op_count);

	for (i = 0; i < detail->op_count; i++) {
		cs_xtensa_op *op = &(detail->operands[i]);
		if (op->type == CS_OP_REG)
			printf("\t\toperands[%u].type: REG = %s\n", i,
			       cs_reg_name(handle, op->reg));
		else if (op->type == CS_OP_IMM)
			printf("\t\toperands[%u].type: IMM = 0x%" PRIx32 "\n",
			       i, op->imm);
		else if (op->type == CS_OP_MEM)
			printf("\t\toperands[%u].type: MEM\n"
			       "\t\t\t.mem.base: REG = %s\n"
			       "\t\t\t.mem.disp: 0x%" PRIx32 "\n",
			       i, cs_reg_name(handle, op->mem.base),
			       op->mem.disp);
		else if (op->type == XTENSA_OP_L32R) {
			printf("\t\toperands[%u].type: L32R\n"
			       "\t\t\t.l32r = %" PRIx32 "\n",
			       i, op->imm);
		}

		if (op->access & CS_AC_READ)
			printf("\t\t\t.access: READ\n");
		else if (op->access & CS_AC_WRITE)
			printf("\t\t\t.access: WRITE\n");
		else if (op->access & (CS_AC_READ | CS_AC_WRITE))
			printf("\t\t\t.access: READ | WRITE\n");
	}
	// Print out all registers accessed by this instruction (either implicit or
	// explicit)
	if (!cs_regs_access(handle, ins, regs_read, &regs_read_count,
			    regs_write, &regs_write_count)) {
		if (regs_read_count) {
			printf("\tRegisters read:");
			for (i = 0; i < regs_read_count; i++) {
				printf(" %s",
				       cs_reg_name(handle, regs_read[i]));
			}
			printf("\n");
		}

		if (regs_write_count) {
			printf("\tRegisters modified:");
			for (i = 0; i < regs_write_count; i++) {
				printf(" %s",
				       cs_reg_name(handle, regs_write[i]));
			}
			printf("\n");
		}
	}
}

//
//  cstool_sh.c
//
//  Yoshinori Sato 2022/09/07
//

#include <stdio.h>
#include <capstone/capstone.h>
#include "cstool.h"

static const char *s_addressing_modes[] = {
	"<invalid mode>",

	"Register Direct", /// Rn

	"Register Indirect", /// @Rn
	"Register Indirect with Postincrement", /// @Rn+
	"Register Indirect with Predecrement", /// @-Rn
	"Register Indirect with Displacement", /// @(disp,Rn)

	"Indexed register indirect", /// @(R0, Rn)
	"GBR indirect with displacement", /// @(disp,GBR)
	"Indexed GBR indirect", /// @(R0, GBR)

	"PC-relative with Displacement", /// @(disp, PC)

	"Immediate value",
};

static void print_read_write_regs(cs_detail *detail, csh handle)
{
	int i;

	for (i = 0; i < detail->regs_read_count; ++i) {
		uint16_t reg_id = detail->regs_read[i];
		const char *reg_name = cs_reg_name(handle, reg_id);
		printf("\treading from reg: %s\n", reg_name);
	}

	for (i = 0; i < detail->regs_write_count; ++i) {
		uint16_t reg_id = detail->regs_write[i];
		const char *reg_name = cs_reg_name(handle, reg_id);
		printf("\twriting to reg:   %s\n", reg_name);
	}
}

void print_insn_detail_sh(csh handle, cs_insn *ins)
{
	cs_detail *detail;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	detail = ins->detail;

	print_read_write_regs(detail, handle);

	printf("\tgroups_count: %u\n", detail->groups_count);

	for (i = 0; i < detail->sh.op_count; i++) {
		cs_sh_op *op = &(detail->sh.operands[i]);

		switch ((int)op->type) {
		default:
			break;
		case SH_OP_REG:
			printf("\t\toperands[%u].type: REG = %s\n", i,
			       cs_reg_name(handle, op->reg));
			break;
		case SH_OP_IMM:
			printf("\t\toperands[%u].type: IMM = 0x%x\n", i,
			       (int)op->imm);
			break;
		case SH_OP_MEM:
			printf("\t\toperands[%u].type: MEM\n", i);
			if (op->mem.reg != SH_REG_INVALID)
				printf("\t\t\toperands[%u].mem.reg: REG = %s\n",
				       i, cs_reg_name(handle, op->mem.reg));
			if (op->mem.disp != 0)
				printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i,
				       op->mem.disp);
			printf("\t\taddress mode: %s\n",
			       s_addressing_modes[op->mem.address]);
			break;
		}
	}
}

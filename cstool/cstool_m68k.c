//
//  cstool_m68k.c
//  
//
//  Created by YUHANG TANG on 26/10/16.
//
//

#include <stdio.h>
#include <capstone/capstone.h>

void print_insn_detail_m68k(csh handle, cs_insn *ins);

static const char* s_addressing_modes[] = {
	"<invalid mode>",

	"Register Direct - Data",
	"Register Direct - Address",

	"Register Indirect - Address",
	"Register Indirect - Address with Postincrement",
	"Register Indirect - Address with Predecrement",
	"Register Indirect - Address with Displacement",

	"Address Register Indirect With Index - 8-bit displacement",
	"Address Register Indirect With Index - Base displacement",

	"Memory indirect - Postindex",
	"Memory indirect - Preindex",

	"Program Counter Indirect - with Displacement",

	"Program Counter Indirect with Index - with 8-Bit Displacement",
	"Program Counter Indirect with Index - with Base Displacement",

	"Program Counter Memory Indirect - Postindexed",
	"Program Counter Memory Indirect - Preindexed",

	"Absolute Data Addressing  - Short",
	"Absolute Data Addressing  - Long",
	"Immediate value",
};

static void print_read_write_regs(cs_detail* detail, csh handle)
{
	int i;

	for (i = 0; i < detail->regs_read_count; ++i) {
		uint16_t reg_id = detail->regs_read[i];
		const char* reg_name = cs_reg_name(handle, reg_id);
		printf("\treading from reg: %s\n", reg_name);
	}

	for (i = 0; i < detail->regs_write_count; ++i) {
		uint16_t reg_id = detail->regs_write[i];
		const char* reg_name = cs_reg_name(handle, reg_id);
		printf("\twriting to reg:   %s\n", reg_name);
	}
}

void print_insn_detail_m68k(csh handle, cs_insn *ins)
{
	cs_m68k* m68k;
	cs_detail* detail;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	detail = ins->detail;
	m68k = &detail->m68k;
	if (m68k->op_count)
		printf("\top_count: %u\n", m68k->op_count);

	print_read_write_regs(detail, handle);

	printf("\tgroups_count: %u\n", detail->groups_count);

	for (i = 0; i < m68k->op_count; i++) {
		cs_m68k_op* op = &(m68k->operands[i]);

		switch((int)op->type) {
			default:
				break;
			case M68K_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case M68K_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%x\n", i, (int)op->imm);
				break;
			case M68K_OP_MEM:
				printf("\t\toperands[%u].type: MEM\n", i);
				if (op->mem.base_reg != M68K_REG_INVALID)
					printf("\t\t\toperands[%u].mem.base: REG = %s\n",
							i, cs_reg_name(handle, op->mem.base_reg));
				if (op->mem.index_reg != M68K_REG_INVALID) {
					printf("\t\t\toperands[%u].mem.index: REG = %s\n",
							i, cs_reg_name(handle, op->mem.index_reg));
					printf("\t\t\toperands[%u].mem.index: size = %c\n",
							i, op->mem.index_size ? 'l' : 'w');
				}
				if (op->mem.disp != 0)
					printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);
				if (op->mem.scale != 0)
					printf("\t\t\toperands[%u].mem.scale: %d\n", i, op->mem.scale);

				printf("\t\taddress mode: %s\n", s_addressing_modes[op->address_mode]);
				break;
			case M68K_OP_FP_SINGLE:
				printf("\t\toperands[%u].type: FP_SINGLE\n", i);
				printf("\t\t\toperands[%u].simm: %f\n", i, op->simm);
				break;
			case M68K_OP_FP_DOUBLE:
				printf("\t\toperands[%u].type: FP_DOUBLE\n", i);
				printf("\t\t\toperands[%u].dimm: %lf\n", i, op->dimm);
				break;
		}
	}
}


/* Capstone testing regression */
/* By Do Minh Tuan <tuanit96@gmail.com>, 02-2019 */


#include "factory.h"

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

static void print_read_write_regs(char *result, cs_detail* detail, csh *handle)
{
	int i;

	for (i = 0; i < detail->regs_read_count; ++i) {
		uint16_t reg_id = detail->regs_read[i];
		const char* reg_name = cs_reg_name(*handle, reg_id);
		add_str(&result, " ; reading from reg: %s", reg_name);
	}

	for (i = 0; i < detail->regs_write_count; ++i) {
		uint16_t reg_id = detail->regs_write[i];
		const char* reg_name = cs_reg_name(*handle, reg_id);
		add_str(&result, " ; writing to reg:   %s", reg_name);
	}
}

char *get_detail_m68k(csh *handle, cs_mode mode, cs_insn *ins)
{
	cs_m68k* m68k;
	cs_detail* detail;
	int i;
	char *result;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';

	if (ins->detail == NULL)
		return result;


	detail = ins->detail;
	m68k = &detail->m68k;
	if (m68k->op_count)
		add_str(&result, " ; op_count: %u", m68k->op_count);

	print_read_write_regs(result, detail, handle);

	add_str(&result, " ; groups_count: %u", detail->groups_count);

	for (i = 0; i < m68k->op_count; i++) {
		cs_m68k_op* op = &(m68k->operands[i]);

		switch((int)op->type) {
			default:
				break;
			case M68K_OP_REG:
				add_str(&result, " ; operands[%u].type: REG = %s", i, cs_reg_name(*handle, op->reg));
				break;
			case M68K_OP_IMM:
				add_str(&result, " ; operands[%u].type: IMM = 0x%x", i, (int)op->imm);
				break;
			case M68K_OP_MEM:
				add_str(&result, " ; operands[%u].type: MEM", i);
				if (op->mem.base_reg != M68K_REG_INVALID)
					add_str(&result, " ; operands[%u].mem.base: REG = %s", i, cs_reg_name(*handle, op->mem.base_reg));
				if (op->mem.index_reg != M68K_REG_INVALID) {
					add_str(&result, " ; operands[%u].mem.index: REG = %s", i, cs_reg_name(*handle, op->mem.index_reg));
					add_str(&result, " ; operands[%u].mem.index: size = %c", i, op->mem.index_size ? 'l' : 'w');
				}
				if (op->mem.disp != 0)
					add_str(&result, " ; operands[%u].mem.disp: 0x%x", i, op->mem.disp);
				if (op->mem.scale != 0)
					add_str(&result, " ; operands[%u].mem.scale: %d", i, op->mem.scale);

				add_str(&result, " ; address mode: %s", s_addressing_modes[op->address_mode]);
				break;
			case M68K_OP_FP_SINGLE:
				add_str(&result, " ; operands[%u].type: FP_SINGLE", i);
				add_str(&result, " ; operands[%u].simm: %f", i, op->simm);
				break;
			case M68K_OP_FP_DOUBLE:
				add_str(&result, " ; operands[%u].type: FP_DOUBLE", i);
				add_str(&result, " ; operands[%u].dimm: %lf", i, op->dimm);
				break;
		}
	}

	return result;
}

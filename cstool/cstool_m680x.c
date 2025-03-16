/* Capstone Disassembly Engine */
/* M680X Backend by Wolfgang Schwotzer <wolfgang.schwotzer@gmx.net> 2017 */

#include <stdio.h>
#include <capstone/capstone.h>
#include "cstool.h"

static const char *s_access[] = {
	"UNCHANGED", "READ", "WRITE", "READ | WRITE",
};

static void print_read_write_regs(csh handle, cs_detail *detail)
{
	int i;

	if (detail->regs_read_count > 0) {
		printf("\treading from regs: ");

		for (i = 0; i < detail->regs_read_count; ++i) {
			if (i > 0)
				printf(", ");

			printf("%s", cs_reg_name(handle, detail->regs_read[i]));
		}

		printf("\n");
	}

	if (detail->regs_write_count > 0) {
		printf("\twriting to regs: ");

		for (i = 0; i < detail->regs_write_count; ++i) {
			if (i > 0)
				printf(", ");

			printf("%s", cs_reg_name(handle,
					detail->regs_write[i]));
		}

		printf("\n");
	}
}

void print_insn_detail_m680x(csh handle, cs_insn *insn)
{
	cs_detail *detail = insn->detail;
	cs_m680x *m680x = NULL;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is
	// turned ON
	if (detail == NULL)
		return;

	m680x = &detail->d.m680x;

	if (m680x->op_count)
		printf("\top_count: %u\n", m680x->op_count);

	for (i = 0; i < m680x->op_count; i++) {
		cs_m680x_op *op = &(m680x->operands[i]);
		const char *comment;

		switch ((int)op->type) {
		default:
			break;

		case M680X_OP_REGISTER:
			comment = "";

			if ((i == 0 && m680x->flags & M680X_FIRST_OP_IN_MNEM) ||
				(i == 1 && m680x->flags &
					M680X_SECOND_OP_IN_MNEM))
				comment = " (in mnemonic)";

			printf("\t\toperands[%u].type: REGISTER = %s%s\n", i,
				cs_reg_name(handle, op->v.reg), comment);
			break;

		case M680X_OP_CONSTANT:
			printf("\t\toperands[%u].type: CONSTANT = %u\n", i,
				op->v.const_val);
			break;

		case M680X_OP_IMMEDIATE:
			printf("\t\toperands[%u].type: IMMEDIATE = #%d\n", i,
				op->v.imm);
			break;

		case M680X_OP_DIRECT:
			printf("\t\toperands[%u].type: DIRECT = 0x%02x\n", i,
				op->v.direct_addr);
			break;

		case M680X_OP_EXTENDED:
			printf("\t\toperands[%u].type: EXTENDED %s = 0x%04x\n",
				i, op->v.ext.indirect ? "INDIRECT" : "",
				op->v.ext.address);
			break;

		case M680X_OP_RELATIVE:
			printf("\t\toperands[%u].type: RELATIVE = 0x%04x\n", i,
				op->v.rel.address);
			break;

		case M680X_OP_INDEXED:
			printf("\t\toperands[%u].type: INDEXED%s\n", i,
				(op->v.idx.flags & M680X_IDX_INDIRECT) ?
				" INDIRECT" : "");

			if (op->v.idx.base_reg != M680X_REG_INVALID)
				printf("\t\t\tbase register: %s\n",
					cs_reg_name(handle, op->v.idx.base_reg));

			if (op->v.idx.offset_reg != M680X_REG_INVALID)
				printf("\t\t\toffset register: %s\n",
					cs_reg_name(handle, op->v.idx.offset_reg));

			if ((op->v.idx.offset_bits != 0) &&
				(op->v.idx.offset_reg == M680X_REG_INVALID) &&
				!op->v.idx.inc_dec) {
				printf("\t\t\toffset: %d\n", op->v.idx.offset);

				if (op->v.idx.base_reg == M680X_REG_PC)
					printf("\t\t\toffset address: 0x%x\n",
						op->v.idx.offset_addr);

				printf("\t\t\toffset bits: %u\n",
					op->v.idx.offset_bits);
			}

			if (op->v.idx.inc_dec) {
				const char *post_pre = op->v.idx.flags &
					M680X_IDX_POST_INC_DEC ? "post" : "pre";
				const char *inc_dec = (op->v.idx.inc_dec > 0) ?
					"increment" : "decrement";

				printf("\t\t\t%s %s: %d\n", post_pre, inc_dec,
					abs(op->v.idx.inc_dec));
			}

			break;
		}

		if (op->size != 0)
			printf("\t\t\tsize: %u\n", op->size);

		if (op->access != CS_AC_INVALID)
			printf("\t\t\taccess: %s\n", s_access[op->access]);
	}

	print_read_write_regs(handle, detail);
}


/* Capstone Disassembly Engine */
/* M680X Backend by Wolfgang Schwotzer <wolfgang.schwotzer@gmx.net> 2017 */

#include <stdio.h>
#include <capstone/capstone.h>

void print_string_hex(char *comment, unsigned char *str, size_t len);

static const char *s_addressing_modes[] = {
	"M680X_AM_NONE",
	"M680X_AM_INHERENT",
	"M680X_AM_REGISTER",
	"M680X_AM_IMMEDIATE",
	"M680X_AM_INDEXED",
	"M680X_AM_EXTENDED",
	"M680X_AM_DIRECT",
	"M680X_AM_RELATIVE",
	"M680X_AM_IMM_DIRECT",
	"M680X_AM_IMM_INDEXED",
};

void print_read_write_regs(csh handle, cs_detail *detail)
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

			printf("%s", cs_reg_name(handle, detail->regs_write[i]));
		}

		printf("\n");
	}
}

void print_insn_detail_m680x(csh handle, cs_insn *ins)
{
	cs_detail *detail = ins->detail;
	cs_m680x *m680x = NULL;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is
        //  turned ON
	if (detail == NULL)
		return;

	m680x = &detail->m680x;

	printf("\taddress_mode: %s\n", s_addressing_modes[m680x->address_mode]);

	if (m680x->op_count)
		printf("\toperand_count: %u\n", m680x->op_count);

	for (i = 0; i < m680x->op_count; i++) {
		cs_m680x_op *op = &(m680x->operands[i]);

		switch ((int)op->type) {
		default:
			break;

		case M680X_OP_REGISTER:
			printf("\t\toperands[%u].type: REGISTER = %s\n", i,
				cs_reg_name(handle, op->reg));
			break;

		case M680X_OP_IMMEDIATE:
			printf("\t\toperands[%u].type: IMMEDIATE = #%d\n", i,
                               op->imm);
			break;

		case M680X_OP_DIRECT:
			printf("\t\toperands[%u].type: DIRECT = 0x%02X\n", i,
                           op->direct_addr);
			break;

		case M680X_OP_EXTENDED:
			printf("\t\toperands[%u].type: EXTENDED %s = 0x%04X\n",
                                i, op->ext.indirect ? "INDIRECT" : "",
                                op->ext.address);
			break;

		case M680X_OP_RELATIVE:
			printf("\t\toperands[%u].type: RELATIVE = 0x%04X\n", i,
				op->rel.address);
			break;

		case M6800_OP_INDEXED:
			printf("\t\toperands[%u].type: INDEXED_M6800\n", i);

			if (op->idx.base_reg != M680X_REG_INVALID)
				printf("\t\t\tbase register: %s\n",
                                                cs_reg_name(handle,
						op->idx.base_reg));

			if (op->idx.offset_bits != 0) {
				printf("\t\t\toffset: %u\n", op->idx.offset);
				printf("\t\t\toffset bits: %u\n",
                                       op->idx.offset_bits);
			}

			break;

		case M6809_OP_INDEXED:
			printf("\t\toperands[%u].type: INDEXED_M6809 %s\n", i,
				op->idx.indirect ? "INDIRECT" : "");

			if (op->idx.base_reg != M680X_REG_INVALID)
				printf("\t\t\tbase register: %s\n",
                                       cs_reg_name(handle, op->idx.base_reg));

			if (op->idx.offset_reg != M680X_REG_INVALID)
				printf("\t\t\toffset register: %s\n",
                                       cs_reg_name(handle, op->idx.offset_reg));

			if ((op->idx.offset_bits != 0) &&
				(op->idx.offset_reg == M680X_REG_INVALID) &&
				(op->idx.inc_dec == 0)) {
				printf("\t\t\toffset: %d\n", op->idx.offset);

				if (op->idx.base_reg == M680X_REG_PC)
					printf("\t\t\toffset address: 0x%X\n",
                                               op->idx.offset_addr);

				printf("\t\t\toffset bits: %d\n",
                                       op->idx.offset_bits);
			}

			if (op->idx.inc_dec > 0)
				printf("\t\t\tpost increment: %d\n",
                                       op->idx.inc_dec);

			if (op->idx.inc_dec < 0)
				printf("\t\t\tpre decrement: %d\n",
                                        op->idx.inc_dec);

			break;
		}
	}

	print_read_write_regs(handle, detail);

	if (detail->groups_count)
		printf("\tgroups_count: %u\n", detail->groups_count);

	printf("\n");
}


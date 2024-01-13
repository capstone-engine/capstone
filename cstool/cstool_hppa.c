#include <stdio.h>

#include <capstone/capstone.h>
#include <capstone/platform.h>
#include "cstool.h"

#define LONG_MIN  (-__LONG_MAX__ -1L)

void printfInt64(int64_t val)
{
	if (val >= 0) {
		if (val > 9)
			printf("0x%"PRIx64, val);
		else
			printf("%"PRIu64, val);
	} else {
		if (val <- 9) {
			if (val == LONG_MIN)
				printf("-0x%"PRIx64, (uint64_t)val);
			else
				printf("-0x%"PRIx64, (uint64_t)-val);
		} else
			printf("-%"PRIu64, -val);
	}
}

void print_insn_detail_hppa(csh handle, cs_insn *ins)
{
	cs_hppa *hppa;
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;

    if (ins->detail == NULL)
        return;

    hppa = &ins->detail->hppa;

    printf("\tOperand count: %u\n", hppa->op_count);

    for (unsigned i = 0; i < hppa->op_count; i++) {
		cs_hppa_op *op = &(hppa->operands[i]);
        printf("\t\toperands[%u].type: ", i);
        switch (op->type)
        {
        case HPPA_OP_INVALID:
            printf("INVALID\n");
            break;
        case HPPA_OP_REG:
            printf("REG: %s\n", cs_reg_name(handle, op->reg));
            break;
        case HPPA_OP_IMM:
            printf("IMM: ");
            printfInt64(op->imm);
            printf("\n");
            break;
        case HPPA_OP_IDX_REG:
            printf("IDX_REG: %s\n", cs_reg_name(handle, op->reg));
            break;
        case HPPA_OP_DISP:
            printf("IMM: ");
            printfInt64(op->imm);
            printf("\n");
            break;
        case HPPA_OP_MEM:
            printf("MEM\n");
            if (op->mem.space != HPPA_OP_INVALID) {
                printf("\t\t\toperands[%u].mem.space: REG = %s\n",
						i, cs_reg_name(handle, op->mem.space));
            }
            printf("\t\t\toperands[%u].mem.base: REG = %s\n",
                    i, cs_reg_name(handle, op->mem.base));
            break;
        case HPPA_OP_TARGET:
            if (op->imm >= 0x8000000000000000)
                printf("TARGET: -0x%lx\n", -op->imm);
            else 
                printf("TARGET: 0x%lx\n", op->imm);
            break;
        }
    }

    if (!cs_regs_access(handle, ins,
			regs_read, &regs_read_count,
			regs_write, &regs_write_count)) {
		if (regs_read_count) {
			printf("\tRegisters read:");
			for(unsigned i = 0; i < regs_read_count; i++)
				printf(" %s", cs_reg_name(handle, regs_read[i]));
			printf("\n");
		}

		if (regs_write_count) {
			printf("\tRegisters modified:");
			for(unsigned i = 0; i < regs_write_count; i++)
				printf(" %s", cs_reg_name(handle, regs_write[i]));
			printf("\n");
		}
	}
}
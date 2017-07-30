/* Second-Best Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <stdio.h>
#include <stdlib.h>

#include <capstone.h>

void print_string_hex(char *comment, unsigned char *str, size_t len);

void print_insn_detail_x86(csh ud, cs_mode mode, cs_insn *ins)
{
	int count, i;
	cs_x86 *x86;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	x86 = &(ins->detail->x86);

	print_string_hex("\tPrefix:", x86->prefix, 4);

	print_string_hex("\tOpcode:", x86->opcode, 4);

	printf("\trex: 0x%x\n", x86->rex);

	printf("\taddr_size: %u\n", x86->addr_size);
	printf("\tmodrm: 0x%x\n", x86->modrm);
	printf("\tdisp: 0x%x\n", x86->disp);

	// SIB is not available in 16-bit mode
	if ((mode & CS_MODE_16) == 0) {
		printf("\tsib: 0x%x\n", x86->sib);
		if (x86->sib_base != X86_REG_INVALID)
			printf("\t\tsib_base: %s\n", cs_reg_name(ud, x86->sib_base));
		if (x86->sib_index != X86_REG_INVALID)
			printf("\t\tsib_index: %s\n", cs_reg_name(ud, x86->sib_index));
		if (x86->sib_scale != 0)
			printf("\t\tsib_scale: %d\n", x86->sib_scale);
	}

	// SSE code condition
	if (x86->sse_cc != X86_SSE_CC_INVALID) {
		printf("\tsse_cc: %u\n", x86->sse_cc);
	}

	// AVX code condition
	if (x86->avx_cc != X86_AVX_CC_INVALID) {
		printf("\tavx_cc: %u\n", x86->avx_cc);
	}

	// AVX Suppress All Exception
	if (x86->avx_sae) {
		printf("\tavx_sae: %u\n", x86->avx_sae);
	}

	// AVX Rounding Mode
	if (x86->avx_rm != X86_AVX_RM_INVALID) {
		printf("\tavx_rm: %u\n", x86->avx_rm);
	}

	count = cs_op_count(ud, ins, X86_OP_IMM);
	if (count > 0) {
		printf("\timm_count: %u\n", count);
		for (i = 1; i < count + 1; i++) {
			int index = cs_op_index(ud, ins, X86_OP_IMM, i);
			printf("\t\timms[%u]: 0x%" PRIx64 "\n", i, x86->operands[index].imm);
		}
	}

	if (x86->op_count)
		printf("\top_count: %u\n", x86->op_count);
	for (i = 0; i < x86->op_count; i++) {
		cs_x86_op *op = &(x86->operands[i]);

		switch((int)op->type) {
			case X86_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(ud, op->reg));
				break;
			case X86_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "\n", i, op->imm);
				break;
			case X86_OP_MEM:
				printf("\t\toperands[%u].type: MEM\n", i);
				if (op->mem.segment != X86_REG_INVALID)
					printf("\t\t\toperands[%u].mem.segment: REG = %s\n", i, cs_reg_name(ud, op->mem.segment));
				if (op->mem.base != X86_REG_INVALID)
					printf("\t\t\toperands[%u].mem.base: REG = %s\n", i, cs_reg_name(ud, op->mem.base));
				if (op->mem.index != X86_REG_INVALID)
					printf("\t\t\toperands[%u].mem.index: REG = %s\n", i, cs_reg_name(ud, op->mem.index));
				if (op->mem.scale != 1)
					printf("\t\t\toperands[%u].mem.scale: %u\n", i, op->mem.scale);
				if (op->mem.disp != 0)
					printf("\t\t\toperands[%u].mem.disp: 0x%" PRIx64 "\n", i, op->mem.disp);
				break;
			default:
				break;
		}

		// AVX broadcast type
		if (op->avx_bcast != X86_AVX_BCAST_INVALID)
			printf("\t\toperands[%u].avx_bcast: %u\n", i, op->avx_bcast);

		// AVX zero opmask {z}
		if (op->avx_zero_opmask != false)
			printf("\t\toperands[%u].avx_zero_opmask: TRUE\n", i);

		printf("\t\toperands[%u].size: %u\n", i, op->size);
	}
}

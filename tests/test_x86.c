/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013 */

#include <stdio.h>
#include <stdlib.h>

#include <capstone/platform.h>
#include <capstone/capstone.h>

static csh handle;

struct platform {
	cs_arch arch;
	cs_mode mode;
	unsigned char *code;
	size_t size;
	const char *comment;
	cs_opt_type opt_type;
	cs_opt_value opt_value;
};

static void print_string_hex(const char *comment, unsigned char *str, size_t len)
{
	unsigned char *c;

	printf("%s [", comment);
	for (c = str; c < str + len; c++) {
		printf("0x%02x, ", *c & 0xff);
	}

	printf("]\n");
}

static const char *get_eflag_name(uint64_t flag)
{
	switch(flag) {
		default:
			return NULL;
		case X86_EFLAGS_UNDEFINED_OF:
			return "X86_EFLAGS_UNDEFINED_OF";
		case X86_EFLAGS_UNDEFINED_SF:
			return "X86_EFLAGS_UNDEFINED_SF";
		case X86_EFLAGS_UNDEFINED_ZF:
			return "X86_EFLAGS_UNDEFINED_ZF";
		case X86_EFLAGS_MODIFY_AF:
			return "X86_EFLAGS_MODIFY_AF";
		case X86_EFLAGS_UNDEFINED_PF:
			return "X86_EFLAGS_UNDEFINED_PF";
		case X86_EFLAGS_MODIFY_CF:
			return "X86_EFLAGS_MODIFY_CF";
		case X86_EFLAGS_MODIFY_SF:
			return "X86_EFLAGS_MODIFY_SF";
		case X86_EFLAGS_MODIFY_ZF:
			return "X86_EFLAGS_MODIFY_ZF";
		case X86_EFLAGS_UNDEFINED_AF:
			return "X86_EFLAGS_UNDEFINED_AF";
		case X86_EFLAGS_MODIFY_PF:
			return "X86_EFLAGS_MODIFY_PF";
		case X86_EFLAGS_UNDEFINED_CF:
			return "X86_EFLAGS_UNDEFINED_CF";
		case X86_EFLAGS_MODIFY_OF:
			return "X86_EFLAGS_MODIFY_OF";
		case X86_EFLAGS_RESET_OF:
			return "X86_EFLAGS_RESET_OF";
		case X86_EFLAGS_RESET_CF:
			return "X86_EFLAGS_RESET_CF";
		case X86_EFLAGS_RESET_DF:
			return "X86_EFLAGS_RESET_DF";
		case X86_EFLAGS_RESET_IF:
			return "X86_EFLAGS_RESET_IF";
		case X86_EFLAGS_TEST_OF:
			return "X86_EFLAGS_TEST_OF";
		case X86_EFLAGS_TEST_SF:
			return "X86_EFLAGS_TEST_SF";
		case X86_EFLAGS_TEST_ZF:
			return "X86_EFLAGS_TEST_ZF";
		case X86_EFLAGS_TEST_PF:
			return "X86_EFLAGS_TEST_PF";
		case X86_EFLAGS_TEST_CF:
			return "X86_EFLAGS_TEST_CF";
		case X86_EFLAGS_RESET_SF:
			return "X86_EFLAGS_RESET_SF";
		case X86_EFLAGS_RESET_AF:
			return "X86_EFLAGS_RESET_AF";
		case X86_EFLAGS_RESET_TF:
			return "X86_EFLAGS_RESET_TF";
		case X86_EFLAGS_RESET_NT:
			return "X86_EFLAGS_RESET_NT";
		case X86_EFLAGS_PRIOR_OF:
			return "X86_EFLAGS_PRIOR_OF";
		case X86_EFLAGS_PRIOR_SF:
			return "X86_EFLAGS_PRIOR_SF";
		case X86_EFLAGS_PRIOR_ZF:
			return "X86_EFLAGS_PRIOR_ZF";
		case X86_EFLAGS_PRIOR_AF:
			return "X86_EFLAGS_PRIOR_AF";
		case X86_EFLAGS_PRIOR_PF:
			return "X86_EFLAGS_PRIOR_PF";
		case X86_EFLAGS_PRIOR_CF:
			return "X86_EFLAGS_PRIOR_CF";
		case X86_EFLAGS_PRIOR_TF:
			return "X86_EFLAGS_PRIOR_TF";
		case X86_EFLAGS_PRIOR_IF:
			return "X86_EFLAGS_PRIOR_IF";
		case X86_EFLAGS_PRIOR_DF:
			return "X86_EFLAGS_PRIOR_DF";
		case X86_EFLAGS_TEST_NT:
			return "X86_EFLAGS_TEST_NT";
		case X86_EFLAGS_TEST_DF:
			return "X86_EFLAGS_TEST_DF";
		case X86_EFLAGS_RESET_PF:
			return "X86_EFLAGS_RESET_PF";
		case X86_EFLAGS_PRIOR_NT:
			return "X86_EFLAGS_PRIOR_NT";
		case X86_EFLAGS_MODIFY_TF:
			return "X86_EFLAGS_MODIFY_TF";
		case X86_EFLAGS_MODIFY_IF:
			return "X86_EFLAGS_MODIFY_IF";
		case X86_EFLAGS_MODIFY_DF:
			return "X86_EFLAGS_MODIFY_DF";
		case X86_EFLAGS_MODIFY_NT:
			return "X86_EFLAGS_MODIFY_NT";
		case X86_EFLAGS_MODIFY_RF:
			return "X86_EFLAGS_MODIFY_RF";
		case X86_EFLAGS_SET_CF:
			return "X86_EFLAGS_SET_CF";
		case X86_EFLAGS_SET_DF:
			return "X86_EFLAGS_SET_DF";
		case X86_EFLAGS_SET_IF:
			return "X86_EFLAGS_SET_IF";
	}
}

static const char *get_fpu_flag_name(uint64_t flag)
{
	switch (flag) {
		default:
			return NULL;
		case X86_FPU_FLAGS_MODIFY_C0:
			return "X86_FPU_FLAGS_MODIFY_C0";
		case X86_FPU_FLAGS_MODIFY_C1:
			return "X86_FPU_FLAGS_MODIFY_C1";
		case X86_FPU_FLAGS_MODIFY_C2:
			return "X86_FPU_FLAGS_MODIFY_C2";
		case X86_FPU_FLAGS_MODIFY_C3:
			return "X86_FPU_FLAGS_MODIFY_C3";
		case X86_FPU_FLAGS_RESET_C0:
			return "X86_FPU_FLAGS_RESET_C0";
		case X86_FPU_FLAGS_RESET_C1:
			return "X86_FPU_FLAGS_RESET_C1";
		case X86_FPU_FLAGS_RESET_C2:
			return "X86_FPU_FLAGS_RESET_C2";
		case X86_FPU_FLAGS_RESET_C3:
			return "X86_FPU_FLAGS_RESET_C3";
		case X86_FPU_FLAGS_SET_C0:
			return "X86_FPU_FLAGS_SET_C0";
		case X86_FPU_FLAGS_SET_C1:
			return "X86_FPU_FLAGS_SET_C1";
		case X86_FPU_FLAGS_SET_C2:
			return "X86_FPU_FLAGS_SET_C2";
		case X86_FPU_FLAGS_SET_C3:
			return "X86_FPU_FLAGS_SET_C3";
		case X86_FPU_FLAGS_UNDEFINED_C0:
			return "X86_FPU_FLAGS_UNDEFINED_C0";
		case X86_FPU_FLAGS_UNDEFINED_C1:
			return "X86_FPU_FLAGS_UNDEFINED_C1";
		case X86_FPU_FLAGS_UNDEFINED_C2:
			return "X86_FPU_FLAGS_UNDEFINED_C2";
		case X86_FPU_FLAGS_UNDEFINED_C3:
			return "X86_FPU_FLAGS_UNDEFINED_C3";
		case X86_FPU_FLAGS_TEST_C0:
			return "X86_FPU_FLAGS_TEST_C0";
		case X86_FPU_FLAGS_TEST_C1:
			return "X86_FPU_FLAGS_TEST_C1";
		case X86_FPU_FLAGS_TEST_C2:
			return "X86_FPU_FLAGS_TEST_C2";
		case X86_FPU_FLAGS_TEST_C3:
			return "X86_FPU_FLAGS_TEST_C3";
		}
}

static const char *get_avx_rm_flag_name(uint64_t flag)
{
	switch (flag) {
	default:
		return NULL;
	case X86_AVX_RM_RN:
		return "X86_AVX_RM_RN";
	case X86_AVX_RM_RD:
		return "X86_AVX_RM_RD";
	case X86_AVX_RM_RU:
		return "X86_AVX_RM_RU";
	case X86_AVX_RM_RZ:
		return "X86_AVX_RM_RZ";
	}
}

static const char *get_prefix_flag_name(uint64_t flag)
{
	switch (flag) {
	default:
		return NULL;
	case 0:
		return "X86_PREFIX_0";
	case X86_PREFIX_LOCK:
		return "X86_PREFIX_LOCK";
	case X86_PREFIX_REP:
		return "X86_PREFIX_REP";
	case X86_PREFIX_REPNE:
		return "X86_PREFIX_REPNE";
	case X86_PREFIX_CS:
		return "X86_PREFIX_CS";
	case X86_PREFIX_SS:
		return "X86_PREFIX_SS";
	case X86_PREFIX_DS:
		return "X86_PREFIX_DS";
	case X86_PREFIX_ES:
		return "X86_PREFIX_ES";
	case X86_PREFIX_FS:
		return "X86_PREFIX_FS";
	case X86_PREFIX_GS:
		return "X86_PREFIX_GS";
	case X86_PREFIX_OPSIZE:
		return "X86_PREFIX_OPSIZE";
	case X86_PREFIX_ADDRSIZE:
		return "X86_PREFIX_ADDRSIZE";
	}
}

static const char *get_xop_cc_flag_name(uint64_t flag)
{
	switch (flag) {
	default:
		return NULL;
	case X86_XOP_CC_LT:
		return "X86_XOP_CC_LT";
	case X86_XOP_CC_LE:
		return "X86_XOP_CC_LE";
	case X86_XOP_CC_GT:
		return "X86_XOP_CC_GT";
	case X86_XOP_CC_GE:
		return "X86_XOP_CC_GE";
	case X86_XOP_CC_EQ:
		return "X86_XOP_CC_EQ";
	case X86_XOP_CC_NEQ:
		return "X86_XOP_CC_NEQ";
	case X86_XOP_CC_FALSE:
		return "X86_XOP_CC_FALSE";
	case X86_XOP_CC_TRUE:
		return "X86_XOP_CC_TRUE";
	}
}

static const char *get_avx_bcast_flag_name(uint64_t flag)
{
	switch (flag) {
	default:
		return NULL;
	case X86_AVX_BCAST_2:
		return "X86_AVX_BCAST_2";
	case X86_AVX_BCAST_4:
		return "X86_AVX_BCAST_4";
	case X86_AVX_BCAST_8:
		return "X86_AVX_BCAST_8";
	case X86_AVX_BCAST_16:
		return "X86_AVX_BCAST_16";
	}
}

static const char *get_sse_cc_flag_name(uint64_t flag)
{
	switch (flag) {
	default:
		return NULL;
	case X86_SSE_CC_EQ:
		return "X86_SSE_CC_EQ";
	case X86_SSE_CC_LT:
		return "X86_SSE_CC_LT";
	case X86_SSE_CC_LE:
		return "X86_SSE_CC_LE";
	case X86_SSE_CC_UNORD:
		return "X86_SSE_CC_UNORD";
	case X86_SSE_CC_NEQ:
		return "X86_SSE_CC_NEQ";
	case X86_SSE_CC_NLT:
		return "X86_SSE_CC_NLT";
	case X86_SSE_CC_NLE:
		return "X86_SSE_CC_NLE";
	case X86_SSE_CC_ORD:
		return "X86_SSE_CC_ORD";
	}
}

static const char *get_avx_cc_flag_name(uint64_t flag)
{
	switch (flag) {
	default:
		return NULL;
	case X86_AVX_CC_EQ:
		return "X86_AVX_CC_EQ";
	case X86_AVX_CC_LT:
		return "X86_AVX_CC_LT";
	case X86_AVX_CC_LE:
		return "X86_AVX_CC_LE";
	case X86_AVX_CC_UNORD:
		return "X86_AVX_CC_UNORD";
	case X86_AVX_CC_NEQ:
		return "X86_AVX_CC_NEQ";
	case X86_AVX_CC_NLT:
		return "X86_AVX_CC_NLT";
	case X86_AVX_CC_NLE:
		return "X86_AVX_CC_NLE";
	case X86_AVX_CC_ORD:
		return "X86_AVX_CC_ORD";
	case X86_AVX_CC_EQ_UQ:
		return "X86_AVX_CC_EQ_UQ";
	case X86_AVX_CC_NGE:
		return "X86_AVX_CC_NGE";
	case X86_AVX_CC_NGT:
		return "X86_AVX_CC_NGT";
	case X86_AVX_CC_FALSE:
		return "X86_AVX_CC_FALSE";
	case X86_AVX_CC_NEQ_OQ:
		return "X86_AVX_CC_NEQ_OQ";
	case X86_AVX_CC_GE:
		return "X86_AVX_CC_GE";
	case X86_AVX_CC_GT:
		return "X86_AVX_CC_GT";
	case X86_AVX_CC_TRUE:
		return "X86_AVX_CC_TRUE";
	case X86_AVX_CC_EQ_OS:
		return "X86_AVX_CC_EQ_OS";
	case X86_AVX_CC_LT_OQ:
		return "X86_AVX_CC_LT_OQ";
	case X86_AVX_CC_LE_OQ:
		return "X86_AVX_CC_LE_OQ";
	case X86_AVX_CC_UNORD_S:
		return "X86_AVX_CC_UNORD_S";
	case X86_AVX_CC_NEQ_US:
		return "X86_AVX_CC_NEQ_US";
	case X86_AVX_CC_NLT_UQ:
		return "X86_AVX_CC_NLT_UQ";
	case X86_AVX_CC_NLE_UQ:
		return "X86_AVX_CC_NLE_UQ";
	case X86_AVX_CC_ORD_S:
		return "X86_AVX_CC_ORD_S";
	case X86_AVX_CC_EQ_US:
		return "X86_AVX_CC_EQ_US";
	case X86_AVX_CC_NGE_UQ:
		return "X86_AVX_CC_NGE_UQ";
	case X86_AVX_CC_NGT_UQ:
		return "X86_AVX_CC_NGT_UQ";
	case X86_AVX_CC_FALSE_OS:
		return "X86_AVX_CC_FALSE_OS";
	case X86_AVX_CC_NEQ_OS:
		return "X86_AVX_CC_NEQ_OS";
	case X86_AVX_CC_GE_OQ:
		return "X86_AVX_CC_GE_OQ";
	case X86_AVX_CC_GT_OQ:
		return "X86_AVX_CC_GT_OQ";
	case X86_AVX_CC_TRUE_US:
		return "X86_AVX_CC_TRUE_US";
	}
}

static void print_insn_detail(csh ud, cs_mode mode, cs_insn *ins)
{
	int i;
	cs_x86 *x86;
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	x86 = &(ins->detail->x86);

	printf("%s [", "\tPrefix:");
	for (uint8_t c = 0; c < 4; c++) {
		printf("%s, ", get_prefix_flag_name(x86->prefix[c] & 0xff));
	}
	printf("]\n");

	print_string_hex("\tOpcode:", x86->opcode, 4);

	printf("\trex: 0x%x\n", x86->rex);

	printf("\taddr_size: %u\n", x86->addr_size);
	printf("\tmodrm: 0x%x\n", x86->modrm);
	if (x86->encoding.modrm_offset != 0) {
		printf("\tmodrm_offset: 0x%x\n", x86->encoding.modrm_offset);
	}
	
	printf("\tdisp: 0x%" PRIx64 "\n", x86->disp);
	if (x86->encoding.disp_offset != 0) {
		printf("\tdisp_offset: 0x%x\n", x86->encoding.disp_offset);
	}
	
	if (x86->encoding.disp_size != 0) {
		printf("\tdisp_size: 0x%x\n", x86->encoding.disp_size);
	}
	
	// SIB is not available in 16-bit mode
	if ((mode & CS_MODE_16) == 0) {
		printf("\tsib: 0x%x\n", x86->sib);
		if (x86->sib_base != X86_REG_INVALID)
			printf("\t\tsib_base: %s\n", cs_reg_name(handle, x86->sib_base));
		if (x86->sib_index != X86_REG_INVALID)
			printf("\t\tsib_index: %s\n", cs_reg_name(handle, x86->sib_index));
		if (x86->sib_scale != 0)
			printf("\t\tsib_scale: %d\n", x86->sib_scale);
	}

	// XOP code condition
	if (x86->xop_cc != X86_XOP_CC_INVALID) {
		printf("\txop_cc: %s\n", get_xop_cc_flag_name(x86->xop_cc));
	}

	// SSE code condition
	if (x86->sse_cc != X86_SSE_CC_INVALID) {
		printf("\tsse_cc: %s\n", get_sse_cc_flag_name(x86->sse_cc));
	}

	// AVX code condition
	if (x86->avx_cc != X86_AVX_CC_INVALID) {
		printf("\tavx_cc: %s\n", get_avx_cc_flag_name(x86->avx_cc));
	}

	// AVX Suppress All Exception
	if (x86->avx_sae) {
		printf("\tavx_sae: %s\n", x86->avx_sae ? "1" : "-1");
	}

	// AVX Rounding Mode
	if (x86->avx_rm != X86_AVX_RM_INVALID) {
		printf("\tavx_rm: %s\n", get_avx_rm_flag_name(x86->avx_rm));
	}

	// Print out all immediate operands
	// count = cs_op_count(ud, ins, X86_OP_IMM);
	// if (count) {
	// 	printf("\timm_count: %u\n", count);
	// 	for (i = 1; i < count + 1; i++) {
	// 		int index = cs_op_index(ud, ins, X86_OP_IMM, i);
	// 		printf("\t\timms[%u]: 0x%" PRIx64 "\n", i, x86->operands[index].imm);
	// 		if (x86->encoding.imm_offset != 0) {
	// 			printf("\timm_offset: 0x%x\n", x86->encoding.imm_offset);
	// 		}

	// 		if (x86->encoding.imm_size != 0) {
	// 			printf("\timm_size: 0x%x\n", x86->encoding.imm_size);
	// 		}
	// 	}
	// }

	// if (x86->op_count)
	// 	printf("\top_count: %u\n", x86->op_count);

	// Print out all operands
	for (i = 0; i < x86->op_count; i++) {
		cs_x86_op *op = &(x86->operands[i]);

		switch((int)op->type) {
			case X86_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case X86_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "\n", i, op->imm);
				break;
			case X86_OP_MEM:
				printf("\t\toperands[%u].type: MEM\n", i);
				if (op->mem.segment != X86_REG_INVALID)
					printf("\t\t\toperands[%u].mem.segment: REG = %s\n", i, cs_reg_name(handle, op->mem.segment));
				if (op->mem.base != X86_REG_INVALID)
					printf("\t\t\toperands[%u].mem.base: REG = %s\n", i, cs_reg_name(handle, op->mem.base));
				if (op->mem.index != X86_REG_INVALID)
					printf("\t\t\toperands[%u].mem.index: REG = %s\n", i, cs_reg_name(handle, op->mem.index));
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
			printf("\t\toperands[%u].avx_bcast: %s\n", i,
			       get_avx_bcast_flag_name(op->avx_bcast));

		// AVX zero opmask {z}
		if (op->avx_zero_opmask != false)
			printf("\t\toperands[%u].avx_zero_opmask: %u\n", i, 1);

		printf("\t\toperands[%u].size: %u\n", i, op->size);

		switch(op->access) {
			default:
				break;
			case CS_AC_READ:
				printf("\t\toperands[%u].access: READ\n", i);
				break;
			case CS_AC_WRITE:
				printf("\t\toperands[%u].access: WRITE\n", i);
				break;
			case CS_AC_READ | CS_AC_WRITE:
				printf("\t\toperands[%u].access: READ | WRITE\n", i);
				break;
		}
	}

	// Print out all registers accessed by this instruction (either implicit or explicit)
	if (!cs_regs_access(ud, ins,
				regs_read, &regs_read_count,
				regs_write, &regs_write_count)) {
		if (regs_read_count) {
			printf("\tRegisters read:");
			for(i = 0; i < regs_read_count; i++) {
				printf(" %s", cs_reg_name(handle, regs_read[i]));
			}
			printf("\n");
		}

		if (regs_write_count) {
			printf("\tRegisters modified:");
			for(i = 0; i < regs_write_count; i++) {
				printf(" %s", cs_reg_name(handle, regs_write[i]));
			}
			printf("\n");
		}
	}

	if (x86->eflags || x86->fpu_flags) {
		for(i = 0; i < ins->detail->groups_count; i++) {
			if (ins->detail->groups[i] == X86_GRP_FPU) {
				printf("\tFPU_FLAGS: [");
				for(i = 0; i <= 63; i++)
					if (x86->fpu_flags & ((uint64_t)1 << i)) {
						printf(" %s", get_fpu_flag_name((uint64_t)1 << i));
					}
				printf("]\n");
				break;
			}
		}

		if (i == ins->detail->groups_count) {
			printf("\tEFLAGS: [ ");
			for(i = 0; i <= 63; i++)
				if (x86->eflags & ((uint64_t)1 << i)) {
					printf(" %s", get_eflag_name((uint64_t)1 << i));
				}
			printf(" ]\n");
		}
	}

	printf("\n");
}

static void test()
{
#define X86_CODE64 "\x55\x48\x8b\x05\xb8\x13\x00\x00\xe9\xea\xbe\xad\xde\xff\x25\x23\x01\x00\x00\xe8\xdf\xbe\xad\xde\x74\xff"
#define X86_CODE16 "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89\x67\x00\x00\xb4\xc6\x66\xe9\xb8\x00\x00\x00\x67\xff\xa0\x23\x01\x00\x00\x66\xe8\xcb\x00\x00\x00\x74\xfc"
#define X86_CODE32 "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89\x67\x00\x00\xb4\xc6\xe9\xea\xbe\xad\xde\xff\xa0\x23\x01\x00\x00\xe8\xdf\xbe\xad\xde\x74\xff"

	struct platform platforms[] = {
		{
			CS_ARCH_X86,
			CS_MODE_16,
			(unsigned char *)X86_CODE16,
			sizeof(X86_CODE16) - 1,
			"X86 16bit (Intel syntax)"
		},
		{
			CS_ARCH_X86,
			CS_MODE_32,
			(unsigned char *)X86_CODE32,
			sizeof(X86_CODE32) - 1,
			"X86 32 (AT&T syntax)",
			CS_OPT_SYNTAX,
			CS_OPT_SYNTAX_ATT,
		},
		{
			CS_ARCH_X86,
			CS_MODE_32,
			(unsigned char *)X86_CODE32,
			sizeof(X86_CODE32) - 1,
			"X86 32 (Intel syntax)"
		},
		{
			CS_ARCH_X86,
			CS_MODE_64,
			(unsigned char *)X86_CODE64,
			sizeof(X86_CODE64) - 1,
			"X86 64 (Intel syntax)"
		},
	};

	uint64_t address = 0x1000;
	cs_insn *insn;
	int i;
	size_t count;

	for (i = 0; i < sizeof(platforms)/sizeof(platforms[0]); i++) {
		cs_err err = cs_open(platforms[i].arch, platforms[i].mode, &handle);
		if (err) {
			printf("Failed on cs_open() with error returned: %u\n", err);
			abort();
		}

		if (platforms[i].opt_type)
			cs_option(handle, platforms[i].opt_type, platforms[i].opt_value);

		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

		count = cs_disasm(handle, platforms[i].code, platforms[i].size, address, 0, &insn);
		if (count) {
			size_t j;

			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code:", platforms[i].code, platforms[i].size);
			printf("Disasm:\n");

			for (j = 0; j < count; j++) {
				printf("0x%" PRIx64 ":\t%s\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
				print_insn_detail(handle, platforms[i].mode, &insn[j]);
			}
			printf("0x%" PRIx64 ":\n", insn[j-1].address + insn[j-1].size);

			// free memory allocated by cs_disasm()
			cs_free(insn, count);
		} else {
			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code:", platforms[i].code, platforms[i].size);
			printf("ERROR: Failed to disasm given code!\n");
			abort();
		}

		printf("\n");

		cs_close(&handle);
	}
}

int main()
{
	test();

	return 0;
}

/* Capstone testing regression */
/* By Do Minh Tuan <tuanit96@gmail.com>, 02-2019 */


#include "factory.h"

static void print_string_hex(char **result, const char *comment, unsigned char *str, size_t len)
{
	unsigned char *c;

	add_str(result, "%s", comment);
	for (c = str; c < str + len; c++) {
		add_str(result, "0x%02x", *c & 0xff);
		if (c < str + len - 1)
			add_str(result, " ");
	}

}

static const char *get_eflag_name(uint64_t flag)
{
	switch(flag) {
		default:
			return NULL;
		case X86_EFLAGS_UNDEFINED_OF:
			return "UNDEF_OF";
		case X86_EFLAGS_UNDEFINED_SF:
			return "UNDEF_SF";
		case X86_EFLAGS_UNDEFINED_ZF:
			return "UNDEF_ZF";
		case X86_EFLAGS_MODIFY_AF:
			return "MOD_AF";
		case X86_EFLAGS_UNDEFINED_PF:
			return "UNDEF_PF";
		case X86_EFLAGS_MODIFY_CF:
			return "MOD_CF";
		case X86_EFLAGS_MODIFY_SF:
			return "MOD_SF";
		case X86_EFLAGS_MODIFY_ZF:
			return "MOD_ZF";
		case X86_EFLAGS_UNDEFINED_AF:
			return "UNDEF_AF";
		case X86_EFLAGS_MODIFY_PF:
			return "MOD_PF";
		case X86_EFLAGS_UNDEFINED_CF:
			return "UNDEF_CF";
		case X86_EFLAGS_MODIFY_OF:
			return "MOD_OF";
		case X86_EFLAGS_RESET_OF:
			return "RESET_OF";
		case X86_EFLAGS_RESET_CF:
			return "RESET_CF";
		case X86_EFLAGS_RESET_DF:
			return "RESET_DF";
		case X86_EFLAGS_RESET_IF:
			return "RESET_IF";
		case X86_EFLAGS_RESET_ZF:
			return "RESET_ZF";
		case X86_EFLAGS_TEST_OF:
			return "TEST_OF";
		case X86_EFLAGS_TEST_SF:
			return "TEST_SF";
		case X86_EFLAGS_TEST_ZF:
			return "TEST_ZF";
		case X86_EFLAGS_TEST_PF:
			return "TEST_PF";
		case X86_EFLAGS_TEST_CF:
			return "TEST_CF";
		case X86_EFLAGS_RESET_SF:
			return "RESET_SF";
		case X86_EFLAGS_RESET_AF:
			return "RESET_AF";
		case X86_EFLAGS_RESET_TF:
			return "RESET_TF";
		case X86_EFLAGS_RESET_NT:
			return "RESET_NT";
		case X86_EFLAGS_PRIOR_OF:
			return "PRIOR_OF";
		case X86_EFLAGS_PRIOR_SF:
			return "PRIOR_SF";
		case X86_EFLAGS_PRIOR_ZF:
			return "PRIOR_ZF";
		case X86_EFLAGS_PRIOR_AF:
			return "PRIOR_AF";
		case X86_EFLAGS_PRIOR_PF:
			return "PRIOR_PF";
		case X86_EFLAGS_PRIOR_CF:
			return "PRIOR_CF";
		case X86_EFLAGS_PRIOR_TF:
			return "PRIOR_TF";
		case X86_EFLAGS_PRIOR_IF:
			return "PRIOR_IF";
		case X86_EFLAGS_PRIOR_DF:
			return "PRIOR_DF";
		case X86_EFLAGS_TEST_NT:
			return "TEST_NT";
		case X86_EFLAGS_TEST_DF:
			return "TEST_DF";
		case X86_EFLAGS_RESET_PF:
			return "RESET_PF";
		case X86_EFLAGS_PRIOR_NT:
			return "PRIOR_NT";
		case X86_EFLAGS_MODIFY_TF:
			return "MOD_TF";
		case X86_EFLAGS_MODIFY_IF:
			return "MOD_IF";
		case X86_EFLAGS_MODIFY_DF:
			return "MOD_DF";
		case X86_EFLAGS_MODIFY_NT:
			return "MOD_NT";
		case X86_EFLAGS_MODIFY_RF:
			return "MOD_RF";
		case X86_EFLAGS_SET_CF:
			return "SET_CF";
		case X86_EFLAGS_SET_DF:
			return "SET_DF";
		case X86_EFLAGS_SET_IF:
			return "SET_IF";
		case X86_EFLAGS_SET_OF:
			return "SET_OF";
		case X86_EFLAGS_SET_SF:
			return "SET_SF";
		case X86_EFLAGS_SET_ZF:
			return "SET_ZF";
		case X86_EFLAGS_SET_AF:
			return "SET_AF";
		case X86_EFLAGS_SET_PF:
			return "SET_PF";
		case X86_EFLAGS_TEST_AF:
			return "TEST_AF";
		case X86_EFLAGS_TEST_TF:
			return "TEST_TF";
		case X86_EFLAGS_TEST_RF:
			return "TEST_RF";
		case X86_EFLAGS_RESET_0F:
			return "RESET_0F";
		case X86_EFLAGS_RESET_AC:
			return "RESET_AC";
	}
}

static const char *get_fpu_flag_name(uint64_t flag)
{
	switch (flag) {
		default:
			return NULL;
		case X86_FPU_FLAGS_MODIFY_C0:
			return "MOD_C0";
		case X86_FPU_FLAGS_MODIFY_C1:
			return "MOD_C1";
		case X86_FPU_FLAGS_MODIFY_C2:
			return "MOD_C2";
		case X86_FPU_FLAGS_MODIFY_C3:
			return "MOD_C3";
		case X86_FPU_FLAGS_RESET_C0:
			return "RESET_C0";
		case X86_FPU_FLAGS_RESET_C1:
			return "RESET_C1";
		case X86_FPU_FLAGS_RESET_C2:
			return "RESET_C2";
		case X86_FPU_FLAGS_RESET_C3:
			return "RESET_C3";
		case X86_FPU_FLAGS_SET_C0:
			return "SET_C0";
		case X86_FPU_FLAGS_SET_C1:
			return "SET_C1";
		case X86_FPU_FLAGS_SET_C2:
			return "SET_C2";
		case X86_FPU_FLAGS_SET_C3:
			return "SET_C3";
		case X86_FPU_FLAGS_UNDEFINED_C0:
			return "UNDEF_C0";
		case X86_FPU_FLAGS_UNDEFINED_C1:
			return "UNDEF_C1";
		case X86_FPU_FLAGS_UNDEFINED_C2:
			return "UNDEF_C2";
		case X86_FPU_FLAGS_UNDEFINED_C3:
			return "UNDEF_C3";
		case X86_FPU_FLAGS_TEST_C0:
			return "TEST_C0";
		case X86_FPU_FLAGS_TEST_C1:
			return "TEST_C1";
		case X86_FPU_FLAGS_TEST_C2:
			return "TEST_C2";
		case X86_FPU_FLAGS_TEST_C3:
			return "TEST_C3";
	}
}

char *get_detail_x86(csh *ud, cs_mode mode, cs_insn *ins)
{
	int count, i;
	cs_x86 *x86;
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;
	char *result;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';

	if (ins->detail == NULL)
		return result;

	x86 = &(ins->detail->x86);

	add_str(&result, " ; ID: %" PRIu32 , ins->id);
	print_string_hex(&result, " ; Prefix:", x86->prefix, 4);
	print_string_hex(&result, " ; Opcode:", x86->opcode, 4);
	add_str(&result, " ; rex: 0x%x", x86->rex);
	add_str(&result, " ; addr_size: %u", x86->addr_size);
	add_str(&result, " ; modrm: 0x%x", x86->modrm);
	add_str(&result, " ; disp: 0x%" PRIx64 "", x86->disp);

	if ((mode & CS_MODE_16) == 0) {
		add_str(&result, " ; sib: 0x%x", x86->sib);
		if (x86->sib_base != X86_REG_INVALID)
			add_str(&result, " ; sib_base: %s", cs_reg_name(*ud, x86->sib_base));
		if (x86->sib_index != X86_REG_INVALID)
			add_str(&result, " ; sib_index: %s", cs_reg_name(*ud, x86->sib_index));
		if (x86->sib_scale != 0)
			add_str(&result, " ; sib_scale: %d", x86->sib_scale);
	}

	if (x86->xop_cc != X86_XOP_CC_INVALID) {
		add_str(&result, " ; xop_cc: %u", x86->xop_cc);
	}

	if (x86->sse_cc != X86_SSE_CC_INVALID) {
		add_str(&result, " ; sse_cc: %u", x86->sse_cc);
	}

	if (x86->avx_cc != X86_AVX_CC_INVALID) {
		add_str(&result, " ; avx_cc: %u", x86->avx_cc);
	}

	if (x86->avx_sae) {
		add_str(&result, " ; avx_sae: %u", x86->avx_sae);
	}

	if (x86->avx_rm != X86_AVX_RM_INVALID) {
		add_str(&result, " ; avx_rm: %u", x86->avx_rm);
	}

	count = cs_op_count(*ud, ins, X86_OP_IMM);
	if (count > 0) {
		add_str(&result, " ; imm_count: %u", count);
		for (i = 1; i < count + 1; i++) {
			int index = cs_op_index(*ud, ins, X86_OP_IMM, i);
			add_str(&result, " ; imms[%u]: 0x%" PRIx64 "", i, x86->operands[index].imm);
		}
	}

	if (x86->op_count)
		add_str(&result, " ; op_count: %u", x86->op_count);

	for (i = 0; i < x86->op_count; i++) {
		cs_x86_op *op = &(x86->operands[i]);

		switch((int)op->type) {
			case X86_OP_REG:
				add_str(&result, " ; operands[%u].type: REG = %s", i, cs_reg_name(*ud, op->reg));
				break;
			case X86_OP_IMM:
				add_str(&result, " ; operands[%u].type: IMM = 0x%" PRIx64 "", i, op->imm);
				break;
			case X86_OP_MEM:
				add_str(&result, " ; operands[%u].type: MEM", i);
				if (op->mem.segment != X86_REG_INVALID)
					add_str(&result, " ; operands[%u].mem.segment: REG = %s", i, cs_reg_name(*ud, op->mem.segment));
				if (op->mem.base != X86_REG_INVALID)
					add_str(&result, " ; operands[%u].mem.base: REG = %s", i, cs_reg_name(*ud, op->mem.base));
				if (op->mem.index != X86_REG_INVALID)
					add_str(&result, " ; operands[%u].mem.index: REG = %s", i, cs_reg_name(*ud, op->mem.index));
				if (op->mem.scale != 1)
					add_str(&result, " ; operands[%u].mem.scale: %u", i, op->mem.scale);
				if (op->mem.disp != 0)
					add_str(&result, " ; operands[%u].mem.disp: 0x%" PRIx64 "", i, op->mem.disp);
				break;
			default:
				break;
		}

		if (op->avx_bcast != X86_AVX_BCAST_INVALID)
			add_str(&result, " ; operands[%u].avx_bcast: %u", i, op->avx_bcast);

		if (op->avx_zero_opmask != false)
			add_str(&result, " ; operands[%u].avx_zero_opmask: TRUE", i);

		add_str(&result, " ; operands[%u].size: %u", i, op->size);

		switch(op->access) {
			default:
				break;
			case CS_AC_READ:
				add_str(&result, " ; operands[%u].access: READ", i);
				break;
			case CS_AC_WRITE:
				add_str(&result, " ; operands[%u].access: WRITE", i);
				break;
			case CS_AC_READ | CS_AC_WRITE:
				add_str(&result, " ; operands[%u].access: READ | WRITE", i);
				break;
		}
	}

	if (!cs_regs_access(*ud, ins, regs_read, &regs_read_count, regs_write, &regs_write_count)) {
		if (regs_read_count) {
			add_str(&result, " ; Registers read:");
			for(i = 0; i < regs_read_count; i++) {
				add_str(&result, " %s", cs_reg_name(*ud, regs_read[i]));
			}
		}

		if (regs_write_count) {
			add_str(&result, " ; Registers modified:");
			for(i = 0; i < regs_write_count; i++) {
				add_str(&result, " %s", cs_reg_name(*ud, regs_write[i]));
			}
		}
	}

	if (x86->eflags || x86->fpu_flags) {
		for(i = 0; i < ins->detail->groups_count; i++) {
			if (ins->detail->groups[i] == X86_GRP_FPU) {
				add_str(&result, " ; FPU_FLAGS:");
				for(i = 0; i <= 63; i++)
					if (x86->fpu_flags & ((uint64_t)1 << i)) {
						add_str(&result, " %s", get_fpu_flag_name((uint64_t)1 << i));
					}
				break;
			}
		}

		if (i == ins->detail->groups_count) {
			add_str(&result, " ; EFLAGS:");
			for(i = 0; i <= 63; i++)
				if (x86->eflags & ((uint64_t)1 << i)) {
					add_str(&result, " %s", get_eflag_name((uint64_t)1 << i));
				}
		}
	}

	return result;
}


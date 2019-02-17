/* Capstone Disassembly Engine */
/* By david942j <david942j@gmail.com>, 2019 */

#include <capstone/capstone.h>
#include <capstone/platform.h>

static csh handle;

struct platform {
	cs_arch arch;
	cs_mode mode;
	const unsigned char *code;
	size_t size;
	const char *comment;
};

static void print_string_hex(const char *comment, const unsigned char *str, size_t len)
{
	const unsigned char *c;

	printf("%s", comment);
	for (c = str; c < str + len; c++) {
		printf(" 0x%02x", *c & 0xff);
	}

	printf("\n");
}

static const char * ext_name[] = {
	[BPF_EXT_LEN] = "#len",
};

static void print_insn_detail(csh cs_handle, cs_insn *ins)
{
	cs_bpf *bpf;
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;
	unsigned i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	if (ins->detail->groups_count) {
		int j;

		printf("\tGroups:");
		for(j = 0; j < ins->detail->groups_count; j++)
			printf(" %s", cs_group_name(handle, ins->detail->groups[j]));
		printf("\n");
	}

	bpf = &(ins->detail->bpf);

	printf("\tOperand count: %u\n", bpf->op_count);
	for (i = 0; i < bpf->op_count; i++) {
		cs_bpf_op *op = &(bpf->operands[i]);
		printf("\t\toperands[%u].type: ", i);
		switch (op->type) {
		case BPF_OP_INVALID:
			printf("INVALID\n");
			break;
		case BPF_OP_REG:
			printf("REG = %s\n", cs_reg_name(handle, op->reg));
			break;
		case BPF_OP_IMM:
			printf("IMM = 0x%" PRIx64 "\n", op->imm);
			break;
		case BPF_OP_OFF:
			printf("OFF = +0x%x\n", op->off);
			break;
		case BPF_OP_MEM:
			printf("MEM\n");
			if (op->mem.base != BPF_REG_INVALID)
				printf("\t\t\toperands[%u].mem.base: REG = %s\n",
						i, cs_reg_name(handle, op->mem.base));
			printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);
			break;
		case BPF_OP_MMEM:
			printf("MMEM = M[0x%x]\n", op->mmem);
			break;
		case BPF_OP_MSH:
			printf("MSH = 4*([0x%x]&0xf)\n", op->msh);
			break;
		case BPF_OP_EXT:
			printf("EXT = %s\n", ext_name[op->ext]);
			break;
		}
	}

	/* print all registers that are involved in this instruction */
	if (!cs_regs_access(cs_handle, ins,
			regs_read, &regs_read_count,
			regs_write, &regs_write_count)) {
		if (regs_read_count) {
			printf("\tRegisters read:");
			for(i = 0; i < regs_read_count; i++)
				printf(" %s", cs_reg_name(cs_handle, regs_read[i]));
			printf("\n");
		}

		if (regs_write_count) {
			printf("\tRegisters modified:");
			for(i = 0; i < regs_write_count; i++)
				printf(" %s", cs_reg_name(cs_handle, regs_write[i]));
			printf("\n");
		}
	}
	puts("");
}

static void test()
{
#define CBPF_CODE	"\x94\x09\x00\x00\x37\x13\x03\x00" \
			"\x87\x00\x00\x00\x00\x00\x00\x00" \
			"\x07\x00\x00\x00\x00\x00\x00\x00" \
			"\x16\x00\x00\x00\x00\x00\x00\x00" \
			"\x80\x00\x00\x00\x00\x00\x00\x00"

#define EBPF_CODE	"\x97\x09\x00\x00\x37\x13\x03\x00" \
			"\xdc\x02\x00\x00\x20\x00\x00\x00" \
			"\x30\x00\x00\x00\x00\x00\x00\x00" \
			"\xdb\x3a\x00\x01\x00\x00\x00\x00" \
			"\x84\x02\x00\x00\x00\x00\x00\x00" \
			"\x6d\x33\x17\x02\x00\x00\x00\x00"
	struct platform platforms[] = {
		{
			CS_ARCH_BPF,
			CS_MODE_LITTLE_ENDIAN | CS_MODE_BPF_CLASSIC,
			(unsigned char *)CBPF_CODE,
			sizeof(CBPF_CODE) - 1,
			"cBPF Le"
		},
		{
			CS_ARCH_BPF,
			CS_MODE_LITTLE_ENDIAN | CS_MODE_BPF_EXTENDED,
			(unsigned char *)EBPF_CODE,
			sizeof(EBPF_CODE) - 1,
			"eBPF Le"
		},
	};
	uint64_t address = 0x0;
	cs_insn *insn;
	int i;
	size_t count;

	for (i = 0; i < sizeof(platforms)/sizeof(platforms[0]); i++) {
		cs_err err = cs_open(platforms[i].arch, platforms[i].mode, &handle);
		if (err) {
			printf("Failed on cs_open() with error returned: %u\n", err);
			abort();
		}

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
				print_insn_detail(handle, &insn[j]);
			}

			// free memory allocated by cs_disasm()
			cs_free(insn, count);
		} else {
			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code:", platforms[i].code, platforms[i].size);
			printf("ERROR: Failed to disasm given code!\n");
			abort();
		}

		cs_close(&handle);
	}
}

int main()
{
	test();
	return 0;
}

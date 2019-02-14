/* Capstone Disassembly Engine */
/* By david942j <david942j@gmail.com>, 2019 */

#include <capstone/capstone.h>
#include <capstone/platform.h>

static csh handle;

struct platform {
	cs_arch arch;
	cs_mode mode;
	unsigned char *code;
	size_t size;
	char *comment;
};

static void print_string_hex(const char *comment, unsigned char *str, size_t len)
{
	unsigned char *c;

	printf("%s", comment);
	for (c = str; c < str + len; c++) {
		printf("0x%02x ", *c & 0xff);
	}

	printf("\n");
}

static void print_insn_detail(csh cs_handle, cs_insn *ins)
{
	cs_bpf *bpf;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	if (ins->detail->groups_count) {
		int j;

		printf("\tGroups: ");
		for(j = 0; j < ins->detail->groups_count; j++) {
			printf("%s ", cs_group_name(handle, ins->detail->groups[j]));
		}
		printf("\n");
	}

	bpf = &(ins->detail->bpf);

	int i;

	printf("\tOperand count: %u\n", bpf->op_count);

	for (i = 0; i < bpf->op_count; i++) {
		cs_bpf_op *op = &(bpf->operands[i]);
		switch (op->type) {
			default:
				break;
			case BPF_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%x\n", i, op->imm);
				break;
		}
	}
}

static void test()
{
#define CBPF_CODE "\x87\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00"
#define EBPF_CODE "\x30\x00\x00\x00\x00\x00\x00\x00"
	struct platform platforms[] = {
		{
			CS_ARCH_BPF,
			CS_MODE_LITTLE_ENDIAN | CS_MODE_BPF_EXTENDED,
			(unsigned char *)EBPF_CODE,
			sizeof(EBPF_CODE) - 1,
			"eBPF Le"
		},
		{
			CS_ARCH_BPF,
			CS_MODE_LITTLE_ENDIAN | CS_MODE_BPF_CLASSIC,
			(unsigned char *)CBPF_CODE,
			sizeof(CBPF_CODE) - 1,
			"cBPF Le"
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

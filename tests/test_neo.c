/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2018 */

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
	char *comment;
};

static void print_string_hex(char *comment, unsigned char *str, size_t len)
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
	cs_neo *neo;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	neo = &(ins->detail->neo);

	if (neo->pop)
		printf("\tPop:     %u\n", neo->pop);

	if (neo->push)
		printf("\tPush:    %u\n", neo->push);

	if (neo->fee) {
		switch(neo->fee) {
			default:
				break;
			case NEO_FEE_0:
				printf("\tGas fee: 0\n");
				break;
			case NEO_FEE_01:
				printf("\tGas fee: 0.1\n");
				break;
			case NEO_FEE_001:
				printf("\tGas fee: 0.01\n");
				break;
			case NEO_FEE_002:
				printf("\tGas fee: 0.02\n");
				break;
			case NEO_FEE_0001:
				printf("\tGas fee: 0.001\n");
				break;
		}
	}

	if (ins->detail->groups_count) {
		int j;

		printf("\tGroups: ");
		for(j = 0; j < ins->detail->groups_count; j++) {
			printf("%s ", cs_group_name(handle, ins->detail->groups[j]));
		}
		printf("\n");
	}
}

static void test()
{
#define NEO_CODE "\x02\xaa\xbb"

	struct platform platforms[] = {
		{
			CS_ARCH_NEO,
			0,
			(unsigned char *)NEO_CODE,
			sizeof(NEO_CODE) - 1,
			"NEO"
		},
	};

	uint64_t address = 0x80001000;
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


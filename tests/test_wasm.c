/* Capstone Disassembler Engine */
/* By Spike <spikeinhouse@gmail.com>, 2018 */

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
	cs_wasm *wasm;

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

	wasm = &(ins->detail->wasm);

	if (wasm->op_count > 0) {
		unsigned int i;

		printf("\tOperand count: %u\n", wasm->op_count);

		for (i = 0; i < wasm->op_count; i++) {
			switch (wasm->operands[i].type) {
				default:
					break;
				case WASM_OP_INT7:
					printf("\t\tOperand[%u] type: int7\n", i);
					printf("\t\tOperand[%u] value: %d\n", i, wasm->operands[i].int7);
					break;
				case WASM_OP_UINT32:
					printf("\t\tOperand[%u] type: uint32\n", i);
					printf("\t\tOperand[%u] value: 0x%x\n", i, wasm->operands[i].uint32);
					break;
				case WASM_OP_UINT64:
					printf("\t\tOperand[%u] type: uint64\n", i);
					printf("\t\tOperand[%u] value: 0x%" PRIx64 "\n", i, wasm->operands[i].uint64);
					break;
				case WASM_OP_VARUINT32:
					printf("\t\tOperand[%u] type: varuint32\n", i);
					printf("\t\tOperand[%u] value: 0x%x\n", i, wasm->operands[i].varuint32);
					break;
				case WASM_OP_VARUINT64:
					printf("\t\tOperand[%u] type: varuint64\n", i);
					printf("\t\tOperand[%u] value: 0x%" PRIx64 "\n", i, wasm->operands[i].varuint64);
					break;
			}
			printf("\t\tOperand[%u] size: %u\n", i, wasm->operands[i].size);
		}
	}
}

static void test()
{
#define WASM_CODE "\x20\x00\x20\x01\x41\x20\x10\xc9\x01\x45\x0b"
	struct platform platforms[] = {
		{
			CS_ARCH_WASM,
			0,
			(unsigned char *)WASM_CODE,
			sizeof(WASM_CODE) - 1,
			"WASM"
		},
	};

	uint64_t address = 0xffff;
	cs_insn *insn;
	size_t count;
	int i;

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
			print_string_hex("Code: ", platforms[i].code, platforms[i].size);
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
			print_string_hex("Code: ", platforms[i].code, platforms[i].size);
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


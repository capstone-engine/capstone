// This sample code demonstrates the option CS_OPT_LITBASE

#include <stdio.h>
#include <stdlib.h>

#include <capstone/platform.h>
#include <capstone/capstone.h>

#define DATA "\x11\x00\x00\x11\xff\xff"

static void print_string_hex(unsigned char *str, size_t len)
{
	unsigned char *c;

	for (c = str; c < str + len; c++) {
		printf("%02x ", *c & 0xff);
	}
	printf("\t");
}

static void print_insn(csh handle)
{
	cs_insn *insn;
	size_t count;

	count = cs_disasm(handle, (const uint8_t *)DATA, sizeof(DATA) - 1,
			  0x10000, 2, &insn);
	if (count) {
		for (int i = 0; i < count; ++i) {
			print_string_hex((unsigned char *)DATA,
					 sizeof(DATA) - 1);
			printf("\t%s\t%s\n", insn[i].mnemonic, insn[i].op_str);
		}
		// Free memory allocated by cs_disasm()
		cs_free(insn, count);
	} else {
		printf("ERROR: Failed to disasm given code!\n");
		abort();
	}
}

static void test()
{
	csh handle;
	cs_err err;

	err = cs_open(CS_ARCH_XTENSA, CS_MODE_XTENSA, &handle);
	if (err) {
		if (cs_support(CS_ARCH_XTENSA)) {
			printf("Failed on cs_open() with error returned: %u\n",
			       err);
			abort();
		} else
			return;
	}

	// 1. Print out the instruction in default setup.
	printf("Disassemble xtensa code with PC=0x10000\n");
	print_insn(handle);

	// Customized mnemonic JNE to JNZ using CS_OPT_LITBASE option
	printf("\nNow customize engine to change LITBASA to 0xff001\n");
	cs_option(handle, CS_OPT_LITBASE, (size_t)0xff001);

	// 2. Now print out the instruction in newly customized setup.
	print_insn(handle);

	// Done
	cs_close(&handle);
}

int main()
{
	test();

	return 0;
}
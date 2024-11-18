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

static void print_insn(cs_insn *insn, size_t count)
{
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

static void check_insn(cs_insn *insn, const char *mnemonic, const char *op_str)
{
	assert(strcmp(insn[0].mnemonic, mnemonic) == 0);
	assert(strcmp(insn[0].op_str, op_str) == 0);
}

static void test()
{
	csh handle;
	cs_err err;

	err = cs_open(CS_ARCH_XTENSA, CS_MODE_XTENSA_ESP32, &handle);
	if (err) {
		if (cs_support(CS_ARCH_XTENSA)) {
			printf("Failed on cs_open() with error returned: %u\n",
			       err);
			abort();
		} else
			return;
	}

	cs_insn *insn = NULL;
	size_t count = 0;

	count = cs_disasm(handle, (const uint8_t *)DATA, sizeof(DATA) - 1,
			  0x100000, 2, &insn);

	// 1. Print out the instruction in default setup.
	printf("Disassemble xtensa code with PC=0x100000\n");
	check_insn(insn, "l32r", "a1, . 0xc0000");
	check_insn(insn + 1, "l32r", "a1, . 0x100000");
	print_insn(insn, count);

	// Customized mnemonic JNE to JNZ using CS_OPT_LITBASE option
	printf("\nNow customize engine to change LITBASE to 0xfffff001\n");
	cs_option(handle, CS_OPT_LITBASE, (size_t)0xfffff001);
	count = cs_disasm(handle, (const uint8_t *)DATA, sizeof(DATA) - 1,
			  0x100000, 2, &insn);

	// 2. Now print out the instruction in newly customized setup.
	check_insn(insn, "l32r", "a1, . 0xfffbf000");
	check_insn(insn + 1, "l32r", "a1, . 0xffffeffc");
	print_insn(insn, count);

	// Done
	cs_close(&handle);
}

int main()
{
	test();

	return 0;
}

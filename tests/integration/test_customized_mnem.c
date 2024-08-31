/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2015-2019 */

// This sample code demonstrates the option CS_OPT_MNEMONIC
// to customize instruction mnemonic.

#include <stdio.h>
#include <stdlib.h>

#include <capstone/platform.h>
#include <capstone/capstone.h>

#define X86_CODE32 "\x75\x01"

// Print out the input code in hexadecimal format
static void print_string_hex(unsigned char *str, size_t len)
{
	unsigned char *c;

	for (c = str; c < str + len; c++) {
		printf("%02x ", *c & 0xff);
	}
	printf("\t");
}

// Print one instruction
static void print_insn(csh handle)
{
	cs_insn *insn;
	size_t count;
	
	count = cs_disasm(handle, (const uint8_t *)X86_CODE32, sizeof(X86_CODE32) - 1, 0x1000, 1, &insn);
	if (count) {
		print_string_hex((unsigned char *)X86_CODE32, sizeof(X86_CODE32) - 1);
		printf("\t%s\t%s\n", insn[0].mnemonic, insn[0].op_str); 
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
	// Customize mnemonic JNE to "jnz"
	cs_opt_mnem my_mnem = { X86_INS_JNE, "jnz" };
	// Set .mnemonic to NULL to reset to default mnemonic
	cs_opt_mnem default_mnem = { X86_INS_JNE, NULL };

	err = cs_open(CS_ARCH_X86, CS_MODE_32, &handle);
	if (err) {
		if (cs_support(CS_ARCH_X86)) {
			printf("Failed on cs_open() with error returned: %u\n", err);
			abort();
		} else
			return;
	}

	// 1. Print out the instruction in default setup.
	printf("Disassemble X86 code with default instruction mnemonic\n");
	print_insn(handle);

	// Customized mnemonic JNE to JNZ using CS_OPT_MNEMONIC option
	printf("\nNow customize engine to change mnemonic from 'JNE' to 'JNZ'\n");
	cs_option(handle, CS_OPT_MNEMONIC, (size_t)&my_mnem);

	// 2. Now print out the instruction in newly customized setup.
	print_insn(handle);

	// Reset engine to use the default mnemonic of JNE
	printf("\nReset engine to use the default mnemonic\n");
	cs_option(handle, CS_OPT_MNEMONIC, (size_t)&default_mnem);

	// 3. Now print out the instruction in default setup.
	print_insn(handle);

	// Done
	cs_close(&handle);
}

int main()
{
	test();

	return 0;
}

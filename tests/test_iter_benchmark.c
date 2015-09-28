/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

// This sample code demonstrates the APIs cs_malloc() & cs_disasm_iter().
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "../myinttypes.h"

#include <capstone.h>

static void test()
{
#define X86_CODE32 "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00"
	/* origin version output: time used:2.683000
	 * modified version output: time used:2.358000
	 * if don't output format text string,like this:
	   //handle->printer(&mci, &ss, handle->printer_info);  <-----cs.c line 700
	   output:time used:1.138000
	 */

	csh handle;
	uint64_t address;
	cs_insn *insn;
	int i;
	cs_err err;
	const uint8_t *code;
	size_t size;

	err = cs_open(CS_ARCH_X86, CS_MODE_32, &handle);
	if (err) {
		printf("Failed on cs_open() with error returned: %u\n", err);
		return;
	}
	cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	clock_t start, end;
	double  timeUsed;

	start = clock();
	int maxcount = 3400000;
	insn = cs_malloc(handle);
	for (i = 0; i < maxcount;) {
		code = X86_CODE32;
		address = 0x1000;
		size = sizeof(X86_CODE32) - 1;
		while(cs_disasm_iter(handle, &code, &size, &address, insn)) {
			i++;
		}
	}
	cs_free(insn, 1);
	cs_close(&handle);
	end = clock();
	timeUsed = (double)(end - start) / CLOCKS_PER_SEC;
	printf("time used:%f\n", timeUsed);
	getchar();
}

int main()
{
	test();

	return 0;
}

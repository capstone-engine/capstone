/* Tang Yuhang <1648200150@qq.com> 2016 */
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <capstone.h>

#define VERSION "1.0"

// convert hexchar to hexnum
static uint8_t char_to_hexnum(char c)
{
	if (c >= '0' && c <= '9') {
		return (uint8_t)(c - '0');
	}

	if (c >= 'a' && c <= 'f') {
		return (uint8_t)(10 + c - 'a');
	}

	//  c >= 'A' && c <= 'F'
	return (uint8_t)(10 + c - 'A');
}

// convert user input (char[]) to uint8_t[], each element of which is
// valid hexadecimal, and return actual length of uint8_t[] in @size.
static uint8_t *preprocess(char *code, size_t *size)
{
	size_t i = 0, j = 0;
	uint8_t high, low;
	uint8_t *result;

	result = (uint8_t *)malloc(strlen(code));
	if (result != NULL) {
		while (code[i] != '\0') {
			if (isxdigit(code[i]) && isxdigit(code[i+1])) {
				high = 16 * char_to_hexnum(code[i]);
				low = char_to_hexnum(code[i+1]);
				result[j] = high + low;
				i++;
				j++;
			}
			i++;
		}
		*size = j;
	}

	return result;
}

static void usage(char *prog)
{
	printf("Cstool v%s for Capstone Disassembler Engine (www.capstone-engine.org)\n\n", VERSION);
	printf("Syntax: %s <arch+mode> <assembly-hexstring> [start-address-in-hex-format]\n", prog);
	printf("\nThe following <arch+mode> options are supported:\n");

	if (cs_support(CS_ARCH_X86)) {
		printf("        x16:       16-bit mode (X86)\n");
		printf("        x32:       32-bit mode (X86)\n");
		printf("        x64:       64-bit mode (X86)\n");
		printf("        x16att:    16-bit mode (X86) syntax-att\n");
		printf("        x32att:    32-bit mode (X86) syntax-att\n");
		printf("        x64att:    64-bit mode (X86) syntax-att\n");
	}

	if (cs_support(CS_ARCH_ARM)) {
		printf("        arm:       arm\n");
		printf("        armb:      arm + big endian\n");
		printf("        arml:      arm + little endian\n");
		printf("        thumb:     thumb mode\n");
		printf("        thumbbe:   thumb + big endian\n");
		printf("        thumble:   thumb + billtle endian\n");
	}

	if (cs_support(CS_ARCH_ARM64)) {
		printf("        arm64:     aarch64 mode\n");
	}

	if (cs_support(CS_ARCH_MIPS)) {
		printf("        mips:      mips32 + little endian\n");
		printf("        mipsbe:    mips32 + big endian\n");
		printf("        mips64:    mips64 + little endian\n");
		printf("        mips64be:  mips64 + big endian\n");
	}

	if (cs_support(CS_ARCH_PPC)) {
		printf("        ppc64:     ppc64 + little endian\n");
		printf("        ppc64be:   ppc64 + big endian\n");
	}

	if (cs_support(CS_ARCH_SPARC)) {
		printf("        sparc:     sparc\n");
	}

	if (cs_support(CS_ARCH_SYSZ)) {
		printf("        systemz:   systemz (s390x)\n");
	}

	if (cs_support(CS_ARCH_XCORE)) {
		printf("        xcore:     xcore\n");
	}

	printf("\n");
}

int main(int argc, char **argv)
{
	csh handle;
	char *mode;
	uint8_t *assembly;
	size_t count, size;
	uint64_t address = 0;
	cs_insn *insn;
	cs_err err;
	bool x86_arch = false;

	if (argc != 3 && argc != 4) {
		usage(argv[0]);
		return -1;
	}

	mode = argv[1];
	assembly = preprocess(argv[2], &size);
	if (assembly == NULL) {
		printf("ERROR: invalid assembler-string argument, quit!\n");
		return -3;
	}

	if (argc == 4) {
		// cstool <arch> <assembly> <address>
		char *temp;
		address = strtoull(argv[3], &temp, 16);
		if (temp == argv[3] || *temp != '\0' || errno == ERANGE) {
			printf("ERROR: invalid address argument, quit!\n");
			return -2;
		}
	}

	if (!strcmp(mode, "arm")) {
		err = cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle);
	}

	if (!strcmp(mode, "armb")) {
		err = cs_open(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_BIG_ENDIAN, &handle);
	}

	if (!strcmp(mode, "arml")) {
		err = cs_open(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN, &handle);
	}

	if (!strcmp(mode, "thumb")) {
		err = cs_open(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN, &handle);
	}

	if (!strcmp(mode, "thumbbe")) {
		err = cs_open(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_BIG_ENDIAN, &handle);
	}

	if (!strcmp(mode, "thumble")) {
		err = cs_open(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN, &handle);
	}

	if (!strcmp(mode, "arm64")) {
		err = cs_open(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, &handle);
	}

	if (!strcmp(mode, "mips")) {
		err = cs_open(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN, &handle);
	}

	if (!strcmp(mode, "mipsbe")) {
		err = cs_open(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN, &handle);
	}

	if (!strcmp(mode, "mips64")) {
		err = cs_open(CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN, &handle);
	}

	if (!strcmp(mode, "mips64be")) {
		err = cs_open(CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN, &handle);
	}

	if (!strcmp(mode, "x16")) {
		x86_arch = true;
		err = cs_open(CS_ARCH_X86, CS_MODE_16, &handle);
	}

	if (!strcmp(mode, "x32")) {
		x86_arch = true;
		err = cs_open(CS_ARCH_X86, CS_MODE_32, &handle);
	}

	if (!strcmp(mode, "x64")) {
		x86_arch = true;
		err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
	}

	if (!strcmp(mode, "x16att")) {
		x86_arch = true;
		err = cs_open(CS_ARCH_X86, CS_MODE_16, &handle);
		if (!err) {
			cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
		}
	}

	if (!strcmp(mode,"x32att")) {
		x86_arch = true;
		err = cs_open(CS_ARCH_X86, CS_MODE_32, &handle);
		if (!err) {
			cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
		}
	}

	if (!strcmp(mode,"x64att")) {
		x86_arch = true;
		err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
		if (!err) {
			cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
		}
	}

	if (!strcmp(mode,"ppc64")) {
		err = cs_open(CS_ARCH_PPC, CS_MODE_64+CS_MODE_LITTLE_ENDIAN, &handle);
	}

	if (!strcmp(mode,"ppc64be")) {
		err = cs_open(CS_ARCH_PPC,CS_MODE_64+CS_MODE_BIG_ENDIAN, &handle);
	}

	if (!strcmp(mode,"sparc")) {
		err = cs_open(CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN, &handle);
	}

	if (!strcmp(mode, "systemz") || !strcmp(mode, "sysz") || !strcmp(mode, "s390x")) {
		err = cs_open(CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN, &handle);
	}

	if (!strcmp(mode,"xcore")) {
		err = cs_open(CS_ARCH_XCORE, CS_MODE_BIG_ENDIAN, &handle);
	}

	if (err) {
		printf("ERROR: Failed on cs_open(), quit!\n");
		usage(argv[0]);
		return -1;
	}

	count = cs_disasm(handle, assembly, size, address, 0, &insn);
	if (count > 0) {
		size_t i;

		for (i = 0; i < count; i++) {
			int j;
			printf("%"PRIx64"  ", insn[i].address);
			for (j = 0; j < insn[i].size; j++) {
				printf("%02x", insn[i].bytes[j]);
			}
			// X86 instruction size is variable.
			// align assembly instruction after the opcode
			if (x86_arch) {
				for (; j < 16; j++) {
					printf("  ");
				}
			}
			printf("  %s\t%s\n", insn[i].mnemonic, insn[i].op_str);
		}
		cs_free(insn, count);
	} else {
		printf("ERROR: invalid assembly code\n");
		return(-4);
	}

	cs_close(&handle);

	return 0;
}



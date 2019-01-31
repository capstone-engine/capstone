#include "capstone_test.h"

single_dict arches[] = {
	{"CS_ARCH_ARM", CS_ARCH_ARM},
	{"CS_ARCH_ARM64", CS_ARCH_ARM64},
	{"CS_ARCH_MIPS", CS_ARCH_MIPS},
	{"CS_ARCH_PPC", CS_ARCH_PPC},
	{"CS_ARCH_SPARC", CS_ARCH_SPARC},
	{"CS_ARCH_SYSZ", CS_ARCH_SYSZ},
	{"CS_ARCH_X86", CS_ARCH_X86},
	{"CS_ARCH_XCORE", CS_ARCH_XCORE},
	{"CS_ARCH_M68K", CS_ARCH_M68K}
};

single_dict modes[] = {
	{"CS_MODE_16", CS_MODE_16},
	{"CS_MODE_32", CS_MODE_32},
	{"CS_MODE_64", CS_MODE_64},
	{"CS_MODE_MIPS32", CS_MODE_MIPS32},
	{"0", CS_MODE_ARM},
	{"CS_MODE_MIPS64", CS_MODE_MIPS64},
	{"CS_MODE_ARM", CS_MODE_ARM},
	{"CS_MODE_THUMB", CS_MODE_THUMB},
	{"CS_MODE_ARM+CS_MODE_V8", CS_MODE_ARM+CS_MODE_V8},
	{"CS_MODE_THUMB+CS_MODE_V8", CS_MODE_THUMB+CS_MODE_V8},
	{"CS_MODE_THUMB+CS_MODE_MCLASS", CS_MODE_THUMB+CS_MODE_MCLASS},
	{"CS_MODE_LITTLE_ENDIAN", CS_MODE_LITTLE_ENDIAN},
	{"CS_MODE_BIG_ENDIAN", CS_MODE_BIG_ENDIAN},
	{"CS_MODE_64+CS_MODE_LITTLE_ENDIAN", CS_MODE_64+CS_MODE_LITTLE_ENDIAN},
	{"CS_MODE_64+CS_MODE_BIG_ENDIAN", CS_MODE_64+CS_MODE_BIG_ENDIAN},
	{"CS_MODE_MIPS32+CS_MODE_MICRO", CS_MODE_MIPS32+CS_MODE_MICRO},
	{"CS_MODE_MIPS32+CS_MODE_MICRO+CS_MODE_BIG_ENDIAN", CS_MODE_MIPS32+CS_MODE_MICRO+CS_MODE_BIG_ENDIAN},
	{"CS_MODE_MIPS32+CS_MODE_BIG_ENDIAN+CS_MODE_MICRO", CS_MODE_MIPS32+CS_MODE_MICRO+CS_MODE_BIG_ENDIAN},
	{"CS_MODE_BIG_ENDIAN+CS_MODE_V9", CS_MODE_BIG_ENDIAN + CS_MODE_V9},
	{"CS_MODE_MIPS32+CS_MODE_BIG_ENDIAN", CS_MODE_MIPS32+CS_MODE_BIG_ENDIAN},
	{"CS_MODE_MIPS32+CS_MODE_LITTLE_ENDIAN", CS_MODE_MIPS32+CS_MODE_LITTLE_ENDIAN},
	{"CS_MODE_MIPS64+CS_MODE_LITTLE_ENDIAN", CS_MODE_MIPS64+CS_MODE_LITTLE_ENDIAN},
	{"CS_MODE_MIPS64+CS_MODE_BIG_ENDIAN", CS_MODE_MIPS64+CS_MODE_BIG_ENDIAN},
	{"CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_BIG_ENDIAN", CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_BIG_ENDIAN}
};

double_dict options[] = {
	{"CS_OPT_DETAIL", CS_OPT_DETAIL, CS_OPT_ON},
	{"CS_OPT_SKIPDATA", CS_OPT_SKIPDATA, CS_OPT_ON},
	{"CS_OPT_SYNTAX_DEFAULT", CS_OPT_SYNTAX, CS_OPT_SYNTAX_DEFAULT},
	{"CS_OPT_SYNTAX_INTEL", CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL},
	{"CS_OPT_SYNTAX_ATT", CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT},
	{"CS_OPT_SYNTAX_NOREGNAME", CS_OPT_SYNTAX, CS_OPT_SYNTAX_NOREGNAME},
	{"CS_OPT_SYNTAX_MASM", CS_OPT_SYNTAX, CS_OPT_SYNTAX_MASM},
	{"CS_MODE_LITTLE_ENDIAN", CS_OPT_MODE, CS_MODE_LITTLE_ENDIAN},
	{"CS_MODE_ARM", CS_OPT_MODE, CS_MODE_ARM},
	{"CS_MODE_16", CS_OPT_MODE, CS_MODE_16},
	{"CS_MODE_32", CS_OPT_MODE, CS_MODE_32},
	{"CS_MODE_64", CS_OPT_MODE, CS_MODE_64},
	{"CS_MODE_THUMB", CS_OPT_MODE, CS_MODE_THUMB},
	{"CS_MODE_MCLASS", CS_OPT_MODE, CS_MODE_MCLASS},
	{"CS_MODE_V8", CS_OPT_MODE, CS_MODE_V8},
	{"CS_MODE_MICRO", CS_OPT_MODE, CS_MODE_MICRO},
	{"CS_MODE_MIPS3", CS_OPT_MODE, CS_MODE_MIPS3},
	{"CS_MODE_MIPS32R6", CS_OPT_MODE, CS_MODE_MIPS32R6},
	{"CS_MODE_MIPS2", CS_OPT_MODE, CS_MODE_MIPS2},
	{"CS_MODE_V9", CS_OPT_MODE, CS_MODE_V9},
	{"CS_MODE_QPX", CS_OPT_MODE, CS_MODE_QPX},
	{"CS_MODE_M68K_000", CS_OPT_MODE, CS_MODE_M68K_000},
	{"CS_MODE_M68K_010", CS_OPT_MODE, CS_MODE_M68K_010},
	{"CS_MODE_M68K_020", CS_OPT_MODE, CS_MODE_M68K_020},
	{"CS_MODE_M68K_030", CS_OPT_MODE, CS_MODE_M68K_030},
	{"CS_MODE_M68K_040", CS_OPT_MODE, CS_MODE_M68K_040},
	{"CS_MODE_M68K_060", CS_OPT_MODE, CS_MODE_M68K_060},
	{"CS_MODE_BIG_ENDIAN", CS_OPT_MODE, CS_MODE_BIG_ENDIAN},
	{"CS_MODE_MIPS32", CS_OPT_MODE, CS_MODE_MIPS32},
	{"CS_MODE_MIPS64", CS_OPT_MODE, CS_MODE_MIPS64},
	{"CS_MODE_M680X_6301", CS_OPT_MODE, CS_MODE_M680X_6301},
	{"CS_MODE_M680X_6309", CS_OPT_MODE, CS_MODE_M680X_6309},
	{"CS_MODE_M680X_6800", CS_OPT_MODE, CS_MODE_M680X_6800},
	{"CS_MODE_M680X_6801", CS_OPT_MODE, CS_MODE_M680X_6801},
	{"CS_MODE_M680X_6805", CS_OPT_MODE, CS_MODE_M680X_6805},
	{"CS_MODE_M680X_6808", CS_OPT_MODE, CS_MODE_M680X_6808},
	{"CS_MODE_M680X_6809", CS_OPT_MODE, CS_MODE_M680X_6809},
	{"CS_MODE_M680X_6811", CS_OPT_MODE, CS_MODE_M680X_6811},
	{"CS_MODE_M680X_CPU12", CS_OPT_MODE, CS_MODE_M680X_CPU12},
	{"CS_MODE_M680X_HCS08", CS_OPT_MODE, CS_MODE_M680X_HCS08}
};

void test_single(csh *handle, char *line)
{
	char **list_part, **list_byte, **list_data;
	int size_part, size_byte, size_data, size_insn;
	int i, count;
	unsigned char *code;
	cs_insn *insn;

	list_part = split(line, " = ", &size_part);
	list_byte = split(list_part[0], ",", &size_byte);
	code = (unsigned char *)malloc(size_byte * sizeof(char));
	for (i=0; i<size_byte; ++i) {
		code[i] = (unsigned char)strtol(list_byte[i], NULL, 16);
		// printf("Byte: 0x%.2x\n", (int)code[i]);
	}

	list_data = split(list_part[1], ";", &size_data);	
	count = cs_disasm(*handle, code, size_byte, 0x1000, 0, &insn);
	// printf("====\nCount: %d\nSize_data: %d\n", count, size_data);
	assert_int_equal(size_data, count);
	for (i=0; i<count; ++i) {
		char *tmp = (char *)malloc(strlen(insn[i].mnemonic) + strlen(insn[i].op_str) + 100);
		strcpy(tmp, insn[i].mnemonic);
		tmp[strlen(insn[i].mnemonic)] = ' ';
		strcpy(tmp + strlen(insn[i].mnemonic) + 1, insn[i].op_str);
		// printf("--------\nCapstone: %s\nUser: %s\n", tmp, list_data[i]);
		assert_string_equal(tmp, list_data[i]);
		free(tmp);
	}
	cs_free(insn, count);
	free(list_part);
	free(list_byte);
	free(list_data);
}

int getValue(single_dict d[], unsigned int size, const char *str)
{
	int i;

	for (i=0; i<size; ++i)
		if (!strcmp(d[i].str, str))
			return d[i].value;
	return -1;
}

int getIndex(double_dict d[], unsigned int size, const char *s)
{
	int i;

	for (i=0; i<size; ++i) {
		if (!strcmp(s, d[i].str))
			return i;
	}
	return -1;
}

int setFunction(char (*function)(csh *, cs_insn*), int arch)
{
	switch(arch) {
		case CS_ARCH_ARM:
			function = get_detail_arm;
		case CS_ARCH_ARM64:
			function = get_detail_arm64;
		case CS_ARCH_MIPS:
			function = get_detail_mips;
		case CS_ARCH_PPC:
			function = get_detail_ppc;
		case CS_ARCH_SPARC:
			function = get_detail_sparc;
		case CS_ARCH_SYSZ:
			function = get_detail_sysz;
		case CS_ARCH_X86:
			function = get_detail_x86;
		case CS_ARCH_XCORE:
			function = get_detail_xcore;
		case CS_ARCH_M68K:
			function = get_detail_m68k;
		default:
			return -1;
	}
	return 0;
}

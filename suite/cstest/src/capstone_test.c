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

char *(*function)(csh *, cs_mode, cs_insn*) = NULL;

int triple_compare(const char *src1, const char *src2, const char *des)
{
	if (strcmp(src1, des) && strcmp(src2, des)) {
		fprintf(stderr,"[  ERROR   ] --- \"%s\" != \"%s\"", src1, des);
		if (strcmp(src1, src2))
			fprintf(stderr, " (\"%s\" != \"%s\")", src2, des);
		fprintf(stderr, "\n");
		return 0;
	}
	return 1;
}

void test_single_MC(csh *handle, char *line)
{
	char **list_part, **list_byte, **list_data;
	int size_part, size_byte, size_data, size_insn;
	int i, count;
	unsigned char *code;
	cs_insn *insn;
	char *tmp, *tmptmp;
	char **offset_opcode;
	int size_offset_opcode;
	unsigned long offset;
	
	list_part = split(line, " = ", &size_part);
	offset_opcode = split(list_part[0], ": ", &size_offset_opcode);
	if (size_offset_opcode > 1) {
		offset = (unsigned int)strtol(offset_opcode[0], NULL, 16);
		list_byte = split(offset_opcode[1], ",", &size_byte);
	}
	else {
		offset = 0;
		list_byte = split(offset_opcode[0], ",", &size_byte);
	}
	code = (unsigned char *)malloc(sizeof(char) * size_byte);
	for (i=0; i<size_byte; ++i) {
		code[i] = (unsigned char)strtol(list_byte[i], NULL, 16);
	//	printf("Byte: 0x%.2x\n", (int)code[i]);
	}

	count = cs_disasm(*handle, code, size_byte, offset, 0, &insn);
	code = (unsigned char *)malloc(size_byte * sizeof(char));
	for (i=0; i<size_byte; ++i) {
		code[i] = (unsigned char)strtol(list_byte[i], NULL, 16);
		// printf("Byte: 0x%.2x\n", (int)code[i]);
	}

	list_data = split(list_part[1], ";", &size_data);	
	count = cs_disasm(*handle, code, size_byte, offset, 0, &insn);
	// printf("====\nCount: %d\nSize_data: %d\n", count, size_data);
//	assert_int_equal(size_data, count);
	if (count == 0) {
		fprintf(stderr, "[  ERROR   ] --- Failed to disassemble given code!\n");
		_fail(__FILE__, __LINE__);
	}
	for (i=0; i<count; ++i) {
		tmp = (char *)malloc(strlen(insn[i].mnemonic) + strlen(insn[i].op_str) + 100);
		strcpy(tmp, insn[i].mnemonic);
		if (strlen(insn[i].op_str) > 0) {
			tmp[strlen(insn[i].mnemonic)] = ' ';
			strcpy(tmp + strlen(insn[i].mnemonic) + 1, insn[i].op_str);
		}
		// printf("--------\nCapstone: %s\nUser: %s\n", tmp, list_data[i]);
		tmptmp = strdup(tmp);
		replaceHex(&tmp);
//		assert_string_equal(tmp, list_data[i]);
		trimwhitespace(&tmp);
		trimwhitespace(&tmptmp);
		trimwhitespace(&list_data[i]);
		if (!triple_compare(tmp, tmptmp, list_data[i]))
			_fail(__FILE__, __LINE__);
		free(tmp);
		free(tmptmp);
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

int setFunction(int arch)
{
	switch(arch) {
		case CS_ARCH_ARM:
			function = get_detail_arm;
			break;
		case CS_ARCH_ARM64:
			function = get_detail_arm64;
			break;
		case CS_ARCH_MIPS:
			function = get_detail_mips;
			break;
		case CS_ARCH_PPC:
			function = get_detail_ppc;
			break;
		case CS_ARCH_SPARC:
			function = get_detail_sparc;
			break;
		case CS_ARCH_SYSZ:
			function = get_detail_sysz;
			break;
		case CS_ARCH_X86:
			function = get_detail_x86;
			break;
		case CS_ARCH_XCORE:
			function = get_detail_xcore;
			break;
		case CS_ARCH_M68K:
			function = get_detail_m68k;
			break;
		case CS_ARCH_M680X:
			function = get_detail_m680x;
			break;
		case CS_ARCH_EVM:
			function = get_detail_evm;
			break;
		case CS_ARCH_MOS65XX:
			function = get_detail_mos65xx;
			break;
		case CS_ARCH_TMS320C64X:
			function = get_detail_tms320c64x;
			break;
		default:
			return -1;
	}
	return 0;
}

void test_single_issue(csh *handle, cs_mode mode, char *line, int detail)
{
	char **list_part, **list_byte, **list_part_cs_result, **list_part_issue_result;
	int size_part, size_byte, size_part_cs_result, size_part_issue_result;
	int i, count, j;
	unsigned char *code;
	cs_insn *insn;
	char *cs_result, *tmp;
	char **offset_opcode;
	int size_offset_opcode;
	unsigned long offset;
	
	cs_result = (char *)malloc(sizeof(char));
	cs_result[0] = '\0';
	
	list_part = split(line, " == ", &size_part);
	offset_opcode = split(list_part[0], ": ", &size_offset_opcode);
	if (size_offset_opcode > 1) {
		offset = (unsigned int)strtol(offset_opcode[0], NULL, 16);
		list_byte = split(offset_opcode[1], ",", &size_byte);
	}
	else {
		offset = 0;
		list_byte = split(offset_opcode[0], ",", &size_byte);
	}
	code = (unsigned char *)malloc(sizeof(char) * size_byte);
	for (i=0; i<size_byte; ++i) {
		code[i] = (unsigned char)strtol(list_byte[i], NULL, 16);
	//	printf("Byte: 0x%.2x\n", (int)code[i]);
	}

	count = cs_disasm(*handle, code, size_byte, offset, 0, &insn);
	for (i=0; i < count; ++i) {
		tmp = (char *)malloc(strlen(insn[i].mnemonic) + strlen(insn[i].op_str) + 100);
		strcpy(tmp, insn[i].mnemonic);
		if (strlen(insn[i].op_str) > 0) {
			tmp[strlen(insn[i].mnemonic)] = ' ';
			strcpy(tmp + strlen(insn[i].mnemonic) + 1, insn[i].op_str);
		}
		add_str(&cs_result, "%s", tmp);
		/*
		if (i < count - 1)
			add_str(&cs_result, ";");
		*/
		free(tmp);
	}

	if (detail == 1) {
		tmp = (*function)(handle, mode, insn);
		add_str(&cs_result, "%s", tmp);
		free(tmp);

		if (insn->detail->groups_count) {
			add_str(&cs_result, " ; Groups: ");
			for (j = 0; j < insn->detail->groups_count; j++) {
				add_str(&cs_result, "%s ", cs_group_name(*handle, insn->detail->groups[j]));
			}
		}
	}
	
	list_part_cs_result = split(cs_result, " ; ", &size_part_cs_result);
	list_part_issue_result = split(list_part[1], " ; ", &size_part_issue_result);

	if (size_part_cs_result != size_part_issue_result) {
		fprintf(stderr, "[  ERROR   ] --- Number of details doesn't match\n");
		_fail(__FILE__, __LINE__);
	}
	for (i=0; i<size_part_cs_result; ++i) {
		trimwhitespace(&list_part_cs_result[i]);
		trimwhitespace(&list_part_issue_result[i]);
		assert_string_equal(list_part_cs_result[i], list_part_issue_result[i]);
	}
//	assert_string_equal(cs_result, list_part[1]);
	cs_free(insn, count);
	free(list_part);
	free(list_byte);
	free(cs_result);
	free(list_part_cs_result);
	free(list_part_issue_result);
}

/* Capstone testing regression */
/* By Do Minh Tuan <tuanit96@gmail.com>, 02-2019 */


#include "capstone_test.h"

char *(*function)(csh *, cs_mode, cs_insn*) = NULL;

void test_single_MC(csh *handle, int mc_mode, char *line)
{
	char **list_part, **list_byte;
	int size_part, size_byte;
	int i, count;
	unsigned char *code;
	cs_insn *insn;
	char tmp[MAXMEM], tmp_mc[MAXMEM], origin[MAXMEM], tmp_noreg[MAXMEM];
	char **offset_opcode;
	int size_offset_opcode;
	unsigned long offset;
	char *p;

	list_part = split(line, " = ", &size_part);
	offset_opcode = split(list_part[0], ": ", &size_offset_opcode);
	if (size_offset_opcode > 1) {
		offset = (unsigned int)strtol(offset_opcode[0], NULL, 16);
		list_byte = split(offset_opcode[1], ",", &size_byte);
	} else {
		offset = 0;
		list_byte = split(offset_opcode[0], ",", &size_byte);
	}

	code = (unsigned char *)malloc(size_byte * sizeof(char));
	for (i = 0; i < size_byte; ++i) {
		code[i] = (unsigned char)strtol(list_byte[i], NULL, 16);
	}

	count = cs_disasm(*handle, code, size_byte, offset, 0, &insn);
	if (count == 0) {
		fprintf(stderr, "[  ERROR   ] --- %s --- Failed to disassemble given code!\n", list_part[0]);
		free_strs(list_part, size_part);
		free_strs(offset_opcode, size_offset_opcode);
		free_strs(list_byte, size_byte);
		free(code);
		_fail(__FILE__, __LINE__);
	}
	if (count > 1) {
		fprintf(stderr, "[  ERROR   ] --- %s --- Multiple instructions(%d) disassembling doesn't support!\n", list_part[0], count);
		free_strs(list_part, size_part);
		free_strs(offset_opcode, size_offset_opcode);
		free_strs(list_byte, size_byte);
		free(code);
		_fail(__FILE__, __LINE__);
	}

	for (p = list_part[1]; *p; ++p) *p = tolower(*p);
	for (p = list_part[1]; *p; ++p)
		if (*p == '\t') *p = ' ';
	trim_str(list_part[1]);
	strcpy(tmp_mc, list_part[1]);
	replace_hex(tmp_mc);
	replace_negative(tmp_mc, mc_mode);

	strcpy(tmp, insn[0].mnemonic);
	if (strlen(insn[0].op_str) > 0) {
		tmp[strlen(insn[0].mnemonic)] = ' ';
		strcpy(tmp + strlen(insn[0].mnemonic) + 1, insn[0].op_str);
	}

	trim_str(tmp);
	strcpy(origin, tmp);
	replace_hex(tmp);
	replace_negative(tmp, mc_mode);

	if (cs_option(*handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_NOREGNAME) == CS_ERR_OK) {
		cs_disasm(*handle, code, size_byte, offset, 0, &insn);
		strcpy(tmp_noreg, insn[0].mnemonic);
		if (strlen(insn[0].op_str) > 0) {
			tmp_noreg[strlen(insn[0].mnemonic)] = ' ';
			strcpy(tmp_noreg + strlen(insn[0].mnemonic) + 1, insn[0].op_str);
		}

		trim_str(tmp_noreg);
		replace_hex(tmp_noreg);
		replace_negative(tmp_noreg, mc_mode);

		if (strcmp(tmp, tmp_mc) && strcmp(tmp_noreg, tmp_mc)) {
			fprintf(stderr, "[  ERROR   ] --- %s --- \"%s\" != \"%s\" ( \"%s\" != \"%s\" and \"%s\" != \"%s\" )\n", list_part[0], origin, list_part[1], tmp, tmp_mc, tmp_noreg, tmp_mc);
			free_strs(list_part, size_part);
			free_strs(offset_opcode, size_offset_opcode);
			free_strs(list_byte, size_byte);
			free(code);
			cs_free(insn, count);
			_fail(__FILE__, __LINE__);
		}

		cs_option(*handle, CS_OPT_SYNTAX, 0);

	} else if (strcmp(tmp, tmp_mc)) {
		fprintf(stderr, "[  ERROR   ] --- %s --- \"%s\" != \"%s\" ( \"%s\" != \"%s\" )\n", list_part[0], origin, list_part[1], tmp, tmp_mc);
		free_strs(list_part, size_part);
		free_strs(offset_opcode, size_offset_opcode);
		free_strs(list_byte, size_byte);
		free(code);
		cs_free(insn, count);
		_fail(__FILE__, __LINE__);
	}

	free_strs(list_part, size_part);
	free_strs(offset_opcode, size_offset_opcode);
	free_strs(list_byte, size_byte);
	free(code);
	cs_free(insn, count);
}

int get_value(single_dict d[], unsigned int size, const char *str)
{
	int i;

	for (i = 0; i < size; ++i)
		if (!strcmp(d[i].str, str))
			return d[i].value;
	return -1;
}

int get_index(double_dict d[], unsigned int size, const char *s)
{
	int i;

	for (i = 0; i < size; ++i) {
		if (!strcmp(s, d[i].str))
			return i;
	}
	return -1;
}

int set_function(int arch)
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
		case CS_ARCH_BPF:
			function = get_detail_bpf;
			break;
		case CS_ARCH_RISCV:
			function = get_detail_riscv;
			break;
		case CS_ARCH_TRICORE:
			function = get_detail_tricore;
			break;
		default:
			return -1;
	}
	return 0;
}

void test_single_issue(csh *handle, cs_mode mode, char *line, int detail)
{
	char **list_part, **list_byte, **list_part_issue_result;
	int size_part, size_byte, size_part_issue_result;
	int i, count, j;
	unsigned char *code;
	cs_insn *insn;
	char *cs_result, *tmp, *p;
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
	} else {
		offset = 0;
		list_byte = split(offset_opcode[0], ",", &size_byte);
	}

	code = (unsigned char *)malloc(sizeof(char) * size_byte);
	for (i = 0; i < size_byte; ++i) {
		code[i] = (unsigned char)strtol(list_byte[i], NULL, 16);
	}

	count = cs_disasm(*handle, code, size_byte, offset, 0, &insn);
	for (i = 0; i < count; ++i) {
		tmp = (char *)malloc(strlen(insn[i].mnemonic) + strlen(insn[i].op_str) + 100);
		strcpy(tmp, insn[i].mnemonic);
		if (strlen(insn[i].op_str) > 0) {
			tmp[strlen(insn[i].mnemonic)] = ' ';
			strcpy(tmp + strlen(insn[i].mnemonic) + 1, insn[i].op_str);
		}
		add_str(&cs_result, "%s", tmp);
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

	trim_str(cs_result);
	add_str(&cs_result, " ;");
	//	list_part_cs_result = split(cs_result, " ; ", &size_part_cs_result);
	for (p = list_part[1]; *p; ++p) if (*p == '\t') *p = ' ';
	list_part_issue_result = split(list_part[1], " ; ", &size_part_issue_result);

	for (i = 0; i < size_part_issue_result; ++i) {
		trim_str(list_part_issue_result[i]);
		char *tmptmp = (char *)malloc(sizeof(char));
		tmptmp[0] = '\0';
		add_str(&tmptmp, "%s", list_part_issue_result[i]);
		add_str(&tmptmp, " ;");

		if ((strstr(cs_result, tmptmp)) == NULL) {
			fprintf(stderr, "[  ERROR   ] --- %s --- \"%s\" not in \"%s\"\n", list_part[0], list_part_issue_result[i], cs_result);
			cs_free(insn, count);
			free_strs(list_part, size_part);
			free_strs(list_byte, size_byte);
			free(cs_result);
			//	free_strs(list_part_cs_result, size_part_cs_result);
			free_strs(list_part_issue_result, size_part_issue_result);
			_fail(__FILE__, __LINE__);
		}
		free(tmptmp);
	}

	cs_free(insn, count);
	free_strs(list_part, size_part);
	free_strs(list_byte, size_byte);
	free(cs_result);
	//	free_strs(list_part_cs_result, size_part_cs_result);
	free_strs(list_part_issue_result, size_part_issue_result);
}

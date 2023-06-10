/* Capstone testing regression */
/* By Do Minh Tuan <tuanit96@gmail.com>, 02-2019 */


#include "helper.h"
#include "capstone_test.h"
#include <unistd.h>

#define ARR_SIZE(a) (sizeof(a)/sizeof(a[0]))

static single_dict arches[] = {
	{"CS_ARCH_ARM", CS_ARCH_ARM},
	{"CS_ARCH_ARM64", CS_ARCH_ARM64},
	{"CS_ARCH_MIPS", CS_ARCH_MIPS},
	{"CS_ARCH_PPC", CS_ARCH_PPC},
	{"CS_ARCH_SPARC", CS_ARCH_SPARC},
	{"CS_ARCH_SYSZ", CS_ARCH_SYSZ},
	{"CS_ARCH_X86", CS_ARCH_X86},
	{"CS_ARCH_XCORE", CS_ARCH_XCORE},
	{"CS_ARCH_M68K", CS_ARCH_M68K},
	{"CS_ARCH_BPF", CS_ARCH_BPF},
	{"CS_ARCH_RISCV", CS_ARCH_RISCV},
	{"CS_ARCH_TRICORE", CS_ARCH_TRICORE},
};

 static single_dict modes[] = {
	{"CS_MODE_LITTLE_ENDIAN", CS_MODE_LITTLE_ENDIAN},
	{"CS_MODE_ARM", CS_MODE_ARM},
	{"CS_MODE_16", CS_MODE_16},
	{"CS_MODE_32", CS_MODE_32},
	{"CS_MODE_64", CS_MODE_64},
	{"CS_MODE_THUMB", CS_MODE_THUMB},
	{"CS_MODE_MCLASS", CS_MODE_MCLASS},
	{"CS_MODE_V8", CS_MODE_V8},
	{"CS_MODE_MICRO", CS_MODE_MICRO},
	{"CS_MODE_MIPS3", CS_MODE_MIPS3},
	{"CS_MODE_MIPS32R6", CS_MODE_MIPS32R6},
	{"CS_MODE_MIPS2", CS_MODE_MIPS2},
	{"CS_MODE_V9", CS_MODE_V9},
	{"CS_MODE_QPX", CS_MODE_QPX},
	{"CS_MODE_PS", CS_MODE_PS},
	{"CS_MODE_M68K_000", CS_MODE_M68K_000},
	{"CS_MODE_M68K_010", CS_MODE_M68K_010},
	{"CS_MODE_M68K_020", CS_MODE_M68K_020},
	{"CS_MODE_M68K_030", CS_MODE_M68K_030},
	{"CS_MODE_M68K_040", CS_MODE_M68K_040},
	{"CS_MODE_M68K_060", CS_MODE_M68K_060},
	{"CS_MODE_BIG_ENDIAN", CS_MODE_BIG_ENDIAN},
	{"CS_MODE_MIPS32", CS_MODE_MIPS32},
	{"CS_MODE_MIPS64", CS_MODE_MIPS64},
	{"CS_MODE_M680X_6301", CS_MODE_M680X_6301},
	{"CS_MODE_M680X_6309", CS_MODE_M680X_6309},
	{"CS_MODE_M680X_6800", CS_MODE_M680X_6800},
	{"CS_MODE_M680X_6801", CS_MODE_M680X_6801},
	{"CS_MODE_M680X_6805", CS_MODE_M680X_6805},
	{"CS_MODE_M680X_6808", CS_MODE_M680X_6808},
	{"CS_MODE_M680X_6809", CS_MODE_M680X_6809},
	{"CS_MODE_M680X_6811", CS_MODE_M680X_6811},
	{"CS_MODE_M680X_CPU12", CS_MODE_M680X_CPU12},
	{"CS_MODE_M680X_HCS08", CS_MODE_M680X_HCS08},
	{"CS_MODE_BPF_CLASSIC", CS_MODE_BPF_CLASSIC},
	{"CS_MODE_BPF_EXTENDED", CS_MODE_BPF_EXTENDED},
	{"CS_MODE_RISCV32", CS_MODE_RISCV32},
	{"CS_MODE_RISCV64", CS_MODE_RISCV64},
	{"CS_MODE_RISCVC", CS_MODE_RISCVC},
	{"CS_MODE_TRICORE_110", CS_MODE_TRICORE_110},
	{"CS_MODE_TRICORE_120", CS_MODE_TRICORE_120},
	{"CS_MODE_TRICORE_130", CS_MODE_TRICORE_130},
	{"CS_MODE_TRICORE_131", CS_MODE_TRICORE_131},
	{"CS_MODE_TRICORE_160", CS_MODE_TRICORE_160},
	{"CS_MODE_TRICORE_161", CS_MODE_TRICORE_161},
	{"CS_MODE_TRICORE_162", CS_MODE_TRICORE_162},
};

 static double_dict options[] = {
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
	{"CS_MODE_PS", CS_OPT_MODE, CS_MODE_PS},
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
	{"CS_MODE_M680X_HCS08", CS_OPT_MODE, CS_MODE_M680X_HCS08},
	{"CS_MODE_RISCV32", CS_OPT_MODE, CS_MODE_RISCV32},
	{"CS_MODE_RISCV64", CS_OPT_MODE, CS_MODE_RISCV64},
	{"CS_MODE_TRICORE_110", CS_OPT_MODE, CS_MODE_TRICORE_110},
	{"CS_MODE_TRICORE_120", CS_OPT_MODE, CS_MODE_TRICORE_120},
	{"CS_MODE_TRICORE_130", CS_OPT_MODE, CS_MODE_TRICORE_130},
	{"CS_MODE_TRICORE_131", CS_OPT_MODE, CS_MODE_TRICORE_131},
	{"CS_MODE_TRICORE_160", CS_OPT_MODE, CS_MODE_TRICORE_160},
	{"CS_MODE_TRICORE_161", CS_OPT_MODE, CS_MODE_TRICORE_161},
	{"CS_MODE_TRICORE_162", CS_OPT_MODE, CS_MODE_TRICORE_162},
	{"CS_OPT_UNSIGNED", CS_OPT_UNSIGNED, CS_OPT_ON},
};

static int counter;
static char **list_lines;
static int failed_setup;
static int size_lines;
static cs_mode issue_mode;
static int getDetail;
static int mc_mode;
static int e_flag;

static int setup_MC(void **state)
{
	csh *handle;
	char **list_params;	
	int size_params;
	int arch, mode;
	int i, tmp_counter;

	if (failed_setup) {
		fprintf(stderr, "[  ERROR   ] --- Invalid file to setup\n");
		return -1;
	}

	tmp_counter = 0;
	while (tmp_counter < size_lines && list_lines[tmp_counter][0] != '#')
		tmp_counter++;

	list_params = split(list_lines[tmp_counter] + 2, ", ", &size_params);
	if (size_params != 3) {
		fprintf(stderr, "[  ERROR   ] --- Invalid options ( arch, mode, option )\n");
		failed_setup = 1;
		return -1;
	}

	arch = get_value(arches, ARR_SIZE(arches), list_params[0]);
	if (!strcmp(list_params[0], "CS_ARCH_ARM64")) 
		mc_mode = 2;
	else 
		mc_mode = 1;

	mode = 0;
	for (i = 0; i < ARR_SIZE(modes); ++i) {
		if (strstr(list_params[1], modes[i].str)) {
			mode += modes[i].value;
			switch (modes[i].value) {
				case CS_MODE_16:
					mc_mode = 0;
					break;
				case CS_MODE_64:
					mc_mode = 2;
					break;
				case CS_MODE_THUMB:
					mc_mode = 1;
					break;
				default:
					break;
			}
		}
	}

	if (arch == -1) {
		fprintf(stderr, "[  ERROR   ] --- Arch is not supported!\n");
		failed_setup = 1;
		return -1;
	}

	handle = (csh *)malloc(sizeof(csh));
	if(cs_open(arch, mode, handle) != CS_ERR_OK) {
		fprintf(stderr, "[  ERROR   ] --- Cannot initialize capstone\n");
		failed_setup = 1;
		return -1;
	}
	
	for (i = 0; i < ARR_SIZE(options); ++i) {
		if (strstr(list_params[2], options[i].str)) {
			if (cs_option(*handle, options[i].first_value, options[i].second_value) != CS_ERR_OK) {
				fprintf(stderr, "[  ERROR   ] --- Option is not supported for this arch/mode\n");
				failed_setup = 1;
				return -1;
			}
		}
	}

	*state = (void *)handle;
	counter++;
	if (e_flag == 0)
		while (counter < size_lines && strncmp(list_lines[counter], "0x", 2))
			counter++;
	else
		while (counter < size_lines && strncmp(list_lines[counter], "// 0x", 5))
			counter++;

	free_strs(list_params, size_params);
	return 0;
}

static void test_MC(void **state)
{
	if (e_flag == 1)
		test_single_MC((csh *)*state, mc_mode, list_lines[counter] + 3);
	else
		test_single_MC((csh *)*state, mc_mode, list_lines[counter]);
}

static int teardown_MC(void **state)
{
	cs_close(*state);
	free(*state);
	return 0;
}

static int setup_issue(void **state)
{
	csh *handle;
	char **list_params;	
	int size_params;
	int arch, mode;
	int i, result;

	getDetail = 0;
	failed_setup = 0;

	if (e_flag == 0)
		while (counter < size_lines && strncmp(list_lines[counter], "!# ", 3))
			counter++; // get issue line
	else
		while (counter < size_lines && strncmp(list_lines[counter], "// !# ", 6))
			counter++;

	counter++;
	if (e_flag == 0)
		while (counter < size_lines && strncmp(list_lines[counter], "!#", 2))
			counter++; // get arch line
	else
		while (counter < size_lines && strncmp(list_lines[counter], "// !# ", 6))
			counter++;

	if (e_flag == 0)
		list_params = split(list_lines[counter] + 3, ", ", &size_params);
	else
		list_params = split(list_lines[counter] + 6, ", ", &size_params);

	arch = get_value(arches, ARR_SIZE(arches), list_params[0]);

	if (!strcmp(list_params[0], "CS_ARCH_ARM64"))
		mc_mode = 2;
	else
		mc_mode = 1;

	mode = 0;
	for (i = 0; i < ARR_SIZE(modes); ++i) {
		if (strstr(list_params[1], modes[i].str)) {
			mode += modes[i].value;
			switch (modes[i].value) {
				case CS_MODE_16:
					mc_mode = 0;
					break;
				case CS_MODE_64:
					mc_mode = 2;
					break;
				case CS_MODE_THUMB:
					mc_mode = 1;
					break;
				default:
					break;
			}
		}
	}

	if (arch == -1) {
		fprintf(stderr, "[  ERROR   ] --- Arch is not supported!\n");
		failed_setup = 1;
		return -1;
	}

	handle = (csh *)calloc(1, sizeof(csh));
	if(cs_open(arch, mode, handle) != CS_ERR_OK) {
		fprintf(stderr, "[  ERROR   ] --- Cannot initialize capstone\n");
		failed_setup = 1;
		return -1;
	}
	
	for (i = 0; i < ARR_SIZE(options); ++i) {
		if (strstr(list_params[2], options[i].str)) {
			if (cs_option(*handle, options[i].first_value, options[i].second_value) != CS_ERR_OK) {
				fprintf(stderr, "[  ERROR   ] --- Option is not supported for this arch/mode\n");
				failed_setup = 1;
				return -1;
			}

			if (i == 0) {
				result = set_function(arch);
				if (result == -1) {
					fprintf(stderr, "[  ERROR   ] --- Cannot get details\n");
					failed_setup = 1;
					return -1;
				}

				getDetail = 1;
			}
		}
	}

	*state = (void *)handle;
	issue_mode = mode;

	if (e_flag == 0)
		while (counter < size_lines && strncmp(list_lines[counter], "0x", 2))
			counter++;
	else
		while (counter < size_lines && strncmp(list_lines[counter], "// 0x", 5))
			counter++;

	free_strs(list_params, size_params);
	return 0;
}

static void test_issue(void **state)
{
	if (e_flag == 0)
		test_single_issue((csh *)*state, issue_mode, list_lines[counter], getDetail);
	else
		test_single_issue((csh *)*state, issue_mode, list_lines[counter] + 3, getDetail);

	return;
}

static int teardown_issue(void **state)
{
	if (e_flag == 0)
		while (counter < size_lines && strncmp(list_lines[counter], "!# ", 3))
			counter++;
	else
		while (counter < size_lines && strncmp(list_lines[counter], "// !# ", 6))
			counter++;

	cs_close(*state);
	free(*state);
	function = NULL;
	return 0;
}

static void test_file(const char *filename)
{
	int i;
	char *content, *tmp;
	struct CMUnitTest *tests;
	int number_of_tests;

	printf("[+] TARGET: %s\n", filename);
	content = readfile(filename);
	counter = 0;
	failed_setup = 0;
	function = NULL;		

	if (strstr(filename, "issue")) {
		number_of_tests = 0;
		list_lines = split(content, "\n", &size_lines);	
		tests = NULL;
		for (i = 0; i < size_lines; ++i) {
			if ((!strncmp(list_lines[i], "// !# issue", 11) && e_flag == 1) || 
					(!strncmp(list_lines[i], "!# issue", 8) && e_flag == 0)) {
				tests = (struct CMUnitTest *)realloc(tests, sizeof(struct CMUnitTest) * (number_of_tests + 1));
				tests[number_of_tests] = (struct CMUnitTest)cmocka_unit_test_setup_teardown(test_issue, setup_issue, teardown_issue);
				tests[number_of_tests].name = strdup(list_lines[i]);
				number_of_tests ++;
			}
		}

		_cmocka_run_group_tests("Testing issues", tests, number_of_tests, NULL, NULL);
	} else {
		list_lines = split(content, "\n", &size_lines);
		number_of_tests = 0;

		tests = NULL;
		for (i = 1; i < size_lines; ++i) {
			if ((!strncmp(list_lines[i], "// 0x", 5) && e_flag == 1) || (!strncmp(list_lines[i], "0x", 2) && e_flag == 0)) {
				tmp = (char *)malloc(sizeof(char) * 100);
				sprintf(tmp, "Line %d", i+1);
				tests = (struct CMUnitTest *)realloc(tests, sizeof(struct CMUnitTest) * (number_of_tests + 1));
				tests[number_of_tests] = (struct CMUnitTest)cmocka_unit_test_setup_teardown(test_MC, setup_MC, teardown_MC);
				tests[number_of_tests].name = tmp;
				number_of_tests ++;
			}
		}

		_cmocka_run_group_tests("Testing MC", tests, number_of_tests, NULL, NULL);
	}

	printf("[+] DONE: %s\n", filename);
	printf("[!] Noted:\n[  ERROR   ] --- \"<capstone result>\" != \"<user result>\"\n");	
	printf("\n\n");
	free_strs(list_lines, size_lines);
}

static void test_folder(const char *folder)
{
	char **files;
	int num_files, i;

	files = NULL;
	num_files = 0;
	listdir(folder, &files, &num_files);
	for (i = 0; i < num_files; ++i) {
		if (strcmp("cs", get_filename_ext(files[i])))
			continue;
		test_file(files[i]);
	}
}

int main(int argc, char *argv[])
{
	int opt, flag;

	flag = 0;
	e_flag = 0;

	while ((opt = getopt(argc, argv, "ef:d:")) > 0) {
		switch (opt) {
			case 'f':
				test_file(optarg);
				flag = 1;
				break;
			case 'd':
				test_folder(optarg);
				flag = 1;
				break;
			case 'e':
				e_flag = 1;
				break;
			default:
				printf("Usage: %s [-e] [-f <file_name.cs>] [-d <directory>]\n", argv[0]);
				exit(-1);
		}
	}

	if (flag == 0) {
		printf("Usage: %s [-e] [-f <file_name.cs>] [-d <directory>]\n", argv[0]);
		exit(-1);
	}

	return 0;
}

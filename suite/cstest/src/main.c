#include "helper.h"
#include "capstone_test.h"
#include <unistd.h>

static int counter;
static char **list_lines;
static int failed_setup;
static int size_lines;
static cs_mode issue_mode;
static int getDetail;

static int setup_MC(void **state)
{
	csh *handle;
	char **list_params;	
	int size_params;
	int arch, mode;
	int i, index, tmp_counter;

	if (failed_setup) {
		fprintf(stderr, "[  ERROR   ] --- Invalid file to setup\n");
		return -1;
	}

	tmp_counter = 0;
	while (tmp_counter < size_lines && list_lines[tmp_counter][0] != '#') tmp_counter++; // get issue line

	list_params = split(list_lines[tmp_counter] + 2, ", ", &size_params);
	arch = get_value(arches, NUMARCH, list_params[0]);
	mode = get_value(modes, NUMMODE, list_params[1]);

	if (arch == -1 || mode == -1) {
		fprintf(stderr, "[  ERROR   ] --- Arch and/or Mode are not supported!\n");
		failed_setup = 1;
		return -1;
	}

	handle = (csh *)malloc(sizeof(csh));

	cs_open(arch, mode, handle);
	for (i=2; i < size_params; ++i)
		if (strcmp(list_params[i], "None")) {
			index = get_index(options, NUMOPTION, list_params[i]);
			if (index == -1) {
				fprintf(stderr, "[  ERROR   ] --- Option is not supported!\n");
				failed_setup = 1;
				return -1;
			}
			cs_option(*handle, options[index].first_value, options[index].second_value);
		}
	*state = (void *)handle;
	counter++;
	while (counter < size_lines && list_lines[counter][0] != '0') counter++;
	free_strs(list_params, size_params);

	return 0;
}

static void test_MC(void **state)
{
	test_single_MC((csh *)*state, list_lines[counter]);
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
	int i, index, result;
	char *(*function)(csh *, cs_mode, cs_insn*);

	getDetail = 0;
	failed_setup = 0;

	while (counter < size_lines && list_lines[counter][0] != '!') counter++; // get issue line
	counter++;
	while (counter < size_lines && list_lines[counter][0] != '!') counter++; // get arch/mode line
	list_params = split(list_lines[counter] + 2, ", ", &size_params);
	//	print_strs(list_params, size_params);
	arch = get_value(arches, NUMARCH, list_params[0]);
	mode = get_value(modes, NUMMODE, list_params[1]);

	if (arch == -1 || mode == -1) {
		fprintf(stderr, "[  ERROR   ] --- Arch and/or Mode are not supported!\n");
		failed_setup = 1;
		return -1;
	}

	handle = (csh *)calloc(1, sizeof(csh));

	cs_open(arch, mode, handle);
	for (i=2; i < size_params; ++i) {
		if (strcmp(list_params[i], "None")) {
			index = get_index(options, NUMOPTION, list_params[i]);
			if (index == -1) {
				fprintf(stderr, "[  ERROR   ] --- Option is not supported!\n");
				failed_setup = 1;
				return -1;
			}
			if (index == 0) {
				result = set_function(arch);
				if (result == -1) {
					fprintf(stderr, "[  ERROR   ] --- Cannot get details\n");
					failed_setup = 1;
					return -1;
				}
				getDetail = 1;
			}
			cs_option(*handle, options[index].first_value, options[index].second_value);
		}
	}

	*state = (void *)handle;
	issue_mode = mode;

	while (counter < size_lines && list_lines[counter][0] != '0') counter ++;
	free_strs(list_params, size_params);

	return 0;
}

static void test_issue(void **state)
{
	test_single_issue((csh *)*state, issue_mode, list_lines[counter], getDetail);
	//	counter ++;
	return;
}

static int teardown_issue(void **state)
{
	while (counter < size_lines && list_lines[counter][0] != '!') counter++; // get next issue
	cs_close(*state);
	free(*state);
	function = NULL;
	return 0;
}

static void test_file(const char *filename)
{
	int size, i;
	char **list_str; 
	char *content, *tmp;
	struct CMUnitTest *tests;
	int issue_num, number_of_tests;

	printf("[+] TARGET: %s\n", filename);
	content = readfile(filename);
	counter = 0;
	failed_setup = 0;
	function = NULL;		

	if (strstr(filename, "issue")) {
		number_of_tests = 0;
		list_lines = split(content, "\n", &size_lines);	
		// tests = (struct CMUnitTest *)malloc(sizeof(struct CMUnitTest) * size_lines / 3);
		tests = NULL;
		for (i=0; i < size_lines; ++i) {
			if (strstr(list_lines[i], "!# issue")) {
				tmp = (char *)malloc(sizeof(char) * 100);
				sscanf(list_lines[i], "!# issue %d\n", &issue_num);			
				sprintf(tmp, "Issue #%d", issue_num);
				tests = (struct CMUnitTest *)realloc(tests, sizeof(struct CMUnitTest) * (number_of_tests + 1));
				tests[number_of_tests] = (struct CMUnitTest)cmocka_unit_test_setup_teardown(test_issue, setup_issue, teardown_issue);
				tests[number_of_tests].name = tmp;
				number_of_tests ++;
			}
		}

		_cmocka_run_group_tests("Testing issues", tests, number_of_tests, NULL, NULL);
	} else {
		list_lines = split(content, "\n", &size_lines);
		number_of_tests = 0;

		tests = NULL;
		// tests = (struct CMUnitTest *)malloc(sizeof(struct CMUnitTest) * (size_lines - 1));
		for (i = 1; i < size_lines; ++i) {
			if (list_lines[i][0] == '0') {
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
	for (i=0; i<num_files; ++i) {
		if (strcmp("cs", get_filename_ext(files[i])))
			continue;
		test_file(files[i]);
	}
}

int main(int argc, char *argv[])
{
	int opt, flag;

	flag = 0;
	while ((opt = getopt(argc, argv, "f:d:")) > 0) {
		switch (opt) {
			case 'f':
				test_file(optarg);
				flag = 1;
				break;
			case 'd':
				test_folder(optarg);
				flag = 1;
				break;
			default:
				printf("Usage: %s [-f <file_name.cs>] [-d <directory>]\n", argv[0]);
				exit(-1);
		}
	}

	if (flag == 0) {
		printf("Usage: %s [-f <file_name.cs>] [-d <directory>]\n", argv[0]);
		exit(-1);
	}

	return 0;
}

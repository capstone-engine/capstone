#include "helper.h"
#include "capstone_test.h"

static int counter;
static char **list_lines;
static int failed_setup;
static int size_lines;

static int setup_MC(void **state)
{
	csh *handle;
	char **list_params;	
	int size_params;
	int arch, mode;
	int i, index;

	if (failed_setup)
		return -1;

	list_params = split(list_lines[0], ", ", &size_params);
	arch = getValue(arches, NUMARCH, list_params[0]);
	mode = getValue(modes, NUMMODE, list_params[1]);
	
	if (arch == -1 || mode == -1) {
		printf("[-] Arch and/or Mode are not supported!\n");
		failed_setup = 1;
		return -1;
	}
	
	handle = (csh *)malloc(sizeof(csh));
	
	cs_open(arch, mode, handle);
	for (i=2; i<size_params; ++i)
		if (strcmp(list_params[i], "None")) {
			index = getIndex(options, NUMOPTION, list_params[i]);
			if (index == -1) {
				printf("[-] Option is not supported!\n");
				return -1;
			}
			cs_option(*handle, options[index].first_value, options[index].second_value);
		}
	*state = (void *)handle;
	counter ++;
	free_strs(list_params, size_params);
	return 0;
}

static void test_MC(void **state)
{
	test_single((csh *)*state, list_lines[counter]);
	return;
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
	int i, index;

	if (failed_setup)
		return -1;

	list_params = split(list_lines[counter], ", ", &size_params);
	arch = getValue(arches, NUMARCH, list_params[0]);
	mode = getValue(modes, NUMMODE, list_params[1]);
	
	if (arch == -1 || mode == -1) {
		printf("[-] Arch and/or Mode are not supported!\n");
		failed_setup = 1;
		return -1;
	}
	
	handle = (csh *)malloc(sizeof(csh));
	
	cs_open(arch, mode, handle);
	for (i=2; i<size_params; ++i)
		if (strcmp(list_params[i], "None")) {
			index = getIndex(options, NUMOPTION, list_params[i]);
			if (index == -1) {
				printf("[-] Option is not supported!\n");
				return -1;
			}
			if (index == 0) {
				
			}
			cs_option(*handle, options[index].first_value, options[index].second_value);
		}
	*state = (void *)handle;
	counter ++;
	free_strs(list_params, size_params);
	return 0;

}

static void test_issues(void **state)
{
	test_single_issues((csh *)*state, list_lines[counter]);
	counter += 3;
	return;
}

int main(int argc, char *argv[])
{
	int size, i;
	char **list_str; 
	char *content;
	struct CMUnitTest *tests;
	
	if (argc != 2) {
		puts("Usage: ./issues <file_name.cs>");
		return -1;
	}
	
	content = readfile(argv[1]);
	list_lines = split(content + 2, "\n", &size_lines);
	counter = 0;

	failed_setup = 0;

	tests = (struct CMUnitTest *)malloc(sizeof(struct CMUnitTest) * (size_lines - 1));
	for (i=0; i<size_lines - 1; ++i) {
		char *tmp = (char *)malloc(sizeof(char) * 100);
		sprintf(tmp, "%d'th line", i+2);
		tests[i] = (struct CMUnitTest)cmocka_unit_test_setup_teardown(test_MC, setup_MC, teardown_MC);
		tests[i].name = tmp;
	}
	
	_cmocka_run_group_tests("Testing", tests, size_lines-1, NULL, NULL);
	
	printf("[+] Noted:\n[  ERROR   ] --- \"<capstone result>\" != \"<user result>\"\n");	
	free_strs(list_lines, size_lines);
	return 0;
}

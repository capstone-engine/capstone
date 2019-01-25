#include "helper.h"
#include "capstone_test.h"

static int counter = 1;
static char **list_lines;
static csh handle;

static void test_disasm(void **state)
{
	test_single(handle, list_lines[counter++]);
}

int main(int argc, char *argv[])
{
	int size, index;
	char **list_str, **list_params;
	char *content;
	struct CMUnitTest *tests;
	int size_lines, size_params;
	int arch, mode;
	int i;

	if (argc != 2) {
		puts("Usage: ./issues <file_name.cs>");
		return -1;
	}
	
	content = readfile(argv[1]);
	list_lines = split(content + 2, "\n", &size_lines);
	list_params = split(list_lines[0], ", ", &size_params);
	arch = getValue(arches, 9, list_params[0]);
	mode = getValue(modes, 20, list_params[1]);
	cs_open(arch, mode, &handle);
	if (strcmp(list_params[2], "None")) {
		index = getIndex(options, 40, list_params[2]);
		cs_option(handle, options[index].first_value, options[index].second_value);
	}
	
	
	tests = (struct CMUnitTest *)malloc(sizeof(struct CMUnitTest) * (size_lines - 1));
	for (i=0; i<size_lines - 1; ++i) {
		char *tmp = (char *)malloc(sizeof(char) * 100);
		sprintf(tmp, "%d'th line", i+2);
		tests[i] = (struct CMUnitTest)cmocka_unit_test(test_disasm);
		tests[i].name = tmp;
	}
	
	
	_cmocka_run_group_tests("Testing", tests, size_lines-1, NULL, NULL);
	
	printf("[+] Noted:\n[  ERROR   ] --- \"<capstone result>\" != \"<user result>\"\n");	
	cs_close(&handle);	
	free(list_lines);
	free(list_params);
	return 0;
}

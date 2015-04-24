
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../myinttypes.h"

#include <capstone.h>
#include "test_utils.h"

void print_string_hex(char *comment, unsigned char *str, size_t len)
{
	unsigned char *c;

	printf("%s", comment);
	for (c = str; c < str + len; c++) {
		printf("0x%02x ", *c & 0xff);
	}

	printf("\n");
}

void expect_group(csh handle, int* error, int grp, const char* name)
{
	const char* res = cs_group_name(handle, grp);
	if(name) {
		if( !res ) {
			printf("ERROR: Expected '%s' for 0x%x, got nullptr\n", name, grp);
			(*error)++;
		} else if( strcmp(name, res)) {
			printf("ERROR: Expected '%s' for 0x%x, got '%s'\n", name, grp, res);
			(*error)++;
		}
	} else {
		if( res ) {
			printf("ERROR: Expected nullptr for 0x%x, got something\n", grp);
			(*error)++;
		}
	}
}

void test_groups_common(csh handle, int* error, struct group_name* groups, size_t count)
{
	size_t n;
	for(n = 0; n < count; ++n) {
		expect_group(handle, error, groups[n].grp, groups[n].code);
	}
}


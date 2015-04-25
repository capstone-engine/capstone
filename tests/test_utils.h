#ifndef CAPSTONE_TEST_UTILS_H
#define CAPSTONE_TEST_UTILS_H

void print_string_hex(char *comment, unsigned char *str, size_t len);

struct group_name {
	int grp;
	char *code;
};

void test_groups_common(csh handle, int* error, struct group_name* groups, size_t count);

#define COUNTOF(x)		(sizeof(x) / sizeof(x[0]))

#endif // CAPSTONE_TEST_UTILS_H

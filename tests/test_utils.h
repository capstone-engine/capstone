
void print_string_hex(char *comment, unsigned char *str, size_t len);

struct group_name {
	int grp;
	char *code;
};

void test_groups_common(csh handle, int* error, struct group_name* groups, size_t count);

#define COUNTOF(x)		(sizeof(x) / sizeof(x[0]))

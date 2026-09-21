#include <stdio.h>

#include <capstone/capstone.h>

int main(int argc, char **argv)
{
	csh h;
	const char *name;

	if (cs_open(CS_ARCH_M68K, 0, &h) != CS_ERR_OK)
		return 1;
	printf("M68K_INS_ENDING=%u\n", M68K_INS_ENDING);
	fflush(stdout);
	name = cs_insn_name(h, 0xdeadbeefu);
	printf("name=%p %s\n", (void *)name, name ? name : "null");

	// M68K_INS_ENDING is one past the last valid id and must not be read.
	name = cs_insn_name(h, M68K_INS_ENDING);
	printf("ending name=%p %s\n", (void *)name, name ? name : "null");
	if (name != NULL) {
		cs_close(&h);
		return 1;
	}

	cs_close(&h);
	return 0;
}

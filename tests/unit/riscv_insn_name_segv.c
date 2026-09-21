#include <stdio.h>

#include <capstone/capstone.h>

int main(int argc, char **argv)
{
	csh h;
	const char *name;

	if (cs_open(CS_ARCH_RISCV, CS_MODE_RISCV64, &h) != CS_ERR_OK)
		return 1;
	printf("RISCV_INS_ENDING=%u\n", RISCV_INS_ENDING);
	printf("RISCV_INS_ALIAS_BEGIN=%u\n", RISCV_INS_ALIAS_BEGIN);
	fflush(stdout);
	name = cs_insn_name(h, RISCV_INS_ENDING);
	printf("name=%p %s\n", (void *)name, name ? name : "null");
	cs_close(&h);
	return 0;
}

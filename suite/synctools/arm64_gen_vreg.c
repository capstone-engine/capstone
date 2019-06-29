// $ make arm64_gen_vreg 
// $ ./arm64_gen_vreg > AArch64GenRegisterV.inc

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#undef CAPSTONE_DIET
#define GET_REGINFO_ENUM

#include "AArch64GenRegisterInfo.inc"
#include "AArch64GenRegisterName.inc"

int main()
{
	unsigned int i;
	size_t size = (size_t)getRegisterName(i, 100);

	printf("// size = %zu\n", size);

	for(i = 1; i < size; i++) {
		unsigned int j;
		const char *name = getRegisterName(i, AArch64_vreg);
		//printf("%u: ARM64_REG_%s, ", i, getRegisterName(i, AArch64_vreg));
		if (strlen(name) == 0) {
			printf("0,\n");
		} else {
			printf("ARM64_REG_");
			for(j = 0; j < strlen(name); j++) {
				printf("%c", toupper(name[j]));
			}
			printf(",\n");
		}
	}

	return 0;
}

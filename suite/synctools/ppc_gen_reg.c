// $ make ppc_gen_reg 
// $ ./ppc_gen_reg > PPCRegisterMapping.inc

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#undef CAPSTONE_DIET
#define GET_REGINFO_ENUM

#include "PPCGenRegisterInfo.inc"
#include "PPCGenRegisterName.inc"

static int valid_name(const char *name)
{
    int i;

    for(i = 0; name[i]; i++) {
        if (name[i] == '*')
			// invalid name
            return 0;
    }

	// good
    return 1;
}

int main()
{
	unsigned int i;

	for(i = 1; i <= 343; i++) {
		const char *name = getRegisterName(i);
		//printf("%u: ARM64_REG_%s, ", i, getRegisterName(i, AArch64_vreg));
		if (strlen(name) == 0 || !valid_name(name)) {
			printf("0,\n");
		} else {
			unsigned int j;

			if (!strcmp("spefscr", name))
				printf("0,\n");
			else {
				// printf("%u: PPC_REG_", i);
				printf("PPC_REG_");

				if (name[0] >= '0' && name[0] <= '9')
					printf("R");

				for(j = 0; j < strlen(name); j++) {
					printf("%c", toupper(name[j]));
				}
				printf(",\n");
			}
		}
	}

	return 0;
}

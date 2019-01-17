/*
 Retrieve architectures compiled in Capstone.
 By Nguyen Anh Quynh, 2019.

 Compile this code with:
 $ cc -o capstone_get_setup capstone_get_setup.c -lcapstone

 On default Capstone build, this code prints out the below output:

 $ capstone_get_setup
 x86=1 arm=1 arm64=1 mips=1 ppc=1 sparc=1 sysz=1 xcore=1 m68k=1 tms320c64x=1 m680x=1 evm=1
*/

#include <stdio.h>
#include <capstone/capstone.h>

int main()
{
	if (cs_support(CS_ARCH_X86)) {
		printf("x86=1 ");
	}

	if (cs_support(CS_ARCH_ARM)) {
		printf("arm=1 ");
	}

	if (cs_support(CS_ARCH_ARM64)) {
		printf("arm64=1 ");
	}

	if (cs_support(CS_ARCH_MIPS)) {
		printf("mips=1 ");
	}

	if (cs_support(CS_ARCH_PPC)) {
		printf("ppc=1 ");
	}

	if (cs_support(CS_ARCH_SPARC)) {
		printf("sparc=1 ");
	}

	if (cs_support(CS_ARCH_SYSZ)) {
		printf("sysz=1 ");
	}

	if (cs_support(CS_ARCH_XCORE)) {
		printf("xcore=1 ");
	}

	if (cs_support(CS_ARCH_M68K)) {
		printf("m68k=1 ");
	}

	if (cs_support(CS_ARCH_TMS320C64X)) {
		printf("tms320c64x=1 ");
	}

	if (cs_support(CS_ARCH_M680X)) {
		printf("m680x=1 ");
	}

	if (cs_support(CS_ARCH_EVM)) {
		printf("evm=1 ");
	}

	if (cs_support(CS_SUPPORT_DIET)) {
		printf("diet=1 ");
	}

	if (cs_support(CS_SUPPORT_X86_REDUCE)) {
		printf("x86_reduce=1 ");
	}

	printf("\n");

	return 0;
}

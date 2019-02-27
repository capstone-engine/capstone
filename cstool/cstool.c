/* Tang Yuhang <tyh000011112222@gmail.com> 2016 */
/* pancake <pancake@nopcode.org> 2017 */

#include <string.h>
#include <ctype.h>
#include <errno.h>
#include "getopt.h"

#include <capstone/capstone.h>

static struct {
	const char *name;
	cs_arch arch;
	cs_mode mode;
} all_archs[] = {
	{ "arm", CS_ARCH_ARM, CS_MODE_ARM },
	{ "armb", CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_BIG_ENDIAN },
	{ "armbe", CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_BIG_ENDIAN },
	{ "arml", CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN },
	{ "armle", CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN },
	{ "armv8", CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_V8 },
	{ "thumbv8", CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_V8 },
	{ "cortexm", CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_MCLASS },
	{ "thumb", CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_THUMB },
	{ "thumbbe", CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_BIG_ENDIAN },
	{ "thumble", CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN },
	{ "arm64", CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN },
	{ "arm64be", CS_ARCH_ARM64, CS_MODE_BIG_ENDIAN },
	{ "mips", CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN },
	{ "mipsmicro", CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_MICRO },
	{ "mipsbemicro", CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_MICRO | CS_MODE_BIG_ENDIAN },
	{ "mipsbe32r6", CS_ARCH_MIPS, CS_MODE_MIPS32R6 | CS_MODE_BIG_ENDIAN},
	{ "mipsbe32r6micro", CS_ARCH_MIPS, CS_MODE_MIPS32R6 | CS_MODE_BIG_ENDIAN | CS_MODE_MICRO },
	{ "mips32r6", CS_ARCH_MIPS, CS_MODE_MIPS32R6 },
	{ "mips32r6micro", CS_ARCH_MIPS, CS_MODE_MIPS32R6 | CS_MODE_MICRO },
	{ "mipsbe", CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_BIG_ENDIAN },
	{ "mips64", CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_LITTLE_ENDIAN },
	{ "mips64be", CS_ARCH_MIPS, CS_MODE_MIPS64 | CS_MODE_BIG_ENDIAN },
	{ "x16", CS_ARCH_X86, CS_MODE_16 }, // CS_MODE_16
	{ "x16att", CS_ARCH_X86, CS_MODE_16 }, // CS_MODE_16 , CS_OPT_SYNTAX_ATT
	{ "x32", CS_ARCH_X86, CS_MODE_32 }, // CS_MODE_32
	{ "x32att", CS_ARCH_X86, CS_MODE_32 }, // CS_MODE_32, CS_OPT_SYNTAX_ATT
	{ "x64", CS_ARCH_X86, CS_MODE_64 }, // CS_MODE_64
	{ "x64att", CS_ARCH_X86, CS_MODE_64 }, // CS_MODE_64, CS_OPT_SYNTAX_ATT
	{ "ppc64", CS_ARCH_PPC, CS_MODE_64 | CS_MODE_LITTLE_ENDIAN },
	{ "ppc64be", CS_ARCH_PPC, CS_MODE_64 | CS_MODE_BIG_ENDIAN },
	{ "sparc", CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN },
	{ "sparcv9", CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN | CS_MODE_V9 },
	{ "systemz", CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN },
	{ "sysz", CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN },
	{ "s390x", CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN },
	{ "xcore", CS_ARCH_XCORE, CS_MODE_BIG_ENDIAN },
	{ "m68k", CS_ARCH_M68K, CS_MODE_BIG_ENDIAN },
	{ "m68k40", CS_ARCH_M68K, CS_MODE_M68K_040 },
	{ "tms320c64x", CS_ARCH_TMS320C64X, CS_MODE_BIG_ENDIAN },
	{ "m6800", CS_ARCH_M680X, CS_MODE_M680X_6800 },
	{ "m6801", CS_ARCH_M680X, CS_MODE_M680X_6801 },
	{ "m6805", CS_ARCH_M680X, CS_MODE_M680X_6805 },
	{ "m6808", CS_ARCH_M680X, CS_MODE_M680X_6808 },
	{ "m6809", CS_ARCH_M680X, CS_MODE_M680X_6809 },
	{ "m6811", CS_ARCH_M680X, CS_MODE_M680X_6811 },
	{ "cpu12", CS_ARCH_M680X, CS_MODE_M680X_CPU12 },
	{ "hd6301", CS_ARCH_M680X, CS_MODE_M680X_6301 },
	{ "hd6309", CS_ARCH_M680X, CS_MODE_M680X_6309 },
	{ "hcs08", CS_ARCH_M680X, CS_MODE_M680X_HCS08 },
	{ "evm", CS_ARCH_EVM, 0 },
	{ NULL }
};

void print_insn_detail_x86(csh ud, cs_mode mode, cs_insn *ins);
void print_insn_detail_arm(csh handle, cs_insn *ins);
void print_insn_detail_arm64(csh handle, cs_insn *ins);
void print_insn_detail_mips(csh handle, cs_insn *ins);
void print_insn_detail_ppc(csh handle, cs_insn *ins);
void print_insn_detail_sparc(csh handle, cs_insn *ins);
void print_insn_detail_sysz(csh handle, cs_insn *ins);
void print_insn_detail_xcore(csh handle, cs_insn *ins);
void print_insn_detail_m68k(csh handle, cs_insn *ins);
void print_insn_detail_tms320c64x(csh handle, cs_insn *ins);
void print_insn_detail_m680x(csh handle, cs_insn *ins);
void print_insn_detail_evm(csh handle, cs_insn *ins);

static void print_details(csh handle, cs_arch arch, cs_mode md, cs_insn *ins);

void print_string_hex(const char *comment, unsigned char *str, size_t len)
{
	unsigned char *c;

	printf("%s", comment);
	for (c = str; c < str + len; c++) {
		printf("0x%02x ", *c & 0xff);
	}

	printf("\n");
}

// convert hexchar to hexnum
static uint8_t char_to_hexnum(char c)
{
	if (c >= '0' && c <= '9') {
		return (uint8_t)(c - '0');
	}

	if (c >= 'a' && c <= 'f') {
		return (uint8_t)(10 + c - 'a');
	}

	//  c >= 'A' && c <= 'F'
	return (uint8_t)(10 + c - 'A');
}

// convert user input (char[]) to uint8_t[], each element of which is
// valid hexadecimal, and return actual length of uint8_t[] in @size.
static uint8_t *preprocess(char *code, size_t *size)
{
	size_t i = 0, j = 0;
	uint8_t high, low;
	uint8_t *result;

	if (strlen(code) == 0)
		return NULL;

	result = (uint8_t *)malloc(strlen(code));
	if (result != NULL) {
		while (code[i] != '\0') {
			if (isxdigit(code[i]) && isxdigit(code[i+1])) {
				high = 16 * char_to_hexnum(code[i]);
				low = char_to_hexnum(code[i+1]);
				result[j] = high + low;
				i++;
				j++;
			}
			i++;
		}
		*size = j;
	}

	return result;
}

static void usage(char *prog)
{
	printf("Cstool for Capstone Disassembler Engine v%u.%u.%u\n\n", CS_VERSION_MAJOR, CS_VERSION_MINOR, CS_VERSION_EXTRA);
	printf("Syntax: %s [-u|-d|-s|-v] <arch+mode> <assembly-hexstring> [start-address-in-hex-format]\n", prog);
	printf("\nThe following <arch+mode> options are supported:\n");

	if (cs_support(CS_ARCH_X86)) {
		printf("        x16:       16-bit mode (X86)\n");
		printf("        x32:       32-bit mode (X86)\n");
		printf("        x64:       64-bit mode (X86)\n");
		printf("        x16att:    16-bit mode (X86) syntax-att\n");
		printf("        x32att:    32-bit mode (X86) syntax-att\n");
		printf("        x64att:    64-bit mode (X86) syntax-att\n");
	}

	if (cs_support(CS_ARCH_ARM)) {
		printf("        arm:       arm\n");
		printf("        armbe:     arm + big endian\n");
		printf("        thumb:     thumb mode\n");
		printf("        thumbbe:   thumb + big endian\n");
		printf("        cortexm:   thumb + cortex-m extensions\n");
		printf("        armv8:     arm v8\n");
		printf("        thumbv8:   thumb v8\n");
	}

	if (cs_support(CS_ARCH_ARM64)) {
		printf("        arm64:     aarch64 mode\n");
		printf("        arm64be:   aarch64 + big endian\n");
	}

	if (cs_support(CS_ARCH_MIPS)) {
		printf("        mips:      mips32 + little endian\n");
		printf("        mipsbe:    mips32 + big endian\n");
		printf("        mips64:    mips64 + little endian\n");
		printf("        mips64be:  mips64 + big endian\n");
	}

	if (cs_support(CS_ARCH_PPC)) {
		printf("        ppc64:     ppc64 + little endian\n");
		printf("        ppc64be:   ppc64 + big endian\n");
	}

	if (cs_support(CS_ARCH_SPARC)) {
		printf("        sparc:     sparc\n");
	}

	if (cs_support(CS_ARCH_SYSZ)) {
		printf("        systemz:   systemz (s390x)\n");
	}

	if (cs_support(CS_ARCH_XCORE)) {
		printf("        xcore:     xcore\n");
	}

	if (cs_support(CS_ARCH_M68K)) {
		printf("        m68k:      m68k + big endian\n");
		printf("        m68k40:    m68k_040\n");
	}

	if (cs_support(CS_ARCH_TMS320C64X)) {
		printf("        tms320c64x:TMS320C64x\n");
	}

	if (cs_support(CS_ARCH_M680X)) {
		printf("        m6800:     M6800/2\n");
		printf("        m6801:     M6801/3\n");
		printf("        m6805:     M6805\n");
		printf("        m6808:     M68HC08\n");
		printf("        m6809:     M6809\n");
		printf("        m6811:     M68HC11\n");
		printf("        cpu12:     M68HC12/HCS12\n");
		printf("        hd6301:    HD6301/3\n");
		printf("        hd6309:    HD6309\n");
		printf("        hcs08:     HCS08\n");
	}

	if (cs_support(CS_ARCH_EVM)) {
		printf("        evm:       Ethereum Virtual Machine\n");
	}

	printf("\nExtra options:\n");
	printf("        -d show detailed information of the instructions\n");
	printf("        -u show immediates as unsigned\n");
	printf("        -s decode in SKIPDATA mode\n");
	printf("        -v show version & Capstone core build info\n\n");
}

static void print_details(csh handle, cs_arch arch, cs_mode md, cs_insn *ins)
{
	switch(arch) {
		case CS_ARCH_X86:
			print_insn_detail_x86(handle, md, ins);
			break;
		case CS_ARCH_ARM:
			print_insn_detail_arm(handle, ins);
			break;
		case CS_ARCH_ARM64:
			print_insn_detail_arm64(handle, ins);
			break;
		case CS_ARCH_MIPS:
			print_insn_detail_mips(handle, ins);
			break;
		case CS_ARCH_PPC:
			print_insn_detail_ppc(handle, ins);
			break;
		case CS_ARCH_SPARC:
			print_insn_detail_sparc(handle, ins);
			break;
		case CS_ARCH_SYSZ:
			print_insn_detail_sysz(handle, ins);
			break;
		case CS_ARCH_XCORE:
			print_insn_detail_xcore(handle, ins);
			break;
		case CS_ARCH_M68K:
			print_insn_detail_m68k(handle, ins);
			break;
		case CS_ARCH_TMS320C64X:
			print_insn_detail_tms320c64x(handle, ins);
			break;
		case CS_ARCH_M680X:
			print_insn_detail_m680x(handle, ins);
			break;
		case CS_ARCH_EVM:
			print_insn_detail_evm(handle, ins);
			break;
		default: break;
	}

	if (ins->detail->groups_count) {
		int j;

		printf("\tGroups: ");
		for(j = 0; j < ins->detail->groups_count; j++) {
			printf("%s ", cs_group_name(handle, ins->detail->groups[j]));
		}
		printf("\n");
	}

	printf("\n");
}

int main(int argc, char **argv)
{
	int i, c;
	csh handle;
	char *mode;
	uint8_t *assembly;
	size_t count, size;
	uint64_t address = 0LL;
	cs_insn *insn;
	cs_err err;
	cs_mode md;
	cs_arch arch = CS_ARCH_ALL;
	bool detail_flag = false;
	bool unsigned_flag = false;
	bool skipdata = false;
	int args_left;

	while ((c = getopt (argc, argv, "sudhv")) != -1) {
		switch (c) {
			case 's':
				skipdata = true;
				break;
			case 'u':
				unsigned_flag = true;
				break;
			case 'd':
				detail_flag = true;
				break;
			case 'v':
				printf("Cstool for Capstone Disassembler Engine v%u.%u.%u\n", CS_VERSION_MAJOR, CS_VERSION_MINOR, CS_VERSION_EXTRA);

				printf("Capstone build: ");
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
			case 'h':
				usage(argv[0]);
				return 0;
			default:
				usage(argv[0]);
				return -1;
		}
	}

	args_left = argc - optind;
	if (args_left < 2 || args_left > 3) {
		usage(argv[0]);
		return -1;
	}

	mode = argv[optind];
	assembly = preprocess(argv[optind + 1], &size);
	if (!assembly) {
		usage(argv[0]);
		return -1;
	}

	if (args_left == 3) {
		char *temp, *src = argv[optind + 2];
		address = strtoull(src, &temp, 16);
		if (temp == src || *temp != '\0' || errno == ERANGE) {
			printf("ERROR: invalid address argument, quit!\n");
			return -2;
		}
	}

	for (i = 0; all_archs[i].name; i++) {
		if (!strcmp(all_archs[i].name, mode)) {
			arch = all_archs[i].arch;
			err = cs_open(all_archs[i].arch, all_archs[i].mode, &handle);
			if (!err) {
				md = all_archs[i].mode;
				if (strstr (mode, "att")) {
					cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
				}

				// turn on SKIPDATA mode
				if (skipdata)
					cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
			}
			break;
		}
	}

	if (arch == CS_ARCH_ALL) {
		printf("ERROR: Invalid <arch+mode>: \"%s\", quit!\n", mode);
		usage(argv[0]);
		return -1;
	}

	if (err) {
		printf("ERROR: Failed on cs_open(), quit!\n");
		usage(argv[0]);
		return -1;
	}

	if (detail_flag) {
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
	}

	if (unsigned_flag) {
		cs_option(handle, CS_OPT_UNSIGNED, CS_OPT_ON);
	}

	count = cs_disasm(handle, assembly, size, address, 0, &insn);
	if (count > 0) {
		size_t i;

		for (i = 0; i < count; i++) {
			int j;

			printf("%2"PRIx64"  ", insn[i].address);
			for (j = 0; j < insn[i].size; j++) {
				if (j > 0)
					putchar(' ');
				printf("%02x", insn[i].bytes[j]);
			}
			// X86 instruction size is variable.
			// align assembly instruction after the opcode
			if (arch == CS_ARCH_X86) {
				for (; j < 16; j++) {
					printf("   ");
				}
			}

			printf("  %s\t%s\n", insn[i].mnemonic, insn[i].op_str);

			if (detail_flag) {
				print_details(handle, arch, md, &insn[i]);
			}
		}

		cs_free(insn, count);
	} else {
		printf("ERROR: invalid assembly code\n");
		return(-4);
	}

	cs_close(&handle);
	free(assembly);

	return 0;
}

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <capstone.h>

struct platform {
	cs_arch arch;
	cs_mode mode;
	char *comment;
};

int main(int argc, char **argv)
{
	if (argc != 2) {
		printf("Usage: %s <testcase>\n", argv[0]);
		return 1;
	}

	struct platform platforms[] = {
		{ CS_ARCH_X86, CS_MODE_32, "X86 32 (Intel syntax)" },
		{ CS_ARCH_X86, CS_MODE_64, "X86 64 (Intel syntax)" },
		{ CS_ARCH_ARM, CS_MODE_ARM, "ARM" },
		{ CS_ARCH_ARM, CS_MODE_THUMB, "THUMB-2" },
		{ CS_ARCH_ARM, CS_MODE_ARM, "ARM: Cortex-A15 + NEON" },
		{ CS_ARCH_ARM, CS_MODE_THUMB, "THUMB" },
		{ CS_ARCH_ARM, (cs_mode)(CS_MODE_THUMB + CS_MODE_MCLASS),
		  "Thumb-MClass" },
		{ CS_ARCH_ARM, (cs_mode)(CS_MODE_ARM + CS_MODE_V8), "Arm-V8" },
		{ CS_ARCH_MIPS, (cs_mode)(CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN),
		  "MIPS-32 (Big-endian)" },
		{ CS_ARCH_MIPS,
		  (cs_mode)(CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN),
		  "MIPS-64-EL (Little-endian)" },
		{ CS_ARCH_MIPS,
		  (cs_mode)(CS_MODE_MIPS32R6 + CS_MODE_MICRO +
			    CS_MODE_BIG_ENDIAN),
		  "MIPS-32R6 | Micro (Big-endian)" },
		{ CS_ARCH_MIPS,
		  (cs_mode)(CS_MODE_MIPS32R6 + CS_MODE_BIG_ENDIAN),
		  "MIPS-32R6 (Big-endian)" },
		{ CS_ARCH_ARM64, CS_MODE_ARM, "ARM-64" },
		{ CS_ARCH_PPC, CS_MODE_BIG_ENDIAN, "PPC-64" },
		{ CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN, "Sparc" },
		{ CS_ARCH_SPARC, (cs_mode)(CS_MODE_BIG_ENDIAN + CS_MODE_V9),
		  "SparcV9" },
		{ CS_ARCH_SYSTEMZ, (cs_mode)0, "SystemZ" },
		{ CS_ARCH_XCORE, (cs_mode)0, "XCore" },
		{ CS_ARCH_M68K, (cs_mode)0, "M68K" },
		{ CS_ARCH_M680X, (cs_mode)CS_MODE_M680X_6809, "M680X_M6809" },
		{ CS_ARCH_XTENSA, (cs_mode)CS_MODE_XTENSA_ESP32,
		  "Xtensa ESP32" },
		{ CS_ARCH_XTENSA, (cs_mode)CS_MODE_XTENSA_ESP32S2,
		  "Xtensa ESP32S2" },
		{ CS_ARCH_XTENSA, (cs_mode)CS_MODE_XTENSA_ESP8266,
		  "Xtensa ESP8266" },
	};

	// Read input
	long bufsize = 0;
	unsigned char *buf = NULL;
	FILE *fp = fopen(argv[1], "r");

	if (fp == NULL)
		return 1;

	if (fseek(fp, 0L, SEEK_END) == 0) {
		bufsize = ftell(fp);

		if (bufsize == -1)
			return 1;

		buf = malloc(bufsize + 1);

		if (buf == NULL)
			return 1;
		if (fseek(fp, 0L, SEEK_SET) != 0)
			return 1;

		size_t len = fread(buf, sizeof(char), bufsize, fp);

		if (len == 0)
			return 2;
	}
	fclose(fp);

	// Disassemble
	csh handle;
	cs_insn *all_insn;
	cs_detail *detail;
	cs_err err;

	if (bufsize < 3)
		return 0;

	int platforms_len = sizeof(platforms) / sizeof(platforms[0]);
	int i = (int)buf[0] % platforms_len;

	unsigned char *buf_ptr = buf + 1;
	long buf_ptr_size = bufsize - 1;

	printf("Platform: %s (0x%.2x of 0x%.2x)\n", platforms[i].comment, i,
	       platforms_len);

	err = cs_open(platforms[i].arch, platforms[i].mode, &handle);
	if (err) {
		printf("Failed on cs_open() with error returned: %u\n", err);
		return 1;
	}

	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	uint64_t address = 0x1000;
	size_t count =
		cs_disasm(handle, buf_ptr, buf_ptr_size, address, 0, &all_insn);

	if (count) {
		size_t j;
		int n;

		printf("Disasm:\n");

		for (j = 0; j < count; j++) {
			cs_insn *i = &(all_insn[j]);
			printf("0x%" PRIx64
			       ":\t%s\t\t%s // insn-ID: %u, insn-mnem: %s\n",
			       i->address, i->mnemonic, i->op_str, i->id,
			       cs_insn_name(handle, i->id));

			detail = i->detail;

			if (detail->regs_read_count > 0) {
				printf("\tImplicit registers read: ");
				for (n = 0; n < detail->regs_read_count; n++) {
					printf("%s ",
					       cs_reg_name(
						       handle,
						       detail->regs_read[n]));
				}
				printf("\n");
			}

			if (detail->regs_write_count > 0) {
				printf("\tImplicit registers modified: ");
				for (n = 0; n < detail->regs_write_count; n++) {
					printf("%s ",
					       cs_reg_name(
						       handle,
						       detail->regs_write[n]));
				}
				printf("\n");
			}

			if (detail->groups_count > 0) {
				printf("\tThis instruction belongs to groups: ");
				for (n = 0; n < detail->groups_count; n++) {
					printf("%s ",
					       cs_group_name(handle,
							     detail->groups[n]));
				}
				printf("\n");
			}
		}
		printf("0x%" PRIx64 ":\n",
		       all_insn[j - 1].address + all_insn[j - 1].size);
		cs_free(all_insn, count);
	} else {
		printf("ERROR: Failed to disasm given code!\n");
	}

	printf("\n");

	free(buf);
	cs_close(&handle);

	return 0;
}

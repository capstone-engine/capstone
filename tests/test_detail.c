/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#include <stdio.h>
#include <stdlib.h>

#include <capstone/platform.h>
#include <capstone/capstone.h>

struct platform {
	cs_arch arch;
	cs_mode mode;
	unsigned char *code;
	size_t size;
	const char *comment;
	cs_opt_type opt_type;
	cs_opt_value opt_value;
};

static void print_string_hex(unsigned char *str, size_t len)
{
	unsigned char *c;

	printf("Code: ");
	for (c = str; c < str + len; c++) {
		printf("0x%02x ", *c & 0xff);
	}
	printf("\n");
}

static void test()
{
#ifdef CAPSTONE_HAS_X86
#define X86_CODE16 "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00"
#define X86_CODE32 "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00"
#define X86_CODE64 "\x55\x48\x8b\x05\xb8\x13\x00\x00"
#endif
#ifdef CAPSTONE_HAS_ARM
#define ARM_CODE "\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3"
#define ARM_CODE2 "\x10\xf1\x10\xe7\x11\xf2\x31\xe7\xdc\xa1\x2e\xf3\xe8\x4e\x62\xf3"
#define THUMB_CODE "\x70\x47\xeb\x46\x83\xb0\xc9\x68"
#define THUMB_CODE2 "\x4f\xf0\x00\x01\xbd\xe8\x00\x88\xd1\xe8\x00\xf0"
#define THUMB_MCLASS "\xef\xf3\x02\x80"
#define ARMV8 "\xe0\x3b\xb2\xee\x42\x00\x01\xe1\x51\xf0\x7f\xf5"
#endif
#ifdef CAPSTONE_HAS_MIPS
#define MIPS_CODE "\x0C\x10\x00\x97\x00\x00\x00\x00\x24\x02\x00\x0c\x8f\xa2\x00\x00\x34\x21\x34\x56\x00\x80\x04\x08"
#define MIPS_CODE2 "\x56\x34\x21\x34\xc2\x17\x01\x00"
#define MIPS_32R6M "\x00\x07\x00\x07\x00\x11\x93\x7c\x01\x8c\x8b\x7c\x00\xc7\x48\xd0"
#define MIPS_32R6 "\xec\x80\x00\x19\x7c\x43\x22\xa0"
#endif
#ifdef CAPSTONE_HAS_AARCH64
#define AARCH64_CODE "\x09\x00\x38\xd5\xbf\x40\x00\xd5\x0c\x05\x13\xd5\x20\x50\x02\x0e\x20\xe4\x3d\x0f\x00\x18\xa0\x5f\xa2\x00\xae\x9e\x9f\x37\x03\xd5\xbf\x33\x03\xd5\xdf\x3f\x03\xd5\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9\x20\x04\x81\xda\x20\x08\x02\x8b\x10\x5b\xe8\x3c"
#endif
#ifdef CAPSTONE_HAS_POWERPC
#define PPC_CODE "\x80\x20\x00\x00\x80\x3f\x00\x00\x10\x43\x23\x0e\xd0\x44\x00\x80\x4c\x43\x22\x02\x2d\x03\x00\x80\x7c\x43\x20\x14\x7c\x43\x20\x93\x4f\x20\x00\x21\x4c\xc8\x00\x21\x40\x82\x00\x14"
#define PPC_CODE2 "\x10\x60\x2a\x10\x10\x64\x28\x88\x7c\x4a\x5d\x0f"
#endif
#ifdef CAPSTONE_HAS_SPARC
#define SPARC_CODE "\x80\xa0\x40\x02\x85\xc2\x60\x08\x85\xe8\x20\x01\x81\xe8\x00\x00\x90\x10\x20\x01\xd5\xf6\x10\x16\x21\x00\x00\x0a\x86\x00\x40\x02\x01\x00\x00\x00\x12\xbf\xff\xff\x10\xbf\xff\xff\xa0\x02\x00\x09\x0d\xbf\xff\xff\xd4\x20\x60\x00\xd4\x4e\x00\x16\x2a\xc2\x80\x03"
#define SPARCV9_CODE "\x81\xa8\x0a\x24\x89\xa0\x10\x20\x89\xa0\x1a\x60\x89\xa0\x00\xe0"
#endif
#ifdef CAPSTONE_HAS_SYSZ
#define SYSZ_CODE "\xed\x00\x00\x00\x00\x1a\x5a\x0f\x1f\xff\xc2\x09\x80\x00\x00\x00\x07\xf7\xeb\x2a\xff\xff\x7f\x57\xe3\x01\xff\xff\x7f\x57\xeb\x00\xf0\x00\x00\x24\xb2\x4f\x00\x78"
#endif
#ifdef CAPSTONE_HAS_XCORE
#define XCORE_CODE "\xfe\x0f\xfe\x17\x13\x17\xc6\xfe\xec\x17\x97\xf8\xec\x4f\x1f\xfd\xec\x37\x07\xf2\x45\x5b\xf9\xfa\x02\x06\x1b\x10"
#endif
#ifdef CAPSTONE_HAS_M68K
#define M68K_CODE "\xd4\x40\x87\x5a\x4e\x71\x02\xb4\xc0\xde\xc0\xde\x5c\x00\x1d\x80\x71\x12\x01\x23\xf2\x3c\x44\x22\x40\x49\x0e\x56\x54\xc5\xf2\x3c\x44\x00\x44\x7a\x00\x00\xf2\x00\x0a\x28\x4E\xB9\x00\x00\x00\x12\x4E\x75"
#endif
#ifdef CAPSTONE_HAS_M680X
#define M680X_CODE "\x06\x10\x19\x1a\x55\x1e\x01\x23\xe9\x31\x06\x34\x55\xa6\x81\xa7\x89\x7f\xff\xa6\x9d\x10\x00\xa7\x91\xa6\x9f\x10\x00\x11\xac\x99\x10\x00\x39"
#endif
#ifdef CAPSTONE_HAS_MOS65XX
#define MOS65XX_CODE "\x0A\x00\xFE\x34\x12\xD0\xFF\xEA\x19\x56\x34\x46\x80"
#endif
#ifdef CAPSTONE_HAS_BPF
#define EBPF_CODE "\x97\x09\x00\x00\x37\x13\x03\x00\xdc\x02\x00\x00\x20\x00\x00\x00\x30\x00\x00\x00\x00\x00\x00\x00\xdb\x3a\x00\x01\x00\x00\x00\x00\x84\x02\x00\x00\x00\x00\x00\x00\x6d\x33\x17\x02\x00\x00\x00\x00"
#endif
#ifdef CAPSTONE_HAS_ALPHA
#define ALPHA_CODE "\x02\x00\xbb\x27\x50\x7a\xbd\x23\xd0\xff\xde\x23\x00\x00\x5e\xb7"
#define ALPHA_CODE_BE "\x27\xbb\x00\x02\x23\xbd\x7a\x50\x23\xde\xff\xd0\xb7\x5e\x00\x00"
#endif

	struct platform platforms[] = {
#ifdef CAPSTONE_HAS_X86
		{
			CS_ARCH_X86,
			CS_MODE_16,
			(unsigned char *)X86_CODE16,
			sizeof(X86_CODE16) - 1,
			"X86 16bit (Intel syntax)"
		},
		{
			CS_ARCH_X86,
			CS_MODE_32,
			(unsigned char *)X86_CODE32,
			sizeof(X86_CODE32) - 1,
			"X86 32bit (ATT syntax)",
			CS_OPT_SYNTAX,
			CS_OPT_SYNTAX_ATT,
		},
		{
			CS_ARCH_X86,
			CS_MODE_32,
			(unsigned char *)X86_CODE32,
			sizeof(X86_CODE32) - 1,
			"X86 32 (Intel syntax)"
		},
		{
			CS_ARCH_X86,
			CS_MODE_64,
			(unsigned char *)X86_CODE64,
			sizeof(X86_CODE64) - 1,
			"X86 64 (Intel syntax)"
		},
#endif
#ifdef CAPSTONE_HAS_ARM
		{
			CS_ARCH_ARM,
			CS_MODE_ARM,
			(unsigned char *)ARM_CODE,
			sizeof(ARM_CODE) - 1,
			"ARM"
		},
		{
			CS_ARCH_ARM,
			CS_MODE_ARM,
			(unsigned char *)ARM_CODE2,
			sizeof(ARM_CODE2) - 1,
			"ARM: Cortex-A15 + NEON"
		},
		{
			CS_ARCH_ARM,
			CS_MODE_THUMB,
			(unsigned char *)THUMB_CODE,
			sizeof(THUMB_CODE) - 1,
			"THUMB"
		},
		{
			CS_ARCH_ARM,
			CS_MODE_THUMB,
			(unsigned char *)THUMB_CODE2,
			sizeof(THUMB_CODE2) - 1,
			"THUMB-2"
		},
		{
			CS_ARCH_ARM,
			(cs_mode)(CS_MODE_THUMB + CS_MODE_MCLASS),
			(unsigned char*)THUMB_MCLASS,
			sizeof(THUMB_MCLASS) - 1,
			"Thumb-MClass"
		},
		{
			CS_ARCH_ARM,
			(cs_mode)(CS_MODE_ARM + CS_MODE_V8),
			(unsigned char*)ARMV8,
			sizeof(ARMV8) - 1,
			"Arm-V8"
		},
#endif
#ifdef CAPSTONE_HAS_AARCH64
		{
			CS_ARCH_AARCH64,
			CS_MODE_ARM,
			(unsigned char *)AARCH64_CODE,
			sizeof(AARCH64_CODE) - 1,
			"AARCH64"
		},
#endif
#ifdef CAPSTONE_HAS_MIPS
		{
			CS_ARCH_MIPS,
			(cs_mode)(CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN),
			(unsigned char *)MIPS_CODE,
			sizeof(MIPS_CODE) - 1,
			"MIPS-32 (Big-endian)"
		},
		{
			CS_ARCH_MIPS,
			(cs_mode)(CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN),
			(unsigned char *)MIPS_CODE2,
			sizeof(MIPS_CODE2) - 1,
			"MIPS-64-EL (Little-endian)"
		},
		{
			CS_ARCH_MIPS,
			(cs_mode)(CS_MODE_MIPS32R6 + CS_MODE_MICRO + CS_MODE_BIG_ENDIAN),
			(unsigned char*)MIPS_32R6M,
			sizeof(MIPS_32R6M) - 1,
			"MIPS-32R6 | Micro (Big-endian)"
		},
		{
			CS_ARCH_MIPS,
			(cs_mode)(CS_MODE_MIPS32R6 + CS_MODE_BIG_ENDIAN),
			(unsigned char*)MIPS_32R6,
			sizeof(MIPS_32R6) - 1,
			"MIPS-32R6 (Big-endian)"
		},
#endif
#ifdef CAPSTONE_HAS_POWERPC
		{
			CS_ARCH_PPC,
			CS_MODE_BIG_ENDIAN,
			(unsigned char*)PPC_CODE,
			sizeof(PPC_CODE) - 1,
			"PPC-64"
		},
		{
			CS_ARCH_PPC,
			CS_MODE_BIG_ENDIAN + CS_MODE_QPX,
			(unsigned char*)PPC_CODE2,
			sizeof(PPC_CODE2) - 1,
			"PPC-64 + QPX",
		},
#endif
#ifdef CAPSTONE_HAS_SPARC
		{
			CS_ARCH_SPARC,
			CS_MODE_BIG_ENDIAN,
			(unsigned char*)SPARC_CODE,
			sizeof(SPARC_CODE) - 1,
			"Sparc"
		},
		{
			CS_ARCH_SPARC,
			(cs_mode)(CS_MODE_BIG_ENDIAN + CS_MODE_V9),
			(unsigned char*)SPARCV9_CODE,
			sizeof(SPARCV9_CODE) - 1,
			"SparcV9"
		},
#endif
#ifdef CAPSTONE_HAS_SYSZ
		{
			CS_ARCH_SYSZ,
			(cs_mode)0,
			(unsigned char*)SYSZ_CODE,
			sizeof(SYSZ_CODE) - 1,
			"SystemZ"
		},
#endif
#ifdef CAPSTONE_HAS_XCORE
		{
			CS_ARCH_XCORE,
			(cs_mode)0,
			(unsigned char*)XCORE_CODE,
			sizeof(XCORE_CODE) - 1,
			"XCore"
		},
#endif
#ifdef CAPSTONE_HAS_M68K
		{
			CS_ARCH_M68K,
			(cs_mode)(CS_MODE_BIG_ENDIAN | CS_MODE_M68K_040),
			(unsigned char*)M68K_CODE,
			sizeof(M68K_CODE) - 1,
			"M68K",
		},
#endif
#ifdef CAPSTONE_HAS_M680X
		{
			CS_ARCH_M680X,
			(cs_mode)(CS_MODE_M680X_6809),
			(unsigned char*)M680X_CODE,
			sizeof(M680X_CODE) - 1,
			"M680X_M6809",
		},
#endif
#ifdef CAPSTONE_HAS_MOS65XX
		{
				CS_ARCH_MOS65XX,
				(cs_mode)0,
				(unsigned char*)MOS65XX_CODE,
				sizeof(MOS65XX_CODE) - 1,
				"MOS65XX",
		},
#endif
#ifdef CAPSTONE_HAS_BPF
		{
			CS_ARCH_BPF,
			CS_MODE_LITTLE_ENDIAN | CS_MODE_BPF_EXTENDED,
			(unsigned char*) EBPF_CODE,
			sizeof(EBPF_CODE) - 1,
			"eBPF"
		},
#endif
#ifdef CAPSTONE_HAS_ALPHA
		{
			CS_ARCH_ALPHA,
			CS_MODE_LITTLE_ENDIAN,
			(unsigned char*)ALPHA_CODE,
			sizeof(ALPHA_CODE) - 1,
			"Alpha (Little-endian)"
		},
		{
			CS_ARCH_ALPHA,
			CS_MODE_BIG_ENDIAN,
			(unsigned char*)ALPHA_CODE_BE,
			sizeof(ALPHA_CODE) - 1,
			"Alpha (Big-endian)"
		},
#endif
	};

	csh handle;
	uint64_t address = 0x1000;
	cs_insn *all_insn;
	cs_detail *detail;
	int i;
	size_t count;
	cs_err err;

	for (i = 0; i < sizeof(platforms)/sizeof(platforms[0]); i++) {
		printf("****************\n");
		printf("Platform: %s\n", platforms[i].comment);
		err = cs_open(platforms[i].arch, platforms[i].mode, &handle);
		if (err) {
			printf("Failed on cs_open() with error returned: %u\n", err);
			abort();
		}

		if (platforms[i].opt_type)
			cs_option(handle, platforms[i].opt_type, platforms[i].opt_value);

		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

		count = cs_disasm(handle, platforms[i].code, platforms[i].size, address, 0, &all_insn);
		if (count) {
			size_t j;
			int n;

			print_string_hex(platforms[i].code, platforms[i].size);
			printf("Disasm:\n");

			for (j = 0; j < count; j++) {
				cs_insn *in = &(all_insn[j]);
				printf("0x%" PRIx64 ":\t%s\t\t%s // insn-ID: %u, insn-mnem: %s\n",
						in->address, in->mnemonic, in->op_str,
						in->id, cs_insn_name(handle, in->id));

				// print implicit registers used by this instruction
				detail = in->detail;

				if (detail->regs_read_count > 0) {
					printf("\tImplicit registers read: ");
					for (n = 0; n < detail->regs_read_count; n++) {
						printf("%s ", cs_reg_name(handle, detail->regs_read[n]));
					}
					printf("\n");
				}

				// print implicit registers modified by this instruction
				if (detail->regs_write_count > 0) {
					printf("\tImplicit registers modified: ");
					for (n = 0; n < detail->regs_write_count; n++) {
						printf("%s ", cs_reg_name(handle, detail->regs_write[n]));
					}
					printf("\n");
				}

				// print the groups this instruction belong to
				if (detail->groups_count > 0) {
					printf("\tThis instruction belongs to groups: ");
					for (n = 0; n < detail->groups_count; n++) {
						printf("%s ", cs_group_name(handle, detail->groups[n]));
					}
					printf("\n");
				}
			}

			// print out the next offset, after the last insn
			printf("0x%" PRIx64 ":\n", all_insn[j-1].address + all_insn[j-1].size);

			// free memory allocated by cs_disasm()
			cs_free(all_insn, count);
		} else {
			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex(platforms[i].code, platforms[i].size);
			printf("ERROR: Failed to disasm given code!\n");
			abort();
		}

		printf("\n");

		cs_close(&handle);
	}
}

int main()
{
	test();

	return 0;
}

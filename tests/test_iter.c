/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013 */

// This sample code demonstrates the APIs cs_malloc() & cs_disasm_iter().
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
//#define X86_CODE32 "\x0f\xa7\xc0"	// xstorerng
#define X86_CODE64 "\x55\x48\x8b\x05\xb8\x13\x00\x00"
#endif
#ifdef CAPSTONE_HAS_ARM
//#define ARM_CODE "\x04\xe0\x2d\xe5"
#define ARM_CODE "\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3"
#define ARM_CODE2 "\x10\xf1\x10\xe7\x11\xf2\x31\xe7\xdc\xa1\x2e\xf3\xe8\x4e\x62\xf3"
#define THUMB_CODE "\x70\x47\xeb\x46\x83\xb0\xc9\x68"
#define THUMB_CODE2 "\x4f\xf0\x00\x01\xbd\xe8\x00\x88\xd1\xe8\x00\xf0"
#endif
#ifdef CAPSTONE_HAS_MIPS
#define MIPS_CODE "\x0C\x10\x00\x97\x00\x00\x00\x00\x24\x02\x00\x0c\x8f\xa2\x00\x00\x34\x21\x34\x56\x00\x80\x04\x08"
//#define MIPS_CODE "\x21\x38\x00\x01"
//#define MIPS_CODE "\x21\x30\xe6\x70"
//#define MIPS_CODE "\x1c\x00\x40\x14"
#define MIPS_CODE2 "\x56\x34\x21\x34\xc2\x17\x01\x00"
#endif
#ifdef CAPSTONE_HAS_ARM64
//#define ARM64_CODE "\xe1\x0b\x40\xb9"	// ldr		w1, [sp, #0x8]
//#define ARM64_CODE "\x00\x40\x21\x4b"	// 	sub		w0, w0, w1, uxtw
//#define ARM64_CODE "\x21\x7c\x02\x9b"	// mul	x1, x1, x2
//#define ARM64_CODE "\x20\x74\x0b\xd5"	// dc	zva, x0
//#define ARM64_CODE "\x20\xfc\x02\x9b"	// mneg	x0, x1, x2
//#define ARM64_CODE "\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9\x10\x20\x21\x1e"
//#define ARM64_CODE "\x21\x7c\x00\x53"
#define ARM64_CODE "\x09\x00\x38\xd5\xbf\x40\x00\xd5\x0c\x05\x13\xd5\x20\x50\x02\x0e\x20\xe4\x3d\x0f\x00\x18\xa0\x5f\xa2\x00\xae\x9e\x9f\x37\x03\xd5\xbf\x33\x03\xd5\xdf\x3f\x03\xd5\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9\x20\x04\x81\xda\x20\x08\x02\x8b\x10\x5b\xe8\x3c"
#endif
//#define THUMB_CODE "\x0a\xbf" // itet eq
//#define X86_CODE32 "\x77\x04"	// ja +6
#ifdef CAPSTONE_HAS_POWERPC
#define PPC_CODE "\x80\x20\x00\x00\x80\x3f\x00\x00\x10\x43\x23\x0e\xd0\x44\x00\x80\x4c\x43\x22\x02\x2d\x03\x00\x80\x7c\x43\x20\x14\x7c\x43\x20\x93\x4f\x20\x00\x21\x4c\xc8\x00\x21\x40\x82\x00\x14"
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
#ifdef CAPSTONE_HAS_M680X
#define M680X_CODE "\x06\x10\x19\x1a\x55\x1e\x01\x23\xe9\x31\x06\x34\x55\xa6\x81\xa7\x89\x7f\xff\xa6\x9d\x10\x00\xa7\x91\xa6\x9f\x10\x00\x11\xac\x99\x10\x00\x39"
#endif

	struct platform platforms[] = {
#ifdef CAPSTONE_HAS_X86
		{
			CS_ARCH_X86,
			CS_MODE_16,
			(unsigned char *)X86_CODE16,
			sizeof(X86_CODE32) - 1,
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
			CS_MODE_THUMB,
			(unsigned char *)THUMB_CODE2,
			sizeof(THUMB_CODE2) - 1,
			"THUMB-2"
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
#endif
#ifdef CAPSTONE_HAS_ARM64
		{
			CS_ARCH_ARM64,
			CS_MODE_ARM,
			(unsigned char *)ARM64_CODE,
			sizeof(ARM64_CODE) - 1,
			"ARM-64"
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
#ifdef CAPSTONE_HAS_M680X
		{
			CS_ARCH_M680X,
			(cs_mode)CS_MODE_M680X_6809,
			(unsigned char*)M680X_CODE,
			sizeof(M680X_CODE) - 1,
			"M680X_6809"
		},
#endif
	};

	csh handle;
	uint64_t address;
	cs_insn *insn;
	cs_detail *detail;
	int i;
	cs_err err;
	const uint8_t *code;
	size_t size;

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

		// allocate memory for the cache to be used by cs_disasm_iter()
		insn = cs_malloc(handle);

		print_string_hex(platforms[i].code, platforms[i].size);
		printf("Disasm:\n");

		address = 0x1000;
		code = platforms[i].code;
		size = platforms[i].size;
		while(cs_disasm_iter(handle, &code, &size, &address, insn)) {
			int n;

			printf("0x%" PRIx64 ":\t%s\t\t%s // insn-ID: %u, insn-mnem: %s\n",
					insn->address, insn->mnemonic, insn->op_str,
					insn->id, cs_insn_name(handle, insn->id));

			// print implicit registers used by this instruction
			detail = insn->detail;

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

		printf("\n");

		// free memory allocated by cs_malloc()
		cs_free(insn, 1);

		cs_close(&handle);
	}
}

int main()
{
	test();

	return 0;
}

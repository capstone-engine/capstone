/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#include <stdio.h>
#include <stdlib.h>

#include <platform.h>
#include <capstone.h>

struct platform {
	cs_arch arch;
	cs_mode mode;
	unsigned char *code;
	size_t size;
	char *comment;
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
#define X86_CODE16 "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00"
#define X86_CODE32 "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00"
//#define X86_CODE32 "\x0f\xa7\xc0"	// xstorerng
#define X86_CODE64 "\x55\x48\x8b\x05\xb8\x13\x00\x00"
//#define ARM_CODE "\x04\xe0\x2d\xe5"
#define ARM_CODE "\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3"
#define ARM_CODE2 "\x10\xf1\x10\xe7\x11\xf2\x31\xe7\xdc\xa1\x2e\xf3\xe8\x4e\x62\xf3"
#define ARMV8 "\xe0\x3b\xb2\xee\x42\x00\x01\xe1\x51\xf0\x7f\xf5"
#define THUMB_MCLASS "\xef\xf3\x02\x80"
#define THUMB_CODE "\x70\x47\xeb\x46\x83\xb0\xc9\x68"
#define THUMB_CODE2 "\x4f\xf0\x00\x01\xbd\xe8\x00\x88\xd1\xe8\x00\xf0"
#define MIPS_CODE "\x0C\x10\x00\x97\x00\x00\x00\x00\x24\x02\x00\x0c\x8f\xa2\x00\x00\x34\x21\x34\x56"
#define MIPS_CODE2 "\x56\x34\x21\x34\xc2\x17\x01\x00"
#define MIPS_32R6M "\x00\x07\x00\x07\x00\x11\x93\x7c\x01\x8c\x8b\x7c\x00\xc7\x48\xd0"
#define MIPS_32R6 "\xec\x80\x00\x19\x7c\x43\x22\xa0"
//#define ARM64_CODE "\x00\x40\x21\x4b"	// 	sub		w0, w0, w1, uxtw
//#define ARM64_CODE "\x21\x7c\x02\x9b"	// mul	x1, x1, x2
//#define ARM64_CODE "\x20\x74\x0b\xd5"	// dc	zva, x0
//#define ARM64_CODE "\xe1\x0b\x40\xb9"	// ldr		w1, [sp, #0x8]
#define ARM64_CODE "\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9"
#define PPC_CODE "\x80\x20\x00\x00\x80\x3f\x00\x00\x10\x43\x23\x0e\xd0\x44\x00\x80\x4c\x43\x22\x02\x2d\x03\x00\x80\x7c\x43\x20\x14\x7c\x43\x20\x93\x4f\x20\x00\x21\x4c\xc8\x00\x21"
#define SPARC_CODE "\x80\xa0\x40\x02\x85\xc2\x60\x08\x85\xe8\x20\x01\x81\xe8\x00\x00\x90\x10\x20\x01\xd5\xf6\x10\x16\x21\x00\x00\x0a\x86\x00\x40\x02\x01\x00\x00\x00\x12\xbf\xff\xff\x10\xbf\xff\xff\xa0\x02\x00\x09\x0d\xbf\xff\xff\xd4\x20\x60\x00\xd4\x4e\x00\x16\x2a\xc2\x80\x03"
#define SPARCV9_CODE "\x81\xa8\x0a\x24\x89\xa0\x10\x20\x89\xa0\x1a\x60\x89\xa0\x00\xe0"
#define SYSZ_CODE "\xed\x00\x00\x00\x00\x1a\x5a\x0f\x1f\xff\xc2\x09\x80\x00\x00\x00\x07\xf7\xeb\x2a\xff\xff\x7f\x57\xe3\x01\xff\xff\x7f\x57\xeb\x00\xf0\x00\x00\x24\xb2\x4f\x00\x78"
#define XCORE_CODE "\xfe\x0f\xfe\x17\x13\x17\xc6\xfe\xec\x17\x97\xf8\xec\x4f\x1f\xfd\xec\x37\x07\xf2\x45\x5b\xf9\xfa\x02\x06\x1b\x10"
	struct platform {
		cs_arch arch;
		cs_mode mode;
		unsigned char *code;
		size_t size;
		char *comment;
		cs_opt_type opt_type;
		cs_opt_value opt_value;
	};
	struct platform platforms[] = {
		{ 
			CS_ARCH_X86,
			CS_MODE_16,
			(unsigned char*)X86_CODE16,
			sizeof(X86_CODE16) - 1,
			"X86 16bit (Intel syntax)"
		},
		{
			CS_ARCH_X86,
			CS_MODE_32,
			(unsigned char*)X86_CODE32,
			sizeof(X86_CODE32) - 1,
			"X86 32bit (ATT syntax)",
			CS_OPT_SYNTAX,
			CS_OPT_SYNTAX_ATT,
		},
		{
			CS_ARCH_X86,
			CS_MODE_32,
			(unsigned char*)X86_CODE32,
			sizeof(X86_CODE32) - 1,
			"X86 32 (Intel syntax)"
		},
		{
			CS_ARCH_X86,
			CS_MODE_64,
			(unsigned char*)X86_CODE64,
			sizeof(X86_CODE64) - 1,
			"X86 64 (Intel syntax)"
		},
		{ 
			CS_ARCH_ARM,
			CS_MODE_ARM,
			(unsigned char*)ARM_CODE,
			sizeof(ARM_CODE) - 1,
			"ARM"
		},
		{
			CS_ARCH_ARM,
			CS_MODE_THUMB,
			(unsigned char*)THUMB_CODE2,
			sizeof(THUMB_CODE2) - 1,
			"THUMB-2"
		},
		{ 
			CS_ARCH_ARM,
			CS_MODE_ARM,
			(unsigned char*)ARM_CODE2,
			sizeof(ARM_CODE2) - 1,
			"ARM: Cortex-A15 + NEON"
		},
		{
			CS_ARCH_ARM,
			CS_MODE_THUMB,
			(unsigned char*)THUMB_CODE,
			sizeof(THUMB_CODE) - 1,
			"THUMB"
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
		{
			CS_ARCH_MIPS,
			(cs_mode)(CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN),
			(unsigned char*)MIPS_CODE,
			sizeof(MIPS_CODE) - 1,
			"MIPS-32 (Big-endian)"
		},
		{
			CS_ARCH_MIPS,
			(cs_mode)(CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN),
			(unsigned char*)MIPS_CODE2,
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
		{
			CS_ARCH_ARM64,
			CS_MODE_ARM,
			(unsigned char*)ARM64_CODE,
			sizeof(ARM64_CODE) - 1,
			"ARM-64"
		},
		{
			CS_ARCH_PPC,
			CS_MODE_BIG_ENDIAN,
			(unsigned char*)PPC_CODE,
			sizeof(PPC_CODE) - 1,
			"PPC-64"
		},
		{
			CS_ARCH_PPC,
			CS_MODE_BIG_ENDIAN,
			(unsigned char*)PPC_CODE,
			sizeof(PPC_CODE) - 1,
			"PPC-64, print register with number only",
			CS_OPT_SYNTAX,
			CS_OPT_SYNTAX_NOREGNAME
		},
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
		{
			CS_ARCH_SYSZ,
			(cs_mode)0,
			(unsigned char*)SYSZ_CODE,
			sizeof(SYSZ_CODE) - 1,
			"SystemZ"
		},
		{
			CS_ARCH_XCORE,
			(cs_mode)0,
			(unsigned char*)XCORE_CODE,
			sizeof(XCORE_CODE) - 1,
			"XCore"
		},
	};

	csh handle;
	uint64_t address = 0x1000;
	cs_insn *insn;
	int i;
	size_t count;
	cs_err err;

	for (i = 0; i < sizeof(platforms)/sizeof(platforms[0]); i++) {
		printf("****************\n");
		printf("Platform: %s\n", platforms[i].comment);
		err = cs_open(platforms[i].arch, platforms[i].mode, &handle);
		if (err) {
			printf("Failed on cs_open() with error returned: %u\n", err);
			continue;
		}

		if (platforms[i].opt_type)
			cs_option(handle, platforms[i].opt_type, platforms[i].opt_value);

		count = cs_disasm(handle, platforms[i].code, platforms[i].size, address, 0, &insn);
		if (count) {
			size_t j;

			print_string_hex(platforms[i].code, platforms[i].size);
			printf("Disasm:\n");

			for (j = 0; j < count; j++) {
				printf("0x%" PRIx64 ":\t%s\t\t%s\n",
						insn[j].address, insn[j].mnemonic, insn[j].op_str);
			}

			// print out the next offset, after the last insn
			printf("0x%" PRIx64 ":\n", insn[j-1].address + insn[j-1].size);

			// free memory allocated by cs_disasm()
			cs_free(insn, count);
		} else {
			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex(platforms[i].code, platforms[i].size);
			printf("ERROR: Failed to disasm given code!\n");
		}

		printf("\n");

		cs_close(&handle);
	}
}

int main()
{
	test();

#if 0
#define offsetof(st, m) __builtin_offsetof(st, m)

	cs_insn insn;
	printf("size: %lu\n", sizeof(insn));
	printf("@id: %lu\n", offsetof(cs_insn, id));
	printf("@address: %lu\n", offsetof(cs_insn, address));
	printf("@size: %lu\n", offsetof(cs_insn, size));
	printf("@bytes: %lu\n", offsetof(cs_insn, bytes));
	printf("@mnemonic: %lu\n", offsetof(cs_insn, mnemonic));
	printf("@op_str: %lu\n", offsetof(cs_insn, op_str));
	printf("@regs_read: %lu\n", offsetof(cs_insn, regs_read));
	printf("@regs_read_count: %lu\n", offsetof(cs_insn, regs_read_count));
	printf("@regs_write: %lu\n", offsetof(cs_insn, regs_write));
	printf("@regs_write_count: %lu\n", offsetof(cs_insn, regs_write_count));
	printf("@groups: %lu\n", offsetof(cs_insn, groups));
	printf("@groups_count: %lu\n", offsetof(cs_insn, groups_count));
	printf("@arch: %lu\n", offsetof(cs_insn, x86));
#endif

	return 0;
}

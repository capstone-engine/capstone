/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013 */

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
	cs_opt_type opt_skipdata;
	size_t skipdata;
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

#ifdef CAPSTONE_HAS_ARM
static size_t CAPSTONE_API mycallback(const uint8_t *buffer, size_t buffer_size, size_t offset, void *p)
{
	// always skip 2 bytes when encountering data
	return 2;
}
#endif

static void test()
{
#ifdef CAPSTONE_HAS_X86
#define X86_CODE32 "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x00\x91\x92"
#endif
#define RANDOM_CODE "\xed\x00\x00\x00\x00\x1a\x5a\x0f\x1f\xff\xc2\x09\x80\x00\x00\x00\x07\xf7\xeb\x2a\xff\xff\x7f\x57\xe3\x01\xff\xff\x7f\x57\xeb\x00\xf0\x00\x00\x24\xb2\x4f\x00\x78"

#if defined(CAPSTONE_HAS_X86)
	cs_opt_skipdata skipdata = {
		// rename default "data" instruction from ".byte" to "db"
		"db",
	};
#endif

#ifdef CAPSTONE_HAS_ARM
	cs_opt_skipdata skipdata_callback = {
		"db",
		&mycallback,
	};
#endif

	struct platform platforms[] = {
#ifdef CAPSTONE_HAS_X86
		{
			CS_ARCH_X86,
			CS_MODE_32,
			(unsigned char*)X86_CODE32,
			sizeof(X86_CODE32) - 1,
			"X86 32 (Intel syntax) - Skip data",
		},
		{
			CS_ARCH_X86,
			CS_MODE_32,
			(unsigned char*)X86_CODE32,
			sizeof(X86_CODE32) - 1,
			"X86 32 (Intel syntax) - Skip data with custom mnemonic",
			CS_OPT_INVALID,
			CS_OPT_OFF,
			CS_OPT_SKIPDATA_SETUP,
			(size_t) &skipdata,
		},
#endif
#ifdef CAPSTONE_HAS_ARM
		{
			CS_ARCH_ARM,
			CS_MODE_ARM,
			(unsigned char*)RANDOM_CODE,
			sizeof(RANDOM_CODE) - 1,
			"Arm - Skip data",
		},
		{
			CS_ARCH_ARM,
			CS_MODE_ARM,
			(unsigned char*)RANDOM_CODE,
			sizeof(RANDOM_CODE) - 1,
			"Arm - Skip data with callback",
			CS_OPT_INVALID,
			CS_OPT_OFF,
			CS_OPT_SKIPDATA_SETUP,
			(size_t) &skipdata_callback,
		},
#endif
	};

	csh handle;
	uint64_t address = 0x1000;
	cs_insn *insn;
	cs_err err;
	int i;
	size_t count;

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

		// turn on SKIPDATA mode
		cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
		cs_option(handle, platforms[i].opt_skipdata, platforms[i].skipdata);

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
			abort();
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

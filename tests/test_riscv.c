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
};

static csh handle;

static void print_string_hex(const char *comment, unsigned char *str, size_t len)
{
	unsigned char *c;

	printf("%s", comment);
	for (c = str; c < str + len; c++) {
		printf("0x%02x ", *c & 0xff);
	}

	printf("\n");
}

static void print_insn_detail(cs_insn *ins)
{
	int i;
	int n;
	cs_riscv *riscv;
	cs_detail *detail;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	riscv = &(ins->detail->riscv);
	detail = ins->detail;
	if (riscv->op_count)
		printf("\top_count: %u\n", riscv->op_count);

	for (i = 0; i < riscv->op_count; i++) {
		cs_riscv_op *op = &(riscv->operands[i]);
		switch((int)op->type) {
			default:
				printf("\terror in opt_type: %u\n", (int)op->type);
				break;
			case RISCV_OP_REG:
				printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case RISCV_OP_IMM:
				printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "\n", i, op->imm);
				break;
			case RISCV_OP_MEM:
				printf("\t\toperands[%u].type: MEM\n", i);
				if (op->mem.base != RISCV_REG_INVALID)
					printf("\t\t\toperands[%u].mem.base: REG = %s\n",
							i, cs_reg_name(handle, op->mem.base));
				if (op->mem.disp != 0)
					printf("\t\t\toperands[%u].mem.disp: 0x%" PRIx64 "\n", i, op->mem.disp);

				break;
		}

		switch(op->access) {
			default:
				break;
			case CS_AC_READ:
				printf("\t\toperands[%u].access: READ\n", i);
				break;
			case CS_AC_WRITE:
				printf("\t\toperands[%u].access: WRITE\n", i);
				break;
			case CS_AC_READ | CS_AC_WRITE:
				printf("\t\toperands[%u].access: READ | WRITE\n", i);
				break;
		}

	}
	
	//print the groups this instruction belongs to
	if (detail->groups_count > 0) {
		printf("\tgroups: ");
		for (n = 0; n < detail->groups_count; n++) {
			printf("%s ", cs_group_name(handle, detail->groups[n]));
		}
		printf("\n");
	}

	printf("\n");
}

static void test()
{
#define RISCV_CODE32 "\x37\x34\x00\x00\x97\x82\x00\x00\xef\x00\x80\x00\xef\xf0\x1f\xff\xe7\x00\x45\x00\xe7\x00\xc0\xff\x63\x05\x41\x00\xe3\x9d\x61\xfe\x63\xca\x93\x00\x63\x53\xb5\x00\x63\x65\xd6\x00\x63\x76\xf7\x00\x03\x88\x18\x00\x03\x99\x49\x00\x03\xaa\x6a\x00\x03\xcb\x2b\x01\x03\xdc\x8c\x01\x23\x86\xad\x03\x23\x9a\xce\x03\x23\x8f\xef\x01\x93\x00\xe0\x00\x13\xa1\x01\x01\x13\xb2\x02\x7d\x13\xc3\x03\xdd\x13\xe4\xc4\x12\x13\xf5\x85\x0c\x13\x96\xe6\x01\x13\xd7\x97\x01\x13\xd8\xf8\x40\x33\x89\x49\x01\xb3\x0a\x7b\x41\x33\xac\xac\x01\xb3\x3d\xde\x01\x33\xd2\x62\x40\xb3\x43\x94\x00\x33\xe5\xc5\x00\xb3\x76\xf7\x00\xb3\x54\x39\x01\xb3\x50\x31\x00\x33\x9f\x0f\x00\x73\x15\x04\xb0\xf3\x56\x00\x10\x33\x05\x7b\x03\xb3\x45\x9c\x03\x33\x66\xbd\x03\x2f\xa4\x02\x10\xaf\x23\x65\x18\x2f\x27\x2f\x01\x43\xf0\x20\x18\xd3\x72\x73\x00\x53\xf4\x04\x58\x53\x85\xc5\x28\x53\x2e\xde\xa1\xd3\x84\x05\xf0\x53\x06\x05\xe0\x53\x75\x00\xc0\xd3\xf0\x05\xd0\xd3\x15\x08\xe0\x87\xaa\x75\x00\x27\x27\x66\x01\x43\xf0\x20\x1a\xd3\x72\x73\x02\x53\xf4\x04\x5a\x53\x85\xc5\x2a\x53\x2e\xde\xa3"
#define RISCV_CODE64 "\x13\x04\xa8\x7a\xbb\x07\x9c\x02\xbb\x40\x5d\x02\x3b\x63\xb7\x03\x2f\xb4\x02\x10\xaf\x33\x65\x18\x2f\x37\x2f\x01\x53\x75\x20\xc0\xd3\xf0\x25\xd0\xd3\x84\x05\xf2\x53\x06\x05\xe2\x53\x75\x00\xc2\xd3\x80\x05\xd2\xd3\x15\x08\xe2\x87\xba\x75\x00\x27\x37\x66\x01"
#define RISCV_CODEC "\xe8\x1f\x7d\x61\x80\x25\x00\x46\x88\xa2\x04\xcb\x55\x13\xf2\x93\x5d\x45\x19\x80\x15\x68\x2a\xa4\x62\x24\xa6\xff\x2a\x65\x76\x86\x65\xdd\x01\x00\xfd\xaf\x82\x82\x11\x20\x82\x94"
	struct platform platforms[] = {
		{
			CS_ARCH_RISCV,
			CS_MODE_RISCV32,
			(unsigned char *)RISCV_CODE32,
			sizeof(RISCV_CODE32) - 1,
			"riscv32"
		},
		{
			CS_ARCH_RISCV,
			CS_MODE_RISCV64,
			(unsigned char *)RISCV_CODE64,
			sizeof(RISCV_CODE64) - 1,
			"riscv64"
		},
		{
			CS_ARCH_RISCV,
			CS_MODE_RISCVC,
			(unsigned char *)RISCV_CODEC,
			sizeof(RISCV_CODEC) - 1,
			"riscvc"
		}
	};
	
	uint64_t address = 0x1000;
	cs_insn *insn;
	int i;
	size_t count;

	for (i = 0; i < sizeof(platforms)/sizeof(platforms[0]); i++) {
		cs_err err = cs_open(platforms[i].arch, platforms[i].mode, &handle);
		if (err) {
			printf("Failed on cs_open() with error returned: %u\n", err);
			continue;
		}
		
		//To turn on or off the Print Details option
		//cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF); 
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

		count = cs_disasm(handle, platforms[i].code, platforms[i].size, address, 0, &insn);
		if (count) {
			size_t j;

			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code:", platforms[i].code, platforms[i].size);
			printf("Disasm:\n");

			for (j = 0; j < count; j++) {
				printf("0x%" PRIx64 ":\t%s\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
				print_insn_detail(&insn[j]);
			}
			printf("0x%" PRIx64 ":\n", insn[j-1].address + insn[j-1].size);

			// free memory allocated by cs_disasm()
			cs_free(insn, count);
		} else {
			printf("****************\n");
			printf("Platform: %s\n", platforms[i].comment);
			print_string_hex("Code:", platforms[i].code, platforms[i].size);
			printf("ERROR: Failed to disasm given code!\n");
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

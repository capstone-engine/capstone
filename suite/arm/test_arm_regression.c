/* Capstone Disassembler Engine */
/* By David Hogarty, 2014 */

// the following must precede stdio (woo, thanks msft)
#if defined(_MSC_VER) && _MSC_VER < 1900
#define _CRT_SECURE_NO_WARNINGS
#define snprintf _snprintf
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <platform.h>
#include <capstone.h>

static csh handle;

struct platform {
	cs_arch arch;
	cs_mode mode;
	unsigned char *code;
	size_t size;
	char *comment;
	int syntax;
};

static char *hex_string(unsigned char *str, size_t len)
{
	// returns a malloced string that has the hex version of the string in it
	// null if failed to malloc
	char *hex_out;
	size_t i;

	hex_out = (char *) malloc(len*2 + 1); // two ascii characters per input character, plus trailing null
	if (!hex_out) { goto Exit; }

	for (i = 0; i < len; ++i) {
		snprintf(hex_out + (i*2), 2, "%02x", str[i]);
	}

	hex_out[len*2] = 0; // trailing null

Exit:
	return hex_out;
}

static void snprint_insn_detail(char * buf, size_t * cur, size_t * left, cs_insn *ins)
{
	size_t used = 0;

#define _this_printf(...) \
	{ \
		size_t used = 0; \
		used = snprintf(buf + *cur, *left, __VA_ARGS__); \
		*left -= used; \
		*cur += used; \
	}

	cs_arm *arm;
	int i;

	// detail can be NULL on "data" instruction if SKIPDATA option is turned ON
	if (ins->detail == NULL)
		return;

	arm = &(ins->detail->arm);

	if (arm->op_count)
		_this_printf("\top_count: %u\n", arm->op_count);

	for (i = 0; i < arm->op_count; i++) {
		cs_arm_op *op = &(arm->operands[i]);
		switch((int)op->type) {
			default:
				break;
			case ARM_OP_REG:
				_this_printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
				break;
			case ARM_OP_IMM:
				_this_printf("\t\toperands[%u].type: IMM = 0x%x\n", i, op->imm);
				break;
			case ARM_OP_FP:
				_this_printf("\t\toperands[%u].type: FP = %f\n", i, op->fp);
				break;
			case ARM_OP_MEM:
				_this_printf("\t\toperands[%u].type: MEM\n", i);
				if (op->mem.base != X86_REG_INVALID)
					_this_printf("\t\t\toperands[%u].mem.base: REG = %s\n",
							i, cs_reg_name(handle, op->mem.base));
				if (op->mem.index != X86_REG_INVALID)
					_this_printf("\t\t\toperands[%u].mem.index: REG = %s\n",
							i, cs_reg_name(handle, op->mem.index));
				if (op->mem.scale != 1)
					_this_printf("\t\t\toperands[%u].mem.scale: %u\n", i, op->mem.scale);
				if (op->mem.disp != 0)
					_this_printf("\t\t\toperands[%u].mem.disp: 0x%x\n", i, op->mem.disp);

				break;
			case ARM_OP_PIMM:
				_this_printf("\t\toperands[%u].type: P-IMM = %u\n", i, op->imm);
				break;
			case ARM_OP_CIMM:
				_this_printf("\t\toperands[%u].type: C-IMM = %u\n", i, op->imm);
				break;
		}

		if (op->shift.type != ARM_SFT_INVALID && op->shift.value) {
			if (op->shift.type < ARM_SFT_ASR_REG) {
				// shift with constant value
				_this_printf("\t\t\tShift: %u = %u\n", op->shift.type, op->shift.value);
			} else {
				// shift with register
				_this_printf("\t\t\tShift: %u = %s\n", op->shift.type,
						cs_reg_name(handle, op->shift.value));
			}
		}
	}

	if (arm->cc != ARM_CC_AL && arm->cc != ARM_CC_INVALID) {
		_this_printf("\tCode condition: %u\n", arm->cc);
	}

	if (arm->update_flags) {
		_this_printf("\tUpdate-flags: True\n");
	}

	if (arm->writeback) {
		_this_printf("\tWrite-back: True\n");
	}

#undef _this_printf
}

static void print_insn_detail(cs_insn *ins)
{
	char a_buf[2048];
	size_t cur=0, left=2048;
	snprint_insn_detail(a_buf, &cur, &left, ins);
	printf("%s\n", a_buf);
}

struct invalid_code {
	unsigned char *code;
	size_t size;
	char *comment;
};

#define MAX_INVALID_CODES 16

struct invalid_instructions {
	cs_arch arch;
	cs_mode mode;
	char *platform_comment;
	int num_invalid_codes;
	struct invalid_code invalid_codes[MAX_INVALID_CODES]; 
};

static void test_invalids()
{
	struct invalid_instructions invalids[] = {{
		CS_ARCH_ARM,
			CS_MODE_THUMB,
			"Thumb",
			1,
			{{
				 (unsigned char *)"\xbd\xe8\x1e\xff",
				 4,
				 "invalid thumb2 pop because sp used and because both pc and lr are "
					 "present at the same time"
			 }},
	}};

	struct invalid_instructions * invalid = NULL;

	uint64_t address = 0x1000;
	cs_insn *insn;
	int i;
	int j;
	size_t count;

	printf("\nShould be invalid\n"
			"-----------------\n");

	for (i = 0; i < sizeof(invalids)/sizeof(invalids[0]); i++) {
		cs_err err;

		invalid = invalids + i;
		err = cs_open(invalid->arch, invalid->mode, &handle);

		if (err) {
			printf("Failed on cs_open() with error returned: %u\n", err);
			continue;
		}

		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_NOREGNAME);

		for (j = 0; j < invalid->num_invalid_codes; ++j) {
			struct invalid_code *invalid_code = NULL;
			char *hex_str = NULL;

			invalid_code = invalid->invalid_codes + j;

			hex_str = hex_string(invalid_code->code, invalid_code->size);

			printf("%s %s: %s\n", invalid->platform_comment, hex_str, invalid_code->comment);

			free(hex_str);

			count = cs_disasm(handle,
					invalid_code->code, invalid_code->size, address, 0, &insn
					);

			if (count) {
				size_t k;
				printf("    ERROR:\n");

				for (k = 0; k < count; k++) {
					printf("    0x%"PRIx64":\t%s\t%s\n", 
							insn[k].address, insn[k].mnemonic, insn[k].op_str);
					print_insn_detail(&insn[k]);
				}
				cs_free(insn, count);

			} else {
				printf("    SUCCESS: invalid\n");
			}
		}

		cs_close(&handle);
	}
}

struct valid_code {
	unsigned char *code;
	size_t size;
	uint32_t start_addr;
	char *expected_out;
	char *comment;
};

#define MAX_VALID_CODES 16
struct valid_instructions {
	cs_arch arch;
	cs_mode mode;
	char *platform_comment;
	int num_valid_codes;
	struct valid_code valid_codes[MAX_VALID_CODES]; 
};

static void test_valids()
{
	struct valid_instructions valids[] = {{
		CS_ARCH_ARM,
			CS_MODE_THUMB,
			"Thumb",
			3,
			{{ (unsigned char *)"\x00\xf0\x26\xe8", 4, 0x352,
				"0x352:\tblx\t#0x3a0\n"
					"\top_count: 1\n"
					"\t\toperands[0].type: IMM = 0x3a0\n",

				"thumb2 blx with misaligned immediate"
			}, { (unsigned char *)"\x05\xdd", 2, 0x1f0,
				"0x1f0:\tble\t#0x1fe\n"
					"\top_count: 1\n"
					"\t\toperands[0].type: IMM = 0x1fe\n"
					"\tCode condition: 14\n",

				"thumb b cc with thumb-aligned target"
			}, { (unsigned char *)"\xbd\xe8\xf0\x8f", 4, 0,
			 "0x0:\tpop.w\t{r4, r5, r6, r7, r8, r9, r10, r11, pc}\n"
				 "\top_count: 9\n"
				 "\t\toperands[0].type: REG = r4\n"
				 "\t\toperands[1].type: REG = r5\n"
				 "\t\toperands[2].type: REG = r6\n"
				 "\t\toperands[3].type: REG = r7\n"
				 "\t\toperands[4].type: REG = r8\n"
				 "\t\toperands[5].type: REG = r9\n"
				 "\t\toperands[6].type: REG = r10\n"
				 "\t\toperands[7].type: REG = r11\n"
				 "\t\toperands[8].type: REG = pc\n",

				"thumb2 pop that should be valid"
			},
		}
	}};

	struct valid_instructions * valid = NULL;

	uint64_t address = 0x1000;
	cs_insn *insn;
	int i;
	int j;
	size_t count;


	for (i = 0; i < sizeof(valids)/sizeof(valids[0]); i++) {
		cs_err err;

		valid = valids + i;
		err = cs_open(valid->arch, valid->mode, &handle);

		if (err) {
			printf("Failed on cs_open() with error returned: %u\n", err);
			continue;
		}

		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
		cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_NOREGNAME);

#define _this_printf(...) \
		{ \
			size_t used = 0; \
			used = snprintf(tmp_buf + cur, left, __VA_ARGS__); \
			left -= used; \
			cur += used; \
		}
		printf("\nShould be valid\n"
				"---------------\n");

		for (j = 0; j < valid->num_valid_codes; ++j) {
			char tmp_buf[2048];
			size_t left = 2048;
			size_t cur = 0;
			size_t used = 0;
			int success = 0;
			char * hex_str = NULL;

			struct valid_code * valid_code = NULL;
			valid_code = valid->valid_codes + j;

			hex_str = hex_string(valid_code->code, valid_code->size);

			printf("%s %s @ 0x%04x: %s\n    %s", 
					valid->platform_comment, hex_str, valid_code->start_addr, 
					valid_code->comment, valid_code->expected_out);

			count = cs_disasm(handle,
					valid_code->code, valid_code->size, 
					valid_code->start_addr, 0, &insn
					);

			if (count) {
				size_t k;
				size_t max_len = 0;
				size_t tmp_len = 0;

				for (k = 0; k < count; k++) {
					_this_printf(
							"0x%"PRIx64":\t%s\t%s\n", 
							insn[k].address, insn[k].mnemonic, 
							insn[k].op_str
							);

					snprint_insn_detail(tmp_buf, &cur, &left, &insn[k]);
				}

				max_len = strlen(tmp_buf);
				tmp_len = strlen(valid_code->expected_out);
				if (tmp_len > max_len) {
					max_len = tmp_len;
				}

				if (memcmp(tmp_buf, valid_code->expected_out, max_len)) {
					printf(
						"    ERROR: '''\n%s''' does not match"
						" expected '''\n%s'''\n", 
						tmp_buf, valid_code->expected_out
					);
				} else {
					printf("    SUCCESS: valid\n");
				}

				cs_free(insn, count);

			} else {
				printf("ERROR: invalid\n");
			}
		}

		cs_close(&handle);
	}

#undef _this_prinf
}

int main()
{
	test_invalids();
	test_valids();
	return 0;
}


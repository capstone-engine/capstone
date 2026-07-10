// SPDX-License-Identifier: BSD-3
// SPDX-FileCopyrightText: 2025 Finder16
// SPDX-FileCopyrightText: 2025 Rot127 <unisono@quyllur.org>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <capstone/platform.h>
#include <capstone/capstone.h>

static size_t big_skip(const uint8_t *code, size_t code_size, size_t offset,
		       void *user_data)
{
	(void)code;
	(void)code_size;
	(void)offset;
	(void)user_data;
	return 1024; // larger than cs_insn.bytes (24)
}

/// Possible buffer overflow of cs_insn.bytes if number of skipped bytes
/// is larger.
/// Reported by Finder16.
static void test_overflow_cs_insn_bytes()
{
	csh handle;
	if (cs_open(CS_ARCH_WASM, CS_MODE_LITTLE_ENDIAN, &handle) !=
	    CS_ERR_OK) {
		return;
	}
	cs_opt_skipdata skip = { .mnemonic = ".byte",
				 .callback = big_skip,
				 .user_data = NULL };
	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
	cs_option(handle, CS_OPT_SKIPDATA_SETUP, (size_t)&skip);
	uint8_t buf[1024] = { 0 };
	buf[0] = 0x06; // invalid WASM opcode to force skipdata path
	cs_insn *insn = NULL;
	// Overflowed cs_insn->bytes before the fix.
	cs_disasm(handle, buf, sizeof(buf), 0, 1, &insn);
	cs_free(insn, 1);
	cs_close(&handle);
	return;
}

/// Possible buffer overflow of cs_insn.bytes if number of skipped bytes
/// is larger.
/// Reported by Finder16.
static void test_overflow_cs_insn_bytes_iter()
{
	csh handle;
	if (cs_open(CS_ARCH_WASM, CS_MODE_LITTLE_ENDIAN, &handle) !=
	    CS_ERR_OK) {
		return;
	}
	cs_opt_skipdata skip = { .mnemonic = ".byte",
				 .callback = big_skip,
				 .user_data = NULL };
	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
	cs_option(handle, CS_OPT_SKIPDATA_SETUP, (size_t)&skip);
	uint64_t address = 0;
	uint8_t buf[1024] = { 0 };
	const uint8_t *b = buf;
	size_t size = sizeof(buf);
	buf[0] = 0x06; // invalid WASM opcode to force skipdata path
	cs_insn *insn = cs_malloc(handle);

	// Overflowed cs_insn->bytes before the fix.
	while (cs_disasm_iter(handle, &b, &size, &address, insn)) {
		continue;
	}
	cs_free(insn, 1);
	cs_close(&handle);
	return;
}

static void test_overflow_set_reg_mem_n(void)
{
	static const uint8_t code[] = {
		0x1e, 0xff, 0x15, 0x02, 0x03, 0x73, 0x7e, 0x77, 0x00, 0x8d,
		0x66, 0x66, 0x66, 0x66, 0xa0, 0x99, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x8d, 0x71, 0x35, 0x8d, 0x8d, 0x49, 0x3e,
		0xff, 0x00, 0x00, 0x00, 0x05, 0x90, 0x8d, 0x8d, 0x8d, 0x8d,
		0x8d, 0x8d, 0x8d, 0x8d, 0x8d, 0x8d, 0x8d, 0x8d, 0x8d, 0x8d,
		0x8d, 0x8d, 0x8d, 0x8d, 0x8d, 0x8d, 0x8d, 0x8d, 0x8d, 0x78,
		0x8d, 0x8d, 0x8d, 0x8d, 0x8d, 0x8d, 0x8d, 0x8d, 0x8d, 0x8d,
		0x8d, 0x2f, 0x8d, 0x8d, 0x8d, 0x8d, 0x8d, 0x8d, 0x8d, 0x8d,
		0xb9, 0x4e
	};

	csh handle;
	if (cs_open(CS_ARCH_SH, CS_MODE_SH2A | CS_MODE_SHFPU, &handle) !=
	    CS_ERR_OK)
		return;
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	cs_insn *insn = cs_malloc(handle);
	const uint8_t *p = code;
	size_t rem = sizeof(code);
	uint64_t addr = 0;

	while (rem > 0) {
		if (!cs_disasm_iter(handle, &p, &rem, &addr, insn))
			break;
	}

	cs_free(insn, 1);
	cs_close(&handle);
	return;
}

/**
 * \brief Clone of cs.c::cs_kern_os_calloc()
 * So we can run it in the CI.
 */
static void *clone_cs_kern_os_calloc(size_t num, size_t size)
{
	size_t alloc = num * size;
	if (num && size != alloc / num) {
		return NULL; // overflow check
	}
	return malloc(alloc);
}

#define VALID_N 10

static void test_integer_overflow(void)
{
	// Invariant: Multiplication of num * size must not overflow before allocation
	// We test this by ensuring the function handles boundary cases safely

	// Test cases: exploit case, boundary values, valid input
	struct {
		size_t num;
		size_t size;
		const char *description;
	} test_cases[] = {
		// Valid normal input
		{ VALID_N, VALID_N, "valid normal input" },
		// Exploit case: multiplication overflows to small value
		{ SIZE_MAX, 2, "overflow to small allocation" },
		// Another overflow case
		{ 1ULL << (sizeof(size_t) * 4), 1ULL << (sizeof(size_t) * 4),
		  "midpoint overflow" },
		// Zero allocation (edge case)
		{ 0, SIZE_MAX, "zero num" }
	};

	int num_cases = sizeof(test_cases) / sizeof(test_cases[0]);

	for (int i = 0; i < num_cases; i++) {
		printf("num = 0x%zx size = 0x%zx\n", test_cases[i].num,
		       test_cases[i].size);
		// The security property: if multiplication would overflow,
		// the function should handle it safely (return NULL or abort)
		void *result = clone_cs_kern_os_calloc(test_cases[i].num,
						       test_cases[i].size);

		// For valid inputs, we expect non-NULL (or NULL is also acceptable
		// if memory allocation fails for other reasons)
		if (test_cases[i].num == VALID_N || test_cases[i].num == 0) {
			assert(result != NULL);
			free(result);
		} else {
			assert(result == NULL);
		}
	}
}

/// Signed left shift overflow when assembling a little-endian SH-DSP
/// parallel instruction word. code[3] is promoted to int and shifted
/// left by 24, which is UB whenever its top bit is set (code[3] >= 0x80).
static void test_ub_shift_sh_dsp_p(void)
{
	static const uint8_t code[] = { 0x00, 0xf8, 0x00, 0x80 };

	csh handle;
	if (cs_open(CS_ARCH_SH, CS_MODE_SH4A | CS_MODE_SHDSP, &handle) !=
	    CS_ERR_OK)
		return;
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, sizeof(code), 0x1000, 0, &insn);
	cs_free(insn, count);
	cs_close(&handle);
	return;
}

/// Swapped isIntN() arguments in decodeOffset_16_16Operand: the untrusted
/// immediate is passed as the bit width N. When the 4-bit offset field is 0,
/// N becomes 0 and isIntN shifts by (unsigned)(0 - 1), which is UB. The word
/// below is an ee.ldf.128.ip with a zero offset field.
static void test_ub_isintn_xtensa_offset(void)
{
	static const uint8_t code[] = { 0x2f, 0x70, 0x44, 0x84 };

	csh handle;
	if (cs_open(CS_ARCH_XTENSA, CS_MODE_XTENSA_ESP32, &handle) != CS_ERR_OK)
		return;
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	cs_insn *insn = NULL;
	size_t count = cs_disasm(handle, code, sizeof(code), 0x1000, 0, &insn);
	cs_free(insn, count);
	cs_close(&handle);
	return;
}

int main()
{
	test_overflow_cs_insn_bytes();
	test_overflow_cs_insn_bytes_iter();
	test_overflow_set_reg_mem_n();
	test_integer_overflow();
	test_ub_shift_sh_dsp_p();
	test_ub_isintn_xtensa_offset();

	return 0;
}

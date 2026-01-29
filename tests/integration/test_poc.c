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

int main()
{
	test_overflow_cs_insn_bytes();
	test_overflow_cs_insn_bytes_iter();

	return 0;
}

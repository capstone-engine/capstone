// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "unit_test.h"
#include "../SStream.h"
#include "../utils.h"
#include <stdio.h>
#include <string.h>

static void overflow_SStream_concat0(SStream *OS, bool *returned_in_time)
{
	char buf[SSTREAM_BUF_LEN + 1] = { 0 };
	memset(&buf, 'A', SSTREAM_BUF_LEN);
	SStream_concat0(OS, buf);
	*returned_in_time = OS->buffer[SSTREAM_BUF_LEN - 1] == '\0';
}

static void overflow_SStream_concat(SStream *OS, bool *returned_in_time)
{
	char buf[SSTREAM_BUF_LEN + 1] = { 0 };
	memset(&buf, 'A', SSTREAM_BUF_LEN);
	SStream_concat(OS, "%s", buf);
	*returned_in_time = OS->buffer[SSTREAM_BUF_LEN - 1] == '\0';
}

static void overflow_SStream_concat1(SStream *OS, bool *returned_in_time)
{
	char buf[SSTREAM_BUF_LEN] = { 0 };
	memset(&buf, 'A', SSTREAM_BUF_LEN - 1);
	SStream_concat0(OS, buf);
	// Should return here because null byte is overflown.
	SStream_concat1(OS, 'A');
	*returned_in_time = OS->buffer[SSTREAM_BUF_LEN - 1] == '\0';
}

static bool test_overflow_check()
{
	printf("Test test_overflow_check\n");

	SStream OS = { 0 };
	SStream_Init(&OS);
	bool returned_in_time = true;
	overflow_SStream_concat0(&OS, &returned_in_time);
	if (!returned_in_time) {
		printf("Failed overflow_SStream_concat0\n");
		return false;
	}
	overflow_SStream_concat(&OS, &returned_in_time);
	if (!returned_in_time) {
		printf("Failed overflow_SStream_concat\n");
		return false;
	}
	overflow_SStream_concat1(&OS, &returned_in_time);
	if (!returned_in_time) {
		printf("Failed overflow_SStream_concat1\n");
		return false;
	}
	return true;
}

static bool test_markup_os()
{
	printf("Test test_markup_os\n");

	SStream OS = { 0 };
	SStream_Init(&OS);
	SStream_concat0(&OS, "0");
	CHECK_OS_EQUAL_RET_FALSE(OS, "0");
	OS.markup_stream = true;
	printUInt64(&OS, 0);
	CHECK_OS_EQUAL_RET_FALSE(OS, "00");
	markup_OS(&OS, Markup_Immediate);
	printUInt64(&OS, 0);
	CHECK_OS_EQUAL_RET_FALSE(OS, "00<imm:0>");
	markup_OS(&OS, Markup_Memory);
	printUInt32(&OS, 0);
	CHECK_OS_EQUAL_RET_FALSE(OS, "00<imm:0><mem:0>");
	markup_OS(&OS, Markup_Target);
	printUInt32(&OS, 0);
	CHECK_OS_EQUAL_RET_FALSE(OS, "00<imm:0><mem:0><tar:0>");
	markup_OS(&OS, Markup_Register);
	SStream_concat0(&OS, "r19");
	CHECK_OS_EQUAL_RET_FALSE(OS, "00<imm:0><mem:0><tar:0><reg:r19>");
	return true;
}

bool test_printint8()
{
	printf("Test test_printint8\n");

	SStream OS = { 0 };
	SStream_Init(&OS);
	printInt8(&OS, HEX_THRESHOLD + 1);
	CHECK_OS_EQUAL_RET_FALSE(OS, "0xa");
	SStream_Flush(&OS, NULL);

	printInt8(&OS, HEX_THRESHOLD);
	CHECK_OS_EQUAL_RET_FALSE(OS, "9");
	SStream_Flush(&OS, NULL);

	printInt8(&OS, -(HEX_THRESHOLD + 1));
	CHECK_OS_EQUAL_RET_FALSE(OS, "-0xa");
	SStream_Flush(&OS, NULL);

	printInt8(&OS, -HEX_THRESHOLD);
	CHECK_OS_EQUAL_RET_FALSE(OS, "-9");
	SStream_Flush(&OS, NULL);

	printInt8(&OS, INT8_MAX);
	CHECK_OS_EQUAL_RET_FALSE(OS, "0x7f");
	SStream_Flush(&OS, NULL);

	printInt8(&OS, INT8_MIN);
	CHECK_OS_EQUAL_RET_FALSE(OS, "-0x80");
	SStream_Flush(&OS, NULL);
	return true;
}

bool test_printint16()
{
	printf("Test test_printint16\n");

	SStream OS = { 0 };
	SStream_Init(&OS);
	printInt16(&OS, HEX_THRESHOLD + 1);
	CHECK_OS_EQUAL_RET_FALSE(OS, "0xa");
	SStream_Flush(&OS, NULL);

	printInt16(&OS, HEX_THRESHOLD);
	CHECK_OS_EQUAL_RET_FALSE(OS, "9");
	SStream_Flush(&OS, NULL);

	printInt16(&OS, -(HEX_THRESHOLD + 1));
	CHECK_OS_EQUAL_RET_FALSE(OS, "-0xa");
	SStream_Flush(&OS, NULL);

	printInt16(&OS, -HEX_THRESHOLD);
	CHECK_OS_EQUAL_RET_FALSE(OS, "-9");
	SStream_Flush(&OS, NULL);

	printInt16(&OS, INT16_MAX);
	CHECK_OS_EQUAL_RET_FALSE(OS, "0x7fff");
	SStream_Flush(&OS, NULL);

	printInt16(&OS, INT16_MIN);
	CHECK_OS_EQUAL_RET_FALSE(OS, "-0x8000");
	SStream_Flush(&OS, NULL);
	return true;
}

bool test_printint32()
{
	printf("Test test_printint32\n");

	SStream OS = { 0 };
	SStream_Init(&OS);
	printInt32(&OS, HEX_THRESHOLD + 1);
	CHECK_OS_EQUAL_RET_FALSE(OS, "0xa");
	SStream_Flush(&OS, NULL);

	printInt32(&OS, HEX_THRESHOLD);
	CHECK_OS_EQUAL_RET_FALSE(OS, "9");
	SStream_Flush(&OS, NULL);

	printInt32(&OS, -(HEX_THRESHOLD + 1));
	CHECK_OS_EQUAL_RET_FALSE(OS, "-0xa");
	SStream_Flush(&OS, NULL);

	printInt32(&OS, -HEX_THRESHOLD);
	CHECK_OS_EQUAL_RET_FALSE(OS, "-9");
	SStream_Flush(&OS, NULL);

	printInt32(&OS, INT32_MAX);
	CHECK_OS_EQUAL_RET_FALSE(OS, "0x7fffffff");
	SStream_Flush(&OS, NULL);

	printInt32(&OS, INT32_MIN);
	CHECK_OS_EQUAL_RET_FALSE(OS, "-0x80000000");
	SStream_Flush(&OS, NULL);
	return true;
}

bool test_printint64()
{
	printf("Test test_printint64\n");

	SStream OS = { 0 };
	SStream_Init(&OS);
	printInt64(&OS, HEX_THRESHOLD + 1);
	CHECK_OS_EQUAL_RET_FALSE(OS, "0xa");
	SStream_Flush(&OS, NULL);

	printInt64(&OS, HEX_THRESHOLD);
	CHECK_OS_EQUAL_RET_FALSE(OS, "9");
	SStream_Flush(&OS, NULL);

	printInt64(&OS, -(HEX_THRESHOLD + 1));
	CHECK_OS_EQUAL_RET_FALSE(OS, "-0xa");
	SStream_Flush(&OS, NULL);

	printInt64(&OS, -HEX_THRESHOLD);
	CHECK_OS_EQUAL_RET_FALSE(OS, "-9");
	SStream_Flush(&OS, NULL);

	printInt64(&OS, INT64_MAX);
	CHECK_OS_EQUAL_RET_FALSE(OS, "0x7fffffffffffffff");
	SStream_Flush(&OS, NULL);

	printInt64(&OS, INT64_MIN);
	CHECK_OS_EQUAL_RET_FALSE(OS, "-0x8000000000000000");
	SStream_Flush(&OS, NULL);
	return true;
}

bool test_printint32_bang()
{
	printf("Test test_printint32Bang\n");

	SStream OS = { 0 };
	SStream_Init(&OS);
	printInt32Bang(&OS, HEX_THRESHOLD + 1);
	CHECK_OS_EQUAL_RET_FALSE(OS, "#0xa");
	SStream_Flush(&OS, NULL);

	printInt32Bang(&OS, HEX_THRESHOLD);
	CHECK_OS_EQUAL_RET_FALSE(OS, "#9");
	SStream_Flush(&OS, NULL);

	printInt32Bang(&OS, -(HEX_THRESHOLD + 1));
	CHECK_OS_EQUAL_RET_FALSE(OS, "#-0xa");
	SStream_Flush(&OS, NULL);

	printInt32Bang(&OS, -HEX_THRESHOLD);
	CHECK_OS_EQUAL_RET_FALSE(OS, "#-9");
	SStream_Flush(&OS, NULL);

	printInt32Bang(&OS, INT32_MAX);
	CHECK_OS_EQUAL_RET_FALSE(OS, "#0x7fffffff");
	SStream_Flush(&OS, NULL);

	printInt32Bang(&OS, INT32_MIN);
	CHECK_OS_EQUAL_RET_FALSE(OS, "#-0x80000000");
	SStream_Flush(&OS, NULL);
	return true;
}

bool test_printint64_bang()
{
	printf("Test test_printint64Bang\n");

	SStream OS = { 0 };
	SStream_Init(&OS);
	printInt64Bang(&OS, HEX_THRESHOLD + 1);
	CHECK_OS_EQUAL_RET_FALSE(OS, "#0xa");
	SStream_Flush(&OS, NULL);

	printInt64Bang(&OS, HEX_THRESHOLD);
	CHECK_OS_EQUAL_RET_FALSE(OS, "#9");
	SStream_Flush(&OS, NULL);

	printInt64Bang(&OS, -(HEX_THRESHOLD + 1));
	CHECK_OS_EQUAL_RET_FALSE(OS, "#-0xa");
	SStream_Flush(&OS, NULL);

	printInt64Bang(&OS, -HEX_THRESHOLD);
	CHECK_OS_EQUAL_RET_FALSE(OS, "#-9");
	SStream_Flush(&OS, NULL);

	printInt64Bang(&OS, INT64_MAX);
	CHECK_OS_EQUAL_RET_FALSE(OS, "#0x7fffffffffffffff");
	SStream_Flush(&OS, NULL);

	printInt64Bang(&OS, INT64_MIN);
	CHECK_OS_EQUAL_RET_FALSE(OS, "#-0x8000000000000000");
	SStream_Flush(&OS, NULL);
	return true;
}

bool test_printuint32_bang()
{
	printf("Test test_printuint32Bang\n");

	SStream OS = { 0 };
	SStream_Init(&OS);
	printUInt32Bang(&OS, HEX_THRESHOLD + 1);
	CHECK_OS_EQUAL_RET_FALSE(OS, "#0xa");
	SStream_Flush(&OS, NULL);

	printUInt32Bang(&OS, HEX_THRESHOLD);
	CHECK_OS_EQUAL_RET_FALSE(OS, "#9");
	SStream_Flush(&OS, NULL);

	printUInt32Bang(&OS, UINT32_MAX);
	CHECK_OS_EQUAL_RET_FALSE(OS, "#0xffffffff");
	SStream_Flush(&OS, NULL);
	return true;
}

bool test_printuint64_bang()
{
	printf("Test test_printuint64Bang\n");

	SStream OS = { 0 };
	SStream_Init(&OS);
	printUInt64Bang(&OS, HEX_THRESHOLD + 1);
	CHECK_OS_EQUAL_RET_FALSE(OS, "#0xa");
	SStream_Flush(&OS, NULL);

	printUInt64Bang(&OS, HEX_THRESHOLD);
	CHECK_OS_EQUAL_RET_FALSE(OS, "#9");
	SStream_Flush(&OS, NULL);

	printUInt64Bang(&OS, UINT64_MAX);
	CHECK_OS_EQUAL_RET_FALSE(OS, "#0xffffffffffffffff");
	SStream_Flush(&OS, NULL);
	return true;
}

bool test_trimls() {
	printf("Test test_replc\n");

	SStream OS = { 0 };
	SStream_Init(&OS);
	SStream_concat0(&OS, "AAA");
	SStream_trimls(&OS);
	CHECK_OS_EQUAL_RET_FALSE(OS, "AAA");
	SStream_Flush(&OS, NULL);

	SStream_concat0(&OS, "\t AAA");
	SStream_trimls(&OS);
	CHECK_OS_EQUAL_RET_FALSE(OS, "AAA");

	// Don't remove middle tabs and spaces
	SStream_concat0(&OS, "\t AAA");
	SStream_trimls(&OS);
	CHECK_OS_EQUAL_RET_FALSE(OS, "AAA\t AAA");
	SStream_Flush(&OS, NULL);

	// Test do nothing
	SStream_trimls(&OS);
	CHECK_OS_EQUAL_RET_FALSE(OS, "");

	// Everywhere tabs
	char cmp_buf[SSTREAM_BUF_LEN] = { 0 };
	memset(cmp_buf, '\t', sizeof(cmp_buf) - 1);
	SStream_trimls(&OS);
	CHECK_OS_EQUAL_RET_FALSE(OS, "");
	CHECK_INT_EQUAL_RET_FALSE(OS.index, 0);
	return true;
}

bool test_copy_mnem_opstr() {
	printf("Test test_copy_mnem_opstr\n");

	SStream OS = { 0 };
	SStream_Init(&OS);
	SStream_concat0(&OS, "AAA\tBBBB");

	char mnem_1[1] = { 0 };
	char opstr_1[1] = { 0 };
	SStream_extract_mnem_opstr(&OS, mnem_1, sizeof(mnem_1), opstr_1, sizeof(opstr_1));
	CHECK_STR_EQUAL_RET_FALSE(mnem_1, "");
	CHECK_STR_EQUAL_RET_FALSE(opstr_1, "");

	char mnem_3[3] = { 0 };
	char opstr_3[3] = { 0 };
	SStream_extract_mnem_opstr(&OS, mnem_3, sizeof(mnem_3), opstr_3, sizeof(opstr_3));
	CHECK_STR_EQUAL_RET_FALSE(mnem_3, "AA");
	CHECK_STR_EQUAL_RET_FALSE(opstr_3, "BB");

	char mnem_4[4] = { 0 };
	char opstr_4[4] = { 0 };
	SStream_extract_mnem_opstr(&OS, mnem_4, sizeof(mnem_4), opstr_4, sizeof(opstr_4));
	CHECK_STR_EQUAL_RET_FALSE(mnem_4, "AAA");
	CHECK_STR_EQUAL_RET_FALSE(opstr_4, "BBB");

	char mnem_5[5] = { 0 };
	char opstr_5[5] = { 0 };
	SStream_extract_mnem_opstr(&OS, mnem_5, sizeof(mnem_5), opstr_5, sizeof(opstr_5));
	CHECK_STR_EQUAL_RET_FALSE(mnem_5, "AAA");
	CHECK_STR_EQUAL_RET_FALSE(opstr_5, "BBBB");

	// No mnemonic
	char mnem_9[9] = { 0 };
	char opstr_9[9] = { 0 };
	SStream_Flush(&OS, NULL);
	SStream_concat0(&OS, " AAA\tBBBB");
	SStream_extract_mnem_opstr(&OS, mnem_9, sizeof(mnem_9), opstr_9, sizeof(opstr_9));
	CHECK_STR_EQUAL_RET_FALSE(mnem_9, "");
	CHECK_STR_EQUAL_RET_FALSE(opstr_9, "AAA\tBBBB");

	// No opstr
	char mnem_6[6] = { 0 };
	char opstr_6[6] = { 0 };
	SStream_Flush(&OS, NULL);
	SStream_concat0(&OS, "AAA  \t");
	SStream_extract_mnem_opstr(&OS, mnem_6, sizeof(mnem_6), opstr_6, sizeof(opstr_6));
	CHECK_STR_EQUAL_RET_FALSE(mnem_6, "AAA");
	CHECK_STR_EQUAL_RET_FALSE(opstr_6, "");

	return true;
}

bool test_replc()
{
	printf("Test test_replc\n");

	SStream OS = { 0 };
	SStream_Init(&OS);
	char cmp_buf[SSTREAM_BUF_LEN] = { 0 };
	memset(cmp_buf, 'A', sizeof(cmp_buf) - 1);
	cmp_buf[100] = 'C';
	SStream_concat0(&OS, cmp_buf);

	cmp_buf[0] = 'B';
	const char *next = SStream_replc(&OS, 'A', 'B');
	CHECK_PTR_EQUAL_RET_FALSE(SStream_rbuf(&OS) + 1, next);
	CHECK_OS_EQUAL_RET_FALSE(OS, cmp_buf);

	cmp_buf[1] = 'B';
	next = SStream_replc(&OS, 'A', 'B');
	CHECK_PTR_EQUAL_RET_FALSE(SStream_rbuf(&OS) + 2, next);
	CHECK_OS_EQUAL_RET_FALSE(OS, cmp_buf);

	cmp_buf[100] = 'A'; // Replace the C from before
	next = SStream_replc(&OS, 'C', 'A');
	CHECK_PTR_EQUAL_RET_FALSE(SStream_rbuf(&OS) + 101, next);
	CHECK_OS_EQUAL_RET_FALSE(OS, cmp_buf);

	// X doesn't exist
	next = SStream_replc(&OS, 'X', 'A');
	CHECK_NULL_RET_FALSE(next);

	// Replacing \0 byte is forbidden.
	next = SStream_replc(&OS, '\0', 'A');
	CHECK_NULL_RET_FALSE(next);

	// But replacing any \0 byte is allowed.
	SStream_Flush(&OS, NULL);
	next = SStream_replc(&OS, '\0', 'A');
	CHECK_PTR_EQUAL_RET_FALSE(SStream_rbuf(&OS) + 1, next);
	CHECK_OS_EQUAL_RET_FALSE(OS, "A");

	return true;
}


bool test_replc_str()
{
	printf("Test test_replc_str\n");

	SStream OS = { 0 };
	SStream_Init(&OS);

	SStream_replc_str(&OS, 'A', "REPLACED");
	CHECK_OS_EQUAL_RET_FALSE(OS, "");
	CHECK_INT_EQUAL_RET_FALSE(OS.index, 0);

	SStream_replc_str(&OS, '\0', "REPLACED");
	CHECK_OS_EQUAL_RET_FALSE(OS, "REPLACED");
	CHECK_INT_EQUAL_RET_FALSE(OS.index, 8);

	SStream_Flush(&OS, NULL);
	SStream_concat0(&OS, "\tA--X");
	SStream_replc_str(&OS, 'A', "REPLACED");
	CHECK_OS_EQUAL_RET_FALSE(OS, "\tREPLACED--X");
	CHECK_INT_EQUAL_RET_FALSE(OS.index, 12);
	SStream_replc_str(&OS, 'X', "REPLACED");
	CHECK_OS_EQUAL_RET_FALSE(OS, "\tREPLACED--REPLACED");
	CHECK_INT_EQUAL_RET_FALSE(OS.index, 19);

	/// Too big strings are ignored.
	char repl[SSTREAM_BUF_LEN] = { 0 };
	memset(repl, 'A', sizeof(repl) - 1);
	SStream_Flush(&OS, NULL);
	SStream_concat0(&OS, "\tA--");
	SStream_replc_str(&OS, 'A', repl);
	CHECK_OS_EQUAL_RET_FALSE(OS, "\tA--");
	CHECK_INT_EQUAL_RET_FALSE(OS.index, 4);

	/// Last null byte is not replaced.
	memset(repl, 'A', sizeof(repl) - 1);
	SStream_Flush(&OS, NULL);
	SStream_concat0(&OS, repl);
	SStream_replc_str(&OS, '\0', repl);
	CHECK_OS_EQUAL_RET_FALSE(OS, repl);
	CHECK_INT_EQUAL_RET_FALSE(OS.index, 511);

	/// Last char is replaced.
	memset(repl, 'A', sizeof(repl) - 1);
	repl[sizeof(repl) - 2] = 'X';
	SStream_Flush(&OS, NULL);
	SStream_concat0(&OS, repl);
	SStream_replc_str(&OS, 'X', "Y");
	repl[sizeof(repl) - 2] = 'Y';
	CHECK_OS_EQUAL_RET_FALSE(OS, repl);
	CHECK_INT_EQUAL_RET_FALSE(OS.index, 511);

	// Possible overflow
	char too_long[SSTREAM_BUF_LEN + 10] = { 0 };
	memset(too_long, 'A', sizeof(too_long) - 1);
	SStream_Flush(&OS, NULL);
	SStream_concat0(&OS, "\tA--");
	SStream_replc_str(&OS, 'A', too_long);
	CHECK_OS_EQUAL_RET_FALSE(OS, "\tA--");
	CHECK_INT_EQUAL_RET_FALSE(OS.index, 4);

	return true;
}

int main()
{
	bool result = true;
	result &= test_markup_os();
	result &= test_overflow_check();
	result &= test_printint8();
	result &= test_printint16();
	result &= test_printint32();
	result &= test_printint64();
	result &= test_printint32_bang();
	result &= test_printint64_bang();
	result &= test_printuint32_bang();
	result &= test_printuint64_bang();
	result &= test_replc();
	result &= test_replc_str();
	result &= test_copy_mnem_opstr();
	result &= test_trimls();
	if (result) {
		printf("All tests passed.\n");
	} else {
		printf("Some tests failed.\n");
	}
	return result ? 0 : -1;
}

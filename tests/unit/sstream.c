// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "../SStream.h"
#include "../utils.h"
#include <stdio.h>
#include <string.h>

#define CHECK_EQUAL_RET_FALSE(OS, str) \
	do { \
		if (strcmp(OS.buffer, str) != 0) { \
			printf("OS.buffer != str\n"); \
			printf("OS.buffer: %s\n", OS.buffer); \
			printf("str      : %s\n", str); \
			return false; \
		} \
	} while (0);

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
	CHECK_EQUAL_RET_FALSE(OS, "0");
	OS.markup_stream = true;
	printUInt64(&OS, 0);
	CHECK_EQUAL_RET_FALSE(OS, "00");
	markup_OS(&OS, Markup_Immediate);
	printUInt64(&OS, 0);
	CHECK_EQUAL_RET_FALSE(OS, "00<imm:0>");
	markup_OS(&OS, Markup_Memory);
	printUInt32(&OS, 0);
	CHECK_EQUAL_RET_FALSE(OS, "00<imm:0><mem:0>");
	markup_OS(&OS, Markup_Target);
	printUInt32(&OS, 0);
	CHECK_EQUAL_RET_FALSE(OS, "00<imm:0><mem:0><tar:0>");
	markup_OS(&OS, Markup_Register);
	SStream_concat0(&OS, "r19");
	CHECK_EQUAL_RET_FALSE(OS, "00<imm:0><mem:0><tar:0><reg:r19>");
	return true;
}

bool test_printint8()
{
	printf("Test test_printint8\n");

	SStream OS = { 0 };
	SStream_Init(&OS);
	printInt8(&OS, HEX_THRESHOLD + 1);
	CHECK_EQUAL_RET_FALSE(OS, "0xa");
	SStream_Flush(&OS, NULL);

	printInt8(&OS, HEX_THRESHOLD);
	CHECK_EQUAL_RET_FALSE(OS, "9");
	SStream_Flush(&OS, NULL);

	printInt8(&OS, -(HEX_THRESHOLD + 1));
	CHECK_EQUAL_RET_FALSE(OS, "-0xa");
	SStream_Flush(&OS, NULL);

	printInt8(&OS, -HEX_THRESHOLD);
	CHECK_EQUAL_RET_FALSE(OS, "-9");
	SStream_Flush(&OS, NULL);

	printInt8(&OS, INT8_MAX);
	CHECK_EQUAL_RET_FALSE(OS, "0x7f");
	SStream_Flush(&OS, NULL);

	printInt8(&OS, INT8_MIN);
	CHECK_EQUAL_RET_FALSE(OS, "-0x80");
	SStream_Flush(&OS, NULL);
	return true;
}

bool test_printint16()
{
	printf("Test test_printint16\n");

	SStream OS = { 0 };
	SStream_Init(&OS);
	printInt16(&OS, HEX_THRESHOLD + 1);
	CHECK_EQUAL_RET_FALSE(OS, "0xa");
	SStream_Flush(&OS, NULL);

	printInt16(&OS, HEX_THRESHOLD);
	CHECK_EQUAL_RET_FALSE(OS, "9");
	SStream_Flush(&OS, NULL);

	printInt16(&OS, -(HEX_THRESHOLD + 1));
	CHECK_EQUAL_RET_FALSE(OS, "-0xa");
	SStream_Flush(&OS, NULL);

	printInt16(&OS, -HEX_THRESHOLD);
	CHECK_EQUAL_RET_FALSE(OS, "-9");
	SStream_Flush(&OS, NULL);

	printInt16(&OS, INT16_MAX);
	CHECK_EQUAL_RET_FALSE(OS, "0x7fff");
	SStream_Flush(&OS, NULL);

	printInt16(&OS, INT16_MIN);
	CHECK_EQUAL_RET_FALSE(OS, "-0x8000");
	SStream_Flush(&OS, NULL);
	return true;
}

bool test_printint32()
{
	printf("Test test_printint32\n");

	SStream OS = { 0 };
	SStream_Init(&OS);
	printInt32(&OS, HEX_THRESHOLD + 1);
	CHECK_EQUAL_RET_FALSE(OS, "0xa");
	SStream_Flush(&OS, NULL);

	printInt32(&OS, HEX_THRESHOLD);
	CHECK_EQUAL_RET_FALSE(OS, "9");
	SStream_Flush(&OS, NULL);

	printInt32(&OS, -(HEX_THRESHOLD + 1));
	CHECK_EQUAL_RET_FALSE(OS, "-0xa");
	SStream_Flush(&OS, NULL);

	printInt32(&OS, -HEX_THRESHOLD);
	CHECK_EQUAL_RET_FALSE(OS, "-9");
	SStream_Flush(&OS, NULL);

	printInt32(&OS, INT32_MAX);
	CHECK_EQUAL_RET_FALSE(OS, "0x7fffffff");
	SStream_Flush(&OS, NULL);

	printInt32(&OS, INT32_MIN);
	CHECK_EQUAL_RET_FALSE(OS, "-0x80000000");
	SStream_Flush(&OS, NULL);
	return true;
}

bool test_printint64()
{
	printf("Test test_printint64\n");

	SStream OS = { 0 };
	SStream_Init(&OS);
	printInt64(&OS, HEX_THRESHOLD + 1);
	CHECK_EQUAL_RET_FALSE(OS, "0xa");
	SStream_Flush(&OS, NULL);

	printInt64(&OS, HEX_THRESHOLD);
	CHECK_EQUAL_RET_FALSE(OS, "9");
	SStream_Flush(&OS, NULL);

	printInt64(&OS, -(HEX_THRESHOLD + 1));
	CHECK_EQUAL_RET_FALSE(OS, "-0xa");
	SStream_Flush(&OS, NULL);

	printInt64(&OS, -HEX_THRESHOLD);
	CHECK_EQUAL_RET_FALSE(OS, "-9");
	SStream_Flush(&OS, NULL);

	printInt64(&OS, INT64_MAX);
	CHECK_EQUAL_RET_FALSE(OS, "0x7fffffffffffffff");
	SStream_Flush(&OS, NULL);

	printInt64(&OS, INT64_MIN);
	CHECK_EQUAL_RET_FALSE(OS, "-0x8000000000000000");
	SStream_Flush(&OS, NULL);
	return true;
}

bool test_printint32_bang()
{
	printf("Test test_printint32Bang\n");

	SStream OS = { 0 };
	SStream_Init(&OS);
	printInt32Bang(&OS, HEX_THRESHOLD + 1);
	CHECK_EQUAL_RET_FALSE(OS, "#0xa");
	SStream_Flush(&OS, NULL);

	printInt32Bang(&OS, HEX_THRESHOLD);
	CHECK_EQUAL_RET_FALSE(OS, "#9");
	SStream_Flush(&OS, NULL);

	printInt32Bang(&OS, -(HEX_THRESHOLD + 1));
	CHECK_EQUAL_RET_FALSE(OS, "#-0xa");
	SStream_Flush(&OS, NULL);

	printInt32Bang(&OS, -HEX_THRESHOLD);
	CHECK_EQUAL_RET_FALSE(OS, "#-9");
	SStream_Flush(&OS, NULL);

	printInt32Bang(&OS, INT32_MAX);
	CHECK_EQUAL_RET_FALSE(OS, "#0x7fffffff");
	SStream_Flush(&OS, NULL);

	printInt32Bang(&OS, INT32_MIN);
	CHECK_EQUAL_RET_FALSE(OS, "#-0x80000000");
	SStream_Flush(&OS, NULL);
	return true;
}

bool test_printint64_bang()
{
	printf("Test test_printint64Bang\n");

	SStream OS = { 0 };
	SStream_Init(&OS);
	printInt64Bang(&OS, HEX_THRESHOLD + 1);
	CHECK_EQUAL_RET_FALSE(OS, "#0xa");
	SStream_Flush(&OS, NULL);

	printInt64Bang(&OS, HEX_THRESHOLD);
	CHECK_EQUAL_RET_FALSE(OS, "#9");
	SStream_Flush(&OS, NULL);

	printInt64Bang(&OS, -(HEX_THRESHOLD + 1));
	CHECK_EQUAL_RET_FALSE(OS, "#-0xa");
	SStream_Flush(&OS, NULL);

	printInt64Bang(&OS, -HEX_THRESHOLD);
	CHECK_EQUAL_RET_FALSE(OS, "#-9");
	SStream_Flush(&OS, NULL);

	printInt64Bang(&OS, INT64_MAX);
	CHECK_EQUAL_RET_FALSE(OS, "#0x7fffffffffffffff");
	SStream_Flush(&OS, NULL);

	printInt64Bang(&OS, INT64_MIN);
	CHECK_EQUAL_RET_FALSE(OS, "#-0x8000000000000000");
	SStream_Flush(&OS, NULL);
	return true;
}

bool test_printuint32_bang()
{
	printf("Test test_printuint32Bang\n");

	SStream OS = { 0 };
	SStream_Init(&OS);
	printUInt32Bang(&OS, HEX_THRESHOLD + 1);
	CHECK_EQUAL_RET_FALSE(OS, "#0xa");
	SStream_Flush(&OS, NULL);

	printUInt32Bang(&OS, HEX_THRESHOLD);
	CHECK_EQUAL_RET_FALSE(OS, "#9");
	SStream_Flush(&OS, NULL);

	printUInt32Bang(&OS, UINT32_MAX);
	CHECK_EQUAL_RET_FALSE(OS, "#0xffffffff");
	SStream_Flush(&OS, NULL);
	return true;
}

bool test_printuint64_bang()
{
	printf("Test test_printuint64Bang\n");

	SStream OS = { 0 };
	SStream_Init(&OS);
	printUInt64Bang(&OS, HEX_THRESHOLD + 1);
	CHECK_EQUAL_RET_FALSE(OS, "#0xa");
	SStream_Flush(&OS, NULL);

	printUInt64Bang(&OS, HEX_THRESHOLD);
	CHECK_EQUAL_RET_FALSE(OS, "#9");
	SStream_Flush(&OS, NULL);

	printUInt64Bang(&OS, UINT64_MAX);
	CHECK_EQUAL_RET_FALSE(OS, "#0xffffffffffffffff");
	SStream_Flush(&OS, NULL);
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
	if (result) {
		printf("All tests passed.\n");
	} else {
		printf("Some tests failed.\n");
	}
	return result ? 0 : -1;
}

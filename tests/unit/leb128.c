// Copyright © 2026 bibi samina <sam@bugqore.com>
// SPDX-License-Identifier: BSD-3

#include "unit_test.h"
#include "../LEB128.h"
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static bool check_sleb128(const uint8_t *bytes, size_t len, int64_t expected,
			  unsigned expected_n)
{
	unsigned n = 0;
	leb128_err error = LEB128_ERR_TOO_BIG;
	int64_t value = decodeSLEB128(bytes, &n, bytes + len, &error);
	if (error != LEB128_OK) {
		printf("Unexpected error: %d\n", error);
		return false;
	}
	if (value != expected) {
		printf("Value %" PRId64 " != %" PRId64 "\n", value, expected);
		return false;
	}
	if (n != expected_n) {
		printf("Length %u != %u\n", n, expected_n);
		return false;
	}
	return true;
}

static bool check_sleb128_error(const uint8_t *bytes, size_t len,
				leb128_err expected_error, unsigned expected_n)
{
	unsigned n = 0;
	leb128_err error = LEB128_OK;
	int64_t value = decodeSLEB128(bytes, &n, bytes + len, &error);
	if (error != expected_error) {
		printf("Error %d != %d\n", error, expected_error);
		return false;
	}
	if (value != 0) {
		printf("Error value %" PRId64 " != 0\n", value);
		return false;
	}
	if (n != expected_n) {
		printf("Error length %u != %u\n", n, expected_n);
		return false;
	}
	return true;
}

#define CHECK_SLEB128(expected, expected_n, ...) \
	do { \
		const uint8_t bytes__[] = { __VA_ARGS__ }; \
		if (!check_sleb128(bytes__, sizeof(bytes__), expected, \
				   expected_n)) { \
			return false; \
		} \
	} while (0)

#define CHECK_SLEB128_ERROR(expected_error, expected_n, ...) \
	do { \
		const uint8_t bytes__[] = { __VA_ARGS__ }; \
		if (!check_sleb128_error(bytes__, sizeof(bytes__), \
					 expected_error, expected_n)) { \
			return false; \
		} \
	} while (0)

static bool test_decode_sleb128()
{
	printf("Test test_decode_sleb128\n");

	// Single byte.
	CHECK_SLEB128(0, 1, 0x00);
	CHECK_SLEB128(1, 1, 0x01);
	CHECK_SLEB128(63, 1, 0x3f);
	CHECK_SLEB128(-1, 1, 0x7f);
	CHECK_SLEB128(-64, 1, 0x40);

	// Multiple bytes.
	CHECK_SLEB128(64, 2, 0xc0, 0x00);
	CHECK_SLEB128(-65, 2, 0xbf, 0x7f);
	CHECK_SLEB128(-128, 2, 0x80, 0x7f);
	CHECK_SLEB128(-123456, 3, 0xc0, 0xbb, 0x78);

	// Non canonical padding is accepted.
	CHECK_SLEB128(0, 3, 0x80, 0x80, 0x00);
	CHECK_SLEB128(-1, 3, 0xff, 0xff, 0x7f);

	// Only the bytes up to the terminating byte are consumed.
	CHECK_SLEB128(-1, 1, 0x7f, 0x01, 0x02);

	// 32-bit limits.
	CHECK_SLEB128(INT32_MAX, 5, 0xff, 0xff, 0xff, 0xff, 0x07);
	CHECK_SLEB128(INT32_MIN, 5, 0x80, 0x80, 0x80, 0x80, 0x78);
	CHECK_SLEB128(UINT32_MAX, 5, 0xff, 0xff, 0xff, 0xff, 0x0f);

	// 64-bit limits.
	CHECK_SLEB128(INT64_MAX, 10, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		      0xff, 0xff, 0x00);
	CHECK_SLEB128(INT64_MIN, 10, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
		      0x80, 0x80, 0x7f);
	CHECK_SLEB128(-1, 11, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		      0xff, 0xff, 0x7f);

	return true;
}

static bool test_decode_sleb128_errors()
{
	printf("Test test_decode_sleb128_errors\n");

	// Encoding extends past the end of the buffer.
	CHECK_SLEB128_ERROR(LEB128_ERR_PAST_END, 1, 0x80);
	CHECK_SLEB128_ERROR(LEB128_ERR_PAST_END, 2, 0xff, 0xff);
	{
		const uint8_t bytes[] = { 0x7f };
		if (!check_sleb128_error(bytes, 0, LEB128_ERR_PAST_END, 0)) {
			return false;
		}
	}

	// Value does not fit into int64_t.
	CHECK_SLEB128_ERROR(LEB128_ERR_TOO_BIG, 9, 0xff, 0xff, 0xff, 0xff, 0xff,
			    0xff, 0xff, 0xff, 0xff, 0x01);
	CHECK_SLEB128_ERROR(LEB128_ERR_TOO_BIG, 9, 0x80, 0x80, 0x80, 0x80, 0x80,
			    0x80, 0x80, 0x80, 0x80, 0x7e);
	CHECK_SLEB128_ERROR(LEB128_ERR_TOO_BIG, 10, 0x80, 0x80, 0x80, 0x80,
			    0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f);
	CHECK_SLEB128_ERROR(LEB128_ERR_TOO_BIG, 10, 0xff, 0xff, 0xff, 0xff,
			    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00);

	return true;
}

static bool test_decode_sleb128_null_args()
{
	printf("Test test_decode_sleb128_null_args\n");

	const uint8_t bytes[] = { 0x80, 0x7f };
	int64_t value = decodeSLEB128(bytes, NULL, bytes + sizeof(bytes), NULL);
	if (value != -128) {
		printf("Value %" PRId64 " != -128\n", value);
		return false;
	}

	// A truncated encoding must not be read past the end even if the
	// caller does not ask for the error.
	value = decodeSLEB128(bytes, NULL, bytes + 1, NULL);
	if (value != 0) {
		printf("Truncated value %" PRId64 " != 0\n", value);
		return false;
	}

	return true;
}

int main()
{
	bool result = true;
	result &= test_decode_sleb128();
	result &= test_decode_sleb128_errors();
	result &= test_decode_sleb128_null_args();

	if (result) {
		printf("All tests passed.\n");
	} else {
		printf("Some tests failed.\n");
	}
	return result ? 0 : -1;
}

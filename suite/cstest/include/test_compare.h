// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_COMPARE_H
#define TEST_COMPARE_H

/// An integer encoding a boolean value from the test files.
/// libcyaml saves 0 by default, if an optional value was not set.
/// Due to that, boolean values are represented as integer with the
/// interpretation:
///
/// = 0 => unset
/// < 0 => false
/// > 0 => true
typedef int tbool;

/// Compares two tbool values representing a Boolean of the form:
/// == 0 = unset
/// < 0 = false
/// > 0 = true.
/// It returns with @ret_val, if expected is set but the values mismatch.
#define compare_tbool_ret(actual, expected, ret_val) \
	if (expected != 0 && actual != expected) { \
		fprintf(stderr, #actual " != " #expected ": %" PRId32 " != %" PRId32 "\n", \
			actual, expected); \
		return ret_val; \
	}

/// Compares two uint8_t values.
/// It returns with @ret_val if they mismatch.
#define compare_uint8_ret(actual, expected, ret_val) \
	if (actual != expected) { \
		fprintf(stderr, #actual " != " #expected ": %" PRId8 " != %" PRId8 "\n", \
			actual, expected); \
		return ret_val; \
	}

#endif // TEST_COMPARE_H

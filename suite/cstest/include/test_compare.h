// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#ifndef TEST_COMPARE_H
#define TEST_COMPARE_H

#include <stdint.h>
#include "test_mapping.h"
#include "../../../utils.h"

/// An integer encoding a boolean value from the test files.
/// libcyaml saves 0 by default, if an optional value was not set.
/// Due to that, boolean values are represented as integer with the
/// interpretation:
///
/// = 0 => unset
/// < 0 => false
/// > 0 => true
typedef int32_t tbool;

#define CYAML_FIELD_TBOOL(name, flags, type, member) \
	CYAML_FIELD_INT(name, flags, type, member)

/// Compares the @actual bool against the @expected tbool:
/// It returns with @ret_val, if expected is set but the values mismatch.
#define compare_tbool_ret(actual, expected, ret_val) \
	if (expected != 0 && \
	    ((actual && expected <= 0) || (!actual && expected >= 0))) { \
		fprintf(stderr, \
			#actual " is %s but expected is %" PRId32 \
				" (=0 unset, >0 true, <0 false)\n", \
			actual ? "true" : "false", expected); \
		return ret_val; \
	}

/// Compares two unsigned int values.
/// It returns with @ret_val if they mismatch.
#define compare_uint_ret(actual, expected, ret_val) \
	if (((unsigned int)actual) != ((unsigned int)expected)) { \
		fprintf(stderr, \
			#actual " != " #expected ": 0x%" PRIx32 \
				" != 0x%" PRIx32 "\n", \
			actual, expected); \
		return ret_val; \
	}

/// Compares two uint8_t values.
/// It returns with @ret_val if they mismatch.
#define compare_uint8_ret(actual, expected, ret_val) \
	if (((uint8_t)actual) != ((uint8_t)expected)) { \
		fprintf(stderr, \
			#actual " != " #expected ": %" PRId8 " != %" PRId8 \
				"\n", \
			actual, expected); \
		return ret_val; \
	}

/// Compares two uint16_t values.
/// It returns with @ret_val if they mismatch.
#define compare_uint16_ret(actual, expected, ret_val) \
	if (((uint16_t)actual) != ((uint16_t)expected)) { \
		fprintf(stderr, \
			#actual " != " #expected ": 0x%" PRIx16 \
				" != 0x%" PRIx16 "\n", \
			actual, expected); \
		return ret_val; \
	}

/// Compares two uint32_t values.
/// It returns with @ret_val if they mismatch.
#define compare_uint32_ret(actual, expected, ret_val) \
	if (((uint32_t)actual) != ((uint32_t)expected)) { \
		fprintf(stderr, \
			#actual " != " #expected ": 0x%" PRIx32 \
				" != 0x%" PRIx32 "\n", \
			actual, expected); \
		return ret_val; \
	}

/// Compares two uint64_t values.
/// It returns with @ret_val if they mismatch.
#define compare_uint64_ret(actual, expected, ret_val) \
	if (((uint64_t)actual) != ((uint64_t)expected)) { \
		fprintf(stderr, \
			#actual " != " #expected ": 0x%" PRIx64 \
				" != 0x%" PRIx64 "\n", \
			actual, expected); \
		return ret_val; \
	}

/// Compares two int values.
/// It returns with @ret_val if they mismatch.
#define compare_int_ret(actual, expected, ret_val) \
	if (((int)actual) != ((int)expected)) { \
		fprintf(stderr, \
			#actual " != " #expected ": 0x%" PRIx32 \
				" != 0x%" PRIx32 "\n", \
			actual, expected); \
		return ret_val; \
	}

/// Compares two int8_t values.
/// It returns with @ret_val if they mismatch.
#define compare_int8_ret(actual, expected, ret_val) \
	if (((int8_t)actual) != ((int8_t)expected)) { \
		fprintf(stderr, \
			#actual " != " #expected ": 0x%" PRIx8 " != 0x%" PRIx8 \
				"\n", \
			actual, expected); \
		return ret_val; \
	}

/// Compares two int16_t values.
/// It returns with @ret_val if they mismatch.
#define compare_int16_ret(actual, expected, ret_val) \
	if (((int16_t)actual) != ((int16_t)expected)) { \
		fprintf(stderr, \
			#actual " != " #expected ": 0x%" PRIx16 \
				" != 0x%" PRIx16 "\n", \
			actual, expected); \
		return ret_val; \
	}

/// Compares two int32_t values.
/// It returns with @ret_val if they mismatch.
#define compare_int32_ret(actual, expected, ret_val) \
	if (((int32_t)actual) != ((int32_t)expected)) { \
		fprintf(stderr, \
			#actual " != " #expected ": 0x%" PRIx32 \
				" != 0x%" PRIx32 "\n", \
			actual, expected); \
		return ret_val; \
	}

/// Compares two int64_t values.
/// It returns with @ret_val if they mismatch.
#define compare_int64_ret(actual, expected, ret_val) \
	if (((int64_t)actual) != ((int64_t)expected)) { \
		fprintf(stderr, \
			#actual " != " #expected ": 0x%" PRIx64 \
				" != 0x%" PRIx64 "\n", \
			actual, expected); \
		return ret_val; \
	}

/// Compares two floating point values.
/// It returns with @ret_val if they mismatch.
#define compare_fp_ret(actual, expected, ret_val) \
	if (actual != expected) { \
		fprintf(stderr, #actual " != " #expected ": %f != %f\n", \
			actual, expected); \
		return ret_val; \
	}

/// Compares enum id.
/// Actual is the value, expected is the enum idetifer as string.
/// It returns with @ret_val if they mismatch.
#define compare_enum_ret(actual, expected, ret_val) \
	if (expected) { \
		bool found = false; \
		uint32_t eval = enum_map_bin_search( \
			cs_enum_map, ARR_SIZE(cs_enum_map), expected, &found); \
		if (expected && (actual != eval || !found)) { \
			fprintf(stderr, \
				#actual " != " #expected ": %" PRId32 \
					" != %s%s\n", \
				actual, expected, \
				found ? "" : " <== id not found. Consider adding it in test_mapping.h::cs_enum_map."); \
			return ret_val; \
		} \
	}

/// Checks if all bit flags in @expected are set in @actual.
/// Actual is the value with all bits set.
/// @expected is a list the @len enum identifiers as string.
/// It returns with @ret_val if they mismatch.
#define compare_bit_flags_ret(actual, expected, len, ret_val) \
	if (expected) { \
		for (size_t cmp_i = 0; cmp_i < len; ++cmp_i) { \
			bool found = false; \
			uint32_t eval = enum_map_bin_search( \
				cs_enum_map, ARR_SIZE(cs_enum_map), \
				expected[cmp_i], &found); \
			if (!(actual & eval) || !found) { \
				fprintf(stderr, \
					#actual " != " #expected ": %" PRId32 \
						" != %s%s\n", \
					actual, expected[cmp_i], \
					found ? " <== Flag not set" : \
						" <== id not found"); \
				return ret_val; \
			} \
		} \
	}

/// Checks if all bit flags in @expected are set in @actual.
/// Actual is the value with all bits set.
/// @expected is a list the @len enum identifiers as string.
/// It returns with @ret_val if they mismatch.
#define compare_bit_flags_64_ret(actual, expected, len, ret_val) \
	if (expected) { \
		for (size_t cmp_i = 0; cmp_i < len; ++cmp_i) { \
			bool found = false; \
			uint64_t eval = enum_map_bin_search( \
				cs_enum_map, ARR_SIZE(cs_enum_map), \
				expected[cmp_i], &found); \
			if (!(actual & eval) || !found) { \
				fprintf(stderr, \
					#actual " != " #expected ": %" PRId64 \
						" != %s%s\n", \
					actual, expected[cmp_i], \
					found ? " <== Flag not set" : \
						" <== id not found"); \
				return ret_val; \
			} \
		} \
	}

/// Compares register names.
/// Actual is the register id, expected is name as string.
/// It returns with @ret_val if they mismatch.
#define compare_reg_ret(handle, actual, expected, ret_val) \
	if (expected) { \
		const char *reg_name = cs_reg_name(handle, actual); \
		if (expected && !strings_match(reg_name, expected)) { \
			fprintf(stderr, \
				#actual " != " #expected ": '%s' != '%s'\n", \
				reg_name, expected); \
			return ret_val; \
		} \
	}

#endif // TEST_COMPARE_H

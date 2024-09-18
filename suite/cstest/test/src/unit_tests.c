// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "../../../utils.h"
#include "../../../Mapping.h"
#include "test_mapping.h"
#include <stdint.h>

bool test_cs_enum_get_val()
{
	bool found = false;
	// Get first value
	uint32_t val = enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map),
					   "AAAAAAAAAAAAAAAAAAAAAAAAAA",
					   &found);
	if (!found || val != 0xffffff) {
		fprintf(stderr,
			"enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map), AAAAAAAAAAAAAAAAAAAAAAAAAA) failed is %d.\n",
			val);
		return false;
	}
	// Get second value
	val = enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map),
					   "AAAAAAAAAAAAAAAAAAAAAAAAAB",
					   &found);
	if (!found || val != 0xffffff) {
		fprintf(stderr,
			"enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map), AAAAAAAAAAAAAAAAAAAAAAAAAB) failed is %d.\n",
			val);
		return false;
	}

	// Get second to last value
	val = enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map),
				  "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzx", &found);
	if (!found || val != 0xffffff) {
		fprintf(stderr,
			"enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map), zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzx) failed is %d.\n",
			val);
		return false;
	}

	// Get last value
	val = enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map),
				  "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", &found);
	if (!found || val != 0xffffff) {
		fprintf(stderr,
			"enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map), zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz) failed is %d.\n",
			val);
		return false;
	}

	// Some values
	val = enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map),
				  "AArch64CC_EQ", &found);
	if (!found || val != AArch64CC_EQ) {
		fprintf(stderr,
			"enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map), AArch64CC_EQ) failed is %d.\n",
			val);
		return false;
	}
	val = enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map),
				  "AArch64CC_Invalid", &found);
	if (!found || val != AArch64CC_Invalid) {
		fprintf(stderr,
			"enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map), AArch64CC_In) failed is %d.\n",
			val);
		return false;
	}

	enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map), "\0", &found);
	if (found) {
		fprintf(stderr, "Out of bounds failed.\n");
		return false;
	}

	enum_map_bin_search(cs_enum_map, ARR_SIZE(cs_enum_map),
			    "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~",
			    &found);
	if (found) {
		fprintf(stderr, "Out of bounds failed.\n");
		return false;
	}

	return true;
}

int main()
{
	bool success = true;
	success &= test_cs_enum_get_val();
	printf("test_cs_enum_get_val: %s\n", success ? "ok" : "fail");
	return success ? 0 : 1;
}

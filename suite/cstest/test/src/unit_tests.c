// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_mapping.h"
#include <stdint.h>

bool test_cs_enum_get_val()
{
	bool found = false;
	// Get first value
	uint32_t val = cs_enum_get_val("AAAAAAAAAAAAAAAAAAAAAAAAAA", &found);
	if (!found || val != 0xffffff) {
		fprintf(stderr,
			"cs_enum_get_val(AAAAAAAAAAAAAAAAAAAAAAAAAA) failed is %d.\n",
			val);
		return false;
	}

	// Get last value
	val = cs_enum_get_val("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", &found);
	if (!found || val != 0xffffff) {
		fprintf(stderr,
			"cs_enum_get_val(zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz) failed is %d.\n",
			val);
		return false;
	}

	// Some values
	val = cs_enum_get_val("AArch64CC_EQ", &found);
	if (!found || val != AArch64CC_EQ) {
		fprintf(stderr, "cs_enum_get_val(AArch64CC_EQ) failed is %d.\n",
			val);
		return false;
	}
	val = cs_enum_get_val("AArch64CC_Invalid", &found);
	if (!found || val != AArch64CC_Invalid) {
		fprintf(stderr, "cs_enum_get_val(AArch64CC_In) failed is %d.\n",
			val);
		return false;
	}

	cs_enum_get_val("\0", &found);
	if (found) {
		fprintf(stderr, "Out of bounds failed.\n");
		return false;
	}

	cs_enum_get_val("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~", &found);
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

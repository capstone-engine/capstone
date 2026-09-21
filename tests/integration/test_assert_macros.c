// SPDX-FileCopyrightText: 2025 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: LGPL-3.0-only

// Has to be built as Release build or with CAPSTONE_ASSERTION_WARNINGS.

#include <capstone/platform.h>
#include <capstone/capstone.h>

// Test: https://github.com/capstone-engine/capstone/issues/2791
static bool test_cs_reg_null_case()
{
	csh handle;
	if (cs_open(CS_ARCH_AARCH64, (cs_mode)0, &handle) != CS_ERR_OK) {
		printf("Open failed\n");
		return false;
	}
	// Invalid register id 0 should return NULL.
	if (cs_reg_name(handle, 0) != NULL) {
		printf("NULL check failed\n");
		return false;
	}
	cs_close(&handle);
	return true;
}

static bool test_version_macros()
{
	bool relations = CS_VERSION_ALPHA < CS_VERSION_BETA;
	relations &= CS_VERSION_ALPHA9 < CS_VERSION_BETA;
	relations &= CS_VERSION_BETA < CS_VERSION_STABLE;
	return relations;
}

int main()
{
	bool result = true;
	result &= test_cs_reg_null_case();
	result &= test_version_macros();

	return result ? 0 : -1;
}

// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3.0-Clause

#include "compat.h"
#include <stdio.h>

int main()
{
	if (arm64() != 0) {
		printf("Failed the arm64 compatibility header test.\n");
		return -1;
	}
	if (sysz() != 0) {
		printf("Failed the sysz compatibility header test.\n");
		return -1;
	}
}

// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "some_header_I.h"

#include <some_system_header.h>

#define MACRO_A 0
#define MACRO_B 0

#define FCN_MACRO_A(x) function_a(x)
#define FCN_MACRO_B(x) \
	function_b(x)

int main() {
	int x = 71;
	return x;
}

void function_a(int x) {
	return;
}

void function_b(int x) {
	return;
}

void only_in_old_I() {}
void only_in_old_II() {}

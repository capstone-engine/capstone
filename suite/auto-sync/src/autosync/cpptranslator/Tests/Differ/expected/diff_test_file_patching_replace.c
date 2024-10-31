// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

void function_a(int x) {
	return;
}

int patch_same_into_old_smaller() {
	// Should replace the same function in the old file.
	// At the same position between function_a and function_b.
	// Function has more line than the function in the old file.
	return 0xffffffff;
}

void function_b(int x) {
	return;
}

void patch_same_into_old_bigger() {
	// Should replace the same function in the old file.
	// At the same position after function_b.
	// Function has less lines than the function in the old file.
	return 1;
}

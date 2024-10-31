// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

void function_a(int x) {
	return;
}

int patch_new_into_old_I() {
	// Should be at the same position between function_b and patch_new_into_old_II
	// in the old file.
	// The order of these two new functions are switched because they are
	// applied backwards
	return 0xffffffff;
}

int patch_new_into_old_II() {
	// Should be at the same position between patch_new_into_old_I and function_a
	// in the old file.
	// The order of these two new functions are switched because they are
	// applied backwards
	return 0xffffffff;
}

void function_b(int x) {
	return;
}

void patch_beginning_of_file() {
	return;
}

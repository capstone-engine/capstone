// SPDX-FileCopyrightText: 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

void function_a(int x) {
	return;
}

int patch_same_into_old_smaller() {
	// Function has less lines than the function in the new file.
	return 0;
}

void function_b(int x) {
	return;
}

int patch_same_into_old_bigger() {
	// Function has more lines than the function in the new file.
	int o = 0;
	o += 1;
	o += 1;
	o += 1;
	o += 1;
	o += 1;
	return 0;
}

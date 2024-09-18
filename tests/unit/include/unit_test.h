// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#define CHECK_OS_EQUAL_RET_FALSE(OS, str) \
	do { \
		if (strcmp(OS.buffer, str) != 0) { \
			printf("OS.buffer != str\n"); \
			printf("OS.buffer: %s\n", OS.buffer); \
			printf("str      : %s\n", str); \
			return false; \
		} \
	} while (0);

#define CHECK_STR_EQUAL_RET_FALSE(a, b) \
	do { \
		if (strcmp(a, b) != 0) { \
			printf("%s != %s\n", a, b); \
			return false; \
		} \
	} while (0);

#define CHECK_NULL_RET_FALSE(ptr) \
	do { \
		if (ptr != NULL) { \
			printf(#ptr " is not NULL\n"); \
			return false; \
		} \
	} while (0);

#define CHECK_PTR_EQUAL_RET_FALSE(a, b) \
	do { \
		if (a != b) { \
			printf("%p != %p\n", a, b); \
			return false; \
		} \
	} while (0);

#define CHECK_INT_EQUAL_RET_FALSE(a, b) \
	do { \
		if (a != b) { \
			printf("%" PRId32 " != %" PRId32 "\n", a, b); \
			return false; \
		} \
	} while (0);

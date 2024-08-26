/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

#if defined(CAPSTONE_HAS_OSXKERNEL)
#include <Availability.h>
#include <libkern/libkern.h>
#else
#include <stdlib.h>
#endif
#include <string.h>
#include <ctype.h>

#include "utils.h"

// count number of positive members in a list.
// NOTE: list must be guaranteed to end in 0
unsigned int count_positive(const uint16_t *list)
{
	unsigned int c;

	for (c = 0; list[c] > 0; c++);

	return c;
}

// count number of positive members in a list.
// NOTE: list must be guaranteed to end in 0
unsigned int count_positive8(const unsigned char *list)
{
	unsigned int c;

	for (c = 0; list[c] > 0; c++);

	return c;
}

char *cs_strdup(const char *str)
{
	size_t len = strlen(str) + 1;
	void *new = cs_mem_malloc(len);

	if (new == NULL)
		return NULL;

	return (char *)memmove(new, str, len);
}

// we need this since Windows doesn't have snprintf()
int cs_snprintf(char *buffer, size_t size, const char *fmt, ...)
{
	int ret;

	va_list ap;
	va_start(ap, fmt);
	ret = cs_vsnprintf(buffer, size, fmt, ap);
	va_end(ap);

	return ret;
}

bool arr_exist8(unsigned char *arr, unsigned char max, unsigned int id)
{
	int i;

	for (i = 0; i < max; i++) {
		if (arr[i] == id)
			return true;
	}

	return false;
}

bool arr_exist(uint16_t *arr, unsigned char max, unsigned int id)
{
	int i;

	for (i = 0; i < max; i++) {
		if (arr[i] == id)
			return true;
	}

	return false;
}

/// Reads 4 bytes in the endian order specified in MI->cs->mode.
uint32_t readBytes32(MCInst *MI, const uint8_t *Bytes)
{
	assert(MI && Bytes);
	uint32_t Insn;
	if (MODE_IS_BIG_ENDIAN(MI->csh->mode))
		Insn = (Bytes[3] << 0) | (Bytes[2] << 8) | (Bytes[1] << 16) |
		       ((uint32_t)Bytes[0] << 24);
	else
		Insn = ((uint32_t)Bytes[3] << 24) | (Bytes[2] << 16) |
		       (Bytes[1] << 8) | (Bytes[0] << 0);
	return Insn;
}

/// Reads 2 bytes in the endian order specified in MI->cs->mode.
uint16_t readBytes16(MCInst *MI, const uint8_t *Bytes)
{
	assert(MI && Bytes);
	uint16_t Insn;
	if (MODE_IS_BIG_ENDIAN(MI->csh->mode))
		Insn = (Bytes[0] << 8) | Bytes[1];
	else
		Insn = (Bytes[1] << 8) | Bytes[0];

	return Insn;
}

/// @brief Appends the string @p src to the string @p str. @p src is put to lower case.
/// @param str The string to append to.
/// @param str_size The length of @p str
/// @param src The string to append.
/// Does nothing if any of the given strings is NULL.
void append_to_str_lower(char *str, size_t str_size, const char *src) {
	if (!str || !src) {
		return;
	}
	char *dest = strchr(str, '\0');
	if (dest - str >= str_size) {
		assert("str_size does not match actual string length." && 0);
		return;
	}

	int i = dest - str;
	for (int j = 0; (i < str_size) && (j < strlen(src)); ++i, ++j) {
		str[i] = tolower(src[j]);
	}
	str[i] = '\0';
}

/// @brief Appends the string @p src to the string @p str. @p src is put to lower case.
/// @param str The string to append to.
/// @param str_buf_size Size of buffer @p str.
/// @param src The string to append.
/// Does nothing if any of the given strings is NULL.
void append_to_str(char *str, size_t str_buf_size, const char *src) {
	if (!str || !src) {
		return;
	}
	if (strlen(str) + strlen(src) + 1 > str_buf_size) {
		assert("str_size does not match actual string length." && 0);
		return;
	}
	strncat(str, src, str_buf_size);
}


/// Allocates memory of strlen(str_a) + strlen(str_b) + 1 chars
/// and copies all strings into it as str_a + str_b
/// str_a is passed to realloc and should not be used afterwards.
/// Returns the result.
/// Returns NULL in case of failure.
char *str_append(char *str_a, const char *str_b) {
	if (!str_a || !str_b) {
		return NULL;
	}
	assert(str_a && str_b);
	size_t asize = strlen(str_a) + strlen(str_b) + 1;
	str_a = realloc(str_a, asize);
	strncat(str_a, str_b, asize);
	return str_a;
}

/// Returns the given byte sequence @bytes as a string of the
/// form: 0xXX,0xXX...
/// Returns NULL in case of failure.
char *byte_seq_to_str(uint8_t *bytes, size_t len)
{
	if (!bytes) {
		return NULL;
	}
	if (len == 0) {
		return NULL;
	}
	char single_byte[8] = { 0 };
	char *s = calloc(sizeof(char), 32);
	for (size_t i = 0; i < len; ++i) {
		cs_snprintf(single_byte, sizeof(single_byte), "0x%02" PRIx8 "%s",
			    bytes[i], i == len - 1 ? "" : ",");
		s = str_append(s, single_byte);
		if (!s) {
			return NULL;
		}
	}
	return s;
}

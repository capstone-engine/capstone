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

	for (c = 0; list[c] > 0; c++)
		;

	return c;
}

// count number of positive members in a list.
// NOTE: list must be guaranteed to end in 0
unsigned int count_positive8(const unsigned char *list)
{
	unsigned int c;

	for (c = 0; list[c] > 0; c++)
		;

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

/// @brief Checks if the @id is in the @table. @table has @table_size elements.
/// @param table The table with the values to compare to.
/// @param table_size The number elements in the table.
/// @param id The identifier to search for in the table.
/// @return True if @id is part of the @table, false otherwise.
bool arr_exist_int(int *table, size_t table_size, int id)
{
	int i;
	for (i = 0; i < table_size; i++) {
		if (table[i] == id)
			return true;
	}

	return false;
}

/// Reads 8 bytes in the endian order specified in MI->cs->mode.
uint64_t readBytes64(MCInst *MI, const uint8_t *Bytes)
{
	assert(MI && Bytes);
	uint64_t Insn;
	if (MODE_IS_BIG_ENDIAN(MI->csh->mode))
		Insn = ((uint64_t)Bytes[7] << 0) | ((uint64_t)Bytes[6] << 8) |
		       ((uint64_t)Bytes[5] << 16) | ((uint64_t)Bytes[4] << 24) |
		       ((uint64_t)Bytes[3] << 32) | ((uint64_t)Bytes[2] << 40) |
		       ((uint64_t)Bytes[1] << 48) | ((uint64_t)Bytes[0] << 56);
	else
		Insn = ((uint64_t)Bytes[7] << 56) | ((uint64_t)Bytes[6] << 48) |
		       ((uint64_t)Bytes[5] << 40) | ((uint64_t)Bytes[4] << 32) |
		       ((uint64_t)Bytes[3] << 24) | ((uint64_t)Bytes[2] << 16) |
		       ((uint64_t)Bytes[1] << 8) | ((uint64_t)Bytes[0] << 0);
	return Insn;
}

/// Reads 6 bytes in the endian order specified in MI->cs->mode.
uint64_t readBytes48(MCInst *MI, const uint8_t *Bytes)
{
	assert(MI && Bytes);
	uint64_t Insn;
	if (MODE_IS_BIG_ENDIAN(MI->csh->mode))
		Insn = ((uint64_t)Bytes[5] << 0) | ((uint64_t)Bytes[4] << 8) |
		       ((uint64_t)Bytes[3] << 16) | ((uint64_t)Bytes[2] << 24) |
		       ((uint64_t)Bytes[1] << 32) | ((uint64_t)Bytes[0] << 40);
	else
		Insn = ((uint64_t)Bytes[5] << 40) | ((uint64_t)Bytes[4] << 32) |
		       ((uint64_t)Bytes[3] << 24) | ((uint64_t)Bytes[2] << 16) |
		       ((uint64_t)Bytes[1] << 8) | ((uint64_t)Bytes[0] << 0);
	return Insn;
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

/// Reads 3 bytes in the endian order specified in MI->cs->mode.
uint32_t readBytes24(MCInst *MI, const uint8_t *Bytes)
{
	assert(MI && Bytes);
	uint32_t Insn;
	if (MODE_IS_BIG_ENDIAN(MI->csh->mode))
		Insn = (Bytes[2]) | (Bytes[1] << 8) |
		       ((uint32_t)Bytes[0] << 16);
	else
		Insn = (Bytes[2] << 16) | (Bytes[1] << 8) |
		       ((uint32_t)Bytes[0]);
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
void append_to_str_lower(char *str, size_t str_size, const char *src)
{
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

/// @brief Appends the string @p src to the string @p dest.
/// @p dest is can be a stack allocated buffer.
///
/// @param dest The string to append to.
/// @param dest_buf_size Size of buffer @p str.
/// @param src The string to append.
/// Does nothing if any of the given strings is NULL.
void str_append_no_realloc(char *dest, size_t dest_buf_size, const char *src)
{
	if (!dest || !src) {
		return;
	}
	if (strlen(dest) + strlen(src) + 1 > dest_buf_size) {
		printf("str_size does not match actual string length.\n");
		return;
	}
	strncat(dest, src, dest_buf_size - strlen(dest));
}

/// Allocates memory of strlen(str_a) + strlen(str_b) + 1 chars
/// and copies all strings into it as str_a + str_b
/// str_a is passed to realloc and should not be used afterwards.
/// Returns the concatenated string.
/// Returns NULL in case of failure.
char *str_append(char *str_a, const char *str_b)
{
	if (!str_a || !str_b) {
		return NULL;
	}
	size_t asize = strlen(str_a) + strlen(str_b) + 1;
	str_a = realloc(str_a, asize);
	strncat(str_a, str_b, asize - strlen(str_a));
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
		cs_snprintf(single_byte, sizeof(single_byte),
			    "0x%02" PRIx8 "%s", bytes[i],
			    i == len - 1 ? "" : ", ");
		s = str_append(s, single_byte);
		if (!s) {
			return NULL;
		}
	}
	return s;
}

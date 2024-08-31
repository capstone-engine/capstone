/* Capstone testing regression */
/* By Do Minh Tuan <tuanit96@gmail.com>, 02-2019 */

#include <assert.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <capstone/platform.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <setjmp.h>
#include "cmocka.h"
#include "helper.h"

void add_str(char **src, const char *format, ...)
{
	char *tmp;
	size_t len1, len2;
	va_list args;

	tmp = (char *)malloc(sizeof(char) * 1000);
	va_start(args, format);
	vsprintf(tmp, format, args);
	va_end(args);

	len1 = strlen(*src);
	len2 = strlen(tmp);

	*src = (char *)realloc(*src, sizeof(char) * (len1 + len2 + 10));
	memcpy(*src + len1, tmp, len2 + 1);
	free(tmp);
}

void replace_hex(char *src, size_t src_len)
{
	char *tmp, *result, *found, *origin, *orig_found;
	int valid;
	unsigned long long int value;
	char *tmp_tmp;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';
	tmp = strdup(src);
	origin = tmp;

	while ((found = strstr(tmp, "0x")) != NULL) {
		orig_found = found;
		found += 2;
		value = 0;
		valid = 0;

		tmp_tmp = strndup(tmp, orig_found - tmp);
		while (*found != '\0' && isxdigit(*found)) {
			valid = 1;
			if (*found >= 'a' && *found <= 'f')
				value = value * 0x10 + (*found - 'a' + 10);
			else if (*found >= 'A' && *found <= 'F')
				value = value * 0x10 + (*found - 'A' + 10);
			else
				value = value * 0x10 + (*found - '0');
			found++;
		}

		if (valid == 1)
			add_str(&result, "%s%llu", tmp_tmp, value);
		else
			add_str(&result, "%s0x", tmp_tmp);
		tmp = found;
		free(tmp_tmp);
	}

	add_str(&result, "%s", tmp);
	if (strlen(result) >= src_len) {
		free(result);
		free(origin);
		fprintf(stderr,
			"[  Error   ] --- Buffer Overflow in replace_hex()\n");
		_fail(__FILE__, __LINE__);
	}

	strcpy(src, result);
	free(result);
	free(origin);
}

void replace_negative(char *src, size_t src_len, size_t arch_bits)
{
	char *tmp, *result, *found, *origin, *orig_found;
	int cnt, valid;
	char *value, *tmp_tmp;
	unsigned short int tmp_short;
	unsigned int tmp_int;
	unsigned long int tmp_long;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';
	tmp = strdup(src);
	origin = tmp;

	while ((found = strstr(tmp, "-")) != NULL) {
		orig_found = found;
		found++;
		valid = 0;

		value = strdup("-");
		cnt = 2;

		while (*found != '\0' && isdigit(*found)) {
			valid = 1;
			value = (char *)realloc(value, cnt + 1);
			value[cnt - 1] = *found;
			value[cnt] = '\0';
			cnt++;
			found++;
		}

		tmp_tmp = strndup(tmp, orig_found - tmp);
		if (valid == 1) {
			*orig_found = '\0';
			if (arch_bits == 16) {
				sscanf(value, "%hu", &tmp_short);
				add_str(&result, "%s%hu", tmp_tmp, tmp_short);
			} else if (arch_bits == 32) {
				sscanf(value, "%u", &tmp_int);
				add_str(&result, "%s%u", tmp_tmp, tmp_int);
			} else if (arch_bits == 64) {
				sscanf(value, "%lu", &tmp_long);
				add_str(&result, "%s%lu", tmp_tmp, tmp_long);
			}

		} else
			add_str(&result, "%s-", tmp_tmp);

		tmp = found;
		free(value);
		free(tmp_tmp);
	}

	add_str(&result, "%s", tmp);
	if (strlen(result) >= src_len) {
		fprintf(stderr,
			"[  Error   ] --- Buffer Overflow in replace_negative()\n");
		free(result);
		free(origin);
		_fail(__FILE__, __LINE__);
	}

	strcpy(src, result);
	free(result);
	free(origin);
}

void trim_str(char *str)
{
	char tmp[MAX_ASM_TXT_MEM];
	int start, end, j, i;

	start = 0;
	end = strlen(str) - 1;
	j = 0;
	while (start < strlen(str) && isspace(str[start]))
		start++;
	while (end >= 0 && isspace(str[end]))
		end--;

	for (i = start; i <= end; ++i)
		tmp[j++] = str[i];

	tmp[j] = '\0';
	strcpy(str, tmp);

	return;
}

/// Normalizes the usage of spaces in the given string.
/// It does:
/// - Replaces '\t' with '\s'
/// - Replace '\s\s+' with a single space.
void norm_spaces(char *str)
{
	assert(str);
	char *space_ptr = NULL;
	while ((space_ptr = strstr(str, "\t")) != NULL) {
		*space_ptr = ' ';
	}
	while ((space_ptr = strstr(str, "  ")) != NULL) {
		memmove(space_ptr, space_ptr + 1, strlen(space_ptr));
	}
	return;
}

void str_to_lower(char *str)
{
	assert(str);
	for (size_t i = 0; i < strlen(str); ++i)
		str[i] = tolower(str[i]);
}

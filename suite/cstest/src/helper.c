/* Capstone testing regression */
/* By Do Minh Tuan <tuanit96@gmail.com>, 02-2019 */

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

void replace_hex(char *src)
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
			if (*found >= 'a' && *found <='f')
				value = value*0x10 + (*found - 'a' + 10);
			else
				value = value*0x10 + (*found - '0');
			found++;
		}

		if (valid == 1) add_str(&result, "%s%llu", tmp_tmp, value);
		else add_str(&result, "%s0x", tmp_tmp);
		tmp = found;
		free(tmp_tmp);
	}

	add_str(&result, "%s", tmp);
	if (strlen(result) >= MAXMEM) {
		free(result);
		free(origin);
		fprintf(stderr, "[  Error   ] --- Buffer Overflow in replace_hex()\n");
		_fail(__FILE__, __LINE__);
	}

	strcpy(src, result);
	free(result);
	free(origin);
}

void replace_negative(char *src, int mode)
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
		found ++;
		valid = 0;
		
		value = strdup("-");
		cnt = 2;

		while (*found != '\0' && isdigit(*found)) {
			valid = 1;
			value = (char *)realloc(value, cnt + 1);
			value[cnt - 1] = *found;
			value[cnt] = '\0';
			cnt ++;
			found++;
		}

		tmp_tmp = strndup(tmp, orig_found - tmp);
		if (valid == 1) {
			*orig_found = '\0';
			if (mode == X86_16) {
				sscanf(value, "%hu", &tmp_short);
				add_str(&result, "%s%hu", tmp_tmp, tmp_short);
			} else if (mode == X86_32) {
				sscanf(value, "%u", &tmp_int);
				add_str(&result, "%s%u", tmp_tmp, tmp_int);
			} else if (mode == X86_64) {
				sscanf(value, "%lu", &tmp_long);
				add_str(&result, "%s%lu", tmp_tmp, tmp_long);
			}
		}
		else add_str(&result, "%s-", tmp_tmp);

		tmp = found;
		free(value);
		free(tmp_tmp);
	}

	add_str(&result, "%s", tmp);
	if (strlen(result) >= MAXMEM) {
		fprintf(stderr, "[  Error   ] --- Buffer Overflow in replace_negative()\n");
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
	char tmp[MAXMEM];
	int start, end, j, i;

	start = 0;
	end = strlen(str) - 1;
	j = 0;
	while (start < strlen(str) && isspace(str[start])) start++;
	while (end >= 0 && isspace(str[end])) end--;

	for (i = start; i <= end; ++i)
		tmp[j++] = str[i];

	tmp[j] = '\0';
	strcpy(str, tmp);

	return;
}

char *replace_decimal_imms(const char *src) {
	if (!src) {
		fail_msg("[!] src was NULL\n");
	}
	char result[1024] = { 0 };
	char *src_cpy = strdup(src);

	char *imm_ptr = NULL;
	char *endptr = src_cpy;
	while ((imm_ptr = strstr(endptr, "#")) != NULL) {
		imm_ptr += 1; // skip '#'
		if (strstr(imm_ptr, "0x") == imm_ptr) {
			// Hexadecimal number
			endptr = imm_ptr;
			continue;
		}
		long long val = strtoll(imm_ptr, &endptr, 10);
		if (strlen(result) >= sizeof(result) - 1) {
			free(src_cpy);
			fail_msg("asm_text too long for buffer.\n");
		}
		snprintf(result, sizeof(result), "%s0x%" PRIx64, result, (uint64_t)val);
	}
	free(src_cpy);
	return strdup(result);
}

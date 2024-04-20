/* Capstone testing regression */
/* By Do Minh Tuan <tuanit96@gmail.com>, 02-2019 */


#include "helper.h"
#include <string.h>

/// Splits a string into a list of strings, separated by the given delimeter.
/// The last element in the list is always a duplicate of @str.
/// @str is not freed.
/// The number of elements in the list is written to @size
char **split(char *str, const char *delim, int *size) {
	// Count the number of delimeters in the string
	uint32_t elem_cnt = 0;
	uint32_t delim_len = strlen(delim);
	char *split_at = NULL;
	char *str_iter = str;
	// Count delimeters
	while ((split_at = strstr(str_iter, delim)) != NULL) {
		str_iter = split_at + delim_len;
		if (split_at != str && split_at == str + strlen(str) - delim_len) {
			// Don't increment if the delimeter is at the very beginning or end of the string.
			elem_cnt++;
		}
	}
	uint32_t table_size = elem_cnt + 2; // Last element is the whole string

	char **list = calloc(table_size, sizeof(char*));
	uint32_t count = 0;
	while ((split_at = strstr(str_iter, delim)) != NULL) {
		unsigned sub_len = (split_at - str_iter);
		list[count] = calloc(sub_len + 1, sizeof(char));
		memcpy(list[count], str_iter, sub_len);
		count++;
		str_iter += sub_len + strlen(delim);
	}

	if (strlen(str) > 0) {
		list[count] = strdup(str);
		count++;
	}
	*size = count;
	return list;
}

void print_strs(char **list_str, int size)
{
	int i;

	printf("[+] Debug %d strings:\n", size);
	for (i = 0; i < size; ++i)
		printf("String %d'th: %s\n", i+1, list_str[i]);
}

void free_strs(char **list_str, int size)
{
	int i;
	for (i = 0; i < size; ++i)
		free(list_str[i]);

	free(list_str);
}

const char *get_filename_ext(const char *filename)
{
	const char *dot;

	dot = strrchr(filename, '.');
	if (!dot || dot == filename)
		return "";

	return dot + 1;
}

char *readfile(const char *filename)
{
	char *result;
	FILE *fp;
	int size;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		puts("No such file");
		exit(-1);
	}

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	rewind(fp);

	result = (char *)calloc(1, sizeof(char) * size + 1);
	fread(result, size, 1, fp);
	result[size] = '\0';

	fclose(fp);
	return result;
}

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
		fprintf(stderr, "[  Error   ] --- Buffer Overflow in replace_hex()\n");
		free(result);
		free(origin);
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

void listdir(const char *name, char ***files, int *num_files)
{
	DIR *dir;
	struct dirent *entry;
	int cnt;

	if (!(dir = opendir(name)))
		return;

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_type == DT_DIR) {
			char path[1024];
			if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
				continue;
			snprintf(path, sizeof(path), "%s/%s", name, entry->d_name);
			listdir(path, files, num_files);
		} else {
			cnt = *num_files;
			*files = (char **)realloc(*files, sizeof(char *) * (cnt + 1));
			(*files)[cnt] = (char *)malloc(sizeof(char) * ( strlen(name) + 1 + strlen(entry->d_name) + 10));
			sprintf((*files)[cnt], "%s/%s", name, entry->d_name);
			cnt ++;
			*num_files = cnt;
		}
	}

	closedir(dir);
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

void replace_tabs(char *str)
{
	char tmp[MAXMEM];
	bool space_char = false;

	int j = 0;
	for (int i = 0; i <= strlen(str); ++i) {
		if (str[i] == ' ' || str[i] == '\t') {
			space_char = true;
			continue;
		}
		if (space_char) {
			space_char = false;
			tmp[j++] = ' ';
		}

		tmp[j++] = str[i];
	}

	tmp[j] = '\0';
	strcpy(str, tmp);

	return;
}

#include "helper.h"

char **split(char *str, char *delim, int *size)
{
	char **result;
	char *token, *src;
	int cnt;

	cnt = 0;
	src = str;
	result = NULL;

	while ((token = strstr(src, delim)) != NULL) {
		result = (char **)realloc(result, sizeof(char *) * (cnt + 1));
		result[cnt] = (char *)calloc(1, sizeof(char) * (int)(token - src + 10));
		memcpy(result[cnt], src, token - src);
		result[cnt][token - src] = '\0';
		src = token + strlen(delim);
		cnt ++;
	}

	if ( strlen(src) > 0 ) {
		result = (char **)realloc(result, sizeof(char *) * (cnt + 1));
		result[cnt] = strdup(src);
		cnt ++;
	}

	*size = cnt;

	return result;
}

void print_strs(char **list_str, int size)
{
	int i;

	printf("[+] Debug %d strings:\n", size);
	for (i=0; i<size; ++i)
		printf("String %d'th: %s\n", i+1, list_str[i]);
}

void free_strs(char **list_str, int size)
{
	int i;
	for (i=0; i<size; ++i)
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
	char *tmp, *result, *found, *origin;
	int i;
	unsigned long long int value;

	result = (char *)malloc(sizeof(char));
	result[0] = '\0';
	tmp = strdup(src);
	origin = tmp;

	while ( (found = strstr(tmp, "0x")) != NULL ) {
		*found = '\0';
		found += 2;
		value = 0;

		while ( *found != '\0' && isxdigit(*found) ) {
			if (*found >= 'a' && *found <='f')
				value = value*0x10 + (*found - 'a' + 10);
			else
				value = value*0x10 + (*found - '0');
			//			printf("====> %d -- %llu\n", *found, value);
			found++;
		}

		add_str(&result, "%s%llu", tmp, value);
		tmp = found;
	}

	add_str(&result, "%s", tmp);
	if (strlen(result) >= MAXMEM) {
		fprintf(stderr, "[  Error   ] --- Buffer Overflow in replace_hex()\n");
		exit(-1);
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
			//			printf("[%s]\n", entry->d_name);
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

	for (i=start; i<=end; ++i)
		tmp[j++] = str[i];

	tmp[j] = '\0';
	strcpy(str, tmp);

	return;
}

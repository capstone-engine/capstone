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

char *readfile(char *filename)
{
	char *result;
	FILE *fp;
	int size;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		puts("No such file");
		exit(-1);
	}
	
	fseek(fp, 0L, SEEK_END);
	size = ftell(fp);
	rewind(fp);

	result = (char *)malloc(sizeof(char) * size);
	fread(result, size, 1, fp);
	
	fclose(fp);
	return result;
}

void addStr(char **src, const char *format, ...)
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

void replaceHex(char **src)
{
	char *tmp, *result, *found;
	int i;
	unsigned long long int value;
	
	result = (char *)malloc(sizeof(char));
	result[0] = '\0';
	tmp = *src;
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
		
		addStr(&result, "%s%llu", tmp, value);
		tmp = found;
	}
	addStr(&result, "%s", tmp);
	free(*src);
	*src = result;
}


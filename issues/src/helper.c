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

void addStr(char *src, char *dst)
{
	const size_t len1 = strlen(src);
    const size_t len2 = strlen(dst);
    src = (char *)realloc(src, sizeof(char) * (len1 + len2 + 1));

    memcpy(result + len1, dst, len2 + 1);
    return result;
}

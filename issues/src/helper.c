#include "helper.h"

char **split(char *str, char *delim, int *size)
{
	char **result;
	char *token;
	int cnt;

	token = strtok(str, delim);
	result = (char **)calloc(1, sizeof(char *) * 2);
	cnt = 0;	
	

	while (token != NULL) {
		result[cnt++] = token;
		token = strtok(NULL, delim);
		if (token != NULL)
			result = (char **)realloc(result, sizeof(char *) * (1 + cnt));
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

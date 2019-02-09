#ifndef HELPER_H
#define HELPER_H

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>

char **split(char *str, char *delim, int *size);
void print_strs(char **list_str, int size);
char *readfile(char *filename);
void free_strs(char **list_str, int size);
void addStr(char **src, const char *format, ...);
void replaceHex(char **src);

#endif /* HELPER_H */

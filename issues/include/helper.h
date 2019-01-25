#ifndef HELPER_H
#define HELPER_H

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

char **split(char *str, char *delim, int *size);
void print_strs(char **list_str, int size);
char *readfile(char *filename);

#endif /* HELPER_H */

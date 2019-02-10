#ifndef HELPER_H
#define HELPER_H

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <dirent.h>

char **split(char *str, char *delim, int *size);
void print_strs(char **list_str, int size);
char *readfile(const char *filename);
void free_strs(char **list_str, int size);
void add_str(char **src, const char *format, ...);
void replaceHex(char **src);
void listdir(const char *name, char ***files, int *num_files);
const char *get_filename_ext(const char *filename);
void trimwhitespace(char **str);

#endif /* HELPER_H */

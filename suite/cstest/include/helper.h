/* Capstone testing regression */
/* By Do Minh Tuan <tuanit96@gmail.com>, 02-2019 */


#ifndef HELPER_H
#define HELPER_H

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <dirent.h>
#include "capstone_test.h"

#define X86_16 0
#define X86_32 1
#define X86_64 2

char **split(char *str, char *delim, int *size);
void print_strs(char **list_str, int size);
void free_strs(char **list_str, int size);
void add_str(char **src, const char *format, ...);
void trim_str(char *src);
void replace_hex(char *src);
void replace_negative(char *src, int mode);
const char *get_filename_ext(const char *filename);

char *readfile(const char *filename);
void listdir(const char *name, char ***files, int *num_files);

#endif /* HELPER_H */

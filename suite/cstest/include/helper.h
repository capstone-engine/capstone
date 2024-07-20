/* Capstone testing regression */
/* By Do Minh Tuan <tuanit96@gmail.com>, 02-2019 */

#ifndef HELPER_H
#define HELPER_H

#include <stddef.h>

#define MAX_ASM_TXT_MEM 1024
#define X86_16 0
#define X86_32 1
#define X86_64 2

void trim_str(char *str);
void add_str(char **src, const char *format, ...);
void replace_hex(char *src, size_t src_len);
void replace_negative(char *src, size_t src_len, size_t arch_bits);
void norm_spaces(char *str);
void str_to_lower(char *str);

#endif /* HELPER_H */

/* Capstone testing regression */
/* By Do Minh Tuan <tuanit96@gmail.com>, 02-2019 */

#ifndef HELPER_H
#define HELPER_H

#define MAXMEM 1024
#define X86_16 0
#define X86_32 1
#define X86_64 2

void trim_str(char *str);
void add_str(char **src, const char *format, ...);
void replace_hex(char *src);
char *replace_decimal_imms(const char *src);
void replace_negative(char *src, int mode);

#endif /* HELPER_H */

#ifndef CS_ARM64_MAP_H
#define CS_ARM64_MAP_H

#include <stdio.h>

#include <capstone.h>

struct platform {
    cs_arch arch;
    cs_mode mode;
    unsigned char *code;
    size_t size;
    char *comment;
    cs_opt_type opt_type;
    cs_opt_value opt_value;
    cs_opt_type opt_skipdata;
    size_t skipdata;
};

static void print_string_hex(unsigned char *str, size_t len)
{
    unsigned char *c;

    printf("Code: ");
    for (c = str; c < str + len; c++) {
        printf("0x%02x ", *c & 0xff);
    }
    printf("\n");
}

#define PLATFORM(arch, mode, code, comment, ...) \
    { \
        CS_ARCH_ ## arch, \
        mode, \
        (unsigned char*)code, \
        sizeof(code) - 1, \
        comment, \
        ##__VA_ARGS__, \
    },

#endif
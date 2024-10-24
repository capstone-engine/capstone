#ifndef __AST2STR_HELPERS_H__
#define __AST2STR_HELPERS_H__

#include <stddef.h>
#include <stdint.h>

#include "riscv_helpers_rvconf.h"

#define RISCV_TEMP_BUFFER_MAX_LEN 32

#define spc(ps, plen, c)                                                       \
  *ps = " ";                                                                   \
  *plen = 1

#define opt_spc spc

#define sep(ps, plen, c)                                                       \
  *ps = " , ";                                                                 \
  *plen = 3

static inline void hex_bits(uint64_t bitvec, char **s, size_t *len,
                            uint8_t bvlen_bits, riscv_conf *conf) {
  char *str = *s;
  uint8_t str_len = bvlen_bits / 4;
  // is not divisible by 4?
  if ((bvlen_bits & 0x3) != 0) {
    str_len++;
  }
  str_len += 2; // for the '0x' in the beginning
  *len = str_len;

  for (uint8_t i = 0; i < bvlen_bits; i += 4) {
    char digit = (bitvec & 0xF) + 48;
    if (digit > '9') {
      digit += ('a' - ':');
    }

    str[--str_len] = digit;
    bitvec = bitvec >> 4;
  }
  str[0] = '0';
  str[1] = 'x';
}

#define DEF_HEX_BITS(n)                                                        \
  static inline void hex_bits_##n(uint64_t bitvec, char **s, size_t *len,      \
                                  riscv_conf *conf) {                          \
    hex_bits(bitvec, s, len, n, conf);                                         \
  }

DEF_HEX_BITS(1)
DEF_HEX_BITS(2)
DEF_HEX_BITS(3)
DEF_HEX_BITS(4)
DEF_HEX_BITS(5)
DEF_HEX_BITS(6)
DEF_HEX_BITS(7)
DEF_HEX_BITS(8)
DEF_HEX_BITS(9)
DEF_HEX_BITS(10)
DEF_HEX_BITS(11)
DEF_HEX_BITS(12)
DEF_HEX_BITS(13)
DEF_HEX_BITS(14)
DEF_HEX_BITS(15)
DEF_HEX_BITS(16)
DEF_HEX_BITS(17)
DEF_HEX_BITS(18)
DEF_HEX_BITS(19)
DEF_HEX_BITS(20)
DEF_HEX_BITS(21)
DEF_HEX_BITS(22)
DEF_HEX_BITS(23)
DEF_HEX_BITS(24)
DEF_HEX_BITS(25)
DEF_HEX_BITS(26)
DEF_HEX_BITS(27)
DEF_HEX_BITS(28)
DEF_HEX_BITS(29)
DEF_HEX_BITS(30)
DEF_HEX_BITS(31)
DEF_HEX_BITS(32)

void hex_bits_signed(uint64_t bitvec, char **s, size_t *len, uint8_t bvlen_bits,
                     riscv_conf *conf) {
  // is not negative ?
  if ((bitvec & (1 << (bvlen_bits - 1))) == 0) {
    hex_bits(bitvec, s, len, bvlen_bits, conf);
  } else {
    char *buff = *s;
    buff[0] = '-';
    buff++;
    hex_bits(~bitvec + 1ULL, &buff, len, bvlen_bits, conf);
  }
}

#define DEF_HEX_BITS_SIGNED(n)                                                 \
  static inline void hex_bits_signed_##n(uint64_t bitvec, char **s,            \
                                         size_t *len, riscv_conf *conf) {      \
    hex_bits_signed(bitvec, s, len, n, conf);                                  \
  }

DEF_HEX_BITS_SIGNED(1);
DEF_HEX_BITS_SIGNED(2);
DEF_HEX_BITS_SIGNED(3);
DEF_HEX_BITS_SIGNED(4);
DEF_HEX_BITS_SIGNED(5);
DEF_HEX_BITS_SIGNED(6);
DEF_HEX_BITS_SIGNED(7);
DEF_HEX_BITS_SIGNED(8);
DEF_HEX_BITS_SIGNED(9);
DEF_HEX_BITS_SIGNED(10);
DEF_HEX_BITS_SIGNED(11);
DEF_HEX_BITS_SIGNED(12);
DEF_HEX_BITS_SIGNED(13);
DEF_HEX_BITS_SIGNED(14);
DEF_HEX_BITS_SIGNED(15);
DEF_HEX_BITS_SIGNED(16);
DEF_HEX_BITS_SIGNED(17);
DEF_HEX_BITS_SIGNED(18);
DEF_HEX_BITS_SIGNED(19);
DEF_HEX_BITS_SIGNED(20);
DEF_HEX_BITS_SIGNED(21);
DEF_HEX_BITS_SIGNED(22);
DEF_HEX_BITS_SIGNED(23);
DEF_HEX_BITS_SIGNED(24);
DEF_HEX_BITS_SIGNED(25);
DEF_HEX_BITS_SIGNED(26);
DEF_HEX_BITS_SIGNED(27);
DEF_HEX_BITS_SIGNED(28);
DEF_HEX_BITS_SIGNED(29);
DEF_HEX_BITS_SIGNED(30);
DEF_HEX_BITS_SIGNED(31);
DEF_HEX_BITS_SIGNED(32);

// TODO
void freg_or_reg_name(uint64_t regidx, char **s, size_t *len,
                      riscv_conf *conf) {
  *s = "";
  *len = 0;
}

void maybe_vmask(uint8_t vm, char **s, size_t *len, riscv_conf *conf) {
  if (vm) {
    *s = "";
    *len = 0;
    return;
  }
  *s = " , v0.t";
  *len = 7;
}

void maybe_ta_flag(uint8_t ta, char **s, size_t *len, riscv_conf *conf) {
  if (ta) {
    *s = "ta";
    *len = 2;
    return;
  }
  *s = "";
  *len = 0;
}

void maybe_ma_flag(uint8_t ma, char **s, size_t *len, riscv_conf *conf) {
  if (ma) {
    *s = "ma";
    *len = 2;
    return;
  }
  *s = "";
  *len = 0;
}

void maybe_lmul_flag(uint8_t lmul, char **s, size_t *len, riscv_conf *conf) {
  switch (lmul) {
  case 0x0:
    *s = "";
    *len = 0;
    return;

  case 0x5:
    *s = " , mf8";
    *len = 6;
    return;

  case 0x6:
    *s = " , mf4";
    *len = 6;
    return;

  case 0x7:
    *s = " , mf2";
    *len = 6;
    return;

  case 0x1:
    *s = " , m2";
    *len = 5;
    return;

  case 0x2:
    *s = " , m4";
    *len = 5;
    return;

  case 0x3:
    *s = " , m8";
    *len = 5;
    return;
  }
}

// TODO
void csr_name_map(uint32_t csr, char **s, size_t *len, riscv_conf *conf) {
  *s = "";
  *len = 0;
}

void fence_bits(uint8_t bits, char **s, size_t *len, riscv_conf *conf) {
  char *buff = *s;
  int length = 0;
  if (bits & 0x8) {
    buff[length++] = 'i';
  }
  if (bits & 0x4) {
    buff[length++] = 'o';
  }
  if (bits & 0x2) {
    buff[length++] = 'r';
  }
  if (bits & 0x1) {
    buff[length++] = 'w';
  }
  *len = length;
}
#endif
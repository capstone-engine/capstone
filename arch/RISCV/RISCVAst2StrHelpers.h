#ifndef __AST2STR_HELPERS_H__
#define __AST2STR_HELPERS_H__

#include <stddef.h>
#include <stdint.h>

#include "RISCVRVContextHelpers.h"
#include "../../SStream.h"
#include "../../cs_priv.h"

#define RISCV_TEMP_BUFFER_MAX_LEN 32

#define spc(ss, c) SStream_concat1(ss, ' ')

#define opt_spc spc

#define sep(ss, c) SStream_concat(ss, " , ")

static inline void hex_bits(uint64_t bitvec, uint8_t bvlen_bits, SStream *ss,
                            RVContext *ctx) {
  char str[25] = {0};
  uint8_t str_len = bvlen_bits / 4;
  // is not divisible by 4?
  if ((bvlen_bits & 0x3) != 0) {
    str_len++;
  }
  str_len += 2; // for the '0x' in the beginning

  CS_ASSERT(str_len > 0);
  CS_ASSERT(str_len < 24);

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
  SStream_concat(ss, "%s", str);
}

#define DEF_HEX_BITS(n)                                                        \
  static inline void hex_bits_##n(uint64_t bitvec, SStream *ss,                \
                                  RVContext *ctx) {                            \
    hex_bits(bitvec, n, ss, ctx);                                              \
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

void hex_bits_signed(uint64_t bitvec, uint8_t bvlen_bits, SStream *ss,
                     RVContext *ctx) {
  // is not negative ?
  if ((bitvec & (1 << (bvlen_bits - 1))) == 0) {
    hex_bits(bitvec, bvlen_bits, ss, ctx);
  } else {
    SStream_concat1(ss, '-');
    hex_bits(bitvec, bvlen_bits, ss, ctx);
  }
}

#define DEF_HEX_BITS_SIGNED(n)                                                 \
  static inline void hex_bits_signed_##n(uint64_t bitvec, SStream *ss,         \
                                         RVContext *ctx) {                     \
    hex_bits_signed(bitvec, n, ss, ctx);                                       \
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
void freg_or_reg_name(uint64_t regidx, SStream *ss, RVContext *ctx) {}

void maybe_vmask(uint8_t vm, SStream *ss, RVContext *ctx) {
  if (vm) {
    return;
  }
  SStream_concat(ss, " , v0.t");
}

void maybe_ta_flag(uint8_t ta, SStream *ss, RVContext *ctx) {
  if (ta) {
    SStream_concat(ss, "ta");
    return;
  }
}

void maybe_ma_flag(uint8_t ma, SStream *ss, RVContext *ctx) {
  if (ma) {
    SStream_concat(ss, "ma");
    return;
  }
}

void maybe_lmul_flag(uint8_t lmul, SStream *ss, RVContext *ctx) {
  switch (lmul) {
  case 0x0:
    return;

  case 0x5:
    SStream_concat(ss, " , mf8");
    return;

  case 0x6:
    SStream_concat(ss, " , mf4");
    return;

  case 0x7:
    SStream_concat(ss, " , mf2");
    return;

  case 0x1:
    SStream_concat(ss, " , m2");
    return;

  case 0x2:
    SStream_concat(ss, " , m4");
    return;

  case 0x3:
    SStream_concat(ss, " , m8");
    return;
  }
}

// TODO
void csr_name_map(uint32_t csr, SStream *ss, RVContext *ctx) {}

void fence_bits(uint8_t bits, SStream *ss, RVContext *ctx) {
  if (bits & 0x8) {
    SStream_concat1(ss, 'i');
  }
  if (bits & 0x4) {
    SStream_concat1(ss, 'o');
  }
  if (bits & 0x2) {
    SStream_concat1(ss, 'r');
  }
  if (bits & 0x1) {
    SStream_concat1(ss, 'w');
  }
}
#endif
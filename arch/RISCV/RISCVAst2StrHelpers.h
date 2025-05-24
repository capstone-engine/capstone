#ifndef __AST2STR_HELPERS_H__
#define __AST2STR_HELPERS_H__

#include <stddef.h>
#include <stdint.h>

#include "../../SStream.h"
#include "../../cs_priv.h"
#include "RISCVDecodeHelpers.h"
#include "RISCVRVContextHelpers.h"

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

static inline void hex_bits_signed(uint64_t bitvec, uint8_t bvlen_bits,
                                   SStream *ss, RVContext *ctx) {
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

const static char *reg_names[] = {
    "zero", "ra", "sp", "gp", "tp",  "t0",  "t1", "t2", "fp", "s1", "a0",
    "a1",   "a2", "a3", "a4", "a5",  "a6",  "a7", "s2", "s3", "s4", "s5",
    "s6",   "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"};
static inline void reg_name(uint8_t r, SStream *ss, RVContext *ctx) {
  CS_ASSERT(r < 32);
  SStream_concat(ss, reg_names[r]);
}

const static char *creg_names[] = {"s0", "s1", "a0", "a1",
                                         "a2", "a3", "a4", "a5"};
static inline void creg_name(uint8_t r, SStream *ss, RVContext *ctx) {
  CS_ASSERT(r < 8);
  SStream_concat(ss, creg_names[r]);
}

const static char *freg_names[] = {
    "ft0", "ft1", "ft2",  "ft3",  "ft4", "ft5", "ft6",  "ft7",
    "fs0", "fs1", "fa0",  "fa1",  "fa2", "fa3", "fa4",  "fa5",
    "fa6", "fa7", "fs2",  "fs3",  "fs4", "fs5", "fs6",  "fs7",
    "fs8", "fs9", "fs10", "fs11", "ft8", "ft9", "ft10", "ft11"};
static inline void freg_name(uint8_t r, SStream *ss, RVContext *ctx) {
  CS_ASSERT(r < 32);
  SStream_concat(ss, freg_names[r]);
}

const static char *vreg_names[] = {
    "v0",  "v1",  "v2",  "v3",  "v4",  "v5",  "v6",  "v7",  "v8",  "v9",  "v10",
    "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21",
    "v22", "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"};
static inline void vreg_name(uint8_t r, SStream *ss, RVContext *ctx) {
  CS_ASSERT(r < 32);
  SStream_concat(ss, vreg_names[r]);
}

static inline void freg_or_reg_name(uint8_t r, SStream *ss, RVContext *ctx) {
  if (HART_SUPPORTS(Ext_Zfinx)) {
    reg_name(r, ss, ctx);
  } else {
    freg_name(r, ss, ctx);
  }
}

static inline void maybe_vmask(uint8_t vm, SStream *ss, RVContext *ctx) {
  if (vm) {
    return;
  }
  SStream_concat(ss, " , v0.t");
}

static inline void ta_flag(uint8_t ta, SStream *ss, RVContext *ctx) {
  if (ta) {
    SStream_concat(ss, "ta");
  } else {
    SStream_concat(ss, "tu");
  }
}

static inline void ma_flag(uint8_t ma, SStream *ss, RVContext *ctx) {
  if (ma) {
    SStream_concat(ss, "ma");
  } else {
    SStream_concat(ss, "mu");
  }
}

static inline void maybe_lmul_flag(uint8_t lmul, SStream *ss, RVContext *ctx) {
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

static inline void csr_name_map(uint32_t csr, SStream *ss, RVContext *ctx) {
  switch (csr) {
  case 0x3a0:
    SStream_concat(ss, "pmpcfg0");
    return;

  case 0x3a1:
    SStream_concat(ss, "pmpcfg1");
    return;

  case 0x3a2:
    SStream_concat(ss, "pmpcfg2");
    return;

  case 0x3a3:
    SStream_concat(ss, "pmpcfg3");
    return;

  case 0x3a4:
    SStream_concat(ss, "pmpcfg4");
    return;

  case 0x3a5:
    SStream_concat(ss, "pmpcfg5");
    return;

  case 0x3a6:
    SStream_concat(ss, "pmpcfg6");
    return;

  case 0x3a7:
    SStream_concat(ss, "pmpcfg7");
    return;

  case 0x3a8:
    SStream_concat(ss, "pmpcfg8");
    return;

  case 0x3a9:
    SStream_concat(ss, "pmpcfg9");
    return;

  case 0x3aa:
    SStream_concat(ss, "pmpcfg10");
    return;

  case 0x3ab:
    SStream_concat(ss, "pmpcfg11");
    return;

  case 0x3ac:
    SStream_concat(ss, "pmpcfg12");
    return;

  case 0x3ad:
    SStream_concat(ss, "pmpcfg13");
    return;

  case 0x3ae:
    SStream_concat(ss, "pmpcfg14");
    return;

  case 0x3af:
    SStream_concat(ss, "pmpcfg15");
    return;

  case 0x3b0:
    SStream_concat(ss, "pmpaddr0");
    return;

  case 0x3b1:
    SStream_concat(ss, "pmpaddr1");
    return;

  case 0x3b2:
    SStream_concat(ss, "pmpaddr2");
    return;

  case 0x3b3:
    SStream_concat(ss, "pmpaddr3");
    return;

  case 0x3b4:
    SStream_concat(ss, "pmpaddr4");
    return;

  case 0x3b5:
    SStream_concat(ss, "pmpaddr5");
    return;

  case 0x3b6:
    SStream_concat(ss, "pmpaddr6");
    return;

  case 0x3b7:
    SStream_concat(ss, "pmpaddr7");
    return;

  case 0x3b8:
    SStream_concat(ss, "pmpaddr8");
    return;

  case 0x3b9:
    SStream_concat(ss, "pmpaddr9");
    return;

  case 0x3ba:
    SStream_concat(ss, "pmpaddr10");
    return;

  case 0x3bb:
    SStream_concat(ss, "pmpaddr11");
    return;

  case 0x3bc:
    SStream_concat(ss, "pmpaddr12");
    return;

  case 0x3bd:
    SStream_concat(ss, "pmpaddr13");
    return;

  case 0x3be:
    SStream_concat(ss, "pmpaddr14");
    return;

  case 0x3bf:
    SStream_concat(ss, "pmpaddr15");
    return;

  case 0x3c0:
    SStream_concat(ss, "pmpaddr16");
    return;

  case 0x3c1:
    SStream_concat(ss, "pmpaddr17");
    return;

  case 0x3c2:
    SStream_concat(ss, "pmpaddr18");
    return;

  case 0x3c3:
    SStream_concat(ss, "pmpaddr19");
    return;

  case 0x3c4:
    SStream_concat(ss, "pmpaddr20");
    return;

  case 0x3c5:
    SStream_concat(ss, "pmpaddr21");
    return;

  case 0x3c6:
    SStream_concat(ss, "pmpaddr22");
    return;

  case 0x3c7:
    SStream_concat(ss, "pmpaddr23");
    return;

  case 0x3c8:
    SStream_concat(ss, "pmpaddr24");
    return;

  case 0x3c9:
    SStream_concat(ss, "pmpaddr25");
    return;

  case 0x3ca:
    SStream_concat(ss, "pmpaddr26");
    return;

  case 0x3cb:
    SStream_concat(ss, "pmpaddr27");
    return;

  case 0x3cc:
    SStream_concat(ss, "pmpaddr28");
    return;

  case 0x3cd:
    SStream_concat(ss, "pmpaddr29");
    return;

  case 0x3ce:
    SStream_concat(ss, "pmpaddr30");
    return;

  case 0x3cf:
    SStream_concat(ss, "pmpaddr31");
    return;

  case 0x3d0:
    SStream_concat(ss, "pmpaddr32");
    return;

  case 0x3d1:
    SStream_concat(ss, "pmpaddr33");
    return;

  case 0x3d2:
    SStream_concat(ss, "pmpaddr34");
    return;

  case 0x3d3:
    SStream_concat(ss, "pmpaddr35");
    return;

  case 0x3d4:
    SStream_concat(ss, "pmpaddr36");
    return;

  case 0x3d5:
    SStream_concat(ss, "pmpaddr37");
    return;

  case 0x3d6:
    SStream_concat(ss, "pmpaddr38");
    return;

  case 0x3d7:
    SStream_concat(ss, "pmpaddr39");
    return;

  case 0x3d8:
    SStream_concat(ss, "pmpaddr40");
    return;

  case 0x3d9:
    SStream_concat(ss, "pmpaddr41");
    return;

  case 0x3da:
    SStream_concat(ss, "pmpaddr42");
    return;

  case 0x3db:
    SStream_concat(ss, "pmpaddr43");
    return;

  case 0x3dc:
    SStream_concat(ss, "pmpaddr44");
    return;

  case 0x3dd:
    SStream_concat(ss, "pmpaddr45");
    return;

  case 0x3de:
    SStream_concat(ss, "pmpaddr46");
    return;

  case 0x3df:
    SStream_concat(ss, "pmpaddr47");
    return;

  case 0x3e0:
    SStream_concat(ss, "pmpaddr48");
    return;

  case 0x3e1:
    SStream_concat(ss, "pmpaddr49");
    return;

  case 0x3e2:
    SStream_concat(ss, "pmpaddr50");
    return;

  case 0x3e3:
    SStream_concat(ss, "pmpaddr51");
    return;

  case 0x3e4:
    SStream_concat(ss, "pmpaddr52");
    return;

  case 0x3e5:
    SStream_concat(ss, "pmpaddr53");
    return;

  case 0x3e6:
    SStream_concat(ss, "pmpaddr54");
    return;

  case 0x3e7:
    SStream_concat(ss, "pmpaddr55");
    return;

  case 0x3e8:
    SStream_concat(ss, "pmpaddr56");
    return;

  case 0x3e9:
    SStream_concat(ss, "pmpaddr57");
    return;

  case 0x3ea:
    SStream_concat(ss, "pmpaddr58");
    return;

  case 0x3eb:
    SStream_concat(ss, "pmpaddr59");
    return;

  case 0x3ec:
    SStream_concat(ss, "pmpaddr60");
    return;

  case 0x3ed:
    SStream_concat(ss, "pmpaddr61");
    return;

  case 0x3ee:
    SStream_concat(ss, "pmpaddr62");
    return;

  case 0x3ef:
    SStream_concat(ss, "pmpaddr63");
    return;

  case 0x180:
    SStream_concat(ss, "satp");
    return;

  case 0x321:
    SStream_concat(ss, "mcyclecfg");
    return;

  case 0x721:
    SStream_concat(ss, "mcyclecfgh");
    return;

  case 0x322:
    SStream_concat(ss, "minstretcfg");
    return;

  case 0x722:
    SStream_concat(ss, "minstretcfgh");
    return;

  case 0x14d:
    SStream_concat(ss, "stimecmp");
    return;

  case 0x15d:
    SStream_concat(ss, "stimecmph");
    return;

  case 0x301:
    SStream_concat(ss, "misa");
    return;

  case 0x300:
    SStream_concat(ss, "mstatus");
    return;

  case 0x30a:
    SStream_concat(ss, "menvcfg");
    return;

  case 0x31a:
    SStream_concat(ss, "menvcfgh");
    return;

  case 0x10a:
    SStream_concat(ss, "senvcfg");
    return;

  case 0x304:
    SStream_concat(ss, "mie");
    return;

  case 0x344:
    SStream_concat(ss, "mip");
    return;

  case 0x302:
    SStream_concat(ss, "medeleg");
    return;

  case 0x312:
    SStream_concat(ss, "medelegh");
    return;

  case 0x303:
    SStream_concat(ss, "mideleg");
    return;

  case 0x342:
    SStream_concat(ss, "mcause");
    return;

  case 0x343:
    SStream_concat(ss, "mtval");
    return;

  case 0x340:
    SStream_concat(ss, "mscratch");
    return;

  case 0x106:
    SStream_concat(ss, "scounteren");
    return;

  case 0x306:
    SStream_concat(ss, "mcounteren");
    return;

  case 0x320:
    SStream_concat(ss, "mcountinhibit");
    return;

  case 0xf11:
    SStream_concat(ss, "mvendorid");
    return;

  case 0xf12:
    SStream_concat(ss, "marchid");
    return;

  case 0xf13:
    SStream_concat(ss, "mimpid");
    return;

  case 0xf14:
    SStream_concat(ss, "mhartid");
    return;

  case 0xf15:
    SStream_concat(ss, "mconfigptr");
    return;

  case 0x100:
    SStream_concat(ss, "sstatus");
    return;

  case 0x144:
    SStream_concat(ss, "sip");
    return;

  case 0x104:
    SStream_concat(ss, "sie");
    return;

  case 0x140:
    SStream_concat(ss, "sscratch");
    return;

  case 0x142:
    SStream_concat(ss, "scause");
    return;

  case 0x143:
    SStream_concat(ss, "stval");
    return;

  case 0x7a0:
    SStream_concat(ss, "tselect");
    return;

  case 0x7a1:
    SStream_concat(ss, "tdata1");
    return;

  case 0x7a2:
    SStream_concat(ss, "tdata2");
    return;

  case 0x7a3:
    SStream_concat(ss, "tdata3");
    return;

  case 0x015:
    SStream_concat(ss, "seed");
    return;

  case 0xb83:
    SStream_concat(ss, "mhpmcounter3h");
    return;

  case 0xb84:
    SStream_concat(ss, "mhpmcounter4h");
    return;

  case 0xb85:
    SStream_concat(ss, "mhpmcounter5h");
    return;

  case 0xb86:
    SStream_concat(ss, "mhpmcounter6h");
    return;

  case 0xb87:
    SStream_concat(ss, "mhpmcounter7h");
    return;

  case 0xb88:
    SStream_concat(ss, "mhpmcounter8h");
    return;

  case 0xb89:
    SStream_concat(ss, "mhpmcounter9h");
    return;

  case 0xb8a:
    SStream_concat(ss, "mhpmcounter10h");
    return;

  case 0xb8b:
    SStream_concat(ss, "mhpmcounter11h");
    return;

  case 0xb8c:
    SStream_concat(ss, "mhpmcounter12h");
    return;

  case 0xb8d:
    SStream_concat(ss, "mhpmcounter13h");
    return;

  case 0xb8e:
    SStream_concat(ss, "mhpmcounter14h");
    return;

  case 0xb8f:
    SStream_concat(ss, "mhpmcounter15h");
    return;

  case 0xb90:
    SStream_concat(ss, "mhpmcounter16h");
    return;

  case 0xb91:
    SStream_concat(ss, "mhpmcounter17h");
    return;

  case 0xb92:
    SStream_concat(ss, "mhpmcounter18h");
    return;

  case 0xb93:
    SStream_concat(ss, "mhpmcounter19h");
    return;

  case 0xb94:
    SStream_concat(ss, "mhpmcounter20h");
    return;

  case 0xb95:
    SStream_concat(ss, "mhpmcounter21h");
    return;

  case 0xb96:
    SStream_concat(ss, "mhpmcounter22h");
    return;

  case 0xb97:
    SStream_concat(ss, "mhpmcounter23h");
    return;

  case 0xb98:
    SStream_concat(ss, "mhpmcounter24h");
    return;

  case 0xb99:
    SStream_concat(ss, "mhpmcounter25h");
    return;

  case 0xb9a:
    SStream_concat(ss, "mhpmcounter26h");
    return;

  case 0xb9b:
    SStream_concat(ss, "mhpmcounter27h");
    return;

  case 0xb9c:
    SStream_concat(ss, "mhpmcounter28h");
    return;

  case 0xb9d:
    SStream_concat(ss, "mhpmcounter29h");
    return;

  case 0xb9e:
    SStream_concat(ss, "mhpmcounter30h");
    return;

  case 0xb9f:
    SStream_concat(ss, "mhpmcounter31h");
    return;

  case 0xda0:
    SStream_concat(ss, "scountovf");
    return;

  case 0x001:
    SStream_concat(ss, "fflags");
    return;

  case 0x002:
    SStream_concat(ss, "frm");
    return;

  case 0x003:
    SStream_concat(ss, "fcsr");
    return;

  case 0xc00:
    SStream_concat(ss, "cycle");
    return;

  case 0xc01:
    SStream_concat(ss, "time");
    return;

  case 0xc02:
    SStream_concat(ss, "instret");
    return;

  case 0xc80:
    SStream_concat(ss, "cycleh");
    return;

  case 0xc81:
    SStream_concat(ss, "timeh");
    return;

  case 0xc82:
    SStream_concat(ss, "instreth");
    return;

  case 0xb00:
    SStream_concat(ss, "mcycle");
    return;

  case 0xb02:
    SStream_concat(ss, "minstret");
    return;

  case 0xb80:
    SStream_concat(ss, "mcycleh");
    return;

  case 0xb82:
    SStream_concat(ss, "minstreth");
    return;

  case 0xc03:
    SStream_concat(ss, "hpmcounter3");
    return;

  case 0xc04:
    SStream_concat(ss, "hpmcounter4");
    return;

  case 0xc05:
    SStream_concat(ss, "hpmcounter5");
    return;

  case 0xc06:
    SStream_concat(ss, "hpmcounter6");
    return;

  case 0xc07:
    SStream_concat(ss, "hpmcounter7");
    return;

  case 0xc08:
    SStream_concat(ss, "hpmcounter8");
    return;

  case 0xc09:
    SStream_concat(ss, "hpmcounter9");
    return;

  case 0xc0a:
    SStream_concat(ss, "hpmcounter10");
    return;

  case 0xc0b:
    SStream_concat(ss, "hpmcounter11");
    return;

  case 0xc0c:
    SStream_concat(ss, "hpmcounter12");
    return;

  case 0xc0d:
    SStream_concat(ss, "hpmcounter13");
    return;

  case 0xc0e:
    SStream_concat(ss, "hpmcounter14");
    return;

  case 0xc0f:
    SStream_concat(ss, "hpmcounter15");
    return;

  case 0xc10:
    SStream_concat(ss, "hpmcounter16");
    return;

  case 0xc11:
    SStream_concat(ss, "hpmcounter17");
    return;

  case 0xc12:
    SStream_concat(ss, "hpmcounter18");
    return;

  case 0xc13:
    SStream_concat(ss, "hpmcounter19");
    return;

  case 0xc14:
    SStream_concat(ss, "hpmcounter20");
    return;

  case 0xc15:
    SStream_concat(ss, "hpmcounter21");
    return;

  case 0xc16:
    SStream_concat(ss, "hpmcounter22");
    return;

  case 0xc17:
    SStream_concat(ss, "hpmcounter23");
    return;

  case 0xc18:
    SStream_concat(ss, "hpmcounter24");
    return;

  case 0xc19:
    SStream_concat(ss, "hpmcounter25");
    return;

  case 0xc1a:
    SStream_concat(ss, "hpmcounter26");
    return;

  case 0xc1b:
    SStream_concat(ss, "hpmcounter27");
    return;

  case 0xc1c:
    SStream_concat(ss, "hpmcounter28");
    return;

  case 0xc1d:
    SStream_concat(ss, "hpmcounter29");
    return;

  case 0xc1e:
    SStream_concat(ss, "hpmcounter30");
    return;

  case 0xc1f:
    SStream_concat(ss, "hpmcounter31");
    return;

  case 0xc83:
    SStream_concat(ss, "hpmcounter3h");
    return;

  case 0xc84:
    SStream_concat(ss, "hpmcounter4h");
    return;

  case 0xc85:
    SStream_concat(ss, "hpmcounter5h");
    return;

  case 0xc86:
    SStream_concat(ss, "hpmcounter6h");
    return;

  case 0xc87:
    SStream_concat(ss, "hpmcounter7h");
    return;

  case 0xc88:
    SStream_concat(ss, "hpmcounter8h");
    return;

  case 0xc89:
    SStream_concat(ss, "hpmcounter9h");
    return;

  case 0xc8a:
    SStream_concat(ss, "hpmcounter10h");
    return;

  case 0xc8b:
    SStream_concat(ss, "hpmcounter11h");
    return;

  case 0xc8c:
    SStream_concat(ss, "hpmcounter12h");
    return;

  case 0xc8d:
    SStream_concat(ss, "hpmcounter13h");
    return;

  case 0xc8e:
    SStream_concat(ss, "hpmcounter14h");
    return;

  case 0xc8f:
    SStream_concat(ss, "hpmcounter15h");
    return;

  case 0xc90:
    SStream_concat(ss, "hpmcounter16h");
    return;

  case 0xc91:
    SStream_concat(ss, "hpmcounter17h");
    return;

  case 0xc92:
    SStream_concat(ss, "hpmcounter18h");
    return;

  case 0xc93:
    SStream_concat(ss, "hpmcounter19h");
    return;

  case 0xc94:
    SStream_concat(ss, "hpmcounter20h");
    return;

  case 0xc95:
    SStream_concat(ss, "hpmcounter21h");
    return;

  case 0xc96:
    SStream_concat(ss, "hpmcounter22h");
    return;

  case 0xc97:
    SStream_concat(ss, "hpmcounter23h");
    return;

  case 0xc98:
    SStream_concat(ss, "hpmcounter24h");
    return;

  case 0xc99:
    SStream_concat(ss, "hpmcounter25h");
    return;

  case 0xc9a:
    SStream_concat(ss, "hpmcounter26h");
    return;

  case 0xc9b:
    SStream_concat(ss, "hpmcounter27h");
    return;

  case 0xc9c:
    SStream_concat(ss, "hpmcounter28h");
    return;

  case 0xc9d:
    SStream_concat(ss, "hpmcounter29h");
    return;

  case 0xc9e:
    SStream_concat(ss, "hpmcounter30h");
    return;

  case 0xc9f:
    SStream_concat(ss, "hpmcounter31h");
    return;

  case 0x323:
    SStream_concat(ss, "mhpmevent3");
    return;

  case 0x324:
    SStream_concat(ss, "mhpmevent4");
    return;

  case 0x325:
    SStream_concat(ss, "mhpmevent5");
    return;

  case 0x326:
    SStream_concat(ss, "mhpmevent6");
    return;

  case 0x327:
    SStream_concat(ss, "mhpmevent7");
    return;

  case 0x328:
    SStream_concat(ss, "mhpmevent8");
    return;

  case 0x329:
    SStream_concat(ss, "mhpmevent9");
    return;

  case 0x32a:
    SStream_concat(ss, "mhpmevent10");
    return;

  case 0x32b:
    SStream_concat(ss, "mhpmevent11");
    return;

  case 0x32c:
    SStream_concat(ss, "mhpmevent12");
    return;

  case 0x32d:
    SStream_concat(ss, "mhpmevent13");
    return;

  case 0x32e:
    SStream_concat(ss, "mhpmevent14");
    return;

  case 0x32f:
    SStream_concat(ss, "mhpmevent15");
    return;

  case 0x330:
    SStream_concat(ss, "mhpmevent16");
    return;

  case 0x331:
    SStream_concat(ss, "mhpmevent17");
    return;

  case 0x332:
    SStream_concat(ss, "mhpmevent18");
    return;

  case 0x333:
    SStream_concat(ss, "mhpmevent19");
    return;

  case 0x334:
    SStream_concat(ss, "mhpmevent20");
    return;

  case 0x335:
    SStream_concat(ss, "mhpmevent21");
    return;

  case 0x336:
    SStream_concat(ss, "mhpmevent22");
    return;

  case 0x337:
    SStream_concat(ss, "mhpmevent23");
    return;

  case 0x338:
    SStream_concat(ss, "mhpmevent24");
    return;

  case 0x339:
    SStream_concat(ss, "mhpmevent25");
    return;

  case 0x33a:
    SStream_concat(ss, "mhpmevent26");
    return;

  case 0x33b:
    SStream_concat(ss, "mhpmevent27");
    return;

  case 0x33c:
    SStream_concat(ss, "mhpmevent28");
    return;

  case 0x33d:
    SStream_concat(ss, "mhpmevent29");
    return;

  case 0x33e:
    SStream_concat(ss, "mhpmevent30");
    return;

  case 0x33f:
    SStream_concat(ss, "mhpmevent31");
    return;

  case 0xb03:
    SStream_concat(ss, "mhpmcounter3");
    return;

  case 0xb04:
    SStream_concat(ss, "mhpmcounter4");
    return;

  case 0xb05:
    SStream_concat(ss, "mhpmcounter5");
    return;

  case 0xb06:
    SStream_concat(ss, "mhpmcounter6");
    return;

  case 0xb07:
    SStream_concat(ss, "mhpmcounter7");
    return;

  case 0xb08:
    SStream_concat(ss, "mhpmcounter8");
    return;

  case 0xb09:
    SStream_concat(ss, "mhpmcounter9");
    return;

  case 0xb0a:
    SStream_concat(ss, "mhpmcounter10");
    return;

  case 0xb0b:
    SStream_concat(ss, "mhpmcounter11");
    return;

  case 0xb0c:
    SStream_concat(ss, "mhpmcounter12");
    return;

  case 0xb0d:
    SStream_concat(ss, "mhpmcounter13");
    return;

  case 0xb0e:
    SStream_concat(ss, "mhpmcounter14");
    return;

  case 0xb0f:
    SStream_concat(ss, "mhpmcounter15");
    return;

  case 0xb10:
    SStream_concat(ss, "mhpmcounter16");
    return;

  case 0xb11:
    SStream_concat(ss, "mhpmcounter17");
    return;

  case 0xb12:
    SStream_concat(ss, "mhpmcounter18");
    return;

  case 0xb13:
    SStream_concat(ss, "mhpmcounter19");
    return;

  case 0xb14:
    SStream_concat(ss, "mhpmcounter20");
    return;

  case 0xb15:
    SStream_concat(ss, "mhpmcounter21");
    return;

  case 0xb16:
    SStream_concat(ss, "mhpmcounter22");
    return;

  case 0xb17:
    SStream_concat(ss, "mhpmcounter23");
    return;

  case 0xb18:
    SStream_concat(ss, "mhpmcounter24");
    return;

  case 0xb19:
    SStream_concat(ss, "mhpmcounter25");
    return;

  case 0xb1a:
    SStream_concat(ss, "mhpmcounter26");
    return;

  case 0xb1b:
    SStream_concat(ss, "mhpmcounter27");
    return;

  case 0xb1c:
    SStream_concat(ss, "mhpmcounter28");
    return;

  case 0xb1d:
    SStream_concat(ss, "mhpmcounter29");
    return;

  case 0xb1e:
    SStream_concat(ss, "mhpmcounter30");
    return;

  case 0xb1f:
    SStream_concat(ss, "mhpmcounter31");
    return;

  case 0x105:
    SStream_concat(ss, "stvec");
    return;

  case 0x141:
    SStream_concat(ss, "sepc");
    return;

  case 0x305:
    SStream_concat(ss, "mtvec");
    return;

  case 0x341:
    SStream_concat(ss, "mepc");
    return;

  case 0x008:
    SStream_concat(ss, "vstart");
    return;

  case 0x009:
    SStream_concat(ss, "vxsat");
    return;

  case 0x00a:
    SStream_concat(ss, "vxrm");
    return;

  case 0x00f:
    SStream_concat(ss, "vcsr");
    return;

  case 0xc20:
    SStream_concat(ss, "vl");
    return;

  case 0xc21:
    SStream_concat(ss, "vtype");
    return;

  case 0xc22:
    SStream_concat(ss, "vlenb");
    return;

  default:
    hex_bits_12(csr, ss, ctx);
    return;
  }
}

static inline void fence_bits(uint8_t bits, SStream *ss, RVContext *ctx) {
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

static inline void dec_bits(uint64_t val, SStream *ss, RVContext *ctx,
                            uint32_t n) {
  for (int i = 0; i < n; i++) {
    // most significant bit printed first
    uint64_t bit = val & (1ULL << (n - 1 - i));
    SStream_concat1(ss, (bit == 0) ? '0' : '1');
  }
}

#define DEF_DEC_BITS(n)                                                        \
  static inline void dec_bits_##n(uint64_t val, SStream *ss, RVContext *ctx) { \
    dec_bits(val, ss, ctx, n);                                                 \
  }
DEF_DEC_BITS(1)
DEF_DEC_BITS(2)
DEF_DEC_BITS(3)
DEF_DEC_BITS(4)
DEF_DEC_BITS(5)

#endif
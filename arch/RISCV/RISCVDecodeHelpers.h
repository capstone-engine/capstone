#ifndef __RISCV_DECODE_HELPERS_H__
#define __RISCV_DECODE_HELPERS_H__

#include "RISCVRVContextHelpers.h"

#include <stdio.h>

#include "RISCVAst.gen.inc"

typedef enum ExtensionType {
  // Integer Multiplication and Division; not Machine!
  RISCV_Ext_M = 1ULL << 0,
  // Atomic Instructions
  RISCV_Ext_A = 1ULL << 1,
  // Single-Precision Floating-Point
  RISCV_Ext_F = 1ULL << 2,
  // Double-Precision Floating-Point
  RISCV_Ext_D = 1ULL << 3,
  // Compressed Instructions
  RISCV_Ext_C = 1ULL << 4,
  // Bit Manipulation
  RISCV_Ext_B = 1ULL << 5,
  // Vector Operations
  RISCV_Ext_V = 1ULL << 6,
  // Supervisor
  RISCV_Ext_S = 1ULL << 7,
  // User
  RISCV_Ext_U = 1ULL << 8,
  // Cache-Block Management Instructions
  RISCV_Ext_Zicbom = 1ULL << 9,
  // Cache-Block Zero Instructions
  RISCV_Ext_Zicboz = 1ULL << 10,
  // Base Counters and Timers
  RISCV_Ext_Zicntr = 1ULL << 11,
  // Integer Conditional Operations
  RISCV_Ext_Zicond = 1ULL << 12,
  // Instruction-Fetch Fence
  RISCV_Ext_Zifencei = 1ULL << 13,
  // Hardware Performance Counters
  RISCV_Ext_Zihpm = 1ULL << 14,
  // May-Be-Operations
  RISCV_Ext_Zimop = 1ULL << 15,
  // Multiplication and Division: Multiplication only
  RISCV_Ext_Zmmul = 1ULL << 16,
  // Atomic Memory Operations
  RISCV_Ext_Zaamo = 1ULL << 17,
  // Byte and Halfword Atomic Memory Operations
  RISCV_Ext_Zabha = 1ULL << 18,
  // Load-Reserved/Store-Conditional Instructions
  RISCV_Ext_Zalrsc = 1ULL << 19,
  // Additional Floating-Point Instructions
  RISCV_Ext_Zfa = 1ULL << 20,
  // Half-Precision Floating-Point
  RISCV_Ext_Zfh = 1ULL << 21,
  // Minimal Half-Precision Floating-Point
  RISCV_Ext_Zfhmin = 1ULL << 22,
  // Floating-Point in Integer Registers (single precision)
  RISCV_Ext_Zfinx = 1ULL << 23,
  // Floating-Point in Integer Registers (double precision)
  RISCV_Ext_Zdinx = 1ULL << 24,
  // Code Size Reduction: compressed instructions excluding floating point loads
  // and stores
  RISCV_Ext_Zca = 1ULL << 25,
  // Code Size Reduction: additional 16-bit aliases
  RISCV_Ext_Zcb = 1ULL << 26,
  // Code Size Reduction: compressed double precision floating point loads and
  // stores
  RISCV_Ext_Zcd = 1ULL << 27,
  // Code Size Reduction: compressed single precision floating point loads and
  // stores
  RISCV_Ext_Zcf = 1ULL << 28,
  // Compressed May-Be-Operations
  RISCV_Ext_Zcmop = 1ULL << 29,
  // Bit Manipulation: Address generation
  RISCV_Ext_Zba = 1ULL << 30,
  // Bit Manipulation: Basic bit-manipulation
  RISCV_Ext_Zbb = 1ULL << 31,
  // Bit Manipulation: Carry-less multiplication
  RISCV_Ext_Zbc = 1ULL << 32,
  // Bit Manipulation: Bit-manipulation for Cryptography
  RISCV_Ext_Zbkb = 1ULL << 33,
  // Bit Manipulation: Carry-less multiplication for Cryptography
  RISCV_Ext_Zbkc = 1ULL << 34,
  // Bit Manipulation: Crossbar permutations
  RISCV_Ext_Zbkx = 1ULL << 35,
  // Bit Manipulation: Single-bit instructions
  RISCV_Ext_Zbs = 1ULL << 36,
  // Scalar & Entropy Source Instructions: NIST Suite: AES Decryption
  RISCV_Ext_Zknd = 1ULL << 37,
  // Scalar & Entropy Source Instructions: NIST Suite: AES Encryption
  RISCV_Ext_Zkne = 1ULL << 38,
  // Scalar & Entropy Source Instructions: NIST Suite: Hash Function
  // Instructions
  RISCV_Ext_Zknh = 1ULL << 39,
  // Scalar & Entropy Source Instructions: Entropy Source ExtensionType
  RISCV_Ext_Zkr = 1ULL << 40,
  // Scalar & Entropy Source Instructions: ShangMi Suite: SM4 Block Cipher
  // Instructions
  RISCV_Ext_Zksed = 1ULL << 41,
  // Scalar & Entropy Source Instructions: ShangMi Suite: SM3 Hash Cipher
  // Instructions
  RISCV_Ext_Zksh = 1ULL << 42,
  // Floating-Point in Integer Registers (half precision)
  RISCV_Ext_Zhinx = 1ULL << 43,
  // Supervisor-mode Timer Interrupts
  RISCV_Ext_Sstc = 1ULL << 44,
  // Fine-Grained Address-Translation Cache Invalidation
  RISCV_Ext_Svinval = 1ULL << 45,
  // Vector Basic Bit-manipulation
  RISCV_Ext_Zvbb = 1ULL << 46,
  // Vector Cryptography Bit-manipulation
  RISCV_Ext_Zvkb = 1ULL << 47,
  // Vector Carryless Multiplication
  RISCV_Ext_Zvbc = 1ULL << 48,
  RISCV_Ext_Zvknhb = 1ULL << 49,
  // NIST Suite: Vector SHA-2 Secure Hash
  RISCV_Ext_Zvknha = 1ULL << 50,
  // Count Overflow and Mode-Based Filtering
  RISCV_Ext_Sscofpmf = 1ULL << 51,
  // NAPOT Translation Contiguity
  RISCV_Ext_Svnapot = 1ULL << 52,
  // Page-Based Memory Types
  RISCV_Ext_Svpbmt = 1ULL << 53,
  // Cycle and Instret Privilege Mode Filtering
  RISCV_Ext_Smcntrpmf = 1ULL << 54
} ExtensionType;

#define HART_SUPPORTS(e) (ctx->extensionsSupported & RISCV_##e)

static inline bool currentlyEnabled(ExtensionType t, RVContext *ctx) {
  switch (t) {
  case RISCV_Ext_M:
    return HART_SUPPORTS(Ext_M) && MISA(M) == 1;
  case RISCV_Ext_A:
    return HART_SUPPORTS(Ext_A) && MISA(A) == 1;
  case RISCV_Ext_F:
    return HART_SUPPORTS(Ext_F) && MISA(F) == 1 && MSTATUS(FS) != 0;
  case RISCV_Ext_D:
    return HART_SUPPORTS(Ext_D) && MISA(D) == 1 && MSTATUS(FS) != 0 &&
           ctx->flen >= 64;
  case RISCV_Ext_C:
    return HART_SUPPORTS(Ext_C) && MISA(C) == 1;
  case RISCV_Ext_B:
    return HART_SUPPORTS(Ext_B) && MISA(B) == 1;
  case RISCV_Ext_V:
    return HART_SUPPORTS(Ext_V) && MISA(V) == 1 && MSTATUS(VS) != 0;
  case RISCV_Ext_S:
    return HART_SUPPORTS(Ext_S) && MISA(S) == 1;
  case RISCV_Ext_U:
    return HART_SUPPORTS(Ext_U) && MISA(U) == 1;
  case RISCV_Ext_Zicbom:
    return HART_SUPPORTS(Ext_Zicbom);
  case RISCV_Ext_Zicboz:
    return HART_SUPPORTS(Ext_Zicboz);
  case RISCV_Ext_Zicntr:
    return HART_SUPPORTS(Ext_Zicntr);
  case RISCV_Ext_Zicond:
    return HART_SUPPORTS(Ext_Zicond);
  case RISCV_Ext_Zifencei:
    return HART_SUPPORTS(Ext_Zifencei);
  case RISCV_Ext_Zihpm:
    return HART_SUPPORTS(Ext_Zihpm) && currentlyEnabled(RISCV_Ext_Zicntr, ctx);
  case RISCV_Ext_Zimop:
    return HART_SUPPORTS(Ext_Zimop);
  case RISCV_Ext_Zmmul:
    return HART_SUPPORTS(Ext_Zmmul) || currentlyEnabled(RISCV_Ext_M, ctx);
  case RISCV_Ext_Zaamo:
    return HART_SUPPORTS(Ext_Zaamo) || currentlyEnabled(RISCV_Ext_A, ctx);

  case RISCV_Ext_Zabha:
    return HART_SUPPORTS(Ext_Zabha) && currentlyEnabled(RISCV_Ext_Zaamo, ctx);
  case RISCV_Ext_Zalrsc:
    return HART_SUPPORTS(Ext_Zalrsc) || currentlyEnabled(RISCV_Ext_A, ctx);
  case RISCV_Ext_Zfa:
    return HART_SUPPORTS(Ext_Zfa) && currentlyEnabled(RISCV_Ext_F, ctx);
  case RISCV_Ext_Zfh:
    return HART_SUPPORTS(Ext_Zfh) && currentlyEnabled(RISCV_Ext_F, ctx);
  case RISCV_Ext_Zfhmin:
    return (HART_SUPPORTS(Ext_Zfhmin) && currentlyEnabled(RISCV_Ext_F, ctx)) ||
           currentlyEnabled(RISCV_Ext_Zfh, ctx);
  // function clause currentlyEnabled(Ext_Zfinx) = sys_enable_zfinx()
  case RISCV_Ext_Zfinx:
    return HART_SUPPORTS(Ext_Zfinx);
  case RISCV_Ext_Zdinx:
    return HART_SUPPORTS(Ext_Zdinx) && ctx->flen >= 64;
  case RISCV_Ext_Zca:
    return HART_SUPPORTS(Ext_Zca) &&
           (currentlyEnabled(RISCV_Ext_C, ctx) || !HART_SUPPORTS(Ext_C));
  case RISCV_Ext_Zcb:
    return HART_SUPPORTS(Ext_Zcb) && currentlyEnabled(RISCV_Ext_Zca, ctx);
  case RISCV_Ext_Zcd:
    return HART_SUPPORTS(Ext_Zcd) && currentlyEnabled(RISCV_Ext_Zca, ctx) &&
           currentlyEnabled(RISCV_Ext_D, ctx) &&
           (currentlyEnabled(RISCV_Ext_C, ctx) || !HART_SUPPORTS(Ext_C));
  case RISCV_Ext_Zcf:
    return HART_SUPPORTS(Ext_Zcf) && currentlyEnabled(RISCV_Ext_Zca, ctx) &&
           currentlyEnabled(RISCV_Ext_F, ctx) &&
           (currentlyEnabled(RISCV_Ext_C, ctx) || !HART_SUPPORTS(Ext_C));
  case RISCV_Ext_Zcmop:
    return HART_SUPPORTS(Ext_Zcmop) && currentlyEnabled(RISCV_Ext_Zca, ctx);
  case RISCV_Ext_Zba:
    return HART_SUPPORTS(Ext_Zba) || currentlyEnabled(RISCV_Ext_B, ctx);
  case RISCV_Ext_Zbb:
    return HART_SUPPORTS(Ext_Zbb) || currentlyEnabled(RISCV_Ext_B, ctx);
  case RISCV_Ext_Zbc:
    return HART_SUPPORTS(Ext_Zbc);
  case RISCV_Ext_Zbkb:
    return HART_SUPPORTS(Ext_Zbkb);
  case RISCV_Ext_Zbkc:
    return HART_SUPPORTS(Ext_Zbkc);
  case RISCV_Ext_Zbkx:
    return HART_SUPPORTS(Ext_Zbkx);
  case RISCV_Ext_Zbs:
    return HART_SUPPORTS(Ext_Zbs) || currentlyEnabled(RISCV_Ext_B, ctx);
  case RISCV_Ext_Zknd:
    return HART_SUPPORTS(Ext_Zknd);
  case RISCV_Ext_Zkne:
    return HART_SUPPORTS(Ext_Zkne);
  case RISCV_Ext_Zknh:
    return HART_SUPPORTS(Ext_Zknh);
  case RISCV_Ext_Zkr:
    return HART_SUPPORTS(Ext_Zkr);
  case RISCV_Ext_Zksed:
    return HART_SUPPORTS(Ext_Zksed);
  case RISCV_Ext_Zksh:
    return HART_SUPPORTS(Ext_Zksh);
  case RISCV_Ext_Zhinx:
    return HART_SUPPORTS(Ext_Zhinx) & currentlyEnabled(RISCV_Ext_Zfinx, ctx);
  case RISCV_Ext_Sstc:
    return HART_SUPPORTS(Ext_Sstc);
  case RISCV_Ext_Svinval:
    return HART_SUPPORTS(Ext_Svinval);
  case RISCV_Ext_Zvbb:
    return HART_SUPPORTS(Ext_Zvbb) && currentlyEnabled(RISCV_Ext_V, ctx);
  case RISCV_Ext_Zvkb:
    return (HART_SUPPORTS(Ext_Zvkb) || currentlyEnabled(RISCV_Ext_Zvbb, ctx)) &&
           currentlyEnabled(RISCV_Ext_V, ctx);
  case RISCV_Ext_Zvbc:
    return HART_SUPPORTS(Ext_Zvbc) && currentlyEnabled(RISCV_Ext_V, ctx);
  case RISCV_Ext_Zvknhb:
    return HART_SUPPORTS(Ext_Zvknhb) && currentlyEnabled(RISCV_Ext_V, ctx);
  case RISCV_Ext_Zvknha:
    return HART_SUPPORTS(Ext_Zvknha) && currentlyEnabled(RISCV_Ext_V, ctx);
  // Not supported in the model yet.
  // function clause currentlyEnabled(Ext_Svnapot) = false
  // function clause currentlyEnabled(Ext_Svpbmt) = false
  case RISCV_Ext_Svnapot:
  case RISCV_Ext_Svpbmt:
    return 0;
  case RISCV_Ext_Sscofpmf:
    return HART_SUPPORTS(Ext_Sscofpmf) &&
           currentlyEnabled(RISCV_Ext_Zihpm, ctx);
  case RISCV_Ext_Smcntrpmf:
    return HART_SUPPORTS(Ext_Smcntrpmf) &&
           currentlyEnabled(RISCV_Ext_Zicntr, ctx);

  default:
    printf("currentlyEnabled: ERROR! Unknown extension.\n");
    return 0;
  }
}

static inline bool not(bool b, RVContext *ctx) { return !b; }

static inline uint8_t size_bytes_forwards(enum word_width width,
                                          RVContext *ctx) {
  switch (width) {
  case RISCV_BYTE:
    return 1;
  case RISCV_HALF:
    return 2;
  case RISCV_WORD:
    return 4;
  case RISCV_DOUBLE:
    return 8;
  default:
    printf("size_bytes_forwards: ERROR! Unhandled word_width case");
    return 0xFF;
  }
}

static inline bool lrsc_width_valid(enum word_width width, RVContext *ctx) {
  switch (width) {
  case RISCV_WORD:
    return 1;
  case RISCV_DOUBLE:
    return ctx->xlen >= 64;
  default:
    return 0;
  }
}

static inline bool amo_width_valid(enum word_width width, RVContext *ctx) {
  switch (width) {
  case RISCV_BYTE:
  case RISCV_HALF:
    return currentlyEnabled(RISCV_Ext_Zabha, ctx);
  case RISCV_WORD:
    return 1;
  case RISCV_DOUBLE:
    return ctx->xlen >= 64;
  default:
    return 0;
  }
}

static inline bool haveDoubleFPU(RVContext *ctx) {
  return currentlyEnabled(RISCV_Ext_D, ctx) ||
         currentlyEnabled(RISCV_Ext_Zdinx, ctx);
}

static inline bool haveSingleFPU(RVContext *ctx) {
  return currentlyEnabled(RISCV_Ext_F, ctx) ||
         currentlyEnabled(RISCV_Ext_Zfinx, ctx);
}

static inline bool haveHalfFPU(RVContext *ctx) {
  return currentlyEnabled(RISCV_Ext_Zfh, ctx) ||
         currentlyEnabled(RISCV_Ext_Zhinx, ctx);
}

static inline bool haveHalfMin(RVContext *ctx) {
  return haveHalfFPU(ctx) || currentlyEnabled(RISCV_Ext_Zfhmin, ctx);
}

static inline bool in32BitMode(RVContext *ctx) { return ctx->xlen == 32; }

static inline bool validDoubleRegsN(uint8_t *regs, RVContext *ctx) {
  if (currentlyEnabled(RISCV_Ext_Zdinx, ctx) && ctx->xlen == 32) {
    for (uint8_t i = 0; regs[i] != 0xff; i++) {
      if (regs[i] & 1) {
        return 0;
      }
    }
  }
  return 1;
}

#define validDoubleRegs(n, ...) validDoubleRegs##n(__VA_ARGS__)

static inline bool validDoubleRegs1(uint8_t rs1, RVContext *ctx) {
  uint8_t regs[] = {rs1, 0xFF};
  return validDoubleRegsN(regs, ctx);
}

static inline bool validDoubleRegs2(uint8_t rs1, uint8_t rd, RVContext *ctx) {
  uint8_t regs[] = {rs1, rd, 0xFF};
  return validDoubleRegsN(regs, ctx);
}

static inline bool validDoubleRegs3(uint8_t rs2, uint8_t rs1, uint8_t rd,
                                    RVContext *ctx) {
  uint8_t regs[] = {rs2, rs1, rd, 0xFF};
  return validDoubleRegsN(regs, ctx);
}

static inline bool validDoubleRegs4(uint8_t rs3, uint8_t rs2, uint8_t rs1,
                                    uint8_t rd, RVContext *ctx) {
  uint8_t regs[] = {rs3, rs2, rs1, rd, 0xFF};
  return validDoubleRegsN(regs, ctx);
}

static inline uint32_t get_sew(RVContext *ctx) {
  switch (VTYPE(VSEW)) {
  case 3:
  case 4:
  case 5:
  case 6:
    return 1 << VTYPE(VSEW);
  default:
    printf(
        "get_sew: ERROR!: Invalid vsew field of vector control register vtype");
    return 0;
  }
}

static inline int32_t get_lmul_pow(RVContext *ctx) {
  switch (VTYPE(VLMUL)) {
  case 0:
  case 1:
  case 2:
  case 3:
    return VTYPE(VLMUL);
  case 5:
  case 6:
  case 7:
    return VTYPE(VLMUL) - 8;
  default:
    printf("get_lmul_pow: ERROR!: Invalid vsew field of vector control "
           "register vtype");
    return 0;
  }
}

static inline float get_lmul(int32_t lpow) {
  if (lpow >= 0)
    return 1 << lpow;

  switch (lpow) {
  case -3:
    return 1.0 / 8.0;
  case -2:
    return 0.25;
  case -1:
    return 0.5;
  default:
    printf("get_lmul: ERROR!: Invalid vsew field, unexpected value");
  }
  // any number that appears strange and invalid
  return (float)(~0);
}

static inline bool zvk_check_encdec(int32_t egw, int32_t egs, RVContext *ctx) {
  return (ctx->vl % egs == 0) && (ctx->vstart % egs == 0) &&
         (get_lmul(get_lmul_pow(ctx)) * ctx->vlen >= egw);
}

static inline bool zvk_valid_reg_overlap(uint8_t rs, uint8_t rd,
                                         int32_t emul_pow) {
  uint64_t reg_group_size = (emul_pow > 0) ? 1 << emul_pow : 1;
  return (rs + reg_group_size <= rd) || (rd + reg_group_size <= rs);
}
static inline bool zvknhab_check_encdec(uint8_t vs2, uint8_t vs1, uint8_t vd,
                                        RVContext *ctx) {
  uint32_t sew = get_sew(ctx);
  int32_t lmulpow = get_lmul_pow(ctx);
  return zvk_check_encdec(sew, 4, ctx) &&
         zvk_valid_reg_overlap(vs1, vd, lmulpow) &&
         zvk_valid_reg_overlap(vs2, vd, lmulpow);
}

#endif
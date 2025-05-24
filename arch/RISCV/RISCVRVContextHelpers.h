#ifndef __RISCV_CONTEXT_H__
#define __RISCV_CONTEXT_H__

#include <stdbool.h>
#include <stdint.h>

// MISA fields
#define MISA_A (1UL << 0)  // Atomic extension
#define MISA_B (1UL << 1)  // Bit-Manipulation extension (tentative)
#define MISA_C (1UL << 2)  // Compressed extension
#define MISA_D (1UL << 3)  // Double-precision FP
#define MISA_E (1UL << 4)  // RV32E base ISA
#define MISA_F (1UL << 5)  // Single-precision FP
#define MISA_G (1UL << 6)  // Reserved
#define MISA_H (1UL << 7)  // Hypervisor extension
#define MISA_I (1UL << 8)  // RV32I/64I/128I base ISA
#define MISA_J (1UL << 9)  // Dynamically Translated Languages (tentative)
#define MISA_K (1UL << 10) // Reserved
#define MISA_L (1UL << 11) // Reserved
#define MISA_M (1UL << 12) // Multiply/Divide extension
#define MISA_N (1UL << 13) // User-Level Interrupts (tentative)
#define MISA_O (1UL << 14) // Reserved
#define MISA_P (1UL << 15) // Packed-SIMD (tentative)
#define MISA_Q (1UL << 16) // Quad-precision FP
#define MISA_R (1UL << 17) // Reserved
#define MISA_S (1UL << 18) // Supervisor mode
#define MISA_T (1UL << 19) // Reserved
#define MISA_U (1UL << 20) // User mode
#define MISA_V (1UL << 21) // Vector extension (tentative)
#define MISA_W (1UL << 22) // Reserved
#define MISA_X (1UL << 23) // Non-standard extensions
#define MISA_Y (1UL << 24) // Reserved
#define MISA_Z (1UL << 25) // Reserved

#define MISA(e) (ctx->misa & MISA_##e)

// MStatus fields
#define MSTATUS_SD_64 (1ULL << 63)
#define MSTATUS_MBE (1ULL << 37)
#define MSTATUS_SBE (1ULL << 36)
#define MSTATUS_SXL (3ULL << 34)
#define MSTATUS_UXL (3ULL << 32)
#define MSTATUS_SD_32 (1ULL << 31)
#define MSTATUS_TSR (1ULL << 22)
#define MSTATUS_TW (1ULL << 21)
#define MSTATUS_TVM (1ULL << 20)
#define MSTATUS_MXR (1ULL << 19)
#define MSTATUS_SUM (1ULL << 18)
#define MSTATUS_MPRV (1ULL << 17)
#define MSTATUS_XS (3ULL << 15)
#define MSTATUS_FS (3ULL << 13)
#define MSTATUS_MPP (3ULL << 11)
#define MSTATUS_VS (3ULL << 9)
#define MSTATUS_SPP (1ULL << 8)
#define MSTATUS_MPIE (1ULL << 7)
#define MSTATUS_SPIE (1ULL << 5)
#define MSTATUS_MIE (1ULL << 3)
#define MSTATUS_SIE (1ULL << 1)

#define MSTATUS(e) (ctx->mstatus & MSTATUS_##e)

#define VTYPE_VSEW (7ULL << 3)
#define VTYPE_VLMUL (7ULL << 0)

#define VTYPE(e) (ctx->vtype & VTYPE_##e)

typedef struct RVContext {
  uint16_t xlen;
  uint16_t xlen_bytes;
  uint16_t flen;

  uint32_t misa;
  uint64_t mstatus;
  uint64_t extensionsSupported;

  uint64_t vtype;
  uint64_t vl;
  uint16_t vstart;
  uint32_t vlen;

  // constants
  uint8_t zreg;
  uint8_t sp;
} RVContext;

#endif
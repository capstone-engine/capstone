/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifdef CAPSTONE_HAS_X86

#if defined(CAPSTONE_HAS_OSXKERNEL)
#include <Availability.h>
#endif

#include <string.h>

#include "X86Mapping.h"
#include "X86DisassemblerDecoder.h"

#include "../../utils.h"


const uint64_t arch_masks[9] = {
	0, 0xff,
	0xffff,
	0,
	0xffffffff,
	0, 0, 0,
	0xffffffffffffffff
};

static const x86_reg sib_base_map[] = {
	X86_REG_INVALID,
#define ENTRY(x) X86_REG_##x,
	ALL_SIB_BASES
#undef ENTRY
};

// Fill-ins to make the compiler happy.  These constants are never actually
//   assigned; they are just filler to make an automatically-generated switch
//   statement work.
enum {
	X86_REG_BX_SI = 500,
	X86_REG_BX_DI = 501,
	X86_REG_BP_SI = 502,
	X86_REG_BP_DI = 503,
	X86_REG_sib   = 504,
	X86_REG_sib64 = 505
};

static const x86_reg sib_index_map[] = {
	X86_REG_INVALID,
#define ENTRY(x) X86_REG_##x,
	ALL_EA_BASES
	REGS_XMM
	REGS_YMM
	REGS_ZMM
#undef ENTRY
};

static const x86_reg segment_map[] = {
	X86_REG_INVALID,
	X86_REG_CS,
	X86_REG_SS,
	X86_REG_DS,
	X86_REG_ES,
	X86_REG_FS,
	X86_REG_GS,
};

x86_reg x86_map_sib_base(int r)
{
	return sib_base_map[r];
}

x86_reg x86_map_sib_index(int r)
{
	return sib_index_map[r];
}

x86_reg x86_map_segment(int r)
{
	return segment_map[r];
}

#ifndef CAPSTONE_DIET
static const name_map reg_name_maps[] = {
	{ X86_REG_INVALID, NULL },

	{ X86_REG_AH, "ah" },
	{ X86_REG_AL, "al" },
	{ X86_REG_AX, "ax" },
	{ X86_REG_BH, "bh" },
	{ X86_REG_BL, "bl" },
	{ X86_REG_BP, "bp" },
	{ X86_REG_BPL, "bpl" },
	{ X86_REG_BX, "bx" },
	{ X86_REG_CH, "ch" },
	{ X86_REG_CL, "cl" },
	{ X86_REG_CS, "cs" },
	{ X86_REG_CX, "cx" },
	{ X86_REG_DH, "dh" },
	{ X86_REG_DI, "di" },
	{ X86_REG_DIL, "dil" },
	{ X86_REG_DL, "dl" },
	{ X86_REG_DS, "ds" },
	{ X86_REG_DX, "dx" },
	{ X86_REG_EAX, "eax" },
	{ X86_REG_EBP, "ebp" },
	{ X86_REG_EBX, "ebx" },
	{ X86_REG_ECX, "ecx" },
	{ X86_REG_EDI, "edi" },
	{ X86_REG_EDX, "edx" },
	{ X86_REG_EFLAGS, "flags" },
	{ X86_REG_EIP, "eip" },
	{ X86_REG_EIZ, "eiz" },
	{ X86_REG_ES, "es" },
	{ X86_REG_ESI, "esi" },
	{ X86_REG_ESP, "esp" },
	{ X86_REG_FPSW, "fpsw" },
	{ X86_REG_FS, "fs" },
	{ X86_REG_GS, "gs" },
	{ X86_REG_IP, "ip" },
	{ X86_REG_RAX, "rax" },
	{ X86_REG_RBP, "rbp" },
	{ X86_REG_RBX, "rbx" },
	{ X86_REG_RCX, "rcx" },
	{ X86_REG_RDI, "rdi" },
	{ X86_REG_RDX, "rdx" },
	{ X86_REG_RIP, "rip" },
	{ X86_REG_RIZ, "riz" },
	{ X86_REG_RSI, "rsi" },
	{ X86_REG_RSP, "rsp" },
	{ X86_REG_SI, "si" },
	{ X86_REG_SIL, "sil" },
	{ X86_REG_SP, "sp" },
	{ X86_REG_SPL, "spl" },
	{ X86_REG_SS, "ss" },
	{ X86_REG_CR0, "cr0" },
	{ X86_REG_CR1, "cr1" },
	{ X86_REG_CR2, "cr2" },
	{ X86_REG_CR3, "cr3" },
	{ X86_REG_CR4, "cr4" },
	{ X86_REG_CR5, "cr5" },
	{ X86_REG_CR6, "cr6" },
	{ X86_REG_CR7, "cr7" },
	{ X86_REG_CR8, "cr8" },
	{ X86_REG_CR9, "cr9" },
	{ X86_REG_CR10, "cr10" },
	{ X86_REG_CR11, "cr11" },
	{ X86_REG_CR12, "cr12" },
	{ X86_REG_CR13, "cr13" },
	{ X86_REG_CR14, "cr14" },
	{ X86_REG_CR15, "cr15" },
	{ X86_REG_DR0, "dr0" },
	{ X86_REG_DR1, "dr1" },
	{ X86_REG_DR2, "dr2" },
	{ X86_REG_DR3, "dr3" },
	{ X86_REG_DR4, "dr4" },
	{ X86_REG_DR5, "dr5" },
	{ X86_REG_DR6, "dr6" },
	{ X86_REG_DR7, "dr7" },
	{ X86_REG_FP0, "fp0" },
	{ X86_REG_FP1, "fp1" },
	{ X86_REG_FP2, "fp2" },
	{ X86_REG_FP3, "fp3" },
	{ X86_REG_FP4, "fp4" },
	{ X86_REG_FP5, "fp5" },
	{ X86_REG_FP6, "fp6" },
	{ X86_REG_FP7, "fp7" },
	{ X86_REG_K0, "k0" },
	{ X86_REG_K1, "k1" },
	{ X86_REG_K2, "k2" },
	{ X86_REG_K3, "k3" },
	{ X86_REG_K4, "k4" },
	{ X86_REG_K5, "k5" },
	{ X86_REG_K6, "k6" },
	{ X86_REG_K7, "k7" },
	{ X86_REG_MM0, "mm0" },
	{ X86_REG_MM1, "mm1" },
	{ X86_REG_MM2, "mm2" },
	{ X86_REG_MM3, "mm3" },
	{ X86_REG_MM4, "mm4" },
	{ X86_REG_MM5, "mm5" },
	{ X86_REG_MM6, "mm6" },
	{ X86_REG_MM7, "mm7" },
	{ X86_REG_R8, "r8" },
	{ X86_REG_R9, "r9" },
	{ X86_REG_R10, "r10" },
	{ X86_REG_R11, "r11" },
	{ X86_REG_R12, "r12" },
	{ X86_REG_R13, "r13" },
	{ X86_REG_R14, "r14" },
	{ X86_REG_R15, "r15" },
	{ X86_REG_ST0, "st(0" },
	{ X86_REG_ST1, "st(1)" },
	{ X86_REG_ST2, "st(2)" },
	{ X86_REG_ST3, "st(3)" },
	{ X86_REG_ST4, "st(4)" },
	{ X86_REG_ST5, "st(5)" },
	{ X86_REG_ST6, "st(6)" },
	{ X86_REG_ST7, "st(7)" },
	{ X86_REG_XMM0, "xmm0" },
	{ X86_REG_XMM1, "xmm1" },
	{ X86_REG_XMM2, "xmm2" },
	{ X86_REG_XMM3, "xmm3" },
	{ X86_REG_XMM4, "xmm4" },
	{ X86_REG_XMM5, "xmm5" },
	{ X86_REG_XMM6, "xmm6" },
	{ X86_REG_XMM7, "xmm7" },
	{ X86_REG_XMM8, "xmm8" },
	{ X86_REG_XMM9, "xmm9" },
	{ X86_REG_XMM10, "xmm10" },
	{ X86_REG_XMM11, "xmm11" },
	{ X86_REG_XMM12, "xmm12" },
	{ X86_REG_XMM13, "xmm13" },
	{ X86_REG_XMM14, "xmm14" },
	{ X86_REG_XMM15, "xmm15" },
	{ X86_REG_XMM16, "xmm16" },
	{ X86_REG_XMM17, "xmm17" },
	{ X86_REG_XMM18, "xmm18" },
	{ X86_REG_XMM19, "xmm19" },
	{ X86_REG_XMM20, "xmm20" },
	{ X86_REG_XMM21, "xmm21" },
	{ X86_REG_XMM22, "xmm22" },
	{ X86_REG_XMM23, "xmm23" },
	{ X86_REG_XMM24, "xmm24" },
	{ X86_REG_XMM25, "xmm25" },
	{ X86_REG_XMM26, "xmm26" },
	{ X86_REG_XMM27, "xmm27" },
	{ X86_REG_XMM28, "xmm28" },
	{ X86_REG_XMM29, "xmm29" },
	{ X86_REG_XMM30, "xmm30" },
	{ X86_REG_XMM31, "xmm31" },
	{ X86_REG_YMM0, "ymm0" },
	{ X86_REG_YMM1, "ymm1" },
	{ X86_REG_YMM2, "ymm2" },
	{ X86_REG_YMM3, "ymm3" },
	{ X86_REG_YMM4, "ymm4" },
	{ X86_REG_YMM5, "ymm5" },
	{ X86_REG_YMM6, "ymm6" },
	{ X86_REG_YMM7, "ymm7" },
	{ X86_REG_YMM8, "ymm8" },
	{ X86_REG_YMM9, "ymm9" },
	{ X86_REG_YMM10, "ymm10" },
	{ X86_REG_YMM11, "ymm11" },
	{ X86_REG_YMM12, "ymm12" },
	{ X86_REG_YMM13, "ymm13" },
	{ X86_REG_YMM14, "ymm14" },
	{ X86_REG_YMM15, "ymm15" },
	{ X86_REG_YMM16, "ymm16" },
	{ X86_REG_YMM17, "ymm17" },
	{ X86_REG_YMM18, "ymm18" },
	{ X86_REG_YMM19, "ymm19" },
	{ X86_REG_YMM20, "ymm20" },
	{ X86_REG_YMM21, "ymm21" },
	{ X86_REG_YMM22, "ymm22" },
	{ X86_REG_YMM23, "ymm23" },
	{ X86_REG_YMM24, "ymm24" },
	{ X86_REG_YMM25, "ymm25" },
	{ X86_REG_YMM26, "ymm26" },
	{ X86_REG_YMM27, "ymm27" },
	{ X86_REG_YMM28, "ymm28" },
	{ X86_REG_YMM29, "ymm29" },
	{ X86_REG_YMM30, "ymm30" },
	{ X86_REG_YMM31, "ymm31" },
	{ X86_REG_ZMM0, "zmm0" },
	{ X86_REG_ZMM1, "zmm1" },
	{ X86_REG_ZMM2, "zmm2" },
	{ X86_REG_ZMM3, "zmm3" },
	{ X86_REG_ZMM4, "zmm4" },
	{ X86_REG_ZMM5, "zmm5" },
	{ X86_REG_ZMM6, "zmm6" },
	{ X86_REG_ZMM7, "zmm7" },
	{ X86_REG_ZMM8, "zmm8" },
	{ X86_REG_ZMM9, "zmm9" },
	{ X86_REG_ZMM10, "zmm10" },
	{ X86_REG_ZMM11, "zmm11" },
	{ X86_REG_ZMM12, "zmm12" },
	{ X86_REG_ZMM13, "zmm13" },
	{ X86_REG_ZMM14, "zmm14" },
	{ X86_REG_ZMM15, "zmm15" },
	{ X86_REG_ZMM16, "zmm16" },
	{ X86_REG_ZMM17, "zmm17" },
	{ X86_REG_ZMM18, "zmm18" },
	{ X86_REG_ZMM19, "zmm19" },
	{ X86_REG_ZMM20, "zmm20" },
	{ X86_REG_ZMM21, "zmm21" },
	{ X86_REG_ZMM22, "zmm22" },
	{ X86_REG_ZMM23, "zmm23" },
	{ X86_REG_ZMM24, "zmm24" },
	{ X86_REG_ZMM25, "zmm25" },
	{ X86_REG_ZMM26, "zmm26" },
	{ X86_REG_ZMM27, "zmm27" },
	{ X86_REG_ZMM28, "zmm28" },
	{ X86_REG_ZMM29, "zmm29" },
	{ X86_REG_ZMM30, "zmm30" },
	{ X86_REG_ZMM31, "zmm31" },
	{ X86_REG_R8B, "r8b" },
	{ X86_REG_R9B, "r9b" },
	{ X86_REG_R10B, "r10b" },
	{ X86_REG_R11B, "r11b" },
	{ X86_REG_R12B, "r12b" },
	{ X86_REG_R13B, "r13b" },
	{ X86_REG_R14B, "r14b" },
	{ X86_REG_R15B, "r15b" },
	{ X86_REG_R8D, "r8d" },
	{ X86_REG_R9D, "r9d" },
	{ X86_REG_R10D, "r10d" },
	{ X86_REG_R11D, "r11d" },
	{ X86_REG_R12D, "r12d" },
	{ X86_REG_R13D, "r13d" },
	{ X86_REG_R14D, "r14d" },
	{ X86_REG_R15D, "r15d" },
	{ X86_REG_R8W, "r8w" },
	{ X86_REG_R9W, "r9w" },
	{ X86_REG_R10W, "r10w" },
	{ X86_REG_R11W, "r11w" },
	{ X86_REG_R12W, "r12w" },
	{ X86_REG_R13W, "r13w" },
	{ X86_REG_R14W, "r14w" },
	{ X86_REG_R15W, "r15w" },
};
#endif

// register size in non-64bit mode
const uint8_t regsize_map_32 [] = {
	0,	// 	{ X86_REG_INVALID, NULL },
	1,	// { X86_REG_AH, "ah" },
	1,	// { X86_REG_AL, "al" },
	2,	// { X86_REG_AX, "ax" },
	1,	// { X86_REG_BH, "bh" },
	1,	// { X86_REG_BL, "bl" },
	2,	// { X86_REG_BP, "bp" },
	1,	// { X86_REG_BPL, "bpl" },
	2,	// { X86_REG_BX, "bx" },
	1,	// { X86_REG_CH, "ch" },
	1,	// { X86_REG_CL, "cl" },
	2,	// { X86_REG_CS, "cs" },
	2,	// { X86_REG_CX, "cx" },
	1,	// { X86_REG_DH, "dh" },
	2,	// { X86_REG_DI, "di" },
	1,	// { X86_REG_DIL, "dil" },
	1,	// { X86_REG_DL, "dl" },
	2,	// { X86_REG_DS, "ds" },
	2,	// { X86_REG_DX, "dx" },
	4,	// { X86_REG_EAX, "eax" },
	4,	// { X86_REG_EBP, "ebp" },
	4,	// { X86_REG_EBX, "ebx" },
	4,	// { X86_REG_ECX, "ecx" },
	4,	// { X86_REG_EDI, "edi" },
	4,	// { X86_REG_EDX, "edx" },
	4,	// { X86_REG_EFLAGS, "flags" },
	4,	// { X86_REG_EIP, "eip" },
	4,	// { X86_REG_EIZ, "eiz" },
	2,	// { X86_REG_ES, "es" },
	4,	// { X86_REG_ESI, "esi" },
	4,	// { X86_REG_ESP, "esp" },
	10,	// { X86_REG_FPSW, "fpsw" },
	2,	// { X86_REG_FS, "fs" },
	2,	// { X86_REG_GS, "gs" },
	2,	// { X86_REG_IP, "ip" },
	8,	// { X86_REG_RAX, "rax" },
	8,	// { X86_REG_RBP, "rbp" },
	8,	// { X86_REG_RBX, "rbx" },
	8,	// { X86_REG_RCX, "rcx" },
	8,	// { X86_REG_RDI, "rdi" },
	8,	// { X86_REG_RDX, "rdx" },
	8,	// { X86_REG_RIP, "rip" },
	8,	// { X86_REG_RIZ, "riz" },
	8,	// { X86_REG_RSI, "rsi" },
	8,	// { X86_REG_RSP, "rsp" },
	2,	// { X86_REG_SI, "si" },
	1,	// { X86_REG_SIL, "sil" },
	2,	// { X86_REG_SP, "sp" },
	1,	// { X86_REG_SPL, "spl" },
	2,	// { X86_REG_SS, "ss" },
	4,	// { X86_REG_CR0, "cr0" },
	4,	// { X86_REG_CR1, "cr1" },
	4,	// { X86_REG_CR2, "cr2" },
	4,	// { X86_REG_CR3, "cr3" },
	4,	// { X86_REG_CR4, "cr4" },
	8,	// { X86_REG_CR5, "cr5" },
	8,	// { X86_REG_CR6, "cr6" },
	8,	// { X86_REG_CR7, "cr7" },
	8,	// { X86_REG_CR8, "cr8" },
	8,	// { X86_REG_CR9, "cr9" },
	8,	// { X86_REG_CR10, "cr10" },
	8,	// { X86_REG_CR11, "cr11" },
	8,	// { X86_REG_CR12, "cr12" },
	8,	// { X86_REG_CR13, "cr13" },
	8,	// { X86_REG_CR14, "cr14" },
	8,	// { X86_REG_CR15, "cr15" },
	4,	// { X86_REG_DR0, "dr0" },
	4,	// { X86_REG_DR1, "dr1" },
	4,	// { X86_REG_DR2, "dr2" },
	4,	// { X86_REG_DR3, "dr3" },
	4,	// { X86_REG_DR4, "dr4" },
	4,	// { X86_REG_DR5, "dr5" },
	4,	// { X86_REG_DR6, "dr6" },
	4,	// { X86_REG_DR7, "dr7" },
	10,	// { X86_REG_FP0, "fp0" },
	10,	// { X86_REG_FP1, "fp1" },
	10,	// { X86_REG_FP2, "fp2" },
	10,	// { X86_REG_FP3, "fp3" },
	10,	// { X86_REG_FP4, "fp4" },
	10,	// { X86_REG_FP5, "fp5" },
	10,	// { X86_REG_FP6, "fp6" },
	10,	// { X86_REG_FP7, "fp7" },
	2,	// { X86_REG_K0, "k0" },
	2,	// { X86_REG_K1, "k1" },
	2,	// { X86_REG_K2, "k2" },
	2,	// { X86_REG_K3, "k3" },
	2,	// { X86_REG_K4, "k4" },
	2,	// { X86_REG_K5, "k5" },
	2,	// { X86_REG_K6, "k6" },
	2,	// { X86_REG_K7, "k7" },
	8,	// { X86_REG_MM0, "mm0" },
	8,	// { X86_REG_MM1, "mm1" },
	8,	// { X86_REG_MM2, "mm2" },
	8,	// { X86_REG_MM3, "mm3" },
	8,	// { X86_REG_MM4, "mm4" },
	8,	// { X86_REG_MM5, "mm5" },
	8,	// { X86_REG_MM6, "mm6" },
	8,	// { X86_REG_MM7, "mm7" },
	8,	// { X86_REG_R8, "r8" },
	8,	// { X86_REG_R9, "r9" },
	8,	// { X86_REG_R10, "r10" },
	8,	// { X86_REG_R11, "r11" },
	8,	// { X86_REG_R12, "r12" },
	8,	// { X86_REG_R13, "r13" },
	8,	// { X86_REG_R14, "r14" },
	8,	// { X86_REG_R15, "r15" },
	10,	// { X86_REG_ST0, "st0" },
	10,	// { X86_REG_ST1, "st1" },
	10,	// { X86_REG_ST2, "st2" },
	10,	// { X86_REG_ST3, "st3" },
	10,	// { X86_REG_ST4, "st4" },
	10,	// { X86_REG_ST5, "st5" },
	10,	// { X86_REG_ST6, "st6" },
	10,	// { X86_REG_ST7, "st7" },
	16,	// { X86_REG_XMM0, "xmm0" },
	16,	// { X86_REG_XMM1, "xmm1" },
	16,	// { X86_REG_XMM2, "xmm2" },
	16,	// { X86_REG_XMM3, "xmm3" },
	16,	// { X86_REG_XMM4, "xmm4" },
	16,	// { X86_REG_XMM5, "xmm5" },
	16,	// { X86_REG_XMM6, "xmm6" },
	16,	// { X86_REG_XMM7, "xmm7" },
	16,	// { X86_REG_XMM8, "xmm8" },
	16,	// { X86_REG_XMM9, "xmm9" },
	16,	// { X86_REG_XMM10, "xmm10" },
	16,	// { X86_REG_XMM11, "xmm11" },
	16,	// { X86_REG_XMM12, "xmm12" },
	16,	// { X86_REG_XMM13, "xmm13" },
	16,	// { X86_REG_XMM14, "xmm14" },
	16,	// { X86_REG_XMM15, "xmm15" },
	16,	// { X86_REG_XMM16, "xmm16" },
	16,	// { X86_REG_XMM17, "xmm17" },
	16,	// { X86_REG_XMM18, "xmm18" },
	16,	// { X86_REG_XMM19, "xmm19" },
	16,	// { X86_REG_XMM20, "xmm20" },
	16,	// { X86_REG_XMM21, "xmm21" },
	16,	// { X86_REG_XMM22, "xmm22" },
	16,	// { X86_REG_XMM23, "xmm23" },
	16,	// { X86_REG_XMM24, "xmm24" },
	16,	// { X86_REG_XMM25, "xmm25" },
	16,	// { X86_REG_XMM26, "xmm26" },
	16,	// { X86_REG_XMM27, "xmm27" },
	16,	// { X86_REG_XMM28, "xmm28" },
	16,	// { X86_REG_XMM29, "xmm29" },
	16,	// { X86_REG_XMM30, "xmm30" },
	16,	// { X86_REG_XMM31, "xmm31" },
	32,	// { X86_REG_YMM0, "ymm0" },
	32,	// { X86_REG_YMM1, "ymm1" },
	32,	// { X86_REG_YMM2, "ymm2" },
	32,	// { X86_REG_YMM3, "ymm3" },
	32,	// { X86_REG_YMM4, "ymm4" },
	32,	// { X86_REG_YMM5, "ymm5" },
	32,	// { X86_REG_YMM6, "ymm6" },
	32,	// { X86_REG_YMM7, "ymm7" },
	32,	// { X86_REG_YMM8, "ymm8" },
	32,	// { X86_REG_YMM9, "ymm9" },
	32,	// { X86_REG_YMM10, "ymm10" },
	32,	// { X86_REG_YMM11, "ymm11" },
	32,	// { X86_REG_YMM12, "ymm12" },
	32,	// { X86_REG_YMM13, "ymm13" },
	32,	// { X86_REG_YMM14, "ymm14" },
	32,	// { X86_REG_YMM15, "ymm15" },
	32,	// { X86_REG_YMM16, "ymm16" },
	32,	// { X86_REG_YMM17, "ymm17" },
	32,	// { X86_REG_YMM18, "ymm18" },
	32,	// { X86_REG_YMM19, "ymm19" },
	32,	// { X86_REG_YMM20, "ymm20" },
	32,	// { X86_REG_YMM21, "ymm21" },
	32,	// { X86_REG_YMM22, "ymm22" },
	32,	// { X86_REG_YMM23, "ymm23" },
	32,	// { X86_REG_YMM24, "ymm24" },
	32,	// { X86_REG_YMM25, "ymm25" },
	32,	// { X86_REG_YMM26, "ymm26" },
	32,	// { X86_REG_YMM27, "ymm27" },
	32,	// { X86_REG_YMM28, "ymm28" },
	32,	// { X86_REG_YMM29, "ymm29" },
	32,	// { X86_REG_YMM30, "ymm30" },
	32,	// { X86_REG_YMM31, "ymm31" },
	64,	// { X86_REG_ZMM0, "zmm0" },
	64,	// { X86_REG_ZMM1, "zmm1" },
	64,	// { X86_REG_ZMM2, "zmm2" },
	64,	// { X86_REG_ZMM3, "zmm3" },
	64,	// { X86_REG_ZMM4, "zmm4" },
	64,	// { X86_REG_ZMM5, "zmm5" },
	64,	// { X86_REG_ZMM6, "zmm6" },
	64,	// { X86_REG_ZMM7, "zmm7" },
	64,	// { X86_REG_ZMM8, "zmm8" },
	64,	// { X86_REG_ZMM9, "zmm9" },
	64,	// { X86_REG_ZMM10, "zmm10" },
	64,	// { X86_REG_ZMM11, "zmm11" },
	64,	// { X86_REG_ZMM12, "zmm12" },
	64,	// { X86_REG_ZMM13, "zmm13" },
	64,	// { X86_REG_ZMM14, "zmm14" },
	64,	// { X86_REG_ZMM15, "zmm15" },
	64,	// { X86_REG_ZMM16, "zmm16" },
	64,	// { X86_REG_ZMM17, "zmm17" },
	64,	// { X86_REG_ZMM18, "zmm18" },
	64,	// { X86_REG_ZMM19, "zmm19" },
	64,	// { X86_REG_ZMM20, "zmm20" },
	64,	// { X86_REG_ZMM21, "zmm21" },
	64,	// { X86_REG_ZMM22, "zmm22" },
	64,	// { X86_REG_ZMM23, "zmm23" },
	64,	// { X86_REG_ZMM24, "zmm24" },
	64,	// { X86_REG_ZMM25, "zmm25" },
	64,	// { X86_REG_ZMM26, "zmm26" },
	64,	// { X86_REG_ZMM27, "zmm27" },
	64,	// { X86_REG_ZMM28, "zmm28" },
	64,	// { X86_REG_ZMM29, "zmm29" },
	64,	// { X86_REG_ZMM30, "zmm30" },
	64,	// { X86_REG_ZMM31, "zmm31" },
	1,	// { X86_REG_R8B, "r8b" },
	1,	// { X86_REG_R9B, "r9b" },
	1,	// { X86_REG_R10B, "r10b" },
	1,	// { X86_REG_R11B, "r11b" },
	1,	// { X86_REG_R12B, "r12b" },
	1,	// { X86_REG_R13B, "r13b" },
	1,	// { X86_REG_R14B, "r14b" },
	1,	// { X86_REG_R15B, "r15b" },
	4,	// { X86_REG_R8D, "r8d" },
	4,	// { X86_REG_R9D, "r9d" },
	4,	// { X86_REG_R10D, "r10d" },
	4,	// { X86_REG_R11D, "r11d" },
	4,	// { X86_REG_R12D, "r12d" },
	4,	// { X86_REG_R13D, "r13d" },
	4,	// { X86_REG_R14D, "r14d" },
	4,	// { X86_REG_R15D, "r15d" },
	2,	// { X86_REG_R8W, "r8w" },
	2,	// { X86_REG_R9W, "r9w" },
	2,	// { X86_REG_R10W, "r10w" },
	2,	// { X86_REG_R11W, "r11w" },
	2,	// { X86_REG_R12W, "r12w" },
	2,	// { X86_REG_R13W, "r13w" },
	2,	// { X86_REG_R14W, "r14w" },
	2,	// { X86_REG_R15W, "r15w" },
};

// register size in 64bit mode
const uint8_t regsize_map_64 [] = {
	0,	// 	{ X86_REG_INVALID, NULL },
	1,	// { X86_REG_AH, "ah" },
	1,	// { X86_REG_AL, "al" },
	2,	// { X86_REG_AX, "ax" },
	1,	// { X86_REG_BH, "bh" },
	1,	// { X86_REG_BL, "bl" },
	2,	// { X86_REG_BP, "bp" },
	1,	// { X86_REG_BPL, "bpl" },
	2,	// { X86_REG_BX, "bx" },
	1,	// { X86_REG_CH, "ch" },
	1,	// { X86_REG_CL, "cl" },
	2,	// { X86_REG_CS, "cs" },
	2,	// { X86_REG_CX, "cx" },
	1,	// { X86_REG_DH, "dh" },
	2,	// { X86_REG_DI, "di" },
	1,	// { X86_REG_DIL, "dil" },
	1,	// { X86_REG_DL, "dl" },
	2,	// { X86_REG_DS, "ds" },
	2,	// { X86_REG_DX, "dx" },
	4,	// { X86_REG_EAX, "eax" },
	4,	// { X86_REG_EBP, "ebp" },
	4,	// { X86_REG_EBX, "ebx" },
	4,	// { X86_REG_ECX, "ecx" },
	4,	// { X86_REG_EDI, "edi" },
	4,	// { X86_REG_EDX, "edx" },
	8,	// { X86_REG_EFLAGS, "flags" },
	4,	// { X86_REG_EIP, "eip" },
	4,	// { X86_REG_EIZ, "eiz" },
	2,	// { X86_REG_ES, "es" },
	4,	// { X86_REG_ESI, "esi" },
	4,	// { X86_REG_ESP, "esp" },
	10,	// { X86_REG_FPSW, "fpsw" },
	2,	// { X86_REG_FS, "fs" },
	2,	// { X86_REG_GS, "gs" },
	2,	// { X86_REG_IP, "ip" },
	8,	// { X86_REG_RAX, "rax" },
	8,	// { X86_REG_RBP, "rbp" },
	8,	// { X86_REG_RBX, "rbx" },
	8,	// { X86_REG_RCX, "rcx" },
	8,	// { X86_REG_RDI, "rdi" },
	8,	// { X86_REG_RDX, "rdx" },
	8,	// { X86_REG_RIP, "rip" },
	8,	// { X86_REG_RIZ, "riz" },
	8,	// { X86_REG_RSI, "rsi" },
	8,	// { X86_REG_RSP, "rsp" },
	2,	// { X86_REG_SI, "si" },
	1,	// { X86_REG_SIL, "sil" },
	2,	// { X86_REG_SP, "sp" },
	1,	// { X86_REG_SPL, "spl" },
	2,	// { X86_REG_SS, "ss" },
	8,	// { X86_REG_CR0, "cr0" },
	8,	// { X86_REG_CR1, "cr1" },
	8,	// { X86_REG_CR2, "cr2" },
	8,	// { X86_REG_CR3, "cr3" },
	8,	// { X86_REG_CR4, "cr4" },
	8,	// { X86_REG_CR5, "cr5" },
	8,	// { X86_REG_CR6, "cr6" },
	8,	// { X86_REG_CR7, "cr7" },
	8,	// { X86_REG_CR8, "cr8" },
	8,	// { X86_REG_CR9, "cr9" },
	8,	// { X86_REG_CR10, "cr10" },
	8,	// { X86_REG_CR11, "cr11" },
	8,	// { X86_REG_CR12, "cr12" },
	8,	// { X86_REG_CR13, "cr13" },
	8,	// { X86_REG_CR14, "cr14" },
	8,	// { X86_REG_CR15, "cr15" },
	8,	// { X86_REG_DR0, "dr0" },
	8,	// { X86_REG_DR1, "dr1" },
	8,	// { X86_REG_DR2, "dr2" },
	8,	// { X86_REG_DR3, "dr3" },
	8,	// { X86_REG_DR4, "dr4" },
	8,	// { X86_REG_DR5, "dr5" },
	8,	// { X86_REG_DR6, "dr6" },
	8,	// { X86_REG_DR7, "dr7" },
	10,	// { X86_REG_FP0, "fp0" },
	10,	// { X86_REG_FP1, "fp1" },
	10,	// { X86_REG_FP2, "fp2" },
	10,	// { X86_REG_FP3, "fp3" },
	10,	// { X86_REG_FP4, "fp4" },
	10,	// { X86_REG_FP5, "fp5" },
	10,	// { X86_REG_FP6, "fp6" },
	10,	// { X86_REG_FP7, "fp7" },
	2,	// { X86_REG_K0, "k0" },
	2,	// { X86_REG_K1, "k1" },
	2,	// { X86_REG_K2, "k2" },
	2,	// { X86_REG_K3, "k3" },
	2,	// { X86_REG_K4, "k4" },
	2,	// { X86_REG_K5, "k5" },
	2,	// { X86_REG_K6, "k6" },
	2,	// { X86_REG_K7, "k7" },
	8,	// { X86_REG_MM0, "mm0" },
	8,	// { X86_REG_MM1, "mm1" },
	8,	// { X86_REG_MM2, "mm2" },
	8,	// { X86_REG_MM3, "mm3" },
	8,	// { X86_REG_MM4, "mm4" },
	8,	// { X86_REG_MM5, "mm5" },
	8,	// { X86_REG_MM6, "mm6" },
	8,	// { X86_REG_MM7, "mm7" },
	8,	// { X86_REG_R8, "r8" },
	8,	// { X86_REG_R9, "r9" },
	8,	// { X86_REG_R10, "r10" },
	8,	// { X86_REG_R11, "r11" },
	8,	// { X86_REG_R12, "r12" },
	8,	// { X86_REG_R13, "r13" },
	8,	// { X86_REG_R14, "r14" },
	8,	// { X86_REG_R15, "r15" },
	10,	// { X86_REG_ST0, "st0" },
	10,	// { X86_REG_ST1, "st1" },
	10,	// { X86_REG_ST2, "st2" },
	10,	// { X86_REG_ST3, "st3" },
	10,	// { X86_REG_ST4, "st4" },
	10,	// { X86_REG_ST5, "st5" },
	10,	// { X86_REG_ST6, "st6" },
	10,	// { X86_REG_ST7, "st7" },
	16,	// { X86_REG_XMM0, "xmm0" },
	16,	// { X86_REG_XMM1, "xmm1" },
	16,	// { X86_REG_XMM2, "xmm2" },
	16,	// { X86_REG_XMM3, "xmm3" },
	16,	// { X86_REG_XMM4, "xmm4" },
	16,	// { X86_REG_XMM5, "xmm5" },
	16,	// { X86_REG_XMM6, "xmm6" },
	16,	// { X86_REG_XMM7, "xmm7" },
	16,	// { X86_REG_XMM8, "xmm8" },
	16,	// { X86_REG_XMM9, "xmm9" },
	16,	// { X86_REG_XMM10, "xmm10" },
	16,	// { X86_REG_XMM11, "xmm11" },
	16,	// { X86_REG_XMM12, "xmm12" },
	16,	// { X86_REG_XMM13, "xmm13" },
	16,	// { X86_REG_XMM14, "xmm14" },
	16,	// { X86_REG_XMM15, "xmm15" },
	16,	// { X86_REG_XMM16, "xmm16" },
	16,	// { X86_REG_XMM17, "xmm17" },
	16,	// { X86_REG_XMM18, "xmm18" },
	16,	// { X86_REG_XMM19, "xmm19" },
	16,	// { X86_REG_XMM20, "xmm20" },
	16,	// { X86_REG_XMM21, "xmm21" },
	16,	// { X86_REG_XMM22, "xmm22" },
	16,	// { X86_REG_XMM23, "xmm23" },
	16,	// { X86_REG_XMM24, "xmm24" },
	16,	// { X86_REG_XMM25, "xmm25" },
	16,	// { X86_REG_XMM26, "xmm26" },
	16,	// { X86_REG_XMM27, "xmm27" },
	16,	// { X86_REG_XMM28, "xmm28" },
	16,	// { X86_REG_XMM29, "xmm29" },
	16,	// { X86_REG_XMM30, "xmm30" },
	16,	// { X86_REG_XMM31, "xmm31" },
	32,	// { X86_REG_YMM0, "ymm0" },
	32,	// { X86_REG_YMM1, "ymm1" },
	32,	// { X86_REG_YMM2, "ymm2" },
	32,	// { X86_REG_YMM3, "ymm3" },
	32,	// { X86_REG_YMM4, "ymm4" },
	32,	// { X86_REG_YMM5, "ymm5" },
	32,	// { X86_REG_YMM6, "ymm6" },
	32,	// { X86_REG_YMM7, "ymm7" },
	32,	// { X86_REG_YMM8, "ymm8" },
	32,	// { X86_REG_YMM9, "ymm9" },
	32,	// { X86_REG_YMM10, "ymm10" },
	32,	// { X86_REG_YMM11, "ymm11" },
	32,	// { X86_REG_YMM12, "ymm12" },
	32,	// { X86_REG_YMM13, "ymm13" },
	32,	// { X86_REG_YMM14, "ymm14" },
	32,	// { X86_REG_YMM15, "ymm15" },
	32,	// { X86_REG_YMM16, "ymm16" },
	32,	// { X86_REG_YMM17, "ymm17" },
	32,	// { X86_REG_YMM18, "ymm18" },
	32,	// { X86_REG_YMM19, "ymm19" },
	32,	// { X86_REG_YMM20, "ymm20" },
	32,	// { X86_REG_YMM21, "ymm21" },
	32,	// { X86_REG_YMM22, "ymm22" },
	32,	// { X86_REG_YMM23, "ymm23" },
	32,	// { X86_REG_YMM24, "ymm24" },
	32,	// { X86_REG_YMM25, "ymm25" },
	32,	// { X86_REG_YMM26, "ymm26" },
	32,	// { X86_REG_YMM27, "ymm27" },
	32,	// { X86_REG_YMM28, "ymm28" },
	32,	// { X86_REG_YMM29, "ymm29" },
	32,	// { X86_REG_YMM30, "ymm30" },
	32,	// { X86_REG_YMM31, "ymm31" },
	64,	// { X86_REG_ZMM0, "zmm0" },
	64,	// { X86_REG_ZMM1, "zmm1" },
	64,	// { X86_REG_ZMM2, "zmm2" },
	64,	// { X86_REG_ZMM3, "zmm3" },
	64,	// { X86_REG_ZMM4, "zmm4" },
	64,	// { X86_REG_ZMM5, "zmm5" },
	64,	// { X86_REG_ZMM6, "zmm6" },
	64,	// { X86_REG_ZMM7, "zmm7" },
	64,	// { X86_REG_ZMM8, "zmm8" },
	64,	// { X86_REG_ZMM9, "zmm9" },
	64,	// { X86_REG_ZMM10, "zmm10" },
	64,	// { X86_REG_ZMM11, "zmm11" },
	64,	// { X86_REG_ZMM12, "zmm12" },
	64,	// { X86_REG_ZMM13, "zmm13" },
	64,	// { X86_REG_ZMM14, "zmm14" },
	64,	// { X86_REG_ZMM15, "zmm15" },
	64,	// { X86_REG_ZMM16, "zmm16" },
	64,	// { X86_REG_ZMM17, "zmm17" },
	64,	// { X86_REG_ZMM18, "zmm18" },
	64,	// { X86_REG_ZMM19, "zmm19" },
	64,	// { X86_REG_ZMM20, "zmm20" },
	64,	// { X86_REG_ZMM21, "zmm21" },
	64,	// { X86_REG_ZMM22, "zmm22" },
	64,	// { X86_REG_ZMM23, "zmm23" },
	64,	// { X86_REG_ZMM24, "zmm24" },
	64,	// { X86_REG_ZMM25, "zmm25" },
	64,	// { X86_REG_ZMM26, "zmm26" },
	64,	// { X86_REG_ZMM27, "zmm27" },
	64,	// { X86_REG_ZMM28, "zmm28" },
	64,	// { X86_REG_ZMM29, "zmm29" },
	64,	// { X86_REG_ZMM30, "zmm30" },
	64,	// { X86_REG_ZMM31, "zmm31" },
	1,	// { X86_REG_R8B, "r8b" },
	1,	// { X86_REG_R9B, "r9b" },
	1,	// { X86_REG_R10B, "r10b" },
	1,	// { X86_REG_R11B, "r11b" },
	1,	// { X86_REG_R12B, "r12b" },
	1,	// { X86_REG_R13B, "r13b" },
	1,	// { X86_REG_R14B, "r14b" },
	1,	// { X86_REG_R15B, "r15b" },
	4,	// { X86_REG_R8D, "r8d" },
	4,	// { X86_REG_R9D, "r9d" },
	4,	// { X86_REG_R10D, "r10d" },
	4,	// { X86_REG_R11D, "r11d" },
	4,	// { X86_REG_R12D, "r12d" },
	4,	// { X86_REG_R13D, "r13d" },
	4,	// { X86_REG_R14D, "r14d" },
	4,	// { X86_REG_R15D, "r15d" },
	2,	// { X86_REG_R8W, "r8w" },
	2,	// { X86_REG_R9W, "r9w" },
	2,	// { X86_REG_R10W, "r10w" },
	2,	// { X86_REG_R11W, "r11w" },
	2,	// { X86_REG_R12W, "r12w" },
	2,	// { X86_REG_R13W, "r13w" },
	2,	// { X86_REG_R14W, "r14w" },
	2,	// { X86_REG_R15W, "r15w" },
};

const char *X86_reg_name(csh handle, unsigned int reg)
{
#ifndef CAPSTONE_DIET
	cs_struct *ud = (cs_struct *)handle;

	if (reg >= X86_REG_ENDING)
		return NULL;

	if (reg == X86_REG_EFLAGS) {
		if (ud->mode & CS_MODE_32)
			return "eflags";
		if (ud->mode & CS_MODE_64)
			return "rflags";
	}

	return reg_name_maps[reg].name;
#else
	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
static const name_map insn_name_maps[] = {
	{ X86_INS_INVALID, NULL },

	{ X86_INS_AAA, "aaa" },
	{ X86_INS_AAD, "aad" },
	{ X86_INS_AAM, "aam" },
	{ X86_INS_AAS, "aas" },
	{ X86_INS_FABS, "fabs" },
	{ X86_INS_ADC, "adc" },
	{ X86_INS_ADCX, "adcx" },
	{ X86_INS_ADD, "add" },
	{ X86_INS_ADDPD, "addpd" },
	{ X86_INS_ADDPS, "addps" },
	{ X86_INS_ADDSD, "addsd" },
	{ X86_INS_ADDSS, "addss" },
	{ X86_INS_ADDSUBPD, "addsubpd" },
	{ X86_INS_ADDSUBPS, "addsubps" },
	{ X86_INS_FADD, "fadd" },
	{ X86_INS_FIADD, "fiadd" },
	{ X86_INS_FADDP, "faddp" },
	{ X86_INS_ADOX, "adox" },
	{ X86_INS_AESDECLAST, "aesdeclast" },
	{ X86_INS_AESDEC, "aesdec" },
	{ X86_INS_AESENCLAST, "aesenclast" },
	{ X86_INS_AESENC, "aesenc" },
	{ X86_INS_AESIMC, "aesimc" },
	{ X86_INS_AESKEYGENASSIST, "aeskeygenassist" },
	{ X86_INS_AND, "and" },
	{ X86_INS_ANDN, "andn" },
	{ X86_INS_ANDNPD, "andnpd" },
	{ X86_INS_ANDNPS, "andnps" },
	{ X86_INS_ANDPD, "andpd" },
	{ X86_INS_ANDPS, "andps" },
	{ X86_INS_ARPL, "arpl" },
	{ X86_INS_BEXTR, "bextr" },
	{ X86_INS_BLCFILL, "blcfill" },
	{ X86_INS_BLCI, "blci" },
	{ X86_INS_BLCIC, "blcic" },
	{ X86_INS_BLCMSK, "blcmsk" },
	{ X86_INS_BLCS, "blcs" },
	{ X86_INS_BLENDPD, "blendpd" },
	{ X86_INS_BLENDPS, "blendps" },
	{ X86_INS_BLENDVPD, "blendvpd" },
	{ X86_INS_BLENDVPS, "blendvps" },
	{ X86_INS_BLSFILL, "blsfill" },
	{ X86_INS_BLSI, "blsi" },
	{ X86_INS_BLSIC, "blsic" },
	{ X86_INS_BLSMSK, "blsmsk" },
	{ X86_INS_BLSR, "blsr" },
	{ X86_INS_BOUND, "bound" },
	{ X86_INS_BSF, "bsf" },
	{ X86_INS_BSR, "bsr" },
	{ X86_INS_BSWAP, "bswap" },
	{ X86_INS_BT, "bt" },
	{ X86_INS_BTC, "btc" },
	{ X86_INS_BTR, "btr" },
	{ X86_INS_BTS, "bts" },
	{ X86_INS_BZHI, "bzhi" },
	{ X86_INS_CALL, "call" },
	{ X86_INS_CBW, "cbw" },
	{ X86_INS_CDQ, "cdq" },
	{ X86_INS_CDQE, "cdqe" },
	{ X86_INS_FCHS, "fchs" },
	{ X86_INS_CLAC, "clac" },
	{ X86_INS_CLC, "clc" },
	{ X86_INS_CLD, "cld" },
	{ X86_INS_CLFLUSH, "clflush" },
	{ X86_INS_CLGI, "clgi" },
	{ X86_INS_CLI, "cli" },
	{ X86_INS_CLTS, "clts" },
	{ X86_INS_CMC, "cmc" },
	{ X86_INS_CMOVA, "cmova" },
	{ X86_INS_CMOVAE, "cmovae" },
	{ X86_INS_CMOVB, "cmovb" },
	{ X86_INS_CMOVBE, "cmovbe" },
	{ X86_INS_FCMOVBE, "fcmovbe" },
	{ X86_INS_FCMOVB, "fcmovb" },
	{ X86_INS_CMOVE, "cmove" },
	{ X86_INS_FCMOVE, "fcmove" },
	{ X86_INS_CMOVG, "cmovg" },
	{ X86_INS_CMOVGE, "cmovge" },
	{ X86_INS_CMOVL, "cmovl" },
	{ X86_INS_CMOVLE, "cmovle" },
	{ X86_INS_FCMOVNBE, "fcmovnbe" },
	{ X86_INS_FCMOVNB, "fcmovnb" },
	{ X86_INS_CMOVNE, "cmovne" },
	{ X86_INS_FCMOVNE, "fcmovne" },
	{ X86_INS_CMOVNO, "cmovno" },
	{ X86_INS_CMOVNP, "cmovnp" },
	{ X86_INS_FCMOVNU, "fcmovnu" },
	{ X86_INS_CMOVNS, "cmovns" },
	{ X86_INS_CMOVO, "cmovo" },
	{ X86_INS_CMOVP, "cmovp" },
	{ X86_INS_FCMOVU, "fcmovu" },
	{ X86_INS_CMOVS, "cmovs" },
	{ X86_INS_CMP, "cmp" },
	{ X86_INS_CMPPD, "cmppd" },
	{ X86_INS_CMPPS, "cmpps" },
	{ X86_INS_CMPSB, "cmpsb" },
	{ X86_INS_CMPSD, "cmpsd" },
	{ X86_INS_CMPSQ, "cmpsq" },
	{ X86_INS_CMPSS, "cmpss" },
	{ X86_INS_CMPSW, "cmpsw" },
	{ X86_INS_CMPXCHG16B, "cmpxchg16b" },
	{ X86_INS_CMPXCHG, "cmpxchg" },
	{ X86_INS_CMPXCHG8B, "cmpxchg8b" },
	{ X86_INS_COMISD, "comisd" },
	{ X86_INS_COMISS, "comiss" },
	{ X86_INS_FCOMP, "fcomp" },
	{ X86_INS_FCOMPI, "fcompi" },
	{ X86_INS_FCOMI, "fcomi" },
	{ X86_INS_FCOM, "fcom" },
	{ X86_INS_FCOS, "fcos" },
	{ X86_INS_CPUID, "cpuid" },
	{ X86_INS_CQO, "cqo" },
	{ X86_INS_CRC32, "crc32" },
	{ X86_INS_CVTDQ2PD, "cvtdq2pd" },
	{ X86_INS_CVTDQ2PS, "cvtdq2ps" },
	{ X86_INS_CVTPD2DQ, "cvtpd2dq" },
	{ X86_INS_CVTPD2PS, "cvtpd2ps" },
	{ X86_INS_CVTPS2DQ, "cvtps2dq" },
	{ X86_INS_CVTPS2PD, "cvtps2pd" },
	{ X86_INS_CVTSD2SI, "cvtsd2si" },
	{ X86_INS_CVTSD2SS, "cvtsd2ss" },
	{ X86_INS_CVTSI2SD, "cvtsi2sd" },
	{ X86_INS_CVTSI2SS, "cvtsi2ss" },
	{ X86_INS_CVTSS2SD, "cvtss2sd" },
	{ X86_INS_CVTSS2SI, "cvtss2si" },
	{ X86_INS_CVTTPD2DQ, "cvttpd2dq" },
	{ X86_INS_CVTTPS2DQ, "cvttps2dq" },
	{ X86_INS_CVTTSD2SI, "cvttsd2si" },
	{ X86_INS_CVTTSS2SI, "cvttss2si" },
	{ X86_INS_CWD, "cwd" },
	{ X86_INS_CWDE, "cwde" },
	{ X86_INS_DAA, "daa" },
	{ X86_INS_DAS, "das" },
	{ X86_INS_DATA16, "data16" },
	{ X86_INS_DEC, "dec" },
	{ X86_INS_DIV, "div" },
	{ X86_INS_DIVPD, "divpd" },
	{ X86_INS_DIVPS, "divps" },
	{ X86_INS_FDIVR, "fdivr" },
	{ X86_INS_FIDIVR, "fidivr" },
	{ X86_INS_FDIVRP, "fdivrp" },
	{ X86_INS_DIVSD, "divsd" },
	{ X86_INS_DIVSS, "divss" },
	{ X86_INS_FDIV, "fdiv" },
	{ X86_INS_FIDIV, "fidiv" },
	{ X86_INS_FDIVP, "fdivp" },
	{ X86_INS_DPPD, "dppd" },
	{ X86_INS_DPPS, "dpps" },
	{ X86_INS_RET, "ret" },
	{ X86_INS_ENCLS, "encls" },
	{ X86_INS_ENCLU, "enclu" },
	{ X86_INS_ENTER, "enter" },
	{ X86_INS_EXTRACTPS, "extractps" },
	{ X86_INS_EXTRQ, "extrq" },
	{ X86_INS_F2XM1, "f2xm1" },
	{ X86_INS_LCALL, "lcall" },
	{ X86_INS_LJMP, "ljmp" },
	{ X86_INS_FBLD, "fbld" },
	{ X86_INS_FBSTP, "fbstp" },
	{ X86_INS_FCOMPP, "fcompp" },
	{ X86_INS_FDECSTP, "fdecstp" },
	{ X86_INS_FEMMS, "femms" },
	{ X86_INS_FFREE, "ffree" },
	{ X86_INS_FICOM, "ficom" },
	{ X86_INS_FICOMP, "ficomp" },
	{ X86_INS_FINCSTP, "fincstp" },
	{ X86_INS_FLDCW, "fldcw" },
	{ X86_INS_FLDENV, "fldenv" },
	{ X86_INS_FLDL2E, "fldl2e" },
	{ X86_INS_FLDL2T, "fldl2t" },
	{ X86_INS_FLDLG2, "fldlg2" },
	{ X86_INS_FLDLN2, "fldln2" },
	{ X86_INS_FLDPI, "fldpi" },
	{ X86_INS_FNCLEX, "fnclex" },
	{ X86_INS_FNINIT, "fninit" },
	{ X86_INS_FNOP, "fnop" },
	{ X86_INS_FNSTCW, "fnstcw" },
	{ X86_INS_FNSTSW, "fnstsw" },
	{ X86_INS_FPATAN, "fpatan" },
	{ X86_INS_FPREM, "fprem" },
	{ X86_INS_FPREM1, "fprem1" },
	{ X86_INS_FPTAN, "fptan" },
	{ X86_INS_FRNDINT, "frndint" },
	{ X86_INS_FRSTOR, "frstor" },
	{ X86_INS_FNSAVE, "fnsave" },
	{ X86_INS_FSCALE, "fscale" },
	{ X86_INS_FSETPM, "fsetpm" },
	{ X86_INS_FSINCOS, "fsincos" },
	{ X86_INS_FNSTENV, "fnstenv" },
	{ X86_INS_FXAM, "fxam" },
	{ X86_INS_FXRSTOR, "fxrstor" },
	{ X86_INS_FXRSTOR64, "fxrstor64" },
	{ X86_INS_FXSAVE, "fxsave" },
	{ X86_INS_FXSAVE64, "fxsave64" },
	{ X86_INS_FXTRACT, "fxtract" },
	{ X86_INS_FYL2X, "fyl2x" },
	{ X86_INS_FYL2XP1, "fyl2xp1" },
	{ X86_INS_MOVAPD, "movapd" },
	{ X86_INS_MOVAPS, "movaps" },
	{ X86_INS_ORPD, "orpd" },
	{ X86_INS_ORPS, "orps" },
	{ X86_INS_VMOVAPD, "vmovapd" },
	{ X86_INS_VMOVAPS, "vmovaps" },
	{ X86_INS_XORPD, "xorpd" },
	{ X86_INS_XORPS, "xorps" },
	{ X86_INS_GETSEC, "getsec" },
	{ X86_INS_HADDPD, "haddpd" },
	{ X86_INS_HADDPS, "haddps" },
	{ X86_INS_HLT, "hlt" },
	{ X86_INS_HSUBPD, "hsubpd" },
	{ X86_INS_HSUBPS, "hsubps" },
	{ X86_INS_IDIV, "idiv" },
	{ X86_INS_FILD, "fild" },
	{ X86_INS_IMUL, "imul" },
	{ X86_INS_IN, "in" },
	{ X86_INS_INC, "inc" },
	{ X86_INS_INSB, "insb" },
	{ X86_INS_INSERTPS, "insertps" },
	{ X86_INS_INSERTQ, "insertq" },
	{ X86_INS_INSD, "insd" },
	{ X86_INS_INSW, "insw" },
	{ X86_INS_INT, "int" },
	{ X86_INS_INT1, "int1" },
	{ X86_INS_INT3, "int3" },
	{ X86_INS_INTO, "into" },
	{ X86_INS_INVD, "invd" },
	{ X86_INS_INVEPT, "invept" },
	{ X86_INS_INVLPG, "invlpg" },
	{ X86_INS_INVLPGA, "invlpga" },
	{ X86_INS_INVPCID, "invpcid" },
	{ X86_INS_INVVPID, "invvpid" },
	{ X86_INS_IRET, "iret" },
	{ X86_INS_IRETD, "iretd" },
	{ X86_INS_IRETQ, "iretq" },
	{ X86_INS_FISTTP, "fisttp" },
	{ X86_INS_FIST, "fist" },
	{ X86_INS_FISTP, "fistp" },
	{ X86_INS_UCOMISD, "ucomisd" },
	{ X86_INS_UCOMISS, "ucomiss" },
	{ X86_INS_VCMP, "vcmp" },
	{ X86_INS_VCOMISD, "vcomisd" },
	{ X86_INS_VCOMISS, "vcomiss" },
	{ X86_INS_VCVTSD2SS, "vcvtsd2ss" },
	{ X86_INS_VCVTSI2SD, "vcvtsi2sd" },
	{ X86_INS_VCVTSI2SS, "vcvtsi2ss" },
	{ X86_INS_VCVTSS2SD, "vcvtss2sd" },
	{ X86_INS_VCVTTSD2SI, "vcvttsd2si" },
	{ X86_INS_VCVTTSD2USI, "vcvttsd2usi" },
	{ X86_INS_VCVTTSS2SI, "vcvttss2si" },
	{ X86_INS_VCVTTSS2USI, "vcvttss2usi" },
	{ X86_INS_VCVTUSI2SD, "vcvtusi2sd" },
	{ X86_INS_VCVTUSI2SS, "vcvtusi2ss" },
	{ X86_INS_VUCOMISD, "vucomisd" },
	{ X86_INS_VUCOMISS, "vucomiss" },
	{ X86_INS_JAE, "jae" },
	{ X86_INS_JA, "ja" },
	{ X86_INS_JBE, "jbe" },
	{ X86_INS_JB, "jb" },
	{ X86_INS_JCXZ, "jcxz" },
	{ X86_INS_JECXZ, "jecxz" },
	{ X86_INS_JE, "je" },
	{ X86_INS_JGE, "jge" },
	{ X86_INS_JG, "jg" },
	{ X86_INS_JLE, "jle" },
	{ X86_INS_JL, "jl" },
	{ X86_INS_JMP, "jmp" },
	{ X86_INS_JNE, "jne" },
	{ X86_INS_JNO, "jno" },
	{ X86_INS_JNP, "jnp" },
	{ X86_INS_JNS, "jns" },
	{ X86_INS_JO, "jo" },
	{ X86_INS_JP, "jp" },
	{ X86_INS_JRCXZ, "jrcxz" },
	{ X86_INS_JS, "js" },
	{ X86_INS_KANDB, "kandb" },
	{ X86_INS_KANDD, "kandd" },
	{ X86_INS_KANDNB, "kandnb" },
	{ X86_INS_KANDND, "kandnd" },
	{ X86_INS_KANDNQ, "kandnq" },
	{ X86_INS_KANDNW, "kandnw" },
	{ X86_INS_KANDQ, "kandq" },
	{ X86_INS_KANDW, "kandw" },
	{ X86_INS_KMOVB, "kmovb" },
	{ X86_INS_KMOVD, "kmovd" },
	{ X86_INS_KMOVQ, "kmovq" },
	{ X86_INS_KMOVW, "kmovw" },
	{ X86_INS_KNOTB, "knotb" },
	{ X86_INS_KNOTD, "knotd" },
	{ X86_INS_KNOTQ, "knotq" },
	{ X86_INS_KNOTW, "knotw" },
	{ X86_INS_KORB, "korb" },
	{ X86_INS_KORD, "kord" },
	{ X86_INS_KORQ, "korq" },
	{ X86_INS_KORTESTW, "kortestw" },
	{ X86_INS_KORW, "korw" },
	{ X86_INS_KSHIFTLW, "kshiftlw" },
	{ X86_INS_KSHIFTRW, "kshiftrw" },
	{ X86_INS_KUNPCKBW, "kunpckbw" },
	{ X86_INS_KXNORB, "kxnorb" },
	{ X86_INS_KXNORD, "kxnord" },
	{ X86_INS_KXNORQ, "kxnorq" },
	{ X86_INS_KXNORW, "kxnorw" },
	{ X86_INS_KXORB, "kxorb" },
	{ X86_INS_KXORD, "kxord" },
	{ X86_INS_KXORQ, "kxorq" },
	{ X86_INS_KXORW, "kxorw" },
	{ X86_INS_LAHF, "lahf" },
	{ X86_INS_LAR, "lar" },
	{ X86_INS_LDDQU, "lddqu" },
	{ X86_INS_LDMXCSR, "ldmxcsr" },
	{ X86_INS_LDS, "lds" },
	{ X86_INS_FLDZ, "fldz" },
	{ X86_INS_FLD1, "fld1" },
	{ X86_INS_FLD, "fld" },
	{ X86_INS_LEA, "lea" },
	{ X86_INS_LEAVE, "leave" },
	{ X86_INS_LES, "les" },
	{ X86_INS_LFENCE, "lfence" },
	{ X86_INS_LFS, "lfs" },
	{ X86_INS_LGDT, "lgdt" },
	{ X86_INS_LGS, "lgs" },
	{ X86_INS_LIDT, "lidt" },
	{ X86_INS_LLDT, "lldt" },
	{ X86_INS_LMSW, "lmsw" },
	{ X86_INS_OR, "or" },
	{ X86_INS_SUB, "sub" },
	{ X86_INS_XOR, "xor" },
	{ X86_INS_LODSB, "lodsb" },
	{ X86_INS_LODSD, "lodsd" },
	{ X86_INS_LODSQ, "lodsq" },
	{ X86_INS_LODSW, "lodsw" },
	{ X86_INS_LOOP, "loop" },
	{ X86_INS_LOOPE, "loope" },
	{ X86_INS_LOOPNE, "loopne" },
	{ X86_INS_RETF, "retf" },
	{ X86_INS_RETFQ, "retfq" },
	{ X86_INS_LSL, "lsl" },
	{ X86_INS_LSS, "lss" },
	{ X86_INS_LTR, "ltr" },
	{ X86_INS_XADD, "xadd" },
	{ X86_INS_LZCNT, "lzcnt" },
	{ X86_INS_MASKMOVDQU, "maskmovdqu" },
	{ X86_INS_MAXPD, "maxpd" },
	{ X86_INS_MAXPS, "maxps" },
	{ X86_INS_MAXSD, "maxsd" },
	{ X86_INS_MAXSS, "maxss" },
	{ X86_INS_MFENCE, "mfence" },
	{ X86_INS_MINPD, "minpd" },
	{ X86_INS_MINPS, "minps" },
	{ X86_INS_MINSD, "minsd" },
	{ X86_INS_MINSS, "minss" },
	{ X86_INS_CVTPD2PI, "cvtpd2pi" },
	{ X86_INS_CVTPI2PD, "cvtpi2pd" },
	{ X86_INS_CVTPI2PS, "cvtpi2ps" },
	{ X86_INS_CVTPS2PI, "cvtps2pi" },
	{ X86_INS_CVTTPD2PI, "cvttpd2pi" },
	{ X86_INS_CVTTPS2PI, "cvttps2pi" },
	{ X86_INS_EMMS, "emms" },
	{ X86_INS_MASKMOVQ, "maskmovq" },
	{ X86_INS_MOVD, "movd" },
	{ X86_INS_MOVDQ2Q, "movdq2q" },
	{ X86_INS_MOVNTQ, "movntq" },
	{ X86_INS_MOVQ2DQ, "movq2dq" },
	{ X86_INS_MOVQ, "movq" },
	{ X86_INS_PABSB, "pabsb" },
	{ X86_INS_PABSD, "pabsd" },
	{ X86_INS_PABSW, "pabsw" },
	{ X86_INS_PACKSSDW, "packssdw" },
	{ X86_INS_PACKSSWB, "packsswb" },
	{ X86_INS_PACKUSWB, "packuswb" },
	{ X86_INS_PADDB, "paddb" },
	{ X86_INS_PADDD, "paddd" },
	{ X86_INS_PADDQ, "paddq" },
	{ X86_INS_PADDSB, "paddsb" },
	{ X86_INS_PADDSW, "paddsw" },
	{ X86_INS_PADDUSB, "paddusb" },
	{ X86_INS_PADDUSW, "paddusw" },
	{ X86_INS_PADDW, "paddw" },
	{ X86_INS_PALIGNR, "palignr" },
	{ X86_INS_PANDN, "pandn" },
	{ X86_INS_PAND, "pand" },
	{ X86_INS_PAVGB, "pavgb" },
	{ X86_INS_PAVGW, "pavgw" },
	{ X86_INS_PCMPEQB, "pcmpeqb" },
	{ X86_INS_PCMPEQD, "pcmpeqd" },
	{ X86_INS_PCMPEQW, "pcmpeqw" },
	{ X86_INS_PCMPGTB, "pcmpgtb" },
	{ X86_INS_PCMPGTD, "pcmpgtd" },
	{ X86_INS_PCMPGTW, "pcmpgtw" },
	{ X86_INS_PEXTRW, "pextrw" },
	{ X86_INS_PHADDSW, "phaddsw" },
	{ X86_INS_PHADDW, "phaddw" },
	{ X86_INS_PHADDD, "phaddd" },
	{ X86_INS_PHSUBD, "phsubd" },
	{ X86_INS_PHSUBSW, "phsubsw" },
	{ X86_INS_PHSUBW, "phsubw" },
	{ X86_INS_PINSRW, "pinsrw" },
	{ X86_INS_PMADDUBSW, "pmaddubsw" },
	{ X86_INS_PMADDWD, "pmaddwd" },
	{ X86_INS_PMAXSW, "pmaxsw" },
	{ X86_INS_PMAXUB, "pmaxub" },
	{ X86_INS_PMINSW, "pminsw" },
	{ X86_INS_PMINUB, "pminub" },
	{ X86_INS_PMOVMSKB, "pmovmskb" },
	{ X86_INS_PMULHRSW, "pmulhrsw" },
	{ X86_INS_PMULHUW, "pmulhuw" },
	{ X86_INS_PMULHW, "pmulhw" },
	{ X86_INS_PMULLW, "pmullw" },
	{ X86_INS_PMULUDQ, "pmuludq" },
	{ X86_INS_POR, "por" },
	{ X86_INS_PSADBW, "psadbw" },
	{ X86_INS_PSHUFB, "pshufb" },
	{ X86_INS_PSHUFW, "pshufw" },
	{ X86_INS_PSIGNB, "psignb" },
	{ X86_INS_PSIGND, "psignd" },
	{ X86_INS_PSIGNW, "psignw" },
	{ X86_INS_PSLLD, "pslld" },
	{ X86_INS_PSLLQ, "psllq" },
	{ X86_INS_PSLLW, "psllw" },
	{ X86_INS_PSRAD, "psrad" },
	{ X86_INS_PSRAW, "psraw" },
	{ X86_INS_PSRLD, "psrld" },
	{ X86_INS_PSRLQ, "psrlq" },
	{ X86_INS_PSRLW, "psrlw" },
	{ X86_INS_PSUBB, "psubb" },
	{ X86_INS_PSUBD, "psubd" },
	{ X86_INS_PSUBQ, "psubq" },
	{ X86_INS_PSUBSB, "psubsb" },
	{ X86_INS_PSUBSW, "psubsw" },
	{ X86_INS_PSUBUSB, "psubusb" },
	{ X86_INS_PSUBUSW, "psubusw" },
	{ X86_INS_PSUBW, "psubw" },
	{ X86_INS_PUNPCKHBW, "punpckhbw" },
	{ X86_INS_PUNPCKHDQ, "punpckhdq" },
	{ X86_INS_PUNPCKHWD, "punpckhwd" },
	{ X86_INS_PUNPCKLBW, "punpcklbw" },
	{ X86_INS_PUNPCKLDQ, "punpckldq" },
	{ X86_INS_PUNPCKLWD, "punpcklwd" },
	{ X86_INS_PXOR, "pxor" },
	{ X86_INS_MONITOR, "monitor" },
	{ X86_INS_MONTMUL, "montmul" },
	{ X86_INS_MOV, "mov" },
	{ X86_INS_MOVABS, "movabs" },
	{ X86_INS_MOVBE, "movbe" },
	{ X86_INS_MOVDDUP, "movddup" },
	{ X86_INS_MOVDQA, "movdqa" },
	{ X86_INS_MOVDQU, "movdqu" },
	{ X86_INS_MOVHLPS, "movhlps" },
	{ X86_INS_MOVHPD, "movhpd" },
	{ X86_INS_MOVHPS, "movhps" },
	{ X86_INS_MOVLHPS, "movlhps" },
	{ X86_INS_MOVLPD, "movlpd" },
	{ X86_INS_MOVLPS, "movlps" },
	{ X86_INS_MOVMSKPD, "movmskpd" },
	{ X86_INS_MOVMSKPS, "movmskps" },
	{ X86_INS_MOVNTDQA, "movntdqa" },
	{ X86_INS_MOVNTDQ, "movntdq" },
	{ X86_INS_MOVNTI, "movnti" },
	{ X86_INS_MOVNTPD, "movntpd" },
	{ X86_INS_MOVNTPS, "movntps" },
	{ X86_INS_MOVNTSD, "movntsd" },
	{ X86_INS_MOVNTSS, "movntss" },
	{ X86_INS_MOVSB, "movsb" },
	{ X86_INS_MOVSD, "movsd" },
	{ X86_INS_MOVSHDUP, "movshdup" },
	{ X86_INS_MOVSLDUP, "movsldup" },
	{ X86_INS_MOVSQ, "movsq" },
	{ X86_INS_MOVSS, "movss" },
	{ X86_INS_MOVSW, "movsw" },
	{ X86_INS_MOVSX, "movsx" },
	{ X86_INS_MOVSXD, "movsxd" },
	{ X86_INS_MOVUPD, "movupd" },
	{ X86_INS_MOVUPS, "movups" },
	{ X86_INS_MOVZX, "movzx" },
	{ X86_INS_MPSADBW, "mpsadbw" },
	{ X86_INS_MUL, "mul" },
	{ X86_INS_MULPD, "mulpd" },
	{ X86_INS_MULPS, "mulps" },
	{ X86_INS_MULSD, "mulsd" },
	{ X86_INS_MULSS, "mulss" },
	{ X86_INS_MULX, "mulx" },
	{ X86_INS_FMUL, "fmul" },
	{ X86_INS_FIMUL, "fimul" },
	{ X86_INS_FMULP, "fmulp" },
	{ X86_INS_MWAIT, "mwait" },
	{ X86_INS_NEG, "neg" },
	{ X86_INS_NOP, "nop" },
	{ X86_INS_NOT, "not" },
	{ X86_INS_OUT, "out" },
	{ X86_INS_OUTSB, "outsb" },
	{ X86_INS_OUTSD, "outsd" },
	{ X86_INS_OUTSW, "outsw" },
	{ X86_INS_PACKUSDW, "packusdw" },
	{ X86_INS_PAUSE, "pause" },
	{ X86_INS_PAVGUSB, "pavgusb" },
	{ X86_INS_PBLENDVB, "pblendvb" },
	{ X86_INS_PBLENDW, "pblendw" },
	{ X86_INS_PCLMULQDQ, "pclmulqdq" },
	{ X86_INS_PCMPEQQ, "pcmpeqq" },
	{ X86_INS_PCMPESTRI, "pcmpestri" },
	{ X86_INS_PCMPESTRM, "pcmpestrm" },
	{ X86_INS_PCMPGTQ, "pcmpgtq" },
	{ X86_INS_PCMPISTRI, "pcmpistri" },
	{ X86_INS_PCMPISTRM, "pcmpistrm" },
	{ X86_INS_PDEP, "pdep" },
	{ X86_INS_PEXT, "pext" },
	{ X86_INS_PEXTRB, "pextrb" },
	{ X86_INS_PEXTRD, "pextrd" },
	{ X86_INS_PEXTRQ, "pextrq" },
	{ X86_INS_PF2ID, "pf2id" },
	{ X86_INS_PF2IW, "pf2iw" },
	{ X86_INS_PFACC, "pfacc" },
	{ X86_INS_PFADD, "pfadd" },
	{ X86_INS_PFCMPEQ, "pfcmpeq" },
	{ X86_INS_PFCMPGE, "pfcmpge" },
	{ X86_INS_PFCMPGT, "pfcmpgt" },
	{ X86_INS_PFMAX, "pfmax" },
	{ X86_INS_PFMIN, "pfmin" },
	{ X86_INS_PFMUL, "pfmul" },
	{ X86_INS_PFNACC, "pfnacc" },
	{ X86_INS_PFPNACC, "pfpnacc" },
	{ X86_INS_PFRCPIT1, "pfrcpit1" },
	{ X86_INS_PFRCPIT2, "pfrcpit2" },
	{ X86_INS_PFRCP, "pfrcp" },
	{ X86_INS_PFRSQIT1, "pfrsqit1" },
	{ X86_INS_PFRSQRT, "pfrsqrt" },
	{ X86_INS_PFSUBR, "pfsubr" },
	{ X86_INS_PFSUB, "pfsub" },
	{ X86_INS_PHMINPOSUW, "phminposuw" },
	{ X86_INS_PI2FD, "pi2fd" },
	{ X86_INS_PI2FW, "pi2fw" },
	{ X86_INS_PINSRB, "pinsrb" },
	{ X86_INS_PINSRD, "pinsrd" },
	{ X86_INS_PINSRQ, "pinsrq" },
	{ X86_INS_PMAXSB, "pmaxsb" },
	{ X86_INS_PMAXSD, "pmaxsd" },
	{ X86_INS_PMAXUD, "pmaxud" },
	{ X86_INS_PMAXUW, "pmaxuw" },
	{ X86_INS_PMINSB, "pminsb" },
	{ X86_INS_PMINSD, "pminsd" },
	{ X86_INS_PMINUD, "pminud" },
	{ X86_INS_PMINUW, "pminuw" },
	{ X86_INS_PMOVSXBD, "pmovsxbd" },
	{ X86_INS_PMOVSXBQ, "pmovsxbq" },
	{ X86_INS_PMOVSXBW, "pmovsxbw" },
	{ X86_INS_PMOVSXDQ, "pmovsxdq" },
	{ X86_INS_PMOVSXWD, "pmovsxwd" },
	{ X86_INS_PMOVSXWQ, "pmovsxwq" },
	{ X86_INS_PMOVZXBD, "pmovzxbd" },
	{ X86_INS_PMOVZXBQ, "pmovzxbq" },
	{ X86_INS_PMOVZXBW, "pmovzxbw" },
	{ X86_INS_PMOVZXDQ, "pmovzxdq" },
	{ X86_INS_PMOVZXWD, "pmovzxwd" },
	{ X86_INS_PMOVZXWQ, "pmovzxwq" },
	{ X86_INS_PMULDQ, "pmuldq" },
	{ X86_INS_PMULHRW, "pmulhrw" },
	{ X86_INS_PMULLD, "pmulld" },
	{ X86_INS_POP, "pop" },
	{ X86_INS_POPAW, "popaw" },
	{ X86_INS_POPAL, "popal" },
	{ X86_INS_POPCNT, "popcnt" },
	{ X86_INS_POPF, "popf" },
	{ X86_INS_POPFD, "popfd" },
	{ X86_INS_POPFQ, "popfq" },
	{ X86_INS_PREFETCH, "prefetch" },
	{ X86_INS_PREFETCHNTA, "prefetchnta" },
	{ X86_INS_PREFETCHT0, "prefetcht0" },
	{ X86_INS_PREFETCHT1, "prefetcht1" },
	{ X86_INS_PREFETCHT2, "prefetcht2" },
	{ X86_INS_PREFETCHW, "prefetchw" },
	{ X86_INS_PSHUFD, "pshufd" },
	{ X86_INS_PSHUFHW, "pshufhw" },
	{ X86_INS_PSHUFLW, "pshuflw" },
	{ X86_INS_PSLLDQ, "pslldq" },
	{ X86_INS_PSRLDQ, "psrldq" },
	{ X86_INS_PSWAPD, "pswapd" },
	{ X86_INS_PTEST, "ptest" },
	{ X86_INS_PUNPCKHQDQ, "punpckhqdq" },
	{ X86_INS_PUNPCKLQDQ, "punpcklqdq" },
	{ X86_INS_PUSH, "push" },
	{ X86_INS_PUSHAW, "pushaw" },
	{ X86_INS_PUSHAL, "pushal" },
	{ X86_INS_PUSHF, "pushf" },
	{ X86_INS_PUSHFD, "pushfd" },
	{ X86_INS_PUSHFQ, "pushfq" },
	{ X86_INS_RCL, "rcl" },
	{ X86_INS_RCPPS, "rcpps" },
	{ X86_INS_RCPSS, "rcpss" },
	{ X86_INS_RCR, "rcr" },
	{ X86_INS_RDFSBASE, "rdfsbase" },
	{ X86_INS_RDGSBASE, "rdgsbase" },
	{ X86_INS_RDMSR, "rdmsr" },
	{ X86_INS_RDPMC, "rdpmc" },
	{ X86_INS_RDRAND, "rdrand" },
	{ X86_INS_RDSEED, "rdseed" },
	{ X86_INS_RDTSC, "rdtsc" },
	{ X86_INS_RDTSCP, "rdtscp" },
	{ X86_INS_ROL, "rol" },
	{ X86_INS_ROR, "ror" },
	{ X86_INS_RORX, "rorx" },
	{ X86_INS_ROUNDPD, "roundpd" },
	{ X86_INS_ROUNDPS, "roundps" },
	{ X86_INS_ROUNDSD, "roundsd" },
	{ X86_INS_ROUNDSS, "roundss" },
	{ X86_INS_RSM, "rsm" },
	{ X86_INS_RSQRTPS, "rsqrtps" },
	{ X86_INS_RSQRTSS, "rsqrtss" },
	{ X86_INS_SAHF, "sahf" },
	{ X86_INS_SAL, "sal" },
	{ X86_INS_SALC, "salc" },
	{ X86_INS_SAR, "sar" },
	{ X86_INS_SARX, "sarx" },
	{ X86_INS_SBB, "sbb" },
	{ X86_INS_SCASB, "scasb" },
	{ X86_INS_SCASD, "scasd" },
	{ X86_INS_SCASQ, "scasq" },
	{ X86_INS_SCASW, "scasw" },
	{ X86_INS_SETAE, "setae" },
	{ X86_INS_SETA, "seta" },
	{ X86_INS_SETBE, "setbe" },
	{ X86_INS_SETB, "setb" },
	{ X86_INS_SETE, "sete" },
	{ X86_INS_SETGE, "setge" },
	{ X86_INS_SETG, "setg" },
	{ X86_INS_SETLE, "setle" },
	{ X86_INS_SETL, "setl" },
	{ X86_INS_SETNE, "setne" },
	{ X86_INS_SETNO, "setno" },
	{ X86_INS_SETNP, "setnp" },
	{ X86_INS_SETNS, "setns" },
	{ X86_INS_SETO, "seto" },
	{ X86_INS_SETP, "setp" },
	{ X86_INS_SETS, "sets" },
	{ X86_INS_SFENCE, "sfence" },
	{ X86_INS_SGDT, "sgdt" },
	{ X86_INS_SHA1MSG1, "sha1msg1" },
	{ X86_INS_SHA1MSG2, "sha1msg2" },
	{ X86_INS_SHA1NEXTE, "sha1nexte" },
	{ X86_INS_SHA1RNDS4, "sha1rnds4" },
	{ X86_INS_SHA256MSG1, "sha256msg1" },
	{ X86_INS_SHA256MSG2, "sha256msg2" },
	{ X86_INS_SHA256RNDS2, "sha256rnds2" },
	{ X86_INS_SHL, "shl" },
	{ X86_INS_SHLD, "shld" },
	{ X86_INS_SHLX, "shlx" },
	{ X86_INS_SHR, "shr" },
	{ X86_INS_SHRD, "shrd" },
	{ X86_INS_SHRX, "shrx" },
	{ X86_INS_SHUFPD, "shufpd" },
	{ X86_INS_SHUFPS, "shufps" },
	{ X86_INS_SIDT, "sidt" },
	{ X86_INS_FSIN, "fsin" },
	{ X86_INS_SKINIT, "skinit" },
	{ X86_INS_SLDT, "sldt" },
	{ X86_INS_SMSW, "smsw" },
	{ X86_INS_SQRTPD, "sqrtpd" },
	{ X86_INS_SQRTPS, "sqrtps" },
	{ X86_INS_SQRTSD, "sqrtsd" },
	{ X86_INS_SQRTSS, "sqrtss" },
	{ X86_INS_FSQRT, "fsqrt" },
	{ X86_INS_STAC, "stac" },
	{ X86_INS_STC, "stc" },
	{ X86_INS_STD, "std" },
	{ X86_INS_STGI, "stgi" },
	{ X86_INS_STI, "sti" },
	{ X86_INS_STMXCSR, "stmxcsr" },
	{ X86_INS_STOSB, "stosb" },
	{ X86_INS_STOSD, "stosd" },
	{ X86_INS_STOSQ, "stosq" },
	{ X86_INS_STOSW, "stosw" },
	{ X86_INS_STR, "str" },
	{ X86_INS_FST, "fst" },
	{ X86_INS_FSTP, "fstp" },
	{ X86_INS_FSTPNCE, "fstpnce" },
	{ X86_INS_SUBPD, "subpd" },
	{ X86_INS_SUBPS, "subps" },
	{ X86_INS_FSUBR, "fsubr" },
	{ X86_INS_FISUBR, "fisubr" },
	{ X86_INS_FSUBRP, "fsubrp" },
	{ X86_INS_SUBSD, "subsd" },
	{ X86_INS_SUBSS, "subss" },
	{ X86_INS_FSUB, "fsub" },
	{ X86_INS_FISUB, "fisub" },
	{ X86_INS_FSUBP, "fsubp" },
	{ X86_INS_SWAPGS, "swapgs" },
	{ X86_INS_SYSCALL, "syscall" },
	{ X86_INS_SYSENTER, "sysenter" },
	{ X86_INS_SYSEXIT, "sysexit" },
	{ X86_INS_SYSRET, "sysret" },
	{ X86_INS_T1MSKC, "t1mskc" },
	{ X86_INS_TEST, "test" },
	{ X86_INS_UD2, "ud2" },
	{ X86_INS_FTST, "ftst" },
	{ X86_INS_TZCNT, "tzcnt" },
	{ X86_INS_TZMSK, "tzmsk" },
	{ X86_INS_FUCOMPI, "fucompi" },
	{ X86_INS_FUCOMI, "fucomi" },
	{ X86_INS_FUCOMPP, "fucompp" },
	{ X86_INS_FUCOMP, "fucomp" },
	{ X86_INS_FUCOM, "fucom" },
	{ X86_INS_UD2B, "ud2b" },
	{ X86_INS_UNPCKHPD, "unpckhpd" },
	{ X86_INS_UNPCKHPS, "unpckhps" },
	{ X86_INS_UNPCKLPD, "unpcklpd" },
	{ X86_INS_UNPCKLPS, "unpcklps" },
	{ X86_INS_VADDPD, "vaddpd" },
	{ X86_INS_VADDPS, "vaddps" },
	{ X86_INS_VADDSD, "vaddsd" },
	{ X86_INS_VADDSS, "vaddss" },
	{ X86_INS_VADDSUBPD, "vaddsubpd" },
	{ X86_INS_VADDSUBPS, "vaddsubps" },
	{ X86_INS_VAESDECLAST, "vaesdeclast" },
	{ X86_INS_VAESDEC, "vaesdec" },
	{ X86_INS_VAESENCLAST, "vaesenclast" },
	{ X86_INS_VAESENC, "vaesenc" },
	{ X86_INS_VAESIMC, "vaesimc" },
	{ X86_INS_VAESKEYGENASSIST, "vaeskeygenassist" },
	{ X86_INS_VALIGND, "valignd" },
	{ X86_INS_VALIGNQ, "valignq" },
	{ X86_INS_VANDNPD, "vandnpd" },
	{ X86_INS_VANDNPS, "vandnps" },
	{ X86_INS_VANDPD, "vandpd" },
	{ X86_INS_VANDPS, "vandps" },
	{ X86_INS_VBLENDMPD, "vblendmpd" },
	{ X86_INS_VBLENDMPS, "vblendmps" },
	{ X86_INS_VBLENDPD, "vblendpd" },
	{ X86_INS_VBLENDPS, "vblendps" },
	{ X86_INS_VBLENDVPD, "vblendvpd" },
	{ X86_INS_VBLENDVPS, "vblendvps" },
	{ X86_INS_VBROADCASTF128, "vbroadcastf128" },
	{ X86_INS_VBROADCASTI128, "vbroadcasti128" },
	{ X86_INS_VBROADCASTI32X4, "vbroadcasti32x4" },
	{ X86_INS_VBROADCASTI64X4, "vbroadcasti64x4" },
	{ X86_INS_VBROADCASTSD, "vbroadcastsd" },
	{ X86_INS_VBROADCASTSS, "vbroadcastss" },
	{ X86_INS_VCMPPD, "vcmppd" },
	{ X86_INS_VCMPPS, "vcmpps" },
	{ X86_INS_VCMPSD, "vcmpsd" },
	{ X86_INS_VCMPSS, "vcmpss" },
	{ X86_INS_VCVTDQ2PD, "vcvtdq2pd" },
	{ X86_INS_VCVTDQ2PS, "vcvtdq2ps" },
	{ X86_INS_VCVTPD2DQX, "vcvtpd2dqx" },
	{ X86_INS_VCVTPD2DQ, "vcvtpd2dq" },
	{ X86_INS_VCVTPD2PSX, "vcvtpd2psx" },
	{ X86_INS_VCVTPD2PS, "vcvtpd2ps" },
	{ X86_INS_VCVTPD2UDQ, "vcvtpd2udq" },
	{ X86_INS_VCVTPH2PS, "vcvtph2ps" },
	{ X86_INS_VCVTPS2DQ, "vcvtps2dq" },
	{ X86_INS_VCVTPS2PD, "vcvtps2pd" },
	{ X86_INS_VCVTPS2PH, "vcvtps2ph" },
	{ X86_INS_VCVTPS2UDQ, "vcvtps2udq" },
	{ X86_INS_VCVTSD2SI, "vcvtsd2si" },
	{ X86_INS_VCVTSD2USI, "vcvtsd2usi" },
	{ X86_INS_VCVTSS2SI, "vcvtss2si" },
	{ X86_INS_VCVTSS2USI, "vcvtss2usi" },
	{ X86_INS_VCVTTPD2DQX, "vcvttpd2dqx" },
	{ X86_INS_VCVTTPD2DQ, "vcvttpd2dq" },
	{ X86_INS_VCVTTPD2UDQ, "vcvttpd2udq" },
	{ X86_INS_VCVTTPS2DQ, "vcvttps2dq" },
	{ X86_INS_VCVTTPS2UDQ, "vcvttps2udq" },
	{ X86_INS_VCVTUDQ2PD, "vcvtudq2pd" },
	{ X86_INS_VCVTUDQ2PS, "vcvtudq2ps" },
	{ X86_INS_VDIVPD, "vdivpd" },
	{ X86_INS_VDIVPS, "vdivps" },
	{ X86_INS_VDIVSD, "vdivsd" },
	{ X86_INS_VDIVSS, "vdivss" },
	{ X86_INS_VDPPD, "vdppd" },
	{ X86_INS_VDPPS, "vdpps" },
	{ X86_INS_VERR, "verr" },
	{ X86_INS_VERW, "verw" },
	{ X86_INS_VEXTRACTF128, "vextractf128" },
	{ X86_INS_VEXTRACTF32X4, "vextractf32x4" },
	{ X86_INS_VEXTRACTF64X4, "vextractf64x4" },
	{ X86_INS_VEXTRACTI128, "vextracti128" },
	{ X86_INS_VEXTRACTI32X4, "vextracti32x4" },
	{ X86_INS_VEXTRACTI64X4, "vextracti64x4" },
	{ X86_INS_VEXTRACTPS, "vextractps" },
	{ X86_INS_VFMADD132PD, "vfmadd132pd" },
	{ X86_INS_VFMADD132PS, "vfmadd132ps" },
	{ X86_INS_VFMADD213PD, "vfmadd213pd" },
	{ X86_INS_VFMADD213PS, "vfmadd213ps" },
	{ X86_INS_VFMADDPD, "vfmaddpd" },
	{ X86_INS_VFMADD231PD, "vfmadd231pd" },
	{ X86_INS_VFMADDPS, "vfmaddps" },
	{ X86_INS_VFMADD231PS, "vfmadd231ps" },
	{ X86_INS_VFMADDSD, "vfmaddsd" },
	{ X86_INS_VFMADD213SD, "vfmadd213sd" },
	{ X86_INS_VFMADD132SD, "vfmadd132sd" },
	{ X86_INS_VFMADD231SD, "vfmadd231sd" },
	{ X86_INS_VFMADDSS, "vfmaddss" },
	{ X86_INS_VFMADD213SS, "vfmadd213ss" },
	{ X86_INS_VFMADD132SS, "vfmadd132ss" },
	{ X86_INS_VFMADD231SS, "vfmadd231ss" },
	{ X86_INS_VFMADDSUB132PD, "vfmaddsub132pd" },
	{ X86_INS_VFMADDSUB132PS, "vfmaddsub132ps" },
	{ X86_INS_VFMADDSUB213PD, "vfmaddsub213pd" },
	{ X86_INS_VFMADDSUB213PS, "vfmaddsub213ps" },
	{ X86_INS_VFMADDSUBPD, "vfmaddsubpd" },
	{ X86_INS_VFMADDSUB231PD, "vfmaddsub231pd" },
	{ X86_INS_VFMADDSUBPS, "vfmaddsubps" },
	{ X86_INS_VFMADDSUB231PS, "vfmaddsub231ps" },
	{ X86_INS_VFMSUB132PD, "vfmsub132pd" },
	{ X86_INS_VFMSUB132PS, "vfmsub132ps" },
	{ X86_INS_VFMSUB213PD, "vfmsub213pd" },
	{ X86_INS_VFMSUB213PS, "vfmsub213ps" },
	{ X86_INS_VFMSUBADD132PD, "vfmsubadd132pd" },
	{ X86_INS_VFMSUBADD132PS, "vfmsubadd132ps" },
	{ X86_INS_VFMSUBADD213PD, "vfmsubadd213pd" },
	{ X86_INS_VFMSUBADD213PS, "vfmsubadd213ps" },
	{ X86_INS_VFMSUBADDPD, "vfmsubaddpd" },
	{ X86_INS_VFMSUBADD231PD, "vfmsubadd231pd" },
	{ X86_INS_VFMSUBADDPS, "vfmsubaddps" },
	{ X86_INS_VFMSUBADD231PS, "vfmsubadd231ps" },
	{ X86_INS_VFMSUBPD, "vfmsubpd" },
	{ X86_INS_VFMSUB231PD, "vfmsub231pd" },
	{ X86_INS_VFMSUBPS, "vfmsubps" },
	{ X86_INS_VFMSUB231PS, "vfmsub231ps" },
	{ X86_INS_VFMSUBSD, "vfmsubsd" },
	{ X86_INS_VFMSUB213SD, "vfmsub213sd" },
	{ X86_INS_VFMSUB132SD, "vfmsub132sd" },
	{ X86_INS_VFMSUB231SD, "vfmsub231sd" },
	{ X86_INS_VFMSUBSS, "vfmsubss" },
	{ X86_INS_VFMSUB213SS, "vfmsub213ss" },
	{ X86_INS_VFMSUB132SS, "vfmsub132ss" },
	{ X86_INS_VFMSUB231SS, "vfmsub231ss" },
	{ X86_INS_VFNMADD132PD, "vfnmadd132pd" },
	{ X86_INS_VFNMADD132PS, "vfnmadd132ps" },
	{ X86_INS_VFNMADD213PD, "vfnmadd213pd" },
	{ X86_INS_VFNMADD213PS, "vfnmadd213ps" },
	{ X86_INS_VFNMADDPD, "vfnmaddpd" },
	{ X86_INS_VFNMADD231PD, "vfnmadd231pd" },
	{ X86_INS_VFNMADDPS, "vfnmaddps" },
	{ X86_INS_VFNMADD231PS, "vfnmadd231ps" },
	{ X86_INS_VFNMADDSD, "vfnmaddsd" },
	{ X86_INS_VFNMADD213SD, "vfnmadd213sd" },
	{ X86_INS_VFNMADD132SD, "vfnmadd132sd" },
	{ X86_INS_VFNMADD231SD, "vfnmadd231sd" },
	{ X86_INS_VFNMADDSS, "vfnmaddss" },
	{ X86_INS_VFNMADD213SS, "vfnmadd213ss" },
	{ X86_INS_VFNMADD132SS, "vfnmadd132ss" },
	{ X86_INS_VFNMADD231SS, "vfnmadd231ss" },
	{ X86_INS_VFNMSUB132PD, "vfnmsub132pd" },
	{ X86_INS_VFNMSUB132PS, "vfnmsub132ps" },
	{ X86_INS_VFNMSUB213PD, "vfnmsub213pd" },
	{ X86_INS_VFNMSUB213PS, "vfnmsub213ps" },
	{ X86_INS_VFNMSUBPD, "vfnmsubpd" },
	{ X86_INS_VFNMSUB231PD, "vfnmsub231pd" },
	{ X86_INS_VFNMSUBPS, "vfnmsubps" },
	{ X86_INS_VFNMSUB231PS, "vfnmsub231ps" },
	{ X86_INS_VFNMSUBSD, "vfnmsubsd" },
	{ X86_INS_VFNMSUB213SD, "vfnmsub213sd" },
	{ X86_INS_VFNMSUB132SD, "vfnmsub132sd" },
	{ X86_INS_VFNMSUB231SD, "vfnmsub231sd" },
	{ X86_INS_VFNMSUBSS, "vfnmsubss" },
	{ X86_INS_VFNMSUB213SS, "vfnmsub213ss" },
	{ X86_INS_VFNMSUB132SS, "vfnmsub132ss" },
	{ X86_INS_VFNMSUB231SS, "vfnmsub231ss" },
	{ X86_INS_VFRCZPD, "vfrczpd" },
	{ X86_INS_VFRCZPS, "vfrczps" },
	{ X86_INS_VFRCZSD, "vfrczsd" },
	{ X86_INS_VFRCZSS, "vfrczss" },
	{ X86_INS_VORPD, "vorpd" },
	{ X86_INS_VORPS, "vorps" },
	{ X86_INS_VXORPD, "vxorpd" },
	{ X86_INS_VXORPS, "vxorps" },
	{ X86_INS_VGATHERDPD, "vgatherdpd" },
	{ X86_INS_VGATHERDPS, "vgatherdps" },
	{ X86_INS_VGATHERPF0DPD, "vgatherpf0dpd" },
	{ X86_INS_VGATHERPF0DPS, "vgatherpf0dps" },
	{ X86_INS_VGATHERPF0QPD, "vgatherpf0qpd" },
	{ X86_INS_VGATHERPF0QPS, "vgatherpf0qps" },
	{ X86_INS_VGATHERPF1DPD, "vgatherpf1dpd" },
	{ X86_INS_VGATHERPF1DPS, "vgatherpf1dps" },
	{ X86_INS_VGATHERPF1QPD, "vgatherpf1qpd" },
	{ X86_INS_VGATHERPF1QPS, "vgatherpf1qps" },
	{ X86_INS_VGATHERQPD, "vgatherqpd" },
	{ X86_INS_VGATHERQPS, "vgatherqps" },
	{ X86_INS_VHADDPD, "vhaddpd" },
	{ X86_INS_VHADDPS, "vhaddps" },
	{ X86_INS_VHSUBPD, "vhsubpd" },
	{ X86_INS_VHSUBPS, "vhsubps" },
	{ X86_INS_VINSERTF128, "vinsertf128" },
	{ X86_INS_VINSERTF32X4, "vinsertf32x4" },
	{ X86_INS_VINSERTF64X4, "vinsertf64x4" },
	{ X86_INS_VINSERTI128, "vinserti128" },
	{ X86_INS_VINSERTI32X4, "vinserti32x4" },
	{ X86_INS_VINSERTI64X4, "vinserti64x4" },
	{ X86_INS_VINSERTPS, "vinsertps" },
	{ X86_INS_VLDDQU, "vlddqu" },
	{ X86_INS_VLDMXCSR, "vldmxcsr" },
	{ X86_INS_VMASKMOVDQU, "vmaskmovdqu" },
	{ X86_INS_VMASKMOVPD, "vmaskmovpd" },
	{ X86_INS_VMASKMOVPS, "vmaskmovps" },
	{ X86_INS_VMAXPD, "vmaxpd" },
	{ X86_INS_VMAXPS, "vmaxps" },
	{ X86_INS_VMAXSD, "vmaxsd" },
	{ X86_INS_VMAXSS, "vmaxss" },
	{ X86_INS_VMCALL, "vmcall" },
	{ X86_INS_VMCLEAR, "vmclear" },
	{ X86_INS_VMFUNC, "vmfunc" },
	{ X86_INS_VMINPD, "vminpd" },
	{ X86_INS_VMINPS, "vminps" },
	{ X86_INS_VMINSD, "vminsd" },
	{ X86_INS_VMINSS, "vminss" },
	{ X86_INS_VMLAUNCH, "vmlaunch" },
	{ X86_INS_VMLOAD, "vmload" },
	{ X86_INS_VMMCALL, "vmmcall" },
	{ X86_INS_VMOVQ, "vmovq" },
	{ X86_INS_VMOVDDUP, "vmovddup" },
	{ X86_INS_VMOVD, "vmovd" },
	{ X86_INS_VMOVDQA32, "vmovdqa32" },
	{ X86_INS_VMOVDQA64, "vmovdqa64" },
	{ X86_INS_VMOVDQA, "vmovdqa" },
	{ X86_INS_VMOVDQU16, "vmovdqu16" },
	{ X86_INS_VMOVDQU32, "vmovdqu32" },
	{ X86_INS_VMOVDQU64, "vmovdqu64" },
	{ X86_INS_VMOVDQU8, "vmovdqu8" },
	{ X86_INS_VMOVDQU, "vmovdqu" },
	{ X86_INS_VMOVHLPS, "vmovhlps" },
	{ X86_INS_VMOVHPD, "vmovhpd" },
	{ X86_INS_VMOVHPS, "vmovhps" },
	{ X86_INS_VMOVLHPS, "vmovlhps" },
	{ X86_INS_VMOVLPD, "vmovlpd" },
	{ X86_INS_VMOVLPS, "vmovlps" },
	{ X86_INS_VMOVMSKPD, "vmovmskpd" },
	{ X86_INS_VMOVMSKPS, "vmovmskps" },
	{ X86_INS_VMOVNTDQA, "vmovntdqa" },
	{ X86_INS_VMOVNTDQ, "vmovntdq" },
	{ X86_INS_VMOVNTPD, "vmovntpd" },
	{ X86_INS_VMOVNTPS, "vmovntps" },
	{ X86_INS_VMOVSD, "vmovsd" },
	{ X86_INS_VMOVSHDUP, "vmovshdup" },
	{ X86_INS_VMOVSLDUP, "vmovsldup" },
	{ X86_INS_VMOVSS, "vmovss" },
	{ X86_INS_VMOVUPD, "vmovupd" },
	{ X86_INS_VMOVUPS, "vmovups" },
	{ X86_INS_VMPSADBW, "vmpsadbw" },
	{ X86_INS_VMPTRLD, "vmptrld" },
	{ X86_INS_VMPTRST, "vmptrst" },
	{ X86_INS_VMREAD, "vmread" },
	{ X86_INS_VMRESUME, "vmresume" },
	{ X86_INS_VMRUN, "vmrun" },
	{ X86_INS_VMSAVE, "vmsave" },
	{ X86_INS_VMULPD, "vmulpd" },
	{ X86_INS_VMULPS, "vmulps" },
	{ X86_INS_VMULSD, "vmulsd" },
	{ X86_INS_VMULSS, "vmulss" },
	{ X86_INS_VMWRITE, "vmwrite" },
	{ X86_INS_VMXOFF, "vmxoff" },
	{ X86_INS_VMXON, "vmxon" },
	{ X86_INS_VPABSB, "vpabsb" },
	{ X86_INS_VPABSD, "vpabsd" },
	{ X86_INS_VPABSQ, "vpabsq" },
	{ X86_INS_VPABSW, "vpabsw" },
	{ X86_INS_VPACKSSDW, "vpackssdw" },
	{ X86_INS_VPACKSSWB, "vpacksswb" },
	{ X86_INS_VPACKUSDW, "vpackusdw" },
	{ X86_INS_VPACKUSWB, "vpackuswb" },
	{ X86_INS_VPADDB, "vpaddb" },
	{ X86_INS_VPADDD, "vpaddd" },
	{ X86_INS_VPADDQ, "vpaddq" },
	{ X86_INS_VPADDSB, "vpaddsb" },
	{ X86_INS_VPADDSW, "vpaddsw" },
	{ X86_INS_VPADDUSB, "vpaddusb" },
	{ X86_INS_VPADDUSW, "vpaddusw" },
	{ X86_INS_VPADDW, "vpaddw" },
	{ X86_INS_VPALIGNR, "vpalignr" },
	{ X86_INS_VPANDD, "vpandd" },
	{ X86_INS_VPANDND, "vpandnd" },
	{ X86_INS_VPANDNQ, "vpandnq" },
	{ X86_INS_VPANDN, "vpandn" },
	{ X86_INS_VPANDQ, "vpandq" },
	{ X86_INS_VPAND, "vpand" },
	{ X86_INS_VPAVGB, "vpavgb" },
	{ X86_INS_VPAVGW, "vpavgw" },
	{ X86_INS_VPBLENDD, "vpblendd" },
	{ X86_INS_VPBLENDMD, "vpblendmd" },
	{ X86_INS_VPBLENDMQ, "vpblendmq" },
	{ X86_INS_VPBLENDVB, "vpblendvb" },
	{ X86_INS_VPBLENDW, "vpblendw" },
	{ X86_INS_VPBROADCASTB, "vpbroadcastb" },
	{ X86_INS_VPBROADCASTD, "vpbroadcastd" },
	{ X86_INS_VPBROADCASTMB2Q, "vpbroadcastmb2q" },
	{ X86_INS_VPBROADCASTMW2D, "vpbroadcastmw2d" },
	{ X86_INS_VPBROADCASTQ, "vpbroadcastq" },
	{ X86_INS_VPBROADCASTW, "vpbroadcastw" },
	{ X86_INS_VPCLMULQDQ, "vpclmulqdq" },
	{ X86_INS_VPCMOV, "vpcmov" },
	{ X86_INS_VPCMP, "vpcmp" },
	{ X86_INS_VPCMPD, "vpcmpd" },
	{ X86_INS_VPCMPEQB, "vpcmpeqb" },
	{ X86_INS_VPCMPEQD, "vpcmpeqd" },
	{ X86_INS_VPCMPEQQ, "vpcmpeqq" },
	{ X86_INS_VPCMPEQW, "vpcmpeqw" },
	{ X86_INS_VPCMPESTRI, "vpcmpestri" },
	{ X86_INS_VPCMPESTRM, "vpcmpestrm" },
	{ X86_INS_VPCMPGTB, "vpcmpgtb" },
	{ X86_INS_VPCMPGTD, "vpcmpgtd" },
	{ X86_INS_VPCMPGTQ, "vpcmpgtq" },
	{ X86_INS_VPCMPGTW, "vpcmpgtw" },
	{ X86_INS_VPCMPISTRI, "vpcmpistri" },
	{ X86_INS_VPCMPISTRM, "vpcmpistrm" },
	{ X86_INS_VPCMPQ, "vpcmpq" },
	{ X86_INS_VPCMPUD, "vpcmpud" },
	{ X86_INS_VPCMPUQ, "vpcmpuq" },
	{ X86_INS_VPCOMB, "vpcomb" },
	{ X86_INS_VPCOMD, "vpcomd" },
	{ X86_INS_VPCOMQ, "vpcomq" },
	{ X86_INS_VPCOMUB, "vpcomub" },
	{ X86_INS_VPCOMUD, "vpcomud" },
	{ X86_INS_VPCOMUQ, "vpcomuq" },
	{ X86_INS_VPCOMUW, "vpcomuw" },
	{ X86_INS_VPCOMW, "vpcomw" },
	{ X86_INS_VPCONFLICTD, "vpconflictd" },
	{ X86_INS_VPCONFLICTQ, "vpconflictq" },
	{ X86_INS_VPERM2F128, "vperm2f128" },
	{ X86_INS_VPERM2I128, "vperm2i128" },
	{ X86_INS_VPERMD, "vpermd" },
	{ X86_INS_VPERMI2D, "vpermi2d" },
	{ X86_INS_VPERMI2PD, "vpermi2pd" },
	{ X86_INS_VPERMI2PS, "vpermi2ps" },
	{ X86_INS_VPERMI2Q, "vpermi2q" },
	{ X86_INS_VPERMIL2PD, "vpermil2pd" },
	{ X86_INS_VPERMIL2PS, "vpermil2ps" },
	{ X86_INS_VPERMILPD, "vpermilpd" },
	{ X86_INS_VPERMILPS, "vpermilps" },
	{ X86_INS_VPERMPD, "vpermpd" },
	{ X86_INS_VPERMPS, "vpermps" },
	{ X86_INS_VPERMQ, "vpermq" },
	{ X86_INS_VPERMT2D, "vpermt2d" },
	{ X86_INS_VPERMT2PD, "vpermt2pd" },
	{ X86_INS_VPERMT2PS, "vpermt2ps" },
	{ X86_INS_VPERMT2Q, "vpermt2q" },
	{ X86_INS_VPEXTRB, "vpextrb" },
	{ X86_INS_VPEXTRD, "vpextrd" },
	{ X86_INS_VPEXTRQ, "vpextrq" },
	{ X86_INS_VPEXTRW, "vpextrw" },
	{ X86_INS_VPGATHERDD, "vpgatherdd" },
	{ X86_INS_VPGATHERDQ, "vpgatherdq" },
	{ X86_INS_VPGATHERQD, "vpgatherqd" },
	{ X86_INS_VPGATHERQQ, "vpgatherqq" },
	{ X86_INS_VPHADDBD, "vphaddbd" },
	{ X86_INS_VPHADDBQ, "vphaddbq" },
	{ X86_INS_VPHADDBW, "vphaddbw" },
	{ X86_INS_VPHADDDQ, "vphadddq" },
	{ X86_INS_VPHADDD, "vphaddd" },
	{ X86_INS_VPHADDSW, "vphaddsw" },
	{ X86_INS_VPHADDUBD, "vphaddubd" },
	{ X86_INS_VPHADDUBQ, "vphaddubq" },
	{ X86_INS_VPHADDUBW, "vphaddubw" },
	{ X86_INS_VPHADDUDQ, "vphaddudq" },
	{ X86_INS_VPHADDUWD, "vphadduwd" },
	{ X86_INS_VPHADDUWQ, "vphadduwq" },
	{ X86_INS_VPHADDWD, "vphaddwd" },
	{ X86_INS_VPHADDWQ, "vphaddwq" },
	{ X86_INS_VPHADDW, "vphaddw" },
	{ X86_INS_VPHMINPOSUW, "vphminposuw" },
	{ X86_INS_VPHSUBBW, "vphsubbw" },
	{ X86_INS_VPHSUBDQ, "vphsubdq" },
	{ X86_INS_VPHSUBD, "vphsubd" },
	{ X86_INS_VPHSUBSW, "vphsubsw" },
	{ X86_INS_VPHSUBWD, "vphsubwd" },
	{ X86_INS_VPHSUBW, "vphsubw" },
	{ X86_INS_VPINSRB, "vpinsrb" },
	{ X86_INS_VPINSRD, "vpinsrd" },
	{ X86_INS_VPINSRQ, "vpinsrq" },
	{ X86_INS_VPINSRW, "vpinsrw" },
	{ X86_INS_VPLZCNTD, "vplzcntd" },
	{ X86_INS_VPLZCNTQ, "vplzcntq" },
	{ X86_INS_VPMACSDD, "vpmacsdd" },
	{ X86_INS_VPMACSDQH, "vpmacsdqh" },
	{ X86_INS_VPMACSDQL, "vpmacsdql" },
	{ X86_INS_VPMACSSDD, "vpmacssdd" },
	{ X86_INS_VPMACSSDQH, "vpmacssdqh" },
	{ X86_INS_VPMACSSDQL, "vpmacssdql" },
	{ X86_INS_VPMACSSWD, "vpmacsswd" },
	{ X86_INS_VPMACSSWW, "vpmacssww" },
	{ X86_INS_VPMACSWD, "vpmacswd" },
	{ X86_INS_VPMACSWW, "vpmacsww" },
	{ X86_INS_VPMADCSSWD, "vpmadcsswd" },
	{ X86_INS_VPMADCSWD, "vpmadcswd" },
	{ X86_INS_VPMADDUBSW, "vpmaddubsw" },
	{ X86_INS_VPMADDWD, "vpmaddwd" },
	{ X86_INS_VPMASKMOVD, "vpmaskmovd" },
	{ X86_INS_VPMASKMOVQ, "vpmaskmovq" },
	{ X86_INS_VPMAXSB, "vpmaxsb" },
	{ X86_INS_VPMAXSD, "vpmaxsd" },
	{ X86_INS_VPMAXSQ, "vpmaxsq" },
	{ X86_INS_VPMAXSW, "vpmaxsw" },
	{ X86_INS_VPMAXUB, "vpmaxub" },
	{ X86_INS_VPMAXUD, "vpmaxud" },
	{ X86_INS_VPMAXUQ, "vpmaxuq" },
	{ X86_INS_VPMAXUW, "vpmaxuw" },
	{ X86_INS_VPMINSB, "vpminsb" },
	{ X86_INS_VPMINSD, "vpminsd" },
	{ X86_INS_VPMINSQ, "vpminsq" },
	{ X86_INS_VPMINSW, "vpminsw" },
	{ X86_INS_VPMINUB, "vpminub" },
	{ X86_INS_VPMINUD, "vpminud" },
	{ X86_INS_VPMINUQ, "vpminuq" },
	{ X86_INS_VPMINUW, "vpminuw" },
	{ X86_INS_VPMOVDB, "vpmovdb" },
	{ X86_INS_VPMOVDW, "vpmovdw" },
	{ X86_INS_VPMOVMSKB, "vpmovmskb" },
	{ X86_INS_VPMOVQB, "vpmovqb" },
	{ X86_INS_VPMOVQD, "vpmovqd" },
	{ X86_INS_VPMOVQW, "vpmovqw" },
	{ X86_INS_VPMOVSDB, "vpmovsdb" },
	{ X86_INS_VPMOVSDW, "vpmovsdw" },
	{ X86_INS_VPMOVSQB, "vpmovsqb" },
	{ X86_INS_VPMOVSQD, "vpmovsqd" },
	{ X86_INS_VPMOVSQW, "vpmovsqw" },
	{ X86_INS_VPMOVSXBD, "vpmovsxbd" },
	{ X86_INS_VPMOVSXBQ, "vpmovsxbq" },
	{ X86_INS_VPMOVSXBW, "vpmovsxbw" },
	{ X86_INS_VPMOVSXDQ, "vpmovsxdq" },
	{ X86_INS_VPMOVSXWD, "vpmovsxwd" },
	{ X86_INS_VPMOVSXWQ, "vpmovsxwq" },
	{ X86_INS_VPMOVUSDB, "vpmovusdb" },
	{ X86_INS_VPMOVUSDW, "vpmovusdw" },
	{ X86_INS_VPMOVUSQB, "vpmovusqb" },
	{ X86_INS_VPMOVUSQD, "vpmovusqd" },
	{ X86_INS_VPMOVUSQW, "vpmovusqw" },
	{ X86_INS_VPMOVZXBD, "vpmovzxbd" },
	{ X86_INS_VPMOVZXBQ, "vpmovzxbq" },
	{ X86_INS_VPMOVZXBW, "vpmovzxbw" },
	{ X86_INS_VPMOVZXDQ, "vpmovzxdq" },
	{ X86_INS_VPMOVZXWD, "vpmovzxwd" },
	{ X86_INS_VPMOVZXWQ, "vpmovzxwq" },
	{ X86_INS_VPMULDQ, "vpmuldq" },
	{ X86_INS_VPMULHRSW, "vpmulhrsw" },
	{ X86_INS_VPMULHUW, "vpmulhuw" },
	{ X86_INS_VPMULHW, "vpmulhw" },
	{ X86_INS_VPMULLD, "vpmulld" },
	{ X86_INS_VPMULLW, "vpmullw" },
	{ X86_INS_VPMULUDQ, "vpmuludq" },
	{ X86_INS_VPORD, "vpord" },
	{ X86_INS_VPORQ, "vporq" },
	{ X86_INS_VPOR, "vpor" },
	{ X86_INS_VPPERM, "vpperm" },
	{ X86_INS_VPROTB, "vprotb" },
	{ X86_INS_VPROTD, "vprotd" },
	{ X86_INS_VPROTQ, "vprotq" },
	{ X86_INS_VPROTW, "vprotw" },
	{ X86_INS_VPSADBW, "vpsadbw" },
	{ X86_INS_VPSCATTERDD, "vpscatterdd" },
	{ X86_INS_VPSCATTERDQ, "vpscatterdq" },
	{ X86_INS_VPSCATTERQD, "vpscatterqd" },
	{ X86_INS_VPSCATTERQQ, "vpscatterqq" },
	{ X86_INS_VPSHAB, "vpshab" },
	{ X86_INS_VPSHAD, "vpshad" },
	{ X86_INS_VPSHAQ, "vpshaq" },
	{ X86_INS_VPSHAW, "vpshaw" },
	{ X86_INS_VPSHLB, "vpshlb" },
	{ X86_INS_VPSHLD, "vpshld" },
	{ X86_INS_VPSHLQ, "vpshlq" },
	{ X86_INS_VPSHLW, "vpshlw" },
	{ X86_INS_VPSHUFB, "vpshufb" },
	{ X86_INS_VPSHUFD, "vpshufd" },
	{ X86_INS_VPSHUFHW, "vpshufhw" },
	{ X86_INS_VPSHUFLW, "vpshuflw" },
	{ X86_INS_VPSIGNB, "vpsignb" },
	{ X86_INS_VPSIGND, "vpsignd" },
	{ X86_INS_VPSIGNW, "vpsignw" },
	{ X86_INS_VPSLLDQ, "vpslldq" },
	{ X86_INS_VPSLLD, "vpslld" },
	{ X86_INS_VPSLLQ, "vpsllq" },
	{ X86_INS_VPSLLVD, "vpsllvd" },
	{ X86_INS_VPSLLVQ, "vpsllvq" },
	{ X86_INS_VPSLLW, "vpsllw" },
	{ X86_INS_VPSRAD, "vpsrad" },
	{ X86_INS_VPSRAQ, "vpsraq" },
	{ X86_INS_VPSRAVD, "vpsravd" },
	{ X86_INS_VPSRAVQ, "vpsravq" },
	{ X86_INS_VPSRAW, "vpsraw" },
	{ X86_INS_VPSRLDQ, "vpsrldq" },
	{ X86_INS_VPSRLD, "vpsrld" },
	{ X86_INS_VPSRLQ, "vpsrlq" },
	{ X86_INS_VPSRLVD, "vpsrlvd" },
	{ X86_INS_VPSRLVQ, "vpsrlvq" },
	{ X86_INS_VPSRLW, "vpsrlw" },
	{ X86_INS_VPSUBB, "vpsubb" },
	{ X86_INS_VPSUBD, "vpsubd" },
	{ X86_INS_VPSUBQ, "vpsubq" },
	{ X86_INS_VPSUBSB, "vpsubsb" },
	{ X86_INS_VPSUBSW, "vpsubsw" },
	{ X86_INS_VPSUBUSB, "vpsubusb" },
	{ X86_INS_VPSUBUSW, "vpsubusw" },
	{ X86_INS_VPSUBW, "vpsubw" },
	{ X86_INS_VPTESTMD, "vptestmd" },
	{ X86_INS_VPTESTMQ, "vptestmq" },
	{ X86_INS_VPTESTNMD, "vptestnmd" },
	{ X86_INS_VPTESTNMQ, "vptestnmq" },
	{ X86_INS_VPTEST, "vptest" },
	{ X86_INS_VPUNPCKHBW, "vpunpckhbw" },
	{ X86_INS_VPUNPCKHDQ, "vpunpckhdq" },
	{ X86_INS_VPUNPCKHQDQ, "vpunpckhqdq" },
	{ X86_INS_VPUNPCKHWD, "vpunpckhwd" },
	{ X86_INS_VPUNPCKLBW, "vpunpcklbw" },
	{ X86_INS_VPUNPCKLDQ, "vpunpckldq" },
	{ X86_INS_VPUNPCKLQDQ, "vpunpcklqdq" },
	{ X86_INS_VPUNPCKLWD, "vpunpcklwd" },
	{ X86_INS_VPXORD, "vpxord" },
	{ X86_INS_VPXORQ, "vpxorq" },
	{ X86_INS_VPXOR, "vpxor" },
	{ X86_INS_VRCP14PD, "vrcp14pd" },
	{ X86_INS_VRCP14PS, "vrcp14ps" },
	{ X86_INS_VRCP14SD, "vrcp14sd" },
	{ X86_INS_VRCP14SS, "vrcp14ss" },
	{ X86_INS_VRCP28PD, "vrcp28pd" },
	{ X86_INS_VRCP28PS, "vrcp28ps" },
	{ X86_INS_VRCP28SD, "vrcp28sd" },
	{ X86_INS_VRCP28SS, "vrcp28ss" },
	{ X86_INS_VRCPPS, "vrcpps" },
	{ X86_INS_VRCPSS, "vrcpss" },
	{ X86_INS_VRNDSCALEPD, "vrndscalepd" },
	{ X86_INS_VRNDSCALEPS, "vrndscaleps" },
	{ X86_INS_VRNDSCALESD, "vrndscalesd" },
	{ X86_INS_VRNDSCALESS, "vrndscaless" },
	{ X86_INS_VROUNDPD, "vroundpd" },
	{ X86_INS_VROUNDPS, "vroundps" },
	{ X86_INS_VROUNDSD, "vroundsd" },
	{ X86_INS_VROUNDSS, "vroundss" },
	{ X86_INS_VRSQRT14PD, "vrsqrt14pd" },
	{ X86_INS_VRSQRT14PS, "vrsqrt14ps" },
	{ X86_INS_VRSQRT14SD, "vrsqrt14sd" },
	{ X86_INS_VRSQRT14SS, "vrsqrt14ss" },
	{ X86_INS_VRSQRT28PD, "vrsqrt28pd" },
	{ X86_INS_VRSQRT28PS, "vrsqrt28ps" },
	{ X86_INS_VRSQRT28SD, "vrsqrt28sd" },
	{ X86_INS_VRSQRT28SS, "vrsqrt28ss" },
	{ X86_INS_VRSQRTPS, "vrsqrtps" },
	{ X86_INS_VRSQRTSS, "vrsqrtss" },
	{ X86_INS_VSCATTERDPD, "vscatterdpd" },
	{ X86_INS_VSCATTERDPS, "vscatterdps" },
	{ X86_INS_VSCATTERPF0DPD, "vscatterpf0dpd" },
	{ X86_INS_VSCATTERPF0DPS, "vscatterpf0dps" },
	{ X86_INS_VSCATTERPF0QPD, "vscatterpf0qpd" },
	{ X86_INS_VSCATTERPF0QPS, "vscatterpf0qps" },
	{ X86_INS_VSCATTERPF1DPD, "vscatterpf1dpd" },
	{ X86_INS_VSCATTERPF1DPS, "vscatterpf1dps" },
	{ X86_INS_VSCATTERPF1QPD, "vscatterpf1qpd" },
	{ X86_INS_VSCATTERPF1QPS, "vscatterpf1qps" },
	{ X86_INS_VSCATTERQPD, "vscatterqpd" },
	{ X86_INS_VSCATTERQPS, "vscatterqps" },
	{ X86_INS_VSHUFPD, "vshufpd" },
	{ X86_INS_VSHUFPS, "vshufps" },
	{ X86_INS_VSQRTPD, "vsqrtpd" },
	{ X86_INS_VSQRTPS, "vsqrtps" },
	{ X86_INS_VSQRTSD, "vsqrtsd" },
	{ X86_INS_VSQRTSS, "vsqrtss" },
	{ X86_INS_VSTMXCSR, "vstmxcsr" },
	{ X86_INS_VSUBPD, "vsubpd" },
	{ X86_INS_VSUBPS, "vsubps" },
	{ X86_INS_VSUBSD, "vsubsd" },
	{ X86_INS_VSUBSS, "vsubss" },
	{ X86_INS_VTESTPD, "vtestpd" },
	{ X86_INS_VTESTPS, "vtestps" },
	{ X86_INS_VUNPCKHPD, "vunpckhpd" },
	{ X86_INS_VUNPCKHPS, "vunpckhps" },
	{ X86_INS_VUNPCKLPD, "vunpcklpd" },
	{ X86_INS_VUNPCKLPS, "vunpcklps" },
	{ X86_INS_VZEROALL, "vzeroall" },
	{ X86_INS_VZEROUPPER, "vzeroupper" },
	{ X86_INS_WAIT, "wait" },
	{ X86_INS_WBINVD, "wbinvd" },
	{ X86_INS_WRFSBASE, "wrfsbase" },
	{ X86_INS_WRGSBASE, "wrgsbase" },
	{ X86_INS_WRMSR, "wrmsr" },
	{ X86_INS_XABORT, "xabort" },
	{ X86_INS_XACQUIRE, "xacquire" },
	{ X86_INS_XBEGIN, "xbegin" },
	{ X86_INS_XCHG, "xchg" },
	{ X86_INS_FXCH, "fxch" },
	{ X86_INS_XCRYPTCBC, "xcryptcbc" },
	{ X86_INS_XCRYPTCFB, "xcryptcfb" },
	{ X86_INS_XCRYPTCTR, "xcryptctr" },
	{ X86_INS_XCRYPTECB, "xcryptecb" },
	{ X86_INS_XCRYPTOFB, "xcryptofb" },
	{ X86_INS_XEND, "xend" },
	{ X86_INS_XGETBV, "xgetbv" },
	{ X86_INS_XLATB, "xlatb" },
	{ X86_INS_XRELEASE, "xrelease" },
	{ X86_INS_XRSTOR, "xrstor" },
	{ X86_INS_XRSTOR64, "xrstor64" },
	{ X86_INS_XSAVE, "xsave" },
	{ X86_INS_XSAVE64, "xsave64" },
	{ X86_INS_XSAVEOPT, "xsaveopt" },
	{ X86_INS_XSAVEOPT64, "xsaveopt64" },
	{ X86_INS_XSETBV, "xsetbv" },
	{ X86_INS_XSHA1, "xsha1" },
	{ X86_INS_XSHA256, "xsha256" },
	{ X86_INS_XSTORE, "xstore" },
	{ X86_INS_XTEST, "xtest" },
};
#endif

const char *X86_insn_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	if (id >= X86_INS_ENDING)
		return NULL;

	return insn_name_maps[id].name;
#else
	return NULL;
#endif
}

#ifndef CAPSTONE_DIET
static const name_map group_name_maps[] = {
	// generic groups
	{ X86_GRP_INVALID, NULL },
	{ X86_GRP_JUMP,	"jump" },
	{ X86_GRP_CALL,	"call" },
	{ X86_GRP_RET, "ret" },
	{ X86_GRP_INT, "int" },
	{ X86_GRP_IRET,	"iret" },

	// architecture-specific groups
	{ X86_GRP_VM, "vm" },
	{ X86_GRP_3DNOW, "3dnow" },
	{ X86_GRP_AES, "aes" },
	{ X86_GRP_ADX, "adx" },
	{ X86_GRP_AVX, "avx" },
	{ X86_GRP_AVX2, "avx2" },
	{ X86_GRP_AVX512, "avx512" },
	{ X86_GRP_BMI, "bmi" },
	{ X86_GRP_BMI2, "bmi2" },
	{ X86_GRP_CMOV, "cmov" },
	{ X86_GRP_F16C, "fc16" },
	{ X86_GRP_FMA, "fma" },
	{ X86_GRP_FMA4, "fma4" },
	{ X86_GRP_FSGSBASE, "fsgsbase" },
	{ X86_GRP_HLE, "hle" },
	{ X86_GRP_MMX, "mmx" },
	{ X86_GRP_MODE32, "mode32" },
	{ X86_GRP_MODE64, "mode64" },
	{ X86_GRP_RTM, "rtm" },
	{ X86_GRP_SHA, "sha" },
	{ X86_GRP_SSE1, "sse1" },
	{ X86_GRP_SSE2, "sse2" },
	{ X86_GRP_SSE3, "sse3" },
	{ X86_GRP_SSE41, "sse41" },
	{ X86_GRP_SSE42, "sse42" },
	{ X86_GRP_SSE4A, "sse4a" },
	{ X86_GRP_SSSE3, "ssse3" },
	{ X86_GRP_PCLMUL, "pclmul" },
	{ X86_GRP_XOP, "xop" },
	{ X86_GRP_CDI, "cdi" },
	{ X86_GRP_ERI, "eri" },
	{ X86_GRP_TBM, "tbm" },
	{ X86_GRP_16BITMODE, "16bitmode" },
	{ X86_GRP_NOT64BITMODE, "not64bitmode" },
	{ X86_GRP_SGX,	"sgx" },
	{ X86_GRP_DQI,	"dqi" },
	{ X86_GRP_BWI,	"bwi" },
	{ X86_GRP_PFI,	"pfi" },
	{ X86_GRP_VLX,	"vlx" },
	{ X86_GRP_SMAP,	"smap" },
	{ X86_GRP_NOVLX, "novlx" },
};
#endif

const char *X86_group_name(csh handle, unsigned int id)
{
#ifndef CAPSTONE_DIET
	// verify group id
	if (id >= X86_GRP_ENDING || (id > X86_GRP_IRET && id < X86_GRP_VM))
		return NULL;

	// NOTE: when new generic groups are added, 6 must be changed accordingly
	if (id >= 128)
		return group_name_maps[id - 128 + 6].name;
	else
		return group_name_maps[id].name;
#else
	return NULL;
#endif
}

#define GET_INSTRINFO_ENUM
#ifdef CAPSTONE_X86_REDUCE
#include "X86GenInstrInfo_reduce.inc"
#else
#include "X86GenInstrInfo.inc"
#endif

#ifndef CAPSTONE_X86_REDUCE
static const insn_map insns[] = {	// full x86 instructions
	// dummy item
	{
		0, 0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},

	{
		X86_AAA, X86_INS_AAA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_AAD8i8, X86_INS_AAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_AAM8i8, X86_INS_AAM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_AAS, X86_INS_AAS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_ABS_F, X86_INS_FABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC16i16, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC16mi, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC16mi8, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC16mr, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC16ri, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC16ri8, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC16rm, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC16rr, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC16rr_REV, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC32i32, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC32mi, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC32mi8, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC32mr, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC32ri, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC32ri8, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC32rm, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC32rr, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC32rr_REV, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC64i32, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC64mi32, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC64mi8, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC64mr, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC64ri32, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC64ri8, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC64rm, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC64rr, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC64rr_REV, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC8i8, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC8mi, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC8mr, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC8ri, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC8rm, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC8rr, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC8rr_REV, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADCX32rm, X86_INS_ADCX,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_ADX, 0 }, 0, 0
#endif
	},
	{
		X86_ADCX32rr, X86_INS_ADCX,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_ADX, 0 }, 0, 0
#endif
	},
	{
		X86_ADCX64rm, X86_INS_ADCX,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_ADX, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_ADCX64rr, X86_INS_ADCX,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_ADX, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_ADD16i16, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD16mi, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD16mi8, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD16mr, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD16ri, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD16ri8, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD16rm, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD16rr, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD16rr_REV, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD32i32, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD32mi, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD32mi8, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD32mr, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD32ri, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD32ri8, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD32rm, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD32rr, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD32rr_REV, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD64i32, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD64mi32, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD64mi8, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD64mr, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD64ri32, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD64ri8, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD64rm, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD64rr, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD64rr_REV, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD8i8, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD8mi, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD8mr, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD8ri, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD8ri8, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_ADD8rm, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD8rr, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD8rr_REV, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADDPDrm, X86_INS_ADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_ADDPDrr, X86_INS_ADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_ADDPSrm, X86_INS_ADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_ADDPSrr, X86_INS_ADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_ADDSDrm, X86_INS_ADDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_ADDSDrm_Int, X86_INS_ADDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_ADDSDrr, X86_INS_ADDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_ADDSDrr_Int, X86_INS_ADDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_ADDSSrm, X86_INS_ADDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_ADDSSrm_Int, X86_INS_ADDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_ADDSSrr, X86_INS_ADDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_ADDSSrr_Int, X86_INS_ADDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_ADDSUBPDrm, X86_INS_ADDSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE3, 0 }, 0, 0
#endif
	},
	{
		X86_ADDSUBPDrr, X86_INS_ADDSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE3, 0 }, 0, 0
#endif
	},
	{
		X86_ADDSUBPSrm, X86_INS_ADDSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE3, 0 }, 0, 0
#endif
	},
	{
		X86_ADDSUBPSrr, X86_INS_ADDSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE3, 0 }, 0, 0
#endif
	},
	{
		X86_ADD_F32m, X86_INS_FADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD_F64m, X86_INS_FADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD_FI16m, X86_INS_FIADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD_FI32m, X86_INS_FIADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD_FPrST0, X86_INS_FADDP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD_FST0r, X86_INS_FADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD_FrST0, X86_INS_FADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADOX32rm, X86_INS_ADOX,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_ADX, 0 }, 0, 0
#endif
	},
	{
		X86_ADOX32rr, X86_INS_ADOX,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_ADX, 0 }, 0, 0
#endif
	},
	{
		X86_ADOX64rm, X86_INS_ADOX,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_ADX, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_ADOX64rr, X86_INS_ADOX,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_ADX, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_AESDECLASTrm, X86_INS_AESDECLAST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AES, 0 }, 0, 0
#endif
	},
	{
		X86_AESDECLASTrr, X86_INS_AESDECLAST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AES, 0 }, 0, 0
#endif
	},
	{
		X86_AESDECrm, X86_INS_AESDEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AES, 0 }, 0, 0
#endif
	},
	{
		X86_AESDECrr, X86_INS_AESDEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AES, 0 }, 0, 0
#endif
	},
	{
		X86_AESENCLASTrm, X86_INS_AESENCLAST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AES, 0 }, 0, 0
#endif
	},
	{
		X86_AESENCLASTrr, X86_INS_AESENCLAST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AES, 0 }, 0, 0
#endif
	},
	{
		X86_AESENCrm, X86_INS_AESENC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AES, 0 }, 0, 0
#endif
	},
	{
		X86_AESENCrr, X86_INS_AESENC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AES, 0 }, 0, 0
#endif
	},
	{
		X86_AESIMCrm, X86_INS_AESIMC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AES, 0 }, 0, 0
#endif
	},
	{
		X86_AESIMCrr, X86_INS_AESIMC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AES, 0 }, 0, 0
#endif
	},
	{
		X86_AESKEYGENASSIST128rm, X86_INS_AESKEYGENASSIST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AES, 0 }, 0, 0
#endif
	},
	{
		X86_AESKEYGENASSIST128rr, X86_INS_AESKEYGENASSIST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AES, 0 }, 0, 0
#endif
	},
	{
		X86_AND16i16, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND16mi, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND16mi8, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND16mr, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND16ri, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND16ri8, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND16rm, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND16rr, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND16rr_REV, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND32i32, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND32mi, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND32mi8, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND32mr, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND32ri, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND32ri8, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND32rm, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND32rr, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND32rr_REV, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND64i32, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND64mi32, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND64mi8, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND64mr, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND64ri32, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND64ri8, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND64rm, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND64rr, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND64rr_REV, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND8i8, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND8mi, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND8mr, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND8ri, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND8ri8, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_AND8rm, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND8rr, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND8rr_REV, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ANDN32rm, X86_INS_ANDN,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_ANDN32rr, X86_INS_ANDN,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_ANDN64rm, X86_INS_ANDN,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_ANDN64rr, X86_INS_ANDN,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_ANDNPDrm, X86_INS_ANDNPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_ANDNPDrr, X86_INS_ANDNPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_ANDNPSrm, X86_INS_ANDNPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_ANDNPSrr, X86_INS_ANDNPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_ANDPDrm, X86_INS_ANDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_ANDPDrr, X86_INS_ANDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_ANDPSrm, X86_INS_ANDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_ANDPSrr, X86_INS_ANDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_ARPL16mr, X86_INS_ARPL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_ARPL16rr, X86_INS_ARPL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_BEXTR32rm, X86_INS_BEXTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BEXTR32rr, X86_INS_BEXTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BEXTR64rm, X86_INS_BEXTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BEXTR64rr, X86_INS_BEXTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BEXTRI32mi, X86_INS_BEXTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BEXTRI32ri, X86_INS_BEXTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BEXTRI64mi, X86_INS_BEXTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BEXTRI64ri, X86_INS_BEXTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCFILL32rm, X86_INS_BLCFILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCFILL32rr, X86_INS_BLCFILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCFILL64rm, X86_INS_BLCFILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCFILL64rr, X86_INS_BLCFILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCI32rm, X86_INS_BLCI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCI32rr, X86_INS_BLCI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCI64rm, X86_INS_BLCI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCI64rr, X86_INS_BLCI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCIC32rm, X86_INS_BLCIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCIC32rr, X86_INS_BLCIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCIC64rm, X86_INS_BLCIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCIC64rr, X86_INS_BLCIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCMSK32rm, X86_INS_BLCMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCMSK32rr, X86_INS_BLCMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCMSK64rm, X86_INS_BLCMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCMSK64rr, X86_INS_BLCMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCS32rm, X86_INS_BLCS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCS32rr, X86_INS_BLCS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCS64rm, X86_INS_BLCS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCS64rr, X86_INS_BLCS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLENDPDrmi, X86_INS_BLENDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_BLENDPDrri, X86_INS_BLENDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_BLENDPSrmi, X86_INS_BLENDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_BLENDPSrri, X86_INS_BLENDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_BLENDVPDrm0, X86_INS_BLENDVPD,
#ifndef CAPSTONE_DIET
		{ X86_REG_XMM0, 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_BLENDVPDrr0, X86_INS_BLENDVPD,
#ifndef CAPSTONE_DIET
		{ X86_REG_XMM0, 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_BLENDVPSrm0, X86_INS_BLENDVPS,
#ifndef CAPSTONE_DIET
		{ X86_REG_XMM0, 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_BLENDVPSrr0, X86_INS_BLENDVPS,
#ifndef CAPSTONE_DIET
		{ X86_REG_XMM0, 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_BLSFILL32rm, X86_INS_BLSFILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLSFILL32rr, X86_INS_BLSFILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLSFILL64rm, X86_INS_BLSFILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLSFILL64rr, X86_INS_BLSFILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLSI32rm, X86_INS_BLSI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BLSI32rr, X86_INS_BLSI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BLSI64rm, X86_INS_BLSI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BLSI64rr, X86_INS_BLSI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BLSIC32rm, X86_INS_BLSIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLSIC32rr, X86_INS_BLSIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLSIC64rm, X86_INS_BLSIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLSIC64rr, X86_INS_BLSIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLSMSK32rm, X86_INS_BLSMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BLSMSK32rr, X86_INS_BLSMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BLSMSK64rm, X86_INS_BLSMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BLSMSK64rr, X86_INS_BLSMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BLSR32rm, X86_INS_BLSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BLSR32rr, X86_INS_BLSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BLSR64rm, X86_INS_BLSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BLSR64rr, X86_INS_BLSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BOUNDS16rm, X86_INS_BOUND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_BOUNDS32rm, X86_INS_BOUND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_BSF16rm, X86_INS_BSF,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSF16rr, X86_INS_BSF,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSF32rm, X86_INS_BSF,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSF32rr, X86_INS_BSF,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSF64rm, X86_INS_BSF,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSF64rr, X86_INS_BSF,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSR16rm, X86_INS_BSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSR16rr, X86_INS_BSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSR32rm, X86_INS_BSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSR32rr, X86_INS_BSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSR64rm, X86_INS_BSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSR64rr, X86_INS_BSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSWAP32r, X86_INS_BSWAP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSWAP64r, X86_INS_BSWAP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BT16mi8, X86_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BT16mr, X86_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BT16ri8, X86_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BT16rr, X86_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BT32mi8, X86_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BT32mr, X86_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BT32ri8, X86_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BT32rr, X86_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BT64mi8, X86_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BT64mr, X86_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BT64ri8, X86_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BT64rr, X86_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTC16mi8, X86_INS_BTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTC16mr, X86_INS_BTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTC16ri8, X86_INS_BTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTC16rr, X86_INS_BTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTC32mi8, X86_INS_BTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTC32mr, X86_INS_BTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTC32ri8, X86_INS_BTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTC32rr, X86_INS_BTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTC64mi8, X86_INS_BTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTC64mr, X86_INS_BTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTC64ri8, X86_INS_BTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTC64rr, X86_INS_BTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTR16mi8, X86_INS_BTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTR16mr, X86_INS_BTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTR16ri8, X86_INS_BTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTR16rr, X86_INS_BTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTR32mi8, X86_INS_BTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTR32mr, X86_INS_BTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTR32ri8, X86_INS_BTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTR32rr, X86_INS_BTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTR64mi8, X86_INS_BTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTR64mr, X86_INS_BTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTR64ri8, X86_INS_BTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTR64rr, X86_INS_BTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTS16mi8, X86_INS_BTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTS16mr, X86_INS_BTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTS16ri8, X86_INS_BTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTS16rr, X86_INS_BTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTS32mi8, X86_INS_BTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTS32mr, X86_INS_BTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTS32ri8, X86_INS_BTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTS32rr, X86_INS_BTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTS64mi8, X86_INS_BTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTS64mr, X86_INS_BTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTS64ri8, X86_INS_BTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTS64rr, X86_INS_BTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BZHI32rm, X86_INS_BZHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_BZHI32rr, X86_INS_BZHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_BZHI64rm, X86_INS_BZHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_BZHI64rr, X86_INS_BZHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_CALL16m, X86_INS_CALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { 0 }, { X86_GRP_CALL, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_CALL16r, X86_INS_CALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { 0 }, { X86_GRP_CALL, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_CALL32m, X86_INS_CALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { 0 }, { X86_GRP_CALL, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_CALL32r, X86_INS_CALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { 0 }, { X86_GRP_CALL, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_CALL64m, X86_INS_CALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { 0 }, { X86_GRP_CALL, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_CALL64pcrel32, X86_INS_CALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { 0 }, { X86_GRP_CALL, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_CALL64r, X86_INS_CALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { 0 }, { X86_GRP_CALL, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_CALLpcrel16, X86_INS_CALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { 0 }, { X86_GRP_CALL, 0 }, 0, 0
#endif
	},
	{
		X86_CALLpcrel32, X86_INS_CALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { 0 }, { X86_GRP_CALL, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_CBW, X86_INS_CBW,
#ifndef CAPSTONE_DIET
		{ X86_REG_AL, 0 }, { X86_REG_AX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CDQ, X86_INS_CDQ,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { X86_REG_EAX, X86_REG_EDX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CDQE, X86_INS_CDQE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { X86_REG_RAX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CHS_F, X86_INS_FCHS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CLAC, X86_INS_CLAC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_SMAP, 0 }, 0, 0
#endif
	},
	{
		X86_CLC, X86_INS_CLC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CLD, X86_INS_CLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CLFLUSH, X86_INS_CLFLUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CLGI, X86_INS_CLGI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_CLI, X86_INS_CLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CLTS, X86_INS_CLTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMC, X86_INS_CMC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMOVA16rm, X86_INS_CMOVA,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVA16rr, X86_INS_CMOVA,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVA32rm, X86_INS_CMOVA,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVA32rr, X86_INS_CMOVA,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVA64rm, X86_INS_CMOVA,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVA64rr, X86_INS_CMOVA,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVAE16rm, X86_INS_CMOVAE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVAE16rr, X86_INS_CMOVAE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVAE32rm, X86_INS_CMOVAE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVAE32rr, X86_INS_CMOVAE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVAE64rm, X86_INS_CMOVAE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVAE64rr, X86_INS_CMOVAE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVB16rm, X86_INS_CMOVB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVB16rr, X86_INS_CMOVB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVB32rm, X86_INS_CMOVB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVB32rr, X86_INS_CMOVB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVB64rm, X86_INS_CMOVB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVB64rr, X86_INS_CMOVB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVBE16rm, X86_INS_CMOVBE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVBE16rr, X86_INS_CMOVBE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVBE32rm, X86_INS_CMOVBE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVBE32rr, X86_INS_CMOVBE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVBE64rm, X86_INS_CMOVBE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVBE64rr, X86_INS_CMOVBE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVBE_F, X86_INS_FCMOVBE,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVB_F, X86_INS_FCMOVB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVE16rm, X86_INS_CMOVE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVE16rr, X86_INS_CMOVE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVE32rm, X86_INS_CMOVE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVE32rr, X86_INS_CMOVE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVE64rm, X86_INS_CMOVE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVE64rr, X86_INS_CMOVE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVE_F, X86_INS_FCMOVE,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVG16rm, X86_INS_CMOVG,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVG16rr, X86_INS_CMOVG,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVG32rm, X86_INS_CMOVG,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVG32rr, X86_INS_CMOVG,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVG64rm, X86_INS_CMOVG,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVG64rr, X86_INS_CMOVG,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVGE16rm, X86_INS_CMOVGE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVGE16rr, X86_INS_CMOVGE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVGE32rm, X86_INS_CMOVGE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVGE32rr, X86_INS_CMOVGE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVGE64rm, X86_INS_CMOVGE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVGE64rr, X86_INS_CMOVGE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVL16rm, X86_INS_CMOVL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVL16rr, X86_INS_CMOVL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVL32rm, X86_INS_CMOVL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVL32rr, X86_INS_CMOVL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVL64rm, X86_INS_CMOVL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVL64rr, X86_INS_CMOVL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVLE16rm, X86_INS_CMOVLE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVLE16rr, X86_INS_CMOVLE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVLE32rm, X86_INS_CMOVLE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVLE32rr, X86_INS_CMOVLE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVLE64rm, X86_INS_CMOVLE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVLE64rr, X86_INS_CMOVLE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNBE_F, X86_INS_FCMOVNBE,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNB_F, X86_INS_FCMOVNB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNE16rm, X86_INS_CMOVNE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNE16rr, X86_INS_CMOVNE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNE32rm, X86_INS_CMOVNE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNE32rr, X86_INS_CMOVNE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNE64rm, X86_INS_CMOVNE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNE64rr, X86_INS_CMOVNE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNE_F, X86_INS_FCMOVNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNO16rm, X86_INS_CMOVNO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNO16rr, X86_INS_CMOVNO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNO32rm, X86_INS_CMOVNO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNO32rr, X86_INS_CMOVNO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNO64rm, X86_INS_CMOVNO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNO64rr, X86_INS_CMOVNO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNP16rm, X86_INS_CMOVNP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNP16rr, X86_INS_CMOVNP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNP32rm, X86_INS_CMOVNP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNP32rr, X86_INS_CMOVNP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNP64rm, X86_INS_CMOVNP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNP64rr, X86_INS_CMOVNP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNP_F, X86_INS_FCMOVNU,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNS16rm, X86_INS_CMOVNS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNS16rr, X86_INS_CMOVNS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNS32rm, X86_INS_CMOVNS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNS32rr, X86_INS_CMOVNS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNS64rm, X86_INS_CMOVNS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNS64rr, X86_INS_CMOVNS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVO16rm, X86_INS_CMOVO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVO16rr, X86_INS_CMOVO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVO32rm, X86_INS_CMOVO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVO32rr, X86_INS_CMOVO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVO64rm, X86_INS_CMOVO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVO64rr, X86_INS_CMOVO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVP16rm, X86_INS_CMOVP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVP16rr, X86_INS_CMOVP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVP32rm, X86_INS_CMOVP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVP32rr, X86_INS_CMOVP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVP64rm, X86_INS_CMOVP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVP64rr, X86_INS_CMOVP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVP_F, X86_INS_FCMOVU,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVS16rm, X86_INS_CMOVS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVS16rr, X86_INS_CMOVS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVS32rm, X86_INS_CMOVS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVS32rr, X86_INS_CMOVS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVS64rm, X86_INS_CMOVS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVS64rr, X86_INS_CMOVS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMP16i16, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP16mi, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP16mi8, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP16mr, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP16ri, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP16ri8, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP16rm, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP16rr, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP16rr_REV, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP32i32, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP32mi, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP32mi8, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP32mr, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP32ri, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP32ri8, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP32rm, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP32rr, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP32rr_REV, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP64i32, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP64mi32, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP64mi8, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP64mr, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP64ri32, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP64ri8, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP64rm, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP64rr, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP64rr_REV, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP8i8, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP8mi, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP8mr, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP8ri, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP8rm, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP8rr, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP8rr_REV, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPPDrmi, X86_INS_CMPPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CMPPDrmi_alt, X86_INS_CMPPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CMPPDrri, X86_INS_CMPPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CMPPDrri_alt, X86_INS_CMPPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CMPPSrmi, X86_INS_CMPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_CMPPSrmi_alt, X86_INS_CMPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_CMPPSrri, X86_INS_CMPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_CMPPSrri_alt, X86_INS_CMPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_CMPSB, X86_INS_CMPSB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDI, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPSDrm, X86_INS_CMPSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CMPSDrm_alt, X86_INS_CMPSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CMPSDrr, X86_INS_CMPSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CMPSDrr_alt, X86_INS_CMPSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CMPSL, X86_INS_CMPSD,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDI, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPSQ, X86_INS_CMPSQ,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDI, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPSSrm, X86_INS_CMPSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_CMPSSrm_alt, X86_INS_CMPSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_CMPSSrr, X86_INS_CMPSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_CMPSSrr_alt, X86_INS_CMPSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_CMPSW, X86_INS_CMPSW,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDI, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPXCHG16B, X86_INS_CMPXCHG16B,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_RBX, X86_REG_RCX, X86_REG_RDX, 0 }, { X86_REG_RAX, X86_REG_RDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPXCHG16rm, X86_INS_CMPXCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPXCHG16rr, X86_INS_CMPXCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPXCHG32rm, X86_INS_CMPXCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPXCHG32rr, X86_INS_CMPXCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPXCHG64rm, X86_INS_CMPXCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPXCHG64rr, X86_INS_CMPXCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPXCHG8B, X86_INS_CMPXCHG8B,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_EBX, X86_REG_ECX, X86_REG_EDX, 0 }, { X86_REG_EAX, X86_REG_EDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPXCHG8rm, X86_INS_CMPXCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPXCHG8rr, X86_INS_CMPXCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_COMISDrm, X86_INS_COMISD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_COMISDrr, X86_INS_COMISD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_COMISSrm, X86_INS_COMISS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_COMISSrr, X86_INS_COMISS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_COMP_FST0r, X86_INS_FCOMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_COM_FIPr, X86_INS_FCOMPI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_COM_FIr, X86_INS_FCOMI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_COM_FST0r, X86_INS_FCOM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_COS_F, X86_INS_FCOS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CPUID32, X86_INS_CPUID,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_ECX, 0 }, { X86_REG_EAX, X86_REG_EBX, X86_REG_ECX, X86_REG_EDX, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_CPUID64, X86_INS_CPUID,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_RCX, 0 }, { X86_REG_RAX, X86_REG_RBX, X86_REG_RCX, X86_REG_RDX, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_CQO, X86_INS_CQO,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, 0 }, { X86_REG_RAX, X86_REG_RDX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CRC32r32m16, X86_INS_CRC32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE42, 0 }, 0, 0
#endif
	},
	{
		X86_CRC32r32m32, X86_INS_CRC32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE42, 0 }, 0, 0
#endif
	},
	{
		X86_CRC32r32m8, X86_INS_CRC32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE42, 0 }, 0, 0
#endif
	},
	{
		X86_CRC32r32r16, X86_INS_CRC32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE42, 0 }, 0, 0
#endif
	},
	{
		X86_CRC32r32r32, X86_INS_CRC32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE42, 0 }, 0, 0
#endif
	},
	{
		X86_CRC32r32r8, X86_INS_CRC32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE42, 0 }, 0, 0
#endif
	},
	{
		X86_CRC32r64m64, X86_INS_CRC32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE42, 0 }, 0, 0
#endif
	},
	{
		X86_CRC32r64m8, X86_INS_CRC32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE42, 0 }, 0, 0
#endif
	},
	{
		X86_CRC32r64r64, X86_INS_CRC32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE42, 0 }, 0, 0
#endif
	},
	{
		X86_CRC32r64r8, X86_INS_CRC32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE42, 0 }, 0, 0
#endif
	},
	{
		X86_CVTDQ2PDrm, X86_INS_CVTDQ2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTDQ2PDrr, X86_INS_CVTDQ2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTDQ2PSrm, X86_INS_CVTDQ2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTDQ2PSrr, X86_INS_CVTDQ2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTPD2DQrm, X86_INS_CVTPD2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTPD2DQrr, X86_INS_CVTPD2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTPD2PSrm, X86_INS_CVTPD2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTPD2PSrr, X86_INS_CVTPD2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTPS2DQrm, X86_INS_CVTPS2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTPS2DQrr, X86_INS_CVTPS2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTPS2PDrm, X86_INS_CVTPS2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTPS2PDrr, X86_INS_CVTPS2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTSD2SI64rm, X86_INS_CVTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTSD2SI64rr, X86_INS_CVTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTSD2SIrm, X86_INS_CVTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTSD2SIrr, X86_INS_CVTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTSD2SSrm, X86_INS_CVTSD2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTSD2SSrr, X86_INS_CVTSD2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTSI2SD64rm, X86_INS_CVTSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTSI2SD64rr, X86_INS_CVTSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTSI2SDrm, X86_INS_CVTSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTSI2SDrr, X86_INS_CVTSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTSI2SS64rm, X86_INS_CVTSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_CVTSI2SS64rr, X86_INS_CVTSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_CVTSI2SSrm, X86_INS_CVTSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_CVTSI2SSrr, X86_INS_CVTSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_CVTSS2SDrm, X86_INS_CVTSS2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTSS2SDrr, X86_INS_CVTSS2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTSS2SI64rm, X86_INS_CVTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_CVTSS2SI64rr, X86_INS_CVTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_CVTSS2SIrm, X86_INS_CVTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_CVTSS2SIrr, X86_INS_CVTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_CVTTPD2DQrm, X86_INS_CVTTPD2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTTPD2DQrr, X86_INS_CVTTPD2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTTPS2DQrm, X86_INS_CVTTPS2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTTPS2DQrr, X86_INS_CVTTPS2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTTSD2SI64rm, X86_INS_CVTTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTTSD2SI64rr, X86_INS_CVTTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTTSD2SIrm, X86_INS_CVTTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTTSD2SIrr, X86_INS_CVTTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_CVTTSS2SI64rm, X86_INS_CVTTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_CVTTSS2SI64rr, X86_INS_CVTTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_CVTTSS2SIrm, X86_INS_CVTTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_CVTTSS2SIrr, X86_INS_CVTTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_CWD, X86_INS_CWD,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, 0 }, { X86_REG_AX, X86_REG_DX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CWDE, X86_INS_CWDE,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, 0 }, { X86_REG_EAX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DAA, X86_INS_DAA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_DAS, X86_INS_DAS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_DATA16_PREFIX, X86_INS_DATA16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DEC16m, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_DEC16r, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_DEC32_16r, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_DEC32_32r, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_DEC32m, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_DEC32r, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_DEC64_16m, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_DEC64_16r, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_DEC64_32m, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_DEC64_32r, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_DEC64m, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DEC64r, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DEC8m, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DEC8r, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIV16m, X86_INS_DIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, X86_REG_DX, 0 }, { X86_REG_AX, X86_REG_DX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIV16r, X86_INS_DIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, X86_REG_DX, 0 }, { X86_REG_AX, X86_REG_DX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIV32m, X86_INS_DIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_EDX, 0 }, { X86_REG_EAX, X86_REG_EDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIV32r, X86_INS_DIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_EDX, 0 }, { X86_REG_EAX, X86_REG_EDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIV64m, X86_INS_DIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_RDX, 0 }, { X86_REG_RAX, X86_REG_RDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIV64r, X86_INS_DIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_RDX, 0 }, { X86_REG_RAX, X86_REG_RDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIV8m, X86_INS_DIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, 0 }, { X86_REG_AL, X86_REG_AH, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIV8r, X86_INS_DIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, 0 }, { X86_REG_AL, X86_REG_AH, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIVPDrm, X86_INS_DIVPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_DIVPDrr, X86_INS_DIVPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_DIVPSrm, X86_INS_DIVPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_DIVPSrr, X86_INS_DIVPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_DIVR_F32m, X86_INS_FDIVR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIVR_F64m, X86_INS_FDIVR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIVR_FI16m, X86_INS_FIDIVR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIVR_FI32m, X86_INS_FIDIVR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIVR_FPrST0, X86_INS_FDIVRP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIVR_FST0r, X86_INS_FDIVR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIVR_FrST0, X86_INS_FDIVR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIVSDrm, X86_INS_DIVSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_DIVSDrm_Int, X86_INS_DIVSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_DIVSDrr, X86_INS_DIVSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_DIVSDrr_Int, X86_INS_DIVSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_DIVSSrm, X86_INS_DIVSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_DIVSSrm_Int, X86_INS_DIVSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_DIVSSrr, X86_INS_DIVSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_DIVSSrr_Int, X86_INS_DIVSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_DIV_F32m, X86_INS_FDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIV_F64m, X86_INS_FDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIV_FI16m, X86_INS_FIDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIV_FI32m, X86_INS_FIDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIV_FPrST0, X86_INS_FDIVP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIV_FST0r, X86_INS_FDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIV_FrST0, X86_INS_FDIV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DPPDrmi, X86_INS_DPPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_DPPDrri, X86_INS_DPPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_DPPSrmi, X86_INS_DPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_DPPSrri, X86_INS_DPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_ENCLS, X86_INS_ENCLS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SGX, 0 }, 0, 0
#endif
	},
	{
		X86_ENCLU, X86_INS_ENCLU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SGX, 0 }, 0, 0
#endif
	},
	{
		X86_ENTER, X86_INS_ENTER,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_EXTRACTPSmr, X86_INS_EXTRACTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_EXTRACTPSrr, X86_INS_EXTRACTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_EXTRQ, X86_INS_EXTRQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE4A, 0 }, 0, 0
#endif
	},
	{
		X86_EXTRQI, X86_INS_EXTRQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE4A, 0 }, 0, 0
#endif
	},
	{
		X86_F2XM1, X86_INS_F2XM1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FARCALL16i, X86_INS_LCALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { 0 }, { X86_GRP_CALL, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_FARCALL16m, X86_INS_LCALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { 0 }, { X86_GRP_CALL, 0 }, 0, 0
#endif
	},
	{
		X86_FARCALL32i, X86_INS_LCALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { 0 }, { X86_GRP_CALL, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_FARCALL32m, X86_INS_LCALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { 0 }, { X86_GRP_CALL, 0 }, 0, 0
#endif
	},
	{
		X86_FARCALL64, X86_INS_LCALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { 0 }, { X86_GRP_CALL, 0 }, 0, 0
#endif
	},
	{
		X86_FARJMP16i, X86_INS_LJMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 1, 1
#endif
	},
	{
		X86_FARJMP16m, X86_INS_LJMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 1
#endif
	},
	{
		X86_FARJMP32i, X86_INS_LJMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 1, 1
#endif
	},
	{
		X86_FARJMP32m, X86_INS_LJMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 1
#endif
	},
	{
		X86_FARJMP64, X86_INS_LJMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 1
#endif
	},
	{
		X86_FBLDm, X86_INS_FBLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FBSTPm, X86_INS_FBSTP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FCOM32m, X86_INS_FCOM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FCOM64m, X86_INS_FCOM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FCOMP32m, X86_INS_FCOMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FCOMP64m, X86_INS_FCOMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FCOMPP, X86_INS_FCOMPP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FDECSTP, X86_INS_FDECSTP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FEMMS, X86_INS_FEMMS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_FFREE, X86_INS_FFREE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FICOM16m, X86_INS_FICOM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FICOM32m, X86_INS_FICOM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FICOMP16m, X86_INS_FICOMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FICOMP32m, X86_INS_FICOMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FINCSTP, X86_INS_FINCSTP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FLDCW16m, X86_INS_FLDCW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FLDENVm, X86_INS_FLDENV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FLDL2E, X86_INS_FLDL2E,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FLDL2T, X86_INS_FLDL2T,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FLDLG2, X86_INS_FLDLG2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FLDLN2, X86_INS_FLDLN2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FLDPI, X86_INS_FLDPI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FNCLEX, X86_INS_FNCLEX,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FNINIT, X86_INS_FNINIT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FNOP, X86_INS_FNOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FNSTCW16m, X86_INS_FNSTCW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FNSTSW16r, X86_INS_FNSTSW,
#ifndef CAPSTONE_DIET
		{ X86_REG_FPSW, 0 }, { X86_REG_AX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FNSTSWm, X86_INS_FNSTSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FPATAN, X86_INS_FPATAN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FPREM, X86_INS_FPREM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FPREM1, X86_INS_FPREM1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FPTAN, X86_INS_FPTAN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FRNDINT, X86_INS_FRNDINT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FRSTORm, X86_INS_FRSTOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FSAVEm, X86_INS_FNSAVE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FSCALE, X86_INS_FSCALE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FSETPM, X86_INS_FSETPM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FSINCOS, X86_INS_FSINCOS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FSTENVm, X86_INS_FNSTENV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FXAM, X86_INS_FXAM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FXRSTOR, X86_INS_FXRSTOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FXRSTOR64, X86_INS_FXRSTOR64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_FXSAVE, X86_INS_FXSAVE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FXSAVE64, X86_INS_FXSAVE64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_FXTRACT, X86_INS_FXTRACT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FYL2X, X86_INS_FYL2X,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FYL2XP1, X86_INS_FYL2XP1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FsANDNPDrm, X86_INS_ANDNPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_FsANDNPDrr, X86_INS_ANDNPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_FsANDNPSrm, X86_INS_ANDNPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_FsANDNPSrr, X86_INS_ANDNPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_FsANDPDrm, X86_INS_ANDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_FsANDPDrr, X86_INS_ANDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_FsANDPSrm, X86_INS_ANDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_FsANDPSrr, X86_INS_ANDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_FsMOVAPDrm, X86_INS_MOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_FsMOVAPSrm, X86_INS_MOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_FsORPDrm, X86_INS_ORPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_FsORPDrr, X86_INS_ORPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_FsORPSrm, X86_INS_ORPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_FsORPSrr, X86_INS_ORPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_FsVMOVAPDrm, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_FsVMOVAPSrm, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_FsXORPDrm, X86_INS_XORPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_FsXORPDrr, X86_INS_XORPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_FsXORPSrm, X86_INS_XORPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_FsXORPSrr, X86_INS_XORPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_GETSEC, X86_INS_GETSEC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_HADDPDrm, X86_INS_HADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE3, 0 }, 0, 0
#endif
	},
	{
		X86_HADDPDrr, X86_INS_HADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE3, 0 }, 0, 0
#endif
	},
	{
		X86_HADDPSrm, X86_INS_HADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE3, 0 }, 0, 0
#endif
	},
	{
		X86_HADDPSrr, X86_INS_HADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE3, 0 }, 0, 0
#endif
	},
	{
		X86_HLT, X86_INS_HLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_HSUBPDrm, X86_INS_HSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE3, 0 }, 0, 0
#endif
	},
	{
		X86_HSUBPDrr, X86_INS_HSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE3, 0 }, 0, 0
#endif
	},
	{
		X86_HSUBPSrm, X86_INS_HSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE3, 0 }, 0, 0
#endif
	},
	{
		X86_HSUBPSrr, X86_INS_HSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE3, 0 }, 0, 0
#endif
	},
	{
		X86_IDIV16m, X86_INS_IDIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, X86_REG_DX, 0 }, { X86_REG_AX, X86_REG_DX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IDIV16r, X86_INS_IDIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, X86_REG_DX, 0 }, { X86_REG_AX, X86_REG_DX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IDIV32m, X86_INS_IDIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_EDX, 0 }, { X86_REG_EAX, X86_REG_EDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IDIV32r, X86_INS_IDIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_EDX, 0 }, { X86_REG_EAX, X86_REG_EDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IDIV64m, X86_INS_IDIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_RDX, 0 }, { X86_REG_RAX, X86_REG_RDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IDIV64r, X86_INS_IDIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_RDX, 0 }, { X86_REG_RAX, X86_REG_RDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IDIV8m, X86_INS_IDIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, 0 }, { X86_REG_AL, X86_REG_AH, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IDIV8r, X86_INS_IDIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, 0 }, { X86_REG_AL, X86_REG_AH, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ILD_F16m, X86_INS_FILD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ILD_F32m, X86_INS_FILD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ILD_F64m, X86_INS_FILD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL16m, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, 0 }, { X86_REG_AX, X86_REG_DX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL16r, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, 0 }, { X86_REG_AX, X86_REG_DX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL16rm, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL16rmi, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL16rmi8, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL16rr, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL16rri, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL16rri8, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL32m, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { X86_REG_EAX, X86_REG_EDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL32r, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { X86_REG_EAX, X86_REG_EDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL32rm, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL32rmi, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL32rmi8, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL32rr, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL32rri, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL32rri8, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL64m, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, 0 }, { X86_REG_RAX, X86_REG_RDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL64r, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, 0 }, { X86_REG_RAX, X86_REG_RDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL64rm, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL64rmi32, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL64rmi8, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL64rr, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL64rri32, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL64rri8, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL8m, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_AL, 0 }, { X86_REG_AL, X86_REG_EFLAGS, X86_REG_AX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL8r, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_AL, 0 }, { X86_REG_AL, X86_REG_EFLAGS, X86_REG_AX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IN16ri, X86_INS_IN,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_AX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IN16rr, X86_INS_IN,
#ifndef CAPSTONE_DIET
		{ X86_REG_DX, 0 }, { X86_REG_AX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IN32ri, X86_INS_IN,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EAX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IN32rr, X86_INS_IN,
#ifndef CAPSTONE_DIET
		{ X86_REG_DX, 0 }, { X86_REG_EAX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IN8ri, X86_INS_IN,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_AL, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IN8rr, X86_INS_IN,
#ifndef CAPSTONE_DIET
		{ X86_REG_DX, 0 }, { X86_REG_AL, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_INC16m, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_INC16r, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_INC32_16r, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_INC32_32r, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_INC32m, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_INC32r, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_INC64_16m, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_INC64_16r, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_INC64_32m, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_INC64_32r, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_INC64m, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_INC64r, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_INC8m, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_INC8r, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_INSB, X86_INS_INSB,
#ifndef CAPSTONE_DIET
		{ X86_REG_DX, X86_REG_EDI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_INSERTPSrm, X86_INS_INSERTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_INSERTPSrr, X86_INS_INSERTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_INSERTQ, X86_INS_INSERTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE4A, 0 }, 0, 0
#endif
	},
	{
		X86_INSERTQI, X86_INS_INSERTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE4A, 0 }, 0, 0
#endif
	},
	{
		X86_INSL, X86_INS_INSD,
#ifndef CAPSTONE_DIET
		{ X86_REG_DX, X86_REG_EDI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_INSW, X86_INS_INSW,
#ifndef CAPSTONE_DIET
		{ X86_REG_DX, X86_REG_EDI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_INT, X86_INS_INT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_INT, 0 }, 0, 0
#endif
	},
	{
		X86_INT1, X86_INS_INT1,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_INT, 0 }, 0, 0
#endif
	},
	{
		X86_INT3, X86_INS_INT3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_INT, 0 }, 0, 0
#endif
	},
	{
		X86_INTO, X86_INS_INTO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_INT, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_INVD, X86_INS_INVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_INVEPT32, X86_INS_INVEPT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_INVEPT64, X86_INS_INVEPT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_INVLPG, X86_INS_INVLPG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_INVLPGA32, X86_INS_INVLPGA,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_ECX, 0 }, { 0 }, { X86_GRP_VM, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_INVLPGA64, X86_INS_INVLPGA,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_ECX, 0 }, { 0 }, { X86_GRP_VM, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_INVPCID32, X86_INS_INVPCID,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_INVPCID64, X86_INS_INVPCID,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_INVVPID32, X86_INS_INVVPID,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_INVVPID64, X86_INS_INVVPID,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_IRET16, X86_INS_IRET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_IRET, 0 }, 0, 0
#endif
	},
	{
		X86_IRET32, X86_INS_IRETD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_IRET, 0 }, 0, 0
#endif
	},
	{
		X86_IRET64, X86_INS_IRETQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_IRET, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_ISTT_FP16m, X86_INS_FISTTP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ISTT_FP32m, X86_INS_FISTTP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ISTT_FP64m, X86_INS_FISTTP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IST_F16m, X86_INS_FIST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IST_F32m, X86_INS_FIST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IST_FP16m, X86_INS_FISTP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IST_FP32m, X86_INS_FISTP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IST_FP64m, X86_INS_FISTP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_Int_CMPSDrm, X86_INS_CMPSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_Int_CMPSDrr, X86_INS_CMPSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_Int_CMPSSrm, X86_INS_CMPSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_Int_CMPSSrr, X86_INS_CMPSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_Int_COMISDrm, X86_INS_COMISD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_Int_COMISDrr, X86_INS_COMISD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_Int_COMISSrm, X86_INS_COMISS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_Int_COMISSrr, X86_INS_COMISS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_Int_CVTSD2SSrm, X86_INS_CVTSD2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_Int_CVTSD2SSrr, X86_INS_CVTSD2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_Int_CVTSI2SD64rm, X86_INS_CVTSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_Int_CVTSI2SD64rr, X86_INS_CVTSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_Int_CVTSI2SDrm, X86_INS_CVTSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_Int_CVTSI2SDrr, X86_INS_CVTSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_Int_CVTSI2SS64rm, X86_INS_CVTSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_Int_CVTSI2SS64rr, X86_INS_CVTSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_Int_CVTSI2SSrm, X86_INS_CVTSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_Int_CVTSI2SSrr, X86_INS_CVTSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_Int_CVTSS2SDrm, X86_INS_CVTSS2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_Int_CVTSS2SDrr, X86_INS_CVTSS2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_Int_CVTTSD2SI64rm, X86_INS_CVTTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_Int_CVTTSD2SI64rr, X86_INS_CVTTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_Int_CVTTSD2SIrm, X86_INS_CVTTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_Int_CVTTSD2SIrr, X86_INS_CVTTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_Int_CVTTSS2SI64rm, X86_INS_CVTTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_Int_CVTTSS2SI64rr, X86_INS_CVTTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_Int_CVTTSS2SIrm, X86_INS_CVTTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_Int_CVTTSS2SIrr, X86_INS_CVTTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_Int_UCOMISDrm, X86_INS_UCOMISD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_Int_UCOMISDrr, X86_INS_UCOMISD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_Int_UCOMISSrm, X86_INS_UCOMISS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_Int_UCOMISSrr, X86_INS_UCOMISS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCMPSDrm, X86_INS_VCMPSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCMPSDrr, X86_INS_VCMPSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCMPSSrm, X86_INS_VCMPSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCMPSSrr, X86_INS_VCMPSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCOMISDZrm, X86_INS_VCOMISD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCOMISDZrr, X86_INS_VCOMISD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCOMISDrm, X86_INS_VCOMISD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCOMISDrr, X86_INS_VCOMISD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCOMISSZrm, X86_INS_VCOMISS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCOMISSZrr, X86_INS_VCOMISS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCOMISSrm, X86_INS_VCOMISS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCOMISSrr, X86_INS_VCOMISS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTSD2SSrm, X86_INS_VCVTSD2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTSD2SSrr, X86_INS_VCVTSD2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTSI2SD64Zrm, X86_INS_VCVTSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTSI2SD64Zrr, X86_INS_VCVTSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTSI2SD64rm, X86_INS_VCVTSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTSI2SD64rr, X86_INS_VCVTSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTSI2SDZrm, X86_INS_VCVTSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTSI2SDZrr, X86_INS_VCVTSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTSI2SDrm, X86_INS_VCVTSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTSI2SDrr, X86_INS_VCVTSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTSI2SS64Zrm, X86_INS_VCVTSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTSI2SS64Zrr, X86_INS_VCVTSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTSI2SS64rm, X86_INS_VCVTSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTSI2SS64rr, X86_INS_VCVTSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTSI2SSZrm, X86_INS_VCVTSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTSI2SSZrr, X86_INS_VCVTSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTSI2SSrm, X86_INS_VCVTSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTSI2SSrr, X86_INS_VCVTSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTSS2SDrm, X86_INS_VCVTSS2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTSS2SDrr, X86_INS_VCVTSS2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTTSD2SI64Zrm, X86_INS_VCVTTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTTSD2SI64Zrr, X86_INS_VCVTTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTTSD2SI64rm, X86_INS_VCVTTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTTSD2SI64rr, X86_INS_VCVTTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTTSD2SIZrm, X86_INS_VCVTTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTTSD2SIZrr, X86_INS_VCVTTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTTSD2SIrm, X86_INS_VCVTTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTTSD2SIrr, X86_INS_VCVTTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTTSD2USI64Zrm, X86_INS_VCVTTSD2USI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTTSD2USI64Zrr, X86_INS_VCVTTSD2USI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTTSD2USIZrm, X86_INS_VCVTTSD2USI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTTSD2USIZrr, X86_INS_VCVTTSD2USI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTTSS2SI64Zrm, X86_INS_VCVTTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTTSS2SI64Zrr, X86_INS_VCVTTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTTSS2SI64rm, X86_INS_VCVTTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTTSS2SI64rr, X86_INS_VCVTTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTTSS2SIZrm, X86_INS_VCVTTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTTSS2SIZrr, X86_INS_VCVTTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTTSS2SIrm, X86_INS_VCVTTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTTSS2SIrr, X86_INS_VCVTTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTTSS2USI64Zrm, X86_INS_VCVTTSS2USI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTTSS2USI64Zrr, X86_INS_VCVTTSS2USI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTTSS2USIZrm, X86_INS_VCVTTSS2USI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTTSS2USIZrr, X86_INS_VCVTTSS2USI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTUSI2SD64Zrm, X86_INS_VCVTUSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTUSI2SD64Zrr, X86_INS_VCVTUSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTUSI2SDZrm, X86_INS_VCVTUSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTUSI2SDZrr, X86_INS_VCVTUSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTUSI2SS64Zrm, X86_INS_VCVTUSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTUSI2SS64Zrr, X86_INS_VCVTUSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTUSI2SSZrm, X86_INS_VCVTUSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VCVTUSI2SSZrr, X86_INS_VCVTUSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VUCOMISDZrm, X86_INS_VUCOMISD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VUCOMISDZrr, X86_INS_VUCOMISD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VUCOMISDrm, X86_INS_VUCOMISD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VUCOMISDrr, X86_INS_VUCOMISD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VUCOMISSZrm, X86_INS_VUCOMISS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VUCOMISSZrr, X86_INS_VUCOMISS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VUCOMISSrm, X86_INS_VUCOMISS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_Int_VUCOMISSrr, X86_INS_VUCOMISS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_JAE_1, X86_INS_JAE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JAE_2, X86_INS_JAE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JAE_4, X86_INS_JAE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JA_1, X86_INS_JA,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JA_2, X86_INS_JA,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JA_4, X86_INS_JA,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JBE_1, X86_INS_JBE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JBE_2, X86_INS_JBE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JBE_4, X86_INS_JBE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JB_1, X86_INS_JB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JB_2, X86_INS_JB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JB_4, X86_INS_JB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JCXZ, X86_INS_JCXZ,
#ifndef CAPSTONE_DIET
		{ X86_REG_CX, 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JECXZ_32, X86_INS_JECXZ,
#ifndef CAPSTONE_DIET
		{ X86_REG_ECX, 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JECXZ_64, X86_INS_JECXZ,
#ifndef CAPSTONE_DIET
		{ X86_REG_ECX, 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 1, 0
#endif
	},
	{
		X86_JE_1, X86_INS_JE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JE_2, X86_INS_JE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JE_4, X86_INS_JE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JGE_1, X86_INS_JGE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JGE_2, X86_INS_JGE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JGE_4, X86_INS_JGE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JG_1, X86_INS_JG,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JG_2, X86_INS_JG,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JG_4, X86_INS_JG,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JLE_1, X86_INS_JLE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JLE_2, X86_INS_JLE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JLE_4, X86_INS_JLE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JL_1, X86_INS_JL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JL_2, X86_INS_JL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JL_4, X86_INS_JL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JMP16m, X86_INS_JMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 1, 1
#endif
	},
	{
		X86_JMP16r, X86_INS_JMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 1, 1
#endif
	},
	{
		X86_JMP32m, X86_INS_JMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 1, 1
#endif
	},
	{
		X86_JMP32r, X86_INS_JMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 1, 1
#endif
	},
	{
		X86_JMP64m, X86_INS_JMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 1, 1
#endif
	},
	{
		X86_JMP64r, X86_INS_JMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 1, 1
#endif
	},
	{
		X86_JMP_1, X86_INS_JMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JMP_2, X86_INS_JMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JMP_4, X86_INS_JMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JNE_1, X86_INS_JNE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JNE_2, X86_INS_JNE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JNE_4, X86_INS_JNE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JNO_1, X86_INS_JNO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JNO_2, X86_INS_JNO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JNO_4, X86_INS_JNO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JNP_1, X86_INS_JNP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JNP_2, X86_INS_JNP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JNP_4, X86_INS_JNP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JNS_1, X86_INS_JNS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JNS_2, X86_INS_JNS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JNS_4, X86_INS_JNS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JO_1, X86_INS_JO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JO_2, X86_INS_JO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JO_4, X86_INS_JO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JP_1, X86_INS_JP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JP_2, X86_INS_JP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JP_4, X86_INS_JP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JRCXZ, X86_INS_JRCXZ,
#ifndef CAPSTONE_DIET
		{ X86_REG_RCX, 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 1, 0
#endif
	},
	{
		X86_JS_1, X86_INS_JS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JS_2, X86_INS_JS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JS_4, X86_INS_JS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_KANDBrr, X86_INS_KANDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_DQI, 0 }, 0, 0
#endif
	},
	{
		X86_KANDDrr, X86_INS_KANDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_KANDNBrr, X86_INS_KANDNB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_DQI, 0 }, 0, 0
#endif
	},
	{
		X86_KANDNDrr, X86_INS_KANDND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_KANDNQrr, X86_INS_KANDNQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_KANDNWrr, X86_INS_KANDNW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_KANDQrr, X86_INS_KANDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_KANDWrr, X86_INS_KANDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_KMOVBkk, X86_INS_KMOVB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_DQI, 0 }, 0, 0
#endif
	},
	{
		X86_KMOVBkm, X86_INS_KMOVB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_DQI, 0 }, 0, 0
#endif
	},
	{
		X86_KMOVBkr, X86_INS_KMOVB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_DQI, 0 }, 0, 0
#endif
	},
	{
		X86_KMOVBmk, X86_INS_KMOVB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_DQI, 0 }, 0, 0
#endif
	},
	{
		X86_KMOVBrk, X86_INS_KMOVB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_DQI, 0 }, 0, 0
#endif
	},
	{
		X86_KMOVDkk, X86_INS_KMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_KMOVDkm, X86_INS_KMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_KMOVDkr, X86_INS_KMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_KMOVDmk, X86_INS_KMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_KMOVDrk, X86_INS_KMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_KMOVQkk, X86_INS_KMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_KMOVQkm, X86_INS_KMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_KMOVQkr, X86_INS_KMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_KMOVQmk, X86_INS_KMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_KMOVQrk, X86_INS_KMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_KMOVWkk, X86_INS_KMOVW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_KMOVWkm, X86_INS_KMOVW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_KMOVWkr, X86_INS_KMOVW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_KMOVWmk, X86_INS_KMOVW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_KMOVWrk, X86_INS_KMOVW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_KNOTBrr, X86_INS_KNOTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_DQI, 0 }, 0, 0
#endif
	},
	{
		X86_KNOTDrr, X86_INS_KNOTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_KNOTQrr, X86_INS_KNOTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_KNOTWrr, X86_INS_KNOTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_KORBrr, X86_INS_KORB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_DQI, 0 }, 0, 0
#endif
	},
	{
		X86_KORDrr, X86_INS_KORD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_KORQrr, X86_INS_KORQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_KORTESTWrr, X86_INS_KORTESTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_KORWrr, X86_INS_KORW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_KSHIFTLWri, X86_INS_KSHIFTLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_KSHIFTRWri, X86_INS_KSHIFTRW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_KUNPCKBWrr, X86_INS_KUNPCKBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_KXNORBrr, X86_INS_KXNORB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_DQI, 0 }, 0, 0
#endif
	},
	{
		X86_KXNORDrr, X86_INS_KXNORD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_KXNORQrr, X86_INS_KXNORQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_KXNORWrr, X86_INS_KXNORW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_KXORBrr, X86_INS_KXORB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_DQI, 0 }, 0, 0
#endif
	},
	{
		X86_KXORDrr, X86_INS_KXORD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_KXORQrr, X86_INS_KXORQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_KXORWrr, X86_INS_KXORW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_LAHF, X86_INS_LAHF,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_AH, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LAR16rm, X86_INS_LAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LAR16rr, X86_INS_LAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LAR32rm, X86_INS_LAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LAR32rr, X86_INS_LAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LAR64rm, X86_INS_LAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LAR64rr, X86_INS_LAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LCMPXCHG16, X86_INS_CMPXCHG,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, 0 }, { X86_REG_AX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LCMPXCHG16B, X86_INS_CMPXCHG16B,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_RBX, X86_REG_RCX, X86_REG_RDX, 0 }, { X86_REG_RAX, X86_REG_RDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LCMPXCHG32, X86_INS_CMPXCHG,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { X86_REG_EAX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LCMPXCHG64, X86_INS_CMPXCHG,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, 0 }, { X86_REG_RAX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LCMPXCHG8, X86_INS_CMPXCHG,
#ifndef CAPSTONE_DIET
		{ X86_REG_AL, 0 }, { X86_REG_AL, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LCMPXCHG8B, X86_INS_CMPXCHG8B,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_EBX, X86_REG_ECX, X86_REG_EDX, 0 }, { X86_REG_EAX, X86_REG_EDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LDDQUrm, X86_INS_LDDQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE3, 0 }, 0, 0
#endif
	},
	{
		X86_LDMXCSR, X86_INS_LDMXCSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_LDS16rm, X86_INS_LDS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LDS32rm, X86_INS_LDS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LD_F0, X86_INS_FLDZ,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LD_F1, X86_INS_FLD1,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LD_F32m, X86_INS_FLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LD_F64m, X86_INS_FLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LD_F80m, X86_INS_FLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LD_Frr, X86_INS_FLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LEA16r, X86_INS_LEA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LEA32r, X86_INS_LEA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_LEA64_32r, X86_INS_LEA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_LEA64r, X86_INS_LEA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LEAVE, X86_INS_LEAVE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EBP, X86_REG_ESP, 0 }, { X86_REG_EBP, X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_LEAVE64, X86_INS_LEAVE,
#ifndef CAPSTONE_DIET
		{ X86_REG_RBP, X86_REG_RSP, 0 }, { X86_REG_RBP, X86_REG_RSP, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_LES16rm, X86_INS_LES,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LES32rm, X86_INS_LES,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LFENCE, X86_INS_LFENCE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_LFS16rm, X86_INS_LFS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LFS32rm, X86_INS_LFS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LFS64rm, X86_INS_LFS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LGDT16m, X86_INS_LGDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_LGDT32m, X86_INS_LGDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_LGDT64m, X86_INS_LGDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_LGS16rm, X86_INS_LGS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LGS32rm, X86_INS_LGS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LGS64rm, X86_INS_LGS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LIDT16m, X86_INS_LIDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_LIDT32m, X86_INS_LIDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_LIDT64m, X86_INS_LIDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_LLDT16m, X86_INS_LLDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LLDT16r, X86_INS_LLDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LMSW16m, X86_INS_LMSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LMSW16r, X86_INS_LMSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_ADD16mi, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_ADD16mi8, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_ADD16mr, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_ADD32mi, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_ADD32mi8, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_ADD32mr, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_ADD64mi32, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_ADD64mi8, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_ADD64mr, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_ADD8mi, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_ADD8mr, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_AND16mi, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_AND16mi8, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_AND16mr, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_AND32mi, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_AND32mi8, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_AND32mr, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_AND64mi32, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_AND64mi8, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_AND64mr, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_AND8mi, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_AND8mr, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_DEC16m, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_DEC32m, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_DEC64m, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_DEC8m, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_INC16m, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_INC32m, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_INC64m, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_INC8m, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_OR16mi, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_OR16mi8, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_OR16mr, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_OR32mi, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_OR32mi8, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_OR32mr, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_OR64mi32, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_OR64mi8, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_OR64mr, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_OR8mi, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_OR8mr, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_SUB16mi, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_SUB16mi8, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_SUB16mr, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_SUB32mi, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_SUB32mi8, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_SUB32mr, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_SUB64mi32, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_SUB64mi8, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_SUB64mr, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_SUB8mi, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_SUB8mr, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_XOR16mi, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_XOR16mi8, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_XOR16mr, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_XOR32mi, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_XOR32mi8, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_XOR32mr, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_XOR64mi32, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_XOR64mi8, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_XOR64mr, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_XOR8mi, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_XOR8mr, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LODSB, X86_INS_LODSB,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_AL, X86_REG_ESI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LODSL, X86_INS_LODSD,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_EAX, X86_REG_ESI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LODSQ, X86_INS_LODSQ,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_RAX, X86_REG_ESI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LODSW, X86_INS_LODSW,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_AX, X86_REG_ESI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOOP, X86_INS_LOOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_LOOPE, X86_INS_LOOPE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_LOOPNE, X86_INS_LOOPNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_LRETIL, X86_INS_RETF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RET, 0 }, 0, 0
#endif
	},
	{
		X86_LRETIQ, X86_INS_RETFQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RET, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_LRETIW, X86_INS_RETF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RET, 0 }, 0, 0
#endif
	},
	{
		X86_LRETL, X86_INS_RETF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RET, 0 }, 0, 0
#endif
	},
	{
		X86_LRETQ, X86_INS_RETFQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RET, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_LRETW, X86_INS_RETF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RET, 0 }, 0, 0
#endif
	},
	{
		X86_LSL16rm, X86_INS_LSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LSL16rr, X86_INS_LSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LSL32rm, X86_INS_LSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LSL32rr, X86_INS_LSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LSL64rm, X86_INS_LSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LSL64rr, X86_INS_LSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LSS16rm, X86_INS_LSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LSS32rm, X86_INS_LSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LSS64rm, X86_INS_LSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LTRm, X86_INS_LTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LTRr, X86_INS_LTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LXADD16, X86_INS_XADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LXADD32, X86_INS_XADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LXADD64, X86_INS_XADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LXADD8, X86_INS_XADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LZCNT16rm, X86_INS_LZCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LZCNT16rr, X86_INS_LZCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LZCNT32rm, X86_INS_LZCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LZCNT32rr, X86_INS_LZCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LZCNT64rm, X86_INS_LZCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LZCNT64rr, X86_INS_LZCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MASKMOVDQU, X86_INS_MASKMOVDQU,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDI, 0 }, { 0 }, { X86_GRP_SSE2, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_MASKMOVDQU64, X86_INS_MASKMOVDQU,
#ifndef CAPSTONE_DIET
		{ X86_REG_RDI, 0 }, { 0 }, { X86_GRP_SSE2, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MAXCPDrm, X86_INS_MAXPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MAXCPDrr, X86_INS_MAXPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MAXCPSrm, X86_INS_MAXPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MAXCPSrr, X86_INS_MAXPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MAXCSDrm, X86_INS_MAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MAXCSDrr, X86_INS_MAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MAXCSSrm, X86_INS_MAXSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MAXCSSrr, X86_INS_MAXSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MAXPDrm, X86_INS_MAXPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MAXPDrr, X86_INS_MAXPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MAXPSrm, X86_INS_MAXPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MAXPSrr, X86_INS_MAXPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MAXSDrm, X86_INS_MAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MAXSDrm_Int, X86_INS_MAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MAXSDrr, X86_INS_MAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MAXSDrr_Int, X86_INS_MAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MAXSSrm, X86_INS_MAXSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MAXSSrm_Int, X86_INS_MAXSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MAXSSrr, X86_INS_MAXSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MAXSSrr_Int, X86_INS_MAXSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MFENCE, X86_INS_MFENCE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MINCPDrm, X86_INS_MINPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MINCPDrr, X86_INS_MINPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MINCPSrm, X86_INS_MINPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MINCPSrr, X86_INS_MINPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MINCSDrm, X86_INS_MINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MINCSDrr, X86_INS_MINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MINCSSrm, X86_INS_MINSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MINCSSrr, X86_INS_MINSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MINPDrm, X86_INS_MINPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MINPDrr, X86_INS_MINPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MINPSrm, X86_INS_MINPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MINPSrr, X86_INS_MINPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MINSDrm, X86_INS_MINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MINSDrm_Int, X86_INS_MINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MINSDrr, X86_INS_MINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MINSDrr_Int, X86_INS_MINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MINSSrm, X86_INS_MINSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MINSSrm_Int, X86_INS_MINSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MINSSrr, X86_INS_MINSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MINSSrr_Int, X86_INS_MINSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_CVTPD2PIirm, X86_INS_CVTPD2PI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_CVTPD2PIirr, X86_INS_CVTPD2PI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_CVTPI2PDirm, X86_INS_CVTPI2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_CVTPI2PDirr, X86_INS_CVTPI2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_CVTPI2PSirm, X86_INS_CVTPI2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_CVTPI2PSirr, X86_INS_CVTPI2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_CVTPS2PIirm, X86_INS_CVTPS2PI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_CVTPS2PIirr, X86_INS_CVTPS2PI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_CVTTPD2PIirm, X86_INS_CVTTPD2PI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_CVTTPD2PIirr, X86_INS_CVTTPD2PI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_CVTTPS2PIirm, X86_INS_CVTTPS2PI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_CVTTPS2PIirr, X86_INS_CVTTPS2PI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_EMMS, X86_INS_EMMS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_MASKMOVQ, X86_INS_MASKMOVQ,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDI, 0 }, { 0 }, { X86_GRP_MMX, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_MASKMOVQ64, X86_INS_MASKMOVQ,
#ifndef CAPSTONE_DIET
		{ X86_REG_RDI, 0 }, { 0 }, { X86_GRP_MMX, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_MOVD64from64rr, X86_INS_MOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_MOVD64grr, X86_INS_MOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_MOVD64mr, X86_INS_MOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_MOVD64rm, X86_INS_MOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_MOVD64rr, X86_INS_MOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_MOVD64to64rr, X86_INS_MOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_MOVDQ2Qrr, X86_INS_MOVDQ2Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_MOVFR642Qrr, X86_INS_MOVDQ2Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_MOVNTQmr, X86_INS_MOVNTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_MOVQ2DQrr, X86_INS_MOVQ2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_MOVQ2FR64rr, X86_INS_MOVQ2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_MOVQ64mr, X86_INS_MOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_MOVQ64rm, X86_INS_MOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_MOVQ64rr, X86_INS_MOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_MOVQ64rr_REV, X86_INS_MOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PABSBrm64, X86_INS_PABSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PABSBrr64, X86_INS_PABSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PABSDrm64, X86_INS_PABSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PABSDrr64, X86_INS_PABSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PABSWrm64, X86_INS_PABSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PABSWrr64, X86_INS_PABSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PACKSSDWirm, X86_INS_PACKSSDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PACKSSDWirr, X86_INS_PACKSSDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PACKSSWBirm, X86_INS_PACKSSWB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PACKSSWBirr, X86_INS_PACKSSWB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PACKUSWBirm, X86_INS_PACKUSWB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PACKUSWBirr, X86_INS_PACKUSWB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PADDBirm, X86_INS_PADDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PADDBirr, X86_INS_PADDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PADDDirm, X86_INS_PADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PADDDirr, X86_INS_PADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PADDQirm, X86_INS_PADDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PADDQirr, X86_INS_PADDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PADDSBirm, X86_INS_PADDSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PADDSBirr, X86_INS_PADDSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PADDSWirm, X86_INS_PADDSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PADDSWirr, X86_INS_PADDSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PADDUSBirm, X86_INS_PADDUSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PADDUSBirr, X86_INS_PADDUSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PADDUSWirm, X86_INS_PADDUSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PADDUSWirr, X86_INS_PADDUSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PADDWirm, X86_INS_PADDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PADDWirr, X86_INS_PADDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PALIGNR64irm, X86_INS_PALIGNR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PALIGNR64irr, X86_INS_PALIGNR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PANDNirm, X86_INS_PANDN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PANDNirr, X86_INS_PANDN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PANDirm, X86_INS_PAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PANDirr, X86_INS_PAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PAVGBirm, X86_INS_PAVGB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PAVGBirr, X86_INS_PAVGB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PAVGWirm, X86_INS_PAVGW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PAVGWirr, X86_INS_PAVGW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PCMPEQBirm, X86_INS_PCMPEQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PCMPEQBirr, X86_INS_PCMPEQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PCMPEQDirm, X86_INS_PCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PCMPEQDirr, X86_INS_PCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PCMPEQWirm, X86_INS_PCMPEQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PCMPEQWirr, X86_INS_PCMPEQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PCMPGTBirm, X86_INS_PCMPGTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PCMPGTBirr, X86_INS_PCMPGTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PCMPGTDirm, X86_INS_PCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PCMPGTDirr, X86_INS_PCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PCMPGTWirm, X86_INS_PCMPGTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PCMPGTWirr, X86_INS_PCMPGTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PEXTRWirri, X86_INS_PEXTRW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PHADDSWrm64, X86_INS_PHADDSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PHADDSWrr64, X86_INS_PHADDSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PHADDWrm64, X86_INS_PHADDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PHADDWrr64, X86_INS_PHADDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PHADDrm64, X86_INS_PHADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PHADDrr64, X86_INS_PHADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PHSUBDrm64, X86_INS_PHSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PHSUBDrr64, X86_INS_PHSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PHSUBSWrm64, X86_INS_PHSUBSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PHSUBSWrr64, X86_INS_PHSUBSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PHSUBWrm64, X86_INS_PHSUBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PHSUBWrr64, X86_INS_PHSUBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PINSRWirmi, X86_INS_PINSRW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PINSRWirri, X86_INS_PINSRW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PMADDUBSWrm64, X86_INS_PMADDUBSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PMADDUBSWrr64, X86_INS_PMADDUBSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PMADDWDirm, X86_INS_PMADDWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PMADDWDirr, X86_INS_PMADDWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PMAXSWirm, X86_INS_PMAXSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PMAXSWirr, X86_INS_PMAXSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PMAXUBirm, X86_INS_PMAXUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PMAXUBirr, X86_INS_PMAXUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PMINSWirm, X86_INS_PMINSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PMINSWirr, X86_INS_PMINSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PMINUBirm, X86_INS_PMINUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PMINUBirr, X86_INS_PMINUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PMOVMSKBrr, X86_INS_PMOVMSKB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PMULHRSWrm64, X86_INS_PMULHRSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PMULHRSWrr64, X86_INS_PMULHRSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PMULHUWirm, X86_INS_PMULHUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PMULHUWirr, X86_INS_PMULHUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PMULHWirm, X86_INS_PMULHW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PMULHWirr, X86_INS_PMULHW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PMULLWirm, X86_INS_PMULLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PMULLWirr, X86_INS_PMULLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PMULUDQirm, X86_INS_PMULUDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PMULUDQirr, X86_INS_PMULUDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PORirm, X86_INS_POR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PORirr, X86_INS_POR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSADBWirm, X86_INS_PSADBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSADBWirr, X86_INS_PSADBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSHUFBrm64, X86_INS_PSHUFB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSHUFBrr64, X86_INS_PSHUFB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSHUFWmi, X86_INS_PSHUFW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSHUFWri, X86_INS_PSHUFW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSIGNBrm64, X86_INS_PSIGNB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSIGNBrr64, X86_INS_PSIGNB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSIGNDrm64, X86_INS_PSIGND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSIGNDrr64, X86_INS_PSIGND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSIGNWrm64, X86_INS_PSIGNW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSIGNWrr64, X86_INS_PSIGNW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSLLDri, X86_INS_PSLLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSLLDrm, X86_INS_PSLLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSLLDrr, X86_INS_PSLLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSLLQri, X86_INS_PSLLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSLLQrm, X86_INS_PSLLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSLLQrr, X86_INS_PSLLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSLLWri, X86_INS_PSLLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSLLWrm, X86_INS_PSLLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSLLWrr, X86_INS_PSLLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSRADri, X86_INS_PSRAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSRADrm, X86_INS_PSRAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSRADrr, X86_INS_PSRAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSRAWri, X86_INS_PSRAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSRAWrm, X86_INS_PSRAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSRAWrr, X86_INS_PSRAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSRLDri, X86_INS_PSRLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSRLDrm, X86_INS_PSRLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSRLDrr, X86_INS_PSRLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSRLQri, X86_INS_PSRLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSRLQrm, X86_INS_PSRLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSRLQrr, X86_INS_PSRLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSRLWri, X86_INS_PSRLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSRLWrm, X86_INS_PSRLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSRLWrr, X86_INS_PSRLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSUBBirm, X86_INS_PSUBB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSUBBirr, X86_INS_PSUBB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSUBDirm, X86_INS_PSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSUBDirr, X86_INS_PSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSUBQirm, X86_INS_PSUBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSUBQirr, X86_INS_PSUBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSUBSBirm, X86_INS_PSUBSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSUBSBirr, X86_INS_PSUBSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSUBSWirm, X86_INS_PSUBSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSUBSWirr, X86_INS_PSUBSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSUBUSBirm, X86_INS_PSUBUSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSUBUSBirr, X86_INS_PSUBUSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSUBUSWirm, X86_INS_PSUBUSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSUBUSWirr, X86_INS_PSUBUSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSUBWirm, X86_INS_PSUBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PSUBWirr, X86_INS_PSUBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PUNPCKHBWirm, X86_INS_PUNPCKHBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PUNPCKHBWirr, X86_INS_PUNPCKHBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PUNPCKHDQirm, X86_INS_PUNPCKHDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PUNPCKHDQirr, X86_INS_PUNPCKHDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PUNPCKHWDirm, X86_INS_PUNPCKHWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PUNPCKHWDirr, X86_INS_PUNPCKHWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PUNPCKLBWirm, X86_INS_PUNPCKLBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PUNPCKLBWirr, X86_INS_PUNPCKLBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PUNPCKLDQirm, X86_INS_PUNPCKLDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PUNPCKLDQirr, X86_INS_PUNPCKLDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PUNPCKLWDirm, X86_INS_PUNPCKLWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PUNPCKLWDirr, X86_INS_PUNPCKLWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PXORirm, X86_INS_PXOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MMX_PXORirr, X86_INS_PXOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MMX, 0 }, 0, 0
#endif
	},
	{
		X86_MONITORrrr, X86_INS_MONITOR,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_ECX, X86_REG_EDX, 0 }, { 0 }, { X86_GRP_SSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MONTMUL, X86_INS_MONTMUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_RSI, 0 }, { X86_REG_RAX, X86_REG_RDX, X86_REG_RSI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV16ao16, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE32, 0 }, 0, 0
#endif
	},
	{
		X86_MOV16ao16_16, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_MOV16mi, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV16mr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV16ms, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV16o16a, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE32, 0 }, 0, 0
#endif
	},
	{
		X86_MOV16o16a_16, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_MOV16ri, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV16ri_alt, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV16rm, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV16rr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV16rr_REV, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV16rs, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV16sm, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV16sr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV32ao32, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE32, 0 }, 0, 0
#endif
	},
	{
		X86_MOV32ao32_16, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_MOV32cr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_MOV32dr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_MOV32mi, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV32mr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV32ms, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV32o32a, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE32, 0 }, 0, 0
#endif
	},
	{
		X86_MOV32o32a_16, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_MOV32rc, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_MOV32rd, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_MOV32ri, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV32ri_alt, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV32rm, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV32rr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV32rr_REV, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV32rs, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV32sm, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV32sr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV64ao16, X86_INS_MOVABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64ao32, X86_INS_MOVABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64ao64, X86_INS_MOVABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64ao8, X86_INS_MOVABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64cr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64dr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64mi32, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV64mr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV64ms, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV64o16a, X86_INS_MOVABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64o32a, X86_INS_MOVABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64o64a, X86_INS_MOVABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64o8a, X86_INS_MOVABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64rc, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64rd, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64ri, X86_INS_MOVABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV64ri32, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV64rm, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV64rr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV64rr_REV, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV64rs, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV64sm, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV64sr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV64toPQIrr, X86_INS_MOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64toSDrm, X86_INS_MOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64toSDrr, X86_INS_MOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOV8ao8, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE32, 0 }, 0, 0
#endif
	},
	{
		X86_MOV8ao8_16, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_MOV8mi, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV8mr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV8mr_NOREX, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV8o8a, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE32, 0 }, 0, 0
#endif
	},
	{
		X86_MOV8o8a_16, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_MOV8ri, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV8ri_alt, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV8rm, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV8rm_NOREX, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV8rr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV8rr_NOREX, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV8rr_REV, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVAPDmr, X86_INS_MOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVAPDrm, X86_INS_MOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVAPDrr, X86_INS_MOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVAPDrr_REV, X86_INS_MOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVAPSmr, X86_INS_MOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MOVAPSrm, X86_INS_MOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MOVAPSrr, X86_INS_MOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MOVAPSrr_REV, X86_INS_MOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MOVBE16mr, X86_INS_MOVBE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVBE16rm, X86_INS_MOVBE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVBE32mr, X86_INS_MOVBE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVBE32rm, X86_INS_MOVBE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVBE64mr, X86_INS_MOVBE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVBE64rm, X86_INS_MOVBE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVDDUPrm, X86_INS_MOVDDUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MOVDDUPrr, X86_INS_MOVDDUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MOVDI2PDIrm, X86_INS_MOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVDI2PDIrr, X86_INS_MOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVDI2SSrm, X86_INS_MOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVDI2SSrr, X86_INS_MOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVDQAmr, X86_INS_MOVDQA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVDQArm, X86_INS_MOVDQA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVDQArr, X86_INS_MOVDQA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVDQArr_REV, X86_INS_MOVDQA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVDQUmr, X86_INS_MOVDQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVDQUrm, X86_INS_MOVDQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVDQUrr, X86_INS_MOVDQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVDQUrr_REV, X86_INS_MOVDQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVHLPSrr, X86_INS_MOVHLPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MOVHPDmr, X86_INS_MOVHPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVHPDrm, X86_INS_MOVHPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVHPSmr, X86_INS_MOVHPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MOVHPSrm, X86_INS_MOVHPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MOVLHPSrr, X86_INS_MOVLHPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MOVLPDmr, X86_INS_MOVLPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVLPDrm, X86_INS_MOVLPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVLPSmr, X86_INS_MOVLPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MOVLPSrm, X86_INS_MOVLPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MOVMSKPDrr, X86_INS_MOVMSKPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVMSKPSrr, X86_INS_MOVMSKPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MOVNTDQArm, X86_INS_MOVNTDQA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_MOVNTDQmr, X86_INS_MOVNTDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVNTI_64mr, X86_INS_MOVNTI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVNTImr, X86_INS_MOVNTI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVNTPDmr, X86_INS_MOVNTPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVNTPSmr, X86_INS_MOVNTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MOVNTSD, X86_INS_MOVNTSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE4A, 0 }, 0, 0
#endif
	},
	{
		X86_MOVNTSS, X86_INS_MOVNTSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE4A, 0 }, 0, 0
#endif
	},
	{
		X86_MOVPDI2DImr, X86_INS_MOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVPDI2DIrr, X86_INS_MOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVPQI2QImr, X86_INS_MOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVPQI2QIrr, X86_INS_MOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVPQIto64rr, X86_INS_MOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVQI2PQIrm, X86_INS_MOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVSB, X86_INS_MOVSB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDI, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, X86_REG_ESI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSDmr, X86_INS_MOVSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVSDrm, X86_INS_MOVSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVSDrr, X86_INS_MOVSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVSDrr_REV, X86_INS_MOVSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVSDto64mr, X86_INS_MOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVSDto64rr, X86_INS_MOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVSHDUPrm, X86_INS_MOVSHDUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MOVSHDUPrr, X86_INS_MOVSHDUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MOVSL, X86_INS_MOVSD,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDI, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, X86_REG_ESI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSLDUPrm, X86_INS_MOVSLDUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MOVSLDUPrr, X86_INS_MOVSLDUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE3, 0 }, 0, 0
#endif
	},
	{
		X86_MOVSQ, X86_INS_MOVSQ,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDI, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, X86_REG_ESI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSS2DImr, X86_INS_MOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVSS2DIrr, X86_INS_MOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVSSmr, X86_INS_MOVSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MOVSSrm, X86_INS_MOVSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MOVSSrr, X86_INS_MOVSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MOVSSrr_REV, X86_INS_MOVSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MOVSW, X86_INS_MOVSW,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDI, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, X86_REG_ESI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX16rm8, X86_INS_MOVSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX16rr8, X86_INS_MOVSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX32rm16, X86_INS_MOVSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX32rm8, X86_INS_MOVSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX32rr16, X86_INS_MOVSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX32rr8, X86_INS_MOVSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX64_NOREXrr32, X86_INS_MOVSXD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX64rm16, X86_INS_MOVSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX64rm32, X86_INS_MOVSXD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX64rm8, X86_INS_MOVSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX64rr16, X86_INS_MOVSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX64rr32, X86_INS_MOVSXD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX64rr8, X86_INS_MOVSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVUPDmr, X86_INS_MOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVUPDrm, X86_INS_MOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVUPDrr, X86_INS_MOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVUPDrr_REV, X86_INS_MOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVUPSmr, X86_INS_MOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MOVUPSrm, X86_INS_MOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MOVUPSrr, X86_INS_MOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MOVUPSrr_REV, X86_INS_MOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MOVZPQILo2PQIrm, X86_INS_MOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVZPQILo2PQIrr, X86_INS_MOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVZQI2PQIrm, X86_INS_MOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVZQI2PQIrr, X86_INS_MOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MOVZX16rm8, X86_INS_MOVZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVZX16rr8, X86_INS_MOVZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVZX32_NOREXrm8, X86_INS_MOVZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVZX32_NOREXrr8, X86_INS_MOVZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVZX32rm16, X86_INS_MOVZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVZX32rm8, X86_INS_MOVZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVZX32rr16, X86_INS_MOVZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVZX32rr8, X86_INS_MOVZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVZX64rm16_Q, X86_INS_MOVZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVZX64rm8_Q, X86_INS_MOVZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVZX64rr16_Q, X86_INS_MOVZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVZX64rr8_Q, X86_INS_MOVZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MPSADBWrmi, X86_INS_MPSADBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_MPSADBWrri, X86_INS_MPSADBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_MUL16m, X86_INS_MUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, 0 }, { X86_REG_AX, X86_REG_DX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MUL16r, X86_INS_MUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, 0 }, { X86_REG_AX, X86_REG_DX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MUL32m, X86_INS_MUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { X86_REG_EAX, X86_REG_EDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MUL32r, X86_INS_MUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { X86_REG_EAX, X86_REG_EDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MUL64m, X86_INS_MUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, 0 }, { X86_REG_RAX, X86_REG_RDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MUL64r, X86_INS_MUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, 0 }, { X86_REG_RAX, X86_REG_RDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MUL8m, X86_INS_MUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_AL, 0 }, { X86_REG_AL, X86_REG_EFLAGS, X86_REG_AX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MUL8r, X86_INS_MUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_AL, 0 }, { X86_REG_AL, X86_REG_EFLAGS, X86_REG_AX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MULPDrm, X86_INS_MULPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MULPDrr, X86_INS_MULPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MULPSrm, X86_INS_MULPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MULPSrr, X86_INS_MULPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MULSDrm, X86_INS_MULSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MULSDrm_Int, X86_INS_MULSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MULSDrr, X86_INS_MULSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MULSDrr_Int, X86_INS_MULSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_MULSSrm, X86_INS_MULSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MULSSrm_Int, X86_INS_MULSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MULSSrr, X86_INS_MULSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MULSSrr_Int, X86_INS_MULSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_MULX32rm, X86_INS_MULX,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDX, 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_MULX32rr, X86_INS_MULX,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDX, 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_MULX64rm, X86_INS_MULX,
#ifndef CAPSTONE_DIET
		{ X86_REG_RDX, 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_MULX64rr, X86_INS_MULX,
#ifndef CAPSTONE_DIET
		{ X86_REG_RDX, 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_MUL_F32m, X86_INS_FMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MUL_F64m, X86_INS_FMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MUL_FI16m, X86_INS_FIMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MUL_FI32m, X86_INS_FIMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MUL_FPrST0, X86_INS_FMULP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MUL_FST0r, X86_INS_FMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MUL_FrST0, X86_INS_FMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MWAITrr, X86_INS_MWAIT,
#ifndef CAPSTONE_DIET
		{ X86_REG_ECX, X86_REG_EAX, 0 }, { 0 }, { X86_GRP_SSE3, 0 }, 0, 0
#endif
	},
	{
		X86_NEG16m, X86_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NEG16r, X86_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NEG32m, X86_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NEG32r, X86_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NEG64m, X86_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NEG64r, X86_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NEG8m, X86_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NEG8r, X86_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_16m4, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_16m5, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_16m6, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_16m7, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_16r4, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_16r5, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_16r6, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_16r7, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_m4, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_m5, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_m6, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_m7, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_r4, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_r5, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_r6, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_r7, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP19rr, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPL, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPL_19, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPL_1a, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPL_1b, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPL_1c, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPL_1d, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPL_1e, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPW, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPW_19, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPW_1a, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPW_1b, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPW_1c, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPW_1d, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPW_1e, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOT16m, X86_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOT16r, X86_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOT32m, X86_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOT32r, X86_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOT64m, X86_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOT64r, X86_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOT8m, X86_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOT8r, X86_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR16i16, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR16mi, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR16mi8, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR16mr, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR16ri, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR16ri8, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR16rm, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR16rr, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR16rr_REV, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR32i32, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR32mi, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR32mi8, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR32mr, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR32mrLocked, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_OR32ri, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR32ri8, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR32rm, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR32rr, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR32rr_REV, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR64i32, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR64mi32, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR64mi8, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR64mr, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR64ri32, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR64ri8, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR64rm, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR64rr, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR64rr_REV, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR8i8, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR8mi, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR8mr, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR8ri, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR8ri8, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_OR8rm, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR8rr, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR8rr_REV, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ORPDrm, X86_INS_ORPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_ORPDrr, X86_INS_ORPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_ORPSrm, X86_INS_ORPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_ORPSrr, X86_INS_ORPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_OUT16ir, X86_INS_OUT,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OUT16rr, X86_INS_OUT,
#ifndef CAPSTONE_DIET
		{ X86_REG_DX, X86_REG_AX, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OUT32ir, X86_INS_OUT,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OUT32rr, X86_INS_OUT,
#ifndef CAPSTONE_DIET
		{ X86_REG_DX, X86_REG_EAX, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OUT8ir, X86_INS_OUT,
#ifndef CAPSTONE_DIET
		{ X86_REG_AL, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OUT8rr, X86_INS_OUT,
#ifndef CAPSTONE_DIET
		{ X86_REG_DX, X86_REG_AL, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OUTSB, X86_INS_OUTSB,
#ifndef CAPSTONE_DIET
		{ X86_REG_DX, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_ESI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OUTSL, X86_INS_OUTSD,
#ifndef CAPSTONE_DIET
		{ X86_REG_DX, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_ESI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OUTSW, X86_INS_OUTSW,
#ifndef CAPSTONE_DIET
		{ X86_REG_DX, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_ESI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_PABSBrm128, X86_INS_PABSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PABSBrr128, X86_INS_PABSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PABSDrm128, X86_INS_PABSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PABSDrr128, X86_INS_PABSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PABSWrm128, X86_INS_PABSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PABSWrr128, X86_INS_PABSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PACKSSDWrm, X86_INS_PACKSSDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PACKSSDWrr, X86_INS_PACKSSDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PACKSSWBrm, X86_INS_PACKSSWB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PACKSSWBrr, X86_INS_PACKSSWB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PACKUSDWrm, X86_INS_PACKUSDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PACKUSDWrr, X86_INS_PACKUSDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PACKUSWBrm, X86_INS_PACKUSWB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PACKUSWBrr, X86_INS_PACKUSWB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PADDBrm, X86_INS_PADDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PADDBrr, X86_INS_PADDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PADDDrm, X86_INS_PADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PADDDrr, X86_INS_PADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PADDQrm, X86_INS_PADDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PADDQrr, X86_INS_PADDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PADDSBrm, X86_INS_PADDSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PADDSBrr, X86_INS_PADDSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PADDSWrm, X86_INS_PADDSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PADDSWrr, X86_INS_PADDSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PADDUSBrm, X86_INS_PADDUSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PADDUSBrr, X86_INS_PADDUSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PADDUSWrm, X86_INS_PADDUSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PADDUSWrr, X86_INS_PADDUSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PADDWrm, X86_INS_PADDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PADDWrr, X86_INS_PADDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PALIGNR128rm, X86_INS_PALIGNR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PALIGNR128rr, X86_INS_PALIGNR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PANDNrm, X86_INS_PANDN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PANDNrr, X86_INS_PANDN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PANDrm, X86_INS_PAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PANDrr, X86_INS_PAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PAUSE, X86_INS_PAUSE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PAVGBrm, X86_INS_PAVGB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PAVGBrr, X86_INS_PAVGB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PAVGUSBrm, X86_INS_PAVGUSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PAVGUSBrr, X86_INS_PAVGUSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PAVGWrm, X86_INS_PAVGW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PAVGWrr, X86_INS_PAVGW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PBLENDVBrm0, X86_INS_PBLENDVB,
#ifndef CAPSTONE_DIET
		{ X86_REG_XMM0, 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PBLENDVBrr0, X86_INS_PBLENDVB,
#ifndef CAPSTONE_DIET
		{ X86_REG_XMM0, 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PBLENDWrmi, X86_INS_PBLENDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PBLENDWrri, X86_INS_PBLENDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PCLMULQDQrm, X86_INS_PCLMULQDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_PCLMUL, 0 }, 0, 0
#endif
	},
	{
		X86_PCLMULQDQrr, X86_INS_PCLMULQDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_PCLMUL, 0 }, 0, 0
#endif
	},
	{
		X86_PCMPEQBrm, X86_INS_PCMPEQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PCMPEQBrr, X86_INS_PCMPEQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PCMPEQDrm, X86_INS_PCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PCMPEQDrr, X86_INS_PCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PCMPEQQrm, X86_INS_PCMPEQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PCMPEQQrr, X86_INS_PCMPEQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PCMPEQWrm, X86_INS_PCMPEQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PCMPEQWrr, X86_INS_PCMPEQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PCMPESTRIrm, X86_INS_PCMPESTRI,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_EDX, 0 }, { X86_REG_ECX, X86_REG_EFLAGS, 0 }, { X86_GRP_SSE42, 0 }, 0, 0
#endif
	},
	{
		X86_PCMPESTRIrr, X86_INS_PCMPESTRI,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_EDX, 0 }, { X86_REG_ECX, X86_REG_EFLAGS, 0 }, { X86_GRP_SSE42, 0 }, 0, 0
#endif
	},
	{
		X86_PCMPESTRM128rm, X86_INS_PCMPESTRM,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_EDX, 0 }, { X86_REG_XMM0, X86_REG_EFLAGS, 0 }, { X86_GRP_SSE42, 0 }, 0, 0
#endif
	},
	{
		X86_PCMPESTRM128rr, X86_INS_PCMPESTRM,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_EDX, 0 }, { X86_REG_XMM0, X86_REG_EFLAGS, 0 }, { X86_GRP_SSE42, 0 }, 0, 0
#endif
	},
	{
		X86_PCMPGTBrm, X86_INS_PCMPGTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PCMPGTBrr, X86_INS_PCMPGTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PCMPGTDrm, X86_INS_PCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PCMPGTDrr, X86_INS_PCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PCMPGTQrm, X86_INS_PCMPGTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE42, 0 }, 0, 0
#endif
	},
	{
		X86_PCMPGTQrr, X86_INS_PCMPGTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE42, 0 }, 0, 0
#endif
	},
	{
		X86_PCMPGTWrm, X86_INS_PCMPGTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PCMPGTWrr, X86_INS_PCMPGTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PCMPISTRIrm, X86_INS_PCMPISTRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_ECX, X86_REG_EFLAGS, 0 }, { X86_GRP_SSE42, 0 }, 0, 0
#endif
	},
	{
		X86_PCMPISTRIrr, X86_INS_PCMPISTRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_ECX, X86_REG_EFLAGS, 0 }, { X86_GRP_SSE42, 0 }, 0, 0
#endif
	},
	{
		X86_PCMPISTRM128rm, X86_INS_PCMPISTRM,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_XMM0, X86_REG_EFLAGS, 0 }, { X86_GRP_SSE42, 0 }, 0, 0
#endif
	},
	{
		X86_PCMPISTRM128rr, X86_INS_PCMPISTRM,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_XMM0, X86_REG_EFLAGS, 0 }, { X86_GRP_SSE42, 0 }, 0, 0
#endif
	},
	{
		X86_PDEP32rm, X86_INS_PDEP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_PDEP32rr, X86_INS_PDEP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_PDEP64rm, X86_INS_PDEP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_PDEP64rr, X86_INS_PDEP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_PEXT32rm, X86_INS_PEXT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_PEXT32rr, X86_INS_PEXT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_PEXT64rm, X86_INS_PEXT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_PEXT64rr, X86_INS_PEXT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_PEXTRBmr, X86_INS_PEXTRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PEXTRBrr, X86_INS_PEXTRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PEXTRDmr, X86_INS_PEXTRD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PEXTRDrr, X86_INS_PEXTRD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PEXTRQmr, X86_INS_PEXTRQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PEXTRQrr, X86_INS_PEXTRQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PEXTRWmr, X86_INS_PEXTRW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PEXTRWri, X86_INS_PEXTRW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PEXTRWrr_REV, X86_INS_PEXTRW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PF2IDrm, X86_INS_PF2ID,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PF2IDrr, X86_INS_PF2ID,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PF2IWrm, X86_INS_PF2IW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PF2IWrr, X86_INS_PF2IW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFACCrm, X86_INS_PFACC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFACCrr, X86_INS_PFACC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFADDrm, X86_INS_PFADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFADDrr, X86_INS_PFADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFCMPEQrm, X86_INS_PFCMPEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFCMPEQrr, X86_INS_PFCMPEQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFCMPGErm, X86_INS_PFCMPGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFCMPGErr, X86_INS_PFCMPGE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFCMPGTrm, X86_INS_PFCMPGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFCMPGTrr, X86_INS_PFCMPGT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFMAXrm, X86_INS_PFMAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFMAXrr, X86_INS_PFMAX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFMINrm, X86_INS_PFMIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFMINrr, X86_INS_PFMIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFMULrm, X86_INS_PFMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFMULrr, X86_INS_PFMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFNACCrm, X86_INS_PFNACC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFNACCrr, X86_INS_PFNACC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFPNACCrm, X86_INS_PFPNACC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFPNACCrr, X86_INS_PFPNACC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFRCPIT1rm, X86_INS_PFRCPIT1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFRCPIT1rr, X86_INS_PFRCPIT1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFRCPIT2rm, X86_INS_PFRCPIT2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFRCPIT2rr, X86_INS_PFRCPIT2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFRCPrm, X86_INS_PFRCP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFRCPrr, X86_INS_PFRCP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFRSQIT1rm, X86_INS_PFRSQIT1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFRSQIT1rr, X86_INS_PFRSQIT1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFRSQRTrm, X86_INS_PFRSQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFRSQRTrr, X86_INS_PFRSQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFSUBRrm, X86_INS_PFSUBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFSUBRrr, X86_INS_PFSUBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFSUBrm, X86_INS_PFSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PFSUBrr, X86_INS_PFSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PHADDDrm, X86_INS_PHADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PHADDDrr, X86_INS_PHADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PHADDSWrm128, X86_INS_PHADDSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PHADDSWrr128, X86_INS_PHADDSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PHADDWrm, X86_INS_PHADDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PHADDWrr, X86_INS_PHADDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PHMINPOSUWrm128, X86_INS_PHMINPOSUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PHMINPOSUWrr128, X86_INS_PHMINPOSUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PHSUBDrm, X86_INS_PHSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PHSUBDrr, X86_INS_PHSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PHSUBSWrm128, X86_INS_PHSUBSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PHSUBSWrr128, X86_INS_PHSUBSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PHSUBWrm, X86_INS_PHSUBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PHSUBWrr, X86_INS_PHSUBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PI2FDrm, X86_INS_PI2FD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PI2FDrr, X86_INS_PI2FD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PI2FWrm, X86_INS_PI2FW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PI2FWrr, X86_INS_PI2FW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PINSRBrm, X86_INS_PINSRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PINSRBrr, X86_INS_PINSRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PINSRDrm, X86_INS_PINSRD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PINSRDrr, X86_INS_PINSRD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PINSRQrm, X86_INS_PINSRQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PINSRQrr, X86_INS_PINSRQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PINSRWrmi, X86_INS_PINSRW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PINSRWrri, X86_INS_PINSRW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PMADDUBSWrm128, X86_INS_PMADDUBSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PMADDUBSWrr128, X86_INS_PMADDUBSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PMADDWDrm, X86_INS_PMADDWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PMADDWDrr, X86_INS_PMADDWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PMAXSBrm, X86_INS_PMAXSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMAXSBrr, X86_INS_PMAXSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMAXSDrm, X86_INS_PMAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMAXSDrr, X86_INS_PMAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMAXSWrm, X86_INS_PMAXSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PMAXSWrr, X86_INS_PMAXSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PMAXUBrm, X86_INS_PMAXUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PMAXUBrr, X86_INS_PMAXUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PMAXUDrm, X86_INS_PMAXUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMAXUDrr, X86_INS_PMAXUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMAXUWrm, X86_INS_PMAXUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMAXUWrr, X86_INS_PMAXUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMINSBrm, X86_INS_PMINSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMINSBrr, X86_INS_PMINSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMINSDrm, X86_INS_PMINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMINSDrr, X86_INS_PMINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMINSWrm, X86_INS_PMINSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PMINSWrr, X86_INS_PMINSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PMINUBrm, X86_INS_PMINUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PMINUBrr, X86_INS_PMINUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PMINUDrm, X86_INS_PMINUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMINUDrr, X86_INS_PMINUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMINUWrm, X86_INS_PMINUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMINUWrr, X86_INS_PMINUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMOVMSKBrr, X86_INS_PMOVMSKB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PMOVSXBDrm, X86_INS_PMOVSXBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMOVSXBDrr, X86_INS_PMOVSXBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMOVSXBQrm, X86_INS_PMOVSXBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMOVSXBQrr, X86_INS_PMOVSXBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMOVSXBWrm, X86_INS_PMOVSXBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMOVSXBWrr, X86_INS_PMOVSXBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMOVSXDQrm, X86_INS_PMOVSXDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMOVSXDQrr, X86_INS_PMOVSXDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMOVSXWDrm, X86_INS_PMOVSXWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMOVSXWDrr, X86_INS_PMOVSXWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMOVSXWQrm, X86_INS_PMOVSXWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMOVSXWQrr, X86_INS_PMOVSXWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMOVZXBDrm, X86_INS_PMOVZXBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMOVZXBDrr, X86_INS_PMOVZXBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMOVZXBQrm, X86_INS_PMOVZXBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMOVZXBQrr, X86_INS_PMOVZXBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMOVZXBWrm, X86_INS_PMOVZXBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMOVZXBWrr, X86_INS_PMOVZXBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMOVZXDQrm, X86_INS_PMOVZXDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMOVZXDQrr, X86_INS_PMOVZXDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMOVZXWDrm, X86_INS_PMOVZXWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMOVZXWDrr, X86_INS_PMOVZXWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMOVZXWQrm, X86_INS_PMOVZXWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMOVZXWQrr, X86_INS_PMOVZXWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMULDQrm, X86_INS_PMULDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMULDQrr, X86_INS_PMULDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMULHRSWrm128, X86_INS_PMULHRSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PMULHRSWrr128, X86_INS_PMULHRSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PMULHRWrm, X86_INS_PMULHRW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PMULHRWrr, X86_INS_PMULHRW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PMULHUWrm, X86_INS_PMULHUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PMULHUWrr, X86_INS_PMULHUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PMULHWrm, X86_INS_PMULHW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PMULHWrr, X86_INS_PMULHW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PMULLDrm, X86_INS_PMULLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMULLDrr, X86_INS_PMULLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PMULLWrm, X86_INS_PMULLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PMULLWrr, X86_INS_PMULLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PMULUDQrm, X86_INS_PMULUDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PMULUDQrr, X86_INS_PMULUDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_POP16r, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_POP16rmm, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_POP16rmr, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_POP32r, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POP32rmm, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POP32rmr, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POP64r, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { X86_REG_RSP, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_POP64rmm, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { X86_REG_RSP, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_POP64rmr, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { X86_REG_RSP, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_POPA16, X86_INS_POPAW,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_EDI, X86_REG_ESI, X86_REG_EBP, X86_REG_EBX, X86_REG_EDX, X86_REG_ECX, X86_REG_EAX, X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POPA32, X86_INS_POPAL,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_EDI, X86_REG_ESI, X86_REG_EBP, X86_REG_EBX, X86_REG_EDX, X86_REG_ECX, X86_REG_EAX, X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POPCNT16rm, X86_INS_POPCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_POPCNT16rr, X86_INS_POPCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_POPCNT32rm, X86_INS_POPCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_POPCNT32rr, X86_INS_POPCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_POPCNT64rm, X86_INS_POPCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_POPCNT64rr, X86_INS_POPCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_POPDS16, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POPDS32, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POPES16, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POPES32, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POPF16, X86_INS_POPF,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_POPF32, X86_INS_POPFD,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POPF64, X86_INS_POPFQ,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { X86_REG_RSP, X86_REG_EFLAGS, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_POPFS16, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_POPFS32, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POPFS64, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_POPGS16, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_POPGS32, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POPGS64, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_POPSS16, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POPSS32, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PORrm, X86_INS_POR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PORrr, X86_INS_POR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PREFETCH, X86_INS_PREFETCH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PREFETCHNTA, X86_INS_PREFETCHNTA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_PREFETCHT0, X86_INS_PREFETCHT0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_PREFETCHT1, X86_INS_PREFETCHT1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_PREFETCHT2, X86_INS_PREFETCHT2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_PREFETCHW, X86_INS_PREFETCHW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_PSADBWrm, X86_INS_PSADBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSADBWrr, X86_INS_PSADBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSHUFBrm, X86_INS_PSHUFB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PSHUFBrr, X86_INS_PSHUFB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PSHUFDmi, X86_INS_PSHUFD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSHUFDri, X86_INS_PSHUFD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSHUFHWmi, X86_INS_PSHUFHW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSHUFHWri, X86_INS_PSHUFHW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSHUFLWmi, X86_INS_PSHUFLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSHUFLWri, X86_INS_PSHUFLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSIGNBrm, X86_INS_PSIGNB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PSIGNBrr, X86_INS_PSIGNB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PSIGNDrm, X86_INS_PSIGND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PSIGNDrr, X86_INS_PSIGND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PSIGNWrm, X86_INS_PSIGNW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PSIGNWrr, X86_INS_PSIGNW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSSE3, 0 }, 0, 0
#endif
	},
	{
		X86_PSLLDQri, X86_INS_PSLLDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSLLDri, X86_INS_PSLLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSLLDrm, X86_INS_PSLLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSLLDrr, X86_INS_PSLLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSLLQri, X86_INS_PSLLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSLLQrm, X86_INS_PSLLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSLLQrr, X86_INS_PSLLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSLLWri, X86_INS_PSLLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSLLWrm, X86_INS_PSLLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSLLWrr, X86_INS_PSLLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSRADri, X86_INS_PSRAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSRADrm, X86_INS_PSRAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSRADrr, X86_INS_PSRAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSRAWri, X86_INS_PSRAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSRAWrm, X86_INS_PSRAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSRAWrr, X86_INS_PSRAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSRLDQri, X86_INS_PSRLDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSRLDri, X86_INS_PSRLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSRLDrm, X86_INS_PSRLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSRLDrr, X86_INS_PSRLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSRLQri, X86_INS_PSRLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSRLQrm, X86_INS_PSRLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSRLQrr, X86_INS_PSRLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSRLWri, X86_INS_PSRLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSRLWrm, X86_INS_PSRLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSRLWrr, X86_INS_PSRLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSUBBrm, X86_INS_PSUBB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSUBBrr, X86_INS_PSUBB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSUBDrm, X86_INS_PSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSUBDrr, X86_INS_PSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSUBQrm, X86_INS_PSUBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSUBQrr, X86_INS_PSUBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSUBSBrm, X86_INS_PSUBSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSUBSBrr, X86_INS_PSUBSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSUBSWrm, X86_INS_PSUBSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSUBSWrr, X86_INS_PSUBSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSUBUSBrm, X86_INS_PSUBUSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSUBUSBrr, X86_INS_PSUBUSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSUBUSWrm, X86_INS_PSUBUSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSUBUSWrr, X86_INS_PSUBUSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSUBWrm, X86_INS_PSUBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSUBWrr, X86_INS_PSUBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PSWAPDrm, X86_INS_PSWAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PSWAPDrr, X86_INS_PSWAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_3DNOW, 0 }, 0, 0
#endif
	},
	{
		X86_PTESTrm, X86_INS_PTEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PTESTrr, X86_INS_PTEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_PUNPCKHBWrm, X86_INS_PUNPCKHBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PUNPCKHBWrr, X86_INS_PUNPCKHBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PUNPCKHDQrm, X86_INS_PUNPCKHDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PUNPCKHDQrr, X86_INS_PUNPCKHDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PUNPCKHQDQrm, X86_INS_PUNPCKHQDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PUNPCKHQDQrr, X86_INS_PUNPCKHQDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PUNPCKHWDrm, X86_INS_PUNPCKHWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PUNPCKHWDrr, X86_INS_PUNPCKHWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PUNPCKLBWrm, X86_INS_PUNPCKLBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PUNPCKLBWrr, X86_INS_PUNPCKLBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PUNPCKLDQrm, X86_INS_PUNPCKLDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PUNPCKLDQrr, X86_INS_PUNPCKLDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PUNPCKLQDQrm, X86_INS_PUNPCKLQDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PUNPCKLQDQrr, X86_INS_PUNPCKLQDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PUNPCKLWDrm, X86_INS_PUNPCKLWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PUNPCKLWDrr, X86_INS_PUNPCKLWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PUSH16i8, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSH16r, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_PUSH16rmm, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_PUSH16rmr, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_PUSH32i8, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSH32r, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSH32rmm, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSH32rmr, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSH64i16, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { X86_REG_RSP, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_PUSH64i32, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { X86_REG_RSP, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_PUSH64i8, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { X86_REG_RSP, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_PUSH64r, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { X86_REG_RSP, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_PUSH64rmm, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { X86_REG_RSP, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_PUSH64rmr, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { X86_REG_RSP, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHA16, X86_INS_PUSHAW,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDI, X86_REG_ESI, X86_REG_EBP, X86_REG_EBX, X86_REG_EDX, X86_REG_ECX, X86_REG_EAX, X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHA32, X86_INS_PUSHAL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDI, X86_REG_ESI, X86_REG_EBP, X86_REG_EBX, X86_REG_EDX, X86_REG_ECX, X86_REG_EAX, X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHCS16, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHCS32, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHDS16, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHDS32, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHES16, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHES32, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHF16, X86_INS_PUSHF,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_PUSHF32, X86_INS_PUSHFD,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHF64, X86_INS_PUSHFQ,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, X86_REG_EFLAGS, 0 }, { X86_REG_RSP, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHFS16, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_PUSHFS32, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHFS64, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHGS16, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_PUSHGS32, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHGS64, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHSS16, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHSS32, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHi16, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHi32, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PXORrm, X86_INS_PXOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_PXORrr, X86_INS_PXOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_RCL16m1, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL16mCL, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL16mi, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL16r1, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL16rCL, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL16ri, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL32m1, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL32mCL, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL32mi, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL32r1, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL32rCL, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL32ri, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL64m1, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL64mCL, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL64mi, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL64r1, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL64rCL, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL64ri, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL8m1, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL8mCL, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL8mi, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL8r1, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL8rCL, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL8ri, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCPPSm, X86_INS_RCPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_RCPPSm_Int, X86_INS_RCPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_RCPPSr, X86_INS_RCPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_RCPPSr_Int, X86_INS_RCPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_RCPSSm, X86_INS_RCPSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_RCPSSm_Int, X86_INS_RCPSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_RCPSSr, X86_INS_RCPSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_RCPSSr_Int, X86_INS_RCPSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_RCR16m1, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR16mCL, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR16mi, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR16r1, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR16rCL, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR16ri, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR32m1, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR32mCL, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR32mi, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR32r1, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR32rCL, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR32ri, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR64m1, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR64mCL, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR64mi, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR64r1, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR64rCL, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR64ri, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR8m1, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR8mCL, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR8mi, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR8r1, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR8rCL, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR8ri, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RDFSBASE, X86_INS_RDFSBASE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FSGSBASE, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_RDFSBASE64, X86_INS_RDFSBASE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FSGSBASE, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_RDGSBASE, X86_INS_RDGSBASE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FSGSBASE, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_RDGSBASE64, X86_INS_RDGSBASE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FSGSBASE, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_RDMSR, X86_INS_RDMSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RDPMC, X86_INS_RDPMC,
#ifndef CAPSTONE_DIET
		{ X86_REG_ECX, 0 }, { X86_REG_RAX, X86_REG_RDX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RDRAND16r, X86_INS_RDRAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RDRAND32r, X86_INS_RDRAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RDRAND64r, X86_INS_RDRAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RDSEED16r, X86_INS_RDSEED,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RDSEED32r, X86_INS_RDSEED,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RDSEED64r, X86_INS_RDSEED,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RDTSC, X86_INS_RDTSC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_RAX, X86_REG_RDX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RDTSCP, X86_INS_RDTSCP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RETIL, X86_INS_RET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RET, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_RETIQ, X86_INS_RET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RET, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_RETIW, X86_INS_RET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RET, 0 }, 0, 0
#endif
	},
	{
		X86_RETL, X86_INS_RET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RET, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_RETQ, X86_INS_RET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RET, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_RETW, X86_INS_RET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RET, 0 }, 0, 0
#endif
	},
	{
		X86_ROL16m1, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL16mCL, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL16mi, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL16r1, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL16rCL, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL16ri, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL32m1, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL32mCL, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL32mi, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL32r1, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL32rCL, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL32ri, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL64m1, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL64mCL, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL64mi, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL64r1, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL64rCL, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL64ri, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL8m1, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL8mCL, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL8mi, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL8r1, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL8rCL, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL8ri, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR16m1, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR16mCL, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR16mi, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR16r1, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR16rCL, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR16ri, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR32m1, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR32mCL, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR32mi, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR32r1, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR32rCL, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR32ri, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR64m1, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR64mCL, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR64mi, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR64r1, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR64rCL, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR64ri, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR8m1, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR8mCL, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR8mi, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR8r1, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR8rCL, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR8ri, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RORX32mi, X86_INS_RORX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_RORX32ri, X86_INS_RORX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_RORX64mi, X86_INS_RORX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_RORX64ri, X86_INS_RORX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_ROUNDPDm, X86_INS_ROUNDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_ROUNDPDr, X86_INS_ROUNDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_ROUNDPSm, X86_INS_ROUNDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_ROUNDPSr, X86_INS_ROUNDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_ROUNDSDm, X86_INS_ROUNDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_ROUNDSDr, X86_INS_ROUNDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_ROUNDSDr_Int, X86_INS_ROUNDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_ROUNDSSm, X86_INS_ROUNDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_ROUNDSSr, X86_INS_ROUNDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_ROUNDSSr_Int, X86_INS_ROUNDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE41, 0 }, 0, 0
#endif
	},
	{
		X86_RSM, X86_INS_RSM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RSQRTPSm, X86_INS_RSQRTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_RSQRTPSm_Int, X86_INS_RSQRTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_RSQRTPSr, X86_INS_RSQRTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_RSQRTPSr_Int, X86_INS_RSQRTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_RSQRTSSm, X86_INS_RSQRTSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_RSQRTSSm_Int, X86_INS_RSQRTSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_RSQRTSSr, X86_INS_RSQRTSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_RSQRTSSr_Int, X86_INS_RSQRTSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_SAHF, X86_INS_SAHF,
#ifndef CAPSTONE_DIET
		{ X86_REG_AH, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL16m1, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL16mCL, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL16mi, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL16r1, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL16rCL, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL16ri, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL32m1, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL32mCL, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL32mi, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL32r1, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL32rCL, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL32ri, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL64m1, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL64mCL, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL64mi, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL64r1, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL64rCL, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL64ri, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL8m1, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL8mCL, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL8mi, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL8r1, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL8rCL, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL8ri, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SALC, X86_INS_SALC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_AL, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_SAR16m1, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR16mCL, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR16mi, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR16r1, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR16rCL, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR16ri, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR32m1, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR32mCL, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR32mi, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR32r1, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR32rCL, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR32ri, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR64m1, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR64mCL, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR64mi, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR64r1, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR64rCL, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR64ri, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR8m1, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR8mCL, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR8mi, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR8r1, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR8rCL, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR8ri, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SARX32rm, X86_INS_SARX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_SARX32rr, X86_INS_SARX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_SARX64rm, X86_INS_SARX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_SARX64rr, X86_INS_SARX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_SBB16i16, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB16mi, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB16mi8, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB16mr, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB16ri, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB16ri8, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB16rm, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB16rr, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB16rr_REV, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB32i32, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB32mi, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB32mi8, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB32mr, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB32ri, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB32ri8, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB32rm, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB32rr, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB32rr_REV, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB64i32, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB64mi32, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB64mi8, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB64mr, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB64ri32, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB64ri8, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB64rm, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB64rr, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB64rr_REV, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB8i8, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB8mi, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB8mr, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB8ri, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB8rm, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB8rr, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB8rr_REV, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SCASB, X86_INS_SCASB,
#ifndef CAPSTONE_DIET
		{ X86_REG_AL, X86_REG_EDI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SCASL, X86_INS_SCASD,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_EDI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SCASQ, X86_INS_SCASQ,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_EDI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SCASW, X86_INS_SCASW,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, X86_REG_EDI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETAEm, X86_INS_SETAE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETAEr, X86_INS_SETAE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETAm, X86_INS_SETA,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETAr, X86_INS_SETA,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETBEm, X86_INS_SETBE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETBEr, X86_INS_SETBE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETBm, X86_INS_SETB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETBr, X86_INS_SETB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETEm, X86_INS_SETE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETEr, X86_INS_SETE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETGEm, X86_INS_SETGE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETGEr, X86_INS_SETGE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETGm, X86_INS_SETG,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETGr, X86_INS_SETG,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETLEm, X86_INS_SETLE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETLEr, X86_INS_SETLE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETLm, X86_INS_SETL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETLr, X86_INS_SETL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETNEm, X86_INS_SETNE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETNEr, X86_INS_SETNE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETNOm, X86_INS_SETNO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETNOr, X86_INS_SETNO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETNPm, X86_INS_SETNP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETNPr, X86_INS_SETNP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETNSm, X86_INS_SETNS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETNSr, X86_INS_SETNS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETOm, X86_INS_SETO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETOr, X86_INS_SETO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETPm, X86_INS_SETP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETPr, X86_INS_SETP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETSm, X86_INS_SETS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETSr, X86_INS_SETS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SFENCE, X86_INS_SFENCE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_SGDT16m, X86_INS_SGDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_SGDT32m, X86_INS_SGDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_SGDT64m, X86_INS_SGDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_SHA1MSG1rm, X86_INS_SHA1MSG1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SHA, 0 }, 0, 0
#endif
	},
	{
		X86_SHA1MSG1rr, X86_INS_SHA1MSG1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SHA, 0 }, 0, 0
#endif
	},
	{
		X86_SHA1MSG2rm, X86_INS_SHA1MSG2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SHA, 0 }, 0, 0
#endif
	},
	{
		X86_SHA1MSG2rr, X86_INS_SHA1MSG2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SHA, 0 }, 0, 0
#endif
	},
	{
		X86_SHA1NEXTErm, X86_INS_SHA1NEXTE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SHA, 0 }, 0, 0
#endif
	},
	{
		X86_SHA1NEXTErr, X86_INS_SHA1NEXTE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SHA, 0 }, 0, 0
#endif
	},
	{
		X86_SHA1RNDS4rmi, X86_INS_SHA1RNDS4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SHA, 0 }, 0, 0
#endif
	},
	{
		X86_SHA1RNDS4rri, X86_INS_SHA1RNDS4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SHA, 0 }, 0, 0
#endif
	},
	{
		X86_SHA256MSG1rm, X86_INS_SHA256MSG1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SHA, 0 }, 0, 0
#endif
	},
	{
		X86_SHA256MSG1rr, X86_INS_SHA256MSG1,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SHA, 0 }, 0, 0
#endif
	},
	{
		X86_SHA256MSG2rm, X86_INS_SHA256MSG2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SHA, 0 }, 0, 0
#endif
	},
	{
		X86_SHA256MSG2rr, X86_INS_SHA256MSG2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SHA, 0 }, 0, 0
#endif
	},
	{
		X86_SHA256RNDS2rm, X86_INS_SHA256RNDS2,
#ifndef CAPSTONE_DIET
		{ X86_REG_XMM0, 0 }, { 0 }, { X86_GRP_SHA, 0 }, 0, 0
#endif
	},
	{
		X86_SHA256RNDS2rr, X86_INS_SHA256RNDS2,
#ifndef CAPSTONE_DIET
		{ X86_REG_XMM0, 0 }, { 0 }, { X86_GRP_SHA, 0 }, 0, 0
#endif
	},
	{
		X86_SHL16m1, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL16mCL, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL16mi, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL16r1, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL16rCL, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL16ri, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL32m1, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL32mCL, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL32mi, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL32r1, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL32rCL, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL32ri, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL64m1, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL64mCL, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL64mi, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL64r1, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL64rCL, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL64ri, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL8m1, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL8mCL, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL8mi, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL8r1, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL8rCL, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL8ri, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLD16mrCL, X86_INS_SHLD,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLD16mri8, X86_INS_SHLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLD16rrCL, X86_INS_SHLD,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLD16rri8, X86_INS_SHLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLD32mrCL, X86_INS_SHLD,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLD32mri8, X86_INS_SHLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLD32rrCL, X86_INS_SHLD,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLD32rri8, X86_INS_SHLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLD64mrCL, X86_INS_SHLD,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLD64mri8, X86_INS_SHLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLD64rrCL, X86_INS_SHLD,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLD64rri8, X86_INS_SHLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLX32rm, X86_INS_SHLX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_SHLX32rr, X86_INS_SHLX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_SHLX64rm, X86_INS_SHLX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_SHLX64rr, X86_INS_SHLX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_SHR16m1, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR16mCL, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR16mi, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR16r1, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR16rCL, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR16ri, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR32m1, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR32mCL, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR32mi, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR32r1, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR32rCL, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR32ri, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR64m1, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR64mCL, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR64mi, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR64r1, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR64rCL, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR64ri, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR8m1, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR8mCL, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR8mi, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR8r1, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR8rCL, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR8ri, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRD16mrCL, X86_INS_SHRD,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRD16mri8, X86_INS_SHRD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRD16rrCL, X86_INS_SHRD,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRD16rri8, X86_INS_SHRD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRD32mrCL, X86_INS_SHRD,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRD32mri8, X86_INS_SHRD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRD32rrCL, X86_INS_SHRD,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRD32rri8, X86_INS_SHRD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRD64mrCL, X86_INS_SHRD,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRD64mri8, X86_INS_SHRD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRD64rrCL, X86_INS_SHRD,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRD64rri8, X86_INS_SHRD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRX32rm, X86_INS_SHRX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_SHRX32rr, X86_INS_SHRX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_SHRX64rm, X86_INS_SHRX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_SHRX64rr, X86_INS_SHRX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_SHUFPDrmi, X86_INS_SHUFPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_SHUFPDrri, X86_INS_SHUFPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_SHUFPSrmi, X86_INS_SHUFPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_SHUFPSrri, X86_INS_SHUFPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_SIDT16m, X86_INS_SIDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_SIDT32m, X86_INS_SIDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_SIDT64m, X86_INS_SIDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_SIN_F, X86_INS_FSIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SKINIT, X86_INS_SKINIT,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_SLDT16m, X86_INS_SLDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SLDT16r, X86_INS_SLDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SLDT32r, X86_INS_SLDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SLDT64m, X86_INS_SLDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SLDT64r, X86_INS_SLDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SMSW16m, X86_INS_SMSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SMSW16r, X86_INS_SMSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SMSW32r, X86_INS_SMSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SMSW64r, X86_INS_SMSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SQRTPDm, X86_INS_SQRTPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_SQRTPDr, X86_INS_SQRTPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_SQRTPSm, X86_INS_SQRTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_SQRTPSr, X86_INS_SQRTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_SQRTSDm, X86_INS_SQRTSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_SQRTSDm_Int, X86_INS_SQRTSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_SQRTSDr, X86_INS_SQRTSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_SQRTSDr_Int, X86_INS_SQRTSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_SQRTSSm, X86_INS_SQRTSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_SQRTSSm_Int, X86_INS_SQRTSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_SQRTSSr, X86_INS_SQRTSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_SQRTSSr_Int, X86_INS_SQRTSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_SQRT_F, X86_INS_FSQRT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_STAC, X86_INS_STAC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_SMAP, 0 }, 0, 0
#endif
	},
	{
		X86_STC, X86_INS_STC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_STD, X86_INS_STD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_STGI, X86_INS_STGI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_STI, X86_INS_STI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_STMXCSR, X86_INS_STMXCSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_STOSB, X86_INS_STOSB,
#ifndef CAPSTONE_DIET
		{ X86_REG_AL, X86_REG_EDI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_STOSL, X86_INS_STOSD,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_EDI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_STOSQ, X86_INS_STOSQ,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_RCX, X86_REG_RDI, X86_REG_EFLAGS, 0 }, { X86_REG_RCX, X86_REG_RDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_STOSW, X86_INS_STOSW,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, X86_REG_EDI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_STR16r, X86_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_STR32r, X86_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_STR64r, X86_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_STRm, X86_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ST_F32m, X86_INS_FST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ST_F64m, X86_INS_FST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ST_FCOMPST0r, X86_INS_FCOMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ST_FCOMPST0r_alt, X86_INS_FCOMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ST_FCOMST0r, X86_INS_FCOM,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ST_FP32m, X86_INS_FSTP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ST_FP64m, X86_INS_FSTP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ST_FP80m, X86_INS_FSTP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ST_FPNCEST0r, X86_INS_FSTPNCE,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ST_FPST0r, X86_INS_FSTP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ST_FPST0r_alt, X86_INS_FSTP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ST_FPrr, X86_INS_FSTP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ST_FXCHST0r, X86_INS_FXCH,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ST_FXCHST0r_alt, X86_INS_FXCH,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ST_Frr, X86_INS_FST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB16i16, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB16mi, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB16mi8, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB16mr, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB16ri, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB16ri8, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB16rm, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB16rr, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB16rr_REV, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB32i32, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB32mi, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB32mi8, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB32mr, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB32ri, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB32ri8, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB32rm, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB32rr, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB32rr_REV, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB64i32, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB64mi32, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB64mi8, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB64mr, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB64ri32, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB64ri8, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB64rm, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB64rr, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB64rr_REV, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB8i8, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB8mi, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB8mr, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB8ri, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB8ri8, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_SUB8rm, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB8rr, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB8rr_REV, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUBPDrm, X86_INS_SUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_SUBPDrr, X86_INS_SUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_SUBPSrm, X86_INS_SUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_SUBPSrr, X86_INS_SUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_SUBR_F32m, X86_INS_FSUBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUBR_F64m, X86_INS_FSUBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUBR_FI16m, X86_INS_FISUBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUBR_FI32m, X86_INS_FISUBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUBR_FPrST0, X86_INS_FSUBRP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUBR_FST0r, X86_INS_FSUBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUBR_FrST0, X86_INS_FSUBR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUBSDrm, X86_INS_SUBSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_SUBSDrm_Int, X86_INS_SUBSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_SUBSDrr, X86_INS_SUBSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_SUBSDrr_Int, X86_INS_SUBSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_SUBSSrm, X86_INS_SUBSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_SUBSSrm_Int, X86_INS_SUBSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_SUBSSrr, X86_INS_SUBSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_SUBSSrr_Int, X86_INS_SUBSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_SUB_F32m, X86_INS_FSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB_F64m, X86_INS_FSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB_FI16m, X86_INS_FISUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB_FI32m, X86_INS_FISUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB_FPrST0, X86_INS_FSUBP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB_FST0r, X86_INS_FSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB_FrST0, X86_INS_FSUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SWAPGS, X86_INS_SWAPGS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SYSCALL, X86_INS_SYSCALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_INT, 0 }, 0, 0
#endif
	},
	{
		X86_SYSENTER, X86_INS_SYSENTER,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_INT, 0 }, 0, 0
#endif
	},
	{
		X86_SYSEXIT, X86_INS_SYSEXIT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_IRET, 0 }, 0, 0
#endif
	},
	{
		X86_SYSEXIT64, X86_INS_SYSEXIT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_IRET, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_SYSRET, X86_INS_SYSRET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_IRET, 0 }, 0, 0
#endif
	},
	{
		X86_SYSRET64, X86_INS_SYSRET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_IRET, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_T1MSKC32rm, X86_INS_T1MSKC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_T1MSKC32rr, X86_INS_T1MSKC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_T1MSKC64rm, X86_INS_T1MSKC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_T1MSKC64rr, X86_INS_T1MSKC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_TEST16i16, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST16mi, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST16mi_alt, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST16ri, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST16ri_alt, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST16rm, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST16rr, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST32i32, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST32mi, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST32mi_alt, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST32ri, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST32ri_alt, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST32rm, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST32rr, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST64i32, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST64mi32, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST64mi32_alt, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST64ri32, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST64ri32_alt, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST64rm, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST64rr, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST8i8, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST8mi, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST8mi_alt, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST8ri, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST8ri_alt, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST8rm, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST8rr, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TRAP, X86_INS_UD2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TST_F, X86_INS_FTST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TZCNT16rm, X86_INS_TZCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_TZCNT16rr, X86_INS_TZCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_TZCNT32rm, X86_INS_TZCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_TZCNT32rr, X86_INS_TZCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_TZCNT64rm, X86_INS_TZCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_TZCNT64rr, X86_INS_TZCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_TZMSK32rm, X86_INS_TZMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_TZMSK32rr, X86_INS_TZMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_TZMSK64rm, X86_INS_TZMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_TZMSK64rr, X86_INS_TZMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_UCOMISDrm, X86_INS_UCOMISD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_UCOMISDrr, X86_INS_UCOMISD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_UCOMISSrm, X86_INS_UCOMISS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_UCOMISSrr, X86_INS_UCOMISS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_UCOM_FIPr, X86_INS_FUCOMPI,
#ifndef CAPSTONE_DIET
		{ X86_REG_ST0, 0 }, { X86_REG_EFLAGS, X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_UCOM_FIr, X86_INS_FUCOMI,
#ifndef CAPSTONE_DIET
		{ X86_REG_ST0, 0 }, { X86_REG_EFLAGS, X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_UCOM_FPPr, X86_INS_FUCOMPP,
#ifndef CAPSTONE_DIET
		{ X86_REG_ST0, 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_UCOM_FPr, X86_INS_FUCOMP,
#ifndef CAPSTONE_DIET
		{ X86_REG_ST0, 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_UCOM_Fr, X86_INS_FUCOM,
#ifndef CAPSTONE_DIET
		{ X86_REG_ST0, 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_UD2B, X86_INS_UD2B,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_UNPCKHPDrm, X86_INS_UNPCKHPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_UNPCKHPDrr, X86_INS_UNPCKHPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_UNPCKHPSrm, X86_INS_UNPCKHPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_UNPCKHPSrr, X86_INS_UNPCKHPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_UNPCKLPDrm, X86_INS_UNPCKLPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_UNPCKLPDrr, X86_INS_UNPCKLPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_UNPCKLPSrm, X86_INS_UNPCKLPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_UNPCKLPSrr, X86_INS_UNPCKLPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPDYrm, X86_INS_VADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPDYrr, X86_INS_VADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPDZrm, X86_INS_VADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPDZrmb, X86_INS_VADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPDZrmbk, X86_INS_VADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPDZrmbkz, X86_INS_VADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPDZrmk, X86_INS_VADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPDZrmkz, X86_INS_VADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPDZrr, X86_INS_VADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPDZrrk, X86_INS_VADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPDZrrkz, X86_INS_VADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPDrm, X86_INS_VADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPDrr, X86_INS_VADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPSYrm, X86_INS_VADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPSYrr, X86_INS_VADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPSZrm, X86_INS_VADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPSZrmb, X86_INS_VADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPSZrmbk, X86_INS_VADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPSZrmbkz, X86_INS_VADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPSZrmk, X86_INS_VADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPSZrmkz, X86_INS_VADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPSZrr, X86_INS_VADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPSZrrk, X86_INS_VADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPSZrrkz, X86_INS_VADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPSrm, X86_INS_VADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VADDPSrr, X86_INS_VADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VADDSDZrm, X86_INS_VADDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VADDSDZrr, X86_INS_VADDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VADDSDrm, X86_INS_VADDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VADDSDrm_Int, X86_INS_VADDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VADDSDrr, X86_INS_VADDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VADDSDrr_Int, X86_INS_VADDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VADDSSZrm, X86_INS_VADDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VADDSSZrr, X86_INS_VADDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VADDSSrm, X86_INS_VADDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VADDSSrm_Int, X86_INS_VADDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VADDSSrr, X86_INS_VADDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VADDSSrr_Int, X86_INS_VADDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VADDSUBPDYrm, X86_INS_VADDSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VADDSUBPDYrr, X86_INS_VADDSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VADDSUBPDrm, X86_INS_VADDSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VADDSUBPDrr, X86_INS_VADDSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VADDSUBPSYrm, X86_INS_VADDSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VADDSUBPSYrr, X86_INS_VADDSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VADDSUBPSrm, X86_INS_VADDSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VADDSUBPSrr, X86_INS_VADDSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VAESDECLASTrm, X86_INS_VAESDECLAST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, X86_GRP_AES, 0 }, 0, 0
#endif
	},
	{
		X86_VAESDECLASTrr, X86_INS_VAESDECLAST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, X86_GRP_AES, 0 }, 0, 0
#endif
	},
	{
		X86_VAESDECrm, X86_INS_VAESDEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, X86_GRP_AES, 0 }, 0, 0
#endif
	},
	{
		X86_VAESDECrr, X86_INS_VAESDEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, X86_GRP_AES, 0 }, 0, 0
#endif
	},
	{
		X86_VAESENCLASTrm, X86_INS_VAESENCLAST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, X86_GRP_AES, 0 }, 0, 0
#endif
	},
	{
		X86_VAESENCLASTrr, X86_INS_VAESENCLAST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, X86_GRP_AES, 0 }, 0, 0
#endif
	},
	{
		X86_VAESENCrm, X86_INS_VAESENC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, X86_GRP_AES, 0 }, 0, 0
#endif
	},
	{
		X86_VAESENCrr, X86_INS_VAESENC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, X86_GRP_AES, 0 }, 0, 0
#endif
	},
	{
		X86_VAESIMCrm, X86_INS_VAESIMC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, X86_GRP_AES, 0 }, 0, 0
#endif
	},
	{
		X86_VAESIMCrr, X86_INS_VAESIMC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, X86_GRP_AES, 0 }, 0, 0
#endif
	},
	{
		X86_VAESKEYGENASSIST128rm, X86_INS_VAESKEYGENASSIST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, X86_GRP_AES, 0 }, 0, 0
#endif
	},
	{
		X86_VAESKEYGENASSIST128rr, X86_INS_VAESKEYGENASSIST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, X86_GRP_AES, 0 }, 0, 0
#endif
	},
	{
		X86_VALIGNDrmi, X86_INS_VALIGND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VALIGNDrri, X86_INS_VALIGND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VALIGNDrrik, X86_INS_VALIGND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VALIGNDrrikz, X86_INS_VALIGND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VALIGNQrmi, X86_INS_VALIGNQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VALIGNQrri, X86_INS_VALIGNQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VALIGNQrrik, X86_INS_VALIGNQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VALIGNQrrikz, X86_INS_VALIGNQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VANDNPDYrm, X86_INS_VANDNPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VANDNPDYrr, X86_INS_VANDNPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VANDNPDrm, X86_INS_VANDNPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VANDNPDrr, X86_INS_VANDNPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VANDNPSYrm, X86_INS_VANDNPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VANDNPSYrr, X86_INS_VANDNPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VANDNPSrm, X86_INS_VANDNPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VANDNPSrr, X86_INS_VANDNPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VANDPDYrm, X86_INS_VANDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VANDPDYrr, X86_INS_VANDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VANDPDrm, X86_INS_VANDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VANDPDrr, X86_INS_VANDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VANDPSYrm, X86_INS_VANDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VANDPSYrr, X86_INS_VANDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VANDPSrm, X86_INS_VANDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VANDPSrr, X86_INS_VANDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VBLENDMPDZrm, X86_INS_VBLENDMPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VBLENDMPDZrr, X86_INS_VBLENDMPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VBLENDMPSZrm, X86_INS_VBLENDMPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VBLENDMPSZrr, X86_INS_VBLENDMPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VBLENDPDYrmi, X86_INS_VBLENDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VBLENDPDYrri, X86_INS_VBLENDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VBLENDPDrmi, X86_INS_VBLENDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VBLENDPDrri, X86_INS_VBLENDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VBLENDPSYrmi, X86_INS_VBLENDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VBLENDPSYrri, X86_INS_VBLENDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VBLENDPSrmi, X86_INS_VBLENDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VBLENDPSrri, X86_INS_VBLENDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VBLENDVPDYrm, X86_INS_VBLENDVPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VBLENDVPDYrr, X86_INS_VBLENDVPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VBLENDVPDrm, X86_INS_VBLENDVPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VBLENDVPDrr, X86_INS_VBLENDVPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VBLENDVPSYrm, X86_INS_VBLENDVPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VBLENDVPSYrr, X86_INS_VBLENDVPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VBLENDVPSrm, X86_INS_VBLENDVPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VBLENDVPSrr, X86_INS_VBLENDVPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VBROADCASTF128, X86_INS_VBROADCASTF128,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VBROADCASTI128, X86_INS_VBROADCASTI128,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VBROADCASTI32X4krm, X86_INS_VBROADCASTI32X4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VBROADCASTI32X4rm, X86_INS_VBROADCASTI32X4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VBROADCASTI64X4krm, X86_INS_VBROADCASTI64X4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VBROADCASTI64X4rm, X86_INS_VBROADCASTI64X4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VBROADCASTSDYrm, X86_INS_VBROADCASTSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VBROADCASTSDYrr, X86_INS_VBROADCASTSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VBROADCASTSDZrm, X86_INS_VBROADCASTSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VBROADCASTSDZrr, X86_INS_VBROADCASTSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VBROADCASTSSYrm, X86_INS_VBROADCASTSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VBROADCASTSSYrr, X86_INS_VBROADCASTSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VBROADCASTSSZrm, X86_INS_VBROADCASTSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VBROADCASTSSZrr, X86_INS_VBROADCASTSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VBROADCASTSSrm, X86_INS_VBROADCASTSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VBROADCASTSSrr, X86_INS_VBROADCASTSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPDYrmi, X86_INS_VCMPPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPDYrmi_alt, X86_INS_VCMPPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPDYrri, X86_INS_VCMPPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPDYrri_alt, X86_INS_VCMPPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPDZrmi, X86_INS_VCMPPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPDZrmi_alt, X86_INS_VCMPPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPDZrri, X86_INS_VCMPPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPDZrri_alt, X86_INS_VCMPPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPDZrrib, X86_INS_VCMPPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPDrmi, X86_INS_VCMPPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPDrmi_alt, X86_INS_VCMPPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPDrri, X86_INS_VCMPPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPDrri_alt, X86_INS_VCMPPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPSYrmi, X86_INS_VCMPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPSYrmi_alt, X86_INS_VCMPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPSYrri, X86_INS_VCMPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPSYrri_alt, X86_INS_VCMPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPSZrmi, X86_INS_VCMPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPSZrmi_alt, X86_INS_VCMPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPSZrri, X86_INS_VCMPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPSZrri_alt, X86_INS_VCMPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPSZrrib, X86_INS_VCMPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPSrmi, X86_INS_VCMPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPSrmi_alt, X86_INS_VCMPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPSrri, X86_INS_VCMPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPPSrri_alt, X86_INS_VCMPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPSDZrm, X86_INS_VCMPSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPSDZrmi_alt, X86_INS_VCMPSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPSDZrr, X86_INS_VCMPSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPSDZrri_alt, X86_INS_VCMPSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPSDrm, X86_INS_VCMPSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPSDrm_alt, X86_INS_VCMPSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPSDrr, X86_INS_VCMPSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPSDrr_alt, X86_INS_VCMPSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPSSZrm, X86_INS_VCMPSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPSSZrmi_alt, X86_INS_VCMPSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPSSZrr, X86_INS_VCMPSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPSSZrri_alt, X86_INS_VCMPSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPSSrm, X86_INS_VCMPSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPSSrm_alt, X86_INS_VCMPSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPSSrr, X86_INS_VCMPSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCMPSSrr_alt, X86_INS_VCMPSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCOMISDZrm, X86_INS_VCOMISD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCOMISDZrr, X86_INS_VCOMISD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCOMISDrm, X86_INS_VCOMISD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCOMISDrr, X86_INS_VCOMISD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCOMISSZrm, X86_INS_VCOMISS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCOMISSZrr, X86_INS_VCOMISS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCOMISSrm, X86_INS_VCOMISS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCOMISSrr, X86_INS_VCOMISS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTDQ2PDYrm, X86_INS_VCVTDQ2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTDQ2PDYrr, X86_INS_VCVTDQ2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTDQ2PDZrm, X86_INS_VCVTDQ2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTDQ2PDZrr, X86_INS_VCVTDQ2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTDQ2PDrm, X86_INS_VCVTDQ2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTDQ2PDrr, X86_INS_VCVTDQ2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTDQ2PSYrm, X86_INS_VCVTDQ2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTDQ2PSYrr, X86_INS_VCVTDQ2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTDQ2PSZrm, X86_INS_VCVTDQ2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTDQ2PSZrr, X86_INS_VCVTDQ2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTDQ2PSZrrb, X86_INS_VCVTDQ2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTDQ2PSrm, X86_INS_VCVTDQ2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTDQ2PSrr, X86_INS_VCVTDQ2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPD2DQXrm, X86_INS_VCVTPD2DQX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPD2DQYrm, X86_INS_VCVTPD2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPD2DQYrr, X86_INS_VCVTPD2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPD2DQZrm, X86_INS_VCVTPD2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPD2DQZrr, X86_INS_VCVTPD2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPD2DQZrrb, X86_INS_VCVTPD2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPD2DQrr, X86_INS_VCVTPD2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPD2PSXrm, X86_INS_VCVTPD2PSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPD2PSYrm, X86_INS_VCVTPD2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPD2PSYrr, X86_INS_VCVTPD2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPD2PSZrm, X86_INS_VCVTPD2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPD2PSZrr, X86_INS_VCVTPD2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPD2PSZrrb, X86_INS_VCVTPD2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPD2PSrr, X86_INS_VCVTPD2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPD2UDQZrm, X86_INS_VCVTPD2UDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPD2UDQZrr, X86_INS_VCVTPD2UDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPD2UDQZrrb, X86_INS_VCVTPD2UDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPH2PSYrm, X86_INS_VCVTPH2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_F16C, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPH2PSYrr, X86_INS_VCVTPH2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_F16C, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPH2PSZrm, X86_INS_VCVTPH2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPH2PSZrr, X86_INS_VCVTPH2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPH2PSrm, X86_INS_VCVTPH2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_F16C, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPH2PSrr, X86_INS_VCVTPH2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_F16C, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPS2DQYrm, X86_INS_VCVTPS2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPS2DQYrr, X86_INS_VCVTPS2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPS2DQZrm, X86_INS_VCVTPS2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPS2DQZrr, X86_INS_VCVTPS2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPS2DQZrrb, X86_INS_VCVTPS2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPS2DQrm, X86_INS_VCVTPS2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPS2DQrr, X86_INS_VCVTPS2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPS2PDYrm, X86_INS_VCVTPS2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPS2PDYrr, X86_INS_VCVTPS2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPS2PDZrm, X86_INS_VCVTPS2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPS2PDZrr, X86_INS_VCVTPS2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPS2PDrm, X86_INS_VCVTPS2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPS2PDrr, X86_INS_VCVTPS2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPS2PHYmr, X86_INS_VCVTPS2PH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_F16C, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPS2PHYrr, X86_INS_VCVTPS2PH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_F16C, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPS2PHZmr, X86_INS_VCVTPS2PH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPS2PHZrr, X86_INS_VCVTPS2PH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPS2PHmr, X86_INS_VCVTPS2PH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_F16C, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPS2PHrr, X86_INS_VCVTPS2PH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_F16C, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPS2UDQZrm, X86_INS_VCVTPS2UDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPS2UDQZrr, X86_INS_VCVTPS2UDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTPS2UDQZrrb, X86_INS_VCVTPS2UDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSD2SI64Zrm, X86_INS_VCVTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSD2SI64Zrr, X86_INS_VCVTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSD2SI64rm, X86_INS_VCVTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSD2SI64rr, X86_INS_VCVTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSD2SIZrm, X86_INS_VCVTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSD2SIZrr, X86_INS_VCVTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSD2SIrm, X86_INS_VCVTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSD2SIrr, X86_INS_VCVTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSD2SSZrm, X86_INS_VCVTSD2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSD2SSZrr, X86_INS_VCVTSD2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSD2SSrm, X86_INS_VCVTSD2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSD2SSrr, X86_INS_VCVTSD2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSD2USI64Zrm, X86_INS_VCVTSD2USI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSD2USI64Zrr, X86_INS_VCVTSD2USI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSD2USIZrm, X86_INS_VCVTSD2USI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSD2USIZrr, X86_INS_VCVTSD2USI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSI2SD64rm, X86_INS_VCVTSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSI2SD64rr, X86_INS_VCVTSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSI2SDZrm, X86_INS_VCVTSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSI2SDZrr, X86_INS_VCVTSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSI2SDrm, X86_INS_VCVTSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSI2SDrr, X86_INS_VCVTSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSI2SS64rm, X86_INS_VCVTSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSI2SS64rr, X86_INS_VCVTSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSI2SSZrm, X86_INS_VCVTSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSI2SSZrr, X86_INS_VCVTSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSI2SSrm, X86_INS_VCVTSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSI2SSrr, X86_INS_VCVTSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSI642SDZrm, X86_INS_VCVTSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSI642SDZrr, X86_INS_VCVTSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSI642SSZrm, X86_INS_VCVTSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSI642SSZrr, X86_INS_VCVTSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSS2SDZrm, X86_INS_VCVTSS2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSS2SDZrr, X86_INS_VCVTSS2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSS2SDrm, X86_INS_VCVTSS2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSS2SDrr, X86_INS_VCVTSS2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSS2SI64Zrm, X86_INS_VCVTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSS2SI64Zrr, X86_INS_VCVTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSS2SI64rm, X86_INS_VCVTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSS2SI64rr, X86_INS_VCVTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSS2SIZrm, X86_INS_VCVTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSS2SIZrr, X86_INS_VCVTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSS2SIrm, X86_INS_VCVTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSS2SIrr, X86_INS_VCVTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSS2USI64Zrm, X86_INS_VCVTSS2USI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSS2USI64Zrr, X86_INS_VCVTSS2USI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSS2USIZrm, X86_INS_VCVTSS2USI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTSS2USIZrr, X86_INS_VCVTSS2USI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTPD2DQXrm, X86_INS_VCVTTPD2DQX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTPD2DQYrm, X86_INS_VCVTTPD2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTPD2DQYrr, X86_INS_VCVTTPD2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTPD2DQZrm, X86_INS_VCVTTPD2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTPD2DQZrr, X86_INS_VCVTTPD2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTPD2DQrr, X86_INS_VCVTTPD2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTPD2UDQZrm, X86_INS_VCVTTPD2UDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTPD2UDQZrr, X86_INS_VCVTTPD2UDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTPS2DQYrm, X86_INS_VCVTTPS2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTPS2DQYrr, X86_INS_VCVTTPS2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTPS2DQZrm, X86_INS_VCVTTPS2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTPS2DQZrr, X86_INS_VCVTTPS2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTPS2DQrm, X86_INS_VCVTTPS2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTPS2DQrr, X86_INS_VCVTTPS2DQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTPS2UDQZrm, X86_INS_VCVTTPS2UDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTPS2UDQZrr, X86_INS_VCVTTPS2UDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTSD2SI64Zrm, X86_INS_VCVTTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTSD2SI64Zrr, X86_INS_VCVTTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTSD2SI64rm, X86_INS_VCVTTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTSD2SI64rr, X86_INS_VCVTTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTSD2SIZrm, X86_INS_VCVTTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTSD2SIZrr, X86_INS_VCVTTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTSD2SIrm, X86_INS_VCVTTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTSD2SIrr, X86_INS_VCVTTSD2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTSD2USI64Zrm, X86_INS_VCVTTSD2USI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTSD2USI64Zrr, X86_INS_VCVTTSD2USI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTSD2USIZrm, X86_INS_VCVTTSD2USI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTSD2USIZrr, X86_INS_VCVTTSD2USI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTSS2SI64Zrm, X86_INS_VCVTTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTSS2SI64Zrr, X86_INS_VCVTTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTSS2SI64rm, X86_INS_VCVTTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTSS2SI64rr, X86_INS_VCVTTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTSS2SIZrm, X86_INS_VCVTTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTSS2SIZrr, X86_INS_VCVTTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTSS2SIrm, X86_INS_VCVTTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTSS2SIrr, X86_INS_VCVTTSS2SI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTSS2USI64Zrm, X86_INS_VCVTTSS2USI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTSS2USI64Zrr, X86_INS_VCVTTSS2USI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTSS2USIZrm, X86_INS_VCVTTSS2USI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTTSS2USIZrr, X86_INS_VCVTTSS2USI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTUDQ2PDZrm, X86_INS_VCVTUDQ2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTUDQ2PDZrr, X86_INS_VCVTUDQ2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTUDQ2PSZrm, X86_INS_VCVTUDQ2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTUDQ2PSZrr, X86_INS_VCVTUDQ2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTUDQ2PSZrrb, X86_INS_VCVTUDQ2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTUSI2SDZrm, X86_INS_VCVTUSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTUSI2SDZrr, X86_INS_VCVTUSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTUSI2SSZrm, X86_INS_VCVTUSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTUSI2SSZrr, X86_INS_VCVTUSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTUSI642SDZrm, X86_INS_VCVTUSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTUSI642SDZrr, X86_INS_VCVTUSI2SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTUSI642SSZrm, X86_INS_VCVTUSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VCVTUSI642SSZrr, X86_INS_VCVTUSI2SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPDYrm, X86_INS_VDIVPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPDYrr, X86_INS_VDIVPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPDZrm, X86_INS_VDIVPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPDZrmb, X86_INS_VDIVPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPDZrmbk, X86_INS_VDIVPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPDZrmbkz, X86_INS_VDIVPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPDZrmk, X86_INS_VDIVPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPDZrmkz, X86_INS_VDIVPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPDZrr, X86_INS_VDIVPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPDZrrk, X86_INS_VDIVPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPDZrrkz, X86_INS_VDIVPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPDrm, X86_INS_VDIVPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPDrr, X86_INS_VDIVPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPSYrm, X86_INS_VDIVPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPSYrr, X86_INS_VDIVPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPSZrm, X86_INS_VDIVPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPSZrmb, X86_INS_VDIVPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPSZrmbk, X86_INS_VDIVPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPSZrmbkz, X86_INS_VDIVPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPSZrmk, X86_INS_VDIVPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPSZrmkz, X86_INS_VDIVPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPSZrr, X86_INS_VDIVPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPSZrrk, X86_INS_VDIVPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPSZrrkz, X86_INS_VDIVPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPSrm, X86_INS_VDIVPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVPSrr, X86_INS_VDIVPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVSDZrm, X86_INS_VDIVSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVSDZrr, X86_INS_VDIVSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVSDrm, X86_INS_VDIVSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVSDrm_Int, X86_INS_VDIVSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVSDrr, X86_INS_VDIVSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVSDrr_Int, X86_INS_VDIVSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVSSZrm, X86_INS_VDIVSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVSSZrr, X86_INS_VDIVSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVSSrm, X86_INS_VDIVSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVSSrm_Int, X86_INS_VDIVSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVSSrr, X86_INS_VDIVSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VDIVSSrr_Int, X86_INS_VDIVSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VDPPDrmi, X86_INS_VDPPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VDPPDrri, X86_INS_VDPPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VDPPSYrmi, X86_INS_VDPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VDPPSYrri, X86_INS_VDPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VDPPSrmi, X86_INS_VDPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VDPPSrri, X86_INS_VDPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VERRm, X86_INS_VERR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_VERRr, X86_INS_VERR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_VERWm, X86_INS_VERW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_VERWr, X86_INS_VERW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_VEXTRACTF128mr, X86_INS_VEXTRACTF128,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VEXTRACTF128rr, X86_INS_VEXTRACTF128,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VEXTRACTF32x4mr, X86_INS_VEXTRACTF32X4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VEXTRACTF32x4rr, X86_INS_VEXTRACTF32X4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VEXTRACTF64x4mr, X86_INS_VEXTRACTF64X4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VEXTRACTF64x4rr, X86_INS_VEXTRACTF64X4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VEXTRACTI128mr, X86_INS_VEXTRACTI128,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VEXTRACTI128rr, X86_INS_VEXTRACTI128,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VEXTRACTI32x4mr, X86_INS_VEXTRACTI32X4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VEXTRACTI32x4rr, X86_INS_VEXTRACTI32X4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VEXTRACTI64x4mr, X86_INS_VEXTRACTI64X4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VEXTRACTI64x4rr, X86_INS_VEXTRACTI64X4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VEXTRACTPSmr, X86_INS_VEXTRACTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VEXTRACTPSrr, X86_INS_VEXTRACTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VEXTRACTPSzmr, X86_INS_VEXTRACTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VEXTRACTPSzrr, X86_INS_VEXTRACTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADD132PDZm, X86_INS_VFMADD132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADD132PDZmb, X86_INS_VFMADD132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADD132PSZm, X86_INS_VFMADD132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADD132PSZmb, X86_INS_VFMADD132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADD213PDZm, X86_INS_VFMADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADD213PDZmb, X86_INS_VFMADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADD213PDZr, X86_INS_VFMADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADD213PDZrk, X86_INS_VFMADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADD213PDZrkz, X86_INS_VFMADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADD213PSZm, X86_INS_VFMADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADD213PSZmb, X86_INS_VFMADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADD213PSZr, X86_INS_VFMADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADD213PSZrk, X86_INS_VFMADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADD213PSZrkz, X86_INS_VFMADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPD4mr, X86_INS_VFMADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPD4mrY, X86_INS_VFMADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPD4rm, X86_INS_VFMADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPD4rmY, X86_INS_VFMADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPD4rr, X86_INS_VFMADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPD4rrY, X86_INS_VFMADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPD4rrY_REV, X86_INS_VFMADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPD4rr_REV, X86_INS_VFMADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPDr132m, X86_INS_VFMADD132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPDr132mY, X86_INS_VFMADD132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPDr132r, X86_INS_VFMADD132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPDr132rY, X86_INS_VFMADD132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPDr213m, X86_INS_VFMADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPDr213mY, X86_INS_VFMADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPDr213r, X86_INS_VFMADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPDr213rY, X86_INS_VFMADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPDr231m, X86_INS_VFMADD231PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPDr231mY, X86_INS_VFMADD231PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPDr231r, X86_INS_VFMADD231PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPDr231rY, X86_INS_VFMADD231PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPS4mr, X86_INS_VFMADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPS4mrY, X86_INS_VFMADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPS4rm, X86_INS_VFMADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPS4rmY, X86_INS_VFMADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPS4rr, X86_INS_VFMADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPS4rrY, X86_INS_VFMADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPS4rrY_REV, X86_INS_VFMADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPS4rr_REV, X86_INS_VFMADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPSr132m, X86_INS_VFMADD132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPSr132mY, X86_INS_VFMADD132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPSr132r, X86_INS_VFMADD132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPSr132rY, X86_INS_VFMADD132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPSr213m, X86_INS_VFMADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPSr213mY, X86_INS_VFMADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPSr213r, X86_INS_VFMADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPSr213rY, X86_INS_VFMADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPSr231m, X86_INS_VFMADD231PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPSr231mY, X86_INS_VFMADD231PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPSr231r, X86_INS_VFMADD231PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDPSr231rY, X86_INS_VFMADD231PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSD4mr, X86_INS_VFMADDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSD4mr_Int, X86_INS_VFMADDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSD4rm, X86_INS_VFMADDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSD4rm_Int, X86_INS_VFMADDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSD4rr, X86_INS_VFMADDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSD4rr_Int, X86_INS_VFMADDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSD4rr_REV, X86_INS_VFMADDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSDZm, X86_INS_VFMADD213SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSDZr, X86_INS_VFMADD213SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSDr132m, X86_INS_VFMADD132SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSDr132r, X86_INS_VFMADD132SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSDr213m, X86_INS_VFMADD213SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSDr213r, X86_INS_VFMADD213SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSDr231m, X86_INS_VFMADD231SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSDr231r, X86_INS_VFMADD231SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSS4mr, X86_INS_VFMADDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSS4mr_Int, X86_INS_VFMADDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSS4rm, X86_INS_VFMADDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSS4rm_Int, X86_INS_VFMADDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSS4rr, X86_INS_VFMADDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSS4rr_Int, X86_INS_VFMADDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSS4rr_REV, X86_INS_VFMADDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSSZm, X86_INS_VFMADD213SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSSZr, X86_INS_VFMADD213SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSSr132m, X86_INS_VFMADD132SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSSr132r, X86_INS_VFMADD132SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSSr213m, X86_INS_VFMADD213SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSSr213r, X86_INS_VFMADD213SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSSr231m, X86_INS_VFMADD231SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSSr231r, X86_INS_VFMADD231SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUB132PDZm, X86_INS_VFMADDSUB132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUB132PDZmb, X86_INS_VFMADDSUB132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUB132PSZm, X86_INS_VFMADDSUB132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUB132PSZmb, X86_INS_VFMADDSUB132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUB213PDZm, X86_INS_VFMADDSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUB213PDZmb, X86_INS_VFMADDSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUB213PDZr, X86_INS_VFMADDSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUB213PDZrk, X86_INS_VFMADDSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUB213PDZrkz, X86_INS_VFMADDSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUB213PSZm, X86_INS_VFMADDSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUB213PSZmb, X86_INS_VFMADDSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUB213PSZr, X86_INS_VFMADDSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUB213PSZrk, X86_INS_VFMADDSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUB213PSZrkz, X86_INS_VFMADDSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPD4mr, X86_INS_VFMADDSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPD4mrY, X86_INS_VFMADDSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPD4rm, X86_INS_VFMADDSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPD4rmY, X86_INS_VFMADDSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPD4rr, X86_INS_VFMADDSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPD4rrY, X86_INS_VFMADDSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPD4rrY_REV, X86_INS_VFMADDSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPD4rr_REV, X86_INS_VFMADDSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPDr132m, X86_INS_VFMADDSUB132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPDr132mY, X86_INS_VFMADDSUB132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPDr132r, X86_INS_VFMADDSUB132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPDr132rY, X86_INS_VFMADDSUB132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPDr213m, X86_INS_VFMADDSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPDr213mY, X86_INS_VFMADDSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPDr213r, X86_INS_VFMADDSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPDr213rY, X86_INS_VFMADDSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPDr231m, X86_INS_VFMADDSUB231PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPDr231mY, X86_INS_VFMADDSUB231PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPDr231r, X86_INS_VFMADDSUB231PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPDr231rY, X86_INS_VFMADDSUB231PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPS4mr, X86_INS_VFMADDSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPS4mrY, X86_INS_VFMADDSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPS4rm, X86_INS_VFMADDSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPS4rmY, X86_INS_VFMADDSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPS4rr, X86_INS_VFMADDSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPS4rrY, X86_INS_VFMADDSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPS4rrY_REV, X86_INS_VFMADDSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPS4rr_REV, X86_INS_VFMADDSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPSr132m, X86_INS_VFMADDSUB132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPSr132mY, X86_INS_VFMADDSUB132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPSr132r, X86_INS_VFMADDSUB132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPSr132rY, X86_INS_VFMADDSUB132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPSr213m, X86_INS_VFMADDSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPSr213mY, X86_INS_VFMADDSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPSr213r, X86_INS_VFMADDSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPSr213rY, X86_INS_VFMADDSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPSr231m, X86_INS_VFMADDSUB231PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPSr231mY, X86_INS_VFMADDSUB231PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPSr231r, X86_INS_VFMADDSUB231PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMADDSUBPSr231rY, X86_INS_VFMADDSUB231PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUB132PDZm, X86_INS_VFMSUB132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUB132PDZmb, X86_INS_VFMSUB132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUB132PSZm, X86_INS_VFMSUB132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUB132PSZmb, X86_INS_VFMSUB132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUB213PDZm, X86_INS_VFMSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUB213PDZmb, X86_INS_VFMSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUB213PDZr, X86_INS_VFMSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUB213PDZrk, X86_INS_VFMSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUB213PDZrkz, X86_INS_VFMSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUB213PSZm, X86_INS_VFMSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUB213PSZmb, X86_INS_VFMSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUB213PSZr, X86_INS_VFMSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUB213PSZrk, X86_INS_VFMSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUB213PSZrkz, X86_INS_VFMSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADD132PDZm, X86_INS_VFMSUBADD132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADD132PDZmb, X86_INS_VFMSUBADD132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADD132PSZm, X86_INS_VFMSUBADD132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADD132PSZmb, X86_INS_VFMSUBADD132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADD213PDZm, X86_INS_VFMSUBADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADD213PDZmb, X86_INS_VFMSUBADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADD213PDZr, X86_INS_VFMSUBADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADD213PDZrk, X86_INS_VFMSUBADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADD213PDZrkz, X86_INS_VFMSUBADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADD213PSZm, X86_INS_VFMSUBADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADD213PSZmb, X86_INS_VFMSUBADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADD213PSZr, X86_INS_VFMSUBADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADD213PSZrk, X86_INS_VFMSUBADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADD213PSZrkz, X86_INS_VFMSUBADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPD4mr, X86_INS_VFMSUBADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPD4mrY, X86_INS_VFMSUBADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPD4rm, X86_INS_VFMSUBADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPD4rmY, X86_INS_VFMSUBADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPD4rr, X86_INS_VFMSUBADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPD4rrY, X86_INS_VFMSUBADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPD4rrY_REV, X86_INS_VFMSUBADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPD4rr_REV, X86_INS_VFMSUBADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPDr132m, X86_INS_VFMSUBADD132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPDr132mY, X86_INS_VFMSUBADD132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPDr132r, X86_INS_VFMSUBADD132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPDr132rY, X86_INS_VFMSUBADD132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPDr213m, X86_INS_VFMSUBADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPDr213mY, X86_INS_VFMSUBADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPDr213r, X86_INS_VFMSUBADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPDr213rY, X86_INS_VFMSUBADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPDr231m, X86_INS_VFMSUBADD231PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPDr231mY, X86_INS_VFMSUBADD231PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPDr231r, X86_INS_VFMSUBADD231PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPDr231rY, X86_INS_VFMSUBADD231PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPS4mr, X86_INS_VFMSUBADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPS4mrY, X86_INS_VFMSUBADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPS4rm, X86_INS_VFMSUBADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPS4rmY, X86_INS_VFMSUBADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPS4rr, X86_INS_VFMSUBADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPS4rrY, X86_INS_VFMSUBADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPS4rrY_REV, X86_INS_VFMSUBADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPS4rr_REV, X86_INS_VFMSUBADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPSr132m, X86_INS_VFMSUBADD132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPSr132mY, X86_INS_VFMSUBADD132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPSr132r, X86_INS_VFMSUBADD132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPSr132rY, X86_INS_VFMSUBADD132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPSr213m, X86_INS_VFMSUBADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPSr213mY, X86_INS_VFMSUBADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPSr213r, X86_INS_VFMSUBADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPSr213rY, X86_INS_VFMSUBADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPSr231m, X86_INS_VFMSUBADD231PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPSr231mY, X86_INS_VFMSUBADD231PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPSr231r, X86_INS_VFMSUBADD231PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBADDPSr231rY, X86_INS_VFMSUBADD231PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPD4mr, X86_INS_VFMSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPD4mrY, X86_INS_VFMSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPD4rm, X86_INS_VFMSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPD4rmY, X86_INS_VFMSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPD4rr, X86_INS_VFMSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPD4rrY, X86_INS_VFMSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPD4rrY_REV, X86_INS_VFMSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPD4rr_REV, X86_INS_VFMSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPDr132m, X86_INS_VFMSUB132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPDr132mY, X86_INS_VFMSUB132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPDr132r, X86_INS_VFMSUB132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPDr132rY, X86_INS_VFMSUB132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPDr213m, X86_INS_VFMSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPDr213mY, X86_INS_VFMSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPDr213r, X86_INS_VFMSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPDr213rY, X86_INS_VFMSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPDr231m, X86_INS_VFMSUB231PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPDr231mY, X86_INS_VFMSUB231PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPDr231r, X86_INS_VFMSUB231PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPDr231rY, X86_INS_VFMSUB231PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPS4mr, X86_INS_VFMSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPS4mrY, X86_INS_VFMSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPS4rm, X86_INS_VFMSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPS4rmY, X86_INS_VFMSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPS4rr, X86_INS_VFMSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPS4rrY, X86_INS_VFMSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPS4rrY_REV, X86_INS_VFMSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPS4rr_REV, X86_INS_VFMSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPSr132m, X86_INS_VFMSUB132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPSr132mY, X86_INS_VFMSUB132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPSr132r, X86_INS_VFMSUB132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPSr132rY, X86_INS_VFMSUB132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPSr213m, X86_INS_VFMSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPSr213mY, X86_INS_VFMSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPSr213r, X86_INS_VFMSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPSr213rY, X86_INS_VFMSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPSr231m, X86_INS_VFMSUB231PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPSr231mY, X86_INS_VFMSUB231PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPSr231r, X86_INS_VFMSUB231PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBPSr231rY, X86_INS_VFMSUB231PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSD4mr, X86_INS_VFMSUBSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSD4mr_Int, X86_INS_VFMSUBSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSD4rm, X86_INS_VFMSUBSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSD4rm_Int, X86_INS_VFMSUBSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSD4rr, X86_INS_VFMSUBSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSD4rr_Int, X86_INS_VFMSUBSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSD4rr_REV, X86_INS_VFMSUBSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSDZm, X86_INS_VFMSUB213SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSDZr, X86_INS_VFMSUB213SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSDr132m, X86_INS_VFMSUB132SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSDr132r, X86_INS_VFMSUB132SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSDr213m, X86_INS_VFMSUB213SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSDr213r, X86_INS_VFMSUB213SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSDr231m, X86_INS_VFMSUB231SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSDr231r, X86_INS_VFMSUB231SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSS4mr, X86_INS_VFMSUBSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSS4mr_Int, X86_INS_VFMSUBSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSS4rm, X86_INS_VFMSUBSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSS4rm_Int, X86_INS_VFMSUBSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSS4rr, X86_INS_VFMSUBSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSS4rr_Int, X86_INS_VFMSUBSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSS4rr_REV, X86_INS_VFMSUBSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSSZm, X86_INS_VFMSUB213SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSSZr, X86_INS_VFMSUB213SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSSr132m, X86_INS_VFMSUB132SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSSr132r, X86_INS_VFMSUB132SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSSr213m, X86_INS_VFMSUB213SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSSr213r, X86_INS_VFMSUB213SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSSr231m, X86_INS_VFMSUB231SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFMSUBSSr231r, X86_INS_VFMSUB231SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADD132PDZm, X86_INS_VFNMADD132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADD132PDZmb, X86_INS_VFNMADD132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADD132PSZm, X86_INS_VFNMADD132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADD132PSZmb, X86_INS_VFNMADD132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADD213PDZm, X86_INS_VFNMADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADD213PDZmb, X86_INS_VFNMADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADD213PDZr, X86_INS_VFNMADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADD213PDZrk, X86_INS_VFNMADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADD213PDZrkz, X86_INS_VFNMADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADD213PSZm, X86_INS_VFNMADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADD213PSZmb, X86_INS_VFNMADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADD213PSZr, X86_INS_VFNMADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADD213PSZrk, X86_INS_VFNMADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADD213PSZrkz, X86_INS_VFNMADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPD4mr, X86_INS_VFNMADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPD4mrY, X86_INS_VFNMADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPD4rm, X86_INS_VFNMADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPD4rmY, X86_INS_VFNMADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPD4rr, X86_INS_VFNMADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPD4rrY, X86_INS_VFNMADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPD4rrY_REV, X86_INS_VFNMADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPD4rr_REV, X86_INS_VFNMADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPDr132m, X86_INS_VFNMADD132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPDr132mY, X86_INS_VFNMADD132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPDr132r, X86_INS_VFNMADD132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPDr132rY, X86_INS_VFNMADD132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPDr213m, X86_INS_VFNMADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPDr213mY, X86_INS_VFNMADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPDr213r, X86_INS_VFNMADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPDr213rY, X86_INS_VFNMADD213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPDr231m, X86_INS_VFNMADD231PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPDr231mY, X86_INS_VFNMADD231PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPDr231r, X86_INS_VFNMADD231PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPDr231rY, X86_INS_VFNMADD231PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPS4mr, X86_INS_VFNMADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPS4mrY, X86_INS_VFNMADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPS4rm, X86_INS_VFNMADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPS4rmY, X86_INS_VFNMADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPS4rr, X86_INS_VFNMADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPS4rrY, X86_INS_VFNMADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPS4rrY_REV, X86_INS_VFNMADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPS4rr_REV, X86_INS_VFNMADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPSr132m, X86_INS_VFNMADD132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPSr132mY, X86_INS_VFNMADD132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPSr132r, X86_INS_VFNMADD132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPSr132rY, X86_INS_VFNMADD132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPSr213m, X86_INS_VFNMADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPSr213mY, X86_INS_VFNMADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPSr213r, X86_INS_VFNMADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPSr213rY, X86_INS_VFNMADD213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPSr231m, X86_INS_VFNMADD231PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPSr231mY, X86_INS_VFNMADD231PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPSr231r, X86_INS_VFNMADD231PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDPSr231rY, X86_INS_VFNMADD231PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSD4mr, X86_INS_VFNMADDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSD4mr_Int, X86_INS_VFNMADDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSD4rm, X86_INS_VFNMADDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSD4rm_Int, X86_INS_VFNMADDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSD4rr, X86_INS_VFNMADDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSD4rr_Int, X86_INS_VFNMADDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSD4rr_REV, X86_INS_VFNMADDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSDZm, X86_INS_VFNMADD213SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSDZr, X86_INS_VFNMADD213SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSDr132m, X86_INS_VFNMADD132SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSDr132r, X86_INS_VFNMADD132SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSDr213m, X86_INS_VFNMADD213SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSDr213r, X86_INS_VFNMADD213SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSDr231m, X86_INS_VFNMADD231SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSDr231r, X86_INS_VFNMADD231SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSS4mr, X86_INS_VFNMADDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSS4mr_Int, X86_INS_VFNMADDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSS4rm, X86_INS_VFNMADDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSS4rm_Int, X86_INS_VFNMADDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSS4rr, X86_INS_VFNMADDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSS4rr_Int, X86_INS_VFNMADDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSS4rr_REV, X86_INS_VFNMADDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSSZm, X86_INS_VFNMADD213SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSSZr, X86_INS_VFNMADD213SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSSr132m, X86_INS_VFNMADD132SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSSr132r, X86_INS_VFNMADD132SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSSr213m, X86_INS_VFNMADD213SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSSr213r, X86_INS_VFNMADD213SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSSr231m, X86_INS_VFNMADD231SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMADDSSr231r, X86_INS_VFNMADD231SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUB132PDZm, X86_INS_VFNMSUB132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUB132PDZmb, X86_INS_VFNMSUB132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUB132PSZm, X86_INS_VFNMSUB132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUB132PSZmb, X86_INS_VFNMSUB132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUB213PDZm, X86_INS_VFNMSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUB213PDZmb, X86_INS_VFNMSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUB213PDZr, X86_INS_VFNMSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUB213PDZrk, X86_INS_VFNMSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUB213PDZrkz, X86_INS_VFNMSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUB213PSZm, X86_INS_VFNMSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUB213PSZmb, X86_INS_VFNMSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUB213PSZr, X86_INS_VFNMSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUB213PSZrk, X86_INS_VFNMSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUB213PSZrkz, X86_INS_VFNMSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPD4mr, X86_INS_VFNMSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPD4mrY, X86_INS_VFNMSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPD4rm, X86_INS_VFNMSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPD4rmY, X86_INS_VFNMSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPD4rr, X86_INS_VFNMSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPD4rrY, X86_INS_VFNMSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPD4rrY_REV, X86_INS_VFNMSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPD4rr_REV, X86_INS_VFNMSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPDr132m, X86_INS_VFNMSUB132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPDr132mY, X86_INS_VFNMSUB132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPDr132r, X86_INS_VFNMSUB132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPDr132rY, X86_INS_VFNMSUB132PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPDr213m, X86_INS_VFNMSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPDr213mY, X86_INS_VFNMSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPDr213r, X86_INS_VFNMSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPDr213rY, X86_INS_VFNMSUB213PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPDr231m, X86_INS_VFNMSUB231PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPDr231mY, X86_INS_VFNMSUB231PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPDr231r, X86_INS_VFNMSUB231PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPDr231rY, X86_INS_VFNMSUB231PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPS4mr, X86_INS_VFNMSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPS4mrY, X86_INS_VFNMSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPS4rm, X86_INS_VFNMSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPS4rmY, X86_INS_VFNMSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPS4rr, X86_INS_VFNMSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPS4rrY, X86_INS_VFNMSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPS4rrY_REV, X86_INS_VFNMSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPS4rr_REV, X86_INS_VFNMSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPSr132m, X86_INS_VFNMSUB132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPSr132mY, X86_INS_VFNMSUB132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPSr132r, X86_INS_VFNMSUB132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPSr132rY, X86_INS_VFNMSUB132PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPSr213m, X86_INS_VFNMSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPSr213mY, X86_INS_VFNMSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPSr213r, X86_INS_VFNMSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPSr213rY, X86_INS_VFNMSUB213PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPSr231m, X86_INS_VFNMSUB231PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPSr231mY, X86_INS_VFNMSUB231PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPSr231r, X86_INS_VFNMSUB231PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBPSr231rY, X86_INS_VFNMSUB231PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSD4mr, X86_INS_VFNMSUBSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSD4mr_Int, X86_INS_VFNMSUBSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSD4rm, X86_INS_VFNMSUBSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSD4rm_Int, X86_INS_VFNMSUBSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSD4rr, X86_INS_VFNMSUBSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSD4rr_Int, X86_INS_VFNMSUBSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSD4rr_REV, X86_INS_VFNMSUBSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSDZm, X86_INS_VFNMSUB213SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSDZr, X86_INS_VFNMSUB213SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSDr132m, X86_INS_VFNMSUB132SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSDr132r, X86_INS_VFNMSUB132SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSDr213m, X86_INS_VFNMSUB213SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSDr213r, X86_INS_VFNMSUB213SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSDr231m, X86_INS_VFNMSUB231SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSDr231r, X86_INS_VFNMSUB231SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSS4mr, X86_INS_VFNMSUBSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSS4mr_Int, X86_INS_VFNMSUBSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSS4rm, X86_INS_VFNMSUBSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSS4rm_Int, X86_INS_VFNMSUBSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSS4rr, X86_INS_VFNMSUBSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSS4rr_Int, X86_INS_VFNMSUBSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSS4rr_REV, X86_INS_VFNMSUBSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA4, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSSZm, X86_INS_VFNMSUB213SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSSZr, X86_INS_VFNMSUB213SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSSr132m, X86_INS_VFNMSUB132SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSSr132r, X86_INS_VFNMSUB132SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSSr213m, X86_INS_VFNMSUB213SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSSr213r, X86_INS_VFNMSUB213SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSSr231m, X86_INS_VFNMSUB231SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFNMSUBSSr231r, X86_INS_VFNMSUB231SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FMA, 0 }, 0, 0
#endif
	},
	{
		X86_VFRCZPDrm, X86_INS_VFRCZPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VFRCZPDrmY, X86_INS_VFRCZPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VFRCZPDrr, X86_INS_VFRCZPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VFRCZPDrrY, X86_INS_VFRCZPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VFRCZPSrm, X86_INS_VFRCZPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VFRCZPSrmY, X86_INS_VFRCZPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VFRCZPSrr, X86_INS_VFRCZPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VFRCZPSrrY, X86_INS_VFRCZPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VFRCZSDrm, X86_INS_VFRCZSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VFRCZSDrr, X86_INS_VFRCZSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VFRCZSSrm, X86_INS_VFRCZSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VFRCZSSrr, X86_INS_VFRCZSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VFsANDNPDrm, X86_INS_VANDNPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VFsANDNPDrr, X86_INS_VANDNPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VFsANDNPSrm, X86_INS_VANDNPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VFsANDNPSrr, X86_INS_VANDNPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VFsANDPDrm, X86_INS_VANDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VFsANDPDrr, X86_INS_VANDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VFsANDPSrm, X86_INS_VANDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VFsANDPSrr, X86_INS_VANDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VFsORPDrm, X86_INS_VORPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VFsORPDrr, X86_INS_VORPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VFsORPSrm, X86_INS_VORPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VFsORPSrr, X86_INS_VORPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VFsXORPDrm, X86_INS_VXORPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VFsXORPDrr, X86_INS_VXORPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VFsXORPSrm, X86_INS_VXORPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VFsXORPSrr, X86_INS_VXORPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VGATHERDPDYrm, X86_INS_VGATHERDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VGATHERDPDZrm, X86_INS_VGATHERDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VGATHERDPDrm, X86_INS_VGATHERDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VGATHERDPSYrm, X86_INS_VGATHERDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VGATHERDPSZrm, X86_INS_VGATHERDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VGATHERDPSrm, X86_INS_VGATHERDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VGATHERPF0DPDm, X86_INS_VGATHERPF0DPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_PFI, 0 }, 0, 0
#endif
	},
	{
		X86_VGATHERPF0DPSm, X86_INS_VGATHERPF0DPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_PFI, 0 }, 0, 0
#endif
	},
	{
		X86_VGATHERPF0QPDm, X86_INS_VGATHERPF0QPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_PFI, 0 }, 0, 0
#endif
	},
	{
		X86_VGATHERPF0QPSm, X86_INS_VGATHERPF0QPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_PFI, 0 }, 0, 0
#endif
	},
	{
		X86_VGATHERPF1DPDm, X86_INS_VGATHERPF1DPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_PFI, 0 }, 0, 0
#endif
	},
	{
		X86_VGATHERPF1DPSm, X86_INS_VGATHERPF1DPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_PFI, 0 }, 0, 0
#endif
	},
	{
		X86_VGATHERPF1QPDm, X86_INS_VGATHERPF1QPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_PFI, 0 }, 0, 0
#endif
	},
	{
		X86_VGATHERPF1QPSm, X86_INS_VGATHERPF1QPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_PFI, 0 }, 0, 0
#endif
	},
	{
		X86_VGATHERQPDYrm, X86_INS_VGATHERQPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VGATHERQPDZrm, X86_INS_VGATHERQPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VGATHERQPDrm, X86_INS_VGATHERQPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VGATHERQPSYrm, X86_INS_VGATHERQPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VGATHERQPSZrm, X86_INS_VGATHERQPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VGATHERQPSrm, X86_INS_VGATHERQPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VHADDPDYrm, X86_INS_VHADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VHADDPDYrr, X86_INS_VHADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VHADDPDrm, X86_INS_VHADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VHADDPDrr, X86_INS_VHADDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VHADDPSYrm, X86_INS_VHADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VHADDPSYrr, X86_INS_VHADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VHADDPSrm, X86_INS_VHADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VHADDPSrr, X86_INS_VHADDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VHSUBPDYrm, X86_INS_VHSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VHSUBPDYrr, X86_INS_VHSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VHSUBPDrm, X86_INS_VHSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VHSUBPDrr, X86_INS_VHSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VHSUBPSYrm, X86_INS_VHSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VHSUBPSYrr, X86_INS_VHSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VHSUBPSrm, X86_INS_VHSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VHSUBPSrr, X86_INS_VHSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VINSERTF128rm, X86_INS_VINSERTF128,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VINSERTF128rr, X86_INS_VINSERTF128,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VINSERTF32x4rm, X86_INS_VINSERTF32X4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VINSERTF32x4rr, X86_INS_VINSERTF32X4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VINSERTF64x4rm, X86_INS_VINSERTF64X4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VINSERTF64x4rr, X86_INS_VINSERTF64X4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VINSERTI128rm, X86_INS_VINSERTI128,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VINSERTI128rr, X86_INS_VINSERTI128,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VINSERTI32x4rm, X86_INS_VINSERTI32X4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VINSERTI32x4rr, X86_INS_VINSERTI32X4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VINSERTI64x4rm, X86_INS_VINSERTI64X4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VINSERTI64x4rr, X86_INS_VINSERTI64X4,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VINSERTPSrm, X86_INS_VINSERTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VINSERTPSrr, X86_INS_VINSERTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VINSERTPSzrm, X86_INS_VINSERTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VINSERTPSzrr, X86_INS_VINSERTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VLDDQUYrm, X86_INS_VLDDQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VLDDQUrm, X86_INS_VLDDQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VLDMXCSR, X86_INS_VLDMXCSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMASKMOVDQU, X86_INS_VMASKMOVDQU,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDI, 0 }, { 0 }, { X86_GRP_AVX, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_VMASKMOVDQU64, X86_INS_VMASKMOVDQU,
#ifndef CAPSTONE_DIET
		{ X86_REG_RDI, 0 }, { 0 }, { X86_GRP_AVX, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_VMASKMOVPDYmr, X86_INS_VMASKMOVPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMASKMOVPDYrm, X86_INS_VMASKMOVPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMASKMOVPDmr, X86_INS_VMASKMOVPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMASKMOVPDrm, X86_INS_VMASKMOVPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMASKMOVPSYmr, X86_INS_VMASKMOVPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMASKMOVPSYrm, X86_INS_VMASKMOVPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMASKMOVPSmr, X86_INS_VMASKMOVPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMASKMOVPSrm, X86_INS_VMASKMOVPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXCPDYrm, X86_INS_VMAXPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXCPDYrr, X86_INS_VMAXPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXCPDrm, X86_INS_VMAXPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXCPDrr, X86_INS_VMAXPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXCPSYrm, X86_INS_VMAXPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXCPSYrr, X86_INS_VMAXPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXCPSrm, X86_INS_VMAXPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXCPSrr, X86_INS_VMAXPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXCSDrm, X86_INS_VMAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXCSDrr, X86_INS_VMAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXCSSrm, X86_INS_VMAXSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXCSSrr, X86_INS_VMAXSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPDYrm, X86_INS_VMAXPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPDYrr, X86_INS_VMAXPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPDZrm, X86_INS_VMAXPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPDZrmb, X86_INS_VMAXPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPDZrmbk, X86_INS_VMAXPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPDZrmbkz, X86_INS_VMAXPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPDZrmk, X86_INS_VMAXPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPDZrmkz, X86_INS_VMAXPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPDZrr, X86_INS_VMAXPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPDZrrk, X86_INS_VMAXPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPDZrrkz, X86_INS_VMAXPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPDrm, X86_INS_VMAXPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPDrr, X86_INS_VMAXPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPSYrm, X86_INS_VMAXPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPSYrr, X86_INS_VMAXPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPSZrm, X86_INS_VMAXPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPSZrmb, X86_INS_VMAXPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPSZrmbk, X86_INS_VMAXPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPSZrmbkz, X86_INS_VMAXPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPSZrmk, X86_INS_VMAXPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPSZrmkz, X86_INS_VMAXPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPSZrr, X86_INS_VMAXPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPSZrrk, X86_INS_VMAXPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPSZrrkz, X86_INS_VMAXPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPSrm, X86_INS_VMAXPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXPSrr, X86_INS_VMAXPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXSDZrm, X86_INS_VMAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXSDZrr, X86_INS_VMAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXSDrm, X86_INS_VMAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXSDrm_Int, X86_INS_VMAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXSDrr, X86_INS_VMAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXSDrr_Int, X86_INS_VMAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXSSZrm, X86_INS_VMAXSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXSSZrr, X86_INS_VMAXSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXSSrm, X86_INS_VMAXSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXSSrm_Int, X86_INS_VMAXSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXSSrr, X86_INS_VMAXSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMAXSSrr_Int, X86_INS_VMAXSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMCALL, X86_INS_VMCALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_VMCLEARm, X86_INS_VMCLEAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_VMFUNC, X86_INS_VMFUNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_VMINCPDYrm, X86_INS_VMINPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINCPDYrr, X86_INS_VMINPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINCPDrm, X86_INS_VMINPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINCPDrr, X86_INS_VMINPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINCPSYrm, X86_INS_VMINPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINCPSYrr, X86_INS_VMINPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINCPSrm, X86_INS_VMINPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINCPSrr, X86_INS_VMINPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINCSDrm, X86_INS_VMINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINCSDrr, X86_INS_VMINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINCSSrm, X86_INS_VMINSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINCSSrr, X86_INS_VMINSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPDYrm, X86_INS_VMINPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPDYrr, X86_INS_VMINPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPDZrm, X86_INS_VMINPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPDZrmb, X86_INS_VMINPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPDZrmbk, X86_INS_VMINPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPDZrmbkz, X86_INS_VMINPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPDZrmk, X86_INS_VMINPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPDZrmkz, X86_INS_VMINPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPDZrr, X86_INS_VMINPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPDZrrk, X86_INS_VMINPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPDZrrkz, X86_INS_VMINPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPDrm, X86_INS_VMINPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPDrr, X86_INS_VMINPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPSYrm, X86_INS_VMINPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPSYrr, X86_INS_VMINPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPSZrm, X86_INS_VMINPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPSZrmb, X86_INS_VMINPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPSZrmbk, X86_INS_VMINPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPSZrmbkz, X86_INS_VMINPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPSZrmk, X86_INS_VMINPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPSZrmkz, X86_INS_VMINPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPSZrr, X86_INS_VMINPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPSZrrk, X86_INS_VMINPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPSZrrkz, X86_INS_VMINPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPSrm, X86_INS_VMINPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINPSrr, X86_INS_VMINPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINSDZrm, X86_INS_VMINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMINSDZrr, X86_INS_VMINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMINSDrm, X86_INS_VMINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINSDrm_Int, X86_INS_VMINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINSDrr, X86_INS_VMINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINSDrr_Int, X86_INS_VMINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINSSZrm, X86_INS_VMINSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMINSSZrr, X86_INS_VMINSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMINSSrm, X86_INS_VMINSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINSSrm_Int, X86_INS_VMINSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINSSrr, X86_INS_VMINSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMINSSrr_Int, X86_INS_VMINSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMLAUNCH, X86_INS_VMLAUNCH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_VMLOAD32, X86_INS_VMLOAD,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { 0 }, { X86_GRP_VM, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_VMLOAD64, X86_INS_VMLOAD,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, 0 }, { 0 }, { X86_GRP_VM, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_VMMCALL, X86_INS_VMMCALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_VMOV64toPQIZrr, X86_INS_VMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOV64toPQIrr, X86_INS_VMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOV64toSDZrr, X86_INS_VMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOV64toSDrm, X86_INS_VMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOV64toSDrr, X86_INS_VMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDYmr, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDYrm, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDYrr, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDYrr_REV, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZ128mr, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZ128mrk, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZ128rm, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZ128rmk, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZ128rmkz, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZ128rr, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZ128rr_alt, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZ128rrk, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZ128rrk_alt, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZ128rrkz, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZ128rrkz_alt, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZ256mr, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZ256mrk, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZ256rm, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZ256rmk, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZ256rmkz, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZ256rr, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZ256rr_alt, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZ256rrk, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZ256rrk_alt, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZ256rrkz, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZ256rrkz_alt, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZmr, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZmrk, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZrm, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZrmk, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZrmkz, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZrr, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZrr_alt, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZrrk, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZrrk_alt, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZrrkz, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDZrrkz_alt, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDmr, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDrm, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDrr, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPDrr_REV, X86_INS_VMOVAPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSYmr, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSYrm, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSYrr, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSYrr_REV, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZ128mr, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZ128mrk, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZ128rm, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZ128rmk, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZ128rmkz, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZ128rr, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZ128rr_alt, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZ128rrk, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZ128rrk_alt, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZ128rrkz, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZ128rrkz_alt, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZ256mr, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZ256mrk, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZ256rm, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZ256rmk, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZ256rmkz, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZ256rr, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZ256rr_alt, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZ256rrk, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZ256rrk_alt, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZ256rrkz, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZ256rrkz_alt, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZmr, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZmrk, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZrm, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZrmk, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZrmkz, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZrr, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZrr_alt, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZrrk, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZrrk_alt, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZrrkz, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSZrrkz_alt, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSmr, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSrm, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSrr, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVAPSrr_REV, X86_INS_VMOVAPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDDUPYrm, X86_INS_VMOVDDUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDDUPYrr, X86_INS_VMOVDDUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDDUPZrm, X86_INS_VMOVDDUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDDUPZrr, X86_INS_VMOVDDUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDDUPrm, X86_INS_VMOVDDUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDDUPrr, X86_INS_VMOVDDUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDI2PDIZrm, X86_INS_VMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDI2PDIZrr, X86_INS_VMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDI2PDIrm, X86_INS_VMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDI2PDIrr, X86_INS_VMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDI2SSZrm, X86_INS_VMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDI2SSZrr, X86_INS_VMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDI2SSrm, X86_INS_VMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDI2SSrr, X86_INS_VMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Z128mr, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Z128mrk, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Z128rm, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Z128rmk, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Z128rmkz, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Z128rr, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Z128rr_alt, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Z128rrk, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Z128rrk_alt, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Z128rrkz, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Z128rrkz_alt, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Z256mr, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Z256mrk, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Z256rm, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Z256rmk, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Z256rmkz, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Z256rr, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Z256rr_alt, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Z256rrk, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Z256rrk_alt, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Z256rrkz, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Z256rrkz_alt, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Zmr, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Zmrk, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Zrm, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Zrmk, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Zrmkz, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Zrr, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Zrr_alt, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Zrrk, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Zrrk_alt, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Zrrkz, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA32Zrrkz_alt, X86_INS_VMOVDQA32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Z128mr, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Z128mrk, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Z128rm, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Z128rmk, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Z128rmkz, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Z128rr, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Z128rr_alt, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Z128rrk, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Z128rrk_alt, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Z128rrkz, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Z128rrkz_alt, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Z256mr, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Z256mrk, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Z256rm, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Z256rmk, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Z256rmkz, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Z256rr, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Z256rr_alt, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Z256rrk, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Z256rrk_alt, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Z256rrkz, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Z256rrkz_alt, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Zmr, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Zmrk, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Zrm, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Zrmk, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Zrmkz, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Zrr, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Zrr_alt, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Zrrk, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Zrrk_alt, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Zrrkz, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQA64Zrrkz_alt, X86_INS_VMOVDQA64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQAYmr, X86_INS_VMOVDQA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQAYrm, X86_INS_VMOVDQA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQAYrr, X86_INS_VMOVDQA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQAYrr_REV, X86_INS_VMOVDQA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQAmr, X86_INS_VMOVDQA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQArm, X86_INS_VMOVDQA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQArr, X86_INS_VMOVDQA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQArr_REV, X86_INS_VMOVDQA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Z128mr, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Z128mrk, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Z128rm, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Z128rmk, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Z128rmkz, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Z128rr, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Z128rr_alt, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Z128rrk, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Z128rrk_alt, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Z128rrkz, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Z128rrkz_alt, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Z256mr, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Z256mrk, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Z256rm, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Z256rmk, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Z256rmkz, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Z256rr, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Z256rr_alt, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Z256rrk, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Z256rrk_alt, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Z256rrkz, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Z256rrkz_alt, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Zmr, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Zmrk, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Zrm, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Zrmk, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Zrmkz, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Zrr, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Zrr_alt, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Zrrk, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Zrrk_alt, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Zrrkz, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU16Zrrkz_alt, X86_INS_VMOVDQU16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Z128mr, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Z128mrk, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Z128rm, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Z128rmk, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Z128rmkz, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Z128rr, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Z128rr_alt, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Z128rrk, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Z128rrk_alt, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Z128rrkz, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Z128rrkz_alt, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Z256mr, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Z256mrk, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Z256rm, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Z256rmk, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Z256rmkz, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Z256rr, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Z256rr_alt, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Z256rrk, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Z256rrk_alt, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Z256rrkz, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Z256rrkz_alt, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Zmr, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Zmrk, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Zrm, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Zrmk, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Zrmkz, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Zrr, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Zrr_alt, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Zrrk, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Zrrk_alt, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Zrrkz, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU32Zrrkz_alt, X86_INS_VMOVDQU32,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Z128mr, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Z128mrk, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Z128rm, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Z128rmk, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Z128rmkz, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Z128rr, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Z128rr_alt, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Z128rrk, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Z128rrk_alt, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Z128rrkz, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Z128rrkz_alt, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Z256mr, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Z256mrk, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Z256rm, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Z256rmk, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Z256rmkz, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Z256rr, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Z256rr_alt, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Z256rrk, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Z256rrk_alt, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Z256rrkz, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Z256rrkz_alt, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Zmr, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Zmrk, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Zrm, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Zrmk, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Zrmkz, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Zrr, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Zrr_alt, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Zrrk, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Zrrk_alt, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Zrrkz, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU64Zrrkz_alt, X86_INS_VMOVDQU64,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Z128mr, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Z128mrk, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Z128rm, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Z128rmk, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Z128rmkz, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Z128rr, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Z128rr_alt, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Z128rrk, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Z128rrk_alt, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Z128rrkz, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Z128rrkz_alt, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Z256mr, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Z256mrk, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Z256rm, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Z256rmk, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Z256rmkz, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Z256rr, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Z256rr_alt, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Z256rrk, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Z256rrk_alt, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Z256rrkz, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Z256rrkz_alt, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Zmr, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Zmrk, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Zrm, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Zrmk, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Zrmkz, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Zrr, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Zrr_alt, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Zrrk, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Zrrk_alt, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Zrrkz, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQU8Zrrkz_alt, X86_INS_VMOVDQU8,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQUYmr, X86_INS_VMOVDQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQUYrm, X86_INS_VMOVDQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQUYrr, X86_INS_VMOVDQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQUYrr_REV, X86_INS_VMOVDQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQUmr, X86_INS_VMOVDQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQUrm, X86_INS_VMOVDQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQUrr, X86_INS_VMOVDQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVDQUrr_REV, X86_INS_VMOVDQU,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVHLPSZrr, X86_INS_VMOVHLPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVHLPSrr, X86_INS_VMOVHLPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVHPDmr, X86_INS_VMOVHPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVHPDrm, X86_INS_VMOVHPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVHPSmr, X86_INS_VMOVHPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVHPSrm, X86_INS_VMOVHPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVLHPSZrr, X86_INS_VMOVLHPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVLHPSrr, X86_INS_VMOVLHPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVLPDmr, X86_INS_VMOVLPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVLPDrm, X86_INS_VMOVLPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVLPSmr, X86_INS_VMOVLPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVLPSrm, X86_INS_VMOVLPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVMSKPDYrr, X86_INS_VMOVMSKPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVMSKPDrr, X86_INS_VMOVMSKPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVMSKPSYrr, X86_INS_VMOVMSKPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVMSKPSrr, X86_INS_VMOVMSKPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVNTDQAYrm, X86_INS_VMOVNTDQA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVNTDQAZ128rm, X86_INS_VMOVNTDQA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVNTDQAZ256rm, X86_INS_VMOVNTDQA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVNTDQAZrm, X86_INS_VMOVNTDQA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVNTDQArm, X86_INS_VMOVNTDQA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVNTDQYmr, X86_INS_VMOVNTDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, X86_GRP_NOVLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVNTDQZ128mr, X86_INS_VMOVNTDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVNTDQZ256mr, X86_INS_VMOVNTDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVNTDQZmr, X86_INS_VMOVNTDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVNTDQmr, X86_INS_VMOVNTDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, X86_GRP_NOVLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVNTPDYmr, X86_INS_VMOVNTPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, X86_GRP_NOVLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVNTPDZ128mr, X86_INS_VMOVNTPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVNTPDZ256mr, X86_INS_VMOVNTPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVNTPDZmr, X86_INS_VMOVNTPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVNTPDmr, X86_INS_VMOVNTPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, X86_GRP_NOVLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVNTPSYmr, X86_INS_VMOVNTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, X86_GRP_NOVLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVNTPSZ128mr, X86_INS_VMOVNTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVNTPSZ256mr, X86_INS_VMOVNTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVNTPSZmr, X86_INS_VMOVNTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVNTPSmr, X86_INS_VMOVNTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, X86_GRP_NOVLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVPDI2DIZmr, X86_INS_VMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVPDI2DIZrr, X86_INS_VMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVPDI2DImr, X86_INS_VMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVPDI2DIrr, X86_INS_VMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVPQI2QImr, X86_INS_VMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVPQI2QIrr, X86_INS_VMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVPQIto64Zmr, X86_INS_VMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVPQIto64Zrr, X86_INS_VMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVPQIto64rr, X86_INS_VMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVQI2PQIZrm, X86_INS_VMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVQI2PQIrm, X86_INS_VMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSDZmr, X86_INS_VMOVSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSDZrm, X86_INS_VMOVSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSDZrr, X86_INS_VMOVSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSDZrr_REV, X86_INS_VMOVSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSDZrrk, X86_INS_VMOVSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSDmr, X86_INS_VMOVSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSDrm, X86_INS_VMOVSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSDrr, X86_INS_VMOVSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSDrr_REV, X86_INS_VMOVSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSDto64Zmr, X86_INS_VMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSDto64Zrr, X86_INS_VMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSDto64mr, X86_INS_VMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSDto64rr, X86_INS_VMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSHDUPYrm, X86_INS_VMOVSHDUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSHDUPYrr, X86_INS_VMOVSHDUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSHDUPZrm, X86_INS_VMOVSHDUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSHDUPZrr, X86_INS_VMOVSHDUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSHDUPrm, X86_INS_VMOVSHDUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSHDUPrr, X86_INS_VMOVSHDUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSLDUPYrm, X86_INS_VMOVSLDUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSLDUPYrr, X86_INS_VMOVSLDUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSLDUPZrm, X86_INS_VMOVSLDUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSLDUPZrr, X86_INS_VMOVSLDUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSLDUPrm, X86_INS_VMOVSLDUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSLDUPrr, X86_INS_VMOVSLDUP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSS2DIZmr, X86_INS_VMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSS2DIZrr, X86_INS_VMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSS2DImr, X86_INS_VMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSS2DIrr, X86_INS_VMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSSZmr, X86_INS_VMOVSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSSZrm, X86_INS_VMOVSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSSZrr, X86_INS_VMOVSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSSZrr_REV, X86_INS_VMOVSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSSZrrk, X86_INS_VMOVSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSSmr, X86_INS_VMOVSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSSrm, X86_INS_VMOVSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSSrr, X86_INS_VMOVSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVSSrr_REV, X86_INS_VMOVSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDYmr, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDYrm, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDYrr, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDYrr_REV, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZ128mr, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZ128mrk, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZ128rm, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZ128rmk, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZ128rmkz, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZ128rr, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZ128rr_alt, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZ128rrk, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZ128rrk_alt, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZ128rrkz, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZ128rrkz_alt, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZ256mr, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZ256mrk, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZ256rm, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZ256rmk, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZ256rmkz, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZ256rr, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZ256rr_alt, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZ256rrk, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZ256rrk_alt, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZ256rrkz, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZ256rrkz_alt, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZmr, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZmrk, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZrm, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZrmk, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZrmkz, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZrr, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZrr_alt, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZrrk, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZrrk_alt, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZrrkz, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDZrrkz_alt, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDmr, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDrm, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDrr, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPDrr_REV, X86_INS_VMOVUPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSYmr, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSYrm, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSYrr, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSYrr_REV, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZ128mr, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZ128mrk, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZ128rm, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZ128rmk, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZ128rmkz, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZ128rr, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZ128rr_alt, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZ128rrk, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZ128rrk_alt, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZ128rrkz, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZ128rrkz_alt, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZ256mr, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZ256mrk, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZ256rm, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZ256rmk, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZ256rmkz, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZ256rr, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZ256rr_alt, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZ256rrk, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZ256rrk_alt, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZ256rrkz, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZ256rrkz_alt, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZmr, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZmrk, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZrm, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZrmk, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZrmkz, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZrr, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZrr_alt, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZrrk, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZrrk_alt, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZrrkz, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSZrrkz_alt, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSmr, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSrm, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSrr, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVUPSrr_REV, X86_INS_VMOVUPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVZPQILo2PQIZrm, X86_INS_VMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVZPQILo2PQIZrr, X86_INS_VMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVZPQILo2PQIrm, X86_INS_VMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVZPQILo2PQIrr, X86_INS_VMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVZQI2PQIrm, X86_INS_VMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMOVZQI2PQIrr, X86_INS_VMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMPSADBWYrmi, X86_INS_VMPSADBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VMPSADBWYrri, X86_INS_VMPSADBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VMPSADBWrmi, X86_INS_VMPSADBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMPSADBWrri, X86_INS_VMPSADBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMPTRLDm, X86_INS_VMPTRLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_VMPTRSTm, X86_INS_VMPTRST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_VMREAD32rm, X86_INS_VMREAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_VMREAD32rr, X86_INS_VMREAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_VMREAD64rm, X86_INS_VMREAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_VMREAD64rr, X86_INS_VMREAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_VMRESUME, X86_INS_VMRESUME,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_VMRUN32, X86_INS_VMRUN,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { 0 }, { X86_GRP_VM, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_VMRUN64, X86_INS_VMRUN,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, 0 }, { 0 }, { X86_GRP_VM, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_VMSAVE32, X86_INS_VMSAVE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { 0 }, { X86_GRP_VM, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_VMSAVE64, X86_INS_VMSAVE,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, 0 }, { 0 }, { X86_GRP_VM, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPDYrm, X86_INS_VMULPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPDYrr, X86_INS_VMULPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPDZrm, X86_INS_VMULPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPDZrmb, X86_INS_VMULPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPDZrmbk, X86_INS_VMULPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPDZrmbkz, X86_INS_VMULPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPDZrmk, X86_INS_VMULPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPDZrmkz, X86_INS_VMULPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPDZrr, X86_INS_VMULPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPDZrrk, X86_INS_VMULPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPDZrrkz, X86_INS_VMULPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPDrm, X86_INS_VMULPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPDrr, X86_INS_VMULPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPSYrm, X86_INS_VMULPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPSYrr, X86_INS_VMULPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPSZrm, X86_INS_VMULPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPSZrmb, X86_INS_VMULPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPSZrmbk, X86_INS_VMULPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPSZrmbkz, X86_INS_VMULPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPSZrmk, X86_INS_VMULPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPSZrmkz, X86_INS_VMULPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPSZrr, X86_INS_VMULPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPSZrrk, X86_INS_VMULPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPSZrrkz, X86_INS_VMULPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPSrm, X86_INS_VMULPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMULPSrr, X86_INS_VMULPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMULSDZrm, X86_INS_VMULSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMULSDZrr, X86_INS_VMULSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMULSDrm, X86_INS_VMULSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMULSDrm_Int, X86_INS_VMULSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMULSDrr, X86_INS_VMULSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMULSDrr_Int, X86_INS_VMULSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMULSSZrm, X86_INS_VMULSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMULSSZrr, X86_INS_VMULSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VMULSSrm, X86_INS_VMULSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMULSSrm_Int, X86_INS_VMULSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMULSSrr, X86_INS_VMULSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMULSSrr_Int, X86_INS_VMULSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VMWRITE32rm, X86_INS_VMWRITE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_VMWRITE32rr, X86_INS_VMWRITE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_VMWRITE64rm, X86_INS_VMWRITE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_VMWRITE64rr, X86_INS_VMWRITE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_VMXOFF, X86_INS_VMXOFF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_VMXON, X86_INS_VMXON,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_VORPDYrm, X86_INS_VORPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VORPDYrr, X86_INS_VORPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VORPDrm, X86_INS_VORPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VORPDrr, X86_INS_VORPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VORPSYrm, X86_INS_VORPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VORPSYrr, X86_INS_VORPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VORPSrm, X86_INS_VORPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VORPSrr, X86_INS_VORPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSBrm128, X86_INS_VPABSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSBrm256, X86_INS_VPABSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSBrr128, X86_INS_VPABSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSBrr256, X86_INS_VPABSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSDZrm, X86_INS_VPABSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSDZrmb, X86_INS_VPABSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSDZrmbk, X86_INS_VPABSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSDZrmbkz, X86_INS_VPABSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSDZrmk, X86_INS_VPABSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSDZrmkz, X86_INS_VPABSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSDZrr, X86_INS_VPABSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSDZrrk, X86_INS_VPABSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSDZrrkz, X86_INS_VPABSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSDrm128, X86_INS_VPABSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSDrm256, X86_INS_VPABSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSDrr128, X86_INS_VPABSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSDrr256, X86_INS_VPABSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSQZrm, X86_INS_VPABSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSQZrmb, X86_INS_VPABSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSQZrmbk, X86_INS_VPABSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSQZrmbkz, X86_INS_VPABSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSQZrmk, X86_INS_VPABSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSQZrmkz, X86_INS_VPABSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSQZrr, X86_INS_VPABSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSQZrrk, X86_INS_VPABSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSQZrrkz, X86_INS_VPABSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSWrm128, X86_INS_VPABSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSWrm256, X86_INS_VPABSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSWrr128, X86_INS_VPABSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPABSWrr256, X86_INS_VPABSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPACKSSDWYrm, X86_INS_VPACKSSDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPACKSSDWYrr, X86_INS_VPACKSSDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPACKSSDWrm, X86_INS_VPACKSSDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPACKSSDWrr, X86_INS_VPACKSSDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPACKSSWBYrm, X86_INS_VPACKSSWB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPACKSSWBYrr, X86_INS_VPACKSSWB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPACKSSWBrm, X86_INS_VPACKSSWB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPACKSSWBrr, X86_INS_VPACKSSWB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPACKUSDWYrm, X86_INS_VPACKUSDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPACKUSDWYrr, X86_INS_VPACKUSDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPACKUSDWrm, X86_INS_VPACKUSDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPACKUSDWrr, X86_INS_VPACKUSDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPACKUSWBYrm, X86_INS_VPACKUSWB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPACKUSWBYrr, X86_INS_VPACKUSWB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPACKUSWBrm, X86_INS_VPACKUSWB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPACKUSWBrr, X86_INS_VPACKUSWB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDBYrm, X86_INS_VPADDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDBYrr, X86_INS_VPADDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDBrm, X86_INS_VPADDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDBrr, X86_INS_VPADDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDDYrm, X86_INS_VPADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDDYrr, X86_INS_VPADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDDZrm, X86_INS_VPADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDDZrmb, X86_INS_VPADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDDZrmbk, X86_INS_VPADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDDZrmbkz, X86_INS_VPADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDDZrmk, X86_INS_VPADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDDZrmkz, X86_INS_VPADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDDZrr, X86_INS_VPADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDDZrrk, X86_INS_VPADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDDZrrkz, X86_INS_VPADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDDrm, X86_INS_VPADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDDrr, X86_INS_VPADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDQYrm, X86_INS_VPADDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDQYrr, X86_INS_VPADDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDQZrm, X86_INS_VPADDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDQZrmb, X86_INS_VPADDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDQZrmbk, X86_INS_VPADDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDQZrmbkz, X86_INS_VPADDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDQZrmk, X86_INS_VPADDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDQZrmkz, X86_INS_VPADDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDQZrr, X86_INS_VPADDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDQZrrk, X86_INS_VPADDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDQZrrkz, X86_INS_VPADDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDQrm, X86_INS_VPADDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDQrr, X86_INS_VPADDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDSBYrm, X86_INS_VPADDSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDSBYrr, X86_INS_VPADDSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDSBrm, X86_INS_VPADDSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDSBrr, X86_INS_VPADDSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDSWYrm, X86_INS_VPADDSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDSWYrr, X86_INS_VPADDSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDSWrm, X86_INS_VPADDSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDSWrr, X86_INS_VPADDSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDUSBYrm, X86_INS_VPADDUSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDUSBYrr, X86_INS_VPADDUSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDUSBrm, X86_INS_VPADDUSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDUSBrr, X86_INS_VPADDUSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDUSWYrm, X86_INS_VPADDUSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDUSWYrr, X86_INS_VPADDUSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDUSWrm, X86_INS_VPADDUSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDUSWrr, X86_INS_VPADDUSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDWYrm, X86_INS_VPADDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDWYrr, X86_INS_VPADDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDWrm, X86_INS_VPADDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPADDWrr, X86_INS_VPADDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPALIGNR128rm, X86_INS_VPALIGNR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPALIGNR128rr, X86_INS_VPALIGNR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPALIGNR256rm, X86_INS_VPALIGNR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPALIGNR256rr, X86_INS_VPALIGNR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDDZrm, X86_INS_VPANDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDDZrmb, X86_INS_VPANDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDDZrmbk, X86_INS_VPANDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDDZrmbkz, X86_INS_VPANDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDDZrmk, X86_INS_VPANDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDDZrmkz, X86_INS_VPANDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDDZrr, X86_INS_VPANDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDDZrrk, X86_INS_VPANDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDDZrrkz, X86_INS_VPANDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDNDZrm, X86_INS_VPANDND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDNDZrmb, X86_INS_VPANDND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDNDZrmbk, X86_INS_VPANDND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDNDZrmbkz, X86_INS_VPANDND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDNDZrmk, X86_INS_VPANDND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDNDZrmkz, X86_INS_VPANDND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDNDZrr, X86_INS_VPANDND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDNDZrrk, X86_INS_VPANDND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDNDZrrkz, X86_INS_VPANDND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDNQZrm, X86_INS_VPANDNQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDNQZrmb, X86_INS_VPANDNQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDNQZrmbk, X86_INS_VPANDNQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDNQZrmbkz, X86_INS_VPANDNQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDNQZrmk, X86_INS_VPANDNQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDNQZrmkz, X86_INS_VPANDNQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDNQZrr, X86_INS_VPANDNQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDNQZrrk, X86_INS_VPANDNQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDNQZrrkz, X86_INS_VPANDNQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDNYrm, X86_INS_VPANDN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDNYrr, X86_INS_VPANDN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDNrm, X86_INS_VPANDN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDNrr, X86_INS_VPANDN,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDQZrm, X86_INS_VPANDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDQZrmb, X86_INS_VPANDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDQZrmbk, X86_INS_VPANDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDQZrmbkz, X86_INS_VPANDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDQZrmk, X86_INS_VPANDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDQZrmkz, X86_INS_VPANDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDQZrr, X86_INS_VPANDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDQZrrk, X86_INS_VPANDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDQZrrkz, X86_INS_VPANDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDYrm, X86_INS_VPAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDYrr, X86_INS_VPAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDrm, X86_INS_VPAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPANDrr, X86_INS_VPAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPAVGBYrm, X86_INS_VPAVGB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPAVGBYrr, X86_INS_VPAVGB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPAVGBrm, X86_INS_VPAVGB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPAVGBrr, X86_INS_VPAVGB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPAVGWYrm, X86_INS_VPAVGW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPAVGWYrr, X86_INS_VPAVGW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPAVGWrm, X86_INS_VPAVGW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPAVGWrr, X86_INS_VPAVGW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPBLENDDYrmi, X86_INS_VPBLENDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPBLENDDYrri, X86_INS_VPBLENDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPBLENDDrmi, X86_INS_VPBLENDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPBLENDDrri, X86_INS_VPBLENDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPBLENDMDZrm, X86_INS_VPBLENDMD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPBLENDMDZrr, X86_INS_VPBLENDMD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPBLENDMQZrm, X86_INS_VPBLENDMQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPBLENDMQZrr, X86_INS_VPBLENDMQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPBLENDVBYrm, X86_INS_VPBLENDVB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPBLENDVBYrr, X86_INS_VPBLENDVB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPBLENDVBrm, X86_INS_VPBLENDVB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPBLENDVBrr, X86_INS_VPBLENDVB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPBLENDWYrmi, X86_INS_VPBLENDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPBLENDWYrri, X86_INS_VPBLENDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPBLENDWrmi, X86_INS_VPBLENDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPBLENDWrri, X86_INS_VPBLENDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTBYrm, X86_INS_VPBROADCASTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTBYrr, X86_INS_VPBROADCASTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTBrm, X86_INS_VPBROADCASTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTBrr, X86_INS_VPBROADCASTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTDYrm, X86_INS_VPBROADCASTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTDYrr, X86_INS_VPBROADCASTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTDZkrm, X86_INS_VPBROADCASTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTDZkrr, X86_INS_VPBROADCASTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTDZrm, X86_INS_VPBROADCASTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTDZrr, X86_INS_VPBROADCASTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTDrZkrr, X86_INS_VPBROADCASTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTDrZrr, X86_INS_VPBROADCASTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTDrm, X86_INS_VPBROADCASTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTDrr, X86_INS_VPBROADCASTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTMB2Qrr, X86_INS_VPBROADCASTMB2Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTMW2Drr, X86_INS_VPBROADCASTMW2D,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTQYrm, X86_INS_VPBROADCASTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTQYrr, X86_INS_VPBROADCASTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTQZkrm, X86_INS_VPBROADCASTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTQZkrr, X86_INS_VPBROADCASTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTQZrm, X86_INS_VPBROADCASTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTQZrr, X86_INS_VPBROADCASTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTQrZkrr, X86_INS_VPBROADCASTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTQrZrr, X86_INS_VPBROADCASTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTQrm, X86_INS_VPBROADCASTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTQrr, X86_INS_VPBROADCASTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTWYrm, X86_INS_VPBROADCASTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTWYrr, X86_INS_VPBROADCASTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTWrm, X86_INS_VPBROADCASTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPBROADCASTWrr, X86_INS_VPBROADCASTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPCLMULQDQrm, X86_INS_VPCLMULQDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, X86_GRP_PCLMUL, 0 }, 0, 0
#endif
	},
	{
		X86_VPCLMULQDQrr, X86_INS_VPCLMULQDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, X86_GRP_PCLMUL, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMOVmr, X86_INS_VPCMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMOVmrY, X86_INS_VPCMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMOVrm, X86_INS_VPCMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMOVrmY, X86_INS_VPCMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMOVrr, X86_INS_VPCMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMOVrrY, X86_INS_VPCMOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPDZrmi, X86_INS_VPCMPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPDZrmi_alt, X86_INS_VPCMPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPDZrmik_alt, X86_INS_VPCMPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPDZrri, X86_INS_VPCMPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPDZrri_alt, X86_INS_VPCMPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPDZrrik_alt, X86_INS_VPCMPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQBYrm, X86_INS_VPCMPEQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQBYrr, X86_INS_VPCMPEQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQBZ128rm, X86_INS_VPCMPEQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQBZ128rmk, X86_INS_VPCMPEQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQBZ128rr, X86_INS_VPCMPEQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQBZ128rrk, X86_INS_VPCMPEQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQBZ256rm, X86_INS_VPCMPEQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQBZ256rmk, X86_INS_VPCMPEQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQBZ256rr, X86_INS_VPCMPEQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQBZ256rrk, X86_INS_VPCMPEQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQBZrm, X86_INS_VPCMPEQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQBZrmk, X86_INS_VPCMPEQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQBZrr, X86_INS_VPCMPEQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQBZrrk, X86_INS_VPCMPEQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQBrm, X86_INS_VPCMPEQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQBrr, X86_INS_VPCMPEQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQDYrm, X86_INS_VPCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQDYrr, X86_INS_VPCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQDZ128rm, X86_INS_VPCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQDZ128rmb, X86_INS_VPCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQDZ128rmbk, X86_INS_VPCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQDZ128rmk, X86_INS_VPCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQDZ128rr, X86_INS_VPCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQDZ128rrk, X86_INS_VPCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQDZ256rm, X86_INS_VPCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQDZ256rmb, X86_INS_VPCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQDZ256rmbk, X86_INS_VPCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQDZ256rmk, X86_INS_VPCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQDZ256rr, X86_INS_VPCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQDZ256rrk, X86_INS_VPCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQDZrm, X86_INS_VPCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQDZrmb, X86_INS_VPCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQDZrmbk, X86_INS_VPCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQDZrmk, X86_INS_VPCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQDZrr, X86_INS_VPCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQDZrrk, X86_INS_VPCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQDrm, X86_INS_VPCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQDrr, X86_INS_VPCMPEQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQQYrm, X86_INS_VPCMPEQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQQYrr, X86_INS_VPCMPEQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQQZ128rm, X86_INS_VPCMPEQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQQZ128rmb, X86_INS_VPCMPEQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQQZ128rmbk, X86_INS_VPCMPEQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQQZ128rmk, X86_INS_VPCMPEQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQQZ128rr, X86_INS_VPCMPEQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQQZ128rrk, X86_INS_VPCMPEQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQQZ256rm, X86_INS_VPCMPEQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQQZ256rmb, X86_INS_VPCMPEQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQQZ256rmbk, X86_INS_VPCMPEQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQQZ256rmk, X86_INS_VPCMPEQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQQZ256rr, X86_INS_VPCMPEQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQQZ256rrk, X86_INS_VPCMPEQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQQZrm, X86_INS_VPCMPEQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQQZrmb, X86_INS_VPCMPEQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQQZrmbk, X86_INS_VPCMPEQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQQZrmk, X86_INS_VPCMPEQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQQZrr, X86_INS_VPCMPEQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQQZrrk, X86_INS_VPCMPEQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQQrm, X86_INS_VPCMPEQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQQrr, X86_INS_VPCMPEQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQWYrm, X86_INS_VPCMPEQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQWYrr, X86_INS_VPCMPEQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQWZ128rm, X86_INS_VPCMPEQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQWZ128rmk, X86_INS_VPCMPEQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQWZ128rr, X86_INS_VPCMPEQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQWZ128rrk, X86_INS_VPCMPEQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQWZ256rm, X86_INS_VPCMPEQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQWZ256rmk, X86_INS_VPCMPEQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQWZ256rr, X86_INS_VPCMPEQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQWZ256rrk, X86_INS_VPCMPEQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQWZrm, X86_INS_VPCMPEQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQWZrmk, X86_INS_VPCMPEQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQWZrr, X86_INS_VPCMPEQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQWZrrk, X86_INS_VPCMPEQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQWrm, X86_INS_VPCMPEQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPEQWrr, X86_INS_VPCMPEQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPESTRIrm, X86_INS_VPCMPESTRI,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_EDX, 0 }, { X86_REG_ECX, X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPESTRIrr, X86_INS_VPCMPESTRI,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_EDX, 0 }, { X86_REG_ECX, X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPESTRM128rm, X86_INS_VPCMPESTRM,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_EDX, 0 }, { X86_REG_XMM0, X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPESTRM128rr, X86_INS_VPCMPESTRM,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_EDX, 0 }, { X86_REG_XMM0, X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTBYrm, X86_INS_VPCMPGTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTBYrr, X86_INS_VPCMPGTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTBZ128rm, X86_INS_VPCMPGTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTBZ128rmk, X86_INS_VPCMPGTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTBZ128rr, X86_INS_VPCMPGTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTBZ128rrk, X86_INS_VPCMPGTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTBZ256rm, X86_INS_VPCMPGTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTBZ256rmk, X86_INS_VPCMPGTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTBZ256rr, X86_INS_VPCMPGTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTBZ256rrk, X86_INS_VPCMPGTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTBZrm, X86_INS_VPCMPGTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTBZrmk, X86_INS_VPCMPGTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTBZrr, X86_INS_VPCMPGTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTBZrrk, X86_INS_VPCMPGTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTBrm, X86_INS_VPCMPGTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTBrr, X86_INS_VPCMPGTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTDYrm, X86_INS_VPCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTDYrr, X86_INS_VPCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTDZ128rm, X86_INS_VPCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTDZ128rmb, X86_INS_VPCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTDZ128rmbk, X86_INS_VPCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTDZ128rmk, X86_INS_VPCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTDZ128rr, X86_INS_VPCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTDZ128rrk, X86_INS_VPCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTDZ256rm, X86_INS_VPCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTDZ256rmb, X86_INS_VPCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTDZ256rmbk, X86_INS_VPCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTDZ256rmk, X86_INS_VPCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTDZ256rr, X86_INS_VPCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTDZ256rrk, X86_INS_VPCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTDZrm, X86_INS_VPCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTDZrmb, X86_INS_VPCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTDZrmbk, X86_INS_VPCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTDZrmk, X86_INS_VPCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTDZrr, X86_INS_VPCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTDZrrk, X86_INS_VPCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTDrm, X86_INS_VPCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTDrr, X86_INS_VPCMPGTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTQYrm, X86_INS_VPCMPGTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTQYrr, X86_INS_VPCMPGTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTQZ128rm, X86_INS_VPCMPGTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTQZ128rmb, X86_INS_VPCMPGTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTQZ128rmbk, X86_INS_VPCMPGTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTQZ128rmk, X86_INS_VPCMPGTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTQZ128rr, X86_INS_VPCMPGTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTQZ128rrk, X86_INS_VPCMPGTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTQZ256rm, X86_INS_VPCMPGTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTQZ256rmb, X86_INS_VPCMPGTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTQZ256rmbk, X86_INS_VPCMPGTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTQZ256rmk, X86_INS_VPCMPGTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTQZ256rr, X86_INS_VPCMPGTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTQZ256rrk, X86_INS_VPCMPGTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTQZrm, X86_INS_VPCMPGTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTQZrmb, X86_INS_VPCMPGTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTQZrmbk, X86_INS_VPCMPGTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTQZrmk, X86_INS_VPCMPGTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTQZrr, X86_INS_VPCMPGTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTQZrrk, X86_INS_VPCMPGTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTQrm, X86_INS_VPCMPGTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTQrr, X86_INS_VPCMPGTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTWYrm, X86_INS_VPCMPGTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTWYrr, X86_INS_VPCMPGTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTWZ128rm, X86_INS_VPCMPGTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTWZ128rmk, X86_INS_VPCMPGTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTWZ128rr, X86_INS_VPCMPGTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTWZ128rrk, X86_INS_VPCMPGTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTWZ256rm, X86_INS_VPCMPGTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTWZ256rmk, X86_INS_VPCMPGTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTWZ256rr, X86_INS_VPCMPGTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTWZ256rrk, X86_INS_VPCMPGTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, X86_GRP_VLX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTWZrm, X86_INS_VPCMPGTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTWZrmk, X86_INS_VPCMPGTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTWZrr, X86_INS_VPCMPGTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTWZrrk, X86_INS_VPCMPGTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BWI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTWrm, X86_INS_VPCMPGTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPGTWrr, X86_INS_VPCMPGTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPISTRIrm, X86_INS_VPCMPISTRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_ECX, X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPISTRIrr, X86_INS_VPCMPISTRI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_ECX, X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPISTRM128rm, X86_INS_VPCMPISTRM,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_XMM0, X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPISTRM128rr, X86_INS_VPCMPISTRM,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_XMM0, X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPQZrmi, X86_INS_VPCMPQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPQZrmi_alt, X86_INS_VPCMPQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPQZrmik_alt, X86_INS_VPCMPQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPQZrri, X86_INS_VPCMPQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPQZrri_alt, X86_INS_VPCMPQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPQZrrik_alt, X86_INS_VPCMPQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPUDZrmi, X86_INS_VPCMPUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPUDZrmi_alt, X86_INS_VPCMPUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPUDZrmik_alt, X86_INS_VPCMPUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPUDZrri, X86_INS_VPCMPUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPUDZrri_alt, X86_INS_VPCMPUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPUDZrrik_alt, X86_INS_VPCMPUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPUQZrmi, X86_INS_VPCMPUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPUQZrmi_alt, X86_INS_VPCMPUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPUQZrmik_alt, X86_INS_VPCMPUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPUQZrri, X86_INS_VPCMPUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPUQZrri_alt, X86_INS_VPCMPUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCMPUQZrrik_alt, X86_INS_VPCMPUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPCOMBmi, X86_INS_VPCOMB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPCOMBri, X86_INS_VPCOMB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPCOMDmi, X86_INS_VPCOMD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPCOMDri, X86_INS_VPCOMD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPCOMQmi, X86_INS_VPCOMQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPCOMQri, X86_INS_VPCOMQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPCOMUBmi, X86_INS_VPCOMUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPCOMUBri, X86_INS_VPCOMUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPCOMUDmi, X86_INS_VPCOMUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPCOMUDri, X86_INS_VPCOMUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPCOMUQmi, X86_INS_VPCOMUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPCOMUQri, X86_INS_VPCOMUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPCOMUWmi, X86_INS_VPCOMUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPCOMUWri, X86_INS_VPCOMUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPCOMWmi, X86_INS_VPCOMW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPCOMWri, X86_INS_VPCOMW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPCONFLICTDrm, X86_INS_VPCONFLICTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCONFLICTDrmb, X86_INS_VPCONFLICTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCONFLICTDrmbk, X86_INS_VPCONFLICTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCONFLICTDrmbkz, X86_INS_VPCONFLICTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCONFLICTDrmk, X86_INS_VPCONFLICTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCONFLICTDrmkz, X86_INS_VPCONFLICTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCONFLICTDrr, X86_INS_VPCONFLICTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCONFLICTDrrk, X86_INS_VPCONFLICTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCONFLICTDrrkz, X86_INS_VPCONFLICTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCONFLICTQrm, X86_INS_VPCONFLICTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCONFLICTQrmb, X86_INS_VPCONFLICTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCONFLICTQrmbk, X86_INS_VPCONFLICTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCONFLICTQrmbkz, X86_INS_VPCONFLICTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCONFLICTQrmk, X86_INS_VPCONFLICTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCONFLICTQrmkz, X86_INS_VPCONFLICTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCONFLICTQrr, X86_INS_VPCONFLICTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCONFLICTQrrk, X86_INS_VPCONFLICTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPCONFLICTQrrkz, X86_INS_VPCONFLICTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPERM2F128rm, X86_INS_VPERM2F128,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPERM2F128rr, X86_INS_VPERM2F128,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPERM2I128rm, X86_INS_VPERM2I128,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPERM2I128rr, X86_INS_VPERM2I128,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMDYrm, X86_INS_VPERMD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMDYrr, X86_INS_VPERMD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMDZrm, X86_INS_VPERMD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMDZrr, X86_INS_VPERMD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMI2Drm, X86_INS_VPERMI2D,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMI2Drmk, X86_INS_VPERMI2D,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMI2Drmkz, X86_INS_VPERMI2D,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMI2Drr, X86_INS_VPERMI2D,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMI2Drrk, X86_INS_VPERMI2D,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMI2Drrkz, X86_INS_VPERMI2D,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMI2PDrm, X86_INS_VPERMI2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMI2PDrmk, X86_INS_VPERMI2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMI2PDrmkz, X86_INS_VPERMI2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMI2PDrr, X86_INS_VPERMI2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMI2PDrrk, X86_INS_VPERMI2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMI2PDrrkz, X86_INS_VPERMI2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMI2PSrm, X86_INS_VPERMI2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMI2PSrmk, X86_INS_VPERMI2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMI2PSrmkz, X86_INS_VPERMI2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMI2PSrr, X86_INS_VPERMI2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMI2PSrrk, X86_INS_VPERMI2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMI2PSrrkz, X86_INS_VPERMI2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMI2Qrm, X86_INS_VPERMI2Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMI2Qrmk, X86_INS_VPERMI2Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMI2Qrmkz, X86_INS_VPERMI2Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMI2Qrr, X86_INS_VPERMI2Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMI2Qrrk, X86_INS_VPERMI2Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMI2Qrrkz, X86_INS_VPERMI2Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMIL2PDmr, X86_INS_VPERMIL2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMIL2PDmrY, X86_INS_VPERMIL2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMIL2PDrm, X86_INS_VPERMIL2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMIL2PDrmY, X86_INS_VPERMIL2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMIL2PDrr, X86_INS_VPERMIL2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMIL2PDrrY, X86_INS_VPERMIL2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMIL2PSmr, X86_INS_VPERMIL2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMIL2PSmrY, X86_INS_VPERMIL2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMIL2PSrm, X86_INS_VPERMIL2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMIL2PSrmY, X86_INS_VPERMIL2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMIL2PSrr, X86_INS_VPERMIL2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMIL2PSrrY, X86_INS_VPERMIL2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMILPDYmi, X86_INS_VPERMILPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMILPDYri, X86_INS_VPERMILPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMILPDYrm, X86_INS_VPERMILPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMILPDYrr, X86_INS_VPERMILPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMILPDZmi, X86_INS_VPERMILPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMILPDZri, X86_INS_VPERMILPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMILPDmi, X86_INS_VPERMILPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMILPDri, X86_INS_VPERMILPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMILPDrm, X86_INS_VPERMILPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMILPDrr, X86_INS_VPERMILPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMILPSYmi, X86_INS_VPERMILPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMILPSYri, X86_INS_VPERMILPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMILPSYrm, X86_INS_VPERMILPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMILPSYrr, X86_INS_VPERMILPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMILPSZmi, X86_INS_VPERMILPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMILPSZri, X86_INS_VPERMILPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMILPSmi, X86_INS_VPERMILPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMILPSri, X86_INS_VPERMILPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMILPSrm, X86_INS_VPERMILPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMILPSrr, X86_INS_VPERMILPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMPDYmi, X86_INS_VPERMPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMPDYri, X86_INS_VPERMPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMPDZmi, X86_INS_VPERMPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMPDZri, X86_INS_VPERMPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMPDZrm, X86_INS_VPERMPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMPDZrr, X86_INS_VPERMPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMPSYrm, X86_INS_VPERMPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMPSYrr, X86_INS_VPERMPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMPSZrm, X86_INS_VPERMPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMPSZrr, X86_INS_VPERMPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMQYmi, X86_INS_VPERMQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMQYri, X86_INS_VPERMQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMQZmi, X86_INS_VPERMQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMQZri, X86_INS_VPERMQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMQZrm, X86_INS_VPERMQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMQZrr, X86_INS_VPERMQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMT2Drm, X86_INS_VPERMT2D,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMT2Drmk, X86_INS_VPERMT2D,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMT2Drmkz, X86_INS_VPERMT2D,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMT2Drr, X86_INS_VPERMT2D,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMT2Drrk, X86_INS_VPERMT2D,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMT2Drrkz, X86_INS_VPERMT2D,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMT2PDrm, X86_INS_VPERMT2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMT2PDrmk, X86_INS_VPERMT2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMT2PDrmkz, X86_INS_VPERMT2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMT2PDrr, X86_INS_VPERMT2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMT2PDrrk, X86_INS_VPERMT2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMT2PDrrkz, X86_INS_VPERMT2PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMT2PSrm, X86_INS_VPERMT2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMT2PSrmk, X86_INS_VPERMT2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMT2PSrmkz, X86_INS_VPERMT2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMT2PSrr, X86_INS_VPERMT2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMT2PSrrk, X86_INS_VPERMT2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMT2PSrrkz, X86_INS_VPERMT2PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMT2Qrm, X86_INS_VPERMT2Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMT2Qrmk, X86_INS_VPERMT2Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMT2Qrmkz, X86_INS_VPERMT2Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMT2Qrr, X86_INS_VPERMT2Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMT2Qrrk, X86_INS_VPERMT2Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPERMT2Qrrkz, X86_INS_VPERMT2Q,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPEXTRBmr, X86_INS_VPEXTRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPEXTRBrr, X86_INS_VPEXTRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPEXTRDmr, X86_INS_VPEXTRD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPEXTRDrr, X86_INS_VPEXTRD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPEXTRQmr, X86_INS_VPEXTRQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPEXTRQrr, X86_INS_VPEXTRQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPEXTRWmr, X86_INS_VPEXTRW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPEXTRWri, X86_INS_VPEXTRW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPEXTRWrr_REV, X86_INS_VPEXTRW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPGATHERDDYrm, X86_INS_VPGATHERDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPGATHERDDZrm, X86_INS_VPGATHERDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPGATHERDDrm, X86_INS_VPGATHERDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPGATHERDQYrm, X86_INS_VPGATHERDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPGATHERDQZrm, X86_INS_VPGATHERDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPGATHERDQrm, X86_INS_VPGATHERDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPGATHERQDYrm, X86_INS_VPGATHERQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPGATHERQDZrm, X86_INS_VPGATHERQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPGATHERQDrm, X86_INS_VPGATHERQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPGATHERQQYrm, X86_INS_VPGATHERQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPGATHERQQZrm, X86_INS_VPGATHERQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPGATHERQQrm, X86_INS_VPGATHERQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDBDrm, X86_INS_VPHADDBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDBDrr, X86_INS_VPHADDBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDBQrm, X86_INS_VPHADDBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDBQrr, X86_INS_VPHADDBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDBWrm, X86_INS_VPHADDBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDBWrr, X86_INS_VPHADDBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDDQrm, X86_INS_VPHADDDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDDQrr, X86_INS_VPHADDDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDDYrm, X86_INS_VPHADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDDYrr, X86_INS_VPHADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDDrm, X86_INS_VPHADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDDrr, X86_INS_VPHADDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDSWrm128, X86_INS_VPHADDSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDSWrm256, X86_INS_VPHADDSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDSWrr128, X86_INS_VPHADDSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDSWrr256, X86_INS_VPHADDSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDUBDrm, X86_INS_VPHADDUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDUBDrr, X86_INS_VPHADDUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDUBQrm, X86_INS_VPHADDUBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDUBQrr, X86_INS_VPHADDUBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDUBWrm, X86_INS_VPHADDUBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDUBWrr, X86_INS_VPHADDUBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDUDQrm, X86_INS_VPHADDUDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDUDQrr, X86_INS_VPHADDUDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDUWDrm, X86_INS_VPHADDUWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDUWDrr, X86_INS_VPHADDUWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDUWQrm, X86_INS_VPHADDUWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDUWQrr, X86_INS_VPHADDUWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDWDrm, X86_INS_VPHADDWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDWDrr, X86_INS_VPHADDWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDWQrm, X86_INS_VPHADDWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDWQrr, X86_INS_VPHADDWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDWYrm, X86_INS_VPHADDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDWYrr, X86_INS_VPHADDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDWrm, X86_INS_VPHADDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPHADDWrr, X86_INS_VPHADDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPHMINPOSUWrm128, X86_INS_VPHMINPOSUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPHMINPOSUWrr128, X86_INS_VPHMINPOSUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPHSUBBWrm, X86_INS_VPHSUBBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHSUBBWrr, X86_INS_VPHSUBBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHSUBDQrm, X86_INS_VPHSUBDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHSUBDQrr, X86_INS_VPHSUBDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHSUBDYrm, X86_INS_VPHSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPHSUBDYrr, X86_INS_VPHSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPHSUBDrm, X86_INS_VPHSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPHSUBDrr, X86_INS_VPHSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPHSUBSWrm128, X86_INS_VPHSUBSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPHSUBSWrm256, X86_INS_VPHSUBSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPHSUBSWrr128, X86_INS_VPHSUBSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPHSUBSWrr256, X86_INS_VPHSUBSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPHSUBWDrm, X86_INS_VPHSUBWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHSUBWDrr, X86_INS_VPHSUBWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPHSUBWYrm, X86_INS_VPHSUBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPHSUBWYrr, X86_INS_VPHSUBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPHSUBWrm, X86_INS_VPHSUBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPHSUBWrr, X86_INS_VPHSUBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPINSRBrm, X86_INS_VPINSRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPINSRBrr, X86_INS_VPINSRB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPINSRDrm, X86_INS_VPINSRD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPINSRDrr, X86_INS_VPINSRD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPINSRQrm, X86_INS_VPINSRQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPINSRQrr, X86_INS_VPINSRQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPINSRWrmi, X86_INS_VPINSRW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPINSRWrri, X86_INS_VPINSRW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPLZCNTDrm, X86_INS_VPLZCNTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPLZCNTDrmb, X86_INS_VPLZCNTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPLZCNTDrmbk, X86_INS_VPLZCNTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPLZCNTDrmbkz, X86_INS_VPLZCNTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPLZCNTDrmk, X86_INS_VPLZCNTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPLZCNTDrmkz, X86_INS_VPLZCNTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPLZCNTDrr, X86_INS_VPLZCNTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPLZCNTDrrk, X86_INS_VPLZCNTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPLZCNTDrrkz, X86_INS_VPLZCNTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPLZCNTQrm, X86_INS_VPLZCNTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPLZCNTQrmb, X86_INS_VPLZCNTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPLZCNTQrmbk, X86_INS_VPLZCNTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPLZCNTQrmbkz, X86_INS_VPLZCNTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPLZCNTQrmk, X86_INS_VPLZCNTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPLZCNTQrmkz, X86_INS_VPLZCNTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPLZCNTQrr, X86_INS_VPLZCNTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPLZCNTQrrk, X86_INS_VPLZCNTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPLZCNTQrrkz, X86_INS_VPLZCNTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPMACSDDrm, X86_INS_VPMACSDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPMACSDDrr, X86_INS_VPMACSDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPMACSDQHrm, X86_INS_VPMACSDQH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPMACSDQHrr, X86_INS_VPMACSDQH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPMACSDQLrm, X86_INS_VPMACSDQL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPMACSDQLrr, X86_INS_VPMACSDQL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPMACSSDDrm, X86_INS_VPMACSSDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPMACSSDDrr, X86_INS_VPMACSSDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPMACSSDQHrm, X86_INS_VPMACSSDQH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPMACSSDQHrr, X86_INS_VPMACSSDQH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPMACSSDQLrm, X86_INS_VPMACSSDQL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPMACSSDQLrr, X86_INS_VPMACSSDQL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPMACSSWDrm, X86_INS_VPMACSSWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPMACSSWDrr, X86_INS_VPMACSSWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPMACSSWWrm, X86_INS_VPMACSSWW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPMACSSWWrr, X86_INS_VPMACSSWW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPMACSWDrm, X86_INS_VPMACSWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPMACSWDrr, X86_INS_VPMACSWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPMACSWWrm, X86_INS_VPMACSWW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPMACSWWrr, X86_INS_VPMACSWW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPMADCSSWDrm, X86_INS_VPMADCSSWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPMADCSSWDrr, X86_INS_VPMADCSSWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPMADCSWDrm, X86_INS_VPMADCSWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPMADCSWDrr, X86_INS_VPMADCSWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPMADDUBSWrm128, X86_INS_VPMADDUBSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMADDUBSWrm256, X86_INS_VPMADDUBSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMADDUBSWrr128, X86_INS_VPMADDUBSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMADDUBSWrr256, X86_INS_VPMADDUBSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMADDWDYrm, X86_INS_VPMADDWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMADDWDYrr, X86_INS_VPMADDWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMADDWDrm, X86_INS_VPMADDWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMADDWDrr, X86_INS_VPMADDWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMASKMOVDYmr, X86_INS_VPMASKMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMASKMOVDYrm, X86_INS_VPMASKMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMASKMOVDmr, X86_INS_VPMASKMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMASKMOVDrm, X86_INS_VPMASKMOVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMASKMOVQYmr, X86_INS_VPMASKMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMASKMOVQYrm, X86_INS_VPMASKMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMASKMOVQmr, X86_INS_VPMASKMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMASKMOVQrm, X86_INS_VPMASKMOVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSBYrm, X86_INS_VPMAXSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSBYrr, X86_INS_VPMAXSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSBrm, X86_INS_VPMAXSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSBrr, X86_INS_VPMAXSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSDYrm, X86_INS_VPMAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSDYrr, X86_INS_VPMAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSDZrm, X86_INS_VPMAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSDZrmb, X86_INS_VPMAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSDZrmbk, X86_INS_VPMAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSDZrmbkz, X86_INS_VPMAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSDZrmk, X86_INS_VPMAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSDZrmkz, X86_INS_VPMAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSDZrr, X86_INS_VPMAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSDZrrk, X86_INS_VPMAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSDZrrkz, X86_INS_VPMAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSDrm, X86_INS_VPMAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSDrr, X86_INS_VPMAXSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSQZrm, X86_INS_VPMAXSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSQZrmb, X86_INS_VPMAXSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSQZrmbk, X86_INS_VPMAXSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSQZrmbkz, X86_INS_VPMAXSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSQZrmk, X86_INS_VPMAXSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSQZrmkz, X86_INS_VPMAXSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSQZrr, X86_INS_VPMAXSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSQZrrk, X86_INS_VPMAXSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSQZrrkz, X86_INS_VPMAXSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSWYrm, X86_INS_VPMAXSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSWYrr, X86_INS_VPMAXSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSWrm, X86_INS_VPMAXSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXSWrr, X86_INS_VPMAXSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUBYrm, X86_INS_VPMAXUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUBYrr, X86_INS_VPMAXUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUBrm, X86_INS_VPMAXUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUBrr, X86_INS_VPMAXUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUDYrm, X86_INS_VPMAXUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUDYrr, X86_INS_VPMAXUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUDZrm, X86_INS_VPMAXUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUDZrmb, X86_INS_VPMAXUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUDZrmbk, X86_INS_VPMAXUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUDZrmbkz, X86_INS_VPMAXUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUDZrmk, X86_INS_VPMAXUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUDZrmkz, X86_INS_VPMAXUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUDZrr, X86_INS_VPMAXUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUDZrrk, X86_INS_VPMAXUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUDZrrkz, X86_INS_VPMAXUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUDrm, X86_INS_VPMAXUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUDrr, X86_INS_VPMAXUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUQZrm, X86_INS_VPMAXUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUQZrmb, X86_INS_VPMAXUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUQZrmbk, X86_INS_VPMAXUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUQZrmbkz, X86_INS_VPMAXUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUQZrmk, X86_INS_VPMAXUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUQZrmkz, X86_INS_VPMAXUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUQZrr, X86_INS_VPMAXUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUQZrrk, X86_INS_VPMAXUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUQZrrkz, X86_INS_VPMAXUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUWYrm, X86_INS_VPMAXUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUWYrr, X86_INS_VPMAXUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUWrm, X86_INS_VPMAXUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMAXUWrr, X86_INS_VPMAXUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSBYrm, X86_INS_VPMINSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSBYrr, X86_INS_VPMINSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSBrm, X86_INS_VPMINSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSBrr, X86_INS_VPMINSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSDYrm, X86_INS_VPMINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSDYrr, X86_INS_VPMINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSDZrm, X86_INS_VPMINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSDZrmb, X86_INS_VPMINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSDZrmbk, X86_INS_VPMINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSDZrmbkz, X86_INS_VPMINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSDZrmk, X86_INS_VPMINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSDZrmkz, X86_INS_VPMINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSDZrr, X86_INS_VPMINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSDZrrk, X86_INS_VPMINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSDZrrkz, X86_INS_VPMINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSDrm, X86_INS_VPMINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSDrr, X86_INS_VPMINSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSQZrm, X86_INS_VPMINSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSQZrmb, X86_INS_VPMINSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSQZrmbk, X86_INS_VPMINSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSQZrmbkz, X86_INS_VPMINSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSQZrmk, X86_INS_VPMINSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSQZrmkz, X86_INS_VPMINSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSQZrr, X86_INS_VPMINSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSQZrrk, X86_INS_VPMINSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSQZrrkz, X86_INS_VPMINSQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSWYrm, X86_INS_VPMINSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSWYrr, X86_INS_VPMINSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSWrm, X86_INS_VPMINSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINSWrr, X86_INS_VPMINSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUBYrm, X86_INS_VPMINUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUBYrr, X86_INS_VPMINUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUBrm, X86_INS_VPMINUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUBrr, X86_INS_VPMINUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUDYrm, X86_INS_VPMINUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUDYrr, X86_INS_VPMINUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUDZrm, X86_INS_VPMINUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUDZrmb, X86_INS_VPMINUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUDZrmbk, X86_INS_VPMINUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUDZrmbkz, X86_INS_VPMINUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUDZrmk, X86_INS_VPMINUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUDZrmkz, X86_INS_VPMINUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUDZrr, X86_INS_VPMINUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUDZrrk, X86_INS_VPMINUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUDZrrkz, X86_INS_VPMINUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUDrm, X86_INS_VPMINUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUDrr, X86_INS_VPMINUD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUQZrm, X86_INS_VPMINUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUQZrmb, X86_INS_VPMINUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUQZrmbk, X86_INS_VPMINUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUQZrmbkz, X86_INS_VPMINUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUQZrmk, X86_INS_VPMINUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUQZrmkz, X86_INS_VPMINUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUQZrr, X86_INS_VPMINUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUQZrrk, X86_INS_VPMINUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUQZrrkz, X86_INS_VPMINUQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUWYrm, X86_INS_VPMINUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUWYrr, X86_INS_VPMINUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUWrm, X86_INS_VPMINUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMINUWrr, X86_INS_VPMINUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVDBmr, X86_INS_VPMOVDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVDBmrk, X86_INS_VPMOVDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVDBrr, X86_INS_VPMOVDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVDBrrk, X86_INS_VPMOVDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVDBrrkz, X86_INS_VPMOVDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVDWmr, X86_INS_VPMOVDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVDWmrk, X86_INS_VPMOVDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVDWrr, X86_INS_VPMOVDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVDWrrk, X86_INS_VPMOVDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVDWrrkz, X86_INS_VPMOVDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVMSKBYrr, X86_INS_VPMOVMSKB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVMSKBrr, X86_INS_VPMOVMSKB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVQBmr, X86_INS_VPMOVQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVQBmrk, X86_INS_VPMOVQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVQBrr, X86_INS_VPMOVQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVQBrrk, X86_INS_VPMOVQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVQBrrkz, X86_INS_VPMOVQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVQDmr, X86_INS_VPMOVQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVQDmrk, X86_INS_VPMOVQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVQDrr, X86_INS_VPMOVQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVQDrrk, X86_INS_VPMOVQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVQDrrkz, X86_INS_VPMOVQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVQWmr, X86_INS_VPMOVQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVQWmrk, X86_INS_VPMOVQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVQWrr, X86_INS_VPMOVQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVQWrrk, X86_INS_VPMOVQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVQWrrkz, X86_INS_VPMOVQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSDBmr, X86_INS_VPMOVSDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSDBmrk, X86_INS_VPMOVSDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSDBrr, X86_INS_VPMOVSDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSDBrrk, X86_INS_VPMOVSDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSDBrrkz, X86_INS_VPMOVSDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSDWmr, X86_INS_VPMOVSDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSDWmrk, X86_INS_VPMOVSDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSDWrr, X86_INS_VPMOVSDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSDWrrk, X86_INS_VPMOVSDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSDWrrkz, X86_INS_VPMOVSDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSQBmr, X86_INS_VPMOVSQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSQBmrk, X86_INS_VPMOVSQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSQBrr, X86_INS_VPMOVSQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSQBrrk, X86_INS_VPMOVSQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSQBrrkz, X86_INS_VPMOVSQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSQDmr, X86_INS_VPMOVSQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSQDmrk, X86_INS_VPMOVSQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSQDrr, X86_INS_VPMOVSQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSQDrrk, X86_INS_VPMOVSQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSQDrrkz, X86_INS_VPMOVSQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSQWmr, X86_INS_VPMOVSQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSQWmrk, X86_INS_VPMOVSQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSQWrr, X86_INS_VPMOVSQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSQWrrk, X86_INS_VPMOVSQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSQWrrkz, X86_INS_VPMOVSQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXBDYrm, X86_INS_VPMOVSXBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXBDYrr, X86_INS_VPMOVSXBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXBDZrm, X86_INS_VPMOVSXBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXBDZrmk, X86_INS_VPMOVSXBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXBDZrmkz, X86_INS_VPMOVSXBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXBDZrr, X86_INS_VPMOVSXBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXBDZrrk, X86_INS_VPMOVSXBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXBDZrrkz, X86_INS_VPMOVSXBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXBDrm, X86_INS_VPMOVSXBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXBDrr, X86_INS_VPMOVSXBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXBQYrm, X86_INS_VPMOVSXBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXBQYrr, X86_INS_VPMOVSXBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXBQZrm, X86_INS_VPMOVSXBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXBQZrmk, X86_INS_VPMOVSXBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXBQZrmkz, X86_INS_VPMOVSXBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXBQZrr, X86_INS_VPMOVSXBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXBQZrrk, X86_INS_VPMOVSXBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXBQZrrkz, X86_INS_VPMOVSXBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXBQrm, X86_INS_VPMOVSXBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXBQrr, X86_INS_VPMOVSXBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXBWYrm, X86_INS_VPMOVSXBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXBWYrr, X86_INS_VPMOVSXBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXBWrm, X86_INS_VPMOVSXBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXBWrr, X86_INS_VPMOVSXBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXDQYrm, X86_INS_VPMOVSXDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXDQYrr, X86_INS_VPMOVSXDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXDQZrm, X86_INS_VPMOVSXDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXDQZrmk, X86_INS_VPMOVSXDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXDQZrmkz, X86_INS_VPMOVSXDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXDQZrr, X86_INS_VPMOVSXDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXDQZrrk, X86_INS_VPMOVSXDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXDQZrrkz, X86_INS_VPMOVSXDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXDQrm, X86_INS_VPMOVSXDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXDQrr, X86_INS_VPMOVSXDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXWDYrm, X86_INS_VPMOVSXWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXWDYrr, X86_INS_VPMOVSXWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXWDZrm, X86_INS_VPMOVSXWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXWDZrmk, X86_INS_VPMOVSXWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXWDZrmkz, X86_INS_VPMOVSXWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXWDZrr, X86_INS_VPMOVSXWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXWDZrrk, X86_INS_VPMOVSXWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXWDZrrkz, X86_INS_VPMOVSXWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXWDrm, X86_INS_VPMOVSXWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXWDrr, X86_INS_VPMOVSXWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXWQYrm, X86_INS_VPMOVSXWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXWQYrr, X86_INS_VPMOVSXWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXWQZrm, X86_INS_VPMOVSXWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXWQZrmk, X86_INS_VPMOVSXWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXWQZrmkz, X86_INS_VPMOVSXWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXWQZrr, X86_INS_VPMOVSXWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXWQZrrk, X86_INS_VPMOVSXWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXWQZrrkz, X86_INS_VPMOVSXWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXWQrm, X86_INS_VPMOVSXWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVSXWQrr, X86_INS_VPMOVSXWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVUSDBmr, X86_INS_VPMOVUSDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVUSDBmrk, X86_INS_VPMOVUSDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVUSDBrr, X86_INS_VPMOVUSDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVUSDBrrk, X86_INS_VPMOVUSDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVUSDBrrkz, X86_INS_VPMOVUSDB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVUSDWmr, X86_INS_VPMOVUSDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVUSDWmrk, X86_INS_VPMOVUSDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVUSDWrr, X86_INS_VPMOVUSDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVUSDWrrk, X86_INS_VPMOVUSDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVUSDWrrkz, X86_INS_VPMOVUSDW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVUSQBmr, X86_INS_VPMOVUSQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVUSQBmrk, X86_INS_VPMOVUSQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVUSQBrr, X86_INS_VPMOVUSQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVUSQBrrk, X86_INS_VPMOVUSQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVUSQBrrkz, X86_INS_VPMOVUSQB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVUSQDmr, X86_INS_VPMOVUSQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVUSQDmrk, X86_INS_VPMOVUSQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVUSQDrr, X86_INS_VPMOVUSQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVUSQDrrk, X86_INS_VPMOVUSQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVUSQDrrkz, X86_INS_VPMOVUSQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVUSQWmr, X86_INS_VPMOVUSQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVUSQWmrk, X86_INS_VPMOVUSQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVUSQWrr, X86_INS_VPMOVUSQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVUSQWrrk, X86_INS_VPMOVUSQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVUSQWrrkz, X86_INS_VPMOVUSQW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXBDYrm, X86_INS_VPMOVZXBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXBDYrr, X86_INS_VPMOVZXBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXBDZrm, X86_INS_VPMOVZXBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXBDZrmk, X86_INS_VPMOVZXBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXBDZrmkz, X86_INS_VPMOVZXBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXBDZrr, X86_INS_VPMOVZXBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXBDZrrk, X86_INS_VPMOVZXBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXBDZrrkz, X86_INS_VPMOVZXBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXBDrm, X86_INS_VPMOVZXBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXBDrr, X86_INS_VPMOVZXBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXBQYrm, X86_INS_VPMOVZXBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXBQYrr, X86_INS_VPMOVZXBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXBQZrm, X86_INS_VPMOVZXBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXBQZrmk, X86_INS_VPMOVZXBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXBQZrmkz, X86_INS_VPMOVZXBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXBQZrr, X86_INS_VPMOVZXBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXBQZrrk, X86_INS_VPMOVZXBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXBQZrrkz, X86_INS_VPMOVZXBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXBQrm, X86_INS_VPMOVZXBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXBQrr, X86_INS_VPMOVZXBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXBWYrm, X86_INS_VPMOVZXBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXBWYrr, X86_INS_VPMOVZXBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXBWrm, X86_INS_VPMOVZXBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXBWrr, X86_INS_VPMOVZXBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXDQYrm, X86_INS_VPMOVZXDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXDQYrr, X86_INS_VPMOVZXDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXDQZrm, X86_INS_VPMOVZXDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXDQZrmk, X86_INS_VPMOVZXDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXDQZrmkz, X86_INS_VPMOVZXDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXDQZrr, X86_INS_VPMOVZXDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXDQZrrk, X86_INS_VPMOVZXDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXDQZrrkz, X86_INS_VPMOVZXDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXDQrm, X86_INS_VPMOVZXDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXDQrr, X86_INS_VPMOVZXDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXWDYrm, X86_INS_VPMOVZXWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXWDYrr, X86_INS_VPMOVZXWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXWDZrm, X86_INS_VPMOVZXWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXWDZrmk, X86_INS_VPMOVZXWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXWDZrmkz, X86_INS_VPMOVZXWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXWDZrr, X86_INS_VPMOVZXWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXWDZrrk, X86_INS_VPMOVZXWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXWDZrrkz, X86_INS_VPMOVZXWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXWDrm, X86_INS_VPMOVZXWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXWDrr, X86_INS_VPMOVZXWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXWQYrm, X86_INS_VPMOVZXWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXWQYrr, X86_INS_VPMOVZXWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXWQZrm, X86_INS_VPMOVZXWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXWQZrmk, X86_INS_VPMOVZXWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXWQZrmkz, X86_INS_VPMOVZXWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXWQZrr, X86_INS_VPMOVZXWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXWQZrrk, X86_INS_VPMOVZXWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXWQZrrkz, X86_INS_VPMOVZXWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXWQrm, X86_INS_VPMOVZXWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMOVZXWQrr, X86_INS_VPMOVZXWQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULDQYrm, X86_INS_VPMULDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULDQYrr, X86_INS_VPMULDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULDQZrm, X86_INS_VPMULDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULDQZrmb, X86_INS_VPMULDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULDQZrmbk, X86_INS_VPMULDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULDQZrmbkz, X86_INS_VPMULDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULDQZrmk, X86_INS_VPMULDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULDQZrmkz, X86_INS_VPMULDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULDQZrr, X86_INS_VPMULDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULDQZrrk, X86_INS_VPMULDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULDQZrrkz, X86_INS_VPMULDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULDQrm, X86_INS_VPMULDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULDQrr, X86_INS_VPMULDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULHRSWrm128, X86_INS_VPMULHRSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULHRSWrm256, X86_INS_VPMULHRSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULHRSWrr128, X86_INS_VPMULHRSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULHRSWrr256, X86_INS_VPMULHRSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULHUWYrm, X86_INS_VPMULHUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULHUWYrr, X86_INS_VPMULHUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULHUWrm, X86_INS_VPMULHUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULHUWrr, X86_INS_VPMULHUW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULHWYrm, X86_INS_VPMULHW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULHWYrr, X86_INS_VPMULHW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULHWrm, X86_INS_VPMULHW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULHWrr, X86_INS_VPMULHW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULLDYrm, X86_INS_VPMULLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULLDYrr, X86_INS_VPMULLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULLDZrm, X86_INS_VPMULLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULLDZrmb, X86_INS_VPMULLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULLDZrmbk, X86_INS_VPMULLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULLDZrmbkz, X86_INS_VPMULLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULLDZrmk, X86_INS_VPMULLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULLDZrmkz, X86_INS_VPMULLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULLDZrr, X86_INS_VPMULLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULLDZrrk, X86_INS_VPMULLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULLDZrrkz, X86_INS_VPMULLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULLDrm, X86_INS_VPMULLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULLDrr, X86_INS_VPMULLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULLWYrm, X86_INS_VPMULLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULLWYrr, X86_INS_VPMULLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULLWrm, X86_INS_VPMULLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULLWrr, X86_INS_VPMULLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULUDQYrm, X86_INS_VPMULUDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULUDQYrr, X86_INS_VPMULUDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULUDQZrm, X86_INS_VPMULUDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULUDQZrmb, X86_INS_VPMULUDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULUDQZrmbk, X86_INS_VPMULUDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULUDQZrmbkz, X86_INS_VPMULUDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULUDQZrmk, X86_INS_VPMULUDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULUDQZrmkz, X86_INS_VPMULUDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULUDQZrr, X86_INS_VPMULUDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULUDQZrrk, X86_INS_VPMULUDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULUDQZrrkz, X86_INS_VPMULUDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULUDQrm, X86_INS_VPMULUDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPMULUDQrr, X86_INS_VPMULUDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPORDZrm, X86_INS_VPORD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPORDZrmb, X86_INS_VPORD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPORDZrmbk, X86_INS_VPORD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPORDZrmbkz, X86_INS_VPORD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPORDZrmk, X86_INS_VPORD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPORDZrmkz, X86_INS_VPORD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPORDZrr, X86_INS_VPORD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPORDZrrk, X86_INS_VPORD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPORDZrrkz, X86_INS_VPORD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPORQZrm, X86_INS_VPORQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPORQZrmb, X86_INS_VPORQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPORQZrmbk, X86_INS_VPORQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPORQZrmbkz, X86_INS_VPORQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPORQZrmk, X86_INS_VPORQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPORQZrmkz, X86_INS_VPORQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPORQZrr, X86_INS_VPORQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPORQZrrk, X86_INS_VPORQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPORQZrrkz, X86_INS_VPORQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPORYrm, X86_INS_VPOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPORYrr, X86_INS_VPOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPORrm, X86_INS_VPOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPORrr, X86_INS_VPOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPPERMmr, X86_INS_VPPERM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPPERMrm, X86_INS_VPPERM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPPERMrr, X86_INS_VPPERM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPROTBmi, X86_INS_VPROTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPROTBmr, X86_INS_VPROTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPROTBri, X86_INS_VPROTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPROTBrm, X86_INS_VPROTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPROTBrr, X86_INS_VPROTB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPROTDmi, X86_INS_VPROTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPROTDmr, X86_INS_VPROTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPROTDri, X86_INS_VPROTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPROTDrm, X86_INS_VPROTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPROTDrr, X86_INS_VPROTD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPROTQmi, X86_INS_VPROTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPROTQmr, X86_INS_VPROTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPROTQri, X86_INS_VPROTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPROTQrm, X86_INS_VPROTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPROTQrr, X86_INS_VPROTQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPROTWmi, X86_INS_VPROTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPROTWmr, X86_INS_VPROTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPROTWri, X86_INS_VPROTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPROTWrm, X86_INS_VPROTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPROTWrr, X86_INS_VPROTW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPSADBWYrm, X86_INS_VPSADBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSADBWYrr, X86_INS_VPSADBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSADBWrm, X86_INS_VPSADBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSADBWrr, X86_INS_VPSADBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSCATTERDDZmr, X86_INS_VPSCATTERDD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSCATTERDQZmr, X86_INS_VPSCATTERDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSCATTERQDZmr, X86_INS_VPSCATTERQD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSCATTERQQZmr, X86_INS_VPSCATTERQQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHABmr, X86_INS_VPSHAB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHABrm, X86_INS_VPSHAB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHABrr, X86_INS_VPSHAB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHADmr, X86_INS_VPSHAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHADrm, X86_INS_VPSHAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHADrr, X86_INS_VPSHAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHAQmr, X86_INS_VPSHAQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHAQrm, X86_INS_VPSHAQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHAQrr, X86_INS_VPSHAQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHAWmr, X86_INS_VPSHAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHAWrm, X86_INS_VPSHAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHAWrr, X86_INS_VPSHAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHLBmr, X86_INS_VPSHLB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHLBrm, X86_INS_VPSHLB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHLBrr, X86_INS_VPSHLB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHLDmr, X86_INS_VPSHLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHLDrm, X86_INS_VPSHLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHLDrr, X86_INS_VPSHLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHLQmr, X86_INS_VPSHLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHLQrm, X86_INS_VPSHLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHLQrr, X86_INS_VPSHLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHLWmr, X86_INS_VPSHLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHLWrm, X86_INS_VPSHLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHLWrr, X86_INS_VPSHLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_XOP, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHUFBYrm, X86_INS_VPSHUFB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHUFBYrr, X86_INS_VPSHUFB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHUFBrm, X86_INS_VPSHUFB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHUFBrr, X86_INS_VPSHUFB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHUFDYmi, X86_INS_VPSHUFD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHUFDYri, X86_INS_VPSHUFD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHUFDZmi, X86_INS_VPSHUFD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHUFDZri, X86_INS_VPSHUFD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHUFDmi, X86_INS_VPSHUFD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHUFDri, X86_INS_VPSHUFD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHUFHWYmi, X86_INS_VPSHUFHW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHUFHWYri, X86_INS_VPSHUFHW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHUFHWmi, X86_INS_VPSHUFHW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHUFHWri, X86_INS_VPSHUFHW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHUFLWYmi, X86_INS_VPSHUFLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHUFLWYri, X86_INS_VPSHUFLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHUFLWmi, X86_INS_VPSHUFLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSHUFLWri, X86_INS_VPSHUFLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSIGNBYrm, X86_INS_VPSIGNB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSIGNBYrr, X86_INS_VPSIGNB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSIGNBrm, X86_INS_VPSIGNB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSIGNBrr, X86_INS_VPSIGNB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSIGNDYrm, X86_INS_VPSIGND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSIGNDYrr, X86_INS_VPSIGND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSIGNDrm, X86_INS_VPSIGND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSIGNDrr, X86_INS_VPSIGND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSIGNWYrm, X86_INS_VPSIGNW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSIGNWYrr, X86_INS_VPSIGNW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSIGNWrm, X86_INS_VPSIGNW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSIGNWrr, X86_INS_VPSIGNW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLDQYri, X86_INS_VPSLLDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLDQri, X86_INS_VPSLLDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLDYri, X86_INS_VPSLLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLDYrm, X86_INS_VPSLLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLDYrr, X86_INS_VPSLLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLDZmi, X86_INS_VPSLLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLDZmik, X86_INS_VPSLLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLDZri, X86_INS_VPSLLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLDZrik, X86_INS_VPSLLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLDZrm, X86_INS_VPSLLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLDZrmk, X86_INS_VPSLLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLDZrr, X86_INS_VPSLLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLDZrrk, X86_INS_VPSLLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLDri, X86_INS_VPSLLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLDrm, X86_INS_VPSLLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLDrr, X86_INS_VPSLLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLQYri, X86_INS_VPSLLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLQYrm, X86_INS_VPSLLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLQYrr, X86_INS_VPSLLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLQZmi, X86_INS_VPSLLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLQZmik, X86_INS_VPSLLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLQZri, X86_INS_VPSLLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLQZrik, X86_INS_VPSLLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLQZrm, X86_INS_VPSLLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLQZrmk, X86_INS_VPSLLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLQZrr, X86_INS_VPSLLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLQZrrk, X86_INS_VPSLLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLQri, X86_INS_VPSLLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLQrm, X86_INS_VPSLLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLQrr, X86_INS_VPSLLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLVDYrm, X86_INS_VPSLLVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLVDYrr, X86_INS_VPSLLVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLVDZrm, X86_INS_VPSLLVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLVDZrr, X86_INS_VPSLLVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLVDrm, X86_INS_VPSLLVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLVDrr, X86_INS_VPSLLVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLVQYrm, X86_INS_VPSLLVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLVQYrr, X86_INS_VPSLLVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLVQZrm, X86_INS_VPSLLVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLVQZrr, X86_INS_VPSLLVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLVQrm, X86_INS_VPSLLVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLVQrr, X86_INS_VPSLLVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLWYri, X86_INS_VPSLLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLWYrm, X86_INS_VPSLLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLWYrr, X86_INS_VPSLLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLWri, X86_INS_VPSLLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLWrm, X86_INS_VPSLLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSLLWrr, X86_INS_VPSLLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRADYri, X86_INS_VPSRAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRADYrm, X86_INS_VPSRAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRADYrr, X86_INS_VPSRAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRADZmi, X86_INS_VPSRAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRADZmik, X86_INS_VPSRAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRADZri, X86_INS_VPSRAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRADZrik, X86_INS_VPSRAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRADZrm, X86_INS_VPSRAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRADZrmk, X86_INS_VPSRAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRADZrr, X86_INS_VPSRAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRADZrrk, X86_INS_VPSRAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRADri, X86_INS_VPSRAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRADrm, X86_INS_VPSRAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRADrr, X86_INS_VPSRAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRAQZmi, X86_INS_VPSRAQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRAQZmik, X86_INS_VPSRAQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRAQZri, X86_INS_VPSRAQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRAQZrik, X86_INS_VPSRAQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRAQZrm, X86_INS_VPSRAQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRAQZrmk, X86_INS_VPSRAQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRAQZrr, X86_INS_VPSRAQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRAQZrrk, X86_INS_VPSRAQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRAVDYrm, X86_INS_VPSRAVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRAVDYrr, X86_INS_VPSRAVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRAVDZrm, X86_INS_VPSRAVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRAVDZrr, X86_INS_VPSRAVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRAVDrm, X86_INS_VPSRAVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRAVDrr, X86_INS_VPSRAVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRAVQZrm, X86_INS_VPSRAVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRAVQZrr, X86_INS_VPSRAVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRAWYri, X86_INS_VPSRAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRAWYrm, X86_INS_VPSRAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRAWYrr, X86_INS_VPSRAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRAWri, X86_INS_VPSRAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRAWrm, X86_INS_VPSRAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRAWrr, X86_INS_VPSRAW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLDQYri, X86_INS_VPSRLDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLDQri, X86_INS_VPSRLDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLDYri, X86_INS_VPSRLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLDYrm, X86_INS_VPSRLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLDYrr, X86_INS_VPSRLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLDZmi, X86_INS_VPSRLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLDZmik, X86_INS_VPSRLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLDZri, X86_INS_VPSRLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLDZrik, X86_INS_VPSRLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLDZrm, X86_INS_VPSRLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLDZrmk, X86_INS_VPSRLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLDZrr, X86_INS_VPSRLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLDZrrk, X86_INS_VPSRLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLDri, X86_INS_VPSRLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLDrm, X86_INS_VPSRLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLDrr, X86_INS_VPSRLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLQYri, X86_INS_VPSRLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLQYrm, X86_INS_VPSRLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLQYrr, X86_INS_VPSRLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLQZmi, X86_INS_VPSRLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLQZmik, X86_INS_VPSRLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLQZri, X86_INS_VPSRLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLQZrik, X86_INS_VPSRLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLQZrm, X86_INS_VPSRLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLQZrmk, X86_INS_VPSRLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLQZrr, X86_INS_VPSRLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLQZrrk, X86_INS_VPSRLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLQri, X86_INS_VPSRLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLQrm, X86_INS_VPSRLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLQrr, X86_INS_VPSRLQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLVDYrm, X86_INS_VPSRLVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLVDYrr, X86_INS_VPSRLVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLVDZrm, X86_INS_VPSRLVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLVDZrr, X86_INS_VPSRLVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLVDrm, X86_INS_VPSRLVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLVDrr, X86_INS_VPSRLVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLVQYrm, X86_INS_VPSRLVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLVQYrr, X86_INS_VPSRLVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLVQZrm, X86_INS_VPSRLVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLVQZrr, X86_INS_VPSRLVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLVQrm, X86_INS_VPSRLVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLVQrr, X86_INS_VPSRLVQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLWYri, X86_INS_VPSRLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLWYrm, X86_INS_VPSRLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLWYrr, X86_INS_VPSRLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLWri, X86_INS_VPSRLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLWrm, X86_INS_VPSRLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSRLWrr, X86_INS_VPSRLW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBBYrm, X86_INS_VPSUBB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBBYrr, X86_INS_VPSUBB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBBrm, X86_INS_VPSUBB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBBrr, X86_INS_VPSUBB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBDYrm, X86_INS_VPSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBDYrr, X86_INS_VPSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBDZrm, X86_INS_VPSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBDZrmb, X86_INS_VPSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBDZrmbk, X86_INS_VPSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBDZrmbkz, X86_INS_VPSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBDZrmk, X86_INS_VPSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBDZrmkz, X86_INS_VPSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBDZrr, X86_INS_VPSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBDZrrk, X86_INS_VPSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBDZrrkz, X86_INS_VPSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBDrm, X86_INS_VPSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBDrr, X86_INS_VPSUBD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBQYrm, X86_INS_VPSUBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBQYrr, X86_INS_VPSUBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBQZrm, X86_INS_VPSUBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBQZrmb, X86_INS_VPSUBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBQZrmbk, X86_INS_VPSUBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBQZrmbkz, X86_INS_VPSUBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBQZrmk, X86_INS_VPSUBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBQZrmkz, X86_INS_VPSUBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBQZrr, X86_INS_VPSUBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBQZrrk, X86_INS_VPSUBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBQZrrkz, X86_INS_VPSUBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBQrm, X86_INS_VPSUBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBQrr, X86_INS_VPSUBQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBSBYrm, X86_INS_VPSUBSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBSBYrr, X86_INS_VPSUBSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBSBrm, X86_INS_VPSUBSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBSBrr, X86_INS_VPSUBSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBSWYrm, X86_INS_VPSUBSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBSWYrr, X86_INS_VPSUBSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBSWrm, X86_INS_VPSUBSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBSWrr, X86_INS_VPSUBSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBUSBYrm, X86_INS_VPSUBUSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBUSBYrr, X86_INS_VPSUBUSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBUSBrm, X86_INS_VPSUBUSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBUSBrr, X86_INS_VPSUBUSB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBUSWYrm, X86_INS_VPSUBUSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBUSWYrr, X86_INS_VPSUBUSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBUSWrm, X86_INS_VPSUBUSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBUSWrr, X86_INS_VPSUBUSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBWYrm, X86_INS_VPSUBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBWYrr, X86_INS_VPSUBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBWrm, X86_INS_VPSUBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPSUBWrr, X86_INS_VPSUBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPTESTMDZrm, X86_INS_VPTESTMD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPTESTMDZrr, X86_INS_VPTESTMD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPTESTMQZrm, X86_INS_VPTESTMQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPTESTMQZrr, X86_INS_VPTESTMQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPTESTNMDZrm, X86_INS_VPTESTNMD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPTESTNMDZrr, X86_INS_VPTESTNMD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPTESTNMQZrm, X86_INS_VPTESTNMQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPTESTNMQZrr, X86_INS_VPTESTNMQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_CDI, 0 }, 0, 0
#endif
	},
	{
		X86_VPTESTYrm, X86_INS_VPTEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPTESTYrr, X86_INS_VPTEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPTESTrm, X86_INS_VPTEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPTESTrr, X86_INS_VPTEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKHBWYrm, X86_INS_VPUNPCKHBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKHBWYrr, X86_INS_VPUNPCKHBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKHBWrm, X86_INS_VPUNPCKHBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKHBWrr, X86_INS_VPUNPCKHBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKHDQYrm, X86_INS_VPUNPCKHDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKHDQYrr, X86_INS_VPUNPCKHDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKHDQZrm, X86_INS_VPUNPCKHDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKHDQZrr, X86_INS_VPUNPCKHDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKHDQrm, X86_INS_VPUNPCKHDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKHDQrr, X86_INS_VPUNPCKHDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKHQDQYrm, X86_INS_VPUNPCKHQDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKHQDQYrr, X86_INS_VPUNPCKHQDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKHQDQZrm, X86_INS_VPUNPCKHQDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKHQDQZrr, X86_INS_VPUNPCKHQDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKHQDQrm, X86_INS_VPUNPCKHQDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKHQDQrr, X86_INS_VPUNPCKHQDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKHWDYrm, X86_INS_VPUNPCKHWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKHWDYrr, X86_INS_VPUNPCKHWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKHWDrm, X86_INS_VPUNPCKHWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKHWDrr, X86_INS_VPUNPCKHWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKLBWYrm, X86_INS_VPUNPCKLBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKLBWYrr, X86_INS_VPUNPCKLBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKLBWrm, X86_INS_VPUNPCKLBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKLBWrr, X86_INS_VPUNPCKLBW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKLDQYrm, X86_INS_VPUNPCKLDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKLDQYrr, X86_INS_VPUNPCKLDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKLDQZrm, X86_INS_VPUNPCKLDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKLDQZrr, X86_INS_VPUNPCKLDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKLDQrm, X86_INS_VPUNPCKLDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKLDQrr, X86_INS_VPUNPCKLDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKLQDQYrm, X86_INS_VPUNPCKLQDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKLQDQYrr, X86_INS_VPUNPCKLQDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKLQDQZrm, X86_INS_VPUNPCKLQDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKLQDQZrr, X86_INS_VPUNPCKLQDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKLQDQrm, X86_INS_VPUNPCKLQDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKLQDQrr, X86_INS_VPUNPCKLQDQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKLWDYrm, X86_INS_VPUNPCKLWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKLWDYrr, X86_INS_VPUNPCKLWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKLWDrm, X86_INS_VPUNPCKLWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPUNPCKLWDrr, X86_INS_VPUNPCKLWD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPXORDZrm, X86_INS_VPXORD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPXORDZrmb, X86_INS_VPXORD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPXORDZrmbk, X86_INS_VPXORD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPXORDZrmbkz, X86_INS_VPXORD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPXORDZrmk, X86_INS_VPXORD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPXORDZrmkz, X86_INS_VPXORD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPXORDZrr, X86_INS_VPXORD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPXORDZrrk, X86_INS_VPXORD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPXORDZrrkz, X86_INS_VPXORD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPXORQZrm, X86_INS_VPXORQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPXORQZrmb, X86_INS_VPXORQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPXORQZrmbk, X86_INS_VPXORQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPXORQZrmbkz, X86_INS_VPXORQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPXORQZrmk, X86_INS_VPXORQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPXORQZrmkz, X86_INS_VPXORQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPXORQZrr, X86_INS_VPXORQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPXORQZrrk, X86_INS_VPXORQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPXORQZrrkz, X86_INS_VPXORQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VPXORYrm, X86_INS_VPXOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPXORYrr, X86_INS_VPXOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX2, 0 }, 0, 0
#endif
	},
	{
		X86_VPXORrm, X86_INS_VPXOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VPXORrr, X86_INS_VPXOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VRCP14PDZm, X86_INS_VRCP14PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VRCP14PDZr, X86_INS_VRCP14PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VRCP14PSZm, X86_INS_VRCP14PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VRCP14PSZr, X86_INS_VRCP14PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VRCP14SDrm, X86_INS_VRCP14SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VRCP14SDrr, X86_INS_VRCP14SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VRCP14SSrm, X86_INS_VRCP14SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VRCP14SSrr, X86_INS_VRCP14SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VRCP28PDZm, X86_INS_VRCP28PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_ERI, 0 }, 0, 0
#endif
	},
	{
		X86_VRCP28PDZr, X86_INS_VRCP28PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_ERI, 0 }, 0, 0
#endif
	},
	{
		X86_VRCP28PDZrb, X86_INS_VRCP28PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_ERI, 0 }, 0, 0
#endif
	},
	{
		X86_VRCP28PSZm, X86_INS_VRCP28PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_ERI, 0 }, 0, 0
#endif
	},
	{
		X86_VRCP28PSZr, X86_INS_VRCP28PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_ERI, 0 }, 0, 0
#endif
	},
	{
		X86_VRCP28PSZrb, X86_INS_VRCP28PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_ERI, 0 }, 0, 0
#endif
	},
	{
		X86_VRCP28SDrm, X86_INS_VRCP28SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_ERI, 0 }, 0, 0
#endif
	},
	{
		X86_VRCP28SDrr, X86_INS_VRCP28SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_ERI, 0 }, 0, 0
#endif
	},
	{
		X86_VRCP28SDrrb, X86_INS_VRCP28SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_ERI, 0 }, 0, 0
#endif
	},
	{
		X86_VRCP28SSrm, X86_INS_VRCP28SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_ERI, 0 }, 0, 0
#endif
	},
	{
		X86_VRCP28SSrr, X86_INS_VRCP28SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_ERI, 0 }, 0, 0
#endif
	},
	{
		X86_VRCP28SSrrb, X86_INS_VRCP28SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_ERI, 0 }, 0, 0
#endif
	},
	{
		X86_VRCPPSYm, X86_INS_VRCPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VRCPPSYm_Int, X86_INS_VRCPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VRCPPSYr, X86_INS_VRCPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VRCPPSYr_Int, X86_INS_VRCPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VRCPPSm, X86_INS_VRCPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VRCPPSm_Int, X86_INS_VRCPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VRCPPSr, X86_INS_VRCPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VRCPPSr_Int, X86_INS_VRCPPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VRCPSSm, X86_INS_VRCPSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VRCPSSm_Int, X86_INS_VRCPSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VRCPSSr, X86_INS_VRCPSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VRNDSCALEPDZm, X86_INS_VRNDSCALEPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VRNDSCALEPDZr, X86_INS_VRNDSCALEPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VRNDSCALEPSZm, X86_INS_VRNDSCALEPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VRNDSCALEPSZr, X86_INS_VRNDSCALEPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VRNDSCALESDm, X86_INS_VRNDSCALESD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VRNDSCALESDr, X86_INS_VRNDSCALESD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VRNDSCALESSm, X86_INS_VRNDSCALESS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VRNDSCALESSr, X86_INS_VRNDSCALESS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VROUNDPDm, X86_INS_VROUNDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VROUNDPDr, X86_INS_VROUNDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VROUNDPSm, X86_INS_VROUNDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VROUNDPSr, X86_INS_VROUNDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VROUNDSDm, X86_INS_VROUNDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VROUNDSDr, X86_INS_VROUNDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VROUNDSDr_Int, X86_INS_VROUNDSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VROUNDSSm, X86_INS_VROUNDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VROUNDSSr, X86_INS_VROUNDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VROUNDSSr_Int, X86_INS_VROUNDSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VROUNDYPDm, X86_INS_VROUNDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VROUNDYPDr, X86_INS_VROUNDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VROUNDYPSm, X86_INS_VROUNDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VROUNDYPSr, X86_INS_VROUNDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRT14PDZm, X86_INS_VRSQRT14PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRT14PDZr, X86_INS_VRSQRT14PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRT14PSZm, X86_INS_VRSQRT14PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRT14PSZr, X86_INS_VRSQRT14PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRT14SDrm, X86_INS_VRSQRT14SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRT14SDrr, X86_INS_VRSQRT14SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRT14SSrm, X86_INS_VRSQRT14SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRT14SSrr, X86_INS_VRSQRT14SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRT28PDZm, X86_INS_VRSQRT28PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_ERI, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRT28PDZr, X86_INS_VRSQRT28PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_ERI, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRT28PDZrb, X86_INS_VRSQRT28PD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_ERI, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRT28PSZm, X86_INS_VRSQRT28PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_ERI, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRT28PSZr, X86_INS_VRSQRT28PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_ERI, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRT28PSZrb, X86_INS_VRSQRT28PS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_ERI, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRT28SDrm, X86_INS_VRSQRT28SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_ERI, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRT28SDrr, X86_INS_VRSQRT28SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_ERI, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRT28SDrrb, X86_INS_VRSQRT28SD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_ERI, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRT28SSrm, X86_INS_VRSQRT28SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_ERI, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRT28SSrr, X86_INS_VRSQRT28SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_ERI, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRT28SSrrb, X86_INS_VRSQRT28SS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_ERI, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRTPSYm, X86_INS_VRSQRTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRTPSYm_Int, X86_INS_VRSQRTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRTPSYr, X86_INS_VRSQRTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRTPSYr_Int, X86_INS_VRSQRTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRTPSm, X86_INS_VRSQRTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRTPSm_Int, X86_INS_VRSQRTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRTPSr, X86_INS_VRSQRTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRTPSr_Int, X86_INS_VRSQRTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRTSSm, X86_INS_VRSQRTSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRTSSm_Int, X86_INS_VRSQRTSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VRSQRTSSr, X86_INS_VRSQRTSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSCATTERDPDZmr, X86_INS_VSCATTERDPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSCATTERDPSZmr, X86_INS_VSCATTERDPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSCATTERPF0DPDm, X86_INS_VSCATTERPF0DPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_PFI, 0 }, 0, 0
#endif
	},
	{
		X86_VSCATTERPF0DPSm, X86_INS_VSCATTERPF0DPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_PFI, 0 }, 0, 0
#endif
	},
	{
		X86_VSCATTERPF0QPDm, X86_INS_VSCATTERPF0QPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_PFI, 0 }, 0, 0
#endif
	},
	{
		X86_VSCATTERPF0QPSm, X86_INS_VSCATTERPF0QPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_PFI, 0 }, 0, 0
#endif
	},
	{
		X86_VSCATTERPF1DPDm, X86_INS_VSCATTERPF1DPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_PFI, 0 }, 0, 0
#endif
	},
	{
		X86_VSCATTERPF1DPSm, X86_INS_VSCATTERPF1DPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_PFI, 0 }, 0, 0
#endif
	},
	{
		X86_VSCATTERPF1QPDm, X86_INS_VSCATTERPF1QPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_PFI, 0 }, 0, 0
#endif
	},
	{
		X86_VSCATTERPF1QPSm, X86_INS_VSCATTERPF1QPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_PFI, 0 }, 0, 0
#endif
	},
	{
		X86_VSCATTERQPDZmr, X86_INS_VSCATTERQPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSCATTERQPSZmr, X86_INS_VSCATTERQPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSHUFPDYrmi, X86_INS_VSHUFPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSHUFPDYrri, X86_INS_VSHUFPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSHUFPDZrmi, X86_INS_VSHUFPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSHUFPDZrri, X86_INS_VSHUFPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSHUFPDrmi, X86_INS_VSHUFPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSHUFPDrri, X86_INS_VSHUFPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSHUFPSYrmi, X86_INS_VSHUFPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSHUFPSYrri, X86_INS_VSHUFPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSHUFPSZrmi, X86_INS_VSHUFPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSHUFPSZrri, X86_INS_VSHUFPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSHUFPSrmi, X86_INS_VSHUFPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSHUFPSrri, X86_INS_VSHUFPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTPDYm, X86_INS_VSQRTPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTPDYr, X86_INS_VSQRTPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTPDZrm, X86_INS_VSQRTPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTPDZrr, X86_INS_VSQRTPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTPDm, X86_INS_VSQRTPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTPDr, X86_INS_VSQRTPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTPSYm, X86_INS_VSQRTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTPSYr, X86_INS_VSQRTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTPSZrm, X86_INS_VSQRTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTPSZrr, X86_INS_VSQRTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTPSm, X86_INS_VSQRTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTPSr, X86_INS_VSQRTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTSDZm, X86_INS_VSQRTSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTSDZm_Int, X86_INS_VSQRTSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTSDZr, X86_INS_VSQRTSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTSDZr_Int, X86_INS_VSQRTSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTSDm, X86_INS_VSQRTSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTSDm_Int, X86_INS_VSQRTSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTSDr, X86_INS_VSQRTSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTSSZm, X86_INS_VSQRTSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTSSZm_Int, X86_INS_VSQRTSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTSSZr, X86_INS_VSQRTSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTSSZr_Int, X86_INS_VSQRTSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTSSm, X86_INS_VSQRTSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTSSm_Int, X86_INS_VSQRTSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSQRTSSr, X86_INS_VSQRTSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSTMXCSR, X86_INS_VSTMXCSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPDYrm, X86_INS_VSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPDYrr, X86_INS_VSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPDZrm, X86_INS_VSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPDZrmb, X86_INS_VSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPDZrmbk, X86_INS_VSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPDZrmbkz, X86_INS_VSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPDZrmk, X86_INS_VSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPDZrmkz, X86_INS_VSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPDZrr, X86_INS_VSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPDZrrk, X86_INS_VSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPDZrrkz, X86_INS_VSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPDrm, X86_INS_VSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPDrr, X86_INS_VSUBPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPSYrm, X86_INS_VSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPSYrr, X86_INS_VSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPSZrm, X86_INS_VSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPSZrmb, X86_INS_VSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPSZrmbk, X86_INS_VSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPSZrmbkz, X86_INS_VSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPSZrmk, X86_INS_VSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPSZrmkz, X86_INS_VSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPSZrr, X86_INS_VSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPSZrrk, X86_INS_VSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPSZrrkz, X86_INS_VSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPSrm, X86_INS_VSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBPSrr, X86_INS_VSUBPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBSDZrm, X86_INS_VSUBSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBSDZrr, X86_INS_VSUBSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBSDrm, X86_INS_VSUBSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBSDrm_Int, X86_INS_VSUBSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBSDrr, X86_INS_VSUBSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBSDrr_Int, X86_INS_VSUBSD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBSSZrm, X86_INS_VSUBSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBSSZrr, X86_INS_VSUBSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBSSrm, X86_INS_VSUBSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBSSrm_Int, X86_INS_VSUBSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBSSrr, X86_INS_VSUBSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VSUBSSrr_Int, X86_INS_VSUBSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VTESTPDYrm, X86_INS_VTESTPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VTESTPDYrr, X86_INS_VTESTPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VTESTPDrm, X86_INS_VTESTPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VTESTPDrr, X86_INS_VTESTPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VTESTPSYrm, X86_INS_VTESTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VTESTPSYrr, X86_INS_VTESTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VTESTPSrm, X86_INS_VTESTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VTESTPSrr, X86_INS_VTESTPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VUCOMISDZrm, X86_INS_VUCOMISD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VUCOMISDZrr, X86_INS_VUCOMISD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VUCOMISDrm, X86_INS_VUCOMISD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VUCOMISDrr, X86_INS_VUCOMISD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VUCOMISSZrm, X86_INS_VUCOMISS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VUCOMISSZrr, X86_INS_VUCOMISS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VUCOMISSrm, X86_INS_VUCOMISS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VUCOMISSrr, X86_INS_VUCOMISS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VUNPCKHPDYrm, X86_INS_VUNPCKHPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VUNPCKHPDYrr, X86_INS_VUNPCKHPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VUNPCKHPDZrm, X86_INS_VUNPCKHPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VUNPCKHPDZrr, X86_INS_VUNPCKHPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VUNPCKHPDrm, X86_INS_VUNPCKHPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VUNPCKHPDrr, X86_INS_VUNPCKHPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VUNPCKHPSYrm, X86_INS_VUNPCKHPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VUNPCKHPSYrr, X86_INS_VUNPCKHPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VUNPCKHPSZrm, X86_INS_VUNPCKHPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VUNPCKHPSZrr, X86_INS_VUNPCKHPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VUNPCKHPSrm, X86_INS_VUNPCKHPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VUNPCKHPSrr, X86_INS_VUNPCKHPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VUNPCKLPDYrm, X86_INS_VUNPCKLPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VUNPCKLPDYrr, X86_INS_VUNPCKLPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VUNPCKLPDZrm, X86_INS_VUNPCKLPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VUNPCKLPDZrr, X86_INS_VUNPCKLPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VUNPCKLPDrm, X86_INS_VUNPCKLPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VUNPCKLPDrr, X86_INS_VUNPCKLPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VUNPCKLPSYrm, X86_INS_VUNPCKLPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VUNPCKLPSYrr, X86_INS_VUNPCKLPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VUNPCKLPSZrm, X86_INS_VUNPCKLPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VUNPCKLPSZrr, X86_INS_VUNPCKLPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX512, 0 }, 0, 0
#endif
	},
	{
		X86_VUNPCKLPSrm, X86_INS_VUNPCKLPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VUNPCKLPSrr, X86_INS_VUNPCKLPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VXORPDYrm, X86_INS_VXORPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VXORPDYrr, X86_INS_VXORPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VXORPDrm, X86_INS_VXORPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VXORPDrr, X86_INS_VXORPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VXORPSYrm, X86_INS_VXORPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VXORPSYrr, X86_INS_VXORPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VXORPSrm, X86_INS_VXORPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VXORPSrr, X86_INS_VXORPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VZEROALL, X86_INS_VZEROALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_YMM0, X86_REG_YMM1, X86_REG_YMM2, X86_REG_YMM3, X86_REG_YMM4, X86_REG_YMM5, X86_REG_YMM6, X86_REG_YMM7, X86_REG_YMM8, X86_REG_YMM9, X86_REG_YMM10, X86_REG_YMM11, X86_REG_YMM12, X86_REG_YMM13, X86_REG_YMM14, X86_REG_YMM15, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_VZEROUPPER, X86_INS_VZEROUPPER,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_YMM0, X86_REG_YMM1, X86_REG_YMM2, X86_REG_YMM3, X86_REG_YMM4, X86_REG_YMM5, X86_REG_YMM6, X86_REG_YMM7, X86_REG_YMM8, X86_REG_YMM9, X86_REG_YMM10, X86_REG_YMM11, X86_REG_YMM12, X86_REG_YMM13, X86_REG_YMM14, X86_REG_YMM15, 0 }, { X86_GRP_AVX, 0 }, 0, 0
#endif
	},
	{
		X86_WAIT, X86_INS_WAIT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_WBINVD, X86_INS_WBINVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_WRFSBASE, X86_INS_WRFSBASE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FSGSBASE, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_WRFSBASE64, X86_INS_WRFSBASE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FSGSBASE, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_WRGSBASE, X86_INS_WRGSBASE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FSGSBASE, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_WRGSBASE64, X86_INS_WRGSBASE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FSGSBASE, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_WRMSR, X86_INS_WRMSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XABORT, X86_INS_XABORT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RTM, 0 }, 0, 0
#endif
	},
	{
		X86_XACQUIRE_PREFIX, X86_INS_XACQUIRE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_HLE, 0 }, 0, 0
#endif
	},
	{
		X86_XADD16rm, X86_INS_XADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XADD16rr, X86_INS_XADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XADD32rm, X86_INS_XADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XADD32rr, X86_INS_XADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XADD64rm, X86_INS_XADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XADD64rr, X86_INS_XADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XADD8rm, X86_INS_XADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XADD8rr, X86_INS_XADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XBEGIN_4, X86_INS_XBEGIN,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EAX, 0 }, { X86_GRP_RTM, 0 }, 1, 0
#endif
	},
	{
		X86_XCHG16ar, X86_INS_XCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCHG16rm, X86_INS_XCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCHG16rr, X86_INS_XCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCHG32ar, X86_INS_XCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_XCHG32ar64, X86_INS_XCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_XCHG32rm, X86_INS_XCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCHG32rr, X86_INS_XCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCHG64ar, X86_INS_XCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCHG64rm, X86_INS_XCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCHG64rr, X86_INS_XCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCHG8rm, X86_INS_XCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCHG8rr, X86_INS_XCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCH_F, X86_INS_FXCH,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_FPSW, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCRYPTCBC, X86_INS_XCRYPTCBC,
#ifndef CAPSTONE_DIET
		{ X86_REG_RBX, X86_REG_RDX, X86_REG_RSI, X86_REG_RDI, 0 }, { X86_REG_RSI, X86_REG_RDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCRYPTCFB, X86_INS_XCRYPTCFB,
#ifndef CAPSTONE_DIET
		{ X86_REG_RBX, X86_REG_RDX, X86_REG_RSI, X86_REG_RDI, 0 }, { X86_REG_RSI, X86_REG_RDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCRYPTCTR, X86_INS_XCRYPTCTR,
#ifndef CAPSTONE_DIET
		{ X86_REG_RBX, X86_REG_RDX, X86_REG_RSI, X86_REG_RDI, 0 }, { X86_REG_RSI, X86_REG_RDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCRYPTECB, X86_INS_XCRYPTECB,
#ifndef CAPSTONE_DIET
		{ X86_REG_RBX, X86_REG_RDX, X86_REG_RSI, X86_REG_RDI, 0 }, { X86_REG_RSI, X86_REG_RDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCRYPTOFB, X86_INS_XCRYPTOFB,
#ifndef CAPSTONE_DIET
		{ X86_REG_RBX, X86_REG_RDX, X86_REG_RSI, X86_REG_RDI, 0 }, { X86_REG_RSI, X86_REG_RDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XEND, X86_INS_XEND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RTM, 0 }, 0, 0
#endif
	},
	{
		X86_XGETBV, X86_INS_XGETBV,
#ifndef CAPSTONE_DIET
		{ X86_REG_RCX, 0 }, { X86_REG_RDX, X86_REG_RAX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XLAT, X86_INS_XLATB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR16i16, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR16mi, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR16mi8, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR16mr, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR16ri, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR16ri8, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR16rm, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR16rr, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR16rr_REV, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR32i32, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR32mi, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR32mi8, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR32mr, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR32ri, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR32ri8, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR32rm, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR32rr, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR32rr_REV, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR64i32, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR64mi32, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR64mi8, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR64mr, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR64ri32, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR64ri8, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR64rm, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR64rr, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR64rr_REV, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR8i8, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR8mi, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR8mr, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR8ri, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR8ri8, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_XOR8rm, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR8rr, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR8rr_REV, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XORPDrm, X86_INS_XORPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_XORPDrr, X86_INS_XORPD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE2, 0 }, 0, 0
#endif
	},
	{
		X86_XORPSrm, X86_INS_XORPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_XORPSrr, X86_INS_XORPS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_SSE1, 0 }, 0, 0
#endif
	},
	{
		X86_XRELEASE_PREFIX, X86_INS_XRELEASE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_HLE, 0 }, 0, 0
#endif
	},
	{
		X86_XRSTOR, X86_INS_XRSTOR,
#ifndef CAPSTONE_DIET
		{ X86_REG_RDX, X86_REG_RAX, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XRSTOR64, X86_INS_XRSTOR64,
#ifndef CAPSTONE_DIET
		{ X86_REG_RDX, X86_REG_RAX, 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_XSAVE, X86_INS_XSAVE,
#ifndef CAPSTONE_DIET
		{ X86_REG_RDX, X86_REG_RAX, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XSAVE64, X86_INS_XSAVE64,
#ifndef CAPSTONE_DIET
		{ X86_REG_RDX, X86_REG_RAX, 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_XSAVEOPT, X86_INS_XSAVEOPT,
#ifndef CAPSTONE_DIET
		{ X86_REG_RDX, X86_REG_RAX, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XSAVEOPT64, X86_INS_XSAVEOPT64,
#ifndef CAPSTONE_DIET
		{ X86_REG_RDX, X86_REG_RAX, 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_XSETBV, X86_INS_XSETBV,
#ifndef CAPSTONE_DIET
		{ X86_REG_RDX, X86_REG_RAX, X86_REG_RCX, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XSHA1, X86_INS_XSHA1,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_RSI, X86_REG_RDI, 0 }, { X86_REG_RAX, X86_REG_RSI, X86_REG_RDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XSHA256, X86_INS_XSHA256,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_RSI, X86_REG_RDI, 0 }, { X86_REG_RAX, X86_REG_RSI, X86_REG_RDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XSTORE, X86_INS_XSTORE,
#ifndef CAPSTONE_DIET
		{ X86_REG_RDX, X86_REG_RDI, 0 }, { X86_REG_RAX, X86_REG_RDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XTEST, X86_INS_XTEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
};
#else	// X86 reduce (defined CAPSTONE_X86_REDUCE)
static const insn_map insns[] = {	// reduce x86 instructions
	// dummy item
	{
		0, 0,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},

	{
		X86_AAA, X86_INS_AAA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_AAD8i8, X86_INS_AAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_AAM8i8, X86_INS_AAM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_AAS, X86_INS_AAS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_ADC16i16, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC16mi, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC16mi8, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC16mr, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC16ri, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC16ri8, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC16rm, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC16rr, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC16rr_REV, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC32i32, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC32mi, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC32mi8, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC32mr, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC32ri, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC32ri8, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC32rm, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC32rr, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC32rr_REV, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC64i32, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC64mi32, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC64mi8, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC64mr, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC64ri32, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC64ri8, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC64rm, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC64rr, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC64rr_REV, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC8i8, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC8mi, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC8mr, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC8ri, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC8rm, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC8rr, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADC8rr_REV, X86_INS_ADC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADCX32rm, X86_INS_ADCX,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_ADX, 0 }, 0, 0
#endif
	},
	{
		X86_ADCX32rr, X86_INS_ADCX,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_ADX, 0 }, 0, 0
#endif
	},
	{
		X86_ADCX64rm, X86_INS_ADCX,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_ADX, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_ADCX64rr, X86_INS_ADCX,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_ADX, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_ADD16i16, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD16mi, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD16mi8, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD16mr, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD16ri, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD16ri8, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD16rm, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD16rr, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD16rr_REV, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD32i32, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD32mi, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD32mi8, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD32mr, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD32ri, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD32ri8, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD32rm, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD32rr, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD32rr_REV, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD64i32, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD64mi32, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD64mi8, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD64mr, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD64ri32, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD64ri8, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD64rm, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD64rr, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD64rr_REV, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD8i8, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD8mi, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD8mr, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD8ri, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD8ri8, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_ADD8rm, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD8rr, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADD8rr_REV, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ADOX32rm, X86_INS_ADOX,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_ADX, 0 }, 0, 0
#endif
	},
	{
		X86_ADOX32rr, X86_INS_ADOX,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_ADX, 0 }, 0, 0
#endif
	},
	{
		X86_ADOX64rm, X86_INS_ADOX,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_ADX, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_ADOX64rr, X86_INS_ADOX,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_ADX, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_AND16i16, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND16mi, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND16mi8, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND16mr, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND16ri, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND16ri8, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND16rm, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND16rr, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND16rr_REV, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND32i32, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND32mi, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND32mi8, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND32mr, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND32ri, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND32ri8, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND32rm, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND32rr, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND32rr_REV, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND64i32, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND64mi32, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND64mi8, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND64mr, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND64ri32, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND64ri8, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND64rm, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND64rr, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND64rr_REV, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND8i8, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND8mi, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND8mr, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND8ri, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND8ri8, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_AND8rm, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND8rr, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_AND8rr_REV, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ANDN32rm, X86_INS_ANDN,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_ANDN32rr, X86_INS_ANDN,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_ANDN64rm, X86_INS_ANDN,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_ANDN64rr, X86_INS_ANDN,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_ARPL16mr, X86_INS_ARPL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_ARPL16rr, X86_INS_ARPL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_BEXTR32rm, X86_INS_BEXTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BEXTR32rr, X86_INS_BEXTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BEXTR64rm, X86_INS_BEXTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BEXTR64rr, X86_INS_BEXTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BEXTRI32mi, X86_INS_BEXTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BEXTRI32ri, X86_INS_BEXTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BEXTRI64mi, X86_INS_BEXTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BEXTRI64ri, X86_INS_BEXTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCFILL32rm, X86_INS_BLCFILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCFILL32rr, X86_INS_BLCFILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCFILL64rm, X86_INS_BLCFILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCFILL64rr, X86_INS_BLCFILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCI32rm, X86_INS_BLCI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCI32rr, X86_INS_BLCI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCI64rm, X86_INS_BLCI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCI64rr, X86_INS_BLCI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCIC32rm, X86_INS_BLCIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCIC32rr, X86_INS_BLCIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCIC64rm, X86_INS_BLCIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCIC64rr, X86_INS_BLCIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCMSK32rm, X86_INS_BLCMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCMSK32rr, X86_INS_BLCMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCMSK64rm, X86_INS_BLCMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCMSK64rr, X86_INS_BLCMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCS32rm, X86_INS_BLCS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCS32rr, X86_INS_BLCS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCS64rm, X86_INS_BLCS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLCS64rr, X86_INS_BLCS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLSFILL32rm, X86_INS_BLSFILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLSFILL32rr, X86_INS_BLSFILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLSFILL64rm, X86_INS_BLSFILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLSFILL64rr, X86_INS_BLSFILL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLSI32rm, X86_INS_BLSI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BLSI32rr, X86_INS_BLSI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BLSI64rm, X86_INS_BLSI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BLSI64rr, X86_INS_BLSI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BLSIC32rm, X86_INS_BLSIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLSIC32rr, X86_INS_BLSIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLSIC64rm, X86_INS_BLSIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLSIC64rr, X86_INS_BLSIC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_BLSMSK32rm, X86_INS_BLSMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BLSMSK32rr, X86_INS_BLSMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BLSMSK64rm, X86_INS_BLSMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BLSMSK64rr, X86_INS_BLSMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BLSR32rm, X86_INS_BLSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BLSR32rr, X86_INS_BLSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BLSR64rm, X86_INS_BLSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BLSR64rr, X86_INS_BLSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_BOUNDS16rm, X86_INS_BOUND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_BOUNDS32rm, X86_INS_BOUND,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_BSF16rm, X86_INS_BSF,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSF16rr, X86_INS_BSF,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSF32rm, X86_INS_BSF,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSF32rr, X86_INS_BSF,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSF64rm, X86_INS_BSF,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSF64rr, X86_INS_BSF,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSR16rm, X86_INS_BSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSR16rr, X86_INS_BSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSR32rm, X86_INS_BSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSR32rr, X86_INS_BSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSR64rm, X86_INS_BSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSR64rr, X86_INS_BSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSWAP32r, X86_INS_BSWAP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BSWAP64r, X86_INS_BSWAP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BT16mi8, X86_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BT16mr, X86_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BT16ri8, X86_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BT16rr, X86_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BT32mi8, X86_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BT32mr, X86_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BT32ri8, X86_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BT32rr, X86_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BT64mi8, X86_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BT64mr, X86_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BT64ri8, X86_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BT64rr, X86_INS_BT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTC16mi8, X86_INS_BTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTC16mr, X86_INS_BTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTC16ri8, X86_INS_BTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTC16rr, X86_INS_BTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTC32mi8, X86_INS_BTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTC32mr, X86_INS_BTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTC32ri8, X86_INS_BTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTC32rr, X86_INS_BTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTC64mi8, X86_INS_BTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTC64mr, X86_INS_BTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTC64ri8, X86_INS_BTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTC64rr, X86_INS_BTC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTR16mi8, X86_INS_BTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTR16mr, X86_INS_BTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTR16ri8, X86_INS_BTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTR16rr, X86_INS_BTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTR32mi8, X86_INS_BTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTR32mr, X86_INS_BTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTR32ri8, X86_INS_BTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTR32rr, X86_INS_BTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTR64mi8, X86_INS_BTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTR64mr, X86_INS_BTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTR64ri8, X86_INS_BTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTR64rr, X86_INS_BTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTS16mi8, X86_INS_BTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTS16mr, X86_INS_BTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTS16ri8, X86_INS_BTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTS16rr, X86_INS_BTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTS32mi8, X86_INS_BTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTS32mr, X86_INS_BTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTS32ri8, X86_INS_BTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTS32rr, X86_INS_BTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTS64mi8, X86_INS_BTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTS64mr, X86_INS_BTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTS64ri8, X86_INS_BTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BTS64rr, X86_INS_BTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_BZHI32rm, X86_INS_BZHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_BZHI32rr, X86_INS_BZHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_BZHI64rm, X86_INS_BZHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_BZHI64rr, X86_INS_BZHI,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_CALL16m, X86_INS_CALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { 0 }, { X86_GRP_CALL, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_CALL16r, X86_INS_CALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { 0 }, { X86_GRP_CALL, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_CALL32m, X86_INS_CALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { 0 }, { X86_GRP_CALL, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_CALL32r, X86_INS_CALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { 0 }, { X86_GRP_CALL, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_CALL64m, X86_INS_CALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { 0 }, { X86_GRP_CALL, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_CALL64pcrel32, X86_INS_CALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { 0 }, { X86_GRP_CALL, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_CALL64r, X86_INS_CALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { 0 }, { X86_GRP_CALL, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_CALLpcrel16, X86_INS_CALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { 0 }, { X86_GRP_CALL, 0 }, 0, 0
#endif
	},
	{
		X86_CALLpcrel32, X86_INS_CALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { 0 }, { X86_GRP_CALL, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_CBW, X86_INS_CBW,
#ifndef CAPSTONE_DIET
		{ X86_REG_AL, 0 }, { X86_REG_AX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CDQ, X86_INS_CDQ,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { X86_REG_EAX, X86_REG_EDX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CDQE, X86_INS_CDQE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { X86_REG_RAX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CLAC, X86_INS_CLAC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_SMAP, 0 }, 0, 0
#endif
	},
	{
		X86_CLC, X86_INS_CLC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CLD, X86_INS_CLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CLGI, X86_INS_CLGI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_CLI, X86_INS_CLI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CLTS, X86_INS_CLTS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMC, X86_INS_CMC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMOVA16rm, X86_INS_CMOVA,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVA16rr, X86_INS_CMOVA,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVA32rm, X86_INS_CMOVA,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVA32rr, X86_INS_CMOVA,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVA64rm, X86_INS_CMOVA,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVA64rr, X86_INS_CMOVA,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVAE16rm, X86_INS_CMOVAE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVAE16rr, X86_INS_CMOVAE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVAE32rm, X86_INS_CMOVAE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVAE32rr, X86_INS_CMOVAE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVAE64rm, X86_INS_CMOVAE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVAE64rr, X86_INS_CMOVAE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVB16rm, X86_INS_CMOVB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVB16rr, X86_INS_CMOVB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVB32rm, X86_INS_CMOVB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVB32rr, X86_INS_CMOVB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVB64rm, X86_INS_CMOVB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVB64rr, X86_INS_CMOVB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVBE16rm, X86_INS_CMOVBE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVBE16rr, X86_INS_CMOVBE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVBE32rm, X86_INS_CMOVBE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVBE32rr, X86_INS_CMOVBE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVBE64rm, X86_INS_CMOVBE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVBE64rr, X86_INS_CMOVBE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVE16rm, X86_INS_CMOVE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVE16rr, X86_INS_CMOVE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVE32rm, X86_INS_CMOVE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVE32rr, X86_INS_CMOVE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVE64rm, X86_INS_CMOVE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVE64rr, X86_INS_CMOVE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVG16rm, X86_INS_CMOVG,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVG16rr, X86_INS_CMOVG,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVG32rm, X86_INS_CMOVG,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVG32rr, X86_INS_CMOVG,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVG64rm, X86_INS_CMOVG,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVG64rr, X86_INS_CMOVG,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVGE16rm, X86_INS_CMOVGE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVGE16rr, X86_INS_CMOVGE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVGE32rm, X86_INS_CMOVGE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVGE32rr, X86_INS_CMOVGE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVGE64rm, X86_INS_CMOVGE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVGE64rr, X86_INS_CMOVGE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVL16rm, X86_INS_CMOVL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVL16rr, X86_INS_CMOVL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVL32rm, X86_INS_CMOVL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVL32rr, X86_INS_CMOVL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVL64rm, X86_INS_CMOVL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVL64rr, X86_INS_CMOVL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVLE16rm, X86_INS_CMOVLE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVLE16rr, X86_INS_CMOVLE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVLE32rm, X86_INS_CMOVLE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVLE32rr, X86_INS_CMOVLE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVLE64rm, X86_INS_CMOVLE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVLE64rr, X86_INS_CMOVLE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNE16rm, X86_INS_CMOVNE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNE16rr, X86_INS_CMOVNE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNE32rm, X86_INS_CMOVNE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNE32rr, X86_INS_CMOVNE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNE64rm, X86_INS_CMOVNE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNE64rr, X86_INS_CMOVNE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNO16rm, X86_INS_CMOVNO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNO16rr, X86_INS_CMOVNO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNO32rm, X86_INS_CMOVNO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNO32rr, X86_INS_CMOVNO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNO64rm, X86_INS_CMOVNO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNO64rr, X86_INS_CMOVNO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNP16rm, X86_INS_CMOVNP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNP16rr, X86_INS_CMOVNP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNP32rm, X86_INS_CMOVNP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNP32rr, X86_INS_CMOVNP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNP64rm, X86_INS_CMOVNP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNP64rr, X86_INS_CMOVNP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNS16rm, X86_INS_CMOVNS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNS16rr, X86_INS_CMOVNS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNS32rm, X86_INS_CMOVNS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNS32rr, X86_INS_CMOVNS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNS64rm, X86_INS_CMOVNS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVNS64rr, X86_INS_CMOVNS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVO16rm, X86_INS_CMOVO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVO16rr, X86_INS_CMOVO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVO32rm, X86_INS_CMOVO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVO32rr, X86_INS_CMOVO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVO64rm, X86_INS_CMOVO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVO64rr, X86_INS_CMOVO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVP16rm, X86_INS_CMOVP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVP16rr, X86_INS_CMOVP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVP32rm, X86_INS_CMOVP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVP32rr, X86_INS_CMOVP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVP64rm, X86_INS_CMOVP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVP64rr, X86_INS_CMOVP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVS16rm, X86_INS_CMOVS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVS16rr, X86_INS_CMOVS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVS32rm, X86_INS_CMOVS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVS32rr, X86_INS_CMOVS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVS64rm, X86_INS_CMOVS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMOVS64rr, X86_INS_CMOVS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_CMOV, 0 }, 0, 0
#endif
	},
	{
		X86_CMP16i16, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP16mi, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP16mi8, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP16mr, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP16ri, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP16ri8, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP16rm, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP16rr, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP16rr_REV, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP32i32, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP32mi, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP32mi8, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP32mr, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP32ri, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP32ri8, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP32rm, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP32rr, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP32rr_REV, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP64i32, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP64mi32, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP64mi8, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP64mr, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP64ri32, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP64ri8, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP64rm, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP64rr, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP64rr_REV, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP8i8, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP8mi, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP8mr, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP8ri, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP8rm, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP8rr, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMP8rr_REV, X86_INS_CMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPSB, X86_INS_CMPSB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDI, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPSL, X86_INS_CMPSD,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDI, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPSQ, X86_INS_CMPSQ,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDI, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPSW, X86_INS_CMPSW,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDI, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPXCHG16B, X86_INS_CMPXCHG16B,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_RBX, X86_REG_RCX, X86_REG_RDX, 0 }, { X86_REG_RAX, X86_REG_RDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPXCHG16rm, X86_INS_CMPXCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPXCHG16rr, X86_INS_CMPXCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPXCHG32rm, X86_INS_CMPXCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPXCHG32rr, X86_INS_CMPXCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPXCHG64rm, X86_INS_CMPXCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPXCHG64rr, X86_INS_CMPXCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPXCHG8B, X86_INS_CMPXCHG8B,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_EBX, X86_REG_ECX, X86_REG_EDX, 0 }, { X86_REG_EAX, X86_REG_EDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPXCHG8rm, X86_INS_CMPXCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CMPXCHG8rr, X86_INS_CMPXCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CPUID32, X86_INS_CPUID,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_ECX, 0 }, { X86_REG_EAX, X86_REG_EBX, X86_REG_ECX, X86_REG_EDX, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_CPUID64, X86_INS_CPUID,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_RCX, 0 }, { X86_REG_RAX, X86_REG_RBX, X86_REG_RCX, X86_REG_RDX, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_CQO, X86_INS_CQO,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, 0 }, { X86_REG_RAX, X86_REG_RDX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CWD, X86_INS_CWD,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, 0 }, { X86_REG_AX, X86_REG_DX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_CWDE, X86_INS_CWDE,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, 0 }, { X86_REG_EAX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DAA, X86_INS_DAA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_DAS, X86_INS_DAS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_DATA16_PREFIX, X86_INS_DATA16,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DEC16m, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_DEC16r, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_DEC32_16r, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_DEC32_32r, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_DEC32m, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_DEC32r, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_DEC64_16m, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_DEC64_16r, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_DEC64_32m, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_DEC64_32r, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_DEC64m, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DEC64r, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DEC8m, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DEC8r, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIV16m, X86_INS_DIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, X86_REG_DX, 0 }, { X86_REG_AX, X86_REG_DX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIV16r, X86_INS_DIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, X86_REG_DX, 0 }, { X86_REG_AX, X86_REG_DX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIV32m, X86_INS_DIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_EDX, 0 }, { X86_REG_EAX, X86_REG_EDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIV32r, X86_INS_DIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_EDX, 0 }, { X86_REG_EAX, X86_REG_EDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIV64m, X86_INS_DIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_RDX, 0 }, { X86_REG_RAX, X86_REG_RDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIV64r, X86_INS_DIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_RDX, 0 }, { X86_REG_RAX, X86_REG_RDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIV8m, X86_INS_DIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, 0 }, { X86_REG_AL, X86_REG_AH, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_DIV8r, X86_INS_DIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, 0 }, { X86_REG_AL, X86_REG_AH, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ENTER, X86_INS_ENTER,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_FARCALL16i, X86_INS_LCALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { 0 }, { X86_GRP_CALL, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_FARCALL16m, X86_INS_LCALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { 0 }, { X86_GRP_CALL, 0 }, 0, 0
#endif
	},
	{
		X86_FARCALL32i, X86_INS_LCALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { 0 }, { X86_GRP_CALL, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_FARCALL32m, X86_INS_LCALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { 0 }, { X86_GRP_CALL, 0 }, 0, 0
#endif
	},
	{
		X86_FARCALL64, X86_INS_LCALL,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { 0 }, { X86_GRP_CALL, 0 }, 0, 0
#endif
	},
	{
		X86_FARJMP16i, X86_INS_LJMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 1, 1
#endif
	},
	{
		X86_FARJMP16m, X86_INS_LJMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 1
#endif
	},
	{
		X86_FARJMP32i, X86_INS_LJMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 1, 1
#endif
	},
	{
		X86_FARJMP32m, X86_INS_LJMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 1
#endif
	},
	{
		X86_FARJMP64, X86_INS_LJMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 1
#endif
	},
	{
		X86_FSETPM, X86_INS_FSETPM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_GETSEC, X86_INS_GETSEC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_HLT, X86_INS_HLT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IDIV16m, X86_INS_IDIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, X86_REG_DX, 0 }, { X86_REG_AX, X86_REG_DX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IDIV16r, X86_INS_IDIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, X86_REG_DX, 0 }, { X86_REG_AX, X86_REG_DX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IDIV32m, X86_INS_IDIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_EDX, 0 }, { X86_REG_EAX, X86_REG_EDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IDIV32r, X86_INS_IDIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_EDX, 0 }, { X86_REG_EAX, X86_REG_EDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IDIV64m, X86_INS_IDIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_RDX, 0 }, { X86_REG_RAX, X86_REG_RDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IDIV64r, X86_INS_IDIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_RDX, 0 }, { X86_REG_RAX, X86_REG_RDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IDIV8m, X86_INS_IDIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, 0 }, { X86_REG_AL, X86_REG_AH, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IDIV8r, X86_INS_IDIV,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, 0 }, { X86_REG_AL, X86_REG_AH, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL16m, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, 0 }, { X86_REG_AX, X86_REG_DX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL16r, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, 0 }, { X86_REG_AX, X86_REG_DX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL16rm, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL16rmi, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL16rmi8, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL16rr, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL16rri, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL16rri8, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL32m, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { X86_REG_EAX, X86_REG_EDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL32r, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { X86_REG_EAX, X86_REG_EDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL32rm, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL32rmi, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL32rmi8, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL32rr, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL32rri, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL32rri8, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL64m, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, 0 }, { X86_REG_RAX, X86_REG_RDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL64r, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, 0 }, { X86_REG_RAX, X86_REG_RDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL64rm, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL64rmi32, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL64rmi8, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL64rr, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL64rri32, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL64rri8, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL8m, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_AL, 0 }, { X86_REG_AL, X86_REG_EFLAGS, X86_REG_AX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IMUL8r, X86_INS_IMUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_AL, 0 }, { X86_REG_AL, X86_REG_EFLAGS, X86_REG_AX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IN16ri, X86_INS_IN,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_AX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IN16rr, X86_INS_IN,
#ifndef CAPSTONE_DIET
		{ X86_REG_DX, 0 }, { X86_REG_AX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IN32ri, X86_INS_IN,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EAX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IN32rr, X86_INS_IN,
#ifndef CAPSTONE_DIET
		{ X86_REG_DX, 0 }, { X86_REG_EAX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IN8ri, X86_INS_IN,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_AL, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_IN8rr, X86_INS_IN,
#ifndef CAPSTONE_DIET
		{ X86_REG_DX, 0 }, { X86_REG_AL, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_INC16m, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_INC16r, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_INC32_16r, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_INC32_32r, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_INC32m, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_INC32r, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_INC64_16m, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_INC64_16r, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_INC64_32m, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_INC64_32r, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_INC64m, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_INC64r, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_INC8m, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_INC8r, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_INSB, X86_INS_INSB,
#ifndef CAPSTONE_DIET
		{ X86_REG_DX, X86_REG_EDI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_INSL, X86_INS_INSD,
#ifndef CAPSTONE_DIET
		{ X86_REG_DX, X86_REG_EDI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_INSW, X86_INS_INSW,
#ifndef CAPSTONE_DIET
		{ X86_REG_DX, X86_REG_EDI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_INT, X86_INS_INT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_INT, 0 }, 0, 0
#endif
	},
	{
		X86_INT1, X86_INS_INT1,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_INT, 0 }, 0, 0
#endif
	},
	{
		X86_INT3, X86_INS_INT3,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_INT, 0 }, 0, 0
#endif
	},
	{
		X86_INTO, X86_INS_INTO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_INT, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_INVD, X86_INS_INVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_INVEPT32, X86_INS_INVEPT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_INVEPT64, X86_INS_INVEPT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_INVLPG, X86_INS_INVLPG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_INVLPGA32, X86_INS_INVLPGA,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_ECX, 0 }, { 0 }, { X86_GRP_VM, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_INVLPGA64, X86_INS_INVLPGA,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_ECX, 0 }, { 0 }, { X86_GRP_VM, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_INVPCID32, X86_INS_INVPCID,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_INVPCID64, X86_INS_INVPCID,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_INVVPID32, X86_INS_INVVPID,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_INVVPID64, X86_INS_INVVPID,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_IRET16, X86_INS_IRET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_IRET, 0 }, 0, 0
#endif
	},
	{
		X86_IRET32, X86_INS_IRETD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_IRET, 0 }, 0, 0
#endif
	},
	{
		X86_IRET64, X86_INS_IRETQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_IRET, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_JAE_1, X86_INS_JAE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JAE_2, X86_INS_JAE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JAE_4, X86_INS_JAE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JA_1, X86_INS_JA,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JA_2, X86_INS_JA,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JA_4, X86_INS_JA,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JBE_1, X86_INS_JBE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JBE_2, X86_INS_JBE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JBE_4, X86_INS_JBE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JB_1, X86_INS_JB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JB_2, X86_INS_JB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JB_4, X86_INS_JB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JCXZ, X86_INS_JCXZ,
#ifndef CAPSTONE_DIET
		{ X86_REG_CX, 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JECXZ_32, X86_INS_JECXZ,
#ifndef CAPSTONE_DIET
		{ X86_REG_ECX, 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JECXZ_64, X86_INS_JECXZ,
#ifndef CAPSTONE_DIET
		{ X86_REG_ECX, 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 1, 0
#endif
	},
	{
		X86_JE_1, X86_INS_JE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JE_2, X86_INS_JE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JE_4, X86_INS_JE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JGE_1, X86_INS_JGE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JGE_2, X86_INS_JGE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JGE_4, X86_INS_JGE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JG_1, X86_INS_JG,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JG_2, X86_INS_JG,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JG_4, X86_INS_JG,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JLE_1, X86_INS_JLE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JLE_2, X86_INS_JLE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JLE_4, X86_INS_JLE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JL_1, X86_INS_JL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JL_2, X86_INS_JL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JL_4, X86_INS_JL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JMP16m, X86_INS_JMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 1, 1
#endif
	},
	{
		X86_JMP16r, X86_INS_JMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 1, 1
#endif
	},
	{
		X86_JMP32m, X86_INS_JMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 1, 1
#endif
	},
	{
		X86_JMP32r, X86_INS_JMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 1, 1
#endif
	},
	{
		X86_JMP64m, X86_INS_JMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 1, 1
#endif
	},
	{
		X86_JMP64r, X86_INS_JMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 1, 1
#endif
	},
	{
		X86_JMP_1, X86_INS_JMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JMP_2, X86_INS_JMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JMP_4, X86_INS_JMP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JNE_1, X86_INS_JNE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JNE_2, X86_INS_JNE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JNE_4, X86_INS_JNE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JNO_1, X86_INS_JNO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JNO_2, X86_INS_JNO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JNO_4, X86_INS_JNO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JNP_1, X86_INS_JNP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JNP_2, X86_INS_JNP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JNP_4, X86_INS_JNP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JNS_1, X86_INS_JNS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JNS_2, X86_INS_JNS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JNS_4, X86_INS_JNS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JO_1, X86_INS_JO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JO_2, X86_INS_JO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JO_4, X86_INS_JO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JP_1, X86_INS_JP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JP_2, X86_INS_JP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JP_4, X86_INS_JP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JRCXZ, X86_INS_JRCXZ,
#ifndef CAPSTONE_DIET
		{ X86_REG_RCX, 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 1, 0
#endif
	},
	{
		X86_JS_1, X86_INS_JS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_JS_2, X86_INS_JS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 1, 0
#endif
	},
	{
		X86_JS_4, X86_INS_JS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_LAHF, X86_INS_LAHF,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_AH, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LAR16rm, X86_INS_LAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LAR16rr, X86_INS_LAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LAR32rm, X86_INS_LAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LAR32rr, X86_INS_LAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LAR64rm, X86_INS_LAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LAR64rr, X86_INS_LAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LCMPXCHG16, X86_INS_CMPXCHG,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, 0 }, { X86_REG_AX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LCMPXCHG16B, X86_INS_CMPXCHG16B,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_RBX, X86_REG_RCX, X86_REG_RDX, 0 }, { X86_REG_RAX, X86_REG_RDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LCMPXCHG32, X86_INS_CMPXCHG,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { X86_REG_EAX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LCMPXCHG64, X86_INS_CMPXCHG,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, 0 }, { X86_REG_RAX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LCMPXCHG8, X86_INS_CMPXCHG,
#ifndef CAPSTONE_DIET
		{ X86_REG_AL, 0 }, { X86_REG_AL, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LCMPXCHG8B, X86_INS_CMPXCHG8B,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_EBX, X86_REG_ECX, X86_REG_EDX, 0 }, { X86_REG_EAX, X86_REG_EDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LDS16rm, X86_INS_LDS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LDS32rm, X86_INS_LDS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LEA16r, X86_INS_LEA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LEA32r, X86_INS_LEA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_LEA64_32r, X86_INS_LEA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_LEA64r, X86_INS_LEA,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LEAVE, X86_INS_LEAVE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EBP, X86_REG_ESP, 0 }, { X86_REG_EBP, X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_LEAVE64, X86_INS_LEAVE,
#ifndef CAPSTONE_DIET
		{ X86_REG_RBP, X86_REG_RSP, 0 }, { X86_REG_RBP, X86_REG_RSP, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_LES16rm, X86_INS_LES,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LES32rm, X86_INS_LES,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LFS16rm, X86_INS_LFS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LFS32rm, X86_INS_LFS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LFS64rm, X86_INS_LFS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LGDT16m, X86_INS_LGDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_LGDT32m, X86_INS_LGDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_LGDT64m, X86_INS_LGDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_LGS16rm, X86_INS_LGS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LGS32rm, X86_INS_LGS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LGS64rm, X86_INS_LGS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LIDT16m, X86_INS_LIDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_LIDT32m, X86_INS_LIDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_LIDT64m, X86_INS_LIDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_LLDT16m, X86_INS_LLDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LLDT16r, X86_INS_LLDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LMSW16m, X86_INS_LMSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LMSW16r, X86_INS_LMSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_ADD16mi, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_ADD16mi8, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_ADD16mr, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_ADD32mi, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_ADD32mi8, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_ADD32mr, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_ADD64mi32, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_ADD64mi8, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_ADD64mr, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_ADD8mi, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_ADD8mr, X86_INS_ADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_AND16mi, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_AND16mi8, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_AND16mr, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_AND32mi, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_AND32mi8, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_AND32mr, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_AND64mi32, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_AND64mi8, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_AND64mr, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_AND8mi, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_AND8mr, X86_INS_AND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_DEC16m, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_DEC32m, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_DEC64m, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_DEC8m, X86_INS_DEC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_INC16m, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_INC32m, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_INC64m, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_INC8m, X86_INS_INC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_OR16mi, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_OR16mi8, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_OR16mr, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_OR32mi, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_OR32mi8, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_OR32mr, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_OR64mi32, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_OR64mi8, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_OR64mr, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_OR8mi, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_OR8mr, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_SUB16mi, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_SUB16mi8, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_SUB16mr, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_SUB32mi, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_SUB32mi8, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_SUB32mr, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_SUB64mi32, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_SUB64mi8, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_SUB64mr, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_SUB8mi, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_SUB8mr, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_XOR16mi, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_XOR16mi8, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_XOR16mr, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_XOR32mi, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_XOR32mi8, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_XOR32mr, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_XOR64mi32, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_XOR64mi8, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_XOR64mr, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_XOR8mi, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOCK_XOR8mr, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LODSB, X86_INS_LODSB,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_AL, X86_REG_ESI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LODSL, X86_INS_LODSD,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_EAX, X86_REG_ESI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LODSQ, X86_INS_LODSQ,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_RAX, X86_REG_ESI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LODSW, X86_INS_LODSW,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_AX, X86_REG_ESI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LOOP, X86_INS_LOOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_LOOPE, X86_INS_LOOPE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_LOOPNE, X86_INS_LOOPNE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 1, 0
#endif
	},
	{
		X86_LRETIL, X86_INS_RETF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RET, 0 }, 0, 0
#endif
	},
	{
		X86_LRETIQ, X86_INS_RETFQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RET, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_LRETIW, X86_INS_RETF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RET, 0 }, 0, 0
#endif
	},
	{
		X86_LRETL, X86_INS_RETF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RET, 0 }, 0, 0
#endif
	},
	{
		X86_LRETQ, X86_INS_RETFQ,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RET, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_LRETW, X86_INS_RETF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RET, 0 }, 0, 0
#endif
	},
	{
		X86_LSL16rm, X86_INS_LSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LSL16rr, X86_INS_LSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LSL32rm, X86_INS_LSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LSL32rr, X86_INS_LSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LSL64rm, X86_INS_LSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LSL64rr, X86_INS_LSL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LSS16rm, X86_INS_LSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LSS32rm, X86_INS_LSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LSS64rm, X86_INS_LSS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LTRm, X86_INS_LTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LTRr, X86_INS_LTR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LXADD16, X86_INS_XADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LXADD32, X86_INS_XADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LXADD64, X86_INS_XADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LXADD8, X86_INS_XADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LZCNT16rm, X86_INS_LZCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LZCNT16rr, X86_INS_LZCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LZCNT32rm, X86_INS_LZCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LZCNT32rr, X86_INS_LZCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LZCNT64rm, X86_INS_LZCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_LZCNT64rr, X86_INS_LZCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MONTMUL, X86_INS_MONTMUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_RSI, 0 }, { X86_REG_RAX, X86_REG_RDX, X86_REG_RSI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV16ao16, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE32, 0 }, 0, 0
#endif
	},
	{
		X86_MOV16ao16_16, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_MOV16mi, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV16mr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV16ms, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV16o16a, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE32, 0 }, 0, 0
#endif
	},
	{
		X86_MOV16o16a_16, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_MOV16ri, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV16ri_alt, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV16rm, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV16rr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV16rr_REV, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV16rs, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV16sm, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV16sr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV32ao32, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE32, 0 }, 0, 0
#endif
	},
	{
		X86_MOV32ao32_16, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_MOV32cr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_MOV32dr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_MOV32mi, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV32mr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV32ms, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV32o32a, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE32, 0 }, 0, 0
#endif
	},
	{
		X86_MOV32o32a_16, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_MOV32rc, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_MOV32rd, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_MOV32ri, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV32ri_alt, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV32rm, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV32rr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV32rr_REV, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV32rs, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV32sm, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV32sr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV64ao16, X86_INS_MOVABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64ao32, X86_INS_MOVABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64ao64, X86_INS_MOVABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64ao8, X86_INS_MOVABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64cr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64dr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64mi32, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV64mr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV64ms, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV64o16a, X86_INS_MOVABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64o32a, X86_INS_MOVABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64o64a, X86_INS_MOVABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64o8a, X86_INS_MOVABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64rc, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64rd, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOV64ri, X86_INS_MOVABS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV64ri32, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV64rm, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV64rr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV64rr_REV, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV64rs, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV64sm, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV64sr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV8ao8, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE32, 0 }, 0, 0
#endif
	},
	{
		X86_MOV8ao8_16, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_MOV8mi, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV8mr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV8mr_NOREX, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV8o8a, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE32, 0 }, 0, 0
#endif
	},
	{
		X86_MOV8o8a_16, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_16BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_MOV8ri, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV8ri_alt, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV8rm, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV8rm_NOREX, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV8rr, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV8rr_NOREX, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOV8rr_REV, X86_INS_MOV,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVBE16mr, X86_INS_MOVBE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVBE16rm, X86_INS_MOVBE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVBE32mr, X86_INS_MOVBE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVBE32rm, X86_INS_MOVBE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVBE64mr, X86_INS_MOVBE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVBE64rm, X86_INS_MOVBE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSB, X86_INS_MOVSB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDI, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, X86_REG_ESI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSL, X86_INS_MOVSD,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDI, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, X86_REG_ESI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSQ, X86_INS_MOVSQ,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDI, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, X86_REG_ESI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSW, X86_INS_MOVSW,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDI, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, X86_REG_ESI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX16rm8, X86_INS_MOVSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX16rr8, X86_INS_MOVSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX32rm16, X86_INS_MOVSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX32rm8, X86_INS_MOVSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX32rr16, X86_INS_MOVSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX32rr8, X86_INS_MOVSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX64_NOREXrr32, X86_INS_MOVSXD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX64rm16, X86_INS_MOVSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX64rm32, X86_INS_MOVSXD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX64rm8, X86_INS_MOVSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX64rr16, X86_INS_MOVSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX64rr32, X86_INS_MOVSXD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVSX64rr8, X86_INS_MOVSX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVZX16rm8, X86_INS_MOVZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVZX16rr8, X86_INS_MOVZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVZX32_NOREXrm8, X86_INS_MOVZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVZX32_NOREXrr8, X86_INS_MOVZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVZX32rm16, X86_INS_MOVZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVZX32rm8, X86_INS_MOVZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVZX32rr16, X86_INS_MOVZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVZX32rr8, X86_INS_MOVZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVZX64rm16_Q, X86_INS_MOVZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVZX64rm8_Q, X86_INS_MOVZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVZX64rr16_Q, X86_INS_MOVZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MOVZX64rr8_Q, X86_INS_MOVZX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MUL16m, X86_INS_MUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, 0 }, { X86_REG_AX, X86_REG_DX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MUL16r, X86_INS_MUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, 0 }, { X86_REG_AX, X86_REG_DX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MUL32m, X86_INS_MUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { X86_REG_EAX, X86_REG_EDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MUL32r, X86_INS_MUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { X86_REG_EAX, X86_REG_EDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MUL64m, X86_INS_MUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, 0 }, { X86_REG_RAX, X86_REG_RDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MUL64r, X86_INS_MUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, 0 }, { X86_REG_RAX, X86_REG_RDX, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MUL8m, X86_INS_MUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_AL, 0 }, { X86_REG_AL, X86_REG_EFLAGS, X86_REG_AX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MUL8r, X86_INS_MUL,
#ifndef CAPSTONE_DIET
		{ X86_REG_AL, 0 }, { X86_REG_AL, X86_REG_EFLAGS, X86_REG_AX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_MULX32rm, X86_INS_MULX,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDX, 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_MULX32rr, X86_INS_MULX,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDX, 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_MULX64rm, X86_INS_MULX,
#ifndef CAPSTONE_DIET
		{ X86_REG_RDX, 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_MULX64rr, X86_INS_MULX,
#ifndef CAPSTONE_DIET
		{ X86_REG_RDX, 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_NEG16m, X86_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NEG16r, X86_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NEG32m, X86_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NEG32r, X86_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NEG64m, X86_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NEG64r, X86_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NEG8m, X86_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NEG8r, X86_INS_NEG,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_16m4, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_16m5, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_16m6, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_16m7, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_16r4, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_16r5, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_16r6, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_16r7, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_m4, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_m5, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_m6, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_m7, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_r4, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_r5, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_r6, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP18_r7, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOP19rr, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPL, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPL_19, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPL_1a, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPL_1b, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPL_1c, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPL_1d, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPL_1e, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPW, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPW_19, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPW_1a, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPW_1b, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPW_1c, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPW_1d, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOOPW_1e, X86_INS_NOP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOT16m, X86_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOT16r, X86_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOT32m, X86_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOT32r, X86_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOT64m, X86_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOT64r, X86_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOT8m, X86_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_NOT8r, X86_INS_NOT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR16i16, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR16mi, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR16mi8, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR16mr, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR16ri, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR16ri8, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR16rm, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR16rr, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR16rr_REV, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR32i32, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR32mi, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR32mi8, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR32mr, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR32mrLocked, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_OR32ri, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR32ri8, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR32rm, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR32rr, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR32rr_REV, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR64i32, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR64mi32, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR64mi8, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR64mr, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR64ri32, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR64ri8, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR64rm, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR64rr, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR64rr_REV, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR8i8, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR8mi, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR8mr, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR8ri, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR8ri8, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_OR8rm, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR8rr, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OR8rr_REV, X86_INS_OR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OUT16ir, X86_INS_OUT,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OUT16rr, X86_INS_OUT,
#ifndef CAPSTONE_DIET
		{ X86_REG_DX, X86_REG_AX, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OUT32ir, X86_INS_OUT,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OUT32rr, X86_INS_OUT,
#ifndef CAPSTONE_DIET
		{ X86_REG_DX, X86_REG_EAX, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OUT8ir, X86_INS_OUT,
#ifndef CAPSTONE_DIET
		{ X86_REG_AL, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OUT8rr, X86_INS_OUT,
#ifndef CAPSTONE_DIET
		{ X86_REG_DX, X86_REG_AL, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OUTSB, X86_INS_OUTSB,
#ifndef CAPSTONE_DIET
		{ X86_REG_DX, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_ESI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OUTSL, X86_INS_OUTSD,
#ifndef CAPSTONE_DIET
		{ X86_REG_DX, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_ESI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_OUTSW, X86_INS_OUTSW,
#ifndef CAPSTONE_DIET
		{ X86_REG_DX, X86_REG_ESI, X86_REG_EFLAGS, 0 }, { X86_REG_ESI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_PDEP32rm, X86_INS_PDEP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_PDEP32rr, X86_INS_PDEP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_PDEP64rm, X86_INS_PDEP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_PDEP64rr, X86_INS_PDEP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_PEXT32rm, X86_INS_PEXT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_PEXT32rr, X86_INS_PEXT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_PEXT64rm, X86_INS_PEXT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_PEXT64rr, X86_INS_PEXT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_POP16r, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_POP16rmm, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_POP16rmr, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_POP32r, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POP32rmm, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POP32rmr, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POP64r, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { X86_REG_RSP, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_POP64rmm, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { X86_REG_RSP, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_POP64rmr, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { X86_REG_RSP, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_POPA16, X86_INS_POPAW,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_EDI, X86_REG_ESI, X86_REG_EBP, X86_REG_EBX, X86_REG_EDX, X86_REG_ECX, X86_REG_EAX, X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POPA32, X86_INS_POPAL,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_EDI, X86_REG_ESI, X86_REG_EBP, X86_REG_EBX, X86_REG_EDX, X86_REG_ECX, X86_REG_EAX, X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POPDS16, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POPDS32, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POPES16, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POPES32, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POPF16, X86_INS_POPF,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_POPF32, X86_INS_POPFD,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POPF64, X86_INS_POPFQ,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { X86_REG_RSP, X86_REG_EFLAGS, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_POPFS16, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_POPFS32, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POPFS64, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_POPGS16, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_POPGS32, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POPGS64, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_POPSS16, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_POPSS32, X86_INS_POP,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSH16i8, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSH16r, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_PUSH16rmm, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_PUSH16rmr, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_PUSH32i8, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSH32r, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSH32rmm, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSH32rmr, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSH64i16, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { X86_REG_RSP, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_PUSH64i32, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { X86_REG_RSP, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_PUSH64i8, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { X86_REG_RSP, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_PUSH64r, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { X86_REG_RSP, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_PUSH64rmm, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { X86_REG_RSP, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_PUSH64rmr, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, 0 }, { X86_REG_RSP, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHA16, X86_INS_PUSHAW,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDI, X86_REG_ESI, X86_REG_EBP, X86_REG_EBX, X86_REG_EDX, X86_REG_ECX, X86_REG_EAX, X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHA32, X86_INS_PUSHAL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EDI, X86_REG_ESI, X86_REG_EBP, X86_REG_EBX, X86_REG_EDX, X86_REG_ECX, X86_REG_EAX, X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHCS16, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHCS32, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHDS16, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHDS32, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHES16, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHES32, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHF16, X86_INS_PUSHF,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_PUSHF32, X86_INS_PUSHFD,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHF64, X86_INS_PUSHFQ,
#ifndef CAPSTONE_DIET
		{ X86_REG_RSP, X86_REG_EFLAGS, 0 }, { X86_REG_RSP, 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHFS16, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_PUSHFS32, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHFS64, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHGS16, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_PUSHGS32, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHGS64, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHSS16, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHSS32, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHi16, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_PUSHi32, X86_INS_PUSH,
#ifndef CAPSTONE_DIET
		{ X86_REG_ESP, 0 }, { X86_REG_ESP, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_RCL16m1, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL16mCL, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL16mi, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL16r1, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL16rCL, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL16ri, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL32m1, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL32mCL, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL32mi, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL32r1, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL32rCL, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL32ri, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL64m1, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL64mCL, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL64mi, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL64r1, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL64rCL, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL64ri, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL8m1, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL8mCL, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL8mi, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL8r1, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL8rCL, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCL8ri, X86_INS_RCL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR16m1, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR16mCL, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR16mi, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR16r1, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR16rCL, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR16ri, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR32m1, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR32mCL, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR32mi, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR32r1, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR32rCL, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR32ri, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR64m1, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR64mCL, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR64mi, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR64r1, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR64rCL, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR64ri, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR8m1, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR8mCL, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR8mi, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR8r1, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR8rCL, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RCR8ri, X86_INS_RCR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RDFSBASE, X86_INS_RDFSBASE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FSGSBASE, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_RDFSBASE64, X86_INS_RDFSBASE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FSGSBASE, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_RDGSBASE, X86_INS_RDGSBASE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FSGSBASE, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_RDGSBASE64, X86_INS_RDGSBASE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FSGSBASE, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_RDMSR, X86_INS_RDMSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RDPMC, X86_INS_RDPMC,
#ifndef CAPSTONE_DIET
		{ X86_REG_ECX, 0 }, { X86_REG_RAX, X86_REG_RDX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RDRAND16r, X86_INS_RDRAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RDRAND32r, X86_INS_RDRAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RDRAND64r, X86_INS_RDRAND,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RDSEED16r, X86_INS_RDSEED,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RDSEED32r, X86_INS_RDSEED,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RDSEED64r, X86_INS_RDSEED,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RDTSC, X86_INS_RDTSC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_RAX, X86_REG_RDX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RDTSCP, X86_INS_RDTSCP,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RETIL, X86_INS_RET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RET, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_RETIQ, X86_INS_RET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RET, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_RETIW, X86_INS_RET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RET, 0 }, 0, 0
#endif
	},
	{
		X86_RETL, X86_INS_RET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RET, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_RETQ, X86_INS_RET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RET, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_RETW, X86_INS_RET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_RET, 0 }, 0, 0
#endif
	},
	{
		X86_ROL16m1, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL16mCL, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL16mi, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL16r1, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL16rCL, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL16ri, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL32m1, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL32mCL, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL32mi, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL32r1, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL32rCL, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL32ri, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL64m1, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL64mCL, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL64mi, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL64r1, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL64rCL, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL64ri, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL8m1, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL8mCL, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL8mi, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL8r1, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL8rCL, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROL8ri, X86_INS_ROL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR16m1, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR16mCL, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR16mi, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR16r1, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR16rCL, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR16ri, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR32m1, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR32mCL, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR32mi, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR32r1, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR32rCL, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR32ri, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR64m1, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR64mCL, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR64mi, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR64r1, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR64rCL, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR64ri, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR8m1, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR8mCL, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR8mi, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR8r1, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR8rCL, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_ROR8ri, X86_INS_ROR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_RORX32mi, X86_INS_RORX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_RORX32ri, X86_INS_RORX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_RORX64mi, X86_INS_RORX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_RORX64ri, X86_INS_RORX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_RSM, X86_INS_RSM,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAHF, X86_INS_SAHF,
#ifndef CAPSTONE_DIET
		{ X86_REG_AH, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL16m1, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL16mCL, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL16mi, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL16r1, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL16rCL, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL16ri, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL32m1, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL32mCL, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL32mi, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL32r1, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL32rCL, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL32ri, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL64m1, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL64mCL, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL64mi, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL64r1, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL64rCL, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL64ri, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL8m1, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL8mCL, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL8mi, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL8r1, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL8rCL, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAL8ri, X86_INS_SAL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SALC, X86_INS_SALC,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_AL, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_SAR16m1, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR16mCL, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR16mi, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR16r1, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR16rCL, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR16ri, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR32m1, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR32mCL, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR32mi, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR32r1, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR32rCL, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR32ri, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR64m1, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR64mCL, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR64mi, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR64r1, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR64rCL, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR64ri, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR8m1, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR8mCL, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR8mi, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR8r1, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR8rCL, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SAR8ri, X86_INS_SAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SARX32rm, X86_INS_SARX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_SARX32rr, X86_INS_SARX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_SARX64rm, X86_INS_SARX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_SARX64rr, X86_INS_SARX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_SBB16i16, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB16mi, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB16mi8, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB16mr, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB16ri, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB16ri8, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB16rm, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB16rr, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB16rr_REV, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB32i32, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB32mi, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB32mi8, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB32mr, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB32ri, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB32ri8, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB32rm, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB32rr, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB32rr_REV, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB64i32, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB64mi32, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB64mi8, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB64mr, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB64ri32, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB64ri8, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB64rm, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB64rr, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB64rr_REV, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB8i8, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB8mi, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB8mr, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB8ri, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB8rm, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB8rr, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SBB8rr_REV, X86_INS_SBB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SCASB, X86_INS_SCASB,
#ifndef CAPSTONE_DIET
		{ X86_REG_AL, X86_REG_EDI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SCASL, X86_INS_SCASD,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_EDI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SCASQ, X86_INS_SCASQ,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_EDI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SCASW, X86_INS_SCASW,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, X86_REG_EDI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETAEm, X86_INS_SETAE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETAEr, X86_INS_SETAE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETAm, X86_INS_SETA,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETAr, X86_INS_SETA,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETBEm, X86_INS_SETBE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETBEr, X86_INS_SETBE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETBm, X86_INS_SETB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETBr, X86_INS_SETB,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETEm, X86_INS_SETE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETEr, X86_INS_SETE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETGEm, X86_INS_SETGE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETGEr, X86_INS_SETGE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETGm, X86_INS_SETG,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETGr, X86_INS_SETG,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETLEm, X86_INS_SETLE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETLEr, X86_INS_SETLE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETLm, X86_INS_SETL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETLr, X86_INS_SETL,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETNEm, X86_INS_SETNE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETNEr, X86_INS_SETNE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETNOm, X86_INS_SETNO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETNOr, X86_INS_SETNO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETNPm, X86_INS_SETNP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETNPr, X86_INS_SETNP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETNSm, X86_INS_SETNS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETNSr, X86_INS_SETNS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETOm, X86_INS_SETO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETOr, X86_INS_SETO,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETPm, X86_INS_SETP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETPr, X86_INS_SETP,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETSm, X86_INS_SETS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SETSr, X86_INS_SETS,
#ifndef CAPSTONE_DIET
		{ X86_REG_EFLAGS, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SGDT16m, X86_INS_SGDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_SGDT32m, X86_INS_SGDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_SGDT64m, X86_INS_SGDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_SHL16m1, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL16mCL, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL16mi, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL16r1, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL16rCL, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL16ri, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL32m1, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL32mCL, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL32mi, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL32r1, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL32rCL, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL32ri, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL64m1, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL64mCL, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL64mi, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL64r1, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL64rCL, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL64ri, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL8m1, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL8mCL, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL8mi, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL8r1, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL8rCL, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHL8ri, X86_INS_SHL,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLD16mrCL, X86_INS_SHLD,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLD16mri8, X86_INS_SHLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLD16rrCL, X86_INS_SHLD,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLD16rri8, X86_INS_SHLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLD32mrCL, X86_INS_SHLD,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLD32mri8, X86_INS_SHLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLD32rrCL, X86_INS_SHLD,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLD32rri8, X86_INS_SHLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLD64mrCL, X86_INS_SHLD,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLD64mri8, X86_INS_SHLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLD64rrCL, X86_INS_SHLD,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLD64rri8, X86_INS_SHLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHLX32rm, X86_INS_SHLX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_SHLX32rr, X86_INS_SHLX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_SHLX64rm, X86_INS_SHLX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_SHLX64rr, X86_INS_SHLX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_SHR16m1, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR16mCL, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR16mi, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR16r1, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR16rCL, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR16ri, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR32m1, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR32mCL, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR32mi, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR32r1, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR32rCL, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR32ri, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR64m1, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR64mCL, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR64mi, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR64r1, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR64rCL, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR64ri, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR8m1, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR8mCL, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR8mi, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR8r1, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR8rCL, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHR8ri, X86_INS_SHR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRD16mrCL, X86_INS_SHRD,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRD16mri8, X86_INS_SHRD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRD16rrCL, X86_INS_SHRD,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRD16rri8, X86_INS_SHRD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRD32mrCL, X86_INS_SHRD,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRD32mri8, X86_INS_SHRD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRD32rrCL, X86_INS_SHRD,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRD32rri8, X86_INS_SHRD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRD64mrCL, X86_INS_SHRD,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRD64mri8, X86_INS_SHRD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRD64rrCL, X86_INS_SHRD,
#ifndef CAPSTONE_DIET
		{ X86_REG_CL, 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRD64rri8, X86_INS_SHRD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SHRX32rm, X86_INS_SHRX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_SHRX32rr, X86_INS_SHRX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_SHRX64rm, X86_INS_SHRX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_SHRX64rr, X86_INS_SHRX,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_BMI2, 0 }, 0, 0
#endif
	},
	{
		X86_SIDT16m, X86_INS_SIDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_SIDT32m, X86_INS_SIDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_SIDT64m, X86_INS_SIDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_SKINIT, X86_INS_SKINIT,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_SLDT16m, X86_INS_SLDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SLDT16r, X86_INS_SLDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SLDT32r, X86_INS_SLDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SLDT64m, X86_INS_SLDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SLDT64r, X86_INS_SLDT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SMSW16m, X86_INS_SMSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SMSW16r, X86_INS_SMSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SMSW32r, X86_INS_SMSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SMSW64r, X86_INS_SMSW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_STAC, X86_INS_STAC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_SMAP, 0 }, 0, 0
#endif
	},
	{
		X86_STC, X86_INS_STC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_STD, X86_INS_STD,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_STGI, X86_INS_STGI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_STI, X86_INS_STI,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_STOSB, X86_INS_STOSB,
#ifndef CAPSTONE_DIET
		{ X86_REG_AL, X86_REG_EDI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_STOSL, X86_INS_STOSD,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, X86_REG_EDI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_STOSQ, X86_INS_STOSQ,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_RCX, X86_REG_RDI, X86_REG_EFLAGS, 0 }, { X86_REG_RCX, X86_REG_RDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_STOSW, X86_INS_STOSW,
#ifndef CAPSTONE_DIET
		{ X86_REG_AX, X86_REG_EDI, X86_REG_EFLAGS, 0 }, { X86_REG_EDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_STR16r, X86_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_STR32r, X86_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_STR64r, X86_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_STRm, X86_INS_STR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB16i16, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB16mi, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB16mi8, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB16mr, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB16ri, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB16ri8, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB16rm, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB16rr, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB16rr_REV, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB32i32, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB32mi, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB32mi8, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB32mr, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB32ri, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB32ri8, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB32rm, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB32rr, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB32rr_REV, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB64i32, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB64mi32, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB64mi8, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB64mr, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB64ri32, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB64ri8, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB64rm, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB64rr, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB64rr_REV, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB8i8, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB8mi, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB8mr, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB8ri, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB8ri8, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_SUB8rm, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB8rr, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SUB8rr_REV, X86_INS_SUB,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SWAPGS, X86_INS_SWAPGS,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_SYSCALL, X86_INS_SYSCALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_INT, 0 }, 0, 0
#endif
	},
	{
		X86_SYSENTER, X86_INS_SYSENTER,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_INT, 0 }, 0, 0
#endif
	},
	{
		X86_SYSEXIT, X86_INS_SYSEXIT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_IRET, 0 }, 0, 0
#endif
	},
	{
		X86_SYSEXIT64, X86_INS_SYSEXIT,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_IRET, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_SYSRET, X86_INS_SYSRET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_IRET, 0 }, 0, 0
#endif
	},
	{
		X86_SYSRET64, X86_INS_SYSRET,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_IRET, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_T1MSKC32rm, X86_INS_T1MSKC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_T1MSKC32rr, X86_INS_T1MSKC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_T1MSKC64rm, X86_INS_T1MSKC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_T1MSKC64rr, X86_INS_T1MSKC,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_TEST16i16, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST16mi, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST16mi_alt, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST16ri, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST16ri_alt, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST16rm, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST16rr, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST32i32, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST32mi, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST32mi_alt, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST32ri, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST32ri_alt, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST32rm, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST32rr, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST64i32, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST64mi32, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST64mi32_alt, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST64ri32, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST64ri32_alt, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST64rm, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST64rr, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST8i8, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST8mi, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST8mi_alt, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST8ri, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST8ri_alt, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST8rm, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TEST8rr, X86_INS_TEST,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TRAP, X86_INS_UD2,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_TZCNT16rm, X86_INS_TZCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_TZCNT16rr, X86_INS_TZCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_TZCNT32rm, X86_INS_TZCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_TZCNT32rr, X86_INS_TZCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_TZCNT64rm, X86_INS_TZCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_TZCNT64rr, X86_INS_TZCNT,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_BMI, 0 }, 0, 0
#endif
	},
	{
		X86_TZMSK32rm, X86_INS_TZMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_TZMSK32rr, X86_INS_TZMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_TZMSK64rm, X86_INS_TZMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_TZMSK64rr, X86_INS_TZMSK,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_TBM, 0 }, 0, 0
#endif
	},
	{
		X86_UD2B, X86_INS_UD2B,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_VERRm, X86_INS_VERR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_VERRr, X86_INS_VERR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_VERWm, X86_INS_VERW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_VERWr, X86_INS_VERW,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_VMCALL, X86_INS_VMCALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_VMCLEARm, X86_INS_VMCLEAR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_VMFUNC, X86_INS_VMFUNC,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_VMLAUNCH, X86_INS_VMLAUNCH,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_VMLOAD32, X86_INS_VMLOAD,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { 0 }, { X86_GRP_VM, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_VMLOAD64, X86_INS_VMLOAD,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, 0 }, { 0 }, { X86_GRP_VM, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_VMMCALL, X86_INS_VMMCALL,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_VMPTRLDm, X86_INS_VMPTRLD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_VMPTRSTm, X86_INS_VMPTRST,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_VMREAD32rm, X86_INS_VMREAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_VMREAD32rr, X86_INS_VMREAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_VMREAD64rm, X86_INS_VMREAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_VMREAD64rr, X86_INS_VMREAD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_VMRESUME, X86_INS_VMRESUME,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_VMRUN32, X86_INS_VMRUN,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { 0 }, { X86_GRP_VM, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_VMRUN64, X86_INS_VMRUN,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, 0 }, { 0 }, { X86_GRP_VM, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_VMSAVE32, X86_INS_VMSAVE,
#ifndef CAPSTONE_DIET
		{ X86_REG_EAX, 0 }, { 0 }, { X86_GRP_VM, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_VMSAVE64, X86_INS_VMSAVE,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, 0 }, { 0 }, { X86_GRP_VM, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_VMWRITE32rm, X86_INS_VMWRITE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_VMWRITE32rr, X86_INS_VMWRITE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_VMWRITE64rm, X86_INS_VMWRITE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_VMWRITE64rr, X86_INS_VMWRITE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_VMXOFF, X86_INS_VMXOFF,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_VMXON, X86_INS_VMXON,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_VM, 0 }, 0, 0
#endif
	},
	{
		X86_WBINVD, X86_INS_WBINVD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_WRFSBASE, X86_INS_WRFSBASE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FSGSBASE, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_WRFSBASE64, X86_INS_WRFSBASE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FSGSBASE, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_WRGSBASE, X86_INS_WRGSBASE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FSGSBASE, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_WRGSBASE64, X86_INS_WRGSBASE,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_FSGSBASE, X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_WRMSR, X86_INS_WRMSR,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XADD16rm, X86_INS_XADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XADD16rr, X86_INS_XADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XADD32rm, X86_INS_XADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XADD32rr, X86_INS_XADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XADD64rm, X86_INS_XADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XADD64rr, X86_INS_XADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XADD8rm, X86_INS_XADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XADD8rr, X86_INS_XADD,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCHG16ar, X86_INS_XCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCHG16rm, X86_INS_XCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCHG16rr, X86_INS_XCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCHG32ar, X86_INS_XCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_XCHG32ar64, X86_INS_XCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_XCHG32rm, X86_INS_XCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCHG32rr, X86_INS_XCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCHG64ar, X86_INS_XCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCHG64rm, X86_INS_XCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCHG64rr, X86_INS_XCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCHG8rm, X86_INS_XCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCHG8rr, X86_INS_XCHG,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCRYPTCBC, X86_INS_XCRYPTCBC,
#ifndef CAPSTONE_DIET
		{ X86_REG_RBX, X86_REG_RDX, X86_REG_RSI, X86_REG_RDI, 0 }, { X86_REG_RSI, X86_REG_RDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCRYPTCFB, X86_INS_XCRYPTCFB,
#ifndef CAPSTONE_DIET
		{ X86_REG_RBX, X86_REG_RDX, X86_REG_RSI, X86_REG_RDI, 0 }, { X86_REG_RSI, X86_REG_RDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCRYPTCTR, X86_INS_XCRYPTCTR,
#ifndef CAPSTONE_DIET
		{ X86_REG_RBX, X86_REG_RDX, X86_REG_RSI, X86_REG_RDI, 0 }, { X86_REG_RSI, X86_REG_RDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCRYPTECB, X86_INS_XCRYPTECB,
#ifndef CAPSTONE_DIET
		{ X86_REG_RBX, X86_REG_RDX, X86_REG_RSI, X86_REG_RDI, 0 }, { X86_REG_RSI, X86_REG_RDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XCRYPTOFB, X86_INS_XCRYPTOFB,
#ifndef CAPSTONE_DIET
		{ X86_REG_RBX, X86_REG_RDX, X86_REG_RSI, X86_REG_RDI, 0 }, { X86_REG_RSI, X86_REG_RDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XGETBV, X86_INS_XGETBV,
#ifndef CAPSTONE_DIET
		{ X86_REG_RCX, 0 }, { X86_REG_RDX, X86_REG_RAX, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XLAT, X86_INS_XLATB,
#ifndef CAPSTONE_DIET
		{ 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR16i16, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR16mi, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR16mi8, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR16mr, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR16ri, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR16ri8, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR16rm, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR16rr, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR16rr_REV, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR32i32, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR32mi, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR32mi8, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR32mr, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR32ri, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR32ri8, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR32rm, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR32rr, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR32rr_REV, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR64i32, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR64mi32, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR64mi8, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR64mr, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR64ri32, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR64ri8, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR64rm, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR64rr, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR64rr_REV, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR8i8, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR8mi, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR8mr, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR8ri, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR8ri8, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { X86_GRP_NOT64BITMODE, 0 }, 0, 0
#endif
	},
	{
		X86_XOR8rm, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR8rr, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XOR8rr_REV, X86_INS_XOR,
#ifndef CAPSTONE_DIET
		{ 0 }, { X86_REG_EFLAGS, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XRSTOR, X86_INS_XRSTOR,
#ifndef CAPSTONE_DIET
		{ X86_REG_RDX, X86_REG_RAX, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XRSTOR64, X86_INS_XRSTOR64,
#ifndef CAPSTONE_DIET
		{ X86_REG_RDX, X86_REG_RAX, 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_XSAVE, X86_INS_XSAVE,
#ifndef CAPSTONE_DIET
		{ X86_REG_RDX, X86_REG_RAX, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XSAVE64, X86_INS_XSAVE64,
#ifndef CAPSTONE_DIET
		{ X86_REG_RDX, X86_REG_RAX, 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_XSAVEOPT, X86_INS_XSAVEOPT,
#ifndef CAPSTONE_DIET
		{ X86_REG_RDX, X86_REG_RAX, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XSAVEOPT64, X86_INS_XSAVEOPT64,
#ifndef CAPSTONE_DIET
		{ X86_REG_RDX, X86_REG_RAX, 0 }, { 0 }, { X86_GRP_MODE64, 0 }, 0, 0
#endif
	},
	{
		X86_XSETBV, X86_INS_XSETBV,
#ifndef CAPSTONE_DIET
		{ X86_REG_RDX, X86_REG_RAX, X86_REG_RCX, 0 }, { 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XSHA1, X86_INS_XSHA1,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_RSI, X86_REG_RDI, 0 }, { X86_REG_RAX, X86_REG_RSI, X86_REG_RDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XSHA256, X86_INS_XSHA256,
#ifndef CAPSTONE_DIET
		{ X86_REG_RAX, X86_REG_RSI, X86_REG_RDI, 0 }, { X86_REG_RAX, X86_REG_RSI, X86_REG_RDI, 0 }, { 0 }, 0, 0
#endif
	},
	{
		X86_XSTORE, X86_INS_XSTORE,
#ifndef CAPSTONE_DIET
		{ X86_REG_RDX, X86_REG_RDI, 0 }, { X86_REG_RAX, X86_REG_RDI, 0 }, { 0 }, 0, 0
#endif
	},
};
#endif

#ifndef CAPSTONE_DIET
// replace r1 = r2
static void arr_replace(uint8_t *arr, uint8_t max, x86_reg r1, x86_reg r2)
{
	uint8_t i;

	for(i = 0; i < max; i++) {
		if (arr[i] == r1) {
			arr[i] = r2;
			break;
		}
	}
}
#endif

// given internal insn id, return public instruction info
void X86_get_insn_id(cs_struct *h, cs_insn *insn, unsigned int id)
{
	int i = insn_find(insns, ARR_SIZE(insns), id, &h->insn_cache);
	if (i != 0) {
		insn->id = insns[i].mapid;

		if (h->detail) {
#ifndef CAPSTONE_DIET
			memcpy(insn->detail->regs_read, insns[i].regs_use, sizeof(insns[i].regs_use));
			insn->detail->regs_read_count = (uint8_t)count_positive(insns[i].regs_use);

			// special cases when regs_write[] depends on arch
			switch(id) {
				default:
					memcpy(insn->detail->regs_write, insns[i].regs_mod, sizeof(insns[i].regs_mod));
					insn->detail->regs_write_count = (uint8_t)count_positive(insns[i].regs_mod);
					break;
				case X86_RDTSC:
					if (h->mode == CS_MODE_64) {
						memcpy(insn->detail->regs_write, insns[i].regs_mod, sizeof(insns[i].regs_mod));
						insn->detail->regs_write_count = (uint8_t)count_positive(insns[i].regs_mod);
					} else {
						insn->detail->regs_write[0] = X86_REG_EAX;
						insn->detail->regs_write[1] = X86_REG_EDX;
						insn->detail->regs_write_count = 2;
					}
					break;
				case X86_RDTSCP:
					if (h->mode == CS_MODE_64) {
						memcpy(insn->detail->regs_write, insns[i].regs_mod, sizeof(insns[i].regs_mod));
						insn->detail->regs_write_count = (uint8_t)count_positive(insns[i].regs_mod);
					} else {
						insn->detail->regs_write[0] = X86_REG_EAX;
						insn->detail->regs_write[1] = X86_REG_ECX;
						insn->detail->regs_write[2] = X86_REG_EDX;
						insn->detail->regs_write_count = 3;
					}
					break;
			}

			switch(insn->id) {
				default:
					break;

				case X86_INS_LOOP:
				case X86_INS_LOOPE:
				case X86_INS_LOOPNE:
					switch(h->mode) {
						default: break;
						case CS_MODE_16:
								 insn->detail->regs_read[0] = X86_REG_CX;
								 insn->detail->regs_read_count = 1;
								 insn->detail->regs_write[0] = X86_REG_CX;
								 insn->detail->regs_write_count = 1;
								 break;
						case CS_MODE_32:
								 insn->detail->regs_read[0] = X86_REG_ECX;
								 insn->detail->regs_read_count = 1;
								 insn->detail->regs_write[0] = X86_REG_ECX;
								 insn->detail->regs_write_count = 1;
								 break;
						case CS_MODE_64:
								 insn->detail->regs_read[0] = X86_REG_RCX;
								 insn->detail->regs_read_count = 1;
								 insn->detail->regs_write[0] = X86_REG_RCX;
								 insn->detail->regs_write_count = 1;
								 break;
					}

					// LOOPE & LOOPNE also read EFLAGS
					if (insn->id != X86_INS_LOOP) {
						insn->detail->regs_read[1] = X86_REG_EFLAGS;
						insn->detail->regs_read_count = 2;
					}

					break;

				case X86_INS_LODSB:
				case X86_INS_LODSD:
				case X86_INS_LODSQ:
				case X86_INS_LODSW:
					switch(h->mode) {
						default:
							break;
						case CS_MODE_16:
							arr_replace(insn->detail->regs_read, insn->detail->regs_read_count, X86_REG_ESI, X86_REG_SI);
							arr_replace(insn->detail->regs_write, insn->detail->regs_write_count, X86_REG_ESI, X86_REG_SI);
							break;
						case CS_MODE_64:
							arr_replace(insn->detail->regs_read, insn->detail->regs_read_count, X86_REG_ESI, X86_REG_RSI);
							arr_replace(insn->detail->regs_write, insn->detail->regs_write_count, X86_REG_ESI, X86_REG_RSI);
							break;
					}
					break;

				case X86_INS_SCASB:
				case X86_INS_SCASW:
				case X86_INS_SCASQ:
				case X86_INS_STOSB:
				case X86_INS_STOSD:
				case X86_INS_STOSQ:
				case X86_INS_STOSW:
					switch(h->mode) {
						default:
							break;
						case CS_MODE_16:
							arr_replace(insn->detail->regs_read, insn->detail->regs_read_count, X86_REG_EDI, X86_REG_DI);
							arr_replace(insn->detail->regs_write, insn->detail->regs_write_count, X86_REG_EDI, X86_REG_DI);
							break;
						case CS_MODE_64:
							arr_replace(insn->detail->regs_read, insn->detail->regs_read_count, X86_REG_EDI, X86_REG_RDI);
							arr_replace(insn->detail->regs_write, insn->detail->regs_write_count, X86_REG_EDI, X86_REG_RDI);
							break;
					}
					break;

				case X86_INS_CMPSB:
				case X86_INS_CMPSD:
				case X86_INS_CMPSQ:
				case X86_INS_CMPSW:
				case X86_INS_MOVSB:
				case X86_INS_MOVSW:
				case X86_INS_MOVSD:
				case X86_INS_MOVSQ:
					switch(h->mode) {
						default:
							break;
						case CS_MODE_16:
							arr_replace(insn->detail->regs_read, insn->detail->regs_read_count, X86_REG_EDI, X86_REG_DI);
							arr_replace(insn->detail->regs_write, insn->detail->regs_write_count, X86_REG_EDI, X86_REG_DI);
							arr_replace(insn->detail->regs_read, insn->detail->regs_read_count, X86_REG_ESI, X86_REG_SI);
							arr_replace(insn->detail->regs_write, insn->detail->regs_write_count, X86_REG_ESI, X86_REG_SI);
							break;
						case CS_MODE_64:
							arr_replace(insn->detail->regs_read, insn->detail->regs_read_count, X86_REG_EDI, X86_REG_RDI);
							arr_replace(insn->detail->regs_write, insn->detail->regs_write_count, X86_REG_EDI, X86_REG_RDI);
							arr_replace(insn->detail->regs_read, insn->detail->regs_read_count, X86_REG_ESI, X86_REG_RSI);
							arr_replace(insn->detail->regs_write, insn->detail->regs_write_count, X86_REG_ESI, X86_REG_RSI);
							break;
					}
					break;
			}

			memcpy(insn->detail->groups, insns[i].groups, sizeof(insns[i].groups));
			insn->detail->groups_count = (uint8_t)count_positive(insns[i].groups);

			if (insns[i].branch || insns[i].indirect_branch) {
				// this insn also belongs to JUMP group. add JUMP group
				insn->detail->groups[insn->detail->groups_count] = X86_GRP_JUMP;
				insn->detail->groups_count++;
			}

			switch (insns[i].id) {
				case X86_OUT8ir:
				case X86_OUT16ir:
				case X86_OUT32ir:
					if (insn->detail->x86.operands[0].imm == -78) {
						// Writing to port 0xb2 causes an SMI on most platforms
						// See: http://cs.gmu.edu/~tr-admin/papers/GMU-CS-TR-2011-8.pdf
						insn->detail->groups[insn->detail->groups_count] = X86_GRP_INT;
						insn->detail->groups_count++;
					}
					break;

				default:
					break;
			}
#endif
		}
	}
}

// map special instructions with accumulate registers.
// this is needed because LLVM embeds these register names into AsmStrs[],
// but not separately in operands
struct insn_reg {
	uint16_t insn;
	x86_reg reg;
};

struct insn_reg2 {
	uint16_t insn;
	x86_reg reg1, reg2;
};

static const struct insn_reg insn_regs_att[] = {
	{ X86_INSB, X86_REG_DX },
	{ X86_INSW, X86_REG_DX },
	{ X86_INSL, X86_REG_DX },

	{ X86_MOV16ao16, X86_REG_AX },

	{ X86_MOV32ao32, X86_REG_EAX },
	{ X86_MOV64o64a, X86_REG_RAX },

	{ X86_PUSHCS32, X86_REG_CS },
	{ X86_PUSHDS32, X86_REG_DS },
	{ X86_PUSHES32, X86_REG_ES },
	{ X86_PUSHFS32, X86_REG_FS },
	{ X86_PUSHGS32, X86_REG_GS },
	{ X86_PUSHSS32, X86_REG_SS },

	{ X86_PUSHFS64, X86_REG_FS },
	{ X86_PUSHGS64, X86_REG_GS },

	{ X86_PUSHCS16, X86_REG_CS },
	{ X86_PUSHDS16, X86_REG_DS },
	{ X86_PUSHES16, X86_REG_ES },
	{ X86_PUSHFS16, X86_REG_FS },
	{ X86_PUSHGS16, X86_REG_GS },
	{ X86_PUSHSS16, X86_REG_SS },

	{ X86_POPDS32, X86_REG_DS },
	{ X86_POPES32, X86_REG_ES },
	{ X86_POPFS32, X86_REG_FS },
	{ X86_POPGS32, X86_REG_GS },
	{ X86_POPSS32, X86_REG_SS },

	{ X86_POPFS64, X86_REG_FS },
	{ X86_POPGS64, X86_REG_GS },

	{ X86_POPDS16, X86_REG_DS },
	{ X86_POPES16, X86_REG_ES },
	{ X86_POPFS16, X86_REG_FS },
	{ X86_POPGS16, X86_REG_GS },
	{ X86_POPSS16, X86_REG_SS },

	{ X86_RCL32rCL, X86_REG_CL },
	{ X86_SHL8rCL, X86_REG_CL },
	{ X86_SHL16rCL, X86_REG_CL },
	{ X86_SHL32rCL, X86_REG_CL },
	{ X86_SHL64rCL, X86_REG_CL },
	{ X86_SAL8rCL, X86_REG_CL },
	{ X86_SAL16rCL, X86_REG_CL },
	{ X86_SAL32rCL, X86_REG_CL },
	{ X86_SAL64rCL, X86_REG_CL },
	{ X86_SHR8rCL, X86_REG_CL },
	{ X86_SHR16rCL, X86_REG_CL },
	{ X86_SHR32rCL, X86_REG_CL },
	{ X86_SHR64rCL, X86_REG_CL },
	{ X86_SAR8rCL, X86_REG_CL },
	{ X86_SAR16rCL, X86_REG_CL },
	{ X86_SAR32rCL, X86_REG_CL },
	{ X86_SAR64rCL, X86_REG_CL },
	{ X86_RCL8rCL, X86_REG_CL },
	{ X86_RCL16rCL, X86_REG_CL },
	{ X86_RCL32rCL, X86_REG_CL },
	{ X86_RCL64rCL, X86_REG_CL },
	{ X86_RCR8rCL, X86_REG_CL },
	{ X86_RCR16rCL, X86_REG_CL },
	{ X86_RCR32rCL, X86_REG_CL },
	{ X86_RCR64rCL, X86_REG_CL },
	{ X86_ROL8rCL, X86_REG_CL },
	{ X86_ROL16rCL, X86_REG_CL },
	{ X86_ROL32rCL, X86_REG_CL },
	{ X86_ROL64rCL, X86_REG_CL },
	{ X86_ROR8rCL, X86_REG_CL },
	{ X86_ROR16rCL, X86_REG_CL },
	{ X86_ROR32rCL, X86_REG_CL },
	{ X86_ROR64rCL, X86_REG_CL },
	{ X86_SHLD16rrCL, X86_REG_CL },
	{ X86_SHRD16rrCL, X86_REG_CL },
	{ X86_SHLD32rrCL, X86_REG_CL },
	{ X86_SHRD32rrCL, X86_REG_CL },
	{ X86_SHLD64rrCL, X86_REG_CL },
	{ X86_SHRD64rrCL, X86_REG_CL },
	{ X86_SHLD16mrCL, X86_REG_CL },
	{ X86_SHRD16mrCL, X86_REG_CL },
	{ X86_SHLD32mrCL, X86_REG_CL },
	{ X86_SHRD32mrCL, X86_REG_CL },
	{ X86_SHLD64mrCL, X86_REG_CL },
	{ X86_SHRD64mrCL, X86_REG_CL },

	{ X86_OUT8ir, X86_REG_AL },
	{ X86_OUT16ir, X86_REG_AX },
	{ X86_OUT32ir, X86_REG_EAX },

#ifndef CAPSTONE_X86_REDUCE
	{ X86_SKINIT, X86_REG_EAX },
	{ X86_VMRUN32, X86_REG_EAX },
	{ X86_VMRUN64, X86_REG_RAX },
	{ X86_VMLOAD32, X86_REG_EAX },
	{ X86_VMLOAD64, X86_REG_RAX },
	{ X86_VMSAVE32, X86_REG_EAX },
	{ X86_VMSAVE64, X86_REG_RAX },

	{ X86_FNSTSW16r, X86_REG_AX },

	{ X86_ADD_FrST0, X86_REG_ST0 },
	{ X86_SUB_FrST0, X86_REG_ST0 },
	{ X86_SUBR_FrST0, X86_REG_ST0 },
	{ X86_MUL_FrST0, X86_REG_ST0 },
	{ X86_DIV_FrST0, X86_REG_ST0 },
	{ X86_DIVR_FrST0, X86_REG_ST0 },
#endif
};

static const struct insn_reg insn_regs_intel[] = {
	{ X86_OUTSB, X86_REG_DX },
	{ X86_OUTSW, X86_REG_DX },
	{ X86_OUTSL, X86_REG_DX },

	{ X86_MOV8o8a, X86_REG_AL },   // a02857887c = mov al, byte ptr[0x7c885728]
	{ X86_MOV32o32a, X86_REG_EAX },
	{ X86_MOV16o16a, X86_REG_AX },
	{ X86_MOV64o64a, X86_REG_RAX },
	{ X86_MOV64o32a, X86_REG_EAX },

	{ X86_MOV64ao32, X86_REG_RAX },   // 64-bit 48 8B04 10203040         // mov     rax, qword ptr [0x40302010]

	{ X86_LODSQ, X86_REG_RAX },
	{ X86_OR32i32, X86_REG_EAX },
	{ X86_SUB32i32, X86_REG_EAX },
	{ X86_TEST32i32, X86_REG_EAX },
	{ X86_ADD32i32, X86_REG_EAX },
	{ X86_XCHG64ar, X86_REG_RAX },
	{ X86_LODSB, X86_REG_AL },
	{ X86_AND32i32, X86_REG_EAX },
	{ X86_IN16ri, X86_REG_AX },
	{ X86_CMP64i32, X86_REG_RAX },
	{ X86_XOR32i32, X86_REG_EAX },
	{ X86_XCHG16ar, X86_REG_AX },
	{ X86_LODSW, X86_REG_AX },
	{ X86_AND16i16, X86_REG_AX },
	{ X86_ADC16i16, X86_REG_AX },
	{ X86_XCHG32ar64, X86_REG_EAX },
	{ X86_ADC8i8, X86_REG_AL },
	{ X86_CMP32i32, X86_REG_EAX },
	{ X86_AND8i8, X86_REG_AL },
	{ X86_SCASW, X86_REG_AX },
	{ X86_XOR8i8, X86_REG_AL },
	{ X86_SUB16i16, X86_REG_AX },
	{ X86_OR16i16, X86_REG_AX },
	{ X86_XCHG32ar, X86_REG_EAX },
	{ X86_SBB8i8, X86_REG_AL },
	{ X86_SCASQ, X86_REG_RAX },
	{ X86_SBB32i32, X86_REG_EAX },
	{ X86_XOR64i32, X86_REG_RAX },
	{ X86_SUB64i32, X86_REG_RAX },
	{ X86_ADD64i32, X86_REG_RAX },
	{ X86_OR8i8, X86_REG_AL },
	{ X86_TEST64i32, X86_REG_RAX },
	{ X86_SBB16i16, X86_REG_AX },
	{ X86_TEST8i8, X86_REG_AL },
	{ X86_IN8ri, X86_REG_AL },
	{ X86_TEST16i16, X86_REG_AX },
	{ X86_SCASL, X86_REG_EAX },
	{ X86_SUB8i8, X86_REG_AL },
	{ X86_ADD8i8, X86_REG_AL },
	{ X86_OR64i32, X86_REG_RAX },
	{ X86_SCASB, X86_REG_AL },
	{ X86_SBB64i32, X86_REG_RAX },
	{ X86_ADD16i16, X86_REG_AX },
	{ X86_XOR16i16, X86_REG_AX },
	{ X86_AND64i32, X86_REG_RAX },
	{ X86_LODSL, X86_REG_EAX },
	{ X86_CMP8i8, X86_REG_AL },
	{ X86_ADC64i32, X86_REG_RAX },
	{ X86_CMP16i16, X86_REG_AX },
	{ X86_ADC32i32, X86_REG_EAX },
	{ X86_IN32ri, X86_REG_EAX },

	{ X86_PUSHCS32, X86_REG_CS },
	{ X86_PUSHDS32, X86_REG_DS },
	{ X86_PUSHES32, X86_REG_ES },
	{ X86_PUSHFS32, X86_REG_FS },
	{ X86_PUSHGS32, X86_REG_GS },
	{ X86_PUSHSS32, X86_REG_SS },

	{ X86_PUSHFS64, X86_REG_FS },
	{ X86_PUSHGS64, X86_REG_GS },

	{ X86_PUSHCS16, X86_REG_CS },
	{ X86_PUSHDS16, X86_REG_DS },
	{ X86_PUSHES16, X86_REG_ES },
	{ X86_PUSHFS16, X86_REG_FS },
	{ X86_PUSHGS16, X86_REG_GS },
	{ X86_PUSHSS16, X86_REG_SS },

	{ X86_POPDS32, X86_REG_DS },
	{ X86_POPES32, X86_REG_ES },
	{ X86_POPFS32, X86_REG_FS },
	{ X86_POPGS32, X86_REG_GS },
	{ X86_POPSS32, X86_REG_SS },

	{ X86_POPFS64, X86_REG_FS },
	{ X86_POPGS64, X86_REG_GS },

	{ X86_POPDS16, X86_REG_DS },
	{ X86_POPES16, X86_REG_ES },
	{ X86_POPFS16, X86_REG_FS },
	{ X86_POPGS16, X86_REG_GS },
	{ X86_POPSS16, X86_REG_SS },

#ifndef CAPSTONE_X86_REDUCE
	{ X86_SKINIT, X86_REG_EAX },
	{ X86_VMRUN32, X86_REG_EAX },
	{ X86_VMRUN64, X86_REG_RAX },
	{ X86_VMLOAD32, X86_REG_EAX },
	{ X86_VMLOAD64, X86_REG_RAX },
	{ X86_VMSAVE32, X86_REG_EAX },
	{ X86_VMSAVE64, X86_REG_RAX },

	{ X86_FNSTSW16r, X86_REG_AX },

	{ X86_CMOVB_F, X86_REG_ST0 },
	{ X86_CMOVBE_F, X86_REG_ST0 },
	{ X86_CMOVE_F, X86_REG_ST0 },
	{ X86_CMOVP_F, X86_REG_ST0 },
	{ X86_CMOVNB_F, X86_REG_ST0 },
	{ X86_CMOVNBE_F, X86_REG_ST0 },
	{ X86_CMOVNE_F, X86_REG_ST0 },
	{ X86_CMOVNP_F, X86_REG_ST0 },
	{ X86_ST_FXCHST0r, X86_REG_ST0 },
	{ X86_ST_FXCHST0r_alt, X86_REG_ST0 },
	{ X86_ST_FCOMST0r, X86_REG_ST0 },
	{ X86_ST_FCOMPST0r, X86_REG_ST0 },
	{ X86_ST_FCOMPST0r_alt, X86_REG_ST0 },
	{ X86_ST_FPST0r, X86_REG_ST0 },
	{ X86_ST_FPST0r_alt, X86_REG_ST0 },
	{ X86_ST_FPNCEST0r, X86_REG_ST0 },
#endif
};

static const struct insn_reg2 insn_regs_intel2[] = {
	{ X86_IN8rr, X86_REG_AL, X86_REG_DX },
	{ X86_IN16rr, X86_REG_AX, X86_REG_DX },
	{ X86_IN32rr, X86_REG_EAX, X86_REG_DX },

	{ X86_OUT8rr, X86_REG_DX, X86_REG_AL },
	{ X86_OUT16rr, X86_REG_DX, X86_REG_AX },
	{ X86_OUT32rr, X86_REG_DX, X86_REG_EAX },
};

// return register of given instruction id
// return 0 if not found
// this is to handle instructions embedding accumulate registers into AsmStrs[]
x86_reg X86_insn_reg_intel(unsigned int id)
{
	unsigned int i;

	for (i = 0; i < ARR_SIZE(insn_regs_intel); i++) {
		if (insn_regs_intel[i].insn == id) {
			return insn_regs_intel[i].reg;
		}
	}

	// not found
	return 0;
}

bool X86_insn_reg_intel2(unsigned int id, x86_reg *reg1, x86_reg *reg2)
{
	unsigned int i;

	for (i = 0; i < ARR_SIZE(insn_regs_intel2); i++) {
		if (insn_regs_intel2[i].insn == id) {
			*reg1 = insn_regs_intel2[i].reg1;
			*reg2 = insn_regs_intel2[i].reg2;
			return true;
		}
	}

	// not found
	return false;
}

// ATT just reuses Intel data, but with the order of registers reversed
bool X86_insn_reg_att2(unsigned int id, x86_reg *reg1, x86_reg *reg2)
{
	unsigned int i;

	for (i = 0; i < ARR_SIZE(insn_regs_intel2); i++) {
		if (insn_regs_intel2[i].insn == id) {
			// reverse order of Intel syntax registers
			*reg1 = insn_regs_intel2[i].reg2;
			*reg2 = insn_regs_intel2[i].reg1;
			return true;
		}
	}

	// not found
	return false;
}

x86_reg X86_insn_reg_att(unsigned int id)
{
	unsigned int i;

	for (i = 0; i < ARR_SIZE(insn_regs_att); i++) {
		if (insn_regs_att[i].insn == id) {
			return insn_regs_att[i].reg;
		}
	}

	// not found
	return 0;
}

// given MCInst's id, find out if this insn is valid for REPNE prefix
static bool valid_repne(cs_struct *h, unsigned int opcode)
{
	unsigned int id;
	int i = insn_find(insns, ARR_SIZE(insns), opcode, &h->insn_cache);
	if (i != 0) {
		id = insns[i].mapid;
		switch(id) {
			default:
				return false;

			case X86_INS_CMPSB:
			case X86_INS_CMPSW:
			case X86_INS_CMPSQ:

			case X86_INS_SCASB:
			case X86_INS_SCASW:
			case X86_INS_SCASQ:

			case X86_INS_MOVSB:
			case X86_INS_MOVSW:
			case X86_INS_MOVSD:
			case X86_INS_MOVSQ:

			case X86_INS_LODSB:
			case X86_INS_LODSW:
			case X86_INS_LODSD:
			case X86_INS_LODSQ:

			case X86_INS_STOSB:
			case X86_INS_STOSW:
			case X86_INS_STOSD:
			case X86_INS_STOSQ:

			case X86_INS_INSB:
			case X86_INS_INSW:
			case X86_INS_INSD:

			case X86_INS_OUTSB:
			case X86_INS_OUTSW:
			case X86_INS_OUTSD:

				return true;

			case X86_INS_CMPSD:
				if (opcode == X86_CMPSL) // REP CMPSD
					return true;
				return false;

			case X86_INS_SCASD:
				if (opcode == X86_SCASL) // REP SCASD
					return true;
				return false;
		}
	}

	// not found
	return false;
}

// given MCInst's id, find out if this insn is valid for BND prefix
// BND prefix is valid for CALL/JMP/RET
#ifndef CAPSTONE_DIET
static bool valid_bnd(cs_struct *h, unsigned int opcode)
{
	unsigned int id;
	int i = insn_find(insns, ARR_SIZE(insns), opcode, &h->insn_cache);
	if (i != 0) {
		id = insns[i].mapid;
		switch(id) {
			default:
				return false;

			case X86_INS_JAE:
			case X86_INS_JA:
			case X86_INS_JBE:
			case X86_INS_JB:
			case X86_INS_JCXZ:
			case X86_INS_JECXZ:
			case X86_INS_JE:
			case X86_INS_JGE:
			case X86_INS_JG:
			case X86_INS_JLE:
			case X86_INS_JL:
			case X86_INS_JMP:
			case X86_INS_JNE:
			case X86_INS_JNO:
			case X86_INS_JNP:
			case X86_INS_JNS:
			case X86_INS_JO:
			case X86_INS_JP:
			case X86_INS_JRCXZ:
			case X86_INS_JS:

			case X86_INS_CALL:
			case X86_INS_RET:
			case X86_INS_RETF:
			case X86_INS_RETFQ:
				return true;
		}
	}

	// not found
	return false;
}
#endif

// given MCInst's id, find out if this insn is valid for REP prefix
static bool valid_rep(cs_struct *h, unsigned int opcode)
{
	unsigned int id;
	int i = insn_find(insns, ARR_SIZE(insns), opcode, &h->insn_cache);
	if (i != 0) {
		id = insns[i].mapid;
		switch(id) {
			default:
				return false;

			case X86_INS_MOVSB:
			case X86_INS_MOVSW:
			case X86_INS_MOVSQ:

			case X86_INS_LODSB:
			case X86_INS_LODSW:
			case X86_INS_LODSQ:

			case X86_INS_STOSB:
			case X86_INS_STOSW:
			case X86_INS_STOSQ:

			case X86_INS_INSB:
			case X86_INS_INSW:
			case X86_INS_INSD:

			case X86_INS_OUTSB:
			case X86_INS_OUTSW:
			case X86_INS_OUTSD:
				return true;

			// following are some confused instructions, which have the same
			// mnemonics in 128bit media instructions. Intel is horribly crazy!
			case X86_INS_MOVSD:
				if (opcode == X86_MOVSL) // REP MOVSD
					return true;
				return false;

			case X86_INS_LODSD:
				if (opcode == X86_LODSL) // REP LODSD
					return true;
				return false;

			case X86_INS_STOSD:
				if (opcode == X86_STOSL) // REP STOSD
					return true;
				return false;
		}
	}

	// not found
	return false;
}

// given MCInst's id, find out if this insn is valid for REPE prefix
static bool valid_repe(cs_struct *h, unsigned int opcode)
{
	unsigned int id;
	int i = insn_find(insns, ARR_SIZE(insns), opcode, &h->insn_cache);
	if (i != 0) {
		id = insns[i].mapid;
		switch(id) {
			default:
				return false;

			case X86_INS_CMPSB:
			case X86_INS_CMPSW:
			case X86_INS_CMPSQ:

			case X86_INS_SCASB:
			case X86_INS_SCASW:
			case X86_INS_SCASQ:
				return true;

			// following are some confused instructions, which have the same
			// mnemonics in 128bit media instructions. Intel is horribly crazy!
			case X86_INS_CMPSD:
				if (opcode == X86_CMPSL) // REP CMPSD
					return true;
				return false;

			case X86_INS_SCASD:
				if (opcode == X86_SCASL) // REP SCASD
					return true;
				return false;
		}
	}

	// not found
	return false;
}

#ifndef CAPSTONE_DIET
// add *CX register to regs_read[] & regs_write[]
static void add_cx(MCInst *MI)
{
	if (MI->csh->detail) {
		x86_reg cx;

		if (MI->csh->mode & CS_MODE_16)
			cx = X86_REG_CX;
		else if (MI->csh->mode & CS_MODE_32)
			cx = X86_REG_ECX;
		else	// 64-bit
			cx = X86_REG_RCX;

		MI->flat_insn->detail->regs_read[MI->flat_insn->detail->regs_read_count] = cx;
		MI->flat_insn->detail->regs_read_count++;

		MI->flat_insn->detail->regs_write[MI->flat_insn->detail->regs_write_count] = cx;
		MI->flat_insn->detail->regs_write_count++;
	}
}
#endif

// return true if we patch the mnemonic
bool X86_lockrep(MCInst *MI, SStream *O)
{
	unsigned int opcode;
	bool res = false;

	switch(MI->x86_prefix[0]) {
		default:
			break;
		case 0xf0:
#ifndef CAPSTONE_DIET
			SStream_concat(O, "lock|");
#endif
			break;
		case 0xf2:	// repne
			opcode = MCInst_getOpcode(MI);
#ifndef CAPSTONE_DIET	// only care about memonic in standard (non-diet) mode
			if (valid_repne(MI->csh, opcode)) {
				SStream_concat(O, "repne|");
				add_cx(MI);
			} else if (valid_bnd(MI->csh, opcode)) {
				SStream_concat(O, "bnd|");
			} else {
				// invalid prefix
				MI->x86_prefix[0] = 0;

				// handle special cases
#ifndef CAPSTONE_X86_REDUCE
				if (opcode == X86_MULPDrr) {
					MCInst_setOpcode(MI, X86_MULSDrr);
					SStream_concat(O, "mulsd\t");
					res = true;
				}
#endif
			}
#else	// diet mode -> only patch opcode in special cases
			if (!valid_repne(MI->csh, opcode)) {
				MI->x86_prefix[0] = 0;
			}
#ifndef CAPSTONE_X86_REDUCE
			// handle special cases
			if (opcode == X86_MULPDrr) {
				MCInst_setOpcode(MI, X86_MULSDrr);
			}
#endif
#endif
			break;

		case 0xf3:
			opcode = MCInst_getOpcode(MI);
#ifndef CAPSTONE_DIET	// only care about memonic in standard (non-diet) mode
			if (valid_rep(MI->csh, opcode)) {
				SStream_concat(O, "rep|");
				add_cx(MI);
			} else if (valid_repe(MI->csh, opcode)) {
				SStream_concat(O, "repe|");
				add_cx(MI);
			} else {
				// invalid prefix
				MI->x86_prefix[0] = 0;

				// handle special cases
#ifndef CAPSTONE_X86_REDUCE
				if (opcode == X86_MULPDrr) {
					MCInst_setOpcode(MI, X86_MULSSrr);
					SStream_concat(O, "mulss\t");
					res = true;
				}
#endif
			}
#else	// diet mode -> only patch opcode in special cases
			if (!valid_rep(MI->csh, opcode) && !valid_repe(MI->csh, opcode)) {
				MI->x86_prefix[0] = 0;
			}
#ifndef CAPSTONE_X86_REDUCE
			// handle special cases
			if (opcode == X86_MULPDrr) {
				MCInst_setOpcode(MI, X86_MULSSrr);
			}
#endif
#endif
			break;
	}

	// copy normalized prefix[] back to x86.prefix[]
	if (MI->csh->detail)
		memcpy(MI->flat_insn->detail->x86.prefix, MI->x86_prefix, ARR_SIZE(MI->x86_prefix));

	return res;
}

void op_addReg(MCInst *MI, int reg)
{
	if (MI->csh->detail) {
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_REG;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].reg = reg;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = MI->csh->regsize_map[reg];
		MI->flat_insn->detail->x86.op_count++;
	}

	if (MI->op1_size == 0)
		MI->op1_size = MI->csh->regsize_map[reg];
}

void op_addImm(MCInst *MI, int v)
{
	if (MI->csh->detail) {
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].type = X86_OP_IMM;
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].imm = v;
		// if op_count > 0, then this operand's size is taken from the destination op
		if (MI->csh->syntax == CS_OPT_SYNTAX_INTEL) {
			if (MI->flat_insn->detail->x86.op_count > 0)
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = MI->flat_insn->detail->x86.operands[0].size;
			else
				MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count].size = MI->imm_size;
		} else
			MI->has_imm = true;
		MI->flat_insn->detail->x86.op_count++;
	}

	if (MI->op1_size == 0)
		MI->op1_size = MI->imm_size;
}

void op_addSseCC(MCInst *MI, int v)
{
	if (MI->csh->detail) {
		MI->flat_insn->detail->x86.sse_cc = v;
	}
}

void op_addAvxCC(MCInst *MI, int v)
{
	if (MI->csh->detail) {
		MI->flat_insn->detail->x86.avx_cc = v;
	}
}

void op_addAvxRoundingMode(MCInst *MI, int v)
{
	if (MI->csh->detail) {
		MI->flat_insn->detail->x86.avx_rm = v;
	}
}

// below functions supply details to X86GenAsmWriter*.inc
void op_addAvxZeroOpmask(MCInst *MI)
{
	if (MI->csh->detail) {
		// link with the previous operand
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count - 1].avx_zero_opmask = true;
	}
}

void op_addAvxSae(MCInst *MI)
{
	if (MI->csh->detail) {
		MI->flat_insn->detail->x86.avx_sae = true;
	}
}

void op_addAvxBroadcast(MCInst *MI, x86_avx_bcast v)
{
	if (MI->csh->detail) {
		// link with the previous operand
		MI->flat_insn->detail->x86.operands[MI->flat_insn->detail->x86.op_count - 1].avx_bcast = v;
	}
}

// map immediate size to instruction id
static struct size_id {
	unsigned char size;
	unsigned short id;
} x86_imm_size[] = {
#include "X86ImmSize.inc"
};

// given the instruction name, return the size of its immediate operand (or 0)
int X86_immediate_size(unsigned int id)
{
	// binary searching since the IDs is sorted in order
	unsigned int left, right, m;

	left = 0;
	right = ARR_SIZE(x86_imm_size) - 1;

	while(left <= right) {
		m = (left + right) / 2;
		if (id == x86_imm_size[m].id)
			return x86_imm_size[m].size;

		if (id < x86_imm_size[m].id)
			right = m - 1;
		else
			left = m + 1;
	}

	// not found
	return 0;
}

#endif

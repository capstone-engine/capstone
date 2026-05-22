/* Capstone Disassembly Engine */
/* M68K Backend by Daniel Collin <daniel@collin.com> 2015-2016 */

#ifndef CS_M68KDISASSEMBLER_H
#define CS_M68KDISASSEMBLER_H

#include "../../MCInst.h"

/* ======================================================================== */
/* ============================ GENERAL DEFINES =========================== */
/* ======================================================================== */

/* Bit Isolation Functions */
#define BIT_0(A) ((A) & 0x00000001)
#define BIT_1(A) ((A) & 0x00000002)
#define BIT_2(A) ((A) & 0x00000004)
#define BIT_3(A) ((A) & 0x00000008)
#define BIT_4(A) ((A) & 0x00000010)
#define BIT_5(A) ((A) & 0x00000020)
#define BIT_6(A) ((A) & 0x00000040)
#define BIT_7(A) ((A) & 0x00000080)
#define BIT_8(A) ((A) & 0x00000100)
#define BIT_9(A) ((A) & 0x00000200)
#define BIT_A(A) ((A) & 0x00000400)
#define BIT_B(A) ((A) & 0x00000800)
#define BIT_C(A) ((A) & 0x00001000)
#define BIT_D(A) ((A) & 0x00002000)
#define BIT_E(A) ((A) & 0x00004000)
#define BIT_F(A) ((A) & 0x00008000)
#define BIT_10(A) ((A) & 0x00010000)
#define BIT_11(A) ((A) & 0x00020000)
#define BIT_12(A) ((A) & 0x00040000)
#define BIT_13(A) ((A) & 0x00080000)
#define BIT_14(A) ((A) & 0x00100000)
#define BIT_15(A) ((A) & 0x00200000)
#define BIT_16(A) ((A) & 0x00400000)
#define BIT_17(A) ((A) & 0x00800000)
#define BIT_18(A) ((A) & 0x01000000)
#define BIT_19(A) ((A) & 0x02000000)
#define BIT_1A(A) ((A) & 0x04000000)
#define BIT_1B(A) ((A) & 0x08000000)
#define BIT_1C(A) ((A) & 0x10000000)
#define BIT_1D(A) ((A) & 0x20000000)
#define BIT_1E(A) ((A) & 0x40000000)
#define BIT_1F(A) ((A) & 0x80000000)

/* These are the M68K feature masks understood by this disassembler. */
#define M68000_ONLY CS_MODE_M68K_000

#define M68010_ONLY CS_MODE_M68K_010
#define M68010_LESS (CS_MODE_M68K_000 | CS_MODE_M68K_010)
#define M68010_PLUS \
	(CS_MODE_M68K_010 | CS_MODE_M68K_020 | CS_MODE_M68K_030 | \
	 CS_MODE_M68K_040 | CS_MODE_M68K_060)

#define M68020_ONLY CS_MODE_M68K_020
#define M68020_LESS (CS_MODE_M68K_010 | CS_MODE_M68K_020)
#define M68020_PLUS \
	(CS_MODE_M68K_020 | CS_MODE_M68K_030 | CS_MODE_M68K_040 | \
	 CS_MODE_M68K_060)

#define M68030_ONLY CS_MODE_M68K_030
#define M68030_LESS (CS_MODE_M68K_010 | CS_MODE_M68K_020 | CS_MODE_M68K_030)
#define M68030_PLUS (CS_MODE_M68K_030 | CS_MODE_M68K_040 | CS_MODE_M68K_060)

#define M68040_PLUS (CS_MODE_M68K_040 | CS_MODE_M68K_060)

typedef uint32_t m68k_feature_mask;

/* Extension word formats */
#define EXT_8BIT_DISPLACEMENT(A) ((A) & 0xff)
#define EXT_FULL(A) BIT_8(A)
#define EXT_EFFECTIVE_ZERO(A) (((A) & 0xe4) == 0xc4 || ((A) & 0xe2) == 0xc0)
#define EXT_BASE_REGISTER_PRESENT(A) (!BIT_7(A))
#define EXT_INDEX_REGISTER_PRESENT(A) (!BIT_6(A))
#define EXT_INDEX_REGISTER(A) (((A) >> 12) & 7)
#define EXT_INDEX_PRE_POST(A) (EXT_INDEX_REGISTER_PRESENT(A) && (A) & 3)
#define EXT_INDEX_PRE(A) \
	(EXT_INDEX_REGISTER_PRESENT(A) && ((A) & 7) < 4 && ((A) & 7) != 0)
#define EXT_INDEX_POST(A) (EXT_INDEX_REGISTER_PRESENT(A) && ((A) & 7) > 4)
#define EXT_INDEX_SCALE(A) (((A) >> 9) & 3)
#define EXT_INDEX_LONG(A) BIT_B(A)
#define EXT_INDEX_AR(A) BIT_F(A)
#define EXT_BASE_DISPLACEMENT_PRESENT(A) (((A) & 0x30) > 0x10)
#define EXT_BASE_DISPLACEMENT_WORD(A) (((A) & 0x30) == 0x20)
#define EXT_BASE_DISPLACEMENT_LONG(A) (((A) & 0x30) == 0x30)
/* Outer displacement is present when I/IS[1:0] (bits 1-0) is 2 (word) or 3 (long).
 * This applies regardless of the IS bit (bit 6): when index is suppressed,
 * I/IS values 5-7 mirror 1-3 (just indirect instead of postindexed).
 * The old check ((A) & 0x47) < 0x44 incorrectly excluded IS=1 cases
 * (I/IS=6,7) which DO have outer displacements per the M68K spec.
 */
#define EXT_OUTER_DISPLACEMENT_PRESENT(A) (((A) & 3) > 1)
#define EXT_OUTER_DISPLACEMENT_WORD(A) (((A) & 3) == 2)
#define EXT_OUTER_DISPLACEMENT_LONG(A) (((A) & 3) == 3)

#define IS_BITSET(val, b) ((val) & (1 << (b)))
#define BITFIELD_MASK(sb, eb) (((1 << ((sb) + 1)) - 1) & (~((1 << (eb)) - 1)))
#define BITFIELD(val, sb, eb) ((BITFIELD_MASK(sb, eb) & (val)) >> (eb))

/* Bitfield offset/width encoding.
 * Public decode macros (M68K_BF_*) live in <capstone/m68k.h>.
 * Internal aliases kept for brevity within arch code. */
#define M68K_BITFIELD_REG_FLAG M68K_BF_REG_FLAG
#define M68K_BITFIELD_IS_REG(v) M68K_BF_IS_REG(v)
#define M68K_BITFIELD_REG_NUM(v) M68K_BF_REG_NUM(v)
#define M68K_BITFIELD_ENCODE_REG(regnum) (((regnum) & 7) | M68K_BF_REG_FLAG)

/* ── Coprocessor ID (CpID) ───────────────────────────────────────────
 * Bits 11:9 of the F-line instruction word select the coprocessor.   */
#define M68K_CPID(info) (((info)->ir >> 9) & 7)

#define M68K_CPID_MMU 0 /* PMMU (68030/68851)                     */
#define M68K_CPID_FPU 1 /* FPU  (68881/68882/internal)            */
#define M68K_CPID_CACHE 2 /* Cache ops -- cinvl/cpushl on 68040+    */

/* ── IR bit-field helpers ────────────────────────────────────────────
 * Extract commonly-used fields from the first instruction word.      */

/* 6-bit coprocessor condition (bits 5:0 of IR). */
#define M68K_IR_CONDITION(info) ((info)->ir & 0x3f)

/* 4-bit condition selector used by Bcc/DBcc/Scc/TRAPcc. */
#define M68K_IR_CONDITION_NIBBLE(info) (((info)->ir >> 8) & 0xf)
#define M68K_CONDITION_FALSE 1

/* cinv/cpush: select cpush(1) vs cinv(0) -- bit 5 of IR. */
#define M68K_IR_IS_CPUSH(info) (((info)->ir >> 5) & 1)

/* cinv/cpush: cache scope -- bits 4:3 of IR (0=invalid,1=line,2=page,3=all). */
#define M68K_IR_CACHE_SCOPE(info) (((info)->ir >> 3) & 3)

/* cinv/cpush: cache selector -- bits 7:6 of IR (DC/IC/BC). */
#define M68K_IR_CACHE_SEL(info) (((info)->ir >> 6) & 3)

/* ── FPU extension-word bit-field helpers ────────────────────────────
 * The FPU command word is the 16-bit extension following the F-line. */

/* R/M bit (bit 14): 1 = source from EA, 0 = source from FP register. */
#define M68K_FEXT_RM(ext) (((ext) >> 14) & 1)

/* Type / command class (bits 15:13). */
#define M68K_FEXT_TYPE(ext) (((ext) >> 13) & 7)

/* Source specifier (bits 12:10) -- data format when R/M=1. */
#define M68K_FEXT_SRC(ext) (((ext) >> 10) & 7)

/* Destination FP register (bits 9:7). */
#define M68K_FEXT_DST(ext) (((ext) >> 7) & 7)

/* Opmode (bits 5:0) -- FPU operation selector. */
#define M68K_FEXT_OPMODE(ext) ((ext) & 0x3f)

/* Single/double precision flag (bit 6) -- 68040+ only. */
#define M68K_FEXT_SD_FLAG(ext) (((ext) >> 6) & 1)

/* FMOVECR signature: bits 15:10 == 0x17 (010111b). */
#define M68K_FEXT_IS_FMOVECR(ext) (BITFIELD((ext), 15, 10) == 0x17)

/* Register-select field for FMOVE to/from FPCR/FPSR/FPIAR (bits 12:10). */
#define M68K_FEXT_REGSEL(ext) (((ext) >> 10) & 7)

/* Direction bit for FMOVE FPCR (bit 13): 0 = ea->fpcr, 1 = fpcr->ea. */
#define M68K_FEXT_DIR(ext) (((ext) >> 13) & 1)

/* ── FPU condition-code mask ─────────────────────────────────────────
 * FBcc/FDBcc/FScc/FTRAPcc encode the FP condition in bits 5,3:0
 * of the extension word (or IR for FBcc).  Bit 4 is always 0,
 * yielding the 0x2f mask.                                            */
#define M68K_FP_COND(x) ((x) & 0x2f)

/* Maximum valid condition codes per coprocessor. */
#define M68K_PMMU_MAX_COND 16
#define M68K_FPU_MAX_COND 32

/* ── FPU source-format constants (bits 12:10 of ext word) ───────────*/
#define M68K_FPSRC_LONG 0x00 /* .l  -- 32-bit integer            */
#define M68K_FPSRC_SINGLE 0x01 /* .s  -- 32-bit IEEE single        */
#define M68K_FPSRC_EXTENDED 0x02 /* .x  -- 96-bit extended real      */
#define M68K_FPSRC_PACKED 0x03 /* .p  -- 96-bit packed decimal     */
#define M68K_FPSRC_WORD 0x04 /* .w  -- 16-bit integer            */
#define M68K_FPSRC_DOUBLE 0x05 /* .d  -- 64-bit IEEE double        */
#define M68K_FPSRC_BYTE 0x06 /* .b  -- 8-bit integer             */

/* ── FPU special raw opmodes (before SD-flag masking) ───────────────
 * FSSQRT/FDSQRT have raw 7-bit opmodes 0x41/0x45.  After the 6-bit
 * truncation (& 0x3f) they become 0x01/0x05 with the SD flag set.   */
#define M68K_FPOP_FSSQRT_RAW 0x01 /* 0x41 & 0x3f */
#define M68K_FPOP_FDSQRT_RAW 0x05 /* 0x45 & 0x3f */

/* ── Feature guard macros ────────────────────────────────────────────
 * These reference the `info` parameter available at each call site.
 * They early-return from the calling function on guard mismatch.     */

#define LIMIT_FEATURE(info, FEATURES) \
	do { \
		if (!m68k_has_feature(info, FEATURES)) { \
			d68000_invalid(info); \
			return; \
		} \
	} while (0)

/* Like LIMIT_FEATURE but also reverses the instruction word consumption,
 * so the invalid instruction produces size=0 (not decoded) instead of size=2.
 * Use for handlers that replace d68000_invalid in the dispatch table. */
#define LIMIT_FEATURE_UNDECODED(info, FEATURES) \
	do { \
		if (!m68k_has_feature(info, FEATURES)) { \
			info->pc -= 2; \
			d68000_invalid(info); \
			return; \
		} \
	} while (0)

/* Like LIMIT_FEATURE but also rejects a feature subset.  CPU32 implies 68020
 * but lacks some 68020 instructions (CAS, CAS2, CHK.L, PACK, UNPK). */
#define LIMIT_FEATURE_EXCLUDING(info, FEATURES, EXCLUDED_FEATURES) \
	do { \
		if (!m68k_has_feature(info, FEATURES) || \
		    m68k_has_feature(info, EXCLUDED_FEATURES)) { \
			d68000_invalid(info); \
			return; \
		} \
	} while (0)

/* Require CpID == FPU.  Rejects all other coprocessor IDs.
 * Used by cpDBcc, cpScc, cpTRAPcc handlers. */
#define REQUIRE_CPID_FPU(info) \
	do { \
		if (M68K_CPID(info) != M68K_CPID_FPU) { \
			d68000_invalid(info); \
			return; \
		} \
	} while (0)

/* ── EA / immediate convenience aliases ─────────────────────────────
 * Shorthand wrappers around the sized get_ea_mode_str / get_imm_str
 * functions.  These expand at the call site where 'info' is in scope. */

/* Fake a split interface */
#define get_ea_mode_str_8(instruction) get_ea_mode_str(instruction, 0)
#define get_ea_mode_str_16(instruction) get_ea_mode_str(instruction, 1)
#define get_ea_mode_str_32(instruction) get_ea_mode_str(instruction, 2)

#define get_imm_str_s8() get_imm_str_s(0)
#define get_imm_str_s16() get_imm_str_s(1)
#define get_imm_str_s32() get_imm_str_s(2)

#define get_imm_str_u8() get_imm_str_u(0)
#define get_imm_str_u16() get_imm_str_u(1)
#define get_imm_str_u32() get_imm_str_u(2)

/* ── Operand access shorthands ──────────────────────────────────────
 * Quick access to the operand array and instruction size via `info`. */
#define IOPS(I) (&info->extension.operands[(I)])
#define ISIZE (info->extension.op_size.cpu_size)

/* ======================================================================== */
/* ============================ INTERNAL TYPES ============================ */
/* ======================================================================== */

/* Private, For internal use only */
typedef struct m68k_info {
	const uint8_t *code;
	size_t code_len;
	uint64_t baseAddress;
	MCInst *inst;
	unsigned int pc; /* program counter */
	unsigned int ir; /* instruction register */
	m68k_feature_mask features;
	unsigned int address_mask; /* Address mask to simulate address lines */
	cs_m68k extension;
	uint16_t regs_read
		[MAX_IMPL_R_REGS]; // list of implicit registers read by this insn
	uint8_t regs_read_count; // number of implicit registers read by this insn
	uint16_t regs_write
		[MAX_IMPL_W_REGS]; // list of implicit registers modified by this insn
	uint8_t regs_write_count; // number of implicit registers modified by this insn
	uint8_t groups[MAX_NUM_GROUPS];
	uint8_t groups_count;
} m68k_info;

static inline bool m68k_has_feature(const m68k_info *info,
				    m68k_feature_mask features)
{
	m68k_feature_mask available = info->features;

	if (available & CS_MODE_M68K_CPU32)
		available |= CS_MODE_M68K_020;
	if (available & CS_MODE_M68K_CF_ISA_A_PLUS)
		available |= CS_MODE_M68K_CF_ISA_A;
	if (available & CS_MODE_M68K_CF_ISA_B)
		available |= CS_MODE_M68K_CF_ISA_A | CS_MODE_M68K_CF_ISA_A_PLUS;
	if (available & CS_MODE_M68K_CF_ISA_C)
		available |= CS_MODE_M68K_CF_ISA_A;
	if (available & CS_MODE_M68K_CF_EMAC)
		available |= CS_MODE_M68K_CF_MAC;
	if (available & CS_MODE_M68K_CF_EMAC_B)
		available |= CS_MODE_M68K_CF_EMAC | CS_MODE_M68K_CF_MAC;

	return (available & features) != 0;
}

bool M68K_getInstruction(csh ud, const uint8_t *code, size_t code_len,
			 MCInst *instr, uint16_t *size, uint64_t address,
			 void *info);

#endif

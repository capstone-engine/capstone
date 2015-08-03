/* ======================================================================== */
/* ========================= LICENSING & COPYRIGHT ======================== */
/* ======================================================================== */
/*
 *                                  MUSASHI
 *                                Version 3.4
 *
 * A portable Motorola M680x0 processor emulation engine.
 * Copyright 1998-2001 Karl Stenerud.  All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

 /* The code bellow is based on MMUSASH but has been heavily modified for capstore by
  * Daniel Collin <daniel@collin.com> 2015 */

/* ======================================================================== */
/* ================================ INCLUDES ============================== */
/* ======================================================================== */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "M68Kdasm.h"

#include "../../MCInst.h"
#include "../../MCInstrDesc.h"
#include "../../MCRegisterInfo.h"

#ifndef DECL_SPEC
#define DECL_SPEC
#endif

/* ======================================================================== */
/* ============================ GENERAL DEFINES =========================== */
/* ======================================================================== */

/* unsigned int and int must be at least 32 bits wide */
#undef uint
#define uint unsigned int

/* Bit Isolation Functions */
#define BIT_0(A)  ((A) & 0x00000001)
#define BIT_1(A)  ((A) & 0x00000002)
#define BIT_2(A)  ((A) & 0x00000004)
#define BIT_3(A)  ((A) & 0x00000008)
#define BIT_4(A)  ((A) & 0x00000010)
#define BIT_5(A)  ((A) & 0x00000020)
#define BIT_6(A)  ((A) & 0x00000040)
#define BIT_7(A)  ((A) & 0x00000080)
#define BIT_8(A)  ((A) & 0x00000100)
#define BIT_9(A)  ((A) & 0x00000200)
#define BIT_A(A)  ((A) & 0x00000400)
#define BIT_B(A)  ((A) & 0x00000800)
#define BIT_C(A)  ((A) & 0x00001000)
#define BIT_D(A)  ((A) & 0x00002000)
#define BIT_E(A)  ((A) & 0x00004000)
#define BIT_F(A)  ((A) & 0x00008000)
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

/* These are the CPU types understood by this disassembler */
#define TYPE_68000 1
#define TYPE_68010 2
#define TYPE_68020 4
#define TYPE_68030 8
#define TYPE_68040 16

#define M68000_ONLY		TYPE_68000

#define M68010_ONLY		TYPE_68010
#define M68010_LESS		(TYPE_68000 | TYPE_68010)
#define M68010_PLUS		(TYPE_68010 | TYPE_68020 | TYPE_68030 | TYPE_68040)

#define M68020_ONLY 	TYPE_68020
#define M68020_LESS 	(TYPE_68010 | TYPE_68020)
#define M68020_PLUS		(TYPE_68020 | TYPE_68030 | TYPE_68040)

#define M68030_ONLY 	TYPE_68030
#define M68030_LESS 	(TYPE_68010 | TYPE_68020 | TYPE_68030)
#define M68030_PLUS		(TYPE_68030 | TYPE_68040)

#define M68040_PLUS		TYPE_68040


/* Extension word formats */
#define EXT_8BIT_DISPLACEMENT(A)          ((A)&0xff)
#define EXT_FULL(A)                       BIT_8(A)
#define EXT_EFFECTIVE_ZERO(A)             (((A)&0xe4) == 0xc4 || ((A)&0xe2) == 0xc0)
#define EXT_BASE_REGISTER_PRESENT(A)      (!BIT_7(A))
#define EXT_INDEX_REGISTER_PRESENT(A)     (!BIT_6(A))
#define EXT_INDEX_REGISTER(A)             (((A)>>12)&7)
#define EXT_INDEX_PRE_POST(A)             (EXT_INDEX_PRESENT(A) && (A)&3)
#define EXT_INDEX_PRE(A)                  (EXT_INDEX_PRESENT(A) && ((A)&7) < 4 && ((A)&7) != 0)
#define EXT_INDEX_POST(A)                 (EXT_INDEX_PRESENT(A) && ((A)&7) > 4)
#define EXT_INDEX_SCALE(A)                (((A)>>9)&3)
#define EXT_INDEX_LONG(A)                 BIT_B(A)
#define EXT_INDEX_AR(A)                   BIT_F(A)
#define EXT_BASE_DISPLACEMENT_PRESENT(A)  (((A)&0x30) > 0x10)
#define EXT_BASE_DISPLACEMENT_WORD(A)     (((A)&0x30) == 0x20)
#define EXT_BASE_DISPLACEMENT_LONG(A)     (((A)&0x30) == 0x30)
#define EXT_OUTER_DISPLACEMENT_PRESENT(A) (((A)&3) > 1 && ((A)&0x47) < 0x44)
#define EXT_OUTER_DISPLACEMENT_WORD(A)    (((A)&3) == 2 && ((A)&0x47) < 0x44)
#define EXT_OUTER_DISPLACEMENT_LONG(A)    (((A)&3) == 3 && ((A)&0x47) < 0x44)

#define IS_BITSET(val,b) ((val) & (1 << (b)))
#define BITFIELD_MASK(sb,eb)  (((1 << ((sb) + 1))-1) & (~((1 << (eb))-1)))
#define BITFIELD(val,sb,eb) ((BITFIELD_MASK(sb,eb) & (val)) >> (eb))


/* ======================================================================== */
/* =============================== PROTOTYPES ============================= */
/* ======================================================================== */

/* Read data at the PC and increment PC */
uint  read_imm_8(void);
uint  read_imm_16(void);
uint  read_imm_32(void);

/* Read data at the PC but don't imcrement the PC */
uint  peek_imm_8(void);
uint  peek_imm_16(void);
uint  peek_imm_32(void);

/* make signed integers 100% portably */
static int make_int_8(int value);
static int make_int_16(int value);

/* Stuff to build the opcode handler jump table */
static void build_opcode_table(void);
static int valid_ea(uint opcode, uint mask);
static int DECL_SPEC compare_nof_true_bits(const void *aptr, const void *bptr);
static void d68000_invalid(void);
static int instruction_is_valid(const unsigned int instruction, const unsigned int word_check);

/* used to build opcode handler jump table */
typedef struct
{
	void (*opcode_handler)(void); /* handler function */
	uint mask;                    /* mask on opcode */
	uint match;                   /* what to match after masking */
	uint ea_mask;                 /* what ea modes are allowed */
	uint mask2;                   /* mask the 2nd word */
	uint match2;                  /* what to match after masking */
} opcode_struct;

typedef struct
{
	void (*instruction)(void);    /* handler function */
	uint word2_mask;              /* mask the 2nd word */
	uint word2_match;             /* what to match after masking */
} instruction_struct;

/* ======================================================================== */
/* ================================= DATA ================================= */
/* ======================================================================== */

/* Opcode handler jump table */
static instruction_struct g_instruction_table[0x10000];
/* Flag if disassembler initialized */
static int  g_initialized = 0;

/* Address mask to simulate address lines */
static unsigned int g_address_mask = 0xffffffff;

static MCInst* g_inst;
static char g_helper_str[100]; /* string to hold helpful info */
static uint g_cpu_pc;        /* program counter */
static uint g_cpu_ir;        /* instruction register */
static uint g_cpu_type;

/* used by ops like asr, ror, addq, etc */
static uint g_3bit_qdata_table[8] = {8, 1, 2, 3, 4, 5, 6, 7};

static uint g_5bit_data_table[32] =
{
	32,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15,
	16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
};

static m68k_insn s_branch_lut[] = {
	M68K_INS_INVALID, M68K_INS_INVALID, M68K_INS_BHI, M68K_INS_BLS,
	M68K_INS_BCC, M68K_INS_BCS, M68K_INS_BNE, M68K_INS_BEQ,
	M68K_INS_BVC, M68K_INS_BVS, M68K_INS_BPL, M68K_INS_BMI,
	M68K_INS_BGE, M68K_INS_BLT, M68K_INS_BGT, M68K_INS_BLE,
};

static m68k_insn s_dbcc_lut[] = {
	M68K_INS_DBT, M68K_INS_DBF, M68K_INS_DBHI, M68K_INS_DBLS,
	M68K_INS_DBCC, M68K_INS_DBCS, M68K_INS_DBNE, M68K_INS_DBEQ,
	M68K_INS_DBVC, M68K_INS_DBVS, M68K_INS_DBPL, M68K_INS_DBMI,
	M68K_INS_DBGE, M68K_INS_DBLT, M68K_INS_DBGT, M68K_INS_DBLE,
};

static m68k_insn s_scc_lut[] = {
	M68K_INS_ST, M68K_INS_SF, M68K_INS_SHI, M68K_INS_SLS,
	M68K_INS_SCC, M68K_INS_SCS, M68K_INS_SNE, M68K_INS_SEQ,
	M68K_INS_SVC, M68K_INS_SVS, M68K_INS_SPL, M68K_INS_SMI,
	M68K_INS_SGE, M68K_INS_SLT, M68K_INS_SGT, M68K_INS_SLE,
};

static m68k_insn s_trap_lut[] = {
	M68K_INS_TRAPT, M68K_INS_TRAPF, M68K_INS_TRAPHI, M68K_INS_TRAPLS,
	M68K_INS_TRAPCC, M68K_INS_TRAPCS, M68K_INS_TRAPNE, M68K_INS_TRAPEQ,
	M68K_INS_TRAPVC, M68K_INS_TRAPVS, M68K_INS_TRAPPL, M68K_INS_TRAPMI,
	M68K_INS_TRAPGE, M68K_INS_TRAPLT, M68K_INS_TRAPGT, M68K_INS_TRAPLE,
};

/* ======================================================================== */
/* =========================== UTILITY FUNCTIONS ========================== */
/* ======================================================================== */

#define LIMIT_CPU_TYPES(ALLOWED_CPU_TYPES)	\
	if(!(g_cpu_type & ALLOWED_CPU_TYPES))	\
	{										\
		d68000_invalid();					\
		return;								\
	}

#define read_imm_8()  (m68k_read_disassembler_16(((g_cpu_pc+=2)-2)&g_address_mask)&0xff)
#define read_imm_16() m68k_read_disassembler_16(((g_cpu_pc+=2)-2)&g_address_mask)
#define read_imm_32() m68k_read_disassembler_32(((g_cpu_pc+=4)-4)&g_address_mask)
#define read_imm_64() m68k_read_disassembler_64(((g_cpu_pc+=8)-8)&g_address_mask)

#define peek_imm_8()  (m68k_read_disassembler_16(g_cpu_pc & g_address_mask)&0xff)
#define peek_imm_16() m68k_read_disassembler_16(g_cpu_pc & g_address_mask)
#define peek_imm_32() m68k_read_disassembler_32(g_cpu_pc & g_address_mask)

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


/* 100% portable signed int generators */
static int make_int_8(int value)
{
	return (value & 0x80) ? value | ~0xff : value & 0xff;
}

static int make_int_16(int value)
{
	return (value & 0x8000) ? value | ~0xffff : value & 0xffff;
}

static void get_with_index_address_mode(cs_m68k_op* op, uint instruction, uint size, bool is_pc)
{
	uint extension = read_imm_16();

	op->address_mode = M68K_AM_AREGI_INDEX_BASE_DISP;

	if (EXT_FULL(extension))
	{
		uint preindex;
		uint postindex;

		op->mem.base_reg = M68K_REG_INVALID;
		op->mem.index_reg = M68K_REG_INVALID;

		/* Not sure how to deal with this?
		if(EXT_EFFECTIVE_ZERO(extension))
		{
			strcpy(mode, "0");
			break;
		}
		*/

		op->mem.in_disp = EXT_BASE_DISPLACEMENT_PRESENT(extension) ? (EXT_BASE_DISPLACEMENT_LONG(extension) ? read_imm_32() : read_imm_16()) : 0;
		op->mem.out_disp = EXT_OUTER_DISPLACEMENT_PRESENT(extension) ? (EXT_OUTER_DISPLACEMENT_LONG(extension) ? read_imm_32() : read_imm_16()) : 0;

		if (EXT_BASE_REGISTER_PRESENT(extension)) {
			if (is_pc) {
				op->mem.base_reg = M68K_REG_PC;
			} else {
				op->mem.base_reg = M68K_REG_A0 + (instruction & 7);
			}
		}

		if (EXT_INDEX_REGISTER_PRESENT(extension))
		{
			if (EXT_INDEX_AR(extension)) {
				op->mem.index_reg = M68K_REG_A0 + EXT_INDEX_REGISTER(extension);
			} else {
				op->mem.index_reg = M68K_REG_D0 + EXT_INDEX_REGISTER(extension);
			}

			op->mem.index_size = EXT_INDEX_LONG(extension) ? 1 : 0;

			if (EXT_INDEX_SCALE(extension)) {
				op->mem.scale = 1 << EXT_INDEX_SCALE(extension);
			}
		}

		preindex = (extension & 7) > 0 && (extension & 7) < 4;
		postindex = (extension & 7) > 4;

		if (preindex) {
			op->address_mode = is_pc ? M68K_AM_PC_MEMI_PRE_INDEX : M68K_AM_MEMI_PRE_INDEX;
		} else if (postindex) { 
			op->address_mode = is_pc ? M68K_AM_PC_MEMI_POST_INDEX : M68K_AM_MEMI_POST_INDEX;
		}

		return;
	}

	op->mem.index_reg = (EXT_INDEX_AR(extension) ? M68K_REG_A0 : M68K_REG_D0) + EXT_INDEX_REGISTER(extension);
	op->mem.index_size = EXT_INDEX_LONG(extension) ? 1 : 0; 

	if (EXT_8BIT_DISPLACEMENT(extension) == 0) {
		if (is_pc) {
			op->mem.base_reg = M68K_REG_PC; 
			op->address_mode = M68K_AM_PCI_INDEX_BASE_DISP;
		} else {
			op->mem.base_reg = M68K_REG_A0 + (instruction & 7); 
		}
	}
	else
	{
		if (is_pc) {
			op->mem.base_reg = M68K_REG_PC; 
			op->address_mode = M68K_AM_PCI_INDEX_8_BIT_DISP;
		} else {
			op->mem.base_reg = M68K_REG_A0 + (instruction & 7); 
			op->address_mode = M68K_AM_AREGI_INDEX_8_BIT_DISP;
		}

		op->mem.disp = extension & 0xff;
	}

	if (EXT_INDEX_SCALE(extension)) {
		op->mem.scale = 1 << EXT_INDEX_SCALE(extension);
	}
}

/* Make string of effective address mode */
void get_ea_mode_op(cs_m68k_op* op, uint instruction, uint size)
{
	// default to memory

	op->type = M68K_OP_MEM;

	switch (instruction & 0x3f)
	{
		case 0x00: case 0x01: case 0x02: case 0x03: case 0x04: case 0x05: case 0x06: case 0x07:
		{
			/* data register direct */
			op->address_mode = M68K_AM_REG_DIRECT_DATA;
			op->reg = M68K_REG_D0 + (instruction & 7);
			op->type = M68K_OP_REG;
			break;
		}

		case 0x08: case 0x09: case 0x0a: case 0x0b: case 0x0c: case 0x0d: case 0x0e: case 0x0f:
		{
			/* address register direct */
			op->address_mode = M68K_AM_REG_DIRECT_ADDR;
			op->reg = M68K_REG_A0 + (instruction & 7);
			op->type = M68K_OP_REG;
			break;
		}

		case 0x10: case 0x11: case 0x12: case 0x13: case 0x14: case 0x15: case 0x16: case 0x17:
		{
			/* address register indirect */
			op->address_mode = M68K_AM_REGI_ADDR;
			op->reg = M68K_REG_A0 + (instruction & 7);
			break;
		}

		case 0x18: case 0x19: case 0x1a: case 0x1b: case 0x1c: case 0x1d: case 0x1e: case 0x1f:
		{
			/* address register indirect with postincrement */
			op->address_mode = M68K_AM_REGI_ADDR_POST_INC;
			op->reg = M68K_REG_A0 + (instruction & 7);
			break;
		}

		case 0x20: case 0x21: case 0x22: case 0x23: case 0x24: case 0x25: case 0x26: case 0x27:
		{
			/* address register indirect with predecrement */
			op->address_mode = M68K_AM_REGI_ADDR_PRE_DEC;
			op->reg = M68K_REG_A0 + (instruction & 7);
			break;
		}

		case 0x28: case 0x29: case 0x2a: case 0x2b: case 0x2c: case 0x2d: case 0x2e: case 0x2f:
		{
			/* address register indirect with displacement*/
			op->address_mode = M68K_AM_REGI_ADDR_DISP;
			op->mem.base_reg = M68K_REG_A0 + (instruction & 7);
			op->mem.disp = read_imm_16();
			break;
		}

		case 0x30: case 0x31: case 0x32: case 0x33: case 0x34: case 0x35: case 0x36: case 0x37:
		{
			/* address register indirect with index */
			get_with_index_address_mode(op, instruction, size, false);
			break;
		}

		case 0x38:
		{
			/* absolute short address */
			op->address_mode = M68K_AM_ABSOLUTE_DATA_SHORT;
			op->imm = read_imm_16();
			break;
		}

		case 0x39:
		{
			/* absolute long address */
			op->address_mode = M68K_AM_ABSOLUTE_DATA_LONG;
			op->imm = read_imm_32();
			break;
		}

		case 0x3a:
		{
			/* program counter with displacement */
			op->address_mode = M68K_AM_PCI_DISP;
			op->mem.disp = read_imm_16();
			break;
		}

		case 0x3b:
		{
			/* program counter with index */
			get_with_index_address_mode(op, instruction, size, true);
			break;
		}

		case 0x3c:
		{
			op->address_mode = M68K_AM_IMMIDIATE;
			op->type = M68K_OP_IMM;

			if (size == 1)
				op->imm = read_imm_8() & 0xff;
			else if (size == 2)
				op->imm = read_imm_16() & 0xffff;
			else if (size == 4)
				op->imm = read_imm_32();
			else
				op->imm = read_imm_64();

			break;
		}

		default:
			break;
	}
}

static cs_m68k* build_init_op(int opcode, int count, int size)
{
	MCInst_setOpcode(g_inst, opcode);

	cs_detail *detail = g_inst->flat_insn->detail;
	if (!detail)
	{
		return NULL;
	}

	cs_m68k* info = &detail->m68k;
	
	info->op_count = count;
	info->op_size.type = M68K_SIZE_TYPE_CPU;
	info->op_size.cpu_size = size; 

	return info;
}

static void build_re_gen_1(bool isDreg, int opcode, uint8_t size)
{
	cs_m68k* info = build_init_op(opcode, 2, size);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];
	
	if (isDreg) {
		op0->address_mode = M68K_AM_REG_DIRECT_DATA;
		op0->reg = M68K_REG_D0 + ((g_cpu_ir >> 9 ) & 7);
	} else {
		op0->address_mode = M68K_AM_REG_DIRECT_ADDR;
		op0->reg = M68K_REG_A0 + ((g_cpu_ir >> 9 ) & 7);
	}

	get_ea_mode_op(op1, g_cpu_ir, size);
}

static void build_re_1(int opcode, uint8_t size)
{
	build_re_gen_1(true, opcode, size);
}

static void build_er_gen_1(bool isDreg, int opcode, uint8_t size)
{
	cs_m68k* info = build_init_op(opcode, 2, size);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];
	
	get_ea_mode_op(op0, g_cpu_ir, size);

	if (isDreg) {
		op1->address_mode = M68K_AM_REG_DIRECT_DATA;
		op1->reg = M68K_REG_D0 + ((g_cpu_ir >> 9) & 7);
	} else {
		op1->address_mode = M68K_AM_REG_DIRECT_ADDR;
		op1->reg = M68K_REG_A0 + ((g_cpu_ir >> 9) & 7);
	}
}

static void build_rr(int opcode, uint8_t size, int imm)
{
	cs_m68k* info = build_init_op(opcode, 2, size);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];
	cs_m68k_op* op2 = &info->operands[2];
	
	op0->address_mode = M68K_AM_REG_DIRECT_DATA;
	op0->reg = M68K_REG_D0 + (g_cpu_ir & 7);

	op1->address_mode = M68K_AM_REG_DIRECT_DATA;
	op1->reg = M68K_REG_D0 + ((g_cpu_ir >> 9) & 7);

	if (imm > 0)
	{
		info->op_count = 3;
		op2->type = M68K_OP_IMM;
		op2->address_mode = M68K_AM_IMMIDIATE;
		op2->imm = imm;
	}
}

static void build_r(int opcode, uint8_t size)
{
	cs_m68k* info = build_init_op(opcode, 2, size);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];
	
	op0->address_mode = M68K_AM_REG_DIRECT_DATA;
	op0->reg = M68K_REG_D0 + ((g_cpu_ir >> 9) & 7);

	op1->address_mode = M68K_AM_REG_DIRECT_DATA;
	op1->reg = M68K_REG_D0 + (g_cpu_ir & 7);
}

static void build_imm_ea(int opcode, uint8_t size, int imm)
{
	cs_m68k* info = build_init_op(opcode, 2, size);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];
	
	op0->type = M68K_OP_IMM;
	op0->address_mode = M68K_AM_IMMIDIATE;
	op0->imm = imm; 

	get_ea_mode_op(op1, g_cpu_ir, size);
}

static void build_3bit_d(int opcode, int size)
{
	cs_m68k* info = build_init_op(opcode, 2, size);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];
	
	op0->type = M68K_OP_IMM;
	op0->address_mode = M68K_AM_IMMIDIATE;
	op0->imm = g_3bit_qdata_table[(g_cpu_ir >> 9) & 7];

	op1->address_mode = M68K_AM_REG_DIRECT_DATA;
	op1->reg = M68K_REG_D0 + (g_cpu_ir & 7);
}

static void build_3bit_ea(int opcode, int size)
{
	cs_m68k* info = build_init_op(opcode, 2, size);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];
	
	op0->type = M68K_OP_IMM;
	op0->address_mode = M68K_AM_IMMIDIATE;
	op0->imm = g_3bit_qdata_table[(g_cpu_ir >> 9) & 7];

	get_ea_mode_op(op1, g_cpu_ir, size);
}

static void build_mm(int opcode, uint8_t size, int imm)
{
	cs_m68k* info = build_init_op(opcode, 2, size);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];
	cs_m68k_op* op2 = &info->operands[2];
	
	op0->address_mode = M68K_AM_REGI_ADDR_PRE_DEC;
	op0->reg = M68K_REG_A0 + (g_cpu_ir & 7);

	op1->address_mode = M68K_AM_REGI_ADDR_PRE_DEC;
	op1->reg = M68K_REG_A0 + ((g_cpu_ir >> 9) & 7);

	if (imm > 0)
	{
		info->op_count = 3;
		op2->type = M68K_OP_IMM;
		op2->address_mode = M68K_AM_IMMIDIATE;
		op2->imm = imm;
	}
}

static void build_ea(int opcode, uint8_t size)
{
	cs_m68k* info = build_init_op(opcode, 1, size);
	if (!info) {
		return;
	}
	get_ea_mode_op(&info->operands[0], g_cpu_ir, size);
}

static void build_ea_a(int opcode, uint8_t size)
{
	cs_m68k* info = build_init_op(opcode, 2, size);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	get_ea_mode_op(op0, g_cpu_ir, size);

	op1->address_mode = M68K_AM_REG_DIRECT_ADDR;
	op1->reg = M68K_REG_A0 + ((g_cpu_ir >> 9) & 7);
}

static void build_ea_ea(int opcode, int size)
{
	cs_m68k* info = build_init_op(opcode, 2, size);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	get_ea_mode_op(op0, g_cpu_ir, size);
	get_ea_mode_op(op1, (((g_cpu_ir>>9) & 7) | ((g_cpu_ir>>3) & 0x38)), size);
}

static void build_pi_pi(int opcode, int size)
{
	cs_m68k* info = build_init_op(opcode, 2, size);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	op0->address_mode = M68K_AM_REGI_ADDR_POST_INC;
	op0->reg = M68K_REG_A0 + (g_cpu_ir & 7);

	op1->address_mode = M68K_AM_REGI_ADDR_POST_INC;
	op1->reg = M68K_REG_A0 + ((g_cpu_ir >> 9) & 7);
}

static void build_imm_special_reg(int opcode, int imm, int size, m68k_reg reg)
{
	cs_m68k* info = build_init_op(opcode, 2, size);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];
	
	op0->type = M68K_OP_IMM;
	op0->address_mode = M68K_AM_IMMIDIATE;
	op0->imm = imm; 

	op1->address_mode = M68K_AM_NONE;
	op1->reg = reg; 
}

static void build_bxx(int opcode, int size, int jump_offset)
{
	cs_m68k* info = build_init_op(opcode, 1, size);
	if (!info) {
		return;
	}

	cs_m68k_op* op = &info->operands[0];
	
	op->type = M68K_OP_IMM;
	op->address_mode = M68K_AM_IMMIDIATE;
	op->imm = jump_offset;
}

static void build_bcc(int size, int jump_offset)
{
	build_bxx(s_branch_lut[(g_cpu_ir >> 8) & 0xf], size, jump_offset);
}

static void build_trap(int size, int jump_offset)
{
	build_bxx(s_trap_lut[(g_cpu_ir >> 8) & 0xf], size, jump_offset);
}

static void build_dbxx(int opcode, int size, int jump_offset)
{
	cs_m68k* info = build_init_op(opcode, 2, size);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	op0->address_mode = M68K_AM_REG_DIRECT_DATA;
	op0->reg = M68K_REG_D0 + (g_cpu_ir & 7);
	
	op1->type = M68K_OP_IMM;
	op1->address_mode = M68K_AM_IMMIDIATE;
	op1->imm = jump_offset;
}

static void build_dbcc(int size, int jump_offset)
{
	build_dbxx(s_dbcc_lut[(g_cpu_ir >> 8) & 0xf], size, jump_offset);
}

static void build_d_d_ea(int opcode, int size)
{
	uint extension = read_imm_16();

	cs_m68k* info = build_init_op(opcode, 3, size);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];
	cs_m68k_op* op2 = &info->operands[2];

	op0->address_mode = M68K_AM_REG_DIRECT_DATA;
	op0->reg = M68K_REG_D0 + (extension & 7);

	op1->address_mode = M68K_AM_REG_DIRECT_DATA;
	op1->reg = M68K_REG_D0 + ((extension >> 6) & 7);

	get_ea_mode_op(op2, g_cpu_ir, size);
}

static void build_bitfield_ins(int opcode, int has_d_arg)
{
	uint8_t offset;
	uint8_t width;

	uint extension = read_imm_16();

	cs_m68k* info = build_init_op(opcode, 1, 0);
	if (!info) {
		return;
	}

	cs_m68k_op* op_ea = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	if (BIT_B(extension))
		offset = (extension >> 6) & 7;
	else
		offset = (extension >> 6) & 31;

	if (BIT_5(extension))
		width = extension & 7;
	else
		width = g_5bit_data_table[extension & 31];

	if (has_d_arg) {
		info->op_count = 2;
		op1->address_mode = M68K_AM_REG_DIRECT_DATA;
		op1->reg = M68K_REG_D0 + ((extension >> 12) & 7);
	}

	get_ea_mode_op(op_ea, g_cpu_ir, 1);

	op_ea->mem.bitfield = 1;
	op_ea->mem.width = width;
	op_ea->mem.offset = offset;
}

static void build_d(int opcode, int size)
{
	cs_m68k* info = build_init_op(opcode, 1, size);
	if (!info) {
		return;
	}

	cs_m68k_op* op = &info->operands[0];

	op->address_mode = M68K_AM_REG_DIRECT_DATA;
	op->reg = M68K_REG_D0 + (g_cpu_ir & 7);
}

static uint16_t reverse_bits(uint v)
{
	uint r = v; // r will be reversed bits of v; first get LSB of v
	uint s = 16 - 1; // extra shift needed at end

	for (v >>= 1; v; v >>= 1)
	{   
		r <<= 1;
		r |= v & 1;
		s--;
	}

	return r <<= s; // shift when v's highest bits are zero
}

static uint8_t reverse_bits_8(uint v)
{
	uint r = v; // r will be reversed bits of v; first get LSB of v
	uint s = 8 - 1; // extra shift needed at end

	for (v >>= 1; v; v >>= 1)
	{   
		r <<= 1;
		r |= v & 1;
		s--;
	}

	return r <<= s; // shift when v's highest bits are zero
}


static void build_movem_re(int opcode, int size)
{
	cs_m68k* info = build_init_op(opcode, 2, size);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	op0->type = M68K_OP_REG_BITS;
	op0->register_bits = reverse_bits(read_imm_16());

	get_ea_mode_op(op1, g_cpu_ir, size);
}

static void build_movem_er(int opcode, int size)
{
	cs_m68k* info = build_init_op(opcode, 2, size);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	get_ea_mode_op(op0, g_cpu_ir, size);

	op1->type = M68K_OP_REG_BITS;
	op1->register_bits = read_imm_16(); 
}

static void build_imm(int opcode, int data)
{
	cs_m68k* info = build_init_op(opcode, 1, 0);
	if (!info) {
		return;
	}

	MCInst_setOpcode(g_inst, opcode);

	cs_m68k_op* op = &info->operands[0];

	op->type = M68K_OP_IMM;
	op->address_mode = M68K_AM_IMMIDIATE;
	op->imm = data;
}

static void build_illegal(int data)
{
	build_imm(M68K_INS_ILLEGAL, data);
}

static void build_invalid(int data)
{
	build_imm(M68K_INS_INVALID, data);
}

static void build_cas2(int size)
{
	cs_m68k* info = build_init_op(M68K_INS_CAS2, 3, size);
	if (!info) {
		return;
	}

	/* cas2 is the only 3 words instruction, word2 and word3 have the same motif bits to check */
	uint word3 = peek_imm_32() & 0xffff;
	if(!instruction_is_valid(g_cpu_ir, word3))
		return;

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];
	cs_m68k_op* op2 = &info->operands[2];

	uint extension = read_imm_32();

	op0->address_mode = M68K_AM_NONE;
	op0->type = M68K_OP_REG_PAIR;
	op0->register_bits = (((extension >> 16) & 7) << 4) | (extension & 7);

	op1->address_mode = M68K_AM_NONE;
	op1->type = M68K_OP_REG_PAIR;
	op1->register_bits = (((extension >> 22) & 7) << 4) | ((extension >> 6) & 7);

	const int reg_0 = (extension >> 28) & 7;
	const int reg_1 = (extension >> 12) & 7;

	op2->address_mode = M68K_AM_NONE;
	op2->type = M68K_OP_REG_PAIR;
	op2->register_bits = ((reg_0 + (BIT_1F(extension) ? 8 : 0)) << 4) |
						  (reg_1 + (BIT_F(extension) ? 8 : 0));
}

static void build_chk2_cmp2(int size)
{
	uint extension = read_imm_16();

	cs_m68k* info = build_init_op(M68K_INS_CHK2, 2, size);

	if (BIT_B(extension))
		MCInst_setOpcode(g_inst, M68K_INS_CHK2);
	else
		MCInst_setOpcode(g_inst, M68K_INS_CMP2);

	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	get_ea_mode_op(op0, g_cpu_ir, size);

	op1->address_mode = M68K_AM_NONE;
	op1->type = M68K_OP_REG;
	op1->reg = (BIT_F(extension) ? M68K_REG_A0 : M68K_REG_D0) + ((extension >> 12) & 7);
}

static void build_move16(int data[2], int modes[2])
{
	int i;

	cs_m68k* info = build_init_op(M68K_INS_MOVE16, 2, 0);
	if (!info) {
		return;
	}

	for (i = 0; i < 2; ++i)
	{
		cs_m68k_op* op = &info->operands[i];
		op->type = M68K_OP_MEM;

		const int d = data[i]; 
		const int m = modes[i]; 

		if (m == M68K_AM_REGI_ADDR_POST_INC || m == M68K_AM_REG_DIRECT_ADDR) {
			op->address_mode = m;
			op->reg = M68K_REG_A0 + d;
		} else {
			op->address_mode = m;
			op->imm = d; 
		}
	}
}

static void build_link(int disp, int size)
{
	cs_m68k* info = build_init_op(M68K_INS_LINK, 2, size);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	op0->address_mode = M68K_AM_NONE;
	op0->reg = M68K_REG_A0 + (g_cpu_ir & 7);

	op1->address_mode = M68K_AM_IMMIDIATE;
	op1->type = M68K_OP_IMM;
	op1->imm = disp;
}

static void build_cpush_cinv(int op_offset)
{
	cs_m68k* info = build_init_op(M68K_INS_ILLEGAL, 2, 0);
	switch ((g_cpu_ir >> 3) & 3)
	{
		case 0:
			if(info) {
				info->op_count = 0;
			}
			break;
		case 1:
			MCInst_setOpcode(g_inst, op_offset + 0);
			break;
		case 2:
			MCInst_setOpcode(g_inst, op_offset + 1);
			break;
		case 3:
			if(info) {
				info->op_count = 1;
			}
			MCInst_setOpcode(g_inst, op_offset + 2);
			break;
	}

	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	op0->address_mode = M68K_AM_IMMIDIATE;
	op0->type = M68K_OP_IMM;
	op0->imm = (g_cpu_ir >> 6) & 3;

	op1->type = M68K_OP_MEM;
	op1->address_mode = M68K_AM_REG_DIRECT_ADDR;
	op1->imm = M68K_REG_A0 + (g_cpu_ir & 7);
}

static void build_movep_re(int size)
{
	cs_m68k* info = build_init_op(M68K_INS_MOVEP, 2, size);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	op0->reg = M68K_REG_D0 + ((g_cpu_ir >> 9) & 7);

	op1->address_mode = M68K_AM_REGI_ADDR_DISP;
	op1->type = M68K_OP_MEM;
	op1->mem.base_reg = M68K_REG_A0 + (g_cpu_ir & 7); 
	op1->mem.disp = read_imm_16();
}

static void build_movep_er(int size)
{
	cs_m68k* info = build_init_op(M68K_INS_MOVEP, 2, size);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	op0->address_mode = M68K_AM_REGI_ADDR_DISP;
	op0->type = M68K_OP_MEM;
	op0->mem.base_reg = M68K_REG_A0 + (g_cpu_ir & 7); 
	op0->mem.disp = read_imm_16();

	op1->reg = M68K_REG_D0 + ((g_cpu_ir >> 9) & 7);
}

static void build_moves(int size)
{
	uint extension = read_imm_16();

	cs_m68k* info = build_init_op(M68K_INS_MOVES, 2, size);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	if (BIT_B(extension)) {
		op0->reg = (BIT_F(extension) ? M68K_REG_A0 : M68K_REG_D0) + ((extension >> 12) & 7);
		get_ea_mode_op(op1, g_cpu_ir, size);
	} else {
		get_ea_mode_op(op0, g_cpu_ir, size);
		op1->reg = (BIT_F(extension) ? M68K_REG_A0 : M68K_REG_D0) + ((extension >> 12) & 7);
	}
}

static void build_er_1(int opcode, uint8_t size)
{
	build_er_gen_1(true, opcode, size);
}

/* ======================================================================== */
/* ========================= INSTRUCTION HANDLERS ========================= */
/* ======================================================================== */
/* Instruction handler function names follow this convention:
 *
 * d68000_NAME_EXTENSIONS(void)
 * where NAME is the name of the opcode it handles and EXTENSIONS are any
 * extensions for special instances of that opcode.
 *
 * Examples:
 *   d68000_add_er_8(): add opcode, from effective address to register,
 *                      size = byte
 *
 *   d68000_asr_s_8(): arithmetic shift right, static count, size = byte
 *
 *
 * Common extensions:
 * 8   : size = byte
 * 16  : size = word
 * 32  : size = long
 * rr  : register to register
 * mm  : memory to memory
 * r   : register
 * s   : static
 * er  : effective address -> register
 * re  : register -> effective address
 * ea  : using effective address mode of operation
 * d   : data register direct
 * a   : address register direct
 * ai  : address register indirect
 * pi  : address register indirect with postincrement
 * pd  : address register indirect with predecrement
 * di  : address register indirect with displacement
 * ix  : address register indirect with index
 * aw  : absolute word
 * al  : absolute long
 */


static void d68000_invalid(void)
{
	build_invalid(g_cpu_ir);
}

static void d68000_illegal(void)
{
	build_illegal(g_cpu_ir);
}

static void d68000_1010(void)
{
	build_invalid(g_cpu_ir);
}

static void d68000_1111(void)
{
	build_invalid(g_cpu_ir);
}

static void d68000_abcd_rr(void)
{
	build_rr(M68K_INS_ABCD, 1, 0); 
}

static void d68000_abcd_mm(void)
{
	build_mm(M68K_INS_ABCD, 1, 0); 
}

static void d68000_add_er_8(void)
{
	build_er_1(M68K_INS_ADD, 1);
}

static void d68000_add_er_16(void)
{
	build_er_1(M68K_INS_ADD, 2);
}

static void d68000_add_er_32(void)
{
	build_er_1(M68K_INS_ADD, 4);
}

static void d68000_add_re_8(void)
{
	build_re_1(M68K_INS_ADD, 1);
}

static void d68000_add_re_16(void)
{
	build_re_1(M68K_INS_ADD, 2);
}

static void d68000_add_re_32(void)
{
	build_re_1(M68K_INS_ADD, 4);
}

static void d68000_adda_16(void)
{
	build_ea_a(M68K_INS_ADDA, 2);
}

static void d68000_adda_32(void)
{
	build_ea_a(M68K_INS_ADDA, 4);
}

static void d68000_addi_8(void)
{
	build_imm_ea(M68K_INS_ADDI, 1, read_imm_8());
}

static void d68000_addi_16(void)
{
	build_imm_ea(M68K_INS_ADDI, 2, read_imm_16());
}

static void d68000_addi_32(void)
{
	build_imm_ea(M68K_INS_ADDI, 4, read_imm_32());
}

static void d68000_addq_8(void)
{
	build_3bit_ea(M68K_INS_ADDQ, 1);
}

static void d68000_addq_16(void)
{
	build_3bit_ea(M68K_INS_ADDQ, 2);
}

static void d68000_addq_32(void)
{
	build_3bit_ea(M68K_INS_ADDQ, 4);
}

static void d68000_addx_rr_8(void)
{
	build_rr(M68K_INS_ADDX, 1, 0); 
}

static void d68000_addx_rr_16(void)
{
	build_rr(M68K_INS_ADDX, 2, 0); 
}

static void d68000_addx_rr_32(void)
{
	build_rr(M68K_INS_ADDX, 4, 0); 
}

static void d68000_addx_mm_8(void)
{
	build_mm(M68K_INS_ADDX, 1, 0); 
}

static void d68000_addx_mm_16(void)
{
	build_mm(M68K_INS_ADDX, 2, 0); 
}

static void d68000_addx_mm_32(void)
{
	build_mm(M68K_INS_ADDX, 4, 0); 
}

static void d68000_and_er_8(void)
{
	build_er_1(M68K_INS_AND, 1);
}

static void d68000_and_er_16(void)
{
	build_er_1(M68K_INS_AND, 2);
}

static void d68000_and_er_32(void)
{
	build_er_1(M68K_INS_AND, 4);
}

static void d68000_and_re_8(void)
{
	build_re_1(M68K_INS_AND, 1);
}

static void d68000_and_re_16(void)
{
	build_re_1(M68K_INS_AND, 2);
}

static void d68000_and_re_32(void)
{
	build_re_1(M68K_INS_AND, 4);
}

static void d68000_andi_8(void)
{
	build_imm_ea(M68K_INS_ANDI, 1, read_imm_8());
}

static void d68000_andi_16(void)
{
	build_imm_ea(M68K_INS_ANDI, 2, read_imm_16());
}

static void d68000_andi_32(void)
{
	build_imm_ea(M68K_INS_ANDI, 4, read_imm_32());
}

static void d68000_andi_to_ccr(void)
{
	build_imm_special_reg(M68K_INS_ANDI, read_imm_8(), 1, M68K_REG_CCR);
}

static void d68000_andi_to_sr(void)
{
	build_imm_special_reg(M68K_INS_ANDI, read_imm_16(), 2, M68K_REG_SR);
}

static void d68000_asr_s_8(void)
{
	build_3bit_d(M68K_INS_ASR, 1);
}

static void d68000_asr_s_16(void)
{
	build_3bit_d(M68K_INS_ASR, 2);
}

static void d68000_asr_s_32(void)
{
	build_3bit_d(M68K_INS_ASR, 4);
}

static void d68000_asr_r_8(void)
{
	build_r(M68K_INS_ASR, 1);
}

static void d68000_asr_r_16(void)
{
	build_r(M68K_INS_ASR, 2);
}

static void d68000_asr_r_32(void)
{
	build_r(M68K_INS_ASR, 4);
}

static void d68000_asr_ea(void)
{
	build_ea(M68K_INS_ASR, 2);
}

static void d68000_asl_s_8(void)
{
	build_3bit_d(M68K_INS_ASL, 1);
}

static void d68000_asl_s_16(void)
{
	build_3bit_d(M68K_INS_ASL, 2);
}

static void d68000_asl_s_32(void)
{
	build_3bit_d(M68K_INS_ASL, 4);
}

static void d68000_asl_r_8(void)
{
	build_r(M68K_INS_ASL, 1);
}

static void d68000_asl_r_16(void)
{
	build_r(M68K_INS_ASL, 2);
}

static void d68000_asl_r_32(void)
{
	build_r(M68K_INS_ASL, 4);
}

static void d68000_asl_ea(void)
{
	build_ea(M68K_INS_ASL, 2);
}

static void d68000_bcc_8(void)
{
	uint temp_pc = g_cpu_pc;
	build_bcc(1, temp_pc + make_int_8(g_cpu_ir));
}

static void d68000_bcc_16(void)
{
	uint temp_pc = g_cpu_pc;
	build_bcc(2, temp_pc + make_int_16(read_imm_16()));
}

static void d68020_bcc_32(void)
{
	uint temp_pc = g_cpu_pc;
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_bcc(4, temp_pc + read_imm_32());
}

static void d68000_bchg_r(void)
{
	build_re_1(M68K_INS_BCHG, 1);
}

static void d68000_bchg_s(void)
{
	build_imm_ea(M68K_INS_BCHG, 1, read_imm_8());
}

static void d68000_bclr_r(void)
{
	build_re_1(M68K_INS_BCLR, 1);
}

static void d68000_bclr_s(void)
{
	build_imm_ea(M68K_INS_BCLR, 1, read_imm_8());
}

static void d68010_bkpt(void)
{
	LIMIT_CPU_TYPES(M68010_PLUS);
	build_bxx(M68K_INS_BKPT, 0, g_cpu_ir & 7);
}

static void d68020_bfchg(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_bitfield_ins(M68K_INS_BFCHG, false);
}


static void d68020_bfclr(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_bitfield_ins(M68K_INS_BFCLR, false);
}

static void d68020_bfexts(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_bitfield_ins(M68K_INS_BFEXTS, true);
}

static void d68020_bfextu(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_bitfield_ins(M68K_INS_BFEXTU, true);
}

static void d68020_bfffo(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_bitfield_ins(M68K_INS_BFFFO, true);
}

static void d68020_bfins(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_bitfield_ins(M68K_INS_BFINS, true);

	cs_detail *detail = g_inst->flat_insn->detail;
	if (!detail)
	{
		return;
	}

	cs_m68k* info = &detail->m68k;
	// a bit hacky but we need to flip the args on only this instruction

	cs_m68k_op temp = info->operands[0];
	info->operands[0] = info->operands[1];
	info->operands[1] = temp;
}

static void d68020_bfset(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_bitfield_ins(M68K_INS_BFSET, false);
}

static void d68020_bftst(void)
{
	build_bitfield_ins(M68K_INS_BFTST, false);
}

static void d68000_bra_8(void)
{
	uint temp_pc = g_cpu_pc;
	build_bxx(M68K_INS_BRA, 1, temp_pc + make_int_8(g_cpu_ir));
}

static void d68000_bra_16(void)
{
	uint temp_pc = g_cpu_pc;
	build_bxx(M68K_INS_BRA, 2, temp_pc + make_int_16(read_imm_16()));
}

static void d68020_bra_32(void)
{
	uint temp_pc = g_cpu_pc;
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_bxx(M68K_INS_BRA, 4, temp_pc + read_imm_32());
}

static void d68000_bset_r(void)
{
	build_re_1(M68K_INS_BSET, 1);
}

static void d68000_bset_s(void)
{
	build_imm_ea(M68K_INS_BSET, 1, read_imm_8());
}

static void d68000_bsr_8(void)
{
	uint temp_pc = g_cpu_pc;
	build_bxx(M68K_INS_BSR, 1, temp_pc + make_int_8(g_cpu_ir));
}

static void d68000_bsr_16(void)
{
	uint temp_pc = g_cpu_pc;
	build_bxx(M68K_INS_BSR, 2, temp_pc + make_int_16(read_imm_16()));
}

static void d68020_bsr_32(void)
{
	uint temp_pc = g_cpu_pc;
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_bxx(M68K_INS_BSR, 4, temp_pc + peek_imm_32());
}

static void d68000_btst_r(void)
{
	build_re_1(M68K_INS_BTST, 4);
}

static void d68000_btst_s(void)
{
	build_imm_ea(M68K_INS_BTST, 1, read_imm_8());
}

static void d68020_callm(void)
{
	LIMIT_CPU_TYPES(M68020_ONLY);
	build_imm_ea(M68K_INS_CALLM, 0, read_imm_8());
}

static void d68020_cas_8(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_d_d_ea(M68K_INS_CAS, 1);
}

static void d68020_cas_16(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_d_d_ea(M68K_INS_CAS, 2);
}

static void d68020_cas_32(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_d_d_ea(M68K_INS_CAS, 4);
}

static void d68020_cas2_16(void)
{
	build_cas2(2);
}

static void d68020_cas2_32(void)
{
	build_cas2(4);
}

static void d68000_chk_16(void)
{
	build_er_1(M68K_INS_CHK, 2);
}

static void d68020_chk_32(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_er_1(M68K_INS_CHK, 4);
}

static void d68020_chk2_cmp2_8(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_chk2_cmp2(1);
}

static void d68020_chk2_cmp2_16(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_chk2_cmp2(2);
}

static void d68020_chk2_cmp2_32(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_chk2_cmp2(4);
}

static void d68040_cinv(void)
{
	LIMIT_CPU_TYPES(M68040_PLUS);
	build_cpush_cinv(M68K_INS_CINVL);
}

static void d68000_clr_8(void)
{
	build_ea(M68K_INS_CLR, 1);
}

static void d68000_clr_16(void)
{
	build_ea(M68K_INS_CLR, 2);
}

static void d68000_clr_32(void)
{
	build_ea(M68K_INS_CLR, 4);
}

static void d68000_cmp_8(void)
{
	build_er_1(M68K_INS_CMP, 1);
}

static void d68000_cmp_16(void)
{
	build_er_1(M68K_INS_CMP, 2);
}

static void d68000_cmp_32(void)
{
	build_er_1(M68K_INS_CMP, 4);
}

static void d68000_cmpa_16(void)
{
	build_ea_a(M68K_INS_CMPA, 2);
}

static void d68000_cmpa_32(void)
{
	build_ea_a(M68K_INS_CMPA, 4);
}

static void d68000_cmpi_8(void)
{
	build_imm_ea(M68K_INS_CMPI, 1, read_imm_8());
}

static void d68020_cmpi_pcdi_8(void)
{
	LIMIT_CPU_TYPES(M68010_PLUS);
	build_imm_ea(M68K_INS_CMPI, 1, read_imm_8());
}

static void d68020_cmpi_pcix_8(void)
{
	LIMIT_CPU_TYPES(M68010_PLUS);
	build_imm_ea(M68K_INS_CMPI, 1, read_imm_8());
}

static void d68000_cmpi_16(void)
{
	build_imm_ea(M68K_INS_CMPI, 2, read_imm_16());
}

static void d68020_cmpi_pcdi_16(void)
{
	LIMIT_CPU_TYPES(M68010_PLUS);
	build_imm_ea(M68K_INS_CMPI, 2, read_imm_16());
}

static void d68020_cmpi_pcix_16(void)
{
	LIMIT_CPU_TYPES(M68010_PLUS);
	build_imm_ea(M68K_INS_CMPI, 2, read_imm_16());
}

static void d68000_cmpi_32(void)
{
	build_imm_ea(M68K_INS_CMPI, 4, read_imm_32());
}

static void d68020_cmpi_pcdi_32(void)
{
	LIMIT_CPU_TYPES(M68010_PLUS);
	build_imm_ea(M68K_INS_CMPI, 4, read_imm_32());
}

static void d68020_cmpi_pcix_32(void)
{
	LIMIT_CPU_TYPES(M68010_PLUS);
	build_imm_ea(M68K_INS_CMPI, 4, read_imm_32());
}

static void d68000_cmpm_8(void)
{
	build_pi_pi(M68K_INS_CMPM, 1);
}

static void d68000_cmpm_16(void)
{
	build_pi_pi(M68K_INS_CMPM, 2);
}

static void d68000_cmpm_32(void)
{
	build_pi_pi(M68K_INS_CMPM, 4);
}

static void d68020_cpbcc_16(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);

	uint new_pc = g_cpu_pc;
	new_pc += make_int_16(read_imm_16());

	cs_m68k* info = build_init_op(M68K_INS_FBF, 1, 2);

	// these are all in row with the extension so just doing a add here is fine
	g_inst->Opcode += (g_cpu_ir & 0x2f); 

	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];

	op0->address_mode = M68K_AM_IMMIDIATE;
	op0->type = M68K_OP_IMM;
	op0->imm = new_pc;
}

static void d68020_cpbcc_32(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);

	LIMIT_CPU_TYPES(M68020_PLUS);

	uint new_pc = g_cpu_pc;
	new_pc += read_imm_32();

	cs_m68k* info = build_init_op(M68K_INS_FBF, 1, 4);

	// these are all in row with the extension so just doing a add here is fine
	g_inst->Opcode += (g_cpu_ir & 0x2f); 

	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];

	op0->type = M68K_OP_IMM;
	op0->address_mode = M68K_AM_IMMIDIATE;
	op0->imm = new_pc;
}

static void d68020_cpdbcc(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);

	uint new_pc = g_cpu_pc;
	uint ext1 = read_imm_16();
	uint ext2 = read_imm_16();
	new_pc += make_int_16(ext2) + 2;

	cs_m68k* info = build_init_op(M68K_INS_FDBF, 2, 0);

	// these are all in row with the extension so just doing a add here is fine
	g_inst->Opcode += (ext1 & 0x2f); 

	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	op0->reg = M68K_REG_D0 + (g_cpu_ir & 7);

	op1->address_mode = M68K_AM_IMMIDIATE;
	op1->type = M68K_OP_IMM;
	op1->imm = new_pc;
}

static void fmove_fpcr(uint ext)
{
	int regsel = (ext >> 10) & 0x7;
	int dir = (ext >> 13) & 0x1;

	cs_m68k* info = build_init_op(M68K_INS_FMOVE, 2, 4);
	if (!info) {
		return;
	}

	cs_m68k_op* special = &info->operands[0];
	cs_m68k_op* op_ea = &info->operands[1];

	if (!dir) {
		cs_m68k_op* t = special;
		special = op_ea;
		op_ea = t;
	}

	get_ea_mode_op(op_ea, g_cpu_ir, 4);

	if (regsel & 4) 
		special->reg = M68K_REG_FPCR; 
	else if (regsel & 2) 
		special->reg = M68K_REG_FPSR; 
	else if (regsel & 1) 
		special->reg = M68K_REG_FPIAR; 
}

static void fmovem(uint ext)
{
	int dir = (ext >> 13) & 0x1;
	int mode = (ext >> 11) & 0x3;
	uint reglist = ext & 0xff;

	cs_m68k* info = build_init_op(M68K_INS_FMOVEM, 2, 0);
	if (!info) {
		return;
	}

	cs_m68k_op* op_reglist = &info->operands[0];
	cs_m68k_op* op_ea = &info->operands[1];

	// flip args around

	if (!dir) {
		cs_m68k_op* t = op_reglist;
		op_reglist = op_ea;
		op_ea = t;
	}

	get_ea_mode_op(op_ea, g_cpu_ir, 0);

	switch (mode)
	{
		case 1 : // Dynamic list in dn register
		{
			op_reglist->reg = M68K_REG_D0 + ((reglist >> 4) & 7);
			break;
		}

		case 0 : 
		{
			op_reglist->address_mode = M68K_AM_NONE;
			op_reglist->type = M68K_OP_REG_BITS;
			op_reglist->register_bits = reglist << 16; 
			break;
		}

		case 2 : // Static list
		{
			op_reglist->address_mode = M68K_AM_NONE;
			op_reglist->type = M68K_OP_REG_BITS;
			op_reglist->register_bits = ((uint32_t)reverse_bits_8(reglist)) << 16; 
			break;
		}
	}
}

static void d68020_cpgen(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	
	bool supports_single_op = true;

	uint next = read_imm_16();

	int rm = (next >> 14) & 0x1;
	int src = (next >> 10) & 0x7;
	int dst = (next >> 7) & 0x7;
	int opmode = next & 0x3f;

	// special handling for fmovecr

	if (BITFIELD(g_cpu_ir, 5, 0) == 0 && BITFIELD(next, 15, 10) == 0x17) {
		cs_m68k* info = build_init_op(M68K_INS_FMOVECR, 2, 0);
		if (!info) {
			return;
		}

		cs_m68k_op* op0 = &info->operands[0];
		cs_m68k_op* op1 = &info->operands[1];

		op0->address_mode = M68K_AM_IMMIDIATE;
		op0->type = M68K_OP_IMM;
		op0->imm = next & 0x3f;

		op1->reg = M68K_REG_FP0 + ((next >> 7) & 7);
		return;
	}

	// deal with extended move stuff

	switch ((next >> 13) & 0x7)
	{
		// fmovem fpcr

		case 0x4:	// FMOVEM ea, FPCR
		case 0x5:	// FMOVEM FPCR, ea
		{
			fmove_fpcr(next);
			return;
		}

		// fmovem list

		case 0x6:
		case 0x7:
		{
			fmovem(next);
			return;
		}
	}

	// Se comment bellow on why this is being done

	if ((next >> 6) & 1)
		opmode &= ~4;

	// special handling of some instructions here
	//


	switch (opmode)
	{
		case 0x00: MCInst_setOpcode(g_inst, M68K_INS_FMOVE); supports_single_op = false; break;
		case 0x01: MCInst_setOpcode(g_inst, M68K_INS_FINT); break; 
		case 0x02: MCInst_setOpcode(g_inst, M68K_INS_FSINH); break;
		case 0x03: MCInst_setOpcode(g_inst, M68K_INS_FINTRZ); break;
		case 0x04: MCInst_setOpcode(g_inst, M68K_INS_FSQRT); break;
		case 0x06: MCInst_setOpcode(g_inst, M68K_INS_FLOGNP1); break;
		case 0x08: MCInst_setOpcode(g_inst, M68K_INS_FETOXM1); break;
		case 0x09: MCInst_setOpcode(g_inst, M68K_INS_FATANH); break;
		case 0x0a: MCInst_setOpcode(g_inst, M68K_INS_FATAN); break;
		case 0x0c: MCInst_setOpcode(g_inst, M68K_INS_FASIN); break; 
		case 0x0d: MCInst_setOpcode(g_inst, M68K_INS_FATANH); break;
		case 0x0e: MCInst_setOpcode(g_inst, M68K_INS_FSIN); break;
		case 0x0f: MCInst_setOpcode(g_inst, M68K_INS_FTAN); break;
		case 0x10: MCInst_setOpcode(g_inst, M68K_INS_FETOX); break;
		case 0x11: MCInst_setOpcode(g_inst, M68K_INS_FTWOTOX); break;
		case 0x12: MCInst_setOpcode(g_inst, M68K_INS_FTENTOX); break;
		case 0x14: MCInst_setOpcode(g_inst, M68K_INS_FLOGN); break;
		case 0x15: MCInst_setOpcode(g_inst, M68K_INS_FLOG10); break;
		case 0x16: MCInst_setOpcode(g_inst, M68K_INS_FLOG2); break;
		case 0x18: MCInst_setOpcode(g_inst, M68K_INS_FABS); break;
		case 0x19: MCInst_setOpcode(g_inst, M68K_INS_FCOSH); break;
		case 0x1a: MCInst_setOpcode(g_inst, M68K_INS_FNEG); break;
		case 0x1c: MCInst_setOpcode(g_inst, M68K_INS_FACOS); break; 
		case 0x1d: MCInst_setOpcode(g_inst, M68K_INS_FCOS); break;
		case 0x1e: MCInst_setOpcode(g_inst, M68K_INS_FGETEXP); break;
		case 0x1f: MCInst_setOpcode(g_inst, M68K_INS_FGETMAN); break;
		case 0x20: MCInst_setOpcode(g_inst, M68K_INS_FDIV); supports_single_op = false; break;
		case 0x21: MCInst_setOpcode(g_inst, M68K_INS_FMOD); supports_single_op = false; break;
		case 0x22: MCInst_setOpcode(g_inst, M68K_INS_FADD); supports_single_op = false; break;
		case 0x23: MCInst_setOpcode(g_inst, M68K_INS_FMUL); supports_single_op = false; break;
		case 0x24: MCInst_setOpcode(g_inst, M68K_INS_FSGLDIV); supports_single_op = false; break;
		case 0x25: MCInst_setOpcode(g_inst, M68K_INS_FREM); break;
		case 0x26: MCInst_setOpcode(g_inst, M68K_INS_FSCALE); break;
		case 0x27: MCInst_setOpcode(g_inst, M68K_INS_FSGLMUL); break;
		case 0x28: MCInst_setOpcode(g_inst, M68K_INS_FSUB); supports_single_op = false; break;
		case 0x38: MCInst_setOpcode(g_inst, M68K_INS_FCMP); supports_single_op = false; break;
		case 0x3a: MCInst_setOpcode(g_inst, M68K_INS_FTST); break;
		default:	
			break;
	}

	// Some trickery here! It's not documented but if bit 6 is set this is a s/d opcode and then
	// if bit 2 is set it's a d. As we already have set our opcode in the code above we can just
	// offset it as the following 2 op codes (if s/d is supported) will always be directly after it

	if ((next >> 6) & 1) {
		if ((next >> 2) & 1)
			g_inst->Opcode += 2;
		else
			g_inst->Opcode += 1;
	}

	cs_detail *detail = g_inst->flat_insn->detail;
	if (!detail)
	{
		return;
	}
	cs_m68k *info = &detail->m68k;

	info->op_count = 2;
	info->op_size.type = M68K_SIZE_TYPE_CPU;
	info->op_size.cpu_size = 0;

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	if (rm == 0 && supports_single_op && src == dst) {
		info->op_count = 1;
		op0->reg = M68K_REG_FP0 + dst;
		return;
	}

	if (rm == 1) {
		switch (src)
		{
			case 0x00 : 
			{
				info->op_size.cpu_size = M68K_CPU_SIZE_LONG; 
				get_ea_mode_op(op0, g_cpu_ir, 4);
				break;
			}

			case 0x06 : 
			{
				info->op_size.cpu_size = M68K_CPU_SIZE_BYTE; 
				get_ea_mode_op(op0, g_cpu_ir, 1);
				break; 
			}

			case 0x04 : 
			{
				info->op_size.cpu_size = M68K_CPU_SIZE_WORD; 
				get_ea_mode_op(op0, g_cpu_ir, 2);
				break;
			}

			case 0x01 : 
			{
				info->op_size.type = M68K_SIZE_TYPE_FPU;
				info->op_size.fpu_size = M68K_FPU_SIZE_SINGLE; 
				get_ea_mode_op(op0, g_cpu_ir, 4);
				break;
			}

			case 0x05:
			{
				info->op_size.type = M68K_SIZE_TYPE_FPU;
				info->op_size.fpu_size = M68K_FPU_SIZE_DOUBLE; 
				get_ea_mode_op(op0, g_cpu_ir, 8);
				break;
			}

			default :
			{
				info->op_size.type = M68K_SIZE_TYPE_FPU;
				info->op_size.fpu_size = M68K_FPU_SIZE_EXTENDED; 
				break;
			}
		}
	} else {
		op0->reg = M68K_REG_FP0 + src; 
	}

	op1->reg = M68K_REG_FP0 + dst;
}

static void d68020_cprestore(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	cs_m68k* info = build_init_op(M68K_INS_FRESTORE, 1, 0);
	if (!info) {
		return;
	}
	get_ea_mode_op(&info->operands[0], g_cpu_ir, 1);
}

static void d68020_cpsave(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	cs_m68k* info = build_init_op(M68K_INS_FSAVE, 1, 0);
	if (!info) {
		return;
	}
	get_ea_mode_op(&info->operands[0], g_cpu_ir, 1);
}

static void d68020_cpscc(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	cs_m68k* info = build_init_op(M68K_INS_FSF, 1, 1);

	// these are all in row with the extension so just doing a add here is fine
	g_inst->Opcode += (read_imm_16() & 0x2f); 

	if (!info) {
		return;
	}

	get_ea_mode_op(&info->operands[0], g_cpu_ir, 1);
}

static void d68020_cptrapcc_0(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	uint extension1 = read_imm_16();

	build_init_op(M68K_INS_FTRAPF, 0, 0);

	// these are all in row with the extension so just doing a add here is fine
	g_inst->Opcode += (extension1 & 0x2f); 
}

static void d68020_cptrapcc_16(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);

	uint extension1 = read_imm_16();
	uint extension2 = read_imm_16();

	cs_m68k* info = build_init_op(M68K_INS_FTRAPF, 1, 2);

	// these are all in row with the extension so just doing a add here is fine
	g_inst->Opcode += (extension1 & 0x2f); 

	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];

	op0->address_mode = M68K_AM_IMMIDIATE;
	op0->type = M68K_OP_IMM;
	op0->imm = extension2;
}

static void d68020_cptrapcc_32(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);

	uint extension1 = read_imm_16();
	uint extension2 = read_imm_32();

	cs_m68k* info = build_init_op(M68K_INS_FTRAPF, 1, 2);

	// these are all in row with the extension so just doing a add here is fine
	g_inst->Opcode += (extension1 & 0x2f); 

	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];

	op0->address_mode = M68K_AM_IMMIDIATE;
	op0->type = M68K_OP_IMM;
	op0->imm = extension2;
}

static void d68040_cpush(void)
{
	LIMIT_CPU_TYPES(M68040_PLUS);
	build_cpush_cinv(M68K_INS_CPUSHL);
}

static void d68000_dbra(void)
{
	uint temp_pc = g_cpu_pc;
	build_dbxx(M68K_INS_DBRA, 0, temp_pc + make_int_16(read_imm_16()));
}

static void d68000_dbcc(void)
{
	uint temp_pc = g_cpu_pc;
	build_dbcc(0, temp_pc + make_int_16(read_imm_16()));
}

static void d68000_divs(void)
{
	build_er_1(M68K_INS_DIVS, 2);
}

static void d68000_divu(void)
{
	build_er_1(M68K_INS_DIVU, 2);
}

static void d68020_divl(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);

	uint extension = read_imm_16();
	uint insn_signed = 0;
   
	if (BIT_B((extension)))
		insn_signed = 1;

	cs_m68k* info = build_init_op(insn_signed ? M68K_INS_DIVS : M68K_INS_DIVU, 2, 4);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	get_ea_mode_op(op0, g_cpu_ir, 4);

	const uint reg_0 = extension & 7;
	const uint reg_1 = (extension >> 12) & 7;

	op1->address_mode = M68K_AM_NONE;
	op1->type = M68K_OP_REG_PAIR;
	op1->register_bits = (reg_0 << 4) | reg_1; 

	if ((reg_0 == reg_1) || !BIT_A(extension)) {
		op1->type = M68K_OP_REG;
		op1->reg = M68K_REG_D0 + reg_1;
	}
}

static void d68000_eor_8(void)
{
	build_re_1(M68K_INS_EOR, 1); 
}

static void d68000_eor_16(void)
{
	build_re_1(M68K_INS_EOR, 2); 
}

static void d68000_eor_32(void)
{
	build_re_1(M68K_INS_EOR, 4); 
}

static void d68000_eori_8(void)
{
	build_imm_ea(M68K_INS_EORI, 1, read_imm_8());
}

static void d68000_eori_16(void)
{
	build_imm_ea(M68K_INS_EORI, 2, read_imm_16());
}

static void d68000_eori_32(void)
{
	build_imm_ea(M68K_INS_EORI, 4, read_imm_32());
}

static void d68000_eori_to_ccr(void)
{
	build_imm_special_reg(M68K_INS_EORI, read_imm_8(), 1, M68K_REG_CCR);
}

static void d68000_eori_to_sr(void)
{
	build_imm_special_reg(M68K_INS_EORI, read_imm_16(), 2, M68K_REG_SR);
}

static void d68000_exg_dd(void)
{
	build_r(M68K_INS_EXG, 4);
}

static void d68000_exg_aa(void)
{
	cs_m68k* info = build_init_op(M68K_INS_EXG, 2, 4);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	op0->address_mode = M68K_AM_NONE;
	op0->reg = M68K_REG_A0 + ((g_cpu_ir >> 9) & 7);

	op1->address_mode = M68K_AM_NONE;
	op1->reg = M68K_REG_A0 + (g_cpu_ir & 7);
}

static void d68000_exg_da(void)
{
	cs_m68k* info = build_init_op(M68K_INS_EXG, 2, 4);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	op0->address_mode = M68K_AM_NONE;
	op0->reg = M68K_REG_D0 + ((g_cpu_ir >> 9) & 7);

	op1->address_mode = M68K_AM_NONE;
	op1->reg = M68K_REG_A0 + (g_cpu_ir & 7);
}

static void d68000_ext_16(void)
{
	build_d(M68K_INS_EXT, 2);
}

static void d68000_ext_32(void)
{
	build_d(M68K_INS_EXT, 4);
}

static void d68020_extb_32(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_d(M68K_INS_EXTB, 4);
}

static void d68000_jmp(void)
{
	cs_m68k* info = build_init_op(M68K_INS_JMP, 1, 0);
	if (!info) {
		return;
	}
	get_ea_mode_op(&info->operands[0], g_cpu_ir, 4);
}

static void d68000_jsr(void)
{
	cs_m68k* info = build_init_op(M68K_INS_JSR, 1, 0);
	if (!info) {
		return;
	}
	get_ea_mode_op(&info->operands[0], g_cpu_ir, 4);
}

static void d68000_lea(void)
{
	build_ea_a(M68K_INS_LEA, 4);
}

static void d68000_link_16(void)
{
	build_link(read_imm_16(), 2);
}

static void d68020_link_32(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_link(read_imm_32(), 4);
}

static void d68000_lsr_s_8(void)
{
	build_3bit_d(M68K_INS_LSR, 1);
}

static void d68000_lsr_s_16(void)
{
	build_3bit_d(M68K_INS_LSR, 2);
}

static void d68000_lsr_s_32(void)
{
	build_3bit_d(M68K_INS_LSR, 4);
}

static void d68000_lsr_r_8(void)
{
	build_r(M68K_INS_LSR, 1);
}

static void d68000_lsr_r_16(void)
{
	build_r(M68K_INS_LSR, 2);
}

static void d68000_lsr_r_32(void)
{
	build_r(M68K_INS_LSR, 4);
}

static void d68000_lsr_ea(void)
{
	build_ea(M68K_INS_LSR, 2);
}

static void d68000_lsl_s_8(void)
{
	build_3bit_d(M68K_INS_LSL, 1);
}

static void d68000_lsl_s_16(void)
{
	build_3bit_d(M68K_INS_LSL, 2);
}

static void d68000_lsl_s_32(void)
{
	build_3bit_d(M68K_INS_LSL, 4);
}

static void d68000_lsl_r_8(void)
{
	build_r(M68K_INS_LSL, 1);
}

static void d68000_lsl_r_16(void)
{
	build_r(M68K_INS_LSL, 2);
}

static void d68000_lsl_r_32(void)
{
	build_r(M68K_INS_LSL, 4);
}

static void d68000_lsl_ea(void)
{
	build_ea(M68K_INS_LSL, 2);
}

static void d68000_move_8(void)
{
	build_ea_ea(M68K_INS_MOVE, 1);
}

static void d68000_move_16(void)
{
	build_ea_ea(M68K_INS_MOVE, 2);
}

static void d68000_move_32(void)
{
	build_ea_ea(M68K_INS_MOVE, 4);
}

static void d68000_movea_16(void)
{
	build_ea_a(M68K_INS_MOVEA, 2);
}

static void d68000_movea_32(void)
{
	build_ea_a(M68K_INS_MOVEA, 4);
}

static void d68000_move_to_ccr(void)
{
	cs_m68k* info = build_init_op(M68K_INS_MOVE, 2, 2);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	get_ea_mode_op(op0, g_cpu_ir, 1);

	op1->address_mode = M68K_AM_NONE;
	op1->reg = M68K_REG_CCR;
}

static void d68010_move_fr_ccr(void)
{
	LIMIT_CPU_TYPES(M68010_PLUS);

	cs_m68k* info = build_init_op(M68K_INS_MOVE, 2, 2);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	op0->address_mode = M68K_AM_NONE;
	op0->reg = M68K_REG_CCR;

	get_ea_mode_op(op1, g_cpu_ir, 1);
}

static void d68000_move_fr_sr(void)
{
	cs_m68k* info = build_init_op(M68K_INS_MOVE, 2, 2);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	op0->address_mode = M68K_AM_NONE;
	op0->reg = M68K_REG_SR;

	get_ea_mode_op(op1, g_cpu_ir, 2);
}

static void d68000_move_to_sr(void)
{
	LIMIT_CPU_TYPES(M68010_PLUS);

	cs_m68k* info = build_init_op(M68K_INS_MOVE, 2, 2);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	get_ea_mode_op(op0, g_cpu_ir, 1);

	op1->address_mode = M68K_AM_NONE;
	op1->reg = M68K_REG_SR;
}

static void d68000_move_fr_usp(void)
{
	cs_m68k* info = build_init_op(M68K_INS_MOVE, 2, 0);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	op0->address_mode = M68K_AM_NONE;
	op0->reg = M68K_REG_USP;

	op1->address_mode = M68K_AM_NONE;
	op1->reg = M68K_REG_A0 + (g_cpu_ir & 7);
}

static void d68000_move_to_usp(void)
{
	cs_m68k* info = build_init_op(M68K_INS_MOVE, 2, 0);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	op0->address_mode = M68K_AM_NONE;
	op0->reg = M68K_REG_A0 + (g_cpu_ir & 7);

	op1->address_mode = M68K_AM_NONE;
	op1->reg = M68K_REG_USP;
}

static void d68010_movec(void)
{
	LIMIT_CPU_TYPES(M68010_PLUS);
	uint extension = read_imm_16();
	m68k_reg reg = M68K_REG_INVALID;

	cs_m68k* info = build_init_op(M68K_INS_MOVEC, 2, 0);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	switch (extension & 0xfff)
	{
		case 0x000: reg = M68K_REG_SFC; break;
		case 0x001: reg = M68K_REG_DFC; break;
		case 0x800: reg = M68K_REG_USP; break;
		case 0x801: reg = M68K_REG_VBR; break;
		case 0x002: reg = M68K_REG_CACR; break;
		case 0x802: reg = M68K_REG_CAAR; break;
		case 0x803: reg = M68K_REG_MSP; break;
		case 0x804: reg = M68K_REG_ISP; break;
		case 0x003: reg = M68K_REG_TC; break;
		case 0x004: reg = M68K_REG_ITT0; break;
		case 0x005: reg = M68K_REG_ITT1; break;
		case 0x006: reg = M68K_REG_DTT0; break;
		case 0x007: reg = M68K_REG_DTT1; break;
		case 0x805: reg = M68K_REG_MMUSR; break;
		case 0x806: reg = M68K_REG_URP; break;
		case 0x807: reg = M68K_REG_SRP; break;
	}

	if (BIT_1(g_cpu_ir)) {
		op0->reg = (BIT_F(extension) ? M68K_REG_A0 : M68K_REG_D0) + ((extension >> 12) & 7);
		op1->reg = reg; 
	} else {
		op0->reg = reg; 
		op1->reg = (BIT_F(extension) ? M68K_REG_A0 : M68K_REG_D0) + ((extension >> 12) & 7);
	}
}

static void d68000_movem_pd_16(void)
{
	build_movem_re(M68K_INS_MOVEM, 2);
}

static void d68000_movem_pd_32(void)
{
	build_movem_re(M68K_INS_MOVEM, 4);
}

static void d68000_movem_er_16(void)
{
	build_movem_er(M68K_INS_MOVEM, 2);
}

static void d68000_movem_er_32(void)
{
	build_movem_er(M68K_INS_MOVEM, 4);
}

static void d68000_movem_re_16(void)
{
	build_movem_re(M68K_INS_MOVEM, 2);
}

static void d68000_movem_re_32(void)
{
	build_movem_re(M68K_INS_MOVEM, 4);
}

static void d68000_movep_re_16(void)
{
	build_movep_re(2);
}

static void d68000_movep_re_32(void)
{
	build_movep_re(4);
}

static void d68000_movep_er_16(void)
{
	build_movep_er(2);
}

static void d68000_movep_er_32(void)
{
	build_movep_er(4);
}

static void d68010_moves_8(void)
{
	LIMIT_CPU_TYPES(M68010_PLUS);
	build_moves(1);
}

static void d68010_moves_16(void)
{
	//uint extension;
	LIMIT_CPU_TYPES(M68010_PLUS);
	build_moves(2);
}

static void d68010_moves_32(void)
{
	LIMIT_CPU_TYPES(M68010_PLUS);
	build_moves(4);
}

static void d68000_moveq(void)
{
	cs_m68k* info = build_init_op(M68K_INS_MOVEQ, 2, 0);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];
	
	op0->type = M68K_OP_IMM;
	op0->address_mode = M68K_AM_IMMIDIATE;
	op0->imm = (g_cpu_ir & 0xff);

	op1->address_mode = M68K_AM_REG_DIRECT_DATA;
	op1->reg = M68K_REG_D0 + ((g_cpu_ir >> 9) & 7);
}

static void d68040_move16_pi_pi(void)
{
	LIMIT_CPU_TYPES(M68040_PLUS);

	int data[] = { g_cpu_ir & 7, (read_imm_16() >> 12) & 7 };
	int modes[] = { M68K_AM_REGI_ADDR_POST_INC, M68K_AM_REGI_ADDR_POST_INC };

	build_move16(data, modes);
}

static void d68040_move16_pi_al(void)
{
	LIMIT_CPU_TYPES(M68040_PLUS);

	int data[] = { g_cpu_ir & 7, read_imm_32() };
	int modes[] = { M68K_AM_REGI_ADDR_POST_INC, M68K_AM_ABSOLUTE_DATA_LONG };

	build_move16(data, modes);
}

static void d68040_move16_al_pi(void)
{
	LIMIT_CPU_TYPES(M68040_PLUS);

	int data[] = { read_imm_32(), g_cpu_ir & 7 };
	int modes[] = { M68K_AM_ABSOLUTE_DATA_LONG, M68K_AM_REGI_ADDR_POST_INC };

	build_move16(data, modes);
}

static void d68040_move16_ai_al(void)
{
	LIMIT_CPU_TYPES(M68040_PLUS);

	int data[] = { g_cpu_ir & 7, read_imm_32() };
	int modes[] = { M68K_AM_REG_DIRECT_ADDR, M68K_AM_ABSOLUTE_DATA_LONG };

	build_move16(data, modes);
}

static void d68040_move16_al_ai(void)
{
	LIMIT_CPU_TYPES(M68040_PLUS);

	int data[] = { read_imm_32(), g_cpu_ir & 7 };
	int modes[] = { M68K_AM_ABSOLUTE_DATA_LONG, M68K_AM_REG_DIRECT_ADDR };

	build_move16(data, modes);
}

static void d68000_muls(void)
{
	build_er_1(M68K_INS_MULS, 2);
}

static void d68000_mulu(void)
{
	build_er_1(M68K_INS_MULU, 2);
}

static void d68020_mull(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);

	uint extension = read_imm_16();
	uint insn_signed = 0;
   
	if (BIT_B((extension)))
		insn_signed = 1;

	cs_m68k* info = build_init_op(insn_signed ? M68K_INS_MULS : M68K_INS_MULU, 2, 4);
	if (!info) {
		return;
	}

	cs_m68k_op* op0 = &info->operands[0];
	cs_m68k_op* op1 = &info->operands[1];

	get_ea_mode_op(op0, g_cpu_ir, 4);

	const uint reg_0 = extension & 7;
	const uint reg_1 = (extension >> 12) & 7;

	op1->address_mode = M68K_AM_NONE;
	op1->type = M68K_OP_REG_PAIR;
	op1->register_bits = (reg_0 << 4) | reg_1; 

	if (!BIT_A(extension)) {
		op1->type = M68K_OP_REG;
		op1->reg = M68K_REG_D0 + reg_1;
	}
}

static void d68000_nbcd(void)
{
	build_ea(M68K_INS_NBCD, 1);
}

static void d68000_neg_8(void)
{
	build_ea(M68K_INS_NEG, 1);
}

static void d68000_neg_16(void)
{
	build_ea(M68K_INS_NEG, 2);
}

static void d68000_neg_32(void)
{
	build_ea(M68K_INS_NEG, 4);
}

static void d68000_negx_8(void)
{
	build_ea(M68K_INS_NEGX, 1);
}

static void d68000_negx_16(void)
{
	build_ea(M68K_INS_NEGX, 2);
}

static void d68000_negx_32(void)
{
	build_ea(M68K_INS_NEGX, 4);
}

static void d68000_nop(void)
{
	MCInst_setOpcode(g_inst, M68K_INS_NOP);
}

static void d68000_not_8(void)
{
	build_ea(M68K_INS_NOT, 1);
}

static void d68000_not_16(void)
{
	build_ea(M68K_INS_NOT, 2);
}

static void d68000_not_32(void)
{
	build_ea(M68K_INS_NOT, 4);
}

static void d68000_or_er_8(void)
{
	build_er_1(M68K_INS_OR, 1);
}

static void d68000_or_er_16(void)
{
	build_er_1(M68K_INS_OR, 2);
}

static void d68000_or_er_32(void)
{
	build_er_1(M68K_INS_OR, 4);
}

static void d68000_or_re_8(void)
{
	build_re_1(M68K_INS_OR, 1); 
}

static void d68000_or_re_16(void)
{
	build_re_1(M68K_INS_OR, 2); 
}

static void d68000_or_re_32(void)
{
	build_re_1(M68K_INS_OR, 4); 
}

static void d68000_ori_8(void)
{
	build_imm_ea(M68K_INS_ORI, 1, read_imm_8());
}

static void d68000_ori_16(void)
{
	build_imm_ea(M68K_INS_ORI, 2, read_imm_16());
}

static void d68000_ori_32(void)
{
	build_imm_ea(M68K_INS_ORI, 4, read_imm_32());
}

static void d68000_ori_to_ccr(void)
{
	build_imm_special_reg(M68K_INS_ORI, read_imm_8(), 1, M68K_REG_CCR);
}

static void d68000_ori_to_sr(void)
{
	build_imm_special_reg(M68K_INS_ORI, read_imm_16(), 2, M68K_REG_SR);
}

static void d68020_pack_rr(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_rr(M68K_INS_PACK, 0, read_imm_16()); 
}

static void d68020_pack_mm(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_mm(M68K_INS_PACK, 0, read_imm_16()); 
}

static void d68000_pea(void)
{
	build_ea(M68K_INS_PEA, 4);
}

static void d68000_reset(void)
{
	MCInst_setOpcode(g_inst, M68K_INS_RESET);
}

static void d68000_ror_s_8(void)
{
	build_3bit_d(M68K_INS_ROR, 1);
}

static void d68000_ror_s_16(void)
{
	build_3bit_d(M68K_INS_ROR, 2);
}

static void d68000_ror_s_32(void)
{
	build_3bit_d(M68K_INS_ROR, 4);
}

static void d68000_ror_r_8(void)
{
	build_r(M68K_INS_ROR, 1);
}

static void d68000_ror_r_16(void)
{
	build_r(M68K_INS_ROR, 2);
}

static void d68000_ror_r_32(void)
{
	build_r(M68K_INS_ROR, 4);
}

static void d68000_ror_ea(void)
{
	build_ea(M68K_INS_ROR, 2);
}

static void d68000_rol_s_8(void)
{
	build_3bit_d(M68K_INS_ROL, 1);
}

static void d68000_rol_s_16(void)
{
	build_3bit_d(M68K_INS_ROL, 2);
}

static void d68000_rol_s_32(void)
{
	build_3bit_d(M68K_INS_ROL, 4);
}

static void d68000_rol_r_8(void)
{
	build_r(M68K_INS_ROL, 1);
}

static void d68000_rol_r_16(void)
{
	build_r(M68K_INS_ROL, 2);
}

static void d68000_rol_r_32(void)
{
	build_r(M68K_INS_ROL, 4);
}

static void d68000_rol_ea(void)
{
	build_ea(M68K_INS_ROL, 2);
}

static void d68000_roxr_s_8(void)
{
	build_3bit_d(M68K_INS_ROXR, 1);
}

static void d68000_roxr_s_16(void)
{
	build_3bit_d(M68K_INS_ROXR, 2);
}

static void d68000_roxr_s_32(void)
{
	build_3bit_d(M68K_INS_ROXR, 4);
}

static void d68000_roxr_r_8(void)
{
	build_3bit_d(M68K_INS_ROXR, 4);
}

static void d68000_roxr_r_16(void)
{
	build_r(M68K_INS_ROXR, 2);
}

static void d68000_roxr_r_32(void)
{
	build_r(M68K_INS_ROXR, 4);
}

static void d68000_roxr_ea(void)
{
	build_ea(M68K_INS_ROL, 2);
}

static void d68000_roxl_s_8(void)
{
	build_3bit_d(M68K_INS_ROXL, 1);
}

static void d68000_roxl_s_16(void)
{
	build_3bit_d(M68K_INS_ROXL, 2);
}

static void d68000_roxl_s_32(void)
{
	build_3bit_d(M68K_INS_ROXL, 4);
}

static void d68000_roxl_r_8(void)
{
	build_r(M68K_INS_ROXL, 1);
}

static void d68000_roxl_r_16(void)
{
	build_r(M68K_INS_ROXL, 2);
}

static void d68000_roxl_r_32(void)
{
	build_r(M68K_INS_ROXL, 4);
}

static void d68000_roxl_ea(void)
{
	build_ea(M68K_INS_ROXL, 2);
}

static void d68010_rtd(void)
{
	LIMIT_CPU_TYPES(M68010_PLUS);
	build_bxx(M68K_INS_RTD, 0, read_imm_16());
}

static void d68000_rte(void)
{
	MCInst_setOpcode(g_inst, M68K_INS_RTE);
}

static void d68020_rtm(void)
{
	LIMIT_CPU_TYPES(M68020_ONLY);

	build_bxx(M68K_INS_RTM, 0, 0); 

	cs_detail *detail = g_inst->flat_insn->detail;
	if (!detail)
	{
		return;
	}

	cs_m68k* info = &detail->m68k;
	cs_m68k_op* op = &info->operands[0];
	
	op->address_mode = M68K_AM_NONE;
	op->type = M68K_OP_REG;
	
	if (BIT_3(g_cpu_ir)) {
		op->reg = M68K_REG_A0 + (g_cpu_ir & 7);
	} else {
		op->reg = M68K_REG_D0 + (g_cpu_ir & 7);
	}
}

static void d68000_rtr(void)
{
	MCInst_setOpcode(g_inst, M68K_INS_RTR);
}

static void d68000_rts(void)
{
	MCInst_setOpcode(g_inst, M68K_INS_RTS);
}

static void d68000_sbcd_rr(void)
{
	build_rr(M68K_INS_SBCD, 1, 0); 
}

static void d68000_sbcd_mm(void)
{
	build_mm(M68K_INS_SBCD, 0, read_imm_16()); 
}

static void d68000_scc(void)
{
	cs_m68k* info = build_init_op(s_scc_lut[(g_cpu_ir >> 8) & 0xf], 1, 1);
	if (!info) {
		return;
	}
	get_ea_mode_op(&info->operands[0], g_cpu_ir, 1);
}

static void d68000_stop(void)
{
	build_bxx(M68K_INS_STOP, 0, read_imm_16()); 
}

static void d68000_sub_er_8(void)
{
	build_er_1(M68K_INS_SUB, 1);
}

static void d68000_sub_er_16(void)
{
	build_er_1(M68K_INS_SUB, 2);
}

static void d68000_sub_er_32(void)
{
	build_er_1(M68K_INS_SUB, 4);
}

static void d68000_sub_re_8(void)
{
	build_re_1(M68K_INS_SUB, 1);
}

static void d68000_sub_re_16(void)
{
	build_re_1(M68K_INS_SUB, 2);
}

static void d68000_sub_re_32(void)
{
	build_re_1(M68K_INS_SUB, 4);
}

static void d68000_suba_16(void)
{
	build_ea_a(M68K_INS_SUBA, 2);
}

static void d68000_suba_32(void)
{
	build_ea_a(M68K_INS_SUBA, 4);
}

static void d68000_subi_8(void)
{
	build_imm_ea(M68K_INS_SUBI, 1, read_imm_8());
}

static void d68000_subi_16(void)
{
	build_imm_ea(M68K_INS_SUBI, 2, read_imm_16());
}

static void d68000_subi_32(void)
{
	build_imm_ea(M68K_INS_SUBI, 4, read_imm_32());
}

static void d68000_subq_8(void)
{
	build_3bit_ea(M68K_INS_SUBQ, 1);
}

static void d68000_subq_16(void)
{
	build_3bit_ea(M68K_INS_SUBQ, 2);
}

static void d68000_subq_32(void)
{
	build_3bit_ea(M68K_INS_SUBQ, 4);
}

static void d68000_subx_rr_8(void)
{
	build_rr(M68K_INS_SUBX, 1, 0); 
}

static void d68000_subx_rr_16(void)
{
	build_rr(M68K_INS_SUBX, 2, 0); 
}

static void d68000_subx_rr_32(void)
{
	build_rr(M68K_INS_SUBX, 4, 0); 
}

static void d68000_subx_mm_8(void)
{
	build_mm(M68K_INS_SUBX, 1, 0); 
}

static void d68000_subx_mm_16(void)
{
	build_mm(M68K_INS_SUBX, 2, 0); 
}

static void d68000_subx_mm_32(void)
{
	build_mm(M68K_INS_SUBX, 4, 0); 
}

static void d68000_swap(void)
{
	build_d(M68K_INS_SWAP, 0);
}

static void d68000_tas(void)
{
	build_ea(M68K_INS_TAS, 1);
}

static void d68000_trap(void)
{
	build_bxx(M68K_INS_TRAP, 0, g_cpu_ir&0xf);
}

static void d68020_trapcc_0(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_trap(0, 0);

	cs_detail *detail = g_inst->flat_insn->detail;
	if (detail)
	{
		detail->m68k.op_count = 0;
	}
}

static void d68020_trapcc_16(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_trap(2, read_imm_16());
}

static void d68020_trapcc_32(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_trap(4, read_imm_32());
}

static void d68000_trapv(void)
{
	MCInst_setOpcode(g_inst, M68K_INS_TRAPV);
}

static void d68000_tst_8(void)
{
	build_ea(M68K_INS_TST, 1);
}

static void d68020_tst_pcdi_8(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_ea(M68K_INS_TST, 1);
}

static void d68020_tst_pcix_8(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_ea(M68K_INS_TST, 1);
}

static void d68020_tst_i_8(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_ea(M68K_INS_TST, 1);
}

static void d68000_tst_16(void)
{
	build_ea(M68K_INS_TST, 2);
}

static void d68020_tst_a_16(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_ea(M68K_INS_TST, 2);
}

static void d68020_tst_pcdi_16(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_ea(M68K_INS_TST, 2);
}

static void d68020_tst_pcix_16(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_ea(M68K_INS_TST, 2);
}

static void d68020_tst_i_16(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_ea(M68K_INS_TST, 2);
}

static void d68000_tst_32(void)
{
	build_ea(M68K_INS_TST, 4);
}

static void d68020_tst_a_32(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_ea(M68K_INS_TST, 4);
}

static void d68020_tst_pcdi_32(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_ea(M68K_INS_TST, 4);
}

static void d68020_tst_pcix_32(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_ea(M68K_INS_TST, 4);
}

static void d68020_tst_i_32(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_ea(M68K_INS_TST, 4);
}

static void d68000_unlk(void)
{
	cs_m68k* info = build_init_op(M68K_INS_UNLK, 1, 0);
	if (!info) {
		return;
	}

	cs_m68k_op* op = &info->operands[0];

	op->address_mode = M68K_AM_REG_DIRECT_ADDR;
	op->reg = M68K_REG_A0 + (g_cpu_ir & 7);
}

static void d68020_unpk_rr(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_rr(M68K_INS_UNPK, 0, read_imm_16()); 
}

static void d68020_unpk_mm(void)
{
	LIMIT_CPU_TYPES(M68020_PLUS);
	build_mm(M68K_INS_UNPK, 0, read_imm_16()); 
}

/* ======================================================================== */
/* ======================= INSTRUCTION TABLE BUILDER ====================== */
/* ======================================================================== */

/* EA Masks:
800 = data register direct
400 = address register direct
200 = address register indirect
100 = ARI postincrement
 80 = ARI pre-decrement
 40 = ARI displacement
 20 = ARI index
 10 = absolute short
  8 = absolute long
  4 = immediate / sr
  2 = pc displacement
  1 = pc idx
*/

static opcode_struct g_opcode_info[] =
{
/*  opcode handler         mask    match   ea_mask   mask2   match2*/
	{d68000_1010         , 0xf000, 0xa000, 0x000},
	{d68000_1111         , 0xf000, 0xf000, 0x000},
	{d68000_abcd_rr      , 0xf1f8, 0xc100, 0x000},
	{d68000_abcd_mm      , 0xf1f8, 0xc108, 0x000},
	{d68000_add_er_8     , 0xf1c0, 0xd000, 0xbff},
	{d68000_add_er_16    , 0xf1c0, 0xd040, 0xfff},
	{d68000_add_er_32    , 0xf1c0, 0xd080, 0xfff},
	{d68000_add_re_8     , 0xf1c0, 0xd100, 0x3f8},
	{d68000_add_re_16    , 0xf1c0, 0xd140, 0x3f8},
	{d68000_add_re_32    , 0xf1c0, 0xd180, 0x3f8},
	{d68000_adda_16      , 0xf1c0, 0xd0c0, 0xfff},
	{d68000_adda_32      , 0xf1c0, 0xd1c0, 0xfff},
	{d68000_addi_8       , 0xffc0, 0x0600, 0xbf8},
	{d68000_addi_16      , 0xffc0, 0x0640, 0xbf8},
	{d68000_addi_32      , 0xffc0, 0x0680, 0xbf8},
	{d68000_addq_8       , 0xf1c0, 0x5000, 0xbf8},
	{d68000_addq_16      , 0xf1c0, 0x5040, 0xff8},
	{d68000_addq_32      , 0xf1c0, 0x5080, 0xff8},
	{d68000_addx_rr_8    , 0xf1f8, 0xd100, 0x000},
	{d68000_addx_rr_16   , 0xf1f8, 0xd140, 0x000},
	{d68000_addx_rr_32   , 0xf1f8, 0xd180, 0x000},
	{d68000_addx_mm_8    , 0xf1f8, 0xd108, 0x000},
	{d68000_addx_mm_16   , 0xf1f8, 0xd148, 0x000},
	{d68000_addx_mm_32   , 0xf1f8, 0xd188, 0x000},
	{d68000_and_er_8     , 0xf1c0, 0xc000, 0xbff},
	{d68000_and_er_16    , 0xf1c0, 0xc040, 0xbff},
	{d68000_and_er_32    , 0xf1c0, 0xc080, 0xbff},
	{d68000_and_re_8     , 0xf1c0, 0xc100, 0x3f8},
	{d68000_and_re_16    , 0xf1c0, 0xc140, 0x3f8},
	{d68000_and_re_32    , 0xf1c0, 0xc180, 0x3f8},
	{d68000_andi_to_ccr  , 0xffff, 0x023c, 0x000, 0xff00, 0x0000},
	{d68000_andi_to_sr   , 0xffff, 0x027c, 0x000},
	{d68000_andi_8       , 0xffc0, 0x0200, 0xbf8},
	{d68000_andi_16      , 0xffc0, 0x0240, 0xbf8},
	{d68000_andi_32      , 0xffc0, 0x0280, 0xbf8},
	{d68000_asr_s_8      , 0xf1f8, 0xe000, 0x000},
	{d68000_asr_s_16     , 0xf1f8, 0xe040, 0x000},
	{d68000_asr_s_32     , 0xf1f8, 0xe080, 0x000},
	{d68000_asr_r_8      , 0xf1f8, 0xe020, 0x000},
	{d68000_asr_r_16     , 0xf1f8, 0xe060, 0x000},
	{d68000_asr_r_32     , 0xf1f8, 0xe0a0, 0x000},
	{d68000_asr_ea       , 0xffc0, 0xe0c0, 0x3f8},
	{d68000_asl_s_8      , 0xf1f8, 0xe100, 0x000},
	{d68000_asl_s_16     , 0xf1f8, 0xe140, 0x000},
	{d68000_asl_s_32     , 0xf1f8, 0xe180, 0x000},
	{d68000_asl_r_8      , 0xf1f8, 0xe120, 0x000},
	{d68000_asl_r_16     , 0xf1f8, 0xe160, 0x000},
	{d68000_asl_r_32     , 0xf1f8, 0xe1a0, 0x000},
	{d68000_asl_ea       , 0xffc0, 0xe1c0, 0x3f8},
	{d68000_bcc_8        , 0xf000, 0x6000, 0x000},
	{d68000_bcc_16       , 0xf0ff, 0x6000, 0x000},
	{d68020_bcc_32       , 0xf0ff, 0x60ff, 0x000},
	{d68000_bchg_r       , 0xf1c0, 0x0140, 0xbf8},
	{d68000_bchg_s       , 0xffc0, 0x0840, 0xbf8, 0xff00, 0x0000},
	{d68000_bclr_r       , 0xf1c0, 0x0180, 0xbf8},
	{d68000_bclr_s       , 0xffc0, 0x0880, 0xbf8, 0xff00, 0x0000},
	{d68020_bfchg        , 0xffc0, 0xeac0, 0xa78, 0xf000, 0x0000},
	{d68020_bfclr        , 0xffc0, 0xecc0, 0xa78, 0xf000, 0x0000},
	{d68020_bfexts       , 0xffc0, 0xebc0, 0xa7b, 0x8000, 0x0000},
	{d68020_bfextu       , 0xffc0, 0xe9c0, 0xa7b, 0x8000, 0x0000},
	{d68020_bfffo        , 0xffc0, 0xedc0, 0xa7b, 0x8000, 0x0000},
	{d68020_bfins        , 0xffc0, 0xefc0, 0xa78, 0x8000, 0x0000},
	{d68020_bfset        , 0xffc0, 0xeec0, 0xa78, 0xf000, 0x0000},
	{d68020_bftst        , 0xffc0, 0xe8c0, 0xa7b, 0xf000, 0x0000},
	{d68010_bkpt         , 0xfff8, 0x4848, 0x000},
	{d68000_bra_8        , 0xff00, 0x6000, 0x000},
	{d68000_bra_16       , 0xffff, 0x6000, 0x000},
	{d68020_bra_32       , 0xffff, 0x60ff, 0x000},
	{d68000_bset_r       , 0xf1c0, 0x01c0, 0xbf8},
	{d68000_bset_s       , 0xffc0, 0x08c0, 0xbf8, 0xfe00, 0x0000 },
	{d68000_bsr_8        , 0xff00, 0x6100, 0x000},
	{d68000_bsr_16       , 0xffff, 0x6100, 0x000},
	{d68020_bsr_32       , 0xffff, 0x61ff, 0x000},
	{d68000_btst_r       , 0xf1c0, 0x0100, 0xbff},
	{d68000_btst_s       , 0xffc0, 0x0800, 0xbfb, 0xff00, 0x0000},
	{d68020_callm        , 0xffc0, 0x06c0, 0x27b, 0xff00, 0x0000},
	{d68020_cas_8        , 0xffc0, 0x0ac0, 0x3f8, 0xfe38, 0x0000},
	{d68020_cas_16       , 0xffc0, 0x0cc0, 0x3f8, 0xfe38, 0x0000},
	{d68020_cas_32       , 0xffc0, 0x0ec0, 0x3f8, 0xfe38, 0x0000},
	{d68020_cas2_16      , 0xffff, 0x0cfc, 0x000, 0x0e38, 0x0000/*, 0x0e38, 0x0000 */},
	{d68020_cas2_32      , 0xffff, 0x0efc, 0x000, 0x0e38, 0x0000/*, 0x0e38, 0x0000 */},
	{d68000_chk_16       , 0xf1c0, 0x4180, 0xbff},
	{d68020_chk_32       , 0xf1c0, 0x4100, 0xbff},
	{d68020_chk2_cmp2_8  , 0xffc0, 0x00c0, 0x27b, 0x07ff, 0x0000},
	{d68020_chk2_cmp2_16 , 0xffc0, 0x02c0, 0x27b, 0x07ff, 0x0000},
	{d68020_chk2_cmp2_32 , 0xffc0, 0x04c0, 0x27b, 0x07ff, 0x0000},
	{d68040_cinv         , 0xff20, 0xf400, 0x000},
	{d68000_clr_8        , 0xffc0, 0x4200, 0xbf8},
	{d68000_clr_16       , 0xffc0, 0x4240, 0xbf8},
	{d68000_clr_32       , 0xffc0, 0x4280, 0xbf8},
	{d68000_cmp_8        , 0xf1c0, 0xb000, 0xbff},
	{d68000_cmp_16       , 0xf1c0, 0xb040, 0xfff},
	{d68000_cmp_32       , 0xf1c0, 0xb080, 0xfff},
	{d68000_cmpa_16      , 0xf1c0, 0xb0c0, 0xfff},
	{d68000_cmpa_32      , 0xf1c0, 0xb1c0, 0xfff},
	{d68000_cmpi_8       , 0xffc0, 0x0c00, 0xbf8},
	{d68020_cmpi_pcdi_8  , 0xffff, 0x0c3a, 0x000},
	{d68020_cmpi_pcix_8  , 0xffff, 0x0c3b, 0x000},
	{d68000_cmpi_16      , 0xffc0, 0x0c40, 0xbf8},
	{d68020_cmpi_pcdi_16 , 0xffff, 0x0c7a, 0x000},
	{d68020_cmpi_pcix_16 , 0xffff, 0x0c7b, 0x000},
	{d68000_cmpi_32      , 0xffc0, 0x0c80, 0xbf8},
	{d68020_cmpi_pcdi_32 , 0xffff, 0x0cba, 0x000},
	{d68020_cmpi_pcix_32 , 0xffff, 0x0cbb, 0x000},
	{d68000_cmpm_8       , 0xf1f8, 0xb108, 0x000},
	{d68000_cmpm_16      , 0xf1f8, 0xb148, 0x000},
	{d68000_cmpm_32      , 0xf1f8, 0xb188, 0x000},
	{d68020_cpbcc_16     , 0xf1c0, 0xf080, 0x000},
	{d68020_cpbcc_32     , 0xf1c0, 0xf0c0, 0x000},
	{d68020_cpdbcc       , 0xf1f8, 0xf048, 0x000},
	{d68020_cpgen        , 0xf1c0, 0xf000, 0x000},
	{d68020_cprestore    , 0xf1c0, 0xf140, 0x37f},
	{d68020_cpsave       , 0xf1c0, 0xf100, 0x2f8},
	{d68020_cpscc        , 0xf1c0, 0xf040, 0xbf8},
	{d68020_cptrapcc_0   , 0xf1ff, 0xf07c, 0x000},
	{d68020_cptrapcc_16  , 0xf1ff, 0xf07a, 0x000},
	{d68020_cptrapcc_32  , 0xf1ff, 0xf07b, 0x000},
	{d68040_cpush        , 0xff20, 0xf420, 0x000},
	{d68000_dbcc         , 0xf0f8, 0x50c8, 0x000},
	{d68000_dbra         , 0xfff8, 0x51c8, 0x000},
	{d68000_divs         , 0xf1c0, 0x81c0, 0xbff},
	{d68000_divu         , 0xf1c0, 0x80c0, 0xbff},
	{d68020_divl         , 0xff80, 0x4c00, 0xbff, 0x83f8, 0x0000},
	{d68000_eor_8        , 0xf1c0, 0xb100, 0xbf8},
	{d68000_eor_16       , 0xf1c0, 0xb140, 0xbf8},
	{d68000_eor_32       , 0xf1c0, 0xb180, 0xbf8},
	{d68000_eori_to_ccr  , 0xffff, 0x0a3c, 0x000, 0xff00, 0x0000},
	{d68000_eori_to_sr   , 0xffff, 0x0a7c, 0x000},
	{d68000_eori_8       , 0xffc0, 0x0a00, 0xbf8},
	{d68000_eori_16      , 0xffc0, 0x0a40, 0xbf8},
	{d68000_eori_32      , 0xffc0, 0x0a80, 0xbf8},
	{d68000_exg_dd       , 0xf1f8, 0xc140, 0x000},
	{d68000_exg_aa       , 0xf1f8, 0xc148, 0x000},
	{d68000_exg_da       , 0xf1f8, 0xc188, 0x000},
	{d68020_extb_32      , 0xfff8, 0x49c0, 0x000},
	{d68000_ext_16       , 0xfff8, 0x4880, 0x000},
	{d68000_ext_32       , 0xfff8, 0x48c0, 0x000},
	{d68000_illegal      , 0xffff, 0x4afc, 0x000},
	{d68000_jmp          , 0xffc0, 0x4ec0, 0x27b},
	{d68000_jsr          , 0xffc0, 0x4e80, 0x27b},
	{d68000_lea          , 0xf1c0, 0x41c0, 0x27b},
	{d68000_link_16      , 0xfff8, 0x4e50, 0x000},
	{d68020_link_32      , 0xfff8, 0x4808, 0x000},
	{d68000_lsr_s_8      , 0xf1f8, 0xe008, 0x000},
	{d68000_lsr_s_16     , 0xf1f8, 0xe048, 0x000},
	{d68000_lsr_s_32     , 0xf1f8, 0xe088, 0x000},
	{d68000_lsr_r_8      , 0xf1f8, 0xe028, 0x000},
	{d68000_lsr_r_16     , 0xf1f8, 0xe068, 0x000},
	{d68000_lsr_r_32     , 0xf1f8, 0xe0a8, 0x000},
	{d68000_lsr_ea       , 0xffc0, 0xe2c0, 0x3f8},
	{d68000_lsl_s_8      , 0xf1f8, 0xe108, 0x000},
	{d68000_lsl_s_16     , 0xf1f8, 0xe148, 0x000},
	{d68000_lsl_s_32     , 0xf1f8, 0xe188, 0x000},
	{d68000_lsl_r_8      , 0xf1f8, 0xe128, 0x000},
	{d68000_lsl_r_16     , 0xf1f8, 0xe168, 0x000},
	{d68000_lsl_r_32     , 0xf1f8, 0xe1a8, 0x000},
	{d68000_lsl_ea       , 0xffc0, 0xe3c0, 0x3f8},
	{d68000_move_8       , 0xf000, 0x1000, 0xbff},
	{d68000_move_16      , 0xf000, 0x3000, 0xfff},
	{d68000_move_32      , 0xf000, 0x2000, 0xfff},
	{d68000_movea_16     , 0xf1c0, 0x3040, 0xfff},
	{d68000_movea_32     , 0xf1c0, 0x2040, 0xfff},
	{d68000_move_to_ccr  , 0xffc0, 0x44c0, 0xbff},
	{d68010_move_fr_ccr  , 0xffc0, 0x42c0, 0xbf8},
	{d68000_move_to_sr   , 0xffc0, 0x46c0, 0xbff},
	{d68000_move_fr_sr   , 0xffc0, 0x40c0, 0xbf8},
	{d68000_move_to_usp  , 0xfff8, 0x4e60, 0x000},
	{d68000_move_fr_usp  , 0xfff8, 0x4e68, 0x000},
	{d68010_movec        , 0xfffe, 0x4e7a, 0x000},
	{d68000_movem_pd_16  , 0xfff8, 0x48a0, 0x000},
	{d68000_movem_pd_32  , 0xfff8, 0x48e0, 0x000},
	{d68000_movem_re_16  , 0xffc0, 0x4880, 0x2f8},
	{d68000_movem_re_32  , 0xffc0, 0x48c0, 0x2f8},
	{d68000_movem_er_16  , 0xffc0, 0x4c80, 0x37b},
	{d68000_movem_er_32  , 0xffc0, 0x4cc0, 0x37b},
	{d68000_movep_er_16  , 0xf1f8, 0x0108, 0x000},
	{d68000_movep_er_32  , 0xf1f8, 0x0148, 0x000},
	{d68000_movep_re_16  , 0xf1f8, 0x0188, 0x000},
	{d68000_movep_re_32  , 0xf1f8, 0x01c8, 0x000},
	{d68010_moves_8      , 0xffc0, 0x0e00, 0x3f8, 0x07ff, 0x0000},
	{d68010_moves_16     , 0xffc0, 0x0e40, 0x3f8, 0x07ff, 0x0000},
	{d68010_moves_32     , 0xffc0, 0x0e80, 0x3f8, 0x07ff, 0x0000},
	{d68000_moveq        , 0xf100, 0x7000, 0x000},
	{d68040_move16_pi_pi , 0xfff8, 0xf620, 0x000, 0x8fff, 0x8000},
	{d68040_move16_pi_al , 0xfff8, 0xf600, 0x000},
	{d68040_move16_al_pi , 0xfff8, 0xf608, 0x000},
	{d68040_move16_ai_al , 0xfff8, 0xf610, 0x000},
	{d68040_move16_al_ai , 0xfff8, 0xf618, 0x000},
	{d68000_muls         , 0xf1c0, 0xc1c0, 0xbff},
	{d68000_mulu         , 0xf1c0, 0xc0c0, 0xbff},
	{d68020_mull         , 0xffc0, 0x4c00, 0xbff, 0x83f8, 0x0000},
	{d68000_nbcd         , 0xffc0, 0x4800, 0xbf8},
	{d68000_neg_8        , 0xffc0, 0x4400, 0xbf8},
	{d68000_neg_16       , 0xffc0, 0x4440, 0xbf8},
	{d68000_neg_32       , 0xffc0, 0x4480, 0xbf8},
	{d68000_negx_8       , 0xffc0, 0x4000, 0xbf8},
	{d68000_negx_16      , 0xffc0, 0x4040, 0xbf8},
	{d68000_negx_32      , 0xffc0, 0x4080, 0xbf8},
	{d68000_nop          , 0xffff, 0x4e71, 0x000},
	{d68000_not_8        , 0xffc0, 0x4600, 0xbf8},
	{d68000_not_16       , 0xffc0, 0x4640, 0xbf8},
	{d68000_not_32       , 0xffc0, 0x4680, 0xbf8},
	{d68000_or_er_8      , 0xf1c0, 0x8000, 0xbff},
	{d68000_or_er_16     , 0xf1c0, 0x8040, 0xbff},
	{d68000_or_er_32     , 0xf1c0, 0x8080, 0xbff},
	{d68000_or_re_8      , 0xf1c0, 0x8100, 0x3f8},
	{d68000_or_re_16     , 0xf1c0, 0x8140, 0x3f8},
	{d68000_or_re_32     , 0xf1c0, 0x8180, 0x3f8},
	{d68000_ori_to_ccr   , 0xffff, 0x003c, 0x000, 0xff00, 0x0000},
	{d68000_ori_to_sr    , 0xffff, 0x007c, 0x000},
	{d68000_ori_8        , 0xffc0, 0x0000, 0xbf8},
	{d68000_ori_16       , 0xffc0, 0x0040, 0xbf8},
	{d68000_ori_32       , 0xffc0, 0x0080, 0xbf8},
	{d68020_pack_rr      , 0xf1f8, 0x8140, 0x000},
	{d68020_pack_mm      , 0xf1f8, 0x8148, 0x000},
	{d68000_pea          , 0xffc0, 0x4840, 0x27b},
	{d68000_reset        , 0xffff, 0x4e70, 0x000},
	{d68000_ror_s_8      , 0xf1f8, 0xe018, 0x000},
	{d68000_ror_s_16     , 0xf1f8, 0xe058, 0x000},
	{d68000_ror_s_32     , 0xf1f8, 0xe098, 0x000},
	{d68000_ror_r_8      , 0xf1f8, 0xe038, 0x000},
	{d68000_ror_r_16     , 0xf1f8, 0xe078, 0x000},
	{d68000_ror_r_32     , 0xf1f8, 0xe0b8, 0x000},
	{d68000_ror_ea       , 0xffc0, 0xe6c0, 0x3f8},
	{d68000_rol_s_8      , 0xf1f8, 0xe118, 0x000},
	{d68000_rol_s_16     , 0xf1f8, 0xe158, 0x000},
	{d68000_rol_s_32     , 0xf1f8, 0xe198, 0x000},
	{d68000_rol_r_8      , 0xf1f8, 0xe138, 0x000},
	{d68000_rol_r_16     , 0xf1f8, 0xe178, 0x000},
	{d68000_rol_r_32     , 0xf1f8, 0xe1b8, 0x000},
	{d68000_rol_ea       , 0xffc0, 0xe7c0, 0x3f8},
	{d68000_roxr_s_8     , 0xf1f8, 0xe010, 0x000},
	{d68000_roxr_s_16    , 0xf1f8, 0xe050, 0x000},
	{d68000_roxr_s_32    , 0xf1f8, 0xe090, 0x000},
	{d68000_roxr_r_8     , 0xf1f8, 0xe030, 0x000},
	{d68000_roxr_r_16    , 0xf1f8, 0xe070, 0x000},
	{d68000_roxr_r_32    , 0xf1f8, 0xe0b0, 0x000},
	{d68000_roxr_ea      , 0xffc0, 0xe4c0, 0x3f8},
	{d68000_roxl_s_8     , 0xf1f8, 0xe110, 0x000},
	{d68000_roxl_s_16    , 0xf1f8, 0xe150, 0x000},
	{d68000_roxl_s_32    , 0xf1f8, 0xe190, 0x000},
	{d68000_roxl_r_8     , 0xf1f8, 0xe130, 0x000},
	{d68000_roxl_r_16    , 0xf1f8, 0xe170, 0x000},
	{d68000_roxl_r_32    , 0xf1f8, 0xe1b0, 0x000},
	{d68000_roxl_ea      , 0xffc0, 0xe5c0, 0x3f8},
	{d68010_rtd          , 0xffff, 0x4e74, 0x000},
	{d68000_rte          , 0xffff, 0x4e73, 0x000},
	{d68020_rtm          , 0xfff0, 0x06c0, 0x000},
	{d68000_rtr          , 0xffff, 0x4e77, 0x000},
	{d68000_rts          , 0xffff, 0x4e75, 0x000},
	{d68000_sbcd_rr      , 0xf1f8, 0x8100, 0x000},
	{d68000_sbcd_mm      , 0xf1f8, 0x8108, 0x000},
	{d68000_scc          , 0xf0c0, 0x50c0, 0xbf8},
	{d68000_stop         , 0xffff, 0x4e72, 0x000},
	{d68000_sub_er_8     , 0xf1c0, 0x9000, 0xbff},
	{d68000_sub_er_16    , 0xf1c0, 0x9040, 0xfff},
	{d68000_sub_er_32    , 0xf1c0, 0x9080, 0xfff},
	{d68000_sub_re_8     , 0xf1c0, 0x9100, 0x3f8},
	{d68000_sub_re_16    , 0xf1c0, 0x9140, 0x3f8},
	{d68000_sub_re_32    , 0xf1c0, 0x9180, 0x3f8},
	{d68000_suba_16      , 0xf1c0, 0x90c0, 0xfff},
	{d68000_suba_32      , 0xf1c0, 0x91c0, 0xfff},
	{d68000_subi_8       , 0xffc0, 0x0400, 0xbf8},
	{d68000_subi_16      , 0xffc0, 0x0440, 0xbf8},
	{d68000_subi_32      , 0xffc0, 0x0480, 0xbf8},
	{d68000_subq_8       , 0xf1c0, 0x5100, 0xbf8},
	{d68000_subq_16      , 0xf1c0, 0x5140, 0xff8},
	{d68000_subq_32      , 0xf1c0, 0x5180, 0xff8},
	{d68000_subx_rr_8    , 0xf1f8, 0x9100, 0x000},
	{d68000_subx_rr_16   , 0xf1f8, 0x9140, 0x000},
	{d68000_subx_rr_32   , 0xf1f8, 0x9180, 0x000},
	{d68000_subx_mm_8    , 0xf1f8, 0x9108, 0x000},
	{d68000_subx_mm_16   , 0xf1f8, 0x9148, 0x000},
	{d68000_subx_mm_32   , 0xf1f8, 0x9188, 0x000},
	{d68000_swap         , 0xfff8, 0x4840, 0x000},
	{d68000_tas          , 0xffc0, 0x4ac0, 0xbf8},
	{d68000_trap         , 0xfff0, 0x4e40, 0x000},
	{d68020_trapcc_0     , 0xf0ff, 0x50fc, 0x000},
	{d68020_trapcc_16    , 0xf0ff, 0x50fa, 0x000},
	{d68020_trapcc_32    , 0xf0ff, 0x50fb, 0x000},
	{d68000_trapv        , 0xffff, 0x4e76, 0x000},
	{d68000_tst_8        , 0xffc0, 0x4a00, 0xbf8},
	{d68020_tst_pcdi_8   , 0xffff, 0x4a3a, 0x000},
	{d68020_tst_pcix_8   , 0xffff, 0x4a3b, 0x000},
	{d68020_tst_i_8      , 0xffff, 0x4a3c, 0x000},
	{d68000_tst_16       , 0xffc0, 0x4a40, 0xbf8},
	{d68020_tst_a_16     , 0xfff8, 0x4a48, 0x000},
	{d68020_tst_pcdi_16  , 0xffff, 0x4a7a, 0x000},
	{d68020_tst_pcix_16  , 0xffff, 0x4a7b, 0x000},
	{d68020_tst_i_16     , 0xffff, 0x4a7c, 0x000},
	{d68000_tst_32       , 0xffc0, 0x4a80, 0xbf8},
	{d68020_tst_a_32     , 0xfff8, 0x4a88, 0x000},
	{d68020_tst_pcdi_32  , 0xffff, 0x4aba, 0x000},
	{d68020_tst_pcix_32  , 0xffff, 0x4abb, 0x000},
	{d68020_tst_i_32     , 0xffff, 0x4abc, 0x000},
	{d68000_unlk         , 0xfff8, 0x4e58, 0x000},
	{d68020_unpk_rr      , 0xf1f8, 0x8180, 0x000},
	{d68020_unpk_mm      , 0xf1f8, 0x8188, 0x000},
	{0, 0, 0, 0}
};

/* Check if opcode is using a valid ea mode */
static int valid_ea(uint opcode, uint mask)
{
	if(mask == 0)
		return 1;

	switch(opcode & 0x3f)
	{
		case 0x00: case 0x01: case 0x02: case 0x03:
		case 0x04: case 0x05: case 0x06: case 0x07:
			return (mask & 0x800) != 0;
		case 0x08: case 0x09: case 0x0a: case 0x0b:
		case 0x0c: case 0x0d: case 0x0e: case 0x0f:
			return (mask & 0x400) != 0;
		case 0x10: case 0x11: case 0x12: case 0x13:
		case 0x14: case 0x15: case 0x16: case 0x17:
			return (mask & 0x200) != 0;
		case 0x18: case 0x19: case 0x1a: case 0x1b:
		case 0x1c: case 0x1d: case 0x1e: case 0x1f:
			return (mask & 0x100) != 0;
		case 0x20: case 0x21: case 0x22: case 0x23:
		case 0x24: case 0x25: case 0x26: case 0x27:
			return (mask & 0x080) != 0;
		case 0x28: case 0x29: case 0x2a: case 0x2b:
		case 0x2c: case 0x2d: case 0x2e: case 0x2f:
			return (mask & 0x040) != 0;
		case 0x30: case 0x31: case 0x32: case 0x33:
		case 0x34: case 0x35: case 0x36: case 0x37:
			return (mask & 0x020) != 0;
		case 0x38:
			return (mask & 0x010) != 0;
		case 0x39:
			return (mask & 0x008) != 0;
		case 0x3a:
			return (mask & 0x002) != 0;
		case 0x3b:
			return (mask & 0x001) != 0;
		case 0x3c:
			return (mask & 0x004) != 0;
	}
	return 0;

}

/* Used by qsort */
static int DECL_SPEC compare_nof_true_bits(const void *aptr, const void *bptr)
{
	uint a = ((const opcode_struct*)aptr)->mask;
	uint b = ((const opcode_struct*)bptr)->mask;

	a = ((a & 0xAAAA) >> 1) + (a & 0x5555);
	a = ((a & 0xCCCC) >> 2) + (a & 0x3333);
	a = ((a & 0xF0F0) >> 4) + (a & 0x0F0F);
	a = ((a & 0xFF00) >> 8) + (a & 0x00FF);

	b = ((b & 0xAAAA) >> 1) + (b & 0x5555);
	b = ((b & 0xCCCC) >> 2) + (b & 0x3333);
	b = ((b & 0xF0F0) >> 4) + (b & 0x0F0F);
	b = ((b & 0xFF00) >> 8) + (b & 0x00FF);

	return b - a; /* reversed to get greatest to least sorting */
}

/* build the opcode handler jump table */
static void build_opcode_table(void)
{
	uint i;
	uint opcode;
	opcode_struct* ostruct;
	uint opcode_info_length = 0;

	for(ostruct = g_opcode_info;ostruct->opcode_handler != 0;ostruct++)
		opcode_info_length++;

	qsort((void *)g_opcode_info, opcode_info_length, sizeof(g_opcode_info[0]), compare_nof_true_bits);

	for(i=0;i<0x10000;i++)
	{
		g_instruction_table[i].instruction = d68000_invalid; /* default to invalid, undecoded opcode */
		opcode = i;
		/* search through opcode info for a match */
		for(ostruct = g_opcode_info;ostruct->opcode_handler != 0;ostruct++)
		{
			/* match opcode mask and allowed ea modes */
			if((opcode & ostruct->mask) == ostruct->match)
			{
				/* Handle destination ea for move instructions */
				if((ostruct->opcode_handler == d68000_move_8 ||
					 ostruct->opcode_handler == d68000_move_16 ||
					 ostruct->opcode_handler == d68000_move_32) &&
					 !valid_ea(((opcode>>9)&7) | ((opcode>>3)&0x38), 0xbf8))
						continue;
				if(valid_ea(opcode, ostruct->ea_mask))
				{
					g_instruction_table[i].instruction = ostruct->opcode_handler;
					g_instruction_table[i].word2_mask = ostruct->mask2;
					g_instruction_table[i].word2_match = ostruct->match2;
					break;
				}
			}
		}
	}
}

static int instruction_is_valid(const unsigned int instruction, const unsigned int word_check) {
	instruction_struct *i = &g_instruction_table[instruction];
	if (i->word2_mask && ((word_check & i->word2_mask) != i->word2_match)) {
		d68000_invalid();
		return 0;
	}
        return 1;
}

/* ======================================================================== */
/* ================================= API ================================== */
/* ======================================================================== */

/* Disasemble one instruction at pc and store in str_buff */
unsigned int m68k_disassemble(MCInst* inst, unsigned int pc, unsigned int cpu_type)
{
	g_inst = inst;

	inst->Opcode = 0;

	cs_detail *detail = g_inst->flat_insn->detail;
	if (detail)
	{
		cs_m68k* info = &detail->m68k;
		int i;

		memset(info, 0, sizeof(cs_m68k));
		info->op_size.type = M68K_SIZE_TYPE_CPU;

		for (i = 0; i < M68K_OPERAND_COUNT; ++i)
			info->operands[i].type = M68K_OP_REG; 
	}

	if(!g_initialized)
	{
		build_opcode_table();
		g_initialized = 1;
	}
	switch(cpu_type)
	{
		case M68K_CPU_TYPE_68000:
			g_cpu_type = TYPE_68000;
			g_address_mask = 0x00ffffff;
			break;
		case M68K_CPU_TYPE_68010:
			g_cpu_type = TYPE_68010;
			g_address_mask = 0x00ffffff;
			break;
		case M68K_CPU_TYPE_68EC020:
			g_cpu_type = TYPE_68020;
			g_address_mask = 0x00ffffff;
			break;
		case M68K_CPU_TYPE_68020:
			g_cpu_type = TYPE_68020;
			g_address_mask = 0xffffffff;
			break;
		case M68K_CPU_TYPE_68030:
			g_cpu_type = TYPE_68030;
			g_address_mask = 0xffffffff;
			break;
		case M68K_CPU_TYPE_68040:
			g_cpu_type = TYPE_68040;
			g_address_mask = 0xffffffff;
			break;
		default:
			return 0;
	}

	g_cpu_pc = pc;
	g_helper_str[0] = 0;
	g_cpu_ir = read_imm_16();
	if (instruction_is_valid(g_cpu_ir, peek_imm_16())) {
		g_instruction_table[g_cpu_ir].instruction();
	}
	return g_cpu_pc - pc;
}

#if 0

// Currently not used

/* Check if the instruction is a valid one */
unsigned int m68k_is_valid_instruction(unsigned int instruction, unsigned int cpu_type)
{
	if(!g_initialized)
	{
		build_opcode_table();
		g_initialized = 1;
	}

	instruction &= 0xffff;
	if(g_instruction_table[instruction] == d68000_invalid)
		return 0;

	switch(cpu_type)
	{
		case M68K_CPU_TYPE_68000:
			if(g_instruction_table[instruction] == d68010_bkpt)
				return 0;
			if(g_instruction_table[instruction] == d68010_move_fr_ccr)
				return 0;
			if(g_instruction_table[instruction] == d68010_movec)
				return 0;
			if(g_instruction_table[instruction] == d68010_moves_8)
				return 0;
			if(g_instruction_table[instruction] == d68010_moves_16)
				return 0;
			if(g_instruction_table[instruction] == d68010_moves_32)
				return 0;
			if(g_instruction_table[instruction] == d68010_rtd)
				return 0;
		case M68K_CPU_TYPE_68010:
			if(g_instruction_table[instruction] == d68020_bcc_32)
				return 0;
			if(g_instruction_table[instruction] == d68020_bfchg)
				return 0;
			if(g_instruction_table[instruction] == d68020_bfclr)
				return 0;
			if(g_instruction_table[instruction] == d68020_bfexts)
				return 0;
			if(g_instruction_table[instruction] == d68020_bfextu)
				return 0;
			if(g_instruction_table[instruction] == d68020_bfffo)
				return 0;
			if(g_instruction_table[instruction] == d68020_bfins)
				return 0;
			if(g_instruction_table[instruction] == d68020_bfset)
				return 0;
			if(g_instruction_table[instruction] == d68020_bftst)
				return 0;
			if(g_instruction_table[instruction] == d68020_bra_32)
				return 0;
			if(g_instruction_table[instruction] == d68020_bsr_32)
				return 0;
			if(g_instruction_table[instruction] == d68020_callm)
				return 0;
			if(g_instruction_table[instruction] == d68020_cas_8)
				return 0;
			if(g_instruction_table[instruction] == d68020_cas_16)
				return 0;
			if(g_instruction_table[instruction] == d68020_cas_32)
				return 0;
			if(g_instruction_table[instruction] == d68020_cas2_16)
				return 0;
			if(g_instruction_table[instruction] == d68020_cas2_32)
				return 0;
			if(g_instruction_table[instruction] == d68020_chk_32)
				return 0;
			if(g_instruction_table[instruction] == d68020_chk2_cmp2_8)
				return 0;
			if(g_instruction_table[instruction] == d68020_chk2_cmp2_16)
				return 0;
			if(g_instruction_table[instruction] == d68020_chk2_cmp2_32)
				return 0;
			if(g_instruction_table[instruction] == d68020_cmpi_pcdi_8)
				return 0;
			if(g_instruction_table[instruction] == d68020_cmpi_pcix_8)
				return 0;
			if(g_instruction_table[instruction] == d68020_cmpi_pcdi_16)
				return 0;
			if(g_instruction_table[instruction] == d68020_cmpi_pcix_16)
				return 0;
			if(g_instruction_table[instruction] == d68020_cmpi_pcdi_32)
				return 0;
			if(g_instruction_table[instruction] == d68020_cmpi_pcix_32)
				return 0;
			if(g_instruction_table[instruction] == d68020_cpbcc_16)
				return 0;
			if(g_instruction_table[instruction] == d68020_cpbcc_32)
				return 0;
			if(g_instruction_table[instruction] == d68020_cpdbcc)
				return 0;
			if(g_instruction_table[instruction] == d68020_cpgen)
				return 0;
			if(g_instruction_table[instruction] == d68020_cprestore)
				return 0;
			if(g_instruction_table[instruction] == d68020_cpsave)
				return 0;
			if(g_instruction_table[instruction] == d68020_cpscc)
				return 0;
			if(g_instruction_table[instruction] == d68020_cptrapcc_0)
				return 0;
			if(g_instruction_table[instruction] == d68020_cptrapcc_16)
				return 0;
			if(g_instruction_table[instruction] == d68020_cptrapcc_32)
				return 0;
			if(g_instruction_table[instruction] == d68020_divl)
				return 0;
			if(g_instruction_table[instruction] == d68020_extb_32)
				return 0;
			if(g_instruction_table[instruction] == d68020_link_32)
				return 0;
			if(g_instruction_table[instruction] == d68020_mull)
				return 0;
			if(g_instruction_table[instruction] == d68020_pack_rr)
				return 0;
			if(g_instruction_table[instruction] == d68020_pack_mm)
				return 0;
			if(g_instruction_table[instruction] == d68020_rtm)
				return 0;
			if(g_instruction_table[instruction] == d68020_trapcc_0)
				return 0;
			if(g_instruction_table[instruction] == d68020_trapcc_16)
				return 0;
			if(g_instruction_table[instruction] == d68020_trapcc_32)
				return 0;
			if(g_instruction_table[instruction] == d68020_tst_pcdi_8)
				return 0;
			if(g_instruction_table[instruction] == d68020_tst_pcix_8)
				return 0;
			if(g_instruction_table[instruction] == d68020_tst_i_8)
				return 0;
			if(g_instruction_table[instruction] == d68020_tst_a_16)
				return 0;
			if(g_instruction_table[instruction] == d68020_tst_pcdi_16)
				return 0;
			if(g_instruction_table[instruction] == d68020_tst_pcix_16)
				return 0;
			if(g_instruction_table[instruction] == d68020_tst_i_16)
				return 0;
			if(g_instruction_table[instruction] == d68020_tst_a_32)
				return 0;
			if(g_instruction_table[instruction] == d68020_tst_pcdi_32)
				return 0;
			if(g_instruction_table[instruction] == d68020_tst_pcix_32)
				return 0;
			if(g_instruction_table[instruction] == d68020_tst_i_32)
				return 0;
			if(g_instruction_table[instruction] == d68020_unpk_rr)
				return 0;
			if(g_instruction_table[instruction] == d68020_unpk_mm)
				return 0;
		case M68K_CPU_TYPE_68EC020:
		case M68K_CPU_TYPE_68020:
		case M68K_CPU_TYPE_68030:
			if(g_instruction_table[instruction] == d68040_cinv)
				return 0;
			if(g_instruction_table[instruction] == d68040_cpush)
				return 0;
			if(g_instruction_table[instruction] == d68040_move16_pi_pi)
				return 0;
			if(g_instruction_table[instruction] == d68040_move16_pi_al)
				return 0;
			if(g_instruction_table[instruction] == d68040_move16_al_pi)
				return 0;
			if(g_instruction_table[instruction] == d68040_move16_ai_al)
				return 0;
			if(g_instruction_table[instruction] == d68040_move16_al_ai)
				return 0;
	}
	if(cpu_type != M68K_CPU_TYPE_68020 && cpu_type != M68K_CPU_TYPE_68EC020 &&
	  (g_instruction_table[instruction] == d68020_callm ||
	  g_instruction_table[instruction] == d68020_rtm))
		return 0;

	return 1;
}

#endif



/* ======================================================================== */
/* ============================== END OF FILE ============================= */
/* ======================================================================== */

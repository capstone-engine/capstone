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

/* The code below is based on MUSASHI but has been heavily modified for Capstone by
 * Daniel Collin <daniel@collin.com> 2015-2019 */

/* ======================================================================== */
/* ================================ INCLUDES ============================== */
/* ======================================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../cs_priv.h"
#include "../../utils.h"

#include "../../MCInst.h"
#include "../../MCInstrDesc.h"
#include "../../MCRegisterInfo.h"
#include "../../MathExtras.h"
#include "M68KDisassembler.h"
#include "M68KInstPrinter.h"

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

static unsigned int m68k_read_disassembler_16(const m68k_info *info,
					      const uint64_t addr)
{
	const uint16_t v0 = info->code[addr + 0];
	const uint16_t v1 = info->code[addr + 1];
	return (v0 << 8) | v1;
}

static unsigned int m68k_read_disassembler_32(const m68k_info *info,
					      const uint64_t addr)
{
	const uint32_t v0 = info->code[addr + 0];
	const uint32_t v1 = info->code[addr + 1];
	const uint32_t v2 = info->code[addr + 2];
	const uint32_t v3 = info->code[addr + 3];
	return (v0 << 24) | (v1 << 16) | (v2 << 8) | v3;
}

static uint64_t m68k_read_disassembler_64(const m68k_info *info,
					  const uint64_t addr)
{
	const uint64_t v0 = info->code[addr + 0];
	const uint64_t v1 = info->code[addr + 1];
	const uint64_t v2 = info->code[addr + 2];
	const uint64_t v3 = info->code[addr + 3];
	const uint64_t v4 = info->code[addr + 4];
	const uint64_t v5 = info->code[addr + 5];
	const uint64_t v6 = info->code[addr + 6];
	const uint64_t v7 = info->code[addr + 7];
	return (v0 << 56) | (v1 << 48) | (v2 << 40) | (v3 << 32) | (v4 << 24) |
	       (v5 << 16) | (v6 << 8) | v7;
}

static unsigned int m68k_read_safe_16(const m68k_info *info,
				      const uint64_t address)
{
	const uint64_t addr = (address - info->baseAddress) &
			      info->address_mask;
	if (info->code_len < addr + 2) {
		return 0xaaaa;
	}
	return m68k_read_disassembler_16(info, addr);
}

static unsigned int m68k_read_safe_32(const m68k_info *info,
				      const uint64_t address)
{
	const uint64_t addr = (address - info->baseAddress) &
			      info->address_mask;
	if (info->code_len < addr + 4) {
		return 0xaaaaaaaa;
	}
	return m68k_read_disassembler_32(info, addr);
}

static uint64_t m68k_read_safe_64(const m68k_info *info, const uint64_t address)
{
	const uint64_t addr = (address - info->baseAddress) &
			      info->address_mask;
	if (info->code_len < addr + 8) {
		return 0xaaaaaaaaaaaaaaaaLL;
	}
	return m68k_read_disassembler_64(info, addr);
}

/* ======================================================================== */
/* =============================== PROTOTYPES ============================= */
/* ======================================================================== */

/* make signed integers 100% portably */
static int make_int_8(int value);
static int make_int_16(int value);

/* Stuff to build the opcode handler jump table */
static void d68000_invalid(m68k_info *info);
static void d68030_pmmu(m68k_info *info);
static void d68040_pflush(m68k_info *info);
static void d68040_ptest(m68k_info *info);
static void d68040_cpush(m68k_info *info);
static int instruction_is_valid(m68k_info *info, uint32_t word_check);

typedef struct {
	void (*instruction)(m68k_info *info); /* handler function */
	uint16_t word2_mask; /* mask the 2nd word */
	uint16_t word2_match; /* what to match after masking */
} instruction_struct;

/* ======================================================================== */
/* ================================= DATA ================================= */
/* ======================================================================== */

static const instruction_struct g_instruction_table[0x10000];

/* used by ops like asr, ror, addq, etc */
static const uint32_t g_3bit_qdata_table[8] = { 8, 1, 2, 3, 4, 5, 6, 7 };

static const uint32_t g_5bit_data_table[32] = {
	32, 1,	2,  3,	4,  5,	6,  7,	8,  9,	10, 11, 12, 13, 14, 15,
	16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
};

static const m68k_insn s_branch_lut[] = {
	M68K_INS_INVALID, M68K_INS_INVALID, M68K_INS_BHI, M68K_INS_BLS,
	M68K_INS_BCC,	  M68K_INS_BCS,	    M68K_INS_BNE, M68K_INS_BEQ,
	M68K_INS_BVC,	  M68K_INS_BVS,	    M68K_INS_BPL, M68K_INS_BMI,
	M68K_INS_BGE,	  M68K_INS_BLT,	    M68K_INS_BGT, M68K_INS_BLE,
};

static const m68k_insn s_dbcc_lut[] = {
	M68K_INS_DBT,  M68K_INS_DBF,  M68K_INS_DBHI, M68K_INS_DBLS,
	M68K_INS_DBCC, M68K_INS_DBCS, M68K_INS_DBNE, M68K_INS_DBEQ,
	M68K_INS_DBVC, M68K_INS_DBVS, M68K_INS_DBPL, M68K_INS_DBMI,
	M68K_INS_DBGE, M68K_INS_DBLT, M68K_INS_DBGT, M68K_INS_DBLE,
};

static const m68k_insn s_scc_lut[] = {
	M68K_INS_ST,  M68K_INS_SF,  M68K_INS_SHI, M68K_INS_SLS,
	M68K_INS_SCC, M68K_INS_SCS, M68K_INS_SNE, M68K_INS_SEQ,
	M68K_INS_SVC, M68K_INS_SVS, M68K_INS_SPL, M68K_INS_SMI,
	M68K_INS_SGE, M68K_INS_SLT, M68K_INS_SGT, M68K_INS_SLE,
};

static const m68k_insn s_trap_lut[] = {
	M68K_INS_TRAPT,	 M68K_INS_TRAPF,  M68K_INS_TRAPHI, M68K_INS_TRAPLS,
	M68K_INS_TRAPCC, M68K_INS_TRAPCS, M68K_INS_TRAPNE, M68K_INS_TRAPEQ,
	M68K_INS_TRAPVC, M68K_INS_TRAPVS, M68K_INS_TRAPPL, M68K_INS_TRAPMI,
	M68K_INS_TRAPGE, M68K_INS_TRAPLT, M68K_INS_TRAPGT, M68K_INS_TRAPLE,
};

/* ======================================================================== */
/* =========================== UTILITY FUNCTIONS ========================== */
/* ======================================================================== */

static unsigned int peek_imm_8(const m68k_info *info)
{
	return (m68k_read_safe_16((info), (info)->pc) & 0xff);
}
static unsigned int peek_imm_16(const m68k_info *info)
{
	return m68k_read_safe_16((info), (info)->pc);
}
static unsigned int peek_imm_32(const m68k_info *info)
{
	return m68k_read_safe_32((info), (info)->pc);
}
static unsigned long long peek_imm_64(const m68k_info *info)
{
	return m68k_read_safe_64((info), (info)->pc);
}

static unsigned int read_imm_8(m68k_info *info)
{
	const unsigned int value = peek_imm_8(info);
	(info)->pc += 2;
	return value & 0xff;
}
static unsigned int read_imm_16(m68k_info *info)
{
	const unsigned int value = peek_imm_16(info);
	(info)->pc += 2;
	return value & 0xffff;
}
static unsigned int read_imm_32(m68k_info *info)
{
	const unsigned int value = peek_imm_32(info);
	(info)->pc += 4;
	return value & 0xffffffff;
}
static unsigned long long read_imm_64(m68k_info *info)
{
	const unsigned long long value = peek_imm_64(info);
	(info)->pc += 8;
	return value & 0xffffffffffffffff;
}

/* 100% portable signed int generators */
static int make_int_8(int value)
{
	return (value & 0x80) ? value | ~0xff : value & 0xff;
}

static int make_int_16(int value)
{
	return (value & 0x8000) ? value | ~0xffff : value & 0xffff;
}

static void get_with_index_address_mode(m68k_info *info, cs_m68k_op *op,
					uint32_t instruction, uint32_t size,
					bool is_pc)
{
	uint32_t ext_addr = info->pc;
	uint32_t extension = read_imm_16(info);
	int32_t pc_adjust =
		is_pc ? (int32_t)(ext_addr - info->baseAddress - 2) : 0;

	op->address_mode = M68K_AM_AREGI_INDEX_BASE_DISP;

	if (EXT_FULL(extension)) {
		uint32_t preindex;
		uint32_t postindex;

		op->mem.base_reg = M68K_REG_INVALID;
		op->mem.index_reg = M68K_REG_INVALID;

		op->mem.in_disp =
			EXT_BASE_DISPLACEMENT_PRESENT(extension) ?
				(EXT_BASE_DISPLACEMENT_LONG(extension) ?
					 read_imm_32(info) :
					 (int16_t)read_imm_16(info)) :
				0;
		op->mem.in_disp += pc_adjust;

		op->mem.in_disp_size =
			EXT_BASE_DISPLACEMENT_PRESENT(extension) &&
					EXT_BASE_DISPLACEMENT_LONG(extension) ?
				1 :
				0;

		op->mem.out_disp =
			EXT_OUTER_DISPLACEMENT_PRESENT(extension) ?
				(EXT_OUTER_DISPLACEMENT_LONG(extension) ?
					 read_imm_32(info) :
					 (int16_t)read_imm_16(info)) :
				0;

		op->mem.out_disp_size =
			EXT_OUTER_DISPLACEMENT_PRESENT(extension) &&
					EXT_OUTER_DISPLACEMENT_LONG(extension) ?
				1 :
				0;

		if (EXT_BASE_REGISTER_PRESENT(extension)) {
			if (is_pc) {
				op->mem.base_reg = M68K_REG_PC;
			} else {
				op->mem.base_reg =
					M68K_REG_A0 + (instruction & 7);
			}
		}

		if (EXT_INDEX_REGISTER_PRESENT(extension)) {
			if (EXT_INDEX_AR(extension)) {
				op->mem.index_reg =
					M68K_REG_A0 +
					EXT_INDEX_REGISTER(extension);
			} else {
				op->mem.index_reg =
					M68K_REG_D0 +
					EXT_INDEX_REGISTER(extension);
			}

			op->mem.index_size = EXT_INDEX_LONG(extension) ? 1 : 0;

			if (EXT_INDEX_SCALE(extension)) {
				op->mem.scale = 1 << EXT_INDEX_SCALE(extension);
			}
		}

		preindex = (extension & 7) > 0 && (extension & 7) < 4;
		postindex = (extension & 7) > 4;

		if (preindex) {
			op->address_mode = is_pc ? M68K_AM_PC_MEMI_PRE_INDEX :
						   M68K_AM_MEMI_PRE_INDEX;
		} else if (postindex) {
			op->address_mode = is_pc ? M68K_AM_PC_MEMI_POST_INDEX :
						   M68K_AM_MEMI_POST_INDEX;
		} else {
			op->address_mode =
				is_pc ? M68K_AM_PCI_INDEX_BASE_DISP :
					M68K_AM_AREGI_INDEX_BASE_DISP;
		}

		return;
	}

	op->mem.index_reg =
		(EXT_INDEX_AR(extension) ? M68K_REG_A0 : M68K_REG_D0) +
		EXT_INDEX_REGISTER(extension);
	op->mem.index_size = EXT_INDEX_LONG(extension) ? 1 : 0;

	if (is_pc) {
		op->mem.base_reg = M68K_REG_PC;
		op->address_mode = M68K_AM_PCI_INDEX_8_BIT_DISP;
	} else {
		op->mem.base_reg = M68K_REG_A0 + (instruction & 7);
		op->address_mode = M68K_AM_AREGI_INDEX_8_BIT_DISP;
	}

	op->mem.disp = (int8_t)(extension & 0xff);
	op->mem.disp += (int16_t)pc_adjust;
	op->mem.disp_size = 0;

	if (EXT_INDEX_SCALE(extension)) {
		op->mem.scale = 1 << EXT_INDEX_SCALE(extension);
	}
}

enum {
	/* Raw effective-address encoding bits, used before get_ea_mode_op()
	 * consumes any extension words and fills cs_m68k_op.address_mode. */
	M68K_EA_REGISTER_MASK = 0x07,
	M68K_EA_MODE_SHIFT = 3,
	M68K_EA_FIELD_MASK = 0x3f,
	M68K_EA_DATA_DIRECT_D0 = 0x00,
	M68K_EA_ADDR_DIRECT_A7 = 0x0f,
	M68K_EA_ADDR_INDIRECT_DISP_A7 = 0x2f,
	M68K_EA_IMMEDIATE_FIELD = 0x3c,
};

enum {
	M68K_EA_MODE_DATA_DIRECT = 0,
	M68K_EA_MODE_ADDR_DIRECT = 1,
	M68K_EA_MODE_ADDR_INDIRECT = 2,
	M68K_EA_MODE_ADDR_INDIRECT_POST_INC = 3,
	M68K_EA_MODE_ADDR_INDIRECT_PRE_DEC = 4,
	M68K_EA_MODE_ADDR_INDIRECT_DISP = 5,
	M68K_EA_MODE_ADDR_INDIRECT_INDEX = 6,
	M68K_EA_MODE_EXTENDED = 7,
};

enum {
	M68K_EA_EXT_ABSOLUTE_SHORT = 0,
	M68K_EA_EXT_ABSOLUTE_LONG = 1,
};

static uint32_t m68k_ea_field(uint32_t ir)
{
	return ir & M68K_EA_FIELD_MASK;
}

static uint32_t m68k_ea_mode(uint32_t ir)
{
	return m68k_ea_field(ir) >> M68K_EA_MODE_SHIFT;
}

static uint32_t m68k_ea_register(uint32_t ir)
{
	return ir & M68K_EA_REGISTER_MASK;
}

static bool m68k_ea_is_data_register_direct(uint32_t ir)
{
	return m68k_ea_mode(ir) == M68K_EA_MODE_DATA_DIRECT;
}

static bool m68k_ea_is_register_direct(uint32_t ir)
{
	return m68k_ea_field(ir) <= M68K_EA_ADDR_DIRECT_A7;
}

static bool m68k_ea_is_immediate(uint32_t ir)
{
	return m68k_ea_field(ir) == M68K_EA_IMMEDIATE_FIELD;
}

static bool m68k_ea_is_data_register_direct_or_immediate(uint32_t ir)
{
	return m68k_ea_is_data_register_direct(ir) || m68k_ea_is_immediate(ir);
}

/* Make string of effective address mode */
static void get_ea_mode_op(m68k_info *info, cs_m68k_op *op,
			   uint32_t instruction, uint32_t size)
{
	// default to memory

	op->type = M68K_OP_MEM;

	switch (m68k_ea_field(instruction)) {
	case 0x00:
	case 0x01:
	case 0x02:
	case 0x03:
	case 0x04:
	case 0x05:
	case 0x06:
	case 0x07:
		/* data register direct */
		op->address_mode = M68K_AM_REG_DIRECT_DATA;
		op->reg = M68K_REG_D0 + (instruction & 7);
		op->type = M68K_OP_REG;
		break;

	case 0x08:
	case 0x09:
	case 0x0a:
	case 0x0b:
	case 0x0c:
	case 0x0d:
	case 0x0e:
	case 0x0f:
		/* address register direct */
		op->address_mode = M68K_AM_REG_DIRECT_ADDR;
		op->reg = M68K_REG_A0 + (instruction & 7);
		op->type = M68K_OP_REG;
		break;

	case 0x10:
	case 0x11:
	case 0x12:
	case 0x13:
	case 0x14:
	case 0x15:
	case 0x16:
	case 0x17:
		/* address register indirect */
		op->address_mode = M68K_AM_REGI_ADDR;
		op->mem.base_reg = M68K_REG_A0 + (instruction & 7);
		break;

	case 0x18:
	case 0x19:
	case 0x1a:
	case 0x1b:
	case 0x1c:
	case 0x1d:
	case 0x1e:
	case 0x1f:
		/* address register indirect with postincrement */
		op->address_mode = M68K_AM_REGI_ADDR_POST_INC;
		op->mem.base_reg = M68K_REG_A0 + (instruction & 7);
		break;

	case 0x20:
	case 0x21:
	case 0x22:
	case 0x23:
	case 0x24:
	case 0x25:
	case 0x26:
	case 0x27:
		/* address register indirect with predecrement */
		op->address_mode = M68K_AM_REGI_ADDR_PRE_DEC;
		op->mem.base_reg = M68K_REG_A0 + (instruction & 7);
		break;

	case 0x28:
	case 0x29:
	case 0x2a:
	case 0x2b:
	case 0x2c:
	case 0x2d:
	case 0x2e:
	case 0x2f:
		/* address register indirect with displacement*/
		op->address_mode = M68K_AM_REGI_ADDR_DISP;
		op->mem.base_reg = M68K_REG_A0 + (instruction & 7);
		op->mem.disp = (int16_t)read_imm_16(info);
		op->mem.disp_size = 1;
		break;

	case 0x30:
	case 0x31:
	case 0x32:
	case 0x33:
	case 0x34:
	case 0x35:
	case 0x36:
	case 0x37:
		/* address register indirect with index */
		get_with_index_address_mode(info, op, instruction, size, false);
		break;

	case 0x38:
		/* absolute short address */
		op->address_mode = M68K_AM_ABSOLUTE_DATA_SHORT;
		op->mem.address = read_imm_16(info);
		break;

	case 0x39:
		/* absolute long address */
		op->address_mode = M68K_AM_ABSOLUTE_DATA_LONG;
		op->mem.address = read_imm_32(info);
		break;

	case 0x3a: {
		/* program counter with displacement */
		/* The printer computes the effective address as
		 * instruction_start + 2 + disp, assuming the displacement
		 * extension word immediately follows the opcode word.
		 * When extra words precede the EA (e.g. an immediate in
		 * BTST #imm,disp(PC)), the displacement word is further
		 * along.  Adjust disp so the printer still produces the
		 * correct absolute address. */
		uint32_t disp_addr = info->pc;
		op->address_mode = M68K_AM_PCI_DISP;
		op->mem.disp = (int16_t)read_imm_16(info);
		op->mem.disp += (int16_t)(disp_addr - info->baseAddress - 2);
		op->mem.disp_size = 1;
		break;
	}

	case 0x3b:
		/* program counter with index */
		get_with_index_address_mode(info, op, instruction, size, true);
		break;

	case 0x3c:
		op->address_mode = M68K_AM_IMMEDIATE;
		op->type = M68K_OP_IMM;

		if (size == 1)
			op->imm = read_imm_8(info);
		else if (size == 2)
			op->imm = read_imm_16(info);
		else if (size == 4)
			op->imm = read_imm_32(info);
		else
			op->imm = read_imm_64(info);

		break;

	default:
		break;
	}
}

static void set_insn_group(m68k_info *info, m68k_group_type group)
{
	info->groups[info->groups_count++] = (uint8_t)group;
}

static cs_m68k *build_init_op(m68k_info *info, int opcode, int count, int size)
{
	cs_m68k *ext;

	MCInst_setOpcode(info->inst, opcode);

	ext = &info->extension;

	ext->op_count = (uint8_t)count;
	ext->op_size.type = M68K_SIZE_TYPE_CPU;
	ext->op_size.cpu_size = size;

	return ext;
}

static void build_re_gen_1(m68k_info *info, bool isDreg, int opcode,
			   uint8_t size)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, opcode, 2, size);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	if (isDreg) {
		op0->address_mode = M68K_AM_REG_DIRECT_DATA;
		op0->reg = M68K_REG_D0 + ((info->ir >> 9) & 7);
	} else {
		op0->address_mode = M68K_AM_REG_DIRECT_ADDR;
		op0->reg = M68K_REG_A0 + ((info->ir >> 9) & 7);
	}

	get_ea_mode_op(info, op1, info->ir, size);
}

static void build_re_1(m68k_info *info, int opcode, uint8_t size)
{
	build_re_gen_1(info, true, opcode, size);
}

static void build_er_gen_1(m68k_info *info, bool isDreg, int opcode,
			   uint8_t size)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, opcode, 2, size);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	get_ea_mode_op(info, op0, info->ir, size);

	if (isDreg) {
		op1->address_mode = M68K_AM_REG_DIRECT_DATA;
		op1->reg = M68K_REG_D0 + ((info->ir >> 9) & 7);
	} else {
		op1->address_mode = M68K_AM_REG_DIRECT_ADDR;
		op1->reg = M68K_REG_A0 + ((info->ir >> 9) & 7);
	}
}

static void append_imm_operand(m68k_info *info, uint32_t value)
{
	cs_m68k *ext = &info->extension;
	cs_m68k_op *op = &ext->operands[ext->op_count];
	op->type = M68K_OP_IMM;
	op->address_mode = M68K_AM_IMMEDIATE;
	op->imm = value;
	ext->op_count++;
}

static void build_rr(m68k_info *info, int opcode, uint8_t size, int imm)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, opcode, 2, size);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	op0->address_mode = M68K_AM_REG_DIRECT_DATA;
	op0->reg = M68K_REG_D0 + (info->ir & 7);

	op1->address_mode = M68K_AM_REG_DIRECT_DATA;
	op1->reg = M68K_REG_D0 + ((info->ir >> 9) & 7);

	if (imm > 0)
		append_imm_operand(info, imm);
}

static void build_r(m68k_info *info, int opcode, uint8_t size)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, opcode, 2, size);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	op0->address_mode = M68K_AM_REG_DIRECT_DATA;
	op0->reg = M68K_REG_D0 + ((info->ir >> 9) & 7);

	op1->address_mode = M68K_AM_REG_DIRECT_DATA;
	op1->reg = M68K_REG_D0 + (info->ir & 7);
}

static void build_imm_ea(m68k_info *info, int opcode, uint8_t size,
			 uint32_t imm)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, opcode, 2, size);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	op0->type = M68K_OP_IMM;
	op0->address_mode = M68K_AM_IMMEDIATE;
	op0->imm = imm;

	get_ea_mode_op(info, op1, info->ir, size);
}

static void build_3bit_d(m68k_info *info, int opcode, int size)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, opcode, 2, size);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	op0->type = M68K_OP_IMM;
	op0->address_mode = M68K_AM_IMMEDIATE;
	op0->imm = g_3bit_qdata_table[(info->ir >> 9) & 7];

	op1->address_mode = M68K_AM_REG_DIRECT_DATA;
	op1->reg = M68K_REG_D0 + (info->ir & 7);
}

static void build_3bit_ea(m68k_info *info, int opcode, int size)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, opcode, 2, size);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	op0->type = M68K_OP_IMM;
	op0->address_mode = M68K_AM_IMMEDIATE;
	op0->imm = g_3bit_qdata_table[(info->ir >> 9) & 7];

	get_ea_mode_op(info, op1, info->ir, size);
}

static void build_mm(m68k_info *info, int opcode, uint8_t size, int imm)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, opcode, 2, size);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	op0->address_mode = M68K_AM_REGI_ADDR_PRE_DEC;
	op0->reg = M68K_REG_A0 + (info->ir & 7);

	op1->address_mode = M68K_AM_REGI_ADDR_PRE_DEC;
	op1->reg = M68K_REG_A0 + ((info->ir >> 9) & 7);

	if (imm > 0)
		append_imm_operand(info, imm);
}

static void build_ea(m68k_info *info, int opcode, uint8_t size)
{
	cs_m68k *ext = build_init_op(info, opcode, 1, size);
	get_ea_mode_op(info, &ext->operands[0], info->ir, size);
}

static void build_ea_a(m68k_info *info, int opcode, uint8_t size)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, opcode, 2, size);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	get_ea_mode_op(info, op0, info->ir, size);

	op1->address_mode = M68K_AM_REG_DIRECT_ADDR;
	op1->reg = M68K_REG_A0 + ((info->ir >> 9) & 7);
}

static void build_ea_ea(m68k_info *info, int opcode, int size)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, opcode, 2, size);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	get_ea_mode_op(info, op0, info->ir, size);
	get_ea_mode_op(info, op1,
		       (((info->ir >> 9) & 7) | ((info->ir >> 3) & 0x38)),
		       size);
}

static void build_pi_pi(m68k_info *info, int opcode, int size)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, opcode, 2, size);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	op0->address_mode = M68K_AM_REGI_ADDR_POST_INC;
	op0->reg = M68K_REG_A0 + (info->ir & 7);

	op1->address_mode = M68K_AM_REGI_ADDR_POST_INC;
	op1->reg = M68K_REG_A0 + ((info->ir >> 9) & 7);
}

static void build_imm_special_reg(m68k_info *info, int opcode, uint32_t imm,
				  int size, m68k_reg reg)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, opcode, 2, size);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	op0->type = M68K_OP_IMM;
	op0->address_mode = M68K_AM_IMMEDIATE;
	op0->imm = imm;

	op1->address_mode = M68K_AM_NONE;
	op1->reg = reg;
}

static void build_relative_branch(m68k_info *info, int opcode, int size,
				  int displacement)
{
	cs_m68k_op *op;
	cs_m68k *ext = build_init_op(info, opcode, 1, size);

	op = &ext->operands[0];

	op->type = M68K_OP_BR_DISP;
	op->address_mode = M68K_AM_BRANCH_DISPLACEMENT;
	op->br_disp.disp = displacement;
	op->br_disp.disp_size = size;

	set_insn_group(info, M68K_GRP_JUMP);
	set_insn_group(info, M68K_GRP_BRANCH_RELATIVE);
}

static void build_absolute_jump_with_immediate(m68k_info *info, int opcode,
					       int size, int immediate)
{
	cs_m68k_op *op;
	cs_m68k *ext = build_init_op(info, opcode, 1, size);

	op = &ext->operands[0];

	op->type = M68K_OP_IMM;
	op->address_mode = M68K_AM_IMMEDIATE;
	op->imm = immediate;

	set_insn_group(info, M68K_GRP_JUMP);
}

static void build_bcc(m68k_info *info, int size, int displacement)
{
	build_relative_branch(info,
			      s_branch_lut[M68K_IR_CONDITION_NIBBLE(info)],
			      size, displacement);
}

static void build_trap(m68k_info *info, int size, int immediate)
{
	build_absolute_jump_with_immediate(
		info, s_trap_lut[M68K_IR_CONDITION_NIBBLE(info)], size,
		immediate);
}

static void build_dbxx(m68k_info *info, int opcode, int size, int displacement)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, opcode, 2, size);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	op0->address_mode = M68K_AM_REG_DIRECT_DATA;
	op0->reg = M68K_REG_D0 + (info->ir & 7);

	op1->type = M68K_OP_BR_DISP;
	op1->address_mode = M68K_AM_BRANCH_DISPLACEMENT;
	op1->br_disp.disp = displacement;
	op1->br_disp.disp_size = M68K_OP_BR_DISP_SIZE_LONG;

	set_insn_group(info, M68K_GRP_JUMP);
	set_insn_group(info, M68K_GRP_BRANCH_RELATIVE);
}

static void build_dbcc(m68k_info *info, int size, int displacement)
{
	build_dbxx(info, s_dbcc_lut[M68K_IR_CONDITION_NIBBLE(info)], size,
		   displacement);
}

static void build_d_d_ea(m68k_info *info, int opcode, int size)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k_op *op2;
	uint32_t extension = read_imm_16(info);
	cs_m68k *ext = build_init_op(info, opcode, 3, size);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];
	op2 = &ext->operands[2];

	op0->address_mode = M68K_AM_REG_DIRECT_DATA;
	op0->reg = M68K_REG_D0 + (extension & 7);

	op1->address_mode = M68K_AM_REG_DIRECT_DATA;
	op1->reg = M68K_REG_D0 + ((extension >> 6) & 7);

	get_ea_mode_op(info, op2, info->ir, size);
}

static void build_bitfield_ins(m68k_info *info, int opcode, int has_d_arg)
{
	uint8_t offset;
	uint8_t width;
	cs_m68k_op *op_ea;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, opcode, 1, 0);
	uint32_t extension = read_imm_16(info);

	op_ea = &ext->operands[0];
	op1 = &ext->operands[1];

	if (BIT_B(extension))
		offset = M68K_BITFIELD_ENCODE_REG((extension >> 6) & 7);
	else
		offset = (extension >> 6) & 31;

	if (BIT_5(extension))
		width = M68K_BITFIELD_ENCODE_REG(extension & 7);
	else
		width = (uint8_t)g_5bit_data_table[extension & 31];

	if (has_d_arg) {
		ext->op_count = 2;
		op1->address_mode = M68K_AM_REG_DIRECT_DATA;
		op1->reg = M68K_REG_D0 + ((extension >> 12) & 7);
	}

	get_ea_mode_op(info, op_ea, info->ir, 1);

	op_ea->mem.bitfield = 1;
	op_ea->mem.width = width;
	op_ea->mem.offset = offset;
}

static void build_d(m68k_info *info, int opcode, int size)
{
	cs_m68k *ext = build_init_op(info, opcode, 1, size);
	cs_m68k_op *op;

	op = &ext->operands[0];

	op->address_mode = M68K_AM_REG_DIRECT_DATA;
	op->reg = M68K_REG_D0 + (info->ir & 7);
}

static m68k_reg cf_reg_from_nibble(unsigned int reg)
{
	return (reg & 8) ? (m68k_reg)(M68K_REG_A0 + (reg & 7)) :
			   (m68k_reg)(M68K_REG_D0 + (reg & 7));
}

static m68k_reg cf_acc_reg(unsigned int acc)
{
	switch (acc & 3) {
	case 0:
		return M68K_REG_ACC0;
	case 1:
		return M68K_REG_ACC1;
	case 2:
		return M68K_REG_ACC2;
	default:
		return M68K_REG_ACC3;
	}
}

static void cf_build_reg_op(cs_m68k_op *op, m68k_reg reg)
{
	op->address_mode = M68K_AM_NONE;
	op->type = M68K_OP_REG;
	op->reg = reg;
}

static void cf_build_direct_reg_op(cs_m68k_op *op, m68k_reg reg)
{
	op->type = M68K_OP_REG;
	op->reg = reg;
	op->address_mode = (reg >= M68K_REG_A0 && reg <= M68K_REG_A7) ?
				   M68K_AM_REG_DIRECT_ADDR :
				   M68K_AM_REG_DIRECT_DATA;
}

static void cf_build_imm_op(cs_m68k_op *op, uint32_t imm)
{
	op->type = M68K_OP_IMM;
	op->address_mode = M68K_AM_IMMEDIATE;
	op->imm = imm;
}

static void cf_build_shift_op(cs_m68k_op *op, uint32_t shift)
{
	op->type = M68K_OP_SHIFT;
	op->address_mode = M68K_AM_NONE;
	op->flags = shift == 0x0200 ? M68K_OP_FLAG_SHIFT_LEFT :
				      M68K_OP_FLAG_SHIFT_RIGHT;
}

static void cf_build_mac_reg_op(cs_m68k_op *op, uint32_t reg, bool long_size)
{
	cf_build_direct_reg_op(op, cf_reg_from_nibble(reg));
	if (!long_size)
		op->flags = (reg & 0x10) ? M68K_OP_FLAG_REG_UPPER :
					   M68K_OP_FLAG_REG_LOWER;
}

static bool cf_mac_ea_is_valid(uint32_t ir)
{
	uint32_t mode = m68k_ea_mode(ir);

	/* ColdFire MAC/EMAC load forms accept (An), (An)+, -(An), and d16(An). */
	return mode >= M68K_EA_MODE_ADDR_INDIRECT &&
	       mode <= M68K_EA_MODE_ADDR_INDIRECT_DISP;
}

static bool cf_coproc_ea_is_valid(uint32_t ir)
{
	return m68k_ea_field(ir) <= M68K_EA_ADDR_INDIRECT_DISP_A7;
}

static bool cf_alterable_memory_ea_is_valid(uint32_t ir)
{
	uint32_t mode = m68k_ea_mode(ir);
	uint32_t reg = m68k_ea_register(ir);

	return (mode >= M68K_EA_MODE_ADDR_INDIRECT &&
		mode <= M68K_EA_MODE_ADDR_INDIRECT_INDEX) ||
	       (mode == M68K_EA_MODE_EXTENDED &&
		reg <= M68K_EA_EXT_ABSOLUTE_LONG);
}

static bool cf_sr_ccr_source_ea_is_valid(uint32_t ir)
{
	return m68k_ea_is_data_register_direct_or_immediate(ir);
}

static bool cf_sr_ccr_destination_ea_is_valid(uint32_t ir)
{
	return m68k_ea_is_data_register_direct(ir);
}

static uint16_t reverse_bits(uint32_t v)
{
	uint32_t r = v; // r will be reversed bits of v; first get LSB of v
	uint32_t s = 16 - 1; // extra shift needed at end

	for (v >>= 1; v; v >>= 1) {
		r <<= 1;
		r |= v & 1;
		s--;
	}

	r <<= s; // shift when v's highest bits are zero
	return r;
}

static uint8_t reverse_bits_8(uint32_t v)
{
	uint32_t r = v; // r will be reversed bits of v; first get LSB of v
	uint32_t s = 8 - 1; // extra shift needed at end

	for (v >>= 1; v; v >>= 1) {
		r <<= 1;
		r |= v & 1;
		s--;
	}

	r <<= s; // shift when v's highest bits are zero
	return r;
}

static void build_movem_re(m68k_info *info, int opcode, int size)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, opcode, 2, size);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	op0->type = M68K_OP_REG_BITS;
	op0->register_bits = read_imm_16(info);

	get_ea_mode_op(info, op1, info->ir, size);

	if (op1->address_mode == M68K_AM_REGI_ADDR_PRE_DEC)
		op0->register_bits = reverse_bits(op0->register_bits);
}

static void build_movem_er(m68k_info *info, int opcode, int size)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, opcode, 2, size);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	op1->type = M68K_OP_REG_BITS;
	op1->register_bits = read_imm_16(info);

	get_ea_mode_op(info, op0, info->ir, size);
}

static void build_imm(m68k_info *info, int opcode, uint32_t data)
{
	cs_m68k_op *op;
	cs_m68k *ext = build_init_op(info, opcode, 1, 0);

	MCInst_setOpcode(info->inst, opcode);

	op = &ext->operands[0];

	op->type = M68K_OP_IMM;
	op->address_mode = M68K_AM_IMMEDIATE;
	op->imm = data;
}

static void build_illegal(m68k_info *info, uint32_t data)
{
	build_imm(info, M68K_INS_ILLEGAL, data);
}

static void build_invalid(m68k_info *info, uint32_t data)
{
	build_imm(info, M68K_INS_INVALID, data);
}

static void build_cas2(m68k_info *info, int size)
{
	uint32_t word3;
	uint32_t extension;
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k_op *op2;
	cs_m68k *ext = build_init_op(info, M68K_INS_CAS2, 3, size);
	uint32_t reg_0, reg_1;

	/* cas2 is the only 3 words instruction, word2 and word3 have the same motif bits to check */
	word3 = peek_imm_32(info) & 0xffff;
	if (!instruction_is_valid(info, word3))
		return;

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];
	op2 = &ext->operands[2];

	extension = read_imm_32(info);

	op0->address_mode = M68K_AM_NONE;
	op0->type = M68K_OP_REG_PAIR;
	op0->reg_pair.reg_0 = ((extension >> 16) & 7) + M68K_REG_D0;
	op0->reg_pair.reg_1 = (extension & 7) + M68K_REG_D0;

	op1->address_mode = M68K_AM_NONE;
	op1->type = M68K_OP_REG_PAIR;
	op1->reg_pair.reg_0 = ((extension >> 22) & 7) + M68K_REG_D0;
	op1->reg_pair.reg_1 = ((extension >> 6) & 7) + M68K_REG_D0;

	reg_0 = (extension >> 28) & 7;
	reg_1 = (extension >> 12) & 7;

	op2->address_mode = M68K_AM_NONE;
	op2->type = M68K_OP_REG_PAIR;
	op2->reg_pair.reg_0 = reg_0 + (BIT_1F(extension) ? 8 : 0) + M68K_REG_D0;
	op2->reg_pair.reg_1 = reg_1 + (BIT_F(extension) ? 8 : 0) + M68K_REG_D0;
}

static void build_chk2_cmp2(m68k_info *info, int size)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, M68K_INS_CHK2, 2, size);

	uint32_t extension = read_imm_16(info);

	if (BIT_B(extension))
		MCInst_setOpcode(info->inst, M68K_INS_CHK2);
	else
		MCInst_setOpcode(info->inst, M68K_INS_CMP2);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	get_ea_mode_op(info, op0, info->ir, size);

	op1->address_mode = M68K_AM_NONE;
	op1->type = M68K_OP_REG;
	op1->reg = (BIT_F(extension) ? M68K_REG_A0 : M68K_REG_D0) +
		   ((extension >> 12) & 7);
}

static void build_move16(m68k_info *info, const uint32_t data[2],
			 const uint32_t modes[2])
{
	cs_m68k *ext = build_init_op(info, M68K_INS_MOVE16, 2, 0);
	int i;

	for (i = 0; i < 2; ++i) {
		cs_m68k_op *op = &ext->operands[i];
		const uint32_t d = data[i];
		const uint32_t m = modes[i];

		op->type = M68K_OP_MEM;
		op->address_mode = m;

		if (m == M68K_AM_REGI_ADDR_POST_INC || m == M68K_AM_REGI_ADDR)
			op->mem.base_reg = M68K_REG_A0 + d;
		else
			op->mem.address = d;
	}
}

static void build_link(m68k_info *info, int disp, int size)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, M68K_INS_LINK, 2, size);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	op0->address_mode = M68K_AM_NONE;
	op0->reg = M68K_REG_A0 + (info->ir & 7);

	op1->address_mode = M68K_AM_IMMEDIATE;
	op1->type = M68K_OP_IMM;
	op1->imm = disp;
}

static void build_cpush_cinv(m68k_info *info, int op_offset)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, M68K_INS_INVALID, 2, 0);

	switch (M68K_IR_CACHE_SCOPE(info)) {
	case 0:
		d68000_invalid(info);
		return;
	case 1: // Line
		MCInst_setOpcode(info->inst, op_offset + 0);
		break;
	case 2: // Page
		MCInst_setOpcode(info->inst, op_offset + 1);
		break;
	case 3: // All
		ext->op_count = 1;
		MCInst_setOpcode(info->inst, op_offset + 2);
		break;
	default:
		return;
	}

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	op0->address_mode = M68K_AM_IMMEDIATE;
	op0->type = M68K_OP_IMM;
	op0->imm = M68K_IR_CACHE_SEL(info);

	op1->type = M68K_OP_MEM;
	op1->address_mode = M68K_AM_REGI_ADDR;
	op1->mem.base_reg = M68K_REG_A0 + (info->ir & 7);
}

static void build_movep_re(m68k_info *info, int size)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, M68K_INS_MOVEP, 2, size);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	op0->reg = M68K_REG_D0 + ((info->ir >> 9) & 7);

	op1->address_mode = M68K_AM_REGI_ADDR_DISP;
	op1->type = M68K_OP_MEM;
	op1->mem.base_reg = M68K_REG_A0 + (info->ir & 7);
	op1->mem.disp = (int16_t)read_imm_16(info);
}

static void build_movep_er(m68k_info *info, int size)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, M68K_INS_MOVEP, 2, size);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	op0->address_mode = M68K_AM_REGI_ADDR_DISP;
	op0->type = M68K_OP_MEM;
	op0->mem.base_reg = M68K_REG_A0 + (info->ir & 7);
	op0->mem.disp = (int16_t)read_imm_16(info);

	op1->reg = M68K_REG_D0 + ((info->ir >> 9) & 7);
}

static void build_moves(m68k_info *info, int size)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, M68K_INS_MOVES, 2, size);
	uint32_t extension = read_imm_16(info);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	if (BIT_B(extension)) {
		op0->reg = (BIT_F(extension) ? M68K_REG_A0 : M68K_REG_D0) +
			   ((extension >> 12) & 7);
		get_ea_mode_op(info, op1, info->ir, size);
	} else {
		get_ea_mode_op(info, op0, info->ir, size);
		op1->reg = (BIT_F(extension) ? M68K_REG_A0 : M68K_REG_D0) +
			   ((extension >> 12) & 7);
	}
}

static void build_er_1(m68k_info *info, int opcode, uint8_t size)
{
	build_er_gen_1(info, true, opcode, size);
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

static void d68000_invalid(m68k_info *info)
{
	build_invalid(info, info->ir);
}

static void d68000_illegal(m68k_info *info)
{
	build_illegal(info, info->ir);
}

static void dcf_1111(m68k_info *info)
{
	d68000_invalid(info);
}

static void dcf_bitop_d(m68k_info *info, m68k_insn insn)
{
	LIMIT_FEATURE(info, CS_MODE_M68K_CF_ISA_A_PLUS | CS_MODE_M68K_CF_ISA_C);
	build_d(info, insn, 0);
}

static void dcf_bitrev(m68k_info *info)
{
	dcf_bitop_d(info, M68K_INS_BITREV);
}

static void dcf_byterev(m68k_info *info)
{
	dcf_bitop_d(info, M68K_INS_BYTEREV);
}

static void dcf_ff1(m68k_info *info)
{
	dcf_bitop_d(info, M68K_INS_FF1);
}

static uint32_t cf_mov3q_imm(uint32_t ir)
{
	uint32_t imm = (ir >> 9) & 7;

	return imm == 0 ? UINT32_MAX : imm;
}

static void dcf_mov3q(m68k_info *info)
{
	cs_m68k *ext;
	cs_m68k_op *op0;
	cs_m68k_op *op1;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_ISA_B | CS_MODE_M68K_CF_ISA_C);

	ext = build_init_op(info, M68K_INS_MOV3Q, 2, 4);
	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	cf_build_imm_op(op0, cf_mov3q_imm(info->ir));
	get_ea_mode_op(info, op1, info->ir, 4);
}

static void cf_init_two_op(m68k_info *info, m68k_insn insn, cs_m68k_op **op0,
			   cs_m68k_op **op1)
{
	cs_m68k *ext = build_init_op(info, insn, 2, 4);

	*op0 = &ext->operands[0];
	*op1 = &ext->operands[1];
}

static m68k_reg cf_primary_acc_reg(const m68k_info *info)
{
	return m68k_has_feature(info, CS_MODE_M68K_CF_EMAC) ? M68K_REG_ACC0 :
							      M68K_REG_ACC;
}

static m68k_reg cf_accext_reg(uint32_t ir)
{
	return (ir & 0x0400) ? M68K_REG_ACCEXT23 : M68K_REG_ACCEXT01;
}

static void dcf_movclr_accn_reg(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_EMAC);
	cf_init_two_op(info, M68K_INS_MOVCLR, &op0, &op1);
	cf_build_reg_op(op0, cf_acc_reg((info->ir >> 9) & 3));
	cf_build_direct_reg_op(op1, cf_reg_from_nibble(info->ir & 0xf));
}

static void dcf_move_acc_reg(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_MAC);
	cf_init_two_op(info, M68K_INS_MOVE, &op0, &op1);
	cf_build_reg_op(op0, cf_primary_acc_reg(info));
	cf_build_direct_reg_op(op1, cf_reg_from_nibble(info->ir & 0xf));
}

static void dcf_move_accn_reg(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_EMAC);
	cf_init_two_op(info, M68K_INS_MOVE, &op0, &op1);
	cf_build_reg_op(op0, cf_acc_reg((info->ir >> 9) & 3));
	cf_build_direct_reg_op(op1, cf_reg_from_nibble(info->ir & 0xf));
}

static void dcf_move_acc_acc(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_EMAC);
	cf_init_two_op(info, M68K_INS_MOVE, &op0, &op1);
	cf_build_reg_op(op0, cf_acc_reg(info->ir & 3));
	cf_build_reg_op(op1, cf_acc_reg((info->ir >> 9) & 3));
}

static void dcf_move_reg_acc(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_MAC);
	cf_init_two_op(info, M68K_INS_MOVE, &op0, &op1);
	cf_build_direct_reg_op(op0, cf_reg_from_nibble(info->ir & 0xf));
	cf_build_reg_op(op1, cf_primary_acc_reg(info));
}

static void dcf_move_reg_accn(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_EMAC);
	cf_init_two_op(info, M68K_INS_MOVE, &op0, &op1);
	cf_build_direct_reg_op(op0, cf_reg_from_nibble(info->ir & 0xf));
	cf_build_reg_op(op1, cf_acc_reg((info->ir >> 9) & 3));
}

static void dcf_move_imm_acc(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_MAC);
	cf_init_two_op(info, M68K_INS_MOVE, &op0, &op1);
	cf_build_imm_op(op0, read_imm_32(info));
	cf_build_reg_op(op1, cf_primary_acc_reg(info));
}

static void dcf_move_imm_accn(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_EMAC);
	cf_init_two_op(info, M68K_INS_MOVE, &op0, &op1);
	cf_build_imm_op(op0, read_imm_32(info));
	cf_build_reg_op(op1, cf_acc_reg((info->ir >> 9) & 3));
}

static void dcf_move_accext_reg(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_EMAC);
	cf_init_two_op(info, M68K_INS_MOVE, &op0, &op1);
	cf_build_reg_op(op0, cf_accext_reg(info->ir));
	cf_build_direct_reg_op(op1, cf_reg_from_nibble(info->ir & 0xf));
}

static void dcf_move_reg_accext(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_EMAC);
	cf_init_two_op(info, M68K_INS_MOVE, &op0, &op1);
	cf_build_direct_reg_op(op0, cf_reg_from_nibble(info->ir & 0xf));
	cf_build_reg_op(op1, cf_accext_reg(info->ir));
}

static void dcf_move_imm_accext(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_EMAC);
	cf_init_two_op(info, M68K_INS_MOVE, &op0, &op1);
	cf_build_imm_op(op0, read_imm_32(info));
	cf_build_reg_op(op1, cf_accext_reg(info->ir));
}

static void dcf_move_macsr_reg(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_MAC);
	cf_init_two_op(info, M68K_INS_MOVE, &op0, &op1);
	cf_build_reg_op(op0, M68K_REG_MACSR);
	cf_build_direct_reg_op(op1, cf_reg_from_nibble(info->ir & 0xf));
}

static void dcf_move_reg_macsr(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_MAC);
	cf_init_two_op(info, M68K_INS_MOVE, &op0, &op1);
	cf_build_direct_reg_op(op0, cf_reg_from_nibble(info->ir & 0xf));
	cf_build_reg_op(op1, M68K_REG_MACSR);
}

static void dcf_move_imm_macsr(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_MAC);
	cf_init_two_op(info, M68K_INS_MOVE, &op0, &op1);
	cf_build_imm_op(op0, read_imm_32(info));
	cf_build_reg_op(op1, M68K_REG_MACSR);
}

static void dcf_move_mask_reg(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_MAC);
	cf_init_two_op(info, M68K_INS_MOVE, &op0, &op1);
	cf_build_reg_op(op0, M68K_REG_MASK);
	cf_build_direct_reg_op(op1, cf_reg_from_nibble(info->ir & 0xf));
}

static void dcf_move_reg_mask(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_MAC);
	cf_init_two_op(info, M68K_INS_MOVE, &op0, &op1);
	cf_build_direct_reg_op(op0, cf_reg_from_nibble(info->ir & 0xf));
	cf_build_reg_op(op1, M68K_REG_MASK);
}

static void dcf_move_imm_mask(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_MAC);
	cf_init_two_op(info, M68K_INS_MOVE, &op0, &op1);
	cf_build_imm_op(op0, read_imm_32(info));
	cf_build_reg_op(op1, M68K_REG_MASK);
}

static void dcf_move_macsr_ccr(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_MAC);
	cf_init_two_op(info, M68K_INS_MOVE, &op0, &op1);
	cf_build_reg_op(op0, M68K_REG_MACSR);
	cf_build_reg_op(op1, M68K_REG_CCR);
}

static void dcf_mac_arith(m68k_info *info)
{
	uint16_t ext_word;
	cs_m68k *ext;
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k_op *op;
	uint32_t src0;
	uint32_t src1;
	uint32_t update;
	uint32_t acc;
	bool is_memory;
	bool is_emac;
	int size;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_MAC);

	is_memory = !m68k_ea_is_register_direct(info->ir);
	if (is_memory && !cf_mac_ea_is_valid(info->ir)) {
		d68000_invalid(info);
		return;
	}

	ext_word = (uint16_t)read_imm_16(info);
	if (!is_memory && (ext_word & 0xf000)) {
		d68000_invalid(info);
		return;
	}

	is_emac = m68k_has_feature(info, CS_MODE_M68K_CF_EMAC) != 0;
	size = (ext_word & 0x0800) ? 4 : 2;

	ext = build_init_op(info,
			    (ext_word & 0x0100) ? M68K_INS_MSAC : M68K_INS_MAC,
			    is_memory ? 0 : 2, size);
	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	if (is_memory) {
		src0 = ext_word & 0xf;
		src1 = (ext_word >> 12) & 0xf;
		if (!(ext_word & 0x0800)) {
			if (ext_word & 0x40)
				src0 |= 0x10;
			if (ext_word & 0x80)
				src1 |= 0x10;
		}
	} else {
		src0 = info->ir & 0xf;
		src1 = ((info->ir >> 9) & 7) | ((info->ir & 0x40) ? 8 : 0);
		if (!(ext_word & 0x0800)) {
			if (ext_word & 0x40)
				src0 |= 0x10;
			if (ext_word & 0x80)
				src1 |= 0x10;
		}
	}

	cf_build_mac_reg_op(op0, src0, size == 4);
	cf_build_mac_reg_op(op1, src1, size == 4);
	ext->op_count = 2;

	if (ext_word & 0x0600) {
		op = &ext->operands[ext->op_count++];
		cf_build_shift_op(op, ext_word & 0x0600);
	}

	if (is_memory) {
		op = &ext->operands[ext->op_count++];
		get_ea_mode_op(info, op, info->ir, size);
		if (ext_word & 0x20)
			op->flags |= M68K_OP_FLAG_MEM_UPDATE;

		update = ((info->ir >> 9) & 7) | ((info->ir & 0x40) ? 8 : 0);
		op = &ext->operands[ext->op_count++];
		cf_build_direct_reg_op(op, cf_reg_from_nibble(update));
	}

	if (is_emac) {
		if (is_memory)
			acc = ((ext_word >> 3) & 0x2) |
			      ((~info->ir >> 7) & 0x1);
		else
			acc = ((info->ir & 0x80) ? 1 : 0) |
			      ((ext_word & 0x10) ? 2 : 0);
		op = &ext->operands[ext->op_count++];
		cf_build_reg_op(op, cf_acc_reg(acc));
	}
}

static void dcf_mvs_8(m68k_info *info)
{
	cs_m68k *ext;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_ISA_B | CS_MODE_M68K_CF_ISA_C);
	ext = build_init_op(info, M68K_INS_MVS, 2, 1);
	get_ea_mode_op(info, &ext->operands[0], info->ir, 1);
	cf_build_direct_reg_op(&ext->operands[1],
			       (m68k_reg)(M68K_REG_D0 + ((info->ir >> 9) & 7)));
}

static void dcf_mvs_16(m68k_info *info)
{
	cs_m68k *ext;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_ISA_B | CS_MODE_M68K_CF_ISA_C);
	ext = build_init_op(info, M68K_INS_MVS, 2, 2);
	get_ea_mode_op(info, &ext->operands[0], info->ir, 2);
	cf_build_direct_reg_op(&ext->operands[1],
			       (m68k_reg)(M68K_REG_D0 + ((info->ir >> 9) & 7)));
}

static void dcf_mvz_8(m68k_info *info)
{
	cs_m68k *ext;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_ISA_B | CS_MODE_M68K_CF_ISA_C);
	ext = build_init_op(info, M68K_INS_MVZ, 2, 1);
	get_ea_mode_op(info, &ext->operands[0], info->ir, 1);
	cf_build_direct_reg_op(&ext->operands[1],
			       (m68k_reg)(M68K_REG_D0 + ((info->ir >> 9) & 7)));
}

static void dcf_mvz_16(m68k_info *info)
{
	cs_m68k *ext;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_ISA_B | CS_MODE_M68K_CF_ISA_C);
	ext = build_init_op(info, M68K_INS_MVZ, 2, 2);
	get_ea_mode_op(info, &ext->operands[0], info->ir, 2);
	cf_build_direct_reg_op(&ext->operands[1],
			       (m68k_reg)(M68K_REG_D0 + ((info->ir >> 9) & 7)));
}

static void dcf_sats(m68k_info *info)
{
	LIMIT_FEATURE(info, CS_MODE_M68K_CF_ISA_B | CS_MODE_M68K_CF_ISA_C);
	build_d(info, M68K_INS_SATS, 4);
}

static void dcf_strldsr(m68k_info *info)
{
	cs_m68k *ext;
	cs_m68k_op *op;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_ISA_A_PLUS | CS_MODE_M68K_CF_ISA_C);

	(void)read_imm_16(info);
	ext = build_init_op(info, M68K_INS_STRLDSR, 1, 2);
	op = &ext->operands[0];
	cf_build_imm_op(op, read_imm_16(info));
}

static void dcf_wddata(m68k_info *info)
{
	int size_bits = (info->ir >> 6) & 3;
	int size;
	cs_m68k *ext;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_ISA_A);

	switch (size_bits) {
	case 0:
		size = 1;
		break;
	case 1:
		size = 2;
		break;
	case 2:
		size = 4;
		break;
	default:
		d68000_invalid(info);
		return;
	}

	if (!cf_alterable_memory_ea_is_valid(info->ir)) {
		d68000_invalid(info);
		return;
	}

	ext = build_init_op(info, M68K_INS_WDDATA, 1, size);
	get_ea_mode_op(info, &ext->operands[0], info->ir, size);
}

static void dcf_wdebug(m68k_info *info)
{
	cs_m68k *ext;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_ISA_A);

	if (read_imm_16(info) != 3) {
		d68000_invalid(info);
		return;
	}

	ext = build_init_op(info, M68K_INS_WDEBUG, 1, 4);
	get_ea_mode_op(info, &ext->operands[0], info->ir, 4);
}

static void dcf_intouch(m68k_info *info)
{
	cs_m68k *ext;
	cs_m68k_op *op;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_ISA_B | CS_MODE_M68K_CF_ISA_C);

	ext = build_init_op(info, M68K_INS_INTOUCH, 1, 0);
	op = &ext->operands[0];
	op->type = M68K_OP_MEM;
	op->address_mode = M68K_AM_REGI_ADDR;
	op->mem.base_reg = M68K_REG_A0 + (info->ir & 7);
}

static void dcf_build_coproc_branch(m68k_info *info, int opcode,
				    int displacement)
{
	cs_m68k_op *op;
	cs_m68k *ext = build_init_op(info, opcode, 1, 0);

	op = &ext->operands[0];
	op->type = M68K_OP_BR_DISP;
	op->address_mode = M68K_AM_BRANCH_DISPLACEMENT;
	op->br_disp.disp = displacement;
	op->br_disp.disp_size = 2;

	set_insn_group(info, M68K_GRP_JUMP);
	set_insn_group(info, M68K_GRP_BRANCH_RELATIVE);
}

static int cf_coproc_size(uint16_t ir)
{
	switch (ir & 0x00c0) {
	case 0x0000:
		return 1;
	case 0x0040:
		return 2;
	case 0x0080:
		return 4;
	default:
		return 0;
	}
}

static void dcf_cp0bcbusy(m68k_info *info)
{
	LIMIT_FEATURE(info, CS_MODE_M68K_CF_ISA_A);
	dcf_build_coproc_branch(info, M68K_INS_CP0BCBUSY,
				make_int_16(read_imm_16(info)));
}

static void dcf_cp1bcbusy(m68k_info *info)
{
	LIMIT_FEATURE(info, CS_MODE_M68K_CF_ISA_A);
	dcf_build_coproc_branch(info, M68K_INS_CP1BCBUSY,
				make_int_16(read_imm_16(info)));
}

static void dcf_coproc_ldst(m68k_info *info)
{
	uint16_t ext_word;
	bool cp1;
	bool store;
	int size;
	int opcode;
	cs_m68k *ext;

	LIMIT_FEATURE(info, CS_MODE_M68K_CF_ISA_A);

	size = cf_coproc_size(info->ir);
	if (!size || !cf_coproc_ea_is_valid(info->ir)) {
		d68000_invalid(info);
		return;
	}

	cp1 = (info->ir & 0x0200) != 0;
	store = (info->ir & 0x0100) != 0;
	ext_word = (uint16_t)read_imm_16(info);

	if (!store && m68k_ea_field(info->ir) == M68K_EA_DATA_DIRECT_D0 &&
	    (ext_word & 0xf1ff) == 0) {
		opcode = cp1 ? M68K_INS_CP1NOP : M68K_INS_CP0NOP;
		ext = build_init_op(info, opcode, 1, 0);
		cf_build_imm_op(&ext->operands[0], ((ext_word >> 9) & 7) + 1);
		return;
	}

	opcode = cp1 ? (store ? M68K_INS_CP1ST : M68K_INS_CP1LD) :
		       (store ? M68K_INS_CP0ST : M68K_INS_CP0LD);
	ext = build_init_op(info, opcode, 4, size);

	if (store) {
		cf_build_direct_reg_op(&ext->operands[0],
				       cf_reg_from_nibble((ext_word >> 12) &
							  0xf));
		get_ea_mode_op(info, &ext->operands[1], info->ir, size);
	} else {
		get_ea_mode_op(info, &ext->operands[0], info->ir, size);
		cf_build_direct_reg_op(&ext->operands[1],
				       cf_reg_from_nibble((ext_word >> 12) &
							  0xf));
	}

	cf_build_imm_op(&ext->operands[2], ((ext_word >> 9) & 7) + 1);
	cf_build_imm_op(&ext->operands[3], ext_word & 0x1ff);
}

static void d68000_abcd_rr(m68k_info *info)
{
	build_rr(info, M68K_INS_ABCD, 1, 0);
}

static void d68000_abcd_mm(m68k_info *info)
{
	build_mm(info, M68K_INS_ABCD, 1, 0);
}

static void d68000_add_er_8(m68k_info *info)
{
	build_er_1(info, M68K_INS_ADD, 1);
}

static void d68000_add_er_16(m68k_info *info)
{
	build_er_1(info, M68K_INS_ADD, 2);
}

static void d68000_add_er_32(m68k_info *info)
{
	build_er_1(info, M68K_INS_ADD, 4);
}

static void d68000_add_re_8(m68k_info *info)
{
	build_re_1(info, M68K_INS_ADD, 1);
}

static void d68000_add_re_16(m68k_info *info)
{
	build_re_1(info, M68K_INS_ADD, 2);
}

static void d68000_add_re_32(m68k_info *info)
{
	build_re_1(info, M68K_INS_ADD, 4);
}

static void d68000_adda_16(m68k_info *info)
{
	build_ea_a(info, M68K_INS_ADDA, 2);
}

static void d68000_adda_32(m68k_info *info)
{
	build_ea_a(info, M68K_INS_ADDA, 4);
}

static void d68000_addi_8(m68k_info *info)
{
	build_imm_ea(info, M68K_INS_ADDI, 1, read_imm_8(info));
}

static void d68000_addi_16(m68k_info *info)
{
	build_imm_ea(info, M68K_INS_ADDI, 2, read_imm_16(info));
}

static void d68000_addi_32(m68k_info *info)
{
	build_imm_ea(info, M68K_INS_ADDI, 4, read_imm_32(info));
}

static void d68000_addq_8(m68k_info *info)
{
	build_3bit_ea(info, M68K_INS_ADDQ, 1);
}

static void d68000_addq_16(m68k_info *info)
{
	build_3bit_ea(info, M68K_INS_ADDQ, 2);
}

static void d68000_addq_32(m68k_info *info)
{
	build_3bit_ea(info, M68K_INS_ADDQ, 4);
}

static void d68000_addx_rr_8(m68k_info *info)
{
	build_rr(info, M68K_INS_ADDX, 1, 0);
}

static void d68000_addx_rr_16(m68k_info *info)
{
	build_rr(info, M68K_INS_ADDX, 2, 0);
}

static void d68000_addx_rr_32(m68k_info *info)
{
	build_rr(info, M68K_INS_ADDX, 4, 0);
}

static void d68000_addx_mm_8(m68k_info *info)
{
	build_mm(info, M68K_INS_ADDX, 1, 0);
}

static void d68000_addx_mm_16(m68k_info *info)
{
	build_mm(info, M68K_INS_ADDX, 2, 0);
}

static void d68000_addx_mm_32(m68k_info *info)
{
	build_mm(info, M68K_INS_ADDX, 4, 0);
}

static void d68000_and_er_8(m68k_info *info)
{
	build_er_1(info, M68K_INS_AND, 1);
}

static void d68000_and_er_16(m68k_info *info)
{
	build_er_1(info, M68K_INS_AND, 2);
}

static void d68000_and_er_32(m68k_info *info)
{
	build_er_1(info, M68K_INS_AND, 4);
}

static void d68000_and_re_8(m68k_info *info)
{
	build_re_1(info, M68K_INS_AND, 1);
}

static void d68000_and_re_16(m68k_info *info)
{
	build_re_1(info, M68K_INS_AND, 2);
}

static void d68000_and_re_32(m68k_info *info)
{
	build_re_1(info, M68K_INS_AND, 4);
}

static void d68000_andi_8(m68k_info *info)
{
	build_imm_ea(info, M68K_INS_ANDI, 1, read_imm_8(info));
}

static void d68000_andi_16(m68k_info *info)
{
	build_imm_ea(info, M68K_INS_ANDI, 2, read_imm_16(info));
}

static void d68000_andi_32(m68k_info *info)
{
	build_imm_ea(info, M68K_INS_ANDI, 4, read_imm_32(info));
}

static void d68000_andi_to_ccr(m68k_info *info)
{
	build_imm_special_reg(info, M68K_INS_ANDI, read_imm_8(info), 1,
			      M68K_REG_CCR);
}

static void d68000_andi_to_sr(m68k_info *info)
{
	build_imm_special_reg(info, M68K_INS_ANDI, read_imm_16(info), 2,
			      M68K_REG_SR);
}

static void d68000_asr_s_8(m68k_info *info)
{
	build_3bit_d(info, M68K_INS_ASR, 1);
}

static void d68000_asr_s_16(m68k_info *info)
{
	build_3bit_d(info, M68K_INS_ASR, 2);
}

static void d68000_asr_s_32(m68k_info *info)
{
	build_3bit_d(info, M68K_INS_ASR, 4);
}

static void d68000_asr_r_8(m68k_info *info)
{
	build_r(info, M68K_INS_ASR, 1);
}

static void d68000_asr_r_16(m68k_info *info)
{
	build_r(info, M68K_INS_ASR, 2);
}

static void d68000_asr_r_32(m68k_info *info)
{
	build_r(info, M68K_INS_ASR, 4);
}

static void d68000_asr_ea(m68k_info *info)
{
	build_ea(info, M68K_INS_ASR, 2);
}

static void d68000_asl_s_8(m68k_info *info)
{
	build_3bit_d(info, M68K_INS_ASL, 1);
}

static void d68000_asl_s_16(m68k_info *info)
{
	build_3bit_d(info, M68K_INS_ASL, 2);
}

static void d68000_asl_s_32(m68k_info *info)
{
	build_3bit_d(info, M68K_INS_ASL, 4);
}

static void d68000_asl_r_8(m68k_info *info)
{
	build_r(info, M68K_INS_ASL, 1);
}

static void d68000_asl_r_16(m68k_info *info)
{
	build_r(info, M68K_INS_ASL, 2);
}

static void d68000_asl_r_32(m68k_info *info)
{
	build_r(info, M68K_INS_ASL, 4);
}

static void d68000_asl_ea(m68k_info *info)
{
	build_ea(info, M68K_INS_ASL, 2);
}

static void d68000_bcc_8(m68k_info *info)
{
	build_bcc(info, 1, make_int_8(info->ir));
}

static void d68000_bcc_16(m68k_info *info)
{
	build_bcc(info, 2, make_int_16(read_imm_16(info)));
}

static void d68020_bcc_32(m68k_info *info)
{
	LIMIT_FEATURE(info, M68020_PLUS | CS_MODE_M68K_CF_ISA_B |
				    CS_MODE_M68K_CF_ISA_C);
	build_bcc(info, 4, read_imm_32(info));
}

static void d68000_bchg_r(m68k_info *info)
{
	build_re_1(info, M68K_INS_BCHG, 1);
}

static void d68000_bchg_s(m68k_info *info)
{
	build_imm_ea(info, M68K_INS_BCHG, 1, read_imm_8(info));
}

static void d68000_bclr_r(m68k_info *info)
{
	build_re_1(info, M68K_INS_BCLR, 1);
}

static void d68000_bclr_s(m68k_info *info)
{
	build_imm_ea(info, M68K_INS_BCLR, 1, read_imm_8(info));
}

static void d68010_bkpt(m68k_info *info)
{
	LIMIT_FEATURE(info, M68010_PLUS);
	build_absolute_jump_with_immediate(info, M68K_INS_BKPT, 0,
					   info->ir & 7);
}

static void d68020_bfchg(m68k_info *info)
{
	/* Bit field ops are 68020+ only; CPU32 does NOT support them
	 * despite sharing CS_MODE_M68K_020. */
	LIMIT_FEATURE_EXCLUDING(info, M68020_PLUS, CS_MODE_M68K_CPU32);
	build_bitfield_ins(info, M68K_INS_BFCHG, false);
}

static void d68020_bfclr(m68k_info *info)
{
	LIMIT_FEATURE_EXCLUDING(info, M68020_PLUS, CS_MODE_M68K_CPU32);
	build_bitfield_ins(info, M68K_INS_BFCLR, false);
}

static void d68020_bfexts(m68k_info *info)
{
	LIMIT_FEATURE_EXCLUDING(info, M68020_PLUS, CS_MODE_M68K_CPU32);
	build_bitfield_ins(info, M68K_INS_BFEXTS, true);
}

static void d68020_bfextu(m68k_info *info)
{
	LIMIT_FEATURE_EXCLUDING(info, M68020_PLUS, CS_MODE_M68K_CPU32);
	build_bitfield_ins(info, M68K_INS_BFEXTU, true);
}

static void d68020_bfffo(m68k_info *info)
{
	LIMIT_FEATURE_EXCLUDING(info, M68020_PLUS, CS_MODE_M68K_CPU32);
	build_bitfield_ins(info, M68K_INS_BFFFO, true);
}

static void d68020_bfins(m68k_info *info)
{
	cs_m68k *ext = &info->extension;
	cs_m68k_op temp;

	LIMIT_FEATURE_EXCLUDING(info, M68020_PLUS, CS_MODE_M68K_CPU32);
	build_bitfield_ins(info, M68K_INS_BFINS, true);

	// a bit hacky but we need to flip the args on only this instruction

	temp = ext->operands[0];
	ext->operands[0] = ext->operands[1];
	ext->operands[1] = temp;
}

static void d68020_bfset(m68k_info *info)
{
	LIMIT_FEATURE_EXCLUDING(info, M68020_PLUS, CS_MODE_M68K_CPU32);
	build_bitfield_ins(info, M68K_INS_BFSET, false);
}

static void d68020_bftst(m68k_info *info)
{
	LIMIT_FEATURE_EXCLUDING(info, M68020_PLUS, CS_MODE_M68K_CPU32);
	build_bitfield_ins(info, M68K_INS_BFTST, false);
}

static void d68000_bra_8(m68k_info *info)
{
	build_relative_branch(info, M68K_INS_BRA, 1, make_int_8(info->ir));
}

static void d68000_bra_16(m68k_info *info)
{
	build_relative_branch(info, M68K_INS_BRA, 2,
			      make_int_16(read_imm_16(info)));
}

static void d68020_bra_32(m68k_info *info)
{
	LIMIT_FEATURE(info, M68020_PLUS | CS_MODE_M68K_CF_ISA_B |
				    CS_MODE_M68K_CF_ISA_C);
	build_relative_branch(info, M68K_INS_BRA, 4, read_imm_32(info));
}

static void d68000_bset_r(m68k_info *info)
{
	build_re_1(info, M68K_INS_BSET, 1);
}

static void d68000_bset_s(m68k_info *info)
{
	build_imm_ea(info, M68K_INS_BSET, 1, read_imm_8(info));
}

static void d68000_bsr_8(m68k_info *info)
{
	build_relative_branch(info, M68K_INS_BSR, 1, make_int_8(info->ir));
}

static void d68000_bsr_16(m68k_info *info)
{
	build_relative_branch(info, M68K_INS_BSR, 2,
			      make_int_16(read_imm_16(info)));
}

static void d68020_bsr_32(m68k_info *info)
{
	LIMIT_FEATURE(info, M68020_PLUS | CS_MODE_M68K_CF_ISA_B |
				    CS_MODE_M68K_CF_ISA_C);
	build_relative_branch(info, M68K_INS_BSR, 4, read_imm_32(info));
}

static void d68000_btst_r(m68k_info *info)
{
	build_re_1(info, M68K_INS_BTST, 2);
	ISIZE = 1;
}

static void d68000_btst_s(m68k_info *info)
{
	build_imm_ea(info, M68K_INS_BTST, 1, read_imm_8(info));
}

static void d68020_callm(m68k_info *info)
{
	LIMIT_FEATURE(info, M68020_ONLY);
	build_imm_ea(info, M68K_INS_CALLM, 0, read_imm_8(info));
}

static void d68020_cas_8(m68k_info *info)
{
	/*
	 * MC68060 traps CAS/CAS2/CHK2/CMP2 for software emulation, but they remain
	 * valid opcodes and must still disassemble successfully.
	 * CAS/CAS2 are NOT available on CPU32 despite its CS_MODE_M68K_020 overlap.
	 */
	LIMIT_FEATURE_EXCLUDING(info, M68020_PLUS, CS_MODE_M68K_CPU32);
	build_d_d_ea(info, M68K_INS_CAS, 1);
}

static void d68020_cas_16(m68k_info *info)
{
	LIMIT_FEATURE_EXCLUDING(info, M68020_PLUS, CS_MODE_M68K_CPU32);
	build_d_d_ea(info, M68K_INS_CAS, 2);
}

static void d68020_cas_32(m68k_info *info)
{
	LIMIT_FEATURE_EXCLUDING(info, M68020_PLUS, CS_MODE_M68K_CPU32);
	build_d_d_ea(info, M68K_INS_CAS, 4);
}

static void d68020_cas2_16(m68k_info *info)
{
	LIMIT_FEATURE_EXCLUDING(info, M68020_PLUS, CS_MODE_M68K_CPU32);
	build_cas2(info, 2);
}

static void d68020_cas2_32(m68k_info *info)
{
	LIMIT_FEATURE_EXCLUDING(info, M68020_PLUS, CS_MODE_M68K_CPU32);
	build_cas2(info, 4);
}

static void d68000_chk_16(m68k_info *info)
{
	build_er_1(info, M68K_INS_CHK, 2);
}

static void d68020_chk_32(m68k_info *info)
{
	LIMIT_FEATURE_EXCLUDING(info, M68020_PLUS, CS_MODE_M68K_CPU32);
	build_er_1(info, M68K_INS_CHK, 4);
}

static void d68020_chk2_cmp2_8(m68k_info *info)
{
	LIMIT_FEATURE(info, M68020_PLUS);
	build_chk2_cmp2(info, 1);
}

static void d68020_chk2_cmp2_16(m68k_info *info)
{
	LIMIT_FEATURE(info, M68020_PLUS);
	build_chk2_cmp2(info, 2);
}

static void d68020_chk2_cmp2_32(m68k_info *info)
{
	LIMIT_FEATURE(info, M68020_PLUS);
	build_chk2_cmp2(info, 4);
}

static void d68040_cinv(m68k_info *info)
{
	LIMIT_FEATURE(info, M68040_PLUS);
	build_cpush_cinv(info, M68K_INS_CINVL);
}

static void d68000_clr_8(m68k_info *info)
{
	build_ea(info, M68K_INS_CLR, 1);
}

static void d68000_clr_16(m68k_info *info)
{
	build_ea(info, M68K_INS_CLR, 2);
}

static void d68000_clr_32(m68k_info *info)
{
	build_ea(info, M68K_INS_CLR, 4);
}

static void d68000_cmp_8(m68k_info *info)
{
	build_er_1(info, M68K_INS_CMP, 1);
}

static void d68000_cmp_16(m68k_info *info)
{
	build_er_1(info, M68K_INS_CMP, 2);
}

static void d68000_cmp_32(m68k_info *info)
{
	build_er_1(info, M68K_INS_CMP, 4);
}

static void d68000_cmpa_16(m68k_info *info)
{
	build_ea_a(info, M68K_INS_CMPA, 2);
}

static void d68000_cmpa_32(m68k_info *info)
{
	build_ea_a(info, M68K_INS_CMPA, 4);
}

static void d68000_cmpi_8(m68k_info *info)
{
	build_imm_ea(info, M68K_INS_CMPI, 1, read_imm_8(info));
}

static void d68020_cmpi_pcdi_8(m68k_info *info)
{
	LIMIT_FEATURE(info, M68010_PLUS);
	build_imm_ea(info, M68K_INS_CMPI, 1, read_imm_8(info));
}

static void d68020_cmpi_pcix_8(m68k_info *info)
{
	LIMIT_FEATURE(info, M68010_PLUS);
	build_imm_ea(info, M68K_INS_CMPI, 1, read_imm_8(info));
}

static void d68000_cmpi_16(m68k_info *info)
{
	build_imm_ea(info, M68K_INS_CMPI, 2, read_imm_16(info));
}

static void d68020_cmpi_pcdi_16(m68k_info *info)
{
	LIMIT_FEATURE(info, M68010_PLUS);
	build_imm_ea(info, M68K_INS_CMPI, 2, read_imm_16(info));
}

static void d68020_cmpi_pcix_16(m68k_info *info)
{
	LIMIT_FEATURE(info, M68010_PLUS);
	build_imm_ea(info, M68K_INS_CMPI, 2, read_imm_16(info));
}

static void d68000_cmpi_32(m68k_info *info)
{
	build_imm_ea(info, M68K_INS_CMPI, 4, read_imm_32(info));
}

static void d68020_cmpi_pcdi_32(m68k_info *info)
{
	LIMIT_FEATURE(info, M68010_PLUS);
	build_imm_ea(info, M68K_INS_CMPI, 4, read_imm_32(info));
}

static void d68020_cmpi_pcix_32(m68k_info *info)
{
	LIMIT_FEATURE(info, M68010_PLUS);
	build_imm_ea(info, M68K_INS_CMPI, 4, read_imm_32(info));
}

static void d68000_cmpm_8(m68k_info *info)
{
	build_pi_pi(info, M68K_INS_CMPM, 1);
}

static void d68000_cmpm_16(m68k_info *info)
{
	build_pi_pi(info, M68K_INS_CMPM, 2);
}

static void d68000_cmpm_32(m68k_info *info)
{
	build_pi_pi(info, M68K_INS_CMPM, 4);
}

static void make_cpbcc_operand(cs_m68k_op *op, int size, int displacement)
{
	op->address_mode = M68K_AM_BRANCH_DISPLACEMENT;
	op->type = M68K_OP_BR_DISP;
	op->br_disp.disp = displacement;
	op->br_disp.disp_size = size;
}

static void d68020_cpbcc_16(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k *ext;
	LIMIT_FEATURE(info, M68020_PLUS | CS_MODE_M68K_CF_FPU);
	int cpid = M68K_CPID(info);
	int cond = M68K_IR_CONDITION(info);
	if (cpid == M68K_CPID_MMU) {
		if (cond >= M68K_PMMU_MAX_COND ||
		    m68k_has_feature(info, CS_MODE_M68K_CPU32)) {
			d68000_invalid(info);
			return;
		}
	} else if (cpid == M68K_CPID_FPU) {
		if (cond >= M68K_FPU_MAX_COND) {
			d68000_invalid(info);
			return;
		}
	} else {
		d68000_invalid(info);
		return;
	}

	if (info->ir == 0xf280 && peek_imm_16(info) == 0) {
		MCInst_setOpcode(info->inst, M68K_INS_FNOP);
		info->pc += 2;
		return;
	}

	ext = build_init_op(info, M68K_INS_FBF, 1, 2);
	info->inst->Opcode += M68K_FP_COND(info->ir);
	op0 = &ext->operands[0];

	make_cpbcc_operand(op0, M68K_OP_BR_DISP_SIZE_WORD,
			   make_int_16(read_imm_16(info)));

	set_insn_group(info, M68K_GRP_JUMP);
	set_insn_group(info, M68K_GRP_BRANCH_RELATIVE);
}

static void d68020_cpbcc_32(m68k_info *info)
{
	cs_m68k *ext;
	cs_m68k_op *op0;
	LIMIT_FEATURE(info, M68020_PLUS | CS_MODE_M68K_CF_FPU);
	int cpid = M68K_CPID(info);
	int cond = M68K_IR_CONDITION(info);
	if (cpid == M68K_CPID_MMU) {
		if (cond >= M68K_PMMU_MAX_COND ||
		    m68k_has_feature(info, CS_MODE_M68K_CPU32)) {
			d68000_invalid(info);
			return;
		}
	} else if (cpid == M68K_CPID_FPU) {
		if (cond >= M68K_FPU_MAX_COND) {
			d68000_invalid(info);
			return;
		}
	} else {
		d68000_invalid(info);
		return;
	}

	ext = build_init_op(info, M68K_INS_FBF, 1, 4);
	info->inst->Opcode += M68K_FP_COND(info->ir);
	op0 = &ext->operands[0];

	make_cpbcc_operand(op0, M68K_OP_BR_DISP_SIZE_LONG, read_imm_32(info));

	set_insn_group(info, M68K_GRP_JUMP);
	set_insn_group(info, M68K_GRP_BRANCH_RELATIVE);
}

static void d68020_cpdbcc(m68k_info *info)
{
	cs_m68k *ext;
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	uint32_t ext1, ext2;

	LIMIT_FEATURE(info, M68020_PLUS | CS_MODE_M68K_CF_FPU);

	if (M68K_CPID(info) == M68K_CPID_CACHE &&
	    m68k_has_feature(info, M68040_PLUS)) {
		if (M68K_IR_IS_CPUSH(info))
			d68040_cpush(info);
		else
			d68040_cinv(info);
		return;
	}

	REQUIRE_CPID_FPU(info);

	ext1 = read_imm_16(info);
	ext2 = read_imm_16(info);

	info->inst->Opcode += M68K_FP_COND(ext1);

	ext = build_init_op(info, M68K_INS_FDBF, 2, 0);
	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	op0->reg = M68K_REG_D0 + (info->ir & 7);

	make_cpbcc_operand(op1, M68K_OP_BR_DISP_SIZE_WORD,
			   make_int_16(ext2) + 2);

	set_insn_group(info, M68K_GRP_JUMP);
	set_insn_group(info, M68K_GRP_BRANCH_RELATIVE);
}

static void fmove_fpcr(m68k_info *info, uint32_t extension)
{
	cs_m68k_op *special;
	cs_m68k_op *op_ea;

	int regsel = M68K_FEXT_REGSEL(extension);
	int dir = M68K_FEXT_DIR(extension);

	cs_m68k *ext = build_init_op(info, M68K_INS_FMOVE, 2, 4);

	special = &ext->operands[0];
	op_ea = &ext->operands[1];

	if (!dir) {
		cs_m68k_op *t = special;
		special = op_ea;
		op_ea = t;
	}

	get_ea_mode_op(info, op_ea, info->ir, 4);

	if (regsel & 4)
		special->reg = M68K_REG_FPCR;
	else if (regsel & 2)
		special->reg = M68K_REG_FPSR;
	else if (regsel & 1)
		special->reg = M68K_REG_FPIAR;
}

static void fmovem(m68k_info *info, uint32_t extension)
{
	cs_m68k_op *op_reglist;
	cs_m68k_op *op_ea;
	int dir = M68K_FEXT_DIR(extension);
	int mode = (extension >> 11) & 0x3;
	uint32_t reglist = extension & 0xff;
	cs_m68k *ext = build_init_op(info, M68K_INS_FMOVEM, 2, 0);

	op_reglist = &ext->operands[0];
	op_ea = &ext->operands[1];

	// flip args around

	if (!dir) {
		cs_m68k_op *t = op_reglist;
		op_reglist = op_ea;
		op_ea = t;
	}

	get_ea_mode_op(info, op_ea, info->ir, 0);

	switch (mode) {
	case 1: // Dynamic list in dn register
		op_reglist->reg = M68K_REG_D0 + ((reglist >> 4) & 7);
		break;

	case 0:
		op_reglist->address_mode = M68K_AM_NONE;
		op_reglist->type = M68K_OP_REG_BITS;
		op_reglist->register_bits = reglist << 16;
		break;

	case 2: // Static list
		op_reglist->address_mode = M68K_AM_NONE;
		op_reglist->type = M68K_OP_REG_BITS;
		op_reglist->register_bits = ((uint32_t)reverse_bits_8(reglist))
					    << 16;
		break;
	default:
		break;
	}
}

static void d68020_cpgen(m68k_info *info)
{
	cs_m68k *ext;
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	bool supports_single_op;
	uint32_t next;
	int rm, src, dst, opmode;

	LIMIT_FEATURE(info, M68020_PLUS | CS_MODE_M68K_CF_FPU);

	if (M68K_CPID(info) == M68K_CPID_MMU &&
	    m68k_has_feature(info, CS_MODE_M68K_030)) {
		d68030_pmmu(info);
		return;
	}

	if (M68K_CPID(info) != M68K_CPID_FPU) {
		d68000_invalid(info);
		return;
	}

	supports_single_op = true;

	/* 68040+ single/double-precision FPU opcodes (SD flag set in command
	 * word) must be rejected on pre-68040 CPUs.  Only guard general FPU
	 * operations (type 0-1); fmove_fpcr/fmovem types are dispatched
	 * separately and never reach the SD path. */
	uint32_t peeked = peek_imm_16(info);
	if (M68K_FEXT_TYPE(peeked) <= 1 && M68K_FEXT_SD_FLAG(peeked))
		LIMIT_FEATURE(info, M68040_PLUS | CS_MODE_M68K_CF_FPU);

	next = read_imm_16(info);

	rm = M68K_FEXT_RM(next);
	src = M68K_FEXT_SRC(next);
	dst = M68K_FEXT_DST(next);
	opmode = M68K_FEXT_OPMODE(next);

	if (BITFIELD(info->ir, 5, 0) == 0 && M68K_FEXT_IS_FMOVECR(next)) {
		ext = build_init_op(info, M68K_INS_FMOVECR, 2, 0);

		op0 = &ext->operands[0];
		op1 = &ext->operands[1];

		op0->address_mode = M68K_AM_IMMEDIATE;
		op0->type = M68K_OP_IMM;
		op0->imm = M68K_FEXT_OPMODE(next);

		op1->reg = M68K_REG_FP0 + M68K_FEXT_DST(next);

		return;
	}

	switch (M68K_FEXT_TYPE(next)) {
	case 0x4:
	case 0x5:
		fmove_fpcr(info, next);
		return;

	case 0x6:
	case 0x7:
		fmovem(info, next);
		return;
	default:
		break;
	}

	if (M68K_FEXT_SD_FLAG(next)) {
		if (opmode == M68K_FPOP_FSSQRT_RAW) {
			MCInst_setOpcode(info->inst, M68K_INS_FSSQRT);
			goto fpu_operands;
		} else if (opmode == M68K_FPOP_FDSQRT_RAW) {
			MCInst_setOpcode(info->inst, M68K_INS_FDSQRT);
			goto fpu_operands;
		}
		opmode &= ~4;
	}

	switch (opmode) {
	case 0x00:
		MCInst_setOpcode(info->inst, M68K_INS_FMOVE);
		supports_single_op = false;
		break;
	case 0x01:
		MCInst_setOpcode(info->inst, M68K_INS_FINT);
		break;
	case 0x02:
		MCInst_setOpcode(info->inst, M68K_INS_FSINH);
		break;
	case 0x03:
		MCInst_setOpcode(info->inst, M68K_INS_FINTRZ);
		break;
	case 0x04:
		MCInst_setOpcode(info->inst, M68K_INS_FSQRT);
		break;
	case 0x06:
		MCInst_setOpcode(info->inst, M68K_INS_FLOGNP1);
		break;
	case 0x08:
		MCInst_setOpcode(info->inst, M68K_INS_FETOXM1);
		break;
	case 0x09:
		MCInst_setOpcode(info->inst, M68K_INS_FATANH);
		break;
	case 0x0a:
		MCInst_setOpcode(info->inst, M68K_INS_FATAN);
		break;
	case 0x0c:
		MCInst_setOpcode(info->inst, M68K_INS_FASIN);
		break;
	case 0x0d:
		MCInst_setOpcode(info->inst, M68K_INS_FATANH);
		break;
	case 0x0e:
		MCInst_setOpcode(info->inst, M68K_INS_FSIN);
		break;
	case 0x0f:
		MCInst_setOpcode(info->inst, M68K_INS_FTAN);
		break;
	case 0x10:
		MCInst_setOpcode(info->inst, M68K_INS_FETOX);
		break;
	case 0x11:
		MCInst_setOpcode(info->inst, M68K_INS_FTWOTOX);
		break;
	case 0x12:
		MCInst_setOpcode(info->inst, M68K_INS_FTENTOX);
		break;
	case 0x14:
		MCInst_setOpcode(info->inst, M68K_INS_FLOGN);
		break;
	case 0x15:
		MCInst_setOpcode(info->inst, M68K_INS_FLOG10);
		break;
	case 0x16:
		MCInst_setOpcode(info->inst, M68K_INS_FLOG2);
		break;
	case 0x18:
		MCInst_setOpcode(info->inst, M68K_INS_FABS);
		break;
	case 0x19:
		MCInst_setOpcode(info->inst, M68K_INS_FCOSH);
		break;
	case 0x1a:
		MCInst_setOpcode(info->inst, M68K_INS_FNEG);
		break;
	case 0x1c:
		MCInst_setOpcode(info->inst, M68K_INS_FACOS);
		break;
	case 0x1d:
		MCInst_setOpcode(info->inst, M68K_INS_FCOS);
		break;
	case 0x1e:
		MCInst_setOpcode(info->inst, M68K_INS_FGETEXP);
		break;
	case 0x1f:
		MCInst_setOpcode(info->inst, M68K_INS_FGETMAN);
		break;
	case 0x20:
		MCInst_setOpcode(info->inst, M68K_INS_FDIV);
		supports_single_op = false;
		break;
	case 0x21:
		MCInst_setOpcode(info->inst, M68K_INS_FMOD);
		supports_single_op = false;
		break;
	case 0x22:
		MCInst_setOpcode(info->inst, M68K_INS_FADD);
		supports_single_op = false;
		break;
	case 0x23:
		MCInst_setOpcode(info->inst, M68K_INS_FMUL);
		supports_single_op = false;
		break;
	case 0x24:
		MCInst_setOpcode(info->inst, M68K_INS_FSGLDIV);
		supports_single_op = false;
		break;
	case 0x25:
		MCInst_setOpcode(info->inst, M68K_INS_FREM);
		break;
	case 0x26:
		MCInst_setOpcode(info->inst, M68K_INS_FSCALE);
		break;
	case 0x27:
		MCInst_setOpcode(info->inst, M68K_INS_FSGLMUL);
		break;
	case 0x28:
		MCInst_setOpcode(info->inst, M68K_INS_FSUB);
		supports_single_op = false;
		break;
	case 0x38:
		MCInst_setOpcode(info->inst, M68K_INS_FCMP);
		supports_single_op = false;
		break;
	case 0x3a:
		MCInst_setOpcode(info->inst, M68K_INS_FTST);
		break;
	default:
		break;
	}

	if (M68K_FEXT_SD_FLAG(next)) {
		if ((next >> 2) & 1)
			info->inst->Opcode += 2;
		else
			info->inst->Opcode += 1;
	}

fpu_operands:
	ext = &info->extension;

	ext->op_count = 2;
	ext->op_size.type = M68K_SIZE_TYPE_CPU;
	ext->op_size.cpu_size = 0;

	if ((opmode == 0x00) && M68K_FEXT_DIR(next) != 0) {
		op0 = &ext->operands[1];
		op1 = &ext->operands[0];
	} else {
		op0 = &ext->operands[0];
		op1 = &ext->operands[1];
	}

	if (rm == 0 && supports_single_op && src == dst) {
		ext->op_count = 1;
		op0->reg = M68K_REG_FP0 + dst;
		return;
	}

	if (rm == 1) {
		switch (src) {
		case M68K_FPSRC_LONG:
			ext->op_size.cpu_size = M68K_CPU_SIZE_LONG;
			get_ea_mode_op(info, op0, info->ir, 4);
			break;

		case M68K_FPSRC_BYTE:
			ext->op_size.cpu_size = M68K_CPU_SIZE_BYTE;
			get_ea_mode_op(info, op0, info->ir, 1);
			break;

		case M68K_FPSRC_WORD:
			ext->op_size.cpu_size = M68K_CPU_SIZE_WORD;
			get_ea_mode_op(info, op0, info->ir, 2);
			break;

		case M68K_FPSRC_SINGLE:
			ext->op_size.type = M68K_SIZE_TYPE_FPU;
			ext->op_size.fpu_size = M68K_FPU_SIZE_SINGLE;
			get_ea_mode_op(info, op0, info->ir, 4);
			if (op0->address_mode == M68K_AM_IMMEDIATE) {
				op0->simm = BitsToFloat(op0->imm);
				op0->type = M68K_OP_FP_SINGLE;
			}
			break;

		case M68K_FPSRC_DOUBLE:
			ext->op_size.type = M68K_SIZE_TYPE_FPU;
			ext->op_size.fpu_size = M68K_FPU_SIZE_DOUBLE;
			get_ea_mode_op(info, op0, info->ir, 8);
			if (op0->address_mode == M68K_AM_IMMEDIATE)
				op0->type = M68K_OP_FP_DOUBLE;
			break;

		case M68K_FPSRC_EXTENDED:
			ext->op_size.type = M68K_SIZE_TYPE_FPU;
			ext->op_size.fpu_size = M68K_FPU_SIZE_EXTENDED;
			get_ea_mode_op(info, op0, info->ir, 12);
			break;

		case M68K_FPSRC_PACKED:
			ext->op_size.type = M68K_SIZE_TYPE_FPU;
			ext->op_size.fpu_size = M68K_FPU_SIZE_EXTENDED;
			get_ea_mode_op(info, op0, info->ir, 12);
			break;

		default:
			ext->op_size.type = M68K_SIZE_TYPE_FPU;
			ext->op_size.fpu_size = M68K_FPU_SIZE_EXTENDED;
			break;
		}
	} else {
		op0->reg = M68K_REG_FP0 + src;
	}

	op1->reg = M68K_REG_FP0 + dst;
}

static void d68020_cprestore(m68k_info *info)
{
	cs_m68k *ext;
	LIMIT_FEATURE(info, M68020_PLUS | CS_MODE_M68K_CF_FPU);
	REQUIRE_CPID_FPU(info);

	ext = build_init_op(info, M68K_INS_FRESTORE, 1, 0);
	get_ea_mode_op(info, &ext->operands[0], info->ir, 1);
}

static void d68020_cpsave(m68k_info *info)
{
	cs_m68k *ext;
	LIMIT_FEATURE(info, M68020_PLUS | CS_MODE_M68K_CF_FPU);
	REQUIRE_CPID_FPU(info);

	ext = build_init_op(info, M68K_INS_FSAVE, 1, 0);
	get_ea_mode_op(info, &ext->operands[0], info->ir, 1);
}

static void d68040_pflush_or_cpsave(m68k_info *info)
{
	if (m68k_has_feature(info, M68040_PLUS)) {
		d68040_pflush(info);
		return;
	}
	d68020_cpsave(info);
}

static void d68040_ptest_or_cprestore(m68k_info *info)
{
	if (m68k_has_feature(info, CS_MODE_M68K_040)) {
		d68040_ptest(info);
		return;
	}
	if (m68k_has_feature(info, CS_MODE_M68K_060)) {
		d68000_invalid(info);
		return;
	}
	d68020_cprestore(info);
}

static void d68020_cpscc(m68k_info *info)
{
	cs_m68k *ext;
	LIMIT_FEATURE(info, M68020_PLUS | CS_MODE_M68K_CF_FPU);
	REQUIRE_CPID_FPU(info);
	ext = build_init_op(info, M68K_INS_FSF, 1, 1);
	info->inst->Opcode += M68K_FP_COND(read_imm_16(info));

	get_ea_mode_op(info, &ext->operands[0], info->ir, 1);
}

static void d68020_cptrapcc_0(m68k_info *info)
{
	uint32_t extension1;
	LIMIT_FEATURE(info, M68020_PLUS | CS_MODE_M68K_CF_FPU);
	REQUIRE_CPID_FPU(info);

	extension1 = read_imm_16(info);

	build_init_op(info, M68K_INS_FTRAPF, 0, 0);
	info->inst->Opcode += M68K_FP_COND(extension1);
}

static void d68020_cptrapcc_16(m68k_info *info)
{
	uint32_t extension1, extension2;
	cs_m68k_op *op0;
	cs_m68k *ext;
	LIMIT_FEATURE(info, M68020_PLUS | CS_MODE_M68K_CF_FPU);
	REQUIRE_CPID_FPU(info);

	extension1 = read_imm_16(info);
	extension2 = read_imm_16(info);

	ext = build_init_op(info, M68K_INS_FTRAPF, 1, 2);
	info->inst->Opcode += M68K_FP_COND(extension1);

	op0 = &ext->operands[0];

	op0->address_mode = M68K_AM_IMMEDIATE;
	op0->type = M68K_OP_IMM;
	op0->imm = extension2;
}

static void d68020_cptrapcc_32(m68k_info *info)
{
	uint32_t extension1, extension2;
	cs_m68k *ext;
	cs_m68k_op *op0;
	LIMIT_FEATURE(info, M68020_PLUS | CS_MODE_M68K_CF_FPU);
	REQUIRE_CPID_FPU(info);

	extension1 = read_imm_16(info);
	extension2 = read_imm_32(info);

	ext = build_init_op(info, M68K_INS_FTRAPF, 1, 2);
	info->inst->Opcode += M68K_FP_COND(extension1);

	op0 = &ext->operands[0];

	op0->address_mode = M68K_AM_IMMEDIATE;
	op0->type = M68K_OP_IMM;
	op0->imm = extension2;
}

static void d68040_cpush(m68k_info *info)
{
	LIMIT_FEATURE(info, M68040_PLUS | CS_MODE_M68K_CF_ISA_A);
	if (m68k_has_feature(info, CS_MODE_M68K_COLDFIRE) &&
	    M68K_IR_CACHE_SCOPE(info) != 1) {
		d68000_invalid(info);
		return;
	}
	build_cpush_cinv(info, M68K_INS_CPUSHL);
}

static void d68000_dbra(m68k_info *info)
{
	build_dbxx(info, M68K_INS_DBRA, 0, make_int_16(read_imm_16(info)));
}

static void d68000_dbcc(m68k_info *info)
{
	build_dbcc(info, 0, make_int_16(read_imm_16(info)));
}

static void d68000_divs(m68k_info *info)
{
	build_er_1(info, M68K_INS_DIVS, 2);
}

static void d68000_divu(m68k_info *info)
{
	build_er_1(info, M68K_INS_DIVU, 2);
}

static void d68020_divl(m68k_info *info)
{
	uint32_t extension, insn_signed;
	bool cf_remainder;
	cs_m68k *ext;
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	uint32_t reg_0, reg_1;
	m68k_insn opcode;

	LIMIT_FEATURE(info, M68020_PLUS | CS_MODE_M68K_CF_DIV);

	extension = read_imm_16(info);
	insn_signed = 0;

	if (BIT_B((extension)))
		insn_signed = 1;

	reg_0 = extension & 7;
	reg_1 = (extension >> 12) & 7;
	cf_remainder = m68k_has_feature(info, CS_MODE_M68K_CF_DIV) &&
		       !BIT_A(extension) && (reg_0 != reg_1);

	if (cf_remainder)
		opcode = insn_signed ? M68K_INS_REMS : M68K_INS_REMU;
	else
		opcode = insn_signed ? M68K_INS_DIVS : M68K_INS_DIVU;

	ext = build_init_op(info, opcode, 2, 4);
	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	get_ea_mode_op(info, op0, info->ir, 4);

	op1->address_mode = M68K_AM_NONE;
	op1->type = M68K_OP_REG_PAIR;
	op1->reg_pair.reg_0 = reg_0 + M68K_REG_D0;
	op1->reg_pair.reg_1 = reg_1 + M68K_REG_D0;

	if ((reg_0 == reg_1) || (!BIT_A(extension) && !cf_remainder)) {
		op1->type = M68K_OP_REG;
		op1->reg = M68K_REG_D0 + reg_1;
	}
}

static void d68000_eor_8(m68k_info *info)
{
	build_re_1(info, M68K_INS_EOR, 1);
}

static void d68000_eor_16(m68k_info *info)
{
	build_re_1(info, M68K_INS_EOR, 2);
}

static void d68000_eor_32(m68k_info *info)
{
	build_re_1(info, M68K_INS_EOR, 4);
}

static void d68000_eori_8(m68k_info *info)
{
	build_imm_ea(info, M68K_INS_EORI, 1, read_imm_8(info));
}

static void d68000_eori_16(m68k_info *info)
{
	build_imm_ea(info, M68K_INS_EORI, 2, read_imm_16(info));
}

static void d68000_eori_32(m68k_info *info)
{
	build_imm_ea(info, M68K_INS_EORI, 4, read_imm_32(info));
}

static void d68000_eori_to_ccr(m68k_info *info)
{
	build_imm_special_reg(info, M68K_INS_EORI, read_imm_8(info), 1,
			      M68K_REG_CCR);
}

static void d68000_eori_to_sr(m68k_info *info)
{
	build_imm_special_reg(info, M68K_INS_EORI, read_imm_16(info), 2,
			      M68K_REG_SR);
}

static void d68000_exg_dd(m68k_info *info)
{
	build_r(info, M68K_INS_EXG, 4);
}

static void d68000_exg_aa(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, M68K_INS_EXG, 2, 4);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	op0->address_mode = M68K_AM_NONE;
	op0->reg = M68K_REG_A0 + ((info->ir >> 9) & 7);

	op1->address_mode = M68K_AM_NONE;
	op1->reg = M68K_REG_A0 + (info->ir & 7);
}

static void d68000_exg_da(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, M68K_INS_EXG, 2, 4);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	op0->address_mode = M68K_AM_NONE;
	op0->reg = M68K_REG_D0 + ((info->ir >> 9) & 7);

	op1->address_mode = M68K_AM_NONE;
	op1->reg = M68K_REG_A0 + (info->ir & 7);
}

static void d68000_ext_16(m68k_info *info)
{
	build_d(info, M68K_INS_EXT, 2);
}

static void d68000_ext_32(m68k_info *info)
{
	build_d(info, M68K_INS_EXT, 4);
}

static void d68020_extb_32(m68k_info *info)
{
	LIMIT_FEATURE(info, M68020_PLUS | CS_MODE_M68K_CF_ISA_A);
	build_d(info, M68K_INS_EXTB, 4);
}

static void d68000_jmp(m68k_info *info)
{
	cs_m68k *ext = build_init_op(info, M68K_INS_JMP, 1, 0);
	set_insn_group(info, M68K_GRP_JUMP);
	get_ea_mode_op(info, &ext->operands[0], info->ir, 4);
}

static void d68000_jsr(m68k_info *info)
{
	cs_m68k *ext = build_init_op(info, M68K_INS_JSR, 1, 0);
	set_insn_group(info, M68K_GRP_JUMP);
	get_ea_mode_op(info, &ext->operands[0], info->ir, 4);
}

static void d68000_lea(m68k_info *info)
{
	build_ea_a(info, M68K_INS_LEA, 4);
}

static void d68000_link_16(m68k_info *info)
{
	build_link(info, read_imm_16(info), 2);
}

static void d68020_link_32(m68k_info *info)
{
	LIMIT_FEATURE(info, M68020_PLUS);
	build_link(info, read_imm_32(info), 4);
}

static void d68000_lsr_s_8(m68k_info *info)
{
	build_3bit_d(info, M68K_INS_LSR, 1);
}

static void d68000_lsr_s_16(m68k_info *info)
{
	build_3bit_d(info, M68K_INS_LSR, 2);
}

static void d68000_lsr_s_32(m68k_info *info)
{
	build_3bit_d(info, M68K_INS_LSR, 4);
}

static void d68000_lsr_r_8(m68k_info *info)
{
	build_r(info, M68K_INS_LSR, 1);
}

static void d68000_lsr_r_16(m68k_info *info)
{
	build_r(info, M68K_INS_LSR, 2);
}

static void d68000_lsr_r_32(m68k_info *info)
{
	build_r(info, M68K_INS_LSR, 4);
}

static void d68000_lsr_ea(m68k_info *info)
{
	build_ea(info, M68K_INS_LSR, 2);
}

static void d68000_lsl_s_8(m68k_info *info)
{
	build_3bit_d(info, M68K_INS_LSL, 1);
}

static void d68000_lsl_s_16(m68k_info *info)
{
	build_3bit_d(info, M68K_INS_LSL, 2);
}

static void d68000_lsl_s_32(m68k_info *info)
{
	build_3bit_d(info, M68K_INS_LSL, 4);
}

static void d68000_lsl_r_8(m68k_info *info)
{
	build_r(info, M68K_INS_LSL, 1);
}

static void d68000_lsl_r_16(m68k_info *info)
{
	build_r(info, M68K_INS_LSL, 2);
}

static void d68000_lsl_r_32(m68k_info *info)
{
	build_r(info, M68K_INS_LSL, 4);
}

static void d68000_lsl_ea(m68k_info *info)
{
	build_ea(info, M68K_INS_LSL, 2);
}

static void d68000_move_8(m68k_info *info)
{
	build_ea_ea(info, M68K_INS_MOVE, 1);
}

static void d68000_move_16(m68k_info *info)
{
	build_ea_ea(info, M68K_INS_MOVE, 2);
}

static void d68000_move_32(m68k_info *info)
{
	build_ea_ea(info, M68K_INS_MOVE, 4);
}

static void d68000_movea_16(m68k_info *info)
{
	build_ea_a(info, M68K_INS_MOVEA, 2);
}

static void d68000_movea_32(m68k_info *info)
{
	build_ea_a(info, M68K_INS_MOVEA, 4);
}

static void d68000_move_to_ccr(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, M68K_INS_MOVE, 2, 2);

	if (m68k_has_feature(info, CS_MODE_M68K_COLDFIRE) &&
	    (!m68k_has_feature(info, CS_MODE_M68K_CF_ISA_A) ||
	     !cf_sr_ccr_source_ea_is_valid(info->ir))) {
		d68000_invalid(info);
		return;
	}

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	get_ea_mode_op(info, op0, info->ir, 1);

	op1->address_mode = M68K_AM_NONE;
	op1->reg = M68K_REG_CCR;
}

static void d68010_move_fr_ccr(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext;

	LIMIT_FEATURE(info, M68010_PLUS | CS_MODE_M68K_CF_ISA_A);

	if (m68k_has_feature(info, CS_MODE_M68K_COLDFIRE) &&
	    !cf_sr_ccr_destination_ea_is_valid(info->ir)) {
		d68000_invalid(info);
		return;
	}

	ext = build_init_op(info, M68K_INS_MOVE, 2, 2);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	op0->address_mode = M68K_AM_NONE;
	op0->reg = M68K_REG_CCR;

	get_ea_mode_op(info, op1, info->ir, 1);
}

static void d68000_move_fr_sr(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, M68K_INS_MOVE, 2, 2);

	if (m68k_has_feature(info, CS_MODE_M68K_COLDFIRE) &&
	    (!m68k_has_feature(info, CS_MODE_M68K_CF_ISA_A) ||
	     !cf_sr_ccr_destination_ea_is_valid(info->ir))) {
		d68000_invalid(info);
		return;
	}

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	op0->address_mode = M68K_AM_NONE;
	op0->reg = M68K_REG_SR;

	get_ea_mode_op(info, op1, info->ir, 2);
}

static void d68000_move_to_sr(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, M68K_INS_MOVE, 2, 2);

	if (m68k_has_feature(info, CS_MODE_M68K_COLDFIRE) &&
	    (!m68k_has_feature(info, CS_MODE_M68K_CF_ISA_A) ||
	     !cf_sr_ccr_source_ea_is_valid(info->ir))) {
		d68000_invalid(info);
		return;
	}

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	get_ea_mode_op(info, op0, info->ir, 2);

	op1->address_mode = M68K_AM_NONE;
	op1->reg = M68K_REG_SR;
}

static void d68000_move_fr_usp(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, M68K_INS_MOVE, 2, 0);

	if (m68k_has_feature(info, CS_MODE_M68K_COLDFIRE) &&
	    !m68k_has_feature(info, CS_MODE_M68K_CF_USP)) {
		d68000_invalid(info);
		return;
	}

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	op0->address_mode = M68K_AM_NONE;
	op0->reg = M68K_REG_USP;

	op1->address_mode = M68K_AM_NONE;
	op1->reg = M68K_REG_A0 + (info->ir & 7);
}

static void d68000_move_to_usp(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	cs_m68k *ext = build_init_op(info, M68K_INS_MOVE, 2, 0);

	if (m68k_has_feature(info, CS_MODE_M68K_COLDFIRE) &&
	    !m68k_has_feature(info, CS_MODE_M68K_CF_USP)) {
		d68000_invalid(info);
		return;
	}

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	op0->address_mode = M68K_AM_NONE;
	op0->reg = M68K_REG_A0 + (info->ir & 7);

	op1->address_mode = M68K_AM_NONE;
	op1->reg = M68K_REG_USP;
}

static void d68010_movec(m68k_info *info)
{
	uint32_t extension;
	m68k_reg reg;
	cs_m68k *ext;
	cs_m68k_op *op0;
	cs_m68k_op *op1;

	LIMIT_FEATURE(info, M68010_PLUS | CS_MODE_M68K_CF_ISA_A);

	extension = read_imm_16(info);
	reg = M68K_REG_INVALID;

	ext = build_init_op(info, M68K_INS_MOVEC, 2, 0);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	switch (extension & 0xfff) {
	case 0x000:
		reg = M68K_REG_SFC;
		break;
	case 0x001:
		reg = M68K_REG_DFC;
		break;
	case 0x800:
		reg = M68K_REG_USP;
		break;
	case 0x801:
		reg = M68K_REG_VBR;
		break;
	case 0x002:
		reg = M68K_REG_CACR;
		break;
	case 0x802:
		reg = M68K_REG_CAAR;
		break;
	case 0x803:
		reg = M68K_REG_MSP;
		break;
	case 0x804:
		reg = M68K_REG_ISP;
		break;
	case 0x003:
		reg = M68K_REG_TC;
		break;
	case 0x004:
		reg = M68K_REG_ITT0;
		break;
	case 0x005:
		reg = M68K_REG_ITT1;
		break;
	case 0x006:
		reg = M68K_REG_DTT0;
		break;
	case 0x007:
		reg = M68K_REG_DTT1;
		break;
	case 0x805:
		reg = M68K_REG_MMUSR;
		break;
	case 0x806:
		reg = M68K_REG_URP;
		break;
	case 0x807:
		reg = M68K_REG_SRP;
		break;
	default:
		break;
	}

	if (BIT_0(info->ir)) {
		op0->reg = (BIT_F(extension) ? M68K_REG_A0 : M68K_REG_D0) +
			   ((extension >> 12) & 7);
		op1->reg = reg;
	} else {
		op0->reg = reg;
		op1->reg = (BIT_F(extension) ? M68K_REG_A0 : M68K_REG_D0) +
			   ((extension >> 12) & 7);
	}
}

static void d68000_movem_pd_16(m68k_info *info)
{
	build_movem_re(info, M68K_INS_MOVEM, 2);
}

static void d68000_movem_pd_32(m68k_info *info)
{
	build_movem_re(info, M68K_INS_MOVEM, 4);
}

static void d68000_movem_er_16(m68k_info *info)
{
	build_movem_er(info, M68K_INS_MOVEM, 2);
}

static void d68000_movem_er_32(m68k_info *info)
{
	build_movem_er(info, M68K_INS_MOVEM, 4);
}

static void d68000_movem_re_16(m68k_info *info)
{
	build_movem_re(info, M68K_INS_MOVEM, 2);
}

static void d68000_movem_re_32(m68k_info *info)
{
	build_movem_re(info, M68K_INS_MOVEM, 4);
}

static void d68000_movep_re_16(m68k_info *info)
{
	/*
	 * MC68060 leaves MOVEP to the software package, but the encoding is still
	 * part of the ISA and should decode as MOVEP.
	 */
	build_movep_re(info, 2);
}

static void d68000_movep_re_32(m68k_info *info)
{
	build_movep_re(info, 4);
}

static void d68000_movep_er_16(m68k_info *info)
{
	build_movep_er(info, 2);
}

static void d68000_movep_er_32(m68k_info *info)
{
	build_movep_er(info, 4);
}

static void d68010_moves_8(m68k_info *info)
{
	LIMIT_FEATURE(info, M68010_PLUS);
	build_moves(info, 1);
}

static void d68010_moves_16(m68k_info *info)
{
	//uint32_t extension;
	LIMIT_FEATURE(info, M68010_PLUS);
	build_moves(info, 2);
}

static void d68010_moves_32(m68k_info *info)
{
	LIMIT_FEATURE(info, M68010_PLUS);
	build_moves(info, 4);
}

static void d68000_moveq(m68k_info *info)
{
	cs_m68k_op *op0;
	cs_m68k_op *op1;

	cs_m68k *ext = build_init_op(info, M68K_INS_MOVEQ, 2, 0);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	op0->type = M68K_OP_IMM;
	op0->address_mode = M68K_AM_IMMEDIATE;
	op0->imm = (info->ir & 0xff);

	op1->address_mode = M68K_AM_REG_DIRECT_DATA;
	op1->reg = M68K_REG_D0 + ((info->ir >> 9) & 7);
}

static void d68040_move16_pi_pi(m68k_info *info)
{
	uint32_t data[] = { info->ir & 7, (read_imm_16(info) >> 12) & 7 };
	uint32_t modes[] = { M68K_AM_REGI_ADDR_POST_INC,
			     M68K_AM_REGI_ADDR_POST_INC };

	LIMIT_FEATURE(info, M68040_PLUS);

	build_move16(info, data, modes);
}

static void d68040_move16_pi_al(m68k_info *info)
{
	uint32_t data[2];
	uint32_t modes[] = { M68K_AM_REGI_ADDR_POST_INC,
			     M68K_AM_ABSOLUTE_DATA_LONG };

	LIMIT_FEATURE(info, M68040_PLUS);

	data[0] = info->ir & 7;
	data[1] = read_imm_32(info);
	build_move16(info, data, modes);
}

static void d68040_move16_al_pi(m68k_info *info)
{
	uint32_t data[2];
	uint32_t modes[] = { M68K_AM_ABSOLUTE_DATA_LONG,
			     M68K_AM_REGI_ADDR_POST_INC };

	LIMIT_FEATURE(info, M68040_PLUS);

	data[0] = read_imm_32(info);
	data[1] = info->ir & 7;
	build_move16(info, data, modes);
}

static void d68040_move16_ai_al(m68k_info *info)
{
	uint32_t data[2];
	uint32_t modes[] = { M68K_AM_REGI_ADDR, M68K_AM_ABSOLUTE_DATA_LONG };

	LIMIT_FEATURE(info, M68040_PLUS);

	data[0] = info->ir & 7;
	data[1] = read_imm_32(info);
	build_move16(info, data, modes);
}

static void d68040_move16_al_ai(m68k_info *info)
{
	uint32_t data[2];
	uint32_t modes[] = { M68K_AM_ABSOLUTE_DATA_LONG, M68K_AM_REGI_ADDR };

	LIMIT_FEATURE(info, M68040_PLUS);

	data[0] = read_imm_32(info);
	data[1] = info->ir & 7;
	build_move16(info, data, modes);
}

static void d68000_muls(m68k_info *info)
{
	build_er_1(info, M68K_INS_MULS, 2);
}

static void d68000_mulu(m68k_info *info)
{
	build_er_1(info, M68K_INS_MULU, 2);
}

static void d68020_mull(m68k_info *info)
{
	uint32_t extension, insn_signed;
	cs_m68k *ext;
	cs_m68k_op *op0;
	cs_m68k_op *op1;
	uint32_t reg_0, reg_1;

	LIMIT_FEATURE(info, M68020_PLUS | CS_MODE_M68K_CF_ISA_A |
				    CS_MODE_M68K_CF_ISA_B |
				    CS_MODE_M68K_CF_ISA_C);

	extension = read_imm_16(info);
	insn_signed = 0;

	if (BIT_B((extension)))
		insn_signed = 1;

	ext = build_init_op(info, insn_signed ? M68K_INS_MULS : M68K_INS_MULU,
			    2, 4);

	op0 = &ext->operands[0];
	op1 = &ext->operands[1];

	get_ea_mode_op(info, op0, info->ir, 4);

	reg_0 = extension & 7;
	reg_1 = (extension >> 12) & 7;

	op1->address_mode = M68K_AM_NONE;
	op1->type = M68K_OP_REG_PAIR;
	op1->reg_pair.reg_0 = reg_0 + M68K_REG_D0;
	op1->reg_pair.reg_1 = reg_1 + M68K_REG_D0;

	if (!BIT_A(extension)) {
		op1->type = M68K_OP_REG;
		op1->reg = M68K_REG_D0 + reg_1;
	}
}

static void d68000_nbcd(m68k_info *info)
{
	build_ea(info, M68K_INS_NBCD, 1);
}

static void d68000_neg_8(m68k_info *info)
{
	build_ea(info, M68K_INS_NEG, 1);
}

static void d68000_neg_16(m68k_info *info)
{
	build_ea(info, M68K_INS_NEG, 2);
}

static void d68000_neg_32(m68k_info *info)
{
	build_ea(info, M68K_INS_NEG, 4);
}

static void d68000_negx_8(m68k_info *info)
{
	build_ea(info, M68K_INS_NEGX, 1);
}

static void d68000_negx_16(m68k_info *info)
{
	build_ea(info, M68K_INS_NEGX, 2);
}

static void d68000_negx_32(m68k_info *info)
{
	build_ea(info, M68K_INS_NEGX, 4);
}

static void d68000_nop(m68k_info *info)
{
	MCInst_setOpcode(info->inst, M68K_INS_NOP);
}

static void d68000_not_8(m68k_info *info)
{
	build_ea(info, M68K_INS_NOT, 1);
}

static void d68000_not_16(m68k_info *info)
{
	build_ea(info, M68K_INS_NOT, 2);
}

static void d68000_not_32(m68k_info *info)
{
	build_ea(info, M68K_INS_NOT, 4);
}

static void d68000_or_er_8(m68k_info *info)
{
	build_er_1(info, M68K_INS_OR, 1);
}

static void d68000_or_er_16(m68k_info *info)
{
	build_er_1(info, M68K_INS_OR, 2);
}

static void d68000_or_er_32(m68k_info *info)
{
	build_er_1(info, M68K_INS_OR, 4);
}

static void d68000_or_re_8(m68k_info *info)
{
	build_re_1(info, M68K_INS_OR, 1);
}

static void d68000_or_re_16(m68k_info *info)
{
	build_re_1(info, M68K_INS_OR, 2);
}

static void d68000_or_re_32(m68k_info *info)
{
	build_re_1(info, M68K_INS_OR, 4);
}

static void d68000_ori_8(m68k_info *info)
{
	build_imm_ea(info, M68K_INS_ORI, 1, read_imm_8(info));
}

static void d68000_ori_16(m68k_info *info)
{
	build_imm_ea(info, M68K_INS_ORI, 2, read_imm_16(info));
}

static void d68000_ori_32(m68k_info *info)
{
	build_imm_ea(info, M68K_INS_ORI, 4, read_imm_32(info));
}

static void d68000_ori_to_ccr(m68k_info *info)
{
	build_imm_special_reg(info, M68K_INS_ORI, read_imm_8(info), 1,
			      M68K_REG_CCR);
}

static void d68000_ori_to_sr(m68k_info *info)
{
	build_imm_special_reg(info, M68K_INS_ORI, read_imm_16(info), 2,
			      M68K_REG_SR);
}

static void d68020_pack_rr(m68k_info *info)
{
	LIMIT_FEATURE_EXCLUDING(info, M68020_PLUS, CS_MODE_M68K_CPU32);
	build_rr(info, M68K_INS_PACK, 0, read_imm_16(info));
}

static void d68020_pack_mm(m68k_info *info)
{
	LIMIT_FEATURE_EXCLUDING(info, M68020_PLUS, CS_MODE_M68K_CPU32);
	build_mm(info, M68K_INS_PACK, 0, read_imm_16(info));
}

static void d68000_pea(m68k_info *info)
{
	build_ea(info, M68K_INS_PEA, 4);
}

static void d68000_reset(m68k_info *info)
{
	MCInst_setOpcode(info->inst, M68K_INS_RESET);
}

static void d68000_ror_s_8(m68k_info *info)
{
	build_3bit_d(info, M68K_INS_ROR, 1);
}

static void d68000_ror_s_16(m68k_info *info)
{
	build_3bit_d(info, M68K_INS_ROR, 2);
}

static void d68000_ror_s_32(m68k_info *info)
{
	build_3bit_d(info, M68K_INS_ROR, 4);
}

static void d68000_ror_r_8(m68k_info *info)
{
	build_r(info, M68K_INS_ROR, 1);
}

static void d68000_ror_r_16(m68k_info *info)
{
	build_r(info, M68K_INS_ROR, 2);
}

static void d68000_ror_r_32(m68k_info *info)
{
	build_r(info, M68K_INS_ROR, 4);
}

static void d68000_ror_ea(m68k_info *info)
{
	build_ea(info, M68K_INS_ROR, 2);
}

static void d68000_rol_s_8(m68k_info *info)
{
	build_3bit_d(info, M68K_INS_ROL, 1);
}

static void d68000_rol_s_16(m68k_info *info)
{
	build_3bit_d(info, M68K_INS_ROL, 2);
}

static void d68000_rol_s_32(m68k_info *info)
{
	build_3bit_d(info, M68K_INS_ROL, 4);
}

static void d68000_rol_r_8(m68k_info *info)
{
	build_r(info, M68K_INS_ROL, 1);
}

static void d68000_rol_r_16(m68k_info *info)
{
	build_r(info, M68K_INS_ROL, 2);
}

static void d68000_rol_r_32(m68k_info *info)
{
	build_r(info, M68K_INS_ROL, 4);
}

static void d68000_rol_ea(m68k_info *info)
{
	build_ea(info, M68K_INS_ROL, 2);
}

static void d68000_roxr_s_8(m68k_info *info)
{
	build_3bit_d(info, M68K_INS_ROXR, 1);
}

static void d68000_roxr_s_16(m68k_info *info)
{
	build_3bit_d(info, M68K_INS_ROXR, 2);
}

static void d68000_roxr_s_32(m68k_info *info)
{
	build_3bit_d(info, M68K_INS_ROXR, 4);
}

static void d68000_roxr_r_8(m68k_info *info)
{
	build_r(info, M68K_INS_ROXR, 1);
}

static void d68000_roxr_r_16(m68k_info *info)
{
	build_r(info, M68K_INS_ROXR, 2);
}

static void d68000_roxr_r_32(m68k_info *info)
{
	build_r(info, M68K_INS_ROXR, 4);
}

static void d68000_roxr_ea(m68k_info *info)
{
	build_ea(info, M68K_INS_ROXR, 2);
}

static void d68000_roxl_s_8(m68k_info *info)
{
	build_3bit_d(info, M68K_INS_ROXL, 1);
}

static void d68000_roxl_s_16(m68k_info *info)
{
	build_3bit_d(info, M68K_INS_ROXL, 2);
}

static void d68000_roxl_s_32(m68k_info *info)
{
	build_3bit_d(info, M68K_INS_ROXL, 4);
}

static void d68000_roxl_r_8(m68k_info *info)
{
	build_r(info, M68K_INS_ROXL, 1);
}

static void d68000_roxl_r_16(m68k_info *info)
{
	build_r(info, M68K_INS_ROXL, 2);
}

static void d68000_roxl_r_32(m68k_info *info)
{
	build_r(info, M68K_INS_ROXL, 4);
}

static void d68000_roxl_ea(m68k_info *info)
{
	build_ea(info, M68K_INS_ROXL, 2);
}

static void d68010_rtd(m68k_info *info)
{
	set_insn_group(info, M68K_GRP_RET);
	LIMIT_FEATURE(info, M68010_PLUS);
	build_absolute_jump_with_immediate(info, M68K_INS_RTD, 0,
					   read_imm_16(info));
}

static void d68000_rte(m68k_info *info)
{
	set_insn_group(info, M68K_GRP_IRET);
	MCInst_setOpcode(info->inst, M68K_INS_RTE);
}

static void d68020_rtm(m68k_info *info)
{
	cs_m68k *ext;
	cs_m68k_op *op;

	set_insn_group(info, M68K_GRP_RET);

	LIMIT_FEATURE(info, M68020_ONLY);

	build_absolute_jump_with_immediate(info, M68K_INS_RTM, 0, 0);

	ext = &info->extension;
	op = &ext->operands[0];

	op->address_mode = M68K_AM_NONE;
	op->type = M68K_OP_REG;

	if (BIT_3(info->ir)) {
		op->reg = M68K_REG_A0 + (info->ir & 7);
	} else {
		op->reg = M68K_REG_D0 + (info->ir & 7);
	}
}

static void d68000_rtr(m68k_info *info)
{
	set_insn_group(info, M68K_GRP_RET);
	MCInst_setOpcode(info->inst, M68K_INS_RTR);
}

static void d68000_rts(m68k_info *info)
{
	set_insn_group(info, M68K_GRP_RET);
	MCInst_setOpcode(info->inst, M68K_INS_RTS);
}

static void d68000_sbcd_rr(m68k_info *info)
{
	build_rr(info, M68K_INS_SBCD, 1, 0);
}

static void d68000_sbcd_mm(m68k_info *info)
{
	build_mm(info, M68K_INS_SBCD, 1, 0);
}

static void d68000_scc(m68k_info *info)
{
	cs_m68k *ext = build_init_op(
		info, s_scc_lut[M68K_IR_CONDITION_NIBBLE(info)], 1, 1);
	get_ea_mode_op(info, &ext->operands[0], info->ir, 1);
}

static void d68000_stop(m68k_info *info)
{
	build_absolute_jump_with_immediate(info, M68K_INS_STOP, 0,
					   read_imm_16(info));
}

static void d68040_pflush(m68k_info *info)
{
	/* 68040/060 PFLUSH variants in the 0xF500-0xF51F range:
	 *   F500-F507: PFLUSHN (An)  — flush non-global ATC entries for (An)
	 *   F508-F50F: PFLUSH (An)   — flush all ATC entries for (An)
	 *   F510-F517: PFLUSHAN      — flush all non-global ATC entries
	 *   F518-F51F: PFLUSHA       — flush all ATC entries
	 */
	int mode;
	cs_m68k *ext;
	cs_m68k_op *op;

	LIMIT_FEATURE(info, M68040_PLUS);

	mode = (info->ir >> 3) & 3;

	switch (mode) {
	case 0: /* PFLUSHN (An) */
		ext = build_init_op(info, M68K_INS_PFLUSHN, 1, 0);
		op = &ext->operands[0];
		op->address_mode = M68K_AM_REGI_ADDR;
		op->type = M68K_OP_MEM;
		op->mem.base_reg = M68K_REG_A0 + (info->ir & 7);
		break;
	case 1: /* PFLUSH (An) */
		ext = build_init_op(info, M68K_INS_PFLUSH, 1, 0);
		op = &ext->operands[0];
		op->address_mode = M68K_AM_REGI_ADDR;
		op->type = M68K_OP_MEM;
		op->mem.base_reg = M68K_REG_A0 + (info->ir & 7);
		break;
	case 2: /* PFLUSHAN */
		build_init_op(info, M68K_INS_PFLUSHAN, 0, 0);
		break;
	case 3: /* PFLUSHA */
		build_init_op(info, M68K_INS_PFLUSHA, 0, 0);
		break;
	default:
		break;
	}
}

static void d68040_ptest(m68k_info *info)
{
	/* 68040-only PTEST instructions:
	 *   F548-F54F: PTESTW (An)
	 *   F568-F56F: PTESTR (An)
	 */
	int is_read;
	cs_m68k *ext;
	cs_m68k_op *op;
	int insn;

	LIMIT_FEATURE(info, CS_MODE_M68K_040);

	is_read = (info->ir >> 5) & 1;
	insn = is_read ? M68K_INS_PTESTR : M68K_INS_PTESTW;

	ext = build_init_op(info, insn, 1, 0);
	op = &ext->operands[0];
	op->address_mode = M68K_AM_REGI_ADDR;
	op->type = M68K_OP_MEM;
	op->mem.base_reg = M68K_REG_A0 + (info->ir & 7);
}

static void d68060_plpa(m68k_info *info)
{
	/* 68060-only PLPA instructions:
	 *   F588-F58F: PLPAW (An)
	 *   F5C8-F5CF: PLPAR (An)
	 */
	int is_read;
	cs_m68k *ext;
	cs_m68k_op *op;
	int insn;

	LIMIT_FEATURE(info, CS_MODE_M68K_060);

	is_read = (info->ir >> 6) & 1;
	insn = is_read ? M68K_INS_PLPAR : M68K_INS_PLPAW;

	ext = build_init_op(info, insn, 1, 0);
	op = &ext->operands[0];
	op->address_mode = M68K_AM_REGI_ADDR;
	op->type = M68K_OP_MEM;
	op->mem.base_reg = M68K_REG_A0 + (info->ir & 7);
}

static void d68060_halt(m68k_info *info)
{
	LIMIT_FEATURE_UNDECODED(info, CS_MODE_M68K_060 | CS_MODE_M68K_CF_ISA_A);
	build_init_op(info, M68K_INS_HALT, 0, 0);
}

static void d68cpu32_bgnd(m68k_info *info)
{
	LIMIT_FEATURE_UNDECODED(info, CS_MODE_M68K_CPU32);
	build_init_op(info, M68K_INS_BGND, 0, 0);
}

static void d68cpu32_tbl(m68k_info *info)
{
	uint16_t ext_word;
	int is_signed, is_round, is_memory;
	int dx, size_bits, size;
	int insn;
	cs_m68k *cs_ext;
	cs_m68k_op *op0;
	cs_m68k_op *op1;

	if (!m68k_has_feature(info, CS_MODE_M68K_CPU32)) {
		d68020_cpgen(info);
		return;
	}

	ext_word = (uint16_t)peek_imm_16(info);

	is_memory = (ext_word >> 8) & 1;
	size_bits = (ext_word >> 6) & 3;

	if ((ext_word & 0x8200) || size_bits == 3 ||
	    (!is_memory && ((info->ir >> 3) & 7) != 0) ||
	    (is_memory && ((info->ir >> 3) & 7) < 2)) {
		d68000_invalid(info);
		return;
	}

	ext_word = (uint16_t)read_imm_16(info);

	is_signed = (ext_word >> 11) & 1;
	is_round = (ext_word >> 10) & 1;
	is_memory = (ext_word >> 8) & 1;
	dx = (ext_word >> 12) & 7;

	switch (size_bits) {
	case 0:
		size = 1;
		break;
	case 1:
		size = 2;
		break;
	case 2:
		size = 4;
		break;
	default:
		d68000_invalid(info);
		return;
	}

	if (is_signed && is_round)
		insn = M68K_INS_TBLSN;
	else if (is_signed)
		insn = M68K_INS_TBLS;
	else if (is_round)
		insn = M68K_INS_TBLUN;
	else
		insn = M68K_INS_TBLU;

	cs_ext = build_init_op(info, insn, 2, size);
	op0 = &cs_ext->operands[0];
	op1 = &cs_ext->operands[1];

	if (is_memory) {
		get_ea_mode_op(info, op0, info->ir, size);
	} else {
		int dm = info->ir & 7;
		int dn = ext_word & 7;

		op0->address_mode = M68K_AM_NONE;
		op0->type = M68K_OP_REG_PAIR;
		op0->reg_pair.reg_0 = M68K_REG_D0 + dm;
		op0->reg_pair.reg_1 = M68K_REG_D0 + dn;
	}

	op1->address_mode = M68K_AM_REG_DIRECT_DATA;
	op1->reg = M68K_REG_D0 + dx;
}

static int pmmu_valid_fc(int fc)
{
	return fc == 0 || fc == 1 || (fc & 0x18) == 0x08 || (fc & 0x10) != 0;
}

static void pmmu_decode_fc(m68k_info *info, cs_m68k_op *op, int fc_source)
{
	if (fc_source == 0) {
		op->address_mode = M68K_AM_NONE;
		op->type = M68K_OP_REG;
		op->reg = M68K_REG_SFC;
	} else if (fc_source == 1) {
		op->address_mode = M68K_AM_NONE;
		op->type = M68K_OP_REG;
		op->reg = M68K_REG_DFC;
	} else if ((fc_source & 0x18) == 0x08) {
		op->address_mode = M68K_AM_REG_DIRECT_DATA;
		op->type = M68K_OP_REG;
		op->reg = M68K_REG_D0 + (fc_source & 7);
	} else {
		op->type = M68K_OP_IMM;
		op->address_mode = M68K_AM_IMMEDIATE;
		op->imm = fc_source & 0xf;
	}
}

static void d68030_pmmu(m68k_info *info)
{
	uint16_t cmd;
	int type;

	cmd = (uint16_t)peek_imm_16(info);
	type = (cmd >> 13) & 7;

	switch (type) {
	case 0: {
		int preg = (cmd >> 10) & 7;
		int direction;
		m68k_reg pmmu_reg;
		cs_m68k *ext;
		cs_m68k_op *op0;
		cs_m68k_op *op1;

		if ((preg != 2 && preg != 3) || (cmd & 0xff)) {
			d68000_invalid(info);
			return;
		}

		read_imm_16(info);
		direction = (cmd >> 9) & 1;
		pmmu_reg = (preg == 2) ? M68K_REG_TT0 : M68K_REG_TT1;

		ext = build_init_op(info, M68K_INS_PMOVE, 2, 0);
		op0 = &ext->operands[0];
		op1 = &ext->operands[1];

		if (direction) {
			op0->address_mode = M68K_AM_NONE;
			op0->type = M68K_OP_REG;
			op0->reg = pmmu_reg;
			get_ea_mode_op(info, op1, info->ir, 4);
		} else {
			get_ea_mode_op(info, op0, info->ir, 4);
			op1->address_mode = M68K_AM_NONE;
			op1->type = M68K_OP_REG;
			op1->reg = pmmu_reg;
		}
		break;
	}

	case 1: {
		int is_flush;

		if (cmd == 0x2400 &&
		    m68k_ea_field(info->ir) == M68K_EA_DATA_DIRECT_D0) {
			read_imm_16(info);
			build_init_op(info, M68K_INS_PFLUSHA, 0, 0);
			break;
		}

		is_flush = (cmd >> 12) & 1;

		if (is_flush) {
			int fc = cmd & 0x1f;
			int mask;
			cs_m68k *ext;
			cs_m68k_op *op0;
			cs_m68k_op *op1;
			cs_m68k_op *op2;

			if (!pmmu_valid_fc(fc)) {
				d68000_invalid(info);
				return;
			}

			read_imm_16(info);
			mask = (cmd >> 5) & 7;
			ext = build_init_op(info, M68K_INS_PFLUSH, 3, 0);
			op0 = &ext->operands[0];
			op1 = &ext->operands[1];
			op2 = &ext->operands[2];

			pmmu_decode_fc(info, op0, fc);

			op1->type = M68K_OP_IMM;
			op1->address_mode = M68K_AM_IMMEDIATE;
			op1->imm = mask;

			get_ea_mode_op(info, op2, info->ir, 1);
		} else {
			int fc_source = cmd & 0x1f;
			int is_read;
			int insn;
			cs_m68k *ext;
			cs_m68k_op *op0;
			cs_m68k_op *op1;

			if (!pmmu_valid_fc(fc_source) || (cmd & 0xde0) != 0) {
				d68000_invalid(info);
				return;
			}

			read_imm_16(info);
			is_read = (cmd >> 9) & 1;
			insn = is_read ? M68K_INS_PLOADR : M68K_INS_PLOADW;
			ext = build_init_op(info, insn, 2, 0);
			op0 = &ext->operands[0];
			op1 = &ext->operands[1];

			pmmu_decode_fc(info, op0, fc_source);
			get_ea_mode_op(info, op1, info->ir, 1);
		}
		break;
	}

	case 2: {
		int preg = (cmd >> 10) & 7;
		int direction, fd, insn;
		m68k_reg pmmu_reg;
		cs_m68k *ext;
		cs_m68k_op *op0;
		cs_m68k_op *op1;

		if (cmd & 0xff) {
			d68000_invalid(info);
			return;
		}

		switch (preg) {
		case 0:
			pmmu_reg = M68K_REG_TC;
			break;
		case 2:
			pmmu_reg = M68K_REG_SRP;
			break;
		case 3:
			pmmu_reg = M68K_REG_CRP;
			break;
		default:
			d68000_invalid(info);
			return;
		}

		read_imm_16(info);
		direction = (cmd >> 9) & 1;
		fd = (cmd >> 8) & 1;
		insn = fd ? M68K_INS_PMOVEFD : M68K_INS_PMOVE;

		ext = build_init_op(info, insn, 2, 0);
		op0 = &ext->operands[0];
		op1 = &ext->operands[1];

		if (direction) {
			op0->address_mode = M68K_AM_NONE;
			op0->type = M68K_OP_REG;
			op0->reg = pmmu_reg;
			get_ea_mode_op(info, op1, info->ir, 4);
		} else {
			get_ea_mode_op(info, op0, info->ir, 4);
			op1->address_mode = M68K_AM_NONE;
			op1->type = M68K_OP_REG;
			op1->reg = pmmu_reg;
		}
		break;
	}

	case 3: {
		int direction;
		cs_m68k *ext;
		cs_m68k_op *op0;
		cs_m68k_op *op1;

		if ((cmd & 0x1dff) != 0) {
			d68000_invalid(info);
			return;
		}

		read_imm_16(info);
		direction = (cmd >> 9) & 1;
		ext = build_init_op(info, M68K_INS_PMOVE, 2, 0);
		op0 = &ext->operands[0];
		op1 = &ext->operands[1];

		if (direction) {
			op0->address_mode = M68K_AM_NONE;
			op0->type = M68K_OP_REG;
			op0->reg = M68K_REG_MMUSR;
			get_ea_mode_op(info, op1, info->ir, 2);
		} else {
			get_ea_mode_op(info, op0, info->ir, 2);
			op1->address_mode = M68K_AM_NONE;
			op1->type = M68K_OP_REG;
			op1->reg = M68K_REG_MMUSR;
		}
		break;
	}

	case 4: {
		int fc_source = cmd & 0x1f;
		int is_read, level, insn;
		cs_m68k *ext;
		cs_m68k_op *op0;
		cs_m68k_op *op1;
		cs_m68k_op *op2;

		if (!pmmu_valid_fc(fc_source) || (cmd & 0x1e0) != 0 ||
		    ((info->ir >> 3) & 7) == 0) {
			d68000_invalid(info);
			return;
		}

		read_imm_16(info);
		is_read = (cmd >> 9) & 1;
		level = (cmd >> 10) & 7;
		insn = is_read ? M68K_INS_PTESTR : M68K_INS_PTESTW;
		ext = build_init_op(info, insn, 3, 0);
		op0 = &ext->operands[0];
		op1 = &ext->operands[1];
		op2 = &ext->operands[2];

		pmmu_decode_fc(info, op0, fc_source);
		get_ea_mode_op(info, op1, info->ir, 1);

		op2->type = M68K_OP_IMM;
		op2->address_mode = M68K_AM_IMMEDIATE;
		op2->imm = level;
		break;
	}

	default:
		d68000_invalid(info);
		return;
	}
}

static void d68060_lpstop(m68k_info *info)
{
	if (!m68k_has_feature(info, CS_MODE_M68K_CPU32 | CS_MODE_M68K_060)) {
		d68020_cpgen(info);
		return;
	}

	/* LPSTOP extension word is 0x01c0. If it doesn't match,
	 * try TBL (CPU32) or fall through to cpgen.
	 */
	if (peek_imm_16(info) != 0x01c0) {
		if (m68k_has_feature(info, CS_MODE_M68K_CPU32)) {
			d68cpu32_tbl(info);
		} else {
			d68020_cpgen(info);
		}
		return;
	}

	read_imm_16(info);
	build_absolute_jump_with_immediate(info, M68K_INS_LPSTOP, 0,
					   read_imm_16(info));
}

static void d68000_sub_er_8(m68k_info *info)
{
	build_er_1(info, M68K_INS_SUB, 1);
}

static void d68000_sub_er_16(m68k_info *info)
{
	build_er_1(info, M68K_INS_SUB, 2);
}

static void d68000_sub_er_32(m68k_info *info)
{
	build_er_1(info, M68K_INS_SUB, 4);
}

static void d68000_sub_re_8(m68k_info *info)
{
	build_re_1(info, M68K_INS_SUB, 1);
}

static void d68000_sub_re_16(m68k_info *info)
{
	build_re_1(info, M68K_INS_SUB, 2);
}

static void d68000_sub_re_32(m68k_info *info)
{
	build_re_1(info, M68K_INS_SUB, 4);
}

static void d68000_suba_16(m68k_info *info)
{
	build_ea_a(info, M68K_INS_SUBA, 2);
}

static void d68000_suba_32(m68k_info *info)
{
	build_ea_a(info, M68K_INS_SUBA, 4);
}

static void d68000_subi_8(m68k_info *info)
{
	build_imm_ea(info, M68K_INS_SUBI, 1, read_imm_8(info));
}

static void d68000_subi_16(m68k_info *info)
{
	build_imm_ea(info, M68K_INS_SUBI, 2, read_imm_16(info));
}

static void d68000_subi_32(m68k_info *info)
{
	build_imm_ea(info, M68K_INS_SUBI, 4, read_imm_32(info));
}

static void d68000_subq_8(m68k_info *info)
{
	build_3bit_ea(info, M68K_INS_SUBQ, 1);
}

static void d68000_subq_16(m68k_info *info)
{
	build_3bit_ea(info, M68K_INS_SUBQ, 2);
}

static void d68000_subq_32(m68k_info *info)
{
	build_3bit_ea(info, M68K_INS_SUBQ, 4);
}

static void d68000_subx_rr_8(m68k_info *info)
{
	build_rr(info, M68K_INS_SUBX, 1, 0);
}

static void d68000_subx_rr_16(m68k_info *info)
{
	build_rr(info, M68K_INS_SUBX, 2, 0);
}

static void d68000_subx_rr_32(m68k_info *info)
{
	build_rr(info, M68K_INS_SUBX, 4, 0);
}

static void d68000_subx_mm_8(m68k_info *info)
{
	build_mm(info, M68K_INS_SUBX, 1, 0);
}

static void d68000_subx_mm_16(m68k_info *info)
{
	build_mm(info, M68K_INS_SUBX, 2, 0);
}

static void d68000_subx_mm_32(m68k_info *info)
{
	build_mm(info, M68K_INS_SUBX, 4, 0);
}

static void d68000_swap(m68k_info *info)
{
	build_d(info, M68K_INS_SWAP, 0);
}

static void d68000_tas(m68k_info *info)
{
	build_ea(info, M68K_INS_TAS, 1);
}

static void d68060_pulse(m68k_info *info)
{
	LIMIT_FEATURE(info, CS_MODE_M68K_060 | CS_MODE_M68K_CF_ISA_A);
	build_init_op(info, M68K_INS_PULSE, 0, 0);
}

static void d68000_trap(m68k_info *info)
{
	build_absolute_jump_with_immediate(info, M68K_INS_TRAP, 0,
					   info->ir & 0xf);
}

static void d68020_trapcc_0(m68k_info *info)
{
	LIMIT_FEATURE(info, M68020_PLUS | CS_MODE_M68K_CF_ISA_A);
	if (m68k_has_feature(info, CS_MODE_M68K_COLDFIRE)) {
		if (M68K_IR_CONDITION_NIBBLE(info) != M68K_CONDITION_FALSE) {
			d68000_invalid(info);
			return;
		}
		build_absolute_jump_with_immediate(info, M68K_INS_TPF, 0, 0);
		info->extension.op_count = 0;
		return;
	}

	build_trap(info, 0, 0);

	info->extension.op_count = 0;
}

static void d68020_trapcc_16(m68k_info *info)
{
	LIMIT_FEATURE(info, M68020_PLUS | CS_MODE_M68K_CF_ISA_A);
	if (m68k_has_feature(info, CS_MODE_M68K_COLDFIRE)) {
		if (M68K_IR_CONDITION_NIBBLE(info) != M68K_CONDITION_FALSE) {
			d68000_invalid(info);
			return;
		}
		build_absolute_jump_with_immediate(info, M68K_INS_TPF, 2,
						   read_imm_16(info));
		return;
	}

	build_trap(info, 2, read_imm_16(info));
}

static void d68020_trapcc_32(m68k_info *info)
{
	LIMIT_FEATURE(info, M68020_PLUS | CS_MODE_M68K_CF_ISA_A);
	if (m68k_has_feature(info, CS_MODE_M68K_COLDFIRE)) {
		if (M68K_IR_CONDITION_NIBBLE(info) != M68K_CONDITION_FALSE) {
			d68000_invalid(info);
			return;
		}
		build_absolute_jump_with_immediate(info, M68K_INS_TPF, 4,
						   read_imm_32(info));
		return;
	}

	build_trap(info, 4, read_imm_32(info));
}

static void d68000_trapv(m68k_info *info)
{
	MCInst_setOpcode(info->inst, M68K_INS_TRAPV);
}

static void d68000_tst_8(m68k_info *info)
{
	build_ea(info, M68K_INS_TST, 1);
}

static void d68020_tst_pcdi_8(m68k_info *info)
{
	LIMIT_FEATURE(info, M68020_PLUS);
	build_ea(info, M68K_INS_TST, 1);
}

static void d68020_tst_pcix_8(m68k_info *info)
{
	LIMIT_FEATURE(info, M68020_PLUS);
	build_ea(info, M68K_INS_TST, 1);
}

static void d68020_tst_i_8(m68k_info *info)
{
	LIMIT_FEATURE(info, M68020_PLUS);
	build_ea(info, M68K_INS_TST, 1);
}

static void d68000_tst_16(m68k_info *info)
{
	build_ea(info, M68K_INS_TST, 2);
}

static void d68020_tst_a_16(m68k_info *info)
{
	LIMIT_FEATURE(info, M68020_PLUS);
	build_ea(info, M68K_INS_TST, 2);
}

static void d68020_tst_pcdi_16(m68k_info *info)
{
	LIMIT_FEATURE(info, M68020_PLUS);
	build_ea(info, M68K_INS_TST, 2);
}

static void d68020_tst_pcix_16(m68k_info *info)
{
	LIMIT_FEATURE(info, M68020_PLUS);
	build_ea(info, M68K_INS_TST, 2);
}

static void d68020_tst_i_16(m68k_info *info)
{
	LIMIT_FEATURE(info, M68020_PLUS);
	build_ea(info, M68K_INS_TST, 2);
}

static void d68000_tst_32(m68k_info *info)
{
	build_ea(info, M68K_INS_TST, 4);
}

static void d68020_tst_a_32(m68k_info *info)
{
	LIMIT_FEATURE(info, M68020_PLUS);
	build_ea(info, M68K_INS_TST, 4);
}

static void d68020_tst_pcdi_32(m68k_info *info)
{
	LIMIT_FEATURE(info, M68020_PLUS);
	build_ea(info, M68K_INS_TST, 4);
}

static void d68020_tst_pcix_32(m68k_info *info)
{
	LIMIT_FEATURE(info, M68020_PLUS);
	build_ea(info, M68K_INS_TST, 4);
}

static void d68020_tst_i_32(m68k_info *info)
{
	LIMIT_FEATURE(info, M68020_PLUS);
	build_ea(info, M68K_INS_TST, 4);
}

static void d68000_unlk(m68k_info *info)
{
	cs_m68k_op *op;
	cs_m68k *ext = build_init_op(info, M68K_INS_UNLK, 1, 0);

	op = &ext->operands[0];

	op->address_mode = M68K_AM_REG_DIRECT_ADDR;
	op->reg = M68K_REG_A0 + (info->ir & 7);
}

static void d68020_unpk_rr(m68k_info *info)
{
	LIMIT_FEATURE_EXCLUDING(info, M68020_PLUS, CS_MODE_M68K_CPU32);
	build_rr(info, M68K_INS_UNPK, 0, read_imm_16(info));
}

static void d68020_unpk_mm(m68k_info *info)
{
	LIMIT_FEATURE_EXCLUDING(info, M68020_PLUS, CS_MODE_M68K_CPU32);
	build_mm(info, M68K_INS_UNPK, 0, read_imm_16(info));
}

/* This table is auto-generated. Look in contrib/m68k_instruction_tbl_gen for more info */
#include "M68KInstructionTable.inc"

static int instruction_is_valid(m68k_info *info, const uint32_t word_check)
{
	const unsigned int instruction = info->ir;
	const instruction_struct *i = &g_instruction_table[instruction];

	if ((i->word2_mask &&
	     ((word_check & i->word2_mask) != i->word2_match)) ||
	    (i->instruction == d68000_invalid)) {
		d68000_invalid(info);
		return 0;
	}

	return 1;
}

static int exists_reg_list(const uint16_t *regs, uint8_t count, m68k_reg reg)
{
	uint8_t i;

	for (i = 0; i < count; ++i) {
		if (regs[i] == (uint16_t)reg)
			return 1;
	}

	return 0;
}

static void add_reg_to_rw_list(m68k_info *info, m68k_reg reg, int write)
{
	if (reg == M68K_REG_INVALID)
		return;

	if (write) {
		if (exists_reg_list(info->regs_write, info->regs_write_count,
				    reg))
			return;

		info->regs_write[info->regs_write_count] = (uint16_t)reg;
		info->regs_write_count++;
	} else {
		if (exists_reg_list(info->regs_read, info->regs_read_count,
				    reg))
			return;

		info->regs_read[info->regs_read_count] = (uint16_t)reg;
		info->regs_read_count++;
	}
}

static void update_am_reg_list(m68k_info *info, cs_m68k_op *op, int write)
{
	switch (op->address_mode) {
	case M68K_AM_REG_DIRECT_ADDR:
	case M68K_AM_REG_DIRECT_DATA:
		add_reg_to_rw_list(info, op->reg, write);
		break;

	case M68K_AM_REGI_ADDR_POST_INC:
	case M68K_AM_REGI_ADDR_PRE_DEC:
		add_reg_to_rw_list(info, op->mem.base_reg, 1);
		break;

	case M68K_AM_REGI_ADDR:
	case M68K_AM_REGI_ADDR_DISP:
		add_reg_to_rw_list(info, op->mem.base_reg, 0);
		break;

	case M68K_AM_AREGI_INDEX_8_BIT_DISP:
	case M68K_AM_AREGI_INDEX_BASE_DISP:
	case M68K_AM_MEMI_POST_INDEX:
	case M68K_AM_MEMI_PRE_INDEX:
	case M68K_AM_PCI_INDEX_8_BIT_DISP:
	case M68K_AM_PCI_INDEX_BASE_DISP:
	case M68K_AM_PC_MEMI_PRE_INDEX:
	case M68K_AM_PC_MEMI_POST_INDEX:
		add_reg_to_rw_list(info, op->mem.index_reg, 0);
		add_reg_to_rw_list(info, op->mem.base_reg, 0);
		break;

	// no register(s) in the other addressing modes
	default:
		break;
	}
}

static void update_bits_range(m68k_info *info, m68k_reg reg_start, uint8_t bits,
			      int write)
{
	int i;

	for (i = 0; i < 8; ++i) {
		if (bits & (1 << i)) {
			add_reg_to_rw_list(info, reg_start + i, write);
		}
	}
}

static void update_reg_list_regbits(m68k_info *info, cs_m68k_op *op, int write)
{
	uint32_t bits = op->register_bits;
	update_bits_range(info, M68K_REG_D0, bits & 0xff, write);
	update_bits_range(info, M68K_REG_A0, (bits >> 8) & 0xff, write);
	update_bits_range(info, M68K_REG_FP0, (bits >> 16) & 0xff, write);
}

static void update_op_reg_list(m68k_info *info, cs_m68k_op *op, int write)
{
	switch ((int)op->type) {
	case M68K_OP_REG:
		add_reg_to_rw_list(info, op->reg, write);
		break;

	case M68K_OP_MEM:
		update_am_reg_list(info, op, write);
		break;

	case M68K_OP_REG_BITS:
		update_reg_list_regbits(info, op, write);
		break;

	case M68K_OP_REG_PAIR:
		add_reg_to_rw_list(info, op->reg_pair.reg_0, write);
		add_reg_to_rw_list(info, op->reg_pair.reg_1, write);
		break;
	default:
		break;
	}
}

static void build_regs_read_write_counts(m68k_info *info)
{
	int i;

	if (!info->extension.op_count)
		return;

	if (info->extension.op_count == 1) {
		update_op_reg_list(info, &info->extension.operands[0], 1);
	} else {
		// first operand is always read
		update_op_reg_list(info, &info->extension.operands[0], 0);

		// remaining write
		for (i = 1; i < info->extension.op_count; ++i)
			update_op_reg_list(info, &info->extension.operands[i],
					   1);
	}
}

static void m68k_setup_internals(m68k_info *info, MCInst *inst, uint32_t pc,
				 m68k_feature_mask features)
{
	info->inst = inst;
	info->pc = pc;
	info->ir = 0;
	info->features = features;
	if (m68k_has_feature(info, M68010_LESS))
		info->address_mask = 0x00ffffff;
	else
		info->address_mask = 0xffffffff;
}

/* ======================================================================== */
/* ================================= API ================================== */
/* ======================================================================== */

/* Disasemble one instruction at pc and store in str_buff */
static unsigned int m68k_disassemble(m68k_info *info, uint64_t pc)
{
	MCInst *inst = info->inst;
	cs_m68k *ext = &info->extension;
	int i;
	unsigned int size;

	inst->Opcode = M68K_INS_INVALID;

	memset(ext, 0, sizeof(cs_m68k));
	ext->op_size.type = M68K_SIZE_TYPE_CPU;

	for (i = 0; i < M68K_OPERAND_COUNT; ++i)
		ext->operands[i].type = M68K_OP_REG;

	info->ir = peek_imm_16(info);
	if (instruction_is_valid(info, peek_imm_32(info) & 0xffff)) {
		info->ir = read_imm_16(info);
		g_instruction_table[info->ir].instruction(info);
	}

	size = info->pc - (unsigned int)pc;
	info->pc = (unsigned int)pc;

	return size;
}

bool M68K_getInstruction(csh ud, const uint8_t *code, size_t code_len,
			 MCInst *instr, uint16_t *size, uint64_t address,
			 void *inst_info)
{
#ifdef M68K_DEBUG
	SStream ss;
#endif
	uint32_t sz = 0;
	m68k_feature_mask features = 0;
	cs_struct *handle = instr->csh;
	m68k_info *info = (m68k_info *)handle->printer_info;

	// code len has to be at least 2 bytes to be valid m68k

	if (code_len < 2) {
		*size = 0;
		return false;
	}

	if (instr->flat_insn->detail) {
		memset(instr->flat_insn->detail, 0,
		       offsetof(cs_detail, m68k) + sizeof(cs_m68k));
	}

	info->groups_count = 0;
	info->regs_read_count = 0;
	info->regs_write_count = 0;
	info->code = code;
	info->code_len = code_len;
	info->baseAddress = address;

	features =
		(m68k_feature_mask)(handle->mode & CS_MODE_M68K_FEATURE_MASK);
	if (!features)
		features = CS_MODE_M68K_000;

	m68k_setup_internals(info, instr, (uint32_t)address, features);
	sz = m68k_disassemble(info, address);

	if (sz == 0) {
		*size = 2;
		return false;
	}

	build_regs_read_write_counts(info);

#ifdef M68K_DEBUG
	SStream_Init(&ss);
	M68K_printInst(instr, &ss, info);
#endif

	// Make sure we always stay within range
	if (sz > (uint32_t)code_len)
		*size = (uint16_t)code_len;
	else
		*size = sz;

	return true;
}

/* Capstone Disassembly Engine */
/* M680X Backend by Wolfgang Schwotzer <wolfgang.schwotzer@gmx.net> 2017 */

/* ======================================================================== */
/* ================================ INCLUDES ============================== */
/* ======================================================================== */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../../cs_priv.h"
#include "../../utils.h"

#include "../../MCInst.h"
#include "../../MCInstrDesc.h"
#include "../../MCRegisterInfo.h"
#include "M680XInstPrinter.h"
#include "M680XDisassembler.h"
#include "M680XDisassemblerInternals.h"

#ifdef CAPSTONE_HAS_M680X

#ifndef DECL_SPEC
#ifdef _MSC_VER
#define DECL_SPEC __cdecl
#else
#define DECL_SPEC
#endif  // _MSC_VER
#endif  // DECL_SPEC

/* ======================================================================== */
/* ============================ GENERAL DEFINES =========================== */
/* ======================================================================== */

/* ======================================================================== */
/* =============================== PROTOTYPES ============================= */
/* ======================================================================== */

typedef enum insn_hdlr_id {
	illegal_hdlr_id,
	relative8_hdlr_id,
	relative16_hdlr_id,
	immediate8_hdlr_id,
	immediate16_hdlr_id,
	immediate32_hdlr_id,
	direct_hdlr_id,
	extended_hdlr_id,
	indexedX_hdlr_id,
	indexedY_hdlr_id,
	indexed09_hdlr_id,
	inherent_hdlr_id,
	reg_reg09_hdlr_id,
	reg_bits_hdlr_id,
	imm_indexedX_hdlr_id,
	imm_indexed09_hdlr_id,
	imm_direct_hdlr_id,
	imm8_extended_hdlr_id,
	imm16_extended_hdlr_id,
	bit_move_hdlr_id,
	tfm_hdlr_id,
	dir_imm_rel_hdlr_id,
	idxX_imm_rel_hdlr_id,
	idxY_imm_rel_hdlr_id,
	direct_imm_hdlr_id,
	idxX_imm_hdlr_id,
	idxY_imm_hdlr_id,
	opidx_dir_rel_hdlr_id,
	opidx_direct_hdlr_id,
	indexedX0_hdlr_id,
	indexedX16_hdlr_id,
        imm_rel_hdlr_id,
        direct_rel_hdlr_id,
        indexedS_hdlr_id,
        indexedS16_hdlr_id,
        indexedS_rel_hdlr_id,
        indexedX_rel_hdlr_id,
        indexedX0_rel_hdlr_id,
        indexedXp_rel_hdlr_id,
        idxX0p_rel_hdlr_id,
        idxX0p_direct_hdlr_id,
        direct_direct_hdlr_id,
        direct_idxX0p_hdlr_id,
        indexed12_hdlr_id,
        indexed12s_hdlr_id,
        indexed12_imm_hdlr_id,
	idx12_imm_rel_hdlr_id,
	ext_imm_rel_hdlr_id,
	extended_imm_hdlr_id,
	ext_index_hdlr_id,
	idx12_index_hdlr_id,
	reg_reg12_hdlr_id,
	loop_hdlr_id,
	ext_ext_hdlr_id,
	idx12_idx12_hdlr_id,
	idx12_ext_hdlr_id,
	imm8_idx12_x_hdlr_id,
	imm16_idx12_x_hdlr_id,
	ext_idx12_x_hdlr_id,
	HANDLER_ID_ENDING,
} insn_hdlr_id;

// Access modes for the first 4 operands. If there are more than
// four operands they use the same access mode as the 4th operand.
//
// u: unchanged
// r: (r)read access
// w: (w)write access
// m: (m)odify access (= read + write)
//
typedef enum e_access_mode {

	uuuu,
	rrrr,
	wwww,
	rwww,
	rrrm,
	rmmm,
	wrrr,
	mrrr,
	mwww,
	mmmm,
	mwrr,
	mmrr,
	wmmm,
	rruu,
	muuu,
	ACCESS_MODE_ENDING,
} e_access_mode;

// Access type values are compatible with enum cs_ac_type:
typedef enum e_access {
	UNCHANGED = CS_AC_INVALID,
	READ = CS_AC_READ,
	WRITE = CS_AC_WRITE,
	MODIFY = (CS_AC_READ | CS_AC_WRITE),
} e_access;

/* Properties of one instruction in PAGE1 (without prefix) */
typedef struct inst_page1 {
	m680x_insn insn : 9;
	insn_hdlr_id handler_id : 6; /* instruction handler id */
} inst_page1;

/* Properties of one instruction in any other PAGE X */
typedef struct inst_pageX {
	unsigned opcode : 8;
	m680x_insn insn : 9;
	insn_hdlr_id handler_id : 6; /* instruction handler id */
} inst_pageX;

typedef struct insn_props {
	unsigned group : 4;
	e_access_mode access_mode : 5;
	m680x_reg reg0 : 5;
	m680x_reg reg1 : 5;
	bool cc_modified : 1;
	bool update_reg_access : 1;
} insn_props;

#include "m6800.inc"
#include "m6801.inc"
#include "hd6301.inc"
#include "m6811.inc"
#include "cpu12.inc"
#include "m6805.inc"
#include "m6808.inc"
#include "hcs08.inc"
#include "m6809.inc"
#include "hd6309.inc"

#include "insn_props.inc"

//////////////////////////////////////////////////////////////////////////////

// M680X instuctions have 1 up to 5 bytes. A reader is needed to read
// a byte or word from a given memory address. See also X86 reader(...)
static bool read_byte(const m680x_info *info, uint8_t *byte, uint16_t address)
{
	if (address - info->offset >= info->size)
		// out of code buffer range
		return false;

	*byte = info->code[address - info->offset];

	return true;
}

static bool read_byte_sign_extended(const m680x_info *info, int16_t *word,
	uint16_t address)
{
	if (address - info->offset >= info->size)
		// out of code buffer range
		return false;

	*word = (int16_t) info->code[address - info->offset];

	if (*word & 0x80)
		*word |= 0xFF00;

	return true;
}

static bool read_word(const m680x_info *info, uint16_t *word, uint16_t address)
{
	if (address + 1 - info->offset >= info->size)
		// out of code buffer range
		return false;

	*word = (uint16_t)info->code[address - info->offset] << 8;
	*word |= (uint16_t)info->code[address + 1 - info->offset];

	return true;
}

static bool read_sdword(const m680x_info *info, int32_t *sdword,
	uint16_t address)
{
	if (address + 3 - info->offset >= info->size)
		// out of code buffer range
		return false;

	*sdword = (uint32_t)info->code[address - info->offset] << 24;
	*sdword |= (uint32_t)info->code[address + 1 - info->offset] << 16;
	*sdword |= (uint32_t)info->code[address + 2 - info->offset] << 8;
	*sdword |= (uint32_t)info->code[address + 3 - info->offset];

	return true;
}

// For PAGE2 and PAGE3 opcodes when using an an array of inst_page1 most
// entries have M680X_INS_ILLGL. To avoid wasting memory an inst_pageX is
// used which contains the opcode. Using a binary search for the right opcode
// is much faster (= O(log n) ) in comparison to a linear search ( = O(n) ).
static int binary_search(const inst_pageX *const inst_pageX_table,
	int table_size, uint8_t opcode)
{
	int first = 0;
	int last = table_size - 1;
	int middle = (first + last) / 2;

	while (first <= last) {
		if (inst_pageX_table[middle].opcode < opcode) {
			first = middle + 1;
		}
		else if (inst_pageX_table[middle].opcode == opcode) {
			return middle;  /* item found */
		}
		else
			last = middle - 1;

		middle = (first + last) / 2;
	}

	if (first > last)
		return -1;  /* item not found */

	return -2;
}

void M680X_get_insn_id(cs_struct *handle, cs_insn *insn, unsigned int id)
{
	const m680x_info *const info = (const m680x_info *)handle->printer_info;
	const cpu_tables *cpu = &info->cpu;
	uint8_t insn_prefix = (id >> 8) & 0xff;
	bool insn_found = false;
	int index;
	int i;

	for (i = 0; i < ARR_SIZE(cpu->pageX_prefix); ++i) {
		if (cpu->pageX_table_size[i] == 0 ||
			(cpu->inst_pageX_table[i] == NULL))
			break;

		if (cpu->pageX_prefix[i] == insn_prefix) {
			index = binary_search(cpu->inst_pageX_table[i],
					cpu->pageX_table_size[i], id & 0xff);
			insn->id = (index >= 0) ?
				cpu->inst_pageX_table[i][index].insn :
				M680X_INS_ILLGL;
			return;
		}
	}

	if (insn_prefix != 0) {
		insn->id = M680X_INS_ILLGL;
		return;
	}

	// Check if opcode byte is present in an overlay table
	for (i = 0; i < ARR_SIZE(cpu->overlay_table_size); ++i) {
		if (cpu->overlay_table_size[i] == 0 ||
		    (cpu->inst_overlay_table[i] == NULL))
			break;

		if ((index = binary_search(cpu->inst_overlay_table[i],
						cpu->overlay_table_size[i],
						id & 0xff)) >= 0) {
			insn->id = cpu->inst_overlay_table[i][index].insn;
			insn_found = true;
		}
	}

	if (!insn_found)
		insn->id = cpu->inst_page1_table[id].insn;
}

static void add_insn_group(cs_detail *detail, m680x_group_type group)
{
	if (detail != NULL &&
		(group != M680X_GRP_INVALID) && (group != M680X_GRP_ENDING))
		detail->groups[detail->groups_count++] = (uint8_t)group;
}

static bool exists_reg_list(uint16_t *regs, uint8_t count, m680x_reg reg)
{
	uint8_t i;

	for (i = 0; i < count; ++i) {
		if (regs[i] == (uint16_t)reg)
			return true;
	}

	return false;
}

static void add_reg_to_rw_list(MCInst *MI, m680x_reg reg, e_access access)
{
	cs_detail *detail = MI->flat_insn->detail;

	if (detail == NULL || (reg == M680X_REG_INVALID))
		return;

	switch (access) {
	case MODIFY:
		if (!exists_reg_list(detail->regs_read,
				detail->regs_read_count, reg))
			detail->regs_read[detail->regs_read_count++] =
				(uint16_t)reg;

	// intentionally fall through

	case WRITE:
		if (!exists_reg_list(detail->regs_write,
				detail->regs_write_count, reg))
			detail->regs_write[detail->regs_write_count++] =
				(uint16_t)reg;

		break;

	case READ:
		if (!exists_reg_list(detail->regs_read,
				detail->regs_read_count, reg))
			detail->regs_read[detail->regs_read_count++] =
				(uint16_t)reg;

		break;

	case UNCHANGED:
	default:
		break;
	}
}

static void update_am_reg_list(MCInst *MI, m680x_info *info, cs_m680x_op *op,
				e_access access)
{
	if (MI->flat_insn->detail == NULL)
		return;

	switch (op->type) {
	case M680X_OP_REGISTER:
		add_reg_to_rw_list(MI, op->reg, access);
		break;

	case M680X_OP_INDEXED:
		add_reg_to_rw_list(MI, op->idx.base_reg, READ);
		if (op->idx.base_reg == M680X_REG_X &&
		    info->cpu.reg_byte_size[M680X_REG_H])
			add_reg_to_rw_list(MI, M680X_REG_H, READ);


		if (op->idx.offset_reg != M680X_REG_INVALID)
			add_reg_to_rw_list(MI, op->idx.offset_reg, READ);

		if (op->idx.inc_dec) {
			add_reg_to_rw_list(MI, op->idx.base_reg, WRITE);
			if (op->idx.base_reg == M680X_REG_X &&
			    info->cpu.reg_byte_size[M680X_REG_H])
				add_reg_to_rw_list(MI, M680X_REG_H, WRITE);
		}

		break;

	default:
		break;
	}
}

static const e_access g_access_mode_to_access[4][15] = {
	{
		UNCHANGED, READ, WRITE, READ,  READ, READ,   WRITE, MODIFY,
		MODIFY, MODIFY, MODIFY, MODIFY, WRITE, READ, MODIFY,
	},
	{
		UNCHANGED, READ, WRITE, WRITE, READ, MODIFY, READ,  READ,
		WRITE, MODIFY, WRITE, MODIFY, MODIFY, READ, UNCHANGED,
	},
	{
		UNCHANGED, READ, WRITE, WRITE, READ, MODIFY, READ,  READ,
		WRITE, MODIFY, READ, READ, MODIFY, UNCHANGED, UNCHANGED,
	},
	{
		UNCHANGED, READ, WRITE, WRITE, MODIFY, MODIFY, READ, READ,
		WRITE, MODIFY, READ, READ, MODIFY, UNCHANGED, UNCHANGED,
	},
};

static e_access get_access(int operator_index, e_access_mode access_mode)
{
	int idx = (operator_index > 3) ? 3 : operator_index;

	return g_access_mode_to_access[idx][access_mode];
}

static void build_regs_read_write_counts(MCInst *MI, m680x_info *info,
					e_access_mode access_mode)
{
	cs_m680x *m680x = &info->m680x;
	int i;

	if (MI->flat_insn->detail == NULL || (!m680x->op_count))
		return;

	for (i = 0; i < m680x->op_count; ++i) {

		e_access access = get_access(i, access_mode);
		update_am_reg_list(MI, info, &m680x->operands[i], access);
	}
}

static void add_operators_access(MCInst *MI, m680x_info *info,
				e_access_mode access_mode)
{
	cs_m680x *m680x = &info->m680x;
	int offset = 0;
	int i;

	if (MI->flat_insn->detail == NULL || (!m680x->op_count) ||
		(access_mode == uuuu))
		return;

	for (i = 0; i < m680x->op_count; ++i) {

		// Ugly fix: MULD has a register operand, an immediate operand
		// AND an implicitly changed register W
		if (info->insn == M680X_INS_MULD && (i == 1))
			offset = 1;
		e_access access = get_access(i + offset, access_mode);
		m680x->operands[i].access = access;
	}
}

typedef struct insn_to_changed_regs {
	m680x_insn insn;
	e_access_mode access_mode;
	m680x_reg regs[10];
} insn_to_changed_regs;

static void set_changed_regs_read_write_counts(MCInst *MI, m680x_info *info)
{
//TABLE
#define EOL M680X_REG_INVALID
	static const insn_to_changed_regs changed_regs[] = {
		{ M680X_INS_BSR, mmmm, { M680X_REG_S, EOL } },
		{ M680X_INS_CALL, mmmm, { M680X_REG_S, EOL } },
		{
			M680X_INS_CWAI, mrrr, {
				M680X_REG_S, M680X_REG_PC, M680X_REG_U,
				M680X_REG_Y, M680X_REG_X, M680X_REG_DP,
				M680X_REG_D, M680X_REG_CC, EOL
			},
		},
		{ M680X_INS_DAA, mrrr, { M680X_REG_A, EOL } },
		{ M680X_INS_DIV, mmrr, {
			M680X_REG_A, M680X_REG_H, M680X_REG_X, EOL
			}
		},
		{ M680X_INS_EDIV, mmrr, {
			M680X_REG_D, M680X_REG_Y, M680X_REG_X, EOL
			}
		},
		{ M680X_INS_EDIVS, mmrr, {
			M680X_REG_D, M680X_REG_Y, M680X_REG_X, EOL
			}
		},
		{ M680X_INS_EMACS, mrrr, { M680X_REG_X, M680X_REG_Y, EOL } },
		{ M680X_INS_EMAXM, rrrr, { M680X_REG_D, EOL } },
		{ M680X_INS_EMINM, rrrr, { M680X_REG_D, EOL } },
		{ M680X_INS_EMUL, mmrr, { M680X_REG_D, M680X_REG_Y, EOL } },
		{ M680X_INS_EMULS, mmrr, { M680X_REG_D, M680X_REG_Y, EOL } },
		{ M680X_INS_ETBL, wmmm, { M680X_REG_A, M680X_REG_B, EOL } },
		{ M680X_INS_FDIV, mmmm, { M680X_REG_D, M680X_REG_X, EOL } },
		{ M680X_INS_IDIV, mmmm, { M680X_REG_D, M680X_REG_X, EOL } },
		{ M680X_INS_IDIVS, mmmm, { M680X_REG_D, M680X_REG_X, EOL } },
		{ M680X_INS_JSR, mmmm, { M680X_REG_S, EOL } },
		{ M680X_INS_LBSR, mmmm, { M680X_REG_S, EOL } },
		{ M680X_INS_MAXM, rrrr, { M680X_REG_A, EOL } },
		{ M680X_INS_MINM, rrrr, { M680X_REG_A, EOL } },
		{ M680X_INS_MEM, mmrr, {
			M680X_REG_X, M680X_REG_Y, M680X_REG_A, EOL
			}
		},
		{ M680X_INS_MUL, mmmm, { M680X_REG_A, M680X_REG_B, EOL } },
		{ M680X_INS_MULD, mwrr, { M680X_REG_D, M680X_REG_W, EOL } },
		{ M680X_INS_PSHA, rmmm, { M680X_REG_A, M680X_REG_S, EOL } },
		{ M680X_INS_PSHB, rmmm, { M680X_REG_B, M680X_REG_S, EOL } },
		{ M680X_INS_PSHC, rmmm, { M680X_REG_CC, M680X_REG_S, EOL } },
		{ M680X_INS_PSHD, rmmm, { M680X_REG_D, M680X_REG_S, EOL } },
		{ M680X_INS_PSHH, rmmm, { M680X_REG_H, M680X_REG_S, EOL } },
		{ M680X_INS_PSHX, rmmm, { M680X_REG_X, M680X_REG_S, EOL } },
		{ M680X_INS_PSHY, rmmm, { M680X_REG_Y, M680X_REG_S, EOL } },
		{ M680X_INS_PULA, wmmm, { M680X_REG_A, M680X_REG_S, EOL } },
		{ M680X_INS_PULB, wmmm, { M680X_REG_B, M680X_REG_S, EOL } },
		{ M680X_INS_PULC, wmmm, { M680X_REG_CC, M680X_REG_S, EOL } },
		{ M680X_INS_PULD, wmmm, { M680X_REG_D, M680X_REG_S, EOL } },
		{ M680X_INS_PULH, wmmm, { M680X_REG_H, M680X_REG_S, EOL } },
		{ M680X_INS_PULX, wmmm, { M680X_REG_X, M680X_REG_S, EOL } },
		{ M680X_INS_PULY, wmmm, { M680X_REG_Y, M680X_REG_S, EOL } },
		{
			M680X_INS_REV, mmrr, {
				M680X_REG_A, M680X_REG_X, M680X_REG_Y, EOL
			}
		},
		{
			M680X_INS_REVW, mmmm, {
				M680X_REG_A, M680X_REG_X, M680X_REG_Y, EOL
			}
		},
		{ M680X_INS_RTC, mwww, { M680X_REG_S, M680X_REG_PC, EOL } },
		{
			M680X_INS_RTI, mwww, {
				M680X_REG_S, M680X_REG_CC, M680X_REG_B,
				M680X_REG_A, M680X_REG_DP, M680X_REG_X,
				M680X_REG_Y, M680X_REG_U, M680X_REG_PC,
				EOL
			},
		},
		{ M680X_INS_RTS, mwww, { M680X_REG_S, M680X_REG_PC, EOL } },
		{ M680X_INS_SEX, wrrr, { M680X_REG_A, M680X_REG_B, EOL } },
		{ M680X_INS_SEXW, rwww, { M680X_REG_W, M680X_REG_D, EOL } },
		{
			M680X_INS_SWI, mmrr, {
				M680X_REG_S, M680X_REG_PC, M680X_REG_U,
				M680X_REG_Y, M680X_REG_X, M680X_REG_DP,
				M680X_REG_A, M680X_REG_B, M680X_REG_CC,
				EOL
			}
		},
		{
			M680X_INS_SWI2, mmrr, {
				M680X_REG_S, M680X_REG_PC, M680X_REG_U,
				M680X_REG_Y, M680X_REG_X, M680X_REG_DP,
				M680X_REG_A, M680X_REG_B, M680X_REG_CC,
				EOL
			},
		},
		{
			M680X_INS_SWI3, mmrr, {
				M680X_REG_S, M680X_REG_PC, M680X_REG_U,
				M680X_REG_Y, M680X_REG_X, M680X_REG_DP,
				M680X_REG_A, M680X_REG_B, M680X_REG_CC,
				EOL
			},
		},
		{ M680X_INS_TBL, wrrr, { M680X_REG_A, M680X_REG_B, EOL } },
		{
			M680X_INS_WAI, mrrr, {
				M680X_REG_S, M680X_REG_PC, M680X_REG_X,
				M680X_REG_A, M680X_REG_B, M680X_REG_CC,
				EOL
			}
		},
		{
			M680X_INS_WAV, rmmm, {
				M680X_REG_A, M680X_REG_B, M680X_REG_X,
				M680X_REG_Y, EOL
			}
		},
		{
			M680X_INS_WAVR, rmmm, {
				M680X_REG_A, M680X_REG_B, M680X_REG_X,
				M680X_REG_Y, EOL
			}
		},
	};

	int i, j;

	if (MI->flat_insn->detail == NULL)
		return;

	for (i = 0; i < ARR_SIZE(changed_regs); ++i) {
		if (info->insn == changed_regs[i].insn) {
			e_access_mode access_mode = changed_regs[i].access_mode;

			for (j = 0; changed_regs[i].regs[j] != EOL; ++j) {
				e_access access;

				m680x_reg reg = changed_regs[i].regs[j];
				if (!info->cpu.reg_byte_size[reg])
				{
					if (info->insn != M680X_INS_MUL)
						continue;
					// Hack for M68HC05: MUL uses reg. A,X
					reg = M680X_REG_X;
				}
				access = get_access(j, access_mode);
				add_reg_to_rw_list(MI, reg, access);
			}
		}
	}
#undef EOL
}

typedef struct insn_desc {
	uint32_t opcode;
	m680x_insn insn;
	insn_hdlr_id handler_id;
	uint16_t insn_size;
} insn_desc;

static bool is_indexed09_post_byte_valid(const m680x_info *info,
	uint16_t address, uint8_t post_byte, insn_desc *insn_description)
{
	uint8_t ir;

	switch (post_byte & 0x9F) {
	case 0x87:
	case 0x8A:
	case 0x8E:
	case 0x8F:
	case 0x90:
	case 0x92:
	case 0x97:
	case 0x9A:
	case 0x9E:
		return false; // illegal indexed post bytes

	case 0x88: // n8,R
	case 0x8C: // n8,PCR
	case 0x98: // [n8,R]
	case 0x9C: // [n8,PCR]
		insn_description->insn_size++;
		return read_byte(info, &ir, address);

	case 0x89: // n16,R
	case 0x8D: // n16,PCR
	case 0x99: // [n16,R]
	case 0x9D: // [n16,PCR]
		insn_description->insn_size += 2;
		return read_byte(info, &ir, address + 1);

	case 0x9F: // [n]
		insn_description->insn_size += 2;
		return (post_byte & 0x60) == 0 &&
			read_byte(info, &ir, address + 1);
	}

	return true; // Any other indexed post byte is valid and
	// no additional bytes have to be read.
}

static bool is_indexed12_post_byte_valid(const m680x_info *info,
	uint16_t *address, uint8_t post_byte, insn_desc *insn_description,
	bool is_subset)
{
	uint8_t ir;
	bool result;

	if (!(post_byte & 0x20)) // n5,R
		return true;

	switch (post_byte & 0xe7) {
	case 0xe0:
	case 0xe1: // n9,R
		if (is_subset)
			return false;
		insn_description->insn_size++;
		return read_byte(info, &ir, (*address)++);
	case 0xe2: // n16,R
	case 0xe3: // [n16,R]
		if (is_subset)
			return false;
		insn_description->insn_size += 2;
		result = read_byte(info, &ir, *address + 1);
		*address += 2;
		return result;
	case 0xe4: // A,R
	case 0xe5: // B,R
	case 0xe6: // D,R
	case 0xe7: // [D,R]
	default: // n,-r n,+r n,r- n,r+
		break;
	}

	return true;
}

// Check for M6809/HD6309 TFR/EXG instruction for valid register
static bool is_tfr09_reg_valid(const m680x_info *info, uint8_t reg_nibble)
{
	if (info->cpu.tfr_reg_valid != NULL)
		return info->cpu.tfr_reg_valid[reg_nibble];

	return true; // e.g. for the M6309 all registers are valid
}

// Check for CPU12 TFR/EXG instruction for valid register
static bool is_exg_tfr12_post_byte_valid(const m680x_info *info,
		 uint8_t post_byte)
{
	return !(post_byte & 0x08);
}

static bool is_tfm_reg_valid(const m680x_info *info, uint8_t reg_nibble)
{
	// HD6809 TFM instruction: Only register X,Y,U,S,D is allowed
	return reg_nibble <= 4;
}

static bool is_loop_post_byte_valid(const m680x_info *info, uint8_t post_byte)
{
	// According to documentation bit 3 is don't care and not checked here.
	if (post_byte >= 0xc0)
		return false;
	return ((post_byte & 0x07) != 2 && ((post_byte & 0x07) != 3));
}

static bool is_sufficient_code_size(const m680x_info *info, uint16_t address,
	insn_desc *insn_description)
{
	uint8_t ir;
	bool is_subset = false;

	switch (insn_description->handler_id) {

	case immediate32_hdlr_id:
	case ext_imm_rel_hdlr_id:
	case imm16_extended_hdlr_id:
	case ext_ext_hdlr_id:
		insn_description->insn_size += 4;
		return read_byte(info, &ir, address + 3);

	case relative16_hdlr_id:
	case extended_hdlr_id:
	case immediate16_hdlr_id:
        case imm_rel_hdlr_id:
        case direct_rel_hdlr_id:
	case imm_direct_hdlr_id:
	case imm_indexedX_hdlr_id:
	case direct_imm_hdlr_id:
	case idxX_imm_hdlr_id:
	case idxY_imm_hdlr_id:
	case opidx_dir_rel_hdlr_id:
	case indexedX16_hdlr_id:
	case indexedS16_hdlr_id:
	case indexedX_rel_hdlr_id:
	case indexedXp_rel_hdlr_id:
	case indexedS_rel_hdlr_id:
	case direct_direct_hdlr_id:
		insn_description->insn_size += 2;
		return read_byte(info, &ir, address + 1);

	case relative8_hdlr_id:
	case direct_hdlr_id:
	case reg_bits_hdlr_id:
	case immediate8_hdlr_id:
	case opidx_direct_hdlr_id:
	case indexedX_hdlr_id:
	case indexedY_hdlr_id:
	case indexedS_hdlr_id:
	case indexedX0_rel_hdlr_id:
	case idxX0p_rel_hdlr_id:
	case idxX0p_direct_hdlr_id:
	case direct_idxX0p_hdlr_id:
		insn_description->insn_size += 1;
		return read_byte(info, &ir, address);

	case illegal_hdlr_id:
	case inherent_hdlr_id:
	case indexedX0_hdlr_id:
		return true;

	case indexed09_hdlr_id:
		insn_description->insn_size += 1;
		if (!read_byte(info, &ir, address++))
			return false;

		return is_indexed09_post_byte_valid(info, address, ir,
				insn_description);

	case indexed12s_hdlr_id:
		is_subset = true;
		// intentionally fall through

	case indexed12_hdlr_id:
		insn_description->insn_size += 1;
		if (!read_byte(info, &ir, address++))
			return false;

		return is_indexed12_post_byte_valid(info, &address, ir,
				insn_description, is_subset);

	case indexed12_imm_hdlr_id:
		insn_description->insn_size += 1;
		if (!read_byte(info, &ir, address++))
			return false;

		if (!is_indexed12_post_byte_valid(info, &address, ir,
				insn_description, false))
			return false;

		insn_description->insn_size += 1;
		return read_byte(info, &ir, address++);

	case ext_idx12_x_hdlr_id:
	case imm16_idx12_x_hdlr_id:
	case idx12_ext_hdlr_id:
		insn_description->insn_size += 1;
		if (!read_byte(info, &ir, address++))
			return false;

		if (!is_indexed12_post_byte_valid(info, &address, ir,
				insn_description, false))
			return false;

		insn_description->insn_size += 2;
		return read_byte(info, &ir, address + 1);

	case idx12_imm_rel_hdlr_id:
		insn_description->insn_size += 1;
		if (!read_byte(info, &ir, address++))
			return false;

		if (!is_indexed12_post_byte_valid(info, &address, ir,
				insn_description, false))
			return false;

		insn_description->insn_size += 1;
		if (!read_byte(info, &ir, address++)) // immediate8 value
			return false;

		insn_description->insn_size += 1;
		return read_byte(info, &ir, address++); // relative8 value

	case imm8_idx12_x_hdlr_id:
	case idx12_index_hdlr_id:
		insn_description->insn_size += 1;
		if (!read_byte(info, &ir, address++))
			return false;

		if (!is_indexed12_post_byte_valid(info, &address, ir,
				insn_description, false))
			return false;

		insn_description->insn_size += 1;
		return read_byte(info, &ir, address++); // index value

	case idx12_idx12_hdlr_id:
		insn_description->insn_size += 1;
		if (!read_byte(info, &ir, address++))
			return false;

		if (!is_indexed12_post_byte_valid(info, &address, ir,
				insn_description, false))
			return false;

		insn_description->insn_size += 1;
		if (!read_byte(info, &ir, address++))
			return false;

		return is_indexed12_post_byte_valid(info, &address, ir,
				insn_description, false);

	case tfm_hdlr_id:
		insn_description->insn_size += 1;
		if (!read_byte(info, &ir, address))
			return false;

		return is_tfm_reg_valid(info, (ir >> 4) & 0x0F) &&
			is_tfm_reg_valid(info, ir & 0x0F);

	case reg_reg09_hdlr_id:
		insn_description->insn_size += 1;
		if (!read_byte(info, &ir, address))
			return false;

		return is_tfr09_reg_valid(info, (ir >> 4) & 0x0F) &&
			is_tfr09_reg_valid(info, ir & 0x0F);

	case reg_reg12_hdlr_id:
		insn_description->insn_size += 1;
		if (!read_byte(info, &ir, address))
			return false;

		return is_exg_tfr12_post_byte_valid(info, ir);

	case bit_move_hdlr_id:
		insn_description->insn_size += 2;
		if (!read_byte(info, &ir, address))
			return false;
		if ((ir & 0xc0) == 0xc0)
			return false; // Invalid register specified
		return read_byte(info, &ir, address + 1);

	case imm_indexed09_hdlr_id:
		insn_description->insn_size += 1;
		// Check for sufficient code for immediate value
		if (!read_byte(info, &ir, address))
			return false;

		// Check for sufficient code for indexed post byte value
		address++;
		insn_description->insn_size += 1;
		if (!read_byte(info, &ir, address))
			return false;

		return is_indexed09_post_byte_valid(info, address, ir,
				insn_description);

	case imm8_extended_hdlr_id:
	case dir_imm_rel_hdlr_id:
	case idxX_imm_rel_hdlr_id:
	case idxY_imm_rel_hdlr_id:
	case extended_imm_hdlr_id:
	case ext_index_hdlr_id:
		insn_description->insn_size += 3;
		return read_byte(info, &ir, address + 2);

	case loop_hdlr_id:
		insn_description->insn_size += 2;
		if (!read_byte(info, &ir, address))
			return false;
		if (!is_loop_post_byte_valid(info, ir))
			return false;
		return read_byte(info, &ir, address + 1);

	default:
		fprintf(stderr, "Internal error: Unexpected instruction "
			"handler id %d\n",
			insn_description->handler_id);
	}

	return false;
}

// Check for a valid M680X instruction AND for enough bytes in the code buffer
// Return an instruction description in insn_desc.
static bool decode_insn(const m680x_info *info, uint16_t address,
	insn_desc *insn_description)
{
	const inst_pageX *inst_table = NULL;
	const cpu_tables *cpu = &info->cpu;
	int table_size = 0;
	uint16_t base_address = address;
	uint8_t ir; // instruction register
	int i;
	int index;

	if (!read_byte(info, &ir, address++))
		return false;

	insn_description->opcode = ir;

	// Check if a page prefix byte is present
	for (i = 0; i < ARR_SIZE(cpu->pageX_table_size); ++i) {
		if (cpu->pageX_table_size[i] == 0 ||
			(cpu->inst_pageX_table[i] == NULL))
			break;

		if ((cpu->pageX_prefix[i] == ir)) {
			inst_table = cpu->inst_pageX_table[i];
			table_size = cpu->pageX_table_size[i];
		}
	}

	if (inst_table != NULL) {
		// Get pageX instruction and handler id. Abort for illegal instr.
		if (!read_byte(info, &ir, address++))
			return false;

		insn_description->opcode = (insn_description->opcode << 8) | ir;

		if ((index = binary_search(inst_table, table_size, ir)) < 0)
			return false;

		insn_description->handler_id = inst_table[index].handler_id;
		insn_description->insn = inst_table[index].insn;
	}
	else {
		bool insn_found = false;

		// Check if opcode byte is present in an overlay table
		for (i = 0; i < ARR_SIZE(cpu->overlay_table_size); ++i) {
			if (cpu->overlay_table_size[i] == 0 ||
				(cpu->inst_overlay_table[i] == NULL))
				break;

			inst_table = cpu->inst_overlay_table[i];
			table_size = cpu->overlay_table_size[i];

			if ((index = binary_search(inst_table, table_size, ir)) >= 0) {
				insn_description->handler_id = inst_table[index].handler_id;
				insn_description->insn = inst_table[index].insn;
				insn_found = true;
			}
		}

		if (!insn_found) {
			// Get page1 insn description
			insn_description->handler_id = cpu->inst_page1_table[ir].handler_id;
			insn_description->insn = cpu->inst_page1_table[ir].insn;
		}
	}

	insn_description->insn_size = address - base_address;

	return (insn_description->insn != M680X_INS_INVLD) &&
		(insn_description->insn != M680X_INS_ILLGL) &&
		is_sufficient_code_size(info, address, insn_description);
}

static void illegal_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x_op *op0 = &info->m680x.operands[info->m680x.op_count++];
	uint8_t temp8 = 0;

	info->insn = M680X_INS_ILLGL;
	read_byte(info, &temp8, (*address)++);
	op0->imm = (int32_t)temp8 & 0xff;
	op0->type = M680X_OP_IMMEDIATE;
	op0->size = 1;
}

static void inherent_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	info->m680x.address_mode = M680X_AM_INHERENT;
}

static void add_reg_operand(m680x_info *info, m680x_reg reg)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op = &m680x->operands[m680x->op_count++];

	op->type = M680X_OP_REGISTER;
	op->reg = reg;
	op->size = info->cpu.reg_byte_size[reg];
}

static void set_operand_size(m680x_info *info, cs_m680x_op *op,
				uint8_t default_size)
{
	cs_m680x *m680x = &info->m680x;

	if (info->insn == M680X_INS_JMP || info->insn == M680X_INS_JSR)
		op->size = 0;
	else if (info->insn == M680X_INS_DIVD ||
		((info->insn == M680X_INS_AIS || info->insn == M680X_INS_AIX) &&
		   op->type != M680X_OP_REGISTER))
		op->size = 1;
	else if (info->insn == M680X_INS_DIVQ ||
		info->insn == M680X_INS_MOVW)
		op->size = 2;
	else if (info->insn == M680X_INS_EMACS)
		op->size = 4;
	else if ((m680x->op_count > 0) &&
		(m680x->operands[0].type == M680X_OP_REGISTER))
		op->size = m680x->operands[0].size;
	else	
		op->size = default_size;
}

static const m680x_reg reg_s_reg_ids[] = {
	M680X_REG_CC, M680X_REG_A, M680X_REG_B, M680X_REG_DP,
	M680X_REG_X,  M680X_REG_Y, M680X_REG_U, M680X_REG_PC,
};

static const m680x_reg reg_u_reg_ids[] = {
	M680X_REG_CC, M680X_REG_A, M680X_REG_B, M680X_REG_DP,
	M680X_REG_X,  M680X_REG_Y, M680X_REG_S, M680X_REG_PC,
};

static void reg_bits_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op0 = &m680x->operands[0];
	uint8_t reg_bits = 0;
	uint16_t bit_index;
	const m680x_reg *reg_to_reg_ids;

	m680x->address_mode = M680X_AM_REGISTER;

	read_byte(info, &reg_bits, (*address)++);

	switch (op0->reg) {
	case M680X_REG_U:
		reg_to_reg_ids = &reg_u_reg_ids[0];
		break;

	case M680X_REG_S:
		reg_to_reg_ids = &reg_s_reg_ids[0];
		break;

	default:
		fprintf(stderr, "Internal error: Unexpected operand0 register "
			"%d\n", op0->reg);
		abort();
	}

	if ((info->insn == M680X_INS_PULU ||
			(info->insn == M680X_INS_PULS)) &&
		((reg_bits & 0x80) != 0))
		// PULS xxx,PC or PULU xxx,PC which is like return from
		// subroutine (RTS)
		add_insn_group(MI->flat_insn->detail, M680X_GRP_RET);

	for (bit_index = 0; bit_index < 8; ++bit_index) {
		if (reg_bits & (1 << bit_index))
			add_reg_operand(info, reg_to_reg_ids[bit_index]);
	}
}

static const m680x_reg g_tfr_exg_reg_ids[] = {
	/* 16-bit registers */
	M680X_REG_D, M680X_REG_X,  M680X_REG_Y,  M680X_REG_U,
	M680X_REG_S, M680X_REG_PC, M680X_REG_W,  M680X_REG_V,
	/* 8-bit registers */
	M680X_REG_A, M680X_REG_B,  M680X_REG_CC, M680X_REG_DP,
	M680X_REG_0, M680X_REG_0,  M680X_REG_E,  M680X_REG_F,
};

static void reg_reg09_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	uint8_t regs = 0;

	m680x->address_mode = M680X_AM_REGISTER;

	read_byte(info, &regs, (*address)++);

	add_reg_operand(info, g_tfr_exg_reg_ids[regs >> 4]);
	add_reg_operand(info, g_tfr_exg_reg_ids[regs & 0x0f]);

	if ((regs & 0x0f) == 0x05) {
		// EXG xxx,PC or TFR xxx,PC which is like a JMP
		add_insn_group(MI->flat_insn->detail, M680X_GRP_JUMP);
	}
}


static void reg_reg12_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	static const m680x_reg g_tfr_exg12_reg0_ids[] = {
		M680X_REG_A, M680X_REG_B,  M680X_REG_CC,  M680X_REG_TMP3,
		M680X_REG_D, M680X_REG_X, M680X_REG_Y,  M680X_REG_S,
	};
	static const m680x_reg g_tfr_exg12_reg1_ids[] = {
		M680X_REG_A, M680X_REG_B,  M680X_REG_CC,  M680X_REG_TMP2,
		M680X_REG_D, M680X_REG_X, M680X_REG_Y,  M680X_REG_S,
	};
	cs_m680x *m680x = &info->m680x;
	uint8_t regs = 0;

	m680x->address_mode = M680X_AM_REGISTER;

	read_byte(info, &regs, (*address)++);

	// The opcode of this instruction depends on
	// the msb of its post byte.
	if (regs & 0x80)
		info->insn = M680X_INS_EXG;
	else
		info->insn = M680X_INS_TFR;

	add_reg_operand(info, g_tfr_exg12_reg0_ids[(regs >> 4) & 0x07]);
	add_reg_operand(info, g_tfr_exg12_reg1_ids[regs & 0x07]);
}

static void add_rel_operand(m680x_info *info, int16_t offset, uint16_t address)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op = &m680x->operands[m680x->op_count++];

	m680x->address_mode = M680X_AM_RELATIVE;

	op->type = M680X_OP_RELATIVE;
	op->size = 0;
	op->rel.offset = offset;
	op->rel.address = address;
}

static void relative8_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	int16_t offset = 0;

	read_byte_sign_extended(info, &offset, (*address)++);
	add_rel_operand(info, offset, *address + offset);
	add_insn_group(MI->flat_insn->detail, M680X_GRP_BRAREL);

	if ((info->insn != M680X_INS_BRA) &&
		(info->insn != M680X_INS_BSR) &&
		(info->insn != M680X_INS_BRN))
		add_reg_to_rw_list(MI, M680X_REG_CC, READ);
}

static void relative16_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	uint16_t offset = 0;

	read_word(info, &offset, *address);
	*address += 2;
	add_rel_operand(info, (int16_t)offset, *address + offset);
	add_insn_group(MI->flat_insn->detail, M680X_GRP_BRAREL);

	if ((info->insn != M680X_INS_LBRA) &&
		(info->insn != M680X_INS_LBSR) &&
		(info->insn != M680X_INS_LBRN))
		add_reg_to_rw_list(MI, M680X_REG_CC, READ);
}

static const m680x_reg g_rr5_to_reg_ids[] = {
	M680X_REG_X, M680X_REG_Y, M680X_REG_U, M680X_REG_S,
};

static void add_indexed_operand(m680x_info *info, m680x_reg base_reg,
	bool post_inc_dec, uint8_t inc_dec, uint8_t offset_bits,
	uint16_t offset, bool no_comma)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op = &m680x->operands[m680x->op_count++];

	op->type = M680X_OP_INDEXED;
	set_operand_size(info, op, 1);
	op->idx.base_reg = base_reg;
	op->idx.offset_reg = M680X_REG_INVALID;
	op->idx.inc_dec = inc_dec;
	if (inc_dec && post_inc_dec)
		op->idx.flags |= M680X_IDX_POST_INC_DEC;
	if (offset_bits != M680X_OFFSET_NONE) {
		op->idx.offset = offset;
		op->idx.offset_addr = 0;
	}
	op->idx.offset_bits = offset_bits;
	op->idx.flags |= (no_comma ? M680X_IDX_NO_COMMA : 0);
}

// M6800/1/2/3 indexed mode handler
static void indexedX_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	uint8_t offset = 0;

	m680x->address_mode = M680X_AM_INDEXED;

	read_byte(info, &offset, (*address)++);

	add_indexed_operand(info, M680X_REG_X, false, 0, M680X_OFFSET_BITS_8,
				 (uint16_t)offset, false);
}

static void indexedY_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	uint8_t offset = 0;

	m680x->address_mode = M680X_AM_INDEXED;

	read_byte(info, &offset, (*address)++);

	add_indexed_operand(info, M680X_REG_Y, false, 0, M680X_OFFSET_BITS_8,
				 (uint16_t)offset, false);
}

// M6809/M6309 indexed mode handler
static void indexed09_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op = &m680x->operands[m680x->op_count++];
	uint8_t post_byte = 0;
	uint16_t offset = 0;
	int16_t soffset = 0;

	m680x->address_mode = M680X_AM_INDEXED;

	read_byte(info, &post_byte, (*address)++);

	op->type = M680X_OP_INDEXED;
	set_operand_size(info, op, 1);
	op->idx.base_reg = g_rr5_to_reg_ids[(post_byte >> 5) & 0x03];
	op->idx.offset_reg = M680X_REG_INVALID;

	if (!(post_byte & 0x80)) {
		// n5,R
		if ((post_byte & 0x10) == 0x10)
			op->idx.offset = post_byte | 0xfff0;
		else
			op->idx.offset = post_byte & 0x0f;

		op->idx.offset_addr = op->idx.offset + *address;
		op->idx.offset_bits = M680X_OFFSET_BITS_5;
	}
	else {
		if ((post_byte & 0x10) == 0x10)
			op->idx.flags |= M680X_IDX_INDIRECT;

		// indexed addressing
		switch (post_byte & 0x1f) {
		case 0x00: // ,R+
			op->idx.inc_dec = 1;
			op->idx.flags |= M680X_IDX_POST_INC_DEC;
			break;

		case 0x11: // [,R++]
		case 0x01: // ,R++
			op->idx.inc_dec = 2;
			op->idx.flags |= M680X_IDX_POST_INC_DEC;
			break;

		case 0x02: // ,-R
			op->idx.inc_dec = -1;
			break;

		case 0x13: // [,--R]
		case 0x03: // ,--R
			op->idx.inc_dec = -2;
			break;

		case 0x14: // [,R]
		case 0x04: // ,R
			break;

		case 0x15: // [B,R]
		case 0x05: // B,R
			op->idx.offset_reg = M680X_REG_B;
			break;

		case 0x16: // [A,R]
		case 0x06: // A,R
			op->idx.offset_reg = M680X_REG_A;
			break;

		case 0x1c: // [n8,PCR]
		case 0x0c: // n8,PCR
			op->idx.base_reg = M680X_REG_PC;
			read_byte_sign_extended(info, &soffset, (*address)++);
			op->idx.offset_addr = offset + *address;
			op->idx.offset = soffset;
			op->idx.offset_bits = M680X_OFFSET_BITS_8;
			break;

		case 0x18: // [n8,R]
		case 0x08: // n8,R
			read_byte_sign_extended(info, &soffset, (*address)++);
			op->idx.offset = soffset;
			op->idx.offset_bits = M680X_OFFSET_BITS_8;
			break;

		case 0x1d: // [n16,PCR]
		case 0x0d: // n16,PCR
			op->idx.base_reg = M680X_REG_PC;
			read_word(info, &offset, *address);
			*address += 2;
			op->idx.offset_addr = offset + *address;
			op->idx.offset = (int16_t)offset;
			op->idx.offset_bits = M680X_OFFSET_BITS_16;
			break;

		case 0x19: // [n16,R]
		case 0x09: // n16,R
			read_word(info, &offset, *address);
			*address += 2;
			op->idx.offset = (int16_t)offset;
			op->idx.offset_bits = M680X_OFFSET_BITS_16;
			break;

		case 0x1b: // [D,R]
		case 0x0b: // D,R
			op->idx.offset_reg = M680X_REG_D;
			break;

		case 0x1f: // [n16]
			m680x->address_mode = M680X_AM_EXTENDED;
			op->type = M680X_OP_EXTENDED;
			op->ext.indirect = true;
			read_word(info, &op->ext.address, *address);
			*address += 2;
			break;

		default:
			op->idx.base_reg = M680X_REG_INVALID;
			break;
		}
	}

	if (((info->insn == M680X_INS_LEAU) ||
			(info->insn == M680X_INS_LEAS) ||
			(info->insn == M680X_INS_LEAX) ||
			(info->insn == M680X_INS_LEAY)) &&
		(m680x->operands[0].reg == M680X_REG_X ||
			(m680x->operands[0].reg == M680X_REG_Y)))
		// Only LEAX and LEAY modify CC register
		add_reg_to_rw_list(MI, M680X_REG_CC, MODIFY);
}


m680x_reg g_idx12_to_reg_ids[4] = {
	M680X_REG_X, M680X_REG_Y, M680X_REG_S, M680X_REG_PC,
};

m680x_reg g_or12_to_reg_ids[3] = {
	M680X_REG_A, M680X_REG_B, M680X_REG_D
};

// CPU12 indexed mode handler
static void indexed12_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op = &m680x->operands[m680x->op_count++];
	uint8_t post_byte = 0;
	uint8_t offset8 = 0;

	m680x->address_mode = M680X_AM_INDEXED;

	read_byte(info, &post_byte, (*address)++);

	op->type = M680X_OP_INDEXED;
	set_operand_size(info, op, 1);
	op->idx.offset_reg = M680X_REG_INVALID;

	if (!(post_byte & 0x20)) {
		// n5,R      n5 is a 5-bit signed offset
		op->idx.base_reg = g_idx12_to_reg_ids[(post_byte >> 6) & 0x03];
		if ((post_byte & 0x10) == 0x10)
			op->idx.offset = post_byte | 0xfff0;
		else
			op->idx.offset = post_byte & 0x0f;

		op->idx.offset_addr = op->idx.offset + *address;
		op->idx.offset_bits = M680X_OFFSET_BITS_5;
	}
	else {
		if ((post_byte & 0xe0) == 0xe0)
			op->idx.base_reg =
				g_idx12_to_reg_ids[(post_byte >> 3) & 0x03];
		switch (post_byte & 0xe7) {
		case 0xe0:
		case 0xe1: // n9,R
			read_byte(info, &offset8, (*address)++);
			op->idx.offset = offset8;
			if (post_byte & 0x01) // sign extension
				op->idx.offset |= 0xff00;
			op->idx.offset_bits = M680X_OFFSET_BITS_9;
			if (op->idx.base_reg == M680X_REG_PC)
				op->idx.offset_addr = op->idx.offset + *address;
			break;
		case 0xe3: // [n16,R]
			op->idx.flags |= M680X_IDX_INDIRECT;
			// intentionally fall through
		case 0xe2: // n16,R
			read_word(info, (uint16_t *)&op->idx.offset, *address);
			(*address) += 2;
			op->idx.offset_bits = M680X_OFFSET_BITS_16;
			if (op->idx.base_reg == M680X_REG_PC)
				op->idx.offset_addr = op->idx.offset + *address;
			break;
		case 0xe4: // A,R
		case 0xe5: // B,R
		case 0xe6: // D,R
			op->idx.offset_reg =
				g_or12_to_reg_ids[post_byte & 0x03];
			break;
		case 0xe7: // [D,R]
			op->idx.offset_reg = M680X_REG_D;
			op->idx.flags |= M680X_IDX_INDIRECT;
			break;
		default: // n,-r n,+r n,r- n,r+
			// PC is not allowed in this mode
			op->idx.base_reg =
				g_idx12_to_reg_ids[(post_byte >> 6) & 0x03];
			op->idx.inc_dec = post_byte & 0x0f;
			if (op->idx.inc_dec & 0x08) // evtl. sign extend value
				op->idx.inc_dec |= 0xf0;
			if (op->idx.inc_dec >= 0)
				op->idx.inc_dec++;
			if (post_byte & 0x10)
				op->idx.flags |= M680X_IDX_POST_INC_DEC;
			break;

		}
	}
}

static void direct_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op = &m680x->operands[m680x->op_count++];

	m680x->address_mode = M680X_AM_DIRECT;

	op->type = M680X_OP_DIRECT;
	set_operand_size(info, op, 1);
	read_byte(info, &op->direct_addr, (*address)++);
};

static void extended_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op = &m680x->operands[m680x->op_count++];

	m680x->address_mode = M680X_AM_EXTENDED;

	op->type = M680X_OP_EXTENDED;
	set_operand_size(info, op, 1);
	read_word(info, &op->ext.address, *address);
	*address += 2;
}

static void immediate_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op = &m680x->operands[m680x->op_count++];
	uint16_t word = 0;
	int16_t sword = 0;

	m680x->address_mode = M680X_AM_IMMEDIATE;

	op->type = M680X_OP_IMMEDIATE;
	set_operand_size(info, op, 1);

	switch (op->size) {
	case 1:
		read_byte_sign_extended(info, &sword, *address);
		op->imm = sword;
		break;

	case 2:
		read_word(info, &word, *address);
		op->imm = (int16_t)word;
		break;

	case 4:
		read_sdword(info, &op->imm, *address);
		break;

	default:
		op->imm = 0;
		fprintf(stderr, "Internal error: Unexpected immediate byte "
			"size %d.\n", op->size);
	}

	*address += op->size;
}

// handler for immediate,direct addr. mode. Used by HD6301/9
static void imm_direct_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;

	immediate_hdlr(MI, info, address);
	direct_hdlr(MI, info, address);

	m680x->address_mode = M680X_AM_IMM_DIRECT;
}

// handler for immediate,indexed addr. mode. Used by HD6301
static void imm_indexedX_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;

	immediate_hdlr(MI, info, address);
	indexedX_hdlr(MI, info, address);

	m680x->address_mode = M680X_AM_IMM_INDEXED;
}

// handler for immediate,indexed addr. mode. Used by HD6309
static void imm_indexed09_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;

	immediate_hdlr(MI, info, address);
	indexed09_hdlr(MI, info, address);

	m680x->address_mode = M680X_AM_IMM_INDEXED;
}

// handler for immediate,extended addr. mode. Used by HD6309, CPU12
static void imm_extended_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;

	immediate_hdlr(MI, info, address);
	extended_hdlr(MI, info, address);

	m680x->address_mode = M680X_AM_IMM_EXTENDED;
}

static void ext_ext_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;

	extended_hdlr(MI, info, address);
	extended_hdlr(MI, info, address);

	m680x->address_mode = M680X_AM_EXT_EXT;
}

// handler for bit move instructions, e.g: BAND A,5,1,$40  Used by HD6309
static void bit_move_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	static const m680x_reg m680x_reg[] = {
		M680X_REG_CC, M680X_REG_A, M680X_REG_B, M680X_REG_INVALID, 
	};

	uint8_t post_byte = 0;
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op;

	read_byte(info, &post_byte, *address);
	(*address)++;

	// operand[0] = register
	add_reg_operand(info, m680x_reg[post_byte >> 6]);

	// operand[1] = bit index in source operand
	op = &m680x->operands[m680x->op_count++];
	op->type = M680X_OP_INDEX;
	op->index = (post_byte >> 3) & 0x07;

	// operand[2] = bit index in destination operand
	op = &m680x->operands[m680x->op_count++];
	op->type = M680X_OP_INDEX;
	op->index = post_byte & 0x07;

	direct_hdlr(MI, info, address);

	m680x->address_mode = M680X_AM_BIT_MOVE;
}

// handler for TFM instruction, e.g: TFM X+,Y+  Used by HD6309
static void tfm_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	static const uint8_t inc_dec_r0[] = {
		1, -1, 1, 0,
	};
	static const uint8_t inc_dec_r1[] = {
		1, -1, 0, 1,
	};
	cs_m680x *m680x = &info->m680x;
	uint8_t regs = 0;
	uint8_t index = (MI->Opcode & 0xff) - 0x38;

	read_byte(info, &regs, *address);

	add_indexed_operand(info, g_tfr_exg_reg_ids[regs >> 4], true,
				inc_dec_r0[index], M680X_OFFSET_NONE, 0, true);
	add_indexed_operand(info, g_tfr_exg_reg_ids[regs & 0x0f], true,
				inc_dec_r1[index], M680X_OFFSET_NONE, 0, true);

	m680x->address_mode = M680X_AM_INDEXED2;

	add_reg_to_rw_list(MI, M680X_REG_W, READ | WRITE);
}

// handler for direct,immediate,relative addr. mode. Used by M6811
static void dir_imm_rel_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;

	direct_hdlr(MI, info, address);
	immediate_hdlr(MI, info, address);
	relative8_hdlr(MI, info, address);

	m680x->address_mode = M680X_AM_DIR_IMM_REL;
}

// handler for indexed(X),immediate,relative addr. mode. Used by M6811
static void idxX_imm_rel_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;

	indexedX_hdlr(MI, info, address);
	immediate_hdlr(MI, info, address);
	relative8_hdlr(MI, info, address);

	m680x->address_mode = M680X_AM_IDX_IMM_REL;
}

// handler for indexed(Y),immediate,relative addr. mode. Used by M6811
static void idxY_imm_rel_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;

	indexedY_hdlr(MI, info, address);
	immediate_hdlr(MI, info, address);
	relative8_hdlr(MI, info, address);

	m680x->address_mode = M680X_AM_IDX_IMM_REL;
}

// handler for direct,immediate addr. mode. Used by M6811
// example BSET 5,$20
static void direct_imm_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;

	direct_hdlr(MI, info, address);
	immediate_hdlr(MI, info, address);

	add_reg_to_rw_list(MI, M680X_REG_CC, MODIFY);

	m680x->address_mode = M680X_AM_DIRECT_IMM;
}

// handler for indexed(X),immediate addr. mode. Used by M6811
// example BSET 5,16,X
static void idxX_imm_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;

	indexedX_hdlr(MI, info, address);
	immediate_hdlr(MI, info, address);

	add_reg_to_rw_list(MI, M680X_REG_CC, MODIFY);

	m680x->address_mode = M680X_AM_INDEXED_IMM;
}

// handler for indexed(Y),immediate addr. mode. Used by M6811
// example BSET 5,16,Y
static void idxY_imm_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;

	indexedY_hdlr(MI, info, address);
	immediate_hdlr(MI, info, address);

	add_reg_to_rw_list(MI, M680X_REG_CC, MODIFY);

	m680x->address_mode = M680X_AM_INDEXED_IMM;
}

// handler for bit test and branch instruction. Used by M6805.
// The bit index is part of the opcode.
// Example: BRSET 3,<$40,LOOP
static void opidx_dir_rel_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op = &m680x->operands[m680x->op_count++];

	// bit index is coded in Opcode
	op->type = M680X_OP_INDEX;
	op->index = (MI->Opcode & 0x0e) >> 1;
	direct_hdlr(MI, info, address);
	relative8_hdlr(MI, info, address);

	add_reg_to_rw_list(MI, M680X_REG_CC, MODIFY);

	m680x->address_mode = M680X_AM_INDEX_DIR_REL;
}

// handler for bit test instruction. Used by M6805.
// The bit index is part of the opcode.
// Example: BSET 3,<$40
static void opidx_direct_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op = &m680x->operands[m680x->op_count++];

	// bit index is coded in Opcode
	op->type = M680X_OP_INDEX;
	op->index = (MI->Opcode & 0x0e) >> 1;
	direct_hdlr(MI, info, address);

	m680x->address_mode = M680X_AM_INDEX_DIRECT;
}

static void indexedX0_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;

	add_indexed_operand(info, M680X_REG_X, false, 0, M680X_OFFSET_NONE,
				 0, false);

	m680x->address_mode = M680X_AM_INDEXED;
}

static void indexedX16_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	uint16_t offset = 0;

	read_word(info, &offset, *address);
	*address += 2;
	add_indexed_operand(info, M680X_REG_X, false, 0, M680X_OFFSET_BITS_16,
				offset, false);

	m680x->address_mode = M680X_AM_INDEXED;
}

static void imm_rel_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	immediate_hdlr(MI, info, address);
	relative8_hdlr(MI, info, address);

	info->m680x.address_mode = M680X_AM_IMM_REL;
}

static void direct_rel_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	direct_hdlr(MI, info, address);
	relative8_hdlr(MI, info, address);

	info->m680x.address_mode = M680X_AM_DIRECT_REL;
}

static void indexedS_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	uint8_t offset = 0;

	info->m680x.address_mode = M680X_AM_INDEXED;

	read_byte(info, &offset, (*address)++);

	add_indexed_operand(info, M680X_REG_S, false, 0, M680X_OFFSET_BITS_8,
				 (uint16_t)offset, false);
}

static void indexedS16_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	uint16_t offset = 0;

	info->m680x.address_mode = M680X_AM_INDEXED;

	read_word(info, &offset, *address);
	address += 2;

	add_indexed_operand(info, M680X_REG_S, false, 0, M680X_OFFSET_BITS_16,
				 offset, false);
}

static void indexedX0p_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	info->m680x.address_mode = M680X_AM_INDEXED;

	add_indexed_operand(info, M680X_REG_X, true, 1, M680X_OFFSET_NONE,
				 0, true);
}

static void indexedXp_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	uint8_t offset = 0;

	info->m680x.address_mode = M680X_AM_INDEXED;

	read_byte(info, &offset, (*address)++);

	add_indexed_operand(info, M680X_REG_X, true, 1, M680X_OFFSET_BITS_8,
				 (uint16_t)offset, false);
}

static void indexedS_rel_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	indexedS_hdlr(MI, info, address);
	relative8_hdlr(MI, info, address);

	info->m680x.address_mode = M680X_AM_INDEXED_REL;
}

static void indexedX_rel_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	indexedX_hdlr(MI, info, address);
	relative8_hdlr(MI, info, address);

	info->m680x.address_mode = M680X_AM_INDEXED_REL;
}

static void indexedX0_rel_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	indexedX0_hdlr(MI, info, address);
	relative8_hdlr(MI, info, address);

	info->m680x.address_mode = M680X_AM_INDEXED_REL;
}

static void indexedXp_rel_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	indexedXp_hdlr(MI, info, address);
	relative8_hdlr(MI, info, address);

	info->m680x.address_mode = M680X_AM_INDEXED_REL;
}

static void idxX0p_rel_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	indexedX0p_hdlr(MI, info, address);
	relative8_hdlr(MI, info, address);

	info->m680x.address_mode = M680X_AM_INDEXED_REL;
}

static void idxX0p_direct_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	indexedX0p_hdlr(MI, info, address);
	direct_hdlr(MI, info, address);

	info->m680x.address_mode = M680X_AM_INDEXED_DIR;
}

static void direct_direct_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	direct_hdlr(MI, info, address);
	direct_hdlr(MI, info, address);

	info->m680x.address_mode = M680X_AM_DIRECT2;
}

static void direct_idxX0p_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	direct_hdlr(MI, info, address);
	indexedX0p_hdlr(MI, info, address);

	info->m680x.address_mode = M680X_AM_DIRECT_IDX;
}

static void indexed12_imm_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	indexed12_hdlr(MI, info, address);
	immediate_hdlr(MI, info, address);

	info->m680x.address_mode = M680X_AM_INDEXED_IMM;
}

static void idx12_imm_rel_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	indexed12_hdlr(MI, info, address);
	immediate_hdlr(MI, info, address);
	relative8_hdlr(MI, info, address);

	info->m680x.address_mode = M680X_AM_IDX_IMM_REL;
}

static void ext_imm_rel_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	extended_hdlr(MI, info, address);
	immediate_hdlr(MI, info, address);
	relative8_hdlr(MI, info, address);

	info->m680x.address_mode = M680X_AM_EXT_IMM_REL;
}

static void idx12_idx12_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;

	indexed12_hdlr(MI, info, address);
	indexed12_hdlr(MI, info, address);

	m680x->address_mode = M680X_AM_INDEXED2;
}

static void idx12_ext_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	indexed12_hdlr(MI, info, address);
	extended_hdlr(MI, info, address);

	info->m680x.address_mode = M680X_AM_INDEXED_EXT;
}

static void imm_idx12_x_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op = &m680x->operands[m680x->op_count++];

	indexed12_hdlr(MI, info, address);
	op->type = M680X_OP_IMMEDIATE;
	if (info->insn == M680X_INS_MOVW) {
		uint16_t imm16 = 0;

		read_word(info, &imm16, *address);
		op->imm = (int16_t)imm16;
		op->size = 2;
	} else {
		uint8_t imm8 = 0;

		read_byte(info, &imm8, *address);
		op->imm = (int8_t)imm8;
		op->size = 1;
	}
	set_operand_size(info, op, 1);

	m680x->address_mode = M680X_AM_IMM_INDEXED;
}

static void ext_idx12_x_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	cs_m680x_op *op0 = &m680x->operands[m680x->op_count++];
	uint16_t imm16 = 0;

	indexed12_hdlr(MI, info, address);
	read_word(info, &imm16, *address);
	op0->type = M680X_OP_EXTENDED;
	op0->imm = (int16_t)imm16;
	set_operand_size(info, op0, 1);

	m680x->address_mode = M680X_AM_IMM_INDEXED;
}

static void extended_imm_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	extended_hdlr(MI, info, address);
	immediate_hdlr(MI, info, address);

	info->m680x.address_mode = M680X_AM_EXTENDED_IMM;
}

// handler for CPU12 CALL instruction.
// Example: CALL $8002,4
static void ext_index_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	uint8_t index = 0;

	extended_hdlr(MI, info, address);

	cs_m680x_op *op = &m680x->operands[m680x->op_count++];
	read_byte(info, &index, (*address)++);

	op->type = M680X_OP_INDEX;
	op->index = index;

	m680x->address_mode = M680X_AM_EXT_PAGE;
}

// handler for CPU12 CALL instruction.
// Example: CALL 8,Y;4
static void idx12_index_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	cs_m680x *m680x = &info->m680x;
	uint8_t index = 0;

	indexed12_hdlr(MI, info, address);

	cs_m680x_op *op = &m680x->operands[m680x->op_count++];
	read_byte(info, &index, (*address)++);

	op->type = M680X_OP_INDEX;
	op->index = index;

	m680x->address_mode = M680X_AM_EXT_PAGE;
}

// handler for CPU12 DBEQ/DNBE/IBEQ/IBNE/TBEQ/TBNE instructions.
// Example: DBNE X,$1000
static void loop_hdlr(MCInst *MI, m680x_info *info, uint16_t *address)
{
	static const m680x_reg index_to_reg_id[] = {
		M680X_REG_A, M680X_REG_B, M680X_REG_INVALID, M680X_REG_INVALID,
		M680X_REG_D, M680X_REG_X, M680X_REG_Y, M680X_REG_S,
	};
	static const m680x_insn index_to_insn_id[] = {
		M680X_INS_DBEQ, M680X_INS_DBNE, M680X_INS_TBEQ, M680X_INS_TBNE,
		M680X_INS_IBEQ, M680X_INS_IBNE, M680X_INS_ILLGL, M680X_INS_ILLGL
	};
	cs_m680x *m680x = &info->m680x;
	uint8_t post_byte = 0;
	uint8_t rel = 0;
	read_byte(info, &post_byte, (*address)++);

	info->insn = index_to_insn_id[(post_byte >> 5) & 0x07];
	if (info->insn == M680X_INS_ILLGL) {
		fprintf(stderr, "Internal error: Unexpected post byte "
			"in loop instruction %02X.\n", post_byte);
		illegal_hdlr(MI, info, address);
	};

	read_byte(info, &rel, (*address)++);

	add_reg_operand(info, index_to_reg_id[post_byte & 0x07]);
	cs_m680x_op *op = &m680x->operands[m680x->op_count++];

	op->type = M680X_OP_RELATIVE;
	op->rel.offset = (post_byte & 0x10) ? 0xff00 | rel : rel;
	op->rel.address = *address + op->rel.offset;

	add_insn_group(MI->flat_insn->detail, M680X_GRP_BRAREL);

	m680x->address_mode = M680X_AM_REG_RELATIVE;
}

static void (*const g_inst_handler[])(MCInst *, m680x_info *, uint16_t *) = {
	illegal_hdlr,
	relative8_hdlr,
	relative16_hdlr,
	immediate_hdlr, // 8-bit
	immediate_hdlr, // 16-bit
	immediate_hdlr, // 32-bit
	direct_hdlr,
	extended_hdlr,
	indexedX_hdlr,
	indexedY_hdlr,
	indexed09_hdlr,
	inherent_hdlr,
	reg_reg09_hdlr,
	reg_bits_hdlr,
	imm_indexedX_hdlr,
	imm_indexed09_hdlr,
	imm_direct_hdlr,
	imm_extended_hdlr, // 8-bit
	imm_extended_hdlr, // 16-bit
	bit_move_hdlr,
	tfm_hdlr,
	dir_imm_rel_hdlr,
	idxX_imm_rel_hdlr,
	idxY_imm_rel_hdlr,
	direct_imm_hdlr,
	idxX_imm_hdlr,
	idxY_imm_hdlr,
	opidx_dir_rel_hdlr,
	opidx_direct_hdlr,
	indexedX0_hdlr,
	indexedX16_hdlr,
        imm_rel_hdlr,
        direct_rel_hdlr,
        indexedS_hdlr,
        indexedS16_hdlr,
        indexedS_rel_hdlr,
        indexedX_rel_hdlr,
        indexedX0_rel_hdlr,
        indexedXp_rel_hdlr,
        idxX0p_rel_hdlr,
        idxX0p_direct_hdlr,
        direct_direct_hdlr,
        direct_idxX0p_hdlr,
        indexed12_hdlr,
        indexed12_hdlr, // subset of indexed12
        indexed12_imm_hdlr,
	idx12_imm_rel_hdlr,
        ext_imm_rel_hdlr,
        extended_imm_hdlr,
        ext_index_hdlr,
        idx12_index_hdlr,
        reg_reg12_hdlr,
	loop_hdlr,
	ext_ext_hdlr,
	idx12_idx12_hdlr,
	idx12_ext_hdlr,
	imm_idx12_x_hdlr,
	imm_idx12_x_hdlr,
	ext_idx12_x_hdlr,
}; /* handler function pointers */

/* Disasemble one instruction at address and store in str_buff */
static unsigned int m680x_disassemble(MCInst *MI, m680x_info *info,
	uint16_t address)
{
	cs_m680x *m680x = &info->m680x;
	cs_detail *detail = MI->flat_insn->detail;
	uint16_t base_address = address;
	insn_desc insn_description;

	if (detail != NULL) {
		detail->regs_read_count = 0;
		detail->regs_write_count = 0;
		detail->groups_count = 0;
	}

	memset(&insn_description, 0, sizeof(insn_description));
	memset(m680x, 0, sizeof(*m680x));
	info->insn_size = 1;

	if (decode_insn(info, address, &insn_description)) {
		m680x_reg reg;

		if (insn_description.opcode > 0xff)
			address += 2; // 8-bit opcode + page prefix
		else
			address++; // 8-bit opcode only

		info->insn = insn_description.insn;

		MCInst_setOpcode(MI, insn_description.opcode);

		reg = g_insn_props[info->insn].reg0;
		if (reg != M680X_REG_INVALID) {
			if (!info->cpu.reg_byte_size[reg] &&
			   reg == M680X_REG_HX)
				reg = M680X_REG_X;
			add_reg_operand(info, reg);
			// First (or second) operand is a register which is
			// part of the mnemonic
			m680x->flags |= M680X_FIRST_OP_IN_MNEM;
			reg = g_insn_props[info->insn].reg1;
			if (reg != M680X_REG_INVALID) {
				if (!info->cpu.reg_byte_size[reg] &&
				    reg == M680X_REG_HX)
					reg = M680X_REG_X;
				add_reg_operand(info, reg);
				m680x->flags |= M680X_SECOND_OP_IN_MNEM;
			}
		}

		// Call addressing mode specific instruction handler
		(g_inst_handler[insn_description.handler_id])(MI, info,
			&address);

		add_insn_group(detail, g_insn_props[info->insn].group);

		if (g_insn_props[info->insn].cc_modified)
			add_reg_to_rw_list(MI, M680X_REG_CC, MODIFY);

		e_access_mode access_mode =
			g_insn_props[info->insn].access_mode;
		// Fix for M6805 BSET/BCLR. It has a differnt operand order
		// in comparison to the M6811
		if (info->cpu_type == M680X_CPU_TYPE_6805 &&
			((info->insn == M680X_INS_BSET) ||
			 (info->insn == M680X_INS_BCLR)))
			access_mode = rmmm;
		build_regs_read_write_counts(MI, info, access_mode);
		add_operators_access(MI, info, access_mode);

		if (g_insn_props[info->insn].update_reg_access)
			set_changed_regs_read_write_counts(MI, info);

		info->insn_size = insn_description.insn_size;

		return info->insn_size;
	} else
		MCInst_setOpcode(MI, insn_description.opcode);

	// Illegal instruction
	address = base_address;
	illegal_hdlr(MI, info, &address);
	return 1;
}

static const char *s_cpu_type[] = {
	"INVALID", "6301", "6309", "6800", "6801", "6805", "6808",
	"6809", "6811", "CPU12", "HCS08",
};

// Tables to get the byte size of a register on the CPU
// based on an enum m680x_reg value.
// Invalid registers return 0.
static const uint8_t g_m6800_reg_byte_size[23] = {
	// A  B  E  F  0  D  W  CC DP MD HX H  X  Y  S  U  V  Q  PC T1 T2 T3
	0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 2, 0, 2, 0, 0, 0, 2, 0, 0, 0
};

static const uint8_t g_m6805_reg_byte_size[23] = {
	// A  B  E  F  0  D  W  CC DP MD HX H  X  Y  S  U  V  Q  PC T1 T2 T3
	0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 2, 0, 0, 0, 2, 0, 0, 0
};

static const uint8_t g_m6808_reg_byte_size[23] = {
	// A  B  E  F  0  D  W  CC DP MD HX H  X  Y  S  U  V  Q  PC T1 T2 T3
	0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 2, 1, 1, 0, 2, 0, 0, 0, 2, 0, 0, 0
};

static const uint8_t g_m6801_reg_byte_size[23] = {
	// A  B  E  F  0  D  W  CC DP MD HX H  X  Y  S  U  V  Q  PC T1 T2 T3
	0, 1, 1, 0, 0, 0, 2, 0, 1, 0, 0, 0, 0, 2, 0, 2, 0, 0, 0, 2, 0, 0, 0
};

static const uint8_t g_m6811_reg_byte_size[23] = {
	// A  B  E  F  0  D  W  CC DP MD HX H  X  Y  S  U  V  Q  PC T1 T2 T3
	0, 1, 1, 0, 0, 0, 2, 0, 1, 0, 0, 0, 0, 2, 2, 2, 0, 0, 0, 2, 0, 0, 0
};

static const uint8_t g_cpu12_reg_byte_size[23] = {
	// A  B  E  F  0  D  W  CC DP MD HX H  X  Y  S  U  V  Q  PC T1 T2 T3
	0, 1, 1, 0, 0, 0, 2, 0, 1, 0, 0, 0, 0, 2, 2, 2, 0, 0, 0, 2, 2, 2, 2
};

static const uint8_t g_m6809_reg_byte_size[23] = {
	// A  B  E  F  0  D  W  CC DP MD HX H  X  Y  S  U  V  Q  PC T1 T2 T3
	0, 1, 1, 0, 0, 0, 2, 0, 1, 1, 0, 0, 0, 2, 2, 2, 2, 0, 0, 2, 0, 0, 0
};

static const uint8_t g_hd6309_reg_byte_size[23] = {
	// A  B  E  F  0  D  W  CC DP MD HX H  X  Y  S  U  V  Q  PC T1 T2 T3
	0, 1, 1, 1, 1, 1, 2, 2, 1, 1, 1, 0, 0, 2, 2, 2, 2, 2, 4, 2, 0, 0, 0
};

static bool m680x_setup_internals(m680x_info *info, e_cpu_type cpu_type,
	uint16_t address,
	const uint8_t *code, uint16_t code_len)
{
	// Table to check for a valid register nibble on the M6809 CPU
	// used for TFR and EXG instruction.
	static const bool m6809_tfr_reg_valid[16] = {
		true, true, true, true, true,  true,  false, false,
		true, true, true, true, false, false, false, false,
	};
	cpu_tables *cpu = &info->cpu;
	size_t table_size;

	info->code = code;
	info->size = code_len;
	info->offset = address;
	info->cpu_type = cpu_type;

	memset(cpu, 0, sizeof(*cpu));

	switch (info->cpu_type) {
	case M680X_CPU_TYPE_6800:
		cpu->inst_page1_table = &g_m6800_inst_page1_table[0];
		cpu->reg_byte_size = &g_m6800_reg_byte_size[0];
		break;

	case M680X_CPU_TYPE_6801:
		cpu->inst_page1_table = &g_m6800_inst_page1_table[0];
		cpu->inst_overlay_table[0] = &g_m6801_inst_overlay_table[0];
		table_size = ARR_SIZE(g_m6801_inst_overlay_table);
		cpu->overlay_table_size[0] = table_size;
		cpu->reg_byte_size = &g_m6801_reg_byte_size[0];
		break;

	case M680X_CPU_TYPE_6805:
		cpu->inst_page1_table = &g_m6805_inst_page1_table[0];
		cpu->reg_byte_size = &g_m6805_reg_byte_size[0];
		break;

	case M680X_CPU_TYPE_6808:
		cpu->inst_page1_table = &g_m6805_inst_page1_table[0];
		cpu->pageX_prefix[0] = 0x9E; // PAGE2 prefix
		cpu->inst_pageX_table[0] = &g_m6808_inst_page2_table[0];
		cpu->pageX_table_size[0] = ARR_SIZE(g_m6808_inst_page2_table);
		cpu->inst_overlay_table[0] = &g_m6808_inst_overlay_table[0];
		table_size = ARR_SIZE(g_m6808_inst_overlay_table);
		cpu->overlay_table_size[0] = table_size;
		cpu->reg_byte_size = &g_m6808_reg_byte_size[0];
		break;

	case M680X_CPU_TYPE_HCS08:
		cpu->inst_page1_table = &g_m6805_inst_page1_table[0];
		cpu->pageX_prefix[0] = 0x9E; // PAGE2 prefix
		cpu->inst_pageX_table[0] = &g_hcs08_inst_page2_table[0];
		cpu->pageX_table_size[0] = ARR_SIZE(g_hcs08_inst_page2_table);
		cpu->inst_overlay_table[0] = &g_m6808_inst_overlay_table[0];
		table_size = ARR_SIZE(g_m6808_inst_overlay_table);
		cpu->overlay_table_size[0] = table_size;
		cpu->inst_overlay_table[1] = &g_hcs08_inst_overlay_table[0];
		table_size = ARR_SIZE(g_hcs08_inst_overlay_table);
		cpu->overlay_table_size[1] = table_size;
		cpu->reg_byte_size = &g_m6808_reg_byte_size[0];
		break;

	case M680X_CPU_TYPE_6301:
		cpu->inst_page1_table = &g_m6800_inst_page1_table[0];
		cpu->inst_overlay_table[0] = &g_m6801_inst_overlay_table[0];
		table_size = ARR_SIZE(g_m6801_inst_overlay_table);
		cpu->overlay_table_size[0] = table_size;
		cpu->inst_overlay_table[1] = &g_hd6301_inst_overlay_table[0];
		table_size = ARR_SIZE(g_hd6301_inst_overlay_table);
		cpu->overlay_table_size[1] = table_size;
		cpu->reg_byte_size = &g_m6801_reg_byte_size[0];
		break;

	case M680X_CPU_TYPE_6809:
		cpu->inst_page1_table = &g_m6809_inst_page1_table[0];
		cpu->pageX_prefix[0] = 0x10; // PAGE2 prefix
		cpu->pageX_prefix[1] = 0x11; // PAGE3 prefix
		cpu->inst_pageX_table[0] = &g_m6809_inst_page2_table[0];
		cpu->inst_pageX_table[1] = &g_m6809_inst_page3_table[0];
		cpu->pageX_table_size[0] = ARR_SIZE(g_m6809_inst_page2_table);
		cpu->pageX_table_size[1] = ARR_SIZE(g_m6809_inst_page3_table);
		cpu->reg_byte_size = &g_m6809_reg_byte_size[0];
		cpu->tfr_reg_valid = &m6809_tfr_reg_valid[0];
		break;

	case M680X_CPU_TYPE_6309:
		cpu->inst_page1_table = &g_m6809_inst_page1_table[0];
		cpu->inst_overlay_table[0] = &g_hd6309_inst_overlay_table[0];
		table_size = ARR_SIZE(g_hd6309_inst_overlay_table);
		cpu->overlay_table_size[0] = table_size;
		cpu->pageX_prefix[0] = 0x10; // PAGE2 prefix
		cpu->pageX_prefix[1] = 0x11; // PAGE3 prefix
		cpu->inst_pageX_table[0] = &g_hd6309_inst_page2_table[0];
		cpu->inst_pageX_table[1] = &g_hd6309_inst_page3_table[0];
		cpu->pageX_table_size[0] = ARR_SIZE(g_hd6309_inst_page2_table);
		cpu->pageX_table_size[1] = ARR_SIZE(g_hd6309_inst_page3_table);
		cpu->reg_byte_size = &g_hd6309_reg_byte_size[0];
		break;

	case M680X_CPU_TYPE_6811:
		cpu->inst_page1_table = &g_m6800_inst_page1_table[0];
		cpu->pageX_prefix[0] = 0x18; // PAGE2 prefix
		cpu->pageX_prefix[1] = 0x1A; // PAGE3 prefix
		cpu->pageX_prefix[2] = 0xCD; // PAGE4 prefix
		cpu->inst_pageX_table[0] = &g_m6811_inst_page2_table[0];
		cpu->inst_pageX_table[1] = &g_m6811_inst_page3_table[0];
		cpu->inst_pageX_table[2] = &g_m6811_inst_page4_table[0];
		cpu->pageX_table_size[0] = ARR_SIZE(g_m6811_inst_page2_table);
		cpu->pageX_table_size[1] = ARR_SIZE(g_m6811_inst_page3_table);
		cpu->pageX_table_size[2] = ARR_SIZE(g_m6811_inst_page4_table);
		cpu->inst_overlay_table[0] = &g_m6801_inst_overlay_table[0];
		table_size = ARR_SIZE(g_m6801_inst_overlay_table);
		cpu->overlay_table_size[0] = table_size;
		cpu->inst_overlay_table[1] = &g_m6811_inst_overlay_table[0];
		table_size = ARR_SIZE(g_m6811_inst_overlay_table);
		cpu->overlay_table_size[1] = table_size;
		cpu->reg_byte_size = &g_m6811_reg_byte_size[0];
		break;

	case M680X_CPU_TYPE_CPU12:
		cpu->inst_page1_table = &g_cpu12_inst_page1_table[0];
		cpu->pageX_prefix[0] = 0x18; // PAGE2 prefix
		cpu->inst_pageX_table[0] = &g_cpu12_inst_page2_table[0];
		cpu->pageX_table_size[0] = ARR_SIZE(g_cpu12_inst_page2_table);
		cpu->reg_byte_size = &g_cpu12_reg_byte_size[0];
		break;

	default:
		fprintf(stderr, "M680X_CPU_TYPE_%s is not suppported yet\n",
			s_cpu_type[cpu_type]);
		return false;
	}

	return true;
}

bool M680X_getInstruction(csh ud, const uint8_t *code, size_t code_len,
	MCInst *MI, uint16_t *size, uint64_t address, void *inst_info)
{
	unsigned int insn_size = 0;
	e_cpu_type cpu_type = M680X_CPU_TYPE_INVALID; // No default CPU type
	cs_struct *handle = (cs_struct *)ud;
	m680x_info *info = (m680x_info *)handle->printer_info;

	MCInst_clear(MI);

	if (handle->mode & CS_MODE_M680X_6800)
		cpu_type = M680X_CPU_TYPE_6800;

	if (handle->mode & CS_MODE_M680X_6801)
		cpu_type = M680X_CPU_TYPE_6801;

	if (handle->mode & CS_MODE_M680X_6805)
		cpu_type = M680X_CPU_TYPE_6805;

	if (handle->mode & CS_MODE_M680X_6808)
		cpu_type = M680X_CPU_TYPE_6808;

	if (handle->mode & CS_MODE_M680X_HCS08)
		cpu_type = M680X_CPU_TYPE_HCS08;

	if (handle->mode & CS_MODE_M680X_6809)
		cpu_type = M680X_CPU_TYPE_6809;

	if (handle->mode & CS_MODE_M680X_6301)
		cpu_type = M680X_CPU_TYPE_6301;

	if (handle->mode & CS_MODE_M680X_6309)
		cpu_type = M680X_CPU_TYPE_6309;

	if (handle->mode & CS_MODE_M680X_6811)
		cpu_type = M680X_CPU_TYPE_6811;

	if (handle->mode & CS_MODE_M680X_CPU12)
		cpu_type = M680X_CPU_TYPE_CPU12;

	if (cpu_type != M680X_CPU_TYPE_INVALID &&
		m680x_setup_internals(info, cpu_type, (uint16_t)address, code,
					code_len))
		insn_size = m680x_disassemble(MI, info, (uint16_t)address);

	if (insn_size == 0) {
		*size = 1;
		return false;
	}

	// Make sure we always stay within range
	if (insn_size > code_len) {
		*size = (uint16_t)code_len;
		return false;
	}
	else
		*size = (uint16_t)insn_size;

	return true;
}

cs_err M680X_disassembler_init(cs_struct *ud)
{
	if (M680X_REG_ENDING != ARR_SIZE(g_m6800_reg_byte_size)) {
		fprintf(stderr, "Internal error: Size mismatch in enum "
			"m680x_reg and g_m6800_reg_byte_size\n");

		return CS_ERR_MODE;
	}

	if (M680X_REG_ENDING != ARR_SIZE(g_m6801_reg_byte_size)) {
		fprintf(stderr, "Internal error: Size mismatch in enum "
			"m680x_reg and g_m6801_reg_byte_size\n");

		return CS_ERR_MODE;
	}

	if (M680X_REG_ENDING != ARR_SIZE(g_m6805_reg_byte_size)) {
		fprintf(stderr, "Internal error: Size mismatch in enum "
			"m680x_reg and g_m6805_reg_byte_size\n");

		return CS_ERR_MODE;
	}

	if (M680X_REG_ENDING != ARR_SIZE(g_m6808_reg_byte_size)) {
		fprintf(stderr, "Internal error: Size mismatch in enum "
			"m680x_reg and g_m6808_reg_byte_size\n");

		return CS_ERR_MODE;
	}

	if (M680X_REG_ENDING != ARR_SIZE(g_m6811_reg_byte_size)) {
		fprintf(stderr, "Internal error: Size mismatch in enum "
			"m680x_reg and g_m6811_reg_byte_size\n");

		return CS_ERR_MODE;
	}

	if (M680X_REG_ENDING != ARR_SIZE(g_cpu12_reg_byte_size)) {
		fprintf(stderr, "Internal error: Size mismatch in enum "
			"m680x_reg and g_cpu12_reg_byte_size\n");

		return CS_ERR_MODE;
	}

	if (M680X_REG_ENDING != ARR_SIZE(g_m6809_reg_byte_size)) {
		fprintf(stderr, "Internal error: Size mismatch in enum "
			"m680x_reg and g_m6809_reg_byte_size\n");

		return CS_ERR_MODE;
	}

	if (M680X_INS_ENDING != ARR_SIZE(g_insn_props)) {
		fprintf(stderr, "Internal error: Size mismatch in enum "
			"m680x_insn and g_insn_props\n");

		return CS_ERR_MODE;
	}

	if (M680X_CPU_TYPE_ENDING != ARR_SIZE(s_cpu_type)) {
		fprintf(stderr, "Internal error: Size mismatch in enum "
			"e_cpu_type and s_cpu_type\n");

		return CS_ERR_MODE;
	}

	if (HANDLER_ID_ENDING != ARR_SIZE(g_inst_handler)) {
		fprintf(stderr, "Internal error: Size mismatch in enum "
			"insn_hdlr_id and g_inst_handler\n");

		return CS_ERR_MODE;
	}

	if (ACCESS_MODE_ENDING !=  MATRIX_SIZE(g_access_mode_to_access)) {
		fprintf(stderr, "Internal error: Size mismatch in enum "
			"e_access_mode and g_access_mode_to_access\n");

		return CS_ERR_MODE;
	}

	return CS_ERR_OK;
}

#ifndef CAPSTONE_DIET
void M680X_reg_access(const cs_insn *insn,
		cs_regs regs_read, uint8_t *regs_read_count,
		cs_regs regs_write, uint8_t *regs_write_count)
{
	if (insn->detail == NULL) {
		*regs_read_count = 0;
		*regs_write_count = 0;
	} else {
		*regs_read_count = insn->detail->regs_read_count;
		*regs_write_count = insn->detail->regs_write_count;

		memcpy(regs_read, insn->detail->regs_read,
			*regs_read_count * sizeof(insn->detail->regs_read[0]));
		memcpy(regs_write, insn->detail->regs_write,
			*regs_write_count *
				sizeof(insn->detail->regs_write[0]));
	}
}
#endif

#endif


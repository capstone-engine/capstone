/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev  <sibirtsevdl@gmail.com>, 2023 */

#ifdef CAPSTONE_HAS_HPPA

#include <string.h>
#include <stddef.h> // offsetof macro
#include <stdio.h>
#include "HPPADisassembler.h"
#include "HPPAConstants.h"

#include "../../Mapping.h"
#include "../../MathExtras.h"
#include "../../utils.h"

#define CMPLT_HAS_MODIFY_BIT(CMPLT) (((CMPLT) & 1) == 1)

#define HPPA_EXT_REF(MI) (&MI->hppa_ext)

static const char *const compare_cond_names[] = {
	"",   "=",  "<",  "<=", "<<",  "<<=", "sv",  "od",
	"tr", "<>", ">=", ">",	">>=", ">>",  "nsv", "ev"
};
static const char *const compare_cond_64_names[] = {
	"*",   "*=",  "*<",  "*<=", "*<<",  "*<<=", "*sv",  "*od",
	"*tr", "*<>", "*>=", "*>",  "*>>=", "*>>",  "*nsv", "*ev"
};
static const char *const cmpib_cond_64_names[] = { "*<<",  "*=",  "*<",	 "*<=",
						   "*>>=", "*<>", "*>=", "*>" };
static const char *const add_cond_names[] = {
	"",   "=",  "<",  "<=", "nuv", "znv", "sv",  "od",
	"tr", "<>", ">=", ">",	"uv",  "vnz", "nsv", "ev"
};
static const char *const add_cond_64_names[] = {
	"*",   "*=",  "*<",  "*<=", "*nuv", "*znv", "*sv",  "*od",
	"*tr", "*<>", "*>=", "*>",  "*uv",  "*vnz", "*nsv", "*ev"
};
static const char *const wide_add_cond_names[] = {
	"*",  "=",  "<",  "<=", "nuv", "*=",  "*<",  "*<=",
	"tr", "<>", ">=", ">",	"uv",  "*<>", "*>=", "*>"
};
static const char *const logical_cond_names[] = {
	"",   "=",  "<",  "<=", "", "", "", "od",
	"tr", "<>", ">=", ">",	"", "", "", "ev"
};
static const char *const logical_cond_64_names[] = {
	"*",   "*=",  "*<",  "*<=", "", "", "", "*od",
	"*tr", "*<>", "*>=", "*>",  "", "", "", "*ev"
};
static const char *const unit_cond_names[] = { "",    "swz", "sbz", "shz",
					       "sdc", "swc", "sbc", "shc",
					       "tr",  "nwz", "nbz", "nhz",
					       "ndc", "nwc", "nbc", "nhc" };
static const char *const unit_cond_64_names[] = {
	"*",   "*swz", "*sbz", "*shz", "*sdc", "*swc", "*sbc", "*shc",
	"*tr", "*nwz", "*nbz", "*nhz", "*ndc", "*nwc", "*nbc", "*nhc"
};
static const char *const shift_cond_names[] = { "",   "=",  "<",  "od",
						"tr", "<>", ">=", "ev" };
static const char *const shift_cond_64_names[] = { "*",	  "*=",	 "*<",	"*od",
						   "*tr", "*<>", "*>=", "*ev" };
static const char *const index_compl_names[] = { "", "m", "s", "sm" };
static const char *const short_ldst_compl_names[] = { "", "ma", "", "mb" };
static const char *const short_bytes_compl_names[] = { "", "b,m", "e", "e,m" };
static const char *const float_format_names[] = { "sgl", "dbl", "", "quad" };
static const char *const float_cond_names[] = {
	"", "acc", "rej",  "", "", "acc8", "rej8", "", "", "acc6", "",
	"", "",	   "acc4", "", "", "",	   "acc2", "", "", "",	   "",
	"", "",	   "",	   "", "", "",	   "",	   "", "", ""
};
static const char *const fcnv_fixed_names[] = { "w", "dw", "", "qw" };
static const char *const fcnv_ufixed_names[] = { "uw", "udw", "", "uqw" };
static const char *const float_comp_names[] = {
	"false?", "false", "?",	 "!<=>", "=",	"=t",  "?=",	"!<>",
	"!?>=",	  "<",	   "?<", "!>=",	 "!?>", "<=",  "?<=",	"!>",
	"!?<=",	  ">",	   "?>", "!<=",	 "!?<", ">=",  "?>=",	"!<",
	"!?=",	  "<>",	   "!=", "!=t",	 "!?",	"<=>", "true?", "true"
};
static const char *const signed_unsigned_names[] = { "u", "s" };
static const char *const saturation_names[] = { "us", "ss", "", "" };
static const char *const add_compl_names[] = { "", "", "l", "tsv" };

#define CREATE_GR_REG(MI, gr) MCOperand_CreateReg0(MI, gr + HPPA_REG_GR0)
#define CREATE_SR_REG(MI, sr) MCOperand_CreateReg0(MI, sr + HPPA_REG_SR0)
#define CREATE_CR_REG(MI, cr) MCOperand_CreateReg0(MI, cr + HPPA_REG_CR0)
#define CREATE_FPR_REG(MI, fpr) MCOperand_CreateReg0(MI, fpr + HPPA_REG_FPR0)
#define CREATE_FPE_REG(MI, fpe) MCOperand_CreateReg0(MI, fpe + HPPA_REG_FPE0)
#define CREATE_SP_FPR_REG(MI, fpr) \
	MCOperand_CreateReg0(MI, fpr + HPPA_REG_SP_FPR0)

static void create_float_reg_spec(MCInst *MI, uint32_t reg, uint32_t fpe_flag)
{
	if (fpe_flag == 1) {
		CREATE_FPE_REG(MI, reg);
	} else {
		CREATE_FPR_REG(MI, reg);
	}
}

/* Get at various relevant fields of an instruction word.  */

#define MASK_5 0x1f
#define MASK_10 0x3ff
#define MASK_11 0x7ff
#define MASK_14 0x3fff
#define MASK_16 0xffff
#define MASK_21 0x1fffff

/* Routines to extract various sized constants out of hppa
   instructions.  */

/* Extract a 3-bit space register number from a be, ble, mtsp or mfsp.  */
static int extract_3(unsigned word)
{
	return get_insn_field(word, 18, 18) << 2 | get_insn_field(word, 16, 17);
}

static int extract_5_load(unsigned word)
{
	return LowSignExtend64(word >> 16 & MASK_5, 5);
}

/* Extract the immediate field from a st{bhw}s instruction.  */

static int extract_5_store(unsigned word)
{
	return LowSignExtend64(word & MASK_5, 5);
}

/* Extract an 11 bit immediate field.  */

static int extract_11(unsigned word)
{
	return LowSignExtend64(word & MASK_11, 11);
}

/* Extract a 14 bit immediate field.  */

static int extract_14(unsigned word)
{
	return LowSignExtend64(word & MASK_14, 14);
}

/* Extract a 16 bit immediate field. */

static int extract_16(unsigned word, bool wide)
{
	int m15, m0, m1;

	m0 = get_insn_bit(word, 16);
	m1 = get_insn_bit(word, 17);
	m15 = get_insn_bit(word, 31);
	word = (word >> 1) & 0x1fff;
	if (wide) {
		word = word | (m15 << 15) | ((m15 ^ m0) << 14) |
		       ((m15 ^ m1) << 13);
	} else {
		word = word | (m15 << 15) | (m15 << 14) | (m15 << 13);
	}
	return SignExtend32(word, 16);
}

/* Extract a 21 bit constant.  */

static int32_t extract_21(unsigned word)
{
	int val;

	word &= MASK_21;
	word <<= 11;
	val = get_insn_field(word, 20, 20);
	val <<= 11;
	val |= get_insn_field(word, 9, 19);
	val <<= 2;
	val |= get_insn_field(word, 5, 6);
	val <<= 5;
	val |= get_insn_field(word, 0, 4);
	val <<= 2;
	val |= get_insn_field(word, 7, 8);
	return (uint32_t)SignExtend32(val, 21) << 11;
}

/* Extract a 12 bit constant from branch instructions.  */

static int32_t extract_12(unsigned word)
{
	return (uint32_t)SignExtend32(get_insn_field(word, 19, 28) |
					      get_insn_field(word, 29, 29)
						      << 10 |
					      (word & 0x1) << 11,
				      12)
	       << 2;
}

/* Extract a 17 bit constant from branch instructions, returning the
   19 bit signed value.  */

static int32_t extract_17(unsigned word)
{
	return (uint32_t)SignExtend32(
		       get_insn_field(word, 19, 28) |
			       get_insn_field(word, 29, 29) << 10 |
			       get_insn_field(word, 11, 15) << 11 |
			       (word & 0x1) << 16,
		       17)
	       << 2;
}

static int32_t extract_22(unsigned word)
{
	return (uint32_t)SignExtend32(
		       get_insn_field(word, 19, 28) |
			       get_insn_field(word, 29, 29) << 10 |
			       get_insn_field(word, 11, 15) << 11 |
			       get_insn_field(word, 6, 10) << 16 |
			       (word & 0x1) << 21,
		       22)
	       << 2;
}

static void push_str_modifier(hppa_ext *hppa, const char *modifier)
{
	if (strcmp(modifier, "")) {
		hppa_modifier *mod = &hppa->modifiers[hppa->mod_num++];
		CS_ASSERT_RET(hppa->mod_num <= HPPA_MAX_MODIFIERS_LEN);
		mod->type = HPPA_MOD_STR;
		CS_ASSERT_RET(strlen(modifier) < HPPA_STR_MODIFIER_LEN);
		strncpy(mod->str_mod, modifier, HPPA_STR_MODIFIER_LEN - 1);
	}
}

static void push_int_modifier(hppa_ext *hppa, uint64_t modifier)
{
	hppa_modifier *mod = &hppa->modifiers[hppa->mod_num++];
	CS_ASSERT_RET(hppa->mod_num <= HPPA_MAX_MODIFIERS_LEN);
	mod->type = HPPA_MOD_INT;
	mod->int_mod = modifier;
}

static void fill_sysop_insn_name(MCInst *MI, uint32_t insn)
{
	uint32_t ext8 = get_insn_field(insn, 19, 26);
	uint32_t ext5 = get_insn_field(insn, 11, 15);
	if (MODE_IS_HPPA_20(MI->csh->mode)) {
		switch (ext8) {
		case 0xa5:
			MCInst_setOpcode(MI, HPPA_INS_MFIA);
			return;
		case 0xc6:
			MCInst_setOpcode(MI, HPPA_INS_MTSARCM);
			return;
		case 0x65:
			push_str_modifier(HPPA_EXT_REF(MI), "r");
			// fallthrough
		case 0x60:
			MCInst_setOpcode(MI, HPPA_INS_RFI);
			return;
		default:
			break;
		}
	}

	switch (ext8) {
	case 0x00:
		MCInst_setOpcode(MI, HPPA_INS_BREAK);
		break;
	case 0x20:
		if (ext5 == 0x00) {
			MCInst_setOpcode(MI, HPPA_INS_SYNC);
		} else if (ext5 == 0x10) {
			MCInst_setOpcode(MI, HPPA_INS_SYNCDMA);
		}
		break;
	case 0x60:
		MCInst_setOpcode(MI, HPPA_INS_RFI);
		break;
	case 0x65:
		MCInst_setOpcode(MI, HPPA_INS_RFIR);
		break;
	case 0x6b:
		MCInst_setOpcode(MI, HPPA_INS_SSM);
		break;
	case 0x73:
		MCInst_setOpcode(MI, HPPA_INS_RSM);
		break;
	case 0xc3:
		MCInst_setOpcode(MI, HPPA_INS_MTSM);
		break;
	case 0x85:
		MCInst_setOpcode(MI, HPPA_INS_LDSID);
		break;
	case 0xc1:
		MCInst_setOpcode(MI, HPPA_INS_MTSP);
		break;
	case 0x25:
		MCInst_setOpcode(MI, HPPA_INS_MFSP);
		break;
	case 0xc2:
		MCInst_setOpcode(MI, HPPA_INS_MTCTL);
		break;
	case 0x45:
		MCInst_setOpcode(MI, HPPA_INS_MFCTL);
		if (get_insn_bit(insn, 17) == 1 &&
		    MODE_IS_HPPA_20(MI->csh->mode)) {
			push_str_modifier(HPPA_EXT_REF(MI), "w");
		}
		break;
	default:
		break;
	}
}

static bool decode_sysop(const cs_struct *ud, MCInst *MI, uint32_t insn)
{
	uint32_t ext8 = get_insn_field(insn, 19, 26);
	uint32_t ext5 = get_insn_field(insn, 11, 15);
	uint32_t r1 = get_insn_field(insn, 6, 10);
	uint32_t r2 = get_insn_field(insn, 11, 15);
	uint32_t t = get_insn_field(insn, 27, 31);
	uint32_t s = extract_3(insn);
	if (MODE_IS_HPPA_20(MI->csh->mode)) {
		switch (ext8) {
		case 0xa5:
			if (ext5 != 0) {
				return false;
			}
			CREATE_GR_REG(MI, t);
			return true;
		case 0xc6:
			CREATE_GR_REG(MI, r2);
			return true;
		default:
			break;
		}
	}

	switch (ext8) {
	case 0x00:
		MCOperand_CreateImm0(MI, t);
		MCOperand_CreateImm0(MI, get_insn_field(insn, 6, 18));
		return true;
	case 0x20:
		if (ext5 != 0x00 && ext5 != 0x10) {
			return false;
		}
		// fallthrough
	case 0x60:
	case 0x65:
		return true;
	case 0x6b:
	case 0x73:
		MCOperand_CreateImm0(MI, get_insn_field(insn, 9, 15));
		CREATE_GR_REG(MI, t);
		return true;
	case 0xc3:
		CREATE_GR_REG(MI, r2);
		return true;
	case 0x85:
		CREATE_SR_REG(MI, s);
		CREATE_GR_REG(MI, r1);
		CREATE_GR_REG(MI, t);
		return true;
	case 0xc1:
		CREATE_GR_REG(MI, r2);
		CREATE_SR_REG(MI, s);
		return true;
	case 0x25:
		if (ext5 != 0) {
			return false;
		}
		CREATE_SR_REG(MI, s);
		CREATE_GR_REG(MI, t);
		return true;
	case 0xc2:
		CREATE_GR_REG(MI, r2);
		CREATE_CR_REG(MI, r1);
		return true;
	case 0x45:
		if (ext5 != 0) {
			return false;
		}
		if (get_insn_bit(insn, 17) == 1 && MODE_IS_HPPA_20(ud->mode) &&
		    r1 != 11) {
			return false;
		}
		CREATE_CR_REG(MI, r1);
		CREATE_GR_REG(MI, t);
		return true;
	default:
		return false;
	}
}

static void fill_memmgmt_insn_name(MCInst *MI, uint32_t insn)
{
	uint32_t ext = get_insn_field(insn, 19, 25);
	if (MODE_IS_HPPA_20(MI->csh->mode)) {
		switch (ext) {
		case 0x20:
			MCInst_setOpcode(MI, HPPA_INS_IITLBT);
			return;
		case 0x18:
			MCInst_setOpcode(MI, HPPA_INS_PITLB);
			push_str_modifier(HPPA_EXT_REF(MI), "l");
			return;
		case 0x60:
			MCInst_setOpcode(MI, HPPA_INS_IDTLBT);
			return;
		case 0x58:
			MCInst_setOpcode(MI, HPPA_INS_PDTLB);
			push_str_modifier(HPPA_EXT_REF(MI), "l");
			return;
		case 0x4f:
			MCInst_setOpcode(MI, HPPA_INS_FIC);
			return;
		case 0x46:
			if (get_insn_bit(insn, 18) == 0) {
				MCInst_setOpcode(MI, HPPA_INS_PROBE);
			} else {
				MCInst_setOpcode(MI, HPPA_INS_PROBEI);
			};
			push_str_modifier(HPPA_EXT_REF(MI), "r");
			return;
		case 0x47:
			if (get_insn_bit(insn, 18) == 0) {
				MCInst_setOpcode(MI, HPPA_INS_PROBE);
			} else {
				MCInst_setOpcode(MI, HPPA_INS_PROBEI);
			};
			push_str_modifier(HPPA_EXT_REF(MI), "w");
			return;
		default:
			break;
		}
	}

	switch (ext) {
	case 0x00:
		MCInst_setOpcode(MI, HPPA_INS_IITLBP);
		break;
	case 0x01:
		MCInst_setOpcode(MI, HPPA_INS_IITLBA);
		break;
	case 0x08:
		MCInst_setOpcode(MI, HPPA_INS_PITLB);
		break;
	case 0x09:
		MCInst_setOpcode(MI, HPPA_INS_PITLBE);
		break;
	case 0x0a:
		MCInst_setOpcode(MI, HPPA_INS_FIC);
		break;
	case 0x0b:
		MCInst_setOpcode(MI, HPPA_INS_FICE);
		break;
	case 0x40:
		MCInst_setOpcode(MI, HPPA_INS_IDTLBP);
		break;
	case 0x41:
		MCInst_setOpcode(MI, HPPA_INS_IDTLBA);
		break;
	case 0x48:
		MCInst_setOpcode(MI, HPPA_INS_PDTLB);
		break;
	case 0x49:
		MCInst_setOpcode(MI, HPPA_INS_PDTLBE);
		break;
	case 0x4a:
		MCInst_setOpcode(MI, HPPA_INS_FDC);
		break;
	case 0x4b:
		MCInst_setOpcode(MI, HPPA_INS_FDCE);
		break;
	case 0x4e:
		MCInst_setOpcode(MI, HPPA_INS_PDC);
		break;
	case 0x46:
		if (get_insn_bit(insn, 18) == 0) {
			MCInst_setOpcode(MI, HPPA_INS_PROBER);
		} else {
			MCInst_setOpcode(MI, HPPA_INS_PROBERI);
		};
		break;
	case 0x47:
		if (get_insn_bit(insn, 18) == 0) {
			MCInst_setOpcode(MI, HPPA_INS_PROBEW);
		} else {
			MCInst_setOpcode(MI, HPPA_INS_PROBEWI);
		};
		break;
	case 0x4d:
		MCInst_setOpcode(MI, HPPA_INS_LPA);
		break;
	case 0x4c:
		MCInst_setOpcode(MI, HPPA_INS_LCI);
		break;
	default:
		break;
	}
}

static void fill_memmgmt_mods(uint32_t insn, hppa_ext *hppa_ext, cs_mode mode)
{
	uint8_t cmplt = get_insn_bit(insn, 26);
	uint32_t ext = get_insn_field(insn, 19, 25);
	if (MODE_IS_HPPA_20(mode)) {
		switch (ext) {
		case 0x18:
		case 0x58:
		case 0x4f:
			goto success;
		default:
			break;
		}
	}

	switch (ext) {
	case 0x08:
	case 0x09:
	case 0x0a:
	case 0x0b:
	case 0x48:
	case 0x49:
	case 0x4a:
	case 0x4b:
	case 0x4e:
	case 0x4d:
		break;
	default:
		return;
	}
success:
	if (CMPLT_HAS_MODIFY_BIT(cmplt)) {
		hppa_ext->b_writeble = true;
	}
	push_str_modifier(hppa_ext, index_compl_names[cmplt]);
}

static bool decode_memmgmt(const cs_struct *ud, MCInst *MI, uint32_t insn)
{
	uint32_t ext = get_insn_field(insn, 19, 25);
	uint32_t b = get_insn_field(insn, 6, 10);
	uint32_t r = get_insn_field(insn, 11, 15);
	uint32_t s3 = extract_3(insn);
	uint32_t s2 = get_insn_field(insn, 16, 17);
	uint32_t t = get_insn_field(insn, 27, 31);
	if (ext > 0x20 && get_insn_bit(insn, 18) == 1 &&
	    (ext != 0x46 && ext != 0x47)) {
		if (MODE_IS_HPPA_20(ud->mode)) {
			if (ext != 0x4a) {
				return false;
			}
		} else {
			return false;
		}
	}
	if (MODE_IS_HPPA_20(ud->mode)) {
		switch (ext) {
		case 0x20:
		case 0x60:
			CREATE_GR_REG(MI, r);
			CREATE_GR_REG(MI, b);
			goto success;
		case 0x58:
		case 0x4f:
			CREATE_GR_REG(MI, r);
			CREATE_SR_REG(MI, s2);
			CREATE_GR_REG(MI, b);
			goto success;
		case 0x18:
			CREATE_GR_REG(MI, r);
			CREATE_SR_REG(MI, s3);
			CREATE_GR_REG(MI, b);
			goto success;
		case 0x4a:
			if (get_insn_bit(insn, 18) == 1) {
				MCOperand_CreateImm0(MI, LowSignExtend64(r, 5));
			} else {
				CREATE_GR_REG(MI, r);
			}
			CREATE_SR_REG(MI, s2);
			CREATE_GR_REG(MI, b);
			goto success;
		default:
			break;
		}
	}

	switch (ext) {
	case 0x00:
	case 0x01:
	case 0x08:
	case 0x09:
	case 0x0a:
	case 0x0b:
		CREATE_GR_REG(MI, r);
		CREATE_SR_REG(MI, s3);
		CREATE_GR_REG(MI, b);
		break;
	case 0x40:
	case 0x41:
	case 0x48:
	case 0x49:
	case 0x4a:
	case 0x4b:
	case 0x4e:
		CREATE_GR_REG(MI, r);
		CREATE_SR_REG(MI, s2);
		CREATE_GR_REG(MI, b);
		break;
	case 0x46:
	case 0x47:
		CREATE_SR_REG(MI, s2);
		CREATE_GR_REG(MI, b);
		if (get_insn_bit(insn, 18) == 0) {
			CREATE_GR_REG(MI, r);
		} else {
			MCOperand_CreateImm0(MI, r);
		}
		CREATE_GR_REG(MI, t);
		break;
	case 0x4d:
	case 0x4c:
		CREATE_GR_REG(MI, r);
		CREATE_SR_REG(MI, s2);
		CREATE_GR_REG(MI, b);
		CREATE_GR_REG(MI, t);
		break;
	default:
		return false;
	}
success:
	fill_memmgmt_mods(insn, HPPA_EXT_REF(MI), MI->csh->mode);
	return true;
}

static void fill_alu_insn_name(MCInst *MI, uint32_t insn)
{
	uint32_t ext = get_insn_field(insn, 20, 25);
	if (MODE_IS_HPPA_20(MI->csh->mode)) {
		switch (ext) {
		case 0x28:
		case 0x38:
		case 0x1c:
		case 0x3c:
			MCInst_setOpcode(MI, HPPA_INS_ADD);
			return;
		case 0x19:
		case 0x29:
		case 0x39:
		case 0x1a:
		case 0x2a:
		case 0x3a:
		case 0x1b:
		case 0x2b:
		case 0x3b:
			MCInst_setOpcode(MI, HPPA_INS_SHLADD);
			return;
		case 0x30:
		case 0x13:
		case 0x33:
		case 0x14:
		case 0x34:
			MCInst_setOpcode(MI, HPPA_INS_SUB);
			return;
		case 0x22:
			MCInst_setOpcode(MI, HPPA_INS_CMPCLR);
			return;
		case 0x27:
			MCInst_setOpcode(MI, HPPA_INS_UADDCM);
			return;
		case 0x2f:
			MCInst_setOpcode(MI, HPPA_INS_DCOR);
			return;
		case 0x0f:
		case 0x0d:
		case 0x0c:
			MCInst_setOpcode(MI, HPPA_INS_HADD);
			return;
		case 0x07:
		case 0x05:
		case 0x04:
			MCInst_setOpcode(MI, HPPA_INS_HSUB);
			return;
		case 0x0b:
			MCInst_setOpcode(MI, HPPA_INS_HAVG);
			return;
		case 0x1d:
		case 0x1e:
		case 0x1f:
			MCInst_setOpcode(MI, HPPA_INS_HSHLADD);
			return;
		case 0x15:
		case 0x16:
		case 0x17:
			MCInst_setOpcode(MI, HPPA_INS_HSHRADD);
			return;
		default:
			break;
		}
	}

	switch (ext) {
	case 0x18:
		MCInst_setOpcode(MI, HPPA_INS_ADD);
		break;
	case 0x38:
		MCInst_setOpcode(MI, HPPA_INS_ADDO);
		break;
	case 0x1c:
		MCInst_setOpcode(MI, HPPA_INS_ADDC);
		break;
	case 0x3c:
		MCInst_setOpcode(MI, HPPA_INS_ADDCO);
		break;
	case 0x19:
		MCInst_setOpcode(MI, HPPA_INS_SH1ADD);
		break;
	case 0x39:
		MCInst_setOpcode(MI, HPPA_INS_SH1ADDO);
		break;
	case 0x1a:
		MCInst_setOpcode(MI, HPPA_INS_SH2ADD);
		break;
	case 0x3a:
		MCInst_setOpcode(MI, HPPA_INS_SH2ADDO);
		break;
	case 0x1b:
		MCInst_setOpcode(MI, HPPA_INS_SH3ADD);
		break;
	case 0x3b:
		MCInst_setOpcode(MI, HPPA_INS_SH3ADDO);
		break;
	case 0x10:
		MCInst_setOpcode(MI, HPPA_INS_SUB);
		break;
	case 0x30:
		MCInst_setOpcode(MI, HPPA_INS_SUBO);
		break;
	case 0x13:
		MCInst_setOpcode(MI, HPPA_INS_SUBT);
		break;
	case 0x33:
		MCInst_setOpcode(MI, HPPA_INS_SUBTO);
		break;
	case 0x14:
		MCInst_setOpcode(MI, HPPA_INS_SUBB);
		break;
	case 0x34:
		MCInst_setOpcode(MI, HPPA_INS_SUBBO);
		break;
	case 0x11:
		MCInst_setOpcode(MI, HPPA_INS_DS);
		break;
	case 0x00:
		MCInst_setOpcode(MI, HPPA_INS_ANDCM);
		break;
	case 0x08:
		MCInst_setOpcode(MI, HPPA_INS_AND);
		break;
	case 0x09:
		MCInst_setOpcode(MI, HPPA_INS_OR);
		break;
	case 0x0a:
		MCInst_setOpcode(MI, HPPA_INS_XOR);
		break;
	case 0x0e:
		MCInst_setOpcode(MI, HPPA_INS_UXOR);
		break;
	case 0x22:
		MCInst_setOpcode(MI, HPPA_INS_COMCLR);
		break;
	case 0x26:
		MCInst_setOpcode(MI, HPPA_INS_UADDCM);
		break;
	case 0x27:
		MCInst_setOpcode(MI, HPPA_INS_UADDCMT);
		break;
	case 0x28:
		MCInst_setOpcode(MI, HPPA_INS_ADDL);
		break;
	case 0x29:
		MCInst_setOpcode(MI, HPPA_INS_SH1ADDL);
		break;
	case 0x2a:
		MCInst_setOpcode(MI, HPPA_INS_SH2ADDL);
		break;
	case 0x2b:
		MCInst_setOpcode(MI, HPPA_INS_SH3ADDL);
		break;
	case 0x2e:
		MCInst_setOpcode(MI, HPPA_INS_DCOR);
		break;
	case 0x2f:
		MCInst_setOpcode(MI, HPPA_INS_IDCOR);
		break;
	default:
		break;
	}
}

static void fill_alu_mods(uint32_t insn, hppa_ext *hppa_ext, cs_mode mode)
{
	uint32_t cond = (get_insn_field(insn, 19, 19) << 3) |
			get_insn_field(insn, 16, 18);
	uint32_t ext = get_insn_field(insn, 20, 25);
	if (MODE_IS_HPPA_20(mode)) {
		uint32_t e1 = get_insn_field(insn, 20, 21);
		uint32_t e2 = get_insn_bit(insn, 23);
		uint32_t e3 = get_insn_field(insn, 24, 25);
		uint32_t d = get_insn_bit(insn, 26);
		switch (ext) {
		case 0x18:
		case 0x28:
		case 0x38:
		case 0x1c:
		case 0x3c:
			if (e2 == 1) {
				if (d == 1) {
					push_str_modifier(hppa_ext, "dc");
				} else {
					push_str_modifier(hppa_ext, "c");
				}
			}
			// fallthrough
		case 0x19:
		case 0x29:
		case 0x39:
		case 0x1a:
		case 0x2a:
		case 0x3a:
		case 0x1b:
		case 0x2b:
		case 0x3b:
			push_str_modifier(hppa_ext, add_compl_names[e1]);
			if (d == 1) {
				push_str_modifier(hppa_ext,
						  add_cond_64_names[cond]);
			} else {
				push_str_modifier(hppa_ext,
						  add_cond_names[cond]);
			}
			return;
		case 0x10:
		case 0x30:
		case 0x13:
		case 0x33:
		case 0x14:
		case 0x34:
			if (e2 == 1) {
				if (d == 1) {
					push_str_modifier(hppa_ext, "db");
				} else {
					push_str_modifier(hppa_ext, "b");
				}
			}
			if (e1 == 3) {
				push_str_modifier(hppa_ext, "tsv");
			}
			if (e3 == 3) {
				push_str_modifier(hppa_ext, "tc");
			}
			// fallthrough
		case 0x22:
			if (d == 1) {
				push_str_modifier(hppa_ext,
						  compare_cond_64_names[cond]);
			} else {
				push_str_modifier(hppa_ext,
						  compare_cond_names[cond]);
			}
			return;
		case 0x00:
		case 0x08:
		case 0x09:
		case 0x0a:
			if (d == 1) {
				push_str_modifier(hppa_ext,
						  logical_cond_64_names[cond]);
			} else {
				push_str_modifier(hppa_ext,
						  logical_cond_names[cond]);
			}
			return;
		case 0x27:
			push_str_modifier(hppa_ext, "tc");
			goto unit_cond;
		case 0x2f:
			push_str_modifier(hppa_ext, "i");
			// fallthrough
		case 0x26:
		case 0x0e:
		case 0x2e:
unit_cond:
			if (d == 1) {
				push_str_modifier(hppa_ext,
						  unit_cond_64_names[cond]);
			} else {
				push_str_modifier(hppa_ext,
						  unit_cond_names[cond]);
			}
			return;
		case 0x0d:
		case 0x0c:
		case 0x05:
		case 0x04:
			push_str_modifier(hppa_ext, saturation_names[e3]);
			return;
		default:
			break;
		}
	}

	switch (ext) {
	case 0x18:
	case 0x38:
	case 0x1c:
	case 0x3c:
	case 0x19:
	case 0x39:
	case 0x1a:
	case 0x3a:
	case 0x3b:
	case 0x28:
	case 0x29:
	case 0x2a:
	case 0x2b:
		push_str_modifier(hppa_ext, add_cond_names[cond]);
		break;
	case 0x10:
	case 0x30:
	case 0x13:
	case 0x33:
	case 0x14:
	case 0x34:
	case 0x11:
	case 0x22:
		push_str_modifier(hppa_ext, compare_cond_names[cond]);
		break;
	case 0x00:
	case 0x08:
	case 0x09:
	case 0x0a:
		push_str_modifier(hppa_ext, logical_cond_names[cond]);
		break;
	case 0x0e:
	case 0x26:
	case 0x27:
	case 0x2e:
	case 0x2f:
		push_str_modifier(hppa_ext, unit_cond_names[cond]);
		break;
	default:
		break;
	}
}

static bool decode_alu(const cs_struct *ud, MCInst *MI, uint32_t insn)
{
	uint32_t ext = get_insn_field(insn, 20, 25);
	uint32_t r1 = get_insn_field(insn, 11, 15);
	uint32_t r2 = get_insn_field(insn, 6, 10);
	uint32_t t = get_insn_field(insn, 27, 31);
	if (MODE_IS_HPPA_20(ud->mode)) {
		switch (ext) {
		case 0x19:
		case 0x29:
		case 0x39:
		case 0x1a:
		case 0x2a:
		case 0x3a:
		case 0x1b:
		case 0x2b:
		case 0x3b:
		case 0x1d:
		case 0x1e:
		case 0x1f:
		case 0x15:
		case 0x16:
		case 0x17:
		case 0x0f:
		case 0x0d:
		case 0x0c:
		case 0x07:
		case 0x05:
		case 0x04:
		case 0x0b:
			CREATE_GR_REG(MI, r1);
			if (ext > 0x10) {
				MCOperand_CreateImm0(
					MI, get_insn_field(insn, 24, 25));
			}
			CREATE_GR_REG(MI, r2);
			CREATE_GR_REG(MI, t);
			goto success;
		default:
			break;
		}
	}
	switch (ext) {
	case 0x18:
	case 0x38:
	case 0x1c:
	case 0x3c:
	case 0x19:
	case 0x39:
	case 0x1a:
	case 0x3a:
	case 0x1b:
	case 0x3b:
	case 0x10:
	case 0x30:
	case 0x13:
	case 0x33:
	case 0x14:
	case 0x34:
	case 0x11:
	case 0x00:
	case 0x08:
	case 0x09:
	case 0x0a:
	case 0x0e:
	case 0x22:
	case 0x26:
	case 0x27:
	case 0x28:
	case 0x29:
	case 0x2a:
	case 0x2b:
		CREATE_GR_REG(MI, r1);
		// fallthrough
	case 0x2e:
	case 0x2f:
		CREATE_GR_REG(MI, r2);
		CREATE_GR_REG(MI, t);
		break;
	default:
		return false;
	}
success:
	fill_alu_mods(insn, HPPA_EXT_REF(MI), MI->csh->mode);
	return true;
}

static void fill_idxmem_insn_name(MCInst *MI, uint32_t insn)
{
	uint32_t ext = get_insn_field(insn, 22, 25);
	if (MODE_IS_HPPA_20(MI->csh->mode)) {
		switch (ext) {
		case 0x00:
			MCInst_setOpcode(MI, HPPA_INS_LDB);
			return;
		case 0x01:
			MCInst_setOpcode(MI, HPPA_INS_LDH);
			return;
		case 0x02:
			MCInst_setOpcode(MI, HPPA_INS_LDW);
			return;
		case 0x03:
			MCInst_setOpcode(MI, HPPA_INS_LDD);
			return;
		case 0x04:
			MCInst_setOpcode(MI, HPPA_INS_LDDA);
			return;
		case 0x05:
			MCInst_setOpcode(MI, HPPA_INS_LDCD);
			return;
		case 0x06:
			MCInst_setOpcode(MI, HPPA_INS_LDWA);
			return;
		case 0x07:
			MCInst_setOpcode(MI, HPPA_INS_LDCW);
			return;
		default:
			break;
		}
		if (get_insn_bit(insn, 19) == 1) {
			switch (ext) {
			case 0x08:
				MCInst_setOpcode(MI, HPPA_INS_STB);
				return;
			case 0x09:
				MCInst_setOpcode(MI, HPPA_INS_STH);
				return;
			case 0x0a:
				MCInst_setOpcode(MI, HPPA_INS_STW);
				return;
			case 0x0b:
				MCInst_setOpcode(MI, HPPA_INS_STD);
				return;
			case 0x0c:
				MCInst_setOpcode(MI, HPPA_INS_STBY);
				return;
			case 0x0d:
				MCInst_setOpcode(MI, HPPA_INS_STDBY);
				return;
			case 0x0e:
				MCInst_setOpcode(MI, HPPA_INS_STWA);
				return;
			case 0x0f:
				MCInst_setOpcode(MI, HPPA_INS_STDA);
				return;
			default:
				break;
			}
		}
	}
	if (get_insn_bit(insn, 19) == 0) {
		switch (ext) {
		case 0x00:
			MCInst_setOpcode(MI, HPPA_INS_LDBX);
			break;
		case 0x01:
			MCInst_setOpcode(MI, HPPA_INS_LDHX);
			break;
		case 0x02:
			MCInst_setOpcode(MI, HPPA_INS_LDWX);
			break;
		case 0x07:
			MCInst_setOpcode(MI, HPPA_INS_LDCWX);
			break;
		case 0x06:
			MCInst_setOpcode(MI, HPPA_INS_LDWAX);
			break;
		default:
			break;
		}
	} else {
		switch (ext) {
		case 0x00:
			MCInst_setOpcode(MI, HPPA_INS_LDBS);
			break;
		case 0x01:
			MCInst_setOpcode(MI, HPPA_INS_LDHS);
			break;
		case 0x02:
			MCInst_setOpcode(MI, HPPA_INS_LDWS);
			break;
		case 0x07:
			MCInst_setOpcode(MI, HPPA_INS_LDCWS);
			break;
		case 0x06:
			MCInst_setOpcode(MI, HPPA_INS_LDWAS);
			break;
		case 0x08:
			MCInst_setOpcode(MI, HPPA_INS_STBS);
			break;
		case 0x09:
			MCInst_setOpcode(MI, HPPA_INS_STHS);
			break;
		case 0x0a:
			MCInst_setOpcode(MI, HPPA_INS_STWS);
			break;
		case 0x0c:
			MCInst_setOpcode(MI, HPPA_INS_STBYS);
			break;
		case 0x0e:
			MCInst_setOpcode(MI, HPPA_INS_STWAS);
			break;
		default:
			break;
		}
	}
}

static void fill_idxmem_mods(uint32_t insn, hppa_ext *hppa_ext, cs_mode mode,
			     uint32_t im5)
{
	uint32_t cmplt = (get_insn_bit(insn, 18) << 1) | get_insn_bit(insn, 26);
	uint32_t cc = get_insn_field(insn, 20, 21);
	uint32_t ext = get_insn_field(insn, 22, 25);
	if (CMPLT_HAS_MODIFY_BIT(cmplt)) {
		hppa_ext->b_writeble = true;
	}
	if (get_insn_bit(insn, 19) == 0) {
		switch (ext) {
		case 0x00:
		case 0x01:
		case 0x02:
		case 0x03:
		case 0x04:
		case 0x06:
			push_str_modifier(hppa_ext, index_compl_names[cmplt]);
			if (cc == 2) {
				push_str_modifier(hppa_ext, "sl");
			}
			break;
		case 0x05:
		case 0x07:
			push_str_modifier(hppa_ext, index_compl_names[cmplt]);
			if (cc == 1) {
				push_str_modifier(hppa_ext, "co");
			}
			break;
		default:
			break;
		}
	} else {
		switch (ext) {
		case 0x00:
		case 0x01:
		case 0x02:
		case 0x03:
		case 0x04:
		case 0x06:
			if (cmplt == 1 && im5 == 0) {
				push_str_modifier(hppa_ext, "o");
			} else {
				push_str_modifier(
					hppa_ext,
					short_ldst_compl_names[cmplt]);
			}
			if (cc == 2) {
				push_str_modifier(hppa_ext, "sl");
			}
			break;
		case 0x05:
		case 0x07:
			if (cmplt == 1 && im5 == 0) {
				push_str_modifier(hppa_ext, "o");
			} else {
				push_str_modifier(
					hppa_ext,
					short_ldst_compl_names[cmplt]);
			}
			if (cc == 1) {
				push_str_modifier(hppa_ext, "co");
			}
			break;
		case 0x08:
		case 0x09:
		case 0x0a:
		case 0x0b:
		case 0x0e:
		case 0x0f:
			if (cmplt == 1 && im5 == 0) {
				push_str_modifier(hppa_ext, "o");
			} else {
				push_str_modifier(
					hppa_ext,
					short_ldst_compl_names[cmplt]);
			}
			if (cc == 1) {
				push_str_modifier(hppa_ext, "bc");
			} else if (cc == 2) {
				push_str_modifier(hppa_ext, "sl");
			}
			break;
		case 0x0c:
		case 0x0d:
			push_str_modifier(hppa_ext,
					  short_bytes_compl_names[cmplt]);
			if (cc == 1) {
				push_str_modifier(hppa_ext, "bc");
			} else if (cc == 2) {
				push_str_modifier(hppa_ext, "sl");
			}
			break;
		default:
			break;
		}
	}
}

static bool decode_idxmem(const cs_struct *ud, MCInst *MI, uint32_t insn)
{
	uint32_t ext = get_insn_field(insn, 22, 25);
	uint32_t im5;
	uint32_t r = get_insn_field(insn, 11, 15);
	uint32_t b = get_insn_field(insn, 6, 10);
	uint32_t t = get_insn_field(insn, 27, 31);
	uint32_t s = get_insn_field(insn, 16, 17);
	if (MODE_IS_HPPA_20(ud->mode)) {
		if (get_insn_bit(insn, 19) == 0) {
			switch (ext) {
			case 0x03:
			case 0x05:
			case 0x04:
				CREATE_GR_REG(MI, r);
				if (ext != 0x04) {
					CREATE_SR_REG(MI, s);
				}
				CREATE_GR_REG(MI, b);
				CREATE_GR_REG(MI, t);
				fill_idxmem_mods(insn, HPPA_EXT_REF(MI),
						 ud->mode, -1);
				return true;
			default:
				break;
			}
		} else {
			switch (ext) {
			case 0x03:
			case 0x05:
			case 0x04:
				im5 = extract_5_load(insn);
				MCOperand_CreateImm0(MI, im5);
				if (ext != 0x04) {
					CREATE_SR_REG(MI, s);
				}
				CREATE_GR_REG(MI, b);
				CREATE_GR_REG(MI, t);
				fill_idxmem_mods(insn, HPPA_EXT_REF(MI),
						 ud->mode, im5);
				return true;
			case 0x0b:
			case 0x0d:
			case 0x0f:
				im5 = extract_5_store(insn);
				CREATE_GR_REG(MI, r);
				MCOperand_CreateImm0(MI, im5);
				if (ext != 0x0f) {
					CREATE_SR_REG(MI, s);
				}
				CREATE_GR_REG(MI, b);
				fill_idxmem_mods(insn, HPPA_EXT_REF(MI),
						 ud->mode, im5);
				return true;
			default:
				break;
			}
		}
	}
	if (get_insn_bit(insn, 19) == 0) {
		switch (ext) {
		case 0x00:
		case 0x01:
		case 0x02:
		case 0x07:
		case 0x06:
			CREATE_GR_REG(MI, r);
			if (ext != 0x06) {
				CREATE_SR_REG(MI, s);
			}
			CREATE_GR_REG(MI, b);
			CREATE_GR_REG(MI, t);
			break;
		default:
			return false;
		}
		fill_idxmem_mods(insn, HPPA_EXT_REF(MI), ud->mode, -1);
		return true;
	} else {
		switch (ext) {
		case 0x00:
		case 0x01:
		case 0x02:
		case 0x07:
		case 0x06:
			im5 = extract_5_load(insn);
			MCOperand_CreateImm0(MI, im5);
			if (ext != 0x06) {
				CREATE_SR_REG(MI, s);
			}
			CREATE_GR_REG(MI, b);
			CREATE_GR_REG(MI, t);
			break;
		case 0x08:
		case 0x09:
		case 0x0a:
		case 0x0c:
		case 0x0e:
			im5 = extract_5_store(insn);
			CREATE_GR_REG(MI, r);
			MCOperand_CreateImm0(MI, im5);
			if (ext != 0x0e) {
				CREATE_SR_REG(MI, s);
			}
			CREATE_GR_REG(MI, b);
			break;
		default:
			return false;
		}
		if (MODE_IS_HPPA_20(ud->mode)) {
			fill_idxmem_mods(insn, HPPA_EXT_REF(MI), ud->mode, im5);
		} else {
			fill_idxmem_mods(insn, HPPA_EXT_REF(MI), ud->mode, -1);
		}
		return true;
	}
}

static void fill_ldst_dw_insn_name(MCInst *MI, uint32_t insn)
{
	uint32_t opcode = insn >> 26;
	uint32_t ext = get_insn_bit(insn, 30);
	if (opcode == 0x14) {
		if (ext == 0) {
			MCInst_setOpcode(MI, HPPA_INS_LDD);
		} else {
			MCInst_setOpcode(MI, HPPA_INS_FLDD);
		}
	} else {
		if (ext == 0) {
			MCInst_setOpcode(MI, HPPA_INS_STD);
		} else {
			MCInst_setOpcode(MI, HPPA_INS_FSTD);
		}
	}
}

static void fill_ldst_dw_mods(uint32_t insn, hppa_ext *hppa_ext, uint32_t im)
{
	uint32_t cmplt = (get_insn_bit(insn, 29) << 1) | get_insn_bit(insn, 28);
	if (cmplt == 1 && im == 0) {
		push_str_modifier(hppa_ext, "o");
	} else {
		push_str_modifier(hppa_ext, short_ldst_compl_names[cmplt]);
	}
}

static bool decode_ldst_dw(const cs_struct *ud, MCInst *MI, uint32_t insn)
{
	uint32_t opcode = insn >> 26;
	uint32_t im = extract_16(insn, MODE_IS_HPPA_20W(ud->mode));
	im &= ~7;
	uint32_t ext = get_insn_bit(insn, 30);
	uint32_t r = get_insn_field(insn, 11, 15);
	uint32_t b = get_insn_field(insn, 6, 10);
	uint32_t s = get_insn_field(insn, 16, 17);
	if (opcode == HPPA_OP_TYPE_LOADDW) {
		MCOperand_CreateImm0(MI, im);
		CREATE_SR_REG(MI, s);
		CREATE_GR_REG(MI, b);
		if (ext == 0) {
			CREATE_GR_REG(MI, r);
		} else {
			CREATE_FPR_REG(MI, r);
		}
	} else {
		if (ext == 0) {
			CREATE_GR_REG(MI, r);
		} else {
			CREATE_FPR_REG(MI, r);
		}
		MCOperand_CreateImm0(MI, im);
		CREATE_SR_REG(MI, s);
		CREATE_GR_REG(MI, b);
	}
	fill_ldst_dw_mods(insn, HPPA_EXT_REF(MI), im);
	return true;
}

static void fill_ldst_w_insn_name(MCInst *MI, uint32_t insn)
{
	uint32_t opcode = insn >> 26;
	uint32_t ext = get_insn_bit(insn, 29);
	if (opcode == 0x17) {
		if (ext == 0) {
			MCInst_setOpcode(MI, HPPA_INS_FLDW);
		} else {
			MCInst_setOpcode(MI, HPPA_INS_LDW);
		}
	} else {
		if (ext == 0) {
			MCInst_setOpcode(MI, HPPA_INS_FSTW);
		} else {
			MCInst_setOpcode(MI, HPPA_INS_STW);
		}
	}
}

static void fill_ldst_w_mods(uint32_t insn, hppa_ext *hppa_ext, int32_t im)
{
	if (im >= 0) {
		push_str_modifier(hppa_ext, "mb");
	} else {
		push_str_modifier(hppa_ext, "ma");
	}
}

static bool decode_ldst_w(const cs_struct *ud, MCInst *MI, uint32_t insn)
{
	uint32_t opcode = insn >> 26;
	uint32_t ext = get_insn_bit(insn, 29);
	int32_t im = extract_16(insn, MODE_IS_HPPA_20W(ud->mode));
	im &= ~3;
	uint32_t r = get_insn_field(insn, 11, 15);
	uint32_t b = get_insn_field(insn, 6, 10);
	uint32_t s = get_insn_field(insn, 16, 17);
	if (opcode == 0x17) {
		MCOperand_CreateImm0(MI, im);
		CREATE_SR_REG(MI, s);
		CREATE_GR_REG(MI, b);
		if (ext == 1) {
			CREATE_GR_REG(MI, r);
		} else {
			CREATE_FPR_REG(MI, r);
		}
	} else {
		if (ext == 1) {
			CREATE_GR_REG(MI, r);
		} else {
			CREATE_FPR_REG(MI, r);
		}
		MCOperand_CreateImm0(MI, im);
		CREATE_SR_REG(MI, s);
		CREATE_GR_REG(MI, b);
	}
	if (ext == 1) {
		fill_ldst_w_mods(insn, HPPA_EXT_REF(MI), im);
	}
	return true;
}

static void fill_arith_imm_insn_name(MCInst *MI, uint32_t insn)
{
	uint32_t opcode = insn >> 26;
	if (MODE_IS_HPPA_20(MI->csh->mode)) {
		switch (opcode) {
		case 0x2d:
		case 0x2c:
			MCInst_setOpcode(MI, HPPA_INS_ADDI);
			return;
		case 0x25:
			MCInst_setOpcode(MI, HPPA_INS_SUBI);
			return;
		default:
			break;
		}
	}
	if (get_insn_bit(insn, 20) == 0) {
		switch (opcode) {
		case 0x2d:
			MCInst_setOpcode(MI, HPPA_INS_ADDI);
			break;
		case 0x2c:
			MCInst_setOpcode(MI, HPPA_INS_ADDIT);
			break;
		case 0x25:
			MCInst_setOpcode(MI, HPPA_INS_SUBI);
			break;
		default:
			break;
		}
	} else {
		switch (opcode) {
		case 0x2d:
			MCInst_setOpcode(MI, HPPA_INS_ADDIO);
			break;
		case 0x2c:
			MCInst_setOpcode(MI, HPPA_INS_ADDITO);
			break;
		case 0x25:
			MCInst_setOpcode(MI, HPPA_INS_SUBIO);
			break;
		default:
			break;
		}
	}
}

static void fill_arith_imm_insn_mods(uint32_t insn, hppa_ext *hppa_ext,
				     cs_mode mode)
{
	uint32_t opcode = insn >> 26;
	uint32_t cond = (get_insn_bit(insn, 19) << 3) |
			get_insn_field(insn, 16, 18);
	uint32_t cmplt = get_insn_bit(insn, 20);
	if (MODE_IS_HPPA_20(mode)) {
		if (cmplt == 1) {
			push_str_modifier(hppa_ext, "tsv");
		}
		if (opcode == 0x2c) {
			push_str_modifier(hppa_ext, "tc");
		}
	}
	switch (opcode) {
	case 0x2d:
	case 0x2c:
		push_str_modifier(hppa_ext, add_cond_names[cond]);
		break;
	case 0x25:
		push_str_modifier(hppa_ext, compare_cond_names[cond]);
		break;
	default:
		break;
	}
}

static bool decode_arith_imm(const cs_struct *ud, MCInst *MI, uint32_t insn)
{
	MCOperand_CreateImm0(MI, extract_11(insn));
	CREATE_GR_REG(MI, get_insn_field(insn, 6, 10));
	CREATE_GR_REG(MI, get_insn_field(insn, 11, 15));
	fill_arith_imm_insn_mods(insn, HPPA_EXT_REF(MI), ud->mode);
	return true;
}

static void fill_shexdep0_insn_name(MCInst *MI, uint32_t insn)
{
	uint32_t ext = get_insn_field(insn, 19, 21);
	uint32_t d = get_insn_bit(insn, 22);
	if (MODE_IS_HPPA_20(MI->csh->mode)) {
		switch (ext) {
		case 0x01:
		case 0x03:
			MCInst_setOpcode(MI, HPPA_INS_SHRPD);
			return;
		case 0x02:
			MCInst_setOpcode(MI, HPPA_INS_SHRPW);
			return;
		case 0x06:
		case 0x07:
			MCInst_setOpcode(MI, HPPA_INS_EXTRW);
			return;
		case 0x00:
			if (d == 0) {
				MCInst_setOpcode(MI, HPPA_INS_SHRPW);
			} else {
				MCInst_setOpcode(MI, HPPA_INS_SHRPD);
			}
			return;
		case 0x04:
		case 0x05:
			if (d == 0) {
				MCInst_setOpcode(MI, HPPA_INS_EXTRW);
			} else {
				MCInst_setOpcode(MI, HPPA_INS_EXTRD);
			}
			return;
		default:
			break;
		}
	}
	switch (ext) {
	case 0x00:
		MCInst_setOpcode(MI, HPPA_INS_VSHD);
		break;
	case 0x02:
		MCInst_setOpcode(MI, HPPA_INS_SHD);
		break;
	case 0x04:
		MCInst_setOpcode(MI, HPPA_INS_VEXTRU);
		break;
	case 0x05:
		MCInst_setOpcode(MI, HPPA_INS_VEXTRS);
		break;
	case 0x06:
		MCInst_setOpcode(MI, HPPA_INS_EXTRU);
		break;
	case 0x07:
		MCInst_setOpcode(MI, HPPA_INS_EXTRS);
		break;
	default:
		break;
	}
}

static void fill_shexdep0_mods(uint32_t insn, hppa_ext *hppa_ext, cs_mode mode)
{
	uint32_t cond = get_insn_field(insn, 16, 18);
	uint32_t ext = get_insn_field(insn, 19, 21);
	uint32_t d = get_insn_bit(insn, 22);

	if (ext >= 0x04 && MODE_IS_HPPA_20(mode)) {
		push_str_modifier(hppa_ext, signed_unsigned_names[ext & 1]);
	}

	if (MODE_IS_HPPA_20(mode)) {
		switch (ext) {
		case 0x00:
		case 0x04:
		case 0x05:
			if (d == 0) {
				break;
			}
			// fallthrough
		case 0x01:
		case 0x03:
			push_str_modifier(hppa_ext, shift_cond_64_names[cond]);
			return;
		default:
			break;
		}
	}
	push_str_modifier(hppa_ext, shift_cond_names[cond]);
}

static bool decode_shexdep0(const cs_struct *ud, MCInst *MI, uint32_t insn)
{
	uint32_t ext = get_insn_field(insn, 19, 21);
	uint32_t cp = get_insn_bit(insn, 20);
	uint32_t cpos = get_insn_field(insn, 22, 26);
	uint32_t sa = 63 - ((cp << 5) | cpos);
	uint32_t r1 = get_insn_field(insn, 11, 15);
	uint32_t r2 = get_insn_field(insn, 6, 10);
	uint32_t clen_t = get_insn_field(insn, 27, 31);
	if (MODE_IS_HPPA_20(ud->mode)) {
		switch (ext) {
		case 0x01:
		case 0x00:
		case 0x03:
		case 0x02:
			CREATE_GR_REG(MI, r1);
			CREATE_GR_REG(MI, r2);
			if (ext <= 0x01) {
				CREATE_CR_REG(MI, 11);
				HPPA_EXT_REF(MI)->is_alternative = true;
			} else {
				MCOperand_CreateImm0(MI, sa);
			}
			CREATE_GR_REG(MI, clen_t);
			break;
		case 0x06:
		case 0x07:
		case 0x04:
		case 0x05:
			CREATE_GR_REG(MI, r2);
			if (ext >= 0x06) {
				MCOperand_CreateImm0(MI, cpos);
			} else {
				CREATE_CR_REG(MI, 11);
				HPPA_EXT_REF(MI)->is_alternative = true;
			}
			MCOperand_CreateImm0(MI, 32 - clen_t);
			CREATE_GR_REG(MI, r1);
			break;
		default:
			return false;
		}
	} else {
		switch (ext) {
		case 0x00:
		case 0x02:
			CREATE_GR_REG(MI, r1);
			CREATE_GR_REG(MI, r2);
			if (ext == 0x02) {
				MCOperand_CreateImm0(MI, 31 - cpos);
			}
			CREATE_GR_REG(MI, clen_t);
			break;
		case 0x04:
		case 0x05:
		case 0x06:
		case 0x07:
			CREATE_GR_REG(MI, r2);
			if (ext >= 0x06) {
				MCOperand_CreateImm0(MI, cpos);
			}
			MCOperand_CreateImm0(MI, 32 - clen_t);
			CREATE_GR_REG(MI, r1);
			break;
		default:
			return false;
		}
	}
	fill_shexdep0_mods(insn, HPPA_EXT_REF(MI), ud->mode);
	return true;
}

static void fill_shexdep1_insn_name(MCInst *MI, uint32_t insn)
{
	uint32_t ext = get_insn_field(insn, 19, 21);
	uint32_t d = get_insn_bit(insn, 22);
	if (MODE_IS_HPPA_20(MI->csh->mode)) {
		switch (ext) {
		case 0x02:
		case 0x03:
			MCInst_setOpcode(MI, HPPA_INS_DEPW);
			break;
		case 0x06:
		case 0x07:
			MCInst_setOpcode(MI, HPPA_INS_DEPWI);
			break;
		case 0x00:
		case 0x01:
			if (d == 0) {
				MCInst_setOpcode(MI, HPPA_INS_DEPW);
			} else {
				MCInst_setOpcode(MI, HPPA_INS_DEPD);
			}
			break;
		case 0x04:
		case 0x05:
			if (d == 0) {
				MCInst_setOpcode(MI, HPPA_INS_DEPWI);
			} else {
				MCInst_setOpcode(MI, HPPA_INS_DEPDI);
			}
			break;
		default:
			break;
		}
	} else {
		switch (ext) {
		case 0x00:
			MCInst_setOpcode(MI, HPPA_INS_ZVDEP);
			break;
		case 0x01:
			MCInst_setOpcode(MI, HPPA_INS_VDEP);
			break;
		case 0x02:
			MCInst_setOpcode(MI, HPPA_INS_ZDEP);
			break;
		case 0x03:
			MCInst_setOpcode(MI, HPPA_INS_DEP);
			break;
		case 0x04:
			MCInst_setOpcode(MI, HPPA_INS_ZVDEPI);
			break;
		case 0x05:
			MCInst_setOpcode(MI, HPPA_INS_VDEPI);
			break;
		case 0x06:
			MCInst_setOpcode(MI, HPPA_INS_ZDEPI);
			break;
		case 0x07:
			MCInst_setOpcode(MI, HPPA_INS_DEPI);
			break;
		default:
			break;
		}
	}
}

static void fill_shexdep1_mods(uint32_t insn, hppa_ext *hppa_ext, cs_mode mode)
{
	uint32_t cond = get_insn_field(insn, 16, 18);
	uint32_t cmplt = get_insn_bit(insn, 21);
	uint32_t ext = get_insn_field(insn, 19, 21);
	if (MODE_IS_HPPA_20(mode)) {
		if (cmplt == 0) {
			push_str_modifier(hppa_ext, "z");
		}
		switch (ext) {
		case 0x00:
		case 0x01:
		case 0x04:
		case 0x05:
			push_str_modifier(hppa_ext, shift_cond_64_names[cond]);
			return;
		default:
			break;
		}
	}
	push_str_modifier(hppa_ext, shift_cond_names[cond]);
}

static bool decode_shexdep1(const cs_struct *ud, MCInst *MI, uint32_t insn)
{
	uint32_t ext = get_insn_field(insn, 19, 21);
	uint32_t cl = get_insn_bit(insn, 23);
	uint32_t clen = get_insn_field(insn, 27, 31);
	uint32_t len = (cl + 1) * 32 - clen;
	uint32_t r = get_insn_field(insn, 11, 15);
	uint32_t t = get_insn_field(insn, 6, 10);
	uint32_t cpos = get_insn_field(insn, 22, 26);
	if (MODE_IS_HPPA_20(ud->mode)) {
		switch (ext) {
		case 0x02:
		case 0x03:
		case 0x06:
		case 0x07:
			if (ext >= 0x06) {
				MCOperand_CreateImm0(MI, LowSignExtend64(r, 5));
			} else {
				CREATE_GR_REG(MI, r);
			}
			MCOperand_CreateImm0(MI, 31 - cpos);
			MCOperand_CreateImm0(MI, 32 - clen);
			CREATE_GR_REG(MI, t);
			break;
		case 0x00:
		case 0x01:
		case 0x04:
		case 0x05:
			if (ext >= 0x04) {
				MCOperand_CreateImm0(MI, LowSignExtend64(r, 5));
			} else {
				CREATE_GR_REG(MI, r);
			}
			CREATE_CR_REG(MI, 11);
			HPPA_EXT_REF(MI)->is_alternative = true;
			MCOperand_CreateImm0(MI, len);
			CREATE_GR_REG(MI, t);
			break;
		default:
			break;
		}
	} else {
		switch (ext) {
		case 0x00:
		case 0x01:
		case 0x02:
		case 0x03:
			CREATE_GR_REG(MI, r);
			if (ext >= 0x02) {
				MCOperand_CreateImm0(MI, 31 - cpos);
			}
			MCOperand_CreateImm0(MI, 32 - clen);
			CREATE_GR_REG(MI, t);
			break;
		case 0x04:
		case 0x05:
		case 0x06:
		case 0x07:
			MCOperand_CreateImm0(MI, LowSignExtend64(r, 5));
			if (ext >= 0x06) {
				MCOperand_CreateImm0(MI, 31 - cpos);
			}
			MCOperand_CreateImm0(MI, 32 - clen);
			CREATE_GR_REG(MI, t);
			break;
		default:
			break;
		}
	}
	fill_shexdep1_mods(insn, HPPA_EXT_REF(MI), ud->mode);
	return true;
}

static void fill_shexdep2_mods(uint32_t insn, hppa_ext *hppa_ext)
{
	uint32_t cmplt = get_insn_bit(insn, 21);
	uint32_t cond = get_insn_field(insn, 16, 18);
	push_str_modifier(hppa_ext, signed_unsigned_names[cmplt]);
	push_str_modifier(hppa_ext, shift_cond_64_names[cond]);
}

static bool decode_shexdep2(MCInst *MI, uint32_t insn)
{
	uint32_t pos = (get_insn_bit(insn, 20) << 5) |
		       get_insn_field(insn, 22, 26);
	uint32_t cl = get_insn_bit(insn, 19);
	uint32_t clen = get_insn_field(insn, 27, 31);
	uint32_t len = (cl + 1) * 32 - clen;
	CREATE_GR_REG(MI, get_insn_field(insn, 6, 10));
	MCOperand_CreateImm0(MI, pos);
	MCOperand_CreateImm0(MI, len);
	CREATE_GR_REG(MI, get_insn_field(insn, 11, 15));
	fill_shexdep2_mods(insn, HPPA_EXT_REF(MI));
	return true;
}

static void fill_shexdep3_mods(uint32_t insn, hppa_ext *hppa_ext)
{
	uint32_t cmplt = get_insn_bit(insn, 21);
	uint32_t cond = get_insn_field(insn, 16, 18);
	if (cmplt == 0) {
		push_str_modifier(hppa_ext, "z");
	}
	push_str_modifier(hppa_ext, shift_cond_64_names[cond]);
}

static bool decode_shexdep3(const cs_struct *ud, MCInst *MI, uint32_t insn)
{
	uint32_t opcode = insn >> 26;
	if (opcode == HPPA_OP_TYPE_SHEXDEP3) {
		MCInst_setOpcode(MI, HPPA_INS_DEPD);
	} else {
		MCInst_setOpcode(MI, HPPA_INS_DEPDI);
	}
	uint32_t pos = 63 - ((get_insn_bit(insn, 20) << 5) |
			     get_insn_field(insn, 22, 26));
	uint32_t cl = get_insn_bit(insn, 19);
	uint32_t clen = get_insn_field(insn, 27, 31);
	uint32_t len = (cl + 1) * 32 - clen;
	if (opcode == HPPA_OP_TYPE_SHEXDEP3) {
		CREATE_GR_REG(MI, get_insn_field(insn, 11, 15));
	} else {
		MCOperand_CreateImm0(
			MI, LowSignExtend64(get_insn_field(insn, 11, 15), 5));
	}
	MCOperand_CreateImm0(MI, pos);
	MCOperand_CreateImm0(MI, len);
	CREATE_GR_REG(MI, get_insn_field(insn, 6, 10));
	fill_shexdep3_mods(insn, HPPA_EXT_REF(MI));
	return true;
}

static void fill_multmed_insn_name(MCInst *MI, uint32_t insn)
{
	uint32_t bit_16 = get_insn_bit(insn, 16);
	uint32_t ext = (get_insn_field(insn, 17, 18) << 2) |
		       get_insn_field(insn, 20, 21);
	if (bit_16 == 0) {
		MCInst_setOpcode(MI, HPPA_INS_PERMH);
		return;
	}
	switch (ext) {
	case 0x02:
		MCInst_setOpcode(MI, HPPA_INS_HSHL);
		break;
	case 0x0a:
	case 0x0b:
		MCInst_setOpcode(MI, HPPA_INS_HSHR);
		break;
	case 0x00:
	case 0x08:
		MCInst_setOpcode(MI, HPPA_INS_MIXW);
		break;
	case 0x01:
	case 0x09:
		MCInst_setOpcode(MI, HPPA_INS_MIXH);
		break;
	default:
		break;
	}
}

static void fill_multmed_mods(uint32_t insn, hppa_ext *hppa_ext)
{
	uint32_t bit_16 = get_insn_bit(insn, 16);
	uint32_t ext = (get_insn_field(insn, 17, 18) << 2) |
		       get_insn_field(insn, 20, 21);
	uint32_t eb = get_insn_field(insn, 20, 21);
	uint32_t ea = get_insn_field(insn, 17, 18);
	if (bit_16 == 0) {
		char c[5];
		snprintf(c, sizeof(c), "%d%d%d%d", get_insn_field(insn, 17, 18),
			 get_insn_field(insn, 20, 21),
			 get_insn_field(insn, 22, 23),
			 get_insn_field(insn, 24, 25));
		push_str_modifier(hppa_ext, c);
		return;
	}
	switch (ext) {
	case 0x0a:
	case 0x0b:
		if (eb >= 2) {
			push_str_modifier(hppa_ext,
					  signed_unsigned_names[eb - 2]);
		}
		break;
	case 0x00:
	case 0x08:
	case 0x01:
	case 0x09:
		if (ea == 2) {
			push_str_modifier(hppa_ext, "l");
		} else if (ea == 0) {
			push_str_modifier(hppa_ext, "r");
		}
		break;
	default:
		break;
	}
}

static bool decode_multmed(MCInst *MI, uint32_t insn)
{
	uint32_t bit_16 = get_insn_bit(insn, 16);
	uint32_t ext = (get_insn_field(insn, 17, 18) << 2) |
		       get_insn_field(insn, 20, 21);
	uint32_t r1 = get_insn_field(insn, 11, 15);
	uint32_t r2 = get_insn_field(insn, 6, 10);
	uint32_t t = get_insn_field(insn, 27, 31);
	uint32_t sa = get_insn_field(insn, 22, 25);
	if (bit_16 == 0) {
		CREATE_GR_REG(MI, r2);
		CREATE_GR_REG(MI, t);
		goto success;
	}
	switch (ext) {
	case 0x02:
	case 0x0a:
	case 0x0b:
		if (ext >= 0x0a) {
			CREATE_GR_REG(MI, r2);
		} else {
			CREATE_GR_REG(MI, r1);
		}
		MCOperand_CreateImm0(MI, sa);
		CREATE_GR_REG(MI, t);
		break;
	case 0x00:
	case 0x08:
	case 0x01:
	case 0x09:
		CREATE_GR_REG(MI, r1);
		CREATE_GR_REG(MI, r2);
		CREATE_GR_REG(MI, t);
		break;
	default:
		return false;
	}
success:
	fill_multmed_mods(insn, HPPA_EXT_REF(MI));
	return true;
}

static void fill_branch_insn_name(MCInst *MI, uint32_t insn)
{
	uint32_t ext = get_insn_field(insn, 16, 18);
	uint32_t bit_19 = get_insn_bit(insn, 19);
	if (MODE_IS_HPPA_20(MI->csh->mode)) {
		if (insn == 0xe8004005) {
			MCInst_setOpcode(MI, HPPA_INS_CLRBTS);
			return;
		} else if (insn == 0xe8004001) {
			MCInst_setOpcode(MI, HPPA_INS_PUSHNOM);
			return;
		}

		switch (ext) {
		case 0x00:
		case 0x01:
		case 0x04:
		case 0x05:
			MCInst_setOpcode(MI, HPPA_INS_B);
			return;
		case 0x06:
			if (bit_19 == 0) {
				MCInst_setOpcode(MI, HPPA_INS_BV);
			} else {
				MCInst_setOpcode(MI, HPPA_INS_BVE);
			}
			return;
		case 0x07:
			if (bit_19 == 1) {
				MCInst_setOpcode(MI, HPPA_INS_BVE);
			}
			return;
		case 0x02:
			if (get_insn_field(insn, 19, 29) == 0 &&
			    get_insn_bit(insn, 31) == 0) {
				MCInst_setOpcode(MI, HPPA_INS_BLR);
				return;
			}
			if (get_insn_field(insn, 19, 31) == 1) {
				MCInst_setOpcode(MI, HPPA_INS_PUSHBTS);
				return;
			}
			if (bit_19 == 0 &&
			    get_insn_field(insn, 29, 31) == 0x5) {
				MCInst_setOpcode(MI, HPPA_INS_POPBTS);
				return;
			}
			return;
		default:
			return;
		}
	}
	switch (ext) {
	case 0x00:
		MCInst_setOpcode(MI, HPPA_INS_BL);
		break;
	case 0x01:
		MCInst_setOpcode(MI, HPPA_INS_GATE);
		break;
	case 0x02:
		MCInst_setOpcode(MI, HPPA_INS_BLR);
		break;
	case 0x06:
		MCInst_setOpcode(MI, HPPA_INS_BV);
		break;
	default:
		break;
	}
}

static void fill_branch_mods(uint32_t insn, hppa_ext *hppa_ext, cs_mode mode)
{
	uint32_t ext = get_insn_field(insn, 16, 18);
	uint32_t n = get_insn_bit(insn, 30);
	uint32_t p = get_insn_bit(insn, 31);
	if (MODE_IS_HPPA_20(mode)) {
		switch (ext) {
		case 0x00:
		case 0x05:
			push_str_modifier(hppa_ext, "l");
			// fallthrough
		case 0x02:
			break;
		case 0x01:
			push_str_modifier(hppa_ext, "gate");
			break;
		case 0x04:
			push_str_modifier(hppa_ext, "l");
			push_str_modifier(hppa_ext, "push");
			break;
		case 0x06:
		case 0x07:
			if (get_insn_bit(insn, 19) == 0) {
				break;
			}
			if (ext == 7) {
				push_str_modifier(hppa_ext, "l");
				hppa_ext->is_alternative = true;
				if (p == 1) {
					push_str_modifier(hppa_ext, "push");
				}
			} else {
				if (p == 1) {
					push_str_modifier(hppa_ext, "pop");
				}
			}
			break;
		default:
			return;
		}
	}
	if (n == 1) {
		push_str_modifier(hppa_ext, "n");
	}
}

static bool decode_branch(const cs_struct *ud, MCInst *MI, uint32_t insn)
{
	uint32_t ext = get_insn_field(insn, 16, 18);
	uint32_t t = get_insn_field(insn, 6, 10);
	uint32_t i = get_insn_field(insn, 20, 28);
	uint32_t r = get_insn_field(insn, 11, 15);
	uint32_t bit_19 = get_insn_bit(insn, 19);
	if (MODE_IS_HPPA_20(ud->mode)) {
		if (insn == 0xe8004005 || insn == 0xe8004001) {
			return true;
		}

		switch (ext) {
		case 0x01:
		case 0x00:
			MCOperand_CreateImm0(MI, extract_17(insn));
			CREATE_GR_REG(MI, t);
			break;
		case 0x04:
		case 0x05:
			MCOperand_CreateImm0(MI, extract_22(insn));
			CREATE_GR_REG(MI, t);
			break;
		case 0x02:
			if (bit_19 == 1) {
				return false;
			}
			if (get_insn_field(insn, 20, 31) == 1 && t == 0) {
				CREATE_GR_REG(MI, r);
				break;
			}
			if (r == 0 && t == 0 &&
			    get_insn_field(insn, 29, 31) == 0x5) {
				MCOperand_CreateImm0(MI, i);
				break;
			}
			if (get_insn_bit(insn, 31) == 0 &&
			    get_insn_field(insn, 19, 29) == 0) {
				CREATE_GR_REG(MI, r);
				CREATE_GR_REG(MI, t);
				break;
			}
			return false;
		case 0x06:
			if (bit_19 == 0) {
				CREATE_GR_REG(MI, r);
			}
			CREATE_GR_REG(MI, t);
			break;
		case 0x07:
			if (bit_19 == 1) {
				CREATE_GR_REG(MI, t);
				CREATE_GR_REG(MI, 2);
				break;
			}
			// fallthrough
		default:
			return false;
		}
		fill_branch_mods(insn, HPPA_EXT_REF(MI), ud->mode);
		return true;
	} else {
		switch (ext) {
		case 0x00:
		case 0x01:
			MCOperand_CreateImm0(MI, extract_17(insn));
			CREATE_GR_REG(MI, t);
			break;
		case 0x02:
		case 0x06:
			CREATE_GR_REG(MI, r);
			CREATE_GR_REG(MI, t);
			break;
		default:
			return false;
		}
		fill_branch_mods(insn, HPPA_EXT_REF(MI), ud->mode);
		return true;
	}
}

static void fill_corpdw_insn_name(MCInst *MI, uint32_t insn)
{
	uint32_t ext = (get_insn_field(insn, 19, 19) << 1) |
		       get_insn_field(insn, 22, 22);
	uint32_t opcode = insn >> 26;
	uint32_t uid = get_insn_field(insn, 23, 25);
	if (MODE_IS_HPPA_20(MI->csh->mode)) {
		if (opcode == 0x09) {
			switch (ext) {
			case 0x00:
			case 0x02:
				if (uid <= 0x01) {
					MCInst_setOpcode(MI, HPPA_INS_FLDW);
				} else {
					MCInst_setOpcode(MI, HPPA_INS_CLDW);
				}
				return;
			case 0x01:
			case 0x03:
				if (uid <= 0x01) {
					MCInst_setOpcode(MI, HPPA_INS_FSTW);
				} else {
					MCInst_setOpcode(MI, HPPA_INS_CSTW);
				}
				return;
			default:
				break;
			}
		} else {
			switch (ext) {
			case 0x00:
			case 0x02:
				if (uid == 0x00) {
					MCInst_setOpcode(MI, HPPA_INS_FLDD);
				} else {
					MCInst_setOpcode(MI, HPPA_INS_CLDD);
				}
				return;
			case 0x01:
			case 0x03:
				if (uid == 0x00) {
					MCInst_setOpcode(MI, HPPA_INS_FSTD);
				} else {
					MCInst_setOpcode(MI, HPPA_INS_CSTD);
				}
				return;
			default:
				break;
			}
		}
	}
	if (opcode == 0x09) {
		switch (ext) {
		case 0x00:
			MCInst_setOpcode(MI, HPPA_INS_CLDWX);
			break;
		case 0x01:
			MCInst_setOpcode(MI, HPPA_INS_CSTWX);
			break;
		case 0x02:
			MCInst_setOpcode(MI, HPPA_INS_CLDWS);
			break;
		case 0x03:
			MCInst_setOpcode(MI, HPPA_INS_CSTWS);
			break;
		default:
			break;
		}
	} else {
		switch (ext) {
		case 0x00:
			MCInst_setOpcode(MI, HPPA_INS_CLDDX);
			break;
		case 0x01:
			MCInst_setOpcode(MI, HPPA_INS_CSTDX);
			break;
		case 0x02:
			MCInst_setOpcode(MI, HPPA_INS_CLDDS);
			break;
		case 0x03:
			MCInst_setOpcode(MI, HPPA_INS_CSTDS);
			break;
		default:
			break;
		}
	}
}

static inline bool coprdw_has_uid_mod(uint32_t opcode, uint32_t uid)
{
	return !((opcode == HPPA_OP_TYPE_COPRW && uid <= 0x01) ||
		 (opcode == HPPA_OP_TYPE_COPRDW && uid == 0x00));
}

static void fill_corpdw_mods(uint32_t insn, uint32_t im, hppa_ext *hppa_ext,
			     cs_mode mode)
{
	uint32_t uid = get_insn_field(insn, 23, 25);
	uint32_t cmplt = (get_insn_bit(insn, 18) << 1) | get_insn_bit(insn, 26);
	uint32_t cc = get_insn_field(insn, 20, 21);
	uint32_t ext = (get_insn_bit(insn, 19) << 1) | get_insn_bit(insn, 22);
	uint32_t opcode = insn >> 26;

	if (coprdw_has_uid_mod(opcode, uid)) {
		push_int_modifier(hppa_ext, uid);
	}
	if (CMPLT_HAS_MODIFY_BIT(cmplt)) {
		hppa_ext->b_writeble = true;
	}

	switch (ext) {
	case 0x00:
	case 0x01:
		push_str_modifier(hppa_ext, index_compl_names[cmplt]);
		break;
	case 0x02:
	case 0x03:
		if (MODE_IS_HPPA_20(mode)) {
			if (cmplt == 1 && im == 0) {
				push_str_modifier(hppa_ext, "o");
				break;
			}
		}
		push_str_modifier(hppa_ext, short_ldst_compl_names[cmplt]);
		break;
	default:
		break;
	}
	if ((ext & 1) == 1 && cc == 1) {
		push_str_modifier(hppa_ext, "bc");
	}
	if (cc == 2) {
		push_str_modifier(hppa_ext, "sl");
	}
}

static bool decode_corpdw(const cs_struct *ud, MCInst *MI, uint32_t insn)
{
	uint32_t ext = (get_insn_bit(insn, 19) << 1) | get_insn_bit(insn, 22);
	uint32_t x = get_insn_field(insn, 11, 15);
	uint32_t b = get_insn_field(insn, 6, 10);
	uint32_t s = get_insn_field(insn, 16, 17);
	uint32_t t = get_insn_field(insn, 27, 31);
	uint32_t opcode = MCInst_getOpcode(MI);
	switch (ext) {
	case 0x00:
	case 0x02:
		if (ext == 0x02) {
			x = LowSignExtend64(x, 5);
			MCOperand_CreateImm0(MI, x);
		} else {
			CREATE_GR_REG(MI, x);
		}
		CREATE_SR_REG(MI, s);
		CREATE_GR_REG(MI, b);
		if (opcode == HPPA_INS_FLDW || opcode == HPPA_INS_FLDD) {
			CREATE_FPR_REG(MI, t);
		} else {
			CREATE_GR_REG(MI, t);
		}
		break;
	case 0x01:
	case 0x03:
		if (opcode == HPPA_INS_FSTW || opcode == HPPA_INS_FSTD) {
			CREATE_FPR_REG(MI, t);
		} else {
			CREATE_GR_REG(MI, t);
		}
		if (ext == 0x03) {
			x = LowSignExtend64(x, 5);
			MCOperand_CreateImm0(MI, x);
		} else {
			CREATE_GR_REG(MI, x);
		}
		CREATE_SR_REG(MI, s);
		CREATE_GR_REG(MI, b);
		break;
	default:
		break;
	}
	fill_corpdw_mods(insn, x, HPPA_EXT_REF(MI), ud->mode);
	return true;
}

static void fill_spop_insn_name(MCInst *MI, uint32_t insn)
{
	uint32_t ext = get_insn_field(insn, 21, 22);
	switch (ext) {
	case 0x00:
		MCInst_setOpcode(MI, HPPA_INS_SPOP0);
		break;
	case 0x01:
		MCInst_setOpcode(MI, HPPA_INS_SPOP1);
		break;
	case 0x02:
		MCInst_setOpcode(MI, HPPA_INS_SPOP2);
		break;
	case 0x03:
		MCInst_setOpcode(MI, HPPA_INS_SPOP3);
		break;
	default:
		break;
	}
}

static void fill_spop_mods(uint32_t insn, uint32_t ext, hppa_ext *hppa_ext)
{
	uint32_t sfu = get_insn_field(insn, 23, 25);
	uint32_t n = get_insn_field(insn, 26, 26);
	uint32_t sop;

	push_int_modifier(hppa_ext, sfu);
	switch (ext) {
	case 0x00:
		sop = (get_insn_field(insn, 6, 20) << 5) |
		      get_insn_field(insn, 27, 31);
		break;
	case 0x01:
		sop = get_insn_field(insn, 6, 20);
		break;
	case 0x02:
		sop = (get_insn_field(insn, 11, 20) << 5) |
		      get_insn_field(insn, 27, 31);
		break;
	case 0x03:
		sop = (get_insn_field(insn, 16, 20) << 5) |
		      get_insn_field(insn, 27, 31);
		break;
	default:
		return;
	}
	push_int_modifier(hppa_ext, sop);
	if (n == 1) {
		push_str_modifier(hppa_ext, "n");
	}
}

static bool decode_spop(const cs_struct *ud, MCInst *MI, uint32_t insn)
{
	uint32_t ext = get_insn_field(insn, 21, 22);
	uint32_t r2 = get_insn_field(insn, 11, 15);
	uint32_t r1 = get_insn_field(insn, 6, 10);
	uint32_t t = get_insn_field(insn, 27, 31);
	switch (ext) {
	case 0x00:
		break;
	case 0x01:
		CREATE_GR_REG(MI, t);
		break;
	case 0x02:
		CREATE_GR_REG(MI, r1);
		break;
	case 0x03:
		CREATE_GR_REG(MI, r2);
		CREATE_GR_REG(MI, r1);
		break;
	default:
		return false;
	}
	fill_spop_mods(insn, ext, HPPA_EXT_REF(MI));
	return true;
}

static void fill_copr_insn_name(MCInst *MI, uint32_t insn)
{
	uint32_t class = get_insn_field(insn, 21, 22);
	uint32_t uid = get_insn_field(insn, 23, 25);
	uint32_t subop;
	if (MODE_IS_HPPA_20(MI->csh->mode)) {
		if (uid == 0) {
			if (class == 0) {
				subop = get_insn_field(insn, 16, 18);
				switch (subop) {
				case 0x00:
					MCInst_setOpcode(MI, HPPA_INS_FID);
					return;
				case 0x06:
					MCInst_setOpcode(MI, HPPA_INS_FNEG);
					return;
				case 0x07:
					MCInst_setOpcode(MI, HPPA_INS_FNEGABS);
					return;
				default:
					break;
				}
			} else if (class == 1) {
				subop = get_insn_field(insn, 14, 16);
				if (subop != 4) {
					MCInst_setOpcode(MI, HPPA_INS_FCNV);
					return;
				}
			} else if (class == 2) {
				if (get_insn_bit(insn, 26) == 0) {
					MCInst_setOpcode(MI, HPPA_INS_FCMP);
				} else {
					MCInst_setOpcode(MI, HPPA_INS_FTEST);
				}
				return;
			}
		}
	}

	if (uid == 0) {
		if (class == 0) {
			subop = get_insn_field(insn, 16, 18);
			switch (subop) {
			case 0x00:
				MCInst_setOpcode(MI, HPPA_INS_COPR);
				return;
			case 0x02:
				MCInst_setOpcode(MI, HPPA_INS_FCPY);
				return;
			case 0x03:
				MCInst_setOpcode(MI, HPPA_INS_FABS);
				return;
			case 0x04:
				MCInst_setOpcode(MI, HPPA_INS_FSQRT);
				return;
			case 0x05:
				MCInst_setOpcode(MI, HPPA_INS_FRND);
				return;
			default:
				break;
			}
		} else if (class == 1) {
			subop = get_insn_field(insn, 15, 16);
			switch (subop) {
			case 0x00:
				MCInst_setOpcode(MI, HPPA_INS_FCNVFF);
				return;
			case 0x01:
				MCInst_setOpcode(MI, HPPA_INS_FCNVXF);
				return;
			case 0x02:
				MCInst_setOpcode(MI, HPPA_INS_FCNVFX);
				return;
			case 0x03:
				MCInst_setOpcode(MI, HPPA_INS_FCNVFXT);
				return;
			default:
				break;
			}
		} else if (class == 2) {
			subop = get_insn_field(insn, 16, 18);
			switch (subop) {
			case 0x00:
				MCInst_setOpcode(MI, HPPA_INS_FCMP);
				return;
			case 0x01:
				MCInst_setOpcode(MI, HPPA_INS_FTEST);
				return;
			default:
				break;
			}
		} else if (class == 3) {
			subop = get_insn_field(insn, 16, 18);
			switch (subop) {
			case 0x00:
				MCInst_setOpcode(MI, HPPA_INS_FADD);
				return;
			case 0x01:
				MCInst_setOpcode(MI, HPPA_INS_FSUB);
				return;
			case 0x02:
				MCInst_setOpcode(MI, HPPA_INS_FMPY);
				return;
			case 0x03:
				MCInst_setOpcode(MI, HPPA_INS_FDIV);
				return;
			default:
				break;
			}
		}
	} else if (uid == 2) {
		subop = get_insn_field(insn, 18, 22);
		switch (subop) {
		case 0x01:
			MCInst_setOpcode(MI, HPPA_INS_PMDIS);
			return;
		case 0x03:
			MCInst_setOpcode(MI, HPPA_INS_PMENB);
			return;
		default:
			break;
		}
	}
	MCInst_setOpcode(MI, HPPA_INS_COPR);
}

static void fill_copr_mods(uint32_t insn, uint32_t uid, uint32_t class,
			   hppa_ext *hppa_ext, uint32_t subop, cs_mode mode)
{
	uint32_t n = get_insn_field(insn, 26, 26);
	uint32_t sf = get_insn_field(insn, 19, 20);
	uint32_t df = get_insn_field(insn, 17, 18);
	if (MODE_IS_HPPA_20(mode)) {
		if (uid == 0) {
			if (class == 0) {
				switch (subop) {
				case 0x00:
					return;
				default:
					break;
				}
			} else if (class == 1) {
				switch (subop) {
				case 0x00:
					push_str_modifier(
						hppa_ext,
						float_format_names[sf]);
					push_str_modifier(
						hppa_ext,
						float_format_names[df]);
					return;
				case 0x01:
					push_str_modifier(hppa_ext,
							  fcnv_fixed_names[sf]);
					push_str_modifier(
						hppa_ext,
						float_format_names[df]);
					return;
				case 0x03:
					push_str_modifier(hppa_ext, "t");
					// fallthrough
				case 0x02:
					push_str_modifier(
						hppa_ext,
						float_format_names[sf]);
					push_str_modifier(hppa_ext,
							  fcnv_fixed_names[df]);
					return;
				case 0x05:
					push_str_modifier(
						hppa_ext,
						fcnv_ufixed_names[sf]);
					push_str_modifier(
						hppa_ext,
						float_format_names[df]);
					return;
				case 0x07:
					push_str_modifier(hppa_ext, "t");
					// fallthrough
				case 0x06:
					push_str_modifier(
						hppa_ext,
						float_format_names[sf]);
					push_str_modifier(
						hppa_ext,
						fcnv_ufixed_names[df]);
					return;
				default:
					break;
				}
			}
		}
	}

	if (uid == 0) {
		if (class == 0) {
			switch (subop) {
			case 0x00:
				push_int_modifier(hppa_ext, 0);
				push_int_modifier(hppa_ext, 0);
				if (n == 1) {
					push_str_modifier(hppa_ext, "n");
				}
				break;
			case 0x02:
			case 0x03:
			case 0x04:
			case 0x05:
			case 0x06:
			case 0x07:
				push_str_modifier(hppa_ext,
						  float_format_names[sf]);
				break;
			default:
				break;
			}
		} else if (class == 1) {
			push_str_modifier(hppa_ext, float_format_names[sf]);
			push_str_modifier(hppa_ext, float_format_names[df]);
		} else if (class == 2) {
			uint32_t cond = get_insn_field(insn, 27, 31);
			if (n == 1 && subop == 1) {
				push_str_modifier(hppa_ext,
						  float_cond_names[cond]);
			}
			if (n == 0) {
				push_str_modifier(hppa_ext,
						  float_format_names[sf]);
				push_str_modifier(hppa_ext,
						  float_comp_names[cond]);
			}
		} else if (class == 3) {
			push_str_modifier(hppa_ext, float_format_names[sf]);
		}
	} else if (uid == 2) {
		if (n == 1) {
			push_str_modifier(hppa_ext, "n");
		}
	} else {
		uid = get_insn_field(insn, 23, 25);
		uint32_t sop = (get_insn_field(insn, 6, 22) << 5) |
			       get_insn_field(insn, 27, 31);
		push_int_modifier(hppa_ext, uid);
		push_int_modifier(hppa_ext, sop);
		if (n == 1) {
			push_str_modifier(hppa_ext, "n");
		}
	}
}

static bool decode_copr(const cs_struct *ud, MCInst *MI, uint32_t insn)
{
	uint32_t class = get_insn_field(insn, 21, 22);
	uint32_t uid = get_insn_field(insn, 23, 25);
	uint32_t subop;
	uint32_t r1 = get_insn_field(insn, 6, 10);
	uint32_t r2 = get_insn_field(insn, 11, 15);
	uint32_t t = get_insn_field(insn, 27, 31);
	if (MODE_IS_HPPA_20(ud->mode)) {
		if (uid == 0) {
			if (class == 0) {
				subop = get_insn_field(insn, 16, 18);
				if (subop == 0x01) {
					return false;
				}
				if (subop >= 0x02) {
					CREATE_FPR_REG(MI, r1);
					CREATE_FPR_REG(MI, t);
				}
			} else if (class == 1) {
				subop = get_insn_field(insn, 14, 16);
				if (subop == 0x04) {
					return false;
				}
				CREATE_FPR_REG(MI, r1);
				CREATE_FPR_REG(MI, t);
			} else if (class == 2) {
				uint32_t n = get_insn_bit(insn, 26);
				subop = get_insn_field(insn, 16, 18);
				if (n == 0) {
					CREATE_FPR_REG(MI, r1);
					CREATE_FPR_REG(MI, r2);
					if (subop != 0) {
						MCOperand_CreateImm0(MI,
								     subop - 1);
						HPPA_EXT_REF(MI)
							->is_alternative = true;
					}
				} else {
					if (subop != 1) {
						MCOperand_CreateImm0(
							MI, (subop ^ 1) - 1);
						HPPA_EXT_REF(MI)
							->is_alternative = true;
					}
				}
			} else {
				subop = get_insn_field(insn, 16, 18);
				if (subop >= 4) {
					return false;
				}
				CREATE_FPR_REG(MI, r1);
				CREATE_FPR_REG(MI, r2);
				CREATE_FPR_REG(MI, t);
			}
			fill_copr_mods(insn, uid, class, HPPA_EXT_REF(MI),
				       subop, ud->mode);
			return true;
		}
	}
	if (uid == 0) {
		if (class == 0) {
			subop = get_insn_field(insn, 16, 18);
			switch (subop) {
			case 0x02:
			case 0x03:
			case 0x04:
			case 0x05:
				CREATE_FPR_REG(MI, r1);
				CREATE_FPR_REG(MI, t);
				// fallthrough
			case 0x00:
				break;
			default:
				return false;
			}
		} else if (class == 1) {
			subop = get_insn_field(insn, 15, 16);
			switch (subop) {
			case 0x00:
			case 0x01:
			case 0x02:
			case 0x03:
				CREATE_FPR_REG(MI, r1);
				CREATE_FPR_REG(MI, t);
				break;
			default:
				return false;
			}
		} else if (class == 2) {
			subop = get_insn_field(insn, 16, 18);
			switch (subop) {
			case 0x00:
				CREATE_FPR_REG(MI, r1);
				CREATE_FPR_REG(MI, r2);
				// fallthrough
			case 0x01:
				break;
			default:
				return false;
			}
		} else {
			subop = get_insn_field(insn, 16, 18);
			switch (subop) {
			case 0x00:
			case 0x01:
			case 0x02:
			case 0x03:
				CREATE_FPR_REG(MI, r1);
				CREATE_FPR_REG(MI, r2);
				CREATE_FPR_REG(MI, t);
				break;
			default:
				return false;
			}
		}
		fill_copr_mods(insn, uid, class, HPPA_EXT_REF(MI), subop,
			       ud->mode);
		return true;
	} else if (uid == 2) {
		subop = get_insn_field(insn, 18, 22);
		switch (subop) {
		case 0x01:
		case 0x03:
			break;
		default:
			return false;
		}
	}
	fill_copr_mods(insn, uid, class, HPPA_EXT_REF(MI), -1, ud->mode);
	return true;
}

static void fill_float_insn_name(MCInst *MI, uint32_t insn)
{
	uint32_t class = get_insn_field(insn, 21, 22);
	uint32_t subop;
	if (MODE_IS_HPPA_20(MI->csh->mode)) {
		if (class == 0) {
			subop = get_insn_field(insn, 16, 18);
			switch (subop) {
			case 0x06:
				MCInst_setOpcode(MI, HPPA_INS_FNEG);
				return;
			case 0x07:
				MCInst_setOpcode(MI, HPPA_INS_FNEGABS);
				return;
			default:
				break;
			}
		} else if (class == 1) {
			subop = get_insn_field(insn, 14, 16);
			if (subop == 0x04) {
				return;
			}
			MCInst_setOpcode(MI, HPPA_INS_FCNV);
			return;
		} else if (class == 2) {
			MCInst_setOpcode(MI, HPPA_INS_FCMP);
			return;
		}
	}
	if (class == 0) {
		subop = get_insn_field(insn, 16, 18);
		switch (subop) {
		case 0x02:
			MCInst_setOpcode(MI, HPPA_INS_FCPY);
			break;
		case 0x03:
			MCInst_setOpcode(MI, HPPA_INS_FABS);
			break;
		case 0x04:
			MCInst_setOpcode(MI, HPPA_INS_FSQRT);
			break;
		case 0x05:
			MCInst_setOpcode(MI, HPPA_INS_FRND);
			break;
		default:
			break;
		}
	} else if (class == 1) {
		subop = get_insn_field(insn, 15, 16);
		switch (subop) {
		case 0x00:
			MCInst_setOpcode(MI, HPPA_INS_FCNVFF);
			break;
		case 0x01:
			MCInst_setOpcode(MI, HPPA_INS_FCNVXF);
			break;
		case 0x02:
			MCInst_setOpcode(MI, HPPA_INS_FCNVFX);
			break;
		case 0x03:
			MCInst_setOpcode(MI, HPPA_INS_FCNVFXT);
			break;
		default:
			break;
		}
	} else if (class == 2) {
		subop = get_insn_field(insn, 16, 18);
		if (subop == 0x00) {
			MCInst_setOpcode(MI, HPPA_INS_FCMP);
		}
	} else if (class == 3) {
		subop = get_insn_field(insn, 16, 18);
		uint32_t fixed = get_insn_field(insn, 23, 23);
		if (fixed == 0) {
			switch (subop) {
			case 0x00:
				MCInst_setOpcode(MI, HPPA_INS_FADD);
				break;
			case 0x01:
				MCInst_setOpcode(MI, HPPA_INS_FSUB);
				break;
			case 0x02:
				MCInst_setOpcode(MI, HPPA_INS_FMPY);
				break;
			case 0x03:
				MCInst_setOpcode(MI, HPPA_INS_FDIV);
				break;
			default:
				break;
			}
		} else {
			if (subop == 0x02) {
				MCInst_setOpcode(MI, HPPA_INS_XMPYU);
			}
		}
	}
}

static void fill_float_mods(uint32_t insn, uint32_t class, hppa_ext *hppa_ext,
			    uint32_t subop, cs_mode mode)
{
	uint32_t sf = get_insn_field(insn, 19, 20);
	uint32_t df = get_insn_field(insn, 17, 18);

	if (MODE_IS_HPPA_20(mode)) {
		if (class == 1) {
			switch (subop) {
			case 0x00:
				push_str_modifier(hppa_ext,
						  float_format_names[sf]);
				push_str_modifier(hppa_ext,
						  float_format_names[df]);
				return;
			case 0x01:
				push_str_modifier(hppa_ext,
						  fcnv_fixed_names[sf]);
				push_str_modifier(hppa_ext,
						  float_format_names[df]);
				return;
			case 0x03:
				push_str_modifier(hppa_ext, "t");
				// fallthrough
			case 0x02:
				push_str_modifier(hppa_ext,
						  float_format_names[sf]);
				push_str_modifier(hppa_ext,
						  fcnv_fixed_names[df]);
				return;
			case 0x05:
				push_str_modifier(hppa_ext,
						  fcnv_ufixed_names[sf]);
				push_str_modifier(hppa_ext,
						  float_format_names[df]);
				return;
			case 0x07:
				push_str_modifier(hppa_ext, "t");
				// fallthrough
			case 0x06:
				push_str_modifier(hppa_ext,
						  float_format_names[sf]);
				push_str_modifier(hppa_ext,
						  fcnv_ufixed_names[df]);
				return;
			default:
				return;
			}
		}
	}

	if (class == 0) {
		uint32_t fmt = get_insn_field(insn, 19, 20);
		push_str_modifier(hppa_ext, float_format_names[fmt]);
	} else if (class == 1) {
		push_str_modifier(hppa_ext, float_format_names[sf]);
		push_str_modifier(hppa_ext, float_format_names[df]);
	} else if (class == 2) {
		uint32_t fmt = get_insn_field(insn, 20, 20);
		uint32_t cond = get_insn_field(insn, 27, 31);
		push_str_modifier(hppa_ext, float_format_names[fmt]);
		push_str_modifier(hppa_ext, float_cond_names[cond]);
	} else if (class == 3) {
		if (get_insn_field(insn, 23, 23) == 0) {
			uint32_t fmt = get_insn_field(insn, 20, 20);
			push_str_modifier(hppa_ext, float_format_names[fmt]);
		}
	}
}

static bool decode_float(const cs_struct *ud, MCInst *MI, uint32_t insn)
{
	uint32_t class = get_insn_field(insn, 21, 22);
	uint32_t subop;
	uint32_t r1 = get_insn_field(insn, 6, 10);
	uint32_t r1_fpe = get_insn_bit(insn, 24);
	uint32_t r2 = get_insn_field(insn, 11, 15);
	uint32_t r2_fpe = get_insn_bit(insn, 19);
	uint32_t t = get_insn_field(insn, 27, 31);
	uint32_t t_fpe = get_insn_bit(insn, 25);
	if (MODE_IS_HPPA_20(ud->mode)) {
		if (class == 0) {
			subop = get_insn_field(insn, 16, 18);
			if (subop >= 0x02) {
				create_float_reg_spec(MI, r1, r1_fpe);
				create_float_reg_spec(MI, t, t_fpe);
				fill_float_mods(insn, class, HPPA_EXT_REF(MI),
						subop, ud->mode);
				return true;
			}
		} else if (class == 1) {
			subop = get_insn_field(insn, 14, 16);
			if (subop == 0x04) {
				return false;
			}
			create_float_reg_spec(MI, r1, r1_fpe);
			create_float_reg_spec(MI, t, t_fpe);
			fill_float_mods(insn, class, HPPA_EXT_REF(MI), subop,
					ud->mode);
			return true;
		} else if (class == 2) {
			subop = get_insn_field(insn, 16, 18);
			create_float_reg_spec(MI, r1, r1_fpe);
			create_float_reg_spec(MI, r2, r2_fpe);
			if (subop != 0) {
				MCOperand_CreateImm0(MI, subop - 1);
			}
			fill_float_mods(insn, class, HPPA_EXT_REF(MI), subop,
					ud->mode);
			return true;
		}
	}
	if (class == 0) {
		subop = get_insn_field(insn, 16, 18);
		switch (subop) {
		case 0x02:
		case 0x03:
		case 0x04:
		case 0x05:
			create_float_reg_spec(MI, r1, r1_fpe);
			create_float_reg_spec(MI, t, t_fpe);
			fill_float_mods(insn, class, HPPA_EXT_REF(MI), subop,
					ud->mode);
			return true;
		default:
			return false;
		}
	} else if (class == 1) {
		subop = get_insn_field(insn, 15, 16);
		if (subop <= 0x03) {
			create_float_reg_spec(MI, r1, r1_fpe);
			create_float_reg_spec(MI, t, t_fpe);
			fill_float_mods(insn, class, HPPA_EXT_REF(MI), subop,
					ud->mode);
			return true;
		}
	} else if (class == 2) {
		subop = get_insn_field(insn, 16, 18);
		switch (subop) {
		case 0x00:
			create_float_reg_spec(MI, r1, r1_fpe);
			create_float_reg_spec(MI, r2, r2_fpe);
			fill_float_mods(insn, class, HPPA_EXT_REF(MI), subop,
					ud->mode);
			return true;
		default:
			return false;
		}
	} else if (class == 3) {
		subop = get_insn_field(insn, 16, 18);
		uint32_t fixed = get_insn_field(insn, 23, 23);
		if ((fixed == 0 && subop <= 0x03) ||
		    (fixed == 1 && subop == 0x02)) {
			create_float_reg_spec(MI, r1, r1_fpe);
			create_float_reg_spec(MI, r2, r2_fpe);
			create_float_reg_spec(MI, t, t_fpe);
			fill_float_mods(insn, class, HPPA_EXT_REF(MI), subop,
					ud->mode);
			return true;
		}
		return false;
	}
	return false;
}

static void fill_fpfused_insn_name(MCInst *MI, uint32_t insn)
{
	uint32_t subop = get_insn_bit(insn, 26);
	if (subop == 0x00) {
		MCInst_setOpcode(MI, HPPA_INS_FMPYFADD);
	} else {
		MCInst_setOpcode(MI, HPPA_INS_FMPYNFADD);
	}
}

static void fill_fpfused_mods(uint32_t insn, hppa_ext *hppa_ext)
{
	uint32_t fmt = get_insn_bit(insn, 20);
	push_str_modifier(hppa_ext, float_format_names[fmt]);
}

static bool decode_fpfused(const cs_struct *ud, MCInst *MI, uint32_t insn)
{
	uint32_t r1 = get_insn_field(insn, 6, 10);
	uint32_t r1_fpe = get_insn_bit(insn, 24);
	uint32_t r2 = get_insn_field(insn, 11, 15);
	uint32_t r2_fpe = get_insn_bit(insn, 19);
	uint32_t ra = (get_insn_field(insn, 16, 18) << 2) |
		      get_insn_field(insn, 21, 22);
	uint32_t ra_fpe = get_insn_bit(insn, 23);
	uint32_t t = get_insn_field(insn, 27, 31);
	uint32_t t_fpe = get_insn_bit(insn, 25);
	create_float_reg_spec(MI, r1, r1_fpe);
	create_float_reg_spec(MI, r2, r2_fpe);
	create_float_reg_spec(MI, ra, ra_fpe);
	create_float_reg_spec(MI, t, t_fpe);
	fill_fpfused_mods(insn, HPPA_EXT_REF(MI));
	return true;
}

static void fill_action_and_branch_insn_name(MCInst *MI, uint32_t opcode)
{
	if (MODE_IS_HPPA_20(MI->csh->mode)) {
		switch (opcode) {
		case HPPA_OP_TYPE_CMPBT:
		case HPPA_OP_TYPE_CMPBF:
		case HPPA_OP_TYPE_CMPBDWT:
		case HPPA_OP_TYPE_CMPBDWF:
			MCInst_setOpcode(MI, HPPA_INS_CMPB);
			return;
		case HPPA_OP_TYPE_CMPIBT:
		case HPPA_OP_TYPE_CMPIBF:
		case HPPA_OP_TYPE_CMPIBDW:
			MCInst_setOpcode(MI, HPPA_INS_CMPIB);
			return;
		case HPPA_OP_TYPE_ADDBT:
		case HPPA_OP_TYPE_ADDBF:
			MCInst_setOpcode(MI, HPPA_INS_ADDB);
			return;
		case HPPA_OP_TYPE_ADDIBT:
		case HPPA_OP_TYPE_ADDIBF:
			MCInst_setOpcode(MI, HPPA_INS_ADDIB);
			return;
		case HPPA_OP_TYPE_BBS:
			MCInst_setOpcode(MI, HPPA_INS_BB);
			return;
		default:
			break;
		}
	}
	switch (opcode) {
	case HPPA_OP_TYPE_CMPBT:
		MCInst_setOpcode(MI, HPPA_INS_COMBT);
		break;
	case HPPA_OP_TYPE_CMPBF:
		MCInst_setOpcode(MI, HPPA_INS_COMBF);
		break;
	case HPPA_OP_TYPE_CMPIBT:
		MCInst_setOpcode(MI, HPPA_INS_COMIBT);
		break;
	case HPPA_OP_TYPE_CMPIBF:
		MCInst_setOpcode(MI, HPPA_INS_COMIBF);
		break;
	case HPPA_OP_TYPE_ADDBT:
		MCInst_setOpcode(MI, HPPA_INS_ADDBT);
		break;
	case HPPA_OP_TYPE_ADDBF:
		MCInst_setOpcode(MI, HPPA_INS_ADDBF);
		break;
	case HPPA_OP_TYPE_ADDIBT:
		MCInst_setOpcode(MI, HPPA_INS_ADDIBT);
		break;
	case HPPA_OP_TYPE_ADDIBF:
		MCInst_setOpcode(MI, HPPA_INS_ADDIBF);
		break;
	case HPPA_OP_TYPE_MOVB:
		MCInst_setOpcode(MI, HPPA_INS_MOVB);
		break;
	case HPPA_OP_TYPE_MOVIB:
		MCInst_setOpcode(MI, HPPA_INS_MOVIB);
		break;
	case HPPA_OP_TYPE_BBS:
		MCInst_setOpcode(MI, HPPA_INS_BVB);
		break;
	case HPPA_OP_TYPE_BB:
		MCInst_setOpcode(MI, HPPA_INS_BB);
		break;
	default:
		break;
	}
}

static void fill_action_and_branch_mods(uint32_t insn, uint32_t opcode,
					hppa_ext *hppa_ext, cs_mode mode)
{
	uint32_t cond = get_insn_field(insn, 16, 18);
	uint32_t n = get_insn_bit(insn, 30);
	uint32_t d = get_insn_bit(insn, 18);

	if (MODE_IS_HPPA_20(mode)) {
		switch (opcode) {
		case HPPA_OP_TYPE_CMPBT:
		case HPPA_OP_TYPE_CMPIBT:
			push_str_modifier(hppa_ext, compare_cond_names[cond]);
			break;
		case HPPA_OP_TYPE_CMPBF:
		case HPPA_OP_TYPE_CMPIBF:
			push_str_modifier(hppa_ext,
					  compare_cond_names[cond + 8]);
			break;
		case HPPA_OP_TYPE_CMPBDWT:
			push_str_modifier(hppa_ext,
					  compare_cond_64_names[cond]);
			break;
		case HPPA_OP_TYPE_CMPBDWF:
			push_str_modifier(hppa_ext,
					  compare_cond_64_names[cond + 8]);
			break;
		case HPPA_OP_TYPE_CMPIBDW:
			push_str_modifier(hppa_ext, cmpib_cond_64_names[cond]);
			break;
		case HPPA_OP_TYPE_ADDBT:
		case HPPA_OP_TYPE_ADDIBT:
			if (MODE_IS_HPPA_20W(mode)) {
				push_str_modifier(hppa_ext,
						  wide_add_cond_names[cond]);
			} else {
				push_str_modifier(hppa_ext,
						  add_cond_names[cond]);
			}
			break;
		case HPPA_OP_TYPE_ADDBF:
		case HPPA_OP_TYPE_ADDIBF:
			if (MODE_IS_HPPA_20W(mode)) {
				push_str_modifier(
					hppa_ext,
					wide_add_cond_names[cond + 8]);
			} else {
				push_str_modifier(hppa_ext,
						  add_cond_names[cond + 8]);
			}
			break;
		case HPPA_OP_TYPE_BBS:
		case HPPA_OP_TYPE_BB:
			if (d == 0) {
				push_str_modifier(hppa_ext,
						  shift_cond_names[cond]);
			} else {
				push_str_modifier(hppa_ext,
						  shift_cond_64_names[cond]);
			}
			break;
		case HPPA_OP_TYPE_MOVB:
		case HPPA_OP_TYPE_MOVIB:
			push_str_modifier(hppa_ext, shift_cond_names[cond]);
			break;
		default:
			break;
		}
		if (n == 1) {
			push_str_modifier(hppa_ext, "n");
		}
		return;
	}
	switch (opcode) {
	case HPPA_OP_TYPE_CMPBT:
	case HPPA_OP_TYPE_CMPBF:
	case HPPA_OP_TYPE_CMPIBT:
	case HPPA_OP_TYPE_CMPIBF:
		push_str_modifier(hppa_ext, compare_cond_names[cond]);
		break;
	case HPPA_OP_TYPE_ADDBT:
	case HPPA_OP_TYPE_ADDBF:
	case HPPA_OP_TYPE_ADDIBT:
	case HPPA_OP_TYPE_ADDIBF:
		push_str_modifier(hppa_ext, add_cond_names[cond]);
		break;
	case HPPA_OP_TYPE_MOVB:
	case HPPA_OP_TYPE_MOVIB:
	case HPPA_OP_TYPE_BBS:
	case HPPA_OP_TYPE_BB:
		push_str_modifier(hppa_ext, shift_cond_names[cond]);
		break;
	default:
		break;
	}
	if (n == 1) {
		push_str_modifier(hppa_ext, "n");
	}
}

static bool fill_action_and_branch(const cs_struct *ud, MCInst *MI,
				   uint32_t insn)
{
	uint32_t opcode = insn >> 26;
	uint32_t r1 = get_insn_field(insn, 6, 10);
	uint32_t r2 = get_insn_field(insn, 11, 15);
	if (MODE_IS_HPPA_20(ud->mode)) {
		switch (opcode) {
		case HPPA_OP_TYPE_CMPBT:
		case HPPA_OP_TYPE_CMPBF:
		case HPPA_OP_TYPE_CMPBDWT:
		case HPPA_OP_TYPE_CMPBDWF:
		case HPPA_OP_TYPE_ADDBT:
		case HPPA_OP_TYPE_ADDBF:
		case HPPA_OP_TYPE_MOVB:
			CREATE_GR_REG(MI, r2);
			CREATE_GR_REG(MI, r1);
			MCOperand_CreateImm0(MI, extract_12(insn));
			break;
		case HPPA_OP_TYPE_CMPIBT:
		case HPPA_OP_TYPE_CMPIBF:
		case HPPA_OP_TYPE_CMPIBDW:
		case HPPA_OP_TYPE_ADDIBT:
		case HPPA_OP_TYPE_ADDIBF:
		case HPPA_OP_TYPE_MOVIB:
			MCOperand_CreateImm0(MI, LowSignExtend64(r2, 5));
			CREATE_GR_REG(MI, r1);
			MCOperand_CreateImm0(MI, extract_12(insn));
			break;
		case HPPA_OP_TYPE_BBS:
		case HPPA_OP_TYPE_BB:
			CREATE_GR_REG(MI, r2);
			if ((opcode & 1) == 1) {
				MCOperand_CreateImm0(MI, r1);
			} else {
				CREATE_CR_REG(MI, 11);
			}
			MCOperand_CreateImm0(MI, extract_12(insn));
			break;
		default:
			return false;
		}
		fill_action_and_branch_mods(insn, opcode, HPPA_EXT_REF(MI),
					    ud->mode);
		return true;
	}
	if ((opcode & 1) == 0 || opcode == HPPA_OP_TYPE_BB) {
		CREATE_GR_REG(MI, r2);
	} else {
		MCOperand_CreateImm0(MI, LowSignExtend64(r2, 5));
	}
	if (opcode == HPPA_OP_TYPE_BB) {
		MCOperand_CreateImm0(MI, r1);
	} else if (opcode != HPPA_OP_TYPE_BBS) {
		CREATE_GR_REG(MI, r1);
	}
	MCOperand_CreateImm0(MI, extract_12(insn));
	fill_action_and_branch_mods(insn, opcode, HPPA_EXT_REF(MI), ud->mode);
	return true;
}

static void fill_load_insn_name(MCInst *MI, uint32_t opcode)
{
	switch (opcode) {
	case HPPA_OP_TYPE_LDB:
		MCInst_setOpcode(MI, HPPA_INS_LDB);
		break;
	case HPPA_OP_TYPE_LDH:
		MCInst_setOpcode(MI, HPPA_INS_LDH);
		break;
	case HPPA_OP_TYPE_LDW:
		MCInst_setOpcode(MI, HPPA_INS_LDW);
		break;
	case HPPA_OP_TYPE_LDWM:
		if (MODE_IS_HPPA_20(MI->csh->mode)) {
			MCInst_setOpcode(MI, HPPA_INS_LDW);
		} else {
			MCInst_setOpcode(MI, HPPA_INS_LDWM);
		}
		break;
	default:
		break;
	}
}

static void fill_store_insn_name(MCInst *MI, uint32_t opcode)
{
	switch (opcode) {
	case HPPA_OP_TYPE_STB:
		MCInst_setOpcode(MI, HPPA_INS_STB);
		break;
	case HPPA_OP_TYPE_STH:
		MCInst_setOpcode(MI, HPPA_INS_STH);
		break;
	case HPPA_OP_TYPE_STW:
		MCInst_setOpcode(MI, HPPA_INS_STW);
		break;
	case HPPA_OP_TYPE_STWM:
		if (MODE_IS_HPPA_20(MI->csh->mode)) {
			MCInst_setOpcode(MI, HPPA_INS_STW);
		} else {
			MCInst_setOpcode(MI, HPPA_INS_STWM);
		}
		break;
	default:
		break;
	}
}

static bool decode_cmpclr(const cs_struct *ud, MCInst *MI, uint32_t insn)
{
	uint32_t cond = (get_insn_bit(insn, 19) << 3) |
			get_insn_field(insn, 16, 18);
	uint32_t d = get_insn_bit(insn, 20);
	if (MODE_IS_HPPA_20(ud->mode)) {
		MCInst_setOpcode(MI, HPPA_INS_CMPICLR);
	} else {
		MCInst_setOpcode(MI, HPPA_INS_COMICLR);
	}

	MCOperand_CreateImm0(MI,
			     LowSignExtend64(get_insn_field(insn, 21, 31), 11));
	CREATE_GR_REG(MI, get_insn_field(insn, 6, 10));
	CREATE_GR_REG(MI, get_insn_field(insn, 11, 15));

	if (d == 0) {
		push_str_modifier(HPPA_EXT_REF(MI), compare_cond_names[cond]);
	} else {
		push_str_modifier(HPPA_EXT_REF(MI),
				  compare_cond_64_names[cond]);
	}
	return true;
}

static bool decode_be(const cs_struct *ud, MCInst *MI, uint32_t insn)
{
	uint32_t opcode = insn >> 26;
	uint32_t n = get_insn_bit(insn, 30);
	bool mode = MODE_IS_HPPA_20(ud->mode);
	if (opcode == HPPA_OP_TYPE_BLE) {
		if (!mode) {
			MCInst_setOpcode(MI, HPPA_INS_BLE);
		} else {
			MCInst_setOpcode(MI, HPPA_INS_BE);
			push_str_modifier(HPPA_EXT_REF(MI), "l");
			HPPA_EXT_REF(MI)->is_alternative = true;
		}
	} else {
		MCInst_setOpcode(MI, HPPA_INS_BE);
	}

	MCOperand_CreateImm0(MI, extract_17(insn));
	CREATE_SR_REG(MI, extract_3(insn));
	CREATE_GR_REG(MI, get_insn_field(insn, 6, 10));
	if (opcode == HPPA_OP_TYPE_BLE && mode) {
		CREATE_SR_REG(MI, 0);
		CREATE_GR_REG(MI, 31);
	}
	if (n == 1) {
		push_str_modifier(HPPA_EXT_REF(MI), "n");
	}
	return true;
}

static bool decode_float_ldst(const cs_struct *ud, MCInst *MI, uint32_t insn)
{
	uint32_t opcode = insn >> 26;
	uint32_t a = get_insn_bit(insn, 29);
	uint32_t disp = extract_16(insn, MODE_IS_HPPA_20W(ud->mode));
	disp &= ~3;

	if (opcode == HPPA_OP_TYPE_FLDW) {
		MCInst_setOpcode(MI, HPPA_INS_FLDW);
		MCOperand_CreateImm0(MI, disp);
		CREATE_SR_REG(MI, get_insn_field(insn, 16, 17));
		CREATE_GR_REG(MI, get_insn_field(insn, 6, 10));
		CREATE_FPR_REG(MI, get_insn_field(insn, 11, 15));
	} else {
		MCInst_setOpcode(MI, HPPA_INS_FSTW);
		CREATE_FPR_REG(MI, get_insn_field(insn, 11, 15));
		MCOperand_CreateImm0(MI, disp);
		CREATE_SR_REG(MI, get_insn_field(insn, 16, 17));
		CREATE_GR_REG(MI, get_insn_field(insn, 6, 10));
	}

	if (a == 0) {
		push_str_modifier(HPPA_EXT_REF(MI), "ma");
	} else {
		push_str_modifier(HPPA_EXT_REF(MI), "mb");
	}
	return true;
}

static bool decode_fmpy(const cs_struct *ud, MCInst *MI, uint32_t insn)
{
	uint32_t opcode = insn >> 26;
	uint32_t rm1 = get_insn_field(insn, 6, 10);
	uint32_t rm2 = get_insn_field(insn, 11, 15);
	uint32_t ta = get_insn_field(insn, 16, 20);
	uint32_t ra = get_insn_field(insn, 21, 25);
	uint32_t tm = get_insn_field(insn, 27, 31);
	uint32_t fmt = get_insn_field(insn, 26, 26);

	if (opcode == HPPA_OP_TYPE_FMPYADD) {
		MCInst_setOpcode(MI, HPPA_INS_FMPYADD);
	} else {
		MCInst_setOpcode(MI, HPPA_INS_FMPYSUB);
	}

	if (fmt == 0) {
		push_str_modifier(HPPA_EXT_REF(MI), "dbl");
		CREATE_FPR_REG(MI, rm1);
		CREATE_FPR_REG(MI, rm2);
		CREATE_FPR_REG(MI, tm);
		CREATE_FPR_REG(MI, ra);
		CREATE_FPR_REG(MI, ta);
	} else {
		push_str_modifier(HPPA_EXT_REF(MI), "sgl");
		CREATE_SP_FPR_REG(MI, rm1);
		CREATE_SP_FPR_REG(MI, rm2);
		CREATE_SP_FPR_REG(MI, tm);
		CREATE_SP_FPR_REG(MI, ra);
		CREATE_SP_FPR_REG(MI, ta);
	}

	return true;
}

static bool decode_load(const cs_struct *ud, MCInst *MI, uint32_t insn)
{
	uint32_t opcode = insn >> 26;
	if (MODE_IS_HPPA_20(ud->mode)) {
		int32_t d = extract_16(insn, MODE_IS_HPPA_20W(ud->mode));
		if (opcode == HPPA_OP_TYPE_LDWM) {
			if (d < 0) {
				push_str_modifier(HPPA_EXT_REF(MI), "mb");
			} else {
				push_str_modifier(HPPA_EXT_REF(MI), "ma");
			}
		}
		MCOperand_CreateImm0(MI, d);
	} else {
		MCOperand_CreateImm0(MI, extract_14(insn));
	}
	CREATE_SR_REG(MI, get_insn_field(insn, 16, 17));
	CREATE_GR_REG(MI, get_insn_field(insn, 6, 10));
	CREATE_GR_REG(MI, get_insn_field(insn, 11, 15));
	return true;
}

static bool decode_store(const cs_struct *ud, MCInst *MI, uint32_t insn)
{
	uint32_t opcode = insn >> 26;
	CREATE_GR_REG(MI, get_insn_field(insn, 11, 15));
	if (MODE_IS_HPPA_20(ud->mode)) {
		int d = extract_16(insn, MODE_IS_HPPA_20W(ud->mode));
		if (opcode == HPPA_OP_TYPE_STWM) {
			if (d < 0) {
				push_str_modifier(HPPA_EXT_REF(MI), "mb");
			} else {
				push_str_modifier(HPPA_EXT_REF(MI), "ma");
			}
		}
		MCOperand_CreateImm0(MI, d);
	} else {
		MCOperand_CreateImm0(MI, extract_14(insn));
	}
	CREATE_SR_REG(MI, get_insn_field(insn, 16, 17));
	CREATE_GR_REG(MI, get_insn_field(insn, 6, 10));
	return true;
}

static bool getInstruction(const cs_struct *ud, const uint8_t *code,
			   size_t code_len, MCInst *MI)
{
	if (code_len < 4)
		return false;

	MCInst_clear(MI);

	uint32_t full_insn = readBytes32(MI, code);
	uint8_t opcode = full_insn >> 26;

	if (MODE_IS_HPPA_20(ud->mode)) {
		switch (opcode) {
		case HPPA_OP_TYPE_LOADDW:
		case HPPA_OP_TYPE_STOREDW:
			fill_ldst_dw_insn_name(MI, full_insn);
			return decode_ldst_dw(ud, MI, full_insn);
		case HPPA_OP_TYPE_LOADW:
		case HPPA_OP_TYPE_STOREW:
			fill_ldst_w_insn_name(MI, full_insn);
			return decode_ldst_w(ud, MI, full_insn);
		case HPPA_OP_TYPE_SHEXDEP2:
			MCInst_setOpcode(MI, HPPA_INS_EXTRD);
			return decode_shexdep2(MI, full_insn);
		case HPPA_OP_TYPE_SHEXDEP3:
		case HPPA_OP_TYPE_SHEXDEP4:
			return decode_shexdep3(ud, MI, full_insn);
		case HPPA_OP_TYPE_MULTMED:
			fill_multmed_insn_name(MI, full_insn);
			return decode_multmed(MI, full_insn);
		case HPPA_OP_TYPE_FPFUSED:
			fill_fpfused_insn_name(MI, full_insn);
			return decode_fpfused(ud, MI, full_insn);
		case HPPA_OP_TYPE_FLDW:
		case HPPA_OP_TYPE_FSTW:
			return decode_float_ldst(ud, MI, full_insn);
		case HPPA_OP_TYPE_CMPBDWT:
		case HPPA_OP_TYPE_CMPBDWF:
		case HPPA_OP_TYPE_CMPIBDW:
			fill_action_and_branch_insn_name(MI, opcode);
			return fill_action_and_branch(ud, MI, full_insn);
		default:
			break;
		}
	}

	switch (opcode) {
	case HPPA_OP_TYPE_SYSOP:
		fill_sysop_insn_name(MI, full_insn);
		return decode_sysop(ud, MI, full_insn);
	case HPPA_OP_TYPE_MEMMGMT:
		fill_memmgmt_insn_name(MI, full_insn);
		return decode_memmgmt(ud, MI, full_insn);
	case HPPA_OP_TYPE_ALU:
		fill_alu_insn_name(MI, full_insn);
		return decode_alu(ud, MI, full_insn);
	case HPPA_OP_TYPE_IDXMEM:
		fill_idxmem_insn_name(MI, full_insn);
		return decode_idxmem(ud, MI, full_insn);
	case HPPA_OP_TYPE_ADDIT:
	case HPPA_OP_TYPE_ADDI:
	case HPPA_OP_TYPE_SUBI:
		fill_arith_imm_insn_name(MI, full_insn);
		return decode_arith_imm(ud, MI, full_insn);
	case HPPA_OP_TYPE_SHEXDEP0:
		fill_shexdep0_insn_name(MI, full_insn);
		return decode_shexdep0(ud, MI, full_insn);
	case HPPA_OP_TYPE_SHEXDEP1:
		fill_shexdep1_insn_name(MI, full_insn);
		return decode_shexdep1(ud, MI, full_insn);
	case HPPA_OP_TYPE_BRANCH:
		fill_branch_insn_name(MI, full_insn);
		return decode_branch(ud, MI, full_insn);
	case HPPA_OP_TYPE_COPRW:
	case HPPA_OP_TYPE_COPRDW:
		fill_corpdw_insn_name(MI, full_insn);
		return decode_corpdw(ud, MI, full_insn);
	case HPPA_OP_TYPE_SPOP:
		fill_spop_insn_name(MI, full_insn);
		return decode_spop(ud, MI, full_insn);
	case HPPA_OP_TYPE_COPR:
		fill_copr_insn_name(MI, full_insn);
		return decode_copr(ud, MI, full_insn);
	case HPPA_OP_TYPE_FLOAT:
		fill_float_insn_name(MI, full_insn);
		return decode_float(ud, MI, full_insn);
	case HPPA_OP_TYPE_DIAG:
		MCInst_setOpcode(MI, HPPA_INS_DIAG);
		MCOperand_CreateImm0(MI, get_insn_field(full_insn, 6, 31));
		return true;
	case HPPA_OP_TYPE_FMPYADD:
	case HPPA_OP_TYPE_FMPYSUB:
		return decode_fmpy(ud, MI, full_insn);
	case HPPA_OP_TYPE_LDIL:
	case HPPA_OP_TYPE_ADDIL:
		if (opcode == HPPA_OP_TYPE_LDIL) {
			MCInst_setOpcode(MI, HPPA_INS_LDIL);
		} else {
			MCInst_setOpcode(MI, HPPA_INS_ADDIL);
		}
		MCOperand_CreateImm0(MI, extract_21(full_insn));
		CREATE_GR_REG(MI, get_insn_field(full_insn, 6, 10));
		return true;
	case HPPA_OP_TYPE_LDO:
		MCInst_setOpcode(MI, HPPA_INS_LDO);
		if (MODE_IS_HPPA_20(ud->mode)) {
			MCOperand_CreateImm0(
				MI, extract_16(full_insn,
					       MODE_IS_HPPA_20W(ud->mode)));
		} else {
			MCOperand_CreateImm0(MI, extract_14(full_insn));
		}
		CREATE_GR_REG(MI, get_insn_field(full_insn, 6, 10));
		CREATE_GR_REG(MI, get_insn_field(full_insn, 11, 15));
		return true;
	case HPPA_OP_TYPE_LDB:
	case HPPA_OP_TYPE_LDH:
	case HPPA_OP_TYPE_LDW:
	case HPPA_OP_TYPE_LDWM:
		fill_load_insn_name(MI, opcode);
		return decode_load(ud, MI, full_insn);
	case HPPA_OP_TYPE_STB:
	case HPPA_OP_TYPE_STH:
	case HPPA_OP_TYPE_STW:
	case HPPA_OP_TYPE_STWM:
		fill_store_insn_name(MI, opcode);
		return decode_store(ud, MI, full_insn);
	case HPPA_OP_TYPE_CMPBT:
	case HPPA_OP_TYPE_CMPBF:
	case HPPA_OP_TYPE_ADDBT:
	case HPPA_OP_TYPE_ADDBF:
	case HPPA_OP_TYPE_MOVB:
	case HPPA_OP_TYPE_CMPIBT:
	case HPPA_OP_TYPE_CMPIBF:
	case HPPA_OP_TYPE_ADDIBT:
	case HPPA_OP_TYPE_ADDIBF:
	case HPPA_OP_TYPE_MOVIB:
	case HPPA_OP_TYPE_BBS:
	case HPPA_OP_TYPE_BB:
		fill_action_and_branch_insn_name(MI, opcode);
		return fill_action_and_branch(ud, MI, full_insn);
	case HPPA_OP_TYPE_CMPICLR:
		return decode_cmpclr(ud, MI, full_insn);
	case HPPA_OP_TYPE_BE:
	case HPPA_OP_TYPE_BLE:
		return decode_be(ud, MI, full_insn);
	default:
		return false;
	}
}

void init_details(MCInst *MI)
{
	cs_detail *detail = get_detail(MI);
	if (detail) {
		memset(detail, 0, offsetof(cs_detail, hppa) + sizeof(cs_hppa));
	}
}

bool HPPA_getInstruction(csh ud, const uint8_t *code, size_t code_len,
			 MCInst *instr, uint16_t *size, uint64_t address,
			 void *info)
{
	cs_struct *cs = (cs_struct *)ud;
	init_details(instr);
	if (!getInstruction(cs, code, code_len, instr)) {
		*size = 0;
		return false;
	}
	*size = 4;
	return true;
}

#endif

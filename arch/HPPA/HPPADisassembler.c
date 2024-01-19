/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev  <sibirtsevdl@gmail.com>, 2023 */

#ifdef CAPSTONE_HAS_HPPA

#include <string.h>
#include <stddef.h> // offsetof macro
#include <stdio.h>
#include "HPPADisassembler.h"
#include "HPPAConstants.h"

#include "../../Mapping.h"

#define CODE_TO_INSN(code) \
    (code[0] << 24) | (code[1] << 16) | (code[2] << 8) | code[3]

#define GET_FIELD(X, FROM, TO) \
  ((X) >> (31 - (TO)) & ((1 << ((TO) - (FROM) + 1)) - 1))

#define GET_BIT(X, WHICH) \
  GET_FIELD (X, WHICH, WHICH)

static const char *const compare_cond_names[] =
{
  "", "=", "<", "<=", "<<", "<<=", "sv", "od",
  "tr", "<>", ">=", ">", ">>=", ">>", "nsv", "ev"
};
static const char *const compare_cond_64_names[] =
{
  "*", "*=", "*<", "*<=", "*<<", "*<<=", "*sv", "*od",
  "*tr", "*<>", "*>=", "*>", "*>>=", "*>>", "*nsv", "*ev"
};
static const char *const cmpib_cond_64_names[] =
{
  "*<<", "*=", "*<", "*<=", "*>>=", "*<>", "*>=", "*>"
};
static const char *const add_cond_names[] =
{
  "", "=", "<", "<=", "nuv", "znv", "sv", "od",
  "tr", "<>", ">=", ">", "uv", "vnz", "nsv", "ev"
};
static const char *const add_cond_64_names[] =
{
  "*", "*=", "*<", "*<=", "*nuv", "*znv", "*sv", "*od",
  "*tr", "*<>", "*>=", "*>", "*uv", "*vnz", "*nsv", "*ev"
};
static const char *const wide_add_cond_names[] =
{
  "*", "=", "<", "<=", "nuv", "*=", "*<", "*<=",
  "tr", "<>", ">=", ">", "uv", "*<>", "*>=", "*>"
};
static const char *const logical_cond_names[] =
{
  "", "=", "<", "<=", "", "", "", "od",
  "tr", "<>", ">=", ">", "", "", "", "ev"};
static const char *const logical_cond_64_names[] =
{
  "*", "*=", "*<", "*<=", "", "", "", "*od",
  "*tr", "*<>", "*>=", "*>", "", "", "", "*ev"};
static const char *const unit_cond_names[] =
{
  "", "swz", "sbz", "shz", "sdc", "swc", "sbc", "shc",
  "tr", "nwz", "nbz", "nhz", "ndc", "nwc", "nbc", "nhc"
};
static const char *const unit_cond_64_names[] =
{
  "*", "*swz", "*sbz", "*shz", "*sdc", "*swc", "*sbc", "*shc",
  "*tr", "*nwz", "*nbz", "*nhz", "*ndc", "*nwc", "*nbc", "*nhc"
};
static const char *const shift_cond_names[] =
{
  "", "=", "<", "od", "tr", "<>", ">=", "ev"
};
static const char *const shift_cond_64_names[] =
{
  "*", "*=", "*<", "*od", "*tr", "*<>", "*>=", "*ev"
};
static const char *const bb_cond_64_names[] =
{
  "*<", "*>="
};
static const char *const index_compl_names[] = {"", "m", "s", "sm"};
static const char *const short_ldst_compl_names[] = {"", "ma", "", "mb"};
static const char *const short_bytes_compl_names[] =
{
  "", "b,m", "e", "e,m"
};
static const char *const float_format_names[] = {"sgl", "dbl", "", "quad"};
static const char *const float_cond_names[] = 
{
    "", "acc", "rej", "", "", "acc8", "rej8", "", 
    "", "acc6", "",    "", "", "acc4", "",      "", 
    "", "acc2", "",    "", "", "",      "",      "",
    "", "",      "",    "", "", "",      "",      ""
};
static const char *const fcnv_fixed_names[] = {"w", "dw", "", "qw"};
static const char *const fcnv_ufixed_names[] = {"uw", "udw", "", "uqw"};
static const char *const float_comp_names[] =
{
  "false?", "false", "?", "!<=>", "=", "=t", "?=", "!<>",
  "!?>=", "<", "?<", "!>=", "!?>", "<=", "?<=", "!>",
  "!?<=", ">", "?>", "!<=", "!?<", ">=", "?>=", "!<",
  "!?=", "<>", "!=", "!=t", "!?", "<=>", "true?", "true"
};
static const char *const signed_unsigned_names[] = {"u", "s"};
static const char *const mix_half_names[] = {"l", "r"};
static const char *const saturation_names[] = {"us", "ss", "", ""};
static const char *const read_write_names[] = {"r", "w"};
static const char *const add_compl_names[] = { "", "", "l", "tsv" };

#define CREATE_GR_REG(MI, gr)       MCOperand_CreateReg0(MI, gr + HPPA_REG_GR0)
#define CREATE_SR_REG(MI, sr)       MCOperand_CreateReg0(MI, sr + HPPA_REG_SR0)
#define CREATE_CR_REG(MI, cr)       MCOperand_CreateReg0(MI, cr + HPPA_REG_CR0)
#define CREATE_FPR_REG(MI, fpr)     MCOperand_CreateReg0(MI, fpr + HPPA_REG_FPR0)
#define CREATE_FPE_REG(MI, fpe)     MCOperand_CreateReg0(MI, fpe + HPPA_REG_FPE0)
#define CREATE_DBAOR_REG(MI, dbaor) MCOperand_CreateReg0(MI, dbaor + HPPA_REG_DBAOR0)
#define CREATE_IBAOR_REG(MI, ibaor) MCOperand_CreateReg0(MI, ibaor + HPPA_REG_IBAOR0)

static void create_float_reg_spec(MCInst *MI, uint32_t reg, uint32_t fpe_flag) {
    if (fpe_flag == 1) {
        CREATE_FPE_REG(MI, reg);
    }
    else {
        CREATE_FPR_REG(MI, reg);
    }
}

/* The PA instruction set variants.  */
enum pa_arch { pa10 = 1 << 1, pa11 = 1 << 2, pa20 = 1 << 3, pa20w = 1 << 4 };

static inline int sign_extend(int x, int len)
{
    int signbit = (1 << (len - 1));
    int mask = (signbit << 1) - 1;
    return ((x & mask) ^ signbit) - signbit;
}

static inline int low_sign_extend(int x, int len)
{
    return (x >> 1) - ((x & 1) << (len - 1));
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
    return GET_FIELD(word, 18, 18) << 2 | GET_FIELD(word, 16, 17);
}

static int extract_5_load(unsigned word)
{
    return low_sign_extend(word >> 16 & MASK_5, 5);
}

/* Extract the immediate field from a st{bhw}s instruction.  */

static int extract_5_store(unsigned word)
{
    return low_sign_extend(word & MASK_5, 5);
}

/* Extract the immediate field from a break instruction.  */

static unsigned extract_5r_store(unsigned word)
{
    return (word & MASK_5);
}

/* Extract the immediate field from a {sr}sm instruction.  */

static unsigned extract_5R_store(unsigned word)
{
    return (word >> 16 & MASK_5);
}

/* Extract the 10 bit immediate field from a {sr}sm instruction.  */

static unsigned extract_10U_store(unsigned word)
{
    return (word >> 16 & MASK_10);
}

/* Extract the immediate field from a bb instruction.  */

static unsigned extract_5Q_store(unsigned word)
{
    return (word >> 21 & MASK_5);
}

/* Extract an 11 bit immediate field.  */

static int extract_11(unsigned word)
{
    return low_sign_extend(word & MASK_11, 11);
}

/* Extract a 14 bit immediate field.  */

static int extract_14(unsigned word)
{
    return low_sign_extend(word & MASK_14, 14);
}

/* Extract a 16 bit immediate field (PA2.0 wide only).  */

static int extract_16(unsigned word)
{
    int m15, m0, m1;

    m0 = GET_BIT(word, 16);
    m1 = GET_BIT(word, 17);
    m15 = GET_BIT(word, 31);
    word = (word >> 1) & 0x1fff;
    word = word | (m15 << 15) | ((m15 ^ m0) << 14) | ((m15 ^ m1) << 13);
    return sign_extend(word, 16);
}

/* Extract a 21 bit constant.  */

static int extract_21(unsigned word)
{
    int val;

    word &= MASK_21;
    word <<= 11;
    val = GET_FIELD(word, 20, 20);
    val <<= 11;
    val |= GET_FIELD(word, 9, 19);
    val <<= 2;
    val |= GET_FIELD(word, 5, 6);
    val <<= 5;
    val |= GET_FIELD(word, 0, 4);
    val <<= 2;
    val |= GET_FIELD(word, 7, 8);
    return sign_extend(val, 21) << 11;
}

/* Extract a 12 bit constant from branch instructions.  */

static int extract_12(unsigned word)
{
    return sign_extend(GET_FIELD(word, 19, 28) |
                   GET_FIELD(word, 29, 29) << 10 |
                   (word & 0x1) << 11,
               12)
           << 2;
}

/* Extract a 17 bit constant from branch instructions, returning the
   19 bit signed value.  */

static int extract_17(unsigned word)
{
    return sign_extend(GET_FIELD(word, 19, 28) |
                   GET_FIELD(word, 29, 29) << 10 |
                   GET_FIELD(word, 11, 15) << 11 |
                   (word & 0x1) << 16,
               17)
           << 2;
}

static int extract_22(unsigned word)
{
    return sign_extend(GET_FIELD(word, 19, 28) |
                   GET_FIELD(word, 29, 29) << 10 |
                   GET_FIELD(word, 11, 15) << 11 |
                   GET_FIELD(word, 6, 10) << 16 |
                   (word & 0x1) << 21,
               22)
           << 2;
}

static void push_str_modifier(hppa_ext *hppa, const char *modifier)
{
    if (modifier != "") {
        hppa_modifier *mod = &hppa->modifiers[hppa->mod_num++];
        mod->type = 0;
        mod->str_mod = (char *)modifier;
    }
}

static void push_int_modifier(hppa_ext *hppa, uint64_t modifier)
{
    hppa_modifier *mod = &hppa->modifiers[hppa->mod_num++];
    mod->type = 1;
    mod->int_mod = modifier;
}

static void fillSysopInsnName(MCInst *MI, uint32_t insn) {
    uint32_t ext8 = GET_FIELD(insn, 19, 26);
    uint32_t ext5 = GET_FIELD(insn, 11, 15);
    switch (ext8) {
    case 0x00:
        MCInst_setOpcode(MI, HPPA_INS_BREAK);
        break;
    case 0x20:
        if (ext5 == 0x00) {
            MCInst_setOpcode(MI, HPPA_INS_SYNC);
        }
        else if (ext5 == 0x10) {
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
        break;
    }
}

static bool decodeSysop(cs_struct *ud, MCInst *MI, uint32_t insn) {
    uint32_t ext8 = GET_FIELD(insn, 19, 26);
    switch (ext8) {
    case 0x00:
        MCOperand_CreateImm0(MI, GET_FIELD(insn, 27, 31));
        MCOperand_CreateImm0(MI, GET_FIELD(insn, 6, 18));
    case 0x20:
    case 0x60:
    case 0x65:
        return true;
    case 0x6b:
    case 0x73:
        MCOperand_CreateImm0(MI, GET_FIELD(insn, 9, 15));
        CREATE_GR_REG(MI, GET_FIELD(insn, 27, 31));
        return true;
    case 0xc3:
        CREATE_GR_REG(MI, GET_FIELD(insn, 11, 15));
        return true;
    case 0x85:
        CREATE_SR_REG(MI, GET_FIELD(insn, 16, 17));
        CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
        CREATE_GR_REG(MI, GET_FIELD(insn, 27, 31));
        return true;
    case 0xc1:
        CREATE_GR_REG(MI, GET_FIELD(insn, 11, 15));
        CREATE_SR_REG(MI, extract_3(insn));
        return true;
    case 0x25:
        CREATE_SR_REG(MI, extract_3(insn));
        CREATE_GR_REG(MI, GET_FIELD(insn, 27, 31));
        return true;
    case 0xc2:
        CREATE_GR_REG(MI, GET_FIELD(insn, 11, 15));
        CREATE_CR_REG(MI, GET_FIELD(insn, 6, 10));
        return true;
    case 0x45:
        CREATE_CR_REG(MI, GET_FIELD(insn, 6, 10));
        CREATE_GR_REG(MI, GET_FIELD(insn, 27, 31));
        return true;
    default:
        return false;
    }
}

static void fillMemmgmtInsnName(MCInst *MI, uint32_t insn) {
    uint32_t ext = GET_FIELD(insn, 22, 25);
    if (GET_FIELD(insn, 19, 19) == 0) {
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
        }
    } 
    else {
        switch (ext) {
        case 0x00:
            MCInst_setOpcode(MI, HPPA_INS_IDTLBP);
            break;
        case 0x01:
            MCInst_setOpcode(MI, HPPA_INS_IDTLBA);
            break;
        case 0x08:
            MCInst_setOpcode(MI, HPPA_INS_PDTLB);
            break;
        case 0x09:
            MCInst_setOpcode(MI, HPPA_INS_PDTLBE);
            break;
        case 0x0a:
            MCInst_setOpcode(MI, HPPA_INS_FDC);
            break;
        case 0x0b:
            MCInst_setOpcode(MI, HPPA_INS_FDCE);
            break;
        case 0x0e:
            MCInst_setOpcode(MI, HPPA_INS_PDC);
            break;
        case 0x06:
            if (GET_FIELD(insn, 18, 18) == 0) {
                MCInst_setOpcode(MI, HPPA_INS_PROBER);
            }
            else {
                MCInst_setOpcode(MI, HPPA_INS_PROBERI);
            };
            break;
        case 0x07:
            if (GET_FIELD(insn, 18, 18) == 0) {
                MCInst_setOpcode(MI, HPPA_INS_PROBEW);
            }
            else {
                MCInst_setOpcode(MI, HPPA_INS_PROBEWI);
            };
            break;
        case 0x0d:
            MCInst_setOpcode(MI, HPPA_INS_LPA);
            break;
        case 0x0c:
            MCInst_setOpcode(MI, HPPA_INS_LCI);
            break;
        }
    }
}

static void fillMemmgmtMods(uint32_t insn, uint32_t ext, hppa_ext* hppa_ext) {
    uint8_t cmplt = GET_FIELD(insn, 26, 26);
    switch (ext)
    {
    case 0x08:
    case 0x09:
    case 0x0a:
    case 0x0b:
    case 0x0e:
    case 0x0d:
        if (cmplt == 1 || cmplt == 3) {
            hppa_ext->b_writeble = true;
        }
        push_str_modifier(hppa_ext, index_compl_names[cmplt]);
        break;
    default:
        break;
    }
} 

static bool decodeMemmgmt(cs_struct *ud, MCInst *MI, uint32_t insn) { 
    uint32_t ext = GET_FIELD(insn, 22, 25);
    if (GET_FIELD(insn, 19, 19) == 0) {
        switch (ext) {
        case 0x00:
        case 0x01:
        case 0x08:
        case 0x09:
        case 0x0a:
        case 0x0b:
            CREATE_GR_REG(MI, GET_FIELD(insn, 11, 15));
            CREATE_SR_REG(MI, extract_3(insn));
            CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
            fillMemmgmtMods(insn, ext, &MI->hppa_ext);
            return true;
        default:
            return false;
        }
    } 
    else {
        switch (ext) {
        case 0x00:
        case 0x01:
        case 0x08:
        case 0x09:
        case 0x0a:
        case 0x0b:
        case 0x0e:
            CREATE_GR_REG(MI, GET_FIELD(insn, 11, 15));
            CREATE_SR_REG(MI, GET_FIELD(insn, 16, 17));
            CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
            fillMemmgmtMods(insn, ext, &MI->hppa_ext);
            return true;
        case 0x06:
        case 0x07:
            CREATE_SR_REG(MI, GET_FIELD(insn, 16, 17));
            CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
            if (GET_FIELD(insn, 18, 18) == 0) {
                CREATE_GR_REG(MI, GET_FIELD(insn, 11, 15));
            } else {
                MCOperand_CreateImm0(MI, GET_FIELD(insn, 11, 15));
            }
            CREATE_GR_REG(MI, GET_FIELD(insn, 27, 31));
            return true;
        case 0x0d:
        case 0x0c:
            CREATE_GR_REG(MI, GET_FIELD(insn, 11, 15));
            CREATE_SR_REG(MI, GET_FIELD(insn, 16, 17));
            CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
            CREATE_GR_REG(MI, GET_FIELD(insn, 27, 31));
            fillMemmgmtMods(insn, ext, &MI->hppa_ext);
            return true;
        default:
            return false;
        }
    }
}

static void fillAluInsnName(MCInst *MI, uint32_t insn) {
    uint32_t ext = GET_FIELD(insn, 20, 25);
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
    }    
}

static void fillAluMods(uint32_t insn, uint32_t ext, hppa_ext* hppa_ext) {
    uint32_t cond = (GET_FIELD(insn, 19, 19) << 3) | GET_FIELD(insn, 16, 18);
    switch (ext)
    {
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

static bool decodeAlu(cs_struct *ud, MCInst *MI, uint32_t insn) {
    uint32_t ext = GET_FIELD(insn, 20, 25);
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
        CREATE_GR_REG(MI, GET_FIELD(insn, 11, 15));
        CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
        CREATE_GR_REG(MI, GET_FIELD(insn, 27, 31));
        fillAluMods(insn, ext, &MI->hppa_ext);
        return true;
    case 0x2e:    
    case 0x2f:
        CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
        CREATE_GR_REG(MI, GET_FIELD(insn, 27, 31));
        fillAluMods(insn, ext, &MI->hppa_ext);
        return true;
    default:
        return false;
    }
}

static void fillIdxmemInsnName(MCInst *MI, uint32_t insn) {
    uint32_t ext = GET_FIELD(insn, 22, 25);
    if (GET_FIELD(insn, 19, 19) == 0) {
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
        }
    }
    else {
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
        }
    }    
}

static void fillIdxmemMods(uint32_t insn, uint32_t ext, hppa_ext* hppa_ext) {
    uint32_t cmplt = (GET_FIELD(insn, 18, 18) << 1) | GET_FIELD(insn, 26, 26);
    uint32_t cc = GET_FIELD(insn, 20, 21);
    if (GET_FIELD(insn, 19, 19) == 0) {
        switch (ext) {
        case 0x00:
        case 0x01:
        case 0x02:
        case 0x06:
            if (cmplt == 1 || cmplt == 3) {
               hppa_ext->b_writeble = true;
            }
            push_str_modifier(hppa_ext, index_compl_names[cmplt]);
            if (cc == 2) {
                push_str_modifier(hppa_ext, "sl");
            }
            break;
        case 0x07:
            if (cmplt == 1 || cmplt == 3) {
               hppa_ext->b_writeble = true;
            }
            push_str_modifier(hppa_ext, index_compl_names[cmplt]);
            if (cc == 1) {
                push_str_modifier(hppa_ext, "co");
            }
            break;
        default:
            break;
        }
    }
    else {
        switch (ext) {
        case 0x00:
        case 0x01:
        case 0x02:
        case 0x06:
            if (cmplt == 1 || cmplt == 3) {
                hppa_ext->b_writeble = true;
            }
            push_str_modifier(hppa_ext, short_ldst_compl_names[cmplt]);
            if (cc == 2) {
                push_str_modifier(hppa_ext, "sl");
            }
            break;
        case 0x07:
            if (cmplt == 1 || cmplt == 3) {
                hppa_ext->b_writeble = true;
            }
            push_str_modifier(hppa_ext, short_ldst_compl_names[cmplt]);
            if (cc == 1) {
                push_str_modifier(hppa_ext, "co");
            } 
            break;           
        case 0x08:
        case 0x09:
        case 0x0a:
        case 0x0e:
            if (cmplt == 1 || cmplt == 3) {
                hppa_ext->b_writeble = true;
            }
            push_str_modifier(hppa_ext, short_ldst_compl_names[cmplt]);
            if (cc == 1) {
                push_str_modifier(hppa_ext, "bc");
            }
            else if (cc == 2) {
                push_str_modifier(hppa_ext, "sl");
            }
            break;
        case 0x0c:
            if (cmplt == 1 || cmplt == 3) {
                hppa_ext->b_writeble = true;
            }
            push_str_modifier(hppa_ext, short_bytes_compl_names[cmplt]);
            if (cc == 1) {
                push_str_modifier(hppa_ext, "bc");
            }
            else if (cc == 2) {
                push_str_modifier(hppa_ext, "sl");
            }
            break;
        default:
            break;
        }
    }
}

static bool decodeIdxmem(cs_struct *ud, MCInst *MI, uint32_t insn) {
    uint32_t ext = GET_FIELD(insn, 22, 25);
    if (GET_FIELD(insn, 19, 19) == 0) {
        switch (ext) {
        case 0x00:
        case 0x01:
        case 0x02:
        case 0x07:
            CREATE_GR_REG(MI, GET_FIELD(insn, 11, 15));
            CREATE_SR_REG(MI, GET_FIELD(insn, 16, 17));
            CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
            CREATE_GR_REG(MI, GET_FIELD(insn, 27, 31));
            fillIdxmemMods(insn, ext, &MI->hppa_ext);
            return true;
        case 0x06:
            CREATE_GR_REG(MI, GET_FIELD(insn, 11, 15));
            CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
            CREATE_GR_REG(MI, GET_FIELD(insn, 27, 31));
            fillIdxmemMods(insn, ext, &MI->hppa_ext);
            return true;
        default:
            return false;
        }
    }
    else {
        switch (ext) {
        case 0x00:
        case 0x01:
        case 0x02:
        case 0x07:
            MCOperand_CreateImm0(MI, low_sign_extend(GET_FIELD(insn, 11, 15), 5));
            CREATE_SR_REG(MI, GET_FIELD(insn, 16, 17));
            CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
            CREATE_GR_REG(MI, GET_FIELD(insn, 27, 31));     
            fillIdxmemMods(insn, ext, &MI->hppa_ext);
            return true;
        case 0x06:
            MCOperand_CreateImm0(MI, low_sign_extend(GET_FIELD(insn, 11, 15), 5));
            CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
            CREATE_GR_REG(MI, GET_FIELD(insn, 27, 31)); 
            fillIdxmemMods(insn, ext, &MI->hppa_ext);
            return true;
        case 0x08:
        case 0x09:
        case 0x0a:
        case 0x0c:
            CREATE_GR_REG(MI, GET_FIELD(insn, 11, 15));
            MCOperand_CreateImm0(MI, low_sign_extend(GET_FIELD(insn, 27, 31), 5));
            CREATE_SR_REG(MI, GET_FIELD(insn, 16, 17));
            CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
            fillIdxmemMods(insn, ext, &MI->hppa_ext);
            return true;
        case 0x0e:
            CREATE_GR_REG(MI, GET_FIELD(insn, 11, 15));
            MCOperand_CreateImm0(MI, low_sign_extend(GET_FIELD(insn, 27, 31), 5));
            CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
            fillIdxmemMods(insn, ext, &MI->hppa_ext);
            return true;
        default:
            return false;
        }
    }
}

static void fillArithImmInsnName(MCInst *MI, uint32_t insn) {
    uint32_t opcode = insn >> 26;
    if (GET_FIELD(insn, 20, 20) == 0) {
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
        }
    }
    else {
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
        }
    }

}

static void fillArithImmMods(uint32_t insn, hppa_ext* hppa_ext) {
    uint32_t opcode = insn >> 26;
    uint32_t cond = (GET_FIELD(insn, 19, 19) << 3) | GET_FIELD(insn, 16, 18);
    switch (opcode) {
    case 0x2d:
    case 0x2c:
        push_str_modifier(hppa_ext, add_cond_names[cond]);
        break;
    case 0x25:
        push_str_modifier(hppa_ext, compare_cond_names[cond]);
        break;
    }
}

static bool decodeArithImm(cs_struct *ud, MCInst *MI, uint32_t insn) {
    MCOperand_CreateImm0(MI, low_sign_extend(GET_FIELD(insn, 21, 31), 11));
    CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
    CREATE_GR_REG(MI, GET_FIELD(insn, 11, 15));
    fillArithImmMods(insn, &MI->hppa_ext);
    return true;
}

static void fillShexdep0InsnName(MCInst *MI, uint32_t insn) {
    uint32_t ext = GET_FIELD(insn, 19, 21);
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
    }
}

static void fillShexdep0Mods(uint32_t insn, hppa_ext* hppa_ext) {
    uint32_t cond = GET_FIELD(insn, 16, 18);
    push_str_modifier(hppa_ext, shift_cond_names[cond]);
}

static bool decodeShexdep0(cs_struct *ud, MCInst *MI, uint32_t insn) {
    uint32_t ext = GET_FIELD(insn, 19, 21);
    switch (ext) {
    case 0x00:
        CREATE_GR_REG(MI, GET_FIELD(insn, 11, 15));
        CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
        CREATE_GR_REG(MI, GET_FIELD(insn, 27, 31));
        fillShexdep0Mods(insn, &MI->hppa_ext);
        return true;
    case 0x02:
        CREATE_GR_REG(MI, GET_FIELD(insn, 11, 15));
        CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
        MCOperand_CreateImm0(MI, 31 - GET_FIELD(insn, 22, 26));
        CREATE_GR_REG(MI, GET_FIELD(insn, 27, 31));
        fillShexdep0Mods(insn, &MI->hppa_ext);
        return true;
    case 0x04:
    case 0x05:
        CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
        MCOperand_CreateImm0(MI, 32 - GET_FIELD(insn, 27, 31));
        CREATE_GR_REG(MI, GET_FIELD(insn, 11, 15));
        fillShexdep0Mods(insn, &MI->hppa_ext);
        return true;
    case 0x06:
    case 0x07:
        CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
        MCOperand_CreateImm0(MI, GET_FIELD(insn, 22, 26));
        MCOperand_CreateImm0(MI, 32 - GET_FIELD(insn, 27, 31));
        CREATE_GR_REG(MI, GET_FIELD(insn, 11, 15));
        fillShexdep0Mods(insn, &MI->hppa_ext);
        return true;
    default:
        return false;
    }
}

static void fillShexdep1InsnName(MCInst *MI, uint32_t insn) {
    uint32_t ext = GET_FIELD(insn, 19, 21);
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
    }
}

static void fillShexdep1Mods(uint32_t insn, hppa_ext* hppa_ext) {
    uint32_t cond = GET_FIELD(insn, 16, 18);
    push_str_modifier(hppa_ext, shift_cond_names[cond]);
}

static bool decodeShexdep1(cs_struct *ud, MCInst *MI, uint32_t insn) {
    uint32_t ext = GET_FIELD(insn, 19, 21);
    switch (ext) {
    case 0x00:
    case 0x01:
        CREATE_GR_REG(MI, GET_FIELD(insn, 11, 15));
        MCOperand_CreateImm0(MI, 32 - GET_FIELD(insn, 27, 31));
        CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
        break;
    case 0x02:
    case 0x03:
        CREATE_GR_REG(MI, GET_FIELD(insn, 11, 15));
        MCOperand_CreateImm0(MI, 31 - GET_FIELD(insn, 22, 26));
        MCOperand_CreateImm0(MI, 32 - GET_FIELD(insn, 27, 31));
        CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
        break;
    case 0x04:
    case 0x05:
        MCOperand_CreateImm0(MI, low_sign_extend(GET_FIELD(insn, 11, 15), 5));
        MCOperand_CreateImm0(MI, 32 - GET_FIELD(insn, 27, 31));
        CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
        break;
    case 0x06:
    case 0x07:
        MCOperand_CreateImm0(MI, low_sign_extend(GET_FIELD(insn, 11, 15), 5));
        MCOperand_CreateImm0(MI, 31 - GET_FIELD(insn, 22, 26));
        MCOperand_CreateImm0(MI, 32 - GET_FIELD(insn, 27, 31));
        CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
        break;
    }
    fillShexdep1Mods(insn, &MI->hppa_ext);
    return true;
}

static void fillBranchInsnName(MCInst *MI, uint32_t insn) {
    uint32_t ext = GET_FIELD(insn, 16, 18);
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
    }
}

static void fillBranchMods(uint32_t insn, hppa_ext* hppa_ext) {
    uint32_t n = GET_FIELD(insn, 30, 30);
    if (n == 1) {
        push_str_modifier(hppa_ext, "n");
    }
}

static bool decodeBranch(cs_struct *ud, MCInst *MI, uint32_t insn) {
    uint32_t ext = GET_FIELD(insn, 16, 18);
    switch (ext) {
    case 0x00:
    case 0x01:
        MCOperand_CreateImm0(MI, extract_17(insn));
        CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
        fillBranchMods(insn, &MI->hppa_ext);
        return true;
    case 0x02:
    case 0x06:
        CREATE_GR_REG(MI, GET_FIELD(insn, 11, 15));
        CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
        fillBranchMods(insn, &MI->hppa_ext);
        return true;
    default:
        return false;
    }
}

static void fillCoprdwInsnName(MCInst *MI, uint32_t insn) {
    uint32_t ext = (GET_FIELD(insn, 19, 19) << 1) | GET_FIELD(insn, 22, 22);
    uint32_t opcode = insn >> 26;
    if (opcode == 0x09) {
        switch (ext)
        {
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
        }
    }
    else {
        switch (ext)
        {
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
        }
    }
}

static void fillCoprdwMods(uint32_t insn, uint32_t ext, hppa_ext* hppa_ext) {
    uint32_t uid = GET_FIELD(insn, 23, 25);
    uint32_t cmplt = (GET_FIELD(insn, 18, 18) << 1) | GET_FIELD(insn, 26, 26);
    uint32_t cc = GET_FIELD(insn, 20, 21);

    push_int_modifier(hppa_ext, uid);
    if (cmplt == 1 || cmplt == 3) {
        hppa_ext->b_writeble = true;
    }
    push_str_modifier(hppa_ext, index_compl_names[cmplt]);
    switch (ext) {
    case 0x00:
    case 0x02:
        if (cc == 2) {
            push_str_modifier(hppa_ext, "sl");
        }
        break;
    case 0x01:
    case 0x03:
        if (cc == 1) {
            push_str_modifier(hppa_ext, "bc");
        }
        else if (cc == 2) {
            push_str_modifier(hppa_ext, "sl");
        }
        break;
    }

}

static bool decodeCoprdw(cs_struct *ud, MCInst *MI, uint32_t insn) {
    uint32_t ext = (GET_FIELD(insn, 19, 19) << 1) | GET_FIELD(insn, 22, 22);
    switch (ext)
    {
    case 0x00:
        CREATE_GR_REG(MI, GET_FIELD(insn, 11, 15));
        CREATE_SR_REG(MI, GET_FIELD(insn, 16, 17));
        CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
        CREATE_GR_REG(MI, GET_FIELD(insn, 27, 31));
        fillCoprdwMods(insn, ext, &MI->hppa_ext);
        return true;
    case 0x01:
        CREATE_GR_REG(MI, GET_FIELD(insn, 27, 31));
        CREATE_GR_REG(MI, GET_FIELD(insn, 11, 15));
        CREATE_SR_REG(MI, GET_FIELD(insn, 16, 17));
        CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
        fillCoprdwMods(insn, ext, &MI->hppa_ext);
        return true;
    case 0x02:
        MCOperand_CreateImm0(MI, low_sign_extend(GET_FIELD(insn, 11, 15), 5));
        CREATE_SR_REG(MI, GET_FIELD(insn, 16, 17));
        CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
        CREATE_GR_REG(MI, GET_FIELD(insn, 27, 31));
        fillCoprdwMods(insn, ext, &MI->hppa_ext);
        return true;
    case 0x03:
        CREATE_GR_REG(MI, GET_FIELD(insn, 27, 31));
        MCOperand_CreateImm0(MI, low_sign_extend(GET_FIELD(insn, 11, 15), 5));
        CREATE_SR_REG(MI, GET_FIELD(insn, 16, 17));
        CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
        fillCoprdwMods(insn, ext, &MI->hppa_ext);
        return true;
    }
}

static void fillSpopInsnName(MCInst *MI, uint32_t insn) {
//    uint32_t uid = GET_FIELD(insn, 23, 25);
//     if (uid == 1) {
//         uint32_t subop = GET_FIELD(insn, 18, 20);
//         uint32_t class = GET_FIELD(insn, 21, 22);
//         if (class == 1) {
//             switch (subop) {
//             case 0x04:
//                 MCInst_setOpcode(MI, HPPA_INS_MTDBAO);
//                 break;                   
//             case 0x05:
//                 MCInst_setOpcode(MI, HPPA_INS_MTDBAM);
//                 break;   
//             case 0x06:
//                 MCInst_setOpcode(MI, HPPA_INS_MTIBAO);
//                 break;   
//             case 0x07:
//                 MCInst_setOpcode(MI, HPPA_INS_MTIBAM);
//                 break;            
//             }
//         }
//         else if (class == 2) {
//             switch (subop) {
//             case 0x00:
//                 MCInst_setOpcode(MI, HPPA_INS_DEBUGID);
//                 break;   
//             case 0x04:
//                 MCInst_setOpcode(MI, HPPA_INS_MFDBAO);
//                 break;   
//             case 0x05:
//                 MCInst_setOpcode(MI, HPPA_INS_MFDBAM);
//                 break;  
//             case 0x06:
//                 MCInst_setOpcode(MI, HPPA_INS_MFIBAO);
//                 break;  
//             case 0x07:
//                 MCInst_setOpcode(MI, HPPA_INS_MFIBAM);
//                 break;  
//             }
//         }
//     }
//     else {
    uint32_t ext = GET_FIELD(insn, 21, 22);
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
    }
    // }    
}

static void fillSpopMods(uint32_t insn, uint32_t ext, hppa_ext* hppa_ext) {
    uint32_t sfu = GET_FIELD(insn, 23, 25);
    uint32_t n = GET_FIELD(insn, 26, 26);
    uint32_t sop;

    push_int_modifier(hppa_ext, sfu);
    switch (ext) {
    case 0x00:
        sop = (GET_FIELD(insn, 6, 20) << 5) | GET_FIELD(insn, 27, 31);
        break;
    case 0x01:
        sop = GET_FIELD(insn, 6, 20);
        break;
    case 0x02:
        sop = (GET_FIELD(insn, 11, 20) << 5) | GET_FIELD(insn, 27, 31);
        break;
    case 0x03:
        sop = (GET_FIELD(insn, 16, 20) << 5) | GET_FIELD(insn, 27, 31);
        break;            
    }
    push_int_modifier(hppa_ext, sop);
    if (n == 1) {
        push_str_modifier(hppa_ext, "n");
    }
}

static bool decodeSpop(cs_struct *ud, MCInst *MI, uint32_t insn) {
    // uint32_t uid = GET_FIELD(insn, 23, 25);
    // if (uid == 1) {
    //     uint32_t subop = GET_FIELD(insn, 18, 20);
    //     uint32_t class = GET_FIELD(insn, 21, 22);
    //     if (class == 1) {
    //         switch (subop) {
    //         case 0x04:
    //         case 0x05:
    //             CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10)); 
    //             CREATE_DBAOR_REG(MI, GET_FIELD(insn, 27, 31));
    //             return true;
    //         case 0x06:
    //         case 0x07:
    //             CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10)); 
    //             CREATE_IBAOR_REG(MI, GET_FIELD(insn, 27, 31));
    //             return true;                
    //         default:
    //             return false;
    //         }
    //     }
    //     else if (class == 2) {
    //         switch (subop) {
    //         case 0x00:
    //             CREATE_GR_REG(MI, GET_FIELD(insn, 27, 31));
    //             return true;
    //         case 0x04:
    //         case 0x05:
    //             CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10)); 
    //             CREATE_DBAOR_REG(MI, GET_FIELD(insn, 27, 31));
    //             return true;
    //         case 0x06:
    //         case 0x07:
    //             CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10)); 
    //             CREATE_IBAOR_REG(MI, GET_FIELD(insn, 27, 31));
    //             return true;
    //         default:
    //             return false;
    //         }
    //     }
    //     return false;
    // }
    // else {
    uint32_t ext = GET_FIELD(insn, 21, 22);
    switch (ext) {
    case 0x00:
        // fillSpopMods(insn, ext, MI->hppa_ext);
        // return true;
        break;
    case 0x01:
        CREATE_GR_REG(MI, GET_FIELD(insn, 27, 31)); 
        // fillSpopMods(insn, ext, MI->hppa_ext);
        // return true;
        break;
    case 0x02:
        CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
        // fillSpopMods(insn, ext, MI->hppa_ext); 
        // return true;
        break;
    case 0x03:
        CREATE_GR_REG(MI, GET_FIELD(insn, 11, 15)); 
        CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10)); 
        // fillSpopMods(insn, ext, MI->hppa_ext);
        // return true;
        break;
    }
    fillSpopMods(insn, ext, &MI->hppa_ext);
    return true;
    // }
}

static void fillCoprInsnName(MCInst *MI, uint32_t insn) {
    uint32_t class = GET_FIELD(insn, 21, 22);
    uint32_t uid = GET_FIELD(insn, 23, 25);
    uint32_t subop;
    if (uid == 0) {
        if (class == 0) {
            subop = GET_FIELD(insn, 16, 18);
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
            }
        }
        else if (class == 1) {
            subop = GET_FIELD(insn, 15, 16);
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
            }
        }
        else if (class == 2) {
            subop = GET_FIELD(insn, 16, 18);
            switch (subop) {
            case 0x00:
                MCInst_setOpcode(MI, HPPA_INS_FCMP);
                return;  
            case 0x01:
                MCInst_setOpcode(MI, HPPA_INS_FTEST);
                return;  
            }
        }
        else if (class == 3) {
            subop = GET_FIELD(insn, 16, 18);
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
            }
        }
    }
    else if (uid == 2) {
        subop = GET_FIELD(insn, 18, 22);
        switch (subop) {
        case 0x01:
            MCInst_setOpcode(MI, HPPA_INS_PMDIS);
            return;  
        case 0x03:
            MCInst_setOpcode(MI, HPPA_INS_PMENB);
            return;  
        }
    }
    MCInst_setOpcode(MI, HPPA_INS_COPR);   
}

static void fillCoprMods(uint32_t insn, uint32_t uid, uint32_t class, 
                         hppa_ext* hppa_ext, uint32_t subop) {
    uint32_t n = GET_FIELD(insn, 26, 26);
    uint32_t sf = GET_FIELD(insn, 19, 20);
    uint32_t df = GET_FIELD(insn, 17, 18);
    // uint32_t subop;
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
                push_str_modifier(hppa_ext, float_format_names[sf]);
                break;
            }
        }
        else if (class == 1) {
            push_str_modifier(hppa_ext, float_format_names[sf]);
            push_str_modifier(hppa_ext, float_format_names[df]);
        }
        else if (class == 2) {
            uint32_t cond = GET_FIELD(insn, 27, 31);
            if (subop == 0) {
                push_str_modifier(hppa_ext, float_format_names[sf]);
                push_str_modifier(hppa_ext, float_comp_names[cond]);
            }
            else {
                push_str_modifier(hppa_ext, float_cond_names[cond]);
            }
        }
        else if (class == 3) {
            push_str_modifier(hppa_ext, float_format_names[sf]);
        }
    }
    else if (uid == 2) {
        if (n == 1) {
            push_str_modifier(hppa_ext, "n");
        }
    } else {
        uint32_t uid = GET_FIELD(insn, 23, 25);
        uint32_t sop = (GET_FIELD(insn, 6, 22) << 5) | GET_FIELD(insn, 27, 31);
        push_int_modifier(hppa_ext, uid);
        push_int_modifier(hppa_ext, sop);
        if (n == 1) {
            push_str_modifier(hppa_ext, "n");
        }
    }

}

static bool decodeCopr(cs_struct *ud, MCInst *MI, uint32_t insn) {
    uint32_t class = GET_FIELD(insn, 21, 22);
    uint32_t uid = GET_FIELD(insn, 23, 25);
    uint32_t subop;
    if (uid == 0) {
        if (class == 0) {
            subop = GET_FIELD(insn, 16, 18);
            switch (subop) {
            case 0x02:
            case 0x03:
            case 0x04:
            case 0x05:
                CREATE_FPR_REG(MI, GET_FIELD(insn, 6, 10));
                CREATE_FPR_REG(MI, GET_FIELD(insn, 27, 31));
            case 0x00:
                fillCoprMods(insn, uid, class, &MI->hppa_ext, subop);
                return true;
            default:
                return false;
            }
        }
        else if (class == 1) {
            subop = GET_FIELD(insn, 15, 16);
            switch (subop) {
            case 0x00:
            case 0x01:
            case 0x02:
            case 0x03:
                CREATE_FPR_REG(MI, GET_FIELD(insn, 6, 10));
                CREATE_FPR_REG(MI, GET_FIELD(insn, 27, 31));
                fillCoprMods(insn, uid, class, &MI->hppa_ext, subop);
                return true;
            }
        }
        else if (class == 2) {
            subop = GET_FIELD(insn, 16, 18);
            switch (subop) {
            case 0x00:
                CREATE_FPR_REG(MI, GET_FIELD(insn, 6, 10));
                CREATE_FPR_REG(MI, GET_FIELD(insn, 11, 15));
            case 0x01:
                fillCoprMods(insn, uid, class, &MI->hppa_ext, subop);
                return true;
            default:
                return false;
            }
        }
        else if (class == 3) {
            subop = GET_FIELD(insn, 16, 18);
            switch (subop) {
            case 0x00:
            case 0x01:
            case 0x02:
            case 0x03:
                CREATE_FPR_REG(MI, GET_FIELD(insn, 6, 10));
                CREATE_FPR_REG(MI, GET_FIELD(insn, 11, 15));
                CREATE_FPR_REG(MI, GET_FIELD(insn, 27, 31));
                fillCoprMods(insn, uid, class, &MI->hppa_ext, subop);
                return true;
            default:
                return false;
            }
        }
    }
    else if (uid == 2) {
        subop = GET_FIELD(insn, 18, 22);
        switch (subop) {
        case 0x01:
        case 0x03:
            fillCoprMods(insn, uid, class, &MI->hppa_ext, subop);
            return true;
        default:
            return false;
        }
    }
    fillCoprMods(insn, uid, class, &MI->hppa_ext, subop);
    return true;
}

static void fillFloatInsnName(MCInst *MI, uint32_t insn) {
    uint32_t class = GET_FIELD(insn, 21, 22);
    uint32_t subop;
    if (class == 0) {
        subop = GET_FIELD(insn, 16, 18);
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
        }
    }
    else if (class == 1) {
        subop = GET_FIELD(insn, 15, 16);
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
        }
    }
    else if (class == 2) {
        subop = GET_FIELD(insn, 16, 18);
        switch (subop) {
        case 0x00:
            MCInst_setOpcode(MI, HPPA_INS_FCMP);
            break;   
        }
    }
    else if (class == 3) {
        subop = GET_FIELD(insn, 16, 18);
        uint32_t fixed = GET_FIELD(insn, 23, 23);
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
            }
        }
        else {
            switch (subop) {
            case 0x02:
                MCInst_setOpcode(MI, HPPA_INS_XMPYU);
                break;  
            }
        }
    }    
}

static void fillFloatMods(uint32_t insn, uint32_t class, 
                         hppa_ext* hppa_ext, uint32_t subop) {
    if (class == 0) {
        uint32_t fmt = GET_FIELD(insn, 19, 20);
        push_str_modifier(hppa_ext, float_format_names[fmt]);
    }
    else if (class == 1) {
        uint32_t sf = GET_FIELD(insn, 19, 20);
        uint32_t df = GET_FIELD(insn, 17, 18);
        push_str_modifier(hppa_ext, float_format_names[sf]);
        push_str_modifier(hppa_ext, float_format_names[df]);
    }
    else if (class == 2) {
        uint32_t fmt = GET_FIELD(insn, 20, 20);
        uint32_t cond = GET_FIELD(insn, 27, 31);
        push_str_modifier(hppa_ext, float_format_names[fmt]);
        push_str_modifier(hppa_ext, float_cond_names[cond]);
    }
    else if (class == 3) {
        if (GET_FIELD(insn, 23, 23) == 0) {
            uint32_t fmt = GET_FIELD(insn, 20, 20);
            push_str_modifier(hppa_ext, float_format_names[fmt]);
        }
    }
}

static bool decodeFloat(cs_struct *ud, MCInst *MI, uint32_t insn) {
    uint32_t class = GET_FIELD(insn, 21, 22);
    uint32_t subop;
    uint32_t r1 = GET_FIELD(insn, 6, 10);
    uint32_t r1_fpe = GET_FIELD(insn, 24, 24);
    uint32_t r2 = GET_FIELD(insn, 11, 15);
    uint32_t r2_fpe = GET_FIELD(insn, 19, 19);
    uint32_t t = GET_FIELD(insn, 27, 31);
    uint32_t t_fpe = GET_FIELD(insn, 25, 25);
    if (class == 0) {
        subop = GET_FIELD(insn, 16, 18);
        switch (subop) {
        case 0x02:
        case 0x03:
        case 0x04:
        case 0x05:
            create_float_reg_spec(MI, r1, r1_fpe);
            create_float_reg_spec(MI, t, t_fpe);
            fillFloatMods(insn, class, &MI->hppa_ext, subop);
            return true;
        default:
            return false;
        }
    }
    else if (class == 1) {
        subop = GET_FIELD(insn, 15, 16);
        switch (subop) {
        case 0x00:
        case 0x01:
        case 0x02:
        case 0x03:
            create_float_reg_spec(MI, r1, r1_fpe);
            create_float_reg_spec(MI, t, t_fpe);
            fillFloatMods(insn, class, &MI->hppa_ext, subop);
            return true;           
        }
    }
    else if (class == 2) {
        subop = GET_FIELD(insn, 16, 18);
        switch (subop) {
        case 0x00:
            create_float_reg_spec(MI, r1, r1_fpe);
            create_float_reg_spec(MI, r2, r2_fpe);  
            fillFloatMods(insn, class, &MI->hppa_ext, subop);
            return true;     
        default:
            return false;
        }
    }
    else if (class == 3) {
        subop = GET_FIELD(insn, 16, 18);
        uint32_t fixed = GET_FIELD(insn, 23, 23);
        if (fixed == 0) {
            switch (subop) {
            case 0x00:
            case 0x01:
            case 0x02:
            case 0x03:
                create_float_reg_spec(MI, r1, r1_fpe);
                create_float_reg_spec(MI, r2, r2_fpe); 
                create_float_reg_spec(MI, t, t_fpe); 
                fillFloatMods(insn, class, &MI->hppa_ext, subop);
                return true;             
            default:
                return false;
            }
        }
        else {
            switch (subop) {
            case 0x02:
                create_float_reg_spec(MI, r1, r1_fpe);
                create_float_reg_spec(MI, r2, r2_fpe); 
                create_float_reg_spec(MI, t, t_fpe); 
                fillFloatMods(insn, class, &MI->hppa_ext, subop);
                return true;
            default:
                return false;
            }
        }
    }
}

static void fillActionAndBranchInsnName(MCInst *MI, uint32_t opcode) {
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
    }
}

static void fillActionAndBranchMods(uint32_t insn, uint32_t opcode, hppa_ext* hppa_ext) {
    uint32_t cond = GET_FIELD(insn, 16, 18);
    uint32_t n = GET_FIELD(insn, 30, 30);

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
    }
    if (n == 1) {
        push_str_modifier(hppa_ext, "n");
    }
}

static bool decodeActionAndBranch(cs_struct *ud, MCInst *MI, uint32_t insn) {
    uint32_t opcode = insn >> 26;
    if ((opcode & 1) == 0 || opcode == HPPA_OP_TYPE_BB) {
        CREATE_GR_REG(MI, GET_FIELD(insn, 11, 15));
    } 
    else {
        MCOperand_CreateImm0(MI, low_sign_extend(GET_FIELD(insn, 11, 15), 5));
    }
    if (opcode == HPPA_OP_TYPE_BB) {
        MCOperand_CreateImm0(MI, GET_FIELD(insn, 6, 10));
    }
    else if (opcode != HPPA_OP_TYPE_BBS) {
        CREATE_GR_REG(MI, GET_FIELD(insn, 6, 10));
    }
    MCOperand_CreateImm0(MI, extract_12(insn));
    fillActionAndBranchMods(insn, opcode, &MI->hppa_ext);

    return true;
}

static void fillLoadInsnName(MCInst *MI, uint32_t opcode) {
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
        MCInst_setOpcode(MI, HPPA_INS_LDWM);
        break;
    }
}

static void fillStoreInsnName(MCInst *MI, uint32_t opcode) {
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
        MCInst_setOpcode(MI, HPPA_INS_STWM);
        break;
    }
}

static bool getInstruction(cs_struct *ud, const uint8_t *code, size_t code_len,
               MCInst *MI)
{
    if (code_len < 4)
        return false;

    cs_detail *detail;
    detail = get_detail(MI);
    if (detail) {
        memset(detail, 0, offsetof(cs_detail, hppa) + sizeof(cs_hppa));
    }
    MCInst_clear(MI);
    memset(&MI->hppa_ext, 0, sizeof(MI->hppa_ext));

    uint8_t opcode = HPPA_OP_TYPE(code[0]);
    uint32_t full_insn = CODE_TO_INSN(code);
    MI->hppa_ext.full_insn = full_insn;

    switch (opcode) {
    case HPPA_OP_TYPE_SYSOP:
        fillSysopInsnName(MI, full_insn);
        return decodeSysop(ud, MI, full_insn);
    case HPPA_OP_TYPE_MEMMGMT:
        fillMemmgmtInsnName(MI, full_insn);
        return decodeMemmgmt(ud, MI, full_insn);
    case HPPA_OP_TYPE_ALU:
        fillAluInsnName(MI, full_insn);
        return decodeAlu(ud, MI, full_insn);
    case HPPA_OP_TYPE_IDXMEM:
        fillIdxmemInsnName(MI, full_insn);
        return decodeIdxmem(ud, MI, full_insn);
    case HPPA_OP_TYPE_ADDIT:
    case HPPA_OP_TYPE_ADDI:
    case HPPA_OP_TYPE_SUBI:
        fillArithImmInsnName(MI, full_insn);
        return decodeArithImm(ud, MI, full_insn);
    case HPPA_OP_TYPE_SHEXDEP0:
        fillShexdep0InsnName(MI, full_insn);
        return decodeShexdep0(ud, MI, full_insn);
    case HPPA_OP_TYPE_SHEXDEP1:
        fillShexdep1InsnName(MI, full_insn);
        return decodeShexdep1(ud, MI, full_insn);
    case HPPA_OP_TYPE_BRANCH:
        fillBranchInsnName(MI, full_insn);
        return decodeBranch(ud, MI, full_insn);
    case HPPA_OP_TYPE_COPRW:
    case HPPA_OP_TYPE_COPRDW:
        fillCoprdwInsnName(MI, full_insn);
        return decodeCoprdw(ud, MI, full_insn);
    case HPPA_OP_TYPE_SPOP:
        fillSpopInsnName(MI, full_insn);
        return decodeSpop(ud, MI, full_insn);
    case HPPA_OP_TYPE_COPR:
        fillCoprInsnName(MI, full_insn);
        return decodeCopr(ud, MI, full_insn);
    case HPPA_OP_TYPE_FLOAT:
        fillFloatInsnName(MI, full_insn);
        return decodeFloat(ud, MI, full_insn);
    case HPPA_OP_TYPE_DIAG:
        MCInst_setOpcode(MI, HPPA_INS_DIAG);
        MCOperand_CreateImm0(MI, GET_FIELD(full_insn, 6, 31));
        return true;
    case HPPA_OP_TYPE_FMPYADD:
    case HPPA_OP_TYPE_FMPYSUB:
        if (opcode == HPPA_OP_TYPE_FMPYADD) {
            MCInst_setOpcode(MI, HPPA_INS_FMPYADD);
        }
        else {
            MCInst_setOpcode(MI, HPPA_INS_FMPYSUB);
        }
        uint32_t fmt = GET_FIELD(full_insn, 26, 26);
        CREATE_FPR_REG(MI, GET_FIELD(full_insn, 6, 10));
        CREATE_FPR_REG(MI, GET_FIELD(full_insn, 11, 15));
        CREATE_FPR_REG(MI, GET_FIELD(full_insn, 27, 31));
        CREATE_FPR_REG(MI, GET_FIELD(full_insn, 21, 25));
        CREATE_FPR_REG(MI, GET_FIELD(full_insn, 16, 20));
        if (fmt == 0) {
            push_str_modifier(&MI->hppa_ext, "dbl");
        }
        else {
            push_str_modifier(&MI->hppa_ext, "sgl");
        }
        
        return true;
    case HPPA_OP_TYPE_LDIL:
    case HPPA_OP_TYPE_ADDIL:
        if (opcode == HPPA_OP_TYPE_LDIL) {
            MCInst_setOpcode(MI, HPPA_INS_LDIL);
        }
        else {
            MCInst_setOpcode(MI, HPPA_INS_ADDIL);
        }
        MCOperand_CreateImm0(MI, extract_21(full_insn));
        CREATE_GR_REG(MI, GET_FIELD(full_insn, 6, 10));
        return true;
    case HPPA_OP_TYPE_LDO:
        MCInst_setOpcode(MI, HPPA_INS_LDO);
        MCOperand_CreateImm0(MI, low_sign_extend(GET_FIELD(full_insn, 18, 31), 14));
        CREATE_GR_REG(MI, GET_FIELD(full_insn, 6, 10));
        CREATE_GR_REG(MI, GET_FIELD(full_insn, 11, 15));
        return true;
    case HPPA_OP_TYPE_LDB:
    case HPPA_OP_TYPE_LDH:
    case HPPA_OP_TYPE_LDW:
    case HPPA_OP_TYPE_LDWM:
        fillLoadInsnName(MI, opcode);
        MCOperand_CreateImm0(MI, low_sign_extend(GET_FIELD(full_insn, 18, 31), 14));
        CREATE_SR_REG(MI, GET_FIELD(full_insn, 16, 17));
        CREATE_GR_REG(MI, GET_FIELD(full_insn, 6, 10));
        CREATE_GR_REG(MI, GET_FIELD(full_insn, 11, 15));
        return true;
    case HPPA_OP_TYPE_STB:
    case HPPA_OP_TYPE_STH:
    case HPPA_OP_TYPE_STW:
    case HPPA_OP_TYPE_STWM:
        fillStoreInsnName(MI, opcode);
        CREATE_GR_REG(MI, GET_FIELD(full_insn, 11, 15));
        MCOperand_CreateImm0(MI, low_sign_extend(GET_FIELD(full_insn, 18, 31), 14));
        CREATE_SR_REG(MI, GET_FIELD(full_insn, 16, 17));
        CREATE_GR_REG(MI, GET_FIELD(full_insn, 6, 10));
        return true;
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
        fillActionAndBranchInsnName(MI, opcode);
        return decodeActionAndBranch(ud, MI, full_insn);
    case HPPA_OP_TYPE_CMPICLR:
        MCInst_setOpcode(MI, HPPA_INS_COMICLR);
        uint32_t cond = GET_FIELD(full_insn, 16, 18);
        MCOperand_CreateImm0(MI, low_sign_extend(GET_FIELD(full_insn, 21, 31), 11));
        CREATE_GR_REG(MI, GET_FIELD(full_insn, 6, 10));
        CREATE_GR_REG(MI, GET_FIELD(full_insn, 11, 15));
        push_str_modifier(&MI->hppa_ext, compare_cond_names[cond]);
        return true;
    case HPPA_OP_TYPE_BE:
    case HPPA_OP_TYPE_BLE:
        if (opcode == HPPA_OP_TYPE_BE) {
            MCInst_setOpcode(MI, HPPA_INS_BE);
        }
        else {
            MCInst_setOpcode(MI, HPPA_INS_BLE);
        }
        uint32_t n = GET_FIELD(full_insn, 30, 30);
        MCOperand_CreateImm0(MI, extract_17(full_insn));
        CREATE_SR_REG(MI, extract_3(full_insn));
        CREATE_GR_REG(MI, GET_FIELD(full_insn, 6, 10));
        if (n == 1) {
            push_str_modifier(&MI->hppa_ext, "n");
        }
        return true;
    default:
        return false;
    }
}

bool HPPA_getInstruction(csh ud, const uint8_t *code, size_t code_len,
             MCInst *instr, uint16_t *size, uint64_t address,
             void *info)
{
    cs_struct *cs = (cs_struct *)ud;
    if (!getInstruction(cs, code, code_len, instr)) {
        return false;
    }
    *size = 4;

    return true;
}

#endif
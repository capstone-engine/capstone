#ifndef CAPSTONE_HPPA_H
#define CAPSTONE_HPPA_H

#ifdef __cplusplus
extern "C" {
#endif

#include "cs_operand.h"
#include "platform.h"

/// Operand type for instruction's operands
typedef enum hppa_op_type {
	HPPA_OP_INVALID = 0,

	HPPA_OP_REG,
	HPPA_OP_IMM,
    HPPA_OP_IDX_REG,
    HPPA_OP_DISP,
    HPPA_OP_MEM,
    HPPA_OP_TARGET,

} hppa_op_type;

//> HPPA registers
typedef enum hppa_reg {
	HPPA_REG_INVALID = 0,

    ///> General registers
    HPPA_REG_GR0,
    HPPA_REG_GR1,
    HPPA_REG_GR2,
    HPPA_REG_GR3,
    HPPA_REG_GR4,
    HPPA_REG_GR5,
    HPPA_REG_GR6,
    HPPA_REG_GR7,
    HPPA_REG_GR8,
    HPPA_REG_GR9,
    HPPA_REG_GR10,
    HPPA_REG_GR11,
    HPPA_REG_GR12,
    HPPA_REG_GR13,
    HPPA_REG_GR14,
    HPPA_REG_GR15,
    HPPA_REG_GR16,
    HPPA_REG_GR17,
    HPPA_REG_GR18,
    HPPA_REG_GR19,
    HPPA_REG_GR20,
    HPPA_REG_GR21,
    HPPA_REG_GR22,
    HPPA_REG_GR23,
    HPPA_REG_GR24,
    HPPA_REG_GR25,
    HPPA_REG_GR26,
    HPPA_REG_GR27,
    HPPA_REG_GR28,
    HPPA_REG_GR29,
    HPPA_REG_GR30,
    HPPA_REG_GR31,

    ///> Floating-point registers
    HPPA_REG_FPR0,
    HPPA_REG_FPR1,
    HPPA_REG_FPR2,
    HPPA_REG_FPR3,
    HPPA_REG_FPR4,
    HPPA_REG_FPR5,
    HPPA_REG_FPR6,
    HPPA_REG_FPR7,
    HPPA_REG_FPR8,
    HPPA_REG_FPR9,
    HPPA_REG_FPR10,
    HPPA_REG_FPR11,
    HPPA_REG_FPR12,
    HPPA_REG_FPR13,
    HPPA_REG_FPR14,
    HPPA_REG_FPR15,
    HPPA_REG_FPR16,
    HPPA_REG_FPR17,
    HPPA_REG_FPR18,
    HPPA_REG_FPR19,
    HPPA_REG_FPR20,
    HPPA_REG_FPR21,
    HPPA_REG_FPR22,
    HPPA_REG_FPR23,
    HPPA_REG_FPR24,
    HPPA_REG_FPR25,
    HPPA_REG_FPR26,
    HPPA_REG_FPR27,
    HPPA_REG_FPR28,
    HPPA_REG_FPR29,
    HPPA_REG_FPR30,
    HPPA_REG_FPR31,

    ///> Space registers
    HPPA_REG_SR0,
    HPPA_REG_SR1,
    HPPA_REG_SR2,
    HPPA_REG_SR3,
    HPPA_REG_SR4,
    HPPA_REG_SR5,
    HPPA_REG_SR6,
    HPPA_REG_SR7,

    ///> Control registers
    HPPA_REG_CR0,
    HPPA_REG_CR1,
    HPPA_REG_CR2,
    HPPA_REG_CR3,
    HPPA_REG_CR4,
    HPPA_REG_CR5,
    HPPA_REG_CR6,
    HPPA_REG_CR7,
    HPPA_REG_CR8,
    HPPA_REG_CR9,
    HPPA_REG_CR10,
    HPPA_REG_CR11,
    HPPA_REG_CR12,
    HPPA_REG_CR13,
    HPPA_REG_CR14,
    HPPA_REG_CR15,
    HPPA_REG_CR16,
    HPPA_REG_CR17,
    HPPA_REG_CR18,
    HPPA_REG_CR19,
    HPPA_REG_CR20,
    HPPA_REG_CR21,
    HPPA_REG_CR22,
    HPPA_REG_CR23,
    HPPA_REG_CR24,
    HPPA_REG_CR25,
    HPPA_REG_CR26,
    HPPA_REG_CR27,
    HPPA_REG_CR28,
    HPPA_REG_CR29,
    HPPA_REG_CR30,
    HPPA_REG_CR31,

    // ///> Coprocessor registers
    // HPPA_REG_CPR0,
    // HPPA_REG_CPR1,
    // HPPA_REG_CPR2,
    // HPPA_REG_CPR3,
    // HPPA_REG_CPR4,
    // HPPA_REG_CPR5,
    // HPPA_REG_CPR6,
    // HPPA_REG_CPR7,
    // HPPA_REG_CPR8,
    // HPPA_REG_CPR9,
    // HPPA_REG_CPR10,
    // HPPA_REG_CPR11,
    // HPPA_REG_CPR12,
    // HPPA_REG_CPR13,
    // HPPA_REG_CPR14,
    // HPPA_REG_CPR15,
    // HPPA_REG_CPR16,
    // HPPA_REG_CPR17,
    // HPPA_REG_CPR18,
    // HPPA_REG_CPR19,
    // HPPA_REG_CPR20,
    // HPPA_REG_CPR21,
    // HPPA_REG_CPR22,
    // HPPA_REG_CPR23,
    // HPPA_REG_CPR24,
    // HPPA_REG_CPR25,
    // HPPA_REG_CPR26,
    // HPPA_REG_CPR27,
    // HPPA_REG_CPR28,
    // HPPA_REG_CPR29,
    // HPPA_REG_CPR30,
    // HPPA_REG_CPR31,

    ///> Debug registers
    HPPA_REG_DBAOR0,
    HPPA_REG_DBAOR1,
    HPPA_REG_DBAOR2,
    HPPA_REG_DBAOR3,
    HPPA_REG_DBAOR4,
    HPPA_REG_DBAOR5,
    HPPA_REG_DBAOR6,
    HPPA_REG_DBAOR7,
    HPPA_REG_DBAOR8,
    HPPA_REG_DBAOR9,
    HPPA_REG_DBAOR10,
    HPPA_REG_DBAOR11,
    HPPA_REG_DBAOR12,
    HPPA_REG_DBAOR13,
    HPPA_REG_DBAOR14,
    HPPA_REG_DBAOR15,
    HPPA_REG_DBAOR16,
    HPPA_REG_DBAOR17,
    HPPA_REG_DBAOR18,
    HPPA_REG_DBAOR19,
    HPPA_REG_DBAOR20,
    HPPA_REG_DBAOR21,
    HPPA_REG_DBAOR22,
    HPPA_REG_DBAOR23,
    HPPA_REG_DBAOR24,
    HPPA_REG_DBAOR25,
    HPPA_REG_DBAOR26,
    HPPA_REG_DBAOR27,
    HPPA_REG_DBAOR28,
    HPPA_REG_DBAOR29,
    HPPA_REG_DBAOR30,

    HPPA_REG_IBAOR0,
    HPPA_REG_IBAOR1,
    HPPA_REG_IBAOR2,
    HPPA_REG_IBAOR3,
    HPPA_REG_IBAOR4,
    HPPA_REG_IBAOR5,
    HPPA_REG_IBAOR6,
    HPPA_REG_IBAOR7,
    HPPA_REG_IBAOR8,
    HPPA_REG_IBAOR9,
    HPPA_REG_IBAOR10,
    HPPA_REG_IBAOR11,
    HPPA_REG_IBAOR12,
    HPPA_REG_IBAOR13,
    HPPA_REG_IBAOR14,
    HPPA_REG_IBAOR15,
    HPPA_REG_IBAOR16,
    HPPA_REG_IBAOR17,
    HPPA_REG_IBAOR18,
    HPPA_REG_IBAOR19,
    HPPA_REG_IBAOR20,
    HPPA_REG_IBAOR21,
    HPPA_REG_IBAOR22,
    HPPA_REG_IBAOR23,
    HPPA_REG_IBAOR24,
    HPPA_REG_IBAOR25,
    HPPA_REG_IBAOR26,
    HPPA_REG_IBAOR27,
    HPPA_REG_IBAOR28,
    HPPA_REG_IBAOR29,
    HPPA_REG_IBAOR30,

    ///> Special floating point exception registers
    HPPA_REG_FPE0,
    HPPA_REG_FPE1,
    HPPA_REG_FPE2,
    HPPA_REG_FPE3,
    HPPA_REG_FPE4,
    HPPA_REG_FPE5,
    HPPA_REG_FPE6,
    HPPA_REG_FPE7,
    HPPA_REG_FPE8,
    HPPA_REG_FPE9,
    HPPA_REG_FPE10,
    HPPA_REG_FPE11,
    HPPA_REG_FPE12,
    HPPA_REG_FPE13,
    HPPA_REG_FPE14,
    HPPA_REG_FPE15,
    HPPA_REG_FPE16,
    HPPA_REG_FPE17,
    HPPA_REG_FPE18,
    HPPA_REG_FPE19,
    HPPA_REG_FPE20,
    HPPA_REG_FPE21,
    HPPA_REG_FPE22,
    HPPA_REG_FPE23,
    HPPA_REG_FPE24,
    HPPA_REG_FPE25,
    HPPA_REG_FPE26,
    HPPA_REG_FPE27,
    HPPA_REG_FPE28,
    HPPA_REG_FPE29,
    HPPA_REG_FPE30,
    HPPA_REG_FPE31,

    ///> Single-precision floating point registers
    HPPA_REG_SP_FPR0,
    HPPA_REG_SP_FPR1,
    HPPA_REG_SP_FPR2,
    HPPA_REG_SP_FPR3,
    HPPA_REG_SP_FPR4,
    HPPA_REG_SP_FPR5,
    HPPA_REG_SP_FPR6,
    HPPA_REG_SP_FPR7,
    HPPA_REG_SP_FPR8,
    HPPA_REG_SP_FPR9,
    HPPA_REG_SP_FPR10,
    HPPA_REG_SP_FPR11,
    HPPA_REG_SP_FPR12,
    HPPA_REG_SP_FPR13,
    HPPA_REG_SP_FPR14,
    HPPA_REG_SP_FPR15,
    HPPA_REG_SP_FPR16,
    HPPA_REG_SP_FPR17,
    HPPA_REG_SP_FPR18,
    HPPA_REG_SP_FPR19,
    HPPA_REG_SP_FPR20,
    HPPA_REG_SP_FPR21,
    HPPA_REG_SP_FPR22,
    HPPA_REG_SP_FPR23,
    HPPA_REG_SP_FPR24,
    HPPA_REG_SP_FPR25,
    HPPA_REG_SP_FPR26,
    HPPA_REG_SP_FPR27,
    HPPA_REG_SP_FPR28,
    HPPA_REG_SP_FPR29,
    HPPA_REG_SP_FPR30,
    HPPA_REG_SP_FPR31,

    HPPA_REG_ENDING,
} hppa_reg;

/// HPPA instruction
typedef enum hppa_insn {
	HPPA_INS_INVALID = 0,

    HPPA_INS_ADD,
    HPPA_INS_ADDI,
    HPPA_INS_ADDIO,
    HPPA_INS_ADDIT,
    HPPA_INS_ADDITO,
    HPPA_INS_ADDB,
    HPPA_INS_ADDBT,
    HPPA_INS_ADDBF,
    HPPA_INS_ADDIB,
    HPPA_INS_ADDIBT,
    HPPA_INS_ADDIBF,
    HPPA_INS_ADDIL,
    HPPA_INS_ADDC,
    HPPA_INS_ADDCO,
    HPPA_INS_ADDL,
    HPPA_INS_ADDO,
    HPPA_INS_AND,
    HPPA_INS_ANDCM,
    HPPA_INS_B,
    HPPA_INS_BB,
    HPPA_INS_BE,
    HPPA_INS_BL,
    HPPA_INS_BLE,
    HPPA_INS_BLR,
    HPPA_INS_BREAK,
    HPPA_INS_BV,
    HPPA_INS_BVB,
    HPPA_INS_BVE,
    HPPA_INS_CALL,
    HPPA_INS_CLDD,
    HPPA_INS_CLDDS,
    HPPA_INS_CLDDX,
    HPPA_INS_CLDW,
    HPPA_INS_CLDWS,
    HPPA_INS_CLDWX,
    HPPA_INS_CLRBTS,
    HPPA_INS_CMPB,
    HPPA_INS_CMPCLR,
    HPPA_INS_CMPIB,
    HPPA_INS_CMPICLR,
    HPPA_INS_COMB,
    HPPA_INS_COMBT,
    HPPA_INS_COMBF,
    HPPA_INS_COMCLR,
    HPPA_INS_COMIB,
    HPPA_INS_COMIBT,
    HPPA_INS_COMIBF,
    HPPA_INS_COMICLR,
    HPPA_INS_COPR,
    HPPA_INS_COPY,
    HPPA_INS_CSTD,
    HPPA_INS_CSTDS,
    HPPA_INS_CSTDX,
    HPPA_INS_CSTW,
    HPPA_INS_CSTWS,
    HPPA_INS_CSTWX,
    HPPA_INS_DCOR,
    HPPA_INS_DEP,
    HPPA_INS_DEPI,
    HPPA_INS_DEPD,
    HPPA_INS_DEPDI,
    HPPA_INS_DEPW,
    HPPA_INS_DEPWI,
    HPPA_INS_DIAG,
    HPPA_INS_DS,
    HPPA_INS_EXTRD,
    HPPA_INS_EXTRS,
    HPPA_INS_EXTRU,
    HPPA_INS_EXTRW,
    HPPA_INS_FABS,
    HPPA_INS_FADD,
    HPPA_INS_FCMP,
    HPPA_INS_FCNV,
    HPPA_INS_FCNVFF,
    HPPA_INS_FCNVFX,
    HPPA_INS_FCNVFXT,
    HPPA_INS_FCNVXF,
    HPPA_INS_FCPY,
    HPPA_INS_FDC,
    HPPA_INS_FDCE,
    HPPA_INS_FDIV,
    HPPA_INS_FIC,
    HPPA_INS_FICE,
    HPPA_INS_FID,
    HPPA_INS_FLDD,
    HPPA_INS_FLDDS,
    HPPA_INS_FLDDX,
    HPPA_INS_FLDW,
    HPPA_INS_FLDWS,
    HPPA_INS_FLDWX,
    HPPA_INS_FMPY,
    HPPA_INS_FMPYADD,
    HPPA_INS_FMPYFADD,
    HPPA_INS_FMPYNFADD,
    HPPA_INS_FMPYSUB,
    HPPA_INS_FNEG,
    HPPA_INS_FNEGABS,
    HPPA_INS_FREM,
    HPPA_INS_FRND,
    HPPA_INS_FSQRT,
    HPPA_INS_FSTD,
    HPPA_INS_FSTDS,
    HPPA_INS_FSTDX,
    HPPA_INS_FSTW,
    HPPA_INS_FSTWS,
    HPPA_INS_FSTWX,
    HPPA_INS_FSTQS,
    HPPA_INS_FSTQX,
    HPPA_INS_FSUB,
    HPPA_INS_FTEST,
    HPPA_INS_GATE,
    HPPA_INS_GFR,
    HPPA_INS_GFW,
    HPPA_INS_GRSHDW,
    HPPA_INS_HADD,
    HPPA_INS_HAVG,
    HPPA_INS_HSHL,
    HPPA_INS_HSHLADD,
    HPPA_INS_HSHR,
    HPPA_INS_HSHRADD,
    HPPA_INS_HSUB,
    HPPA_INS_IDTLBA,
    HPPA_INS_IDTLBP,
    HPPA_INS_IDTLBT,
    HPPA_INS_IDCOR,
    HPPA_INS_IITLBA,
    HPPA_INS_IITLBP,
    HPPA_INS_IITLBT,
    HPPA_INS_LCI,
    HPPA_INS_LDB,
    HPPA_INS_LDBS,
    HPPA_INS_LDBX,
    HPPA_INS_LDCD,
    HPPA_INS_LDCW,
    HPPA_INS_LDCWS,
    HPPA_INS_LDCWX,
    HPPA_INS_LDD,
    HPPA_INS_LDDA,
    HPPA_INS_LDH,
    HPPA_INS_LDHS,
    HPPA_INS_LDHX,
    HPPA_INS_LDI,
    HPPA_INS_LDIL,
    HPPA_INS_LDO,
    HPPA_INS_LDSID,
    HPPA_INS_LDW,
    HPPA_INS_LDWA,
    HPPA_INS_LDWAS,
    HPPA_INS_LDWAX,
    HPPA_INS_LDWM,
    HPPA_INS_LDWS,
    HPPA_INS_LDWX,
    HPPA_INS_LPA,
    HPPA_INS_MFCPU,
    HPPA_INS_MFCTL,
    HPPA_INS_MFIA,
    HPPA_INS_MFSP,
    HPPA_INS_MIXH,
    HPPA_INS_MIXW,
    HPPA_INS_MOVB,
    HPPA_INS_MOVIB,
    HPPA_INS_MTCPU,
    HPPA_INS_MTCTL,
    HPPA_INS_MTSAR,
    HPPA_INS_MTSARCM,
    HPPA_INS_MTSM,
    HPPA_INS_MTSP,
    HPPA_INS_NOP,
    HPPA_INS_OR,
    HPPA_INS_PDC,
    HPPA_INS_PDTLB,
    HPPA_INS_PDTLBE,
    HPPA_INS_PERMH,
    HPPA_INS_PITLB,
    HPPA_INS_PITLBE,
    HPPA_INS_PMDIS,
    HPPA_INS_PMENB,
    HPPA_INS_POPBTS,
    HPPA_INS_PROBE,
    HPPA_INS_PROBEI,
    HPPA_INS_PROBER,
    HPPA_INS_PROBERI,
    HPPA_INS_PROBEW,
    HPPA_INS_PROBEWI,
    HPPA_INS_PUSHBTS,
    HPPA_INS_PUSHNOM,
    HPPA_INS_RET,
    HPPA_INS_RFI,
    HPPA_INS_RFIR,
    HPPA_INS_RSM,
    HPPA_INS_SHDWGR,
    HPPA_INS_SHLADD,
    HPPA_INS_SH1ADD,
    HPPA_INS_SH1ADDL,
    HPPA_INS_SH1ADDO,
    HPPA_INS_SH2ADD,
    HPPA_INS_SH2ADDL,
    HPPA_INS_SH2ADDO,
    HPPA_INS_SH3ADD,
    HPPA_INS_SH3ADDL,
    HPPA_INS_SH3ADDO,
    HPPA_INS_SHD,
    HPPA_INS_SHRPD,
    HPPA_INS_SHRPW,
    HPPA_INS_SPOP0,
    HPPA_INS_SPOP1,
    HPPA_INS_SPOP2,
    HPPA_INS_SPOP3,
    HPPA_INS_SSM,
    HPPA_INS_STB,
    HPPA_INS_STBS,
    HPPA_INS_STBY,
    HPPA_INS_STBYS,
    HPPA_INS_STD,
    HPPA_INS_STDA,
    HPPA_INS_STDBY,
    HPPA_INS_STH,
    HPPA_INS_STHS,
    HPPA_INS_STW,
    HPPA_INS_STWA,
    HPPA_INS_STWAS,
    HPPA_INS_STWS,
    HPPA_INS_STWM,
    HPPA_INS_SUB,
    HPPA_INS_SUBB,
    HPPA_INS_SUBBO,
    HPPA_INS_SUBI,
    HPPA_INS_SUBIO,
    HPPA_INS_SUBO,
    HPPA_INS_SUBT,
    HPPA_INS_SUBTO,
    HPPA_INS_SYNC,
    HPPA_INS_SYNCDMA,
    HPPA_INS_TOCDIS,
    HPPA_INS_TOCEN,
    HPPA_INS_UADDCM,
    HPPA_INS_UADDCMT,
    HPPA_INS_UXOR,
    HPPA_INS_VDEP,
    HPPA_INS_VDEPI,
    HPPA_INS_VEXTRS,
    HPPA_INS_VEXTRU,
    HPPA_INS_VSHD,
    HPPA_INS_XMPYU,
    HPPA_INS_XOR,
    HPPA_INS_ZDEP,
    HPPA_INS_ZDEPI,
    HPPA_INS_ZVDEP,
    HPPA_INS_ZVDEPI,
    
    HPPA_INS_ENDING
} hppa_insn;


/// HPPA space select operand
typedef struct hppa_mem {
    unsigned int base;
    unsigned int space;
    enum cs_ac_type base_access;
} hppa_mem;

// Instruction operand
typedef struct cs_hppa_op {
	enum hppa_op_type type; // operand type
	union {
		unsigned int reg; // register value for REG operand
		int64_t imm;      // immediate value for IMM operand
        struct hppa_mem mem;
	};
	enum cs_ac_type access;
} cs_hppa_op;

// Instruction structure
typedef struct cs_hppa {
	// Number of operands of this instruction,
	// or 0 when instruction has no operand.
	uint8_t op_count;
	cs_hppa_op operands[5]; // operands for this instruction.
} cs_hppa;

/// hppa string/integer modifier
typedef struct hppa_modifier {
    int type;
    union
    {
        char* str_mod;
        uint32_t int_mod;
    };
    
} hppa_modifier;

// Additional instruction info
typedef struct hppa_ext {
    struct hppa_modifier modifiers[5];
    uint8_t mod_num;
    bool b_writeble;
    bool cmplt;
} hppa_ext;




// Group of HPPA instructions
typedef enum hppa_insn_group {
	HPPA_GRP_INVALID = 0, ///< = CS_GRP_INVALID

	HPPA_GRP_COMPUTATION,
    HPPA_GRP_MULTIMEDIA,
    HPPA_GRP_MEM_REF,
    HPPA_GRP_LONG_IMM,
    HPPA_GRP_BRANCH,
    HPPA_GRP_SYSCTRL,
    HPPA_GRP_ASSIST,
    HPPA_GRP_FLOAT,
    HPPA_GRP_PERFMON,

	HPPA_GRP_ENDING,
} hppa_insn_group;

#ifdef __cplusplus
}
#endif

#endif
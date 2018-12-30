/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Instruction Enum Values and Descriptors                             *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifdef GET_INSTRINFO_ENUM
#undef GET_INSTRINFO_ENUM
namespace llvm {

namespace RISCV {
  enum {
    PHI	= 0,
    INLINEASM	= 1,
    CFI_INSTRUCTION	= 2,
    EH_LABEL	= 3,
    GC_LABEL	= 4,
    ANNOTATION_LABEL	= 5,
    KILL	= 6,
    EXTRACT_SUBREG	= 7,
    INSERT_SUBREG	= 8,
    IMPLICIT_DEF	= 9,
    SUBREG_TO_REG	= 10,
    COPY_TO_REGCLASS	= 11,
    DBG_VALUE	= 12,
    DBG_LABEL	= 13,
    REG_SEQUENCE	= 14,
    COPY	= 15,
    BUNDLE	= 16,
    LIFETIME_START	= 17,
    LIFETIME_END	= 18,
    STACKMAP	= 19,
    FENTRY_CALL	= 20,
    PATCHPOINT	= 21,
    LOAD_STACK_GUARD	= 22,
    STATEPOINT	= 23,
    LOCAL_ESCAPE	= 24,
    FAULTING_OP	= 25,
    PATCHABLE_OP	= 26,
    PATCHABLE_FUNCTION_ENTER	= 27,
    PATCHABLE_RET	= 28,
    PATCHABLE_FUNCTION_EXIT	= 29,
    PATCHABLE_TAIL_CALL	= 30,
    PATCHABLE_EVENT_CALL	= 31,
    PATCHABLE_TYPED_EVENT_CALL	= 32,
    ICALL_BRANCH_FUNNEL	= 33,
    G_ADD	= 34,
    G_SUB	= 35,
    G_MUL	= 36,
    G_SDIV	= 37,
    G_UDIV	= 38,
    G_SREM	= 39,
    G_UREM	= 40,
    G_AND	= 41,
    G_OR	= 42,
    G_XOR	= 43,
    G_IMPLICIT_DEF	= 44,
    G_PHI	= 45,
    G_FRAME_INDEX	= 46,
    G_GLOBAL_VALUE	= 47,
    G_EXTRACT	= 48,
    G_UNMERGE_VALUES	= 49,
    G_INSERT	= 50,
    G_MERGE_VALUES	= 51,
    G_BUILD_VECTOR	= 52,
    G_BUILD_VECTOR_TRUNC	= 53,
    G_CONCAT_VECTORS	= 54,
    G_PTRTOINT	= 55,
    G_INTTOPTR	= 56,
    G_BITCAST	= 57,
    G_INTRINSIC_TRUNC	= 58,
    G_INTRINSIC_ROUND	= 59,
    G_LOAD	= 60,
    G_SEXTLOAD	= 61,
    G_ZEXTLOAD	= 62,
    G_STORE	= 63,
    G_ATOMIC_CMPXCHG_WITH_SUCCESS	= 64,
    G_ATOMIC_CMPXCHG	= 65,
    G_ATOMICRMW_XCHG	= 66,
    G_ATOMICRMW_ADD	= 67,
    G_ATOMICRMW_SUB	= 68,
    G_ATOMICRMW_AND	= 69,
    G_ATOMICRMW_NAND	= 70,
    G_ATOMICRMW_OR	= 71,
    G_ATOMICRMW_XOR	= 72,
    G_ATOMICRMW_MAX	= 73,
    G_ATOMICRMW_MIN	= 74,
    G_ATOMICRMW_UMAX	= 75,
    G_ATOMICRMW_UMIN	= 76,
    G_BRCOND	= 77,
    G_BRINDIRECT	= 78,
    G_INTRINSIC	= 79,
    G_INTRINSIC_W_SIDE_EFFECTS	= 80,
    G_ANYEXT	= 81,
    G_TRUNC	= 82,
    G_CONSTANT	= 83,
    G_FCONSTANT	= 84,
    G_VASTART	= 85,
    G_VAARG	= 86,
    G_SEXT	= 87,
    G_ZEXT	= 88,
    G_SHL	= 89,
    G_LSHR	= 90,
    G_ASHR	= 91,
    G_ICMP	= 92,
    G_FCMP	= 93,
    G_SELECT	= 94,
    G_UADDO	= 95,
    G_UADDE	= 96,
    G_USUBO	= 97,
    G_USUBE	= 98,
    G_SADDO	= 99,
    G_SADDE	= 100,
    G_SSUBO	= 101,
    G_SSUBE	= 102,
    G_UMULO	= 103,
    G_SMULO	= 104,
    G_UMULH	= 105,
    G_SMULH	= 106,
    G_FADD	= 107,
    G_FSUB	= 108,
    G_FMUL	= 109,
    G_FMA	= 110,
    G_FDIV	= 111,
    G_FREM	= 112,
    G_FPOW	= 113,
    G_FEXP	= 114,
    G_FEXP2	= 115,
    G_FLOG	= 116,
    G_FLOG2	= 117,
    G_FLOG10	= 118,
    G_FNEG	= 119,
    G_FPEXT	= 120,
    G_FPTRUNC	= 121,
    G_FPTOSI	= 122,
    G_FPTOUI	= 123,
    G_SITOFP	= 124,
    G_UITOFP	= 125,
    G_FABS	= 126,
    G_GEP	= 127,
    G_PTR_MASK	= 128,
    G_BR	= 129,
    G_INSERT_VECTOR_ELT	= 130,
    G_EXTRACT_VECTOR_ELT	= 131,
    G_SHUFFLE_VECTOR	= 132,
    G_CTTZ	= 133,
    G_CTTZ_ZERO_UNDEF	= 134,
    G_CTLZ	= 135,
    G_CTLZ_ZERO_UNDEF	= 136,
    G_CTPOP	= 137,
    G_BSWAP	= 138,
    G_FCEIL	= 139,
    G_ADDRSPACE_CAST	= 140,
    G_BLOCK_ADDR	= 141,
    ADJCALLSTACKDOWN	= 142,
    ADJCALLSTACKUP	= 143,
    BuildPairF64Pseudo	= 144,
    PseudoAtomicLoadNand32	= 145,
    PseudoBR	= 146,
    PseudoBRIND	= 147,
    PseudoCALL	= 148,
    PseudoCALLIndirect	= 149,
    PseudoCmpXchg32	= 150,
    PseudoLI	= 151,
    PseudoLLA	= 152,
    PseudoMaskedAtomicLoadAdd32	= 153,
    PseudoMaskedAtomicLoadMax32	= 154,
    PseudoMaskedAtomicLoadMin32	= 155,
    PseudoMaskedAtomicLoadNand32	= 156,
    PseudoMaskedAtomicLoadSub32	= 157,
    PseudoMaskedAtomicLoadUMax32	= 158,
    PseudoMaskedAtomicLoadUMin32	= 159,
    PseudoMaskedAtomicSwap32	= 160,
    PseudoMaskedCmpXchg32	= 161,
    PseudoRET	= 162,
    PseudoTAIL	= 163,
    PseudoTAILIndirect	= 164,
    Select_FPR32_Using_CC_GPR	= 165,
    Select_FPR64_Using_CC_GPR	= 166,
    Select_GPR_Using_CC_GPR	= 167,
    SplitF64Pseudo	= 168,
    ADD	= 169,
    ADDI	= 170,
    ADDIW	= 171,
    ADDW	= 172,
    AMOADD_D	= 173,
    AMOADD_D_AQ	= 174,
    AMOADD_D_AQ_RL	= 175,
    AMOADD_D_RL	= 176,
    AMOADD_W	= 177,
    AMOADD_W_AQ	= 178,
    AMOADD_W_AQ_RL	= 179,
    AMOADD_W_RL	= 180,
    AMOAND_D	= 181,
    AMOAND_D_AQ	= 182,
    AMOAND_D_AQ_RL	= 183,
    AMOAND_D_RL	= 184,
    AMOAND_W	= 185,
    AMOAND_W_AQ	= 186,
    AMOAND_W_AQ_RL	= 187,
    AMOAND_W_RL	= 188,
    AMOMAXU_D	= 189,
    AMOMAXU_D_AQ	= 190,
    AMOMAXU_D_AQ_RL	= 191,
    AMOMAXU_D_RL	= 192,
    AMOMAXU_W	= 193,
    AMOMAXU_W_AQ	= 194,
    AMOMAXU_W_AQ_RL	= 195,
    AMOMAXU_W_RL	= 196,
    AMOMAX_D	= 197,
    AMOMAX_D_AQ	= 198,
    AMOMAX_D_AQ_RL	= 199,
    AMOMAX_D_RL	= 200,
    AMOMAX_W	= 201,
    AMOMAX_W_AQ	= 202,
    AMOMAX_W_AQ_RL	= 203,
    AMOMAX_W_RL	= 204,
    AMOMINU_D	= 205,
    AMOMINU_D_AQ	= 206,
    AMOMINU_D_AQ_RL	= 207,
    AMOMINU_D_RL	= 208,
    AMOMINU_W	= 209,
    AMOMINU_W_AQ	= 210,
    AMOMINU_W_AQ_RL	= 211,
    AMOMINU_W_RL	= 212,
    AMOMIN_D	= 213,
    AMOMIN_D_AQ	= 214,
    AMOMIN_D_AQ_RL	= 215,
    AMOMIN_D_RL	= 216,
    AMOMIN_W	= 217,
    AMOMIN_W_AQ	= 218,
    AMOMIN_W_AQ_RL	= 219,
    AMOMIN_W_RL	= 220,
    AMOOR_D	= 221,
    AMOOR_D_AQ	= 222,
    AMOOR_D_AQ_RL	= 223,
    AMOOR_D_RL	= 224,
    AMOOR_W	= 225,
    AMOOR_W_AQ	= 226,
    AMOOR_W_AQ_RL	= 227,
    AMOOR_W_RL	= 228,
    AMOSWAP_D	= 229,
    AMOSWAP_D_AQ	= 230,
    AMOSWAP_D_AQ_RL	= 231,
    AMOSWAP_D_RL	= 232,
    AMOSWAP_W	= 233,
    AMOSWAP_W_AQ	= 234,
    AMOSWAP_W_AQ_RL	= 235,
    AMOSWAP_W_RL	= 236,
    AMOXOR_D	= 237,
    AMOXOR_D_AQ	= 238,
    AMOXOR_D_AQ_RL	= 239,
    AMOXOR_D_RL	= 240,
    AMOXOR_W	= 241,
    AMOXOR_W_AQ	= 242,
    AMOXOR_W_AQ_RL	= 243,
    AMOXOR_W_RL	= 244,
    AND	= 245,
    ANDI	= 246,
    AUIPC	= 247,
    BEQ	= 248,
    BGE	= 249,
    BGEU	= 250,
    BLT	= 251,
    BLTU	= 252,
    BNE	= 253,
    CSRRC	= 254,
    CSRRCI	= 255,
    CSRRS	= 256,
    CSRRSI	= 257,
    CSRRW	= 258,
    CSRRWI	= 259,
    C_ADD	= 260,
    C_ADDI	= 261,
    C_ADDI16SP	= 262,
    C_ADDI4SPN	= 263,
    C_ADDIW	= 264,
    C_ADDW	= 265,
    C_AND	= 266,
    C_ANDI	= 267,
    C_BEQZ	= 268,
    C_BNEZ	= 269,
    C_EBREAK	= 270,
    C_FLD	= 271,
    C_FLDSP	= 272,
    C_FLW	= 273,
    C_FLWSP	= 274,
    C_FSD	= 275,
    C_FSDSP	= 276,
    C_FSW	= 277,
    C_FSWSP	= 278,
    C_J	= 279,
    C_JAL	= 280,
    C_JALR	= 281,
    C_JR	= 282,
    C_LD	= 283,
    C_LDSP	= 284,
    C_LI	= 285,
    C_LUI	= 286,
    C_LW	= 287,
    C_LWSP	= 288,
    C_MV	= 289,
    C_NOP	= 290,
    C_OR	= 291,
    C_SD	= 292,
    C_SDSP	= 293,
    C_SLLI	= 294,
    C_SRAI	= 295,
    C_SRLI	= 296,
    C_SUB	= 297,
    C_SUBW	= 298,
    C_SW	= 299,
    C_SWSP	= 300,
    C_UNIMP	= 301,
    C_XOR	= 302,
    DIV	= 303,
    DIVU	= 304,
    DIVUW	= 305,
    DIVW	= 306,
    EBREAK	= 307,
    ECALL	= 308,
    FADD_D	= 309,
    FADD_S	= 310,
    FCLASS_D	= 311,
    FCLASS_S	= 312,
    FCVT_D_L	= 313,
    FCVT_D_LU	= 314,
    FCVT_D_S	= 315,
    FCVT_D_W	= 316,
    FCVT_D_WU	= 317,
    FCVT_LU_D	= 318,
    FCVT_LU_S	= 319,
    FCVT_L_D	= 320,
    FCVT_L_S	= 321,
    FCVT_S_D	= 322,
    FCVT_S_L	= 323,
    FCVT_S_LU	= 324,
    FCVT_S_W	= 325,
    FCVT_S_WU	= 326,
    FCVT_WU_D	= 327,
    FCVT_WU_S	= 328,
    FCVT_W_D	= 329,
    FCVT_W_S	= 330,
    FDIV_D	= 331,
    FDIV_S	= 332,
    FENCE	= 333,
    FENCE_I	= 334,
    FENCE_TSO	= 335,
    FEQ_D	= 336,
    FEQ_S	= 337,
    FLD	= 338,
    FLE_D	= 339,
    FLE_S	= 340,
    FLT_D	= 341,
    FLT_S	= 342,
    FLW	= 343,
    FMADD_D	= 344,
    FMADD_S	= 345,
    FMAX_D	= 346,
    FMAX_S	= 347,
    FMIN_D	= 348,
    FMIN_S	= 349,
    FMSUB_D	= 350,
    FMSUB_S	= 351,
    FMUL_D	= 352,
    FMUL_S	= 353,
    FMV_D_X	= 354,
    FMV_W_X	= 355,
    FMV_X_D	= 356,
    FMV_X_W	= 357,
    FNMADD_D	= 358,
    FNMADD_S	= 359,
    FNMSUB_D	= 360,
    FNMSUB_S	= 361,
    FSD	= 362,
    FSGNJN_D	= 363,
    FSGNJN_S	= 364,
    FSGNJX_D	= 365,
    FSGNJX_S	= 366,
    FSGNJ_D	= 367,
    FSGNJ_S	= 368,
    FSQRT_D	= 369,
    FSQRT_S	= 370,
    FSUB_D	= 371,
    FSUB_S	= 372,
    FSW	= 373,
    JAL	= 374,
    JALR	= 375,
    LB	= 376,
    LBU	= 377,
    LD	= 378,
    LH	= 379,
    LHU	= 380,
    LR_D	= 381,
    LR_D_AQ	= 382,
    LR_D_AQ_RL	= 383,
    LR_D_RL	= 384,
    LR_W	= 385,
    LR_W_AQ	= 386,
    LR_W_AQ_RL	= 387,
    LR_W_RL	= 388,
    LUI	= 389,
    LW	= 390,
    LWU	= 391,
    MRET	= 392,
    MUL	= 393,
    MULH	= 394,
    MULHSU	= 395,
    MULHU	= 396,
    MULW	= 397,
    OR	= 398,
    ORI	= 399,
    REM	= 400,
    REMU	= 401,
    REMUW	= 402,
    REMW	= 403,
    SB	= 404,
    SC_D	= 405,
    SC_D_AQ	= 406,
    SC_D_AQ_RL	= 407,
    SC_D_RL	= 408,
    SC_W	= 409,
    SC_W_AQ	= 410,
    SC_W_AQ_RL	= 411,
    SC_W_RL	= 412,
    SD	= 413,
    SFENCE_VMA	= 414,
    SH	= 415,
    SLL	= 416,
    SLLI	= 417,
    SLLIW	= 418,
    SLLW	= 419,
    SLT	= 420,
    SLTI	= 421,
    SLTIU	= 422,
    SLTU	= 423,
    SRA	= 424,
    SRAI	= 425,
    SRAIW	= 426,
    SRAW	= 427,
    SRET	= 428,
    SRL	= 429,
    SRLI	= 430,
    SRLIW	= 431,
    SRLW	= 432,
    SUB	= 433,
    SUBW	= 434,
    SW	= 435,
    UNIMP	= 436,
    URET	= 437,
    WFI	= 438,
    XOR	= 439,
    XORI	= 440,
    INSTRUCTION_LIST_END = 441
  };

} // end RISCV namespace
} // end llvm namespace
#endif // GET_INSTRINFO_ENUM

#ifdef GET_INSTRINFO_SCHED_ENUM
#undef GET_INSTRINFO_SCHED_ENUM
namespace llvm {

namespace RISCV {
namespace Sched {
  enum {
    NoInstrModel	= 0,
    SCHED_LIST_END = 1
  };
} // end Sched namespace
} // end RISCV namespace
} // end llvm namespace
#endif // GET_INSTRINFO_SCHED_ENUM

#ifdef GET_INSTRINFO_MC_DESC
#undef GET_INSTRINFO_MC_DESC
namespace llvm {

static const MCPhysReg ImplicitList1[] = { RISCV::X2, 0 };
static const MCPhysReg ImplicitList2[] = { RISCV::X1, 0 };

static const MCOperandInfo OperandInfo2[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo3[] = { { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo4[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo5[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo6[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo7[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo8[] = { { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo9[] = { { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo10[] = { { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo11[] = { { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo12[] = { { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, { 0, 0|(1<<MCOI::LookupPtrRegClass), MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo13[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo14[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo15[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo16[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo17[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, };
static const MCOperandInfo OperandInfo18[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo19[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo20[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_2, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo21[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo22[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo23[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, };
static const MCOperandInfo OperandInfo24[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, };
static const MCOperandInfo OperandInfo25[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo26[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, };
static const MCOperandInfo OperandInfo27[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo28[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_2, 0 }, };
static const MCOperandInfo OperandInfo29[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_2, 0 }, };
static const MCOperandInfo OperandInfo30[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_2, 0 }, };
static const MCOperandInfo OperandInfo31[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo32[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo33[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo34[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo35[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo36[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo37[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo38[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo39[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, (1 << MCOI::EARLY_CLOBBER) }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_IMMEDIATE, 0 }, };
static const MCOperandInfo OperandInfo40[] = { { RISCV::GPRTCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo41[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo42[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo43[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo44[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo45[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo46[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo47[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo48[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo49[] = { { RISCV::GPRNoX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRNoX0RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { RISCV::GPRNoX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo50[] = { { RISCV::GPRNoX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRNoX0RegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo51[] = { { RISCV::SPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::SPRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo52[] = { { RISCV::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::SPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo53[] = { { RISCV::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { RISCV::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo54[] = { { RISCV::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, ((0 << 16) | (1 << MCOI::TIED_TO)) }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo55[] = { { RISCV::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo56[] = { { RISCV::FPR64CRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo57[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::SPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo58[] = { { RISCV::FPR32CRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo59[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::SPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo60[] = { { RISCV::GPRNoX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo61[] = { { RISCV::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRCRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo62[] = { { RISCV::GPRNoX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::SPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo63[] = { { RISCV::GPRNoX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo64[] = { { RISCV::GPRNoX0X2RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo65[] = { { RISCV::GPRNoX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRNoX0RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo66[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::SPRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo67[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo68[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo69[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo70[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo71[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo72[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo73[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo74[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo75[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo76[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo77[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo78[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo79[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo80[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo81[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo82[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo83[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo84[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo85[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo86[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo87[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };

extern const MCInstrDesc RISCVInsts[] = {
  { 0,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #0 = PHI
  { 1,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #1 = INLINEASM
  { 2,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #2 = CFI_INSTRUCTION
  { 3,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #3 = EH_LABEL
  { 4,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #4 = GC_LABEL
  { 5,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::NotDuplicable), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #5 = ANNOTATION_LABEL
  { 6,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #6 = KILL
  { 7,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo4, -1 ,nullptr },  // Inst #7 = EXTRACT_SUBREG
  { 8,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo5, -1 ,nullptr },  // Inst #8 = INSERT_SUBREG
  { 9,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Rematerializable)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #9 = IMPLICIT_DEF
  { 10,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo6, -1 ,nullptr },  // Inst #10 = SUBREG_TO_REG
  { 11,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo4, -1 ,nullptr },  // Inst #11 = COPY_TO_REGCLASS
  { 12,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #12 = DBG_VALUE
  { 13,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #13 = DBG_LABEL
  { 14,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo7, -1 ,nullptr },  // Inst #14 = REG_SEQUENCE
  { 15,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo7, -1 ,nullptr },  // Inst #15 = COPY
  { 16,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #16 = BUNDLE
  { 17,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #17 = LIFETIME_START
  { 18,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #18 = LIFETIME_END
  { 19,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo8, -1 ,nullptr },  // Inst #19 = STACKMAP
  { 20,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #20 = FENTRY_CALL
  { 21,	6,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo9, -1 ,nullptr },  // Inst #21 = PATCHPOINT
  { 22,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL, nullptr, nullptr, OperandInfo10, -1 ,nullptr },  // Inst #22 = LOAD_STACK_GUARD
  { 23,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #23 = STATEPOINT
  { 24,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo11, -1 ,nullptr },  // Inst #24 = LOCAL_ESCAPE
  { 25,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #25 = FAULTING_OP
  { 26,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #26 = PATCHABLE_OP
  { 27,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #27 = PATCHABLE_FUNCTION_ENTER
  { 28,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #28 = PATCHABLE_RET
  { 29,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #29 = PATCHABLE_FUNCTION_EXIT
  { 30,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #30 = PATCHABLE_TAIL_CALL
  { 31,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo11, -1 ,nullptr },  // Inst #31 = PATCHABLE_EVENT_CALL
  { 32,	3,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #32 = PATCHABLE_TYPED_EVENT_CALL
  { 33,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #33 = ICALL_BRANCH_FUNNEL
  { 34,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #34 = G_ADD
  { 35,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #35 = G_SUB
  { 36,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #36 = G_MUL
  { 37,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #37 = G_SDIV
  { 38,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #38 = G_UDIV
  { 39,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #39 = G_SREM
  { 40,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #40 = G_UREM
  { 41,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #41 = G_AND
  { 42,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #42 = G_OR
  { 43,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #43 = G_XOR
  { 44,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #44 = G_IMPLICIT_DEF
  { 45,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #45 = G_PHI
  { 46,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #46 = G_FRAME_INDEX
  { 47,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #47 = G_GLOBAL_VALUE
  { 48,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #48 = G_EXTRACT
  { 49,	2,	2,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #49 = G_UNMERGE_VALUES
  { 50,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #50 = G_INSERT
  { 51,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #51 = G_MERGE_VALUES
  { 52,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #52 = G_BUILD_VECTOR
  { 53,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #53 = G_BUILD_VECTOR_TRUNC
  { 54,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #54 = G_CONCAT_VECTORS
  { 55,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #55 = G_PTRTOINT
  { 56,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #56 = G_INTTOPTR
  { 57,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #57 = G_BITCAST
  { 58,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #58 = G_INTRINSIC_TRUNC
  { 59,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #59 = G_INTRINSIC_ROUND
  { 60,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #60 = G_LOAD
  { 61,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #61 = G_SEXTLOAD
  { 62,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #62 = G_ZEXTLOAD
  { 63,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #63 = G_STORE
  { 64,	5,	2,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #64 = G_ATOMIC_CMPXCHG_WITH_SUCCESS
  { 65,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #65 = G_ATOMIC_CMPXCHG
  { 66,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #66 = G_ATOMICRMW_XCHG
  { 67,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #67 = G_ATOMICRMW_ADD
  { 68,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #68 = G_ATOMICRMW_SUB
  { 69,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #69 = G_ATOMICRMW_AND
  { 70,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #70 = G_ATOMICRMW_NAND
  { 71,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #71 = G_ATOMICRMW_OR
  { 72,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #72 = G_ATOMICRMW_XOR
  { 73,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #73 = G_ATOMICRMW_MAX
  { 74,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #74 = G_ATOMICRMW_MIN
  { 75,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #75 = G_ATOMICRMW_UMAX
  { 76,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #76 = G_ATOMICRMW_UMIN
  { 77,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #77 = G_BRCOND
  { 78,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #78 = G_BRINDIRECT
  { 79,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #79 = G_INTRINSIC
  { 80,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #80 = G_INTRINSIC_W_SIDE_EFFECTS
  { 81,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #81 = G_ANYEXT
  { 82,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #82 = G_TRUNC
  { 83,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #83 = G_CONSTANT
  { 84,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #84 = G_FCONSTANT
  { 85,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #85 = G_VASTART
  { 86,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #86 = G_VAARG
  { 87,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #87 = G_SEXT
  { 88,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #88 = G_ZEXT
  { 89,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #89 = G_SHL
  { 90,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #90 = G_LSHR
  { 91,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #91 = G_ASHR
  { 92,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #92 = G_ICMP
  { 93,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #93 = G_FCMP
  { 94,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #94 = G_SELECT
  { 95,	4,	2,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #95 = G_UADDO
  { 96,	5,	2,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #96 = G_UADDE
  { 97,	4,	2,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #97 = G_USUBO
  { 98,	5,	2,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #98 = G_USUBE
  { 99,	4,	2,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #99 = G_SADDO
  { 100,	5,	2,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #100 = G_SADDE
  { 101,	4,	2,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #101 = G_SSUBO
  { 102,	5,	2,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #102 = G_SSUBE
  { 103,	4,	2,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #103 = G_UMULO
  { 104,	4,	2,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #104 = G_SMULO
  { 105,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #105 = G_UMULH
  { 106,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #106 = G_SMULH
  { 107,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #107 = G_FADD
  { 108,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #108 = G_FSUB
  { 109,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #109 = G_FMUL
  { 110,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #110 = G_FMA
  { 111,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #111 = G_FDIV
  { 112,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #112 = G_FREM
  { 113,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #113 = G_FPOW
  { 114,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #114 = G_FEXP
  { 115,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #115 = G_FEXP2
  { 116,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #116 = G_FLOG
  { 117,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #117 = G_FLOG2
  { 118,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #118 = G_FLOG10
  { 119,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #119 = G_FNEG
  { 120,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #120 = G_FPEXT
  { 121,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #121 = G_FPTRUNC
  { 122,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #122 = G_FPTOSI
  { 123,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #123 = G_FPTOUI
  { 124,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #124 = G_SITOFP
  { 125,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #125 = G_UITOFP
  { 126,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #126 = G_FABS
  { 127,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #127 = G_GEP
  { 128,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #128 = G_PTR_MASK
  { 129,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #129 = G_BR
  { 130,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #130 = G_INSERT_VECTOR_ELT
  { 131,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #131 = G_EXTRACT_VECTOR_ELT
  { 132,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #132 = G_SHUFFLE_VECTOR
  { 133,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #133 = G_CTTZ
  { 134,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #134 = G_CTTZ_ZERO_UNDEF
  { 135,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #135 = G_CTLZ
  { 136,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #136 = G_CTLZ_ZERO_UNDEF
  { 137,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #137 = G_CTPOP
  { 138,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #138 = G_BSWAP
  { 139,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #139 = G_FCEIL
  { 140,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #140 = G_ADDRSPACE_CAST
  { 141,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #141 = G_BLOCK_ADDR
  { 142,	2,	0,	4,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo8, -1 ,nullptr },  // Inst #142 = ADJCALLSTACKDOWN
  { 143,	2,	0,	4,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo8, -1 ,nullptr },  // Inst #143 = ADJCALLSTACKUP
  { 144,	3,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #144 = BuildPairF64Pseudo
  { 145,	5,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #145 = PseudoAtomicLoadNand32
  { 146,	1,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #146 = PseudoBR
  { 147,	2,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, ImplicitList2, OperandInfo33, -1 ,nullptr },  // Inst #147 = PseudoBRIND
  { 148,	1,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call), 0x0ULL, nullptr, ImplicitList2, OperandInfo2, -1 ,nullptr },  // Inst #148 = PseudoCALL
  { 149,	1,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call), 0x0ULL, nullptr, ImplicitList2, OperandInfo34, -1 ,nullptr },  // Inst #149 = PseudoCALLIndirect
  { 150,	6,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #150 = PseudoCmpXchg32
  { 151,	2,	1,	32,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #151 = PseudoLI
  { 152,	2,	1,	4,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #152 = PseudoLLA
  { 153,	6,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #153 = PseudoMaskedAtomicLoadAdd32
  { 154,	8,	3,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #154 = PseudoMaskedAtomicLoadMax32
  { 155,	8,	3,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #155 = PseudoMaskedAtomicLoadMin32
  { 156,	6,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #156 = PseudoMaskedAtomicLoadNand32
  { 157,	6,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #157 = PseudoMaskedAtomicLoadSub32
  { 158,	7,	3,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #158 = PseudoMaskedAtomicLoadUMax32
  { 159,	7,	3,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #159 = PseudoMaskedAtomicLoadUMin32
  { 160,	6,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #160 = PseudoMaskedAtomicSwap32
  { 161,	7,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #161 = PseudoMaskedCmpXchg32
  { 162,	0,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #162 = PseudoRET
  { 163,	1,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL, ImplicitList1, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #163 = PseudoTAIL
  { 164,	1,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL, ImplicitList1, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #164 = PseudoTAILIndirect
  { 165,	6,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #165 = Select_FPR32_Using_CC_GPR
  { 166,	6,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo42, -1 ,nullptr },  // Inst #166 = Select_FPR64_Using_CC_GPR
  { 167,	6,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #167 = Select_GPR_Using_CC_GPR
  { 168,	3,	2,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo44, -1 ,nullptr },  // Inst #168 = SplitF64Pseudo
  { 169,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #169 = ADD
  { 170,	3,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable), 0x3ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #170 = ADDI
  { 171,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #171 = ADDIW
  { 172,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #172 = ADDW
  { 173,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #173 = AMOADD_D
  { 174,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #174 = AMOADD_D_AQ
  { 175,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #175 = AMOADD_D_AQ_RL
  { 176,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #176 = AMOADD_D_RL
  { 177,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #177 = AMOADD_W
  { 178,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #178 = AMOADD_W_AQ
  { 179,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #179 = AMOADD_W_AQ_RL
  { 180,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #180 = AMOADD_W_RL
  { 181,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #181 = AMOAND_D
  { 182,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #182 = AMOAND_D_AQ
  { 183,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #183 = AMOAND_D_AQ_RL
  { 184,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #184 = AMOAND_D_RL
  { 185,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #185 = AMOAND_W
  { 186,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #186 = AMOAND_W_AQ
  { 187,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #187 = AMOAND_W_AQ_RL
  { 188,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #188 = AMOAND_W_RL
  { 189,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #189 = AMOMAXU_D
  { 190,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #190 = AMOMAXU_D_AQ
  { 191,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #191 = AMOMAXU_D_AQ_RL
  { 192,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #192 = AMOMAXU_D_RL
  { 193,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #193 = AMOMAXU_W
  { 194,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #194 = AMOMAXU_W_AQ
  { 195,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #195 = AMOMAXU_W_AQ_RL
  { 196,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #196 = AMOMAXU_W_RL
  { 197,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #197 = AMOMAX_D
  { 198,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #198 = AMOMAX_D_AQ
  { 199,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #199 = AMOMAX_D_AQ_RL
  { 200,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #200 = AMOMAX_D_RL
  { 201,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #201 = AMOMAX_W
  { 202,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #202 = AMOMAX_W_AQ
  { 203,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #203 = AMOMAX_W_AQ_RL
  { 204,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #204 = AMOMAX_W_RL
  { 205,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #205 = AMOMINU_D
  { 206,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #206 = AMOMINU_D_AQ
  { 207,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #207 = AMOMINU_D_AQ_RL
  { 208,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #208 = AMOMINU_D_RL
  { 209,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #209 = AMOMINU_W
  { 210,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #210 = AMOMINU_W_AQ
  { 211,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #211 = AMOMINU_W_AQ_RL
  { 212,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #212 = AMOMINU_W_RL
  { 213,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #213 = AMOMIN_D
  { 214,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #214 = AMOMIN_D_AQ
  { 215,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #215 = AMOMIN_D_AQ_RL
  { 216,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #216 = AMOMIN_D_RL
  { 217,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #217 = AMOMIN_W
  { 218,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #218 = AMOMIN_W_AQ
  { 219,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #219 = AMOMIN_W_AQ_RL
  { 220,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #220 = AMOMIN_W_RL
  { 221,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #221 = AMOOR_D
  { 222,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #222 = AMOOR_D_AQ
  { 223,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #223 = AMOOR_D_AQ_RL
  { 224,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #224 = AMOOR_D_RL
  { 225,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #225 = AMOOR_W
  { 226,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #226 = AMOOR_W_AQ
  { 227,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #227 = AMOOR_W_AQ_RL
  { 228,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #228 = AMOOR_W_RL
  { 229,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #229 = AMOSWAP_D
  { 230,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #230 = AMOSWAP_D_AQ
  { 231,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #231 = AMOSWAP_D_AQ_RL
  { 232,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #232 = AMOSWAP_D_RL
  { 233,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #233 = AMOSWAP_W
  { 234,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #234 = AMOSWAP_W_AQ
  { 235,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #235 = AMOSWAP_W_AQ_RL
  { 236,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #236 = AMOSWAP_W_RL
  { 237,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #237 = AMOXOR_D
  { 238,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #238 = AMOXOR_D_AQ
  { 239,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #239 = AMOXOR_D_AQ_RL
  { 240,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #240 = AMOXOR_D_RL
  { 241,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #241 = AMOXOR_W
  { 242,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #242 = AMOXOR_W_AQ
  { 243,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #243 = AMOXOR_W_AQ_RL
  { 244,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #244 = AMOXOR_W_RL
  { 245,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #245 = AND
  { 246,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #246 = ANDI
  { 247,	2,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable), 0x6ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #247 = AUIPC
  { 248,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #248 = BEQ
  { 249,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #249 = BGE
  { 250,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #250 = BGEU
  { 251,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #251 = BLT
  { 252,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #252 = BLTU
  { 253,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #253 = BNE
  { 254,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #254 = CSRRC
  { 255,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #255 = CSRRCI
  { 256,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #256 = CSRRS
  { 257,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #257 = CSRRSI
  { 258,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #258 = CSRRW
  { 259,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #259 = CSRRWI
  { 260,	3,	1,	2,	0,	0, 0x8ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #260 = C_ADD
  { 261,	3,	1,	2,	0,	0, 0x9ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #261 = C_ADDI
  { 262,	3,	1,	2,	0,	0, 0x9ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #262 = C_ADDI16SP
  { 263,	3,	1,	2,	0,	0, 0xbULL, ImplicitList1, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #263 = C_ADDI4SPN
  { 264,	3,	1,	2,	0,	0, 0x9ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #264 = C_ADDIW
  { 265,	3,	1,	2,	0,	0, 0xeULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #265 = C_ADDW
  { 266,	3,	1,	2,	0,	0, 0xeULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #266 = C_AND
  { 267,	3,	1,	2,	0,	0, 0xfULL, nullptr, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #267 = C_ANDI
  { 268,	2,	0,	2,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfULL, nullptr, nullptr, OperandInfo55, -1 ,nullptr },  // Inst #268 = C_BEQZ
  { 269,	2,	0,	2,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0xfULL, nullptr, nullptr, OperandInfo55, -1 ,nullptr },  // Inst #269 = C_BNEZ
  { 270,	0,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x8ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #270 = C_EBREAK
  { 271,	3,	1,	2,	0,	0|(1ULL<<MCID::MayLoad), 0xcULL, nullptr, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #271 = C_FLD
  { 272,	3,	1,	2,	0,	0|(1ULL<<MCID::MayLoad), 0x9ULL, nullptr, nullptr, OperandInfo57, -1 ,nullptr },  // Inst #272 = C_FLDSP
  { 273,	3,	1,	2,	0,	0|(1ULL<<MCID::MayLoad), 0xcULL, nullptr, nullptr, OperandInfo58, -1 ,nullptr },  // Inst #273 = C_FLW
  { 274,	3,	1,	2,	0,	0|(1ULL<<MCID::MayLoad), 0x9ULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #274 = C_FLWSP
  { 275,	3,	0,	2,	0,	0|(1ULL<<MCID::MayStore), 0xdULL, nullptr, nullptr, OperandInfo56, -1 ,nullptr },  // Inst #275 = C_FSD
  { 276,	3,	0,	2,	0,	0|(1ULL<<MCID::MayStore), 0xaULL, nullptr, nullptr, OperandInfo57, -1 ,nullptr },  // Inst #276 = C_FSDSP
  { 277,	3,	0,	2,	0,	0|(1ULL<<MCID::MayStore), 0xdULL, nullptr, nullptr, OperandInfo58, -1 ,nullptr },  // Inst #277 = C_FSW
  { 278,	3,	0,	2,	0,	0|(1ULL<<MCID::MayStore), 0xaULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #278 = C_FSWSP
  { 279,	1,	0,	2,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x10ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #279 = C_J
  { 280,	1,	0,	2,	0,	0|(1ULL<<MCID::Call), 0x10ULL, nullptr, ImplicitList2, OperandInfo2, -1 ,nullptr },  // Inst #280 = C_JAL
  { 281,	1,	0,	2,	0,	0|(1ULL<<MCID::Call), 0x8ULL, nullptr, ImplicitList2, OperandInfo60, -1 ,nullptr },  // Inst #281 = C_JALR
  { 282,	1,	0,	2,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x8ULL, nullptr, nullptr, OperandInfo60, -1 ,nullptr },  // Inst #282 = C_JR
  { 283,	3,	1,	2,	0,	0|(1ULL<<MCID::MayLoad), 0xcULL, nullptr, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #283 = C_LD
  { 284,	3,	1,	2,	0,	0|(1ULL<<MCID::MayLoad), 0x9ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #284 = C_LDSP
  { 285,	2,	1,	2,	0,	0, 0x9ULL, nullptr, nullptr, OperandInfo63, -1 ,nullptr },  // Inst #285 = C_LI
  { 286,	2,	1,	2,	0,	0, 0x9ULL, nullptr, nullptr, OperandInfo64, -1 ,nullptr },  // Inst #286 = C_LUI
  { 287,	3,	1,	2,	0,	0|(1ULL<<MCID::MayLoad), 0xcULL, nullptr, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #287 = C_LW
  { 288,	3,	1,	2,	0,	0|(1ULL<<MCID::MayLoad), 0x9ULL, nullptr, nullptr, OperandInfo62, -1 ,nullptr },  // Inst #288 = C_LWSP
  { 289,	2,	1,	2,	0,	0, 0x8ULL, nullptr, nullptr, OperandInfo65, -1 ,nullptr },  // Inst #289 = C_MV
  { 290,	0,	0,	2,	0,	0, 0x9ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #290 = C_NOP
  { 291,	3,	1,	2,	0,	0, 0xeULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #291 = C_OR
  { 292,	3,	0,	2,	0,	0|(1ULL<<MCID::MayStore), 0xdULL, nullptr, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #292 = C_SD
  { 293,	3,	0,	2,	0,	0|(1ULL<<MCID::MayStore), 0xaULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #293 = C_SDSP
  { 294,	3,	1,	2,	0,	0, 0x9ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #294 = C_SLLI
  { 295,	3,	1,	2,	0,	0, 0xfULL, nullptr, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #295 = C_SRAI
  { 296,	3,	1,	2,	0,	0, 0xfULL, nullptr, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #296 = C_SRLI
  { 297,	3,	1,	2,	0,	0, 0xeULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #297 = C_SUB
  { 298,	3,	1,	2,	0,	0, 0xeULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #298 = C_SUBW
  { 299,	3,	0,	2,	0,	0|(1ULL<<MCID::MayStore), 0xdULL, nullptr, nullptr, OperandInfo61, -1 ,nullptr },  // Inst #299 = C_SW
  { 300,	3,	0,	2,	0,	0|(1ULL<<MCID::MayStore), 0xaULL, nullptr, nullptr, OperandInfo66, -1 ,nullptr },  // Inst #300 = C_SWSP
  { 301,	0,	0,	2,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x11ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #301 = C_UNIMP
  { 302,	3,	1,	2,	0,	0, 0xeULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #302 = C_XOR
  { 303,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #303 = DIV
  { 304,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #304 = DIVU
  { 305,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #305 = DIVUW
  { 306,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #306 = DIVW
  { 307,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #307 = EBREAK
  { 308,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #308 = ECALL
  { 309,	4,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo67, -1 ,nullptr },  // Inst #309 = FADD_D
  { 310,	4,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo68, -1 ,nullptr },  // Inst #310 = FADD_S
  { 311,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo69, -1 ,nullptr },  // Inst #311 = FCLASS_D
  { 312,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #312 = FCLASS_S
  { 313,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo71, -1 ,nullptr },  // Inst #313 = FCVT_D_L
  { 314,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo71, -1 ,nullptr },  // Inst #314 = FCVT_D_LU
  { 315,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo72, -1 ,nullptr },  // Inst #315 = FCVT_D_S
  { 316,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo73, -1 ,nullptr },  // Inst #316 = FCVT_D_W
  { 317,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo73, -1 ,nullptr },  // Inst #317 = FCVT_D_WU
  { 318,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo74, -1 ,nullptr },  // Inst #318 = FCVT_LU_D
  { 319,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo75, -1 ,nullptr },  // Inst #319 = FCVT_LU_S
  { 320,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo74, -1 ,nullptr },  // Inst #320 = FCVT_L_D
  { 321,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo75, -1 ,nullptr },  // Inst #321 = FCVT_L_S
  { 322,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo76, -1 ,nullptr },  // Inst #322 = FCVT_S_D
  { 323,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #323 = FCVT_S_L
  { 324,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #324 = FCVT_S_LU
  { 325,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #325 = FCVT_S_W
  { 326,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #326 = FCVT_S_WU
  { 327,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo74, -1 ,nullptr },  // Inst #327 = FCVT_WU_D
  { 328,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo75, -1 ,nullptr },  // Inst #328 = FCVT_WU_S
  { 329,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo74, -1 ,nullptr },  // Inst #329 = FCVT_W_D
  { 330,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo75, -1 ,nullptr },  // Inst #330 = FCVT_W_S
  { 331,	4,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo67, -1 ,nullptr },  // Inst #331 = FDIV_D
  { 332,	4,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo68, -1 ,nullptr },  // Inst #332 = FDIV_S
  { 333,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo7, -1 ,nullptr },  // Inst #333 = FENCE
  { 334,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #334 = FENCE_I
  { 335,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #335 = FENCE_TSO
  { 336,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #336 = FEQ_D
  { 337,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #337 = FEQ_S
  { 338,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo71, -1 ,nullptr },  // Inst #338 = FLD
  { 339,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #339 = FLE_D
  { 340,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #340 = FLE_S
  { 341,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo78, -1 ,nullptr },  // Inst #341 = FLT_D
  { 342,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo79, -1 ,nullptr },  // Inst #342 = FLT_S
  { 343,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #343 = FLW
  { 344,	5,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #344 = FMADD_D
  { 345,	5,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #345 = FMADD_S
  { 346,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo82, -1 ,nullptr },  // Inst #346 = FMAX_D
  { 347,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #347 = FMAX_S
  { 348,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo82, -1 ,nullptr },  // Inst #348 = FMIN_D
  { 349,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #349 = FMIN_S
  { 350,	5,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #350 = FMSUB_D
  { 351,	5,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #351 = FMSUB_S
  { 352,	4,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo67, -1 ,nullptr },  // Inst #352 = FMUL_D
  { 353,	4,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo68, -1 ,nullptr },  // Inst #353 = FMUL_S
  { 354,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo73, -1 ,nullptr },  // Inst #354 = FMV_D_X
  { 355,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo84, -1 ,nullptr },  // Inst #355 = FMV_W_X
  { 356,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo69, -1 ,nullptr },  // Inst #356 = FMV_X_D
  { 357,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo70, -1 ,nullptr },  // Inst #357 = FMV_X_W
  { 358,	5,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #358 = FNMADD_D
  { 359,	5,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #359 = FNMADD_S
  { 360,	5,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo80, -1 ,nullptr },  // Inst #360 = FNMSUB_D
  { 361,	5,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo81, -1 ,nullptr },  // Inst #361 = FNMSUB_S
  { 362,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, nullptr, OperandInfo71, -1 ,nullptr },  // Inst #362 = FSD
  { 363,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo82, -1 ,nullptr },  // Inst #363 = FSGNJN_D
  { 364,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #364 = FSGNJN_S
  { 365,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo82, -1 ,nullptr },  // Inst #365 = FSGNJX_D
  { 366,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #366 = FSGNJX_S
  { 367,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo82, -1 ,nullptr },  // Inst #367 = FSGNJ_D
  { 368,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo83, -1 ,nullptr },  // Inst #368 = FSGNJ_S
  { 369,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo85, -1 ,nullptr },  // Inst #369 = FSQRT_D
  { 370,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo86, -1 ,nullptr },  // Inst #370 = FSQRT_S
  { 371,	4,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo67, -1 ,nullptr },  // Inst #371 = FSUB_D
  { 372,	4,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo68, -1 ,nullptr },  // Inst #372 = FSUB_S
  { 373,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, nullptr, OperandInfo77, -1 ,nullptr },  // Inst #373 = FSW
  { 374,	2,	1,	4,	0,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::Rematerializable), 0x7ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #374 = JAL
  { 375,	3,	1,	4,	0,	0|(1ULL<<MCID::Call)|(1ULL<<MCID::Rematerializable), 0x3ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #375 = JALR
  { 376,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #376 = LB
  { 377,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #377 = LBU
  { 378,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #378 = LD
  { 379,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #379 = LH
  { 380,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #380 = LHU
  { 381,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #381 = LR_D
  { 382,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #382 = LR_D_AQ
  { 383,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #383 = LR_D_AQ_RL
  { 384,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #384 = LR_D_RL
  { 385,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #385 = LR_W
  { 386,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #386 = LR_W_AQ
  { 387,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #387 = LR_W_AQ_RL
  { 388,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #388 = LR_W_RL
  { 389,	2,	1,	4,	0,	0|(1ULL<<MCID::Rematerializable), 0x6ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #389 = LUI
  { 390,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #390 = LW
  { 391,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #391 = LWU
  { 392,	2,	0,	4,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #392 = MRET
  { 393,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #393 = MUL
  { 394,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #394 = MULH
  { 395,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #395 = MULHSU
  { 396,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #396 = MULHU
  { 397,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #397 = MULW
  { 398,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #398 = OR
  { 399,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #399 = ORI
  { 400,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #400 = REM
  { 401,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #401 = REMU
  { 402,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #402 = REMUW
  { 403,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #403 = REMW
  { 404,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #404 = SB
  { 405,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #405 = SC_D
  { 406,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #406 = SC_D_AQ
  { 407,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #407 = SC_D_AQ_RL
  { 408,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #408 = SC_D_RL
  { 409,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #409 = SC_W
  { 410,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #410 = SC_W_AQ
  { 411,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #411 = SC_W_AQ_RL
  { 412,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #412 = SC_W_RL
  { 413,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #413 = SD
  { 414,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #414 = SFENCE_VMA
  { 415,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #415 = SH
  { 416,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #416 = SLL
  { 417,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #417 = SLLI
  { 418,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #418 = SLLIW
  { 419,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #419 = SLLW
  { 420,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #420 = SLT
  { 421,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #421 = SLTI
  { 422,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #422 = SLTIU
  { 423,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #423 = SLTU
  { 424,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #424 = SRA
  { 425,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #425 = SRAI
  { 426,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #426 = SRAIW
  { 427,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #427 = SRAW
  { 428,	2,	0,	4,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #428 = SRET
  { 429,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #429 = SRL
  { 430,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #430 = SRLI
  { 431,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #431 = SRLIW
  { 432,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #432 = SRLW
  { 433,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #433 = SUB
  { 434,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #434 = SUBW
  { 435,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #435 = SW
  { 436,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #436 = UNIMP
  { 437,	2,	0,	4,	0,	0|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #437 = URET
  { 438,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x1ULL, nullptr, nullptr, OperandInfo87, -1 ,nullptr },  // Inst #438 = WFI
  { 439,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #439 = XOR
  { 440,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #440 = XORI
};

extern const char RISCVInstrNameData[] = {
  /* 0 */ 'G', '_', 'F', 'L', 'O', 'G', '1', '0', 0,
  /* 9 */ 'P', 's', 'e', 'u', 'd', 'o', 'M', 'a', 's', 'k', 'e', 'd', 'A', 't', 'o', 'm', 'i', 'c', 'L', 'o', 'a', 'd', 'S', 'u', 'b', '3', '2', 0,
  /* 37 */ 'P', 's', 'e', 'u', 'd', 'o', 'M', 'a', 's', 'k', 'e', 'd', 'A', 't', 'o', 'm', 'i', 'c', 'L', 'o', 'a', 'd', 'A', 'd', 'd', '3', '2', 0,
  /* 65 */ 'P', 's', 'e', 'u', 'd', 'o', 'M', 'a', 's', 'k', 'e', 'd', 'A', 't', 'o', 'm', 'i', 'c', 'L', 'o', 'a', 'd', 'N', 'a', 'n', 'd', '3', '2', 0,
  /* 94 */ 'P', 's', 'e', 'u', 'd', 'o', 'A', 't', 'o', 'm', 'i', 'c', 'L', 'o', 'a', 'd', 'N', 'a', 'n', 'd', '3', '2', 0,
  /* 117 */ 'P', 's', 'e', 'u', 'd', 'o', 'M', 'a', 's', 'k', 'e', 'd', 'C', 'm', 'p', 'X', 'c', 'h', 'g', '3', '2', 0,
  /* 139 */ 'P', 's', 'e', 'u', 'd', 'o', 'C', 'm', 'p', 'X', 'c', 'h', 'g', '3', '2', 0,
  /* 155 */ 'P', 's', 'e', 'u', 'd', 'o', 'M', 'a', 's', 'k', 'e', 'd', 'A', 't', 'o', 'm', 'i', 'c', 'L', 'o', 'a', 'd', 'U', 'M', 'i', 'n', '3', '2', 0,
  /* 184 */ 'P', 's', 'e', 'u', 'd', 'o', 'M', 'a', 's', 'k', 'e', 'd', 'A', 't', 'o', 'm', 'i', 'c', 'L', 'o', 'a', 'd', 'M', 'i', 'n', '3', '2', 0,
  /* 212 */ 'P', 's', 'e', 'u', 'd', 'o', 'M', 'a', 's', 'k', 'e', 'd', 'A', 't', 'o', 'm', 'i', 'c', 'S', 'w', 'a', 'p', '3', '2', 0,
  /* 237 */ 'P', 's', 'e', 'u', 'd', 'o', 'M', 'a', 's', 'k', 'e', 'd', 'A', 't', 'o', 'm', 'i', 'c', 'L', 'o', 'a', 'd', 'U', 'M', 'a', 'x', '3', '2', 0,
  /* 266 */ 'P', 's', 'e', 'u', 'd', 'o', 'M', 'a', 's', 'k', 'e', 'd', 'A', 't', 'o', 'm', 'i', 'c', 'L', 'o', 'a', 'd', 'M', 'a', 'x', '3', '2', 0,
  /* 294 */ 'G', '_', 'F', 'L', 'O', 'G', '2', 0,
  /* 302 */ 'G', '_', 'F', 'E', 'X', 'P', '2', 0,
  /* 310 */ 'P', 's', 'e', 'u', 'd', 'o', 'L', 'L', 'A', 0,
  /* 320 */ 'G', '_', 'F', 'M', 'A', 0,
  /* 326 */ 'S', 'F', 'E', 'N', 'C', 'E', '_', 'V', 'M', 'A', 0,
  /* 337 */ 'S', 'R', 'A', 0,
  /* 341 */ 'L', 'B', 0,
  /* 344 */ 'S', 'B', 0,
  /* 347 */ 'G', '_', 'F', 'S', 'U', 'B', 0,
  /* 354 */ 'C', '_', 'S', 'U', 'B', 0,
  /* 360 */ 'G', '_', 'S', 'U', 'B', 0,
  /* 366 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'S', 'U', 'B', 0,
  /* 382 */ 'G', '_', 'I', 'N', 'T', 'R', 'I', 'N', 'S', 'I', 'C', 0,
  /* 394 */ 'G', '_', 'F', 'P', 'T', 'R', 'U', 'N', 'C', 0,
  /* 404 */ 'G', '_', 'I', 'N', 'T', 'R', 'I', 'N', 'S', 'I', 'C', '_', 'T', 'R', 'U', 'N', 'C', 0,
  /* 422 */ 'G', '_', 'T', 'R', 'U', 'N', 'C', 0,
  /* 430 */ 'G', '_', 'B', 'U', 'I', 'L', 'D', '_', 'V', 'E', 'C', 'T', 'O', 'R', '_', 'T', 'R', 'U', 'N', 'C', 0,
  /* 451 */ 'A', 'U', 'I', 'P', 'C', 0,
  /* 457 */ 'C', 'S', 'R', 'R', 'C', 0,
  /* 463 */ 'G', '_', 'S', 'E', 'X', 'T', 'L', 'O', 'A', 'D', 0,
  /* 474 */ 'G', '_', 'Z', 'E', 'X', 'T', 'L', 'O', 'A', 'D', 0,
  /* 485 */ 'G', '_', 'L', 'O', 'A', 'D', 0,
  /* 492 */ 'G', '_', 'F', 'A', 'D', 'D', 0,
  /* 499 */ 'C', '_', 'A', 'D', 'D', 0,
  /* 505 */ 'G', '_', 'A', 'D', 'D', 0,
  /* 511 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'A', 'D', 'D', 0,
  /* 527 */ 'C', '_', 'F', 'L', 'D', 0,
  /* 533 */ 'C', '_', 'L', 'D', 0,
  /* 538 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'N', 'A', 'N', 'D', 0,
  /* 555 */ 'C', '_', 'A', 'N', 'D', 0,
  /* 561 */ 'G', '_', 'A', 'N', 'D', 0,
  /* 567 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'A', 'N', 'D', 0,
  /* 583 */ 'L', 'I', 'F', 'E', 'T', 'I', 'M', 'E', '_', 'E', 'N', 'D', 0,
  /* 596 */ 'P', 's', 'e', 'u', 'd', 'o', 'B', 'R', 'I', 'N', 'D', 0,
  /* 608 */ 'G', '_', 'B', 'R', 'C', 'O', 'N', 'D', 0,
  /* 617 */ 'G', '_', 'I', 'N', 'T', 'R', 'I', 'N', 'S', 'I', 'C', '_', 'R', 'O', 'U', 'N', 'D', 0,
  /* 635 */ 'L', 'O', 'A', 'D', '_', 'S', 'T', 'A', 'C', 'K', '_', 'G', 'U', 'A', 'R', 'D', 0,
  /* 652 */ 'C', '_', 'F', 'S', 'D', 0,
  /* 658 */ 'C', '_', 'S', 'D', 0,
  /* 663 */ 'F', 'S', 'U', 'B', '_', 'D', 0,
  /* 670 */ 'F', 'M', 'S', 'U', 'B', '_', 'D', 0,
  /* 678 */ 'F', 'N', 'M', 'S', 'U', 'B', '_', 'D', 0,
  /* 687 */ 'S', 'C', '_', 'D', 0,
  /* 692 */ 'F', 'A', 'D', 'D', '_', 'D', 0,
  /* 699 */ 'F', 'M', 'A', 'D', 'D', '_', 'D', 0,
  /* 707 */ 'F', 'N', 'M', 'A', 'D', 'D', '_', 'D', 0,
  /* 716 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'D', 0,
  /* 725 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'D', 0,
  /* 734 */ 'F', 'L', 'E', '_', 'D', 0,
  /* 740 */ 'F', 'S', 'G', 'N', 'J', '_', 'D', 0,
  /* 748 */ 'F', 'M', 'U', 'L', '_', 'D', 0,
  /* 755 */ 'F', 'C', 'V', 'T', '_', 'L', '_', 'D', 0,
  /* 764 */ 'F', 'M', 'I', 'N', '_', 'D', 0,
  /* 771 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'D', 0,
  /* 780 */ 'F', 'S', 'G', 'N', 'J', 'N', '_', 'D', 0,
  /* 789 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'D', 0,
  /* 799 */ 'F', 'E', 'Q', '_', 'D', 0,
  /* 805 */ 'L', 'R', '_', 'D', 0,
  /* 810 */ 'A', 'M', 'O', 'O', 'R', '_', 'D', 0,
  /* 818 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'D', 0,
  /* 827 */ 'F', 'C', 'L', 'A', 'S', 'S', '_', 'D', 0,
  /* 836 */ 'F', 'C', 'V', 'T', '_', 'S', '_', 'D', 0,
  /* 845 */ 'F', 'L', 'T', '_', 'D', 0,
  /* 851 */ 'F', 'S', 'Q', 'R', 'T', '_', 'D', 0,
  /* 859 */ 'F', 'C', 'V', 'T', '_', 'L', 'U', '_', 'D', 0,
  /* 869 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'D', 0,
  /* 879 */ 'F', 'C', 'V', 'T', '_', 'W', 'U', '_', 'D', 0,
  /* 889 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'D', 0,
  /* 899 */ 'F', 'D', 'I', 'V', '_', 'D', 0,
  /* 906 */ 'F', 'C', 'V', 'T', '_', 'W', '_', 'D', 0,
  /* 915 */ 'F', 'M', 'A', 'X', '_', 'D', 0,
  /* 922 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'D', 0,
  /* 931 */ 'F', 'S', 'G', 'N', 'J', 'X', '_', 'D', 0,
  /* 940 */ 'F', 'M', 'V', '_', 'X', '_', 'D', 0,
  /* 948 */ 'G', '_', 'S', 'S', 'U', 'B', 'E', 0,
  /* 956 */ 'G', '_', 'U', 'S', 'U', 'B', 'E', 0,
  /* 964 */ 'F', 'E', 'N', 'C', 'E', 0,
  /* 970 */ 'R', 'E', 'G', '_', 'S', 'E', 'Q', 'U', 'E', 'N', 'C', 'E', 0,
  /* 983 */ 'G', '_', 'S', 'A', 'D', 'D', 'E', 0,
  /* 991 */ 'G', '_', 'U', 'A', 'D', 'D', 'E', 0,
  /* 999 */ 'B', 'G', 'E', 0,
  /* 1003 */ 'B', 'U', 'N', 'D', 'L', 'E', 0,
  /* 1010 */ 'B', 'N', 'E', 0,
  /* 1014 */ 'L', 'O', 'C', 'A', 'L', '_', 'E', 'S', 'C', 'A', 'P', 'E', 0,
  /* 1027 */ 'G', '_', 'S', 'T', 'O', 'R', 'E', 0,
  /* 1035 */ 'D', 'B', 'G', '_', 'V', 'A', 'L', 'U', 'E', 0,
  /* 1045 */ 'G', '_', 'G', 'L', 'O', 'B', 'A', 'L', '_', 'V', 'A', 'L', 'U', 'E', 0,
  /* 1060 */ 'G', '_', 'C', 'T', 'L', 'Z', '_', 'Z', 'E', 'R', 'O', '_', 'U', 'N', 'D', 'E', 'F', 0,
  /* 1078 */ 'G', '_', 'C', 'T', 'T', 'Z', '_', 'Z', 'E', 'R', 'O', '_', 'U', 'N', 'D', 'E', 'F', 0,
  /* 1096 */ 'G', '_', 'I', 'M', 'P', 'L', 'I', 'C', 'I', 'T', '_', 'D', 'E', 'F', 0,
  /* 1111 */ 'G', '_', 'F', 'N', 'E', 'G', 0,
  /* 1118 */ 'E', 'X', 'T', 'R', 'A', 'C', 'T', '_', 'S', 'U', 'B', 'R', 'E', 'G', 0,
  /* 1133 */ 'I', 'N', 'S', 'E', 'R', 'T', '_', 'S', 'U', 'B', 'R', 'E', 'G', 0,
  /* 1147 */ 'S', 'U', 'B', 'R', 'E', 'G', '_', 'T', 'O', '_', 'R', 'E', 'G', 0,
  /* 1161 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', '_', 'C', 'M', 'P', 'X', 'C', 'H', 'G', 0,
  /* 1178 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'X', 'C', 'H', 'G', 0,
  /* 1195 */ 'G', '_', 'F', 'L', 'O', 'G', 0,
  /* 1202 */ 'G', '_', 'V', 'A', 'A', 'R', 'G', 0,
  /* 1210 */ 'G', '_', 'S', 'M', 'U', 'L', 'H', 0,
  /* 1218 */ 'G', '_', 'U', 'M', 'U', 'L', 'H', 0,
  /* 1226 */ 'S', 'H', 0,
  /* 1229 */ 'C', '_', 'S', 'R', 'A', 'I', 0,
  /* 1236 */ 'C', 'S', 'R', 'R', 'C', 'I', 0,
  /* 1243 */ 'C', '_', 'A', 'D', 'D', 'I', 0,
  /* 1250 */ 'C', '_', 'A', 'N', 'D', 'I', 0,
  /* 1257 */ 'W', 'F', 'I', 0,
  /* 1261 */ 'G', '_', 'P', 'H', 'I', 0,
  /* 1267 */ 'C', '_', 'S', 'L', 'L', 'I', 0,
  /* 1274 */ 'C', '_', 'S', 'R', 'L', 'I', 0,
  /* 1281 */ 'C', '_', 'L', 'I', 0,
  /* 1286 */ 'P', 's', 'e', 'u', 'd', 'o', 'L', 'I', 0,
  /* 1295 */ 'X', 'O', 'R', 'I', 0,
  /* 1300 */ 'G', '_', 'F', 'P', 'T', 'O', 'S', 'I', 0,
  /* 1309 */ 'C', 'S', 'R', 'R', 'S', 'I', 0,
  /* 1316 */ 'S', 'L', 'T', 'I', 0,
  /* 1321 */ 'C', '_', 'L', 'U', 'I', 0,
  /* 1327 */ 'G', '_', 'F', 'P', 'T', 'O', 'U', 'I', 0,
  /* 1336 */ 'C', 'S', 'R', 'R', 'W', 'I', 0,
  /* 1343 */ 'F', 'E', 'N', 'C', 'E', '_', 'I', 0,
  /* 1351 */ 'C', '_', 'J', 0,
  /* 1355 */ 'C', '_', 'E', 'B', 'R', 'E', 'A', 'K', 0,
  /* 1364 */ 'G', '_', 'P', 'T', 'R', '_', 'M', 'A', 'S', 'K', 0,
  /* 1375 */ 'C', '_', 'J', 'A', 'L', 0,
  /* 1381 */ 'G', 'C', '_', 'L', 'A', 'B', 'E', 'L', 0,
  /* 1390 */ 'D', 'B', 'G', '_', 'L', 'A', 'B', 'E', 'L', 0,
  /* 1400 */ 'E', 'H', '_', 'L', 'A', 'B', 'E', 'L', 0,
  /* 1409 */ 'A', 'N', 'N', 'O', 'T', 'A', 'T', 'I', 'O', 'N', '_', 'L', 'A', 'B', 'E', 'L', 0,
  /* 1426 */ 'I', 'C', 'A', 'L', 'L', '_', 'B', 'R', 'A', 'N', 'C', 'H', '_', 'F', 'U', 'N', 'N', 'E', 'L', 0,
  /* 1446 */ 'G', '_', 'S', 'H', 'L', 0,
  /* 1452 */ 'P', 's', 'e', 'u', 'd', 'o', 'T', 'A', 'I', 'L', 0,
  /* 1463 */ 'G', '_', 'F', 'C', 'E', 'I', 'L', 0,
  /* 1471 */ 'E', 'C', 'A', 'L', 'L', 0,
  /* 1477 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'T', 'A', 'I', 'L', '_', 'C', 'A', 'L', 'L', 0,
  /* 1497 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'T', 'Y', 'P', 'E', 'D', '_', 'E', 'V', 'E', 'N', 'T', '_', 'C', 'A', 'L', 'L', 0,
  /* 1524 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'E', 'V', 'E', 'N', 'T', '_', 'C', 'A', 'L', 'L', 0,
  /* 1545 */ 'F', 'E', 'N', 'T', 'R', 'Y', '_', 'C', 'A', 'L', 'L', 0,
  /* 1557 */ 'P', 's', 'e', 'u', 'd', 'o', 'C', 'A', 'L', 'L', 0,
  /* 1568 */ 'K', 'I', 'L', 'L', 0,
  /* 1573 */ 'S', 'L', 'L', 0,
  /* 1577 */ 'S', 'R', 'L', 0,
  /* 1581 */ 'S', 'C', '_', 'D', '_', 'R', 'L', 0,
  /* 1589 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'D', '_', 'R', 'L', 0,
  /* 1601 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'D', '_', 'R', 'L', 0,
  /* 1613 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'D', '_', 'R', 'L', 0,
  /* 1625 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'D', '_', 'R', 'L', 0,
  /* 1638 */ 'L', 'R', '_', 'D', '_', 'R', 'L', 0,
  /* 1646 */ 'A', 'M', 'O', 'O', 'R', '_', 'D', '_', 'R', 'L', 0,
  /* 1657 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'D', '_', 'R', 'L', 0,
  /* 1669 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'D', '_', 'R', 'L', 0,
  /* 1682 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'D', '_', 'R', 'L', 0,
  /* 1695 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'D', '_', 'R', 'L', 0,
  /* 1707 */ 'S', 'C', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1718 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1733 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1748 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1763 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1779 */ 'L', 'R', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1790 */ 'A', 'M', 'O', 'O', 'R', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1804 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1819 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1835 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1851 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1866 */ 'S', 'C', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1877 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1892 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1907 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1922 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1938 */ 'L', 'R', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1949 */ 'A', 'M', 'O', 'O', 'R', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1963 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1978 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1994 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 2010 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 2025 */ 'S', 'C', '_', 'W', '_', 'R', 'L', 0,
  /* 2033 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'W', '_', 'R', 'L', 0,
  /* 2045 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'W', '_', 'R', 'L', 0,
  /* 2057 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'W', '_', 'R', 'L', 0,
  /* 2069 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'W', '_', 'R', 'L', 0,
  /* 2082 */ 'L', 'R', '_', 'W', '_', 'R', 'L', 0,
  /* 2090 */ 'A', 'M', 'O', 'O', 'R', '_', 'W', '_', 'R', 'L', 0,
  /* 2101 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'W', '_', 'R', 'L', 0,
  /* 2113 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'W', '_', 'R', 'L', 0,
  /* 2126 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'W', '_', 'R', 'L', 0,
  /* 2139 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'W', '_', 'R', 'L', 0,
  /* 2151 */ 'G', '_', 'F', 'M', 'U', 'L', 0,
  /* 2158 */ 'G', '_', 'M', 'U', 'L', 0,
  /* 2164 */ 'F', 'C', 'V', 'T', '_', 'D', '_', 'L', 0,
  /* 2173 */ 'F', 'C', 'V', 'T', '_', 'S', '_', 'L', 0,
  /* 2182 */ 'G', '_', 'F', 'R', 'E', 'M', 0,
  /* 2189 */ 'G', '_', 'S', 'R', 'E', 'M', 0,
  /* 2196 */ 'G', '_', 'U', 'R', 'E', 'M', 0,
  /* 2203 */ 'I', 'N', 'L', 'I', 'N', 'E', 'A', 'S', 'M', 0,
  /* 2213 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'U', 'M', 'I', 'N', 0,
  /* 2230 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'M', 'I', 'N', 0,
  /* 2246 */ 'C', 'F', 'I', '_', 'I', 'N', 'S', 'T', 'R', 'U', 'C', 'T', 'I', 'O', 'N', 0,
  /* 2262 */ 'C', '_', 'A', 'D', 'D', 'I', '4', 'S', 'P', 'N', 0,
  /* 2273 */ 'A', 'D', 'J', 'C', 'A', 'L', 'L', 'S', 'T', 'A', 'C', 'K', 'D', 'O', 'W', 'N', 0,
  /* 2290 */ 'G', '_', 'S', 'S', 'U', 'B', 'O', 0,
  /* 2298 */ 'G', '_', 'U', 'S', 'U', 'B', 'O', 0,
  /* 2306 */ 'G', '_', 'S', 'A', 'D', 'D', 'O', 0,
  /* 2314 */ 'G', '_', 'U', 'A', 'D', 'D', 'O', 0,
  /* 2322 */ 'G', '_', 'S', 'M', 'U', 'L', 'O', 0,
  /* 2330 */ 'G', '_', 'U', 'M', 'U', 'L', 'O', 0,
  /* 2338 */ 'F', 'E', 'N', 'C', 'E', '_', 'T', 'S', 'O', 0,
  /* 2348 */ 'S', 'T', 'A', 'C', 'K', 'M', 'A', 'P', 0,
  /* 2357 */ 'G', '_', 'B', 'S', 'W', 'A', 'P', 0,
  /* 2365 */ 'G', '_', 'G', 'E', 'P', 0,
  /* 2371 */ 'G', '_', 'S', 'I', 'T', 'O', 'F', 'P', 0,
  /* 2380 */ 'G', '_', 'U', 'I', 'T', 'O', 'F', 'P', 0,
  /* 2389 */ 'G', '_', 'F', 'C', 'M', 'P', 0,
  /* 2396 */ 'G', '_', 'I', 'C', 'M', 'P', 0,
  /* 2403 */ 'C', '_', 'U', 'N', 'I', 'M', 'P', 0,
  /* 2411 */ 'C', '_', 'N', 'O', 'P', 0,
  /* 2417 */ 'G', '_', 'C', 'T', 'P', 'O', 'P', 0,
  /* 2425 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'O', 'P', 0,
  /* 2438 */ 'F', 'A', 'U', 'L', 'T', 'I', 'N', 'G', '_', 'O', 'P', 0,
  /* 2450 */ 'C', '_', 'A', 'D', 'D', 'I', '1', '6', 'S', 'P', 0,
  /* 2461 */ 'C', '_', 'F', 'L', 'D', 'S', 'P', 0,
  /* 2469 */ 'C', '_', 'L', 'D', 'S', 'P', 0,
  /* 2476 */ 'C', '_', 'F', 'S', 'D', 'S', 'P', 0,
  /* 2484 */ 'C', '_', 'S', 'D', 'S', 'P', 0,
  /* 2491 */ 'C', '_', 'F', 'L', 'W', 'S', 'P', 0,
  /* 2499 */ 'C', '_', 'L', 'W', 'S', 'P', 0,
  /* 2506 */ 'C', '_', 'F', 'S', 'W', 'S', 'P', 0,
  /* 2514 */ 'C', '_', 'S', 'W', 'S', 'P', 0,
  /* 2521 */ 'A', 'D', 'J', 'C', 'A', 'L', 'L', 'S', 'T', 'A', 'C', 'K', 'U', 'P', 0,
  /* 2536 */ 'G', '_', 'F', 'E', 'X', 'P', 0,
  /* 2543 */ 'S', 'C', '_', 'D', '_', 'A', 'Q', 0,
  /* 2551 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'D', '_', 'A', 'Q', 0,
  /* 2563 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'D', '_', 'A', 'Q', 0,
  /* 2575 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'D', '_', 'A', 'Q', 0,
  /* 2587 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'D', '_', 'A', 'Q', 0,
  /* 2600 */ 'L', 'R', '_', 'D', '_', 'A', 'Q', 0,
  /* 2608 */ 'A', 'M', 'O', 'O', 'R', '_', 'D', '_', 'A', 'Q', 0,
  /* 2619 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'D', '_', 'A', 'Q', 0,
  /* 2631 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'D', '_', 'A', 'Q', 0,
  /* 2644 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'D', '_', 'A', 'Q', 0,
  /* 2657 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'D', '_', 'A', 'Q', 0,
  /* 2669 */ 'S', 'C', '_', 'W', '_', 'A', 'Q', 0,
  /* 2677 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'W', '_', 'A', 'Q', 0,
  /* 2689 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'W', '_', 'A', 'Q', 0,
  /* 2701 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'W', '_', 'A', 'Q', 0,
  /* 2713 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'W', '_', 'A', 'Q', 0,
  /* 2726 */ 'L', 'R', '_', 'W', '_', 'A', 'Q', 0,
  /* 2734 */ 'A', 'M', 'O', 'O', 'R', '_', 'W', '_', 'A', 'Q', 0,
  /* 2745 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'W', '_', 'A', 'Q', 0,
  /* 2757 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'W', '_', 'A', 'Q', 0,
  /* 2770 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'W', '_', 'A', 'Q', 0,
  /* 2783 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'W', '_', 'A', 'Q', 0,
  /* 2795 */ 'B', 'E', 'Q', 0,
  /* 2799 */ 'G', '_', 'B', 'R', 0,
  /* 2804 */ 'P', 's', 'e', 'u', 'd', 'o', 'B', 'R', 0,
  /* 2813 */ 'G', '_', 'B', 'L', 'O', 'C', 'K', '_', 'A', 'D', 'D', 'R', 0,
  /* 2826 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'F', 'U', 'N', 'C', 'T', 'I', 'O', 'N', '_', 'E', 'N', 'T', 'E', 'R', 0,
  /* 2851 */ 'G', '_', 'A', 'S', 'H', 'R', 0,
  /* 2858 */ 'G', '_', 'L', 'S', 'H', 'R', 0,
  /* 2865 */ 'C', '_', 'J', 'R', 0,
  /* 2870 */ 'C', '_', 'J', 'A', 'L', 'R', 0,
  /* 2877 */ 'G', '_', 'B', 'U', 'I', 'L', 'D', '_', 'V', 'E', 'C', 'T', 'O', 'R', 0,
  /* 2892 */ 'G', '_', 'S', 'H', 'U', 'F', 'F', 'L', 'E', '_', 'V', 'E', 'C', 'T', 'O', 'R', 0,
  /* 2909 */ 'C', '_', 'X', 'O', 'R', 0,
  /* 2915 */ 'G', '_', 'X', 'O', 'R', 0,
  /* 2921 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'X', 'O', 'R', 0,
  /* 2937 */ 'C', '_', 'O', 'R', 0,
  /* 2942 */ 'G', '_', 'O', 'R', 0,
  /* 2947 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'O', 'R', 0,
  /* 2962 */ 'S', 'e', 'l', 'e', 'c', 't', '_', 'F', 'P', 'R', '3', '2', '_', 'U', 's', 'i', 'n', 'g', '_', 'C', 'C', '_', 'G', 'P', 'R', 0,
  /* 2988 */ 'S', 'e', 'l', 'e', 'c', 't', '_', 'F', 'P', 'R', '6', '4', '_', 'U', 's', 'i', 'n', 'g', '_', 'C', 'C', '_', 'G', 'P', 'R', 0,
  /* 3014 */ 'S', 'e', 'l', 'e', 'c', 't', '_', 'G', 'P', 'R', '_', 'U', 's', 'i', 'n', 'g', '_', 'C', 'C', '_', 'G', 'P', 'R', 0,
  /* 3038 */ 'G', '_', 'I', 'N', 'T', 'T', 'O', 'P', 'T', 'R', 0,
  /* 3049 */ 'G', '_', 'F', 'A', 'B', 'S', 0,
  /* 3056 */ 'G', '_', 'U', 'N', 'M', 'E', 'R', 'G', 'E', '_', 'V', 'A', 'L', 'U', 'E', 'S', 0,
  /* 3073 */ 'G', '_', 'M', 'E', 'R', 'G', 'E', '_', 'V', 'A', 'L', 'U', 'E', 'S', 0,
  /* 3088 */ 'G', '_', 'C', 'O', 'N', 'C', 'A', 'T', '_', 'V', 'E', 'C', 'T', 'O', 'R', 'S', 0,
  /* 3105 */ 'C', 'S', 'R', 'R', 'S', 0,
  /* 3111 */ 'C', 'O', 'P', 'Y', '_', 'T', 'O', '_', 'R', 'E', 'G', 'C', 'L', 'A', 'S', 'S', 0,
  /* 3128 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', '_', 'C', 'M', 'P', 'X', 'C', 'H', 'G', '_', 'W', 'I', 'T', 'H', '_', 'S', 'U', 'C', 'C', 'E', 'S', 'S', 0,
  /* 3158 */ 'G', '_', 'I', 'N', 'T', 'R', 'I', 'N', 'S', 'I', 'C', '_', 'W', '_', 'S', 'I', 'D', 'E', '_', 'E', 'F', 'F', 'E', 'C', 'T', 'S', 0,
  /* 3185 */ 'F', 'S', 'U', 'B', '_', 'S', 0,
  /* 3192 */ 'F', 'M', 'S', 'U', 'B', '_', 'S', 0,
  /* 3200 */ 'F', 'N', 'M', 'S', 'U', 'B', '_', 'S', 0,
  /* 3209 */ 'F', 'A', 'D', 'D', '_', 'S', 0,
  /* 3216 */ 'F', 'M', 'A', 'D', 'D', '_', 'S', 0,
  /* 3224 */ 'F', 'N', 'M', 'A', 'D', 'D', '_', 'S', 0,
  /* 3233 */ 'F', 'C', 'V', 'T', '_', 'D', '_', 'S', 0,
  /* 3242 */ 'F', 'L', 'E', '_', 'S', 0,
  /* 3248 */ 'F', 'S', 'G', 'N', 'J', '_', 'S', 0,
  /* 3256 */ 'F', 'M', 'U', 'L', '_', 'S', 0,
  /* 3263 */ 'F', 'C', 'V', 'T', '_', 'L', '_', 'S', 0,
  /* 3272 */ 'F', 'M', 'I', 'N', '_', 'S', 0,
  /* 3279 */ 'F', 'S', 'G', 'N', 'J', 'N', '_', 'S', 0,
  /* 3288 */ 'F', 'E', 'Q', '_', 'S', 0,
  /* 3294 */ 'F', 'C', 'L', 'A', 'S', 'S', '_', 'S', 0,
  /* 3303 */ 'F', 'L', 'T', '_', 'S', 0,
  /* 3309 */ 'F', 'S', 'Q', 'R', 'T', '_', 'S', 0,
  /* 3317 */ 'F', 'C', 'V', 'T', '_', 'L', 'U', '_', 'S', 0,
  /* 3327 */ 'F', 'C', 'V', 'T', '_', 'W', 'U', '_', 'S', 0,
  /* 3337 */ 'F', 'D', 'I', 'V', '_', 'S', 0,
  /* 3344 */ 'F', 'C', 'V', 'T', '_', 'W', '_', 'S', 0,
  /* 3353 */ 'F', 'M', 'A', 'X', '_', 'S', 0,
  /* 3360 */ 'F', 'S', 'G', 'N', 'J', 'X', '_', 'S', 0,
  /* 3369 */ 'G', '_', 'E', 'X', 'T', 'R', 'A', 'C', 'T', 0,
  /* 3379 */ 'G', '_', 'S', 'E', 'L', 'E', 'C', 'T', 0,
  /* 3388 */ 'G', '_', 'B', 'R', 'I', 'N', 'D', 'I', 'R', 'E', 'C', 'T', 0,
  /* 3401 */ 'M', 'R', 'E', 'T', 0,
  /* 3406 */ 'S', 'R', 'E', 'T', 0,
  /* 3411 */ 'U', 'R', 'E', 'T', 0,
  /* 3416 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'R', 'E', 'T', 0,
  /* 3430 */ 'P', 's', 'e', 'u', 'd', 'o', 'R', 'E', 'T', 0,
  /* 3440 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'F', 'U', 'N', 'C', 'T', 'I', 'O', 'N', '_', 'E', 'X', 'I', 'T', 0,
  /* 3464 */ 'B', 'L', 'T', 0,
  /* 3468 */ 'G', '_', 'E', 'X', 'T', 'R', 'A', 'C', 'T', '_', 'V', 'E', 'C', 'T', 'O', 'R', '_', 'E', 'L', 'T', 0,
  /* 3489 */ 'G', '_', 'I', 'N', 'S', 'E', 'R', 'T', '_', 'V', 'E', 'C', 'T', 'O', 'R', '_', 'E', 'L', 'T', 0,
  /* 3509 */ 'S', 'L', 'T', 0,
  /* 3513 */ 'G', '_', 'F', 'C', 'O', 'N', 'S', 'T', 'A', 'N', 'T', 0,
  /* 3525 */ 'G', '_', 'C', 'O', 'N', 'S', 'T', 'A', 'N', 'T', 0,
  /* 3536 */ 'S', 'T', 'A', 'T', 'E', 'P', 'O', 'I', 'N', 'T', 0,
  /* 3547 */ 'P', 'A', 'T', 'C', 'H', 'P', 'O', 'I', 'N', 'T', 0,
  /* 3558 */ 'G', '_', 'P', 'T', 'R', 'T', 'O', 'I', 'N', 'T', 0,
  /* 3569 */ 'G', '_', 'V', 'A', 'S', 'T', 'A', 'R', 'T', 0,
  /* 3579 */ 'L', 'I', 'F', 'E', 'T', 'I', 'M', 'E', '_', 'S', 'T', 'A', 'R', 'T', 0,
  /* 3594 */ 'G', '_', 'I', 'N', 'S', 'E', 'R', 'T', 0,
  /* 3603 */ 'G', '_', 'B', 'I', 'T', 'C', 'A', 'S', 'T', 0,
  /* 3613 */ 'G', '_', 'A', 'D', 'D', 'R', 'S', 'P', 'A', 'C', 'E', '_', 'C', 'A', 'S', 'T', 0,
  /* 3630 */ 'G', '_', 'F', 'P', 'E', 'X', 'T', 0,
  /* 3638 */ 'G', '_', 'S', 'E', 'X', 'T', 0,
  /* 3645 */ 'G', '_', 'A', 'N', 'Y', 'E', 'X', 'T', 0,
  /* 3654 */ 'G', '_', 'Z', 'E', 'X', 'T', 0,
  /* 3661 */ 'L', 'B', 'U', 0,
  /* 3665 */ 'B', 'G', 'E', 'U', 0,
  /* 3670 */ 'M', 'U', 'L', 'H', 'U', 0,
  /* 3676 */ 'S', 'L', 'T', 'I', 'U', 0,
  /* 3682 */ 'F', 'C', 'V', 'T', '_', 'D', '_', 'L', 'U', 0,
  /* 3692 */ 'F', 'C', 'V', 'T', '_', 'S', '_', 'L', 'U', 0,
  /* 3702 */ 'R', 'E', 'M', 'U', 0,
  /* 3707 */ 'M', 'U', 'L', 'H', 'S', 'U', 0,
  /* 3714 */ 'B', 'L', 'T', 'U', 0,
  /* 3719 */ 'S', 'L', 'T', 'U', 0,
  /* 3724 */ 'D', 'I', 'V', 'U', 0,
  /* 3729 */ 'L', 'W', 'U', 0,
  /* 3733 */ 'F', 'C', 'V', 'T', '_', 'D', '_', 'W', 'U', 0,
  /* 3743 */ 'F', 'C', 'V', 'T', '_', 'S', '_', 'W', 'U', 0,
  /* 3753 */ 'G', '_', 'F', 'D', 'I', 'V', 0,
  /* 3760 */ 'G', '_', 'S', 'D', 'I', 'V', 0,
  /* 3767 */ 'G', '_', 'U', 'D', 'I', 'V', 0,
  /* 3774 */ 'C', '_', 'M', 'V', 0,
  /* 3779 */ 'S', 'R', 'A', 'W', 0,
  /* 3784 */ 'C', '_', 'S', 'U', 'B', 'W', 0,
  /* 3791 */ 'C', '_', 'A', 'D', 'D', 'W', 0,
  /* 3798 */ 'S', 'R', 'A', 'I', 'W', 0,
  /* 3804 */ 'C', '_', 'A', 'D', 'D', 'I', 'W', 0,
  /* 3812 */ 'S', 'L', 'L', 'I', 'W', 0,
  /* 3818 */ 'S', 'R', 'L', 'I', 'W', 0,
  /* 3824 */ 'C', '_', 'F', 'L', 'W', 0,
  /* 3830 */ 'S', 'L', 'L', 'W', 0,
  /* 3835 */ 'S', 'R', 'L', 'W', 0,
  /* 3840 */ 'M', 'U', 'L', 'W', 0,
  /* 3845 */ 'C', '_', 'L', 'W', 0,
  /* 3850 */ 'R', 'E', 'M', 'W', 0,
  /* 3855 */ 'G', '_', 'F', 'P', 'O', 'W', 0,
  /* 3862 */ 'C', 'S', 'R', 'R', 'W', 0,
  /* 3868 */ 'C', '_', 'F', 'S', 'W', 0,
  /* 3874 */ 'C', '_', 'S', 'W', 0,
  /* 3879 */ 'R', 'E', 'M', 'U', 'W', 0,
  /* 3885 */ 'D', 'I', 'V', 'U', 'W', 0,
  /* 3891 */ 'D', 'I', 'V', 'W', 0,
  /* 3896 */ 'S', 'C', '_', 'W', 0,
  /* 3901 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'W', 0,
  /* 3910 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'W', 0,
  /* 3919 */ 'F', 'C', 'V', 'T', '_', 'D', '_', 'W', 0,
  /* 3928 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'W', 0,
  /* 3937 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'W', 0,
  /* 3947 */ 'L', 'R', '_', 'W', 0,
  /* 3952 */ 'A', 'M', 'O', 'O', 'R', '_', 'W', 0,
  /* 3960 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'W', 0,
  /* 3969 */ 'F', 'C', 'V', 'T', '_', 'S', '_', 'W', 0,
  /* 3978 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'W', 0,
  /* 3988 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'W', 0,
  /* 3998 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'W', 0,
  /* 4007 */ 'F', 'M', 'V', '_', 'X', '_', 'W', 0,
  /* 4015 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'U', 'M', 'A', 'X', 0,
  /* 4032 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'M', 'A', 'X', 0,
  /* 4048 */ 'G', '_', 'F', 'R', 'A', 'M', 'E', '_', 'I', 'N', 'D', 'E', 'X', 0,
  /* 4062 */ 'F', 'M', 'V', '_', 'D', '_', 'X', 0,
  /* 4070 */ 'F', 'M', 'V', '_', 'W', '_', 'X', 0,
  /* 4078 */ 'C', 'O', 'P', 'Y', 0,
  /* 4083 */ 'C', '_', 'B', 'N', 'E', 'Z', 0,
  /* 4090 */ 'G', '_', 'C', 'T', 'L', 'Z', 0,
  /* 4097 */ 'C', '_', 'B', 'E', 'Q', 'Z', 0,
  /* 4104 */ 'G', '_', 'C', 'T', 'T', 'Z', 0,
  /* 4111 */ 'B', 'u', 'i', 'l', 'd', 'P', 'a', 'i', 'r', 'F', '6', '4', 'P', 's', 'e', 'u', 'd', 'o', 0,
  /* 4130 */ 'S', 'p', 'l', 'i', 't', 'F', '6', '4', 'P', 's', 'e', 'u', 'd', 'o', 0,
  /* 4145 */ 'P', 's', 'e', 'u', 'd', 'o', 'T', 'A', 'I', 'L', 'I', 'n', 'd', 'i', 'r', 'e', 'c', 't', 0,
  /* 4164 */ 'P', 's', 'e', 'u', 'd', 'o', 'C', 'A', 'L', 'L', 'I', 'n', 'd', 'i', 'r', 'e', 'c', 't', 0,
};

extern const unsigned RISCVInstrNameIndices[] = {
    1263U, 2203U, 2246U, 1400U, 1381U, 1409U, 1568U, 1118U, 
    1133U, 1098U, 1147U, 3111U, 1035U, 1390U, 970U, 4078U, 
    1003U, 3579U, 583U, 2348U, 1545U, 3547U, 635U, 3536U, 
    1014U, 2438U, 2425U, 2826U, 3416U, 3440U, 1477U, 1524U, 
    1497U, 1426U, 505U, 360U, 2158U, 3760U, 3767U, 2189U, 
    2196U, 561U, 2942U, 2915U, 1096U, 1261U, 4048U, 1045U, 
    3369U, 3056U, 3594U, 3073U, 2877U, 430U, 3088U, 3558U, 
    3038U, 3603U, 404U, 617U, 485U, 463U, 474U, 1027U, 
    3128U, 1161U, 1178U, 511U, 366U, 567U, 538U, 2947U, 
    2921U, 4032U, 2230U, 4015U, 2213U, 608U, 3388U, 382U, 
    3158U, 3645U, 422U, 3525U, 3513U, 3569U, 1202U, 3638U, 
    3654U, 1446U, 2858U, 2851U, 2396U, 2389U, 3379U, 2314U, 
    991U, 2298U, 956U, 2306U, 983U, 2290U, 948U, 2330U, 
    2322U, 1218U, 1210U, 492U, 347U, 2151U, 320U, 3753U, 
    2182U, 3855U, 2536U, 302U, 1195U, 294U, 0U, 1111U, 
    3630U, 394U, 1300U, 1327U, 2371U, 2380U, 3049U, 2365U, 
    1364U, 2799U, 3489U, 3468U, 2892U, 4104U, 1078U, 4090U, 
    1060U, 2417U, 2357U, 1463U, 3613U, 2813U, 2273U, 2521U, 
    4111U, 94U, 2804U, 596U, 1557U, 4164U, 139U, 1286U, 
    310U, 37U, 266U, 184U, 65U, 9U, 237U, 155U, 
    212U, 117U, 3430U, 1452U, 4145U, 2962U, 2988U, 3014U, 
    4130U, 495U, 1245U, 3806U, 3793U, 716U, 2551U, 1718U, 
    1589U, 3901U, 2677U, 1877U, 2033U, 725U, 2563U, 1733U, 
    1601U, 3910U, 2689U, 1892U, 2045U, 889U, 2644U, 1835U, 
    1682U, 3988U, 2770U, 1994U, 2126U, 922U, 2657U, 1851U, 
    1695U, 3998U, 2783U, 2010U, 2139U, 869U, 2631U, 1819U, 
    1669U, 3978U, 2757U, 1978U, 2113U, 771U, 2575U, 1748U, 
    1613U, 3928U, 2701U, 1907U, 2057U, 810U, 2608U, 1790U, 
    1646U, 3952U, 2734U, 1949U, 2090U, 789U, 2587U, 1763U, 
    1625U, 3937U, 2713U, 1922U, 2069U, 818U, 2619U, 1804U, 
    1657U, 3960U, 2745U, 1963U, 2101U, 551U, 1252U, 451U, 
    2795U, 999U, 3665U, 3464U, 3714U, 1010U, 457U, 1236U, 
    3105U, 1309U, 3862U, 1336U, 499U, 1243U, 2450U, 2262U, 
    3804U, 3791U, 555U, 1250U, 4097U, 4083U, 1355U, 527U, 
    2461U, 3824U, 2491U, 652U, 2476U, 3868U, 2506U, 1351U, 
    1375U, 2870U, 2865U, 533U, 2469U, 1281U, 1321U, 3845U, 
    2499U, 3774U, 2411U, 2937U, 658U, 2484U, 1267U, 1229U, 
    1274U, 354U, 3784U, 3874U, 2514U, 2403U, 2909U, 3756U, 
    3724U, 3885U, 3891U, 1357U, 1471U, 692U, 3209U, 827U, 
    3294U, 2164U, 3682U, 3233U, 3919U, 3733U, 859U, 3317U, 
    755U, 3263U, 836U, 2173U, 3692U, 3969U, 3743U, 879U, 
    3327U, 906U, 3344U, 899U, 3337U, 964U, 1343U, 2338U, 
    799U, 3288U, 529U, 734U, 3242U, 845U, 3303U, 3826U, 
    699U, 3216U, 915U, 3353U, 764U, 3272U, 670U, 3192U, 
    748U, 3256U, 4062U, 4070U, 940U, 4007U, 707U, 3224U, 
    678U, 3200U, 654U, 780U, 3279U, 931U, 3360U, 740U, 
    3248U, 851U, 3309U, 663U, 3185U, 3870U, 1377U, 2872U, 
    341U, 3661U, 530U, 1215U, 3672U, 805U, 2600U, 1779U, 
    1638U, 3947U, 2726U, 1938U, 2082U, 1323U, 3827U, 3729U, 
    3401U, 2154U, 1213U, 3707U, 3670U, 3840U, 2889U, 1296U, 
    2185U, 3702U, 3879U, 3850U, 344U, 687U, 2543U, 1707U, 
    1581U, 3896U, 2669U, 1866U, 2025U, 655U, 326U, 1226U, 
    1573U, 1269U, 3812U, 3830U, 3509U, 1316U, 3676U, 3719U, 
    337U, 1231U, 3798U, 3779U, 3406U, 1577U, 1276U, 3818U, 
    3835U, 350U, 3786U, 3871U, 2405U, 3411U, 1257U, 2911U, 
    1295U, 
};

static inline void InitRISCVMCInstrInfo(MCInstrInfo *II) {
  II->InitMCInstrInfo(RISCVInsts, RISCVInstrNameIndices, RISCVInstrNameData, 441);
}

} // end llvm namespace
#endif // GET_INSTRINFO_MC_DESC

#ifdef GET_INSTRINFO_HEADER
#undef GET_INSTRINFO_HEADER
namespace llvm {
struct RISCVGenInstrInfo : public TargetInstrInfo {
  explicit RISCVGenInstrInfo(int CFSetupOpcode = -1, int CFDestroyOpcode = -1, int CatchRetOpcode = -1, int ReturnOpcode = -1);
  ~RISCVGenInstrInfo() override = default;

};
} // end llvm namespace
#endif // GET_INSTRINFO_HEADER

#ifdef GET_INSTRINFO_HELPER_DECLS
#undef GET_INSTRINFO_HELPER_DECLS


#endif // GET_INSTRINFO_HELPER_DECLS

#ifdef GET_INSTRINFO_HELPERS
#undef GET_INSTRINFO_HELPERS

#endif // GET_INSTRINFO_HELPERS

#ifdef GET_INSTRINFO_CTOR_DTOR
#undef GET_INSTRINFO_CTOR_DTOR
namespace llvm {
extern const MCInstrDesc RISCVInsts[];
extern const unsigned RISCVInstrNameIndices[];
extern const char RISCVInstrNameData[];
RISCVGenInstrInfo::RISCVGenInstrInfo(int CFSetupOpcode, int CFDestroyOpcode, int CatchRetOpcode, int ReturnOpcode)
  : TargetInstrInfo(CFSetupOpcode, CFDestroyOpcode, CatchRetOpcode, ReturnOpcode) {
  InitMCInstrInfo(RISCVInsts, RISCVInstrNameIndices, RISCVInstrNameData, 441);
}
} // end llvm namespace
#endif // GET_INSTRINFO_CTOR_DTOR

#ifdef GET_INSTRINFO_OPERAND_ENUM
#undef GET_INSTRINFO_OPERAND_ENUM
namespace llvm {
namespace RISCV {
namespace OpName {
enum {
OPERAND_LAST
};
} // end namespace OpName
} // end namespace RISCV
} // end namespace llvm
#endif //GET_INSTRINFO_OPERAND_ENUM

#ifdef GET_INSTRINFO_NAMED_OPS
#undef GET_INSTRINFO_NAMED_OPS
namespace llvm {
namespace RISCV {
LLVM_READONLY
int16_t getNamedOperandIdx(uint16_t Opcode, uint16_t NamedIdx) {
  return -1;
}
} // end namespace RISCV
} // end namespace llvm
#endif //GET_INSTRINFO_NAMED_OPS

#ifdef GET_INSTRINFO_OPERAND_TYPES_ENUM
#undef GET_INSTRINFO_OPERAND_TYPES_ENUM
namespace llvm {
namespace RISCV {
namespace OpTypes {
enum OperandType {
  bare_symbol = 0,
  c_lui_imm = 1,
  csr_sysreg = 2,
  f32imm = 3,
  f64imm = 4,
  fencearg = 5,
  frmarg = 6,
  i16imm = 7,
  i1imm = 8,
  i32imm = 9,
  i64imm = 10,
  i8imm = 11,
  ixlenimm = 12,
  ptype0 = 13,
  ptype1 = 14,
  ptype2 = 15,
  ptype3 = 16,
  ptype4 = 17,
  ptype5 = 18,
  simm10_lsb0000nonzero = 19,
  simm12 = 20,
  simm12_lsb0 = 21,
  simm13_lsb0 = 22,
  simm21_lsb0_jal = 23,
  simm6 = 24,
  simm6nonzero = 25,
  simm9_lsb0 = 26,
  type0 = 27,
  type1 = 28,
  type2 = 29,
  type3 = 30,
  type4 = 31,
  type5 = 32,
  uimm10_lsb00nonzero = 33,
  uimm20_auipc = 34,
  uimm20_lui = 35,
  uimm5 = 36,
  uimm7_lsb00 = 37,
  uimm8_lsb00 = 38,
  uimm8_lsb000 = 39,
  uimm9_lsb000 = 40,
  uimmlog2xlen = 41,
  uimmlog2xlennonzero = 42,
  OPERAND_TYPE_LIST_END
};
} // end namespace OpTypes
} // end namespace RISCV
} // end namespace llvm
#endif // GET_INSTRINFO_OPERAND_TYPES_ENUM


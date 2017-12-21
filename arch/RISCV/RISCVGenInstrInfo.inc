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
    REG_SEQUENCE	= 13,
    COPY	= 14,
    BUNDLE	= 15,
    LIFETIME_START	= 16,
    LIFETIME_END	= 17,
    STACKMAP	= 18,
    FENTRY_CALL	= 19,
    PATCHPOINT	= 20,
    LOAD_STACK_GUARD	= 21,
    STATEPOINT	= 22,
    LOCAL_ESCAPE	= 23,
    FAULTING_OP	= 24,
    PATCHABLE_OP	= 25,
    PATCHABLE_FUNCTION_ENTER	= 26,
    PATCHABLE_RET	= 27,
    PATCHABLE_FUNCTION_EXIT	= 28,
    PATCHABLE_TAIL_CALL	= 29,
    PATCHABLE_EVENT_CALL	= 30,
    G_ADD	= 31,
    G_SUB	= 32,
    G_MUL	= 33,
    G_SDIV	= 34,
    G_UDIV	= 35,
    G_SREM	= 36,
    G_UREM	= 37,
    G_AND	= 38,
    G_OR	= 39,
    G_XOR	= 40,
    G_IMPLICIT_DEF	= 41,
    G_PHI	= 42,
    G_FRAME_INDEX	= 43,
    G_GLOBAL_VALUE	= 44,
    G_EXTRACT	= 45,
    G_UNMERGE_VALUES	= 46,
    G_INSERT	= 47,
    G_MERGE_VALUES	= 48,
    G_PTRTOINT	= 49,
    G_INTTOPTR	= 50,
    G_BITCAST	= 51,
    G_LOAD	= 52,
    G_STORE	= 53,
    G_ATOMIC_CMPXCHG_WITH_SUCCESS	= 54,
    G_ATOMIC_CMPXCHG	= 55,
    G_ATOMICRMW_XCHG	= 56,
    G_ATOMICRMW_ADD	= 57,
    G_ATOMICRMW_SUB	= 58,
    G_ATOMICRMW_AND	= 59,
    G_ATOMICRMW_NAND	= 60,
    G_ATOMICRMW_OR	= 61,
    G_ATOMICRMW_XOR	= 62,
    G_ATOMICRMW_MAX	= 63,
    G_ATOMICRMW_MIN	= 64,
    G_ATOMICRMW_UMAX	= 65,
    G_ATOMICRMW_UMIN	= 66,
    G_BRCOND	= 67,
    G_BRINDIRECT	= 68,
    G_INTRINSIC	= 69,
    G_INTRINSIC_W_SIDE_EFFECTS	= 70,
    G_ANYEXT	= 71,
    G_TRUNC	= 72,
    G_CONSTANT	= 73,
    G_FCONSTANT	= 74,
    G_VASTART	= 75,
    G_VAARG	= 76,
    G_SEXT	= 77,
    G_ZEXT	= 78,
    G_SHL	= 79,
    G_LSHR	= 80,
    G_ASHR	= 81,
    G_ICMP	= 82,
    G_FCMP	= 83,
    G_SELECT	= 84,
    G_UADDE	= 85,
    G_USUBE	= 86,
    G_SADDO	= 87,
    G_SSUBO	= 88,
    G_UMULO	= 89,
    G_SMULO	= 90,
    G_UMULH	= 91,
    G_SMULH	= 92,
    G_FADD	= 93,
    G_FSUB	= 94,
    G_FMUL	= 95,
    G_FMA	= 96,
    G_FDIV	= 97,
    G_FREM	= 98,
    G_FPOW	= 99,
    G_FEXP	= 100,
    G_FEXP2	= 101,
    G_FLOG	= 102,
    G_FLOG2	= 103,
    G_FNEG	= 104,
    G_FPEXT	= 105,
    G_FPTRUNC	= 106,
    G_FPTOSI	= 107,
    G_FPTOUI	= 108,
    G_SITOFP	= 109,
    G_UITOFP	= 110,
    G_GEP	= 111,
    G_PTR_MASK	= 112,
    G_BR	= 113,
    G_INSERT_VECTOR_ELT	= 114,
    G_EXTRACT_VECTOR_ELT	= 115,
    G_SHUFFLE_VECTOR	= 116,
    G_BSWAP	= 117,
    ADD	= 118,
    ADDI	= 119,
    ADDIW	= 120,
    ADDW	= 121,
    ADJCALLSTACKDOWN	= 122,
    ADJCALLSTACKUP	= 123,
    AMOADD_D	= 124,
    AMOADD_D_AQ	= 125,
    AMOADD_D_AQ_RL	= 126,
    AMOADD_D_RL	= 127,
    AMOADD_W	= 128,
    AMOADD_W_AQ	= 129,
    AMOADD_W_AQ_RL	= 130,
    AMOADD_W_RL	= 131,
    AMOAND_D	= 132,
    AMOAND_D_AQ	= 133,
    AMOAND_D_AQ_RL	= 134,
    AMOAND_D_RL	= 135,
    AMOAND_W	= 136,
    AMOAND_W_AQ	= 137,
    AMOAND_W_AQ_RL	= 138,
    AMOAND_W_RL	= 139,
    AMOMAXU_D	= 140,
    AMOMAXU_D_AQ	= 141,
    AMOMAXU_D_AQ_RL	= 142,
    AMOMAXU_D_RL	= 143,
    AMOMAXU_W	= 144,
    AMOMAXU_W_AQ	= 145,
    AMOMAXU_W_AQ_RL	= 146,
    AMOMAXU_W_RL	= 147,
    AMOMAX_D	= 148,
    AMOMAX_D_AQ	= 149,
    AMOMAX_D_AQ_RL	= 150,
    AMOMAX_D_RL	= 151,
    AMOMAX_W	= 152,
    AMOMAX_W_AQ	= 153,
    AMOMAX_W_AQ_RL	= 154,
    AMOMAX_W_RL	= 155,
    AMOMINU_D	= 156,
    AMOMINU_D_AQ	= 157,
    AMOMINU_D_AQ_RL	= 158,
    AMOMINU_D_RL	= 159,
    AMOMINU_W	= 160,
    AMOMINU_W_AQ	= 161,
    AMOMINU_W_AQ_RL	= 162,
    AMOMINU_W_RL	= 163,
    AMOMIN_D	= 164,
    AMOMIN_D_AQ	= 165,
    AMOMIN_D_AQ_RL	= 166,
    AMOMIN_D_RL	= 167,
    AMOMIN_W	= 168,
    AMOMIN_W_AQ	= 169,
    AMOMIN_W_AQ_RL	= 170,
    AMOMIN_W_RL	= 171,
    AMOOR_D	= 172,
    AMOOR_D_AQ	= 173,
    AMOOR_D_AQ_RL	= 174,
    AMOOR_D_RL	= 175,
    AMOOR_W	= 176,
    AMOOR_W_AQ	= 177,
    AMOOR_W_AQ_RL	= 178,
    AMOOR_W_RL	= 179,
    AMOSWAP_D	= 180,
    AMOSWAP_D_AQ	= 181,
    AMOSWAP_D_AQ_RL	= 182,
    AMOSWAP_D_RL	= 183,
    AMOSWAP_W	= 184,
    AMOSWAP_W_AQ	= 185,
    AMOSWAP_W_AQ_RL	= 186,
    AMOSWAP_W_RL	= 187,
    AMOXOR_D	= 188,
    AMOXOR_D_AQ	= 189,
    AMOXOR_D_AQ_RL	= 190,
    AMOXOR_D_RL	= 191,
    AMOXOR_W	= 192,
    AMOXOR_W_AQ	= 193,
    AMOXOR_W_AQ_RL	= 194,
    AMOXOR_W_RL	= 195,
    AND	= 196,
    ANDI	= 197,
    AUIPC	= 198,
    BEQ	= 199,
    BGE	= 200,
    BGEU	= 201,
    BLT	= 202,
    BLTU	= 203,
    BNE	= 204,
    CSRRC	= 205,
    CSRRCI	= 206,
    CSRRS	= 207,
    CSRRSI	= 208,
    CSRRW	= 209,
    CSRRWI	= 210,
    DIV	= 211,
    DIVU	= 212,
    DIVUW	= 213,
    DIVW	= 214,
    EBREAK	= 215,
    ECALL	= 216,
    FADD_D	= 217,
    FADD_S	= 218,
    FCLASS_D	= 219,
    FCLASS_S	= 220,
    FCVT_D_L	= 221,
    FCVT_D_LU	= 222,
    FCVT_D_S	= 223,
    FCVT_D_W	= 224,
    FCVT_D_WU	= 225,
    FCVT_LU_D	= 226,
    FCVT_LU_S	= 227,
    FCVT_L_D	= 228,
    FCVT_L_S	= 229,
    FCVT_S_D	= 230,
    FCVT_S_L	= 231,
    FCVT_S_LU	= 232,
    FCVT_S_W	= 233,
    FCVT_S_WU	= 234,
    FCVT_WU_D	= 235,
    FCVT_WU_S	= 236,
    FCVT_W_D	= 237,
    FCVT_W_S	= 238,
    FDIV_D	= 239,
    FDIV_S	= 240,
    FENCE	= 241,
    FENCE_I	= 242,
    FEQ_D	= 243,
    FEQ_S	= 244,
    FLD	= 245,
    FLE_D	= 246,
    FLE_S	= 247,
    FLT_D	= 248,
    FLT_S	= 249,
    FLW	= 250,
    FMADD_D	= 251,
    FMADD_S	= 252,
    FMAX_D	= 253,
    FMAX_S	= 254,
    FMIN_D	= 255,
    FMIN_S	= 256,
    FMSUB_D	= 257,
    FMSUB_S	= 258,
    FMUL_D	= 259,
    FMUL_S	= 260,
    FMV_D_X	= 261,
    FMV_W_X	= 262,
    FMV_X_D	= 263,
    FMV_X_W	= 264,
    FNMADD_D	= 265,
    FNMADD_S	= 266,
    FNMSUB_D	= 267,
    FNMSUB_S	= 268,
    FSD	= 269,
    FSGNJN_D	= 270,
    FSGNJN_S	= 271,
    FSGNJX_D	= 272,
    FSGNJX_S	= 273,
    FSGNJ_D	= 274,
    FSGNJ_S	= 275,
    FSQRT_D	= 276,
    FSQRT_S	= 277,
    FSUB_D	= 278,
    FSUB_S	= 279,
    FSW	= 280,
    JAL	= 281,
    JALR	= 282,
    LB	= 283,
    LBU	= 284,
    LD	= 285,
    LH	= 286,
    LHU	= 287,
    LR_D	= 288,
    LR_D_AQ	= 289,
    LR_D_AQ_RL	= 290,
    LR_D_RL	= 291,
    LR_W	= 292,
    LR_W_AQ	= 293,
    LR_W_AQ_RL	= 294,
    LR_W_RL	= 295,
    LUI	= 296,
    LW	= 297,
    LWU	= 298,
    MUL	= 299,
    MULH	= 300,
    MULHSU	= 301,
    MULHU	= 302,
    MULW	= 303,
    OR	= 304,
    ORI	= 305,
    PseudoBR	= 306,
    PseudoBRIND	= 307,
    PseudoCALL	= 308,
    PseudoRET	= 309,
    REM	= 310,
    REMU	= 311,
    REMUW	= 312,
    REMW	= 313,
    SB	= 314,
    SC_D	= 315,
    SC_D_AQ	= 316,
    SC_D_AQ_RL	= 317,
    SC_D_RL	= 318,
    SC_W	= 319,
    SC_W_AQ	= 320,
    SC_W_AQ_RL	= 321,
    SC_W_RL	= 322,
    SD	= 323,
    SH	= 324,
    SLL	= 325,
    SLLI	= 326,
    SLLIW	= 327,
    SLLW	= 328,
    SLT	= 329,
    SLTI	= 330,
    SLTIU	= 331,
    SLTU	= 332,
    SRA	= 333,
    SRAI	= 334,
    SRAIW	= 335,
    SRAW	= 336,
    SRL	= 337,
    SRLI	= 338,
    SRLIW	= 339,
    SRLW	= 340,
    SUB	= 341,
    SUBW	= 342,
    SW	= 343,
    Select_FPR32_Using_CC_GPR	= 344,
    Select_FPR64_Using_CC_GPR	= 345,
    Select_GPR_Using_CC_GPR	= 346,
    XOR	= 347,
    XORI	= 348,
    INSTRUCTION_LIST_END = 349
  };

namespace Sched {
  enum {
    NoInstrModel	= 0,
    SCHED_LIST_END = 1
  };
} // end Sched namespace
} // end RISCV namespace
} // end llvm namespace
#endif // GET_INSTRINFO_ENUM

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
static const MCOperandInfo OperandInfo12[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo13[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo14[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo15[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo16[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, };
static const MCOperandInfo OperandInfo17[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo18[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_2, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo19[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo20[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo21[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, };
static const MCOperandInfo OperandInfo22[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, };
static const MCOperandInfo OperandInfo23[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo24[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, };
static const MCOperandInfo OperandInfo25[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, };
static const MCOperandInfo OperandInfo26[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo27[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_2, 0 }, };
static const MCOperandInfo OperandInfo28[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_2, 0 }, };
static const MCOperandInfo OperandInfo29[] = { { -1, 0, MCOI::OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI::OPERAND_GENERIC_2, 0 }, };
static const MCOperandInfo OperandInfo30[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo31[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo32[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo33[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo34[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo35[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo36[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo37[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo38[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo39[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo40[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo41[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo42[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo43[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo44[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo45[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo46[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo47[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo48[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo49[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo50[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo51[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo52[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo53[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo54[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, };
static const MCOperandInfo OperandInfo55[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo56[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo57[] = { { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR32RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo58[] = { { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::FPR64RegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };
static const MCOperandInfo OperandInfo59[] = { { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { -1, 0, MCOI::OPERAND_UNKNOWN, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, { RISCV::GPRRegClassID, 0, MCOI::OPERAND_REGISTER, 0 }, };

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
  { 13,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo7, -1 ,nullptr },  // Inst #13 = REG_SEQUENCE
  { 14,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::CheapAsAMove), 0x0ULL, nullptr, nullptr, OperandInfo7, -1 ,nullptr },  // Inst #14 = COPY
  { 15,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #15 = BUNDLE
  { 16,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #16 = LIFETIME_START
  { 17,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo3, -1 ,nullptr },  // Inst #17 = LIFETIME_END
  { 18,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo8, -1 ,nullptr },  // Inst #18 = STACKMAP
  { 19,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #19 = FENTRY_CALL
  { 20,	6,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo9, -1 ,nullptr },  // Inst #20 = PATCHPOINT
  { 21,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::Rematerializable), 0x0ULL, nullptr, nullptr, OperandInfo10, -1 ,nullptr },  // Inst #21 = LOAD_STACK_GUARD
  { 22,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #22 = STATEPOINT
  { 23,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo11, -1 ,nullptr },  // Inst #23 = LOCAL_ESCAPE
  { 24,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #24 = FAULTING_OP
  { 25,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #25 = PATCHABLE_OP
  { 26,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #26 = PATCHABLE_FUNCTION_ENTER
  { 27,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Terminator)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #27 = PATCHABLE_RET
  { 28,	0,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #28 = PATCHABLE_FUNCTION_EXIT
  { 29,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #29 = PATCHABLE_TAIL_CALL
  { 30,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::UsesCustomInserter)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo11, -1 ,nullptr },  // Inst #30 = PATCHABLE_EVENT_CALL
  { 31,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #31 = G_ADD
  { 32,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #32 = G_SUB
  { 33,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #33 = G_MUL
  { 34,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #34 = G_SDIV
  { 35,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #35 = G_UDIV
  { 36,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #36 = G_SREM
  { 37,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #37 = G_UREM
  { 38,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #38 = G_AND
  { 39,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #39 = G_OR
  { 40,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #40 = G_XOR
  { 41,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #41 = G_IMPLICIT_DEF
  { 42,	1,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #42 = G_PHI
  { 43,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #43 = G_FRAME_INDEX
  { 44,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #44 = G_GLOBAL_VALUE
  { 45,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #45 = G_EXTRACT
  { 46,	2,	2,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #46 = G_UNMERGE_VALUES
  { 47,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo17, -1 ,nullptr },  // Inst #47 = G_INSERT
  { 48,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #48 = G_MERGE_VALUES
  { 49,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #49 = G_PTRTOINT
  { 50,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #50 = G_INTTOPTR
  { 51,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #51 = G_BITCAST
  { 52,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #52 = G_LOAD
  { 53,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #53 = G_STORE
  { 54,	5,	2,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo18, -1 ,nullptr },  // Inst #54 = G_ATOMIC_CMPXCHG_WITH_SUCCESS
  { 55,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #55 = G_ATOMIC_CMPXCHG
  { 56,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #56 = G_ATOMICRMW_XCHG
  { 57,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #57 = G_ATOMICRMW_ADD
  { 58,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #58 = G_ATOMICRMW_SUB
  { 59,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #59 = G_ATOMICRMW_AND
  { 60,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #60 = G_ATOMICRMW_NAND
  { 61,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #61 = G_ATOMICRMW_OR
  { 62,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #62 = G_ATOMICRMW_XOR
  { 63,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #63 = G_ATOMICRMW_MAX
  { 64,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #64 = G_ATOMICRMW_MIN
  { 65,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #65 = G_ATOMICRMW_UMAX
  { 66,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo20, -1 ,nullptr },  // Inst #66 = G_ATOMICRMW_UMIN
  { 67,	2,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #67 = G_BRCOND
  { 68,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #68 = G_BRINDIRECT
  { 69,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Variadic), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #69 = G_INTRINSIC
  { 70,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore)|(1ULL<<MCID::Variadic)|(1ULL<<MCID::UnmodeledSideEffects), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #70 = G_INTRINSIC_W_SIDE_EFFECTS
  { 71,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #71 = G_ANYEXT
  { 72,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #72 = G_TRUNC
  { 73,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #73 = G_CONSTANT
  { 74,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo14, -1 ,nullptr },  // Inst #74 = G_FCONSTANT
  { 75,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo13, -1 ,nullptr },  // Inst #75 = G_VASTART
  { 76,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x0ULL, nullptr, nullptr, OperandInfo15, -1 ,nullptr },  // Inst #76 = G_VAARG
  { 77,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #77 = G_SEXT
  { 78,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #78 = G_ZEXT
  { 79,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #79 = G_SHL
  { 80,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #80 = G_LSHR
  { 81,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #81 = G_ASHR
  { 82,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #82 = G_ICMP
  { 83,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo21, -1 ,nullptr },  // Inst #83 = G_FCMP
  { 84,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #84 = G_SELECT
  { 85,	5,	2,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #85 = G_UADDE
  { 86,	5,	2,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo22, -1 ,nullptr },  // Inst #86 = G_USUBE
  { 87,	4,	2,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #87 = G_SADDO
  { 88,	4,	2,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #88 = G_SSUBO
  { 89,	4,	2,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #89 = G_UMULO
  { 90,	4,	2,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo19, -1 ,nullptr },  // Inst #90 = G_SMULO
  { 91,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #91 = G_UMULH
  { 92,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #92 = G_SMULH
  { 93,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #93 = G_FADD
  { 94,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #94 = G_FSUB
  { 95,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Commutable), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #95 = G_FMUL
  { 96,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo23, -1 ,nullptr },  // Inst #96 = G_FMA
  { 97,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #97 = G_FDIV
  { 98,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #98 = G_FREM
  { 99,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo12, -1 ,nullptr },  // Inst #99 = G_FPOW
  { 100,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #100 = G_FEXP
  { 101,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #101 = G_FEXP2
  { 102,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #102 = G_FLOG
  { 103,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #103 = G_FLOG2
  { 104,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #104 = G_FNEG
  { 105,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #105 = G_FPEXT
  { 106,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #106 = G_FPTRUNC
  { 107,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #107 = G_FPTOSI
  { 108,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #108 = G_FPTOUI
  { 109,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #109 = G_SITOFP
  { 110,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo16, -1 ,nullptr },  // Inst #110 = G_UITOFP
  { 111,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo25, -1 ,nullptr },  // Inst #111 = G_GEP
  { 112,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo26, -1 ,nullptr },  // Inst #112 = G_PTR_MASK
  { 113,	1,	0,	0,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #113 = G_BR
  { 114,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo27, -1 ,nullptr },  // Inst #114 = G_INSERT_VECTOR_ELT
  { 115,	3,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo28, -1 ,nullptr },  // Inst #115 = G_EXTRACT_VECTOR_ELT
  { 116,	4,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo29, -1 ,nullptr },  // Inst #116 = G_SHUFFLE_VECTOR
  { 117,	2,	1,	0,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, nullptr, nullptr, OperandInfo24, -1 ,nullptr },  // Inst #117 = G_BSWAP
  { 118,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #118 = ADD
  { 119,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #119 = ADDI
  { 120,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #120 = ADDIW
  { 121,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #121 = ADDW
  { 122,	2,	0,	4,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo8, -1 ,nullptr },  // Inst #122 = ADJCALLSTACKDOWN
  { 123,	2,	0,	4,	0,	0|(1ULL<<MCID::Pseudo), 0x0ULL, ImplicitList1, ImplicitList1, OperandInfo8, -1 ,nullptr },  // Inst #123 = ADJCALLSTACKUP
  { 124,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #124 = AMOADD_D
  { 125,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #125 = AMOADD_D_AQ
  { 126,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #126 = AMOADD_D_AQ_RL
  { 127,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #127 = AMOADD_D_RL
  { 128,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #128 = AMOADD_W
  { 129,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #129 = AMOADD_W_AQ
  { 130,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #130 = AMOADD_W_AQ_RL
  { 131,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #131 = AMOADD_W_RL
  { 132,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #132 = AMOAND_D
  { 133,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #133 = AMOAND_D_AQ
  { 134,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #134 = AMOAND_D_AQ_RL
  { 135,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #135 = AMOAND_D_RL
  { 136,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #136 = AMOAND_W
  { 137,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #137 = AMOAND_W_AQ
  { 138,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #138 = AMOAND_W_AQ_RL
  { 139,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #139 = AMOAND_W_RL
  { 140,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #140 = AMOMAXU_D
  { 141,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #141 = AMOMAXU_D_AQ
  { 142,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #142 = AMOMAXU_D_AQ_RL
  { 143,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #143 = AMOMAXU_D_RL
  { 144,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #144 = AMOMAXU_W
  { 145,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #145 = AMOMAXU_W_AQ
  { 146,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #146 = AMOMAXU_W_AQ_RL
  { 147,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #147 = AMOMAXU_W_RL
  { 148,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #148 = AMOMAX_D
  { 149,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #149 = AMOMAX_D_AQ
  { 150,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #150 = AMOMAX_D_AQ_RL
  { 151,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #151 = AMOMAX_D_RL
  { 152,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #152 = AMOMAX_W
  { 153,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #153 = AMOMAX_W_AQ
  { 154,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #154 = AMOMAX_W_AQ_RL
  { 155,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #155 = AMOMAX_W_RL
  { 156,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #156 = AMOMINU_D
  { 157,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #157 = AMOMINU_D_AQ
  { 158,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #158 = AMOMINU_D_AQ_RL
  { 159,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #159 = AMOMINU_D_RL
  { 160,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #160 = AMOMINU_W
  { 161,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #161 = AMOMINU_W_AQ
  { 162,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #162 = AMOMINU_W_AQ_RL
  { 163,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #163 = AMOMINU_W_RL
  { 164,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #164 = AMOMIN_D
  { 165,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #165 = AMOMIN_D_AQ
  { 166,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #166 = AMOMIN_D_AQ_RL
  { 167,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #167 = AMOMIN_D_RL
  { 168,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #168 = AMOMIN_W
  { 169,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #169 = AMOMIN_W_AQ
  { 170,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #170 = AMOMIN_W_AQ_RL
  { 171,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #171 = AMOMIN_W_RL
  { 172,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #172 = AMOOR_D
  { 173,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #173 = AMOOR_D_AQ
  { 174,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #174 = AMOOR_D_AQ_RL
  { 175,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #175 = AMOOR_D_RL
  { 176,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #176 = AMOOR_W
  { 177,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #177 = AMOOR_W_AQ
  { 178,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #178 = AMOOR_W_AQ_RL
  { 179,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #179 = AMOOR_W_RL
  { 180,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #180 = AMOSWAP_D
  { 181,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #181 = AMOSWAP_D_AQ
  { 182,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #182 = AMOSWAP_D_AQ_RL
  { 183,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #183 = AMOSWAP_D_RL
  { 184,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #184 = AMOSWAP_W
  { 185,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #185 = AMOSWAP_W_AQ
  { 186,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #186 = AMOSWAP_W_AQ_RL
  { 187,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #187 = AMOSWAP_W_RL
  { 188,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #188 = AMOXOR_D
  { 189,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #189 = AMOXOR_D_AQ
  { 190,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #190 = AMOXOR_D_AQ_RL
  { 191,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #191 = AMOXOR_D_RL
  { 192,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #192 = AMOXOR_W
  { 193,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #193 = AMOXOR_W_AQ
  { 194,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #194 = AMOXOR_W_AQ_RL
  { 195,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #195 = AMOXOR_W_RL
  { 196,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #196 = AND
  { 197,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #197 = ANDI
  { 198,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #198 = AUIPC
  { 199,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #199 = BEQ
  { 200,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #200 = BGE
  { 201,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #201 = BGEU
  { 202,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #202 = BLT
  { 203,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #203 = BLTU
  { 204,	3,	0,	4,	0,	0|(1ULL<<MCID::Branch)|(1ULL<<MCID::Terminator), 0x5ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #204 = BNE
  { 205,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #205 = CSRRC
  { 206,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #206 = CSRRCI
  { 207,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #207 = CSRRS
  { 208,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #208 = CSRRSI
  { 209,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo33, -1 ,nullptr },  // Inst #209 = CSRRW
  { 210,	3,	1,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo34, -1 ,nullptr },  // Inst #210 = CSRRWI
  { 211,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #211 = DIV
  { 212,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #212 = DIVU
  { 213,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #213 = DIVUW
  { 214,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #214 = DIVW
  { 215,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #215 = EBREAK
  { 216,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #216 = ECALL
  { 217,	4,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #217 = FADD_D
  { 218,	4,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #218 = FADD_S
  { 219,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #219 = FCLASS_D
  { 220,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #220 = FCLASS_S
  { 221,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #221 = FCVT_D_L
  { 222,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #222 = FCVT_D_LU
  { 223,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo40, -1 ,nullptr },  // Inst #223 = FCVT_D_S
  { 224,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #224 = FCVT_D_W
  { 225,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #225 = FCVT_D_WU
  { 226,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo42, -1 ,nullptr },  // Inst #226 = FCVT_LU_D
  { 227,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #227 = FCVT_LU_S
  { 228,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo42, -1 ,nullptr },  // Inst #228 = FCVT_L_D
  { 229,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #229 = FCVT_L_S
  { 230,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo44, -1 ,nullptr },  // Inst #230 = FCVT_S_D
  { 231,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #231 = FCVT_S_L
  { 232,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #232 = FCVT_S_LU
  { 233,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #233 = FCVT_S_W
  { 234,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #234 = FCVT_S_WU
  { 235,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo42, -1 ,nullptr },  // Inst #235 = FCVT_WU_D
  { 236,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #236 = FCVT_WU_S
  { 237,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo42, -1 ,nullptr },  // Inst #237 = FCVT_W_D
  { 238,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo43, -1 ,nullptr },  // Inst #238 = FCVT_W_S
  { 239,	4,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #239 = FDIV_D
  { 240,	4,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #240 = FDIV_S
  { 241,	2,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, OperandInfo7, -1 ,nullptr },  // Inst #241 = FENCE
  { 242,	0,	0,	4,	0,	0|(1ULL<<MCID::UnmodeledSideEffects), 0x3ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #242 = FENCE_I
  { 243,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #243 = FEQ_D
  { 244,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #244 = FEQ_S
  { 245,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #245 = FLD
  { 246,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #246 = FLE_D
  { 247,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #247 = FLE_S
  { 248,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo46, -1 ,nullptr },  // Inst #248 = FLT_D
  { 249,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo47, -1 ,nullptr },  // Inst #249 = FLT_S
  { 250,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #250 = FLW
  { 251,	5,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #251 = FMADD_D
  { 252,	5,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #252 = FMADD_S
  { 253,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #253 = FMAX_D
  { 254,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #254 = FMAX_S
  { 255,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #255 = FMIN_D
  { 256,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #256 = FMIN_S
  { 257,	5,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #257 = FMSUB_D
  { 258,	5,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #258 = FMSUB_S
  { 259,	4,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #259 = FMUL_D
  { 260,	4,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #260 = FMUL_S
  { 261,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo41, -1 ,nullptr },  // Inst #261 = FMV_D_X
  { 262,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo52, -1 ,nullptr },  // Inst #262 = FMV_W_X
  { 263,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo37, -1 ,nullptr },  // Inst #263 = FMV_X_D
  { 264,	2,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo38, -1 ,nullptr },  // Inst #264 = FMV_X_W
  { 265,	5,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #265 = FNMADD_D
  { 266,	5,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #266 = FNMADD_S
  { 267,	5,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo48, -1 ,nullptr },  // Inst #267 = FNMSUB_D
  { 268,	5,	1,	4,	0,	0, 0x2ULL, nullptr, nullptr, OperandInfo49, -1 ,nullptr },  // Inst #268 = FNMSUB_S
  { 269,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, nullptr, OperandInfo39, -1 ,nullptr },  // Inst #269 = FSD
  { 270,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #270 = FSGNJN_D
  { 271,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #271 = FSGNJN_S
  { 272,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #272 = FSGNJX_D
  { 273,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #273 = FSGNJX_S
  { 274,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo50, -1 ,nullptr },  // Inst #274 = FSGNJ_D
  { 275,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo51, -1 ,nullptr },  // Inst #275 = FSGNJ_S
  { 276,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo53, -1 ,nullptr },  // Inst #276 = FSQRT_D
  { 277,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo54, -1 ,nullptr },  // Inst #277 = FSQRT_S
  { 278,	4,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo35, -1 ,nullptr },  // Inst #278 = FSUB_D
  { 279,	4,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo36, -1 ,nullptr },  // Inst #279 = FSUB_S
  { 280,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, nullptr, OperandInfo45, -1 ,nullptr },  // Inst #280 = FSW
  { 281,	2,	1,	4,	0,	0|(1ULL<<MCID::Call), 0x7ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #281 = JAL
  { 282,	3,	1,	4,	0,	0|(1ULL<<MCID::Call), 0x3ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #282 = JALR
  { 283,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #283 = LB
  { 284,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #284 = LBU
  { 285,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #285 = LD
  { 286,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #286 = LH
  { 287,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #287 = LHU
  { 288,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo55, -1 ,nullptr },  // Inst #288 = LR_D
  { 289,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo55, -1 ,nullptr },  // Inst #289 = LR_D_AQ
  { 290,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo55, -1 ,nullptr },  // Inst #290 = LR_D_AQ_RL
  { 291,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo55, -1 ,nullptr },  // Inst #291 = LR_D_RL
  { 292,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo55, -1 ,nullptr },  // Inst #292 = LR_W
  { 293,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo55, -1 ,nullptr },  // Inst #293 = LR_W_AQ
  { 294,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo55, -1 ,nullptr },  // Inst #294 = LR_W_AQ_RL
  { 295,	2,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x1ULL, nullptr, nullptr, OperandInfo55, -1 ,nullptr },  // Inst #295 = LR_W_RL
  { 296,	2,	1,	4,	0,	0, 0x6ULL, nullptr, nullptr, OperandInfo32, -1 ,nullptr },  // Inst #296 = LUI
  { 297,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #297 = LW
  { 298,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad), 0x3ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #298 = LWU
  { 299,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #299 = MUL
  { 300,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #300 = MULH
  { 301,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #301 = MULHSU
  { 302,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #302 = MULHU
  { 303,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #303 = MULW
  { 304,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #304 = OR
  { 305,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #305 = ORI
  { 306,	1,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, OperandInfo2, -1 ,nullptr },  // Inst #306 = PseudoBR
  { 307,	2,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Branch)|(1ULL<<MCID::IndirectBranch)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Call)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, ImplicitList2, OperandInfo32, -1 ,nullptr },  // Inst #307 = PseudoBRIND
  { 308,	1,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Call), 0x0ULL, nullptr, ImplicitList2, OperandInfo56, -1 ,nullptr },  // Inst #308 = PseudoCALL
  { 309,	0,	0,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::Return)|(1ULL<<MCID::Barrier)|(1ULL<<MCID::Terminator), 0x0ULL, nullptr, nullptr, nullptr, -1 ,nullptr },  // Inst #309 = PseudoRET
  { 310,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #310 = REM
  { 311,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #311 = REMU
  { 312,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #312 = REMUW
  { 313,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #313 = REMW
  { 314,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #314 = SB
  { 315,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #315 = SC_D
  { 316,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #316 = SC_D_AQ
  { 317,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #317 = SC_D_AQ_RL
  { 318,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #318 = SC_D_RL
  { 319,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #319 = SC_W
  { 320,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #320 = SC_W_AQ
  { 321,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #321 = SC_W_AQ_RL
  { 322,	3,	1,	4,	0,	0|(1ULL<<MCID::MayLoad)|(1ULL<<MCID::MayStore), 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #322 = SC_W_RL
  { 323,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #323 = SD
  { 324,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #324 = SH
  { 325,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #325 = SLL
  { 326,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #326 = SLLI
  { 327,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #327 = SLLIW
  { 328,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #328 = SLLW
  { 329,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #329 = SLT
  { 330,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #330 = SLTI
  { 331,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #331 = SLTIU
  { 332,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #332 = SLTU
  { 333,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #333 = SRA
  { 334,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #334 = SRAI
  { 335,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #335 = SRAIW
  { 336,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #336 = SRAW
  { 337,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #337 = SRL
  { 338,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #338 = SRLI
  { 339,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #339 = SRLIW
  { 340,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #340 = SRLW
  { 341,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #341 = SUB
  { 342,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #342 = SUBW
  { 343,	3,	0,	4,	0,	0|(1ULL<<MCID::MayStore), 0x4ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #343 = SW
  { 344,	6,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo57, -1 ,nullptr },  // Inst #344 = Select_FPR32_Using_CC_GPR
  { 345,	6,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo58, -1 ,nullptr },  // Inst #345 = Select_FPR64_Using_CC_GPR
  { 346,	6,	1,	4,	0,	0|(1ULL<<MCID::Pseudo)|(1ULL<<MCID::UsesCustomInserter), 0x0ULL, nullptr, nullptr, OperandInfo59, -1 ,nullptr },  // Inst #346 = Select_GPR_Using_CC_GPR
  { 347,	3,	1,	4,	0,	0, 0x1ULL, nullptr, nullptr, OperandInfo30, -1 ,nullptr },  // Inst #347 = XOR
  { 348,	3,	1,	4,	0,	0, 0x3ULL, nullptr, nullptr, OperandInfo31, -1 ,nullptr },  // Inst #348 = XORI
};

extern const char RISCVInstrNameData[] = {
  /* 0 */ 'G', '_', 'F', 'L', 'O', 'G', '2', 0,
  /* 8 */ 'G', '_', 'F', 'E', 'X', 'P', '2', 0,
  /* 16 */ 'G', '_', 'F', 'M', 'A', 0,
  /* 22 */ 'S', 'R', 'A', 0,
  /* 26 */ 'L', 'B', 0,
  /* 29 */ 'S', 'B', 0,
  /* 32 */ 'G', '_', 'F', 'S', 'U', 'B', 0,
  /* 39 */ 'G', '_', 'S', 'U', 'B', 0,
  /* 45 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'S', 'U', 'B', 0,
  /* 61 */ 'G', '_', 'I', 'N', 'T', 'R', 'I', 'N', 'S', 'I', 'C', 0,
  /* 73 */ 'G', '_', 'F', 'P', 'T', 'R', 'U', 'N', 'C', 0,
  /* 83 */ 'G', '_', 'T', 'R', 'U', 'N', 'C', 0,
  /* 91 */ 'A', 'U', 'I', 'P', 'C', 0,
  /* 97 */ 'C', 'S', 'R', 'R', 'C', 0,
  /* 103 */ 'G', '_', 'L', 'O', 'A', 'D', 0,
  /* 110 */ 'G', '_', 'F', 'A', 'D', 'D', 0,
  /* 117 */ 'G', '_', 'A', 'D', 'D', 0,
  /* 123 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'A', 'D', 'D', 0,
  /* 139 */ 'F', 'L', 'D', 0,
  /* 143 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'N', 'A', 'N', 'D', 0,
  /* 160 */ 'G', '_', 'A', 'N', 'D', 0,
  /* 166 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'A', 'N', 'D', 0,
  /* 182 */ 'L', 'I', 'F', 'E', 'T', 'I', 'M', 'E', '_', 'E', 'N', 'D', 0,
  /* 195 */ 'P', 's', 'e', 'u', 'd', 'o', 'B', 'R', 'I', 'N', 'D', 0,
  /* 207 */ 'G', '_', 'B', 'R', 'C', 'O', 'N', 'D', 0,
  /* 216 */ 'L', 'O', 'A', 'D', '_', 'S', 'T', 'A', 'C', 'K', '_', 'G', 'U', 'A', 'R', 'D', 0,
  /* 233 */ 'F', 'S', 'D', 0,
  /* 237 */ 'F', 'S', 'U', 'B', '_', 'D', 0,
  /* 244 */ 'F', 'M', 'S', 'U', 'B', '_', 'D', 0,
  /* 252 */ 'F', 'N', 'M', 'S', 'U', 'B', '_', 'D', 0,
  /* 261 */ 'S', 'C', '_', 'D', 0,
  /* 266 */ 'F', 'A', 'D', 'D', '_', 'D', 0,
  /* 273 */ 'F', 'M', 'A', 'D', 'D', '_', 'D', 0,
  /* 281 */ 'F', 'N', 'M', 'A', 'D', 'D', '_', 'D', 0,
  /* 290 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'D', 0,
  /* 299 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'D', 0,
  /* 308 */ 'F', 'L', 'E', '_', 'D', 0,
  /* 314 */ 'F', 'S', 'G', 'N', 'J', '_', 'D', 0,
  /* 322 */ 'F', 'M', 'U', 'L', '_', 'D', 0,
  /* 329 */ 'F', 'C', 'V', 'T', '_', 'L', '_', 'D', 0,
  /* 338 */ 'F', 'M', 'I', 'N', '_', 'D', 0,
  /* 345 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'D', 0,
  /* 354 */ 'F', 'S', 'G', 'N', 'J', 'N', '_', 'D', 0,
  /* 363 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'D', 0,
  /* 373 */ 'F', 'E', 'Q', '_', 'D', 0,
  /* 379 */ 'L', 'R', '_', 'D', 0,
  /* 384 */ 'A', 'M', 'O', 'O', 'R', '_', 'D', 0,
  /* 392 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'D', 0,
  /* 401 */ 'F', 'C', 'L', 'A', 'S', 'S', '_', 'D', 0,
  /* 410 */ 'F', 'C', 'V', 'T', '_', 'S', '_', 'D', 0,
  /* 419 */ 'F', 'L', 'T', '_', 'D', 0,
  /* 425 */ 'F', 'S', 'Q', 'R', 'T', '_', 'D', 0,
  /* 433 */ 'F', 'C', 'V', 'T', '_', 'L', 'U', '_', 'D', 0,
  /* 443 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'D', 0,
  /* 453 */ 'F', 'C', 'V', 'T', '_', 'W', 'U', '_', 'D', 0,
  /* 463 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'D', 0,
  /* 473 */ 'F', 'D', 'I', 'V', '_', 'D', 0,
  /* 480 */ 'F', 'C', 'V', 'T', '_', 'W', '_', 'D', 0,
  /* 489 */ 'F', 'M', 'A', 'X', '_', 'D', 0,
  /* 496 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'D', 0,
  /* 505 */ 'F', 'S', 'G', 'N', 'J', 'X', '_', 'D', 0,
  /* 514 */ 'F', 'M', 'V', '_', 'X', '_', 'D', 0,
  /* 522 */ 'G', '_', 'U', 'S', 'U', 'B', 'E', 0,
  /* 530 */ 'F', 'E', 'N', 'C', 'E', 0,
  /* 536 */ 'R', 'E', 'G', '_', 'S', 'E', 'Q', 'U', 'E', 'N', 'C', 'E', 0,
  /* 549 */ 'G', '_', 'U', 'A', 'D', 'D', 'E', 0,
  /* 557 */ 'B', 'G', 'E', 0,
  /* 561 */ 'B', 'U', 'N', 'D', 'L', 'E', 0,
  /* 568 */ 'B', 'N', 'E', 0,
  /* 572 */ 'L', 'O', 'C', 'A', 'L', '_', 'E', 'S', 'C', 'A', 'P', 'E', 0,
  /* 585 */ 'G', '_', 'S', 'T', 'O', 'R', 'E', 0,
  /* 593 */ 'D', 'B', 'G', '_', 'V', 'A', 'L', 'U', 'E', 0,
  /* 603 */ 'G', '_', 'G', 'L', 'O', 'B', 'A', 'L', '_', 'V', 'A', 'L', 'U', 'E', 0,
  /* 618 */ 'G', '_', 'I', 'M', 'P', 'L', 'I', 'C', 'I', 'T', '_', 'D', 'E', 'F', 0,
  /* 633 */ 'G', '_', 'F', 'N', 'E', 'G', 0,
  /* 640 */ 'E', 'X', 'T', 'R', 'A', 'C', 'T', '_', 'S', 'U', 'B', 'R', 'E', 'G', 0,
  /* 655 */ 'I', 'N', 'S', 'E', 'R', 'T', '_', 'S', 'U', 'B', 'R', 'E', 'G', 0,
  /* 669 */ 'S', 'U', 'B', 'R', 'E', 'G', '_', 'T', 'O', '_', 'R', 'E', 'G', 0,
  /* 683 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', '_', 'C', 'M', 'P', 'X', 'C', 'H', 'G', 0,
  /* 700 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'X', 'C', 'H', 'G', 0,
  /* 717 */ 'G', '_', 'F', 'L', 'O', 'G', 0,
  /* 724 */ 'G', '_', 'V', 'A', 'A', 'R', 'G', 0,
  /* 732 */ 'G', '_', 'S', 'M', 'U', 'L', 'H', 0,
  /* 740 */ 'G', '_', 'U', 'M', 'U', 'L', 'H', 0,
  /* 748 */ 'S', 'H', 0,
  /* 751 */ 'S', 'R', 'A', 'I', 0,
  /* 756 */ 'C', 'S', 'R', 'R', 'C', 'I', 0,
  /* 763 */ 'A', 'D', 'D', 'I', 0,
  /* 768 */ 'A', 'N', 'D', 'I', 0,
  /* 773 */ 'G', '_', 'P', 'H', 'I', 0,
  /* 779 */ 'S', 'L', 'L', 'I', 0,
  /* 784 */ 'S', 'R', 'L', 'I', 0,
  /* 789 */ 'X', 'O', 'R', 'I', 0,
  /* 794 */ 'G', '_', 'F', 'P', 'T', 'O', 'S', 'I', 0,
  /* 803 */ 'C', 'S', 'R', 'R', 'S', 'I', 0,
  /* 810 */ 'S', 'L', 'T', 'I', 0,
  /* 815 */ 'L', 'U', 'I', 0,
  /* 819 */ 'G', '_', 'F', 'P', 'T', 'O', 'U', 'I', 0,
  /* 828 */ 'C', 'S', 'R', 'R', 'W', 'I', 0,
  /* 835 */ 'F', 'E', 'N', 'C', 'E', '_', 'I', 0,
  /* 843 */ 'E', 'B', 'R', 'E', 'A', 'K', 0,
  /* 850 */ 'G', '_', 'P', 'T', 'R', '_', 'M', 'A', 'S', 'K', 0,
  /* 861 */ 'J', 'A', 'L', 0,
  /* 865 */ 'G', 'C', '_', 'L', 'A', 'B', 'E', 'L', 0,
  /* 874 */ 'E', 'H', '_', 'L', 'A', 'B', 'E', 'L', 0,
  /* 883 */ 'A', 'N', 'N', 'O', 'T', 'A', 'T', 'I', 'O', 'N', '_', 'L', 'A', 'B', 'E', 'L', 0,
  /* 900 */ 'G', '_', 'S', 'H', 'L', 0,
  /* 906 */ 'E', 'C', 'A', 'L', 'L', 0,
  /* 912 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'T', 'A', 'I', 'L', '_', 'C', 'A', 'L', 'L', 0,
  /* 932 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'E', 'V', 'E', 'N', 'T', '_', 'C', 'A', 'L', 'L', 0,
  /* 953 */ 'F', 'E', 'N', 'T', 'R', 'Y', '_', 'C', 'A', 'L', 'L', 0,
  /* 965 */ 'P', 's', 'e', 'u', 'd', 'o', 'C', 'A', 'L', 'L', 0,
  /* 976 */ 'K', 'I', 'L', 'L', 0,
  /* 981 */ 'S', 'L', 'L', 0,
  /* 985 */ 'S', 'R', 'L', 0,
  /* 989 */ 'S', 'C', '_', 'D', '_', 'R', 'L', 0,
  /* 997 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'D', '_', 'R', 'L', 0,
  /* 1009 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'D', '_', 'R', 'L', 0,
  /* 1021 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'D', '_', 'R', 'L', 0,
  /* 1033 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'D', '_', 'R', 'L', 0,
  /* 1046 */ 'L', 'R', '_', 'D', '_', 'R', 'L', 0,
  /* 1054 */ 'A', 'M', 'O', 'O', 'R', '_', 'D', '_', 'R', 'L', 0,
  /* 1065 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'D', '_', 'R', 'L', 0,
  /* 1077 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'D', '_', 'R', 'L', 0,
  /* 1090 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'D', '_', 'R', 'L', 0,
  /* 1103 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'D', '_', 'R', 'L', 0,
  /* 1115 */ 'S', 'C', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1126 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1141 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1156 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1171 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1187 */ 'L', 'R', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1198 */ 'A', 'M', 'O', 'O', 'R', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1212 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1227 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1243 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1259 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'D', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1274 */ 'S', 'C', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1285 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1300 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1315 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1330 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1346 */ 'L', 'R', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1357 */ 'A', 'M', 'O', 'O', 'R', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1371 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1386 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1402 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1418 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'W', '_', 'A', 'Q', '_', 'R', 'L', 0,
  /* 1433 */ 'S', 'C', '_', 'W', '_', 'R', 'L', 0,
  /* 1441 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'W', '_', 'R', 'L', 0,
  /* 1453 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'W', '_', 'R', 'L', 0,
  /* 1465 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'W', '_', 'R', 'L', 0,
  /* 1477 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'W', '_', 'R', 'L', 0,
  /* 1490 */ 'L', 'R', '_', 'W', '_', 'R', 'L', 0,
  /* 1498 */ 'A', 'M', 'O', 'O', 'R', '_', 'W', '_', 'R', 'L', 0,
  /* 1509 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'W', '_', 'R', 'L', 0,
  /* 1521 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'W', '_', 'R', 'L', 0,
  /* 1534 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'W', '_', 'R', 'L', 0,
  /* 1547 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'W', '_', 'R', 'L', 0,
  /* 1559 */ 'G', '_', 'F', 'M', 'U', 'L', 0,
  /* 1566 */ 'G', '_', 'M', 'U', 'L', 0,
  /* 1572 */ 'F', 'C', 'V', 'T', '_', 'D', '_', 'L', 0,
  /* 1581 */ 'F', 'C', 'V', 'T', '_', 'S', '_', 'L', 0,
  /* 1590 */ 'G', '_', 'F', 'R', 'E', 'M', 0,
  /* 1597 */ 'G', '_', 'S', 'R', 'E', 'M', 0,
  /* 1604 */ 'G', '_', 'U', 'R', 'E', 'M', 0,
  /* 1611 */ 'I', 'N', 'L', 'I', 'N', 'E', 'A', 'S', 'M', 0,
  /* 1621 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'U', 'M', 'I', 'N', 0,
  /* 1638 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'M', 'I', 'N', 0,
  /* 1654 */ 'C', 'F', 'I', '_', 'I', 'N', 'S', 'T', 'R', 'U', 'C', 'T', 'I', 'O', 'N', 0,
  /* 1670 */ 'A', 'D', 'J', 'C', 'A', 'L', 'L', 'S', 'T', 'A', 'C', 'K', 'D', 'O', 'W', 'N', 0,
  /* 1687 */ 'G', '_', 'S', 'S', 'U', 'B', 'O', 0,
  /* 1695 */ 'G', '_', 'S', 'A', 'D', 'D', 'O', 0,
  /* 1703 */ 'G', '_', 'S', 'M', 'U', 'L', 'O', 0,
  /* 1711 */ 'G', '_', 'U', 'M', 'U', 'L', 'O', 0,
  /* 1719 */ 'S', 'T', 'A', 'C', 'K', 'M', 'A', 'P', 0,
  /* 1728 */ 'G', '_', 'B', 'S', 'W', 'A', 'P', 0,
  /* 1736 */ 'G', '_', 'G', 'E', 'P', 0,
  /* 1742 */ 'G', '_', 'S', 'I', 'T', 'O', 'F', 'P', 0,
  /* 1751 */ 'G', '_', 'U', 'I', 'T', 'O', 'F', 'P', 0,
  /* 1760 */ 'G', '_', 'F', 'C', 'M', 'P', 0,
  /* 1767 */ 'G', '_', 'I', 'C', 'M', 'P', 0,
  /* 1774 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'O', 'P', 0,
  /* 1787 */ 'F', 'A', 'U', 'L', 'T', 'I', 'N', 'G', '_', 'O', 'P', 0,
  /* 1799 */ 'A', 'D', 'J', 'C', 'A', 'L', 'L', 'S', 'T', 'A', 'C', 'K', 'U', 'P', 0,
  /* 1814 */ 'G', '_', 'F', 'E', 'X', 'P', 0,
  /* 1821 */ 'S', 'C', '_', 'D', '_', 'A', 'Q', 0,
  /* 1829 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'D', '_', 'A', 'Q', 0,
  /* 1841 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'D', '_', 'A', 'Q', 0,
  /* 1853 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'D', '_', 'A', 'Q', 0,
  /* 1865 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'D', '_', 'A', 'Q', 0,
  /* 1878 */ 'L', 'R', '_', 'D', '_', 'A', 'Q', 0,
  /* 1886 */ 'A', 'M', 'O', 'O', 'R', '_', 'D', '_', 'A', 'Q', 0,
  /* 1897 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'D', '_', 'A', 'Q', 0,
  /* 1909 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'D', '_', 'A', 'Q', 0,
  /* 1922 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'D', '_', 'A', 'Q', 0,
  /* 1935 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'D', '_', 'A', 'Q', 0,
  /* 1947 */ 'S', 'C', '_', 'W', '_', 'A', 'Q', 0,
  /* 1955 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'W', '_', 'A', 'Q', 0,
  /* 1967 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'W', '_', 'A', 'Q', 0,
  /* 1979 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'W', '_', 'A', 'Q', 0,
  /* 1991 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'W', '_', 'A', 'Q', 0,
  /* 2004 */ 'L', 'R', '_', 'W', '_', 'A', 'Q', 0,
  /* 2012 */ 'A', 'M', 'O', 'O', 'R', '_', 'W', '_', 'A', 'Q', 0,
  /* 2023 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'W', '_', 'A', 'Q', 0,
  /* 2035 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'W', '_', 'A', 'Q', 0,
  /* 2048 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'W', '_', 'A', 'Q', 0,
  /* 2061 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'W', '_', 'A', 'Q', 0,
  /* 2073 */ 'B', 'E', 'Q', 0,
  /* 2077 */ 'G', '_', 'B', 'R', 0,
  /* 2082 */ 'P', 's', 'e', 'u', 'd', 'o', 'B', 'R', 0,
  /* 2091 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'F', 'U', 'N', 'C', 'T', 'I', 'O', 'N', '_', 'E', 'N', 'T', 'E', 'R', 0,
  /* 2116 */ 'G', '_', 'A', 'S', 'H', 'R', 0,
  /* 2123 */ 'G', '_', 'L', 'S', 'H', 'R', 0,
  /* 2130 */ 'J', 'A', 'L', 'R', 0,
  /* 2135 */ 'G', '_', 'S', 'H', 'U', 'F', 'F', 'L', 'E', '_', 'V', 'E', 'C', 'T', 'O', 'R', 0,
  /* 2152 */ 'G', '_', 'X', 'O', 'R', 0,
  /* 2158 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'X', 'O', 'R', 0,
  /* 2174 */ 'G', '_', 'O', 'R', 0,
  /* 2179 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'O', 'R', 0,
  /* 2194 */ 'S', 'e', 'l', 'e', 'c', 't', '_', 'F', 'P', 'R', '3', '2', '_', 'U', 's', 'i', 'n', 'g', '_', 'C', 'C', '_', 'G', 'P', 'R', 0,
  /* 2220 */ 'S', 'e', 'l', 'e', 'c', 't', '_', 'F', 'P', 'R', '6', '4', '_', 'U', 's', 'i', 'n', 'g', '_', 'C', 'C', '_', 'G', 'P', 'R', 0,
  /* 2246 */ 'S', 'e', 'l', 'e', 'c', 't', '_', 'G', 'P', 'R', '_', 'U', 's', 'i', 'n', 'g', '_', 'C', 'C', '_', 'G', 'P', 'R', 0,
  /* 2270 */ 'G', '_', 'I', 'N', 'T', 'T', 'O', 'P', 'T', 'R', 0,
  /* 2281 */ 'G', '_', 'U', 'N', 'M', 'E', 'R', 'G', 'E', '_', 'V', 'A', 'L', 'U', 'E', 'S', 0,
  /* 2298 */ 'G', '_', 'M', 'E', 'R', 'G', 'E', '_', 'V', 'A', 'L', 'U', 'E', 'S', 0,
  /* 2313 */ 'C', 'S', 'R', 'R', 'S', 0,
  /* 2319 */ 'C', 'O', 'P', 'Y', '_', 'T', 'O', '_', 'R', 'E', 'G', 'C', 'L', 'A', 'S', 'S', 0,
  /* 2336 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', '_', 'C', 'M', 'P', 'X', 'C', 'H', 'G', '_', 'W', 'I', 'T', 'H', '_', 'S', 'U', 'C', 'C', 'E', 'S', 'S', 0,
  /* 2366 */ 'G', '_', 'I', 'N', 'T', 'R', 'I', 'N', 'S', 'I', 'C', '_', 'W', '_', 'S', 'I', 'D', 'E', '_', 'E', 'F', 'F', 'E', 'C', 'T', 'S', 0,
  /* 2393 */ 'F', 'S', 'U', 'B', '_', 'S', 0,
  /* 2400 */ 'F', 'M', 'S', 'U', 'B', '_', 'S', 0,
  /* 2408 */ 'F', 'N', 'M', 'S', 'U', 'B', '_', 'S', 0,
  /* 2417 */ 'F', 'A', 'D', 'D', '_', 'S', 0,
  /* 2424 */ 'F', 'M', 'A', 'D', 'D', '_', 'S', 0,
  /* 2432 */ 'F', 'N', 'M', 'A', 'D', 'D', '_', 'S', 0,
  /* 2441 */ 'F', 'C', 'V', 'T', '_', 'D', '_', 'S', 0,
  /* 2450 */ 'F', 'L', 'E', '_', 'S', 0,
  /* 2456 */ 'F', 'S', 'G', 'N', 'J', '_', 'S', 0,
  /* 2464 */ 'F', 'M', 'U', 'L', '_', 'S', 0,
  /* 2471 */ 'F', 'C', 'V', 'T', '_', 'L', '_', 'S', 0,
  /* 2480 */ 'F', 'M', 'I', 'N', '_', 'S', 0,
  /* 2487 */ 'F', 'S', 'G', 'N', 'J', 'N', '_', 'S', 0,
  /* 2496 */ 'F', 'E', 'Q', '_', 'S', 0,
  /* 2502 */ 'F', 'C', 'L', 'A', 'S', 'S', '_', 'S', 0,
  /* 2511 */ 'F', 'L', 'T', '_', 'S', 0,
  /* 2517 */ 'F', 'S', 'Q', 'R', 'T', '_', 'S', 0,
  /* 2525 */ 'F', 'C', 'V', 'T', '_', 'L', 'U', '_', 'S', 0,
  /* 2535 */ 'F', 'C', 'V', 'T', '_', 'W', 'U', '_', 'S', 0,
  /* 2545 */ 'F', 'D', 'I', 'V', '_', 'S', 0,
  /* 2552 */ 'F', 'C', 'V', 'T', '_', 'W', '_', 'S', 0,
  /* 2561 */ 'F', 'M', 'A', 'X', '_', 'S', 0,
  /* 2568 */ 'F', 'S', 'G', 'N', 'J', 'X', '_', 'S', 0,
  /* 2577 */ 'G', '_', 'E', 'X', 'T', 'R', 'A', 'C', 'T', 0,
  /* 2587 */ 'G', '_', 'S', 'E', 'L', 'E', 'C', 'T', 0,
  /* 2596 */ 'G', '_', 'B', 'R', 'I', 'N', 'D', 'I', 'R', 'E', 'C', 'T', 0,
  /* 2609 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'R', 'E', 'T', 0,
  /* 2623 */ 'P', 's', 'e', 'u', 'd', 'o', 'R', 'E', 'T', 0,
  /* 2633 */ 'P', 'A', 'T', 'C', 'H', 'A', 'B', 'L', 'E', '_', 'F', 'U', 'N', 'C', 'T', 'I', 'O', 'N', '_', 'E', 'X', 'I', 'T', 0,
  /* 2657 */ 'B', 'L', 'T', 0,
  /* 2661 */ 'G', '_', 'E', 'X', 'T', 'R', 'A', 'C', 'T', '_', 'V', 'E', 'C', 'T', 'O', 'R', '_', 'E', 'L', 'T', 0,
  /* 2682 */ 'G', '_', 'I', 'N', 'S', 'E', 'R', 'T', '_', 'V', 'E', 'C', 'T', 'O', 'R', '_', 'E', 'L', 'T', 0,
  /* 2702 */ 'S', 'L', 'T', 0,
  /* 2706 */ 'G', '_', 'F', 'C', 'O', 'N', 'S', 'T', 'A', 'N', 'T', 0,
  /* 2718 */ 'G', '_', 'C', 'O', 'N', 'S', 'T', 'A', 'N', 'T', 0,
  /* 2729 */ 'S', 'T', 'A', 'T', 'E', 'P', 'O', 'I', 'N', 'T', 0,
  /* 2740 */ 'P', 'A', 'T', 'C', 'H', 'P', 'O', 'I', 'N', 'T', 0,
  /* 2751 */ 'G', '_', 'P', 'T', 'R', 'T', 'O', 'I', 'N', 'T', 0,
  /* 2762 */ 'G', '_', 'V', 'A', 'S', 'T', 'A', 'R', 'T', 0,
  /* 2772 */ 'L', 'I', 'F', 'E', 'T', 'I', 'M', 'E', '_', 'S', 'T', 'A', 'R', 'T', 0,
  /* 2787 */ 'G', '_', 'I', 'N', 'S', 'E', 'R', 'T', 0,
  /* 2796 */ 'G', '_', 'B', 'I', 'T', 'C', 'A', 'S', 'T', 0,
  /* 2806 */ 'G', '_', 'F', 'P', 'E', 'X', 'T', 0,
  /* 2814 */ 'G', '_', 'S', 'E', 'X', 'T', 0,
  /* 2821 */ 'G', '_', 'A', 'N', 'Y', 'E', 'X', 'T', 0,
  /* 2830 */ 'G', '_', 'Z', 'E', 'X', 'T', 0,
  /* 2837 */ 'L', 'B', 'U', 0,
  /* 2841 */ 'B', 'G', 'E', 'U', 0,
  /* 2846 */ 'M', 'U', 'L', 'H', 'U', 0,
  /* 2852 */ 'S', 'L', 'T', 'I', 'U', 0,
  /* 2858 */ 'F', 'C', 'V', 'T', '_', 'D', '_', 'L', 'U', 0,
  /* 2868 */ 'F', 'C', 'V', 'T', '_', 'S', '_', 'L', 'U', 0,
  /* 2878 */ 'R', 'E', 'M', 'U', 0,
  /* 2883 */ 'M', 'U', 'L', 'H', 'S', 'U', 0,
  /* 2890 */ 'B', 'L', 'T', 'U', 0,
  /* 2895 */ 'S', 'L', 'T', 'U', 0,
  /* 2900 */ 'D', 'I', 'V', 'U', 0,
  /* 2905 */ 'L', 'W', 'U', 0,
  /* 2909 */ 'F', 'C', 'V', 'T', '_', 'D', '_', 'W', 'U', 0,
  /* 2919 */ 'F', 'C', 'V', 'T', '_', 'S', '_', 'W', 'U', 0,
  /* 2929 */ 'G', '_', 'F', 'D', 'I', 'V', 0,
  /* 2936 */ 'G', '_', 'S', 'D', 'I', 'V', 0,
  /* 2943 */ 'G', '_', 'U', 'D', 'I', 'V', 0,
  /* 2950 */ 'S', 'R', 'A', 'W', 0,
  /* 2955 */ 'S', 'U', 'B', 'W', 0,
  /* 2960 */ 'A', 'D', 'D', 'W', 0,
  /* 2965 */ 'S', 'R', 'A', 'I', 'W', 0,
  /* 2971 */ 'A', 'D', 'D', 'I', 'W', 0,
  /* 2977 */ 'S', 'L', 'L', 'I', 'W', 0,
  /* 2983 */ 'S', 'R', 'L', 'I', 'W', 0,
  /* 2989 */ 'F', 'L', 'W', 0,
  /* 2993 */ 'S', 'L', 'L', 'W', 0,
  /* 2998 */ 'S', 'R', 'L', 'W', 0,
  /* 3003 */ 'M', 'U', 'L', 'W', 0,
  /* 3008 */ 'R', 'E', 'M', 'W', 0,
  /* 3013 */ 'G', '_', 'F', 'P', 'O', 'W', 0,
  /* 3020 */ 'C', 'S', 'R', 'R', 'W', 0,
  /* 3026 */ 'F', 'S', 'W', 0,
  /* 3030 */ 'R', 'E', 'M', 'U', 'W', 0,
  /* 3036 */ 'D', 'I', 'V', 'U', 'W', 0,
  /* 3042 */ 'D', 'I', 'V', 'W', 0,
  /* 3047 */ 'S', 'C', '_', 'W', 0,
  /* 3052 */ 'A', 'M', 'O', 'A', 'D', 'D', '_', 'W', 0,
  /* 3061 */ 'A', 'M', 'O', 'A', 'N', 'D', '_', 'W', 0,
  /* 3070 */ 'F', 'C', 'V', 'T', '_', 'D', '_', 'W', 0,
  /* 3079 */ 'A', 'M', 'O', 'M', 'I', 'N', '_', 'W', 0,
  /* 3088 */ 'A', 'M', 'O', 'S', 'W', 'A', 'P', '_', 'W', 0,
  /* 3098 */ 'L', 'R', '_', 'W', 0,
  /* 3103 */ 'A', 'M', 'O', 'O', 'R', '_', 'W', 0,
  /* 3111 */ 'A', 'M', 'O', 'X', 'O', 'R', '_', 'W', 0,
  /* 3120 */ 'F', 'C', 'V', 'T', '_', 'S', '_', 'W', 0,
  /* 3129 */ 'A', 'M', 'O', 'M', 'I', 'N', 'U', '_', 'W', 0,
  /* 3139 */ 'A', 'M', 'O', 'M', 'A', 'X', 'U', '_', 'W', 0,
  /* 3149 */ 'A', 'M', 'O', 'M', 'A', 'X', '_', 'W', 0,
  /* 3158 */ 'F', 'M', 'V', '_', 'X', '_', 'W', 0,
  /* 3166 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'U', 'M', 'A', 'X', 0,
  /* 3183 */ 'G', '_', 'A', 'T', 'O', 'M', 'I', 'C', 'R', 'M', 'W', '_', 'M', 'A', 'X', 0,
  /* 3199 */ 'G', '_', 'F', 'R', 'A', 'M', 'E', '_', 'I', 'N', 'D', 'E', 'X', 0,
  /* 3213 */ 'F', 'M', 'V', '_', 'D', '_', 'X', 0,
  /* 3221 */ 'F', 'M', 'V', '_', 'W', '_', 'X', 0,
  /* 3229 */ 'C', 'O', 'P', 'Y', 0,
};

extern const unsigned RISCVInstrNameIndices[] = {
    775U, 1611U, 1654U, 874U, 865U, 883U, 976U, 640U, 
    655U, 620U, 669U, 2319U, 593U, 536U, 3229U, 561U, 
    2772U, 182U, 1719U, 953U, 2740U, 216U, 2729U, 572U, 
    1787U, 1774U, 2091U, 2609U, 2633U, 912U, 932U, 117U, 
    39U, 1566U, 2936U, 2943U, 1597U, 1604U, 160U, 2174U, 
    2152U, 618U, 773U, 3199U, 603U, 2577U, 2281U, 2787U, 
    2298U, 2751U, 2270U, 2796U, 103U, 585U, 2336U, 683U, 
    700U, 123U, 45U, 166U, 143U, 2179U, 2158U, 3183U, 
    1638U, 3166U, 1621U, 207U, 2596U, 61U, 2366U, 2821U, 
    83U, 2718U, 2706U, 2762U, 724U, 2814U, 2830U, 900U, 
    2123U, 2116U, 1767U, 1760U, 2587U, 549U, 522U, 1695U, 
    1687U, 1711U, 1703U, 740U, 732U, 110U, 32U, 1559U, 
    16U, 2929U, 1590U, 3013U, 1814U, 8U, 717U, 0U, 
    633U, 2806U, 73U, 794U, 819U, 1742U, 1751U, 1736U, 
    850U, 2077U, 2682U, 2661U, 2135U, 1728U, 113U, 763U, 
    2971U, 2960U, 1670U, 1799U, 290U, 1829U, 1126U, 997U, 
    3052U, 1955U, 1285U, 1441U, 299U, 1841U, 1141U, 1009U, 
    3061U, 1967U, 1300U, 1453U, 463U, 1922U, 1243U, 1090U, 
    3139U, 2048U, 1402U, 1534U, 496U, 1935U, 1259U, 1103U, 
    3149U, 2061U, 1418U, 1547U, 443U, 1909U, 1227U, 1077U, 
    3129U, 2035U, 1386U, 1521U, 345U, 1853U, 1156U, 1021U, 
    3079U, 1979U, 1315U, 1465U, 384U, 1886U, 1198U, 1054U, 
    3103U, 2012U, 1357U, 1498U, 363U, 1865U, 1171U, 1033U, 
    3088U, 1991U, 1330U, 1477U, 392U, 1897U, 1212U, 1065U, 
    3111U, 2023U, 1371U, 1509U, 156U, 768U, 91U, 2073U, 
    557U, 2841U, 2657U, 2890U, 568U, 97U, 756U, 2313U, 
    803U, 3020U, 828U, 2932U, 2900U, 3036U, 3042U, 843U, 
    906U, 266U, 2417U, 401U, 2502U, 1572U, 2858U, 2441U, 
    3070U, 2909U, 433U, 2525U, 329U, 2471U, 410U, 1581U, 
    2868U, 3120U, 2919U, 453U, 2535U, 480U, 2552U, 473U, 
    2545U, 530U, 835U, 373U, 2496U, 139U, 308U, 2450U, 
    419U, 2511U, 2989U, 273U, 2424U, 489U, 2561U, 338U, 
    2480U, 244U, 2400U, 322U, 2464U, 3213U, 3221U, 514U, 
    3158U, 281U, 2432U, 252U, 2408U, 233U, 354U, 2487U, 
    505U, 2568U, 314U, 2456U, 425U, 2517U, 237U, 2393U, 
    3026U, 861U, 2130U, 26U, 2837U, 140U, 737U, 2848U, 
    379U, 1878U, 1187U, 1046U, 3098U, 2004U, 1346U, 1490U, 
    815U, 2990U, 2905U, 1562U, 735U, 2883U, 2846U, 3003U, 
    2149U, 790U, 2082U, 195U, 965U, 2623U, 1593U, 2878U, 
    3030U, 3008U, 29U, 261U, 1821U, 1115U, 989U, 3047U, 
    1947U, 1274U, 1433U, 234U, 748U, 981U, 779U, 2977U, 
    2993U, 2702U, 810U, 2852U, 2895U, 22U, 751U, 2965U, 
    2950U, 985U, 784U, 2983U, 2998U, 35U, 2955U, 3027U, 
    2194U, 2220U, 2246U, 2154U, 789U, 
};

static inline void InitRISCVMCInstrInfo(MCInstrInfo *II) {
  II->InitMCInstrInfo(RISCVInsts, RISCVInstrNameIndices, RISCVInstrNameData, 349);
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

#ifdef GET_INSTRINFO_CTOR_DTOR
#undef GET_INSTRINFO_CTOR_DTOR
namespace llvm {
extern const MCInstrDesc RISCVInsts[];
extern const unsigned RISCVInstrNameIndices[];
extern const char RISCVInstrNameData[];
RISCVGenInstrInfo::RISCVGenInstrInfo(int CFSetupOpcode, int CFDestroyOpcode, int CatchRetOpcode, int ReturnOpcode)
  : TargetInstrInfo(CFSetupOpcode, CFDestroyOpcode, CatchRetOpcode, ReturnOpcode) {
  InitMCInstrInfo(RISCVInsts, RISCVInstrNameIndices, RISCVInstrNameData, 349);
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
  MEMii = 0,
  f32imm = 1,
  f64imm = 2,
  fencearg = 3,
  frmarg = 4,
  i16imm = 5,
  i1imm = 6,
  i32imm = 7,
  i64imm = 8,
  i8imm = 9,
  ixlenimm = 10,
  ptype0 = 11,
  ptype1 = 12,
  ptype2 = 13,
  ptype3 = 14,
  ptype4 = 15,
  ptype5 = 16,
  simm12 = 17,
  simm13_lsb0 = 18,
  simm21_lsb0 = 19,
  type0 = 20,
  type1 = 21,
  type2 = 22,
  type3 = 23,
  type4 = 24,
  type5 = 25,
  uimm12 = 26,
  uimm20 = 27,
  uimm5 = 28,
  uimmlog2xlen = 29,
  OPERAND_TYPE_LIST_END
};
} // end namespace OpTypes
} // end namespace RISCV
} // end namespace llvm
#endif // GET_INSTRINFO_OPERAND_TYPES_ENUM


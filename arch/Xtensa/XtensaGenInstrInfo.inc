/* Capstone Disassembly Engine, https://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/*    Rot127 <unisono@quyllur.org> 2022-2024 */
/* Automatically generated file by Capstone's LLVM TableGen Disassembler Backend. */

/* LLVM-commit: <commit> */
/* LLVM-tag: <tag> */

/* Do not edit. */

/* Capstone's LLVM TableGen Backends: */
/* https://github.com/capstone-engine/llvm-capstone */

#ifdef GET_INSTRINFO_ENUM
#undef GET_INSTRINFO_ENUM

  enum {
    Xtensa_PHI	= 0,
    Xtensa_INLINEASM	= 1,
    Xtensa_INLINEASM_BR	= 2,
    Xtensa_CFI_INSTRUCTION	= 3,
    Xtensa_EH_LABEL	= 4,
    Xtensa_GC_LABEL	= 5,
    Xtensa_ANNOTATION_LABEL	= 6,
    Xtensa_KILL	= 7,
    Xtensa_EXTRACT_SUBREG	= 8,
    Xtensa_INSERT_SUBREG	= 9,
    Xtensa_IMPLICIT_DEF	= 10,
    Xtensa_SUBREG_TO_REG	= 11,
    Xtensa_COPY_TO_REGCLASS	= 12,
    Xtensa_DBG_VALUE	= 13,
    Xtensa_DBG_VALUE_LIST	= 14,
    Xtensa_DBG_INSTR_REF	= 15,
    Xtensa_DBG_PHI	= 16,
    Xtensa_DBG_LABEL	= 17,
    Xtensa_REG_SEQUENCE	= 18,
    Xtensa_COPY	= 19,
    Xtensa_BUNDLE	= 20,
    Xtensa_LIFETIME_START	= 21,
    Xtensa_LIFETIME_END	= 22,
    Xtensa_PSEUDO_PROBE	= 23,
    Xtensa_ARITH_FENCE	= 24,
    Xtensa_STACKMAP	= 25,
    Xtensa_FENTRY_CALL	= 26,
    Xtensa_PATCHPOINT	= 27,
    Xtensa_LOAD_STACK_GUARD	= 28,
    Xtensa_PREALLOCATED_SETUP	= 29,
    Xtensa_PREALLOCATED_ARG	= 30,
    Xtensa_STATEPOINT	= 31,
    Xtensa_LOCAL_ESCAPE	= 32,
    Xtensa_FAULTING_OP	= 33,
    Xtensa_PATCHABLE_OP	= 34,
    Xtensa_PATCHABLE_FUNCTION_ENTER	= 35,
    Xtensa_PATCHABLE_RET	= 36,
    Xtensa_PATCHABLE_FUNCTION_EXIT	= 37,
    Xtensa_PATCHABLE_TAIL_CALL	= 38,
    Xtensa_PATCHABLE_EVENT_CALL	= 39,
    Xtensa_PATCHABLE_TYPED_EVENT_CALL	= 40,
    Xtensa_ICALL_BRANCH_FUNNEL	= 41,
    Xtensa_MEMBARRIER	= 42,
    Xtensa_JUMP_TABLE_DEBUG_INFO	= 43,
    Xtensa_G_ASSERT_SEXT	= 44,
    Xtensa_G_ASSERT_ZEXT	= 45,
    Xtensa_G_ASSERT_ALIGN	= 46,
    Xtensa_G_ADD	= 47,
    Xtensa_G_SUB	= 48,
    Xtensa_G_MUL	= 49,
    Xtensa_G_SDIV	= 50,
    Xtensa_G_UDIV	= 51,
    Xtensa_G_SREM	= 52,
    Xtensa_G_UREM	= 53,
    Xtensa_G_SDIVREM	= 54,
    Xtensa_G_UDIVREM	= 55,
    Xtensa_G_AND	= 56,
    Xtensa_G_OR	= 57,
    Xtensa_G_XOR	= 58,
    Xtensa_G_IMPLICIT_DEF	= 59,
    Xtensa_G_PHI	= 60,
    Xtensa_G_FRAME_INDEX	= 61,
    Xtensa_G_GLOBAL_VALUE	= 62,
    Xtensa_G_CONSTANT_POOL	= 63,
    Xtensa_G_EXTRACT	= 64,
    Xtensa_G_UNMERGE_VALUES	= 65,
    Xtensa_G_INSERT	= 66,
    Xtensa_G_MERGE_VALUES	= 67,
    Xtensa_G_BUILD_VECTOR	= 68,
    Xtensa_G_BUILD_VECTOR_TRUNC	= 69,
    Xtensa_G_CONCAT_VECTORS	= 70,
    Xtensa_G_PTRTOINT	= 71,
    Xtensa_G_INTTOPTR	= 72,
    Xtensa_G_BITCAST	= 73,
    Xtensa_G_FREEZE	= 74,
    Xtensa_G_CONSTANT_FOLD_BARRIER	= 75,
    Xtensa_G_INTRINSIC_FPTRUNC_ROUND	= 76,
    Xtensa_G_INTRINSIC_TRUNC	= 77,
    Xtensa_G_INTRINSIC_ROUND	= 78,
    Xtensa_G_INTRINSIC_LRINT	= 79,
    Xtensa_G_INTRINSIC_ROUNDEVEN	= 80,
    Xtensa_G_READCYCLECOUNTER	= 81,
    Xtensa_G_LOAD	= 82,
    Xtensa_G_SEXTLOAD	= 83,
    Xtensa_G_ZEXTLOAD	= 84,
    Xtensa_G_INDEXED_LOAD	= 85,
    Xtensa_G_INDEXED_SEXTLOAD	= 86,
    Xtensa_G_INDEXED_ZEXTLOAD	= 87,
    Xtensa_G_STORE	= 88,
    Xtensa_G_INDEXED_STORE	= 89,
    Xtensa_G_ATOMIC_CMPXCHG_WITH_SUCCESS	= 90,
    Xtensa_G_ATOMIC_CMPXCHG	= 91,
    Xtensa_G_ATOMICRMW_XCHG	= 92,
    Xtensa_G_ATOMICRMW_ADD	= 93,
    Xtensa_G_ATOMICRMW_SUB	= 94,
    Xtensa_G_ATOMICRMW_AND	= 95,
    Xtensa_G_ATOMICRMW_NAND	= 96,
    Xtensa_G_ATOMICRMW_OR	= 97,
    Xtensa_G_ATOMICRMW_XOR	= 98,
    Xtensa_G_ATOMICRMW_MAX	= 99,
    Xtensa_G_ATOMICRMW_MIN	= 100,
    Xtensa_G_ATOMICRMW_UMAX	= 101,
    Xtensa_G_ATOMICRMW_UMIN	= 102,
    Xtensa_G_ATOMICRMW_FADD	= 103,
    Xtensa_G_ATOMICRMW_FSUB	= 104,
    Xtensa_G_ATOMICRMW_FMAX	= 105,
    Xtensa_G_ATOMICRMW_FMIN	= 106,
    Xtensa_G_ATOMICRMW_UINC_WRAP	= 107,
    Xtensa_G_ATOMICRMW_UDEC_WRAP	= 108,
    Xtensa_G_FENCE	= 109,
    Xtensa_G_PREFETCH	= 110,
    Xtensa_G_BRCOND	= 111,
    Xtensa_G_BRINDIRECT	= 112,
    Xtensa_G_INVOKE_REGION_START	= 113,
    Xtensa_G_INTRINSIC	= 114,
    Xtensa_G_INTRINSIC_W_SIDE_EFFECTS	= 115,
    Xtensa_G_INTRINSIC_CONVERGENT	= 116,
    Xtensa_G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS	= 117,
    Xtensa_G_ANYEXT	= 118,
    Xtensa_G_TRUNC	= 119,
    Xtensa_G_CONSTANT	= 120,
    Xtensa_G_FCONSTANT	= 121,
    Xtensa_G_VASTART	= 122,
    Xtensa_G_VAARG	= 123,
    Xtensa_G_SEXT	= 124,
    Xtensa_G_SEXT_INREG	= 125,
    Xtensa_G_ZEXT	= 126,
    Xtensa_G_SHL	= 127,
    Xtensa_G_LSHR	= 128,
    Xtensa_G_ASHR	= 129,
    Xtensa_G_FSHL	= 130,
    Xtensa_G_FSHR	= 131,
    Xtensa_G_ROTR	= 132,
    Xtensa_G_ROTL	= 133,
    Xtensa_G_ICMP	= 134,
    Xtensa_G_FCMP	= 135,
    Xtensa_G_SELECT	= 136,
    Xtensa_G_UADDO	= 137,
    Xtensa_G_UADDE	= 138,
    Xtensa_G_USUBO	= 139,
    Xtensa_G_USUBE	= 140,
    Xtensa_G_SADDO	= 141,
    Xtensa_G_SADDE	= 142,
    Xtensa_G_SSUBO	= 143,
    Xtensa_G_SSUBE	= 144,
    Xtensa_G_UMULO	= 145,
    Xtensa_G_SMULO	= 146,
    Xtensa_G_UMULH	= 147,
    Xtensa_G_SMULH	= 148,
    Xtensa_G_UADDSAT	= 149,
    Xtensa_G_SADDSAT	= 150,
    Xtensa_G_USUBSAT	= 151,
    Xtensa_G_SSUBSAT	= 152,
    Xtensa_G_USHLSAT	= 153,
    Xtensa_G_SSHLSAT	= 154,
    Xtensa_G_SMULFIX	= 155,
    Xtensa_G_UMULFIX	= 156,
    Xtensa_G_SMULFIXSAT	= 157,
    Xtensa_G_UMULFIXSAT	= 158,
    Xtensa_G_SDIVFIX	= 159,
    Xtensa_G_UDIVFIX	= 160,
    Xtensa_G_SDIVFIXSAT	= 161,
    Xtensa_G_UDIVFIXSAT	= 162,
    Xtensa_G_FADD	= 163,
    Xtensa_G_FSUB	= 164,
    Xtensa_G_FMUL	= 165,
    Xtensa_G_FMA	= 166,
    Xtensa_G_FMAD	= 167,
    Xtensa_G_FDIV	= 168,
    Xtensa_G_FREM	= 169,
    Xtensa_G_FPOW	= 170,
    Xtensa_G_FPOWI	= 171,
    Xtensa_G_FEXP	= 172,
    Xtensa_G_FEXP2	= 173,
    Xtensa_G_FEXP10	= 174,
    Xtensa_G_FLOG	= 175,
    Xtensa_G_FLOG2	= 176,
    Xtensa_G_FLOG10	= 177,
    Xtensa_G_FLDEXP	= 178,
    Xtensa_G_FFREXP	= 179,
    Xtensa_G_FNEG	= 180,
    Xtensa_G_FPEXT	= 181,
    Xtensa_G_FPTRUNC	= 182,
    Xtensa_G_FPTOSI	= 183,
    Xtensa_G_FPTOUI	= 184,
    Xtensa_G_SITOFP	= 185,
    Xtensa_G_UITOFP	= 186,
    Xtensa_G_FABS	= 187,
    Xtensa_G_FCOPYSIGN	= 188,
    Xtensa_G_IS_FPCLASS	= 189,
    Xtensa_G_FCANONICALIZE	= 190,
    Xtensa_G_FMINNUM	= 191,
    Xtensa_G_FMAXNUM	= 192,
    Xtensa_G_FMINNUM_IEEE	= 193,
    Xtensa_G_FMAXNUM_IEEE	= 194,
    Xtensa_G_FMINIMUM	= 195,
    Xtensa_G_FMAXIMUM	= 196,
    Xtensa_G_GET_FPENV	= 197,
    Xtensa_G_SET_FPENV	= 198,
    Xtensa_G_RESET_FPENV	= 199,
    Xtensa_G_GET_FPMODE	= 200,
    Xtensa_G_SET_FPMODE	= 201,
    Xtensa_G_RESET_FPMODE	= 202,
    Xtensa_G_PTR_ADD	= 203,
    Xtensa_G_PTRMASK	= 204,
    Xtensa_G_SMIN	= 205,
    Xtensa_G_SMAX	= 206,
    Xtensa_G_UMIN	= 207,
    Xtensa_G_UMAX	= 208,
    Xtensa_G_ABS	= 209,
    Xtensa_G_LROUND	= 210,
    Xtensa_G_LLROUND	= 211,
    Xtensa_G_BR	= 212,
    Xtensa_G_BRJT	= 213,
    Xtensa_G_INSERT_VECTOR_ELT	= 214,
    Xtensa_G_EXTRACT_VECTOR_ELT	= 215,
    Xtensa_G_SHUFFLE_VECTOR	= 216,
    Xtensa_G_CTTZ	= 217,
    Xtensa_G_CTTZ_ZERO_UNDEF	= 218,
    Xtensa_G_CTLZ	= 219,
    Xtensa_G_CTLZ_ZERO_UNDEF	= 220,
    Xtensa_G_CTPOP	= 221,
    Xtensa_G_BSWAP	= 222,
    Xtensa_G_BITREVERSE	= 223,
    Xtensa_G_FCEIL	= 224,
    Xtensa_G_FCOS	= 225,
    Xtensa_G_FSIN	= 226,
    Xtensa_G_FSQRT	= 227,
    Xtensa_G_FFLOOR	= 228,
    Xtensa_G_FRINT	= 229,
    Xtensa_G_FNEARBYINT	= 230,
    Xtensa_G_ADDRSPACE_CAST	= 231,
    Xtensa_G_BLOCK_ADDR	= 232,
    Xtensa_G_JUMP_TABLE	= 233,
    Xtensa_G_DYN_STACKALLOC	= 234,
    Xtensa_G_STACKSAVE	= 235,
    Xtensa_G_STACKRESTORE	= 236,
    Xtensa_G_STRICT_FADD	= 237,
    Xtensa_G_STRICT_FSUB	= 238,
    Xtensa_G_STRICT_FMUL	= 239,
    Xtensa_G_STRICT_FDIV	= 240,
    Xtensa_G_STRICT_FREM	= 241,
    Xtensa_G_STRICT_FMA	= 242,
    Xtensa_G_STRICT_FSQRT	= 243,
    Xtensa_G_STRICT_FLDEXP	= 244,
    Xtensa_G_READ_REGISTER	= 245,
    Xtensa_G_WRITE_REGISTER	= 246,
    Xtensa_G_MEMCPY	= 247,
    Xtensa_G_MEMCPY_INLINE	= 248,
    Xtensa_G_MEMMOVE	= 249,
    Xtensa_G_MEMSET	= 250,
    Xtensa_G_BZERO	= 251,
    Xtensa_G_VECREDUCE_SEQ_FADD	= 252,
    Xtensa_G_VECREDUCE_SEQ_FMUL	= 253,
    Xtensa_G_VECREDUCE_FADD	= 254,
    Xtensa_G_VECREDUCE_FMUL	= 255,
    Xtensa_G_VECREDUCE_FMAX	= 256,
    Xtensa_G_VECREDUCE_FMIN	= 257,
    Xtensa_G_VECREDUCE_FMAXIMUM	= 258,
    Xtensa_G_VECREDUCE_FMINIMUM	= 259,
    Xtensa_G_VECREDUCE_ADD	= 260,
    Xtensa_G_VECREDUCE_MUL	= 261,
    Xtensa_G_VECREDUCE_AND	= 262,
    Xtensa_G_VECREDUCE_OR	= 263,
    Xtensa_G_VECREDUCE_XOR	= 264,
    Xtensa_G_VECREDUCE_SMAX	= 265,
    Xtensa_G_VECREDUCE_SMIN	= 266,
    Xtensa_G_VECREDUCE_UMAX	= 267,
    Xtensa_G_VECREDUCE_UMIN	= 268,
    Xtensa_G_SBFX	= 269,
    Xtensa_G_UBFX	= 270,
    Xtensa_ABS	= 271,
    Xtensa_ADD	= 272,
    Xtensa_ADDI	= 273,
    Xtensa_ADDMI	= 274,
    Xtensa_ADDX2	= 275,
    Xtensa_ADDX4	= 276,
    Xtensa_ADDX8	= 277,
    Xtensa_AND	= 278,
    Xtensa_BALL	= 279,
    Xtensa_BANY	= 280,
    Xtensa_BBC	= 281,
    Xtensa_BBCI	= 282,
    Xtensa_BBS	= 283,
    Xtensa_BBSI	= 284,
    Xtensa_BEQ	= 285,
    Xtensa_BEQI	= 286,
    Xtensa_BEQZ	= 287,
    Xtensa_BGE	= 288,
    Xtensa_BGEI	= 289,
    Xtensa_BGEU	= 290,
    Xtensa_BGEUI	= 291,
    Xtensa_BGEZ	= 292,
    Xtensa_BLT	= 293,
    Xtensa_BLTI	= 294,
    Xtensa_BLTU	= 295,
    Xtensa_BLTUI	= 296,
    Xtensa_BLTZ	= 297,
    Xtensa_BNALL	= 298,
    Xtensa_BNE	= 299,
    Xtensa_BNEI	= 300,
    Xtensa_BNEZ	= 301,
    Xtensa_BNONE	= 302,
    Xtensa_CALL0	= 303,
    Xtensa_CALLX0	= 304,
    Xtensa_DSYNC	= 305,
    Xtensa_ESYNC	= 306,
    Xtensa_EXTUI	= 307,
    Xtensa_EXTW	= 308,
    Xtensa_ISYNC	= 309,
    Xtensa_J	= 310,
    Xtensa_JX	= 311,
    Xtensa_L16SI	= 312,
    Xtensa_L16UI	= 313,
    Xtensa_L32I	= 314,
    Xtensa_L32R	= 315,
    Xtensa_L8UI	= 316,
    Xtensa_MEMW	= 317,
    Xtensa_MOVEQZ	= 318,
    Xtensa_MOVGEZ	= 319,
    Xtensa_MOVI	= 320,
    Xtensa_MOVLTZ	= 321,
    Xtensa_MOVNEZ	= 322,
    Xtensa_NEG	= 323,
    Xtensa_NOP	= 324,
    Xtensa_OR	= 325,
    Xtensa_RET	= 326,
    Xtensa_RSR	= 327,
    Xtensa_RSYNC	= 328,
    Xtensa_S16I	= 329,
    Xtensa_S32I	= 330,
    Xtensa_S8I	= 331,
    Xtensa_SLL	= 332,
    Xtensa_SLLI	= 333,
    Xtensa_SRA	= 334,
    Xtensa_SRAI	= 335,
    Xtensa_SRC	= 336,
    Xtensa_SRL	= 337,
    Xtensa_SRLI	= 338,
    Xtensa_SSA8L	= 339,
    Xtensa_SSAI	= 340,
    Xtensa_SSL	= 341,
    Xtensa_SSR	= 342,
    Xtensa_SUB	= 343,
    Xtensa_SUBX2	= 344,
    Xtensa_SUBX4	= 345,
    Xtensa_SUBX8	= 346,
    Xtensa_WSR	= 347,
    Xtensa_XOR	= 348,
    Xtensa_XSR	= 349,
    INSTRUCTION_LIST_END = 350
  };

#endif // GET_INSTRINFO_ENUM

#if defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)
typedef struct XtensaInstrTable {
  MCInstrDesc Insts[350];
  MCOperandInfo OperandInfo[169];
  MCPhysReg ImplicitOps[2];
} XtensaInstrTable;

#endif // defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

#ifdef GET_INSTRINFO_MC_DESC
#undef GET_INSTRINFO_MC_DESC

static const unsigned XtensaImpOpBase = sizeof(MCOperandInfo) / (sizeof(MCPhysReg));

static const XtensaInstrTable XtensaDescs = {
  {
  { 4, &XtensaDescs.OperandInfo[165] },  // Inst #349 = XSR
  { 3, &XtensaDescs.OperandInfo[142] },  // Inst #348 = XOR
  { 2, &XtensaDescs.OperandInfo[163] },  // Inst #347 = WSR
  { 3, &XtensaDescs.OperandInfo[142] },  // Inst #346 = SUBX8
  { 3, &XtensaDescs.OperandInfo[142] },  // Inst #345 = SUBX4
  { 3, &XtensaDescs.OperandInfo[142] },  // Inst #344 = SUBX2
  { 3, &XtensaDescs.OperandInfo[142] },  // Inst #343 = SUB
  { 1, &XtensaDescs.OperandInfo[153] },  // Inst #342 = SSR
  { 1, &XtensaDescs.OperandInfo[153] },  // Inst #341 = SSL
  { 1, &XtensaDescs.OperandInfo[0] },  // Inst #340 = SSAI
  { 1, &XtensaDescs.OperandInfo[153] },  // Inst #339 = SSA8L
  { 3, &XtensaDescs.OperandInfo[145] },  // Inst #338 = SRLI
  { 2, &XtensaDescs.OperandInfo[140] },  // Inst #337 = SRL
  { 3, &XtensaDescs.OperandInfo[142] },  // Inst #336 = SRC
  { 3, &XtensaDescs.OperandInfo[145] },  // Inst #335 = SRAI
  { 2, &XtensaDescs.OperandInfo[140] },  // Inst #334 = SRA
  { 3, &XtensaDescs.OperandInfo[145] },  // Inst #333 = SLLI
  { 2, &XtensaDescs.OperandInfo[140] },  // Inst #332 = SLL
  { 3, &XtensaDescs.OperandInfo[158] },  // Inst #331 = S8I
  { 3, &XtensaDescs.OperandInfo[158] },  // Inst #330 = S32I
  { 3, &XtensaDescs.OperandInfo[158] },  // Inst #329 = S16I
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #328 = RSYNC
  { 2, &XtensaDescs.OperandInfo[161] },  // Inst #327 = RSR
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #326 = RET
  { 3, &XtensaDescs.OperandInfo[142] },  // Inst #325 = OR
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #324 = NOP
  { 2, &XtensaDescs.OperandInfo[140] },  // Inst #323 = NEG
  { 3, &XtensaDescs.OperandInfo[142] },  // Inst #322 = MOVNEZ
  { 3, &XtensaDescs.OperandInfo[142] },  // Inst #321 = MOVLTZ
  { 2, &XtensaDescs.OperandInfo[151] },  // Inst #320 = MOVI
  { 3, &XtensaDescs.OperandInfo[142] },  // Inst #319 = MOVGEZ
  { 3, &XtensaDescs.OperandInfo[142] },  // Inst #318 = MOVEQZ
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #317 = MEMW
  { 3, &XtensaDescs.OperandInfo[158] },  // Inst #316 = L8UI
  { 2, &XtensaDescs.OperandInfo[151] },  // Inst #315 = L32R
  { 3, &XtensaDescs.OperandInfo[158] },  // Inst #314 = L32I
  { 3, &XtensaDescs.OperandInfo[158] },  // Inst #313 = L16UI
  { 3, &XtensaDescs.OperandInfo[158] },  // Inst #312 = L16SI
  { 1, &XtensaDescs.OperandInfo[153] },  // Inst #311 = JX
  { 1, &XtensaDescs.OperandInfo[0] },  // Inst #310 = J
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #309 = ISYNC
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #308 = EXTW
  { 4, &XtensaDescs.OperandInfo[154] },  // Inst #307 = EXTUI
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #306 = ESYNC
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #305 = DSYNC
  { 1, &XtensaDescs.OperandInfo[153] },  // Inst #304 = CALLX0
  { 1, &XtensaDescs.OperandInfo[0] },  // Inst #303 = CALL0
  { 3, &XtensaDescs.OperandInfo[145] },  // Inst #302 = BNONE
  { 2, &XtensaDescs.OperandInfo[151] },  // Inst #301 = BNEZ
  { 3, &XtensaDescs.OperandInfo[148] },  // Inst #300 = BNEI
  { 3, &XtensaDescs.OperandInfo[145] },  // Inst #299 = BNE
  { 3, &XtensaDescs.OperandInfo[145] },  // Inst #298 = BNALL
  { 2, &XtensaDescs.OperandInfo[151] },  // Inst #297 = BLTZ
  { 3, &XtensaDescs.OperandInfo[148] },  // Inst #296 = BLTUI
  { 3, &XtensaDescs.OperandInfo[145] },  // Inst #295 = BLTU
  { 3, &XtensaDescs.OperandInfo[148] },  // Inst #294 = BLTI
  { 3, &XtensaDescs.OperandInfo[145] },  // Inst #293 = BLT
  { 2, &XtensaDescs.OperandInfo[151] },  // Inst #292 = BGEZ
  { 3, &XtensaDescs.OperandInfo[148] },  // Inst #291 = BGEUI
  { 3, &XtensaDescs.OperandInfo[145] },  // Inst #290 = BGEU
  { 3, &XtensaDescs.OperandInfo[148] },  // Inst #289 = BGEI
  { 3, &XtensaDescs.OperandInfo[145] },  // Inst #288 = BGE
  { 2, &XtensaDescs.OperandInfo[151] },  // Inst #287 = BEQZ
  { 3, &XtensaDescs.OperandInfo[148] },  // Inst #286 = BEQI
  { 3, &XtensaDescs.OperandInfo[145] },  // Inst #285 = BEQ
  { 3, &XtensaDescs.OperandInfo[148] },  // Inst #284 = BBSI
  { 3, &XtensaDescs.OperandInfo[145] },  // Inst #283 = BBS
  { 3, &XtensaDescs.OperandInfo[148] },  // Inst #282 = BBCI
  { 3, &XtensaDescs.OperandInfo[145] },  // Inst #281 = BBC
  { 3, &XtensaDescs.OperandInfo[145] },  // Inst #280 = BANY
  { 3, &XtensaDescs.OperandInfo[145] },  // Inst #279 = BALL
  { 3, &XtensaDescs.OperandInfo[142] },  // Inst #278 = AND
  { 3, &XtensaDescs.OperandInfo[142] },  // Inst #277 = ADDX8
  { 3, &XtensaDescs.OperandInfo[142] },  // Inst #276 = ADDX4
  { 3, &XtensaDescs.OperandInfo[142] },  // Inst #275 = ADDX2
  { 3, &XtensaDescs.OperandInfo[145] },  // Inst #274 = ADDMI
  { 3, &XtensaDescs.OperandInfo[145] },  // Inst #273 = ADDI
  { 3, &XtensaDescs.OperandInfo[142] },  // Inst #272 = ADD
  { 2, &XtensaDescs.OperandInfo[140] },  // Inst #271 = ABS
  { 4, &XtensaDescs.OperandInfo[136] },  // Inst #270 = G_UBFX
  { 4, &XtensaDescs.OperandInfo[136] },  // Inst #269 = G_SBFX
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #268 = G_VECREDUCE_UMIN
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #267 = G_VECREDUCE_UMAX
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #266 = G_VECREDUCE_SMIN
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #265 = G_VECREDUCE_SMAX
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #264 = G_VECREDUCE_XOR
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #263 = G_VECREDUCE_OR
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #262 = G_VECREDUCE_AND
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #261 = G_VECREDUCE_MUL
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #260 = G_VECREDUCE_ADD
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #259 = G_VECREDUCE_FMINIMUM
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #258 = G_VECREDUCE_FMAXIMUM
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #257 = G_VECREDUCE_FMIN
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #256 = G_VECREDUCE_FMAX
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #255 = G_VECREDUCE_FMUL
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #254 = G_VECREDUCE_FADD
  { 3, &XtensaDescs.OperandInfo[123] },  // Inst #253 = G_VECREDUCE_SEQ_FMUL
  { 3, &XtensaDescs.OperandInfo[123] },  // Inst #252 = G_VECREDUCE_SEQ_FADD
  { 3, &XtensaDescs.OperandInfo[53] },  // Inst #251 = G_BZERO
  { 4, &XtensaDescs.OperandInfo[132] },  // Inst #250 = G_MEMSET
  { 4, &XtensaDescs.OperandInfo[132] },  // Inst #249 = G_MEMMOVE
  { 3, &XtensaDescs.OperandInfo[123] },  // Inst #248 = G_MEMCPY_INLINE
  { 4, &XtensaDescs.OperandInfo[132] },  // Inst #247 = G_MEMCPY
  { 2, &XtensaDescs.OperandInfo[130] },  // Inst #246 = G_WRITE_REGISTER
  { 2, &XtensaDescs.OperandInfo[51] },  // Inst #245 = G_READ_REGISTER
  { 3, &XtensaDescs.OperandInfo[96] },  // Inst #244 = G_STRICT_FLDEXP
  { 2, &XtensaDescs.OperandInfo[62] },  // Inst #243 = G_STRICT_FSQRT
  { 4, &XtensaDescs.OperandInfo[46] },  // Inst #242 = G_STRICT_FMA
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #241 = G_STRICT_FREM
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #240 = G_STRICT_FDIV
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #239 = G_STRICT_FMUL
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #238 = G_STRICT_FSUB
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #237 = G_STRICT_FADD
  { 1, &XtensaDescs.OperandInfo[50] },  // Inst #236 = G_STACKRESTORE
  { 1, &XtensaDescs.OperandInfo[50] },  // Inst #235 = G_STACKSAVE
  { 3, &XtensaDescs.OperandInfo[64] },  // Inst #234 = G_DYN_STACKALLOC
  { 2, &XtensaDescs.OperandInfo[51] },  // Inst #233 = G_JUMP_TABLE
  { 2, &XtensaDescs.OperandInfo[51] },  // Inst #232 = G_BLOCK_ADDR
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #231 = G_ADDRSPACE_CAST
  { 2, &XtensaDescs.OperandInfo[62] },  // Inst #230 = G_FNEARBYINT
  { 2, &XtensaDescs.OperandInfo[62] },  // Inst #229 = G_FRINT
  { 2, &XtensaDescs.OperandInfo[62] },  // Inst #228 = G_FFLOOR
  { 2, &XtensaDescs.OperandInfo[62] },  // Inst #227 = G_FSQRT
  { 2, &XtensaDescs.OperandInfo[62] },  // Inst #226 = G_FSIN
  { 2, &XtensaDescs.OperandInfo[62] },  // Inst #225 = G_FCOS
  { 2, &XtensaDescs.OperandInfo[62] },  // Inst #224 = G_FCEIL
  { 2, &XtensaDescs.OperandInfo[62] },  // Inst #223 = G_BITREVERSE
  { 2, &XtensaDescs.OperandInfo[62] },  // Inst #222 = G_BSWAP
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #221 = G_CTPOP
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #220 = G_CTLZ_ZERO_UNDEF
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #219 = G_CTLZ
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #218 = G_CTTZ_ZERO_UNDEF
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #217 = G_CTTZ
  { 4, &XtensaDescs.OperandInfo[126] },  // Inst #216 = G_SHUFFLE_VECTOR
  { 3, &XtensaDescs.OperandInfo[123] },  // Inst #215 = G_EXTRACT_VECTOR_ELT
  { 4, &XtensaDescs.OperandInfo[119] },  // Inst #214 = G_INSERT_VECTOR_ELT
  { 3, &XtensaDescs.OperandInfo[116] },  // Inst #213 = G_BRJT
  { 1, &XtensaDescs.OperandInfo[0] },  // Inst #212 = G_BR
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #211 = G_LLROUND
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #210 = G_LROUND
  { 2, &XtensaDescs.OperandInfo[62] },  // Inst #209 = G_ABS
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #208 = G_UMAX
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #207 = G_UMIN
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #206 = G_SMAX
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #205 = G_SMIN
  { 3, &XtensaDescs.OperandInfo[96] },  // Inst #204 = G_PTRMASK
  { 3, &XtensaDescs.OperandInfo[96] },  // Inst #203 = G_PTR_ADD
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #202 = G_RESET_FPMODE
  { 1, &XtensaDescs.OperandInfo[50] },  // Inst #201 = G_SET_FPMODE
  { 1, &XtensaDescs.OperandInfo[50] },  // Inst #200 = G_GET_FPMODE
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #199 = G_RESET_FPENV
  { 1, &XtensaDescs.OperandInfo[50] },  // Inst #198 = G_SET_FPENV
  { 1, &XtensaDescs.OperandInfo[50] },  // Inst #197 = G_GET_FPENV
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #196 = G_FMAXIMUM
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #195 = G_FMINIMUM
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #194 = G_FMAXNUM_IEEE
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #193 = G_FMINNUM_IEEE
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #192 = G_FMAXNUM
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #191 = G_FMINNUM
  { 2, &XtensaDescs.OperandInfo[62] },  // Inst #190 = G_FCANONICALIZE
  { 3, &XtensaDescs.OperandInfo[93] },  // Inst #189 = G_IS_FPCLASS
  { 3, &XtensaDescs.OperandInfo[96] },  // Inst #188 = G_FCOPYSIGN
  { 2, &XtensaDescs.OperandInfo[62] },  // Inst #187 = G_FABS
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #186 = G_UITOFP
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #185 = G_SITOFP
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #184 = G_FPTOUI
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #183 = G_FPTOSI
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #182 = G_FPTRUNC
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #181 = G_FPEXT
  { 2, &XtensaDescs.OperandInfo[62] },  // Inst #180 = G_FNEG
  { 3, &XtensaDescs.OperandInfo[86] },  // Inst #179 = G_FFREXP
  { 3, &XtensaDescs.OperandInfo[96] },  // Inst #178 = G_FLDEXP
  { 2, &XtensaDescs.OperandInfo[62] },  // Inst #177 = G_FLOG10
  { 2, &XtensaDescs.OperandInfo[62] },  // Inst #176 = G_FLOG2
  { 2, &XtensaDescs.OperandInfo[62] },  // Inst #175 = G_FLOG
  { 2, &XtensaDescs.OperandInfo[62] },  // Inst #174 = G_FEXP10
  { 2, &XtensaDescs.OperandInfo[62] },  // Inst #173 = G_FEXP2
  { 2, &XtensaDescs.OperandInfo[62] },  // Inst #172 = G_FEXP
  { 3, &XtensaDescs.OperandInfo[96] },  // Inst #171 = G_FPOWI
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #170 = G_FPOW
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #169 = G_FREM
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #168 = G_FDIV
  { 4, &XtensaDescs.OperandInfo[46] },  // Inst #167 = G_FMAD
  { 4, &XtensaDescs.OperandInfo[46] },  // Inst #166 = G_FMA
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #165 = G_FMUL
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #164 = G_FSUB
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #163 = G_FADD
  { 4, &XtensaDescs.OperandInfo[112] },  // Inst #162 = G_UDIVFIXSAT
  { 4, &XtensaDescs.OperandInfo[112] },  // Inst #161 = G_SDIVFIXSAT
  { 4, &XtensaDescs.OperandInfo[112] },  // Inst #160 = G_UDIVFIX
  { 4, &XtensaDescs.OperandInfo[112] },  // Inst #159 = G_SDIVFIX
  { 4, &XtensaDescs.OperandInfo[112] },  // Inst #158 = G_UMULFIXSAT
  { 4, &XtensaDescs.OperandInfo[112] },  // Inst #157 = G_SMULFIXSAT
  { 4, &XtensaDescs.OperandInfo[112] },  // Inst #156 = G_UMULFIX
  { 4, &XtensaDescs.OperandInfo[112] },  // Inst #155 = G_SMULFIX
  { 3, &XtensaDescs.OperandInfo[96] },  // Inst #154 = G_SSHLSAT
  { 3, &XtensaDescs.OperandInfo[96] },  // Inst #153 = G_USHLSAT
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #152 = G_SSUBSAT
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #151 = G_USUBSAT
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #150 = G_SADDSAT
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #149 = G_UADDSAT
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #148 = G_SMULH
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #147 = G_UMULH
  { 4, &XtensaDescs.OperandInfo[82] },  // Inst #146 = G_SMULO
  { 4, &XtensaDescs.OperandInfo[82] },  // Inst #145 = G_UMULO
  { 5, &XtensaDescs.OperandInfo[107] },  // Inst #144 = G_SSUBE
  { 4, &XtensaDescs.OperandInfo[82] },  // Inst #143 = G_SSUBO
  { 5, &XtensaDescs.OperandInfo[107] },  // Inst #142 = G_SADDE
  { 4, &XtensaDescs.OperandInfo[82] },  // Inst #141 = G_SADDO
  { 5, &XtensaDescs.OperandInfo[107] },  // Inst #140 = G_USUBE
  { 4, &XtensaDescs.OperandInfo[82] },  // Inst #139 = G_USUBO
  { 5, &XtensaDescs.OperandInfo[107] },  // Inst #138 = G_UADDE
  { 4, &XtensaDescs.OperandInfo[82] },  // Inst #137 = G_UADDO
  { 4, &XtensaDescs.OperandInfo[82] },  // Inst #136 = G_SELECT
  { 4, &XtensaDescs.OperandInfo[103] },  // Inst #135 = G_FCMP
  { 4, &XtensaDescs.OperandInfo[103] },  // Inst #134 = G_ICMP
  { 3, &XtensaDescs.OperandInfo[96] },  // Inst #133 = G_ROTL
  { 3, &XtensaDescs.OperandInfo[96] },  // Inst #132 = G_ROTR
  { 4, &XtensaDescs.OperandInfo[99] },  // Inst #131 = G_FSHR
  { 4, &XtensaDescs.OperandInfo[99] },  // Inst #130 = G_FSHL
  { 3, &XtensaDescs.OperandInfo[96] },  // Inst #129 = G_ASHR
  { 3, &XtensaDescs.OperandInfo[96] },  // Inst #128 = G_LSHR
  { 3, &XtensaDescs.OperandInfo[96] },  // Inst #127 = G_SHL
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #126 = G_ZEXT
  { 3, &XtensaDescs.OperandInfo[40] },  // Inst #125 = G_SEXT_INREG
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #124 = G_SEXT
  { 3, &XtensaDescs.OperandInfo[93] },  // Inst #123 = G_VAARG
  { 1, &XtensaDescs.OperandInfo[50] },  // Inst #122 = G_VASTART
  { 2, &XtensaDescs.OperandInfo[51] },  // Inst #121 = G_FCONSTANT
  { 2, &XtensaDescs.OperandInfo[51] },  // Inst #120 = G_CONSTANT
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #119 = G_TRUNC
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #118 = G_ANYEXT
  { 1, &XtensaDescs.OperandInfo[0] },  // Inst #117 = G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS
  { 1, &XtensaDescs.OperandInfo[0] },  // Inst #116 = G_INTRINSIC_CONVERGENT
  { 1, &XtensaDescs.OperandInfo[0] },  // Inst #115 = G_INTRINSIC_W_SIDE_EFFECTS
  { 1, &XtensaDescs.OperandInfo[0] },  // Inst #114 = G_INTRINSIC
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #113 = G_INVOKE_REGION_START
  { 1, &XtensaDescs.OperandInfo[50] },  // Inst #112 = G_BRINDIRECT
  { 2, &XtensaDescs.OperandInfo[51] },  // Inst #111 = G_BRCOND
  { 4, &XtensaDescs.OperandInfo[89] },  // Inst #110 = G_PREFETCH
  { 2, &XtensaDescs.OperandInfo[21] },  // Inst #109 = G_FENCE
  { 3, &XtensaDescs.OperandInfo[86] },  // Inst #108 = G_ATOMICRMW_UDEC_WRAP
  { 3, &XtensaDescs.OperandInfo[86] },  // Inst #107 = G_ATOMICRMW_UINC_WRAP
  { 3, &XtensaDescs.OperandInfo[86] },  // Inst #106 = G_ATOMICRMW_FMIN
  { 3, &XtensaDescs.OperandInfo[86] },  // Inst #105 = G_ATOMICRMW_FMAX
  { 3, &XtensaDescs.OperandInfo[86] },  // Inst #104 = G_ATOMICRMW_FSUB
  { 3, &XtensaDescs.OperandInfo[86] },  // Inst #103 = G_ATOMICRMW_FADD
  { 3, &XtensaDescs.OperandInfo[86] },  // Inst #102 = G_ATOMICRMW_UMIN
  { 3, &XtensaDescs.OperandInfo[86] },  // Inst #101 = G_ATOMICRMW_UMAX
  { 3, &XtensaDescs.OperandInfo[86] },  // Inst #100 = G_ATOMICRMW_MIN
  { 3, &XtensaDescs.OperandInfo[86] },  // Inst #99 = G_ATOMICRMW_MAX
  { 3, &XtensaDescs.OperandInfo[86] },  // Inst #98 = G_ATOMICRMW_XOR
  { 3, &XtensaDescs.OperandInfo[86] },  // Inst #97 = G_ATOMICRMW_OR
  { 3, &XtensaDescs.OperandInfo[86] },  // Inst #96 = G_ATOMICRMW_NAND
  { 3, &XtensaDescs.OperandInfo[86] },  // Inst #95 = G_ATOMICRMW_AND
  { 3, &XtensaDescs.OperandInfo[86] },  // Inst #94 = G_ATOMICRMW_SUB
  { 3, &XtensaDescs.OperandInfo[86] },  // Inst #93 = G_ATOMICRMW_ADD
  { 3, &XtensaDescs.OperandInfo[86] },  // Inst #92 = G_ATOMICRMW_XCHG
  { 4, &XtensaDescs.OperandInfo[82] },  // Inst #91 = G_ATOMIC_CMPXCHG
  { 5, &XtensaDescs.OperandInfo[77] },  // Inst #90 = G_ATOMIC_CMPXCHG_WITH_SUCCESS
  { 5, &XtensaDescs.OperandInfo[72] },  // Inst #89 = G_INDEXED_STORE
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #88 = G_STORE
  { 5, &XtensaDescs.OperandInfo[67] },  // Inst #87 = G_INDEXED_ZEXTLOAD
  { 5, &XtensaDescs.OperandInfo[67] },  // Inst #86 = G_INDEXED_SEXTLOAD
  { 5, &XtensaDescs.OperandInfo[67] },  // Inst #85 = G_INDEXED_LOAD
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #84 = G_ZEXTLOAD
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #83 = G_SEXTLOAD
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #82 = G_LOAD
  { 1, &XtensaDescs.OperandInfo[50] },  // Inst #81 = G_READCYCLECOUNTER
  { 2, &XtensaDescs.OperandInfo[62] },  // Inst #80 = G_INTRINSIC_ROUNDEVEN
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #79 = G_INTRINSIC_LRINT
  { 2, &XtensaDescs.OperandInfo[62] },  // Inst #78 = G_INTRINSIC_ROUND
  { 2, &XtensaDescs.OperandInfo[62] },  // Inst #77 = G_INTRINSIC_TRUNC
  { 3, &XtensaDescs.OperandInfo[64] },  // Inst #76 = G_INTRINSIC_FPTRUNC_ROUND
  { 2, &XtensaDescs.OperandInfo[62] },  // Inst #75 = G_CONSTANT_FOLD_BARRIER
  { 2, &XtensaDescs.OperandInfo[62] },  // Inst #74 = G_FREEZE
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #73 = G_BITCAST
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #72 = G_INTTOPTR
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #71 = G_PTRTOINT
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #70 = G_CONCAT_VECTORS
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #69 = G_BUILD_VECTOR_TRUNC
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #68 = G_BUILD_VECTOR
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #67 = G_MERGE_VALUES
  { 4, &XtensaDescs.OperandInfo[58] },  // Inst #66 = G_INSERT
  { 2, &XtensaDescs.OperandInfo[56] },  // Inst #65 = G_UNMERGE_VALUES
  { 3, &XtensaDescs.OperandInfo[53] },  // Inst #64 = G_EXTRACT
  { 2, &XtensaDescs.OperandInfo[51] },  // Inst #63 = G_CONSTANT_POOL
  { 2, &XtensaDescs.OperandInfo[51] },  // Inst #62 = G_GLOBAL_VALUE
  { 2, &XtensaDescs.OperandInfo[51] },  // Inst #61 = G_FRAME_INDEX
  { 1, &XtensaDescs.OperandInfo[50] },  // Inst #60 = G_PHI
  { 1, &XtensaDescs.OperandInfo[50] },  // Inst #59 = G_IMPLICIT_DEF
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #58 = G_XOR
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #57 = G_OR
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #56 = G_AND
  { 4, &XtensaDescs.OperandInfo[46] },  // Inst #55 = G_UDIVREM
  { 4, &XtensaDescs.OperandInfo[46] },  // Inst #54 = G_SDIVREM
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #53 = G_UREM
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #52 = G_SREM
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #51 = G_UDIV
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #50 = G_SDIV
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #49 = G_MUL
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #48 = G_SUB
  { 3, &XtensaDescs.OperandInfo[43] },  // Inst #47 = G_ADD
  { 3, &XtensaDescs.OperandInfo[40] },  // Inst #46 = G_ASSERT_ALIGN
  { 3, &XtensaDescs.OperandInfo[40] },  // Inst #45 = G_ASSERT_ZEXT
  { 3, &XtensaDescs.OperandInfo[40] },  // Inst #44 = G_ASSERT_SEXT
  { 1, &XtensaDescs.OperandInfo[1] },  // Inst #43 = JUMP_TABLE_DEBUG_INFO
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #42 = MEMBARRIER
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #41 = ICALL_BRANCH_FUNNEL
  { 3, &XtensaDescs.OperandInfo[37] },  // Inst #40 = PATCHABLE_TYPED_EVENT_CALL
  { 2, &XtensaDescs.OperandInfo[35] },  // Inst #39 = PATCHABLE_EVENT_CALL
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #38 = PATCHABLE_TAIL_CALL
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #37 = PATCHABLE_FUNCTION_EXIT
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #36 = PATCHABLE_RET
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #35 = PATCHABLE_FUNCTION_ENTER
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #34 = PATCHABLE_OP
  { 1, &XtensaDescs.OperandInfo[0] },  // Inst #33 = FAULTING_OP
  { 2, &XtensaDescs.OperandInfo[33] },  // Inst #32 = LOCAL_ESCAPE
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #31 = STATEPOINT
  { 3, &XtensaDescs.OperandInfo[30] },  // Inst #30 = PREALLOCATED_ARG
  { 1, &XtensaDescs.OperandInfo[1] },  // Inst #29 = PREALLOCATED_SETUP
  { 1, &XtensaDescs.OperandInfo[29] },  // Inst #28 = LOAD_STACK_GUARD
  { 6, &XtensaDescs.OperandInfo[23] },  // Inst #27 = PATCHPOINT
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #26 = FENTRY_CALL
  { 2, &XtensaDescs.OperandInfo[21] },  // Inst #25 = STACKMAP
  { 2, &XtensaDescs.OperandInfo[19] },  // Inst #24 = ARITH_FENCE
  { 4, &XtensaDescs.OperandInfo[15] },  // Inst #23 = PSEUDO_PROBE
  { 1, &XtensaDescs.OperandInfo[1] },  // Inst #22 = LIFETIME_END
  { 1, &XtensaDescs.OperandInfo[1] },  // Inst #21 = LIFETIME_START
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #20 = BUNDLE
  { 2, &XtensaDescs.OperandInfo[13] },  // Inst #19 = COPY
  { 2, &XtensaDescs.OperandInfo[13] },  // Inst #18 = REG_SEQUENCE
  { 1, &XtensaDescs.OperandInfo[0] },  // Inst #17 = DBG_LABEL
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #16 = DBG_PHI
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #15 = DBG_INSTR_REF
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #14 = DBG_VALUE_LIST
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #13 = DBG_VALUE
  { 3, &XtensaDescs.OperandInfo[2] },  // Inst #12 = COPY_TO_REGCLASS
  { 4, &XtensaDescs.OperandInfo[9] },  // Inst #11 = SUBREG_TO_REG
  { 1, &XtensaDescs.OperandInfo[0] },  // Inst #10 = IMPLICIT_DEF
  { 4, &XtensaDescs.OperandInfo[5] },  // Inst #9 = INSERT_SUBREG
  { 3, &XtensaDescs.OperandInfo[2] },  // Inst #8 = EXTRACT_SUBREG
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #7 = KILL
  { 1, &XtensaDescs.OperandInfo[1] },  // Inst #6 = ANNOTATION_LABEL
  { 1, &XtensaDescs.OperandInfo[1] },  // Inst #5 = GC_LABEL
  { 1, &XtensaDescs.OperandInfo[1] },  // Inst #4 = EH_LABEL
  { 1, &XtensaDescs.OperandInfo[1] },  // Inst #3 = CFI_INSTRUCTION
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #2 = INLINEASM_BR
  { 0, &XtensaDescs.OperandInfo[1] },  // Inst #1 = INLINEASM
  { 1, &XtensaDescs.OperandInfo[0] },  // Inst #0 = PHI
  }, {
    /* 0 */ { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 1 */
    /* 1 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 2 */ { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 5 */ { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 9 */ { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 13 */ { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 15 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 19 */ { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 21 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 23 */ { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 29 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 },
    /* 30 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 33 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 35 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 37 */ { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 40 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_IMM_0, 0 },
    /* 43 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 },
    /* 46 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 },
    /* 50 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 },
    /* 51 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 53 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_IMM_0, 0 },
    /* 56 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 },
    /* 58 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_IMM_0, 0 },
    /* 62 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 },
    /* 64 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 67 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_2, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 72 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_2, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 77 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_2, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 },
    /* 82 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 },
    /* 86 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 },
    /* 89 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 93 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 96 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 },
    /* 99 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 },
    /* 103 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 },
    /* 107 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 },
    /* 112 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_IMM_0, 0 },
    /* 116 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 },
    /* 119 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_2, 0 },
    /* 123 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_2, 0 },
    /* 126 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 130 */ { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 },
    /* 132 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_2, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_IMM_0, 0 },
    /* 136 */ { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_0, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 }, { -1, 0, MCOI_OPERAND_GENERIC_1, 0 },
    /* 140 */ { Xtensa_ARRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Xtensa_ARRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 142 */ { Xtensa_ARRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Xtensa_ARRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Xtensa_ARRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 145 */ { Xtensa_ARRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Xtensa_ARRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 148 */ { Xtensa_ARRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 151 */ { Xtensa_ARRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 153 */ { Xtensa_ARRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 154 */ { Xtensa_ARRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Xtensa_ARRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 158 */ { Xtensa_ARRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Xtensa_ARRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 161 */ { Xtensa_ARRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Xtensa_SRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 163 */ { Xtensa_SRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Xtensa_ARRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 165 */ { Xtensa_ARRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Xtensa_SRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Xtensa_ARRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Xtensa_SRRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(1) },
  }, {
    /* 0 */
    /* 0 */ Xtensa_A0,
    /* 1 */ Xtensa_SAR,
  }
};

#endif // GET_INSTRINFO_MC_DESC

#ifdef GET_COMPUTE_FEATURES
#undef GET_COMPUTE_FEATURES

#endif // GET_COMPUTE_FEATURES

#ifdef GET_AVAILABLE_OPCODE_CHECKER
#undef GET_AVAILABLE_OPCODE_CHECKER

#endif // GET_AVAILABLE_OPCODE_CHECKER


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
    ARC_PHI	= 0,
    ARC_INLINEASM	= 1,
    ARC_INLINEASM_BR	= 2,
    ARC_CFI_INSTRUCTION	= 3,
    ARC_EH_LABEL	= 4,
    ARC_GC_LABEL	= 5,
    ARC_ANNOTATION_LABEL	= 6,
    ARC_KILL	= 7,
    ARC_EXTRACT_SUBREG	= 8,
    ARC_INSERT_SUBREG	= 9,
    ARC_IMPLICIT_DEF	= 10,
    ARC_SUBREG_TO_REG	= 11,
    ARC_COPY_TO_REGCLASS	= 12,
    ARC_DBG_VALUE	= 13,
    ARC_DBG_VALUE_LIST	= 14,
    ARC_DBG_INSTR_REF	= 15,
    ARC_DBG_PHI	= 16,
    ARC_DBG_LABEL	= 17,
    ARC_REG_SEQUENCE	= 18,
    ARC_COPY	= 19,
    ARC_BUNDLE	= 20,
    ARC_LIFETIME_START	= 21,
    ARC_LIFETIME_END	= 22,
    ARC_PSEUDO_PROBE	= 23,
    ARC_ARITH_FENCE	= 24,
    ARC_STACKMAP	= 25,
    ARC_FENTRY_CALL	= 26,
    ARC_PATCHPOINT	= 27,
    ARC_LOAD_STACK_GUARD	= 28,
    ARC_PREALLOCATED_SETUP	= 29,
    ARC_PREALLOCATED_ARG	= 30,
    ARC_STATEPOINT	= 31,
    ARC_LOCAL_ESCAPE	= 32,
    ARC_FAULTING_OP	= 33,
    ARC_PATCHABLE_OP	= 34,
    ARC_PATCHABLE_FUNCTION_ENTER	= 35,
    ARC_PATCHABLE_RET	= 36,
    ARC_PATCHABLE_FUNCTION_EXIT	= 37,
    ARC_PATCHABLE_TAIL_CALL	= 38,
    ARC_PATCHABLE_EVENT_CALL	= 39,
    ARC_PATCHABLE_TYPED_EVENT_CALL	= 40,
    ARC_ICALL_BRANCH_FUNNEL	= 41,
    ARC_MEMBARRIER	= 42,
    ARC_JUMP_TABLE_DEBUG_INFO	= 43,
    ARC_G_ASSERT_SEXT	= 44,
    ARC_G_ASSERT_ZEXT	= 45,
    ARC_G_ASSERT_ALIGN	= 46,
    ARC_G_ADD	= 47,
    ARC_G_SUB	= 48,
    ARC_G_MUL	= 49,
    ARC_G_SDIV	= 50,
    ARC_G_UDIV	= 51,
    ARC_G_SREM	= 52,
    ARC_G_UREM	= 53,
    ARC_G_SDIVREM	= 54,
    ARC_G_UDIVREM	= 55,
    ARC_G_AND	= 56,
    ARC_G_OR	= 57,
    ARC_G_XOR	= 58,
    ARC_G_IMPLICIT_DEF	= 59,
    ARC_G_PHI	= 60,
    ARC_G_FRAME_INDEX	= 61,
    ARC_G_GLOBAL_VALUE	= 62,
    ARC_G_CONSTANT_POOL	= 63,
    ARC_G_EXTRACT	= 64,
    ARC_G_UNMERGE_VALUES	= 65,
    ARC_G_INSERT	= 66,
    ARC_G_MERGE_VALUES	= 67,
    ARC_G_BUILD_VECTOR	= 68,
    ARC_G_BUILD_VECTOR_TRUNC	= 69,
    ARC_G_CONCAT_VECTORS	= 70,
    ARC_G_PTRTOINT	= 71,
    ARC_G_INTTOPTR	= 72,
    ARC_G_BITCAST	= 73,
    ARC_G_FREEZE	= 74,
    ARC_G_CONSTANT_FOLD_BARRIER	= 75,
    ARC_G_INTRINSIC_FPTRUNC_ROUND	= 76,
    ARC_G_INTRINSIC_TRUNC	= 77,
    ARC_G_INTRINSIC_ROUND	= 78,
    ARC_G_INTRINSIC_LRINT	= 79,
    ARC_G_INTRINSIC_ROUNDEVEN	= 80,
    ARC_G_READCYCLECOUNTER	= 81,
    ARC_G_LOAD	= 82,
    ARC_G_SEXTLOAD	= 83,
    ARC_G_ZEXTLOAD	= 84,
    ARC_G_INDEXED_LOAD	= 85,
    ARC_G_INDEXED_SEXTLOAD	= 86,
    ARC_G_INDEXED_ZEXTLOAD	= 87,
    ARC_G_STORE	= 88,
    ARC_G_INDEXED_STORE	= 89,
    ARC_G_ATOMIC_CMPXCHG_WITH_SUCCESS	= 90,
    ARC_G_ATOMIC_CMPXCHG	= 91,
    ARC_G_ATOMICRMW_XCHG	= 92,
    ARC_G_ATOMICRMW_ADD	= 93,
    ARC_G_ATOMICRMW_SUB	= 94,
    ARC_G_ATOMICRMW_AND	= 95,
    ARC_G_ATOMICRMW_NAND	= 96,
    ARC_G_ATOMICRMW_OR	= 97,
    ARC_G_ATOMICRMW_XOR	= 98,
    ARC_G_ATOMICRMW_MAX	= 99,
    ARC_G_ATOMICRMW_MIN	= 100,
    ARC_G_ATOMICRMW_UMAX	= 101,
    ARC_G_ATOMICRMW_UMIN	= 102,
    ARC_G_ATOMICRMW_FADD	= 103,
    ARC_G_ATOMICRMW_FSUB	= 104,
    ARC_G_ATOMICRMW_FMAX	= 105,
    ARC_G_ATOMICRMW_FMIN	= 106,
    ARC_G_ATOMICRMW_UINC_WRAP	= 107,
    ARC_G_ATOMICRMW_UDEC_WRAP	= 108,
    ARC_G_FENCE	= 109,
    ARC_G_PREFETCH	= 110,
    ARC_G_BRCOND	= 111,
    ARC_G_BRINDIRECT	= 112,
    ARC_G_INVOKE_REGION_START	= 113,
    ARC_G_INTRINSIC	= 114,
    ARC_G_INTRINSIC_W_SIDE_EFFECTS	= 115,
    ARC_G_INTRINSIC_CONVERGENT	= 116,
    ARC_G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS	= 117,
    ARC_G_ANYEXT	= 118,
    ARC_G_TRUNC	= 119,
    ARC_G_CONSTANT	= 120,
    ARC_G_FCONSTANT	= 121,
    ARC_G_VASTART	= 122,
    ARC_G_VAARG	= 123,
    ARC_G_SEXT	= 124,
    ARC_G_SEXT_INREG	= 125,
    ARC_G_ZEXT	= 126,
    ARC_G_SHL	= 127,
    ARC_G_LSHR	= 128,
    ARC_G_ASHR	= 129,
    ARC_G_FSHL	= 130,
    ARC_G_FSHR	= 131,
    ARC_G_ROTR	= 132,
    ARC_G_ROTL	= 133,
    ARC_G_ICMP	= 134,
    ARC_G_FCMP	= 135,
    ARC_G_SELECT	= 136,
    ARC_G_UADDO	= 137,
    ARC_G_UADDE	= 138,
    ARC_G_USUBO	= 139,
    ARC_G_USUBE	= 140,
    ARC_G_SADDO	= 141,
    ARC_G_SADDE	= 142,
    ARC_G_SSUBO	= 143,
    ARC_G_SSUBE	= 144,
    ARC_G_UMULO	= 145,
    ARC_G_SMULO	= 146,
    ARC_G_UMULH	= 147,
    ARC_G_SMULH	= 148,
    ARC_G_UADDSAT	= 149,
    ARC_G_SADDSAT	= 150,
    ARC_G_USUBSAT	= 151,
    ARC_G_SSUBSAT	= 152,
    ARC_G_USHLSAT	= 153,
    ARC_G_SSHLSAT	= 154,
    ARC_G_SMULFIX	= 155,
    ARC_G_UMULFIX	= 156,
    ARC_G_SMULFIXSAT	= 157,
    ARC_G_UMULFIXSAT	= 158,
    ARC_G_SDIVFIX	= 159,
    ARC_G_UDIVFIX	= 160,
    ARC_G_SDIVFIXSAT	= 161,
    ARC_G_UDIVFIXSAT	= 162,
    ARC_G_FADD	= 163,
    ARC_G_FSUB	= 164,
    ARC_G_FMUL	= 165,
    ARC_G_FMA	= 166,
    ARC_G_FMAD	= 167,
    ARC_G_FDIV	= 168,
    ARC_G_FREM	= 169,
    ARC_G_FPOW	= 170,
    ARC_G_FPOWI	= 171,
    ARC_G_FEXP	= 172,
    ARC_G_FEXP2	= 173,
    ARC_G_FEXP10	= 174,
    ARC_G_FLOG	= 175,
    ARC_G_FLOG2	= 176,
    ARC_G_FLOG10	= 177,
    ARC_G_FLDEXP	= 178,
    ARC_G_FFREXP	= 179,
    ARC_G_FNEG	= 180,
    ARC_G_FPEXT	= 181,
    ARC_G_FPTRUNC	= 182,
    ARC_G_FPTOSI	= 183,
    ARC_G_FPTOUI	= 184,
    ARC_G_SITOFP	= 185,
    ARC_G_UITOFP	= 186,
    ARC_G_FABS	= 187,
    ARC_G_FCOPYSIGN	= 188,
    ARC_G_IS_FPCLASS	= 189,
    ARC_G_FCANONICALIZE	= 190,
    ARC_G_FMINNUM	= 191,
    ARC_G_FMAXNUM	= 192,
    ARC_G_FMINNUM_IEEE	= 193,
    ARC_G_FMAXNUM_IEEE	= 194,
    ARC_G_FMINIMUM	= 195,
    ARC_G_FMAXIMUM	= 196,
    ARC_G_GET_FPENV	= 197,
    ARC_G_SET_FPENV	= 198,
    ARC_G_RESET_FPENV	= 199,
    ARC_G_GET_FPMODE	= 200,
    ARC_G_SET_FPMODE	= 201,
    ARC_G_RESET_FPMODE	= 202,
    ARC_G_PTR_ADD	= 203,
    ARC_G_PTRMASK	= 204,
    ARC_G_SMIN	= 205,
    ARC_G_SMAX	= 206,
    ARC_G_UMIN	= 207,
    ARC_G_UMAX	= 208,
    ARC_G_ABS	= 209,
    ARC_G_LROUND	= 210,
    ARC_G_LLROUND	= 211,
    ARC_G_BR	= 212,
    ARC_G_BRJT	= 213,
    ARC_G_INSERT_VECTOR_ELT	= 214,
    ARC_G_EXTRACT_VECTOR_ELT	= 215,
    ARC_G_SHUFFLE_VECTOR	= 216,
    ARC_G_CTTZ	= 217,
    ARC_G_CTTZ_ZERO_UNDEF	= 218,
    ARC_G_CTLZ	= 219,
    ARC_G_CTLZ_ZERO_UNDEF	= 220,
    ARC_G_CTPOP	= 221,
    ARC_G_BSWAP	= 222,
    ARC_G_BITREVERSE	= 223,
    ARC_G_FCEIL	= 224,
    ARC_G_FCOS	= 225,
    ARC_G_FSIN	= 226,
    ARC_G_FSQRT	= 227,
    ARC_G_FFLOOR	= 228,
    ARC_G_FRINT	= 229,
    ARC_G_FNEARBYINT	= 230,
    ARC_G_ADDRSPACE_CAST	= 231,
    ARC_G_BLOCK_ADDR	= 232,
    ARC_G_JUMP_TABLE	= 233,
    ARC_G_DYN_STACKALLOC	= 234,
    ARC_G_STACKSAVE	= 235,
    ARC_G_STACKRESTORE	= 236,
    ARC_G_STRICT_FADD	= 237,
    ARC_G_STRICT_FSUB	= 238,
    ARC_G_STRICT_FMUL	= 239,
    ARC_G_STRICT_FDIV	= 240,
    ARC_G_STRICT_FREM	= 241,
    ARC_G_STRICT_FMA	= 242,
    ARC_G_STRICT_FSQRT	= 243,
    ARC_G_STRICT_FLDEXP	= 244,
    ARC_G_READ_REGISTER	= 245,
    ARC_G_WRITE_REGISTER	= 246,
    ARC_G_MEMCPY	= 247,
    ARC_G_MEMCPY_INLINE	= 248,
    ARC_G_MEMMOVE	= 249,
    ARC_G_MEMSET	= 250,
    ARC_G_BZERO	= 251,
    ARC_G_VECREDUCE_SEQ_FADD	= 252,
    ARC_G_VECREDUCE_SEQ_FMUL	= 253,
    ARC_G_VECREDUCE_FADD	= 254,
    ARC_G_VECREDUCE_FMUL	= 255,
    ARC_G_VECREDUCE_FMAX	= 256,
    ARC_G_VECREDUCE_FMIN	= 257,
    ARC_G_VECREDUCE_FMAXIMUM	= 258,
    ARC_G_VECREDUCE_FMINIMUM	= 259,
    ARC_G_VECREDUCE_ADD	= 260,
    ARC_G_VECREDUCE_MUL	= 261,
    ARC_G_VECREDUCE_AND	= 262,
    ARC_G_VECREDUCE_OR	= 263,
    ARC_G_VECREDUCE_XOR	= 264,
    ARC_G_VECREDUCE_SMAX	= 265,
    ARC_G_VECREDUCE_SMIN	= 266,
    ARC_G_VECREDUCE_UMAX	= 267,
    ARC_G_VECREDUCE_UMIN	= 268,
    ARC_G_SBFX	= 269,
    ARC_G_UBFX	= 270,
    ARC_ADJCALLSTACKDOWN	= 271,
    ARC_ADJCALLSTACKUP	= 272,
    ARC_BRcc_rr_p	= 273,
    ARC_BRcc_ru6_p	= 274,
    ARC_CTLZ	= 275,
    ARC_CTTZ	= 276,
    ARC_GETFI	= 277,
    ARC_STB_FAR	= 278,
    ARC_STH_FAR	= 279,
    ARC_ST_FAR	= 280,
    ARC_ADC_cc_f_rru6	= 281,
    ARC_ADC_cc_rru6	= 282,
    ARC_ADC_f_rrlimm	= 283,
    ARC_ADC_f_rrr	= 284,
    ARC_ADC_f_rrs12	= 285,
    ARC_ADC_f_rru6	= 286,
    ARC_ADC_rrlimm	= 287,
    ARC_ADC_rrr	= 288,
    ARC_ADC_rrs12	= 289,
    ARC_ADC_rru6	= 290,
    ARC_ADD_S_limms3	= 291,
    ARC_ADD_S_rlimm	= 292,
    ARC_ADD_S_rr	= 293,
    ARC_ADD_S_rrr	= 294,
    ARC_ADD_S_rru6	= 295,
    ARC_ADD_S_rs3	= 296,
    ARC_ADD_S_ru3	= 297,
    ARC_ADD_S_u7	= 298,
    ARC_ADD_cc_f_rru6	= 299,
    ARC_ADD_cc_rru6	= 300,
    ARC_ADD_f_rrlimm	= 301,
    ARC_ADD_f_rrr	= 302,
    ARC_ADD_f_rrs12	= 303,
    ARC_ADD_f_rru6	= 304,
    ARC_ADD_rrlimm	= 305,
    ARC_ADD_rrr	= 306,
    ARC_ADD_rrs12	= 307,
    ARC_ADD_rru6	= 308,
    ARC_AND_cc_f_rru6	= 309,
    ARC_AND_cc_rru6	= 310,
    ARC_AND_f_rrlimm	= 311,
    ARC_AND_f_rrr	= 312,
    ARC_AND_f_rrs12	= 313,
    ARC_AND_f_rru6	= 314,
    ARC_AND_rrlimm	= 315,
    ARC_AND_rrr	= 316,
    ARC_AND_rrs12	= 317,
    ARC_AND_rru6	= 318,
    ARC_ASL_S_ru3	= 319,
    ARC_ASL_S_ru5	= 320,
    ARC_ASL_cc_f_rru6	= 321,
    ARC_ASL_cc_rru6	= 322,
    ARC_ASL_f_rrlimm	= 323,
    ARC_ASL_f_rrr	= 324,
    ARC_ASL_f_rrs12	= 325,
    ARC_ASL_f_rru6	= 326,
    ARC_ASL_rrlimm	= 327,
    ARC_ASL_rrr	= 328,
    ARC_ASL_rrs12	= 329,
    ARC_ASL_rru6	= 330,
    ARC_ASR_S_ru3	= 331,
    ARC_ASR_S_ru5	= 332,
    ARC_ASR_cc_f_rru6	= 333,
    ARC_ASR_cc_rru6	= 334,
    ARC_ASR_f_rrlimm	= 335,
    ARC_ASR_f_rrr	= 336,
    ARC_ASR_f_rrs12	= 337,
    ARC_ASR_f_rru6	= 338,
    ARC_ASR_rrlimm	= 339,
    ARC_ASR_rrr	= 340,
    ARC_ASR_rrs12	= 341,
    ARC_ASR_rru6	= 342,
    ARC_BCLR_S_ru5	= 343,
    ARC_BEQ_S	= 344,
    ARC_BGE_S	= 345,
    ARC_BGT_S	= 346,
    ARC_BHI_S	= 347,
    ARC_BHS_S	= 348,
    ARC_BL	= 349,
    ARC_BLE_S	= 350,
    ARC_BLO_S	= 351,
    ARC_BLS_S	= 352,
    ARC_BLT_S	= 353,
    ARC_BL_S	= 354,
    ARC_BMSK_S_ru5	= 355,
    ARC_BNE_S	= 356,
    ARC_BR	= 357,
    ARC_BREQ_S	= 358,
    ARC_BRNE_S	= 359,
    ARC_BRcc_rr	= 360,
    ARC_BRcc_ru6	= 361,
    ARC_BSET_S_ru5	= 362,
    ARC_BTST_S_ru5	= 363,
    ARC_B_S	= 364,
    ARC_Bcc	= 365,
    ARC_CMP_S_limms3	= 366,
    ARC_CMP_S_rlimm	= 367,
    ARC_CMP_S_rr	= 368,
    ARC_CMP_S_rs3	= 369,
    ARC_CMP_S_u7	= 370,
    ARC_CMP_rlimm	= 371,
    ARC_CMP_rr	= 372,
    ARC_CMP_ru6	= 373,
    ARC_COMPACT_LD_S	= 374,
    ARC_COMPACT_MOV_S_hreg	= 375,
    ARC_COMPACT_MOV_S_limm	= 376,
    ARC_EI_S	= 377,
    ARC_ENTER_S	= 378,
    ARC_FFS_f_rr	= 379,
    ARC_FFS_rr	= 380,
    ARC_FLS_f_rr	= 381,
    ARC_FLS_rr	= 382,
    ARC_GEN_ABS_S	= 383,
    ARC_GEN_ADD1_S	= 384,
    ARC_GEN_ADD2_S	= 385,
    ARC_GEN_ADD3_S	= 386,
    ARC_GEN_AND_S	= 387,
    ARC_GEN_AS1L_S	= 388,
    ARC_GEN_AS1R_S	= 389,
    ARC_GEN_ASL_S	= 390,
    ARC_GEN_ASR_S	= 391,
    ARC_GEN_BIC_S	= 392,
    ARC_GEN_BRK_S	= 393,
    ARC_GEN_EXTB_S	= 394,
    ARC_GEN_EXTH_S	= 395,
    ARC_GEN_JEQ_S	= 396,
    ARC_GEN_JL_S	= 397,
    ARC_GEN_JL_S_D	= 398,
    ARC_GEN_JNE_S	= 399,
    ARC_GEN_J_S	= 400,
    ARC_GEN_J_S_D	= 401,
    ARC_GEN_J_S_D_BLINK	= 402,
    ARC_GEN_LS1R_S	= 403,
    ARC_GEN_LSR_S	= 404,
    ARC_GEN_MPYUW_S	= 405,
    ARC_GEN_MPYW_S	= 406,
    ARC_GEN_MPY_S	= 407,
    ARC_GEN_NEG_S	= 408,
    ARC_GEN_NOP_S	= 409,
    ARC_GEN_NOT_S	= 410,
    ARC_GEN_OR_S	= 411,
    ARC_GEN_SEXB_S	= 412,
    ARC_GEN_SEXH_S	= 413,
    ARC_GEN_SUB_S	= 414,
    ARC_GEN_SUB_S_NE	= 415,
    ARC_GEN_SWI_S	= 416,
    ARC_GEN_TRAP_S	= 417,
    ARC_GEN_TST_S	= 418,
    ARC_GEN_UNIMP_S	= 419,
    ARC_GEN_XOR_S	= 420,
    ARC_GP_ADD_S	= 421,
    ARC_GP_LDB_S	= 422,
    ARC_GP_LDH_S	= 423,
    ARC_GP_LD_S	= 424,
    ARC_J	= 425,
    ARC_JL	= 426,
    ARC_JLI_S	= 427,
    ARC_JL_LImm	= 428,
    ARC_J_LImm	= 429,
    ARC_J_S_BLINK	= 430,
    ARC_LDB_AB_rs9	= 431,
    ARC_LDB_AW_rs9	= 432,
    ARC_LDB_DI_AB_rs9	= 433,
    ARC_LDB_DI_AW_rs9	= 434,
    ARC_LDB_DI_limm	= 435,
    ARC_LDB_DI_rlimm	= 436,
    ARC_LDB_DI_rs9	= 437,
    ARC_LDB_S_OFF	= 438,
    ARC_LDB_S_rrr	= 439,
    ARC_LDB_X_AB_rs9	= 440,
    ARC_LDB_X_AW_rs9	= 441,
    ARC_LDB_X_DI_AB_rs9	= 442,
    ARC_LDB_X_DI_AW_rs9	= 443,
    ARC_LDB_X_DI_limm	= 444,
    ARC_LDB_X_DI_rlimm	= 445,
    ARC_LDB_X_DI_rs9	= 446,
    ARC_LDB_X_limm	= 447,
    ARC_LDB_X_rlimm	= 448,
    ARC_LDB_X_rs9	= 449,
    ARC_LDB_limm	= 450,
    ARC_LDB_rlimm	= 451,
    ARC_LDB_rs9	= 452,
    ARC_LDH_AB_rs9	= 453,
    ARC_LDH_AW_rs9	= 454,
    ARC_LDH_DI_AB_rs9	= 455,
    ARC_LDH_DI_AW_rs9	= 456,
    ARC_LDH_DI_limm	= 457,
    ARC_LDH_DI_rlimm	= 458,
    ARC_LDH_DI_rs9	= 459,
    ARC_LDH_S_OFF	= 460,
    ARC_LDH_S_X_OFF	= 461,
    ARC_LDH_S_rrr	= 462,
    ARC_LDH_X_AB_rs9	= 463,
    ARC_LDH_X_AW_rs9	= 464,
    ARC_LDH_X_DI_AB_rs9	= 465,
    ARC_LDH_X_DI_AW_rs9	= 466,
    ARC_LDH_X_DI_limm	= 467,
    ARC_LDH_X_DI_rlimm	= 468,
    ARC_LDH_X_DI_rs9	= 469,
    ARC_LDH_X_limm	= 470,
    ARC_LDH_X_rlimm	= 471,
    ARC_LDH_X_rs9	= 472,
    ARC_LDH_limm	= 473,
    ARC_LDH_rlimm	= 474,
    ARC_LDH_rs9	= 475,
    ARC_LDI_S_u7	= 476,
    ARC_LD_AB_rs9	= 477,
    ARC_LD_AW_rs9	= 478,
    ARC_LD_DI_AB_rs9	= 479,
    ARC_LD_DI_AW_rs9	= 480,
    ARC_LD_DI_limm	= 481,
    ARC_LD_DI_rlimm	= 482,
    ARC_LD_DI_rs9	= 483,
    ARC_LD_S_AS_rrr	= 484,
    ARC_LD_S_OFF	= 485,
    ARC_LD_S_rrr	= 486,
    ARC_LD_S_s11	= 487,
    ARC_LD_limm	= 488,
    ARC_LD_rlimm	= 489,
    ARC_LD_rs9	= 490,
    ARC_LEAVE_S	= 491,
    ARC_LR_rs12	= 492,
    ARC_LR_ru6	= 493,
    ARC_LSR_S_ru5	= 494,
    ARC_LSR_cc_f_rru6	= 495,
    ARC_LSR_cc_rru6	= 496,
    ARC_LSR_f_rrlimm	= 497,
    ARC_LSR_f_rrr	= 498,
    ARC_LSR_f_rrs12	= 499,
    ARC_LSR_f_rru6	= 500,
    ARC_LSR_rrlimm	= 501,
    ARC_LSR_rrr	= 502,
    ARC_LSR_rrs12	= 503,
    ARC_LSR_rru6	= 504,
    ARC_MAX_cc_f_rru6	= 505,
    ARC_MAX_cc_rru6	= 506,
    ARC_MAX_f_rrlimm	= 507,
    ARC_MAX_f_rrr	= 508,
    ARC_MAX_f_rrs12	= 509,
    ARC_MAX_f_rru6	= 510,
    ARC_MAX_rrlimm	= 511,
    ARC_MAX_rrr	= 512,
    ARC_MAX_rrs12	= 513,
    ARC_MAX_rru6	= 514,
    ARC_MIN_cc_f_rru6	= 515,
    ARC_MIN_cc_rru6	= 516,
    ARC_MIN_f_rrlimm	= 517,
    ARC_MIN_f_rrr	= 518,
    ARC_MIN_f_rrs12	= 519,
    ARC_MIN_f_rru6	= 520,
    ARC_MIN_rrlimm	= 521,
    ARC_MIN_rrr	= 522,
    ARC_MIN_rrs12	= 523,
    ARC_MIN_rru6	= 524,
    ARC_MOV_S_NE_rlimm	= 525,
    ARC_MOV_S_NE_rr	= 526,
    ARC_MOV_S_rs3	= 527,
    ARC_MOV_S_s3	= 528,
    ARC_MOV_S_u8	= 529,
    ARC_MOV_cc	= 530,
    ARC_MOV_cc_f_ru6	= 531,
    ARC_MOV_cc_ru6	= 532,
    ARC_MOV_f_ru6	= 533,
    ARC_MOV_rlimm	= 534,
    ARC_MOV_rr	= 535,
    ARC_MOV_rs12	= 536,
    ARC_MOV_ru6	= 537,
    ARC_MPYMU_cc_f_rru6	= 538,
    ARC_MPYMU_cc_rru6	= 539,
    ARC_MPYMU_f_rrlimm	= 540,
    ARC_MPYMU_f_rrr	= 541,
    ARC_MPYMU_f_rrs12	= 542,
    ARC_MPYMU_f_rru6	= 543,
    ARC_MPYMU_rrlimm	= 544,
    ARC_MPYMU_rrr	= 545,
    ARC_MPYMU_rrs12	= 546,
    ARC_MPYMU_rru6	= 547,
    ARC_MPYM_cc_f_rru6	= 548,
    ARC_MPYM_cc_rru6	= 549,
    ARC_MPYM_f_rrlimm	= 550,
    ARC_MPYM_f_rrr	= 551,
    ARC_MPYM_f_rrs12	= 552,
    ARC_MPYM_f_rru6	= 553,
    ARC_MPYM_rrlimm	= 554,
    ARC_MPYM_rrr	= 555,
    ARC_MPYM_rrs12	= 556,
    ARC_MPYM_rru6	= 557,
    ARC_MPY_cc_f_rru6	= 558,
    ARC_MPY_cc_rru6	= 559,
    ARC_MPY_f_rrlimm	= 560,
    ARC_MPY_f_rrr	= 561,
    ARC_MPY_f_rrs12	= 562,
    ARC_MPY_f_rru6	= 563,
    ARC_MPY_rrlimm	= 564,
    ARC_MPY_rrr	= 565,
    ARC_MPY_rrs12	= 566,
    ARC_MPY_rru6	= 567,
    ARC_NORMH_f_rr	= 568,
    ARC_NORMH_rr	= 569,
    ARC_NORM_f_rr	= 570,
    ARC_NORM_rr	= 571,
    ARC_OR_cc_f_rru6	= 572,
    ARC_OR_cc_rru6	= 573,
    ARC_OR_f_rrlimm	= 574,
    ARC_OR_f_rrr	= 575,
    ARC_OR_f_rrs12	= 576,
    ARC_OR_f_rru6	= 577,
    ARC_OR_rrlimm	= 578,
    ARC_OR_rrr	= 579,
    ARC_OR_rrs12	= 580,
    ARC_OR_rru6	= 581,
    ARC_PCL_LD	= 582,
    ARC_POP_S_BLINK	= 583,
    ARC_POP_S_r	= 584,
    ARC_PUSH_S_BLINK	= 585,
    ARC_PUSH_S_r	= 586,
    ARC_ROR_cc_f_rru6	= 587,
    ARC_ROR_cc_rru6	= 588,
    ARC_ROR_f_rrlimm	= 589,
    ARC_ROR_f_rrr	= 590,
    ARC_ROR_f_rrs12	= 591,
    ARC_ROR_f_rru6	= 592,
    ARC_ROR_rrlimm	= 593,
    ARC_ROR_rrr	= 594,
    ARC_ROR_rrs12	= 595,
    ARC_ROR_rru6	= 596,
    ARC_RSUB_cc_f_rru6	= 597,
    ARC_RSUB_cc_rru6	= 598,
    ARC_RSUB_f_rrlimm	= 599,
    ARC_RSUB_f_rrr	= 600,
    ARC_RSUB_f_rrs12	= 601,
    ARC_RSUB_f_rru6	= 602,
    ARC_RSUB_rrlimm	= 603,
    ARC_RSUB_rrr	= 604,
    ARC_RSUB_rrs12	= 605,
    ARC_RSUB_rru6	= 606,
    ARC_SBC_cc_f_rru6	= 607,
    ARC_SBC_cc_rru6	= 608,
    ARC_SBC_f_rrlimm	= 609,
    ARC_SBC_f_rrr	= 610,
    ARC_SBC_f_rrs12	= 611,
    ARC_SBC_f_rru6	= 612,
    ARC_SBC_rrlimm	= 613,
    ARC_SBC_rrr	= 614,
    ARC_SBC_rrs12	= 615,
    ARC_SBC_rru6	= 616,
    ARC_SETEQ_cc_f_rru6	= 617,
    ARC_SETEQ_cc_rru6	= 618,
    ARC_SETEQ_f_rrlimm	= 619,
    ARC_SETEQ_f_rrr	= 620,
    ARC_SETEQ_f_rrs12	= 621,
    ARC_SETEQ_f_rru6	= 622,
    ARC_SETEQ_rrlimm	= 623,
    ARC_SETEQ_rrr	= 624,
    ARC_SETEQ_rrs12	= 625,
    ARC_SETEQ_rru6	= 626,
    ARC_SEXB_f_rr	= 627,
    ARC_SEXB_rr	= 628,
    ARC_SEXH_f_rr	= 629,
    ARC_SEXH_rr	= 630,
    ARC_SP_ADD_S	= 631,
    ARC_SP_ADD_SP_S	= 632,
    ARC_SP_LDB_S	= 633,
    ARC_SP_LD_S	= 634,
    ARC_SP_STB_S	= 635,
    ARC_SP_ST_S	= 636,
    ARC_SP_SUB_SP_S	= 637,
    ARC_STB_AB_rs9	= 638,
    ARC_STB_AW_rs9	= 639,
    ARC_STB_DI_AB_rs9	= 640,
    ARC_STB_DI_AW_rs9	= 641,
    ARC_STB_DI_limm	= 642,
    ARC_STB_DI_rs9	= 643,
    ARC_STB_S_OFF	= 644,
    ARC_STB_limm	= 645,
    ARC_STB_rs9	= 646,
    ARC_STH_AB_rs9	= 647,
    ARC_STH_AW_rs9	= 648,
    ARC_STH_DI_AB_rs9	= 649,
    ARC_STH_DI_AW_rs9	= 650,
    ARC_STH_DI_limm	= 651,
    ARC_STH_DI_rs9	= 652,
    ARC_STH_S_OFF	= 653,
    ARC_STH_limm	= 654,
    ARC_STH_rs9	= 655,
    ARC_ST_AB_rs9	= 656,
    ARC_ST_AW_rs9	= 657,
    ARC_ST_DI_AB_rs9	= 658,
    ARC_ST_DI_AW_rs9	= 659,
    ARC_ST_DI_limm	= 660,
    ARC_ST_DI_rs9	= 661,
    ARC_ST_S_OFF	= 662,
    ARC_ST_S_s11	= 663,
    ARC_ST_limm	= 664,
    ARC_ST_rs9	= 665,
    ARC_SUB1_cc_f_rru6	= 666,
    ARC_SUB1_cc_rru6	= 667,
    ARC_SUB1_f_rrlimm	= 668,
    ARC_SUB1_f_rrr	= 669,
    ARC_SUB1_f_rrs12	= 670,
    ARC_SUB1_f_rru6	= 671,
    ARC_SUB1_rrlimm	= 672,
    ARC_SUB1_rrr	= 673,
    ARC_SUB1_rrs12	= 674,
    ARC_SUB1_rru6	= 675,
    ARC_SUB2_cc_f_rru6	= 676,
    ARC_SUB2_cc_rru6	= 677,
    ARC_SUB2_f_rrlimm	= 678,
    ARC_SUB2_f_rrr	= 679,
    ARC_SUB2_f_rrs12	= 680,
    ARC_SUB2_f_rru6	= 681,
    ARC_SUB2_rrlimm	= 682,
    ARC_SUB2_rrr	= 683,
    ARC_SUB2_rrs12	= 684,
    ARC_SUB2_rru6	= 685,
    ARC_SUB3_cc_f_rru6	= 686,
    ARC_SUB3_cc_rru6	= 687,
    ARC_SUB3_f_rrlimm	= 688,
    ARC_SUB3_f_rrr	= 689,
    ARC_SUB3_f_rrs12	= 690,
    ARC_SUB3_f_rru6	= 691,
    ARC_SUB3_rrlimm	= 692,
    ARC_SUB3_rrr	= 693,
    ARC_SUB3_rrs12	= 694,
    ARC_SUB3_rru6	= 695,
    ARC_SUB_S_rrr	= 696,
    ARC_SUB_S_ru3	= 697,
    ARC_SUB_S_ru5	= 698,
    ARC_SUB_cc_f_rru6	= 699,
    ARC_SUB_cc_rru6	= 700,
    ARC_SUB_f_rrlimm	= 701,
    ARC_SUB_f_rrr	= 702,
    ARC_SUB_f_rrs12	= 703,
    ARC_SUB_f_rru6	= 704,
    ARC_SUB_rrlimm	= 705,
    ARC_SUB_rrr	= 706,
    ARC_SUB_rrs12	= 707,
    ARC_SUB_rru6	= 708,
    ARC_XOR_cc_f_rru6	= 709,
    ARC_XOR_cc_rru6	= 710,
    ARC_XOR_f_rrlimm	= 711,
    ARC_XOR_f_rrr	= 712,
    ARC_XOR_f_rrs12	= 713,
    ARC_XOR_f_rru6	= 714,
    ARC_XOR_rrlimm	= 715,
    ARC_XOR_rrr	= 716,
    ARC_XOR_rrs12	= 717,
    ARC_XOR_rru6	= 718,
    INSTRUCTION_LIST_END = 719
  };

#endif // GET_INSTRINFO_ENUM

#if defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)
typedef struct ARCInstrTable {
  MCInstrDesc Insts[719];
  MCOperandInfo OperandInfo[207];
  MCPhysReg ImplicitOps[9];
} ARCInstrTable;

#endif // defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

#ifdef GET_INSTRINFO_MC_DESC
#undef GET_INSTRINFO_MC_DESC

static const unsigned ARCImpOpBase = sizeof(MCOperandInfo) / (sizeof(MCPhysReg));

static const ARCInstrTable ARCDescs = {
  {
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #718 = XOR_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #717 = XOR_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #716 = XOR_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #715 = XOR_rrlimm
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #714 = XOR_f_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #713 = XOR_f_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #712 = XOR_f_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #711 = XOR_f_rrlimm
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #710 = XOR_cc_rru6
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #709 = XOR_cc_f_rru6
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #708 = SUB_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #707 = SUB_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #706 = SUB_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #705 = SUB_rrlimm
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #704 = SUB_f_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #703 = SUB_f_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #702 = SUB_f_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #701 = SUB_f_rrlimm
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #700 = SUB_cc_rru6
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #699 = SUB_cc_f_rru6
  { 2, &ARCDescs.OperandInfo[176] },  // Inst #698 = SUB_S_ru5
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #697 = SUB_S_ru3
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #696 = SUB_S_rrr
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #695 = SUB3_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #694 = SUB3_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #693 = SUB3_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #692 = SUB3_rrlimm
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #691 = SUB3_f_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #690 = SUB3_f_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #689 = SUB3_f_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #688 = SUB3_f_rrlimm
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #687 = SUB3_cc_rru6
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #686 = SUB3_cc_f_rru6
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #685 = SUB2_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #684 = SUB2_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #683 = SUB2_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #682 = SUB2_rrlimm
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #681 = SUB2_f_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #680 = SUB2_f_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #679 = SUB2_f_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #678 = SUB2_f_rrlimm
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #677 = SUB2_cc_rru6
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #676 = SUB2_cc_f_rru6
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #675 = SUB1_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #674 = SUB1_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #673 = SUB1_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #672 = SUB1_rrlimm
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #671 = SUB1_f_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #670 = SUB1_f_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #669 = SUB1_f_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #668 = SUB1_f_rrlimm
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #667 = SUB1_cc_rru6
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #666 = SUB1_cc_f_rru6
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #665 = ST_rs9
  { 3, &ARCDescs.OperandInfo[150] },  // Inst #664 = ST_limm
  { 1, &ARCDescs.OperandInfo[0] },  // Inst #663 = ST_S_s11
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #662 = ST_S_OFF
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #661 = ST_DI_rs9
  { 3, &ARCDescs.OperandInfo[150] },  // Inst #660 = ST_DI_limm
  { 4, &ARCDescs.OperandInfo[203] },  // Inst #659 = ST_DI_AW_rs9
  { 4, &ARCDescs.OperandInfo[203] },  // Inst #658 = ST_DI_AB_rs9
  { 4, &ARCDescs.OperandInfo[203] },  // Inst #657 = ST_AW_rs9
  { 4, &ARCDescs.OperandInfo[203] },  // Inst #656 = ST_AB_rs9
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #655 = STH_rs9
  { 3, &ARCDescs.OperandInfo[150] },  // Inst #654 = STH_limm
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #653 = STH_S_OFF
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #652 = STH_DI_rs9
  { 3, &ARCDescs.OperandInfo[150] },  // Inst #651 = STH_DI_limm
  { 4, &ARCDescs.OperandInfo[203] },  // Inst #650 = STH_DI_AW_rs9
  { 4, &ARCDescs.OperandInfo[203] },  // Inst #649 = STH_DI_AB_rs9
  { 4, &ARCDescs.OperandInfo[203] },  // Inst #648 = STH_AW_rs9
  { 4, &ARCDescs.OperandInfo[203] },  // Inst #647 = STH_AB_rs9
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #646 = STB_rs9
  { 3, &ARCDescs.OperandInfo[150] },  // Inst #645 = STB_limm
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #644 = STB_S_OFF
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #643 = STB_DI_rs9
  { 3, &ARCDescs.OperandInfo[150] },  // Inst #642 = STB_DI_limm
  { 4, &ARCDescs.OperandInfo[203] },  // Inst #641 = STB_DI_AW_rs9
  { 4, &ARCDescs.OperandInfo[203] },  // Inst #640 = STB_DI_AB_rs9
  { 4, &ARCDescs.OperandInfo[203] },  // Inst #639 = STB_AW_rs9
  { 4, &ARCDescs.OperandInfo[203] },  // Inst #638 = STB_AB_rs9
  { 1, &ARCDescs.OperandInfo[0] },  // Inst #637 = SP_SUB_SP_S
  { 2, &ARCDescs.OperandInfo[201] },  // Inst #636 = SP_ST_S
  { 2, &ARCDescs.OperandInfo[201] },  // Inst #635 = SP_STB_S
  { 2, &ARCDescs.OperandInfo[201] },  // Inst #634 = SP_LD_S
  { 2, &ARCDescs.OperandInfo[201] },  // Inst #633 = SP_LDB_S
  { 1, &ARCDescs.OperandInfo[0] },  // Inst #632 = SP_ADD_SP_S
  { 2, &ARCDescs.OperandInfo[201] },  // Inst #631 = SP_ADD_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #630 = SEXH_rr
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #629 = SEXH_f_rr
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #628 = SEXB_rr
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #627 = SEXB_f_rr
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #626 = SETEQ_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #625 = SETEQ_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #624 = SETEQ_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #623 = SETEQ_rrlimm
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #622 = SETEQ_f_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #621 = SETEQ_f_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #620 = SETEQ_f_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #619 = SETEQ_f_rrlimm
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #618 = SETEQ_cc_rru6
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #617 = SETEQ_cc_f_rru6
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #616 = SBC_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #615 = SBC_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #614 = SBC_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #613 = SBC_rrlimm
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #612 = SBC_f_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #611 = SBC_f_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #610 = SBC_f_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #609 = SBC_f_rrlimm
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #608 = SBC_cc_rru6
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #607 = SBC_cc_f_rru6
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #606 = RSUB_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #605 = RSUB_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #604 = RSUB_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #603 = RSUB_rrlimm
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #602 = RSUB_f_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #601 = RSUB_f_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #600 = RSUB_f_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #599 = RSUB_f_rrlimm
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #598 = RSUB_cc_rru6
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #597 = RSUB_cc_f_rru6
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #596 = ROR_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #595 = ROR_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #594 = ROR_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #593 = ROR_rrlimm
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #592 = ROR_f_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #591 = ROR_f_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #590 = ROR_f_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #589 = ROR_f_rrlimm
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #588 = ROR_cc_rru6
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #587 = ROR_cc_f_rru6
  { 1, &ARCDescs.OperandInfo[200] },  // Inst #586 = PUSH_S_r
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #585 = PUSH_S_BLINK
  { 1, &ARCDescs.OperandInfo[200] },  // Inst #584 = POP_S_r
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #583 = POP_S_BLINK
  { 2, &ARCDescs.OperandInfo[176] },  // Inst #582 = PCL_LD
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #581 = OR_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #580 = OR_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #579 = OR_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #578 = OR_rrlimm
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #577 = OR_f_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #576 = OR_f_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #575 = OR_f_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #574 = OR_f_rrlimm
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #573 = OR_cc_rru6
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #572 = OR_cc_f_rru6
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #571 = NORM_rr
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #570 = NORM_f_rr
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #569 = NORMH_rr
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #568 = NORMH_f_rr
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #567 = MPY_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #566 = MPY_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #565 = MPY_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #564 = MPY_rrlimm
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #563 = MPY_f_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #562 = MPY_f_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #561 = MPY_f_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #560 = MPY_f_rrlimm
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #559 = MPY_cc_rru6
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #558 = MPY_cc_f_rru6
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #557 = MPYM_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #556 = MPYM_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #555 = MPYM_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #554 = MPYM_rrlimm
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #553 = MPYM_f_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #552 = MPYM_f_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #551 = MPYM_f_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #550 = MPYM_f_rrlimm
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #549 = MPYM_cc_rru6
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #548 = MPYM_cc_f_rru6
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #547 = MPYMU_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #546 = MPYMU_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #545 = MPYMU_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #544 = MPYMU_rrlimm
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #543 = MPYMU_f_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #542 = MPYMU_f_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #541 = MPYMU_f_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #540 = MPYMU_f_rrlimm
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #539 = MPYMU_cc_rru6
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #538 = MPYMU_cc_f_rru6
  { 2, &ARCDescs.OperandInfo[176] },  // Inst #537 = MOV_ru6
  { 2, &ARCDescs.OperandInfo[176] },  // Inst #536 = MOV_rs12
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #535 = MOV_rr
  { 2, &ARCDescs.OperandInfo[174] },  // Inst #534 = MOV_rlimm
  { 2, &ARCDescs.OperandInfo[176] },  // Inst #533 = MOV_f_ru6
  { 4, &ARCDescs.OperandInfo[196] },  // Inst #532 = MOV_cc_ru6
  { 4, &ARCDescs.OperandInfo[196] },  // Inst #531 = MOV_cc_f_ru6
  { 4, &ARCDescs.OperandInfo[192] },  // Inst #530 = MOV_cc
  { 2, &ARCDescs.OperandInfo[176] },  // Inst #529 = MOV_S_u8
  { 1, &ARCDescs.OperandInfo[0] },  // Inst #528 = MOV_S_s3
  { 2, &ARCDescs.OperandInfo[176] },  // Inst #527 = MOV_S_rs3
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #526 = MOV_S_NE_rr
  { 2, &ARCDescs.OperandInfo[174] },  // Inst #525 = MOV_S_NE_rlimm
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #524 = MIN_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #523 = MIN_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #522 = MIN_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #521 = MIN_rrlimm
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #520 = MIN_f_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #519 = MIN_f_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #518 = MIN_f_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #517 = MIN_f_rrlimm
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #516 = MIN_cc_rru6
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #515 = MIN_cc_f_rru6
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #514 = MAX_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #513 = MAX_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #512 = MAX_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #511 = MAX_rrlimm
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #510 = MAX_f_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #509 = MAX_f_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #508 = MAX_f_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #507 = MAX_f_rrlimm
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #506 = MAX_cc_rru6
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #505 = MAX_cc_f_rru6
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #504 = LSR_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #503 = LSR_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #502 = LSR_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #501 = LSR_rrlimm
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #500 = LSR_f_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #499 = LSR_f_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #498 = LSR_f_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #497 = LSR_f_rrlimm
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #496 = LSR_cc_rru6
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #495 = LSR_cc_f_rru6
  { 2, &ARCDescs.OperandInfo[176] },  // Inst #494 = LSR_S_ru5
  { 2, &ARCDescs.OperandInfo[176] },  // Inst #493 = LR_ru6
  { 2, &ARCDescs.OperandInfo[176] },  // Inst #492 = LR_rs12
  { 1, &ARCDescs.OperandInfo[0] },  // Inst #491 = LEAVE_S
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #490 = LD_rs9
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #489 = LD_rlimm
  { 3, &ARCDescs.OperandInfo[150] },  // Inst #488 = LD_limm
  { 1, &ARCDescs.OperandInfo[0] },  // Inst #487 = LD_S_s11
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #486 = LD_S_rrr
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #485 = LD_S_OFF
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #484 = LD_S_AS_rrr
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #483 = LD_DI_rs9
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #482 = LD_DI_rlimm
  { 3, &ARCDescs.OperandInfo[150] },  // Inst #481 = LD_DI_limm
  { 4, &ARCDescs.OperandInfo[188] },  // Inst #480 = LD_DI_AW_rs9
  { 4, &ARCDescs.OperandInfo[188] },  // Inst #479 = LD_DI_AB_rs9
  { 4, &ARCDescs.OperandInfo[188] },  // Inst #478 = LD_AW_rs9
  { 4, &ARCDescs.OperandInfo[188] },  // Inst #477 = LD_AB_rs9
  { 2, &ARCDescs.OperandInfo[176] },  // Inst #476 = LDI_S_u7
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #475 = LDH_rs9
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #474 = LDH_rlimm
  { 3, &ARCDescs.OperandInfo[150] },  // Inst #473 = LDH_limm
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #472 = LDH_X_rs9
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #471 = LDH_X_rlimm
  { 3, &ARCDescs.OperandInfo[150] },  // Inst #470 = LDH_X_limm
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #469 = LDH_X_DI_rs9
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #468 = LDH_X_DI_rlimm
  { 3, &ARCDescs.OperandInfo[150] },  // Inst #467 = LDH_X_DI_limm
  { 4, &ARCDescs.OperandInfo[188] },  // Inst #466 = LDH_X_DI_AW_rs9
  { 4, &ARCDescs.OperandInfo[188] },  // Inst #465 = LDH_X_DI_AB_rs9
  { 4, &ARCDescs.OperandInfo[188] },  // Inst #464 = LDH_X_AW_rs9
  { 4, &ARCDescs.OperandInfo[188] },  // Inst #463 = LDH_X_AB_rs9
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #462 = LDH_S_rrr
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #461 = LDH_S_X_OFF
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #460 = LDH_S_OFF
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #459 = LDH_DI_rs9
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #458 = LDH_DI_rlimm
  { 3, &ARCDescs.OperandInfo[150] },  // Inst #457 = LDH_DI_limm
  { 4, &ARCDescs.OperandInfo[188] },  // Inst #456 = LDH_DI_AW_rs9
  { 4, &ARCDescs.OperandInfo[188] },  // Inst #455 = LDH_DI_AB_rs9
  { 4, &ARCDescs.OperandInfo[188] },  // Inst #454 = LDH_AW_rs9
  { 4, &ARCDescs.OperandInfo[188] },  // Inst #453 = LDH_AB_rs9
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #452 = LDB_rs9
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #451 = LDB_rlimm
  { 3, &ARCDescs.OperandInfo[150] },  // Inst #450 = LDB_limm
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #449 = LDB_X_rs9
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #448 = LDB_X_rlimm
  { 3, &ARCDescs.OperandInfo[150] },  // Inst #447 = LDB_X_limm
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #446 = LDB_X_DI_rs9
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #445 = LDB_X_DI_rlimm
  { 3, &ARCDescs.OperandInfo[150] },  // Inst #444 = LDB_X_DI_limm
  { 4, &ARCDescs.OperandInfo[188] },  // Inst #443 = LDB_X_DI_AW_rs9
  { 4, &ARCDescs.OperandInfo[188] },  // Inst #442 = LDB_X_DI_AB_rs9
  { 4, &ARCDescs.OperandInfo[188] },  // Inst #441 = LDB_X_AW_rs9
  { 4, &ARCDescs.OperandInfo[188] },  // Inst #440 = LDB_X_AB_rs9
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #439 = LDB_S_rrr
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #438 = LDB_S_OFF
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #437 = LDB_DI_rs9
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #436 = LDB_DI_rlimm
  { 3, &ARCDescs.OperandInfo[150] },  // Inst #435 = LDB_DI_limm
  { 4, &ARCDescs.OperandInfo[188] },  // Inst #434 = LDB_DI_AW_rs9
  { 4, &ARCDescs.OperandInfo[188] },  // Inst #433 = LDB_DI_AB_rs9
  { 4, &ARCDescs.OperandInfo[188] },  // Inst #432 = LDB_AW_rs9
  { 4, &ARCDescs.OperandInfo[188] },  // Inst #431 = LDB_AB_rs9
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #430 = J_S_BLINK
  { 1, &ARCDescs.OperandInfo[1] },  // Inst #429 = J_LImm
  { 1, &ARCDescs.OperandInfo[1] },  // Inst #428 = JL_LImm
  { 1, &ARCDescs.OperandInfo[0] },  // Inst #427 = JLI_S
  { 1, &ARCDescs.OperandInfo[187] },  // Inst #426 = JL
  { 1, &ARCDescs.OperandInfo[187] },  // Inst #425 = J
  { 1, &ARCDescs.OperandInfo[0] },  // Inst #424 = GP_LD_S
  { 1, &ARCDescs.OperandInfo[0] },  // Inst #423 = GP_LDH_S
  { 1, &ARCDescs.OperandInfo[0] },  // Inst #422 = GP_LDB_S
  { 1, &ARCDescs.OperandInfo[0] },  // Inst #421 = GP_ADD_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #420 = GEN_XOR_S
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #419 = GEN_UNIMP_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #418 = GEN_TST_S
  { 1, &ARCDescs.OperandInfo[0] },  // Inst #417 = GEN_TRAP_S
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #416 = GEN_SWI_S
  { 1, &ARCDescs.OperandInfo[187] },  // Inst #415 = GEN_SUB_S_NE
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #414 = GEN_SUB_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #413 = GEN_SEXH_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #412 = GEN_SEXB_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #411 = GEN_OR_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #410 = GEN_NOT_S
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #409 = GEN_NOP_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #408 = GEN_NEG_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #407 = GEN_MPY_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #406 = GEN_MPYW_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #405 = GEN_MPYUW_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #404 = GEN_LSR_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #403 = GEN_LS1R_S
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #402 = GEN_J_S_D_BLINK
  { 1, &ARCDescs.OperandInfo[187] },  // Inst #401 = GEN_J_S_D
  { 1, &ARCDescs.OperandInfo[187] },  // Inst #400 = GEN_J_S
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #399 = GEN_JNE_S
  { 1, &ARCDescs.OperandInfo[187] },  // Inst #398 = GEN_JL_S_D
  { 1, &ARCDescs.OperandInfo[187] },  // Inst #397 = GEN_JL_S
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #396 = GEN_JEQ_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #395 = GEN_EXTH_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #394 = GEN_EXTB_S
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #393 = GEN_BRK_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #392 = GEN_BIC_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #391 = GEN_ASR_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #390 = GEN_ASL_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #389 = GEN_AS1R_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #388 = GEN_AS1L_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #387 = GEN_AND_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #386 = GEN_ADD3_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #385 = GEN_ADD2_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #384 = GEN_ADD1_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #383 = GEN_ABS_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #382 = FLS_rr
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #381 = FLS_f_rr
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #380 = FFS_rr
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #379 = FFS_f_rr
  { 1, &ARCDescs.OperandInfo[0] },  // Inst #378 = ENTER_S
  { 1, &ARCDescs.OperandInfo[0] },  // Inst #377 = EI_S
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #376 = COMPACT_MOV_S_limm
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #375 = COMPACT_MOV_S_hreg
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #374 = COMPACT_LD_S
  { 2, &ARCDescs.OperandInfo[174] },  // Inst #373 = CMP_ru6
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #372 = CMP_rr
  { 2, &ARCDescs.OperandInfo[174] },  // Inst #371 = CMP_rlimm
  { 2, &ARCDescs.OperandInfo[176] },  // Inst #370 = CMP_S_u7
  { 2, &ARCDescs.OperandInfo[176] },  // Inst #369 = CMP_S_rs3
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #368 = CMP_S_rr
  { 2, &ARCDescs.OperandInfo[174] },  // Inst #367 = CMP_S_rlimm
  { 2, &ARCDescs.OperandInfo[172] },  // Inst #366 = CMP_S_limms3
  { 2, &ARCDescs.OperandInfo[185] },  // Inst #365 = Bcc
  { 1, &ARCDescs.OperandInfo[178] },  // Inst #364 = B_S
  { 2, &ARCDescs.OperandInfo[176] },  // Inst #363 = BTST_S_ru5
  { 2, &ARCDescs.OperandInfo[176] },  // Inst #362 = BSET_S_ru5
  { 4, &ARCDescs.OperandInfo[181] },  // Inst #361 = BRcc_ru6
  { 4, &ARCDescs.OperandInfo[140] },  // Inst #360 = BRcc_rr
  { 2, &ARCDescs.OperandInfo[179] },  // Inst #359 = BRNE_S
  { 2, &ARCDescs.OperandInfo[179] },  // Inst #358 = BREQ_S
  { 1, &ARCDescs.OperandInfo[178] },  // Inst #357 = BR
  { 1, &ARCDescs.OperandInfo[178] },  // Inst #356 = BNE_S
  { 2, &ARCDescs.OperandInfo[176] },  // Inst #355 = BMSK_S_ru5
  { 1, &ARCDescs.OperandInfo[178] },  // Inst #354 = BL_S
  { 1, &ARCDescs.OperandInfo[178] },  // Inst #353 = BLT_S
  { 1, &ARCDescs.OperandInfo[178] },  // Inst #352 = BLS_S
  { 1, &ARCDescs.OperandInfo[178] },  // Inst #351 = BLO_S
  { 1, &ARCDescs.OperandInfo[178] },  // Inst #350 = BLE_S
  { 1, &ARCDescs.OperandInfo[178] },  // Inst #349 = BL
  { 1, &ARCDescs.OperandInfo[178] },  // Inst #348 = BHS_S
  { 1, &ARCDescs.OperandInfo[178] },  // Inst #347 = BHI_S
  { 1, &ARCDescs.OperandInfo[178] },  // Inst #346 = BGT_S
  { 1, &ARCDescs.OperandInfo[178] },  // Inst #345 = BGE_S
  { 1, &ARCDescs.OperandInfo[178] },  // Inst #344 = BEQ_S
  { 2, &ARCDescs.OperandInfo[176] },  // Inst #343 = BCLR_S_ru5
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #342 = ASR_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #341 = ASR_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #340 = ASR_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #339 = ASR_rrlimm
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #338 = ASR_f_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #337 = ASR_f_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #336 = ASR_f_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #335 = ASR_f_rrlimm
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #334 = ASR_cc_rru6
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #333 = ASR_cc_f_rru6
  { 2, &ARCDescs.OperandInfo[176] },  // Inst #332 = ASR_S_ru5
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #331 = ASR_S_ru3
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #330 = ASL_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #329 = ASL_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #328 = ASL_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #327 = ASL_rrlimm
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #326 = ASL_f_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #325 = ASL_f_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #324 = ASL_f_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #323 = ASL_f_rrlimm
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #322 = ASL_cc_rru6
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #321 = ASL_cc_f_rru6
  { 2, &ARCDescs.OperandInfo[176] },  // Inst #320 = ASL_S_ru5
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #319 = ASL_S_ru3
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #318 = AND_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #317 = AND_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #316 = AND_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #315 = AND_rrlimm
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #314 = AND_f_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #313 = AND_f_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #312 = AND_f_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #311 = AND_f_rrlimm
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #310 = AND_cc_rru6
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #309 = AND_cc_f_rru6
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #308 = ADD_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #307 = ADD_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #306 = ADD_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #305 = ADD_rrlimm
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #304 = ADD_f_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #303 = ADD_f_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #302 = ADD_f_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #301 = ADD_f_rrlimm
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #300 = ADD_cc_rru6
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #299 = ADD_cc_f_rru6
  { 2, &ARCDescs.OperandInfo[176] },  // Inst #298 = ADD_S_u7
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #297 = ADD_S_ru3
  { 2, &ARCDescs.OperandInfo[176] },  // Inst #296 = ADD_S_rs3
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #295 = ADD_S_rru6
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #294 = ADD_S_rrr
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #293 = ADD_S_rr
  { 2, &ARCDescs.OperandInfo[174] },  // Inst #292 = ADD_S_rlimm
  { 2, &ARCDescs.OperandInfo[172] },  // Inst #291 = ADD_S_limms3
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #290 = ADC_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #289 = ADC_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #288 = ADC_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #287 = ADC_rrlimm
  { 3, &ARCDescs.OperandInfo[169] },  // Inst #286 = ADC_f_rru6
  { 3, &ARCDescs.OperandInfo[166] },  // Inst #285 = ADC_f_rrs12
  { 3, &ARCDescs.OperandInfo[163] },  // Inst #284 = ADC_f_rrr
  { 3, &ARCDescs.OperandInfo[160] },  // Inst #283 = ADC_f_rrlimm
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #282 = ADC_cc_rru6
  { 4, &ARCDescs.OperandInfo[156] },  // Inst #281 = ADC_cc_f_rru6
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #280 = ST_FAR
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #279 = STH_FAR
  { 3, &ARCDescs.OperandInfo[153] },  // Inst #278 = STB_FAR
  { 3, &ARCDescs.OperandInfo[150] },  // Inst #277 = GETFI
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #276 = CTTZ
  { 2, &ARCDescs.OperandInfo[148] },  // Inst #275 = CTLZ
  { 4, &ARCDescs.OperandInfo[144] },  // Inst #274 = BRcc_ru6_p
  { 4, &ARCDescs.OperandInfo[140] },  // Inst #273 = BRcc_rr_p
  { 2, &ARCDescs.OperandInfo[21] },  // Inst #272 = ADJCALLSTACKUP
  { 2, &ARCDescs.OperandInfo[21] },  // Inst #271 = ADJCALLSTACKDOWN
  { 4, &ARCDescs.OperandInfo[136] },  // Inst #270 = G_UBFX
  { 4, &ARCDescs.OperandInfo[136] },  // Inst #269 = G_SBFX
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #268 = G_VECREDUCE_UMIN
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #267 = G_VECREDUCE_UMAX
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #266 = G_VECREDUCE_SMIN
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #265 = G_VECREDUCE_SMAX
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #264 = G_VECREDUCE_XOR
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #263 = G_VECREDUCE_OR
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #262 = G_VECREDUCE_AND
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #261 = G_VECREDUCE_MUL
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #260 = G_VECREDUCE_ADD
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #259 = G_VECREDUCE_FMINIMUM
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #258 = G_VECREDUCE_FMAXIMUM
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #257 = G_VECREDUCE_FMIN
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #256 = G_VECREDUCE_FMAX
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #255 = G_VECREDUCE_FMUL
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #254 = G_VECREDUCE_FADD
  { 3, &ARCDescs.OperandInfo[123] },  // Inst #253 = G_VECREDUCE_SEQ_FMUL
  { 3, &ARCDescs.OperandInfo[123] },  // Inst #252 = G_VECREDUCE_SEQ_FADD
  { 3, &ARCDescs.OperandInfo[53] },  // Inst #251 = G_BZERO
  { 4, &ARCDescs.OperandInfo[132] },  // Inst #250 = G_MEMSET
  { 4, &ARCDescs.OperandInfo[132] },  // Inst #249 = G_MEMMOVE
  { 3, &ARCDescs.OperandInfo[123] },  // Inst #248 = G_MEMCPY_INLINE
  { 4, &ARCDescs.OperandInfo[132] },  // Inst #247 = G_MEMCPY
  { 2, &ARCDescs.OperandInfo[130] },  // Inst #246 = G_WRITE_REGISTER
  { 2, &ARCDescs.OperandInfo[51] },  // Inst #245 = G_READ_REGISTER
  { 3, &ARCDescs.OperandInfo[96] },  // Inst #244 = G_STRICT_FLDEXP
  { 2, &ARCDescs.OperandInfo[62] },  // Inst #243 = G_STRICT_FSQRT
  { 4, &ARCDescs.OperandInfo[46] },  // Inst #242 = G_STRICT_FMA
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #241 = G_STRICT_FREM
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #240 = G_STRICT_FDIV
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #239 = G_STRICT_FMUL
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #238 = G_STRICT_FSUB
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #237 = G_STRICT_FADD
  { 1, &ARCDescs.OperandInfo[50] },  // Inst #236 = G_STACKRESTORE
  { 1, &ARCDescs.OperandInfo[50] },  // Inst #235 = G_STACKSAVE
  { 3, &ARCDescs.OperandInfo[64] },  // Inst #234 = G_DYN_STACKALLOC
  { 2, &ARCDescs.OperandInfo[51] },  // Inst #233 = G_JUMP_TABLE
  { 2, &ARCDescs.OperandInfo[51] },  // Inst #232 = G_BLOCK_ADDR
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #231 = G_ADDRSPACE_CAST
  { 2, &ARCDescs.OperandInfo[62] },  // Inst #230 = G_FNEARBYINT
  { 2, &ARCDescs.OperandInfo[62] },  // Inst #229 = G_FRINT
  { 2, &ARCDescs.OperandInfo[62] },  // Inst #228 = G_FFLOOR
  { 2, &ARCDescs.OperandInfo[62] },  // Inst #227 = G_FSQRT
  { 2, &ARCDescs.OperandInfo[62] },  // Inst #226 = G_FSIN
  { 2, &ARCDescs.OperandInfo[62] },  // Inst #225 = G_FCOS
  { 2, &ARCDescs.OperandInfo[62] },  // Inst #224 = G_FCEIL
  { 2, &ARCDescs.OperandInfo[62] },  // Inst #223 = G_BITREVERSE
  { 2, &ARCDescs.OperandInfo[62] },  // Inst #222 = G_BSWAP
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #221 = G_CTPOP
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #220 = G_CTLZ_ZERO_UNDEF
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #219 = G_CTLZ
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #218 = G_CTTZ_ZERO_UNDEF
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #217 = G_CTTZ
  { 4, &ARCDescs.OperandInfo[126] },  // Inst #216 = G_SHUFFLE_VECTOR
  { 3, &ARCDescs.OperandInfo[123] },  // Inst #215 = G_EXTRACT_VECTOR_ELT
  { 4, &ARCDescs.OperandInfo[119] },  // Inst #214 = G_INSERT_VECTOR_ELT
  { 3, &ARCDescs.OperandInfo[116] },  // Inst #213 = G_BRJT
  { 1, &ARCDescs.OperandInfo[0] },  // Inst #212 = G_BR
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #211 = G_LLROUND
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #210 = G_LROUND
  { 2, &ARCDescs.OperandInfo[62] },  // Inst #209 = G_ABS
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #208 = G_UMAX
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #207 = G_UMIN
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #206 = G_SMAX
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #205 = G_SMIN
  { 3, &ARCDescs.OperandInfo[96] },  // Inst #204 = G_PTRMASK
  { 3, &ARCDescs.OperandInfo[96] },  // Inst #203 = G_PTR_ADD
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #202 = G_RESET_FPMODE
  { 1, &ARCDescs.OperandInfo[50] },  // Inst #201 = G_SET_FPMODE
  { 1, &ARCDescs.OperandInfo[50] },  // Inst #200 = G_GET_FPMODE
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #199 = G_RESET_FPENV
  { 1, &ARCDescs.OperandInfo[50] },  // Inst #198 = G_SET_FPENV
  { 1, &ARCDescs.OperandInfo[50] },  // Inst #197 = G_GET_FPENV
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #196 = G_FMAXIMUM
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #195 = G_FMINIMUM
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #194 = G_FMAXNUM_IEEE
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #193 = G_FMINNUM_IEEE
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #192 = G_FMAXNUM
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #191 = G_FMINNUM
  { 2, &ARCDescs.OperandInfo[62] },  // Inst #190 = G_FCANONICALIZE
  { 3, &ARCDescs.OperandInfo[93] },  // Inst #189 = G_IS_FPCLASS
  { 3, &ARCDescs.OperandInfo[96] },  // Inst #188 = G_FCOPYSIGN
  { 2, &ARCDescs.OperandInfo[62] },  // Inst #187 = G_FABS
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #186 = G_UITOFP
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #185 = G_SITOFP
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #184 = G_FPTOUI
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #183 = G_FPTOSI
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #182 = G_FPTRUNC
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #181 = G_FPEXT
  { 2, &ARCDescs.OperandInfo[62] },  // Inst #180 = G_FNEG
  { 3, &ARCDescs.OperandInfo[86] },  // Inst #179 = G_FFREXP
  { 3, &ARCDescs.OperandInfo[96] },  // Inst #178 = G_FLDEXP
  { 2, &ARCDescs.OperandInfo[62] },  // Inst #177 = G_FLOG10
  { 2, &ARCDescs.OperandInfo[62] },  // Inst #176 = G_FLOG2
  { 2, &ARCDescs.OperandInfo[62] },  // Inst #175 = G_FLOG
  { 2, &ARCDescs.OperandInfo[62] },  // Inst #174 = G_FEXP10
  { 2, &ARCDescs.OperandInfo[62] },  // Inst #173 = G_FEXP2
  { 2, &ARCDescs.OperandInfo[62] },  // Inst #172 = G_FEXP
  { 3, &ARCDescs.OperandInfo[96] },  // Inst #171 = G_FPOWI
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #170 = G_FPOW
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #169 = G_FREM
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #168 = G_FDIV
  { 4, &ARCDescs.OperandInfo[46] },  // Inst #167 = G_FMAD
  { 4, &ARCDescs.OperandInfo[46] },  // Inst #166 = G_FMA
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #165 = G_FMUL
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #164 = G_FSUB
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #163 = G_FADD
  { 4, &ARCDescs.OperandInfo[112] },  // Inst #162 = G_UDIVFIXSAT
  { 4, &ARCDescs.OperandInfo[112] },  // Inst #161 = G_SDIVFIXSAT
  { 4, &ARCDescs.OperandInfo[112] },  // Inst #160 = G_UDIVFIX
  { 4, &ARCDescs.OperandInfo[112] },  // Inst #159 = G_SDIVFIX
  { 4, &ARCDescs.OperandInfo[112] },  // Inst #158 = G_UMULFIXSAT
  { 4, &ARCDescs.OperandInfo[112] },  // Inst #157 = G_SMULFIXSAT
  { 4, &ARCDescs.OperandInfo[112] },  // Inst #156 = G_UMULFIX
  { 4, &ARCDescs.OperandInfo[112] },  // Inst #155 = G_SMULFIX
  { 3, &ARCDescs.OperandInfo[96] },  // Inst #154 = G_SSHLSAT
  { 3, &ARCDescs.OperandInfo[96] },  // Inst #153 = G_USHLSAT
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #152 = G_SSUBSAT
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #151 = G_USUBSAT
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #150 = G_SADDSAT
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #149 = G_UADDSAT
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #148 = G_SMULH
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #147 = G_UMULH
  { 4, &ARCDescs.OperandInfo[82] },  // Inst #146 = G_SMULO
  { 4, &ARCDescs.OperandInfo[82] },  // Inst #145 = G_UMULO
  { 5, &ARCDescs.OperandInfo[107] },  // Inst #144 = G_SSUBE
  { 4, &ARCDescs.OperandInfo[82] },  // Inst #143 = G_SSUBO
  { 5, &ARCDescs.OperandInfo[107] },  // Inst #142 = G_SADDE
  { 4, &ARCDescs.OperandInfo[82] },  // Inst #141 = G_SADDO
  { 5, &ARCDescs.OperandInfo[107] },  // Inst #140 = G_USUBE
  { 4, &ARCDescs.OperandInfo[82] },  // Inst #139 = G_USUBO
  { 5, &ARCDescs.OperandInfo[107] },  // Inst #138 = G_UADDE
  { 4, &ARCDescs.OperandInfo[82] },  // Inst #137 = G_UADDO
  { 4, &ARCDescs.OperandInfo[82] },  // Inst #136 = G_SELECT
  { 4, &ARCDescs.OperandInfo[103] },  // Inst #135 = G_FCMP
  { 4, &ARCDescs.OperandInfo[103] },  // Inst #134 = G_ICMP
  { 3, &ARCDescs.OperandInfo[96] },  // Inst #133 = G_ROTL
  { 3, &ARCDescs.OperandInfo[96] },  // Inst #132 = G_ROTR
  { 4, &ARCDescs.OperandInfo[99] },  // Inst #131 = G_FSHR
  { 4, &ARCDescs.OperandInfo[99] },  // Inst #130 = G_FSHL
  { 3, &ARCDescs.OperandInfo[96] },  // Inst #129 = G_ASHR
  { 3, &ARCDescs.OperandInfo[96] },  // Inst #128 = G_LSHR
  { 3, &ARCDescs.OperandInfo[96] },  // Inst #127 = G_SHL
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #126 = G_ZEXT
  { 3, &ARCDescs.OperandInfo[40] },  // Inst #125 = G_SEXT_INREG
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #124 = G_SEXT
  { 3, &ARCDescs.OperandInfo[93] },  // Inst #123 = G_VAARG
  { 1, &ARCDescs.OperandInfo[50] },  // Inst #122 = G_VASTART
  { 2, &ARCDescs.OperandInfo[51] },  // Inst #121 = G_FCONSTANT
  { 2, &ARCDescs.OperandInfo[51] },  // Inst #120 = G_CONSTANT
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #119 = G_TRUNC
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #118 = G_ANYEXT
  { 1, &ARCDescs.OperandInfo[0] },  // Inst #117 = G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS
  { 1, &ARCDescs.OperandInfo[0] },  // Inst #116 = G_INTRINSIC_CONVERGENT
  { 1, &ARCDescs.OperandInfo[0] },  // Inst #115 = G_INTRINSIC_W_SIDE_EFFECTS
  { 1, &ARCDescs.OperandInfo[0] },  // Inst #114 = G_INTRINSIC
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #113 = G_INVOKE_REGION_START
  { 1, &ARCDescs.OperandInfo[50] },  // Inst #112 = G_BRINDIRECT
  { 2, &ARCDescs.OperandInfo[51] },  // Inst #111 = G_BRCOND
  { 4, &ARCDescs.OperandInfo[89] },  // Inst #110 = G_PREFETCH
  { 2, &ARCDescs.OperandInfo[21] },  // Inst #109 = G_FENCE
  { 3, &ARCDescs.OperandInfo[86] },  // Inst #108 = G_ATOMICRMW_UDEC_WRAP
  { 3, &ARCDescs.OperandInfo[86] },  // Inst #107 = G_ATOMICRMW_UINC_WRAP
  { 3, &ARCDescs.OperandInfo[86] },  // Inst #106 = G_ATOMICRMW_FMIN
  { 3, &ARCDescs.OperandInfo[86] },  // Inst #105 = G_ATOMICRMW_FMAX
  { 3, &ARCDescs.OperandInfo[86] },  // Inst #104 = G_ATOMICRMW_FSUB
  { 3, &ARCDescs.OperandInfo[86] },  // Inst #103 = G_ATOMICRMW_FADD
  { 3, &ARCDescs.OperandInfo[86] },  // Inst #102 = G_ATOMICRMW_UMIN
  { 3, &ARCDescs.OperandInfo[86] },  // Inst #101 = G_ATOMICRMW_UMAX
  { 3, &ARCDescs.OperandInfo[86] },  // Inst #100 = G_ATOMICRMW_MIN
  { 3, &ARCDescs.OperandInfo[86] },  // Inst #99 = G_ATOMICRMW_MAX
  { 3, &ARCDescs.OperandInfo[86] },  // Inst #98 = G_ATOMICRMW_XOR
  { 3, &ARCDescs.OperandInfo[86] },  // Inst #97 = G_ATOMICRMW_OR
  { 3, &ARCDescs.OperandInfo[86] },  // Inst #96 = G_ATOMICRMW_NAND
  { 3, &ARCDescs.OperandInfo[86] },  // Inst #95 = G_ATOMICRMW_AND
  { 3, &ARCDescs.OperandInfo[86] },  // Inst #94 = G_ATOMICRMW_SUB
  { 3, &ARCDescs.OperandInfo[86] },  // Inst #93 = G_ATOMICRMW_ADD
  { 3, &ARCDescs.OperandInfo[86] },  // Inst #92 = G_ATOMICRMW_XCHG
  { 4, &ARCDescs.OperandInfo[82] },  // Inst #91 = G_ATOMIC_CMPXCHG
  { 5, &ARCDescs.OperandInfo[77] },  // Inst #90 = G_ATOMIC_CMPXCHG_WITH_SUCCESS
  { 5, &ARCDescs.OperandInfo[72] },  // Inst #89 = G_INDEXED_STORE
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #88 = G_STORE
  { 5, &ARCDescs.OperandInfo[67] },  // Inst #87 = G_INDEXED_ZEXTLOAD
  { 5, &ARCDescs.OperandInfo[67] },  // Inst #86 = G_INDEXED_SEXTLOAD
  { 5, &ARCDescs.OperandInfo[67] },  // Inst #85 = G_INDEXED_LOAD
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #84 = G_ZEXTLOAD
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #83 = G_SEXTLOAD
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #82 = G_LOAD
  { 1, &ARCDescs.OperandInfo[50] },  // Inst #81 = G_READCYCLECOUNTER
  { 2, &ARCDescs.OperandInfo[62] },  // Inst #80 = G_INTRINSIC_ROUNDEVEN
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #79 = G_INTRINSIC_LRINT
  { 2, &ARCDescs.OperandInfo[62] },  // Inst #78 = G_INTRINSIC_ROUND
  { 2, &ARCDescs.OperandInfo[62] },  // Inst #77 = G_INTRINSIC_TRUNC
  { 3, &ARCDescs.OperandInfo[64] },  // Inst #76 = G_INTRINSIC_FPTRUNC_ROUND
  { 2, &ARCDescs.OperandInfo[62] },  // Inst #75 = G_CONSTANT_FOLD_BARRIER
  { 2, &ARCDescs.OperandInfo[62] },  // Inst #74 = G_FREEZE
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #73 = G_BITCAST
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #72 = G_INTTOPTR
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #71 = G_PTRTOINT
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #70 = G_CONCAT_VECTORS
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #69 = G_BUILD_VECTOR_TRUNC
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #68 = G_BUILD_VECTOR
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #67 = G_MERGE_VALUES
  { 4, &ARCDescs.OperandInfo[58] },  // Inst #66 = G_INSERT
  { 2, &ARCDescs.OperandInfo[56] },  // Inst #65 = G_UNMERGE_VALUES
  { 3, &ARCDescs.OperandInfo[53] },  // Inst #64 = G_EXTRACT
  { 2, &ARCDescs.OperandInfo[51] },  // Inst #63 = G_CONSTANT_POOL
  { 2, &ARCDescs.OperandInfo[51] },  // Inst #62 = G_GLOBAL_VALUE
  { 2, &ARCDescs.OperandInfo[51] },  // Inst #61 = G_FRAME_INDEX
  { 1, &ARCDescs.OperandInfo[50] },  // Inst #60 = G_PHI
  { 1, &ARCDescs.OperandInfo[50] },  // Inst #59 = G_IMPLICIT_DEF
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #58 = G_XOR
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #57 = G_OR
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #56 = G_AND
  { 4, &ARCDescs.OperandInfo[46] },  // Inst #55 = G_UDIVREM
  { 4, &ARCDescs.OperandInfo[46] },  // Inst #54 = G_SDIVREM
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #53 = G_UREM
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #52 = G_SREM
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #51 = G_UDIV
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #50 = G_SDIV
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #49 = G_MUL
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #48 = G_SUB
  { 3, &ARCDescs.OperandInfo[43] },  // Inst #47 = G_ADD
  { 3, &ARCDescs.OperandInfo[40] },  // Inst #46 = G_ASSERT_ALIGN
  { 3, &ARCDescs.OperandInfo[40] },  // Inst #45 = G_ASSERT_ZEXT
  { 3, &ARCDescs.OperandInfo[40] },  // Inst #44 = G_ASSERT_SEXT
  { 1, &ARCDescs.OperandInfo[1] },  // Inst #43 = JUMP_TABLE_DEBUG_INFO
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #42 = MEMBARRIER
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #41 = ICALL_BRANCH_FUNNEL
  { 3, &ARCDescs.OperandInfo[37] },  // Inst #40 = PATCHABLE_TYPED_EVENT_CALL
  { 2, &ARCDescs.OperandInfo[35] },  // Inst #39 = PATCHABLE_EVENT_CALL
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #38 = PATCHABLE_TAIL_CALL
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #37 = PATCHABLE_FUNCTION_EXIT
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #36 = PATCHABLE_RET
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #35 = PATCHABLE_FUNCTION_ENTER
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #34 = PATCHABLE_OP
  { 1, &ARCDescs.OperandInfo[0] },  // Inst #33 = FAULTING_OP
  { 2, &ARCDescs.OperandInfo[33] },  // Inst #32 = LOCAL_ESCAPE
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #31 = STATEPOINT
  { 3, &ARCDescs.OperandInfo[30] },  // Inst #30 = PREALLOCATED_ARG
  { 1, &ARCDescs.OperandInfo[1] },  // Inst #29 = PREALLOCATED_SETUP
  { 1, &ARCDescs.OperandInfo[29] },  // Inst #28 = LOAD_STACK_GUARD
  { 6, &ARCDescs.OperandInfo[23] },  // Inst #27 = PATCHPOINT
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #26 = FENTRY_CALL
  { 2, &ARCDescs.OperandInfo[21] },  // Inst #25 = STACKMAP
  { 2, &ARCDescs.OperandInfo[19] },  // Inst #24 = ARITH_FENCE
  { 4, &ARCDescs.OperandInfo[15] },  // Inst #23 = PSEUDO_PROBE
  { 1, &ARCDescs.OperandInfo[1] },  // Inst #22 = LIFETIME_END
  { 1, &ARCDescs.OperandInfo[1] },  // Inst #21 = LIFETIME_START
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #20 = BUNDLE
  { 2, &ARCDescs.OperandInfo[13] },  // Inst #19 = COPY
  { 2, &ARCDescs.OperandInfo[13] },  // Inst #18 = REG_SEQUENCE
  { 1, &ARCDescs.OperandInfo[0] },  // Inst #17 = DBG_LABEL
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #16 = DBG_PHI
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #15 = DBG_INSTR_REF
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #14 = DBG_VALUE_LIST
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #13 = DBG_VALUE
  { 3, &ARCDescs.OperandInfo[2] },  // Inst #12 = COPY_TO_REGCLASS
  { 4, &ARCDescs.OperandInfo[9] },  // Inst #11 = SUBREG_TO_REG
  { 1, &ARCDescs.OperandInfo[0] },  // Inst #10 = IMPLICIT_DEF
  { 4, &ARCDescs.OperandInfo[5] },  // Inst #9 = INSERT_SUBREG
  { 3, &ARCDescs.OperandInfo[2] },  // Inst #8 = EXTRACT_SUBREG
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #7 = KILL
  { 1, &ARCDescs.OperandInfo[1] },  // Inst #6 = ANNOTATION_LABEL
  { 1, &ARCDescs.OperandInfo[1] },  // Inst #5 = GC_LABEL
  { 1, &ARCDescs.OperandInfo[1] },  // Inst #4 = EH_LABEL
  { 1, &ARCDescs.OperandInfo[1] },  // Inst #3 = CFI_INSTRUCTION
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #2 = INLINEASM_BR
  { 0, &ARCDescs.OperandInfo[1] },  // Inst #1 = INLINEASM
  { 1, &ARCDescs.OperandInfo[0] },  // Inst #0 = PHI
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
    /* 140 */ { -1, 0, MCOI_OPERAND_PCREL, 0 }, { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 144 */ { -1, 0, MCOI_OPERAND_PCREL, 0 }, { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 148 */ { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 150 */ { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 153 */ { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { ARC_GPR32RegClassID, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 156 */ { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 160 */ { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 163 */ { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 166 */ { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 169 */ { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 172 */ { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 174 */ { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 176 */ { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 178 */ { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 179 */ { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 181 */ { -1, 0, MCOI_OPERAND_PCREL, 0 }, { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 185 */ { -1, 0, MCOI_OPERAND_PCREL, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 187 */ { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 188 */ { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(1) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 192 */ { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0|(1<<MCOI_Predicate), MCOI_OPERAND_UNKNOWN, 0 },
    /* 196 */ { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0|(1<<MCOI_Predicate), MCOI_OPERAND_UNKNOWN, 0 }, { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 200 */ { -1, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 201 */ { -1, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 203 */ { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { ARC_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
  }, {
    /* 0 */
    /* 0 */ ARC_SP, ARC_SP,
    /* 2 */ ARC_STATUS32,
    /* 3 */ ARC_STATUS32, ARC_STATUS32,
    /* 5 */ ARC_SP, ARC_BLINK,
    /* 7 */ ARC_BLINK, ARC_SP,
  }
};

#endif // GET_INSTRINFO_MC_DESC

#ifdef GET_COMPUTE_FEATURES
#undef GET_COMPUTE_FEATURES

#endif // GET_COMPUTE_FEATURES

#ifdef GET_AVAILABLE_OPCODE_CHECKER
#undef GET_AVAILABLE_OPCODE_CHECKER

#endif // GET_AVAILABLE_OPCODE_CHECKER

#ifdef GET_INSTRMAP_INFO
#undef GET_INSTRMAP_INFO
enum AA {
	AA_PostIncAM
};

// getPostIncOpcode
int getPostIncOpcode(uint16_t Opcode) {
static const uint16_t getPostIncOpcodeTable[][2] = {
  { ARC_LDB_DI_rs9, ARC_LDB_DI_AB_rs9 },
  { ARC_LDB_X_DI_rs9, ARC_LDB_X_DI_AB_rs9 },
  { ARC_LDB_X_rs9, ARC_LDB_X_AB_rs9 },
  { ARC_LDB_rs9, ARC_LDB_AB_rs9 },
  { ARC_LDH_DI_rs9, ARC_LDH_DI_AB_rs9 },
  { ARC_LDH_X_DI_rs9, ARC_LDH_X_DI_AB_rs9 },
  { ARC_LDH_X_rs9, ARC_LDH_X_AB_rs9 },
  { ARC_LDH_rs9, ARC_LDH_AB_rs9 },
  { ARC_LD_DI_rs9, ARC_LD_DI_AB_rs9 },
  { ARC_LD_rs9, ARC_LD_AB_rs9 },
  { ARC_STB_DI_rs9, ARC_STB_DI_AB_rs9 },
  { ARC_STB_rs9, ARC_STB_AB_rs9 },
  { ARC_STH_DI_rs9, ARC_STH_DI_AB_rs9 },
  { ARC_STH_rs9, ARC_STH_AB_rs9 },
  { ARC_ST_DI_rs9, ARC_ST_DI_AB_rs9 },
  { ARC_ST_rs9, ARC_ST_AB_rs9 },
}; // End of getPostIncOpcodeTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 16;
  while (start < end) {
    mid = start + (end - start) / 2;
    if (Opcode == getPostIncOpcodeTable[mid][0]) {
      break;
    }
    if (Opcode < getPostIncOpcodeTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return getPostIncOpcodeTable[mid][1];
}

#endif // GET_INSTRMAP_INFO


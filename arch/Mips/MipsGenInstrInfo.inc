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
    Mips_PHI	= 0,
    Mips_INLINEASM	= 1,
    Mips_INLINEASM_BR	= 2,
    Mips_CFI_INSTRUCTION	= 3,
    Mips_EH_LABEL	= 4,
    Mips_GC_LABEL	= 5,
    Mips_ANNOTATION_LABEL	= 6,
    Mips_KILL	= 7,
    Mips_EXTRACT_SUBREG	= 8,
    Mips_INSERT_SUBREG	= 9,
    Mips_IMPLICIT_DEF	= 10,
    Mips_SUBREG_TO_REG	= 11,
    Mips_COPY_TO_REGCLASS	= 12,
    Mips_DBG_VALUE	= 13,
    Mips_DBG_VALUE_LIST	= 14,
    Mips_DBG_INSTR_REF	= 15,
    Mips_DBG_PHI	= 16,
    Mips_DBG_LABEL	= 17,
    Mips_REG_SEQUENCE	= 18,
    Mips_COPY	= 19,
    Mips_BUNDLE	= 20,
    Mips_LIFETIME_START	= 21,
    Mips_LIFETIME_END	= 22,
    Mips_PSEUDO_PROBE	= 23,
    Mips_ARITH_FENCE	= 24,
    Mips_STACKMAP	= 25,
    Mips_FENTRY_CALL	= 26,
    Mips_PATCHPOINT	= 27,
    Mips_LOAD_STACK_GUARD	= 28,
    Mips_PREALLOCATED_SETUP	= 29,
    Mips_PREALLOCATED_ARG	= 30,
    Mips_STATEPOINT	= 31,
    Mips_LOCAL_ESCAPE	= 32,
    Mips_FAULTING_OP	= 33,
    Mips_PATCHABLE_OP	= 34,
    Mips_PATCHABLE_FUNCTION_ENTER	= 35,
    Mips_PATCHABLE_RET	= 36,
    Mips_PATCHABLE_FUNCTION_EXIT	= 37,
    Mips_PATCHABLE_TAIL_CALL	= 38,
    Mips_PATCHABLE_EVENT_CALL	= 39,
    Mips_PATCHABLE_TYPED_EVENT_CALL	= 40,
    Mips_ICALL_BRANCH_FUNNEL	= 41,
    Mips_MEMBARRIER	= 42,
    Mips_JUMP_TABLE_DEBUG_INFO	= 43,
    Mips_G_ASSERT_SEXT	= 44,
    Mips_G_ASSERT_ZEXT	= 45,
    Mips_G_ASSERT_ALIGN	= 46,
    Mips_G_ADD	= 47,
    Mips_G_SUB	= 48,
    Mips_G_MUL	= 49,
    Mips_G_SDIV	= 50,
    Mips_G_UDIV	= 51,
    Mips_G_SREM	= 52,
    Mips_G_UREM	= 53,
    Mips_G_SDIVREM	= 54,
    Mips_G_UDIVREM	= 55,
    Mips_G_AND	= 56,
    Mips_G_OR	= 57,
    Mips_G_XOR	= 58,
    Mips_G_IMPLICIT_DEF	= 59,
    Mips_G_PHI	= 60,
    Mips_G_FRAME_INDEX	= 61,
    Mips_G_GLOBAL_VALUE	= 62,
    Mips_G_CONSTANT_POOL	= 63,
    Mips_G_EXTRACT	= 64,
    Mips_G_UNMERGE_VALUES	= 65,
    Mips_G_INSERT	= 66,
    Mips_G_MERGE_VALUES	= 67,
    Mips_G_BUILD_VECTOR	= 68,
    Mips_G_BUILD_VECTOR_TRUNC	= 69,
    Mips_G_CONCAT_VECTORS	= 70,
    Mips_G_PTRTOINT	= 71,
    Mips_G_INTTOPTR	= 72,
    Mips_G_BITCAST	= 73,
    Mips_G_FREEZE	= 74,
    Mips_G_CONSTANT_FOLD_BARRIER	= 75,
    Mips_G_INTRINSIC_FPTRUNC_ROUND	= 76,
    Mips_G_INTRINSIC_TRUNC	= 77,
    Mips_G_INTRINSIC_ROUND	= 78,
    Mips_G_INTRINSIC_LRINT	= 79,
    Mips_G_INTRINSIC_ROUNDEVEN	= 80,
    Mips_G_READCYCLECOUNTER	= 81,
    Mips_G_LOAD	= 82,
    Mips_G_SEXTLOAD	= 83,
    Mips_G_ZEXTLOAD	= 84,
    Mips_G_INDEXED_LOAD	= 85,
    Mips_G_INDEXED_SEXTLOAD	= 86,
    Mips_G_INDEXED_ZEXTLOAD	= 87,
    Mips_G_STORE	= 88,
    Mips_G_INDEXED_STORE	= 89,
    Mips_G_ATOMIC_CMPXCHG_WITH_SUCCESS	= 90,
    Mips_G_ATOMIC_CMPXCHG	= 91,
    Mips_G_ATOMICRMW_XCHG	= 92,
    Mips_G_ATOMICRMW_ADD	= 93,
    Mips_G_ATOMICRMW_SUB	= 94,
    Mips_G_ATOMICRMW_AND	= 95,
    Mips_G_ATOMICRMW_NAND	= 96,
    Mips_G_ATOMICRMW_OR	= 97,
    Mips_G_ATOMICRMW_XOR	= 98,
    Mips_G_ATOMICRMW_MAX	= 99,
    Mips_G_ATOMICRMW_MIN	= 100,
    Mips_G_ATOMICRMW_UMAX	= 101,
    Mips_G_ATOMICRMW_UMIN	= 102,
    Mips_G_ATOMICRMW_FADD	= 103,
    Mips_G_ATOMICRMW_FSUB	= 104,
    Mips_G_ATOMICRMW_FMAX	= 105,
    Mips_G_ATOMICRMW_FMIN	= 106,
    Mips_G_ATOMICRMW_UINC_WRAP	= 107,
    Mips_G_ATOMICRMW_UDEC_WRAP	= 108,
    Mips_G_FENCE	= 109,
    Mips_G_PREFETCH	= 110,
    Mips_G_BRCOND	= 111,
    Mips_G_BRINDIRECT	= 112,
    Mips_G_INVOKE_REGION_START	= 113,
    Mips_G_INTRINSIC	= 114,
    Mips_G_INTRINSIC_W_SIDE_EFFECTS	= 115,
    Mips_G_INTRINSIC_CONVERGENT	= 116,
    Mips_G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS	= 117,
    Mips_G_ANYEXT	= 118,
    Mips_G_TRUNC	= 119,
    Mips_G_CONSTANT	= 120,
    Mips_G_FCONSTANT	= 121,
    Mips_G_VASTART	= 122,
    Mips_G_VAARG	= 123,
    Mips_G_SEXT	= 124,
    Mips_G_SEXT_INREG	= 125,
    Mips_G_ZEXT	= 126,
    Mips_G_SHL	= 127,
    Mips_G_LSHR	= 128,
    Mips_G_ASHR	= 129,
    Mips_G_FSHL	= 130,
    Mips_G_FSHR	= 131,
    Mips_G_ROTR	= 132,
    Mips_G_ROTL	= 133,
    Mips_G_ICMP	= 134,
    Mips_G_FCMP	= 135,
    Mips_G_SELECT	= 136,
    Mips_G_UADDO	= 137,
    Mips_G_UADDE	= 138,
    Mips_G_USUBO	= 139,
    Mips_G_USUBE	= 140,
    Mips_G_SADDO	= 141,
    Mips_G_SADDE	= 142,
    Mips_G_SSUBO	= 143,
    Mips_G_SSUBE	= 144,
    Mips_G_UMULO	= 145,
    Mips_G_SMULO	= 146,
    Mips_G_UMULH	= 147,
    Mips_G_SMULH	= 148,
    Mips_G_UADDSAT	= 149,
    Mips_G_SADDSAT	= 150,
    Mips_G_USUBSAT	= 151,
    Mips_G_SSUBSAT	= 152,
    Mips_G_USHLSAT	= 153,
    Mips_G_SSHLSAT	= 154,
    Mips_G_SMULFIX	= 155,
    Mips_G_UMULFIX	= 156,
    Mips_G_SMULFIXSAT	= 157,
    Mips_G_UMULFIXSAT	= 158,
    Mips_G_SDIVFIX	= 159,
    Mips_G_UDIVFIX	= 160,
    Mips_G_SDIVFIXSAT	= 161,
    Mips_G_UDIVFIXSAT	= 162,
    Mips_G_FADD	= 163,
    Mips_G_FSUB	= 164,
    Mips_G_FMUL	= 165,
    Mips_G_FMA	= 166,
    Mips_G_FMAD	= 167,
    Mips_G_FDIV	= 168,
    Mips_G_FREM	= 169,
    Mips_G_FPOW	= 170,
    Mips_G_FPOWI	= 171,
    Mips_G_FEXP	= 172,
    Mips_G_FEXP2	= 173,
    Mips_G_FEXP10	= 174,
    Mips_G_FLOG	= 175,
    Mips_G_FLOG2	= 176,
    Mips_G_FLOG10	= 177,
    Mips_G_FLDEXP	= 178,
    Mips_G_FFREXP	= 179,
    Mips_G_FNEG	= 180,
    Mips_G_FPEXT	= 181,
    Mips_G_FPTRUNC	= 182,
    Mips_G_FPTOSI	= 183,
    Mips_G_FPTOUI	= 184,
    Mips_G_SITOFP	= 185,
    Mips_G_UITOFP	= 186,
    Mips_G_FABS	= 187,
    Mips_G_FCOPYSIGN	= 188,
    Mips_G_IS_FPCLASS	= 189,
    Mips_G_FCANONICALIZE	= 190,
    Mips_G_FMINNUM	= 191,
    Mips_G_FMAXNUM	= 192,
    Mips_G_FMINNUM_IEEE	= 193,
    Mips_G_FMAXNUM_IEEE	= 194,
    Mips_G_FMINIMUM	= 195,
    Mips_G_FMAXIMUM	= 196,
    Mips_G_GET_FPENV	= 197,
    Mips_G_SET_FPENV	= 198,
    Mips_G_RESET_FPENV	= 199,
    Mips_G_GET_FPMODE	= 200,
    Mips_G_SET_FPMODE	= 201,
    Mips_G_RESET_FPMODE	= 202,
    Mips_G_PTR_ADD	= 203,
    Mips_G_PTRMASK	= 204,
    Mips_G_SMIN	= 205,
    Mips_G_SMAX	= 206,
    Mips_G_UMIN	= 207,
    Mips_G_UMAX	= 208,
    Mips_G_ABS	= 209,
    Mips_G_LROUND	= 210,
    Mips_G_LLROUND	= 211,
    Mips_G_BR	= 212,
    Mips_G_BRJT	= 213,
    Mips_G_INSERT_VECTOR_ELT	= 214,
    Mips_G_EXTRACT_VECTOR_ELT	= 215,
    Mips_G_SHUFFLE_VECTOR	= 216,
    Mips_G_CTTZ	= 217,
    Mips_G_CTTZ_ZERO_UNDEF	= 218,
    Mips_G_CTLZ	= 219,
    Mips_G_CTLZ_ZERO_UNDEF	= 220,
    Mips_G_CTPOP	= 221,
    Mips_G_BSWAP	= 222,
    Mips_G_BITREVERSE	= 223,
    Mips_G_FCEIL	= 224,
    Mips_G_FCOS	= 225,
    Mips_G_FSIN	= 226,
    Mips_G_FSQRT	= 227,
    Mips_G_FFLOOR	= 228,
    Mips_G_FRINT	= 229,
    Mips_G_FNEARBYINT	= 230,
    Mips_G_ADDRSPACE_CAST	= 231,
    Mips_G_BLOCK_ADDR	= 232,
    Mips_G_JUMP_TABLE	= 233,
    Mips_G_DYN_STACKALLOC	= 234,
    Mips_G_STACKSAVE	= 235,
    Mips_G_STACKRESTORE	= 236,
    Mips_G_STRICT_FADD	= 237,
    Mips_G_STRICT_FSUB	= 238,
    Mips_G_STRICT_FMUL	= 239,
    Mips_G_STRICT_FDIV	= 240,
    Mips_G_STRICT_FREM	= 241,
    Mips_G_STRICT_FMA	= 242,
    Mips_G_STRICT_FSQRT	= 243,
    Mips_G_STRICT_FLDEXP	= 244,
    Mips_G_READ_REGISTER	= 245,
    Mips_G_WRITE_REGISTER	= 246,
    Mips_G_MEMCPY	= 247,
    Mips_G_MEMCPY_INLINE	= 248,
    Mips_G_MEMMOVE	= 249,
    Mips_G_MEMSET	= 250,
    Mips_G_BZERO	= 251,
    Mips_G_VECREDUCE_SEQ_FADD	= 252,
    Mips_G_VECREDUCE_SEQ_FMUL	= 253,
    Mips_G_VECREDUCE_FADD	= 254,
    Mips_G_VECREDUCE_FMUL	= 255,
    Mips_G_VECREDUCE_FMAX	= 256,
    Mips_G_VECREDUCE_FMIN	= 257,
    Mips_G_VECREDUCE_FMAXIMUM	= 258,
    Mips_G_VECREDUCE_FMINIMUM	= 259,
    Mips_G_VECREDUCE_ADD	= 260,
    Mips_G_VECREDUCE_MUL	= 261,
    Mips_G_VECREDUCE_AND	= 262,
    Mips_G_VECREDUCE_OR	= 263,
    Mips_G_VECREDUCE_XOR	= 264,
    Mips_G_VECREDUCE_SMAX	= 265,
    Mips_G_VECREDUCE_SMIN	= 266,
    Mips_G_VECREDUCE_UMAX	= 267,
    Mips_G_VECREDUCE_UMIN	= 268,
    Mips_G_SBFX	= 269,
    Mips_G_UBFX	= 270,
    Mips_ABSMacro	= 271,
    Mips_ADJCALLSTACKDOWN	= 272,
    Mips_ADJCALLSTACKUP	= 273,
    Mips_AND_V_D_PSEUDO	= 274,
    Mips_AND_V_H_PSEUDO	= 275,
    Mips_AND_V_W_PSEUDO	= 276,
    Mips_ATOMIC_CMP_SWAP_I16	= 277,
    Mips_ATOMIC_CMP_SWAP_I16_POSTRA	= 278,
    Mips_ATOMIC_CMP_SWAP_I32	= 279,
    Mips_ATOMIC_CMP_SWAP_I32_POSTRA	= 280,
    Mips_ATOMIC_CMP_SWAP_I64	= 281,
    Mips_ATOMIC_CMP_SWAP_I64_POSTRA	= 282,
    Mips_ATOMIC_CMP_SWAP_I8	= 283,
    Mips_ATOMIC_CMP_SWAP_I8_POSTRA	= 284,
    Mips_ATOMIC_LOAD_ADD_I16	= 285,
    Mips_ATOMIC_LOAD_ADD_I16_POSTRA	= 286,
    Mips_ATOMIC_LOAD_ADD_I32	= 287,
    Mips_ATOMIC_LOAD_ADD_I32_POSTRA	= 288,
    Mips_ATOMIC_LOAD_ADD_I64	= 289,
    Mips_ATOMIC_LOAD_ADD_I64_POSTRA	= 290,
    Mips_ATOMIC_LOAD_ADD_I8	= 291,
    Mips_ATOMIC_LOAD_ADD_I8_POSTRA	= 292,
    Mips_ATOMIC_LOAD_AND_I16	= 293,
    Mips_ATOMIC_LOAD_AND_I16_POSTRA	= 294,
    Mips_ATOMIC_LOAD_AND_I32	= 295,
    Mips_ATOMIC_LOAD_AND_I32_POSTRA	= 296,
    Mips_ATOMIC_LOAD_AND_I64	= 297,
    Mips_ATOMIC_LOAD_AND_I64_POSTRA	= 298,
    Mips_ATOMIC_LOAD_AND_I8	= 299,
    Mips_ATOMIC_LOAD_AND_I8_POSTRA	= 300,
    Mips_ATOMIC_LOAD_MAX_I16	= 301,
    Mips_ATOMIC_LOAD_MAX_I16_POSTRA	= 302,
    Mips_ATOMIC_LOAD_MAX_I32	= 303,
    Mips_ATOMIC_LOAD_MAX_I32_POSTRA	= 304,
    Mips_ATOMIC_LOAD_MAX_I64	= 305,
    Mips_ATOMIC_LOAD_MAX_I64_POSTRA	= 306,
    Mips_ATOMIC_LOAD_MAX_I8	= 307,
    Mips_ATOMIC_LOAD_MAX_I8_POSTRA	= 308,
    Mips_ATOMIC_LOAD_MIN_I16	= 309,
    Mips_ATOMIC_LOAD_MIN_I16_POSTRA	= 310,
    Mips_ATOMIC_LOAD_MIN_I32	= 311,
    Mips_ATOMIC_LOAD_MIN_I32_POSTRA	= 312,
    Mips_ATOMIC_LOAD_MIN_I64	= 313,
    Mips_ATOMIC_LOAD_MIN_I64_POSTRA	= 314,
    Mips_ATOMIC_LOAD_MIN_I8	= 315,
    Mips_ATOMIC_LOAD_MIN_I8_POSTRA	= 316,
    Mips_ATOMIC_LOAD_NAND_I16	= 317,
    Mips_ATOMIC_LOAD_NAND_I16_POSTRA	= 318,
    Mips_ATOMIC_LOAD_NAND_I32	= 319,
    Mips_ATOMIC_LOAD_NAND_I32_POSTRA	= 320,
    Mips_ATOMIC_LOAD_NAND_I64	= 321,
    Mips_ATOMIC_LOAD_NAND_I64_POSTRA	= 322,
    Mips_ATOMIC_LOAD_NAND_I8	= 323,
    Mips_ATOMIC_LOAD_NAND_I8_POSTRA	= 324,
    Mips_ATOMIC_LOAD_OR_I16	= 325,
    Mips_ATOMIC_LOAD_OR_I16_POSTRA	= 326,
    Mips_ATOMIC_LOAD_OR_I32	= 327,
    Mips_ATOMIC_LOAD_OR_I32_POSTRA	= 328,
    Mips_ATOMIC_LOAD_OR_I64	= 329,
    Mips_ATOMIC_LOAD_OR_I64_POSTRA	= 330,
    Mips_ATOMIC_LOAD_OR_I8	= 331,
    Mips_ATOMIC_LOAD_OR_I8_POSTRA	= 332,
    Mips_ATOMIC_LOAD_SUB_I16	= 333,
    Mips_ATOMIC_LOAD_SUB_I16_POSTRA	= 334,
    Mips_ATOMIC_LOAD_SUB_I32	= 335,
    Mips_ATOMIC_LOAD_SUB_I32_POSTRA	= 336,
    Mips_ATOMIC_LOAD_SUB_I64	= 337,
    Mips_ATOMIC_LOAD_SUB_I64_POSTRA	= 338,
    Mips_ATOMIC_LOAD_SUB_I8	= 339,
    Mips_ATOMIC_LOAD_SUB_I8_POSTRA	= 340,
    Mips_ATOMIC_LOAD_UMAX_I16	= 341,
    Mips_ATOMIC_LOAD_UMAX_I16_POSTRA	= 342,
    Mips_ATOMIC_LOAD_UMAX_I32	= 343,
    Mips_ATOMIC_LOAD_UMAX_I32_POSTRA	= 344,
    Mips_ATOMIC_LOAD_UMAX_I64	= 345,
    Mips_ATOMIC_LOAD_UMAX_I64_POSTRA	= 346,
    Mips_ATOMIC_LOAD_UMAX_I8	= 347,
    Mips_ATOMIC_LOAD_UMAX_I8_POSTRA	= 348,
    Mips_ATOMIC_LOAD_UMIN_I16	= 349,
    Mips_ATOMIC_LOAD_UMIN_I16_POSTRA	= 350,
    Mips_ATOMIC_LOAD_UMIN_I32	= 351,
    Mips_ATOMIC_LOAD_UMIN_I32_POSTRA	= 352,
    Mips_ATOMIC_LOAD_UMIN_I64	= 353,
    Mips_ATOMIC_LOAD_UMIN_I64_POSTRA	= 354,
    Mips_ATOMIC_LOAD_UMIN_I8	= 355,
    Mips_ATOMIC_LOAD_UMIN_I8_POSTRA	= 356,
    Mips_ATOMIC_LOAD_XOR_I16	= 357,
    Mips_ATOMIC_LOAD_XOR_I16_POSTRA	= 358,
    Mips_ATOMIC_LOAD_XOR_I32	= 359,
    Mips_ATOMIC_LOAD_XOR_I32_POSTRA	= 360,
    Mips_ATOMIC_LOAD_XOR_I64	= 361,
    Mips_ATOMIC_LOAD_XOR_I64_POSTRA	= 362,
    Mips_ATOMIC_LOAD_XOR_I8	= 363,
    Mips_ATOMIC_LOAD_XOR_I8_POSTRA	= 364,
    Mips_ATOMIC_SWAP_I16	= 365,
    Mips_ATOMIC_SWAP_I16_POSTRA	= 366,
    Mips_ATOMIC_SWAP_I32	= 367,
    Mips_ATOMIC_SWAP_I32_POSTRA	= 368,
    Mips_ATOMIC_SWAP_I64	= 369,
    Mips_ATOMIC_SWAP_I64_POSTRA	= 370,
    Mips_ATOMIC_SWAP_I8	= 371,
    Mips_ATOMIC_SWAP_I8_POSTRA	= 372,
    Mips_B	= 373,
    Mips_BAL_BR	= 374,
    Mips_BAL_BR_MM	= 375,
    Mips_BEQLImmMacro	= 376,
    Mips_BGE	= 377,
    Mips_BGEImmMacro	= 378,
    Mips_BGEL	= 379,
    Mips_BGELImmMacro	= 380,
    Mips_BGEU	= 381,
    Mips_BGEUImmMacro	= 382,
    Mips_BGEUL	= 383,
    Mips_BGEULImmMacro	= 384,
    Mips_BGT	= 385,
    Mips_BGTImmMacro	= 386,
    Mips_BGTL	= 387,
    Mips_BGTLImmMacro	= 388,
    Mips_BGTU	= 389,
    Mips_BGTUImmMacro	= 390,
    Mips_BGTUL	= 391,
    Mips_BGTULImmMacro	= 392,
    Mips_BLE	= 393,
    Mips_BLEImmMacro	= 394,
    Mips_BLEL	= 395,
    Mips_BLELImmMacro	= 396,
    Mips_BLEU	= 397,
    Mips_BLEUImmMacro	= 398,
    Mips_BLEUL	= 399,
    Mips_BLEULImmMacro	= 400,
    Mips_BLT	= 401,
    Mips_BLTImmMacro	= 402,
    Mips_BLTL	= 403,
    Mips_BLTLImmMacro	= 404,
    Mips_BLTU	= 405,
    Mips_BLTUImmMacro	= 406,
    Mips_BLTUL	= 407,
    Mips_BLTULImmMacro	= 408,
    Mips_BNELImmMacro	= 409,
    Mips_BPOSGE32_PSEUDO	= 410,
    Mips_BSEL_D_PSEUDO	= 411,
    Mips_BSEL_FD_PSEUDO	= 412,
    Mips_BSEL_FW_PSEUDO	= 413,
    Mips_BSEL_H_PSEUDO	= 414,
    Mips_BSEL_W_PSEUDO	= 415,
    Mips_B_MM	= 416,
    Mips_B_MMR6_Pseudo	= 417,
    Mips_B_MM_Pseudo	= 418,
    Mips_BeqImm	= 419,
    Mips_BneImm	= 420,
    Mips_BteqzT8CmpX16	= 421,
    Mips_BteqzT8CmpiX16	= 422,
    Mips_BteqzT8SltX16	= 423,
    Mips_BteqzT8SltiX16	= 424,
    Mips_BteqzT8SltiuX16	= 425,
    Mips_BteqzT8SltuX16	= 426,
    Mips_BtnezT8CmpX16	= 427,
    Mips_BtnezT8CmpiX16	= 428,
    Mips_BtnezT8SltX16	= 429,
    Mips_BtnezT8SltiX16	= 430,
    Mips_BtnezT8SltiuX16	= 431,
    Mips_BtnezT8SltuX16	= 432,
    Mips_BuildPairF64	= 433,
    Mips_BuildPairF64_64	= 434,
    Mips_CFTC1	= 435,
    Mips_CONSTPOOL_ENTRY	= 436,
    Mips_COPY_FD_PSEUDO	= 437,
    Mips_COPY_FW_PSEUDO	= 438,
    Mips_CTTC1	= 439,
    Mips_Constant32	= 440,
    Mips_DMULImmMacro	= 441,
    Mips_DMULMacro	= 442,
    Mips_DMULOMacro	= 443,
    Mips_DMULOUMacro	= 444,
    Mips_DROL	= 445,
    Mips_DROLImm	= 446,
    Mips_DROR	= 447,
    Mips_DRORImm	= 448,
    Mips_DSDivIMacro	= 449,
    Mips_DSDivMacro	= 450,
    Mips_DSRemIMacro	= 451,
    Mips_DSRemMacro	= 452,
    Mips_DUDivIMacro	= 453,
    Mips_DUDivMacro	= 454,
    Mips_DURemIMacro	= 455,
    Mips_DURemMacro	= 456,
    Mips_ERet	= 457,
    Mips_ExtractElementF64	= 458,
    Mips_ExtractElementF64_64	= 459,
    Mips_FABS_D	= 460,
    Mips_FABS_W	= 461,
    Mips_FEXP2_D_1_PSEUDO	= 462,
    Mips_FEXP2_W_1_PSEUDO	= 463,
    Mips_FILL_FD_PSEUDO	= 464,
    Mips_FILL_FW_PSEUDO	= 465,
    Mips_GotPrologue16	= 466,
    Mips_INSERT_B_VIDX64_PSEUDO	= 467,
    Mips_INSERT_B_VIDX_PSEUDO	= 468,
    Mips_INSERT_D_VIDX64_PSEUDO	= 469,
    Mips_INSERT_D_VIDX_PSEUDO	= 470,
    Mips_INSERT_FD_PSEUDO	= 471,
    Mips_INSERT_FD_VIDX64_PSEUDO	= 472,
    Mips_INSERT_FD_VIDX_PSEUDO	= 473,
    Mips_INSERT_FW_PSEUDO	= 474,
    Mips_INSERT_FW_VIDX64_PSEUDO	= 475,
    Mips_INSERT_FW_VIDX_PSEUDO	= 476,
    Mips_INSERT_H_VIDX64_PSEUDO	= 477,
    Mips_INSERT_H_VIDX_PSEUDO	= 478,
    Mips_INSERT_W_VIDX64_PSEUDO	= 479,
    Mips_INSERT_W_VIDX_PSEUDO	= 480,
    Mips_JALR64Pseudo	= 481,
    Mips_JALRHB64Pseudo	= 482,
    Mips_JALRHBPseudo	= 483,
    Mips_JALRPseudo	= 484,
    Mips_JAL_MMR6	= 485,
    Mips_JalOneReg	= 486,
    Mips_JalTwoReg	= 487,
    Mips_LDMacro	= 488,
    Mips_LDR_D	= 489,
    Mips_LDR_W	= 490,
    Mips_LD_F16	= 491,
    Mips_LOAD_ACC128	= 492,
    Mips_LOAD_ACC64	= 493,
    Mips_LOAD_ACC64DSP	= 494,
    Mips_LOAD_CCOND_DSP	= 495,
    Mips_LONG_BRANCH_ADDiu	= 496,
    Mips_LONG_BRANCH_ADDiu2Op	= 497,
    Mips_LONG_BRANCH_DADDiu	= 498,
    Mips_LONG_BRANCH_DADDiu2Op	= 499,
    Mips_LONG_BRANCH_LUi	= 500,
    Mips_LONG_BRANCH_LUi2Op	= 501,
    Mips_LONG_BRANCH_LUi2Op_64	= 502,
    Mips_LWM_MM	= 503,
    Mips_LoadAddrImm32	= 504,
    Mips_LoadAddrImm64	= 505,
    Mips_LoadAddrReg32	= 506,
    Mips_LoadAddrReg64	= 507,
    Mips_LoadImm32	= 508,
    Mips_LoadImm64	= 509,
    Mips_LoadImmDoubleFGR	= 510,
    Mips_LoadImmDoubleFGR_32	= 511,
    Mips_LoadImmDoubleGPR	= 512,
    Mips_LoadImmSingleFGR	= 513,
    Mips_LoadImmSingleGPR	= 514,
    Mips_LwConstant32	= 515,
    Mips_MFTACX	= 516,
    Mips_MFTC0	= 517,
    Mips_MFTC1	= 518,
    Mips_MFTDSP	= 519,
    Mips_MFTGPR	= 520,
    Mips_MFTHC1	= 521,
    Mips_MFTHI	= 522,
    Mips_MFTLO	= 523,
    Mips_MIPSeh_return32	= 524,
    Mips_MIPSeh_return64	= 525,
    Mips_MSA_FP_EXTEND_D_PSEUDO	= 526,
    Mips_MSA_FP_EXTEND_W_PSEUDO	= 527,
    Mips_MSA_FP_ROUND_D_PSEUDO	= 528,
    Mips_MSA_FP_ROUND_W_PSEUDO	= 529,
    Mips_MTTACX	= 530,
    Mips_MTTC0	= 531,
    Mips_MTTC1	= 532,
    Mips_MTTDSP	= 533,
    Mips_MTTGPR	= 534,
    Mips_MTTHC1	= 535,
    Mips_MTTHI	= 536,
    Mips_MTTLO	= 537,
    Mips_MULImmMacro	= 538,
    Mips_MULOMacro	= 539,
    Mips_MULOUMacro	= 540,
    Mips_MultRxRy16	= 541,
    Mips_MultRxRyRz16	= 542,
    Mips_MultuRxRy16	= 543,
    Mips_MultuRxRyRz16	= 544,
    Mips_NOP	= 545,
    Mips_NORImm	= 546,
    Mips_NORImm64	= 547,
    Mips_NOR_V_D_PSEUDO	= 548,
    Mips_NOR_V_H_PSEUDO	= 549,
    Mips_NOR_V_W_PSEUDO	= 550,
    Mips_OR_V_D_PSEUDO	= 551,
    Mips_OR_V_H_PSEUDO	= 552,
    Mips_OR_V_W_PSEUDO	= 553,
    Mips_PseudoCMPU_EQ_QB	= 554,
    Mips_PseudoCMPU_LE_QB	= 555,
    Mips_PseudoCMPU_LT_QB	= 556,
    Mips_PseudoCMP_EQ_PH	= 557,
    Mips_PseudoCMP_LE_PH	= 558,
    Mips_PseudoCMP_LT_PH	= 559,
    Mips_PseudoCVT_D32_W	= 560,
    Mips_PseudoCVT_D64_L	= 561,
    Mips_PseudoCVT_D64_W	= 562,
    Mips_PseudoCVT_S_L	= 563,
    Mips_PseudoCVT_S_W	= 564,
    Mips_PseudoDMULT	= 565,
    Mips_PseudoDMULTu	= 566,
    Mips_PseudoDSDIV	= 567,
    Mips_PseudoDUDIV	= 568,
    Mips_PseudoD_SELECT_I	= 569,
    Mips_PseudoD_SELECT_I64	= 570,
    Mips_PseudoIndirectBranch	= 571,
    Mips_PseudoIndirectBranch64	= 572,
    Mips_PseudoIndirectBranch64R6	= 573,
    Mips_PseudoIndirectBranchR6	= 574,
    Mips_PseudoIndirectBranch_MM	= 575,
    Mips_PseudoIndirectBranch_MMR6	= 576,
    Mips_PseudoIndirectHazardBranch	= 577,
    Mips_PseudoIndirectHazardBranch64	= 578,
    Mips_PseudoIndrectHazardBranch64R6	= 579,
    Mips_PseudoIndrectHazardBranchR6	= 580,
    Mips_PseudoMADD	= 581,
    Mips_PseudoMADDU	= 582,
    Mips_PseudoMADDU_MM	= 583,
    Mips_PseudoMADD_MM	= 584,
    Mips_PseudoMFHI	= 585,
    Mips_PseudoMFHI64	= 586,
    Mips_PseudoMFHI_MM	= 587,
    Mips_PseudoMFLO	= 588,
    Mips_PseudoMFLO64	= 589,
    Mips_PseudoMFLO_MM	= 590,
    Mips_PseudoMSUB	= 591,
    Mips_PseudoMSUBU	= 592,
    Mips_PseudoMSUBU_MM	= 593,
    Mips_PseudoMSUB_MM	= 594,
    Mips_PseudoMTLOHI	= 595,
    Mips_PseudoMTLOHI64	= 596,
    Mips_PseudoMTLOHI_DSP	= 597,
    Mips_PseudoMTLOHI_MM	= 598,
    Mips_PseudoMULT	= 599,
    Mips_PseudoMULT_MM	= 600,
    Mips_PseudoMULTu	= 601,
    Mips_PseudoMULTu_MM	= 602,
    Mips_PseudoPICK_PH	= 603,
    Mips_PseudoPICK_QB	= 604,
    Mips_PseudoReturn	= 605,
    Mips_PseudoReturn64	= 606,
    Mips_PseudoSDIV	= 607,
    Mips_PseudoSELECTFP_F_D32	= 608,
    Mips_PseudoSELECTFP_F_D64	= 609,
    Mips_PseudoSELECTFP_F_I	= 610,
    Mips_PseudoSELECTFP_F_I64	= 611,
    Mips_PseudoSELECTFP_F_S	= 612,
    Mips_PseudoSELECTFP_T_D32	= 613,
    Mips_PseudoSELECTFP_T_D64	= 614,
    Mips_PseudoSELECTFP_T_I	= 615,
    Mips_PseudoSELECTFP_T_I64	= 616,
    Mips_PseudoSELECTFP_T_S	= 617,
    Mips_PseudoSELECT_D32	= 618,
    Mips_PseudoSELECT_D64	= 619,
    Mips_PseudoSELECT_I	= 620,
    Mips_PseudoSELECT_I64	= 621,
    Mips_PseudoSELECT_S	= 622,
    Mips_PseudoTRUNC_W_D	= 623,
    Mips_PseudoTRUNC_W_D32	= 624,
    Mips_PseudoTRUNC_W_S	= 625,
    Mips_PseudoUDIV	= 626,
    Mips_ROL	= 627,
    Mips_ROLImm	= 628,
    Mips_ROR	= 629,
    Mips_RORImm	= 630,
    Mips_RetRA	= 631,
    Mips_RetRA16	= 632,
    Mips_SDC1_M1	= 633,
    Mips_SDIV_MM_Pseudo	= 634,
    Mips_SDMacro	= 635,
    Mips_SDivIMacro	= 636,
    Mips_SDivMacro	= 637,
    Mips_SEQIMacro	= 638,
    Mips_SEQMacro	= 639,
    Mips_SGE	= 640,
    Mips_SGEImm	= 641,
    Mips_SGEImm64	= 642,
    Mips_SGEU	= 643,
    Mips_SGEUImm	= 644,
    Mips_SGEUImm64	= 645,
    Mips_SGTImm	= 646,
    Mips_SGTImm64	= 647,
    Mips_SGTUImm	= 648,
    Mips_SGTUImm64	= 649,
    Mips_SLE	= 650,
    Mips_SLEImm	= 651,
    Mips_SLEImm64	= 652,
    Mips_SLEU	= 653,
    Mips_SLEUImm	= 654,
    Mips_SLEUImm64	= 655,
    Mips_SLTImm64	= 656,
    Mips_SLTUImm64	= 657,
    Mips_SNEIMacro	= 658,
    Mips_SNEMacro	= 659,
    Mips_SNZ_B_PSEUDO	= 660,
    Mips_SNZ_D_PSEUDO	= 661,
    Mips_SNZ_H_PSEUDO	= 662,
    Mips_SNZ_V_PSEUDO	= 663,
    Mips_SNZ_W_PSEUDO	= 664,
    Mips_SRemIMacro	= 665,
    Mips_SRemMacro	= 666,
    Mips_STORE_ACC128	= 667,
    Mips_STORE_ACC64	= 668,
    Mips_STORE_ACC64DSP	= 669,
    Mips_STORE_CCOND_DSP	= 670,
    Mips_STR_D	= 671,
    Mips_STR_W	= 672,
    Mips_ST_F16	= 673,
    Mips_SWM_MM	= 674,
    Mips_SZ_B_PSEUDO	= 675,
    Mips_SZ_D_PSEUDO	= 676,
    Mips_SZ_H_PSEUDO	= 677,
    Mips_SZ_V_PSEUDO	= 678,
    Mips_SZ_W_PSEUDO	= 679,
    Mips_SaaAddr	= 680,
    Mips_SaadAddr	= 681,
    Mips_SelBeqZ	= 682,
    Mips_SelBneZ	= 683,
    Mips_SelTBteqZCmp	= 684,
    Mips_SelTBteqZCmpi	= 685,
    Mips_SelTBteqZSlt	= 686,
    Mips_SelTBteqZSlti	= 687,
    Mips_SelTBteqZSltiu	= 688,
    Mips_SelTBteqZSltu	= 689,
    Mips_SelTBtneZCmp	= 690,
    Mips_SelTBtneZCmpi	= 691,
    Mips_SelTBtneZSlt	= 692,
    Mips_SelTBtneZSlti	= 693,
    Mips_SelTBtneZSltiu	= 694,
    Mips_SelTBtneZSltu	= 695,
    Mips_SltCCRxRy16	= 696,
    Mips_SltiCCRxImmX16	= 697,
    Mips_SltiuCCRxImmX16	= 698,
    Mips_SltuCCRxRy16	= 699,
    Mips_SltuRxRyRz16	= 700,
    Mips_TAILCALL	= 701,
    Mips_TAILCALL64R6REG	= 702,
    Mips_TAILCALLHB64R6REG	= 703,
    Mips_TAILCALLHBR6REG	= 704,
    Mips_TAILCALLR6REG	= 705,
    Mips_TAILCALLREG	= 706,
    Mips_TAILCALLREG64	= 707,
    Mips_TAILCALLREGHB	= 708,
    Mips_TAILCALLREGHB64	= 709,
    Mips_TAILCALLREG_MM	= 710,
    Mips_TAILCALLREG_MMR6	= 711,
    Mips_TAILCALL_MM	= 712,
    Mips_TAILCALL_MMR6	= 713,
    Mips_TRAP	= 714,
    Mips_TRAP_MM	= 715,
    Mips_UDIV_MM_Pseudo	= 716,
    Mips_UDivIMacro	= 717,
    Mips_UDivMacro	= 718,
    Mips_URemIMacro	= 719,
    Mips_URemMacro	= 720,
    Mips_Ulh	= 721,
    Mips_Ulhu	= 722,
    Mips_Ulw	= 723,
    Mips_Ush	= 724,
    Mips_Usw	= 725,
    Mips_XOR_V_D_PSEUDO	= 726,
    Mips_XOR_V_H_PSEUDO	= 727,
    Mips_XOR_V_W_PSEUDO	= 728,
    Mips_ABSQ_S_PH	= 729,
    Mips_ABSQ_S_PH_MM	= 730,
    Mips_ABSQ_S_QB	= 731,
    Mips_ABSQ_S_QB_MMR2	= 732,
    Mips_ABSQ_S_W	= 733,
    Mips_ABSQ_S_W_MM	= 734,
    Mips_ADD	= 735,
    Mips_ADDIUPC	= 736,
    Mips_ADDIUPC_MM	= 737,
    Mips_ADDIUPC_MMR6	= 738,
    Mips_ADDIUR1SP_MM	= 739,
    Mips_ADDIUR2_MM	= 740,
    Mips_ADDIUS5_MM	= 741,
    Mips_ADDIUSP_MM	= 742,
    Mips_ADDIU_MMR6	= 743,
    Mips_ADDQH_PH	= 744,
    Mips_ADDQH_PH_MMR2	= 745,
    Mips_ADDQH_R_PH	= 746,
    Mips_ADDQH_R_PH_MMR2	= 747,
    Mips_ADDQH_R_W	= 748,
    Mips_ADDQH_R_W_MMR2	= 749,
    Mips_ADDQH_W	= 750,
    Mips_ADDQH_W_MMR2	= 751,
    Mips_ADDQ_PH	= 752,
    Mips_ADDQ_PH_MM	= 753,
    Mips_ADDQ_S_PH	= 754,
    Mips_ADDQ_S_PH_MM	= 755,
    Mips_ADDQ_S_W	= 756,
    Mips_ADDQ_S_W_MM	= 757,
    Mips_ADDR_PS64	= 758,
    Mips_ADDSC	= 759,
    Mips_ADDSC_MM	= 760,
    Mips_ADDS_A_B	= 761,
    Mips_ADDS_A_D	= 762,
    Mips_ADDS_A_H	= 763,
    Mips_ADDS_A_W	= 764,
    Mips_ADDS_S_B	= 765,
    Mips_ADDS_S_D	= 766,
    Mips_ADDS_S_H	= 767,
    Mips_ADDS_S_W	= 768,
    Mips_ADDS_U_B	= 769,
    Mips_ADDS_U_D	= 770,
    Mips_ADDS_U_H	= 771,
    Mips_ADDS_U_W	= 772,
    Mips_ADDU16_MM	= 773,
    Mips_ADDU16_MMR6	= 774,
    Mips_ADDUH_QB	= 775,
    Mips_ADDUH_QB_MMR2	= 776,
    Mips_ADDUH_R_QB	= 777,
    Mips_ADDUH_R_QB_MMR2	= 778,
    Mips_ADDU_MMR6	= 779,
    Mips_ADDU_PH	= 780,
    Mips_ADDU_PH_MMR2	= 781,
    Mips_ADDU_QB	= 782,
    Mips_ADDU_QB_MM	= 783,
    Mips_ADDU_S_PH	= 784,
    Mips_ADDU_S_PH_MMR2	= 785,
    Mips_ADDU_S_QB	= 786,
    Mips_ADDU_S_QB_MM	= 787,
    Mips_ADDVI_B	= 788,
    Mips_ADDVI_D	= 789,
    Mips_ADDVI_H	= 790,
    Mips_ADDVI_W	= 791,
    Mips_ADDV_B	= 792,
    Mips_ADDV_D	= 793,
    Mips_ADDV_H	= 794,
    Mips_ADDV_W	= 795,
    Mips_ADDWC	= 796,
    Mips_ADDWC_MM	= 797,
    Mips_ADD_A_B	= 798,
    Mips_ADD_A_D	= 799,
    Mips_ADD_A_H	= 800,
    Mips_ADD_A_W	= 801,
    Mips_ADD_MM	= 802,
    Mips_ADD_MMR6	= 803,
    Mips_ADDi	= 804,
    Mips_ADDi_MM	= 805,
    Mips_ADDiu	= 806,
    Mips_ADDiu_MM	= 807,
    Mips_ADDu	= 808,
    Mips_ADDu_MM	= 809,
    Mips_ALIGN	= 810,
    Mips_ALIGN_MMR6	= 811,
    Mips_ALUIPC	= 812,
    Mips_ALUIPC_MMR6	= 813,
    Mips_AND	= 814,
    Mips_AND16_MM	= 815,
    Mips_AND16_MMR6	= 816,
    Mips_AND64	= 817,
    Mips_ANDI16_MM	= 818,
    Mips_ANDI16_MMR6	= 819,
    Mips_ANDI_B	= 820,
    Mips_ANDI_MMR6	= 821,
    Mips_AND_MM	= 822,
    Mips_AND_MMR6	= 823,
    Mips_AND_V	= 824,
    Mips_ANDi	= 825,
    Mips_ANDi64	= 826,
    Mips_ANDi_MM	= 827,
    Mips_APPEND	= 828,
    Mips_APPEND_MMR2	= 829,
    Mips_ASUB_S_B	= 830,
    Mips_ASUB_S_D	= 831,
    Mips_ASUB_S_H	= 832,
    Mips_ASUB_S_W	= 833,
    Mips_ASUB_U_B	= 834,
    Mips_ASUB_U_D	= 835,
    Mips_ASUB_U_H	= 836,
    Mips_ASUB_U_W	= 837,
    Mips_AUI	= 838,
    Mips_AUIPC	= 839,
    Mips_AUIPC_MMR6	= 840,
    Mips_AUI_MMR6	= 841,
    Mips_AVER_S_B	= 842,
    Mips_AVER_S_D	= 843,
    Mips_AVER_S_H	= 844,
    Mips_AVER_S_W	= 845,
    Mips_AVER_U_B	= 846,
    Mips_AVER_U_D	= 847,
    Mips_AVER_U_H	= 848,
    Mips_AVER_U_W	= 849,
    Mips_AVE_S_B	= 850,
    Mips_AVE_S_D	= 851,
    Mips_AVE_S_H	= 852,
    Mips_AVE_S_W	= 853,
    Mips_AVE_U_B	= 854,
    Mips_AVE_U_D	= 855,
    Mips_AVE_U_H	= 856,
    Mips_AVE_U_W	= 857,
    Mips_AddiuRxImmX16	= 858,
    Mips_AddiuRxPcImmX16	= 859,
    Mips_AddiuRxRxImm16	= 860,
    Mips_AddiuRxRxImmX16	= 861,
    Mips_AddiuRxRyOffMemX16	= 862,
    Mips_AddiuSpImm16	= 863,
    Mips_AddiuSpImmX16	= 864,
    Mips_AdduRxRyRz16	= 865,
    Mips_AndRxRxRy16	= 866,
    Mips_B16_MM	= 867,
    Mips_BADDu	= 868,
    Mips_BAL	= 869,
    Mips_BALC	= 870,
    Mips_BALC_MMR6	= 871,
    Mips_BALIGN	= 872,
    Mips_BALIGN_MMR2	= 873,
    Mips_BBIT0	= 874,
    Mips_BBIT032	= 875,
    Mips_BBIT1	= 876,
    Mips_BBIT132	= 877,
    Mips_BC	= 878,
    Mips_BC16_MMR6	= 879,
    Mips_BC1EQZ	= 880,
    Mips_BC1EQZC_MMR6	= 881,
    Mips_BC1F	= 882,
    Mips_BC1FL	= 883,
    Mips_BC1F_MM	= 884,
    Mips_BC1NEZ	= 885,
    Mips_BC1NEZC_MMR6	= 886,
    Mips_BC1T	= 887,
    Mips_BC1TL	= 888,
    Mips_BC1T_MM	= 889,
    Mips_BC2EQZ	= 890,
    Mips_BC2EQZC_MMR6	= 891,
    Mips_BC2NEZ	= 892,
    Mips_BC2NEZC_MMR6	= 893,
    Mips_BCLRI_B	= 894,
    Mips_BCLRI_D	= 895,
    Mips_BCLRI_H	= 896,
    Mips_BCLRI_W	= 897,
    Mips_BCLR_B	= 898,
    Mips_BCLR_D	= 899,
    Mips_BCLR_H	= 900,
    Mips_BCLR_W	= 901,
    Mips_BC_MMR6	= 902,
    Mips_BEQ	= 903,
    Mips_BEQ64	= 904,
    Mips_BEQC	= 905,
    Mips_BEQC64	= 906,
    Mips_BEQC_MMR6	= 907,
    Mips_BEQL	= 908,
    Mips_BEQZ16_MM	= 909,
    Mips_BEQZALC	= 910,
    Mips_BEQZALC_MMR6	= 911,
    Mips_BEQZC	= 912,
    Mips_BEQZC16_MMR6	= 913,
    Mips_BEQZC64	= 914,
    Mips_BEQZC_MM	= 915,
    Mips_BEQZC_MMR6	= 916,
    Mips_BEQ_MM	= 917,
    Mips_BGEC	= 918,
    Mips_BGEC64	= 919,
    Mips_BGEC_MMR6	= 920,
    Mips_BGEUC	= 921,
    Mips_BGEUC64	= 922,
    Mips_BGEUC_MMR6	= 923,
    Mips_BGEZ	= 924,
    Mips_BGEZ64	= 925,
    Mips_BGEZAL	= 926,
    Mips_BGEZALC	= 927,
    Mips_BGEZALC_MMR6	= 928,
    Mips_BGEZALL	= 929,
    Mips_BGEZALS_MM	= 930,
    Mips_BGEZAL_MM	= 931,
    Mips_BGEZC	= 932,
    Mips_BGEZC64	= 933,
    Mips_BGEZC_MMR6	= 934,
    Mips_BGEZL	= 935,
    Mips_BGEZ_MM	= 936,
    Mips_BGTZ	= 937,
    Mips_BGTZ64	= 938,
    Mips_BGTZALC	= 939,
    Mips_BGTZALC_MMR6	= 940,
    Mips_BGTZC	= 941,
    Mips_BGTZC64	= 942,
    Mips_BGTZC_MMR6	= 943,
    Mips_BGTZL	= 944,
    Mips_BGTZ_MM	= 945,
    Mips_BINSLI_B	= 946,
    Mips_BINSLI_D	= 947,
    Mips_BINSLI_H	= 948,
    Mips_BINSLI_W	= 949,
    Mips_BINSL_B	= 950,
    Mips_BINSL_D	= 951,
    Mips_BINSL_H	= 952,
    Mips_BINSL_W	= 953,
    Mips_BINSRI_B	= 954,
    Mips_BINSRI_D	= 955,
    Mips_BINSRI_H	= 956,
    Mips_BINSRI_W	= 957,
    Mips_BINSR_B	= 958,
    Mips_BINSR_D	= 959,
    Mips_BINSR_H	= 960,
    Mips_BINSR_W	= 961,
    Mips_BITREV	= 962,
    Mips_BITREV_MM	= 963,
    Mips_BITSWAP	= 964,
    Mips_BITSWAP_MMR6	= 965,
    Mips_BLEZ	= 966,
    Mips_BLEZ64	= 967,
    Mips_BLEZALC	= 968,
    Mips_BLEZALC_MMR6	= 969,
    Mips_BLEZC	= 970,
    Mips_BLEZC64	= 971,
    Mips_BLEZC_MMR6	= 972,
    Mips_BLEZL	= 973,
    Mips_BLEZ_MM	= 974,
    Mips_BLTC	= 975,
    Mips_BLTC64	= 976,
    Mips_BLTC_MMR6	= 977,
    Mips_BLTUC	= 978,
    Mips_BLTUC64	= 979,
    Mips_BLTUC_MMR6	= 980,
    Mips_BLTZ	= 981,
    Mips_BLTZ64	= 982,
    Mips_BLTZAL	= 983,
    Mips_BLTZALC	= 984,
    Mips_BLTZALC_MMR6	= 985,
    Mips_BLTZALL	= 986,
    Mips_BLTZALS_MM	= 987,
    Mips_BLTZAL_MM	= 988,
    Mips_BLTZC	= 989,
    Mips_BLTZC64	= 990,
    Mips_BLTZC_MMR6	= 991,
    Mips_BLTZL	= 992,
    Mips_BLTZ_MM	= 993,
    Mips_BMNZI_B	= 994,
    Mips_BMNZ_V	= 995,
    Mips_BMZI_B	= 996,
    Mips_BMZ_V	= 997,
    Mips_BNE	= 998,
    Mips_BNE64	= 999,
    Mips_BNEC	= 1000,
    Mips_BNEC64	= 1001,
    Mips_BNEC_MMR6	= 1002,
    Mips_BNEGI_B	= 1003,
    Mips_BNEGI_D	= 1004,
    Mips_BNEGI_H	= 1005,
    Mips_BNEGI_W	= 1006,
    Mips_BNEG_B	= 1007,
    Mips_BNEG_D	= 1008,
    Mips_BNEG_H	= 1009,
    Mips_BNEG_W	= 1010,
    Mips_BNEL	= 1011,
    Mips_BNEZ16_MM	= 1012,
    Mips_BNEZALC	= 1013,
    Mips_BNEZALC_MMR6	= 1014,
    Mips_BNEZC	= 1015,
    Mips_BNEZC16_MMR6	= 1016,
    Mips_BNEZC64	= 1017,
    Mips_BNEZC_MM	= 1018,
    Mips_BNEZC_MMR6	= 1019,
    Mips_BNE_MM	= 1020,
    Mips_BNVC	= 1021,
    Mips_BNVC_MMR6	= 1022,
    Mips_BNZ_B	= 1023,
    Mips_BNZ_D	= 1024,
    Mips_BNZ_H	= 1025,
    Mips_BNZ_V	= 1026,
    Mips_BNZ_W	= 1027,
    Mips_BOVC	= 1028,
    Mips_BOVC_MMR6	= 1029,
    Mips_BPOSGE32	= 1030,
    Mips_BPOSGE32C_MMR3	= 1031,
    Mips_BPOSGE32_MM	= 1032,
    Mips_BREAK	= 1033,
    Mips_BREAK16_MM	= 1034,
    Mips_BREAK16_MMR6	= 1035,
    Mips_BREAK_MM	= 1036,
    Mips_BREAK_MMR6	= 1037,
    Mips_BSELI_B	= 1038,
    Mips_BSEL_V	= 1039,
    Mips_BSETI_B	= 1040,
    Mips_BSETI_D	= 1041,
    Mips_BSETI_H	= 1042,
    Mips_BSETI_W	= 1043,
    Mips_BSET_B	= 1044,
    Mips_BSET_D	= 1045,
    Mips_BSET_H	= 1046,
    Mips_BSET_W	= 1047,
    Mips_BZ_B	= 1048,
    Mips_BZ_D	= 1049,
    Mips_BZ_H	= 1050,
    Mips_BZ_V	= 1051,
    Mips_BZ_W	= 1052,
    Mips_BeqzRxImm16	= 1053,
    Mips_BeqzRxImmX16	= 1054,
    Mips_Bimm16	= 1055,
    Mips_BimmX16	= 1056,
    Mips_BnezRxImm16	= 1057,
    Mips_BnezRxImmX16	= 1058,
    Mips_Break16	= 1059,
    Mips_Bteqz16	= 1060,
    Mips_BteqzX16	= 1061,
    Mips_Btnez16	= 1062,
    Mips_BtnezX16	= 1063,
    Mips_CACHE	= 1064,
    Mips_CACHEE	= 1065,
    Mips_CACHEE_MM	= 1066,
    Mips_CACHE_MM	= 1067,
    Mips_CACHE_MMR6	= 1068,
    Mips_CACHE_R6	= 1069,
    Mips_CEIL_L_D64	= 1070,
    Mips_CEIL_L_D_MMR6	= 1071,
    Mips_CEIL_L_S	= 1072,
    Mips_CEIL_L_S_MMR6	= 1073,
    Mips_CEIL_W_D32	= 1074,
    Mips_CEIL_W_D64	= 1075,
    Mips_CEIL_W_D_MMR6	= 1076,
    Mips_CEIL_W_MM	= 1077,
    Mips_CEIL_W_S	= 1078,
    Mips_CEIL_W_S_MM	= 1079,
    Mips_CEIL_W_S_MMR6	= 1080,
    Mips_CEQI_B	= 1081,
    Mips_CEQI_D	= 1082,
    Mips_CEQI_H	= 1083,
    Mips_CEQI_W	= 1084,
    Mips_CEQ_B	= 1085,
    Mips_CEQ_D	= 1086,
    Mips_CEQ_H	= 1087,
    Mips_CEQ_W	= 1088,
    Mips_CFC1	= 1089,
    Mips_CFC1_MM	= 1090,
    Mips_CFC2_MM	= 1091,
    Mips_CFCMSA	= 1092,
    Mips_CINS	= 1093,
    Mips_CINS32	= 1094,
    Mips_CINS64_32	= 1095,
    Mips_CINS_i32	= 1096,
    Mips_CLASS_D	= 1097,
    Mips_CLASS_D_MMR6	= 1098,
    Mips_CLASS_S	= 1099,
    Mips_CLASS_S_MMR6	= 1100,
    Mips_CLEI_S_B	= 1101,
    Mips_CLEI_S_D	= 1102,
    Mips_CLEI_S_H	= 1103,
    Mips_CLEI_S_W	= 1104,
    Mips_CLEI_U_B	= 1105,
    Mips_CLEI_U_D	= 1106,
    Mips_CLEI_U_H	= 1107,
    Mips_CLEI_U_W	= 1108,
    Mips_CLE_S_B	= 1109,
    Mips_CLE_S_D	= 1110,
    Mips_CLE_S_H	= 1111,
    Mips_CLE_S_W	= 1112,
    Mips_CLE_U_B	= 1113,
    Mips_CLE_U_D	= 1114,
    Mips_CLE_U_H	= 1115,
    Mips_CLE_U_W	= 1116,
    Mips_CLO	= 1117,
    Mips_CLO_MM	= 1118,
    Mips_CLO_MMR6	= 1119,
    Mips_CLO_R6	= 1120,
    Mips_CLTI_S_B	= 1121,
    Mips_CLTI_S_D	= 1122,
    Mips_CLTI_S_H	= 1123,
    Mips_CLTI_S_W	= 1124,
    Mips_CLTI_U_B	= 1125,
    Mips_CLTI_U_D	= 1126,
    Mips_CLTI_U_H	= 1127,
    Mips_CLTI_U_W	= 1128,
    Mips_CLT_S_B	= 1129,
    Mips_CLT_S_D	= 1130,
    Mips_CLT_S_H	= 1131,
    Mips_CLT_S_W	= 1132,
    Mips_CLT_U_B	= 1133,
    Mips_CLT_U_D	= 1134,
    Mips_CLT_U_H	= 1135,
    Mips_CLT_U_W	= 1136,
    Mips_CLZ	= 1137,
    Mips_CLZ_MM	= 1138,
    Mips_CLZ_MMR6	= 1139,
    Mips_CLZ_R6	= 1140,
    Mips_CMPGDU_EQ_QB	= 1141,
    Mips_CMPGDU_EQ_QB_MMR2	= 1142,
    Mips_CMPGDU_LE_QB	= 1143,
    Mips_CMPGDU_LE_QB_MMR2	= 1144,
    Mips_CMPGDU_LT_QB	= 1145,
    Mips_CMPGDU_LT_QB_MMR2	= 1146,
    Mips_CMPGU_EQ_QB	= 1147,
    Mips_CMPGU_EQ_QB_MM	= 1148,
    Mips_CMPGU_LE_QB	= 1149,
    Mips_CMPGU_LE_QB_MM	= 1150,
    Mips_CMPGU_LT_QB	= 1151,
    Mips_CMPGU_LT_QB_MM	= 1152,
    Mips_CMPU_EQ_QB	= 1153,
    Mips_CMPU_EQ_QB_MM	= 1154,
    Mips_CMPU_LE_QB	= 1155,
    Mips_CMPU_LE_QB_MM	= 1156,
    Mips_CMPU_LT_QB	= 1157,
    Mips_CMPU_LT_QB_MM	= 1158,
    Mips_CMP_AF_D_MMR6	= 1159,
    Mips_CMP_AF_S_MMR6	= 1160,
    Mips_CMP_EQ_D	= 1161,
    Mips_CMP_EQ_D_MMR6	= 1162,
    Mips_CMP_EQ_PH	= 1163,
    Mips_CMP_EQ_PH_MM	= 1164,
    Mips_CMP_EQ_S	= 1165,
    Mips_CMP_EQ_S_MMR6	= 1166,
    Mips_CMP_F_D	= 1167,
    Mips_CMP_F_S	= 1168,
    Mips_CMP_LE_D	= 1169,
    Mips_CMP_LE_D_MMR6	= 1170,
    Mips_CMP_LE_PH	= 1171,
    Mips_CMP_LE_PH_MM	= 1172,
    Mips_CMP_LE_S	= 1173,
    Mips_CMP_LE_S_MMR6	= 1174,
    Mips_CMP_LT_D	= 1175,
    Mips_CMP_LT_D_MMR6	= 1176,
    Mips_CMP_LT_PH	= 1177,
    Mips_CMP_LT_PH_MM	= 1178,
    Mips_CMP_LT_S	= 1179,
    Mips_CMP_LT_S_MMR6	= 1180,
    Mips_CMP_SAF_D	= 1181,
    Mips_CMP_SAF_D_MMR6	= 1182,
    Mips_CMP_SAF_S	= 1183,
    Mips_CMP_SAF_S_MMR6	= 1184,
    Mips_CMP_SEQ_D	= 1185,
    Mips_CMP_SEQ_D_MMR6	= 1186,
    Mips_CMP_SEQ_S	= 1187,
    Mips_CMP_SEQ_S_MMR6	= 1188,
    Mips_CMP_SLE_D	= 1189,
    Mips_CMP_SLE_D_MMR6	= 1190,
    Mips_CMP_SLE_S	= 1191,
    Mips_CMP_SLE_S_MMR6	= 1192,
    Mips_CMP_SLT_D	= 1193,
    Mips_CMP_SLT_D_MMR6	= 1194,
    Mips_CMP_SLT_S	= 1195,
    Mips_CMP_SLT_S_MMR6	= 1196,
    Mips_CMP_SUEQ_D	= 1197,
    Mips_CMP_SUEQ_D_MMR6	= 1198,
    Mips_CMP_SUEQ_S	= 1199,
    Mips_CMP_SUEQ_S_MMR6	= 1200,
    Mips_CMP_SULE_D	= 1201,
    Mips_CMP_SULE_D_MMR6	= 1202,
    Mips_CMP_SULE_S	= 1203,
    Mips_CMP_SULE_S_MMR6	= 1204,
    Mips_CMP_SULT_D	= 1205,
    Mips_CMP_SULT_D_MMR6	= 1206,
    Mips_CMP_SULT_S	= 1207,
    Mips_CMP_SULT_S_MMR6	= 1208,
    Mips_CMP_SUN_D	= 1209,
    Mips_CMP_SUN_D_MMR6	= 1210,
    Mips_CMP_SUN_S	= 1211,
    Mips_CMP_SUN_S_MMR6	= 1212,
    Mips_CMP_UEQ_D	= 1213,
    Mips_CMP_UEQ_D_MMR6	= 1214,
    Mips_CMP_UEQ_S	= 1215,
    Mips_CMP_UEQ_S_MMR6	= 1216,
    Mips_CMP_ULE_D	= 1217,
    Mips_CMP_ULE_D_MMR6	= 1218,
    Mips_CMP_ULE_S	= 1219,
    Mips_CMP_ULE_S_MMR6	= 1220,
    Mips_CMP_ULT_D	= 1221,
    Mips_CMP_ULT_D_MMR6	= 1222,
    Mips_CMP_ULT_S	= 1223,
    Mips_CMP_ULT_S_MMR6	= 1224,
    Mips_CMP_UN_D	= 1225,
    Mips_CMP_UN_D_MMR6	= 1226,
    Mips_CMP_UN_S	= 1227,
    Mips_CMP_UN_S_MMR6	= 1228,
    Mips_COPY_S_B	= 1229,
    Mips_COPY_S_D	= 1230,
    Mips_COPY_S_H	= 1231,
    Mips_COPY_S_W	= 1232,
    Mips_COPY_U_B	= 1233,
    Mips_COPY_U_H	= 1234,
    Mips_COPY_U_W	= 1235,
    Mips_CRC32B	= 1236,
    Mips_CRC32CB	= 1237,
    Mips_CRC32CD	= 1238,
    Mips_CRC32CH	= 1239,
    Mips_CRC32CW	= 1240,
    Mips_CRC32D	= 1241,
    Mips_CRC32H	= 1242,
    Mips_CRC32W	= 1243,
    Mips_CTC1	= 1244,
    Mips_CTC1_MM	= 1245,
    Mips_CTC2_MM	= 1246,
    Mips_CTCMSA	= 1247,
    Mips_CVT_D32_S	= 1248,
    Mips_CVT_D32_S_MM	= 1249,
    Mips_CVT_D32_W	= 1250,
    Mips_CVT_D32_W_MM	= 1251,
    Mips_CVT_D64_L	= 1252,
    Mips_CVT_D64_S	= 1253,
    Mips_CVT_D64_S_MM	= 1254,
    Mips_CVT_D64_W	= 1255,
    Mips_CVT_D64_W_MM	= 1256,
    Mips_CVT_D_L_MMR6	= 1257,
    Mips_CVT_L_D64	= 1258,
    Mips_CVT_L_D64_MM	= 1259,
    Mips_CVT_L_D_MMR6	= 1260,
    Mips_CVT_L_S	= 1261,
    Mips_CVT_L_S_MM	= 1262,
    Mips_CVT_L_S_MMR6	= 1263,
    Mips_CVT_PS_PW64	= 1264,
    Mips_CVT_PS_S64	= 1265,
    Mips_CVT_PW_PS64	= 1266,
    Mips_CVT_S_D32	= 1267,
    Mips_CVT_S_D32_MM	= 1268,
    Mips_CVT_S_D64	= 1269,
    Mips_CVT_S_D64_MM	= 1270,
    Mips_CVT_S_L	= 1271,
    Mips_CVT_S_L_MMR6	= 1272,
    Mips_CVT_S_PL64	= 1273,
    Mips_CVT_S_PU64	= 1274,
    Mips_CVT_S_W	= 1275,
    Mips_CVT_S_W_MM	= 1276,
    Mips_CVT_S_W_MMR6	= 1277,
    Mips_CVT_W_D32	= 1278,
    Mips_CVT_W_D32_MM	= 1279,
    Mips_CVT_W_D64	= 1280,
    Mips_CVT_W_D64_MM	= 1281,
    Mips_CVT_W_S	= 1282,
    Mips_CVT_W_S_MM	= 1283,
    Mips_CVT_W_S_MMR6	= 1284,
    Mips_C_EQ_D32	= 1285,
    Mips_C_EQ_D32_MM	= 1286,
    Mips_C_EQ_D64	= 1287,
    Mips_C_EQ_D64_MM	= 1288,
    Mips_C_EQ_S	= 1289,
    Mips_C_EQ_S_MM	= 1290,
    Mips_C_F_D32	= 1291,
    Mips_C_F_D32_MM	= 1292,
    Mips_C_F_D64	= 1293,
    Mips_C_F_D64_MM	= 1294,
    Mips_C_F_S	= 1295,
    Mips_C_F_S_MM	= 1296,
    Mips_C_LE_D32	= 1297,
    Mips_C_LE_D32_MM	= 1298,
    Mips_C_LE_D64	= 1299,
    Mips_C_LE_D64_MM	= 1300,
    Mips_C_LE_S	= 1301,
    Mips_C_LE_S_MM	= 1302,
    Mips_C_LT_D32	= 1303,
    Mips_C_LT_D32_MM	= 1304,
    Mips_C_LT_D64	= 1305,
    Mips_C_LT_D64_MM	= 1306,
    Mips_C_LT_S	= 1307,
    Mips_C_LT_S_MM	= 1308,
    Mips_C_NGE_D32	= 1309,
    Mips_C_NGE_D32_MM	= 1310,
    Mips_C_NGE_D64	= 1311,
    Mips_C_NGE_D64_MM	= 1312,
    Mips_C_NGE_S	= 1313,
    Mips_C_NGE_S_MM	= 1314,
    Mips_C_NGLE_D32	= 1315,
    Mips_C_NGLE_D32_MM	= 1316,
    Mips_C_NGLE_D64	= 1317,
    Mips_C_NGLE_D64_MM	= 1318,
    Mips_C_NGLE_S	= 1319,
    Mips_C_NGLE_S_MM	= 1320,
    Mips_C_NGL_D32	= 1321,
    Mips_C_NGL_D32_MM	= 1322,
    Mips_C_NGL_D64	= 1323,
    Mips_C_NGL_D64_MM	= 1324,
    Mips_C_NGL_S	= 1325,
    Mips_C_NGL_S_MM	= 1326,
    Mips_C_NGT_D32	= 1327,
    Mips_C_NGT_D32_MM	= 1328,
    Mips_C_NGT_D64	= 1329,
    Mips_C_NGT_D64_MM	= 1330,
    Mips_C_NGT_S	= 1331,
    Mips_C_NGT_S_MM	= 1332,
    Mips_C_OLE_D32	= 1333,
    Mips_C_OLE_D32_MM	= 1334,
    Mips_C_OLE_D64	= 1335,
    Mips_C_OLE_D64_MM	= 1336,
    Mips_C_OLE_S	= 1337,
    Mips_C_OLE_S_MM	= 1338,
    Mips_C_OLT_D32	= 1339,
    Mips_C_OLT_D32_MM	= 1340,
    Mips_C_OLT_D64	= 1341,
    Mips_C_OLT_D64_MM	= 1342,
    Mips_C_OLT_S	= 1343,
    Mips_C_OLT_S_MM	= 1344,
    Mips_C_SEQ_D32	= 1345,
    Mips_C_SEQ_D32_MM	= 1346,
    Mips_C_SEQ_D64	= 1347,
    Mips_C_SEQ_D64_MM	= 1348,
    Mips_C_SEQ_S	= 1349,
    Mips_C_SEQ_S_MM	= 1350,
    Mips_C_SF_D32	= 1351,
    Mips_C_SF_D32_MM	= 1352,
    Mips_C_SF_D64	= 1353,
    Mips_C_SF_D64_MM	= 1354,
    Mips_C_SF_S	= 1355,
    Mips_C_SF_S_MM	= 1356,
    Mips_C_UEQ_D32	= 1357,
    Mips_C_UEQ_D32_MM	= 1358,
    Mips_C_UEQ_D64	= 1359,
    Mips_C_UEQ_D64_MM	= 1360,
    Mips_C_UEQ_S	= 1361,
    Mips_C_UEQ_S_MM	= 1362,
    Mips_C_ULE_D32	= 1363,
    Mips_C_ULE_D32_MM	= 1364,
    Mips_C_ULE_D64	= 1365,
    Mips_C_ULE_D64_MM	= 1366,
    Mips_C_ULE_S	= 1367,
    Mips_C_ULE_S_MM	= 1368,
    Mips_C_ULT_D32	= 1369,
    Mips_C_ULT_D32_MM	= 1370,
    Mips_C_ULT_D64	= 1371,
    Mips_C_ULT_D64_MM	= 1372,
    Mips_C_ULT_S	= 1373,
    Mips_C_ULT_S_MM	= 1374,
    Mips_C_UN_D32	= 1375,
    Mips_C_UN_D32_MM	= 1376,
    Mips_C_UN_D64	= 1377,
    Mips_C_UN_D64_MM	= 1378,
    Mips_C_UN_S	= 1379,
    Mips_C_UN_S_MM	= 1380,
    Mips_CmpRxRy16	= 1381,
    Mips_CmpiRxImm16	= 1382,
    Mips_CmpiRxImmX16	= 1383,
    Mips_DADD	= 1384,
    Mips_DADDi	= 1385,
    Mips_DADDiu	= 1386,
    Mips_DADDu	= 1387,
    Mips_DAHI	= 1388,
    Mips_DALIGN	= 1389,
    Mips_DATI	= 1390,
    Mips_DAUI	= 1391,
    Mips_DBITSWAP	= 1392,
    Mips_DCLO	= 1393,
    Mips_DCLO_R6	= 1394,
    Mips_DCLZ	= 1395,
    Mips_DCLZ_R6	= 1396,
    Mips_DDIV	= 1397,
    Mips_DDIVU	= 1398,
    Mips_DERET	= 1399,
    Mips_DERET_MM	= 1400,
    Mips_DERET_MMR6	= 1401,
    Mips_DEXT	= 1402,
    Mips_DEXT64_32	= 1403,
    Mips_DEXTM	= 1404,
    Mips_DEXTU	= 1405,
    Mips_DI	= 1406,
    Mips_DINS	= 1407,
    Mips_DINSM	= 1408,
    Mips_DINSU	= 1409,
    Mips_DIV	= 1410,
    Mips_DIVU	= 1411,
    Mips_DIVU_MMR6	= 1412,
    Mips_DIV_MMR6	= 1413,
    Mips_DIV_S_B	= 1414,
    Mips_DIV_S_D	= 1415,
    Mips_DIV_S_H	= 1416,
    Mips_DIV_S_W	= 1417,
    Mips_DIV_U_B	= 1418,
    Mips_DIV_U_D	= 1419,
    Mips_DIV_U_H	= 1420,
    Mips_DIV_U_W	= 1421,
    Mips_DI_MM	= 1422,
    Mips_DI_MMR6	= 1423,
    Mips_DLSA	= 1424,
    Mips_DLSA_R6	= 1425,
    Mips_DMFC0	= 1426,
    Mips_DMFC1	= 1427,
    Mips_DMFC2	= 1428,
    Mips_DMFC2_OCTEON	= 1429,
    Mips_DMFGC0	= 1430,
    Mips_DMOD	= 1431,
    Mips_DMODU	= 1432,
    Mips_DMT	= 1433,
    Mips_DMTC0	= 1434,
    Mips_DMTC1	= 1435,
    Mips_DMTC2	= 1436,
    Mips_DMTC2_OCTEON	= 1437,
    Mips_DMTGC0	= 1438,
    Mips_DMUH	= 1439,
    Mips_DMUHU	= 1440,
    Mips_DMUL	= 1441,
    Mips_DMULT	= 1442,
    Mips_DMULTu	= 1443,
    Mips_DMULU	= 1444,
    Mips_DMUL_R6	= 1445,
    Mips_DOTP_S_D	= 1446,
    Mips_DOTP_S_H	= 1447,
    Mips_DOTP_S_W	= 1448,
    Mips_DOTP_U_D	= 1449,
    Mips_DOTP_U_H	= 1450,
    Mips_DOTP_U_W	= 1451,
    Mips_DPADD_S_D	= 1452,
    Mips_DPADD_S_H	= 1453,
    Mips_DPADD_S_W	= 1454,
    Mips_DPADD_U_D	= 1455,
    Mips_DPADD_U_H	= 1456,
    Mips_DPADD_U_W	= 1457,
    Mips_DPAQX_SA_W_PH	= 1458,
    Mips_DPAQX_SA_W_PH_MMR2	= 1459,
    Mips_DPAQX_S_W_PH	= 1460,
    Mips_DPAQX_S_W_PH_MMR2	= 1461,
    Mips_DPAQ_SA_L_W	= 1462,
    Mips_DPAQ_SA_L_W_MM	= 1463,
    Mips_DPAQ_S_W_PH	= 1464,
    Mips_DPAQ_S_W_PH_MM	= 1465,
    Mips_DPAU_H_QBL	= 1466,
    Mips_DPAU_H_QBL_MM	= 1467,
    Mips_DPAU_H_QBR	= 1468,
    Mips_DPAU_H_QBR_MM	= 1469,
    Mips_DPAX_W_PH	= 1470,
    Mips_DPAX_W_PH_MMR2	= 1471,
    Mips_DPA_W_PH	= 1472,
    Mips_DPA_W_PH_MMR2	= 1473,
    Mips_DPOP	= 1474,
    Mips_DPSQX_SA_W_PH	= 1475,
    Mips_DPSQX_SA_W_PH_MMR2	= 1476,
    Mips_DPSQX_S_W_PH	= 1477,
    Mips_DPSQX_S_W_PH_MMR2	= 1478,
    Mips_DPSQ_SA_L_W	= 1479,
    Mips_DPSQ_SA_L_W_MM	= 1480,
    Mips_DPSQ_S_W_PH	= 1481,
    Mips_DPSQ_S_W_PH_MM	= 1482,
    Mips_DPSUB_S_D	= 1483,
    Mips_DPSUB_S_H	= 1484,
    Mips_DPSUB_S_W	= 1485,
    Mips_DPSUB_U_D	= 1486,
    Mips_DPSUB_U_H	= 1487,
    Mips_DPSUB_U_W	= 1488,
    Mips_DPSU_H_QBL	= 1489,
    Mips_DPSU_H_QBL_MM	= 1490,
    Mips_DPSU_H_QBR	= 1491,
    Mips_DPSU_H_QBR_MM	= 1492,
    Mips_DPSX_W_PH	= 1493,
    Mips_DPSX_W_PH_MMR2	= 1494,
    Mips_DPS_W_PH	= 1495,
    Mips_DPS_W_PH_MMR2	= 1496,
    Mips_DROTR	= 1497,
    Mips_DROTR32	= 1498,
    Mips_DROTRV	= 1499,
    Mips_DSBH	= 1500,
    Mips_DSDIV	= 1501,
    Mips_DSHD	= 1502,
    Mips_DSLL	= 1503,
    Mips_DSLL32	= 1504,
    Mips_DSLL64_32	= 1505,
    Mips_DSLLV	= 1506,
    Mips_DSRA	= 1507,
    Mips_DSRA32	= 1508,
    Mips_DSRAV	= 1509,
    Mips_DSRL	= 1510,
    Mips_DSRL32	= 1511,
    Mips_DSRLV	= 1512,
    Mips_DSUB	= 1513,
    Mips_DSUBu	= 1514,
    Mips_DUDIV	= 1515,
    Mips_DVP	= 1516,
    Mips_DVPE	= 1517,
    Mips_DVP_MMR6	= 1518,
    Mips_DivRxRy16	= 1519,
    Mips_DivuRxRy16	= 1520,
    Mips_EHB	= 1521,
    Mips_EHB_MM	= 1522,
    Mips_EHB_MMR6	= 1523,
    Mips_EI	= 1524,
    Mips_EI_MM	= 1525,
    Mips_EI_MMR6	= 1526,
    Mips_EMT	= 1527,
    Mips_ERET	= 1528,
    Mips_ERETNC	= 1529,
    Mips_ERETNC_MMR6	= 1530,
    Mips_ERET_MM	= 1531,
    Mips_ERET_MMR6	= 1532,
    Mips_EVP	= 1533,
    Mips_EVPE	= 1534,
    Mips_EVP_MMR6	= 1535,
    Mips_EXT	= 1536,
    Mips_EXTP	= 1537,
    Mips_EXTPDP	= 1538,
    Mips_EXTPDPV	= 1539,
    Mips_EXTPDPV_MM	= 1540,
    Mips_EXTPDP_MM	= 1541,
    Mips_EXTPV	= 1542,
    Mips_EXTPV_MM	= 1543,
    Mips_EXTP_MM	= 1544,
    Mips_EXTRV_RS_W	= 1545,
    Mips_EXTRV_RS_W_MM	= 1546,
    Mips_EXTRV_R_W	= 1547,
    Mips_EXTRV_R_W_MM	= 1548,
    Mips_EXTRV_S_H	= 1549,
    Mips_EXTRV_S_H_MM	= 1550,
    Mips_EXTRV_W	= 1551,
    Mips_EXTRV_W_MM	= 1552,
    Mips_EXTR_RS_W	= 1553,
    Mips_EXTR_RS_W_MM	= 1554,
    Mips_EXTR_R_W	= 1555,
    Mips_EXTR_R_W_MM	= 1556,
    Mips_EXTR_S_H	= 1557,
    Mips_EXTR_S_H_MM	= 1558,
    Mips_EXTR_W	= 1559,
    Mips_EXTR_W_MM	= 1560,
    Mips_EXTS	= 1561,
    Mips_EXTS32	= 1562,
    Mips_EXT_MM	= 1563,
    Mips_EXT_MMR6	= 1564,
    Mips_FABS_D32	= 1565,
    Mips_FABS_D32_MM	= 1566,
    Mips_FABS_D64	= 1567,
    Mips_FABS_D64_MM	= 1568,
    Mips_FABS_S	= 1569,
    Mips_FABS_S_MM	= 1570,
    Mips_FADD_D	= 1571,
    Mips_FADD_D32	= 1572,
    Mips_FADD_D32_MM	= 1573,
    Mips_FADD_D64	= 1574,
    Mips_FADD_D64_MM	= 1575,
    Mips_FADD_PS64	= 1576,
    Mips_FADD_S	= 1577,
    Mips_FADD_S_MM	= 1578,
    Mips_FADD_S_MMR6	= 1579,
    Mips_FADD_W	= 1580,
    Mips_FCAF_D	= 1581,
    Mips_FCAF_W	= 1582,
    Mips_FCEQ_D	= 1583,
    Mips_FCEQ_W	= 1584,
    Mips_FCLASS_D	= 1585,
    Mips_FCLASS_W	= 1586,
    Mips_FCLE_D	= 1587,
    Mips_FCLE_W	= 1588,
    Mips_FCLT_D	= 1589,
    Mips_FCLT_W	= 1590,
    Mips_FCMP_D32	= 1591,
    Mips_FCMP_D32_MM	= 1592,
    Mips_FCMP_D64	= 1593,
    Mips_FCMP_S32	= 1594,
    Mips_FCMP_S32_MM	= 1595,
    Mips_FCNE_D	= 1596,
    Mips_FCNE_W	= 1597,
    Mips_FCOR_D	= 1598,
    Mips_FCOR_W	= 1599,
    Mips_FCUEQ_D	= 1600,
    Mips_FCUEQ_W	= 1601,
    Mips_FCULE_D	= 1602,
    Mips_FCULE_W	= 1603,
    Mips_FCULT_D	= 1604,
    Mips_FCULT_W	= 1605,
    Mips_FCUNE_D	= 1606,
    Mips_FCUNE_W	= 1607,
    Mips_FCUN_D	= 1608,
    Mips_FCUN_W	= 1609,
    Mips_FDIV_D	= 1610,
    Mips_FDIV_D32	= 1611,
    Mips_FDIV_D32_MM	= 1612,
    Mips_FDIV_D64	= 1613,
    Mips_FDIV_D64_MM	= 1614,
    Mips_FDIV_S	= 1615,
    Mips_FDIV_S_MM	= 1616,
    Mips_FDIV_S_MMR6	= 1617,
    Mips_FDIV_W	= 1618,
    Mips_FEXDO_H	= 1619,
    Mips_FEXDO_W	= 1620,
    Mips_FEXP2_D	= 1621,
    Mips_FEXP2_W	= 1622,
    Mips_FEXUPL_D	= 1623,
    Mips_FEXUPL_W	= 1624,
    Mips_FEXUPR_D	= 1625,
    Mips_FEXUPR_W	= 1626,
    Mips_FFINT_S_D	= 1627,
    Mips_FFINT_S_W	= 1628,
    Mips_FFINT_U_D	= 1629,
    Mips_FFINT_U_W	= 1630,
    Mips_FFQL_D	= 1631,
    Mips_FFQL_W	= 1632,
    Mips_FFQR_D	= 1633,
    Mips_FFQR_W	= 1634,
    Mips_FILL_B	= 1635,
    Mips_FILL_D	= 1636,
    Mips_FILL_H	= 1637,
    Mips_FILL_W	= 1638,
    Mips_FLOG2_D	= 1639,
    Mips_FLOG2_W	= 1640,
    Mips_FLOOR_L_D64	= 1641,
    Mips_FLOOR_L_D_MMR6	= 1642,
    Mips_FLOOR_L_S	= 1643,
    Mips_FLOOR_L_S_MMR6	= 1644,
    Mips_FLOOR_W_D32	= 1645,
    Mips_FLOOR_W_D64	= 1646,
    Mips_FLOOR_W_D_MMR6	= 1647,
    Mips_FLOOR_W_MM	= 1648,
    Mips_FLOOR_W_S	= 1649,
    Mips_FLOOR_W_S_MM	= 1650,
    Mips_FLOOR_W_S_MMR6	= 1651,
    Mips_FMADD_D	= 1652,
    Mips_FMADD_W	= 1653,
    Mips_FMAX_A_D	= 1654,
    Mips_FMAX_A_W	= 1655,
    Mips_FMAX_D	= 1656,
    Mips_FMAX_W	= 1657,
    Mips_FMIN_A_D	= 1658,
    Mips_FMIN_A_W	= 1659,
    Mips_FMIN_D	= 1660,
    Mips_FMIN_W	= 1661,
    Mips_FMOV_D32	= 1662,
    Mips_FMOV_D32_MM	= 1663,
    Mips_FMOV_D64	= 1664,
    Mips_FMOV_D64_MM	= 1665,
    Mips_FMOV_D_MMR6	= 1666,
    Mips_FMOV_S	= 1667,
    Mips_FMOV_S_MM	= 1668,
    Mips_FMOV_S_MMR6	= 1669,
    Mips_FMSUB_D	= 1670,
    Mips_FMSUB_W	= 1671,
    Mips_FMUL_D	= 1672,
    Mips_FMUL_D32	= 1673,
    Mips_FMUL_D32_MM	= 1674,
    Mips_FMUL_D64	= 1675,
    Mips_FMUL_D64_MM	= 1676,
    Mips_FMUL_PS64	= 1677,
    Mips_FMUL_S	= 1678,
    Mips_FMUL_S_MM	= 1679,
    Mips_FMUL_S_MMR6	= 1680,
    Mips_FMUL_W	= 1681,
    Mips_FNEG_D32	= 1682,
    Mips_FNEG_D32_MM	= 1683,
    Mips_FNEG_D64	= 1684,
    Mips_FNEG_D64_MM	= 1685,
    Mips_FNEG_S	= 1686,
    Mips_FNEG_S_MM	= 1687,
    Mips_FNEG_S_MMR6	= 1688,
    Mips_FORK	= 1689,
    Mips_FRCP_D	= 1690,
    Mips_FRCP_W	= 1691,
    Mips_FRINT_D	= 1692,
    Mips_FRINT_W	= 1693,
    Mips_FRSQRT_D	= 1694,
    Mips_FRSQRT_W	= 1695,
    Mips_FSAF_D	= 1696,
    Mips_FSAF_W	= 1697,
    Mips_FSEQ_D	= 1698,
    Mips_FSEQ_W	= 1699,
    Mips_FSLE_D	= 1700,
    Mips_FSLE_W	= 1701,
    Mips_FSLT_D	= 1702,
    Mips_FSLT_W	= 1703,
    Mips_FSNE_D	= 1704,
    Mips_FSNE_W	= 1705,
    Mips_FSOR_D	= 1706,
    Mips_FSOR_W	= 1707,
    Mips_FSQRT_D	= 1708,
    Mips_FSQRT_D32	= 1709,
    Mips_FSQRT_D32_MM	= 1710,
    Mips_FSQRT_D64	= 1711,
    Mips_FSQRT_D64_MM	= 1712,
    Mips_FSQRT_S	= 1713,
    Mips_FSQRT_S_MM	= 1714,
    Mips_FSQRT_W	= 1715,
    Mips_FSUB_D	= 1716,
    Mips_FSUB_D32	= 1717,
    Mips_FSUB_D32_MM	= 1718,
    Mips_FSUB_D64	= 1719,
    Mips_FSUB_D64_MM	= 1720,
    Mips_FSUB_PS64	= 1721,
    Mips_FSUB_S	= 1722,
    Mips_FSUB_S_MM	= 1723,
    Mips_FSUB_S_MMR6	= 1724,
    Mips_FSUB_W	= 1725,
    Mips_FSUEQ_D	= 1726,
    Mips_FSUEQ_W	= 1727,
    Mips_FSULE_D	= 1728,
    Mips_FSULE_W	= 1729,
    Mips_FSULT_D	= 1730,
    Mips_FSULT_W	= 1731,
    Mips_FSUNE_D	= 1732,
    Mips_FSUNE_W	= 1733,
    Mips_FSUN_D	= 1734,
    Mips_FSUN_W	= 1735,
    Mips_FTINT_S_D	= 1736,
    Mips_FTINT_S_W	= 1737,
    Mips_FTINT_U_D	= 1738,
    Mips_FTINT_U_W	= 1739,
    Mips_FTQ_H	= 1740,
    Mips_FTQ_W	= 1741,
    Mips_FTRUNC_S_D	= 1742,
    Mips_FTRUNC_S_W	= 1743,
    Mips_FTRUNC_U_D	= 1744,
    Mips_FTRUNC_U_W	= 1745,
    Mips_GINVI	= 1746,
    Mips_GINVI_MMR6	= 1747,
    Mips_GINVT	= 1748,
    Mips_GINVT_MMR6	= 1749,
    Mips_HADD_S_D	= 1750,
    Mips_HADD_S_H	= 1751,
    Mips_HADD_S_W	= 1752,
    Mips_HADD_U_D	= 1753,
    Mips_HADD_U_H	= 1754,
    Mips_HADD_U_W	= 1755,
    Mips_HSUB_S_D	= 1756,
    Mips_HSUB_S_H	= 1757,
    Mips_HSUB_S_W	= 1758,
    Mips_HSUB_U_D	= 1759,
    Mips_HSUB_U_H	= 1760,
    Mips_HSUB_U_W	= 1761,
    Mips_HYPCALL	= 1762,
    Mips_HYPCALL_MM	= 1763,
    Mips_ILVEV_B	= 1764,
    Mips_ILVEV_D	= 1765,
    Mips_ILVEV_H	= 1766,
    Mips_ILVEV_W	= 1767,
    Mips_ILVL_B	= 1768,
    Mips_ILVL_D	= 1769,
    Mips_ILVL_H	= 1770,
    Mips_ILVL_W	= 1771,
    Mips_ILVOD_B	= 1772,
    Mips_ILVOD_D	= 1773,
    Mips_ILVOD_H	= 1774,
    Mips_ILVOD_W	= 1775,
    Mips_ILVR_B	= 1776,
    Mips_ILVR_D	= 1777,
    Mips_ILVR_H	= 1778,
    Mips_ILVR_W	= 1779,
    Mips_INS	= 1780,
    Mips_INSERT_B	= 1781,
    Mips_INSERT_D	= 1782,
    Mips_INSERT_H	= 1783,
    Mips_INSERT_W	= 1784,
    Mips_INSV	= 1785,
    Mips_INSVE_B	= 1786,
    Mips_INSVE_D	= 1787,
    Mips_INSVE_H	= 1788,
    Mips_INSVE_W	= 1789,
    Mips_INSV_MM	= 1790,
    Mips_INS_MM	= 1791,
    Mips_INS_MMR6	= 1792,
    Mips_J	= 1793,
    Mips_JAL	= 1794,
    Mips_JALR	= 1795,
    Mips_JALR16_MM	= 1796,
    Mips_JALR64	= 1797,
    Mips_JALRC16_MMR6	= 1798,
    Mips_JALRC_HB_MMR6	= 1799,
    Mips_JALRC_MMR6	= 1800,
    Mips_JALRS16_MM	= 1801,
    Mips_JALRS_MM	= 1802,
    Mips_JALR_HB	= 1803,
    Mips_JALR_HB64	= 1804,
    Mips_JALR_MM	= 1805,
    Mips_JALS_MM	= 1806,
    Mips_JALX	= 1807,
    Mips_JALX_MM	= 1808,
    Mips_JAL_MM	= 1809,
    Mips_JIALC	= 1810,
    Mips_JIALC64	= 1811,
    Mips_JIALC_MMR6	= 1812,
    Mips_JIC	= 1813,
    Mips_JIC64	= 1814,
    Mips_JIC_MMR6	= 1815,
    Mips_JR	= 1816,
    Mips_JR16_MM	= 1817,
    Mips_JR64	= 1818,
    Mips_JRADDIUSP	= 1819,
    Mips_JRC16_MM	= 1820,
    Mips_JRC16_MMR6	= 1821,
    Mips_JRCADDIUSP_MMR6	= 1822,
    Mips_JR_HB	= 1823,
    Mips_JR_HB64	= 1824,
    Mips_JR_HB64_R6	= 1825,
    Mips_JR_HB_R6	= 1826,
    Mips_JR_MM	= 1827,
    Mips_J_MM	= 1828,
    Mips_Jal16	= 1829,
    Mips_JalB16	= 1830,
    Mips_JrRa16	= 1831,
    Mips_JrcRa16	= 1832,
    Mips_JrcRx16	= 1833,
    Mips_JumpLinkReg16	= 1834,
    Mips_LB	= 1835,
    Mips_LB64	= 1836,
    Mips_LBE	= 1837,
    Mips_LBE_MM	= 1838,
    Mips_LBU16_MM	= 1839,
    Mips_LBUX	= 1840,
    Mips_LBUX_MM	= 1841,
    Mips_LBU_MMR6	= 1842,
    Mips_LB_MM	= 1843,
    Mips_LB_MMR6	= 1844,
    Mips_LBu	= 1845,
    Mips_LBu64	= 1846,
    Mips_LBuE	= 1847,
    Mips_LBuE_MM	= 1848,
    Mips_LBu_MM	= 1849,
    Mips_LD	= 1850,
    Mips_LDC1	= 1851,
    Mips_LDC164	= 1852,
    Mips_LDC1_D64_MMR6	= 1853,
    Mips_LDC1_MM_D32	= 1854,
    Mips_LDC1_MM_D64	= 1855,
    Mips_LDC2	= 1856,
    Mips_LDC2_MMR6	= 1857,
    Mips_LDC2_R6	= 1858,
    Mips_LDC3	= 1859,
    Mips_LDI_B	= 1860,
    Mips_LDI_D	= 1861,
    Mips_LDI_H	= 1862,
    Mips_LDI_W	= 1863,
    Mips_LDL	= 1864,
    Mips_LDPC	= 1865,
    Mips_LDR	= 1866,
    Mips_LDXC1	= 1867,
    Mips_LDXC164	= 1868,
    Mips_LD_B	= 1869,
    Mips_LD_D	= 1870,
    Mips_LD_H	= 1871,
    Mips_LD_W	= 1872,
    Mips_LEA_ADDiu	= 1873,
    Mips_LEA_ADDiu64	= 1874,
    Mips_LEA_ADDiu_MM	= 1875,
    Mips_LH	= 1876,
    Mips_LH64	= 1877,
    Mips_LHE	= 1878,
    Mips_LHE_MM	= 1879,
    Mips_LHU16_MM	= 1880,
    Mips_LHX	= 1881,
    Mips_LHX_MM	= 1882,
    Mips_LH_MM	= 1883,
    Mips_LHu	= 1884,
    Mips_LHu64	= 1885,
    Mips_LHuE	= 1886,
    Mips_LHuE_MM	= 1887,
    Mips_LHu_MM	= 1888,
    Mips_LI16_MM	= 1889,
    Mips_LI16_MMR6	= 1890,
    Mips_LL	= 1891,
    Mips_LL64	= 1892,
    Mips_LL64_R6	= 1893,
    Mips_LLD	= 1894,
    Mips_LLD_R6	= 1895,
    Mips_LLE	= 1896,
    Mips_LLE_MM	= 1897,
    Mips_LL_MM	= 1898,
    Mips_LL_MMR6	= 1899,
    Mips_LL_R6	= 1900,
    Mips_LSA	= 1901,
    Mips_LSA_MMR6	= 1902,
    Mips_LSA_R6	= 1903,
    Mips_LUI_MMR6	= 1904,
    Mips_LUXC1	= 1905,
    Mips_LUXC164	= 1906,
    Mips_LUXC1_MM	= 1907,
    Mips_LUi	= 1908,
    Mips_LUi64	= 1909,
    Mips_LUi_MM	= 1910,
    Mips_LW	= 1911,
    Mips_LW16_MM	= 1912,
    Mips_LW64	= 1913,
    Mips_LWC1	= 1914,
    Mips_LWC1_MM	= 1915,
    Mips_LWC2	= 1916,
    Mips_LWC2_MMR6	= 1917,
    Mips_LWC2_R6	= 1918,
    Mips_LWC3	= 1919,
    Mips_LWDSP	= 1920,
    Mips_LWDSP_MM	= 1921,
    Mips_LWE	= 1922,
    Mips_LWE_MM	= 1923,
    Mips_LWGP_MM	= 1924,
    Mips_LWL	= 1925,
    Mips_LWL64	= 1926,
    Mips_LWLE	= 1927,
    Mips_LWLE_MM	= 1928,
    Mips_LWL_MM	= 1929,
    Mips_LWM16_MM	= 1930,
    Mips_LWM16_MMR6	= 1931,
    Mips_LWM32_MM	= 1932,
    Mips_LWPC	= 1933,
    Mips_LWPC_MMR6	= 1934,
    Mips_LWP_MM	= 1935,
    Mips_LWR	= 1936,
    Mips_LWR64	= 1937,
    Mips_LWRE	= 1938,
    Mips_LWRE_MM	= 1939,
    Mips_LWR_MM	= 1940,
    Mips_LWSP_MM	= 1941,
    Mips_LWUPC	= 1942,
    Mips_LWU_MM	= 1943,
    Mips_LWX	= 1944,
    Mips_LWXC1	= 1945,
    Mips_LWXC1_MM	= 1946,
    Mips_LWXS_MM	= 1947,
    Mips_LWX_MM	= 1948,
    Mips_LW_MM	= 1949,
    Mips_LW_MMR6	= 1950,
    Mips_LWu	= 1951,
    Mips_LbRxRyOffMemX16	= 1952,
    Mips_LbuRxRyOffMemX16	= 1953,
    Mips_LhRxRyOffMemX16	= 1954,
    Mips_LhuRxRyOffMemX16	= 1955,
    Mips_LiRxImm16	= 1956,
    Mips_LiRxImmAlignX16	= 1957,
    Mips_LiRxImmX16	= 1958,
    Mips_LwRxPcTcp16	= 1959,
    Mips_LwRxPcTcpX16	= 1960,
    Mips_LwRxRyOffMemX16	= 1961,
    Mips_LwRxSpImmX16	= 1962,
    Mips_MADD	= 1963,
    Mips_MADDF_D	= 1964,
    Mips_MADDF_D_MMR6	= 1965,
    Mips_MADDF_S	= 1966,
    Mips_MADDF_S_MMR6	= 1967,
    Mips_MADDR_Q_H	= 1968,
    Mips_MADDR_Q_W	= 1969,
    Mips_MADDU	= 1970,
    Mips_MADDU_DSP	= 1971,
    Mips_MADDU_DSP_MM	= 1972,
    Mips_MADDU_MM	= 1973,
    Mips_MADDV_B	= 1974,
    Mips_MADDV_D	= 1975,
    Mips_MADDV_H	= 1976,
    Mips_MADDV_W	= 1977,
    Mips_MADD_D32	= 1978,
    Mips_MADD_D32_MM	= 1979,
    Mips_MADD_D64	= 1980,
    Mips_MADD_DSP	= 1981,
    Mips_MADD_DSP_MM	= 1982,
    Mips_MADD_MM	= 1983,
    Mips_MADD_Q_H	= 1984,
    Mips_MADD_Q_W	= 1985,
    Mips_MADD_S	= 1986,
    Mips_MADD_S_MM	= 1987,
    Mips_MAQ_SA_W_PHL	= 1988,
    Mips_MAQ_SA_W_PHL_MM	= 1989,
    Mips_MAQ_SA_W_PHR	= 1990,
    Mips_MAQ_SA_W_PHR_MM	= 1991,
    Mips_MAQ_S_W_PHL	= 1992,
    Mips_MAQ_S_W_PHL_MM	= 1993,
    Mips_MAQ_S_W_PHR	= 1994,
    Mips_MAQ_S_W_PHR_MM	= 1995,
    Mips_MAXA_D	= 1996,
    Mips_MAXA_D_MMR6	= 1997,
    Mips_MAXA_S	= 1998,
    Mips_MAXA_S_MMR6	= 1999,
    Mips_MAXI_S_B	= 2000,
    Mips_MAXI_S_D	= 2001,
    Mips_MAXI_S_H	= 2002,
    Mips_MAXI_S_W	= 2003,
    Mips_MAXI_U_B	= 2004,
    Mips_MAXI_U_D	= 2005,
    Mips_MAXI_U_H	= 2006,
    Mips_MAXI_U_W	= 2007,
    Mips_MAX_A_B	= 2008,
    Mips_MAX_A_D	= 2009,
    Mips_MAX_A_H	= 2010,
    Mips_MAX_A_W	= 2011,
    Mips_MAX_D	= 2012,
    Mips_MAX_D_MMR6	= 2013,
    Mips_MAX_S	= 2014,
    Mips_MAX_S_B	= 2015,
    Mips_MAX_S_D	= 2016,
    Mips_MAX_S_H	= 2017,
    Mips_MAX_S_MMR6	= 2018,
    Mips_MAX_S_W	= 2019,
    Mips_MAX_U_B	= 2020,
    Mips_MAX_U_D	= 2021,
    Mips_MAX_U_H	= 2022,
    Mips_MAX_U_W	= 2023,
    Mips_MFC0	= 2024,
    Mips_MFC0_MMR6	= 2025,
    Mips_MFC1	= 2026,
    Mips_MFC1_D64	= 2027,
    Mips_MFC1_MM	= 2028,
    Mips_MFC1_MMR6	= 2029,
    Mips_MFC2	= 2030,
    Mips_MFC2_MMR6	= 2031,
    Mips_MFGC0	= 2032,
    Mips_MFGC0_MM	= 2033,
    Mips_MFHC0_MMR6	= 2034,
    Mips_MFHC1_D32	= 2035,
    Mips_MFHC1_D32_MM	= 2036,
    Mips_MFHC1_D64	= 2037,
    Mips_MFHC1_D64_MM	= 2038,
    Mips_MFHC2_MMR6	= 2039,
    Mips_MFHGC0	= 2040,
    Mips_MFHGC0_MM	= 2041,
    Mips_MFHI	= 2042,
    Mips_MFHI16_MM	= 2043,
    Mips_MFHI64	= 2044,
    Mips_MFHI_DSP	= 2045,
    Mips_MFHI_DSP_MM	= 2046,
    Mips_MFHI_MM	= 2047,
    Mips_MFLO	= 2048,
    Mips_MFLO16_MM	= 2049,
    Mips_MFLO64	= 2050,
    Mips_MFLO_DSP	= 2051,
    Mips_MFLO_DSP_MM	= 2052,
    Mips_MFLO_MM	= 2053,
    Mips_MFTR	= 2054,
    Mips_MINA_D	= 2055,
    Mips_MINA_D_MMR6	= 2056,
    Mips_MINA_S	= 2057,
    Mips_MINA_S_MMR6	= 2058,
    Mips_MINI_S_B	= 2059,
    Mips_MINI_S_D	= 2060,
    Mips_MINI_S_H	= 2061,
    Mips_MINI_S_W	= 2062,
    Mips_MINI_U_B	= 2063,
    Mips_MINI_U_D	= 2064,
    Mips_MINI_U_H	= 2065,
    Mips_MINI_U_W	= 2066,
    Mips_MIN_A_B	= 2067,
    Mips_MIN_A_D	= 2068,
    Mips_MIN_A_H	= 2069,
    Mips_MIN_A_W	= 2070,
    Mips_MIN_D	= 2071,
    Mips_MIN_D_MMR6	= 2072,
    Mips_MIN_S	= 2073,
    Mips_MIN_S_B	= 2074,
    Mips_MIN_S_D	= 2075,
    Mips_MIN_S_H	= 2076,
    Mips_MIN_S_MMR6	= 2077,
    Mips_MIN_S_W	= 2078,
    Mips_MIN_U_B	= 2079,
    Mips_MIN_U_D	= 2080,
    Mips_MIN_U_H	= 2081,
    Mips_MIN_U_W	= 2082,
    Mips_MOD	= 2083,
    Mips_MODSUB	= 2084,
    Mips_MODSUB_MM	= 2085,
    Mips_MODU	= 2086,
    Mips_MODU_MMR6	= 2087,
    Mips_MOD_MMR6	= 2088,
    Mips_MOD_S_B	= 2089,
    Mips_MOD_S_D	= 2090,
    Mips_MOD_S_H	= 2091,
    Mips_MOD_S_W	= 2092,
    Mips_MOD_U_B	= 2093,
    Mips_MOD_U_D	= 2094,
    Mips_MOD_U_H	= 2095,
    Mips_MOD_U_W	= 2096,
    Mips_MOVE16_MM	= 2097,
    Mips_MOVE16_MMR6	= 2098,
    Mips_MOVEP_MM	= 2099,
    Mips_MOVEP_MMR6	= 2100,
    Mips_MOVE_V	= 2101,
    Mips_MOVF_D32	= 2102,
    Mips_MOVF_D32_MM	= 2103,
    Mips_MOVF_D64	= 2104,
    Mips_MOVF_I	= 2105,
    Mips_MOVF_I64	= 2106,
    Mips_MOVF_I_MM	= 2107,
    Mips_MOVF_S	= 2108,
    Mips_MOVF_S_MM	= 2109,
    Mips_MOVN_I64_D64	= 2110,
    Mips_MOVN_I64_I	= 2111,
    Mips_MOVN_I64_I64	= 2112,
    Mips_MOVN_I64_S	= 2113,
    Mips_MOVN_I_D32	= 2114,
    Mips_MOVN_I_D32_MM	= 2115,
    Mips_MOVN_I_D64	= 2116,
    Mips_MOVN_I_I	= 2117,
    Mips_MOVN_I_I64	= 2118,
    Mips_MOVN_I_MM	= 2119,
    Mips_MOVN_I_S	= 2120,
    Mips_MOVN_I_S_MM	= 2121,
    Mips_MOVT_D32	= 2122,
    Mips_MOVT_D32_MM	= 2123,
    Mips_MOVT_D64	= 2124,
    Mips_MOVT_I	= 2125,
    Mips_MOVT_I64	= 2126,
    Mips_MOVT_I_MM	= 2127,
    Mips_MOVT_S	= 2128,
    Mips_MOVT_S_MM	= 2129,
    Mips_MOVZ_I64_D64	= 2130,
    Mips_MOVZ_I64_I	= 2131,
    Mips_MOVZ_I64_I64	= 2132,
    Mips_MOVZ_I64_S	= 2133,
    Mips_MOVZ_I_D32	= 2134,
    Mips_MOVZ_I_D32_MM	= 2135,
    Mips_MOVZ_I_D64	= 2136,
    Mips_MOVZ_I_I	= 2137,
    Mips_MOVZ_I_I64	= 2138,
    Mips_MOVZ_I_MM	= 2139,
    Mips_MOVZ_I_S	= 2140,
    Mips_MOVZ_I_S_MM	= 2141,
    Mips_MSUB	= 2142,
    Mips_MSUBF_D	= 2143,
    Mips_MSUBF_D_MMR6	= 2144,
    Mips_MSUBF_S	= 2145,
    Mips_MSUBF_S_MMR6	= 2146,
    Mips_MSUBR_Q_H	= 2147,
    Mips_MSUBR_Q_W	= 2148,
    Mips_MSUBU	= 2149,
    Mips_MSUBU_DSP	= 2150,
    Mips_MSUBU_DSP_MM	= 2151,
    Mips_MSUBU_MM	= 2152,
    Mips_MSUBV_B	= 2153,
    Mips_MSUBV_D	= 2154,
    Mips_MSUBV_H	= 2155,
    Mips_MSUBV_W	= 2156,
    Mips_MSUB_D32	= 2157,
    Mips_MSUB_D32_MM	= 2158,
    Mips_MSUB_D64	= 2159,
    Mips_MSUB_DSP	= 2160,
    Mips_MSUB_DSP_MM	= 2161,
    Mips_MSUB_MM	= 2162,
    Mips_MSUB_Q_H	= 2163,
    Mips_MSUB_Q_W	= 2164,
    Mips_MSUB_S	= 2165,
    Mips_MSUB_S_MM	= 2166,
    Mips_MTC0	= 2167,
    Mips_MTC0_MMR6	= 2168,
    Mips_MTC1	= 2169,
    Mips_MTC1_D64	= 2170,
    Mips_MTC1_D64_MM	= 2171,
    Mips_MTC1_MM	= 2172,
    Mips_MTC1_MMR6	= 2173,
    Mips_MTC2	= 2174,
    Mips_MTC2_MMR6	= 2175,
    Mips_MTGC0	= 2176,
    Mips_MTGC0_MM	= 2177,
    Mips_MTHC0_MMR6	= 2178,
    Mips_MTHC1_D32	= 2179,
    Mips_MTHC1_D32_MM	= 2180,
    Mips_MTHC1_D64	= 2181,
    Mips_MTHC1_D64_MM	= 2182,
    Mips_MTHC2_MMR6	= 2183,
    Mips_MTHGC0	= 2184,
    Mips_MTHGC0_MM	= 2185,
    Mips_MTHI	= 2186,
    Mips_MTHI64	= 2187,
    Mips_MTHI_DSP	= 2188,
    Mips_MTHI_DSP_MM	= 2189,
    Mips_MTHI_MM	= 2190,
    Mips_MTHLIP	= 2191,
    Mips_MTHLIP_MM	= 2192,
    Mips_MTLO	= 2193,
    Mips_MTLO64	= 2194,
    Mips_MTLO_DSP	= 2195,
    Mips_MTLO_DSP_MM	= 2196,
    Mips_MTLO_MM	= 2197,
    Mips_MTM0	= 2198,
    Mips_MTM1	= 2199,
    Mips_MTM2	= 2200,
    Mips_MTP0	= 2201,
    Mips_MTP1	= 2202,
    Mips_MTP2	= 2203,
    Mips_MTTR	= 2204,
    Mips_MUH	= 2205,
    Mips_MUHU	= 2206,
    Mips_MUHU_MMR6	= 2207,
    Mips_MUH_MMR6	= 2208,
    Mips_MUL	= 2209,
    Mips_MULEQ_S_W_PHL	= 2210,
    Mips_MULEQ_S_W_PHL_MM	= 2211,
    Mips_MULEQ_S_W_PHR	= 2212,
    Mips_MULEQ_S_W_PHR_MM	= 2213,
    Mips_MULEU_S_PH_QBL	= 2214,
    Mips_MULEU_S_PH_QBL_MM	= 2215,
    Mips_MULEU_S_PH_QBR	= 2216,
    Mips_MULEU_S_PH_QBR_MM	= 2217,
    Mips_MULQ_RS_PH	= 2218,
    Mips_MULQ_RS_PH_MM	= 2219,
    Mips_MULQ_RS_W	= 2220,
    Mips_MULQ_RS_W_MMR2	= 2221,
    Mips_MULQ_S_PH	= 2222,
    Mips_MULQ_S_PH_MMR2	= 2223,
    Mips_MULQ_S_W	= 2224,
    Mips_MULQ_S_W_MMR2	= 2225,
    Mips_MULR_PS64	= 2226,
    Mips_MULR_Q_H	= 2227,
    Mips_MULR_Q_W	= 2228,
    Mips_MULSAQ_S_W_PH	= 2229,
    Mips_MULSAQ_S_W_PH_MM	= 2230,
    Mips_MULSA_W_PH	= 2231,
    Mips_MULSA_W_PH_MMR2	= 2232,
    Mips_MULT	= 2233,
    Mips_MULTU_DSP	= 2234,
    Mips_MULTU_DSP_MM	= 2235,
    Mips_MULT_DSP	= 2236,
    Mips_MULT_DSP_MM	= 2237,
    Mips_MULT_MM	= 2238,
    Mips_MULTu	= 2239,
    Mips_MULTu_MM	= 2240,
    Mips_MULU	= 2241,
    Mips_MULU_MMR6	= 2242,
    Mips_MULV_B	= 2243,
    Mips_MULV_D	= 2244,
    Mips_MULV_H	= 2245,
    Mips_MULV_W	= 2246,
    Mips_MUL_MM	= 2247,
    Mips_MUL_MMR6	= 2248,
    Mips_MUL_PH	= 2249,
    Mips_MUL_PH_MMR2	= 2250,
    Mips_MUL_Q_H	= 2251,
    Mips_MUL_Q_W	= 2252,
    Mips_MUL_R6	= 2253,
    Mips_MUL_S_PH	= 2254,
    Mips_MUL_S_PH_MMR2	= 2255,
    Mips_Mfhi16	= 2256,
    Mips_Mflo16	= 2257,
    Mips_Move32R16	= 2258,
    Mips_MoveR3216	= 2259,
    Mips_NLOC_B	= 2260,
    Mips_NLOC_D	= 2261,
    Mips_NLOC_H	= 2262,
    Mips_NLOC_W	= 2263,
    Mips_NLZC_B	= 2264,
    Mips_NLZC_D	= 2265,
    Mips_NLZC_H	= 2266,
    Mips_NLZC_W	= 2267,
    Mips_NMADD_D32	= 2268,
    Mips_NMADD_D32_MM	= 2269,
    Mips_NMADD_D64	= 2270,
    Mips_NMADD_S	= 2271,
    Mips_NMADD_S_MM	= 2272,
    Mips_NMSUB_D32	= 2273,
    Mips_NMSUB_D32_MM	= 2274,
    Mips_NMSUB_D64	= 2275,
    Mips_NMSUB_S	= 2276,
    Mips_NMSUB_S_MM	= 2277,
    Mips_NOR	= 2278,
    Mips_NOR64	= 2279,
    Mips_NORI_B	= 2280,
    Mips_NOR_MM	= 2281,
    Mips_NOR_MMR6	= 2282,
    Mips_NOR_V	= 2283,
    Mips_NOT16_MM	= 2284,
    Mips_NOT16_MMR6	= 2285,
    Mips_NegRxRy16	= 2286,
    Mips_NotRxRy16	= 2287,
    Mips_OR	= 2288,
    Mips_OR16_MM	= 2289,
    Mips_OR16_MMR6	= 2290,
    Mips_OR64	= 2291,
    Mips_ORI_B	= 2292,
    Mips_ORI_MMR6	= 2293,
    Mips_OR_MM	= 2294,
    Mips_OR_MMR6	= 2295,
    Mips_OR_V	= 2296,
    Mips_ORi	= 2297,
    Mips_ORi64	= 2298,
    Mips_ORi_MM	= 2299,
    Mips_OrRxRxRy16	= 2300,
    Mips_PACKRL_PH	= 2301,
    Mips_PACKRL_PH_MM	= 2302,
    Mips_PAUSE	= 2303,
    Mips_PAUSE_MM	= 2304,
    Mips_PAUSE_MMR6	= 2305,
    Mips_PCKEV_B	= 2306,
    Mips_PCKEV_D	= 2307,
    Mips_PCKEV_H	= 2308,
    Mips_PCKEV_W	= 2309,
    Mips_PCKOD_B	= 2310,
    Mips_PCKOD_D	= 2311,
    Mips_PCKOD_H	= 2312,
    Mips_PCKOD_W	= 2313,
    Mips_PCNT_B	= 2314,
    Mips_PCNT_D	= 2315,
    Mips_PCNT_H	= 2316,
    Mips_PCNT_W	= 2317,
    Mips_PICK_PH	= 2318,
    Mips_PICK_PH_MM	= 2319,
    Mips_PICK_QB	= 2320,
    Mips_PICK_QB_MM	= 2321,
    Mips_PLL_PS64	= 2322,
    Mips_PLU_PS64	= 2323,
    Mips_POP	= 2324,
    Mips_PRECEQU_PH_QBL	= 2325,
    Mips_PRECEQU_PH_QBLA	= 2326,
    Mips_PRECEQU_PH_QBLA_MM	= 2327,
    Mips_PRECEQU_PH_QBL_MM	= 2328,
    Mips_PRECEQU_PH_QBR	= 2329,
    Mips_PRECEQU_PH_QBRA	= 2330,
    Mips_PRECEQU_PH_QBRA_MM	= 2331,
    Mips_PRECEQU_PH_QBR_MM	= 2332,
    Mips_PRECEQ_W_PHL	= 2333,
    Mips_PRECEQ_W_PHL_MM	= 2334,
    Mips_PRECEQ_W_PHR	= 2335,
    Mips_PRECEQ_W_PHR_MM	= 2336,
    Mips_PRECEU_PH_QBL	= 2337,
    Mips_PRECEU_PH_QBLA	= 2338,
    Mips_PRECEU_PH_QBLA_MM	= 2339,
    Mips_PRECEU_PH_QBL_MM	= 2340,
    Mips_PRECEU_PH_QBR	= 2341,
    Mips_PRECEU_PH_QBRA	= 2342,
    Mips_PRECEU_PH_QBRA_MM	= 2343,
    Mips_PRECEU_PH_QBR_MM	= 2344,
    Mips_PRECRQU_S_QB_PH	= 2345,
    Mips_PRECRQU_S_QB_PH_MM	= 2346,
    Mips_PRECRQ_PH_W	= 2347,
    Mips_PRECRQ_PH_W_MM	= 2348,
    Mips_PRECRQ_QB_PH	= 2349,
    Mips_PRECRQ_QB_PH_MM	= 2350,
    Mips_PRECRQ_RS_PH_W	= 2351,
    Mips_PRECRQ_RS_PH_W_MM	= 2352,
    Mips_PRECR_QB_PH	= 2353,
    Mips_PRECR_QB_PH_MMR2	= 2354,
    Mips_PRECR_SRA_PH_W	= 2355,
    Mips_PRECR_SRA_PH_W_MMR2	= 2356,
    Mips_PRECR_SRA_R_PH_W	= 2357,
    Mips_PRECR_SRA_R_PH_W_MMR2	= 2358,
    Mips_PREF	= 2359,
    Mips_PREFE	= 2360,
    Mips_PREFE_MM	= 2361,
    Mips_PREFX_MM	= 2362,
    Mips_PREF_MM	= 2363,
    Mips_PREF_MMR6	= 2364,
    Mips_PREF_R6	= 2365,
    Mips_PREPEND	= 2366,
    Mips_PREPEND_MMR2	= 2367,
    Mips_PUL_PS64	= 2368,
    Mips_PUU_PS64	= 2369,
    Mips_RADDU_W_QB	= 2370,
    Mips_RADDU_W_QB_MM	= 2371,
    Mips_RDDSP	= 2372,
    Mips_RDDSP_MM	= 2373,
    Mips_RDHWR	= 2374,
    Mips_RDHWR64	= 2375,
    Mips_RDHWR_MM	= 2376,
    Mips_RDHWR_MMR6	= 2377,
    Mips_RDPGPR_MMR6	= 2378,
    Mips_RECIP_D32	= 2379,
    Mips_RECIP_D32_MM	= 2380,
    Mips_RECIP_D64	= 2381,
    Mips_RECIP_D64_MM	= 2382,
    Mips_RECIP_S	= 2383,
    Mips_RECIP_S_MM	= 2384,
    Mips_REPLV_PH	= 2385,
    Mips_REPLV_PH_MM	= 2386,
    Mips_REPLV_QB	= 2387,
    Mips_REPLV_QB_MM	= 2388,
    Mips_REPL_PH	= 2389,
    Mips_REPL_PH_MM	= 2390,
    Mips_REPL_QB	= 2391,
    Mips_REPL_QB_MM	= 2392,
    Mips_RINT_D	= 2393,
    Mips_RINT_D_MMR6	= 2394,
    Mips_RINT_S	= 2395,
    Mips_RINT_S_MMR6	= 2396,
    Mips_ROTR	= 2397,
    Mips_ROTRV	= 2398,
    Mips_ROTRV_MM	= 2399,
    Mips_ROTR_MM	= 2400,
    Mips_ROUND_L_D64	= 2401,
    Mips_ROUND_L_D_MMR6	= 2402,
    Mips_ROUND_L_S	= 2403,
    Mips_ROUND_L_S_MMR6	= 2404,
    Mips_ROUND_W_D32	= 2405,
    Mips_ROUND_W_D64	= 2406,
    Mips_ROUND_W_D_MMR6	= 2407,
    Mips_ROUND_W_MM	= 2408,
    Mips_ROUND_W_S	= 2409,
    Mips_ROUND_W_S_MM	= 2410,
    Mips_ROUND_W_S_MMR6	= 2411,
    Mips_RSQRT_D32	= 2412,
    Mips_RSQRT_D32_MM	= 2413,
    Mips_RSQRT_D64	= 2414,
    Mips_RSQRT_D64_MM	= 2415,
    Mips_RSQRT_S	= 2416,
    Mips_RSQRT_S_MM	= 2417,
    Mips_Restore16	= 2418,
    Mips_RestoreX16	= 2419,
    Mips_SAA	= 2420,
    Mips_SAAD	= 2421,
    Mips_SAT_S_B	= 2422,
    Mips_SAT_S_D	= 2423,
    Mips_SAT_S_H	= 2424,
    Mips_SAT_S_W	= 2425,
    Mips_SAT_U_B	= 2426,
    Mips_SAT_U_D	= 2427,
    Mips_SAT_U_H	= 2428,
    Mips_SAT_U_W	= 2429,
    Mips_SB	= 2430,
    Mips_SB16_MM	= 2431,
    Mips_SB16_MMR6	= 2432,
    Mips_SB64	= 2433,
    Mips_SBE	= 2434,
    Mips_SBE_MM	= 2435,
    Mips_SB_MM	= 2436,
    Mips_SB_MMR6	= 2437,
    Mips_SC	= 2438,
    Mips_SC64	= 2439,
    Mips_SC64_R6	= 2440,
    Mips_SCD	= 2441,
    Mips_SCD_R6	= 2442,
    Mips_SCE	= 2443,
    Mips_SCE_MM	= 2444,
    Mips_SC_MM	= 2445,
    Mips_SC_MMR6	= 2446,
    Mips_SC_R6	= 2447,
    Mips_SD	= 2448,
    Mips_SDBBP	= 2449,
    Mips_SDBBP16_MM	= 2450,
    Mips_SDBBP16_MMR6	= 2451,
    Mips_SDBBP_MM	= 2452,
    Mips_SDBBP_MMR6	= 2453,
    Mips_SDBBP_R6	= 2454,
    Mips_SDC1	= 2455,
    Mips_SDC164	= 2456,
    Mips_SDC1_D64_MMR6	= 2457,
    Mips_SDC1_MM_D32	= 2458,
    Mips_SDC1_MM_D64	= 2459,
    Mips_SDC2	= 2460,
    Mips_SDC2_MMR6	= 2461,
    Mips_SDC2_R6	= 2462,
    Mips_SDC3	= 2463,
    Mips_SDIV	= 2464,
    Mips_SDIV_MM	= 2465,
    Mips_SDL	= 2466,
    Mips_SDR	= 2467,
    Mips_SDXC1	= 2468,
    Mips_SDXC164	= 2469,
    Mips_SEB	= 2470,
    Mips_SEB64	= 2471,
    Mips_SEB_MM	= 2472,
    Mips_SEH	= 2473,
    Mips_SEH64	= 2474,
    Mips_SEH_MM	= 2475,
    Mips_SELEQZ	= 2476,
    Mips_SELEQZ64	= 2477,
    Mips_SELEQZ_D	= 2478,
    Mips_SELEQZ_D_MMR6	= 2479,
    Mips_SELEQZ_MMR6	= 2480,
    Mips_SELEQZ_S	= 2481,
    Mips_SELEQZ_S_MMR6	= 2482,
    Mips_SELNEZ	= 2483,
    Mips_SELNEZ64	= 2484,
    Mips_SELNEZ_D	= 2485,
    Mips_SELNEZ_D_MMR6	= 2486,
    Mips_SELNEZ_MMR6	= 2487,
    Mips_SELNEZ_S	= 2488,
    Mips_SELNEZ_S_MMR6	= 2489,
    Mips_SEL_D	= 2490,
    Mips_SEL_D_MMR6	= 2491,
    Mips_SEL_S	= 2492,
    Mips_SEL_S_MMR6	= 2493,
    Mips_SEQ	= 2494,
    Mips_SEQi	= 2495,
    Mips_SH	= 2496,
    Mips_SH16_MM	= 2497,
    Mips_SH16_MMR6	= 2498,
    Mips_SH64	= 2499,
    Mips_SHE	= 2500,
    Mips_SHE_MM	= 2501,
    Mips_SHF_B	= 2502,
    Mips_SHF_H	= 2503,
    Mips_SHF_W	= 2504,
    Mips_SHILO	= 2505,
    Mips_SHILOV	= 2506,
    Mips_SHILOV_MM	= 2507,
    Mips_SHILO_MM	= 2508,
    Mips_SHLLV_PH	= 2509,
    Mips_SHLLV_PH_MM	= 2510,
    Mips_SHLLV_QB	= 2511,
    Mips_SHLLV_QB_MM	= 2512,
    Mips_SHLLV_S_PH	= 2513,
    Mips_SHLLV_S_PH_MM	= 2514,
    Mips_SHLLV_S_W	= 2515,
    Mips_SHLLV_S_W_MM	= 2516,
    Mips_SHLL_PH	= 2517,
    Mips_SHLL_PH_MM	= 2518,
    Mips_SHLL_QB	= 2519,
    Mips_SHLL_QB_MM	= 2520,
    Mips_SHLL_S_PH	= 2521,
    Mips_SHLL_S_PH_MM	= 2522,
    Mips_SHLL_S_W	= 2523,
    Mips_SHLL_S_W_MM	= 2524,
    Mips_SHRAV_PH	= 2525,
    Mips_SHRAV_PH_MM	= 2526,
    Mips_SHRAV_QB	= 2527,
    Mips_SHRAV_QB_MMR2	= 2528,
    Mips_SHRAV_R_PH	= 2529,
    Mips_SHRAV_R_PH_MM	= 2530,
    Mips_SHRAV_R_QB	= 2531,
    Mips_SHRAV_R_QB_MMR2	= 2532,
    Mips_SHRAV_R_W	= 2533,
    Mips_SHRAV_R_W_MM	= 2534,
    Mips_SHRA_PH	= 2535,
    Mips_SHRA_PH_MM	= 2536,
    Mips_SHRA_QB	= 2537,
    Mips_SHRA_QB_MMR2	= 2538,
    Mips_SHRA_R_PH	= 2539,
    Mips_SHRA_R_PH_MM	= 2540,
    Mips_SHRA_R_QB	= 2541,
    Mips_SHRA_R_QB_MMR2	= 2542,
    Mips_SHRA_R_W	= 2543,
    Mips_SHRA_R_W_MM	= 2544,
    Mips_SHRLV_PH	= 2545,
    Mips_SHRLV_PH_MMR2	= 2546,
    Mips_SHRLV_QB	= 2547,
    Mips_SHRLV_QB_MM	= 2548,
    Mips_SHRL_PH	= 2549,
    Mips_SHRL_PH_MMR2	= 2550,
    Mips_SHRL_QB	= 2551,
    Mips_SHRL_QB_MM	= 2552,
    Mips_SH_MM	= 2553,
    Mips_SH_MMR6	= 2554,
    Mips_SIGRIE	= 2555,
    Mips_SIGRIE_MMR6	= 2556,
    Mips_SLDI_B	= 2557,
    Mips_SLDI_D	= 2558,
    Mips_SLDI_H	= 2559,
    Mips_SLDI_W	= 2560,
    Mips_SLD_B	= 2561,
    Mips_SLD_D	= 2562,
    Mips_SLD_H	= 2563,
    Mips_SLD_W	= 2564,
    Mips_SLL	= 2565,
    Mips_SLL16_MM	= 2566,
    Mips_SLL16_MMR6	= 2567,
    Mips_SLL64_32	= 2568,
    Mips_SLL64_64	= 2569,
    Mips_SLLI_B	= 2570,
    Mips_SLLI_D	= 2571,
    Mips_SLLI_H	= 2572,
    Mips_SLLI_W	= 2573,
    Mips_SLLV	= 2574,
    Mips_SLLV_MM	= 2575,
    Mips_SLL_B	= 2576,
    Mips_SLL_D	= 2577,
    Mips_SLL_H	= 2578,
    Mips_SLL_MM	= 2579,
    Mips_SLL_MMR6	= 2580,
    Mips_SLL_W	= 2581,
    Mips_SLT	= 2582,
    Mips_SLT64	= 2583,
    Mips_SLT_MM	= 2584,
    Mips_SLTi	= 2585,
    Mips_SLTi64	= 2586,
    Mips_SLTi_MM	= 2587,
    Mips_SLTiu	= 2588,
    Mips_SLTiu64	= 2589,
    Mips_SLTiu_MM	= 2590,
    Mips_SLTu	= 2591,
    Mips_SLTu64	= 2592,
    Mips_SLTu_MM	= 2593,
    Mips_SNE	= 2594,
    Mips_SNEi	= 2595,
    Mips_SPLATI_B	= 2596,
    Mips_SPLATI_D	= 2597,
    Mips_SPLATI_H	= 2598,
    Mips_SPLATI_W	= 2599,
    Mips_SPLAT_B	= 2600,
    Mips_SPLAT_D	= 2601,
    Mips_SPLAT_H	= 2602,
    Mips_SPLAT_W	= 2603,
    Mips_SRA	= 2604,
    Mips_SRAI_B	= 2605,
    Mips_SRAI_D	= 2606,
    Mips_SRAI_H	= 2607,
    Mips_SRAI_W	= 2608,
    Mips_SRARI_B	= 2609,
    Mips_SRARI_D	= 2610,
    Mips_SRARI_H	= 2611,
    Mips_SRARI_W	= 2612,
    Mips_SRAR_B	= 2613,
    Mips_SRAR_D	= 2614,
    Mips_SRAR_H	= 2615,
    Mips_SRAR_W	= 2616,
    Mips_SRAV	= 2617,
    Mips_SRAV_MM	= 2618,
    Mips_SRA_B	= 2619,
    Mips_SRA_D	= 2620,
    Mips_SRA_H	= 2621,
    Mips_SRA_MM	= 2622,
    Mips_SRA_W	= 2623,
    Mips_SRL	= 2624,
    Mips_SRL16_MM	= 2625,
    Mips_SRL16_MMR6	= 2626,
    Mips_SRLI_B	= 2627,
    Mips_SRLI_D	= 2628,
    Mips_SRLI_H	= 2629,
    Mips_SRLI_W	= 2630,
    Mips_SRLRI_B	= 2631,
    Mips_SRLRI_D	= 2632,
    Mips_SRLRI_H	= 2633,
    Mips_SRLRI_W	= 2634,
    Mips_SRLR_B	= 2635,
    Mips_SRLR_D	= 2636,
    Mips_SRLR_H	= 2637,
    Mips_SRLR_W	= 2638,
    Mips_SRLV	= 2639,
    Mips_SRLV_MM	= 2640,
    Mips_SRL_B	= 2641,
    Mips_SRL_D	= 2642,
    Mips_SRL_H	= 2643,
    Mips_SRL_MM	= 2644,
    Mips_SRL_W	= 2645,
    Mips_SSNOP	= 2646,
    Mips_SSNOP_MM	= 2647,
    Mips_SSNOP_MMR6	= 2648,
    Mips_ST_B	= 2649,
    Mips_ST_D	= 2650,
    Mips_ST_H	= 2651,
    Mips_ST_W	= 2652,
    Mips_SUB	= 2653,
    Mips_SUBQH_PH	= 2654,
    Mips_SUBQH_PH_MMR2	= 2655,
    Mips_SUBQH_R_PH	= 2656,
    Mips_SUBQH_R_PH_MMR2	= 2657,
    Mips_SUBQH_R_W	= 2658,
    Mips_SUBQH_R_W_MMR2	= 2659,
    Mips_SUBQH_W	= 2660,
    Mips_SUBQH_W_MMR2	= 2661,
    Mips_SUBQ_PH	= 2662,
    Mips_SUBQ_PH_MM	= 2663,
    Mips_SUBQ_S_PH	= 2664,
    Mips_SUBQ_S_PH_MM	= 2665,
    Mips_SUBQ_S_W	= 2666,
    Mips_SUBQ_S_W_MM	= 2667,
    Mips_SUBSUS_U_B	= 2668,
    Mips_SUBSUS_U_D	= 2669,
    Mips_SUBSUS_U_H	= 2670,
    Mips_SUBSUS_U_W	= 2671,
    Mips_SUBSUU_S_B	= 2672,
    Mips_SUBSUU_S_D	= 2673,
    Mips_SUBSUU_S_H	= 2674,
    Mips_SUBSUU_S_W	= 2675,
    Mips_SUBS_S_B	= 2676,
    Mips_SUBS_S_D	= 2677,
    Mips_SUBS_S_H	= 2678,
    Mips_SUBS_S_W	= 2679,
    Mips_SUBS_U_B	= 2680,
    Mips_SUBS_U_D	= 2681,
    Mips_SUBS_U_H	= 2682,
    Mips_SUBS_U_W	= 2683,
    Mips_SUBU16_MM	= 2684,
    Mips_SUBU16_MMR6	= 2685,
    Mips_SUBUH_QB	= 2686,
    Mips_SUBUH_QB_MMR2	= 2687,
    Mips_SUBUH_R_QB	= 2688,
    Mips_SUBUH_R_QB_MMR2	= 2689,
    Mips_SUBU_MMR6	= 2690,
    Mips_SUBU_PH	= 2691,
    Mips_SUBU_PH_MMR2	= 2692,
    Mips_SUBU_QB	= 2693,
    Mips_SUBU_QB_MM	= 2694,
    Mips_SUBU_S_PH	= 2695,
    Mips_SUBU_S_PH_MMR2	= 2696,
    Mips_SUBU_S_QB	= 2697,
    Mips_SUBU_S_QB_MM	= 2698,
    Mips_SUBVI_B	= 2699,
    Mips_SUBVI_D	= 2700,
    Mips_SUBVI_H	= 2701,
    Mips_SUBVI_W	= 2702,
    Mips_SUBV_B	= 2703,
    Mips_SUBV_D	= 2704,
    Mips_SUBV_H	= 2705,
    Mips_SUBV_W	= 2706,
    Mips_SUB_MM	= 2707,
    Mips_SUB_MMR6	= 2708,
    Mips_SUBu	= 2709,
    Mips_SUBu_MM	= 2710,
    Mips_SUXC1	= 2711,
    Mips_SUXC164	= 2712,
    Mips_SUXC1_MM	= 2713,
    Mips_SW	= 2714,
    Mips_SW16_MM	= 2715,
    Mips_SW16_MMR6	= 2716,
    Mips_SW64	= 2717,
    Mips_SWC1	= 2718,
    Mips_SWC1_MM	= 2719,
    Mips_SWC2	= 2720,
    Mips_SWC2_MMR6	= 2721,
    Mips_SWC2_R6	= 2722,
    Mips_SWC3	= 2723,
    Mips_SWDSP	= 2724,
    Mips_SWDSP_MM	= 2725,
    Mips_SWE	= 2726,
    Mips_SWE_MM	= 2727,
    Mips_SWL	= 2728,
    Mips_SWL64	= 2729,
    Mips_SWLE	= 2730,
    Mips_SWLE_MM	= 2731,
    Mips_SWL_MM	= 2732,
    Mips_SWM16_MM	= 2733,
    Mips_SWM16_MMR6	= 2734,
    Mips_SWM32_MM	= 2735,
    Mips_SWP_MM	= 2736,
    Mips_SWR	= 2737,
    Mips_SWR64	= 2738,
    Mips_SWRE	= 2739,
    Mips_SWRE_MM	= 2740,
    Mips_SWR_MM	= 2741,
    Mips_SWSP_MM	= 2742,
    Mips_SWSP_MMR6	= 2743,
    Mips_SWXC1	= 2744,
    Mips_SWXC1_MM	= 2745,
    Mips_SW_MM	= 2746,
    Mips_SW_MMR6	= 2747,
    Mips_SYNC	= 2748,
    Mips_SYNCI	= 2749,
    Mips_SYNCI_MM	= 2750,
    Mips_SYNCI_MMR6	= 2751,
    Mips_SYNC_MM	= 2752,
    Mips_SYNC_MMR6	= 2753,
    Mips_SYSCALL	= 2754,
    Mips_SYSCALL_MM	= 2755,
    Mips_Save16	= 2756,
    Mips_SaveX16	= 2757,
    Mips_SbRxRyOffMemX16	= 2758,
    Mips_SebRx16	= 2759,
    Mips_SehRx16	= 2760,
    Mips_ShRxRyOffMemX16	= 2761,
    Mips_SllX16	= 2762,
    Mips_SllvRxRy16	= 2763,
    Mips_SltRxRy16	= 2764,
    Mips_SltiRxImm16	= 2765,
    Mips_SltiRxImmX16	= 2766,
    Mips_SltiuRxImm16	= 2767,
    Mips_SltiuRxImmX16	= 2768,
    Mips_SltuRxRy16	= 2769,
    Mips_SraX16	= 2770,
    Mips_SravRxRy16	= 2771,
    Mips_SrlX16	= 2772,
    Mips_SrlvRxRy16	= 2773,
    Mips_SubuRxRyRz16	= 2774,
    Mips_SwRxRyOffMemX16	= 2775,
    Mips_SwRxSpImmX16	= 2776,
    Mips_TEQ	= 2777,
    Mips_TEQI	= 2778,
    Mips_TEQI_MM	= 2779,
    Mips_TEQ_MM	= 2780,
    Mips_TGE	= 2781,
    Mips_TGEI	= 2782,
    Mips_TGEIU	= 2783,
    Mips_TGEIU_MM	= 2784,
    Mips_TGEI_MM	= 2785,
    Mips_TGEU	= 2786,
    Mips_TGEU_MM	= 2787,
    Mips_TGE_MM	= 2788,
    Mips_TLBGINV	= 2789,
    Mips_TLBGINVF	= 2790,
    Mips_TLBGINVF_MM	= 2791,
    Mips_TLBGINV_MM	= 2792,
    Mips_TLBGP	= 2793,
    Mips_TLBGP_MM	= 2794,
    Mips_TLBGR	= 2795,
    Mips_TLBGR_MM	= 2796,
    Mips_TLBGWI	= 2797,
    Mips_TLBGWI_MM	= 2798,
    Mips_TLBGWR	= 2799,
    Mips_TLBGWR_MM	= 2800,
    Mips_TLBINV	= 2801,
    Mips_TLBINVF	= 2802,
    Mips_TLBINVF_MMR6	= 2803,
    Mips_TLBINV_MMR6	= 2804,
    Mips_TLBP	= 2805,
    Mips_TLBP_MM	= 2806,
    Mips_TLBR	= 2807,
    Mips_TLBR_MM	= 2808,
    Mips_TLBWI	= 2809,
    Mips_TLBWI_MM	= 2810,
    Mips_TLBWR	= 2811,
    Mips_TLBWR_MM	= 2812,
    Mips_TLT	= 2813,
    Mips_TLTI	= 2814,
    Mips_TLTIU_MM	= 2815,
    Mips_TLTI_MM	= 2816,
    Mips_TLTU	= 2817,
    Mips_TLTU_MM	= 2818,
    Mips_TLT_MM	= 2819,
    Mips_TNE	= 2820,
    Mips_TNEI	= 2821,
    Mips_TNEI_MM	= 2822,
    Mips_TNE_MM	= 2823,
    Mips_TRUNC_L_D64	= 2824,
    Mips_TRUNC_L_D_MMR6	= 2825,
    Mips_TRUNC_L_S	= 2826,
    Mips_TRUNC_L_S_MMR6	= 2827,
    Mips_TRUNC_W_D32	= 2828,
    Mips_TRUNC_W_D64	= 2829,
    Mips_TRUNC_W_D_MMR6	= 2830,
    Mips_TRUNC_W_MM	= 2831,
    Mips_TRUNC_W_S	= 2832,
    Mips_TRUNC_W_S_MM	= 2833,
    Mips_TRUNC_W_S_MMR6	= 2834,
    Mips_TTLTIU	= 2835,
    Mips_UDIV	= 2836,
    Mips_UDIV_MM	= 2837,
    Mips_V3MULU	= 2838,
    Mips_VMM0	= 2839,
    Mips_VMULU	= 2840,
    Mips_VSHF_B	= 2841,
    Mips_VSHF_D	= 2842,
    Mips_VSHF_H	= 2843,
    Mips_VSHF_W	= 2844,
    Mips_WAIT	= 2845,
    Mips_WAIT_MM	= 2846,
    Mips_WAIT_MMR6	= 2847,
    Mips_WRDSP	= 2848,
    Mips_WRDSP_MM	= 2849,
    Mips_WRPGPR_MMR6	= 2850,
    Mips_WSBH	= 2851,
    Mips_WSBH_MM	= 2852,
    Mips_WSBH_MMR6	= 2853,
    Mips_XOR	= 2854,
    Mips_XOR16_MM	= 2855,
    Mips_XOR16_MMR6	= 2856,
    Mips_XOR64	= 2857,
    Mips_XORI_B	= 2858,
    Mips_XORI_MMR6	= 2859,
    Mips_XOR_MM	= 2860,
    Mips_XOR_MMR6	= 2861,
    Mips_XOR_V	= 2862,
    Mips_XORi	= 2863,
    Mips_XORi64	= 2864,
    Mips_XORi_MM	= 2865,
    Mips_XorRxRxRy16	= 2866,
    Mips_YIELD	= 2867,
    INSTRUCTION_LIST_END = 2868
  };

#endif // GET_INSTRINFO_ENUM

#if defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)
typedef struct MipsInstrTable {
  MCInstrDesc Insts[2868];
  MCOperandInfo OperandInfo[1130];
  MCPhysReg ImplicitOps[67];
} MipsInstrTable;

#endif // defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

#ifdef GET_INSTRINFO_MC_DESC
#undef GET_INSTRINFO_MC_DESC

static const unsigned MipsImpOpBase = sizeof(MCOperandInfo) / (sizeof(MCPhysReg));

static const MipsInstrTable MipsDescs = {
  {
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2867 = YIELD
  { 3, &MipsDescs.OperandInfo[576] },  // Inst #2866 = XorRxRxRy16
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2865 = XORi_MM
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #2864 = XORi64
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2863 = XORi
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #2862 = XOR_V
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2861 = XOR_MMR6
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2860 = XOR_MM
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2859 = XORI_MMR6
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #2858 = XORI_B
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #2857 = XOR64
  { 3, &MipsDescs.OperandInfo[561] },  // Inst #2856 = XOR16_MMR6
  { 3, &MipsDescs.OperandInfo[561] },  // Inst #2855 = XOR16_MM
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2854 = XOR
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2853 = WSBH_MMR6
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2852 = WSBH_MM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2851 = WSBH
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2850 = WRPGPR_MMR6
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #2849 = WRDSP_MM
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #2848 = WRDSP
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2847 = WAIT_MMR6
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2846 = WAIT_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2845 = WAIT
  { 4, &MipsDescs.OperandInfo[190] },  // Inst #2844 = VSHF_W
  { 4, &MipsDescs.OperandInfo[194] },  // Inst #2843 = VSHF_H
  { 4, &MipsDescs.OperandInfo[186] },  // Inst #2842 = VSHF_D
  { 4, &MipsDescs.OperandInfo[606] },  // Inst #2841 = VSHF_B
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #2840 = VMULU
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #2839 = VMM0
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #2838 = V3MULU
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2837 = UDIV_MM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2836 = UDIV
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #2835 = TTLTIU
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #2834 = TRUNC_W_S_MMR6
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #2833 = TRUNC_W_S_MM
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #2832 = TRUNC_W_S
  { 2, &MipsDescs.OperandInfo[627] },  // Inst #2831 = TRUNC_W_MM
  { 2, &MipsDescs.OperandInfo[629] },  // Inst #2830 = TRUNC_W_D_MMR6
  { 2, &MipsDescs.OperandInfo[629] },  // Inst #2829 = TRUNC_W_D64
  { 2, &MipsDescs.OperandInfo[627] },  // Inst #2828 = TRUNC_W_D32
  { 2, &MipsDescs.OperandInfo[625] },  // Inst #2827 = TRUNC_L_S_MMR6
  { 2, &MipsDescs.OperandInfo[625] },  // Inst #2826 = TRUNC_L_S
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #2825 = TRUNC_L_D_MMR6
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #2824 = TRUNC_L_D64
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2823 = TNE_MM
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #2822 = TNEI_MM
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #2821 = TNEI
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2820 = TNE
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2819 = TLT_MM
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2818 = TLTU_MM
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2817 = TLTU
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #2816 = TLTI_MM
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #2815 = TLTIU_MM
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #2814 = TLTI
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2813 = TLT
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2812 = TLBWR_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2811 = TLBWR
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2810 = TLBWI_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2809 = TLBWI
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2808 = TLBR_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2807 = TLBR
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2806 = TLBP_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2805 = TLBP
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2804 = TLBINV_MMR6
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2803 = TLBINVF_MMR6
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2802 = TLBINVF
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2801 = TLBINV
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2800 = TLBGWR_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2799 = TLBGWR
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2798 = TLBGWI_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2797 = TLBGWI
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2796 = TLBGR_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2795 = TLBGR
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2794 = TLBGP_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2793 = TLBGP
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2792 = TLBGINV_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2791 = TLBGINVF_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2790 = TLBGINVF
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2789 = TLBGINV
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2788 = TGE_MM
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2787 = TGEU_MM
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2786 = TGEU
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #2785 = TGEI_MM
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #2784 = TGEIU_MM
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #2783 = TGEIU
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #2782 = TGEI
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2781 = TGE
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2780 = TEQ_MM
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #2779 = TEQI_MM
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #2778 = TEQI
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2777 = TEQ
  { 3, &MipsDescs.OperandInfo[573] },  // Inst #2776 = SwRxSpImmX16
  { 3, &MipsDescs.OperandInfo[914] },  // Inst #2775 = SwRxRyOffMemX16
  { 3, &MipsDescs.OperandInfo[396] },  // Inst #2774 = SubuRxRyRz16
  { 3, &MipsDescs.OperandInfo[576] },  // Inst #2773 = SrlvRxRy16
  { 3, &MipsDescs.OperandInfo[520] },  // Inst #2772 = SrlX16
  { 3, &MipsDescs.OperandInfo[576] },  // Inst #2771 = SravRxRy16
  { 3, &MipsDescs.OperandInfo[520] },  // Inst #2770 = SraX16
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #2769 = SltuRxRy16
  { 2, &MipsDescs.OperandInfo[568] },  // Inst #2768 = SltiuRxImmX16
  { 2, &MipsDescs.OperandInfo[568] },  // Inst #2767 = SltiuRxImm16
  { 2, &MipsDescs.OperandInfo[568] },  // Inst #2766 = SltiRxImmX16
  { 2, &MipsDescs.OperandInfo[568] },  // Inst #2765 = SltiRxImm16
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #2764 = SltRxRy16
  { 3, &MipsDescs.OperandInfo[576] },  // Inst #2763 = SllvRxRy16
  { 3, &MipsDescs.OperandInfo[520] },  // Inst #2762 = SllX16
  { 3, &MipsDescs.OperandInfo[914] },  // Inst #2761 = ShRxRyOffMemX16
  { 2, &MipsDescs.OperandInfo[1128] },  // Inst #2760 = SehRx16
  { 2, &MipsDescs.OperandInfo[1128] },  // Inst #2759 = SebRx16
  { 3, &MipsDescs.OperandInfo[914] },  // Inst #2758 = SbRxRyOffMemX16
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2757 = SaveX16
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2756 = Save16
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2755 = SYSCALL_MM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2754 = SYSCALL
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2753 = SYNC_MMR6
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2752 = SYNC_MM
  { 2, &MipsDescs.OperandInfo[1126] },  // Inst #2751 = SYNCI_MMR6
  { 2, &MipsDescs.OperandInfo[1126] },  // Inst #2750 = SYNCI_MM
  { 2, &MipsDescs.OperandInfo[1126] },  // Inst #2749 = SYNCI
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2748 = SYNC
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #2747 = SW_MMR6
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #2746 = SW_MM
  { 3, &MipsDescs.OperandInfo[911] },  // Inst #2745 = SWXC1_MM
  { 3, &MipsDescs.OperandInfo[911] },  // Inst #2744 = SWXC1
  { 3, &MipsDescs.OperandInfo[908] },  // Inst #2743 = SWSP_MMR6
  { 3, &MipsDescs.OperandInfo[908] },  // Inst #2742 = SWSP_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #2741 = SWR_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #2740 = SWRE_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #2739 = SWRE
  { 3, &MipsDescs.OperandInfo[356] },  // Inst #2738 = SWR64
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #2737 = SWR
  { 4, &MipsDescs.OperandInfo[904] },  // Inst #2736 = SWP_MM
  { 3, &MipsDescs.OperandInfo[349] },  // Inst #2735 = SWM32_MM
  { 3, &MipsDescs.OperandInfo[901] },  // Inst #2734 = SWM16_MMR6
  { 3, &MipsDescs.OperandInfo[901] },  // Inst #2733 = SWM16_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #2732 = SWL_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #2731 = SWLE_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #2730 = SWLE
  { 3, &MipsDescs.OperandInfo[356] },  // Inst #2729 = SWL64
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #2728 = SWL
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #2727 = SWE_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #2726 = SWE
  { 3, &MipsDescs.OperandInfo[891] },  // Inst #2725 = SWDSP_MM
  { 3, &MipsDescs.OperandInfo[891] },  // Inst #2724 = SWDSP
  { 3, &MipsDescs.OperandInfo[849] },  // Inst #2723 = SWC3
  { 3, &MipsDescs.OperandInfo[843] },  // Inst #2722 = SWC2_R6
  { 3, &MipsDescs.OperandInfo[846] },  // Inst #2721 = SWC2_MMR6
  { 3, &MipsDescs.OperandInfo[843] },  // Inst #2720 = SWC2
  { 3, &MipsDescs.OperandInfo[888] },  // Inst #2719 = SWC1_MM
  { 3, &MipsDescs.OperandInfo[888] },  // Inst #2718 = SWC1
  { 3, &MipsDescs.OperandInfo[356] },  // Inst #2717 = SW64
  { 3, &MipsDescs.OperandInfo[1060] },  // Inst #2716 = SW16_MMR6
  { 3, &MipsDescs.OperandInfo[1060] },  // Inst #2715 = SW16_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #2714 = SW
  { 3, &MipsDescs.OperandInfo[867] },  // Inst #2713 = SUXC1_MM
  { 3, &MipsDescs.OperandInfo[867] },  // Inst #2712 = SUXC164
  { 3, &MipsDescs.OperandInfo[864] },  // Inst #2711 = SUXC1
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2710 = SUBu_MM
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2709 = SUBu
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2708 = SUB_MMR6
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2707 = SUB_MM
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #2706 = SUBV_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #2705 = SUBV_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #2704 = SUBV_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #2703 = SUBV_B
  { 3, &MipsDescs.OperandInfo[554] },  // Inst #2702 = SUBVI_W
  { 3, &MipsDescs.OperandInfo[551] },  // Inst #2701 = SUBVI_H
  { 3, &MipsDescs.OperandInfo[548] },  // Inst #2700 = SUBVI_D
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #2699 = SUBVI_B
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2698 = SUBU_S_QB_MM
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2697 = SUBU_S_QB
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2696 = SUBU_S_PH_MMR2
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2695 = SUBU_S_PH
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2694 = SUBU_QB_MM
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2693 = SUBU_QB
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2692 = SUBU_PH_MMR2
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2691 = SUBU_PH
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2690 = SUBU_MMR6
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2689 = SUBUH_R_QB_MMR2
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2688 = SUBUH_R_QB
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2687 = SUBUH_QB_MMR2
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2686 = SUBUH_QB
  { 3, &MipsDescs.OperandInfo[542] },  // Inst #2685 = SUBU16_MMR6
  { 3, &MipsDescs.OperandInfo[542] },  // Inst #2684 = SUBU16_MM
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #2683 = SUBS_U_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #2682 = SUBS_U_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #2681 = SUBS_U_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #2680 = SUBS_U_B
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #2679 = SUBS_S_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #2678 = SUBS_S_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #2677 = SUBS_S_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #2676 = SUBS_S_B
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #2675 = SUBSUU_S_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #2674 = SUBSUU_S_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #2673 = SUBSUU_S_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #2672 = SUBSUU_S_B
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #2671 = SUBSUS_U_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #2670 = SUBSUS_U_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #2669 = SUBSUS_U_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #2668 = SUBSUS_U_B
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2667 = SUBQ_S_W_MM
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2666 = SUBQ_S_W
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2665 = SUBQ_S_PH_MM
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2664 = SUBQ_S_PH
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2663 = SUBQ_PH_MM
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2662 = SUBQ_PH
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2661 = SUBQH_W_MMR2
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2660 = SUBQH_W
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2659 = SUBQH_R_W_MMR2
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2658 = SUBQH_R_W
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2657 = SUBQH_R_PH_MMR2
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2656 = SUBQH_R_PH
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2655 = SUBQH_PH_MMR2
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2654 = SUBQH_PH
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2653 = SUB
  { 3, &MipsDescs.OperandInfo[879] },  // Inst #2652 = ST_W
  { 3, &MipsDescs.OperandInfo[876] },  // Inst #2651 = ST_H
  { 3, &MipsDescs.OperandInfo[873] },  // Inst #2650 = ST_D
  { 3, &MipsDescs.OperandInfo[870] },  // Inst #2649 = ST_B
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2648 = SSNOP_MMR6
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2647 = SSNOP_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2646 = SSNOP
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #2645 = SRL_W
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2644 = SRL_MM
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #2643 = SRL_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #2642 = SRL_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #2641 = SRL_B
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2640 = SRLV_MM
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2639 = SRLV
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #2638 = SRLR_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #2637 = SRLR_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #2636 = SRLR_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #2635 = SRLR_B
  { 3, &MipsDescs.OperandInfo[554] },  // Inst #2634 = SRLRI_W
  { 3, &MipsDescs.OperandInfo[551] },  // Inst #2633 = SRLRI_H
  { 3, &MipsDescs.OperandInfo[548] },  // Inst #2632 = SRLRI_D
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #2631 = SRLRI_B
  { 3, &MipsDescs.OperandInfo[554] },  // Inst #2630 = SRLI_W
  { 3, &MipsDescs.OperandInfo[551] },  // Inst #2629 = SRLI_H
  { 3, &MipsDescs.OperandInfo[548] },  // Inst #2628 = SRLI_D
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #2627 = SRLI_B
  { 3, &MipsDescs.OperandInfo[527] },  // Inst #2626 = SRL16_MMR6
  { 3, &MipsDescs.OperandInfo[527] },  // Inst #2625 = SRL16_MM
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2624 = SRL
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #2623 = SRA_W
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2622 = SRA_MM
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #2621 = SRA_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #2620 = SRA_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #2619 = SRA_B
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2618 = SRAV_MM
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2617 = SRAV
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #2616 = SRAR_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #2615 = SRAR_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #2614 = SRAR_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #2613 = SRAR_B
  { 3, &MipsDescs.OperandInfo[554] },  // Inst #2612 = SRARI_W
  { 3, &MipsDescs.OperandInfo[551] },  // Inst #2611 = SRARI_H
  { 3, &MipsDescs.OperandInfo[548] },  // Inst #2610 = SRARI_D
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #2609 = SRARI_B
  { 3, &MipsDescs.OperandInfo[554] },  // Inst #2608 = SRAI_W
  { 3, &MipsDescs.OperandInfo[551] },  // Inst #2607 = SRAI_H
  { 3, &MipsDescs.OperandInfo[548] },  // Inst #2606 = SRAI_D
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #2605 = SRAI_B
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2604 = SRA
  { 3, &MipsDescs.OperandInfo[1123] },  // Inst #2603 = SPLAT_W
  { 3, &MipsDescs.OperandInfo[1120] },  // Inst #2602 = SPLAT_H
  { 3, &MipsDescs.OperandInfo[1117] },  // Inst #2601 = SPLAT_D
  { 3, &MipsDescs.OperandInfo[1114] },  // Inst #2600 = SPLAT_B
  { 3, &MipsDescs.OperandInfo[554] },  // Inst #2599 = SPLATI_W
  { 3, &MipsDescs.OperandInfo[551] },  // Inst #2598 = SPLATI_H
  { 3, &MipsDescs.OperandInfo[548] },  // Inst #2597 = SPLATI_D
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #2596 = SPLATI_B
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #2595 = SNEi
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #2594 = SNE
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2593 = SLTu_MM
  { 3, &MipsDescs.OperandInfo[1108] },  // Inst #2592 = SLTu64
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2591 = SLTu
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2590 = SLTiu_MM
  { 3, &MipsDescs.OperandInfo[1111] },  // Inst #2589 = SLTiu64
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2588 = SLTiu
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2587 = SLTi_MM
  { 3, &MipsDescs.OperandInfo[1111] },  // Inst #2586 = SLTi64
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2585 = SLTi
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2584 = SLT_MM
  { 3, &MipsDescs.OperandInfo[1108] },  // Inst #2583 = SLT64
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2582 = SLT
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #2581 = SLL_W
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2580 = SLL_MMR6
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2579 = SLL_MM
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #2578 = SLL_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #2577 = SLL_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #2576 = SLL_B
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2575 = SLLV_MM
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2574 = SLLV
  { 3, &MipsDescs.OperandInfo[554] },  // Inst #2573 = SLLI_W
  { 3, &MipsDescs.OperandInfo[551] },  // Inst #2572 = SLLI_H
  { 3, &MipsDescs.OperandInfo[548] },  // Inst #2571 = SLLI_D
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #2570 = SLLI_B
  { 2, &MipsDescs.OperandInfo[377] },  // Inst #2569 = SLL64_64
  { 2, &MipsDescs.OperandInfo[746] },  // Inst #2568 = SLL64_32
  { 3, &MipsDescs.OperandInfo[527] },  // Inst #2567 = SLL16_MMR6
  { 3, &MipsDescs.OperandInfo[527] },  // Inst #2566 = SLL16_MM
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2565 = SLL
  { 4, &MipsDescs.OperandInfo[1104] },  // Inst #2564 = SLD_W
  { 4, &MipsDescs.OperandInfo[1100] },  // Inst #2563 = SLD_H
  { 4, &MipsDescs.OperandInfo[1096] },  // Inst #2562 = SLD_D
  { 4, &MipsDescs.OperandInfo[1092] },  // Inst #2561 = SLD_B
  { 4, &MipsDescs.OperandInfo[602] },  // Inst #2560 = SLDI_W
  { 4, &MipsDescs.OperandInfo[598] },  // Inst #2559 = SLDI_H
  { 4, &MipsDescs.OperandInfo[594] },  // Inst #2558 = SLDI_D
  { 4, &MipsDescs.OperandInfo[590] },  // Inst #2557 = SLDI_B
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2556 = SIGRIE_MMR6
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2555 = SIGRIE
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #2554 = SH_MMR6
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #2553 = SH_MM
  { 3, &MipsDescs.OperandInfo[1089] },  // Inst #2552 = SHRL_QB_MM
  { 3, &MipsDescs.OperandInfo[1089] },  // Inst #2551 = SHRL_QB
  { 3, &MipsDescs.OperandInfo[1089] },  // Inst #2550 = SHRL_PH_MMR2
  { 3, &MipsDescs.OperandInfo[1089] },  // Inst #2549 = SHRL_PH
  { 3, &MipsDescs.OperandInfo[1086] },  // Inst #2548 = SHRLV_QB_MM
  { 3, &MipsDescs.OperandInfo[1086] },  // Inst #2547 = SHRLV_QB
  { 3, &MipsDescs.OperandInfo[1086] },  // Inst #2546 = SHRLV_PH_MMR2
  { 3, &MipsDescs.OperandInfo[1086] },  // Inst #2545 = SHRLV_PH
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2544 = SHRA_R_W_MM
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2543 = SHRA_R_W
  { 3, &MipsDescs.OperandInfo[1089] },  // Inst #2542 = SHRA_R_QB_MMR2
  { 3, &MipsDescs.OperandInfo[1089] },  // Inst #2541 = SHRA_R_QB
  { 3, &MipsDescs.OperandInfo[1089] },  // Inst #2540 = SHRA_R_PH_MM
  { 3, &MipsDescs.OperandInfo[1089] },  // Inst #2539 = SHRA_R_PH
  { 3, &MipsDescs.OperandInfo[1089] },  // Inst #2538 = SHRA_QB_MMR2
  { 3, &MipsDescs.OperandInfo[1089] },  // Inst #2537 = SHRA_QB
  { 3, &MipsDescs.OperandInfo[1089] },  // Inst #2536 = SHRA_PH_MM
  { 3, &MipsDescs.OperandInfo[1089] },  // Inst #2535 = SHRA_PH
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2534 = SHRAV_R_W_MM
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2533 = SHRAV_R_W
  { 3, &MipsDescs.OperandInfo[1086] },  // Inst #2532 = SHRAV_R_QB_MMR2
  { 3, &MipsDescs.OperandInfo[1086] },  // Inst #2531 = SHRAV_R_QB
  { 3, &MipsDescs.OperandInfo[1086] },  // Inst #2530 = SHRAV_R_PH_MM
  { 3, &MipsDescs.OperandInfo[1086] },  // Inst #2529 = SHRAV_R_PH
  { 3, &MipsDescs.OperandInfo[1086] },  // Inst #2528 = SHRAV_QB_MMR2
  { 3, &MipsDescs.OperandInfo[1086] },  // Inst #2527 = SHRAV_QB
  { 3, &MipsDescs.OperandInfo[1086] },  // Inst #2526 = SHRAV_PH_MM
  { 3, &MipsDescs.OperandInfo[1086] },  // Inst #2525 = SHRAV_PH
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2524 = SHLL_S_W_MM
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2523 = SHLL_S_W
  { 3, &MipsDescs.OperandInfo[1089] },  // Inst #2522 = SHLL_S_PH_MM
  { 3, &MipsDescs.OperandInfo[1089] },  // Inst #2521 = SHLL_S_PH
  { 3, &MipsDescs.OperandInfo[1089] },  // Inst #2520 = SHLL_QB_MM
  { 3, &MipsDescs.OperandInfo[1089] },  // Inst #2519 = SHLL_QB
  { 3, &MipsDescs.OperandInfo[1089] },  // Inst #2518 = SHLL_PH_MM
  { 3, &MipsDescs.OperandInfo[1089] },  // Inst #2517 = SHLL_PH
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2516 = SHLLV_S_W_MM
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2515 = SHLLV_S_W
  { 3, &MipsDescs.OperandInfo[1086] },  // Inst #2514 = SHLLV_S_PH_MM
  { 3, &MipsDescs.OperandInfo[1086] },  // Inst #2513 = SHLLV_S_PH
  { 3, &MipsDescs.OperandInfo[1086] },  // Inst #2512 = SHLLV_QB_MM
  { 3, &MipsDescs.OperandInfo[1086] },  // Inst #2511 = SHLLV_QB
  { 3, &MipsDescs.OperandInfo[1086] },  // Inst #2510 = SHLLV_PH_MM
  { 3, &MipsDescs.OperandInfo[1086] },  // Inst #2509 = SHLLV_PH
  { 3, &MipsDescs.OperandInfo[1083] },  // Inst #2508 = SHILO_MM
  { 3, &MipsDescs.OperandInfo[1025] },  // Inst #2507 = SHILOV_MM
  { 3, &MipsDescs.OperandInfo[1025] },  // Inst #2506 = SHILOV
  { 3, &MipsDescs.OperandInfo[1083] },  // Inst #2505 = SHILO
  { 3, &MipsDescs.OperandInfo[554] },  // Inst #2504 = SHF_W
  { 3, &MipsDescs.OperandInfo[551] },  // Inst #2503 = SHF_H
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #2502 = SHF_B
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #2501 = SHE_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #2500 = SHE
  { 3, &MipsDescs.OperandInfo[356] },  // Inst #2499 = SH64
  { 3, &MipsDescs.OperandInfo[1060] },  // Inst #2498 = SH16_MMR6
  { 3, &MipsDescs.OperandInfo[1060] },  // Inst #2497 = SH16_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #2496 = SH
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #2495 = SEQi
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #2494 = SEQ
  { 4, &MipsDescs.OperandInfo[1079] },  // Inst #2493 = SEL_S_MMR6
  { 4, &MipsDescs.OperandInfo[1079] },  // Inst #2492 = SEL_S
  { 4, &MipsDescs.OperandInfo[920] },  // Inst #2491 = SEL_D_MMR6
  { 4, &MipsDescs.OperandInfo[920] },  // Inst #2490 = SEL_D
  { 3, &MipsDescs.OperandInfo[759] },  // Inst #2489 = SELNEZ_S_MMR6
  { 3, &MipsDescs.OperandInfo[759] },  // Inst #2488 = SELNEZ_S
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2487 = SELNEZ_MMR6
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #2486 = SELNEZ_D_MMR6
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #2485 = SELNEZ_D
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #2484 = SELNEZ64
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2483 = SELNEZ
  { 3, &MipsDescs.OperandInfo[759] },  // Inst #2482 = SELEQZ_S_MMR6
  { 3, &MipsDescs.OperandInfo[759] },  // Inst #2481 = SELEQZ_S
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2480 = SELEQZ_MMR6
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #2479 = SELEQZ_D_MMR6
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #2478 = SELEQZ_D
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #2477 = SELEQZ64
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2476 = SELEQZ
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2475 = SEH_MM
  { 2, &MipsDescs.OperandInfo[377] },  // Inst #2474 = SEH64
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2473 = SEH
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2472 = SEB_MM
  { 2, &MipsDescs.OperandInfo[377] },  // Inst #2471 = SEB64
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2470 = SEB
  { 3, &MipsDescs.OperandInfo[867] },  // Inst #2469 = SDXC164
  { 3, &MipsDescs.OperandInfo[864] },  // Inst #2468 = SDXC1
  { 3, &MipsDescs.OperandInfo[356] },  // Inst #2467 = SDR
  { 3, &MipsDescs.OperandInfo[356] },  // Inst #2466 = SDL
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2465 = SDIV_MM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2464 = SDIV
  { 3, &MipsDescs.OperandInfo[849] },  // Inst #2463 = SDC3
  { 3, &MipsDescs.OperandInfo[843] },  // Inst #2462 = SDC2_R6
  { 3, &MipsDescs.OperandInfo[846] },  // Inst #2461 = SDC2_MMR6
  { 3, &MipsDescs.OperandInfo[843] },  // Inst #2460 = SDC2
  { 3, &MipsDescs.OperandInfo[840] },  // Inst #2459 = SDC1_MM_D64
  { 3, &MipsDescs.OperandInfo[492] },  // Inst #2458 = SDC1_MM_D32
  { 3, &MipsDescs.OperandInfo[840] },  // Inst #2457 = SDC1_D64_MMR6
  { 3, &MipsDescs.OperandInfo[840] },  // Inst #2456 = SDC164
  { 3, &MipsDescs.OperandInfo[492] },  // Inst #2455 = SDC1
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2454 = SDBBP_R6
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2453 = SDBBP_MMR6
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2452 = SDBBP_MM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2451 = SDBBP16_MMR6
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2450 = SDBBP16_MM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2449 = SDBBP
  { 3, &MipsDescs.OperandInfo[356] },  // Inst #2448 = SD
  { 4, &MipsDescs.OperandInfo[1067] },  // Inst #2447 = SC_R6
  { 4, &MipsDescs.OperandInfo[1063] },  // Inst #2446 = SC_MMR6
  { 4, &MipsDescs.OperandInfo[1063] },  // Inst #2445 = SC_MM
  { 4, &MipsDescs.OperandInfo[1063] },  // Inst #2444 = SCE_MM
  { 4, &MipsDescs.OperandInfo[1063] },  // Inst #2443 = SCE
  { 4, &MipsDescs.OperandInfo[1075] },  // Inst #2442 = SCD_R6
  { 4, &MipsDescs.OperandInfo[1071] },  // Inst #2441 = SCD
  { 4, &MipsDescs.OperandInfo[1067] },  // Inst #2440 = SC64_R6
  { 4, &MipsDescs.OperandInfo[1063] },  // Inst #2439 = SC64
  { 4, &MipsDescs.OperandInfo[1063] },  // Inst #2438 = SC
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #2437 = SB_MMR6
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #2436 = SB_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #2435 = SBE_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #2434 = SBE
  { 3, &MipsDescs.OperandInfo[356] },  // Inst #2433 = SB64
  { 3, &MipsDescs.OperandInfo[1060] },  // Inst #2432 = SB16_MMR6
  { 3, &MipsDescs.OperandInfo[1060] },  // Inst #2431 = SB16_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #2430 = SB
  { 3, &MipsDescs.OperandInfo[554] },  // Inst #2429 = SAT_U_W
  { 3, &MipsDescs.OperandInfo[551] },  // Inst #2428 = SAT_U_H
  { 3, &MipsDescs.OperandInfo[548] },  // Inst #2427 = SAT_U_D
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #2426 = SAT_U_B
  { 3, &MipsDescs.OperandInfo[554] },  // Inst #2425 = SAT_S_W
  { 3, &MipsDescs.OperandInfo[551] },  // Inst #2424 = SAT_S_H
  { 3, &MipsDescs.OperandInfo[548] },  // Inst #2423 = SAT_S_D
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #2422 = SAT_S_B
  { 2, &MipsDescs.OperandInfo[377] },  // Inst #2421 = SAAD
  { 2, &MipsDescs.OperandInfo[377] },  // Inst #2420 = SAA
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2419 = RestoreX16
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2418 = Restore16
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #2417 = RSQRT_S_MM
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #2416 = RSQRT_S
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #2415 = RSQRT_D64_MM
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #2414 = RSQRT_D64
  { 2, &MipsDescs.OperandInfo[754] },  // Inst #2413 = RSQRT_D32_MM
  { 2, &MipsDescs.OperandInfo[754] },  // Inst #2412 = RSQRT_D32
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #2411 = ROUND_W_S_MMR6
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #2410 = ROUND_W_S_MM
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #2409 = ROUND_W_S
  { 2, &MipsDescs.OperandInfo[627] },  // Inst #2408 = ROUND_W_MM
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #2407 = ROUND_W_D_MMR6
  { 2, &MipsDescs.OperandInfo[629] },  // Inst #2406 = ROUND_W_D64
  { 2, &MipsDescs.OperandInfo[627] },  // Inst #2405 = ROUND_W_D32
  { 2, &MipsDescs.OperandInfo[625] },  // Inst #2404 = ROUND_L_S_MMR6
  { 2, &MipsDescs.OperandInfo[625] },  // Inst #2403 = ROUND_L_S
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #2402 = ROUND_L_D_MMR6
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #2401 = ROUND_L_D64
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2400 = ROTR_MM
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2399 = ROTRV_MM
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2398 = ROTRV
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2397 = ROTR
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #2396 = RINT_S_MMR6
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #2395 = RINT_S
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #2394 = RINT_D_MMR6
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #2393 = RINT_D
  { 2, &MipsDescs.OperandInfo[1058] },  // Inst #2392 = REPL_QB_MM
  { 2, &MipsDescs.OperandInfo[1058] },  // Inst #2391 = REPL_QB
  { 2, &MipsDescs.OperandInfo[1058] },  // Inst #2390 = REPL_PH_MM
  { 2, &MipsDescs.OperandInfo[1058] },  // Inst #2389 = REPL_PH
  { 2, &MipsDescs.OperandInfo[1056] },  // Inst #2388 = REPLV_QB_MM
  { 2, &MipsDescs.OperandInfo[1056] },  // Inst #2387 = REPLV_QB
  { 2, &MipsDescs.OperandInfo[1056] },  // Inst #2386 = REPLV_PH_MM
  { 2, &MipsDescs.OperandInfo[1056] },  // Inst #2385 = REPLV_PH
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #2384 = RECIP_S_MM
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #2383 = RECIP_S
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #2382 = RECIP_D64_MM
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #2381 = RECIP_D64
  { 2, &MipsDescs.OperandInfo[754] },  // Inst #2380 = RECIP_D32_MM
  { 2, &MipsDescs.OperandInfo[754] },  // Inst #2379 = RECIP_D32
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2378 = RDPGPR_MMR6
  { 3, &MipsDescs.OperandInfo[1050] },  // Inst #2377 = RDHWR_MMR6
  { 3, &MipsDescs.OperandInfo[1050] },  // Inst #2376 = RDHWR_MM
  { 3, &MipsDescs.OperandInfo[1053] },  // Inst #2375 = RDHWR64
  { 3, &MipsDescs.OperandInfo[1050] },  // Inst #2374 = RDHWR
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #2373 = RDDSP_MM
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #2372 = RDDSP
  { 2, &MipsDescs.OperandInfo[1038] },  // Inst #2371 = RADDU_W_QB_MM
  { 2, &MipsDescs.OperandInfo[1038] },  // Inst #2370 = RADDU_W_QB
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #2369 = PUU_PS64
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #2368 = PUL_PS64
  { 4, &MipsDescs.OperandInfo[564] },  // Inst #2367 = PREPEND_MMR2
  { 4, &MipsDescs.OperandInfo[564] },  // Inst #2366 = PREPEND
  { 3, &MipsDescs.OperandInfo[620] },  // Inst #2365 = PREF_R6
  { 3, &MipsDescs.OperandInfo[620] },  // Inst #2364 = PREF_MMR6
  { 3, &MipsDescs.OperandInfo[620] },  // Inst #2363 = PREF_MM
  { 3, &MipsDescs.OperandInfo[1047] },  // Inst #2362 = PREFX_MM
  { 3, &MipsDescs.OperandInfo[620] },  // Inst #2361 = PREFE_MM
  { 3, &MipsDescs.OperandInfo[620] },  // Inst #2360 = PREFE
  { 3, &MipsDescs.OperandInfo[620] },  // Inst #2359 = PREF
  { 4, &MipsDescs.OperandInfo[1043] },  // Inst #2358 = PRECR_SRA_R_PH_W_MMR2
  { 4, &MipsDescs.OperandInfo[1043] },  // Inst #2357 = PRECR_SRA_R_PH_W
  { 4, &MipsDescs.OperandInfo[1043] },  // Inst #2356 = PRECR_SRA_PH_W_MMR2
  { 4, &MipsDescs.OperandInfo[1043] },  // Inst #2355 = PRECR_SRA_PH_W
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2354 = PRECR_QB_PH_MMR2
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2353 = PRECR_QB_PH
  { 3, &MipsDescs.OperandInfo[1040] },  // Inst #2352 = PRECRQ_RS_PH_W_MM
  { 3, &MipsDescs.OperandInfo[1040] },  // Inst #2351 = PRECRQ_RS_PH_W
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2350 = PRECRQ_QB_PH_MM
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2349 = PRECRQ_QB_PH
  { 3, &MipsDescs.OperandInfo[1040] },  // Inst #2348 = PRECRQ_PH_W_MM
  { 3, &MipsDescs.OperandInfo[1040] },  // Inst #2347 = PRECRQ_PH_W
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2346 = PRECRQU_S_QB_PH_MM
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2345 = PRECRQU_S_QB_PH
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #2344 = PRECEU_PH_QBR_MM
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #2343 = PRECEU_PH_QBRA_MM
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #2342 = PRECEU_PH_QBRA
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #2341 = PRECEU_PH_QBR
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #2340 = PRECEU_PH_QBL_MM
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #2339 = PRECEU_PH_QBLA_MM
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #2338 = PRECEU_PH_QBLA
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #2337 = PRECEU_PH_QBL
  { 2, &MipsDescs.OperandInfo[1038] },  // Inst #2336 = PRECEQ_W_PHR_MM
  { 2, &MipsDescs.OperandInfo[1038] },  // Inst #2335 = PRECEQ_W_PHR
  { 2, &MipsDescs.OperandInfo[1038] },  // Inst #2334 = PRECEQ_W_PHL_MM
  { 2, &MipsDescs.OperandInfo[1038] },  // Inst #2333 = PRECEQ_W_PHL
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #2332 = PRECEQU_PH_QBR_MM
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #2331 = PRECEQU_PH_QBRA_MM
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #2330 = PRECEQU_PH_QBRA
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #2329 = PRECEQU_PH_QBR
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #2328 = PRECEQU_PH_QBL_MM
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #2327 = PRECEQU_PH_QBLA_MM
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #2326 = PRECEQU_PH_QBLA
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #2325 = PRECEQU_PH_QBL
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2324 = POP
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #2323 = PLU_PS64
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #2322 = PLL_PS64
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2321 = PICK_QB_MM
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2320 = PICK_QB
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2319 = PICK_PH_MM
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2318 = PICK_PH
  { 2, &MipsDescs.OperandInfo[240] },  // Inst #2317 = PCNT_W
  { 2, &MipsDescs.OperandInfo[1034] },  // Inst #2316 = PCNT_H
  { 2, &MipsDescs.OperandInfo[238] },  // Inst #2315 = PCNT_D
  { 2, &MipsDescs.OperandInfo[956] },  // Inst #2314 = PCNT_B
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #2313 = PCKOD_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #2312 = PCKOD_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #2311 = PCKOD_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #2310 = PCKOD_B
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #2309 = PCKEV_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #2308 = PCKEV_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #2307 = PCKEV_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #2306 = PCKEV_B
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2305 = PAUSE_MMR6
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2304 = PAUSE_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2303 = PAUSE
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2302 = PACKRL_PH_MM
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2301 = PACKRL_PH
  { 3, &MipsDescs.OperandInfo[576] },  // Inst #2300 = OrRxRxRy16
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2299 = ORi_MM
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #2298 = ORi64
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2297 = ORi
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #2296 = OR_V
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2295 = OR_MMR6
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2294 = OR_MM
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #2293 = ORI_MMR6
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #2292 = ORI_B
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #2291 = OR64
  { 3, &MipsDescs.OperandInfo[561] },  // Inst #2290 = OR16_MMR6
  { 3, &MipsDescs.OperandInfo[561] },  // Inst #2289 = OR16_MM
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2288 = OR
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #2287 = NotRxRy16
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #2286 = NegRxRy16
  { 2, &MipsDescs.OperandInfo[1036] },  // Inst #2285 = NOT16_MMR6
  { 2, &MipsDescs.OperandInfo[1036] },  // Inst #2284 = NOT16_MM
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #2283 = NOR_V
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2282 = NOR_MMR6
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2281 = NOR_MM
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #2280 = NORI_B
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #2279 = NOR64
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2278 = NOR
  { 4, &MipsDescs.OperandInfo[936] },  // Inst #2277 = NMSUB_S_MM
  { 4, &MipsDescs.OperandInfo[936] },  // Inst #2276 = NMSUB_S
  { 4, &MipsDescs.OperandInfo[932] },  // Inst #2275 = NMSUB_D64
  { 4, &MipsDescs.OperandInfo[928] },  // Inst #2274 = NMSUB_D32_MM
  { 4, &MipsDescs.OperandInfo[928] },  // Inst #2273 = NMSUB_D32
  { 4, &MipsDescs.OperandInfo[936] },  // Inst #2272 = NMADD_S_MM
  { 4, &MipsDescs.OperandInfo[936] },  // Inst #2271 = NMADD_S
  { 4, &MipsDescs.OperandInfo[932] },  // Inst #2270 = NMADD_D64
  { 4, &MipsDescs.OperandInfo[928] },  // Inst #2269 = NMADD_D32_MM
  { 4, &MipsDescs.OperandInfo[928] },  // Inst #2268 = NMADD_D32
  { 2, &MipsDescs.OperandInfo[240] },  // Inst #2267 = NLZC_W
  { 2, &MipsDescs.OperandInfo[1034] },  // Inst #2266 = NLZC_H
  { 2, &MipsDescs.OperandInfo[238] },  // Inst #2265 = NLZC_D
  { 2, &MipsDescs.OperandInfo[956] },  // Inst #2264 = NLZC_B
  { 2, &MipsDescs.OperandInfo[240] },  // Inst #2263 = NLOC_W
  { 2, &MipsDescs.OperandInfo[1034] },  // Inst #2262 = NLOC_H
  { 2, &MipsDescs.OperandInfo[238] },  // Inst #2261 = NLOC_D
  { 2, &MipsDescs.OperandInfo[956] },  // Inst #2260 = NLOC_B
  { 2, &MipsDescs.OperandInfo[1032] },  // Inst #2259 = MoveR3216
  { 2, &MipsDescs.OperandInfo[1030] },  // Inst #2258 = Move32R16
  { 1, &MipsDescs.OperandInfo[833] },  // Inst #2257 = Mflo16
  { 1, &MipsDescs.OperandInfo[833] },  // Inst #2256 = Mfhi16
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2255 = MUL_S_PH_MMR2
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2254 = MUL_S_PH
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2253 = MUL_R6
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #2252 = MUL_Q_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #2251 = MUL_Q_H
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2250 = MUL_PH_MMR2
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2249 = MUL_PH
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2248 = MUL_MMR6
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2247 = MUL_MM
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #2246 = MULV_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #2245 = MULV_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #2244 = MULV_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #2243 = MULV_B
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2242 = MULU_MMR6
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2241 = MULU
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2240 = MULTu_MM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2239 = MULTu
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2238 = MULT_MM
  { 3, &MipsDescs.OperandInfo[436] },  // Inst #2237 = MULT_DSP_MM
  { 3, &MipsDescs.OperandInfo[436] },  // Inst #2236 = MULT_DSP
  { 3, &MipsDescs.OperandInfo[436] },  // Inst #2235 = MULTU_DSP_MM
  { 3, &MipsDescs.OperandInfo[436] },  // Inst #2234 = MULTU_DSP
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2233 = MULT
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #2232 = MULSA_W_PH_MMR2
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #2231 = MULSA_W_PH
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #2230 = MULSAQ_S_W_PH_MM
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #2229 = MULSAQ_S_W_PH
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #2228 = MULR_Q_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #2227 = MULR_Q_H
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #2226 = MULR_PS64
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2225 = MULQ_S_W_MMR2
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2224 = MULQ_S_W
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2223 = MULQ_S_PH_MMR2
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2222 = MULQ_S_PH
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2221 = MULQ_RS_W_MMR2
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2220 = MULQ_RS_W
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2219 = MULQ_RS_PH_MM
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2218 = MULQ_RS_PH
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2217 = MULEU_S_PH_QBR_MM
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2216 = MULEU_S_PH_QBR
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2215 = MULEU_S_PH_QBL_MM
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #2214 = MULEU_S_PH_QBL
  { 3, &MipsDescs.OperandInfo[651] },  // Inst #2213 = MULEQ_S_W_PHR_MM
  { 3, &MipsDescs.OperandInfo[651] },  // Inst #2212 = MULEQ_S_W_PHR
  { 3, &MipsDescs.OperandInfo[651] },  // Inst #2211 = MULEQ_S_W_PHL_MM
  { 3, &MipsDescs.OperandInfo[651] },  // Inst #2210 = MULEQ_S_W_PHL
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2209 = MUL
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2208 = MUH_MMR6
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2207 = MUHU_MMR6
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2206 = MUHU
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2205 = MUH
  { 5, &MipsDescs.OperandInfo[947] },  // Inst #2204 = MTTR
  { 1, &MipsDescs.OperandInfo[306] },  // Inst #2203 = MTP2
  { 1, &MipsDescs.OperandInfo[306] },  // Inst #2202 = MTP1
  { 1, &MipsDescs.OperandInfo[306] },  // Inst #2201 = MTP0
  { 1, &MipsDescs.OperandInfo[306] },  // Inst #2200 = MTM2
  { 1, &MipsDescs.OperandInfo[306] },  // Inst #2199 = MTM1
  { 1, &MipsDescs.OperandInfo[306] },  // Inst #2198 = MTM0
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #2197 = MTLO_MM
  { 2, &MipsDescs.OperandInfo[1028] },  // Inst #2196 = MTLO_DSP_MM
  { 2, &MipsDescs.OperandInfo[1028] },  // Inst #2195 = MTLO_DSP
  { 1, &MipsDescs.OperandInfo[306] },  // Inst #2194 = MTLO64
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #2193 = MTLO
  { 3, &MipsDescs.OperandInfo[1025] },  // Inst #2192 = MTHLIP_MM
  { 3, &MipsDescs.OperandInfo[1025] },  // Inst #2191 = MTHLIP
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #2190 = MTHI_MM
  { 2, &MipsDescs.OperandInfo[1023] },  // Inst #2189 = MTHI_DSP_MM
  { 2, &MipsDescs.OperandInfo[1023] },  // Inst #2188 = MTHI_DSP
  { 1, &MipsDescs.OperandInfo[306] },  // Inst #2187 = MTHI64
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #2186 = MTHI
  { 3, &MipsDescs.OperandInfo[389] },  // Inst #2185 = MTHGC0_MM
  { 3, &MipsDescs.OperandInfo[389] },  // Inst #2184 = MTHGC0
  { 2, &MipsDescs.OperandInfo[674] },  // Inst #2183 = MTHC2_MMR6
  { 3, &MipsDescs.OperandInfo[1020] },  // Inst #2182 = MTHC1_D64_MM
  { 3, &MipsDescs.OperandInfo[1020] },  // Inst #2181 = MTHC1_D64
  { 3, &MipsDescs.OperandInfo[1017] },  // Inst #2180 = MTHC1_D32_MM
  { 3, &MipsDescs.OperandInfo[1017] },  // Inst #2179 = MTHC1_D32
  { 3, &MipsDescs.OperandInfo[389] },  // Inst #2178 = MTHC0_MMR6
  { 3, &MipsDescs.OperandInfo[389] },  // Inst #2177 = MTGC0_MM
  { 3, &MipsDescs.OperandInfo[389] },  // Inst #2176 = MTGC0
  { 2, &MipsDescs.OperandInfo[674] },  // Inst #2175 = MTC2_MMR6
  { 3, &MipsDescs.OperandInfo[1014] },  // Inst #2174 = MTC2
  { 2, &MipsDescs.OperandInfo[392] },  // Inst #2173 = MTC1_MMR6
  { 2, &MipsDescs.OperandInfo[392] },  // Inst #2172 = MTC1_MM
  { 2, &MipsDescs.OperandInfo[406] },  // Inst #2171 = MTC1_D64_MM
  { 2, &MipsDescs.OperandInfo[406] },  // Inst #2170 = MTC1_D64
  { 2, &MipsDescs.OperandInfo[392] },  // Inst #2169 = MTC1
  { 3, &MipsDescs.OperandInfo[389] },  // Inst #2168 = MTC0_MMR6
  { 3, &MipsDescs.OperandInfo[389] },  // Inst #2167 = MTC0
  { 4, &MipsDescs.OperandInfo[936] },  // Inst #2166 = MSUB_S_MM
  { 4, &MipsDescs.OperandInfo[936] },  // Inst #2165 = MSUB_S
  { 4, &MipsDescs.OperandInfo[190] },  // Inst #2164 = MSUB_Q_W
  { 4, &MipsDescs.OperandInfo[194] },  // Inst #2163 = MSUB_Q_H
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2162 = MSUB_MM
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #2161 = MSUB_DSP_MM
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #2160 = MSUB_DSP
  { 4, &MipsDescs.OperandInfo[932] },  // Inst #2159 = MSUB_D64
  { 4, &MipsDescs.OperandInfo[928] },  // Inst #2158 = MSUB_D32_MM
  { 4, &MipsDescs.OperandInfo[928] },  // Inst #2157 = MSUB_D32
  { 4, &MipsDescs.OperandInfo[190] },  // Inst #2156 = MSUBV_W
  { 4, &MipsDescs.OperandInfo[194] },  // Inst #2155 = MSUBV_H
  { 4, &MipsDescs.OperandInfo[186] },  // Inst #2154 = MSUBV_D
  { 4, &MipsDescs.OperandInfo[606] },  // Inst #2153 = MSUBV_B
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2152 = MSUBU_MM
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #2151 = MSUBU_DSP_MM
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #2150 = MSUBU_DSP
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2149 = MSUBU
  { 4, &MipsDescs.OperandInfo[190] },  // Inst #2148 = MSUBR_Q_W
  { 4, &MipsDescs.OperandInfo[194] },  // Inst #2147 = MSUBR_Q_H
  { 4, &MipsDescs.OperandInfo[924] },  // Inst #2146 = MSUBF_S_MMR6
  { 4, &MipsDescs.OperandInfo[924] },  // Inst #2145 = MSUBF_S
  { 4, &MipsDescs.OperandInfo[920] },  // Inst #2144 = MSUBF_D_MMR6
  { 4, &MipsDescs.OperandInfo[920] },  // Inst #2143 = MSUBF_D
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2142 = MSUB
  { 4, &MipsDescs.OperandInfo[1010] },  // Inst #2141 = MOVZ_I_S_MM
  { 4, &MipsDescs.OperandInfo[1010] },  // Inst #2140 = MOVZ_I_S
  { 4, &MipsDescs.OperandInfo[1002] },  // Inst #2139 = MOVZ_I_MM
  { 4, &MipsDescs.OperandInfo[1006] },  // Inst #2138 = MOVZ_I_I64
  { 4, &MipsDescs.OperandInfo[1002] },  // Inst #2137 = MOVZ_I_I
  { 4, &MipsDescs.OperandInfo[998] },  // Inst #2136 = MOVZ_I_D64
  { 4, &MipsDescs.OperandInfo[994] },  // Inst #2135 = MOVZ_I_D32_MM
  { 4, &MipsDescs.OperandInfo[994] },  // Inst #2134 = MOVZ_I_D32
  { 4, &MipsDescs.OperandInfo[990] },  // Inst #2133 = MOVZ_I64_S
  { 4, &MipsDescs.OperandInfo[986] },  // Inst #2132 = MOVZ_I64_I64
  { 4, &MipsDescs.OperandInfo[982] },  // Inst #2131 = MOVZ_I64_I
  { 4, &MipsDescs.OperandInfo[978] },  // Inst #2130 = MOVZ_I64_D64
  { 4, &MipsDescs.OperandInfo[974] },  // Inst #2129 = MOVT_S_MM
  { 4, &MipsDescs.OperandInfo[974] },  // Inst #2128 = MOVT_S
  { 4, &MipsDescs.OperandInfo[966] },  // Inst #2127 = MOVT_I_MM
  { 4, &MipsDescs.OperandInfo[970] },  // Inst #2126 = MOVT_I64
  { 4, &MipsDescs.OperandInfo[966] },  // Inst #2125 = MOVT_I
  { 4, &MipsDescs.OperandInfo[962] },  // Inst #2124 = MOVT_D64
  { 4, &MipsDescs.OperandInfo[958] },  // Inst #2123 = MOVT_D32_MM
  { 4, &MipsDescs.OperandInfo[958] },  // Inst #2122 = MOVT_D32
  { 4, &MipsDescs.OperandInfo[1010] },  // Inst #2121 = MOVN_I_S_MM
  { 4, &MipsDescs.OperandInfo[1010] },  // Inst #2120 = MOVN_I_S
  { 4, &MipsDescs.OperandInfo[1002] },  // Inst #2119 = MOVN_I_MM
  { 4, &MipsDescs.OperandInfo[1006] },  // Inst #2118 = MOVN_I_I64
  { 4, &MipsDescs.OperandInfo[1002] },  // Inst #2117 = MOVN_I_I
  { 4, &MipsDescs.OperandInfo[998] },  // Inst #2116 = MOVN_I_D64
  { 4, &MipsDescs.OperandInfo[994] },  // Inst #2115 = MOVN_I_D32_MM
  { 4, &MipsDescs.OperandInfo[994] },  // Inst #2114 = MOVN_I_D32
  { 4, &MipsDescs.OperandInfo[990] },  // Inst #2113 = MOVN_I64_S
  { 4, &MipsDescs.OperandInfo[986] },  // Inst #2112 = MOVN_I64_I64
  { 4, &MipsDescs.OperandInfo[982] },  // Inst #2111 = MOVN_I64_I
  { 4, &MipsDescs.OperandInfo[978] },  // Inst #2110 = MOVN_I64_D64
  { 4, &MipsDescs.OperandInfo[974] },  // Inst #2109 = MOVF_S_MM
  { 4, &MipsDescs.OperandInfo[974] },  // Inst #2108 = MOVF_S
  { 4, &MipsDescs.OperandInfo[966] },  // Inst #2107 = MOVF_I_MM
  { 4, &MipsDescs.OperandInfo[970] },  // Inst #2106 = MOVF_I64
  { 4, &MipsDescs.OperandInfo[966] },  // Inst #2105 = MOVF_I
  { 4, &MipsDescs.OperandInfo[962] },  // Inst #2104 = MOVF_D64
  { 4, &MipsDescs.OperandInfo[958] },  // Inst #2103 = MOVF_D32_MM
  { 4, &MipsDescs.OperandInfo[958] },  // Inst #2102 = MOVF_D32
  { 2, &MipsDescs.OperandInfo[956] },  // Inst #2101 = MOVE_V
  { 4, &MipsDescs.OperandInfo[952] },  // Inst #2100 = MOVEP_MMR6
  { 4, &MipsDescs.OperandInfo[952] },  // Inst #2099 = MOVEP_MM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2098 = MOVE16_MMR6
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2097 = MOVE16_MM
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #2096 = MOD_U_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #2095 = MOD_U_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #2094 = MOD_U_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #2093 = MOD_U_B
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #2092 = MOD_S_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #2091 = MOD_S_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #2090 = MOD_S_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #2089 = MOD_S_B
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2088 = MOD_MMR6
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2087 = MODU_MMR6
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2086 = MODU
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2085 = MODSUB_MM
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2084 = MODSUB
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #2083 = MOD
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #2082 = MIN_U_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #2081 = MIN_U_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #2080 = MIN_U_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #2079 = MIN_U_B
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #2078 = MIN_S_W
  { 3, &MipsDescs.OperandInfo[759] },  // Inst #2077 = MIN_S_MMR6
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #2076 = MIN_S_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #2075 = MIN_S_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #2074 = MIN_S_B
  { 3, &MipsDescs.OperandInfo[759] },  // Inst #2073 = MIN_S
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #2072 = MIN_D_MMR6
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #2071 = MIN_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #2070 = MIN_A_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #2069 = MIN_A_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #2068 = MIN_A_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #2067 = MIN_A_B
  { 3, &MipsDescs.OperandInfo[554] },  // Inst #2066 = MINI_U_W
  { 3, &MipsDescs.OperandInfo[551] },  // Inst #2065 = MINI_U_H
  { 3, &MipsDescs.OperandInfo[548] },  // Inst #2064 = MINI_U_D
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #2063 = MINI_U_B
  { 3, &MipsDescs.OperandInfo[554] },  // Inst #2062 = MINI_S_W
  { 3, &MipsDescs.OperandInfo[551] },  // Inst #2061 = MINI_S_H
  { 3, &MipsDescs.OperandInfo[548] },  // Inst #2060 = MINI_S_D
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #2059 = MINI_S_B
  { 3, &MipsDescs.OperandInfo[759] },  // Inst #2058 = MINA_S_MMR6
  { 3, &MipsDescs.OperandInfo[759] },  // Inst #2057 = MINA_S
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #2056 = MINA_D_MMR6
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #2055 = MINA_D
  { 5, &MipsDescs.OperandInfo[947] },  // Inst #2054 = MFTR
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #2053 = MFLO_MM
  { 2, &MipsDescs.OperandInfo[370] },  // Inst #2052 = MFLO_DSP_MM
  { 2, &MipsDescs.OperandInfo[370] },  // Inst #2051 = MFLO_DSP
  { 1, &MipsDescs.OperandInfo[306] },  // Inst #2050 = MFLO64
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #2049 = MFLO16_MM
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #2048 = MFLO
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #2047 = MFHI_MM
  { 2, &MipsDescs.OperandInfo[370] },  // Inst #2046 = MFHI_DSP_MM
  { 2, &MipsDescs.OperandInfo[370] },  // Inst #2045 = MFHI_DSP
  { 1, &MipsDescs.OperandInfo[306] },  // Inst #2044 = MFHI64
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #2043 = MFHI16_MM
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #2042 = MFHI
  { 3, &MipsDescs.OperandInfo[372] },  // Inst #2041 = MFHGC0_MM
  { 3, &MipsDescs.OperandInfo[372] },  // Inst #2040 = MFHGC0
  { 2, &MipsDescs.OperandInfo[635] },  // Inst #2039 = MFHC2_MMR6
  { 2, &MipsDescs.OperandInfo[940] },  // Inst #2038 = MFHC1_D64_MM
  { 2, &MipsDescs.OperandInfo[940] },  // Inst #2037 = MFHC1_D64
  { 2, &MipsDescs.OperandInfo[945] },  // Inst #2036 = MFHC1_D32_MM
  { 2, &MipsDescs.OperandInfo[945] },  // Inst #2035 = MFHC1_D32
  { 3, &MipsDescs.OperandInfo[372] },  // Inst #2034 = MFHC0_MMR6
  { 3, &MipsDescs.OperandInfo[372] },  // Inst #2033 = MFGC0_MM
  { 3, &MipsDescs.OperandInfo[372] },  // Inst #2032 = MFGC0
  { 2, &MipsDescs.OperandInfo[635] },  // Inst #2031 = MFC2_MMR6
  { 3, &MipsDescs.OperandInfo[942] },  // Inst #2030 = MFC2
  { 2, &MipsDescs.OperandInfo[375] },  // Inst #2029 = MFC1_MMR6
  { 2, &MipsDescs.OperandInfo[375] },  // Inst #2028 = MFC1_MM
  { 2, &MipsDescs.OperandInfo[940] },  // Inst #2027 = MFC1_D64
  { 2, &MipsDescs.OperandInfo[375] },  // Inst #2026 = MFC1
  { 3, &MipsDescs.OperandInfo[372] },  // Inst #2025 = MFC0_MMR6
  { 3, &MipsDescs.OperandInfo[372] },  // Inst #2024 = MFC0
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #2023 = MAX_U_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #2022 = MAX_U_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #2021 = MAX_U_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #2020 = MAX_U_B
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #2019 = MAX_S_W
  { 3, &MipsDescs.OperandInfo[759] },  // Inst #2018 = MAX_S_MMR6
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #2017 = MAX_S_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #2016 = MAX_S_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #2015 = MAX_S_B
  { 3, &MipsDescs.OperandInfo[759] },  // Inst #2014 = MAX_S
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #2013 = MAX_D_MMR6
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #2012 = MAX_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #2011 = MAX_A_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #2010 = MAX_A_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #2009 = MAX_A_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #2008 = MAX_A_B
  { 3, &MipsDescs.OperandInfo[554] },  // Inst #2007 = MAXI_U_W
  { 3, &MipsDescs.OperandInfo[551] },  // Inst #2006 = MAXI_U_H
  { 3, &MipsDescs.OperandInfo[548] },  // Inst #2005 = MAXI_U_D
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #2004 = MAXI_U_B
  { 3, &MipsDescs.OperandInfo[554] },  // Inst #2003 = MAXI_S_W
  { 3, &MipsDescs.OperandInfo[551] },  // Inst #2002 = MAXI_S_H
  { 3, &MipsDescs.OperandInfo[548] },  // Inst #2001 = MAXI_S_D
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #2000 = MAXI_S_B
  { 3, &MipsDescs.OperandInfo[759] },  // Inst #1999 = MAXA_S_MMR6
  { 3, &MipsDescs.OperandInfo[759] },  // Inst #1998 = MAXA_S
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #1997 = MAXA_D_MMR6
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #1996 = MAXA_D
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1995 = MAQ_S_W_PHR_MM
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1994 = MAQ_S_W_PHR
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1993 = MAQ_S_W_PHL_MM
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1992 = MAQ_S_W_PHL
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1991 = MAQ_SA_W_PHR_MM
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1990 = MAQ_SA_W_PHR
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1989 = MAQ_SA_W_PHL_MM
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1988 = MAQ_SA_W_PHL
  { 4, &MipsDescs.OperandInfo[936] },  // Inst #1987 = MADD_S_MM
  { 4, &MipsDescs.OperandInfo[936] },  // Inst #1986 = MADD_S
  { 4, &MipsDescs.OperandInfo[190] },  // Inst #1985 = MADD_Q_W
  { 4, &MipsDescs.OperandInfo[194] },  // Inst #1984 = MADD_Q_H
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1983 = MADD_MM
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1982 = MADD_DSP_MM
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1981 = MADD_DSP
  { 4, &MipsDescs.OperandInfo[932] },  // Inst #1980 = MADD_D64
  { 4, &MipsDescs.OperandInfo[928] },  // Inst #1979 = MADD_D32_MM
  { 4, &MipsDescs.OperandInfo[928] },  // Inst #1978 = MADD_D32
  { 4, &MipsDescs.OperandInfo[190] },  // Inst #1977 = MADDV_W
  { 4, &MipsDescs.OperandInfo[194] },  // Inst #1976 = MADDV_H
  { 4, &MipsDescs.OperandInfo[186] },  // Inst #1975 = MADDV_D
  { 4, &MipsDescs.OperandInfo[606] },  // Inst #1974 = MADDV_B
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1973 = MADDU_MM
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1972 = MADDU_DSP_MM
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1971 = MADDU_DSP
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1970 = MADDU
  { 4, &MipsDescs.OperandInfo[190] },  // Inst #1969 = MADDR_Q_W
  { 4, &MipsDescs.OperandInfo[194] },  // Inst #1968 = MADDR_Q_H
  { 4, &MipsDescs.OperandInfo[924] },  // Inst #1967 = MADDF_S_MMR6
  { 4, &MipsDescs.OperandInfo[924] },  // Inst #1966 = MADDF_S
  { 4, &MipsDescs.OperandInfo[920] },  // Inst #1965 = MADDF_D_MMR6
  { 4, &MipsDescs.OperandInfo[920] },  // Inst #1964 = MADDF_D
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1963 = MADD
  { 3, &MipsDescs.OperandInfo[573] },  // Inst #1962 = LwRxSpImmX16
  { 3, &MipsDescs.OperandInfo[914] },  // Inst #1961 = LwRxRyOffMemX16
  { 3, &MipsDescs.OperandInfo[917] },  // Inst #1960 = LwRxPcTcpX16
  { 3, &MipsDescs.OperandInfo[917] },  // Inst #1959 = LwRxPcTcp16
  { 2, &MipsDescs.OperandInfo[568] },  // Inst #1958 = LiRxImmX16
  { 2, &MipsDescs.OperandInfo[568] },  // Inst #1957 = LiRxImmAlignX16
  { 2, &MipsDescs.OperandInfo[568] },  // Inst #1956 = LiRxImm16
  { 3, &MipsDescs.OperandInfo[914] },  // Inst #1955 = LhuRxRyOffMemX16
  { 3, &MipsDescs.OperandInfo[914] },  // Inst #1954 = LhRxRyOffMemX16
  { 3, &MipsDescs.OperandInfo[914] },  // Inst #1953 = LbuRxRyOffMemX16
  { 3, &MipsDescs.OperandInfo[914] },  // Inst #1952 = LbRxRyOffMemX16
  { 3, &MipsDescs.OperandInfo[356] },  // Inst #1951 = LWu
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1950 = LW_MMR6
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1949 = LW_MM
  { 3, &MipsDescs.OperandInfo[837] },  // Inst #1948 = LWX_MM
  { 3, &MipsDescs.OperandInfo[837] },  // Inst #1947 = LWXS_MM
  { 3, &MipsDescs.OperandInfo[911] },  // Inst #1946 = LWXC1_MM
  { 3, &MipsDescs.OperandInfo[911] },  // Inst #1945 = LWXC1
  { 3, &MipsDescs.OperandInfo[837] },  // Inst #1944 = LWX
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1943 = LWU_MM
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #1942 = LWUPC
  { 3, &MipsDescs.OperandInfo[908] },  // Inst #1941 = LWSP_MM
  { 4, &MipsDescs.OperandInfo[897] },  // Inst #1940 = LWR_MM
  { 4, &MipsDescs.OperandInfo[897] },  // Inst #1939 = LWRE_MM
  { 4, &MipsDescs.OperandInfo[897] },  // Inst #1938 = LWRE
  { 4, &MipsDescs.OperandInfo[860] },  // Inst #1937 = LWR64
  { 4, &MipsDescs.OperandInfo[897] },  // Inst #1936 = LWR
  { 4, &MipsDescs.OperandInfo[904] },  // Inst #1935 = LWP_MM
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #1934 = LWPC_MMR6
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #1933 = LWPC
  { 3, &MipsDescs.OperandInfo[349] },  // Inst #1932 = LWM32_MM
  { 3, &MipsDescs.OperandInfo[901] },  // Inst #1931 = LWM16_MMR6
  { 3, &MipsDescs.OperandInfo[901] },  // Inst #1930 = LWM16_MM
  { 4, &MipsDescs.OperandInfo[897] },  // Inst #1929 = LWL_MM
  { 4, &MipsDescs.OperandInfo[897] },  // Inst #1928 = LWLE_MM
  { 4, &MipsDescs.OperandInfo[897] },  // Inst #1927 = LWLE
  { 4, &MipsDescs.OperandInfo[860] },  // Inst #1926 = LWL64
  { 4, &MipsDescs.OperandInfo[897] },  // Inst #1925 = LWL
  { 3, &MipsDescs.OperandInfo[894] },  // Inst #1924 = LWGP_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1923 = LWE_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1922 = LWE
  { 3, &MipsDescs.OperandInfo[891] },  // Inst #1921 = LWDSP_MM
  { 3, &MipsDescs.OperandInfo[891] },  // Inst #1920 = LWDSP
  { 3, &MipsDescs.OperandInfo[849] },  // Inst #1919 = LWC3
  { 3, &MipsDescs.OperandInfo[843] },  // Inst #1918 = LWC2_R6
  { 3, &MipsDescs.OperandInfo[846] },  // Inst #1917 = LWC2_MMR6
  { 3, &MipsDescs.OperandInfo[843] },  // Inst #1916 = LWC2
  { 3, &MipsDescs.OperandInfo[888] },  // Inst #1915 = LWC1_MM
  { 3, &MipsDescs.OperandInfo[888] },  // Inst #1914 = LWC1
  { 3, &MipsDescs.OperandInfo[356] },  // Inst #1913 = LW64
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #1912 = LW16_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1911 = LW
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #1910 = LUi_MM
  { 2, &MipsDescs.OperandInfo[354] },  // Inst #1909 = LUi64
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #1908 = LUi
  { 3, &MipsDescs.OperandInfo[867] },  // Inst #1907 = LUXC1_MM
  { 3, &MipsDescs.OperandInfo[867] },  // Inst #1906 = LUXC164
  { 3, &MipsDescs.OperandInfo[864] },  // Inst #1905 = LUXC1
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #1904 = LUI_MMR6
  { 4, &MipsDescs.OperandInfo[557] },  // Inst #1903 = LSA_R6
  { 4, &MipsDescs.OperandInfo[557] },  // Inst #1902 = LSA_MMR6
  { 4, &MipsDescs.OperandInfo[557] },  // Inst #1901 = LSA
  { 3, &MipsDescs.OperandInfo[882] },  // Inst #1900 = LL_R6
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1899 = LL_MMR6
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1898 = LL_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1897 = LLE_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1896 = LLE
  { 3, &MipsDescs.OperandInfo[885] },  // Inst #1895 = LLD_R6
  { 3, &MipsDescs.OperandInfo[356] },  // Inst #1894 = LLD
  { 3, &MipsDescs.OperandInfo[882] },  // Inst #1893 = LL64_R6
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1892 = LL64
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1891 = LL
  { 2, &MipsDescs.OperandInfo[525] },  // Inst #1890 = LI16_MMR6
  { 2, &MipsDescs.OperandInfo[525] },  // Inst #1889 = LI16_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1888 = LHu_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1887 = LHuE_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1886 = LHuE
  { 3, &MipsDescs.OperandInfo[356] },  // Inst #1885 = LHu64
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1884 = LHu
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1883 = LH_MM
  { 3, &MipsDescs.OperandInfo[837] },  // Inst #1882 = LHX_MM
  { 3, &MipsDescs.OperandInfo[837] },  // Inst #1881 = LHX
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #1880 = LHU16_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1879 = LHE_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1878 = LHE
  { 3, &MipsDescs.OperandInfo[356] },  // Inst #1877 = LH64
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1876 = LH
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1875 = LEA_ADDiu_MM
  { 3, &MipsDescs.OperandInfo[356] },  // Inst #1874 = LEA_ADDiu64
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1873 = LEA_ADDiu
  { 3, &MipsDescs.OperandInfo[879] },  // Inst #1872 = LD_W
  { 3, &MipsDescs.OperandInfo[876] },  // Inst #1871 = LD_H
  { 3, &MipsDescs.OperandInfo[873] },  // Inst #1870 = LD_D
  { 3, &MipsDescs.OperandInfo[870] },  // Inst #1869 = LD_B
  { 3, &MipsDescs.OperandInfo[867] },  // Inst #1868 = LDXC164
  { 3, &MipsDescs.OperandInfo[864] },  // Inst #1867 = LDXC1
  { 4, &MipsDescs.OperandInfo[860] },  // Inst #1866 = LDR
  { 2, &MipsDescs.OperandInfo[354] },  // Inst #1865 = LDPC
  { 4, &MipsDescs.OperandInfo[860] },  // Inst #1864 = LDL
  { 2, &MipsDescs.OperandInfo[858] },  // Inst #1863 = LDI_W
  { 2, &MipsDescs.OperandInfo[856] },  // Inst #1862 = LDI_H
  { 2, &MipsDescs.OperandInfo[854] },  // Inst #1861 = LDI_D
  { 2, &MipsDescs.OperandInfo[852] },  // Inst #1860 = LDI_B
  { 3, &MipsDescs.OperandInfo[849] },  // Inst #1859 = LDC3
  { 3, &MipsDescs.OperandInfo[843] },  // Inst #1858 = LDC2_R6
  { 3, &MipsDescs.OperandInfo[846] },  // Inst #1857 = LDC2_MMR6
  { 3, &MipsDescs.OperandInfo[843] },  // Inst #1856 = LDC2
  { 3, &MipsDescs.OperandInfo[840] },  // Inst #1855 = LDC1_MM_D64
  { 3, &MipsDescs.OperandInfo[492] },  // Inst #1854 = LDC1_MM_D32
  { 3, &MipsDescs.OperandInfo[840] },  // Inst #1853 = LDC1_D64_MMR6
  { 3, &MipsDescs.OperandInfo[840] },  // Inst #1852 = LDC164
  { 3, &MipsDescs.OperandInfo[492] },  // Inst #1851 = LDC1
  { 3, &MipsDescs.OperandInfo[356] },  // Inst #1850 = LD
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1849 = LBu_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1848 = LBuE_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1847 = LBuE
  { 3, &MipsDescs.OperandInfo[356] },  // Inst #1846 = LBu64
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1845 = LBu
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1844 = LB_MMR6
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1843 = LB_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1842 = LBU_MMR6
  { 3, &MipsDescs.OperandInfo[837] },  // Inst #1841 = LBUX_MM
  { 3, &MipsDescs.OperandInfo[837] },  // Inst #1840 = LBUX
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #1839 = LBU16_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1838 = LBE_MM
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1837 = LBE
  { 3, &MipsDescs.OperandInfo[356] },  // Inst #1836 = LB64
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #1835 = LB
  { 1, &MipsDescs.OperandInfo[833] },  // Inst #1834 = JumpLinkReg16
  { 1, &MipsDescs.OperandInfo[833] },  // Inst #1833 = JrcRx16
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1832 = JrcRa16
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1831 = JrRa16
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1830 = JalB16
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1829 = Jal16
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1828 = J_MM
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1827 = JR_MM
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1826 = JR_HB_R6
  { 1, &MipsDescs.OperandInfo[306] },  // Inst #1825 = JR_HB64_R6
  { 1, &MipsDescs.OperandInfo[306] },  // Inst #1824 = JR_HB64
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1823 = JR_HB
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1822 = JRCADDIUSP_MMR6
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1821 = JRC16_MMR6
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1820 = JRC16_MM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1819 = JRADDIUSP
  { 1, &MipsDescs.OperandInfo[306] },  // Inst #1818 = JR64
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1817 = JR16_MM
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1816 = JR
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #1815 = JIC_MMR6
  { 2, &MipsDescs.OperandInfo[354] },  // Inst #1814 = JIC64
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #1813 = JIC
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #1812 = JIALC_MMR6
  { 2, &MipsDescs.OperandInfo[354] },  // Inst #1811 = JIALC64
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #1810 = JIALC
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1809 = JAL_MM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1808 = JALX_MM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1807 = JALX
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1806 = JALS_MM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1805 = JALR_MM
  { 2, &MipsDescs.OperandInfo[377] },  // Inst #1804 = JALR_HB64
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1803 = JALR_HB
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1802 = JALRS_MM
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1801 = JALRS16_MM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1800 = JALRC_MMR6
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1799 = JALRC_HB_MMR6
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1798 = JALRC16_MMR6
  { 2, &MipsDescs.OperandInfo[377] },  // Inst #1797 = JALR64
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1796 = JALR16_MM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1795 = JALR
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1794 = JAL
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1793 = J
  { 5, &MipsDescs.OperandInfo[789] },  // Inst #1792 = INS_MMR6
  { 5, &MipsDescs.OperandInfo[789] },  // Inst #1791 = INS_MM
  { 3, &MipsDescs.OperandInfo[810] },  // Inst #1790 = INSV_MM
  { 5, &MipsDescs.OperandInfo[828] },  // Inst #1789 = INSVE_W
  { 5, &MipsDescs.OperandInfo[823] },  // Inst #1788 = INSVE_H
  { 5, &MipsDescs.OperandInfo[818] },  // Inst #1787 = INSVE_D
  { 5, &MipsDescs.OperandInfo[813] },  // Inst #1786 = INSVE_B
  { 3, &MipsDescs.OperandInfo[810] },  // Inst #1785 = INSV
  { 4, &MipsDescs.OperandInfo[806] },  // Inst #1784 = INSERT_W
  { 4, &MipsDescs.OperandInfo[802] },  // Inst #1783 = INSERT_H
  { 4, &MipsDescs.OperandInfo[798] },  // Inst #1782 = INSERT_D
  { 4, &MipsDescs.OperandInfo[794] },  // Inst #1781 = INSERT_B
  { 5, &MipsDescs.OperandInfo[789] },  // Inst #1780 = INS
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1779 = ILVR_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #1778 = ILVR_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1777 = ILVR_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #1776 = ILVR_B
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1775 = ILVOD_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #1774 = ILVOD_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1773 = ILVOD_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #1772 = ILVOD_B
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1771 = ILVL_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #1770 = ILVL_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1769 = ILVL_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #1768 = ILVL_B
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1767 = ILVEV_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #1766 = ILVEV_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1765 = ILVEV_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #1764 = ILVEV_B
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1763 = HYPCALL_MM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1762 = HYPCALL
  { 3, &MipsDescs.OperandInfo[724] },  // Inst #1761 = HSUB_U_W
  { 3, &MipsDescs.OperandInfo[721] },  // Inst #1760 = HSUB_U_H
  { 3, &MipsDescs.OperandInfo[718] },  // Inst #1759 = HSUB_U_D
  { 3, &MipsDescs.OperandInfo[724] },  // Inst #1758 = HSUB_S_W
  { 3, &MipsDescs.OperandInfo[721] },  // Inst #1757 = HSUB_S_H
  { 3, &MipsDescs.OperandInfo[718] },  // Inst #1756 = HSUB_S_D
  { 3, &MipsDescs.OperandInfo[724] },  // Inst #1755 = HADD_U_W
  { 3, &MipsDescs.OperandInfo[721] },  // Inst #1754 = HADD_U_H
  { 3, &MipsDescs.OperandInfo[718] },  // Inst #1753 = HADD_U_D
  { 3, &MipsDescs.OperandInfo[724] },  // Inst #1752 = HADD_S_W
  { 3, &MipsDescs.OperandInfo[721] },  // Inst #1751 = HADD_S_H
  { 3, &MipsDescs.OperandInfo[718] },  // Inst #1750 = HADD_S_D
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #1749 = GINVT_MMR6
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #1748 = GINVT
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1747 = GINVI_MMR6
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1746 = GINVI
  { 2, &MipsDescs.OperandInfo[240] },  // Inst #1745 = FTRUNC_U_W
  { 2, &MipsDescs.OperandInfo[238] },  // Inst #1744 = FTRUNC_U_D
  { 2, &MipsDescs.OperandInfo[240] },  // Inst #1743 = FTRUNC_S_W
  { 2, &MipsDescs.OperandInfo[238] },  // Inst #1742 = FTRUNC_S_D
  { 3, &MipsDescs.OperandInfo[774] },  // Inst #1741 = FTQ_W
  { 3, &MipsDescs.OperandInfo[771] },  // Inst #1740 = FTQ_H
  { 2, &MipsDescs.OperandInfo[240] },  // Inst #1739 = FTINT_U_W
  { 2, &MipsDescs.OperandInfo[238] },  // Inst #1738 = FTINT_U_D
  { 2, &MipsDescs.OperandInfo[240] },  // Inst #1737 = FTINT_S_W
  { 2, &MipsDescs.OperandInfo[238] },  // Inst #1736 = FTINT_S_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1735 = FSUN_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1734 = FSUN_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1733 = FSUNE_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1732 = FSUNE_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1731 = FSULT_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1730 = FSULT_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1729 = FSULE_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1728 = FSULE_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1727 = FSUEQ_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1726 = FSUEQ_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1725 = FSUB_W
  { 3, &MipsDescs.OperandInfo[759] },  // Inst #1724 = FSUB_S_MMR6
  { 3, &MipsDescs.OperandInfo[759] },  // Inst #1723 = FSUB_S_MM
  { 3, &MipsDescs.OperandInfo[759] },  // Inst #1722 = FSUB_S
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #1721 = FSUB_PS64
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #1720 = FSUB_D64_MM
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #1719 = FSUB_D64
  { 3, &MipsDescs.OperandInfo[756] },  // Inst #1718 = FSUB_D32_MM
  { 3, &MipsDescs.OperandInfo[756] },  // Inst #1717 = FSUB_D32
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1716 = FSUB_D
  { 2, &MipsDescs.OperandInfo[240] },  // Inst #1715 = FSQRT_W
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #1714 = FSQRT_S_MM
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #1713 = FSQRT_S
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #1712 = FSQRT_D64_MM
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #1711 = FSQRT_D64
  { 2, &MipsDescs.OperandInfo[754] },  // Inst #1710 = FSQRT_D32_MM
  { 2, &MipsDescs.OperandInfo[754] },  // Inst #1709 = FSQRT_D32
  { 2, &MipsDescs.OperandInfo[238] },  // Inst #1708 = FSQRT_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1707 = FSOR_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1706 = FSOR_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1705 = FSNE_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1704 = FSNE_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1703 = FSLT_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1702 = FSLT_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1701 = FSLE_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1700 = FSLE_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1699 = FSEQ_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1698 = FSEQ_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1697 = FSAF_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1696 = FSAF_D
  { 2, &MipsDescs.OperandInfo[240] },  // Inst #1695 = FRSQRT_W
  { 2, &MipsDescs.OperandInfo[238] },  // Inst #1694 = FRSQRT_D
  { 2, &MipsDescs.OperandInfo[240] },  // Inst #1693 = FRINT_W
  { 2, &MipsDescs.OperandInfo[238] },  // Inst #1692 = FRINT_D
  { 2, &MipsDescs.OperandInfo[240] },  // Inst #1691 = FRCP_W
  { 2, &MipsDescs.OperandInfo[238] },  // Inst #1690 = FRCP_D
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #1689 = FORK
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #1688 = FNEG_S_MMR6
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #1687 = FNEG_S_MM
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #1686 = FNEG_S
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #1685 = FNEG_D64_MM
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #1684 = FNEG_D64
  { 2, &MipsDescs.OperandInfo[754] },  // Inst #1683 = FNEG_D32_MM
  { 2, &MipsDescs.OperandInfo[754] },  // Inst #1682 = FNEG_D32
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1681 = FMUL_W
  { 3, &MipsDescs.OperandInfo[759] },  // Inst #1680 = FMUL_S_MMR6
  { 3, &MipsDescs.OperandInfo[759] },  // Inst #1679 = FMUL_S_MM
  { 3, &MipsDescs.OperandInfo[759] },  // Inst #1678 = FMUL_S
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #1677 = FMUL_PS64
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #1676 = FMUL_D64_MM
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #1675 = FMUL_D64
  { 3, &MipsDescs.OperandInfo[756] },  // Inst #1674 = FMUL_D32_MM
  { 3, &MipsDescs.OperandInfo[756] },  // Inst #1673 = FMUL_D32
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1672 = FMUL_D
  { 4, &MipsDescs.OperandInfo[190] },  // Inst #1671 = FMSUB_W
  { 4, &MipsDescs.OperandInfo[186] },  // Inst #1670 = FMSUB_D
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #1669 = FMOV_S_MMR6
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #1668 = FMOV_S_MM
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #1667 = FMOV_S
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #1666 = FMOV_D_MMR6
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #1665 = FMOV_D64_MM
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #1664 = FMOV_D64
  { 2, &MipsDescs.OperandInfo[754] },  // Inst #1663 = FMOV_D32_MM
  { 2, &MipsDescs.OperandInfo[754] },  // Inst #1662 = FMOV_D32
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1661 = FMIN_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1660 = FMIN_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1659 = FMIN_A_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1658 = FMIN_A_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1657 = FMAX_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1656 = FMAX_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1655 = FMAX_A_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1654 = FMAX_A_D
  { 4, &MipsDescs.OperandInfo[190] },  // Inst #1653 = FMADD_W
  { 4, &MipsDescs.OperandInfo[186] },  // Inst #1652 = FMADD_D
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #1651 = FLOOR_W_S_MMR6
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #1650 = FLOOR_W_S_MM
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #1649 = FLOOR_W_S
  { 2, &MipsDescs.OperandInfo[627] },  // Inst #1648 = FLOOR_W_MM
  { 2, &MipsDescs.OperandInfo[627] },  // Inst #1647 = FLOOR_W_D_MMR6
  { 2, &MipsDescs.OperandInfo[629] },  // Inst #1646 = FLOOR_W_D64
  { 2, &MipsDescs.OperandInfo[627] },  // Inst #1645 = FLOOR_W_D32
  { 2, &MipsDescs.OperandInfo[625] },  // Inst #1644 = FLOOR_L_S_MMR6
  { 2, &MipsDescs.OperandInfo[625] },  // Inst #1643 = FLOOR_L_S
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #1642 = FLOOR_L_D_MMR6
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #1641 = FLOOR_L_D64
  { 2, &MipsDescs.OperandInfo[240] },  // Inst #1640 = FLOG2_W
  { 2, &MipsDescs.OperandInfo[238] },  // Inst #1639 = FLOG2_D
  { 2, &MipsDescs.OperandInfo[787] },  // Inst #1638 = FILL_W
  { 2, &MipsDescs.OperandInfo[785] },  // Inst #1637 = FILL_H
  { 2, &MipsDescs.OperandInfo[783] },  // Inst #1636 = FILL_D
  { 2, &MipsDescs.OperandInfo[781] },  // Inst #1635 = FILL_B
  { 2, &MipsDescs.OperandInfo[779] },  // Inst #1634 = FFQR_W
  { 2, &MipsDescs.OperandInfo[777] },  // Inst #1633 = FFQR_D
  { 2, &MipsDescs.OperandInfo[779] },  // Inst #1632 = FFQL_W
  { 2, &MipsDescs.OperandInfo[777] },  // Inst #1631 = FFQL_D
  { 2, &MipsDescs.OperandInfo[240] },  // Inst #1630 = FFINT_U_W
  { 2, &MipsDescs.OperandInfo[238] },  // Inst #1629 = FFINT_U_D
  { 2, &MipsDescs.OperandInfo[240] },  // Inst #1628 = FFINT_S_W
  { 2, &MipsDescs.OperandInfo[238] },  // Inst #1627 = FFINT_S_D
  { 2, &MipsDescs.OperandInfo[779] },  // Inst #1626 = FEXUPR_W
  { 2, &MipsDescs.OperandInfo[777] },  // Inst #1625 = FEXUPR_D
  { 2, &MipsDescs.OperandInfo[779] },  // Inst #1624 = FEXUPL_W
  { 2, &MipsDescs.OperandInfo[777] },  // Inst #1623 = FEXUPL_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1622 = FEXP2_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1621 = FEXP2_D
  { 3, &MipsDescs.OperandInfo[774] },  // Inst #1620 = FEXDO_W
  { 3, &MipsDescs.OperandInfo[771] },  // Inst #1619 = FEXDO_H
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1618 = FDIV_W
  { 3, &MipsDescs.OperandInfo[759] },  // Inst #1617 = FDIV_S_MMR6
  { 3, &MipsDescs.OperandInfo[759] },  // Inst #1616 = FDIV_S_MM
  { 3, &MipsDescs.OperandInfo[759] },  // Inst #1615 = FDIV_S
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #1614 = FDIV_D64_MM
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #1613 = FDIV_D64
  { 3, &MipsDescs.OperandInfo[756] },  // Inst #1612 = FDIV_D32_MM
  { 3, &MipsDescs.OperandInfo[756] },  // Inst #1611 = FDIV_D32
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1610 = FDIV_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1609 = FCUN_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1608 = FCUN_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1607 = FCUNE_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1606 = FCUNE_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1605 = FCULT_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1604 = FCULT_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1603 = FCULE_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1602 = FCULE_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1601 = FCUEQ_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1600 = FCUEQ_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1599 = FCOR_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1598 = FCOR_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1597 = FCNE_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1596 = FCNE_D
  { 3, &MipsDescs.OperandInfo[768] },  // Inst #1595 = FCMP_S32_MM
  { 3, &MipsDescs.OperandInfo[768] },  // Inst #1594 = FCMP_S32
  { 3, &MipsDescs.OperandInfo[765] },  // Inst #1593 = FCMP_D64
  { 3, &MipsDescs.OperandInfo[762] },  // Inst #1592 = FCMP_D32_MM
  { 3, &MipsDescs.OperandInfo[762] },  // Inst #1591 = FCMP_D32
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1590 = FCLT_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1589 = FCLT_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1588 = FCLE_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1587 = FCLE_D
  { 2, &MipsDescs.OperandInfo[240] },  // Inst #1586 = FCLASS_W
  { 2, &MipsDescs.OperandInfo[238] },  // Inst #1585 = FCLASS_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1584 = FCEQ_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1583 = FCEQ_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1582 = FCAF_W
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1581 = FCAF_D
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1580 = FADD_W
  { 3, &MipsDescs.OperandInfo[759] },  // Inst #1579 = FADD_S_MMR6
  { 3, &MipsDescs.OperandInfo[759] },  // Inst #1578 = FADD_S_MM
  { 3, &MipsDescs.OperandInfo[759] },  // Inst #1577 = FADD_S
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #1576 = FADD_PS64
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #1575 = FADD_D64_MM
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #1574 = FADD_D64
  { 3, &MipsDescs.OperandInfo[756] },  // Inst #1573 = FADD_D32_MM
  { 3, &MipsDescs.OperandInfo[756] },  // Inst #1572 = FADD_D32
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1571 = FADD_D
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #1570 = FABS_S_MM
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #1569 = FABS_S
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #1568 = FABS_D64_MM
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #1567 = FABS_D64
  { 2, &MipsDescs.OperandInfo[754] },  // Inst #1566 = FABS_D32_MM
  { 2, &MipsDescs.OperandInfo[754] },  // Inst #1565 = FABS_D32
  { 4, &MipsDescs.OperandInfo[647] },  // Inst #1564 = EXT_MMR6
  { 4, &MipsDescs.OperandInfo[647] },  // Inst #1563 = EXT_MM
  { 4, &MipsDescs.OperandInfo[639] },  // Inst #1562 = EXTS32
  { 4, &MipsDescs.OperandInfo[639] },  // Inst #1561 = EXTS
  { 3, &MipsDescs.OperandInfo[748] },  // Inst #1560 = EXTR_W_MM
  { 3, &MipsDescs.OperandInfo[748] },  // Inst #1559 = EXTR_W
  { 3, &MipsDescs.OperandInfo[748] },  // Inst #1558 = EXTR_S_H_MM
  { 3, &MipsDescs.OperandInfo[748] },  // Inst #1557 = EXTR_S_H
  { 3, &MipsDescs.OperandInfo[748] },  // Inst #1556 = EXTR_R_W_MM
  { 3, &MipsDescs.OperandInfo[748] },  // Inst #1555 = EXTR_R_W
  { 3, &MipsDescs.OperandInfo[748] },  // Inst #1554 = EXTR_RS_W_MM
  { 3, &MipsDescs.OperandInfo[748] },  // Inst #1553 = EXTR_RS_W
  { 3, &MipsDescs.OperandInfo[751] },  // Inst #1552 = EXTRV_W_MM
  { 3, &MipsDescs.OperandInfo[751] },  // Inst #1551 = EXTRV_W
  { 3, &MipsDescs.OperandInfo[751] },  // Inst #1550 = EXTRV_S_H_MM
  { 3, &MipsDescs.OperandInfo[751] },  // Inst #1549 = EXTRV_S_H
  { 3, &MipsDescs.OperandInfo[751] },  // Inst #1548 = EXTRV_R_W_MM
  { 3, &MipsDescs.OperandInfo[751] },  // Inst #1547 = EXTRV_R_W
  { 3, &MipsDescs.OperandInfo[751] },  // Inst #1546 = EXTRV_RS_W_MM
  { 3, &MipsDescs.OperandInfo[751] },  // Inst #1545 = EXTRV_RS_W
  { 3, &MipsDescs.OperandInfo[748] },  // Inst #1544 = EXTP_MM
  { 3, &MipsDescs.OperandInfo[751] },  // Inst #1543 = EXTPV_MM
  { 3, &MipsDescs.OperandInfo[751] },  // Inst #1542 = EXTPV
  { 3, &MipsDescs.OperandInfo[748] },  // Inst #1541 = EXTPDP_MM
  { 3, &MipsDescs.OperandInfo[751] },  // Inst #1540 = EXTPDPV_MM
  { 3, &MipsDescs.OperandInfo[751] },  // Inst #1539 = EXTPDPV
  { 3, &MipsDescs.OperandInfo[748] },  // Inst #1538 = EXTPDP
  { 3, &MipsDescs.OperandInfo[748] },  // Inst #1537 = EXTP
  { 4, &MipsDescs.OperandInfo[647] },  // Inst #1536 = EXT
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1535 = EVP_MMR6
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1534 = EVPE
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1533 = EVP
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1532 = ERET_MMR6
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1531 = ERET_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1530 = ERETNC_MMR6
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1529 = ERETNC
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1528 = ERET
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1527 = EMT
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1526 = EI_MMR6
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1525 = EI_MM
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1524 = EI
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1523 = EHB_MMR6
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1522 = EHB_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1521 = EHB
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #1520 = DivuRxRy16
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #1519 = DivRxRy16
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1518 = DVP_MMR6
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1517 = DVPE
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1516 = DVP
  { 2, &MipsDescs.OperandInfo[377] },  // Inst #1515 = DUDIV
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #1514 = DSUBu
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #1513 = DSUB
  { 3, &MipsDescs.OperandInfo[743] },  // Inst #1512 = DSRLV
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #1511 = DSRL32
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #1510 = DSRL
  { 3, &MipsDescs.OperandInfo[743] },  // Inst #1509 = DSRAV
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #1508 = DSRA32
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #1507 = DSRA
  { 3, &MipsDescs.OperandInfo[743] },  // Inst #1506 = DSLLV
  { 2, &MipsDescs.OperandInfo[746] },  // Inst #1505 = DSLL64_32
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #1504 = DSLL32
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #1503 = DSLL
  { 2, &MipsDescs.OperandInfo[377] },  // Inst #1502 = DSHD
  { 2, &MipsDescs.OperandInfo[377] },  // Inst #1501 = DSDIV
  { 2, &MipsDescs.OperandInfo[377] },  // Inst #1500 = DSBH
  { 3, &MipsDescs.OperandInfo[743] },  // Inst #1499 = DROTRV
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #1498 = DROTR32
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #1497 = DROTR
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1496 = DPS_W_PH_MMR2
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1495 = DPS_W_PH
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1494 = DPSX_W_PH_MMR2
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1493 = DPSX_W_PH
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1492 = DPSU_H_QBR_MM
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1491 = DPSU_H_QBR
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1490 = DPSU_H_QBL_MM
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1489 = DPSU_H_QBL
  { 4, &MipsDescs.OperandInfo[735] },  // Inst #1488 = DPSUB_U_W
  { 4, &MipsDescs.OperandInfo[731] },  // Inst #1487 = DPSUB_U_H
  { 4, &MipsDescs.OperandInfo[727] },  // Inst #1486 = DPSUB_U_D
  { 4, &MipsDescs.OperandInfo[735] },  // Inst #1485 = DPSUB_S_W
  { 4, &MipsDescs.OperandInfo[731] },  // Inst #1484 = DPSUB_S_H
  { 4, &MipsDescs.OperandInfo[727] },  // Inst #1483 = DPSUB_S_D
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1482 = DPSQ_S_W_PH_MM
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1481 = DPSQ_S_W_PH
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1480 = DPSQ_SA_L_W_MM
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1479 = DPSQ_SA_L_W
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1478 = DPSQX_S_W_PH_MMR2
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1477 = DPSQX_S_W_PH
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1476 = DPSQX_SA_W_PH_MMR2
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1475 = DPSQX_SA_W_PH
  { 2, &MipsDescs.OperandInfo[377] },  // Inst #1474 = DPOP
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1473 = DPA_W_PH_MMR2
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1472 = DPA_W_PH
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1471 = DPAX_W_PH_MMR2
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1470 = DPAX_W_PH
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1469 = DPAU_H_QBR_MM
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1468 = DPAU_H_QBR
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1467 = DPAU_H_QBL_MM
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1466 = DPAU_H_QBL
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1465 = DPAQ_S_W_PH_MM
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1464 = DPAQ_S_W_PH
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1463 = DPAQ_SA_L_W_MM
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1462 = DPAQ_SA_L_W
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1461 = DPAQX_S_W_PH_MMR2
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1460 = DPAQX_S_W_PH
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1459 = DPAQX_SA_W_PH_MMR2
  { 4, &MipsDescs.OperandInfo[739] },  // Inst #1458 = DPAQX_SA_W_PH
  { 4, &MipsDescs.OperandInfo[735] },  // Inst #1457 = DPADD_U_W
  { 4, &MipsDescs.OperandInfo[731] },  // Inst #1456 = DPADD_U_H
  { 4, &MipsDescs.OperandInfo[727] },  // Inst #1455 = DPADD_U_D
  { 4, &MipsDescs.OperandInfo[735] },  // Inst #1454 = DPADD_S_W
  { 4, &MipsDescs.OperandInfo[731] },  // Inst #1453 = DPADD_S_H
  { 4, &MipsDescs.OperandInfo[727] },  // Inst #1452 = DPADD_S_D
  { 3, &MipsDescs.OperandInfo[724] },  // Inst #1451 = DOTP_U_W
  { 3, &MipsDescs.OperandInfo[721] },  // Inst #1450 = DOTP_U_H
  { 3, &MipsDescs.OperandInfo[718] },  // Inst #1449 = DOTP_U_D
  { 3, &MipsDescs.OperandInfo[724] },  // Inst #1448 = DOTP_S_W
  { 3, &MipsDescs.OperandInfo[721] },  // Inst #1447 = DOTP_S_H
  { 3, &MipsDescs.OperandInfo[718] },  // Inst #1446 = DOTP_S_D
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #1445 = DMUL_R6
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #1444 = DMULU
  { 2, &MipsDescs.OperandInfo[377] },  // Inst #1443 = DMULTu
  { 2, &MipsDescs.OperandInfo[377] },  // Inst #1442 = DMULT
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #1441 = DMUL
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #1440 = DMUHU
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #1439 = DMUH
  { 3, &MipsDescs.OperandInfo[712] },  // Inst #1438 = DMTGC0
  { 2, &MipsDescs.OperandInfo[354] },  // Inst #1437 = DMTC2_OCTEON
  { 3, &MipsDescs.OperandInfo[715] },  // Inst #1436 = DMTC2
  { 2, &MipsDescs.OperandInfo[404] },  // Inst #1435 = DMTC1
  { 3, &MipsDescs.OperandInfo[712] },  // Inst #1434 = DMTC0
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1433 = DMT
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #1432 = DMODU
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #1431 = DMOD
  { 3, &MipsDescs.OperandInfo[704] },  // Inst #1430 = DMFGC0
  { 2, &MipsDescs.OperandInfo[354] },  // Inst #1429 = DMFC2_OCTEON
  { 3, &MipsDescs.OperandInfo[709] },  // Inst #1428 = DMFC2
  { 2, &MipsDescs.OperandInfo[707] },  // Inst #1427 = DMFC1
  { 3, &MipsDescs.OperandInfo[704] },  // Inst #1426 = DMFC0
  { 4, &MipsDescs.OperandInfo[695] },  // Inst #1425 = DLSA_R6
  { 4, &MipsDescs.OperandInfo[695] },  // Inst #1424 = DLSA
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1423 = DI_MMR6
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1422 = DI_MM
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1421 = DIV_U_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #1420 = DIV_U_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1419 = DIV_U_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #1418 = DIV_U_B
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1417 = DIV_S_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #1416 = DIV_S_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1415 = DIV_S_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #1414 = DIV_S_B
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #1413 = DIV_MMR6
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #1412 = DIVU_MMR6
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #1411 = DIVU
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #1410 = DIV
  { 5, &MipsDescs.OperandInfo[699] },  // Inst #1409 = DINSU
  { 5, &MipsDescs.OperandInfo[699] },  // Inst #1408 = DINSM
  { 5, &MipsDescs.OperandInfo[699] },  // Inst #1407 = DINS
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #1406 = DI
  { 4, &MipsDescs.OperandInfo[639] },  // Inst #1405 = DEXTU
  { 4, &MipsDescs.OperandInfo[639] },  // Inst #1404 = DEXTM
  { 4, &MipsDescs.OperandInfo[643] },  // Inst #1403 = DEXT64_32
  { 4, &MipsDescs.OperandInfo[639] },  // Inst #1402 = DEXT
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1401 = DERET_MMR6
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1400 = DERET_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1399 = DERET
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #1398 = DDIVU
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #1397 = DDIV
  { 2, &MipsDescs.OperandInfo[377] },  // Inst #1396 = DCLZ_R6
  { 2, &MipsDescs.OperandInfo[377] },  // Inst #1395 = DCLZ
  { 2, &MipsDescs.OperandInfo[377] },  // Inst #1394 = DCLO_R6
  { 2, &MipsDescs.OperandInfo[377] },  // Inst #1393 = DCLO
  { 2, &MipsDescs.OperandInfo[377] },  // Inst #1392 = DBITSWAP
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #1391 = DAUI
  { 3, &MipsDescs.OperandInfo[692] },  // Inst #1390 = DATI
  { 4, &MipsDescs.OperandInfo[695] },  // Inst #1389 = DALIGN
  { 3, &MipsDescs.OperandInfo[692] },  // Inst #1388 = DAHI
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #1387 = DADDu
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #1386 = DADDiu
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #1385 = DADDi
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #1384 = DADD
  { 2, &MipsDescs.OperandInfo[568] },  // Inst #1383 = CmpiRxImmX16
  { 2, &MipsDescs.OperandInfo[568] },  // Inst #1382 = CmpiRxImm16
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #1381 = CmpRxRy16
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1380 = C_UN_S_MM
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1379 = C_UN_S
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1378 = C_UN_D64_MM
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1377 = C_UN_D64
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1376 = C_UN_D32_MM
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1375 = C_UN_D32
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1374 = C_ULT_S_MM
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1373 = C_ULT_S
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1372 = C_ULT_D64_MM
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1371 = C_ULT_D64
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1370 = C_ULT_D32_MM
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1369 = C_ULT_D32
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1368 = C_ULE_S_MM
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1367 = C_ULE_S
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1366 = C_ULE_D64_MM
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1365 = C_ULE_D64
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1364 = C_ULE_D32_MM
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1363 = C_ULE_D32
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1362 = C_UEQ_S_MM
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1361 = C_UEQ_S
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1360 = C_UEQ_D64_MM
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1359 = C_UEQ_D64
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1358 = C_UEQ_D32_MM
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1357 = C_UEQ_D32
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1356 = C_SF_S_MM
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1355 = C_SF_S
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1354 = C_SF_D64_MM
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1353 = C_SF_D64
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1352 = C_SF_D32_MM
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1351 = C_SF_D32
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1350 = C_SEQ_S_MM
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1349 = C_SEQ_S
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1348 = C_SEQ_D64_MM
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1347 = C_SEQ_D64
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1346 = C_SEQ_D32_MM
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1345 = C_SEQ_D32
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1344 = C_OLT_S_MM
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1343 = C_OLT_S
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1342 = C_OLT_D64_MM
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1341 = C_OLT_D64
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1340 = C_OLT_D32_MM
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1339 = C_OLT_D32
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1338 = C_OLE_S_MM
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1337 = C_OLE_S
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1336 = C_OLE_D64_MM
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1335 = C_OLE_D64
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1334 = C_OLE_D32_MM
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1333 = C_OLE_D32
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1332 = C_NGT_S_MM
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1331 = C_NGT_S
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1330 = C_NGT_D64_MM
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1329 = C_NGT_D64
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1328 = C_NGT_D32_MM
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1327 = C_NGT_D32
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1326 = C_NGL_S_MM
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1325 = C_NGL_S
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1324 = C_NGL_D64_MM
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1323 = C_NGL_D64
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1322 = C_NGL_D32_MM
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1321 = C_NGL_D32
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1320 = C_NGLE_S_MM
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1319 = C_NGLE_S
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1318 = C_NGLE_D64_MM
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1317 = C_NGLE_D64
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1316 = C_NGLE_D32_MM
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1315 = C_NGLE_D32
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1314 = C_NGE_S_MM
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1313 = C_NGE_S
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1312 = C_NGE_D64_MM
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1311 = C_NGE_D64
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1310 = C_NGE_D32_MM
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1309 = C_NGE_D32
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1308 = C_LT_S_MM
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1307 = C_LT_S
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1306 = C_LT_D64_MM
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1305 = C_LT_D64
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1304 = C_LT_D32_MM
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1303 = C_LT_D32
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1302 = C_LE_S_MM
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1301 = C_LE_S
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1300 = C_LE_D64_MM
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1299 = C_LE_D64
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1298 = C_LE_D32_MM
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1297 = C_LE_D32
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1296 = C_F_S_MM
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1295 = C_F_S
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1294 = C_F_D64_MM
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1293 = C_F_D64
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1292 = C_F_D32_MM
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1291 = C_F_D32
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1290 = C_EQ_S_MM
  { 3, &MipsDescs.OperandInfo[689] },  // Inst #1289 = C_EQ_S
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1288 = C_EQ_D64_MM
  { 3, &MipsDescs.OperandInfo[686] },  // Inst #1287 = C_EQ_D64
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1286 = C_EQ_D32_MM
  { 3, &MipsDescs.OperandInfo[683] },  // Inst #1285 = C_EQ_D32
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #1284 = CVT_W_S_MMR6
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #1283 = CVT_W_S_MM
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #1282 = CVT_W_S
  { 2, &MipsDescs.OperandInfo[629] },  // Inst #1281 = CVT_W_D64_MM
  { 2, &MipsDescs.OperandInfo[629] },  // Inst #1280 = CVT_W_D64
  { 2, &MipsDescs.OperandInfo[627] },  // Inst #1279 = CVT_W_D32_MM
  { 2, &MipsDescs.OperandInfo[627] },  // Inst #1278 = CVT_W_D32
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #1277 = CVT_S_W_MMR6
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #1276 = CVT_S_W_MM
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #1275 = CVT_S_W
  { 2, &MipsDescs.OperandInfo[629] },  // Inst #1274 = CVT_S_PU64
  { 2, &MipsDescs.OperandInfo[629] },  // Inst #1273 = CVT_S_PL64
  { 2, &MipsDescs.OperandInfo[625] },  // Inst #1272 = CVT_S_L_MMR6
  { 2, &MipsDescs.OperandInfo[629] },  // Inst #1271 = CVT_S_L
  { 2, &MipsDescs.OperandInfo[629] },  // Inst #1270 = CVT_S_D64_MM
  { 2, &MipsDescs.OperandInfo[629] },  // Inst #1269 = CVT_S_D64
  { 2, &MipsDescs.OperandInfo[627] },  // Inst #1268 = CVT_S_D32_MM
  { 2, &MipsDescs.OperandInfo[627] },  // Inst #1267 = CVT_S_D32
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #1266 = CVT_PW_PS64
  { 3, &MipsDescs.OperandInfo[680] },  // Inst #1265 = CVT_PS_S64
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #1264 = CVT_PS_PW64
  { 2, &MipsDescs.OperandInfo[625] },  // Inst #1263 = CVT_L_S_MMR6
  { 2, &MipsDescs.OperandInfo[625] },  // Inst #1262 = CVT_L_S_MM
  { 2, &MipsDescs.OperandInfo[625] },  // Inst #1261 = CVT_L_S
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #1260 = CVT_L_D_MMR6
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #1259 = CVT_L_D64_MM
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #1258 = CVT_L_D64
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #1257 = CVT_D_L_MMR6
  { 2, &MipsDescs.OperandInfo[625] },  // Inst #1256 = CVT_D64_W_MM
  { 2, &MipsDescs.OperandInfo[625] },  // Inst #1255 = CVT_D64_W
  { 2, &MipsDescs.OperandInfo[625] },  // Inst #1254 = CVT_D64_S_MM
  { 2, &MipsDescs.OperandInfo[625] },  // Inst #1253 = CVT_D64_S
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #1252 = CVT_D64_L
  { 2, &MipsDescs.OperandInfo[678] },  // Inst #1251 = CVT_D32_W_MM
  { 2, &MipsDescs.OperandInfo[678] },  // Inst #1250 = CVT_D32_W
  { 2, &MipsDescs.OperandInfo[678] },  // Inst #1249 = CVT_D32_S_MM
  { 2, &MipsDescs.OperandInfo[678] },  // Inst #1248 = CVT_D32_S
  { 2, &MipsDescs.OperandInfo[676] },  // Inst #1247 = CTCMSA
  { 2, &MipsDescs.OperandInfo[674] },  // Inst #1246 = CTC2_MM
  { 2, &MipsDescs.OperandInfo[672] },  // Inst #1245 = CTC1_MM
  { 2, &MipsDescs.OperandInfo[672] },  // Inst #1244 = CTC1
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #1243 = CRC32W
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #1242 = CRC32H
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #1241 = CRC32D
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #1240 = CRC32CW
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #1239 = CRC32CH
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #1238 = CRC32CD
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #1237 = CRC32CB
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #1236 = CRC32B
  { 3, &MipsDescs.OperandInfo[669] },  // Inst #1235 = COPY_U_W
  { 3, &MipsDescs.OperandInfo[666] },  // Inst #1234 = COPY_U_H
  { 3, &MipsDescs.OperandInfo[660] },  // Inst #1233 = COPY_U_B
  { 3, &MipsDescs.OperandInfo[669] },  // Inst #1232 = COPY_S_W
  { 3, &MipsDescs.OperandInfo[666] },  // Inst #1231 = COPY_S_H
  { 3, &MipsDescs.OperandInfo[663] },  // Inst #1230 = COPY_S_D
  { 3, &MipsDescs.OperandInfo[660] },  // Inst #1229 = COPY_S_B
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1228 = CMP_UN_S_MMR6
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1227 = CMP_UN_S
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1226 = CMP_UN_D_MMR6
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1225 = CMP_UN_D
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1224 = CMP_ULT_S_MMR6
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1223 = CMP_ULT_S
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1222 = CMP_ULT_D_MMR6
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1221 = CMP_ULT_D
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1220 = CMP_ULE_S_MMR6
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1219 = CMP_ULE_S
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1218 = CMP_ULE_D_MMR6
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1217 = CMP_ULE_D
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1216 = CMP_UEQ_S_MMR6
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1215 = CMP_UEQ_S
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1214 = CMP_UEQ_D_MMR6
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1213 = CMP_UEQ_D
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1212 = CMP_SUN_S_MMR6
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1211 = CMP_SUN_S
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1210 = CMP_SUN_D_MMR6
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1209 = CMP_SUN_D
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1208 = CMP_SULT_S_MMR6
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1207 = CMP_SULT_S
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1206 = CMP_SULT_D_MMR6
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1205 = CMP_SULT_D
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1204 = CMP_SULE_S_MMR6
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1203 = CMP_SULE_S
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1202 = CMP_SULE_D_MMR6
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1201 = CMP_SULE_D
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1200 = CMP_SUEQ_S_MMR6
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1199 = CMP_SUEQ_S
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1198 = CMP_SUEQ_D_MMR6
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1197 = CMP_SUEQ_D
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1196 = CMP_SLT_S_MMR6
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1195 = CMP_SLT_S
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1194 = CMP_SLT_D_MMR6
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1193 = CMP_SLT_D
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1192 = CMP_SLE_S_MMR6
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1191 = CMP_SLE_S
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1190 = CMP_SLE_D_MMR6
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1189 = CMP_SLE_D
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1188 = CMP_SEQ_S_MMR6
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1187 = CMP_SEQ_S
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1186 = CMP_SEQ_D_MMR6
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1185 = CMP_SEQ_D
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1184 = CMP_SAF_S_MMR6
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1183 = CMP_SAF_S
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1182 = CMP_SAF_D_MMR6
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1181 = CMP_SAF_D
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1180 = CMP_LT_S_MMR6
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1179 = CMP_LT_S
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #1178 = CMP_LT_PH_MM
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #1177 = CMP_LT_PH
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1176 = CMP_LT_D_MMR6
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1175 = CMP_LT_D
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1174 = CMP_LE_S_MMR6
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1173 = CMP_LE_S
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #1172 = CMP_LE_PH_MM
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #1171 = CMP_LE_PH
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1170 = CMP_LE_D_MMR6
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1169 = CMP_LE_D
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1168 = CMP_F_S
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1167 = CMP_F_D
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1166 = CMP_EQ_S_MMR6
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1165 = CMP_EQ_S
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #1164 = CMP_EQ_PH_MM
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #1163 = CMP_EQ_PH
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1162 = CMP_EQ_D_MMR6
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1161 = CMP_EQ_D
  { 3, &MipsDescs.OperandInfo[657] },  // Inst #1160 = CMP_AF_S_MMR6
  { 3, &MipsDescs.OperandInfo[654] },  // Inst #1159 = CMP_AF_D_MMR6
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #1158 = CMPU_LT_QB_MM
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #1157 = CMPU_LT_QB
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #1156 = CMPU_LE_QB_MM
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #1155 = CMPU_LE_QB
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #1154 = CMPU_EQ_QB_MM
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #1153 = CMPU_EQ_QB
  { 3, &MipsDescs.OperandInfo[651] },  // Inst #1152 = CMPGU_LT_QB_MM
  { 3, &MipsDescs.OperandInfo[651] },  // Inst #1151 = CMPGU_LT_QB
  { 3, &MipsDescs.OperandInfo[651] },  // Inst #1150 = CMPGU_LE_QB_MM
  { 3, &MipsDescs.OperandInfo[651] },  // Inst #1149 = CMPGU_LE_QB
  { 3, &MipsDescs.OperandInfo[651] },  // Inst #1148 = CMPGU_EQ_QB_MM
  { 3, &MipsDescs.OperandInfo[651] },  // Inst #1147 = CMPGU_EQ_QB
  { 3, &MipsDescs.OperandInfo[651] },  // Inst #1146 = CMPGDU_LT_QB_MMR2
  { 3, &MipsDescs.OperandInfo[651] },  // Inst #1145 = CMPGDU_LT_QB
  { 3, &MipsDescs.OperandInfo[651] },  // Inst #1144 = CMPGDU_LE_QB_MMR2
  { 3, &MipsDescs.OperandInfo[651] },  // Inst #1143 = CMPGDU_LE_QB
  { 3, &MipsDescs.OperandInfo[651] },  // Inst #1142 = CMPGDU_EQ_QB_MMR2
  { 3, &MipsDescs.OperandInfo[651] },  // Inst #1141 = CMPGDU_EQ_QB
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1140 = CLZ_R6
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1139 = CLZ_MMR6
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1138 = CLZ_MM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1137 = CLZ
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1136 = CLT_U_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #1135 = CLT_U_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1134 = CLT_U_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #1133 = CLT_U_B
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1132 = CLT_S_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #1131 = CLT_S_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1130 = CLT_S_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #1129 = CLT_S_B
  { 3, &MipsDescs.OperandInfo[554] },  // Inst #1128 = CLTI_U_W
  { 3, &MipsDescs.OperandInfo[551] },  // Inst #1127 = CLTI_U_H
  { 3, &MipsDescs.OperandInfo[548] },  // Inst #1126 = CLTI_U_D
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #1125 = CLTI_U_B
  { 3, &MipsDescs.OperandInfo[554] },  // Inst #1124 = CLTI_S_W
  { 3, &MipsDescs.OperandInfo[551] },  // Inst #1123 = CLTI_S_H
  { 3, &MipsDescs.OperandInfo[548] },  // Inst #1122 = CLTI_S_D
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #1121 = CLTI_S_B
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1120 = CLO_R6
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1119 = CLO_MMR6
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1118 = CLO_MM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1117 = CLO
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1116 = CLE_U_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #1115 = CLE_U_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1114 = CLE_U_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #1113 = CLE_U_B
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1112 = CLE_S_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #1111 = CLE_S_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1110 = CLE_S_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #1109 = CLE_S_B
  { 3, &MipsDescs.OperandInfo[554] },  // Inst #1108 = CLEI_U_W
  { 3, &MipsDescs.OperandInfo[551] },  // Inst #1107 = CLEI_U_H
  { 3, &MipsDescs.OperandInfo[548] },  // Inst #1106 = CLEI_U_D
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #1105 = CLEI_U_B
  { 3, &MipsDescs.OperandInfo[554] },  // Inst #1104 = CLEI_S_W
  { 3, &MipsDescs.OperandInfo[551] },  // Inst #1103 = CLEI_S_H
  { 3, &MipsDescs.OperandInfo[548] },  // Inst #1102 = CLEI_S_D
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #1101 = CLEI_S_B
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #1100 = CLASS_S_MMR6
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #1099 = CLASS_S
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #1098 = CLASS_D_MMR6
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #1097 = CLASS_D
  { 4, &MipsDescs.OperandInfo[647] },  // Inst #1096 = CINS_i32
  { 4, &MipsDescs.OperandInfo[643] },  // Inst #1095 = CINS64_32
  { 4, &MipsDescs.OperandInfo[639] },  // Inst #1094 = CINS32
  { 4, &MipsDescs.OperandInfo[639] },  // Inst #1093 = CINS
  { 2, &MipsDescs.OperandInfo[637] },  // Inst #1092 = CFCMSA
  { 2, &MipsDescs.OperandInfo[635] },  // Inst #1091 = CFC2_MM
  { 2, &MipsDescs.OperandInfo[633] },  // Inst #1090 = CFC1_MM
  { 2, &MipsDescs.OperandInfo[633] },  // Inst #1089 = CFC1
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1088 = CEQ_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #1087 = CEQ_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1086 = CEQ_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #1085 = CEQ_B
  { 3, &MipsDescs.OperandInfo[554] },  // Inst #1084 = CEQI_W
  { 3, &MipsDescs.OperandInfo[551] },  // Inst #1083 = CEQI_H
  { 3, &MipsDescs.OperandInfo[548] },  // Inst #1082 = CEQI_D
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #1081 = CEQI_B
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #1080 = CEIL_W_S_MMR6
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #1079 = CEIL_W_S_MM
  { 2, &MipsDescs.OperandInfo[631] },  // Inst #1078 = CEIL_W_S
  { 2, &MipsDescs.OperandInfo[627] },  // Inst #1077 = CEIL_W_MM
  { 2, &MipsDescs.OperandInfo[627] },  // Inst #1076 = CEIL_W_D_MMR6
  { 2, &MipsDescs.OperandInfo[629] },  // Inst #1075 = CEIL_W_D64
  { 2, &MipsDescs.OperandInfo[627] },  // Inst #1074 = CEIL_W_D32
  { 2, &MipsDescs.OperandInfo[625] },  // Inst #1073 = CEIL_L_S_MMR6
  { 2, &MipsDescs.OperandInfo[625] },  // Inst #1072 = CEIL_L_S
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #1071 = CEIL_L_D_MMR6
  { 2, &MipsDescs.OperandInfo[623] },  // Inst #1070 = CEIL_L_D64
  { 3, &MipsDescs.OperandInfo[620] },  // Inst #1069 = CACHE_R6
  { 3, &MipsDescs.OperandInfo[620] },  // Inst #1068 = CACHE_MMR6
  { 3, &MipsDescs.OperandInfo[620] },  // Inst #1067 = CACHE_MM
  { 3, &MipsDescs.OperandInfo[620] },  // Inst #1066 = CACHEE_MM
  { 3, &MipsDescs.OperandInfo[620] },  // Inst #1065 = CACHEE
  { 3, &MipsDescs.OperandInfo[620] },  // Inst #1064 = CACHE
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1063 = BtnezX16
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1062 = Btnez16
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1061 = BteqzX16
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1060 = Bteqz16
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1059 = Break16
  { 2, &MipsDescs.OperandInfo[618] },  // Inst #1058 = BnezRxImmX16
  { 2, &MipsDescs.OperandInfo[618] },  // Inst #1057 = BnezRxImm16
  { 1, &MipsDescs.OperandInfo[178] },  // Inst #1056 = BimmX16
  { 1, &MipsDescs.OperandInfo[178] },  // Inst #1055 = Bimm16
  { 2, &MipsDescs.OperandInfo[618] },  // Inst #1054 = BeqzRxImmX16
  { 2, &MipsDescs.OperandInfo[618] },  // Inst #1053 = BeqzRxImm16
  { 2, &MipsDescs.OperandInfo[616] },  // Inst #1052 = BZ_W
  { 2, &MipsDescs.OperandInfo[610] },  // Inst #1051 = BZ_V
  { 2, &MipsDescs.OperandInfo[614] },  // Inst #1050 = BZ_H
  { 2, &MipsDescs.OperandInfo[612] },  // Inst #1049 = BZ_D
  { 2, &MipsDescs.OperandInfo[610] },  // Inst #1048 = BZ_B
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1047 = BSET_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #1046 = BSET_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1045 = BSET_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #1044 = BSET_B
  { 3, &MipsDescs.OperandInfo[554] },  // Inst #1043 = BSETI_W
  { 3, &MipsDescs.OperandInfo[551] },  // Inst #1042 = BSETI_H
  { 3, &MipsDescs.OperandInfo[548] },  // Inst #1041 = BSETI_D
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #1040 = BSETI_B
  { 4, &MipsDescs.OperandInfo[606] },  // Inst #1039 = BSEL_V
  { 4, &MipsDescs.OperandInfo[590] },  // Inst #1038 = BSELI_B
  { 2, &MipsDescs.OperandInfo[13] },  // Inst #1037 = BREAK_MMR6
  { 2, &MipsDescs.OperandInfo[13] },  // Inst #1036 = BREAK_MM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1035 = BREAK16_MMR6
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1034 = BREAK16_MM
  { 2, &MipsDescs.OperandInfo[13] },  // Inst #1033 = BREAK
  { 1, &MipsDescs.OperandInfo[178] },  // Inst #1032 = BPOSGE32_MM
  { 1, &MipsDescs.OperandInfo[178] },  // Inst #1031 = BPOSGE32C_MMR3
  { 1, &MipsDescs.OperandInfo[178] },  // Inst #1030 = BPOSGE32
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #1029 = BOVC_MMR6
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #1028 = BOVC
  { 2, &MipsDescs.OperandInfo[616] },  // Inst #1027 = BNZ_W
  { 2, &MipsDescs.OperandInfo[610] },  // Inst #1026 = BNZ_V
  { 2, &MipsDescs.OperandInfo[614] },  // Inst #1025 = BNZ_H
  { 2, &MipsDescs.OperandInfo[612] },  // Inst #1024 = BNZ_D
  { 2, &MipsDescs.OperandInfo[610] },  // Inst #1023 = BNZ_B
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #1022 = BNVC_MMR6
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #1021 = BNVC
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #1020 = BNE_MM
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #1019 = BNEZC_MMR6
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #1018 = BNEZC_MM
  { 2, &MipsDescs.OperandInfo[347] },  // Inst #1017 = BNEZC64
  { 2, &MipsDescs.OperandInfo[588] },  // Inst #1016 = BNEZC16_MMR6
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #1015 = BNEZC
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #1014 = BNEZALC_MMR6
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #1013 = BNEZALC
  { 2, &MipsDescs.OperandInfo[588] },  // Inst #1012 = BNEZ16_MM
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #1011 = BNEL
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #1010 = BNEG_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #1009 = BNEG_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #1008 = BNEG_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #1007 = BNEG_B
  { 3, &MipsDescs.OperandInfo[554] },  // Inst #1006 = BNEGI_W
  { 3, &MipsDescs.OperandInfo[551] },  // Inst #1005 = BNEGI_H
  { 3, &MipsDescs.OperandInfo[548] },  // Inst #1004 = BNEGI_D
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #1003 = BNEGI_B
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #1002 = BNEC_MMR6
  { 3, &MipsDescs.OperandInfo[339] },  // Inst #1001 = BNEC64
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #1000 = BNEC
  { 3, &MipsDescs.OperandInfo[339] },  // Inst #999 = BNE64
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #998 = BNE
  { 4, &MipsDescs.OperandInfo[606] },  // Inst #997 = BMZ_V
  { 4, &MipsDescs.OperandInfo[590] },  // Inst #996 = BMZI_B
  { 4, &MipsDescs.OperandInfo[606] },  // Inst #995 = BMNZ_V
  { 4, &MipsDescs.OperandInfo[590] },  // Inst #994 = BMNZI_B
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #993 = BLTZ_MM
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #992 = BLTZL
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #991 = BLTZC_MMR6
  { 2, &MipsDescs.OperandInfo[347] },  // Inst #990 = BLTZC64
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #989 = BLTZC
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #988 = BLTZAL_MM
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #987 = BLTZALS_MM
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #986 = BLTZALL
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #985 = BLTZALC_MMR6
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #984 = BLTZALC
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #983 = BLTZAL
  { 2, &MipsDescs.OperandInfo[347] },  // Inst #982 = BLTZ64
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #981 = BLTZ
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #980 = BLTUC_MMR6
  { 3, &MipsDescs.OperandInfo[339] },  // Inst #979 = BLTUC64
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #978 = BLTUC
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #977 = BLTC_MMR6
  { 3, &MipsDescs.OperandInfo[339] },  // Inst #976 = BLTC64
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #975 = BLTC
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #974 = BLEZ_MM
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #973 = BLEZL
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #972 = BLEZC_MMR6
  { 2, &MipsDescs.OperandInfo[347] },  // Inst #971 = BLEZC64
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #970 = BLEZC
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #969 = BLEZALC_MMR6
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #968 = BLEZALC
  { 2, &MipsDescs.OperandInfo[347] },  // Inst #967 = BLEZ64
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #966 = BLEZ
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #965 = BITSWAP_MMR6
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #964 = BITSWAP
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #963 = BITREV_MM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #962 = BITREV
  { 4, &MipsDescs.OperandInfo[190] },  // Inst #961 = BINSR_W
  { 4, &MipsDescs.OperandInfo[194] },  // Inst #960 = BINSR_H
  { 4, &MipsDescs.OperandInfo[186] },  // Inst #959 = BINSR_D
  { 4, &MipsDescs.OperandInfo[606] },  // Inst #958 = BINSR_B
  { 4, &MipsDescs.OperandInfo[602] },  // Inst #957 = BINSRI_W
  { 4, &MipsDescs.OperandInfo[598] },  // Inst #956 = BINSRI_H
  { 4, &MipsDescs.OperandInfo[594] },  // Inst #955 = BINSRI_D
  { 4, &MipsDescs.OperandInfo[590] },  // Inst #954 = BINSRI_B
  { 4, &MipsDescs.OperandInfo[190] },  // Inst #953 = BINSL_W
  { 4, &MipsDescs.OperandInfo[194] },  // Inst #952 = BINSL_H
  { 4, &MipsDescs.OperandInfo[186] },  // Inst #951 = BINSL_D
  { 4, &MipsDescs.OperandInfo[606] },  // Inst #950 = BINSL_B
  { 4, &MipsDescs.OperandInfo[602] },  // Inst #949 = BINSLI_W
  { 4, &MipsDescs.OperandInfo[598] },  // Inst #948 = BINSLI_H
  { 4, &MipsDescs.OperandInfo[594] },  // Inst #947 = BINSLI_D
  { 4, &MipsDescs.OperandInfo[590] },  // Inst #946 = BINSLI_B
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #945 = BGTZ_MM
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #944 = BGTZL
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #943 = BGTZC_MMR6
  { 2, &MipsDescs.OperandInfo[347] },  // Inst #942 = BGTZC64
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #941 = BGTZC
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #940 = BGTZALC_MMR6
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #939 = BGTZALC
  { 2, &MipsDescs.OperandInfo[347] },  // Inst #938 = BGTZ64
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #937 = BGTZ
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #936 = BGEZ_MM
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #935 = BGEZL
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #934 = BGEZC_MMR6
  { 2, &MipsDescs.OperandInfo[347] },  // Inst #933 = BGEZC64
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #932 = BGEZC
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #931 = BGEZAL_MM
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #930 = BGEZALS_MM
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #929 = BGEZALL
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #928 = BGEZALC_MMR6
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #927 = BGEZALC
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #926 = BGEZAL
  { 2, &MipsDescs.OperandInfo[347] },  // Inst #925 = BGEZ64
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #924 = BGEZ
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #923 = BGEUC_MMR6
  { 3, &MipsDescs.OperandInfo[339] },  // Inst #922 = BGEUC64
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #921 = BGEUC
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #920 = BGEC_MMR6
  { 3, &MipsDescs.OperandInfo[339] },  // Inst #919 = BGEC64
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #918 = BGEC
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #917 = BEQ_MM
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #916 = BEQZC_MMR6
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #915 = BEQZC_MM
  { 2, &MipsDescs.OperandInfo[347] },  // Inst #914 = BEQZC64
  { 2, &MipsDescs.OperandInfo[588] },  // Inst #913 = BEQZC16_MMR6
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #912 = BEQZC
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #911 = BEQZALC_MMR6
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #910 = BEQZALC
  { 2, &MipsDescs.OperandInfo[588] },  // Inst #909 = BEQZ16_MM
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #908 = BEQL
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #907 = BEQC_MMR6
  { 3, &MipsDescs.OperandInfo[339] },  // Inst #906 = BEQC64
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #905 = BEQC
  { 3, &MipsDescs.OperandInfo[339] },  // Inst #904 = BEQ64
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #903 = BEQ
  { 1, &MipsDescs.OperandInfo[178] },  // Inst #902 = BC_MMR6
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #901 = BCLR_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #900 = BCLR_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #899 = BCLR_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #898 = BCLR_B
  { 3, &MipsDescs.OperandInfo[554] },  // Inst #897 = BCLRI_W
  { 3, &MipsDescs.OperandInfo[551] },  // Inst #896 = BCLRI_H
  { 3, &MipsDescs.OperandInfo[548] },  // Inst #895 = BCLRI_D
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #894 = BCLRI_B
  { 2, &MipsDescs.OperandInfo[586] },  // Inst #893 = BC2NEZC_MMR6
  { 2, &MipsDescs.OperandInfo[586] },  // Inst #892 = BC2NEZ
  { 2, &MipsDescs.OperandInfo[586] },  // Inst #891 = BC2EQZC_MMR6
  { 2, &MipsDescs.OperandInfo[586] },  // Inst #890 = BC2EQZ
  { 2, &MipsDescs.OperandInfo[584] },  // Inst #889 = BC1T_MM
  { 2, &MipsDescs.OperandInfo[584] },  // Inst #888 = BC1TL
  { 2, &MipsDescs.OperandInfo[584] },  // Inst #887 = BC1T
  { 2, &MipsDescs.OperandInfo[582] },  // Inst #886 = BC1NEZC_MMR6
  { 2, &MipsDescs.OperandInfo[582] },  // Inst #885 = BC1NEZ
  { 2, &MipsDescs.OperandInfo[584] },  // Inst #884 = BC1F_MM
  { 2, &MipsDescs.OperandInfo[584] },  // Inst #883 = BC1FL
  { 2, &MipsDescs.OperandInfo[584] },  // Inst #882 = BC1F
  { 2, &MipsDescs.OperandInfo[582] },  // Inst #881 = BC1EQZC_MMR6
  { 2, &MipsDescs.OperandInfo[582] },  // Inst #880 = BC1EQZ
  { 1, &MipsDescs.OperandInfo[178] },  // Inst #879 = BC16_MMR6
  { 1, &MipsDescs.OperandInfo[178] },  // Inst #878 = BC
  { 3, &MipsDescs.OperandInfo[579] },  // Inst #877 = BBIT132
  { 3, &MipsDescs.OperandInfo[579] },  // Inst #876 = BBIT1
  { 3, &MipsDescs.OperandInfo[579] },  // Inst #875 = BBIT032
  { 3, &MipsDescs.OperandInfo[579] },  // Inst #874 = BBIT0
  { 4, &MipsDescs.OperandInfo[564] },  // Inst #873 = BALIGN_MMR2
  { 4, &MipsDescs.OperandInfo[564] },  // Inst #872 = BALIGN
  { 1, &MipsDescs.OperandInfo[178] },  // Inst #871 = BALC_MMR6
  { 1, &MipsDescs.OperandInfo[178] },  // Inst #870 = BALC
  { 1, &MipsDescs.OperandInfo[178] },  // Inst #869 = BAL
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #868 = BADDu
  { 1, &MipsDescs.OperandInfo[178] },  // Inst #867 = B16_MM
  { 3, &MipsDescs.OperandInfo[576] },  // Inst #866 = AndRxRxRy16
  { 3, &MipsDescs.OperandInfo[396] },  // Inst #865 = AdduRxRyRz16
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #864 = AddiuSpImmX16
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #863 = AddiuSpImm16
  { 3, &MipsDescs.OperandInfo[573] },  // Inst #862 = AddiuRxRyOffMemX16
  { 3, &MipsDescs.OperandInfo[570] },  // Inst #861 = AddiuRxRxImmX16
  { 3, &MipsDescs.OperandInfo[570] },  // Inst #860 = AddiuRxRxImm16
  { 2, &MipsDescs.OperandInfo[568] },  // Inst #859 = AddiuRxPcImmX16
  { 2, &MipsDescs.OperandInfo[568] },  // Inst #858 = AddiuRxImmX16
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #857 = AVE_U_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #856 = AVE_U_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #855 = AVE_U_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #854 = AVE_U_B
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #853 = AVE_S_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #852 = AVE_S_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #851 = AVE_S_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #850 = AVE_S_B
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #849 = AVER_U_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #848 = AVER_U_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #847 = AVER_U_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #846 = AVER_U_B
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #845 = AVER_S_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #844 = AVER_S_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #843 = AVER_S_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #842 = AVER_S_B
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #841 = AUI_MMR6
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #840 = AUIPC_MMR6
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #839 = AUIPC
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #838 = AUI
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #837 = ASUB_U_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #836 = ASUB_U_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #835 = ASUB_U_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #834 = ASUB_U_B
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #833 = ASUB_S_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #832 = ASUB_S_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #831 = ASUB_S_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #830 = ASUB_S_B
  { 4, &MipsDescs.OperandInfo[564] },  // Inst #829 = APPEND_MMR2
  { 4, &MipsDescs.OperandInfo[564] },  // Inst #828 = APPEND
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #827 = ANDi_MM
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #826 = ANDi64
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #825 = ANDi
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #824 = AND_V
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #823 = AND_MMR6
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #822 = AND_MM
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #821 = ANDI_MMR6
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #820 = ANDI_B
  { 3, &MipsDescs.OperandInfo[527] },  // Inst #819 = ANDI16_MMR6
  { 3, &MipsDescs.OperandInfo[527] },  // Inst #818 = ANDI16_MM
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #817 = AND64
  { 3, &MipsDescs.OperandInfo[561] },  // Inst #816 = AND16_MMR6
  { 3, &MipsDescs.OperandInfo[561] },  // Inst #815 = AND16_MM
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #814 = AND
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #813 = ALUIPC_MMR6
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #812 = ALUIPC
  { 4, &MipsDescs.OperandInfo[557] },  // Inst #811 = ALIGN_MMR6
  { 4, &MipsDescs.OperandInfo[557] },  // Inst #810 = ALIGN
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #809 = ADDu_MM
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #808 = ADDu
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #807 = ADDiu_MM
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #806 = ADDiu
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #805 = ADDi_MM
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #804 = ADDi
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #803 = ADD_MMR6
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #802 = ADD_MM
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #801 = ADD_A_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #800 = ADD_A_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #799 = ADD_A_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #798 = ADD_A_B
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #797 = ADDWC_MM
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #796 = ADDWC
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #795 = ADDV_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #794 = ADDV_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #793 = ADDV_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #792 = ADDV_B
  { 3, &MipsDescs.OperandInfo[554] },  // Inst #791 = ADDVI_W
  { 3, &MipsDescs.OperandInfo[551] },  // Inst #790 = ADDVI_H
  { 3, &MipsDescs.OperandInfo[548] },  // Inst #789 = ADDVI_D
  { 3, &MipsDescs.OperandInfo[545] },  // Inst #788 = ADDVI_B
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #787 = ADDU_S_QB_MM
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #786 = ADDU_S_QB
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #785 = ADDU_S_PH_MMR2
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #784 = ADDU_S_PH
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #783 = ADDU_QB_MM
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #782 = ADDU_QB
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #781 = ADDU_PH_MMR2
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #780 = ADDU_PH
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #779 = ADDU_MMR6
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #778 = ADDUH_R_QB_MMR2
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #777 = ADDUH_R_QB
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #776 = ADDUH_QB_MMR2
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #775 = ADDUH_QB
  { 3, &MipsDescs.OperandInfo[542] },  // Inst #774 = ADDU16_MMR6
  { 3, &MipsDescs.OperandInfo[542] },  // Inst #773 = ADDU16_MM
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #772 = ADDS_U_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #771 = ADDS_U_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #770 = ADDS_U_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #769 = ADDS_U_B
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #768 = ADDS_S_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #767 = ADDS_S_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #766 = ADDS_S_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #765 = ADDS_S_B
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #764 = ADDS_A_W
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #763 = ADDS_A_H
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #762 = ADDS_A_D
  { 3, &MipsDescs.OperandInfo[539] },  // Inst #761 = ADDS_A_B
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #760 = ADDSC_MM
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #759 = ADDSC
  { 3, &MipsDescs.OperandInfo[536] },  // Inst #758 = ADDR_PS64
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #757 = ADDQ_S_W_MM
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #756 = ADDQ_S_W
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #755 = ADDQ_S_PH_MM
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #754 = ADDQ_S_PH
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #753 = ADDQ_PH_MM
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #752 = ADDQ_PH
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #751 = ADDQH_W_MMR2
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #750 = ADDQH_W
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #749 = ADDQH_R_W_MMR2
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #748 = ADDQH_R_W
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #747 = ADDQH_R_PH_MMR2
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #746 = ADDQH_R_PH
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #745 = ADDQH_PH_MMR2
  { 3, &MipsDescs.OperandInfo[533] },  // Inst #744 = ADDQH_PH
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #743 = ADDIU_MMR6
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #742 = ADDIUSP_MM
  { 3, &MipsDescs.OperandInfo[530] },  // Inst #741 = ADDIUS5_MM
  { 3, &MipsDescs.OperandInfo[527] },  // Inst #740 = ADDIUR2_MM
  { 2, &MipsDescs.OperandInfo[525] },  // Inst #739 = ADDIUR1SP_MM
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #738 = ADDIUPC_MMR6
  { 2, &MipsDescs.OperandInfo[525] },  // Inst #737 = ADDIUPC_MM
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #736 = ADDIUPC
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #735 = ADD
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #734 = ABSQ_S_W_MM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #733 = ABSQ_S_W
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #732 = ABSQ_S_QB_MMR2
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #731 = ABSQ_S_QB
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #730 = ABSQ_S_PH_MM
  { 2, &MipsDescs.OperandInfo[523] },  // Inst #729 = ABSQ_S_PH
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #728 = XOR_V_W_PSEUDO
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #727 = XOR_V_H_PSEUDO
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #726 = XOR_V_D_PSEUDO
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #725 = Usw
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #724 = Ush
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #723 = Ulw
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #722 = Ulhu
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #721 = Ulh
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #720 = URemMacro
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #719 = URemIMacro
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #718 = UDivMacro
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #717 = UDivIMacro
  { 3, &MipsDescs.OperandInfo[433] },  // Inst #716 = UDIV_MM_Pseudo
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #715 = TRAP_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #714 = TRAP
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #713 = TAILCALL_MMR6
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #712 = TAILCALL_MM
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #711 = TAILCALLREG_MMR6
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #710 = TAILCALLREG_MM
  { 1, &MipsDescs.OperandInfo[306] },  // Inst #709 = TAILCALLREGHB64
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #708 = TAILCALLREGHB
  { 1, &MipsDescs.OperandInfo[306] },  // Inst #707 = TAILCALLREG64
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #706 = TAILCALLREG
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #705 = TAILCALLR6REG
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #704 = TAILCALLHBR6REG
  { 1, &MipsDescs.OperandInfo[306] },  // Inst #703 = TAILCALLHB64R6REG
  { 1, &MipsDescs.OperandInfo[306] },  // Inst #702 = TAILCALL64R6REG
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #701 = TAILCALL
  { 3, &MipsDescs.OperandInfo[396] },  // Inst #700 = SltuRxRyRz16
  { 3, &MipsDescs.OperandInfo[396] },  // Inst #699 = SltuCCRxRy16
  { 3, &MipsDescs.OperandInfo[520] },  // Inst #698 = SltiuCCRxImmX16
  { 3, &MipsDescs.OperandInfo[520] },  // Inst #697 = SltiCCRxImmX16
  { 3, &MipsDescs.OperandInfo[396] },  // Inst #696 = SltCCRxRy16
  { 5, &MipsDescs.OperandInfo[510] },  // Inst #695 = SelTBtneZSltu
  { 5, &MipsDescs.OperandInfo[515] },  // Inst #694 = SelTBtneZSltiu
  { 5, &MipsDescs.OperandInfo[515] },  // Inst #693 = SelTBtneZSlti
  { 5, &MipsDescs.OperandInfo[510] },  // Inst #692 = SelTBtneZSlt
  { 5, &MipsDescs.OperandInfo[515] },  // Inst #691 = SelTBtneZCmpi
  { 5, &MipsDescs.OperandInfo[510] },  // Inst #690 = SelTBtneZCmp
  { 5, &MipsDescs.OperandInfo[510] },  // Inst #689 = SelTBteqZSltu
  { 5, &MipsDescs.OperandInfo[515] },  // Inst #688 = SelTBteqZSltiu
  { 5, &MipsDescs.OperandInfo[515] },  // Inst #687 = SelTBteqZSlti
  { 5, &MipsDescs.OperandInfo[510] },  // Inst #686 = SelTBteqZSlt
  { 5, &MipsDescs.OperandInfo[515] },  // Inst #685 = SelTBteqZCmpi
  { 5, &MipsDescs.OperandInfo[510] },  // Inst #684 = SelTBteqZCmp
  { 4, &MipsDescs.OperandInfo[506] },  // Inst #683 = SelBneZ
  { 4, &MipsDescs.OperandInfo[506] },  // Inst #682 = SelBeqZ
  { 3, &MipsDescs.OperandInfo[356] },  // Inst #681 = SaadAddr
  { 3, &MipsDescs.OperandInfo[356] },  // Inst #680 = SaaAddr
  { 2, &MipsDescs.OperandInfo[504] },  // Inst #679 = SZ_W_PSEUDO
  { 2, &MipsDescs.OperandInfo[498] },  // Inst #678 = SZ_V_PSEUDO
  { 2, &MipsDescs.OperandInfo[502] },  // Inst #677 = SZ_H_PSEUDO
  { 2, &MipsDescs.OperandInfo[500] },  // Inst #676 = SZ_D_PSEUDO
  { 2, &MipsDescs.OperandInfo[498] },  // Inst #675 = SZ_B_PSEUDO
  { 3, &MipsDescs.OperandInfo[349] },  // Inst #674 = SWM_MM
  { 3, &MipsDescs.OperandInfo[316] },  // Inst #673 = ST_F16
  { 3, &MipsDescs.OperandInfo[313] },  // Inst #672 = STR_W
  { 3, &MipsDescs.OperandInfo[310] },  // Inst #671 = STR_D
  { 3, &MipsDescs.OperandInfo[328] },  // Inst #670 = STORE_CCOND_DSP
  { 3, &MipsDescs.OperandInfo[325] },  // Inst #669 = STORE_ACC64DSP
  { 3, &MipsDescs.OperandInfo[322] },  // Inst #668 = STORE_ACC64
  { 3, &MipsDescs.OperandInfo[319] },  // Inst #667 = STORE_ACC128
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #666 = SRemMacro
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #665 = SRemIMacro
  { 2, &MipsDescs.OperandInfo[504] },  // Inst #664 = SNZ_W_PSEUDO
  { 2, &MipsDescs.OperandInfo[498] },  // Inst #663 = SNZ_V_PSEUDO
  { 2, &MipsDescs.OperandInfo[502] },  // Inst #662 = SNZ_H_PSEUDO
  { 2, &MipsDescs.OperandInfo[500] },  // Inst #661 = SNZ_D_PSEUDO
  { 2, &MipsDescs.OperandInfo[498] },  // Inst #660 = SNZ_B_PSEUDO
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #659 = SNEMacro
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #658 = SNEIMacro
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #657 = SLTUImm64
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #656 = SLTImm64
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #655 = SLEUImm64
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #654 = SLEUImm
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #653 = SLEU
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #652 = SLEImm64
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #651 = SLEImm
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #650 = SLE
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #649 = SGTUImm64
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #648 = SGTUImm
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #647 = SGTImm64
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #646 = SGTImm
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #645 = SGEUImm64
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #644 = SGEUImm
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #643 = SGEU
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #642 = SGEImm64
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #641 = SGEImm
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #640 = SGE
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #639 = SEQMacro
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #638 = SEQIMacro
  { 3, &MipsDescs.OperandInfo[495] },  // Inst #637 = SDivMacro
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #636 = SDivIMacro
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #635 = SDMacro
  { 3, &MipsDescs.OperandInfo[433] },  // Inst #634 = SDIV_MM_Pseudo
  { 3, &MipsDescs.OperandInfo[492] },  // Inst #633 = SDC1_M1
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #632 = RetRA16
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #631 = RetRA
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #630 = RORImm
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #629 = ROR
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #628 = ROLImm
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #627 = ROL
  { 3, &MipsDescs.OperandInfo[433] },  // Inst #626 = PseudoUDIV
  { 3, &MipsDescs.OperandInfo[489] },  // Inst #625 = PseudoTRUNC_W_S
  { 3, &MipsDescs.OperandInfo[486] },  // Inst #624 = PseudoTRUNC_W_D32
  { 3, &MipsDescs.OperandInfo[483] },  // Inst #623 = PseudoTRUNC_W_D
  { 4, &MipsDescs.OperandInfo[479] },  // Inst #622 = PseudoSELECT_S
  { 4, &MipsDescs.OperandInfo[475] },  // Inst #621 = PseudoSELECT_I64
  { 4, &MipsDescs.OperandInfo[471] },  // Inst #620 = PseudoSELECT_I
  { 4, &MipsDescs.OperandInfo[467] },  // Inst #619 = PseudoSELECT_D64
  { 4, &MipsDescs.OperandInfo[463] },  // Inst #618 = PseudoSELECT_D32
  { 4, &MipsDescs.OperandInfo[459] },  // Inst #617 = PseudoSELECTFP_T_S
  { 4, &MipsDescs.OperandInfo[455] },  // Inst #616 = PseudoSELECTFP_T_I64
  { 4, &MipsDescs.OperandInfo[451] },  // Inst #615 = PseudoSELECTFP_T_I
  { 4, &MipsDescs.OperandInfo[447] },  // Inst #614 = PseudoSELECTFP_T_D64
  { 4, &MipsDescs.OperandInfo[443] },  // Inst #613 = PseudoSELECTFP_T_D32
  { 4, &MipsDescs.OperandInfo[459] },  // Inst #612 = PseudoSELECTFP_F_S
  { 4, &MipsDescs.OperandInfo[455] },  // Inst #611 = PseudoSELECTFP_F_I64
  { 4, &MipsDescs.OperandInfo[451] },  // Inst #610 = PseudoSELECTFP_F_I
  { 4, &MipsDescs.OperandInfo[447] },  // Inst #609 = PseudoSELECTFP_F_D64
  { 4, &MipsDescs.OperandInfo[443] },  // Inst #608 = PseudoSELECTFP_F_D32
  { 3, &MipsDescs.OperandInfo[433] },  // Inst #607 = PseudoSDIV
  { 1, &MipsDescs.OperandInfo[306] },  // Inst #606 = PseudoReturn64
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #605 = PseudoReturn
  { 4, &MipsDescs.OperandInfo[439] },  // Inst #604 = PseudoPICK_QB
  { 4, &MipsDescs.OperandInfo[439] },  // Inst #603 = PseudoPICK_PH
  { 3, &MipsDescs.OperandInfo[433] },  // Inst #602 = PseudoMULTu_MM
  { 3, &MipsDescs.OperandInfo[433] },  // Inst #601 = PseudoMULTu
  { 3, &MipsDescs.OperandInfo[433] },  // Inst #600 = PseudoMULT_MM
  { 3, &MipsDescs.OperandInfo[433] },  // Inst #599 = PseudoMULT
  { 3, &MipsDescs.OperandInfo[433] },  // Inst #598 = PseudoMTLOHI_MM
  { 3, &MipsDescs.OperandInfo[436] },  // Inst #597 = PseudoMTLOHI_DSP
  { 3, &MipsDescs.OperandInfo[408] },  // Inst #596 = PseudoMTLOHI64
  { 3, &MipsDescs.OperandInfo[433] },  // Inst #595 = PseudoMTLOHI
  { 4, &MipsDescs.OperandInfo[425] },  // Inst #594 = PseudoMSUB_MM
  { 4, &MipsDescs.OperandInfo[425] },  // Inst #593 = PseudoMSUBU_MM
  { 4, &MipsDescs.OperandInfo[425] },  // Inst #592 = PseudoMSUBU
  { 4, &MipsDescs.OperandInfo[425] },  // Inst #591 = PseudoMSUB
  { 2, &MipsDescs.OperandInfo[429] },  // Inst #590 = PseudoMFLO_MM
  { 2, &MipsDescs.OperandInfo[431] },  // Inst #589 = PseudoMFLO64
  { 2, &MipsDescs.OperandInfo[429] },  // Inst #588 = PseudoMFLO
  { 2, &MipsDescs.OperandInfo[429] },  // Inst #587 = PseudoMFHI_MM
  { 2, &MipsDescs.OperandInfo[431] },  // Inst #586 = PseudoMFHI64
  { 2, &MipsDescs.OperandInfo[429] },  // Inst #585 = PseudoMFHI
  { 4, &MipsDescs.OperandInfo[425] },  // Inst #584 = PseudoMADD_MM
  { 4, &MipsDescs.OperandInfo[425] },  // Inst #583 = PseudoMADDU_MM
  { 4, &MipsDescs.OperandInfo[425] },  // Inst #582 = PseudoMADDU
  { 4, &MipsDescs.OperandInfo[425] },  // Inst #581 = PseudoMADD
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #580 = PseudoIndrectHazardBranchR6
  { 1, &MipsDescs.OperandInfo[306] },  // Inst #579 = PseudoIndrectHazardBranch64R6
  { 1, &MipsDescs.OperandInfo[306] },  // Inst #578 = PseudoIndirectHazardBranch64
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #577 = PseudoIndirectHazardBranch
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #576 = PseudoIndirectBranch_MMR6
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #575 = PseudoIndirectBranch_MM
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #574 = PseudoIndirectBranchR6
  { 1, &MipsDescs.OperandInfo[306] },  // Inst #573 = PseudoIndirectBranch64R6
  { 1, &MipsDescs.OperandInfo[306] },  // Inst #572 = PseudoIndirectBranch64
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #571 = PseudoIndirectBranch
  { 7, &MipsDescs.OperandInfo[418] },  // Inst #570 = PseudoD_SELECT_I64
  { 7, &MipsDescs.OperandInfo[411] },  // Inst #569 = PseudoD_SELECT_I
  { 3, &MipsDescs.OperandInfo[408] },  // Inst #568 = PseudoDUDIV
  { 3, &MipsDescs.OperandInfo[408] },  // Inst #567 = PseudoDSDIV
  { 3, &MipsDescs.OperandInfo[408] },  // Inst #566 = PseudoDMULTu
  { 3, &MipsDescs.OperandInfo[408] },  // Inst #565 = PseudoDMULT
  { 2, &MipsDescs.OperandInfo[392] },  // Inst #564 = PseudoCVT_S_W
  { 2, &MipsDescs.OperandInfo[404] },  // Inst #563 = PseudoCVT_S_L
  { 2, &MipsDescs.OperandInfo[406] },  // Inst #562 = PseudoCVT_D64_W
  { 2, &MipsDescs.OperandInfo[404] },  // Inst #561 = PseudoCVT_D64_L
  { 2, &MipsDescs.OperandInfo[402] },  // Inst #560 = PseudoCVT_D32_W
  { 3, &MipsDescs.OperandInfo[399] },  // Inst #559 = PseudoCMP_LT_PH
  { 3, &MipsDescs.OperandInfo[399] },  // Inst #558 = PseudoCMP_LE_PH
  { 3, &MipsDescs.OperandInfo[399] },  // Inst #557 = PseudoCMP_EQ_PH
  { 3, &MipsDescs.OperandInfo[399] },  // Inst #556 = PseudoCMPU_LT_QB
  { 3, &MipsDescs.OperandInfo[399] },  // Inst #555 = PseudoCMPU_LE_QB
  { 3, &MipsDescs.OperandInfo[399] },  // Inst #554 = PseudoCMPU_EQ_QB
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #553 = OR_V_W_PSEUDO
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #552 = OR_V_H_PSEUDO
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #551 = OR_V_D_PSEUDO
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #550 = NOR_V_W_PSEUDO
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #549 = NOR_V_H_PSEUDO
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #548 = NOR_V_D_PSEUDO
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #547 = NORImm64
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #546 = NORImm
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #545 = NOP
  { 3, &MipsDescs.OperandInfo[396] },  // Inst #544 = MultuRxRyRz16
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #543 = MultuRxRy16
  { 3, &MipsDescs.OperandInfo[396] },  // Inst #542 = MultRxRyRz16
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #541 = MultRxRy16
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #540 = MULOUMacro
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #539 = MULOMacro
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #538 = MULImmMacro
  { 2, &MipsDescs.OperandInfo[387] },  // Inst #537 = MTTLO
  { 2, &MipsDescs.OperandInfo[387] },  // Inst #536 = MTTHI
  { 2, &MipsDescs.OperandInfo[392] },  // Inst #535 = MTTHC1
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #534 = MTTGPR
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #533 = MTTDSP
  { 2, &MipsDescs.OperandInfo[392] },  // Inst #532 = MTTC1
  { 3, &MipsDescs.OperandInfo[389] },  // Inst #531 = MTTC0
  { 2, &MipsDescs.OperandInfo[387] },  // Inst #530 = MTTACX
  { 2, &MipsDescs.OperandInfo[385] },  // Inst #529 = MSA_FP_ROUND_W_PSEUDO
  { 2, &MipsDescs.OperandInfo[383] },  // Inst #528 = MSA_FP_ROUND_D_PSEUDO
  { 2, &MipsDescs.OperandInfo[381] },  // Inst #527 = MSA_FP_EXTEND_W_PSEUDO
  { 2, &MipsDescs.OperandInfo[379] },  // Inst #526 = MSA_FP_EXTEND_D_PSEUDO
  { 2, &MipsDescs.OperandInfo[377] },  // Inst #525 = MIPSeh_return64
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #524 = MIPSeh_return32
  { 2, &MipsDescs.OperandInfo[370] },  // Inst #523 = MFTLO
  { 2, &MipsDescs.OperandInfo[370] },  // Inst #522 = MFTHI
  { 2, &MipsDescs.OperandInfo[375] },  // Inst #521 = MFTHC1
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #520 = MFTGPR
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #519 = MFTDSP
  { 2, &MipsDescs.OperandInfo[375] },  // Inst #518 = MFTC1
  { 3, &MipsDescs.OperandInfo[372] },  // Inst #517 = MFTC0
  { 2, &MipsDescs.OperandInfo[370] },  // Inst #516 = MFTACX
  { 3, &MipsDescs.OperandInfo[367] },  // Inst #515 = LwConstant32
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #514 = LoadImmSingleGPR
  { 2, &MipsDescs.OperandInfo[365] },  // Inst #513 = LoadImmSingleFGR
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #512 = LoadImmDoubleGPR
  { 2, &MipsDescs.OperandInfo[363] },  // Inst #511 = LoadImmDoubleFGR_32
  { 2, &MipsDescs.OperandInfo[361] },  // Inst #510 = LoadImmDoubleFGR
  { 2, &MipsDescs.OperandInfo[354] },  // Inst #509 = LoadImm64
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #508 = LoadImm32
  { 3, &MipsDescs.OperandInfo[356] },  // Inst #507 = LoadAddrReg64
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #506 = LoadAddrReg32
  { 2, &MipsDescs.OperandInfo[354] },  // Inst #505 = LoadAddrImm64
  { 2, &MipsDescs.OperandInfo[352] },  // Inst #504 = LoadAddrImm32
  { 3, &MipsDescs.OperandInfo[349] },  // Inst #503 = LWM_MM
  { 2, &MipsDescs.OperandInfo[347] },  // Inst #502 = LONG_BRANCH_LUi2Op_64
  { 2, &MipsDescs.OperandInfo[345] },  // Inst #501 = LONG_BRANCH_LUi2Op
  { 3, &MipsDescs.OperandInfo[342] },  // Inst #500 = LONG_BRANCH_LUi
  { 3, &MipsDescs.OperandInfo[339] },  // Inst #499 = LONG_BRANCH_DADDiu2Op
  { 4, &MipsDescs.OperandInfo[335] },  // Inst #498 = LONG_BRANCH_DADDiu
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #497 = LONG_BRANCH_ADDiu2Op
  { 4, &MipsDescs.OperandInfo[331] },  // Inst #496 = LONG_BRANCH_ADDiu
  { 3, &MipsDescs.OperandInfo[328] },  // Inst #495 = LOAD_CCOND_DSP
  { 3, &MipsDescs.OperandInfo[325] },  // Inst #494 = LOAD_ACC64DSP
  { 3, &MipsDescs.OperandInfo[322] },  // Inst #493 = LOAD_ACC64
  { 3, &MipsDescs.OperandInfo[319] },  // Inst #492 = LOAD_ACC128
  { 3, &MipsDescs.OperandInfo[316] },  // Inst #491 = LD_F16
  { 3, &MipsDescs.OperandInfo[313] },  // Inst #490 = LDR_W
  { 3, &MipsDescs.OperandInfo[310] },  // Inst #489 = LDR_D
  { 3, &MipsDescs.OperandInfo[307] },  // Inst #488 = LDMacro
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #487 = JalTwoReg
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #486 = JalOneReg
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #485 = JAL_MMR6
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #484 = JALRPseudo
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #483 = JALRHBPseudo
  { 1, &MipsDescs.OperandInfo[306] },  // Inst #482 = JALRHB64Pseudo
  { 1, &MipsDescs.OperandInfo[306] },  // Inst #481 = JALR64Pseudo
  { 4, &MipsDescs.OperandInfo[302] },  // Inst #480 = INSERT_W_VIDX_PSEUDO
  { 4, &MipsDescs.OperandInfo[298] },  // Inst #479 = INSERT_W_VIDX64_PSEUDO
  { 4, &MipsDescs.OperandInfo[294] },  // Inst #478 = INSERT_H_VIDX_PSEUDO
  { 4, &MipsDescs.OperandInfo[290] },  // Inst #477 = INSERT_H_VIDX64_PSEUDO
  { 4, &MipsDescs.OperandInfo[286] },  // Inst #476 = INSERT_FW_VIDX_PSEUDO
  { 4, &MipsDescs.OperandInfo[282] },  // Inst #475 = INSERT_FW_VIDX64_PSEUDO
  { 4, &MipsDescs.OperandInfo[278] },  // Inst #474 = INSERT_FW_PSEUDO
  { 4, &MipsDescs.OperandInfo[274] },  // Inst #473 = INSERT_FD_VIDX_PSEUDO
  { 4, &MipsDescs.OperandInfo[270] },  // Inst #472 = INSERT_FD_VIDX64_PSEUDO
  { 4, &MipsDescs.OperandInfo[266] },  // Inst #471 = INSERT_FD_PSEUDO
  { 4, &MipsDescs.OperandInfo[262] },  // Inst #470 = INSERT_D_VIDX_PSEUDO
  { 4, &MipsDescs.OperandInfo[258] },  // Inst #469 = INSERT_D_VIDX64_PSEUDO
  { 4, &MipsDescs.OperandInfo[254] },  // Inst #468 = INSERT_B_VIDX_PSEUDO
  { 4, &MipsDescs.OperandInfo[250] },  // Inst #467 = INSERT_B_VIDX64_PSEUDO
  { 4, &MipsDescs.OperandInfo[246] },  // Inst #466 = GotPrologue16
  { 2, &MipsDescs.OperandInfo[244] },  // Inst #465 = FILL_FW_PSEUDO
  { 2, &MipsDescs.OperandInfo[242] },  // Inst #464 = FILL_FD_PSEUDO
  { 2, &MipsDescs.OperandInfo[240] },  // Inst #463 = FEXP2_W_1_PSEUDO
  { 2, &MipsDescs.OperandInfo[238] },  // Inst #462 = FEXP2_D_1_PSEUDO
  { 2, &MipsDescs.OperandInfo[240] },  // Inst #461 = FABS_W
  { 2, &MipsDescs.OperandInfo[238] },  // Inst #460 = FABS_D
  { 3, &MipsDescs.OperandInfo[235] },  // Inst #459 = ExtractElementF64_64
  { 3, &MipsDescs.OperandInfo[232] },  // Inst #458 = ExtractElementF64
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #457 = ERet
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #456 = DURemMacro
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #455 = DURemIMacro
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #454 = DUDivMacro
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #453 = DUDivIMacro
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #452 = DSRemMacro
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #451 = DSRemIMacro
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #450 = DSDivMacro
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #449 = DSDivIMacro
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #448 = DRORImm
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #447 = DROR
  { 3, &MipsDescs.OperandInfo[229] },  // Inst #446 = DROLImm
  { 3, &MipsDescs.OperandInfo[226] },  // Inst #445 = DROL
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #444 = DMULOUMacro
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #443 = DMULOMacro
  { 3, &MipsDescs.OperandInfo[223] },  // Inst #442 = DMULMacro
  { 3, &MipsDescs.OperandInfo[220] },  // Inst #441 = DMULImmMacro
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #440 = Constant32
  { 2, &MipsDescs.OperandInfo[218] },  // Inst #439 = CTTC1
  { 3, &MipsDescs.OperandInfo[215] },  // Inst #438 = COPY_FW_PSEUDO
  { 3, &MipsDescs.OperandInfo[212] },  // Inst #437 = COPY_FD_PSEUDO
  { 3, &MipsDescs.OperandInfo[2] },  // Inst #436 = CONSTPOOL_ENTRY
  { 2, &MipsDescs.OperandInfo[210] },  // Inst #435 = CFTC1
  { 3, &MipsDescs.OperandInfo[207] },  // Inst #434 = BuildPairF64_64
  { 3, &MipsDescs.OperandInfo[204] },  // Inst #433 = BuildPairF64
  { 3, &MipsDescs.OperandInfo[198] },  // Inst #432 = BtnezT8SltuX16
  { 3, &MipsDescs.OperandInfo[201] },  // Inst #431 = BtnezT8SltiuX16
  { 3, &MipsDescs.OperandInfo[201] },  // Inst #430 = BtnezT8SltiX16
  { 3, &MipsDescs.OperandInfo[198] },  // Inst #429 = BtnezT8SltX16
  { 3, &MipsDescs.OperandInfo[201] },  // Inst #428 = BtnezT8CmpiX16
  { 3, &MipsDescs.OperandInfo[198] },  // Inst #427 = BtnezT8CmpX16
  { 3, &MipsDescs.OperandInfo[198] },  // Inst #426 = BteqzT8SltuX16
  { 3, &MipsDescs.OperandInfo[201] },  // Inst #425 = BteqzT8SltiuX16
  { 3, &MipsDescs.OperandInfo[201] },  // Inst #424 = BteqzT8SltiX16
  { 3, &MipsDescs.OperandInfo[198] },  // Inst #423 = BteqzT8SltX16
  { 3, &MipsDescs.OperandInfo[201] },  // Inst #422 = BteqzT8CmpiX16
  { 3, &MipsDescs.OperandInfo[198] },  // Inst #421 = BteqzT8CmpX16
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #420 = BneImm
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #419 = BeqImm
  { 1, &MipsDescs.OperandInfo[178] },  // Inst #418 = B_MM_Pseudo
  { 1, &MipsDescs.OperandInfo[178] },  // Inst #417 = B_MMR6_Pseudo
  { 1, &MipsDescs.OperandInfo[178] },  // Inst #416 = B_MM
  { 4, &MipsDescs.OperandInfo[190] },  // Inst #415 = BSEL_W_PSEUDO
  { 4, &MipsDescs.OperandInfo[194] },  // Inst #414 = BSEL_H_PSEUDO
  { 4, &MipsDescs.OperandInfo[190] },  // Inst #413 = BSEL_FW_PSEUDO
  { 4, &MipsDescs.OperandInfo[186] },  // Inst #412 = BSEL_FD_PSEUDO
  { 4, &MipsDescs.OperandInfo[186] },  // Inst #411 = BSEL_D_PSEUDO
  { 1, &MipsDescs.OperandInfo[185] },  // Inst #410 = BPOSGE32_PSEUDO
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #409 = BNELImmMacro
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #408 = BLTULImmMacro
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #407 = BLTUL
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #406 = BLTUImmMacro
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #405 = BLTU
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #404 = BLTLImmMacro
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #403 = BLTL
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #402 = BLTImmMacro
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #401 = BLT
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #400 = BLEULImmMacro
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #399 = BLEUL
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #398 = BLEUImmMacro
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #397 = BLEU
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #396 = BLELImmMacro
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #395 = BLEL
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #394 = BLEImmMacro
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #393 = BLE
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #392 = BGTULImmMacro
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #391 = BGTUL
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #390 = BGTUImmMacro
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #389 = BGTU
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #388 = BGTLImmMacro
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #387 = BGTL
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #386 = BGTImmMacro
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #385 = BGT
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #384 = BGEULImmMacro
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #383 = BGEUL
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #382 = BGEUImmMacro
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #381 = BGEU
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #380 = BGELImmMacro
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #379 = BGEL
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #378 = BGEImmMacro
  { 3, &MipsDescs.OperandInfo[182] },  // Inst #377 = BGE
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #376 = BEQLImmMacro
  { 1, &MipsDescs.OperandInfo[178] },  // Inst #375 = BAL_BR_MM
  { 1, &MipsDescs.OperandInfo[178] },  // Inst #374 = BAL_BR
  { 1, &MipsDescs.OperandInfo[178] },  // Inst #373 = B
  { 6, &MipsDescs.OperandInfo[169] },  // Inst #372 = ATOMIC_SWAP_I8_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #371 = ATOMIC_SWAP_I8
  { 3, &MipsDescs.OperandInfo[175] },  // Inst #370 = ATOMIC_SWAP_I64_POSTRA
  { 3, &MipsDescs.OperandInfo[175] },  // Inst #369 = ATOMIC_SWAP_I64
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #368 = ATOMIC_SWAP_I32_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #367 = ATOMIC_SWAP_I32
  { 6, &MipsDescs.OperandInfo[169] },  // Inst #366 = ATOMIC_SWAP_I16_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #365 = ATOMIC_SWAP_I16
  { 6, &MipsDescs.OperandInfo[169] },  // Inst #364 = ATOMIC_LOAD_XOR_I8_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #363 = ATOMIC_LOAD_XOR_I8
  { 3, &MipsDescs.OperandInfo[175] },  // Inst #362 = ATOMIC_LOAD_XOR_I64_POSTRA
  { 3, &MipsDescs.OperandInfo[175] },  // Inst #361 = ATOMIC_LOAD_XOR_I64
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #360 = ATOMIC_LOAD_XOR_I32_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #359 = ATOMIC_LOAD_XOR_I32
  { 6, &MipsDescs.OperandInfo[169] },  // Inst #358 = ATOMIC_LOAD_XOR_I16_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #357 = ATOMIC_LOAD_XOR_I16
  { 6, &MipsDescs.OperandInfo[169] },  // Inst #356 = ATOMIC_LOAD_UMIN_I8_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #355 = ATOMIC_LOAD_UMIN_I8
  { 3, &MipsDescs.OperandInfo[175] },  // Inst #354 = ATOMIC_LOAD_UMIN_I64_POSTRA
  { 3, &MipsDescs.OperandInfo[175] },  // Inst #353 = ATOMIC_LOAD_UMIN_I64
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #352 = ATOMIC_LOAD_UMIN_I32_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #351 = ATOMIC_LOAD_UMIN_I32
  { 6, &MipsDescs.OperandInfo[169] },  // Inst #350 = ATOMIC_LOAD_UMIN_I16_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #349 = ATOMIC_LOAD_UMIN_I16
  { 6, &MipsDescs.OperandInfo[169] },  // Inst #348 = ATOMIC_LOAD_UMAX_I8_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #347 = ATOMIC_LOAD_UMAX_I8
  { 3, &MipsDescs.OperandInfo[175] },  // Inst #346 = ATOMIC_LOAD_UMAX_I64_POSTRA
  { 3, &MipsDescs.OperandInfo[175] },  // Inst #345 = ATOMIC_LOAD_UMAX_I64
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #344 = ATOMIC_LOAD_UMAX_I32_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #343 = ATOMIC_LOAD_UMAX_I32
  { 6, &MipsDescs.OperandInfo[169] },  // Inst #342 = ATOMIC_LOAD_UMAX_I16_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #341 = ATOMIC_LOAD_UMAX_I16
  { 6, &MipsDescs.OperandInfo[169] },  // Inst #340 = ATOMIC_LOAD_SUB_I8_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #339 = ATOMIC_LOAD_SUB_I8
  { 3, &MipsDescs.OperandInfo[175] },  // Inst #338 = ATOMIC_LOAD_SUB_I64_POSTRA
  { 3, &MipsDescs.OperandInfo[175] },  // Inst #337 = ATOMIC_LOAD_SUB_I64
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #336 = ATOMIC_LOAD_SUB_I32_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #335 = ATOMIC_LOAD_SUB_I32
  { 6, &MipsDescs.OperandInfo[169] },  // Inst #334 = ATOMIC_LOAD_SUB_I16_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #333 = ATOMIC_LOAD_SUB_I16
  { 6, &MipsDescs.OperandInfo[169] },  // Inst #332 = ATOMIC_LOAD_OR_I8_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #331 = ATOMIC_LOAD_OR_I8
  { 3, &MipsDescs.OperandInfo[175] },  // Inst #330 = ATOMIC_LOAD_OR_I64_POSTRA
  { 3, &MipsDescs.OperandInfo[175] },  // Inst #329 = ATOMIC_LOAD_OR_I64
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #328 = ATOMIC_LOAD_OR_I32_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #327 = ATOMIC_LOAD_OR_I32
  { 6, &MipsDescs.OperandInfo[169] },  // Inst #326 = ATOMIC_LOAD_OR_I16_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #325 = ATOMIC_LOAD_OR_I16
  { 6, &MipsDescs.OperandInfo[169] },  // Inst #324 = ATOMIC_LOAD_NAND_I8_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #323 = ATOMIC_LOAD_NAND_I8
  { 3, &MipsDescs.OperandInfo[175] },  // Inst #322 = ATOMIC_LOAD_NAND_I64_POSTRA
  { 3, &MipsDescs.OperandInfo[175] },  // Inst #321 = ATOMIC_LOAD_NAND_I64
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #320 = ATOMIC_LOAD_NAND_I32_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #319 = ATOMIC_LOAD_NAND_I32
  { 6, &MipsDescs.OperandInfo[169] },  // Inst #318 = ATOMIC_LOAD_NAND_I16_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #317 = ATOMIC_LOAD_NAND_I16
  { 6, &MipsDescs.OperandInfo[169] },  // Inst #316 = ATOMIC_LOAD_MIN_I8_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #315 = ATOMIC_LOAD_MIN_I8
  { 3, &MipsDescs.OperandInfo[175] },  // Inst #314 = ATOMIC_LOAD_MIN_I64_POSTRA
  { 3, &MipsDescs.OperandInfo[175] },  // Inst #313 = ATOMIC_LOAD_MIN_I64
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #312 = ATOMIC_LOAD_MIN_I32_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #311 = ATOMIC_LOAD_MIN_I32
  { 6, &MipsDescs.OperandInfo[169] },  // Inst #310 = ATOMIC_LOAD_MIN_I16_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #309 = ATOMIC_LOAD_MIN_I16
  { 6, &MipsDescs.OperandInfo[169] },  // Inst #308 = ATOMIC_LOAD_MAX_I8_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #307 = ATOMIC_LOAD_MAX_I8
  { 3, &MipsDescs.OperandInfo[175] },  // Inst #306 = ATOMIC_LOAD_MAX_I64_POSTRA
  { 3, &MipsDescs.OperandInfo[175] },  // Inst #305 = ATOMIC_LOAD_MAX_I64
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #304 = ATOMIC_LOAD_MAX_I32_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #303 = ATOMIC_LOAD_MAX_I32
  { 6, &MipsDescs.OperandInfo[169] },  // Inst #302 = ATOMIC_LOAD_MAX_I16_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #301 = ATOMIC_LOAD_MAX_I16
  { 6, &MipsDescs.OperandInfo[169] },  // Inst #300 = ATOMIC_LOAD_AND_I8_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #299 = ATOMIC_LOAD_AND_I8
  { 3, &MipsDescs.OperandInfo[175] },  // Inst #298 = ATOMIC_LOAD_AND_I64_POSTRA
  { 3, &MipsDescs.OperandInfo[175] },  // Inst #297 = ATOMIC_LOAD_AND_I64
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #296 = ATOMIC_LOAD_AND_I32_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #295 = ATOMIC_LOAD_AND_I32
  { 6, &MipsDescs.OperandInfo[169] },  // Inst #294 = ATOMIC_LOAD_AND_I16_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #293 = ATOMIC_LOAD_AND_I16
  { 6, &MipsDescs.OperandInfo[169] },  // Inst #292 = ATOMIC_LOAD_ADD_I8_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #291 = ATOMIC_LOAD_ADD_I8
  { 3, &MipsDescs.OperandInfo[175] },  // Inst #290 = ATOMIC_LOAD_ADD_I64_POSTRA
  { 3, &MipsDescs.OperandInfo[175] },  // Inst #289 = ATOMIC_LOAD_ADD_I64
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #288 = ATOMIC_LOAD_ADD_I32_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #287 = ATOMIC_LOAD_ADD_I32
  { 6, &MipsDescs.OperandInfo[169] },  // Inst #286 = ATOMIC_LOAD_ADD_I16_POSTRA
  { 3, &MipsDescs.OperandInfo[166] },  // Inst #285 = ATOMIC_LOAD_ADD_I16
  { 7, &MipsDescs.OperandInfo[155] },  // Inst #284 = ATOMIC_CMP_SWAP_I8_POSTRA
  { 4, &MipsDescs.OperandInfo[151] },  // Inst #283 = ATOMIC_CMP_SWAP_I8
  { 4, &MipsDescs.OperandInfo[162] },  // Inst #282 = ATOMIC_CMP_SWAP_I64_POSTRA
  { 4, &MipsDescs.OperandInfo[162] },  // Inst #281 = ATOMIC_CMP_SWAP_I64
  { 4, &MipsDescs.OperandInfo[151] },  // Inst #280 = ATOMIC_CMP_SWAP_I32_POSTRA
  { 4, &MipsDescs.OperandInfo[151] },  // Inst #279 = ATOMIC_CMP_SWAP_I32
  { 7, &MipsDescs.OperandInfo[155] },  // Inst #278 = ATOMIC_CMP_SWAP_I16_POSTRA
  { 4, &MipsDescs.OperandInfo[151] },  // Inst #277 = ATOMIC_CMP_SWAP_I16
  { 3, &MipsDescs.OperandInfo[148] },  // Inst #276 = AND_V_W_PSEUDO
  { 3, &MipsDescs.OperandInfo[145] },  // Inst #275 = AND_V_H_PSEUDO
  { 3, &MipsDescs.OperandInfo[142] },  // Inst #274 = AND_V_D_PSEUDO
  { 2, &MipsDescs.OperandInfo[21] },  // Inst #273 = ADJCALLSTACKUP
  { 2, &MipsDescs.OperandInfo[21] },  // Inst #272 = ADJCALLSTACKDOWN
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #271 = ABSMacro
  { 4, &MipsDescs.OperandInfo[136] },  // Inst #270 = G_UBFX
  { 4, &MipsDescs.OperandInfo[136] },  // Inst #269 = G_SBFX
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #268 = G_VECREDUCE_UMIN
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #267 = G_VECREDUCE_UMAX
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #266 = G_VECREDUCE_SMIN
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #265 = G_VECREDUCE_SMAX
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #264 = G_VECREDUCE_XOR
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #263 = G_VECREDUCE_OR
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #262 = G_VECREDUCE_AND
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #261 = G_VECREDUCE_MUL
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #260 = G_VECREDUCE_ADD
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #259 = G_VECREDUCE_FMINIMUM
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #258 = G_VECREDUCE_FMAXIMUM
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #257 = G_VECREDUCE_FMIN
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #256 = G_VECREDUCE_FMAX
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #255 = G_VECREDUCE_FMUL
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #254 = G_VECREDUCE_FADD
  { 3, &MipsDescs.OperandInfo[123] },  // Inst #253 = G_VECREDUCE_SEQ_FMUL
  { 3, &MipsDescs.OperandInfo[123] },  // Inst #252 = G_VECREDUCE_SEQ_FADD
  { 3, &MipsDescs.OperandInfo[53] },  // Inst #251 = G_BZERO
  { 4, &MipsDescs.OperandInfo[132] },  // Inst #250 = G_MEMSET
  { 4, &MipsDescs.OperandInfo[132] },  // Inst #249 = G_MEMMOVE
  { 3, &MipsDescs.OperandInfo[123] },  // Inst #248 = G_MEMCPY_INLINE
  { 4, &MipsDescs.OperandInfo[132] },  // Inst #247 = G_MEMCPY
  { 2, &MipsDescs.OperandInfo[130] },  // Inst #246 = G_WRITE_REGISTER
  { 2, &MipsDescs.OperandInfo[51] },  // Inst #245 = G_READ_REGISTER
  { 3, &MipsDescs.OperandInfo[96] },  // Inst #244 = G_STRICT_FLDEXP
  { 2, &MipsDescs.OperandInfo[62] },  // Inst #243 = G_STRICT_FSQRT
  { 4, &MipsDescs.OperandInfo[46] },  // Inst #242 = G_STRICT_FMA
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #241 = G_STRICT_FREM
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #240 = G_STRICT_FDIV
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #239 = G_STRICT_FMUL
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #238 = G_STRICT_FSUB
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #237 = G_STRICT_FADD
  { 1, &MipsDescs.OperandInfo[50] },  // Inst #236 = G_STACKRESTORE
  { 1, &MipsDescs.OperandInfo[50] },  // Inst #235 = G_STACKSAVE
  { 3, &MipsDescs.OperandInfo[64] },  // Inst #234 = G_DYN_STACKALLOC
  { 2, &MipsDescs.OperandInfo[51] },  // Inst #233 = G_JUMP_TABLE
  { 2, &MipsDescs.OperandInfo[51] },  // Inst #232 = G_BLOCK_ADDR
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #231 = G_ADDRSPACE_CAST
  { 2, &MipsDescs.OperandInfo[62] },  // Inst #230 = G_FNEARBYINT
  { 2, &MipsDescs.OperandInfo[62] },  // Inst #229 = G_FRINT
  { 2, &MipsDescs.OperandInfo[62] },  // Inst #228 = G_FFLOOR
  { 2, &MipsDescs.OperandInfo[62] },  // Inst #227 = G_FSQRT
  { 2, &MipsDescs.OperandInfo[62] },  // Inst #226 = G_FSIN
  { 2, &MipsDescs.OperandInfo[62] },  // Inst #225 = G_FCOS
  { 2, &MipsDescs.OperandInfo[62] },  // Inst #224 = G_FCEIL
  { 2, &MipsDescs.OperandInfo[62] },  // Inst #223 = G_BITREVERSE
  { 2, &MipsDescs.OperandInfo[62] },  // Inst #222 = G_BSWAP
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #221 = G_CTPOP
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #220 = G_CTLZ_ZERO_UNDEF
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #219 = G_CTLZ
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #218 = G_CTTZ_ZERO_UNDEF
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #217 = G_CTTZ
  { 4, &MipsDescs.OperandInfo[126] },  // Inst #216 = G_SHUFFLE_VECTOR
  { 3, &MipsDescs.OperandInfo[123] },  // Inst #215 = G_EXTRACT_VECTOR_ELT
  { 4, &MipsDescs.OperandInfo[119] },  // Inst #214 = G_INSERT_VECTOR_ELT
  { 3, &MipsDescs.OperandInfo[116] },  // Inst #213 = G_BRJT
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #212 = G_BR
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #211 = G_LLROUND
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #210 = G_LROUND
  { 2, &MipsDescs.OperandInfo[62] },  // Inst #209 = G_ABS
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #208 = G_UMAX
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #207 = G_UMIN
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #206 = G_SMAX
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #205 = G_SMIN
  { 3, &MipsDescs.OperandInfo[96] },  // Inst #204 = G_PTRMASK
  { 3, &MipsDescs.OperandInfo[96] },  // Inst #203 = G_PTR_ADD
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #202 = G_RESET_FPMODE
  { 1, &MipsDescs.OperandInfo[50] },  // Inst #201 = G_SET_FPMODE
  { 1, &MipsDescs.OperandInfo[50] },  // Inst #200 = G_GET_FPMODE
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #199 = G_RESET_FPENV
  { 1, &MipsDescs.OperandInfo[50] },  // Inst #198 = G_SET_FPENV
  { 1, &MipsDescs.OperandInfo[50] },  // Inst #197 = G_GET_FPENV
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #196 = G_FMAXIMUM
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #195 = G_FMINIMUM
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #194 = G_FMAXNUM_IEEE
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #193 = G_FMINNUM_IEEE
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #192 = G_FMAXNUM
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #191 = G_FMINNUM
  { 2, &MipsDescs.OperandInfo[62] },  // Inst #190 = G_FCANONICALIZE
  { 3, &MipsDescs.OperandInfo[93] },  // Inst #189 = G_IS_FPCLASS
  { 3, &MipsDescs.OperandInfo[96] },  // Inst #188 = G_FCOPYSIGN
  { 2, &MipsDescs.OperandInfo[62] },  // Inst #187 = G_FABS
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #186 = G_UITOFP
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #185 = G_SITOFP
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #184 = G_FPTOUI
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #183 = G_FPTOSI
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #182 = G_FPTRUNC
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #181 = G_FPEXT
  { 2, &MipsDescs.OperandInfo[62] },  // Inst #180 = G_FNEG
  { 3, &MipsDescs.OperandInfo[86] },  // Inst #179 = G_FFREXP
  { 3, &MipsDescs.OperandInfo[96] },  // Inst #178 = G_FLDEXP
  { 2, &MipsDescs.OperandInfo[62] },  // Inst #177 = G_FLOG10
  { 2, &MipsDescs.OperandInfo[62] },  // Inst #176 = G_FLOG2
  { 2, &MipsDescs.OperandInfo[62] },  // Inst #175 = G_FLOG
  { 2, &MipsDescs.OperandInfo[62] },  // Inst #174 = G_FEXP10
  { 2, &MipsDescs.OperandInfo[62] },  // Inst #173 = G_FEXP2
  { 2, &MipsDescs.OperandInfo[62] },  // Inst #172 = G_FEXP
  { 3, &MipsDescs.OperandInfo[96] },  // Inst #171 = G_FPOWI
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #170 = G_FPOW
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #169 = G_FREM
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #168 = G_FDIV
  { 4, &MipsDescs.OperandInfo[46] },  // Inst #167 = G_FMAD
  { 4, &MipsDescs.OperandInfo[46] },  // Inst #166 = G_FMA
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #165 = G_FMUL
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #164 = G_FSUB
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #163 = G_FADD
  { 4, &MipsDescs.OperandInfo[112] },  // Inst #162 = G_UDIVFIXSAT
  { 4, &MipsDescs.OperandInfo[112] },  // Inst #161 = G_SDIVFIXSAT
  { 4, &MipsDescs.OperandInfo[112] },  // Inst #160 = G_UDIVFIX
  { 4, &MipsDescs.OperandInfo[112] },  // Inst #159 = G_SDIVFIX
  { 4, &MipsDescs.OperandInfo[112] },  // Inst #158 = G_UMULFIXSAT
  { 4, &MipsDescs.OperandInfo[112] },  // Inst #157 = G_SMULFIXSAT
  { 4, &MipsDescs.OperandInfo[112] },  // Inst #156 = G_UMULFIX
  { 4, &MipsDescs.OperandInfo[112] },  // Inst #155 = G_SMULFIX
  { 3, &MipsDescs.OperandInfo[96] },  // Inst #154 = G_SSHLSAT
  { 3, &MipsDescs.OperandInfo[96] },  // Inst #153 = G_USHLSAT
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #152 = G_SSUBSAT
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #151 = G_USUBSAT
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #150 = G_SADDSAT
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #149 = G_UADDSAT
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #148 = G_SMULH
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #147 = G_UMULH
  { 4, &MipsDescs.OperandInfo[82] },  // Inst #146 = G_SMULO
  { 4, &MipsDescs.OperandInfo[82] },  // Inst #145 = G_UMULO
  { 5, &MipsDescs.OperandInfo[107] },  // Inst #144 = G_SSUBE
  { 4, &MipsDescs.OperandInfo[82] },  // Inst #143 = G_SSUBO
  { 5, &MipsDescs.OperandInfo[107] },  // Inst #142 = G_SADDE
  { 4, &MipsDescs.OperandInfo[82] },  // Inst #141 = G_SADDO
  { 5, &MipsDescs.OperandInfo[107] },  // Inst #140 = G_USUBE
  { 4, &MipsDescs.OperandInfo[82] },  // Inst #139 = G_USUBO
  { 5, &MipsDescs.OperandInfo[107] },  // Inst #138 = G_UADDE
  { 4, &MipsDescs.OperandInfo[82] },  // Inst #137 = G_UADDO
  { 4, &MipsDescs.OperandInfo[82] },  // Inst #136 = G_SELECT
  { 4, &MipsDescs.OperandInfo[103] },  // Inst #135 = G_FCMP
  { 4, &MipsDescs.OperandInfo[103] },  // Inst #134 = G_ICMP
  { 3, &MipsDescs.OperandInfo[96] },  // Inst #133 = G_ROTL
  { 3, &MipsDescs.OperandInfo[96] },  // Inst #132 = G_ROTR
  { 4, &MipsDescs.OperandInfo[99] },  // Inst #131 = G_FSHR
  { 4, &MipsDescs.OperandInfo[99] },  // Inst #130 = G_FSHL
  { 3, &MipsDescs.OperandInfo[96] },  // Inst #129 = G_ASHR
  { 3, &MipsDescs.OperandInfo[96] },  // Inst #128 = G_LSHR
  { 3, &MipsDescs.OperandInfo[96] },  // Inst #127 = G_SHL
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #126 = G_ZEXT
  { 3, &MipsDescs.OperandInfo[40] },  // Inst #125 = G_SEXT_INREG
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #124 = G_SEXT
  { 3, &MipsDescs.OperandInfo[93] },  // Inst #123 = G_VAARG
  { 1, &MipsDescs.OperandInfo[50] },  // Inst #122 = G_VASTART
  { 2, &MipsDescs.OperandInfo[51] },  // Inst #121 = G_FCONSTANT
  { 2, &MipsDescs.OperandInfo[51] },  // Inst #120 = G_CONSTANT
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #119 = G_TRUNC
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #118 = G_ANYEXT
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #117 = G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #116 = G_INTRINSIC_CONVERGENT
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #115 = G_INTRINSIC_W_SIDE_EFFECTS
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #114 = G_INTRINSIC
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #113 = G_INVOKE_REGION_START
  { 1, &MipsDescs.OperandInfo[50] },  // Inst #112 = G_BRINDIRECT
  { 2, &MipsDescs.OperandInfo[51] },  // Inst #111 = G_BRCOND
  { 4, &MipsDescs.OperandInfo[89] },  // Inst #110 = G_PREFETCH
  { 2, &MipsDescs.OperandInfo[21] },  // Inst #109 = G_FENCE
  { 3, &MipsDescs.OperandInfo[86] },  // Inst #108 = G_ATOMICRMW_UDEC_WRAP
  { 3, &MipsDescs.OperandInfo[86] },  // Inst #107 = G_ATOMICRMW_UINC_WRAP
  { 3, &MipsDescs.OperandInfo[86] },  // Inst #106 = G_ATOMICRMW_FMIN
  { 3, &MipsDescs.OperandInfo[86] },  // Inst #105 = G_ATOMICRMW_FMAX
  { 3, &MipsDescs.OperandInfo[86] },  // Inst #104 = G_ATOMICRMW_FSUB
  { 3, &MipsDescs.OperandInfo[86] },  // Inst #103 = G_ATOMICRMW_FADD
  { 3, &MipsDescs.OperandInfo[86] },  // Inst #102 = G_ATOMICRMW_UMIN
  { 3, &MipsDescs.OperandInfo[86] },  // Inst #101 = G_ATOMICRMW_UMAX
  { 3, &MipsDescs.OperandInfo[86] },  // Inst #100 = G_ATOMICRMW_MIN
  { 3, &MipsDescs.OperandInfo[86] },  // Inst #99 = G_ATOMICRMW_MAX
  { 3, &MipsDescs.OperandInfo[86] },  // Inst #98 = G_ATOMICRMW_XOR
  { 3, &MipsDescs.OperandInfo[86] },  // Inst #97 = G_ATOMICRMW_OR
  { 3, &MipsDescs.OperandInfo[86] },  // Inst #96 = G_ATOMICRMW_NAND
  { 3, &MipsDescs.OperandInfo[86] },  // Inst #95 = G_ATOMICRMW_AND
  { 3, &MipsDescs.OperandInfo[86] },  // Inst #94 = G_ATOMICRMW_SUB
  { 3, &MipsDescs.OperandInfo[86] },  // Inst #93 = G_ATOMICRMW_ADD
  { 3, &MipsDescs.OperandInfo[86] },  // Inst #92 = G_ATOMICRMW_XCHG
  { 4, &MipsDescs.OperandInfo[82] },  // Inst #91 = G_ATOMIC_CMPXCHG
  { 5, &MipsDescs.OperandInfo[77] },  // Inst #90 = G_ATOMIC_CMPXCHG_WITH_SUCCESS
  { 5, &MipsDescs.OperandInfo[72] },  // Inst #89 = G_INDEXED_STORE
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #88 = G_STORE
  { 5, &MipsDescs.OperandInfo[67] },  // Inst #87 = G_INDEXED_ZEXTLOAD
  { 5, &MipsDescs.OperandInfo[67] },  // Inst #86 = G_INDEXED_SEXTLOAD
  { 5, &MipsDescs.OperandInfo[67] },  // Inst #85 = G_INDEXED_LOAD
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #84 = G_ZEXTLOAD
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #83 = G_SEXTLOAD
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #82 = G_LOAD
  { 1, &MipsDescs.OperandInfo[50] },  // Inst #81 = G_READCYCLECOUNTER
  { 2, &MipsDescs.OperandInfo[62] },  // Inst #80 = G_INTRINSIC_ROUNDEVEN
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #79 = G_INTRINSIC_LRINT
  { 2, &MipsDescs.OperandInfo[62] },  // Inst #78 = G_INTRINSIC_ROUND
  { 2, &MipsDescs.OperandInfo[62] },  // Inst #77 = G_INTRINSIC_TRUNC
  { 3, &MipsDescs.OperandInfo[64] },  // Inst #76 = G_INTRINSIC_FPTRUNC_ROUND
  { 2, &MipsDescs.OperandInfo[62] },  // Inst #75 = G_CONSTANT_FOLD_BARRIER
  { 2, &MipsDescs.OperandInfo[62] },  // Inst #74 = G_FREEZE
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #73 = G_BITCAST
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #72 = G_INTTOPTR
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #71 = G_PTRTOINT
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #70 = G_CONCAT_VECTORS
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #69 = G_BUILD_VECTOR_TRUNC
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #68 = G_BUILD_VECTOR
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #67 = G_MERGE_VALUES
  { 4, &MipsDescs.OperandInfo[58] },  // Inst #66 = G_INSERT
  { 2, &MipsDescs.OperandInfo[56] },  // Inst #65 = G_UNMERGE_VALUES
  { 3, &MipsDescs.OperandInfo[53] },  // Inst #64 = G_EXTRACT
  { 2, &MipsDescs.OperandInfo[51] },  // Inst #63 = G_CONSTANT_POOL
  { 2, &MipsDescs.OperandInfo[51] },  // Inst #62 = G_GLOBAL_VALUE
  { 2, &MipsDescs.OperandInfo[51] },  // Inst #61 = G_FRAME_INDEX
  { 1, &MipsDescs.OperandInfo[50] },  // Inst #60 = G_PHI
  { 1, &MipsDescs.OperandInfo[50] },  // Inst #59 = G_IMPLICIT_DEF
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #58 = G_XOR
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #57 = G_OR
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #56 = G_AND
  { 4, &MipsDescs.OperandInfo[46] },  // Inst #55 = G_UDIVREM
  { 4, &MipsDescs.OperandInfo[46] },  // Inst #54 = G_SDIVREM
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #53 = G_UREM
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #52 = G_SREM
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #51 = G_UDIV
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #50 = G_SDIV
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #49 = G_MUL
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #48 = G_SUB
  { 3, &MipsDescs.OperandInfo[43] },  // Inst #47 = G_ADD
  { 3, &MipsDescs.OperandInfo[40] },  // Inst #46 = G_ASSERT_ALIGN
  { 3, &MipsDescs.OperandInfo[40] },  // Inst #45 = G_ASSERT_ZEXT
  { 3, &MipsDescs.OperandInfo[40] },  // Inst #44 = G_ASSERT_SEXT
  { 1, &MipsDescs.OperandInfo[1] },  // Inst #43 = JUMP_TABLE_DEBUG_INFO
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #42 = MEMBARRIER
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #41 = ICALL_BRANCH_FUNNEL
  { 3, &MipsDescs.OperandInfo[37] },  // Inst #40 = PATCHABLE_TYPED_EVENT_CALL
  { 2, &MipsDescs.OperandInfo[35] },  // Inst #39 = PATCHABLE_EVENT_CALL
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #38 = PATCHABLE_TAIL_CALL
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #37 = PATCHABLE_FUNCTION_EXIT
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #36 = PATCHABLE_RET
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #35 = PATCHABLE_FUNCTION_ENTER
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #34 = PATCHABLE_OP
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #33 = FAULTING_OP
  { 2, &MipsDescs.OperandInfo[33] },  // Inst #32 = LOCAL_ESCAPE
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #31 = STATEPOINT
  { 3, &MipsDescs.OperandInfo[30] },  // Inst #30 = PREALLOCATED_ARG
  { 1, &MipsDescs.OperandInfo[1] },  // Inst #29 = PREALLOCATED_SETUP
  { 1, &MipsDescs.OperandInfo[29] },  // Inst #28 = LOAD_STACK_GUARD
  { 6, &MipsDescs.OperandInfo[23] },  // Inst #27 = PATCHPOINT
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #26 = FENTRY_CALL
  { 2, &MipsDescs.OperandInfo[21] },  // Inst #25 = STACKMAP
  { 2, &MipsDescs.OperandInfo[19] },  // Inst #24 = ARITH_FENCE
  { 4, &MipsDescs.OperandInfo[15] },  // Inst #23 = PSEUDO_PROBE
  { 1, &MipsDescs.OperandInfo[1] },  // Inst #22 = LIFETIME_END
  { 1, &MipsDescs.OperandInfo[1] },  // Inst #21 = LIFETIME_START
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #20 = BUNDLE
  { 2, &MipsDescs.OperandInfo[13] },  // Inst #19 = COPY
  { 2, &MipsDescs.OperandInfo[13] },  // Inst #18 = REG_SEQUENCE
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #17 = DBG_LABEL
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #16 = DBG_PHI
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #15 = DBG_INSTR_REF
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #14 = DBG_VALUE_LIST
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #13 = DBG_VALUE
  { 3, &MipsDescs.OperandInfo[2] },  // Inst #12 = COPY_TO_REGCLASS
  { 4, &MipsDescs.OperandInfo[9] },  // Inst #11 = SUBREG_TO_REG
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #10 = IMPLICIT_DEF
  { 4, &MipsDescs.OperandInfo[5] },  // Inst #9 = INSERT_SUBREG
  { 3, &MipsDescs.OperandInfo[2] },  // Inst #8 = EXTRACT_SUBREG
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #7 = KILL
  { 1, &MipsDescs.OperandInfo[1] },  // Inst #6 = ANNOTATION_LABEL
  { 1, &MipsDescs.OperandInfo[1] },  // Inst #5 = GC_LABEL
  { 1, &MipsDescs.OperandInfo[1] },  // Inst #4 = EH_LABEL
  { 1, &MipsDescs.OperandInfo[1] },  // Inst #3 = CFI_INSTRUCTION
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2 = INLINEASM_BR
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1 = INLINEASM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #0 = PHI
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
    /* 140 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 142 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 145 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 148 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 151 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 155 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 162 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 166 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 169 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 175 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 178 */ { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 179 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 182 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 185 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 186 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 190 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 194 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 198 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 201 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 204 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 207 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 210 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGRCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 212 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 215 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 218 */ { Mips_FGRCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 220 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 223 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 226 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 229 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 232 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 235 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 238 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 240 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 242 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 244 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 246 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 250 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 254 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 258 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 262 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 266 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 270 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 274 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 278 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 282 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 286 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 290 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 294 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 298 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 302 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 306 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 307 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 310 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 313 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 316 */ { Mips_MSA128F16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 319 */ { Mips_ACC128RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 322 */ { Mips_ACC64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 325 */ { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 328 */ { Mips_DSPCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 331 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 335 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 339 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 342 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 345 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 347 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 349 */ { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 352 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 354 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 356 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 359 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 361 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 363 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 365 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 367 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 370 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 372 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_COP0RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 375 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 377 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 379 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128F16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 381 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128F16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 383 */ { Mips_MSA128F16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 385 */ { Mips_MSA128F16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 387 */ { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 389 */ { Mips_COP0RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 392 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 394 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 396 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 399 */ { Mips_DSPCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 402 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 404 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 406 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 408 */ { Mips_ACC128RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 411 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 418 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 425 */ { Mips_ACC64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_ACC64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 429 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_ACC64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 431 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_ACC128RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 433 */ { Mips_ACC64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 436 */ { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 439 */ { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 443 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 447 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 451 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 455 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 459 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 463 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 467 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 471 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 475 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 479 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 483 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 486 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 489 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 492 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 495 */ { Mips_GPR32NONZERORegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 498 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 500 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 502 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 504 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 506 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 510 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 515 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 520 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 523 */ { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 525 */ { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 527 */ { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 530 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 533 */ { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 536 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 539 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 542 */ { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 545 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 548 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 551 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 554 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 557 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 561 */ { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 564 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 568 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 570 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 573 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsPlusSPRegClassID, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 576 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 579 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 582 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 584 */ { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 586 */ { Mips_COP2RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 588 */ { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 590 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 594 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 598 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 602 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 606 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 610 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 612 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 614 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 616 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 618 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 620 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 623 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 625 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 627 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 629 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 631 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 633 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CCRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 635 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_COP2RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 637 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSACtrlRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 639 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 643 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 647 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 651 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 654 */ { Mips_FGRCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 657 */ { Mips_FGRCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 660 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 663 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 666 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 669 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 672 */ { Mips_CCRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 674 */ { Mips_COP2RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 676 */ { Mips_MSACtrlRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 678 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 680 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 683 */ { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 686 */ { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 689 */ { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 692 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 695 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 699 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 704 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_COP0RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 707 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 709 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_COP2RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 712 */ { Mips_COP0RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 715 */ { Mips_COP2RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 718 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 721 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 724 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 727 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 731 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 735 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 739 */ { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 743 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 746 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 748 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 751 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 754 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 756 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 759 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 762 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 765 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 768 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 771 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 774 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 777 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 779 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 781 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 783 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 785 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 787 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 789 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 794 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 798 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 802 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 806 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 810 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 813 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 818 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 823 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 828 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 833 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 834 */ { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 837 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 },
    /* 840 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 843 */ { Mips_COP2RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 846 */ { Mips_COP2RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 849 */ { Mips_COP3RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 852 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 854 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 856 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 858 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 860 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 864 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 },
    /* 867 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 },
    /* 870 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 873 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 876 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 879 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 882 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MipsII_OPERAND_MEM_SIMM9, 0 }, { -1, 0, MipsII_OPERAND_MEM_SIMM9, 0 },
    /* 885 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MipsII_OPERAND_MEM_SIMM9, 0 }, { -1, 0, MipsII_OPERAND_MEM_SIMM9, 0 },
    /* 888 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 891 */ { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 894 */ { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 3, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 897 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 901 */ { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { 2, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 904 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 908 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 2, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 911 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 },
    /* 914 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 917 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 920 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 924 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 928 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 932 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 936 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 940 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 942 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_COP2RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 945 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 947 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 952 */ { Mips_GPRMM16MovePPairFirstRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRMM16MovePPairSecondRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRMM16MovePRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRMM16MovePRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 956 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 958 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 962 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 966 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 970 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 974 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 978 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 982 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 986 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 990 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 994 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 998 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1002 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1006 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1010 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1014 */ { Mips_COP2RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 1017 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1020 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1023 */ { Mips_HI32DSPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1025 */ { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1028 */ { Mips_LO32DSPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1030 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1032 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1034 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1036 */ { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1038 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1040 */ { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1043 */ { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1047 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 1050 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_HWRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 1053 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_HWRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 1056 */ { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1058 */ { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 1060 */ { Mips_GPRMM16ZeroRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1063 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1067 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MipsII_OPERAND_MEM_SIMM9, 0 }, { -1, 0, MipsII_OPERAND_MEM_SIMM9, 0 },
    /* 1071 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1075 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MipsII_OPERAND_MEM_SIMM9, 0 }, { -1, 0, MipsII_OPERAND_MEM_SIMM9, 0 },
    /* 1079 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGRCCRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1083 */ { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1086 */ { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1089 */ { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 1092 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1096 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1100 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1104 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1108 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1111 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 1114 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1117 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1120 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1123 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1126 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1128 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
  }, {
    /* 0 */
    /* 0 */ Mips_SP, Mips_SP,
    /* 2 */ Mips_AT,
    /* 3 */ Mips_RA,
    /* 4 */ Mips_DSPPos,
    /* 5 */ Mips_V0, Mips_V1,
    /* 7 */ Mips_HI0, Mips_LO0,
    /* 9 */ Mips_T8,
    /* 10 */ Mips_DSPOutFlag20,
    /* 11 */ Mips_DSPCarry,
    /* 12 */ Mips_DSPCarry, Mips_DSPOutFlag20,
    /* 14 */ Mips_DSPCCond,
    /* 15 */ Mips_HI0, Mips_LO0, Mips_P0, Mips_P1, Mips_P2,
    /* 20 */ Mips_HI0_64, Mips_LO0_64,
    /* 22 */ Mips_DSPOutFlag16_19,
    /* 23 */ Mips_DSPPos, Mips_DSPEFI,
    /* 25 */ Mips_DSPPos, Mips_DSPPos, Mips_DSPEFI,
    /* 28 */ Mips_DSPOutFlag23,
    /* 29 */ Mips_FCC0,
    /* 30 */ Mips_DSPPos, Mips_DSPSCount,
    /* 32 */ Mips_HI0, Mips_LO0, Mips_HI0, Mips_LO0,
    /* 36 */ Mips_AC0,
    /* 37 */ Mips_AC0_64,
    /* 38 */ Mips_HI0,
    /* 39 */ Mips_HI0_64,
    /* 40 */ Mips_LO0,
    /* 41 */ Mips_LO0_64,
    /* 42 */ Mips_MPL0, Mips_P0, Mips_P1, Mips_P2,
    /* 46 */ Mips_MPL1, Mips_P0, Mips_P1, Mips_P2,
    /* 50 */ Mips_MPL2, Mips_P0, Mips_P1, Mips_P2,
    /* 54 */ Mips_P0,
    /* 55 */ Mips_P1,
    /* 56 */ Mips_P2,
    /* 57 */ Mips_DSPOutFlag21,
    /* 58 */ Mips_DSPOutFlag22,
    /* 59 */ Mips_P0, Mips_P1, Mips_P2,
    /* 62 */ Mips_MPL1, Mips_MPL2, Mips_P0, Mips_P1, Mips_P2,
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
enum Arch {
	Arch_dsp,
	Arch_mmdsp,
	Arch_mipsr6,
	Arch_micromipsr6,
	Arch_se,
	Arch_micromips
};

// Dsp2MicroMips
int Dsp2MicroMips(uint16_t Opcode, enum Arch inArch) {
static const uint16_t Dsp2MicroMipsTable[][3] = {
  { Mips_ABSQ_S_PH, Mips_ABSQ_S_PH, Mips_ABSQ_S_PH_MM },
  { Mips_ABSQ_S_QB, Mips_ABSQ_S_QB, Mips_ABSQ_S_QB_MMR2 },
  { Mips_ABSQ_S_W, Mips_ABSQ_S_W, Mips_ABSQ_S_W_MM },
  { Mips_ADDQH_PH, Mips_ADDQH_PH, Mips_ADDQH_PH_MMR2 },
  { Mips_ADDQH_R_PH, Mips_ADDQH_R_PH, Mips_ADDQH_R_PH_MMR2 },
  { Mips_ADDQH_R_W, Mips_ADDQH_R_W, Mips_ADDQH_R_W_MMR2 },
  { Mips_ADDQH_W, Mips_ADDQH_W, Mips_ADDQH_W_MMR2 },
  { Mips_ADDQ_PH, Mips_ADDQ_PH, Mips_ADDQ_PH_MM },
  { Mips_ADDQ_S_PH, Mips_ADDQ_S_PH, Mips_ADDQ_S_PH_MM },
  { Mips_ADDQ_S_W, Mips_ADDQ_S_W, Mips_ADDQ_S_W_MM },
  { Mips_ADDSC, Mips_ADDSC, Mips_ADDSC_MM },
  { Mips_ADDUH_QB, Mips_ADDUH_QB, Mips_ADDUH_QB_MMR2 },
  { Mips_ADDUH_R_QB, Mips_ADDUH_R_QB, Mips_ADDUH_R_QB_MMR2 },
  { Mips_ADDU_PH, Mips_ADDU_PH, Mips_ADDU_PH_MMR2 },
  { Mips_ADDU_QB, Mips_ADDU_QB, Mips_ADDU_QB_MM },
  { Mips_ADDU_S_PH, Mips_ADDU_S_PH, Mips_ADDU_S_PH_MMR2 },
  { Mips_ADDU_S_QB, Mips_ADDU_S_QB, Mips_ADDU_S_QB_MM },
  { Mips_ADDWC, Mips_ADDWC, Mips_ADDWC_MM },
  { Mips_APPEND, Mips_APPEND, Mips_APPEND_MMR2 },
  { Mips_BALIGN, Mips_BALIGN, Mips_BALIGN_MMR2 },
  { Mips_BITREV, Mips_BITREV, Mips_BITREV_MM },
  { Mips_BPOSGE32, Mips_BPOSGE32, Mips_BPOSGE32_MM },
  { Mips_CMPGDU_EQ_QB, Mips_CMPGDU_EQ_QB, Mips_CMPGDU_EQ_QB_MMR2 },
  { Mips_CMPGDU_LE_QB, Mips_CMPGDU_LE_QB, Mips_CMPGDU_LE_QB_MMR2 },
  { Mips_CMPGDU_LT_QB, Mips_CMPGDU_LT_QB, Mips_CMPGDU_LT_QB_MMR2 },
  { Mips_CMPGU_EQ_QB, Mips_CMPGU_EQ_QB, Mips_CMPGU_EQ_QB_MM },
  { Mips_CMPGU_LE_QB, Mips_CMPGU_LE_QB, Mips_CMPGU_LE_QB_MM },
  { Mips_CMPGU_LT_QB, Mips_CMPGU_LT_QB, Mips_CMPGU_LT_QB_MM },
  { Mips_CMPU_EQ_QB, Mips_CMPU_EQ_QB, Mips_CMPU_EQ_QB_MM },
  { Mips_CMPU_LE_QB, Mips_CMPU_LE_QB, Mips_CMPU_LE_QB_MM },
  { Mips_CMPU_LT_QB, Mips_CMPU_LT_QB, Mips_CMPU_LT_QB_MM },
  { Mips_CMP_EQ_PH, Mips_CMP_EQ_PH, Mips_CMP_EQ_PH_MM },
  { Mips_CMP_LE_PH, Mips_CMP_LE_PH, Mips_CMP_LE_PH_MM },
  { Mips_CMP_LT_PH, Mips_CMP_LT_PH, Mips_CMP_LT_PH_MM },
  { Mips_DPAQX_SA_W_PH, Mips_DPAQX_SA_W_PH, Mips_DPAQX_SA_W_PH_MMR2 },
  { Mips_DPAQX_S_W_PH, Mips_DPAQX_S_W_PH, Mips_DPAQX_S_W_PH_MMR2 },
  { Mips_DPAQ_SA_L_W, Mips_DPAQ_SA_L_W, Mips_DPAQ_SA_L_W_MM },
  { Mips_DPAQ_S_W_PH, Mips_DPAQ_S_W_PH, Mips_DPAQ_S_W_PH_MM },
  { Mips_DPAU_H_QBL, Mips_DPAU_H_QBL, Mips_DPAU_H_QBL_MM },
  { Mips_DPAU_H_QBR, Mips_DPAU_H_QBR, Mips_DPAU_H_QBR_MM },
  { Mips_DPAX_W_PH, Mips_DPAX_W_PH, Mips_DPAX_W_PH_MMR2 },
  { Mips_DPA_W_PH, Mips_DPA_W_PH, Mips_DPA_W_PH_MMR2 },
  { Mips_DPSQX_SA_W_PH, Mips_DPSQX_SA_W_PH, Mips_DPSQX_SA_W_PH_MMR2 },
  { Mips_DPSQX_S_W_PH, Mips_DPSQX_S_W_PH, Mips_DPSQX_S_W_PH_MMR2 },
  { Mips_DPSQ_SA_L_W, Mips_DPSQ_SA_L_W, Mips_DPSQ_SA_L_W_MM },
  { Mips_DPSQ_S_W_PH, Mips_DPSQ_S_W_PH, Mips_DPSQ_S_W_PH_MM },
  { Mips_DPSU_H_QBL, Mips_DPSU_H_QBL, Mips_DPSU_H_QBL_MM },
  { Mips_DPSU_H_QBR, Mips_DPSU_H_QBR, Mips_DPSU_H_QBR_MM },
  { Mips_DPSX_W_PH, Mips_DPSX_W_PH, Mips_DPSX_W_PH_MMR2 },
  { Mips_DPS_W_PH, Mips_DPS_W_PH, Mips_DPS_W_PH_MMR2 },
  { Mips_EXTP, Mips_EXTP, Mips_EXTP_MM },
  { Mips_EXTPDP, Mips_EXTPDP, Mips_EXTPDP_MM },
  { Mips_EXTPDPV, Mips_EXTPDPV, Mips_EXTPDPV_MM },
  { Mips_EXTPV, Mips_EXTPV, Mips_EXTPV_MM },
  { Mips_EXTRV_RS_W, Mips_EXTRV_RS_W, Mips_EXTRV_RS_W_MM },
  { Mips_EXTRV_R_W, Mips_EXTRV_R_W, Mips_EXTRV_R_W_MM },
  { Mips_EXTRV_S_H, Mips_EXTRV_S_H, Mips_EXTRV_S_H_MM },
  { Mips_EXTRV_W, Mips_EXTRV_W, Mips_EXTRV_W_MM },
  { Mips_EXTR_RS_W, Mips_EXTR_RS_W, Mips_EXTR_RS_W_MM },
  { Mips_EXTR_R_W, Mips_EXTR_R_W, Mips_EXTR_R_W_MM },
  { Mips_EXTR_S_H, Mips_EXTR_S_H, Mips_EXTR_S_H_MM },
  { Mips_EXTR_W, Mips_EXTR_W, Mips_EXTR_W_MM },
  { Mips_INSV, Mips_INSV, Mips_INSV_MM },
  { Mips_LBUX, Mips_LBUX, Mips_LBUX_MM },
  { Mips_LHX, Mips_LHX, Mips_LHX_MM },
  { Mips_LWDSP, Mips_LWDSP, Mips_LWDSP_MM },
  { Mips_LWX, Mips_LWX, Mips_LWX_MM },
  { Mips_MADDU_DSP, Mips_MADDU_DSP, Mips_MADDU_DSP_MM },
  { Mips_MADD_DSP, Mips_MADD_DSP, Mips_MADD_DSP_MM },
  { Mips_MAQ_SA_W_PHL, Mips_MAQ_SA_W_PHL, Mips_MAQ_SA_W_PHL_MM },
  { Mips_MAQ_SA_W_PHR, Mips_MAQ_SA_W_PHR, Mips_MAQ_SA_W_PHR_MM },
  { Mips_MAQ_S_W_PHL, Mips_MAQ_S_W_PHL, Mips_MAQ_S_W_PHL_MM },
  { Mips_MAQ_S_W_PHR, Mips_MAQ_S_W_PHR, Mips_MAQ_S_W_PHR_MM },
  { Mips_MFHI_DSP, Mips_MFHI_DSP, Mips_MFHI_DSP_MM },
  { Mips_MFLO_DSP, Mips_MFLO_DSP, Mips_MFLO_DSP_MM },
  { Mips_MODSUB, Mips_MODSUB, Mips_MODSUB_MM },
  { Mips_MSUBU_DSP, Mips_MSUBU_DSP, Mips_MSUBU_DSP_MM },
  { Mips_MSUB_DSP, Mips_MSUB_DSP, Mips_MSUB_DSP_MM },
  { Mips_MTHI_DSP, Mips_MTHI_DSP, Mips_MTHI_DSP_MM },
  { Mips_MTHLIP, Mips_MTHLIP, Mips_MTHLIP_MM },
  { Mips_MTLO_DSP, Mips_MTLO_DSP, Mips_MTLO_DSP_MM },
  { Mips_MULEQ_S_W_PHL, Mips_MULEQ_S_W_PHL, Mips_MULEQ_S_W_PHL_MM },
  { Mips_MULEQ_S_W_PHR, Mips_MULEQ_S_W_PHR, Mips_MULEQ_S_W_PHR_MM },
  { Mips_MULEU_S_PH_QBL, Mips_MULEU_S_PH_QBL, Mips_MULEU_S_PH_QBL_MM },
  { Mips_MULEU_S_PH_QBR, Mips_MULEU_S_PH_QBR, Mips_MULEU_S_PH_QBR_MM },
  { Mips_MULQ_RS_PH, Mips_MULQ_RS_PH, Mips_MULQ_RS_PH_MM },
  { Mips_MULQ_RS_W, Mips_MULQ_RS_W, Mips_MULQ_RS_W_MMR2 },
  { Mips_MULQ_S_PH, Mips_MULQ_S_PH, Mips_MULQ_S_PH_MMR2 },
  { Mips_MULQ_S_W, Mips_MULQ_S_W, Mips_MULQ_S_W_MMR2 },
  { Mips_MULSAQ_S_W_PH, Mips_MULSAQ_S_W_PH, Mips_MULSAQ_S_W_PH_MM },
  { Mips_MULSA_W_PH, Mips_MULSA_W_PH, Mips_MULSA_W_PH_MMR2 },
  { Mips_MULTU_DSP, Mips_MULTU_DSP, Mips_MULTU_DSP_MM },
  { Mips_MULT_DSP, Mips_MULT_DSP, Mips_MULT_DSP_MM },
  { Mips_MUL_PH, Mips_MUL_PH, Mips_MUL_PH_MMR2 },
  { Mips_MUL_S_PH, Mips_MUL_S_PH, Mips_MUL_S_PH_MMR2 },
  { Mips_PACKRL_PH, Mips_PACKRL_PH, Mips_PACKRL_PH_MM },
  { Mips_PICK_PH, Mips_PICK_PH, Mips_PICK_PH_MM },
  { Mips_PICK_QB, Mips_PICK_QB, Mips_PICK_QB_MM },
  { Mips_PRECEQU_PH_QBL, Mips_PRECEQU_PH_QBL, Mips_PRECEQU_PH_QBL_MM },
  { Mips_PRECEQU_PH_QBLA, Mips_PRECEQU_PH_QBLA, Mips_PRECEQU_PH_QBLA_MM },
  { Mips_PRECEQU_PH_QBR, Mips_PRECEQU_PH_QBR, Mips_PRECEQU_PH_QBR_MM },
  { Mips_PRECEQU_PH_QBRA, Mips_PRECEQU_PH_QBRA, Mips_PRECEQU_PH_QBRA_MM },
  { Mips_PRECEQ_W_PHL, Mips_PRECEQ_W_PHL, Mips_PRECEQ_W_PHL_MM },
  { Mips_PRECEQ_W_PHR, Mips_PRECEQ_W_PHR, Mips_PRECEQ_W_PHR_MM },
  { Mips_PRECEU_PH_QBL, Mips_PRECEU_PH_QBL, Mips_PRECEU_PH_QBL_MM },
  { Mips_PRECEU_PH_QBLA, Mips_PRECEU_PH_QBLA, Mips_PRECEU_PH_QBLA_MM },
  { Mips_PRECEU_PH_QBR, Mips_PRECEU_PH_QBR, Mips_PRECEU_PH_QBR_MM },
  { Mips_PRECEU_PH_QBRA, Mips_PRECEU_PH_QBRA, Mips_PRECEU_PH_QBRA_MM },
  { Mips_PRECRQU_S_QB_PH, Mips_PRECRQU_S_QB_PH, Mips_PRECRQU_S_QB_PH_MM },
  { Mips_PRECRQ_PH_W, Mips_PRECRQ_PH_W, Mips_PRECRQ_PH_W_MM },
  { Mips_PRECRQ_QB_PH, Mips_PRECRQ_QB_PH, Mips_PRECRQ_QB_PH_MM },
  { Mips_PRECRQ_RS_PH_W, Mips_PRECRQ_RS_PH_W, Mips_PRECRQ_RS_PH_W_MM },
  { Mips_PRECR_QB_PH, Mips_PRECR_QB_PH, Mips_PRECR_QB_PH_MMR2 },
  { Mips_PRECR_SRA_PH_W, Mips_PRECR_SRA_PH_W, Mips_PRECR_SRA_PH_W_MMR2 },
  { Mips_PRECR_SRA_R_PH_W, Mips_PRECR_SRA_R_PH_W, Mips_PRECR_SRA_R_PH_W_MMR2 },
  { Mips_PREPEND, Mips_PREPEND, Mips_PREPEND_MMR2 },
  { Mips_RADDU_W_QB, Mips_RADDU_W_QB, Mips_RADDU_W_QB_MM },
  { Mips_RDDSP, Mips_RDDSP, Mips_RDDSP_MM },
  { Mips_REPLV_PH, Mips_REPLV_PH, Mips_REPLV_PH_MM },
  { Mips_REPLV_QB, Mips_REPLV_QB, Mips_REPLV_QB_MM },
  { Mips_REPL_PH, Mips_REPL_PH, Mips_REPL_PH_MM },
  { Mips_REPL_QB, Mips_REPL_QB, Mips_REPL_QB_MM },
  { Mips_SHILO, Mips_SHILO, Mips_SHILO_MM },
  { Mips_SHILOV, Mips_SHILOV, Mips_SHILOV_MM },
  { Mips_SHLLV_PH, Mips_SHLLV_PH, Mips_SHLLV_PH_MM },
  { Mips_SHLLV_QB, Mips_SHLLV_QB, Mips_SHLLV_QB_MM },
  { Mips_SHLLV_S_PH, Mips_SHLLV_S_PH, Mips_SHLLV_S_PH_MM },
  { Mips_SHLLV_S_W, Mips_SHLLV_S_W, Mips_SHLLV_S_W_MM },
  { Mips_SHLL_PH, Mips_SHLL_PH, Mips_SHLL_PH_MM },
  { Mips_SHLL_QB, Mips_SHLL_QB, Mips_SHLL_QB_MM },
  { Mips_SHLL_S_PH, Mips_SHLL_S_PH, Mips_SHLL_S_PH_MM },
  { Mips_SHLL_S_W, Mips_SHLL_S_W, Mips_SHLL_S_W_MM },
  { Mips_SHRAV_PH, Mips_SHRAV_PH, Mips_SHRAV_PH_MM },
  { Mips_SHRAV_QB, Mips_SHRAV_QB, Mips_SHRAV_QB_MMR2 },
  { Mips_SHRAV_R_PH, Mips_SHRAV_R_PH, Mips_SHRAV_R_PH_MM },
  { Mips_SHRAV_R_QB, Mips_SHRAV_R_QB, Mips_SHRAV_R_QB_MMR2 },
  { Mips_SHRAV_R_W, Mips_SHRAV_R_W, Mips_SHRAV_R_W_MM },
  { Mips_SHRA_PH, Mips_SHRA_PH, Mips_SHRA_PH_MM },
  { Mips_SHRA_QB, Mips_SHRA_QB, Mips_SHRA_QB_MMR2 },
  { Mips_SHRA_R_PH, Mips_SHRA_R_PH, Mips_SHRA_R_PH_MM },
  { Mips_SHRA_R_QB, Mips_SHRA_R_QB, Mips_SHRA_R_QB_MMR2 },
  { Mips_SHRA_R_W, Mips_SHRA_R_W, Mips_SHRA_R_W_MM },
  { Mips_SHRLV_PH, Mips_SHRLV_PH, Mips_SHRLV_PH_MMR2 },
  { Mips_SHRLV_QB, Mips_SHRLV_QB, Mips_SHRLV_QB_MM },
  { Mips_SHRL_PH, Mips_SHRL_PH, Mips_SHRL_PH_MMR2 },
  { Mips_SHRL_QB, Mips_SHRL_QB, Mips_SHRL_QB_MM },
  { Mips_SUBQH_PH, Mips_SUBQH_PH, Mips_SUBQH_PH_MMR2 },
  { Mips_SUBQH_R_PH, Mips_SUBQH_R_PH, Mips_SUBQH_R_PH_MMR2 },
  { Mips_SUBQH_R_W, Mips_SUBQH_R_W, Mips_SUBQH_R_W_MMR2 },
  { Mips_SUBQH_W, Mips_SUBQH_W, Mips_SUBQH_W_MMR2 },
  { Mips_SUBQ_PH, Mips_SUBQ_PH, Mips_SUBQ_PH_MM },
  { Mips_SUBQ_S_PH, Mips_SUBQ_S_PH, Mips_SUBQ_S_PH_MM },
  { Mips_SUBQ_S_W, Mips_SUBQ_S_W, Mips_SUBQ_S_W_MM },
  { Mips_SUBUH_QB, Mips_SUBUH_QB, Mips_SUBUH_QB_MMR2 },
  { Mips_SUBUH_R_QB, Mips_SUBUH_R_QB, Mips_SUBUH_R_QB_MMR2 },
  { Mips_SUBU_PH, Mips_SUBU_PH, Mips_SUBU_PH_MMR2 },
  { Mips_SUBU_QB, Mips_SUBU_QB, Mips_SUBU_QB_MM },
  { Mips_SUBU_S_PH, Mips_SUBU_S_PH, Mips_SUBU_S_PH_MMR2 },
  { Mips_SUBU_S_QB, Mips_SUBU_S_QB, Mips_SUBU_S_QB_MM },
  { Mips_SWDSP, Mips_SWDSP, Mips_SWDSP_MM },
}; // End of Dsp2MicroMipsTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 160;
  while (start < end) {
    mid = start + (end - start) / 2;
    if (Opcode == Dsp2MicroMipsTable[mid][0]) {
      break;
    }
    if (Opcode < Dsp2MicroMipsTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  if (inArch == Arch_dsp)
    return Dsp2MicroMipsTable[mid][1];
  if (inArch == Arch_mmdsp)
    return Dsp2MicroMipsTable[mid][2];
  return -1;}

// MipsR62MicroMipsR6
int MipsR62MicroMipsR6(uint16_t Opcode, enum Arch inArch) {
static const uint16_t MipsR62MicroMipsR6Table[][3] = {
  { Mips_ADDIUPC, Mips_ADDIUPC, Mips_ADDIUPC_MMR6 },
  { Mips_ALIGN, Mips_ALIGN, Mips_ALIGN_MMR6 },
  { Mips_ALUIPC, Mips_ALUIPC, Mips_ALUIPC_MMR6 },
  { Mips_AUI, Mips_AUI, Mips_AUI_MMR6 },
  { Mips_AUIPC, Mips_AUIPC, Mips_AUIPC_MMR6 },
  { Mips_BALC, Mips_BALC, Mips_BALC_MMR6 },
  { Mips_BC, Mips_BC, Mips_BC_MMR6 },
  { Mips_BEQC, Mips_BEQC, Mips_BEQC_MMR6 },
  { Mips_BEQZALC, Mips_BEQZALC, Mips_BEQZALC_MMR6 },
  { Mips_BEQZC, Mips_BEQZC, Mips_BEQZC_MMR6 },
  { Mips_BGEC, Mips_BGEC, Mips_BGEC_MMR6 },
  { Mips_BGEUC, Mips_BGEUC, Mips_BGEUC_MMR6 },
  { Mips_BGEZALC, Mips_BGEZALC, Mips_BGEZALC_MMR6 },
  { Mips_BGEZC, Mips_BGEZC, Mips_BGEZC_MMR6 },
  { Mips_BGTZALC, Mips_BGTZALC, Mips_BGTZALC_MMR6 },
  { Mips_BGTZC, Mips_BGTZC, Mips_BGTZC_MMR6 },
  { Mips_BITSWAP, Mips_BITSWAP, Mips_BITSWAP_MMR6 },
  { Mips_BLEZALC, Mips_BLEZALC, Mips_BLEZALC_MMR6 },
  { Mips_BLEZC, Mips_BLEZC, Mips_BLEZC_MMR6 },
  { Mips_BLTC, Mips_BLTC, Mips_BLTC_MMR6 },
  { Mips_BLTUC, Mips_BLTUC, Mips_BLTUC_MMR6 },
  { Mips_BLTZALC, Mips_BLTZALC, Mips_BLTZALC_MMR6 },
  { Mips_BLTZC, Mips_BLTZC, Mips_BLTZC_MMR6 },
  { Mips_BNEC, Mips_BNEC, Mips_BNEC_MMR6 },
  { Mips_BNEZALC, Mips_BNEZALC, Mips_BNEZALC_MMR6 },
  { Mips_BNEZC, Mips_BNEZC, Mips_BNEZC_MMR6 },
  { Mips_BNVC, Mips_BNVC, Mips_BNVC_MMR6 },
  { Mips_BOVC, Mips_BOVC, Mips_BOVC_MMR6 },
  { Mips_CACHE_R6, Mips_CACHE_R6, Mips_CACHE_MMR6 },
  { Mips_CLO_R6, Mips_CLO_R6, Mips_CLO_MMR6 },
  { Mips_CLZ_R6, Mips_CLZ_R6, Mips_CLZ_MMR6 },
  { Mips_CMP_EQ_D, Mips_CMP_EQ_D, Mips_CMP_EQ_D_MMR6 },
  { Mips_CMP_EQ_S, Mips_CMP_EQ_S, Mips_CMP_EQ_S_MMR6 },
  { Mips_CMP_F_D, Mips_CMP_F_D, Mips_CMP_AF_D_MMR6 },
  { Mips_CMP_F_S, Mips_CMP_F_S, Mips_CMP_AF_S_MMR6 },
  { Mips_CMP_LE_D, Mips_CMP_LE_D, Mips_CMP_LE_D_MMR6 },
  { Mips_CMP_LE_S, Mips_CMP_LE_S, Mips_CMP_LE_S_MMR6 },
  { Mips_CMP_LT_D, Mips_CMP_LT_D, Mips_CMP_LT_D_MMR6 },
  { Mips_CMP_LT_S, Mips_CMP_LT_S, Mips_CMP_LT_S_MMR6 },
  { Mips_CMP_SAF_D, Mips_CMP_SAF_D, Mips_CMP_SAF_D_MMR6 },
  { Mips_CMP_SAF_S, Mips_CMP_SAF_S, Mips_CMP_SAF_S_MMR6 },
  { Mips_CMP_SEQ_D, Mips_CMP_SEQ_D, Mips_CMP_SEQ_D_MMR6 },
  { Mips_CMP_SEQ_S, Mips_CMP_SEQ_S, Mips_CMP_SEQ_S_MMR6 },
  { Mips_CMP_SLE_D, Mips_CMP_SLE_D, Mips_CMP_SLE_D_MMR6 },
  { Mips_CMP_SLE_S, Mips_CMP_SLE_S, Mips_CMP_SLE_S_MMR6 },
  { Mips_CMP_SLT_D, Mips_CMP_SLT_D, Mips_CMP_SLT_D_MMR6 },
  { Mips_CMP_SLT_S, Mips_CMP_SLT_S, Mips_CMP_SLT_S_MMR6 },
  { Mips_CMP_SUEQ_D, Mips_CMP_SUEQ_D, Mips_CMP_SUEQ_D_MMR6 },
  { Mips_CMP_SUEQ_S, Mips_CMP_SUEQ_S, Mips_CMP_SUEQ_S_MMR6 },
  { Mips_CMP_SULE_D, Mips_CMP_SULE_D, Mips_CMP_SULE_D_MMR6 },
  { Mips_CMP_SULE_S, Mips_CMP_SULE_S, Mips_CMP_SULE_S_MMR6 },
  { Mips_CMP_SULT_D, Mips_CMP_SULT_D, Mips_CMP_SULT_D_MMR6 },
  { Mips_CMP_SULT_S, Mips_CMP_SULT_S, Mips_CMP_SULT_S_MMR6 },
  { Mips_CMP_SUN_D, Mips_CMP_SUN_D, Mips_CMP_SUN_D_MMR6 },
  { Mips_CMP_SUN_S, Mips_CMP_SUN_S, Mips_CMP_SUN_S_MMR6 },
  { Mips_CMP_UEQ_D, Mips_CMP_UEQ_D, Mips_CMP_UEQ_D_MMR6 },
  { Mips_CMP_UEQ_S, Mips_CMP_UEQ_S, Mips_CMP_UEQ_S_MMR6 },
  { Mips_CMP_ULE_D, Mips_CMP_ULE_D, Mips_CMP_ULE_D_MMR6 },
  { Mips_CMP_ULE_S, Mips_CMP_ULE_S, Mips_CMP_ULE_S_MMR6 },
  { Mips_CMP_ULT_D, Mips_CMP_ULT_D, Mips_CMP_ULT_D_MMR6 },
  { Mips_CMP_ULT_S, Mips_CMP_ULT_S, Mips_CMP_ULT_S_MMR6 },
  { Mips_CMP_UN_D, Mips_CMP_UN_D, Mips_CMP_UN_D_MMR6 },
  { Mips_CMP_UN_S, Mips_CMP_UN_S, Mips_CMP_UN_S_MMR6 },
  { Mips_CRC32B, Mips_CRC32B, (uint16_t)-1U },
  { Mips_CRC32CB, Mips_CRC32CB, (uint16_t)-1U },
  { Mips_CRC32CD, Mips_CRC32CD, (uint16_t)-1U },
  { Mips_CRC32CH, Mips_CRC32CH, (uint16_t)-1U },
  { Mips_CRC32CW, Mips_CRC32CW, (uint16_t)-1U },
  { Mips_CRC32D, Mips_CRC32D, (uint16_t)-1U },
  { Mips_CRC32H, Mips_CRC32H, (uint16_t)-1U },
  { Mips_CRC32W, Mips_CRC32W, (uint16_t)-1U },
  { Mips_DIV, Mips_DIV, Mips_DIV_MMR6 },
  { Mips_DIVU, Mips_DIVU, Mips_DIVU_MMR6 },
  { Mips_DVP, Mips_DVP, Mips_DVP_MMR6 },
  { Mips_EVP, Mips_EVP, Mips_EVP_MMR6 },
  { Mips_GINVI, Mips_GINVI, Mips_GINVI_MMR6 },
  { Mips_GINVT, Mips_GINVT, Mips_GINVT_MMR6 },
  { Mips_JIALC, Mips_JIALC, Mips_JIALC_MMR6 },
  { Mips_JIC, Mips_JIC, Mips_JIC_MMR6 },
  { Mips_LSA_R6, Mips_LSA_R6, Mips_LSA_MMR6 },
  { Mips_LWPC, Mips_LWPC, Mips_LWPC_MMR6 },
  { Mips_MOD, Mips_MOD, Mips_MOD_MMR6 },
  { Mips_MODU, Mips_MODU, Mips_MODU_MMR6 },
  { Mips_MUH, Mips_MUH, Mips_MUH_MMR6 },
  { Mips_MUHU, Mips_MUHU, Mips_MUHU_MMR6 },
  { Mips_MULU, Mips_MULU, Mips_MULU_MMR6 },
  { Mips_MUL_R6, Mips_MUL_R6, Mips_MUL_MMR6 },
  { Mips_PREF_R6, Mips_PREF_R6, Mips_PREF_MMR6 },
  { Mips_SELEQZ, Mips_SELEQZ, Mips_SELEQZ_MMR6 },
  { Mips_SELEQZ_D, Mips_SELEQZ_D, Mips_SELEQZ_D_MMR6 },
  { Mips_SELEQZ_S, Mips_SELEQZ_S, Mips_SELEQZ_S_MMR6 },
  { Mips_SELNEZ, Mips_SELNEZ, Mips_SELNEZ_MMR6 },
  { Mips_SELNEZ_D, Mips_SELNEZ_D, Mips_SELNEZ_D_MMR6 },
  { Mips_SELNEZ_S, Mips_SELNEZ_S, Mips_SELNEZ_S_MMR6 },
  { Mips_SEL_D, Mips_SEL_D, Mips_SEL_D_MMR6 },
  { Mips_SEL_S, Mips_SEL_S, Mips_SEL_S_MMR6 },
}; // End of MipsR62MicroMipsR6Table

  unsigned mid;
  unsigned start = 0;
  unsigned end = 96;
  while (start < end) {
    mid = start + (end - start) / 2;
    if (Opcode == MipsR62MicroMipsR6Table[mid][0]) {
      break;
    }
    if (Opcode < MipsR62MicroMipsR6Table[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  if (inArch == Arch_mipsr6)
    return MipsR62MicroMipsR6Table[mid][1];
  if (inArch == Arch_micromipsr6)
    return MipsR62MicroMipsR6Table[mid][2];
  return -1;}

// Std2MicroMips
int Std2MicroMips(uint16_t Opcode, enum Arch inArch) {
static const uint16_t Std2MicroMipsTable[][3] = {
  { Mips_ADD, Mips_ADD, Mips_ADD_MM },
  { Mips_ADDi, Mips_ADDi, Mips_ADDi_MM },
  { Mips_ADDiu, Mips_ADDiu, Mips_ADDiu_MM },
  { Mips_ADDu, Mips_ADDu, Mips_ADDu_MM },
  { Mips_AND, Mips_AND, Mips_AND_MM },
  { Mips_ANDi, Mips_ANDi, Mips_ANDi_MM },
  { Mips_BC1F, Mips_BC1F, Mips_BC1F_MM },
  { Mips_BC1FL, Mips_BC1FL, (uint16_t)-1U },
  { Mips_BC1T, Mips_BC1T, Mips_BC1T_MM },
  { Mips_BC1TL, Mips_BC1TL, (uint16_t)-1U },
  { Mips_BEQ, Mips_BEQ, Mips_BEQ_MM },
  { Mips_BEQL, Mips_BEQL, (uint16_t)-1U },
  { Mips_BGEZ, Mips_BGEZ, Mips_BGEZ_MM },
  { Mips_BGEZAL, Mips_BGEZAL, Mips_BGEZAL_MM },
  { Mips_BGEZALL, Mips_BGEZALL, (uint16_t)-1U },
  { Mips_BGEZL, Mips_BGEZL, (uint16_t)-1U },
  { Mips_BGTZ, Mips_BGTZ, Mips_BGTZ_MM },
  { Mips_BGTZL, Mips_BGTZL, (uint16_t)-1U },
  { Mips_BLEZ, Mips_BLEZ, Mips_BLEZ_MM },
  { Mips_BLEZL, Mips_BLEZL, (uint16_t)-1U },
  { Mips_BLTZ, Mips_BLTZ, Mips_BLTZ_MM },
  { Mips_BLTZAL, Mips_BLTZAL, Mips_BLTZAL_MM },
  { Mips_BLTZALL, Mips_BLTZALL, (uint16_t)-1U },
  { Mips_BLTZL, Mips_BLTZL, (uint16_t)-1U },
  { Mips_BNE, Mips_BNE, Mips_BNE_MM },
  { Mips_BNEL, Mips_BNEL, (uint16_t)-1U },
  { Mips_BREAK, Mips_BREAK, Mips_BREAK_MM },
  { Mips_CACHE, Mips_CACHE, Mips_CACHE_MM },
  { Mips_CACHEE, Mips_CACHEE, Mips_CACHEE_MM },
  { Mips_CEIL_W_D32, Mips_CEIL_W_D32, Mips_CEIL_W_MM },
  { Mips_CEIL_W_S, Mips_CEIL_W_S, Mips_CEIL_W_S_MM },
  { Mips_CFC1, Mips_CFC1, Mips_CFC1_MM },
  { Mips_CLO, Mips_CLO, Mips_CLO_MM },
  { Mips_CLZ, Mips_CLZ, Mips_CLZ_MM },
  { Mips_CTC1, Mips_CTC1, Mips_CTC1_MM },
  { Mips_CVT_D32_S, Mips_CVT_D32_S, Mips_CVT_D32_S_MM },
  { Mips_CVT_D32_W, Mips_CVT_D32_W, Mips_CVT_D32_W_MM },
  { Mips_CVT_L_D64, Mips_CVT_L_D64, Mips_CVT_L_D64_MM },
  { Mips_CVT_L_S, Mips_CVT_L_S, Mips_CVT_L_S_MM },
  { Mips_CVT_S_D32, Mips_CVT_S_D32, Mips_CVT_S_D32_MM },
  { Mips_CVT_S_W, Mips_CVT_S_W, Mips_CVT_S_W_MM },
  { Mips_CVT_W_D32, Mips_CVT_W_D32, Mips_CVT_W_D32_MM },
  { Mips_CVT_W_S, Mips_CVT_W_S, Mips_CVT_W_S_MM },
  { Mips_C_EQ_D32, Mips_C_EQ_D32, Mips_C_EQ_D32_MM },
  { Mips_C_EQ_D64, Mips_C_EQ_D64, Mips_C_EQ_D64_MM },
  { Mips_C_EQ_S, Mips_C_EQ_S, Mips_C_EQ_S_MM },
  { Mips_C_F_D32, Mips_C_F_D32, Mips_C_F_D32_MM },
  { Mips_C_F_D64, Mips_C_F_D64, Mips_C_F_D64_MM },
  { Mips_C_F_S, Mips_C_F_S, Mips_C_F_S_MM },
  { Mips_C_LE_D32, Mips_C_LE_D32, Mips_C_LE_D32_MM },
  { Mips_C_LE_D64, Mips_C_LE_D64, Mips_C_LE_D64_MM },
  { Mips_C_LE_S, Mips_C_LE_S, Mips_C_LE_S_MM },
  { Mips_C_LT_D32, Mips_C_LT_D32, Mips_C_LT_D32_MM },
  { Mips_C_LT_D64, Mips_C_LT_D64, Mips_C_LT_D64_MM },
  { Mips_C_LT_S, Mips_C_LT_S, Mips_C_LT_S_MM },
  { Mips_C_NGE_D32, Mips_C_NGE_D32, Mips_C_NGE_D32_MM },
  { Mips_C_NGE_D64, Mips_C_NGE_D64, Mips_C_NGE_D64_MM },
  { Mips_C_NGE_S, Mips_C_NGE_S, Mips_C_NGE_S_MM },
  { Mips_C_NGLE_D32, Mips_C_NGLE_D32, Mips_C_NGLE_D32_MM },
  { Mips_C_NGLE_D64, Mips_C_NGLE_D64, Mips_C_NGLE_D64_MM },
  { Mips_C_NGLE_S, Mips_C_NGLE_S, Mips_C_NGLE_S_MM },
  { Mips_C_NGL_D32, Mips_C_NGL_D32, Mips_C_NGL_D32_MM },
  { Mips_C_NGL_D64, Mips_C_NGL_D64, Mips_C_NGL_D64_MM },
  { Mips_C_NGL_S, Mips_C_NGL_S, Mips_C_NGL_S_MM },
  { Mips_C_NGT_D32, Mips_C_NGT_D32, Mips_C_NGT_D32_MM },
  { Mips_C_NGT_D64, Mips_C_NGT_D64, Mips_C_NGT_D64_MM },
  { Mips_C_NGT_S, Mips_C_NGT_S, Mips_C_NGT_S_MM },
  { Mips_C_OLE_D32, Mips_C_OLE_D32, Mips_C_OLE_D32_MM },
  { Mips_C_OLE_D64, Mips_C_OLE_D64, Mips_C_OLE_D64_MM },
  { Mips_C_OLE_S, Mips_C_OLE_S, Mips_C_OLE_S_MM },
  { Mips_C_OLT_D32, Mips_C_OLT_D32, Mips_C_OLT_D32_MM },
  { Mips_C_OLT_D64, Mips_C_OLT_D64, Mips_C_OLT_D64_MM },
  { Mips_C_OLT_S, Mips_C_OLT_S, Mips_C_OLT_S_MM },
  { Mips_C_SEQ_D32, Mips_C_SEQ_D32, Mips_C_SEQ_D32_MM },
  { Mips_C_SEQ_D64, Mips_C_SEQ_D64, Mips_C_SEQ_D64_MM },
  { Mips_C_SEQ_S, Mips_C_SEQ_S, Mips_C_SEQ_S_MM },
  { Mips_C_SF_D32, Mips_C_SF_D32, Mips_C_SF_D32_MM },
  { Mips_C_SF_D64, Mips_C_SF_D64, Mips_C_SF_D64_MM },
  { Mips_C_SF_S, Mips_C_SF_S, Mips_C_SF_S_MM },
  { Mips_C_UEQ_D32, Mips_C_UEQ_D32, Mips_C_UEQ_D32_MM },
  { Mips_C_UEQ_D64, Mips_C_UEQ_D64, Mips_C_UEQ_D64_MM },
  { Mips_C_UEQ_S, Mips_C_UEQ_S, Mips_C_UEQ_S_MM },
  { Mips_C_ULE_D32, Mips_C_ULE_D32, Mips_C_ULE_D32_MM },
  { Mips_C_ULE_D64, Mips_C_ULE_D64, Mips_C_ULE_D64_MM },
  { Mips_C_ULE_S, Mips_C_ULE_S, Mips_C_ULE_S_MM },
  { Mips_C_ULT_D32, Mips_C_ULT_D32, Mips_C_ULT_D32_MM },
  { Mips_C_ULT_D64, Mips_C_ULT_D64, Mips_C_ULT_D64_MM },
  { Mips_C_ULT_S, Mips_C_ULT_S, Mips_C_ULT_S_MM },
  { Mips_C_UN_D32, Mips_C_UN_D32, Mips_C_UN_D32_MM },
  { Mips_C_UN_D64, Mips_C_UN_D64, Mips_C_UN_D64_MM },
  { Mips_C_UN_S, Mips_C_UN_S, Mips_C_UN_S_MM },
  { Mips_DERET, Mips_DERET, Mips_DERET_MM },
  { Mips_DI, Mips_DI, Mips_DI_MM },
  { Mips_EHB, Mips_EHB, Mips_EHB_MM },
  { Mips_EI, Mips_EI, Mips_EI_MM },
  { Mips_ERET, Mips_ERET, Mips_ERET_MM },
  { Mips_ERETNC, Mips_ERETNC, (uint16_t)-1U },
  { Mips_EXT, Mips_EXT, Mips_EXT_MM },
  { Mips_FABS_D32, Mips_FABS_D32, Mips_FABS_D32_MM },
  { Mips_FABS_S, Mips_FABS_S, Mips_FABS_S_MM },
  { Mips_FADD_D32, Mips_FADD_D32, Mips_FADD_D32_MM },
  { Mips_FADD_S, Mips_FADD_S, Mips_FADD_S_MM },
  { Mips_FCMP_D32, Mips_FCMP_D32, Mips_FCMP_D32_MM },
  { Mips_FCMP_S32, Mips_FCMP_S32, Mips_FCMP_S32_MM },
  { Mips_FDIV_D32, Mips_FDIV_D32, Mips_FDIV_D32_MM },
  { Mips_FDIV_S, Mips_FDIV_S, Mips_FDIV_S_MM },
  { Mips_FLOOR_W_D32, Mips_FLOOR_W_D32, Mips_FLOOR_W_MM },
  { Mips_FLOOR_W_S, Mips_FLOOR_W_S, Mips_FLOOR_W_S_MM },
  { Mips_FMOV_D32, Mips_FMOV_D32, Mips_FMOV_D32_MM },
  { Mips_FMOV_S, Mips_FMOV_S, Mips_FMOV_S_MM },
  { Mips_FMUL_D32, Mips_FMUL_D32, Mips_FMUL_D32_MM },
  { Mips_FMUL_S, Mips_FMUL_S, Mips_FMUL_S_MM },
  { Mips_FNEG_D32, Mips_FNEG_D32, Mips_FNEG_D32_MM },
  { Mips_FNEG_S, Mips_FNEG_S, Mips_FNEG_S_MM },
  { Mips_FSQRT_D32, Mips_FSQRT_D32, Mips_FSQRT_D32_MM },
  { Mips_FSQRT_S, Mips_FSQRT_S, Mips_FSQRT_S_MM },
  { Mips_FSUB_D32, Mips_FSUB_D32, Mips_FSUB_D32_MM },
  { Mips_FSUB_S, Mips_FSUB_S, Mips_FSUB_S_MM },
  { Mips_HYPCALL, Mips_HYPCALL, Mips_HYPCALL_MM },
  { Mips_INS, Mips_INS, Mips_INS_MM },
  { Mips_J, Mips_J, Mips_J_MM },
  { Mips_JAL, Mips_JAL, Mips_JAL_MM },
  { Mips_JALX, Mips_JALX, Mips_JALX_MM },
  { Mips_JR, Mips_JR, Mips_JR_MM },
  { Mips_LB, Mips_LB, Mips_LB_MM },
  { Mips_LBE, Mips_LBE, Mips_LBE_MM },
  { Mips_LBu, Mips_LBu, Mips_LBu_MM },
  { Mips_LBuE, Mips_LBuE, Mips_LBuE_MM },
  { Mips_LDC1, Mips_LDC1, Mips_LDC1_MM_D32 },
  { Mips_LEA_ADDiu, Mips_LEA_ADDiu, Mips_LEA_ADDiu_MM },
  { Mips_LH, Mips_LH, Mips_LH_MM },
  { Mips_LHE, Mips_LHE, Mips_LHE_MM },
  { Mips_LHu, Mips_LHu, Mips_LHu_MM },
  { Mips_LHuE, Mips_LHuE, Mips_LHuE_MM },
  { Mips_LLE, Mips_LLE, Mips_LLE_MM },
  { Mips_LUXC1, Mips_LUXC1, Mips_LUXC1_MM },
  { Mips_LUi, Mips_LUi, Mips_LUi_MM },
  { Mips_LW, Mips_LW, Mips_LW_MM },
  { Mips_LWC1, Mips_LWC1, Mips_LWC1_MM },
  { Mips_LWE, Mips_LWE, Mips_LWE_MM },
  { Mips_LWL, Mips_LWL, Mips_LWL_MM },
  { Mips_LWLE, Mips_LWLE, Mips_LWLE_MM },
  { Mips_LWR, Mips_LWR, Mips_LWR_MM },
  { Mips_LWRE, Mips_LWRE, Mips_LWRE_MM },
  { Mips_LWXC1, Mips_LWXC1, Mips_LWXC1_MM },
  { Mips_LWu, Mips_LWu, Mips_LWU_MM },
  { Mips_MADD, Mips_MADD, Mips_MADD_MM },
  { Mips_MADDU, Mips_MADDU, Mips_MADDU_MM },
  { Mips_MADD_D32, Mips_MADD_D32, Mips_MADD_D32_MM },
  { Mips_MADD_S, Mips_MADD_S, Mips_MADD_S_MM },
  { Mips_MFC1, Mips_MFC1, Mips_MFC1_MM },
  { Mips_MFGC0, Mips_MFGC0, Mips_MFGC0_MM },
  { Mips_MFHC1_D32, Mips_MFHC1_D32, Mips_MFHC1_D32_MM },
  { Mips_MFHGC0, Mips_MFHGC0, Mips_MFHGC0_MM },
  { Mips_MFHI, Mips_MFHI, Mips_MFHI_MM },
  { Mips_MFLO, Mips_MFLO, Mips_MFLO_MM },
  { Mips_MOVF_D32, Mips_MOVF_D32, Mips_MOVF_D32_MM },
  { Mips_MOVF_I, Mips_MOVF_I, Mips_MOVF_I_MM },
  { Mips_MOVF_S, Mips_MOVF_S, Mips_MOVF_S_MM },
  { Mips_MOVN_I_D32, Mips_MOVN_I_D32, Mips_MOVN_I_D32_MM },
  { Mips_MOVN_I_I, Mips_MOVN_I_I, Mips_MOVN_I_MM },
  { Mips_MOVN_I_S, Mips_MOVN_I_S, Mips_MOVN_I_S_MM },
  { Mips_MOVT_D32, Mips_MOVT_D32, Mips_MOVT_D32_MM },
  { Mips_MOVT_I, Mips_MOVT_I, Mips_MOVT_I_MM },
  { Mips_MOVT_S, Mips_MOVT_S, Mips_MOVT_S_MM },
  { Mips_MOVZ_I_D32, Mips_MOVZ_I_D32, Mips_MOVZ_I_D32_MM },
  { Mips_MOVZ_I_I, Mips_MOVZ_I_I, Mips_MOVZ_I_MM },
  { Mips_MOVZ_I_S, Mips_MOVZ_I_S, Mips_MOVZ_I_S_MM },
  { Mips_MSUB, Mips_MSUB, Mips_MSUB_MM },
  { Mips_MSUBU, Mips_MSUBU, Mips_MSUBU_MM },
  { Mips_MSUB_D32, Mips_MSUB_D32, Mips_MSUB_D32_MM },
  { Mips_MSUB_S, Mips_MSUB_S, Mips_MSUB_S_MM },
  { Mips_MTC1, Mips_MTC1, Mips_MTC1_MM },
  { Mips_MTGC0, Mips_MTGC0, Mips_MTGC0_MM },
  { Mips_MTHC1_D32, Mips_MTHC1_D32, Mips_MTHC1_D32_MM },
  { Mips_MTHGC0, Mips_MTHGC0, Mips_MTHGC0_MM },
  { Mips_MTHI, Mips_MTHI, Mips_MTHI_MM },
  { Mips_MTLO, Mips_MTLO, Mips_MTLO_MM },
  { Mips_MUL, Mips_MUL, Mips_MUL_MM },
  { Mips_MULT, Mips_MULT, Mips_MULT_MM },
  { Mips_MULTu, Mips_MULTu, Mips_MULTu_MM },
  { Mips_NMADD_D32, Mips_NMADD_D32, Mips_NMADD_D32_MM },
  { Mips_NMADD_S, Mips_NMADD_S, Mips_NMADD_S_MM },
  { Mips_NMSUB_D32, Mips_NMSUB_D32, Mips_NMSUB_D32_MM },
  { Mips_NMSUB_S, Mips_NMSUB_S, Mips_NMSUB_S_MM },
  { Mips_NOR, Mips_NOR, Mips_NOR_MM },
  { Mips_OR, Mips_OR, Mips_OR_MM },
  { Mips_ORi, Mips_ORi, Mips_ORi_MM },
  { Mips_PAUSE, Mips_PAUSE, Mips_PAUSE_MM },
  { Mips_PREF, Mips_PREF, Mips_PREF_MM },
  { Mips_PREFE, Mips_PREFE, Mips_PREFE_MM },
  { Mips_RDHWR, Mips_RDHWR, Mips_RDHWR_MM },
  { Mips_RECIP_D32, Mips_RECIP_D32, Mips_RECIP_D32_MM },
  { Mips_RECIP_D64, Mips_RECIP_D64, Mips_RECIP_D64_MM },
  { Mips_RECIP_S, Mips_RECIP_S, Mips_RECIP_S_MM },
  { Mips_ROTR, Mips_ROTR, Mips_ROTR_MM },
  { Mips_ROTRV, Mips_ROTRV, Mips_ROTRV_MM },
  { Mips_ROUND_W_D32, Mips_ROUND_W_D32, Mips_ROUND_W_MM },
  { Mips_ROUND_W_S, Mips_ROUND_W_S, Mips_ROUND_W_S_MM },
  { Mips_RSQRT_D32, Mips_RSQRT_D32, Mips_RSQRT_D32_MM },
  { Mips_RSQRT_D64, Mips_RSQRT_D64, Mips_RSQRT_D64_MM },
  { Mips_RSQRT_S, Mips_RSQRT_S, Mips_RSQRT_S_MM },
  { Mips_SB, Mips_SB, Mips_SB_MM },
  { Mips_SBE, Mips_SBE, Mips_SBE_MM },
  { Mips_SCE, Mips_SCE, Mips_SCE_MM },
  { Mips_SDBBP, Mips_SDBBP, Mips_SDBBP_MM },
  { Mips_SDC1, Mips_SDC1, (uint16_t)-1U },
  { Mips_SDIV, Mips_SDIV, Mips_SDIV_MM },
  { Mips_SEB, Mips_SEB, Mips_SEB_MM },
  { Mips_SEH, Mips_SEH, Mips_SEH_MM },
  { Mips_SH, Mips_SH, Mips_SH_MM },
  { Mips_SHE, Mips_SHE, Mips_SHE_MM },
  { Mips_SLL, Mips_SLL, Mips_SLL_MM },
  { Mips_SLLV, Mips_SLLV, Mips_SLLV_MM },
  { Mips_SLT, Mips_SLT, Mips_SLT_MM },
  { Mips_SLTi, Mips_SLTi, Mips_SLTi_MM },
  { Mips_SLTiu, Mips_SLTiu, Mips_SLTiu_MM },
  { Mips_SLTu, Mips_SLTu, Mips_SLTu_MM },
  { Mips_SRA, Mips_SRA, Mips_SRA_MM },
  { Mips_SRAV, Mips_SRAV, Mips_SRAV_MM },
  { Mips_SRL, Mips_SRL, Mips_SRL_MM },
  { Mips_SRLV, Mips_SRLV, Mips_SRLV_MM },
  { Mips_SSNOP, Mips_SSNOP, Mips_SSNOP_MM },
  { Mips_SUB, Mips_SUB, Mips_SUB_MM },
  { Mips_SUBu, Mips_SUBu, Mips_SUBu_MM },
  { Mips_SUXC1, Mips_SUXC1, Mips_SUXC1_MM },
  { Mips_SW, Mips_SW, Mips_SW_MM },
  { Mips_SWC1, Mips_SWC1, Mips_SWC1_MM },
  { Mips_SWE, Mips_SWE, Mips_SWE_MM },
  { Mips_SWL, Mips_SWL, Mips_SWL_MM },
  { Mips_SWLE, Mips_SWLE, Mips_SWLE_MM },
  { Mips_SWR, Mips_SWR, Mips_SWR_MM },
  { Mips_SWRE, Mips_SWRE, Mips_SWRE_MM },
  { Mips_SWXC1, Mips_SWXC1, Mips_SWXC1_MM },
  { Mips_SYNC, Mips_SYNC, Mips_SYNC_MM },
  { Mips_SYNCI, Mips_SYNCI, Mips_SYNCI_MM },
  { Mips_SYSCALL, Mips_SYSCALL, Mips_SYSCALL_MM },
  { Mips_TEQ, Mips_TEQ, Mips_TEQ_MM },
  { Mips_TEQI, Mips_TEQI, Mips_TEQI_MM },
  { Mips_TGE, Mips_TGE, Mips_TGE_MM },
  { Mips_TGEI, Mips_TGEI, Mips_TGEI_MM },
  { Mips_TGEIU, Mips_TGEIU, Mips_TGEIU_MM },
  { Mips_TGEU, Mips_TGEU, Mips_TGEU_MM },
  { Mips_TLBGINV, Mips_TLBGINV, Mips_TLBGINV_MM },
  { Mips_TLBGINVF, Mips_TLBGINVF, Mips_TLBGINVF_MM },
  { Mips_TLBGP, Mips_TLBGP, Mips_TLBGP_MM },
  { Mips_TLBGR, Mips_TLBGR, Mips_TLBGR_MM },
  { Mips_TLBGWI, Mips_TLBGWI, Mips_TLBGWI_MM },
  { Mips_TLBGWR, Mips_TLBGWR, Mips_TLBGWR_MM },
  { Mips_TLBP, Mips_TLBP, Mips_TLBP_MM },
  { Mips_TLBR, Mips_TLBR, Mips_TLBR_MM },
  { Mips_TLBWI, Mips_TLBWI, Mips_TLBWI_MM },
  { Mips_TLBWR, Mips_TLBWR, Mips_TLBWR_MM },
  { Mips_TLT, Mips_TLT, Mips_TLT_MM },
  { Mips_TLTI, Mips_TLTI, Mips_TLTI_MM },
  { Mips_TLTU, Mips_TLTU, Mips_TLTU_MM },
  { Mips_TNE, Mips_TNE, Mips_TNE_MM },
  { Mips_TNEI, Mips_TNEI, Mips_TNEI_MM },
  { Mips_TRUNC_W_D32, Mips_TRUNC_W_D32, Mips_TRUNC_W_MM },
  { Mips_TRUNC_W_S, Mips_TRUNC_W_S, Mips_TRUNC_W_S_MM },
  { Mips_TTLTIU, Mips_TTLTIU, Mips_TLTIU_MM },
  { Mips_UDIV, Mips_UDIV, Mips_UDIV_MM },
  { Mips_WAIT, Mips_WAIT, Mips_WAIT_MM },
  { Mips_WSBH, Mips_WSBH, Mips_WSBH_MM },
  { Mips_XOR, Mips_XOR, Mips_XOR_MM },
  { Mips_XORi, Mips_XORi, Mips_XORi_MM },
}; // End of Std2MicroMipsTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 266;
  while (start < end) {
    mid = start + (end - start) / 2;
    if (Opcode == Std2MicroMipsTable[mid][0]) {
      break;
    }
    if (Opcode < Std2MicroMipsTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  if (inArch == Arch_se)
    return Std2MicroMipsTable[mid][1];
  if (inArch == Arch_micromips)
    return Std2MicroMipsTable[mid][2];
  return -1;}

// Std2MicroMipsR6
int Std2MicroMipsR6(uint16_t Opcode, enum Arch inArch) {
static const uint16_t Std2MicroMipsR6Table[][3] = {
  { Mips_ADD, Mips_ADD, Mips_ADD_MMR6 },
  { Mips_ADDiu, Mips_ADDiu, Mips_ADDIU_MMR6 },
  { Mips_ADDu, Mips_ADDu, Mips_ADDU_MMR6 },
  { Mips_AND, Mips_AND, Mips_AND_MMR6 },
  { Mips_ANDi, Mips_ANDi, Mips_ANDI_MMR6 },
  { Mips_BREAK, Mips_BREAK, Mips_BREAK_MMR6 },
  { Mips_CEIL_W_D64, Mips_CEIL_W_D64, Mips_CEIL_W_D_MMR6 },
  { Mips_CEIL_W_S, Mips_CEIL_W_S, Mips_CEIL_W_S_MMR6 },
  { Mips_CVT_W_D64, Mips_CVT_W_D64, (uint16_t)-1U },
  { Mips_DI, Mips_DI, Mips_DI_MMR6 },
  { Mips_EI, Mips_EI, Mips_EI_MMR6 },
  { Mips_EXT, Mips_EXT, Mips_EXT_MMR6 },
  { Mips_FABS_D64, Mips_FABS_D64, (uint16_t)-1U },
  { Mips_FLOOR_W_D64, Mips_FLOOR_W_D64, Mips_FLOOR_W_D_MMR6 },
  { Mips_FLOOR_W_S, Mips_FLOOR_W_S, Mips_FLOOR_W_S_MMR6 },
  { Mips_FMOV_D64, Mips_FMOV_D64, Mips_FMOV_D_MMR6 },
  { Mips_FNEG_D64, Mips_FNEG_D64, (uint16_t)-1U },
  { Mips_FSQRT_D64, Mips_FSQRT_D64, (uint16_t)-1U },
  { Mips_FSQRT_S, Mips_FSQRT_S, (uint16_t)-1U },
  { Mips_INS, Mips_INS, Mips_INS_MMR6 },
  { Mips_LDC1, Mips_LDC1, (uint16_t)-1U },
  { Mips_LDC164, Mips_LDC164, Mips_LDC1_D64_MMR6 },
  { Mips_LDC2, Mips_LDC2, Mips_LDC2_MMR6 },
  { Mips_LW, Mips_LW, Mips_LW_MMR6 },
  { Mips_LWC2, Mips_LWC2, Mips_LWC2_MMR6 },
  { Mips_MFC1, Mips_MFC1, Mips_MFC1_MMR6 },
  { Mips_MTC1, Mips_MTC1, Mips_MTC1_MMR6 },
  { Mips_MTHC1_D32, Mips_MTHC1_D32, (uint16_t)-1U },
  { Mips_NOR, Mips_NOR, Mips_NOR_MMR6 },
  { Mips_OR, Mips_OR, Mips_OR_MMR6 },
  { Mips_ORi, Mips_ORi, Mips_ORI_MMR6 },
  { Mips_PAUSE, Mips_PAUSE, Mips_PAUSE_MMR6 },
  { Mips_ROUND_W_D64, Mips_ROUND_W_D64, Mips_ROUND_W_D_MMR6 },
  { Mips_ROUND_W_S, Mips_ROUND_W_S, Mips_ROUND_W_S_MMR6 },
  { Mips_SB, Mips_SB, Mips_SB_MMR6 },
  { Mips_SDC164, Mips_SDC164, Mips_SDC1_D64_MMR6 },
  { Mips_SDC2, Mips_SDC2, Mips_SDC2_MMR6 },
  { Mips_SEB, Mips_SEB, (uint16_t)-1U },
  { Mips_SEH, Mips_SEH, (uint16_t)-1U },
  { Mips_SSNOP, Mips_SSNOP, Mips_SSNOP_MMR6 },
  { Mips_SUB, Mips_SUB, Mips_SUB_MMR6 },
  { Mips_SUBu, Mips_SUBu, Mips_SUBU_MMR6 },
  { Mips_SW, Mips_SW, Mips_SW_MMR6 },
  { Mips_SWC2, Mips_SWC2, Mips_SWC2_MMR6 },
  { Mips_SYNC, Mips_SYNC, Mips_SYNC_MMR6 },
  { Mips_SYNCI, Mips_SYNCI, Mips_SYNCI_MMR6 },
  { Mips_TRUNC_W_D64, Mips_TRUNC_W_D64, Mips_TRUNC_W_D_MMR6 },
  { Mips_TRUNC_W_S, Mips_TRUNC_W_S, Mips_TRUNC_W_S_MMR6 },
  { Mips_WAIT, Mips_WAIT, Mips_WAIT_MMR6 },
  { Mips_XOR, Mips_XOR, Mips_XOR_MMR6 },
  { Mips_XORi, Mips_XORi, Mips_XORI_MMR6 },
}; // End of Std2MicroMipsR6Table

  unsigned mid;
  unsigned start = 0;
  unsigned end = 51;
  while (start < end) {
    mid = start + (end - start) / 2;
    if (Opcode == Std2MicroMipsR6Table[mid][0]) {
      break;
    }
    if (Opcode < Std2MicroMipsR6Table[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  if (inArch == Arch_se)
    return Std2MicroMipsR6Table[mid][1];
  if (inArch == Arch_micromipsr6)
    return Std2MicroMipsR6Table[mid][2];
  return -1;}

#endif // GET_INSTRMAP_INFO


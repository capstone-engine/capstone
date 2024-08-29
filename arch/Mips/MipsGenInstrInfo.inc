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
    Mips_ADJCALLSTACKDOWN_NM	= 273,
    Mips_ADJCALLSTACKUP	= 274,
    Mips_ADJCALLSTACKUP_NM	= 275,
    Mips_ALIGN_NM	= 276,
    Mips_AND_V_D_PSEUDO	= 277,
    Mips_AND_V_H_PSEUDO	= 278,
    Mips_AND_V_W_PSEUDO	= 279,
    Mips_ATOMIC_CMP_SWAP_I16	= 280,
    Mips_ATOMIC_CMP_SWAP_I16_POSTRA	= 281,
    Mips_ATOMIC_CMP_SWAP_I32	= 282,
    Mips_ATOMIC_CMP_SWAP_I32_POSTRA	= 283,
    Mips_ATOMIC_CMP_SWAP_I64	= 284,
    Mips_ATOMIC_CMP_SWAP_I64_POSTRA	= 285,
    Mips_ATOMIC_CMP_SWAP_I8	= 286,
    Mips_ATOMIC_CMP_SWAP_I8_POSTRA	= 287,
    Mips_ATOMIC_LOAD_ADD_I16	= 288,
    Mips_ATOMIC_LOAD_ADD_I16_POSTRA	= 289,
    Mips_ATOMIC_LOAD_ADD_I32	= 290,
    Mips_ATOMIC_LOAD_ADD_I32_POSTRA	= 291,
    Mips_ATOMIC_LOAD_ADD_I64	= 292,
    Mips_ATOMIC_LOAD_ADD_I64_POSTRA	= 293,
    Mips_ATOMIC_LOAD_ADD_I8	= 294,
    Mips_ATOMIC_LOAD_ADD_I8_POSTRA	= 295,
    Mips_ATOMIC_LOAD_AND_I16	= 296,
    Mips_ATOMIC_LOAD_AND_I16_POSTRA	= 297,
    Mips_ATOMIC_LOAD_AND_I32	= 298,
    Mips_ATOMIC_LOAD_AND_I32_POSTRA	= 299,
    Mips_ATOMIC_LOAD_AND_I64	= 300,
    Mips_ATOMIC_LOAD_AND_I64_POSTRA	= 301,
    Mips_ATOMIC_LOAD_AND_I8	= 302,
    Mips_ATOMIC_LOAD_AND_I8_POSTRA	= 303,
    Mips_ATOMIC_LOAD_MAX_I16	= 304,
    Mips_ATOMIC_LOAD_MAX_I16_POSTRA	= 305,
    Mips_ATOMIC_LOAD_MAX_I32	= 306,
    Mips_ATOMIC_LOAD_MAX_I32_POSTRA	= 307,
    Mips_ATOMIC_LOAD_MAX_I64	= 308,
    Mips_ATOMIC_LOAD_MAX_I64_POSTRA	= 309,
    Mips_ATOMIC_LOAD_MAX_I8	= 310,
    Mips_ATOMIC_LOAD_MAX_I8_POSTRA	= 311,
    Mips_ATOMIC_LOAD_MIN_I16	= 312,
    Mips_ATOMIC_LOAD_MIN_I16_POSTRA	= 313,
    Mips_ATOMIC_LOAD_MIN_I32	= 314,
    Mips_ATOMIC_LOAD_MIN_I32_POSTRA	= 315,
    Mips_ATOMIC_LOAD_MIN_I64	= 316,
    Mips_ATOMIC_LOAD_MIN_I64_POSTRA	= 317,
    Mips_ATOMIC_LOAD_MIN_I8	= 318,
    Mips_ATOMIC_LOAD_MIN_I8_POSTRA	= 319,
    Mips_ATOMIC_LOAD_NAND_I16	= 320,
    Mips_ATOMIC_LOAD_NAND_I16_POSTRA	= 321,
    Mips_ATOMIC_LOAD_NAND_I32	= 322,
    Mips_ATOMIC_LOAD_NAND_I32_POSTRA	= 323,
    Mips_ATOMIC_LOAD_NAND_I64	= 324,
    Mips_ATOMIC_LOAD_NAND_I64_POSTRA	= 325,
    Mips_ATOMIC_LOAD_NAND_I8	= 326,
    Mips_ATOMIC_LOAD_NAND_I8_POSTRA	= 327,
    Mips_ATOMIC_LOAD_OR_I16	= 328,
    Mips_ATOMIC_LOAD_OR_I16_POSTRA	= 329,
    Mips_ATOMIC_LOAD_OR_I32	= 330,
    Mips_ATOMIC_LOAD_OR_I32_POSTRA	= 331,
    Mips_ATOMIC_LOAD_OR_I64	= 332,
    Mips_ATOMIC_LOAD_OR_I64_POSTRA	= 333,
    Mips_ATOMIC_LOAD_OR_I8	= 334,
    Mips_ATOMIC_LOAD_OR_I8_POSTRA	= 335,
    Mips_ATOMIC_LOAD_SUB_I16	= 336,
    Mips_ATOMIC_LOAD_SUB_I16_POSTRA	= 337,
    Mips_ATOMIC_LOAD_SUB_I32	= 338,
    Mips_ATOMIC_LOAD_SUB_I32_POSTRA	= 339,
    Mips_ATOMIC_LOAD_SUB_I64	= 340,
    Mips_ATOMIC_LOAD_SUB_I64_POSTRA	= 341,
    Mips_ATOMIC_LOAD_SUB_I8	= 342,
    Mips_ATOMIC_LOAD_SUB_I8_POSTRA	= 343,
    Mips_ATOMIC_LOAD_UMAX_I16	= 344,
    Mips_ATOMIC_LOAD_UMAX_I16_POSTRA	= 345,
    Mips_ATOMIC_LOAD_UMAX_I32	= 346,
    Mips_ATOMIC_LOAD_UMAX_I32_POSTRA	= 347,
    Mips_ATOMIC_LOAD_UMAX_I64	= 348,
    Mips_ATOMIC_LOAD_UMAX_I64_POSTRA	= 349,
    Mips_ATOMIC_LOAD_UMAX_I8	= 350,
    Mips_ATOMIC_LOAD_UMAX_I8_POSTRA	= 351,
    Mips_ATOMIC_LOAD_UMIN_I16	= 352,
    Mips_ATOMIC_LOAD_UMIN_I16_POSTRA	= 353,
    Mips_ATOMIC_LOAD_UMIN_I32	= 354,
    Mips_ATOMIC_LOAD_UMIN_I32_POSTRA	= 355,
    Mips_ATOMIC_LOAD_UMIN_I64	= 356,
    Mips_ATOMIC_LOAD_UMIN_I64_POSTRA	= 357,
    Mips_ATOMIC_LOAD_UMIN_I8	= 358,
    Mips_ATOMIC_LOAD_UMIN_I8_POSTRA	= 359,
    Mips_ATOMIC_LOAD_XOR_I16	= 360,
    Mips_ATOMIC_LOAD_XOR_I16_POSTRA	= 361,
    Mips_ATOMIC_LOAD_XOR_I32	= 362,
    Mips_ATOMIC_LOAD_XOR_I32_POSTRA	= 363,
    Mips_ATOMIC_LOAD_XOR_I64	= 364,
    Mips_ATOMIC_LOAD_XOR_I64_POSTRA	= 365,
    Mips_ATOMIC_LOAD_XOR_I8	= 366,
    Mips_ATOMIC_LOAD_XOR_I8_POSTRA	= 367,
    Mips_ATOMIC_SWAP_I16	= 368,
    Mips_ATOMIC_SWAP_I16_POSTRA	= 369,
    Mips_ATOMIC_SWAP_I32	= 370,
    Mips_ATOMIC_SWAP_I32_POSTRA	= 371,
    Mips_ATOMIC_SWAP_I64	= 372,
    Mips_ATOMIC_SWAP_I64_POSTRA	= 373,
    Mips_ATOMIC_SWAP_I8	= 374,
    Mips_ATOMIC_SWAP_I8_POSTRA	= 375,
    Mips_B	= 376,
    Mips_BAL_BR	= 377,
    Mips_BAL_BR_MM	= 378,
    Mips_BEQLImmMacro	= 379,
    Mips_BGE	= 380,
    Mips_BGEImmMacro	= 381,
    Mips_BGEL	= 382,
    Mips_BGELImmMacro	= 383,
    Mips_BGEU	= 384,
    Mips_BGEUImmMacro	= 385,
    Mips_BGEUL	= 386,
    Mips_BGEULImmMacro	= 387,
    Mips_BGT	= 388,
    Mips_BGTImmMacro	= 389,
    Mips_BGTL	= 390,
    Mips_BGTLImmMacro	= 391,
    Mips_BGTU	= 392,
    Mips_BGTUImmMacro	= 393,
    Mips_BGTUL	= 394,
    Mips_BGTULImmMacro	= 395,
    Mips_BLE	= 396,
    Mips_BLEImmMacro	= 397,
    Mips_BLEL	= 398,
    Mips_BLELImmMacro	= 399,
    Mips_BLEU	= 400,
    Mips_BLEUImmMacro	= 401,
    Mips_BLEUL	= 402,
    Mips_BLEULImmMacro	= 403,
    Mips_BLT	= 404,
    Mips_BLTImmMacro	= 405,
    Mips_BLTL	= 406,
    Mips_BLTLImmMacro	= 407,
    Mips_BLTU	= 408,
    Mips_BLTUImmMacro	= 409,
    Mips_BLTUL	= 410,
    Mips_BLTULImmMacro	= 411,
    Mips_BNELImmMacro	= 412,
    Mips_BPOSGE32_PSEUDO	= 413,
    Mips_BSEL_D_PSEUDO	= 414,
    Mips_BSEL_FD_PSEUDO	= 415,
    Mips_BSEL_FW_PSEUDO	= 416,
    Mips_BSEL_H_PSEUDO	= 417,
    Mips_BSEL_W_PSEUDO	= 418,
    Mips_B_MM	= 419,
    Mips_B_MMR6_Pseudo	= 420,
    Mips_B_MM_Pseudo	= 421,
    Mips_BeqImm	= 422,
    Mips_BneImm	= 423,
    Mips_BteqzT8CmpX16	= 424,
    Mips_BteqzT8CmpiX16	= 425,
    Mips_BteqzT8SltX16	= 426,
    Mips_BteqzT8SltiX16	= 427,
    Mips_BteqzT8SltiuX16	= 428,
    Mips_BteqzT8SltuX16	= 429,
    Mips_BtnezT8CmpX16	= 430,
    Mips_BtnezT8CmpiX16	= 431,
    Mips_BtnezT8SltX16	= 432,
    Mips_BtnezT8SltiX16	= 433,
    Mips_BtnezT8SltiuX16	= 434,
    Mips_BtnezT8SltuX16	= 435,
    Mips_BuildPairF64	= 436,
    Mips_BuildPairF64_64	= 437,
    Mips_CFTC1	= 438,
    Mips_CONSTPOOL_ENTRY	= 439,
    Mips_COPY_FD_PSEUDO	= 440,
    Mips_COPY_FW_PSEUDO	= 441,
    Mips_CTTC1	= 442,
    Mips_Constant32	= 443,
    Mips_DMULImmMacro	= 444,
    Mips_DMULMacro	= 445,
    Mips_DMULOMacro	= 446,
    Mips_DMULOUMacro	= 447,
    Mips_DROL	= 448,
    Mips_DROLImm	= 449,
    Mips_DROR	= 450,
    Mips_DRORImm	= 451,
    Mips_DSDivIMacro	= 452,
    Mips_DSDivMacro	= 453,
    Mips_DSRemIMacro	= 454,
    Mips_DSRemMacro	= 455,
    Mips_DUDivIMacro	= 456,
    Mips_DUDivMacro	= 457,
    Mips_DURemIMacro	= 458,
    Mips_DURemMacro	= 459,
    Mips_ERet	= 460,
    Mips_ExtractElementF64	= 461,
    Mips_ExtractElementF64_64	= 462,
    Mips_FABS_D	= 463,
    Mips_FABS_W	= 464,
    Mips_FEXP2_D_1_PSEUDO	= 465,
    Mips_FEXP2_W_1_PSEUDO	= 466,
    Mips_FILL_FD_PSEUDO	= 467,
    Mips_FILL_FW_PSEUDO	= 468,
    Mips_GotPrologue16	= 469,
    Mips_INSERT_B_VIDX64_PSEUDO	= 470,
    Mips_INSERT_B_VIDX_PSEUDO	= 471,
    Mips_INSERT_D_VIDX64_PSEUDO	= 472,
    Mips_INSERT_D_VIDX_PSEUDO	= 473,
    Mips_INSERT_FD_PSEUDO	= 474,
    Mips_INSERT_FD_VIDX64_PSEUDO	= 475,
    Mips_INSERT_FD_VIDX_PSEUDO	= 476,
    Mips_INSERT_FW_PSEUDO	= 477,
    Mips_INSERT_FW_VIDX64_PSEUDO	= 478,
    Mips_INSERT_FW_VIDX_PSEUDO	= 479,
    Mips_INSERT_H_VIDX64_PSEUDO	= 480,
    Mips_INSERT_H_VIDX_PSEUDO	= 481,
    Mips_INSERT_W_VIDX64_PSEUDO	= 482,
    Mips_INSERT_W_VIDX_PSEUDO	= 483,
    Mips_JALR64Pseudo	= 484,
    Mips_JALRCPseudo	= 485,
    Mips_JALRHB64Pseudo	= 486,
    Mips_JALRHBPseudo	= 487,
    Mips_JALRPseudo	= 488,
    Mips_JAL_MMR6	= 489,
    Mips_JalOneReg	= 490,
    Mips_JalTwoReg	= 491,
    Mips_LDMacro	= 492,
    Mips_LDR_D	= 493,
    Mips_LDR_W	= 494,
    Mips_LD_F16	= 495,
    Mips_LOAD_ACC128	= 496,
    Mips_LOAD_ACC64	= 497,
    Mips_LOAD_ACC64DSP	= 498,
    Mips_LOAD_CCOND_DSP	= 499,
    Mips_LONG_BRANCH_ADDiu	= 500,
    Mips_LONG_BRANCH_ADDiu2Op	= 501,
    Mips_LONG_BRANCH_DADDiu	= 502,
    Mips_LONG_BRANCH_DADDiu2Op	= 503,
    Mips_LONG_BRANCH_LUi	= 504,
    Mips_LONG_BRANCH_LUi2Op	= 505,
    Mips_LONG_BRANCH_LUi2Op_64	= 506,
    Mips_LWM_MM	= 507,
    Mips_LoadAddrImm32	= 508,
    Mips_LoadAddrImm64	= 509,
    Mips_LoadAddrReg32	= 510,
    Mips_LoadAddrReg64	= 511,
    Mips_LoadImm32	= 512,
    Mips_LoadImm64	= 513,
    Mips_LoadImmDoubleFGR	= 514,
    Mips_LoadImmDoubleFGR_32	= 515,
    Mips_LoadImmDoubleGPR	= 516,
    Mips_LoadImmSingleFGR	= 517,
    Mips_LoadImmSingleGPR	= 518,
    Mips_LoadJumpTableOffset	= 519,
    Mips_LwConstant32	= 520,
    Mips_MFTACX	= 521,
    Mips_MFTACX_NM	= 522,
    Mips_MFTC0	= 523,
    Mips_MFTC0_NM	= 524,
    Mips_MFTC1	= 525,
    Mips_MFTDSP	= 526,
    Mips_MFTDSP_NM	= 527,
    Mips_MFTGPR	= 528,
    Mips_MFTGPR_NM	= 529,
    Mips_MFTHC1	= 530,
    Mips_MFTHI	= 531,
    Mips_MFTHI_NM	= 532,
    Mips_MFTLO	= 533,
    Mips_MFTLO_NM	= 534,
    Mips_MIPSeh_return32	= 535,
    Mips_MIPSeh_return64	= 536,
    Mips_MSA_FP_EXTEND_D_PSEUDO	= 537,
    Mips_MSA_FP_EXTEND_W_PSEUDO	= 538,
    Mips_MSA_FP_ROUND_D_PSEUDO	= 539,
    Mips_MSA_FP_ROUND_W_PSEUDO	= 540,
    Mips_MTTACX	= 541,
    Mips_MTTACX_NM	= 542,
    Mips_MTTC0	= 543,
    Mips_MTTC0_NM	= 544,
    Mips_MTTC1	= 545,
    Mips_MTTDSP	= 546,
    Mips_MTTDSP_NM	= 547,
    Mips_MTTGPR	= 548,
    Mips_MTTGPR_NM	= 549,
    Mips_MTTHC1	= 550,
    Mips_MTTHI	= 551,
    Mips_MTTHI_NM	= 552,
    Mips_MTTLO	= 553,
    Mips_MTTLO_NM	= 554,
    Mips_MULImmMacro	= 555,
    Mips_MULOMacro	= 556,
    Mips_MULOUMacro	= 557,
    Mips_MUSTTAILCALLREG_NM	= 558,
    Mips_MUSTTAILCALL_NM	= 559,
    Mips_MultRxRy16	= 560,
    Mips_MultRxRyRz16	= 561,
    Mips_MultuRxRy16	= 562,
    Mips_MultuRxRyRz16	= 563,
    Mips_NOP	= 564,
    Mips_NORImm	= 565,
    Mips_NORImm64	= 566,
    Mips_NOR_V_D_PSEUDO	= 567,
    Mips_NOR_V_H_PSEUDO	= 568,
    Mips_NOR_V_W_PSEUDO	= 569,
    Mips_OR_V_D_PSEUDO	= 570,
    Mips_OR_V_H_PSEUDO	= 571,
    Mips_OR_V_W_PSEUDO	= 572,
    Mips_PseudoADDIU_NM	= 573,
    Mips_PseudoANDI_NM	= 574,
    Mips_PseudoCMPU_EQ_QB	= 575,
    Mips_PseudoCMPU_LE_QB	= 576,
    Mips_PseudoCMPU_LT_QB	= 577,
    Mips_PseudoCMP_EQ_PH	= 578,
    Mips_PseudoCMP_LE_PH	= 579,
    Mips_PseudoCMP_LT_PH	= 580,
    Mips_PseudoCVT_D32_W	= 581,
    Mips_PseudoCVT_D64_L	= 582,
    Mips_PseudoCVT_D64_W	= 583,
    Mips_PseudoCVT_S_L	= 584,
    Mips_PseudoCVT_S_W	= 585,
    Mips_PseudoDMULT	= 586,
    Mips_PseudoDMULTu	= 587,
    Mips_PseudoDSDIV	= 588,
    Mips_PseudoDUDIV	= 589,
    Mips_PseudoD_SELECT_I	= 590,
    Mips_PseudoD_SELECT_I64	= 591,
    Mips_PseudoIndirectBranch	= 592,
    Mips_PseudoIndirectBranch64	= 593,
    Mips_PseudoIndirectBranch64R6	= 594,
    Mips_PseudoIndirectBranchNM	= 595,
    Mips_PseudoIndirectBranchR6	= 596,
    Mips_PseudoIndirectBranch_MM	= 597,
    Mips_PseudoIndirectBranch_MMR6	= 598,
    Mips_PseudoIndirectHazardBranch	= 599,
    Mips_PseudoIndirectHazardBranch64	= 600,
    Mips_PseudoIndrectHazardBranch64R6	= 601,
    Mips_PseudoIndrectHazardBranchR6	= 602,
    Mips_PseudoLA_NM	= 603,
    Mips_PseudoLI_NM	= 604,
    Mips_PseudoMADD	= 605,
    Mips_PseudoMADDU	= 606,
    Mips_PseudoMADDU_MM	= 607,
    Mips_PseudoMADD_MM	= 608,
    Mips_PseudoMFHI	= 609,
    Mips_PseudoMFHI64	= 610,
    Mips_PseudoMFHI_MM	= 611,
    Mips_PseudoMFLO	= 612,
    Mips_PseudoMFLO64	= 613,
    Mips_PseudoMFLO_MM	= 614,
    Mips_PseudoMSUB	= 615,
    Mips_PseudoMSUBU	= 616,
    Mips_PseudoMSUBU_MM	= 617,
    Mips_PseudoMSUB_MM	= 618,
    Mips_PseudoMTLOHI	= 619,
    Mips_PseudoMTLOHI64	= 620,
    Mips_PseudoMTLOHI_DSP	= 621,
    Mips_PseudoMTLOHI_MM	= 622,
    Mips_PseudoMULT	= 623,
    Mips_PseudoMULT_MM	= 624,
    Mips_PseudoMULTu	= 625,
    Mips_PseudoMULTu_MM	= 626,
    Mips_PseudoPICK_PH	= 627,
    Mips_PseudoPICK_QB	= 628,
    Mips_PseudoReturn	= 629,
    Mips_PseudoReturn64	= 630,
    Mips_PseudoReturnNM	= 631,
    Mips_PseudoSDIV	= 632,
    Mips_PseudoSELECTFP_F_D32	= 633,
    Mips_PseudoSELECTFP_F_D64	= 634,
    Mips_PseudoSELECTFP_F_I	= 635,
    Mips_PseudoSELECTFP_F_I64	= 636,
    Mips_PseudoSELECTFP_F_S	= 637,
    Mips_PseudoSELECTFP_T_D32	= 638,
    Mips_PseudoSELECTFP_T_D64	= 639,
    Mips_PseudoSELECTFP_T_I	= 640,
    Mips_PseudoSELECTFP_T_I64	= 641,
    Mips_PseudoSELECTFP_T_S	= 642,
    Mips_PseudoSELECT_D32	= 643,
    Mips_PseudoSELECT_D64	= 644,
    Mips_PseudoSELECT_I	= 645,
    Mips_PseudoSELECT_I64	= 646,
    Mips_PseudoSELECT_S	= 647,
    Mips_PseudoSUBU_NM	= 648,
    Mips_PseudoTRUNC_W_D	= 649,
    Mips_PseudoTRUNC_W_D32	= 650,
    Mips_PseudoTRUNC_W_S	= 651,
    Mips_PseudoUDIV	= 652,
    Mips_ROL	= 653,
    Mips_ROLImm	= 654,
    Mips_ROR	= 655,
    Mips_RORImm	= 656,
    Mips_RetRA	= 657,
    Mips_RetRA16	= 658,
    Mips_SDC1_M1	= 659,
    Mips_SDIV_MM_Pseudo	= 660,
    Mips_SDMacro	= 661,
    Mips_SDivIMacro	= 662,
    Mips_SDivMacro	= 663,
    Mips_SEQIMacro	= 664,
    Mips_SEQMacro	= 665,
    Mips_SGE	= 666,
    Mips_SGEImm	= 667,
    Mips_SGEImm64	= 668,
    Mips_SGEU	= 669,
    Mips_SGEUImm	= 670,
    Mips_SGEUImm64	= 671,
    Mips_SGTImm	= 672,
    Mips_SGTImm64	= 673,
    Mips_SGTUImm	= 674,
    Mips_SGTUImm64	= 675,
    Mips_SLE	= 676,
    Mips_SLEImm	= 677,
    Mips_SLEImm64	= 678,
    Mips_SLEU	= 679,
    Mips_SLEUImm	= 680,
    Mips_SLEUImm64	= 681,
    Mips_SLTImm64	= 682,
    Mips_SLTUImm64	= 683,
    Mips_SNEIMacro	= 684,
    Mips_SNEMacro	= 685,
    Mips_SNZ_B_PSEUDO	= 686,
    Mips_SNZ_D_PSEUDO	= 687,
    Mips_SNZ_H_PSEUDO	= 688,
    Mips_SNZ_V_PSEUDO	= 689,
    Mips_SNZ_W_PSEUDO	= 690,
    Mips_SRemIMacro	= 691,
    Mips_SRemMacro	= 692,
    Mips_STORE_ACC128	= 693,
    Mips_STORE_ACC64	= 694,
    Mips_STORE_ACC64DSP	= 695,
    Mips_STORE_CCOND_DSP	= 696,
    Mips_STR_D	= 697,
    Mips_STR_W	= 698,
    Mips_ST_F16	= 699,
    Mips_SWM_MM	= 700,
    Mips_SZ_B_PSEUDO	= 701,
    Mips_SZ_D_PSEUDO	= 702,
    Mips_SZ_H_PSEUDO	= 703,
    Mips_SZ_V_PSEUDO	= 704,
    Mips_SZ_W_PSEUDO	= 705,
    Mips_SaaAddr	= 706,
    Mips_SaadAddr	= 707,
    Mips_SelBeqZ	= 708,
    Mips_SelBneZ	= 709,
    Mips_SelTBteqZCmp	= 710,
    Mips_SelTBteqZCmpi	= 711,
    Mips_SelTBteqZSlt	= 712,
    Mips_SelTBteqZSlti	= 713,
    Mips_SelTBteqZSltiu	= 714,
    Mips_SelTBteqZSltu	= 715,
    Mips_SelTBtneZCmp	= 716,
    Mips_SelTBtneZCmpi	= 717,
    Mips_SelTBtneZSlt	= 718,
    Mips_SelTBtneZSlti	= 719,
    Mips_SelTBtneZSltiu	= 720,
    Mips_SelTBtneZSltu	= 721,
    Mips_SltCCRxRy16	= 722,
    Mips_SltiCCRxImmX16	= 723,
    Mips_SltiuCCRxImmX16	= 724,
    Mips_SltuCCRxRy16	= 725,
    Mips_SltuRxRyRz16	= 726,
    Mips_TAILCALL	= 727,
    Mips_TAILCALL64R6REG	= 728,
    Mips_TAILCALLHB64R6REG	= 729,
    Mips_TAILCALLHBR6REG	= 730,
    Mips_TAILCALLR6REG	= 731,
    Mips_TAILCALLREG	= 732,
    Mips_TAILCALLREG64	= 733,
    Mips_TAILCALLREGHB	= 734,
    Mips_TAILCALLREGHB64	= 735,
    Mips_TAILCALLREG_MM	= 736,
    Mips_TAILCALLREG_MMR6	= 737,
    Mips_TAILCALLREG_NM	= 738,
    Mips_TAILCALL_MM	= 739,
    Mips_TAILCALL_MMR6	= 740,
    Mips_TAILCALL_NM	= 741,
    Mips_TRAP	= 742,
    Mips_TRAP_MM	= 743,
    Mips_UDIV_MM_Pseudo	= 744,
    Mips_UDivIMacro	= 745,
    Mips_UDivMacro	= 746,
    Mips_URemIMacro	= 747,
    Mips_URemMacro	= 748,
    Mips_Ulh	= 749,
    Mips_Ulhu	= 750,
    Mips_Ulw	= 751,
    Mips_Ush	= 752,
    Mips_Usw	= 753,
    Mips_XOR_V_D_PSEUDO	= 754,
    Mips_XOR_V_H_PSEUDO	= 755,
    Mips_XOR_V_W_PSEUDO	= 756,
    Mips_ABSQ_S_PH	= 757,
    Mips_ABSQ_S_PH_MM	= 758,
    Mips_ABSQ_S_QB	= 759,
    Mips_ABSQ_S_QB_MMR2	= 760,
    Mips_ABSQ_S_W	= 761,
    Mips_ABSQ_S_W_MM	= 762,
    Mips_ADD	= 763,
    Mips_ADDIU48_NM	= 764,
    Mips_ADDIUGP48_NM	= 765,
    Mips_ADDIUGPB_NM	= 766,
    Mips_ADDIUGPW_NM	= 767,
    Mips_ADDIUNEG_NM	= 768,
    Mips_ADDIUPC	= 769,
    Mips_ADDIUPC_MM	= 770,
    Mips_ADDIUPC_MMR6	= 771,
    Mips_ADDIUR1SP_MM	= 772,
    Mips_ADDIUR1SP_NM	= 773,
    Mips_ADDIUR2_MM	= 774,
    Mips_ADDIUR2_NM	= 775,
    Mips_ADDIURS5_NM	= 776,
    Mips_ADDIUS5_MM	= 777,
    Mips_ADDIUSP_MM	= 778,
    Mips_ADDIU_MMR6	= 779,
    Mips_ADDIU_NM	= 780,
    Mips_ADDQH_PH	= 781,
    Mips_ADDQH_PH_MMR2	= 782,
    Mips_ADDQH_R_PH	= 783,
    Mips_ADDQH_R_PH_MMR2	= 784,
    Mips_ADDQH_R_W	= 785,
    Mips_ADDQH_R_W_MMR2	= 786,
    Mips_ADDQH_W	= 787,
    Mips_ADDQH_W_MMR2	= 788,
    Mips_ADDQ_PH	= 789,
    Mips_ADDQ_PH_MM	= 790,
    Mips_ADDQ_S_PH	= 791,
    Mips_ADDQ_S_PH_MM	= 792,
    Mips_ADDQ_S_W	= 793,
    Mips_ADDQ_S_W_MM	= 794,
    Mips_ADDR_PS64	= 795,
    Mips_ADDSC	= 796,
    Mips_ADDSC_MM	= 797,
    Mips_ADDS_A_B	= 798,
    Mips_ADDS_A_D	= 799,
    Mips_ADDS_A_H	= 800,
    Mips_ADDS_A_W	= 801,
    Mips_ADDS_S_B	= 802,
    Mips_ADDS_S_D	= 803,
    Mips_ADDS_S_H	= 804,
    Mips_ADDS_S_W	= 805,
    Mips_ADDS_U_B	= 806,
    Mips_ADDS_U_D	= 807,
    Mips_ADDS_U_H	= 808,
    Mips_ADDS_U_W	= 809,
    Mips_ADDU16_MM	= 810,
    Mips_ADDU16_MMR6	= 811,
    Mips_ADDUH_QB	= 812,
    Mips_ADDUH_QB_MMR2	= 813,
    Mips_ADDUH_R_QB	= 814,
    Mips_ADDUH_R_QB_MMR2	= 815,
    Mips_ADDU_MMR6	= 816,
    Mips_ADDU_PH	= 817,
    Mips_ADDU_PH_MMR2	= 818,
    Mips_ADDU_QB	= 819,
    Mips_ADDU_QB_MM	= 820,
    Mips_ADDU_S_PH	= 821,
    Mips_ADDU_S_PH_MMR2	= 822,
    Mips_ADDU_S_QB	= 823,
    Mips_ADDU_S_QB_MM	= 824,
    Mips_ADDVI_B	= 825,
    Mips_ADDVI_D	= 826,
    Mips_ADDVI_H	= 827,
    Mips_ADDVI_W	= 828,
    Mips_ADDV_B	= 829,
    Mips_ADDV_D	= 830,
    Mips_ADDV_H	= 831,
    Mips_ADDV_W	= 832,
    Mips_ADDWC	= 833,
    Mips_ADDWC_MM	= 834,
    Mips_ADD_A_B	= 835,
    Mips_ADD_A_D	= 836,
    Mips_ADD_A_H	= 837,
    Mips_ADD_A_W	= 838,
    Mips_ADD_MM	= 839,
    Mips_ADD_MMR6	= 840,
    Mips_ADD_NM	= 841,
    Mips_ADDi	= 842,
    Mips_ADDi_MM	= 843,
    Mips_ADDiu	= 844,
    Mips_ADDiu_MM	= 845,
    Mips_ADDu	= 846,
    Mips_ADDu16_NM	= 847,
    Mips_ADDu4x4_NM	= 848,
    Mips_ADDu_MM	= 849,
    Mips_ADDu_NM	= 850,
    Mips_ALIGN	= 851,
    Mips_ALIGN_MMR6	= 852,
    Mips_ALUIPC	= 853,
    Mips_ALUIPC_MMR6	= 854,
    Mips_ALUIPC_NM	= 855,
    Mips_AND	= 856,
    Mips_AND16_MM	= 857,
    Mips_AND16_MMR6	= 858,
    Mips_AND16_NM	= 859,
    Mips_AND64	= 860,
    Mips_ANDI16_MM	= 861,
    Mips_ANDI16_MMR6	= 862,
    Mips_ANDI16_NM	= 863,
    Mips_ANDI_B	= 864,
    Mips_ANDI_MMR6	= 865,
    Mips_ANDI_NM	= 866,
    Mips_AND_MM	= 867,
    Mips_AND_MMR6	= 868,
    Mips_AND_NM	= 869,
    Mips_AND_V	= 870,
    Mips_ANDi	= 871,
    Mips_ANDi64	= 872,
    Mips_ANDi_MM	= 873,
    Mips_APPEND	= 874,
    Mips_APPEND_MMR2	= 875,
    Mips_ASUB_S_B	= 876,
    Mips_ASUB_S_D	= 877,
    Mips_ASUB_S_H	= 878,
    Mips_ASUB_S_W	= 879,
    Mips_ASUB_U_B	= 880,
    Mips_ASUB_U_D	= 881,
    Mips_ASUB_U_H	= 882,
    Mips_ASUB_U_W	= 883,
    Mips_AUI	= 884,
    Mips_AUIPC	= 885,
    Mips_AUIPC_MMR6	= 886,
    Mips_AUI_MMR6	= 887,
    Mips_AVER_S_B	= 888,
    Mips_AVER_S_D	= 889,
    Mips_AVER_S_H	= 890,
    Mips_AVER_S_W	= 891,
    Mips_AVER_U_B	= 892,
    Mips_AVER_U_D	= 893,
    Mips_AVER_U_H	= 894,
    Mips_AVER_U_W	= 895,
    Mips_AVE_S_B	= 896,
    Mips_AVE_S_D	= 897,
    Mips_AVE_S_H	= 898,
    Mips_AVE_S_W	= 899,
    Mips_AVE_U_B	= 900,
    Mips_AVE_U_D	= 901,
    Mips_AVE_U_H	= 902,
    Mips_AVE_U_W	= 903,
    Mips_AddiuRxImmX16	= 904,
    Mips_AddiuRxPcImmX16	= 905,
    Mips_AddiuRxRxImm16	= 906,
    Mips_AddiuRxRxImmX16	= 907,
    Mips_AddiuRxRyOffMemX16	= 908,
    Mips_AddiuSpImm16	= 909,
    Mips_AddiuSpImmX16	= 910,
    Mips_AdduRxRyRz16	= 911,
    Mips_AndRxRxRy16	= 912,
    Mips_B16_MM	= 913,
    Mips_BADDu	= 914,
    Mips_BAL	= 915,
    Mips_BALC	= 916,
    Mips_BALC16_NM	= 917,
    Mips_BALC_MMR6	= 918,
    Mips_BALC_NM	= 919,
    Mips_BALIGN	= 920,
    Mips_BALIGN_MMR2	= 921,
    Mips_BALRSC_NM	= 922,
    Mips_BBEQZC_NM	= 923,
    Mips_BBIT0	= 924,
    Mips_BBIT032	= 925,
    Mips_BBIT1	= 926,
    Mips_BBIT132	= 927,
    Mips_BBNEZC_NM	= 928,
    Mips_BC	= 929,
    Mips_BC16_MMR6	= 930,
    Mips_BC16_NM	= 931,
    Mips_BC1EQZ	= 932,
    Mips_BC1EQZC_MMR6	= 933,
    Mips_BC1F	= 934,
    Mips_BC1FL	= 935,
    Mips_BC1F_MM	= 936,
    Mips_BC1NEZ	= 937,
    Mips_BC1NEZC_MMR6	= 938,
    Mips_BC1T	= 939,
    Mips_BC1TL	= 940,
    Mips_BC1T_MM	= 941,
    Mips_BC2EQZ	= 942,
    Mips_BC2EQZC_MMR6	= 943,
    Mips_BC2NEZ	= 944,
    Mips_BC2NEZC_MMR6	= 945,
    Mips_BCLRI_B	= 946,
    Mips_BCLRI_D	= 947,
    Mips_BCLRI_H	= 948,
    Mips_BCLRI_W	= 949,
    Mips_BCLR_B	= 950,
    Mips_BCLR_D	= 951,
    Mips_BCLR_H	= 952,
    Mips_BCLR_W	= 953,
    Mips_BC_MMR6	= 954,
    Mips_BC_NM	= 955,
    Mips_BEQ	= 956,
    Mips_BEQ64	= 957,
    Mips_BEQC	= 958,
    Mips_BEQC16_NM	= 959,
    Mips_BEQC64	= 960,
    Mips_BEQC_MMR6	= 961,
    Mips_BEQC_NM	= 962,
    Mips_BEQCzero_NM	= 963,
    Mips_BEQIC_NM	= 964,
    Mips_BEQL	= 965,
    Mips_BEQZ16_MM	= 966,
    Mips_BEQZALC	= 967,
    Mips_BEQZALC_MMR6	= 968,
    Mips_BEQZC	= 969,
    Mips_BEQZC16_MMR6	= 970,
    Mips_BEQZC16_NM	= 971,
    Mips_BEQZC64	= 972,
    Mips_BEQZC_MM	= 973,
    Mips_BEQZC_MMR6	= 974,
    Mips_BEQZC_NM	= 975,
    Mips_BEQ_MM	= 976,
    Mips_BGEC	= 977,
    Mips_BGEC64	= 978,
    Mips_BGEC_MMR6	= 979,
    Mips_BGEC_NM	= 980,
    Mips_BGEIC_NM	= 981,
    Mips_BGEIUC_NM	= 982,
    Mips_BGEUC	= 983,
    Mips_BGEUC64	= 984,
    Mips_BGEUC_MMR6	= 985,
    Mips_BGEUC_NM	= 986,
    Mips_BGEZ	= 987,
    Mips_BGEZ64	= 988,
    Mips_BGEZAL	= 989,
    Mips_BGEZALC	= 990,
    Mips_BGEZALC_MMR6	= 991,
    Mips_BGEZALL	= 992,
    Mips_BGEZALS_MM	= 993,
    Mips_BGEZAL_MM	= 994,
    Mips_BGEZC	= 995,
    Mips_BGEZC64	= 996,
    Mips_BGEZC_MMR6	= 997,
    Mips_BGEZL	= 998,
    Mips_BGEZ_MM	= 999,
    Mips_BGTZ	= 1000,
    Mips_BGTZ64	= 1001,
    Mips_BGTZALC	= 1002,
    Mips_BGTZALC_MMR6	= 1003,
    Mips_BGTZC	= 1004,
    Mips_BGTZC64	= 1005,
    Mips_BGTZC_MMR6	= 1006,
    Mips_BGTZL	= 1007,
    Mips_BGTZ_MM	= 1008,
    Mips_BINSLI_B	= 1009,
    Mips_BINSLI_D	= 1010,
    Mips_BINSLI_H	= 1011,
    Mips_BINSLI_W	= 1012,
    Mips_BINSL_B	= 1013,
    Mips_BINSL_D	= 1014,
    Mips_BINSL_H	= 1015,
    Mips_BINSL_W	= 1016,
    Mips_BINSRI_B	= 1017,
    Mips_BINSRI_D	= 1018,
    Mips_BINSRI_H	= 1019,
    Mips_BINSRI_W	= 1020,
    Mips_BINSR_B	= 1021,
    Mips_BINSR_D	= 1022,
    Mips_BINSR_H	= 1023,
    Mips_BINSR_W	= 1024,
    Mips_BITREV	= 1025,
    Mips_BITREVW_NM	= 1026,
    Mips_BITREV_MM	= 1027,
    Mips_BITSWAP	= 1028,
    Mips_BITSWAP_MMR6	= 1029,
    Mips_BLEZ	= 1030,
    Mips_BLEZ64	= 1031,
    Mips_BLEZALC	= 1032,
    Mips_BLEZALC_MMR6	= 1033,
    Mips_BLEZC	= 1034,
    Mips_BLEZC64	= 1035,
    Mips_BLEZC_MMR6	= 1036,
    Mips_BLEZL	= 1037,
    Mips_BLEZ_MM	= 1038,
    Mips_BLTC	= 1039,
    Mips_BLTC64	= 1040,
    Mips_BLTC_MMR6	= 1041,
    Mips_BLTC_NM	= 1042,
    Mips_BLTIC_NM	= 1043,
    Mips_BLTIUC_NM	= 1044,
    Mips_BLTUC	= 1045,
    Mips_BLTUC64	= 1046,
    Mips_BLTUC_MMR6	= 1047,
    Mips_BLTUC_NM	= 1048,
    Mips_BLTZ	= 1049,
    Mips_BLTZ64	= 1050,
    Mips_BLTZAL	= 1051,
    Mips_BLTZALC	= 1052,
    Mips_BLTZALC_MMR6	= 1053,
    Mips_BLTZALL	= 1054,
    Mips_BLTZALS_MM	= 1055,
    Mips_BLTZAL_MM	= 1056,
    Mips_BLTZC	= 1057,
    Mips_BLTZC64	= 1058,
    Mips_BLTZC_MMR6	= 1059,
    Mips_BLTZL	= 1060,
    Mips_BLTZ_MM	= 1061,
    Mips_BMNZI_B	= 1062,
    Mips_BMNZ_V	= 1063,
    Mips_BMZI_B	= 1064,
    Mips_BMZ_V	= 1065,
    Mips_BNE	= 1066,
    Mips_BNE64	= 1067,
    Mips_BNEC	= 1068,
    Mips_BNEC16_NM	= 1069,
    Mips_BNEC64	= 1070,
    Mips_BNEC_MMR6	= 1071,
    Mips_BNEC_NM	= 1072,
    Mips_BNECzero_NM	= 1073,
    Mips_BNEGI_B	= 1074,
    Mips_BNEGI_D	= 1075,
    Mips_BNEGI_H	= 1076,
    Mips_BNEGI_W	= 1077,
    Mips_BNEG_B	= 1078,
    Mips_BNEG_D	= 1079,
    Mips_BNEG_H	= 1080,
    Mips_BNEG_W	= 1081,
    Mips_BNEIC_NM	= 1082,
    Mips_BNEL	= 1083,
    Mips_BNEZ16_MM	= 1084,
    Mips_BNEZALC	= 1085,
    Mips_BNEZALC_MMR6	= 1086,
    Mips_BNEZC	= 1087,
    Mips_BNEZC16_MMR6	= 1088,
    Mips_BNEZC16_NM	= 1089,
    Mips_BNEZC64	= 1090,
    Mips_BNEZC_MM	= 1091,
    Mips_BNEZC_MMR6	= 1092,
    Mips_BNEZC_NM	= 1093,
    Mips_BNE_MM	= 1094,
    Mips_BNVC	= 1095,
    Mips_BNVC_MMR6	= 1096,
    Mips_BNZ_B	= 1097,
    Mips_BNZ_D	= 1098,
    Mips_BNZ_H	= 1099,
    Mips_BNZ_V	= 1100,
    Mips_BNZ_W	= 1101,
    Mips_BOVC	= 1102,
    Mips_BOVC_MMR6	= 1103,
    Mips_BPOSGE32	= 1104,
    Mips_BPOSGE32C_MMR3	= 1105,
    Mips_BPOSGE32_MM	= 1106,
    Mips_BREAK	= 1107,
    Mips_BREAK16_MM	= 1108,
    Mips_BREAK16_MMR6	= 1109,
    Mips_BREAK16_NM	= 1110,
    Mips_BREAK_MM	= 1111,
    Mips_BREAK_MMR6	= 1112,
    Mips_BREAK_NM	= 1113,
    Mips_BRSC_NM	= 1114,
    Mips_BSELI_B	= 1115,
    Mips_BSEL_V	= 1116,
    Mips_BSETI_B	= 1117,
    Mips_BSETI_D	= 1118,
    Mips_BSETI_H	= 1119,
    Mips_BSETI_W	= 1120,
    Mips_BSET_B	= 1121,
    Mips_BSET_D	= 1122,
    Mips_BSET_H	= 1123,
    Mips_BSET_W	= 1124,
    Mips_BYTEREVW_NM	= 1125,
    Mips_BZ_B	= 1126,
    Mips_BZ_D	= 1127,
    Mips_BZ_H	= 1128,
    Mips_BZ_V	= 1129,
    Mips_BZ_W	= 1130,
    Mips_BeqzRxImm16	= 1131,
    Mips_BeqzRxImmX16	= 1132,
    Mips_Bimm16	= 1133,
    Mips_BimmX16	= 1134,
    Mips_BnezRxImm16	= 1135,
    Mips_BnezRxImmX16	= 1136,
    Mips_Break16	= 1137,
    Mips_Bteqz16	= 1138,
    Mips_BteqzX16	= 1139,
    Mips_Btnez16	= 1140,
    Mips_BtnezX16	= 1141,
    Mips_CACHE	= 1142,
    Mips_CACHEE	= 1143,
    Mips_CACHEE_MM	= 1144,
    Mips_CACHE_MM	= 1145,
    Mips_CACHE_MMR6	= 1146,
    Mips_CACHE_NM	= 1147,
    Mips_CACHE_R6	= 1148,
    Mips_CEIL_L_D64	= 1149,
    Mips_CEIL_L_D_MMR6	= 1150,
    Mips_CEIL_L_S	= 1151,
    Mips_CEIL_L_S_MMR6	= 1152,
    Mips_CEIL_W_D32	= 1153,
    Mips_CEIL_W_D64	= 1154,
    Mips_CEIL_W_D_MMR6	= 1155,
    Mips_CEIL_W_MM	= 1156,
    Mips_CEIL_W_S	= 1157,
    Mips_CEIL_W_S_MM	= 1158,
    Mips_CEIL_W_S_MMR6	= 1159,
    Mips_CEQI_B	= 1160,
    Mips_CEQI_D	= 1161,
    Mips_CEQI_H	= 1162,
    Mips_CEQI_W	= 1163,
    Mips_CEQ_B	= 1164,
    Mips_CEQ_D	= 1165,
    Mips_CEQ_H	= 1166,
    Mips_CEQ_W	= 1167,
    Mips_CFC1	= 1168,
    Mips_CFC1_MM	= 1169,
    Mips_CFC2_MM	= 1170,
    Mips_CFCMSA	= 1171,
    Mips_CINS	= 1172,
    Mips_CINS32	= 1173,
    Mips_CINS64_32	= 1174,
    Mips_CINS_i32	= 1175,
    Mips_CLASS_D	= 1176,
    Mips_CLASS_D_MMR6	= 1177,
    Mips_CLASS_S	= 1178,
    Mips_CLASS_S_MMR6	= 1179,
    Mips_CLEI_S_B	= 1180,
    Mips_CLEI_S_D	= 1181,
    Mips_CLEI_S_H	= 1182,
    Mips_CLEI_S_W	= 1183,
    Mips_CLEI_U_B	= 1184,
    Mips_CLEI_U_D	= 1185,
    Mips_CLEI_U_H	= 1186,
    Mips_CLEI_U_W	= 1187,
    Mips_CLE_S_B	= 1188,
    Mips_CLE_S_D	= 1189,
    Mips_CLE_S_H	= 1190,
    Mips_CLE_S_W	= 1191,
    Mips_CLE_U_B	= 1192,
    Mips_CLE_U_D	= 1193,
    Mips_CLE_U_H	= 1194,
    Mips_CLE_U_W	= 1195,
    Mips_CLO	= 1196,
    Mips_CLO_MM	= 1197,
    Mips_CLO_MMR6	= 1198,
    Mips_CLO_NM	= 1199,
    Mips_CLO_R6	= 1200,
    Mips_CLTI_S_B	= 1201,
    Mips_CLTI_S_D	= 1202,
    Mips_CLTI_S_H	= 1203,
    Mips_CLTI_S_W	= 1204,
    Mips_CLTI_U_B	= 1205,
    Mips_CLTI_U_D	= 1206,
    Mips_CLTI_U_H	= 1207,
    Mips_CLTI_U_W	= 1208,
    Mips_CLT_S_B	= 1209,
    Mips_CLT_S_D	= 1210,
    Mips_CLT_S_H	= 1211,
    Mips_CLT_S_W	= 1212,
    Mips_CLT_U_B	= 1213,
    Mips_CLT_U_D	= 1214,
    Mips_CLT_U_H	= 1215,
    Mips_CLT_U_W	= 1216,
    Mips_CLZ	= 1217,
    Mips_CLZ_MM	= 1218,
    Mips_CLZ_MMR6	= 1219,
    Mips_CLZ_NM	= 1220,
    Mips_CLZ_R6	= 1221,
    Mips_CMPGDU_EQ_QB	= 1222,
    Mips_CMPGDU_EQ_QB_MMR2	= 1223,
    Mips_CMPGDU_LE_QB	= 1224,
    Mips_CMPGDU_LE_QB_MMR2	= 1225,
    Mips_CMPGDU_LT_QB	= 1226,
    Mips_CMPGDU_LT_QB_MMR2	= 1227,
    Mips_CMPGU_EQ_QB	= 1228,
    Mips_CMPGU_EQ_QB_MM	= 1229,
    Mips_CMPGU_LE_QB	= 1230,
    Mips_CMPGU_LE_QB_MM	= 1231,
    Mips_CMPGU_LT_QB	= 1232,
    Mips_CMPGU_LT_QB_MM	= 1233,
    Mips_CMPU_EQ_QB	= 1234,
    Mips_CMPU_EQ_QB_MM	= 1235,
    Mips_CMPU_LE_QB	= 1236,
    Mips_CMPU_LE_QB_MM	= 1237,
    Mips_CMPU_LT_QB	= 1238,
    Mips_CMPU_LT_QB_MM	= 1239,
    Mips_CMP_AF_D_MMR6	= 1240,
    Mips_CMP_AF_S_MMR6	= 1241,
    Mips_CMP_EQ_D	= 1242,
    Mips_CMP_EQ_D_MMR6	= 1243,
    Mips_CMP_EQ_PH	= 1244,
    Mips_CMP_EQ_PH_MM	= 1245,
    Mips_CMP_EQ_S	= 1246,
    Mips_CMP_EQ_S_MMR6	= 1247,
    Mips_CMP_F_D	= 1248,
    Mips_CMP_F_S	= 1249,
    Mips_CMP_LE_D	= 1250,
    Mips_CMP_LE_D_MMR6	= 1251,
    Mips_CMP_LE_PH	= 1252,
    Mips_CMP_LE_PH_MM	= 1253,
    Mips_CMP_LE_S	= 1254,
    Mips_CMP_LE_S_MMR6	= 1255,
    Mips_CMP_LT_D	= 1256,
    Mips_CMP_LT_D_MMR6	= 1257,
    Mips_CMP_LT_PH	= 1258,
    Mips_CMP_LT_PH_MM	= 1259,
    Mips_CMP_LT_S	= 1260,
    Mips_CMP_LT_S_MMR6	= 1261,
    Mips_CMP_SAF_D	= 1262,
    Mips_CMP_SAF_D_MMR6	= 1263,
    Mips_CMP_SAF_S	= 1264,
    Mips_CMP_SAF_S_MMR6	= 1265,
    Mips_CMP_SEQ_D	= 1266,
    Mips_CMP_SEQ_D_MMR6	= 1267,
    Mips_CMP_SEQ_S	= 1268,
    Mips_CMP_SEQ_S_MMR6	= 1269,
    Mips_CMP_SLE_D	= 1270,
    Mips_CMP_SLE_D_MMR6	= 1271,
    Mips_CMP_SLE_S	= 1272,
    Mips_CMP_SLE_S_MMR6	= 1273,
    Mips_CMP_SLT_D	= 1274,
    Mips_CMP_SLT_D_MMR6	= 1275,
    Mips_CMP_SLT_S	= 1276,
    Mips_CMP_SLT_S_MMR6	= 1277,
    Mips_CMP_SUEQ_D	= 1278,
    Mips_CMP_SUEQ_D_MMR6	= 1279,
    Mips_CMP_SUEQ_S	= 1280,
    Mips_CMP_SUEQ_S_MMR6	= 1281,
    Mips_CMP_SULE_D	= 1282,
    Mips_CMP_SULE_D_MMR6	= 1283,
    Mips_CMP_SULE_S	= 1284,
    Mips_CMP_SULE_S_MMR6	= 1285,
    Mips_CMP_SULT_D	= 1286,
    Mips_CMP_SULT_D_MMR6	= 1287,
    Mips_CMP_SULT_S	= 1288,
    Mips_CMP_SULT_S_MMR6	= 1289,
    Mips_CMP_SUN_D	= 1290,
    Mips_CMP_SUN_D_MMR6	= 1291,
    Mips_CMP_SUN_S	= 1292,
    Mips_CMP_SUN_S_MMR6	= 1293,
    Mips_CMP_UEQ_D	= 1294,
    Mips_CMP_UEQ_D_MMR6	= 1295,
    Mips_CMP_UEQ_S	= 1296,
    Mips_CMP_UEQ_S_MMR6	= 1297,
    Mips_CMP_ULE_D	= 1298,
    Mips_CMP_ULE_D_MMR6	= 1299,
    Mips_CMP_ULE_S	= 1300,
    Mips_CMP_ULE_S_MMR6	= 1301,
    Mips_CMP_ULT_D	= 1302,
    Mips_CMP_ULT_D_MMR6	= 1303,
    Mips_CMP_ULT_S	= 1304,
    Mips_CMP_ULT_S_MMR6	= 1305,
    Mips_CMP_UN_D	= 1306,
    Mips_CMP_UN_D_MMR6	= 1307,
    Mips_CMP_UN_S	= 1308,
    Mips_CMP_UN_S_MMR6	= 1309,
    Mips_COPY_S_B	= 1310,
    Mips_COPY_S_D	= 1311,
    Mips_COPY_S_H	= 1312,
    Mips_COPY_S_W	= 1313,
    Mips_COPY_U_B	= 1314,
    Mips_COPY_U_H	= 1315,
    Mips_COPY_U_W	= 1316,
    Mips_CRC32B	= 1317,
    Mips_CRC32B_NM	= 1318,
    Mips_CRC32CB	= 1319,
    Mips_CRC32CB_NM	= 1320,
    Mips_CRC32CD	= 1321,
    Mips_CRC32CH	= 1322,
    Mips_CRC32CH_NM	= 1323,
    Mips_CRC32CW	= 1324,
    Mips_CRC32CW_NM	= 1325,
    Mips_CRC32D	= 1326,
    Mips_CRC32H	= 1327,
    Mips_CRC32H_NM	= 1328,
    Mips_CRC32W	= 1329,
    Mips_CRC32W_NM	= 1330,
    Mips_CTC1	= 1331,
    Mips_CTC1_MM	= 1332,
    Mips_CTC2_MM	= 1333,
    Mips_CTCMSA	= 1334,
    Mips_CVT_D32_S	= 1335,
    Mips_CVT_D32_S_MM	= 1336,
    Mips_CVT_D32_W	= 1337,
    Mips_CVT_D32_W_MM	= 1338,
    Mips_CVT_D64_L	= 1339,
    Mips_CVT_D64_S	= 1340,
    Mips_CVT_D64_S_MM	= 1341,
    Mips_CVT_D64_W	= 1342,
    Mips_CVT_D64_W_MM	= 1343,
    Mips_CVT_D_L_MMR6	= 1344,
    Mips_CVT_L_D64	= 1345,
    Mips_CVT_L_D64_MM	= 1346,
    Mips_CVT_L_D_MMR6	= 1347,
    Mips_CVT_L_S	= 1348,
    Mips_CVT_L_S_MM	= 1349,
    Mips_CVT_L_S_MMR6	= 1350,
    Mips_CVT_PS_PW64	= 1351,
    Mips_CVT_PS_S64	= 1352,
    Mips_CVT_PW_PS64	= 1353,
    Mips_CVT_S_D32	= 1354,
    Mips_CVT_S_D32_MM	= 1355,
    Mips_CVT_S_D64	= 1356,
    Mips_CVT_S_D64_MM	= 1357,
    Mips_CVT_S_L	= 1358,
    Mips_CVT_S_L_MMR6	= 1359,
    Mips_CVT_S_PL64	= 1360,
    Mips_CVT_S_PU64	= 1361,
    Mips_CVT_S_W	= 1362,
    Mips_CVT_S_W_MM	= 1363,
    Mips_CVT_S_W_MMR6	= 1364,
    Mips_CVT_W_D32	= 1365,
    Mips_CVT_W_D32_MM	= 1366,
    Mips_CVT_W_D64	= 1367,
    Mips_CVT_W_D64_MM	= 1368,
    Mips_CVT_W_S	= 1369,
    Mips_CVT_W_S_MM	= 1370,
    Mips_CVT_W_S_MMR6	= 1371,
    Mips_C_EQ_D32	= 1372,
    Mips_C_EQ_D32_MM	= 1373,
    Mips_C_EQ_D64	= 1374,
    Mips_C_EQ_D64_MM	= 1375,
    Mips_C_EQ_S	= 1376,
    Mips_C_EQ_S_MM	= 1377,
    Mips_C_F_D32	= 1378,
    Mips_C_F_D32_MM	= 1379,
    Mips_C_F_D64	= 1380,
    Mips_C_F_D64_MM	= 1381,
    Mips_C_F_S	= 1382,
    Mips_C_F_S_MM	= 1383,
    Mips_C_LE_D32	= 1384,
    Mips_C_LE_D32_MM	= 1385,
    Mips_C_LE_D64	= 1386,
    Mips_C_LE_D64_MM	= 1387,
    Mips_C_LE_S	= 1388,
    Mips_C_LE_S_MM	= 1389,
    Mips_C_LT_D32	= 1390,
    Mips_C_LT_D32_MM	= 1391,
    Mips_C_LT_D64	= 1392,
    Mips_C_LT_D64_MM	= 1393,
    Mips_C_LT_S	= 1394,
    Mips_C_LT_S_MM	= 1395,
    Mips_C_NGE_D32	= 1396,
    Mips_C_NGE_D32_MM	= 1397,
    Mips_C_NGE_D64	= 1398,
    Mips_C_NGE_D64_MM	= 1399,
    Mips_C_NGE_S	= 1400,
    Mips_C_NGE_S_MM	= 1401,
    Mips_C_NGLE_D32	= 1402,
    Mips_C_NGLE_D32_MM	= 1403,
    Mips_C_NGLE_D64	= 1404,
    Mips_C_NGLE_D64_MM	= 1405,
    Mips_C_NGLE_S	= 1406,
    Mips_C_NGLE_S_MM	= 1407,
    Mips_C_NGL_D32	= 1408,
    Mips_C_NGL_D32_MM	= 1409,
    Mips_C_NGL_D64	= 1410,
    Mips_C_NGL_D64_MM	= 1411,
    Mips_C_NGL_S	= 1412,
    Mips_C_NGL_S_MM	= 1413,
    Mips_C_NGT_D32	= 1414,
    Mips_C_NGT_D32_MM	= 1415,
    Mips_C_NGT_D64	= 1416,
    Mips_C_NGT_D64_MM	= 1417,
    Mips_C_NGT_S	= 1418,
    Mips_C_NGT_S_MM	= 1419,
    Mips_C_OLE_D32	= 1420,
    Mips_C_OLE_D32_MM	= 1421,
    Mips_C_OLE_D64	= 1422,
    Mips_C_OLE_D64_MM	= 1423,
    Mips_C_OLE_S	= 1424,
    Mips_C_OLE_S_MM	= 1425,
    Mips_C_OLT_D32	= 1426,
    Mips_C_OLT_D32_MM	= 1427,
    Mips_C_OLT_D64	= 1428,
    Mips_C_OLT_D64_MM	= 1429,
    Mips_C_OLT_S	= 1430,
    Mips_C_OLT_S_MM	= 1431,
    Mips_C_SEQ_D32	= 1432,
    Mips_C_SEQ_D32_MM	= 1433,
    Mips_C_SEQ_D64	= 1434,
    Mips_C_SEQ_D64_MM	= 1435,
    Mips_C_SEQ_S	= 1436,
    Mips_C_SEQ_S_MM	= 1437,
    Mips_C_SF_D32	= 1438,
    Mips_C_SF_D32_MM	= 1439,
    Mips_C_SF_D64	= 1440,
    Mips_C_SF_D64_MM	= 1441,
    Mips_C_SF_S	= 1442,
    Mips_C_SF_S_MM	= 1443,
    Mips_C_UEQ_D32	= 1444,
    Mips_C_UEQ_D32_MM	= 1445,
    Mips_C_UEQ_D64	= 1446,
    Mips_C_UEQ_D64_MM	= 1447,
    Mips_C_UEQ_S	= 1448,
    Mips_C_UEQ_S_MM	= 1449,
    Mips_C_ULE_D32	= 1450,
    Mips_C_ULE_D32_MM	= 1451,
    Mips_C_ULE_D64	= 1452,
    Mips_C_ULE_D64_MM	= 1453,
    Mips_C_ULE_S	= 1454,
    Mips_C_ULE_S_MM	= 1455,
    Mips_C_ULT_D32	= 1456,
    Mips_C_ULT_D32_MM	= 1457,
    Mips_C_ULT_D64	= 1458,
    Mips_C_ULT_D64_MM	= 1459,
    Mips_C_ULT_S	= 1460,
    Mips_C_ULT_S_MM	= 1461,
    Mips_C_UN_D32	= 1462,
    Mips_C_UN_D32_MM	= 1463,
    Mips_C_UN_D64	= 1464,
    Mips_C_UN_D64_MM	= 1465,
    Mips_C_UN_S	= 1466,
    Mips_C_UN_S_MM	= 1467,
    Mips_CmpRxRy16	= 1468,
    Mips_CmpiRxImm16	= 1469,
    Mips_CmpiRxImmX16	= 1470,
    Mips_DADD	= 1471,
    Mips_DADDi	= 1472,
    Mips_DADDiu	= 1473,
    Mips_DADDu	= 1474,
    Mips_DAHI	= 1475,
    Mips_DALIGN	= 1476,
    Mips_DATI	= 1477,
    Mips_DAUI	= 1478,
    Mips_DBITSWAP	= 1479,
    Mips_DCLO	= 1480,
    Mips_DCLO_R6	= 1481,
    Mips_DCLZ	= 1482,
    Mips_DCLZ_R6	= 1483,
    Mips_DDIV	= 1484,
    Mips_DDIVU	= 1485,
    Mips_DERET	= 1486,
    Mips_DERET_MM	= 1487,
    Mips_DERET_MMR6	= 1488,
    Mips_DERET_NM	= 1489,
    Mips_DEXT	= 1490,
    Mips_DEXT64_32	= 1491,
    Mips_DEXTM	= 1492,
    Mips_DEXTU	= 1493,
    Mips_DI	= 1494,
    Mips_DINS	= 1495,
    Mips_DINSM	= 1496,
    Mips_DINSU	= 1497,
    Mips_DIV	= 1498,
    Mips_DIVU	= 1499,
    Mips_DIVU_MMR6	= 1500,
    Mips_DIVU_NM	= 1501,
    Mips_DIV_MMR6	= 1502,
    Mips_DIV_NM	= 1503,
    Mips_DIV_S_B	= 1504,
    Mips_DIV_S_D	= 1505,
    Mips_DIV_S_H	= 1506,
    Mips_DIV_S_W	= 1507,
    Mips_DIV_U_B	= 1508,
    Mips_DIV_U_D	= 1509,
    Mips_DIV_U_H	= 1510,
    Mips_DIV_U_W	= 1511,
    Mips_DI_MM	= 1512,
    Mips_DI_MMR6	= 1513,
    Mips_DI_NM	= 1514,
    Mips_DLSA	= 1515,
    Mips_DLSA_R6	= 1516,
    Mips_DMFC0	= 1517,
    Mips_DMFC1	= 1518,
    Mips_DMFC2	= 1519,
    Mips_DMFC2_OCTEON	= 1520,
    Mips_DMFGC0	= 1521,
    Mips_DMOD	= 1522,
    Mips_DMODU	= 1523,
    Mips_DMT	= 1524,
    Mips_DMTC0	= 1525,
    Mips_DMTC1	= 1526,
    Mips_DMTC2	= 1527,
    Mips_DMTC2_OCTEON	= 1528,
    Mips_DMTGC0	= 1529,
    Mips_DMT_NM	= 1530,
    Mips_DMUH	= 1531,
    Mips_DMUHU	= 1532,
    Mips_DMUL	= 1533,
    Mips_DMULT	= 1534,
    Mips_DMULTu	= 1535,
    Mips_DMULU	= 1536,
    Mips_DMUL_R6	= 1537,
    Mips_DOTP_S_D	= 1538,
    Mips_DOTP_S_H	= 1539,
    Mips_DOTP_S_W	= 1540,
    Mips_DOTP_U_D	= 1541,
    Mips_DOTP_U_H	= 1542,
    Mips_DOTP_U_W	= 1543,
    Mips_DPADD_S_D	= 1544,
    Mips_DPADD_S_H	= 1545,
    Mips_DPADD_S_W	= 1546,
    Mips_DPADD_U_D	= 1547,
    Mips_DPADD_U_H	= 1548,
    Mips_DPADD_U_W	= 1549,
    Mips_DPAQX_SA_W_PH	= 1550,
    Mips_DPAQX_SA_W_PH_MMR2	= 1551,
    Mips_DPAQX_S_W_PH	= 1552,
    Mips_DPAQX_S_W_PH_MMR2	= 1553,
    Mips_DPAQ_SA_L_W	= 1554,
    Mips_DPAQ_SA_L_W_MM	= 1555,
    Mips_DPAQ_S_W_PH	= 1556,
    Mips_DPAQ_S_W_PH_MM	= 1557,
    Mips_DPAU_H_QBL	= 1558,
    Mips_DPAU_H_QBL_MM	= 1559,
    Mips_DPAU_H_QBR	= 1560,
    Mips_DPAU_H_QBR_MM	= 1561,
    Mips_DPAX_W_PH	= 1562,
    Mips_DPAX_W_PH_MMR2	= 1563,
    Mips_DPA_W_PH	= 1564,
    Mips_DPA_W_PH_MMR2	= 1565,
    Mips_DPOP	= 1566,
    Mips_DPSQX_SA_W_PH	= 1567,
    Mips_DPSQX_SA_W_PH_MMR2	= 1568,
    Mips_DPSQX_S_W_PH	= 1569,
    Mips_DPSQX_S_W_PH_MMR2	= 1570,
    Mips_DPSQ_SA_L_W	= 1571,
    Mips_DPSQ_SA_L_W_MM	= 1572,
    Mips_DPSQ_S_W_PH	= 1573,
    Mips_DPSQ_S_W_PH_MM	= 1574,
    Mips_DPSUB_S_D	= 1575,
    Mips_DPSUB_S_H	= 1576,
    Mips_DPSUB_S_W	= 1577,
    Mips_DPSUB_U_D	= 1578,
    Mips_DPSUB_U_H	= 1579,
    Mips_DPSUB_U_W	= 1580,
    Mips_DPSU_H_QBL	= 1581,
    Mips_DPSU_H_QBL_MM	= 1582,
    Mips_DPSU_H_QBR	= 1583,
    Mips_DPSU_H_QBR_MM	= 1584,
    Mips_DPSX_W_PH	= 1585,
    Mips_DPSX_W_PH_MMR2	= 1586,
    Mips_DPS_W_PH	= 1587,
    Mips_DPS_W_PH_MMR2	= 1588,
    Mips_DROTR	= 1589,
    Mips_DROTR32	= 1590,
    Mips_DROTRV	= 1591,
    Mips_DSBH	= 1592,
    Mips_DSDIV	= 1593,
    Mips_DSHD	= 1594,
    Mips_DSLL	= 1595,
    Mips_DSLL32	= 1596,
    Mips_DSLL64_32	= 1597,
    Mips_DSLLV	= 1598,
    Mips_DSRA	= 1599,
    Mips_DSRA32	= 1600,
    Mips_DSRAV	= 1601,
    Mips_DSRL	= 1602,
    Mips_DSRL32	= 1603,
    Mips_DSRLV	= 1604,
    Mips_DSUB	= 1605,
    Mips_DSUBu	= 1606,
    Mips_DUDIV	= 1607,
    Mips_DVP	= 1608,
    Mips_DVPE	= 1609,
    Mips_DVPE_NM	= 1610,
    Mips_DVP_MMR6	= 1611,
    Mips_DivRxRy16	= 1612,
    Mips_DivuRxRy16	= 1613,
    Mips_EHB	= 1614,
    Mips_EHB_MM	= 1615,
    Mips_EHB_MMR6	= 1616,
    Mips_EHB_NM	= 1617,
    Mips_EI	= 1618,
    Mips_EI_MM	= 1619,
    Mips_EI_MMR6	= 1620,
    Mips_EI_NM	= 1621,
    Mips_EMT	= 1622,
    Mips_EMT_NM	= 1623,
    Mips_ERET	= 1624,
    Mips_ERETNC	= 1625,
    Mips_ERETNC_MMR6	= 1626,
    Mips_ERETNC_NM	= 1627,
    Mips_ERET_MM	= 1628,
    Mips_ERET_MMR6	= 1629,
    Mips_ERET_NM	= 1630,
    Mips_EVP	= 1631,
    Mips_EVPE	= 1632,
    Mips_EVPE_NM	= 1633,
    Mips_EVP_MMR6	= 1634,
    Mips_EXT	= 1635,
    Mips_EXTP	= 1636,
    Mips_EXTPDP	= 1637,
    Mips_EXTPDPV	= 1638,
    Mips_EXTPDPV_MM	= 1639,
    Mips_EXTPDP_MM	= 1640,
    Mips_EXTPV	= 1641,
    Mips_EXTPV_MM	= 1642,
    Mips_EXTP_MM	= 1643,
    Mips_EXTRV_RS_W	= 1644,
    Mips_EXTRV_RS_W_MM	= 1645,
    Mips_EXTRV_R_W	= 1646,
    Mips_EXTRV_R_W_MM	= 1647,
    Mips_EXTRV_S_H	= 1648,
    Mips_EXTRV_S_H_MM	= 1649,
    Mips_EXTRV_W	= 1650,
    Mips_EXTRV_W_MM	= 1651,
    Mips_EXTR_RS_W	= 1652,
    Mips_EXTR_RS_W_MM	= 1653,
    Mips_EXTR_R_W	= 1654,
    Mips_EXTR_R_W_MM	= 1655,
    Mips_EXTR_S_H	= 1656,
    Mips_EXTR_S_H_MM	= 1657,
    Mips_EXTR_W	= 1658,
    Mips_EXTR_W_MM	= 1659,
    Mips_EXTS	= 1660,
    Mips_EXTS32	= 1661,
    Mips_EXTW_NM	= 1662,
    Mips_EXT_MM	= 1663,
    Mips_EXT_MMR6	= 1664,
    Mips_EXT_NM	= 1665,
    Mips_FABS_D32	= 1666,
    Mips_FABS_D32_MM	= 1667,
    Mips_FABS_D64	= 1668,
    Mips_FABS_D64_MM	= 1669,
    Mips_FABS_S	= 1670,
    Mips_FABS_S_MM	= 1671,
    Mips_FADD_D	= 1672,
    Mips_FADD_D32	= 1673,
    Mips_FADD_D32_MM	= 1674,
    Mips_FADD_D64	= 1675,
    Mips_FADD_D64_MM	= 1676,
    Mips_FADD_PS64	= 1677,
    Mips_FADD_S	= 1678,
    Mips_FADD_S_MM	= 1679,
    Mips_FADD_S_MMR6	= 1680,
    Mips_FADD_W	= 1681,
    Mips_FCAF_D	= 1682,
    Mips_FCAF_W	= 1683,
    Mips_FCEQ_D	= 1684,
    Mips_FCEQ_W	= 1685,
    Mips_FCLASS_D	= 1686,
    Mips_FCLASS_W	= 1687,
    Mips_FCLE_D	= 1688,
    Mips_FCLE_W	= 1689,
    Mips_FCLT_D	= 1690,
    Mips_FCLT_W	= 1691,
    Mips_FCMP_D32	= 1692,
    Mips_FCMP_D32_MM	= 1693,
    Mips_FCMP_D64	= 1694,
    Mips_FCMP_S32	= 1695,
    Mips_FCMP_S32_MM	= 1696,
    Mips_FCNE_D	= 1697,
    Mips_FCNE_W	= 1698,
    Mips_FCOR_D	= 1699,
    Mips_FCOR_W	= 1700,
    Mips_FCUEQ_D	= 1701,
    Mips_FCUEQ_W	= 1702,
    Mips_FCULE_D	= 1703,
    Mips_FCULE_W	= 1704,
    Mips_FCULT_D	= 1705,
    Mips_FCULT_W	= 1706,
    Mips_FCUNE_D	= 1707,
    Mips_FCUNE_W	= 1708,
    Mips_FCUN_D	= 1709,
    Mips_FCUN_W	= 1710,
    Mips_FDIV_D	= 1711,
    Mips_FDIV_D32	= 1712,
    Mips_FDIV_D32_MM	= 1713,
    Mips_FDIV_D64	= 1714,
    Mips_FDIV_D64_MM	= 1715,
    Mips_FDIV_S	= 1716,
    Mips_FDIV_S_MM	= 1717,
    Mips_FDIV_S_MMR6	= 1718,
    Mips_FDIV_W	= 1719,
    Mips_FEXDO_H	= 1720,
    Mips_FEXDO_W	= 1721,
    Mips_FEXP2_D	= 1722,
    Mips_FEXP2_W	= 1723,
    Mips_FEXUPL_D	= 1724,
    Mips_FEXUPL_W	= 1725,
    Mips_FEXUPR_D	= 1726,
    Mips_FEXUPR_W	= 1727,
    Mips_FFINT_S_D	= 1728,
    Mips_FFINT_S_W	= 1729,
    Mips_FFINT_U_D	= 1730,
    Mips_FFINT_U_W	= 1731,
    Mips_FFQL_D	= 1732,
    Mips_FFQL_W	= 1733,
    Mips_FFQR_D	= 1734,
    Mips_FFQR_W	= 1735,
    Mips_FILL_B	= 1736,
    Mips_FILL_D	= 1737,
    Mips_FILL_H	= 1738,
    Mips_FILL_W	= 1739,
    Mips_FLOG2_D	= 1740,
    Mips_FLOG2_W	= 1741,
    Mips_FLOOR_L_D64	= 1742,
    Mips_FLOOR_L_D_MMR6	= 1743,
    Mips_FLOOR_L_S	= 1744,
    Mips_FLOOR_L_S_MMR6	= 1745,
    Mips_FLOOR_W_D32	= 1746,
    Mips_FLOOR_W_D64	= 1747,
    Mips_FLOOR_W_D_MMR6	= 1748,
    Mips_FLOOR_W_MM	= 1749,
    Mips_FLOOR_W_S	= 1750,
    Mips_FLOOR_W_S_MM	= 1751,
    Mips_FLOOR_W_S_MMR6	= 1752,
    Mips_FMADD_D	= 1753,
    Mips_FMADD_W	= 1754,
    Mips_FMAX_A_D	= 1755,
    Mips_FMAX_A_W	= 1756,
    Mips_FMAX_D	= 1757,
    Mips_FMAX_W	= 1758,
    Mips_FMIN_A_D	= 1759,
    Mips_FMIN_A_W	= 1760,
    Mips_FMIN_D	= 1761,
    Mips_FMIN_W	= 1762,
    Mips_FMOV_D32	= 1763,
    Mips_FMOV_D32_MM	= 1764,
    Mips_FMOV_D64	= 1765,
    Mips_FMOV_D64_MM	= 1766,
    Mips_FMOV_D_MMR6	= 1767,
    Mips_FMOV_S	= 1768,
    Mips_FMOV_S_MM	= 1769,
    Mips_FMOV_S_MMR6	= 1770,
    Mips_FMSUB_D	= 1771,
    Mips_FMSUB_W	= 1772,
    Mips_FMUL_D	= 1773,
    Mips_FMUL_D32	= 1774,
    Mips_FMUL_D32_MM	= 1775,
    Mips_FMUL_D64	= 1776,
    Mips_FMUL_D64_MM	= 1777,
    Mips_FMUL_PS64	= 1778,
    Mips_FMUL_S	= 1779,
    Mips_FMUL_S_MM	= 1780,
    Mips_FMUL_S_MMR6	= 1781,
    Mips_FMUL_W	= 1782,
    Mips_FNEG_D32	= 1783,
    Mips_FNEG_D32_MM	= 1784,
    Mips_FNEG_D64	= 1785,
    Mips_FNEG_D64_MM	= 1786,
    Mips_FNEG_S	= 1787,
    Mips_FNEG_S_MM	= 1788,
    Mips_FNEG_S_MMR6	= 1789,
    Mips_FORK	= 1790,
    Mips_FORK_NM	= 1791,
    Mips_FRCP_D	= 1792,
    Mips_FRCP_W	= 1793,
    Mips_FRINT_D	= 1794,
    Mips_FRINT_W	= 1795,
    Mips_FRSQRT_D	= 1796,
    Mips_FRSQRT_W	= 1797,
    Mips_FSAF_D	= 1798,
    Mips_FSAF_W	= 1799,
    Mips_FSEQ_D	= 1800,
    Mips_FSEQ_W	= 1801,
    Mips_FSLE_D	= 1802,
    Mips_FSLE_W	= 1803,
    Mips_FSLT_D	= 1804,
    Mips_FSLT_W	= 1805,
    Mips_FSNE_D	= 1806,
    Mips_FSNE_W	= 1807,
    Mips_FSOR_D	= 1808,
    Mips_FSOR_W	= 1809,
    Mips_FSQRT_D	= 1810,
    Mips_FSQRT_D32	= 1811,
    Mips_FSQRT_D32_MM	= 1812,
    Mips_FSQRT_D64	= 1813,
    Mips_FSQRT_D64_MM	= 1814,
    Mips_FSQRT_S	= 1815,
    Mips_FSQRT_S_MM	= 1816,
    Mips_FSQRT_W	= 1817,
    Mips_FSUB_D	= 1818,
    Mips_FSUB_D32	= 1819,
    Mips_FSUB_D32_MM	= 1820,
    Mips_FSUB_D64	= 1821,
    Mips_FSUB_D64_MM	= 1822,
    Mips_FSUB_PS64	= 1823,
    Mips_FSUB_S	= 1824,
    Mips_FSUB_S_MM	= 1825,
    Mips_FSUB_S_MMR6	= 1826,
    Mips_FSUB_W	= 1827,
    Mips_FSUEQ_D	= 1828,
    Mips_FSUEQ_W	= 1829,
    Mips_FSULE_D	= 1830,
    Mips_FSULE_W	= 1831,
    Mips_FSULT_D	= 1832,
    Mips_FSULT_W	= 1833,
    Mips_FSUNE_D	= 1834,
    Mips_FSUNE_W	= 1835,
    Mips_FSUN_D	= 1836,
    Mips_FSUN_W	= 1837,
    Mips_FTINT_S_D	= 1838,
    Mips_FTINT_S_W	= 1839,
    Mips_FTINT_U_D	= 1840,
    Mips_FTINT_U_W	= 1841,
    Mips_FTQ_H	= 1842,
    Mips_FTQ_W	= 1843,
    Mips_FTRUNC_S_D	= 1844,
    Mips_FTRUNC_S_W	= 1845,
    Mips_FTRUNC_U_D	= 1846,
    Mips_FTRUNC_U_W	= 1847,
    Mips_GINVI	= 1848,
    Mips_GINVI_MMR6	= 1849,
    Mips_GINVI_NM	= 1850,
    Mips_GINVT	= 1851,
    Mips_GINVT_MMR6	= 1852,
    Mips_GINVT_NM	= 1853,
    Mips_HADD_S_D	= 1854,
    Mips_HADD_S_H	= 1855,
    Mips_HADD_S_W	= 1856,
    Mips_HADD_U_D	= 1857,
    Mips_HADD_U_H	= 1858,
    Mips_HADD_U_W	= 1859,
    Mips_HSUB_S_D	= 1860,
    Mips_HSUB_S_H	= 1861,
    Mips_HSUB_S_W	= 1862,
    Mips_HSUB_U_D	= 1863,
    Mips_HSUB_U_H	= 1864,
    Mips_HSUB_U_W	= 1865,
    Mips_HYPCALL	= 1866,
    Mips_HYPCALL_MM	= 1867,
    Mips_ILVEV_B	= 1868,
    Mips_ILVEV_D	= 1869,
    Mips_ILVEV_H	= 1870,
    Mips_ILVEV_W	= 1871,
    Mips_ILVL_B	= 1872,
    Mips_ILVL_D	= 1873,
    Mips_ILVL_H	= 1874,
    Mips_ILVL_W	= 1875,
    Mips_ILVOD_B	= 1876,
    Mips_ILVOD_D	= 1877,
    Mips_ILVOD_H	= 1878,
    Mips_ILVOD_W	= 1879,
    Mips_ILVR_B	= 1880,
    Mips_ILVR_D	= 1881,
    Mips_ILVR_H	= 1882,
    Mips_ILVR_W	= 1883,
    Mips_INS	= 1884,
    Mips_INSERT_B	= 1885,
    Mips_INSERT_D	= 1886,
    Mips_INSERT_H	= 1887,
    Mips_INSERT_W	= 1888,
    Mips_INSV	= 1889,
    Mips_INSVE_B	= 1890,
    Mips_INSVE_D	= 1891,
    Mips_INSVE_H	= 1892,
    Mips_INSVE_W	= 1893,
    Mips_INSV_MM	= 1894,
    Mips_INS_MM	= 1895,
    Mips_INS_MMR6	= 1896,
    Mips_INS_NM	= 1897,
    Mips_J	= 1898,
    Mips_JAL	= 1899,
    Mips_JALR	= 1900,
    Mips_JALR16_MM	= 1901,
    Mips_JALR64	= 1902,
    Mips_JALRC16_MMR6	= 1903,
    Mips_JALRC16_NM	= 1904,
    Mips_JALRCHB_NM	= 1905,
    Mips_JALRC_HB_MMR6	= 1906,
    Mips_JALRC_MMR6	= 1907,
    Mips_JALRC_NM	= 1908,
    Mips_JALRS16_MM	= 1909,
    Mips_JALRS_MM	= 1910,
    Mips_JALR_HB	= 1911,
    Mips_JALR_HB64	= 1912,
    Mips_JALR_MM	= 1913,
    Mips_JALS_MM	= 1914,
    Mips_JALX	= 1915,
    Mips_JALX_MM	= 1916,
    Mips_JAL_MM	= 1917,
    Mips_JIALC	= 1918,
    Mips_JIALC64	= 1919,
    Mips_JIALC_MMR6	= 1920,
    Mips_JIC	= 1921,
    Mips_JIC64	= 1922,
    Mips_JIC_MMR6	= 1923,
    Mips_JR	= 1924,
    Mips_JR16_MM	= 1925,
    Mips_JR64	= 1926,
    Mips_JRADDIUSP	= 1927,
    Mips_JRC16_MM	= 1928,
    Mips_JRC16_MMR6	= 1929,
    Mips_JRCADDIUSP_MMR6	= 1930,
    Mips_JRC_NM	= 1931,
    Mips_JR_HB	= 1932,
    Mips_JR_HB64	= 1933,
    Mips_JR_HB64_R6	= 1934,
    Mips_JR_HB_R6	= 1935,
    Mips_JR_MM	= 1936,
    Mips_J_MM	= 1937,
    Mips_Jal16	= 1938,
    Mips_JalB16	= 1939,
    Mips_JrRa16	= 1940,
    Mips_JrcRa16	= 1941,
    Mips_JrcRx16	= 1942,
    Mips_JumpLinkReg16	= 1943,
    Mips_LAPC32_NM	= 1944,
    Mips_LAPC48_NM	= 1945,
    Mips_LB	= 1946,
    Mips_LB16_NM	= 1947,
    Mips_LB64	= 1948,
    Mips_LBE	= 1949,
    Mips_LBE_MM	= 1950,
    Mips_LBGP_NM	= 1951,
    Mips_LBU16_MM	= 1952,
    Mips_LBU16_NM	= 1953,
    Mips_LBUGP_NM	= 1954,
    Mips_LBUX	= 1955,
    Mips_LBUX_MM	= 1956,
    Mips_LBUX_NM	= 1957,
    Mips_LBU_MMR6	= 1958,
    Mips_LBU_NM	= 1959,
    Mips_LBUs9_NM	= 1960,
    Mips_LBX_NM	= 1961,
    Mips_LB_MM	= 1962,
    Mips_LB_MMR6	= 1963,
    Mips_LB_NM	= 1964,
    Mips_LBs9_NM	= 1965,
    Mips_LBu	= 1966,
    Mips_LBu64	= 1967,
    Mips_LBuE	= 1968,
    Mips_LBuE_MM	= 1969,
    Mips_LBu_MM	= 1970,
    Mips_LD	= 1971,
    Mips_LDC1	= 1972,
    Mips_LDC164	= 1973,
    Mips_LDC1_D64_MMR6	= 1974,
    Mips_LDC1_MM_D32	= 1975,
    Mips_LDC1_MM_D64	= 1976,
    Mips_LDC2	= 1977,
    Mips_LDC2_MMR6	= 1978,
    Mips_LDC2_R6	= 1979,
    Mips_LDC3	= 1980,
    Mips_LDI_B	= 1981,
    Mips_LDI_D	= 1982,
    Mips_LDI_H	= 1983,
    Mips_LDI_W	= 1984,
    Mips_LDL	= 1985,
    Mips_LDPC	= 1986,
    Mips_LDR	= 1987,
    Mips_LDXC1	= 1988,
    Mips_LDXC164	= 1989,
    Mips_LD_B	= 1990,
    Mips_LD_D	= 1991,
    Mips_LD_H	= 1992,
    Mips_LD_W	= 1993,
    Mips_LEA_ADDIU_NM	= 1994,
    Mips_LEA_ADDiu	= 1995,
    Mips_LEA_ADDiu64	= 1996,
    Mips_LEA_ADDiu_MM	= 1997,
    Mips_LH	= 1998,
    Mips_LH16_NM	= 1999,
    Mips_LH64	= 2000,
    Mips_LHE	= 2001,
    Mips_LHE_MM	= 2002,
    Mips_LHGP_NM	= 2003,
    Mips_LHU16_MM	= 2004,
    Mips_LHU16_NM	= 2005,
    Mips_LHUGP_NM	= 2006,
    Mips_LHUXS_NM	= 2007,
    Mips_LHUX_NM	= 2008,
    Mips_LHU_NM	= 2009,
    Mips_LHUs9_NM	= 2010,
    Mips_LHX	= 2011,
    Mips_LHXS_NM	= 2012,
    Mips_LHX_MM	= 2013,
    Mips_LHX_NM	= 2014,
    Mips_LH_MM	= 2015,
    Mips_LH_NM	= 2016,
    Mips_LHs9_NM	= 2017,
    Mips_LHu	= 2018,
    Mips_LHu64	= 2019,
    Mips_LHuE	= 2020,
    Mips_LHuE_MM	= 2021,
    Mips_LHu_MM	= 2022,
    Mips_LI16_MM	= 2023,
    Mips_LI16_MMR6	= 2024,
    Mips_LI16_NM	= 2025,
    Mips_LI48_NM	= 2026,
    Mips_LL	= 2027,
    Mips_LL64	= 2028,
    Mips_LL64_R6	= 2029,
    Mips_LLD	= 2030,
    Mips_LLD_R6	= 2031,
    Mips_LLE	= 2032,
    Mips_LLE_MM	= 2033,
    Mips_LLWP_NM	= 2034,
    Mips_LL_MM	= 2035,
    Mips_LL_MMR6	= 2036,
    Mips_LL_NM	= 2037,
    Mips_LL_R6	= 2038,
    Mips_LSA	= 2039,
    Mips_LSA_MMR6	= 2040,
    Mips_LSA_NM	= 2041,
    Mips_LSA_R6	= 2042,
    Mips_LUI_MMR6	= 2043,
    Mips_LUI_NM	= 2044,
    Mips_LUXC1	= 2045,
    Mips_LUXC164	= 2046,
    Mips_LUXC1_MM	= 2047,
    Mips_LUi	= 2048,
    Mips_LUi64	= 2049,
    Mips_LUi_MM	= 2050,
    Mips_LW	= 2051,
    Mips_LW16_MM	= 2052,
    Mips_LW16_NM	= 2053,
    Mips_LW4x4_NM	= 2054,
    Mips_LW64	= 2055,
    Mips_LWC1	= 2056,
    Mips_LWC1_MM	= 2057,
    Mips_LWC2	= 2058,
    Mips_LWC2_MMR6	= 2059,
    Mips_LWC2_R6	= 2060,
    Mips_LWC3	= 2061,
    Mips_LWDSP	= 2062,
    Mips_LWDSP_MM	= 2063,
    Mips_LWE	= 2064,
    Mips_LWE_MM	= 2065,
    Mips_LWGP16_NM	= 2066,
    Mips_LWGP_MM	= 2067,
    Mips_LWGP_NM	= 2068,
    Mips_LWL	= 2069,
    Mips_LWL64	= 2070,
    Mips_LWLE	= 2071,
    Mips_LWLE_MM	= 2072,
    Mips_LWL_MM	= 2073,
    Mips_LWM16_MM	= 2074,
    Mips_LWM16_MMR6	= 2075,
    Mips_LWM32_MM	= 2076,
    Mips_LWM_NM	= 2077,
    Mips_LWPC	= 2078,
    Mips_LWPC_MMR6	= 2079,
    Mips_LWPC_NM	= 2080,
    Mips_LWP_MM	= 2081,
    Mips_LWR	= 2082,
    Mips_LWR64	= 2083,
    Mips_LWRE	= 2084,
    Mips_LWRE_MM	= 2085,
    Mips_LWR_MM	= 2086,
    Mips_LWSP16_NM	= 2087,
    Mips_LWSP_MM	= 2088,
    Mips_LWUPC	= 2089,
    Mips_LWU_MM	= 2090,
    Mips_LWX	= 2091,
    Mips_LWXC1	= 2092,
    Mips_LWXC1_MM	= 2093,
    Mips_LWXS16_NM	= 2094,
    Mips_LWXS_MM	= 2095,
    Mips_LWXS_NM	= 2096,
    Mips_LWX_MM	= 2097,
    Mips_LWX_NM	= 2098,
    Mips_LW_MM	= 2099,
    Mips_LW_MMR6	= 2100,
    Mips_LW_NM	= 2101,
    Mips_LWs9_NM	= 2102,
    Mips_LWu	= 2103,
    Mips_LbRxRyOffMemX16	= 2104,
    Mips_LbuRxRyOffMemX16	= 2105,
    Mips_LhRxRyOffMemX16	= 2106,
    Mips_LhuRxRyOffMemX16	= 2107,
    Mips_LiRxImm16	= 2108,
    Mips_LiRxImmAlignX16	= 2109,
    Mips_LiRxImmX16	= 2110,
    Mips_LwRxPcTcp16	= 2111,
    Mips_LwRxPcTcpX16	= 2112,
    Mips_LwRxRyOffMemX16	= 2113,
    Mips_LwRxSpImmX16	= 2114,
    Mips_MADD	= 2115,
    Mips_MADDF_D	= 2116,
    Mips_MADDF_D_MMR6	= 2117,
    Mips_MADDF_S	= 2118,
    Mips_MADDF_S_MMR6	= 2119,
    Mips_MADDR_Q_H	= 2120,
    Mips_MADDR_Q_W	= 2121,
    Mips_MADDU	= 2122,
    Mips_MADDU_DSP	= 2123,
    Mips_MADDU_DSP_MM	= 2124,
    Mips_MADDU_MM	= 2125,
    Mips_MADDV_B	= 2126,
    Mips_MADDV_D	= 2127,
    Mips_MADDV_H	= 2128,
    Mips_MADDV_W	= 2129,
    Mips_MADD_D32	= 2130,
    Mips_MADD_D32_MM	= 2131,
    Mips_MADD_D64	= 2132,
    Mips_MADD_DSP	= 2133,
    Mips_MADD_DSP_MM	= 2134,
    Mips_MADD_MM	= 2135,
    Mips_MADD_Q_H	= 2136,
    Mips_MADD_Q_W	= 2137,
    Mips_MADD_S	= 2138,
    Mips_MADD_S_MM	= 2139,
    Mips_MAQ_SA_W_PHL	= 2140,
    Mips_MAQ_SA_W_PHL_MM	= 2141,
    Mips_MAQ_SA_W_PHR	= 2142,
    Mips_MAQ_SA_W_PHR_MM	= 2143,
    Mips_MAQ_S_W_PHL	= 2144,
    Mips_MAQ_S_W_PHL_MM	= 2145,
    Mips_MAQ_S_W_PHR	= 2146,
    Mips_MAQ_S_W_PHR_MM	= 2147,
    Mips_MAXA_D	= 2148,
    Mips_MAXA_D_MMR6	= 2149,
    Mips_MAXA_S	= 2150,
    Mips_MAXA_S_MMR6	= 2151,
    Mips_MAXI_S_B	= 2152,
    Mips_MAXI_S_D	= 2153,
    Mips_MAXI_S_H	= 2154,
    Mips_MAXI_S_W	= 2155,
    Mips_MAXI_U_B	= 2156,
    Mips_MAXI_U_D	= 2157,
    Mips_MAXI_U_H	= 2158,
    Mips_MAXI_U_W	= 2159,
    Mips_MAX_A_B	= 2160,
    Mips_MAX_A_D	= 2161,
    Mips_MAX_A_H	= 2162,
    Mips_MAX_A_W	= 2163,
    Mips_MAX_D	= 2164,
    Mips_MAX_D_MMR6	= 2165,
    Mips_MAX_S	= 2166,
    Mips_MAX_S_B	= 2167,
    Mips_MAX_S_D	= 2168,
    Mips_MAX_S_H	= 2169,
    Mips_MAX_S_MMR6	= 2170,
    Mips_MAX_S_W	= 2171,
    Mips_MAX_U_B	= 2172,
    Mips_MAX_U_D	= 2173,
    Mips_MAX_U_H	= 2174,
    Mips_MAX_U_W	= 2175,
    Mips_MFC0	= 2176,
    Mips_MFC0Sel_NM	= 2177,
    Mips_MFC0_MMR6	= 2178,
    Mips_MFC0_NM	= 2179,
    Mips_MFC1	= 2180,
    Mips_MFC1_D64	= 2181,
    Mips_MFC1_MM	= 2182,
    Mips_MFC1_MMR6	= 2183,
    Mips_MFC2	= 2184,
    Mips_MFC2_MMR6	= 2185,
    Mips_MFGC0	= 2186,
    Mips_MFGC0_MM	= 2187,
    Mips_MFHC0Sel_NM	= 2188,
    Mips_MFHC0_MMR6	= 2189,
    Mips_MFHC0_NM	= 2190,
    Mips_MFHC1_D32	= 2191,
    Mips_MFHC1_D32_MM	= 2192,
    Mips_MFHC1_D64	= 2193,
    Mips_MFHC1_D64_MM	= 2194,
    Mips_MFHC2_MMR6	= 2195,
    Mips_MFHGC0	= 2196,
    Mips_MFHGC0_MM	= 2197,
    Mips_MFHI	= 2198,
    Mips_MFHI16_MM	= 2199,
    Mips_MFHI64	= 2200,
    Mips_MFHI_DSP	= 2201,
    Mips_MFHI_DSP_MM	= 2202,
    Mips_MFHI_MM	= 2203,
    Mips_MFLO	= 2204,
    Mips_MFLO16_MM	= 2205,
    Mips_MFLO64	= 2206,
    Mips_MFLO_DSP	= 2207,
    Mips_MFLO_DSP_MM	= 2208,
    Mips_MFLO_MM	= 2209,
    Mips_MFTR	= 2210,
    Mips_MFTR_NM	= 2211,
    Mips_MINA_D	= 2212,
    Mips_MINA_D_MMR6	= 2213,
    Mips_MINA_S	= 2214,
    Mips_MINA_S_MMR6	= 2215,
    Mips_MINI_S_B	= 2216,
    Mips_MINI_S_D	= 2217,
    Mips_MINI_S_H	= 2218,
    Mips_MINI_S_W	= 2219,
    Mips_MINI_U_B	= 2220,
    Mips_MINI_U_D	= 2221,
    Mips_MINI_U_H	= 2222,
    Mips_MINI_U_W	= 2223,
    Mips_MIN_A_B	= 2224,
    Mips_MIN_A_D	= 2225,
    Mips_MIN_A_H	= 2226,
    Mips_MIN_A_W	= 2227,
    Mips_MIN_D	= 2228,
    Mips_MIN_D_MMR6	= 2229,
    Mips_MIN_S	= 2230,
    Mips_MIN_S_B	= 2231,
    Mips_MIN_S_D	= 2232,
    Mips_MIN_S_H	= 2233,
    Mips_MIN_S_MMR6	= 2234,
    Mips_MIN_S_W	= 2235,
    Mips_MIN_U_B	= 2236,
    Mips_MIN_U_D	= 2237,
    Mips_MIN_U_H	= 2238,
    Mips_MIN_U_W	= 2239,
    Mips_MOD	= 2240,
    Mips_MODSUB	= 2241,
    Mips_MODSUB_MM	= 2242,
    Mips_MODU	= 2243,
    Mips_MODU_MMR6	= 2244,
    Mips_MODU_NM	= 2245,
    Mips_MOD_MMR6	= 2246,
    Mips_MOD_NM	= 2247,
    Mips_MOD_S_B	= 2248,
    Mips_MOD_S_D	= 2249,
    Mips_MOD_S_H	= 2250,
    Mips_MOD_S_W	= 2251,
    Mips_MOD_U_B	= 2252,
    Mips_MOD_U_D	= 2253,
    Mips_MOD_U_H	= 2254,
    Mips_MOD_U_W	= 2255,
    Mips_MOVE16_MM	= 2256,
    Mips_MOVE16_MMR6	= 2257,
    Mips_MOVEBALC_NM	= 2258,
    Mips_MOVEPREV_NM	= 2259,
    Mips_MOVEP_MM	= 2260,
    Mips_MOVEP_MMR6	= 2261,
    Mips_MOVEP_NM	= 2262,
    Mips_MOVE_NM	= 2263,
    Mips_MOVE_V	= 2264,
    Mips_MOVF_D32	= 2265,
    Mips_MOVF_D32_MM	= 2266,
    Mips_MOVF_D64	= 2267,
    Mips_MOVF_I	= 2268,
    Mips_MOVF_I64	= 2269,
    Mips_MOVF_I_MM	= 2270,
    Mips_MOVF_S	= 2271,
    Mips_MOVF_S_MM	= 2272,
    Mips_MOVN_I64_D64	= 2273,
    Mips_MOVN_I64_I	= 2274,
    Mips_MOVN_I64_I64	= 2275,
    Mips_MOVN_I64_S	= 2276,
    Mips_MOVN_I_D32	= 2277,
    Mips_MOVN_I_D32_MM	= 2278,
    Mips_MOVN_I_D64	= 2279,
    Mips_MOVN_I_I	= 2280,
    Mips_MOVN_I_I64	= 2281,
    Mips_MOVN_I_MM	= 2282,
    Mips_MOVN_I_S	= 2283,
    Mips_MOVN_I_S_MM	= 2284,
    Mips_MOVN_NM	= 2285,
    Mips_MOVT_D32	= 2286,
    Mips_MOVT_D32_MM	= 2287,
    Mips_MOVT_D64	= 2288,
    Mips_MOVT_I	= 2289,
    Mips_MOVT_I64	= 2290,
    Mips_MOVT_I_MM	= 2291,
    Mips_MOVT_S	= 2292,
    Mips_MOVT_S_MM	= 2293,
    Mips_MOVZ_I64_D64	= 2294,
    Mips_MOVZ_I64_I	= 2295,
    Mips_MOVZ_I64_I64	= 2296,
    Mips_MOVZ_I64_S	= 2297,
    Mips_MOVZ_I_D32	= 2298,
    Mips_MOVZ_I_D32_MM	= 2299,
    Mips_MOVZ_I_D64	= 2300,
    Mips_MOVZ_I_I	= 2301,
    Mips_MOVZ_I_I64	= 2302,
    Mips_MOVZ_I_MM	= 2303,
    Mips_MOVZ_I_S	= 2304,
    Mips_MOVZ_I_S_MM	= 2305,
    Mips_MOVZ_NM	= 2306,
    Mips_MSUB	= 2307,
    Mips_MSUBF_D	= 2308,
    Mips_MSUBF_D_MMR6	= 2309,
    Mips_MSUBF_S	= 2310,
    Mips_MSUBF_S_MMR6	= 2311,
    Mips_MSUBR_Q_H	= 2312,
    Mips_MSUBR_Q_W	= 2313,
    Mips_MSUBU	= 2314,
    Mips_MSUBU_DSP	= 2315,
    Mips_MSUBU_DSP_MM	= 2316,
    Mips_MSUBU_MM	= 2317,
    Mips_MSUBV_B	= 2318,
    Mips_MSUBV_D	= 2319,
    Mips_MSUBV_H	= 2320,
    Mips_MSUBV_W	= 2321,
    Mips_MSUB_D32	= 2322,
    Mips_MSUB_D32_MM	= 2323,
    Mips_MSUB_D64	= 2324,
    Mips_MSUB_DSP	= 2325,
    Mips_MSUB_DSP_MM	= 2326,
    Mips_MSUB_MM	= 2327,
    Mips_MSUB_Q_H	= 2328,
    Mips_MSUB_Q_W	= 2329,
    Mips_MSUB_S	= 2330,
    Mips_MSUB_S_MM	= 2331,
    Mips_MTC0	= 2332,
    Mips_MTC0Sel_NM	= 2333,
    Mips_MTC0_MMR6	= 2334,
    Mips_MTC0_NM	= 2335,
    Mips_MTC1	= 2336,
    Mips_MTC1_D64	= 2337,
    Mips_MTC1_D64_MM	= 2338,
    Mips_MTC1_MM	= 2339,
    Mips_MTC1_MMR6	= 2340,
    Mips_MTC2	= 2341,
    Mips_MTC2_MMR6	= 2342,
    Mips_MTGC0	= 2343,
    Mips_MTGC0_MM	= 2344,
    Mips_MTHC0Sel_NM	= 2345,
    Mips_MTHC0_MMR6	= 2346,
    Mips_MTHC0_NM	= 2347,
    Mips_MTHC1_D32	= 2348,
    Mips_MTHC1_D32_MM	= 2349,
    Mips_MTHC1_D64	= 2350,
    Mips_MTHC1_D64_MM	= 2351,
    Mips_MTHC2_MMR6	= 2352,
    Mips_MTHGC0	= 2353,
    Mips_MTHGC0_MM	= 2354,
    Mips_MTHI	= 2355,
    Mips_MTHI64	= 2356,
    Mips_MTHI_DSP	= 2357,
    Mips_MTHI_DSP_MM	= 2358,
    Mips_MTHI_MM	= 2359,
    Mips_MTHLIP	= 2360,
    Mips_MTHLIP_MM	= 2361,
    Mips_MTLO	= 2362,
    Mips_MTLO64	= 2363,
    Mips_MTLO_DSP	= 2364,
    Mips_MTLO_DSP_MM	= 2365,
    Mips_MTLO_MM	= 2366,
    Mips_MTM0	= 2367,
    Mips_MTM1	= 2368,
    Mips_MTM2	= 2369,
    Mips_MTP0	= 2370,
    Mips_MTP1	= 2371,
    Mips_MTP2	= 2372,
    Mips_MTTR	= 2373,
    Mips_MTTR_NM	= 2374,
    Mips_MUH	= 2375,
    Mips_MUHU	= 2376,
    Mips_MUHU_MMR6	= 2377,
    Mips_MUHU_NM	= 2378,
    Mips_MUH_MMR6	= 2379,
    Mips_MUH_NM	= 2380,
    Mips_MUL	= 2381,
    Mips_MUL4x4_NM	= 2382,
    Mips_MULEQ_S_W_PHL	= 2383,
    Mips_MULEQ_S_W_PHL_MM	= 2384,
    Mips_MULEQ_S_W_PHR	= 2385,
    Mips_MULEQ_S_W_PHR_MM	= 2386,
    Mips_MULEU_S_PH_QBL	= 2387,
    Mips_MULEU_S_PH_QBL_MM	= 2388,
    Mips_MULEU_S_PH_QBR	= 2389,
    Mips_MULEU_S_PH_QBR_MM	= 2390,
    Mips_MULQ_RS_PH	= 2391,
    Mips_MULQ_RS_PH_MM	= 2392,
    Mips_MULQ_RS_W	= 2393,
    Mips_MULQ_RS_W_MMR2	= 2394,
    Mips_MULQ_S_PH	= 2395,
    Mips_MULQ_S_PH_MMR2	= 2396,
    Mips_MULQ_S_W	= 2397,
    Mips_MULQ_S_W_MMR2	= 2398,
    Mips_MULR_PS64	= 2399,
    Mips_MULR_Q_H	= 2400,
    Mips_MULR_Q_W	= 2401,
    Mips_MULSAQ_S_W_PH	= 2402,
    Mips_MULSAQ_S_W_PH_MM	= 2403,
    Mips_MULSA_W_PH	= 2404,
    Mips_MULSA_W_PH_MMR2	= 2405,
    Mips_MULT	= 2406,
    Mips_MULTU_DSP	= 2407,
    Mips_MULTU_DSP_MM	= 2408,
    Mips_MULT_DSP	= 2409,
    Mips_MULT_DSP_MM	= 2410,
    Mips_MULT_MM	= 2411,
    Mips_MULTu	= 2412,
    Mips_MULTu_MM	= 2413,
    Mips_MULU	= 2414,
    Mips_MULU_MMR6	= 2415,
    Mips_MULU_NM	= 2416,
    Mips_MULV_B	= 2417,
    Mips_MULV_D	= 2418,
    Mips_MULV_H	= 2419,
    Mips_MULV_W	= 2420,
    Mips_MUL_MM	= 2421,
    Mips_MUL_MMR6	= 2422,
    Mips_MUL_NM	= 2423,
    Mips_MUL_PH	= 2424,
    Mips_MUL_PH_MMR2	= 2425,
    Mips_MUL_Q_H	= 2426,
    Mips_MUL_Q_W	= 2427,
    Mips_MUL_R6	= 2428,
    Mips_MUL_S_PH	= 2429,
    Mips_MUL_S_PH_MMR2	= 2430,
    Mips_Mfhi16	= 2431,
    Mips_Mflo16	= 2432,
    Mips_Move32R16	= 2433,
    Mips_MoveR3216	= 2434,
    Mips_NLOC_B	= 2435,
    Mips_NLOC_D	= 2436,
    Mips_NLOC_H	= 2437,
    Mips_NLOC_W	= 2438,
    Mips_NLZC_B	= 2439,
    Mips_NLZC_D	= 2440,
    Mips_NLZC_H	= 2441,
    Mips_NLZC_W	= 2442,
    Mips_NMADD_D32	= 2443,
    Mips_NMADD_D32_MM	= 2444,
    Mips_NMADD_D64	= 2445,
    Mips_NMADD_S	= 2446,
    Mips_NMADD_S_MM	= 2447,
    Mips_NMSUB_D32	= 2448,
    Mips_NMSUB_D32_MM	= 2449,
    Mips_NMSUB_D64	= 2450,
    Mips_NMSUB_S	= 2451,
    Mips_NMSUB_S_MM	= 2452,
    Mips_NOP32_NM	= 2453,
    Mips_NOP_NM	= 2454,
    Mips_NOR	= 2455,
    Mips_NOR64	= 2456,
    Mips_NORI_B	= 2457,
    Mips_NOR_MM	= 2458,
    Mips_NOR_MMR6	= 2459,
    Mips_NOR_NM	= 2460,
    Mips_NOR_V	= 2461,
    Mips_NOT16_MM	= 2462,
    Mips_NOT16_MMR6	= 2463,
    Mips_NOT16_NM	= 2464,
    Mips_NegRxRy16	= 2465,
    Mips_NotRxRy16	= 2466,
    Mips_OR	= 2467,
    Mips_OR16_MM	= 2468,
    Mips_OR16_MMR6	= 2469,
    Mips_OR16_NM	= 2470,
    Mips_OR64	= 2471,
    Mips_ORI_B	= 2472,
    Mips_ORI_MMR6	= 2473,
    Mips_ORI_NM	= 2474,
    Mips_OR_MM	= 2475,
    Mips_OR_MMR6	= 2476,
    Mips_OR_NM	= 2477,
    Mips_OR_V	= 2478,
    Mips_ORi	= 2479,
    Mips_ORi64	= 2480,
    Mips_ORi_MM	= 2481,
    Mips_OrRxRxRy16	= 2482,
    Mips_PACKRL_PH	= 2483,
    Mips_PACKRL_PH_MM	= 2484,
    Mips_PAUSE	= 2485,
    Mips_PAUSE_MM	= 2486,
    Mips_PAUSE_MMR6	= 2487,
    Mips_PAUSE_NM	= 2488,
    Mips_PCKEV_B	= 2489,
    Mips_PCKEV_D	= 2490,
    Mips_PCKEV_H	= 2491,
    Mips_PCKEV_W	= 2492,
    Mips_PCKOD_B	= 2493,
    Mips_PCKOD_D	= 2494,
    Mips_PCKOD_H	= 2495,
    Mips_PCKOD_W	= 2496,
    Mips_PCNT_B	= 2497,
    Mips_PCNT_D	= 2498,
    Mips_PCNT_H	= 2499,
    Mips_PCNT_W	= 2500,
    Mips_PICK_PH	= 2501,
    Mips_PICK_PH_MM	= 2502,
    Mips_PICK_QB	= 2503,
    Mips_PICK_QB_MM	= 2504,
    Mips_PLL_PS64	= 2505,
    Mips_PLU_PS64	= 2506,
    Mips_POP	= 2507,
    Mips_PRECEQU_PH_QBL	= 2508,
    Mips_PRECEQU_PH_QBLA	= 2509,
    Mips_PRECEQU_PH_QBLA_MM	= 2510,
    Mips_PRECEQU_PH_QBL_MM	= 2511,
    Mips_PRECEQU_PH_QBR	= 2512,
    Mips_PRECEQU_PH_QBRA	= 2513,
    Mips_PRECEQU_PH_QBRA_MM	= 2514,
    Mips_PRECEQU_PH_QBR_MM	= 2515,
    Mips_PRECEQ_W_PHL	= 2516,
    Mips_PRECEQ_W_PHL_MM	= 2517,
    Mips_PRECEQ_W_PHR	= 2518,
    Mips_PRECEQ_W_PHR_MM	= 2519,
    Mips_PRECEU_PH_QBL	= 2520,
    Mips_PRECEU_PH_QBLA	= 2521,
    Mips_PRECEU_PH_QBLA_MM	= 2522,
    Mips_PRECEU_PH_QBL_MM	= 2523,
    Mips_PRECEU_PH_QBR	= 2524,
    Mips_PRECEU_PH_QBRA	= 2525,
    Mips_PRECEU_PH_QBRA_MM	= 2526,
    Mips_PRECEU_PH_QBR_MM	= 2527,
    Mips_PRECRQU_S_QB_PH	= 2528,
    Mips_PRECRQU_S_QB_PH_MM	= 2529,
    Mips_PRECRQ_PH_W	= 2530,
    Mips_PRECRQ_PH_W_MM	= 2531,
    Mips_PRECRQ_QB_PH	= 2532,
    Mips_PRECRQ_QB_PH_MM	= 2533,
    Mips_PRECRQ_RS_PH_W	= 2534,
    Mips_PRECRQ_RS_PH_W_MM	= 2535,
    Mips_PRECR_QB_PH	= 2536,
    Mips_PRECR_QB_PH_MMR2	= 2537,
    Mips_PRECR_SRA_PH_W	= 2538,
    Mips_PRECR_SRA_PH_W_MMR2	= 2539,
    Mips_PRECR_SRA_R_PH_W	= 2540,
    Mips_PRECR_SRA_R_PH_W_MMR2	= 2541,
    Mips_PREF	= 2542,
    Mips_PREFE	= 2543,
    Mips_PREFE_MM	= 2544,
    Mips_PREFX_MM	= 2545,
    Mips_PREF_MM	= 2546,
    Mips_PREF_MMR6	= 2547,
    Mips_PREF_NM	= 2548,
    Mips_PREF_R6	= 2549,
    Mips_PREFs9_NM	= 2550,
    Mips_PREPEND	= 2551,
    Mips_PREPEND_MMR2	= 2552,
    Mips_PUL_PS64	= 2553,
    Mips_PUU_PS64	= 2554,
    Mips_RADDU_W_QB	= 2555,
    Mips_RADDU_W_QB_MM	= 2556,
    Mips_RDDSP	= 2557,
    Mips_RDDSP_MM	= 2558,
    Mips_RDHWR	= 2559,
    Mips_RDHWR64	= 2560,
    Mips_RDHWR_MM	= 2561,
    Mips_RDHWR_MMR6	= 2562,
    Mips_RDHWR_NM	= 2563,
    Mips_RDPGPR_MMR6	= 2564,
    Mips_RDPGPR_NM	= 2565,
    Mips_RECIP_D32	= 2566,
    Mips_RECIP_D32_MM	= 2567,
    Mips_RECIP_D64	= 2568,
    Mips_RECIP_D64_MM	= 2569,
    Mips_RECIP_S	= 2570,
    Mips_RECIP_S_MM	= 2571,
    Mips_REPLV_PH	= 2572,
    Mips_REPLV_PH_MM	= 2573,
    Mips_REPLV_QB	= 2574,
    Mips_REPLV_QB_MM	= 2575,
    Mips_REPL_PH	= 2576,
    Mips_REPL_PH_MM	= 2577,
    Mips_REPL_QB	= 2578,
    Mips_REPL_QB_MM	= 2579,
    Mips_RESTOREJRC16_NM	= 2580,
    Mips_RESTOREJRC_NM	= 2581,
    Mips_RESTORE_NM	= 2582,
    Mips_RINT_D	= 2583,
    Mips_RINT_D_MMR6	= 2584,
    Mips_RINT_S	= 2585,
    Mips_RINT_S_MMR6	= 2586,
    Mips_ROTR	= 2587,
    Mips_ROTRV	= 2588,
    Mips_ROTRV_MM	= 2589,
    Mips_ROTRV_NM	= 2590,
    Mips_ROTR_MM	= 2591,
    Mips_ROTR_NM	= 2592,
    Mips_ROTX_NM	= 2593,
    Mips_ROUND_L_D64	= 2594,
    Mips_ROUND_L_D_MMR6	= 2595,
    Mips_ROUND_L_S	= 2596,
    Mips_ROUND_L_S_MMR6	= 2597,
    Mips_ROUND_W_D32	= 2598,
    Mips_ROUND_W_D64	= 2599,
    Mips_ROUND_W_D_MMR6	= 2600,
    Mips_ROUND_W_MM	= 2601,
    Mips_ROUND_W_S	= 2602,
    Mips_ROUND_W_S_MM	= 2603,
    Mips_ROUND_W_S_MMR6	= 2604,
    Mips_RSQRT_D32	= 2605,
    Mips_RSQRT_D32_MM	= 2606,
    Mips_RSQRT_D64	= 2607,
    Mips_RSQRT_D64_MM	= 2608,
    Mips_RSQRT_S	= 2609,
    Mips_RSQRT_S_MM	= 2610,
    Mips_Restore16	= 2611,
    Mips_RestoreX16	= 2612,
    Mips_SAA	= 2613,
    Mips_SAAD	= 2614,
    Mips_SAT_S_B	= 2615,
    Mips_SAT_S_D	= 2616,
    Mips_SAT_S_H	= 2617,
    Mips_SAT_S_W	= 2618,
    Mips_SAT_U_B	= 2619,
    Mips_SAT_U_D	= 2620,
    Mips_SAT_U_H	= 2621,
    Mips_SAT_U_W	= 2622,
    Mips_SAVE16_NM	= 2623,
    Mips_SAVE_NM	= 2624,
    Mips_SB	= 2625,
    Mips_SB16_MM	= 2626,
    Mips_SB16_MMR6	= 2627,
    Mips_SB16_NM	= 2628,
    Mips_SB64	= 2629,
    Mips_SBE	= 2630,
    Mips_SBE_MM	= 2631,
    Mips_SBGP_NM	= 2632,
    Mips_SBX_NM	= 2633,
    Mips_SB_MM	= 2634,
    Mips_SB_MMR6	= 2635,
    Mips_SB_NM	= 2636,
    Mips_SBs9_NM	= 2637,
    Mips_SC	= 2638,
    Mips_SC64	= 2639,
    Mips_SC64_R6	= 2640,
    Mips_SCD	= 2641,
    Mips_SCD_R6	= 2642,
    Mips_SCE	= 2643,
    Mips_SCE_MM	= 2644,
    Mips_SCWP_NM	= 2645,
    Mips_SC_MM	= 2646,
    Mips_SC_MMR6	= 2647,
    Mips_SC_NM	= 2648,
    Mips_SC_R6	= 2649,
    Mips_SD	= 2650,
    Mips_SDBBP	= 2651,
    Mips_SDBBP16_MM	= 2652,
    Mips_SDBBP16_MMR6	= 2653,
    Mips_SDBBP16_NM	= 2654,
    Mips_SDBBP_MM	= 2655,
    Mips_SDBBP_MMR6	= 2656,
    Mips_SDBBP_NM	= 2657,
    Mips_SDBBP_R6	= 2658,
    Mips_SDC1	= 2659,
    Mips_SDC164	= 2660,
    Mips_SDC1_D64_MMR6	= 2661,
    Mips_SDC1_MM_D32	= 2662,
    Mips_SDC1_MM_D64	= 2663,
    Mips_SDC2	= 2664,
    Mips_SDC2_MMR6	= 2665,
    Mips_SDC2_R6	= 2666,
    Mips_SDC3	= 2667,
    Mips_SDIV	= 2668,
    Mips_SDIV_MM	= 2669,
    Mips_SDL	= 2670,
    Mips_SDR	= 2671,
    Mips_SDXC1	= 2672,
    Mips_SDXC164	= 2673,
    Mips_SEB	= 2674,
    Mips_SEB64	= 2675,
    Mips_SEB_MM	= 2676,
    Mips_SEB_NM	= 2677,
    Mips_SEH	= 2678,
    Mips_SEH64	= 2679,
    Mips_SEH_MM	= 2680,
    Mips_SEH_NM	= 2681,
    Mips_SELEQZ	= 2682,
    Mips_SELEQZ64	= 2683,
    Mips_SELEQZ_D	= 2684,
    Mips_SELEQZ_D_MMR6	= 2685,
    Mips_SELEQZ_MMR6	= 2686,
    Mips_SELEQZ_S	= 2687,
    Mips_SELEQZ_S_MMR6	= 2688,
    Mips_SELNEZ	= 2689,
    Mips_SELNEZ64	= 2690,
    Mips_SELNEZ_D	= 2691,
    Mips_SELNEZ_D_MMR6	= 2692,
    Mips_SELNEZ_MMR6	= 2693,
    Mips_SELNEZ_S	= 2694,
    Mips_SELNEZ_S_MMR6	= 2695,
    Mips_SEL_D	= 2696,
    Mips_SEL_D_MMR6	= 2697,
    Mips_SEL_S	= 2698,
    Mips_SEL_S_MMR6	= 2699,
    Mips_SEQ	= 2700,
    Mips_SEQI_NM	= 2701,
    Mips_SEQi	= 2702,
    Mips_SH	= 2703,
    Mips_SH16_MM	= 2704,
    Mips_SH16_MMR6	= 2705,
    Mips_SH16_NM	= 2706,
    Mips_SH64	= 2707,
    Mips_SHE	= 2708,
    Mips_SHE_MM	= 2709,
    Mips_SHF_B	= 2710,
    Mips_SHF_H	= 2711,
    Mips_SHF_W	= 2712,
    Mips_SHGP_NM	= 2713,
    Mips_SHILO	= 2714,
    Mips_SHILOV	= 2715,
    Mips_SHILOV_MM	= 2716,
    Mips_SHILO_MM	= 2717,
    Mips_SHLLV_PH	= 2718,
    Mips_SHLLV_PH_MM	= 2719,
    Mips_SHLLV_QB	= 2720,
    Mips_SHLLV_QB_MM	= 2721,
    Mips_SHLLV_S_PH	= 2722,
    Mips_SHLLV_S_PH_MM	= 2723,
    Mips_SHLLV_S_W	= 2724,
    Mips_SHLLV_S_W_MM	= 2725,
    Mips_SHLL_PH	= 2726,
    Mips_SHLL_PH_MM	= 2727,
    Mips_SHLL_QB	= 2728,
    Mips_SHLL_QB_MM	= 2729,
    Mips_SHLL_S_PH	= 2730,
    Mips_SHLL_S_PH_MM	= 2731,
    Mips_SHLL_S_W	= 2732,
    Mips_SHLL_S_W_MM	= 2733,
    Mips_SHRAV_PH	= 2734,
    Mips_SHRAV_PH_MM	= 2735,
    Mips_SHRAV_QB	= 2736,
    Mips_SHRAV_QB_MMR2	= 2737,
    Mips_SHRAV_R_PH	= 2738,
    Mips_SHRAV_R_PH_MM	= 2739,
    Mips_SHRAV_R_QB	= 2740,
    Mips_SHRAV_R_QB_MMR2	= 2741,
    Mips_SHRAV_R_W	= 2742,
    Mips_SHRAV_R_W_MM	= 2743,
    Mips_SHRA_PH	= 2744,
    Mips_SHRA_PH_MM	= 2745,
    Mips_SHRA_QB	= 2746,
    Mips_SHRA_QB_MMR2	= 2747,
    Mips_SHRA_R_PH	= 2748,
    Mips_SHRA_R_PH_MM	= 2749,
    Mips_SHRA_R_QB	= 2750,
    Mips_SHRA_R_QB_MMR2	= 2751,
    Mips_SHRA_R_W	= 2752,
    Mips_SHRA_R_W_MM	= 2753,
    Mips_SHRLV_PH	= 2754,
    Mips_SHRLV_PH_MMR2	= 2755,
    Mips_SHRLV_QB	= 2756,
    Mips_SHRLV_QB_MM	= 2757,
    Mips_SHRL_PH	= 2758,
    Mips_SHRL_PH_MMR2	= 2759,
    Mips_SHRL_QB	= 2760,
    Mips_SHRL_QB_MM	= 2761,
    Mips_SHXS_NM	= 2762,
    Mips_SHX_NM	= 2763,
    Mips_SH_MM	= 2764,
    Mips_SH_MMR6	= 2765,
    Mips_SH_NM	= 2766,
    Mips_SHs9_NM	= 2767,
    Mips_SIGRIE	= 2768,
    Mips_SIGRIE_MMR6	= 2769,
    Mips_SIGRIE_NM	= 2770,
    Mips_SLDI_B	= 2771,
    Mips_SLDI_D	= 2772,
    Mips_SLDI_H	= 2773,
    Mips_SLDI_W	= 2774,
    Mips_SLD_B	= 2775,
    Mips_SLD_D	= 2776,
    Mips_SLD_H	= 2777,
    Mips_SLD_W	= 2778,
    Mips_SLL	= 2779,
    Mips_SLL16_MM	= 2780,
    Mips_SLL16_MMR6	= 2781,
    Mips_SLL16_NM	= 2782,
    Mips_SLL64_32	= 2783,
    Mips_SLL64_64	= 2784,
    Mips_SLLI_B	= 2785,
    Mips_SLLI_D	= 2786,
    Mips_SLLI_H	= 2787,
    Mips_SLLI_W	= 2788,
    Mips_SLLV	= 2789,
    Mips_SLLV_MM	= 2790,
    Mips_SLLV_NM	= 2791,
    Mips_SLL_B	= 2792,
    Mips_SLL_D	= 2793,
    Mips_SLL_H	= 2794,
    Mips_SLL_MM	= 2795,
    Mips_SLL_MMR6	= 2796,
    Mips_SLL_NM	= 2797,
    Mips_SLL_W	= 2798,
    Mips_SLT	= 2799,
    Mips_SLT64	= 2800,
    Mips_SLTIU_NM	= 2801,
    Mips_SLTI_NM	= 2802,
    Mips_SLTU_NM	= 2803,
    Mips_SLT_MM	= 2804,
    Mips_SLT_NM	= 2805,
    Mips_SLTi	= 2806,
    Mips_SLTi64	= 2807,
    Mips_SLTi_MM	= 2808,
    Mips_SLTiu	= 2809,
    Mips_SLTiu64	= 2810,
    Mips_SLTiu_MM	= 2811,
    Mips_SLTu	= 2812,
    Mips_SLTu64	= 2813,
    Mips_SLTu_MM	= 2814,
    Mips_SNE	= 2815,
    Mips_SNEi	= 2816,
    Mips_SOV_NM	= 2817,
    Mips_SPLATI_B	= 2818,
    Mips_SPLATI_D	= 2819,
    Mips_SPLATI_H	= 2820,
    Mips_SPLATI_W	= 2821,
    Mips_SPLAT_B	= 2822,
    Mips_SPLAT_D	= 2823,
    Mips_SPLAT_H	= 2824,
    Mips_SPLAT_W	= 2825,
    Mips_SRA	= 2826,
    Mips_SRAI_B	= 2827,
    Mips_SRAI_D	= 2828,
    Mips_SRAI_H	= 2829,
    Mips_SRAI_W	= 2830,
    Mips_SRARI_B	= 2831,
    Mips_SRARI_D	= 2832,
    Mips_SRARI_H	= 2833,
    Mips_SRARI_W	= 2834,
    Mips_SRAR_B	= 2835,
    Mips_SRAR_D	= 2836,
    Mips_SRAR_H	= 2837,
    Mips_SRAR_W	= 2838,
    Mips_SRAV	= 2839,
    Mips_SRAV_MM	= 2840,
    Mips_SRAV_NM	= 2841,
    Mips_SRA_B	= 2842,
    Mips_SRA_D	= 2843,
    Mips_SRA_H	= 2844,
    Mips_SRA_MM	= 2845,
    Mips_SRA_NM	= 2846,
    Mips_SRA_W	= 2847,
    Mips_SRL	= 2848,
    Mips_SRL16_MM	= 2849,
    Mips_SRL16_MMR6	= 2850,
    Mips_SRL16_NM	= 2851,
    Mips_SRLI_B	= 2852,
    Mips_SRLI_D	= 2853,
    Mips_SRLI_H	= 2854,
    Mips_SRLI_W	= 2855,
    Mips_SRLRI_B	= 2856,
    Mips_SRLRI_D	= 2857,
    Mips_SRLRI_H	= 2858,
    Mips_SRLRI_W	= 2859,
    Mips_SRLR_B	= 2860,
    Mips_SRLR_D	= 2861,
    Mips_SRLR_H	= 2862,
    Mips_SRLR_W	= 2863,
    Mips_SRLV	= 2864,
    Mips_SRLV_MM	= 2865,
    Mips_SRLV_NM	= 2866,
    Mips_SRL_B	= 2867,
    Mips_SRL_D	= 2868,
    Mips_SRL_H	= 2869,
    Mips_SRL_MM	= 2870,
    Mips_SRL_NM	= 2871,
    Mips_SRL_W	= 2872,
    Mips_SSNOP	= 2873,
    Mips_SSNOP_MM	= 2874,
    Mips_SSNOP_MMR6	= 2875,
    Mips_ST_B	= 2876,
    Mips_ST_D	= 2877,
    Mips_ST_H	= 2878,
    Mips_ST_W	= 2879,
    Mips_SUB	= 2880,
    Mips_SUBQH_PH	= 2881,
    Mips_SUBQH_PH_MMR2	= 2882,
    Mips_SUBQH_R_PH	= 2883,
    Mips_SUBQH_R_PH_MMR2	= 2884,
    Mips_SUBQH_R_W	= 2885,
    Mips_SUBQH_R_W_MMR2	= 2886,
    Mips_SUBQH_W	= 2887,
    Mips_SUBQH_W_MMR2	= 2888,
    Mips_SUBQ_PH	= 2889,
    Mips_SUBQ_PH_MM	= 2890,
    Mips_SUBQ_S_PH	= 2891,
    Mips_SUBQ_S_PH_MM	= 2892,
    Mips_SUBQ_S_W	= 2893,
    Mips_SUBQ_S_W_MM	= 2894,
    Mips_SUBSUS_U_B	= 2895,
    Mips_SUBSUS_U_D	= 2896,
    Mips_SUBSUS_U_H	= 2897,
    Mips_SUBSUS_U_W	= 2898,
    Mips_SUBSUU_S_B	= 2899,
    Mips_SUBSUU_S_D	= 2900,
    Mips_SUBSUU_S_H	= 2901,
    Mips_SUBSUU_S_W	= 2902,
    Mips_SUBS_S_B	= 2903,
    Mips_SUBS_S_D	= 2904,
    Mips_SUBS_S_H	= 2905,
    Mips_SUBS_S_W	= 2906,
    Mips_SUBS_U_B	= 2907,
    Mips_SUBS_U_D	= 2908,
    Mips_SUBS_U_H	= 2909,
    Mips_SUBS_U_W	= 2910,
    Mips_SUBU16_MM	= 2911,
    Mips_SUBU16_MMR6	= 2912,
    Mips_SUBUH_QB	= 2913,
    Mips_SUBUH_QB_MMR2	= 2914,
    Mips_SUBUH_R_QB	= 2915,
    Mips_SUBUH_R_QB_MMR2	= 2916,
    Mips_SUBU_MMR6	= 2917,
    Mips_SUBU_PH	= 2918,
    Mips_SUBU_PH_MMR2	= 2919,
    Mips_SUBU_QB	= 2920,
    Mips_SUBU_QB_MM	= 2921,
    Mips_SUBU_S_PH	= 2922,
    Mips_SUBU_S_PH_MMR2	= 2923,
    Mips_SUBU_S_QB	= 2924,
    Mips_SUBU_S_QB_MM	= 2925,
    Mips_SUBVI_B	= 2926,
    Mips_SUBVI_D	= 2927,
    Mips_SUBVI_H	= 2928,
    Mips_SUBVI_W	= 2929,
    Mips_SUBV_B	= 2930,
    Mips_SUBV_D	= 2931,
    Mips_SUBV_H	= 2932,
    Mips_SUBV_W	= 2933,
    Mips_SUB_MM	= 2934,
    Mips_SUB_MMR6	= 2935,
    Mips_SUB_NM	= 2936,
    Mips_SUBu	= 2937,
    Mips_SUBu16_NM	= 2938,
    Mips_SUBu_MM	= 2939,
    Mips_SUBu_NM	= 2940,
    Mips_SUXC1	= 2941,
    Mips_SUXC164	= 2942,
    Mips_SUXC1_MM	= 2943,
    Mips_SW	= 2944,
    Mips_SW16_MM	= 2945,
    Mips_SW16_MMR6	= 2946,
    Mips_SW16_NM	= 2947,
    Mips_SW4x4_NM	= 2948,
    Mips_SW64	= 2949,
    Mips_SWC1	= 2950,
    Mips_SWC1_MM	= 2951,
    Mips_SWC2	= 2952,
    Mips_SWC2_MMR6	= 2953,
    Mips_SWC2_R6	= 2954,
    Mips_SWC3	= 2955,
    Mips_SWDSP	= 2956,
    Mips_SWDSP_MM	= 2957,
    Mips_SWE	= 2958,
    Mips_SWE_MM	= 2959,
    Mips_SWGP16_NM	= 2960,
    Mips_SWGP_NM	= 2961,
    Mips_SWL	= 2962,
    Mips_SWL64	= 2963,
    Mips_SWLE	= 2964,
    Mips_SWLE_MM	= 2965,
    Mips_SWL_MM	= 2966,
    Mips_SWM16_MM	= 2967,
    Mips_SWM16_MMR6	= 2968,
    Mips_SWM32_MM	= 2969,
    Mips_SWM_NM	= 2970,
    Mips_SWPC_NM	= 2971,
    Mips_SWP_MM	= 2972,
    Mips_SWR	= 2973,
    Mips_SWR64	= 2974,
    Mips_SWRE	= 2975,
    Mips_SWRE_MM	= 2976,
    Mips_SWR_MM	= 2977,
    Mips_SWSP16_NM	= 2978,
    Mips_SWSP_MM	= 2979,
    Mips_SWSP_MMR6	= 2980,
    Mips_SWXC1	= 2981,
    Mips_SWXC1_MM	= 2982,
    Mips_SWXS_NM	= 2983,
    Mips_SWX_NM	= 2984,
    Mips_SW_MM	= 2985,
    Mips_SW_MMR6	= 2986,
    Mips_SW_NM	= 2987,
    Mips_SWs9_NM	= 2988,
    Mips_SYNC	= 2989,
    Mips_SYNCI	= 2990,
    Mips_SYNCI_MM	= 2991,
    Mips_SYNCI_MMR6	= 2992,
    Mips_SYNCI_NM	= 2993,
    Mips_SYNCIs9_NM	= 2994,
    Mips_SYNC_MM	= 2995,
    Mips_SYNC_MMR6	= 2996,
    Mips_SYNC_NM	= 2997,
    Mips_SYSCALL	= 2998,
    Mips_SYSCALL16_NM	= 2999,
    Mips_SYSCALL_MM	= 3000,
    Mips_SYSCALL_NM	= 3001,
    Mips_Save16	= 3002,
    Mips_SaveX16	= 3003,
    Mips_SbRxRyOffMemX16	= 3004,
    Mips_SebRx16	= 3005,
    Mips_SehRx16	= 3006,
    Mips_ShRxRyOffMemX16	= 3007,
    Mips_SllX16	= 3008,
    Mips_SllvRxRy16	= 3009,
    Mips_SltRxRy16	= 3010,
    Mips_SltiRxImm16	= 3011,
    Mips_SltiRxImmX16	= 3012,
    Mips_SltiuRxImm16	= 3013,
    Mips_SltiuRxImmX16	= 3014,
    Mips_SltuRxRy16	= 3015,
    Mips_SraX16	= 3016,
    Mips_SravRxRy16	= 3017,
    Mips_SrlX16	= 3018,
    Mips_SrlvRxRy16	= 3019,
    Mips_SubuRxRyRz16	= 3020,
    Mips_SwRxRyOffMemX16	= 3021,
    Mips_SwRxSpImmX16	= 3022,
    Mips_TEQ	= 3023,
    Mips_TEQI	= 3024,
    Mips_TEQI_MM	= 3025,
    Mips_TEQ_MM	= 3026,
    Mips_TEQ_NM	= 3027,
    Mips_TGE	= 3028,
    Mips_TGEI	= 3029,
    Mips_TGEIU	= 3030,
    Mips_TGEIU_MM	= 3031,
    Mips_TGEI_MM	= 3032,
    Mips_TGEU	= 3033,
    Mips_TGEU_MM	= 3034,
    Mips_TGE_MM	= 3035,
    Mips_TLBGINV	= 3036,
    Mips_TLBGINVF	= 3037,
    Mips_TLBGINVF_MM	= 3038,
    Mips_TLBGINV_MM	= 3039,
    Mips_TLBGP	= 3040,
    Mips_TLBGP_MM	= 3041,
    Mips_TLBGR	= 3042,
    Mips_TLBGR_MM	= 3043,
    Mips_TLBGWI	= 3044,
    Mips_TLBGWI_MM	= 3045,
    Mips_TLBGWR	= 3046,
    Mips_TLBGWR_MM	= 3047,
    Mips_TLBINV	= 3048,
    Mips_TLBINVF	= 3049,
    Mips_TLBINVF_MMR6	= 3050,
    Mips_TLBINVF_NM	= 3051,
    Mips_TLBINV_MMR6	= 3052,
    Mips_TLBINV_NM	= 3053,
    Mips_TLBP	= 3054,
    Mips_TLBP_MM	= 3055,
    Mips_TLBP_NM	= 3056,
    Mips_TLBR	= 3057,
    Mips_TLBR_MM	= 3058,
    Mips_TLBR_NM	= 3059,
    Mips_TLBWI	= 3060,
    Mips_TLBWI_MM	= 3061,
    Mips_TLBWI_NM	= 3062,
    Mips_TLBWR	= 3063,
    Mips_TLBWR_MM	= 3064,
    Mips_TLBWR_NM	= 3065,
    Mips_TLT	= 3066,
    Mips_TLTI	= 3067,
    Mips_TLTIU_MM	= 3068,
    Mips_TLTI_MM	= 3069,
    Mips_TLTU	= 3070,
    Mips_TLTU_MM	= 3071,
    Mips_TLT_MM	= 3072,
    Mips_TNE	= 3073,
    Mips_TNEI	= 3074,
    Mips_TNEI_MM	= 3075,
    Mips_TNE_MM	= 3076,
    Mips_TNE_NM	= 3077,
    Mips_TRUNC_L_D64	= 3078,
    Mips_TRUNC_L_D_MMR6	= 3079,
    Mips_TRUNC_L_S	= 3080,
    Mips_TRUNC_L_S_MMR6	= 3081,
    Mips_TRUNC_W_D32	= 3082,
    Mips_TRUNC_W_D64	= 3083,
    Mips_TRUNC_W_D_MMR6	= 3084,
    Mips_TRUNC_W_MM	= 3085,
    Mips_TRUNC_W_S	= 3086,
    Mips_TRUNC_W_S_MM	= 3087,
    Mips_TRUNC_W_S_MMR6	= 3088,
    Mips_TTLTIU	= 3089,
    Mips_UALH_NM	= 3090,
    Mips_UALWM_NM	= 3091,
    Mips_UALW_NM	= 3092,
    Mips_UASH_NM	= 3093,
    Mips_UASWM_NM	= 3094,
    Mips_UASW_NM	= 3095,
    Mips_UDIV	= 3096,
    Mips_UDIV_MM	= 3097,
    Mips_V3MULU	= 3098,
    Mips_VMM0	= 3099,
    Mips_VMULU	= 3100,
    Mips_VSHF_B	= 3101,
    Mips_VSHF_D	= 3102,
    Mips_VSHF_H	= 3103,
    Mips_VSHF_W	= 3104,
    Mips_WAIT	= 3105,
    Mips_WAIT_MM	= 3106,
    Mips_WAIT_MMR6	= 3107,
    Mips_WAIT_NM	= 3108,
    Mips_WRDSP	= 3109,
    Mips_WRDSP_MM	= 3110,
    Mips_WRPGPR_MMR6	= 3111,
    Mips_WRPGPR_NM	= 3112,
    Mips_WSBH	= 3113,
    Mips_WSBH_MM	= 3114,
    Mips_WSBH_MMR6	= 3115,
    Mips_XOR	= 3116,
    Mips_XOR16_MM	= 3117,
    Mips_XOR16_MMR6	= 3118,
    Mips_XOR16_NM	= 3119,
    Mips_XOR64	= 3120,
    Mips_XORI_B	= 3121,
    Mips_XORI_MMR6	= 3122,
    Mips_XORI_NM	= 3123,
    Mips_XOR_MM	= 3124,
    Mips_XOR_MMR6	= 3125,
    Mips_XOR_NM	= 3126,
    Mips_XOR_V	= 3127,
    Mips_XORi	= 3128,
    Mips_XORi64	= 3129,
    Mips_XORi_MM	= 3130,
    Mips_XorRxRxRy16	= 3131,
    Mips_YIELD	= 3132,
    Mips_YIELD_NM	= 3133,
    INSTRUCTION_LIST_END = 3134
  };

#endif // GET_INSTRINFO_ENUM

#if defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)
typedef struct MipsInstrTable {
  MCInstrDesc Insts[3134];
  MCOperandInfo OperandInfo[1301];
  MCPhysReg ImplicitOps[70];
} MipsInstrTable;

#endif // defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

#ifdef GET_INSTRINFO_MC_DESC
#undef GET_INSTRINFO_MC_DESC

static const unsigned MipsImpOpBase = sizeof(MCOperandInfo) / (sizeof(MCPhysReg));

static const MipsInstrTable MipsDescs = {
  {
  { 2, &MipsDescs.OperandInfo[416] },  // Inst #3133 = YIELD_NM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #3132 = YIELD
  { 3, &MipsDescs.OperandInfo[626] },  // Inst #3131 = XorRxRxRy16
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #3130 = XORi_MM
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #3129 = XORi64
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #3128 = XORi
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #3127 = XOR_V
  { 3, &MipsDescs.OperandInfo[596] },  // Inst #3126 = XOR_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #3125 = XOR_MMR6
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #3124 = XOR_MM
  { 3, &MipsDescs.OperandInfo[391] },  // Inst #3123 = XORI_NM
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #3122 = XORI_MMR6
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #3121 = XORI_B
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #3120 = XOR64
  { 3, &MipsDescs.OperandInfo[599] },  // Inst #3119 = XOR16_NM
  { 3, &MipsDescs.OperandInfo[611] },  // Inst #3118 = XOR16_MMR6
  { 3, &MipsDescs.OperandInfo[611] },  // Inst #3117 = XOR16_MM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #3116 = XOR
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #3115 = WSBH_MMR6
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #3114 = WSBH_MM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #3113 = WSBH
  { 2, &MipsDescs.OperandInfo[416] },  // Inst #3112 = WRPGPR_NM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #3111 = WRPGPR_MMR6
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #3110 = WRDSP_MM
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #3109 = WRDSP
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #3108 = WAIT_NM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #3107 = WAIT_MMR6
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #3106 = WAIT_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3105 = WAIT
  { 4, &MipsDescs.OperandInfo[194] },  // Inst #3104 = VSHF_W
  { 4, &MipsDescs.OperandInfo[198] },  // Inst #3103 = VSHF_H
  { 4, &MipsDescs.OperandInfo[190] },  // Inst #3102 = VSHF_D
  { 4, &MipsDescs.OperandInfo[672] },  // Inst #3101 = VSHF_B
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #3100 = VMULU
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #3099 = VMM0
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #3098 = V3MULU
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #3097 = UDIV_MM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #3096 = UDIV
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #3095 = UASW_NM
  { 4, &MipsDescs.OperandInfo[1010] },  // Inst #3094 = UASWM_NM
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #3093 = UASH_NM
  { 4, &MipsDescs.OperandInfo[1297] },  // Inst #3092 = UALW_NM
  { 4, &MipsDescs.OperandInfo[1010] },  // Inst #3091 = UALWM_NM
  { 4, &MipsDescs.OperandInfo[1297] },  // Inst #3090 = UALH_NM
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #3089 = TTLTIU
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #3088 = TRUNC_W_S_MMR6
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #3087 = TRUNC_W_S_MM
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #3086 = TRUNC_W_S
  { 2, &MipsDescs.OperandInfo[695] },  // Inst #3085 = TRUNC_W_MM
  { 2, &MipsDescs.OperandInfo[697] },  // Inst #3084 = TRUNC_W_D_MMR6
  { 2, &MipsDescs.OperandInfo[697] },  // Inst #3083 = TRUNC_W_D64
  { 2, &MipsDescs.OperandInfo[695] },  // Inst #3082 = TRUNC_W_D32
  { 2, &MipsDescs.OperandInfo[693] },  // Inst #3081 = TRUNC_L_S_MMR6
  { 2, &MipsDescs.OperandInfo[693] },  // Inst #3080 = TRUNC_L_S
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #3079 = TRUNC_L_D_MMR6
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #3078 = TRUNC_L_D64
  { 3, &MipsDescs.OperandInfo[391] },  // Inst #3077 = TNE_NM
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #3076 = TNE_MM
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #3075 = TNEI_MM
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #3074 = TNEI
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #3073 = TNE
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #3072 = TLT_MM
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #3071 = TLTU_MM
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #3070 = TLTU
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #3069 = TLTI_MM
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #3068 = TLTIU_MM
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #3067 = TLTI
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #3066 = TLT
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3065 = TLBWR_NM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3064 = TLBWR_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3063 = TLBWR
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3062 = TLBWI_NM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3061 = TLBWI_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3060 = TLBWI
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3059 = TLBR_NM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3058 = TLBR_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3057 = TLBR
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3056 = TLBP_NM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3055 = TLBP_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3054 = TLBP
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3053 = TLBINV_NM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3052 = TLBINV_MMR6
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3051 = TLBINVF_NM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3050 = TLBINVF_MMR6
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3049 = TLBINVF
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3048 = TLBINV
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3047 = TLBGWR_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3046 = TLBGWR
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3045 = TLBGWI_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3044 = TLBGWI
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3043 = TLBGR_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3042 = TLBGR
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3041 = TLBGP_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3040 = TLBGP
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3039 = TLBGINV_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3038 = TLBGINVF_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3037 = TLBGINVF
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3036 = TLBGINV
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #3035 = TGE_MM
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #3034 = TGEU_MM
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #3033 = TGEU
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #3032 = TGEI_MM
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #3031 = TGEIU_MM
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #3030 = TGEIU
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #3029 = TGEI
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #3028 = TGE
  { 3, &MipsDescs.OperandInfo[391] },  // Inst #3027 = TEQ_NM
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #3026 = TEQ_MM
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #3025 = TEQI_MM
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #3024 = TEQI
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #3023 = TEQ
  { 3, &MipsDescs.OperandInfo[623] },  // Inst #3022 = SwRxSpImmX16
  { 3, &MipsDescs.OperandInfo[1027] },  // Inst #3021 = SwRxRyOffMemX16
  { 3, &MipsDescs.OperandInfo[421] },  // Inst #3020 = SubuRxRyRz16
  { 3, &MipsDescs.OperandInfo[626] },  // Inst #3019 = SrlvRxRy16
  { 3, &MipsDescs.OperandInfo[547] },  // Inst #3018 = SrlX16
  { 3, &MipsDescs.OperandInfo[626] },  // Inst #3017 = SravRxRy16
  { 3, &MipsDescs.OperandInfo[547] },  // Inst #3016 = SraX16
  { 2, &MipsDescs.OperandInfo[419] },  // Inst #3015 = SltuRxRy16
  { 2, &MipsDescs.OperandInfo[618] },  // Inst #3014 = SltiuRxImmX16
  { 2, &MipsDescs.OperandInfo[618] },  // Inst #3013 = SltiuRxImm16
  { 2, &MipsDescs.OperandInfo[618] },  // Inst #3012 = SltiRxImmX16
  { 2, &MipsDescs.OperandInfo[618] },  // Inst #3011 = SltiRxImm16
  { 2, &MipsDescs.OperandInfo[419] },  // Inst #3010 = SltRxRy16
  { 3, &MipsDescs.OperandInfo[626] },  // Inst #3009 = SllvRxRy16
  { 3, &MipsDescs.OperandInfo[547] },  // Inst #3008 = SllX16
  { 3, &MipsDescs.OperandInfo[1027] },  // Inst #3007 = ShRxRyOffMemX16
  { 2, &MipsDescs.OperandInfo[1295] },  // Inst #3006 = SehRx16
  { 2, &MipsDescs.OperandInfo[1295] },  // Inst #3005 = SebRx16
  { 3, &MipsDescs.OperandInfo[1027] },  // Inst #3004 = SbRxRyOffMemX16
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3003 = SaveX16
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #3002 = Save16
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #3001 = SYSCALL_NM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #3000 = SYSCALL_MM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2999 = SYSCALL16_NM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2998 = SYSCALL
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2997 = SYNC_NM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2996 = SYNC_MMR6
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2995 = SYNC_MM
  { 2, &MipsDescs.OperandInfo[1293] },  // Inst #2994 = SYNCIs9_NM
  { 2, &MipsDescs.OperandInfo[1293] },  // Inst #2993 = SYNCI_NM
  { 2, &MipsDescs.OperandInfo[1293] },  // Inst #2992 = SYNCI_MMR6
  { 2, &MipsDescs.OperandInfo[1293] },  // Inst #2991 = SYNCI_MM
  { 2, &MipsDescs.OperandInfo[1293] },  // Inst #2990 = SYNCI
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2989 = SYNC
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #2988 = SWs9_NM
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #2987 = SW_NM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2986 = SW_MMR6
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2985 = SW_MM
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #2984 = SWX_NM
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #2983 = SWXS_NM
  { 3, &MipsDescs.OperandInfo[1024] },  // Inst #2982 = SWXC1_MM
  { 3, &MipsDescs.OperandInfo[1024] },  // Inst #2981 = SWXC1
  { 3, &MipsDescs.OperandInfo[1021] },  // Inst #2980 = SWSP_MMR6
  { 3, &MipsDescs.OperandInfo[1021] },  // Inst #2979 = SWSP_MM
  { 3, &MipsDescs.OperandInfo[1018] },  // Inst #2978 = SWSP16_NM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2977 = SWR_MM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2976 = SWRE_MM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2975 = SWRE
  { 3, &MipsDescs.OperandInfo[361] },  // Inst #2974 = SWR64
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2973 = SWR
  { 4, &MipsDescs.OperandInfo[1014] },  // Inst #2972 = SWP_MM
  { 2, &MipsDescs.OperandInfo[609] },  // Inst #2971 = SWPC_NM
  { 4, &MipsDescs.OperandInfo[1010] },  // Inst #2970 = SWM_NM
  { 3, &MipsDescs.OperandInfo[354] },  // Inst #2969 = SWM32_MM
  { 3, &MipsDescs.OperandInfo[1007] },  // Inst #2968 = SWM16_MMR6
  { 3, &MipsDescs.OperandInfo[1007] },  // Inst #2967 = SWM16_MM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2966 = SWL_MM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2965 = SWLE_MM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2964 = SWLE
  { 3, &MipsDescs.OperandInfo[361] },  // Inst #2963 = SWL64
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2962 = SWL
  { 3, &MipsDescs.OperandInfo[1000] },  // Inst #2961 = SWGP_NM
  { 3, &MipsDescs.OperandInfo[1290] },  // Inst #2960 = SWGP16_NM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2959 = SWE_MM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2958 = SWE
  { 3, &MipsDescs.OperandInfo[991] },  // Inst #2957 = SWDSP_MM
  { 3, &MipsDescs.OperandInfo[991] },  // Inst #2956 = SWDSP
  { 3, &MipsDescs.OperandInfo[940] },  // Inst #2955 = SWC3
  { 3, &MipsDescs.OperandInfo[934] },  // Inst #2954 = SWC2_R6
  { 3, &MipsDescs.OperandInfo[937] },  // Inst #2953 = SWC2_MMR6
  { 3, &MipsDescs.OperandInfo[934] },  // Inst #2952 = SWC2
  { 3, &MipsDescs.OperandInfo[988] },  // Inst #2951 = SWC1_MM
  { 3, &MipsDescs.OperandInfo[988] },  // Inst #2950 = SWC1
  { 3, &MipsDescs.OperandInfo[361] },  // Inst #2949 = SW64
  { 3, &MipsDescs.OperandInfo[1287] },  // Inst #2948 = SW4x4_NM
  { 3, &MipsDescs.OperandInfo[1212] },  // Inst #2947 = SW16_NM
  { 3, &MipsDescs.OperandInfo[1209] },  // Inst #2946 = SW16_MMR6
  { 3, &MipsDescs.OperandInfo[1209] },  // Inst #2945 = SW16_MM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2944 = SW
  { 3, &MipsDescs.OperandInfo[958] },  // Inst #2943 = SUXC1_MM
  { 3, &MipsDescs.OperandInfo[958] },  // Inst #2942 = SUXC164
  { 3, &MipsDescs.OperandInfo[955] },  // Inst #2941 = SUXC1
  { 3, &MipsDescs.OperandInfo[596] },  // Inst #2940 = SUBu_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2939 = SUBu_MM
  { 3, &MipsDescs.OperandInfo[599] },  // Inst #2938 = SUBu16_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2937 = SUBu
  { 3, &MipsDescs.OperandInfo[596] },  // Inst #2936 = SUB_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2935 = SUB_MMR6
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2934 = SUB_MM
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #2933 = SUBV_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #2932 = SUBV_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #2931 = SUBV_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #2930 = SUBV_B
  { 3, &MipsDescs.OperandInfo[593] },  // Inst #2929 = SUBVI_W
  { 3, &MipsDescs.OperandInfo[590] },  // Inst #2928 = SUBVI_H
  { 3, &MipsDescs.OperandInfo[587] },  // Inst #2927 = SUBVI_D
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #2926 = SUBVI_B
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2925 = SUBU_S_QB_MM
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2924 = SUBU_S_QB
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2923 = SUBU_S_PH_MMR2
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2922 = SUBU_S_PH
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2921 = SUBU_QB_MM
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2920 = SUBU_QB
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2919 = SUBU_PH_MMR2
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2918 = SUBU_PH
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2917 = SUBU_MMR6
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2916 = SUBUH_R_QB_MMR2
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2915 = SUBUH_R_QB
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2914 = SUBUH_QB_MMR2
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2913 = SUBUH_QB
  { 3, &MipsDescs.OperandInfo[581] },  // Inst #2912 = SUBU16_MMR6
  { 3, &MipsDescs.OperandInfo[581] },  // Inst #2911 = SUBU16_MM
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #2910 = SUBS_U_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #2909 = SUBS_U_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #2908 = SUBS_U_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #2907 = SUBS_U_B
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #2906 = SUBS_S_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #2905 = SUBS_S_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #2904 = SUBS_S_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #2903 = SUBS_S_B
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #2902 = SUBSUU_S_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #2901 = SUBSUU_S_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #2900 = SUBSUU_S_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #2899 = SUBSUU_S_B
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #2898 = SUBSUS_U_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #2897 = SUBSUS_U_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #2896 = SUBSUS_U_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #2895 = SUBSUS_U_B
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2894 = SUBQ_S_W_MM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2893 = SUBQ_S_W
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2892 = SUBQ_S_PH_MM
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2891 = SUBQ_S_PH
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2890 = SUBQ_PH_MM
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2889 = SUBQ_PH
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2888 = SUBQH_W_MMR2
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2887 = SUBQH_W
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2886 = SUBQH_R_W_MMR2
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2885 = SUBQH_R_W
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2884 = SUBQH_R_PH_MMR2
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2883 = SUBQH_R_PH
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2882 = SUBQH_PH_MMR2
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2881 = SUBQH_PH
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2880 = SUB
  { 3, &MipsDescs.OperandInfo[970] },  // Inst #2879 = ST_W
  { 3, &MipsDescs.OperandInfo[967] },  // Inst #2878 = ST_H
  { 3, &MipsDescs.OperandInfo[964] },  // Inst #2877 = ST_D
  { 3, &MipsDescs.OperandInfo[961] },  // Inst #2876 = ST_B
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2875 = SSNOP_MMR6
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2874 = SSNOP_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2873 = SSNOP
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #2872 = SRL_W
  { 3, &MipsDescs.OperandInfo[391] },  // Inst #2871 = SRL_NM
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #2870 = SRL_MM
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #2869 = SRL_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #2868 = SRL_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #2867 = SRL_B
  { 3, &MipsDescs.OperandInfo[596] },  // Inst #2866 = SRLV_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2865 = SRLV_MM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2864 = SRLV
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #2863 = SRLR_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #2862 = SRLR_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #2861 = SRLR_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #2860 = SRLR_B
  { 3, &MipsDescs.OperandInfo[593] },  // Inst #2859 = SRLRI_W
  { 3, &MipsDescs.OperandInfo[590] },  // Inst #2858 = SRLRI_H
  { 3, &MipsDescs.OperandInfo[587] },  // Inst #2857 = SRLRI_D
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #2856 = SRLRI_B
  { 3, &MipsDescs.OperandInfo[593] },  // Inst #2855 = SRLI_W
  { 3, &MipsDescs.OperandInfo[590] },  // Inst #2854 = SRLI_H
  { 3, &MipsDescs.OperandInfo[587] },  // Inst #2853 = SRLI_D
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #2852 = SRLI_B
  { 3, &MipsDescs.OperandInfo[566] },  // Inst #2851 = SRL16_NM
  { 3, &MipsDescs.OperandInfo[563] },  // Inst #2850 = SRL16_MMR6
  { 3, &MipsDescs.OperandInfo[563] },  // Inst #2849 = SRL16_MM
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #2848 = SRL
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #2847 = SRA_W
  { 3, &MipsDescs.OperandInfo[391] },  // Inst #2846 = SRA_NM
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #2845 = SRA_MM
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #2844 = SRA_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #2843 = SRA_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #2842 = SRA_B
  { 3, &MipsDescs.OperandInfo[596] },  // Inst #2841 = SRAV_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2840 = SRAV_MM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2839 = SRAV
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #2838 = SRAR_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #2837 = SRAR_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #2836 = SRAR_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #2835 = SRAR_B
  { 3, &MipsDescs.OperandInfo[593] },  // Inst #2834 = SRARI_W
  { 3, &MipsDescs.OperandInfo[590] },  // Inst #2833 = SRARI_H
  { 3, &MipsDescs.OperandInfo[587] },  // Inst #2832 = SRARI_D
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #2831 = SRARI_B
  { 3, &MipsDescs.OperandInfo[593] },  // Inst #2830 = SRAI_W
  { 3, &MipsDescs.OperandInfo[590] },  // Inst #2829 = SRAI_H
  { 3, &MipsDescs.OperandInfo[587] },  // Inst #2828 = SRAI_D
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #2827 = SRAI_B
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #2826 = SRA
  { 3, &MipsDescs.OperandInfo[1284] },  // Inst #2825 = SPLAT_W
  { 3, &MipsDescs.OperandInfo[1281] },  // Inst #2824 = SPLAT_H
  { 3, &MipsDescs.OperandInfo[1278] },  // Inst #2823 = SPLAT_D
  { 3, &MipsDescs.OperandInfo[1275] },  // Inst #2822 = SPLAT_B
  { 3, &MipsDescs.OperandInfo[593] },  // Inst #2821 = SPLATI_W
  { 3, &MipsDescs.OperandInfo[590] },  // Inst #2820 = SPLATI_H
  { 3, &MipsDescs.OperandInfo[587] },  // Inst #2819 = SPLATI_D
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #2818 = SPLATI_B
  { 3, &MipsDescs.OperandInfo[596] },  // Inst #2817 = SOV_NM
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #2816 = SNEi
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #2815 = SNE
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2814 = SLTu_MM
  { 3, &MipsDescs.OperandInfo[1269] },  // Inst #2813 = SLTu64
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2812 = SLTu
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #2811 = SLTiu_MM
  { 3, &MipsDescs.OperandInfo[1272] },  // Inst #2810 = SLTiu64
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #2809 = SLTiu
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #2808 = SLTi_MM
  { 3, &MipsDescs.OperandInfo[1272] },  // Inst #2807 = SLTi64
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #2806 = SLTi
  { 3, &MipsDescs.OperandInfo[596] },  // Inst #2805 = SLT_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2804 = SLT_MM
  { 3, &MipsDescs.OperandInfo[596] },  // Inst #2803 = SLTU_NM
  { 3, &MipsDescs.OperandInfo[391] },  // Inst #2802 = SLTI_NM
  { 3, &MipsDescs.OperandInfo[391] },  // Inst #2801 = SLTIU_NM
  { 3, &MipsDescs.OperandInfo[1269] },  // Inst #2800 = SLT64
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2799 = SLT
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #2798 = SLL_W
  { 3, &MipsDescs.OperandInfo[391] },  // Inst #2797 = SLL_NM
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #2796 = SLL_MMR6
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #2795 = SLL_MM
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #2794 = SLL_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #2793 = SLL_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #2792 = SLL_B
  { 3, &MipsDescs.OperandInfo[596] },  // Inst #2791 = SLLV_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2790 = SLLV_MM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2789 = SLLV
  { 3, &MipsDescs.OperandInfo[593] },  // Inst #2788 = SLLI_W
  { 3, &MipsDescs.OperandInfo[590] },  // Inst #2787 = SLLI_H
  { 3, &MipsDescs.OperandInfo[587] },  // Inst #2786 = SLLI_D
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #2785 = SLLI_B
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #2784 = SLL64_64
  { 2, &MipsDescs.OperandInfo[817] },  // Inst #2783 = SLL64_32
  { 3, &MipsDescs.OperandInfo[566] },  // Inst #2782 = SLL16_NM
  { 3, &MipsDescs.OperandInfo[563] },  // Inst #2781 = SLL16_MMR6
  { 3, &MipsDescs.OperandInfo[563] },  // Inst #2780 = SLL16_MM
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #2779 = SLL
  { 4, &MipsDescs.OperandInfo[1265] },  // Inst #2778 = SLD_W
  { 4, &MipsDescs.OperandInfo[1261] },  // Inst #2777 = SLD_H
  { 4, &MipsDescs.OperandInfo[1257] },  // Inst #2776 = SLD_D
  { 4, &MipsDescs.OperandInfo[1253] },  // Inst #2775 = SLD_B
  { 4, &MipsDescs.OperandInfo[668] },  // Inst #2774 = SLDI_W
  { 4, &MipsDescs.OperandInfo[664] },  // Inst #2773 = SLDI_H
  { 4, &MipsDescs.OperandInfo[660] },  // Inst #2772 = SLDI_D
  { 4, &MipsDescs.OperandInfo[656] },  // Inst #2771 = SLDI_B
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2770 = SIGRIE_NM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2769 = SIGRIE_MMR6
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2768 = SIGRIE
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #2767 = SHs9_NM
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #2766 = SH_NM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2765 = SH_MMR6
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2764 = SH_MM
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #2763 = SHX_NM
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #2762 = SHXS_NM
  { 3, &MipsDescs.OperandInfo[1250] },  // Inst #2761 = SHRL_QB_MM
  { 3, &MipsDescs.OperandInfo[1250] },  // Inst #2760 = SHRL_QB
  { 3, &MipsDescs.OperandInfo[1250] },  // Inst #2759 = SHRL_PH_MMR2
  { 3, &MipsDescs.OperandInfo[1250] },  // Inst #2758 = SHRL_PH
  { 3, &MipsDescs.OperandInfo[1247] },  // Inst #2757 = SHRLV_QB_MM
  { 3, &MipsDescs.OperandInfo[1247] },  // Inst #2756 = SHRLV_QB
  { 3, &MipsDescs.OperandInfo[1247] },  // Inst #2755 = SHRLV_PH_MMR2
  { 3, &MipsDescs.OperandInfo[1247] },  // Inst #2754 = SHRLV_PH
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #2753 = SHRA_R_W_MM
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #2752 = SHRA_R_W
  { 3, &MipsDescs.OperandInfo[1250] },  // Inst #2751 = SHRA_R_QB_MMR2
  { 3, &MipsDescs.OperandInfo[1250] },  // Inst #2750 = SHRA_R_QB
  { 3, &MipsDescs.OperandInfo[1250] },  // Inst #2749 = SHRA_R_PH_MM
  { 3, &MipsDescs.OperandInfo[1250] },  // Inst #2748 = SHRA_R_PH
  { 3, &MipsDescs.OperandInfo[1250] },  // Inst #2747 = SHRA_QB_MMR2
  { 3, &MipsDescs.OperandInfo[1250] },  // Inst #2746 = SHRA_QB
  { 3, &MipsDescs.OperandInfo[1250] },  // Inst #2745 = SHRA_PH_MM
  { 3, &MipsDescs.OperandInfo[1250] },  // Inst #2744 = SHRA_PH
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2743 = SHRAV_R_W_MM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2742 = SHRAV_R_W
  { 3, &MipsDescs.OperandInfo[1247] },  // Inst #2741 = SHRAV_R_QB_MMR2
  { 3, &MipsDescs.OperandInfo[1247] },  // Inst #2740 = SHRAV_R_QB
  { 3, &MipsDescs.OperandInfo[1247] },  // Inst #2739 = SHRAV_R_PH_MM
  { 3, &MipsDescs.OperandInfo[1247] },  // Inst #2738 = SHRAV_R_PH
  { 3, &MipsDescs.OperandInfo[1247] },  // Inst #2737 = SHRAV_QB_MMR2
  { 3, &MipsDescs.OperandInfo[1247] },  // Inst #2736 = SHRAV_QB
  { 3, &MipsDescs.OperandInfo[1247] },  // Inst #2735 = SHRAV_PH_MM
  { 3, &MipsDescs.OperandInfo[1247] },  // Inst #2734 = SHRAV_PH
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #2733 = SHLL_S_W_MM
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #2732 = SHLL_S_W
  { 3, &MipsDescs.OperandInfo[1250] },  // Inst #2731 = SHLL_S_PH_MM
  { 3, &MipsDescs.OperandInfo[1250] },  // Inst #2730 = SHLL_S_PH
  { 3, &MipsDescs.OperandInfo[1250] },  // Inst #2729 = SHLL_QB_MM
  { 3, &MipsDescs.OperandInfo[1250] },  // Inst #2728 = SHLL_QB
  { 3, &MipsDescs.OperandInfo[1250] },  // Inst #2727 = SHLL_PH_MM
  { 3, &MipsDescs.OperandInfo[1250] },  // Inst #2726 = SHLL_PH
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2725 = SHLLV_S_W_MM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2724 = SHLLV_S_W
  { 3, &MipsDescs.OperandInfo[1247] },  // Inst #2723 = SHLLV_S_PH_MM
  { 3, &MipsDescs.OperandInfo[1247] },  // Inst #2722 = SHLLV_S_PH
  { 3, &MipsDescs.OperandInfo[1247] },  // Inst #2721 = SHLLV_QB_MM
  { 3, &MipsDescs.OperandInfo[1247] },  // Inst #2720 = SHLLV_QB
  { 3, &MipsDescs.OperandInfo[1247] },  // Inst #2719 = SHLLV_PH_MM
  { 3, &MipsDescs.OperandInfo[1247] },  // Inst #2718 = SHLLV_PH
  { 3, &MipsDescs.OperandInfo[1244] },  // Inst #2717 = SHILO_MM
  { 3, &MipsDescs.OperandInfo[1160] },  // Inst #2716 = SHILOV_MM
  { 3, &MipsDescs.OperandInfo[1160] },  // Inst #2715 = SHILOV
  { 3, &MipsDescs.OperandInfo[1244] },  // Inst #2714 = SHILO
  { 3, &MipsDescs.OperandInfo[919] },  // Inst #2713 = SHGP_NM
  { 3, &MipsDescs.OperandInfo[593] },  // Inst #2712 = SHF_W
  { 3, &MipsDescs.OperandInfo[590] },  // Inst #2711 = SHF_H
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #2710 = SHF_B
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2709 = SHE_MM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2708 = SHE
  { 3, &MipsDescs.OperandInfo[361] },  // Inst #2707 = SH64
  { 3, &MipsDescs.OperandInfo[1212] },  // Inst #2706 = SH16_NM
  { 3, &MipsDescs.OperandInfo[1209] },  // Inst #2705 = SH16_MMR6
  { 3, &MipsDescs.OperandInfo[1209] },  // Inst #2704 = SH16_MM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2703 = SH
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #2702 = SEQi
  { 3, &MipsDescs.OperandInfo[391] },  // Inst #2701 = SEQI_NM
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #2700 = SEQ
  { 4, &MipsDescs.OperandInfo[1240] },  // Inst #2699 = SEL_S_MMR6
  { 4, &MipsDescs.OperandInfo[1240] },  // Inst #2698 = SEL_S
  { 4, &MipsDescs.OperandInfo[1033] },  // Inst #2697 = SEL_D_MMR6
  { 4, &MipsDescs.OperandInfo[1033] },  // Inst #2696 = SEL_D
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #2695 = SELNEZ_S_MMR6
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #2694 = SELNEZ_S
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2693 = SELNEZ_MMR6
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #2692 = SELNEZ_D_MMR6
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #2691 = SELNEZ_D
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #2690 = SELNEZ64
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2689 = SELNEZ
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #2688 = SELEQZ_S_MMR6
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #2687 = SELEQZ_S
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2686 = SELEQZ_MMR6
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #2685 = SELEQZ_D_MMR6
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #2684 = SELEQZ_D
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #2683 = SELEQZ64
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2682 = SELEQZ
  { 2, &MipsDescs.OperandInfo[416] },  // Inst #2681 = SEH_NM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2680 = SEH_MM
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #2679 = SEH64
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2678 = SEH
  { 2, &MipsDescs.OperandInfo[416] },  // Inst #2677 = SEB_NM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2676 = SEB_MM
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #2675 = SEB64
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2674 = SEB
  { 3, &MipsDescs.OperandInfo[958] },  // Inst #2673 = SDXC164
  { 3, &MipsDescs.OperandInfo[955] },  // Inst #2672 = SDXC1
  { 3, &MipsDescs.OperandInfo[361] },  // Inst #2671 = SDR
  { 3, &MipsDescs.OperandInfo[361] },  // Inst #2670 = SDL
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2669 = SDIV_MM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2668 = SDIV
  { 3, &MipsDescs.OperandInfo[940] },  // Inst #2667 = SDC3
  { 3, &MipsDescs.OperandInfo[934] },  // Inst #2666 = SDC2_R6
  { 3, &MipsDescs.OperandInfo[937] },  // Inst #2665 = SDC2_MMR6
  { 3, &MipsDescs.OperandInfo[934] },  // Inst #2664 = SDC2
  { 3, &MipsDescs.OperandInfo[931] },  // Inst #2663 = SDC1_MM_D64
  { 3, &MipsDescs.OperandInfo[519] },  // Inst #2662 = SDC1_MM_D32
  { 3, &MipsDescs.OperandInfo[931] },  // Inst #2661 = SDC1_D64_MMR6
  { 3, &MipsDescs.OperandInfo[931] },  // Inst #2660 = SDC164
  { 3, &MipsDescs.OperandInfo[519] },  // Inst #2659 = SDC1
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2658 = SDBBP_R6
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2657 = SDBBP_NM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2656 = SDBBP_MMR6
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2655 = SDBBP_MM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2654 = SDBBP16_NM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2653 = SDBBP16_MMR6
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2652 = SDBBP16_MM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #2651 = SDBBP
  { 3, &MipsDescs.OperandInfo[361] },  // Inst #2650 = SD
  { 4, &MipsDescs.OperandInfo[1219] },  // Inst #2649 = SC_R6
  { 4, &MipsDescs.OperandInfo[1236] },  // Inst #2648 = SC_NM
  { 4, &MipsDescs.OperandInfo[1215] },  // Inst #2647 = SC_MMR6
  { 4, &MipsDescs.OperandInfo[1215] },  // Inst #2646 = SC_MM
  { 5, &MipsDescs.OperandInfo[1231] },  // Inst #2645 = SCWP_NM
  { 4, &MipsDescs.OperandInfo[1215] },  // Inst #2644 = SCE_MM
  { 4, &MipsDescs.OperandInfo[1215] },  // Inst #2643 = SCE
  { 4, &MipsDescs.OperandInfo[1227] },  // Inst #2642 = SCD_R6
  { 4, &MipsDescs.OperandInfo[1223] },  // Inst #2641 = SCD
  { 4, &MipsDescs.OperandInfo[1219] },  // Inst #2640 = SC64_R6
  { 4, &MipsDescs.OperandInfo[1215] },  // Inst #2639 = SC64
  { 4, &MipsDescs.OperandInfo[1215] },  // Inst #2638 = SC
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #2637 = SBs9_NM
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #2636 = SB_NM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2635 = SB_MMR6
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2634 = SB_MM
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #2633 = SBX_NM
  { 3, &MipsDescs.OperandInfo[919] },  // Inst #2632 = SBGP_NM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2631 = SBE_MM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2630 = SBE
  { 3, &MipsDescs.OperandInfo[361] },  // Inst #2629 = SB64
  { 3, &MipsDescs.OperandInfo[1212] },  // Inst #2628 = SB16_NM
  { 3, &MipsDescs.OperandInfo[1209] },  // Inst #2627 = SB16_MMR6
  { 3, &MipsDescs.OperandInfo[1209] },  // Inst #2626 = SB16_MM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2625 = SB
  { 2, &MipsDescs.OperandInfo[1202] },  // Inst #2624 = SAVE_NM
  { 2, &MipsDescs.OperandInfo[1202] },  // Inst #2623 = SAVE16_NM
  { 3, &MipsDescs.OperandInfo[593] },  // Inst #2622 = SAT_U_W
  { 3, &MipsDescs.OperandInfo[590] },  // Inst #2621 = SAT_U_H
  { 3, &MipsDescs.OperandInfo[587] },  // Inst #2620 = SAT_U_D
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #2619 = SAT_U_B
  { 3, &MipsDescs.OperandInfo[593] },  // Inst #2618 = SAT_S_W
  { 3, &MipsDescs.OperandInfo[590] },  // Inst #2617 = SAT_S_H
  { 3, &MipsDescs.OperandInfo[587] },  // Inst #2616 = SAT_S_D
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #2615 = SAT_S_B
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #2614 = SAAD
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #2613 = SAA
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2612 = RestoreX16
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2611 = Restore16
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #2610 = RSQRT_S_MM
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #2609 = RSQRT_S
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #2608 = RSQRT_D64_MM
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #2607 = RSQRT_D64
  { 2, &MipsDescs.OperandInfo[829] },  // Inst #2606 = RSQRT_D32_MM
  { 2, &MipsDescs.OperandInfo[829] },  // Inst #2605 = RSQRT_D32
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #2604 = ROUND_W_S_MMR6
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #2603 = ROUND_W_S_MM
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #2602 = ROUND_W_S
  { 2, &MipsDescs.OperandInfo[695] },  // Inst #2601 = ROUND_W_MM
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #2600 = ROUND_W_D_MMR6
  { 2, &MipsDescs.OperandInfo[697] },  // Inst #2599 = ROUND_W_D64
  { 2, &MipsDescs.OperandInfo[695] },  // Inst #2598 = ROUND_W_D32
  { 2, &MipsDescs.OperandInfo[693] },  // Inst #2597 = ROUND_L_S_MMR6
  { 2, &MipsDescs.OperandInfo[693] },  // Inst #2596 = ROUND_L_S
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #2595 = ROUND_L_D_MMR6
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #2594 = ROUND_L_D64
  { 5, &MipsDescs.OperandInfo[1204] },  // Inst #2593 = ROTX_NM
  { 3, &MipsDescs.OperandInfo[391] },  // Inst #2592 = ROTR_NM
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #2591 = ROTR_MM
  { 3, &MipsDescs.OperandInfo[596] },  // Inst #2590 = ROTRV_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2589 = ROTRV_MM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2588 = ROTRV
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #2587 = ROTR
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #2586 = RINT_S_MMR6
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #2585 = RINT_S
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #2584 = RINT_D_MMR6
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #2583 = RINT_D
  { 2, &MipsDescs.OperandInfo[1202] },  // Inst #2582 = RESTORE_NM
  { 2, &MipsDescs.OperandInfo[1202] },  // Inst #2581 = RESTOREJRC_NM
  { 2, &MipsDescs.OperandInfo[1202] },  // Inst #2580 = RESTOREJRC16_NM
  { 2, &MipsDescs.OperandInfo[1200] },  // Inst #2579 = REPL_QB_MM
  { 2, &MipsDescs.OperandInfo[1200] },  // Inst #2578 = REPL_QB
  { 2, &MipsDescs.OperandInfo[1200] },  // Inst #2577 = REPL_PH_MM
  { 2, &MipsDescs.OperandInfo[1200] },  // Inst #2576 = REPL_PH
  { 2, &MipsDescs.OperandInfo[1198] },  // Inst #2575 = REPLV_QB_MM
  { 2, &MipsDescs.OperandInfo[1198] },  // Inst #2574 = REPLV_QB
  { 2, &MipsDescs.OperandInfo[1198] },  // Inst #2573 = REPLV_PH_MM
  { 2, &MipsDescs.OperandInfo[1198] },  // Inst #2572 = REPLV_PH
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #2571 = RECIP_S_MM
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #2570 = RECIP_S
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #2569 = RECIP_D64_MM
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #2568 = RECIP_D64
  { 2, &MipsDescs.OperandInfo[829] },  // Inst #2567 = RECIP_D32_MM
  { 2, &MipsDescs.OperandInfo[829] },  // Inst #2566 = RECIP_D32
  { 2, &MipsDescs.OperandInfo[416] },  // Inst #2565 = RDPGPR_NM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2564 = RDPGPR_MMR6
  { 3, &MipsDescs.OperandInfo[386] },  // Inst #2563 = RDHWR_NM
  { 3, &MipsDescs.OperandInfo[1192] },  // Inst #2562 = RDHWR_MMR6
  { 3, &MipsDescs.OperandInfo[1192] },  // Inst #2561 = RDHWR_MM
  { 3, &MipsDescs.OperandInfo[1195] },  // Inst #2560 = RDHWR64
  { 3, &MipsDescs.OperandInfo[1192] },  // Inst #2559 = RDHWR
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #2558 = RDDSP_MM
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #2557 = RDDSP
  { 2, &MipsDescs.OperandInfo[1180] },  // Inst #2556 = RADDU_W_QB_MM
  { 2, &MipsDescs.OperandInfo[1180] },  // Inst #2555 = RADDU_W_QB
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #2554 = PUU_PS64
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #2553 = PUL_PS64
  { 4, &MipsDescs.OperandInfo[614] },  // Inst #2552 = PREPEND_MMR2
  { 4, &MipsDescs.OperandInfo[614] },  // Inst #2551 = PREPEND
  { 3, &MipsDescs.OperandInfo[354] },  // Inst #2550 = PREFs9_NM
  { 3, &MipsDescs.OperandInfo[688] },  // Inst #2549 = PREF_R6
  { 3, &MipsDescs.OperandInfo[354] },  // Inst #2548 = PREF_NM
  { 3, &MipsDescs.OperandInfo[688] },  // Inst #2547 = PREF_MMR6
  { 3, &MipsDescs.OperandInfo[688] },  // Inst #2546 = PREF_MM
  { 3, &MipsDescs.OperandInfo[1189] },  // Inst #2545 = PREFX_MM
  { 3, &MipsDescs.OperandInfo[688] },  // Inst #2544 = PREFE_MM
  { 3, &MipsDescs.OperandInfo[688] },  // Inst #2543 = PREFE
  { 3, &MipsDescs.OperandInfo[688] },  // Inst #2542 = PREF
  { 4, &MipsDescs.OperandInfo[1185] },  // Inst #2541 = PRECR_SRA_R_PH_W_MMR2
  { 4, &MipsDescs.OperandInfo[1185] },  // Inst #2540 = PRECR_SRA_R_PH_W
  { 4, &MipsDescs.OperandInfo[1185] },  // Inst #2539 = PRECR_SRA_PH_W_MMR2
  { 4, &MipsDescs.OperandInfo[1185] },  // Inst #2538 = PRECR_SRA_PH_W
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2537 = PRECR_QB_PH_MMR2
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2536 = PRECR_QB_PH
  { 3, &MipsDescs.OperandInfo[1182] },  // Inst #2535 = PRECRQ_RS_PH_W_MM
  { 3, &MipsDescs.OperandInfo[1182] },  // Inst #2534 = PRECRQ_RS_PH_W
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2533 = PRECRQ_QB_PH_MM
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2532 = PRECRQ_QB_PH
  { 3, &MipsDescs.OperandInfo[1182] },  // Inst #2531 = PRECRQ_PH_W_MM
  { 3, &MipsDescs.OperandInfo[1182] },  // Inst #2530 = PRECRQ_PH_W
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2529 = PRECRQU_S_QB_PH_MM
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2528 = PRECRQU_S_QB_PH
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #2527 = PRECEU_PH_QBR_MM
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #2526 = PRECEU_PH_QBRA_MM
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #2525 = PRECEU_PH_QBRA
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #2524 = PRECEU_PH_QBR
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #2523 = PRECEU_PH_QBL_MM
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #2522 = PRECEU_PH_QBLA_MM
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #2521 = PRECEU_PH_QBLA
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #2520 = PRECEU_PH_QBL
  { 2, &MipsDescs.OperandInfo[1180] },  // Inst #2519 = PRECEQ_W_PHR_MM
  { 2, &MipsDescs.OperandInfo[1180] },  // Inst #2518 = PRECEQ_W_PHR
  { 2, &MipsDescs.OperandInfo[1180] },  // Inst #2517 = PRECEQ_W_PHL_MM
  { 2, &MipsDescs.OperandInfo[1180] },  // Inst #2516 = PRECEQ_W_PHL
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #2515 = PRECEQU_PH_QBR_MM
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #2514 = PRECEQU_PH_QBRA_MM
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #2513 = PRECEQU_PH_QBRA
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #2512 = PRECEQU_PH_QBR
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #2511 = PRECEQU_PH_QBL_MM
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #2510 = PRECEQU_PH_QBLA_MM
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #2509 = PRECEQU_PH_QBLA
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #2508 = PRECEQU_PH_QBL
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2507 = POP
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #2506 = PLU_PS64
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #2505 = PLL_PS64
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2504 = PICK_QB_MM
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2503 = PICK_QB
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2502 = PICK_PH_MM
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2501 = PICK_PH
  { 2, &MipsDescs.OperandInfo[244] },  // Inst #2500 = PCNT_W
  { 2, &MipsDescs.OperandInfo[1174] },  // Inst #2499 = PCNT_H
  { 2, &MipsDescs.OperandInfo[242] },  // Inst #2498 = PCNT_D
  { 2, &MipsDescs.OperandInfo[1087] },  // Inst #2497 = PCNT_B
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #2496 = PCKOD_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #2495 = PCKOD_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #2494 = PCKOD_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #2493 = PCKOD_B
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #2492 = PCKEV_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #2491 = PCKEV_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #2490 = PCKEV_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #2489 = PCKEV_B
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2488 = PAUSE_NM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2487 = PAUSE_MMR6
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2486 = PAUSE_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2485 = PAUSE
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2484 = PACKRL_PH_MM
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2483 = PACKRL_PH
  { 3, &MipsDescs.OperandInfo[626] },  // Inst #2482 = OrRxRxRy16
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #2481 = ORi_MM
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #2480 = ORi64
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #2479 = ORi
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #2478 = OR_V
  { 3, &MipsDescs.OperandInfo[596] },  // Inst #2477 = OR_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2476 = OR_MMR6
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2475 = OR_MM
  { 3, &MipsDescs.OperandInfo[391] },  // Inst #2474 = ORI_NM
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #2473 = ORI_MMR6
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #2472 = ORI_B
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #2471 = OR64
  { 3, &MipsDescs.OperandInfo[599] },  // Inst #2470 = OR16_NM
  { 3, &MipsDescs.OperandInfo[611] },  // Inst #2469 = OR16_MMR6
  { 3, &MipsDescs.OperandInfo[611] },  // Inst #2468 = OR16_MM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2467 = OR
  { 2, &MipsDescs.OperandInfo[419] },  // Inst #2466 = NotRxRy16
  { 2, &MipsDescs.OperandInfo[419] },  // Inst #2465 = NegRxRy16
  { 2, &MipsDescs.OperandInfo[1178] },  // Inst #2464 = NOT16_NM
  { 2, &MipsDescs.OperandInfo[1176] },  // Inst #2463 = NOT16_MMR6
  { 2, &MipsDescs.OperandInfo[1176] },  // Inst #2462 = NOT16_MM
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #2461 = NOR_V
  { 3, &MipsDescs.OperandInfo[596] },  // Inst #2460 = NOR_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2459 = NOR_MMR6
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2458 = NOR_MM
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #2457 = NORI_B
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #2456 = NOR64
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2455 = NOR
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2454 = NOP_NM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #2453 = NOP32_NM
  { 4, &MipsDescs.OperandInfo[1049] },  // Inst #2452 = NMSUB_S_MM
  { 4, &MipsDescs.OperandInfo[1049] },  // Inst #2451 = NMSUB_S
  { 4, &MipsDescs.OperandInfo[1045] },  // Inst #2450 = NMSUB_D64
  { 4, &MipsDescs.OperandInfo[1041] },  // Inst #2449 = NMSUB_D32_MM
  { 4, &MipsDescs.OperandInfo[1041] },  // Inst #2448 = NMSUB_D32
  { 4, &MipsDescs.OperandInfo[1049] },  // Inst #2447 = NMADD_S_MM
  { 4, &MipsDescs.OperandInfo[1049] },  // Inst #2446 = NMADD_S
  { 4, &MipsDescs.OperandInfo[1045] },  // Inst #2445 = NMADD_D64
  { 4, &MipsDescs.OperandInfo[1041] },  // Inst #2444 = NMADD_D32_MM
  { 4, &MipsDescs.OperandInfo[1041] },  // Inst #2443 = NMADD_D32
  { 2, &MipsDescs.OperandInfo[244] },  // Inst #2442 = NLZC_W
  { 2, &MipsDescs.OperandInfo[1174] },  // Inst #2441 = NLZC_H
  { 2, &MipsDescs.OperandInfo[242] },  // Inst #2440 = NLZC_D
  { 2, &MipsDescs.OperandInfo[1087] },  // Inst #2439 = NLZC_B
  { 2, &MipsDescs.OperandInfo[244] },  // Inst #2438 = NLOC_W
  { 2, &MipsDescs.OperandInfo[1174] },  // Inst #2437 = NLOC_H
  { 2, &MipsDescs.OperandInfo[242] },  // Inst #2436 = NLOC_D
  { 2, &MipsDescs.OperandInfo[1087] },  // Inst #2435 = NLOC_B
  { 2, &MipsDescs.OperandInfo[1172] },  // Inst #2434 = MoveR3216
  { 2, &MipsDescs.OperandInfo[1170] },  // Inst #2433 = Move32R16
  { 1, &MipsDescs.OperandInfo[915] },  // Inst #2432 = Mflo16
  { 1, &MipsDescs.OperandInfo[915] },  // Inst #2431 = Mfhi16
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2430 = MUL_S_PH_MMR2
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2429 = MUL_S_PH
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2428 = MUL_R6
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #2427 = MUL_Q_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #2426 = MUL_Q_H
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2425 = MUL_PH_MMR2
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2424 = MUL_PH
  { 3, &MipsDescs.OperandInfo[596] },  // Inst #2423 = MUL_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2422 = MUL_MMR6
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2421 = MUL_MM
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #2420 = MULV_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #2419 = MULV_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #2418 = MULV_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #2417 = MULV_B
  { 3, &MipsDescs.OperandInfo[596] },  // Inst #2416 = MULU_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2415 = MULU_MMR6
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2414 = MULU
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2413 = MULTu_MM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2412 = MULTu
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2411 = MULT_MM
  { 3, &MipsDescs.OperandInfo[463] },  // Inst #2410 = MULT_DSP_MM
  { 3, &MipsDescs.OperandInfo[463] },  // Inst #2409 = MULT_DSP
  { 3, &MipsDescs.OperandInfo[463] },  // Inst #2408 = MULTU_DSP_MM
  { 3, &MipsDescs.OperandInfo[463] },  // Inst #2407 = MULTU_DSP
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2406 = MULT
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #2405 = MULSA_W_PH_MMR2
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #2404 = MULSA_W_PH
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #2403 = MULSAQ_S_W_PH_MM
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #2402 = MULSAQ_S_W_PH
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #2401 = MULR_Q_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #2400 = MULR_Q_H
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #2399 = MULR_PS64
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2398 = MULQ_S_W_MMR2
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2397 = MULQ_S_W
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2396 = MULQ_S_PH_MMR2
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2395 = MULQ_S_PH
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2394 = MULQ_RS_W_MMR2
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2393 = MULQ_RS_W
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2392 = MULQ_RS_PH_MM
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2391 = MULQ_RS_PH
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2390 = MULEU_S_PH_QBR_MM
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2389 = MULEU_S_PH_QBR
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2388 = MULEU_S_PH_QBL_MM
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #2387 = MULEU_S_PH_QBL
  { 3, &MipsDescs.OperandInfo[719] },  // Inst #2386 = MULEQ_S_W_PHR_MM
  { 3, &MipsDescs.OperandInfo[719] },  // Inst #2385 = MULEQ_S_W_PHR
  { 3, &MipsDescs.OperandInfo[719] },  // Inst #2384 = MULEQ_S_W_PHL_MM
  { 3, &MipsDescs.OperandInfo[719] },  // Inst #2383 = MULEQ_S_W_PHL
  { 3, &MipsDescs.OperandInfo[602] },  // Inst #2382 = MUL4x4_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2381 = MUL
  { 3, &MipsDescs.OperandInfo[596] },  // Inst #2380 = MUH_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2379 = MUH_MMR6
  { 3, &MipsDescs.OperandInfo[596] },  // Inst #2378 = MUHU_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2377 = MUHU_MMR6
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2376 = MUHU
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2375 = MUH
  { 5, &MipsDescs.OperandInfo[1165] },  // Inst #2374 = MTTR_NM
  { 5, &MipsDescs.OperandInfo[1062] },  // Inst #2373 = MTTR
  { 1, &MipsDescs.OperandInfo[310] },  // Inst #2372 = MTP2
  { 1, &MipsDescs.OperandInfo[310] },  // Inst #2371 = MTP1
  { 1, &MipsDescs.OperandInfo[310] },  // Inst #2370 = MTP0
  { 1, &MipsDescs.OperandInfo[310] },  // Inst #2369 = MTM2
  { 1, &MipsDescs.OperandInfo[310] },  // Inst #2368 = MTM1
  { 1, &MipsDescs.OperandInfo[310] },  // Inst #2367 = MTM0
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #2366 = MTLO_MM
  { 2, &MipsDescs.OperandInfo[1163] },  // Inst #2365 = MTLO_DSP_MM
  { 2, &MipsDescs.OperandInfo[1163] },  // Inst #2364 = MTLO_DSP
  { 1, &MipsDescs.OperandInfo[310] },  // Inst #2363 = MTLO64
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #2362 = MTLO
  { 3, &MipsDescs.OperandInfo[1160] },  // Inst #2361 = MTHLIP_MM
  { 3, &MipsDescs.OperandInfo[1160] },  // Inst #2360 = MTHLIP
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #2359 = MTHI_MM
  { 2, &MipsDescs.OperandInfo[1158] },  // Inst #2358 = MTHI_DSP_MM
  { 2, &MipsDescs.OperandInfo[1158] },  // Inst #2357 = MTHI_DSP
  { 1, &MipsDescs.OperandInfo[310] },  // Inst #2356 = MTHI64
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #2355 = MTHI
  { 3, &MipsDescs.OperandInfo[408] },  // Inst #2354 = MTHGC0_MM
  { 3, &MipsDescs.OperandInfo[408] },  // Inst #2353 = MTHGC0
  { 2, &MipsDescs.OperandInfo[745] },  // Inst #2352 = MTHC2_MMR6
  { 3, &MipsDescs.OperandInfo[1155] },  // Inst #2351 = MTHC1_D64_MM
  { 3, &MipsDescs.OperandInfo[1155] },  // Inst #2350 = MTHC1_D64
  { 3, &MipsDescs.OperandInfo[1152] },  // Inst #2349 = MTHC1_D32_MM
  { 3, &MipsDescs.OperandInfo[1152] },  // Inst #2348 = MTHC1_D32
  { 3, &MipsDescs.OperandInfo[386] },  // Inst #2347 = MTHC0_NM
  { 3, &MipsDescs.OperandInfo[408] },  // Inst #2346 = MTHC0_MMR6
  { 2, &MipsDescs.OperandInfo[1053] },  // Inst #2345 = MTHC0Sel_NM
  { 3, &MipsDescs.OperandInfo[408] },  // Inst #2344 = MTGC0_MM
  { 3, &MipsDescs.OperandInfo[408] },  // Inst #2343 = MTGC0
  { 2, &MipsDescs.OperandInfo[745] },  // Inst #2342 = MTC2_MMR6
  { 3, &MipsDescs.OperandInfo[1149] },  // Inst #2341 = MTC2
  { 2, &MipsDescs.OperandInfo[414] },  // Inst #2340 = MTC1_MMR6
  { 2, &MipsDescs.OperandInfo[414] },  // Inst #2339 = MTC1_MM
  { 2, &MipsDescs.OperandInfo[431] },  // Inst #2338 = MTC1_D64_MM
  { 2, &MipsDescs.OperandInfo[431] },  // Inst #2337 = MTC1_D64
  { 2, &MipsDescs.OperandInfo[414] },  // Inst #2336 = MTC1
  { 3, &MipsDescs.OperandInfo[386] },  // Inst #2335 = MTC0_NM
  { 3, &MipsDescs.OperandInfo[408] },  // Inst #2334 = MTC0_MMR6
  { 2, &MipsDescs.OperandInfo[1053] },  // Inst #2333 = MTC0Sel_NM
  { 3, &MipsDescs.OperandInfo[408] },  // Inst #2332 = MTC0
  { 4, &MipsDescs.OperandInfo[1049] },  // Inst #2331 = MSUB_S_MM
  { 4, &MipsDescs.OperandInfo[1049] },  // Inst #2330 = MSUB_S
  { 4, &MipsDescs.OperandInfo[194] },  // Inst #2329 = MSUB_Q_W
  { 4, &MipsDescs.OperandInfo[198] },  // Inst #2328 = MSUB_Q_H
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2327 = MSUB_MM
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #2326 = MSUB_DSP_MM
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #2325 = MSUB_DSP
  { 4, &MipsDescs.OperandInfo[1045] },  // Inst #2324 = MSUB_D64
  { 4, &MipsDescs.OperandInfo[1041] },  // Inst #2323 = MSUB_D32_MM
  { 4, &MipsDescs.OperandInfo[1041] },  // Inst #2322 = MSUB_D32
  { 4, &MipsDescs.OperandInfo[194] },  // Inst #2321 = MSUBV_W
  { 4, &MipsDescs.OperandInfo[198] },  // Inst #2320 = MSUBV_H
  { 4, &MipsDescs.OperandInfo[190] },  // Inst #2319 = MSUBV_D
  { 4, &MipsDescs.OperandInfo[672] },  // Inst #2318 = MSUBV_B
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2317 = MSUBU_MM
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #2316 = MSUBU_DSP_MM
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #2315 = MSUBU_DSP
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2314 = MSUBU
  { 4, &MipsDescs.OperandInfo[194] },  // Inst #2313 = MSUBR_Q_W
  { 4, &MipsDescs.OperandInfo[198] },  // Inst #2312 = MSUBR_Q_H
  { 4, &MipsDescs.OperandInfo[1037] },  // Inst #2311 = MSUBF_S_MMR6
  { 4, &MipsDescs.OperandInfo[1037] },  // Inst #2310 = MSUBF_S
  { 4, &MipsDescs.OperandInfo[1033] },  // Inst #2309 = MSUBF_D_MMR6
  { 4, &MipsDescs.OperandInfo[1033] },  // Inst #2308 = MSUBF_D
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2307 = MSUB
  { 4, &MipsDescs.OperandInfo[1145] },  // Inst #2306 = MOVZ_NM
  { 4, &MipsDescs.OperandInfo[1141] },  // Inst #2305 = MOVZ_I_S_MM
  { 4, &MipsDescs.OperandInfo[1141] },  // Inst #2304 = MOVZ_I_S
  { 4, &MipsDescs.OperandInfo[1133] },  // Inst #2303 = MOVZ_I_MM
  { 4, &MipsDescs.OperandInfo[1137] },  // Inst #2302 = MOVZ_I_I64
  { 4, &MipsDescs.OperandInfo[1133] },  // Inst #2301 = MOVZ_I_I
  { 4, &MipsDescs.OperandInfo[1129] },  // Inst #2300 = MOVZ_I_D64
  { 4, &MipsDescs.OperandInfo[1125] },  // Inst #2299 = MOVZ_I_D32_MM
  { 4, &MipsDescs.OperandInfo[1125] },  // Inst #2298 = MOVZ_I_D32
  { 4, &MipsDescs.OperandInfo[1121] },  // Inst #2297 = MOVZ_I64_S
  { 4, &MipsDescs.OperandInfo[1117] },  // Inst #2296 = MOVZ_I64_I64
  { 4, &MipsDescs.OperandInfo[1113] },  // Inst #2295 = MOVZ_I64_I
  { 4, &MipsDescs.OperandInfo[1109] },  // Inst #2294 = MOVZ_I64_D64
  { 4, &MipsDescs.OperandInfo[1105] },  // Inst #2293 = MOVT_S_MM
  { 4, &MipsDescs.OperandInfo[1105] },  // Inst #2292 = MOVT_S
  { 4, &MipsDescs.OperandInfo[1097] },  // Inst #2291 = MOVT_I_MM
  { 4, &MipsDescs.OperandInfo[1101] },  // Inst #2290 = MOVT_I64
  { 4, &MipsDescs.OperandInfo[1097] },  // Inst #2289 = MOVT_I
  { 4, &MipsDescs.OperandInfo[1093] },  // Inst #2288 = MOVT_D64
  { 4, &MipsDescs.OperandInfo[1089] },  // Inst #2287 = MOVT_D32_MM
  { 4, &MipsDescs.OperandInfo[1089] },  // Inst #2286 = MOVT_D32
  { 4, &MipsDescs.OperandInfo[1145] },  // Inst #2285 = MOVN_NM
  { 4, &MipsDescs.OperandInfo[1141] },  // Inst #2284 = MOVN_I_S_MM
  { 4, &MipsDescs.OperandInfo[1141] },  // Inst #2283 = MOVN_I_S
  { 4, &MipsDescs.OperandInfo[1133] },  // Inst #2282 = MOVN_I_MM
  { 4, &MipsDescs.OperandInfo[1137] },  // Inst #2281 = MOVN_I_I64
  { 4, &MipsDescs.OperandInfo[1133] },  // Inst #2280 = MOVN_I_I
  { 4, &MipsDescs.OperandInfo[1129] },  // Inst #2279 = MOVN_I_D64
  { 4, &MipsDescs.OperandInfo[1125] },  // Inst #2278 = MOVN_I_D32_MM
  { 4, &MipsDescs.OperandInfo[1125] },  // Inst #2277 = MOVN_I_D32
  { 4, &MipsDescs.OperandInfo[1121] },  // Inst #2276 = MOVN_I64_S
  { 4, &MipsDescs.OperandInfo[1117] },  // Inst #2275 = MOVN_I64_I64
  { 4, &MipsDescs.OperandInfo[1113] },  // Inst #2274 = MOVN_I64_I
  { 4, &MipsDescs.OperandInfo[1109] },  // Inst #2273 = MOVN_I64_D64
  { 4, &MipsDescs.OperandInfo[1105] },  // Inst #2272 = MOVF_S_MM
  { 4, &MipsDescs.OperandInfo[1105] },  // Inst #2271 = MOVF_S
  { 4, &MipsDescs.OperandInfo[1097] },  // Inst #2270 = MOVF_I_MM
  { 4, &MipsDescs.OperandInfo[1101] },  // Inst #2269 = MOVF_I64
  { 4, &MipsDescs.OperandInfo[1097] },  // Inst #2268 = MOVF_I
  { 4, &MipsDescs.OperandInfo[1093] },  // Inst #2267 = MOVF_D64
  { 4, &MipsDescs.OperandInfo[1089] },  // Inst #2266 = MOVF_D32_MM
  { 4, &MipsDescs.OperandInfo[1089] },  // Inst #2265 = MOVF_D32
  { 2, &MipsDescs.OperandInfo[1087] },  // Inst #2264 = MOVE_V
  { 2, &MipsDescs.OperandInfo[629] },  // Inst #2263 = MOVE_NM
  { 4, &MipsDescs.OperandInfo[1083] },  // Inst #2262 = MOVEP_NM
  { 4, &MipsDescs.OperandInfo[1079] },  // Inst #2261 = MOVEP_MMR6
  { 4, &MipsDescs.OperandInfo[1079] },  // Inst #2260 = MOVEP_MM
  { 4, &MipsDescs.OperandInfo[1075] },  // Inst #2259 = MOVEPREV_NM
  { 3, &MipsDescs.OperandInfo[1072] },  // Inst #2258 = MOVEBALC_NM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2257 = MOVE16_MMR6
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2256 = MOVE16_MM
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #2255 = MOD_U_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #2254 = MOD_U_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #2253 = MOD_U_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #2252 = MOD_U_B
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #2251 = MOD_S_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #2250 = MOD_S_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #2249 = MOD_S_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #2248 = MOD_S_B
  { 3, &MipsDescs.OperandInfo[596] },  // Inst #2247 = MOD_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2246 = MOD_MMR6
  { 3, &MipsDescs.OperandInfo[596] },  // Inst #2245 = MODU_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2244 = MODU_MMR6
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2243 = MODU
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2242 = MODSUB_MM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2241 = MODSUB
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #2240 = MOD
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #2239 = MIN_U_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #2238 = MIN_U_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #2237 = MIN_U_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #2236 = MIN_U_B
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #2235 = MIN_S_W
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #2234 = MIN_S_MMR6
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #2233 = MIN_S_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #2232 = MIN_S_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #2231 = MIN_S_B
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #2230 = MIN_S
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #2229 = MIN_D_MMR6
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #2228 = MIN_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #2227 = MIN_A_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #2226 = MIN_A_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #2225 = MIN_A_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #2224 = MIN_A_B
  { 3, &MipsDescs.OperandInfo[593] },  // Inst #2223 = MINI_U_W
  { 3, &MipsDescs.OperandInfo[590] },  // Inst #2222 = MINI_U_H
  { 3, &MipsDescs.OperandInfo[587] },  // Inst #2221 = MINI_U_D
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #2220 = MINI_U_B
  { 3, &MipsDescs.OperandInfo[593] },  // Inst #2219 = MINI_S_W
  { 3, &MipsDescs.OperandInfo[590] },  // Inst #2218 = MINI_S_H
  { 3, &MipsDescs.OperandInfo[587] },  // Inst #2217 = MINI_S_D
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #2216 = MINI_S_B
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #2215 = MINA_S_MMR6
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #2214 = MINA_S
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #2213 = MINA_D_MMR6
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #2212 = MINA_D
  { 5, &MipsDescs.OperandInfo[1067] },  // Inst #2211 = MFTR_NM
  { 5, &MipsDescs.OperandInfo[1062] },  // Inst #2210 = MFTR
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #2209 = MFLO_MM
  { 2, &MipsDescs.OperandInfo[379] },  // Inst #2208 = MFLO_DSP_MM
  { 2, &MipsDescs.OperandInfo[379] },  // Inst #2207 = MFLO_DSP
  { 1, &MipsDescs.OperandInfo[310] },  // Inst #2206 = MFLO64
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #2205 = MFLO16_MM
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #2204 = MFLO
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #2203 = MFHI_MM
  { 2, &MipsDescs.OperandInfo[379] },  // Inst #2202 = MFHI_DSP_MM
  { 2, &MipsDescs.OperandInfo[379] },  // Inst #2201 = MFHI_DSP
  { 1, &MipsDescs.OperandInfo[310] },  // Inst #2200 = MFHI64
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #2199 = MFHI16_MM
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #2198 = MFHI
  { 3, &MipsDescs.OperandInfo[383] },  // Inst #2197 = MFHGC0_MM
  { 3, &MipsDescs.OperandInfo[383] },  // Inst #2196 = MFHGC0
  { 2, &MipsDescs.OperandInfo[703] },  // Inst #2195 = MFHC2_MMR6
  { 2, &MipsDescs.OperandInfo[1055] },  // Inst #2194 = MFHC1_D64_MM
  { 2, &MipsDescs.OperandInfo[1055] },  // Inst #2193 = MFHC1_D64
  { 2, &MipsDescs.OperandInfo[1060] },  // Inst #2192 = MFHC1_D32_MM
  { 2, &MipsDescs.OperandInfo[1060] },  // Inst #2191 = MFHC1_D32
  { 3, &MipsDescs.OperandInfo[386] },  // Inst #2190 = MFHC0_NM
  { 3, &MipsDescs.OperandInfo[383] },  // Inst #2189 = MFHC0_MMR6
  { 2, &MipsDescs.OperandInfo[1053] },  // Inst #2188 = MFHC0Sel_NM
  { 3, &MipsDescs.OperandInfo[383] },  // Inst #2187 = MFGC0_MM
  { 3, &MipsDescs.OperandInfo[383] },  // Inst #2186 = MFGC0
  { 2, &MipsDescs.OperandInfo[703] },  // Inst #2185 = MFC2_MMR6
  { 3, &MipsDescs.OperandInfo[1057] },  // Inst #2184 = MFC2
  { 2, &MipsDescs.OperandInfo[389] },  // Inst #2183 = MFC1_MMR6
  { 2, &MipsDescs.OperandInfo[389] },  // Inst #2182 = MFC1_MM
  { 2, &MipsDescs.OperandInfo[1055] },  // Inst #2181 = MFC1_D64
  { 2, &MipsDescs.OperandInfo[389] },  // Inst #2180 = MFC1
  { 3, &MipsDescs.OperandInfo[386] },  // Inst #2179 = MFC0_NM
  { 3, &MipsDescs.OperandInfo[383] },  // Inst #2178 = MFC0_MMR6
  { 2, &MipsDescs.OperandInfo[1053] },  // Inst #2177 = MFC0Sel_NM
  { 3, &MipsDescs.OperandInfo[383] },  // Inst #2176 = MFC0
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #2175 = MAX_U_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #2174 = MAX_U_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #2173 = MAX_U_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #2172 = MAX_U_B
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #2171 = MAX_S_W
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #2170 = MAX_S_MMR6
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #2169 = MAX_S_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #2168 = MAX_S_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #2167 = MAX_S_B
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #2166 = MAX_S
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #2165 = MAX_D_MMR6
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #2164 = MAX_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #2163 = MAX_A_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #2162 = MAX_A_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #2161 = MAX_A_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #2160 = MAX_A_B
  { 3, &MipsDescs.OperandInfo[593] },  // Inst #2159 = MAXI_U_W
  { 3, &MipsDescs.OperandInfo[590] },  // Inst #2158 = MAXI_U_H
  { 3, &MipsDescs.OperandInfo[587] },  // Inst #2157 = MAXI_U_D
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #2156 = MAXI_U_B
  { 3, &MipsDescs.OperandInfo[593] },  // Inst #2155 = MAXI_S_W
  { 3, &MipsDescs.OperandInfo[590] },  // Inst #2154 = MAXI_S_H
  { 3, &MipsDescs.OperandInfo[587] },  // Inst #2153 = MAXI_S_D
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #2152 = MAXI_S_B
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #2151 = MAXA_S_MMR6
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #2150 = MAXA_S
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #2149 = MAXA_D_MMR6
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #2148 = MAXA_D
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #2147 = MAQ_S_W_PHR_MM
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #2146 = MAQ_S_W_PHR
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #2145 = MAQ_S_W_PHL_MM
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #2144 = MAQ_S_W_PHL
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #2143 = MAQ_SA_W_PHR_MM
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #2142 = MAQ_SA_W_PHR
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #2141 = MAQ_SA_W_PHL_MM
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #2140 = MAQ_SA_W_PHL
  { 4, &MipsDescs.OperandInfo[1049] },  // Inst #2139 = MADD_S_MM
  { 4, &MipsDescs.OperandInfo[1049] },  // Inst #2138 = MADD_S
  { 4, &MipsDescs.OperandInfo[194] },  // Inst #2137 = MADD_Q_W
  { 4, &MipsDescs.OperandInfo[198] },  // Inst #2136 = MADD_Q_H
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2135 = MADD_MM
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #2134 = MADD_DSP_MM
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #2133 = MADD_DSP
  { 4, &MipsDescs.OperandInfo[1045] },  // Inst #2132 = MADD_D64
  { 4, &MipsDescs.OperandInfo[1041] },  // Inst #2131 = MADD_D32_MM
  { 4, &MipsDescs.OperandInfo[1041] },  // Inst #2130 = MADD_D32
  { 4, &MipsDescs.OperandInfo[194] },  // Inst #2129 = MADDV_W
  { 4, &MipsDescs.OperandInfo[198] },  // Inst #2128 = MADDV_H
  { 4, &MipsDescs.OperandInfo[190] },  // Inst #2127 = MADDV_D
  { 4, &MipsDescs.OperandInfo[672] },  // Inst #2126 = MADDV_B
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2125 = MADDU_MM
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #2124 = MADDU_DSP_MM
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #2123 = MADDU_DSP
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2122 = MADDU
  { 4, &MipsDescs.OperandInfo[194] },  // Inst #2121 = MADDR_Q_W
  { 4, &MipsDescs.OperandInfo[198] },  // Inst #2120 = MADDR_Q_H
  { 4, &MipsDescs.OperandInfo[1037] },  // Inst #2119 = MADDF_S_MMR6
  { 4, &MipsDescs.OperandInfo[1037] },  // Inst #2118 = MADDF_S
  { 4, &MipsDescs.OperandInfo[1033] },  // Inst #2117 = MADDF_D_MMR6
  { 4, &MipsDescs.OperandInfo[1033] },  // Inst #2116 = MADDF_D
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #2115 = MADD
  { 3, &MipsDescs.OperandInfo[623] },  // Inst #2114 = LwRxSpImmX16
  { 3, &MipsDescs.OperandInfo[1027] },  // Inst #2113 = LwRxRyOffMemX16
  { 3, &MipsDescs.OperandInfo[1030] },  // Inst #2112 = LwRxPcTcpX16
  { 3, &MipsDescs.OperandInfo[1030] },  // Inst #2111 = LwRxPcTcp16
  { 2, &MipsDescs.OperandInfo[618] },  // Inst #2110 = LiRxImmX16
  { 2, &MipsDescs.OperandInfo[618] },  // Inst #2109 = LiRxImmAlignX16
  { 2, &MipsDescs.OperandInfo[618] },  // Inst #2108 = LiRxImm16
  { 3, &MipsDescs.OperandInfo[1027] },  // Inst #2107 = LhuRxRyOffMemX16
  { 3, &MipsDescs.OperandInfo[1027] },  // Inst #2106 = LhRxRyOffMemX16
  { 3, &MipsDescs.OperandInfo[1027] },  // Inst #2105 = LbuRxRyOffMemX16
  { 3, &MipsDescs.OperandInfo[1027] },  // Inst #2104 = LbRxRyOffMemX16
  { 3, &MipsDescs.OperandInfo[361] },  // Inst #2103 = LWu
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #2102 = LWs9_NM
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #2101 = LW_NM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2100 = LW_MMR6
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2099 = LW_MM
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #2098 = LWX_NM
  { 3, &MipsDescs.OperandInfo[925] },  // Inst #2097 = LWX_MM
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #2096 = LWXS_NM
  { 3, &MipsDescs.OperandInfo[925] },  // Inst #2095 = LWXS_MM
  { 3, &MipsDescs.OperandInfo[916] },  // Inst #2094 = LWXS16_NM
  { 3, &MipsDescs.OperandInfo[1024] },  // Inst #2093 = LWXC1_MM
  { 3, &MipsDescs.OperandInfo[1024] },  // Inst #2092 = LWXC1
  { 3, &MipsDescs.OperandInfo[925] },  // Inst #2091 = LWX
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2090 = LWU_MM
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #2089 = LWUPC
  { 3, &MipsDescs.OperandInfo[1021] },  // Inst #2088 = LWSP_MM
  { 3, &MipsDescs.OperandInfo[1018] },  // Inst #2087 = LWSP16_NM
  { 4, &MipsDescs.OperandInfo[1003] },  // Inst #2086 = LWR_MM
  { 4, &MipsDescs.OperandInfo[1003] },  // Inst #2085 = LWRE_MM
  { 4, &MipsDescs.OperandInfo[1003] },  // Inst #2084 = LWRE
  { 4, &MipsDescs.OperandInfo[951] },  // Inst #2083 = LWR64
  { 4, &MipsDescs.OperandInfo[1003] },  // Inst #2082 = LWR
  { 4, &MipsDescs.OperandInfo[1014] },  // Inst #2081 = LWP_MM
  { 2, &MipsDescs.OperandInfo[609] },  // Inst #2080 = LWPC_NM
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #2079 = LWPC_MMR6
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #2078 = LWPC
  { 4, &MipsDescs.OperandInfo[1010] },  // Inst #2077 = LWM_NM
  { 3, &MipsDescs.OperandInfo[354] },  // Inst #2076 = LWM32_MM
  { 3, &MipsDescs.OperandInfo[1007] },  // Inst #2075 = LWM16_MMR6
  { 3, &MipsDescs.OperandInfo[1007] },  // Inst #2074 = LWM16_MM
  { 4, &MipsDescs.OperandInfo[1003] },  // Inst #2073 = LWL_MM
  { 4, &MipsDescs.OperandInfo[1003] },  // Inst #2072 = LWLE_MM
  { 4, &MipsDescs.OperandInfo[1003] },  // Inst #2071 = LWLE
  { 4, &MipsDescs.OperandInfo[951] },  // Inst #2070 = LWL64
  { 4, &MipsDescs.OperandInfo[1003] },  // Inst #2069 = LWL
  { 3, &MipsDescs.OperandInfo[1000] },  // Inst #2068 = LWGP_NM
  { 3, &MipsDescs.OperandInfo[997] },  // Inst #2067 = LWGP_MM
  { 3, &MipsDescs.OperandInfo[994] },  // Inst #2066 = LWGP16_NM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2065 = LWE_MM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2064 = LWE
  { 3, &MipsDescs.OperandInfo[991] },  // Inst #2063 = LWDSP_MM
  { 3, &MipsDescs.OperandInfo[991] },  // Inst #2062 = LWDSP
  { 3, &MipsDescs.OperandInfo[940] },  // Inst #2061 = LWC3
  { 3, &MipsDescs.OperandInfo[934] },  // Inst #2060 = LWC2_R6
  { 3, &MipsDescs.OperandInfo[937] },  // Inst #2059 = LWC2_MMR6
  { 3, &MipsDescs.OperandInfo[934] },  // Inst #2058 = LWC2
  { 3, &MipsDescs.OperandInfo[988] },  // Inst #2057 = LWC1_MM
  { 3, &MipsDescs.OperandInfo[988] },  // Inst #2056 = LWC1
  { 3, &MipsDescs.OperandInfo[361] },  // Inst #2055 = LW64
  { 3, &MipsDescs.OperandInfo[985] },  // Inst #2054 = LW4x4_NM
  { 3, &MipsDescs.OperandInfo[916] },  // Inst #2053 = LW16_NM
  { 3, &MipsDescs.OperandInfo[922] },  // Inst #2052 = LW16_MM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2051 = LW
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #2050 = LUi_MM
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #2049 = LUi64
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #2048 = LUi
  { 3, &MipsDescs.OperandInfo[958] },  // Inst #2047 = LUXC1_MM
  { 3, &MipsDescs.OperandInfo[958] },  // Inst #2046 = LUXC164
  { 3, &MipsDescs.OperandInfo[955] },  // Inst #2045 = LUXC1
  { 2, &MipsDescs.OperandInfo[450] },  // Inst #2044 = LUI_NM
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #2043 = LUI_MMR6
  { 4, &MipsDescs.OperandInfo[605] },  // Inst #2042 = LSA_R6
  { 4, &MipsDescs.OperandInfo[142] },  // Inst #2041 = LSA_NM
  { 4, &MipsDescs.OperandInfo[605] },  // Inst #2040 = LSA_MMR6
  { 4, &MipsDescs.OperandInfo[605] },  // Inst #2039 = LSA
  { 3, &MipsDescs.OperandInfo[975] },  // Inst #2038 = LL_R6
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #2037 = LL_NM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2036 = LL_MMR6
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2035 = LL_MM
  { 4, &MipsDescs.OperandInfo[981] },  // Inst #2034 = LLWP_NM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2033 = LLE_MM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2032 = LLE
  { 3, &MipsDescs.OperandInfo[978] },  // Inst #2031 = LLD_R6
  { 3, &MipsDescs.OperandInfo[361] },  // Inst #2030 = LLD
  { 3, &MipsDescs.OperandInfo[975] },  // Inst #2029 = LL64_R6
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2028 = LL64
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2027 = LL
  { 2, &MipsDescs.OperandInfo[450] },  // Inst #2026 = LI48_NM
  { 2, &MipsDescs.OperandInfo[973] },  // Inst #2025 = LI16_NM
  { 2, &MipsDescs.OperandInfo[558] },  // Inst #2024 = LI16_MMR6
  { 2, &MipsDescs.OperandInfo[558] },  // Inst #2023 = LI16_MM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2022 = LHu_MM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2021 = LHuE_MM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2020 = LHuE
  { 3, &MipsDescs.OperandInfo[361] },  // Inst #2019 = LHu64
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2018 = LHu
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #2017 = LHs9_NM
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #2016 = LH_NM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2015 = LH_MM
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #2014 = LHX_NM
  { 3, &MipsDescs.OperandInfo[925] },  // Inst #2013 = LHX_MM
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #2012 = LHXS_NM
  { 3, &MipsDescs.OperandInfo[925] },  // Inst #2011 = LHX
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #2010 = LHUs9_NM
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #2009 = LHU_NM
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #2008 = LHUX_NM
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #2007 = LHUXS_NM
  { 3, &MipsDescs.OperandInfo[919] },  // Inst #2006 = LHUGP_NM
  { 3, &MipsDescs.OperandInfo[916] },  // Inst #2005 = LHU16_NM
  { 3, &MipsDescs.OperandInfo[922] },  // Inst #2004 = LHU16_MM
  { 3, &MipsDescs.OperandInfo[919] },  // Inst #2003 = LHGP_NM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2002 = LHE_MM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #2001 = LHE
  { 3, &MipsDescs.OperandInfo[361] },  // Inst #2000 = LH64
  { 3, &MipsDescs.OperandInfo[916] },  // Inst #1999 = LH16_NM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #1998 = LH
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #1997 = LEA_ADDiu_MM
  { 3, &MipsDescs.OperandInfo[361] },  // Inst #1996 = LEA_ADDiu64
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #1995 = LEA_ADDiu
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #1994 = LEA_ADDIU_NM
  { 3, &MipsDescs.OperandInfo[970] },  // Inst #1993 = LD_W
  { 3, &MipsDescs.OperandInfo[967] },  // Inst #1992 = LD_H
  { 3, &MipsDescs.OperandInfo[964] },  // Inst #1991 = LD_D
  { 3, &MipsDescs.OperandInfo[961] },  // Inst #1990 = LD_B
  { 3, &MipsDescs.OperandInfo[958] },  // Inst #1989 = LDXC164
  { 3, &MipsDescs.OperandInfo[955] },  // Inst #1988 = LDXC1
  { 4, &MipsDescs.OperandInfo[951] },  // Inst #1987 = LDR
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #1986 = LDPC
  { 4, &MipsDescs.OperandInfo[951] },  // Inst #1985 = LDL
  { 2, &MipsDescs.OperandInfo[949] },  // Inst #1984 = LDI_W
  { 2, &MipsDescs.OperandInfo[947] },  // Inst #1983 = LDI_H
  { 2, &MipsDescs.OperandInfo[945] },  // Inst #1982 = LDI_D
  { 2, &MipsDescs.OperandInfo[943] },  // Inst #1981 = LDI_B
  { 3, &MipsDescs.OperandInfo[940] },  // Inst #1980 = LDC3
  { 3, &MipsDescs.OperandInfo[934] },  // Inst #1979 = LDC2_R6
  { 3, &MipsDescs.OperandInfo[937] },  // Inst #1978 = LDC2_MMR6
  { 3, &MipsDescs.OperandInfo[934] },  // Inst #1977 = LDC2
  { 3, &MipsDescs.OperandInfo[931] },  // Inst #1976 = LDC1_MM_D64
  { 3, &MipsDescs.OperandInfo[519] },  // Inst #1975 = LDC1_MM_D32
  { 3, &MipsDescs.OperandInfo[931] },  // Inst #1974 = LDC1_D64_MMR6
  { 3, &MipsDescs.OperandInfo[931] },  // Inst #1973 = LDC164
  { 3, &MipsDescs.OperandInfo[519] },  // Inst #1972 = LDC1
  { 3, &MipsDescs.OperandInfo[361] },  // Inst #1971 = LD
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #1970 = LBu_MM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #1969 = LBuE_MM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #1968 = LBuE
  { 3, &MipsDescs.OperandInfo[361] },  // Inst #1967 = LBu64
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #1966 = LBu
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #1965 = LBs9_NM
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #1964 = LB_NM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #1963 = LB_MMR6
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #1962 = LB_MM
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #1961 = LBX_NM
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #1960 = LBUs9_NM
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #1959 = LBU_NM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #1958 = LBU_MMR6
  { 3, &MipsDescs.OperandInfo[928] },  // Inst #1957 = LBUX_NM
  { 3, &MipsDescs.OperandInfo[925] },  // Inst #1956 = LBUX_MM
  { 3, &MipsDescs.OperandInfo[925] },  // Inst #1955 = LBUX
  { 3, &MipsDescs.OperandInfo[919] },  // Inst #1954 = LBUGP_NM
  { 3, &MipsDescs.OperandInfo[916] },  // Inst #1953 = LBU16_NM
  { 3, &MipsDescs.OperandInfo[922] },  // Inst #1952 = LBU16_MM
  { 3, &MipsDescs.OperandInfo[919] },  // Inst #1951 = LBGP_NM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #1950 = LBE_MM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #1949 = LBE
  { 3, &MipsDescs.OperandInfo[361] },  // Inst #1948 = LB64
  { 3, &MipsDescs.OperandInfo[916] },  // Inst #1947 = LB16_NM
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #1946 = LB
  { 2, &MipsDescs.OperandInfo[609] },  // Inst #1945 = LAPC48_NM
  { 2, &MipsDescs.OperandInfo[609] },  // Inst #1944 = LAPC32_NM
  { 1, &MipsDescs.OperandInfo[915] },  // Inst #1943 = JumpLinkReg16
  { 1, &MipsDescs.OperandInfo[915] },  // Inst #1942 = JrcRx16
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1941 = JrcRa16
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1940 = JrRa16
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1939 = JalB16
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1938 = Jal16
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1937 = J_MM
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1936 = JR_MM
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1935 = JR_HB_R6
  { 1, &MipsDescs.OperandInfo[310] },  // Inst #1934 = JR_HB64_R6
  { 1, &MipsDescs.OperandInfo[310] },  // Inst #1933 = JR_HB64
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1932 = JR_HB
  { 1, &MipsDescs.OperandInfo[311] },  // Inst #1931 = JRC_NM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1930 = JRCADDIUSP_MMR6
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1929 = JRC16_MMR6
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1928 = JRC16_MM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1927 = JRADDIUSP
  { 1, &MipsDescs.OperandInfo[310] },  // Inst #1926 = JR64
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1925 = JR16_MM
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1924 = JR
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #1923 = JIC_MMR6
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #1922 = JIC64
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #1921 = JIC
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #1920 = JIALC_MMR6
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #1919 = JIALC64
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #1918 = JIALC
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1917 = JAL_MM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1916 = JALX_MM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1915 = JALX
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1914 = JALS_MM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1913 = JALR_MM
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #1912 = JALR_HB64
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1911 = JALR_HB
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1910 = JALRS_MM
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1909 = JALRS16_MM
  { 2, &MipsDescs.OperandInfo[416] },  // Inst #1908 = JALRC_NM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1907 = JALRC_MMR6
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1906 = JALRC_HB_MMR6
  { 2, &MipsDescs.OperandInfo[416] },  // Inst #1905 = JALRCHB_NM
  { 2, &MipsDescs.OperandInfo[913] },  // Inst #1904 = JALRC16_NM
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1903 = JALRC16_MMR6
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #1902 = JALR64
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1901 = JALR16_MM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1900 = JALR
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1899 = JAL
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1898 = J
  { 5, &MipsDescs.OperandInfo[908] },  // Inst #1897 = INS_NM
  { 5, &MipsDescs.OperandInfo[864] },  // Inst #1896 = INS_MMR6
  { 5, &MipsDescs.OperandInfo[864] },  // Inst #1895 = INS_MM
  { 3, &MipsDescs.OperandInfo[885] },  // Inst #1894 = INSV_MM
  { 5, &MipsDescs.OperandInfo[903] },  // Inst #1893 = INSVE_W
  { 5, &MipsDescs.OperandInfo[898] },  // Inst #1892 = INSVE_H
  { 5, &MipsDescs.OperandInfo[893] },  // Inst #1891 = INSVE_D
  { 5, &MipsDescs.OperandInfo[888] },  // Inst #1890 = INSVE_B
  { 3, &MipsDescs.OperandInfo[885] },  // Inst #1889 = INSV
  { 4, &MipsDescs.OperandInfo[881] },  // Inst #1888 = INSERT_W
  { 4, &MipsDescs.OperandInfo[877] },  // Inst #1887 = INSERT_H
  { 4, &MipsDescs.OperandInfo[873] },  // Inst #1886 = INSERT_D
  { 4, &MipsDescs.OperandInfo[869] },  // Inst #1885 = INSERT_B
  { 5, &MipsDescs.OperandInfo[864] },  // Inst #1884 = INS
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1883 = ILVR_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #1882 = ILVR_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1881 = ILVR_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #1880 = ILVR_B
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1879 = ILVOD_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #1878 = ILVOD_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1877 = ILVOD_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #1876 = ILVOD_B
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1875 = ILVL_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #1874 = ILVL_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1873 = ILVL_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #1872 = ILVL_B
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1871 = ILVEV_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #1870 = ILVEV_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1869 = ILVEV_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #1868 = ILVEV_B
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1867 = HYPCALL_MM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1866 = HYPCALL
  { 3, &MipsDescs.OperandInfo[795] },  // Inst #1865 = HSUB_U_W
  { 3, &MipsDescs.OperandInfo[792] },  // Inst #1864 = HSUB_U_H
  { 3, &MipsDescs.OperandInfo[789] },  // Inst #1863 = HSUB_U_D
  { 3, &MipsDescs.OperandInfo[795] },  // Inst #1862 = HSUB_S_W
  { 3, &MipsDescs.OperandInfo[792] },  // Inst #1861 = HSUB_S_H
  { 3, &MipsDescs.OperandInfo[789] },  // Inst #1860 = HSUB_S_D
  { 3, &MipsDescs.OperandInfo[795] },  // Inst #1859 = HADD_U_W
  { 3, &MipsDescs.OperandInfo[792] },  // Inst #1858 = HADD_U_H
  { 3, &MipsDescs.OperandInfo[789] },  // Inst #1857 = HADD_U_D
  { 3, &MipsDescs.OperandInfo[795] },  // Inst #1856 = HADD_S_W
  { 3, &MipsDescs.OperandInfo[792] },  // Inst #1855 = HADD_S_H
  { 3, &MipsDescs.OperandInfo[789] },  // Inst #1854 = HADD_S_D
  { 2, &MipsDescs.OperandInfo[450] },  // Inst #1853 = GINVT_NM
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #1852 = GINVT_MMR6
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #1851 = GINVT
  { 1, &MipsDescs.OperandInfo[311] },  // Inst #1850 = GINVI_NM
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1849 = GINVI_MMR6
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1848 = GINVI
  { 2, &MipsDescs.OperandInfo[244] },  // Inst #1847 = FTRUNC_U_W
  { 2, &MipsDescs.OperandInfo[242] },  // Inst #1846 = FTRUNC_U_D
  { 2, &MipsDescs.OperandInfo[244] },  // Inst #1845 = FTRUNC_S_W
  { 2, &MipsDescs.OperandInfo[242] },  // Inst #1844 = FTRUNC_S_D
  { 3, &MipsDescs.OperandInfo[849] },  // Inst #1843 = FTQ_W
  { 3, &MipsDescs.OperandInfo[846] },  // Inst #1842 = FTQ_H
  { 2, &MipsDescs.OperandInfo[244] },  // Inst #1841 = FTINT_U_W
  { 2, &MipsDescs.OperandInfo[242] },  // Inst #1840 = FTINT_U_D
  { 2, &MipsDescs.OperandInfo[244] },  // Inst #1839 = FTINT_S_W
  { 2, &MipsDescs.OperandInfo[242] },  // Inst #1838 = FTINT_S_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1837 = FSUN_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1836 = FSUN_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1835 = FSUNE_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1834 = FSUNE_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1833 = FSULT_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1832 = FSULT_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1831 = FSULE_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1830 = FSULE_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1829 = FSUEQ_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1828 = FSUEQ_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1827 = FSUB_W
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #1826 = FSUB_S_MMR6
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #1825 = FSUB_S_MM
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #1824 = FSUB_S
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #1823 = FSUB_PS64
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #1822 = FSUB_D64_MM
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #1821 = FSUB_D64
  { 3, &MipsDescs.OperandInfo[831] },  // Inst #1820 = FSUB_D32_MM
  { 3, &MipsDescs.OperandInfo[831] },  // Inst #1819 = FSUB_D32
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1818 = FSUB_D
  { 2, &MipsDescs.OperandInfo[244] },  // Inst #1817 = FSQRT_W
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #1816 = FSQRT_S_MM
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #1815 = FSQRT_S
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #1814 = FSQRT_D64_MM
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #1813 = FSQRT_D64
  { 2, &MipsDescs.OperandInfo[829] },  // Inst #1812 = FSQRT_D32_MM
  { 2, &MipsDescs.OperandInfo[829] },  // Inst #1811 = FSQRT_D32
  { 2, &MipsDescs.OperandInfo[242] },  // Inst #1810 = FSQRT_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1809 = FSOR_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1808 = FSOR_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1807 = FSNE_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1806 = FSNE_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1805 = FSLT_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1804 = FSLT_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1803 = FSLE_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1802 = FSLE_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1801 = FSEQ_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1800 = FSEQ_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1799 = FSAF_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1798 = FSAF_D
  { 2, &MipsDescs.OperandInfo[244] },  // Inst #1797 = FRSQRT_W
  { 2, &MipsDescs.OperandInfo[242] },  // Inst #1796 = FRSQRT_D
  { 2, &MipsDescs.OperandInfo[244] },  // Inst #1795 = FRINT_W
  { 2, &MipsDescs.OperandInfo[242] },  // Inst #1794 = FRINT_D
  { 2, &MipsDescs.OperandInfo[244] },  // Inst #1793 = FRCP_W
  { 2, &MipsDescs.OperandInfo[242] },  // Inst #1792 = FRCP_D
  { 3, &MipsDescs.OperandInfo[596] },  // Inst #1791 = FORK_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #1790 = FORK
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #1789 = FNEG_S_MMR6
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #1788 = FNEG_S_MM
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #1787 = FNEG_S
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #1786 = FNEG_D64_MM
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #1785 = FNEG_D64
  { 2, &MipsDescs.OperandInfo[829] },  // Inst #1784 = FNEG_D32_MM
  { 2, &MipsDescs.OperandInfo[829] },  // Inst #1783 = FNEG_D32
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1782 = FMUL_W
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #1781 = FMUL_S_MMR6
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #1780 = FMUL_S_MM
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #1779 = FMUL_S
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #1778 = FMUL_PS64
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #1777 = FMUL_D64_MM
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #1776 = FMUL_D64
  { 3, &MipsDescs.OperandInfo[831] },  // Inst #1775 = FMUL_D32_MM
  { 3, &MipsDescs.OperandInfo[831] },  // Inst #1774 = FMUL_D32
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1773 = FMUL_D
  { 4, &MipsDescs.OperandInfo[194] },  // Inst #1772 = FMSUB_W
  { 4, &MipsDescs.OperandInfo[190] },  // Inst #1771 = FMSUB_D
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #1770 = FMOV_S_MMR6
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #1769 = FMOV_S_MM
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #1768 = FMOV_S
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #1767 = FMOV_D_MMR6
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #1766 = FMOV_D64_MM
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #1765 = FMOV_D64
  { 2, &MipsDescs.OperandInfo[829] },  // Inst #1764 = FMOV_D32_MM
  { 2, &MipsDescs.OperandInfo[829] },  // Inst #1763 = FMOV_D32
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1762 = FMIN_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1761 = FMIN_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1760 = FMIN_A_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1759 = FMIN_A_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1758 = FMAX_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1757 = FMAX_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1756 = FMAX_A_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1755 = FMAX_A_D
  { 4, &MipsDescs.OperandInfo[194] },  // Inst #1754 = FMADD_W
  { 4, &MipsDescs.OperandInfo[190] },  // Inst #1753 = FMADD_D
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #1752 = FLOOR_W_S_MMR6
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #1751 = FLOOR_W_S_MM
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #1750 = FLOOR_W_S
  { 2, &MipsDescs.OperandInfo[695] },  // Inst #1749 = FLOOR_W_MM
  { 2, &MipsDescs.OperandInfo[695] },  // Inst #1748 = FLOOR_W_D_MMR6
  { 2, &MipsDescs.OperandInfo[697] },  // Inst #1747 = FLOOR_W_D64
  { 2, &MipsDescs.OperandInfo[695] },  // Inst #1746 = FLOOR_W_D32
  { 2, &MipsDescs.OperandInfo[693] },  // Inst #1745 = FLOOR_L_S_MMR6
  { 2, &MipsDescs.OperandInfo[693] },  // Inst #1744 = FLOOR_L_S
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #1743 = FLOOR_L_D_MMR6
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #1742 = FLOOR_L_D64
  { 2, &MipsDescs.OperandInfo[244] },  // Inst #1741 = FLOG2_W
  { 2, &MipsDescs.OperandInfo[242] },  // Inst #1740 = FLOG2_D
  { 2, &MipsDescs.OperandInfo[862] },  // Inst #1739 = FILL_W
  { 2, &MipsDescs.OperandInfo[860] },  // Inst #1738 = FILL_H
  { 2, &MipsDescs.OperandInfo[858] },  // Inst #1737 = FILL_D
  { 2, &MipsDescs.OperandInfo[856] },  // Inst #1736 = FILL_B
  { 2, &MipsDescs.OperandInfo[854] },  // Inst #1735 = FFQR_W
  { 2, &MipsDescs.OperandInfo[852] },  // Inst #1734 = FFQR_D
  { 2, &MipsDescs.OperandInfo[854] },  // Inst #1733 = FFQL_W
  { 2, &MipsDescs.OperandInfo[852] },  // Inst #1732 = FFQL_D
  { 2, &MipsDescs.OperandInfo[244] },  // Inst #1731 = FFINT_U_W
  { 2, &MipsDescs.OperandInfo[242] },  // Inst #1730 = FFINT_U_D
  { 2, &MipsDescs.OperandInfo[244] },  // Inst #1729 = FFINT_S_W
  { 2, &MipsDescs.OperandInfo[242] },  // Inst #1728 = FFINT_S_D
  { 2, &MipsDescs.OperandInfo[854] },  // Inst #1727 = FEXUPR_W
  { 2, &MipsDescs.OperandInfo[852] },  // Inst #1726 = FEXUPR_D
  { 2, &MipsDescs.OperandInfo[854] },  // Inst #1725 = FEXUPL_W
  { 2, &MipsDescs.OperandInfo[852] },  // Inst #1724 = FEXUPL_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1723 = FEXP2_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1722 = FEXP2_D
  { 3, &MipsDescs.OperandInfo[849] },  // Inst #1721 = FEXDO_W
  { 3, &MipsDescs.OperandInfo[846] },  // Inst #1720 = FEXDO_H
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1719 = FDIV_W
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #1718 = FDIV_S_MMR6
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #1717 = FDIV_S_MM
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #1716 = FDIV_S
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #1715 = FDIV_D64_MM
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #1714 = FDIV_D64
  { 3, &MipsDescs.OperandInfo[831] },  // Inst #1713 = FDIV_D32_MM
  { 3, &MipsDescs.OperandInfo[831] },  // Inst #1712 = FDIV_D32
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1711 = FDIV_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1710 = FCUN_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1709 = FCUN_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1708 = FCUNE_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1707 = FCUNE_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1706 = FCULT_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1705 = FCULT_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1704 = FCULE_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1703 = FCULE_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1702 = FCUEQ_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1701 = FCUEQ_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1700 = FCOR_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1699 = FCOR_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1698 = FCNE_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1697 = FCNE_D
  { 3, &MipsDescs.OperandInfo[843] },  // Inst #1696 = FCMP_S32_MM
  { 3, &MipsDescs.OperandInfo[843] },  // Inst #1695 = FCMP_S32
  { 3, &MipsDescs.OperandInfo[840] },  // Inst #1694 = FCMP_D64
  { 3, &MipsDescs.OperandInfo[837] },  // Inst #1693 = FCMP_D32_MM
  { 3, &MipsDescs.OperandInfo[837] },  // Inst #1692 = FCMP_D32
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1691 = FCLT_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1690 = FCLT_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1689 = FCLE_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1688 = FCLE_D
  { 2, &MipsDescs.OperandInfo[244] },  // Inst #1687 = FCLASS_W
  { 2, &MipsDescs.OperandInfo[242] },  // Inst #1686 = FCLASS_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1685 = FCEQ_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1684 = FCEQ_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1683 = FCAF_W
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1682 = FCAF_D
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1681 = FADD_W
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #1680 = FADD_S_MMR6
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #1679 = FADD_S_MM
  { 3, &MipsDescs.OperandInfo[834] },  // Inst #1678 = FADD_S
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #1677 = FADD_PS64
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #1676 = FADD_D64_MM
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #1675 = FADD_D64
  { 3, &MipsDescs.OperandInfo[831] },  // Inst #1674 = FADD_D32_MM
  { 3, &MipsDescs.OperandInfo[831] },  // Inst #1673 = FADD_D32
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1672 = FADD_D
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #1671 = FABS_S_MM
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #1670 = FABS_S
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #1669 = FABS_D64_MM
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #1668 = FABS_D64
  { 2, &MipsDescs.OperandInfo[829] },  // Inst #1667 = FABS_D32_MM
  { 2, &MipsDescs.OperandInfo[829] },  // Inst #1666 = FABS_D32
  { 4, &MipsDescs.OperandInfo[825] },  // Inst #1665 = EXT_NM
  { 4, &MipsDescs.OperandInfo[715] },  // Inst #1664 = EXT_MMR6
  { 4, &MipsDescs.OperandInfo[715] },  // Inst #1663 = EXT_MM
  { 4, &MipsDescs.OperandInfo[142] },  // Inst #1662 = EXTW_NM
  { 4, &MipsDescs.OperandInfo[707] },  // Inst #1661 = EXTS32
  { 4, &MipsDescs.OperandInfo[707] },  // Inst #1660 = EXTS
  { 3, &MipsDescs.OperandInfo[819] },  // Inst #1659 = EXTR_W_MM
  { 3, &MipsDescs.OperandInfo[819] },  // Inst #1658 = EXTR_W
  { 3, &MipsDescs.OperandInfo[819] },  // Inst #1657 = EXTR_S_H_MM
  { 3, &MipsDescs.OperandInfo[819] },  // Inst #1656 = EXTR_S_H
  { 3, &MipsDescs.OperandInfo[819] },  // Inst #1655 = EXTR_R_W_MM
  { 3, &MipsDescs.OperandInfo[819] },  // Inst #1654 = EXTR_R_W
  { 3, &MipsDescs.OperandInfo[819] },  // Inst #1653 = EXTR_RS_W_MM
  { 3, &MipsDescs.OperandInfo[819] },  // Inst #1652 = EXTR_RS_W
  { 3, &MipsDescs.OperandInfo[822] },  // Inst #1651 = EXTRV_W_MM
  { 3, &MipsDescs.OperandInfo[822] },  // Inst #1650 = EXTRV_W
  { 3, &MipsDescs.OperandInfo[822] },  // Inst #1649 = EXTRV_S_H_MM
  { 3, &MipsDescs.OperandInfo[822] },  // Inst #1648 = EXTRV_S_H
  { 3, &MipsDescs.OperandInfo[822] },  // Inst #1647 = EXTRV_R_W_MM
  { 3, &MipsDescs.OperandInfo[822] },  // Inst #1646 = EXTRV_R_W
  { 3, &MipsDescs.OperandInfo[822] },  // Inst #1645 = EXTRV_RS_W_MM
  { 3, &MipsDescs.OperandInfo[822] },  // Inst #1644 = EXTRV_RS_W
  { 3, &MipsDescs.OperandInfo[819] },  // Inst #1643 = EXTP_MM
  { 3, &MipsDescs.OperandInfo[822] },  // Inst #1642 = EXTPV_MM
  { 3, &MipsDescs.OperandInfo[822] },  // Inst #1641 = EXTPV
  { 3, &MipsDescs.OperandInfo[819] },  // Inst #1640 = EXTPDP_MM
  { 3, &MipsDescs.OperandInfo[822] },  // Inst #1639 = EXTPDPV_MM
  { 3, &MipsDescs.OperandInfo[822] },  // Inst #1638 = EXTPDPV
  { 3, &MipsDescs.OperandInfo[819] },  // Inst #1637 = EXTPDP
  { 3, &MipsDescs.OperandInfo[819] },  // Inst #1636 = EXTP
  { 4, &MipsDescs.OperandInfo[715] },  // Inst #1635 = EXT
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1634 = EVP_MMR6
  { 1, &MipsDescs.OperandInfo[311] },  // Inst #1633 = EVPE_NM
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1632 = EVPE
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1631 = EVP
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1630 = ERET_NM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1629 = ERET_MMR6
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1628 = ERET_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1627 = ERETNC_NM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1626 = ERETNC_MMR6
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1625 = ERETNC
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1624 = ERET
  { 1, &MipsDescs.OperandInfo[311] },  // Inst #1623 = EMT_NM
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1622 = EMT
  { 1, &MipsDescs.OperandInfo[311] },  // Inst #1621 = EI_NM
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1620 = EI_MMR6
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1619 = EI_MM
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1618 = EI
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1617 = EHB_NM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1616 = EHB_MMR6
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1615 = EHB_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1614 = EHB
  { 2, &MipsDescs.OperandInfo[419] },  // Inst #1613 = DivuRxRy16
  { 2, &MipsDescs.OperandInfo[419] },  // Inst #1612 = DivRxRy16
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1611 = DVP_MMR6
  { 1, &MipsDescs.OperandInfo[311] },  // Inst #1610 = DVPE_NM
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1609 = DVPE
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1608 = DVP
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #1607 = DUDIV
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #1606 = DSUBu
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #1605 = DSUB
  { 3, &MipsDescs.OperandInfo[814] },  // Inst #1604 = DSRLV
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #1603 = DSRL32
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #1602 = DSRL
  { 3, &MipsDescs.OperandInfo[814] },  // Inst #1601 = DSRAV
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #1600 = DSRA32
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #1599 = DSRA
  { 3, &MipsDescs.OperandInfo[814] },  // Inst #1598 = DSLLV
  { 2, &MipsDescs.OperandInfo[817] },  // Inst #1597 = DSLL64_32
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #1596 = DSLL32
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #1595 = DSLL
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #1594 = DSHD
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #1593 = DSDIV
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #1592 = DSBH
  { 3, &MipsDescs.OperandInfo[814] },  // Inst #1591 = DROTRV
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #1590 = DROTR32
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #1589 = DROTR
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1588 = DPS_W_PH_MMR2
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1587 = DPS_W_PH
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1586 = DPSX_W_PH_MMR2
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1585 = DPSX_W_PH
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1584 = DPSU_H_QBR_MM
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1583 = DPSU_H_QBR
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1582 = DPSU_H_QBL_MM
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1581 = DPSU_H_QBL
  { 4, &MipsDescs.OperandInfo[806] },  // Inst #1580 = DPSUB_U_W
  { 4, &MipsDescs.OperandInfo[802] },  // Inst #1579 = DPSUB_U_H
  { 4, &MipsDescs.OperandInfo[798] },  // Inst #1578 = DPSUB_U_D
  { 4, &MipsDescs.OperandInfo[806] },  // Inst #1577 = DPSUB_S_W
  { 4, &MipsDescs.OperandInfo[802] },  // Inst #1576 = DPSUB_S_H
  { 4, &MipsDescs.OperandInfo[798] },  // Inst #1575 = DPSUB_S_D
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1574 = DPSQ_S_W_PH_MM
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1573 = DPSQ_S_W_PH
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1572 = DPSQ_SA_L_W_MM
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1571 = DPSQ_SA_L_W
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1570 = DPSQX_S_W_PH_MMR2
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1569 = DPSQX_S_W_PH
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1568 = DPSQX_SA_W_PH_MMR2
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1567 = DPSQX_SA_W_PH
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #1566 = DPOP
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1565 = DPA_W_PH_MMR2
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1564 = DPA_W_PH
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1563 = DPAX_W_PH_MMR2
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1562 = DPAX_W_PH
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1561 = DPAU_H_QBR_MM
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1560 = DPAU_H_QBR
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1559 = DPAU_H_QBL_MM
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1558 = DPAU_H_QBL
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1557 = DPAQ_S_W_PH_MM
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1556 = DPAQ_S_W_PH
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1555 = DPAQ_SA_L_W_MM
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1554 = DPAQ_SA_L_W
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1553 = DPAQX_S_W_PH_MMR2
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1552 = DPAQX_S_W_PH
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1551 = DPAQX_SA_W_PH_MMR2
  { 4, &MipsDescs.OperandInfo[810] },  // Inst #1550 = DPAQX_SA_W_PH
  { 4, &MipsDescs.OperandInfo[806] },  // Inst #1549 = DPADD_U_W
  { 4, &MipsDescs.OperandInfo[802] },  // Inst #1548 = DPADD_U_H
  { 4, &MipsDescs.OperandInfo[798] },  // Inst #1547 = DPADD_U_D
  { 4, &MipsDescs.OperandInfo[806] },  // Inst #1546 = DPADD_S_W
  { 4, &MipsDescs.OperandInfo[802] },  // Inst #1545 = DPADD_S_H
  { 4, &MipsDescs.OperandInfo[798] },  // Inst #1544 = DPADD_S_D
  { 3, &MipsDescs.OperandInfo[795] },  // Inst #1543 = DOTP_U_W
  { 3, &MipsDescs.OperandInfo[792] },  // Inst #1542 = DOTP_U_H
  { 3, &MipsDescs.OperandInfo[789] },  // Inst #1541 = DOTP_U_D
  { 3, &MipsDescs.OperandInfo[795] },  // Inst #1540 = DOTP_S_W
  { 3, &MipsDescs.OperandInfo[792] },  // Inst #1539 = DOTP_S_H
  { 3, &MipsDescs.OperandInfo[789] },  // Inst #1538 = DOTP_S_D
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #1537 = DMUL_R6
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #1536 = DMULU
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #1535 = DMULTu
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #1534 = DMULT
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #1533 = DMUL
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #1532 = DMUHU
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #1531 = DMUH
  { 1, &MipsDescs.OperandInfo[311] },  // Inst #1530 = DMT_NM
  { 3, &MipsDescs.OperandInfo[783] },  // Inst #1529 = DMTGC0
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #1528 = DMTC2_OCTEON
  { 3, &MipsDescs.OperandInfo[786] },  // Inst #1527 = DMTC2
  { 2, &MipsDescs.OperandInfo[429] },  // Inst #1526 = DMTC1
  { 3, &MipsDescs.OperandInfo[783] },  // Inst #1525 = DMTC0
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1524 = DMT
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #1523 = DMODU
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #1522 = DMOD
  { 3, &MipsDescs.OperandInfo[775] },  // Inst #1521 = DMFGC0
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #1520 = DMFC2_OCTEON
  { 3, &MipsDescs.OperandInfo[780] },  // Inst #1519 = DMFC2
  { 2, &MipsDescs.OperandInfo[778] },  // Inst #1518 = DMFC1
  { 3, &MipsDescs.OperandInfo[775] },  // Inst #1517 = DMFC0
  { 4, &MipsDescs.OperandInfo[766] },  // Inst #1516 = DLSA_R6
  { 4, &MipsDescs.OperandInfo[766] },  // Inst #1515 = DLSA
  { 1, &MipsDescs.OperandInfo[311] },  // Inst #1514 = DI_NM
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1513 = DI_MMR6
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1512 = DI_MM
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1511 = DIV_U_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #1510 = DIV_U_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1509 = DIV_U_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #1508 = DIV_U_B
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1507 = DIV_S_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #1506 = DIV_S_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1505 = DIV_S_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #1504 = DIV_S_B
  { 3, &MipsDescs.OperandInfo[596] },  // Inst #1503 = DIV_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #1502 = DIV_MMR6
  { 3, &MipsDescs.OperandInfo[596] },  // Inst #1501 = DIVU_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #1500 = DIVU_MMR6
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #1499 = DIVU
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #1498 = DIV
  { 5, &MipsDescs.OperandInfo[770] },  // Inst #1497 = DINSU
  { 5, &MipsDescs.OperandInfo[770] },  // Inst #1496 = DINSM
  { 5, &MipsDescs.OperandInfo[770] },  // Inst #1495 = DINS
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #1494 = DI
  { 4, &MipsDescs.OperandInfo[707] },  // Inst #1493 = DEXTU
  { 4, &MipsDescs.OperandInfo[707] },  // Inst #1492 = DEXTM
  { 4, &MipsDescs.OperandInfo[711] },  // Inst #1491 = DEXT64_32
  { 4, &MipsDescs.OperandInfo[707] },  // Inst #1490 = DEXT
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1489 = DERET_NM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1488 = DERET_MMR6
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1487 = DERET_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1486 = DERET
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #1485 = DDIVU
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #1484 = DDIV
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #1483 = DCLZ_R6
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #1482 = DCLZ
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #1481 = DCLO_R6
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #1480 = DCLO
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #1479 = DBITSWAP
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #1478 = DAUI
  { 3, &MipsDescs.OperandInfo[763] },  // Inst #1477 = DATI
  { 4, &MipsDescs.OperandInfo[766] },  // Inst #1476 = DALIGN
  { 3, &MipsDescs.OperandInfo[763] },  // Inst #1475 = DAHI
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #1474 = DADDu
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #1473 = DADDiu
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #1472 = DADDi
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #1471 = DADD
  { 2, &MipsDescs.OperandInfo[618] },  // Inst #1470 = CmpiRxImmX16
  { 2, &MipsDescs.OperandInfo[618] },  // Inst #1469 = CmpiRxImm16
  { 2, &MipsDescs.OperandInfo[419] },  // Inst #1468 = CmpRxRy16
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1467 = C_UN_S_MM
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1466 = C_UN_S
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1465 = C_UN_D64_MM
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1464 = C_UN_D64
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1463 = C_UN_D32_MM
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1462 = C_UN_D32
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1461 = C_ULT_S_MM
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1460 = C_ULT_S
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1459 = C_ULT_D64_MM
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1458 = C_ULT_D64
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1457 = C_ULT_D32_MM
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1456 = C_ULT_D32
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1455 = C_ULE_S_MM
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1454 = C_ULE_S
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1453 = C_ULE_D64_MM
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1452 = C_ULE_D64
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1451 = C_ULE_D32_MM
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1450 = C_ULE_D32
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1449 = C_UEQ_S_MM
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1448 = C_UEQ_S
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1447 = C_UEQ_D64_MM
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1446 = C_UEQ_D64
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1445 = C_UEQ_D32_MM
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1444 = C_UEQ_D32
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1443 = C_SF_S_MM
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1442 = C_SF_S
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1441 = C_SF_D64_MM
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1440 = C_SF_D64
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1439 = C_SF_D32_MM
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1438 = C_SF_D32
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1437 = C_SEQ_S_MM
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1436 = C_SEQ_S
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1435 = C_SEQ_D64_MM
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1434 = C_SEQ_D64
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1433 = C_SEQ_D32_MM
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1432 = C_SEQ_D32
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1431 = C_OLT_S_MM
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1430 = C_OLT_S
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1429 = C_OLT_D64_MM
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1428 = C_OLT_D64
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1427 = C_OLT_D32_MM
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1426 = C_OLT_D32
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1425 = C_OLE_S_MM
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1424 = C_OLE_S
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1423 = C_OLE_D64_MM
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1422 = C_OLE_D64
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1421 = C_OLE_D32_MM
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1420 = C_OLE_D32
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1419 = C_NGT_S_MM
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1418 = C_NGT_S
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1417 = C_NGT_D64_MM
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1416 = C_NGT_D64
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1415 = C_NGT_D32_MM
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1414 = C_NGT_D32
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1413 = C_NGL_S_MM
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1412 = C_NGL_S
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1411 = C_NGL_D64_MM
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1410 = C_NGL_D64
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1409 = C_NGL_D32_MM
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1408 = C_NGL_D32
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1407 = C_NGLE_S_MM
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1406 = C_NGLE_S
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1405 = C_NGLE_D64_MM
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1404 = C_NGLE_D64
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1403 = C_NGLE_D32_MM
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1402 = C_NGLE_D32
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1401 = C_NGE_S_MM
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1400 = C_NGE_S
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1399 = C_NGE_D64_MM
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1398 = C_NGE_D64
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1397 = C_NGE_D32_MM
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1396 = C_NGE_D32
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1395 = C_LT_S_MM
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1394 = C_LT_S
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1393 = C_LT_D64_MM
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1392 = C_LT_D64
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1391 = C_LT_D32_MM
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1390 = C_LT_D32
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1389 = C_LE_S_MM
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1388 = C_LE_S
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1387 = C_LE_D64_MM
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1386 = C_LE_D64
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1385 = C_LE_D32_MM
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1384 = C_LE_D32
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1383 = C_F_S_MM
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1382 = C_F_S
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1381 = C_F_D64_MM
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1380 = C_F_D64
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1379 = C_F_D32_MM
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1378 = C_F_D32
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1377 = C_EQ_S_MM
  { 3, &MipsDescs.OperandInfo[760] },  // Inst #1376 = C_EQ_S
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1375 = C_EQ_D64_MM
  { 3, &MipsDescs.OperandInfo[757] },  // Inst #1374 = C_EQ_D64
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1373 = C_EQ_D32_MM
  { 3, &MipsDescs.OperandInfo[754] },  // Inst #1372 = C_EQ_D32
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #1371 = CVT_W_S_MMR6
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #1370 = CVT_W_S_MM
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #1369 = CVT_W_S
  { 2, &MipsDescs.OperandInfo[697] },  // Inst #1368 = CVT_W_D64_MM
  { 2, &MipsDescs.OperandInfo[697] },  // Inst #1367 = CVT_W_D64
  { 2, &MipsDescs.OperandInfo[695] },  // Inst #1366 = CVT_W_D32_MM
  { 2, &MipsDescs.OperandInfo[695] },  // Inst #1365 = CVT_W_D32
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #1364 = CVT_S_W_MMR6
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #1363 = CVT_S_W_MM
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #1362 = CVT_S_W
  { 2, &MipsDescs.OperandInfo[697] },  // Inst #1361 = CVT_S_PU64
  { 2, &MipsDescs.OperandInfo[697] },  // Inst #1360 = CVT_S_PL64
  { 2, &MipsDescs.OperandInfo[693] },  // Inst #1359 = CVT_S_L_MMR6
  { 2, &MipsDescs.OperandInfo[697] },  // Inst #1358 = CVT_S_L
  { 2, &MipsDescs.OperandInfo[697] },  // Inst #1357 = CVT_S_D64_MM
  { 2, &MipsDescs.OperandInfo[697] },  // Inst #1356 = CVT_S_D64
  { 2, &MipsDescs.OperandInfo[695] },  // Inst #1355 = CVT_S_D32_MM
  { 2, &MipsDescs.OperandInfo[695] },  // Inst #1354 = CVT_S_D32
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #1353 = CVT_PW_PS64
  { 3, &MipsDescs.OperandInfo[751] },  // Inst #1352 = CVT_PS_S64
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #1351 = CVT_PS_PW64
  { 2, &MipsDescs.OperandInfo[693] },  // Inst #1350 = CVT_L_S_MMR6
  { 2, &MipsDescs.OperandInfo[693] },  // Inst #1349 = CVT_L_S_MM
  { 2, &MipsDescs.OperandInfo[693] },  // Inst #1348 = CVT_L_S
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #1347 = CVT_L_D_MMR6
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #1346 = CVT_L_D64_MM
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #1345 = CVT_L_D64
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #1344 = CVT_D_L_MMR6
  { 2, &MipsDescs.OperandInfo[693] },  // Inst #1343 = CVT_D64_W_MM
  { 2, &MipsDescs.OperandInfo[693] },  // Inst #1342 = CVT_D64_W
  { 2, &MipsDescs.OperandInfo[693] },  // Inst #1341 = CVT_D64_S_MM
  { 2, &MipsDescs.OperandInfo[693] },  // Inst #1340 = CVT_D64_S
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #1339 = CVT_D64_L
  { 2, &MipsDescs.OperandInfo[749] },  // Inst #1338 = CVT_D32_W_MM
  { 2, &MipsDescs.OperandInfo[749] },  // Inst #1337 = CVT_D32_W
  { 2, &MipsDescs.OperandInfo[749] },  // Inst #1336 = CVT_D32_S_MM
  { 2, &MipsDescs.OperandInfo[749] },  // Inst #1335 = CVT_D32_S
  { 2, &MipsDescs.OperandInfo[747] },  // Inst #1334 = CTCMSA
  { 2, &MipsDescs.OperandInfo[745] },  // Inst #1333 = CTC2_MM
  { 2, &MipsDescs.OperandInfo[743] },  // Inst #1332 = CTC1_MM
  { 2, &MipsDescs.OperandInfo[743] },  // Inst #1331 = CTC1
  { 3, &MipsDescs.OperandInfo[740] },  // Inst #1330 = CRC32W_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #1329 = CRC32W
  { 3, &MipsDescs.OperandInfo[740] },  // Inst #1328 = CRC32H_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #1327 = CRC32H
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #1326 = CRC32D
  { 3, &MipsDescs.OperandInfo[740] },  // Inst #1325 = CRC32CW_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #1324 = CRC32CW
  { 3, &MipsDescs.OperandInfo[740] },  // Inst #1323 = CRC32CH_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #1322 = CRC32CH
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #1321 = CRC32CD
  { 3, &MipsDescs.OperandInfo[740] },  // Inst #1320 = CRC32CB_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #1319 = CRC32CB
  { 3, &MipsDescs.OperandInfo[740] },  // Inst #1318 = CRC32B_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #1317 = CRC32B
  { 3, &MipsDescs.OperandInfo[737] },  // Inst #1316 = COPY_U_W
  { 3, &MipsDescs.OperandInfo[734] },  // Inst #1315 = COPY_U_H
  { 3, &MipsDescs.OperandInfo[728] },  // Inst #1314 = COPY_U_B
  { 3, &MipsDescs.OperandInfo[737] },  // Inst #1313 = COPY_S_W
  { 3, &MipsDescs.OperandInfo[734] },  // Inst #1312 = COPY_S_H
  { 3, &MipsDescs.OperandInfo[731] },  // Inst #1311 = COPY_S_D
  { 3, &MipsDescs.OperandInfo[728] },  // Inst #1310 = COPY_S_B
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1309 = CMP_UN_S_MMR6
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1308 = CMP_UN_S
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1307 = CMP_UN_D_MMR6
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1306 = CMP_UN_D
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1305 = CMP_ULT_S_MMR6
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1304 = CMP_ULT_S
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1303 = CMP_ULT_D_MMR6
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1302 = CMP_ULT_D
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1301 = CMP_ULE_S_MMR6
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1300 = CMP_ULE_S
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1299 = CMP_ULE_D_MMR6
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1298 = CMP_ULE_D
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1297 = CMP_UEQ_S_MMR6
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1296 = CMP_UEQ_S
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1295 = CMP_UEQ_D_MMR6
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1294 = CMP_UEQ_D
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1293 = CMP_SUN_S_MMR6
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1292 = CMP_SUN_S
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1291 = CMP_SUN_D_MMR6
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1290 = CMP_SUN_D
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1289 = CMP_SULT_S_MMR6
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1288 = CMP_SULT_S
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1287 = CMP_SULT_D_MMR6
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1286 = CMP_SULT_D
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1285 = CMP_SULE_S_MMR6
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1284 = CMP_SULE_S
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1283 = CMP_SULE_D_MMR6
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1282 = CMP_SULE_D
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1281 = CMP_SUEQ_S_MMR6
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1280 = CMP_SUEQ_S
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1279 = CMP_SUEQ_D_MMR6
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1278 = CMP_SUEQ_D
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1277 = CMP_SLT_S_MMR6
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1276 = CMP_SLT_S
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1275 = CMP_SLT_D_MMR6
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1274 = CMP_SLT_D
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1273 = CMP_SLE_S_MMR6
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1272 = CMP_SLE_S
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1271 = CMP_SLE_D_MMR6
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1270 = CMP_SLE_D
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1269 = CMP_SEQ_S_MMR6
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1268 = CMP_SEQ_S
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1267 = CMP_SEQ_D_MMR6
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1266 = CMP_SEQ_D
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1265 = CMP_SAF_S_MMR6
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1264 = CMP_SAF_S
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1263 = CMP_SAF_D_MMR6
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1262 = CMP_SAF_D
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1261 = CMP_LT_S_MMR6
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1260 = CMP_LT_S
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #1259 = CMP_LT_PH_MM
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #1258 = CMP_LT_PH
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1257 = CMP_LT_D_MMR6
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1256 = CMP_LT_D
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1255 = CMP_LE_S_MMR6
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1254 = CMP_LE_S
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #1253 = CMP_LE_PH_MM
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #1252 = CMP_LE_PH
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1251 = CMP_LE_D_MMR6
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1250 = CMP_LE_D
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1249 = CMP_F_S
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1248 = CMP_F_D
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1247 = CMP_EQ_S_MMR6
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1246 = CMP_EQ_S
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #1245 = CMP_EQ_PH_MM
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #1244 = CMP_EQ_PH
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1243 = CMP_EQ_D_MMR6
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1242 = CMP_EQ_D
  { 3, &MipsDescs.OperandInfo[725] },  // Inst #1241 = CMP_AF_S_MMR6
  { 3, &MipsDescs.OperandInfo[722] },  // Inst #1240 = CMP_AF_D_MMR6
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #1239 = CMPU_LT_QB_MM
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #1238 = CMPU_LT_QB
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #1237 = CMPU_LE_QB_MM
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #1236 = CMPU_LE_QB
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #1235 = CMPU_EQ_QB_MM
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #1234 = CMPU_EQ_QB
  { 3, &MipsDescs.OperandInfo[719] },  // Inst #1233 = CMPGU_LT_QB_MM
  { 3, &MipsDescs.OperandInfo[719] },  // Inst #1232 = CMPGU_LT_QB
  { 3, &MipsDescs.OperandInfo[719] },  // Inst #1231 = CMPGU_LE_QB_MM
  { 3, &MipsDescs.OperandInfo[719] },  // Inst #1230 = CMPGU_LE_QB
  { 3, &MipsDescs.OperandInfo[719] },  // Inst #1229 = CMPGU_EQ_QB_MM
  { 3, &MipsDescs.OperandInfo[719] },  // Inst #1228 = CMPGU_EQ_QB
  { 3, &MipsDescs.OperandInfo[719] },  // Inst #1227 = CMPGDU_LT_QB_MMR2
  { 3, &MipsDescs.OperandInfo[719] },  // Inst #1226 = CMPGDU_LT_QB
  { 3, &MipsDescs.OperandInfo[719] },  // Inst #1225 = CMPGDU_LE_QB_MMR2
  { 3, &MipsDescs.OperandInfo[719] },  // Inst #1224 = CMPGDU_LE_QB
  { 3, &MipsDescs.OperandInfo[719] },  // Inst #1223 = CMPGDU_EQ_QB_MMR2
  { 3, &MipsDescs.OperandInfo[719] },  // Inst #1222 = CMPGDU_EQ_QB
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1221 = CLZ_R6
  { 2, &MipsDescs.OperandInfo[416] },  // Inst #1220 = CLZ_NM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1219 = CLZ_MMR6
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1218 = CLZ_MM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1217 = CLZ
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1216 = CLT_U_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #1215 = CLT_U_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1214 = CLT_U_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #1213 = CLT_U_B
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1212 = CLT_S_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #1211 = CLT_S_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1210 = CLT_S_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #1209 = CLT_S_B
  { 3, &MipsDescs.OperandInfo[593] },  // Inst #1208 = CLTI_U_W
  { 3, &MipsDescs.OperandInfo[590] },  // Inst #1207 = CLTI_U_H
  { 3, &MipsDescs.OperandInfo[587] },  // Inst #1206 = CLTI_U_D
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #1205 = CLTI_U_B
  { 3, &MipsDescs.OperandInfo[593] },  // Inst #1204 = CLTI_S_W
  { 3, &MipsDescs.OperandInfo[590] },  // Inst #1203 = CLTI_S_H
  { 3, &MipsDescs.OperandInfo[587] },  // Inst #1202 = CLTI_S_D
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #1201 = CLTI_S_B
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1200 = CLO_R6
  { 2, &MipsDescs.OperandInfo[416] },  // Inst #1199 = CLO_NM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1198 = CLO_MMR6
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1197 = CLO_MM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1196 = CLO
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1195 = CLE_U_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #1194 = CLE_U_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1193 = CLE_U_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #1192 = CLE_U_B
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1191 = CLE_S_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #1190 = CLE_S_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1189 = CLE_S_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #1188 = CLE_S_B
  { 3, &MipsDescs.OperandInfo[593] },  // Inst #1187 = CLEI_U_W
  { 3, &MipsDescs.OperandInfo[590] },  // Inst #1186 = CLEI_U_H
  { 3, &MipsDescs.OperandInfo[587] },  // Inst #1185 = CLEI_U_D
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #1184 = CLEI_U_B
  { 3, &MipsDescs.OperandInfo[593] },  // Inst #1183 = CLEI_S_W
  { 3, &MipsDescs.OperandInfo[590] },  // Inst #1182 = CLEI_S_H
  { 3, &MipsDescs.OperandInfo[587] },  // Inst #1181 = CLEI_S_D
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #1180 = CLEI_S_B
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #1179 = CLASS_S_MMR6
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #1178 = CLASS_S
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #1177 = CLASS_D_MMR6
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #1176 = CLASS_D
  { 4, &MipsDescs.OperandInfo[715] },  // Inst #1175 = CINS_i32
  { 4, &MipsDescs.OperandInfo[711] },  // Inst #1174 = CINS64_32
  { 4, &MipsDescs.OperandInfo[707] },  // Inst #1173 = CINS32
  { 4, &MipsDescs.OperandInfo[707] },  // Inst #1172 = CINS
  { 2, &MipsDescs.OperandInfo[705] },  // Inst #1171 = CFCMSA
  { 2, &MipsDescs.OperandInfo[703] },  // Inst #1170 = CFC2_MM
  { 2, &MipsDescs.OperandInfo[701] },  // Inst #1169 = CFC1_MM
  { 2, &MipsDescs.OperandInfo[701] },  // Inst #1168 = CFC1
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1167 = CEQ_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #1166 = CEQ_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1165 = CEQ_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #1164 = CEQ_B
  { 3, &MipsDescs.OperandInfo[593] },  // Inst #1163 = CEQI_W
  { 3, &MipsDescs.OperandInfo[590] },  // Inst #1162 = CEQI_H
  { 3, &MipsDescs.OperandInfo[587] },  // Inst #1161 = CEQI_D
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #1160 = CEQI_B
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #1159 = CEIL_W_S_MMR6
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #1158 = CEIL_W_S_MM
  { 2, &MipsDescs.OperandInfo[699] },  // Inst #1157 = CEIL_W_S
  { 2, &MipsDescs.OperandInfo[695] },  // Inst #1156 = CEIL_W_MM
  { 2, &MipsDescs.OperandInfo[695] },  // Inst #1155 = CEIL_W_D_MMR6
  { 2, &MipsDescs.OperandInfo[697] },  // Inst #1154 = CEIL_W_D64
  { 2, &MipsDescs.OperandInfo[695] },  // Inst #1153 = CEIL_W_D32
  { 2, &MipsDescs.OperandInfo[693] },  // Inst #1152 = CEIL_L_S_MMR6
  { 2, &MipsDescs.OperandInfo[693] },  // Inst #1151 = CEIL_L_S
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #1150 = CEIL_L_D_MMR6
  { 2, &MipsDescs.OperandInfo[691] },  // Inst #1149 = CEIL_L_D64
  { 3, &MipsDescs.OperandInfo[688] },  // Inst #1148 = CACHE_R6
  { 3, &MipsDescs.OperandInfo[354] },  // Inst #1147 = CACHE_NM
  { 3, &MipsDescs.OperandInfo[688] },  // Inst #1146 = CACHE_MMR6
  { 3, &MipsDescs.OperandInfo[688] },  // Inst #1145 = CACHE_MM
  { 3, &MipsDescs.OperandInfo[688] },  // Inst #1144 = CACHEE_MM
  { 3, &MipsDescs.OperandInfo[688] },  // Inst #1143 = CACHEE
  { 3, &MipsDescs.OperandInfo[688] },  // Inst #1142 = CACHE
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1141 = BtnezX16
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1140 = Btnez16
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1139 = BteqzX16
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1138 = Bteqz16
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #1137 = Break16
  { 2, &MipsDescs.OperandInfo[686] },  // Inst #1136 = BnezRxImmX16
  { 2, &MipsDescs.OperandInfo[686] },  // Inst #1135 = BnezRxImm16
  { 1, &MipsDescs.OperandInfo[182] },  // Inst #1134 = BimmX16
  { 1, &MipsDescs.OperandInfo[182] },  // Inst #1133 = Bimm16
  { 2, &MipsDescs.OperandInfo[686] },  // Inst #1132 = BeqzRxImmX16
  { 2, &MipsDescs.OperandInfo[686] },  // Inst #1131 = BeqzRxImm16
  { 2, &MipsDescs.OperandInfo[682] },  // Inst #1130 = BZ_W
  { 2, &MipsDescs.OperandInfo[676] },  // Inst #1129 = BZ_V
  { 2, &MipsDescs.OperandInfo[680] },  // Inst #1128 = BZ_H
  { 2, &MipsDescs.OperandInfo[678] },  // Inst #1127 = BZ_D
  { 2, &MipsDescs.OperandInfo[676] },  // Inst #1126 = BZ_B
  { 2, &MipsDescs.OperandInfo[416] },  // Inst #1125 = BYTEREVW_NM
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1124 = BSET_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #1123 = BSET_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1122 = BSET_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #1121 = BSET_B
  { 3, &MipsDescs.OperandInfo[593] },  // Inst #1120 = BSETI_W
  { 3, &MipsDescs.OperandInfo[590] },  // Inst #1119 = BSETI_H
  { 3, &MipsDescs.OperandInfo[587] },  // Inst #1118 = BSETI_D
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #1117 = BSETI_B
  { 4, &MipsDescs.OperandInfo[672] },  // Inst #1116 = BSEL_V
  { 4, &MipsDescs.OperandInfo[656] },  // Inst #1115 = BSELI_B
  { 2, &MipsDescs.OperandInfo[684] },  // Inst #1114 = BRSC_NM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1113 = BREAK_NM
  { 2, &MipsDescs.OperandInfo[13] },  // Inst #1112 = BREAK_MMR6
  { 2, &MipsDescs.OperandInfo[13] },  // Inst #1111 = BREAK_MM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1110 = BREAK16_NM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1109 = BREAK16_MMR6
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #1108 = BREAK16_MM
  { 2, &MipsDescs.OperandInfo[13] },  // Inst #1107 = BREAK
  { 1, &MipsDescs.OperandInfo[182] },  // Inst #1106 = BPOSGE32_MM
  { 1, &MipsDescs.OperandInfo[182] },  // Inst #1105 = BPOSGE32C_MMR3
  { 1, &MipsDescs.OperandInfo[182] },  // Inst #1104 = BPOSGE32
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #1103 = BOVC_MMR6
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #1102 = BOVC
  { 2, &MipsDescs.OperandInfo[682] },  // Inst #1101 = BNZ_W
  { 2, &MipsDescs.OperandInfo[676] },  // Inst #1100 = BNZ_V
  { 2, &MipsDescs.OperandInfo[680] },  // Inst #1099 = BNZ_H
  { 2, &MipsDescs.OperandInfo[678] },  // Inst #1098 = BNZ_D
  { 2, &MipsDescs.OperandInfo[676] },  // Inst #1097 = BNZ_B
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #1096 = BNVC_MMR6
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #1095 = BNVC
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #1094 = BNE_MM
  { 2, &MipsDescs.OperandInfo[609] },  // Inst #1093 = BNEZC_NM
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1092 = BNEZC_MMR6
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1091 = BNEZC_MM
  { 2, &MipsDescs.OperandInfo[352] },  // Inst #1090 = BNEZC64
  { 2, &MipsDescs.OperandInfo[654] },  // Inst #1089 = BNEZC16_NM
  { 2, &MipsDescs.OperandInfo[652] },  // Inst #1088 = BNEZC16_MMR6
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1087 = BNEZC
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1086 = BNEZALC_MMR6
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1085 = BNEZALC
  { 2, &MipsDescs.OperandInfo[652] },  // Inst #1084 = BNEZ16_MM
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #1083 = BNEL
  { 3, &MipsDescs.OperandInfo[631] },  // Inst #1082 = BNEIC_NM
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #1081 = BNEG_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #1080 = BNEG_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #1079 = BNEG_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #1078 = BNEG_B
  { 3, &MipsDescs.OperandInfo[593] },  // Inst #1077 = BNEGI_W
  { 3, &MipsDescs.OperandInfo[590] },  // Inst #1076 = BNEGI_H
  { 3, &MipsDescs.OperandInfo[587] },  // Inst #1075 = BNEGI_D
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #1074 = BNEGI_B
  { 3, &MipsDescs.OperandInfo[649] },  // Inst #1073 = BNECzero_NM
  { 3, &MipsDescs.OperandInfo[646] },  // Inst #1072 = BNEC_NM
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #1071 = BNEC_MMR6
  { 3, &MipsDescs.OperandInfo[344] },  // Inst #1070 = BNEC64
  { 3, &MipsDescs.OperandInfo[643] },  // Inst #1069 = BNEC16_NM
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #1068 = BNEC
  { 3, &MipsDescs.OperandInfo[344] },  // Inst #1067 = BNE64
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #1066 = BNE
  { 4, &MipsDescs.OperandInfo[672] },  // Inst #1065 = BMZ_V
  { 4, &MipsDescs.OperandInfo[656] },  // Inst #1064 = BMZI_B
  { 4, &MipsDescs.OperandInfo[672] },  // Inst #1063 = BMNZ_V
  { 4, &MipsDescs.OperandInfo[656] },  // Inst #1062 = BMNZI_B
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1061 = BLTZ_MM
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1060 = BLTZL
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1059 = BLTZC_MMR6
  { 2, &MipsDescs.OperandInfo[352] },  // Inst #1058 = BLTZC64
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1057 = BLTZC
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1056 = BLTZAL_MM
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1055 = BLTZALS_MM
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1054 = BLTZALL
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1053 = BLTZALC_MMR6
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1052 = BLTZALC
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1051 = BLTZAL
  { 2, &MipsDescs.OperandInfo[352] },  // Inst #1050 = BLTZ64
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1049 = BLTZ
  { 3, &MipsDescs.OperandInfo[646] },  // Inst #1048 = BLTUC_NM
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #1047 = BLTUC_MMR6
  { 3, &MipsDescs.OperandInfo[344] },  // Inst #1046 = BLTUC64
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #1045 = BLTUC
  { 3, &MipsDescs.OperandInfo[631] },  // Inst #1044 = BLTIUC_NM
  { 3, &MipsDescs.OperandInfo[631] },  // Inst #1043 = BLTIC_NM
  { 3, &MipsDescs.OperandInfo[646] },  // Inst #1042 = BLTC_NM
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #1041 = BLTC_MMR6
  { 3, &MipsDescs.OperandInfo[344] },  // Inst #1040 = BLTC64
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #1039 = BLTC
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1038 = BLEZ_MM
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1037 = BLEZL
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1036 = BLEZC_MMR6
  { 2, &MipsDescs.OperandInfo[352] },  // Inst #1035 = BLEZC64
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1034 = BLEZC
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1033 = BLEZALC_MMR6
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1032 = BLEZALC
  { 2, &MipsDescs.OperandInfo[352] },  // Inst #1031 = BLEZ64
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1030 = BLEZ
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1029 = BITSWAP_MMR6
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1028 = BITSWAP
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1027 = BITREV_MM
  { 2, &MipsDescs.OperandInfo[416] },  // Inst #1026 = BITREVW_NM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #1025 = BITREV
  { 4, &MipsDescs.OperandInfo[194] },  // Inst #1024 = BINSR_W
  { 4, &MipsDescs.OperandInfo[198] },  // Inst #1023 = BINSR_H
  { 4, &MipsDescs.OperandInfo[190] },  // Inst #1022 = BINSR_D
  { 4, &MipsDescs.OperandInfo[672] },  // Inst #1021 = BINSR_B
  { 4, &MipsDescs.OperandInfo[668] },  // Inst #1020 = BINSRI_W
  { 4, &MipsDescs.OperandInfo[664] },  // Inst #1019 = BINSRI_H
  { 4, &MipsDescs.OperandInfo[660] },  // Inst #1018 = BINSRI_D
  { 4, &MipsDescs.OperandInfo[656] },  // Inst #1017 = BINSRI_B
  { 4, &MipsDescs.OperandInfo[194] },  // Inst #1016 = BINSL_W
  { 4, &MipsDescs.OperandInfo[198] },  // Inst #1015 = BINSL_H
  { 4, &MipsDescs.OperandInfo[190] },  // Inst #1014 = BINSL_D
  { 4, &MipsDescs.OperandInfo[672] },  // Inst #1013 = BINSL_B
  { 4, &MipsDescs.OperandInfo[668] },  // Inst #1012 = BINSLI_W
  { 4, &MipsDescs.OperandInfo[664] },  // Inst #1011 = BINSLI_H
  { 4, &MipsDescs.OperandInfo[660] },  // Inst #1010 = BINSLI_D
  { 4, &MipsDescs.OperandInfo[656] },  // Inst #1009 = BINSLI_B
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1008 = BGTZ_MM
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1007 = BGTZL
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1006 = BGTZC_MMR6
  { 2, &MipsDescs.OperandInfo[352] },  // Inst #1005 = BGTZC64
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1004 = BGTZC
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1003 = BGTZALC_MMR6
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1002 = BGTZALC
  { 2, &MipsDescs.OperandInfo[352] },  // Inst #1001 = BGTZ64
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #1000 = BGTZ
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #999 = BGEZ_MM
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #998 = BGEZL
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #997 = BGEZC_MMR6
  { 2, &MipsDescs.OperandInfo[352] },  // Inst #996 = BGEZC64
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #995 = BGEZC
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #994 = BGEZAL_MM
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #993 = BGEZALS_MM
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #992 = BGEZALL
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #991 = BGEZALC_MMR6
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #990 = BGEZALC
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #989 = BGEZAL
  { 2, &MipsDescs.OperandInfo[352] },  // Inst #988 = BGEZ64
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #987 = BGEZ
  { 3, &MipsDescs.OperandInfo[646] },  // Inst #986 = BGEUC_NM
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #985 = BGEUC_MMR6
  { 3, &MipsDescs.OperandInfo[344] },  // Inst #984 = BGEUC64
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #983 = BGEUC
  { 3, &MipsDescs.OperandInfo[631] },  // Inst #982 = BGEIUC_NM
  { 3, &MipsDescs.OperandInfo[631] },  // Inst #981 = BGEIC_NM
  { 3, &MipsDescs.OperandInfo[646] },  // Inst #980 = BGEC_NM
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #979 = BGEC_MMR6
  { 3, &MipsDescs.OperandInfo[344] },  // Inst #978 = BGEC64
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #977 = BGEC
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #976 = BEQ_MM
  { 2, &MipsDescs.OperandInfo[609] },  // Inst #975 = BEQZC_NM
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #974 = BEQZC_MMR6
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #973 = BEQZC_MM
  { 2, &MipsDescs.OperandInfo[352] },  // Inst #972 = BEQZC64
  { 2, &MipsDescs.OperandInfo[654] },  // Inst #971 = BEQZC16_NM
  { 2, &MipsDescs.OperandInfo[652] },  // Inst #970 = BEQZC16_MMR6
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #969 = BEQZC
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #968 = BEQZALC_MMR6
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #967 = BEQZALC
  { 2, &MipsDescs.OperandInfo[652] },  // Inst #966 = BEQZ16_MM
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #965 = BEQL
  { 3, &MipsDescs.OperandInfo[631] },  // Inst #964 = BEQIC_NM
  { 3, &MipsDescs.OperandInfo[649] },  // Inst #963 = BEQCzero_NM
  { 3, &MipsDescs.OperandInfo[646] },  // Inst #962 = BEQC_NM
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #961 = BEQC_MMR6
  { 3, &MipsDescs.OperandInfo[344] },  // Inst #960 = BEQC64
  { 3, &MipsDescs.OperandInfo[643] },  // Inst #959 = BEQC16_NM
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #958 = BEQC
  { 3, &MipsDescs.OperandInfo[344] },  // Inst #957 = BEQ64
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #956 = BEQ
  { 1, &MipsDescs.OperandInfo[182] },  // Inst #955 = BC_NM
  { 1, &MipsDescs.OperandInfo[182] },  // Inst #954 = BC_MMR6
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #953 = BCLR_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #952 = BCLR_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #951 = BCLR_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #950 = BCLR_B
  { 3, &MipsDescs.OperandInfo[593] },  // Inst #949 = BCLRI_W
  { 3, &MipsDescs.OperandInfo[590] },  // Inst #948 = BCLRI_H
  { 3, &MipsDescs.OperandInfo[587] },  // Inst #947 = BCLRI_D
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #946 = BCLRI_B
  { 2, &MipsDescs.OperandInfo[641] },  // Inst #945 = BC2NEZC_MMR6
  { 2, &MipsDescs.OperandInfo[641] },  // Inst #944 = BC2NEZ
  { 2, &MipsDescs.OperandInfo[641] },  // Inst #943 = BC2EQZC_MMR6
  { 2, &MipsDescs.OperandInfo[641] },  // Inst #942 = BC2EQZ
  { 2, &MipsDescs.OperandInfo[639] },  // Inst #941 = BC1T_MM
  { 2, &MipsDescs.OperandInfo[639] },  // Inst #940 = BC1TL
  { 2, &MipsDescs.OperandInfo[639] },  // Inst #939 = BC1T
  { 2, &MipsDescs.OperandInfo[637] },  // Inst #938 = BC1NEZC_MMR6
  { 2, &MipsDescs.OperandInfo[637] },  // Inst #937 = BC1NEZ
  { 2, &MipsDescs.OperandInfo[639] },  // Inst #936 = BC1F_MM
  { 2, &MipsDescs.OperandInfo[639] },  // Inst #935 = BC1FL
  { 2, &MipsDescs.OperandInfo[639] },  // Inst #934 = BC1F
  { 2, &MipsDescs.OperandInfo[637] },  // Inst #933 = BC1EQZC_MMR6
  { 2, &MipsDescs.OperandInfo[637] },  // Inst #932 = BC1EQZ
  { 1, &MipsDescs.OperandInfo[182] },  // Inst #931 = BC16_NM
  { 1, &MipsDescs.OperandInfo[182] },  // Inst #930 = BC16_MMR6
  { 1, &MipsDescs.OperandInfo[182] },  // Inst #929 = BC
  { 3, &MipsDescs.OperandInfo[631] },  // Inst #928 = BBNEZC_NM
  { 3, &MipsDescs.OperandInfo[634] },  // Inst #927 = BBIT132
  { 3, &MipsDescs.OperandInfo[634] },  // Inst #926 = BBIT1
  { 3, &MipsDescs.OperandInfo[634] },  // Inst #925 = BBIT032
  { 3, &MipsDescs.OperandInfo[634] },  // Inst #924 = BBIT0
  { 3, &MipsDescs.OperandInfo[631] },  // Inst #923 = BBEQZC_NM
  { 2, &MipsDescs.OperandInfo[629] },  // Inst #922 = BALRSC_NM
  { 4, &MipsDescs.OperandInfo[614] },  // Inst #921 = BALIGN_MMR2
  { 4, &MipsDescs.OperandInfo[614] },  // Inst #920 = BALIGN
  { 1, &MipsDescs.OperandInfo[182] },  // Inst #919 = BALC_NM
  { 1, &MipsDescs.OperandInfo[182] },  // Inst #918 = BALC_MMR6
  { 1, &MipsDescs.OperandInfo[182] },  // Inst #917 = BALC16_NM
  { 1, &MipsDescs.OperandInfo[182] },  // Inst #916 = BALC
  { 1, &MipsDescs.OperandInfo[182] },  // Inst #915 = BAL
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #914 = BADDu
  { 1, &MipsDescs.OperandInfo[182] },  // Inst #913 = B16_MM
  { 3, &MipsDescs.OperandInfo[626] },  // Inst #912 = AndRxRxRy16
  { 3, &MipsDescs.OperandInfo[421] },  // Inst #911 = AdduRxRyRz16
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #910 = AddiuSpImmX16
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #909 = AddiuSpImm16
  { 3, &MipsDescs.OperandInfo[623] },  // Inst #908 = AddiuRxRyOffMemX16
  { 3, &MipsDescs.OperandInfo[620] },  // Inst #907 = AddiuRxRxImmX16
  { 3, &MipsDescs.OperandInfo[620] },  // Inst #906 = AddiuRxRxImm16
  { 2, &MipsDescs.OperandInfo[618] },  // Inst #905 = AddiuRxPcImmX16
  { 2, &MipsDescs.OperandInfo[618] },  // Inst #904 = AddiuRxImmX16
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #903 = AVE_U_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #902 = AVE_U_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #901 = AVE_U_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #900 = AVE_U_B
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #899 = AVE_S_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #898 = AVE_S_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #897 = AVE_S_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #896 = AVE_S_B
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #895 = AVER_U_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #894 = AVER_U_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #893 = AVER_U_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #892 = AVER_U_B
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #891 = AVER_S_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #890 = AVER_S_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #889 = AVER_S_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #888 = AVER_S_B
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #887 = AUI_MMR6
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #886 = AUIPC_MMR6
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #885 = AUIPC
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #884 = AUI
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #883 = ASUB_U_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #882 = ASUB_U_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #881 = ASUB_U_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #880 = ASUB_U_B
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #879 = ASUB_S_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #878 = ASUB_S_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #877 = ASUB_S_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #876 = ASUB_S_B
  { 4, &MipsDescs.OperandInfo[614] },  // Inst #875 = APPEND_MMR2
  { 4, &MipsDescs.OperandInfo[614] },  // Inst #874 = APPEND
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #873 = ANDi_MM
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #872 = ANDi64
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #871 = ANDi
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #870 = AND_V
  { 3, &MipsDescs.OperandInfo[596] },  // Inst #869 = AND_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #868 = AND_MMR6
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #867 = AND_MM
  { 3, &MipsDescs.OperandInfo[391] },  // Inst #866 = ANDI_NM
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #865 = ANDI_MMR6
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #864 = ANDI_B
  { 3, &MipsDescs.OperandInfo[566] },  // Inst #863 = ANDI16_NM
  { 3, &MipsDescs.OperandInfo[563] },  // Inst #862 = ANDI16_MMR6
  { 3, &MipsDescs.OperandInfo[563] },  // Inst #861 = ANDI16_MM
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #860 = AND64
  { 3, &MipsDescs.OperandInfo[599] },  // Inst #859 = AND16_NM
  { 3, &MipsDescs.OperandInfo[611] },  // Inst #858 = AND16_MMR6
  { 3, &MipsDescs.OperandInfo[611] },  // Inst #857 = AND16_MM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #856 = AND
  { 2, &MipsDescs.OperandInfo[609] },  // Inst #855 = ALUIPC_NM
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #854 = ALUIPC_MMR6
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #853 = ALUIPC
  { 4, &MipsDescs.OperandInfo[605] },  // Inst #852 = ALIGN_MMR6
  { 4, &MipsDescs.OperandInfo[605] },  // Inst #851 = ALIGN
  { 3, &MipsDescs.OperandInfo[596] },  // Inst #850 = ADDu_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #849 = ADDu_MM
  { 3, &MipsDescs.OperandInfo[602] },  // Inst #848 = ADDu4x4_NM
  { 3, &MipsDescs.OperandInfo[599] },  // Inst #847 = ADDu16_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #846 = ADDu
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #845 = ADDiu_MM
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #844 = ADDiu
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #843 = ADDi_MM
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #842 = ADDi
  { 3, &MipsDescs.OperandInfo[596] },  // Inst #841 = ADD_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #840 = ADD_MMR6
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #839 = ADD_MM
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #838 = ADD_A_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #837 = ADD_A_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #836 = ADD_A_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #835 = ADD_A_B
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #834 = ADDWC_MM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #833 = ADDWC
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #832 = ADDV_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #831 = ADDV_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #830 = ADDV_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #829 = ADDV_B
  { 3, &MipsDescs.OperandInfo[593] },  // Inst #828 = ADDVI_W
  { 3, &MipsDescs.OperandInfo[590] },  // Inst #827 = ADDVI_H
  { 3, &MipsDescs.OperandInfo[587] },  // Inst #826 = ADDVI_D
  { 3, &MipsDescs.OperandInfo[584] },  // Inst #825 = ADDVI_B
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #824 = ADDU_S_QB_MM
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #823 = ADDU_S_QB
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #822 = ADDU_S_PH_MMR2
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #821 = ADDU_S_PH
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #820 = ADDU_QB_MM
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #819 = ADDU_QB
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #818 = ADDU_PH_MMR2
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #817 = ADDU_PH
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #816 = ADDU_MMR6
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #815 = ADDUH_R_QB_MMR2
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #814 = ADDUH_R_QB
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #813 = ADDUH_QB_MMR2
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #812 = ADDUH_QB
  { 3, &MipsDescs.OperandInfo[581] },  // Inst #811 = ADDU16_MMR6
  { 3, &MipsDescs.OperandInfo[581] },  // Inst #810 = ADDU16_MM
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #809 = ADDS_U_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #808 = ADDS_U_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #807 = ADDS_U_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #806 = ADDS_U_B
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #805 = ADDS_S_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #804 = ADDS_S_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #803 = ADDS_S_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #802 = ADDS_S_B
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #801 = ADDS_A_W
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #800 = ADDS_A_H
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #799 = ADDS_A_D
  { 3, &MipsDescs.OperandInfo[578] },  // Inst #798 = ADDS_A_B
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #797 = ADDSC_MM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #796 = ADDSC
  { 3, &MipsDescs.OperandInfo[575] },  // Inst #795 = ADDR_PS64
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #794 = ADDQ_S_W_MM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #793 = ADDQ_S_W
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #792 = ADDQ_S_PH_MM
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #791 = ADDQ_S_PH
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #790 = ADDQ_PH_MM
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #789 = ADDQ_PH
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #788 = ADDQH_W_MMR2
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #787 = ADDQH_W
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #786 = ADDQH_R_W_MMR2
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #785 = ADDQH_R_W
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #784 = ADDQH_R_PH_MMR2
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #783 = ADDQH_R_PH
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #782 = ADDQH_PH_MMR2
  { 3, &MipsDescs.OperandInfo[572] },  // Inst #781 = ADDQH_PH
  { 3, &MipsDescs.OperandInfo[391] },  // Inst #780 = ADDIU_NM
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #779 = ADDIU_MMR6
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #778 = ADDIUSP_MM
  { 3, &MipsDescs.OperandInfo[569] },  // Inst #777 = ADDIUS5_MM
  { 3, &MipsDescs.OperandInfo[552] },  // Inst #776 = ADDIURS5_NM
  { 3, &MipsDescs.OperandInfo[566] },  // Inst #775 = ADDIUR2_NM
  { 3, &MipsDescs.OperandInfo[563] },  // Inst #774 = ADDIUR2_MM
  { 3, &MipsDescs.OperandInfo[560] },  // Inst #773 = ADDIUR1SP_NM
  { 2, &MipsDescs.OperandInfo[558] },  // Inst #772 = ADDIUR1SP_MM
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #771 = ADDIUPC_MMR6
  { 2, &MipsDescs.OperandInfo[558] },  // Inst #770 = ADDIUPC_MM
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #769 = ADDIUPC
  { 3, &MipsDescs.OperandInfo[391] },  // Inst #768 = ADDIUNEG_NM
  { 3, &MipsDescs.OperandInfo[555] },  // Inst #767 = ADDIUGPW_NM
  { 3, &MipsDescs.OperandInfo[555] },  // Inst #766 = ADDIUGPB_NM
  { 3, &MipsDescs.OperandInfo[391] },  // Inst #765 = ADDIUGP48_NM
  { 3, &MipsDescs.OperandInfo[552] },  // Inst #764 = ADDIU48_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #763 = ADD
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #762 = ABSQ_S_W_MM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #761 = ABSQ_S_W
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #760 = ABSQ_S_QB_MMR2
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #759 = ABSQ_S_QB
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #758 = ABSQ_S_PH_MM
  { 2, &MipsDescs.OperandInfo[550] },  // Inst #757 = ABSQ_S_PH
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #756 = XOR_V_W_PSEUDO
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #755 = XOR_V_H_PSEUDO
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #754 = XOR_V_D_PSEUDO
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #753 = Usw
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #752 = Ush
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #751 = Ulw
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #750 = Ulhu
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #749 = Ulh
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #748 = URemMacro
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #747 = URemIMacro
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #746 = UDivMacro
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #745 = UDivIMacro
  { 3, &MipsDescs.OperandInfo[460] },  // Inst #744 = UDIV_MM_Pseudo
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #743 = TRAP_MM
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #742 = TRAP
  { 1, &MipsDescs.OperandInfo[182] },  // Inst #741 = TAILCALL_NM
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #740 = TAILCALL_MMR6
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #739 = TAILCALL_MM
  { 1, &MipsDescs.OperandInfo[418] },  // Inst #738 = TAILCALLREG_NM
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #737 = TAILCALLREG_MMR6
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #736 = TAILCALLREG_MM
  { 1, &MipsDescs.OperandInfo[310] },  // Inst #735 = TAILCALLREGHB64
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #734 = TAILCALLREGHB
  { 1, &MipsDescs.OperandInfo[310] },  // Inst #733 = TAILCALLREG64
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #732 = TAILCALLREG
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #731 = TAILCALLR6REG
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #730 = TAILCALLHBR6REG
  { 1, &MipsDescs.OperandInfo[310] },  // Inst #729 = TAILCALLHB64R6REG
  { 1, &MipsDescs.OperandInfo[310] },  // Inst #728 = TAILCALL64R6REG
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #727 = TAILCALL
  { 3, &MipsDescs.OperandInfo[421] },  // Inst #726 = SltuRxRyRz16
  { 3, &MipsDescs.OperandInfo[421] },  // Inst #725 = SltuCCRxRy16
  { 3, &MipsDescs.OperandInfo[547] },  // Inst #724 = SltiuCCRxImmX16
  { 3, &MipsDescs.OperandInfo[547] },  // Inst #723 = SltiCCRxImmX16
  { 3, &MipsDescs.OperandInfo[421] },  // Inst #722 = SltCCRxRy16
  { 5, &MipsDescs.OperandInfo[537] },  // Inst #721 = SelTBtneZSltu
  { 5, &MipsDescs.OperandInfo[542] },  // Inst #720 = SelTBtneZSltiu
  { 5, &MipsDescs.OperandInfo[542] },  // Inst #719 = SelTBtneZSlti
  { 5, &MipsDescs.OperandInfo[537] },  // Inst #718 = SelTBtneZSlt
  { 5, &MipsDescs.OperandInfo[542] },  // Inst #717 = SelTBtneZCmpi
  { 5, &MipsDescs.OperandInfo[537] },  // Inst #716 = SelTBtneZCmp
  { 5, &MipsDescs.OperandInfo[537] },  // Inst #715 = SelTBteqZSltu
  { 5, &MipsDescs.OperandInfo[542] },  // Inst #714 = SelTBteqZSltiu
  { 5, &MipsDescs.OperandInfo[542] },  // Inst #713 = SelTBteqZSlti
  { 5, &MipsDescs.OperandInfo[537] },  // Inst #712 = SelTBteqZSlt
  { 5, &MipsDescs.OperandInfo[542] },  // Inst #711 = SelTBteqZCmpi
  { 5, &MipsDescs.OperandInfo[537] },  // Inst #710 = SelTBteqZCmp
  { 4, &MipsDescs.OperandInfo[533] },  // Inst #709 = SelBneZ
  { 4, &MipsDescs.OperandInfo[533] },  // Inst #708 = SelBeqZ
  { 3, &MipsDescs.OperandInfo[361] },  // Inst #707 = SaadAddr
  { 3, &MipsDescs.OperandInfo[361] },  // Inst #706 = SaaAddr
  { 2, &MipsDescs.OperandInfo[531] },  // Inst #705 = SZ_W_PSEUDO
  { 2, &MipsDescs.OperandInfo[525] },  // Inst #704 = SZ_V_PSEUDO
  { 2, &MipsDescs.OperandInfo[529] },  // Inst #703 = SZ_H_PSEUDO
  { 2, &MipsDescs.OperandInfo[527] },  // Inst #702 = SZ_D_PSEUDO
  { 2, &MipsDescs.OperandInfo[525] },  // Inst #701 = SZ_B_PSEUDO
  { 3, &MipsDescs.OperandInfo[354] },  // Inst #700 = SWM_MM
  { 3, &MipsDescs.OperandInfo[321] },  // Inst #699 = ST_F16
  { 3, &MipsDescs.OperandInfo[318] },  // Inst #698 = STR_W
  { 3, &MipsDescs.OperandInfo[315] },  // Inst #697 = STR_D
  { 3, &MipsDescs.OperandInfo[333] },  // Inst #696 = STORE_CCOND_DSP
  { 3, &MipsDescs.OperandInfo[330] },  // Inst #695 = STORE_ACC64DSP
  { 3, &MipsDescs.OperandInfo[327] },  // Inst #694 = STORE_ACC64
  { 3, &MipsDescs.OperandInfo[324] },  // Inst #693 = STORE_ACC128
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #692 = SRemMacro
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #691 = SRemIMacro
  { 2, &MipsDescs.OperandInfo[531] },  // Inst #690 = SNZ_W_PSEUDO
  { 2, &MipsDescs.OperandInfo[525] },  // Inst #689 = SNZ_V_PSEUDO
  { 2, &MipsDescs.OperandInfo[529] },  // Inst #688 = SNZ_H_PSEUDO
  { 2, &MipsDescs.OperandInfo[527] },  // Inst #687 = SNZ_D_PSEUDO
  { 2, &MipsDescs.OperandInfo[525] },  // Inst #686 = SNZ_B_PSEUDO
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #685 = SNEMacro
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #684 = SNEIMacro
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #683 = SLTUImm64
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #682 = SLTImm64
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #681 = SLEUImm64
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #680 = SLEUImm
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #679 = SLEU
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #678 = SLEImm64
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #677 = SLEImm
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #676 = SLE
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #675 = SGTUImm64
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #674 = SGTUImm
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #673 = SGTImm64
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #672 = SGTImm
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #671 = SGEUImm64
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #670 = SGEUImm
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #669 = SGEU
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #668 = SGEImm64
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #667 = SGEImm
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #666 = SGE
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #665 = SEQMacro
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #664 = SEQIMacro
  { 3, &MipsDescs.OperandInfo[522] },  // Inst #663 = SDivMacro
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #662 = SDivIMacro
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #661 = SDMacro
  { 3, &MipsDescs.OperandInfo[460] },  // Inst #660 = SDIV_MM_Pseudo
  { 3, &MipsDescs.OperandInfo[519] },  // Inst #659 = SDC1_M1
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #658 = RetRA16
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #657 = RetRA
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #656 = RORImm
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #655 = ROR
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #654 = ROLImm
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #653 = ROL
  { 3, &MipsDescs.OperandInfo[460] },  // Inst #652 = PseudoUDIV
  { 3, &MipsDescs.OperandInfo[516] },  // Inst #651 = PseudoTRUNC_W_S
  { 3, &MipsDescs.OperandInfo[513] },  // Inst #650 = PseudoTRUNC_W_D32
  { 3, &MipsDescs.OperandInfo[510] },  // Inst #649 = PseudoTRUNC_W_D
  { 3, &MipsDescs.OperandInfo[391] },  // Inst #648 = PseudoSUBU_NM
  { 4, &MipsDescs.OperandInfo[506] },  // Inst #647 = PseudoSELECT_S
  { 4, &MipsDescs.OperandInfo[502] },  // Inst #646 = PseudoSELECT_I64
  { 4, &MipsDescs.OperandInfo[498] },  // Inst #645 = PseudoSELECT_I
  { 4, &MipsDescs.OperandInfo[494] },  // Inst #644 = PseudoSELECT_D64
  { 4, &MipsDescs.OperandInfo[490] },  // Inst #643 = PseudoSELECT_D32
  { 4, &MipsDescs.OperandInfo[486] },  // Inst #642 = PseudoSELECTFP_T_S
  { 4, &MipsDescs.OperandInfo[482] },  // Inst #641 = PseudoSELECTFP_T_I64
  { 4, &MipsDescs.OperandInfo[478] },  // Inst #640 = PseudoSELECTFP_T_I
  { 4, &MipsDescs.OperandInfo[474] },  // Inst #639 = PseudoSELECTFP_T_D64
  { 4, &MipsDescs.OperandInfo[470] },  // Inst #638 = PseudoSELECTFP_T_D32
  { 4, &MipsDescs.OperandInfo[486] },  // Inst #637 = PseudoSELECTFP_F_S
  { 4, &MipsDescs.OperandInfo[482] },  // Inst #636 = PseudoSELECTFP_F_I64
  { 4, &MipsDescs.OperandInfo[478] },  // Inst #635 = PseudoSELECTFP_F_I
  { 4, &MipsDescs.OperandInfo[474] },  // Inst #634 = PseudoSELECTFP_F_D64
  { 4, &MipsDescs.OperandInfo[470] },  // Inst #633 = PseudoSELECTFP_F_D32
  { 3, &MipsDescs.OperandInfo[460] },  // Inst #632 = PseudoSDIV
  { 1, &MipsDescs.OperandInfo[311] },  // Inst #631 = PseudoReturnNM
  { 1, &MipsDescs.OperandInfo[310] },  // Inst #630 = PseudoReturn64
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #629 = PseudoReturn
  { 4, &MipsDescs.OperandInfo[466] },  // Inst #628 = PseudoPICK_QB
  { 4, &MipsDescs.OperandInfo[466] },  // Inst #627 = PseudoPICK_PH
  { 3, &MipsDescs.OperandInfo[460] },  // Inst #626 = PseudoMULTu_MM
  { 3, &MipsDescs.OperandInfo[460] },  // Inst #625 = PseudoMULTu
  { 3, &MipsDescs.OperandInfo[460] },  // Inst #624 = PseudoMULT_MM
  { 3, &MipsDescs.OperandInfo[460] },  // Inst #623 = PseudoMULT
  { 3, &MipsDescs.OperandInfo[460] },  // Inst #622 = PseudoMTLOHI_MM
  { 3, &MipsDescs.OperandInfo[463] },  // Inst #621 = PseudoMTLOHI_DSP
  { 3, &MipsDescs.OperandInfo[433] },  // Inst #620 = PseudoMTLOHI64
  { 3, &MipsDescs.OperandInfo[460] },  // Inst #619 = PseudoMTLOHI
  { 4, &MipsDescs.OperandInfo[452] },  // Inst #618 = PseudoMSUB_MM
  { 4, &MipsDescs.OperandInfo[452] },  // Inst #617 = PseudoMSUBU_MM
  { 4, &MipsDescs.OperandInfo[452] },  // Inst #616 = PseudoMSUBU
  { 4, &MipsDescs.OperandInfo[452] },  // Inst #615 = PseudoMSUB
  { 2, &MipsDescs.OperandInfo[456] },  // Inst #614 = PseudoMFLO_MM
  { 2, &MipsDescs.OperandInfo[458] },  // Inst #613 = PseudoMFLO64
  { 2, &MipsDescs.OperandInfo[456] },  // Inst #612 = PseudoMFLO
  { 2, &MipsDescs.OperandInfo[456] },  // Inst #611 = PseudoMFHI_MM
  { 2, &MipsDescs.OperandInfo[458] },  // Inst #610 = PseudoMFHI64
  { 2, &MipsDescs.OperandInfo[456] },  // Inst #609 = PseudoMFHI
  { 4, &MipsDescs.OperandInfo[452] },  // Inst #608 = PseudoMADD_MM
  { 4, &MipsDescs.OperandInfo[452] },  // Inst #607 = PseudoMADDU_MM
  { 4, &MipsDescs.OperandInfo[452] },  // Inst #606 = PseudoMADDU
  { 4, &MipsDescs.OperandInfo[452] },  // Inst #605 = PseudoMADD
  { 2, &MipsDescs.OperandInfo[450] },  // Inst #604 = PseudoLI_NM
  { 2, &MipsDescs.OperandInfo[450] },  // Inst #603 = PseudoLA_NM
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #602 = PseudoIndrectHazardBranchR6
  { 1, &MipsDescs.OperandInfo[310] },  // Inst #601 = PseudoIndrectHazardBranch64R6
  { 1, &MipsDescs.OperandInfo[310] },  // Inst #600 = PseudoIndirectHazardBranch64
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #599 = PseudoIndirectHazardBranch
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #598 = PseudoIndirectBranch_MMR6
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #597 = PseudoIndirectBranch_MM
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #596 = PseudoIndirectBranchR6
  { 1, &MipsDescs.OperandInfo[311] },  // Inst #595 = PseudoIndirectBranchNM
  { 1, &MipsDescs.OperandInfo[310] },  // Inst #594 = PseudoIndirectBranch64R6
  { 1, &MipsDescs.OperandInfo[310] },  // Inst #593 = PseudoIndirectBranch64
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #592 = PseudoIndirectBranch
  { 7, &MipsDescs.OperandInfo[443] },  // Inst #591 = PseudoD_SELECT_I64
  { 7, &MipsDescs.OperandInfo[436] },  // Inst #590 = PseudoD_SELECT_I
  { 3, &MipsDescs.OperandInfo[433] },  // Inst #589 = PseudoDUDIV
  { 3, &MipsDescs.OperandInfo[433] },  // Inst #588 = PseudoDSDIV
  { 3, &MipsDescs.OperandInfo[433] },  // Inst #587 = PseudoDMULTu
  { 3, &MipsDescs.OperandInfo[433] },  // Inst #586 = PseudoDMULT
  { 2, &MipsDescs.OperandInfo[414] },  // Inst #585 = PseudoCVT_S_W
  { 2, &MipsDescs.OperandInfo[429] },  // Inst #584 = PseudoCVT_S_L
  { 2, &MipsDescs.OperandInfo[431] },  // Inst #583 = PseudoCVT_D64_W
  { 2, &MipsDescs.OperandInfo[429] },  // Inst #582 = PseudoCVT_D64_L
  { 2, &MipsDescs.OperandInfo[427] },  // Inst #581 = PseudoCVT_D32_W
  { 3, &MipsDescs.OperandInfo[424] },  // Inst #580 = PseudoCMP_LT_PH
  { 3, &MipsDescs.OperandInfo[424] },  // Inst #579 = PseudoCMP_LE_PH
  { 3, &MipsDescs.OperandInfo[424] },  // Inst #578 = PseudoCMP_EQ_PH
  { 3, &MipsDescs.OperandInfo[424] },  // Inst #577 = PseudoCMPU_LT_QB
  { 3, &MipsDescs.OperandInfo[424] },  // Inst #576 = PseudoCMPU_LE_QB
  { 3, &MipsDescs.OperandInfo[424] },  // Inst #575 = PseudoCMPU_EQ_QB
  { 3, &MipsDescs.OperandInfo[391] },  // Inst #574 = PseudoANDI_NM
  { 3, &MipsDescs.OperandInfo[391] },  // Inst #573 = PseudoADDIU_NM
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #572 = OR_V_W_PSEUDO
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #571 = OR_V_H_PSEUDO
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #570 = OR_V_D_PSEUDO
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #569 = NOR_V_W_PSEUDO
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #568 = NOR_V_H_PSEUDO
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #567 = NOR_V_D_PSEUDO
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #566 = NORImm64
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #565 = NORImm
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #564 = NOP
  { 3, &MipsDescs.OperandInfo[421] },  // Inst #563 = MultuRxRyRz16
  { 2, &MipsDescs.OperandInfo[419] },  // Inst #562 = MultuRxRy16
  { 3, &MipsDescs.OperandInfo[421] },  // Inst #561 = MultRxRyRz16
  { 2, &MipsDescs.OperandInfo[419] },  // Inst #560 = MultRxRy16
  { 1, &MipsDescs.OperandInfo[182] },  // Inst #559 = MUSTTAILCALL_NM
  { 1, &MipsDescs.OperandInfo[418] },  // Inst #558 = MUSTTAILCALLREG_NM
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #557 = MULOUMacro
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #556 = MULOMacro
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #555 = MULImmMacro
  { 2, &MipsDescs.OperandInfo[406] },  // Inst #554 = MTTLO_NM
  { 2, &MipsDescs.OperandInfo[404] },  // Inst #553 = MTTLO
  { 2, &MipsDescs.OperandInfo[406] },  // Inst #552 = MTTHI_NM
  { 2, &MipsDescs.OperandInfo[404] },  // Inst #551 = MTTHI
  { 2, &MipsDescs.OperandInfo[414] },  // Inst #550 = MTTHC1
  { 2, &MipsDescs.OperandInfo[416] },  // Inst #549 = MTTGPR_NM
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #548 = MTTGPR
  { 1, &MipsDescs.OperandInfo[311] },  // Inst #547 = MTTDSP_NM
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #546 = MTTDSP
  { 2, &MipsDescs.OperandInfo[414] },  // Inst #545 = MTTC1
  { 3, &MipsDescs.OperandInfo[411] },  // Inst #544 = MTTC0_NM
  { 3, &MipsDescs.OperandInfo[408] },  // Inst #543 = MTTC0
  { 2, &MipsDescs.OperandInfo[406] },  // Inst #542 = MTTACX_NM
  { 2, &MipsDescs.OperandInfo[404] },  // Inst #541 = MTTACX
  { 2, &MipsDescs.OperandInfo[402] },  // Inst #540 = MSA_FP_ROUND_W_PSEUDO
  { 2, &MipsDescs.OperandInfo[400] },  // Inst #539 = MSA_FP_ROUND_D_PSEUDO
  { 2, &MipsDescs.OperandInfo[398] },  // Inst #538 = MSA_FP_EXTEND_W_PSEUDO
  { 2, &MipsDescs.OperandInfo[396] },  // Inst #537 = MSA_FP_EXTEND_D_PSEUDO
  { 2, &MipsDescs.OperandInfo[394] },  // Inst #536 = MIPSeh_return64
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #535 = MIPSeh_return32
  { 2, &MipsDescs.OperandInfo[381] },  // Inst #534 = MFTLO_NM
  { 2, &MipsDescs.OperandInfo[379] },  // Inst #533 = MFTLO
  { 2, &MipsDescs.OperandInfo[381] },  // Inst #532 = MFTHI_NM
  { 2, &MipsDescs.OperandInfo[379] },  // Inst #531 = MFTHI
  { 2, &MipsDescs.OperandInfo[389] },  // Inst #530 = MFTHC1
  { 3, &MipsDescs.OperandInfo[391] },  // Inst #529 = MFTGPR_NM
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #528 = MFTGPR
  { 1, &MipsDescs.OperandInfo[311] },  // Inst #527 = MFTDSP_NM
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #526 = MFTDSP
  { 2, &MipsDescs.OperandInfo[389] },  // Inst #525 = MFTC1
  { 3, &MipsDescs.OperandInfo[386] },  // Inst #524 = MFTC0_NM
  { 3, &MipsDescs.OperandInfo[383] },  // Inst #523 = MFTC0
  { 2, &MipsDescs.OperandInfo[381] },  // Inst #522 = MFTACX_NM
  { 2, &MipsDescs.OperandInfo[379] },  // Inst #521 = MFTACX
  { 3, &MipsDescs.OperandInfo[376] },  // Inst #520 = LwConstant32
  { 4, &MipsDescs.OperandInfo[372] },  // Inst #519 = LoadJumpTableOffset
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #518 = LoadImmSingleGPR
  { 2, &MipsDescs.OperandInfo[370] },  // Inst #517 = LoadImmSingleFGR
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #516 = LoadImmDoubleGPR
  { 2, &MipsDescs.OperandInfo[368] },  // Inst #515 = LoadImmDoubleFGR_32
  { 2, &MipsDescs.OperandInfo[366] },  // Inst #514 = LoadImmDoubleFGR
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #513 = LoadImm64
  { 2, &MipsDescs.OperandInfo[364] },  // Inst #512 = LoadImm32
  { 3, &MipsDescs.OperandInfo[361] },  // Inst #511 = LoadAddrReg64
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #510 = LoadAddrReg32
  { 2, &MipsDescs.OperandInfo[359] },  // Inst #509 = LoadAddrImm64
  { 2, &MipsDescs.OperandInfo[357] },  // Inst #508 = LoadAddrImm32
  { 3, &MipsDescs.OperandInfo[354] },  // Inst #507 = LWM_MM
  { 2, &MipsDescs.OperandInfo[352] },  // Inst #506 = LONG_BRANCH_LUi2Op_64
  { 2, &MipsDescs.OperandInfo[350] },  // Inst #505 = LONG_BRANCH_LUi2Op
  { 3, &MipsDescs.OperandInfo[347] },  // Inst #504 = LONG_BRANCH_LUi
  { 3, &MipsDescs.OperandInfo[344] },  // Inst #503 = LONG_BRANCH_DADDiu2Op
  { 4, &MipsDescs.OperandInfo[340] },  // Inst #502 = LONG_BRANCH_DADDiu
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #501 = LONG_BRANCH_ADDiu2Op
  { 4, &MipsDescs.OperandInfo[336] },  // Inst #500 = LONG_BRANCH_ADDiu
  { 3, &MipsDescs.OperandInfo[333] },  // Inst #499 = LOAD_CCOND_DSP
  { 3, &MipsDescs.OperandInfo[330] },  // Inst #498 = LOAD_ACC64DSP
  { 3, &MipsDescs.OperandInfo[327] },  // Inst #497 = LOAD_ACC64
  { 3, &MipsDescs.OperandInfo[324] },  // Inst #496 = LOAD_ACC128
  { 3, &MipsDescs.OperandInfo[321] },  // Inst #495 = LD_F16
  { 3, &MipsDescs.OperandInfo[318] },  // Inst #494 = LDR_W
  { 3, &MipsDescs.OperandInfo[315] },  // Inst #493 = LDR_D
  { 3, &MipsDescs.OperandInfo[312] },  // Inst #492 = LDMacro
  { 2, &MipsDescs.OperandInfo[140] },  // Inst #491 = JalTwoReg
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #490 = JalOneReg
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #489 = JAL_MMR6
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #488 = JALRPseudo
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #487 = JALRHBPseudo
  { 1, &MipsDescs.OperandInfo[310] },  // Inst #486 = JALRHB64Pseudo
  { 1, &MipsDescs.OperandInfo[311] },  // Inst #485 = JALRCPseudo
  { 1, &MipsDescs.OperandInfo[310] },  // Inst #484 = JALR64Pseudo
  { 4, &MipsDescs.OperandInfo[306] },  // Inst #483 = INSERT_W_VIDX_PSEUDO
  { 4, &MipsDescs.OperandInfo[302] },  // Inst #482 = INSERT_W_VIDX64_PSEUDO
  { 4, &MipsDescs.OperandInfo[298] },  // Inst #481 = INSERT_H_VIDX_PSEUDO
  { 4, &MipsDescs.OperandInfo[294] },  // Inst #480 = INSERT_H_VIDX64_PSEUDO
  { 4, &MipsDescs.OperandInfo[290] },  // Inst #479 = INSERT_FW_VIDX_PSEUDO
  { 4, &MipsDescs.OperandInfo[286] },  // Inst #478 = INSERT_FW_VIDX64_PSEUDO
  { 4, &MipsDescs.OperandInfo[282] },  // Inst #477 = INSERT_FW_PSEUDO
  { 4, &MipsDescs.OperandInfo[278] },  // Inst #476 = INSERT_FD_VIDX_PSEUDO
  { 4, &MipsDescs.OperandInfo[274] },  // Inst #475 = INSERT_FD_VIDX64_PSEUDO
  { 4, &MipsDescs.OperandInfo[270] },  // Inst #474 = INSERT_FD_PSEUDO
  { 4, &MipsDescs.OperandInfo[266] },  // Inst #473 = INSERT_D_VIDX_PSEUDO
  { 4, &MipsDescs.OperandInfo[262] },  // Inst #472 = INSERT_D_VIDX64_PSEUDO
  { 4, &MipsDescs.OperandInfo[258] },  // Inst #471 = INSERT_B_VIDX_PSEUDO
  { 4, &MipsDescs.OperandInfo[254] },  // Inst #470 = INSERT_B_VIDX64_PSEUDO
  { 4, &MipsDescs.OperandInfo[250] },  // Inst #469 = GotPrologue16
  { 2, &MipsDescs.OperandInfo[248] },  // Inst #468 = FILL_FW_PSEUDO
  { 2, &MipsDescs.OperandInfo[246] },  // Inst #467 = FILL_FD_PSEUDO
  { 2, &MipsDescs.OperandInfo[244] },  // Inst #466 = FEXP2_W_1_PSEUDO
  { 2, &MipsDescs.OperandInfo[242] },  // Inst #465 = FEXP2_D_1_PSEUDO
  { 2, &MipsDescs.OperandInfo[244] },  // Inst #464 = FABS_W
  { 2, &MipsDescs.OperandInfo[242] },  // Inst #463 = FABS_D
  { 3, &MipsDescs.OperandInfo[239] },  // Inst #462 = ExtractElementF64_64
  { 3, &MipsDescs.OperandInfo[236] },  // Inst #461 = ExtractElementF64
  { 0, &MipsDescs.OperandInfo[1] },  // Inst #460 = ERet
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #459 = DURemMacro
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #458 = DURemIMacro
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #457 = DUDivMacro
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #456 = DUDivIMacro
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #455 = DSRemMacro
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #454 = DSRemIMacro
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #453 = DSDivMacro
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #452 = DSDivIMacro
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #451 = DRORImm
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #450 = DROR
  { 3, &MipsDescs.OperandInfo[233] },  // Inst #449 = DROLImm
  { 3, &MipsDescs.OperandInfo[230] },  // Inst #448 = DROL
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #447 = DMULOUMacro
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #446 = DMULOMacro
  { 3, &MipsDescs.OperandInfo[227] },  // Inst #445 = DMULMacro
  { 3, &MipsDescs.OperandInfo[224] },  // Inst #444 = DMULImmMacro
  { 1, &MipsDescs.OperandInfo[0] },  // Inst #443 = Constant32
  { 2, &MipsDescs.OperandInfo[222] },  // Inst #442 = CTTC1
  { 3, &MipsDescs.OperandInfo[219] },  // Inst #441 = COPY_FW_PSEUDO
  { 3, &MipsDescs.OperandInfo[216] },  // Inst #440 = COPY_FD_PSEUDO
  { 3, &MipsDescs.OperandInfo[2] },  // Inst #439 = CONSTPOOL_ENTRY
  { 2, &MipsDescs.OperandInfo[214] },  // Inst #438 = CFTC1
  { 3, &MipsDescs.OperandInfo[211] },  // Inst #437 = BuildPairF64_64
  { 3, &MipsDescs.OperandInfo[208] },  // Inst #436 = BuildPairF64
  { 3, &MipsDescs.OperandInfo[202] },  // Inst #435 = BtnezT8SltuX16
  { 3, &MipsDescs.OperandInfo[205] },  // Inst #434 = BtnezT8SltiuX16
  { 3, &MipsDescs.OperandInfo[205] },  // Inst #433 = BtnezT8SltiX16
  { 3, &MipsDescs.OperandInfo[202] },  // Inst #432 = BtnezT8SltX16
  { 3, &MipsDescs.OperandInfo[205] },  // Inst #431 = BtnezT8CmpiX16
  { 3, &MipsDescs.OperandInfo[202] },  // Inst #430 = BtnezT8CmpX16
  { 3, &MipsDescs.OperandInfo[202] },  // Inst #429 = BteqzT8SltuX16
  { 3, &MipsDescs.OperandInfo[205] },  // Inst #428 = BteqzT8SltiuX16
  { 3, &MipsDescs.OperandInfo[205] },  // Inst #427 = BteqzT8SltiX16
  { 3, &MipsDescs.OperandInfo[202] },  // Inst #426 = BteqzT8SltX16
  { 3, &MipsDescs.OperandInfo[205] },  // Inst #425 = BteqzT8CmpiX16
  { 3, &MipsDescs.OperandInfo[202] },  // Inst #424 = BteqzT8CmpX16
  { 3, &MipsDescs.OperandInfo[183] },  // Inst #423 = BneImm
  { 3, &MipsDescs.OperandInfo[183] },  // Inst #422 = BeqImm
  { 1, &MipsDescs.OperandInfo[182] },  // Inst #421 = B_MM_Pseudo
  { 1, &MipsDescs.OperandInfo[182] },  // Inst #420 = B_MMR6_Pseudo
  { 1, &MipsDescs.OperandInfo[182] },  // Inst #419 = B_MM
  { 4, &MipsDescs.OperandInfo[194] },  // Inst #418 = BSEL_W_PSEUDO
  { 4, &MipsDescs.OperandInfo[198] },  // Inst #417 = BSEL_H_PSEUDO
  { 4, &MipsDescs.OperandInfo[194] },  // Inst #416 = BSEL_FW_PSEUDO
  { 4, &MipsDescs.OperandInfo[190] },  // Inst #415 = BSEL_FD_PSEUDO
  { 4, &MipsDescs.OperandInfo[190] },  // Inst #414 = BSEL_D_PSEUDO
  { 1, &MipsDescs.OperandInfo[189] },  // Inst #413 = BPOSGE32_PSEUDO
  { 3, &MipsDescs.OperandInfo[183] },  // Inst #412 = BNELImmMacro
  { 3, &MipsDescs.OperandInfo[183] },  // Inst #411 = BLTULImmMacro
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #410 = BLTUL
  { 3, &MipsDescs.OperandInfo[183] },  // Inst #409 = BLTUImmMacro
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #408 = BLTU
  { 3, &MipsDescs.OperandInfo[183] },  // Inst #407 = BLTLImmMacro
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #406 = BLTL
  { 3, &MipsDescs.OperandInfo[183] },  // Inst #405 = BLTImmMacro
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #404 = BLT
  { 3, &MipsDescs.OperandInfo[183] },  // Inst #403 = BLEULImmMacro
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #402 = BLEUL
  { 3, &MipsDescs.OperandInfo[183] },  // Inst #401 = BLEUImmMacro
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #400 = BLEU
  { 3, &MipsDescs.OperandInfo[183] },  // Inst #399 = BLELImmMacro
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #398 = BLEL
  { 3, &MipsDescs.OperandInfo[183] },  // Inst #397 = BLEImmMacro
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #396 = BLE
  { 3, &MipsDescs.OperandInfo[183] },  // Inst #395 = BGTULImmMacro
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #394 = BGTUL
  { 3, &MipsDescs.OperandInfo[183] },  // Inst #393 = BGTUImmMacro
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #392 = BGTU
  { 3, &MipsDescs.OperandInfo[183] },  // Inst #391 = BGTLImmMacro
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #390 = BGTL
  { 3, &MipsDescs.OperandInfo[183] },  // Inst #389 = BGTImmMacro
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #388 = BGT
  { 3, &MipsDescs.OperandInfo[183] },  // Inst #387 = BGEULImmMacro
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #386 = BGEUL
  { 3, &MipsDescs.OperandInfo[183] },  // Inst #385 = BGEUImmMacro
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #384 = BGEU
  { 3, &MipsDescs.OperandInfo[183] },  // Inst #383 = BGELImmMacro
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #382 = BGEL
  { 3, &MipsDescs.OperandInfo[183] },  // Inst #381 = BGEImmMacro
  { 3, &MipsDescs.OperandInfo[186] },  // Inst #380 = BGE
  { 3, &MipsDescs.OperandInfo[183] },  // Inst #379 = BEQLImmMacro
  { 1, &MipsDescs.OperandInfo[182] },  // Inst #378 = BAL_BR_MM
  { 1, &MipsDescs.OperandInfo[182] },  // Inst #377 = BAL_BR
  { 1, &MipsDescs.OperandInfo[182] },  // Inst #376 = B
  { 6, &MipsDescs.OperandInfo[173] },  // Inst #375 = ATOMIC_SWAP_I8_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #374 = ATOMIC_SWAP_I8
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #373 = ATOMIC_SWAP_I64_POSTRA
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #372 = ATOMIC_SWAP_I64
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #371 = ATOMIC_SWAP_I32_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #370 = ATOMIC_SWAP_I32
  { 6, &MipsDescs.OperandInfo[173] },  // Inst #369 = ATOMIC_SWAP_I16_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #368 = ATOMIC_SWAP_I16
  { 6, &MipsDescs.OperandInfo[173] },  // Inst #367 = ATOMIC_LOAD_XOR_I8_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #366 = ATOMIC_LOAD_XOR_I8
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #365 = ATOMIC_LOAD_XOR_I64_POSTRA
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #364 = ATOMIC_LOAD_XOR_I64
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #363 = ATOMIC_LOAD_XOR_I32_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #362 = ATOMIC_LOAD_XOR_I32
  { 6, &MipsDescs.OperandInfo[173] },  // Inst #361 = ATOMIC_LOAD_XOR_I16_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #360 = ATOMIC_LOAD_XOR_I16
  { 6, &MipsDescs.OperandInfo[173] },  // Inst #359 = ATOMIC_LOAD_UMIN_I8_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #358 = ATOMIC_LOAD_UMIN_I8
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #357 = ATOMIC_LOAD_UMIN_I64_POSTRA
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #356 = ATOMIC_LOAD_UMIN_I64
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #355 = ATOMIC_LOAD_UMIN_I32_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #354 = ATOMIC_LOAD_UMIN_I32
  { 6, &MipsDescs.OperandInfo[173] },  // Inst #353 = ATOMIC_LOAD_UMIN_I16_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #352 = ATOMIC_LOAD_UMIN_I16
  { 6, &MipsDescs.OperandInfo[173] },  // Inst #351 = ATOMIC_LOAD_UMAX_I8_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #350 = ATOMIC_LOAD_UMAX_I8
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #349 = ATOMIC_LOAD_UMAX_I64_POSTRA
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #348 = ATOMIC_LOAD_UMAX_I64
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #347 = ATOMIC_LOAD_UMAX_I32_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #346 = ATOMIC_LOAD_UMAX_I32
  { 6, &MipsDescs.OperandInfo[173] },  // Inst #345 = ATOMIC_LOAD_UMAX_I16_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #344 = ATOMIC_LOAD_UMAX_I16
  { 6, &MipsDescs.OperandInfo[173] },  // Inst #343 = ATOMIC_LOAD_SUB_I8_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #342 = ATOMIC_LOAD_SUB_I8
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #341 = ATOMIC_LOAD_SUB_I64_POSTRA
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #340 = ATOMIC_LOAD_SUB_I64
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #339 = ATOMIC_LOAD_SUB_I32_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #338 = ATOMIC_LOAD_SUB_I32
  { 6, &MipsDescs.OperandInfo[173] },  // Inst #337 = ATOMIC_LOAD_SUB_I16_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #336 = ATOMIC_LOAD_SUB_I16
  { 6, &MipsDescs.OperandInfo[173] },  // Inst #335 = ATOMIC_LOAD_OR_I8_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #334 = ATOMIC_LOAD_OR_I8
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #333 = ATOMIC_LOAD_OR_I64_POSTRA
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #332 = ATOMIC_LOAD_OR_I64
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #331 = ATOMIC_LOAD_OR_I32_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #330 = ATOMIC_LOAD_OR_I32
  { 6, &MipsDescs.OperandInfo[173] },  // Inst #329 = ATOMIC_LOAD_OR_I16_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #328 = ATOMIC_LOAD_OR_I16
  { 6, &MipsDescs.OperandInfo[173] },  // Inst #327 = ATOMIC_LOAD_NAND_I8_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #326 = ATOMIC_LOAD_NAND_I8
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #325 = ATOMIC_LOAD_NAND_I64_POSTRA
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #324 = ATOMIC_LOAD_NAND_I64
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #323 = ATOMIC_LOAD_NAND_I32_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #322 = ATOMIC_LOAD_NAND_I32
  { 6, &MipsDescs.OperandInfo[173] },  // Inst #321 = ATOMIC_LOAD_NAND_I16_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #320 = ATOMIC_LOAD_NAND_I16
  { 6, &MipsDescs.OperandInfo[173] },  // Inst #319 = ATOMIC_LOAD_MIN_I8_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #318 = ATOMIC_LOAD_MIN_I8
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #317 = ATOMIC_LOAD_MIN_I64_POSTRA
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #316 = ATOMIC_LOAD_MIN_I64
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #315 = ATOMIC_LOAD_MIN_I32_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #314 = ATOMIC_LOAD_MIN_I32
  { 6, &MipsDescs.OperandInfo[173] },  // Inst #313 = ATOMIC_LOAD_MIN_I16_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #312 = ATOMIC_LOAD_MIN_I16
  { 6, &MipsDescs.OperandInfo[173] },  // Inst #311 = ATOMIC_LOAD_MAX_I8_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #310 = ATOMIC_LOAD_MAX_I8
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #309 = ATOMIC_LOAD_MAX_I64_POSTRA
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #308 = ATOMIC_LOAD_MAX_I64
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #307 = ATOMIC_LOAD_MAX_I32_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #306 = ATOMIC_LOAD_MAX_I32
  { 6, &MipsDescs.OperandInfo[173] },  // Inst #305 = ATOMIC_LOAD_MAX_I16_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #304 = ATOMIC_LOAD_MAX_I16
  { 6, &MipsDescs.OperandInfo[173] },  // Inst #303 = ATOMIC_LOAD_AND_I8_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #302 = ATOMIC_LOAD_AND_I8
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #301 = ATOMIC_LOAD_AND_I64_POSTRA
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #300 = ATOMIC_LOAD_AND_I64
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #299 = ATOMIC_LOAD_AND_I32_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #298 = ATOMIC_LOAD_AND_I32
  { 6, &MipsDescs.OperandInfo[173] },  // Inst #297 = ATOMIC_LOAD_AND_I16_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #296 = ATOMIC_LOAD_AND_I16
  { 6, &MipsDescs.OperandInfo[173] },  // Inst #295 = ATOMIC_LOAD_ADD_I8_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #294 = ATOMIC_LOAD_ADD_I8
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #293 = ATOMIC_LOAD_ADD_I64_POSTRA
  { 3, &MipsDescs.OperandInfo[179] },  // Inst #292 = ATOMIC_LOAD_ADD_I64
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #291 = ATOMIC_LOAD_ADD_I32_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #290 = ATOMIC_LOAD_ADD_I32
  { 6, &MipsDescs.OperandInfo[173] },  // Inst #289 = ATOMIC_LOAD_ADD_I16_POSTRA
  { 3, &MipsDescs.OperandInfo[170] },  // Inst #288 = ATOMIC_LOAD_ADD_I16
  { 7, &MipsDescs.OperandInfo[159] },  // Inst #287 = ATOMIC_CMP_SWAP_I8_POSTRA
  { 4, &MipsDescs.OperandInfo[155] },  // Inst #286 = ATOMIC_CMP_SWAP_I8
  { 4, &MipsDescs.OperandInfo[166] },  // Inst #285 = ATOMIC_CMP_SWAP_I64_POSTRA
  { 4, &MipsDescs.OperandInfo[166] },  // Inst #284 = ATOMIC_CMP_SWAP_I64
  { 4, &MipsDescs.OperandInfo[155] },  // Inst #283 = ATOMIC_CMP_SWAP_I32_POSTRA
  { 4, &MipsDescs.OperandInfo[155] },  // Inst #282 = ATOMIC_CMP_SWAP_I32
  { 7, &MipsDescs.OperandInfo[159] },  // Inst #281 = ATOMIC_CMP_SWAP_I16_POSTRA
  { 4, &MipsDescs.OperandInfo[155] },  // Inst #280 = ATOMIC_CMP_SWAP_I16
  { 3, &MipsDescs.OperandInfo[152] },  // Inst #279 = AND_V_W_PSEUDO
  { 3, &MipsDescs.OperandInfo[149] },  // Inst #278 = AND_V_H_PSEUDO
  { 3, &MipsDescs.OperandInfo[146] },  // Inst #277 = AND_V_D_PSEUDO
  { 4, &MipsDescs.OperandInfo[142] },  // Inst #276 = ALIGN_NM
  { 2, &MipsDescs.OperandInfo[21] },  // Inst #275 = ADJCALLSTACKUP_NM
  { 2, &MipsDescs.OperandInfo[21] },  // Inst #274 = ADJCALLSTACKUP
  { 2, &MipsDescs.OperandInfo[21] },  // Inst #273 = ADJCALLSTACKDOWN_NM
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
    /* 142 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 146 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 149 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 152 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 155 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 159 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 166 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 170 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 173 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 179 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 182 */ { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 183 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 186 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 189 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 190 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 194 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 198 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 202 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 205 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 208 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 211 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 214 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGRCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 216 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 219 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 222 */ { Mips_FGRCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 224 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 227 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 230 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 233 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 236 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 239 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 242 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 244 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 246 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 248 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 250 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 254 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 258 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 262 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 266 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 270 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 274 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 278 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 282 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 286 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 290 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 294 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 298 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 302 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 306 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 310 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 311 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 312 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 315 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 318 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 321 */ { Mips_MSA128F16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 324 */ { Mips_ACC128RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 327 */ { Mips_ACC64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 330 */ { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 333 */ { Mips_DSPCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 336 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 340 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 344 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 347 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 350 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 352 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 354 */ { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 357 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 359 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 361 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 364 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 366 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 368 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 370 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 372 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 376 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 379 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 381 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 383 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_COP0RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 386 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_COP0RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 389 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 391 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 394 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 396 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128F16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 398 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128F16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 400 */ { Mips_MSA128F16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 402 */ { Mips_MSA128F16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 404 */ { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 406 */ { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 408 */ { Mips_COP0RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 411 */ { Mips_COP0RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 414 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 416 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 418 */ { Mips_GPRNM32_TAILRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 419 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 421 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 424 */ { Mips_DSPCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 427 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 429 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 431 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 433 */ { Mips_ACC128RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 436 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 443 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 450 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 452 */ { Mips_ACC64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_ACC64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 456 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_ACC64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 458 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_ACC128RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 460 */ { Mips_ACC64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 463 */ { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 466 */ { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 470 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 474 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 478 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 482 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 486 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 490 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 494 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 498 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 502 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 506 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 510 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 513 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 516 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 519 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 522 */ { Mips_GPR32NONZERORegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 525 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 527 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 529 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 531 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 533 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 537 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 542 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 547 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 550 */ { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 552 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 555 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNMGPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 558 */ { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 560 */ { Mips_GPRNM3RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNMSPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 563 */ { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 566 */ { Mips_GPRNM3RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM3RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 569 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 572 */ { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 575 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 578 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 581 */ { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 584 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 587 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 590 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 593 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 596 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 599 */ { Mips_GPRNM3RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM3RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM3RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 602 */ { Mips_GPRNM4RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM4RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM4RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 605 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 609 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 611 */ { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 614 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 618 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 620 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 623 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsPlusSPRegClassID, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 626 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 629 */ { Mips_GPRNM32NZRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 631 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 634 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 637 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 639 */ { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 641 */ { Mips_COP2RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 643 */ { Mips_GPRNM3RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM3RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 646 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 649 */ { Mips_GPRNM3RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32ZERORegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 652 */ { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 654 */ { Mips_GPRNM3RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 656 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 660 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 664 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 668 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 672 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 676 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 678 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 680 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 682 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 684 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 686 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 688 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 691 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 693 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 695 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 697 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 699 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 701 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CCRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 703 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_COP2RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 705 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSACtrlRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 707 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 711 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 715 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 719 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 722 */ { Mips_FGRCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 725 */ { Mips_FGRCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 728 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 731 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 734 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 737 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 740 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 743 */ { Mips_CCRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 745 */ { Mips_COP2RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 747 */ { Mips_MSACtrlRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 749 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 751 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 754 */ { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 757 */ { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 760 */ { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 763 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 766 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 770 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 775 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_COP0RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 778 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 780 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_COP2RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 783 */ { Mips_COP0RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 786 */ { Mips_COP2RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 789 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 792 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 795 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 798 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 802 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 806 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 810 */ { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 814 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 817 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 819 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 822 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 825 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 829 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 831 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 834 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 837 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 840 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 843 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 846 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 849 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 852 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 854 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 856 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 858 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 860 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 862 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 864 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 869 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 873 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 877 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 881 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 885 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 888 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 893 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 898 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 903 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 908 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 913 */ { Mips_GPRNMRARegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 915 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 916 */ { Mips_GPRNM3RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 919 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), NanoMips_OPERAND_NM_GPREL18, 0 }, { -1, 0, NanoMips_OPERAND_NM_GPREL18, 0 },
    /* 922 */ { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 925 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 },
    /* 928 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 931 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 934 */ { Mips_COP2RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 937 */ { Mips_COP2RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 940 */ { Mips_COP3RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 943 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 945 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 947 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 949 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 951 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 955 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 },
    /* 958 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 },
    /* 961 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 964 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 967 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 970 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 973 */ { Mips_GPRNM3RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 975 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MipsII_OPERAND_MEM_SIMM9, 0 }, { -1, 0, MipsII_OPERAND_MEM_SIMM9, 0 },
    /* 978 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MipsII_OPERAND_MEM_SIMM9, 0 }, { -1, 0, MipsII_OPERAND_MEM_SIMM9, 0 },
    /* 981 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 985 */ { Mips_GPRNM4RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 988 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 991 */ { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 994 */ { Mips_GPRNM3RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), NanoMips_OPERAND_NM_GPREL9, 0 }, { -1, 0, NanoMips_OPERAND_NM_GPREL9, 0 },
    /* 997 */ { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 3, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1000 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), NanoMips_OPERAND_NM_GPREL21, 0 }, { -1, 0, NanoMips_OPERAND_NM_GPREL21, 0 },
    /* 1003 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1007 */ { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { 2, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1010 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 1014 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1018 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), NanoMips_OPERAND_NM_SPREL7, 0 }, { -1, 0, NanoMips_OPERAND_NM_SPREL7, 0 },
    /* 1021 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 2, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1024 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 },
    /* 1027 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 1030 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1033 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1037 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1041 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1045 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1049 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1053 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_COP0SelRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1055 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1057 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_COP2RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 1060 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1062 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 1067 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_COP0RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 1072 */ { Mips_GPRNM1R1RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM4ZRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 1075 */ { Mips_GPRNM4RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM4RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM2R1RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM2R2RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1079 */ { Mips_GPRMM16MovePPairFirstRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRMM16MovePPairSecondRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRMM16MovePRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRMM16MovePRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1083 */ { Mips_GPRNM2R1RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM2R2RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM4ZRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM4ZRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1087 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1089 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1093 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1097 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1101 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1105 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FCCRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1109 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1113 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1117 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1121 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1125 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1129 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1133 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1137 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1141 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1145 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1149 */ { Mips_COP2RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 1152 */ { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_AFGR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1155 */ { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1158 */ { Mips_HI32DSPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1160 */ { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1163 */ { Mips_LO32DSPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1165 */ { Mips_COP0RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 1170 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1172 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1174 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1176 */ { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRMM16RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1178 */ { Mips_GPRNM3RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM3RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1180 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1182 */ { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1185 */ { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1189 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 1192 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_HWRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 1195 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_HWRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 1198 */ { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1200 */ { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 1202 */ { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, NanoMips_OPERAND_NM_SAVE_REGLIST, 0 },
    /* 1204 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 1209 */ { Mips_GPRMM16ZeroRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 1, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1212 */ { Mips_GPRNM3ZRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1215 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1219 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MipsII_OPERAND_MEM_SIMM9, 0 }, { -1, 0, MipsII_OPERAND_MEM_SIMM9, 0 },
    /* 1223 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1227 */ { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MipsII_OPERAND_MEM_SIMM9, 0 }, { -1, 0, MipsII_OPERAND_MEM_SIMM9, 0 },
    /* 1231 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1236 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1240 */ { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGRCCRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_FGR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1244 */ { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { Mips_ACC64DSPRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1247 */ { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1250 */ { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_DSPRRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 1253 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1257 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1261 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1265 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1269 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1272 */ { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR64RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 1275 */ { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128BRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1278 */ { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128DRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1281 */ { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128HRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1284 */ { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_MSA128WRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_GPR32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1287 */ { Mips_GPRNM4ZRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1290 */ { Mips_GPRNM3ZRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), NanoMips_OPERAND_NM_GPREL9, 0 }, { -1, 0, NanoMips_OPERAND_NM_GPREL9, 0 },
    /* 1293 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1295 */ { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { Mips_CPU16RegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1297 */ { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { Mips_GPRNM32RegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
  }, {
    /* 0 */
    /* 0 */ Mips_SP, Mips_SP,
    /* 2 */ Mips_SP_NM, Mips_SP_NM,
    /* 4 */ Mips_AT,
    /* 5 */ Mips_RA,
    /* 6 */ Mips_DSPPos,
    /* 7 */ Mips_RA_NM,
    /* 8 */ Mips_V0, Mips_V1,
    /* 10 */ Mips_HI0, Mips_LO0,
    /* 12 */ Mips_T8,
    /* 13 */ Mips_DSPOutFlag20,
    /* 14 */ Mips_DSPCarry,
    /* 15 */ Mips_DSPCarry, Mips_DSPOutFlag20,
    /* 17 */ Mips_DSPCCond,
    /* 18 */ Mips_HI0, Mips_LO0, Mips_P0, Mips_P1, Mips_P2,
    /* 23 */ Mips_HI0_64, Mips_LO0_64,
    /* 25 */ Mips_DSPOutFlag16_19,
    /* 26 */ Mips_DSPPos, Mips_DSPEFI,
    /* 28 */ Mips_DSPPos, Mips_DSPPos, Mips_DSPEFI,
    /* 31 */ Mips_DSPOutFlag23,
    /* 32 */ Mips_FCC0,
    /* 33 */ Mips_DSPPos, Mips_DSPSCount,
    /* 35 */ Mips_HI0, Mips_LO0, Mips_HI0, Mips_LO0,
    /* 39 */ Mips_AC0,
    /* 40 */ Mips_AC0_64,
    /* 41 */ Mips_HI0,
    /* 42 */ Mips_HI0_64,
    /* 43 */ Mips_LO0,
    /* 44 */ Mips_LO0_64,
    /* 45 */ Mips_MPL0, Mips_P0, Mips_P1, Mips_P2,
    /* 49 */ Mips_MPL1, Mips_P0, Mips_P1, Mips_P2,
    /* 53 */ Mips_MPL2, Mips_P0, Mips_P1, Mips_P2,
    /* 57 */ Mips_P0,
    /* 58 */ Mips_P1,
    /* 59 */ Mips_P2,
    /* 60 */ Mips_DSPOutFlag21,
    /* 61 */ Mips_DSPOutFlag22,
    /* 62 */ Mips_P0, Mips_P1, Mips_P2,
    /* 65 */ Mips_MPL1, Mips_MPL2, Mips_P0, Mips_P1, Mips_P2,
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


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
    Sparc_PHI	= 0,
    Sparc_INLINEASM	= 1,
    Sparc_INLINEASM_BR	= 2,
    Sparc_CFI_INSTRUCTION	= 3,
    Sparc_EH_LABEL	= 4,
    Sparc_GC_LABEL	= 5,
    Sparc_ANNOTATION_LABEL	= 6,
    Sparc_KILL	= 7,
    Sparc_EXTRACT_SUBREG	= 8,
    Sparc_INSERT_SUBREG	= 9,
    Sparc_IMPLICIT_DEF	= 10,
    Sparc_SUBREG_TO_REG	= 11,
    Sparc_COPY_TO_REGCLASS	= 12,
    Sparc_DBG_VALUE	= 13,
    Sparc_DBG_VALUE_LIST	= 14,
    Sparc_DBG_INSTR_REF	= 15,
    Sparc_DBG_PHI	= 16,
    Sparc_DBG_LABEL	= 17,
    Sparc_REG_SEQUENCE	= 18,
    Sparc_COPY	= 19,
    Sparc_BUNDLE	= 20,
    Sparc_LIFETIME_START	= 21,
    Sparc_LIFETIME_END	= 22,
    Sparc_PSEUDO_PROBE	= 23,
    Sparc_ARITH_FENCE	= 24,
    Sparc_STACKMAP	= 25,
    Sparc_FENTRY_CALL	= 26,
    Sparc_PATCHPOINT	= 27,
    Sparc_LOAD_STACK_GUARD	= 28,
    Sparc_PREALLOCATED_SETUP	= 29,
    Sparc_PREALLOCATED_ARG	= 30,
    Sparc_STATEPOINT	= 31,
    Sparc_LOCAL_ESCAPE	= 32,
    Sparc_FAULTING_OP	= 33,
    Sparc_PATCHABLE_OP	= 34,
    Sparc_PATCHABLE_FUNCTION_ENTER	= 35,
    Sparc_PATCHABLE_RET	= 36,
    Sparc_PATCHABLE_FUNCTION_EXIT	= 37,
    Sparc_PATCHABLE_TAIL_CALL	= 38,
    Sparc_PATCHABLE_EVENT_CALL	= 39,
    Sparc_PATCHABLE_TYPED_EVENT_CALL	= 40,
    Sparc_ICALL_BRANCH_FUNNEL	= 41,
    Sparc_MEMBARRIER	= 42,
    Sparc_JUMP_TABLE_DEBUG_INFO	= 43,
    Sparc_G_ASSERT_SEXT	= 44,
    Sparc_G_ASSERT_ZEXT	= 45,
    Sparc_G_ASSERT_ALIGN	= 46,
    Sparc_G_ADD	= 47,
    Sparc_G_SUB	= 48,
    Sparc_G_MUL	= 49,
    Sparc_G_SDIV	= 50,
    Sparc_G_UDIV	= 51,
    Sparc_G_SREM	= 52,
    Sparc_G_UREM	= 53,
    Sparc_G_SDIVREM	= 54,
    Sparc_G_UDIVREM	= 55,
    Sparc_G_AND	= 56,
    Sparc_G_OR	= 57,
    Sparc_G_XOR	= 58,
    Sparc_G_IMPLICIT_DEF	= 59,
    Sparc_G_PHI	= 60,
    Sparc_G_FRAME_INDEX	= 61,
    Sparc_G_GLOBAL_VALUE	= 62,
    Sparc_G_CONSTANT_POOL	= 63,
    Sparc_G_EXTRACT	= 64,
    Sparc_G_UNMERGE_VALUES	= 65,
    Sparc_G_INSERT	= 66,
    Sparc_G_MERGE_VALUES	= 67,
    Sparc_G_BUILD_VECTOR	= 68,
    Sparc_G_BUILD_VECTOR_TRUNC	= 69,
    Sparc_G_CONCAT_VECTORS	= 70,
    Sparc_G_PTRTOINT	= 71,
    Sparc_G_INTTOPTR	= 72,
    Sparc_G_BITCAST	= 73,
    Sparc_G_FREEZE	= 74,
    Sparc_G_CONSTANT_FOLD_BARRIER	= 75,
    Sparc_G_INTRINSIC_FPTRUNC_ROUND	= 76,
    Sparc_G_INTRINSIC_TRUNC	= 77,
    Sparc_G_INTRINSIC_ROUND	= 78,
    Sparc_G_INTRINSIC_LRINT	= 79,
    Sparc_G_INTRINSIC_ROUNDEVEN	= 80,
    Sparc_G_READCYCLECOUNTER	= 81,
    Sparc_G_LOAD	= 82,
    Sparc_G_SEXTLOAD	= 83,
    Sparc_G_ZEXTLOAD	= 84,
    Sparc_G_INDEXED_LOAD	= 85,
    Sparc_G_INDEXED_SEXTLOAD	= 86,
    Sparc_G_INDEXED_ZEXTLOAD	= 87,
    Sparc_G_STORE	= 88,
    Sparc_G_INDEXED_STORE	= 89,
    Sparc_G_ATOMIC_CMPXCHG_WITH_SUCCESS	= 90,
    Sparc_G_ATOMIC_CMPXCHG	= 91,
    Sparc_G_ATOMICRMW_XCHG	= 92,
    Sparc_G_ATOMICRMW_ADD	= 93,
    Sparc_G_ATOMICRMW_SUB	= 94,
    Sparc_G_ATOMICRMW_AND	= 95,
    Sparc_G_ATOMICRMW_NAND	= 96,
    Sparc_G_ATOMICRMW_OR	= 97,
    Sparc_G_ATOMICRMW_XOR	= 98,
    Sparc_G_ATOMICRMW_MAX	= 99,
    Sparc_G_ATOMICRMW_MIN	= 100,
    Sparc_G_ATOMICRMW_UMAX	= 101,
    Sparc_G_ATOMICRMW_UMIN	= 102,
    Sparc_G_ATOMICRMW_FADD	= 103,
    Sparc_G_ATOMICRMW_FSUB	= 104,
    Sparc_G_ATOMICRMW_FMAX	= 105,
    Sparc_G_ATOMICRMW_FMIN	= 106,
    Sparc_G_ATOMICRMW_UINC_WRAP	= 107,
    Sparc_G_ATOMICRMW_UDEC_WRAP	= 108,
    Sparc_G_FENCE	= 109,
    Sparc_G_PREFETCH	= 110,
    Sparc_G_BRCOND	= 111,
    Sparc_G_BRINDIRECT	= 112,
    Sparc_G_INVOKE_REGION_START	= 113,
    Sparc_G_INTRINSIC	= 114,
    Sparc_G_INTRINSIC_W_SIDE_EFFECTS	= 115,
    Sparc_G_INTRINSIC_CONVERGENT	= 116,
    Sparc_G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS	= 117,
    Sparc_G_ANYEXT	= 118,
    Sparc_G_TRUNC	= 119,
    Sparc_G_CONSTANT	= 120,
    Sparc_G_FCONSTANT	= 121,
    Sparc_G_VASTART	= 122,
    Sparc_G_VAARG	= 123,
    Sparc_G_SEXT	= 124,
    Sparc_G_SEXT_INREG	= 125,
    Sparc_G_ZEXT	= 126,
    Sparc_G_SHL	= 127,
    Sparc_G_LSHR	= 128,
    Sparc_G_ASHR	= 129,
    Sparc_G_FSHL	= 130,
    Sparc_G_FSHR	= 131,
    Sparc_G_ROTR	= 132,
    Sparc_G_ROTL	= 133,
    Sparc_G_ICMP	= 134,
    Sparc_G_FCMP	= 135,
    Sparc_G_SELECT	= 136,
    Sparc_G_UADDO	= 137,
    Sparc_G_UADDE	= 138,
    Sparc_G_USUBO	= 139,
    Sparc_G_USUBE	= 140,
    Sparc_G_SADDO	= 141,
    Sparc_G_SADDE	= 142,
    Sparc_G_SSUBO	= 143,
    Sparc_G_SSUBE	= 144,
    Sparc_G_UMULO	= 145,
    Sparc_G_SMULO	= 146,
    Sparc_G_UMULH	= 147,
    Sparc_G_SMULH	= 148,
    Sparc_G_UADDSAT	= 149,
    Sparc_G_SADDSAT	= 150,
    Sparc_G_USUBSAT	= 151,
    Sparc_G_SSUBSAT	= 152,
    Sparc_G_USHLSAT	= 153,
    Sparc_G_SSHLSAT	= 154,
    Sparc_G_SMULFIX	= 155,
    Sparc_G_UMULFIX	= 156,
    Sparc_G_SMULFIXSAT	= 157,
    Sparc_G_UMULFIXSAT	= 158,
    Sparc_G_SDIVFIX	= 159,
    Sparc_G_UDIVFIX	= 160,
    Sparc_G_SDIVFIXSAT	= 161,
    Sparc_G_UDIVFIXSAT	= 162,
    Sparc_G_FADD	= 163,
    Sparc_G_FSUB	= 164,
    Sparc_G_FMUL	= 165,
    Sparc_G_FMA	= 166,
    Sparc_G_FMAD	= 167,
    Sparc_G_FDIV	= 168,
    Sparc_G_FREM	= 169,
    Sparc_G_FPOW	= 170,
    Sparc_G_FPOWI	= 171,
    Sparc_G_FEXP	= 172,
    Sparc_G_FEXP2	= 173,
    Sparc_G_FEXP10	= 174,
    Sparc_G_FLOG	= 175,
    Sparc_G_FLOG2	= 176,
    Sparc_G_FLOG10	= 177,
    Sparc_G_FLDEXP	= 178,
    Sparc_G_FFREXP	= 179,
    Sparc_G_FNEG	= 180,
    Sparc_G_FPEXT	= 181,
    Sparc_G_FPTRUNC	= 182,
    Sparc_G_FPTOSI	= 183,
    Sparc_G_FPTOUI	= 184,
    Sparc_G_SITOFP	= 185,
    Sparc_G_UITOFP	= 186,
    Sparc_G_FABS	= 187,
    Sparc_G_FCOPYSIGN	= 188,
    Sparc_G_IS_FPCLASS	= 189,
    Sparc_G_FCANONICALIZE	= 190,
    Sparc_G_FMINNUM	= 191,
    Sparc_G_FMAXNUM	= 192,
    Sparc_G_FMINNUM_IEEE	= 193,
    Sparc_G_FMAXNUM_IEEE	= 194,
    Sparc_G_FMINIMUM	= 195,
    Sparc_G_FMAXIMUM	= 196,
    Sparc_G_GET_FPENV	= 197,
    Sparc_G_SET_FPENV	= 198,
    Sparc_G_RESET_FPENV	= 199,
    Sparc_G_GET_FPMODE	= 200,
    Sparc_G_SET_FPMODE	= 201,
    Sparc_G_RESET_FPMODE	= 202,
    Sparc_G_PTR_ADD	= 203,
    Sparc_G_PTRMASK	= 204,
    Sparc_G_SMIN	= 205,
    Sparc_G_SMAX	= 206,
    Sparc_G_UMIN	= 207,
    Sparc_G_UMAX	= 208,
    Sparc_G_ABS	= 209,
    Sparc_G_LROUND	= 210,
    Sparc_G_LLROUND	= 211,
    Sparc_G_BR	= 212,
    Sparc_G_BRJT	= 213,
    Sparc_G_INSERT_VECTOR_ELT	= 214,
    Sparc_G_EXTRACT_VECTOR_ELT	= 215,
    Sparc_G_SHUFFLE_VECTOR	= 216,
    Sparc_G_CTTZ	= 217,
    Sparc_G_CTTZ_ZERO_UNDEF	= 218,
    Sparc_G_CTLZ	= 219,
    Sparc_G_CTLZ_ZERO_UNDEF	= 220,
    Sparc_G_CTPOP	= 221,
    Sparc_G_BSWAP	= 222,
    Sparc_G_BITREVERSE	= 223,
    Sparc_G_FCEIL	= 224,
    Sparc_G_FCOS	= 225,
    Sparc_G_FSIN	= 226,
    Sparc_G_FSQRT	= 227,
    Sparc_G_FFLOOR	= 228,
    Sparc_G_FRINT	= 229,
    Sparc_G_FNEARBYINT	= 230,
    Sparc_G_ADDRSPACE_CAST	= 231,
    Sparc_G_BLOCK_ADDR	= 232,
    Sparc_G_JUMP_TABLE	= 233,
    Sparc_G_DYN_STACKALLOC	= 234,
    Sparc_G_STACKSAVE	= 235,
    Sparc_G_STACKRESTORE	= 236,
    Sparc_G_STRICT_FADD	= 237,
    Sparc_G_STRICT_FSUB	= 238,
    Sparc_G_STRICT_FMUL	= 239,
    Sparc_G_STRICT_FDIV	= 240,
    Sparc_G_STRICT_FREM	= 241,
    Sparc_G_STRICT_FMA	= 242,
    Sparc_G_STRICT_FSQRT	= 243,
    Sparc_G_STRICT_FLDEXP	= 244,
    Sparc_G_READ_REGISTER	= 245,
    Sparc_G_WRITE_REGISTER	= 246,
    Sparc_G_MEMCPY	= 247,
    Sparc_G_MEMCPY_INLINE	= 248,
    Sparc_G_MEMMOVE	= 249,
    Sparc_G_MEMSET	= 250,
    Sparc_G_BZERO	= 251,
    Sparc_G_VECREDUCE_SEQ_FADD	= 252,
    Sparc_G_VECREDUCE_SEQ_FMUL	= 253,
    Sparc_G_VECREDUCE_FADD	= 254,
    Sparc_G_VECREDUCE_FMUL	= 255,
    Sparc_G_VECREDUCE_FMAX	= 256,
    Sparc_G_VECREDUCE_FMIN	= 257,
    Sparc_G_VECREDUCE_FMAXIMUM	= 258,
    Sparc_G_VECREDUCE_FMINIMUM	= 259,
    Sparc_G_VECREDUCE_ADD	= 260,
    Sparc_G_VECREDUCE_MUL	= 261,
    Sparc_G_VECREDUCE_AND	= 262,
    Sparc_G_VECREDUCE_OR	= 263,
    Sparc_G_VECREDUCE_XOR	= 264,
    Sparc_G_VECREDUCE_SMAX	= 265,
    Sparc_G_VECREDUCE_SMIN	= 266,
    Sparc_G_VECREDUCE_UMAX	= 267,
    Sparc_G_VECREDUCE_UMIN	= 268,
    Sparc_G_SBFX	= 269,
    Sparc_G_UBFX	= 270,
    Sparc_ADJCALLSTACKDOWN	= 271,
    Sparc_ADJCALLSTACKUP	= 272,
    Sparc_GETPCX	= 273,
    Sparc_SELECT_CC_DFP_FCC	= 274,
    Sparc_SELECT_CC_DFP_ICC	= 275,
    Sparc_SELECT_CC_DFP_XCC	= 276,
    Sparc_SELECT_CC_FP_FCC	= 277,
    Sparc_SELECT_CC_FP_ICC	= 278,
    Sparc_SELECT_CC_FP_XCC	= 279,
    Sparc_SELECT_CC_Int_FCC	= 280,
    Sparc_SELECT_CC_Int_ICC	= 281,
    Sparc_SELECT_CC_Int_XCC	= 282,
    Sparc_SELECT_CC_QFP_FCC	= 283,
    Sparc_SELECT_CC_QFP_ICC	= 284,
    Sparc_SELECT_CC_QFP_XCC	= 285,
    Sparc_SET	= 286,
    Sparc_SETX	= 287,
    Sparc_ADDCCri	= 288,
    Sparc_ADDCCrr	= 289,
    Sparc_ADDCri	= 290,
    Sparc_ADDCrr	= 291,
    Sparc_ADDEri	= 292,
    Sparc_ADDErr	= 293,
    Sparc_ADDXC	= 294,
    Sparc_ADDXCCC	= 295,
    Sparc_ADDri	= 296,
    Sparc_ADDrr	= 297,
    Sparc_ALIGNADDR	= 298,
    Sparc_ALIGNADDRL	= 299,
    Sparc_ANDCCri	= 300,
    Sparc_ANDCCrr	= 301,
    Sparc_ANDNCCri	= 302,
    Sparc_ANDNCCrr	= 303,
    Sparc_ANDNri	= 304,
    Sparc_ANDNrr	= 305,
    Sparc_ANDri	= 306,
    Sparc_ANDrr	= 307,
    Sparc_ARRAY16	= 308,
    Sparc_ARRAY32	= 309,
    Sparc_ARRAY8	= 310,
    Sparc_BA	= 311,
    Sparc_BCOND	= 312,
    Sparc_BCONDA	= 313,
    Sparc_BINDri	= 314,
    Sparc_BINDrr	= 315,
    Sparc_BMASK	= 316,
    Sparc_BPFCC	= 317,
    Sparc_BPFCCA	= 318,
    Sparc_BPFCCANT	= 319,
    Sparc_BPFCCNT	= 320,
    Sparc_BPICC	= 321,
    Sparc_BPICCA	= 322,
    Sparc_BPICCANT	= 323,
    Sparc_BPICCNT	= 324,
    Sparc_BPR	= 325,
    Sparc_BPRA	= 326,
    Sparc_BPRANT	= 327,
    Sparc_BPRNT	= 328,
    Sparc_BPXCC	= 329,
    Sparc_BPXCCA	= 330,
    Sparc_BPXCCANT	= 331,
    Sparc_BPXCCNT	= 332,
    Sparc_BSHUFFLE	= 333,
    Sparc_CALL	= 334,
    Sparc_CALLri	= 335,
    Sparc_CALLrr	= 336,
    Sparc_CASAri	= 337,
    Sparc_CASArr	= 338,
    Sparc_CASXAri	= 339,
    Sparc_CASXArr	= 340,
    Sparc_CBCOND	= 341,
    Sparc_CBCONDA	= 342,
    Sparc_CMASK16	= 343,
    Sparc_CMASK32	= 344,
    Sparc_CMASK8	= 345,
    Sparc_DONE	= 346,
    Sparc_EDGE16	= 347,
    Sparc_EDGE16L	= 348,
    Sparc_EDGE16LN	= 349,
    Sparc_EDGE16N	= 350,
    Sparc_EDGE32	= 351,
    Sparc_EDGE32L	= 352,
    Sparc_EDGE32LN	= 353,
    Sparc_EDGE32N	= 354,
    Sparc_EDGE8	= 355,
    Sparc_EDGE8L	= 356,
    Sparc_EDGE8LN	= 357,
    Sparc_EDGE8N	= 358,
    Sparc_FABSD	= 359,
    Sparc_FABSQ	= 360,
    Sparc_FABSS	= 361,
    Sparc_FADDD	= 362,
    Sparc_FADDQ	= 363,
    Sparc_FADDS	= 364,
    Sparc_FALIGNADATA	= 365,
    Sparc_FAND	= 366,
    Sparc_FANDNOT1	= 367,
    Sparc_FANDNOT1S	= 368,
    Sparc_FANDNOT2	= 369,
    Sparc_FANDNOT2S	= 370,
    Sparc_FANDS	= 371,
    Sparc_FBCOND	= 372,
    Sparc_FBCONDA	= 373,
    Sparc_FBCONDA_V9	= 374,
    Sparc_FBCOND_V9	= 375,
    Sparc_FCHKSM16	= 376,
    Sparc_FCMPD	= 377,
    Sparc_FCMPD_V9	= 378,
    Sparc_FCMPEQ16	= 379,
    Sparc_FCMPEQ32	= 380,
    Sparc_FCMPGT16	= 381,
    Sparc_FCMPGT32	= 382,
    Sparc_FCMPLE16	= 383,
    Sparc_FCMPLE32	= 384,
    Sparc_FCMPNE16	= 385,
    Sparc_FCMPNE32	= 386,
    Sparc_FCMPQ	= 387,
    Sparc_FCMPQ_V9	= 388,
    Sparc_FCMPS	= 389,
    Sparc_FCMPS_V9	= 390,
    Sparc_FDIVD	= 391,
    Sparc_FDIVQ	= 392,
    Sparc_FDIVS	= 393,
    Sparc_FDMULQ	= 394,
    Sparc_FDTOI	= 395,
    Sparc_FDTOQ	= 396,
    Sparc_FDTOS	= 397,
    Sparc_FDTOX	= 398,
    Sparc_FEXPAND	= 399,
    Sparc_FHADDD	= 400,
    Sparc_FHADDS	= 401,
    Sparc_FHSUBD	= 402,
    Sparc_FHSUBS	= 403,
    Sparc_FITOD	= 404,
    Sparc_FITOQ	= 405,
    Sparc_FITOS	= 406,
    Sparc_FLCMPD	= 407,
    Sparc_FLCMPS	= 408,
    Sparc_FLUSH	= 409,
    Sparc_FLUSHW	= 410,
    Sparc_FLUSHri	= 411,
    Sparc_FLUSHrr	= 412,
    Sparc_FMEAN16	= 413,
    Sparc_FMOVD	= 414,
    Sparc_FMOVD_FCC	= 415,
    Sparc_FMOVD_ICC	= 416,
    Sparc_FMOVD_XCC	= 417,
    Sparc_FMOVQ	= 418,
    Sparc_FMOVQ_FCC	= 419,
    Sparc_FMOVQ_ICC	= 420,
    Sparc_FMOVQ_XCC	= 421,
    Sparc_FMOVRD	= 422,
    Sparc_FMOVRQ	= 423,
    Sparc_FMOVRS	= 424,
    Sparc_FMOVS	= 425,
    Sparc_FMOVS_FCC	= 426,
    Sparc_FMOVS_ICC	= 427,
    Sparc_FMOVS_XCC	= 428,
    Sparc_FMUL8SUX16	= 429,
    Sparc_FMUL8ULX16	= 430,
    Sparc_FMUL8X16	= 431,
    Sparc_FMUL8X16AL	= 432,
    Sparc_FMUL8X16AU	= 433,
    Sparc_FMULD	= 434,
    Sparc_FMULD8SUX16	= 435,
    Sparc_FMULD8ULX16	= 436,
    Sparc_FMULQ	= 437,
    Sparc_FMULS	= 438,
    Sparc_FNADDD	= 439,
    Sparc_FNADDS	= 440,
    Sparc_FNAND	= 441,
    Sparc_FNANDS	= 442,
    Sparc_FNEGD	= 443,
    Sparc_FNEGQ	= 444,
    Sparc_FNEGS	= 445,
    Sparc_FNHADDD	= 446,
    Sparc_FNHADDS	= 447,
    Sparc_FNMULD	= 448,
    Sparc_FNMULS	= 449,
    Sparc_FNOR	= 450,
    Sparc_FNORS	= 451,
    Sparc_FNOT1	= 452,
    Sparc_FNOT1S	= 453,
    Sparc_FNOT2	= 454,
    Sparc_FNOT2S	= 455,
    Sparc_FNSMULD	= 456,
    Sparc_FONE	= 457,
    Sparc_FONES	= 458,
    Sparc_FOR	= 459,
    Sparc_FORNOT1	= 460,
    Sparc_FORNOT1S	= 461,
    Sparc_FORNOT2	= 462,
    Sparc_FORNOT2S	= 463,
    Sparc_FORS	= 464,
    Sparc_FPACK16	= 465,
    Sparc_FPACK32	= 466,
    Sparc_FPACKFIX	= 467,
    Sparc_FPADD16	= 468,
    Sparc_FPADD16S	= 469,
    Sparc_FPADD32	= 470,
    Sparc_FPADD32S	= 471,
    Sparc_FPADD64	= 472,
    Sparc_FPMERGE	= 473,
    Sparc_FPSUB16	= 474,
    Sparc_FPSUB16S	= 475,
    Sparc_FPSUB32	= 476,
    Sparc_FPSUB32S	= 477,
    Sparc_FQTOD	= 478,
    Sparc_FQTOI	= 479,
    Sparc_FQTOS	= 480,
    Sparc_FQTOX	= 481,
    Sparc_FSLAS16	= 482,
    Sparc_FSLAS32	= 483,
    Sparc_FSLL16	= 484,
    Sparc_FSLL32	= 485,
    Sparc_FSMULD	= 486,
    Sparc_FSQRTD	= 487,
    Sparc_FSQRTQ	= 488,
    Sparc_FSQRTS	= 489,
    Sparc_FSRA16	= 490,
    Sparc_FSRA32	= 491,
    Sparc_FSRC1	= 492,
    Sparc_FSRC1S	= 493,
    Sparc_FSRC2	= 494,
    Sparc_FSRC2S	= 495,
    Sparc_FSRL16	= 496,
    Sparc_FSRL32	= 497,
    Sparc_FSTOD	= 498,
    Sparc_FSTOI	= 499,
    Sparc_FSTOQ	= 500,
    Sparc_FSTOX	= 501,
    Sparc_FSUBD	= 502,
    Sparc_FSUBQ	= 503,
    Sparc_FSUBS	= 504,
    Sparc_FXNOR	= 505,
    Sparc_FXNORS	= 506,
    Sparc_FXOR	= 507,
    Sparc_FXORS	= 508,
    Sparc_FXTOD	= 509,
    Sparc_FXTOQ	= 510,
    Sparc_FXTOS	= 511,
    Sparc_FZERO	= 512,
    Sparc_FZEROS	= 513,
    Sparc_GDOP_LDXrr	= 514,
    Sparc_GDOP_LDrr	= 515,
    Sparc_JMPLri	= 516,
    Sparc_JMPLrr	= 517,
    Sparc_LDAri	= 518,
    Sparc_LDArr	= 519,
    Sparc_LDCSRri	= 520,
    Sparc_LDCSRrr	= 521,
    Sparc_LDCri	= 522,
    Sparc_LDCrr	= 523,
    Sparc_LDDAri	= 524,
    Sparc_LDDArr	= 525,
    Sparc_LDDCri	= 526,
    Sparc_LDDCrr	= 527,
    Sparc_LDDFAri	= 528,
    Sparc_LDDFArr	= 529,
    Sparc_LDDFri	= 530,
    Sparc_LDDFrr	= 531,
    Sparc_LDDri	= 532,
    Sparc_LDDrr	= 533,
    Sparc_LDFAri	= 534,
    Sparc_LDFArr	= 535,
    Sparc_LDFSRri	= 536,
    Sparc_LDFSRrr	= 537,
    Sparc_LDFri	= 538,
    Sparc_LDFrr	= 539,
    Sparc_LDQFAri	= 540,
    Sparc_LDQFArr	= 541,
    Sparc_LDQFri	= 542,
    Sparc_LDQFrr	= 543,
    Sparc_LDSBAri	= 544,
    Sparc_LDSBArr	= 545,
    Sparc_LDSBri	= 546,
    Sparc_LDSBrr	= 547,
    Sparc_LDSHAri	= 548,
    Sparc_LDSHArr	= 549,
    Sparc_LDSHri	= 550,
    Sparc_LDSHrr	= 551,
    Sparc_LDSTUBAri	= 552,
    Sparc_LDSTUBArr	= 553,
    Sparc_LDSTUBri	= 554,
    Sparc_LDSTUBrr	= 555,
    Sparc_LDSWAri	= 556,
    Sparc_LDSWArr	= 557,
    Sparc_LDSWri	= 558,
    Sparc_LDSWrr	= 559,
    Sparc_LDUBAri	= 560,
    Sparc_LDUBArr	= 561,
    Sparc_LDUBri	= 562,
    Sparc_LDUBrr	= 563,
    Sparc_LDUHAri	= 564,
    Sparc_LDUHArr	= 565,
    Sparc_LDUHri	= 566,
    Sparc_LDUHrr	= 567,
    Sparc_LDXAri	= 568,
    Sparc_LDXArr	= 569,
    Sparc_LDXFSRri	= 570,
    Sparc_LDXFSRrr	= 571,
    Sparc_LDXri	= 572,
    Sparc_LDXrr	= 573,
    Sparc_LDri	= 574,
    Sparc_LDrr	= 575,
    Sparc_LZCNT	= 576,
    Sparc_MEMBARi	= 577,
    Sparc_MOVDTOX	= 578,
    Sparc_MOVFCCri	= 579,
    Sparc_MOVFCCrr	= 580,
    Sparc_MOVICCri	= 581,
    Sparc_MOVICCrr	= 582,
    Sparc_MOVRri	= 583,
    Sparc_MOVRrr	= 584,
    Sparc_MOVSTOSW	= 585,
    Sparc_MOVSTOUW	= 586,
    Sparc_MOVWTOS	= 587,
    Sparc_MOVXCCri	= 588,
    Sparc_MOVXCCrr	= 589,
    Sparc_MOVXTOD	= 590,
    Sparc_MULSCCri	= 591,
    Sparc_MULSCCrr	= 592,
    Sparc_MULXri	= 593,
    Sparc_MULXrr	= 594,
    Sparc_NOP	= 595,
    Sparc_ORCCri	= 596,
    Sparc_ORCCrr	= 597,
    Sparc_ORNCCri	= 598,
    Sparc_ORNCCrr	= 599,
    Sparc_ORNri	= 600,
    Sparc_ORNrr	= 601,
    Sparc_ORri	= 602,
    Sparc_ORrr	= 603,
    Sparc_PDIST	= 604,
    Sparc_PDISTN	= 605,
    Sparc_POPCrr	= 606,
    Sparc_PREFETCHi	= 607,
    Sparc_PREFETCHr	= 608,
    Sparc_PWRPSRri	= 609,
    Sparc_PWRPSRrr	= 610,
    Sparc_RDASR	= 611,
    Sparc_RDFQ	= 612,
    Sparc_RDPR	= 613,
    Sparc_RDPSR	= 614,
    Sparc_RDTBR	= 615,
    Sparc_RDWIM	= 616,
    Sparc_RESTORED	= 617,
    Sparc_RESTOREri	= 618,
    Sparc_RESTORErr	= 619,
    Sparc_RET	= 620,
    Sparc_RETL	= 621,
    Sparc_RETRY	= 622,
    Sparc_RETTri	= 623,
    Sparc_RETTrr	= 624,
    Sparc_SAVED	= 625,
    Sparc_SAVEri	= 626,
    Sparc_SAVErr	= 627,
    Sparc_SDIVCCri	= 628,
    Sparc_SDIVCCrr	= 629,
    Sparc_SDIVXri	= 630,
    Sparc_SDIVXrr	= 631,
    Sparc_SDIVri	= 632,
    Sparc_SDIVrr	= 633,
    Sparc_SETHIi	= 634,
    Sparc_SHUTDOWN	= 635,
    Sparc_SIAM	= 636,
    Sparc_SIR	= 637,
    Sparc_SLLXri	= 638,
    Sparc_SLLXrr	= 639,
    Sparc_SLLri	= 640,
    Sparc_SLLrr	= 641,
    Sparc_SMACri	= 642,
    Sparc_SMACrr	= 643,
    Sparc_SMULCCri	= 644,
    Sparc_SMULCCrr	= 645,
    Sparc_SMULri	= 646,
    Sparc_SMULrr	= 647,
    Sparc_SRAXri	= 648,
    Sparc_SRAXrr	= 649,
    Sparc_SRAri	= 650,
    Sparc_SRArr	= 651,
    Sparc_SRLXri	= 652,
    Sparc_SRLXrr	= 653,
    Sparc_SRLri	= 654,
    Sparc_SRLrr	= 655,
    Sparc_STAri	= 656,
    Sparc_STArr	= 657,
    Sparc_STBAR	= 658,
    Sparc_STBAri	= 659,
    Sparc_STBArr	= 660,
    Sparc_STBri	= 661,
    Sparc_STBrr	= 662,
    Sparc_STCSRri	= 663,
    Sparc_STCSRrr	= 664,
    Sparc_STCri	= 665,
    Sparc_STCrr	= 666,
    Sparc_STDAri	= 667,
    Sparc_STDArr	= 668,
    Sparc_STDCQri	= 669,
    Sparc_STDCQrr	= 670,
    Sparc_STDCri	= 671,
    Sparc_STDCrr	= 672,
    Sparc_STDFAri	= 673,
    Sparc_STDFArr	= 674,
    Sparc_STDFQri	= 675,
    Sparc_STDFQrr	= 676,
    Sparc_STDFri	= 677,
    Sparc_STDFrr	= 678,
    Sparc_STDri	= 679,
    Sparc_STDrr	= 680,
    Sparc_STFAri	= 681,
    Sparc_STFArr	= 682,
    Sparc_STFSRri	= 683,
    Sparc_STFSRrr	= 684,
    Sparc_STFri	= 685,
    Sparc_STFrr	= 686,
    Sparc_STHAri	= 687,
    Sparc_STHArr	= 688,
    Sparc_STHri	= 689,
    Sparc_STHrr	= 690,
    Sparc_STQFAri	= 691,
    Sparc_STQFArr	= 692,
    Sparc_STQFri	= 693,
    Sparc_STQFrr	= 694,
    Sparc_STXAri	= 695,
    Sparc_STXArr	= 696,
    Sparc_STXFSRri	= 697,
    Sparc_STXFSRrr	= 698,
    Sparc_STXri	= 699,
    Sparc_STXrr	= 700,
    Sparc_STri	= 701,
    Sparc_STrr	= 702,
    Sparc_SUBCCri	= 703,
    Sparc_SUBCCrr	= 704,
    Sparc_SUBCri	= 705,
    Sparc_SUBCrr	= 706,
    Sparc_SUBEri	= 707,
    Sparc_SUBErr	= 708,
    Sparc_SUBri	= 709,
    Sparc_SUBrr	= 710,
    Sparc_SWAPAri	= 711,
    Sparc_SWAPArr	= 712,
    Sparc_SWAPri	= 713,
    Sparc_SWAPrr	= 714,
    Sparc_TA1	= 715,
    Sparc_TA3	= 716,
    Sparc_TA5	= 717,
    Sparc_TADDCCTVri	= 718,
    Sparc_TADDCCTVrr	= 719,
    Sparc_TADDCCri	= 720,
    Sparc_TADDCCrr	= 721,
    Sparc_TAIL_CALL	= 722,
    Sparc_TAIL_CALLri	= 723,
    Sparc_TICCri	= 724,
    Sparc_TICCrr	= 725,
    Sparc_TLS_ADDrr	= 726,
    Sparc_TLS_CALL	= 727,
    Sparc_TLS_LDXrr	= 728,
    Sparc_TLS_LDrr	= 729,
    Sparc_TRAPri	= 730,
    Sparc_TRAPrr	= 731,
    Sparc_TSUBCCTVri	= 732,
    Sparc_TSUBCCTVrr	= 733,
    Sparc_TSUBCCri	= 734,
    Sparc_TSUBCCrr	= 735,
    Sparc_TXCCri	= 736,
    Sparc_TXCCrr	= 737,
    Sparc_UDIVCCri	= 738,
    Sparc_UDIVCCrr	= 739,
    Sparc_UDIVXri	= 740,
    Sparc_UDIVXrr	= 741,
    Sparc_UDIVri	= 742,
    Sparc_UDIVrr	= 743,
    Sparc_UMACri	= 744,
    Sparc_UMACrr	= 745,
    Sparc_UMULCCri	= 746,
    Sparc_UMULCCrr	= 747,
    Sparc_UMULXHI	= 748,
    Sparc_UMULri	= 749,
    Sparc_UMULrr	= 750,
    Sparc_UNIMP	= 751,
    Sparc_V9FCMPD	= 752,
    Sparc_V9FCMPED	= 753,
    Sparc_V9FCMPEQ	= 754,
    Sparc_V9FCMPES	= 755,
    Sparc_V9FCMPQ	= 756,
    Sparc_V9FCMPS	= 757,
    Sparc_V9FMOVD_FCC	= 758,
    Sparc_V9FMOVQ_FCC	= 759,
    Sparc_V9FMOVS_FCC	= 760,
    Sparc_V9MOVFCCri	= 761,
    Sparc_V9MOVFCCrr	= 762,
    Sparc_WRASRri	= 763,
    Sparc_WRASRrr	= 764,
    Sparc_WRPRri	= 765,
    Sparc_WRPRrr	= 766,
    Sparc_WRPSRri	= 767,
    Sparc_WRPSRrr	= 768,
    Sparc_WRTBRri	= 769,
    Sparc_WRTBRrr	= 770,
    Sparc_WRWIMri	= 771,
    Sparc_WRWIMrr	= 772,
    Sparc_XMULX	= 773,
    Sparc_XMULXHI	= 774,
    Sparc_XNORCCri	= 775,
    Sparc_XNORCCrr	= 776,
    Sparc_XNORri	= 777,
    Sparc_XNORrr	= 778,
    Sparc_XORCCri	= 779,
    Sparc_XORCCrr	= 780,
    Sparc_XORri	= 781,
    Sparc_XORrr	= 782,
    INSTRUCTION_LIST_END = 783
  };

#endif // GET_INSTRINFO_ENUM

#if defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)
typedef struct SparcInstrTable {
  MCInstrDesc Insts[783];
  MCOperandInfo OperandInfo[532];
  MCPhysReg ImplicitOps[32];
} SparcInstrTable;

#endif // defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

#ifdef GET_INSTRINFO_MC_DESC
#undef GET_INSTRINFO_MC_DESC

static const unsigned SparcImpOpBase = sizeof(MCOperandInfo) / (sizeof(MCPhysReg));

static const SparcInstrTable SparcDescs = {
  {
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #782 = XORrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #781 = XORri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #780 = XORCCrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #779 = XORCCri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #778 = XNORrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #777 = XNORri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #776 = XNORCCrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #775 = XNORCCri
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #774 = XMULXHI
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #773 = XMULX
  { 2, &SparcDescs.OperandInfo[367] },  // Inst #772 = WRWIMrr
  { 2, &SparcDescs.OperandInfo[156] },  // Inst #771 = WRWIMri
  { 2, &SparcDescs.OperandInfo[367] },  // Inst #770 = WRTBRrr
  { 2, &SparcDescs.OperandInfo[156] },  // Inst #769 = WRTBRri
  { 2, &SparcDescs.OperandInfo[367] },  // Inst #768 = WRPSRrr
  { 2, &SparcDescs.OperandInfo[156] },  // Inst #767 = WRPSRri
  { 3, &SparcDescs.OperandInfo[529] },  // Inst #766 = WRPRrr
  { 3, &SparcDescs.OperandInfo[526] },  // Inst #765 = WRPRri
  { 3, &SparcDescs.OperandInfo[523] },  // Inst #764 = WRASRrr
  { 3, &SparcDescs.OperandInfo[520] },  // Inst #763 = WRASRri
  { 5, &SparcDescs.OperandInfo[515] },  // Inst #762 = V9MOVFCCrr
  { 5, &SparcDescs.OperandInfo[510] },  // Inst #761 = V9MOVFCCri
  { 5, &SparcDescs.OperandInfo[505] },  // Inst #760 = V9FMOVS_FCC
  { 5, &SparcDescs.OperandInfo[500] },  // Inst #759 = V9FMOVQ_FCC
  { 5, &SparcDescs.OperandInfo[495] },  // Inst #758 = V9FMOVD_FCC
  { 3, &SparcDescs.OperandInfo[492] },  // Inst #757 = V9FCMPS
  { 3, &SparcDescs.OperandInfo[489] },  // Inst #756 = V9FCMPQ
  { 3, &SparcDescs.OperandInfo[492] },  // Inst #755 = V9FCMPES
  { 3, &SparcDescs.OperandInfo[489] },  // Inst #754 = V9FCMPEQ
  { 3, &SparcDescs.OperandInfo[230] },  // Inst #753 = V9FCMPED
  { 3, &SparcDescs.OperandInfo[230] },  // Inst #752 = V9FCMPD
  { 1, &SparcDescs.OperandInfo[1] },  // Inst #751 = UNIMP
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #750 = UMULrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #749 = UMULri
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #748 = UMULXHI
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #747 = UMULCCrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #746 = UMULCCri
  { 4, &SparcDescs.OperandInfo[393] },  // Inst #745 = UMACrr
  { 4, &SparcDescs.OperandInfo[389] },  // Inst #744 = UMACri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #743 = UDIVrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #742 = UDIVri
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #741 = UDIVXrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #740 = UDIVXri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #739 = UDIVCCrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #738 = UDIVCCri
  { 3, &SparcDescs.OperandInfo[386] },  // Inst #737 = TXCCrr
  { 3, &SparcDescs.OperandInfo[482] },  // Inst #736 = TXCCri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #735 = TSUBCCrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #734 = TSUBCCri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #733 = TSUBCCTVrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #732 = TSUBCCTVri
  { 3, &SparcDescs.OperandInfo[386] },  // Inst #731 = TRAPrr
  { 3, &SparcDescs.OperandInfo[482] },  // Inst #730 = TRAPri
  { 4, &SparcDescs.OperandInfo[275] },  // Inst #729 = TLS_LDrr
  { 4, &SparcDescs.OperandInfo[275] },  // Inst #728 = TLS_LDXrr
  { 2, &SparcDescs.OperandInfo[13] },  // Inst #727 = TLS_CALL
  { 4, &SparcDescs.OperandInfo[485] },  // Inst #726 = TLS_ADDrr
  { 3, &SparcDescs.OperandInfo[386] },  // Inst #725 = TICCrr
  { 3, &SparcDescs.OperandInfo[482] },  // Inst #724 = TICCri
  { 2, &SparcDescs.OperandInfo[172] },  // Inst #723 = TAIL_CALLri
  { 1, &SparcDescs.OperandInfo[0] },  // Inst #722 = TAIL_CALL
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #721 = TADDCCrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #720 = TADDCCri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #719 = TADDCCTVrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #718 = TADDCCTVri
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #717 = TA5
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #716 = TA3
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #715 = TA1
  { 4, &SparcDescs.OperandInfo[478] },  // Inst #714 = SWAPrr
  { 4, &SparcDescs.OperandInfo[469] },  // Inst #713 = SWAPri
  { 5, &SparcDescs.OperandInfo[473] },  // Inst #712 = SWAPArr
  { 4, &SparcDescs.OperandInfo[469] },  // Inst #711 = SWAPAri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #710 = SUBrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #709 = SUBri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #708 = SUBErr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #707 = SUBEri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #706 = SUBCrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #705 = SUBCri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #704 = SUBCCrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #703 = SUBCCri
  { 3, &SparcDescs.OperandInfo[404] },  // Inst #702 = STrr
  { 3, &SparcDescs.OperandInfo[397] },  // Inst #701 = STri
  { 3, &SparcDescs.OperandInfo[466] },  // Inst #700 = STXrr
  { 3, &SparcDescs.OperandInfo[459] },  // Inst #699 = STXri
  { 2, &SparcDescs.OperandInfo[174] },  // Inst #698 = STXFSRrr
  { 2, &SparcDescs.OperandInfo[172] },  // Inst #697 = STXFSRri
  { 4, &SparcDescs.OperandInfo[462] },  // Inst #696 = STXArr
  { 3, &SparcDescs.OperandInfo[459] },  // Inst #695 = STXAri
  { 3, &SparcDescs.OperandInfo[456] },  // Inst #694 = STQFrr
  { 3, &SparcDescs.OperandInfo[449] },  // Inst #693 = STQFri
  { 4, &SparcDescs.OperandInfo[452] },  // Inst #692 = STQFArr
  { 3, &SparcDescs.OperandInfo[449] },  // Inst #691 = STQFAri
  { 3, &SparcDescs.OperandInfo[404] },  // Inst #690 = STHrr
  { 3, &SparcDescs.OperandInfo[397] },  // Inst #689 = STHri
  { 4, &SparcDescs.OperandInfo[400] },  // Inst #688 = STHArr
  { 3, &SparcDescs.OperandInfo[397] },  // Inst #687 = STHAri
  { 3, &SparcDescs.OperandInfo[446] },  // Inst #686 = STFrr
  { 3, &SparcDescs.OperandInfo[439] },  // Inst #685 = STFri
  { 2, &SparcDescs.OperandInfo[174] },  // Inst #684 = STFSRrr
  { 2, &SparcDescs.OperandInfo[172] },  // Inst #683 = STFSRri
  { 4, &SparcDescs.OperandInfo[442] },  // Inst #682 = STFArr
  { 3, &SparcDescs.OperandInfo[439] },  // Inst #681 = STFAri
  { 3, &SparcDescs.OperandInfo[436] },  // Inst #680 = STDrr
  { 3, &SparcDescs.OperandInfo[413] },  // Inst #679 = STDri
  { 3, &SparcDescs.OperandInfo[433] },  // Inst #678 = STDFrr
  { 3, &SparcDescs.OperandInfo[426] },  // Inst #677 = STDFri
  { 2, &SparcDescs.OperandInfo[174] },  // Inst #676 = STDFQrr
  { 2, &SparcDescs.OperandInfo[172] },  // Inst #675 = STDFQri
  { 4, &SparcDescs.OperandInfo[429] },  // Inst #674 = STDFArr
  { 3, &SparcDescs.OperandInfo[426] },  // Inst #673 = STDFAri
  { 3, &SparcDescs.OperandInfo[423] },  // Inst #672 = STDCrr
  { 3, &SparcDescs.OperandInfo[420] },  // Inst #671 = STDCri
  { 2, &SparcDescs.OperandInfo[174] },  // Inst #670 = STDCQrr
  { 2, &SparcDescs.OperandInfo[172] },  // Inst #669 = STDCQri
  { 4, &SparcDescs.OperandInfo[416] },  // Inst #668 = STDArr
  { 3, &SparcDescs.OperandInfo[413] },  // Inst #667 = STDAri
  { 3, &SparcDescs.OperandInfo[410] },  // Inst #666 = STCrr
  { 3, &SparcDescs.OperandInfo[407] },  // Inst #665 = STCri
  { 2, &SparcDescs.OperandInfo[174] },  // Inst #664 = STCSRrr
  { 2, &SparcDescs.OperandInfo[172] },  // Inst #663 = STCSRri
  { 3, &SparcDescs.OperandInfo[404] },  // Inst #662 = STBrr
  { 3, &SparcDescs.OperandInfo[397] },  // Inst #661 = STBri
  { 4, &SparcDescs.OperandInfo[400] },  // Inst #660 = STBArr
  { 3, &SparcDescs.OperandInfo[397] },  // Inst #659 = STBAri
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #658 = STBAR
  { 4, &SparcDescs.OperandInfo[400] },  // Inst #657 = STArr
  { 3, &SparcDescs.OperandInfo[397] },  // Inst #656 = STAri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #655 = SRLrr
  { 3, &SparcDescs.OperandInfo[386] },  // Inst #654 = SRLri
  { 3, &SparcDescs.OperandInfo[383] },  // Inst #653 = SRLXrr
  { 3, &SparcDescs.OperandInfo[380] },  // Inst #652 = SRLXri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #651 = SRArr
  { 3, &SparcDescs.OperandInfo[386] },  // Inst #650 = SRAri
  { 3, &SparcDescs.OperandInfo[383] },  // Inst #649 = SRAXrr
  { 3, &SparcDescs.OperandInfo[380] },  // Inst #648 = SRAXri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #647 = SMULrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #646 = SMULri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #645 = SMULCCrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #644 = SMULCCri
  { 4, &SparcDescs.OperandInfo[393] },  // Inst #643 = SMACrr
  { 4, &SparcDescs.OperandInfo[389] },  // Inst #642 = SMACri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #641 = SLLrr
  { 3, &SparcDescs.OperandInfo[386] },  // Inst #640 = SLLri
  { 3, &SparcDescs.OperandInfo[383] },  // Inst #639 = SLLXrr
  { 3, &SparcDescs.OperandInfo[380] },  // Inst #638 = SLLXri
  { 1, &SparcDescs.OperandInfo[1] },  // Inst #637 = SIR
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #636 = SIAM
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #635 = SHUTDOWN
  { 2, &SparcDescs.OperandInfo[156] },  // Inst #634 = SETHIi
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #633 = SDIVrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #632 = SDIVri
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #631 = SDIVXrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #630 = SDIVXri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #629 = SDIVCCrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #628 = SDIVCCri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #627 = SAVErr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #626 = SAVEri
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #625 = SAVED
  { 2, &SparcDescs.OperandInfo[174] },  // Inst #624 = RETTrr
  { 2, &SparcDescs.OperandInfo[172] },  // Inst #623 = RETTri
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #622 = RETRY
  { 1, &SparcDescs.OperandInfo[1] },  // Inst #621 = RETL
  { 1, &SparcDescs.OperandInfo[1] },  // Inst #620 = RET
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #619 = RESTORErr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #618 = RESTOREri
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #617 = RESTORED
  { 1, &SparcDescs.OperandInfo[377] },  // Inst #616 = RDWIM
  { 1, &SparcDescs.OperandInfo[377] },  // Inst #615 = RDTBR
  { 1, &SparcDescs.OperandInfo[377] },  // Inst #614 = RDPSR
  { 2, &SparcDescs.OperandInfo[378] },  // Inst #613 = RDPR
  { 1, &SparcDescs.OperandInfo[377] },  // Inst #612 = RDFQ
  { 2, &SparcDescs.OperandInfo[375] },  // Inst #611 = RDASR
  { 2, &SparcDescs.OperandInfo[367] },  // Inst #610 = PWRPSRrr
  { 2, &SparcDescs.OperandInfo[156] },  // Inst #609 = PWRPSRri
  { 3, &SparcDescs.OperandInfo[372] },  // Inst #608 = PREFETCHr
  { 3, &SparcDescs.OperandInfo[369] },  // Inst #607 = PREFETCHi
  { 2, &SparcDescs.OperandInfo[367] },  // Inst #606 = POPCrr
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #605 = PDISTN
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #604 = PDIST
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #603 = ORrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #602 = ORri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #601 = ORNrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #600 = ORNri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #599 = ORNCCrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #598 = ORNCCri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #597 = ORCCrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #596 = ORCCri
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #595 = NOP
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #594 = MULXrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #593 = MULXri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #592 = MULSCCrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #591 = MULSCCri
  { 2, &SparcDescs.OperandInfo[365] },  // Inst #590 = MOVXTOD
  { 4, &SparcDescs.OperandInfo[351] },  // Inst #589 = MOVXCCrr
  { 4, &SparcDescs.OperandInfo[347] },  // Inst #588 = MOVXCCri
  { 2, &SparcDescs.OperandInfo[365] },  // Inst #587 = MOVWTOS
  { 2, &SparcDescs.OperandInfo[345] },  // Inst #586 = MOVSTOUW
  { 2, &SparcDescs.OperandInfo[345] },  // Inst #585 = MOVSTOSW
  { 5, &SparcDescs.OperandInfo[360] },  // Inst #584 = MOVRrr
  { 5, &SparcDescs.OperandInfo[355] },  // Inst #583 = MOVRri
  { 4, &SparcDescs.OperandInfo[351] },  // Inst #582 = MOVICCrr
  { 4, &SparcDescs.OperandInfo[347] },  // Inst #581 = MOVICCri
  { 4, &SparcDescs.OperandInfo[351] },  // Inst #580 = MOVFCCrr
  { 4, &SparcDescs.OperandInfo[347] },  // Inst #579 = MOVFCCri
  { 2, &SparcDescs.OperandInfo[345] },  // Inst #578 = MOVDTOX
  { 1, &SparcDescs.OperandInfo[0] },  // Inst #577 = MEMBARi
  { 2, &SparcDescs.OperandInfo[343] },  // Inst #576 = LZCNT
  { 3, &SparcDescs.OperandInfo[282] },  // Inst #575 = LDrr
  { 3, &SparcDescs.OperandInfo[279] },  // Inst #574 = LDri
  { 3, &SparcDescs.OperandInfo[340] },  // Inst #573 = LDXrr
  { 3, &SparcDescs.OperandInfo[337] },  // Inst #572 = LDXri
  { 2, &SparcDescs.OperandInfo[174] },  // Inst #571 = LDXFSRrr
  { 2, &SparcDescs.OperandInfo[172] },  // Inst #570 = LDXFSRri
  { 4, &SparcDescs.OperandInfo[271] },  // Inst #569 = LDXArr
  { 3, &SparcDescs.OperandInfo[337] },  // Inst #568 = LDXAri
  { 3, &SparcDescs.OperandInfo[282] },  // Inst #567 = LDUHrr
  { 3, &SparcDescs.OperandInfo[279] },  // Inst #566 = LDUHri
  { 4, &SparcDescs.OperandInfo[275] },  // Inst #565 = LDUHArr
  { 3, &SparcDescs.OperandInfo[279] },  // Inst #564 = LDUHAri
  { 3, &SparcDescs.OperandInfo[282] },  // Inst #563 = LDUBrr
  { 3, &SparcDescs.OperandInfo[279] },  // Inst #562 = LDUBri
  { 4, &SparcDescs.OperandInfo[275] },  // Inst #561 = LDUBArr
  { 3, &SparcDescs.OperandInfo[279] },  // Inst #560 = LDUBAri
  { 3, &SparcDescs.OperandInfo[340] },  // Inst #559 = LDSWrr
  { 3, &SparcDescs.OperandInfo[337] },  // Inst #558 = LDSWri
  { 4, &SparcDescs.OperandInfo[271] },  // Inst #557 = LDSWArr
  { 3, &SparcDescs.OperandInfo[337] },  // Inst #556 = LDSWAri
  { 3, &SparcDescs.OperandInfo[282] },  // Inst #555 = LDSTUBrr
  { 3, &SparcDescs.OperandInfo[279] },  // Inst #554 = LDSTUBri
  { 4, &SparcDescs.OperandInfo[275] },  // Inst #553 = LDSTUBArr
  { 3, &SparcDescs.OperandInfo[279] },  // Inst #552 = LDSTUBAri
  { 3, &SparcDescs.OperandInfo[282] },  // Inst #551 = LDSHrr
  { 3, &SparcDescs.OperandInfo[279] },  // Inst #550 = LDSHri
  { 4, &SparcDescs.OperandInfo[275] },  // Inst #549 = LDSHArr
  { 3, &SparcDescs.OperandInfo[279] },  // Inst #548 = LDSHAri
  { 3, &SparcDescs.OperandInfo[282] },  // Inst #547 = LDSBrr
  { 3, &SparcDescs.OperandInfo[279] },  // Inst #546 = LDSBri
  { 4, &SparcDescs.OperandInfo[275] },  // Inst #545 = LDSBArr
  { 3, &SparcDescs.OperandInfo[279] },  // Inst #544 = LDSBAri
  { 3, &SparcDescs.OperandInfo[334] },  // Inst #543 = LDQFrr
  { 3, &SparcDescs.OperandInfo[327] },  // Inst #542 = LDQFri
  { 4, &SparcDescs.OperandInfo[330] },  // Inst #541 = LDQFArr
  { 3, &SparcDescs.OperandInfo[327] },  // Inst #540 = LDQFAri
  { 3, &SparcDescs.OperandInfo[324] },  // Inst #539 = LDFrr
  { 3, &SparcDescs.OperandInfo[317] },  // Inst #538 = LDFri
  { 2, &SparcDescs.OperandInfo[174] },  // Inst #537 = LDFSRrr
  { 2, &SparcDescs.OperandInfo[172] },  // Inst #536 = LDFSRri
  { 4, &SparcDescs.OperandInfo[320] },  // Inst #535 = LDFArr
  { 3, &SparcDescs.OperandInfo[317] },  // Inst #534 = LDFAri
  { 3, &SparcDescs.OperandInfo[314] },  // Inst #533 = LDDrr
  { 3, &SparcDescs.OperandInfo[291] },  // Inst #532 = LDDri
  { 3, &SparcDescs.OperandInfo[311] },  // Inst #531 = LDDFrr
  { 3, &SparcDescs.OperandInfo[304] },  // Inst #530 = LDDFri
  { 4, &SparcDescs.OperandInfo[307] },  // Inst #529 = LDDFArr
  { 3, &SparcDescs.OperandInfo[304] },  // Inst #528 = LDDFAri
  { 3, &SparcDescs.OperandInfo[301] },  // Inst #527 = LDDCrr
  { 3, &SparcDescs.OperandInfo[298] },  // Inst #526 = LDDCri
  { 4, &SparcDescs.OperandInfo[294] },  // Inst #525 = LDDArr
  { 3, &SparcDescs.OperandInfo[291] },  // Inst #524 = LDDAri
  { 3, &SparcDescs.OperandInfo[288] },  // Inst #523 = LDCrr
  { 3, &SparcDescs.OperandInfo[285] },  // Inst #522 = LDCri
  { 2, &SparcDescs.OperandInfo[174] },  // Inst #521 = LDCSRrr
  { 2, &SparcDescs.OperandInfo[172] },  // Inst #520 = LDCSRri
  { 4, &SparcDescs.OperandInfo[275] },  // Inst #519 = LDArr
  { 3, &SparcDescs.OperandInfo[279] },  // Inst #518 = LDAri
  { 3, &SparcDescs.OperandInfo[282] },  // Inst #517 = JMPLrr
  { 3, &SparcDescs.OperandInfo[279] },  // Inst #516 = JMPLri
  { 4, &SparcDescs.OperandInfo[275] },  // Inst #515 = GDOP_LDrr
  { 4, &SparcDescs.OperandInfo[271] },  // Inst #514 = GDOP_LDXrr
  { 2, &SparcDescs.OperandInfo[262] },  // Inst #513 = FZEROS
  { 2, &SparcDescs.OperandInfo[260] },  // Inst #512 = FZERO
  { 2, &SparcDescs.OperandInfo[222] },  // Inst #511 = FXTOS
  { 2, &SparcDescs.OperandInfo[224] },  // Inst #510 = FXTOQ
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #509 = FXTOD
  { 3, &SparcDescs.OperandInfo[213] },  // Inst #508 = FXORS
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #507 = FXOR
  { 3, &SparcDescs.OperandInfo[213] },  // Inst #506 = FXNORS
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #505 = FXNOR
  { 3, &SparcDescs.OperandInfo[213] },  // Inst #504 = FSUBS
  { 3, &SparcDescs.OperandInfo[210] },  // Inst #503 = FSUBQ
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #502 = FSUBD
  { 2, &SparcDescs.OperandInfo[226] },  // Inst #501 = FSTOX
  { 2, &SparcDescs.OperandInfo[228] },  // Inst #500 = FSTOQ
  { 2, &SparcDescs.OperandInfo[208] },  // Inst #499 = FSTOI
  { 2, &SparcDescs.OperandInfo[226] },  // Inst #498 = FSTOD
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #497 = FSRL32
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #496 = FSRL16
  { 2, &SparcDescs.OperandInfo[208] },  // Inst #495 = FSRC2S
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #494 = FSRC2
  { 2, &SparcDescs.OperandInfo[208] },  // Inst #493 = FSRC1S
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #492 = FSRC1
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #491 = FSRA32
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #490 = FSRA16
  { 2, &SparcDescs.OperandInfo[208] },  // Inst #489 = FSQRTS
  { 2, &SparcDescs.OperandInfo[206] },  // Inst #488 = FSQRTQ
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #487 = FSQRTD
  { 3, &SparcDescs.OperandInfo[268] },  // Inst #486 = FSMULD
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #485 = FSLL32
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #484 = FSLL16
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #483 = FSLAS32
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #482 = FSLAS16
  { 2, &SparcDescs.OperandInfo[264] },  // Inst #481 = FQTOX
  { 2, &SparcDescs.OperandInfo[266] },  // Inst #480 = FQTOS
  { 2, &SparcDescs.OperandInfo[266] },  // Inst #479 = FQTOI
  { 2, &SparcDescs.OperandInfo[264] },  // Inst #478 = FQTOD
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #477 = FPSUB32S
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #476 = FPSUB32
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #475 = FPSUB16S
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #474 = FPSUB16
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #473 = FPMERGE
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #472 = FPADD64
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #471 = FPADD32S
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #470 = FPADD32
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #469 = FPADD16S
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #468 = FPADD16
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #467 = FPACKFIX
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #466 = FPACK32
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #465 = FPACK16
  { 3, &SparcDescs.OperandInfo[213] },  // Inst #464 = FORS
  { 3, &SparcDescs.OperandInfo[213] },  // Inst #463 = FORNOT2S
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #462 = FORNOT2
  { 3, &SparcDescs.OperandInfo[213] },  // Inst #461 = FORNOT1S
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #460 = FORNOT1
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #459 = FOR
  { 2, &SparcDescs.OperandInfo[262] },  // Inst #458 = FONES
  { 2, &SparcDescs.OperandInfo[260] },  // Inst #457 = FONE
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #456 = FNSMULD
  { 2, &SparcDescs.OperandInfo[208] },  // Inst #455 = FNOT2S
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #454 = FNOT2
  { 2, &SparcDescs.OperandInfo[208] },  // Inst #453 = FNOT1S
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #452 = FNOT1
  { 3, &SparcDescs.OperandInfo[213] },  // Inst #451 = FNORS
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #450 = FNOR
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #449 = FNMULS
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #448 = FNMULD
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #447 = FNHADDS
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #446 = FNHADDD
  { 2, &SparcDescs.OperandInfo[208] },  // Inst #445 = FNEGS
  { 2, &SparcDescs.OperandInfo[206] },  // Inst #444 = FNEGQ
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #443 = FNEGD
  { 3, &SparcDescs.OperandInfo[213] },  // Inst #442 = FNANDS
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #441 = FNAND
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #440 = FNADDS
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #439 = FNADDD
  { 3, &SparcDescs.OperandInfo[213] },  // Inst #438 = FMULS
  { 3, &SparcDescs.OperandInfo[210] },  // Inst #437 = FMULQ
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #436 = FMULD8ULX16
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #435 = FMULD8SUX16
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #434 = FMULD
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #433 = FMUL8X16AU
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #432 = FMUL8X16AL
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #431 = FMUL8X16
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #430 = FMUL8ULX16
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #429 = FMUL8SUX16
  { 4, &SparcDescs.OperandInfo[256] },  // Inst #428 = FMOVS_XCC
  { 4, &SparcDescs.OperandInfo[256] },  // Inst #427 = FMOVS_ICC
  { 4, &SparcDescs.OperandInfo[256] },  // Inst #426 = FMOVS_FCC
  { 2, &SparcDescs.OperandInfo[208] },  // Inst #425 = FMOVS
  { 5, &SparcDescs.OperandInfo[251] },  // Inst #424 = FMOVRS
  { 5, &SparcDescs.OperandInfo[246] },  // Inst #423 = FMOVRQ
  { 5, &SparcDescs.OperandInfo[241] },  // Inst #422 = FMOVRD
  { 4, &SparcDescs.OperandInfo[237] },  // Inst #421 = FMOVQ_XCC
  { 4, &SparcDescs.OperandInfo[237] },  // Inst #420 = FMOVQ_ICC
  { 4, &SparcDescs.OperandInfo[237] },  // Inst #419 = FMOVQ_FCC
  { 2, &SparcDescs.OperandInfo[206] },  // Inst #418 = FMOVQ
  { 4, &SparcDescs.OperandInfo[233] },  // Inst #417 = FMOVD_XCC
  { 4, &SparcDescs.OperandInfo[233] },  // Inst #416 = FMOVD_ICC
  { 4, &SparcDescs.OperandInfo[233] },  // Inst #415 = FMOVD_FCC
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #414 = FMOVD
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #413 = FMEAN16
  { 2, &SparcDescs.OperandInfo[174] },  // Inst #412 = FLUSHrr
  { 2, &SparcDescs.OperandInfo[172] },  // Inst #411 = FLUSHri
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #410 = FLUSHW
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #409 = FLUSH
  { 3, &SparcDescs.OperandInfo[230] },  // Inst #408 = FLCMPS
  { 3, &SparcDescs.OperandInfo[230] },  // Inst #407 = FLCMPD
  { 2, &SparcDescs.OperandInfo[208] },  // Inst #406 = FITOS
  { 2, &SparcDescs.OperandInfo[228] },  // Inst #405 = FITOQ
  { 2, &SparcDescs.OperandInfo[226] },  // Inst #404 = FITOD
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #403 = FHSUBS
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #402 = FHSUBD
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #401 = FHADDS
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #400 = FHADDD
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #399 = FEXPAND
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #398 = FDTOX
  { 2, &SparcDescs.OperandInfo[222] },  // Inst #397 = FDTOS
  { 2, &SparcDescs.OperandInfo[224] },  // Inst #396 = FDTOQ
  { 2, &SparcDescs.OperandInfo[222] },  // Inst #395 = FDTOI
  { 3, &SparcDescs.OperandInfo[219] },  // Inst #394 = FDMULQ
  { 3, &SparcDescs.OperandInfo[213] },  // Inst #393 = FDIVS
  { 3, &SparcDescs.OperandInfo[210] },  // Inst #392 = FDIVQ
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #391 = FDIVD
  { 2, &SparcDescs.OperandInfo[208] },  // Inst #390 = FCMPS_V9
  { 2, &SparcDescs.OperandInfo[208] },  // Inst #389 = FCMPS
  { 2, &SparcDescs.OperandInfo[206] },  // Inst #388 = FCMPQ_V9
  { 2, &SparcDescs.OperandInfo[206] },  // Inst #387 = FCMPQ
  { 3, &SparcDescs.OperandInfo[216] },  // Inst #386 = FCMPNE32
  { 3, &SparcDescs.OperandInfo[216] },  // Inst #385 = FCMPNE16
  { 3, &SparcDescs.OperandInfo[216] },  // Inst #384 = FCMPLE32
  { 3, &SparcDescs.OperandInfo[216] },  // Inst #383 = FCMPLE16
  { 3, &SparcDescs.OperandInfo[216] },  // Inst #382 = FCMPGT32
  { 3, &SparcDescs.OperandInfo[216] },  // Inst #381 = FCMPGT16
  { 3, &SparcDescs.OperandInfo[216] },  // Inst #380 = FCMPEQ32
  { 3, &SparcDescs.OperandInfo[216] },  // Inst #379 = FCMPEQ16
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #378 = FCMPD_V9
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #377 = FCMPD
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #376 = FCHKSM16
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #375 = FBCOND_V9
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #374 = FBCONDA_V9
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #373 = FBCONDA
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #372 = FBCOND
  { 3, &SparcDescs.OperandInfo[213] },  // Inst #371 = FANDS
  { 3, &SparcDescs.OperandInfo[213] },  // Inst #370 = FANDNOT2S
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #369 = FANDNOT2
  { 3, &SparcDescs.OperandInfo[213] },  // Inst #368 = FANDNOT1S
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #367 = FANDNOT1
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #366 = FAND
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #365 = FALIGNADATA
  { 3, &SparcDescs.OperandInfo[213] },  // Inst #364 = FADDS
  { 3, &SparcDescs.OperandInfo[210] },  // Inst #363 = FADDQ
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #362 = FADDD
  { 2, &SparcDescs.OperandInfo[208] },  // Inst #361 = FABSS
  { 2, &SparcDescs.OperandInfo[206] },  // Inst #360 = FABSQ
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #359 = FABSD
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #358 = EDGE8N
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #357 = EDGE8LN
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #356 = EDGE8L
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #355 = EDGE8
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #354 = EDGE32N
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #353 = EDGE32LN
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #352 = EDGE32L
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #351 = EDGE32
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #350 = EDGE16N
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #349 = EDGE16LN
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #348 = EDGE16L
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #347 = EDGE16
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #346 = DONE
  { 1, &SparcDescs.OperandInfo[203] },  // Inst #345 = CMASK8
  { 1, &SparcDescs.OperandInfo[203] },  // Inst #344 = CMASK32
  { 1, &SparcDescs.OperandInfo[203] },  // Inst #343 = CMASK16
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #342 = CBCONDA
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #341 = CBCOND
  { 5, &SparcDescs.OperandInfo[198] },  // Inst #340 = CASXArr
  { 4, &SparcDescs.OperandInfo[194] },  // Inst #339 = CASXAri
  { 5, &SparcDescs.OperandInfo[189] },  // Inst #338 = CASArr
  { 4, &SparcDescs.OperandInfo[185] },  // Inst #337 = CASAri
  { 2, &SparcDescs.OperandInfo[174] },  // Inst #336 = CALLrr
  { 2, &SparcDescs.OperandInfo[172] },  // Inst #335 = CALLri
  { 1, &SparcDescs.OperandInfo[0] },  // Inst #334 = CALL
  { 3, &SparcDescs.OperandInfo[182] },  // Inst #333 = BSHUFFLE
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #332 = BPXCCNT
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #331 = BPXCCANT
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #330 = BPXCCA
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #329 = BPXCC
  { 3, &SparcDescs.OperandInfo[179] },  // Inst #328 = BPRNT
  { 3, &SparcDescs.OperandInfo[179] },  // Inst #327 = BPRANT
  { 3, &SparcDescs.OperandInfo[179] },  // Inst #326 = BPRA
  { 3, &SparcDescs.OperandInfo[179] },  // Inst #325 = BPR
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #324 = BPICCNT
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #323 = BPICCANT
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #322 = BPICCA
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #321 = BPICC
  { 3, &SparcDescs.OperandInfo[176] },  // Inst #320 = BPFCCNT
  { 3, &SparcDescs.OperandInfo[176] },  // Inst #319 = BPFCCANT
  { 3, &SparcDescs.OperandInfo[176] },  // Inst #318 = BPFCCA
  { 3, &SparcDescs.OperandInfo[176] },  // Inst #317 = BPFCC
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #316 = BMASK
  { 2, &SparcDescs.OperandInfo[174] },  // Inst #315 = BINDrr
  { 2, &SparcDescs.OperandInfo[172] },  // Inst #314 = BINDri
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #313 = BCONDA
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #312 = BCOND
  { 1, &SparcDescs.OperandInfo[1] },  // Inst #311 = BA
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #310 = ARRAY8
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #309 = ARRAY32
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #308 = ARRAY16
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #307 = ANDrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #306 = ANDri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #305 = ANDNrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #304 = ANDNri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #303 = ANDNCCrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #302 = ANDNCCri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #301 = ANDCCrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #300 = ANDCCri
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #299 = ALIGNADDRL
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #298 = ALIGNADDR
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #297 = ADDrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #296 = ADDri
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #295 = ADDXCCC
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #294 = ADDXC
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #293 = ADDErr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #292 = ADDEri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #291 = ADDCrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #290 = ADDCri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #289 = ADDCCrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #288 = ADDCCri
  { 3, &SparcDescs.OperandInfo[158] },  // Inst #287 = SETX
  { 2, &SparcDescs.OperandInfo[156] },  // Inst #286 = SET
  { 4, &SparcDescs.OperandInfo[152] },  // Inst #285 = SELECT_CC_QFP_XCC
  { 4, &SparcDescs.OperandInfo[152] },  // Inst #284 = SELECT_CC_QFP_ICC
  { 4, &SparcDescs.OperandInfo[152] },  // Inst #283 = SELECT_CC_QFP_FCC
  { 4, &SparcDescs.OperandInfo[148] },  // Inst #282 = SELECT_CC_Int_XCC
  { 4, &SparcDescs.OperandInfo[148] },  // Inst #281 = SELECT_CC_Int_ICC
  { 4, &SparcDescs.OperandInfo[148] },  // Inst #280 = SELECT_CC_Int_FCC
  { 4, &SparcDescs.OperandInfo[144] },  // Inst #279 = SELECT_CC_FP_XCC
  { 4, &SparcDescs.OperandInfo[144] },  // Inst #278 = SELECT_CC_FP_ICC
  { 4, &SparcDescs.OperandInfo[144] },  // Inst #277 = SELECT_CC_FP_FCC
  { 4, &SparcDescs.OperandInfo[140] },  // Inst #276 = SELECT_CC_DFP_XCC
  { 4, &SparcDescs.OperandInfo[140] },  // Inst #275 = SELECT_CC_DFP_ICC
  { 4, &SparcDescs.OperandInfo[140] },  // Inst #274 = SELECT_CC_DFP_FCC
  { 1, &SparcDescs.OperandInfo[0] },  // Inst #273 = GETPCX
  { 2, &SparcDescs.OperandInfo[21] },  // Inst #272 = ADJCALLSTACKUP
  { 2, &SparcDescs.OperandInfo[21] },  // Inst #271 = ADJCALLSTACKDOWN
  { 4, &SparcDescs.OperandInfo[136] },  // Inst #270 = G_UBFX
  { 4, &SparcDescs.OperandInfo[136] },  // Inst #269 = G_SBFX
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #268 = G_VECREDUCE_UMIN
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #267 = G_VECREDUCE_UMAX
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #266 = G_VECREDUCE_SMIN
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #265 = G_VECREDUCE_SMAX
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #264 = G_VECREDUCE_XOR
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #263 = G_VECREDUCE_OR
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #262 = G_VECREDUCE_AND
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #261 = G_VECREDUCE_MUL
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #260 = G_VECREDUCE_ADD
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #259 = G_VECREDUCE_FMINIMUM
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #258 = G_VECREDUCE_FMAXIMUM
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #257 = G_VECREDUCE_FMIN
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #256 = G_VECREDUCE_FMAX
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #255 = G_VECREDUCE_FMUL
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #254 = G_VECREDUCE_FADD
  { 3, &SparcDescs.OperandInfo[123] },  // Inst #253 = G_VECREDUCE_SEQ_FMUL
  { 3, &SparcDescs.OperandInfo[123] },  // Inst #252 = G_VECREDUCE_SEQ_FADD
  { 3, &SparcDescs.OperandInfo[53] },  // Inst #251 = G_BZERO
  { 4, &SparcDescs.OperandInfo[132] },  // Inst #250 = G_MEMSET
  { 4, &SparcDescs.OperandInfo[132] },  // Inst #249 = G_MEMMOVE
  { 3, &SparcDescs.OperandInfo[123] },  // Inst #248 = G_MEMCPY_INLINE
  { 4, &SparcDescs.OperandInfo[132] },  // Inst #247 = G_MEMCPY
  { 2, &SparcDescs.OperandInfo[130] },  // Inst #246 = G_WRITE_REGISTER
  { 2, &SparcDescs.OperandInfo[51] },  // Inst #245 = G_READ_REGISTER
  { 3, &SparcDescs.OperandInfo[96] },  // Inst #244 = G_STRICT_FLDEXP
  { 2, &SparcDescs.OperandInfo[62] },  // Inst #243 = G_STRICT_FSQRT
  { 4, &SparcDescs.OperandInfo[46] },  // Inst #242 = G_STRICT_FMA
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #241 = G_STRICT_FREM
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #240 = G_STRICT_FDIV
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #239 = G_STRICT_FMUL
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #238 = G_STRICT_FSUB
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #237 = G_STRICT_FADD
  { 1, &SparcDescs.OperandInfo[50] },  // Inst #236 = G_STACKRESTORE
  { 1, &SparcDescs.OperandInfo[50] },  // Inst #235 = G_STACKSAVE
  { 3, &SparcDescs.OperandInfo[64] },  // Inst #234 = G_DYN_STACKALLOC
  { 2, &SparcDescs.OperandInfo[51] },  // Inst #233 = G_JUMP_TABLE
  { 2, &SparcDescs.OperandInfo[51] },  // Inst #232 = G_BLOCK_ADDR
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #231 = G_ADDRSPACE_CAST
  { 2, &SparcDescs.OperandInfo[62] },  // Inst #230 = G_FNEARBYINT
  { 2, &SparcDescs.OperandInfo[62] },  // Inst #229 = G_FRINT
  { 2, &SparcDescs.OperandInfo[62] },  // Inst #228 = G_FFLOOR
  { 2, &SparcDescs.OperandInfo[62] },  // Inst #227 = G_FSQRT
  { 2, &SparcDescs.OperandInfo[62] },  // Inst #226 = G_FSIN
  { 2, &SparcDescs.OperandInfo[62] },  // Inst #225 = G_FCOS
  { 2, &SparcDescs.OperandInfo[62] },  // Inst #224 = G_FCEIL
  { 2, &SparcDescs.OperandInfo[62] },  // Inst #223 = G_BITREVERSE
  { 2, &SparcDescs.OperandInfo[62] },  // Inst #222 = G_BSWAP
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #221 = G_CTPOP
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #220 = G_CTLZ_ZERO_UNDEF
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #219 = G_CTLZ
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #218 = G_CTTZ_ZERO_UNDEF
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #217 = G_CTTZ
  { 4, &SparcDescs.OperandInfo[126] },  // Inst #216 = G_SHUFFLE_VECTOR
  { 3, &SparcDescs.OperandInfo[123] },  // Inst #215 = G_EXTRACT_VECTOR_ELT
  { 4, &SparcDescs.OperandInfo[119] },  // Inst #214 = G_INSERT_VECTOR_ELT
  { 3, &SparcDescs.OperandInfo[116] },  // Inst #213 = G_BRJT
  { 1, &SparcDescs.OperandInfo[0] },  // Inst #212 = G_BR
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #211 = G_LLROUND
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #210 = G_LROUND
  { 2, &SparcDescs.OperandInfo[62] },  // Inst #209 = G_ABS
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #208 = G_UMAX
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #207 = G_UMIN
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #206 = G_SMAX
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #205 = G_SMIN
  { 3, &SparcDescs.OperandInfo[96] },  // Inst #204 = G_PTRMASK
  { 3, &SparcDescs.OperandInfo[96] },  // Inst #203 = G_PTR_ADD
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #202 = G_RESET_FPMODE
  { 1, &SparcDescs.OperandInfo[50] },  // Inst #201 = G_SET_FPMODE
  { 1, &SparcDescs.OperandInfo[50] },  // Inst #200 = G_GET_FPMODE
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #199 = G_RESET_FPENV
  { 1, &SparcDescs.OperandInfo[50] },  // Inst #198 = G_SET_FPENV
  { 1, &SparcDescs.OperandInfo[50] },  // Inst #197 = G_GET_FPENV
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #196 = G_FMAXIMUM
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #195 = G_FMINIMUM
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #194 = G_FMAXNUM_IEEE
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #193 = G_FMINNUM_IEEE
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #192 = G_FMAXNUM
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #191 = G_FMINNUM
  { 2, &SparcDescs.OperandInfo[62] },  // Inst #190 = G_FCANONICALIZE
  { 3, &SparcDescs.OperandInfo[93] },  // Inst #189 = G_IS_FPCLASS
  { 3, &SparcDescs.OperandInfo[96] },  // Inst #188 = G_FCOPYSIGN
  { 2, &SparcDescs.OperandInfo[62] },  // Inst #187 = G_FABS
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #186 = G_UITOFP
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #185 = G_SITOFP
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #184 = G_FPTOUI
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #183 = G_FPTOSI
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #182 = G_FPTRUNC
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #181 = G_FPEXT
  { 2, &SparcDescs.OperandInfo[62] },  // Inst #180 = G_FNEG
  { 3, &SparcDescs.OperandInfo[86] },  // Inst #179 = G_FFREXP
  { 3, &SparcDescs.OperandInfo[96] },  // Inst #178 = G_FLDEXP
  { 2, &SparcDescs.OperandInfo[62] },  // Inst #177 = G_FLOG10
  { 2, &SparcDescs.OperandInfo[62] },  // Inst #176 = G_FLOG2
  { 2, &SparcDescs.OperandInfo[62] },  // Inst #175 = G_FLOG
  { 2, &SparcDescs.OperandInfo[62] },  // Inst #174 = G_FEXP10
  { 2, &SparcDescs.OperandInfo[62] },  // Inst #173 = G_FEXP2
  { 2, &SparcDescs.OperandInfo[62] },  // Inst #172 = G_FEXP
  { 3, &SparcDescs.OperandInfo[96] },  // Inst #171 = G_FPOWI
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #170 = G_FPOW
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #169 = G_FREM
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #168 = G_FDIV
  { 4, &SparcDescs.OperandInfo[46] },  // Inst #167 = G_FMAD
  { 4, &SparcDescs.OperandInfo[46] },  // Inst #166 = G_FMA
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #165 = G_FMUL
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #164 = G_FSUB
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #163 = G_FADD
  { 4, &SparcDescs.OperandInfo[112] },  // Inst #162 = G_UDIVFIXSAT
  { 4, &SparcDescs.OperandInfo[112] },  // Inst #161 = G_SDIVFIXSAT
  { 4, &SparcDescs.OperandInfo[112] },  // Inst #160 = G_UDIVFIX
  { 4, &SparcDescs.OperandInfo[112] },  // Inst #159 = G_SDIVFIX
  { 4, &SparcDescs.OperandInfo[112] },  // Inst #158 = G_UMULFIXSAT
  { 4, &SparcDescs.OperandInfo[112] },  // Inst #157 = G_SMULFIXSAT
  { 4, &SparcDescs.OperandInfo[112] },  // Inst #156 = G_UMULFIX
  { 4, &SparcDescs.OperandInfo[112] },  // Inst #155 = G_SMULFIX
  { 3, &SparcDescs.OperandInfo[96] },  // Inst #154 = G_SSHLSAT
  { 3, &SparcDescs.OperandInfo[96] },  // Inst #153 = G_USHLSAT
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #152 = G_SSUBSAT
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #151 = G_USUBSAT
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #150 = G_SADDSAT
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #149 = G_UADDSAT
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #148 = G_SMULH
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #147 = G_UMULH
  { 4, &SparcDescs.OperandInfo[82] },  // Inst #146 = G_SMULO
  { 4, &SparcDescs.OperandInfo[82] },  // Inst #145 = G_UMULO
  { 5, &SparcDescs.OperandInfo[107] },  // Inst #144 = G_SSUBE
  { 4, &SparcDescs.OperandInfo[82] },  // Inst #143 = G_SSUBO
  { 5, &SparcDescs.OperandInfo[107] },  // Inst #142 = G_SADDE
  { 4, &SparcDescs.OperandInfo[82] },  // Inst #141 = G_SADDO
  { 5, &SparcDescs.OperandInfo[107] },  // Inst #140 = G_USUBE
  { 4, &SparcDescs.OperandInfo[82] },  // Inst #139 = G_USUBO
  { 5, &SparcDescs.OperandInfo[107] },  // Inst #138 = G_UADDE
  { 4, &SparcDescs.OperandInfo[82] },  // Inst #137 = G_UADDO
  { 4, &SparcDescs.OperandInfo[82] },  // Inst #136 = G_SELECT
  { 4, &SparcDescs.OperandInfo[103] },  // Inst #135 = G_FCMP
  { 4, &SparcDescs.OperandInfo[103] },  // Inst #134 = G_ICMP
  { 3, &SparcDescs.OperandInfo[96] },  // Inst #133 = G_ROTL
  { 3, &SparcDescs.OperandInfo[96] },  // Inst #132 = G_ROTR
  { 4, &SparcDescs.OperandInfo[99] },  // Inst #131 = G_FSHR
  { 4, &SparcDescs.OperandInfo[99] },  // Inst #130 = G_FSHL
  { 3, &SparcDescs.OperandInfo[96] },  // Inst #129 = G_ASHR
  { 3, &SparcDescs.OperandInfo[96] },  // Inst #128 = G_LSHR
  { 3, &SparcDescs.OperandInfo[96] },  // Inst #127 = G_SHL
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #126 = G_ZEXT
  { 3, &SparcDescs.OperandInfo[40] },  // Inst #125 = G_SEXT_INREG
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #124 = G_SEXT
  { 3, &SparcDescs.OperandInfo[93] },  // Inst #123 = G_VAARG
  { 1, &SparcDescs.OperandInfo[50] },  // Inst #122 = G_VASTART
  { 2, &SparcDescs.OperandInfo[51] },  // Inst #121 = G_FCONSTANT
  { 2, &SparcDescs.OperandInfo[51] },  // Inst #120 = G_CONSTANT
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #119 = G_TRUNC
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #118 = G_ANYEXT
  { 1, &SparcDescs.OperandInfo[0] },  // Inst #117 = G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS
  { 1, &SparcDescs.OperandInfo[0] },  // Inst #116 = G_INTRINSIC_CONVERGENT
  { 1, &SparcDescs.OperandInfo[0] },  // Inst #115 = G_INTRINSIC_W_SIDE_EFFECTS
  { 1, &SparcDescs.OperandInfo[0] },  // Inst #114 = G_INTRINSIC
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #113 = G_INVOKE_REGION_START
  { 1, &SparcDescs.OperandInfo[50] },  // Inst #112 = G_BRINDIRECT
  { 2, &SparcDescs.OperandInfo[51] },  // Inst #111 = G_BRCOND
  { 4, &SparcDescs.OperandInfo[89] },  // Inst #110 = G_PREFETCH
  { 2, &SparcDescs.OperandInfo[21] },  // Inst #109 = G_FENCE
  { 3, &SparcDescs.OperandInfo[86] },  // Inst #108 = G_ATOMICRMW_UDEC_WRAP
  { 3, &SparcDescs.OperandInfo[86] },  // Inst #107 = G_ATOMICRMW_UINC_WRAP
  { 3, &SparcDescs.OperandInfo[86] },  // Inst #106 = G_ATOMICRMW_FMIN
  { 3, &SparcDescs.OperandInfo[86] },  // Inst #105 = G_ATOMICRMW_FMAX
  { 3, &SparcDescs.OperandInfo[86] },  // Inst #104 = G_ATOMICRMW_FSUB
  { 3, &SparcDescs.OperandInfo[86] },  // Inst #103 = G_ATOMICRMW_FADD
  { 3, &SparcDescs.OperandInfo[86] },  // Inst #102 = G_ATOMICRMW_UMIN
  { 3, &SparcDescs.OperandInfo[86] },  // Inst #101 = G_ATOMICRMW_UMAX
  { 3, &SparcDescs.OperandInfo[86] },  // Inst #100 = G_ATOMICRMW_MIN
  { 3, &SparcDescs.OperandInfo[86] },  // Inst #99 = G_ATOMICRMW_MAX
  { 3, &SparcDescs.OperandInfo[86] },  // Inst #98 = G_ATOMICRMW_XOR
  { 3, &SparcDescs.OperandInfo[86] },  // Inst #97 = G_ATOMICRMW_OR
  { 3, &SparcDescs.OperandInfo[86] },  // Inst #96 = G_ATOMICRMW_NAND
  { 3, &SparcDescs.OperandInfo[86] },  // Inst #95 = G_ATOMICRMW_AND
  { 3, &SparcDescs.OperandInfo[86] },  // Inst #94 = G_ATOMICRMW_SUB
  { 3, &SparcDescs.OperandInfo[86] },  // Inst #93 = G_ATOMICRMW_ADD
  { 3, &SparcDescs.OperandInfo[86] },  // Inst #92 = G_ATOMICRMW_XCHG
  { 4, &SparcDescs.OperandInfo[82] },  // Inst #91 = G_ATOMIC_CMPXCHG
  { 5, &SparcDescs.OperandInfo[77] },  // Inst #90 = G_ATOMIC_CMPXCHG_WITH_SUCCESS
  { 5, &SparcDescs.OperandInfo[72] },  // Inst #89 = G_INDEXED_STORE
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #88 = G_STORE
  { 5, &SparcDescs.OperandInfo[67] },  // Inst #87 = G_INDEXED_ZEXTLOAD
  { 5, &SparcDescs.OperandInfo[67] },  // Inst #86 = G_INDEXED_SEXTLOAD
  { 5, &SparcDescs.OperandInfo[67] },  // Inst #85 = G_INDEXED_LOAD
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #84 = G_ZEXTLOAD
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #83 = G_SEXTLOAD
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #82 = G_LOAD
  { 1, &SparcDescs.OperandInfo[50] },  // Inst #81 = G_READCYCLECOUNTER
  { 2, &SparcDescs.OperandInfo[62] },  // Inst #80 = G_INTRINSIC_ROUNDEVEN
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #79 = G_INTRINSIC_LRINT
  { 2, &SparcDescs.OperandInfo[62] },  // Inst #78 = G_INTRINSIC_ROUND
  { 2, &SparcDescs.OperandInfo[62] },  // Inst #77 = G_INTRINSIC_TRUNC
  { 3, &SparcDescs.OperandInfo[64] },  // Inst #76 = G_INTRINSIC_FPTRUNC_ROUND
  { 2, &SparcDescs.OperandInfo[62] },  // Inst #75 = G_CONSTANT_FOLD_BARRIER
  { 2, &SparcDescs.OperandInfo[62] },  // Inst #74 = G_FREEZE
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #73 = G_BITCAST
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #72 = G_INTTOPTR
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #71 = G_PTRTOINT
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #70 = G_CONCAT_VECTORS
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #69 = G_BUILD_VECTOR_TRUNC
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #68 = G_BUILD_VECTOR
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #67 = G_MERGE_VALUES
  { 4, &SparcDescs.OperandInfo[58] },  // Inst #66 = G_INSERT
  { 2, &SparcDescs.OperandInfo[56] },  // Inst #65 = G_UNMERGE_VALUES
  { 3, &SparcDescs.OperandInfo[53] },  // Inst #64 = G_EXTRACT
  { 2, &SparcDescs.OperandInfo[51] },  // Inst #63 = G_CONSTANT_POOL
  { 2, &SparcDescs.OperandInfo[51] },  // Inst #62 = G_GLOBAL_VALUE
  { 2, &SparcDescs.OperandInfo[51] },  // Inst #61 = G_FRAME_INDEX
  { 1, &SparcDescs.OperandInfo[50] },  // Inst #60 = G_PHI
  { 1, &SparcDescs.OperandInfo[50] },  // Inst #59 = G_IMPLICIT_DEF
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #58 = G_XOR
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #57 = G_OR
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #56 = G_AND
  { 4, &SparcDescs.OperandInfo[46] },  // Inst #55 = G_UDIVREM
  { 4, &SparcDescs.OperandInfo[46] },  // Inst #54 = G_SDIVREM
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #53 = G_UREM
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #52 = G_SREM
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #51 = G_UDIV
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #50 = G_SDIV
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #49 = G_MUL
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #48 = G_SUB
  { 3, &SparcDescs.OperandInfo[43] },  // Inst #47 = G_ADD
  { 3, &SparcDescs.OperandInfo[40] },  // Inst #46 = G_ASSERT_ALIGN
  { 3, &SparcDescs.OperandInfo[40] },  // Inst #45 = G_ASSERT_ZEXT
  { 3, &SparcDescs.OperandInfo[40] },  // Inst #44 = G_ASSERT_SEXT
  { 1, &SparcDescs.OperandInfo[1] },  // Inst #43 = JUMP_TABLE_DEBUG_INFO
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #42 = MEMBARRIER
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #41 = ICALL_BRANCH_FUNNEL
  { 3, &SparcDescs.OperandInfo[37] },  // Inst #40 = PATCHABLE_TYPED_EVENT_CALL
  { 2, &SparcDescs.OperandInfo[35] },  // Inst #39 = PATCHABLE_EVENT_CALL
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #38 = PATCHABLE_TAIL_CALL
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #37 = PATCHABLE_FUNCTION_EXIT
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #36 = PATCHABLE_RET
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #35 = PATCHABLE_FUNCTION_ENTER
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #34 = PATCHABLE_OP
  { 1, &SparcDescs.OperandInfo[0] },  // Inst #33 = FAULTING_OP
  { 2, &SparcDescs.OperandInfo[33] },  // Inst #32 = LOCAL_ESCAPE
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #31 = STATEPOINT
  { 3, &SparcDescs.OperandInfo[30] },  // Inst #30 = PREALLOCATED_ARG
  { 1, &SparcDescs.OperandInfo[1] },  // Inst #29 = PREALLOCATED_SETUP
  { 1, &SparcDescs.OperandInfo[29] },  // Inst #28 = LOAD_STACK_GUARD
  { 6, &SparcDescs.OperandInfo[23] },  // Inst #27 = PATCHPOINT
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #26 = FENTRY_CALL
  { 2, &SparcDescs.OperandInfo[21] },  // Inst #25 = STACKMAP
  { 2, &SparcDescs.OperandInfo[19] },  // Inst #24 = ARITH_FENCE
  { 4, &SparcDescs.OperandInfo[15] },  // Inst #23 = PSEUDO_PROBE
  { 1, &SparcDescs.OperandInfo[1] },  // Inst #22 = LIFETIME_END
  { 1, &SparcDescs.OperandInfo[1] },  // Inst #21 = LIFETIME_START
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #20 = BUNDLE
  { 2, &SparcDescs.OperandInfo[13] },  // Inst #19 = COPY
  { 2, &SparcDescs.OperandInfo[13] },  // Inst #18 = REG_SEQUENCE
  { 1, &SparcDescs.OperandInfo[0] },  // Inst #17 = DBG_LABEL
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #16 = DBG_PHI
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #15 = DBG_INSTR_REF
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #14 = DBG_VALUE_LIST
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #13 = DBG_VALUE
  { 3, &SparcDescs.OperandInfo[2] },  // Inst #12 = COPY_TO_REGCLASS
  { 4, &SparcDescs.OperandInfo[9] },  // Inst #11 = SUBREG_TO_REG
  { 1, &SparcDescs.OperandInfo[0] },  // Inst #10 = IMPLICIT_DEF
  { 4, &SparcDescs.OperandInfo[5] },  // Inst #9 = INSERT_SUBREG
  { 3, &SparcDescs.OperandInfo[2] },  // Inst #8 = EXTRACT_SUBREG
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #7 = KILL
  { 1, &SparcDescs.OperandInfo[1] },  // Inst #6 = ANNOTATION_LABEL
  { 1, &SparcDescs.OperandInfo[1] },  // Inst #5 = GC_LABEL
  { 1, &SparcDescs.OperandInfo[1] },  // Inst #4 = EH_LABEL
  { 1, &SparcDescs.OperandInfo[1] },  // Inst #3 = CFI_INSTRUCTION
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #2 = INLINEASM_BR
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #1 = INLINEASM
  { 1, &SparcDescs.OperandInfo[0] },  // Inst #0 = PHI
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
    /* 140 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 144 */ { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 148 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 152 */ { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 156 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 158 */ { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 161 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 164 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 167 */ { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 170 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 172 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 174 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 },
    /* 176 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 179 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 182 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 185 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 189 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 194 */ { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 198 */ { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 203 */ { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 204 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 206 */ { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 208 */ { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 210 */ { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 213 */ { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 216 */ { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 219 */ { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 222 */ { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 224 */ { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 226 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 228 */ { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 230 */ { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 233 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 237 */ { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 241 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 246 */ { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 251 */ { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 256 */ { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 260 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 262 */ { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 264 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 266 */ { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 268 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 271 */ { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 275 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 279 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 282 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 },
    /* 285 */ { SP_CoprocRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 288 */ { SP_CoprocRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 },
    /* 291 */ { SP_IntPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 294 */ { SP_IntPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 298 */ { SP_CoprocPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 301 */ { SP_CoprocPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 },
    /* 304 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 307 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 311 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 },
    /* 314 */ { SP_IntPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 },
    /* 317 */ { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 320 */ { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 324 */ { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 },
    /* 327 */ { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 330 */ { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 334 */ { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 },
    /* 337 */ { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 340 */ { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 },
    /* 343 */ { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 345 */ { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 347 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 351 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 355 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 360 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 365 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 367 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 369 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 372 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 375 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_ASRRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 377 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 378 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_PRRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 380 */ { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 383 */ { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 386 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 389 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SP_ASRRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 393 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_ASRRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 397 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 400 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 404 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 407 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SP_CoprocRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 410 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { SP_CoprocRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 413 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SP_IntPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 416 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { SP_IntPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 420 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SP_CoprocPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 423 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { SP_CoprocPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 426 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 429 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 433 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 436 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { SP_IntPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 439 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 442 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 446 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 449 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 452 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 456 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 459 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 462 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 466 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 469 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 473 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 478 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_MEMORY, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 482 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 485 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 489 */ { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 492 */ { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 495 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 500 */ { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 505 */ { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 510 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 515 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 520 */ { SP_ASRRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 523 */ { SP_ASRRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 526 */ { SP_PRRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 529 */ { SP_PRRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
  }, {
    /* 0 */
    /* 0 */ Sparc_O6, Sparc_O6,
    /* 2 */ Sparc_O7,
    /* 3 */ Sparc_FCC0,
    /* 4 */ Sparc_ICC,
    /* 5 */ Sparc_ICC, Sparc_ICC,
    /* 7 */ Sparc_O6,
    /* 8 */ Sparc_ASR3,
    /* 9 */ Sparc_CPSR,
    /* 10 */ Sparc_FSR,
    /* 11 */ Sparc_Y, Sparc_ICC, Sparc_Y, Sparc_ICC,
    /* 15 */ Sparc_PSR,
    /* 16 */ Sparc_FQ,
    /* 17 */ Sparc_TBR,
    /* 18 */ Sparc_WIM,
    /* 19 */ Sparc_Y, Sparc_Y, Sparc_ICC,
    /* 22 */ Sparc_Y, Sparc_Y,
    /* 24 */ Sparc_Y, Sparc_ASR18, Sparc_Y, Sparc_ASR18,
    /* 28 */ Sparc_Y, Sparc_ICC,
    /* 30 */ Sparc_Y,
    /* 31 */ Sparc_CPQ,
  }
};

#endif // GET_INSTRINFO_MC_DESC

#ifdef GET_COMPUTE_FEATURES
#undef GET_COMPUTE_FEATURES

#endif // GET_COMPUTE_FEATURES

#ifdef GET_AVAILABLE_OPCODE_CHECKER
#undef GET_AVAILABLE_OPCODE_CHECKER

#endif // GET_AVAILABLE_OPCODE_CHECKER


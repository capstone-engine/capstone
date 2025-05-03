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
    SP_PHI	= 0,
    SP_INLINEASM	= 1,
    SP_INLINEASM_BR	= 2,
    SP_CFI_INSTRUCTION	= 3,
    SP_EH_LABEL	= 4,
    SP_GC_LABEL	= 5,
    SP_ANNOTATION_LABEL	= 6,
    SP_KILL	= 7,
    SP_EXTRACT_SUBREG	= 8,
    SP_INSERT_SUBREG	= 9,
    SP_IMPLICIT_DEF	= 10,
    SP_SUBREG_TO_REG	= 11,
    SP_COPY_TO_REGCLASS	= 12,
    SP_DBG_VALUE	= 13,
    SP_DBG_VALUE_LIST	= 14,
    SP_DBG_INSTR_REF	= 15,
    SP_DBG_PHI	= 16,
    SP_DBG_LABEL	= 17,
    SP_REG_SEQUENCE	= 18,
    SP_COPY	= 19,
    SP_BUNDLE	= 20,
    SP_LIFETIME_START	= 21,
    SP_LIFETIME_END	= 22,
    SP_PSEUDO_PROBE	= 23,
    SP_ARITH_FENCE	= 24,
    SP_STACKMAP	= 25,
    SP_FENTRY_CALL	= 26,
    SP_PATCHPOINT	= 27,
    SP_LOAD_STACK_GUARD	= 28,
    SP_PREALLOCATED_SETUP	= 29,
    SP_PREALLOCATED_ARG	= 30,
    SP_STATEPOINT	= 31,
    SP_LOCAL_ESCAPE	= 32,
    SP_FAULTING_OP	= 33,
    SP_PATCHABLE_OP	= 34,
    SP_PATCHABLE_FUNCTION_ENTER	= 35,
    SP_PATCHABLE_RET	= 36,
    SP_PATCHABLE_FUNCTION_EXIT	= 37,
    SP_PATCHABLE_TAIL_CALL	= 38,
    SP_PATCHABLE_EVENT_CALL	= 39,
    SP_PATCHABLE_TYPED_EVENT_CALL	= 40,
    SP_ICALL_BRANCH_FUNNEL	= 41,
    SP_MEMBARRIER	= 42,
    SP_JUMP_TABLE_DEBUG_INFO	= 43,
    SP_G_ASSERT_SEXT	= 44,
    SP_G_ASSERT_ZEXT	= 45,
    SP_G_ASSERT_ALIGN	= 46,
    SP_G_ADD	= 47,
    SP_G_SUB	= 48,
    SP_G_MUL	= 49,
    SP_G_SDIV	= 50,
    SP_G_UDIV	= 51,
    SP_G_SREM	= 52,
    SP_G_UREM	= 53,
    SP_G_SDIVREM	= 54,
    SP_G_UDIVREM	= 55,
    SP_G_AND	= 56,
    SP_G_OR	= 57,
    SP_G_XOR	= 58,
    SP_G_IMPLICIT_DEF	= 59,
    SP_G_PHI	= 60,
    SP_G_FRAME_INDEX	= 61,
    SP_G_GLOBAL_VALUE	= 62,
    SP_G_CONSTANT_POOL	= 63,
    SP_G_EXTRACT	= 64,
    SP_G_UNMERGE_VALUES	= 65,
    SP_G_INSERT	= 66,
    SP_G_MERGE_VALUES	= 67,
    SP_G_BUILD_VECTOR	= 68,
    SP_G_BUILD_VECTOR_TRUNC	= 69,
    SP_G_CONCAT_VECTORS	= 70,
    SP_G_PTRTOINT	= 71,
    SP_G_INTTOPTR	= 72,
    SP_G_BITCAST	= 73,
    SP_G_FREEZE	= 74,
    SP_G_CONSTANT_FOLD_BARRIER	= 75,
    SP_G_INTRINSIC_FPTRUNC_ROUND	= 76,
    SP_G_INTRINSIC_TRUNC	= 77,
    SP_G_INTRINSIC_ROUND	= 78,
    SP_G_INTRINSIC_LRINT	= 79,
    SP_G_INTRINSIC_ROUNDEVEN	= 80,
    SP_G_READCYCLECOUNTER	= 81,
    SP_G_LOAD	= 82,
    SP_G_SEXTLOAD	= 83,
    SP_G_ZEXTLOAD	= 84,
    SP_G_INDEXED_LOAD	= 85,
    SP_G_INDEXED_SEXTLOAD	= 86,
    SP_G_INDEXED_ZEXTLOAD	= 87,
    SP_G_STORE	= 88,
    SP_G_INDEXED_STORE	= 89,
    SP_G_ATOMIC_CMPXCHG_WITH_SUCCESS	= 90,
    SP_G_ATOMIC_CMPXCHG	= 91,
    SP_G_ATOMICRMW_XCHG	= 92,
    SP_G_ATOMICRMW_ADD	= 93,
    SP_G_ATOMICRMW_SUB	= 94,
    SP_G_ATOMICRMW_AND	= 95,
    SP_G_ATOMICRMW_NAND	= 96,
    SP_G_ATOMICRMW_OR	= 97,
    SP_G_ATOMICRMW_XOR	= 98,
    SP_G_ATOMICRMW_MAX	= 99,
    SP_G_ATOMICRMW_MIN	= 100,
    SP_G_ATOMICRMW_UMAX	= 101,
    SP_G_ATOMICRMW_UMIN	= 102,
    SP_G_ATOMICRMW_FADD	= 103,
    SP_G_ATOMICRMW_FSUB	= 104,
    SP_G_ATOMICRMW_FMAX	= 105,
    SP_G_ATOMICRMW_FMIN	= 106,
    SP_G_ATOMICRMW_UINC_WRAP	= 107,
    SP_G_ATOMICRMW_UDEC_WRAP	= 108,
    SP_G_FENCE	= 109,
    SP_G_PREFETCH	= 110,
    SP_G_BRCOND	= 111,
    SP_G_BRINDIRECT	= 112,
    SP_G_INVOKE_REGION_START	= 113,
    SP_G_INTRINSIC	= 114,
    SP_G_INTRINSIC_W_SIDE_EFFECTS	= 115,
    SP_G_INTRINSIC_CONVERGENT	= 116,
    SP_G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS	= 117,
    SP_G_ANYEXT	= 118,
    SP_G_TRUNC	= 119,
    SP_G_CONSTANT	= 120,
    SP_G_FCONSTANT	= 121,
    SP_G_VASTART	= 122,
    SP_G_VAARG	= 123,
    SP_G_SEXT	= 124,
    SP_G_SEXT_INREG	= 125,
    SP_G_ZEXT	= 126,
    SP_G_SHL	= 127,
    SP_G_LSHR	= 128,
    SP_G_ASHR	= 129,
    SP_G_FSHL	= 130,
    SP_G_FSHR	= 131,
    SP_G_ROTR	= 132,
    SP_G_ROTL	= 133,
    SP_G_ICMP	= 134,
    SP_G_FCMP	= 135,
    SP_G_SELECT	= 136,
    SP_G_UADDO	= 137,
    SP_G_UADDE	= 138,
    SP_G_USUBO	= 139,
    SP_G_USUBE	= 140,
    SP_G_SADDO	= 141,
    SP_G_SADDE	= 142,
    SP_G_SSUBO	= 143,
    SP_G_SSUBE	= 144,
    SP_G_UMULO	= 145,
    SP_G_SMULO	= 146,
    SP_G_UMULH	= 147,
    SP_G_SMULH	= 148,
    SP_G_UADDSAT	= 149,
    SP_G_SADDSAT	= 150,
    SP_G_USUBSAT	= 151,
    SP_G_SSUBSAT	= 152,
    SP_G_USHLSAT	= 153,
    SP_G_SSHLSAT	= 154,
    SP_G_SMULFIX	= 155,
    SP_G_UMULFIX	= 156,
    SP_G_SMULFIXSAT	= 157,
    SP_G_UMULFIXSAT	= 158,
    SP_G_SDIVFIX	= 159,
    SP_G_UDIVFIX	= 160,
    SP_G_SDIVFIXSAT	= 161,
    SP_G_UDIVFIXSAT	= 162,
    SP_G_FADD	= 163,
    SP_G_FSUB	= 164,
    SP_G_FMUL	= 165,
    SP_G_FMA	= 166,
    SP_G_FMAD	= 167,
    SP_G_FDIV	= 168,
    SP_G_FREM	= 169,
    SP_G_FPOW	= 170,
    SP_G_FPOWI	= 171,
    SP_G_FEXP	= 172,
    SP_G_FEXP2	= 173,
    SP_G_FEXP10	= 174,
    SP_G_FLOG	= 175,
    SP_G_FLOG2	= 176,
    SP_G_FLOG10	= 177,
    SP_G_FLDEXP	= 178,
    SP_G_FFREXP	= 179,
    SP_G_FNEG	= 180,
    SP_G_FPEXT	= 181,
    SP_G_FPTRUNC	= 182,
    SP_G_FPTOSI	= 183,
    SP_G_FPTOUI	= 184,
    SP_G_SITOFP	= 185,
    SP_G_UITOFP	= 186,
    SP_G_FABS	= 187,
    SP_G_FCOPYSIGN	= 188,
    SP_G_IS_FPCLASS	= 189,
    SP_G_FCANONICALIZE	= 190,
    SP_G_FMINNUM	= 191,
    SP_G_FMAXNUM	= 192,
    SP_G_FMINNUM_IEEE	= 193,
    SP_G_FMAXNUM_IEEE	= 194,
    SP_G_FMINIMUM	= 195,
    SP_G_FMAXIMUM	= 196,
    SP_G_GET_FPENV	= 197,
    SP_G_SET_FPENV	= 198,
    SP_G_RESET_FPENV	= 199,
    SP_G_GET_FPMODE	= 200,
    SP_G_SET_FPMODE	= 201,
    SP_G_RESET_FPMODE	= 202,
    SP_G_PTR_ADD	= 203,
    SP_G_PTRMASK	= 204,
    SP_G_SMIN	= 205,
    SP_G_SMAX	= 206,
    SP_G_UMIN	= 207,
    SP_G_UMAX	= 208,
    SP_G_ABS	= 209,
    SP_G_LROUND	= 210,
    SP_G_LLROUND	= 211,
    SP_G_BR	= 212,
    SP_G_BRJT	= 213,
    SP_G_INSERT_VECTOR_ELT	= 214,
    SP_G_EXTRACT_VECTOR_ELT	= 215,
    SP_G_SHUFFLE_VECTOR	= 216,
    SP_G_CTTZ	= 217,
    SP_G_CTTZ_ZERO_UNDEF	= 218,
    SP_G_CTLZ	= 219,
    SP_G_CTLZ_ZERO_UNDEF	= 220,
    SP_G_CTPOP	= 221,
    SP_G_BSWAP	= 222,
    SP_G_BITREVERSE	= 223,
    SP_G_FCEIL	= 224,
    SP_G_FCOS	= 225,
    SP_G_FSIN	= 226,
    SP_G_FSQRT	= 227,
    SP_G_FFLOOR	= 228,
    SP_G_FRINT	= 229,
    SP_G_FNEARBYINT	= 230,
    SP_G_ADDRSPACE_CAST	= 231,
    SP_G_BLOCK_ADDR	= 232,
    SP_G_JUMP_TABLE	= 233,
    SP_G_DYN_STACKALLOC	= 234,
    SP_G_STACKSAVE	= 235,
    SP_G_STACKRESTORE	= 236,
    SP_G_STRICT_FADD	= 237,
    SP_G_STRICT_FSUB	= 238,
    SP_G_STRICT_FMUL	= 239,
    SP_G_STRICT_FDIV	= 240,
    SP_G_STRICT_FREM	= 241,
    SP_G_STRICT_FMA	= 242,
    SP_G_STRICT_FSQRT	= 243,
    SP_G_STRICT_FLDEXP	= 244,
    SP_G_READ_REGISTER	= 245,
    SP_G_WRITE_REGISTER	= 246,
    SP_G_MEMCPY	= 247,
    SP_G_MEMCPY_INLINE	= 248,
    SP_G_MEMMOVE	= 249,
    SP_G_MEMSET	= 250,
    SP_G_BZERO	= 251,
    SP_G_VECREDUCE_SEQ_FADD	= 252,
    SP_G_VECREDUCE_SEQ_FMUL	= 253,
    SP_G_VECREDUCE_FADD	= 254,
    SP_G_VECREDUCE_FMUL	= 255,
    SP_G_VECREDUCE_FMAX	= 256,
    SP_G_VECREDUCE_FMIN	= 257,
    SP_G_VECREDUCE_FMAXIMUM	= 258,
    SP_G_VECREDUCE_FMINIMUM	= 259,
    SP_G_VECREDUCE_ADD	= 260,
    SP_G_VECREDUCE_MUL	= 261,
    SP_G_VECREDUCE_AND	= 262,
    SP_G_VECREDUCE_OR	= 263,
    SP_G_VECREDUCE_XOR	= 264,
    SP_G_VECREDUCE_SMAX	= 265,
    SP_G_VECREDUCE_SMIN	= 266,
    SP_G_VECREDUCE_UMAX	= 267,
    SP_G_VECREDUCE_UMIN	= 268,
    SP_G_SBFX	= 269,
    SP_G_UBFX	= 270,
    SP_ADJCALLSTACKDOWN	= 271,
    SP_ADJCALLSTACKUP	= 272,
    SP_GETPCX	= 273,
    SP_SELECT_CC_DFP_FCC	= 274,
    SP_SELECT_CC_DFP_ICC	= 275,
    SP_SELECT_CC_DFP_XCC	= 276,
    SP_SELECT_CC_FP_FCC	= 277,
    SP_SELECT_CC_FP_ICC	= 278,
    SP_SELECT_CC_FP_XCC	= 279,
    SP_SELECT_CC_Int_FCC	= 280,
    SP_SELECT_CC_Int_ICC	= 281,
    SP_SELECT_CC_Int_XCC	= 282,
    SP_SELECT_CC_QFP_FCC	= 283,
    SP_SELECT_CC_QFP_ICC	= 284,
    SP_SELECT_CC_QFP_XCC	= 285,
    SP_SET	= 286,
    SP_SETX	= 287,
    SP_ADDCCri	= 288,
    SP_ADDCCrr	= 289,
    SP_ADDCri	= 290,
    SP_ADDCrr	= 291,
    SP_ADDEri	= 292,
    SP_ADDErr	= 293,
    SP_ADDXC	= 294,
    SP_ADDXCCC	= 295,
    SP_ADDri	= 296,
    SP_ADDrr	= 297,
    SP_ALIGNADDR	= 298,
    SP_ALIGNADDRL	= 299,
    SP_ANDCCri	= 300,
    SP_ANDCCrr	= 301,
    SP_ANDNCCri	= 302,
    SP_ANDNCCrr	= 303,
    SP_ANDNri	= 304,
    SP_ANDNrr	= 305,
    SP_ANDri	= 306,
    SP_ANDrr	= 307,
    SP_ARRAY16	= 308,
    SP_ARRAY32	= 309,
    SP_ARRAY8	= 310,
    SP_BA	= 311,
    SP_BCOND	= 312,
    SP_BCONDA	= 313,
    SP_BINDri	= 314,
    SP_BINDrr	= 315,
    SP_BMASK	= 316,
    SP_BPFCC	= 317,
    SP_BPFCCA	= 318,
    SP_BPFCCANT	= 319,
    SP_BPFCCNT	= 320,
    SP_BPICC	= 321,
    SP_BPICCA	= 322,
    SP_BPICCANT	= 323,
    SP_BPICCNT	= 324,
    SP_BPR	= 325,
    SP_BPRA	= 326,
    SP_BPRANT	= 327,
    SP_BPRNT	= 328,
    SP_BPXCC	= 329,
    SP_BPXCCA	= 330,
    SP_BPXCCANT	= 331,
    SP_BPXCCNT	= 332,
    SP_BSHUFFLE	= 333,
    SP_CALL	= 334,
    SP_CALLri	= 335,
    SP_CALLrr	= 336,
    SP_CASAri	= 337,
    SP_CASArr	= 338,
    SP_CASXAri	= 339,
    SP_CASXArr	= 340,
    SP_CBCOND	= 341,
    SP_CBCONDA	= 342,
    SP_CMASK16	= 343,
    SP_CMASK32	= 344,
    SP_CMASK8	= 345,
    SP_DONE	= 346,
    SP_EDGE16	= 347,
    SP_EDGE16L	= 348,
    SP_EDGE16LN	= 349,
    SP_EDGE16N	= 350,
    SP_EDGE32	= 351,
    SP_EDGE32L	= 352,
    SP_EDGE32LN	= 353,
    SP_EDGE32N	= 354,
    SP_EDGE8	= 355,
    SP_EDGE8L	= 356,
    SP_EDGE8LN	= 357,
    SP_EDGE8N	= 358,
    SP_FABSD	= 359,
    SP_FABSQ	= 360,
    SP_FABSS	= 361,
    SP_FADDD	= 362,
    SP_FADDQ	= 363,
    SP_FADDS	= 364,
    SP_FALIGNADATA	= 365,
    SP_FAND	= 366,
    SP_FANDNOT1	= 367,
    SP_FANDNOT1S	= 368,
    SP_FANDNOT2	= 369,
    SP_FANDNOT2S	= 370,
    SP_FANDS	= 371,
    SP_FBCOND	= 372,
    SP_FBCONDA	= 373,
    SP_FBCONDA_V9	= 374,
    SP_FBCOND_V9	= 375,
    SP_FCHKSM16	= 376,
    SP_FCMPD	= 377,
    SP_FCMPD_V9	= 378,
    SP_FCMPEQ16	= 379,
    SP_FCMPEQ32	= 380,
    SP_FCMPGT16	= 381,
    SP_FCMPGT32	= 382,
    SP_FCMPLE16	= 383,
    SP_FCMPLE32	= 384,
    SP_FCMPNE16	= 385,
    SP_FCMPNE32	= 386,
    SP_FCMPQ	= 387,
    SP_FCMPQ_V9	= 388,
    SP_FCMPS	= 389,
    SP_FCMPS_V9	= 390,
    SP_FDIVD	= 391,
    SP_FDIVQ	= 392,
    SP_FDIVS	= 393,
    SP_FDMULQ	= 394,
    SP_FDTOI	= 395,
    SP_FDTOQ	= 396,
    SP_FDTOS	= 397,
    SP_FDTOX	= 398,
    SP_FEXPAND	= 399,
    SP_FHADDD	= 400,
    SP_FHADDS	= 401,
    SP_FHSUBD	= 402,
    SP_FHSUBS	= 403,
    SP_FITOD	= 404,
    SP_FITOQ	= 405,
    SP_FITOS	= 406,
    SP_FLCMPD	= 407,
    SP_FLCMPS	= 408,
    SP_FLUSH	= 409,
    SP_FLUSHW	= 410,
    SP_FLUSHri	= 411,
    SP_FLUSHrr	= 412,
    SP_FMEAN16	= 413,
    SP_FMOVD	= 414,
    SP_FMOVD_FCC	= 415,
    SP_FMOVD_ICC	= 416,
    SP_FMOVD_XCC	= 417,
    SP_FMOVQ	= 418,
    SP_FMOVQ_FCC	= 419,
    SP_FMOVQ_ICC	= 420,
    SP_FMOVQ_XCC	= 421,
    SP_FMOVRD	= 422,
    SP_FMOVRQ	= 423,
    SP_FMOVRS	= 424,
    SP_FMOVS	= 425,
    SP_FMOVS_FCC	= 426,
    SP_FMOVS_ICC	= 427,
    SP_FMOVS_XCC	= 428,
    SP_FMUL8SUX16	= 429,
    SP_FMUL8ULX16	= 430,
    SP_FMUL8X16	= 431,
    SP_FMUL8X16AL	= 432,
    SP_FMUL8X16AU	= 433,
    SP_FMULD	= 434,
    SP_FMULD8SUX16	= 435,
    SP_FMULD8ULX16	= 436,
    SP_FMULQ	= 437,
    SP_FMULS	= 438,
    SP_FNADDD	= 439,
    SP_FNADDS	= 440,
    SP_FNAND	= 441,
    SP_FNANDS	= 442,
    SP_FNEGD	= 443,
    SP_FNEGQ	= 444,
    SP_FNEGS	= 445,
    SP_FNHADDD	= 446,
    SP_FNHADDS	= 447,
    SP_FNMULD	= 448,
    SP_FNMULS	= 449,
    SP_FNOR	= 450,
    SP_FNORS	= 451,
    SP_FNOT1	= 452,
    SP_FNOT1S	= 453,
    SP_FNOT2	= 454,
    SP_FNOT2S	= 455,
    SP_FNSMULD	= 456,
    SP_FONE	= 457,
    SP_FONES	= 458,
    SP_FOR	= 459,
    SP_FORNOT1	= 460,
    SP_FORNOT1S	= 461,
    SP_FORNOT2	= 462,
    SP_FORNOT2S	= 463,
    SP_FORS	= 464,
    SP_FPACK16	= 465,
    SP_FPACK32	= 466,
    SP_FPACKFIX	= 467,
    SP_FPADD16	= 468,
    SP_FPADD16S	= 469,
    SP_FPADD32	= 470,
    SP_FPADD32S	= 471,
    SP_FPADD64	= 472,
    SP_FPMERGE	= 473,
    SP_FPSUB16	= 474,
    SP_FPSUB16S	= 475,
    SP_FPSUB32	= 476,
    SP_FPSUB32S	= 477,
    SP_FQTOD	= 478,
    SP_FQTOI	= 479,
    SP_FQTOS	= 480,
    SP_FQTOX	= 481,
    SP_FSLAS16	= 482,
    SP_FSLAS32	= 483,
    SP_FSLL16	= 484,
    SP_FSLL32	= 485,
    SP_FSMULD	= 486,
    SP_FSQRTD	= 487,
    SP_FSQRTQ	= 488,
    SP_FSQRTS	= 489,
    SP_FSRA16	= 490,
    SP_FSRA32	= 491,
    SP_FSRC1	= 492,
    SP_FSRC1S	= 493,
    SP_FSRC2	= 494,
    SP_FSRC2S	= 495,
    SP_FSRL16	= 496,
    SP_FSRL32	= 497,
    SP_FSTOD	= 498,
    SP_FSTOI	= 499,
    SP_FSTOQ	= 500,
    SP_FSTOX	= 501,
    SP_FSUBD	= 502,
    SP_FSUBQ	= 503,
    SP_FSUBS	= 504,
    SP_FXNOR	= 505,
    SP_FXNORS	= 506,
    SP_FXOR	= 507,
    SP_FXORS	= 508,
    SP_FXTOD	= 509,
    SP_FXTOQ	= 510,
    SP_FXTOS	= 511,
    SP_FZERO	= 512,
    SP_FZEROS	= 513,
    SP_GDOP_LDXrr	= 514,
    SP_GDOP_LDrr	= 515,
    SP_JMPLri	= 516,
    SP_JMPLrr	= 517,
    SP_LDAri	= 518,
    SP_LDArr	= 519,
    SP_LDCSRri	= 520,
    SP_LDCSRrr	= 521,
    SP_LDCri	= 522,
    SP_LDCrr	= 523,
    SP_LDDAri	= 524,
    SP_LDDArr	= 525,
    SP_LDDCri	= 526,
    SP_LDDCrr	= 527,
    SP_LDDFAri	= 528,
    SP_LDDFArr	= 529,
    SP_LDDFri	= 530,
    SP_LDDFrr	= 531,
    SP_LDDri	= 532,
    SP_LDDrr	= 533,
    SP_LDFAri	= 534,
    SP_LDFArr	= 535,
    SP_LDFSRri	= 536,
    SP_LDFSRrr	= 537,
    SP_LDFri	= 538,
    SP_LDFrr	= 539,
    SP_LDQFAri	= 540,
    SP_LDQFArr	= 541,
    SP_LDQFri	= 542,
    SP_LDQFrr	= 543,
    SP_LDSBAri	= 544,
    SP_LDSBArr	= 545,
    SP_LDSBri	= 546,
    SP_LDSBrr	= 547,
    SP_LDSHAri	= 548,
    SP_LDSHArr	= 549,
    SP_LDSHri	= 550,
    SP_LDSHrr	= 551,
    SP_LDSTUBAri	= 552,
    SP_LDSTUBArr	= 553,
    SP_LDSTUBri	= 554,
    SP_LDSTUBrr	= 555,
    SP_LDSWAri	= 556,
    SP_LDSWArr	= 557,
    SP_LDSWri	= 558,
    SP_LDSWrr	= 559,
    SP_LDUBAri	= 560,
    SP_LDUBArr	= 561,
    SP_LDUBri	= 562,
    SP_LDUBrr	= 563,
    SP_LDUHAri	= 564,
    SP_LDUHArr	= 565,
    SP_LDUHri	= 566,
    SP_LDUHrr	= 567,
    SP_LDXAri	= 568,
    SP_LDXArr	= 569,
    SP_LDXFSRri	= 570,
    SP_LDXFSRrr	= 571,
    SP_LDXri	= 572,
    SP_LDXrr	= 573,
    SP_LDri	= 574,
    SP_LDrr	= 575,
    SP_LZCNT	= 576,
    SP_MEMBARi	= 577,
    SP_MOVDTOX	= 578,
    SP_MOVFCCri	= 579,
    SP_MOVFCCrr	= 580,
    SP_MOVICCri	= 581,
    SP_MOVICCrr	= 582,
    SP_MOVRri	= 583,
    SP_MOVRrr	= 584,
    SP_MOVSTOSW	= 585,
    SP_MOVSTOUW	= 586,
    SP_MOVWTOS	= 587,
    SP_MOVXCCri	= 588,
    SP_MOVXCCrr	= 589,
    SP_MOVXTOD	= 590,
    SP_MULSCCri	= 591,
    SP_MULSCCrr	= 592,
    SP_MULXri	= 593,
    SP_MULXrr	= 594,
    SP_NOP	= 595,
    SP_ORCCri	= 596,
    SP_ORCCrr	= 597,
    SP_ORNCCri	= 598,
    SP_ORNCCrr	= 599,
    SP_ORNri	= 600,
    SP_ORNrr	= 601,
    SP_ORri	= 602,
    SP_ORrr	= 603,
    SP_PDIST	= 604,
    SP_PDISTN	= 605,
    SP_POPCrr	= 606,
    SP_PREFETCHi	= 607,
    SP_PREFETCHr	= 608,
    SP_PWRPSRri	= 609,
    SP_PWRPSRrr	= 610,
    SP_RDASR	= 611,
    SP_RDFQ	= 612,
    SP_RDPR	= 613,
    SP_RDPSR	= 614,
    SP_RDTBR	= 615,
    SP_RDWIM	= 616,
    SP_RESTORED	= 617,
    SP_RESTOREri	= 618,
    SP_RESTORErr	= 619,
    SP_RET	= 620,
    SP_RETL	= 621,
    SP_RETRY	= 622,
    SP_RETTri	= 623,
    SP_RETTrr	= 624,
    SP_SAVED	= 625,
    SP_SAVEri	= 626,
    SP_SAVErr	= 627,
    SP_SDIVCCri	= 628,
    SP_SDIVCCrr	= 629,
    SP_SDIVXri	= 630,
    SP_SDIVXrr	= 631,
    SP_SDIVri	= 632,
    SP_SDIVrr	= 633,
    SP_SETHIi	= 634,
    SP_SHUTDOWN	= 635,
    SP_SIAM	= 636,
    SP_SIR	= 637,
    SP_SLLXri	= 638,
    SP_SLLXrr	= 639,
    SP_SLLri	= 640,
    SP_SLLrr	= 641,
    SP_SMACri	= 642,
    SP_SMACrr	= 643,
    SP_SMULCCri	= 644,
    SP_SMULCCrr	= 645,
    SP_SMULri	= 646,
    SP_SMULrr	= 647,
    SP_SRAXri	= 648,
    SP_SRAXrr	= 649,
    SP_SRAri	= 650,
    SP_SRArr	= 651,
    SP_SRLXri	= 652,
    SP_SRLXrr	= 653,
    SP_SRLri	= 654,
    SP_SRLrr	= 655,
    SP_STAri	= 656,
    SP_STArr	= 657,
    SP_STBAR	= 658,
    SP_STBAri	= 659,
    SP_STBArr	= 660,
    SP_STBri	= 661,
    SP_STBrr	= 662,
    SP_STCSRri	= 663,
    SP_STCSRrr	= 664,
    SP_STCri	= 665,
    SP_STCrr	= 666,
    SP_STDAri	= 667,
    SP_STDArr	= 668,
    SP_STDCQri	= 669,
    SP_STDCQrr	= 670,
    SP_STDCri	= 671,
    SP_STDCrr	= 672,
    SP_STDFAri	= 673,
    SP_STDFArr	= 674,
    SP_STDFQri	= 675,
    SP_STDFQrr	= 676,
    SP_STDFri	= 677,
    SP_STDFrr	= 678,
    SP_STDri	= 679,
    SP_STDrr	= 680,
    SP_STFAri	= 681,
    SP_STFArr	= 682,
    SP_STFSRri	= 683,
    SP_STFSRrr	= 684,
    SP_STFri	= 685,
    SP_STFrr	= 686,
    SP_STHAri	= 687,
    SP_STHArr	= 688,
    SP_STHri	= 689,
    SP_STHrr	= 690,
    SP_STQFAri	= 691,
    SP_STQFArr	= 692,
    SP_STQFri	= 693,
    SP_STQFrr	= 694,
    SP_STXAri	= 695,
    SP_STXArr	= 696,
    SP_STXFSRri	= 697,
    SP_STXFSRrr	= 698,
    SP_STXri	= 699,
    SP_STXrr	= 700,
    SP_STri	= 701,
    SP_STrr	= 702,
    SP_SUBCCri	= 703,
    SP_SUBCCrr	= 704,
    SP_SUBCri	= 705,
    SP_SUBCrr	= 706,
    SP_SUBEri	= 707,
    SP_SUBErr	= 708,
    SP_SUBri	= 709,
    SP_SUBrr	= 710,
    SP_SWAPAri	= 711,
    SP_SWAPArr	= 712,
    SP_SWAPri	= 713,
    SP_SWAPrr	= 714,
    SP_TA1	= 715,
    SP_TA3	= 716,
    SP_TA5	= 717,
    SP_TADDCCTVri	= 718,
    SP_TADDCCTVrr	= 719,
    SP_TADDCCri	= 720,
    SP_TADDCCrr	= 721,
    SP_TAIL_CALL	= 722,
    SP_TAIL_CALLri	= 723,
    SP_TICCri	= 724,
    SP_TICCrr	= 725,
    SP_TLS_ADDrr	= 726,
    SP_TLS_CALL	= 727,
    SP_TLS_LDXrr	= 728,
    SP_TLS_LDrr	= 729,
    SP_TRAPri	= 730,
    SP_TRAPrr	= 731,
    SP_TSUBCCTVri	= 732,
    SP_TSUBCCTVrr	= 733,
    SP_TSUBCCri	= 734,
    SP_TSUBCCrr	= 735,
    SP_TXCCri	= 736,
    SP_TXCCrr	= 737,
    SP_UDIVCCri	= 738,
    SP_UDIVCCrr	= 739,
    SP_UDIVXri	= 740,
    SP_UDIVXrr	= 741,
    SP_UDIVri	= 742,
    SP_UDIVrr	= 743,
    SP_UMACri	= 744,
    SP_UMACrr	= 745,
    SP_UMULCCri	= 746,
    SP_UMULCCrr	= 747,
    SP_UMULXHI	= 748,
    SP_UMULri	= 749,
    SP_UMULrr	= 750,
    SP_UNIMP	= 751,
    SP_V9FCMPD	= 752,
    SP_V9FCMPED	= 753,
    SP_V9FCMPEQ	= 754,
    SP_V9FCMPES	= 755,
    SP_V9FCMPQ	= 756,
    SP_V9FCMPS	= 757,
    SP_V9FMOVD_FCC	= 758,
    SP_V9FMOVQ_FCC	= 759,
    SP_V9FMOVS_FCC	= 760,
    SP_V9MOVFCCri	= 761,
    SP_V9MOVFCCrr	= 762,
    SP_WRASRri	= 763,
    SP_WRASRrr	= 764,
    SP_WRPRri	= 765,
    SP_WRPRrr	= 766,
    SP_WRPSRri	= 767,
    SP_WRPSRrr	= 768,
    SP_WRTBRri	= 769,
    SP_WRTBRrr	= 770,
    SP_WRWIMri	= 771,
    SP_WRWIMrr	= 772,
    SP_XMULX	= 773,
    SP_XMULXHI	= 774,
    SP_XNORCCri	= 775,
    SP_XNORCCrr	= 776,
    SP_XNORri	= 777,
    SP_XNORrr	= 778,
    SP_XORCCri	= 779,
    SP_XORCCrr	= 780,
    SP_XORri	= 781,
    SP_XORrr	= 782,
    INSTRUCTION_LIST_END = 783
  };

#endif // GET_INSTRINFO_ENUM

#if defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)
typedef struct SparcInstrTable {
  MCInstrDesc Insts[783];
  MCOperandInfo OperandInfo[528];
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
  { 2, &SparcDescs.OperandInfo[363] },  // Inst #772 = WRWIMrr
  { 2, &SparcDescs.OperandInfo[156] },  // Inst #771 = WRWIMri
  { 2, &SparcDescs.OperandInfo[363] },  // Inst #770 = WRTBRrr
  { 2, &SparcDescs.OperandInfo[156] },  // Inst #769 = WRTBRri
  { 2, &SparcDescs.OperandInfo[363] },  // Inst #768 = WRPSRrr
  { 2, &SparcDescs.OperandInfo[156] },  // Inst #767 = WRPSRri
  { 3, &SparcDescs.OperandInfo[525] },  // Inst #766 = WRPRrr
  { 3, &SparcDescs.OperandInfo[522] },  // Inst #765 = WRPRri
  { 3, &SparcDescs.OperandInfo[519] },  // Inst #764 = WRASRrr
  { 3, &SparcDescs.OperandInfo[516] },  // Inst #763 = WRASRri
  { 5, &SparcDescs.OperandInfo[511] },  // Inst #762 = V9MOVFCCrr
  { 5, &SparcDescs.OperandInfo[506] },  // Inst #761 = V9MOVFCCri
  { 5, &SparcDescs.OperandInfo[501] },  // Inst #760 = V9FMOVS_FCC
  { 5, &SparcDescs.OperandInfo[496] },  // Inst #759 = V9FMOVQ_FCC
  { 5, &SparcDescs.OperandInfo[491] },  // Inst #758 = V9FMOVD_FCC
  { 3, &SparcDescs.OperandInfo[488] },  // Inst #757 = V9FCMPS
  { 3, &SparcDescs.OperandInfo[485] },  // Inst #756 = V9FCMPQ
  { 3, &SparcDescs.OperandInfo[488] },  // Inst #755 = V9FCMPES
  { 3, &SparcDescs.OperandInfo[485] },  // Inst #754 = V9FCMPEQ
  { 3, &SparcDescs.OperandInfo[226] },  // Inst #753 = V9FCMPED
  { 3, &SparcDescs.OperandInfo[226] },  // Inst #752 = V9FCMPD
  { 1, &SparcDescs.OperandInfo[1] },  // Inst #751 = UNIMP
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #750 = UMULrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #749 = UMULri
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #748 = UMULXHI
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #747 = UMULCCrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #746 = UMULCCri
  { 4, &SparcDescs.OperandInfo[389] },  // Inst #745 = UMACrr
  { 4, &SparcDescs.OperandInfo[385] },  // Inst #744 = UMACri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #743 = UDIVrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #742 = UDIVri
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #741 = UDIVXrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #740 = UDIVXri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #739 = UDIVCCrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #738 = UDIVCCri
  { 3, &SparcDescs.OperandInfo[382] },  // Inst #737 = TXCCrr
  { 3, &SparcDescs.OperandInfo[478] },  // Inst #736 = TXCCri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #735 = TSUBCCrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #734 = TSUBCCri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #733 = TSUBCCTVrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #732 = TSUBCCTVri
  { 3, &SparcDescs.OperandInfo[382] },  // Inst #731 = TRAPrr
  { 3, &SparcDescs.OperandInfo[478] },  // Inst #730 = TRAPri
  { 4, &SparcDescs.OperandInfo[271] },  // Inst #729 = TLS_LDrr
  { 4, &SparcDescs.OperandInfo[271] },  // Inst #728 = TLS_LDXrr
  { 2, &SparcDescs.OperandInfo[13] },  // Inst #727 = TLS_CALL
  { 4, &SparcDescs.OperandInfo[481] },  // Inst #726 = TLS_ADDrr
  { 3, &SparcDescs.OperandInfo[382] },  // Inst #725 = TICCrr
  { 3, &SparcDescs.OperandInfo[478] },  // Inst #724 = TICCri
  { 2, &SparcDescs.OperandInfo[35] },  // Inst #723 = TAIL_CALLri
  { 1, &SparcDescs.OperandInfo[0] },  // Inst #722 = TAIL_CALL
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #721 = TADDCCrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #720 = TADDCCri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #719 = TADDCCTVrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #718 = TADDCCTVri
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #717 = TA5
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #716 = TA3
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #715 = TA1
  { 4, &SparcDescs.OperandInfo[474] },  // Inst #714 = SWAPrr
  { 4, &SparcDescs.OperandInfo[465] },  // Inst #713 = SWAPri
  { 5, &SparcDescs.OperandInfo[469] },  // Inst #712 = SWAPArr
  { 4, &SparcDescs.OperandInfo[465] },  // Inst #711 = SWAPAri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #710 = SUBrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #709 = SUBri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #708 = SUBErr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #707 = SUBEri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #706 = SUBCrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #705 = SUBCri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #704 = SUBCCrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #703 = SUBCCri
  { 3, &SparcDescs.OperandInfo[400] },  // Inst #702 = STrr
  { 3, &SparcDescs.OperandInfo[393] },  // Inst #701 = STri
  { 3, &SparcDescs.OperandInfo[462] },  // Inst #700 = STXrr
  { 3, &SparcDescs.OperandInfo[455] },  // Inst #699 = STXri
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #698 = STXFSRrr
  { 2, &SparcDescs.OperandInfo[35] },  // Inst #697 = STXFSRri
  { 4, &SparcDescs.OperandInfo[458] },  // Inst #696 = STXArr
  { 3, &SparcDescs.OperandInfo[455] },  // Inst #695 = STXAri
  { 3, &SparcDescs.OperandInfo[452] },  // Inst #694 = STQFrr
  { 3, &SparcDescs.OperandInfo[445] },  // Inst #693 = STQFri
  { 4, &SparcDescs.OperandInfo[448] },  // Inst #692 = STQFArr
  { 3, &SparcDescs.OperandInfo[445] },  // Inst #691 = STQFAri
  { 3, &SparcDescs.OperandInfo[400] },  // Inst #690 = STHrr
  { 3, &SparcDescs.OperandInfo[393] },  // Inst #689 = STHri
  { 4, &SparcDescs.OperandInfo[396] },  // Inst #688 = STHArr
  { 3, &SparcDescs.OperandInfo[393] },  // Inst #687 = STHAri
  { 3, &SparcDescs.OperandInfo[442] },  // Inst #686 = STFrr
  { 3, &SparcDescs.OperandInfo[435] },  // Inst #685 = STFri
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #684 = STFSRrr
  { 2, &SparcDescs.OperandInfo[35] },  // Inst #683 = STFSRri
  { 4, &SparcDescs.OperandInfo[438] },  // Inst #682 = STFArr
  { 3, &SparcDescs.OperandInfo[435] },  // Inst #681 = STFAri
  { 3, &SparcDescs.OperandInfo[432] },  // Inst #680 = STDrr
  { 3, &SparcDescs.OperandInfo[409] },  // Inst #679 = STDri
  { 3, &SparcDescs.OperandInfo[429] },  // Inst #678 = STDFrr
  { 3, &SparcDescs.OperandInfo[422] },  // Inst #677 = STDFri
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #676 = STDFQrr
  { 2, &SparcDescs.OperandInfo[35] },  // Inst #675 = STDFQri
  { 4, &SparcDescs.OperandInfo[425] },  // Inst #674 = STDFArr
  { 3, &SparcDescs.OperandInfo[422] },  // Inst #673 = STDFAri
  { 3, &SparcDescs.OperandInfo[419] },  // Inst #672 = STDCrr
  { 3, &SparcDescs.OperandInfo[416] },  // Inst #671 = STDCri
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #670 = STDCQrr
  { 2, &SparcDescs.OperandInfo[35] },  // Inst #669 = STDCQri
  { 4, &SparcDescs.OperandInfo[412] },  // Inst #668 = STDArr
  { 3, &SparcDescs.OperandInfo[409] },  // Inst #667 = STDAri
  { 3, &SparcDescs.OperandInfo[406] },  // Inst #666 = STCrr
  { 3, &SparcDescs.OperandInfo[403] },  // Inst #665 = STCri
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #664 = STCSRrr
  { 2, &SparcDescs.OperandInfo[35] },  // Inst #663 = STCSRri
  { 3, &SparcDescs.OperandInfo[400] },  // Inst #662 = STBrr
  { 3, &SparcDescs.OperandInfo[393] },  // Inst #661 = STBri
  { 4, &SparcDescs.OperandInfo[396] },  // Inst #660 = STBArr
  { 3, &SparcDescs.OperandInfo[393] },  // Inst #659 = STBAri
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #658 = STBAR
  { 4, &SparcDescs.OperandInfo[396] },  // Inst #657 = STArr
  { 3, &SparcDescs.OperandInfo[393] },  // Inst #656 = STAri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #655 = SRLrr
  { 3, &SparcDescs.OperandInfo[382] },  // Inst #654 = SRLri
  { 3, &SparcDescs.OperandInfo[379] },  // Inst #653 = SRLXrr
  { 3, &SparcDescs.OperandInfo[376] },  // Inst #652 = SRLXri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #651 = SRArr
  { 3, &SparcDescs.OperandInfo[382] },  // Inst #650 = SRAri
  { 3, &SparcDescs.OperandInfo[379] },  // Inst #649 = SRAXrr
  { 3, &SparcDescs.OperandInfo[376] },  // Inst #648 = SRAXri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #647 = SMULrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #646 = SMULri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #645 = SMULCCrr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #644 = SMULCCri
  { 4, &SparcDescs.OperandInfo[389] },  // Inst #643 = SMACrr
  { 4, &SparcDescs.OperandInfo[385] },  // Inst #642 = SMACri
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #641 = SLLrr
  { 3, &SparcDescs.OperandInfo[382] },  // Inst #640 = SLLri
  { 3, &SparcDescs.OperandInfo[379] },  // Inst #639 = SLLXrr
  { 3, &SparcDescs.OperandInfo[376] },  // Inst #638 = SLLXri
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
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #624 = RETTrr
  { 2, &SparcDescs.OperandInfo[35] },  // Inst #623 = RETTri
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #622 = RETRY
  { 1, &SparcDescs.OperandInfo[1] },  // Inst #621 = RETL
  { 1, &SparcDescs.OperandInfo[1] },  // Inst #620 = RET
  { 3, &SparcDescs.OperandInfo[164] },  // Inst #619 = RESTORErr
  { 3, &SparcDescs.OperandInfo[161] },  // Inst #618 = RESTOREri
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #617 = RESTORED
  { 1, &SparcDescs.OperandInfo[373] },  // Inst #616 = RDWIM
  { 1, &SparcDescs.OperandInfo[373] },  // Inst #615 = RDTBR
  { 1, &SparcDescs.OperandInfo[373] },  // Inst #614 = RDPSR
  { 2, &SparcDescs.OperandInfo[374] },  // Inst #613 = RDPR
  { 1, &SparcDescs.OperandInfo[373] },  // Inst #612 = RDFQ
  { 2, &SparcDescs.OperandInfo[371] },  // Inst #611 = RDASR
  { 2, &SparcDescs.OperandInfo[363] },  // Inst #610 = PWRPSRrr
  { 2, &SparcDescs.OperandInfo[156] },  // Inst #609 = PWRPSRri
  { 3, &SparcDescs.OperandInfo[368] },  // Inst #608 = PREFETCHr
  { 3, &SparcDescs.OperandInfo[365] },  // Inst #607 = PREFETCHi
  { 2, &SparcDescs.OperandInfo[363] },  // Inst #606 = POPCrr
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #605 = PDISTN
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #604 = PDIST
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
  { 2, &SparcDescs.OperandInfo[361] },  // Inst #590 = MOVXTOD
  { 4, &SparcDescs.OperandInfo[347] },  // Inst #589 = MOVXCCrr
  { 4, &SparcDescs.OperandInfo[343] },  // Inst #588 = MOVXCCri
  { 2, &SparcDescs.OperandInfo[361] },  // Inst #587 = MOVWTOS
  { 2, &SparcDescs.OperandInfo[341] },  // Inst #586 = MOVSTOUW
  { 2, &SparcDescs.OperandInfo[341] },  // Inst #585 = MOVSTOSW
  { 5, &SparcDescs.OperandInfo[356] },  // Inst #584 = MOVRrr
  { 5, &SparcDescs.OperandInfo[351] },  // Inst #583 = MOVRri
  { 4, &SparcDescs.OperandInfo[347] },  // Inst #582 = MOVICCrr
  { 4, &SparcDescs.OperandInfo[343] },  // Inst #581 = MOVICCri
  { 4, &SparcDescs.OperandInfo[347] },  // Inst #580 = MOVFCCrr
  { 4, &SparcDescs.OperandInfo[343] },  // Inst #579 = MOVFCCri
  { 2, &SparcDescs.OperandInfo[341] },  // Inst #578 = MOVDTOX
  { 1, &SparcDescs.OperandInfo[0] },  // Inst #577 = MEMBARi
  { 2, &SparcDescs.OperandInfo[339] },  // Inst #576 = LZCNT
  { 3, &SparcDescs.OperandInfo[278] },  // Inst #575 = LDrr
  { 3, &SparcDescs.OperandInfo[275] },  // Inst #574 = LDri
  { 3, &SparcDescs.OperandInfo[336] },  // Inst #573 = LDXrr
  { 3, &SparcDescs.OperandInfo[333] },  // Inst #572 = LDXri
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #571 = LDXFSRrr
  { 2, &SparcDescs.OperandInfo[35] },  // Inst #570 = LDXFSRri
  { 4, &SparcDescs.OperandInfo[267] },  // Inst #569 = LDXArr
  { 3, &SparcDescs.OperandInfo[333] },  // Inst #568 = LDXAri
  { 3, &SparcDescs.OperandInfo[278] },  // Inst #567 = LDUHrr
  { 3, &SparcDescs.OperandInfo[275] },  // Inst #566 = LDUHri
  { 4, &SparcDescs.OperandInfo[271] },  // Inst #565 = LDUHArr
  { 3, &SparcDescs.OperandInfo[275] },  // Inst #564 = LDUHAri
  { 3, &SparcDescs.OperandInfo[278] },  // Inst #563 = LDUBrr
  { 3, &SparcDescs.OperandInfo[275] },  // Inst #562 = LDUBri
  { 4, &SparcDescs.OperandInfo[271] },  // Inst #561 = LDUBArr
  { 3, &SparcDescs.OperandInfo[275] },  // Inst #560 = LDUBAri
  { 3, &SparcDescs.OperandInfo[336] },  // Inst #559 = LDSWrr
  { 3, &SparcDescs.OperandInfo[333] },  // Inst #558 = LDSWri
  { 4, &SparcDescs.OperandInfo[267] },  // Inst #557 = LDSWArr
  { 3, &SparcDescs.OperandInfo[333] },  // Inst #556 = LDSWAri
  { 3, &SparcDescs.OperandInfo[278] },  // Inst #555 = LDSTUBrr
  { 3, &SparcDescs.OperandInfo[275] },  // Inst #554 = LDSTUBri
  { 4, &SparcDescs.OperandInfo[271] },  // Inst #553 = LDSTUBArr
  { 3, &SparcDescs.OperandInfo[275] },  // Inst #552 = LDSTUBAri
  { 3, &SparcDescs.OperandInfo[278] },  // Inst #551 = LDSHrr
  { 3, &SparcDescs.OperandInfo[275] },  // Inst #550 = LDSHri
  { 4, &SparcDescs.OperandInfo[271] },  // Inst #549 = LDSHArr
  { 3, &SparcDescs.OperandInfo[275] },  // Inst #548 = LDSHAri
  { 3, &SparcDescs.OperandInfo[278] },  // Inst #547 = LDSBrr
  { 3, &SparcDescs.OperandInfo[275] },  // Inst #546 = LDSBri
  { 4, &SparcDescs.OperandInfo[271] },  // Inst #545 = LDSBArr
  { 3, &SparcDescs.OperandInfo[275] },  // Inst #544 = LDSBAri
  { 3, &SparcDescs.OperandInfo[330] },  // Inst #543 = LDQFrr
  { 3, &SparcDescs.OperandInfo[323] },  // Inst #542 = LDQFri
  { 4, &SparcDescs.OperandInfo[326] },  // Inst #541 = LDQFArr
  { 3, &SparcDescs.OperandInfo[323] },  // Inst #540 = LDQFAri
  { 3, &SparcDescs.OperandInfo[320] },  // Inst #539 = LDFrr
  { 3, &SparcDescs.OperandInfo[313] },  // Inst #538 = LDFri
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #537 = LDFSRrr
  { 2, &SparcDescs.OperandInfo[35] },  // Inst #536 = LDFSRri
  { 4, &SparcDescs.OperandInfo[316] },  // Inst #535 = LDFArr
  { 3, &SparcDescs.OperandInfo[313] },  // Inst #534 = LDFAri
  { 3, &SparcDescs.OperandInfo[310] },  // Inst #533 = LDDrr
  { 3, &SparcDescs.OperandInfo[287] },  // Inst #532 = LDDri
  { 3, &SparcDescs.OperandInfo[307] },  // Inst #531 = LDDFrr
  { 3, &SparcDescs.OperandInfo[300] },  // Inst #530 = LDDFri
  { 4, &SparcDescs.OperandInfo[303] },  // Inst #529 = LDDFArr
  { 3, &SparcDescs.OperandInfo[300] },  // Inst #528 = LDDFAri
  { 3, &SparcDescs.OperandInfo[297] },  // Inst #527 = LDDCrr
  { 3, &SparcDescs.OperandInfo[294] },  // Inst #526 = LDDCri
  { 4, &SparcDescs.OperandInfo[290] },  // Inst #525 = LDDArr
  { 3, &SparcDescs.OperandInfo[287] },  // Inst #524 = LDDAri
  { 3, &SparcDescs.OperandInfo[284] },  // Inst #523 = LDCrr
  { 3, &SparcDescs.OperandInfo[281] },  // Inst #522 = LDCri
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #521 = LDCSRrr
  { 2, &SparcDescs.OperandInfo[35] },  // Inst #520 = LDCSRri
  { 4, &SparcDescs.OperandInfo[271] },  // Inst #519 = LDArr
  { 3, &SparcDescs.OperandInfo[275] },  // Inst #518 = LDAri
  { 3, &SparcDescs.OperandInfo[278] },  // Inst #517 = JMPLrr
  { 3, &SparcDescs.OperandInfo[275] },  // Inst #516 = JMPLri
  { 4, &SparcDescs.OperandInfo[271] },  // Inst #515 = GDOP_LDrr
  { 4, &SparcDescs.OperandInfo[267] },  // Inst #514 = GDOP_LDXrr
  { 2, &SparcDescs.OperandInfo[258] },  // Inst #513 = FZEROS
  { 2, &SparcDescs.OperandInfo[256] },  // Inst #512 = FZERO
  { 2, &SparcDescs.OperandInfo[218] },  // Inst #511 = FXTOS
  { 2, &SparcDescs.OperandInfo[220] },  // Inst #510 = FXTOQ
  { 2, &SparcDescs.OperandInfo[200] },  // Inst #509 = FXTOD
  { 3, &SparcDescs.OperandInfo[209] },  // Inst #508 = FXORS
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #507 = FXOR
  { 3, &SparcDescs.OperandInfo[209] },  // Inst #506 = FXNORS
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #505 = FXNOR
  { 3, &SparcDescs.OperandInfo[209] },  // Inst #504 = FSUBS
  { 3, &SparcDescs.OperandInfo[206] },  // Inst #503 = FSUBQ
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #502 = FSUBD
  { 2, &SparcDescs.OperandInfo[222] },  // Inst #501 = FSTOX
  { 2, &SparcDescs.OperandInfo[224] },  // Inst #500 = FSTOQ
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #499 = FSTOI
  { 2, &SparcDescs.OperandInfo[222] },  // Inst #498 = FSTOD
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #497 = FSRL32
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #496 = FSRL16
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #495 = FSRC2S
  { 2, &SparcDescs.OperandInfo[200] },  // Inst #494 = FSRC2
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #493 = FSRC1S
  { 2, &SparcDescs.OperandInfo[200] },  // Inst #492 = FSRC1
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #491 = FSRA32
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #490 = FSRA16
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #489 = FSQRTS
  { 2, &SparcDescs.OperandInfo[202] },  // Inst #488 = FSQRTQ
  { 2, &SparcDescs.OperandInfo[200] },  // Inst #487 = FSQRTD
  { 3, &SparcDescs.OperandInfo[264] },  // Inst #486 = FSMULD
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #485 = FSLL32
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #484 = FSLL16
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #483 = FSLAS32
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #482 = FSLAS16
  { 2, &SparcDescs.OperandInfo[260] },  // Inst #481 = FQTOX
  { 2, &SparcDescs.OperandInfo[262] },  // Inst #480 = FQTOS
  { 2, &SparcDescs.OperandInfo[262] },  // Inst #479 = FQTOI
  { 2, &SparcDescs.OperandInfo[260] },  // Inst #478 = FQTOD
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #477 = FPSUB32S
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #476 = FPSUB32
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #475 = FPSUB16S
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #474 = FPSUB16
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #473 = FPMERGE
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #472 = FPADD64
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #471 = FPADD32S
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #470 = FPADD32
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #469 = FPADD16S
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #468 = FPADD16
  { 2, &SparcDescs.OperandInfo[200] },  // Inst #467 = FPACKFIX
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #466 = FPACK32
  { 2, &SparcDescs.OperandInfo[200] },  // Inst #465 = FPACK16
  { 3, &SparcDescs.OperandInfo[209] },  // Inst #464 = FORS
  { 3, &SparcDescs.OperandInfo[209] },  // Inst #463 = FORNOT2S
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #462 = FORNOT2
  { 3, &SparcDescs.OperandInfo[209] },  // Inst #461 = FORNOT1S
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #460 = FORNOT1
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #459 = FOR
  { 2, &SparcDescs.OperandInfo[258] },  // Inst #458 = FONES
  { 2, &SparcDescs.OperandInfo[256] },  // Inst #457 = FONE
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #456 = FNSMULD
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #455 = FNOT2S
  { 2, &SparcDescs.OperandInfo[200] },  // Inst #454 = FNOT2
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #453 = FNOT1S
  { 2, &SparcDescs.OperandInfo[200] },  // Inst #452 = FNOT1
  { 3, &SparcDescs.OperandInfo[209] },  // Inst #451 = FNORS
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #450 = FNOR
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #449 = FNMULS
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #448 = FNMULD
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #447 = FNHADDS
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #446 = FNHADDD
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #445 = FNEGS
  { 2, &SparcDescs.OperandInfo[202] },  // Inst #444 = FNEGQ
  { 2, &SparcDescs.OperandInfo[200] },  // Inst #443 = FNEGD
  { 3, &SparcDescs.OperandInfo[209] },  // Inst #442 = FNANDS
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #441 = FNAND
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #440 = FNADDS
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #439 = FNADDD
  { 3, &SparcDescs.OperandInfo[209] },  // Inst #438 = FMULS
  { 3, &SparcDescs.OperandInfo[206] },  // Inst #437 = FMULQ
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #436 = FMULD8ULX16
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #435 = FMULD8SUX16
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #434 = FMULD
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #433 = FMUL8X16AU
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #432 = FMUL8X16AL
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #431 = FMUL8X16
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #430 = FMUL8ULX16
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #429 = FMUL8SUX16
  { 4, &SparcDescs.OperandInfo[252] },  // Inst #428 = FMOVS_XCC
  { 4, &SparcDescs.OperandInfo[252] },  // Inst #427 = FMOVS_ICC
  { 4, &SparcDescs.OperandInfo[252] },  // Inst #426 = FMOVS_FCC
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #425 = FMOVS
  { 5, &SparcDescs.OperandInfo[247] },  // Inst #424 = FMOVRS
  { 5, &SparcDescs.OperandInfo[242] },  // Inst #423 = FMOVRQ
  { 5, &SparcDescs.OperandInfo[237] },  // Inst #422 = FMOVRD
  { 4, &SparcDescs.OperandInfo[233] },  // Inst #421 = FMOVQ_XCC
  { 4, &SparcDescs.OperandInfo[233] },  // Inst #420 = FMOVQ_ICC
  { 4, &SparcDescs.OperandInfo[233] },  // Inst #419 = FMOVQ_FCC
  { 2, &SparcDescs.OperandInfo[202] },  // Inst #418 = FMOVQ
  { 4, &SparcDescs.OperandInfo[229] },  // Inst #417 = FMOVD_XCC
  { 4, &SparcDescs.OperandInfo[229] },  // Inst #416 = FMOVD_ICC
  { 4, &SparcDescs.OperandInfo[229] },  // Inst #415 = FMOVD_FCC
  { 2, &SparcDescs.OperandInfo[200] },  // Inst #414 = FMOVD
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #413 = FMEAN16
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #412 = FLUSHrr
  { 2, &SparcDescs.OperandInfo[35] },  // Inst #411 = FLUSHri
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #410 = FLUSHW
  { 0, &SparcDescs.OperandInfo[1] },  // Inst #409 = FLUSH
  { 3, &SparcDescs.OperandInfo[226] },  // Inst #408 = FLCMPS
  { 3, &SparcDescs.OperandInfo[226] },  // Inst #407 = FLCMPD
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #406 = FITOS
  { 2, &SparcDescs.OperandInfo[224] },  // Inst #405 = FITOQ
  { 2, &SparcDescs.OperandInfo[222] },  // Inst #404 = FITOD
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #403 = FHSUBS
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #402 = FHSUBD
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #401 = FHADDS
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #400 = FHADDD
  { 2, &SparcDescs.OperandInfo[200] },  // Inst #399 = FEXPAND
  { 2, &SparcDescs.OperandInfo[200] },  // Inst #398 = FDTOX
  { 2, &SparcDescs.OperandInfo[218] },  // Inst #397 = FDTOS
  { 2, &SparcDescs.OperandInfo[220] },  // Inst #396 = FDTOQ
  { 2, &SparcDescs.OperandInfo[218] },  // Inst #395 = FDTOI
  { 3, &SparcDescs.OperandInfo[215] },  // Inst #394 = FDMULQ
  { 3, &SparcDescs.OperandInfo[209] },  // Inst #393 = FDIVS
  { 3, &SparcDescs.OperandInfo[206] },  // Inst #392 = FDIVQ
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #391 = FDIVD
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #390 = FCMPS_V9
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #389 = FCMPS
  { 2, &SparcDescs.OperandInfo[202] },  // Inst #388 = FCMPQ_V9
  { 2, &SparcDescs.OperandInfo[202] },  // Inst #387 = FCMPQ
  { 3, &SparcDescs.OperandInfo[212] },  // Inst #386 = FCMPNE32
  { 3, &SparcDescs.OperandInfo[212] },  // Inst #385 = FCMPNE16
  { 3, &SparcDescs.OperandInfo[212] },  // Inst #384 = FCMPLE32
  { 3, &SparcDescs.OperandInfo[212] },  // Inst #383 = FCMPLE16
  { 3, &SparcDescs.OperandInfo[212] },  // Inst #382 = FCMPGT32
  { 3, &SparcDescs.OperandInfo[212] },  // Inst #381 = FCMPGT16
  { 3, &SparcDescs.OperandInfo[212] },  // Inst #380 = FCMPEQ32
  { 3, &SparcDescs.OperandInfo[212] },  // Inst #379 = FCMPEQ16
  { 2, &SparcDescs.OperandInfo[200] },  // Inst #378 = FCMPD_V9
  { 2, &SparcDescs.OperandInfo[200] },  // Inst #377 = FCMPD
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #376 = FCHKSM16
  { 2, &SparcDescs.OperandInfo[13] },  // Inst #375 = FBCOND_V9
  { 2, &SparcDescs.OperandInfo[13] },  // Inst #374 = FBCONDA_V9
  { 2, &SparcDescs.OperandInfo[13] },  // Inst #373 = FBCONDA
  { 2, &SparcDescs.OperandInfo[13] },  // Inst #372 = FBCOND
  { 3, &SparcDescs.OperandInfo[209] },  // Inst #371 = FANDS
  { 3, &SparcDescs.OperandInfo[209] },  // Inst #370 = FANDNOT2S
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #369 = FANDNOT2
  { 3, &SparcDescs.OperandInfo[209] },  // Inst #368 = FANDNOT1S
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #367 = FANDNOT1
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #366 = FAND
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #365 = FALIGNADATA
  { 3, &SparcDescs.OperandInfo[209] },  // Inst #364 = FADDS
  { 3, &SparcDescs.OperandInfo[206] },  // Inst #363 = FADDQ
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #362 = FADDD
  { 2, &SparcDescs.OperandInfo[204] },  // Inst #361 = FABSS
  { 2, &SparcDescs.OperandInfo[202] },  // Inst #360 = FABSQ
  { 2, &SparcDescs.OperandInfo[200] },  // Inst #359 = FABSD
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
  { 1, &SparcDescs.OperandInfo[199] },  // Inst #345 = CMASK8
  { 1, &SparcDescs.OperandInfo[199] },  // Inst #344 = CMASK32
  { 1, &SparcDescs.OperandInfo[199] },  // Inst #343 = CMASK16
  { 2, &SparcDescs.OperandInfo[13] },  // Inst #342 = CBCONDA
  { 2, &SparcDescs.OperandInfo[13] },  // Inst #341 = CBCOND
  { 5, &SparcDescs.OperandInfo[194] },  // Inst #340 = CASXArr
  { 4, &SparcDescs.OperandInfo[190] },  // Inst #339 = CASXAri
  { 5, &SparcDescs.OperandInfo[185] },  // Inst #338 = CASArr
  { 4, &SparcDescs.OperandInfo[181] },  // Inst #337 = CASAri
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #336 = CALLrr
  { 2, &SparcDescs.OperandInfo[35] },  // Inst #335 = CALLri
  { 1, &SparcDescs.OperandInfo[0] },  // Inst #334 = CALL
  { 3, &SparcDescs.OperandInfo[178] },  // Inst #333 = BSHUFFLE
  { 2, &SparcDescs.OperandInfo[13] },  // Inst #332 = BPXCCNT
  { 2, &SparcDescs.OperandInfo[13] },  // Inst #331 = BPXCCANT
  { 2, &SparcDescs.OperandInfo[13] },  // Inst #330 = BPXCCA
  { 2, &SparcDescs.OperandInfo[13] },  // Inst #329 = BPXCC
  { 3, &SparcDescs.OperandInfo[175] },  // Inst #328 = BPRNT
  { 3, &SparcDescs.OperandInfo[175] },  // Inst #327 = BPRANT
  { 3, &SparcDescs.OperandInfo[175] },  // Inst #326 = BPRA
  { 3, &SparcDescs.OperandInfo[175] },  // Inst #325 = BPR
  { 2, &SparcDescs.OperandInfo[13] },  // Inst #324 = BPICCNT
  { 2, &SparcDescs.OperandInfo[13] },  // Inst #323 = BPICCANT
  { 2, &SparcDescs.OperandInfo[13] },  // Inst #322 = BPICCA
  { 2, &SparcDescs.OperandInfo[13] },  // Inst #321 = BPICC
  { 3, &SparcDescs.OperandInfo[172] },  // Inst #320 = BPFCCNT
  { 3, &SparcDescs.OperandInfo[172] },  // Inst #319 = BPFCCANT
  { 3, &SparcDescs.OperandInfo[172] },  // Inst #318 = BPFCCA
  { 3, &SparcDescs.OperandInfo[172] },  // Inst #317 = BPFCC
  { 3, &SparcDescs.OperandInfo[167] },  // Inst #316 = BMASK
  { 2, &SparcDescs.OperandInfo[170] },  // Inst #315 = BINDrr
  { 2, &SparcDescs.OperandInfo[35] },  // Inst #314 = BINDri
  { 2, &SparcDescs.OperandInfo[13] },  // Inst #313 = BCONDA
  { 2, &SparcDescs.OperandInfo[13] },  // Inst #312 = BCOND
  { 1, &SparcDescs.OperandInfo[0] },  // Inst #311 = BA
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
    /* 170 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 },
    /* 172 */ { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 175 */ { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 178 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 181 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 185 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 190 */ { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 194 */ { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 199 */ { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 200 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 202 */ { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 204 */ { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 206 */ { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 209 */ { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 212 */ { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 215 */ { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 218 */ { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 220 */ { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 222 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 224 */ { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 226 */ { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 229 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 233 */ { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 237 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 242 */ { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 247 */ { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 252 */ { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 256 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 258 */ { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 260 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 262 */ { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 264 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 267 */ { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 271 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 275 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 278 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 },
    /* 281 */ { SP_CoprocRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 284 */ { SP_CoprocRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 },
    /* 287 */ { SP_IntPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 290 */ { SP_IntPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 294 */ { SP_CoprocPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 297 */ { SP_CoprocPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 },
    /* 300 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 303 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 307 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 },
    /* 310 */ { SP_IntPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 },
    /* 313 */ { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 316 */ { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 320 */ { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 },
    /* 323 */ { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 326 */ { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 330 */ { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 },
    /* 333 */ { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 336 */ { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 },
    /* 339 */ { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 341 */ { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 343 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 347 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 351 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 356 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 361 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 363 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 365 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 368 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 371 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_ASRRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 373 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 374 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_PRRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 376 */ { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 379 */ { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 382 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 385 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SP_ASRRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 389 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_ASRRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 393 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 396 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 400 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 403 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_CoprocRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 406 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_CoprocRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 409 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_IntPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 412 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_IntPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 416 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_CoprocPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 419 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_CoprocPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 422 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 425 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 429 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 432 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_IntPairRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 435 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 438 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 442 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 445 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 448 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 452 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 455 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 458 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 462 */ { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_I64RegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 465 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 469 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 474 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { 0, 0|(1<<MCOI_LookupPtrRegClass), MCOI_OPERAND_UNKNOWN, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 478 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 481 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 485 */ { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 488 */ { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 491 */ { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_DFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 496 */ { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_QFPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 501 */ { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FPRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 506 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 511 */ { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_FCCRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 },
    /* 516 */ { SP_ASRRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 519 */ { SP_ASRRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 522 */ { SP_PRRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 525 */ { SP_PRRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SP_IntRegsRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
  }, {
    /* 0 */
    /* 0 */ SP_O6, SP_O6,
    /* 2 */ SP_O7,
    /* 3 */ SP_FCC0,
    /* 4 */ SP_ICC,
    /* 5 */ SP_ICC, SP_ICC,
    /* 7 */ SP_O6,
    /* 8 */ SP_ASR3,
    /* 9 */ SP_CPSR,
    /* 10 */ SP_FSR,
    /* 11 */ SP_Y, SP_ICC, SP_Y, SP_ICC,
    /* 15 */ SP_PSR,
    /* 16 */ SP_FQ,
    /* 17 */ SP_TBR,
    /* 18 */ SP_WIM,
    /* 19 */ SP_Y, SP_Y, SP_ICC,
    /* 22 */ SP_Y, SP_Y,
    /* 24 */ SP_Y, SP_ASR18, SP_Y, SP_ASR18,
    /* 28 */ SP_Y, SP_ICC,
    /* 30 */ SP_Y,
    /* 31 */ SP_CPQ,
  }
};

#endif // GET_INSTRINFO_MC_DESC

#ifdef GET_COMPUTE_FEATURES
#undef GET_COMPUTE_FEATURES

#endif // GET_COMPUTE_FEATURES

#ifdef GET_AVAILABLE_OPCODE_CHECKER
#undef GET_AVAILABLE_OPCODE_CHECKER

#endif // GET_AVAILABLE_OPCODE_CHECKER


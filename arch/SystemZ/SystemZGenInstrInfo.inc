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
    SystemZ_PHI	= 0,
    SystemZ_INLINEASM	= 1,
    SystemZ_INLINEASM_BR	= 2,
    SystemZ_CFI_INSTRUCTION	= 3,
    SystemZ_EH_LABEL	= 4,
    SystemZ_GC_LABEL	= 5,
    SystemZ_ANNOTATION_LABEL	= 6,
    SystemZ_KILL	= 7,
    SystemZ_EXTRACT_SUBREG	= 8,
    SystemZ_INSERT_SUBREG	= 9,
    SystemZ_IMPLICIT_DEF	= 10,
    SystemZ_SUBREG_TO_REG	= 11,
    SystemZ_COPY_TO_REGCLASS	= 12,
    SystemZ_DBG_VALUE	= 13,
    SystemZ_DBG_VALUE_LIST	= 14,
    SystemZ_DBG_INSTR_REF	= 15,
    SystemZ_DBG_PHI	= 16,
    SystemZ_DBG_LABEL	= 17,
    SystemZ_REG_SEQUENCE	= 18,
    SystemZ_COPY	= 19,
    SystemZ_BUNDLE	= 20,
    SystemZ_LIFETIME_START	= 21,
    SystemZ_LIFETIME_END	= 22,
    SystemZ_PSEUDO_PROBE	= 23,
    SystemZ_ARITH_FENCE	= 24,
    SystemZ_STACKMAP	= 25,
    SystemZ_FENTRY_CALL	= 26,
    SystemZ_PATCHPOINT	= 27,
    SystemZ_LOAD_STACK_GUARD	= 28,
    SystemZ_PREALLOCATED_SETUP	= 29,
    SystemZ_PREALLOCATED_ARG	= 30,
    SystemZ_STATEPOINT	= 31,
    SystemZ_LOCAL_ESCAPE	= 32,
    SystemZ_FAULTING_OP	= 33,
    SystemZ_PATCHABLE_OP	= 34,
    SystemZ_PATCHABLE_FUNCTION_ENTER	= 35,
    SystemZ_PATCHABLE_RET	= 36,
    SystemZ_PATCHABLE_FUNCTION_EXIT	= 37,
    SystemZ_PATCHABLE_TAIL_CALL	= 38,
    SystemZ_PATCHABLE_EVENT_CALL	= 39,
    SystemZ_PATCHABLE_TYPED_EVENT_CALL	= 40,
    SystemZ_ICALL_BRANCH_FUNNEL	= 41,
    SystemZ_MEMBARRIER	= 42,
    SystemZ_JUMP_TABLE_DEBUG_INFO	= 43,
    SystemZ_G_ASSERT_SEXT	= 44,
    SystemZ_G_ASSERT_ZEXT	= 45,
    SystemZ_G_ASSERT_ALIGN	= 46,
    SystemZ_G_ADD	= 47,
    SystemZ_G_SUB	= 48,
    SystemZ_G_MUL	= 49,
    SystemZ_G_SDIV	= 50,
    SystemZ_G_UDIV	= 51,
    SystemZ_G_SREM	= 52,
    SystemZ_G_UREM	= 53,
    SystemZ_G_SDIVREM	= 54,
    SystemZ_G_UDIVREM	= 55,
    SystemZ_G_AND	= 56,
    SystemZ_G_OR	= 57,
    SystemZ_G_XOR	= 58,
    SystemZ_G_IMPLICIT_DEF	= 59,
    SystemZ_G_PHI	= 60,
    SystemZ_G_FRAME_INDEX	= 61,
    SystemZ_G_GLOBAL_VALUE	= 62,
    SystemZ_G_CONSTANT_POOL	= 63,
    SystemZ_G_EXTRACT	= 64,
    SystemZ_G_UNMERGE_VALUES	= 65,
    SystemZ_G_INSERT	= 66,
    SystemZ_G_MERGE_VALUES	= 67,
    SystemZ_G_BUILD_VECTOR	= 68,
    SystemZ_G_BUILD_VECTOR_TRUNC	= 69,
    SystemZ_G_CONCAT_VECTORS	= 70,
    SystemZ_G_PTRTOINT	= 71,
    SystemZ_G_INTTOPTR	= 72,
    SystemZ_G_BITCAST	= 73,
    SystemZ_G_FREEZE	= 74,
    SystemZ_G_CONSTANT_FOLD_BARRIER	= 75,
    SystemZ_G_INTRINSIC_FPTRUNC_ROUND	= 76,
    SystemZ_G_INTRINSIC_TRUNC	= 77,
    SystemZ_G_INTRINSIC_ROUND	= 78,
    SystemZ_G_INTRINSIC_LRINT	= 79,
    SystemZ_G_INTRINSIC_ROUNDEVEN	= 80,
    SystemZ_G_READCYCLECOUNTER	= 81,
    SystemZ_G_LOAD	= 82,
    SystemZ_G_SEXTLOAD	= 83,
    SystemZ_G_ZEXTLOAD	= 84,
    SystemZ_G_INDEXED_LOAD	= 85,
    SystemZ_G_INDEXED_SEXTLOAD	= 86,
    SystemZ_G_INDEXED_ZEXTLOAD	= 87,
    SystemZ_G_STORE	= 88,
    SystemZ_G_INDEXED_STORE	= 89,
    SystemZ_G_ATOMIC_CMPXCHG_WITH_SUCCESS	= 90,
    SystemZ_G_ATOMIC_CMPXCHG	= 91,
    SystemZ_G_ATOMICRMW_XCHG	= 92,
    SystemZ_G_ATOMICRMW_ADD	= 93,
    SystemZ_G_ATOMICRMW_SUB	= 94,
    SystemZ_G_ATOMICRMW_AND	= 95,
    SystemZ_G_ATOMICRMW_NAND	= 96,
    SystemZ_G_ATOMICRMW_OR	= 97,
    SystemZ_G_ATOMICRMW_XOR	= 98,
    SystemZ_G_ATOMICRMW_MAX	= 99,
    SystemZ_G_ATOMICRMW_MIN	= 100,
    SystemZ_G_ATOMICRMW_UMAX	= 101,
    SystemZ_G_ATOMICRMW_UMIN	= 102,
    SystemZ_G_ATOMICRMW_FADD	= 103,
    SystemZ_G_ATOMICRMW_FSUB	= 104,
    SystemZ_G_ATOMICRMW_FMAX	= 105,
    SystemZ_G_ATOMICRMW_FMIN	= 106,
    SystemZ_G_ATOMICRMW_UINC_WRAP	= 107,
    SystemZ_G_ATOMICRMW_UDEC_WRAP	= 108,
    SystemZ_G_FENCE	= 109,
    SystemZ_G_PREFETCH	= 110,
    SystemZ_G_BRCOND	= 111,
    SystemZ_G_BRINDIRECT	= 112,
    SystemZ_G_INVOKE_REGION_START	= 113,
    SystemZ_G_INTRINSIC	= 114,
    SystemZ_G_INTRINSIC_W_SIDE_EFFECTS	= 115,
    SystemZ_G_INTRINSIC_CONVERGENT	= 116,
    SystemZ_G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS	= 117,
    SystemZ_G_ANYEXT	= 118,
    SystemZ_G_TRUNC	= 119,
    SystemZ_G_CONSTANT	= 120,
    SystemZ_G_FCONSTANT	= 121,
    SystemZ_G_VASTART	= 122,
    SystemZ_G_VAARG	= 123,
    SystemZ_G_SEXT	= 124,
    SystemZ_G_SEXT_INREG	= 125,
    SystemZ_G_ZEXT	= 126,
    SystemZ_G_SHL	= 127,
    SystemZ_G_LSHR	= 128,
    SystemZ_G_ASHR	= 129,
    SystemZ_G_FSHL	= 130,
    SystemZ_G_FSHR	= 131,
    SystemZ_G_ROTR	= 132,
    SystemZ_G_ROTL	= 133,
    SystemZ_G_ICMP	= 134,
    SystemZ_G_FCMP	= 135,
    SystemZ_G_SELECT	= 136,
    SystemZ_G_UADDO	= 137,
    SystemZ_G_UADDE	= 138,
    SystemZ_G_USUBO	= 139,
    SystemZ_G_USUBE	= 140,
    SystemZ_G_SADDO	= 141,
    SystemZ_G_SADDE	= 142,
    SystemZ_G_SSUBO	= 143,
    SystemZ_G_SSUBE	= 144,
    SystemZ_G_UMULO	= 145,
    SystemZ_G_SMULO	= 146,
    SystemZ_G_UMULH	= 147,
    SystemZ_G_SMULH	= 148,
    SystemZ_G_UADDSAT	= 149,
    SystemZ_G_SADDSAT	= 150,
    SystemZ_G_USUBSAT	= 151,
    SystemZ_G_SSUBSAT	= 152,
    SystemZ_G_USHLSAT	= 153,
    SystemZ_G_SSHLSAT	= 154,
    SystemZ_G_SMULFIX	= 155,
    SystemZ_G_UMULFIX	= 156,
    SystemZ_G_SMULFIXSAT	= 157,
    SystemZ_G_UMULFIXSAT	= 158,
    SystemZ_G_SDIVFIX	= 159,
    SystemZ_G_UDIVFIX	= 160,
    SystemZ_G_SDIVFIXSAT	= 161,
    SystemZ_G_UDIVFIXSAT	= 162,
    SystemZ_G_FADD	= 163,
    SystemZ_G_FSUB	= 164,
    SystemZ_G_FMUL	= 165,
    SystemZ_G_FMA	= 166,
    SystemZ_G_FMAD	= 167,
    SystemZ_G_FDIV	= 168,
    SystemZ_G_FREM	= 169,
    SystemZ_G_FPOW	= 170,
    SystemZ_G_FPOWI	= 171,
    SystemZ_G_FEXP	= 172,
    SystemZ_G_FEXP2	= 173,
    SystemZ_G_FEXP10	= 174,
    SystemZ_G_FLOG	= 175,
    SystemZ_G_FLOG2	= 176,
    SystemZ_G_FLOG10	= 177,
    SystemZ_G_FLDEXP	= 178,
    SystemZ_G_FFREXP	= 179,
    SystemZ_G_FNEG	= 180,
    SystemZ_G_FPEXT	= 181,
    SystemZ_G_FPTRUNC	= 182,
    SystemZ_G_FPTOSI	= 183,
    SystemZ_G_FPTOUI	= 184,
    SystemZ_G_SITOFP	= 185,
    SystemZ_G_UITOFP	= 186,
    SystemZ_G_FABS	= 187,
    SystemZ_G_FCOPYSIGN	= 188,
    SystemZ_G_IS_FPCLASS	= 189,
    SystemZ_G_FCANONICALIZE	= 190,
    SystemZ_G_FMINNUM	= 191,
    SystemZ_G_FMAXNUM	= 192,
    SystemZ_G_FMINNUM_IEEE	= 193,
    SystemZ_G_FMAXNUM_IEEE	= 194,
    SystemZ_G_FMINIMUM	= 195,
    SystemZ_G_FMAXIMUM	= 196,
    SystemZ_G_GET_FPENV	= 197,
    SystemZ_G_SET_FPENV	= 198,
    SystemZ_G_RESET_FPENV	= 199,
    SystemZ_G_GET_FPMODE	= 200,
    SystemZ_G_SET_FPMODE	= 201,
    SystemZ_G_RESET_FPMODE	= 202,
    SystemZ_G_PTR_ADD	= 203,
    SystemZ_G_PTRMASK	= 204,
    SystemZ_G_SMIN	= 205,
    SystemZ_G_SMAX	= 206,
    SystemZ_G_UMIN	= 207,
    SystemZ_G_UMAX	= 208,
    SystemZ_G_ABS	= 209,
    SystemZ_G_LROUND	= 210,
    SystemZ_G_LLROUND	= 211,
    SystemZ_G_BR	= 212,
    SystemZ_G_BRJT	= 213,
    SystemZ_G_INSERT_VECTOR_ELT	= 214,
    SystemZ_G_EXTRACT_VECTOR_ELT	= 215,
    SystemZ_G_SHUFFLE_VECTOR	= 216,
    SystemZ_G_CTTZ	= 217,
    SystemZ_G_CTTZ_ZERO_UNDEF	= 218,
    SystemZ_G_CTLZ	= 219,
    SystemZ_G_CTLZ_ZERO_UNDEF	= 220,
    SystemZ_G_CTPOP	= 221,
    SystemZ_G_BSWAP	= 222,
    SystemZ_G_BITREVERSE	= 223,
    SystemZ_G_FCEIL	= 224,
    SystemZ_G_FCOS	= 225,
    SystemZ_G_FSIN	= 226,
    SystemZ_G_FSQRT	= 227,
    SystemZ_G_FFLOOR	= 228,
    SystemZ_G_FRINT	= 229,
    SystemZ_G_FNEARBYINT	= 230,
    SystemZ_G_ADDRSPACE_CAST	= 231,
    SystemZ_G_BLOCK_ADDR	= 232,
    SystemZ_G_JUMP_TABLE	= 233,
    SystemZ_G_DYN_STACKALLOC	= 234,
    SystemZ_G_STACKSAVE	= 235,
    SystemZ_G_STACKRESTORE	= 236,
    SystemZ_G_STRICT_FADD	= 237,
    SystemZ_G_STRICT_FSUB	= 238,
    SystemZ_G_STRICT_FMUL	= 239,
    SystemZ_G_STRICT_FDIV	= 240,
    SystemZ_G_STRICT_FREM	= 241,
    SystemZ_G_STRICT_FMA	= 242,
    SystemZ_G_STRICT_FSQRT	= 243,
    SystemZ_G_STRICT_FLDEXP	= 244,
    SystemZ_G_READ_REGISTER	= 245,
    SystemZ_G_WRITE_REGISTER	= 246,
    SystemZ_G_MEMCPY	= 247,
    SystemZ_G_MEMCPY_INLINE	= 248,
    SystemZ_G_MEMMOVE	= 249,
    SystemZ_G_MEMSET	= 250,
    SystemZ_G_BZERO	= 251,
    SystemZ_G_VECREDUCE_SEQ_FADD	= 252,
    SystemZ_G_VECREDUCE_SEQ_FMUL	= 253,
    SystemZ_G_VECREDUCE_FADD	= 254,
    SystemZ_G_VECREDUCE_FMUL	= 255,
    SystemZ_G_VECREDUCE_FMAX	= 256,
    SystemZ_G_VECREDUCE_FMIN	= 257,
    SystemZ_G_VECREDUCE_FMAXIMUM	= 258,
    SystemZ_G_VECREDUCE_FMINIMUM	= 259,
    SystemZ_G_VECREDUCE_ADD	= 260,
    SystemZ_G_VECREDUCE_MUL	= 261,
    SystemZ_G_VECREDUCE_AND	= 262,
    SystemZ_G_VECREDUCE_OR	= 263,
    SystemZ_G_VECREDUCE_XOR	= 264,
    SystemZ_G_VECREDUCE_SMAX	= 265,
    SystemZ_G_VECREDUCE_SMIN	= 266,
    SystemZ_G_VECREDUCE_UMAX	= 267,
    SystemZ_G_VECREDUCE_UMIN	= 268,
    SystemZ_G_SBFX	= 269,
    SystemZ_G_UBFX	= 270,
    SystemZ_ADA_ENTRY	= 271,
    SystemZ_ADA_ENTRY_VALUE	= 272,
    SystemZ_ADB_MemFoldPseudo	= 273,
    SystemZ_ADJCALLSTACKDOWN	= 274,
    SystemZ_ADJCALLSTACKUP	= 275,
    SystemZ_ADJDYNALLOC	= 276,
    SystemZ_AEB_MemFoldPseudo	= 277,
    SystemZ_AEXT128	= 278,
    SystemZ_AFIMux	= 279,
    SystemZ_AG_MemFoldPseudo	= 280,
    SystemZ_AHIMux	= 281,
    SystemZ_AHIMuxK	= 282,
    SystemZ_ALG_MemFoldPseudo	= 283,
    SystemZ_AL_MemFoldPseudo	= 284,
    SystemZ_ATOMIC_CMP_SWAPW	= 285,
    SystemZ_ATOMIC_LOADW_AFI	= 286,
    SystemZ_ATOMIC_LOADW_AR	= 287,
    SystemZ_ATOMIC_LOADW_MAX	= 288,
    SystemZ_ATOMIC_LOADW_MIN	= 289,
    SystemZ_ATOMIC_LOADW_NILH	= 290,
    SystemZ_ATOMIC_LOADW_NILHi	= 291,
    SystemZ_ATOMIC_LOADW_NR	= 292,
    SystemZ_ATOMIC_LOADW_NRi	= 293,
    SystemZ_ATOMIC_LOADW_OILH	= 294,
    SystemZ_ATOMIC_LOADW_OR	= 295,
    SystemZ_ATOMIC_LOADW_SR	= 296,
    SystemZ_ATOMIC_LOADW_UMAX	= 297,
    SystemZ_ATOMIC_LOADW_UMIN	= 298,
    SystemZ_ATOMIC_LOADW_XILF	= 299,
    SystemZ_ATOMIC_LOADW_XR	= 300,
    SystemZ_ATOMIC_SWAPW	= 301,
    SystemZ_A_MemFoldPseudo	= 302,
    SystemZ_CFIMux	= 303,
    SystemZ_CGIBCall	= 304,
    SystemZ_CGIBReturn	= 305,
    SystemZ_CGRBCall	= 306,
    SystemZ_CGRBReturn	= 307,
    SystemZ_CHIMux	= 308,
    SystemZ_CIBCall	= 309,
    SystemZ_CIBReturn	= 310,
    SystemZ_CLCImm	= 311,
    SystemZ_CLCReg	= 312,
    SystemZ_CLFIMux	= 313,
    SystemZ_CLGIBCall	= 314,
    SystemZ_CLGIBReturn	= 315,
    SystemZ_CLGRBCall	= 316,
    SystemZ_CLGRBReturn	= 317,
    SystemZ_CLIBCall	= 318,
    SystemZ_CLIBReturn	= 319,
    SystemZ_CLMux	= 320,
    SystemZ_CLRBCall	= 321,
    SystemZ_CLRBReturn	= 322,
    SystemZ_CLSTLoop	= 323,
    SystemZ_CMux	= 324,
    SystemZ_CRBCall	= 325,
    SystemZ_CRBReturn	= 326,
    SystemZ_CallBASR	= 327,
    SystemZ_CallBASR_STACKEXT	= 328,
    SystemZ_CallBASR_XPLINK64	= 329,
    SystemZ_CallBCR	= 330,
    SystemZ_CallBR	= 331,
    SystemZ_CallBRASL	= 332,
    SystemZ_CallBRASL_XPLINK64	= 333,
    SystemZ_CallBRCL	= 334,
    SystemZ_CallJG	= 335,
    SystemZ_CondReturn	= 336,
    SystemZ_CondReturn_XPLINK	= 337,
    SystemZ_CondStore16	= 338,
    SystemZ_CondStore16Inv	= 339,
    SystemZ_CondStore16Mux	= 340,
    SystemZ_CondStore16MuxInv	= 341,
    SystemZ_CondStore32	= 342,
    SystemZ_CondStore32Inv	= 343,
    SystemZ_CondStore32Mux	= 344,
    SystemZ_CondStore32MuxInv	= 345,
    SystemZ_CondStore64	= 346,
    SystemZ_CondStore64Inv	= 347,
    SystemZ_CondStore8	= 348,
    SystemZ_CondStore8Inv	= 349,
    SystemZ_CondStore8Mux	= 350,
    SystemZ_CondStore8MuxInv	= 351,
    SystemZ_CondStoreF32	= 352,
    SystemZ_CondStoreF32Inv	= 353,
    SystemZ_CondStoreF64	= 354,
    SystemZ_CondStoreF64Inv	= 355,
    SystemZ_CondTrap	= 356,
    SystemZ_DDB_MemFoldPseudo	= 357,
    SystemZ_DEB_MemFoldPseudo	= 358,
    SystemZ_EXRL_Pseudo	= 359,
    SystemZ_GOT	= 360,
    SystemZ_IIFMux	= 361,
    SystemZ_IIHF64	= 362,
    SystemZ_IIHH64	= 363,
    SystemZ_IIHL64	= 364,
    SystemZ_IIHMux	= 365,
    SystemZ_IILF64	= 366,
    SystemZ_IILH64	= 367,
    SystemZ_IILL64	= 368,
    SystemZ_IILMux	= 369,
    SystemZ_L128	= 370,
    SystemZ_LBMux	= 371,
    SystemZ_LEFR	= 372,
    SystemZ_LFER	= 373,
    SystemZ_LHIMux	= 374,
    SystemZ_LHMux	= 375,
    SystemZ_LLCMux	= 376,
    SystemZ_LLCRMux	= 377,
    SystemZ_LLHMux	= 378,
    SystemZ_LLHRMux	= 379,
    SystemZ_LMux	= 380,
    SystemZ_LOCG_MemFoldPseudo	= 381,
    SystemZ_LOCHIMux	= 382,
    SystemZ_LOCMux	= 383,
    SystemZ_LOCMux_MemFoldPseudo	= 384,
    SystemZ_LOCRMux	= 385,
    SystemZ_LTDBRCompare_Pseudo	= 386,
    SystemZ_LTEBRCompare_Pseudo	= 387,
    SystemZ_LTXBRCompare_Pseudo	= 388,
    SystemZ_LX	= 389,
    SystemZ_MADB_MemFoldPseudo	= 390,
    SystemZ_MAEB_MemFoldPseudo	= 391,
    SystemZ_MDB_MemFoldPseudo	= 392,
    SystemZ_MEEB_MemFoldPseudo	= 393,
    SystemZ_MSC_MemFoldPseudo	= 394,
    SystemZ_MSDB_MemFoldPseudo	= 395,
    SystemZ_MSEB_MemFoldPseudo	= 396,
    SystemZ_MSGC_MemFoldPseudo	= 397,
    SystemZ_MVCImm	= 398,
    SystemZ_MVCReg	= 399,
    SystemZ_MVSTLoop	= 400,
    SystemZ_MemsetImmImm	= 401,
    SystemZ_MemsetImmReg	= 402,
    SystemZ_MemsetRegImm	= 403,
    SystemZ_MemsetRegReg	= 404,
    SystemZ_NCImm	= 405,
    SystemZ_NCReg	= 406,
    SystemZ_NG_MemFoldPseudo	= 407,
    SystemZ_NIFMux	= 408,
    SystemZ_NIHF64	= 409,
    SystemZ_NIHH64	= 410,
    SystemZ_NIHL64	= 411,
    SystemZ_NIHMux	= 412,
    SystemZ_NILF64	= 413,
    SystemZ_NILH64	= 414,
    SystemZ_NILL64	= 415,
    SystemZ_NILMux	= 416,
    SystemZ_N_MemFoldPseudo	= 417,
    SystemZ_OCImm	= 418,
    SystemZ_OCReg	= 419,
    SystemZ_OG_MemFoldPseudo	= 420,
    SystemZ_OIFMux	= 421,
    SystemZ_OIHF64	= 422,
    SystemZ_OIHH64	= 423,
    SystemZ_OIHL64	= 424,
    SystemZ_OIHMux	= 425,
    SystemZ_OILF64	= 426,
    SystemZ_OILH64	= 427,
    SystemZ_OILL64	= 428,
    SystemZ_OILMux	= 429,
    SystemZ_O_MemFoldPseudo	= 430,
    SystemZ_PAIR128	= 431,
    SystemZ_PROBED_ALLOCA	= 432,
    SystemZ_PROBED_STACKALLOC	= 433,
    SystemZ_RISBHH	= 434,
    SystemZ_RISBHL	= 435,
    SystemZ_RISBLH	= 436,
    SystemZ_RISBLL	= 437,
    SystemZ_RISBMux	= 438,
    SystemZ_Return	= 439,
    SystemZ_Return_XPLINK	= 440,
    SystemZ_SCmp128Hi	= 441,
    SystemZ_SDB_MemFoldPseudo	= 442,
    SystemZ_SEB_MemFoldPseudo	= 443,
    SystemZ_SELRMux	= 444,
    SystemZ_SG_MemFoldPseudo	= 445,
    SystemZ_SLG_MemFoldPseudo	= 446,
    SystemZ_SL_MemFoldPseudo	= 447,
    SystemZ_SRSTLoop	= 448,
    SystemZ_ST128	= 449,
    SystemZ_STCMux	= 450,
    SystemZ_STHMux	= 451,
    SystemZ_STMux	= 452,
    SystemZ_STOCMux	= 453,
    SystemZ_STX	= 454,
    SystemZ_S_MemFoldPseudo	= 455,
    SystemZ_Select128	= 456,
    SystemZ_Select32	= 457,
    SystemZ_Select64	= 458,
    SystemZ_SelectF128	= 459,
    SystemZ_SelectF32	= 460,
    SystemZ_SelectF64	= 461,
    SystemZ_SelectVR128	= 462,
    SystemZ_SelectVR32	= 463,
    SystemZ_SelectVR64	= 464,
    SystemZ_Serialize	= 465,
    SystemZ_TBEGIN_nofloat	= 466,
    SystemZ_TLS_GDCALL	= 467,
    SystemZ_TLS_LDCALL	= 468,
    SystemZ_TMHH64	= 469,
    SystemZ_TMHL64	= 470,
    SystemZ_TMHMux	= 471,
    SystemZ_TMLH64	= 472,
    SystemZ_TMLL64	= 473,
    SystemZ_TMLMux	= 474,
    SystemZ_Trap	= 475,
    SystemZ_UCmp128Hi	= 476,
    SystemZ_VL32	= 477,
    SystemZ_VL64	= 478,
    SystemZ_VLR32	= 479,
    SystemZ_VLR64	= 480,
    SystemZ_VLVGP32	= 481,
    SystemZ_VST32	= 482,
    SystemZ_VST64	= 483,
    SystemZ_XCImm	= 484,
    SystemZ_XCReg	= 485,
    SystemZ_XG_MemFoldPseudo	= 486,
    SystemZ_XIFMux	= 487,
    SystemZ_XIHF64	= 488,
    SystemZ_XILF64	= 489,
    SystemZ_XPLINK_STACKALLOC	= 490,
    SystemZ_X_MemFoldPseudo	= 491,
    SystemZ_ZEXT128	= 492,
    SystemZ_A	= 493,
    SystemZ_AD	= 494,
    SystemZ_ADB	= 495,
    SystemZ_ADBR	= 496,
    SystemZ_ADR	= 497,
    SystemZ_ADTR	= 498,
    SystemZ_ADTRA	= 499,
    SystemZ_AE	= 500,
    SystemZ_AEB	= 501,
    SystemZ_AEBR	= 502,
    SystemZ_AER	= 503,
    SystemZ_AFI	= 504,
    SystemZ_AG	= 505,
    SystemZ_AGF	= 506,
    SystemZ_AGFI	= 507,
    SystemZ_AGFR	= 508,
    SystemZ_AGH	= 509,
    SystemZ_AGHI	= 510,
    SystemZ_AGHIK	= 511,
    SystemZ_AGR	= 512,
    SystemZ_AGRK	= 513,
    SystemZ_AGSI	= 514,
    SystemZ_AH	= 515,
    SystemZ_AHHHR	= 516,
    SystemZ_AHHLR	= 517,
    SystemZ_AHI	= 518,
    SystemZ_AHIK	= 519,
    SystemZ_AHY	= 520,
    SystemZ_AIH	= 521,
    SystemZ_AL	= 522,
    SystemZ_ALC	= 523,
    SystemZ_ALCG	= 524,
    SystemZ_ALCGR	= 525,
    SystemZ_ALCR	= 526,
    SystemZ_ALFI	= 527,
    SystemZ_ALG	= 528,
    SystemZ_ALGF	= 529,
    SystemZ_ALGFI	= 530,
    SystemZ_ALGFR	= 531,
    SystemZ_ALGHSIK	= 532,
    SystemZ_ALGR	= 533,
    SystemZ_ALGRK	= 534,
    SystemZ_ALGSI	= 535,
    SystemZ_ALHHHR	= 536,
    SystemZ_ALHHLR	= 537,
    SystemZ_ALHSIK	= 538,
    SystemZ_ALR	= 539,
    SystemZ_ALRK	= 540,
    SystemZ_ALSI	= 541,
    SystemZ_ALSIH	= 542,
    SystemZ_ALSIHN	= 543,
    SystemZ_ALY	= 544,
    SystemZ_AP	= 545,
    SystemZ_AR	= 546,
    SystemZ_ARK	= 547,
    SystemZ_ASI	= 548,
    SystemZ_AU	= 549,
    SystemZ_AUR	= 550,
    SystemZ_AW	= 551,
    SystemZ_AWR	= 552,
    SystemZ_AXBR	= 553,
    SystemZ_AXR	= 554,
    SystemZ_AXTR	= 555,
    SystemZ_AXTRA	= 556,
    SystemZ_AY	= 557,
    SystemZ_B	= 558,
    SystemZ_BAKR	= 559,
    SystemZ_BAL	= 560,
    SystemZ_BALR	= 561,
    SystemZ_BAS	= 562,
    SystemZ_BASR	= 563,
    SystemZ_BASSM	= 564,
    SystemZ_BAsmE	= 565,
    SystemZ_BAsmH	= 566,
    SystemZ_BAsmHE	= 567,
    SystemZ_BAsmL	= 568,
    SystemZ_BAsmLE	= 569,
    SystemZ_BAsmLH	= 570,
    SystemZ_BAsmM	= 571,
    SystemZ_BAsmNE	= 572,
    SystemZ_BAsmNH	= 573,
    SystemZ_BAsmNHE	= 574,
    SystemZ_BAsmNL	= 575,
    SystemZ_BAsmNLE	= 576,
    SystemZ_BAsmNLH	= 577,
    SystemZ_BAsmNM	= 578,
    SystemZ_BAsmNO	= 579,
    SystemZ_BAsmNP	= 580,
    SystemZ_BAsmNZ	= 581,
    SystemZ_BAsmO	= 582,
    SystemZ_BAsmP	= 583,
    SystemZ_BAsmZ	= 584,
    SystemZ_BC	= 585,
    SystemZ_BCAsm	= 586,
    SystemZ_BCR	= 587,
    SystemZ_BCRAsm	= 588,
    SystemZ_BCT	= 589,
    SystemZ_BCTG	= 590,
    SystemZ_BCTGR	= 591,
    SystemZ_BCTR	= 592,
    SystemZ_BI	= 593,
    SystemZ_BIAsmE	= 594,
    SystemZ_BIAsmH	= 595,
    SystemZ_BIAsmHE	= 596,
    SystemZ_BIAsmL	= 597,
    SystemZ_BIAsmLE	= 598,
    SystemZ_BIAsmLH	= 599,
    SystemZ_BIAsmM	= 600,
    SystemZ_BIAsmNE	= 601,
    SystemZ_BIAsmNH	= 602,
    SystemZ_BIAsmNHE	= 603,
    SystemZ_BIAsmNL	= 604,
    SystemZ_BIAsmNLE	= 605,
    SystemZ_BIAsmNLH	= 606,
    SystemZ_BIAsmNM	= 607,
    SystemZ_BIAsmNO	= 608,
    SystemZ_BIAsmNP	= 609,
    SystemZ_BIAsmNZ	= 610,
    SystemZ_BIAsmO	= 611,
    SystemZ_BIAsmP	= 612,
    SystemZ_BIAsmZ	= 613,
    SystemZ_BIC	= 614,
    SystemZ_BICAsm	= 615,
    SystemZ_BPP	= 616,
    SystemZ_BPRP	= 617,
    SystemZ_BR	= 618,
    SystemZ_BRAS	= 619,
    SystemZ_BRASL	= 620,
    SystemZ_BRAsmE	= 621,
    SystemZ_BRAsmH	= 622,
    SystemZ_BRAsmHE	= 623,
    SystemZ_BRAsmL	= 624,
    SystemZ_BRAsmLE	= 625,
    SystemZ_BRAsmLH	= 626,
    SystemZ_BRAsmM	= 627,
    SystemZ_BRAsmNE	= 628,
    SystemZ_BRAsmNH	= 629,
    SystemZ_BRAsmNHE	= 630,
    SystemZ_BRAsmNL	= 631,
    SystemZ_BRAsmNLE	= 632,
    SystemZ_BRAsmNLH	= 633,
    SystemZ_BRAsmNM	= 634,
    SystemZ_BRAsmNO	= 635,
    SystemZ_BRAsmNP	= 636,
    SystemZ_BRAsmNZ	= 637,
    SystemZ_BRAsmO	= 638,
    SystemZ_BRAsmP	= 639,
    SystemZ_BRAsmZ	= 640,
    SystemZ_BRC	= 641,
    SystemZ_BRCAsm	= 642,
    SystemZ_BRCL	= 643,
    SystemZ_BRCLAsm	= 644,
    SystemZ_BRCT	= 645,
    SystemZ_BRCTG	= 646,
    SystemZ_BRCTH	= 647,
    SystemZ_BRXH	= 648,
    SystemZ_BRXHG	= 649,
    SystemZ_BRXLE	= 650,
    SystemZ_BRXLG	= 651,
    SystemZ_BSA	= 652,
    SystemZ_BSG	= 653,
    SystemZ_BSM	= 654,
    SystemZ_BXH	= 655,
    SystemZ_BXHG	= 656,
    SystemZ_BXLE	= 657,
    SystemZ_BXLEG	= 658,
    SystemZ_C	= 659,
    SystemZ_CD	= 660,
    SystemZ_CDB	= 661,
    SystemZ_CDBR	= 662,
    SystemZ_CDFBR	= 663,
    SystemZ_CDFBRA	= 664,
    SystemZ_CDFR	= 665,
    SystemZ_CDFTR	= 666,
    SystemZ_CDGBR	= 667,
    SystemZ_CDGBRA	= 668,
    SystemZ_CDGR	= 669,
    SystemZ_CDGTR	= 670,
    SystemZ_CDGTRA	= 671,
    SystemZ_CDLFBR	= 672,
    SystemZ_CDLFTR	= 673,
    SystemZ_CDLGBR	= 674,
    SystemZ_CDLGTR	= 675,
    SystemZ_CDPT	= 676,
    SystemZ_CDR	= 677,
    SystemZ_CDS	= 678,
    SystemZ_CDSG	= 679,
    SystemZ_CDSTR	= 680,
    SystemZ_CDSY	= 681,
    SystemZ_CDTR	= 682,
    SystemZ_CDUTR	= 683,
    SystemZ_CDZT	= 684,
    SystemZ_CE	= 685,
    SystemZ_CEB	= 686,
    SystemZ_CEBR	= 687,
    SystemZ_CEDTR	= 688,
    SystemZ_CEFBR	= 689,
    SystemZ_CEFBRA	= 690,
    SystemZ_CEFR	= 691,
    SystemZ_CEGBR	= 692,
    SystemZ_CEGBRA	= 693,
    SystemZ_CEGR	= 694,
    SystemZ_CELFBR	= 695,
    SystemZ_CELGBR	= 696,
    SystemZ_CER	= 697,
    SystemZ_CEXTR	= 698,
    SystemZ_CFC	= 699,
    SystemZ_CFDBR	= 700,
    SystemZ_CFDBRA	= 701,
    SystemZ_CFDR	= 702,
    SystemZ_CFDTR	= 703,
    SystemZ_CFEBR	= 704,
    SystemZ_CFEBRA	= 705,
    SystemZ_CFER	= 706,
    SystemZ_CFI	= 707,
    SystemZ_CFXBR	= 708,
    SystemZ_CFXBRA	= 709,
    SystemZ_CFXR	= 710,
    SystemZ_CFXTR	= 711,
    SystemZ_CG	= 712,
    SystemZ_CGDBR	= 713,
    SystemZ_CGDBRA	= 714,
    SystemZ_CGDR	= 715,
    SystemZ_CGDTR	= 716,
    SystemZ_CGDTRA	= 717,
    SystemZ_CGEBR	= 718,
    SystemZ_CGEBRA	= 719,
    SystemZ_CGER	= 720,
    SystemZ_CGF	= 721,
    SystemZ_CGFI	= 722,
    SystemZ_CGFR	= 723,
    SystemZ_CGFRL	= 724,
    SystemZ_CGH	= 725,
    SystemZ_CGHI	= 726,
    SystemZ_CGHRL	= 727,
    SystemZ_CGHSI	= 728,
    SystemZ_CGIB	= 729,
    SystemZ_CGIBAsm	= 730,
    SystemZ_CGIBAsmE	= 731,
    SystemZ_CGIBAsmH	= 732,
    SystemZ_CGIBAsmHE	= 733,
    SystemZ_CGIBAsmL	= 734,
    SystemZ_CGIBAsmLE	= 735,
    SystemZ_CGIBAsmLH	= 736,
    SystemZ_CGIBAsmNE	= 737,
    SystemZ_CGIBAsmNH	= 738,
    SystemZ_CGIBAsmNHE	= 739,
    SystemZ_CGIBAsmNL	= 740,
    SystemZ_CGIBAsmNLE	= 741,
    SystemZ_CGIBAsmNLH	= 742,
    SystemZ_CGIJ	= 743,
    SystemZ_CGIJAsm	= 744,
    SystemZ_CGIJAsmE	= 745,
    SystemZ_CGIJAsmH	= 746,
    SystemZ_CGIJAsmHE	= 747,
    SystemZ_CGIJAsmL	= 748,
    SystemZ_CGIJAsmLE	= 749,
    SystemZ_CGIJAsmLH	= 750,
    SystemZ_CGIJAsmNE	= 751,
    SystemZ_CGIJAsmNH	= 752,
    SystemZ_CGIJAsmNHE	= 753,
    SystemZ_CGIJAsmNL	= 754,
    SystemZ_CGIJAsmNLE	= 755,
    SystemZ_CGIJAsmNLH	= 756,
    SystemZ_CGIT	= 757,
    SystemZ_CGITAsm	= 758,
    SystemZ_CGITAsmE	= 759,
    SystemZ_CGITAsmH	= 760,
    SystemZ_CGITAsmHE	= 761,
    SystemZ_CGITAsmL	= 762,
    SystemZ_CGITAsmLE	= 763,
    SystemZ_CGITAsmLH	= 764,
    SystemZ_CGITAsmNE	= 765,
    SystemZ_CGITAsmNH	= 766,
    SystemZ_CGITAsmNHE	= 767,
    SystemZ_CGITAsmNL	= 768,
    SystemZ_CGITAsmNLE	= 769,
    SystemZ_CGITAsmNLH	= 770,
    SystemZ_CGR	= 771,
    SystemZ_CGRB	= 772,
    SystemZ_CGRBAsm	= 773,
    SystemZ_CGRBAsmE	= 774,
    SystemZ_CGRBAsmH	= 775,
    SystemZ_CGRBAsmHE	= 776,
    SystemZ_CGRBAsmL	= 777,
    SystemZ_CGRBAsmLE	= 778,
    SystemZ_CGRBAsmLH	= 779,
    SystemZ_CGRBAsmNE	= 780,
    SystemZ_CGRBAsmNH	= 781,
    SystemZ_CGRBAsmNHE	= 782,
    SystemZ_CGRBAsmNL	= 783,
    SystemZ_CGRBAsmNLE	= 784,
    SystemZ_CGRBAsmNLH	= 785,
    SystemZ_CGRJ	= 786,
    SystemZ_CGRJAsm	= 787,
    SystemZ_CGRJAsmE	= 788,
    SystemZ_CGRJAsmH	= 789,
    SystemZ_CGRJAsmHE	= 790,
    SystemZ_CGRJAsmL	= 791,
    SystemZ_CGRJAsmLE	= 792,
    SystemZ_CGRJAsmLH	= 793,
    SystemZ_CGRJAsmNE	= 794,
    SystemZ_CGRJAsmNH	= 795,
    SystemZ_CGRJAsmNHE	= 796,
    SystemZ_CGRJAsmNL	= 797,
    SystemZ_CGRJAsmNLE	= 798,
    SystemZ_CGRJAsmNLH	= 799,
    SystemZ_CGRL	= 800,
    SystemZ_CGRT	= 801,
    SystemZ_CGRTAsm	= 802,
    SystemZ_CGRTAsmE	= 803,
    SystemZ_CGRTAsmH	= 804,
    SystemZ_CGRTAsmHE	= 805,
    SystemZ_CGRTAsmL	= 806,
    SystemZ_CGRTAsmLE	= 807,
    SystemZ_CGRTAsmLH	= 808,
    SystemZ_CGRTAsmNE	= 809,
    SystemZ_CGRTAsmNH	= 810,
    SystemZ_CGRTAsmNHE	= 811,
    SystemZ_CGRTAsmNL	= 812,
    SystemZ_CGRTAsmNLE	= 813,
    SystemZ_CGRTAsmNLH	= 814,
    SystemZ_CGXBR	= 815,
    SystemZ_CGXBRA	= 816,
    SystemZ_CGXR	= 817,
    SystemZ_CGXTR	= 818,
    SystemZ_CGXTRA	= 819,
    SystemZ_CH	= 820,
    SystemZ_CHF	= 821,
    SystemZ_CHHR	= 822,
    SystemZ_CHHSI	= 823,
    SystemZ_CHI	= 824,
    SystemZ_CHLR	= 825,
    SystemZ_CHRL	= 826,
    SystemZ_CHSI	= 827,
    SystemZ_CHY	= 828,
    SystemZ_CIB	= 829,
    SystemZ_CIBAsm	= 830,
    SystemZ_CIBAsmE	= 831,
    SystemZ_CIBAsmH	= 832,
    SystemZ_CIBAsmHE	= 833,
    SystemZ_CIBAsmL	= 834,
    SystemZ_CIBAsmLE	= 835,
    SystemZ_CIBAsmLH	= 836,
    SystemZ_CIBAsmNE	= 837,
    SystemZ_CIBAsmNH	= 838,
    SystemZ_CIBAsmNHE	= 839,
    SystemZ_CIBAsmNL	= 840,
    SystemZ_CIBAsmNLE	= 841,
    SystemZ_CIBAsmNLH	= 842,
    SystemZ_CIH	= 843,
    SystemZ_CIJ	= 844,
    SystemZ_CIJAsm	= 845,
    SystemZ_CIJAsmE	= 846,
    SystemZ_CIJAsmH	= 847,
    SystemZ_CIJAsmHE	= 848,
    SystemZ_CIJAsmL	= 849,
    SystemZ_CIJAsmLE	= 850,
    SystemZ_CIJAsmLH	= 851,
    SystemZ_CIJAsmNE	= 852,
    SystemZ_CIJAsmNH	= 853,
    SystemZ_CIJAsmNHE	= 854,
    SystemZ_CIJAsmNL	= 855,
    SystemZ_CIJAsmNLE	= 856,
    SystemZ_CIJAsmNLH	= 857,
    SystemZ_CIT	= 858,
    SystemZ_CITAsm	= 859,
    SystemZ_CITAsmE	= 860,
    SystemZ_CITAsmH	= 861,
    SystemZ_CITAsmHE	= 862,
    SystemZ_CITAsmL	= 863,
    SystemZ_CITAsmLE	= 864,
    SystemZ_CITAsmLH	= 865,
    SystemZ_CITAsmNE	= 866,
    SystemZ_CITAsmNH	= 867,
    SystemZ_CITAsmNHE	= 868,
    SystemZ_CITAsmNL	= 869,
    SystemZ_CITAsmNLE	= 870,
    SystemZ_CITAsmNLH	= 871,
    SystemZ_CKSM	= 872,
    SystemZ_CL	= 873,
    SystemZ_CLC	= 874,
    SystemZ_CLCL	= 875,
    SystemZ_CLCLE	= 876,
    SystemZ_CLCLU	= 877,
    SystemZ_CLFDBR	= 878,
    SystemZ_CLFDTR	= 879,
    SystemZ_CLFEBR	= 880,
    SystemZ_CLFHSI	= 881,
    SystemZ_CLFI	= 882,
    SystemZ_CLFIT	= 883,
    SystemZ_CLFITAsm	= 884,
    SystemZ_CLFITAsmE	= 885,
    SystemZ_CLFITAsmH	= 886,
    SystemZ_CLFITAsmHE	= 887,
    SystemZ_CLFITAsmL	= 888,
    SystemZ_CLFITAsmLE	= 889,
    SystemZ_CLFITAsmLH	= 890,
    SystemZ_CLFITAsmNE	= 891,
    SystemZ_CLFITAsmNH	= 892,
    SystemZ_CLFITAsmNHE	= 893,
    SystemZ_CLFITAsmNL	= 894,
    SystemZ_CLFITAsmNLE	= 895,
    SystemZ_CLFITAsmNLH	= 896,
    SystemZ_CLFXBR	= 897,
    SystemZ_CLFXTR	= 898,
    SystemZ_CLG	= 899,
    SystemZ_CLGDBR	= 900,
    SystemZ_CLGDTR	= 901,
    SystemZ_CLGEBR	= 902,
    SystemZ_CLGF	= 903,
    SystemZ_CLGFI	= 904,
    SystemZ_CLGFR	= 905,
    SystemZ_CLGFRL	= 906,
    SystemZ_CLGHRL	= 907,
    SystemZ_CLGHSI	= 908,
    SystemZ_CLGIB	= 909,
    SystemZ_CLGIBAsm	= 910,
    SystemZ_CLGIBAsmE	= 911,
    SystemZ_CLGIBAsmH	= 912,
    SystemZ_CLGIBAsmHE	= 913,
    SystemZ_CLGIBAsmL	= 914,
    SystemZ_CLGIBAsmLE	= 915,
    SystemZ_CLGIBAsmLH	= 916,
    SystemZ_CLGIBAsmNE	= 917,
    SystemZ_CLGIBAsmNH	= 918,
    SystemZ_CLGIBAsmNHE	= 919,
    SystemZ_CLGIBAsmNL	= 920,
    SystemZ_CLGIBAsmNLE	= 921,
    SystemZ_CLGIBAsmNLH	= 922,
    SystemZ_CLGIJ	= 923,
    SystemZ_CLGIJAsm	= 924,
    SystemZ_CLGIJAsmE	= 925,
    SystemZ_CLGIJAsmH	= 926,
    SystemZ_CLGIJAsmHE	= 927,
    SystemZ_CLGIJAsmL	= 928,
    SystemZ_CLGIJAsmLE	= 929,
    SystemZ_CLGIJAsmLH	= 930,
    SystemZ_CLGIJAsmNE	= 931,
    SystemZ_CLGIJAsmNH	= 932,
    SystemZ_CLGIJAsmNHE	= 933,
    SystemZ_CLGIJAsmNL	= 934,
    SystemZ_CLGIJAsmNLE	= 935,
    SystemZ_CLGIJAsmNLH	= 936,
    SystemZ_CLGIT	= 937,
    SystemZ_CLGITAsm	= 938,
    SystemZ_CLGITAsmE	= 939,
    SystemZ_CLGITAsmH	= 940,
    SystemZ_CLGITAsmHE	= 941,
    SystemZ_CLGITAsmL	= 942,
    SystemZ_CLGITAsmLE	= 943,
    SystemZ_CLGITAsmLH	= 944,
    SystemZ_CLGITAsmNE	= 945,
    SystemZ_CLGITAsmNH	= 946,
    SystemZ_CLGITAsmNHE	= 947,
    SystemZ_CLGITAsmNL	= 948,
    SystemZ_CLGITAsmNLE	= 949,
    SystemZ_CLGITAsmNLH	= 950,
    SystemZ_CLGR	= 951,
    SystemZ_CLGRB	= 952,
    SystemZ_CLGRBAsm	= 953,
    SystemZ_CLGRBAsmE	= 954,
    SystemZ_CLGRBAsmH	= 955,
    SystemZ_CLGRBAsmHE	= 956,
    SystemZ_CLGRBAsmL	= 957,
    SystemZ_CLGRBAsmLE	= 958,
    SystemZ_CLGRBAsmLH	= 959,
    SystemZ_CLGRBAsmNE	= 960,
    SystemZ_CLGRBAsmNH	= 961,
    SystemZ_CLGRBAsmNHE	= 962,
    SystemZ_CLGRBAsmNL	= 963,
    SystemZ_CLGRBAsmNLE	= 964,
    SystemZ_CLGRBAsmNLH	= 965,
    SystemZ_CLGRJ	= 966,
    SystemZ_CLGRJAsm	= 967,
    SystemZ_CLGRJAsmE	= 968,
    SystemZ_CLGRJAsmH	= 969,
    SystemZ_CLGRJAsmHE	= 970,
    SystemZ_CLGRJAsmL	= 971,
    SystemZ_CLGRJAsmLE	= 972,
    SystemZ_CLGRJAsmLH	= 973,
    SystemZ_CLGRJAsmNE	= 974,
    SystemZ_CLGRJAsmNH	= 975,
    SystemZ_CLGRJAsmNHE	= 976,
    SystemZ_CLGRJAsmNL	= 977,
    SystemZ_CLGRJAsmNLE	= 978,
    SystemZ_CLGRJAsmNLH	= 979,
    SystemZ_CLGRL	= 980,
    SystemZ_CLGRT	= 981,
    SystemZ_CLGRTAsm	= 982,
    SystemZ_CLGRTAsmE	= 983,
    SystemZ_CLGRTAsmH	= 984,
    SystemZ_CLGRTAsmHE	= 985,
    SystemZ_CLGRTAsmL	= 986,
    SystemZ_CLGRTAsmLE	= 987,
    SystemZ_CLGRTAsmLH	= 988,
    SystemZ_CLGRTAsmNE	= 989,
    SystemZ_CLGRTAsmNH	= 990,
    SystemZ_CLGRTAsmNHE	= 991,
    SystemZ_CLGRTAsmNL	= 992,
    SystemZ_CLGRTAsmNLE	= 993,
    SystemZ_CLGRTAsmNLH	= 994,
    SystemZ_CLGT	= 995,
    SystemZ_CLGTAsm	= 996,
    SystemZ_CLGTAsmE	= 997,
    SystemZ_CLGTAsmH	= 998,
    SystemZ_CLGTAsmHE	= 999,
    SystemZ_CLGTAsmL	= 1000,
    SystemZ_CLGTAsmLE	= 1001,
    SystemZ_CLGTAsmLH	= 1002,
    SystemZ_CLGTAsmNE	= 1003,
    SystemZ_CLGTAsmNH	= 1004,
    SystemZ_CLGTAsmNHE	= 1005,
    SystemZ_CLGTAsmNL	= 1006,
    SystemZ_CLGTAsmNLE	= 1007,
    SystemZ_CLGTAsmNLH	= 1008,
    SystemZ_CLGXBR	= 1009,
    SystemZ_CLGXTR	= 1010,
    SystemZ_CLHF	= 1011,
    SystemZ_CLHHR	= 1012,
    SystemZ_CLHHSI	= 1013,
    SystemZ_CLHLR	= 1014,
    SystemZ_CLHRL	= 1015,
    SystemZ_CLI	= 1016,
    SystemZ_CLIB	= 1017,
    SystemZ_CLIBAsm	= 1018,
    SystemZ_CLIBAsmE	= 1019,
    SystemZ_CLIBAsmH	= 1020,
    SystemZ_CLIBAsmHE	= 1021,
    SystemZ_CLIBAsmL	= 1022,
    SystemZ_CLIBAsmLE	= 1023,
    SystemZ_CLIBAsmLH	= 1024,
    SystemZ_CLIBAsmNE	= 1025,
    SystemZ_CLIBAsmNH	= 1026,
    SystemZ_CLIBAsmNHE	= 1027,
    SystemZ_CLIBAsmNL	= 1028,
    SystemZ_CLIBAsmNLE	= 1029,
    SystemZ_CLIBAsmNLH	= 1030,
    SystemZ_CLIH	= 1031,
    SystemZ_CLIJ	= 1032,
    SystemZ_CLIJAsm	= 1033,
    SystemZ_CLIJAsmE	= 1034,
    SystemZ_CLIJAsmH	= 1035,
    SystemZ_CLIJAsmHE	= 1036,
    SystemZ_CLIJAsmL	= 1037,
    SystemZ_CLIJAsmLE	= 1038,
    SystemZ_CLIJAsmLH	= 1039,
    SystemZ_CLIJAsmNE	= 1040,
    SystemZ_CLIJAsmNH	= 1041,
    SystemZ_CLIJAsmNHE	= 1042,
    SystemZ_CLIJAsmNL	= 1043,
    SystemZ_CLIJAsmNLE	= 1044,
    SystemZ_CLIJAsmNLH	= 1045,
    SystemZ_CLIY	= 1046,
    SystemZ_CLM	= 1047,
    SystemZ_CLMH	= 1048,
    SystemZ_CLMY	= 1049,
    SystemZ_CLR	= 1050,
    SystemZ_CLRB	= 1051,
    SystemZ_CLRBAsm	= 1052,
    SystemZ_CLRBAsmE	= 1053,
    SystemZ_CLRBAsmH	= 1054,
    SystemZ_CLRBAsmHE	= 1055,
    SystemZ_CLRBAsmL	= 1056,
    SystemZ_CLRBAsmLE	= 1057,
    SystemZ_CLRBAsmLH	= 1058,
    SystemZ_CLRBAsmNE	= 1059,
    SystemZ_CLRBAsmNH	= 1060,
    SystemZ_CLRBAsmNHE	= 1061,
    SystemZ_CLRBAsmNL	= 1062,
    SystemZ_CLRBAsmNLE	= 1063,
    SystemZ_CLRBAsmNLH	= 1064,
    SystemZ_CLRJ	= 1065,
    SystemZ_CLRJAsm	= 1066,
    SystemZ_CLRJAsmE	= 1067,
    SystemZ_CLRJAsmH	= 1068,
    SystemZ_CLRJAsmHE	= 1069,
    SystemZ_CLRJAsmL	= 1070,
    SystemZ_CLRJAsmLE	= 1071,
    SystemZ_CLRJAsmLH	= 1072,
    SystemZ_CLRJAsmNE	= 1073,
    SystemZ_CLRJAsmNH	= 1074,
    SystemZ_CLRJAsmNHE	= 1075,
    SystemZ_CLRJAsmNL	= 1076,
    SystemZ_CLRJAsmNLE	= 1077,
    SystemZ_CLRJAsmNLH	= 1078,
    SystemZ_CLRL	= 1079,
    SystemZ_CLRT	= 1080,
    SystemZ_CLRTAsm	= 1081,
    SystemZ_CLRTAsmE	= 1082,
    SystemZ_CLRTAsmH	= 1083,
    SystemZ_CLRTAsmHE	= 1084,
    SystemZ_CLRTAsmL	= 1085,
    SystemZ_CLRTAsmLE	= 1086,
    SystemZ_CLRTAsmLH	= 1087,
    SystemZ_CLRTAsmNE	= 1088,
    SystemZ_CLRTAsmNH	= 1089,
    SystemZ_CLRTAsmNHE	= 1090,
    SystemZ_CLRTAsmNL	= 1091,
    SystemZ_CLRTAsmNLE	= 1092,
    SystemZ_CLRTAsmNLH	= 1093,
    SystemZ_CLST	= 1094,
    SystemZ_CLT	= 1095,
    SystemZ_CLTAsm	= 1096,
    SystemZ_CLTAsmE	= 1097,
    SystemZ_CLTAsmH	= 1098,
    SystemZ_CLTAsmHE	= 1099,
    SystemZ_CLTAsmL	= 1100,
    SystemZ_CLTAsmLE	= 1101,
    SystemZ_CLTAsmLH	= 1102,
    SystemZ_CLTAsmNE	= 1103,
    SystemZ_CLTAsmNH	= 1104,
    SystemZ_CLTAsmNHE	= 1105,
    SystemZ_CLTAsmNL	= 1106,
    SystemZ_CLTAsmNLE	= 1107,
    SystemZ_CLTAsmNLH	= 1108,
    SystemZ_CLY	= 1109,
    SystemZ_CMPSC	= 1110,
    SystemZ_CP	= 1111,
    SystemZ_CPDT	= 1112,
    SystemZ_CPSDRdd	= 1113,
    SystemZ_CPSDRds	= 1114,
    SystemZ_CPSDRsd	= 1115,
    SystemZ_CPSDRss	= 1116,
    SystemZ_CPXT	= 1117,
    SystemZ_CPYA	= 1118,
    SystemZ_CR	= 1119,
    SystemZ_CRB	= 1120,
    SystemZ_CRBAsm	= 1121,
    SystemZ_CRBAsmE	= 1122,
    SystemZ_CRBAsmH	= 1123,
    SystemZ_CRBAsmHE	= 1124,
    SystemZ_CRBAsmL	= 1125,
    SystemZ_CRBAsmLE	= 1126,
    SystemZ_CRBAsmLH	= 1127,
    SystemZ_CRBAsmNE	= 1128,
    SystemZ_CRBAsmNH	= 1129,
    SystemZ_CRBAsmNHE	= 1130,
    SystemZ_CRBAsmNL	= 1131,
    SystemZ_CRBAsmNLE	= 1132,
    SystemZ_CRBAsmNLH	= 1133,
    SystemZ_CRDTE	= 1134,
    SystemZ_CRDTEOpt	= 1135,
    SystemZ_CRJ	= 1136,
    SystemZ_CRJAsm	= 1137,
    SystemZ_CRJAsmE	= 1138,
    SystemZ_CRJAsmH	= 1139,
    SystemZ_CRJAsmHE	= 1140,
    SystemZ_CRJAsmL	= 1141,
    SystemZ_CRJAsmLE	= 1142,
    SystemZ_CRJAsmLH	= 1143,
    SystemZ_CRJAsmNE	= 1144,
    SystemZ_CRJAsmNH	= 1145,
    SystemZ_CRJAsmNHE	= 1146,
    SystemZ_CRJAsmNL	= 1147,
    SystemZ_CRJAsmNLE	= 1148,
    SystemZ_CRJAsmNLH	= 1149,
    SystemZ_CRL	= 1150,
    SystemZ_CRT	= 1151,
    SystemZ_CRTAsm	= 1152,
    SystemZ_CRTAsmE	= 1153,
    SystemZ_CRTAsmH	= 1154,
    SystemZ_CRTAsmHE	= 1155,
    SystemZ_CRTAsmL	= 1156,
    SystemZ_CRTAsmLE	= 1157,
    SystemZ_CRTAsmLH	= 1158,
    SystemZ_CRTAsmNE	= 1159,
    SystemZ_CRTAsmNH	= 1160,
    SystemZ_CRTAsmNHE	= 1161,
    SystemZ_CRTAsmNL	= 1162,
    SystemZ_CRTAsmNLE	= 1163,
    SystemZ_CRTAsmNLH	= 1164,
    SystemZ_CS	= 1165,
    SystemZ_CSCH	= 1166,
    SystemZ_CSDTR	= 1167,
    SystemZ_CSG	= 1168,
    SystemZ_CSP	= 1169,
    SystemZ_CSPG	= 1170,
    SystemZ_CSST	= 1171,
    SystemZ_CSXTR	= 1172,
    SystemZ_CSY	= 1173,
    SystemZ_CU12	= 1174,
    SystemZ_CU12Opt	= 1175,
    SystemZ_CU14	= 1176,
    SystemZ_CU14Opt	= 1177,
    SystemZ_CU21	= 1178,
    SystemZ_CU21Opt	= 1179,
    SystemZ_CU24	= 1180,
    SystemZ_CU24Opt	= 1181,
    SystemZ_CU41	= 1182,
    SystemZ_CU42	= 1183,
    SystemZ_CUDTR	= 1184,
    SystemZ_CUSE	= 1185,
    SystemZ_CUTFU	= 1186,
    SystemZ_CUTFUOpt	= 1187,
    SystemZ_CUUTF	= 1188,
    SystemZ_CUUTFOpt	= 1189,
    SystemZ_CUXTR	= 1190,
    SystemZ_CVB	= 1191,
    SystemZ_CVBG	= 1192,
    SystemZ_CVBY	= 1193,
    SystemZ_CVD	= 1194,
    SystemZ_CVDG	= 1195,
    SystemZ_CVDY	= 1196,
    SystemZ_CXBR	= 1197,
    SystemZ_CXFBR	= 1198,
    SystemZ_CXFBRA	= 1199,
    SystemZ_CXFR	= 1200,
    SystemZ_CXFTR	= 1201,
    SystemZ_CXGBR	= 1202,
    SystemZ_CXGBRA	= 1203,
    SystemZ_CXGR	= 1204,
    SystemZ_CXGTR	= 1205,
    SystemZ_CXGTRA	= 1206,
    SystemZ_CXLFBR	= 1207,
    SystemZ_CXLFTR	= 1208,
    SystemZ_CXLGBR	= 1209,
    SystemZ_CXLGTR	= 1210,
    SystemZ_CXPT	= 1211,
    SystemZ_CXR	= 1212,
    SystemZ_CXSTR	= 1213,
    SystemZ_CXTR	= 1214,
    SystemZ_CXUTR	= 1215,
    SystemZ_CXZT	= 1216,
    SystemZ_CY	= 1217,
    SystemZ_CZDT	= 1218,
    SystemZ_CZXT	= 1219,
    SystemZ_D	= 1220,
    SystemZ_DD	= 1221,
    SystemZ_DDB	= 1222,
    SystemZ_DDBR	= 1223,
    SystemZ_DDR	= 1224,
    SystemZ_DDTR	= 1225,
    SystemZ_DDTRA	= 1226,
    SystemZ_DE	= 1227,
    SystemZ_DEB	= 1228,
    SystemZ_DEBR	= 1229,
    SystemZ_DER	= 1230,
    SystemZ_DFLTCC	= 1231,
    SystemZ_DIAG	= 1232,
    SystemZ_DIDBR	= 1233,
    SystemZ_DIEBR	= 1234,
    SystemZ_DL	= 1235,
    SystemZ_DLG	= 1236,
    SystemZ_DLGR	= 1237,
    SystemZ_DLR	= 1238,
    SystemZ_DP	= 1239,
    SystemZ_DR	= 1240,
    SystemZ_DSG	= 1241,
    SystemZ_DSGF	= 1242,
    SystemZ_DSGFR	= 1243,
    SystemZ_DSGR	= 1244,
    SystemZ_DXBR	= 1245,
    SystemZ_DXR	= 1246,
    SystemZ_DXTR	= 1247,
    SystemZ_DXTRA	= 1248,
    SystemZ_EAR	= 1249,
    SystemZ_ECAG	= 1250,
    SystemZ_ECCTR	= 1251,
    SystemZ_ECPGA	= 1252,
    SystemZ_ECTG	= 1253,
    SystemZ_ED	= 1254,
    SystemZ_EDMK	= 1255,
    SystemZ_EEDTR	= 1256,
    SystemZ_EEXTR	= 1257,
    SystemZ_EFPC	= 1258,
    SystemZ_EPAIR	= 1259,
    SystemZ_EPAR	= 1260,
    SystemZ_EPCTR	= 1261,
    SystemZ_EPSW	= 1262,
    SystemZ_EREG	= 1263,
    SystemZ_EREGG	= 1264,
    SystemZ_ESAIR	= 1265,
    SystemZ_ESAR	= 1266,
    SystemZ_ESDTR	= 1267,
    SystemZ_ESEA	= 1268,
    SystemZ_ESTA	= 1269,
    SystemZ_ESXTR	= 1270,
    SystemZ_ETND	= 1271,
    SystemZ_EX	= 1272,
    SystemZ_EXRL	= 1273,
    SystemZ_FIDBR	= 1274,
    SystemZ_FIDBRA	= 1275,
    SystemZ_FIDR	= 1276,
    SystemZ_FIDTR	= 1277,
    SystemZ_FIEBR	= 1278,
    SystemZ_FIEBRA	= 1279,
    SystemZ_FIER	= 1280,
    SystemZ_FIXBR	= 1281,
    SystemZ_FIXBRA	= 1282,
    SystemZ_FIXR	= 1283,
    SystemZ_FIXTR	= 1284,
    SystemZ_FLOGR	= 1285,
    SystemZ_HDR	= 1286,
    SystemZ_HER	= 1287,
    SystemZ_HSCH	= 1288,
    SystemZ_IAC	= 1289,
    SystemZ_IC	= 1290,
    SystemZ_IC32	= 1291,
    SystemZ_IC32Y	= 1292,
    SystemZ_ICM	= 1293,
    SystemZ_ICMH	= 1294,
    SystemZ_ICMY	= 1295,
    SystemZ_ICY	= 1296,
    SystemZ_IDTE	= 1297,
    SystemZ_IDTEOpt	= 1298,
    SystemZ_IEDTR	= 1299,
    SystemZ_IEXTR	= 1300,
    SystemZ_IIHF	= 1301,
    SystemZ_IIHH	= 1302,
    SystemZ_IIHL	= 1303,
    SystemZ_IILF	= 1304,
    SystemZ_IILH	= 1305,
    SystemZ_IILL	= 1306,
    SystemZ_IPK	= 1307,
    SystemZ_IPM	= 1308,
    SystemZ_IPTE	= 1309,
    SystemZ_IPTEOpt	= 1310,
    SystemZ_IPTEOptOpt	= 1311,
    SystemZ_IRBM	= 1312,
    SystemZ_ISKE	= 1313,
    SystemZ_IVSK	= 1314,
    SystemZ_InsnE	= 1315,
    SystemZ_InsnRI	= 1316,
    SystemZ_InsnRIE	= 1317,
    SystemZ_InsnRIL	= 1318,
    SystemZ_InsnRILU	= 1319,
    SystemZ_InsnRIS	= 1320,
    SystemZ_InsnRR	= 1321,
    SystemZ_InsnRRE	= 1322,
    SystemZ_InsnRRF	= 1323,
    SystemZ_InsnRRS	= 1324,
    SystemZ_InsnRS	= 1325,
    SystemZ_InsnRSE	= 1326,
    SystemZ_InsnRSI	= 1327,
    SystemZ_InsnRSY	= 1328,
    SystemZ_InsnRX	= 1329,
    SystemZ_InsnRXE	= 1330,
    SystemZ_InsnRXF	= 1331,
    SystemZ_InsnRXY	= 1332,
    SystemZ_InsnS	= 1333,
    SystemZ_InsnSI	= 1334,
    SystemZ_InsnSIL	= 1335,
    SystemZ_InsnSIY	= 1336,
    SystemZ_InsnSS	= 1337,
    SystemZ_InsnSSE	= 1338,
    SystemZ_InsnSSF	= 1339,
    SystemZ_InsnVRI	= 1340,
    SystemZ_InsnVRR	= 1341,
    SystemZ_InsnVRS	= 1342,
    SystemZ_InsnVRV	= 1343,
    SystemZ_InsnVRX	= 1344,
    SystemZ_InsnVSI	= 1345,
    SystemZ_J	= 1346,
    SystemZ_JAsmE	= 1347,
    SystemZ_JAsmH	= 1348,
    SystemZ_JAsmHE	= 1349,
    SystemZ_JAsmL	= 1350,
    SystemZ_JAsmLE	= 1351,
    SystemZ_JAsmLH	= 1352,
    SystemZ_JAsmM	= 1353,
    SystemZ_JAsmNE	= 1354,
    SystemZ_JAsmNH	= 1355,
    SystemZ_JAsmNHE	= 1356,
    SystemZ_JAsmNL	= 1357,
    SystemZ_JAsmNLE	= 1358,
    SystemZ_JAsmNLH	= 1359,
    SystemZ_JAsmNM	= 1360,
    SystemZ_JAsmNO	= 1361,
    SystemZ_JAsmNP	= 1362,
    SystemZ_JAsmNZ	= 1363,
    SystemZ_JAsmO	= 1364,
    SystemZ_JAsmP	= 1365,
    SystemZ_JAsmZ	= 1366,
    SystemZ_JG	= 1367,
    SystemZ_JGAsmE	= 1368,
    SystemZ_JGAsmH	= 1369,
    SystemZ_JGAsmHE	= 1370,
    SystemZ_JGAsmL	= 1371,
    SystemZ_JGAsmLE	= 1372,
    SystemZ_JGAsmLH	= 1373,
    SystemZ_JGAsmM	= 1374,
    SystemZ_JGAsmNE	= 1375,
    SystemZ_JGAsmNH	= 1376,
    SystemZ_JGAsmNHE	= 1377,
    SystemZ_JGAsmNL	= 1378,
    SystemZ_JGAsmNLE	= 1379,
    SystemZ_JGAsmNLH	= 1380,
    SystemZ_JGAsmNM	= 1381,
    SystemZ_JGAsmNO	= 1382,
    SystemZ_JGAsmNP	= 1383,
    SystemZ_JGAsmNZ	= 1384,
    SystemZ_JGAsmO	= 1385,
    SystemZ_JGAsmP	= 1386,
    SystemZ_JGAsmZ	= 1387,
    SystemZ_KDB	= 1388,
    SystemZ_KDBR	= 1389,
    SystemZ_KDSA	= 1390,
    SystemZ_KDTR	= 1391,
    SystemZ_KEB	= 1392,
    SystemZ_KEBR	= 1393,
    SystemZ_KIMD	= 1394,
    SystemZ_KLMD	= 1395,
    SystemZ_KM	= 1396,
    SystemZ_KMA	= 1397,
    SystemZ_KMAC	= 1398,
    SystemZ_KMC	= 1399,
    SystemZ_KMCTR	= 1400,
    SystemZ_KMF	= 1401,
    SystemZ_KMO	= 1402,
    SystemZ_KXBR	= 1403,
    SystemZ_KXTR	= 1404,
    SystemZ_L	= 1405,
    SystemZ_LA	= 1406,
    SystemZ_LAA	= 1407,
    SystemZ_LAAG	= 1408,
    SystemZ_LAAL	= 1409,
    SystemZ_LAALG	= 1410,
    SystemZ_LAE	= 1411,
    SystemZ_LAEY	= 1412,
    SystemZ_LAM	= 1413,
    SystemZ_LAMY	= 1414,
    SystemZ_LAN	= 1415,
    SystemZ_LANG	= 1416,
    SystemZ_LAO	= 1417,
    SystemZ_LAOG	= 1418,
    SystemZ_LARL	= 1419,
    SystemZ_LASP	= 1420,
    SystemZ_LAT	= 1421,
    SystemZ_LAX	= 1422,
    SystemZ_LAXG	= 1423,
    SystemZ_LAY	= 1424,
    SystemZ_LB	= 1425,
    SystemZ_LBEAR	= 1426,
    SystemZ_LBH	= 1427,
    SystemZ_LBR	= 1428,
    SystemZ_LCBB	= 1429,
    SystemZ_LCCTL	= 1430,
    SystemZ_LCDBR	= 1431,
    SystemZ_LCDFR	= 1432,
    SystemZ_LCDFR_32	= 1433,
    SystemZ_LCDR	= 1434,
    SystemZ_LCEBR	= 1435,
    SystemZ_LCER	= 1436,
    SystemZ_LCGFR	= 1437,
    SystemZ_LCGR	= 1438,
    SystemZ_LCR	= 1439,
    SystemZ_LCTL	= 1440,
    SystemZ_LCTLG	= 1441,
    SystemZ_LCXBR	= 1442,
    SystemZ_LCXR	= 1443,
    SystemZ_LD	= 1444,
    SystemZ_LDE	= 1445,
    SystemZ_LDE32	= 1446,
    SystemZ_LDEB	= 1447,
    SystemZ_LDEBR	= 1448,
    SystemZ_LDER	= 1449,
    SystemZ_LDETR	= 1450,
    SystemZ_LDGR	= 1451,
    SystemZ_LDR	= 1452,
    SystemZ_LDR32	= 1453,
    SystemZ_LDXBR	= 1454,
    SystemZ_LDXBRA	= 1455,
    SystemZ_LDXR	= 1456,
    SystemZ_LDXTR	= 1457,
    SystemZ_LDY	= 1458,
    SystemZ_LE	= 1459,
    SystemZ_LEDBR	= 1460,
    SystemZ_LEDBRA	= 1461,
    SystemZ_LEDR	= 1462,
    SystemZ_LEDTR	= 1463,
    SystemZ_LER	= 1464,
    SystemZ_LEXBR	= 1465,
    SystemZ_LEXBRA	= 1466,
    SystemZ_LEXR	= 1467,
    SystemZ_LEY	= 1468,
    SystemZ_LFAS	= 1469,
    SystemZ_LFH	= 1470,
    SystemZ_LFHAT	= 1471,
    SystemZ_LFPC	= 1472,
    SystemZ_LG	= 1473,
    SystemZ_LGAT	= 1474,
    SystemZ_LGB	= 1475,
    SystemZ_LGBR	= 1476,
    SystemZ_LGDR	= 1477,
    SystemZ_LGF	= 1478,
    SystemZ_LGFI	= 1479,
    SystemZ_LGFR	= 1480,
    SystemZ_LGFRL	= 1481,
    SystemZ_LGG	= 1482,
    SystemZ_LGH	= 1483,
    SystemZ_LGHI	= 1484,
    SystemZ_LGHR	= 1485,
    SystemZ_LGHRL	= 1486,
    SystemZ_LGR	= 1487,
    SystemZ_LGRL	= 1488,
    SystemZ_LGSC	= 1489,
    SystemZ_LH	= 1490,
    SystemZ_LHH	= 1491,
    SystemZ_LHI	= 1492,
    SystemZ_LHR	= 1493,
    SystemZ_LHRL	= 1494,
    SystemZ_LHY	= 1495,
    SystemZ_LLC	= 1496,
    SystemZ_LLCH	= 1497,
    SystemZ_LLCR	= 1498,
    SystemZ_LLGC	= 1499,
    SystemZ_LLGCR	= 1500,
    SystemZ_LLGF	= 1501,
    SystemZ_LLGFAT	= 1502,
    SystemZ_LLGFR	= 1503,
    SystemZ_LLGFRL	= 1504,
    SystemZ_LLGFSG	= 1505,
    SystemZ_LLGH	= 1506,
    SystemZ_LLGHR	= 1507,
    SystemZ_LLGHRL	= 1508,
    SystemZ_LLGT	= 1509,
    SystemZ_LLGTAT	= 1510,
    SystemZ_LLGTR	= 1511,
    SystemZ_LLH	= 1512,
    SystemZ_LLHH	= 1513,
    SystemZ_LLHR	= 1514,
    SystemZ_LLHRL	= 1515,
    SystemZ_LLIHF	= 1516,
    SystemZ_LLIHH	= 1517,
    SystemZ_LLIHL	= 1518,
    SystemZ_LLILF	= 1519,
    SystemZ_LLILH	= 1520,
    SystemZ_LLILL	= 1521,
    SystemZ_LLZRGF	= 1522,
    SystemZ_LM	= 1523,
    SystemZ_LMD	= 1524,
    SystemZ_LMG	= 1525,
    SystemZ_LMH	= 1526,
    SystemZ_LMY	= 1527,
    SystemZ_LNDBR	= 1528,
    SystemZ_LNDFR	= 1529,
    SystemZ_LNDFR_32	= 1530,
    SystemZ_LNDR	= 1531,
    SystemZ_LNEBR	= 1532,
    SystemZ_LNER	= 1533,
    SystemZ_LNGFR	= 1534,
    SystemZ_LNGR	= 1535,
    SystemZ_LNR	= 1536,
    SystemZ_LNXBR	= 1537,
    SystemZ_LNXR	= 1538,
    SystemZ_LOC	= 1539,
    SystemZ_LOCAsm	= 1540,
    SystemZ_LOCAsmE	= 1541,
    SystemZ_LOCAsmH	= 1542,
    SystemZ_LOCAsmHE	= 1543,
    SystemZ_LOCAsmL	= 1544,
    SystemZ_LOCAsmLE	= 1545,
    SystemZ_LOCAsmLH	= 1546,
    SystemZ_LOCAsmM	= 1547,
    SystemZ_LOCAsmNE	= 1548,
    SystemZ_LOCAsmNH	= 1549,
    SystemZ_LOCAsmNHE	= 1550,
    SystemZ_LOCAsmNL	= 1551,
    SystemZ_LOCAsmNLE	= 1552,
    SystemZ_LOCAsmNLH	= 1553,
    SystemZ_LOCAsmNM	= 1554,
    SystemZ_LOCAsmNO	= 1555,
    SystemZ_LOCAsmNP	= 1556,
    SystemZ_LOCAsmNZ	= 1557,
    SystemZ_LOCAsmO	= 1558,
    SystemZ_LOCAsmP	= 1559,
    SystemZ_LOCAsmZ	= 1560,
    SystemZ_LOCFH	= 1561,
    SystemZ_LOCFHAsm	= 1562,
    SystemZ_LOCFHAsmE	= 1563,
    SystemZ_LOCFHAsmH	= 1564,
    SystemZ_LOCFHAsmHE	= 1565,
    SystemZ_LOCFHAsmL	= 1566,
    SystemZ_LOCFHAsmLE	= 1567,
    SystemZ_LOCFHAsmLH	= 1568,
    SystemZ_LOCFHAsmM	= 1569,
    SystemZ_LOCFHAsmNE	= 1570,
    SystemZ_LOCFHAsmNH	= 1571,
    SystemZ_LOCFHAsmNHE	= 1572,
    SystemZ_LOCFHAsmNL	= 1573,
    SystemZ_LOCFHAsmNLE	= 1574,
    SystemZ_LOCFHAsmNLH	= 1575,
    SystemZ_LOCFHAsmNM	= 1576,
    SystemZ_LOCFHAsmNO	= 1577,
    SystemZ_LOCFHAsmNP	= 1578,
    SystemZ_LOCFHAsmNZ	= 1579,
    SystemZ_LOCFHAsmO	= 1580,
    SystemZ_LOCFHAsmP	= 1581,
    SystemZ_LOCFHAsmZ	= 1582,
    SystemZ_LOCFHR	= 1583,
    SystemZ_LOCFHRAsm	= 1584,
    SystemZ_LOCFHRAsmE	= 1585,
    SystemZ_LOCFHRAsmH	= 1586,
    SystemZ_LOCFHRAsmHE	= 1587,
    SystemZ_LOCFHRAsmL	= 1588,
    SystemZ_LOCFHRAsmLE	= 1589,
    SystemZ_LOCFHRAsmLH	= 1590,
    SystemZ_LOCFHRAsmM	= 1591,
    SystemZ_LOCFHRAsmNE	= 1592,
    SystemZ_LOCFHRAsmNH	= 1593,
    SystemZ_LOCFHRAsmNHE	= 1594,
    SystemZ_LOCFHRAsmNL	= 1595,
    SystemZ_LOCFHRAsmNLE	= 1596,
    SystemZ_LOCFHRAsmNLH	= 1597,
    SystemZ_LOCFHRAsmNM	= 1598,
    SystemZ_LOCFHRAsmNO	= 1599,
    SystemZ_LOCFHRAsmNP	= 1600,
    SystemZ_LOCFHRAsmNZ	= 1601,
    SystemZ_LOCFHRAsmO	= 1602,
    SystemZ_LOCFHRAsmP	= 1603,
    SystemZ_LOCFHRAsmZ	= 1604,
    SystemZ_LOCG	= 1605,
    SystemZ_LOCGAsm	= 1606,
    SystemZ_LOCGAsmE	= 1607,
    SystemZ_LOCGAsmH	= 1608,
    SystemZ_LOCGAsmHE	= 1609,
    SystemZ_LOCGAsmL	= 1610,
    SystemZ_LOCGAsmLE	= 1611,
    SystemZ_LOCGAsmLH	= 1612,
    SystemZ_LOCGAsmM	= 1613,
    SystemZ_LOCGAsmNE	= 1614,
    SystemZ_LOCGAsmNH	= 1615,
    SystemZ_LOCGAsmNHE	= 1616,
    SystemZ_LOCGAsmNL	= 1617,
    SystemZ_LOCGAsmNLE	= 1618,
    SystemZ_LOCGAsmNLH	= 1619,
    SystemZ_LOCGAsmNM	= 1620,
    SystemZ_LOCGAsmNO	= 1621,
    SystemZ_LOCGAsmNP	= 1622,
    SystemZ_LOCGAsmNZ	= 1623,
    SystemZ_LOCGAsmO	= 1624,
    SystemZ_LOCGAsmP	= 1625,
    SystemZ_LOCGAsmZ	= 1626,
    SystemZ_LOCGHI	= 1627,
    SystemZ_LOCGHIAsm	= 1628,
    SystemZ_LOCGHIAsmE	= 1629,
    SystemZ_LOCGHIAsmH	= 1630,
    SystemZ_LOCGHIAsmHE	= 1631,
    SystemZ_LOCGHIAsmL	= 1632,
    SystemZ_LOCGHIAsmLE	= 1633,
    SystemZ_LOCGHIAsmLH	= 1634,
    SystemZ_LOCGHIAsmM	= 1635,
    SystemZ_LOCGHIAsmNE	= 1636,
    SystemZ_LOCGHIAsmNH	= 1637,
    SystemZ_LOCGHIAsmNHE	= 1638,
    SystemZ_LOCGHIAsmNL	= 1639,
    SystemZ_LOCGHIAsmNLE	= 1640,
    SystemZ_LOCGHIAsmNLH	= 1641,
    SystemZ_LOCGHIAsmNM	= 1642,
    SystemZ_LOCGHIAsmNO	= 1643,
    SystemZ_LOCGHIAsmNP	= 1644,
    SystemZ_LOCGHIAsmNZ	= 1645,
    SystemZ_LOCGHIAsmO	= 1646,
    SystemZ_LOCGHIAsmP	= 1647,
    SystemZ_LOCGHIAsmZ	= 1648,
    SystemZ_LOCGR	= 1649,
    SystemZ_LOCGRAsm	= 1650,
    SystemZ_LOCGRAsmE	= 1651,
    SystemZ_LOCGRAsmH	= 1652,
    SystemZ_LOCGRAsmHE	= 1653,
    SystemZ_LOCGRAsmL	= 1654,
    SystemZ_LOCGRAsmLE	= 1655,
    SystemZ_LOCGRAsmLH	= 1656,
    SystemZ_LOCGRAsmM	= 1657,
    SystemZ_LOCGRAsmNE	= 1658,
    SystemZ_LOCGRAsmNH	= 1659,
    SystemZ_LOCGRAsmNHE	= 1660,
    SystemZ_LOCGRAsmNL	= 1661,
    SystemZ_LOCGRAsmNLE	= 1662,
    SystemZ_LOCGRAsmNLH	= 1663,
    SystemZ_LOCGRAsmNM	= 1664,
    SystemZ_LOCGRAsmNO	= 1665,
    SystemZ_LOCGRAsmNP	= 1666,
    SystemZ_LOCGRAsmNZ	= 1667,
    SystemZ_LOCGRAsmO	= 1668,
    SystemZ_LOCGRAsmP	= 1669,
    SystemZ_LOCGRAsmZ	= 1670,
    SystemZ_LOCHHI	= 1671,
    SystemZ_LOCHHIAsm	= 1672,
    SystemZ_LOCHHIAsmE	= 1673,
    SystemZ_LOCHHIAsmH	= 1674,
    SystemZ_LOCHHIAsmHE	= 1675,
    SystemZ_LOCHHIAsmL	= 1676,
    SystemZ_LOCHHIAsmLE	= 1677,
    SystemZ_LOCHHIAsmLH	= 1678,
    SystemZ_LOCHHIAsmM	= 1679,
    SystemZ_LOCHHIAsmNE	= 1680,
    SystemZ_LOCHHIAsmNH	= 1681,
    SystemZ_LOCHHIAsmNHE	= 1682,
    SystemZ_LOCHHIAsmNL	= 1683,
    SystemZ_LOCHHIAsmNLE	= 1684,
    SystemZ_LOCHHIAsmNLH	= 1685,
    SystemZ_LOCHHIAsmNM	= 1686,
    SystemZ_LOCHHIAsmNO	= 1687,
    SystemZ_LOCHHIAsmNP	= 1688,
    SystemZ_LOCHHIAsmNZ	= 1689,
    SystemZ_LOCHHIAsmO	= 1690,
    SystemZ_LOCHHIAsmP	= 1691,
    SystemZ_LOCHHIAsmZ	= 1692,
    SystemZ_LOCHI	= 1693,
    SystemZ_LOCHIAsm	= 1694,
    SystemZ_LOCHIAsmE	= 1695,
    SystemZ_LOCHIAsmH	= 1696,
    SystemZ_LOCHIAsmHE	= 1697,
    SystemZ_LOCHIAsmL	= 1698,
    SystemZ_LOCHIAsmLE	= 1699,
    SystemZ_LOCHIAsmLH	= 1700,
    SystemZ_LOCHIAsmM	= 1701,
    SystemZ_LOCHIAsmNE	= 1702,
    SystemZ_LOCHIAsmNH	= 1703,
    SystemZ_LOCHIAsmNHE	= 1704,
    SystemZ_LOCHIAsmNL	= 1705,
    SystemZ_LOCHIAsmNLE	= 1706,
    SystemZ_LOCHIAsmNLH	= 1707,
    SystemZ_LOCHIAsmNM	= 1708,
    SystemZ_LOCHIAsmNO	= 1709,
    SystemZ_LOCHIAsmNP	= 1710,
    SystemZ_LOCHIAsmNZ	= 1711,
    SystemZ_LOCHIAsmO	= 1712,
    SystemZ_LOCHIAsmP	= 1713,
    SystemZ_LOCHIAsmZ	= 1714,
    SystemZ_LOCR	= 1715,
    SystemZ_LOCRAsm	= 1716,
    SystemZ_LOCRAsmE	= 1717,
    SystemZ_LOCRAsmH	= 1718,
    SystemZ_LOCRAsmHE	= 1719,
    SystemZ_LOCRAsmL	= 1720,
    SystemZ_LOCRAsmLE	= 1721,
    SystemZ_LOCRAsmLH	= 1722,
    SystemZ_LOCRAsmM	= 1723,
    SystemZ_LOCRAsmNE	= 1724,
    SystemZ_LOCRAsmNH	= 1725,
    SystemZ_LOCRAsmNHE	= 1726,
    SystemZ_LOCRAsmNL	= 1727,
    SystemZ_LOCRAsmNLE	= 1728,
    SystemZ_LOCRAsmNLH	= 1729,
    SystemZ_LOCRAsmNM	= 1730,
    SystemZ_LOCRAsmNO	= 1731,
    SystemZ_LOCRAsmNP	= 1732,
    SystemZ_LOCRAsmNZ	= 1733,
    SystemZ_LOCRAsmO	= 1734,
    SystemZ_LOCRAsmP	= 1735,
    SystemZ_LOCRAsmZ	= 1736,
    SystemZ_LPCTL	= 1737,
    SystemZ_LPD	= 1738,
    SystemZ_LPDBR	= 1739,
    SystemZ_LPDFR	= 1740,
    SystemZ_LPDFR_32	= 1741,
    SystemZ_LPDG	= 1742,
    SystemZ_LPDR	= 1743,
    SystemZ_LPEBR	= 1744,
    SystemZ_LPER	= 1745,
    SystemZ_LPGFR	= 1746,
    SystemZ_LPGR	= 1747,
    SystemZ_LPP	= 1748,
    SystemZ_LPQ	= 1749,
    SystemZ_LPR	= 1750,
    SystemZ_LPSW	= 1751,
    SystemZ_LPSWE	= 1752,
    SystemZ_LPSWEY	= 1753,
    SystemZ_LPTEA	= 1754,
    SystemZ_LPXBR	= 1755,
    SystemZ_LPXR	= 1756,
    SystemZ_LR	= 1757,
    SystemZ_LRA	= 1758,
    SystemZ_LRAG	= 1759,
    SystemZ_LRAY	= 1760,
    SystemZ_LRDR	= 1761,
    SystemZ_LRER	= 1762,
    SystemZ_LRL	= 1763,
    SystemZ_LRV	= 1764,
    SystemZ_LRVG	= 1765,
    SystemZ_LRVGR	= 1766,
    SystemZ_LRVH	= 1767,
    SystemZ_LRVR	= 1768,
    SystemZ_LSCTL	= 1769,
    SystemZ_LT	= 1770,
    SystemZ_LTDBR	= 1771,
    SystemZ_LTDR	= 1772,
    SystemZ_LTDTR	= 1773,
    SystemZ_LTEBR	= 1774,
    SystemZ_LTER	= 1775,
    SystemZ_LTG	= 1776,
    SystemZ_LTGF	= 1777,
    SystemZ_LTGFR	= 1778,
    SystemZ_LTGR	= 1779,
    SystemZ_LTR	= 1780,
    SystemZ_LTXBR	= 1781,
    SystemZ_LTXR	= 1782,
    SystemZ_LTXTR	= 1783,
    SystemZ_LURA	= 1784,
    SystemZ_LURAG	= 1785,
    SystemZ_LXD	= 1786,
    SystemZ_LXDB	= 1787,
    SystemZ_LXDBR	= 1788,
    SystemZ_LXDR	= 1789,
    SystemZ_LXDTR	= 1790,
    SystemZ_LXE	= 1791,
    SystemZ_LXEB	= 1792,
    SystemZ_LXEBR	= 1793,
    SystemZ_LXER	= 1794,
    SystemZ_LXR	= 1795,
    SystemZ_LY	= 1796,
    SystemZ_LZDR	= 1797,
    SystemZ_LZER	= 1798,
    SystemZ_LZRF	= 1799,
    SystemZ_LZRG	= 1800,
    SystemZ_LZXR	= 1801,
    SystemZ_M	= 1802,
    SystemZ_MAD	= 1803,
    SystemZ_MADB	= 1804,
    SystemZ_MADBR	= 1805,
    SystemZ_MADR	= 1806,
    SystemZ_MAE	= 1807,
    SystemZ_MAEB	= 1808,
    SystemZ_MAEBR	= 1809,
    SystemZ_MAER	= 1810,
    SystemZ_MAY	= 1811,
    SystemZ_MAYH	= 1812,
    SystemZ_MAYHR	= 1813,
    SystemZ_MAYL	= 1814,
    SystemZ_MAYLR	= 1815,
    SystemZ_MAYR	= 1816,
    SystemZ_MC	= 1817,
    SystemZ_MD	= 1818,
    SystemZ_MDB	= 1819,
    SystemZ_MDBR	= 1820,
    SystemZ_MDE	= 1821,
    SystemZ_MDEB	= 1822,
    SystemZ_MDEBR	= 1823,
    SystemZ_MDER	= 1824,
    SystemZ_MDR	= 1825,
    SystemZ_MDTR	= 1826,
    SystemZ_MDTRA	= 1827,
    SystemZ_ME	= 1828,
    SystemZ_MEE	= 1829,
    SystemZ_MEEB	= 1830,
    SystemZ_MEEBR	= 1831,
    SystemZ_MEER	= 1832,
    SystemZ_MER	= 1833,
    SystemZ_MFY	= 1834,
    SystemZ_MG	= 1835,
    SystemZ_MGH	= 1836,
    SystemZ_MGHI	= 1837,
    SystemZ_MGRK	= 1838,
    SystemZ_MH	= 1839,
    SystemZ_MHI	= 1840,
    SystemZ_MHY	= 1841,
    SystemZ_ML	= 1842,
    SystemZ_MLG	= 1843,
    SystemZ_MLGR	= 1844,
    SystemZ_MLR	= 1845,
    SystemZ_MP	= 1846,
    SystemZ_MR	= 1847,
    SystemZ_MS	= 1848,
    SystemZ_MSC	= 1849,
    SystemZ_MSCH	= 1850,
    SystemZ_MSD	= 1851,
    SystemZ_MSDB	= 1852,
    SystemZ_MSDBR	= 1853,
    SystemZ_MSDR	= 1854,
    SystemZ_MSE	= 1855,
    SystemZ_MSEB	= 1856,
    SystemZ_MSEBR	= 1857,
    SystemZ_MSER	= 1858,
    SystemZ_MSFI	= 1859,
    SystemZ_MSG	= 1860,
    SystemZ_MSGC	= 1861,
    SystemZ_MSGF	= 1862,
    SystemZ_MSGFI	= 1863,
    SystemZ_MSGFR	= 1864,
    SystemZ_MSGR	= 1865,
    SystemZ_MSGRKC	= 1866,
    SystemZ_MSR	= 1867,
    SystemZ_MSRKC	= 1868,
    SystemZ_MSTA	= 1869,
    SystemZ_MSY	= 1870,
    SystemZ_MVC	= 1871,
    SystemZ_MVCDK	= 1872,
    SystemZ_MVCIN	= 1873,
    SystemZ_MVCK	= 1874,
    SystemZ_MVCL	= 1875,
    SystemZ_MVCLE	= 1876,
    SystemZ_MVCLU	= 1877,
    SystemZ_MVCOS	= 1878,
    SystemZ_MVCP	= 1879,
    SystemZ_MVCRL	= 1880,
    SystemZ_MVCS	= 1881,
    SystemZ_MVCSK	= 1882,
    SystemZ_MVGHI	= 1883,
    SystemZ_MVHHI	= 1884,
    SystemZ_MVHI	= 1885,
    SystemZ_MVI	= 1886,
    SystemZ_MVIY	= 1887,
    SystemZ_MVN	= 1888,
    SystemZ_MVO	= 1889,
    SystemZ_MVPG	= 1890,
    SystemZ_MVST	= 1891,
    SystemZ_MVZ	= 1892,
    SystemZ_MXBR	= 1893,
    SystemZ_MXD	= 1894,
    SystemZ_MXDB	= 1895,
    SystemZ_MXDBR	= 1896,
    SystemZ_MXDR	= 1897,
    SystemZ_MXR	= 1898,
    SystemZ_MXTR	= 1899,
    SystemZ_MXTRA	= 1900,
    SystemZ_MY	= 1901,
    SystemZ_MYH	= 1902,
    SystemZ_MYHR	= 1903,
    SystemZ_MYL	= 1904,
    SystemZ_MYLR	= 1905,
    SystemZ_MYR	= 1906,
    SystemZ_N	= 1907,
    SystemZ_NC	= 1908,
    SystemZ_NCGRK	= 1909,
    SystemZ_NCRK	= 1910,
    SystemZ_NG	= 1911,
    SystemZ_NGR	= 1912,
    SystemZ_NGRK	= 1913,
    SystemZ_NI	= 1914,
    SystemZ_NIAI	= 1915,
    SystemZ_NIHF	= 1916,
    SystemZ_NIHH	= 1917,
    SystemZ_NIHL	= 1918,
    SystemZ_NILF	= 1919,
    SystemZ_NILH	= 1920,
    SystemZ_NILL	= 1921,
    SystemZ_NIY	= 1922,
    SystemZ_NNGRK	= 1923,
    SystemZ_NNPA	= 1924,
    SystemZ_NNRK	= 1925,
    SystemZ_NOGRK	= 1926,
    SystemZ_NOP_bare	= 1927,
    SystemZ_NORK	= 1928,
    SystemZ_NR	= 1929,
    SystemZ_NRK	= 1930,
    SystemZ_NTSTG	= 1931,
    SystemZ_NXGRK	= 1932,
    SystemZ_NXRK	= 1933,
    SystemZ_NY	= 1934,
    SystemZ_O	= 1935,
    SystemZ_OC	= 1936,
    SystemZ_OCGRK	= 1937,
    SystemZ_OCRK	= 1938,
    SystemZ_OG	= 1939,
    SystemZ_OGR	= 1940,
    SystemZ_OGRK	= 1941,
    SystemZ_OI	= 1942,
    SystemZ_OIHF	= 1943,
    SystemZ_OIHH	= 1944,
    SystemZ_OIHL	= 1945,
    SystemZ_OILF	= 1946,
    SystemZ_OILH	= 1947,
    SystemZ_OILL	= 1948,
    SystemZ_OIY	= 1949,
    SystemZ_OR	= 1950,
    SystemZ_ORK	= 1951,
    SystemZ_OY	= 1952,
    SystemZ_PACK	= 1953,
    SystemZ_PALB	= 1954,
    SystemZ_PC	= 1955,
    SystemZ_PCC	= 1956,
    SystemZ_PCKMO	= 1957,
    SystemZ_PFD	= 1958,
    SystemZ_PFDRL	= 1959,
    SystemZ_PFMF	= 1960,
    SystemZ_PFPO	= 1961,
    SystemZ_PGIN	= 1962,
    SystemZ_PGOUT	= 1963,
    SystemZ_PKA	= 1964,
    SystemZ_PKU	= 1965,
    SystemZ_PLO	= 1966,
    SystemZ_POPCNT	= 1967,
    SystemZ_POPCNTOpt	= 1968,
    SystemZ_PPA	= 1969,
    SystemZ_PPNO	= 1970,
    SystemZ_PR	= 1971,
    SystemZ_PRNO	= 1972,
    SystemZ_PT	= 1973,
    SystemZ_PTF	= 1974,
    SystemZ_PTFF	= 1975,
    SystemZ_PTI	= 1976,
    SystemZ_PTLB	= 1977,
    SystemZ_QADTR	= 1978,
    SystemZ_QAXTR	= 1979,
    SystemZ_QCTRI	= 1980,
    SystemZ_QPACI	= 1981,
    SystemZ_QSI	= 1982,
    SystemZ_RCHP	= 1983,
    SystemZ_RDP	= 1984,
    SystemZ_RDPOpt	= 1985,
    SystemZ_RISBG	= 1986,
    SystemZ_RISBG32	= 1987,
    SystemZ_RISBGN	= 1988,
    SystemZ_RISBHG	= 1989,
    SystemZ_RISBLG	= 1990,
    SystemZ_RLL	= 1991,
    SystemZ_RLLG	= 1992,
    SystemZ_RNSBG	= 1993,
    SystemZ_ROSBG	= 1994,
    SystemZ_RP	= 1995,
    SystemZ_RRBE	= 1996,
    SystemZ_RRBM	= 1997,
    SystemZ_RRDTR	= 1998,
    SystemZ_RRXTR	= 1999,
    SystemZ_RSCH	= 2000,
    SystemZ_RXSBG	= 2001,
    SystemZ_S	= 2002,
    SystemZ_SAC	= 2003,
    SystemZ_SACF	= 2004,
    SystemZ_SAL	= 2005,
    SystemZ_SAM24	= 2006,
    SystemZ_SAM31	= 2007,
    SystemZ_SAM64	= 2008,
    SystemZ_SAR	= 2009,
    SystemZ_SCCTR	= 2010,
    SystemZ_SCHM	= 2011,
    SystemZ_SCK	= 2012,
    SystemZ_SCKC	= 2013,
    SystemZ_SCKPF	= 2014,
    SystemZ_SD	= 2015,
    SystemZ_SDB	= 2016,
    SystemZ_SDBR	= 2017,
    SystemZ_SDR	= 2018,
    SystemZ_SDTR	= 2019,
    SystemZ_SDTRA	= 2020,
    SystemZ_SE	= 2021,
    SystemZ_SEB	= 2022,
    SystemZ_SEBR	= 2023,
    SystemZ_SELFHR	= 2024,
    SystemZ_SELFHRAsm	= 2025,
    SystemZ_SELFHRAsmE	= 2026,
    SystemZ_SELFHRAsmH	= 2027,
    SystemZ_SELFHRAsmHE	= 2028,
    SystemZ_SELFHRAsmL	= 2029,
    SystemZ_SELFHRAsmLE	= 2030,
    SystemZ_SELFHRAsmLH	= 2031,
    SystemZ_SELFHRAsmM	= 2032,
    SystemZ_SELFHRAsmNE	= 2033,
    SystemZ_SELFHRAsmNH	= 2034,
    SystemZ_SELFHRAsmNHE	= 2035,
    SystemZ_SELFHRAsmNL	= 2036,
    SystemZ_SELFHRAsmNLE	= 2037,
    SystemZ_SELFHRAsmNLH	= 2038,
    SystemZ_SELFHRAsmNM	= 2039,
    SystemZ_SELFHRAsmNO	= 2040,
    SystemZ_SELFHRAsmNP	= 2041,
    SystemZ_SELFHRAsmNZ	= 2042,
    SystemZ_SELFHRAsmO	= 2043,
    SystemZ_SELFHRAsmP	= 2044,
    SystemZ_SELFHRAsmZ	= 2045,
    SystemZ_SELGR	= 2046,
    SystemZ_SELGRAsm	= 2047,
    SystemZ_SELGRAsmE	= 2048,
    SystemZ_SELGRAsmH	= 2049,
    SystemZ_SELGRAsmHE	= 2050,
    SystemZ_SELGRAsmL	= 2051,
    SystemZ_SELGRAsmLE	= 2052,
    SystemZ_SELGRAsmLH	= 2053,
    SystemZ_SELGRAsmM	= 2054,
    SystemZ_SELGRAsmNE	= 2055,
    SystemZ_SELGRAsmNH	= 2056,
    SystemZ_SELGRAsmNHE	= 2057,
    SystemZ_SELGRAsmNL	= 2058,
    SystemZ_SELGRAsmNLE	= 2059,
    SystemZ_SELGRAsmNLH	= 2060,
    SystemZ_SELGRAsmNM	= 2061,
    SystemZ_SELGRAsmNO	= 2062,
    SystemZ_SELGRAsmNP	= 2063,
    SystemZ_SELGRAsmNZ	= 2064,
    SystemZ_SELGRAsmO	= 2065,
    SystemZ_SELGRAsmP	= 2066,
    SystemZ_SELGRAsmZ	= 2067,
    SystemZ_SELR	= 2068,
    SystemZ_SELRAsm	= 2069,
    SystemZ_SELRAsmE	= 2070,
    SystemZ_SELRAsmH	= 2071,
    SystemZ_SELRAsmHE	= 2072,
    SystemZ_SELRAsmL	= 2073,
    SystemZ_SELRAsmLE	= 2074,
    SystemZ_SELRAsmLH	= 2075,
    SystemZ_SELRAsmM	= 2076,
    SystemZ_SELRAsmNE	= 2077,
    SystemZ_SELRAsmNH	= 2078,
    SystemZ_SELRAsmNHE	= 2079,
    SystemZ_SELRAsmNL	= 2080,
    SystemZ_SELRAsmNLE	= 2081,
    SystemZ_SELRAsmNLH	= 2082,
    SystemZ_SELRAsmNM	= 2083,
    SystemZ_SELRAsmNO	= 2084,
    SystemZ_SELRAsmNP	= 2085,
    SystemZ_SELRAsmNZ	= 2086,
    SystemZ_SELRAsmO	= 2087,
    SystemZ_SELRAsmP	= 2088,
    SystemZ_SELRAsmZ	= 2089,
    SystemZ_SER	= 2090,
    SystemZ_SFASR	= 2091,
    SystemZ_SFPC	= 2092,
    SystemZ_SG	= 2093,
    SystemZ_SGF	= 2094,
    SystemZ_SGFR	= 2095,
    SystemZ_SGH	= 2096,
    SystemZ_SGR	= 2097,
    SystemZ_SGRK	= 2098,
    SystemZ_SH	= 2099,
    SystemZ_SHHHR	= 2100,
    SystemZ_SHHLR	= 2101,
    SystemZ_SHY	= 2102,
    SystemZ_SIE	= 2103,
    SystemZ_SIGA	= 2104,
    SystemZ_SIGP	= 2105,
    SystemZ_SL	= 2106,
    SystemZ_SLA	= 2107,
    SystemZ_SLAG	= 2108,
    SystemZ_SLAK	= 2109,
    SystemZ_SLB	= 2110,
    SystemZ_SLBG	= 2111,
    SystemZ_SLBGR	= 2112,
    SystemZ_SLBR	= 2113,
    SystemZ_SLDA	= 2114,
    SystemZ_SLDL	= 2115,
    SystemZ_SLDT	= 2116,
    SystemZ_SLFI	= 2117,
    SystemZ_SLG	= 2118,
    SystemZ_SLGF	= 2119,
    SystemZ_SLGFI	= 2120,
    SystemZ_SLGFR	= 2121,
    SystemZ_SLGR	= 2122,
    SystemZ_SLGRK	= 2123,
    SystemZ_SLHHHR	= 2124,
    SystemZ_SLHHLR	= 2125,
    SystemZ_SLL	= 2126,
    SystemZ_SLLG	= 2127,
    SystemZ_SLLK	= 2128,
    SystemZ_SLR	= 2129,
    SystemZ_SLRK	= 2130,
    SystemZ_SLXT	= 2131,
    SystemZ_SLY	= 2132,
    SystemZ_SORTL	= 2133,
    SystemZ_SP	= 2134,
    SystemZ_SPCTR	= 2135,
    SystemZ_SPKA	= 2136,
    SystemZ_SPM	= 2137,
    SystemZ_SPT	= 2138,
    SystemZ_SPX	= 2139,
    SystemZ_SQD	= 2140,
    SystemZ_SQDB	= 2141,
    SystemZ_SQDBR	= 2142,
    SystemZ_SQDR	= 2143,
    SystemZ_SQE	= 2144,
    SystemZ_SQEB	= 2145,
    SystemZ_SQEBR	= 2146,
    SystemZ_SQER	= 2147,
    SystemZ_SQXBR	= 2148,
    SystemZ_SQXR	= 2149,
    SystemZ_SR	= 2150,
    SystemZ_SRA	= 2151,
    SystemZ_SRAG	= 2152,
    SystemZ_SRAK	= 2153,
    SystemZ_SRDA	= 2154,
    SystemZ_SRDL	= 2155,
    SystemZ_SRDT	= 2156,
    SystemZ_SRK	= 2157,
    SystemZ_SRL	= 2158,
    SystemZ_SRLG	= 2159,
    SystemZ_SRLK	= 2160,
    SystemZ_SRNM	= 2161,
    SystemZ_SRNMB	= 2162,
    SystemZ_SRNMT	= 2163,
    SystemZ_SRP	= 2164,
    SystemZ_SRST	= 2165,
    SystemZ_SRSTU	= 2166,
    SystemZ_SRXT	= 2167,
    SystemZ_SSAIR	= 2168,
    SystemZ_SSAR	= 2169,
    SystemZ_SSCH	= 2170,
    SystemZ_SSKE	= 2171,
    SystemZ_SSKEOpt	= 2172,
    SystemZ_SSM	= 2173,
    SystemZ_ST	= 2174,
    SystemZ_STAM	= 2175,
    SystemZ_STAMY	= 2176,
    SystemZ_STAP	= 2177,
    SystemZ_STBEAR	= 2178,
    SystemZ_STC	= 2179,
    SystemZ_STCH	= 2180,
    SystemZ_STCK	= 2181,
    SystemZ_STCKC	= 2182,
    SystemZ_STCKE	= 2183,
    SystemZ_STCKF	= 2184,
    SystemZ_STCM	= 2185,
    SystemZ_STCMH	= 2186,
    SystemZ_STCMY	= 2187,
    SystemZ_STCPS	= 2188,
    SystemZ_STCRW	= 2189,
    SystemZ_STCTG	= 2190,
    SystemZ_STCTL	= 2191,
    SystemZ_STCY	= 2192,
    SystemZ_STD	= 2193,
    SystemZ_STDY	= 2194,
    SystemZ_STE	= 2195,
    SystemZ_STEY	= 2196,
    SystemZ_STFH	= 2197,
    SystemZ_STFL	= 2198,
    SystemZ_STFLE	= 2199,
    SystemZ_STFPC	= 2200,
    SystemZ_STG	= 2201,
    SystemZ_STGRL	= 2202,
    SystemZ_STGSC	= 2203,
    SystemZ_STH	= 2204,
    SystemZ_STHH	= 2205,
    SystemZ_STHRL	= 2206,
    SystemZ_STHY	= 2207,
    SystemZ_STIDP	= 2208,
    SystemZ_STM	= 2209,
    SystemZ_STMG	= 2210,
    SystemZ_STMH	= 2211,
    SystemZ_STMY	= 2212,
    SystemZ_STNSM	= 2213,
    SystemZ_STOC	= 2214,
    SystemZ_STOCAsm	= 2215,
    SystemZ_STOCAsmE	= 2216,
    SystemZ_STOCAsmH	= 2217,
    SystemZ_STOCAsmHE	= 2218,
    SystemZ_STOCAsmL	= 2219,
    SystemZ_STOCAsmLE	= 2220,
    SystemZ_STOCAsmLH	= 2221,
    SystemZ_STOCAsmM	= 2222,
    SystemZ_STOCAsmNE	= 2223,
    SystemZ_STOCAsmNH	= 2224,
    SystemZ_STOCAsmNHE	= 2225,
    SystemZ_STOCAsmNL	= 2226,
    SystemZ_STOCAsmNLE	= 2227,
    SystemZ_STOCAsmNLH	= 2228,
    SystemZ_STOCAsmNM	= 2229,
    SystemZ_STOCAsmNO	= 2230,
    SystemZ_STOCAsmNP	= 2231,
    SystemZ_STOCAsmNZ	= 2232,
    SystemZ_STOCAsmO	= 2233,
    SystemZ_STOCAsmP	= 2234,
    SystemZ_STOCAsmZ	= 2235,
    SystemZ_STOCFH	= 2236,
    SystemZ_STOCFHAsm	= 2237,
    SystemZ_STOCFHAsmE	= 2238,
    SystemZ_STOCFHAsmH	= 2239,
    SystemZ_STOCFHAsmHE	= 2240,
    SystemZ_STOCFHAsmL	= 2241,
    SystemZ_STOCFHAsmLE	= 2242,
    SystemZ_STOCFHAsmLH	= 2243,
    SystemZ_STOCFHAsmM	= 2244,
    SystemZ_STOCFHAsmNE	= 2245,
    SystemZ_STOCFHAsmNH	= 2246,
    SystemZ_STOCFHAsmNHE	= 2247,
    SystemZ_STOCFHAsmNL	= 2248,
    SystemZ_STOCFHAsmNLE	= 2249,
    SystemZ_STOCFHAsmNLH	= 2250,
    SystemZ_STOCFHAsmNM	= 2251,
    SystemZ_STOCFHAsmNO	= 2252,
    SystemZ_STOCFHAsmNP	= 2253,
    SystemZ_STOCFHAsmNZ	= 2254,
    SystemZ_STOCFHAsmO	= 2255,
    SystemZ_STOCFHAsmP	= 2256,
    SystemZ_STOCFHAsmZ	= 2257,
    SystemZ_STOCG	= 2258,
    SystemZ_STOCGAsm	= 2259,
    SystemZ_STOCGAsmE	= 2260,
    SystemZ_STOCGAsmH	= 2261,
    SystemZ_STOCGAsmHE	= 2262,
    SystemZ_STOCGAsmL	= 2263,
    SystemZ_STOCGAsmLE	= 2264,
    SystemZ_STOCGAsmLH	= 2265,
    SystemZ_STOCGAsmM	= 2266,
    SystemZ_STOCGAsmNE	= 2267,
    SystemZ_STOCGAsmNH	= 2268,
    SystemZ_STOCGAsmNHE	= 2269,
    SystemZ_STOCGAsmNL	= 2270,
    SystemZ_STOCGAsmNLE	= 2271,
    SystemZ_STOCGAsmNLH	= 2272,
    SystemZ_STOCGAsmNM	= 2273,
    SystemZ_STOCGAsmNO	= 2274,
    SystemZ_STOCGAsmNP	= 2275,
    SystemZ_STOCGAsmNZ	= 2276,
    SystemZ_STOCGAsmO	= 2277,
    SystemZ_STOCGAsmP	= 2278,
    SystemZ_STOCGAsmZ	= 2279,
    SystemZ_STOSM	= 2280,
    SystemZ_STPQ	= 2281,
    SystemZ_STPT	= 2282,
    SystemZ_STPX	= 2283,
    SystemZ_STRAG	= 2284,
    SystemZ_STRL	= 2285,
    SystemZ_STRV	= 2286,
    SystemZ_STRVG	= 2287,
    SystemZ_STRVH	= 2288,
    SystemZ_STSCH	= 2289,
    SystemZ_STSI	= 2290,
    SystemZ_STURA	= 2291,
    SystemZ_STURG	= 2292,
    SystemZ_STY	= 2293,
    SystemZ_SU	= 2294,
    SystemZ_SUR	= 2295,
    SystemZ_SVC	= 2296,
    SystemZ_SW	= 2297,
    SystemZ_SWR	= 2298,
    SystemZ_SXBR	= 2299,
    SystemZ_SXR	= 2300,
    SystemZ_SXTR	= 2301,
    SystemZ_SXTRA	= 2302,
    SystemZ_SY	= 2303,
    SystemZ_TABORT	= 2304,
    SystemZ_TAM	= 2305,
    SystemZ_TAR	= 2306,
    SystemZ_TB	= 2307,
    SystemZ_TBDR	= 2308,
    SystemZ_TBEDR	= 2309,
    SystemZ_TBEGIN	= 2310,
    SystemZ_TBEGINC	= 2311,
    SystemZ_TCDB	= 2312,
    SystemZ_TCEB	= 2313,
    SystemZ_TCXB	= 2314,
    SystemZ_TDCDT	= 2315,
    SystemZ_TDCET	= 2316,
    SystemZ_TDCXT	= 2317,
    SystemZ_TDGDT	= 2318,
    SystemZ_TDGET	= 2319,
    SystemZ_TDGXT	= 2320,
    SystemZ_TEND	= 2321,
    SystemZ_THDER	= 2322,
    SystemZ_THDR	= 2323,
    SystemZ_TM	= 2324,
    SystemZ_TMHH	= 2325,
    SystemZ_TMHL	= 2326,
    SystemZ_TMLH	= 2327,
    SystemZ_TMLL	= 2328,
    SystemZ_TMY	= 2329,
    SystemZ_TP	= 2330,
    SystemZ_TPI	= 2331,
    SystemZ_TPROT	= 2332,
    SystemZ_TR	= 2333,
    SystemZ_TRACE	= 2334,
    SystemZ_TRACG	= 2335,
    SystemZ_TRAP2	= 2336,
    SystemZ_TRAP4	= 2337,
    SystemZ_TRE	= 2338,
    SystemZ_TROO	= 2339,
    SystemZ_TROOOpt	= 2340,
    SystemZ_TROT	= 2341,
    SystemZ_TROTOpt	= 2342,
    SystemZ_TRT	= 2343,
    SystemZ_TRTE	= 2344,
    SystemZ_TRTEOpt	= 2345,
    SystemZ_TRTO	= 2346,
    SystemZ_TRTOOpt	= 2347,
    SystemZ_TRTR	= 2348,
    SystemZ_TRTRE	= 2349,
    SystemZ_TRTREOpt	= 2350,
    SystemZ_TRTT	= 2351,
    SystemZ_TRTTOpt	= 2352,
    SystemZ_TS	= 2353,
    SystemZ_TSCH	= 2354,
    SystemZ_UNPK	= 2355,
    SystemZ_UNPKA	= 2356,
    SystemZ_UNPKU	= 2357,
    SystemZ_UPT	= 2358,
    SystemZ_VA	= 2359,
    SystemZ_VAB	= 2360,
    SystemZ_VAC	= 2361,
    SystemZ_VACC	= 2362,
    SystemZ_VACCB	= 2363,
    SystemZ_VACCC	= 2364,
    SystemZ_VACCCQ	= 2365,
    SystemZ_VACCF	= 2366,
    SystemZ_VACCG	= 2367,
    SystemZ_VACCH	= 2368,
    SystemZ_VACCQ	= 2369,
    SystemZ_VACQ	= 2370,
    SystemZ_VAF	= 2371,
    SystemZ_VAG	= 2372,
    SystemZ_VAH	= 2373,
    SystemZ_VAP	= 2374,
    SystemZ_VAQ	= 2375,
    SystemZ_VAVG	= 2376,
    SystemZ_VAVGB	= 2377,
    SystemZ_VAVGF	= 2378,
    SystemZ_VAVGG	= 2379,
    SystemZ_VAVGH	= 2380,
    SystemZ_VAVGL	= 2381,
    SystemZ_VAVGLB	= 2382,
    SystemZ_VAVGLF	= 2383,
    SystemZ_VAVGLG	= 2384,
    SystemZ_VAVGLH	= 2385,
    SystemZ_VBPERM	= 2386,
    SystemZ_VCDG	= 2387,
    SystemZ_VCDGB	= 2388,
    SystemZ_VCDLG	= 2389,
    SystemZ_VCDLGB	= 2390,
    SystemZ_VCEFB	= 2391,
    SystemZ_VCELFB	= 2392,
    SystemZ_VCEQ	= 2393,
    SystemZ_VCEQB	= 2394,
    SystemZ_VCEQBS	= 2395,
    SystemZ_VCEQF	= 2396,
    SystemZ_VCEQFS	= 2397,
    SystemZ_VCEQG	= 2398,
    SystemZ_VCEQGS	= 2399,
    SystemZ_VCEQH	= 2400,
    SystemZ_VCEQHS	= 2401,
    SystemZ_VCFEB	= 2402,
    SystemZ_VCFN	= 2403,
    SystemZ_VCFPL	= 2404,
    SystemZ_VCFPS	= 2405,
    SystemZ_VCGD	= 2406,
    SystemZ_VCGDB	= 2407,
    SystemZ_VCH	= 2408,
    SystemZ_VCHB	= 2409,
    SystemZ_VCHBS	= 2410,
    SystemZ_VCHF	= 2411,
    SystemZ_VCHFS	= 2412,
    SystemZ_VCHG	= 2413,
    SystemZ_VCHGS	= 2414,
    SystemZ_VCHH	= 2415,
    SystemZ_VCHHS	= 2416,
    SystemZ_VCHL	= 2417,
    SystemZ_VCHLB	= 2418,
    SystemZ_VCHLBS	= 2419,
    SystemZ_VCHLF	= 2420,
    SystemZ_VCHLFS	= 2421,
    SystemZ_VCHLG	= 2422,
    SystemZ_VCHLGS	= 2423,
    SystemZ_VCHLH	= 2424,
    SystemZ_VCHLHS	= 2425,
    SystemZ_VCKSM	= 2426,
    SystemZ_VCLFEB	= 2427,
    SystemZ_VCLFNH	= 2428,
    SystemZ_VCLFNL	= 2429,
    SystemZ_VCLFP	= 2430,
    SystemZ_VCLGD	= 2431,
    SystemZ_VCLGDB	= 2432,
    SystemZ_VCLZ	= 2433,
    SystemZ_VCLZB	= 2434,
    SystemZ_VCLZDP	= 2435,
    SystemZ_VCLZF	= 2436,
    SystemZ_VCLZG	= 2437,
    SystemZ_VCLZH	= 2438,
    SystemZ_VCNF	= 2439,
    SystemZ_VCP	= 2440,
    SystemZ_VCRNF	= 2441,
    SystemZ_VCSFP	= 2442,
    SystemZ_VCSPH	= 2443,
    SystemZ_VCTZ	= 2444,
    SystemZ_VCTZB	= 2445,
    SystemZ_VCTZF	= 2446,
    SystemZ_VCTZG	= 2447,
    SystemZ_VCTZH	= 2448,
    SystemZ_VCVB	= 2449,
    SystemZ_VCVBG	= 2450,
    SystemZ_VCVBGOpt	= 2451,
    SystemZ_VCVBOpt	= 2452,
    SystemZ_VCVD	= 2453,
    SystemZ_VCVDG	= 2454,
    SystemZ_VDP	= 2455,
    SystemZ_VEC	= 2456,
    SystemZ_VECB	= 2457,
    SystemZ_VECF	= 2458,
    SystemZ_VECG	= 2459,
    SystemZ_VECH	= 2460,
    SystemZ_VECL	= 2461,
    SystemZ_VECLB	= 2462,
    SystemZ_VECLF	= 2463,
    SystemZ_VECLG	= 2464,
    SystemZ_VECLH	= 2465,
    SystemZ_VERIM	= 2466,
    SystemZ_VERIMB	= 2467,
    SystemZ_VERIMF	= 2468,
    SystemZ_VERIMG	= 2469,
    SystemZ_VERIMH	= 2470,
    SystemZ_VERLL	= 2471,
    SystemZ_VERLLB	= 2472,
    SystemZ_VERLLF	= 2473,
    SystemZ_VERLLG	= 2474,
    SystemZ_VERLLH	= 2475,
    SystemZ_VERLLV	= 2476,
    SystemZ_VERLLVB	= 2477,
    SystemZ_VERLLVF	= 2478,
    SystemZ_VERLLVG	= 2479,
    SystemZ_VERLLVH	= 2480,
    SystemZ_VESL	= 2481,
    SystemZ_VESLB	= 2482,
    SystemZ_VESLF	= 2483,
    SystemZ_VESLG	= 2484,
    SystemZ_VESLH	= 2485,
    SystemZ_VESLV	= 2486,
    SystemZ_VESLVB	= 2487,
    SystemZ_VESLVF	= 2488,
    SystemZ_VESLVG	= 2489,
    SystemZ_VESLVH	= 2490,
    SystemZ_VESRA	= 2491,
    SystemZ_VESRAB	= 2492,
    SystemZ_VESRAF	= 2493,
    SystemZ_VESRAG	= 2494,
    SystemZ_VESRAH	= 2495,
    SystemZ_VESRAV	= 2496,
    SystemZ_VESRAVB	= 2497,
    SystemZ_VESRAVF	= 2498,
    SystemZ_VESRAVG	= 2499,
    SystemZ_VESRAVH	= 2500,
    SystemZ_VESRL	= 2501,
    SystemZ_VESRLB	= 2502,
    SystemZ_VESRLF	= 2503,
    SystemZ_VESRLG	= 2504,
    SystemZ_VESRLH	= 2505,
    SystemZ_VESRLV	= 2506,
    SystemZ_VESRLVB	= 2507,
    SystemZ_VESRLVF	= 2508,
    SystemZ_VESRLVG	= 2509,
    SystemZ_VESRLVH	= 2510,
    SystemZ_VFA	= 2511,
    SystemZ_VFADB	= 2512,
    SystemZ_VFAE	= 2513,
    SystemZ_VFAEB	= 2514,
    SystemZ_VFAEBS	= 2515,
    SystemZ_VFAEF	= 2516,
    SystemZ_VFAEFS	= 2517,
    SystemZ_VFAEH	= 2518,
    SystemZ_VFAEHS	= 2519,
    SystemZ_VFAEZB	= 2520,
    SystemZ_VFAEZBS	= 2521,
    SystemZ_VFAEZF	= 2522,
    SystemZ_VFAEZFS	= 2523,
    SystemZ_VFAEZH	= 2524,
    SystemZ_VFAEZHS	= 2525,
    SystemZ_VFASB	= 2526,
    SystemZ_VFCE	= 2527,
    SystemZ_VFCEDB	= 2528,
    SystemZ_VFCEDBS	= 2529,
    SystemZ_VFCESB	= 2530,
    SystemZ_VFCESBS	= 2531,
    SystemZ_VFCH	= 2532,
    SystemZ_VFCHDB	= 2533,
    SystemZ_VFCHDBS	= 2534,
    SystemZ_VFCHE	= 2535,
    SystemZ_VFCHEDB	= 2536,
    SystemZ_VFCHEDBS	= 2537,
    SystemZ_VFCHESB	= 2538,
    SystemZ_VFCHESBS	= 2539,
    SystemZ_VFCHSB	= 2540,
    SystemZ_VFCHSBS	= 2541,
    SystemZ_VFD	= 2542,
    SystemZ_VFDDB	= 2543,
    SystemZ_VFDSB	= 2544,
    SystemZ_VFEE	= 2545,
    SystemZ_VFEEB	= 2546,
    SystemZ_VFEEBS	= 2547,
    SystemZ_VFEEF	= 2548,
    SystemZ_VFEEFS	= 2549,
    SystemZ_VFEEH	= 2550,
    SystemZ_VFEEHS	= 2551,
    SystemZ_VFEEZB	= 2552,
    SystemZ_VFEEZBS	= 2553,
    SystemZ_VFEEZF	= 2554,
    SystemZ_VFEEZFS	= 2555,
    SystemZ_VFEEZH	= 2556,
    SystemZ_VFEEZHS	= 2557,
    SystemZ_VFENE	= 2558,
    SystemZ_VFENEB	= 2559,
    SystemZ_VFENEBS	= 2560,
    SystemZ_VFENEF	= 2561,
    SystemZ_VFENEFS	= 2562,
    SystemZ_VFENEH	= 2563,
    SystemZ_VFENEHS	= 2564,
    SystemZ_VFENEZB	= 2565,
    SystemZ_VFENEZBS	= 2566,
    SystemZ_VFENEZF	= 2567,
    SystemZ_VFENEZFS	= 2568,
    SystemZ_VFENEZH	= 2569,
    SystemZ_VFENEZHS	= 2570,
    SystemZ_VFI	= 2571,
    SystemZ_VFIDB	= 2572,
    SystemZ_VFISB	= 2573,
    SystemZ_VFKEDB	= 2574,
    SystemZ_VFKEDBS	= 2575,
    SystemZ_VFKESB	= 2576,
    SystemZ_VFKESBS	= 2577,
    SystemZ_VFKHDB	= 2578,
    SystemZ_VFKHDBS	= 2579,
    SystemZ_VFKHEDB	= 2580,
    SystemZ_VFKHEDBS	= 2581,
    SystemZ_VFKHESB	= 2582,
    SystemZ_VFKHESBS	= 2583,
    SystemZ_VFKHSB	= 2584,
    SystemZ_VFKHSBS	= 2585,
    SystemZ_VFLCDB	= 2586,
    SystemZ_VFLCSB	= 2587,
    SystemZ_VFLL	= 2588,
    SystemZ_VFLLS	= 2589,
    SystemZ_VFLNDB	= 2590,
    SystemZ_VFLNSB	= 2591,
    SystemZ_VFLPDB	= 2592,
    SystemZ_VFLPSB	= 2593,
    SystemZ_VFLR	= 2594,
    SystemZ_VFLRD	= 2595,
    SystemZ_VFM	= 2596,
    SystemZ_VFMA	= 2597,
    SystemZ_VFMADB	= 2598,
    SystemZ_VFMASB	= 2599,
    SystemZ_VFMAX	= 2600,
    SystemZ_VFMAXDB	= 2601,
    SystemZ_VFMAXSB	= 2602,
    SystemZ_VFMDB	= 2603,
    SystemZ_VFMIN	= 2604,
    SystemZ_VFMINDB	= 2605,
    SystemZ_VFMINSB	= 2606,
    SystemZ_VFMS	= 2607,
    SystemZ_VFMSB	= 2608,
    SystemZ_VFMSDB	= 2609,
    SystemZ_VFMSSB	= 2610,
    SystemZ_VFNMA	= 2611,
    SystemZ_VFNMADB	= 2612,
    SystemZ_VFNMASB	= 2613,
    SystemZ_VFNMS	= 2614,
    SystemZ_VFNMSDB	= 2615,
    SystemZ_VFNMSSB	= 2616,
    SystemZ_VFPSO	= 2617,
    SystemZ_VFPSODB	= 2618,
    SystemZ_VFPSOSB	= 2619,
    SystemZ_VFS	= 2620,
    SystemZ_VFSDB	= 2621,
    SystemZ_VFSQ	= 2622,
    SystemZ_VFSQDB	= 2623,
    SystemZ_VFSQSB	= 2624,
    SystemZ_VFSSB	= 2625,
    SystemZ_VFTCI	= 2626,
    SystemZ_VFTCIDB	= 2627,
    SystemZ_VFTCISB	= 2628,
    SystemZ_VGBM	= 2629,
    SystemZ_VGEF	= 2630,
    SystemZ_VGEG	= 2631,
    SystemZ_VGFM	= 2632,
    SystemZ_VGFMA	= 2633,
    SystemZ_VGFMAB	= 2634,
    SystemZ_VGFMAF	= 2635,
    SystemZ_VGFMAG	= 2636,
    SystemZ_VGFMAH	= 2637,
    SystemZ_VGFMB	= 2638,
    SystemZ_VGFMF	= 2639,
    SystemZ_VGFMG	= 2640,
    SystemZ_VGFMH	= 2641,
    SystemZ_VGM	= 2642,
    SystemZ_VGMB	= 2643,
    SystemZ_VGMF	= 2644,
    SystemZ_VGMG	= 2645,
    SystemZ_VGMH	= 2646,
    SystemZ_VISTR	= 2647,
    SystemZ_VISTRB	= 2648,
    SystemZ_VISTRBS	= 2649,
    SystemZ_VISTRF	= 2650,
    SystemZ_VISTRFS	= 2651,
    SystemZ_VISTRH	= 2652,
    SystemZ_VISTRHS	= 2653,
    SystemZ_VL	= 2654,
    SystemZ_VLAlign	= 2655,
    SystemZ_VLBB	= 2656,
    SystemZ_VLBR	= 2657,
    SystemZ_VLBRF	= 2658,
    SystemZ_VLBRG	= 2659,
    SystemZ_VLBRH	= 2660,
    SystemZ_VLBRQ	= 2661,
    SystemZ_VLBRREP	= 2662,
    SystemZ_VLBRREPF	= 2663,
    SystemZ_VLBRREPG	= 2664,
    SystemZ_VLBRREPH	= 2665,
    SystemZ_VLC	= 2666,
    SystemZ_VLCB	= 2667,
    SystemZ_VLCF	= 2668,
    SystemZ_VLCG	= 2669,
    SystemZ_VLCH	= 2670,
    SystemZ_VLDE	= 2671,
    SystemZ_VLDEB	= 2672,
    SystemZ_VLEB	= 2673,
    SystemZ_VLEBRF	= 2674,
    SystemZ_VLEBRG	= 2675,
    SystemZ_VLEBRH	= 2676,
    SystemZ_VLED	= 2677,
    SystemZ_VLEDB	= 2678,
    SystemZ_VLEF	= 2679,
    SystemZ_VLEG	= 2680,
    SystemZ_VLEH	= 2681,
    SystemZ_VLEIB	= 2682,
    SystemZ_VLEIF	= 2683,
    SystemZ_VLEIG	= 2684,
    SystemZ_VLEIH	= 2685,
    SystemZ_VLER	= 2686,
    SystemZ_VLERF	= 2687,
    SystemZ_VLERG	= 2688,
    SystemZ_VLERH	= 2689,
    SystemZ_VLGV	= 2690,
    SystemZ_VLGVB	= 2691,
    SystemZ_VLGVF	= 2692,
    SystemZ_VLGVG	= 2693,
    SystemZ_VLGVH	= 2694,
    SystemZ_VLIP	= 2695,
    SystemZ_VLL	= 2696,
    SystemZ_VLLEBRZ	= 2697,
    SystemZ_VLLEBRZE	= 2698,
    SystemZ_VLLEBRZF	= 2699,
    SystemZ_VLLEBRZG	= 2700,
    SystemZ_VLLEBRZH	= 2701,
    SystemZ_VLLEZ	= 2702,
    SystemZ_VLLEZB	= 2703,
    SystemZ_VLLEZF	= 2704,
    SystemZ_VLLEZG	= 2705,
    SystemZ_VLLEZH	= 2706,
    SystemZ_VLLEZLF	= 2707,
    SystemZ_VLM	= 2708,
    SystemZ_VLMAlign	= 2709,
    SystemZ_VLP	= 2710,
    SystemZ_VLPB	= 2711,
    SystemZ_VLPF	= 2712,
    SystemZ_VLPG	= 2713,
    SystemZ_VLPH	= 2714,
    SystemZ_VLR	= 2715,
    SystemZ_VLREP	= 2716,
    SystemZ_VLREPB	= 2717,
    SystemZ_VLREPF	= 2718,
    SystemZ_VLREPG	= 2719,
    SystemZ_VLREPH	= 2720,
    SystemZ_VLRL	= 2721,
    SystemZ_VLRLR	= 2722,
    SystemZ_VLVG	= 2723,
    SystemZ_VLVGB	= 2724,
    SystemZ_VLVGF	= 2725,
    SystemZ_VLVGG	= 2726,
    SystemZ_VLVGH	= 2727,
    SystemZ_VLVGP	= 2728,
    SystemZ_VMAE	= 2729,
    SystemZ_VMAEB	= 2730,
    SystemZ_VMAEF	= 2731,
    SystemZ_VMAEH	= 2732,
    SystemZ_VMAH	= 2733,
    SystemZ_VMAHB	= 2734,
    SystemZ_VMAHF	= 2735,
    SystemZ_VMAHH	= 2736,
    SystemZ_VMAL	= 2737,
    SystemZ_VMALB	= 2738,
    SystemZ_VMALE	= 2739,
    SystemZ_VMALEB	= 2740,
    SystemZ_VMALEF	= 2741,
    SystemZ_VMALEH	= 2742,
    SystemZ_VMALF	= 2743,
    SystemZ_VMALH	= 2744,
    SystemZ_VMALHB	= 2745,
    SystemZ_VMALHF	= 2746,
    SystemZ_VMALHH	= 2747,
    SystemZ_VMALHW	= 2748,
    SystemZ_VMALO	= 2749,
    SystemZ_VMALOB	= 2750,
    SystemZ_VMALOF	= 2751,
    SystemZ_VMALOH	= 2752,
    SystemZ_VMAO	= 2753,
    SystemZ_VMAOB	= 2754,
    SystemZ_VMAOF	= 2755,
    SystemZ_VMAOH	= 2756,
    SystemZ_VME	= 2757,
    SystemZ_VMEB	= 2758,
    SystemZ_VMEF	= 2759,
    SystemZ_VMEH	= 2760,
    SystemZ_VMH	= 2761,
    SystemZ_VMHB	= 2762,
    SystemZ_VMHF	= 2763,
    SystemZ_VMHH	= 2764,
    SystemZ_VML	= 2765,
    SystemZ_VMLB	= 2766,
    SystemZ_VMLE	= 2767,
    SystemZ_VMLEB	= 2768,
    SystemZ_VMLEF	= 2769,
    SystemZ_VMLEH	= 2770,
    SystemZ_VMLF	= 2771,
    SystemZ_VMLH	= 2772,
    SystemZ_VMLHB	= 2773,
    SystemZ_VMLHF	= 2774,
    SystemZ_VMLHH	= 2775,
    SystemZ_VMLHW	= 2776,
    SystemZ_VMLO	= 2777,
    SystemZ_VMLOB	= 2778,
    SystemZ_VMLOF	= 2779,
    SystemZ_VMLOH	= 2780,
    SystemZ_VMN	= 2781,
    SystemZ_VMNB	= 2782,
    SystemZ_VMNF	= 2783,
    SystemZ_VMNG	= 2784,
    SystemZ_VMNH	= 2785,
    SystemZ_VMNL	= 2786,
    SystemZ_VMNLB	= 2787,
    SystemZ_VMNLF	= 2788,
    SystemZ_VMNLG	= 2789,
    SystemZ_VMNLH	= 2790,
    SystemZ_VMO	= 2791,
    SystemZ_VMOB	= 2792,
    SystemZ_VMOF	= 2793,
    SystemZ_VMOH	= 2794,
    SystemZ_VMP	= 2795,
    SystemZ_VMRH	= 2796,
    SystemZ_VMRHB	= 2797,
    SystemZ_VMRHF	= 2798,
    SystemZ_VMRHG	= 2799,
    SystemZ_VMRHH	= 2800,
    SystemZ_VMRL	= 2801,
    SystemZ_VMRLB	= 2802,
    SystemZ_VMRLF	= 2803,
    SystemZ_VMRLG	= 2804,
    SystemZ_VMRLH	= 2805,
    SystemZ_VMSL	= 2806,
    SystemZ_VMSLG	= 2807,
    SystemZ_VMSP	= 2808,
    SystemZ_VMX	= 2809,
    SystemZ_VMXB	= 2810,
    SystemZ_VMXF	= 2811,
    SystemZ_VMXG	= 2812,
    SystemZ_VMXH	= 2813,
    SystemZ_VMXL	= 2814,
    SystemZ_VMXLB	= 2815,
    SystemZ_VMXLF	= 2816,
    SystemZ_VMXLG	= 2817,
    SystemZ_VMXLH	= 2818,
    SystemZ_VN	= 2819,
    SystemZ_VNC	= 2820,
    SystemZ_VNN	= 2821,
    SystemZ_VNO	= 2822,
    SystemZ_VNX	= 2823,
    SystemZ_VO	= 2824,
    SystemZ_VOC	= 2825,
    SystemZ_VONE	= 2826,
    SystemZ_VPDI	= 2827,
    SystemZ_VPERM	= 2828,
    SystemZ_VPK	= 2829,
    SystemZ_VPKF	= 2830,
    SystemZ_VPKG	= 2831,
    SystemZ_VPKH	= 2832,
    SystemZ_VPKLS	= 2833,
    SystemZ_VPKLSF	= 2834,
    SystemZ_VPKLSFS	= 2835,
    SystemZ_VPKLSG	= 2836,
    SystemZ_VPKLSGS	= 2837,
    SystemZ_VPKLSH	= 2838,
    SystemZ_VPKLSHS	= 2839,
    SystemZ_VPKS	= 2840,
    SystemZ_VPKSF	= 2841,
    SystemZ_VPKSFS	= 2842,
    SystemZ_VPKSG	= 2843,
    SystemZ_VPKSGS	= 2844,
    SystemZ_VPKSH	= 2845,
    SystemZ_VPKSHS	= 2846,
    SystemZ_VPKZ	= 2847,
    SystemZ_VPKZR	= 2848,
    SystemZ_VPOPCT	= 2849,
    SystemZ_VPOPCTB	= 2850,
    SystemZ_VPOPCTF	= 2851,
    SystemZ_VPOPCTG	= 2852,
    SystemZ_VPOPCTH	= 2853,
    SystemZ_VPSOP	= 2854,
    SystemZ_VREP	= 2855,
    SystemZ_VREPB	= 2856,
    SystemZ_VREPF	= 2857,
    SystemZ_VREPG	= 2858,
    SystemZ_VREPH	= 2859,
    SystemZ_VREPI	= 2860,
    SystemZ_VREPIB	= 2861,
    SystemZ_VREPIF	= 2862,
    SystemZ_VREPIG	= 2863,
    SystemZ_VREPIH	= 2864,
    SystemZ_VRP	= 2865,
    SystemZ_VS	= 2866,
    SystemZ_VSB	= 2867,
    SystemZ_VSBCBI	= 2868,
    SystemZ_VSBCBIQ	= 2869,
    SystemZ_VSBI	= 2870,
    SystemZ_VSBIQ	= 2871,
    SystemZ_VSCBI	= 2872,
    SystemZ_VSCBIB	= 2873,
    SystemZ_VSCBIF	= 2874,
    SystemZ_VSCBIG	= 2875,
    SystemZ_VSCBIH	= 2876,
    SystemZ_VSCBIQ	= 2877,
    SystemZ_VSCEF	= 2878,
    SystemZ_VSCEG	= 2879,
    SystemZ_VSCHDP	= 2880,
    SystemZ_VSCHP	= 2881,
    SystemZ_VSCHSP	= 2882,
    SystemZ_VSCHXP	= 2883,
    SystemZ_VSCSHP	= 2884,
    SystemZ_VSDP	= 2885,
    SystemZ_VSEG	= 2886,
    SystemZ_VSEGB	= 2887,
    SystemZ_VSEGF	= 2888,
    SystemZ_VSEGH	= 2889,
    SystemZ_VSEL	= 2890,
    SystemZ_VSF	= 2891,
    SystemZ_VSG	= 2892,
    SystemZ_VSH	= 2893,
    SystemZ_VSL	= 2894,
    SystemZ_VSLB	= 2895,
    SystemZ_VSLD	= 2896,
    SystemZ_VSLDB	= 2897,
    SystemZ_VSP	= 2898,
    SystemZ_VSQ	= 2899,
    SystemZ_VSRA	= 2900,
    SystemZ_VSRAB	= 2901,
    SystemZ_VSRD	= 2902,
    SystemZ_VSRL	= 2903,
    SystemZ_VSRLB	= 2904,
    SystemZ_VSRP	= 2905,
    SystemZ_VSRPR	= 2906,
    SystemZ_VST	= 2907,
    SystemZ_VSTAlign	= 2908,
    SystemZ_VSTBR	= 2909,
    SystemZ_VSTBRF	= 2910,
    SystemZ_VSTBRG	= 2911,
    SystemZ_VSTBRH	= 2912,
    SystemZ_VSTBRQ	= 2913,
    SystemZ_VSTEB	= 2914,
    SystemZ_VSTEBRF	= 2915,
    SystemZ_VSTEBRG	= 2916,
    SystemZ_VSTEBRH	= 2917,
    SystemZ_VSTEF	= 2918,
    SystemZ_VSTEG	= 2919,
    SystemZ_VSTEH	= 2920,
    SystemZ_VSTER	= 2921,
    SystemZ_VSTERF	= 2922,
    SystemZ_VSTERG	= 2923,
    SystemZ_VSTERH	= 2924,
    SystemZ_VSTL	= 2925,
    SystemZ_VSTM	= 2926,
    SystemZ_VSTMAlign	= 2927,
    SystemZ_VSTRC	= 2928,
    SystemZ_VSTRCB	= 2929,
    SystemZ_VSTRCBS	= 2930,
    SystemZ_VSTRCF	= 2931,
    SystemZ_VSTRCFS	= 2932,
    SystemZ_VSTRCH	= 2933,
    SystemZ_VSTRCHS	= 2934,
    SystemZ_VSTRCZB	= 2935,
    SystemZ_VSTRCZBS	= 2936,
    SystemZ_VSTRCZF	= 2937,
    SystemZ_VSTRCZFS	= 2938,
    SystemZ_VSTRCZH	= 2939,
    SystemZ_VSTRCZHS	= 2940,
    SystemZ_VSTRL	= 2941,
    SystemZ_VSTRLR	= 2942,
    SystemZ_VSTRS	= 2943,
    SystemZ_VSTRSB	= 2944,
    SystemZ_VSTRSF	= 2945,
    SystemZ_VSTRSH	= 2946,
    SystemZ_VSTRSZB	= 2947,
    SystemZ_VSTRSZF	= 2948,
    SystemZ_VSTRSZH	= 2949,
    SystemZ_VSUM	= 2950,
    SystemZ_VSUMB	= 2951,
    SystemZ_VSUMG	= 2952,
    SystemZ_VSUMGF	= 2953,
    SystemZ_VSUMGH	= 2954,
    SystemZ_VSUMH	= 2955,
    SystemZ_VSUMQ	= 2956,
    SystemZ_VSUMQF	= 2957,
    SystemZ_VSUMQG	= 2958,
    SystemZ_VTM	= 2959,
    SystemZ_VTP	= 2960,
    SystemZ_VUPH	= 2961,
    SystemZ_VUPHB	= 2962,
    SystemZ_VUPHF	= 2963,
    SystemZ_VUPHH	= 2964,
    SystemZ_VUPKZ	= 2965,
    SystemZ_VUPKZH	= 2966,
    SystemZ_VUPKZL	= 2967,
    SystemZ_VUPL	= 2968,
    SystemZ_VUPLB	= 2969,
    SystemZ_VUPLF	= 2970,
    SystemZ_VUPLH	= 2971,
    SystemZ_VUPLHB	= 2972,
    SystemZ_VUPLHF	= 2973,
    SystemZ_VUPLHH	= 2974,
    SystemZ_VUPLHW	= 2975,
    SystemZ_VUPLL	= 2976,
    SystemZ_VUPLLB	= 2977,
    SystemZ_VUPLLF	= 2978,
    SystemZ_VUPLLH	= 2979,
    SystemZ_VX	= 2980,
    SystemZ_VZERO	= 2981,
    SystemZ_WCDGB	= 2982,
    SystemZ_WCDLGB	= 2983,
    SystemZ_WCEFB	= 2984,
    SystemZ_WCELFB	= 2985,
    SystemZ_WCFEB	= 2986,
    SystemZ_WCGDB	= 2987,
    SystemZ_WCLFEB	= 2988,
    SystemZ_WCLGDB	= 2989,
    SystemZ_WFADB	= 2990,
    SystemZ_WFASB	= 2991,
    SystemZ_WFAXB	= 2992,
    SystemZ_WFC	= 2993,
    SystemZ_WFCDB	= 2994,
    SystemZ_WFCEDB	= 2995,
    SystemZ_WFCEDBS	= 2996,
    SystemZ_WFCESB	= 2997,
    SystemZ_WFCESBS	= 2998,
    SystemZ_WFCEXB	= 2999,
    SystemZ_WFCEXBS	= 3000,
    SystemZ_WFCHDB	= 3001,
    SystemZ_WFCHDBS	= 3002,
    SystemZ_WFCHEDB	= 3003,
    SystemZ_WFCHEDBS	= 3004,
    SystemZ_WFCHESB	= 3005,
    SystemZ_WFCHESBS	= 3006,
    SystemZ_WFCHEXB	= 3007,
    SystemZ_WFCHEXBS	= 3008,
    SystemZ_WFCHSB	= 3009,
    SystemZ_WFCHSBS	= 3010,
    SystemZ_WFCHXB	= 3011,
    SystemZ_WFCHXBS	= 3012,
    SystemZ_WFCSB	= 3013,
    SystemZ_WFCXB	= 3014,
    SystemZ_WFDDB	= 3015,
    SystemZ_WFDSB	= 3016,
    SystemZ_WFDXB	= 3017,
    SystemZ_WFIDB	= 3018,
    SystemZ_WFISB	= 3019,
    SystemZ_WFIXB	= 3020,
    SystemZ_WFK	= 3021,
    SystemZ_WFKDB	= 3022,
    SystemZ_WFKEDB	= 3023,
    SystemZ_WFKEDBS	= 3024,
    SystemZ_WFKESB	= 3025,
    SystemZ_WFKESBS	= 3026,
    SystemZ_WFKEXB	= 3027,
    SystemZ_WFKEXBS	= 3028,
    SystemZ_WFKHDB	= 3029,
    SystemZ_WFKHDBS	= 3030,
    SystemZ_WFKHEDB	= 3031,
    SystemZ_WFKHEDBS	= 3032,
    SystemZ_WFKHESB	= 3033,
    SystemZ_WFKHESBS	= 3034,
    SystemZ_WFKHEXB	= 3035,
    SystemZ_WFKHEXBS	= 3036,
    SystemZ_WFKHSB	= 3037,
    SystemZ_WFKHSBS	= 3038,
    SystemZ_WFKHXB	= 3039,
    SystemZ_WFKHXBS	= 3040,
    SystemZ_WFKSB	= 3041,
    SystemZ_WFKXB	= 3042,
    SystemZ_WFLCDB	= 3043,
    SystemZ_WFLCSB	= 3044,
    SystemZ_WFLCXB	= 3045,
    SystemZ_WFLLD	= 3046,
    SystemZ_WFLLS	= 3047,
    SystemZ_WFLNDB	= 3048,
    SystemZ_WFLNSB	= 3049,
    SystemZ_WFLNXB	= 3050,
    SystemZ_WFLPDB	= 3051,
    SystemZ_WFLPSB	= 3052,
    SystemZ_WFLPXB	= 3053,
    SystemZ_WFLRD	= 3054,
    SystemZ_WFLRX	= 3055,
    SystemZ_WFMADB	= 3056,
    SystemZ_WFMASB	= 3057,
    SystemZ_WFMAXB	= 3058,
    SystemZ_WFMAXDB	= 3059,
    SystemZ_WFMAXSB	= 3060,
    SystemZ_WFMAXXB	= 3061,
    SystemZ_WFMDB	= 3062,
    SystemZ_WFMINDB	= 3063,
    SystemZ_WFMINSB	= 3064,
    SystemZ_WFMINXB	= 3065,
    SystemZ_WFMSB	= 3066,
    SystemZ_WFMSDB	= 3067,
    SystemZ_WFMSSB	= 3068,
    SystemZ_WFMSXB	= 3069,
    SystemZ_WFMXB	= 3070,
    SystemZ_WFNMADB	= 3071,
    SystemZ_WFNMASB	= 3072,
    SystemZ_WFNMAXB	= 3073,
    SystemZ_WFNMSDB	= 3074,
    SystemZ_WFNMSSB	= 3075,
    SystemZ_WFNMSXB	= 3076,
    SystemZ_WFPSODB	= 3077,
    SystemZ_WFPSOSB	= 3078,
    SystemZ_WFPSOXB	= 3079,
    SystemZ_WFSDB	= 3080,
    SystemZ_WFSQDB	= 3081,
    SystemZ_WFSQSB	= 3082,
    SystemZ_WFSQXB	= 3083,
    SystemZ_WFSSB	= 3084,
    SystemZ_WFSXB	= 3085,
    SystemZ_WFTCIDB	= 3086,
    SystemZ_WFTCISB	= 3087,
    SystemZ_WFTCIXB	= 3088,
    SystemZ_WLDEB	= 3089,
    SystemZ_WLEDB	= 3090,
    SystemZ_X	= 3091,
    SystemZ_XC	= 3092,
    SystemZ_XG	= 3093,
    SystemZ_XGR	= 3094,
    SystemZ_XGRK	= 3095,
    SystemZ_XI	= 3096,
    SystemZ_XIHF	= 3097,
    SystemZ_XILF	= 3098,
    SystemZ_XIY	= 3099,
    SystemZ_XR	= 3100,
    SystemZ_XRK	= 3101,
    SystemZ_XSCH	= 3102,
    SystemZ_XY	= 3103,
    SystemZ_ZAP	= 3104,
    INSTRUCTION_LIST_END = 3105
  };

#endif // GET_INSTRINFO_ENUM

#if defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)
typedef struct SystemZInstrTable {
  MCInstrDesc Insts[3105];
  MCOperandInfo OperandInfo[1650];
  MCPhysReg ImplicitOps[102];
} SystemZInstrTable;

#endif // defined(GET_INSTRINFO_MC_DESC) || defined(GET_INSTRINFO_CTOR_DTOR)

#ifdef GET_INSTRINFO_MC_DESC
#undef GET_INSTRINFO_MC_DESC

static const unsigned SystemZImpOpBase = sizeof(MCOperandInfo) / (sizeof(MCPhysReg));

static const SystemZInstrTable SystemZDescs = {
  {
  { 6, &SystemZDescs.OperandInfo[532] },  // Inst #3104 = ZAP
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #3103 = XY
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #3102 = XSCH
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #3101 = XRK
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #3100 = XR
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #3099 = XIY
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #3098 = XILF
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #3097 = XIHF
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #3096 = XI
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #3095 = XGRK
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #3094 = XGR
  { 5, &SystemZDescs.OperandInfo[506] },  // Inst #3093 = XG
  { 5, &SystemZDescs.OperandInfo[777] },  // Inst #3092 = XC
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #3091 = X
  { 4, &SystemZDescs.OperandInfo[1620] },  // Inst #3090 = WLEDB
  { 2, &SystemZDescs.OperandInfo[1618] },  // Inst #3089 = WLDEB
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #3088 = WFTCIXB
  { 3, &SystemZDescs.OperandInfo[1647] },  // Inst #3087 = WFTCISB
  { 3, &SystemZDescs.OperandInfo[1644] },  // Inst #3086 = WFTCIDB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #3085 = WFSXB
  { 3, &SystemZDescs.OperandInfo[1613] },  // Inst #3084 = WFSSB
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #3083 = WFSQXB
  { 2, &SystemZDescs.OperandInfo[468] },  // Inst #3082 = WFSQSB
  { 2, &SystemZDescs.OperandInfo[470] },  // Inst #3081 = WFSQDB
  { 3, &SystemZDescs.OperandInfo[1610] },  // Inst #3080 = WFSDB
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #3079 = WFPSOXB
  { 3, &SystemZDescs.OperandInfo[1647] },  // Inst #3078 = WFPSOSB
  { 3, &SystemZDescs.OperandInfo[1644] },  // Inst #3077 = WFPSODB
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #3076 = WFNMSXB
  { 4, &SystemZDescs.OperandInfo[1632] },  // Inst #3075 = WFNMSSB
  { 4, &SystemZDescs.OperandInfo[1628] },  // Inst #3074 = WFNMSDB
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #3073 = WFNMAXB
  { 4, &SystemZDescs.OperandInfo[1632] },  // Inst #3072 = WFNMASB
  { 4, &SystemZDescs.OperandInfo[1628] },  // Inst #3071 = WFNMADB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #3070 = WFMXB
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #3069 = WFMSXB
  { 4, &SystemZDescs.OperandInfo[1632] },  // Inst #3068 = WFMSSB
  { 4, &SystemZDescs.OperandInfo[1628] },  // Inst #3067 = WFMSDB
  { 3, &SystemZDescs.OperandInfo[1613] },  // Inst #3066 = WFMSB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #3065 = WFMINXB
  { 4, &SystemZDescs.OperandInfo[1640] },  // Inst #3064 = WFMINSB
  { 4, &SystemZDescs.OperandInfo[1636] },  // Inst #3063 = WFMINDB
  { 3, &SystemZDescs.OperandInfo[1610] },  // Inst #3062 = WFMDB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #3061 = WFMAXXB
  { 4, &SystemZDescs.OperandInfo[1640] },  // Inst #3060 = WFMAXSB
  { 4, &SystemZDescs.OperandInfo[1636] },  // Inst #3059 = WFMAXDB
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #3058 = WFMAXB
  { 4, &SystemZDescs.OperandInfo[1632] },  // Inst #3057 = WFMASB
  { 4, &SystemZDescs.OperandInfo[1628] },  // Inst #3056 = WFMADB
  { 4, &SystemZDescs.OperandInfo[1624] },  // Inst #3055 = WFLRX
  { 4, &SystemZDescs.OperandInfo[1620] },  // Inst #3054 = WFLRD
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #3053 = WFLPXB
  { 2, &SystemZDescs.OperandInfo[468] },  // Inst #3052 = WFLPSB
  { 2, &SystemZDescs.OperandInfo[470] },  // Inst #3051 = WFLPDB
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #3050 = WFLNXB
  { 2, &SystemZDescs.OperandInfo[468] },  // Inst #3049 = WFLNSB
  { 2, &SystemZDescs.OperandInfo[470] },  // Inst #3048 = WFLNDB
  { 2, &SystemZDescs.OperandInfo[1618] },  // Inst #3047 = WFLLS
  { 2, &SystemZDescs.OperandInfo[1616] },  // Inst #3046 = WFLLD
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #3045 = WFLCXB
  { 2, &SystemZDescs.OperandInfo[468] },  // Inst #3044 = WFLCSB
  { 2, &SystemZDescs.OperandInfo[470] },  // Inst #3043 = WFLCDB
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #3042 = WFKXB
  { 2, &SystemZDescs.OperandInfo[468] },  // Inst #3041 = WFKSB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #3040 = WFKHXBS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #3039 = WFKHXB
  { 3, &SystemZDescs.OperandInfo[1613] },  // Inst #3038 = WFKHSBS
  { 3, &SystemZDescs.OperandInfo[1613] },  // Inst #3037 = WFKHSB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #3036 = WFKHEXBS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #3035 = WFKHEXB
  { 3, &SystemZDescs.OperandInfo[1613] },  // Inst #3034 = WFKHESBS
  { 3, &SystemZDescs.OperandInfo[1613] },  // Inst #3033 = WFKHESB
  { 3, &SystemZDescs.OperandInfo[1610] },  // Inst #3032 = WFKHEDBS
  { 3, &SystemZDescs.OperandInfo[1610] },  // Inst #3031 = WFKHEDB
  { 3, &SystemZDescs.OperandInfo[1610] },  // Inst #3030 = WFKHDBS
  { 3, &SystemZDescs.OperandInfo[1610] },  // Inst #3029 = WFKHDB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #3028 = WFKEXBS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #3027 = WFKEXB
  { 3, &SystemZDescs.OperandInfo[1613] },  // Inst #3026 = WFKESBS
  { 3, &SystemZDescs.OperandInfo[1613] },  // Inst #3025 = WFKESB
  { 3, &SystemZDescs.OperandInfo[1610] },  // Inst #3024 = WFKEDBS
  { 3, &SystemZDescs.OperandInfo[1610] },  // Inst #3023 = WFKEDB
  { 2, &SystemZDescs.OperandInfo[470] },  // Inst #3022 = WFKDB
  { 4, &SystemZDescs.OperandInfo[1602] },  // Inst #3021 = WFK
  { 4, &SystemZDescs.OperandInfo[1456] },  // Inst #3020 = WFIXB
  { 4, &SystemZDescs.OperandInfo[1606] },  // Inst #3019 = WFISB
  { 4, &SystemZDescs.OperandInfo[1602] },  // Inst #3018 = WFIDB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #3017 = WFDXB
  { 3, &SystemZDescs.OperandInfo[1613] },  // Inst #3016 = WFDSB
  { 3, &SystemZDescs.OperandInfo[1610] },  // Inst #3015 = WFDDB
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #3014 = WFCXB
  { 2, &SystemZDescs.OperandInfo[468] },  // Inst #3013 = WFCSB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #3012 = WFCHXBS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #3011 = WFCHXB
  { 3, &SystemZDescs.OperandInfo[1613] },  // Inst #3010 = WFCHSBS
  { 3, &SystemZDescs.OperandInfo[1613] },  // Inst #3009 = WFCHSB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #3008 = WFCHEXBS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #3007 = WFCHEXB
  { 3, &SystemZDescs.OperandInfo[1613] },  // Inst #3006 = WFCHESBS
  { 3, &SystemZDescs.OperandInfo[1613] },  // Inst #3005 = WFCHESB
  { 3, &SystemZDescs.OperandInfo[1610] },  // Inst #3004 = WFCHEDBS
  { 3, &SystemZDescs.OperandInfo[1610] },  // Inst #3003 = WFCHEDB
  { 3, &SystemZDescs.OperandInfo[1610] },  // Inst #3002 = WFCHDBS
  { 3, &SystemZDescs.OperandInfo[1610] },  // Inst #3001 = WFCHDB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #3000 = WFCEXBS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2999 = WFCEXB
  { 3, &SystemZDescs.OperandInfo[1613] },  // Inst #2998 = WFCESBS
  { 3, &SystemZDescs.OperandInfo[1613] },  // Inst #2997 = WFCESB
  { 3, &SystemZDescs.OperandInfo[1610] },  // Inst #2996 = WFCEDBS
  { 3, &SystemZDescs.OperandInfo[1610] },  // Inst #2995 = WFCEDB
  { 2, &SystemZDescs.OperandInfo[470] },  // Inst #2994 = WFCDB
  { 4, &SystemZDescs.OperandInfo[1602] },  // Inst #2993 = WFC
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2992 = WFAXB
  { 3, &SystemZDescs.OperandInfo[1613] },  // Inst #2991 = WFASB
  { 3, &SystemZDescs.OperandInfo[1610] },  // Inst #2990 = WFADB
  { 4, &SystemZDescs.OperandInfo[1602] },  // Inst #2989 = WCLGDB
  { 4, &SystemZDescs.OperandInfo[1606] },  // Inst #2988 = WCLFEB
  { 4, &SystemZDescs.OperandInfo[1602] },  // Inst #2987 = WCGDB
  { 4, &SystemZDescs.OperandInfo[1606] },  // Inst #2986 = WCFEB
  { 4, &SystemZDescs.OperandInfo[1606] },  // Inst #2985 = WCELFB
  { 4, &SystemZDescs.OperandInfo[1606] },  // Inst #2984 = WCEFB
  { 4, &SystemZDescs.OperandInfo[1602] },  // Inst #2983 = WCDLGB
  { 4, &SystemZDescs.OperandInfo[1602] },  // Inst #2982 = WCDGB
  { 1, &SystemZDescs.OperandInfo[1596] },  // Inst #2981 = VZERO
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2980 = VX
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2979 = VUPLLH
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2978 = VUPLLF
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2977 = VUPLLB
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2976 = VUPLL
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2975 = VUPLHW
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2974 = VUPLHH
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2973 = VUPLHF
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2972 = VUPLHB
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2971 = VUPLH
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2970 = VUPLF
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2969 = VUPLB
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2968 = VUPL
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2967 = VUPKZL
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2966 = VUPKZH
  { 4, &SystemZDescs.OperandInfo[1573] },  // Inst #2965 = VUPKZ
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2964 = VUPHH
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2963 = VUPHF
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2962 = VUPHB
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2961 = VUPH
  { 1, &SystemZDescs.OperandInfo[1596] },  // Inst #2960 = VTP
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2959 = VTM
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2958 = VSUMQG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2957 = VSUMQF
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2956 = VSUMQ
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2955 = VSUMH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2954 = VSUMGH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2953 = VSUMGF
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2952 = VSUMG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2951 = VSUMB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2950 = VSUM
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2949 = VSTRSZH
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2948 = VSTRSZF
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2947 = VSTRSZB
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2946 = VSTRSH
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2945 = VSTRSF
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2944 = VSTRSB
  { 6, &SystemZDescs.OperandInfo[1511] },  // Inst #2943 = VSTRS
  { 4, &SystemZDescs.OperandInfo[1560] },  // Inst #2942 = VSTRLR
  { 4, &SystemZDescs.OperandInfo[1573] },  // Inst #2941 = VSTRL
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2940 = VSTRCZHS
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2939 = VSTRCZH
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2938 = VSTRCZFS
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2937 = VSTRCZF
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2936 = VSTRCZBS
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2935 = VSTRCZB
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2934 = VSTRCHS
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2933 = VSTRCH
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2932 = VSTRCFS
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2931 = VSTRCF
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2930 = VSTRCBS
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2929 = VSTRCB
  { 6, &SystemZDescs.OperandInfo[1511] },  // Inst #2928 = VSTRC
  { 5, &SystemZDescs.OperandInfo[1568] },  // Inst #2927 = VSTMAlign
  { 4, &SystemZDescs.OperandInfo[1564] },  // Inst #2926 = VSTM
  { 4, &SystemZDescs.OperandInfo[1560] },  // Inst #2925 = VSTL
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2924 = VSTERH
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2923 = VSTERG
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2922 = VSTERF
  { 5, &SystemZDescs.OperandInfo[1536] },  // Inst #2921 = VSTER
  { 5, &SystemZDescs.OperandInfo[1536] },  // Inst #2920 = VSTEH
  { 5, &SystemZDescs.OperandInfo[1536] },  // Inst #2919 = VSTEG
  { 5, &SystemZDescs.OperandInfo[1536] },  // Inst #2918 = VSTEF
  { 5, &SystemZDescs.OperandInfo[1536] },  // Inst #2917 = VSTEBRH
  { 5, &SystemZDescs.OperandInfo[1536] },  // Inst #2916 = VSTEBRG
  { 5, &SystemZDescs.OperandInfo[1536] },  // Inst #2915 = VSTEBRF
  { 5, &SystemZDescs.OperandInfo[1536] },  // Inst #2914 = VSTEB
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2913 = VSTBRQ
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2912 = VSTBRH
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2911 = VSTBRG
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2910 = VSTBRF
  { 5, &SystemZDescs.OperandInfo[1536] },  // Inst #2909 = VSTBR
  { 5, &SystemZDescs.OperandInfo[1536] },  // Inst #2908 = VSTAlign
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2907 = VST
  { 5, &SystemZDescs.OperandInfo[415] },  // Inst #2906 = VSRPR
  { 5, &SystemZDescs.OperandInfo[1451] },  // Inst #2905 = VSRP
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2904 = VSRLB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2903 = VSRL
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2902 = VSRD
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2901 = VSRAB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2900 = VSRA
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2899 = VSQ
  { 5, &SystemZDescs.OperandInfo[415] },  // Inst #2898 = VSP
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2897 = VSLDB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2896 = VSLD
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2895 = VSLB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2894 = VSL
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2893 = VSH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2892 = VSG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2891 = VSF
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2890 = VSEL
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2889 = VSEGH
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2888 = VSEGF
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2887 = VSEGB
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2886 = VSEG
  { 5, &SystemZDescs.OperandInfo[415] },  // Inst #2885 = VSDP
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2884 = VSCSHP
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2883 = VSCHXP
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2882 = VSCHSP
  { 5, &SystemZDescs.OperandInfo[415] },  // Inst #2881 = VSCHP
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2880 = VSCHDP
  { 5, &SystemZDescs.OperandInfo[1597] },  // Inst #2879 = VSCEG
  { 5, &SystemZDescs.OperandInfo[1597] },  // Inst #2878 = VSCEF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2877 = VSCBIQ
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2876 = VSCBIH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2875 = VSCBIG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2874 = VSCBIF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2873 = VSCBIB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2872 = VSCBI
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2871 = VSBIQ
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2870 = VSBI
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2869 = VSBCBIQ
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2868 = VSBCBI
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2867 = VSB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2866 = VS
  { 5, &SystemZDescs.OperandInfo[415] },  // Inst #2865 = VRP
  { 2, &SystemZDescs.OperandInfo[1517] },  // Inst #2864 = VREPIH
  { 2, &SystemZDescs.OperandInfo[1517] },  // Inst #2863 = VREPIG
  { 2, &SystemZDescs.OperandInfo[1517] },  // Inst #2862 = VREPIF
  { 2, &SystemZDescs.OperandInfo[1517] },  // Inst #2861 = VREPIB
  { 3, &SystemZDescs.OperandInfo[1529] },  // Inst #2860 = VREPI
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2859 = VREPH
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2858 = VREPG
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2857 = VREPF
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2856 = VREPB
  { 4, &SystemZDescs.OperandInfo[1456] },  // Inst #2855 = VREP
  { 5, &SystemZDescs.OperandInfo[1451] },  // Inst #2854 = VPSOP
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2853 = VPOPCTH
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2852 = VPOPCTG
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2851 = VPOPCTF
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2850 = VPOPCTB
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2849 = VPOPCT
  { 5, &SystemZDescs.OperandInfo[415] },  // Inst #2848 = VPKZR
  { 4, &SystemZDescs.OperandInfo[1573] },  // Inst #2847 = VPKZ
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2846 = VPKSHS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2845 = VPKSH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2844 = VPKSGS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2843 = VPKSG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2842 = VPKSFS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2841 = VPKSF
  { 5, &SystemZDescs.OperandInfo[415] },  // Inst #2840 = VPKS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2839 = VPKLSHS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2838 = VPKLSH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2837 = VPKLSGS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2836 = VPKLSG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2835 = VPKLSFS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2834 = VPKLSF
  { 5, &SystemZDescs.OperandInfo[415] },  // Inst #2833 = VPKLS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2832 = VPKH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2831 = VPKG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2830 = VPKF
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2829 = VPK
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2828 = VPERM
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2827 = VPDI
  { 1, &SystemZDescs.OperandInfo[1596] },  // Inst #2826 = VONE
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2825 = VOC
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2824 = VO
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2823 = VNX
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2822 = VNO
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2821 = VNN
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2820 = VNC
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2819 = VN
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2818 = VMXLH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2817 = VMXLG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2816 = VMXLF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2815 = VMXLB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2814 = VMXL
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2813 = VMXH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2812 = VMXG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2811 = VMXF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2810 = VMXB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2809 = VMX
  { 5, &SystemZDescs.OperandInfo[415] },  // Inst #2808 = VMSP
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2807 = VMSLG
  { 6, &SystemZDescs.OperandInfo[1511] },  // Inst #2806 = VMSL
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2805 = VMRLH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2804 = VMRLG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2803 = VMRLF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2802 = VMRLB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2801 = VMRL
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2800 = VMRHH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2799 = VMRHG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2798 = VMRHF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2797 = VMRHB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2796 = VMRH
  { 5, &SystemZDescs.OperandInfo[415] },  // Inst #2795 = VMP
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2794 = VMOH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2793 = VMOF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2792 = VMOB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2791 = VMO
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2790 = VMNLH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2789 = VMNLG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2788 = VMNLF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2787 = VMNLB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2786 = VMNL
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2785 = VMNH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2784 = VMNG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2783 = VMNF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2782 = VMNB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2781 = VMN
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2780 = VMLOH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2779 = VMLOF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2778 = VMLOB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2777 = VMLO
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2776 = VMLHW
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2775 = VMLHH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2774 = VMLHF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2773 = VMLHB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2772 = VMLH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2771 = VMLF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2770 = VMLEH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2769 = VMLEF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2768 = VMLEB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2767 = VMLE
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2766 = VMLB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2765 = VML
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2764 = VMHH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2763 = VMHF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2762 = VMHB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2761 = VMH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2760 = VMEH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2759 = VMEF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2758 = VMEB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2757 = VME
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2756 = VMAOH
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2755 = VMAOF
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2754 = VMAOB
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2753 = VMAO
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2752 = VMALOH
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2751 = VMALOF
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2750 = VMALOB
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2749 = VMALO
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2748 = VMALHW
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2747 = VMALHH
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2746 = VMALHF
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2745 = VMALHB
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2744 = VMALH
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2743 = VMALF
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2742 = VMALEH
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2741 = VMALEF
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2740 = VMALEB
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2739 = VMALE
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2738 = VMALB
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2737 = VMAL
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2736 = VMAHH
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2735 = VMAHF
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2734 = VMAHB
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2733 = VMAH
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2732 = VMAEH
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2731 = VMAEF
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2730 = VMAEB
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2729 = VMAE
  { 3, &SystemZDescs.OperandInfo[1593] },  // Inst #2728 = VLVGP
  { 5, &SystemZDescs.OperandInfo[1583] },  // Inst #2727 = VLVGH
  { 5, &SystemZDescs.OperandInfo[1588] },  // Inst #2726 = VLVGG
  { 5, &SystemZDescs.OperandInfo[1583] },  // Inst #2725 = VLVGF
  { 5, &SystemZDescs.OperandInfo[1583] },  // Inst #2724 = VLVGB
  { 6, &SystemZDescs.OperandInfo[1577] },  // Inst #2723 = VLVG
  { 4, &SystemZDescs.OperandInfo[1560] },  // Inst #2722 = VLRLR
  { 4, &SystemZDescs.OperandInfo[1573] },  // Inst #2721 = VLRL
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2720 = VLREPH
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2719 = VLREPG
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2718 = VLREPF
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2717 = VLREPB
  { 5, &SystemZDescs.OperandInfo[1536] },  // Inst #2716 = VLREP
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2715 = VLR
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2714 = VLPH
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2713 = VLPG
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2712 = VLPF
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2711 = VLPB
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2710 = VLP
  { 5, &SystemZDescs.OperandInfo[1568] },  // Inst #2709 = VLMAlign
  { 4, &SystemZDescs.OperandInfo[1564] },  // Inst #2708 = VLM
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2707 = VLLEZLF
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2706 = VLLEZH
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2705 = VLLEZG
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2704 = VLLEZF
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2703 = VLLEZB
  { 5, &SystemZDescs.OperandInfo[1536] },  // Inst #2702 = VLLEZ
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2701 = VLLEBRZH
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2700 = VLLEBRZG
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2699 = VLLEBRZF
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2698 = VLLEBRZE
  { 5, &SystemZDescs.OperandInfo[1536] },  // Inst #2697 = VLLEBRZ
  { 4, &SystemZDescs.OperandInfo[1560] },  // Inst #2696 = VLL
  { 3, &SystemZDescs.OperandInfo[1529] },  // Inst #2695 = VLIP
  { 4, &SystemZDescs.OperandInfo[1556] },  // Inst #2694 = VLGVH
  { 4, &SystemZDescs.OperandInfo[1556] },  // Inst #2693 = VLGVG
  { 4, &SystemZDescs.OperandInfo[1556] },  // Inst #2692 = VLGVF
  { 4, &SystemZDescs.OperandInfo[1556] },  // Inst #2691 = VLGVB
  { 5, &SystemZDescs.OperandInfo[1551] },  // Inst #2690 = VLGV
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2689 = VLERH
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2688 = VLERG
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2687 = VLERF
  { 5, &SystemZDescs.OperandInfo[1536] },  // Inst #2686 = VLER
  { 4, &SystemZDescs.OperandInfo[1547] },  // Inst #2685 = VLEIH
  { 4, &SystemZDescs.OperandInfo[1547] },  // Inst #2684 = VLEIG
  { 4, &SystemZDescs.OperandInfo[1547] },  // Inst #2683 = VLEIF
  { 4, &SystemZDescs.OperandInfo[1547] },  // Inst #2682 = VLEIB
  { 6, &SystemZDescs.OperandInfo[1541] },  // Inst #2681 = VLEH
  { 6, &SystemZDescs.OperandInfo[1541] },  // Inst #2680 = VLEG
  { 6, &SystemZDescs.OperandInfo[1541] },  // Inst #2679 = VLEF
  { 4, &SystemZDescs.OperandInfo[1456] },  // Inst #2678 = VLEDB
  { 5, &SystemZDescs.OperandInfo[1451] },  // Inst #2677 = VLED
  { 6, &SystemZDescs.OperandInfo[1541] },  // Inst #2676 = VLEBRH
  { 6, &SystemZDescs.OperandInfo[1541] },  // Inst #2675 = VLEBRG
  { 6, &SystemZDescs.OperandInfo[1541] },  // Inst #2674 = VLEBRF
  { 6, &SystemZDescs.OperandInfo[1541] },  // Inst #2673 = VLEB
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2672 = VLDEB
  { 4, &SystemZDescs.OperandInfo[1456] },  // Inst #2671 = VLDE
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2670 = VLCH
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2669 = VLCG
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2668 = VLCF
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2667 = VLCB
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2666 = VLC
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2665 = VLBRREPH
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2664 = VLBRREPG
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2663 = VLBRREPF
  { 5, &SystemZDescs.OperandInfo[1536] },  // Inst #2662 = VLBRREP
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2661 = VLBRQ
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2660 = VLBRH
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2659 = VLBRG
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2658 = VLBRF
  { 5, &SystemZDescs.OperandInfo[1536] },  // Inst #2657 = VLBR
  { 5, &SystemZDescs.OperandInfo[1536] },  // Inst #2656 = VLBB
  { 5, &SystemZDescs.OperandInfo[1536] },  // Inst #2655 = VLAlign
  { 4, &SystemZDescs.OperandInfo[1532] },  // Inst #2654 = VL
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2653 = VISTRHS
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2652 = VISTRH
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2651 = VISTRFS
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2650 = VISTRF
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2649 = VISTRBS
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2648 = VISTRB
  { 4, &SystemZDescs.OperandInfo[1456] },  // Inst #2647 = VISTR
  { 3, &SystemZDescs.OperandInfo[1529] },  // Inst #2646 = VGMH
  { 3, &SystemZDescs.OperandInfo[1529] },  // Inst #2645 = VGMG
  { 3, &SystemZDescs.OperandInfo[1529] },  // Inst #2644 = VGMF
  { 3, &SystemZDescs.OperandInfo[1529] },  // Inst #2643 = VGMB
  { 4, &SystemZDescs.OperandInfo[1525] },  // Inst #2642 = VGM
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2641 = VGFMH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2640 = VGFMG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2639 = VGFMF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2638 = VGFMB
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2637 = VGFMAH
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2636 = VGFMAG
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2635 = VGFMAF
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2634 = VGFMAB
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2633 = VGFMA
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2632 = VGFM
  { 6, &SystemZDescs.OperandInfo[1519] },  // Inst #2631 = VGEG
  { 6, &SystemZDescs.OperandInfo[1519] },  // Inst #2630 = VGEF
  { 2, &SystemZDescs.OperandInfo[1517] },  // Inst #2629 = VGBM
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2628 = VFTCISB
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2627 = VFTCIDB
  { 5, &SystemZDescs.OperandInfo[1451] },  // Inst #2626 = VFTCI
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2625 = VFSSB
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2624 = VFSQSB
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2623 = VFSQDB
  { 4, &SystemZDescs.OperandInfo[1456] },  // Inst #2622 = VFSQ
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2621 = VFSDB
  { 5, &SystemZDescs.OperandInfo[415] },  // Inst #2620 = VFS
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2619 = VFPSOSB
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2618 = VFPSODB
  { 5, &SystemZDescs.OperandInfo[1451] },  // Inst #2617 = VFPSO
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2616 = VFNMSSB
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2615 = VFNMSDB
  { 6, &SystemZDescs.OperandInfo[1511] },  // Inst #2614 = VFNMS
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2613 = VFNMASB
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2612 = VFNMADB
  { 6, &SystemZDescs.OperandInfo[1511] },  // Inst #2611 = VFNMA
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2610 = VFMSSB
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2609 = VFMSDB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2608 = VFMSB
  { 6, &SystemZDescs.OperandInfo[1511] },  // Inst #2607 = VFMS
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2606 = VFMINSB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2605 = VFMINDB
  { 6, &SystemZDescs.OperandInfo[1505] },  // Inst #2604 = VFMIN
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2603 = VFMDB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2602 = VFMAXSB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2601 = VFMAXDB
  { 6, &SystemZDescs.OperandInfo[1505] },  // Inst #2600 = VFMAX
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2599 = VFMASB
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2598 = VFMADB
  { 6, &SystemZDescs.OperandInfo[1511] },  // Inst #2597 = VFMA
  { 5, &SystemZDescs.OperandInfo[415] },  // Inst #2596 = VFM
  { 4, &SystemZDescs.OperandInfo[1456] },  // Inst #2595 = VFLRD
  { 5, &SystemZDescs.OperandInfo[1451] },  // Inst #2594 = VFLR
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2593 = VFLPSB
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2592 = VFLPDB
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2591 = VFLNSB
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2590 = VFLNDB
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2589 = VFLLS
  { 4, &SystemZDescs.OperandInfo[1456] },  // Inst #2588 = VFLL
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2587 = VFLCSB
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2586 = VFLCDB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2585 = VFKHSBS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2584 = VFKHSB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2583 = VFKHESBS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2582 = VFKHESB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2581 = VFKHEDBS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2580 = VFKHEDB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2579 = VFKHDBS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2578 = VFKHDB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2577 = VFKESBS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2576 = VFKESB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2575 = VFKEDBS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2574 = VFKEDB
  { 4, &SystemZDescs.OperandInfo[1456] },  // Inst #2573 = VFISB
  { 4, &SystemZDescs.OperandInfo[1456] },  // Inst #2572 = VFIDB
  { 5, &SystemZDescs.OperandInfo[1451] },  // Inst #2571 = VFI
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2570 = VFENEZHS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2569 = VFENEZH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2568 = VFENEZFS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2567 = VFENEZF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2566 = VFENEZBS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2565 = VFENEZB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2564 = VFENEHS
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2563 = VFENEH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2562 = VFENEFS
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2561 = VFENEF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2560 = VFENEBS
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2559 = VFENEB
  { 5, &SystemZDescs.OperandInfo[415] },  // Inst #2558 = VFENE
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2557 = VFEEZHS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2556 = VFEEZH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2555 = VFEEZFS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2554 = VFEEZF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2553 = VFEEZBS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2552 = VFEEZB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2551 = VFEEHS
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2550 = VFEEH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2549 = VFEEFS
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2548 = VFEEF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2547 = VFEEBS
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2546 = VFEEB
  { 5, &SystemZDescs.OperandInfo[415] },  // Inst #2545 = VFEE
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2544 = VFDSB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2543 = VFDDB
  { 5, &SystemZDescs.OperandInfo[415] },  // Inst #2542 = VFD
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2541 = VFCHSBS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2540 = VFCHSB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2539 = VFCHESBS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2538 = VFCHESB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2537 = VFCHEDBS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2536 = VFCHEDB
  { 6, &SystemZDescs.OperandInfo[1505] },  // Inst #2535 = VFCHE
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2534 = VFCHDBS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2533 = VFCHDB
  { 6, &SystemZDescs.OperandInfo[1505] },  // Inst #2532 = VFCH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2531 = VFCESBS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2530 = VFCESB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2529 = VFCEDBS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2528 = VFCEDB
  { 6, &SystemZDescs.OperandInfo[1505] },  // Inst #2527 = VFCE
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2526 = VFASB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2525 = VFAEZHS
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2524 = VFAEZH
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2523 = VFAEZFS
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2522 = VFAEZF
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2521 = VFAEZBS
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2520 = VFAEZB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2519 = VFAEHS
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2518 = VFAEH
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2517 = VFAEFS
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2516 = VFAEF
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2515 = VFAEBS
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2514 = VFAEB
  { 5, &SystemZDescs.OperandInfo[415] },  // Inst #2513 = VFAE
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2512 = VFADB
  { 5, &SystemZDescs.OperandInfo[415] },  // Inst #2511 = VFA
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2510 = VESRLVH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2509 = VESRLVG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2508 = VESRLVF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2507 = VESRLVB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2506 = VESRLV
  { 4, &SystemZDescs.OperandInfo[1501] },  // Inst #2505 = VESRLH
  { 4, &SystemZDescs.OperandInfo[1501] },  // Inst #2504 = VESRLG
  { 4, &SystemZDescs.OperandInfo[1501] },  // Inst #2503 = VESRLF
  { 4, &SystemZDescs.OperandInfo[1501] },  // Inst #2502 = VESRLB
  { 5, &SystemZDescs.OperandInfo[1496] },  // Inst #2501 = VESRL
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2500 = VESRAVH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2499 = VESRAVG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2498 = VESRAVF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2497 = VESRAVB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2496 = VESRAV
  { 4, &SystemZDescs.OperandInfo[1501] },  // Inst #2495 = VESRAH
  { 4, &SystemZDescs.OperandInfo[1501] },  // Inst #2494 = VESRAG
  { 4, &SystemZDescs.OperandInfo[1501] },  // Inst #2493 = VESRAF
  { 4, &SystemZDescs.OperandInfo[1501] },  // Inst #2492 = VESRAB
  { 5, &SystemZDescs.OperandInfo[1496] },  // Inst #2491 = VESRA
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2490 = VESLVH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2489 = VESLVG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2488 = VESLVF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2487 = VESLVB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2486 = VESLV
  { 4, &SystemZDescs.OperandInfo[1501] },  // Inst #2485 = VESLH
  { 4, &SystemZDescs.OperandInfo[1501] },  // Inst #2484 = VESLG
  { 4, &SystemZDescs.OperandInfo[1501] },  // Inst #2483 = VESLF
  { 4, &SystemZDescs.OperandInfo[1501] },  // Inst #2482 = VESLB
  { 5, &SystemZDescs.OperandInfo[1496] },  // Inst #2481 = VESL
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2480 = VERLLVH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2479 = VERLLVG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2478 = VERLLVF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2477 = VERLLVB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2476 = VERLLV
  { 4, &SystemZDescs.OperandInfo[1501] },  // Inst #2475 = VERLLH
  { 4, &SystemZDescs.OperandInfo[1501] },  // Inst #2474 = VERLLG
  { 4, &SystemZDescs.OperandInfo[1501] },  // Inst #2473 = VERLLF
  { 4, &SystemZDescs.OperandInfo[1501] },  // Inst #2472 = VERLLB
  { 5, &SystemZDescs.OperandInfo[1496] },  // Inst #2471 = VERLL
  { 5, &SystemZDescs.OperandInfo[1491] },  // Inst #2470 = VERIMH
  { 5, &SystemZDescs.OperandInfo[1491] },  // Inst #2469 = VERIMG
  { 5, &SystemZDescs.OperandInfo[1491] },  // Inst #2468 = VERIMF
  { 5, &SystemZDescs.OperandInfo[1491] },  // Inst #2467 = VERIMB
  { 6, &SystemZDescs.OperandInfo[1485] },  // Inst #2466 = VERIM
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2465 = VECLH
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2464 = VECLG
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2463 = VECLF
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2462 = VECLB
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2461 = VECL
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2460 = VECH
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2459 = VECG
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2458 = VECF
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2457 = VECB
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2456 = VEC
  { 5, &SystemZDescs.OperandInfo[415] },  // Inst #2455 = VDP
  { 4, &SystemZDescs.OperandInfo[1481] },  // Inst #2454 = VCVDG
  { 4, &SystemZDescs.OperandInfo[1477] },  // Inst #2453 = VCVD
  { 4, &SystemZDescs.OperandInfo[1473] },  // Inst #2452 = VCVBOpt
  { 4, &SystemZDescs.OperandInfo[1469] },  // Inst #2451 = VCVBGOpt
  { 3, &SystemZDescs.OperandInfo[1466] },  // Inst #2450 = VCVBG
  { 3, &SystemZDescs.OperandInfo[1463] },  // Inst #2449 = VCVB
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2448 = VCTZH
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2447 = VCTZG
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2446 = VCTZF
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2445 = VCTZB
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2444 = VCTZ
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2443 = VCSPH
  { 5, &SystemZDescs.OperandInfo[1451] },  // Inst #2442 = VCSFP
  { 5, &SystemZDescs.OperandInfo[415] },  // Inst #2441 = VCRNF
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2440 = VCP
  { 4, &SystemZDescs.OperandInfo[1456] },  // Inst #2439 = VCNF
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2438 = VCLZH
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2437 = VCLZG
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2436 = VCLZF
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2435 = VCLZDP
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #2434 = VCLZB
  { 3, &SystemZDescs.OperandInfo[1460] },  // Inst #2433 = VCLZ
  { 4, &SystemZDescs.OperandInfo[1456] },  // Inst #2432 = VCLGDB
  { 5, &SystemZDescs.OperandInfo[1451] },  // Inst #2431 = VCLGD
  { 5, &SystemZDescs.OperandInfo[1451] },  // Inst #2430 = VCLFP
  { 4, &SystemZDescs.OperandInfo[1456] },  // Inst #2429 = VCLFNL
  { 4, &SystemZDescs.OperandInfo[1456] },  // Inst #2428 = VCLFNH
  { 4, &SystemZDescs.OperandInfo[1456] },  // Inst #2427 = VCLFEB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2426 = VCKSM
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2425 = VCHLHS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2424 = VCHLH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2423 = VCHLGS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2422 = VCHLG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2421 = VCHLFS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2420 = VCHLF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2419 = VCHLBS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2418 = VCHLB
  { 5, &SystemZDescs.OperandInfo[415] },  // Inst #2417 = VCHL
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2416 = VCHHS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2415 = VCHH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2414 = VCHGS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2413 = VCHG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2412 = VCHFS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2411 = VCHF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2410 = VCHBS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2409 = VCHB
  { 5, &SystemZDescs.OperandInfo[415] },  // Inst #2408 = VCH
  { 4, &SystemZDescs.OperandInfo[1456] },  // Inst #2407 = VCGDB
  { 5, &SystemZDescs.OperandInfo[1451] },  // Inst #2406 = VCGD
  { 5, &SystemZDescs.OperandInfo[1451] },  // Inst #2405 = VCFPS
  { 5, &SystemZDescs.OperandInfo[1451] },  // Inst #2404 = VCFPL
  { 4, &SystemZDescs.OperandInfo[1456] },  // Inst #2403 = VCFN
  { 4, &SystemZDescs.OperandInfo[1456] },  // Inst #2402 = VCFEB
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2401 = VCEQHS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2400 = VCEQH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2399 = VCEQGS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2398 = VCEQG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2397 = VCEQFS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2396 = VCEQF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2395 = VCEQBS
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2394 = VCEQB
  { 5, &SystemZDescs.OperandInfo[415] },  // Inst #2393 = VCEQ
  { 4, &SystemZDescs.OperandInfo[1456] },  // Inst #2392 = VCELFB
  { 4, &SystemZDescs.OperandInfo[1456] },  // Inst #2391 = VCEFB
  { 4, &SystemZDescs.OperandInfo[1456] },  // Inst #2390 = VCDLGB
  { 5, &SystemZDescs.OperandInfo[1451] },  // Inst #2389 = VCDLG
  { 4, &SystemZDescs.OperandInfo[1456] },  // Inst #2388 = VCDGB
  { 5, &SystemZDescs.OperandInfo[1451] },  // Inst #2387 = VCDG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2386 = VBPERM
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2385 = VAVGLH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2384 = VAVGLG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2383 = VAVGLF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2382 = VAVGLB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2381 = VAVGL
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2380 = VAVGH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2379 = VAVGG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2378 = VAVGF
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2377 = VAVGB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2376 = VAVG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2375 = VAQ
  { 5, &SystemZDescs.OperandInfo[415] },  // Inst #2374 = VAP
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2373 = VAH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2372 = VAG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2371 = VAF
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2370 = VACQ
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2369 = VACCQ
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2368 = VACCH
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2367 = VACCG
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2366 = VACCF
  { 4, &SystemZDescs.OperandInfo[1447] },  // Inst #2365 = VACCCQ
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2364 = VACCC
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2363 = VACCB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2362 = VACC
  { 5, &SystemZDescs.OperandInfo[1442] },  // Inst #2361 = VAC
  { 3, &SystemZDescs.OperandInfo[1439] },  // Inst #2360 = VAB
  { 4, &SystemZDescs.OperandInfo[1435] },  // Inst #2359 = VA
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #2358 = UPT
  { 5, &SystemZDescs.OperandInfo[777] },  // Inst #2357 = UNPKU
  { 5, &SystemZDescs.OperandInfo[777] },  // Inst #2356 = UNPKA
  { 6, &SystemZDescs.OperandInfo[532] },  // Inst #2355 = UNPK
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2354 = TSCH
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2353 = TS
  { 4, &SystemZDescs.OperandInfo[1419] },  // Inst #2352 = TRTTOpt
  { 5, &SystemZDescs.OperandInfo[1423] },  // Inst #2351 = TRTT
  { 3, &SystemZDescs.OperandInfo[1432] },  // Inst #2350 = TRTREOpt
  { 4, &SystemZDescs.OperandInfo[1428] },  // Inst #2349 = TRTRE
  { 5, &SystemZDescs.OperandInfo[777] },  // Inst #2348 = TRTR
  { 4, &SystemZDescs.OperandInfo[1419] },  // Inst #2347 = TRTOOpt
  { 5, &SystemZDescs.OperandInfo[1423] },  // Inst #2346 = TRTO
  { 3, &SystemZDescs.OperandInfo[1432] },  // Inst #2345 = TRTEOpt
  { 4, &SystemZDescs.OperandInfo[1428] },  // Inst #2344 = TRTE
  { 5, &SystemZDescs.OperandInfo[777] },  // Inst #2343 = TRT
  { 4, &SystemZDescs.OperandInfo[1419] },  // Inst #2342 = TROTOpt
  { 5, &SystemZDescs.OperandInfo[1423] },  // Inst #2341 = TROT
  { 4, &SystemZDescs.OperandInfo[1419] },  // Inst #2340 = TROOOpt
  { 5, &SystemZDescs.OperandInfo[1423] },  // Inst #2339 = TROO
  { 4, &SystemZDescs.OperandInfo[1419] },  // Inst #2338 = TRE
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2337 = TRAP4
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #2336 = TRAP2
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #2335 = TRACG
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #2334 = TRACE
  { 5, &SystemZDescs.OperandInfo[777] },  // Inst #2333 = TR
  { 4, &SystemZDescs.OperandInfo[1096] },  // Inst #2332 = TPROT
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2331 = TPI
  { 3, &SystemZDescs.OperandInfo[1416] },  // Inst #2330 = TP
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #2329 = TMY
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #2328 = TMLL
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #2327 = TMLH
  { 2, &SystemZDescs.OperandInfo[764] },  // Inst #2326 = TMHL
  { 2, &SystemZDescs.OperandInfo[764] },  // Inst #2325 = TMHH
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #2324 = TM
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #2323 = THDR
  { 2, &SystemZDescs.OperandInfo[1109] },  // Inst #2322 = THDER
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #2321 = TEND
  { 4, &SystemZDescs.OperandInfo[335] },  // Inst #2320 = TDGXT
  { 4, &SystemZDescs.OperandInfo[643] },  // Inst #2319 = TDGET
  { 4, &SystemZDescs.OperandInfo[615] },  // Inst #2318 = TDGDT
  { 4, &SystemZDescs.OperandInfo[335] },  // Inst #2317 = TDCXT
  { 4, &SystemZDescs.OperandInfo[643] },  // Inst #2316 = TDCET
  { 4, &SystemZDescs.OperandInfo[615] },  // Inst #2315 = TDCDT
  { 4, &SystemZDescs.OperandInfo[335] },  // Inst #2314 = TCXB
  { 4, &SystemZDescs.OperandInfo[643] },  // Inst #2313 = TCEB
  { 4, &SystemZDescs.OperandInfo[615] },  // Inst #2312 = TCDB
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #2311 = TBEGINC
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #2310 = TBEGIN
  { 3, &SystemZDescs.OperandInfo[1413] },  // Inst #2309 = TBEDR
  { 3, &SystemZDescs.OperandInfo[934] },  // Inst #2308 = TBDR
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #2307 = TB
  { 2, &SystemZDescs.OperandInfo[1352] },  // Inst #2306 = TAR
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #2305 = TAM
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2304 = TABORT
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #2303 = SY
  { 4, &SystemZDescs.OperandInfo[544] },  // Inst #2302 = SXTRA
  { 3, &SystemZDescs.OperandInfo[541] },  // Inst #2301 = SXTR
  { 3, &SystemZDescs.OperandInfo[538] },  // Inst #2300 = SXR
  { 3, &SystemZDescs.OperandInfo[538] },  // Inst #2299 = SXBR
  { 3, &SystemZDescs.OperandInfo[485] },  // Inst #2298 = SWR
  { 5, &SystemZDescs.OperandInfo[480] },  // Inst #2297 = SW
  { 1, &SystemZDescs.OperandInfo[1] },  // Inst #2296 = SVC
  { 3, &SystemZDescs.OperandInfo[500] },  // Inst #2295 = SUR
  { 5, &SystemZDescs.OperandInfo[495] },  // Inst #2294 = SU
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #2293 = STY
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #2292 = STURG
  { 2, &SystemZDescs.OperandInfo[921] },  // Inst #2291 = STURA
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2290 = STSI
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2289 = STSCH
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #2288 = STRVH
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #2287 = STRVG
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #2286 = STRV
  { 2, &SystemZDescs.OperandInfo[753] },  // Inst #2285 = STRL
  { 4, &SystemZDescs.OperandInfo[1096] },  // Inst #2284 = STRAG
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2283 = STPX
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2282 = STPT
  { 4, &SystemZDescs.OperandInfo[294] },  // Inst #2281 = STPQ
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #2280 = STOSM
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #2279 = STOCGAsmZ
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #2278 = STOCGAsmP
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #2277 = STOCGAsmO
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #2276 = STOCGAsmNZ
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #2275 = STOCGAsmNP
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #2274 = STOCGAsmNO
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #2273 = STOCGAsmNM
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #2272 = STOCGAsmNLH
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #2271 = STOCGAsmNLE
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #2270 = STOCGAsmNL
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #2269 = STOCGAsmNHE
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #2268 = STOCGAsmNH
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #2267 = STOCGAsmNE
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #2266 = STOCGAsmM
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #2265 = STOCGAsmLH
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #2264 = STOCGAsmLE
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #2263 = STOCGAsmL
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #2262 = STOCGAsmHE
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #2261 = STOCGAsmH
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #2260 = STOCGAsmE
  { 4, &SystemZDescs.OperandInfo[792] },  // Inst #2259 = STOCGAsm
  { 5, &SystemZDescs.OperandInfo[1408] },  // Inst #2258 = STOCG
  { 3, &SystemZDescs.OperandInfo[1405] },  // Inst #2257 = STOCFHAsmZ
  { 3, &SystemZDescs.OperandInfo[1405] },  // Inst #2256 = STOCFHAsmP
  { 3, &SystemZDescs.OperandInfo[1405] },  // Inst #2255 = STOCFHAsmO
  { 3, &SystemZDescs.OperandInfo[1405] },  // Inst #2254 = STOCFHAsmNZ
  { 3, &SystemZDescs.OperandInfo[1405] },  // Inst #2253 = STOCFHAsmNP
  { 3, &SystemZDescs.OperandInfo[1405] },  // Inst #2252 = STOCFHAsmNO
  { 3, &SystemZDescs.OperandInfo[1405] },  // Inst #2251 = STOCFHAsmNM
  { 3, &SystemZDescs.OperandInfo[1405] },  // Inst #2250 = STOCFHAsmNLH
  { 3, &SystemZDescs.OperandInfo[1405] },  // Inst #2249 = STOCFHAsmNLE
  { 3, &SystemZDescs.OperandInfo[1405] },  // Inst #2248 = STOCFHAsmNL
  { 3, &SystemZDescs.OperandInfo[1405] },  // Inst #2247 = STOCFHAsmNHE
  { 3, &SystemZDescs.OperandInfo[1405] },  // Inst #2246 = STOCFHAsmNH
  { 3, &SystemZDescs.OperandInfo[1405] },  // Inst #2245 = STOCFHAsmNE
  { 3, &SystemZDescs.OperandInfo[1405] },  // Inst #2244 = STOCFHAsmM
  { 3, &SystemZDescs.OperandInfo[1405] },  // Inst #2243 = STOCFHAsmLH
  { 3, &SystemZDescs.OperandInfo[1405] },  // Inst #2242 = STOCFHAsmLE
  { 3, &SystemZDescs.OperandInfo[1405] },  // Inst #2241 = STOCFHAsmL
  { 3, &SystemZDescs.OperandInfo[1405] },  // Inst #2240 = STOCFHAsmHE
  { 3, &SystemZDescs.OperandInfo[1405] },  // Inst #2239 = STOCFHAsmH
  { 3, &SystemZDescs.OperandInfo[1405] },  // Inst #2238 = STOCFHAsmE
  { 4, &SystemZDescs.OperandInfo[1401] },  // Inst #2237 = STOCFHAsm
  { 5, &SystemZDescs.OperandInfo[1396] },  // Inst #2236 = STOCFH
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #2235 = STOCAsmZ
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #2234 = STOCAsmP
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #2233 = STOCAsmO
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #2232 = STOCAsmNZ
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #2231 = STOCAsmNP
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #2230 = STOCAsmNO
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #2229 = STOCAsmNM
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #2228 = STOCAsmNLH
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #2227 = STOCAsmNLE
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #2226 = STOCAsmNL
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #2225 = STOCAsmNHE
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #2224 = STOCAsmNH
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #2223 = STOCAsmNE
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #2222 = STOCAsmM
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #2221 = STOCAsmLH
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #2220 = STOCAsmLE
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #2219 = STOCAsmL
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #2218 = STOCAsmHE
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #2217 = STOCAsmH
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #2216 = STOCAsmE
  { 4, &SystemZDescs.OperandInfo[825] },  // Inst #2215 = STOCAsm
  { 5, &SystemZDescs.OperandInfo[1391] },  // Inst #2214 = STOC
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #2213 = STNSM
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #2212 = STMY
  { 4, &SystemZDescs.OperandInfo[1130] },  // Inst #2211 = STMH
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #2210 = STMG
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #2209 = STM
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2208 = STIDP
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #2207 = STHY
  { 2, &SystemZDescs.OperandInfo[753] },  // Inst #2206 = STHRL
  { 4, &SystemZDescs.OperandInfo[745] },  // Inst #2205 = STHH
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #2204 = STH
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #2203 = STGSC
  { 2, &SystemZDescs.OperandInfo[704] },  // Inst #2202 = STGRL
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #2201 = STG
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2200 = STFPC
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2199 = STFLE
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2198 = STFL
  { 4, &SystemZDescs.OperandInfo[745] },  // Inst #2197 = STFH
  { 4, &SystemZDescs.OperandInfo[643] },  // Inst #2196 = STEY
  { 4, &SystemZDescs.OperandInfo[643] },  // Inst #2195 = STE
  { 4, &SystemZDescs.OperandInfo[615] },  // Inst #2194 = STDY
  { 4, &SystemZDescs.OperandInfo[615] },  // Inst #2193 = STD
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #2192 = STCY
  { 4, &SystemZDescs.OperandInfo[1105] },  // Inst #2191 = STCTL
  { 4, &SystemZDescs.OperandInfo[1105] },  // Inst #2190 = STCTG
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2189 = STCRW
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2188 = STCPS
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #2187 = STCMY
  { 4, &SystemZDescs.OperandInfo[799] },  // Inst #2186 = STCMH
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #2185 = STCM
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2184 = STCKF
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2183 = STCKE
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2182 = STCKC
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2181 = STCK
  { 4, &SystemZDescs.OperandInfo[745] },  // Inst #2180 = STCH
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #2179 = STC
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2178 = STBEAR
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2177 = STAP
  { 4, &SystemZDescs.OperandInfo[1092] },  // Inst #2176 = STAMY
  { 4, &SystemZDescs.OperandInfo[1092] },  // Inst #2175 = STAM
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #2174 = ST
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2173 = SSM
  { 2, &SystemZDescs.OperandInfo[921] },  // Inst #2172 = SSKEOpt
  { 3, &SystemZDescs.OperandInfo[1388] },  // Inst #2171 = SSKE
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2170 = SSCH
  { 1, &SystemZDescs.OperandInfo[923] },  // Inst #2169 = SSAR
  { 1, &SystemZDescs.OperandInfo[290] },  // Inst #2168 = SSAIR
  { 5, &SystemZDescs.OperandInfo[1375] },  // Inst #2167 = SRXT
  { 4, &SystemZDescs.OperandInfo[821] },  // Inst #2166 = SRSTU
  { 4, &SystemZDescs.OperandInfo[821] },  // Inst #2165 = SRST
  { 6, &SystemZDescs.OperandInfo[1382] },  // Inst #2164 = SRP
  { 2, &SystemZDescs.OperandInfo[1380] },  // Inst #2163 = SRNMT
  { 2, &SystemZDescs.OperandInfo[1380] },  // Inst #2162 = SRNMB
  { 2, &SystemZDescs.OperandInfo[1380] },  // Inst #2161 = SRNM
  { 4, &SystemZDescs.OperandInfo[1348] },  // Inst #2160 = SRLK
  { 4, &SystemZDescs.OperandInfo[917] },  // Inst #2159 = SRLG
  { 4, &SystemZDescs.OperandInfo[1367] },  // Inst #2158 = SRL
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #2157 = SRK
  { 5, &SystemZDescs.OperandInfo[144] },  // Inst #2156 = SRDT
  { 4, &SystemZDescs.OperandInfo[1371] },  // Inst #2155 = SRDL
  { 4, &SystemZDescs.OperandInfo[1371] },  // Inst #2154 = SRDA
  { 4, &SystemZDescs.OperandInfo[1348] },  // Inst #2153 = SRAK
  { 4, &SystemZDescs.OperandInfo[917] },  // Inst #2152 = SRAG
  { 4, &SystemZDescs.OperandInfo[1367] },  // Inst #2151 = SRA
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #2150 = SR
  { 2, &SystemZDescs.OperandInfo[661] },  // Inst #2149 = SQXR
  { 2, &SystemZDescs.OperandInfo[661] },  // Inst #2148 = SQXBR
  { 2, &SystemZDescs.OperandInfo[647] },  // Inst #2147 = SQER
  { 2, &SystemZDescs.OperandInfo[647] },  // Inst #2146 = SQEBR
  { 4, &SystemZDescs.OperandInfo[643] },  // Inst #2145 = SQEB
  { 4, &SystemZDescs.OperandInfo[643] },  // Inst #2144 = SQE
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #2143 = SQDR
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #2142 = SQDBR
  { 4, &SystemZDescs.OperandInfo[615] },  // Inst #2141 = SQDB
  { 4, &SystemZDescs.OperandInfo[615] },  // Inst #2140 = SQD
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2139 = SPX
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2138 = SPT
  { 1, &SystemZDescs.OperandInfo[923] },  // Inst #2137 = SPM
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2136 = SPKA
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #2135 = SPCTR
  { 6, &SystemZDescs.OperandInfo[532] },  // Inst #2134 = SP
  { 4, &SystemZDescs.OperandInfo[782] },  // Inst #2133 = SORTL
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #2132 = SLY
  { 5, &SystemZDescs.OperandInfo[1375] },  // Inst #2131 = SLXT
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #2130 = SLRK
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #2129 = SLR
  { 4, &SystemZDescs.OperandInfo[1348] },  // Inst #2128 = SLLK
  { 4, &SystemZDescs.OperandInfo[917] },  // Inst #2127 = SLLG
  { 4, &SystemZDescs.OperandInfo[1367] },  // Inst #2126 = SLL
  { 3, &SystemZDescs.OperandInfo[520] },  // Inst #2125 = SLHHLR
  { 3, &SystemZDescs.OperandInfo[517] },  // Inst #2124 = SLHHHR
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #2123 = SLGRK
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #2122 = SLGR
  { 3, &SystemZDescs.OperandInfo[511] },  // Inst #2121 = SLGFR
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #2120 = SLGFI
  { 5, &SystemZDescs.OperandInfo[506] },  // Inst #2119 = SLGF
  { 5, &SystemZDescs.OperandInfo[506] },  // Inst #2118 = SLG
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #2117 = SLFI
  { 5, &SystemZDescs.OperandInfo[144] },  // Inst #2116 = SLDT
  { 4, &SystemZDescs.OperandInfo[1371] },  // Inst #2115 = SLDL
  { 4, &SystemZDescs.OperandInfo[1371] },  // Inst #2114 = SLDA
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #2113 = SLBR
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #2112 = SLBGR
  { 5, &SystemZDescs.OperandInfo[506] },  // Inst #2111 = SLBG
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #2110 = SLB
  { 4, &SystemZDescs.OperandInfo[1348] },  // Inst #2109 = SLAK
  { 4, &SystemZDescs.OperandInfo[917] },  // Inst #2108 = SLAG
  { 4, &SystemZDescs.OperandInfo[1367] },  // Inst #2107 = SLA
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #2106 = SL
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #2105 = SIGP
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2104 = SIGA
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2103 = SIE
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #2102 = SHY
  { 3, &SystemZDescs.OperandInfo[520] },  // Inst #2101 = SHHLR
  { 3, &SystemZDescs.OperandInfo[517] },  // Inst #2100 = SHHHR
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #2099 = SH
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #2098 = SGRK
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #2097 = SGR
  { 5, &SystemZDescs.OperandInfo[506] },  // Inst #2096 = SGH
  { 3, &SystemZDescs.OperandInfo[511] },  // Inst #2095 = SGFR
  { 5, &SystemZDescs.OperandInfo[506] },  // Inst #2094 = SGF
  { 5, &SystemZDescs.OperandInfo[506] },  // Inst #2093 = SG
  { 1, &SystemZDescs.OperandInfo[923] },  // Inst #2092 = SFPC
  { 1, &SystemZDescs.OperandInfo[923] },  // Inst #2091 = SFASR
  { 3, &SystemZDescs.OperandInfo[500] },  // Inst #2090 = SER
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #2089 = SELRAsmZ
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #2088 = SELRAsmP
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #2087 = SELRAsmO
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #2086 = SELRAsmNZ
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #2085 = SELRAsmNP
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #2084 = SELRAsmNO
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #2083 = SELRAsmNM
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #2082 = SELRAsmNLH
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #2081 = SELRAsmNLE
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #2080 = SELRAsmNL
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #2079 = SELRAsmNHE
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #2078 = SELRAsmNH
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #2077 = SELRAsmNE
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #2076 = SELRAsmM
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #2075 = SELRAsmLH
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #2074 = SELRAsmLE
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #2073 = SELRAsmL
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #2072 = SELRAsmHE
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #2071 = SELRAsmH
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #2070 = SELRAsmE
  { 4, &SystemZDescs.OperandInfo[1363] },  // Inst #2069 = SELRAsm
  { 5, &SystemZDescs.OperandInfo[420] },  // Inst #2068 = SELR
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #2067 = SELGRAsmZ
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #2066 = SELGRAsmP
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #2065 = SELGRAsmO
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #2064 = SELGRAsmNZ
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #2063 = SELGRAsmNP
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #2062 = SELGRAsmNO
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #2061 = SELGRAsmNM
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #2060 = SELGRAsmNLH
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #2059 = SELGRAsmNLE
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #2058 = SELGRAsmNL
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #2057 = SELGRAsmNHE
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #2056 = SELGRAsmNH
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #2055 = SELGRAsmNE
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #2054 = SELGRAsmM
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #2053 = SELGRAsmLH
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #2052 = SELGRAsmLE
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #2051 = SELGRAsmL
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #2050 = SELGRAsmHE
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #2049 = SELGRAsmH
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #2048 = SELGRAsmE
  { 4, &SystemZDescs.OperandInfo[965] },  // Inst #2047 = SELGRAsm
  { 5, &SystemZDescs.OperandInfo[425] },  // Inst #2046 = SELGR
  { 3, &SystemZDescs.OperandInfo[517] },  // Inst #2045 = SELFHRAsmZ
  { 3, &SystemZDescs.OperandInfo[517] },  // Inst #2044 = SELFHRAsmP
  { 3, &SystemZDescs.OperandInfo[517] },  // Inst #2043 = SELFHRAsmO
  { 3, &SystemZDescs.OperandInfo[517] },  // Inst #2042 = SELFHRAsmNZ
  { 3, &SystemZDescs.OperandInfo[517] },  // Inst #2041 = SELFHRAsmNP
  { 3, &SystemZDescs.OperandInfo[517] },  // Inst #2040 = SELFHRAsmNO
  { 3, &SystemZDescs.OperandInfo[517] },  // Inst #2039 = SELFHRAsmNM
  { 3, &SystemZDescs.OperandInfo[517] },  // Inst #2038 = SELFHRAsmNLH
  { 3, &SystemZDescs.OperandInfo[517] },  // Inst #2037 = SELFHRAsmNLE
  { 3, &SystemZDescs.OperandInfo[517] },  // Inst #2036 = SELFHRAsmNL
  { 3, &SystemZDescs.OperandInfo[517] },  // Inst #2035 = SELFHRAsmNHE
  { 3, &SystemZDescs.OperandInfo[517] },  // Inst #2034 = SELFHRAsmNH
  { 3, &SystemZDescs.OperandInfo[517] },  // Inst #2033 = SELFHRAsmNE
  { 3, &SystemZDescs.OperandInfo[517] },  // Inst #2032 = SELFHRAsmM
  { 3, &SystemZDescs.OperandInfo[517] },  // Inst #2031 = SELFHRAsmLH
  { 3, &SystemZDescs.OperandInfo[517] },  // Inst #2030 = SELFHRAsmLE
  { 3, &SystemZDescs.OperandInfo[517] },  // Inst #2029 = SELFHRAsmL
  { 3, &SystemZDescs.OperandInfo[517] },  // Inst #2028 = SELFHRAsmHE
  { 3, &SystemZDescs.OperandInfo[517] },  // Inst #2027 = SELFHRAsmH
  { 3, &SystemZDescs.OperandInfo[517] },  // Inst #2026 = SELFHRAsmE
  { 4, &SystemZDescs.OperandInfo[1359] },  // Inst #2025 = SELFHRAsm
  { 5, &SystemZDescs.OperandInfo[1354] },  // Inst #2024 = SELFHR
  { 3, &SystemZDescs.OperandInfo[500] },  // Inst #2023 = SEBR
  { 5, &SystemZDescs.OperandInfo[495] },  // Inst #2022 = SEB
  { 5, &SystemZDescs.OperandInfo[495] },  // Inst #2021 = SE
  { 4, &SystemZDescs.OperandInfo[491] },  // Inst #2020 = SDTRA
  { 3, &SystemZDescs.OperandInfo[488] },  // Inst #2019 = SDTR
  { 3, &SystemZDescs.OperandInfo[485] },  // Inst #2018 = SDR
  { 3, &SystemZDescs.OperandInfo[485] },  // Inst #2017 = SDBR
  { 5, &SystemZDescs.OperandInfo[480] },  // Inst #2016 = SDB
  { 5, &SystemZDescs.OperandInfo[480] },  // Inst #2015 = SD
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #2014 = SCKPF
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2013 = SCKC
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2012 = SCK
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #2011 = SCHM
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #2010 = SCCTR
  { 2, &SystemZDescs.OperandInfo[1352] },  // Inst #2009 = SAR
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #2008 = SAM64
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #2007 = SAM31
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #2006 = SAM24
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #2005 = SAL
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2004 = SACF
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #2003 = SAC
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #2002 = S
  { 6, &SystemZDescs.OperandInfo[1330] },  // Inst #2001 = RXSBG
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #2000 = RSCH
  { 5, &SystemZDescs.OperandInfo[1325] },  // Inst #1999 = RRXTR
  { 5, &SystemZDescs.OperandInfo[902] },  // Inst #1998 = RRDTR
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #1997 = RRBM
  { 2, &SystemZDescs.OperandInfo[921] },  // Inst #1996 = RRBE
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #1995 = RP
  { 6, &SystemZDescs.OperandInfo[1330] },  // Inst #1994 = ROSBG
  { 6, &SystemZDescs.OperandInfo[1330] },  // Inst #1993 = RNSBG
  { 4, &SystemZDescs.OperandInfo[917] },  // Inst #1992 = RLLG
  { 4, &SystemZDescs.OperandInfo[1348] },  // Inst #1991 = RLL
  { 6, &SystemZDescs.OperandInfo[1342] },  // Inst #1990 = RISBLG
  { 6, &SystemZDescs.OperandInfo[1336] },  // Inst #1989 = RISBHG
  { 6, &SystemZDescs.OperandInfo[1330] },  // Inst #1988 = RISBGN
  { 6, &SystemZDescs.OperandInfo[391] },  // Inst #1987 = RISBG32
  { 6, &SystemZDescs.OperandInfo[1330] },  // Inst #1986 = RISBG
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #1985 = RDPOpt
  { 4, &SystemZDescs.OperandInfo[965] },  // Inst #1984 = RDP
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #1983 = RCHP
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #1982 = QSI
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #1981 = QPACI
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #1980 = QCTRI
  { 5, &SystemZDescs.OperandInfo[1325] },  // Inst #1979 = QAXTR
  { 5, &SystemZDescs.OperandInfo[902] },  // Inst #1978 = QADTR
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #1977 = PTLB
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #1976 = PTI
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #1975 = PTFF
  { 2, &SystemZDescs.OperandInfo[1323] },  // Inst #1974 = PTF
  { 2, &SystemZDescs.OperandInfo[921] },  // Inst #1973 = PT
  { 4, &SystemZDescs.OperandInfo[782] },  // Inst #1972 = PRNO
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #1971 = PR
  { 4, &SystemZDescs.OperandInfo[782] },  // Inst #1970 = PPNO
  { 3, &SystemZDescs.OperandInfo[211] },  // Inst #1969 = PPA
  { 3, &SystemZDescs.OperandInfo[211] },  // Inst #1968 = POPCNTOpt
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #1967 = POPCNT
  { 6, &SystemZDescs.OperandInfo[1317] },  // Inst #1966 = PLO
  { 5, &SystemZDescs.OperandInfo[1312] },  // Inst #1965 = PKU
  { 5, &SystemZDescs.OperandInfo[1312] },  // Inst #1964 = PKA
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #1963 = PGOUT
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #1962 = PGIN
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #1961 = PFPO
  { 3, &SystemZDescs.OperandInfo[1309] },  // Inst #1960 = PFMF
  { 2, &SystemZDescs.OperandInfo[582] },  // Inst #1959 = PFDRL
  { 4, &SystemZDescs.OperandInfo[560] },  // Inst #1958 = PFD
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #1957 = PCKMO
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #1956 = PCC
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #1955 = PC
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #1954 = PALB
  { 6, &SystemZDescs.OperandInfo[532] },  // Inst #1953 = PACK
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #1952 = OY
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #1951 = ORK
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #1950 = OR
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #1949 = OIY
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1948 = OILL
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1947 = OILH
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1946 = OILF
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1945 = OIHL
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1944 = OIHH
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1943 = OIHF
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #1942 = OI
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #1941 = OGRK
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #1940 = OGR
  { 5, &SystemZDescs.OperandInfo[506] },  // Inst #1939 = OG
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #1938 = OCRK
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #1937 = OCGRK
  { 5, &SystemZDescs.OperandInfo[777] },  // Inst #1936 = OC
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #1935 = O
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #1934 = NY
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #1933 = NXRK
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #1932 = NXGRK
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1931 = NTSTG
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #1930 = NRK
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #1929 = NR
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #1928 = NORK
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #1927 = NOP_bare
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #1926 = NOGRK
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #1925 = NNRK
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #1924 = NNPA
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #1923 = NNGRK
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #1922 = NIY
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1921 = NILL
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1920 = NILH
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1919 = NILF
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1918 = NIHL
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1917 = NIHH
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1916 = NIHF
  { 2, &SystemZDescs.OperandInfo[21] },  // Inst #1915 = NIAI
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #1914 = NI
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #1913 = NGRK
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #1912 = NGR
  { 5, &SystemZDescs.OperandInfo[506] },  // Inst #1911 = NG
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #1910 = NCRK
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #1909 = NCGRK
  { 5, &SystemZDescs.OperandInfo[777] },  // Inst #1908 = NC
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #1907 = N
  { 3, &SystemZDescs.OperandInfo[1306] },  // Inst #1906 = MYR
  { 3, &SystemZDescs.OperandInfo[488] },  // Inst #1905 = MYLR
  { 5, &SystemZDescs.OperandInfo[144] },  // Inst #1904 = MYL
  { 3, &SystemZDescs.OperandInfo[488] },  // Inst #1903 = MYHR
  { 5, &SystemZDescs.OperandInfo[144] },  // Inst #1902 = MYH
  { 5, &SystemZDescs.OperandInfo[1301] },  // Inst #1901 = MY
  { 4, &SystemZDescs.OperandInfo[544] },  // Inst #1900 = MXTRA
  { 3, &SystemZDescs.OperandInfo[541] },  // Inst #1899 = MXTR
  { 3, &SystemZDescs.OperandInfo[538] },  // Inst #1898 = MXR
  { 3, &SystemZDescs.OperandInfo[1298] },  // Inst #1897 = MXDR
  { 3, &SystemZDescs.OperandInfo[1298] },  // Inst #1896 = MXDBR
  { 5, &SystemZDescs.OperandInfo[1293] },  // Inst #1895 = MXDB
  { 5, &SystemZDescs.OperandInfo[1293] },  // Inst #1894 = MXD
  { 3, &SystemZDescs.OperandInfo[538] },  // Inst #1893 = MXBR
  { 5, &SystemZDescs.OperandInfo[777] },  // Inst #1892 = MVZ
  { 4, &SystemZDescs.OperandInfo[821] },  // Inst #1891 = MVST
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #1890 = MVPG
  { 6, &SystemZDescs.OperandInfo[532] },  // Inst #1889 = MVO
  { 5, &SystemZDescs.OperandInfo[777] },  // Inst #1888 = MVN
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #1887 = MVIY
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #1886 = MVI
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #1885 = MVHI
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #1884 = MVHHI
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #1883 = MVGHI
  { 4, &SystemZDescs.OperandInfo[1096] },  // Inst #1882 = MVCSK
  { 6, &SystemZDescs.OperandInfo[1287] },  // Inst #1881 = MVCS
  { 4, &SystemZDescs.OperandInfo[1096] },  // Inst #1880 = MVCRL
  { 6, &SystemZDescs.OperandInfo[1287] },  // Inst #1879 = MVCP
  { 5, &SystemZDescs.OperandInfo[861] },  // Inst #1878 = MVCOS
  { 6, &SystemZDescs.OperandInfo[786] },  // Inst #1877 = MVCLU
  { 6, &SystemZDescs.OperandInfo[786] },  // Inst #1876 = MVCLE
  { 4, &SystemZDescs.OperandInfo[782] },  // Inst #1875 = MVCL
  { 6, &SystemZDescs.OperandInfo[1287] },  // Inst #1874 = MVCK
  { 5, &SystemZDescs.OperandInfo[777] },  // Inst #1873 = MVCIN
  { 4, &SystemZDescs.OperandInfo[1096] },  // Inst #1872 = MVCDK
  { 5, &SystemZDescs.OperandInfo[777] },  // Inst #1871 = MVC
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #1870 = MSY
  { 1, &SystemZDescs.OperandInfo[1286] },  // Inst #1869 = MSTA
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #1868 = MSRKC
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #1867 = MSR
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #1866 = MSGRKC
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #1865 = MSGR
  { 3, &SystemZDescs.OperandInfo[511] },  // Inst #1864 = MSGFR
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #1863 = MSGFI
  { 5, &SystemZDescs.OperandInfo[506] },  // Inst #1862 = MSGF
  { 5, &SystemZDescs.OperandInfo[506] },  // Inst #1861 = MSGC
  { 5, &SystemZDescs.OperandInfo[506] },  // Inst #1860 = MSG
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1859 = MSFI
  { 4, &SystemZDescs.OperandInfo[1269] },  // Inst #1858 = MSER
  { 4, &SystemZDescs.OperandInfo[1269] },  // Inst #1857 = MSEBR
  { 6, &SystemZDescs.OperandInfo[1263] },  // Inst #1856 = MSEB
  { 6, &SystemZDescs.OperandInfo[1263] },  // Inst #1855 = MSE
  { 4, &SystemZDescs.OperandInfo[1259] },  // Inst #1854 = MSDR
  { 4, &SystemZDescs.OperandInfo[1259] },  // Inst #1853 = MSDBR
  { 6, &SystemZDescs.OperandInfo[1253] },  // Inst #1852 = MSDB
  { 6, &SystemZDescs.OperandInfo[1253] },  // Inst #1851 = MSD
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #1850 = MSCH
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #1849 = MSC
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #1848 = MS
  { 3, &SystemZDescs.OperandInfo[912] },  // Inst #1847 = MR
  { 6, &SystemZDescs.OperandInfo[532] },  // Inst #1846 = MP
  { 3, &SystemZDescs.OperandInfo[912] },  // Inst #1845 = MLR
  { 3, &SystemZDescs.OperandInfo[858] },  // Inst #1844 = MLGR
  { 5, &SystemZDescs.OperandInfo[892] },  // Inst #1843 = MLG
  { 5, &SystemZDescs.OperandInfo[892] },  // Inst #1842 = ML
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #1841 = MHY
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1840 = MHI
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #1839 = MH
  { 3, &SystemZDescs.OperandInfo[367] },  // Inst #1838 = MGRK
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #1837 = MGHI
  { 5, &SystemZDescs.OperandInfo[506] },  // Inst #1836 = MGH
  { 5, &SystemZDescs.OperandInfo[892] },  // Inst #1835 = MG
  { 5, &SystemZDescs.OperandInfo[892] },  // Inst #1834 = MFY
  { 3, &SystemZDescs.OperandInfo[1283] },  // Inst #1833 = MER
  { 3, &SystemZDescs.OperandInfo[500] },  // Inst #1832 = MEER
  { 3, &SystemZDescs.OperandInfo[500] },  // Inst #1831 = MEEBR
  { 5, &SystemZDescs.OperandInfo[495] },  // Inst #1830 = MEEB
  { 5, &SystemZDescs.OperandInfo[495] },  // Inst #1829 = MEE
  { 5, &SystemZDescs.OperandInfo[480] },  // Inst #1828 = ME
  { 4, &SystemZDescs.OperandInfo[491] },  // Inst #1827 = MDTRA
  { 3, &SystemZDescs.OperandInfo[488] },  // Inst #1826 = MDTR
  { 3, &SystemZDescs.OperandInfo[485] },  // Inst #1825 = MDR
  { 3, &SystemZDescs.OperandInfo[1283] },  // Inst #1824 = MDER
  { 3, &SystemZDescs.OperandInfo[1283] },  // Inst #1823 = MDEBR
  { 5, &SystemZDescs.OperandInfo[480] },  // Inst #1822 = MDEB
  { 5, &SystemZDescs.OperandInfo[480] },  // Inst #1821 = MDE
  { 3, &SystemZDescs.OperandInfo[485] },  // Inst #1820 = MDBR
  { 5, &SystemZDescs.OperandInfo[480] },  // Inst #1819 = MDB
  { 5, &SystemZDescs.OperandInfo[480] },  // Inst #1818 = MD
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #1817 = MC
  { 4, &SystemZDescs.OperandInfo[1279] },  // Inst #1816 = MAYR
  { 4, &SystemZDescs.OperandInfo[1259] },  // Inst #1815 = MAYLR
  { 6, &SystemZDescs.OperandInfo[1253] },  // Inst #1814 = MAYL
  { 4, &SystemZDescs.OperandInfo[1259] },  // Inst #1813 = MAYHR
  { 6, &SystemZDescs.OperandInfo[1253] },  // Inst #1812 = MAYH
  { 6, &SystemZDescs.OperandInfo[1273] },  // Inst #1811 = MAY
  { 4, &SystemZDescs.OperandInfo[1269] },  // Inst #1810 = MAER
  { 4, &SystemZDescs.OperandInfo[1269] },  // Inst #1809 = MAEBR
  { 6, &SystemZDescs.OperandInfo[1263] },  // Inst #1808 = MAEB
  { 6, &SystemZDescs.OperandInfo[1263] },  // Inst #1807 = MAE
  { 4, &SystemZDescs.OperandInfo[1259] },  // Inst #1806 = MADR
  { 4, &SystemZDescs.OperandInfo[1259] },  // Inst #1805 = MADBR
  { 6, &SystemZDescs.OperandInfo[1253] },  // Inst #1804 = MADB
  { 6, &SystemZDescs.OperandInfo[1253] },  // Inst #1803 = MAD
  { 5, &SystemZDescs.OperandInfo[892] },  // Inst #1802 = M
  { 1, &SystemZDescs.OperandInfo[334] },  // Inst #1801 = LZXR
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1800 = LZRG
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #1799 = LZRF
  { 1, &SystemZDescs.OperandInfo[333] },  // Inst #1798 = LZER
  { 1, &SystemZDescs.OperandInfo[332] },  // Inst #1797 = LZDR
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #1796 = LY
  { 2, &SystemZDescs.OperandInfo[661] },  // Inst #1795 = LXR
  { 2, &SystemZDescs.OperandInfo[1251] },  // Inst #1794 = LXER
  { 2, &SystemZDescs.OperandInfo[1251] },  // Inst #1793 = LXEBR
  { 4, &SystemZDescs.OperandInfo[335] },  // Inst #1792 = LXEB
  { 4, &SystemZDescs.OperandInfo[335] },  // Inst #1791 = LXE
  { 3, &SystemZDescs.OperandInfo[1248] },  // Inst #1790 = LXDTR
  { 2, &SystemZDescs.OperandInfo[1246] },  // Inst #1789 = LXDR
  { 2, &SystemZDescs.OperandInfo[1246] },  // Inst #1788 = LXDBR
  { 4, &SystemZDescs.OperandInfo[335] },  // Inst #1787 = LXDB
  { 4, &SystemZDescs.OperandInfo[335] },  // Inst #1786 = LXD
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #1785 = LURAG
  { 2, &SystemZDescs.OperandInfo[921] },  // Inst #1784 = LURA
  { 2, &SystemZDescs.OperandInfo[661] },  // Inst #1783 = LTXTR
  { 2, &SystemZDescs.OperandInfo[661] },  // Inst #1782 = LTXR
  { 2, &SystemZDescs.OperandInfo[661] },  // Inst #1781 = LTXBR
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1780 = LTR
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #1779 = LTGR
  { 2, &SystemZDescs.OperandInfo[702] },  // Inst #1778 = LTGFR
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1777 = LTGF
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1776 = LTG
  { 2, &SystemZDescs.OperandInfo[647] },  // Inst #1775 = LTER
  { 2, &SystemZDescs.OperandInfo[647] },  // Inst #1774 = LTEBR
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #1773 = LTDTR
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #1772 = LTDR
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #1771 = LTDBR
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #1770 = LT
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #1769 = LSCTL
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1768 = LRVR
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #1767 = LRVH
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #1766 = LRVGR
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1765 = LRVG
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #1764 = LRV
  { 2, &SystemZDescs.OperandInfo[753] },  // Inst #1763 = LRL
  { 2, &SystemZDescs.OperandInfo[1116] },  // Inst #1762 = LRER
  { 2, &SystemZDescs.OperandInfo[1114] },  // Inst #1761 = LRDR
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1760 = LRAY
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1759 = LRAG
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1758 = LRA
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1757 = LR
  { 2, &SystemZDescs.OperandInfo[661] },  // Inst #1756 = LPXR
  { 2, &SystemZDescs.OperandInfo[661] },  // Inst #1755 = LPXBR
  { 5, &SystemZDescs.OperandInfo[1241] },  // Inst #1754 = LPTEA
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #1753 = LPSWEY
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #1752 = LPSWE
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #1751 = LPSW
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1750 = LPR
  { 4, &SystemZDescs.OperandInfo[294] },  // Inst #1749 = LPQ
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #1748 = LPP
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #1747 = LPGR
  { 2, &SystemZDescs.OperandInfo[702] },  // Inst #1746 = LPGFR
  { 2, &SystemZDescs.OperandInfo[647] },  // Inst #1745 = LPER
  { 2, &SystemZDescs.OperandInfo[647] },  // Inst #1744 = LPEBR
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #1743 = LPDR
  { 5, &SystemZDescs.OperandInfo[1236] },  // Inst #1742 = LPDG
  { 2, &SystemZDescs.OperandInfo[647] },  // Inst #1741 = LPDFR_32
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #1740 = LPDFR
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #1739 = LPDBR
  { 5, &SystemZDescs.OperandInfo[1236] },  // Inst #1738 = LPD
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #1737 = LPCTL
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #1736 = LOCRAsmZ
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #1735 = LOCRAsmP
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #1734 = LOCRAsmO
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #1733 = LOCRAsmNZ
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #1732 = LOCRAsmNP
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #1731 = LOCRAsmNO
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #1730 = LOCRAsmNM
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #1729 = LOCRAsmNLH
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #1728 = LOCRAsmNLE
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #1727 = LOCRAsmNL
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #1726 = LOCRAsmNHE
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #1725 = LOCRAsmNH
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #1724 = LOCRAsmNE
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #1723 = LOCRAsmM
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #1722 = LOCRAsmLH
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #1721 = LOCRAsmLE
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #1720 = LOCRAsmL
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #1719 = LOCRAsmHE
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #1718 = LOCRAsmH
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #1717 = LOCRAsmE
  { 4, &SystemZDescs.OperandInfo[1232] },  // Inst #1716 = LOCRAsm
  { 5, &SystemZDescs.OperandInfo[1227] },  // Inst #1715 = LOCR
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1714 = LOCHIAsmZ
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1713 = LOCHIAsmP
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1712 = LOCHIAsmO
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1711 = LOCHIAsmNZ
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1710 = LOCHIAsmNP
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1709 = LOCHIAsmNO
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1708 = LOCHIAsmNM
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1707 = LOCHIAsmNLH
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1706 = LOCHIAsmNLE
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1705 = LOCHIAsmNL
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1704 = LOCHIAsmNHE
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1703 = LOCHIAsmNH
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1702 = LOCHIAsmNE
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1701 = LOCHIAsmM
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1700 = LOCHIAsmLH
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1699 = LOCHIAsmLE
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1698 = LOCHIAsmL
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1697 = LOCHIAsmHE
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1696 = LOCHIAsmH
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1695 = LOCHIAsmE
  { 4, &SystemZDescs.OperandInfo[1223] },  // Inst #1694 = LOCHIAsm
  { 5, &SystemZDescs.OperandInfo[1218] },  // Inst #1693 = LOCHI
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1692 = LOCHHIAsmZ
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1691 = LOCHHIAsmP
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1690 = LOCHHIAsmO
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1689 = LOCHHIAsmNZ
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1688 = LOCHHIAsmNP
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1687 = LOCHHIAsmNO
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1686 = LOCHHIAsmNM
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1685 = LOCHHIAsmNLH
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1684 = LOCHHIAsmNLE
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1683 = LOCHHIAsmNL
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1682 = LOCHHIAsmNHE
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1681 = LOCHHIAsmNH
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1680 = LOCHHIAsmNE
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1679 = LOCHHIAsmM
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1678 = LOCHHIAsmLH
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1677 = LOCHHIAsmLE
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1676 = LOCHHIAsmL
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1675 = LOCHHIAsmHE
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1674 = LOCHHIAsmH
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1673 = LOCHHIAsmE
  { 4, &SystemZDescs.OperandInfo[1214] },  // Inst #1672 = LOCHHIAsm
  { 5, &SystemZDescs.OperandInfo[1209] },  // Inst #1671 = LOCHHI
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #1670 = LOCGRAsmZ
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #1669 = LOCGRAsmP
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #1668 = LOCGRAsmO
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #1667 = LOCGRAsmNZ
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #1666 = LOCGRAsmNP
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #1665 = LOCGRAsmNO
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #1664 = LOCGRAsmNM
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #1663 = LOCGRAsmNLH
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #1662 = LOCGRAsmNLE
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #1661 = LOCGRAsmNL
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #1660 = LOCGRAsmNHE
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #1659 = LOCGRAsmNH
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #1658 = LOCGRAsmNE
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #1657 = LOCGRAsmM
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #1656 = LOCGRAsmLH
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #1655 = LOCGRAsmLE
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #1654 = LOCGRAsmL
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #1653 = LOCGRAsmHE
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #1652 = LOCGRAsmH
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #1651 = LOCGRAsmE
  { 4, &SystemZDescs.OperandInfo[1205] },  // Inst #1650 = LOCGRAsm
  { 5, &SystemZDescs.OperandInfo[1200] },  // Inst #1649 = LOCGR
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #1648 = LOCGHIAsmZ
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #1647 = LOCGHIAsmP
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #1646 = LOCGHIAsmO
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #1645 = LOCGHIAsmNZ
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #1644 = LOCGHIAsmNP
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #1643 = LOCGHIAsmNO
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #1642 = LOCGHIAsmNM
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #1641 = LOCGHIAsmNLH
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #1640 = LOCGHIAsmNLE
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #1639 = LOCGHIAsmNL
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #1638 = LOCGHIAsmNHE
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #1637 = LOCGHIAsmNH
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #1636 = LOCGHIAsmNE
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #1635 = LOCGHIAsmM
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #1634 = LOCGHIAsmLH
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #1633 = LOCGHIAsmLE
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #1632 = LOCGHIAsmL
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #1631 = LOCGHIAsmHE
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #1630 = LOCGHIAsmH
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #1629 = LOCGHIAsmE
  { 4, &SystemZDescs.OperandInfo[1196] },  // Inst #1628 = LOCGHIAsm
  { 5, &SystemZDescs.OperandInfo[1191] },  // Inst #1627 = LOCGHI
  { 4, &SystemZDescs.OperandInfo[1187] },  // Inst #1626 = LOCGAsmZ
  { 4, &SystemZDescs.OperandInfo[1187] },  // Inst #1625 = LOCGAsmP
  { 4, &SystemZDescs.OperandInfo[1187] },  // Inst #1624 = LOCGAsmO
  { 4, &SystemZDescs.OperandInfo[1187] },  // Inst #1623 = LOCGAsmNZ
  { 4, &SystemZDescs.OperandInfo[1187] },  // Inst #1622 = LOCGAsmNP
  { 4, &SystemZDescs.OperandInfo[1187] },  // Inst #1621 = LOCGAsmNO
  { 4, &SystemZDescs.OperandInfo[1187] },  // Inst #1620 = LOCGAsmNM
  { 4, &SystemZDescs.OperandInfo[1187] },  // Inst #1619 = LOCGAsmNLH
  { 4, &SystemZDescs.OperandInfo[1187] },  // Inst #1618 = LOCGAsmNLE
  { 4, &SystemZDescs.OperandInfo[1187] },  // Inst #1617 = LOCGAsmNL
  { 4, &SystemZDescs.OperandInfo[1187] },  // Inst #1616 = LOCGAsmNHE
  { 4, &SystemZDescs.OperandInfo[1187] },  // Inst #1615 = LOCGAsmNH
  { 4, &SystemZDescs.OperandInfo[1187] },  // Inst #1614 = LOCGAsmNE
  { 4, &SystemZDescs.OperandInfo[1187] },  // Inst #1613 = LOCGAsmM
  { 4, &SystemZDescs.OperandInfo[1187] },  // Inst #1612 = LOCGAsmLH
  { 4, &SystemZDescs.OperandInfo[1187] },  // Inst #1611 = LOCGAsmLE
  { 4, &SystemZDescs.OperandInfo[1187] },  // Inst #1610 = LOCGAsmL
  { 4, &SystemZDescs.OperandInfo[1187] },  // Inst #1609 = LOCGAsmHE
  { 4, &SystemZDescs.OperandInfo[1187] },  // Inst #1608 = LOCGAsmH
  { 4, &SystemZDescs.OperandInfo[1187] },  // Inst #1607 = LOCGAsmE
  { 5, &SystemZDescs.OperandInfo[1182] },  // Inst #1606 = LOCGAsm
  { 6, &SystemZDescs.OperandInfo[1176] },  // Inst #1605 = LOCG
  { 3, &SystemZDescs.OperandInfo[1173] },  // Inst #1604 = LOCFHRAsmZ
  { 3, &SystemZDescs.OperandInfo[1173] },  // Inst #1603 = LOCFHRAsmP
  { 3, &SystemZDescs.OperandInfo[1173] },  // Inst #1602 = LOCFHRAsmO
  { 3, &SystemZDescs.OperandInfo[1173] },  // Inst #1601 = LOCFHRAsmNZ
  { 3, &SystemZDescs.OperandInfo[1173] },  // Inst #1600 = LOCFHRAsmNP
  { 3, &SystemZDescs.OperandInfo[1173] },  // Inst #1599 = LOCFHRAsmNO
  { 3, &SystemZDescs.OperandInfo[1173] },  // Inst #1598 = LOCFHRAsmNM
  { 3, &SystemZDescs.OperandInfo[1173] },  // Inst #1597 = LOCFHRAsmNLH
  { 3, &SystemZDescs.OperandInfo[1173] },  // Inst #1596 = LOCFHRAsmNLE
  { 3, &SystemZDescs.OperandInfo[1173] },  // Inst #1595 = LOCFHRAsmNL
  { 3, &SystemZDescs.OperandInfo[1173] },  // Inst #1594 = LOCFHRAsmNHE
  { 3, &SystemZDescs.OperandInfo[1173] },  // Inst #1593 = LOCFHRAsmNH
  { 3, &SystemZDescs.OperandInfo[1173] },  // Inst #1592 = LOCFHRAsmNE
  { 3, &SystemZDescs.OperandInfo[1173] },  // Inst #1591 = LOCFHRAsmM
  { 3, &SystemZDescs.OperandInfo[1173] },  // Inst #1590 = LOCFHRAsmLH
  { 3, &SystemZDescs.OperandInfo[1173] },  // Inst #1589 = LOCFHRAsmLE
  { 3, &SystemZDescs.OperandInfo[1173] },  // Inst #1588 = LOCFHRAsmL
  { 3, &SystemZDescs.OperandInfo[1173] },  // Inst #1587 = LOCFHRAsmHE
  { 3, &SystemZDescs.OperandInfo[1173] },  // Inst #1586 = LOCFHRAsmH
  { 3, &SystemZDescs.OperandInfo[1173] },  // Inst #1585 = LOCFHRAsmE
  { 4, &SystemZDescs.OperandInfo[1169] },  // Inst #1584 = LOCFHRAsm
  { 5, &SystemZDescs.OperandInfo[1164] },  // Inst #1583 = LOCFHR
  { 4, &SystemZDescs.OperandInfo[1160] },  // Inst #1582 = LOCFHAsmZ
  { 4, &SystemZDescs.OperandInfo[1160] },  // Inst #1581 = LOCFHAsmP
  { 4, &SystemZDescs.OperandInfo[1160] },  // Inst #1580 = LOCFHAsmO
  { 4, &SystemZDescs.OperandInfo[1160] },  // Inst #1579 = LOCFHAsmNZ
  { 4, &SystemZDescs.OperandInfo[1160] },  // Inst #1578 = LOCFHAsmNP
  { 4, &SystemZDescs.OperandInfo[1160] },  // Inst #1577 = LOCFHAsmNO
  { 4, &SystemZDescs.OperandInfo[1160] },  // Inst #1576 = LOCFHAsmNM
  { 4, &SystemZDescs.OperandInfo[1160] },  // Inst #1575 = LOCFHAsmNLH
  { 4, &SystemZDescs.OperandInfo[1160] },  // Inst #1574 = LOCFHAsmNLE
  { 4, &SystemZDescs.OperandInfo[1160] },  // Inst #1573 = LOCFHAsmNL
  { 4, &SystemZDescs.OperandInfo[1160] },  // Inst #1572 = LOCFHAsmNHE
  { 4, &SystemZDescs.OperandInfo[1160] },  // Inst #1571 = LOCFHAsmNH
  { 4, &SystemZDescs.OperandInfo[1160] },  // Inst #1570 = LOCFHAsmNE
  { 4, &SystemZDescs.OperandInfo[1160] },  // Inst #1569 = LOCFHAsmM
  { 4, &SystemZDescs.OperandInfo[1160] },  // Inst #1568 = LOCFHAsmLH
  { 4, &SystemZDescs.OperandInfo[1160] },  // Inst #1567 = LOCFHAsmLE
  { 4, &SystemZDescs.OperandInfo[1160] },  // Inst #1566 = LOCFHAsmL
  { 4, &SystemZDescs.OperandInfo[1160] },  // Inst #1565 = LOCFHAsmHE
  { 4, &SystemZDescs.OperandInfo[1160] },  // Inst #1564 = LOCFHAsmH
  { 4, &SystemZDescs.OperandInfo[1160] },  // Inst #1563 = LOCFHAsmE
  { 5, &SystemZDescs.OperandInfo[1155] },  // Inst #1562 = LOCFHAsm
  { 6, &SystemZDescs.OperandInfo[1149] },  // Inst #1561 = LOCFH
  { 4, &SystemZDescs.OperandInfo[1145] },  // Inst #1560 = LOCAsmZ
  { 4, &SystemZDescs.OperandInfo[1145] },  // Inst #1559 = LOCAsmP
  { 4, &SystemZDescs.OperandInfo[1145] },  // Inst #1558 = LOCAsmO
  { 4, &SystemZDescs.OperandInfo[1145] },  // Inst #1557 = LOCAsmNZ
  { 4, &SystemZDescs.OperandInfo[1145] },  // Inst #1556 = LOCAsmNP
  { 4, &SystemZDescs.OperandInfo[1145] },  // Inst #1555 = LOCAsmNO
  { 4, &SystemZDescs.OperandInfo[1145] },  // Inst #1554 = LOCAsmNM
  { 4, &SystemZDescs.OperandInfo[1145] },  // Inst #1553 = LOCAsmNLH
  { 4, &SystemZDescs.OperandInfo[1145] },  // Inst #1552 = LOCAsmNLE
  { 4, &SystemZDescs.OperandInfo[1145] },  // Inst #1551 = LOCAsmNL
  { 4, &SystemZDescs.OperandInfo[1145] },  // Inst #1550 = LOCAsmNHE
  { 4, &SystemZDescs.OperandInfo[1145] },  // Inst #1549 = LOCAsmNH
  { 4, &SystemZDescs.OperandInfo[1145] },  // Inst #1548 = LOCAsmNE
  { 4, &SystemZDescs.OperandInfo[1145] },  // Inst #1547 = LOCAsmM
  { 4, &SystemZDescs.OperandInfo[1145] },  // Inst #1546 = LOCAsmLH
  { 4, &SystemZDescs.OperandInfo[1145] },  // Inst #1545 = LOCAsmLE
  { 4, &SystemZDescs.OperandInfo[1145] },  // Inst #1544 = LOCAsmL
  { 4, &SystemZDescs.OperandInfo[1145] },  // Inst #1543 = LOCAsmHE
  { 4, &SystemZDescs.OperandInfo[1145] },  // Inst #1542 = LOCAsmH
  { 4, &SystemZDescs.OperandInfo[1145] },  // Inst #1541 = LOCAsmE
  { 5, &SystemZDescs.OperandInfo[1140] },  // Inst #1540 = LOCAsm
  { 6, &SystemZDescs.OperandInfo[1134] },  // Inst #1539 = LOC
  { 2, &SystemZDescs.OperandInfo[661] },  // Inst #1538 = LNXR
  { 2, &SystemZDescs.OperandInfo[661] },  // Inst #1537 = LNXBR
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1536 = LNR
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #1535 = LNGR
  { 2, &SystemZDescs.OperandInfo[702] },  // Inst #1534 = LNGFR
  { 2, &SystemZDescs.OperandInfo[647] },  // Inst #1533 = LNER
  { 2, &SystemZDescs.OperandInfo[647] },  // Inst #1532 = LNEBR
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #1531 = LNDR
  { 2, &SystemZDescs.OperandInfo[647] },  // Inst #1530 = LNDFR_32
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #1529 = LNDFR
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #1528 = LNDBR
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1527 = LMY
  { 4, &SystemZDescs.OperandInfo[1130] },  // Inst #1526 = LMH
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #1525 = LMG
  { 6, &SystemZDescs.OperandInfo[1124] },  // Inst #1524 = LMD
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1523 = LM
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1522 = LLZRGF
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #1521 = LLILL
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #1520 = LLILH
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #1519 = LLILF
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #1518 = LLIHL
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #1517 = LLIHH
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #1516 = LLIHF
  { 2, &SystemZDescs.OperandInfo[753] },  // Inst #1515 = LLHRL
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1514 = LLHR
  { 4, &SystemZDescs.OperandInfo[745] },  // Inst #1513 = LLHH
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #1512 = LLH
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #1511 = LLGTR
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1510 = LLGTAT
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1509 = LLGT
  { 2, &SystemZDescs.OperandInfo[704] },  // Inst #1508 = LLGHRL
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #1507 = LLGHR
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1506 = LLGH
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1505 = LLGFSG
  { 2, &SystemZDescs.OperandInfo[704] },  // Inst #1504 = LLGFRL
  { 2, &SystemZDescs.OperandInfo[702] },  // Inst #1503 = LLGFR
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1502 = LLGFAT
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1501 = LLGF
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #1500 = LLGCR
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1499 = LLGC
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1498 = LLCR
  { 4, &SystemZDescs.OperandInfo[745] },  // Inst #1497 = LLCH
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #1496 = LLC
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #1495 = LHY
  { 2, &SystemZDescs.OperandInfo[753] },  // Inst #1494 = LHRL
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1493 = LHR
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #1492 = LHI
  { 4, &SystemZDescs.OperandInfo[745] },  // Inst #1491 = LHH
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #1490 = LH
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1489 = LGSC
  { 2, &SystemZDescs.OperandInfo[704] },  // Inst #1488 = LGRL
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #1487 = LGR
  { 2, &SystemZDescs.OperandInfo[704] },  // Inst #1486 = LGHRL
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #1485 = LGHR
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #1484 = LGHI
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1483 = LGH
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1482 = LGG
  { 2, &SystemZDescs.OperandInfo[704] },  // Inst #1481 = LGFRL
  { 2, &SystemZDescs.OperandInfo[702] },  // Inst #1480 = LGFR
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #1479 = LGFI
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1478 = LGF
  { 2, &SystemZDescs.OperandInfo[874] },  // Inst #1477 = LGDR
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #1476 = LGBR
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1475 = LGB
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1474 = LGAT
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1473 = LG
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #1472 = LFPC
  { 4, &SystemZDescs.OperandInfo[745] },  // Inst #1471 = LFHAT
  { 4, &SystemZDescs.OperandInfo[745] },  // Inst #1470 = LFH
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #1469 = LFAS
  { 4, &SystemZDescs.OperandInfo[643] },  // Inst #1468 = LEY
  { 2, &SystemZDescs.OperandInfo[1122] },  // Inst #1467 = LEXR
  { 4, &SystemZDescs.OperandInfo[951] },  // Inst #1466 = LEXBRA
  { 2, &SystemZDescs.OperandInfo[661] },  // Inst #1465 = LEXBR
  { 2, &SystemZDescs.OperandInfo[647] },  // Inst #1464 = LER
  { 4, &SystemZDescs.OperandInfo[1118] },  // Inst #1463 = LEDTR
  { 2, &SystemZDescs.OperandInfo[1116] },  // Inst #1462 = LEDR
  { 4, &SystemZDescs.OperandInfo[1118] },  // Inst #1461 = LEDBRA
  { 2, &SystemZDescs.OperandInfo[1116] },  // Inst #1460 = LEDBR
  { 4, &SystemZDescs.OperandInfo[643] },  // Inst #1459 = LE
  { 4, &SystemZDescs.OperandInfo[615] },  // Inst #1458 = LDY
  { 4, &SystemZDescs.OperandInfo[951] },  // Inst #1457 = LDXTR
  { 2, &SystemZDescs.OperandInfo[1114] },  // Inst #1456 = LDXR
  { 4, &SystemZDescs.OperandInfo[951] },  // Inst #1455 = LDXBRA
  { 2, &SystemZDescs.OperandInfo[661] },  // Inst #1454 = LDXBR
  { 2, &SystemZDescs.OperandInfo[647] },  // Inst #1453 = LDR32
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #1452 = LDR
  { 2, &SystemZDescs.OperandInfo[627] },  // Inst #1451 = LDGR
  { 3, &SystemZDescs.OperandInfo[1111] },  // Inst #1450 = LDETR
  { 2, &SystemZDescs.OperandInfo[1109] },  // Inst #1449 = LDER
  { 2, &SystemZDescs.OperandInfo[1109] },  // Inst #1448 = LDEBR
  { 4, &SystemZDescs.OperandInfo[615] },  // Inst #1447 = LDEB
  { 4, &SystemZDescs.OperandInfo[643] },  // Inst #1446 = LDE32
  { 4, &SystemZDescs.OperandInfo[615] },  // Inst #1445 = LDE
  { 4, &SystemZDescs.OperandInfo[615] },  // Inst #1444 = LD
  { 2, &SystemZDescs.OperandInfo[661] },  // Inst #1443 = LCXR
  { 2, &SystemZDescs.OperandInfo[661] },  // Inst #1442 = LCXBR
  { 4, &SystemZDescs.OperandInfo[1105] },  // Inst #1441 = LCTLG
  { 4, &SystemZDescs.OperandInfo[1105] },  // Inst #1440 = LCTL
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1439 = LCR
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #1438 = LCGR
  { 2, &SystemZDescs.OperandInfo[702] },  // Inst #1437 = LCGFR
  { 2, &SystemZDescs.OperandInfo[647] },  // Inst #1436 = LCER
  { 2, &SystemZDescs.OperandInfo[647] },  // Inst #1435 = LCEBR
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #1434 = LCDR
  { 2, &SystemZDescs.OperandInfo[647] },  // Inst #1433 = LCDFR_32
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #1432 = LCDFR
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #1431 = LCDBR
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #1430 = LCCTL
  { 5, &SystemZDescs.OperandInfo[1100] },  // Inst #1429 = LCBB
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1428 = LBR
  { 4, &SystemZDescs.OperandInfo[745] },  // Inst #1427 = LBH
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #1426 = LBEAR
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #1425 = LB
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1424 = LAY
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #1423 = LAXG
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1422 = LAX
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #1421 = LAT
  { 4, &SystemZDescs.OperandInfo[1096] },  // Inst #1420 = LASP
  { 2, &SystemZDescs.OperandInfo[704] },  // Inst #1419 = LARL
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #1418 = LAOG
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1417 = LAO
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #1416 = LANG
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1415 = LAN
  { 4, &SystemZDescs.OperandInfo[1092] },  // Inst #1414 = LAMY
  { 4, &SystemZDescs.OperandInfo[1092] },  // Inst #1413 = LAM
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1412 = LAEY
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1411 = LAE
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #1410 = LAALG
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1409 = LAAL
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #1408 = LAAG
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1407 = LAA
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1406 = LA
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #1405 = L
  { 2, &SystemZDescs.OperandInfo[661] },  // Inst #1404 = KXTR
  { 2, &SystemZDescs.OperandInfo[661] },  // Inst #1403 = KXBR
  { 4, &SystemZDescs.OperandInfo[782] },  // Inst #1402 = KMO
  { 4, &SystemZDescs.OperandInfo[782] },  // Inst #1401 = KMF
  { 6, &SystemZDescs.OperandInfo[1086] },  // Inst #1400 = KMCTR
  { 4, &SystemZDescs.OperandInfo[782] },  // Inst #1399 = KMC
  { 3, &SystemZDescs.OperandInfo[1083] },  // Inst #1398 = KMAC
  { 6, &SystemZDescs.OperandInfo[1086] },  // Inst #1397 = KMA
  { 4, &SystemZDescs.OperandInfo[782] },  // Inst #1396 = KM
  { 3, &SystemZDescs.OperandInfo[1083] },  // Inst #1395 = KLMD
  { 3, &SystemZDescs.OperandInfo[1083] },  // Inst #1394 = KIMD
  { 2, &SystemZDescs.OperandInfo[647] },  // Inst #1393 = KEBR
  { 4, &SystemZDescs.OperandInfo[643] },  // Inst #1392 = KEB
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #1391 = KDTR
  { 3, &SystemZDescs.OperandInfo[1083] },  // Inst #1390 = KDSA
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #1389 = KDBR
  { 4, &SystemZDescs.OperandInfo[615] },  // Inst #1388 = KDB
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1387 = JGAsmZ
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1386 = JGAsmP
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1385 = JGAsmO
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1384 = JGAsmNZ
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1383 = JGAsmNP
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1382 = JGAsmNO
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1381 = JGAsmNM
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1380 = JGAsmNLH
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1379 = JGAsmNLE
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1378 = JGAsmNL
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1377 = JGAsmNHE
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1376 = JGAsmNH
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1375 = JGAsmNE
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1374 = JGAsmM
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1373 = JGAsmLH
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1372 = JGAsmLE
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1371 = JGAsmL
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1370 = JGAsmHE
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1369 = JGAsmH
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1368 = JGAsmE
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1367 = JG
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1366 = JAsmZ
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1365 = JAsmP
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1364 = JAsmO
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1363 = JAsmNZ
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1362 = JAsmNP
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1361 = JAsmNO
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1360 = JAsmNM
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1359 = JAsmNLH
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1358 = JAsmNLE
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1357 = JAsmNL
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1356 = JAsmNHE
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1355 = JAsmNH
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1354 = JAsmNE
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1353 = JAsmM
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1352 = JAsmLH
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1351 = JAsmLE
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1350 = JAsmL
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1349 = JAsmHE
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1348 = JAsmH
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1347 = JAsmE
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #1346 = J
  { 5, &SystemZDescs.OperandInfo[1078] },  // Inst #1345 = InsnVSI
  { 6, &SystemZDescs.OperandInfo[1072] },  // Inst #1344 = InsnVRX
  { 6, &SystemZDescs.OperandInfo[1066] },  // Inst #1343 = InsnVRV
  { 6, &SystemZDescs.OperandInfo[1060] },  // Inst #1342 = InsnVRS
  { 7, &SystemZDescs.OperandInfo[1053] },  // Inst #1341 = InsnVRR
  { 6, &SystemZDescs.OperandInfo[1047] },  // Inst #1340 = InsnVRI
  { 6, &SystemZDescs.OperandInfo[1041] },  // Inst #1339 = InsnSSF
  { 5, &SystemZDescs.OperandInfo[1036] },  // Inst #1338 = InsnSSE
  { 7, &SystemZDescs.OperandInfo[1029] },  // Inst #1337 = InsnSS
  { 4, &SystemZDescs.OperandInfo[1025] },  // Inst #1336 = InsnSIY
  { 4, &SystemZDescs.OperandInfo[1025] },  // Inst #1335 = InsnSIL
  { 4, &SystemZDescs.OperandInfo[1025] },  // Inst #1334 = InsnSI
  { 3, &SystemZDescs.OperandInfo[1022] },  // Inst #1333 = InsnS
  { 5, &SystemZDescs.OperandInfo[1011] },  // Inst #1332 = InsnRXY
  { 6, &SystemZDescs.OperandInfo[1016] },  // Inst #1331 = InsnRXF
  { 5, &SystemZDescs.OperandInfo[1011] },  // Inst #1330 = InsnRXE
  { 5, &SystemZDescs.OperandInfo[1011] },  // Inst #1329 = InsnRX
  { 5, &SystemZDescs.OperandInfo[1006] },  // Inst #1328 = InsnRSY
  { 4, &SystemZDescs.OperandInfo[979] },  // Inst #1327 = InsnRSI
  { 5, &SystemZDescs.OperandInfo[1006] },  // Inst #1326 = InsnRSE
  { 5, &SystemZDescs.OperandInfo[1006] },  // Inst #1325 = InsnRS
  { 6, &SystemZDescs.OperandInfo[1000] },  // Inst #1324 = InsnRRS
  { 5, &SystemZDescs.OperandInfo[995] },  // Inst #1323 = InsnRRF
  { 3, &SystemZDescs.OperandInfo[992] },  // Inst #1322 = InsnRRE
  { 3, &SystemZDescs.OperandInfo[992] },  // Inst #1321 = InsnRR
  { 6, &SystemZDescs.OperandInfo[986] },  // Inst #1320 = InsnRIS
  { 3, &SystemZDescs.OperandInfo[976] },  // Inst #1319 = InsnRILU
  { 3, &SystemZDescs.OperandInfo[983] },  // Inst #1318 = InsnRIL
  { 4, &SystemZDescs.OperandInfo[979] },  // Inst #1317 = InsnRIE
  { 3, &SystemZDescs.OperandInfo[976] },  // Inst #1316 = InsnRI
  { 1, &SystemZDescs.OperandInfo[1] },  // Inst #1315 = InsnE
  { 3, &SystemZDescs.OperandInfo[569] },  // Inst #1314 = IVSK
  { 3, &SystemZDescs.OperandInfo[569] },  // Inst #1313 = ISKE
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #1312 = IRBM
  { 2, &SystemZDescs.OperandInfo[702] },  // Inst #1311 = IPTEOptOpt
  { 3, &SystemZDescs.OperandInfo[973] },  // Inst #1310 = IPTEOpt
  { 4, &SystemZDescs.OperandInfo[969] },  // Inst #1309 = IPTE
  { 1, &SystemZDescs.OperandInfo[923] },  // Inst #1308 = IPM
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #1307 = IPK
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1306 = IILL
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #1305 = IILH
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #1304 = IILF
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1303 = IIHL
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #1302 = IIHH
  { 2, &SystemZDescs.OperandInfo[764] },  // Inst #1301 = IIHF
  { 3, &SystemZDescs.OperandInfo[541] },  // Inst #1300 = IEXTR
  { 3, &SystemZDescs.OperandInfo[488] },  // Inst #1299 = IEDTR
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #1298 = IDTEOpt
  { 4, &SystemZDescs.OperandInfo[965] },  // Inst #1297 = IDTE
  { 5, &SystemZDescs.OperandInfo[506] },  // Inst #1296 = ICY
  { 5, &SystemZDescs.OperandInfo[955] },  // Inst #1295 = ICMY
  { 5, &SystemZDescs.OperandInfo[960] },  // Inst #1294 = ICMH
  { 5, &SystemZDescs.OperandInfo[955] },  // Inst #1293 = ICM
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #1292 = IC32Y
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #1291 = IC32
  { 5, &SystemZDescs.OperandInfo[506] },  // Inst #1290 = IC
  { 1, &SystemZDescs.OperandInfo[923] },  // Inst #1289 = IAC
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #1288 = HSCH
  { 2, &SystemZDescs.OperandInfo[647] },  // Inst #1287 = HER
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #1286 = HDR
  { 2, &SystemZDescs.OperandInfo[158] },  // Inst #1285 = FLOGR
  { 4, &SystemZDescs.OperandInfo[951] },  // Inst #1284 = FIXTR
  { 2, &SystemZDescs.OperandInfo[661] },  // Inst #1283 = FIXR
  { 4, &SystemZDescs.OperandInfo[951] },  // Inst #1282 = FIXBRA
  { 3, &SystemZDescs.OperandInfo[948] },  // Inst #1281 = FIXBR
  { 2, &SystemZDescs.OperandInfo[647] },  // Inst #1280 = FIER
  { 4, &SystemZDescs.OperandInfo[944] },  // Inst #1279 = FIEBRA
  { 3, &SystemZDescs.OperandInfo[941] },  // Inst #1278 = FIEBR
  { 4, &SystemZDescs.OperandInfo[937] },  // Inst #1277 = FIDTR
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #1276 = FIDR
  { 4, &SystemZDescs.OperandInfo[937] },  // Inst #1275 = FIDBRA
  { 3, &SystemZDescs.OperandInfo[934] },  // Inst #1274 = FIDBR
  { 2, &SystemZDescs.OperandInfo[932] },  // Inst #1273 = EXRL
  { 4, &SystemZDescs.OperandInfo[928] },  // Inst #1272 = EX
  { 1, &SystemZDescs.OperandInfo[923] },  // Inst #1271 = ETND
  { 2, &SystemZDescs.OperandInfo[661] },  // Inst #1270 = ESXTR
  { 2, &SystemZDescs.OperandInfo[926] },  // Inst #1269 = ESTA
  { 2, &SystemZDescs.OperandInfo[924] },  // Inst #1268 = ESEA
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #1267 = ESDTR
  { 1, &SystemZDescs.OperandInfo[923] },  // Inst #1266 = ESAR
  { 1, &SystemZDescs.OperandInfo[290] },  // Inst #1265 = ESAIR
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #1264 = EREGG
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1263 = EREG
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1262 = EPSW
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #1261 = EPCTR
  { 1, &SystemZDescs.OperandInfo[923] },  // Inst #1260 = EPAR
  { 1, &SystemZDescs.OperandInfo[290] },  // Inst #1259 = EPAIR
  { 1, &SystemZDescs.OperandInfo[923] },  // Inst #1258 = EFPC
  { 2, &SystemZDescs.OperandInfo[661] },  // Inst #1257 = EEXTR
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #1256 = EEDTR
  { 5, &SystemZDescs.OperandInfo[777] },  // Inst #1255 = EDMK
  { 5, &SystemZDescs.OperandInfo[777] },  // Inst #1254 = ED
  { 5, &SystemZDescs.OperandInfo[861] },  // Inst #1253 = ECTG
  { 2, &SystemZDescs.OperandInfo[921] },  // Inst #1252 = ECPGA
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #1251 = ECCTR
  { 4, &SystemZDescs.OperandInfo[917] },  // Inst #1250 = ECAG
  { 2, &SystemZDescs.OperandInfo[915] },  // Inst #1249 = EAR
  { 4, &SystemZDescs.OperandInfo[544] },  // Inst #1248 = DXTRA
  { 3, &SystemZDescs.OperandInfo[541] },  // Inst #1247 = DXTR
  { 3, &SystemZDescs.OperandInfo[538] },  // Inst #1246 = DXR
  { 3, &SystemZDescs.OperandInfo[538] },  // Inst #1245 = DXBR
  { 3, &SystemZDescs.OperandInfo[858] },  // Inst #1244 = DSGR
  { 3, &SystemZDescs.OperandInfo[912] },  // Inst #1243 = DSGFR
  { 5, &SystemZDescs.OperandInfo[892] },  // Inst #1242 = DSGF
  { 5, &SystemZDescs.OperandInfo[892] },  // Inst #1241 = DSG
  { 3, &SystemZDescs.OperandInfo[912] },  // Inst #1240 = DR
  { 6, &SystemZDescs.OperandInfo[532] },  // Inst #1239 = DP
  { 3, &SystemZDescs.OperandInfo[912] },  // Inst #1238 = DLR
  { 3, &SystemZDescs.OperandInfo[858] },  // Inst #1237 = DLGR
  { 5, &SystemZDescs.OperandInfo[892] },  // Inst #1236 = DLG
  { 5, &SystemZDescs.OperandInfo[892] },  // Inst #1235 = DL
  { 5, &SystemZDescs.OperandInfo[907] },  // Inst #1234 = DIEBR
  { 5, &SystemZDescs.OperandInfo[902] },  // Inst #1233 = DIDBR
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1232 = DIAG
  { 5, &SystemZDescs.OperandInfo[897] },  // Inst #1231 = DFLTCC
  { 3, &SystemZDescs.OperandInfo[500] },  // Inst #1230 = DER
  { 3, &SystemZDescs.OperandInfo[500] },  // Inst #1229 = DEBR
  { 5, &SystemZDescs.OperandInfo[495] },  // Inst #1228 = DEB
  { 5, &SystemZDescs.OperandInfo[495] },  // Inst #1227 = DE
  { 4, &SystemZDescs.OperandInfo[491] },  // Inst #1226 = DDTRA
  { 3, &SystemZDescs.OperandInfo[488] },  // Inst #1225 = DDTR
  { 3, &SystemZDescs.OperandInfo[485] },  // Inst #1224 = DDR
  { 3, &SystemZDescs.OperandInfo[485] },  // Inst #1223 = DDBR
  { 5, &SystemZDescs.OperandInfo[480] },  // Inst #1222 = DDB
  { 5, &SystemZDescs.OperandInfo[480] },  // Inst #1221 = DD
  { 5, &SystemZDescs.OperandInfo[892] },  // Inst #1220 = D
  { 5, &SystemZDescs.OperandInfo[841] },  // Inst #1219 = CZXT
  { 5, &SystemZDescs.OperandInfo[633] },  // Inst #1218 = CZDT
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #1217 = CY
  { 5, &SystemZDescs.OperandInfo[841] },  // Inst #1216 = CXZT
  { 2, &SystemZDescs.OperandInfo[890] },  // Inst #1215 = CXUTR
  { 2, &SystemZDescs.OperandInfo[661] },  // Inst #1214 = CXTR
  { 2, &SystemZDescs.OperandInfo[890] },  // Inst #1213 = CXSTR
  { 2, &SystemZDescs.OperandInfo[661] },  // Inst #1212 = CXR
  { 5, &SystemZDescs.OperandInfo[841] },  // Inst #1211 = CXPT
  { 4, &SystemZDescs.OperandInfo[886] },  // Inst #1210 = CXLGTR
  { 4, &SystemZDescs.OperandInfo[886] },  // Inst #1209 = CXLGBR
  { 4, &SystemZDescs.OperandInfo[880] },  // Inst #1208 = CXLFTR
  { 4, &SystemZDescs.OperandInfo[880] },  // Inst #1207 = CXLFBR
  { 4, &SystemZDescs.OperandInfo[886] },  // Inst #1206 = CXGTRA
  { 2, &SystemZDescs.OperandInfo[884] },  // Inst #1205 = CXGTR
  { 2, &SystemZDescs.OperandInfo[884] },  // Inst #1204 = CXGR
  { 4, &SystemZDescs.OperandInfo[886] },  // Inst #1203 = CXGBRA
  { 2, &SystemZDescs.OperandInfo[884] },  // Inst #1202 = CXGBR
  { 4, &SystemZDescs.OperandInfo[880] },  // Inst #1201 = CXFTR
  { 2, &SystemZDescs.OperandInfo[878] },  // Inst #1200 = CXFR
  { 4, &SystemZDescs.OperandInfo[880] },  // Inst #1199 = CXFBRA
  { 2, &SystemZDescs.OperandInfo[878] },  // Inst #1198 = CXFBR
  { 2, &SystemZDescs.OperandInfo[661] },  // Inst #1197 = CXBR
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #1196 = CVDY
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #1195 = CVDG
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #1194 = CVD
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #1193 = CVBY
  { 5, &SystemZDescs.OperandInfo[506] },  // Inst #1192 = CVBG
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #1191 = CVB
  { 2, &SystemZDescs.OperandInfo[876] },  // Inst #1190 = CUXTR
  { 4, &SystemZDescs.OperandInfo[782] },  // Inst #1189 = CUUTFOpt
  { 5, &SystemZDescs.OperandInfo[869] },  // Inst #1188 = CUUTF
  { 4, &SystemZDescs.OperandInfo[782] },  // Inst #1187 = CUTFUOpt
  { 5, &SystemZDescs.OperandInfo[869] },  // Inst #1186 = CUTFU
  { 4, &SystemZDescs.OperandInfo[782] },  // Inst #1185 = CUSE
  { 2, &SystemZDescs.OperandInfo[874] },  // Inst #1184 = CUDTR
  { 4, &SystemZDescs.OperandInfo[782] },  // Inst #1183 = CU42
  { 4, &SystemZDescs.OperandInfo[782] },  // Inst #1182 = CU41
  { 4, &SystemZDescs.OperandInfo[782] },  // Inst #1181 = CU24Opt
  { 5, &SystemZDescs.OperandInfo[869] },  // Inst #1180 = CU24
  { 4, &SystemZDescs.OperandInfo[782] },  // Inst #1179 = CU21Opt
  { 5, &SystemZDescs.OperandInfo[869] },  // Inst #1178 = CU21
  { 4, &SystemZDescs.OperandInfo[782] },  // Inst #1177 = CU14Opt
  { 5, &SystemZDescs.OperandInfo[869] },  // Inst #1176 = CU14
  { 4, &SystemZDescs.OperandInfo[782] },  // Inst #1175 = CU12Opt
  { 5, &SystemZDescs.OperandInfo[869] },  // Inst #1174 = CU12
  { 5, &SystemZDescs.OperandInfo[601] },  // Inst #1173 = CSY
  { 3, &SystemZDescs.OperandInfo[866] },  // Inst #1172 = CSXTR
  { 5, &SystemZDescs.OperandInfo[861] },  // Inst #1171 = CSST
  { 3, &SystemZDescs.OperandInfo[858] },  // Inst #1170 = CSPG
  { 3, &SystemZDescs.OperandInfo[858] },  // Inst #1169 = CSP
  { 5, &SystemZDescs.OperandInfo[606] },  // Inst #1168 = CSG
  { 3, &SystemZDescs.OperandInfo[855] },  // Inst #1167 = CSDTR
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #1166 = CSCH
  { 5, &SystemZDescs.OperandInfo[601] },  // Inst #1165 = CS
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1164 = CRTAsmNLH
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1163 = CRTAsmNLE
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1162 = CRTAsmNL
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1161 = CRTAsmNHE
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1160 = CRTAsmNH
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1159 = CRTAsmNE
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1158 = CRTAsmLH
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1157 = CRTAsmLE
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1156 = CRTAsmL
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1155 = CRTAsmHE
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1154 = CRTAsmH
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1153 = CRTAsmE
  { 3, &SystemZDescs.OperandInfo[239] },  // Inst #1152 = CRTAsm
  { 3, &SystemZDescs.OperandInfo[239] },  // Inst #1151 = CRT
  { 2, &SystemZDescs.OperandInfo[753] },  // Inst #1150 = CRL
  { 3, &SystemZDescs.OperandInfo[818] },  // Inst #1149 = CRJAsmNLH
  { 3, &SystemZDescs.OperandInfo[818] },  // Inst #1148 = CRJAsmNLE
  { 3, &SystemZDescs.OperandInfo[818] },  // Inst #1147 = CRJAsmNL
  { 3, &SystemZDescs.OperandInfo[818] },  // Inst #1146 = CRJAsmNHE
  { 3, &SystemZDescs.OperandInfo[818] },  // Inst #1145 = CRJAsmNH
  { 3, &SystemZDescs.OperandInfo[818] },  // Inst #1144 = CRJAsmNE
  { 3, &SystemZDescs.OperandInfo[818] },  // Inst #1143 = CRJAsmLH
  { 3, &SystemZDescs.OperandInfo[818] },  // Inst #1142 = CRJAsmLE
  { 3, &SystemZDescs.OperandInfo[818] },  // Inst #1141 = CRJAsmL
  { 3, &SystemZDescs.OperandInfo[818] },  // Inst #1140 = CRJAsmHE
  { 3, &SystemZDescs.OperandInfo[818] },  // Inst #1139 = CRJAsmH
  { 3, &SystemZDescs.OperandInfo[818] },  // Inst #1138 = CRJAsmE
  { 4, &SystemZDescs.OperandInfo[814] },  // Inst #1137 = CRJAsm
  { 4, &SystemZDescs.OperandInfo[814] },  // Inst #1136 = CRJ
  { 3, &SystemZDescs.OperandInfo[852] },  // Inst #1135 = CRDTEOpt
  { 4, &SystemZDescs.OperandInfo[848] },  // Inst #1134 = CRDTE
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1133 = CRBAsmNLH
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1132 = CRBAsmNLE
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1131 = CRBAsmNL
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1130 = CRBAsmNHE
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1129 = CRBAsmNH
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1128 = CRBAsmNE
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1127 = CRBAsmLH
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1126 = CRBAsmLE
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1125 = CRBAsmL
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1124 = CRBAsmHE
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1123 = CRBAsmH
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1122 = CRBAsmE
  { 5, &SystemZDescs.OperandInfo[805] },  // Inst #1121 = CRBAsm
  { 5, &SystemZDescs.OperandInfo[805] },  // Inst #1120 = CRB
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1119 = CR
  { 2, &SystemZDescs.OperandInfo[846] },  // Inst #1118 = CPYA
  { 5, &SystemZDescs.OperandInfo[841] },  // Inst #1117 = CPXT
  { 3, &SystemZDescs.OperandInfo[838] },  // Inst #1116 = CPSDRss
  { 3, &SystemZDescs.OperandInfo[835] },  // Inst #1115 = CPSDRsd
  { 3, &SystemZDescs.OperandInfo[832] },  // Inst #1114 = CPSDRds
  { 3, &SystemZDescs.OperandInfo[488] },  // Inst #1113 = CPSDRdd
  { 5, &SystemZDescs.OperandInfo[633] },  // Inst #1112 = CPDT
  { 6, &SystemZDescs.OperandInfo[532] },  // Inst #1111 = CP
  { 4, &SystemZDescs.OperandInfo[782] },  // Inst #1110 = CMPSC
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #1109 = CLY
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #1108 = CLTAsmNLH
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #1107 = CLTAsmNLE
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #1106 = CLTAsmNL
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #1105 = CLTAsmNHE
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #1104 = CLTAsmNH
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #1103 = CLTAsmNE
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #1102 = CLTAsmLH
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #1101 = CLTAsmLE
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #1100 = CLTAsmL
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #1099 = CLTAsmHE
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #1098 = CLTAsmH
  { 3, &SystemZDescs.OperandInfo[829] },  // Inst #1097 = CLTAsmE
  { 4, &SystemZDescs.OperandInfo[825] },  // Inst #1096 = CLTAsm
  { 4, &SystemZDescs.OperandInfo[825] },  // Inst #1095 = CLT
  { 4, &SystemZDescs.OperandInfo[821] },  // Inst #1094 = CLST
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1093 = CLRTAsmNLH
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1092 = CLRTAsmNLE
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1091 = CLRTAsmNL
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1090 = CLRTAsmNHE
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1089 = CLRTAsmNH
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1088 = CLRTAsmNE
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1087 = CLRTAsmLH
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1086 = CLRTAsmLE
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1085 = CLRTAsmL
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1084 = CLRTAsmHE
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1083 = CLRTAsmH
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1082 = CLRTAsmE
  { 3, &SystemZDescs.OperandInfo[239] },  // Inst #1081 = CLRTAsm
  { 3, &SystemZDescs.OperandInfo[239] },  // Inst #1080 = CLRT
  { 2, &SystemZDescs.OperandInfo[753] },  // Inst #1079 = CLRL
  { 3, &SystemZDescs.OperandInfo[818] },  // Inst #1078 = CLRJAsmNLH
  { 3, &SystemZDescs.OperandInfo[818] },  // Inst #1077 = CLRJAsmNLE
  { 3, &SystemZDescs.OperandInfo[818] },  // Inst #1076 = CLRJAsmNL
  { 3, &SystemZDescs.OperandInfo[818] },  // Inst #1075 = CLRJAsmNHE
  { 3, &SystemZDescs.OperandInfo[818] },  // Inst #1074 = CLRJAsmNH
  { 3, &SystemZDescs.OperandInfo[818] },  // Inst #1073 = CLRJAsmNE
  { 3, &SystemZDescs.OperandInfo[818] },  // Inst #1072 = CLRJAsmLH
  { 3, &SystemZDescs.OperandInfo[818] },  // Inst #1071 = CLRJAsmLE
  { 3, &SystemZDescs.OperandInfo[818] },  // Inst #1070 = CLRJAsmL
  { 3, &SystemZDescs.OperandInfo[818] },  // Inst #1069 = CLRJAsmHE
  { 3, &SystemZDescs.OperandInfo[818] },  // Inst #1068 = CLRJAsmH
  { 3, &SystemZDescs.OperandInfo[818] },  // Inst #1067 = CLRJAsmE
  { 4, &SystemZDescs.OperandInfo[814] },  // Inst #1066 = CLRJAsm
  { 4, &SystemZDescs.OperandInfo[814] },  // Inst #1065 = CLRJ
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1064 = CLRBAsmNLH
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1063 = CLRBAsmNLE
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1062 = CLRBAsmNL
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1061 = CLRBAsmNHE
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1060 = CLRBAsmNH
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1059 = CLRBAsmNE
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1058 = CLRBAsmLH
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1057 = CLRBAsmLE
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1056 = CLRBAsmL
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1055 = CLRBAsmHE
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1054 = CLRBAsmH
  { 4, &SystemZDescs.OperandInfo[810] },  // Inst #1053 = CLRBAsmE
  { 5, &SystemZDescs.OperandInfo[805] },  // Inst #1052 = CLRBAsm
  { 5, &SystemZDescs.OperandInfo[805] },  // Inst #1051 = CLRB
  { 2, &SystemZDescs.OperandInfo[803] },  // Inst #1050 = CLR
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #1049 = CLMY
  { 4, &SystemZDescs.OperandInfo[799] },  // Inst #1048 = CLMH
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #1047 = CLM
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #1046 = CLIY
  { 3, &SystemZDescs.OperandInfo[770] },  // Inst #1045 = CLIJAsmNLH
  { 3, &SystemZDescs.OperandInfo[770] },  // Inst #1044 = CLIJAsmNLE
  { 3, &SystemZDescs.OperandInfo[770] },  // Inst #1043 = CLIJAsmNL
  { 3, &SystemZDescs.OperandInfo[770] },  // Inst #1042 = CLIJAsmNHE
  { 3, &SystemZDescs.OperandInfo[770] },  // Inst #1041 = CLIJAsmNH
  { 3, &SystemZDescs.OperandInfo[770] },  // Inst #1040 = CLIJAsmNE
  { 3, &SystemZDescs.OperandInfo[770] },  // Inst #1039 = CLIJAsmLH
  { 3, &SystemZDescs.OperandInfo[770] },  // Inst #1038 = CLIJAsmLE
  { 3, &SystemZDescs.OperandInfo[770] },  // Inst #1037 = CLIJAsmL
  { 3, &SystemZDescs.OperandInfo[770] },  // Inst #1036 = CLIJAsmHE
  { 3, &SystemZDescs.OperandInfo[770] },  // Inst #1035 = CLIJAsmH
  { 3, &SystemZDescs.OperandInfo[770] },  // Inst #1034 = CLIJAsmE
  { 4, &SystemZDescs.OperandInfo[766] },  // Inst #1033 = CLIJAsm
  { 4, &SystemZDescs.OperandInfo[766] },  // Inst #1032 = CLIJ
  { 2, &SystemZDescs.OperandInfo[764] },  // Inst #1031 = CLIH
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #1030 = CLIBAsmNLH
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #1029 = CLIBAsmNLE
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #1028 = CLIBAsmNL
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #1027 = CLIBAsmNHE
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #1026 = CLIBAsmNH
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #1025 = CLIBAsmNE
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #1024 = CLIBAsmLH
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #1023 = CLIBAsmLE
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #1022 = CLIBAsmL
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #1021 = CLIBAsmHE
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #1020 = CLIBAsmH
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #1019 = CLIBAsmE
  { 5, &SystemZDescs.OperandInfo[755] },  // Inst #1018 = CLIBAsm
  { 5, &SystemZDescs.OperandInfo[755] },  // Inst #1017 = CLIB
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #1016 = CLI
  { 2, &SystemZDescs.OperandInfo[753] },  // Inst #1015 = CLHRL
  { 2, &SystemZDescs.OperandInfo[751] },  // Inst #1014 = CLHLR
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #1013 = CLHHSI
  { 2, &SystemZDescs.OperandInfo[749] },  // Inst #1012 = CLHHR
  { 4, &SystemZDescs.OperandInfo[745] },  // Inst #1011 = CLHF
  { 4, &SystemZDescs.OperandInfo[741] },  // Inst #1010 = CLGXTR
  { 4, &SystemZDescs.OperandInfo[741] },  // Inst #1009 = CLGXBR
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #1008 = CLGTAsmNLH
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #1007 = CLGTAsmNLE
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #1006 = CLGTAsmNL
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #1005 = CLGTAsmNHE
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #1004 = CLGTAsmNH
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #1003 = CLGTAsmNE
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #1002 = CLGTAsmLH
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #1001 = CLGTAsmLE
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #1000 = CLGTAsmL
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #999 = CLGTAsmHE
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #998 = CLGTAsmH
  { 3, &SystemZDescs.OperandInfo[796] },  // Inst #997 = CLGTAsmE
  { 4, &SystemZDescs.OperandInfo[792] },  // Inst #996 = CLGTAsm
  { 4, &SystemZDescs.OperandInfo[792] },  // Inst #995 = CLGT
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #994 = CLGRTAsmNLH
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #993 = CLGRTAsmNLE
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #992 = CLGRTAsmNL
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #991 = CLGRTAsmNHE
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #990 = CLGRTAsmNH
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #989 = CLGRTAsmNE
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #988 = CLGRTAsmLH
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #987 = CLGRTAsmLE
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #986 = CLGRTAsmL
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #985 = CLGRTAsmHE
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #984 = CLGRTAsmH
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #983 = CLGRTAsmE
  { 3, &SystemZDescs.OperandInfo[211] },  // Inst #982 = CLGRTAsm
  { 3, &SystemZDescs.OperandInfo[211] },  // Inst #981 = CLGRT
  { 2, &SystemZDescs.OperandInfo[704] },  // Inst #980 = CLGRL
  { 3, &SystemZDescs.OperandInfo[735] },  // Inst #979 = CLGRJAsmNLH
  { 3, &SystemZDescs.OperandInfo[735] },  // Inst #978 = CLGRJAsmNLE
  { 3, &SystemZDescs.OperandInfo[735] },  // Inst #977 = CLGRJAsmNL
  { 3, &SystemZDescs.OperandInfo[735] },  // Inst #976 = CLGRJAsmNHE
  { 3, &SystemZDescs.OperandInfo[735] },  // Inst #975 = CLGRJAsmNH
  { 3, &SystemZDescs.OperandInfo[735] },  // Inst #974 = CLGRJAsmNE
  { 3, &SystemZDescs.OperandInfo[735] },  // Inst #973 = CLGRJAsmLH
  { 3, &SystemZDescs.OperandInfo[735] },  // Inst #972 = CLGRJAsmLE
  { 3, &SystemZDescs.OperandInfo[735] },  // Inst #971 = CLGRJAsmL
  { 3, &SystemZDescs.OperandInfo[735] },  // Inst #970 = CLGRJAsmHE
  { 3, &SystemZDescs.OperandInfo[735] },  // Inst #969 = CLGRJAsmH
  { 3, &SystemZDescs.OperandInfo[735] },  // Inst #968 = CLGRJAsmE
  { 4, &SystemZDescs.OperandInfo[731] },  // Inst #967 = CLGRJAsm
  { 4, &SystemZDescs.OperandInfo[731] },  // Inst #966 = CLGRJ
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #965 = CLGRBAsmNLH
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #964 = CLGRBAsmNLE
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #963 = CLGRBAsmNL
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #962 = CLGRBAsmNHE
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #961 = CLGRBAsmNH
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #960 = CLGRBAsmNE
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #959 = CLGRBAsmLH
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #958 = CLGRBAsmLE
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #957 = CLGRBAsmL
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #956 = CLGRBAsmHE
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #955 = CLGRBAsmH
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #954 = CLGRBAsmE
  { 5, &SystemZDescs.OperandInfo[722] },  // Inst #953 = CLGRBAsm
  { 5, &SystemZDescs.OperandInfo[722] },  // Inst #952 = CLGRB
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #951 = CLGR
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #950 = CLGITAsmNLH
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #949 = CLGITAsmNLE
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #948 = CLGITAsmNL
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #947 = CLGITAsmNHE
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #946 = CLGITAsmNH
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #945 = CLGITAsmNE
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #944 = CLGITAsmLH
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #943 = CLGITAsmLE
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #942 = CLGITAsmL
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #941 = CLGITAsmHE
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #940 = CLGITAsmH
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #939 = CLGITAsmE
  { 3, &SystemZDescs.OperandInfo[204] },  // Inst #938 = CLGITAsm
  { 3, &SystemZDescs.OperandInfo[204] },  // Inst #937 = CLGIT
  { 3, &SystemZDescs.OperandInfo[719] },  // Inst #936 = CLGIJAsmNLH
  { 3, &SystemZDescs.OperandInfo[719] },  // Inst #935 = CLGIJAsmNLE
  { 3, &SystemZDescs.OperandInfo[719] },  // Inst #934 = CLGIJAsmNL
  { 3, &SystemZDescs.OperandInfo[719] },  // Inst #933 = CLGIJAsmNHE
  { 3, &SystemZDescs.OperandInfo[719] },  // Inst #932 = CLGIJAsmNH
  { 3, &SystemZDescs.OperandInfo[719] },  // Inst #931 = CLGIJAsmNE
  { 3, &SystemZDescs.OperandInfo[719] },  // Inst #930 = CLGIJAsmLH
  { 3, &SystemZDescs.OperandInfo[719] },  // Inst #929 = CLGIJAsmLE
  { 3, &SystemZDescs.OperandInfo[719] },  // Inst #928 = CLGIJAsmL
  { 3, &SystemZDescs.OperandInfo[719] },  // Inst #927 = CLGIJAsmHE
  { 3, &SystemZDescs.OperandInfo[719] },  // Inst #926 = CLGIJAsmH
  { 3, &SystemZDescs.OperandInfo[719] },  // Inst #925 = CLGIJAsmE
  { 4, &SystemZDescs.OperandInfo[715] },  // Inst #924 = CLGIJAsm
  { 4, &SystemZDescs.OperandInfo[715] },  // Inst #923 = CLGIJ
  { 4, &SystemZDescs.OperandInfo[711] },  // Inst #922 = CLGIBAsmNLH
  { 4, &SystemZDescs.OperandInfo[711] },  // Inst #921 = CLGIBAsmNLE
  { 4, &SystemZDescs.OperandInfo[711] },  // Inst #920 = CLGIBAsmNL
  { 4, &SystemZDescs.OperandInfo[711] },  // Inst #919 = CLGIBAsmNHE
  { 4, &SystemZDescs.OperandInfo[711] },  // Inst #918 = CLGIBAsmNH
  { 4, &SystemZDescs.OperandInfo[711] },  // Inst #917 = CLGIBAsmNE
  { 4, &SystemZDescs.OperandInfo[711] },  // Inst #916 = CLGIBAsmLH
  { 4, &SystemZDescs.OperandInfo[711] },  // Inst #915 = CLGIBAsmLE
  { 4, &SystemZDescs.OperandInfo[711] },  // Inst #914 = CLGIBAsmL
  { 4, &SystemZDescs.OperandInfo[711] },  // Inst #913 = CLGIBAsmHE
  { 4, &SystemZDescs.OperandInfo[711] },  // Inst #912 = CLGIBAsmH
  { 4, &SystemZDescs.OperandInfo[711] },  // Inst #911 = CLGIBAsmE
  { 5, &SystemZDescs.OperandInfo[706] },  // Inst #910 = CLGIBAsm
  { 5, &SystemZDescs.OperandInfo[706] },  // Inst #909 = CLGIB
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #908 = CLGHSI
  { 2, &SystemZDescs.OperandInfo[704] },  // Inst #907 = CLGHRL
  { 2, &SystemZDescs.OperandInfo[704] },  // Inst #906 = CLGFRL
  { 2, &SystemZDescs.OperandInfo[702] },  // Inst #905 = CLGFR
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #904 = CLGFI
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #903 = CLGF
  { 4, &SystemZDescs.OperandInfo[698] },  // Inst #902 = CLGEBR
  { 4, &SystemZDescs.OperandInfo[691] },  // Inst #901 = CLGDTR
  { 4, &SystemZDescs.OperandInfo[691] },  // Inst #900 = CLGDBR
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #899 = CLG
  { 4, &SystemZDescs.OperandInfo[684] },  // Inst #898 = CLFXTR
  { 4, &SystemZDescs.OperandInfo[684] },  // Inst #897 = CLFXBR
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #896 = CLFITAsmNLH
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #895 = CLFITAsmNLE
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #894 = CLFITAsmNL
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #893 = CLFITAsmNHE
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #892 = CLFITAsmNH
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #891 = CLFITAsmNE
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #890 = CLFITAsmLH
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #889 = CLFITAsmLE
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #888 = CLFITAsmL
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #887 = CLFITAsmHE
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #886 = CLFITAsmH
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #885 = CLFITAsmE
  { 3, &SystemZDescs.OperandInfo[218] },  // Inst #884 = CLFITAsm
  { 3, &SystemZDescs.OperandInfo[218] },  // Inst #883 = CLFIT
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #882 = CLFI
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #881 = CLFHSI
  { 4, &SystemZDescs.OperandInfo[675] },  // Inst #880 = CLFEBR
  { 4, &SystemZDescs.OperandInfo[668] },  // Inst #879 = CLFDTR
  { 4, &SystemZDescs.OperandInfo[668] },  // Inst #878 = CLFDBR
  { 6, &SystemZDescs.OperandInfo[786] },  // Inst #877 = CLCLU
  { 6, &SystemZDescs.OperandInfo[786] },  // Inst #876 = CLCLE
  { 4, &SystemZDescs.OperandInfo[782] },  // Inst #875 = CLCL
  { 5, &SystemZDescs.OperandInfo[777] },  // Inst #874 = CLC
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #873 = CL
  { 4, &SystemZDescs.OperandInfo[773] },  // Inst #872 = CKSM
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #871 = CITAsmNLH
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #870 = CITAsmNLE
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #869 = CITAsmNL
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #868 = CITAsmNHE
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #867 = CITAsmNH
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #866 = CITAsmNE
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #865 = CITAsmLH
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #864 = CITAsmLE
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #863 = CITAsmL
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #862 = CITAsmHE
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #861 = CITAsmH
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #860 = CITAsmE
  { 3, &SystemZDescs.OperandInfo[218] },  // Inst #859 = CITAsm
  { 3, &SystemZDescs.OperandInfo[218] },  // Inst #858 = CIT
  { 3, &SystemZDescs.OperandInfo[770] },  // Inst #857 = CIJAsmNLH
  { 3, &SystemZDescs.OperandInfo[770] },  // Inst #856 = CIJAsmNLE
  { 3, &SystemZDescs.OperandInfo[770] },  // Inst #855 = CIJAsmNL
  { 3, &SystemZDescs.OperandInfo[770] },  // Inst #854 = CIJAsmNHE
  { 3, &SystemZDescs.OperandInfo[770] },  // Inst #853 = CIJAsmNH
  { 3, &SystemZDescs.OperandInfo[770] },  // Inst #852 = CIJAsmNE
  { 3, &SystemZDescs.OperandInfo[770] },  // Inst #851 = CIJAsmLH
  { 3, &SystemZDescs.OperandInfo[770] },  // Inst #850 = CIJAsmLE
  { 3, &SystemZDescs.OperandInfo[770] },  // Inst #849 = CIJAsmL
  { 3, &SystemZDescs.OperandInfo[770] },  // Inst #848 = CIJAsmHE
  { 3, &SystemZDescs.OperandInfo[770] },  // Inst #847 = CIJAsmH
  { 3, &SystemZDescs.OperandInfo[770] },  // Inst #846 = CIJAsmE
  { 4, &SystemZDescs.OperandInfo[766] },  // Inst #845 = CIJAsm
  { 4, &SystemZDescs.OperandInfo[766] },  // Inst #844 = CIJ
  { 2, &SystemZDescs.OperandInfo[764] },  // Inst #843 = CIH
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #842 = CIBAsmNLH
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #841 = CIBAsmNLE
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #840 = CIBAsmNL
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #839 = CIBAsmNHE
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #838 = CIBAsmNH
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #837 = CIBAsmNE
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #836 = CIBAsmLH
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #835 = CIBAsmLE
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #834 = CIBAsmL
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #833 = CIBAsmHE
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #832 = CIBAsmH
  { 4, &SystemZDescs.OperandInfo[760] },  // Inst #831 = CIBAsmE
  { 5, &SystemZDescs.OperandInfo[755] },  // Inst #830 = CIBAsm
  { 5, &SystemZDescs.OperandInfo[755] },  // Inst #829 = CIB
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #828 = CHY
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #827 = CHSI
  { 2, &SystemZDescs.OperandInfo[753] },  // Inst #826 = CHRL
  { 2, &SystemZDescs.OperandInfo[751] },  // Inst #825 = CHLR
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #824 = CHI
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #823 = CHHSI
  { 2, &SystemZDescs.OperandInfo[749] },  // Inst #822 = CHHR
  { 4, &SystemZDescs.OperandInfo[745] },  // Inst #821 = CHF
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #820 = CH
  { 4, &SystemZDescs.OperandInfo[741] },  // Inst #819 = CGXTRA
  { 3, &SystemZDescs.OperandInfo[738] },  // Inst #818 = CGXTR
  { 3, &SystemZDescs.OperandInfo[738] },  // Inst #817 = CGXR
  { 4, &SystemZDescs.OperandInfo[741] },  // Inst #816 = CGXBRA
  { 3, &SystemZDescs.OperandInfo[738] },  // Inst #815 = CGXBR
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #814 = CGRTAsmNLH
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #813 = CGRTAsmNLE
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #812 = CGRTAsmNL
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #811 = CGRTAsmNHE
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #810 = CGRTAsmNH
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #809 = CGRTAsmNE
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #808 = CGRTAsmLH
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #807 = CGRTAsmLE
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #806 = CGRTAsmL
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #805 = CGRTAsmHE
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #804 = CGRTAsmH
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #803 = CGRTAsmE
  { 3, &SystemZDescs.OperandInfo[211] },  // Inst #802 = CGRTAsm
  { 3, &SystemZDescs.OperandInfo[211] },  // Inst #801 = CGRT
  { 2, &SystemZDescs.OperandInfo[704] },  // Inst #800 = CGRL
  { 3, &SystemZDescs.OperandInfo[735] },  // Inst #799 = CGRJAsmNLH
  { 3, &SystemZDescs.OperandInfo[735] },  // Inst #798 = CGRJAsmNLE
  { 3, &SystemZDescs.OperandInfo[735] },  // Inst #797 = CGRJAsmNL
  { 3, &SystemZDescs.OperandInfo[735] },  // Inst #796 = CGRJAsmNHE
  { 3, &SystemZDescs.OperandInfo[735] },  // Inst #795 = CGRJAsmNH
  { 3, &SystemZDescs.OperandInfo[735] },  // Inst #794 = CGRJAsmNE
  { 3, &SystemZDescs.OperandInfo[735] },  // Inst #793 = CGRJAsmLH
  { 3, &SystemZDescs.OperandInfo[735] },  // Inst #792 = CGRJAsmLE
  { 3, &SystemZDescs.OperandInfo[735] },  // Inst #791 = CGRJAsmL
  { 3, &SystemZDescs.OperandInfo[735] },  // Inst #790 = CGRJAsmHE
  { 3, &SystemZDescs.OperandInfo[735] },  // Inst #789 = CGRJAsmH
  { 3, &SystemZDescs.OperandInfo[735] },  // Inst #788 = CGRJAsmE
  { 4, &SystemZDescs.OperandInfo[731] },  // Inst #787 = CGRJAsm
  { 4, &SystemZDescs.OperandInfo[731] },  // Inst #786 = CGRJ
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #785 = CGRBAsmNLH
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #784 = CGRBAsmNLE
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #783 = CGRBAsmNL
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #782 = CGRBAsmNHE
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #781 = CGRBAsmNH
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #780 = CGRBAsmNE
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #779 = CGRBAsmLH
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #778 = CGRBAsmLE
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #777 = CGRBAsmL
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #776 = CGRBAsmHE
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #775 = CGRBAsmH
  { 4, &SystemZDescs.OperandInfo[727] },  // Inst #774 = CGRBAsmE
  { 5, &SystemZDescs.OperandInfo[722] },  // Inst #773 = CGRBAsm
  { 5, &SystemZDescs.OperandInfo[722] },  // Inst #772 = CGRB
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #771 = CGR
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #770 = CGITAsmNLH
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #769 = CGITAsmNLE
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #768 = CGITAsmNL
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #767 = CGITAsmNHE
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #766 = CGITAsmNH
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #765 = CGITAsmNE
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #764 = CGITAsmLH
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #763 = CGITAsmLE
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #762 = CGITAsmL
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #761 = CGITAsmHE
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #760 = CGITAsmH
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #759 = CGITAsmE
  { 3, &SystemZDescs.OperandInfo[204] },  // Inst #758 = CGITAsm
  { 3, &SystemZDescs.OperandInfo[204] },  // Inst #757 = CGIT
  { 3, &SystemZDescs.OperandInfo[719] },  // Inst #756 = CGIJAsmNLH
  { 3, &SystemZDescs.OperandInfo[719] },  // Inst #755 = CGIJAsmNLE
  { 3, &SystemZDescs.OperandInfo[719] },  // Inst #754 = CGIJAsmNL
  { 3, &SystemZDescs.OperandInfo[719] },  // Inst #753 = CGIJAsmNHE
  { 3, &SystemZDescs.OperandInfo[719] },  // Inst #752 = CGIJAsmNH
  { 3, &SystemZDescs.OperandInfo[719] },  // Inst #751 = CGIJAsmNE
  { 3, &SystemZDescs.OperandInfo[719] },  // Inst #750 = CGIJAsmLH
  { 3, &SystemZDescs.OperandInfo[719] },  // Inst #749 = CGIJAsmLE
  { 3, &SystemZDescs.OperandInfo[719] },  // Inst #748 = CGIJAsmL
  { 3, &SystemZDescs.OperandInfo[719] },  // Inst #747 = CGIJAsmHE
  { 3, &SystemZDescs.OperandInfo[719] },  // Inst #746 = CGIJAsmH
  { 3, &SystemZDescs.OperandInfo[719] },  // Inst #745 = CGIJAsmE
  { 4, &SystemZDescs.OperandInfo[715] },  // Inst #744 = CGIJAsm
  { 4, &SystemZDescs.OperandInfo[715] },  // Inst #743 = CGIJ
  { 4, &SystemZDescs.OperandInfo[711] },  // Inst #742 = CGIBAsmNLH
  { 4, &SystemZDescs.OperandInfo[711] },  // Inst #741 = CGIBAsmNLE
  { 4, &SystemZDescs.OperandInfo[711] },  // Inst #740 = CGIBAsmNL
  { 4, &SystemZDescs.OperandInfo[711] },  // Inst #739 = CGIBAsmNHE
  { 4, &SystemZDescs.OperandInfo[711] },  // Inst #738 = CGIBAsmNH
  { 4, &SystemZDescs.OperandInfo[711] },  // Inst #737 = CGIBAsmNE
  { 4, &SystemZDescs.OperandInfo[711] },  // Inst #736 = CGIBAsmLH
  { 4, &SystemZDescs.OperandInfo[711] },  // Inst #735 = CGIBAsmLE
  { 4, &SystemZDescs.OperandInfo[711] },  // Inst #734 = CGIBAsmL
  { 4, &SystemZDescs.OperandInfo[711] },  // Inst #733 = CGIBAsmHE
  { 4, &SystemZDescs.OperandInfo[711] },  // Inst #732 = CGIBAsmH
  { 4, &SystemZDescs.OperandInfo[711] },  // Inst #731 = CGIBAsmE
  { 5, &SystemZDescs.OperandInfo[706] },  // Inst #730 = CGIBAsm
  { 5, &SystemZDescs.OperandInfo[706] },  // Inst #729 = CGIB
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #728 = CGHSI
  { 2, &SystemZDescs.OperandInfo[704] },  // Inst #727 = CGHRL
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #726 = CGHI
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #725 = CGH
  { 2, &SystemZDescs.OperandInfo[704] },  // Inst #724 = CGFRL
  { 2, &SystemZDescs.OperandInfo[702] },  // Inst #723 = CGFR
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #722 = CGFI
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #721 = CGF
  { 3, &SystemZDescs.OperandInfo[695] },  // Inst #720 = CGER
  { 4, &SystemZDescs.OperandInfo[698] },  // Inst #719 = CGEBRA
  { 3, &SystemZDescs.OperandInfo[695] },  // Inst #718 = CGEBR
  { 4, &SystemZDescs.OperandInfo[691] },  // Inst #717 = CGDTRA
  { 3, &SystemZDescs.OperandInfo[688] },  // Inst #716 = CGDTR
  { 3, &SystemZDescs.OperandInfo[688] },  // Inst #715 = CGDR
  { 4, &SystemZDescs.OperandInfo[691] },  // Inst #714 = CGDBRA
  { 3, &SystemZDescs.OperandInfo[688] },  // Inst #713 = CGDBR
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #712 = CG
  { 4, &SystemZDescs.OperandInfo[684] },  // Inst #711 = CFXTR
  { 3, &SystemZDescs.OperandInfo[681] },  // Inst #710 = CFXR
  { 4, &SystemZDescs.OperandInfo[684] },  // Inst #709 = CFXBRA
  { 3, &SystemZDescs.OperandInfo[681] },  // Inst #708 = CFXBR
  { 2, &SystemZDescs.OperandInfo[679] },  // Inst #707 = CFI
  { 3, &SystemZDescs.OperandInfo[672] },  // Inst #706 = CFER
  { 4, &SystemZDescs.OperandInfo[675] },  // Inst #705 = CFEBRA
  { 3, &SystemZDescs.OperandInfo[672] },  // Inst #704 = CFEBR
  { 4, &SystemZDescs.OperandInfo[668] },  // Inst #703 = CFDTR
  { 3, &SystemZDescs.OperandInfo[665] },  // Inst #702 = CFDR
  { 4, &SystemZDescs.OperandInfo[668] },  // Inst #701 = CFDBRA
  { 3, &SystemZDescs.OperandInfo[665] },  // Inst #700 = CFDBR
  { 2, &SystemZDescs.OperandInfo[663] },  // Inst #699 = CFC
  { 2, &SystemZDescs.OperandInfo[661] },  // Inst #698 = CEXTR
  { 2, &SystemZDescs.OperandInfo[647] },  // Inst #697 = CER
  { 4, &SystemZDescs.OperandInfo[657] },  // Inst #696 = CELGBR
  { 4, &SystemZDescs.OperandInfo[651] },  // Inst #695 = CELFBR
  { 2, &SystemZDescs.OperandInfo[655] },  // Inst #694 = CEGR
  { 4, &SystemZDescs.OperandInfo[657] },  // Inst #693 = CEGBRA
  { 2, &SystemZDescs.OperandInfo[655] },  // Inst #692 = CEGBR
  { 2, &SystemZDescs.OperandInfo[649] },  // Inst #691 = CEFR
  { 4, &SystemZDescs.OperandInfo[651] },  // Inst #690 = CEFBRA
  { 2, &SystemZDescs.OperandInfo[649] },  // Inst #689 = CEFBR
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #688 = CEDTR
  { 2, &SystemZDescs.OperandInfo[647] },  // Inst #687 = CEBR
  { 4, &SystemZDescs.OperandInfo[643] },  // Inst #686 = CEB
  { 4, &SystemZDescs.OperandInfo[643] },  // Inst #685 = CE
  { 5, &SystemZDescs.OperandInfo[633] },  // Inst #684 = CDZT
  { 2, &SystemZDescs.OperandInfo[627] },  // Inst #683 = CDUTR
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #682 = CDTR
  { 5, &SystemZDescs.OperandInfo[638] },  // Inst #681 = CDSY
  { 2, &SystemZDescs.OperandInfo[627] },  // Inst #680 = CDSTR
  { 5, &SystemZDescs.OperandInfo[638] },  // Inst #679 = CDSG
  { 5, &SystemZDescs.OperandInfo[638] },  // Inst #678 = CDS
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #677 = CDR
  { 5, &SystemZDescs.OperandInfo[633] },  // Inst #676 = CDPT
  { 4, &SystemZDescs.OperandInfo[629] },  // Inst #675 = CDLGTR
  { 4, &SystemZDescs.OperandInfo[629] },  // Inst #674 = CDLGBR
  { 4, &SystemZDescs.OperandInfo[623] },  // Inst #673 = CDLFTR
  { 4, &SystemZDescs.OperandInfo[623] },  // Inst #672 = CDLFBR
  { 4, &SystemZDescs.OperandInfo[629] },  // Inst #671 = CDGTRA
  { 2, &SystemZDescs.OperandInfo[627] },  // Inst #670 = CDGTR
  { 2, &SystemZDescs.OperandInfo[627] },  // Inst #669 = CDGR
  { 4, &SystemZDescs.OperandInfo[629] },  // Inst #668 = CDGBRA
  { 2, &SystemZDescs.OperandInfo[627] },  // Inst #667 = CDGBR
  { 4, &SystemZDescs.OperandInfo[623] },  // Inst #666 = CDFTR
  { 2, &SystemZDescs.OperandInfo[621] },  // Inst #665 = CDFR
  { 4, &SystemZDescs.OperandInfo[623] },  // Inst #664 = CDFBRA
  { 2, &SystemZDescs.OperandInfo[621] },  // Inst #663 = CDFBR
  { 2, &SystemZDescs.OperandInfo[619] },  // Inst #662 = CDBR
  { 4, &SystemZDescs.OperandInfo[615] },  // Inst #661 = CDB
  { 4, &SystemZDescs.OperandInfo[615] },  // Inst #660 = CD
  { 4, &SystemZDescs.OperandInfo[611] },  // Inst #659 = C
  { 5, &SystemZDescs.OperandInfo[606] },  // Inst #658 = BXLEG
  { 5, &SystemZDescs.OperandInfo[601] },  // Inst #657 = BXLE
  { 5, &SystemZDescs.OperandInfo[606] },  // Inst #656 = BXHG
  { 5, &SystemZDescs.OperandInfo[601] },  // Inst #655 = BXH
  { 2, &SystemZDescs.OperandInfo[553] },  // Inst #654 = BSM
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #653 = BSG
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #652 = BSA
  { 4, &SystemZDescs.OperandInfo[597] },  // Inst #651 = BRXLG
  { 4, &SystemZDescs.OperandInfo[593] },  // Inst #650 = BRXLE
  { 4, &SystemZDescs.OperandInfo[597] },  // Inst #649 = BRXHG
  { 4, &SystemZDescs.OperandInfo[593] },  // Inst #648 = BRXH
  { 3, &SystemZDescs.OperandInfo[590] },  // Inst #647 = BRCTH
  { 3, &SystemZDescs.OperandInfo[587] },  // Inst #646 = BRCTG
  { 3, &SystemZDescs.OperandInfo[584] },  // Inst #645 = BRCT
  { 2, &SystemZDescs.OperandInfo[582] },  // Inst #644 = BRCLAsm
  { 3, &SystemZDescs.OperandInfo[251] },  // Inst #643 = BRCL
  { 2, &SystemZDescs.OperandInfo[582] },  // Inst #642 = BRCAsm
  { 3, &SystemZDescs.OperandInfo[251] },  // Inst #641 = BRC
  { 1, &SystemZDescs.OperandInfo[246] },  // Inst #640 = BRAsmZ
  { 1, &SystemZDescs.OperandInfo[246] },  // Inst #639 = BRAsmP
  { 1, &SystemZDescs.OperandInfo[246] },  // Inst #638 = BRAsmO
  { 1, &SystemZDescs.OperandInfo[246] },  // Inst #637 = BRAsmNZ
  { 1, &SystemZDescs.OperandInfo[246] },  // Inst #636 = BRAsmNP
  { 1, &SystemZDescs.OperandInfo[246] },  // Inst #635 = BRAsmNO
  { 1, &SystemZDescs.OperandInfo[246] },  // Inst #634 = BRAsmNM
  { 1, &SystemZDescs.OperandInfo[246] },  // Inst #633 = BRAsmNLH
  { 1, &SystemZDescs.OperandInfo[246] },  // Inst #632 = BRAsmNLE
  { 1, &SystemZDescs.OperandInfo[246] },  // Inst #631 = BRAsmNL
  { 1, &SystemZDescs.OperandInfo[246] },  // Inst #630 = BRAsmNHE
  { 1, &SystemZDescs.OperandInfo[246] },  // Inst #629 = BRAsmNH
  { 1, &SystemZDescs.OperandInfo[246] },  // Inst #628 = BRAsmNE
  { 1, &SystemZDescs.OperandInfo[246] },  // Inst #627 = BRAsmM
  { 1, &SystemZDescs.OperandInfo[246] },  // Inst #626 = BRAsmLH
  { 1, &SystemZDescs.OperandInfo[246] },  // Inst #625 = BRAsmLE
  { 1, &SystemZDescs.OperandInfo[246] },  // Inst #624 = BRAsmL
  { 1, &SystemZDescs.OperandInfo[246] },  // Inst #623 = BRAsmHE
  { 1, &SystemZDescs.OperandInfo[246] },  // Inst #622 = BRAsmH
  { 1, &SystemZDescs.OperandInfo[246] },  // Inst #621 = BRAsmE
  { 3, &SystemZDescs.OperandInfo[579] },  // Inst #620 = BRASL
  { 3, &SystemZDescs.OperandInfo[579] },  // Inst #619 = BRAS
  { 1, &SystemZDescs.OperandInfo[246] },  // Inst #618 = BR
  { 3, &SystemZDescs.OperandInfo[576] },  // Inst #617 = BPRP
  { 4, &SystemZDescs.OperandInfo[572] },  // Inst #616 = BPP
  { 4, &SystemZDescs.OperandInfo[560] },  // Inst #615 = BICAsm
  { 5, &SystemZDescs.OperandInfo[555] },  // Inst #614 = BIC
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #613 = BIAsmZ
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #612 = BIAsmP
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #611 = BIAsmO
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #610 = BIAsmNZ
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #609 = BIAsmNP
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #608 = BIAsmNO
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #607 = BIAsmNM
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #606 = BIAsmNLH
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #605 = BIAsmNLE
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #604 = BIAsmNL
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #603 = BIAsmNHE
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #602 = BIAsmNH
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #601 = BIAsmNE
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #600 = BIAsmM
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #599 = BIAsmLH
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #598 = BIAsmLE
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #597 = BIAsmL
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #596 = BIAsmHE
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #595 = BIAsmH
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #594 = BIAsmE
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #593 = BI
  { 3, &SystemZDescs.OperandInfo[569] },  // Inst #592 = BCTR
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #591 = BCTGR
  { 5, &SystemZDescs.OperandInfo[506] },  // Inst #590 = BCTG
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #589 = BCT
  { 2, &SystemZDescs.OperandInfo[567] },  // Inst #588 = BCRAsm
  { 3, &SystemZDescs.OperandInfo[564] },  // Inst #587 = BCR
  { 4, &SystemZDescs.OperandInfo[560] },  // Inst #586 = BCAsm
  { 5, &SystemZDescs.OperandInfo[555] },  // Inst #585 = BC
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #584 = BAsmZ
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #583 = BAsmP
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #582 = BAsmO
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #581 = BAsmNZ
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #580 = BAsmNP
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #579 = BAsmNO
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #578 = BAsmNM
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #577 = BAsmNLH
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #576 = BAsmNLE
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #575 = BAsmNL
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #574 = BAsmNHE
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #573 = BAsmNH
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #572 = BAsmNE
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #571 = BAsmM
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #570 = BAsmLH
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #569 = BAsmLE
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #568 = BAsmL
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #567 = BAsmHE
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #566 = BAsmH
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #565 = BAsmE
  { 2, &SystemZDescs.OperandInfo[553] },  // Inst #564 = BASSM
  { 2, &SystemZDescs.OperandInfo[553] },  // Inst #563 = BASR
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #562 = BAS
  { 2, &SystemZDescs.OperandInfo[553] },  // Inst #561 = BALR
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #560 = BAL
  { 2, &SystemZDescs.OperandInfo[551] },  // Inst #559 = BAKR
  { 3, &SystemZDescs.OperandInfo[548] },  // Inst #558 = B
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #557 = AY
  { 4, &SystemZDescs.OperandInfo[544] },  // Inst #556 = AXTRA
  { 3, &SystemZDescs.OperandInfo[541] },  // Inst #555 = AXTR
  { 3, &SystemZDescs.OperandInfo[538] },  // Inst #554 = AXR
  { 3, &SystemZDescs.OperandInfo[538] },  // Inst #553 = AXBR
  { 3, &SystemZDescs.OperandInfo[485] },  // Inst #552 = AWR
  { 5, &SystemZDescs.OperandInfo[480] },  // Inst #551 = AW
  { 3, &SystemZDescs.OperandInfo[500] },  // Inst #550 = AUR
  { 5, &SystemZDescs.OperandInfo[495] },  // Inst #549 = AU
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #548 = ASI
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #547 = ARK
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #546 = AR
  { 6, &SystemZDescs.OperandInfo[532] },  // Inst #545 = AP
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #544 = ALY
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #543 = ALSIHN
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #542 = ALSIH
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #541 = ALSI
  { 3, &SystemZDescs.OperandInfo[529] },  // Inst #540 = ALRK
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #539 = ALR
  { 3, &SystemZDescs.OperandInfo[239] },  // Inst #538 = ALHSIK
  { 3, &SystemZDescs.OperandInfo[520] },  // Inst #537 = ALHHLR
  { 3, &SystemZDescs.OperandInfo[517] },  // Inst #536 = ALHHHR
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #535 = ALGSI
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #534 = ALGRK
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #533 = ALGR
  { 3, &SystemZDescs.OperandInfo[211] },  // Inst #532 = ALGHSIK
  { 3, &SystemZDescs.OperandInfo[511] },  // Inst #531 = ALGFR
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #530 = ALGFI
  { 5, &SystemZDescs.OperandInfo[506] },  // Inst #529 = ALGF
  { 5, &SystemZDescs.OperandInfo[506] },  // Inst #528 = ALG
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #527 = ALFI
  { 3, &SystemZDescs.OperandInfo[526] },  // Inst #526 = ALCR
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #525 = ALCGR
  { 5, &SystemZDescs.OperandInfo[506] },  // Inst #524 = ALCG
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #523 = ALC
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #522 = AL
  { 3, &SystemZDescs.OperandInfo[523] },  // Inst #521 = AIH
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #520 = AHY
  { 3, &SystemZDescs.OperandInfo[239] },  // Inst #519 = AHIK
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #518 = AHI
  { 3, &SystemZDescs.OperandInfo[520] },  // Inst #517 = AHHLR
  { 3, &SystemZDescs.OperandInfo[517] },  // Inst #516 = AHHHR
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #515 = AH
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #514 = AGSI
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #513 = AGRK
  { 3, &SystemZDescs.OperandInfo[514] },  // Inst #512 = AGR
  { 3, &SystemZDescs.OperandInfo[211] },  // Inst #511 = AGHIK
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #510 = AGHI
  { 5, &SystemZDescs.OperandInfo[506] },  // Inst #509 = AGH
  { 3, &SystemZDescs.OperandInfo[511] },  // Inst #508 = AGFR
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #507 = AGFI
  { 5, &SystemZDescs.OperandInfo[506] },  // Inst #506 = AGF
  { 5, &SystemZDescs.OperandInfo[506] },  // Inst #505 = AG
  { 3, &SystemZDescs.OperandInfo[503] },  // Inst #504 = AFI
  { 3, &SystemZDescs.OperandInfo[500] },  // Inst #503 = AER
  { 3, &SystemZDescs.OperandInfo[500] },  // Inst #502 = AEBR
  { 5, &SystemZDescs.OperandInfo[495] },  // Inst #501 = AEB
  { 5, &SystemZDescs.OperandInfo[495] },  // Inst #500 = AE
  { 4, &SystemZDescs.OperandInfo[491] },  // Inst #499 = ADTRA
  { 3, &SystemZDescs.OperandInfo[488] },  // Inst #498 = ADTR
  { 3, &SystemZDescs.OperandInfo[485] },  // Inst #497 = ADR
  { 3, &SystemZDescs.OperandInfo[485] },  // Inst #496 = ADBR
  { 5, &SystemZDescs.OperandInfo[480] },  // Inst #495 = ADB
  { 5, &SystemZDescs.OperandInfo[480] },  // Inst #494 = AD
  { 5, &SystemZDescs.OperandInfo[475] },  // Inst #493 = A
  { 2, &SystemZDescs.OperandInfo[158] },  // Inst #492 = ZEXT128
  { 5, &SystemZDescs.OperandInfo[171] },  // Inst #491 = X_MemFoldPseudo
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #490 = XPLINK_STACKALLOC
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #489 = XILF64
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #488 = XIHF64
  { 3, &SystemZDescs.OperandInfo[160] },  // Inst #487 = XIFMux
  { 5, &SystemZDescs.OperandInfo[163] },  // Inst #486 = XG_MemFoldPseudo
  { 5, &SystemZDescs.OperandInfo[226] },  // Inst #485 = XCReg
  { 5, &SystemZDescs.OperandInfo[221] },  // Inst #484 = XCImm
  { 4, &SystemZDescs.OperandInfo[464] },  // Inst #483 = VST64
  { 4, &SystemZDescs.OperandInfo[460] },  // Inst #482 = VST32
  { 3, &SystemZDescs.OperandInfo[472] },  // Inst #481 = VLVGP32
  { 2, &SystemZDescs.OperandInfo[470] },  // Inst #480 = VLR64
  { 2, &SystemZDescs.OperandInfo[468] },  // Inst #479 = VLR32
  { 4, &SystemZDescs.OperandInfo[464] },  // Inst #478 = VL64
  { 4, &SystemZDescs.OperandInfo[460] },  // Inst #477 = VL32
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #476 = UCmp128Hi
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #475 = Trap
  { 2, &SystemZDescs.OperandInfo[198] },  // Inst #474 = TMLMux
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #473 = TMLL64
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #472 = TMLH64
  { 2, &SystemZDescs.OperandInfo[198] },  // Inst #471 = TMHMux
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #470 = TMHL64
  { 2, &SystemZDescs.OperandInfo[458] },  // Inst #469 = TMHH64
  { 1, &SystemZDescs.OperandInfo[0] },  // Inst #468 = TLS_LDCALL
  { 1, &SystemZDescs.OperandInfo[0] },  // Inst #467 = TLS_GDCALL
  { 3, &SystemZDescs.OperandInfo[455] },  // Inst #466 = TBEGIN_nofloat
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #465 = Serialize
  { 5, &SystemZDescs.OperandInfo[450] },  // Inst #464 = SelectVR64
  { 5, &SystemZDescs.OperandInfo[445] },  // Inst #463 = SelectVR32
  { 5, &SystemZDescs.OperandInfo[415] },  // Inst #462 = SelectVR128
  { 5, &SystemZDescs.OperandInfo[440] },  // Inst #461 = SelectF64
  { 5, &SystemZDescs.OperandInfo[435] },  // Inst #460 = SelectF32
  { 5, &SystemZDescs.OperandInfo[430] },  // Inst #459 = SelectF128
  { 5, &SystemZDescs.OperandInfo[425] },  // Inst #458 = Select64
  { 5, &SystemZDescs.OperandInfo[420] },  // Inst #457 = Select32
  { 5, &SystemZDescs.OperandInfo[415] },  // Inst #456 = Select128
  { 5, &SystemZDescs.OperandInfo[171] },  // Inst #455 = S_MemFoldPseudo
  { 4, &SystemZDescs.OperandInfo[335] },  // Inst #454 = STX
  { 5, &SystemZDescs.OperandInfo[410] },  // Inst #453 = STOCMux
  { 4, &SystemZDescs.OperandInfo[231] },  // Inst #452 = STMux
  { 4, &SystemZDescs.OperandInfo[231] },  // Inst #451 = STHMux
  { 4, &SystemZDescs.OperandInfo[231] },  // Inst #450 = STCMux
  { 4, &SystemZDescs.OperandInfo[294] },  // Inst #449 = ST128
  { 4, &SystemZDescs.OperandInfo[242] },  // Inst #448 = SRSTLoop
  { 5, &SystemZDescs.OperandInfo[171] },  // Inst #447 = SL_MemFoldPseudo
  { 5, &SystemZDescs.OperandInfo[163] },  // Inst #446 = SLG_MemFoldPseudo
  { 5, &SystemZDescs.OperandInfo[163] },  // Inst #445 = SG_MemFoldPseudo
  { 5, &SystemZDescs.OperandInfo[405] },  // Inst #444 = SELRMux
  { 5, &SystemZDescs.OperandInfo[153] },  // Inst #443 = SEB_MemFoldPseudo
  { 5, &SystemZDescs.OperandInfo[144] },  // Inst #442 = SDB_MemFoldPseudo
  { 2, &SystemZDescs.OperandInfo[403] },  // Inst #441 = SCmp128Hi
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #440 = Return_XPLINK
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #439 = Return
  { 6, &SystemZDescs.OperandInfo[397] },  // Inst #438 = RISBMux
  { 6, &SystemZDescs.OperandInfo[391] },  // Inst #437 = RISBLL
  { 6, &SystemZDescs.OperandInfo[385] },  // Inst #436 = RISBLH
  { 6, &SystemZDescs.OperandInfo[379] },  // Inst #435 = RISBHL
  { 6, &SystemZDescs.OperandInfo[373] },  // Inst #434 = RISBHH
  { 1, &SystemZDescs.OperandInfo[1] },  // Inst #433 = PROBED_STACKALLOC
  { 3, &SystemZDescs.OperandInfo[370] },  // Inst #432 = PROBED_ALLOCA
  { 3, &SystemZDescs.OperandInfo[367] },  // Inst #431 = PAIR128
  { 5, &SystemZDescs.OperandInfo[171] },  // Inst #430 = O_MemFoldPseudo
  { 3, &SystemZDescs.OperandInfo[160] },  // Inst #429 = OILMux
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #428 = OILL64
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #427 = OILH64
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #426 = OILF64
  { 3, &SystemZDescs.OperandInfo[160] },  // Inst #425 = OIHMux
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #424 = OIHL64
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #423 = OIHH64
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #422 = OIHF64
  { 3, &SystemZDescs.OperandInfo[160] },  // Inst #421 = OIFMux
  { 5, &SystemZDescs.OperandInfo[163] },  // Inst #420 = OG_MemFoldPseudo
  { 5, &SystemZDescs.OperandInfo[226] },  // Inst #419 = OCReg
  { 5, &SystemZDescs.OperandInfo[221] },  // Inst #418 = OCImm
  { 5, &SystemZDescs.OperandInfo[171] },  // Inst #417 = N_MemFoldPseudo
  { 3, &SystemZDescs.OperandInfo[160] },  // Inst #416 = NILMux
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #415 = NILL64
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #414 = NILH64
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #413 = NILF64
  { 3, &SystemZDescs.OperandInfo[160] },  // Inst #412 = NIHMux
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #411 = NIHL64
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #410 = NIHH64
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #409 = NIHF64
  { 3, &SystemZDescs.OperandInfo[160] },  // Inst #408 = NIFMux
  { 5, &SystemZDescs.OperandInfo[163] },  // Inst #407 = NG_MemFoldPseudo
  { 5, &SystemZDescs.OperandInfo[226] },  // Inst #406 = NCReg
  { 5, &SystemZDescs.OperandInfo[221] },  // Inst #405 = NCImm
  { 4, &SystemZDescs.OperandInfo[363] },  // Inst #404 = MemsetRegReg
  { 4, &SystemZDescs.OperandInfo[359] },  // Inst #403 = MemsetRegImm
  { 4, &SystemZDescs.OperandInfo[355] },  // Inst #402 = MemsetImmReg
  { 4, &SystemZDescs.OperandInfo[351] },  // Inst #401 = MemsetImmImm
  { 4, &SystemZDescs.OperandInfo[242] },  // Inst #400 = MVSTLoop
  { 5, &SystemZDescs.OperandInfo[226] },  // Inst #399 = MVCReg
  { 5, &SystemZDescs.OperandInfo[221] },  // Inst #398 = MVCImm
  { 5, &SystemZDescs.OperandInfo[163] },  // Inst #397 = MSGC_MemFoldPseudo
  { 6, &SystemZDescs.OperandInfo[345] },  // Inst #396 = MSEB_MemFoldPseudo
  { 6, &SystemZDescs.OperandInfo[339] },  // Inst #395 = MSDB_MemFoldPseudo
  { 5, &SystemZDescs.OperandInfo[171] },  // Inst #394 = MSC_MemFoldPseudo
  { 5, &SystemZDescs.OperandInfo[153] },  // Inst #393 = MEEB_MemFoldPseudo
  { 5, &SystemZDescs.OperandInfo[144] },  // Inst #392 = MDB_MemFoldPseudo
  { 6, &SystemZDescs.OperandInfo[345] },  // Inst #391 = MAEB_MemFoldPseudo
  { 6, &SystemZDescs.OperandInfo[339] },  // Inst #390 = MADB_MemFoldPseudo
  { 4, &SystemZDescs.OperandInfo[335] },  // Inst #389 = LX
  { 1, &SystemZDescs.OperandInfo[334] },  // Inst #388 = LTXBRCompare_Pseudo
  { 1, &SystemZDescs.OperandInfo[333] },  // Inst #387 = LTEBRCompare_Pseudo
  { 1, &SystemZDescs.OperandInfo[332] },  // Inst #386 = LTDBRCompare_Pseudo
  { 5, &SystemZDescs.OperandInfo[327] },  // Inst #385 = LOCRMux
  { 6, &SystemZDescs.OperandInfo[321] },  // Inst #384 = LOCMux_MemFoldPseudo
  { 6, &SystemZDescs.OperandInfo[315] },  // Inst #383 = LOCMux
  { 5, &SystemZDescs.OperandInfo[310] },  // Inst #382 = LOCHIMux
  { 6, &SystemZDescs.OperandInfo[304] },  // Inst #381 = LOCG_MemFoldPseudo
  { 4, &SystemZDescs.OperandInfo[231] },  // Inst #380 = LMux
  { 2, &SystemZDescs.OperandInfo[302] },  // Inst #379 = LLHRMux
  { 4, &SystemZDescs.OperandInfo[231] },  // Inst #378 = LLHMux
  { 2, &SystemZDescs.OperandInfo[302] },  // Inst #377 = LLCRMux
  { 4, &SystemZDescs.OperandInfo[231] },  // Inst #376 = LLCMux
  { 4, &SystemZDescs.OperandInfo[231] },  // Inst #375 = LHMux
  { 2, &SystemZDescs.OperandInfo[198] },  // Inst #374 = LHIMux
  { 2, &SystemZDescs.OperandInfo[300] },  // Inst #373 = LFER
  { 2, &SystemZDescs.OperandInfo[298] },  // Inst #372 = LEFR
  { 4, &SystemZDescs.OperandInfo[231] },  // Inst #371 = LBMux
  { 4, &SystemZDescs.OperandInfo[294] },  // Inst #370 = L128
  { 3, &SystemZDescs.OperandInfo[160] },  // Inst #369 = IILMux
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #368 = IILL64
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #367 = IILH64
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #366 = IILF64
  { 3, &SystemZDescs.OperandInfo[160] },  // Inst #365 = IIHMux
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #364 = IIHL64
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #363 = IIHH64
  { 3, &SystemZDescs.OperandInfo[291] },  // Inst #362 = IIHF64
  { 2, &SystemZDescs.OperandInfo[198] },  // Inst #361 = IIFMux
  { 1, &SystemZDescs.OperandInfo[290] },  // Inst #360 = GOT
  { 6, &SystemZDescs.OperandInfo[284] },  // Inst #359 = EXRL_Pseudo
  { 5, &SystemZDescs.OperandInfo[153] },  // Inst #358 = DEB_MemFoldPseudo
  { 5, &SystemZDescs.OperandInfo[144] },  // Inst #357 = DDB_MemFoldPseudo
  { 2, &SystemZDescs.OperandInfo[21] },  // Inst #356 = CondTrap
  { 6, &SystemZDescs.OperandInfo[278] },  // Inst #355 = CondStoreF64Inv
  { 6, &SystemZDescs.OperandInfo[278] },  // Inst #354 = CondStoreF64
  { 6, &SystemZDescs.OperandInfo[272] },  // Inst #353 = CondStoreF32Inv
  { 6, &SystemZDescs.OperandInfo[272] },  // Inst #352 = CondStoreF32
  { 6, &SystemZDescs.OperandInfo[260] },  // Inst #351 = CondStore8MuxInv
  { 6, &SystemZDescs.OperandInfo[260] },  // Inst #350 = CondStore8Mux
  { 6, &SystemZDescs.OperandInfo[254] },  // Inst #349 = CondStore8Inv
  { 6, &SystemZDescs.OperandInfo[254] },  // Inst #348 = CondStore8
  { 6, &SystemZDescs.OperandInfo[266] },  // Inst #347 = CondStore64Inv
  { 6, &SystemZDescs.OperandInfo[266] },  // Inst #346 = CondStore64
  { 6, &SystemZDescs.OperandInfo[260] },  // Inst #345 = CondStore32MuxInv
  { 6, &SystemZDescs.OperandInfo[260] },  // Inst #344 = CondStore32Mux
  { 6, &SystemZDescs.OperandInfo[254] },  // Inst #343 = CondStore32Inv
  { 6, &SystemZDescs.OperandInfo[254] },  // Inst #342 = CondStore32
  { 6, &SystemZDescs.OperandInfo[260] },  // Inst #341 = CondStore16MuxInv
  { 6, &SystemZDescs.OperandInfo[260] },  // Inst #340 = CondStore16Mux
  { 6, &SystemZDescs.OperandInfo[254] },  // Inst #339 = CondStore16Inv
  { 6, &SystemZDescs.OperandInfo[254] },  // Inst #338 = CondStore16
  { 2, &SystemZDescs.OperandInfo[21] },  // Inst #337 = CondReturn_XPLINK
  { 2, &SystemZDescs.OperandInfo[21] },  // Inst #336 = CondReturn
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #335 = CallJG
  { 3, &SystemZDescs.OperandInfo[251] },  // Inst #334 = CallBRCL
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #333 = CallBRASL_XPLINK64
  { 1, &SystemZDescs.OperandInfo[250] },  // Inst #332 = CallBRASL
  { 1, &SystemZDescs.OperandInfo[246] },  // Inst #331 = CallBR
  { 3, &SystemZDescs.OperandInfo[247] },  // Inst #330 = CallBCR
  { 1, &SystemZDescs.OperandInfo[246] },  // Inst #329 = CallBASR_XPLINK64
  { 1, &SystemZDescs.OperandInfo[246] },  // Inst #328 = CallBASR_STACKEXT
  { 1, &SystemZDescs.OperandInfo[246] },  // Inst #327 = CallBASR
  { 3, &SystemZDescs.OperandInfo[239] },  // Inst #326 = CRBReturn
  { 4, &SystemZDescs.OperandInfo[235] },  // Inst #325 = CRBCall
  { 4, &SystemZDescs.OperandInfo[231] },  // Inst #324 = CMux
  { 4, &SystemZDescs.OperandInfo[242] },  // Inst #323 = CLSTLoop
  { 3, &SystemZDescs.OperandInfo[239] },  // Inst #322 = CLRBReturn
  { 4, &SystemZDescs.OperandInfo[235] },  // Inst #321 = CLRBCall
  { 4, &SystemZDescs.OperandInfo[231] },  // Inst #320 = CLMux
  { 3, &SystemZDescs.OperandInfo[218] },  // Inst #319 = CLIBReturn
  { 4, &SystemZDescs.OperandInfo[214] },  // Inst #318 = CLIBCall
  { 3, &SystemZDescs.OperandInfo[211] },  // Inst #317 = CLGRBReturn
  { 4, &SystemZDescs.OperandInfo[207] },  // Inst #316 = CLGRBCall
  { 3, &SystemZDescs.OperandInfo[204] },  // Inst #315 = CLGIBReturn
  { 4, &SystemZDescs.OperandInfo[200] },  // Inst #314 = CLGIBCall
  { 2, &SystemZDescs.OperandInfo[198] },  // Inst #313 = CLFIMux
  { 5, &SystemZDescs.OperandInfo[226] },  // Inst #312 = CLCReg
  { 5, &SystemZDescs.OperandInfo[221] },  // Inst #311 = CLCImm
  { 3, &SystemZDescs.OperandInfo[218] },  // Inst #310 = CIBReturn
  { 4, &SystemZDescs.OperandInfo[214] },  // Inst #309 = CIBCall
  { 2, &SystemZDescs.OperandInfo[198] },  // Inst #308 = CHIMux
  { 3, &SystemZDescs.OperandInfo[211] },  // Inst #307 = CGRBReturn
  { 4, &SystemZDescs.OperandInfo[207] },  // Inst #306 = CGRBCall
  { 3, &SystemZDescs.OperandInfo[204] },  // Inst #305 = CGIBReturn
  { 4, &SystemZDescs.OperandInfo[200] },  // Inst #304 = CGIBCall
  { 2, &SystemZDescs.OperandInfo[198] },  // Inst #303 = CFIMux
  { 5, &SystemZDescs.OperandInfo[171] },  // Inst #302 = A_MemFoldPseudo
  { 7, &SystemZDescs.OperandInfo[191] },  // Inst #301 = ATOMIC_SWAPW
  { 7, &SystemZDescs.OperandInfo[191] },  // Inst #300 = ATOMIC_LOADW_XR
  { 7, &SystemZDescs.OperandInfo[184] },  // Inst #299 = ATOMIC_LOADW_XILF
  { 7, &SystemZDescs.OperandInfo[191] },  // Inst #298 = ATOMIC_LOADW_UMIN
  { 7, &SystemZDescs.OperandInfo[191] },  // Inst #297 = ATOMIC_LOADW_UMAX
  { 7, &SystemZDescs.OperandInfo[191] },  // Inst #296 = ATOMIC_LOADW_SR
  { 7, &SystemZDescs.OperandInfo[191] },  // Inst #295 = ATOMIC_LOADW_OR
  { 7, &SystemZDescs.OperandInfo[184] },  // Inst #294 = ATOMIC_LOADW_OILH
  { 7, &SystemZDescs.OperandInfo[191] },  // Inst #293 = ATOMIC_LOADW_NRi
  { 7, &SystemZDescs.OperandInfo[191] },  // Inst #292 = ATOMIC_LOADW_NR
  { 7, &SystemZDescs.OperandInfo[184] },  // Inst #291 = ATOMIC_LOADW_NILHi
  { 7, &SystemZDescs.OperandInfo[184] },  // Inst #290 = ATOMIC_LOADW_NILH
  { 7, &SystemZDescs.OperandInfo[191] },  // Inst #289 = ATOMIC_LOADW_MIN
  { 7, &SystemZDescs.OperandInfo[191] },  // Inst #288 = ATOMIC_LOADW_MAX
  { 7, &SystemZDescs.OperandInfo[191] },  // Inst #287 = ATOMIC_LOADW_AR
  { 7, &SystemZDescs.OperandInfo[184] },  // Inst #286 = ATOMIC_LOADW_AFI
  { 8, &SystemZDescs.OperandInfo[176] },  // Inst #285 = ATOMIC_CMP_SWAPW
  { 5, &SystemZDescs.OperandInfo[171] },  // Inst #284 = AL_MemFoldPseudo
  { 5, &SystemZDescs.OperandInfo[163] },  // Inst #283 = ALG_MemFoldPseudo
  { 3, &SystemZDescs.OperandInfo[168] },  // Inst #282 = AHIMuxK
  { 3, &SystemZDescs.OperandInfo[160] },  // Inst #281 = AHIMux
  { 5, &SystemZDescs.OperandInfo[163] },  // Inst #280 = AG_MemFoldPseudo
  { 3, &SystemZDescs.OperandInfo[160] },  // Inst #279 = AFIMux
  { 2, &SystemZDescs.OperandInfo[158] },  // Inst #278 = AEXT128
  { 5, &SystemZDescs.OperandInfo[153] },  // Inst #277 = AEB_MemFoldPseudo
  { 4, &SystemZDescs.OperandInfo[149] },  // Inst #276 = ADJDYNALLOC
  { 2, &SystemZDescs.OperandInfo[21] },  // Inst #275 = ADJCALLSTACKUP
  { 2, &SystemZDescs.OperandInfo[21] },  // Inst #274 = ADJCALLSTACKDOWN
  { 5, &SystemZDescs.OperandInfo[144] },  // Inst #273 = ADB_MemFoldPseudo
  { 4, &SystemZDescs.OperandInfo[140] },  // Inst #272 = ADA_ENTRY_VALUE
  { 4, &SystemZDescs.OperandInfo[140] },  // Inst #271 = ADA_ENTRY
  { 4, &SystemZDescs.OperandInfo[136] },  // Inst #270 = G_UBFX
  { 4, &SystemZDescs.OperandInfo[136] },  // Inst #269 = G_SBFX
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #268 = G_VECREDUCE_UMIN
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #267 = G_VECREDUCE_UMAX
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #266 = G_VECREDUCE_SMIN
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #265 = G_VECREDUCE_SMAX
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #264 = G_VECREDUCE_XOR
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #263 = G_VECREDUCE_OR
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #262 = G_VECREDUCE_AND
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #261 = G_VECREDUCE_MUL
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #260 = G_VECREDUCE_ADD
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #259 = G_VECREDUCE_FMINIMUM
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #258 = G_VECREDUCE_FMAXIMUM
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #257 = G_VECREDUCE_FMIN
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #256 = G_VECREDUCE_FMAX
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #255 = G_VECREDUCE_FMUL
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #254 = G_VECREDUCE_FADD
  { 3, &SystemZDescs.OperandInfo[123] },  // Inst #253 = G_VECREDUCE_SEQ_FMUL
  { 3, &SystemZDescs.OperandInfo[123] },  // Inst #252 = G_VECREDUCE_SEQ_FADD
  { 3, &SystemZDescs.OperandInfo[53] },  // Inst #251 = G_BZERO
  { 4, &SystemZDescs.OperandInfo[132] },  // Inst #250 = G_MEMSET
  { 4, &SystemZDescs.OperandInfo[132] },  // Inst #249 = G_MEMMOVE
  { 3, &SystemZDescs.OperandInfo[123] },  // Inst #248 = G_MEMCPY_INLINE
  { 4, &SystemZDescs.OperandInfo[132] },  // Inst #247 = G_MEMCPY
  { 2, &SystemZDescs.OperandInfo[130] },  // Inst #246 = G_WRITE_REGISTER
  { 2, &SystemZDescs.OperandInfo[51] },  // Inst #245 = G_READ_REGISTER
  { 3, &SystemZDescs.OperandInfo[96] },  // Inst #244 = G_STRICT_FLDEXP
  { 2, &SystemZDescs.OperandInfo[62] },  // Inst #243 = G_STRICT_FSQRT
  { 4, &SystemZDescs.OperandInfo[46] },  // Inst #242 = G_STRICT_FMA
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #241 = G_STRICT_FREM
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #240 = G_STRICT_FDIV
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #239 = G_STRICT_FMUL
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #238 = G_STRICT_FSUB
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #237 = G_STRICT_FADD
  { 1, &SystemZDescs.OperandInfo[50] },  // Inst #236 = G_STACKRESTORE
  { 1, &SystemZDescs.OperandInfo[50] },  // Inst #235 = G_STACKSAVE
  { 3, &SystemZDescs.OperandInfo[64] },  // Inst #234 = G_DYN_STACKALLOC
  { 2, &SystemZDescs.OperandInfo[51] },  // Inst #233 = G_JUMP_TABLE
  { 2, &SystemZDescs.OperandInfo[51] },  // Inst #232 = G_BLOCK_ADDR
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #231 = G_ADDRSPACE_CAST
  { 2, &SystemZDescs.OperandInfo[62] },  // Inst #230 = G_FNEARBYINT
  { 2, &SystemZDescs.OperandInfo[62] },  // Inst #229 = G_FRINT
  { 2, &SystemZDescs.OperandInfo[62] },  // Inst #228 = G_FFLOOR
  { 2, &SystemZDescs.OperandInfo[62] },  // Inst #227 = G_FSQRT
  { 2, &SystemZDescs.OperandInfo[62] },  // Inst #226 = G_FSIN
  { 2, &SystemZDescs.OperandInfo[62] },  // Inst #225 = G_FCOS
  { 2, &SystemZDescs.OperandInfo[62] },  // Inst #224 = G_FCEIL
  { 2, &SystemZDescs.OperandInfo[62] },  // Inst #223 = G_BITREVERSE
  { 2, &SystemZDescs.OperandInfo[62] },  // Inst #222 = G_BSWAP
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #221 = G_CTPOP
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #220 = G_CTLZ_ZERO_UNDEF
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #219 = G_CTLZ
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #218 = G_CTTZ_ZERO_UNDEF
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #217 = G_CTTZ
  { 4, &SystemZDescs.OperandInfo[126] },  // Inst #216 = G_SHUFFLE_VECTOR
  { 3, &SystemZDescs.OperandInfo[123] },  // Inst #215 = G_EXTRACT_VECTOR_ELT
  { 4, &SystemZDescs.OperandInfo[119] },  // Inst #214 = G_INSERT_VECTOR_ELT
  { 3, &SystemZDescs.OperandInfo[116] },  // Inst #213 = G_BRJT
  { 1, &SystemZDescs.OperandInfo[0] },  // Inst #212 = G_BR
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #211 = G_LLROUND
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #210 = G_LROUND
  { 2, &SystemZDescs.OperandInfo[62] },  // Inst #209 = G_ABS
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #208 = G_UMAX
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #207 = G_UMIN
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #206 = G_SMAX
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #205 = G_SMIN
  { 3, &SystemZDescs.OperandInfo[96] },  // Inst #204 = G_PTRMASK
  { 3, &SystemZDescs.OperandInfo[96] },  // Inst #203 = G_PTR_ADD
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #202 = G_RESET_FPMODE
  { 1, &SystemZDescs.OperandInfo[50] },  // Inst #201 = G_SET_FPMODE
  { 1, &SystemZDescs.OperandInfo[50] },  // Inst #200 = G_GET_FPMODE
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #199 = G_RESET_FPENV
  { 1, &SystemZDescs.OperandInfo[50] },  // Inst #198 = G_SET_FPENV
  { 1, &SystemZDescs.OperandInfo[50] },  // Inst #197 = G_GET_FPENV
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #196 = G_FMAXIMUM
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #195 = G_FMINIMUM
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #194 = G_FMAXNUM_IEEE
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #193 = G_FMINNUM_IEEE
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #192 = G_FMAXNUM
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #191 = G_FMINNUM
  { 2, &SystemZDescs.OperandInfo[62] },  // Inst #190 = G_FCANONICALIZE
  { 3, &SystemZDescs.OperandInfo[93] },  // Inst #189 = G_IS_FPCLASS
  { 3, &SystemZDescs.OperandInfo[96] },  // Inst #188 = G_FCOPYSIGN
  { 2, &SystemZDescs.OperandInfo[62] },  // Inst #187 = G_FABS
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #186 = G_UITOFP
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #185 = G_SITOFP
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #184 = G_FPTOUI
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #183 = G_FPTOSI
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #182 = G_FPTRUNC
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #181 = G_FPEXT
  { 2, &SystemZDescs.OperandInfo[62] },  // Inst #180 = G_FNEG
  { 3, &SystemZDescs.OperandInfo[86] },  // Inst #179 = G_FFREXP
  { 3, &SystemZDescs.OperandInfo[96] },  // Inst #178 = G_FLDEXP
  { 2, &SystemZDescs.OperandInfo[62] },  // Inst #177 = G_FLOG10
  { 2, &SystemZDescs.OperandInfo[62] },  // Inst #176 = G_FLOG2
  { 2, &SystemZDescs.OperandInfo[62] },  // Inst #175 = G_FLOG
  { 2, &SystemZDescs.OperandInfo[62] },  // Inst #174 = G_FEXP10
  { 2, &SystemZDescs.OperandInfo[62] },  // Inst #173 = G_FEXP2
  { 2, &SystemZDescs.OperandInfo[62] },  // Inst #172 = G_FEXP
  { 3, &SystemZDescs.OperandInfo[96] },  // Inst #171 = G_FPOWI
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #170 = G_FPOW
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #169 = G_FREM
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #168 = G_FDIV
  { 4, &SystemZDescs.OperandInfo[46] },  // Inst #167 = G_FMAD
  { 4, &SystemZDescs.OperandInfo[46] },  // Inst #166 = G_FMA
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #165 = G_FMUL
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #164 = G_FSUB
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #163 = G_FADD
  { 4, &SystemZDescs.OperandInfo[112] },  // Inst #162 = G_UDIVFIXSAT
  { 4, &SystemZDescs.OperandInfo[112] },  // Inst #161 = G_SDIVFIXSAT
  { 4, &SystemZDescs.OperandInfo[112] },  // Inst #160 = G_UDIVFIX
  { 4, &SystemZDescs.OperandInfo[112] },  // Inst #159 = G_SDIVFIX
  { 4, &SystemZDescs.OperandInfo[112] },  // Inst #158 = G_UMULFIXSAT
  { 4, &SystemZDescs.OperandInfo[112] },  // Inst #157 = G_SMULFIXSAT
  { 4, &SystemZDescs.OperandInfo[112] },  // Inst #156 = G_UMULFIX
  { 4, &SystemZDescs.OperandInfo[112] },  // Inst #155 = G_SMULFIX
  { 3, &SystemZDescs.OperandInfo[96] },  // Inst #154 = G_SSHLSAT
  { 3, &SystemZDescs.OperandInfo[96] },  // Inst #153 = G_USHLSAT
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #152 = G_SSUBSAT
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #151 = G_USUBSAT
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #150 = G_SADDSAT
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #149 = G_UADDSAT
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #148 = G_SMULH
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #147 = G_UMULH
  { 4, &SystemZDescs.OperandInfo[82] },  // Inst #146 = G_SMULO
  { 4, &SystemZDescs.OperandInfo[82] },  // Inst #145 = G_UMULO
  { 5, &SystemZDescs.OperandInfo[107] },  // Inst #144 = G_SSUBE
  { 4, &SystemZDescs.OperandInfo[82] },  // Inst #143 = G_SSUBO
  { 5, &SystemZDescs.OperandInfo[107] },  // Inst #142 = G_SADDE
  { 4, &SystemZDescs.OperandInfo[82] },  // Inst #141 = G_SADDO
  { 5, &SystemZDescs.OperandInfo[107] },  // Inst #140 = G_USUBE
  { 4, &SystemZDescs.OperandInfo[82] },  // Inst #139 = G_USUBO
  { 5, &SystemZDescs.OperandInfo[107] },  // Inst #138 = G_UADDE
  { 4, &SystemZDescs.OperandInfo[82] },  // Inst #137 = G_UADDO
  { 4, &SystemZDescs.OperandInfo[82] },  // Inst #136 = G_SELECT
  { 4, &SystemZDescs.OperandInfo[103] },  // Inst #135 = G_FCMP
  { 4, &SystemZDescs.OperandInfo[103] },  // Inst #134 = G_ICMP
  { 3, &SystemZDescs.OperandInfo[96] },  // Inst #133 = G_ROTL
  { 3, &SystemZDescs.OperandInfo[96] },  // Inst #132 = G_ROTR
  { 4, &SystemZDescs.OperandInfo[99] },  // Inst #131 = G_FSHR
  { 4, &SystemZDescs.OperandInfo[99] },  // Inst #130 = G_FSHL
  { 3, &SystemZDescs.OperandInfo[96] },  // Inst #129 = G_ASHR
  { 3, &SystemZDescs.OperandInfo[96] },  // Inst #128 = G_LSHR
  { 3, &SystemZDescs.OperandInfo[96] },  // Inst #127 = G_SHL
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #126 = G_ZEXT
  { 3, &SystemZDescs.OperandInfo[40] },  // Inst #125 = G_SEXT_INREG
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #124 = G_SEXT
  { 3, &SystemZDescs.OperandInfo[93] },  // Inst #123 = G_VAARG
  { 1, &SystemZDescs.OperandInfo[50] },  // Inst #122 = G_VASTART
  { 2, &SystemZDescs.OperandInfo[51] },  // Inst #121 = G_FCONSTANT
  { 2, &SystemZDescs.OperandInfo[51] },  // Inst #120 = G_CONSTANT
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #119 = G_TRUNC
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #118 = G_ANYEXT
  { 1, &SystemZDescs.OperandInfo[0] },  // Inst #117 = G_INTRINSIC_CONVERGENT_W_SIDE_EFFECTS
  { 1, &SystemZDescs.OperandInfo[0] },  // Inst #116 = G_INTRINSIC_CONVERGENT
  { 1, &SystemZDescs.OperandInfo[0] },  // Inst #115 = G_INTRINSIC_W_SIDE_EFFECTS
  { 1, &SystemZDescs.OperandInfo[0] },  // Inst #114 = G_INTRINSIC
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #113 = G_INVOKE_REGION_START
  { 1, &SystemZDescs.OperandInfo[50] },  // Inst #112 = G_BRINDIRECT
  { 2, &SystemZDescs.OperandInfo[51] },  // Inst #111 = G_BRCOND
  { 4, &SystemZDescs.OperandInfo[89] },  // Inst #110 = G_PREFETCH
  { 2, &SystemZDescs.OperandInfo[21] },  // Inst #109 = G_FENCE
  { 3, &SystemZDescs.OperandInfo[86] },  // Inst #108 = G_ATOMICRMW_UDEC_WRAP
  { 3, &SystemZDescs.OperandInfo[86] },  // Inst #107 = G_ATOMICRMW_UINC_WRAP
  { 3, &SystemZDescs.OperandInfo[86] },  // Inst #106 = G_ATOMICRMW_FMIN
  { 3, &SystemZDescs.OperandInfo[86] },  // Inst #105 = G_ATOMICRMW_FMAX
  { 3, &SystemZDescs.OperandInfo[86] },  // Inst #104 = G_ATOMICRMW_FSUB
  { 3, &SystemZDescs.OperandInfo[86] },  // Inst #103 = G_ATOMICRMW_FADD
  { 3, &SystemZDescs.OperandInfo[86] },  // Inst #102 = G_ATOMICRMW_UMIN
  { 3, &SystemZDescs.OperandInfo[86] },  // Inst #101 = G_ATOMICRMW_UMAX
  { 3, &SystemZDescs.OperandInfo[86] },  // Inst #100 = G_ATOMICRMW_MIN
  { 3, &SystemZDescs.OperandInfo[86] },  // Inst #99 = G_ATOMICRMW_MAX
  { 3, &SystemZDescs.OperandInfo[86] },  // Inst #98 = G_ATOMICRMW_XOR
  { 3, &SystemZDescs.OperandInfo[86] },  // Inst #97 = G_ATOMICRMW_OR
  { 3, &SystemZDescs.OperandInfo[86] },  // Inst #96 = G_ATOMICRMW_NAND
  { 3, &SystemZDescs.OperandInfo[86] },  // Inst #95 = G_ATOMICRMW_AND
  { 3, &SystemZDescs.OperandInfo[86] },  // Inst #94 = G_ATOMICRMW_SUB
  { 3, &SystemZDescs.OperandInfo[86] },  // Inst #93 = G_ATOMICRMW_ADD
  { 3, &SystemZDescs.OperandInfo[86] },  // Inst #92 = G_ATOMICRMW_XCHG
  { 4, &SystemZDescs.OperandInfo[82] },  // Inst #91 = G_ATOMIC_CMPXCHG
  { 5, &SystemZDescs.OperandInfo[77] },  // Inst #90 = G_ATOMIC_CMPXCHG_WITH_SUCCESS
  { 5, &SystemZDescs.OperandInfo[72] },  // Inst #89 = G_INDEXED_STORE
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #88 = G_STORE
  { 5, &SystemZDescs.OperandInfo[67] },  // Inst #87 = G_INDEXED_ZEXTLOAD
  { 5, &SystemZDescs.OperandInfo[67] },  // Inst #86 = G_INDEXED_SEXTLOAD
  { 5, &SystemZDescs.OperandInfo[67] },  // Inst #85 = G_INDEXED_LOAD
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #84 = G_ZEXTLOAD
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #83 = G_SEXTLOAD
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #82 = G_LOAD
  { 1, &SystemZDescs.OperandInfo[50] },  // Inst #81 = G_READCYCLECOUNTER
  { 2, &SystemZDescs.OperandInfo[62] },  // Inst #80 = G_INTRINSIC_ROUNDEVEN
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #79 = G_INTRINSIC_LRINT
  { 2, &SystemZDescs.OperandInfo[62] },  // Inst #78 = G_INTRINSIC_ROUND
  { 2, &SystemZDescs.OperandInfo[62] },  // Inst #77 = G_INTRINSIC_TRUNC
  { 3, &SystemZDescs.OperandInfo[64] },  // Inst #76 = G_INTRINSIC_FPTRUNC_ROUND
  { 2, &SystemZDescs.OperandInfo[62] },  // Inst #75 = G_CONSTANT_FOLD_BARRIER
  { 2, &SystemZDescs.OperandInfo[62] },  // Inst #74 = G_FREEZE
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #73 = G_BITCAST
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #72 = G_INTTOPTR
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #71 = G_PTRTOINT
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #70 = G_CONCAT_VECTORS
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #69 = G_BUILD_VECTOR_TRUNC
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #68 = G_BUILD_VECTOR
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #67 = G_MERGE_VALUES
  { 4, &SystemZDescs.OperandInfo[58] },  // Inst #66 = G_INSERT
  { 2, &SystemZDescs.OperandInfo[56] },  // Inst #65 = G_UNMERGE_VALUES
  { 3, &SystemZDescs.OperandInfo[53] },  // Inst #64 = G_EXTRACT
  { 2, &SystemZDescs.OperandInfo[51] },  // Inst #63 = G_CONSTANT_POOL
  { 2, &SystemZDescs.OperandInfo[51] },  // Inst #62 = G_GLOBAL_VALUE
  { 2, &SystemZDescs.OperandInfo[51] },  // Inst #61 = G_FRAME_INDEX
  { 1, &SystemZDescs.OperandInfo[50] },  // Inst #60 = G_PHI
  { 1, &SystemZDescs.OperandInfo[50] },  // Inst #59 = G_IMPLICIT_DEF
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #58 = G_XOR
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #57 = G_OR
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #56 = G_AND
  { 4, &SystemZDescs.OperandInfo[46] },  // Inst #55 = G_UDIVREM
  { 4, &SystemZDescs.OperandInfo[46] },  // Inst #54 = G_SDIVREM
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #53 = G_UREM
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #52 = G_SREM
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #51 = G_UDIV
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #50 = G_SDIV
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #49 = G_MUL
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #48 = G_SUB
  { 3, &SystemZDescs.OperandInfo[43] },  // Inst #47 = G_ADD
  { 3, &SystemZDescs.OperandInfo[40] },  // Inst #46 = G_ASSERT_ALIGN
  { 3, &SystemZDescs.OperandInfo[40] },  // Inst #45 = G_ASSERT_ZEXT
  { 3, &SystemZDescs.OperandInfo[40] },  // Inst #44 = G_ASSERT_SEXT
  { 1, &SystemZDescs.OperandInfo[1] },  // Inst #43 = JUMP_TABLE_DEBUG_INFO
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #42 = MEMBARRIER
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #41 = ICALL_BRANCH_FUNNEL
  { 3, &SystemZDescs.OperandInfo[37] },  // Inst #40 = PATCHABLE_TYPED_EVENT_CALL
  { 2, &SystemZDescs.OperandInfo[35] },  // Inst #39 = PATCHABLE_EVENT_CALL
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #38 = PATCHABLE_TAIL_CALL
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #37 = PATCHABLE_FUNCTION_EXIT
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #36 = PATCHABLE_RET
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #35 = PATCHABLE_FUNCTION_ENTER
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #34 = PATCHABLE_OP
  { 1, &SystemZDescs.OperandInfo[0] },  // Inst #33 = FAULTING_OP
  { 2, &SystemZDescs.OperandInfo[33] },  // Inst #32 = LOCAL_ESCAPE
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #31 = STATEPOINT
  { 3, &SystemZDescs.OperandInfo[30] },  // Inst #30 = PREALLOCATED_ARG
  { 1, &SystemZDescs.OperandInfo[1] },  // Inst #29 = PREALLOCATED_SETUP
  { 1, &SystemZDescs.OperandInfo[29] },  // Inst #28 = LOAD_STACK_GUARD
  { 6, &SystemZDescs.OperandInfo[23] },  // Inst #27 = PATCHPOINT
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #26 = FENTRY_CALL
  { 2, &SystemZDescs.OperandInfo[21] },  // Inst #25 = STACKMAP
  { 2, &SystemZDescs.OperandInfo[19] },  // Inst #24 = ARITH_FENCE
  { 4, &SystemZDescs.OperandInfo[15] },  // Inst #23 = PSEUDO_PROBE
  { 1, &SystemZDescs.OperandInfo[1] },  // Inst #22 = LIFETIME_END
  { 1, &SystemZDescs.OperandInfo[1] },  // Inst #21 = LIFETIME_START
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #20 = BUNDLE
  { 2, &SystemZDescs.OperandInfo[13] },  // Inst #19 = COPY
  { 2, &SystemZDescs.OperandInfo[13] },  // Inst #18 = REG_SEQUENCE
  { 1, &SystemZDescs.OperandInfo[0] },  // Inst #17 = DBG_LABEL
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #16 = DBG_PHI
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #15 = DBG_INSTR_REF
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #14 = DBG_VALUE_LIST
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #13 = DBG_VALUE
  { 3, &SystemZDescs.OperandInfo[2] },  // Inst #12 = COPY_TO_REGCLASS
  { 4, &SystemZDescs.OperandInfo[9] },  // Inst #11 = SUBREG_TO_REG
  { 1, &SystemZDescs.OperandInfo[0] },  // Inst #10 = IMPLICIT_DEF
  { 4, &SystemZDescs.OperandInfo[5] },  // Inst #9 = INSERT_SUBREG
  { 3, &SystemZDescs.OperandInfo[2] },  // Inst #8 = EXTRACT_SUBREG
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #7 = KILL
  { 1, &SystemZDescs.OperandInfo[1] },  // Inst #6 = ANNOTATION_LABEL
  { 1, &SystemZDescs.OperandInfo[1] },  // Inst #5 = GC_LABEL
  { 1, &SystemZDescs.OperandInfo[1] },  // Inst #4 = EH_LABEL
  { 1, &SystemZDescs.OperandInfo[1] },  // Inst #3 = CFI_INSTRUCTION
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #2 = INLINEASM_BR
  { 0, &SystemZDescs.OperandInfo[1] },  // Inst #1 = INLINEASM
  { 1, &SystemZDescs.OperandInfo[0] },  // Inst #0 = PHI
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
    /* 140 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_UNKNOWN, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 144 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 149 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 153 */ { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 158 */ { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 160 */ { SystemZ_GRX32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRX32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 163 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 168 */ { SystemZ_GRX32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRX32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 171 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 176 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 184 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_ADDR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 191 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 198 */ { SystemZ_GRX32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 200 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 204 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 207 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 211 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 214 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 218 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 221 */ { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 226 */ { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 231 */ { SystemZ_GRX32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 235 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 239 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 242 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 246 */ { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 247 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 250 */ { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 251 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 254 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 260 */ { SystemZ_GRX32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 266 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 272 */ { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 278 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 284 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 290 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 291 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 294 */ { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 298 */ { SystemZ_VR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 300 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 302 */ { SystemZ_GRX32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRX32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 304 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 310 */ { SystemZ_GRX32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRX32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 315 */ { SystemZ_GRX32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRX32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 321 */ { SystemZ_GRX32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRX32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 327 */ { SystemZ_GRX32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRX32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GRX32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 332 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 333 */ { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 334 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 335 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 339 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 345 */ { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 351 */ { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 355 */ { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 359 */ { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 363 */ { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 367 */ { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 370 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 373 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 379 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 385 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 391 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 397 */ { SystemZ_GRX32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRX32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GRX32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 403 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 405 */ { SystemZ_GRX32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRX32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRX32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 410 */ { SystemZ_GRX32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 415 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 420 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 425 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 430 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 435 */ { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 440 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 445 */ { SystemZ_VR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 450 */ { SystemZ_VR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 455 */ { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 458 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 460 */ { SystemZ_VR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 464 */ { SystemZ_VR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 468 */ { SystemZ_VR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 470 */ { SystemZ_VR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 472 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 475 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 480 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 485 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 488 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 491 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 495 */ { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 500 */ { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 503 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 506 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 511 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 514 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 517 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 520 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 523 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 526 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 529 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 532 */ { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 538 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 541 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 544 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 548 */ { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 551 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 553 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 555 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 560 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 564 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 567 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 569 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 572 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 576 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 579 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 582 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 584 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 587 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 590 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 593 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 597 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 601 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 606 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 611 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 615 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 619 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 621 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 623 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 627 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 629 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 633 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 638 */ { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 643 */ { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 647 */ { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 649 */ { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 651 */ { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 655 */ { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 657 */ { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 661 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 663 */ { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 665 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 668 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 672 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 675 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 679 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 681 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 684 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 688 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 691 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 695 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 698 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 702 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 704 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 706 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 711 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 715 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 719 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 722 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 727 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 731 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 735 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 738 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 741 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 745 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 749 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 751 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 753 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 755 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 760 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 764 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 766 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 770 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 773 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(1) },
    /* 777 */ { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 782 */ { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(1) },
    /* 786 */ { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(1) }, { SystemZ_ADDR32BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 792 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 796 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 799 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 803 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 805 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 810 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 814 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 818 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 821 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(1) },
    /* 825 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 829 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 832 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 835 */ { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 838 */ { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 841 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 846 */ { SystemZ_AR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_AR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 848 */ { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 852 */ { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 855 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 858 */ { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 861 */ { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 866 */ { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 869 */ { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(1) }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 874 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 876 */ { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 878 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 880 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 884 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 886 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 890 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 892 */ { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 897 */ { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(1) }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 902 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 907 */ { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 912 */ { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 915 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_AR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 917 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR32BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 921 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 923 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 924 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 926 */ { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 928 */ { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 932 */ { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 934 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 937 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 941 */ { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 944 */ { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 948 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 951 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 955 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 960 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 965 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 969 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 973 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 976 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_AnyRegBitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 979 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_AnyRegBitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_AnyRegBitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 983 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_AnyRegBitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_PCREL, 0 },
    /* 986 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_AnyRegBitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 992 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_AnyRegBitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_AnyRegBitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 995 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_AnyRegBitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_AnyRegBitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_AnyRegBitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1000 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_AnyRegBitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_AnyRegBitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1006 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_AnyRegBitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_AnyRegBitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1011 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_AnyRegBitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1016 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_AnyRegBitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_AnyRegBitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1022 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1025 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1029 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_AnyRegBitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1036 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1041 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_AnyRegBitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1047 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1053 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1060 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_AnyRegBitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1066 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1072 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1078 */ { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1083 */ { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1086 */ { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(1) }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(2) },
    /* 1092 */ { SystemZ_AR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_AR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1096 */ { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1100 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1105 */ { SystemZ_CR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_CR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1109 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1111 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1114 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1116 */ { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1118 */ { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1122 */ { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1124 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1130 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1134 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1140 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1145 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1149 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1155 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1160 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1164 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1169 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1173 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1176 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1182 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1187 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1191 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1196 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1200 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1205 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1209 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1214 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1218 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1223 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1227 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1232 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1236 */ { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1241 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1246 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1248 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1251 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1253 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1259 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1263 */ { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1269 */ { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1273 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1279 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1283 */ { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1286 */ { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1287 */ { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1293 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1298 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1301 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1306 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1309 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1312 */ { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1317 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1323 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) },
    /* 1325 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1330 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1336 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1342 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1348 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR32BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1352 */ { SystemZ_AR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1354 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1359 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1363 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1367 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_ADDR32BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1371 */ { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_ADDR32BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1375 */ { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_FP128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1380 */ { SystemZ_ADDR32BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1382 */ { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR32BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1388 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1391 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1396 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1401 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1405 */ { SystemZ_GRH32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1408 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1413 */ { SystemZ_FP32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { SystemZ_FP64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1416 */ { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1419 */ { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(1) },
    /* 1423 */ { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(1) }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1428 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(1) }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1432 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(1) },
    /* 1435 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1439 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1442 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1447 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1451 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1456 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1460 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1463 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1466 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1469 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1473 */ { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1477 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1481 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1485 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1491 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1496 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR32BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1501 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR32BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1505 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1511 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1517 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1519 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1525 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1529 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1532 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1536 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1541 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1547 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1551 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR32BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1556 */ { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR32BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1560 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1564 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1568 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1573 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1577 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR32BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1583 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR32BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1588 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, CONSTRAINT_MCOI_TIED_TO(0) }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR32BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 },
    /* 1593 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_GR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1596 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1597 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_ADDR64BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_MEMORY, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_MEMORY, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1602 */ { SystemZ_VR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1606 */ { SystemZ_VR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1610 */ { SystemZ_VR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1613 */ { SystemZ_VR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1616 */ { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1618 */ { SystemZ_VR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1620 */ { SystemZ_VR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1624 */ { SystemZ_VR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR128BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1628 */ { SystemZ_VR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1632 */ { SystemZ_VR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 },
    /* 1636 */ { SystemZ_VR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1640 */ { SystemZ_VR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1644 */ { SystemZ_VR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR64BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
    /* 1647 */ { SystemZ_VR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { SystemZ_VR32BitRegClassID, 0, MCOI_OPERAND_REGISTER, 0 }, { -1, 0, MCOI_OPERAND_IMMEDIATE, 0 },
  }, {
    /* 0 */
    /* 0 */ SystemZ_CC,
    /* 1 */ SystemZ_FPC, SystemZ_CC,
    /* 3 */ SystemZ_FPC, SystemZ_R14D, SystemZ_CC,
    /* 6 */ SystemZ_FPC, SystemZ_R3D, SystemZ_CC,
    /* 9 */ SystemZ_FPC, SystemZ_R7D, SystemZ_CC,
    /* 12 */ SystemZ_FPC,
    /* 13 */ SystemZ_R15D, SystemZ_R15D, SystemZ_CC,
    /* 16 */ SystemZ_R15D, SystemZ_R1D, SystemZ_R15D, SystemZ_CC,
    /* 20 */ SystemZ_R14D, SystemZ_CC,
    /* 22 */ SystemZ_R3D, SystemZ_R4D, SystemZ_R3D, SystemZ_CC,
    /* 26 */ SystemZ_CC, SystemZ_CC,
    /* 28 */ SystemZ_R1D, SystemZ_R2D, SystemZ_R3D, SystemZ_CC, SystemZ_R1D, SystemZ_R2D, SystemZ_R3D,
    /* 35 */ SystemZ_R0L, SystemZ_CC,
    /* 37 */ SystemZ_R0L, SystemZ_R1D, SystemZ_CC, SystemZ_R1D,
    /* 41 */ SystemZ_R1L, SystemZ_CC,
    /* 43 */ SystemZ_R0L, SystemZ_R1D, SystemZ_CC,
    /* 46 */ SystemZ_R0L, SystemZ_R1L, SystemZ_CC,
    /* 49 */ SystemZ_R0D, SystemZ_R1D,
    /* 51 */ SystemZ_R2L, SystemZ_R2L,
    /* 53 */ SystemZ_R0L, SystemZ_R1L,
    /* 55 */ SystemZ_R0L,
    /* 56 */ SystemZ_R0D, SystemZ_R1D, SystemZ_R0D, SystemZ_CC,
    /* 60 */ SystemZ_R0L, SystemZ_R1D,
    /* 62 */ SystemZ_FPC, SystemZ_R0L, SystemZ_F4Q, SystemZ_CC, SystemZ_R1L, SystemZ_F0Q,
    /* 68 */ SystemZ_R0D, SystemZ_R0D, SystemZ_CC,
    /* 71 */ SystemZ_R1L,
    /* 72 */ SystemZ_R1L, SystemZ_R2D,
    /* 74 */ SystemZ_R0D, SystemZ_R1D, SystemZ_R2D, SystemZ_R3D, SystemZ_CC,
    /* 79 */ SystemZ_FPC, SystemZ_FPC,
    /* 81 */ SystemZ_R0L, SystemZ_R1L, SystemZ_R0L, SystemZ_CC,
    /* 85 */ SystemZ_CC, SystemZ_R0L, SystemZ_R1D,
    /* 88 */ SystemZ_R1D, SystemZ_CC,
    /* 90 */ SystemZ_R0D, SystemZ_R1D, SystemZ_R2D, SystemZ_R3D, SystemZ_R4D, SystemZ_R5D, SystemZ_CC, SystemZ_R0D, SystemZ_R1D, SystemZ_R2D, SystemZ_R3D, SystemZ_R5D,
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
enum DispSize {
	DispSize_12,
	DispSize_20
};

enum MemType {
	MemType_target
};

enum NumOpsValue {
	NumOpsValue_2
};

enum OpType {
	OpType_mem
};

// getDisp12Opcode
int getDisp12Opcode(uint16_t Opcode) {
static const uint16_t getDisp12OpcodeTable[][2] = {
  { SystemZ_AHY, SystemZ_AH },
  { SystemZ_ALY, SystemZ_AL },
  { SystemZ_AY, SystemZ_A },
  { SystemZ_CDSY, SystemZ_CDS },
  { SystemZ_CHY, SystemZ_CH },
  { SystemZ_CLIY, SystemZ_CLI },
  { SystemZ_CLMY, SystemZ_CLM },
  { SystemZ_CLY, SystemZ_CL },
  { SystemZ_CSY, SystemZ_CS },
  { SystemZ_CVBY, SystemZ_CVB },
  { SystemZ_CVDY, SystemZ_CVD },
  { SystemZ_CY, SystemZ_C },
  { SystemZ_IC32Y, SystemZ_IC32 },
  { SystemZ_ICMY, SystemZ_ICM },
  { SystemZ_ICY, SystemZ_IC },
  { SystemZ_LAEY, SystemZ_LAE },
  { SystemZ_LAMY, SystemZ_LAM },
  { SystemZ_LAY, SystemZ_LA },
  { SystemZ_LDY, SystemZ_LD },
  { SystemZ_LEY, SystemZ_LE },
  { SystemZ_LHY, SystemZ_LH },
  { SystemZ_LMY, SystemZ_LM },
  { SystemZ_LRAY, SystemZ_LRA },
  { SystemZ_LY, SystemZ_L },
  { SystemZ_MHY, SystemZ_MH },
  { SystemZ_MSY, SystemZ_MS },
  { SystemZ_MVIY, SystemZ_MVI },
  { SystemZ_NIY, SystemZ_NI },
  { SystemZ_NY, SystemZ_N },
  { SystemZ_OIY, SystemZ_OI },
  { SystemZ_OY, SystemZ_O },
  { SystemZ_SHY, SystemZ_SH },
  { SystemZ_SLY, SystemZ_SL },
  { SystemZ_STAMY, SystemZ_STAM },
  { SystemZ_STCMY, SystemZ_STCM },
  { SystemZ_STCY, SystemZ_STC },
  { SystemZ_STDY, SystemZ_STD },
  { SystemZ_STEY, SystemZ_STE },
  { SystemZ_STHY, SystemZ_STH },
  { SystemZ_STMY, SystemZ_STM },
  { SystemZ_STY, SystemZ_ST },
  { SystemZ_SY, SystemZ_S },
  { SystemZ_TMY, SystemZ_TM },
  { SystemZ_XIY, SystemZ_XI },
  { SystemZ_XY, SystemZ_X },
}; // End of getDisp12OpcodeTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 45;
  while (start < end) {
    mid = start + (end - start) / 2;
    if (Opcode == getDisp12OpcodeTable[mid][0]) {
      break;
    }
    if (Opcode < getDisp12OpcodeTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return getDisp12OpcodeTable[mid][1];
}

// getDisp20Opcode
int getDisp20Opcode(uint16_t Opcode) {
static const uint16_t getDisp20OpcodeTable[][2] = {
  { SystemZ_A, SystemZ_AY },
  { SystemZ_AH, SystemZ_AHY },
  { SystemZ_AL, SystemZ_ALY },
  { SystemZ_C, SystemZ_CY },
  { SystemZ_CDS, SystemZ_CDSY },
  { SystemZ_CH, SystemZ_CHY },
  { SystemZ_CL, SystemZ_CLY },
  { SystemZ_CLI, SystemZ_CLIY },
  { SystemZ_CLM, SystemZ_CLMY },
  { SystemZ_CS, SystemZ_CSY },
  { SystemZ_CVB, SystemZ_CVBY },
  { SystemZ_CVD, SystemZ_CVDY },
  { SystemZ_IC, SystemZ_ICY },
  { SystemZ_IC32, SystemZ_IC32Y },
  { SystemZ_ICM, SystemZ_ICMY },
  { SystemZ_L, SystemZ_LY },
  { SystemZ_LA, SystemZ_LAY },
  { SystemZ_LAE, SystemZ_LAEY },
  { SystemZ_LAM, SystemZ_LAMY },
  { SystemZ_LD, SystemZ_LDY },
  { SystemZ_LE, SystemZ_LEY },
  { SystemZ_LH, SystemZ_LHY },
  { SystemZ_LM, SystemZ_LMY },
  { SystemZ_LRA, SystemZ_LRAY },
  { SystemZ_MH, SystemZ_MHY },
  { SystemZ_MS, SystemZ_MSY },
  { SystemZ_MVI, SystemZ_MVIY },
  { SystemZ_N, SystemZ_NY },
  { SystemZ_NI, SystemZ_NIY },
  { SystemZ_O, SystemZ_OY },
  { SystemZ_OI, SystemZ_OIY },
  { SystemZ_S, SystemZ_SY },
  { SystemZ_SH, SystemZ_SHY },
  { SystemZ_SL, SystemZ_SLY },
  { SystemZ_ST, SystemZ_STY },
  { SystemZ_STAM, SystemZ_STAMY },
  { SystemZ_STC, SystemZ_STCY },
  { SystemZ_STCM, SystemZ_STCMY },
  { SystemZ_STD, SystemZ_STDY },
  { SystemZ_STE, SystemZ_STEY },
  { SystemZ_STH, SystemZ_STHY },
  { SystemZ_STM, SystemZ_STMY },
  { SystemZ_TM, SystemZ_TMY },
  { SystemZ_X, SystemZ_XY },
  { SystemZ_XI, SystemZ_XIY },
}; // End of getDisp20OpcodeTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 45;
  while (start < end) {
    mid = start + (end - start) / 2;
    if (Opcode == getDisp20OpcodeTable[mid][0]) {
      break;
    }
    if (Opcode < getDisp20OpcodeTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return getDisp20OpcodeTable[mid][1];
}

// getMemOpcode
int getMemOpcode(uint16_t Opcode) {
static const uint16_t getMemOpcodeTable[][2] = {
  { SystemZ_LLCRMux, SystemZ_LLCMux },
  { SystemZ_LLHRMux, SystemZ_LLHMux },
  { SystemZ_LOCRMux, SystemZ_LOCMux },
  { SystemZ_SELRMux, SystemZ_LOCMux_MemFoldPseudo },
  { SystemZ_ADBR, SystemZ_ADB },
  { SystemZ_ADR, SystemZ_AD },
  { SystemZ_AEBR, SystemZ_AEB },
  { SystemZ_AER, SystemZ_AE },
  { SystemZ_AGFR, SystemZ_AGF },
  { SystemZ_AGR, SystemZ_AG },
  { SystemZ_AGRK, SystemZ_AG_MemFoldPseudo },
  { SystemZ_ALCGR, SystemZ_ALCG },
  { SystemZ_ALCR, SystemZ_ALC },
  { SystemZ_ALGFR, SystemZ_ALGF },
  { SystemZ_ALGR, SystemZ_ALG },
  { SystemZ_ALGRK, SystemZ_ALG_MemFoldPseudo },
  { SystemZ_ALR, SystemZ_AL },
  { SystemZ_ALRK, SystemZ_AL_MemFoldPseudo },
  { SystemZ_AR, SystemZ_A },
  { SystemZ_ARK, SystemZ_A_MemFoldPseudo },
  { SystemZ_AUR, SystemZ_AU },
  { SystemZ_AWR, SystemZ_AW },
  { SystemZ_CDBR, SystemZ_CDB },
  { SystemZ_CDR, SystemZ_CD },
  { SystemZ_CEBR, SystemZ_CEB },
  { SystemZ_CER, SystemZ_CE },
  { SystemZ_CGFR, SystemZ_CGF },
  { SystemZ_CGR, SystemZ_CG },
  { SystemZ_CLGFR, SystemZ_CLGF },
  { SystemZ_CLGR, SystemZ_CLG },
  { SystemZ_CLR, SystemZ_CL },
  { SystemZ_CR, SystemZ_C },
  { SystemZ_DDBR, SystemZ_DDB },
  { SystemZ_DDR, SystemZ_DD },
  { SystemZ_DEBR, SystemZ_DEB },
  { SystemZ_DER, SystemZ_DE },
  { SystemZ_DLGR, SystemZ_DLG },
  { SystemZ_DLR, SystemZ_DL },
  { SystemZ_DR, SystemZ_D },
  { SystemZ_DSGFR, SystemZ_DSGF },
  { SystemZ_DSGR, SystemZ_DSG },
  { SystemZ_KDBR, SystemZ_KDB },
  { SystemZ_KEBR, SystemZ_KEB },
  { SystemZ_LBR, SystemZ_LB },
  { SystemZ_LDEBR, SystemZ_LDEB },
  { SystemZ_LDER, SystemZ_LDE },
  { SystemZ_LDR, SystemZ_LD },
  { SystemZ_LER, SystemZ_LE },
  { SystemZ_LGBR, SystemZ_LGB },
  { SystemZ_LGFR, SystemZ_LGF },
  { SystemZ_LGHR, SystemZ_LGH },
  { SystemZ_LGR, SystemZ_LG },
  { SystemZ_LHR, SystemZ_LH },
  { SystemZ_LLCR, SystemZ_LLC },
  { SystemZ_LLGCR, SystemZ_LLGC },
  { SystemZ_LLGFR, SystemZ_LLGF },
  { SystemZ_LLGHR, SystemZ_LLGH },
  { SystemZ_LLGTR, SystemZ_LLGT },
  { SystemZ_LLHR, SystemZ_LLH },
  { SystemZ_LOCFHR, SystemZ_LOCFH },
  { SystemZ_LOCGR, SystemZ_LOCG },
  { SystemZ_LOCR, SystemZ_LOC },
  { SystemZ_LR, SystemZ_L },
  { SystemZ_LRVGR, SystemZ_LRVG },
  { SystemZ_LRVR, SystemZ_LRV },
  { SystemZ_LTGFR, SystemZ_LTGF },
  { SystemZ_LTGR, SystemZ_LTG },
  { SystemZ_LTR, SystemZ_LT },
  { SystemZ_LXDBR, SystemZ_LXDB },
  { SystemZ_LXDR, SystemZ_LXD },
  { SystemZ_LXEBR, SystemZ_LXEB },
  { SystemZ_LXER, SystemZ_LXE },
  { SystemZ_MADBR, SystemZ_MADB },
  { SystemZ_MADR, SystemZ_MAD },
  { SystemZ_MAEBR, SystemZ_MAEB },
  { SystemZ_MAER, SystemZ_MAE },
  { SystemZ_MAYHR, SystemZ_MAYH },
  { SystemZ_MAYLR, SystemZ_MAYL },
  { SystemZ_MAYR, SystemZ_MAY },
  { SystemZ_MDBR, SystemZ_MDB },
  { SystemZ_MDEBR, SystemZ_MDEB },
  { SystemZ_MDER, SystemZ_MDE },
  { SystemZ_MDR, SystemZ_MD },
  { SystemZ_MEEBR, SystemZ_MEEB },
  { SystemZ_MEER, SystemZ_MEE },
  { SystemZ_MER, SystemZ_ME },
  { SystemZ_MLGR, SystemZ_MLG },
  { SystemZ_MLR, SystemZ_ML },
  { SystemZ_MR, SystemZ_M },
  { SystemZ_MSDBR, SystemZ_MSDB },
  { SystemZ_MSDR, SystemZ_MSD },
  { SystemZ_MSEBR, SystemZ_MSEB },
  { SystemZ_MSER, SystemZ_MSE },
  { SystemZ_MSGFR, SystemZ_MSGF },
  { SystemZ_MSGR, SystemZ_MSG },
  { SystemZ_MSGRKC, SystemZ_MSGC_MemFoldPseudo },
  { SystemZ_MSR, SystemZ_MS },
  { SystemZ_MSRKC, SystemZ_MSC_MemFoldPseudo },
  { SystemZ_MXDBR, SystemZ_MXDB },
  { SystemZ_MXDR, SystemZ_MXD },
  { SystemZ_MYHR, SystemZ_MYH },
  { SystemZ_MYLR, SystemZ_MYL },
  { SystemZ_MYR, SystemZ_MY },
  { SystemZ_NGR, SystemZ_NG },
  { SystemZ_NGRK, SystemZ_NG_MemFoldPseudo },
  { SystemZ_NR, SystemZ_N },
  { SystemZ_NRK, SystemZ_N_MemFoldPseudo },
  { SystemZ_OGR, SystemZ_OG },
  { SystemZ_OGRK, SystemZ_OG_MemFoldPseudo },
  { SystemZ_OR, SystemZ_O },
  { SystemZ_ORK, SystemZ_O_MemFoldPseudo },
  { SystemZ_SDBR, SystemZ_SDB },
  { SystemZ_SDR, SystemZ_SD },
  { SystemZ_SEBR, SystemZ_SEB },
  { SystemZ_SELGR, SystemZ_LOCG_MemFoldPseudo },
  { SystemZ_SER, SystemZ_SE },
  { SystemZ_SGFR, SystemZ_SGF },
  { SystemZ_SGR, SystemZ_SG },
  { SystemZ_SGRK, SystemZ_SG_MemFoldPseudo },
  { SystemZ_SLBGR, SystemZ_SLBG },
  { SystemZ_SLBR, SystemZ_SLB },
  { SystemZ_SLGFR, SystemZ_SLGF },
  { SystemZ_SLGR, SystemZ_SLG },
  { SystemZ_SLGRK, SystemZ_SLG_MemFoldPseudo },
  { SystemZ_SLR, SystemZ_SL },
  { SystemZ_SLRK, SystemZ_SL_MemFoldPseudo },
  { SystemZ_SQDBR, SystemZ_SQDB },
  { SystemZ_SQDR, SystemZ_SQD },
  { SystemZ_SQEBR, SystemZ_SQEB },
  { SystemZ_SQER, SystemZ_SQE },
  { SystemZ_SR, SystemZ_S },
  { SystemZ_SRK, SystemZ_S_MemFoldPseudo },
  { SystemZ_SUR, SystemZ_SU },
  { SystemZ_SWR, SystemZ_SW },
  { SystemZ_WFADB, SystemZ_ADB_MemFoldPseudo },
  { SystemZ_WFASB, SystemZ_AEB_MemFoldPseudo },
  { SystemZ_WFCDB, SystemZ_CDB },
  { SystemZ_WFCSB, SystemZ_CEB },
  { SystemZ_WFDDB, SystemZ_DDB_MemFoldPseudo },
  { SystemZ_WFDSB, SystemZ_DEB_MemFoldPseudo },
  { SystemZ_WFKDB, SystemZ_KDB },
  { SystemZ_WFKSB, SystemZ_KEB },
  { SystemZ_WFMADB, SystemZ_MADB_MemFoldPseudo },
  { SystemZ_WFMASB, SystemZ_MAEB_MemFoldPseudo },
  { SystemZ_WFMDB, SystemZ_MDB_MemFoldPseudo },
  { SystemZ_WFMSB, SystemZ_MEEB_MemFoldPseudo },
  { SystemZ_WFMSDB, SystemZ_MSDB_MemFoldPseudo },
  { SystemZ_WFMSSB, SystemZ_MSEB_MemFoldPseudo },
  { SystemZ_WFSDB, SystemZ_SDB_MemFoldPseudo },
  { SystemZ_WFSQDB, SystemZ_SQDB },
  { SystemZ_WFSQSB, SystemZ_SQEB },
  { SystemZ_WFSSB, SystemZ_SEB_MemFoldPseudo },
  { SystemZ_WLDEB, SystemZ_LDEB },
  { SystemZ_XGR, SystemZ_XG },
  { SystemZ_XGRK, SystemZ_XG_MemFoldPseudo },
  { SystemZ_XR, SystemZ_X },
  { SystemZ_XRK, SystemZ_X_MemFoldPseudo },
}; // End of getMemOpcodeTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 157;
  while (start < end) {
    mid = start + (end - start) / 2;
    if (Opcode == getMemOpcodeTable[mid][0]) {
      break;
    }
    if (Opcode < getMemOpcodeTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return getMemOpcodeTable[mid][1];
}

// getTargetMemOpcode
int getTargetMemOpcode(uint16_t Opcode) {
static const uint16_t getTargetMemOpcodeTable[][2] = {
  { SystemZ_ADB_MemFoldPseudo, SystemZ_ADB },
  { SystemZ_AEB_MemFoldPseudo, SystemZ_AEB },
  { SystemZ_AG_MemFoldPseudo, SystemZ_AG },
  { SystemZ_ALG_MemFoldPseudo, SystemZ_ALG },
  { SystemZ_AL_MemFoldPseudo, SystemZ_AL },
  { SystemZ_A_MemFoldPseudo, SystemZ_A },
  { SystemZ_DDB_MemFoldPseudo, SystemZ_DDB },
  { SystemZ_DEB_MemFoldPseudo, SystemZ_DEB },
  { SystemZ_LOCG_MemFoldPseudo, SystemZ_LOCG },
  { SystemZ_LOCMux_MemFoldPseudo, SystemZ_LOCMux },
  { SystemZ_MADB_MemFoldPseudo, SystemZ_MADB },
  { SystemZ_MAEB_MemFoldPseudo, SystemZ_MAEB },
  { SystemZ_MDB_MemFoldPseudo, SystemZ_MDB },
  { SystemZ_MEEB_MemFoldPseudo, SystemZ_MEEB },
  { SystemZ_MSC_MemFoldPseudo, SystemZ_MSC },
  { SystemZ_MSDB_MemFoldPseudo, SystemZ_MSDB },
  { SystemZ_MSEB_MemFoldPseudo, SystemZ_MSEB },
  { SystemZ_MSGC_MemFoldPseudo, SystemZ_MSGC },
  { SystemZ_NG_MemFoldPseudo, SystemZ_NG },
  { SystemZ_N_MemFoldPseudo, SystemZ_N },
  { SystemZ_OG_MemFoldPseudo, SystemZ_OG },
  { SystemZ_O_MemFoldPseudo, SystemZ_O },
  { SystemZ_SDB_MemFoldPseudo, SystemZ_SDB },
  { SystemZ_SEB_MemFoldPseudo, SystemZ_SEB },
  { SystemZ_SG_MemFoldPseudo, SystemZ_SG },
  { SystemZ_SLG_MemFoldPseudo, SystemZ_SLG },
  { SystemZ_SL_MemFoldPseudo, SystemZ_SL },
  { SystemZ_S_MemFoldPseudo, SystemZ_S },
  { SystemZ_XG_MemFoldPseudo, SystemZ_XG },
  { SystemZ_X_MemFoldPseudo, SystemZ_X },
}; // End of getTargetMemOpcodeTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 30;
  while (start < end) {
    mid = start + (end - start) / 2;
    if (Opcode == getTargetMemOpcodeTable[mid][0]) {
      break;
    }
    if (Opcode < getTargetMemOpcodeTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return getTargetMemOpcodeTable[mid][1];
}

// getTwoOperandOpcode
int getTwoOperandOpcode(uint16_t Opcode) {
static const uint16_t getTwoOperandOpcodeTable[][2] = {
  { SystemZ_AHIMuxK, SystemZ_AHIMux },
  { SystemZ_SELRMux, SystemZ_LOCRMux },
  { SystemZ_AGHIK, SystemZ_AGHI },
  { SystemZ_AGRK, SystemZ_AGR },
  { SystemZ_AHIK, SystemZ_AHI },
  { SystemZ_ALGRK, SystemZ_ALGR },
  { SystemZ_ALRK, SystemZ_ALR },
  { SystemZ_ARK, SystemZ_AR },
  { SystemZ_NGRK, SystemZ_NGR },
  { SystemZ_NRK, SystemZ_NR },
  { SystemZ_OGRK, SystemZ_OGR },
  { SystemZ_ORK, SystemZ_OR },
  { SystemZ_SELFHR, SystemZ_LOCFHR },
  { SystemZ_SELGR, SystemZ_LOCGR },
  { SystemZ_SELR, SystemZ_LOCR },
  { SystemZ_SGRK, SystemZ_SGR },
  { SystemZ_SLAK, SystemZ_SLA },
  { SystemZ_SLGRK, SystemZ_SLGR },
  { SystemZ_SLLK, SystemZ_SLL },
  { SystemZ_SLRK, SystemZ_SLR },
  { SystemZ_SRAK, SystemZ_SRA },
  { SystemZ_SRK, SystemZ_SR },
  { SystemZ_SRLK, SystemZ_SRL },
  { SystemZ_XGRK, SystemZ_XGR },
  { SystemZ_XRK, SystemZ_XR },
}; // End of getTwoOperandOpcodeTable

  unsigned mid;
  unsigned start = 0;
  unsigned end = 25;
  while (start < end) {
    mid = start + (end - start) / 2;
    if (Opcode == getTwoOperandOpcodeTable[mid][0]) {
      break;
    }
    if (Opcode < getTwoOperandOpcodeTable[mid][0])
      end = mid;
    else
      start = mid + 1;
  }
  if (start == end)
    return -1; // Instruction doesn't exist in this table.

  return getTwoOperandOpcodeTable[mid][1];
}

#endif // GET_INSTRMAP_INFO


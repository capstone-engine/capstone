#ifdef GET_REGINFO_ENUM
#undef GET_REGINFO_ENUM

enum {
  Mips_NoRegister,
  Mips_AT = 1,
  Mips_AT_NM = 2,
  Mips_DSPCCond = 3,
  Mips_DSPCarry = 4,
  Mips_DSPEFI = 5,
  Mips_DSPOutFlag = 6,
  Mips_DSPPos = 7,
  Mips_DSPSCount = 8,
  Mips_FP = 9,
  Mips_FP_NM = 10,
  Mips_GP = 11,
  Mips_GP_NM = 12,
  Mips_MSAAccess = 13,
  Mips_MSACSR = 14,
  Mips_MSAIR = 15,
  Mips_MSAMap = 16,
  Mips_MSAModify = 17,
  Mips_MSARequest = 18,
  Mips_MSASave = 19,
  Mips_MSAUnmap = 20,
  Mips_PC = 21,
  Mips_RA = 22,
  Mips_RA_NM = 23,
  Mips_SP = 24,
  Mips_SP_NM = 25,
  Mips_ZERO = 26,
  Mips_ZERO_NM = 27,
  Mips_A0 = 28,
  Mips_A1 = 29,
  Mips_A2 = 30,
  Mips_A3 = 31,
  Mips_AC0 = 32,
  Mips_AC1 = 33,
  Mips_AC2 = 34,
  Mips_AC3 = 35,
  Mips_AT_64 = 36,
  Mips_COP00 = 37,
  Mips_COP01 = 38,
  Mips_COP02 = 39,
  Mips_COP03 = 40,
  Mips_COP04 = 41,
  Mips_COP05 = 42,
  Mips_COP06 = 43,
  Mips_COP07 = 44,
  Mips_COP08 = 45,
  Mips_COP09 = 46,
  Mips_COP20 = 47,
  Mips_COP21 = 48,
  Mips_COP22 = 49,
  Mips_COP23 = 50,
  Mips_COP24 = 51,
  Mips_COP25 = 52,
  Mips_COP26 = 53,
  Mips_COP27 = 54,
  Mips_COP28 = 55,
  Mips_COP29 = 56,
  Mips_COP30 = 57,
  Mips_COP31 = 58,
  Mips_COP32 = 59,
  Mips_COP33 = 60,
  Mips_COP34 = 61,
  Mips_COP35 = 62,
  Mips_COP36 = 63,
  Mips_COP37 = 64,
  Mips_COP38 = 65,
  Mips_COP39 = 66,
  Mips_COP010 = 67,
  Mips_COP011 = 68,
  Mips_COP012 = 69,
  Mips_COP013 = 70,
  Mips_COP014 = 71,
  Mips_COP015 = 72,
  Mips_COP016 = 73,
  Mips_COP017 = 74,
  Mips_COP018 = 75,
  Mips_COP019 = 76,
  Mips_COP020 = 77,
  Mips_COP021 = 78,
  Mips_COP022 = 79,
  Mips_COP023 = 80,
  Mips_COP024 = 81,
  Mips_COP025 = 82,
  Mips_COP026 = 83,
  Mips_COP027 = 84,
  Mips_COP028 = 85,
  Mips_COP029 = 86,
  Mips_COP030 = 87,
  Mips_COP031 = 88,
  Mips_COP210 = 89,
  Mips_COP211 = 90,
  Mips_COP212 = 91,
  Mips_COP213 = 92,
  Mips_COP214 = 93,
  Mips_COP215 = 94,
  Mips_COP216 = 95,
  Mips_COP217 = 96,
  Mips_COP218 = 97,
  Mips_COP219 = 98,
  Mips_COP220 = 99,
  Mips_COP221 = 100,
  Mips_COP222 = 101,
  Mips_COP223 = 102,
  Mips_COP224 = 103,
  Mips_COP225 = 104,
  Mips_COP226 = 105,
  Mips_COP227 = 106,
  Mips_COP228 = 107,
  Mips_COP229 = 108,
  Mips_COP230 = 109,
  Mips_COP231 = 110,
  Mips_COP310 = 111,
  Mips_COP311 = 112,
  Mips_COP312 = 113,
  Mips_COP313 = 114,
  Mips_COP314 = 115,
  Mips_COP315 = 116,
  Mips_COP316 = 117,
  Mips_COP317 = 118,
  Mips_COP318 = 119,
  Mips_COP319 = 120,
  Mips_COP320 = 121,
  Mips_COP321 = 122,
  Mips_COP322 = 123,
  Mips_COP323 = 124,
  Mips_COP324 = 125,
  Mips_COP325 = 126,
  Mips_COP326 = 127,
  Mips_COP327 = 128,
  Mips_COP328 = 129,
  Mips_COP329 = 130,
  Mips_COP330 = 131,
  Mips_COP331 = 132,
  Mips_D0 = 133,
  Mips_D1 = 134,
  Mips_D2 = 135,
  Mips_D3 = 136,
  Mips_D4 = 137,
  Mips_D5 = 138,
  Mips_D6 = 139,
  Mips_D7 = 140,
  Mips_D8 = 141,
  Mips_D9 = 142,
  Mips_D10 = 143,
  Mips_D11 = 144,
  Mips_D12 = 145,
  Mips_D13 = 146,
  Mips_D14 = 147,
  Mips_D15 = 148,
  Mips_DSPOutFlag20 = 149,
  Mips_DSPOutFlag21 = 150,
  Mips_DSPOutFlag22 = 151,
  Mips_DSPOutFlag23 = 152,
  Mips_F0 = 153,
  Mips_F1 = 154,
  Mips_F2 = 155,
  Mips_F3 = 156,
  Mips_F4 = 157,
  Mips_F5 = 158,
  Mips_F6 = 159,
  Mips_F7 = 160,
  Mips_F8 = 161,
  Mips_F9 = 162,
  Mips_F10 = 163,
  Mips_F11 = 164,
  Mips_F12 = 165,
  Mips_F13 = 166,
  Mips_F14 = 167,
  Mips_F15 = 168,
  Mips_F16 = 169,
  Mips_F17 = 170,
  Mips_F18 = 171,
  Mips_F19 = 172,
  Mips_F20 = 173,
  Mips_F21 = 174,
  Mips_F22 = 175,
  Mips_F23 = 176,
  Mips_F24 = 177,
  Mips_F25 = 178,
  Mips_F26 = 179,
  Mips_F27 = 180,
  Mips_F28 = 181,
  Mips_F29 = 182,
  Mips_F30 = 183,
  Mips_F31 = 184,
  Mips_FCC0 = 185,
  Mips_FCC1 = 186,
  Mips_FCC2 = 187,
  Mips_FCC3 = 188,
  Mips_FCC4 = 189,
  Mips_FCC5 = 190,
  Mips_FCC6 = 191,
  Mips_FCC7 = 192,
  Mips_FCR0 = 193,
  Mips_FCR1 = 194,
  Mips_FCR2 = 195,
  Mips_FCR3 = 196,
  Mips_FCR4 = 197,
  Mips_FCR5 = 198,
  Mips_FCR6 = 199,
  Mips_FCR7 = 200,
  Mips_FCR8 = 201,
  Mips_FCR9 = 202,
  Mips_FCR10 = 203,
  Mips_FCR11 = 204,
  Mips_FCR12 = 205,
  Mips_FCR13 = 206,
  Mips_FCR14 = 207,
  Mips_FCR15 = 208,
  Mips_FCR16 = 209,
  Mips_FCR17 = 210,
  Mips_FCR18 = 211,
  Mips_FCR19 = 212,
  Mips_FCR20 = 213,
  Mips_FCR21 = 214,
  Mips_FCR22 = 215,
  Mips_FCR23 = 216,
  Mips_FCR24 = 217,
  Mips_FCR25 = 218,
  Mips_FCR26 = 219,
  Mips_FCR27 = 220,
  Mips_FCR28 = 221,
  Mips_FCR29 = 222,
  Mips_FCR30 = 223,
  Mips_FCR31 = 224,
  Mips_FP_64 = 225,
  Mips_F_HI0 = 226,
  Mips_F_HI1 = 227,
  Mips_F_HI2 = 228,
  Mips_F_HI3 = 229,
  Mips_F_HI4 = 230,
  Mips_F_HI5 = 231,
  Mips_F_HI6 = 232,
  Mips_F_HI7 = 233,
  Mips_F_HI8 = 234,
  Mips_F_HI9 = 235,
  Mips_F_HI10 = 236,
  Mips_F_HI11 = 237,
  Mips_F_HI12 = 238,
  Mips_F_HI13 = 239,
  Mips_F_HI14 = 240,
  Mips_F_HI15 = 241,
  Mips_F_HI16 = 242,
  Mips_F_HI17 = 243,
  Mips_F_HI18 = 244,
  Mips_F_HI19 = 245,
  Mips_F_HI20 = 246,
  Mips_F_HI21 = 247,
  Mips_F_HI22 = 248,
  Mips_F_HI23 = 249,
  Mips_F_HI24 = 250,
  Mips_F_HI25 = 251,
  Mips_F_HI26 = 252,
  Mips_F_HI27 = 253,
  Mips_F_HI28 = 254,
  Mips_F_HI29 = 255,
  Mips_F_HI30 = 256,
  Mips_F_HI31 = 257,
  Mips_GP_64 = 258,
  Mips_HI0 = 259,
  Mips_HI1 = 260,
  Mips_HI2 = 261,
  Mips_HI3 = 262,
  Mips_HWR0 = 263,
  Mips_HWR1 = 264,
  Mips_HWR2 = 265,
  Mips_HWR3 = 266,
  Mips_HWR4 = 267,
  Mips_HWR5 = 268,
  Mips_HWR6 = 269,
  Mips_HWR7 = 270,
  Mips_HWR8 = 271,
  Mips_HWR9 = 272,
  Mips_HWR10 = 273,
  Mips_HWR11 = 274,
  Mips_HWR12 = 275,
  Mips_HWR13 = 276,
  Mips_HWR14 = 277,
  Mips_HWR15 = 278,
  Mips_HWR16 = 279,
  Mips_HWR17 = 280,
  Mips_HWR18 = 281,
  Mips_HWR19 = 282,
  Mips_HWR20 = 283,
  Mips_HWR21 = 284,
  Mips_HWR22 = 285,
  Mips_HWR23 = 286,
  Mips_HWR24 = 287,
  Mips_HWR25 = 288,
  Mips_HWR26 = 289,
  Mips_HWR27 = 290,
  Mips_HWR28 = 291,
  Mips_HWR29 = 292,
  Mips_HWR30 = 293,
  Mips_HWR31 = 294,
  Mips_K0 = 295,
  Mips_K1 = 296,
  Mips_LO0 = 297,
  Mips_LO1 = 298,
  Mips_LO2 = 299,
  Mips_LO3 = 300,
  Mips_MPL0 = 301,
  Mips_MPL1 = 302,
  Mips_MPL2 = 303,
  Mips_MSA8 = 304,
  Mips_MSA9 = 305,
  Mips_MSA10 = 306,
  Mips_MSA11 = 307,
  Mips_MSA12 = 308,
  Mips_MSA13 = 309,
  Mips_MSA14 = 310,
  Mips_MSA15 = 311,
  Mips_MSA16 = 312,
  Mips_MSA17 = 313,
  Mips_MSA18 = 314,
  Mips_MSA19 = 315,
  Mips_MSA20 = 316,
  Mips_MSA21 = 317,
  Mips_MSA22 = 318,
  Mips_MSA23 = 319,
  Mips_MSA24 = 320,
  Mips_MSA25 = 321,
  Mips_MSA26 = 322,
  Mips_MSA27 = 323,
  Mips_MSA28 = 324,
  Mips_MSA29 = 325,
  Mips_MSA30 = 326,
  Mips_MSA31 = 327,
  Mips_P0 = 328,
  Mips_P1 = 329,
  Mips_P2 = 330,
  Mips_RA_64 = 331,
  Mips_S0 = 332,
  Mips_S1 = 333,
  Mips_S2 = 334,
  Mips_S3 = 335,
  Mips_S4 = 336,
  Mips_S5 = 337,
  Mips_S6 = 338,
  Mips_S7 = 339,
  Mips_SP_64 = 340,
  Mips_T0 = 341,
  Mips_T1 = 342,
  Mips_T2 = 343,
  Mips_T3 = 344,
  Mips_T4 = 345,
  Mips_T5 = 346,
  Mips_T6 = 347,
  Mips_T7 = 348,
  Mips_T8 = 349,
  Mips_T9 = 350,
  Mips_V0 = 351,
  Mips_V1 = 352,
  Mips_W0 = 353,
  Mips_W1 = 354,
  Mips_W2 = 355,
  Mips_W3 = 356,
  Mips_W4 = 357,
  Mips_W5 = 358,
  Mips_W6 = 359,
  Mips_W7 = 360,
  Mips_W8 = 361,
  Mips_W9 = 362,
  Mips_W10 = 363,
  Mips_W11 = 364,
  Mips_W12 = 365,
  Mips_W13 = 366,
  Mips_W14 = 367,
  Mips_W15 = 368,
  Mips_W16 = 369,
  Mips_W17 = 370,
  Mips_W18 = 371,
  Mips_W19 = 372,
  Mips_W20 = 373,
  Mips_W21 = 374,
  Mips_W22 = 375,
  Mips_W23 = 376,
  Mips_W24 = 377,
  Mips_W25 = 378,
  Mips_W26 = 379,
  Mips_W27 = 380,
  Mips_W28 = 381,
  Mips_W29 = 382,
  Mips_W30 = 383,
  Mips_W31 = 384,
  Mips_ZERO_64 = 385,
  Mips_A0_NM = 386,
  Mips_A1_NM = 387,
  Mips_A2_NM = 388,
  Mips_A3_NM = 389,
  Mips_A4_NM = 390,
  Mips_A5_NM = 391,
  Mips_A6_NM = 392,
  Mips_A7_NM = 393,
  Mips_COP0Sel_BADINST = 394,
  Mips_COP0Sel_BADINSTRP = 395,
  Mips_COP0Sel_BADINSTRX = 396,
  Mips_COP0Sel_BADVADDR = 397,
  Mips_COP0Sel_BEVVA = 398,
  Mips_COP0Sel_CACHEERR = 399,
  Mips_COP0Sel_CAUSE = 400,
  Mips_COP0Sel_CDMMBASE = 401,
  Mips_COP0Sel_CMGCRBASE = 402,
  Mips_COP0Sel_COMPARE = 403,
  Mips_COP0Sel_CONFIG = 404,
  Mips_COP0Sel_CONTEXT = 405,
  Mips_COP0Sel_CONTEXTCONFIG = 406,
  Mips_COP0Sel_COUNT = 407,
  Mips_COP0Sel_DDATAHI = 408,
  Mips_COP0Sel_DDATALO = 409,
  Mips_COP0Sel_DEBUG = 410,
  Mips_COP0Sel_DEBUGCONTEXTID = 411,
  Mips_COP0Sel_DEPC = 412,
  Mips_COP0Sel_DESAVE = 413,
  Mips_COP0Sel_DTAGHI = 414,
  Mips_COP0Sel_DTAGLO = 415,
  Mips_COP0Sel_EBASE = 416,
  Mips_COP0Sel_ENTRYHI = 417,
  Mips_COP0Sel_EPC = 418,
  Mips_COP0Sel_ERRCTL = 419,
  Mips_COP0Sel_ERROREPC = 420,
  Mips_COP0Sel_GLOBALNUMBER = 421,
  Mips_COP0Sel_GTOFFSET = 422,
  Mips_COP0Sel_HWRENA = 423,
  Mips_COP0Sel_IDATAHI = 424,
  Mips_COP0Sel_IDATALO = 425,
  Mips_COP0Sel_INDEX = 426,
  Mips_COP0Sel_INTCTL = 427,
  Mips_COP0Sel_ITAGHI = 428,
  Mips_COP0Sel_ITAGLO = 429,
  Mips_COP0Sel_LLADDR = 430,
  Mips_COP0Sel_MAAR = 431,
  Mips_COP0Sel_MAARI = 432,
  Mips_COP0Sel_MEMORYMAPID = 433,
  Mips_COP0Sel_MVPCONTROL = 434,
  Mips_COP0Sel_NESTEDEPC = 435,
  Mips_COP0Sel_NESTEDEXC = 436,
  Mips_COP0Sel_PAGEGRAIN = 437,
  Mips_COP0Sel_PAGEMASK = 438,
  Mips_COP0Sel_PRID = 439,
  Mips_COP0Sel_PWBASE = 440,
  Mips_COP0Sel_PWCTL = 441,
  Mips_COP0Sel_PWFIELD = 442,
  Mips_COP0Sel_PWSIZE = 443,
  Mips_COP0Sel_RANDOM = 444,
  Mips_COP0Sel_SRSCTL = 445,
  Mips_COP0Sel_SRSMAP = 446,
  Mips_COP0Sel_STATUS = 447,
  Mips_COP0Sel_TCBIND = 448,
  Mips_COP0Sel_TCCONTEXT = 449,
  Mips_COP0Sel_TCHALT = 450,
  Mips_COP0Sel_TCOPT = 451,
  Mips_COP0Sel_TCRESTART = 452,
  Mips_COP0Sel_TCSCHEDULE = 453,
  Mips_COP0Sel_TCSCHEFBACK = 454,
  Mips_COP0Sel_TCSTATUS = 455,
  Mips_COP0Sel_TRACECONTROL = 456,
  Mips_COP0Sel_TRACEDBPC = 457,
  Mips_COP0Sel_TRACEIBPC = 458,
  Mips_COP0Sel_USERLOCAL = 459,
  Mips_COP0Sel_VIEW_IPL = 460,
  Mips_COP0Sel_VIEW_RIPL = 461,
  Mips_COP0Sel_VPCONTROL = 462,
  Mips_COP0Sel_VPECONTROL = 463,
  Mips_COP0Sel_VPEOPT = 464,
  Mips_COP0Sel_VPESCHEDULE = 465,
  Mips_COP0Sel_VPESCHEFBACK = 466,
  Mips_COP0Sel_WIRED = 467,
  Mips_COP0Sel_XCONTEXT = 468,
  Mips_COP0Sel_XCONTEXTCONFIG = 469,
  Mips_COP0Sel_YQMASK = 470,
  Mips_K0_NM = 471,
  Mips_K1_NM = 472,
  Mips_S0_NM = 473,
  Mips_S1_NM = 474,
  Mips_S2_NM = 475,
  Mips_S3_NM = 476,
  Mips_S4_NM = 477,
  Mips_S5_NM = 478,
  Mips_S6_NM = 479,
  Mips_S7_NM = 480,
  Mips_T0_NM = 481,
  Mips_T1_NM = 482,
  Mips_T2_NM = 483,
  Mips_T3_NM = 484,
  Mips_T4_NM = 485,
  Mips_T5_NM = 486,
  Mips_T8_NM = 487,
  Mips_T9_NM = 488,
  Mips_A0_64 = 489,
  Mips_A1_64 = 490,
  Mips_A2_64 = 491,
  Mips_A3_64 = 492,
  Mips_AC0_64 = 493,
  Mips_COP0Sel_CONFIG1 = 494,
  Mips_COP0Sel_CONFIG2 = 495,
  Mips_COP0Sel_CONFIG3 = 496,
  Mips_COP0Sel_CONFIG4 = 497,
  Mips_COP0Sel_CONFIG5 = 498,
  Mips_COP0Sel_DEBUG2 = 499,
  Mips_COP0Sel_ENTRYLO0 = 500,
  Mips_COP0Sel_ENTRYLO1 = 501,
  Mips_COP0Sel_GUESTCTL0 = 502,
  Mips_COP0Sel_GUESTCTL1 = 503,
  Mips_COP0Sel_GUESTCTL2 = 504,
  Mips_COP0Sel_GUESTCTL3 = 505,
  Mips_COP0Sel_KSCRATCH1 = 506,
  Mips_COP0Sel_KSCRATCH2 = 507,
  Mips_COP0Sel_KSCRATCH3 = 508,
  Mips_COP0Sel_KSCRATCH4 = 509,
  Mips_COP0Sel_KSCRATCH5 = 510,
  Mips_COP0Sel_KSCRATCH6 = 511,
  Mips_COP0Sel_MVPCONF0 = 512,
  Mips_COP0Sel_MVPCONF1 = 513,
  Mips_COP0Sel_PERFCNT0 = 514,
  Mips_COP0Sel_PERFCNT1 = 515,
  Mips_COP0Sel_PERFCNT2 = 516,
  Mips_COP0Sel_PERFCNT3 = 517,
  Mips_COP0Sel_PERFCNT4 = 518,
  Mips_COP0Sel_PERFCNT5 = 519,
  Mips_COP0Sel_PERFCNT6 = 520,
  Mips_COP0Sel_PERFCNT7 = 521,
  Mips_COP0Sel_PERFCTL0 = 522,
  Mips_COP0Sel_PERFCTL1 = 523,
  Mips_COP0Sel_PERFCTL2 = 524,
  Mips_COP0Sel_PERFCTL3 = 525,
  Mips_COP0Sel_PERFCTL4 = 526,
  Mips_COP0Sel_PERFCTL5 = 527,
  Mips_COP0Sel_PERFCTL6 = 528,
  Mips_COP0Sel_PERFCTL7 = 529,
  Mips_COP0Sel_SEGCTL0 = 530,
  Mips_COP0Sel_SEGCTL1 = 531,
  Mips_COP0Sel_SEGCTL2 = 532,
  Mips_COP0Sel_SRSCONF0 = 533,
  Mips_COP0Sel_SRSCONF1 = 534,
  Mips_COP0Sel_SRSCONF2 = 535,
  Mips_COP0Sel_SRSCONF3 = 536,
  Mips_COP0Sel_SRSCONF4 = 537,
  Mips_COP0Sel_SRSMAP2 = 538,
  Mips_COP0Sel_TRACECONTROL2 = 539,
  Mips_COP0Sel_TRACECONTROL3 = 540,
  Mips_COP0Sel_USERTRACEDATA1 = 541,
  Mips_COP0Sel_USERTRACEDATA2 = 542,
  Mips_COP0Sel_VPECONF0 = 543,
  Mips_COP0Sel_VPECONF1 = 544,
  Mips_COP0Sel_WATCHHI0 = 545,
  Mips_COP0Sel_WATCHHI1 = 546,
  Mips_COP0Sel_WATCHHI2 = 547,
  Mips_COP0Sel_WATCHHI3 = 548,
  Mips_COP0Sel_WATCHHI4 = 549,
  Mips_COP0Sel_WATCHHI5 = 550,
  Mips_COP0Sel_WATCHHI6 = 551,
  Mips_COP0Sel_WATCHHI7 = 552,
  Mips_COP0Sel_WATCHHI8 = 553,
  Mips_COP0Sel_WATCHHI9 = 554,
  Mips_COP0Sel_WATCHHI10 = 555,
  Mips_COP0Sel_WATCHHI11 = 556,
  Mips_COP0Sel_WATCHHI12 = 557,
  Mips_COP0Sel_WATCHHI13 = 558,
  Mips_COP0Sel_WATCHHI14 = 559,
  Mips_COP0Sel_WATCHHI15 = 560,
  Mips_COP0Sel_WATCHLO0 = 561,
  Mips_COP0Sel_WATCHLO1 = 562,
  Mips_COP0Sel_WATCHLO2 = 563,
  Mips_COP0Sel_WATCHLO3 = 564,
  Mips_COP0Sel_WATCHLO4 = 565,
  Mips_COP0Sel_WATCHLO5 = 566,
  Mips_COP0Sel_WATCHLO6 = 567,
  Mips_COP0Sel_WATCHLO7 = 568,
  Mips_COP0Sel_WATCHLO8 = 569,
  Mips_COP0Sel_WATCHLO9 = 570,
  Mips_COP0Sel_WATCHLO10 = 571,
  Mips_COP0Sel_WATCHLO11 = 572,
  Mips_COP0Sel_WATCHLO12 = 573,
  Mips_COP0Sel_WATCHLO13 = 574,
  Mips_COP0Sel_WATCHLO14 = 575,
  Mips_COP0Sel_WATCHLO15 = 576,
  Mips_D0_64 = 577,
  Mips_D1_64 = 578,
  Mips_D2_64 = 579,
  Mips_D3_64 = 580,
  Mips_D4_64 = 581,
  Mips_D5_64 = 582,
  Mips_D6_64 = 583,
  Mips_D7_64 = 584,
  Mips_D8_64 = 585,
  Mips_D9_64 = 586,
  Mips_D10_64 = 587,
  Mips_D11_64 = 588,
  Mips_D12_64 = 589,
  Mips_D13_64 = 590,
  Mips_D14_64 = 591,
  Mips_D15_64 = 592,
  Mips_D16_64 = 593,
  Mips_D17_64 = 594,
  Mips_D18_64 = 595,
  Mips_D19_64 = 596,
  Mips_D20_64 = 597,
  Mips_D21_64 = 598,
  Mips_D22_64 = 599,
  Mips_D23_64 = 600,
  Mips_D24_64 = 601,
  Mips_D25_64 = 602,
  Mips_D26_64 = 603,
  Mips_D27_64 = 604,
  Mips_D28_64 = 605,
  Mips_D29_64 = 606,
  Mips_D30_64 = 607,
  Mips_D31_64 = 608,
  Mips_DSPOutFlag16_19 = 609,
  Mips_HI0_64 = 610,
  Mips_K0_64 = 611,
  Mips_K1_64 = 612,
  Mips_LO0_64 = 613,
  Mips_S0_64 = 614,
  Mips_S1_64 = 615,
  Mips_S2_64 = 616,
  Mips_S3_64 = 617,
  Mips_S4_64 = 618,
  Mips_S5_64 = 619,
  Mips_S6_64 = 620,
  Mips_S7_64 = 621,
  Mips_T0_64 = 622,
  Mips_T1_64 = 623,
  Mips_T2_64 = 624,
  Mips_T3_64 = 625,
  Mips_T4_64 = 626,
  Mips_T5_64 = 627,
  Mips_T6_64 = 628,
  Mips_T7_64 = 629,
  Mips_T8_64 = 630,
  Mips_T9_64 = 631,
  Mips_V0_64 = 632,
  Mips_V1_64 = 633,
  Mips_COP0Sel_GUESTCTL0EXT = 634,
  NUM_TARGET_REGS // 635
};

// Register classes

enum {
  Mips_MSA128F16RegClassID = 0,
  Mips_COP0SelRegClassID = 1,
  Mips_CCRRegClassID = 2,
  Mips_COP0RegClassID = 3,
  Mips_COP2RegClassID = 4,
  Mips_COP3RegClassID = 5,
  Mips_DSPRRegClassID = 6,
  Mips_FGR32RegClassID = 7,
  Mips_FGRCCRegClassID = 8,
  Mips_GPR32RegClassID = 9,
  Mips_GPRNM32RegClassID = 10,
  Mips_HWRegsRegClassID = 11,
  Mips_MSACtrlRegClassID = 12,
  Mips_GPR32NONZERORegClassID = 13,
  Mips_GPRNM32NZRegClassID = 14,
  Mips_GPRNM32_TAILRegClassID = 15,
  Mips_GPRNM4RegClassID = 16,
  Mips_GPRNM4ZRegClassID = 17,
  Mips_GPRNM4_and_GPRNM4ZRegClassID = 18,
  Mips_CPU16RegsPlusSPRegClassID = 19,
  Mips_CPU16RegsRegClassID = 20,
  Mips_FCCRegClassID = 21,
  Mips_GPRMM16RegClassID = 22,
  Mips_GPRMM16MovePRegClassID = 23,
  Mips_GPRMM16ZeroRegClassID = 24,
  Mips_GPRNM3RegClassID = 25,
  Mips_GPRNM3ZRegClassID = 26,
  Mips_GPRNM4_and_GPRNM32_TAILRegClassID = 27,
  Mips_CPU16Regs_and_GPRMM16ZeroRegClassID = 28,
  Mips_GPR32NONZERO_and_GPRMM16MovePRegClassID = 29,
  Mips_GPRNM3_and_GPRNM3ZRegClassID = 30,
  Mips_GPRNM4Z_and_GPRNM32_TAILRegClassID = 31,
  Mips_GPRMM16MovePPairSecondRegClassID = 32,
  Mips_CPU16Regs_and_GPRMM16MovePRegClassID = 33,
  Mips_GPRMM16MoveP_and_GPRMM16ZeroRegClassID = 34,
  Mips_GPRNM2R1RegClassID = 35,
  Mips_GPRNM2R2RegClassID = 36,
  Mips_HI32DSPRegClassID = 37,
  Mips_LO32DSPRegClassID = 38,
  Mips_CPU16Regs_and_GPRMM16MovePPairSecondRegClassID = 39,
  Mips_GPRMM16MovePPairFirstRegClassID = 40,
  Mips_GPRMM16MoveP_and_CPU16Regs_and_GPRMM16ZeroRegClassID = 41,
  Mips_GPRNM2R1_and_GPRNM2R2RegClassID = 42,
  Mips_GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecondRegClassID = 43,
  Mips_GPRNM1R1RegClassID = 44,
  Mips_CPURARegRegClassID = 45,
  Mips_CPUSPRegRegClassID = 46,
  Mips_DSPCCRegClassID = 47,
  Mips_GP32RegClassID = 48,
  Mips_GPR32ZERORegClassID = 49,
  Mips_GPRNM1R1_and_GPRNM2R2RegClassID = 50,
  Mips_GPRNMGPRegClassID = 51,
  Mips_GPRNMRARegClassID = 52,
  Mips_GPRNMSPRegClassID = 53,
  Mips_HI32RegClassID = 54,
  Mips_LO32RegClassID = 55,
  Mips_SP32RegClassID = 56,
  Mips_FGR64RegClassID = 57,
  Mips_GPR64RegClassID = 58,
  Mips_GPR64_with_sub_32_in_GPR32NONZERORegClassID = 59,
  Mips_AFGR64RegClassID = 60,
  Mips_GPR64_with_sub_32_in_CPU16RegsPlusSPRegClassID = 61,
  Mips_GPR64_with_sub_32_in_CPU16RegsRegClassID = 62,
  Mips_GPR64_with_sub_32_in_GPRMM16MovePRegClassID = 63,
  Mips_GPR64_with_sub_32_in_GPRMM16ZeroRegClassID = 64,
  Mips_GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16ZeroRegClassID = 65,
  Mips_GPR64_with_sub_32_in_GPR32NONZERO_and_GPRMM16MovePRegClassID = 66,
  Mips_GPR64_with_sub_32_in_GPRMM16MovePPairSecondRegClassID = 67,
  Mips_ACC64DSPRegClassID = 68,
  Mips_GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MovePRegClassID = 69,
  Mips_GPR64_with_sub_32_in_GPRMM16MoveP_and_GPRMM16ZeroRegClassID = 70,
  Mips_GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MovePPairSecondRegClassID = 71,
  Mips_GPR64_with_sub_32_in_GPRMM16MovePPairFirstRegClassID = 72,
  Mips_GPR64_with_sub_32_in_GPRMM16MoveP_and_CPU16Regs_and_GPRMM16ZeroRegClassID = 73,
  Mips_OCTEON_MPLRegClassID = 74,
  Mips_OCTEON_PRegClassID = 75,
  Mips_GPR64_with_sub_32_in_GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecondRegClassID = 76,
  Mips_ACC64RegClassID = 77,
  Mips_GP64RegClassID = 78,
  Mips_GPR64_with_sub_32_in_CPURARegRegClassID = 79,
  Mips_GPR64_with_sub_32_in_GPR32ZERORegClassID = 80,
  Mips_HI64RegClassID = 81,
  Mips_LO64RegClassID = 82,
  Mips_SP64RegClassID = 83,
  Mips_MSA128BRegClassID = 84,
  Mips_MSA128DRegClassID = 85,
  Mips_MSA128HRegClassID = 86,
  Mips_MSA128WRegClassID = 87,
  Mips_MSA128WEvensRegClassID = 88,
  Mips_ACC128RegClassID = 89,

};

// Subregister indices

enum {
  Mips_NoSubRegister,
  Mips_sub_32,	// 1
  Mips_sub_64,	// 2
  Mips_sub_dsp16_19,	// 3
  Mips_sub_dsp20,	// 4
  Mips_sub_dsp21,	// 5
  Mips_sub_dsp22,	// 6
  Mips_sub_dsp23,	// 7
  Mips_sub_hi,	// 8
  Mips_sub_lo,	// 9
  Mips_sub_hi_then_sub_32,	// 10
  Mips_sub_32_sub_hi_then_sub_32,	// 11
  Mips_NUM_TARGET_SUBREGS
};
#endif // GET_REGINFO_ENUM

/* Capstone Disassembly Engine, https://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/*    Rot127 <unisono@quyllur.org> 2022-2024 */
/* Automatically generated file by Capstone's LLVM TableGen Disassembler Backend. */

/* LLVM-commit: <commit> */
/* LLVM-tag: <tag> */

/* Do not edit. */

/* Capstone's LLVM TableGen Backends: */
/* https://github.com/capstone-engine/llvm-capstone */

#ifdef GET_REGINFO_MC_DESC
#undef GET_REGINFO_MC_DESC

static const MCPhysReg MipsRegDiffLists[] = {
  /* 0 */ -603, 0,
  /* 2 */ -461, 0,
  /* 4 */ -359, 0,
  /* 6 */ -351, 0,
  /* 8 */ -316, 0,
  /* 10 */ -309, 0,
  /* 12 */ -282, 0,
  /* 14 */ -281, 0,
  /* 16 */ -265, 0,
  /* 18 */ -247, 0,
  /* 20 */ 120, -316, 313, -351, -227, 0,
  /* 26 */ 351, -224, 0,
  /* 29 */ -20, 444, -224, 0,
  /* 33 */ -21, 445, -224, 0,
  /* 37 */ -22, 446, -224, 0,
  /* 41 */ -23, 447, -224, 0,
  /* 45 */ -24, 448, -224, 0,
  /* 49 */ -25, 449, -224, 0,
  /* 53 */ -26, 450, -224, 0,
  /* 57 */ -27, 451, -224, 0,
  /* 61 */ -28, 452, -224, 0,
  /* 65 */ -29, 453, -224, 0,
  /* 69 */ -30, 454, -224, 0,
  /* 73 */ -31, 455, -224, 0,
  /* 77 */ -32, 456, -224, 0,
  /* 81 */ -33, 457, -224, 0,
  /* 85 */ -34, 458, -224, 0,
  /* 89 */ -35, 459, -224, 0,
  /* 93 */ -36, 460, -224, 0,
  /* 97 */ -216, 0,
  /* 99 */ -146, 0,
  /* 101 */ -145, 0,
  /* 103 */ -144, 0,
  /* 105 */ -143, 0,
  /* 107 */ -265, 581, -120, 0,
  /* 111 */ -227, 578, -117, 0,
  /* 115 */ 265, -38, 0,
  /* 118 */ -35, 0,
  /* 120 */ 603, -460, 1, 1, 1, 0,
  /* 126 */ 1, 1, 1, 1, 0,
  /* 131 */ 20, 1, 0,
  /* 134 */ 21, 1, 0,
  /* 137 */ 22, 1, 0,
  /* 140 */ 23, 1, 0,
  /* 143 */ 24, 1, 0,
  /* 146 */ 25, 1, 0,
  /* 149 */ 26, 1, 0,
  /* 152 */ 27, 1, 0,
  /* 155 */ 28, 1, 0,
  /* 158 */ 29, 1, 0,
  /* 161 */ 30, 1, 0,
  /* 164 */ 31, 1, 0,
  /* 167 */ 32, 1, 0,
  /* 170 */ 33, 1, 0,
  /* 173 */ 34, 1, 0,
  /* 176 */ 35, 1, 0,
  /* 179 */ 35, 0,
  /* 181 */ 72, 0,
  /* 183 */ 224, -424, 73, 0,
  /* 187 */ 216, 0,
  /* 189 */ 247, 0,
  /* 191 */ 281, 0,
  /* 193 */ 282, 0,
  /* 195 */ 309, 0,
  /* 197 */ 316, 0,
  /* 199 */ 359, 0,
  /* 201 */ 461, 0,
};

static const uint16_t MipsSubRegIdxLists[] = {
  /* 0 */ 1, 0,
  /* 2 */ 3, 4, 5, 6, 7, 0,
  /* 8 */ 2, 9, 8, 0,
  /* 12 */ 9, 1, 8, 10, 11, 0,
};

static const MCRegisterDesc MipsRegDesc[] = { // Descriptors
  { 5, 0, 0, 0, 0, 0 },
  { 5012, 1, 179, 1, 4096, 11 },
  { 4736, 1, 1, 1, 4097, 11 },
  { 5228, 1, 1, 1, 4098, 11 },
  { 5320, 1, 1, 1, 4099, 11 },
  { 4187, 1, 1, 1, 4100, 11 },
  { 5245, 120, 1, 2, 516101, 2 },
  { 5272, 1, 1, 1, 4106, 11 },
  { 5289, 1, 1, 1, 4107, 11 },
  { 4857, 1, 187, 1, 4108, 11 },
  { 4718, 1, 1, 1, 4109, 11 },
  { 4860, 1, 189, 1, 4110, 11 },
  { 4724, 1, 1, 1, 4111, 11 },
  { 5279, 1, 1, 1, 4112, 11 },
  { 4973, 1, 1, 1, 4113, 11 },
  { 4950, 1, 1, 1, 4114, 11 },
  { 5256, 1, 1, 1, 4115, 11 },
  { 5310, 1, 1, 1, 4116, 11 },
  { 5299, 1, 1, 1, 4117, 11 },
  { 5237, 1, 1, 1, 4118, 11 },
  { 5263, 1, 1, 1, 4119, 11 },
  { 3750, 1, 1, 1, 4120, 11 },
  { 3718, 1, 195, 1, 4121, 11 },
  { 4704, 1, 1, 1, 4122, 11 },
  { 4881, 1, 197, 1, 4123, 11 },
  { 4730, 1, 1, 1, 4124, 11 },
  { 4837, 1, 199, 1, 4125, 11 },
  { 4710, 1, 1, 1, 4126, 11 },
  { 233, 1, 201, 1, 4127, 11 },
  { 707, 1, 201, 1, 4128, 11 },
  { 1161, 1, 201, 1, 4129, 11 },
  { 1588, 1, 201, 1, 4130, 11 },
  { 236, 115, 201, 9, 507939, 8 },
  { 710, 115, 1, 9, 507941, 8 },
  { 1164, 115, 1, 9, 507943, 8 },
  { 1591, 115, 1, 9, 507945, 8 },
  { 2373, 118, 1, 0, 4096, 0 },
  { 0, 1, 1, 1, 4139, 11 },
  { 454, 1, 1, 1, 4140, 11 },
  { 962, 1, 1, 1, 4141, 11 },
  { 1409, 1, 1, 1, 4142, 11 },
  { 1784, 1, 1, 1, 4143, 11 },
  { 2528, 1, 1, 1, 4144, 11 },
  { 2829, 1, 1, 1, 4145, 11 },
  { 3074, 1, 1, 1, 4146, 11 },
  { 3301, 1, 1, 1, 4147, 11 },
  { 3494, 1, 1, 1, 4148, 11 },
  { 138, 1, 1, 1, 4149, 11 },
  { 592, 1, 1, 1, 4150, 11 },
  { 1100, 1, 1, 1, 4151, 11 },
  { 1547, 1, 1, 1, 4152, 11 },
  { 1922, 1, 1, 1, 4153, 11 },
  { 2666, 1, 1, 1, 4154, 11 },
  { 2927, 1, 1, 1, 4155, 11 },
  { 3172, 1, 1, 1, 4156, 11 },
  { 3399, 1, 1, 1, 4157, 11 },
  { 3608, 1, 1, 1, 4158, 11 },
  { 211, 1, 1, 1, 4159, 11 },
  { 665, 1, 1, 1, 4160, 11 },
  { 1135, 1, 1, 1, 4161, 11 },
  { 1582, 1, 1, 1, 4162, 11 },
  { 1944, 1, 1, 1, 4163, 11 },
  { 2688, 1, 1, 1, 4164, 11 },
  { 2949, 1, 1, 1, 4165, 11 },
  { 3194, 1, 1, 1, 4166, 11 },
  { 3421, 1, 1, 1, 4167, 11 },
  { 3630, 1, 1, 1, 4168, 11 },
  { 6, 1, 1, 1, 4169, 11 },
  { 460, 1, 1, 1, 4170, 11 },
  { 968, 1, 1, 1, 4171, 11 },
  { 1415, 1, 1, 1, 4172, 11 },
  { 1790, 1, 1, 1, 4173, 11 },
  { 2534, 1, 1, 1, 4174, 11 },
  { 2835, 1, 1, 1, 4175, 11 },
  { 3080, 1, 1, 1, 4176, 11 },
  { 3307, 1, 1, 1, 4177, 11 },
  { 3500, 1, 1, 1, 4178, 11 },
  { 100, 1, 1, 1, 4179, 11 },
  { 554, 1, 1, 1, 4180, 11 },
  { 1062, 1, 1, 1, 4181, 11 },
  { 1509, 1, 1, 1, 4182, 11 },
  { 1884, 1, 1, 1, 4183, 11 },
  { 2628, 1, 1, 1, 4184, 11 },
  { 2889, 1, 1, 1, 4185, 11 },
  { 3134, 1, 1, 1, 4186, 11 },
  { 3361, 1, 1, 1, 4187, 11 },
  { 3570, 1, 1, 1, 4188, 11 },
  { 173, 1, 1, 1, 4189, 11 },
  { 627, 1, 1, 1, 4190, 11 },
  { 13, 1, 1, 1, 4191, 11 },
  { 467, 1, 1, 1, 4192, 11 },
  { 975, 1, 1, 1, 4193, 11 },
  { 1422, 1, 1, 1, 4194, 11 },
  { 1797, 1, 1, 1, 4195, 11 },
  { 2541, 1, 1, 1, 4196, 11 },
  { 2842, 1, 1, 1, 4197, 11 },
  { 3087, 1, 1, 1, 4198, 11 },
  { 3314, 1, 1, 1, 4199, 11 },
  { 3507, 1, 1, 1, 4200, 11 },
  { 107, 1, 1, 1, 4201, 11 },
  { 561, 1, 1, 1, 4202, 11 },
  { 1069, 1, 1, 1, 4203, 11 },
  { 1516, 1, 1, 1, 4204, 11 },
  { 1891, 1, 1, 1, 4205, 11 },
  { 2635, 1, 1, 1, 4206, 11 },
  { 2896, 1, 1, 1, 4207, 11 },
  { 3141, 1, 1, 1, 4208, 11 },
  { 3368, 1, 1, 1, 4209, 11 },
  { 3577, 1, 1, 1, 4210, 11 },
  { 180, 1, 1, 1, 4211, 11 },
  { 634, 1, 1, 1, 4212, 11 },
  { 20, 1, 1, 1, 4213, 11 },
  { 474, 1, 1, 1, 4214, 11 },
  { 982, 1, 1, 1, 4215, 11 },
  { 1429, 1, 1, 1, 4216, 11 },
  { 1804, 1, 1, 1, 4217, 11 },
  { 2548, 1, 1, 1, 4218, 11 },
  { 2849, 1, 1, 1, 4219, 11 },
  { 3094, 1, 1, 1, 4220, 11 },
  { 3321, 1, 1, 1, 4221, 11 },
  { 3514, 1, 1, 1, 4222, 11 },
  { 114, 1, 1, 1, 4223, 11 },
  { 568, 1, 1, 1, 4224, 11 },
  { 1076, 1, 1, 1, 4225, 11 },
  { 1523, 1, 1, 1, 4226, 11 },
  { 1898, 1, 1, 1, 4227, 11 },
  { 2642, 1, 1, 1, 4228, 11 },
  { 2903, 1, 1, 1, 4229, 11 },
  { 3148, 1, 1, 1, 4230, 11 },
  { 3375, 1, 1, 1, 4231, 11 },
  { 3584, 1, 1, 1, 4232, 11 },
  { 187, 1, 1, 1, 4233, 11 },
  { 641, 1, 1, 1, 4234, 11 },
  { 245, 131, 1, 9, 508043, 8 },
  { 719, 134, 1, 9, 508045, 8 },
  { 1173, 137, 1, 9, 508047, 8 },
  { 1600, 140, 1, 9, 508049, 8 },
  { 2384, 143, 1, 9, 508051, 8 },
  { 2699, 146, 1, 9, 508053, 8 },
  { 2960, 149, 1, 9, 508055, 8 },
  { 3205, 152, 1, 9, 508057, 8 },
  { 3432, 155, 1, 9, 508059, 8 },
  { 3641, 158, 1, 9, 508061, 8 },
  { 33, 161, 1, 9, 508063, 8 },
  { 487, 164, 1, 9, 508065, 8 },
  { 995, 167, 1, 9, 508067, 8 },
  { 1442, 170, 1, 9, 508069, 8 },
  { 1817, 173, 1, 9, 508071, 8 },
  { 2561, 176, 1, 9, 508073, 8 },
  { 160, 1, 105, 1, 4102, 11 },
  { 614, 1, 103, 1, 4103, 11 },
  { 1122, 1, 101, 1, 4104, 11 },
  { 1569, 1, 99, 1, 4105, 11 },
  { 262, 1, 29, 1, 4235, 11 },
  { 736, 1, 33, 1, 4236, 11 },
  { 1190, 1, 33, 1, 4237, 11 },
  { 1617, 1, 37, 1, 4238, 11 },
  { 2401, 1, 37, 1, 4239, 11 },
  { 2702, 1, 41, 1, 4240, 11 },
  { 2963, 1, 41, 1, 4241, 11 },
  { 3208, 1, 45, 1, 4242, 11 },
  { 3435, 1, 45, 1, 4243, 11 },
  { 3644, 1, 49, 1, 4244, 11 },
  { 37, 1, 49, 1, 4245, 11 },
  { 491, 1, 53, 1, 4246, 11 },
  { 999, 1, 53, 1, 4247, 11 },
  { 1446, 1, 57, 1, 4248, 11 },
  { 1821, 1, 57, 1, 4249, 11 },
  { 2565, 1, 61, 1, 4250, 11 },
  { 2862, 1, 61, 1, 4251, 11 },
  { 3107, 1, 65, 1, 4252, 11 },
  { 3334, 1, 65, 1, 4253, 11 },
  { 3527, 1, 69, 1, 4254, 11 },
  { 127, 1, 69, 1, 4255, 11 },
  { 581, 1, 73, 1, 4256, 11 },
  { 1089, 1, 73, 1, 4257, 11 },
  { 1536, 1, 77, 1, 4258, 11 },
  { 1911, 1, 77, 1, 4259, 11 },
  { 2655, 1, 81, 1, 4260, 11 },
  { 2916, 1, 81, 1, 4261, 11 },
  { 3161, 1, 85, 1, 4262, 11 },
  { 3388, 1, 85, 1, 4263, 11 },
  { 3597, 1, 89, 1, 4264, 11 },
  { 200, 1, 89, 1, 4265, 11 },
  { 654, 1, 93, 1, 4266, 11 },
  { 240, 1, 1, 1, 4267, 11 },
  { 714, 1, 1, 1, 4268, 11 },
  { 1168, 1, 1, 1, 4269, 11 },
  { 1595, 1, 1, 1, 4270, 11 },
  { 2379, 1, 1, 1, 4271, 11 },
  { 2694, 1, 1, 1, 4272, 11 },
  { 2955, 1, 1, 1, 4273, 11 },
  { 3200, 1, 1, 1, 4274, 11 },
  { 418, 1, 1, 1, 4275, 11 },
  { 926, 1, 1, 1, 4276, 11 },
  { 1376, 1, 1, 1, 4277, 11 },
  { 1751, 1, 1, 1, 4278, 11 },
  { 2495, 1, 1, 1, 4279, 11 },
  { 2796, 1, 1, 1, 4280, 11 },
  { 3041, 1, 1, 1, 4281, 11 },
  { 3268, 1, 1, 1, 4282, 11 },
  { 3478, 1, 1, 1, 4283, 11 },
  { 3687, 1, 1, 1, 4284, 11 },
  { 84, 1, 1, 1, 4285, 11 },
  { 538, 1, 1, 1, 4286, 11 },
  { 1046, 1, 1, 1, 4287, 11 },
  { 1493, 1, 1, 1, 4288, 11 },
  { 1868, 1, 1, 1, 4289, 11 },
  { 2612, 1, 1, 1, 4290, 11 },
  { 2873, 1, 1, 1, 4291, 11 },
  { 3118, 1, 1, 1, 4292, 11 },
  { 3345, 1, 1, 1, 4293, 11 },
  { 3538, 1, 1, 1, 4294, 11 },
  { 144, 1, 1, 1, 4295, 11 },
  { 598, 1, 1, 1, 4296, 11 },
  { 1106, 1, 1, 1, 4297, 11 },
  { 1553, 1, 1, 1, 4298, 11 },
  { 1928, 1, 1, 1, 4299, 11 },
  { 2672, 1, 1, 1, 4300, 11 },
  { 2933, 1, 1, 1, 4301, 11 },
  { 3178, 1, 1, 1, 4302, 11 },
  { 3405, 1, 1, 1, 4303, 11 },
  { 3614, 1, 1, 1, 4304, 11 },
  { 217, 1, 1, 1, 4305, 11 },
  { 671, 1, 1, 1, 4306, 11 },
  { 2355, 97, 1, 0, 4108, 0 },
  { 316, 1, 26, 1, 4307, 11 },
  { 824, 1, 26, 1, 4308, 11 },
  { 1259, 1, 26, 1, 4309, 11 },
  { 1671, 1, 26, 1, 4310, 11 },
  { 2455, 1, 26, 1, 4311, 11 },
  { 2756, 1, 26, 1, 4312, 11 },
  { 3001, 1, 26, 1, 4313, 11 },
  { 3228, 1, 26, 1, 4314, 11 },
  { 3455, 1, 26, 1, 4315, 11 },
  { 3664, 1, 26, 1, 4316, 11 },
  { 59, 1, 26, 1, 4317, 11 },
  { 513, 1, 26, 1, 4318, 11 },
  { 1021, 1, 26, 1, 4319, 11 },
  { 1468, 1, 26, 1, 4320, 11 },
  { 1843, 1, 26, 1, 4321, 11 },
  { 2587, 1, 26, 1, 4322, 11 },
  { 2866, 1, 26, 1, 4323, 11 },
  { 3111, 1, 26, 1, 4324, 11 },
  { 3338, 1, 26, 1, 4325, 11 },
  { 3531, 1, 26, 1, 4326, 11 },
  { 131, 1, 26, 1, 4327, 11 },
  { 585, 1, 26, 1, 4328, 11 },
  { 1093, 1, 26, 1, 4329, 11 },
  { 1540, 1, 26, 1, 4330, 11 },
  { 1915, 1, 26, 1, 4331, 11 },
  { 2659, 1, 26, 1, 4332, 11 },
  { 2920, 1, 26, 1, 4333, 11 },
  { 3165, 1, 26, 1, 4334, 11 },
  { 3392, 1, 26, 1, 4335, 11 },
  { 3601, 1, 26, 1, 4336, 11 },
  { 204, 1, 26, 1, 4337, 11 },
  { 658, 1, 26, 1, 4338, 11 },
  { 2361, 18, 1, 0, 4110, 0 },
  { 312, 1, 111, 1, 4132, 11 },
  { 820, 1, 24, 1, 4134, 11 },
  { 1255, 1, 24, 1, 4136, 11 },
  { 1667, 1, 24, 1, 4138, 11 },
  { 423, 1, 1, 1, 4339, 11 },
  { 931, 1, 1, 1, 4340, 11 },
  { 1381, 1, 1, 1, 4341, 11 },
  { 1756, 1, 1, 1, 4342, 11 },
  { 2500, 1, 1, 1, 4343, 11 },
  { 2801, 1, 1, 1, 4344, 11 },
  { 3046, 1, 1, 1, 4345, 11 },
  { 3273, 1, 1, 1, 4346, 11 },
  { 3483, 1, 1, 1, 4347, 11 },
  { 3692, 1, 1, 1, 4348, 11 },
  { 90, 1, 1, 1, 4349, 11 },
  { 544, 1, 1, 1, 4350, 11 },
  { 1052, 1, 1, 1, 4351, 11 },
  { 1499, 1, 1, 1, 4352, 11 },
  { 1874, 1, 1, 1, 4353, 11 },
  { 2618, 1, 1, 1, 4354, 11 },
  { 2879, 1, 1, 1, 4355, 11 },
  { 3124, 1, 1, 1, 4356, 11 },
  { 3351, 1, 1, 1, 4357, 11 },
  { 3544, 1, 1, 1, 4358, 11 },
  { 150, 1, 1, 1, 4359, 11 },
  { 604, 1, 1, 1, 4360, 11 },
  { 1112, 1, 1, 1, 4361, 11 },
  { 1559, 1, 1, 1, 4362, 11 },
  { 1934, 1, 1, 1, 4363, 11 },
  { 2678, 1, 1, 1, 4364, 11 },
  { 2939, 1, 1, 1, 4365, 11 },
  { 3184, 1, 1, 1, 4366, 11 },
  { 3411, 1, 1, 1, 4367, 11 },
  { 3620, 1, 1, 1, 4368, 11 },
  { 223, 1, 1, 1, 4369, 11 },
  { 677, 1, 1, 1, 4370, 11 },
  { 322, 1, 197, 1, 4371, 11 },
  { 830, 1, 197, 1, 4372, 11 },
  { 394, 1, 107, 1, 4131, 11 },
  { 902, 1, 16, 1, 4133, 11 },
  { 1356, 1, 16, 1, 4135, 11 },
  { 1747, 1, 16, 1, 4137, 11 },
  { 325, 1, 1, 1, 4373, 11 },
  { 833, 1, 1, 1, 4374, 11 },
  { 1287, 1, 1, 1, 4375, 11 },
  { 3427, 1, 1, 1, 4376, 11 },
  { 3636, 1, 1, 1, 4377, 11 },
  { 27, 1, 1, 1, 4378, 11 },
  { 481, 1, 1, 1, 4379, 11 },
  { 989, 1, 1, 1, 4380, 11 },
  { 1436, 1, 1, 1, 4381, 11 },
  { 1811, 1, 1, 1, 4382, 11 },
  { 2555, 1, 1, 1, 4383, 11 },
  { 2856, 1, 1, 1, 4384, 11 },
  { 3101, 1, 1, 1, 4385, 11 },
  { 3328, 1, 1, 1, 4386, 11 },
  { 3521, 1, 1, 1, 4387, 11 },
  { 121, 1, 1, 1, 4388, 11 },
  { 575, 1, 1, 1, 4389, 11 },
  { 1083, 1, 1, 1, 4390, 11 },
  { 1530, 1, 1, 1, 4391, 11 },
  { 1905, 1, 1, 1, 4392, 11 },
  { 2649, 1, 1, 1, 4393, 11 },
  { 2910, 1, 1, 1, 4394, 11 },
  { 3155, 1, 1, 1, 4395, 11 },
  { 3382, 1, 1, 1, 4396, 11 },
  { 3591, 1, 1, 1, 4397, 11 },
  { 194, 1, 1, 1, 4398, 11 },
  { 648, 1, 1, 1, 4399, 11 },
  { 415, 1, 1, 1, 4400, 11 },
  { 923, 1, 1, 1, 4401, 11 },
  { 1373, 1, 1, 1, 4402, 11 },
  { 2341, 10, 1, 0, 4121, 0 },
  { 428, 1, 193, 1, 4403, 11 },
  { 936, 1, 193, 1, 4404, 11 },
  { 1386, 1, 193, 1, 4405, 11 },
  { 1761, 1, 193, 1, 4406, 11 },
  { 2505, 1, 193, 1, 4407, 11 },
  { 2806, 1, 193, 1, 4408, 11 },
  { 3051, 1, 193, 1, 4409, 11 },
  { 3278, 1, 193, 1, 4410, 11 },
  { 2367, 8, 1, 0, 4123, 0 },
  { 445, 1, 191, 1, 4411, 11 },
  { 953, 1, 191, 1, 4412, 11 },
  { 1403, 1, 191, 1, 4413, 11 },
  { 1778, 1, 191, 1, 4414, 11 },
  { 2522, 1, 191, 1, 4415, 11 },
  { 2823, 1, 191, 1, 4416, 11 },
  { 3068, 1, 191, 1, 4417, 11 },
  { 3295, 1, 191, 1, 4418, 11 },
  { 3488, 1, 191, 1, 4419, 11 },
  { 3697, 1, 191, 1, 4420, 11 },
  { 448, 1, 191, 1, 4421, 11 },
  { 956, 1, 191, 1, 4422, 11 },
  { 451, 183, 1, 8, 741515, 8 },
  { 959, 183, 1, 8, 741516, 8 },
  { 1406, 183, 1, 8, 741517, 8 },
  { 1781, 183, 1, 8, 741518, 8 },
  { 2525, 183, 1, 8, 741519, 8 },
  { 2826, 183, 1, 8, 741520, 8 },
  { 3071, 183, 1, 8, 741521, 8 },
  { 3298, 183, 1, 8, 741522, 8 },
  { 3491, 183, 1, 8, 741523, 8 },
  { 3700, 183, 1, 8, 741524, 8 },
  { 96, 183, 1, 8, 741525, 8 },
  { 550, 183, 1, 8, 741526, 8 },
  { 1058, 183, 1, 8, 741527, 8 },
  { 1505, 183, 1, 8, 741528, 8 },
  { 1880, 183, 1, 8, 741529, 8 },
  { 2624, 183, 1, 8, 741530, 8 },
  { 2885, 183, 1, 8, 741531, 8 },
  { 3130, 183, 1, 8, 741532, 8 },
  { 3357, 183, 1, 8, 741533, 8 },
  { 3550, 183, 1, 8, 741534, 8 },
  { 156, 183, 1, 8, 741535, 8 },
  { 610, 183, 1, 8, 741536, 8 },
  { 1118, 183, 1, 8, 741537, 8 },
  { 1565, 183, 1, 8, 741538, 8 },
  { 1940, 183, 1, 8, 741539, 8 },
  { 2684, 183, 1, 8, 741540, 8 },
  { 2945, 183, 1, 8, 741541, 8 },
  { 3190, 183, 1, 8, 741542, 8 },
  { 3417, 183, 1, 8, 741543, 8 },
  { 3626, 183, 1, 8, 741544, 8 },
  { 229, 183, 1, 8, 741545, 8 },
  { 683, 183, 1, 8, 741546, 8 },
  { 2347, 4, 1, 0, 4125, 0 },
  { 4548, 1, 1, 1, 4423, 11 },
  { 4572, 1, 1, 1, 4424, 11 },
  { 4596, 1, 1, 1, 4425, 11 },
  { 4614, 1, 1, 1, 4426, 11 },
  { 4632, 1, 1, 1, 4427, 11 },
  { 4650, 1, 1, 1, 4428, 11 },
  { 4668, 1, 1, 1, 4429, 11 },
  { 4680, 1, 1, 1, 4430, 11 },
  { 5108, 1, 1, 1, 4431, 11 },
  { 4863, 1, 1, 1, 4432, 11 },
  { 5210, 1, 1, 1, 4433, 11 },
  { 4912, 1, 1, 1, 4434, 11 },
  { 3721, 1, 1, 1, 4435, 11 },
  { 4956, 1, 1, 1, 4436, 11 },
  { 4069, 1, 1, 1, 4437, 11 },
  { 4019, 1, 1, 1, 4438, 11 },
  { 4036, 1, 1, 1, 4439, 11 },
  { 3989, 1, 1, 1, 4440, 11 },
  { 4158, 1, 1, 1, 4441, 11 },
  { 5180, 1, 1, 1, 4442, 11 },
  { 4136, 1, 1, 1, 4443, 11 },
  { 5047, 1, 1, 1, 4444, 11 },
  { 4194, 1, 1, 1, 4445, 11 },
  { 4775, 1, 1, 1, 4446, 11 },
  { 4173, 1, 1, 1, 4447, 11 },
  { 3896, 1, 1, 1, 4448, 11 },
  { 3789, 1, 1, 1, 4449, 11 },
  { 4083, 1, 1, 1, 4450, 11 },
  { 4226, 1, 1, 1, 4451, 11 },
  { 4807, 1, 1, 1, 4452, 11 },
  { 4005, 1, 1, 1, 4453, 11 },
  { 4256, 1, 1, 1, 4454, 11 },
  { 3819, 1, 1, 1, 4455, 11 },
  { 4489, 1, 1, 1, 4456, 11 },
  { 3802, 1, 1, 1, 4457, 11 },
  { 4929, 1, 1, 1, 4458, 11 },
  { 5015, 1, 1, 1, 4459, 11 },
  { 3703, 1, 1, 1, 4460, 11 },
  { 4210, 1, 1, 1, 4461, 11 },
  { 4791, 1, 1, 1, 4462, 11 },
  { 5196, 1, 1, 1, 4463, 11 },
  { 4519, 1, 1, 1, 4464, 11 },
  { 4241, 1, 1, 1, 4465, 11 },
  { 4822, 1, 1, 1, 4466, 11 },
  { 4897, 1, 1, 1, 4467, 11 },
  { 4884, 1, 1, 1, 4468, 11 },
  { 4272, 1, 1, 1, 4469, 11 },
  { 3863, 1, 1, 1, 4470, 11 },
  { 4417, 1, 1, 1, 4471, 11 },
  { 3771, 1, 1, 1, 4472, 11 },
  { 3831, 1, 1, 1, 4473, 11 },
  { 4757, 1, 1, 1, 4474, 11 },
  { 4327, 1, 1, 1, 4475, 11 },
  { 3883, 1, 1, 1, 4476, 11 },
  { 4054, 1, 1, 1, 4477, 11 },
  { 4534, 1, 1, 1, 4478, 11 },
  { 3919, 1, 1, 1, 4479, 11 },
  { 4098, 1, 1, 1, 4480, 11 },
  { 4742, 1, 1, 1, 4481, 11 },
  { 4504, 1, 1, 1, 4482, 11 },
  { 4842, 1, 1, 1, 4483, 11 },
  { 4997, 1, 1, 1, 4484, 11 },
  { 3935, 1, 1, 1, 4485, 11 },
  { 5145, 1, 1, 1, 4486, 11 },
  { 5032, 1, 1, 1, 4487, 11 },
  { 5061, 1, 1, 1, 4488, 11 },
  { 5090, 1, 1, 1, 4489, 11 },
  { 3950, 1, 1, 1, 4490, 11 },
  { 4286, 1, 1, 1, 4491, 11 },
  { 4980, 1, 1, 1, 4492, 11 },
  { 4377, 1, 1, 1, 4493, 11 },
  { 3735, 1, 1, 1, 4494, 11 },
  { 3753, 1, 1, 1, 4495, 11 },
  { 4359, 1, 1, 1, 4496, 11 },
  { 4472, 1, 1, 1, 4497, 11 },
  { 4454, 1, 1, 1, 4498, 11 },
  { 4436, 1, 1, 1, 4499, 11 },
  { 4398, 1, 1, 1, 4500, 11 },
  { 5075, 1, 1, 1, 4501, 11 },
  { 3969, 1, 1, 1, 4502, 11 },
  { 4306, 1, 1, 1, 4503, 11 },
  { 3849, 1, 1, 1, 4504, 11 },
  { 5163, 1, 1, 1, 4505, 11 },
  { 4113, 1, 1, 1, 4506, 11 },
  { 4344, 1, 1, 1, 4507, 11 },
  { 4554, 1, 1, 1, 4508, 11 },
  { 4578, 1, 1, 1, 4509, 11 },
  { 4560, 1, 1, 1, 4510, 11 },
  { 4584, 1, 1, 1, 4511, 11 },
  { 4602, 1, 1, 1, 4512, 11 },
  { 4620, 1, 1, 1, 4513, 11 },
  { 4638, 1, 1, 1, 4514, 11 },
  { 4656, 1, 1, 1, 4515, 11 },
  { 4674, 1, 1, 1, 4516, 11 },
  { 4686, 1, 1, 1, 4517, 11 },
  { 4566, 1, 1, 1, 4518, 11 },
  { 4590, 1, 1, 1, 4519, 11 },
  { 4608, 1, 1, 1, 4520, 11 },
  { 4626, 1, 1, 1, 4521, 11 },
  { 4644, 1, 1, 1, 4522, 11 },
  { 4662, 1, 1, 1, 4523, 11 },
  { 4692, 1, 1, 1, 4524, 11 },
  { 4698, 1, 1, 1, 4525, 11 },
  { 1971, 2, 1, 0, 4127, 0 },
  { 2049, 2, 1, 0, 4128, 0 },
  { 2099, 2, 1, 0, 4129, 0 },
  { 2137, 2, 1, 0, 4130, 0 },
  { 1977, 20, 1, 12, 507939, 8 },
  { 773, 1, 1, 1, 4526, 11 },
  { 1193, 1, 1, 1, 4527, 11 },
  { 1620, 1, 1, 1, 4528, 11 },
  { 2404, 1, 1, 1, 4529, 11 },
  { 2705, 1, 1, 1, 4530, 11 },
  { 1209, 1, 1, 1, 4531, 11 },
  { 398, 1, 1, 1, 4532, 11 },
  { 906, 1, 1, 1, 4533, 11 },
  { 363, 1, 1, 1, 4534, 11 },
  { 871, 1, 1, 1, 4535, 11 },
  { 1325, 1, 1, 1, 4536, 11 },
  { 1716, 1, 1, 1, 4537, 11 },
  { 789, 1, 1, 1, 4538, 11 },
  { 1224, 1, 1, 1, 4539, 11 },
  { 1636, 1, 1, 1, 4540, 11 },
  { 2420, 1, 1, 1, 4541, 11 },
  { 2721, 1, 1, 1, 4542, 11 },
  { 2966, 1, 1, 1, 4543, 11 },
  { 265, 1, 1, 1, 4544, 11 },
  { 739, 1, 1, 1, 4545, 11 },
  { 431, 1, 1, 1, 4546, 11 },
  { 939, 1, 1, 1, 4547, 11 },
  { 1389, 1, 1, 1, 4548, 11 },
  { 1764, 1, 1, 1, 4549, 11 },
  { 2508, 1, 1, 1, 4550, 11 },
  { 2809, 1, 1, 1, 4551, 11 },
  { 3054, 1, 1, 1, 4552, 11 },
  { 3281, 1, 1, 1, 4553, 11 },
  { 330, 1, 1, 1, 4554, 11 },
  { 838, 1, 1, 1, 4555, 11 },
  { 1292, 1, 1, 1, 4556, 11 },
  { 1699, 1, 1, 1, 4557, 11 },
  { 2461, 1, 1, 1, 4558, 11 },
  { 2762, 1, 1, 1, 4559, 11 },
  { 3007, 1, 1, 1, 4560, 11 },
  { 3234, 1, 1, 1, 4561, 11 },
  { 347, 1, 1, 1, 4562, 11 },
  { 855, 1, 1, 1, 4563, 11 },
  { 1309, 1, 1, 1, 4564, 11 },
  { 282, 1, 1, 1, 4565, 11 },
  { 756, 1, 1, 1, 4566, 11 },
  { 1176, 1, 1, 1, 4567, 11 },
  { 1603, 1, 1, 1, 4568, 11 },
  { 2387, 1, 1, 1, 4569, 11 },
  { 1360, 1, 1, 1, 4570, 11 },
  { 1265, 1, 1, 1, 4571, 11 },
  { 1677, 1, 1, 1, 4572, 11 },
  { 687, 1, 1, 1, 4573, 11 },
  { 1141, 1, 1, 1, 4574, 11 },
  { 248, 1, 1, 1, 4575, 11 },
  { 722, 1, 1, 1, 4576, 11 },
  { 299, 1, 1, 1, 4577, 11 },
  { 807, 1, 1, 1, 4578, 11 },
  { 1242, 1, 1, 1, 4579, 11 },
  { 1654, 1, 1, 1, 4580, 11 },
  { 2438, 1, 1, 1, 4581, 11 },
  { 2739, 1, 1, 1, 4582, 11 },
  { 2984, 1, 1, 1, 4583, 11 },
  { 3211, 1, 1, 1, 4584, 11 },
  { 3438, 1, 1, 1, 4585, 11 },
  { 3647, 1, 1, 1, 4586, 11 },
  { 41, 1, 1, 1, 4587, 11 },
  { 495, 1, 1, 1, 4588, 11 },
  { 1003, 1, 1, 1, 4589, 11 },
  { 1450, 1, 1, 1, 4590, 11 },
  { 1825, 1, 1, 1, 4591, 11 },
  { 2569, 1, 1, 1, 4592, 11 },
  { 381, 1, 1, 1, 4593, 11 },
  { 889, 1, 1, 1, 4594, 11 },
  { 1343, 1, 1, 1, 4595, 11 },
  { 1734, 1, 1, 1, 4596, 11 },
  { 2478, 1, 1, 1, 4597, 11 },
  { 2779, 1, 1, 1, 4598, 11 },
  { 3024, 1, 1, 1, 4599, 11 },
  { 3251, 1, 1, 1, 4600, 11 },
  { 3461, 1, 1, 1, 4601, 11 },
  { 3670, 1, 1, 1, 4602, 11 },
  { 66, 1, 1, 1, 4603, 11 },
  { 520, 1, 1, 1, 4604, 11 },
  { 1028, 1, 1, 1, 4605, 11 },
  { 1475, 1, 1, 1, 4606, 11 },
  { 1850, 1, 1, 1, 4607, 11 },
  { 2594, 1, 1, 1, 4608, 11 },
  { 1984, 184, 27, 9, 741515, 8 },
  { 2055, 184, 27, 9, 741516, 8 },
  { 2105, 184, 27, 9, 741517, 8 },
  { 2143, 184, 27, 9, 741518, 8 },
  { 2175, 184, 27, 9, 741519, 8 },
  { 2207, 184, 27, 9, 741520, 8 },
  { 2239, 184, 27, 9, 741521, 8 },
  { 2271, 184, 27, 9, 741522, 8 },
  { 2303, 184, 27, 9, 741523, 8 },
  { 2329, 184, 27, 9, 741524, 8 },
  { 1950, 184, 27, 9, 741525, 8 },
  { 2028, 184, 27, 9, 741526, 8 },
  { 2085, 184, 27, 9, 741527, 8 },
  { 2123, 184, 27, 9, 741528, 8 },
  { 2161, 184, 27, 9, 741529, 8 },
  { 2193, 184, 27, 9, 741530, 8 },
  { 2225, 184, 27, 9, 741531, 8 },
  { 2257, 184, 27, 9, 741532, 8 },
  { 2289, 184, 27, 9, 741533, 8 },
  { 2315, 184, 27, 9, 741534, 8 },
  { 1957, 184, 27, 9, 741535, 8 },
  { 2035, 184, 27, 9, 741536, 8 },
  { 2092, 184, 27, 9, 741537, 8 },
  { 2130, 184, 27, 9, 741538, 8 },
  { 2168, 184, 27, 9, 741539, 8 },
  { 2200, 184, 27, 9, 741540, 8 },
  { 2232, 184, 27, 9, 741541, 8 },
  { 2264, 184, 27, 9, 741542, 8 },
  { 2296, 184, 27, 9, 741543, 8 },
  { 2322, 184, 27, 9, 741544, 8 },
  { 1964, 184, 27, 9, 741545, 8 },
  { 2042, 184, 27, 9, 741546, 8 },
  { 3554, 1, 0, 1, 4101, 11 },
  { 1990, 6, 113, 0, 4132, 0 },
  { 1997, 8, 1, 0, 4371, 0 },
  { 2061, 8, 1, 0, 4372, 0 },
  { 2003, 8, 109, 0, 4131, 0 },
  { 2010, 12, 1, 0, 4403, 0 },
  { 2067, 12, 1, 0, 4404, 0 },
  { 2111, 12, 1, 0, 4405, 0 },
  { 2149, 12, 1, 0, 4406, 0 },
  { 2181, 12, 1, 0, 4407, 0 },
  { 2213, 12, 1, 0, 4408, 0 },
  { 2245, 12, 1, 0, 4409, 0 },
  { 2277, 12, 1, 0, 4410, 0 },
  { 2016, 14, 1, 0, 4411, 0 },
  { 2073, 14, 1, 0, 4412, 0 },
  { 2117, 14, 1, 0, 4413, 0 },
  { 2155, 14, 1, 0, 4414, 0 },
  { 2187, 14, 1, 0, 4415, 0 },
  { 2219, 14, 1, 0, 4416, 0 },
  { 2251, 14, 1, 0, 4417, 0 },
  { 2283, 14, 1, 0, 4418, 0 },
  { 2309, 14, 1, 0, 4419, 0 },
  { 2335, 14, 1, 0, 4420, 0 },
  { 2022, 14, 1, 0, 4421, 0 },
  { 2079, 14, 1, 0, 4422, 0 },
  { 5124, 1, 1, 1, 4609, 11 },
};

  // MSA128F16 Register Class...
  static const MCPhysReg MSA128F16[] = {
    Mips_W0, Mips_W1, Mips_W2, Mips_W3, Mips_W4, Mips_W5, Mips_W6, Mips_W7, Mips_W8, Mips_W9, Mips_W10, Mips_W11, Mips_W12, Mips_W13, Mips_W14, Mips_W15, Mips_W16, Mips_W17, Mips_W18, Mips_W19, Mips_W20, Mips_W21, Mips_W22, Mips_W23, Mips_W24, Mips_W25, Mips_W26, Mips_W27, Mips_W28, Mips_W29, Mips_W30, Mips_W31, 
  };

  // MSA128F16 Bit set.
  static const uint8_t MSA128F16Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01, 
  };

  // COP0Sel Register Class...
  static const MCPhysReg COP0Sel[] = {
    Mips_COP0Sel_INDEX, Mips_COP0Sel_MVPCONTROL, Mips_COP0Sel_MVPCONF0, Mips_COP0Sel_MVPCONF1, Mips_COP0Sel_VPCONTROL, Mips_COP0Sel_RANDOM, Mips_COP0Sel_VPECONTROL, Mips_COP0Sel_VPECONF0, Mips_COP0Sel_VPECONF1, Mips_COP0Sel_YQMASK, Mips_COP0Sel_VPESCHEDULE, Mips_COP0Sel_VPESCHEFBACK, Mips_COP0Sel_VPEOPT, Mips_COP0Sel_ENTRYLO0, Mips_COP0Sel_TCSTATUS, Mips_COP0Sel_TCBIND, Mips_COP0Sel_TCRESTART, Mips_COP0Sel_TCHALT, Mips_COP0Sel_TCCONTEXT, Mips_COP0Sel_TCSCHEDULE, Mips_COP0Sel_TCSCHEFBACK, Mips_COP0Sel_ENTRYLO1, Mips_COP0Sel_GLOBALNUMBER, Mips_COP0Sel_TCOPT, Mips_COP0Sel_CONTEXT, Mips_COP0Sel_CONTEXTCONFIG, Mips_COP0Sel_USERLOCAL, Mips_COP0Sel_XCONTEXTCONFIG, Mips_COP0Sel_DEBUGCONTEXTID, Mips_COP0Sel_MEMORYMAPID, Mips_COP0Sel_PAGEMASK, Mips_COP0Sel_PAGEGRAIN, Mips_COP0Sel_SEGCTL0, Mips_COP0Sel_SEGCTL1, Mips_COP0Sel_SEGCTL2, Mips_COP0Sel_PWBASE, Mips_COP0Sel_PWFIELD, Mips_COP0Sel_PWSIZE, Mips_COP0Sel_WIRED, Mips_COP0Sel_SRSCONF0, Mips_COP0Sel_SRSCONF1, Mips_COP0Sel_SRSCONF2, Mips_COP0Sel_SRSCONF3, Mips_COP0Sel_SRSCONF4, Mips_COP0Sel_PWCTL, Mips_COP0Sel_HWRENA, Mips_COP0Sel_BADVADDR, Mips_COP0Sel_BADINST, Mips_COP0Sel_BADINSTRP, Mips_COP0Sel_BADINSTRX, Mips_COP0Sel_COUNT, Mips_COP0Sel_ENTRYHI, Mips_COP0Sel_GUESTCTL1, Mips_COP0Sel_GUESTCTL2, Mips_COP0Sel_GUESTCTL3, Mips_COP0Sel_COMPARE, Mips_COP0Sel_GUESTCTL0EXT, Mips_COP0Sel_STATUS, Mips_COP0Sel_INTCTL, Mips_COP0Sel_SRSCTL, Mips_COP0Sel_SRSMAP, Mips_COP0Sel_VIEW_IPL, Mips_COP0Sel_SRSMAP2, Mips_COP0Sel_GUESTCTL0, Mips_COP0Sel_GTOFFSET, Mips_COP0Sel_CAUSE, Mips_COP0Sel_VIEW_RIPL, Mips_COP0Sel_NESTEDEXC, Mips_COP0Sel_EPC, Mips_COP0Sel_NESTEDEPC, Mips_COP0Sel_PRID, Mips_COP0Sel_EBASE, Mips_COP0Sel_CDMMBASE, Mips_COP0Sel_CMGCRBASE, Mips_COP0Sel_BEVVA, Mips_COP0Sel_CONFIG, Mips_COP0Sel_CONFIG1, Mips_COP0Sel_CONFIG2, Mips_COP0Sel_CONFIG3, Mips_COP0Sel_CONFIG4, Mips_COP0Sel_CONFIG5, Mips_COP0Sel_LLADDR, Mips_COP0Sel_MAAR, Mips_COP0Sel_MAARI, Mips_COP0Sel_WATCHLO0, Mips_COP0Sel_WATCHLO1, Mips_COP0Sel_WATCHLO2, Mips_COP0Sel_WATCHLO3, Mips_COP0Sel_WATCHLO4, Mips_COP0Sel_WATCHLO5, Mips_COP0Sel_WATCHLO6, Mips_COP0Sel_WATCHLO7, Mips_COP0Sel_WATCHLO8, Mips_COP0Sel_WATCHLO9, Mips_COP0Sel_WATCHLO10, Mips_COP0Sel_WATCHLO11, Mips_COP0Sel_WATCHLO12, Mips_COP0Sel_WATCHLO13, Mips_COP0Sel_WATCHLO14, Mips_COP0Sel_WATCHLO15, Mips_COP0Sel_WATCHHI0, Mips_COP0Sel_WATCHHI1, Mips_COP0Sel_WATCHHI2, Mips_COP0Sel_WATCHHI3, Mips_COP0Sel_WATCHHI4, Mips_COP0Sel_WATCHHI5, Mips_COP0Sel_WATCHHI6, Mips_COP0Sel_WATCHHI7, Mips_COP0Sel_WATCHHI8, Mips_COP0Sel_WATCHHI9, Mips_COP0Sel_WATCHHI10, Mips_COP0Sel_WATCHHI11, Mips_COP0Sel_WATCHHI12, Mips_COP0Sel_WATCHHI13, Mips_COP0Sel_WATCHHI14, Mips_COP0Sel_WATCHHI15, Mips_COP0Sel_XCONTEXT, Mips_COP0Sel_DEBUG, Mips_COP0Sel_TRACECONTROL, Mips_COP0Sel_TRACECONTROL2, Mips_COP0Sel_USERTRACEDATA1, Mips_COP0Sel_TRACEIBPC, Mips_COP0Sel_TRACEDBPC, Mips_COP0Sel_DEBUG2, Mips_COP0Sel_DEPC, Mips_COP0Sel_TRACECONTROL3, Mips_COP0Sel_USERTRACEDATA2, Mips_COP0Sel_PERFCTL0, Mips_COP0Sel_PERFCNT0, Mips_COP0Sel_PERFCTL1, Mips_COP0Sel_PERFCNT1, Mips_COP0Sel_PERFCTL2, Mips_COP0Sel_PERFCNT2, Mips_COP0Sel_PERFCTL3, Mips_COP0Sel_PERFCNT3, Mips_COP0Sel_PERFCTL4, Mips_COP0Sel_PERFCNT4, Mips_COP0Sel_PERFCTL5, Mips_COP0Sel_PERFCNT5, Mips_COP0Sel_PERFCTL6, Mips_COP0Sel_PERFCNT6, Mips_COP0Sel_PERFCTL7, Mips_COP0Sel_PERFCNT7, Mips_COP0Sel_ERRCTL, Mips_COP0Sel_CACHEERR, Mips_COP0Sel_ITAGLO, Mips_COP0Sel_IDATALO, Mips_COP0Sel_DTAGLO, Mips_COP0Sel_DDATALO, Mips_COP0Sel_ITAGHI, Mips_COP0Sel_IDATAHI, Mips_COP0Sel_DTAGHI, Mips_COP0Sel_DDATAHI, Mips_COP0Sel_ERROREPC, Mips_COP0Sel_DESAVE, Mips_COP0Sel_KSCRATCH1, Mips_COP0Sel_KSCRATCH2, Mips_COP0Sel_KSCRATCH3, Mips_COP0Sel_KSCRATCH4, Mips_COP0Sel_KSCRATCH5, Mips_COP0Sel_KSCRATCH6, 
  };

  // COP0Sel Bit set.
  static const uint8_t COP0SelBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 
  };

  // CCR Register Class...
  static const MCPhysReg CCR[] = {
    Mips_FCR0, Mips_FCR1, Mips_FCR2, Mips_FCR3, Mips_FCR4, Mips_FCR5, Mips_FCR6, Mips_FCR7, Mips_FCR8, Mips_FCR9, Mips_FCR10, Mips_FCR11, Mips_FCR12, Mips_FCR13, Mips_FCR14, Mips_FCR15, Mips_FCR16, Mips_FCR17, Mips_FCR18, Mips_FCR19, Mips_FCR20, Mips_FCR21, Mips_FCR22, Mips_FCR23, Mips_FCR24, Mips_FCR25, Mips_FCR26, Mips_FCR27, Mips_FCR28, Mips_FCR29, Mips_FCR30, Mips_FCR31, 
  };

  // CCR Bit set.
  static const uint8_t CCRBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01, 
  };

  // COP0 Register Class...
  static const MCPhysReg COP0[] = {
    Mips_COP00, Mips_COP01, Mips_COP02, Mips_COP03, Mips_COP04, Mips_COP05, Mips_COP06, Mips_COP07, Mips_COP08, Mips_COP09, Mips_COP010, Mips_COP011, Mips_COP012, Mips_COP013, Mips_COP014, Mips_COP015, Mips_COP016, Mips_COP017, Mips_COP018, Mips_COP019, Mips_COP020, Mips_COP021, Mips_COP022, Mips_COP023, Mips_COP024, Mips_COP025, Mips_COP026, Mips_COP027, Mips_COP028, Mips_COP029, Mips_COP030, Mips_COP031, 
  };

  // COP0 Bit set.
  static const uint8_t COP0Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0xe0, 0x7f, 0x00, 0x00, 0xf8, 0xff, 0xff, 0x01, 
  };

  // COP2 Register Class...
  static const MCPhysReg COP2[] = {
    Mips_COP20, Mips_COP21, Mips_COP22, Mips_COP23, Mips_COP24, Mips_COP25, Mips_COP26, Mips_COP27, Mips_COP28, Mips_COP29, Mips_COP210, Mips_COP211, Mips_COP212, Mips_COP213, Mips_COP214, Mips_COP215, Mips_COP216, Mips_COP217, Mips_COP218, Mips_COP219, Mips_COP220, Mips_COP221, Mips_COP222, Mips_COP223, Mips_COP224, Mips_COP225, Mips_COP226, Mips_COP227, Mips_COP228, Mips_COP229, Mips_COP230, Mips_COP231, 
  };

  // COP2 Bit set.
  static const uint8_t COP2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0x01, 0x00, 0x00, 0x00, 0xfe, 0xff, 0x7f, 
  };

  // COP3 Register Class...
  static const MCPhysReg COP3[] = {
    Mips_COP30, Mips_COP31, Mips_COP32, Mips_COP33, Mips_COP34, Mips_COP35, Mips_COP36, Mips_COP37, Mips_COP38, Mips_COP39, Mips_COP310, Mips_COP311, Mips_COP312, Mips_COP313, Mips_COP314, Mips_COP315, Mips_COP316, Mips_COP317, Mips_COP318, Mips_COP319, Mips_COP320, Mips_COP321, Mips_COP322, Mips_COP323, Mips_COP324, Mips_COP325, Mips_COP326, Mips_COP327, Mips_COP328, Mips_COP329, Mips_COP330, Mips_COP331, 
  };

  // COP3 Bit set.
  static const uint8_t COP3Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x07, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0x1f, 
  };

  // DSPR Register Class...
  static const MCPhysReg DSPR[] = {
    Mips_ZERO, Mips_AT, Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, Mips_T0, Mips_T1, Mips_T2, Mips_T3, Mips_T4, Mips_T5, Mips_T6, Mips_T7, Mips_S0, Mips_S1, Mips_S2, Mips_S3, Mips_S4, Mips_S5, Mips_S6, Mips_S7, Mips_T8, Mips_T9, Mips_K0, Mips_K1, Mips_GP, Mips_SP, Mips_FP, Mips_RA, 
  };

  // DSPR Bit set.
  static const uint8_t DSPRBits[] = {
    0x02, 0x0a, 0x40, 0xf5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0xf0, 0xef, 0xff, 0x01, 
  };

  // FGR32 Register Class...
  static const MCPhysReg FGR32[] = {
    Mips_F0, Mips_F1, Mips_F2, Mips_F3, Mips_F4, Mips_F5, Mips_F6, Mips_F7, Mips_F8, Mips_F9, Mips_F10, Mips_F11, Mips_F12, Mips_F13, Mips_F14, Mips_F15, Mips_F16, Mips_F17, Mips_F18, Mips_F19, Mips_F20, Mips_F21, Mips_F22, Mips_F23, Mips_F24, Mips_F25, Mips_F26, Mips_F27, Mips_F28, Mips_F29, Mips_F30, Mips_F31, 
  };

  // FGR32 Bit set.
  static const uint8_t FGR32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01, 
  };

  // FGRCC Register Class...
  static const MCPhysReg FGRCC[] = {
    Mips_F0, Mips_F1, Mips_F2, Mips_F3, Mips_F4, Mips_F5, Mips_F6, Mips_F7, Mips_F8, Mips_F9, Mips_F10, Mips_F11, Mips_F12, Mips_F13, Mips_F14, Mips_F15, Mips_F16, Mips_F17, Mips_F18, Mips_F19, Mips_F20, Mips_F21, Mips_F22, Mips_F23, Mips_F24, Mips_F25, Mips_F26, Mips_F27, Mips_F28, Mips_F29, Mips_F30, Mips_F31, 
  };

  // FGRCC Bit set.
  static const uint8_t FGRCCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01, 
  };

  // GPR32 Register Class...
  static const MCPhysReg GPR32[] = {
    Mips_ZERO, Mips_AT, Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, Mips_T0, Mips_T1, Mips_T2, Mips_T3, Mips_T4, Mips_T5, Mips_T6, Mips_T7, Mips_S0, Mips_S1, Mips_S2, Mips_S3, Mips_S4, Mips_S5, Mips_S6, Mips_S7, Mips_T8, Mips_T9, Mips_K0, Mips_K1, Mips_GP, Mips_SP, Mips_FP, Mips_RA, 
  };

  // GPR32 Bit set.
  static const uint8_t GPR32Bits[] = {
    0x02, 0x0a, 0x40, 0xf5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0xf0, 0xef, 0xff, 0x01, 
  };

  // GPRNM32 Register Class...
  static const MCPhysReg GPRNM32[] = {
    Mips_ZERO_NM, Mips_AT_NM, Mips_T4_NM, Mips_T5_NM, Mips_A0_NM, Mips_A1_NM, Mips_A2_NM, Mips_A3_NM, Mips_A4_NM, Mips_A5_NM, Mips_A6_NM, Mips_A7_NM, Mips_T0_NM, Mips_T1_NM, Mips_T2_NM, Mips_T3_NM, Mips_S0_NM, Mips_S1_NM, Mips_S2_NM, Mips_S3_NM, Mips_S4_NM, Mips_S5_NM, Mips_S6_NM, Mips_S7_NM, Mips_T8_NM, Mips_T9_NM, Mips_K0_NM, Mips_K1_NM, Mips_GP_NM, Mips_SP_NM, Mips_FP_NM, Mips_RA_NM, 
  };

  // GPRNM32 Bit set.
  static const uint8_t GPRNM32Bits[] = {
    0x04, 0x14, 0x80, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0x01, 
  };

  // HWRegs Register Class...
  static const MCPhysReg HWRegs[] = {
    Mips_HWR0, Mips_HWR1, Mips_HWR2, Mips_HWR3, Mips_HWR4, Mips_HWR5, Mips_HWR6, Mips_HWR7, Mips_HWR8, Mips_HWR9, Mips_HWR10, Mips_HWR11, Mips_HWR12, Mips_HWR13, Mips_HWR14, Mips_HWR15, Mips_HWR16, Mips_HWR17, Mips_HWR18, Mips_HWR19, Mips_HWR20, Mips_HWR21, Mips_HWR22, Mips_HWR23, Mips_HWR24, Mips_HWR25, Mips_HWR26, Mips_HWR27, Mips_HWR28, Mips_HWR29, Mips_HWR30, Mips_HWR31, 
  };

  // HWRegs Bit set.
  static const uint8_t HWRegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0xff, 0x7f, 
  };

  // MSACtrl Register Class...
  static const MCPhysReg MSACtrl[] = {
    Mips_MSAIR, Mips_MSACSR, Mips_MSAAccess, Mips_MSASave, Mips_MSAModify, Mips_MSARequest, Mips_MSAMap, Mips_MSAUnmap, Mips_MSA8, Mips_MSA9, Mips_MSA10, Mips_MSA11, Mips_MSA12, Mips_MSA13, Mips_MSA14, Mips_MSA15, Mips_MSA16, Mips_MSA17, Mips_MSA18, Mips_MSA19, Mips_MSA20, Mips_MSA21, Mips_MSA22, Mips_MSA23, Mips_MSA24, Mips_MSA25, Mips_MSA26, Mips_MSA27, Mips_MSA28, Mips_MSA29, Mips_MSA30, Mips_MSA31, 
  };

  // MSACtrl Bit set.
  static const uint8_t MSACtrlBits[] = {
    0x00, 0xe0, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 
  };

  // GPR32NONZERO Register Class...
  static const MCPhysReg GPR32NONZERO[] = {
    Mips_AT, Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, Mips_T0, Mips_T1, Mips_T2, Mips_T3, Mips_T4, Mips_T5, Mips_T6, Mips_T7, Mips_S0, Mips_S1, Mips_S2, Mips_S3, Mips_S4, Mips_S5, Mips_S6, Mips_S7, Mips_T8, Mips_T9, Mips_K0, Mips_K1, Mips_GP, Mips_SP, Mips_FP, Mips_RA, 
  };

  // GPR32NONZERO Bit set.
  static const uint8_t GPR32NONZEROBits[] = {
    0x02, 0x0a, 0x40, 0xf1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0xf0, 0xef, 0xff, 0x01, 
  };

  // GPRNM32NZ Register Class...
  static const MCPhysReg GPRNM32NZ[] = {
    Mips_AT_NM, Mips_T4_NM, Mips_T5_NM, Mips_A0_NM, Mips_A1_NM, Mips_A2_NM, Mips_A3_NM, Mips_A4_NM, Mips_A5_NM, Mips_A6_NM, Mips_A7_NM, Mips_T0_NM, Mips_T1_NM, Mips_T2_NM, Mips_T3_NM, Mips_S0_NM, Mips_S1_NM, Mips_S2_NM, Mips_S3_NM, Mips_S4_NM, Mips_S5_NM, Mips_S6_NM, Mips_S7_NM, Mips_T8_NM, Mips_T9_NM, Mips_K0_NM, Mips_K1_NM, Mips_GP_NM, Mips_SP_NM, Mips_FP_NM, Mips_RA_NM, 
  };

  // GPRNM32NZ Bit set.
  static const uint8_t GPRNM32NZBits[] = {
    0x04, 0x14, 0x80, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0x01, 
  };

  // GPRNM32_TAIL Register Class...
  static const MCPhysReg GPRNM32_TAIL[] = {
    Mips_T4_NM, Mips_T5_NM, Mips_A0_NM, Mips_A1_NM, Mips_A2_NM, Mips_A3_NM, Mips_A4_NM, Mips_A5_NM, Mips_A6_NM, Mips_A7_NM, Mips_T0_NM, Mips_T1_NM, Mips_T2_NM, Mips_T3_NM, Mips_T8_NM, Mips_T9_NM, 
  };

  // GPRNM32_TAIL Bit set.
  static const uint8_t GPRNM32_TAILBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x01, 
  };

  // GPRNM4 Register Class...
  static const MCPhysReg GPRNM4[] = {
    Mips_A4_NM, Mips_A5_NM, Mips_A6_NM, Mips_A7_NM, Mips_A0_NM, Mips_A1_NM, Mips_A2_NM, Mips_A3_NM, Mips_S0_NM, Mips_S1_NM, Mips_S2_NM, Mips_S3_NM, Mips_S4_NM, Mips_S5_NM, Mips_S6_NM, Mips_S7_NM, 
  };

  // GPRNM4 Bit set.
  static const uint8_t GPRNM4Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x01, 
  };

  // GPRNM4Z Register Class...
  static const MCPhysReg GPRNM4Z[] = {
    Mips_A4_NM, Mips_A5_NM, Mips_A6_NM, Mips_ZERO_NM, Mips_A0_NM, Mips_A1_NM, Mips_A2_NM, Mips_A3_NM, Mips_S0_NM, Mips_S1_NM, Mips_S2_NM, Mips_S3_NM, Mips_S4_NM, Mips_S5_NM, Mips_S6_NM, Mips_S7_NM, 
  };

  // GPRNM4Z Bit set.
  static const uint8_t GPRNM4ZBits[] = {
    0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x01, 
  };

  // GPRNM4_and_GPRNM4Z Register Class...
  static const MCPhysReg GPRNM4_and_GPRNM4Z[] = {
    Mips_A4_NM, Mips_A5_NM, Mips_A6_NM, Mips_A0_NM, Mips_A1_NM, Mips_A2_NM, Mips_A3_NM, Mips_S0_NM, Mips_S1_NM, Mips_S2_NM, Mips_S3_NM, Mips_S4_NM, Mips_S5_NM, Mips_S6_NM, Mips_S7_NM, 
  };

  // GPRNM4_and_GPRNM4Z Bit set.
  static const uint8_t GPRNM4_and_GPRNM4ZBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x01, 
  };

  // CPU16RegsPlusSP Register Class...
  static const MCPhysReg CPU16RegsPlusSP[] = {
    Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, Mips_S0, Mips_S1, Mips_SP, 
  };

  // CPU16RegsPlusSP Bit set.
  static const uint8_t CPU16RegsPlusSPBits[] = {
    0x00, 0x00, 0x00, 0xf1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x80, 0x01, 
  };

  // CPU16Regs Register Class...
  static const MCPhysReg CPU16Regs[] = {
    Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, Mips_S0, Mips_S1, 
  };

  // CPU16Regs Bit set.
  static const uint8_t CPU16RegsBits[] = {
    0x00, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x80, 0x01, 
  };

  // FCC Register Class...
  static const MCPhysReg FCC[] = {
    Mips_FCC0, Mips_FCC1, Mips_FCC2, Mips_FCC3, Mips_FCC4, Mips_FCC5, Mips_FCC6, Mips_FCC7, 
  };

  // FCC Bit set.
  static const uint8_t FCCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x01, 
  };

  // GPRMM16 Register Class...
  static const MCPhysReg GPRMM16[] = {
    Mips_S0, Mips_S1, Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, 
  };

  // GPRMM16 Bit set.
  static const uint8_t GPRMM16Bits[] = {
    0x00, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x80, 0x01, 
  };

  // GPRMM16MoveP Register Class...
  static const MCPhysReg GPRMM16MoveP[] = {
    Mips_ZERO, Mips_S1, Mips_V0, Mips_V1, Mips_S0, Mips_S2, Mips_S3, Mips_S4, 
  };

  // GPRMM16MoveP Bit set.
  static const uint8_t GPRMM16MovePBits[] = {
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x01, 0x80, 0x01, 
  };

  // GPRMM16Zero Register Class...
  static const MCPhysReg GPRMM16Zero[] = {
    Mips_ZERO, Mips_S1, Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, 
  };

  // GPRMM16Zero Bit set.
  static const uint8_t GPRMM16ZeroBits[] = {
    0x00, 0x00, 0x00, 0xf4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x80, 0x01, 
  };

  // GPRNM3 Register Class...
  static const MCPhysReg GPRNM3[] = {
    Mips_S0_NM, Mips_S1_NM, Mips_S2_NM, Mips_S3_NM, Mips_A0_NM, Mips_A1_NM, Mips_A2_NM, Mips_A3_NM, 
  };

  // GPRNM3 Bit set.
  static const uint8_t GPRNM3Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 
  };

  // GPRNM3Z Register Class...
  static const MCPhysReg GPRNM3Z[] = {
    Mips_ZERO_NM, Mips_S1_NM, Mips_S2_NM, Mips_S3_NM, Mips_A0_NM, Mips_A1_NM, Mips_A2_NM, Mips_A3_NM, 
  };

  // GPRNM3Z Bit set.
  static const uint8_t GPRNM3ZBits[] = {
    0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 
  };

  // GPRNM4_and_GPRNM32_TAIL Register Class...
  static const MCPhysReg GPRNM4_and_GPRNM32_TAIL[] = {
    Mips_A4_NM, Mips_A5_NM, Mips_A6_NM, Mips_A7_NM, Mips_A0_NM, Mips_A1_NM, Mips_A2_NM, Mips_A3_NM, 
  };

  // GPRNM4_and_GPRNM32_TAIL Bit set.
  static const uint8_t GPRNM4_and_GPRNM32_TAILBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 
  };

  // CPU16Regs_and_GPRMM16Zero Register Class...
  static const MCPhysReg CPU16Regs_and_GPRMM16Zero[] = {
    Mips_S1, Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, 
  };

  // CPU16Regs_and_GPRMM16Zero Bit set.
  static const uint8_t CPU16Regs_and_GPRMM16ZeroBits[] = {
    0x00, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x80, 0x01, 
  };

  // GPR32NONZERO_and_GPRMM16MoveP Register Class...
  static const MCPhysReg GPR32NONZERO_and_GPRMM16MoveP[] = {
    Mips_S1, Mips_V0, Mips_V1, Mips_S0, Mips_S2, Mips_S3, Mips_S4, 
  };

  // GPR32NONZERO_and_GPRMM16MoveP Bit set.
  static const uint8_t GPR32NONZERO_and_GPRMM16MovePBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x01, 0x80, 0x01, 
  };

  // GPRNM3_and_GPRNM3Z Register Class...
  static const MCPhysReg GPRNM3_and_GPRNM3Z[] = {
    Mips_S1_NM, Mips_S2_NM, Mips_S3_NM, Mips_A0_NM, Mips_A1_NM, Mips_A2_NM, Mips_A3_NM, 
  };

  // GPRNM3_and_GPRNM3Z Bit set.
  static const uint8_t GPRNM3_and_GPRNM3ZBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 
  };

  // GPRNM4Z_and_GPRNM32_TAIL Register Class...
  static const MCPhysReg GPRNM4Z_and_GPRNM32_TAIL[] = {
    Mips_A4_NM, Mips_A5_NM, Mips_A6_NM, Mips_A0_NM, Mips_A1_NM, Mips_A2_NM, Mips_A3_NM, 
  };

  // GPRNM4Z_and_GPRNM32_TAIL Bit set.
  static const uint8_t GPRNM4Z_and_GPRNM32_TAILBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x01, 
  };

  // GPRMM16MovePPairSecond Register Class...
  static const MCPhysReg GPRMM16MovePPairSecond[] = {
    Mips_A1, Mips_A2, Mips_A3, Mips_S5, Mips_S6, 
  };

  // GPRMM16MovePPairSecond Bit set.
  static const uint8_t GPRMM16MovePPairSecondBits[] = {
    0x00, 0x00, 0x00, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 
  };

  // CPU16Regs_and_GPRMM16MoveP Register Class...
  static const MCPhysReg CPU16Regs_and_GPRMM16MoveP[] = {
    Mips_S1, Mips_V0, Mips_V1, Mips_S0, 
  };

  // CPU16Regs_and_GPRMM16MoveP Bit set.
  static const uint8_t CPU16Regs_and_GPRMM16MovePBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x80, 0x01, 
  };

  // GPRMM16MoveP_and_GPRMM16Zero Register Class...
  static const MCPhysReg GPRMM16MoveP_and_GPRMM16Zero[] = {
    Mips_ZERO, Mips_S1, Mips_V0, Mips_V1, 
  };

  // GPRMM16MoveP_and_GPRMM16Zero Bit set.
  static const uint8_t GPRMM16MoveP_and_GPRMM16ZeroBits[] = {
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x80, 0x01, 
  };

  // GPRNM2R1 Register Class...
  static const MCPhysReg GPRNM2R1[] = {
    Mips_A0_NM, Mips_A1_NM, Mips_A2_NM, Mips_A3_NM, 
  };

  // GPRNM2R1 Bit set.
  static const uint8_t GPRNM2R1Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c, 
  };

  // GPRNM2R2 Register Class...
  static const MCPhysReg GPRNM2R2[] = {
    Mips_A1_NM, Mips_A2_NM, Mips_A3_NM, Mips_A4_NM, 
  };

  // GPRNM2R2 Bit set.
  static const uint8_t GPRNM2R2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 
  };

  // HI32DSP Register Class...
  static const MCPhysReg HI32DSP[] = {
    Mips_HI0, Mips_HI1, Mips_HI2, Mips_HI3, 
  };

  // HI32DSP Bit set.
  static const uint8_t HI32DSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 
  };

  // LO32DSP Register Class...
  static const MCPhysReg LO32DSP[] = {
    Mips_LO0, Mips_LO1, Mips_LO2, Mips_LO3, 
  };

  // LO32DSP Bit set.
  static const uint8_t LO32DSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 
  };

  // CPU16Regs_and_GPRMM16MovePPairSecond Register Class...
  static const MCPhysReg CPU16Regs_and_GPRMM16MovePPairSecond[] = {
    Mips_A1, Mips_A2, Mips_A3, 
  };

  // CPU16Regs_and_GPRMM16MovePPairSecond Bit set.
  static const uint8_t CPU16Regs_and_GPRMM16MovePPairSecondBits[] = {
    0x00, 0x00, 0x00, 0xe0, 
  };

  // GPRMM16MovePPairFirst Register Class...
  static const MCPhysReg GPRMM16MovePPairFirst[] = {
    Mips_A0, Mips_A1, Mips_A2, 
  };

  // GPRMM16MovePPairFirst Bit set.
  static const uint8_t GPRMM16MovePPairFirstBits[] = {
    0x00, 0x00, 0x00, 0x70, 
  };

  // GPRMM16MoveP_and_CPU16Regs_and_GPRMM16Zero Register Class...
  static const MCPhysReg GPRMM16MoveP_and_CPU16Regs_and_GPRMM16Zero[] = {
    Mips_S1, Mips_V0, Mips_V1, 
  };

  // GPRMM16MoveP_and_CPU16Regs_and_GPRMM16Zero Bit set.
  static const uint8_t GPRMM16MoveP_and_CPU16Regs_and_GPRMM16ZeroBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x80, 0x01, 
  };

  // GPRNM2R1_and_GPRNM2R2 Register Class...
  static const MCPhysReg GPRNM2R1_and_GPRNM2R2[] = {
    Mips_A1_NM, Mips_A2_NM, Mips_A3_NM, 
  };

  // GPRNM2R1_and_GPRNM2R2 Bit set.
  static const uint8_t GPRNM2R1_and_GPRNM2R2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 
  };

  // GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecond Register Class...
  static const MCPhysReg GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecond[] = {
    Mips_A1, Mips_A2, 
  };

  // GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecond Bit set.
  static const uint8_t GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecondBits[] = {
    0x00, 0x00, 0x00, 0x60, 
  };

  // GPRNM1R1 Register Class...
  static const MCPhysReg GPRNM1R1[] = {
    Mips_A0_NM, Mips_A1_NM, 
  };

  // GPRNM1R1 Bit set.
  static const uint8_t GPRNM1R1Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 
  };

  // CPURAReg Register Class...
  static const MCPhysReg CPURAReg[] = {
    Mips_RA, 
  };

  // CPURAReg Bit set.
  static const uint8_t CPURARegBits[] = {
    0x00, 0x00, 0x40, 
  };

  // CPUSPReg Register Class...
  static const MCPhysReg CPUSPReg[] = {
    Mips_SP, 
  };

  // CPUSPReg Bit set.
  static const uint8_t CPUSPRegBits[] = {
    0x00, 0x00, 0x00, 0x01, 
  };

  // DSPCC Register Class...
  static const MCPhysReg DSPCC[] = {
    Mips_DSPCCond, 
  };

  // DSPCC Bit set.
  static const uint8_t DSPCCBits[] = {
    0x08, 
  };

  // GP32 Register Class...
  static const MCPhysReg GP32[] = {
    Mips_GP, 
  };

  // GP32 Bit set.
  static const uint8_t GP32Bits[] = {
    0x00, 0x08, 
  };

  // GPR32ZERO Register Class...
  static const MCPhysReg GPR32ZERO[] = {
    Mips_ZERO, 
  };

  // GPR32ZERO Bit set.
  static const uint8_t GPR32ZEROBits[] = {
    0x00, 0x00, 0x00, 0x04, 
  };

  // GPRNM1R1_and_GPRNM2R2 Register Class...
  static const MCPhysReg GPRNM1R1_and_GPRNM2R2[] = {
    Mips_A1_NM, 
  };

  // GPRNM1R1_and_GPRNM2R2 Bit set.
  static const uint8_t GPRNM1R1_and_GPRNM2R2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 
  };

  // GPRNMGP Register Class...
  static const MCPhysReg GPRNMGP[] = {
    Mips_GP_NM, 
  };

  // GPRNMGP Bit set.
  static const uint8_t GPRNMGPBits[] = {
    0x00, 0x10, 
  };

  // GPRNMRA Register Class...
  static const MCPhysReg GPRNMRA[] = {
    Mips_RA_NM, 
  };

  // GPRNMRA Bit set.
  static const uint8_t GPRNMRABits[] = {
    0x00, 0x00, 0x80, 
  };

  // GPRNMSP Register Class...
  static const MCPhysReg GPRNMSP[] = {
    Mips_SP_NM, 
  };

  // GPRNMSP Bit set.
  static const uint8_t GPRNMSPBits[] = {
    0x00, 0x00, 0x00, 0x02, 
  };

  // HI32 Register Class...
  static const MCPhysReg HI32[] = {
    Mips_HI0, 
  };

  // HI32 Bit set.
  static const uint8_t HI32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 
  };

  // LO32 Register Class...
  static const MCPhysReg LO32[] = {
    Mips_LO0, 
  };

  // LO32 Bit set.
  static const uint8_t LO32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 
  };

  // SP32 Register Class...
  static const MCPhysReg SP32[] = {
    Mips_SP, 
  };

  // SP32 Bit set.
  static const uint8_t SP32Bits[] = {
    0x00, 0x00, 0x00, 0x01, 
  };

  // FGR64 Register Class...
  static const MCPhysReg FGR64[] = {
    Mips_D0_64, Mips_D1_64, Mips_D2_64, Mips_D3_64, Mips_D4_64, Mips_D5_64, Mips_D6_64, Mips_D7_64, Mips_D8_64, Mips_D9_64, Mips_D10_64, Mips_D11_64, Mips_D12_64, Mips_D13_64, Mips_D14_64, Mips_D15_64, Mips_D16_64, Mips_D17_64, Mips_D18_64, Mips_D19_64, Mips_D20_64, Mips_D21_64, Mips_D22_64, Mips_D23_64, Mips_D24_64, Mips_D25_64, Mips_D26_64, Mips_D27_64, Mips_D28_64, Mips_D29_64, Mips_D30_64, Mips_D31_64, 
  };

  // FGR64 Bit set.
  static const uint8_t FGR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01, 
  };

  // GPR64 Register Class...
  static const MCPhysReg GPR64[] = {
    Mips_ZERO_64, Mips_AT_64, Mips_V0_64, Mips_V1_64, Mips_A0_64, Mips_A1_64, Mips_A2_64, Mips_A3_64, Mips_T0_64, Mips_T1_64, Mips_T2_64, Mips_T3_64, Mips_T4_64, Mips_T5_64, Mips_T6_64, Mips_T7_64, Mips_S0_64, Mips_S1_64, Mips_S2_64, Mips_S3_64, Mips_S4_64, Mips_S5_64, Mips_S6_64, Mips_S7_64, Mips_T8_64, Mips_T9_64, Mips_K0_64, Mips_K1_64, Mips_GP_64, Mips_SP_64, Mips_FP_64, Mips_RA_64, 
  };

  // GPR64 Bit set.
  static const uint8_t GPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd8, 0xff, 0xff, 0x03, 
  };

  // GPR64_with_sub_32_in_GPR32NONZERO Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_GPR32NONZERO[] = {
    Mips_AT_64, Mips_V0_64, Mips_V1_64, Mips_A0_64, Mips_A1_64, Mips_A2_64, Mips_A3_64, Mips_T0_64, Mips_T1_64, Mips_T2_64, Mips_T3_64, Mips_T4_64, Mips_T5_64, Mips_T6_64, Mips_T7_64, Mips_S0_64, Mips_S1_64, Mips_S2_64, Mips_S3_64, Mips_S4_64, Mips_S5_64, Mips_S6_64, Mips_S7_64, Mips_T8_64, Mips_T9_64, Mips_K0_64, Mips_K1_64, Mips_GP_64, Mips_SP_64, Mips_FP_64, Mips_RA_64, 
  };

  // GPR64_with_sub_32_in_GPR32NONZERO Bit set.
  static const uint8_t GPR64_with_sub_32_in_GPR32NONZEROBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd8, 0xff, 0xff, 0x03, 
  };

  // AFGR64 Register Class...
  static const MCPhysReg AFGR64[] = {
    Mips_D0, Mips_D1, Mips_D2, Mips_D3, Mips_D4, Mips_D5, Mips_D6, Mips_D7, Mips_D8, Mips_D9, Mips_D10, Mips_D11, Mips_D12, Mips_D13, Mips_D14, Mips_D15, 
  };

  // AFGR64 Bit set.
  static const uint8_t AFGR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x1f, 
  };

  // GPR64_with_sub_32_in_CPU16RegsPlusSP Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_CPU16RegsPlusSP[] = {
    Mips_V0_64, Mips_V1_64, Mips_A0_64, Mips_A1_64, Mips_A2_64, Mips_A3_64, Mips_S0_64, Mips_S1_64, Mips_SP_64, 
  };

  // GPR64_with_sub_32_in_CPU16RegsPlusSP Bit set.
  static const uint8_t GPR64_with_sub_32_in_CPU16RegsPlusSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x03, 
  };

  // GPR64_with_sub_32_in_CPU16Regs Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_CPU16Regs[] = {
    Mips_V0_64, Mips_V1_64, Mips_A0_64, Mips_A1_64, Mips_A2_64, Mips_A3_64, Mips_S0_64, Mips_S1_64, 
  };

  // GPR64_with_sub_32_in_CPU16Regs Bit set.
  static const uint8_t GPR64_with_sub_32_in_CPU16RegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x03, 
  };

  // GPR64_with_sub_32_in_GPRMM16MoveP Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_GPRMM16MoveP[] = {
    Mips_ZERO_64, Mips_V0_64, Mips_V1_64, Mips_S0_64, Mips_S1_64, Mips_S2_64, Mips_S3_64, Mips_S4_64, 
  };

  // GPR64_with_sub_32_in_GPRMM16MoveP Bit set.
  static const uint8_t GPR64_with_sub_32_in_GPRMM16MovePBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x07, 0x00, 0x03, 
  };

  // GPR64_with_sub_32_in_GPRMM16Zero Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_GPRMM16Zero[] = {
    Mips_ZERO_64, Mips_V0_64, Mips_V1_64, Mips_A0_64, Mips_A1_64, Mips_A2_64, Mips_A3_64, Mips_S1_64, 
  };

  // GPR64_with_sub_32_in_GPRMM16Zero Bit set.
  static const uint8_t GPR64_with_sub_32_in_GPRMM16ZeroBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x03, 
  };

  // GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16Zero Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16Zero[] = {
    Mips_V0_64, Mips_V1_64, Mips_A0_64, Mips_A1_64, Mips_A2_64, Mips_A3_64, Mips_S1_64, 
  };

  // GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16Zero Bit set.
  static const uint8_t GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16ZeroBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x03, 
  };

  // GPR64_with_sub_32_in_GPR32NONZERO_and_GPRMM16MoveP Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_GPR32NONZERO_and_GPRMM16MoveP[] = {
    Mips_V0_64, Mips_V1_64, Mips_S0_64, Mips_S1_64, Mips_S2_64, Mips_S3_64, Mips_S4_64, 
  };

  // GPR64_with_sub_32_in_GPR32NONZERO_and_GPRMM16MoveP Bit set.
  static const uint8_t GPR64_with_sub_32_in_GPR32NONZERO_and_GPRMM16MovePBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x07, 0x00, 0x03, 
  };

  // GPR64_with_sub_32_in_GPRMM16MovePPairSecond Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_GPRMM16MovePPairSecond[] = {
    Mips_A1_64, Mips_A2_64, Mips_A3_64, Mips_S5_64, Mips_S6_64, 
  };

  // GPR64_with_sub_32_in_GPRMM16MovePPairSecond Bit set.
  static const uint8_t GPR64_with_sub_32_in_GPRMM16MovePPairSecondBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 
  };

  // ACC64DSP Register Class...
  static const MCPhysReg ACC64DSP[] = {
    Mips_AC0, Mips_AC1, Mips_AC2, Mips_AC3, 
  };

  // ACC64DSP Bit set.
  static const uint8_t ACC64DSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x0f, 
  };

  // GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MoveP Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MoveP[] = {
    Mips_V0_64, Mips_V1_64, Mips_S0_64, Mips_S1_64, 
  };

  // GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MoveP Bit set.
  static const uint8_t GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MovePBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x03, 
  };

  // GPR64_with_sub_32_in_GPRMM16MoveP_and_GPRMM16Zero Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_GPRMM16MoveP_and_GPRMM16Zero[] = {
    Mips_ZERO_64, Mips_V0_64, Mips_V1_64, Mips_S1_64, 
  };

  // GPR64_with_sub_32_in_GPRMM16MoveP_and_GPRMM16Zero Bit set.
  static const uint8_t GPR64_with_sub_32_in_GPRMM16MoveP_and_GPRMM16ZeroBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x03, 
  };

  // GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MovePPairSecond Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MovePPairSecond[] = {
    Mips_A1_64, Mips_A2_64, Mips_A3_64, 
  };

  // GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MovePPairSecond Bit set.
  static const uint8_t GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MovePPairSecondBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 
  };

  // GPR64_with_sub_32_in_GPRMM16MovePPairFirst Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_GPRMM16MovePPairFirst[] = {
    Mips_A0_64, Mips_A1_64, Mips_A2_64, 
  };

  // GPR64_with_sub_32_in_GPRMM16MovePPairFirst Bit set.
  static const uint8_t GPR64_with_sub_32_in_GPRMM16MovePPairFirstBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 
  };

  // GPR64_with_sub_32_in_GPRMM16MoveP_and_CPU16Regs_and_GPRMM16Zero Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_GPRMM16MoveP_and_CPU16Regs_and_GPRMM16Zero[] = {
    Mips_V0_64, Mips_V1_64, Mips_S1_64, 
  };

  // GPR64_with_sub_32_in_GPRMM16MoveP_and_CPU16Regs_and_GPRMM16Zero Bit set.
  static const uint8_t GPR64_with_sub_32_in_GPRMM16MoveP_and_CPU16Regs_and_GPRMM16ZeroBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x03, 
  };

  // OCTEON_MPL Register Class...
  static const MCPhysReg OCTEON_MPL[] = {
    Mips_MPL0, Mips_MPL1, Mips_MPL2, 
  };

  // OCTEON_MPL Bit set.
  static const uint8_t OCTEON_MPLBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 
  };

  // OCTEON_P Register Class...
  static const MCPhysReg OCTEON_P[] = {
    Mips_P0, Mips_P1, Mips_P2, 
  };

  // OCTEON_P Bit set.
  static const uint8_t OCTEON_PBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 
  };

  // GPR64_with_sub_32_in_GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecond Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecond[] = {
    Mips_A1_64, Mips_A2_64, 
  };

  // GPR64_with_sub_32_in_GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecond Bit set.
  static const uint8_t GPR64_with_sub_32_in_GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecondBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 
  };

  // ACC64 Register Class...
  static const MCPhysReg ACC64[] = {
    Mips_AC0, 
  };

  // ACC64 Bit set.
  static const uint8_t ACC64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x01, 
  };

  // GP64 Register Class...
  static const MCPhysReg GP64[] = {
    Mips_GP_64, 
  };

  // GP64 Bit set.
  static const uint8_t GP64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 
  };

  // GPR64_with_sub_32_in_CPURAReg Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_CPURAReg[] = {
    Mips_RA_64, 
  };

  // GPR64_with_sub_32_in_CPURAReg Bit set.
  static const uint8_t GPR64_with_sub_32_in_CPURARegBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 
  };

  // GPR64_with_sub_32_in_GPR32ZERO Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_GPR32ZERO[] = {
    Mips_ZERO_64, 
  };

  // GPR64_with_sub_32_in_GPR32ZERO Bit set.
  static const uint8_t GPR64_with_sub_32_in_GPR32ZEROBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 
  };

  // HI64 Register Class...
  static const MCPhysReg HI64[] = {
    Mips_HI0_64, 
  };

  // HI64 Bit set.
  static const uint8_t HI64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 
  };

  // LO64 Register Class...
  static const MCPhysReg LO64[] = {
    Mips_LO0_64, 
  };

  // LO64 Bit set.
  static const uint8_t LO64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 
  };

  // SP64 Register Class...
  static const MCPhysReg SP64[] = {
    Mips_SP_64, 
  };

  // SP64 Bit set.
  static const uint8_t SP64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 
  };

  // MSA128B Register Class...
  static const MCPhysReg MSA128B[] = {
    Mips_W0, Mips_W1, Mips_W2, Mips_W3, Mips_W4, Mips_W5, Mips_W6, Mips_W7, Mips_W8, Mips_W9, Mips_W10, Mips_W11, Mips_W12, Mips_W13, Mips_W14, Mips_W15, Mips_W16, Mips_W17, Mips_W18, Mips_W19, Mips_W20, Mips_W21, Mips_W22, Mips_W23, Mips_W24, Mips_W25, Mips_W26, Mips_W27, Mips_W28, Mips_W29, Mips_W30, Mips_W31, 
  };

  // MSA128B Bit set.
  static const uint8_t MSA128BBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01, 
  };

  // MSA128D Register Class...
  static const MCPhysReg MSA128D[] = {
    Mips_W0, Mips_W1, Mips_W2, Mips_W3, Mips_W4, Mips_W5, Mips_W6, Mips_W7, Mips_W8, Mips_W9, Mips_W10, Mips_W11, Mips_W12, Mips_W13, Mips_W14, Mips_W15, Mips_W16, Mips_W17, Mips_W18, Mips_W19, Mips_W20, Mips_W21, Mips_W22, Mips_W23, Mips_W24, Mips_W25, Mips_W26, Mips_W27, Mips_W28, Mips_W29, Mips_W30, Mips_W31, 
  };

  // MSA128D Bit set.
  static const uint8_t MSA128DBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01, 
  };

  // MSA128H Register Class...
  static const MCPhysReg MSA128H[] = {
    Mips_W0, Mips_W1, Mips_W2, Mips_W3, Mips_W4, Mips_W5, Mips_W6, Mips_W7, Mips_W8, Mips_W9, Mips_W10, Mips_W11, Mips_W12, Mips_W13, Mips_W14, Mips_W15, Mips_W16, Mips_W17, Mips_W18, Mips_W19, Mips_W20, Mips_W21, Mips_W22, Mips_W23, Mips_W24, Mips_W25, Mips_W26, Mips_W27, Mips_W28, Mips_W29, Mips_W30, Mips_W31, 
  };

  // MSA128H Bit set.
  static const uint8_t MSA128HBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01, 
  };

  // MSA128W Register Class...
  static const MCPhysReg MSA128W[] = {
    Mips_W0, Mips_W1, Mips_W2, Mips_W3, Mips_W4, Mips_W5, Mips_W6, Mips_W7, Mips_W8, Mips_W9, Mips_W10, Mips_W11, Mips_W12, Mips_W13, Mips_W14, Mips_W15, Mips_W16, Mips_W17, Mips_W18, Mips_W19, Mips_W20, Mips_W21, Mips_W22, Mips_W23, Mips_W24, Mips_W25, Mips_W26, Mips_W27, Mips_W28, Mips_W29, Mips_W30, Mips_W31, 
  };

  // MSA128W Bit set.
  static const uint8_t MSA128WBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01, 
  };

  // MSA128WEvens Register Class...
  static const MCPhysReg MSA128WEvens[] = {
    Mips_W0, Mips_W2, Mips_W4, Mips_W6, Mips_W8, Mips_W10, Mips_W12, Mips_W14, Mips_W16, Mips_W18, Mips_W20, Mips_W22, Mips_W24, Mips_W26, Mips_W28, Mips_W30, 
  };

  // MSA128WEvens Bit set.
  static const uint8_t MSA128WEvensBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 
  };

  // ACC128 Register Class...
  static const MCPhysReg ACC128[] = {
    Mips_AC0_64, 
  };

  // ACC128 Bit set.
  static const uint8_t ACC128Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 
  };

static const MCRegisterClass MipsMCRegisterClasses[] = {
  { MSA128F16, MSA128F16Bits, sizeof(MSA128F16Bits) },
  { COP0Sel, COP0SelBits, sizeof(COP0SelBits) },
  { CCR, CCRBits, sizeof(CCRBits) },
  { COP0, COP0Bits, sizeof(COP0Bits) },
  { COP2, COP2Bits, sizeof(COP2Bits) },
  { COP3, COP3Bits, sizeof(COP3Bits) },
  { DSPR, DSPRBits, sizeof(DSPRBits) },
  { FGR32, FGR32Bits, sizeof(FGR32Bits) },
  { FGRCC, FGRCCBits, sizeof(FGRCCBits) },
  { GPR32, GPR32Bits, sizeof(GPR32Bits) },
  { GPRNM32, GPRNM32Bits, sizeof(GPRNM32Bits) },
  { HWRegs, HWRegsBits, sizeof(HWRegsBits) },
  { MSACtrl, MSACtrlBits, sizeof(MSACtrlBits) },
  { GPR32NONZERO, GPR32NONZEROBits, sizeof(GPR32NONZEROBits) },
  { GPRNM32NZ, GPRNM32NZBits, sizeof(GPRNM32NZBits) },
  { GPRNM32_TAIL, GPRNM32_TAILBits, sizeof(GPRNM32_TAILBits) },
  { GPRNM4, GPRNM4Bits, sizeof(GPRNM4Bits) },
  { GPRNM4Z, GPRNM4ZBits, sizeof(GPRNM4ZBits) },
  { GPRNM4_and_GPRNM4Z, GPRNM4_and_GPRNM4ZBits, sizeof(GPRNM4_and_GPRNM4ZBits) },
  { CPU16RegsPlusSP, CPU16RegsPlusSPBits, sizeof(CPU16RegsPlusSPBits) },
  { CPU16Regs, CPU16RegsBits, sizeof(CPU16RegsBits) },
  { FCC, FCCBits, sizeof(FCCBits) },
  { GPRMM16, GPRMM16Bits, sizeof(GPRMM16Bits) },
  { GPRMM16MoveP, GPRMM16MovePBits, sizeof(GPRMM16MovePBits) },
  { GPRMM16Zero, GPRMM16ZeroBits, sizeof(GPRMM16ZeroBits) },
  { GPRNM3, GPRNM3Bits, sizeof(GPRNM3Bits) },
  { GPRNM3Z, GPRNM3ZBits, sizeof(GPRNM3ZBits) },
  { GPRNM4_and_GPRNM32_TAIL, GPRNM4_and_GPRNM32_TAILBits, sizeof(GPRNM4_and_GPRNM32_TAILBits) },
  { CPU16Regs_and_GPRMM16Zero, CPU16Regs_and_GPRMM16ZeroBits, sizeof(CPU16Regs_and_GPRMM16ZeroBits) },
  { GPR32NONZERO_and_GPRMM16MoveP, GPR32NONZERO_and_GPRMM16MovePBits, sizeof(GPR32NONZERO_and_GPRMM16MovePBits) },
  { GPRNM3_and_GPRNM3Z, GPRNM3_and_GPRNM3ZBits, sizeof(GPRNM3_and_GPRNM3ZBits) },
  { GPRNM4Z_and_GPRNM32_TAIL, GPRNM4Z_and_GPRNM32_TAILBits, sizeof(GPRNM4Z_and_GPRNM32_TAILBits) },
  { GPRMM16MovePPairSecond, GPRMM16MovePPairSecondBits, sizeof(GPRMM16MovePPairSecondBits) },
  { CPU16Regs_and_GPRMM16MoveP, CPU16Regs_and_GPRMM16MovePBits, sizeof(CPU16Regs_and_GPRMM16MovePBits) },
  { GPRMM16MoveP_and_GPRMM16Zero, GPRMM16MoveP_and_GPRMM16ZeroBits, sizeof(GPRMM16MoveP_and_GPRMM16ZeroBits) },
  { GPRNM2R1, GPRNM2R1Bits, sizeof(GPRNM2R1Bits) },
  { GPRNM2R2, GPRNM2R2Bits, sizeof(GPRNM2R2Bits) },
  { HI32DSP, HI32DSPBits, sizeof(HI32DSPBits) },
  { LO32DSP, LO32DSPBits, sizeof(LO32DSPBits) },
  { CPU16Regs_and_GPRMM16MovePPairSecond, CPU16Regs_and_GPRMM16MovePPairSecondBits, sizeof(CPU16Regs_and_GPRMM16MovePPairSecondBits) },
  { GPRMM16MovePPairFirst, GPRMM16MovePPairFirstBits, sizeof(GPRMM16MovePPairFirstBits) },
  { GPRMM16MoveP_and_CPU16Regs_and_GPRMM16Zero, GPRMM16MoveP_and_CPU16Regs_and_GPRMM16ZeroBits, sizeof(GPRMM16MoveP_and_CPU16Regs_and_GPRMM16ZeroBits) },
  { GPRNM2R1_and_GPRNM2R2, GPRNM2R1_and_GPRNM2R2Bits, sizeof(GPRNM2R1_and_GPRNM2R2Bits) },
  { GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecond, GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecondBits, sizeof(GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecondBits) },
  { GPRNM1R1, GPRNM1R1Bits, sizeof(GPRNM1R1Bits) },
  { CPURAReg, CPURARegBits, sizeof(CPURARegBits) },
  { CPUSPReg, CPUSPRegBits, sizeof(CPUSPRegBits) },
  { DSPCC, DSPCCBits, sizeof(DSPCCBits) },
  { GP32, GP32Bits, sizeof(GP32Bits) },
  { GPR32ZERO, GPR32ZEROBits, sizeof(GPR32ZEROBits) },
  { GPRNM1R1_and_GPRNM2R2, GPRNM1R1_and_GPRNM2R2Bits, sizeof(GPRNM1R1_and_GPRNM2R2Bits) },
  { GPRNMGP, GPRNMGPBits, sizeof(GPRNMGPBits) },
  { GPRNMRA, GPRNMRABits, sizeof(GPRNMRABits) },
  { GPRNMSP, GPRNMSPBits, sizeof(GPRNMSPBits) },
  { HI32, HI32Bits, sizeof(HI32Bits) },
  { LO32, LO32Bits, sizeof(LO32Bits) },
  { SP32, SP32Bits, sizeof(SP32Bits) },
  { FGR64, FGR64Bits, sizeof(FGR64Bits) },
  { GPR64, GPR64Bits, sizeof(GPR64Bits) },
  { GPR64_with_sub_32_in_GPR32NONZERO, GPR64_with_sub_32_in_GPR32NONZEROBits, sizeof(GPR64_with_sub_32_in_GPR32NONZEROBits) },
  { AFGR64, AFGR64Bits, sizeof(AFGR64Bits) },
  { GPR64_with_sub_32_in_CPU16RegsPlusSP, GPR64_with_sub_32_in_CPU16RegsPlusSPBits, sizeof(GPR64_with_sub_32_in_CPU16RegsPlusSPBits) },
  { GPR64_with_sub_32_in_CPU16Regs, GPR64_with_sub_32_in_CPU16RegsBits, sizeof(GPR64_with_sub_32_in_CPU16RegsBits) },
  { GPR64_with_sub_32_in_GPRMM16MoveP, GPR64_with_sub_32_in_GPRMM16MovePBits, sizeof(GPR64_with_sub_32_in_GPRMM16MovePBits) },
  { GPR64_with_sub_32_in_GPRMM16Zero, GPR64_with_sub_32_in_GPRMM16ZeroBits, sizeof(GPR64_with_sub_32_in_GPRMM16ZeroBits) },
  { GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16Zero, GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16ZeroBits, sizeof(GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16ZeroBits) },
  { GPR64_with_sub_32_in_GPR32NONZERO_and_GPRMM16MoveP, GPR64_with_sub_32_in_GPR32NONZERO_and_GPRMM16MovePBits, sizeof(GPR64_with_sub_32_in_GPR32NONZERO_and_GPRMM16MovePBits) },
  { GPR64_with_sub_32_in_GPRMM16MovePPairSecond, GPR64_with_sub_32_in_GPRMM16MovePPairSecondBits, sizeof(GPR64_with_sub_32_in_GPRMM16MovePPairSecondBits) },
  { ACC64DSP, ACC64DSPBits, sizeof(ACC64DSPBits) },
  { GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MoveP, GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MovePBits, sizeof(GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MovePBits) },
  { GPR64_with_sub_32_in_GPRMM16MoveP_and_GPRMM16Zero, GPR64_with_sub_32_in_GPRMM16MoveP_and_GPRMM16ZeroBits, sizeof(GPR64_with_sub_32_in_GPRMM16MoveP_and_GPRMM16ZeroBits) },
  { GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MovePPairSecond, GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MovePPairSecondBits, sizeof(GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MovePPairSecondBits) },
  { GPR64_with_sub_32_in_GPRMM16MovePPairFirst, GPR64_with_sub_32_in_GPRMM16MovePPairFirstBits, sizeof(GPR64_with_sub_32_in_GPRMM16MovePPairFirstBits) },
  { GPR64_with_sub_32_in_GPRMM16MoveP_and_CPU16Regs_and_GPRMM16Zero, GPR64_with_sub_32_in_GPRMM16MoveP_and_CPU16Regs_and_GPRMM16ZeroBits, sizeof(GPR64_with_sub_32_in_GPRMM16MoveP_and_CPU16Regs_and_GPRMM16ZeroBits) },
  { OCTEON_MPL, OCTEON_MPLBits, sizeof(OCTEON_MPLBits) },
  { OCTEON_P, OCTEON_PBits, sizeof(OCTEON_PBits) },
  { GPR64_with_sub_32_in_GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecond, GPR64_with_sub_32_in_GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecondBits, sizeof(GPR64_with_sub_32_in_GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecondBits) },
  { ACC64, ACC64Bits, sizeof(ACC64Bits) },
  { GP64, GP64Bits, sizeof(GP64Bits) },
  { GPR64_with_sub_32_in_CPURAReg, GPR64_with_sub_32_in_CPURARegBits, sizeof(GPR64_with_sub_32_in_CPURARegBits) },
  { GPR64_with_sub_32_in_GPR32ZERO, GPR64_with_sub_32_in_GPR32ZEROBits, sizeof(GPR64_with_sub_32_in_GPR32ZEROBits) },
  { HI64, HI64Bits, sizeof(HI64Bits) },
  { LO64, LO64Bits, sizeof(LO64Bits) },
  { SP64, SP64Bits, sizeof(SP64Bits) },
  { MSA128B, MSA128BBits, sizeof(MSA128BBits) },
  { MSA128D, MSA128DBits, sizeof(MSA128DBits) },
  { MSA128H, MSA128HBits, sizeof(MSA128HBits) },
  { MSA128W, MSA128WBits, sizeof(MSA128WBits) },
  { MSA128WEvens, MSA128WEvensBits, sizeof(MSA128WEvensBits) },
  { ACC128, ACC128Bits, sizeof(ACC128Bits) },
};

static const uint16_t MipsRegEncodingTable[] = {
  0,
  1,
  1,
  0,
  0,
  0,
  0,
  0,
  0,
  30,
  30,
  28,
  28,
  2,
  1,
  0,
  6,
  4,
  5,
  3,
  7,
  0,
  31,
  31,
  29,
  29,
  0,
  0,
  4,
  5,
  6,
  7,
  0,
  1,
  2,
  3,
  1,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16,
  17,
  18,
  19,
  20,
  21,
  22,
  23,
  24,
  25,
  26,
  27,
  28,
  29,
  30,
  31,
  10,
  11,
  12,
  13,
  14,
  15,
  16,
  17,
  18,
  19,
  20,
  21,
  22,
  23,
  24,
  25,
  26,
  27,
  28,
  29,
  30,
  31,
  10,
  11,
  12,
  13,
  14,
  15,
  16,
  17,
  18,
  19,
  20,
  21,
  22,
  23,
  24,
  25,
  26,
  27,
  28,
  29,
  30,
  31,
  0,
  2,
  4,
  6,
  8,
  10,
  12,
  14,
  16,
  18,
  20,
  22,
  24,
  26,
  28,
  30,
  0,
  0,
  0,
  0,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16,
  17,
  18,
  19,
  20,
  21,
  22,
  23,
  24,
  25,
  26,
  27,
  28,
  29,
  30,
  31,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16,
  17,
  18,
  19,
  20,
  21,
  22,
  23,
  24,
  25,
  26,
  27,
  28,
  29,
  30,
  31,
  30,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16,
  17,
  18,
  19,
  20,
  21,
  22,
  23,
  24,
  25,
  26,
  27,
  28,
  29,
  30,
  31,
  28,
  0,
  1,
  2,
  3,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16,
  17,
  18,
  19,
  20,
  21,
  22,
  23,
  24,
  25,
  26,
  27,
  28,
  29,
  30,
  31,
  26,
  27,
  0,
  1,
  2,
  3,
  0,
  1,
  2,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16,
  17,
  18,
  19,
  20,
  21,
  22,
  23,
  24,
  25,
  26,
  27,
  28,
  29,
  30,
  31,
  0,
  1,
  2,
  31,
  16,
  17,
  18,
  19,
  20,
  21,
  22,
  23,
  29,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  24,
  25,
  2,
  3,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16,
  17,
  18,
  19,
  20,
  21,
  22,
  23,
  24,
  25,
  26,
  27,
  28,
  29,
  30,
  31,
  0,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  257,
  258,
  259,
  256,
  484,
  864,
  416,
  482,
  483,
  352,
  512,
  128,
  129,
  288,
  931,
  899,
  736,
  132,
  768,
  992,
  930,
  898,
  481,
  320,
  448,
  832,
  960,
  97,
  391,
  224,
  929,
  897,
  0,
  385,
  928,
  896,
  544,
  545,
  546,
  133,
  1,
  450,
  421,
  161,
  160,
  480,
  165,
  198,
  166,
  167,
  32,
  386,
  387,
  384,
  66,
  69,
  68,
  103,
  67,
  70,
  71,
  65,
  737,
  741,
  740,
  130,
  388,
  420,
  4,
  33,
  39,
  37,
  38,
  192,
  640,
  131,
  36,
  26,
  27,
  16,
  17,
  18,
  19,
  20,
  21,
  22,
  23,
  12,
  13,
  14,
  15,
  2,
  3,
  24,
  25,
  4,
  5,
  6,
  7,
  0,
  513,
  514,
  515,
  516,
  517,
  742,
  64,
  96,
  390,
  324,
  325,
  326,
  994,
  995,
  996,
  997,
  998,
  999,
  2,
  3,
  801,
  803,
  805,
  807,
  809,
  811,
  813,
  815,
  800,
  802,
  804,
  806,
  808,
  810,
  812,
  814,
  162,
  163,
  164,
  193,
  194,
  195,
  196,
  197,
  389,
  738,
  770,
  739,
  771,
  34,
  35,
  608,
  609,
  610,
  611,
  612,
  613,
  614,
  615,
  616,
  617,
  618,
  619,
  620,
  621,
  622,
  623,
  576,
  577,
  578,
  579,
  580,
  581,
  582,
  583,
  584,
  585,
  586,
  587,
  588,
  589,
  590,
  591,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  16,
  17,
  18,
  19,
  20,
  21,
  22,
  23,
  24,
  25,
  26,
  27,
  28,
  29,
  30,
  31,
  0,
  0,
  26,
  27,
  0,
  16,
  17,
  18,
  19,
  20,
  21,
  22,
  23,
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
  24,
  25,
  2,
  3,
  356,
};
#endif // GET_REGINFO_MC_DESC




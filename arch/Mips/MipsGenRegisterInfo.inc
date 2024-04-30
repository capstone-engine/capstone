#ifdef GET_REGINFO_ENUM
#undef GET_REGINFO_ENUM

enum {
  Mips_NoRegister,
  Mips_AT = 1,
  Mips_DSPCCond = 2,
  Mips_DSPCarry = 3,
  Mips_DSPEFI = 4,
  Mips_DSPOutFlag = 5,
  Mips_DSPPos = 6,
  Mips_DSPSCount = 7,
  Mips_FP = 8,
  Mips_GP = 9,
  Mips_MSAAccess = 10,
  Mips_MSACSR = 11,
  Mips_MSAIR = 12,
  Mips_MSAMap = 13,
  Mips_MSAModify = 14,
  Mips_MSARequest = 15,
  Mips_MSASave = 16,
  Mips_MSAUnmap = 17,
  Mips_PC = 18,
  Mips_RA = 19,
  Mips_SP = 20,
  Mips_ZERO = 21,
  Mips_A0 = 22,
  Mips_A1 = 23,
  Mips_A2 = 24,
  Mips_A3 = 25,
  Mips_AC0 = 26,
  Mips_AC1 = 27,
  Mips_AC2 = 28,
  Mips_AC3 = 29,
  Mips_AT_64 = 30,
  Mips_COP00 = 31,
  Mips_COP01 = 32,
  Mips_COP02 = 33,
  Mips_COP03 = 34,
  Mips_COP04 = 35,
  Mips_COP05 = 36,
  Mips_COP06 = 37,
  Mips_COP07 = 38,
  Mips_COP08 = 39,
  Mips_COP09 = 40,
  Mips_COP20 = 41,
  Mips_COP21 = 42,
  Mips_COP22 = 43,
  Mips_COP23 = 44,
  Mips_COP24 = 45,
  Mips_COP25 = 46,
  Mips_COP26 = 47,
  Mips_COP27 = 48,
  Mips_COP28 = 49,
  Mips_COP29 = 50,
  Mips_COP30 = 51,
  Mips_COP31 = 52,
  Mips_COP32 = 53,
  Mips_COP33 = 54,
  Mips_COP34 = 55,
  Mips_COP35 = 56,
  Mips_COP36 = 57,
  Mips_COP37 = 58,
  Mips_COP38 = 59,
  Mips_COP39 = 60,
  Mips_COP010 = 61,
  Mips_COP011 = 62,
  Mips_COP012 = 63,
  Mips_COP013 = 64,
  Mips_COP014 = 65,
  Mips_COP015 = 66,
  Mips_COP016 = 67,
  Mips_COP017 = 68,
  Mips_COP018 = 69,
  Mips_COP019 = 70,
  Mips_COP020 = 71,
  Mips_COP021 = 72,
  Mips_COP022 = 73,
  Mips_COP023 = 74,
  Mips_COP024 = 75,
  Mips_COP025 = 76,
  Mips_COP026 = 77,
  Mips_COP027 = 78,
  Mips_COP028 = 79,
  Mips_COP029 = 80,
  Mips_COP030 = 81,
  Mips_COP031 = 82,
  Mips_COP210 = 83,
  Mips_COP211 = 84,
  Mips_COP212 = 85,
  Mips_COP213 = 86,
  Mips_COP214 = 87,
  Mips_COP215 = 88,
  Mips_COP216 = 89,
  Mips_COP217 = 90,
  Mips_COP218 = 91,
  Mips_COP219 = 92,
  Mips_COP220 = 93,
  Mips_COP221 = 94,
  Mips_COP222 = 95,
  Mips_COP223 = 96,
  Mips_COP224 = 97,
  Mips_COP225 = 98,
  Mips_COP226 = 99,
  Mips_COP227 = 100,
  Mips_COP228 = 101,
  Mips_COP229 = 102,
  Mips_COP230 = 103,
  Mips_COP231 = 104,
  Mips_COP310 = 105,
  Mips_COP311 = 106,
  Mips_COP312 = 107,
  Mips_COP313 = 108,
  Mips_COP314 = 109,
  Mips_COP315 = 110,
  Mips_COP316 = 111,
  Mips_COP317 = 112,
  Mips_COP318 = 113,
  Mips_COP319 = 114,
  Mips_COP320 = 115,
  Mips_COP321 = 116,
  Mips_COP322 = 117,
  Mips_COP323 = 118,
  Mips_COP324 = 119,
  Mips_COP325 = 120,
  Mips_COP326 = 121,
  Mips_COP327 = 122,
  Mips_COP328 = 123,
  Mips_COP329 = 124,
  Mips_COP330 = 125,
  Mips_COP331 = 126,
  Mips_D0 = 127,
  Mips_D1 = 128,
  Mips_D2 = 129,
  Mips_D3 = 130,
  Mips_D4 = 131,
  Mips_D5 = 132,
  Mips_D6 = 133,
  Mips_D7 = 134,
  Mips_D8 = 135,
  Mips_D9 = 136,
  Mips_D10 = 137,
  Mips_D11 = 138,
  Mips_D12 = 139,
  Mips_D13 = 140,
  Mips_D14 = 141,
  Mips_D15 = 142,
  Mips_DSPOutFlag20 = 143,
  Mips_DSPOutFlag21 = 144,
  Mips_DSPOutFlag22 = 145,
  Mips_DSPOutFlag23 = 146,
  Mips_F0 = 147,
  Mips_F1 = 148,
  Mips_F2 = 149,
  Mips_F3 = 150,
  Mips_F4 = 151,
  Mips_F5 = 152,
  Mips_F6 = 153,
  Mips_F7 = 154,
  Mips_F8 = 155,
  Mips_F9 = 156,
  Mips_F10 = 157,
  Mips_F11 = 158,
  Mips_F12 = 159,
  Mips_F13 = 160,
  Mips_F14 = 161,
  Mips_F15 = 162,
  Mips_F16 = 163,
  Mips_F17 = 164,
  Mips_F18 = 165,
  Mips_F19 = 166,
  Mips_F20 = 167,
  Mips_F21 = 168,
  Mips_F22 = 169,
  Mips_F23 = 170,
  Mips_F24 = 171,
  Mips_F25 = 172,
  Mips_F26 = 173,
  Mips_F27 = 174,
  Mips_F28 = 175,
  Mips_F29 = 176,
  Mips_F30 = 177,
  Mips_F31 = 178,
  Mips_FCC0 = 179,
  Mips_FCC1 = 180,
  Mips_FCC2 = 181,
  Mips_FCC3 = 182,
  Mips_FCC4 = 183,
  Mips_FCC5 = 184,
  Mips_FCC6 = 185,
  Mips_FCC7 = 186,
  Mips_FCR0 = 187,
  Mips_FCR1 = 188,
  Mips_FCR2 = 189,
  Mips_FCR3 = 190,
  Mips_FCR4 = 191,
  Mips_FCR5 = 192,
  Mips_FCR6 = 193,
  Mips_FCR7 = 194,
  Mips_FCR8 = 195,
  Mips_FCR9 = 196,
  Mips_FCR10 = 197,
  Mips_FCR11 = 198,
  Mips_FCR12 = 199,
  Mips_FCR13 = 200,
  Mips_FCR14 = 201,
  Mips_FCR15 = 202,
  Mips_FCR16 = 203,
  Mips_FCR17 = 204,
  Mips_FCR18 = 205,
  Mips_FCR19 = 206,
  Mips_FCR20 = 207,
  Mips_FCR21 = 208,
  Mips_FCR22 = 209,
  Mips_FCR23 = 210,
  Mips_FCR24 = 211,
  Mips_FCR25 = 212,
  Mips_FCR26 = 213,
  Mips_FCR27 = 214,
  Mips_FCR28 = 215,
  Mips_FCR29 = 216,
  Mips_FCR30 = 217,
  Mips_FCR31 = 218,
  Mips_FP_64 = 219,
  Mips_F_HI0 = 220,
  Mips_F_HI1 = 221,
  Mips_F_HI2 = 222,
  Mips_F_HI3 = 223,
  Mips_F_HI4 = 224,
  Mips_F_HI5 = 225,
  Mips_F_HI6 = 226,
  Mips_F_HI7 = 227,
  Mips_F_HI8 = 228,
  Mips_F_HI9 = 229,
  Mips_F_HI10 = 230,
  Mips_F_HI11 = 231,
  Mips_F_HI12 = 232,
  Mips_F_HI13 = 233,
  Mips_F_HI14 = 234,
  Mips_F_HI15 = 235,
  Mips_F_HI16 = 236,
  Mips_F_HI17 = 237,
  Mips_F_HI18 = 238,
  Mips_F_HI19 = 239,
  Mips_F_HI20 = 240,
  Mips_F_HI21 = 241,
  Mips_F_HI22 = 242,
  Mips_F_HI23 = 243,
  Mips_F_HI24 = 244,
  Mips_F_HI25 = 245,
  Mips_F_HI26 = 246,
  Mips_F_HI27 = 247,
  Mips_F_HI28 = 248,
  Mips_F_HI29 = 249,
  Mips_F_HI30 = 250,
  Mips_F_HI31 = 251,
  Mips_GP_64 = 252,
  Mips_HI0 = 253,
  Mips_HI1 = 254,
  Mips_HI2 = 255,
  Mips_HI3 = 256,
  Mips_HWR0 = 257,
  Mips_HWR1 = 258,
  Mips_HWR2 = 259,
  Mips_HWR3 = 260,
  Mips_HWR4 = 261,
  Mips_HWR5 = 262,
  Mips_HWR6 = 263,
  Mips_HWR7 = 264,
  Mips_HWR8 = 265,
  Mips_HWR9 = 266,
  Mips_HWR10 = 267,
  Mips_HWR11 = 268,
  Mips_HWR12 = 269,
  Mips_HWR13 = 270,
  Mips_HWR14 = 271,
  Mips_HWR15 = 272,
  Mips_HWR16 = 273,
  Mips_HWR17 = 274,
  Mips_HWR18 = 275,
  Mips_HWR19 = 276,
  Mips_HWR20 = 277,
  Mips_HWR21 = 278,
  Mips_HWR22 = 279,
  Mips_HWR23 = 280,
  Mips_HWR24 = 281,
  Mips_HWR25 = 282,
  Mips_HWR26 = 283,
  Mips_HWR27 = 284,
  Mips_HWR28 = 285,
  Mips_HWR29 = 286,
  Mips_HWR30 = 287,
  Mips_HWR31 = 288,
  Mips_K0 = 289,
  Mips_K1 = 290,
  Mips_LO0 = 291,
  Mips_LO1 = 292,
  Mips_LO2 = 293,
  Mips_LO3 = 294,
  Mips_MPL0 = 295,
  Mips_MPL1 = 296,
  Mips_MPL2 = 297,
  Mips_MSA8 = 298,
  Mips_MSA9 = 299,
  Mips_MSA10 = 300,
  Mips_MSA11 = 301,
  Mips_MSA12 = 302,
  Mips_MSA13 = 303,
  Mips_MSA14 = 304,
  Mips_MSA15 = 305,
  Mips_MSA16 = 306,
  Mips_MSA17 = 307,
  Mips_MSA18 = 308,
  Mips_MSA19 = 309,
  Mips_MSA20 = 310,
  Mips_MSA21 = 311,
  Mips_MSA22 = 312,
  Mips_MSA23 = 313,
  Mips_MSA24 = 314,
  Mips_MSA25 = 315,
  Mips_MSA26 = 316,
  Mips_MSA27 = 317,
  Mips_MSA28 = 318,
  Mips_MSA29 = 319,
  Mips_MSA30 = 320,
  Mips_MSA31 = 321,
  Mips_P0 = 322,
  Mips_P1 = 323,
  Mips_P2 = 324,
  Mips_RA_64 = 325,
  Mips_S0 = 326,
  Mips_S1 = 327,
  Mips_S2 = 328,
  Mips_S3 = 329,
  Mips_S4 = 330,
  Mips_S5 = 331,
  Mips_S6 = 332,
  Mips_S7 = 333,
  Mips_SP_64 = 334,
  Mips_T0 = 335,
  Mips_T1 = 336,
  Mips_T2 = 337,
  Mips_T3 = 338,
  Mips_T4 = 339,
  Mips_T5 = 340,
  Mips_T6 = 341,
  Mips_T7 = 342,
  Mips_T8 = 343,
  Mips_T9 = 344,
  Mips_V0 = 345,
  Mips_V1 = 346,
  Mips_W0 = 347,
  Mips_W1 = 348,
  Mips_W2 = 349,
  Mips_W3 = 350,
  Mips_W4 = 351,
  Mips_W5 = 352,
  Mips_W6 = 353,
  Mips_W7 = 354,
  Mips_W8 = 355,
  Mips_W9 = 356,
  Mips_W10 = 357,
  Mips_W11 = 358,
  Mips_W12 = 359,
  Mips_W13 = 360,
  Mips_W14 = 361,
  Mips_W15 = 362,
  Mips_W16 = 363,
  Mips_W17 = 364,
  Mips_W18 = 365,
  Mips_W19 = 366,
  Mips_W20 = 367,
  Mips_W21 = 368,
  Mips_W22 = 369,
  Mips_W23 = 370,
  Mips_W24 = 371,
  Mips_W25 = 372,
  Mips_W26 = 373,
  Mips_W27 = 374,
  Mips_W28 = 375,
  Mips_W29 = 376,
  Mips_W30 = 377,
  Mips_W31 = 378,
  Mips_ZERO_64 = 379,
  Mips_A0_64 = 380,
  Mips_A1_64 = 381,
  Mips_A2_64 = 382,
  Mips_A3_64 = 383,
  Mips_AC0_64 = 384,
  Mips_D0_64 = 385,
  Mips_D1_64 = 386,
  Mips_D2_64 = 387,
  Mips_D3_64 = 388,
  Mips_D4_64 = 389,
  Mips_D5_64 = 390,
  Mips_D6_64 = 391,
  Mips_D7_64 = 392,
  Mips_D8_64 = 393,
  Mips_D9_64 = 394,
  Mips_D10_64 = 395,
  Mips_D11_64 = 396,
  Mips_D12_64 = 397,
  Mips_D13_64 = 398,
  Mips_D14_64 = 399,
  Mips_D15_64 = 400,
  Mips_D16_64 = 401,
  Mips_D17_64 = 402,
  Mips_D18_64 = 403,
  Mips_D19_64 = 404,
  Mips_D20_64 = 405,
  Mips_D21_64 = 406,
  Mips_D22_64 = 407,
  Mips_D23_64 = 408,
  Mips_D24_64 = 409,
  Mips_D25_64 = 410,
  Mips_D26_64 = 411,
  Mips_D27_64 = 412,
  Mips_D28_64 = 413,
  Mips_D29_64 = 414,
  Mips_D30_64 = 415,
  Mips_D31_64 = 416,
  Mips_DSPOutFlag16_19 = 417,
  Mips_HI0_64 = 418,
  Mips_K0_64 = 419,
  Mips_K1_64 = 420,
  Mips_LO0_64 = 421,
  Mips_S0_64 = 422,
  Mips_S1_64 = 423,
  Mips_S2_64 = 424,
  Mips_S3_64 = 425,
  Mips_S4_64 = 426,
  Mips_S5_64 = 427,
  Mips_S6_64 = 428,
  Mips_S7_64 = 429,
  Mips_T0_64 = 430,
  Mips_T1_64 = 431,
  Mips_T2_64 = 432,
  Mips_T3_64 = 433,
  Mips_T4_64 = 434,
  Mips_T5_64 = 435,
  Mips_T6_64 = 436,
  Mips_T7_64 = 437,
  Mips_T8_64 = 438,
  Mips_T9_64 = 439,
  Mips_V0_64 = 440,
  Mips_V1_64 = 441,
  NUM_TARGET_REGS // 442
};

// Register classes

enum {
  Mips_MSA128F16RegClassID = 0,
  Mips_CCRRegClassID = 1,
  Mips_COP0RegClassID = 2,
  Mips_COP2RegClassID = 3,
  Mips_COP3RegClassID = 4,
  Mips_DSPRRegClassID = 5,
  Mips_FGR32RegClassID = 6,
  Mips_FGRCCRegClassID = 7,
  Mips_GPR32RegClassID = 8,
  Mips_HWRegsRegClassID = 9,
  Mips_MSACtrlRegClassID = 10,
  Mips_GPR32NONZERORegClassID = 11,
  Mips_CPU16RegsPlusSPRegClassID = 12,
  Mips_CPU16RegsRegClassID = 13,
  Mips_FCCRegClassID = 14,
  Mips_GPRMM16RegClassID = 15,
  Mips_GPRMM16MovePRegClassID = 16,
  Mips_GPRMM16ZeroRegClassID = 17,
  Mips_CPU16Regs_and_GPRMM16ZeroRegClassID = 18,
  Mips_GPR32NONZERO_and_GPRMM16MovePRegClassID = 19,
  Mips_GPRMM16MovePPairSecondRegClassID = 20,
  Mips_CPU16Regs_and_GPRMM16MovePRegClassID = 21,
  Mips_GPRMM16MoveP_and_GPRMM16ZeroRegClassID = 22,
  Mips_HI32DSPRegClassID = 23,
  Mips_LO32DSPRegClassID = 24,
  Mips_CPU16Regs_and_GPRMM16MovePPairSecondRegClassID = 25,
  Mips_GPRMM16MovePPairFirstRegClassID = 26,
  Mips_GPRMM16MoveP_and_CPU16Regs_and_GPRMM16ZeroRegClassID = 27,
  Mips_GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecondRegClassID = 28,
  Mips_CPURARegRegClassID = 29,
  Mips_CPUSPRegRegClassID = 30,
  Mips_DSPCCRegClassID = 31,
  Mips_GP32RegClassID = 32,
  Mips_GPR32ZERORegClassID = 33,
  Mips_HI32RegClassID = 34,
  Mips_LO32RegClassID = 35,
  Mips_SP32RegClassID = 36,
  Mips_FGR64RegClassID = 37,
  Mips_GPR64RegClassID = 38,
  Mips_GPR64_with_sub_32_in_GPR32NONZERORegClassID = 39,
  Mips_AFGR64RegClassID = 40,
  Mips_GPR64_with_sub_32_in_CPU16RegsPlusSPRegClassID = 41,
  Mips_GPR64_with_sub_32_in_CPU16RegsRegClassID = 42,
  Mips_GPR64_with_sub_32_in_GPRMM16MovePRegClassID = 43,
  Mips_GPR64_with_sub_32_in_GPRMM16ZeroRegClassID = 44,
  Mips_GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16ZeroRegClassID = 45,
  Mips_GPR64_with_sub_32_in_GPR32NONZERO_and_GPRMM16MovePRegClassID = 46,
  Mips_GPR64_with_sub_32_in_GPRMM16MovePPairSecondRegClassID = 47,
  Mips_ACC64DSPRegClassID = 48,
  Mips_GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MovePRegClassID = 49,
  Mips_GPR64_with_sub_32_in_GPRMM16MoveP_and_GPRMM16ZeroRegClassID = 50,
  Mips_GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MovePPairSecondRegClassID = 51,
  Mips_GPR64_with_sub_32_in_GPRMM16MovePPairFirstRegClassID = 52,
  Mips_GPR64_with_sub_32_in_GPRMM16MoveP_and_CPU16Regs_and_GPRMM16ZeroRegClassID = 53,
  Mips_OCTEON_MPLRegClassID = 54,
  Mips_OCTEON_PRegClassID = 55,
  Mips_GPR64_with_sub_32_in_GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecondRegClassID = 56,
  Mips_ACC64RegClassID = 57,
  Mips_GP64RegClassID = 58,
  Mips_GPR64_with_sub_32_in_CPURARegRegClassID = 59,
  Mips_GPR64_with_sub_32_in_GPR32ZERORegClassID = 60,
  Mips_HI64RegClassID = 61,
  Mips_LO64RegClassID = 62,
  Mips_SP64RegClassID = 63,
  Mips_MSA128BRegClassID = 64,
  Mips_MSA128DRegClassID = 65,
  Mips_MSA128HRegClassID = 66,
  Mips_MSA128WRegClassID = 67,
  Mips_MSA128WEvensRegClassID = 68,
  Mips_ACC128RegClassID = 69,

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
  /* 0 */ -412, 0,
  /* 2 */ -358, 0,
  /* 4 */ -314, 0,
  /* 6 */ -306, 0,
  /* 8 */ -265, 0,
  /* 10 */ -243, 0,
  /* 12 */ 37, -130, 127, -165, -227, 0,
  /* 18 */ -211, 0,
  /* 20 */ -165, 0,
  /* 22 */ -141, 0,
  /* 24 */ -140, 0,
  /* 26 */ -139, 0,
  /* 28 */ -138, 0,
  /* 30 */ -130, 0,
  /* 32 */ -96, 0,
  /* 34 */ -95, 0,
  /* 36 */ 165, -38, 0,
  /* 39 */ -20, 258, -38, 0,
  /* 43 */ -21, 259, -38, 0,
  /* 47 */ -22, 260, -38, 0,
  /* 51 */ -23, 261, -38, 0,
  /* 55 */ -24, 262, -38, 0,
  /* 59 */ -25, 263, -38, 0,
  /* 63 */ -26, 264, -38, 0,
  /* 67 */ -27, 265, -38, 0,
  /* 71 */ -28, 266, -38, 0,
  /* 75 */ -29, 267, -38, 0,
  /* 79 */ -30, 268, -38, 0,
  /* 83 */ -31, 269, -38, 0,
  /* 87 */ -32, 270, -38, 0,
  /* 91 */ -33, 271, -38, 0,
  /* 95 */ -34, 272, -38, 0,
  /* 99 */ -35, 273, -38, 0,
  /* 103 */ -36, 274, -38, 0,
  /* 107 */ -265, 395, -37, 0,
  /* 111 */ -227, 392, -34, 0,
  /* 115 */ -29, 0,
  /* 117 */ 412, -274, 1, 1, 1, 0,
  /* 123 */ 1, 1, 1, 1, 0,
  /* 128 */ 20, 1, 0,
  /* 131 */ 21, 1, 0,
  /* 134 */ 22, 1, 0,
  /* 137 */ 23, 1, 0,
  /* 140 */ 24, 1, 0,
  /* 143 */ 25, 1, 0,
  /* 146 */ 26, 1, 0,
  /* 149 */ 27, 1, 0,
  /* 152 */ 28, 1, 0,
  /* 155 */ 29, 1, 0,
  /* 158 */ 30, 1, 0,
  /* 161 */ 31, 1, 0,
  /* 164 */ 32, 1, 0,
  /* 167 */ 33, 1, 0,
  /* 170 */ 34, 1, 0,
  /* 173 */ 35, 1, 0,
  /* 176 */ 29, 0,
  /* 178 */ 72, 0,
  /* 180 */ 38, -238, 73, 0,
  /* 184 */ 95, 0,
  /* 186 */ 96, 0,
  /* 188 */ 130, 0,
  /* 190 */ 211, 0,
  /* 192 */ 243, 0,
  /* 194 */ 306, 0,
  /* 196 */ 314, 0,
  /* 198 */ 358, 0,
};

static const uint16_t MipsSubRegIdxLists[] = {
  /* 0 */ 1, 0,
  /* 2 */ 3, 4, 5, 6, 7, 0,
  /* 8 */ 2, 9, 8, 0,
  /* 12 */ 9, 1, 8, 10, 11, 0,
};

static const MCRegisterDesc MipsRegDesc[] = { // Descriptors
  { 5, 0, 0, 0, 0, 0 },
  { 2363, 1, 176, 1, 4096, 11 },
  { 2366, 1, 1, 1, 4097, 11 },
  { 2458, 1, 1, 1, 4098, 11 },
  { 2329, 1, 1, 1, 4099, 11 },
  { 2383, 117, 1, 2, 503812, 2 },
  { 2410, 1, 1, 1, 4105, 11 },
  { 2427, 1, 1, 1, 4106, 11 },
  { 2341, 1, 190, 1, 4107, 11 },
  { 2344, 1, 192, 1, 4108, 11 },
  { 2417, 1, 1, 1, 4109, 11 },
  { 2356, 1, 1, 1, 4110, 11 },
  { 2350, 1, 1, 1, 4111, 11 },
  { 2394, 1, 1, 1, 4112, 11 },
  { 2448, 1, 1, 1, 4113, 11 },
  { 2437, 1, 1, 1, 4114, 11 },
  { 2375, 1, 1, 1, 4115, 11 },
  { 2401, 1, 1, 1, 4116, 11 },
  { 2326, 1, 1, 1, 4117, 11 },
  { 2323, 1, 194, 1, 4118, 11 },
  { 2347, 1, 196, 1, 4119, 11 },
  { 2336, 1, 198, 1, 4120, 11 },
  { 197, 1, 198, 1, 4121, 11 },
  { 455, 1, 198, 1, 4122, 11 },
  { 659, 1, 198, 1, 4123, 11 },
  { 857, 1, 198, 1, 4124, 11 },
  { 200, 68, 198, 9, 495645, 8 },
  { 458, 68, 1, 9, 495647, 8 },
  { 662, 68, 1, 9, 495649, 8 },
  { 860, 68, 1, 9, 495651, 8 },
  { 1457, 115, 1, 0, 4096, 0 },
  { 0, 1, 1, 1, 4133, 11 },
  { 258, 1, 1, 1, 4134, 11 },
  { 516, 1, 1, 1, 4135, 11 },
  { 714, 1, 1, 1, 4136, 11 },
  { 904, 1, 1, 1, 4137, 11 },
  { 1499, 1, 1, 1, 4138, 11 },
  { 1665, 1, 1, 1, 4139, 11 },
  { 1827, 1, 1, 1, 4140, 11 },
  { 1989, 1, 1, 1, 4141, 11 },
  { 2148, 1, 1, 1, 4142, 11 },
  { 102, 1, 1, 1, 4143, 11 },
  { 360, 1, 1, 1, 4144, 11 },
  { 618, 1, 1, 1, 4145, 11 },
  { 816, 1, 1, 1, 4146, 11 },
  { 1006, 1, 1, 1, 4147, 11 },
  { 1601, 1, 1, 1, 4148, 11 },
  { 1763, 1, 1, 1, 4149, 11 },
  { 1925, 1, 1, 1, 4150, 11 },
  { 2087, 1, 1, 1, 4151, 11 },
  { 2262, 1, 1, 1, 4152, 11 },
  { 175, 1, 1, 1, 4153, 11 },
  { 433, 1, 1, 1, 4154, 11 },
  { 653, 1, 1, 1, 4155, 11 },
  { 851, 1, 1, 1, 4156, 11 },
  { 1028, 1, 1, 1, 4157, 11 },
  { 1623, 1, 1, 1, 4158, 11 },
  { 1785, 1, 1, 1, 4159, 11 },
  { 1947, 1, 1, 1, 4160, 11 },
  { 2109, 1, 1, 1, 4161, 11 },
  { 2284, 1, 1, 1, 4162, 11 },
  { 6, 1, 1, 1, 4163, 11 },
  { 264, 1, 1, 1, 4164, 11 },
  { 522, 1, 1, 1, 4165, 11 },
  { 720, 1, 1, 1, 4166, 11 },
  { 910, 1, 1, 1, 4167, 11 },
  { 1505, 1, 1, 1, 4168, 11 },
  { 1671, 1, 1, 1, 4169, 11 },
  { 1833, 1, 1, 1, 4170, 11 },
  { 1995, 1, 1, 1, 4171, 11 },
  { 2154, 1, 1, 1, 4172, 11 },
  { 64, 1, 1, 1, 4173, 11 },
  { 322, 1, 1, 1, 4174, 11 },
  { 580, 1, 1, 1, 4175, 11 },
  { 778, 1, 1, 1, 4176, 11 },
  { 968, 1, 1, 1, 4177, 11 },
  { 1563, 1, 1, 1, 4178, 11 },
  { 1725, 1, 1, 1, 4179, 11 },
  { 1887, 1, 1, 1, 4180, 11 },
  { 2049, 1, 1, 1, 4181, 11 },
  { 2224, 1, 1, 1, 4182, 11 },
  { 137, 1, 1, 1, 4183, 11 },
  { 395, 1, 1, 1, 4184, 11 },
  { 13, 1, 1, 1, 4185, 11 },
  { 271, 1, 1, 1, 4186, 11 },
  { 529, 1, 1, 1, 4187, 11 },
  { 727, 1, 1, 1, 4188, 11 },
  { 917, 1, 1, 1, 4189, 11 },
  { 1512, 1, 1, 1, 4190, 11 },
  { 1678, 1, 1, 1, 4191, 11 },
  { 1840, 1, 1, 1, 4192, 11 },
  { 2002, 1, 1, 1, 4193, 11 },
  { 2161, 1, 1, 1, 4194, 11 },
  { 71, 1, 1, 1, 4195, 11 },
  { 329, 1, 1, 1, 4196, 11 },
  { 587, 1, 1, 1, 4197, 11 },
  { 785, 1, 1, 1, 4198, 11 },
  { 975, 1, 1, 1, 4199, 11 },
  { 1570, 1, 1, 1, 4200, 11 },
  { 1732, 1, 1, 1, 4201, 11 },
  { 1894, 1, 1, 1, 4202, 11 },
  { 2056, 1, 1, 1, 4203, 11 },
  { 2231, 1, 1, 1, 4204, 11 },
  { 144, 1, 1, 1, 4205, 11 },
  { 402, 1, 1, 1, 4206, 11 },
  { 20, 1, 1, 1, 4207, 11 },
  { 278, 1, 1, 1, 4208, 11 },
  { 536, 1, 1, 1, 4209, 11 },
  { 734, 1, 1, 1, 4210, 11 },
  { 924, 1, 1, 1, 4211, 11 },
  { 1519, 1, 1, 1, 4212, 11 },
  { 1685, 1, 1, 1, 4213, 11 },
  { 1847, 1, 1, 1, 4214, 11 },
  { 2009, 1, 1, 1, 4215, 11 },
  { 2168, 1, 1, 1, 4216, 11 },
  { 78, 1, 1, 1, 4217, 11 },
  { 336, 1, 1, 1, 4218, 11 },
  { 594, 1, 1, 1, 4219, 11 },
  { 792, 1, 1, 1, 4220, 11 },
  { 982, 1, 1, 1, 4221, 11 },
  { 1577, 1, 1, 1, 4222, 11 },
  { 1739, 1, 1, 1, 4223, 11 },
  { 1901, 1, 1, 1, 4224, 11 },
  { 2063, 1, 1, 1, 4225, 11 },
  { 2238, 1, 1, 1, 4226, 11 },
  { 151, 1, 1, 1, 4227, 11 },
  { 409, 1, 1, 1, 4228, 11 },
  { 209, 128, 1, 9, 495749, 8 },
  { 467, 131, 1, 9, 495751, 8 },
  { 671, 134, 1, 9, 495753, 8 },
  { 869, 137, 1, 9, 495755, 8 },
  { 1468, 140, 1, 9, 495757, 8 },
  { 1634, 143, 1, 9, 495759, 8 },
  { 1796, 146, 1, 9, 495761, 8 },
  { 1958, 149, 1, 9, 495763, 8 },
  { 2120, 152, 1, 9, 495765, 8 },
  { 2295, 155, 1, 9, 495767, 8 },
  { 33, 158, 1, 9, 495769, 8 },
  { 291, 161, 1, 9, 495771, 8 },
  { 549, 164, 1, 9, 495773, 8 },
  { 747, 167, 1, 9, 495775, 8 },
  { 937, 170, 1, 9, 495777, 8 },
  { 1532, 173, 1, 9, 495779, 8 },
  { 124, 1, 28, 1, 4101, 11 },
  { 382, 1, 26, 1, 4102, 11 },
  { 640, 1, 24, 1, 4103, 11 },
  { 838, 1, 22, 1, 4104, 11 },
  { 212, 1, 39, 1, 4229, 11 },
  { 470, 1, 43, 1, 4230, 11 },
  { 674, 1, 43, 1, 4231, 11 },
  { 872, 1, 47, 1, 4232, 11 },
  { 1471, 1, 47, 1, 4233, 11 },
  { 1637, 1, 51, 1, 4234, 11 },
  { 1799, 1, 51, 1, 4235, 11 },
  { 1961, 1, 55, 1, 4236, 11 },
  { 2123, 1, 55, 1, 4237, 11 },
  { 2298, 1, 59, 1, 4238, 11 },
  { 37, 1, 59, 1, 4239, 11 },
  { 295, 1, 63, 1, 4240, 11 },
  { 553, 1, 63, 1, 4241, 11 },
  { 751, 1, 67, 1, 4242, 11 },
  { 941, 1, 67, 1, 4243, 11 },
  { 1536, 1, 71, 1, 4244, 11 },
  { 1698, 1, 71, 1, 4245, 11 },
  { 1860, 1, 75, 1, 4246, 11 },
  { 2022, 1, 75, 1, 4247, 11 },
  { 2181, 1, 79, 1, 4248, 11 },
  { 91, 1, 79, 1, 4249, 11 },
  { 349, 1, 83, 1, 4250, 11 },
  { 607, 1, 83, 1, 4251, 11 },
  { 805, 1, 87, 1, 4252, 11 },
  { 995, 1, 87, 1, 4253, 11 },
  { 1590, 1, 91, 1, 4254, 11 },
  { 1752, 1, 91, 1, 4255, 11 },
  { 1914, 1, 95, 1, 4256, 11 },
  { 2076, 1, 95, 1, 4257, 11 },
  { 2251, 1, 99, 1, 4258, 11 },
  { 164, 1, 99, 1, 4259, 11 },
  { 422, 1, 103, 1, 4260, 11 },
  { 204, 1, 1, 1, 4261, 11 },
  { 462, 1, 1, 1, 4262, 11 },
  { 666, 1, 1, 1, 4263, 11 },
  { 864, 1, 1, 1, 4264, 11 },
  { 1463, 1, 1, 1, 4265, 11 },
  { 1629, 1, 1, 1, 4266, 11 },
  { 1791, 1, 1, 1, 4267, 11 },
  { 1953, 1, 1, 1, 4268, 11 },
  { 236, 1, 1, 1, 4269, 11 },
  { 494, 1, 1, 1, 4270, 11 },
  { 695, 1, 1, 1, 4271, 11 },
  { 885, 1, 1, 1, 4272, 11 },
  { 1480, 1, 1, 1, 4273, 11 },
  { 1646, 1, 1, 1, 4274, 11 },
  { 1808, 1, 1, 1, 4275, 11 },
  { 1970, 1, 1, 1, 4276, 11 },
  { 2132, 1, 1, 1, 4277, 11 },
  { 2307, 1, 1, 1, 4278, 11 },
  { 48, 1, 1, 1, 4279, 11 },
  { 306, 1, 1, 1, 4280, 11 },
  { 564, 1, 1, 1, 4281, 11 },
  { 762, 1, 1, 1, 4282, 11 },
  { 952, 1, 1, 1, 4283, 11 },
  { 1547, 1, 1, 1, 4284, 11 },
  { 1709, 1, 1, 1, 4285, 11 },
  { 1871, 1, 1, 1, 4286, 11 },
  { 2033, 1, 1, 1, 4287, 11 },
  { 2192, 1, 1, 1, 4288, 11 },
  { 108, 1, 1, 1, 4289, 11 },
  { 366, 1, 1, 1, 4290, 11 },
  { 624, 1, 1, 1, 4291, 11 },
  { 822, 1, 1, 1, 4292, 11 },
  { 1012, 1, 1, 1, 4293, 11 },
  { 1607, 1, 1, 1, 4294, 11 },
  { 1769, 1, 1, 1, 4295, 11 },
  { 1931, 1, 1, 1, 4296, 11 },
  { 2093, 1, 1, 1, 4297, 11 },
  { 2268, 1, 1, 1, 4298, 11 },
  { 181, 1, 1, 1, 4299, 11 },
  { 439, 1, 1, 1, 4300, 11 },
  { 1439, 18, 1, 0, 4107, 0 },
  { 215, 1, 36, 1, 4301, 11 },
  { 473, 1, 36, 1, 4302, 11 },
  { 677, 1, 36, 1, 4303, 11 },
  { 875, 1, 36, 1, 4304, 11 },
  { 1474, 1, 36, 1, 4305, 11 },
  { 1640, 1, 36, 1, 4306, 11 },
  { 1802, 1, 36, 1, 4307, 11 },
  { 1964, 1, 36, 1, 4308, 11 },
  { 2126, 1, 36, 1, 4309, 11 },
  { 2301, 1, 36, 1, 4310, 11 },
  { 41, 1, 36, 1, 4311, 11 },
  { 299, 1, 36, 1, 4312, 11 },
  { 557, 1, 36, 1, 4313, 11 },
  { 755, 1, 36, 1, 4314, 11 },
  { 945, 1, 36, 1, 4315, 11 },
  { 1540, 1, 36, 1, 4316, 11 },
  { 1702, 1, 36, 1, 4317, 11 },
  { 1864, 1, 36, 1, 4318, 11 },
  { 2026, 1, 36, 1, 4319, 11 },
  { 2185, 1, 36, 1, 4320, 11 },
  { 95, 1, 36, 1, 4321, 11 },
  { 353, 1, 36, 1, 4322, 11 },
  { 611, 1, 36, 1, 4323, 11 },
  { 809, 1, 36, 1, 4324, 11 },
  { 999, 1, 36, 1, 4325, 11 },
  { 1594, 1, 36, 1, 4326, 11 },
  { 1756, 1, 36, 1, 4327, 11 },
  { 1918, 1, 36, 1, 4328, 11 },
  { 2080, 1, 36, 1, 4329, 11 },
  { 2255, 1, 36, 1, 4330, 11 },
  { 168, 1, 36, 1, 4331, 11 },
  { 426, 1, 36, 1, 4332, 11 },
  { 1445, 10, 1, 0, 4108, 0 },
  { 217, 1, 111, 1, 4126, 11 },
  { 475, 1, 16, 1, 4128, 11 },
  { 679, 1, 16, 1, 4130, 11 },
  { 877, 1, 16, 1, 4132, 11 },
  { 241, 1, 1, 1, 4333, 11 },
  { 499, 1, 1, 1, 4334, 11 },
  { 700, 1, 1, 1, 4335, 11 },
  { 890, 1, 1, 1, 4336, 11 },
  { 1485, 1, 1, 1, 4337, 11 },
  { 1651, 1, 1, 1, 4338, 11 },
  { 1813, 1, 1, 1, 4339, 11 },
  { 1975, 1, 1, 1, 4340, 11 },
  { 2137, 1, 1, 1, 4341, 11 },
  { 2312, 1, 1, 1, 4342, 11 },
  { 54, 1, 1, 1, 4343, 11 },
  { 312, 1, 1, 1, 4344, 11 },
  { 570, 1, 1, 1, 4345, 11 },
  { 768, 1, 1, 1, 4346, 11 },
  { 958, 1, 1, 1, 4347, 11 },
  { 1553, 1, 1, 1, 4348, 11 },
  { 1715, 1, 1, 1, 4349, 11 },
  { 1877, 1, 1, 1, 4350, 11 },
  { 2039, 1, 1, 1, 4351, 11 },
  { 2198, 1, 1, 1, 4352, 11 },
  { 114, 1, 1, 1, 4353, 11 },
  { 372, 1, 1, 1, 4354, 11 },
  { 630, 1, 1, 1, 4355, 11 },
  { 828, 1, 1, 1, 4356, 11 },
  { 1018, 1, 1, 1, 4357, 11 },
  { 1613, 1, 1, 1, 4358, 11 },
  { 1775, 1, 1, 1, 4359, 11 },
  { 1937, 1, 1, 1, 4360, 11 },
  { 2099, 1, 1, 1, 4361, 11 },
  { 2274, 1, 1, 1, 4362, 11 },
  { 187, 1, 1, 1, 4363, 11 },
  { 445, 1, 1, 1, 4364, 11 },
  { 221, 1, 188, 1, 4365, 11 },
  { 479, 1, 188, 1, 4366, 11 },
  { 229, 1, 107, 1, 4125, 11 },
  { 487, 1, 8, 1, 4127, 11 },
  { 688, 1, 8, 1, 4129, 11 },
  { 881, 1, 8, 1, 4131, 11 },
  { 224, 1, 1, 1, 4367, 11 },
  { 482, 1, 1, 1, 4368, 11 },
  { 683, 1, 1, 1, 4369, 11 },
  { 2115, 1, 1, 1, 4370, 11 },
  { 2290, 1, 1, 1, 4371, 11 },
  { 27, 1, 1, 1, 4372, 11 },
  { 285, 1, 1, 1, 4373, 11 },
  { 543, 1, 1, 1, 4374, 11 },
  { 741, 1, 1, 1, 4375, 11 },
  { 931, 1, 1, 1, 4376, 11 },
  { 1526, 1, 1, 1, 4377, 11 },
  { 1692, 1, 1, 1, 4378, 11 },
  { 1854, 1, 1, 1, 4379, 11 },
  { 2016, 1, 1, 1, 4380, 11 },
  { 2175, 1, 1, 1, 4381, 11 },
  { 85, 1, 1, 1, 4382, 11 },
  { 343, 1, 1, 1, 4383, 11 },
  { 601, 1, 1, 1, 4384, 11 },
  { 799, 1, 1, 1, 4385, 11 },
  { 989, 1, 1, 1, 4386, 11 },
  { 1584, 1, 1, 1, 4387, 11 },
  { 1746, 1, 1, 1, 4388, 11 },
  { 1908, 1, 1, 1, 4389, 11 },
  { 2070, 1, 1, 1, 4390, 11 },
  { 2245, 1, 1, 1, 4391, 11 },
  { 158, 1, 1, 1, 4392, 11 },
  { 416, 1, 1, 1, 4393, 11 },
  { 233, 1, 1, 1, 4394, 11 },
  { 491, 1, 1, 1, 4395, 11 },
  { 692, 1, 1, 1, 4396, 11 },
  { 1425, 6, 1, 0, 4118, 0 },
  { 246, 1, 186, 1, 4397, 11 },
  { 504, 1, 186, 1, 4398, 11 },
  { 705, 1, 186, 1, 4399, 11 },
  { 895, 1, 186, 1, 4400, 11 },
  { 1490, 1, 186, 1, 4401, 11 },
  { 1656, 1, 186, 1, 4402, 11 },
  { 1818, 1, 186, 1, 4403, 11 },
  { 1980, 1, 186, 1, 4404, 11 },
  { 1451, 4, 1, 0, 4119, 0 },
  { 249, 1, 184, 1, 4405, 11 },
  { 507, 1, 184, 1, 4406, 11 },
  { 708, 1, 184, 1, 4407, 11 },
  { 898, 1, 184, 1, 4408, 11 },
  { 1493, 1, 184, 1, 4409, 11 },
  { 1659, 1, 184, 1, 4410, 11 },
  { 1821, 1, 184, 1, 4411, 11 },
  { 1983, 1, 184, 1, 4412, 11 },
  { 2142, 1, 184, 1, 4413, 11 },
  { 2317, 1, 184, 1, 4414, 11 },
  { 252, 1, 184, 1, 4415, 11 },
  { 510, 1, 184, 1, 4416, 11 },
  { 255, 180, 1, 8, 729221, 8 },
  { 513, 180, 1, 8, 729222, 8 },
  { 711, 180, 1, 8, 729223, 8 },
  { 901, 180, 1, 8, 729224, 8 },
  { 1496, 180, 1, 8, 729225, 8 },
  { 1662, 180, 1, 8, 729226, 8 },
  { 1824, 180, 1, 8, 729227, 8 },
  { 1986, 180, 1, 8, 729228, 8 },
  { 2145, 180, 1, 8, 729229, 8 },
  { 2320, 180, 1, 8, 729230, 8 },
  { 60, 180, 1, 8, 729231, 8 },
  { 318, 180, 1, 8, 729232, 8 },
  { 576, 180, 1, 8, 729233, 8 },
  { 774, 180, 1, 8, 729234, 8 },
  { 964, 180, 1, 8, 729235, 8 },
  { 1559, 180, 1, 8, 729236, 8 },
  { 1721, 180, 1, 8, 729237, 8 },
  { 1883, 180, 1, 8, 729238, 8 },
  { 2045, 180, 1, 8, 729239, 8 },
  { 2204, 180, 1, 8, 729240, 8 },
  { 120, 180, 1, 8, 729241, 8 },
  { 378, 180, 1, 8, 729242, 8 },
  { 636, 180, 1, 8, 729243, 8 },
  { 834, 180, 1, 8, 729244, 8 },
  { 1024, 180, 1, 8, 729245, 8 },
  { 1619, 180, 1, 8, 729246, 8 },
  { 1781, 180, 1, 8, 729247, 8 },
  { 1943, 180, 1, 8, 729248, 8 },
  { 2105, 180, 1, 8, 729249, 8 },
  { 2280, 180, 1, 8, 729250, 8 },
  { 193, 180, 1, 8, 729251, 8 },
  { 451, 180, 1, 8, 729252, 8 },
  { 1431, 2, 1, 0, 4120, 0 },
  { 1055, 2, 1, 0, 4121, 0 },
  { 1133, 2, 1, 0, 4122, 0 },
  { 1183, 2, 1, 0, 4123, 0 },
  { 1221, 2, 1, 0, 4124, 0 },
  { 1061, 12, 1, 12, 495645, 8 },
  { 1068, 181, 37, 9, 729221, 8 },
  { 1139, 181, 37, 9, 729222, 8 },
  { 1189, 181, 37, 9, 729223, 8 },
  { 1227, 181, 37, 9, 729224, 8 },
  { 1259, 181, 37, 9, 729225, 8 },
  { 1291, 181, 37, 9, 729226, 8 },
  { 1323, 181, 37, 9, 729227, 8 },
  { 1355, 181, 37, 9, 729228, 8 },
  { 1387, 181, 37, 9, 729229, 8 },
  { 1413, 181, 37, 9, 729230, 8 },
  { 1034, 181, 37, 9, 729231, 8 },
  { 1112, 181, 37, 9, 729232, 8 },
  { 1169, 181, 37, 9, 729233, 8 },
  { 1207, 181, 37, 9, 729234, 8 },
  { 1245, 181, 37, 9, 729235, 8 },
  { 1277, 181, 37, 9, 729236, 8 },
  { 1309, 181, 37, 9, 729237, 8 },
  { 1341, 181, 37, 9, 729238, 8 },
  { 1373, 181, 37, 9, 729239, 8 },
  { 1399, 181, 37, 9, 729240, 8 },
  { 1041, 181, 37, 9, 729241, 8 },
  { 1119, 181, 37, 9, 729242, 8 },
  { 1176, 181, 37, 9, 729243, 8 },
  { 1214, 181, 37, 9, 729244, 8 },
  { 1252, 181, 37, 9, 729245, 8 },
  { 1284, 181, 37, 9, 729246, 8 },
  { 1316, 181, 37, 9, 729247, 8 },
  { 1348, 181, 37, 9, 729248, 8 },
  { 1380, 181, 37, 9, 729249, 8 },
  { 1406, 181, 37, 9, 729250, 8 },
  { 1048, 181, 37, 9, 729251, 8 },
  { 1126, 181, 37, 9, 729252, 8 },
  { 2208, 1, 0, 1, 4100, 11 },
  { 1074, 20, 113, 0, 4126, 0 },
  { 1081, 30, 1, 0, 4365, 0 },
  { 1145, 30, 1, 0, 4366, 0 },
  { 1087, 30, 109, 0, 4125, 0 },
  { 1094, 32, 1, 0, 4397, 0 },
  { 1151, 32, 1, 0, 4398, 0 },
  { 1195, 32, 1, 0, 4399, 0 },
  { 1233, 32, 1, 0, 4400, 0 },
  { 1265, 32, 1, 0, 4401, 0 },
  { 1297, 32, 1, 0, 4402, 0 },
  { 1329, 32, 1, 0, 4403, 0 },
  { 1361, 32, 1, 0, 4404, 0 },
  { 1100, 34, 1, 0, 4405, 0 },
  { 1157, 34, 1, 0, 4406, 0 },
  { 1201, 34, 1, 0, 4407, 0 },
  { 1239, 34, 1, 0, 4408, 0 },
  { 1271, 34, 1, 0, 4409, 0 },
  { 1303, 34, 1, 0, 4410, 0 },
  { 1335, 34, 1, 0, 4411, 0 },
  { 1367, 34, 1, 0, 4412, 0 },
  { 1393, 34, 1, 0, 4413, 0 },
  { 1419, 34, 1, 0, 4414, 0 },
  { 1106, 34, 1, 0, 4415, 0 },
  { 1163, 34, 1, 0, 4416, 0 },
};

  // MSA128F16 Register Class...
  static const MCPhysReg MSA128F16[] = {
    Mips_W0, Mips_W1, Mips_W2, Mips_W3, Mips_W4, Mips_W5, Mips_W6, Mips_W7, Mips_W8, Mips_W9, Mips_W10, Mips_W11, Mips_W12, Mips_W13, Mips_W14, Mips_W15, Mips_W16, Mips_W17, Mips_W18, Mips_W19, Mips_W20, Mips_W21, Mips_W22, Mips_W23, Mips_W24, Mips_W25, Mips_W26, Mips_W27, Mips_W28, Mips_W29, Mips_W30, Mips_W31, 
  };

  // MSA128F16 Bit set.
  static const uint8_t MSA128F16Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // CCR Register Class...
  static const MCPhysReg CCR[] = {
    Mips_FCR0, Mips_FCR1, Mips_FCR2, Mips_FCR3, Mips_FCR4, Mips_FCR5, Mips_FCR6, Mips_FCR7, Mips_FCR8, Mips_FCR9, Mips_FCR10, Mips_FCR11, Mips_FCR12, Mips_FCR13, Mips_FCR14, Mips_FCR15, Mips_FCR16, Mips_FCR17, Mips_FCR18, Mips_FCR19, Mips_FCR20, Mips_FCR21, Mips_FCR22, Mips_FCR23, Mips_FCR24, Mips_FCR25, Mips_FCR26, Mips_FCR27, Mips_FCR28, Mips_FCR29, Mips_FCR30, Mips_FCR31, 
  };

  // CCR Bit set.
  static const uint8_t CCRBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // COP0 Register Class...
  static const MCPhysReg COP0[] = {
    Mips_COP00, Mips_COP01, Mips_COP02, Mips_COP03, Mips_COP04, Mips_COP05, Mips_COP06, Mips_COP07, Mips_COP08, Mips_COP09, Mips_COP010, Mips_COP011, Mips_COP012, Mips_COP013, Mips_COP014, Mips_COP015, Mips_COP016, Mips_COP017, Mips_COP018, Mips_COP019, Mips_COP020, Mips_COP021, Mips_COP022, Mips_COP023, Mips_COP024, Mips_COP025, Mips_COP026, Mips_COP027, Mips_COP028, Mips_COP029, Mips_COP030, Mips_COP031, 
  };

  // COP0 Bit set.
  static const uint8_t COP0Bits[] = {
    0x00, 0x00, 0x00, 0x80, 0xff, 0x01, 0x00, 0xe0, 0xff, 0xff, 0x07, 
  };

  // COP2 Register Class...
  static const MCPhysReg COP2[] = {
    Mips_COP20, Mips_COP21, Mips_COP22, Mips_COP23, Mips_COP24, Mips_COP25, Mips_COP26, Mips_COP27, Mips_COP28, Mips_COP29, Mips_COP210, Mips_COP211, Mips_COP212, Mips_COP213, Mips_COP214, Mips_COP215, Mips_COP216, Mips_COP217, Mips_COP218, Mips_COP219, Mips_COP220, Mips_COP221, Mips_COP222, Mips_COP223, Mips_COP224, Mips_COP225, Mips_COP226, Mips_COP227, Mips_COP228, Mips_COP229, Mips_COP230, Mips_COP231, 
  };

  // COP2 Bit set.
  static const uint8_t COP2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x07, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0x01, 
  };

  // COP3 Register Class...
  static const MCPhysReg COP3[] = {
    Mips_COP30, Mips_COP31, Mips_COP32, Mips_COP33, Mips_COP34, Mips_COP35, Mips_COP36, Mips_COP37, Mips_COP38, Mips_COP39, Mips_COP310, Mips_COP311, Mips_COP312, Mips_COP313, Mips_COP314, Mips_COP315, Mips_COP316, Mips_COP317, Mips_COP318, Mips_COP319, Mips_COP320, Mips_COP321, Mips_COP322, Mips_COP323, Mips_COP324, Mips_COP325, Mips_COP326, Mips_COP327, Mips_COP328, Mips_COP329, Mips_COP330, Mips_COP331, 
  };

  // COP3 Bit set.
  static const uint8_t COP3Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0x7f, 
  };

  // DSPR Register Class...
  static const MCPhysReg DSPR[] = {
    Mips_ZERO, Mips_AT, Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, Mips_T0, Mips_T1, Mips_T2, Mips_T3, Mips_T4, Mips_T5, Mips_T6, Mips_T7, Mips_S0, Mips_S1, Mips_S2, Mips_S3, Mips_S4, Mips_S5, Mips_S6, Mips_S7, Mips_T8, Mips_T9, Mips_K0, Mips_K1, Mips_GP, Mips_SP, Mips_FP, Mips_RA, 
  };

  // DSPR Bit set.
  static const uint8_t DSPRBits[] = {
    0x02, 0x03, 0xf8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0xc0, 0xbf, 0xff, 0x07, 
  };

  // FGR32 Register Class...
  static const MCPhysReg FGR32[] = {
    Mips_F0, Mips_F1, Mips_F2, Mips_F3, Mips_F4, Mips_F5, Mips_F6, Mips_F7, Mips_F8, Mips_F9, Mips_F10, Mips_F11, Mips_F12, Mips_F13, Mips_F14, Mips_F15, Mips_F16, Mips_F17, Mips_F18, Mips_F19, Mips_F20, Mips_F21, Mips_F22, Mips_F23, Mips_F24, Mips_F25, Mips_F26, Mips_F27, Mips_F28, Mips_F29, Mips_F30, Mips_F31, 
  };

  // FGR32 Bit set.
  static const uint8_t FGR32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // FGRCC Register Class...
  static const MCPhysReg FGRCC[] = {
    Mips_F0, Mips_F1, Mips_F2, Mips_F3, Mips_F4, Mips_F5, Mips_F6, Mips_F7, Mips_F8, Mips_F9, Mips_F10, Mips_F11, Mips_F12, Mips_F13, Mips_F14, Mips_F15, Mips_F16, Mips_F17, Mips_F18, Mips_F19, Mips_F20, Mips_F21, Mips_F22, Mips_F23, Mips_F24, Mips_F25, Mips_F26, Mips_F27, Mips_F28, Mips_F29, Mips_F30, Mips_F31, 
  };

  // FGRCC Bit set.
  static const uint8_t FGRCCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // GPR32 Register Class...
  static const MCPhysReg GPR32[] = {
    Mips_ZERO, Mips_AT, Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, Mips_T0, Mips_T1, Mips_T2, Mips_T3, Mips_T4, Mips_T5, Mips_T6, Mips_T7, Mips_S0, Mips_S1, Mips_S2, Mips_S3, Mips_S4, Mips_S5, Mips_S6, Mips_S7, Mips_T8, Mips_T9, Mips_K0, Mips_K1, Mips_GP, Mips_SP, Mips_FP, Mips_RA, 
  };

  // GPR32 Bit set.
  static const uint8_t GPR32Bits[] = {
    0x02, 0x03, 0xf8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0xc0, 0xbf, 0xff, 0x07, 
  };

  // HWRegs Register Class...
  static const MCPhysReg HWRegs[] = {
    Mips_HWR0, Mips_HWR1, Mips_HWR2, Mips_HWR3, Mips_HWR4, Mips_HWR5, Mips_HWR6, Mips_HWR7, Mips_HWR8, Mips_HWR9, Mips_HWR10, Mips_HWR11, Mips_HWR12, Mips_HWR13, Mips_HWR14, Mips_HWR15, Mips_HWR16, Mips_HWR17, Mips_HWR18, Mips_HWR19, Mips_HWR20, Mips_HWR21, Mips_HWR22, Mips_HWR23, Mips_HWR24, Mips_HWR25, Mips_HWR26, Mips_HWR27, Mips_HWR28, Mips_HWR29, Mips_HWR30, Mips_HWR31, 
  };

  // HWRegs Bit set.
  static const uint8_t HWRegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01, 
  };

  // MSACtrl Register Class...
  static const MCPhysReg MSACtrl[] = {
    Mips_MSAIR, Mips_MSACSR, Mips_MSAAccess, Mips_MSASave, Mips_MSAModify, Mips_MSARequest, Mips_MSAMap, Mips_MSAUnmap, Mips_MSA8, Mips_MSA9, Mips_MSA10, Mips_MSA11, Mips_MSA12, Mips_MSA13, Mips_MSA14, Mips_MSA15, Mips_MSA16, Mips_MSA17, Mips_MSA18, Mips_MSA19, Mips_MSA20, Mips_MSA21, Mips_MSA22, Mips_MSA23, Mips_MSA24, Mips_MSA25, Mips_MSA26, Mips_MSA27, Mips_MSA28, Mips_MSA29, Mips_MSA30, Mips_MSA31, 
  };

  // MSACtrl Bit set.
  static const uint8_t MSACtrlBits[] = {
    0x00, 0xfc, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0xff, 0xff, 0x03, 
  };

  // GPR32NONZERO Register Class...
  static const MCPhysReg GPR32NONZERO[] = {
    Mips_AT, Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, Mips_T0, Mips_T1, Mips_T2, Mips_T3, Mips_T4, Mips_T5, Mips_T6, Mips_T7, Mips_S0, Mips_S1, Mips_S2, Mips_S3, Mips_S4, Mips_S5, Mips_S6, Mips_S7, Mips_T8, Mips_T9, Mips_K0, Mips_K1, Mips_GP, Mips_SP, Mips_FP, Mips_RA, 
  };

  // GPR32NONZERO Bit set.
  static const uint8_t GPR32NONZEROBits[] = {
    0x02, 0x03, 0xd8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0xc0, 0xbf, 0xff, 0x07, 
  };

  // CPU16RegsPlusSP Register Class...
  static const MCPhysReg CPU16RegsPlusSP[] = {
    Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, Mips_S0, Mips_S1, Mips_SP, 
  };

  // CPU16RegsPlusSP Bit set.
  static const uint8_t CPU16RegsPlusSPBits[] = {
    0x00, 0x00, 0xd0, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x06, 
  };

  // CPU16Regs Register Class...
  static const MCPhysReg CPU16Regs[] = {
    Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, Mips_S0, Mips_S1, 
  };

  // CPU16Regs Bit set.
  static const uint8_t CPU16RegsBits[] = {
    0x00, 0x00, 0xc0, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x06, 
  };

  // FCC Register Class...
  static const MCPhysReg FCC[] = {
    Mips_FCC0, Mips_FCC1, Mips_FCC2, Mips_FCC3, Mips_FCC4, Mips_FCC5, Mips_FCC6, Mips_FCC7, 
  };

  // FCC Bit set.
  static const uint8_t FCCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x07, 
  };

  // GPRMM16 Register Class...
  static const MCPhysReg GPRMM16[] = {
    Mips_S0, Mips_S1, Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, 
  };

  // GPRMM16 Bit set.
  static const uint8_t GPRMM16Bits[] = {
    0x00, 0x00, 0xc0, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x06, 
  };

  // GPRMM16MoveP Register Class...
  static const MCPhysReg GPRMM16MoveP[] = {
    Mips_ZERO, Mips_S1, Mips_V0, Mips_V1, Mips_S0, Mips_S2, Mips_S3, Mips_S4, 
  };

  // GPRMM16MoveP Bit set.
  static const uint8_t GPRMM16MovePBits[] = {
    0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x07, 0x00, 0x06, 
  };

  // GPRMM16Zero Register Class...
  static const MCPhysReg GPRMM16Zero[] = {
    Mips_ZERO, Mips_S1, Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, 
  };

  // GPRMM16Zero Bit set.
  static const uint8_t GPRMM16ZeroBits[] = {
    0x00, 0x00, 0xe0, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x06, 
  };

  // CPU16Regs_and_GPRMM16Zero Register Class...
  static const MCPhysReg CPU16Regs_and_GPRMM16Zero[] = {
    Mips_S1, Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, 
  };

  // CPU16Regs_and_GPRMM16Zero Bit set.
  static const uint8_t CPU16Regs_and_GPRMM16ZeroBits[] = {
    0x00, 0x00, 0xc0, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x06, 
  };

  // GPR32NONZERO_and_GPRMM16MoveP Register Class...
  static const MCPhysReg GPR32NONZERO_and_GPRMM16MoveP[] = {
    Mips_S1, Mips_V0, Mips_V1, Mips_S0, Mips_S2, Mips_S3, Mips_S4, 
  };

  // GPR32NONZERO_and_GPRMM16MoveP Bit set.
  static const uint8_t GPR32NONZERO_and_GPRMM16MovePBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x07, 0x00, 0x06, 
  };

  // GPRMM16MovePPairSecond Register Class...
  static const MCPhysReg GPRMM16MovePPairSecond[] = {
    Mips_A1, Mips_A2, Mips_A3, Mips_S5, Mips_S6, 
  };

  // GPRMM16MovePPairSecond Bit set.
  static const uint8_t GPRMM16MovePPairSecondBits[] = {
    0x00, 0x00, 0x80, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 
  };

  // CPU16Regs_and_GPRMM16MoveP Register Class...
  static const MCPhysReg CPU16Regs_and_GPRMM16MoveP[] = {
    Mips_S1, Mips_V0, Mips_V1, Mips_S0, 
  };

  // CPU16Regs_and_GPRMM16MoveP Bit set.
  static const uint8_t CPU16Regs_and_GPRMM16MovePBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x06, 
  };

  // GPRMM16MoveP_and_GPRMM16Zero Register Class...
  static const MCPhysReg GPRMM16MoveP_and_GPRMM16Zero[] = {
    Mips_ZERO, Mips_S1, Mips_V0, Mips_V1, 
  };

  // GPRMM16MoveP_and_GPRMM16Zero Bit set.
  static const uint8_t GPRMM16MoveP_and_GPRMM16ZeroBits[] = {
    0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x06, 
  };

  // HI32DSP Register Class...
  static const MCPhysReg HI32DSP[] = {
    Mips_HI0, Mips_HI1, Mips_HI2, Mips_HI3, 
  };

  // HI32DSP Bit set.
  static const uint8_t HI32DSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x01, 
  };

  // LO32DSP Register Class...
  static const MCPhysReg LO32DSP[] = {
    Mips_LO0, Mips_LO1, Mips_LO2, Mips_LO3, 
  };

  // LO32DSP Bit set.
  static const uint8_t LO32DSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 
  };

  // CPU16Regs_and_GPRMM16MovePPairSecond Register Class...
  static const MCPhysReg CPU16Regs_and_GPRMM16MovePPairSecond[] = {
    Mips_A1, Mips_A2, Mips_A3, 
  };

  // CPU16Regs_and_GPRMM16MovePPairSecond Bit set.
  static const uint8_t CPU16Regs_and_GPRMM16MovePPairSecondBits[] = {
    0x00, 0x00, 0x80, 0x03, 
  };

  // GPRMM16MovePPairFirst Register Class...
  static const MCPhysReg GPRMM16MovePPairFirst[] = {
    Mips_A0, Mips_A1, Mips_A2, 
  };

  // GPRMM16MovePPairFirst Bit set.
  static const uint8_t GPRMM16MovePPairFirstBits[] = {
    0x00, 0x00, 0xc0, 0x01, 
  };

  // GPRMM16MoveP_and_CPU16Regs_and_GPRMM16Zero Register Class...
  static const MCPhysReg GPRMM16MoveP_and_CPU16Regs_and_GPRMM16Zero[] = {
    Mips_S1, Mips_V0, Mips_V1, 
  };

  // GPRMM16MoveP_and_CPU16Regs_and_GPRMM16Zero Bit set.
  static const uint8_t GPRMM16MoveP_and_CPU16Regs_and_GPRMM16ZeroBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x06, 
  };

  // GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecond Register Class...
  static const MCPhysReg GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecond[] = {
    Mips_A1, Mips_A2, 
  };

  // GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecond Bit set.
  static const uint8_t GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecondBits[] = {
    0x00, 0x00, 0x80, 0x01, 
  };

  // CPURAReg Register Class...
  static const MCPhysReg CPURAReg[] = {
    Mips_RA, 
  };

  // CPURAReg Bit set.
  static const uint8_t CPURARegBits[] = {
    0x00, 0x00, 0x08, 
  };

  // CPUSPReg Register Class...
  static const MCPhysReg CPUSPReg[] = {
    Mips_SP, 
  };

  // CPUSPReg Bit set.
  static const uint8_t CPUSPRegBits[] = {
    0x00, 0x00, 0x10, 
  };

  // DSPCC Register Class...
  static const MCPhysReg DSPCC[] = {
    Mips_DSPCCond, 
  };

  // DSPCC Bit set.
  static const uint8_t DSPCCBits[] = {
    0x04, 
  };

  // GP32 Register Class...
  static const MCPhysReg GP32[] = {
    Mips_GP, 
  };

  // GP32 Bit set.
  static const uint8_t GP32Bits[] = {
    0x00, 0x02, 
  };

  // GPR32ZERO Register Class...
  static const MCPhysReg GPR32ZERO[] = {
    Mips_ZERO, 
  };

  // GPR32ZERO Bit set.
  static const uint8_t GPR32ZEROBits[] = {
    0x00, 0x00, 0x20, 
  };

  // HI32 Register Class...
  static const MCPhysReg HI32[] = {
    Mips_HI0, 
  };

  // HI32 Bit set.
  static const uint8_t HI32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 
  };

  // LO32 Register Class...
  static const MCPhysReg LO32[] = {
    Mips_LO0, 
  };

  // LO32 Bit set.
  static const uint8_t LO32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 
  };

  // SP32 Register Class...
  static const MCPhysReg SP32[] = {
    Mips_SP, 
  };

  // SP32 Bit set.
  static const uint8_t SP32Bits[] = {
    0x00, 0x00, 0x10, 
  };

  // FGR64 Register Class...
  static const MCPhysReg FGR64[] = {
    Mips_D0_64, Mips_D1_64, Mips_D2_64, Mips_D3_64, Mips_D4_64, Mips_D5_64, Mips_D6_64, Mips_D7_64, Mips_D8_64, Mips_D9_64, Mips_D10_64, Mips_D11_64, Mips_D12_64, Mips_D13_64, Mips_D14_64, Mips_D15_64, Mips_D16_64, Mips_D17_64, Mips_D18_64, Mips_D19_64, Mips_D20_64, Mips_D21_64, Mips_D22_64, Mips_D23_64, Mips_D24_64, Mips_D25_64, Mips_D26_64, Mips_D27_64, Mips_D28_64, Mips_D29_64, Mips_D30_64, Mips_D31_64, 
  };

  // FGR64 Bit set.
  static const uint8_t FGR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01, 
  };

  // GPR64 Register Class...
  static const MCPhysReg GPR64[] = {
    Mips_ZERO_64, Mips_AT_64, Mips_V0_64, Mips_V1_64, Mips_A0_64, Mips_A1_64, Mips_A2_64, Mips_A3_64, Mips_T0_64, Mips_T1_64, Mips_T2_64, Mips_T3_64, Mips_T4_64, Mips_T5_64, Mips_T6_64, Mips_T7_64, Mips_S0_64, Mips_S1_64, Mips_S2_64, Mips_S3_64, Mips_S4_64, Mips_S5_64, Mips_S6_64, Mips_S7_64, Mips_T8_64, Mips_T9_64, Mips_K0_64, Mips_K1_64, Mips_GP_64, Mips_SP_64, Mips_FP_64, Mips_RA_64, 
  };

  // GPR64 Bit set.
  static const uint8_t GPR64Bits[] = {
    0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x00, 0x00, 0x00, 0x00, 0xd8, 0xff, 0xff, 0x03, 
  };

  // GPR64_with_sub_32_in_GPR32NONZERO Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_GPR32NONZERO[] = {
    Mips_AT_64, Mips_V0_64, Mips_V1_64, Mips_A0_64, Mips_A1_64, Mips_A2_64, Mips_A3_64, Mips_T0_64, Mips_T1_64, Mips_T2_64, Mips_T3_64, Mips_T4_64, Mips_T5_64, Mips_T6_64, Mips_T7_64, Mips_S0_64, Mips_S1_64, Mips_S2_64, Mips_S3_64, Mips_S4_64, Mips_S5_64, Mips_S6_64, Mips_S7_64, Mips_T8_64, Mips_T9_64, Mips_K0_64, Mips_K1_64, Mips_GP_64, Mips_SP_64, Mips_FP_64, Mips_RA_64, 
  };

  // GPR64_with_sub_32_in_GPR32NONZERO Bit set.
  static const uint8_t GPR64_with_sub_32_in_GPR32NONZEROBits[] = {
    0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0xd8, 0xff, 0xff, 0x03, 
  };

  // AFGR64 Register Class...
  static const MCPhysReg AFGR64[] = {
    Mips_D0, Mips_D1, Mips_D2, Mips_D3, Mips_D4, Mips_D5, Mips_D6, Mips_D7, Mips_D8, Mips_D9, Mips_D10, Mips_D11, Mips_D12, Mips_D13, Mips_D14, Mips_D15, 
  };

  // AFGR64 Bit set.
  static const uint8_t AFGR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0x7f, 
  };

  // GPR64_with_sub_32_in_CPU16RegsPlusSP Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_CPU16RegsPlusSP[] = {
    Mips_V0_64, Mips_V1_64, Mips_A0_64, Mips_A1_64, Mips_A2_64, Mips_A3_64, Mips_S0_64, Mips_S1_64, Mips_SP_64, 
  };

  // GPR64_with_sub_32_in_CPU16RegsPlusSP Bit set.
  static const uint8_t GPR64_with_sub_32_in_CPU16RegsPlusSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x03, 
  };

  // GPR64_with_sub_32_in_CPU16Regs Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_CPU16Regs[] = {
    Mips_V0_64, Mips_V1_64, Mips_A0_64, Mips_A1_64, Mips_A2_64, Mips_A3_64, Mips_S0_64, Mips_S1_64, 
  };

  // GPR64_with_sub_32_in_CPU16Regs Bit set.
  static const uint8_t GPR64_with_sub_32_in_CPU16RegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x03, 
  };

  // GPR64_with_sub_32_in_GPRMM16MoveP Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_GPRMM16MoveP[] = {
    Mips_ZERO_64, Mips_V0_64, Mips_V1_64, Mips_S0_64, Mips_S1_64, Mips_S2_64, Mips_S3_64, Mips_S4_64, 
  };

  // GPR64_with_sub_32_in_GPRMM16MoveP Bit set.
  static const uint8_t GPR64_with_sub_32_in_GPRMM16MovePBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x07, 0x00, 0x03, 
  };

  // GPR64_with_sub_32_in_GPRMM16Zero Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_GPRMM16Zero[] = {
    Mips_ZERO_64, Mips_V0_64, Mips_V1_64, Mips_A0_64, Mips_A1_64, Mips_A2_64, Mips_A3_64, Mips_S1_64, 
  };

  // GPR64_with_sub_32_in_GPRMM16Zero Bit set.
  static const uint8_t GPR64_with_sub_32_in_GPRMM16ZeroBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x03, 
  };

  // GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16Zero Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16Zero[] = {
    Mips_V0_64, Mips_V1_64, Mips_A0_64, Mips_A1_64, Mips_A2_64, Mips_A3_64, Mips_S1_64, 
  };

  // GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16Zero Bit set.
  static const uint8_t GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16ZeroBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x03, 
  };

  // GPR64_with_sub_32_in_GPR32NONZERO_and_GPRMM16MoveP Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_GPR32NONZERO_and_GPRMM16MoveP[] = {
    Mips_V0_64, Mips_V1_64, Mips_S0_64, Mips_S1_64, Mips_S2_64, Mips_S3_64, Mips_S4_64, 
  };

  // GPR64_with_sub_32_in_GPR32NONZERO_and_GPRMM16MoveP Bit set.
  static const uint8_t GPR64_with_sub_32_in_GPR32NONZERO_and_GPRMM16MovePBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x07, 0x00, 0x03, 
  };

  // GPR64_with_sub_32_in_GPRMM16MovePPairSecond Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_GPRMM16MovePPairSecond[] = {
    Mips_A1_64, Mips_A2_64, Mips_A3_64, Mips_S5_64, Mips_S6_64, 
  };

  // GPR64_with_sub_32_in_GPRMM16MovePPairSecond Bit set.
  static const uint8_t GPR64_with_sub_32_in_GPRMM16MovePPairSecondBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 
  };

  // ACC64DSP Register Class...
  static const MCPhysReg ACC64DSP[] = {
    Mips_AC0, Mips_AC1, Mips_AC2, Mips_AC3, 
  };

  // ACC64DSP Bit set.
  static const uint8_t ACC64DSPBits[] = {
    0x00, 0x00, 0x00, 0x3c, 
  };

  // GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MoveP Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MoveP[] = {
    Mips_V0_64, Mips_V1_64, Mips_S0_64, Mips_S1_64, 
  };

  // GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MoveP Bit set.
  static const uint8_t GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MovePBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x03, 
  };

  // GPR64_with_sub_32_in_GPRMM16MoveP_and_GPRMM16Zero Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_GPRMM16MoveP_and_GPRMM16Zero[] = {
    Mips_ZERO_64, Mips_V0_64, Mips_V1_64, Mips_S1_64, 
  };

  // GPR64_with_sub_32_in_GPRMM16MoveP_and_GPRMM16Zero Bit set.
  static const uint8_t GPR64_with_sub_32_in_GPRMM16MoveP_and_GPRMM16ZeroBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x03, 
  };

  // GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MovePPairSecond Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MovePPairSecond[] = {
    Mips_A1_64, Mips_A2_64, Mips_A3_64, 
  };

  // GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MovePPairSecond Bit set.
  static const uint8_t GPR64_with_sub_32_in_CPU16Regs_and_GPRMM16MovePPairSecondBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 
  };

  // GPR64_with_sub_32_in_GPRMM16MovePPairFirst Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_GPRMM16MovePPairFirst[] = {
    Mips_A0_64, Mips_A1_64, Mips_A2_64, 
  };

  // GPR64_with_sub_32_in_GPRMM16MovePPairFirst Bit set.
  static const uint8_t GPR64_with_sub_32_in_GPRMM16MovePPairFirstBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70, 
  };

  // GPR64_with_sub_32_in_GPRMM16MoveP_and_CPU16Regs_and_GPRMM16Zero Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_GPRMM16MoveP_and_CPU16Regs_and_GPRMM16Zero[] = {
    Mips_V0_64, Mips_V1_64, Mips_S1_64, 
  };

  // GPR64_with_sub_32_in_GPRMM16MoveP_and_CPU16Regs_and_GPRMM16Zero Bit set.
  static const uint8_t GPR64_with_sub_32_in_GPRMM16MoveP_and_CPU16Regs_and_GPRMM16ZeroBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x03, 
  };

  // OCTEON_MPL Register Class...
  static const MCPhysReg OCTEON_MPL[] = {
    Mips_MPL0, Mips_MPL1, Mips_MPL2, 
  };

  // OCTEON_MPL Bit set.
  static const uint8_t OCTEON_MPLBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x03, 
  };

  // OCTEON_P Register Class...
  static const MCPhysReg OCTEON_P[] = {
    Mips_P0, Mips_P1, Mips_P2, 
  };

  // OCTEON_P Bit set.
  static const uint8_t OCTEON_PBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 
  };

  // GPR64_with_sub_32_in_GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecond Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecond[] = {
    Mips_A1_64, Mips_A2_64, 
  };

  // GPR64_with_sub_32_in_GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecond Bit set.
  static const uint8_t GPR64_with_sub_32_in_GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecondBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 
  };

  // ACC64 Register Class...
  static const MCPhysReg ACC64[] = {
    Mips_AC0, 
  };

  // ACC64 Bit set.
  static const uint8_t ACC64Bits[] = {
    0x00, 0x00, 0x00, 0x04, 
  };

  // GP64 Register Class...
  static const MCPhysReg GP64[] = {
    Mips_GP_64, 
  };

  // GP64 Bit set.
  static const uint8_t GP64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 
  };

  // GPR64_with_sub_32_in_CPURAReg Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_CPURAReg[] = {
    Mips_RA_64, 
  };

  // GPR64_with_sub_32_in_CPURAReg Bit set.
  static const uint8_t GPR64_with_sub_32_in_CPURARegBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 
  };

  // GPR64_with_sub_32_in_GPR32ZERO Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_GPR32ZERO[] = {
    Mips_ZERO_64, 
  };

  // GPR64_with_sub_32_in_GPR32ZERO Bit set.
  static const uint8_t GPR64_with_sub_32_in_GPR32ZEROBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 
  };

  // HI64 Register Class...
  static const MCPhysReg HI64[] = {
    Mips_HI0_64, 
  };

  // HI64 Bit set.
  static const uint8_t HI64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 
  };

  // LO64 Register Class...
  static const MCPhysReg LO64[] = {
    Mips_LO0_64, 
  };

  // LO64 Bit set.
  static const uint8_t LO64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 
  };

  // SP64 Register Class...
  static const MCPhysReg SP64[] = {
    Mips_SP_64, 
  };

  // SP64 Bit set.
  static const uint8_t SP64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 
  };

  // MSA128B Register Class...
  static const MCPhysReg MSA128B[] = {
    Mips_W0, Mips_W1, Mips_W2, Mips_W3, Mips_W4, Mips_W5, Mips_W6, Mips_W7, Mips_W8, Mips_W9, Mips_W10, Mips_W11, Mips_W12, Mips_W13, Mips_W14, Mips_W15, Mips_W16, Mips_W17, Mips_W18, Mips_W19, Mips_W20, Mips_W21, Mips_W22, Mips_W23, Mips_W24, Mips_W25, Mips_W26, Mips_W27, Mips_W28, Mips_W29, Mips_W30, Mips_W31, 
  };

  // MSA128B Bit set.
  static const uint8_t MSA128BBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // MSA128D Register Class...
  static const MCPhysReg MSA128D[] = {
    Mips_W0, Mips_W1, Mips_W2, Mips_W3, Mips_W4, Mips_W5, Mips_W6, Mips_W7, Mips_W8, Mips_W9, Mips_W10, Mips_W11, Mips_W12, Mips_W13, Mips_W14, Mips_W15, Mips_W16, Mips_W17, Mips_W18, Mips_W19, Mips_W20, Mips_W21, Mips_W22, Mips_W23, Mips_W24, Mips_W25, Mips_W26, Mips_W27, Mips_W28, Mips_W29, Mips_W30, Mips_W31, 
  };

  // MSA128D Bit set.
  static const uint8_t MSA128DBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // MSA128H Register Class...
  static const MCPhysReg MSA128H[] = {
    Mips_W0, Mips_W1, Mips_W2, Mips_W3, Mips_W4, Mips_W5, Mips_W6, Mips_W7, Mips_W8, Mips_W9, Mips_W10, Mips_W11, Mips_W12, Mips_W13, Mips_W14, Mips_W15, Mips_W16, Mips_W17, Mips_W18, Mips_W19, Mips_W20, Mips_W21, Mips_W22, Mips_W23, Mips_W24, Mips_W25, Mips_W26, Mips_W27, Mips_W28, Mips_W29, Mips_W30, Mips_W31, 
  };

  // MSA128H Bit set.
  static const uint8_t MSA128HBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // MSA128W Register Class...
  static const MCPhysReg MSA128W[] = {
    Mips_W0, Mips_W1, Mips_W2, Mips_W3, Mips_W4, Mips_W5, Mips_W6, Mips_W7, Mips_W8, Mips_W9, Mips_W10, Mips_W11, Mips_W12, Mips_W13, Mips_W14, Mips_W15, Mips_W16, Mips_W17, Mips_W18, Mips_W19, Mips_W20, Mips_W21, Mips_W22, Mips_W23, Mips_W24, Mips_W25, Mips_W26, Mips_W27, Mips_W28, Mips_W29, Mips_W30, Mips_W31, 
  };

  // MSA128W Bit set.
  static const uint8_t MSA128WBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // MSA128WEvens Register Class...
  static const MCPhysReg MSA128WEvens[] = {
    Mips_W0, Mips_W2, Mips_W4, Mips_W6, Mips_W8, Mips_W10, Mips_W12, Mips_W14, Mips_W16, Mips_W18, Mips_W20, Mips_W22, Mips_W24, Mips_W26, Mips_W28, Mips_W30, 
  };

  // MSA128WEvens Bit set.
  static const uint8_t MSA128WEvensBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa8, 0xaa, 0xaa, 0xaa, 0x02, 
  };

  // ACC128 Register Class...
  static const MCPhysReg ACC128[] = {
    Mips_AC0_64, 
  };

  // ACC128 Bit set.
  static const uint8_t ACC128Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
  };

static const MCRegisterClass MipsMCRegisterClasses[] = {
  { MSA128F16, MSA128F16Bits, sizeof(MSA128F16Bits) },
  { CCR, CCRBits, sizeof(CCRBits) },
  { COP0, COP0Bits, sizeof(COP0Bits) },
  { COP2, COP2Bits, sizeof(COP2Bits) },
  { COP3, COP3Bits, sizeof(COP3Bits) },
  { DSPR, DSPRBits, sizeof(DSPRBits) },
  { FGR32, FGR32Bits, sizeof(FGR32Bits) },
  { FGRCC, FGRCCBits, sizeof(FGRCCBits) },
  { GPR32, GPR32Bits, sizeof(GPR32Bits) },
  { HWRegs, HWRegsBits, sizeof(HWRegsBits) },
  { MSACtrl, MSACtrlBits, sizeof(MSACtrlBits) },
  { GPR32NONZERO, GPR32NONZEROBits, sizeof(GPR32NONZEROBits) },
  { CPU16RegsPlusSP, CPU16RegsPlusSPBits, sizeof(CPU16RegsPlusSPBits) },
  { CPU16Regs, CPU16RegsBits, sizeof(CPU16RegsBits) },
  { FCC, FCCBits, sizeof(FCCBits) },
  { GPRMM16, GPRMM16Bits, sizeof(GPRMM16Bits) },
  { GPRMM16MoveP, GPRMM16MovePBits, sizeof(GPRMM16MovePBits) },
  { GPRMM16Zero, GPRMM16ZeroBits, sizeof(GPRMM16ZeroBits) },
  { CPU16Regs_and_GPRMM16Zero, CPU16Regs_and_GPRMM16ZeroBits, sizeof(CPU16Regs_and_GPRMM16ZeroBits) },
  { GPR32NONZERO_and_GPRMM16MoveP, GPR32NONZERO_and_GPRMM16MovePBits, sizeof(GPR32NONZERO_and_GPRMM16MovePBits) },
  { GPRMM16MovePPairSecond, GPRMM16MovePPairSecondBits, sizeof(GPRMM16MovePPairSecondBits) },
  { CPU16Regs_and_GPRMM16MoveP, CPU16Regs_and_GPRMM16MovePBits, sizeof(CPU16Regs_and_GPRMM16MovePBits) },
  { GPRMM16MoveP_and_GPRMM16Zero, GPRMM16MoveP_and_GPRMM16ZeroBits, sizeof(GPRMM16MoveP_and_GPRMM16ZeroBits) },
  { HI32DSP, HI32DSPBits, sizeof(HI32DSPBits) },
  { LO32DSP, LO32DSPBits, sizeof(LO32DSPBits) },
  { CPU16Regs_and_GPRMM16MovePPairSecond, CPU16Regs_and_GPRMM16MovePPairSecondBits, sizeof(CPU16Regs_and_GPRMM16MovePPairSecondBits) },
  { GPRMM16MovePPairFirst, GPRMM16MovePPairFirstBits, sizeof(GPRMM16MovePPairFirstBits) },
  { GPRMM16MoveP_and_CPU16Regs_and_GPRMM16Zero, GPRMM16MoveP_and_CPU16Regs_and_GPRMM16ZeroBits, sizeof(GPRMM16MoveP_and_CPU16Regs_and_GPRMM16ZeroBits) },
  { GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecond, GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecondBits, sizeof(GPRMM16MovePPairFirst_and_GPRMM16MovePPairSecondBits) },
  { CPURAReg, CPURARegBits, sizeof(CPURARegBits) },
  { CPUSPReg, CPUSPRegBits, sizeof(CPUSPRegBits) },
  { DSPCC, DSPCCBits, sizeof(DSPCCBits) },
  { GP32, GP32Bits, sizeof(GP32Bits) },
  { GPR32ZERO, GPR32ZEROBits, sizeof(GPR32ZEROBits) },
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
  0,
  0,
  0,
  0,
  0,
  0,
  30,
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
  29,
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
};
#endif // GET_REGINFO_MC_DESC




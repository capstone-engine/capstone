/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|*Target Register Enum Values                                                 *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */


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
  Mips_CC0 = 31,
  Mips_CC1 = 32,
  Mips_CC2 = 33,
  Mips_CC3 = 34,
  Mips_CC4 = 35,
  Mips_CC5 = 36,
  Mips_CC6 = 37,
  Mips_CC7 = 38,
  Mips_COP20 = 39,
  Mips_COP21 = 40,
  Mips_COP22 = 41,
  Mips_COP23 = 42,
  Mips_COP24 = 43,
  Mips_COP25 = 44,
  Mips_COP26 = 45,
  Mips_COP27 = 46,
  Mips_COP28 = 47,
  Mips_COP29 = 48,
  Mips_COP30 = 49,
  Mips_COP31 = 50,
  Mips_COP32 = 51,
  Mips_COP33 = 52,
  Mips_COP34 = 53,
  Mips_COP35 = 54,
  Mips_COP36 = 55,
  Mips_COP37 = 56,
  Mips_COP38 = 57,
  Mips_COP39 = 58,
  Mips_COP210 = 59,
  Mips_COP211 = 60,
  Mips_COP212 = 61,
  Mips_COP213 = 62,
  Mips_COP214 = 63,
  Mips_COP215 = 64,
  Mips_COP216 = 65,
  Mips_COP217 = 66,
  Mips_COP218 = 67,
  Mips_COP219 = 68,
  Mips_COP220 = 69,
  Mips_COP221 = 70,
  Mips_COP222 = 71,
  Mips_COP223 = 72,
  Mips_COP224 = 73,
  Mips_COP225 = 74,
  Mips_COP226 = 75,
  Mips_COP227 = 76,
  Mips_COP228 = 77,
  Mips_COP229 = 78,
  Mips_COP230 = 79,
  Mips_COP231 = 80,
  Mips_COP310 = 81,
  Mips_COP311 = 82,
  Mips_COP312 = 83,
  Mips_COP313 = 84,
  Mips_COP314 = 85,
  Mips_COP315 = 86,
  Mips_COP316 = 87,
  Mips_COP317 = 88,
  Mips_COP318 = 89,
  Mips_COP319 = 90,
  Mips_COP320 = 91,
  Mips_COP321 = 92,
  Mips_COP322 = 93,
  Mips_COP323 = 94,
  Mips_COP324 = 95,
  Mips_COP325 = 96,
  Mips_COP326 = 97,
  Mips_COP327 = 98,
  Mips_COP328 = 99,
  Mips_COP329 = 100,
  Mips_COP330 = 101,
  Mips_COP331 = 102,
  Mips_D0 = 103,
  Mips_D1 = 104,
  Mips_D2 = 105,
  Mips_D3 = 106,
  Mips_D4 = 107,
  Mips_D5 = 108,
  Mips_D6 = 109,
  Mips_D7 = 110,
  Mips_D8 = 111,
  Mips_D9 = 112,
  Mips_D10 = 113,
  Mips_D11 = 114,
  Mips_D12 = 115,
  Mips_D13 = 116,
  Mips_D14 = 117,
  Mips_D15 = 118,
  Mips_DSPOutFlag20 = 119,
  Mips_DSPOutFlag21 = 120,
  Mips_DSPOutFlag22 = 121,
  Mips_DSPOutFlag23 = 122,
  Mips_F0 = 123,
  Mips_F1 = 124,
  Mips_F2 = 125,
  Mips_F3 = 126,
  Mips_F4 = 127,
  Mips_F5 = 128,
  Mips_F6 = 129,
  Mips_F7 = 130,
  Mips_F8 = 131,
  Mips_F9 = 132,
  Mips_F10 = 133,
  Mips_F11 = 134,
  Mips_F12 = 135,
  Mips_F13 = 136,
  Mips_F14 = 137,
  Mips_F15 = 138,
  Mips_F16 = 139,
  Mips_F17 = 140,
  Mips_F18 = 141,
  Mips_F19 = 142,
  Mips_F20 = 143,
  Mips_F21 = 144,
  Mips_F22 = 145,
  Mips_F23 = 146,
  Mips_F24 = 147,
  Mips_F25 = 148,
  Mips_F26 = 149,
  Mips_F27 = 150,
  Mips_F28 = 151,
  Mips_F29 = 152,
  Mips_F30 = 153,
  Mips_F31 = 154,
  Mips_FCC0 = 155,
  Mips_FCC1 = 156,
  Mips_FCC2 = 157,
  Mips_FCC3 = 158,
  Mips_FCC4 = 159,
  Mips_FCC5 = 160,
  Mips_FCC6 = 161,
  Mips_FCC7 = 162,
  Mips_FCR0 = 163,
  Mips_FCR1 = 164,
  Mips_FCR2 = 165,
  Mips_FCR3 = 166,
  Mips_FCR4 = 167,
  Mips_FCR5 = 168,
  Mips_FCR6 = 169,
  Mips_FCR7 = 170,
  Mips_FCR8 = 171,
  Mips_FCR9 = 172,
  Mips_FCR10 = 173,
  Mips_FCR11 = 174,
  Mips_FCR12 = 175,
  Mips_FCR13 = 176,
  Mips_FCR14 = 177,
  Mips_FCR15 = 178,
  Mips_FCR16 = 179,
  Mips_FCR17 = 180,
  Mips_FCR18 = 181,
  Mips_FCR19 = 182,
  Mips_FCR20 = 183,
  Mips_FCR21 = 184,
  Mips_FCR22 = 185,
  Mips_FCR23 = 186,
  Mips_FCR24 = 187,
  Mips_FCR25 = 188,
  Mips_FCR26 = 189,
  Mips_FCR27 = 190,
  Mips_FCR28 = 191,
  Mips_FCR29 = 192,
  Mips_FCR30 = 193,
  Mips_FCR31 = 194,
  Mips_FP_64 = 195,
  Mips_F_HI0 = 196,
  Mips_F_HI1 = 197,
  Mips_F_HI2 = 198,
  Mips_F_HI3 = 199,
  Mips_F_HI4 = 200,
  Mips_F_HI5 = 201,
  Mips_F_HI6 = 202,
  Mips_F_HI7 = 203,
  Mips_F_HI8 = 204,
  Mips_F_HI9 = 205,
  Mips_F_HI10 = 206,
  Mips_F_HI11 = 207,
  Mips_F_HI12 = 208,
  Mips_F_HI13 = 209,
  Mips_F_HI14 = 210,
  Mips_F_HI15 = 211,
  Mips_F_HI16 = 212,
  Mips_F_HI17 = 213,
  Mips_F_HI18 = 214,
  Mips_F_HI19 = 215,
  Mips_F_HI20 = 216,
  Mips_F_HI21 = 217,
  Mips_F_HI22 = 218,
  Mips_F_HI23 = 219,
  Mips_F_HI24 = 220,
  Mips_F_HI25 = 221,
  Mips_F_HI26 = 222,
  Mips_F_HI27 = 223,
  Mips_F_HI28 = 224,
  Mips_F_HI29 = 225,
  Mips_F_HI30 = 226,
  Mips_F_HI31 = 227,
  Mips_GP_64 = 228,
  Mips_HI0 = 229,
  Mips_HI1 = 230,
  Mips_HI2 = 231,
  Mips_HI3 = 232,
  Mips_HWR0 = 233,
  Mips_HWR1 = 234,
  Mips_HWR2 = 235,
  Mips_HWR3 = 236,
  Mips_HWR4 = 237,
  Mips_HWR5 = 238,
  Mips_HWR6 = 239,
  Mips_HWR7 = 240,
  Mips_HWR8 = 241,
  Mips_HWR9 = 242,
  Mips_HWR10 = 243,
  Mips_HWR11 = 244,
  Mips_HWR12 = 245,
  Mips_HWR13 = 246,
  Mips_HWR14 = 247,
  Mips_HWR15 = 248,
  Mips_HWR16 = 249,
  Mips_HWR17 = 250,
  Mips_HWR18 = 251,
  Mips_HWR19 = 252,
  Mips_HWR20 = 253,
  Mips_HWR21 = 254,
  Mips_HWR22 = 255,
  Mips_HWR23 = 256,
  Mips_HWR24 = 257,
  Mips_HWR25 = 258,
  Mips_HWR26 = 259,
  Mips_HWR27 = 260,
  Mips_HWR28 = 261,
  Mips_HWR29 = 262,
  Mips_HWR30 = 263,
  Mips_HWR31 = 264,
  Mips_K0 = 265,
  Mips_K1 = 266,
  Mips_LO0 = 267,
  Mips_LO1 = 268,
  Mips_LO2 = 269,
  Mips_LO3 = 270,
  Mips_MPL0 = 271,
  Mips_MPL1 = 272,
  Mips_MPL2 = 273,
  Mips_P0 = 274,
  Mips_P1 = 275,
  Mips_P2 = 276,
  Mips_RA_64 = 277,
  Mips_S0 = 278,
  Mips_S1 = 279,
  Mips_S2 = 280,
  Mips_S3 = 281,
  Mips_S4 = 282,
  Mips_S5 = 283,
  Mips_S6 = 284,
  Mips_S7 = 285,
  Mips_SP_64 = 286,
  Mips_T0 = 287,
  Mips_T1 = 288,
  Mips_T2 = 289,
  Mips_T3 = 290,
  Mips_T4 = 291,
  Mips_T5 = 292,
  Mips_T6 = 293,
  Mips_T7 = 294,
  Mips_T8 = 295,
  Mips_T9 = 296,
  Mips_V0 = 297,
  Mips_V1 = 298,
  Mips_W0 = 299,
  Mips_W1 = 300,
  Mips_W2 = 301,
  Mips_W3 = 302,
  Mips_W4 = 303,
  Mips_W5 = 304,
  Mips_W6 = 305,
  Mips_W7 = 306,
  Mips_W8 = 307,
  Mips_W9 = 308,
  Mips_W10 = 309,
  Mips_W11 = 310,
  Mips_W12 = 311,
  Mips_W13 = 312,
  Mips_W14 = 313,
  Mips_W15 = 314,
  Mips_W16 = 315,
  Mips_W17 = 316,
  Mips_W18 = 317,
  Mips_W19 = 318,
  Mips_W20 = 319,
  Mips_W21 = 320,
  Mips_W22 = 321,
  Mips_W23 = 322,
  Mips_W24 = 323,
  Mips_W25 = 324,
  Mips_W26 = 325,
  Mips_W27 = 326,
  Mips_W28 = 327,
  Mips_W29 = 328,
  Mips_W30 = 329,
  Mips_W31 = 330,
  Mips_ZERO_64 = 331,
  Mips_A0_64 = 332,
  Mips_A1_64 = 333,
  Mips_A2_64 = 334,
  Mips_A3_64 = 335,
  Mips_AC0_64 = 336,
  Mips_D0_64 = 337,
  Mips_D1_64 = 338,
  Mips_D2_64 = 339,
  Mips_D3_64 = 340,
  Mips_D4_64 = 341,
  Mips_D5_64 = 342,
  Mips_D6_64 = 343,
  Mips_D7_64 = 344,
  Mips_D8_64 = 345,
  Mips_D9_64 = 346,
  Mips_D10_64 = 347,
  Mips_D11_64 = 348,
  Mips_D12_64 = 349,
  Mips_D13_64 = 350,
  Mips_D14_64 = 351,
  Mips_D15_64 = 352,
  Mips_D16_64 = 353,
  Mips_D17_64 = 354,
  Mips_D18_64 = 355,
  Mips_D19_64 = 356,
  Mips_D20_64 = 357,
  Mips_D21_64 = 358,
  Mips_D22_64 = 359,
  Mips_D23_64 = 360,
  Mips_D24_64 = 361,
  Mips_D25_64 = 362,
  Mips_D26_64 = 363,
  Mips_D27_64 = 364,
  Mips_D28_64 = 365,
  Mips_D29_64 = 366,
  Mips_D30_64 = 367,
  Mips_D31_64 = 368,
  Mips_DSPOutFlag16_19 = 369,
  Mips_HI0_64 = 370,
  Mips_K0_64 = 371,
  Mips_K1_64 = 372,
  Mips_LO0_64 = 373,
  Mips_S0_64 = 374,
  Mips_S1_64 = 375,
  Mips_S2_64 = 376,
  Mips_S3_64 = 377,
  Mips_S4_64 = 378,
  Mips_S5_64 = 379,
  Mips_S6_64 = 380,
  Mips_S7_64 = 381,
  Mips_T0_64 = 382,
  Mips_T1_64 = 383,
  Mips_T2_64 = 384,
  Mips_T3_64 = 385,
  Mips_T4_64 = 386,
  Mips_T5_64 = 387,
  Mips_T6_64 = 388,
  Mips_T7_64 = 389,
  Mips_T8_64 = 390,
  Mips_T9_64 = 391,
  Mips_V0_64 = 392,
  Mips_V1_64 = 393,
  Mips_NUM_TARGET_REGS 	// 394
};

// Register classes
enum {
  Mips_OddSPRegClassID = 0,
  Mips_CCRRegClassID = 1,
  Mips_COP2RegClassID = 2,
  Mips_COP3RegClassID = 3,
  Mips_DSPRRegClassID = 4,
  Mips_FGR32RegClassID = 5,
  Mips_FGRCCRegClassID = 6,
  Mips_FGRH32RegClassID = 7,
  Mips_GPR32RegClassID = 8,
  Mips_HWRegsRegClassID = 9,
  Mips_OddSP_with_sub_hiRegClassID = 10,
  Mips_FGR32_and_OddSPRegClassID = 11,
  Mips_FGRH32_and_OddSPRegClassID = 12,
  Mips_OddSP_with_sub_hi_with_sub_hi_in_FGRH32RegClassID = 13,
  Mips_CPU16RegsPlusSPRegClassID = 14,
  Mips_CCRegClassID = 15,
  Mips_CPU16RegsRegClassID = 16,
  Mips_FCCRegClassID = 17,
  Mips_MSACtrlRegClassID = 18,
  Mips_OddSP_with_sub_hi_with_sub_hi_in_FGR32RegClassID = 19,
  Mips_HI32DSPRegClassID = 20,
  Mips_LO32DSPRegClassID = 21,
  Mips_CPURARegRegClassID = 22,
  Mips_CPUSPRegRegClassID = 23,
  Mips_DSPCCRegClassID = 24,
  Mips_HI32RegClassID = 25,
  Mips_LO32RegClassID = 26,
  Mips_FGR64RegClassID = 27,
  Mips_GPR64RegClassID = 28,
  Mips_AFGR64RegClassID = 29,
  Mips_FGR64_and_OddSPRegClassID = 30,
  Mips_GPR64_with_sub_32_in_CPU16RegsPlusSPRegClassID = 31,
  Mips_AFGR64_and_OddSPRegClassID = 32,
  Mips_GPR64_with_sub_32_in_CPU16RegsRegClassID = 33,
  Mips_ACC64DSPRegClassID = 34,
  Mips_OCTEON_MPLRegClassID = 35,
  Mips_OCTEON_PRegClassID = 36,
  Mips_ACC64RegClassID = 37,
  Mips_GPR64_with_sub_32_in_CPURARegRegClassID = 38,
  Mips_GPR64_with_sub_32_in_CPUSPRegRegClassID = 39,
  Mips_HI64RegClassID = 40,
  Mips_LO64RegClassID = 41,
  Mips_MSA128BRegClassID = 42,
  Mips_MSA128DRegClassID = 43,
  Mips_MSA128HRegClassID = 44,
  Mips_MSA128WRegClassID = 45,
  Mips_MSA128B_with_sub_64_in_OddSPRegClassID = 46,
  Mips_ACC128RegClassID = 47
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

/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|*MC Register Information                                                     *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */


#ifdef GET_REGINFO_MC_DESC
#undef GET_REGINFO_MC_DESC

static const MCPhysReg MipsRegDiffLists[] = {
  /* 0 */ 0, 0,
  /* 2 */ 4, 1, 1, 1, 1, 0,
  /* 8 */ 364, 65286, 1, 1, 1, 0,
  /* 14 */ 20, 1, 0,
  /* 17 */ 21, 1, 0,
  /* 20 */ 22, 1, 0,
  /* 23 */ 23, 1, 0,
  /* 26 */ 24, 1, 0,
  /* 29 */ 25, 1, 0,
  /* 32 */ 26, 1, 0,
  /* 35 */ 27, 1, 0,
  /* 38 */ 28, 1, 0,
  /* 41 */ 29, 1, 0,
  /* 44 */ 30, 1, 0,
  /* 47 */ 31, 1, 0,
  /* 50 */ 32, 1, 0,
  /* 53 */ 33, 1, 0,
  /* 56 */ 34, 1, 0,
  /* 59 */ 35, 1, 0,
  /* 62 */ 65439, 1, 0,
  /* 65 */ 65513, 1, 0,
  /* 68 */ 3, 0,
  /* 70 */ 4, 0,
  /* 72 */ 6, 0,
  /* 74 */ 11, 0,
  /* 76 */ 12, 0,
  /* 78 */ 22, 0,
  /* 80 */ 23, 0,
  /* 82 */ 29, 0,
  /* 84 */ 30, 0,
  /* 86 */ 65308, 72, 0,
  /* 89 */ 65346, 72, 0,
  /* 92 */ 38, 65322, 73, 0,
  /* 96 */ 95, 0,
  /* 98 */ 96, 0,
  /* 100 */ 106, 0,
  /* 102 */ 187, 0,
  /* 104 */ 219, 0,
  /* 106 */ 258, 0,
  /* 108 */ 266, 0,
  /* 110 */ 310, 0,
  /* 112 */ 65031, 0,
  /* 114 */ 65108, 0,
  /* 116 */ 65172, 0,
  /* 118 */ 65226, 0,
  /* 120 */ 65229, 0,
  /* 122 */ 65270, 0,
  /* 124 */ 65278, 0,
  /* 126 */ 65295, 0,
  /* 128 */ 65317, 0,
  /* 130 */ 37, 65430, 103, 65395, 65333, 0,
  /* 136 */ 65349, 0,
  /* 138 */ 65395, 0,
  /* 140 */ 65410, 0,
  /* 142 */ 65415, 0,
  /* 144 */ 65419, 0,
  /* 146 */ 65420, 0,
  /* 148 */ 65421, 0,
  /* 150 */ 65422, 0,
  /* 152 */ 65430, 0,
  /* 154 */ 65440, 0,
  /* 156 */ 65441, 0,
  /* 158 */ 141, 65498, 0,
  /* 161 */ 65516, 234, 65498, 0,
  /* 165 */ 65515, 235, 65498, 0,
  /* 169 */ 65514, 236, 65498, 0,
  /* 173 */ 65513, 237, 65498, 0,
  /* 177 */ 65512, 238, 65498, 0,
  /* 181 */ 65511, 239, 65498, 0,
  /* 185 */ 65510, 240, 65498, 0,
  /* 189 */ 65509, 241, 65498, 0,
  /* 193 */ 65508, 242, 65498, 0,
  /* 197 */ 65507, 243, 65498, 0,
  /* 201 */ 65506, 244, 65498, 0,
  /* 205 */ 65505, 245, 65498, 0,
  /* 209 */ 65504, 246, 65498, 0,
  /* 213 */ 65503, 247, 65498, 0,
  /* 217 */ 65502, 248, 65498, 0,
  /* 221 */ 65501, 249, 65498, 0,
  /* 225 */ 65500, 250, 65498, 0,
  /* 229 */ 65295, 347, 65499, 0,
  /* 233 */ 65333, 344, 65502, 0,
  /* 237 */ 65507, 0,
  /* 239 */ 65510, 0,
  /* 241 */ 65511, 0,
  /* 243 */ 65512, 0,
  /* 245 */ 65516, 0,
  /* 247 */ 65521, 0,
  /* 249 */ 65522, 0,
  /* 251 */ 65535, 0,
};

static const uint16_t MipsSubRegIdxLists[] = {
  /* 0 */ 1, 0,
  /* 2 */ 3, 4, 5, 6, 7, 0,
  /* 8 */ 2, 9, 8, 0,
  /* 12 */ 9, 1, 8, 10, 11, 0,
};

static const MCRegisterDesc MipsRegDesc[] = { // Descriptors
  { 6, 0, 0, 0, 0 },
  { 2007, 1, 82, 1, 4017 },
  { 2010, 1, 1, 1, 4017 },
  { 2102, 1, 1, 1, 4017 },
  { 1973, 1, 1, 1, 4017 },
  { 2027, 8, 1, 2, 32 },
  { 2054, 1, 1, 1, 1089 },
  { 2071, 1, 1, 1, 1089 },
  { 1985, 1, 102, 1, 1089 },
  { 1988, 1, 104, 1, 1089 },
  { 2061, 1, 1, 1, 1089 },
  { 2000, 1, 1, 1, 1089 },
  { 1994, 1, 1, 1, 1089 },
  { 2038, 1, 1, 1, 1089 },
  { 2092, 1, 1, 1, 1089 },
  { 2081, 1, 1, 1, 1089 },
  { 2019, 1, 1, 1, 1089 },
  { 2045, 1, 1, 1, 1089 },
  { 1970, 1, 1, 1, 1089 },
  { 1967, 1, 106, 1, 1089 },
  { 1991, 1, 108, 1, 1089 },
  { 1980, 1, 110, 1, 1089 },
  { 152, 1, 110, 1, 1089 },
  { 365, 1, 110, 1, 1089 },
  { 537, 1, 110, 1, 1089 },
  { 703, 1, 110, 1, 1089 },
  { 155, 190, 110, 9, 1042 },
  { 368, 190, 1, 9, 1042 },
  { 540, 190, 1, 9, 1042 },
  { 706, 190, 1, 9, 1042 },
  { 1271, 237, 1, 0, 0 },
  { 160, 1, 1, 1, 1153 },
  { 373, 1, 1, 1, 1153 },
  { 545, 1, 1, 1, 1153 },
  { 711, 1, 1, 1, 1153 },
  { 1278, 1, 1, 1, 1153 },
  { 1412, 1, 1, 1, 1153 },
  { 1542, 1, 1, 1, 1153 },
  { 1672, 1, 1, 1, 1153 },
  { 70, 1, 1, 1, 1153 },
  { 283, 1, 1, 1, 1153 },
  { 496, 1, 1, 1, 1153 },
  { 662, 1, 1, 1, 1153 },
  { 820, 1, 1, 1, 1153 },
  { 1383, 1, 1, 1, 1153 },
  { 1513, 1, 1, 1, 1153 },
  { 1643, 1, 1, 1, 1153 },
  { 1773, 1, 1, 1, 1153 },
  { 1911, 1, 1, 1, 1153 },
  { 130, 1, 1, 1, 1153 },
  { 343, 1, 1, 1, 1153 },
  { 531, 1, 1, 1, 1153 },
  { 697, 1, 1, 1, 1153 },
  { 842, 1, 1, 1, 1153 },
  { 1405, 1, 1, 1, 1153 },
  { 1535, 1, 1, 1, 1153 },
  { 1665, 1, 1, 1, 1153 },
  { 1795, 1, 1, 1, 1153 },
  { 1933, 1, 1, 1, 1153 },
  { 0, 1, 1, 1, 1153 },
  { 213, 1, 1, 1, 1153 },
  { 426, 1, 1, 1, 1153 },
  { 592, 1, 1, 1, 1153 },
  { 750, 1, 1, 1, 1153 },
  { 1313, 1, 1, 1, 1153 },
  { 1447, 1, 1, 1, 1153 },
  { 1577, 1, 1, 1, 1153 },
  { 1707, 1, 1, 1, 1153 },
  { 1829, 1, 1, 1, 1153 },
  { 45, 1, 1, 1, 1153 },
  { 258, 1, 1, 1, 1153 },
  { 471, 1, 1, 1, 1153 },
  { 637, 1, 1, 1, 1153 },
  { 795, 1, 1, 1, 1153 },
  { 1358, 1, 1, 1, 1153 },
  { 1488, 1, 1, 1, 1153 },
  { 1618, 1, 1, 1, 1153 },
  { 1748, 1, 1, 1, 1153 },
  { 1886, 1, 1, 1, 1153 },
  { 105, 1, 1, 1, 1153 },
  { 318, 1, 1, 1, 1153 },
  { 7, 1, 1, 1, 1153 },
  { 220, 1, 1, 1, 1153 },
  { 433, 1, 1, 1, 1153 },
  { 599, 1, 1, 1, 1153 },
  { 757, 1, 1, 1, 1153 },
  { 1320, 1, 1, 1, 1153 },
  { 1454, 1, 1, 1, 1153 },
  { 1584, 1, 1, 1, 1153 },
  { 1714, 1, 1, 1, 1153 },
  { 1836, 1, 1, 1, 1153 },
  { 52, 1, 1, 1, 1153 },
  { 265, 1, 1, 1, 1153 },
  { 478, 1, 1, 1, 1153 },
  { 644, 1, 1, 1, 1153 },
  { 802, 1, 1, 1, 1153 },
  { 1365, 1, 1, 1, 1153 },
  { 1495, 1, 1, 1, 1153 },
  { 1625, 1, 1, 1, 1153 },
  { 1755, 1, 1, 1, 1153 },
  { 1893, 1, 1, 1, 1153 },
  { 112, 1, 1, 1, 1153 },
  { 325, 1, 1, 1, 1153 },
  { 164, 14, 1, 9, 994 },
  { 377, 17, 1, 9, 994 },
  { 549, 20, 1, 9, 994 },
  { 715, 23, 1, 9, 994 },
  { 1282, 26, 1, 9, 994 },
  { 1416, 29, 1, 9, 994 },
  { 1546, 32, 1, 9, 994 },
  { 1676, 35, 1, 9, 994 },
  { 1801, 38, 1, 9, 994 },
  { 1939, 41, 1, 9, 994 },
  { 14, 44, 1, 9, 994 },
  { 227, 47, 1, 9, 994 },
  { 440, 50, 1, 9, 994 },
  { 606, 53, 1, 9, 994 },
  { 764, 56, 1, 9, 994 },
  { 1327, 59, 1, 9, 994 },
  { 92, 1, 150, 1, 2401 },
  { 305, 1, 148, 1, 2401 },
  { 518, 1, 146, 1, 2401 },
  { 684, 1, 144, 1, 2401 },
  { 167, 1, 161, 1, 3985 },
  { 380, 1, 165, 1, 3985 },
  { 552, 1, 165, 1, 3985 },
  { 718, 1, 169, 1, 3985 },
  { 1285, 1, 169, 1, 3985 },
  { 1419, 1, 173, 1, 3985 },
  { 1549, 1, 173, 1, 3985 },
  { 1679, 1, 177, 1, 3985 },
  { 1804, 1, 177, 1, 3985 },
  { 1942, 1, 181, 1, 3985 },
  { 18, 1, 181, 1, 3985 },
  { 231, 1, 185, 1, 3985 },
  { 444, 1, 185, 1, 3985 },
  { 610, 1, 189, 1, 3985 },
  { 768, 1, 189, 1, 3985 },
  { 1331, 1, 193, 1, 3985 },
  { 1461, 1, 193, 1, 3985 },
  { 1591, 1, 197, 1, 3985 },
  { 1721, 1, 197, 1, 3985 },
  { 1843, 1, 201, 1, 3985 },
  { 59, 1, 201, 1, 3985 },
  { 272, 1, 205, 1, 3985 },
  { 485, 1, 205, 1, 3985 },
  { 651, 1, 209, 1, 3985 },
  { 809, 1, 209, 1, 3985 },
  { 1372, 1, 213, 1, 3985 },
  { 1502, 1, 213, 1, 3985 },
  { 1632, 1, 217, 1, 3985 },
  { 1762, 1, 217, 1, 3985 },
  { 1900, 1, 221, 1, 3985 },
  { 119, 1, 221, 1, 3985 },
  { 332, 1, 225, 1, 3985 },
  { 159, 1, 1, 1, 3985 },
  { 372, 1, 1, 1, 3985 },
  { 544, 1, 1, 1, 3985 },
  { 710, 1, 1, 1, 3985 },
  { 1277, 1, 1, 1, 3985 },
  { 1411, 1, 1, 1, 3985 },
  { 1541, 1, 1, 1, 3985 },
  { 1671, 1, 1, 1, 3985 },
  { 191, 1, 1, 1, 3985 },
  { 404, 1, 1, 1, 3985 },
  { 573, 1, 1, 1, 3985 },
  { 731, 1, 1, 1, 3985 },
  { 1294, 1, 1, 1, 3985 },
  { 1428, 1, 1, 1, 3985 },
  { 1558, 1, 1, 1, 3985 },
  { 1688, 1, 1, 1, 3985 },
  { 1813, 1, 1, 1, 3985 },
  { 1951, 1, 1, 1, 3985 },
  { 29, 1, 1, 1, 3985 },
  { 242, 1, 1, 1, 3985 },
  { 455, 1, 1, 1, 3985 },
  { 621, 1, 1, 1, 3985 },
  { 779, 1, 1, 1, 3985 },
  { 1342, 1, 1, 1, 3985 },
  { 1472, 1, 1, 1, 3985 },
  { 1602, 1, 1, 1, 3985 },
  { 1732, 1, 1, 1, 3985 },
  { 1854, 1, 1, 1, 3985 },
  { 76, 1, 1, 1, 3985 },
  { 289, 1, 1, 1, 3985 },
  { 502, 1, 1, 1, 3985 },
  { 668, 1, 1, 1, 3985 },
  { 826, 1, 1, 1, 3985 },
  { 1389, 1, 1, 1, 3985 },
  { 1519, 1, 1, 1, 3985 },
  { 1649, 1, 1, 1, 3985 },
  { 1779, 1, 1, 1, 3985 },
  { 1917, 1, 1, 1, 3985 },
  { 136, 1, 1, 1, 3985 },
  { 349, 1, 1, 1, 3985 },
  { 1253, 136, 1, 0, 1184 },
  { 170, 1, 158, 1, 3953 },
  { 383, 1, 158, 1, 3953 },
  { 555, 1, 158, 1, 3953 },
  { 721, 1, 158, 1, 3953 },
  { 1288, 1, 158, 1, 3953 },
  { 1422, 1, 158, 1, 3953 },
  { 1552, 1, 158, 1, 3953 },
  { 1682, 1, 158, 1, 3953 },
  { 1807, 1, 158, 1, 3953 },
  { 1945, 1, 158, 1, 3953 },
  { 22, 1, 158, 1, 3953 },
  { 235, 1, 158, 1, 3953 },
  { 448, 1, 158, 1, 3953 },
  { 614, 1, 158, 1, 3953 },
  { 772, 1, 158, 1, 3953 },
  { 1335, 1, 158, 1, 3953 },
  { 1465, 1, 158, 1, 3953 },
  { 1595, 1, 158, 1, 3953 },
  { 1725, 1, 158, 1, 3953 },
  { 1847, 1, 158, 1, 3953 },
  { 63, 1, 158, 1, 3953 },
  { 276, 1, 158, 1, 3953 },
  { 489, 1, 158, 1, 3953 },
  { 655, 1, 158, 1, 3953 },
  { 813, 1, 158, 1, 3953 },
  { 1376, 1, 158, 1, 3953 },
  { 1506, 1, 158, 1, 3953 },
  { 1636, 1, 158, 1, 3953 },
  { 1766, 1, 158, 1, 3953 },
  { 1904, 1, 158, 1, 3953 },
  { 123, 1, 158, 1, 3953 },
  { 336, 1, 158, 1, 3953 },
  { 1259, 128, 1, 0, 1216 },
  { 172, 1, 233, 1, 1826 },
  { 385, 1, 134, 1, 1826 },
  { 557, 1, 134, 1, 1826 },
  { 723, 1, 134, 1, 1826 },
  { 196, 1, 1, 1, 3921 },
  { 409, 1, 1, 1, 3921 },
  { 578, 1, 1, 1, 3921 },
  { 736, 1, 1, 1, 3921 },
  { 1299, 1, 1, 1, 3921 },
  { 1433, 1, 1, 1, 3921 },
  { 1563, 1, 1, 1, 3921 },
  { 1693, 1, 1, 1, 3921 },
  { 1818, 1, 1, 1, 3921 },
  { 1956, 1, 1, 1, 3921 },
  { 35, 1, 1, 1, 3921 },
  { 248, 1, 1, 1, 3921 },
  { 461, 1, 1, 1, 3921 },
  { 627, 1, 1, 1, 3921 },
  { 785, 1, 1, 1, 3921 },
  { 1348, 1, 1, 1, 3921 },
  { 1478, 1, 1, 1, 3921 },
  { 1608, 1, 1, 1, 3921 },
  { 1738, 1, 1, 1, 3921 },
  { 1860, 1, 1, 1, 3921 },
  { 82, 1, 1, 1, 3921 },
  { 295, 1, 1, 1, 3921 },
  { 508, 1, 1, 1, 3921 },
  { 674, 1, 1, 1, 3921 },
  { 832, 1, 1, 1, 3921 },
  { 1395, 1, 1, 1, 3921 },
  { 1525, 1, 1, 1, 3921 },
  { 1655, 1, 1, 1, 3921 },
  { 1785, 1, 1, 1, 3921 },
  { 1923, 1, 1, 1, 3921 },
  { 142, 1, 1, 1, 3921 },
  { 355, 1, 1, 1, 3921 },
  { 176, 1, 100, 1, 3921 },
  { 389, 1, 100, 1, 3921 },
  { 184, 1, 229, 1, 1794 },
  { 397, 1, 126, 1, 1794 },
  { 566, 1, 126, 1, 1794 },
  { 727, 1, 126, 1, 1794 },
  { 179, 1, 1, 1, 3889 },
  { 392, 1, 1, 1, 3889 },
  { 561, 1, 1, 1, 3889 },
  { 188, 1, 1, 1, 3889 },
  { 401, 1, 1, 1, 3889 },
  { 570, 1, 1, 1, 3889 },
  { 1239, 124, 1, 0, 1248 },
  { 201, 1, 98, 1, 3857 },
  { 414, 1, 98, 1, 3857 },
  { 583, 1, 98, 1, 3857 },
  { 741, 1, 98, 1, 3857 },
  { 1304, 1, 98, 1, 3857 },
  { 1438, 1, 98, 1, 3857 },
  { 1568, 1, 98, 1, 3857 },
  { 1698, 1, 98, 1, 3857 },
  { 1265, 122, 1, 0, 1280 },
  { 204, 1, 96, 1, 3825 },
  { 417, 1, 96, 1, 3825 },
  { 586, 1, 96, 1, 3825 },
  { 744, 1, 96, 1, 3825 },
  { 1307, 1, 96, 1, 3825 },
  { 1441, 1, 96, 1, 3825 },
  { 1571, 1, 96, 1, 3825 },
  { 1701, 1, 96, 1, 3825 },
  { 1823, 1, 96, 1, 3825 },
  { 1961, 1, 96, 1, 3825 },
  { 207, 1, 96, 1, 3825 },
  { 420, 1, 96, 1, 3825 },
  { 210, 92, 1, 8, 1425 },
  { 423, 92, 1, 8, 1425 },
  { 589, 92, 1, 8, 1425 },
  { 747, 92, 1, 8, 1425 },
  { 1310, 92, 1, 8, 1425 },
  { 1444, 92, 1, 8, 1425 },
  { 1574, 92, 1, 8, 1425 },
  { 1704, 92, 1, 8, 1425 },
  { 1826, 92, 1, 8, 1425 },
  { 1964, 92, 1, 8, 1425 },
  { 41, 92, 1, 8, 1425 },
  { 254, 92, 1, 8, 1425 },
  { 467, 92, 1, 8, 1425 },
  { 633, 92, 1, 8, 1425 },
  { 791, 92, 1, 8, 1425 },
  { 1354, 92, 1, 8, 1425 },
  { 1484, 92, 1, 8, 1425 },
  { 1614, 92, 1, 8, 1425 },
  { 1744, 92, 1, 8, 1425 },
  { 1866, 92, 1, 8, 1425 },
  { 88, 92, 1, 8, 1425 },
  { 301, 92, 1, 8, 1425 },
  { 514, 92, 1, 8, 1425 },
  { 680, 92, 1, 8, 1425 },
  { 838, 92, 1, 8, 1425 },
  { 1401, 92, 1, 8, 1425 },
  { 1531, 92, 1, 8, 1425 },
  { 1661, 92, 1, 8, 1425 },
  { 1791, 92, 1, 8, 1425 },
  { 1929, 92, 1, 8, 1425 },
  { 148, 92, 1, 8, 1425 },
  { 361, 92, 1, 8, 1425 },
  { 1245, 118, 1, 0, 1921 },
  { 869, 118, 1, 0, 1921 },
  { 947, 118, 1, 0, 1921 },
  { 997, 118, 1, 0, 1921 },
  { 1035, 118, 1, 0, 1921 },
  { 875, 130, 1, 12, 656 },
  { 882, 93, 159, 9, 1377 },
  { 953, 93, 159, 9, 1377 },
  { 1003, 93, 159, 9, 1377 },
  { 1041, 93, 159, 9, 1377 },
  { 1073, 93, 159, 9, 1377 },
  { 1105, 93, 159, 9, 1377 },
  { 1137, 93, 159, 9, 1377 },
  { 1169, 93, 159, 9, 1377 },
  { 1201, 93, 159, 9, 1377 },
  { 1227, 93, 159, 9, 1377 },
  { 848, 93, 159, 9, 1377 },
  { 926, 93, 159, 9, 1377 },
  { 983, 93, 159, 9, 1377 },
  { 1021, 93, 159, 9, 1377 },
  { 1059, 93, 159, 9, 1377 },
  { 1091, 93, 159, 9, 1377 },
  { 1123, 93, 159, 9, 1377 },
  { 1155, 93, 159, 9, 1377 },
  { 1187, 93, 159, 9, 1377 },
  { 1213, 93, 159, 9, 1377 },
  { 855, 93, 159, 9, 1377 },
  { 933, 93, 159, 9, 1377 },
  { 990, 93, 159, 9, 1377 },
  { 1028, 93, 159, 9, 1377 },
  { 1066, 93, 159, 9, 1377 },
  { 1098, 93, 159, 9, 1377 },
  { 1130, 93, 159, 9, 1377 },
  { 1162, 93, 159, 9, 1377 },
  { 1194, 93, 159, 9, 1377 },
  { 1220, 93, 159, 9, 1377 },
  { 862, 93, 159, 9, 1377 },
  { 940, 93, 159, 9, 1377 },
  { 1870, 1, 116, 1, 1120 },
  { 888, 138, 235, 0, 1344 },
  { 895, 152, 1, 0, 2241 },
  { 959, 152, 1, 0, 2241 },
  { 901, 152, 231, 0, 1312 },
  { 908, 154, 1, 0, 2273 },
  { 965, 154, 1, 0, 2273 },
  { 1009, 154, 1, 0, 2273 },
  { 1047, 154, 1, 0, 2273 },
  { 1079, 154, 1, 0, 2273 },
  { 1111, 154, 1, 0, 2273 },
  { 1143, 154, 1, 0, 2273 },
  { 1175, 154, 1, 0, 2273 },
  { 914, 156, 1, 0, 2273 },
  { 971, 156, 1, 0, 2273 },
  { 1015, 156, 1, 0, 2273 },
  { 1053, 156, 1, 0, 2273 },
  { 1085, 156, 1, 0, 2273 },
  { 1117, 156, 1, 0, 2273 },
  { 1149, 156, 1, 0, 2273 },
  { 1181, 156, 1, 0, 2273 },
  { 1207, 156, 1, 0, 2273 },
  { 1233, 156, 1, 0, 2273 },
  { 920, 156, 1, 0, 2273 },
  { 977, 156, 1, 0, 2273 },
};

  static const MCPhysReg OddSP[] = {
    Mips_F1, Mips_F3, Mips_F5, Mips_F7, Mips_F9, Mips_F11, Mips_F13, Mips_F15, Mips_F17, Mips_F19, Mips_F21, Mips_F23, Mips_F25, Mips_F27, Mips_F29, Mips_F31, Mips_F_HI1, Mips_F_HI3, Mips_F_HI5, Mips_F_HI7, Mips_F_HI9, Mips_F_HI11, Mips_F_HI13, Mips_F_HI15, Mips_F_HI17, Mips_F_HI19, Mips_F_HI21, Mips_F_HI23, Mips_F_HI25, Mips_F_HI27, Mips_F_HI29, Mips_F_HI31, Mips_D1, Mips_D3, Mips_D5, Mips_D7, Mips_D9, Mips_D11, Mips_D13, Mips_D15, Mips_D1_64, Mips_D3_64, Mips_D5_64, Mips_D7_64, Mips_D9_64, Mips_D11_64, Mips_D13_64, Mips_D15_64, Mips_D17_64, Mips_D19_64, Mips_D21_64, Mips_D23_64, Mips_D25_64, Mips_D27_64, Mips_D29_64, Mips_D31_64, 
  };

  // OddSP Bit set.
  static const uint8_t OddSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x55, 0x50, 0x55, 0x55, 0x55, 0x05, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 0xaa, 0xaa, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x55, 0x55, 0x55, 0x01, 
  };

  // CCR Register Class...
  static const MCPhysReg CCR[] = {
    Mips_FCR0, Mips_FCR1, Mips_FCR2, Mips_FCR3, Mips_FCR4, Mips_FCR5, Mips_FCR6, Mips_FCR7, Mips_FCR8, Mips_FCR9, Mips_FCR10, Mips_FCR11, Mips_FCR12, Mips_FCR13, Mips_FCR14, Mips_FCR15, Mips_FCR16, Mips_FCR17, Mips_FCR18, Mips_FCR19, Mips_FCR20, Mips_FCR21, Mips_FCR22, Mips_FCR23, Mips_FCR24, Mips_FCR25, Mips_FCR26, Mips_FCR27, Mips_FCR28, Mips_FCR29, Mips_FCR30, Mips_FCR31, 
  };

  // CCR Bit set.
  static const uint8_t CCRBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // COP2 Register Class...
  static const MCPhysReg COP2[] = {
    Mips_COP20, Mips_COP21, Mips_COP22, Mips_COP23, Mips_COP24, Mips_COP25, Mips_COP26, Mips_COP27, Mips_COP28, Mips_COP29, Mips_COP210, Mips_COP211, Mips_COP212, Mips_COP213, Mips_COP214, Mips_COP215, Mips_COP216, Mips_COP217, Mips_COP218, Mips_COP219, Mips_COP220, Mips_COP221, Mips_COP222, Mips_COP223, Mips_COP224, Mips_COP225, Mips_COP226, Mips_COP227, Mips_COP228, Mips_COP229, Mips_COP230, Mips_COP231, 
  };

  // COP2 Bit set.
  static const uint8_t COP2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0x01, 0xf8, 0xff, 0xff, 0x01, 
  };

  // COP3 Register Class...
  static const MCPhysReg COP3[] = {
    Mips_COP30, Mips_COP31, Mips_COP32, Mips_COP33, Mips_COP34, Mips_COP35, Mips_COP36, Mips_COP37, Mips_COP38, Mips_COP39, Mips_COP310, Mips_COP311, Mips_COP312, Mips_COP313, Mips_COP314, Mips_COP315, Mips_COP316, Mips_COP317, Mips_COP318, Mips_COP319, Mips_COP320, Mips_COP321, Mips_COP322, Mips_COP323, Mips_COP324, Mips_COP325, Mips_COP326, Mips_COP327, Mips_COP328, Mips_COP329, Mips_COP330, Mips_COP331, 
  };

  // COP3 Bit set.
  static const uint8_t COP3Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x07, 0x00, 0x00, 0xfe, 0xff, 0x7f, 
  };

  // DSPR Register Class...
  static const MCPhysReg DSPR[] = {
    Mips_ZERO, Mips_AT, Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, Mips_T0, Mips_T1, Mips_T2, Mips_T3, Mips_T4, Mips_T5, Mips_T6, Mips_T7, Mips_S0, Mips_S1, Mips_S2, Mips_S3, Mips_S4, Mips_S5, Mips_S6, Mips_S7, Mips_T8, Mips_T9, Mips_K0, Mips_K1, Mips_GP, Mips_SP, Mips_FP, Mips_RA, 
  };

  // DSPR Bit set.
  static const uint8_t DSPRBits[] = {
    0x02, 0x03, 0xf8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0xc0, 0xbf, 0xff, 0x07, 
  };

  // FGR32 Register Class...
  static const MCPhysReg FGR32[] = {
    Mips_F0, Mips_F1, Mips_F2, Mips_F3, Mips_F4, Mips_F5, Mips_F6, Mips_F7, Mips_F8, Mips_F9, Mips_F10, Mips_F11, Mips_F12, Mips_F13, Mips_F14, Mips_F15, Mips_F16, Mips_F17, Mips_F18, Mips_F19, Mips_F20, Mips_F21, Mips_F22, Mips_F23, Mips_F24, Mips_F25, Mips_F26, Mips_F27, Mips_F28, Mips_F29, Mips_F30, Mips_F31, 
  };

  // FGR32 Bit set.
  static const uint8_t FGR32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // FGRCC Register Class...
  static const MCPhysReg FGRCC[] = {
    Mips_F0, Mips_F1, Mips_F2, Mips_F3, Mips_F4, Mips_F5, Mips_F6, Mips_F7, Mips_F8, Mips_F9, Mips_F10, Mips_F11, Mips_F12, Mips_F13, Mips_F14, Mips_F15, Mips_F16, Mips_F17, Mips_F18, Mips_F19, Mips_F20, Mips_F21, Mips_F22, Mips_F23, Mips_F24, Mips_F25, Mips_F26, Mips_F27, Mips_F28, Mips_F29, Mips_F30, Mips_F31, 
  };

  // FGRCC Bit set.
  static const uint8_t FGRCCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // FGRH32 Register Class...
  static const MCPhysReg FGRH32[] = {
    Mips_F_HI0, Mips_F_HI1, Mips_F_HI2, Mips_F_HI3, Mips_F_HI4, Mips_F_HI5, Mips_F_HI6, Mips_F_HI7, Mips_F_HI8, Mips_F_HI9, Mips_F_HI10, Mips_F_HI11, Mips_F_HI12, Mips_F_HI13, Mips_F_HI14, Mips_F_HI15, Mips_F_HI16, Mips_F_HI17, Mips_F_HI18, Mips_F_HI19, Mips_F_HI20, Mips_F_HI21, Mips_F_HI22, Mips_F_HI23, Mips_F_HI24, Mips_F_HI25, Mips_F_HI26, Mips_F_HI27, Mips_F_HI28, Mips_F_HI29, Mips_F_HI30, Mips_F_HI31, 
  };

  // FGRH32 Bit set.
  static const uint8_t FGRH32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // GPR32 Register Class...
  static const MCPhysReg GPR32[] = {
    Mips_ZERO, Mips_AT, Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, Mips_T0, Mips_T1, Mips_T2, Mips_T3, Mips_T4, Mips_T5, Mips_T6, Mips_T7, Mips_S0, Mips_S1, Mips_S2, Mips_S3, Mips_S4, Mips_S5, Mips_S6, Mips_S7, Mips_T8, Mips_T9, Mips_K0, Mips_K1, Mips_GP, Mips_SP, Mips_FP, Mips_RA, 
  };

  // GPR32 Bit set.
  static const uint8_t GPR32Bits[] = {
    0x02, 0x03, 0xf8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0xc0, 0xbf, 0xff, 0x07, 
  };

  // HWRegs Register Class...
  static const MCPhysReg HWRegs[] = {
    Mips_HWR0, Mips_HWR1, Mips_HWR2, Mips_HWR3, Mips_HWR4, Mips_HWR5, Mips_HWR6, Mips_HWR7, Mips_HWR8, Mips_HWR9, Mips_HWR10, Mips_HWR11, Mips_HWR12, Mips_HWR13, Mips_HWR14, Mips_HWR15, Mips_HWR16, Mips_HWR17, Mips_HWR18, Mips_HWR19, Mips_HWR20, Mips_HWR21, Mips_HWR22, Mips_HWR23, Mips_HWR24, Mips_HWR25, Mips_HWR26, Mips_HWR27, Mips_HWR28, Mips_HWR29, Mips_HWR30, Mips_HWR31, 
  };

  // HWRegs Bit set.
  static const uint8_t HWRegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01, 
  };

  // OddSP_with_sub_hi Register Class...
  static const MCPhysReg OddSP_with_sub_hi[] = {
    Mips_D1, Mips_D3, Mips_D5, Mips_D7, Mips_D9, Mips_D11, Mips_D13, Mips_D15, Mips_D1_64, Mips_D3_64, Mips_D5_64, Mips_D7_64, Mips_D9_64, Mips_D11_64, Mips_D13_64, Mips_D15_64, Mips_D17_64, Mips_D19_64, Mips_D21_64, Mips_D23_64, Mips_D25_64, Mips_D27_64, Mips_D29_64, Mips_D31_64, 
  };

  // OddSP_with_sub_hi Bit set.
  static const uint8_t OddSP_with_sub_hiBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x55, 0x55, 0x55, 0x01, 
  };

  // FGR32_and_OddSP Register Class...
  static const MCPhysReg FGR32_and_OddSP[] = {
    Mips_F1, Mips_F3, Mips_F5, Mips_F7, Mips_F9, Mips_F11, Mips_F13, Mips_F15, Mips_F17, Mips_F19, Mips_F21, Mips_F23, Mips_F25, Mips_F27, Mips_F29, Mips_F31, 
  };

  // FGR32_and_OddSP Bit set.
  static const uint8_t FGR32_and_OddSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x55, 0x55, 0x05, 
  };

  // FGRH32_and_OddSP Register Class...
  static const MCPhysReg FGRH32_and_OddSP[] = {
    Mips_F_HI1, Mips_F_HI3, Mips_F_HI5, Mips_F_HI7, Mips_F_HI9, Mips_F_HI11, Mips_F_HI13, Mips_F_HI15, Mips_F_HI17, Mips_F_HI19, Mips_F_HI21, Mips_F_HI23, Mips_F_HI25, Mips_F_HI27, Mips_F_HI29, Mips_F_HI31, 
  };

  // FGRH32_and_OddSP Bit set.
  static const uint8_t FGRH32_and_OddSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 0xaa, 0xaa, 0x0a, 
  };

  // OddSP_with_sub_hi_with_sub_hi_in_FGRH32 Register Class...
  static const MCPhysReg OddSP_with_sub_hi_with_sub_hi_in_FGRH32[] = {
    Mips_D1_64, Mips_D3_64, Mips_D5_64, Mips_D7_64, Mips_D9_64, Mips_D11_64, Mips_D13_64, Mips_D15_64, Mips_D17_64, Mips_D19_64, Mips_D21_64, Mips_D23_64, Mips_D25_64, Mips_D27_64, Mips_D29_64, Mips_D31_64, 
  };

  // OddSP_with_sub_hi_with_sub_hi_in_FGRH32 Bit set.
  static const uint8_t OddSP_with_sub_hi_with_sub_hi_in_FGRH32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x55, 0x55, 0x55, 0x01, 
  };

  // CPU16RegsPlusSP Register Class...
  static const MCPhysReg CPU16RegsPlusSP[] = {
    Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, Mips_S0, Mips_S1, Mips_SP, 
  };

  // CPU16RegsPlusSP Bit set.
  static const uint8_t CPU16RegsPlusSPBits[] = {
    0x00, 0x00, 0xd0, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x06, 
  };

  // CC Register Class...
  static const MCPhysReg CC[] = {
    Mips_CC0, Mips_CC1, Mips_CC2, Mips_CC3, Mips_CC4, Mips_CC5, Mips_CC6, Mips_CC7, 
  };

  // CC Bit set.
  static const uint8_t CCBits[] = {
    0x00, 0x00, 0x00, 0x80, 0x7f, 
  };

  // CPU16Regs Register Class...
  static const MCPhysReg CPU16Regs[] = {
    Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, Mips_S0, Mips_S1, 
  };

  // CPU16Regs Bit set.
  static const uint8_t CPU16RegsBits[] = {
    0x00, 0x00, 0xc0, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x06, 
  };

  // FCC Register Class...
  static const MCPhysReg FCC[] = {
    Mips_FCC0, Mips_FCC1, Mips_FCC2, Mips_FCC3, Mips_FCC4, Mips_FCC5, Mips_FCC6, Mips_FCC7, 
  };

  // FCC Bit set.
  static const uint8_t FCCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x07, 
  };

  // MSACtrl Register Class...
  static const MCPhysReg MSACtrl[] = {
    Mips_MSAIR, Mips_MSACSR, Mips_MSAAccess, Mips_MSASave, Mips_MSAModify, Mips_MSARequest, Mips_MSAMap, Mips_MSAUnmap, 
  };

  // MSACtrl Bit set.
  static const uint8_t MSACtrlBits[] = {
    0x00, 0xfc, 0x03, 
  };

  // OddSP_with_sub_hi_with_sub_hi_in_FGR32 Register Class...
  static const MCPhysReg OddSP_with_sub_hi_with_sub_hi_in_FGR32[] = {
    Mips_D1, Mips_D3, Mips_D5, Mips_D7, Mips_D9, Mips_D11, Mips_D13, Mips_D15, 
  };

  // OddSP_with_sub_hi_with_sub_hi_in_FGR32 Bit set.
  static const uint8_t OddSP_with_sub_hi_with_sub_hi_in_FGR32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x55, 
  };

  // HI32DSP Register Class...
  static const MCPhysReg HI32DSP[] = {
    Mips_HI0, Mips_HI1, Mips_HI2, Mips_HI3, 
  };

  // HI32DSP Bit set.
  static const uint8_t HI32DSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x01, 
  };

  // LO32DSP Register Class...
  static const MCPhysReg LO32DSP[] = {
    Mips_LO0, Mips_LO1, Mips_LO2, Mips_LO3, 
  };

  // LO32DSP Bit set.
  static const uint8_t LO32DSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 
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

  // HI32 Register Class...
  static const MCPhysReg HI32[] = {
    Mips_HI0, 
  };

  // HI32 Bit set.
  static const uint8_t HI32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 
  };

  // LO32 Register Class...
  static const MCPhysReg LO32[] = {
    Mips_LO0, 
  };

  // LO32 Bit set.
  static const uint8_t LO32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 
  };

  // FGR64 Register Class...
  static const MCPhysReg FGR64[] = {
    Mips_D0_64, Mips_D1_64, Mips_D2_64, Mips_D3_64, Mips_D4_64, Mips_D5_64, Mips_D6_64, Mips_D7_64, Mips_D8_64, Mips_D9_64, Mips_D10_64, Mips_D11_64, Mips_D12_64, Mips_D13_64, Mips_D14_64, Mips_D15_64, Mips_D16_64, Mips_D17_64, Mips_D18_64, Mips_D19_64, Mips_D20_64, Mips_D21_64, Mips_D22_64, Mips_D23_64, Mips_D24_64, Mips_D25_64, Mips_D26_64, Mips_D27_64, Mips_D28_64, Mips_D29_64, Mips_D30_64, Mips_D31_64, 
  };

  // FGR64 Bit set.
  static const uint8_t FGR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01, 
  };

  // GPR64 Register Class...
  static const MCPhysReg GPR64[] = {
    Mips_ZERO_64, Mips_AT_64, Mips_V0_64, Mips_V1_64, Mips_A0_64, Mips_A1_64, Mips_A2_64, Mips_A3_64, Mips_T0_64, Mips_T1_64, Mips_T2_64, Mips_T3_64, Mips_T4_64, Mips_T5_64, Mips_T6_64, Mips_T7_64, Mips_S0_64, Mips_S1_64, Mips_S2_64, Mips_S3_64, Mips_S4_64, Mips_S5_64, Mips_S6_64, Mips_S7_64, Mips_T8_64, Mips_T9_64, Mips_K0_64, Mips_K1_64, Mips_GP_64, Mips_SP_64, Mips_FP_64, Mips_RA_64, 
  };

  // GPR64 Bit set.
  static const uint8_t GPR64Bits[] = {
    0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x00, 0x00, 0x00, 0x00, 0xd8, 0xff, 0xff, 0x03, 
  };

  // AFGR64 Register Class...
  static const MCPhysReg AFGR64[] = {
    Mips_D0, Mips_D1, Mips_D2, Mips_D3, Mips_D4, Mips_D5, Mips_D6, Mips_D7, Mips_D8, Mips_D9, Mips_D10, Mips_D11, Mips_D12, Mips_D13, Mips_D14, Mips_D15, 
  };

  // AFGR64 Bit set.
  static const uint8_t AFGR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0x7f, 
  };

  // FGR64_and_OddSP Register Class...
  static const MCPhysReg FGR64_and_OddSP[] = {
    Mips_D1_64, Mips_D3_64, Mips_D5_64, Mips_D7_64, Mips_D9_64, Mips_D11_64, Mips_D13_64, Mips_D15_64, Mips_D17_64, Mips_D19_64, Mips_D21_64, Mips_D23_64, Mips_D25_64, Mips_D27_64, Mips_D29_64, Mips_D31_64, 
  };

  // FGR64_and_OddSP Bit set.
  static const uint8_t FGR64_and_OddSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x55, 0x55, 0x55, 0x01, 
  };

  // GPR64_with_sub_32_in_CPU16RegsPlusSP Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_CPU16RegsPlusSP[] = {
    Mips_V0_64, Mips_V1_64, Mips_A0_64, Mips_A1_64, Mips_A2_64, Mips_A3_64, Mips_S0_64, Mips_S1_64, Mips_SP_64, 
  };

  // GPR64_with_sub_32_in_CPU16RegsPlusSP Bit set.
  static const uint8_t GPR64_with_sub_32_in_CPU16RegsPlusSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x03, 
  };

  // AFGR64_and_OddSP Register Class...
  static const MCPhysReg AFGR64_and_OddSP[] = {
    Mips_D1, Mips_D3, Mips_D5, Mips_D7, Mips_D9, Mips_D11, Mips_D13, Mips_D15, 
  };

  // AFGR64_and_OddSP Bit set.
  static const uint8_t AFGR64_and_OddSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x55, 
  };

  // GPR64_with_sub_32_in_CPU16Regs Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_CPU16Regs[] = {
    Mips_V0_64, Mips_V1_64, Mips_A0_64, Mips_A1_64, Mips_A2_64, Mips_A3_64, Mips_S0_64, Mips_S1_64, 
  };

  // GPR64_with_sub_32_in_CPU16Regs Bit set.
  static const uint8_t GPR64_with_sub_32_in_CPU16RegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x03, 
  };

  // ACC64DSP Register Class...
  static const MCPhysReg ACC64DSP[] = {
    Mips_AC0, Mips_AC1, Mips_AC2, Mips_AC3, 
  };

  // ACC64DSP Bit set.
  static const uint8_t ACC64DSPBits[] = {
    0x00, 0x00, 0x00, 0x3c, 
  };

  // OCTEON_MPL Register Class...
  static const MCPhysReg OCTEON_MPL[] = {
    Mips_MPL0, Mips_MPL1, Mips_MPL2, 
  };

  // OCTEON_MPL Bit set.
  static const uint8_t OCTEON_MPLBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x03, 
  };

  // OCTEON_P Register Class...
  static const MCPhysReg OCTEON_P[] = {
    Mips_P0, Mips_P1, Mips_P2, 
  };

  // OCTEON_P Bit set.
  static const uint8_t OCTEON_PBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 
  };

  // ACC64 Register Class...
  static const MCPhysReg ACC64[] = {
    Mips_AC0, 
  };

  // ACC64 Bit set.
  static const uint8_t ACC64Bits[] = {
    0x00, 0x00, 0x00, 0x04, 
  };

  // GPR64_with_sub_32_in_CPURAReg Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_CPURAReg[] = {
    Mips_RA_64, 
  };

  // GPR64_with_sub_32_in_CPURAReg Bit set.
  static const uint8_t GPR64_with_sub_32_in_CPURARegBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 
  };

  // GPR64_with_sub_32_in_CPUSPReg Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_CPUSPReg[] = {
    Mips_SP_64, 
  };

  // GPR64_with_sub_32_in_CPUSPReg Bit set.
  static const uint8_t GPR64_with_sub_32_in_CPUSPRegBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 
  };

  // HI64 Register Class...
  static const MCPhysReg HI64[] = {
    Mips_HI0_64, 
  };

  // HI64 Bit set.
  static const uint8_t HI64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 
  };

  // LO64 Register Class...
  static const MCPhysReg LO64[] = {
    Mips_LO0_64, 
  };

  // LO64 Bit set.
  static const uint8_t LO64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 
  };

  // MSA128B Register Class...
  static const MCPhysReg MSA128B[] = {
    Mips_W0, Mips_W1, Mips_W2, Mips_W3, Mips_W4, Mips_W5, Mips_W6, Mips_W7, Mips_W8, Mips_W9, Mips_W10, Mips_W11, Mips_W12, Mips_W13, Mips_W14, Mips_W15, Mips_W16, Mips_W17, Mips_W18, Mips_W19, Mips_W20, Mips_W21, Mips_W22, Mips_W23, Mips_W24, Mips_W25, Mips_W26, Mips_W27, Mips_W28, Mips_W29, Mips_W30, Mips_W31, 
  };

  // MSA128B Bit set.
  static const uint8_t MSA128BBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // MSA128D Register Class...
  static const MCPhysReg MSA128D[] = {
    Mips_W0, Mips_W1, Mips_W2, Mips_W3, Mips_W4, Mips_W5, Mips_W6, Mips_W7, Mips_W8, Mips_W9, Mips_W10, Mips_W11, Mips_W12, Mips_W13, Mips_W14, Mips_W15, Mips_W16, Mips_W17, Mips_W18, Mips_W19, Mips_W20, Mips_W21, Mips_W22, Mips_W23, Mips_W24, Mips_W25, Mips_W26, Mips_W27, Mips_W28, Mips_W29, Mips_W30, Mips_W31, 
  };

  // MSA128D Bit set.
  static const uint8_t MSA128DBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // MSA128H Register Class...
  static const MCPhysReg MSA128H[] = {
    Mips_W0, Mips_W1, Mips_W2, Mips_W3, Mips_W4, Mips_W5, Mips_W6, Mips_W7, Mips_W8, Mips_W9, Mips_W10, Mips_W11, Mips_W12, Mips_W13, Mips_W14, Mips_W15, Mips_W16, Mips_W17, Mips_W18, Mips_W19, Mips_W20, Mips_W21, Mips_W22, Mips_W23, Mips_W24, Mips_W25, Mips_W26, Mips_W27, Mips_W28, Mips_W29, Mips_W30, Mips_W31, 
  };

  // MSA128H Bit set.
  static const uint8_t MSA128HBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // MSA128W Register Class...
  static const MCPhysReg MSA128W[] = {
    Mips_W0, Mips_W1, Mips_W2, Mips_W3, Mips_W4, Mips_W5, Mips_W6, Mips_W7, Mips_W8, Mips_W9, Mips_W10, Mips_W11, Mips_W12, Mips_W13, Mips_W14, Mips_W15, Mips_W16, Mips_W17, Mips_W18, Mips_W19, Mips_W20, Mips_W21, Mips_W22, Mips_W23, Mips_W24, Mips_W25, Mips_W26, Mips_W27, Mips_W28, Mips_W29, Mips_W30, Mips_W31, 
  };

  // MSA128W Bit set.
  static const uint8_t MSA128WBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // MSA128B_with_sub_64_in_OddSP Register Class...
  static const MCPhysReg MSA128B_with_sub_64_in_OddSP[] = {
    Mips_W1, Mips_W3, Mips_W5, Mips_W7, Mips_W9, Mips_W11, Mips_W13, Mips_W15, Mips_W17, Mips_W19, Mips_W21, Mips_W23, Mips_W25, Mips_W27, Mips_W29, Mips_W31, 
  };

  // MSA128B_with_sub_64_in_OddSP Bit set.
  static const uint8_t MSA128B_with_sub_64_in_OddSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x55, 0x55, 0x05, 
  };

  // ACC128 Register Class...
  static const MCPhysReg ACC128[] = {
    Mips_AC0_64, 
  };

  // ACC128 Bit set.
  static const uint8_t ACC128Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
  };

static const MCRegisterClass MipsMCRegisterClasses[] = {
  { "OddSP", OddSP, OddSPBits, 56, sizeof(OddSPBits), Mips_OddSPRegClassID, 4, 4, 1, 0 },
  { "CCR", CCR, CCRBits, 32, sizeof(CCRBits), Mips_CCRRegClassID, 4, 4, 1, 0 },
  { "COP2", COP2, COP2Bits, 32, sizeof(COP2Bits), Mips_COP2RegClassID, 4, 4, 1, 0 },
  { "COP3", COP3, COP3Bits, 32, sizeof(COP3Bits), Mips_COP3RegClassID, 4, 4, 1, 0 },
  { "DSPR", DSPR, DSPRBits, 32, sizeof(DSPRBits), Mips_DSPRRegClassID, 4, 4, 1, 1 },
  { "FGR32", FGR32, FGR32Bits, 32, sizeof(FGR32Bits), Mips_FGR32RegClassID, 4, 4, 1, 1 },
  { "FGRCC", FGRCC, FGRCCBits, 32, sizeof(FGRCCBits), Mips_FGRCCRegClassID, 4, 4, 1, 1 },
  { "FGRH32", FGRH32, FGRH32Bits, 32, sizeof(FGRH32Bits), Mips_FGRH32RegClassID, 4, 4, 1, 0 },
  { "GPR32", GPR32, GPR32Bits, 32, sizeof(GPR32Bits), Mips_GPR32RegClassID, 4, 4, 1, 1 },
  { "HWRegs", HWRegs, HWRegsBits, 32, sizeof(HWRegsBits), Mips_HWRegsRegClassID, 4, 4, 1, 0 },
  { "OddSP_with_sub_hi", OddSP_with_sub_hi, OddSP_with_sub_hiBits, 24, sizeof(OddSP_with_sub_hiBits), Mips_OddSP_with_sub_hiRegClassID, 4, 4, 1, 0 },
  { "FGR32_and_OddSP", FGR32_and_OddSP, FGR32_and_OddSPBits, 16, sizeof(FGR32_and_OddSPBits), Mips_FGR32_and_OddSPRegClassID, 4, 4, 1, 1 },
  { "FGRH32_and_OddSP", FGRH32_and_OddSP, FGRH32_and_OddSPBits, 16, sizeof(FGRH32_and_OddSPBits), Mips_FGRH32_and_OddSPRegClassID, 4, 4, 1, 0 },
  { "OddSP_with_sub_hi_with_sub_hi_in_FGRH32", OddSP_with_sub_hi_with_sub_hi_in_FGRH32, OddSP_with_sub_hi_with_sub_hi_in_FGRH32Bits, 16, sizeof(OddSP_with_sub_hi_with_sub_hi_in_FGRH32Bits), Mips_OddSP_with_sub_hi_with_sub_hi_in_FGRH32RegClassID, 4, 4, 1, 0 },
  { "CPU16RegsPlusSP", CPU16RegsPlusSP, CPU16RegsPlusSPBits, 9, sizeof(CPU16RegsPlusSPBits), Mips_CPU16RegsPlusSPRegClassID, 4, 4, 1, 1 },
  { "CC", CC, CCBits, 8, sizeof(CCBits), Mips_CCRegClassID, 4, 4, 1, 0 },
  { "CPU16Regs", CPU16Regs, CPU16RegsBits, 8, sizeof(CPU16RegsBits), Mips_CPU16RegsRegClassID, 4, 4, 1, 1 },
  { "FCC", FCC, FCCBits, 8, sizeof(FCCBits), Mips_FCCRegClassID, 4, 4, 1, 0 },
  { "MSACtrl", MSACtrl, MSACtrlBits, 8, sizeof(MSACtrlBits), Mips_MSACtrlRegClassID, 4, 4, 1, 1 },
  { "OddSP_with_sub_hi_with_sub_hi_in_FGR32", OddSP_with_sub_hi_with_sub_hi_in_FGR32, OddSP_with_sub_hi_with_sub_hi_in_FGR32Bits, 8, sizeof(OddSP_with_sub_hi_with_sub_hi_in_FGR32Bits), Mips_OddSP_with_sub_hi_with_sub_hi_in_FGR32RegClassID, 4, 4, 1, 0 },
  { "HI32DSP", HI32DSP, HI32DSPBits, 4, sizeof(HI32DSPBits), Mips_HI32DSPRegClassID, 4, 4, 1, 1 },
  { "LO32DSP", LO32DSP, LO32DSPBits, 4, sizeof(LO32DSPBits), Mips_LO32DSPRegClassID, 4, 4, 1, 1 },
  { "CPURAReg", CPURAReg, CPURARegBits, 1, sizeof(CPURARegBits), Mips_CPURARegRegClassID, 4, 4, 1, 0 },
  { "CPUSPReg", CPUSPReg, CPUSPRegBits, 1, sizeof(CPUSPRegBits), Mips_CPUSPRegRegClassID, 4, 4, 1, 0 },
  { "DSPCC", DSPCC, DSPCCBits, 1, sizeof(DSPCCBits), Mips_DSPCCRegClassID, 4, 4, 1, 1 },
  { "HI32", HI32, HI32Bits, 1, sizeof(HI32Bits), Mips_HI32RegClassID, 4, 4, 1, 1 },
  { "LO32", LO32, LO32Bits, 1, sizeof(LO32Bits), Mips_LO32RegClassID, 4, 4, 1, 1 },
  { "FGR64", FGR64, FGR64Bits, 32, sizeof(FGR64Bits), Mips_FGR64RegClassID, 8, 8, 1, 1 },
  { "GPR64", GPR64, GPR64Bits, 32, sizeof(GPR64Bits), Mips_GPR64RegClassID, 8, 8, 1, 1 },
  { "AFGR64", AFGR64, AFGR64Bits, 16, sizeof(AFGR64Bits), Mips_AFGR64RegClassID, 8, 8, 1, 1 },
  { "FGR64_and_OddSP", FGR64_and_OddSP, FGR64_and_OddSPBits, 16, sizeof(FGR64_and_OddSPBits), Mips_FGR64_and_OddSPRegClassID, 8, 8, 1, 1 },
  { "GPR64_with_sub_32_in_CPU16RegsPlusSP", GPR64_with_sub_32_in_CPU16RegsPlusSP, GPR64_with_sub_32_in_CPU16RegsPlusSPBits, 9, sizeof(GPR64_with_sub_32_in_CPU16RegsPlusSPBits), Mips_GPR64_with_sub_32_in_CPU16RegsPlusSPRegClassID, 8, 8, 1, 1 },
  { "AFGR64_and_OddSP", AFGR64_and_OddSP, AFGR64_and_OddSPBits, 8, sizeof(AFGR64_and_OddSPBits), Mips_AFGR64_and_OddSPRegClassID, 8, 8, 1, 1 },
  { "GPR64_with_sub_32_in_CPU16Regs", GPR64_with_sub_32_in_CPU16Regs, GPR64_with_sub_32_in_CPU16RegsBits, 8, sizeof(GPR64_with_sub_32_in_CPU16RegsBits), Mips_GPR64_with_sub_32_in_CPU16RegsRegClassID, 8, 8, 1, 1 },
  { "ACC64DSP", ACC64DSP, ACC64DSPBits, 4, sizeof(ACC64DSPBits), Mips_ACC64DSPRegClassID, 8, 8, 1, 1 },
  { "OCTEON_MPL", OCTEON_MPL, OCTEON_MPLBits, 3, sizeof(OCTEON_MPLBits), Mips_OCTEON_MPLRegClassID, 8, 8, 1, 0 },
  { "OCTEON_P", OCTEON_P, OCTEON_PBits, 3, sizeof(OCTEON_PBits), Mips_OCTEON_PRegClassID, 8, 8, 1, 0 },
  { "ACC64", ACC64, ACC64Bits, 1, sizeof(ACC64Bits), Mips_ACC64RegClassID, 8, 8, 1, 1 },
  { "GPR64_with_sub_32_in_CPURAReg", GPR64_with_sub_32_in_CPURAReg, GPR64_with_sub_32_in_CPURARegBits, 1, sizeof(GPR64_with_sub_32_in_CPURARegBits), Mips_GPR64_with_sub_32_in_CPURARegRegClassID, 8, 8, 1, 1 },
  { "GPR64_with_sub_32_in_CPUSPReg", GPR64_with_sub_32_in_CPUSPReg, GPR64_with_sub_32_in_CPUSPRegBits, 1, sizeof(GPR64_with_sub_32_in_CPUSPRegBits), Mips_GPR64_with_sub_32_in_CPUSPRegRegClassID, 8, 8, 1, 1 },
  { "HI64", HI64, HI64Bits, 1, sizeof(HI64Bits), Mips_HI64RegClassID, 8, 8, 1, 1 },
  { "LO64", LO64, LO64Bits, 1, sizeof(LO64Bits), Mips_LO64RegClassID, 8, 8, 1, 1 },
  { "MSA128B", MSA128B, MSA128BBits, 32, sizeof(MSA128BBits), Mips_MSA128BRegClassID, 16, 16, 1, 1 },
  { "MSA128D", MSA128D, MSA128DBits, 32, sizeof(MSA128DBits), Mips_MSA128DRegClassID, 16, 16, 1, 1 },
  { "MSA128H", MSA128H, MSA128HBits, 32, sizeof(MSA128HBits), Mips_MSA128HRegClassID, 16, 16, 1, 1 },
  { "MSA128W", MSA128W, MSA128WBits, 32, sizeof(MSA128WBits), Mips_MSA128WRegClassID, 16, 16, 1, 1 },
  { "MSA128B_with_sub_64_in_OddSP", MSA128B_with_sub_64_in_OddSP, MSA128B_with_sub_64_in_OddSPBits, 16, sizeof(MSA128B_with_sub_64_in_OddSPBits), Mips_MSA128B_with_sub_64_in_OddSPRegClassID, 16, 16, 1, 1 },
  { "ACC128", ACC128, ACC128Bits, 1, sizeof(ACC128Bits), Mips_ACC128RegClassID, 16, 16, 1, 1 },
};

#endif // GET_REGINFO_MC_DESC

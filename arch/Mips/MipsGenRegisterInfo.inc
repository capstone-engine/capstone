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
  Mips_COP20 = 31,
  Mips_COP21 = 32,
  Mips_COP22 = 33,
  Mips_COP23 = 34,
  Mips_COP24 = 35,
  Mips_COP25 = 36,
  Mips_COP26 = 37,
  Mips_COP27 = 38,
  Mips_COP28 = 39,
  Mips_COP29 = 40,
  Mips_COP30 = 41,
  Mips_COP31 = 42,
  Mips_COP32 = 43,
  Mips_COP33 = 44,
  Mips_COP34 = 45,
  Mips_COP35 = 46,
  Mips_COP36 = 47,
  Mips_COP37 = 48,
  Mips_COP38 = 49,
  Mips_COP39 = 50,
  Mips_COP210 = 51,
  Mips_COP211 = 52,
  Mips_COP212 = 53,
  Mips_COP213 = 54,
  Mips_COP214 = 55,
  Mips_COP215 = 56,
  Mips_COP216 = 57,
  Mips_COP217 = 58,
  Mips_COP218 = 59,
  Mips_COP219 = 60,
  Mips_COP220 = 61,
  Mips_COP221 = 62,
  Mips_COP222 = 63,
  Mips_COP223 = 64,
  Mips_COP224 = 65,
  Mips_COP225 = 66,
  Mips_COP226 = 67,
  Mips_COP227 = 68,
  Mips_COP228 = 69,
  Mips_COP229 = 70,
  Mips_COP230 = 71,
  Mips_COP231 = 72,
  Mips_COP310 = 73,
  Mips_COP311 = 74,
  Mips_COP312 = 75,
  Mips_COP313 = 76,
  Mips_COP314 = 77,
  Mips_COP315 = 78,
  Mips_COP316 = 79,
  Mips_COP317 = 80,
  Mips_COP318 = 81,
  Mips_COP319 = 82,
  Mips_COP320 = 83,
  Mips_COP321 = 84,
  Mips_COP322 = 85,
  Mips_COP323 = 86,
  Mips_COP324 = 87,
  Mips_COP325 = 88,
  Mips_COP326 = 89,
  Mips_COP327 = 90,
  Mips_COP328 = 91,
  Mips_COP329 = 92,
  Mips_COP330 = 93,
  Mips_COP331 = 94,
  Mips_D0 = 95,
  Mips_D1 = 96,
  Mips_D2 = 97,
  Mips_D3 = 98,
  Mips_D4 = 99,
  Mips_D5 = 100,
  Mips_D6 = 101,
  Mips_D7 = 102,
  Mips_D8 = 103,
  Mips_D9 = 104,
  Mips_D10 = 105,
  Mips_D11 = 106,
  Mips_D12 = 107,
  Mips_D13 = 108,
  Mips_D14 = 109,
  Mips_D15 = 110,
  Mips_DSPOutFlag20 = 111,
  Mips_DSPOutFlag21 = 112,
  Mips_DSPOutFlag22 = 113,
  Mips_DSPOutFlag23 = 114,
  Mips_F0 = 115,
  Mips_F1 = 116,
  Mips_F2 = 117,
  Mips_F3 = 118,
  Mips_F4 = 119,
  Mips_F5 = 120,
  Mips_F6 = 121,
  Mips_F7 = 122,
  Mips_F8 = 123,
  Mips_F9 = 124,
  Mips_F10 = 125,
  Mips_F11 = 126,
  Mips_F12 = 127,
  Mips_F13 = 128,
  Mips_F14 = 129,
  Mips_F15 = 130,
  Mips_F16 = 131,
  Mips_F17 = 132,
  Mips_F18 = 133,
  Mips_F19 = 134,
  Mips_F20 = 135,
  Mips_F21 = 136,
  Mips_F22 = 137,
  Mips_F23 = 138,
  Mips_F24 = 139,
  Mips_F25 = 140,
  Mips_F26 = 141,
  Mips_F27 = 142,
  Mips_F28 = 143,
  Mips_F29 = 144,
  Mips_F30 = 145,
  Mips_F31 = 146,
  Mips_FCC0 = 147,
  Mips_FCC1 = 148,
  Mips_FCC2 = 149,
  Mips_FCC3 = 150,
  Mips_FCC4 = 151,
  Mips_FCC5 = 152,
  Mips_FCC6 = 153,
  Mips_FCC7 = 154,
  Mips_FCR0 = 155,
  Mips_FCR1 = 156,
  Mips_FCR2 = 157,
  Mips_FCR3 = 158,
  Mips_FCR4 = 159,
  Mips_FCR5 = 160,
  Mips_FCR6 = 161,
  Mips_FCR7 = 162,
  Mips_FCR8 = 163,
  Mips_FCR9 = 164,
  Mips_FCR10 = 165,
  Mips_FCR11 = 166,
  Mips_FCR12 = 167,
  Mips_FCR13 = 168,
  Mips_FCR14 = 169,
  Mips_FCR15 = 170,
  Mips_FCR16 = 171,
  Mips_FCR17 = 172,
  Mips_FCR18 = 173,
  Mips_FCR19 = 174,
  Mips_FCR20 = 175,
  Mips_FCR21 = 176,
  Mips_FCR22 = 177,
  Mips_FCR23 = 178,
  Mips_FCR24 = 179,
  Mips_FCR25 = 180,
  Mips_FCR26 = 181,
  Mips_FCR27 = 182,
  Mips_FCR28 = 183,
  Mips_FCR29 = 184,
  Mips_FCR30 = 185,
  Mips_FCR31 = 186,
  Mips_FP_64 = 187,
  Mips_F_HI0 = 188,
  Mips_F_HI1 = 189,
  Mips_F_HI2 = 190,
  Mips_F_HI3 = 191,
  Mips_F_HI4 = 192,
  Mips_F_HI5 = 193,
  Mips_F_HI6 = 194,
  Mips_F_HI7 = 195,
  Mips_F_HI8 = 196,
  Mips_F_HI9 = 197,
  Mips_F_HI10 = 198,
  Mips_F_HI11 = 199,
  Mips_F_HI12 = 200,
  Mips_F_HI13 = 201,
  Mips_F_HI14 = 202,
  Mips_F_HI15 = 203,
  Mips_F_HI16 = 204,
  Mips_F_HI17 = 205,
  Mips_F_HI18 = 206,
  Mips_F_HI19 = 207,
  Mips_F_HI20 = 208,
  Mips_F_HI21 = 209,
  Mips_F_HI22 = 210,
  Mips_F_HI23 = 211,
  Mips_F_HI24 = 212,
  Mips_F_HI25 = 213,
  Mips_F_HI26 = 214,
  Mips_F_HI27 = 215,
  Mips_F_HI28 = 216,
  Mips_F_HI29 = 217,
  Mips_F_HI30 = 218,
  Mips_F_HI31 = 219,
  Mips_GP_64 = 220,
  Mips_HI0 = 221,
  Mips_HI1 = 222,
  Mips_HI2 = 223,
  Mips_HI3 = 224,
  Mips_HWR0 = 225,
  Mips_HWR1 = 226,
  Mips_HWR2 = 227,
  Mips_HWR3 = 228,
  Mips_HWR4 = 229,
  Mips_HWR5 = 230,
  Mips_HWR6 = 231,
  Mips_HWR7 = 232,
  Mips_HWR8 = 233,
  Mips_HWR9 = 234,
  Mips_HWR10 = 235,
  Mips_HWR11 = 236,
  Mips_HWR12 = 237,
  Mips_HWR13 = 238,
  Mips_HWR14 = 239,
  Mips_HWR15 = 240,
  Mips_HWR16 = 241,
  Mips_HWR17 = 242,
  Mips_HWR18 = 243,
  Mips_HWR19 = 244,
  Mips_HWR20 = 245,
  Mips_HWR21 = 246,
  Mips_HWR22 = 247,
  Mips_HWR23 = 248,
  Mips_HWR24 = 249,
  Mips_HWR25 = 250,
  Mips_HWR26 = 251,
  Mips_HWR27 = 252,
  Mips_HWR28 = 253,
  Mips_HWR29 = 254,
  Mips_HWR30 = 255,
  Mips_HWR31 = 256,
  Mips_K0 = 257,
  Mips_K1 = 258,
  Mips_LO0 = 259,
  Mips_LO1 = 260,
  Mips_LO2 = 261,
  Mips_LO3 = 262,
  Mips_MPL0 = 263,
  Mips_MPL1 = 264,
  Mips_MPL2 = 265,
  Mips_P0 = 266,
  Mips_P1 = 267,
  Mips_P2 = 268,
  Mips_RA_64 = 269,
  Mips_S0 = 270,
  Mips_S1 = 271,
  Mips_S2 = 272,
  Mips_S3 = 273,
  Mips_S4 = 274,
  Mips_S5 = 275,
  Mips_S6 = 276,
  Mips_S7 = 277,
  Mips_SP_64 = 278,
  Mips_T0 = 279,
  Mips_T1 = 280,
  Mips_T2 = 281,
  Mips_T3 = 282,
  Mips_T4 = 283,
  Mips_T5 = 284,
  Mips_T6 = 285,
  Mips_T7 = 286,
  Mips_T8 = 287,
  Mips_T9 = 288,
  Mips_V0 = 289,
  Mips_V1 = 290,
  Mips_W0 = 291,
  Mips_W1 = 292,
  Mips_W2 = 293,
  Mips_W3 = 294,
  Mips_W4 = 295,
  Mips_W5 = 296,
  Mips_W6 = 297,
  Mips_W7 = 298,
  Mips_W8 = 299,
  Mips_W9 = 300,
  Mips_W10 = 301,
  Mips_W11 = 302,
  Mips_W12 = 303,
  Mips_W13 = 304,
  Mips_W14 = 305,
  Mips_W15 = 306,
  Mips_W16 = 307,
  Mips_W17 = 308,
  Mips_W18 = 309,
  Mips_W19 = 310,
  Mips_W20 = 311,
  Mips_W21 = 312,
  Mips_W22 = 313,
  Mips_W23 = 314,
  Mips_W24 = 315,
  Mips_W25 = 316,
  Mips_W26 = 317,
  Mips_W27 = 318,
  Mips_W28 = 319,
  Mips_W29 = 320,
  Mips_W30 = 321,
  Mips_W31 = 322,
  Mips_ZERO_64 = 323,
  Mips_A0_64 = 324,
  Mips_A1_64 = 325,
  Mips_A2_64 = 326,
  Mips_A3_64 = 327,
  Mips_AC0_64 = 328,
  Mips_D0_64 = 329,
  Mips_D1_64 = 330,
  Mips_D2_64 = 331,
  Mips_D3_64 = 332,
  Mips_D4_64 = 333,
  Mips_D5_64 = 334,
  Mips_D6_64 = 335,
  Mips_D7_64 = 336,
  Mips_D8_64 = 337,
  Mips_D9_64 = 338,
  Mips_D10_64 = 339,
  Mips_D11_64 = 340,
  Mips_D12_64 = 341,
  Mips_D13_64 = 342,
  Mips_D14_64 = 343,
  Mips_D15_64 = 344,
  Mips_D16_64 = 345,
  Mips_D17_64 = 346,
  Mips_D18_64 = 347,
  Mips_D19_64 = 348,
  Mips_D20_64 = 349,
  Mips_D21_64 = 350,
  Mips_D22_64 = 351,
  Mips_D23_64 = 352,
  Mips_D24_64 = 353,
  Mips_D25_64 = 354,
  Mips_D26_64 = 355,
  Mips_D27_64 = 356,
  Mips_D28_64 = 357,
  Mips_D29_64 = 358,
  Mips_D30_64 = 359,
  Mips_D31_64 = 360,
  Mips_DSPOutFlag16_19 = 361,
  Mips_HI0_64 = 362,
  Mips_K0_64 = 363,
  Mips_K1_64 = 364,
  Mips_LO0_64 = 365,
  Mips_S0_64 = 366,
  Mips_S1_64 = 367,
  Mips_S2_64 = 368,
  Mips_S3_64 = 369,
  Mips_S4_64 = 370,
  Mips_S5_64 = 371,
  Mips_S6_64 = 372,
  Mips_S7_64 = 373,
  Mips_T0_64 = 374,
  Mips_T1_64 = 375,
  Mips_T2_64 = 376,
  Mips_T3_64 = 377,
  Mips_T4_64 = 378,
  Mips_T5_64 = 379,
  Mips_T6_64 = 380,
  Mips_T7_64 = 381,
  Mips_T8_64 = 382,
  Mips_T9_64 = 383,
  Mips_V0_64 = 384,
  Mips_V1_64 = 385,
  Mips_NUM_TARGET_REGS 	// 386
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
  Mips_CPU16RegsRegClassID = 15,
  Mips_FCCRegClassID = 16,
  Mips_MSACtrlRegClassID = 17,
  Mips_OddSP_with_sub_hi_with_sub_hi_in_FGR32RegClassID = 18,
  Mips_HI32DSPRegClassID = 19,
  Mips_LO32DSPRegClassID = 20,
  Mips_CPURARegRegClassID = 21,
  Mips_CPUSPRegRegClassID = 22,
  Mips_DSPCCRegClassID = 23,
  Mips_HI32RegClassID = 24,
  Mips_LO32RegClassID = 25,
  Mips_FGR64RegClassID = 26,
  Mips_GPR64RegClassID = 27,
  Mips_AFGR64RegClassID = 28,
  Mips_FGR64_and_OddSPRegClassID = 29,
  Mips_GPR64_with_sub_32_in_CPU16RegsPlusSPRegClassID = 30,
  Mips_AFGR64_and_OddSPRegClassID = 31,
  Mips_GPR64_with_sub_32_in_CPU16RegsRegClassID = 32,
  Mips_ACC64DSPRegClassID = 33,
  Mips_OCTEON_MPLRegClassID = 34,
  Mips_OCTEON_PRegClassID = 35,
  Mips_ACC64RegClassID = 36,
  Mips_GPR64_with_sub_32_in_CPURARegRegClassID = 37,
  Mips_GPR64_with_sub_32_in_CPUSPRegRegClassID = 38,
  Mips_HI64RegClassID = 39,
  Mips_LO64RegClassID = 40,
  Mips_MSA128BRegClassID = 41,
  Mips_MSA128DRegClassID = 42,
  Mips_MSA128HRegClassID = 43,
  Mips_MSA128WRegClassID = 44,
  Mips_MSA128B_with_sub_64_in_OddSPRegClassID = 45,
  Mips_ACC128RegClassID = 46
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

static MCPhysReg MipsRegDiffLists[] = {
  /* 0 */ 0, 0,
  /* 2 */ 4, 1, 1, 1, 1, 0,
  /* 8 */ 356, 65286, 1, 1, 1, 0,
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
  /* 62 */ 65447, 1, 0,
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
  /* 102 */ 179, 0,
  /* 104 */ 211, 0,
  /* 106 */ 250, 0,
  /* 108 */ 258, 0,
  /* 110 */ 302, 0,
  /* 112 */ 65047, 0,
  /* 114 */ 65124, 0,
  /* 116 */ 65180, 0,
  /* 118 */ 65234, 0,
  /* 120 */ 65237, 0,
  /* 122 */ 65278, 0,
  /* 124 */ 65286, 0,
  /* 126 */ 65303, 0,
  /* 128 */ 65325, 0,
  /* 130 */ 37, 65430, 103, 65395, 65341, 0,
  /* 136 */ 65357, 0,
  /* 138 */ 65395, 0,
  /* 140 */ 65410, 0,
  /* 142 */ 65415, 0,
  /* 144 */ 65427, 0,
  /* 146 */ 65428, 0,
  /* 148 */ 65429, 0,
  /* 150 */ 65430, 0,
  /* 152 */ 65440, 0,
  /* 154 */ 65441, 0,
  /* 156 */ 141, 65498, 0,
  /* 159 */ 233, 65498, 0,
  /* 162 */ 65516, 234, 65498, 0,
  /* 166 */ 65515, 235, 65498, 0,
  /* 170 */ 65514, 236, 65498, 0,
  /* 174 */ 65513, 237, 65498, 0,
  /* 178 */ 65512, 238, 65498, 0,
  /* 182 */ 65511, 239, 65498, 0,
  /* 186 */ 65510, 240, 65498, 0,
  /* 190 */ 65509, 241, 65498, 0,
  /* 194 */ 65508, 242, 65498, 0,
  /* 198 */ 65507, 243, 65498, 0,
  /* 202 */ 65506, 244, 65498, 0,
  /* 206 */ 65505, 245, 65498, 0,
  /* 210 */ 65504, 246, 65498, 0,
  /* 214 */ 65503, 247, 65498, 0,
  /* 218 */ 65502, 248, 65498, 0,
  /* 222 */ 65501, 249, 65498, 0,
  /* 226 */ 65500, 250, 65498, 0,
  /* 230 */ 65303, 339, 65499, 0,
  /* 234 */ 65341, 336, 65502, 0,
  /* 238 */ 65507, 0,
  /* 240 */ 65510, 0,
  /* 242 */ 65511, 0,
  /* 244 */ 65512, 0,
  /* 246 */ 65516, 0,
  /* 248 */ 65521, 0,
  /* 250 */ 65522, 0,
  /* 252 */ 65535, 0,
};

static uint16_t MipsSubRegIdxLists[] = {
  /* 0 */ 1, 0,
  /* 2 */ 3, 4, 5, 6, 7, 0,
  /* 8 */ 2, 9, 8, 0,
  /* 12 */ 9, 1, 8, 10, 11, 0,
};

static MCRegisterDesc MipsRegDesc[] = { // Descriptors
  { 6, 0, 0, 0, 0 },
  { 2007, 1, 82, 1, 4033 },
  { 2010, 1, 1, 1, 4033 },
  { 2102, 1, 1, 1, 4033 },
  { 1973, 1, 1, 1, 4033 },
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
  { 155, 159, 110, 9, 1042 },
  { 368, 159, 1, 9, 1042 },
  { 540, 159, 1, 9, 1042 },
  { 706, 159, 1, 9, 1042 },
  { 1271, 238, 1, 0, 0 },
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
  { 167, 1, 162, 1, 4001 },
  { 380, 1, 166, 1, 4001 },
  { 552, 1, 166, 1, 4001 },
  { 718, 1, 170, 1, 4001 },
  { 1285, 1, 170, 1, 4001 },
  { 1419, 1, 174, 1, 4001 },
  { 1549, 1, 174, 1, 4001 },
  { 1679, 1, 178, 1, 4001 },
  { 1804, 1, 178, 1, 4001 },
  { 1942, 1, 182, 1, 4001 },
  { 18, 1, 182, 1, 4001 },
  { 231, 1, 186, 1, 4001 },
  { 444, 1, 186, 1, 4001 },
  { 610, 1, 190, 1, 4001 },
  { 768, 1, 190, 1, 4001 },
  { 1331, 1, 194, 1, 4001 },
  { 1461, 1, 194, 1, 4001 },
  { 1591, 1, 198, 1, 4001 },
  { 1721, 1, 198, 1, 4001 },
  { 1843, 1, 202, 1, 4001 },
  { 59, 1, 202, 1, 4001 },
  { 272, 1, 206, 1, 4001 },
  { 485, 1, 206, 1, 4001 },
  { 651, 1, 210, 1, 4001 },
  { 809, 1, 210, 1, 4001 },
  { 1372, 1, 214, 1, 4001 },
  { 1502, 1, 214, 1, 4001 },
  { 1632, 1, 218, 1, 4001 },
  { 1762, 1, 218, 1, 4001 },
  { 1900, 1, 222, 1, 4001 },
  { 119, 1, 222, 1, 4001 },
  { 332, 1, 226, 1, 4001 },
  { 159, 1, 1, 1, 4001 },
  { 372, 1, 1, 1, 4001 },
  { 544, 1, 1, 1, 4001 },
  { 710, 1, 1, 1, 4001 },
  { 1277, 1, 1, 1, 4001 },
  { 1411, 1, 1, 1, 4001 },
  { 1541, 1, 1, 1, 4001 },
  { 1671, 1, 1, 1, 4001 },
  { 191, 1, 1, 1, 4001 },
  { 404, 1, 1, 1, 4001 },
  { 573, 1, 1, 1, 4001 },
  { 731, 1, 1, 1, 4001 },
  { 1294, 1, 1, 1, 4001 },
  { 1428, 1, 1, 1, 4001 },
  { 1558, 1, 1, 1, 4001 },
  { 1688, 1, 1, 1, 4001 },
  { 1813, 1, 1, 1, 4001 },
  { 1951, 1, 1, 1, 4001 },
  { 29, 1, 1, 1, 4001 },
  { 242, 1, 1, 1, 4001 },
  { 455, 1, 1, 1, 4001 },
  { 621, 1, 1, 1, 4001 },
  { 779, 1, 1, 1, 4001 },
  { 1342, 1, 1, 1, 4001 },
  { 1472, 1, 1, 1, 4001 },
  { 1602, 1, 1, 1, 4001 },
  { 1732, 1, 1, 1, 4001 },
  { 1854, 1, 1, 1, 4001 },
  { 76, 1, 1, 1, 4001 },
  { 289, 1, 1, 1, 4001 },
  { 502, 1, 1, 1, 4001 },
  { 668, 1, 1, 1, 4001 },
  { 826, 1, 1, 1, 4001 },
  { 1389, 1, 1, 1, 4001 },
  { 1519, 1, 1, 1, 4001 },
  { 1649, 1, 1, 1, 4001 },
  { 1779, 1, 1, 1, 4001 },
  { 1917, 1, 1, 1, 4001 },
  { 136, 1, 1, 1, 4001 },
  { 349, 1, 1, 1, 4001 },
  { 1253, 136, 1, 0, 1184 },
  { 170, 1, 156, 1, 3969 },
  { 383, 1, 156, 1, 3969 },
  { 555, 1, 156, 1, 3969 },
  { 721, 1, 156, 1, 3969 },
  { 1288, 1, 156, 1, 3969 },
  { 1422, 1, 156, 1, 3969 },
  { 1552, 1, 156, 1, 3969 },
  { 1682, 1, 156, 1, 3969 },
  { 1807, 1, 156, 1, 3969 },
  { 1945, 1, 156, 1, 3969 },
  { 22, 1, 156, 1, 3969 },
  { 235, 1, 156, 1, 3969 },
  { 448, 1, 156, 1, 3969 },
  { 614, 1, 156, 1, 3969 },
  { 772, 1, 156, 1, 3969 },
  { 1335, 1, 156, 1, 3969 },
  { 1465, 1, 156, 1, 3969 },
  { 1595, 1, 156, 1, 3969 },
  { 1725, 1, 156, 1, 3969 },
  { 1847, 1, 156, 1, 3969 },
  { 63, 1, 156, 1, 3969 },
  { 276, 1, 156, 1, 3969 },
  { 489, 1, 156, 1, 3969 },
  { 655, 1, 156, 1, 3969 },
  { 813, 1, 156, 1, 3969 },
  { 1376, 1, 156, 1, 3969 },
  { 1506, 1, 156, 1, 3969 },
  { 1636, 1, 156, 1, 3969 },
  { 1766, 1, 156, 1, 3969 },
  { 1904, 1, 156, 1, 3969 },
  { 123, 1, 156, 1, 3969 },
  { 336, 1, 156, 1, 3969 },
  { 1259, 128, 1, 0, 1216 },
  { 172, 1, 234, 1, 1826 },
  { 385, 1, 134, 1, 1826 },
  { 557, 1, 134, 1, 1826 },
  { 723, 1, 134, 1, 1826 },
  { 196, 1, 1, 1, 3937 },
  { 409, 1, 1, 1, 3937 },
  { 578, 1, 1, 1, 3937 },
  { 736, 1, 1, 1, 3937 },
  { 1299, 1, 1, 1, 3937 },
  { 1433, 1, 1, 1, 3937 },
  { 1563, 1, 1, 1, 3937 },
  { 1693, 1, 1, 1, 3937 },
  { 1818, 1, 1, 1, 3937 },
  { 1956, 1, 1, 1, 3937 },
  { 35, 1, 1, 1, 3937 },
  { 248, 1, 1, 1, 3937 },
  { 461, 1, 1, 1, 3937 },
  { 627, 1, 1, 1, 3937 },
  { 785, 1, 1, 1, 3937 },
  { 1348, 1, 1, 1, 3937 },
  { 1478, 1, 1, 1, 3937 },
  { 1608, 1, 1, 1, 3937 },
  { 1738, 1, 1, 1, 3937 },
  { 1860, 1, 1, 1, 3937 },
  { 82, 1, 1, 1, 3937 },
  { 295, 1, 1, 1, 3937 },
  { 508, 1, 1, 1, 3937 },
  { 674, 1, 1, 1, 3937 },
  { 832, 1, 1, 1, 3937 },
  { 1395, 1, 1, 1, 3937 },
  { 1525, 1, 1, 1, 3937 },
  { 1655, 1, 1, 1, 3937 },
  { 1785, 1, 1, 1, 3937 },
  { 1923, 1, 1, 1, 3937 },
  { 142, 1, 1, 1, 3937 },
  { 355, 1, 1, 1, 3937 },
  { 176, 1, 100, 1, 3937 },
  { 389, 1, 100, 1, 3937 },
  { 184, 1, 230, 1, 1794 },
  { 397, 1, 126, 1, 1794 },
  { 566, 1, 126, 1, 1794 },
  { 727, 1, 126, 1, 1794 },
  { 179, 1, 1, 1, 3905 },
  { 392, 1, 1, 1, 3905 },
  { 561, 1, 1, 1, 3905 },
  { 188, 1, 1, 1, 3905 },
  { 401, 1, 1, 1, 3905 },
  { 570, 1, 1, 1, 3905 },
  { 1239, 124, 1, 0, 1248 },
  { 201, 1, 98, 1, 3873 },
  { 414, 1, 98, 1, 3873 },
  { 583, 1, 98, 1, 3873 },
  { 741, 1, 98, 1, 3873 },
  { 1304, 1, 98, 1, 3873 },
  { 1438, 1, 98, 1, 3873 },
  { 1568, 1, 98, 1, 3873 },
  { 1698, 1, 98, 1, 3873 },
  { 1265, 122, 1, 0, 1280 },
  { 204, 1, 96, 1, 3841 },
  { 417, 1, 96, 1, 3841 },
  { 586, 1, 96, 1, 3841 },
  { 744, 1, 96, 1, 3841 },
  { 1307, 1, 96, 1, 3841 },
  { 1441, 1, 96, 1, 3841 },
  { 1571, 1, 96, 1, 3841 },
  { 1701, 1, 96, 1, 3841 },
  { 1823, 1, 96, 1, 3841 },
  { 1961, 1, 96, 1, 3841 },
  { 207, 1, 96, 1, 3841 },
  { 420, 1, 96, 1, 3841 },
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
  { 882, 93, 157, 9, 1377 },
  { 953, 93, 157, 9, 1377 },
  { 1003, 93, 157, 9, 1377 },
  { 1041, 93, 157, 9, 1377 },
  { 1073, 93, 157, 9, 1377 },
  { 1105, 93, 157, 9, 1377 },
  { 1137, 93, 157, 9, 1377 },
  { 1169, 93, 157, 9, 1377 },
  { 1201, 93, 157, 9, 1377 },
  { 1227, 93, 157, 9, 1377 },
  { 848, 93, 157, 9, 1377 },
  { 926, 93, 157, 9, 1377 },
  { 983, 93, 157, 9, 1377 },
  { 1021, 93, 157, 9, 1377 },
  { 1059, 93, 157, 9, 1377 },
  { 1091, 93, 157, 9, 1377 },
  { 1123, 93, 157, 9, 1377 },
  { 1155, 93, 157, 9, 1377 },
  { 1187, 93, 157, 9, 1377 },
  { 1213, 93, 157, 9, 1377 },
  { 855, 93, 157, 9, 1377 },
  { 933, 93, 157, 9, 1377 },
  { 990, 93, 157, 9, 1377 },
  { 1028, 93, 157, 9, 1377 },
  { 1066, 93, 157, 9, 1377 },
  { 1098, 93, 157, 9, 1377 },
  { 1130, 93, 157, 9, 1377 },
  { 1162, 93, 157, 9, 1377 },
  { 1194, 93, 157, 9, 1377 },
  { 1220, 93, 157, 9, 1377 },
  { 862, 93, 157, 9, 1377 },
  { 940, 93, 157, 9, 1377 },
  { 1870, 1, 116, 1, 1120 },
  { 888, 138, 236, 0, 1344 },
  { 895, 150, 1, 0, 2241 },
  { 959, 150, 1, 0, 2241 },
  { 901, 150, 232, 0, 1312 },
  { 908, 152, 1, 0, 2273 },
  { 965, 152, 1, 0, 2273 },
  { 1009, 152, 1, 0, 2273 },
  { 1047, 152, 1, 0, 2273 },
  { 1079, 152, 1, 0, 2273 },
  { 1111, 152, 1, 0, 2273 },
  { 1143, 152, 1, 0, 2273 },
  { 1175, 152, 1, 0, 2273 },
  { 914, 154, 1, 0, 2273 },
  { 971, 154, 1, 0, 2273 },
  { 1015, 154, 1, 0, 2273 },
  { 1053, 154, 1, 0, 2273 },
  { 1085, 154, 1, 0, 2273 },
  { 1117, 154, 1, 0, 2273 },
  { 1149, 154, 1, 0, 2273 },
  { 1181, 154, 1, 0, 2273 },
  { 1207, 154, 1, 0, 2273 },
  { 1233, 154, 1, 0, 2273 },
  { 920, 154, 1, 0, 2273 },
  { 977, 154, 1, 0, 2273 },
};

  // OddSP Register Class...
  static MCPhysReg OddSP[] = {
    Mips_F1, Mips_F3, Mips_F5, Mips_F7, Mips_F9, Mips_F11, Mips_F13, Mips_F15, Mips_F17, Mips_F19, Mips_F21, Mips_F23, Mips_F25, Mips_F27, Mips_F29, Mips_F31, Mips_F_HI1, Mips_F_HI3, Mips_F_HI5, Mips_F_HI7, Mips_F_HI9, Mips_F_HI11, Mips_F_HI13, Mips_F_HI15, Mips_F_HI17, Mips_F_HI19, Mips_F_HI21, Mips_F_HI23, Mips_F_HI25, Mips_F_HI27, Mips_F_HI29, Mips_F_HI31, Mips_D1, Mips_D3, Mips_D5, Mips_D7, Mips_D9, Mips_D11, Mips_D13, Mips_D15, Mips_D1_64, Mips_D3_64, Mips_D5_64, Mips_D7_64, Mips_D9_64, Mips_D11_64, Mips_D13_64, Mips_D15_64, Mips_D17_64, Mips_D19_64, Mips_D21_64, Mips_D23_64, Mips_D25_64, Mips_D27_64, Mips_D29_64, Mips_D31_64, 
  };

  // OddSP Bit set.
  static uint8_t OddSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x55, 0x50, 0x55, 0x55, 0x55, 0x05, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 0xaa, 0xaa, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x55, 0x55, 0x55, 0x01, 
  };

  // CCR Register Class...
  static MCPhysReg CCR[] = {
    Mips_FCR0, Mips_FCR1, Mips_FCR2, Mips_FCR3, Mips_FCR4, Mips_FCR5, Mips_FCR6, Mips_FCR7, Mips_FCR8, Mips_FCR9, Mips_FCR10, Mips_FCR11, Mips_FCR12, Mips_FCR13, Mips_FCR14, Mips_FCR15, Mips_FCR16, Mips_FCR17, Mips_FCR18, Mips_FCR19, Mips_FCR20, Mips_FCR21, Mips_FCR22, Mips_FCR23, Mips_FCR24, Mips_FCR25, Mips_FCR26, Mips_FCR27, Mips_FCR28, Mips_FCR29, Mips_FCR30, Mips_FCR31, 
  };

  // CCR Bit set.
  static uint8_t CCRBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // COP2 Register Class...
  static MCPhysReg COP2[] = {
    Mips_COP20, Mips_COP21, Mips_COP22, Mips_COP23, Mips_COP24, Mips_COP25, Mips_COP26, Mips_COP27, Mips_COP28, Mips_COP29, Mips_COP210, Mips_COP211, Mips_COP212, Mips_COP213, Mips_COP214, Mips_COP215, Mips_COP216, Mips_COP217, Mips_COP218, Mips_COP219, Mips_COP220, Mips_COP221, Mips_COP222, Mips_COP223, Mips_COP224, Mips_COP225, Mips_COP226, Mips_COP227, Mips_COP228, Mips_COP229, Mips_COP230, Mips_COP231, 
  };

  // COP2 Bit set.
  static uint8_t COP2Bits[] = {
    0x00, 0x00, 0x00, 0x80, 0xff, 0x01, 0xf8, 0xff, 0xff, 0x01, 
  };

  // COP3 Register Class...
  static MCPhysReg COP3[] = {
    Mips_COP30, Mips_COP31, Mips_COP32, Mips_COP33, Mips_COP34, Mips_COP35, Mips_COP36, Mips_COP37, Mips_COP38, Mips_COP39, Mips_COP310, Mips_COP311, Mips_COP312, Mips_COP313, Mips_COP314, Mips_COP315, Mips_COP316, Mips_COP317, Mips_COP318, Mips_COP319, Mips_COP320, Mips_COP321, Mips_COP322, Mips_COP323, Mips_COP324, Mips_COP325, Mips_COP326, Mips_COP327, Mips_COP328, Mips_COP329, Mips_COP330, Mips_COP331, 
  };

  // COP3 Bit set.
  static uint8_t COP3Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x07, 0x00, 0x00, 0xfe, 0xff, 0x7f, 
  };

  // DSPR Register Class...
  static MCPhysReg DSPR[] = {
    Mips_ZERO, Mips_AT, Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, Mips_T0, Mips_T1, Mips_T2, Mips_T3, Mips_T4, Mips_T5, Mips_T6, Mips_T7, Mips_S0, Mips_S1, Mips_S2, Mips_S3, Mips_S4, Mips_S5, Mips_S6, Mips_S7, Mips_T8, Mips_T9, Mips_K0, Mips_K1, Mips_GP, Mips_SP, Mips_FP, Mips_RA, 
  };

  // DSPR Bit set.
  static uint8_t DSPRBits[] = {
    0x02, 0x03, 0xf8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0xc0, 0xbf, 0xff, 0x07, 
  };

  // FGR32 Register Class...
  static MCPhysReg FGR32[] = {
    Mips_F0, Mips_F1, Mips_F2, Mips_F3, Mips_F4, Mips_F5, Mips_F6, Mips_F7, Mips_F8, Mips_F9, Mips_F10, Mips_F11, Mips_F12, Mips_F13, Mips_F14, Mips_F15, Mips_F16, Mips_F17, Mips_F18, Mips_F19, Mips_F20, Mips_F21, Mips_F22, Mips_F23, Mips_F24, Mips_F25, Mips_F26, Mips_F27, Mips_F28, Mips_F29, Mips_F30, Mips_F31, 
  };

  // FGR32 Bit set.
  static uint8_t FGR32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // FGRCC Register Class...
  static MCPhysReg FGRCC[] = {
    Mips_F0, Mips_F1, Mips_F2, Mips_F3, Mips_F4, Mips_F5, Mips_F6, Mips_F7, Mips_F8, Mips_F9, Mips_F10, Mips_F11, Mips_F12, Mips_F13, Mips_F14, Mips_F15, Mips_F16, Mips_F17, Mips_F18, Mips_F19, Mips_F20, Mips_F21, Mips_F22, Mips_F23, Mips_F24, Mips_F25, Mips_F26, Mips_F27, Mips_F28, Mips_F29, Mips_F30, Mips_F31, 
  };

  // FGRCC Bit set.
  static uint8_t FGRCCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // FGRH32 Register Class...
  static MCPhysReg FGRH32[] = {
    Mips_F_HI0, Mips_F_HI1, Mips_F_HI2, Mips_F_HI3, Mips_F_HI4, Mips_F_HI5, Mips_F_HI6, Mips_F_HI7, Mips_F_HI8, Mips_F_HI9, Mips_F_HI10, Mips_F_HI11, Mips_F_HI12, Mips_F_HI13, Mips_F_HI14, Mips_F_HI15, Mips_F_HI16, Mips_F_HI17, Mips_F_HI18, Mips_F_HI19, Mips_F_HI20, Mips_F_HI21, Mips_F_HI22, Mips_F_HI23, Mips_F_HI24, Mips_F_HI25, Mips_F_HI26, Mips_F_HI27, Mips_F_HI28, Mips_F_HI29, Mips_F_HI30, Mips_F_HI31, 
  };

  // FGRH32 Bit set.
  static uint8_t FGRH32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // GPR32 Register Class...
  static MCPhysReg GPR32[] = {
    Mips_ZERO, Mips_AT, Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, Mips_T0, Mips_T1, Mips_T2, Mips_T3, Mips_T4, Mips_T5, Mips_T6, Mips_T7, Mips_S0, Mips_S1, Mips_S2, Mips_S3, Mips_S4, Mips_S5, Mips_S6, Mips_S7, Mips_T8, Mips_T9, Mips_K0, Mips_K1, Mips_GP, Mips_SP, Mips_FP, Mips_RA, 
  };

  // GPR32 Bit set.
  static uint8_t GPR32Bits[] = {
    0x02, 0x03, 0xf8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0xc0, 0xbf, 0xff, 0x07, 
  };

  // HWRegs Register Class...
  static MCPhysReg HWRegs[] = {
    Mips_HWR0, Mips_HWR1, Mips_HWR2, Mips_HWR3, Mips_HWR4, Mips_HWR5, Mips_HWR6, Mips_HWR7, Mips_HWR8, Mips_HWR9, Mips_HWR10, Mips_HWR11, Mips_HWR12, Mips_HWR13, Mips_HWR14, Mips_HWR15, Mips_HWR16, Mips_HWR17, Mips_HWR18, Mips_HWR19, Mips_HWR20, Mips_HWR21, Mips_HWR22, Mips_HWR23, Mips_HWR24, Mips_HWR25, Mips_HWR26, Mips_HWR27, Mips_HWR28, Mips_HWR29, Mips_HWR30, Mips_HWR31, 
  };

  // HWRegs Bit set.
  static uint8_t HWRegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01, 
  };

  // OddSP_with_sub_hi Register Class...
  static MCPhysReg OddSP_with_sub_hi[] = {
    Mips_D1, Mips_D3, Mips_D5, Mips_D7, Mips_D9, Mips_D11, Mips_D13, Mips_D15, Mips_D1_64, Mips_D3_64, Mips_D5_64, Mips_D7_64, Mips_D9_64, Mips_D11_64, Mips_D13_64, Mips_D15_64, Mips_D17_64, Mips_D19_64, Mips_D21_64, Mips_D23_64, Mips_D25_64, Mips_D27_64, Mips_D29_64, Mips_D31_64, 
  };

  // OddSP_with_sub_hi Bit set.
  static uint8_t OddSP_with_sub_hiBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x55, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x55, 0x55, 0x55, 0x01, 
  };

  // FGR32_and_OddSP Register Class...
  static MCPhysReg FGR32_and_OddSP[] = {
    Mips_F1, Mips_F3, Mips_F5, Mips_F7, Mips_F9, Mips_F11, Mips_F13, Mips_F15, Mips_F17, Mips_F19, Mips_F21, Mips_F23, Mips_F25, Mips_F27, Mips_F29, Mips_F31, 
  };

  // FGR32_and_OddSP Bit set.
  static uint8_t FGR32_and_OddSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x55, 0x55, 0x05, 
  };

  // FGRH32_and_OddSP Register Class...
  static MCPhysReg FGRH32_and_OddSP[] = {
    Mips_F_HI1, Mips_F_HI3, Mips_F_HI5, Mips_F_HI7, Mips_F_HI9, Mips_F_HI11, Mips_F_HI13, Mips_F_HI15, Mips_F_HI17, Mips_F_HI19, Mips_F_HI21, Mips_F_HI23, Mips_F_HI25, Mips_F_HI27, Mips_F_HI29, Mips_F_HI31, 
  };

  // FGRH32_and_OddSP Bit set.
  static uint8_t FGRH32_and_OddSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 0xaa, 0xaa, 0x0a, 
  };

  // OddSP_with_sub_hi_with_sub_hi_in_FGRH32 Register Class...
  static MCPhysReg OddSP_with_sub_hi_with_sub_hi_in_FGRH32[] = {
    Mips_D1_64, Mips_D3_64, Mips_D5_64, Mips_D7_64, Mips_D9_64, Mips_D11_64, Mips_D13_64, Mips_D15_64, Mips_D17_64, Mips_D19_64, Mips_D21_64, Mips_D23_64, Mips_D25_64, Mips_D27_64, Mips_D29_64, Mips_D31_64, 
  };

  // OddSP_with_sub_hi_with_sub_hi_in_FGRH32 Bit set.
  static uint8_t OddSP_with_sub_hi_with_sub_hi_in_FGRH32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x55, 0x55, 0x55, 0x01, 
  };

  // CPU16RegsPlusSP Register Class...
  static MCPhysReg CPU16RegsPlusSP[] = {
    Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, Mips_S0, Mips_S1, Mips_SP, 
  };

  // CPU16RegsPlusSP Bit set.
  static uint8_t CPU16RegsPlusSPBits[] = {
    0x00, 0x00, 0xd0, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x06, 
  };

  // CPU16Regs Register Class...
  static MCPhysReg CPU16Regs[] = {
    Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, Mips_S0, Mips_S1, 
  };

  // CPU16Regs Bit set.
  static uint8_t CPU16RegsBits[] = {
    0x00, 0x00, 0xc0, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x06, 
  };

  // FCC Register Class...
  static MCPhysReg FCC[] = {
    Mips_FCC0, Mips_FCC1, Mips_FCC2, Mips_FCC3, Mips_FCC4, Mips_FCC5, Mips_FCC6, Mips_FCC7, 
  };

  // FCC Bit set.
  static uint8_t FCCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x07, 
  };

  // MSACtrl Register Class...
  static MCPhysReg MSACtrl[] = {
    Mips_MSAIR, Mips_MSACSR, Mips_MSAAccess, Mips_MSASave, Mips_MSAModify, Mips_MSARequest, Mips_MSAMap, Mips_MSAUnmap, 
  };

  // MSACtrl Bit set.
  static uint8_t MSACtrlBits[] = {
    0x00, 0xfc, 0x03, 
  };

  // OddSP_with_sub_hi_with_sub_hi_in_FGR32 Register Class...
  static MCPhysReg OddSP_with_sub_hi_with_sub_hi_in_FGR32[] = {
    Mips_D1, Mips_D3, Mips_D5, Mips_D7, Mips_D9, Mips_D11, Mips_D13, Mips_D15, 
  };

  // OddSP_with_sub_hi_with_sub_hi_in_FGR32 Bit set.
  static uint8_t OddSP_with_sub_hi_with_sub_hi_in_FGR32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x55, 
  };

  // HI32DSP Register Class...
  static MCPhysReg HI32DSP[] = {
    Mips_HI0, Mips_HI1, Mips_HI2, Mips_HI3, 
  };

  // HI32DSP Bit set.
  static uint8_t HI32DSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x01, 
  };

  // LO32DSP Register Class...
  static MCPhysReg LO32DSP[] = {
    Mips_LO0, Mips_LO1, Mips_LO2, Mips_LO3, 
  };

  // LO32DSP Bit set.
  static uint8_t LO32DSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 
  };

  // CPURAReg Register Class...
  static MCPhysReg CPURAReg[] = {
    Mips_RA, 
  };

  // CPURAReg Bit set.
  static uint8_t CPURARegBits[] = {
    0x00, 0x00, 0x08, 
  };

  // CPUSPReg Register Class...
  static MCPhysReg CPUSPReg[] = {
    Mips_SP, 
  };

  // CPUSPReg Bit set.
  static uint8_t CPUSPRegBits[] = {
    0x00, 0x00, 0x10, 
  };

  // DSPCC Register Class...
  static MCPhysReg DSPCC[] = {
    Mips_DSPCCond, 
  };

  // DSPCC Bit set.
  static uint8_t DSPCCBits[] = {
    0x04, 
  };

  // HI32 Register Class...
  static MCPhysReg HI32[] = {
    Mips_HI0, 
  };

  // HI32 Bit set.
  static uint8_t HI32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 
  };

  // LO32 Register Class...
  static MCPhysReg LO32[] = {
    Mips_LO0, 
  };

  // LO32 Bit set.
  static uint8_t LO32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 
  };

  // FGR64 Register Class...
  static MCPhysReg FGR64[] = {
    Mips_D0_64, Mips_D1_64, Mips_D2_64, Mips_D3_64, Mips_D4_64, Mips_D5_64, Mips_D6_64, Mips_D7_64, Mips_D8_64, Mips_D9_64, Mips_D10_64, Mips_D11_64, Mips_D12_64, Mips_D13_64, Mips_D14_64, Mips_D15_64, Mips_D16_64, Mips_D17_64, Mips_D18_64, Mips_D19_64, Mips_D20_64, Mips_D21_64, Mips_D22_64, Mips_D23_64, Mips_D24_64, Mips_D25_64, Mips_D26_64, Mips_D27_64, Mips_D28_64, Mips_D29_64, Mips_D30_64, Mips_D31_64, 
  };

  // FGR64 Bit set.
  static uint8_t FGR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01, 
  };

  // GPR64 Register Class...
  static MCPhysReg GPR64[] = {
    Mips_ZERO_64, Mips_AT_64, Mips_V0_64, Mips_V1_64, Mips_A0_64, Mips_A1_64, Mips_A2_64, Mips_A3_64, Mips_T0_64, Mips_T1_64, Mips_T2_64, Mips_T3_64, Mips_T4_64, Mips_T5_64, Mips_T6_64, Mips_T7_64, Mips_S0_64, Mips_S1_64, Mips_S2_64, Mips_S3_64, Mips_S4_64, Mips_S5_64, Mips_S6_64, Mips_S7_64, Mips_T8_64, Mips_T9_64, Mips_K0_64, Mips_K1_64, Mips_GP_64, Mips_SP_64, Mips_FP_64, Mips_RA_64, 
  };

  // GPR64 Bit set.
  static uint8_t GPR64Bits[] = {
    0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x00, 0x00, 0x00, 0x00, 0xd8, 0xff, 0xff, 0x03, 
  };

  // AFGR64 Register Class...
  static MCPhysReg AFGR64[] = {
    Mips_D0, Mips_D1, Mips_D2, Mips_D3, Mips_D4, Mips_D5, Mips_D6, Mips_D7, Mips_D8, Mips_D9, Mips_D10, Mips_D11, Mips_D12, Mips_D13, Mips_D14, Mips_D15, 
  };

  // AFGR64 Bit set.
  static uint8_t AFGR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0x7f, 
  };

  // FGR64_and_OddSP Register Class...
  static MCPhysReg FGR64_and_OddSP[] = {
    Mips_D1_64, Mips_D3_64, Mips_D5_64, Mips_D7_64, Mips_D9_64, Mips_D11_64, Mips_D13_64, Mips_D15_64, Mips_D17_64, Mips_D19_64, Mips_D21_64, Mips_D23_64, Mips_D25_64, Mips_D27_64, Mips_D29_64, Mips_D31_64, 
  };

  // FGR64_and_OddSP Bit set.
  static uint8_t FGR64_and_OddSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x54, 0x55, 0x55, 0x55, 0x01, 
  };

  // GPR64_with_sub_32_in_CPU16RegsPlusSP Register Class...
  static MCPhysReg GPR64_with_sub_32_in_CPU16RegsPlusSP[] = {
    Mips_V0_64, Mips_V1_64, Mips_A0_64, Mips_A1_64, Mips_A2_64, Mips_A3_64, Mips_S0_64, Mips_S1_64, Mips_SP_64, 
  };

  // GPR64_with_sub_32_in_CPU16RegsPlusSP Bit set.
  static uint8_t GPR64_with_sub_32_in_CPU16RegsPlusSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x03, 
  };

  // AFGR64_and_OddSP Register Class...
  static MCPhysReg AFGR64_and_OddSP[] = {
    Mips_D1, Mips_D3, Mips_D5, Mips_D7, Mips_D9, Mips_D11, Mips_D13, Mips_D15, 
  };

  // AFGR64_and_OddSP Bit set.
  static uint8_t AFGR64_and_OddSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x55, 
  };

  // GPR64_with_sub_32_in_CPU16Regs Register Class...
  static MCPhysReg GPR64_with_sub_32_in_CPU16Regs[] = {
    Mips_V0_64, Mips_V1_64, Mips_A0_64, Mips_A1_64, Mips_A2_64, Mips_A3_64, Mips_S0_64, Mips_S1_64, 
  };

  // GPR64_with_sub_32_in_CPU16Regs Bit set.
  static uint8_t GPR64_with_sub_32_in_CPU16RegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x03, 
  };

  // ACC64DSP Register Class...
  static MCPhysReg ACC64DSP[] = {
    Mips_AC0, Mips_AC1, Mips_AC2, Mips_AC3, 
  };

  // ACC64DSP Bit set.
  static uint8_t ACC64DSPBits[] = {
    0x00, 0x00, 0x00, 0x3c, 
  };

  // OCTEON_MPL Register Class...
  static MCPhysReg OCTEON_MPL[] = {
    Mips_MPL0, Mips_MPL1, Mips_MPL2, 
  };

  // OCTEON_MPL Bit set.
  static uint8_t OCTEON_MPLBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x03, 
  };

  // OCTEON_P Register Class...
  static MCPhysReg OCTEON_P[] = {
    Mips_P0, Mips_P1, Mips_P2, 
  };

  // OCTEON_P Bit set.
  static uint8_t OCTEON_PBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 
  };

  // ACC64 Register Class...
  static MCPhysReg ACC64[] = {
    Mips_AC0, 
  };

  // ACC64 Bit set.
  static uint8_t ACC64Bits[] = {
    0x00, 0x00, 0x00, 0x04, 
  };

  // GPR64_with_sub_32_in_CPURAReg Register Class...
  static MCPhysReg GPR64_with_sub_32_in_CPURAReg[] = {
    Mips_RA_64, 
  };

  // GPR64_with_sub_32_in_CPURAReg Bit set.
  static uint8_t GPR64_with_sub_32_in_CPURARegBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 
  };

  // GPR64_with_sub_32_in_CPUSPReg Register Class...
  static MCPhysReg GPR64_with_sub_32_in_CPUSPReg[] = {
    Mips_SP_64, 
  };

  // GPR64_with_sub_32_in_CPUSPReg Bit set.
  static uint8_t GPR64_with_sub_32_in_CPUSPRegBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 
  };

  // HI64 Register Class...
  static MCPhysReg HI64[] = {
    Mips_HI0_64, 
  };

  // HI64 Bit set.
  static uint8_t HI64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 
  };

  // LO64 Register Class...
  static MCPhysReg LO64[] = {
    Mips_LO0_64, 
  };

  // LO64 Bit set.
  static uint8_t LO64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 
  };

  // MSA128B Register Class...
  static MCPhysReg MSA128B[] = {
    Mips_W0, Mips_W1, Mips_W2, Mips_W3, Mips_W4, Mips_W5, Mips_W6, Mips_W7, Mips_W8, Mips_W9, Mips_W10, Mips_W11, Mips_W12, Mips_W13, Mips_W14, Mips_W15, Mips_W16, Mips_W17, Mips_W18, Mips_W19, Mips_W20, Mips_W21, Mips_W22, Mips_W23, Mips_W24, Mips_W25, Mips_W26, Mips_W27, Mips_W28, Mips_W29, Mips_W30, Mips_W31, 
  };

  // MSA128B Bit set.
  static uint8_t MSA128BBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // MSA128D Register Class...
  static MCPhysReg MSA128D[] = {
    Mips_W0, Mips_W1, Mips_W2, Mips_W3, Mips_W4, Mips_W5, Mips_W6, Mips_W7, Mips_W8, Mips_W9, Mips_W10, Mips_W11, Mips_W12, Mips_W13, Mips_W14, Mips_W15, Mips_W16, Mips_W17, Mips_W18, Mips_W19, Mips_W20, Mips_W21, Mips_W22, Mips_W23, Mips_W24, Mips_W25, Mips_W26, Mips_W27, Mips_W28, Mips_W29, Mips_W30, Mips_W31, 
  };

  // MSA128D Bit set.
  static uint8_t MSA128DBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // MSA128H Register Class...
  static MCPhysReg MSA128H[] = {
    Mips_W0, Mips_W1, Mips_W2, Mips_W3, Mips_W4, Mips_W5, Mips_W6, Mips_W7, Mips_W8, Mips_W9, Mips_W10, Mips_W11, Mips_W12, Mips_W13, Mips_W14, Mips_W15, Mips_W16, Mips_W17, Mips_W18, Mips_W19, Mips_W20, Mips_W21, Mips_W22, Mips_W23, Mips_W24, Mips_W25, Mips_W26, Mips_W27, Mips_W28, Mips_W29, Mips_W30, Mips_W31, 
  };

  // MSA128H Bit set.
  static uint8_t MSA128HBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // MSA128W Register Class...
  static MCPhysReg MSA128W[] = {
    Mips_W0, Mips_W1, Mips_W2, Mips_W3, Mips_W4, Mips_W5, Mips_W6, Mips_W7, Mips_W8, Mips_W9, Mips_W10, Mips_W11, Mips_W12, Mips_W13, Mips_W14, Mips_W15, Mips_W16, Mips_W17, Mips_W18, Mips_W19, Mips_W20, Mips_W21, Mips_W22, Mips_W23, Mips_W24, Mips_W25, Mips_W26, Mips_W27, Mips_W28, Mips_W29, Mips_W30, Mips_W31, 
  };

  // MSA128W Bit set.
  static uint8_t MSA128WBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // MSA128B_with_sub_64_in_OddSP Register Class...
  static MCPhysReg MSA128B_with_sub_64_in_OddSP[] = {
    Mips_W1, Mips_W3, Mips_W5, Mips_W7, Mips_W9, Mips_W11, Mips_W13, Mips_W15, Mips_W17, Mips_W19, Mips_W21, Mips_W23, Mips_W25, Mips_W27, Mips_W29, Mips_W31, 
  };

  // MSA128B_with_sub_64_in_OddSP Bit set.
  static uint8_t MSA128B_with_sub_64_in_OddSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x55, 0x55, 0x05, 
  };

  // ACC128 Register Class...
  static MCPhysReg ACC128[] = {
    Mips_AC0_64, 
  };

  // ACC128 Bit set.
  static uint8_t ACC128Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
  };

static MCRegisterClass MipsMCRegisterClasses[] = {
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

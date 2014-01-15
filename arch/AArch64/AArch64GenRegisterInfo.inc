/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|*Target Register Enum Values                                                 *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */


#ifdef GET_REGINFO_ENUM
#undef GET_REGINFO_ENUM

enum {
  AArch64_NoRegister,
  AArch64_NZCV = 1,
  AArch64_WSP = 2,
  AArch64_WZR = 3,
  AArch64_XSP = 4,
  AArch64_XZR = 5,
  AArch64_B0 = 6,
  AArch64_B1 = 7,
  AArch64_B2 = 8,
  AArch64_B3 = 9,
  AArch64_B4 = 10,
  AArch64_B5 = 11,
  AArch64_B6 = 12,
  AArch64_B7 = 13,
  AArch64_B8 = 14,
  AArch64_B9 = 15,
  AArch64_B10 = 16,
  AArch64_B11 = 17,
  AArch64_B12 = 18,
  AArch64_B13 = 19,
  AArch64_B14 = 20,
  AArch64_B15 = 21,
  AArch64_B16 = 22,
  AArch64_B17 = 23,
  AArch64_B18 = 24,
  AArch64_B19 = 25,
  AArch64_B20 = 26,
  AArch64_B21 = 27,
  AArch64_B22 = 28,
  AArch64_B23 = 29,
  AArch64_B24 = 30,
  AArch64_B25 = 31,
  AArch64_B26 = 32,
  AArch64_B27 = 33,
  AArch64_B28 = 34,
  AArch64_B29 = 35,
  AArch64_B30 = 36,
  AArch64_B31 = 37,
  AArch64_D0 = 38,
  AArch64_D1 = 39,
  AArch64_D2 = 40,
  AArch64_D3 = 41,
  AArch64_D4 = 42,
  AArch64_D5 = 43,
  AArch64_D6 = 44,
  AArch64_D7 = 45,
  AArch64_D8 = 46,
  AArch64_D9 = 47,
  AArch64_D10 = 48,
  AArch64_D11 = 49,
  AArch64_D12 = 50,
  AArch64_D13 = 51,
  AArch64_D14 = 52,
  AArch64_D15 = 53,
  AArch64_D16 = 54,
  AArch64_D17 = 55,
  AArch64_D18 = 56,
  AArch64_D19 = 57,
  AArch64_D20 = 58,
  AArch64_D21 = 59,
  AArch64_D22 = 60,
  AArch64_D23 = 61,
  AArch64_D24 = 62,
  AArch64_D25 = 63,
  AArch64_D26 = 64,
  AArch64_D27 = 65,
  AArch64_D28 = 66,
  AArch64_D29 = 67,
  AArch64_D30 = 68,
  AArch64_D31 = 69,
  AArch64_H0 = 70,
  AArch64_H1 = 71,
  AArch64_H2 = 72,
  AArch64_H3 = 73,
  AArch64_H4 = 74,
  AArch64_H5 = 75,
  AArch64_H6 = 76,
  AArch64_H7 = 77,
  AArch64_H8 = 78,
  AArch64_H9 = 79,
  AArch64_H10 = 80,
  AArch64_H11 = 81,
  AArch64_H12 = 82,
  AArch64_H13 = 83,
  AArch64_H14 = 84,
  AArch64_H15 = 85,
  AArch64_H16 = 86,
  AArch64_H17 = 87,
  AArch64_H18 = 88,
  AArch64_H19 = 89,
  AArch64_H20 = 90,
  AArch64_H21 = 91,
  AArch64_H22 = 92,
  AArch64_H23 = 93,
  AArch64_H24 = 94,
  AArch64_H25 = 95,
  AArch64_H26 = 96,
  AArch64_H27 = 97,
  AArch64_H28 = 98,
  AArch64_H29 = 99,
  AArch64_H30 = 100,
  AArch64_H31 = 101,
  AArch64_Q0 = 102,
  AArch64_Q1 = 103,
  AArch64_Q2 = 104,
  AArch64_Q3 = 105,
  AArch64_Q4 = 106,
  AArch64_Q5 = 107,
  AArch64_Q6 = 108,
  AArch64_Q7 = 109,
  AArch64_Q8 = 110,
  AArch64_Q9 = 111,
  AArch64_Q10 = 112,
  AArch64_Q11 = 113,
  AArch64_Q12 = 114,
  AArch64_Q13 = 115,
  AArch64_Q14 = 116,
  AArch64_Q15 = 117,
  AArch64_Q16 = 118,
  AArch64_Q17 = 119,
  AArch64_Q18 = 120,
  AArch64_Q19 = 121,
  AArch64_Q20 = 122,
  AArch64_Q21 = 123,
  AArch64_Q22 = 124,
  AArch64_Q23 = 125,
  AArch64_Q24 = 126,
  AArch64_Q25 = 127,
  AArch64_Q26 = 128,
  AArch64_Q27 = 129,
  AArch64_Q28 = 130,
  AArch64_Q29 = 131,
  AArch64_Q30 = 132,
  AArch64_Q31 = 133,
  AArch64_S0 = 134,
  AArch64_S1 = 135,
  AArch64_S2 = 136,
  AArch64_S3 = 137,
  AArch64_S4 = 138,
  AArch64_S5 = 139,
  AArch64_S6 = 140,
  AArch64_S7 = 141,
  AArch64_S8 = 142,
  AArch64_S9 = 143,
  AArch64_S10 = 144,
  AArch64_S11 = 145,
  AArch64_S12 = 146,
  AArch64_S13 = 147,
  AArch64_S14 = 148,
  AArch64_S15 = 149,
  AArch64_S16 = 150,
  AArch64_S17 = 151,
  AArch64_S18 = 152,
  AArch64_S19 = 153,
  AArch64_S20 = 154,
  AArch64_S21 = 155,
  AArch64_S22 = 156,
  AArch64_S23 = 157,
  AArch64_S24 = 158,
  AArch64_S25 = 159,
  AArch64_S26 = 160,
  AArch64_S27 = 161,
  AArch64_S28 = 162,
  AArch64_S29 = 163,
  AArch64_S30 = 164,
  AArch64_S31 = 165,
  AArch64_W0 = 166,
  AArch64_W1 = 167,
  AArch64_W2 = 168,
  AArch64_W3 = 169,
  AArch64_W4 = 170,
  AArch64_W5 = 171,
  AArch64_W6 = 172,
  AArch64_W7 = 173,
  AArch64_W8 = 174,
  AArch64_W9 = 175,
  AArch64_W10 = 176,
  AArch64_W11 = 177,
  AArch64_W12 = 178,
  AArch64_W13 = 179,
  AArch64_W14 = 180,
  AArch64_W15 = 181,
  AArch64_W16 = 182,
  AArch64_W17 = 183,
  AArch64_W18 = 184,
  AArch64_W19 = 185,
  AArch64_W20 = 186,
  AArch64_W21 = 187,
  AArch64_W22 = 188,
  AArch64_W23 = 189,
  AArch64_W24 = 190,
  AArch64_W25 = 191,
  AArch64_W26 = 192,
  AArch64_W27 = 193,
  AArch64_W28 = 194,
  AArch64_W29 = 195,
  AArch64_W30 = 196,
  AArch64_X0 = 197,
  AArch64_X1 = 198,
  AArch64_X2 = 199,
  AArch64_X3 = 200,
  AArch64_X4 = 201,
  AArch64_X5 = 202,
  AArch64_X6 = 203,
  AArch64_X7 = 204,
  AArch64_X8 = 205,
  AArch64_X9 = 206,
  AArch64_X10 = 207,
  AArch64_X11 = 208,
  AArch64_X12 = 209,
  AArch64_X13 = 210,
  AArch64_X14 = 211,
  AArch64_X15 = 212,
  AArch64_X16 = 213,
  AArch64_X17 = 214,
  AArch64_X18 = 215,
  AArch64_X19 = 216,
  AArch64_X20 = 217,
  AArch64_X21 = 218,
  AArch64_X22 = 219,
  AArch64_X23 = 220,
  AArch64_X24 = 221,
  AArch64_X25 = 222,
  AArch64_X26 = 223,
  AArch64_X27 = 224,
  AArch64_X28 = 225,
  AArch64_X29 = 226,
  AArch64_X30 = 227,
  AArch64_D0_D1 = 228,
  AArch64_D1_D2 = 229,
  AArch64_D2_D3 = 230,
  AArch64_D3_D4 = 231,
  AArch64_D4_D5 = 232,
  AArch64_D5_D6 = 233,
  AArch64_D6_D7 = 234,
  AArch64_D7_D8 = 235,
  AArch64_D8_D9 = 236,
  AArch64_D9_D10 = 237,
  AArch64_D10_D11 = 238,
  AArch64_D11_D12 = 239,
  AArch64_D12_D13 = 240,
  AArch64_D13_D14 = 241,
  AArch64_D14_D15 = 242,
  AArch64_D15_D16 = 243,
  AArch64_D16_D17 = 244,
  AArch64_D17_D18 = 245,
  AArch64_D18_D19 = 246,
  AArch64_D19_D20 = 247,
  AArch64_D20_D21 = 248,
  AArch64_D21_D22 = 249,
  AArch64_D22_D23 = 250,
  AArch64_D23_D24 = 251,
  AArch64_D24_D25 = 252,
  AArch64_D25_D26 = 253,
  AArch64_D26_D27 = 254,
  AArch64_D27_D28 = 255,
  AArch64_D28_D29 = 256,
  AArch64_D29_D30 = 257,
  AArch64_D30_D31 = 258,
  AArch64_D31_D0 = 259,
  AArch64_Q0_Q1 = 260,
  AArch64_Q1_Q2 = 261,
  AArch64_Q2_Q3 = 262,
  AArch64_Q3_Q4 = 263,
  AArch64_Q4_Q5 = 264,
  AArch64_Q5_Q6 = 265,
  AArch64_Q6_Q7 = 266,
  AArch64_Q7_Q8 = 267,
  AArch64_Q8_Q9 = 268,
  AArch64_Q9_Q10 = 269,
  AArch64_Q10_Q11 = 270,
  AArch64_Q11_Q12 = 271,
  AArch64_Q12_Q13 = 272,
  AArch64_Q13_Q14 = 273,
  AArch64_Q14_Q15 = 274,
  AArch64_Q15_Q16 = 275,
  AArch64_Q16_Q17 = 276,
  AArch64_Q17_Q18 = 277,
  AArch64_Q18_Q19 = 278,
  AArch64_Q19_Q20 = 279,
  AArch64_Q20_Q21 = 280,
  AArch64_Q21_Q22 = 281,
  AArch64_Q22_Q23 = 282,
  AArch64_Q23_Q24 = 283,
  AArch64_Q24_Q25 = 284,
  AArch64_Q25_Q26 = 285,
  AArch64_Q26_Q27 = 286,
  AArch64_Q27_Q28 = 287,
  AArch64_Q28_Q29 = 288,
  AArch64_Q29_Q30 = 289,
  AArch64_Q30_Q31 = 290,
  AArch64_Q31_Q0 = 291,
  AArch64_D0_D1_D2 = 292,
  AArch64_D1_D2_D3 = 293,
  AArch64_D2_D3_D4 = 294,
  AArch64_D3_D4_D5 = 295,
  AArch64_D4_D5_D6 = 296,
  AArch64_D5_D6_D7 = 297,
  AArch64_D6_D7_D8 = 298,
  AArch64_D7_D8_D9 = 299,
  AArch64_D8_D9_D10 = 300,
  AArch64_D9_D10_D11 = 301,
  AArch64_D10_D11_D12 = 302,
  AArch64_D11_D12_D13 = 303,
  AArch64_D12_D13_D14 = 304,
  AArch64_D13_D14_D15 = 305,
  AArch64_D14_D15_D16 = 306,
  AArch64_D15_D16_D17 = 307,
  AArch64_D16_D17_D18 = 308,
  AArch64_D17_D18_D19 = 309,
  AArch64_D18_D19_D20 = 310,
  AArch64_D19_D20_D21 = 311,
  AArch64_D20_D21_D22 = 312,
  AArch64_D21_D22_D23 = 313,
  AArch64_D22_D23_D24 = 314,
  AArch64_D23_D24_D25 = 315,
  AArch64_D24_D25_D26 = 316,
  AArch64_D25_D26_D27 = 317,
  AArch64_D26_D27_D28 = 318,
  AArch64_D27_D28_D29 = 319,
  AArch64_D28_D29_D30 = 320,
  AArch64_D29_D30_D31 = 321,
  AArch64_D30_D31_D0 = 322,
  AArch64_D31_D0_D1 = 323,
  AArch64_Q0_Q1_Q2 = 324,
  AArch64_Q1_Q2_Q3 = 325,
  AArch64_Q2_Q3_Q4 = 326,
  AArch64_Q3_Q4_Q5 = 327,
  AArch64_Q4_Q5_Q6 = 328,
  AArch64_Q5_Q6_Q7 = 329,
  AArch64_Q6_Q7_Q8 = 330,
  AArch64_Q7_Q8_Q9 = 331,
  AArch64_Q8_Q9_Q10 = 332,
  AArch64_Q9_Q10_Q11 = 333,
  AArch64_Q10_Q11_Q12 = 334,
  AArch64_Q11_Q12_Q13 = 335,
  AArch64_Q12_Q13_Q14 = 336,
  AArch64_Q13_Q14_Q15 = 337,
  AArch64_Q14_Q15_Q16 = 338,
  AArch64_Q15_Q16_Q17 = 339,
  AArch64_Q16_Q17_Q18 = 340,
  AArch64_Q17_Q18_Q19 = 341,
  AArch64_Q18_Q19_Q20 = 342,
  AArch64_Q19_Q20_Q21 = 343,
  AArch64_Q20_Q21_Q22 = 344,
  AArch64_Q21_Q22_Q23 = 345,
  AArch64_Q22_Q23_Q24 = 346,
  AArch64_Q23_Q24_Q25 = 347,
  AArch64_Q24_Q25_Q26 = 348,
  AArch64_Q25_Q26_Q27 = 349,
  AArch64_Q26_Q27_Q28 = 350,
  AArch64_Q27_Q28_Q29 = 351,
  AArch64_Q28_Q29_Q30 = 352,
  AArch64_Q29_Q30_Q31 = 353,
  AArch64_Q30_Q31_Q0 = 354,
  AArch64_Q31_Q0_Q1 = 355,
  AArch64_D0_D1_D2_D3 = 356,
  AArch64_D1_D2_D3_D4 = 357,
  AArch64_D2_D3_D4_D5 = 358,
  AArch64_D3_D4_D5_D6 = 359,
  AArch64_D4_D5_D6_D7 = 360,
  AArch64_D5_D6_D7_D8 = 361,
  AArch64_D6_D7_D8_D9 = 362,
  AArch64_D7_D8_D9_D10 = 363,
  AArch64_D8_D9_D10_D11 = 364,
  AArch64_D9_D10_D11_D12 = 365,
  AArch64_D10_D11_D12_D13 = 366,
  AArch64_D11_D12_D13_D14 = 367,
  AArch64_D12_D13_D14_D15 = 368,
  AArch64_D13_D14_D15_D16 = 369,
  AArch64_D14_D15_D16_D17 = 370,
  AArch64_D15_D16_D17_D18 = 371,
  AArch64_D16_D17_D18_D19 = 372,
  AArch64_D17_D18_D19_D20 = 373,
  AArch64_D18_D19_D20_D21 = 374,
  AArch64_D19_D20_D21_D22 = 375,
  AArch64_D20_D21_D22_D23 = 376,
  AArch64_D21_D22_D23_D24 = 377,
  AArch64_D22_D23_D24_D25 = 378,
  AArch64_D23_D24_D25_D26 = 379,
  AArch64_D24_D25_D26_D27 = 380,
  AArch64_D25_D26_D27_D28 = 381,
  AArch64_D26_D27_D28_D29 = 382,
  AArch64_D27_D28_D29_D30 = 383,
  AArch64_D28_D29_D30_D31 = 384,
  AArch64_D29_D30_D31_D0 = 385,
  AArch64_D30_D31_D0_D1 = 386,
  AArch64_D31_D0_D1_D2 = 387,
  AArch64_Q0_Q1_Q2_Q3 = 388,
  AArch64_Q1_Q2_Q3_Q4 = 389,
  AArch64_Q2_Q3_Q4_Q5 = 390,
  AArch64_Q3_Q4_Q5_Q6 = 391,
  AArch64_Q4_Q5_Q6_Q7 = 392,
  AArch64_Q5_Q6_Q7_Q8 = 393,
  AArch64_Q6_Q7_Q8_Q9 = 394,
  AArch64_Q7_Q8_Q9_Q10 = 395,
  AArch64_Q8_Q9_Q10_Q11 = 396,
  AArch64_Q9_Q10_Q11_Q12 = 397,
  AArch64_Q10_Q11_Q12_Q13 = 398,
  AArch64_Q11_Q12_Q13_Q14 = 399,
  AArch64_Q12_Q13_Q14_Q15 = 400,
  AArch64_Q13_Q14_Q15_Q16 = 401,
  AArch64_Q14_Q15_Q16_Q17 = 402,
  AArch64_Q15_Q16_Q17_Q18 = 403,
  AArch64_Q16_Q17_Q18_Q19 = 404,
  AArch64_Q17_Q18_Q19_Q20 = 405,
  AArch64_Q18_Q19_Q20_Q21 = 406,
  AArch64_Q19_Q20_Q21_Q22 = 407,
  AArch64_Q20_Q21_Q22_Q23 = 408,
  AArch64_Q21_Q22_Q23_Q24 = 409,
  AArch64_Q22_Q23_Q24_Q25 = 410,
  AArch64_Q23_Q24_Q25_Q26 = 411,
  AArch64_Q24_Q25_Q26_Q27 = 412,
  AArch64_Q25_Q26_Q27_Q28 = 413,
  AArch64_Q26_Q27_Q28_Q29 = 414,
  AArch64_Q27_Q28_Q29_Q30 = 415,
  AArch64_Q28_Q29_Q30_Q31 = 416,
  AArch64_Q29_Q30_Q31_Q0 = 417,
  AArch64_Q30_Q31_Q0_Q1 = 418,
  AArch64_Q31_Q0_Q1_Q2 = 419,
  AArch64_NUM_TARGET_REGS 	// 420
};

// Register classes
enum {
  AArch64_FPR8RegClassID = 0,
  AArch64_FPR16RegClassID = 1,
  AArch64_FPR32RegClassID = 2,
  AArch64_GPR32RegClassID = 3,
  AArch64_GPR32wspRegClassID = 4,
  AArch64_GPR32nowzrRegClassID = 5,
  AArch64_FlagClassRegClassID = 6,
  AArch64_RwspRegClassID = 7,
  AArch64_FPR64RegClassID = 8,
  AArch64_GPR64RegClassID = 9,
  AArch64_GPR64xspRegClassID = 10,
  AArch64_GPR64noxzrRegClassID = 11,
  AArch64_tcGPR64RegClassID = 12,
  AArch64_FPR64LoRegClassID = 13,
  AArch64_RxspRegClassID = 14,
  AArch64_DPairRegClassID = 15,
  AArch64_DPair_with_dsub_0_in_FPR64LoRegClassID = 16,
  AArch64_DPair_with_dsub_1_in_FPR64LoRegClassID = 17,
  AArch64_DPair_with_dsub_0_in_FPR64Lo_and_DPair_with_dsub_1_in_FPR64LoRegClassID = 18,
  AArch64_FPR128RegClassID = 19,
  AArch64_FPR128LoRegClassID = 20,
  AArch64_DTripleRegClassID = 21,
  AArch64_DTriple_with_dsub_0_in_FPR64LoRegClassID = 22,
  AArch64_DTriple_with_dsub_1_in_FPR64LoRegClassID = 23,
  AArch64_DTriple_with_dsub_2_in_FPR64LoRegClassID = 24,
  AArch64_DTriple_with_dsub_0_in_FPR64Lo_and_DTriple_with_dsub_1_in_FPR64LoRegClassID = 25,
  AArch64_DTriple_with_dsub_1_in_FPR64Lo_and_DTriple_with_dsub_2_in_FPR64LoRegClassID = 26,
  AArch64_DTriple_with_dsub_0_in_FPR64Lo_and_DTriple_with_dsub_2_in_FPR64LoRegClassID = 27,
  AArch64_DQuadRegClassID = 28,
  AArch64_DQuad_with_dsub_0_in_FPR64LoRegClassID = 29,
  AArch64_DQuad_with_dsub_1_in_FPR64LoRegClassID = 30,
  AArch64_DQuad_with_dsub_2_in_FPR64LoRegClassID = 31,
  AArch64_DQuad_with_dsub_3_in_FPR64LoRegClassID = 32,
  AArch64_DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_1_in_FPR64LoRegClassID = 33,
  AArch64_DQuad_with_dsub_1_in_FPR64Lo_and_DQuad_with_dsub_2_in_FPR64LoRegClassID = 34,
  AArch64_DQuad_with_dsub_2_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64LoRegClassID = 35,
  AArch64_DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_2_in_FPR64LoRegClassID = 36,
  AArch64_DQuad_with_dsub_1_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64LoRegClassID = 37,
  AArch64_DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64LoRegClassID = 38,
  AArch64_QPairRegClassID = 39,
  AArch64_QPair_with_qsub_0_in_FPR128LoRegClassID = 40,
  AArch64_QPair_with_qsub_1_in_FPR128LoRegClassID = 41,
  AArch64_QPair_with_qsub_0_in_FPR128Lo_and_QPair_with_qsub_1_in_FPR128LoRegClassID = 42,
  AArch64_QTripleRegClassID = 43,
  AArch64_QTriple_with_qsub_0_in_FPR128LoRegClassID = 44,
  AArch64_QTriple_with_qsub_1_in_FPR128LoRegClassID = 45,
  AArch64_QTriple_with_qsub_2_in_FPR128LoRegClassID = 46,
  AArch64_QTriple_with_qsub_0_in_FPR128Lo_and_QTriple_with_qsub_1_in_FPR128LoRegClassID = 47,
  AArch64_QTriple_with_qsub_1_in_FPR128Lo_and_QTriple_with_qsub_2_in_FPR128LoRegClassID = 48,
  AArch64_QTriple_with_qsub_0_in_FPR128Lo_and_QTriple_with_qsub_2_in_FPR128LoRegClassID = 49,
  AArch64_QQuadRegClassID = 50,
  AArch64_QQuad_with_qsub_0_in_FPR128LoRegClassID = 51,
  AArch64_QQuad_with_qsub_1_in_FPR128LoRegClassID = 52,
  AArch64_QQuad_with_qsub_2_in_FPR128LoRegClassID = 53,
  AArch64_QQuad_with_qsub_3_in_FPR128LoRegClassID = 54,
  AArch64_QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_1_in_FPR128LoRegClassID = 55,
  AArch64_QQuad_with_qsub_1_in_FPR128Lo_and_QQuad_with_qsub_2_in_FPR128LoRegClassID = 56,
  AArch64_QQuad_with_qsub_2_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128LoRegClassID = 57,
  AArch64_QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_2_in_FPR128LoRegClassID = 58,
  AArch64_QQuad_with_qsub_1_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128LoRegClassID = 59,
  AArch64_QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128LoRegClassID = 60
};

// Subregister indices
enum {
  AArch64_NoSubRegister,
  AArch64_dsub_0,	// 1
  AArch64_dsub_1,	// 2
  AArch64_dsub_2,	// 3
  AArch64_dsub_3,	// 4
  AArch64_qqsub,	// 5
  AArch64_qsub_0,	// 6
  AArch64_qsub_1,	// 7
  AArch64_qsub_2,	// 8
  AArch64_qsub_3,	// 9
  AArch64_sub_8,	// 10
  AArch64_sub_16,	// 11
  AArch64_sub_32,	// 12
  AArch64_sub_64,	// 13
  AArch64_sub_128,	// 14
  AArch64_dsub_1_then_sub_8,	// 15
  AArch64_dsub_1_then_sub_16,	// 16
  AArch64_dsub_1_then_sub_32,	// 17
  AArch64_qsub_1_then_sub_8,	// 18
  AArch64_qsub_1_then_sub_16,	// 19
  AArch64_qsub_1_then_sub_32,	// 20
  AArch64_qsub_1_then_sub_64,	// 21
  AArch64_dsub_2_then_sub_8,	// 22
  AArch64_dsub_2_then_sub_16,	// 23
  AArch64_dsub_2_then_sub_32,	// 24
  AArch64_qsub_2_then_sub_8,	// 25
  AArch64_qsub_2_then_sub_16,	// 26
  AArch64_qsub_2_then_sub_32,	// 27
  AArch64_qsub_2_then_sub_64,	// 28
  AArch64_dsub_3_then_sub_8,	// 29
  AArch64_dsub_3_then_sub_16,	// 30
  AArch64_dsub_3_then_sub_32,	// 31
  AArch64_qsub_3_then_sub_8,	// 32
  AArch64_qsub_3_then_sub_16,	// 33
  AArch64_qsub_3_then_sub_32,	// 34
  AArch64_qsub_3_then_sub_64,	// 35
  AArch64_sub_64_qsub_1_then_sub_64,	// 36
  AArch64_dsub_0_dsub_1,	// 37
  AArch64_dsub_1_dsub_2,	// 38
  AArch64_qsub_0_qsub_1,	// 39
  AArch64_qsub_1_qsub_2,	// 40
  AArch64_sub_64_qsub_1_then_sub_64_qsub_2_then_sub_64,	// 41
  AArch64_qsub_1_then_sub_64_qsub_2_then_sub_64,	// 42
  AArch64_dsub_0_dsub_1_dsub_2,	// 43
  AArch64_dsub_1_dsub_2_dsub_3,	// 44
  AArch64_dsub_2_dsub_3,	// 45
  AArch64_qsub_0_qsub_1_qsub_2,	// 46
  AArch64_qsub_1_qsub_2_qsub_3,	// 47
  AArch64_qsub_2_qsub_3,	// 48
  AArch64_sub_64_qsub_1_then_sub_64_qsub_2_then_sub_64_qsub_3_then_sub_64,	// 49
  AArch64_qsub_1_then_sub_64_qsub_2_then_sub_64_qsub_3_then_sub_64,	// 50
  AArch64_qsub_2_then_sub_64_qsub_3_then_sub_64,	// 51
  AArch64_NUM_TARGET_SUBREGS
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
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */


#ifdef GET_REGINFO_MC_DESC
#undef GET_REGINFO_MC_DESC

static MCPhysReg AArch64RegDiffLists[] = {
  /* 0 */ 3, 1, 1, 1, 0,
  /* 5 */ 64, 64, 65440, 64, 125, 1, 31, 1, 30, 1, 1, 30, 1, 1, 29, 1, 1, 1, 29, 1, 1, 1, 0,
  /* 28 */ 157, 1, 62, 1, 1, 61, 1, 1, 1, 0,
  /* 38 */ 65151, 1, 1, 1, 0,
  /* 43 */ 65183, 1, 1, 1, 0,
  /* 48 */ 3, 1, 1, 0,
  /* 52 */ 64, 64, 65440, 64, 126, 31, 1, 31, 1, 30, 1, 1, 30, 1, 1, 29, 1, 1, 1, 29, 1, 1, 0,
  /* 75 */ 3, 29, 1, 1, 0,
  /* 80 */ 158, 31, 33, 30, 1, 33, 29, 1, 1, 0,
  /* 90 */ 32, 31, 1, 31, 1, 30, 1, 1, 30, 1, 1, 0,
  /* 102 */ 63, 1, 62, 1, 1, 0,
  /* 108 */ 65215, 1, 1, 0,
  /* 112 */ 65247, 1, 1, 0,
  /* 116 */ 3, 1, 0,
  /* 119 */ 64, 64, 65440, 64, 125, 1, 31, 1, 31, 1, 30, 1, 1, 30, 1, 1, 29, 1, 1, 1, 29, 1, 0,
  /* 142 */ 3, 1, 29, 1, 0,
  /* 147 */ 157, 1, 63, 1, 30, 33, 1, 29, 1, 0,
  /* 157 */ 32, 32, 31, 1, 31, 1, 30, 1, 1, 30, 1, 0,
  /* 169 */ 3, 30, 1, 0,
  /* 173 */ 64, 31, 33, 30, 1, 0,
  /* 179 */ 32, 31, 1, 31, 1, 0,
  /* 185 */ 63, 1, 0,
  /* 188 */ 65282, 96, 65472, 65472, 33, 96, 65472, 65472, 33, 96, 65472, 65472, 220, 1, 0,
  /* 203 */ 65282, 96, 65472, 65472, 33, 96, 65472, 65472, 1, 96, 65472, 65472, 252, 1, 0,
  /* 218 */ 65279, 1, 0,
  /* 221 */ 65311, 1, 0,
  /* 224 */ 2, 0,
  /* 226 */ 64, 64, 65440, 64, 125, 1, 31, 1, 30, 1, 1, 30, 1, 1, 30, 1, 1, 29, 1, 1, 1, 29, 0,
  /* 249 */ 3, 1, 1, 29, 0,
  /* 254 */ 157, 1, 62, 1, 1, 62, 1, 1, 29, 0,
  /* 264 */ 32, 31, 1, 31, 1, 31, 1, 30, 1, 1, 30, 0,
  /* 276 */ 3, 1, 30, 0,
  /* 280 */ 63, 1, 63, 1, 30, 0,
  /* 286 */ 32, 32, 31, 1, 31, 0,
  /* 292 */ 3, 31, 0,
  /* 295 */ 64, 31, 0,
  /* 298 */ 32, 0,
  /* 300 */ 65378, 65472, 96, 65472, 65472, 97, 65472, 96, 65472, 65472, 221, 0,
  /* 312 */ 65378, 65472, 96, 65472, 65472, 65, 65472, 96, 65472, 65472, 253, 0,
  /* 324 */ 65374, 0,
  /* 326 */ 65405, 0,
  /* 328 */ 65437, 0,
  /* 330 */ 65218, 96, 65472, 65472, 33, 96, 65472, 65472, 1, 96, 65472, 65472, 33, 96, 65472, 65472, 251, 1, 63, 1, 65441, 0,
  /* 352 */ 65314, 65472, 96, 65472, 65472, 65, 65472, 96, 65472, 65472, 97, 65472, 96, 65472, 65472, 252, 32, 65505, 63, 65441, 0,
  /* 373 */ 65250, 65472, 96, 65472, 65472, 97, 65472, 96, 65472, 65472, 65, 65472, 96, 65472, 65472, 97, 65472, 96, 65472, 65472, 251, 32, 1, 31, 65473, 95, 1, 65441, 126, 65473, 65441, 0,
  /* 405 */ 65469, 0,
  /* 407 */ 65346, 96, 65472, 65472, 1, 96, 65472, 65472, 0,
  /* 416 */ 65346, 96, 65472, 65472, 33, 96, 65472, 65472, 0,
  /* 425 */ 65472, 96, 65472, 65472, 0,
  /* 430 */ 65218, 96, 65472, 65472, 33, 96, 65472, 65472, 33, 96, 65472, 65472, 33, 96, 65472, 65472, 219, 1, 63, 1, 65473, 0,
  /* 452 */ 65218, 96, 65472, 65472, 33, 96, 65472, 65472, 33, 96, 65472, 65472, 1, 96, 65472, 65472, 251, 1, 63, 1, 65473, 0,
  /* 474 */ 65314, 65472, 96, 65472, 65472, 97, 65472, 96, 65472, 65472, 97, 65472, 96, 65472, 65472, 220, 32, 1, 31, 65473, 0,
  /* 495 */ 65314, 65472, 96, 65472, 65472, 97, 65472, 96, 65472, 65472, 65, 65472, 96, 65472, 65472, 252, 32, 1, 31, 65473, 0,
  /* 516 */ 65250, 65472, 96, 65472, 65472, 65, 65472, 96, 65472, 65472, 97, 65472, 96, 65472, 65472, 97, 65472, 96, 65472, 65472, 251, 32, 65505, 63, 65441, 127, 65505, 65473, 126, 65441, 65473, 0,
  /* 548 */ 65250, 65472, 96, 65472, 65472, 97, 65472, 96, 65472, 65472, 97, 65472, 96, 65472, 65472, 97, 65472, 96, 65472, 65472, 219, 32, 1, 31, 65473, 95, 1, 65473, 94, 65473, 65473, 0,
  /* 580 */ 65250, 65472, 96, 65472, 65472, 97, 65472, 96, 65472, 65472, 97, 65472, 96, 65472, 65472, 65, 65472, 96, 65472, 65472, 251, 32, 1, 31, 65473, 95, 1, 65473, 94, 65473, 65473, 0,
  /* 612 */ 65218, 96, 65472, 65472, 1, 96, 65472, 65472, 33, 96, 65472, 65472, 33, 96, 65472, 65472, 251, 65505, 95, 65505, 65473, 0,
  /* 634 */ 65501, 0,
  /* 636 */ 65282, 96, 65472, 65472, 1, 96, 65472, 65472, 33, 96, 65472, 65472, 252, 65505, 0,
  /* 651 */ 65533, 0,
  /* 653 */ 65534, 0,
  /* 655 */ 65535, 0,
};

static uint16_t AArch64SubRegIdxLists[] = {
  /* 0 */ 13, 12, 11, 10, 0,
  /* 5 */ 12, 0,
  /* 7 */ 1, 12, 11, 10, 2, 17, 16, 15, 0,
  /* 16 */ 6, 13, 12, 11, 10, 7, 21, 20, 19, 18, 36, 0,
  /* 28 */ 1, 12, 11, 10, 2, 17, 16, 15, 3, 24, 23, 22, 37, 38, 0,
  /* 43 */ 6, 13, 12, 11, 10, 7, 21, 20, 19, 18, 8, 28, 27, 26, 25, 36, 39, 40, 41, 42, 0,
  /* 64 */ 1, 12, 11, 10, 2, 17, 16, 15, 3, 24, 23, 22, 4, 31, 30, 29, 37, 38, 43, 44, 45, 0,
  /* 86 */ 6, 13, 12, 11, 10, 7, 21, 20, 19, 18, 8, 28, 27, 26, 25, 9, 35, 34, 33, 32, 36, 39, 40, 41, 42, 46, 47, 48, 49, 50, 51, 0,
};

static MCRegisterDesc AArch64RegDesc[] = { // Descriptors
  { 3, 0, 0, 0, 0 },
  { 1542, 4, 4, 4, 10481 },
  { 1526, 4, 224, 4, 10481 },
  { 1534, 4, 224, 4, 10481 },
  { 1530, 653, 4, 5, 10417 },
  { 1538, 653, 4, 5, 10417 },
  { 150, 4, 52, 4, 10417 },
  { 339, 4, 119, 4, 10417 },
  { 484, 4, 226, 4, 10417 },
  { 629, 4, 5, 4, 10417 },
  { 772, 4, 5, 4, 10417 },
  { 915, 4, 5, 4, 10417 },
  { 1058, 4, 5, 4, 10417 },
  { 1201, 4, 5, 4, 10417 },
  { 1344, 4, 5, 4, 10417 },
  { 1487, 4, 5, 4, 10417 },
  { 0, 4, 5, 4, 10417 },
  { 195, 4, 5, 4, 10417 },
  { 382, 4, 5, 4, 10417 },
  { 525, 4, 5, 4, 10417 },
  { 668, 4, 5, 4, 10417 },
  { 811, 4, 5, 4, 10417 },
  { 954, 4, 5, 4, 10417 },
  { 1097, 4, 5, 4, 10417 },
  { 1240, 4, 5, 4, 10417 },
  { 1383, 4, 5, 4, 10417 },
  { 46, 4, 5, 4, 10417 },
  { 243, 4, 5, 4, 10417 },
  { 432, 4, 5, 4, 10417 },
  { 577, 4, 5, 4, 10417 },
  { 720, 4, 5, 4, 10417 },
  { 863, 4, 5, 4, 10417 },
  { 1006, 4, 5, 4, 10417 },
  { 1149, 4, 5, 4, 10417 },
  { 1292, 4, 5, 4, 10417 },
  { 1435, 4, 5, 4, 10417 },
  { 98, 4, 5, 4, 10417 },
  { 295, 4, 5, 4, 10417 },
  { 165, 412, 55, 1, 10145 },
  { 353, 412, 122, 1, 10145 },
  { 497, 412, 229, 1, 10145 },
  { 641, 412, 8, 1, 10145 },
  { 784, 412, 8, 1, 10145 },
  { 927, 412, 8, 1, 10145 },
  { 1070, 412, 8, 1, 10145 },
  { 1213, 412, 8, 1, 10145 },
  { 1356, 412, 8, 1, 10145 },
  { 1499, 412, 8, 1, 10145 },
  { 13, 412, 8, 1, 10145 },
  { 209, 412, 8, 1, 10145 },
  { 397, 412, 8, 1, 10145 },
  { 541, 412, 8, 1, 10145 },
  { 684, 412, 8, 1, 10145 },
  { 827, 412, 8, 1, 10145 },
  { 970, 412, 8, 1, 10145 },
  { 1113, 412, 8, 1, 10145 },
  { 1256, 412, 8, 1, 10145 },
  { 1399, 412, 8, 1, 10145 },
  { 62, 412, 8, 1, 10145 },
  { 259, 412, 8, 1, 10145 },
  { 448, 412, 8, 1, 10145 },
  { 593, 412, 8, 1, 10145 },
  { 736, 412, 8, 1, 10145 },
  { 879, 412, 8, 1, 10145 },
  { 1022, 412, 8, 1, 10145 },
  { 1165, 412, 8, 1, 10145 },
  { 1308, 412, 8, 1, 10145 },
  { 1451, 412, 8, 1, 10145 },
  { 114, 412, 8, 1, 10145 },
  { 311, 412, 8, 1, 10145 },
  { 168, 414, 53, 3, 6481 },
  { 356, 414, 120, 3, 6481 },
  { 500, 414, 227, 3, 6481 },
  { 644, 414, 6, 3, 6481 },
  { 787, 414, 6, 3, 6481 },
  { 930, 414, 6, 3, 6481 },
  { 1073, 414, 6, 3, 6481 },
  { 1216, 414, 6, 3, 6481 },
  { 1359, 414, 6, 3, 6481 },
  { 1502, 414, 6, 3, 6481 },
  { 17, 414, 6, 3, 6481 },
  { 213, 414, 6, 3, 6481 },
  { 401, 414, 6, 3, 6481 },
  { 545, 414, 6, 3, 6481 },
  { 688, 414, 6, 3, 6481 },
  { 831, 414, 6, 3, 6481 },
  { 974, 414, 6, 3, 6481 },
  { 1117, 414, 6, 3, 6481 },
  { 1260, 414, 6, 3, 6481 },
  { 1403, 414, 6, 3, 6481 },
  { 66, 414, 6, 3, 6481 },
  { 263, 414, 6, 3, 6481 },
  { 452, 414, 6, 3, 6481 },
  { 597, 414, 6, 3, 6481 },
  { 740, 414, 6, 3, 6481 },
  { 883, 414, 6, 3, 6481 },
  { 1026, 414, 6, 3, 6481 },
  { 1169, 414, 6, 3, 6481 },
  { 1312, 414, 6, 3, 6481 },
  { 1455, 414, 6, 3, 6481 },
  { 118, 414, 6, 3, 6481 },
  { 315, 414, 6, 3, 6481 },
  { 183, 425, 80, 0, 5249 },
  { 370, 425, 147, 0, 5249 },
  { 513, 425, 254, 0, 5249 },
  { 656, 425, 28, 0, 5249 },
  { 799, 425, 28, 0, 5249 },
  { 942, 425, 28, 0, 5249 },
  { 1085, 425, 28, 0, 5249 },
  { 1228, 425, 28, 0, 5249 },
  { 1371, 425, 28, 0, 5249 },
  { 1514, 425, 28, 0, 5249 },
  { 30, 425, 28, 0, 5249 },
  { 227, 425, 28, 0, 5249 },
  { 416, 425, 28, 0, 5249 },
  { 561, 425, 28, 0, 5249 },
  { 704, 425, 28, 0, 5249 },
  { 847, 425, 28, 0, 5249 },
  { 990, 425, 28, 0, 5249 },
  { 1133, 425, 28, 0, 5249 },
  { 1276, 425, 28, 0, 5249 },
  { 1419, 425, 28, 0, 5249 },
  { 82, 425, 28, 0, 5249 },
  { 279, 425, 28, 0, 5249 },
  { 468, 425, 28, 0, 5249 },
  { 613, 425, 28, 0, 5249 },
  { 756, 425, 28, 0, 5249 },
  { 899, 425, 28, 0, 5249 },
  { 1042, 425, 28, 0, 5249 },
  { 1185, 425, 28, 0, 5249 },
  { 1328, 425, 28, 0, 5249 },
  { 1471, 425, 28, 0, 5249 },
  { 134, 425, 28, 0, 5249 },
  { 331, 425, 28, 0, 5249 },
  { 186, 413, 54, 2, 5217 },
  { 373, 413, 121, 2, 5217 },
  { 516, 413, 228, 2, 5217 },
  { 659, 413, 7, 2, 5217 },
  { 802, 413, 7, 2, 5217 },
  { 945, 413, 7, 2, 5217 },
  { 1088, 413, 7, 2, 5217 },
  { 1231, 413, 7, 2, 5217 },
  { 1374, 413, 7, 2, 5217 },
  { 1517, 413, 7, 2, 5217 },
  { 34, 413, 7, 2, 5217 },
  { 231, 413, 7, 2, 5217 },
  { 420, 413, 7, 2, 5217 },
  { 565, 413, 7, 2, 5217 },
  { 708, 413, 7, 2, 5217 },
  { 851, 413, 7, 2, 5217 },
  { 994, 413, 7, 2, 5217 },
  { 1137, 413, 7, 2, 5217 },
  { 1280, 413, 7, 2, 5217 },
  { 1423, 413, 7, 2, 5217 },
  { 86, 413, 7, 2, 5217 },
  { 283, 413, 7, 2, 5217 },
  { 472, 413, 7, 2, 5217 },
  { 617, 413, 7, 2, 5217 },
  { 760, 413, 7, 2, 5217 },
  { 903, 413, 7, 2, 5217 },
  { 1046, 413, 7, 2, 5217 },
  { 1189, 413, 7, 2, 5217 },
  { 1332, 413, 7, 2, 5217 },
  { 1475, 413, 7, 2, 5217 },
  { 138, 413, 7, 2, 5217 },
  { 335, 413, 7, 2, 5217 },
  { 189, 4, 290, 4, 5217 },
  { 376, 4, 290, 4, 5217 },
  { 519, 4, 290, 4, 5217 },
  { 662, 4, 290, 4, 5217 },
  { 805, 4, 290, 4, 5217 },
  { 948, 4, 290, 4, 5217 },
  { 1091, 4, 290, 4, 5217 },
  { 1234, 4, 290, 4, 5217 },
  { 1377, 4, 290, 4, 5217 },
  { 1520, 4, 290, 4, 5217 },
  { 38, 4, 290, 4, 5217 },
  { 235, 4, 290, 4, 5217 },
  { 424, 4, 290, 4, 5217 },
  { 569, 4, 290, 4, 5217 },
  { 712, 4, 290, 4, 5217 },
  { 855, 4, 290, 4, 5217 },
  { 998, 4, 290, 4, 5217 },
  { 1141, 4, 290, 4, 5217 },
  { 1284, 4, 290, 4, 5217 },
  { 1427, 4, 290, 4, 5217 },
  { 90, 4, 290, 4, 5217 },
  { 287, 4, 290, 4, 5217 },
  { 476, 4, 290, 4, 5217 },
  { 621, 4, 290, 4, 5217 },
  { 764, 4, 290, 4, 5217 },
  { 907, 4, 290, 4, 5217 },
  { 1050, 4, 290, 4, 5217 },
  { 1193, 4, 290, 4, 5217 },
  { 1336, 4, 290, 4, 5217 },
  { 1479, 4, 290, 4, 5217 },
  { 142, 4, 290, 4, 5217 },
  { 192, 649, 4, 5, 5185 },
  { 379, 649, 4, 5, 5185 },
  { 522, 649, 4, 5, 5185 },
  { 665, 649, 4, 5, 5185 },
  { 808, 649, 4, 5, 5185 },
  { 951, 649, 4, 5, 5185 },
  { 1094, 649, 4, 5, 5185 },
  { 1237, 649, 4, 5, 5185 },
  { 1380, 649, 4, 5, 5185 },
  { 1523, 649, 4, 5, 5185 },
  { 42, 649, 4, 5, 5185 },
  { 239, 649, 4, 5, 5185 },
  { 428, 649, 4, 5, 5185 },
  { 573, 649, 4, 5, 5185 },
  { 716, 649, 4, 5, 5185 },
  { 859, 649, 4, 5, 5185 },
  { 1002, 649, 4, 5, 5185 },
  { 1145, 649, 4, 5, 5185 },
  { 1288, 649, 4, 5, 5185 },
  { 1431, 649, 4, 5, 5185 },
  { 94, 649, 4, 5, 5185 },
  { 291, 649, 4, 5, 5185 },
  { 480, 649, 4, 5, 5185 },
  { 625, 649, 4, 5, 5185 },
  { 768, 649, 4, 5, 5185 },
  { 911, 649, 4, 5, 5185 },
  { 1054, 649, 4, 5, 5185 },
  { 1197, 649, 4, 5, 5185 },
  { 1340, 649, 4, 5, 5185 },
  { 1483, 649, 4, 5, 5185 },
  { 146, 649, 4, 5, 5185 },
  { 350, 416, 157, 7, 3537 },
  { 494, 416, 264, 7, 3537 },
  { 638, 416, 90, 7, 3537 },
  { 781, 416, 90, 7, 3537 },
  { 924, 416, 90, 7, 3537 },
  { 1067, 416, 90, 7, 3537 },
  { 1210, 416, 90, 7, 3537 },
  { 1353, 416, 90, 7, 3537 },
  { 1496, 416, 90, 7, 3537 },
  { 10, 416, 90, 7, 3537 },
  { 205, 416, 90, 7, 3537 },
  { 393, 416, 90, 7, 3537 },
  { 537, 416, 90, 7, 3537 },
  { 680, 416, 90, 7, 3537 },
  { 823, 416, 90, 7, 3537 },
  { 966, 416, 90, 7, 3537 },
  { 1109, 416, 90, 7, 3537 },
  { 1252, 416, 90, 7, 3537 },
  { 1395, 416, 90, 7, 3537 },
  { 58, 416, 90, 7, 3537 },
  { 255, 416, 90, 7, 3537 },
  { 444, 416, 90, 7, 3537 },
  { 589, 416, 90, 7, 3537 },
  { 732, 416, 90, 7, 3537 },
  { 875, 416, 90, 7, 3537 },
  { 1018, 416, 90, 7, 3537 },
  { 1161, 416, 90, 7, 3537 },
  { 1304, 416, 90, 7, 3537 },
  { 1447, 416, 90, 7, 3537 },
  { 110, 416, 90, 7, 3537 },
  { 307, 416, 90, 7, 3537 },
  { 161, 407, 90, 7, 4672 },
  { 367, 300, 173, 16, 1856 },
  { 510, 300, 280, 16, 3489 },
  { 653, 300, 102, 16, 3489 },
  { 796, 300, 102, 16, 3489 },
  { 939, 300, 102, 16, 3489 },
  { 1082, 300, 102, 16, 3489 },
  { 1225, 300, 102, 16, 3489 },
  { 1368, 300, 102, 16, 3489 },
  { 1511, 300, 102, 16, 3489 },
  { 27, 300, 102, 16, 3489 },
  { 223, 300, 102, 16, 3489 },
  { 412, 300, 102, 16, 3489 },
  { 557, 300, 102, 16, 3489 },
  { 700, 300, 102, 16, 3489 },
  { 843, 300, 102, 16, 3489 },
  { 986, 300, 102, 16, 3489 },
  { 1129, 300, 102, 16, 3489 },
  { 1272, 300, 102, 16, 3489 },
  { 1415, 300, 102, 16, 3489 },
  { 78, 300, 102, 16, 3489 },
  { 275, 300, 102, 16, 3489 },
  { 464, 300, 102, 16, 3489 },
  { 609, 300, 102, 16, 3489 },
  { 752, 300, 102, 16, 3489 },
  { 895, 300, 102, 16, 3489 },
  { 1038, 300, 102, 16, 3489 },
  { 1181, 300, 102, 16, 3489 },
  { 1324, 300, 102, 16, 3489 },
  { 1467, 300, 102, 16, 3489 },
  { 130, 300, 102, 16, 3489 },
  { 327, 300, 102, 16, 3489 },
  { 179, 312, 102, 16, 4672 },
  { 491, 188, 286, 28, 1793 },
  { 635, 188, 179, 28, 1793 },
  { 778, 188, 179, 28, 1793 },
  { 921, 188, 179, 28, 1793 },
  { 1064, 188, 179, 28, 1793 },
  { 1207, 188, 179, 28, 1793 },
  { 1350, 188, 179, 28, 1793 },
  { 1493, 188, 179, 28, 1793 },
  { 7, 188, 179, 28, 1793 },
  { 202, 188, 179, 28, 1793 },
  { 389, 188, 179, 28, 1793 },
  { 533, 188, 179, 28, 1793 },
  { 676, 188, 179, 28, 1793 },
  { 819, 188, 179, 28, 1793 },
  { 962, 188, 179, 28, 1793 },
  { 1105, 188, 179, 28, 1793 },
  { 1248, 188, 179, 28, 1793 },
  { 1391, 188, 179, 28, 1793 },
  { 54, 188, 179, 28, 1793 },
  { 251, 188, 179, 28, 1793 },
  { 440, 188, 179, 28, 1793 },
  { 585, 188, 179, 28, 1793 },
  { 728, 188, 179, 28, 1793 },
  { 871, 188, 179, 28, 1793 },
  { 1014, 188, 179, 28, 1793 },
  { 1157, 188, 179, 28, 1793 },
  { 1300, 188, 179, 28, 1793 },
  { 1443, 188, 179, 28, 1793 },
  { 106, 188, 179, 28, 1793 },
  { 303, 188, 179, 28, 1793 },
  { 157, 203, 179, 28, 2704 },
  { 346, 636, 179, 28, 4416 },
  { 507, 474, 295, 43, 768 },
  { 650, 474, 185, 43, 1729 },
  { 793, 474, 185, 43, 1729 },
  { 936, 474, 185, 43, 1729 },
  { 1079, 474, 185, 43, 1729 },
  { 1222, 474, 185, 43, 1729 },
  { 1365, 474, 185, 43, 1729 },
  { 1508, 474, 185, 43, 1729 },
  { 24, 474, 185, 43, 1729 },
  { 220, 474, 185, 43, 1729 },
  { 408, 474, 185, 43, 1729 },
  { 553, 474, 185, 43, 1729 },
  { 696, 474, 185, 43, 1729 },
  { 839, 474, 185, 43, 1729 },
  { 982, 474, 185, 43, 1729 },
  { 1125, 474, 185, 43, 1729 },
  { 1268, 474, 185, 43, 1729 },
  { 1411, 474, 185, 43, 1729 },
  { 74, 474, 185, 43, 1729 },
  { 271, 474, 185, 43, 1729 },
  { 460, 474, 185, 43, 1729 },
  { 605, 474, 185, 43, 1729 },
  { 748, 474, 185, 43, 1729 },
  { 891, 474, 185, 43, 1729 },
  { 1034, 474, 185, 43, 1729 },
  { 1177, 474, 185, 43, 1729 },
  { 1320, 474, 185, 43, 1729 },
  { 1463, 474, 185, 43, 1729 },
  { 126, 474, 185, 43, 1729 },
  { 323, 474, 185, 43, 1729 },
  { 175, 495, 185, 43, 2704 },
  { 363, 352, 185, 43, 4416 },
  { 632, 430, 298, 64, 689 },
  { 775, 430, 298, 64, 689 },
  { 918, 430, 298, 64, 689 },
  { 1061, 430, 298, 64, 689 },
  { 1204, 430, 298, 64, 689 },
  { 1347, 430, 298, 64, 689 },
  { 1490, 430, 298, 64, 689 },
  { 4, 430, 298, 64, 689 },
  { 199, 430, 298, 64, 689 },
  { 386, 430, 298, 64, 689 },
  { 529, 430, 298, 64, 689 },
  { 672, 430, 298, 64, 689 },
  { 815, 430, 298, 64, 689 },
  { 958, 430, 298, 64, 689 },
  { 1101, 430, 298, 64, 689 },
  { 1244, 430, 298, 64, 689 },
  { 1387, 430, 298, 64, 689 },
  { 50, 430, 298, 64, 689 },
  { 247, 430, 298, 64, 689 },
  { 436, 430, 298, 64, 689 },
  { 581, 430, 298, 64, 689 },
  { 724, 430, 298, 64, 689 },
  { 867, 430, 298, 64, 689 },
  { 1010, 430, 298, 64, 689 },
  { 1153, 430, 298, 64, 689 },
  { 1296, 430, 298, 64, 689 },
  { 1439, 430, 298, 64, 689 },
  { 102, 430, 298, 64, 689 },
  { 299, 430, 298, 64, 689 },
  { 153, 452, 298, 64, 1200 },
  { 342, 330, 298, 64, 2272 },
  { 487, 612, 298, 64, 3984 },
  { 647, 548, 4, 86, 0 },
  { 790, 548, 4, 86, 609 },
  { 933, 548, 4, 86, 609 },
  { 1076, 548, 4, 86, 609 },
  { 1219, 548, 4, 86, 609 },
  { 1362, 548, 4, 86, 609 },
  { 1505, 548, 4, 86, 609 },
  { 21, 548, 4, 86, 609 },
  { 217, 548, 4, 86, 609 },
  { 405, 548, 4, 86, 609 },
  { 549, 548, 4, 86, 609 },
  { 692, 548, 4, 86, 609 },
  { 835, 548, 4, 86, 609 },
  { 978, 548, 4, 86, 609 },
  { 1121, 548, 4, 86, 609 },
  { 1264, 548, 4, 86, 609 },
  { 1407, 548, 4, 86, 609 },
  { 70, 548, 4, 86, 609 },
  { 267, 548, 4, 86, 609 },
  { 456, 548, 4, 86, 609 },
  { 601, 548, 4, 86, 609 },
  { 744, 548, 4, 86, 609 },
  { 887, 548, 4, 86, 609 },
  { 1030, 548, 4, 86, 609 },
  { 1173, 548, 4, 86, 609 },
  { 1316, 548, 4, 86, 609 },
  { 1459, 548, 4, 86, 609 },
  { 122, 548, 4, 86, 609 },
  { 319, 548, 4, 86, 609 },
  { 171, 580, 4, 86, 1200 },
  { 359, 373, 4, 86, 2272 },
  { 503, 516, 4, 86, 3984 },
};

  // FPR8 Register Class...
  static uint16_t FPR8[] = {
    AArch64_B0, AArch64_B1, AArch64_B2, AArch64_B3, AArch64_B4, AArch64_B5, AArch64_B6, AArch64_B7, AArch64_B8, AArch64_B9, AArch64_B10, AArch64_B11, AArch64_B12, AArch64_B13, AArch64_B14, AArch64_B15, AArch64_B16, AArch64_B17, AArch64_B18, AArch64_B19, AArch64_B20, AArch64_B21, AArch64_B22, AArch64_B23, AArch64_B24, AArch64_B25, AArch64_B26, AArch64_B27, AArch64_B28, AArch64_B29, AArch64_B30, AArch64_B31, 
  };

  // FPR8 Bit set.
  static uint8_t FPR8Bits[] = {
    0xc0, 0xff, 0xff, 0xff, 0x3f, 
  };

  // FPR16 Register Class...
  static uint16_t FPR16[] = {
    AArch64_H0, AArch64_H1, AArch64_H2, AArch64_H3, AArch64_H4, AArch64_H5, AArch64_H6, AArch64_H7, AArch64_H8, AArch64_H9, AArch64_H10, AArch64_H11, AArch64_H12, AArch64_H13, AArch64_H14, AArch64_H15, AArch64_H16, AArch64_H17, AArch64_H18, AArch64_H19, AArch64_H20, AArch64_H21, AArch64_H22, AArch64_H23, AArch64_H24, AArch64_H25, AArch64_H26, AArch64_H27, AArch64_H28, AArch64_H29, AArch64_H30, AArch64_H31, 
  };

  // FPR16 Bit set.
  static uint8_t FPR16Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f, 
  };

  // FPR32 Register Class...
  static uint16_t FPR32[] = {
    AArch64_S0, AArch64_S1, AArch64_S2, AArch64_S3, AArch64_S4, AArch64_S5, AArch64_S6, AArch64_S7, AArch64_S8, AArch64_S9, AArch64_S10, AArch64_S11, AArch64_S12, AArch64_S13, AArch64_S14, AArch64_S15, AArch64_S16, AArch64_S17, AArch64_S18, AArch64_S19, AArch64_S20, AArch64_S21, AArch64_S22, AArch64_S23, AArch64_S24, AArch64_S25, AArch64_S26, AArch64_S27, AArch64_S28, AArch64_S29, AArch64_S30, AArch64_S31, 
  };

  // FPR32 Bit set.
  static uint8_t FPR32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f, 
  };

  // GPR32 Register Class...
  static uint16_t GPR32[] = {
    AArch64_W0, AArch64_W1, AArch64_W2, AArch64_W3, AArch64_W4, AArch64_W5, AArch64_W6, AArch64_W7, AArch64_W8, AArch64_W9, AArch64_W10, AArch64_W11, AArch64_W12, AArch64_W13, AArch64_W14, AArch64_W15, AArch64_W16, AArch64_W17, AArch64_W18, AArch64_W19, AArch64_W20, AArch64_W21, AArch64_W22, AArch64_W23, AArch64_W24, AArch64_W25, AArch64_W26, AArch64_W27, AArch64_W28, AArch64_W29, AArch64_W30, AArch64_WZR, 
  };

  // GPR32 Bit set.
  static uint8_t GPR32Bits[] = {
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x1f, 
  };

  // GPR32wsp Register Class...
  static uint16_t GPR32wsp[] = {
    AArch64_W0, AArch64_W1, AArch64_W2, AArch64_W3, AArch64_W4, AArch64_W5, AArch64_W6, AArch64_W7, AArch64_W8, AArch64_W9, AArch64_W10, AArch64_W11, AArch64_W12, AArch64_W13, AArch64_W14, AArch64_W15, AArch64_W16, AArch64_W17, AArch64_W18, AArch64_W19, AArch64_W20, AArch64_W21, AArch64_W22, AArch64_W23, AArch64_W24, AArch64_W25, AArch64_W26, AArch64_W27, AArch64_W28, AArch64_W29, AArch64_W30, AArch64_WSP, 
  };

  // GPR32wsp Bit set.
  static uint8_t GPR32wspBits[] = {
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x1f, 
  };

  // GPR32nowzr Register Class...
  static uint16_t GPR32nowzr[] = {
    AArch64_W0, AArch64_W1, AArch64_W2, AArch64_W3, AArch64_W4, AArch64_W5, AArch64_W6, AArch64_W7, AArch64_W8, AArch64_W9, AArch64_W10, AArch64_W11, AArch64_W12, AArch64_W13, AArch64_W14, AArch64_W15, AArch64_W16, AArch64_W17, AArch64_W18, AArch64_W19, AArch64_W20, AArch64_W21, AArch64_W22, AArch64_W23, AArch64_W24, AArch64_W25, AArch64_W26, AArch64_W27, AArch64_W28, AArch64_W29, AArch64_W30, 
  };

  // GPR32nowzr Bit set.
  static uint8_t GPR32nowzrBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x1f, 
  };

  // FlagClass Register Class...
  static uint16_t FlagClass[] = {
    AArch64_NZCV, 
  };

  // FlagClass Bit set.
  static uint8_t FlagClassBits[] = {
    0x02, 
  };

  // Rwsp Register Class...
  static uint16_t Rwsp[] = {
    AArch64_WSP, 
  };

  // Rwsp Bit set.
  static uint8_t RwspBits[] = {
    0x04, 
  };

  // FPR64 Register Class...
  static uint16_t FPR64[] = {
    AArch64_D0, AArch64_D1, AArch64_D2, AArch64_D3, AArch64_D4, AArch64_D5, AArch64_D6, AArch64_D7, AArch64_D8, AArch64_D9, AArch64_D10, AArch64_D11, AArch64_D12, AArch64_D13, AArch64_D14, AArch64_D15, AArch64_D16, AArch64_D17, AArch64_D18, AArch64_D19, AArch64_D20, AArch64_D21, AArch64_D22, AArch64_D23, AArch64_D24, AArch64_D25, AArch64_D26, AArch64_D27, AArch64_D28, AArch64_D29, AArch64_D30, AArch64_D31, 
  };

  // FPR64 Bit set.
  static uint8_t FPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f, 
  };

  // GPR64 Register Class...
  static uint16_t GPR64[] = {
    AArch64_X0, AArch64_X1, AArch64_X2, AArch64_X3, AArch64_X4, AArch64_X5, AArch64_X6, AArch64_X7, AArch64_X8, AArch64_X9, AArch64_X10, AArch64_X11, AArch64_X12, AArch64_X13, AArch64_X14, AArch64_X15, AArch64_X16, AArch64_X17, AArch64_X18, AArch64_X19, AArch64_X20, AArch64_X21, AArch64_X22, AArch64_X23, AArch64_X24, AArch64_X25, AArch64_X26, AArch64_X27, AArch64_X28, AArch64_X29, AArch64_X30, AArch64_XZR, 
  };

  // GPR64 Bit set.
  static uint8_t GPR64Bits[] = {
    0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // GPR64xsp Register Class...
  static uint16_t GPR64xsp[] = {
    AArch64_X0, AArch64_X1, AArch64_X2, AArch64_X3, AArch64_X4, AArch64_X5, AArch64_X6, AArch64_X7, AArch64_X8, AArch64_X9, AArch64_X10, AArch64_X11, AArch64_X12, AArch64_X13, AArch64_X14, AArch64_X15, AArch64_X16, AArch64_X17, AArch64_X18, AArch64_X19, AArch64_X20, AArch64_X21, AArch64_X22, AArch64_X23, AArch64_X24, AArch64_X25, AArch64_X26, AArch64_X27, AArch64_X28, AArch64_X29, AArch64_X30, AArch64_XSP, 
  };

  // GPR64xsp Bit set.
  static uint8_t GPR64xspBits[] = {
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // GPR64noxzr Register Class...
  static uint16_t GPR64noxzr[] = {
    AArch64_X0, AArch64_X1, AArch64_X2, AArch64_X3, AArch64_X4, AArch64_X5, AArch64_X6, AArch64_X7, AArch64_X8, AArch64_X9, AArch64_X10, AArch64_X11, AArch64_X12, AArch64_X13, AArch64_X14, AArch64_X15, AArch64_X16, AArch64_X17, AArch64_X18, AArch64_X19, AArch64_X20, AArch64_X21, AArch64_X22, AArch64_X23, AArch64_X24, AArch64_X25, AArch64_X26, AArch64_X27, AArch64_X28, AArch64_X29, AArch64_X30, 
  };

  // GPR64noxzr Bit set.
  static uint8_t GPR64noxzrBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // tcGPR64 Register Class...
  static uint16_t tcGPR64[] = {
    AArch64_X0, AArch64_X1, AArch64_X2, AArch64_X3, AArch64_X4, AArch64_X5, AArch64_X6, AArch64_X7, AArch64_X9, AArch64_X10, AArch64_X11, AArch64_X12, AArch64_X13, AArch64_X14, AArch64_X15, AArch64_X16, AArch64_X17, AArch64_X18, 
  };

  // tcGPR64 Bit set.
  static uint8_t tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xdf, 0xff, 
  };

  // FPR64Lo Register Class...
  static uint16_t FPR64Lo[] = {
    AArch64_D0, AArch64_D1, AArch64_D2, AArch64_D3, AArch64_D4, AArch64_D5, AArch64_D6, AArch64_D7, AArch64_D8, AArch64_D9, AArch64_D10, AArch64_D11, AArch64_D12, AArch64_D13, AArch64_D14, AArch64_D15, 
  };

  // FPR64Lo Bit set.
  static uint8_t FPR64LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0x3f, 
  };

  // Rxsp Register Class...
  static uint16_t Rxsp[] = {
    AArch64_XSP, 
  };

  // Rxsp Bit set.
  static uint8_t RxspBits[] = {
    0x10, 
  };

  // DPair Register Class...
  static uint16_t DPair[] = {
    AArch64_D0_D1, AArch64_D1_D2, AArch64_D2_D3, AArch64_D3_D4, AArch64_D4_D5, AArch64_D5_D6, AArch64_D6_D7, AArch64_D7_D8, AArch64_D8_D9, AArch64_D9_D10, AArch64_D10_D11, AArch64_D11_D12, AArch64_D12_D13, AArch64_D13_D14, AArch64_D14_D15, AArch64_D15_D16, AArch64_D16_D17, AArch64_D17_D18, AArch64_D18_D19, AArch64_D19_D20, AArch64_D20_D21, AArch64_D21_D22, AArch64_D22_D23, AArch64_D23_D24, AArch64_D24_D25, AArch64_D25_D26, AArch64_D26_D27, AArch64_D27_D28, AArch64_D28_D29, AArch64_D29_D30, AArch64_D30_D31, AArch64_D31_D0, 
  };

  // DPair Bit set.
  static uint8_t DPairBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // DPair_with_dsub_0_in_FPR64Lo Register Class...
  static uint16_t DPair_with_dsub_0_in_FPR64Lo[] = {
    AArch64_D0_D1, AArch64_D1_D2, AArch64_D2_D3, AArch64_D3_D4, AArch64_D4_D5, AArch64_D5_D6, AArch64_D6_D7, AArch64_D7_D8, AArch64_D8_D9, AArch64_D9_D10, AArch64_D10_D11, AArch64_D11_D12, AArch64_D12_D13, AArch64_D13_D14, AArch64_D14_D15, AArch64_D15_D16, 
  };

  // DPair_with_dsub_0_in_FPR64Lo Bit set.
  static uint8_t DPair_with_dsub_0_in_FPR64LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // DPair_with_dsub_1_in_FPR64Lo Register Class...
  static uint16_t DPair_with_dsub_1_in_FPR64Lo[] = {
    AArch64_D0_D1, AArch64_D1_D2, AArch64_D2_D3, AArch64_D3_D4, AArch64_D4_D5, AArch64_D5_D6, AArch64_D6_D7, AArch64_D7_D8, AArch64_D8_D9, AArch64_D9_D10, AArch64_D10_D11, AArch64_D11_D12, AArch64_D12_D13, AArch64_D13_D14, AArch64_D14_D15, AArch64_D31_D0, 
  };

  // DPair_with_dsub_1_in_FPR64Lo Bit set.
  static uint8_t DPair_with_dsub_1_in_FPR64LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 0x00, 0x08, 
  };

  // DPair_with_dsub_0_in_FPR64Lo_and_DPair_with_dsub_1_in_FPR64Lo Register Class...
  static uint16_t DPair_with_dsub_0_in_FPR64Lo_and_DPair_with_dsub_1_in_FPR64Lo[] = {
    AArch64_D0_D1, AArch64_D1_D2, AArch64_D2_D3, AArch64_D3_D4, AArch64_D4_D5, AArch64_D5_D6, AArch64_D6_D7, AArch64_D7_D8, AArch64_D8_D9, AArch64_D9_D10, AArch64_D10_D11, AArch64_D11_D12, AArch64_D12_D13, AArch64_D13_D14, AArch64_D14_D15, 
  };

  // DPair_with_dsub_0_in_FPR64Lo_and_DPair_with_dsub_1_in_FPR64Lo Bit set.
  static uint8_t DPair_with_dsub_0_in_FPR64Lo_and_DPair_with_dsub_1_in_FPR64LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 
  };

  // FPR128 Register Class...
  static uint16_t FPR128[] = {
    AArch64_Q0, AArch64_Q1, AArch64_Q2, AArch64_Q3, AArch64_Q4, AArch64_Q5, AArch64_Q6, AArch64_Q7, AArch64_Q8, AArch64_Q9, AArch64_Q10, AArch64_Q11, AArch64_Q12, AArch64_Q13, AArch64_Q14, AArch64_Q15, AArch64_Q16, AArch64_Q17, AArch64_Q18, AArch64_Q19, AArch64_Q20, AArch64_Q21, AArch64_Q22, AArch64_Q23, AArch64_Q24, AArch64_Q25, AArch64_Q26, AArch64_Q27, AArch64_Q28, AArch64_Q29, AArch64_Q30, AArch64_Q31, 
  };

  // FPR128 Bit set.
  static uint8_t FPR128Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f, 
  };

  // FPR128Lo Register Class...
  static uint16_t FPR128Lo[] = {
    AArch64_Q0, AArch64_Q1, AArch64_Q2, AArch64_Q3, AArch64_Q4, AArch64_Q5, AArch64_Q6, AArch64_Q7, AArch64_Q8, AArch64_Q9, AArch64_Q10, AArch64_Q11, AArch64_Q12, AArch64_Q13, AArch64_Q14, AArch64_Q15, 
  };

  // FPR128Lo Bit set.
  static uint8_t FPR128LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0x3f, 
  };

  // DTriple Register Class...
  static uint16_t DTriple[] = {
    AArch64_D0_D1_D2, AArch64_D1_D2_D3, AArch64_D2_D3_D4, AArch64_D3_D4_D5, AArch64_D4_D5_D6, AArch64_D5_D6_D7, AArch64_D6_D7_D8, AArch64_D7_D8_D9, AArch64_D8_D9_D10, AArch64_D9_D10_D11, AArch64_D10_D11_D12, AArch64_D11_D12_D13, AArch64_D12_D13_D14, AArch64_D13_D14_D15, AArch64_D14_D15_D16, AArch64_D15_D16_D17, AArch64_D16_D17_D18, AArch64_D17_D18_D19, AArch64_D18_D19_D20, AArch64_D19_D20_D21, AArch64_D20_D21_D22, AArch64_D21_D22_D23, AArch64_D22_D23_D24, AArch64_D23_D24_D25, AArch64_D24_D25_D26, AArch64_D25_D26_D27, AArch64_D26_D27_D28, AArch64_D27_D28_D29, AArch64_D28_D29_D30, AArch64_D29_D30_D31, AArch64_D30_D31_D0, AArch64_D31_D0_D1, 
  };

  // DTriple Bit set.
  static uint8_t DTripleBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // DTriple_with_dsub_0_in_FPR64Lo Register Class...
  static uint16_t DTriple_with_dsub_0_in_FPR64Lo[] = {
    AArch64_D0_D1_D2, AArch64_D1_D2_D3, AArch64_D2_D3_D4, AArch64_D3_D4_D5, AArch64_D4_D5_D6, AArch64_D5_D6_D7, AArch64_D6_D7_D8, AArch64_D7_D8_D9, AArch64_D8_D9_D10, AArch64_D9_D10_D11, AArch64_D10_D11_D12, AArch64_D11_D12_D13, AArch64_D12_D13_D14, AArch64_D13_D14_D15, AArch64_D14_D15_D16, AArch64_D15_D16_D17, 
  };

  // DTriple_with_dsub_0_in_FPR64Lo Bit set.
  static uint8_t DTriple_with_dsub_0_in_FPR64LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // DTriple_with_dsub_1_in_FPR64Lo Register Class...
  static uint16_t DTriple_with_dsub_1_in_FPR64Lo[] = {
    AArch64_D0_D1_D2, AArch64_D1_D2_D3, AArch64_D2_D3_D4, AArch64_D3_D4_D5, AArch64_D4_D5_D6, AArch64_D5_D6_D7, AArch64_D6_D7_D8, AArch64_D7_D8_D9, AArch64_D8_D9_D10, AArch64_D9_D10_D11, AArch64_D10_D11_D12, AArch64_D11_D12_D13, AArch64_D12_D13_D14, AArch64_D13_D14_D15, AArch64_D14_D15_D16, AArch64_D31_D0_D1, 
  };

  // DTriple_with_dsub_1_in_FPR64Lo Bit set.
  static uint8_t DTriple_with_dsub_1_in_FPR64LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 0x00, 0x08, 
  };

  // DTriple_with_dsub_2_in_FPR64Lo Register Class...
  static uint16_t DTriple_with_dsub_2_in_FPR64Lo[] = {
    AArch64_D0_D1_D2, AArch64_D1_D2_D3, AArch64_D2_D3_D4, AArch64_D3_D4_D5, AArch64_D4_D5_D6, AArch64_D5_D6_D7, AArch64_D6_D7_D8, AArch64_D7_D8_D9, AArch64_D8_D9_D10, AArch64_D9_D10_D11, AArch64_D10_D11_D12, AArch64_D11_D12_D13, AArch64_D12_D13_D14, AArch64_D13_D14_D15, AArch64_D30_D31_D0, AArch64_D31_D0_D1, 
  };

  // DTriple_with_dsub_2_in_FPR64Lo Bit set.
  static uint8_t DTriple_with_dsub_2_in_FPR64LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x03, 0x00, 0x0c, 
  };

  // DTriple_with_dsub_0_in_FPR64Lo_and_DTriple_with_dsub_1_in_FPR64Lo Register Class...
  static uint16_t DTriple_with_dsub_0_in_FPR64Lo_and_DTriple_with_dsub_1_in_FPR64Lo[] = {
    AArch64_D0_D1_D2, AArch64_D1_D2_D3, AArch64_D2_D3_D4, AArch64_D3_D4_D5, AArch64_D4_D5_D6, AArch64_D5_D6_D7, AArch64_D6_D7_D8, AArch64_D7_D8_D9, AArch64_D8_D9_D10, AArch64_D9_D10_D11, AArch64_D10_D11_D12, AArch64_D11_D12_D13, AArch64_D12_D13_D14, AArch64_D13_D14_D15, AArch64_D14_D15_D16, 
  };

  // DTriple_with_dsub_0_in_FPR64Lo_and_DTriple_with_dsub_1_in_FPR64Lo Bit set.
  static uint8_t DTriple_with_dsub_0_in_FPR64Lo_and_DTriple_with_dsub_1_in_FPR64LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 
  };

  // DTriple_with_dsub_1_in_FPR64Lo_and_DTriple_with_dsub_2_in_FPR64Lo Register Class...
  static uint16_t DTriple_with_dsub_1_in_FPR64Lo_and_DTriple_with_dsub_2_in_FPR64Lo[] = {
    AArch64_D0_D1_D2, AArch64_D1_D2_D3, AArch64_D2_D3_D4, AArch64_D3_D4_D5, AArch64_D4_D5_D6, AArch64_D5_D6_D7, AArch64_D6_D7_D8, AArch64_D7_D8_D9, AArch64_D8_D9_D10, AArch64_D9_D10_D11, AArch64_D10_D11_D12, AArch64_D11_D12_D13, AArch64_D12_D13_D14, AArch64_D13_D14_D15, AArch64_D31_D0_D1, 
  };

  // DTriple_with_dsub_1_in_FPR64Lo_and_DTriple_with_dsub_2_in_FPR64Lo Bit set.
  static uint8_t DTriple_with_dsub_1_in_FPR64Lo_and_DTriple_with_dsub_2_in_FPR64LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x03, 0x00, 0x08, 
  };

  // DTriple_with_dsub_0_in_FPR64Lo_and_DTriple_with_dsub_2_in_FPR64Lo Register Class...
  static uint16_t DTriple_with_dsub_0_in_FPR64Lo_and_DTriple_with_dsub_2_in_FPR64Lo[] = {
    AArch64_D0_D1_D2, AArch64_D1_D2_D3, AArch64_D2_D3_D4, AArch64_D3_D4_D5, AArch64_D4_D5_D6, AArch64_D5_D6_D7, AArch64_D6_D7_D8, AArch64_D7_D8_D9, AArch64_D8_D9_D10, AArch64_D9_D10_D11, AArch64_D10_D11_D12, AArch64_D11_D12_D13, AArch64_D12_D13_D14, AArch64_D13_D14_D15, 
  };

  // DTriple_with_dsub_0_in_FPR64Lo_and_DTriple_with_dsub_2_in_FPR64Lo Bit set.
  static uint8_t DTriple_with_dsub_0_in_FPR64Lo_and_DTriple_with_dsub_2_in_FPR64LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x03, 
  };

  // DQuad Register Class...
  static uint16_t DQuad[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D13_D14_D15_D16, AArch64_D14_D15_D16_D17, AArch64_D15_D16_D17_D18, AArch64_D16_D17_D18_D19, AArch64_D17_D18_D19_D20, AArch64_D18_D19_D20_D21, AArch64_D19_D20_D21_D22, AArch64_D20_D21_D22_D23, AArch64_D21_D22_D23_D24, AArch64_D22_D23_D24_D25, AArch64_D23_D24_D25_D26, AArch64_D24_D25_D26_D27, AArch64_D25_D26_D27_D28, AArch64_D26_D27_D28_D29, AArch64_D27_D28_D29_D30, AArch64_D28_D29_D30_D31, AArch64_D29_D30_D31_D0, AArch64_D30_D31_D0_D1, AArch64_D31_D0_D1_D2, 
  };

  // DQuad Bit set.
  static uint8_t DQuadBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // DQuad_with_dsub_0_in_FPR64Lo Register Class...
  static uint16_t DQuad_with_dsub_0_in_FPR64Lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D13_D14_D15_D16, AArch64_D14_D15_D16_D17, AArch64_D15_D16_D17_D18, 
  };

  // DQuad_with_dsub_0_in_FPR64Lo Bit set.
  static uint8_t DQuad_with_dsub_0_in_FPR64LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // DQuad_with_dsub_1_in_FPR64Lo Register Class...
  static uint16_t DQuad_with_dsub_1_in_FPR64Lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D13_D14_D15_D16, AArch64_D14_D15_D16_D17, AArch64_D31_D0_D1_D2, 
  };

  // DQuad_with_dsub_1_in_FPR64Lo Bit set.
  static uint8_t DQuad_with_dsub_1_in_FPR64LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 0x00, 0x08, 
  };

  // DQuad_with_dsub_2_in_FPR64Lo Register Class...
  static uint16_t DQuad_with_dsub_2_in_FPR64Lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D13_D14_D15_D16, AArch64_D30_D31_D0_D1, AArch64_D31_D0_D1_D2, 
  };

  // DQuad_with_dsub_2_in_FPR64Lo Bit set.
  static uint8_t DQuad_with_dsub_2_in_FPR64LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x03, 0x00, 0x0c, 
  };

  // DQuad_with_dsub_3_in_FPR64Lo Register Class...
  static uint16_t DQuad_with_dsub_3_in_FPR64Lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D29_D30_D31_D0, AArch64_D30_D31_D0_D1, AArch64_D31_D0_D1_D2, 
  };

  // DQuad_with_dsub_3_in_FPR64Lo Bit set.
  static uint8_t DQuad_with_dsub_3_in_FPR64LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x01, 0x00, 0x0e, 
  };

  // DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_1_in_FPR64Lo Register Class...
  static uint16_t DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_1_in_FPR64Lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D13_D14_D15_D16, AArch64_D14_D15_D16_D17, 
  };

  // DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_1_in_FPR64Lo Bit set.
  static uint8_t DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_1_in_FPR64LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 
  };

  // DQuad_with_dsub_1_in_FPR64Lo_and_DQuad_with_dsub_2_in_FPR64Lo Register Class...
  static uint16_t DQuad_with_dsub_1_in_FPR64Lo_and_DQuad_with_dsub_2_in_FPR64Lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D13_D14_D15_D16, AArch64_D31_D0_D1_D2, 
  };

  // DQuad_with_dsub_1_in_FPR64Lo_and_DQuad_with_dsub_2_in_FPR64Lo Bit set.
  static uint8_t DQuad_with_dsub_1_in_FPR64Lo_and_DQuad_with_dsub_2_in_FPR64LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x03, 0x00, 0x08, 
  };

  // DQuad_with_dsub_2_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64Lo Register Class...
  static uint16_t DQuad_with_dsub_2_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64Lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D30_D31_D0_D1, AArch64_D31_D0_D1_D2, 
  };

  // DQuad_with_dsub_2_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64Lo Bit set.
  static uint8_t DQuad_with_dsub_2_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x01, 0x00, 0x0c, 
  };

  // DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_2_in_FPR64Lo Register Class...
  static uint16_t DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_2_in_FPR64Lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D13_D14_D15_D16, 
  };

  // DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_2_in_FPR64Lo Bit set.
  static uint8_t DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_2_in_FPR64LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x03, 
  };

  // DQuad_with_dsub_1_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64Lo Register Class...
  static uint16_t DQuad_with_dsub_1_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64Lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D31_D0_D1_D2, 
  };

  // DQuad_with_dsub_1_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64Lo Bit set.
  static uint8_t DQuad_with_dsub_1_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x01, 0x00, 0x08, 
  };

  // DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64Lo Register Class...
  static uint16_t DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64Lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, 
  };

  // DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64Lo Bit set.
  static uint8_t DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x01, 
  };

  // QPair Register Class...
  static uint16_t QPair[] = {
    AArch64_Q0_Q1, AArch64_Q1_Q2, AArch64_Q2_Q3, AArch64_Q3_Q4, AArch64_Q4_Q5, AArch64_Q5_Q6, AArch64_Q6_Q7, AArch64_Q7_Q8, AArch64_Q8_Q9, AArch64_Q9_Q10, AArch64_Q10_Q11, AArch64_Q11_Q12, AArch64_Q12_Q13, AArch64_Q13_Q14, AArch64_Q14_Q15, AArch64_Q15_Q16, AArch64_Q16_Q17, AArch64_Q17_Q18, AArch64_Q18_Q19, AArch64_Q19_Q20, AArch64_Q20_Q21, AArch64_Q21_Q22, AArch64_Q22_Q23, AArch64_Q23_Q24, AArch64_Q24_Q25, AArch64_Q25_Q26, AArch64_Q26_Q27, AArch64_Q27_Q28, AArch64_Q28_Q29, AArch64_Q29_Q30, AArch64_Q30_Q31, AArch64_Q31_Q0, 
  };

  // QPair Bit set.
  static uint8_t QPairBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // QPair_with_qsub_0_in_FPR128Lo Register Class...
  static uint16_t QPair_with_qsub_0_in_FPR128Lo[] = {
    AArch64_Q0_Q1, AArch64_Q1_Q2, AArch64_Q2_Q3, AArch64_Q3_Q4, AArch64_Q4_Q5, AArch64_Q5_Q6, AArch64_Q6_Q7, AArch64_Q7_Q8, AArch64_Q8_Q9, AArch64_Q9_Q10, AArch64_Q10_Q11, AArch64_Q11_Q12, AArch64_Q12_Q13, AArch64_Q13_Q14, AArch64_Q14_Q15, AArch64_Q15_Q16, 
  };

  // QPair_with_qsub_0_in_FPR128Lo Bit set.
  static uint8_t QPair_with_qsub_0_in_FPR128LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // QPair_with_qsub_1_in_FPR128Lo Register Class...
  static uint16_t QPair_with_qsub_1_in_FPR128Lo[] = {
    AArch64_Q0_Q1, AArch64_Q1_Q2, AArch64_Q2_Q3, AArch64_Q3_Q4, AArch64_Q4_Q5, AArch64_Q5_Q6, AArch64_Q6_Q7, AArch64_Q7_Q8, AArch64_Q8_Q9, AArch64_Q9_Q10, AArch64_Q10_Q11, AArch64_Q11_Q12, AArch64_Q12_Q13, AArch64_Q13_Q14, AArch64_Q14_Q15, AArch64_Q31_Q0, 
  };

  // QPair_with_qsub_1_in_FPR128Lo Bit set.
  static uint8_t QPair_with_qsub_1_in_FPR128LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 0x00, 0x08, 
  };

  // QPair_with_qsub_0_in_FPR128Lo_and_QPair_with_qsub_1_in_FPR128Lo Register Class...
  static uint16_t QPair_with_qsub_0_in_FPR128Lo_and_QPair_with_qsub_1_in_FPR128Lo[] = {
    AArch64_Q0_Q1, AArch64_Q1_Q2, AArch64_Q2_Q3, AArch64_Q3_Q4, AArch64_Q4_Q5, AArch64_Q5_Q6, AArch64_Q6_Q7, AArch64_Q7_Q8, AArch64_Q8_Q9, AArch64_Q9_Q10, AArch64_Q10_Q11, AArch64_Q11_Q12, AArch64_Q12_Q13, AArch64_Q13_Q14, AArch64_Q14_Q15, 
  };

  // QPair_with_qsub_0_in_FPR128Lo_and_QPair_with_qsub_1_in_FPR128Lo Bit set.
  static uint8_t QPair_with_qsub_0_in_FPR128Lo_and_QPair_with_qsub_1_in_FPR128LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 
  };

  // QTriple Register Class...
  static uint16_t QTriple[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, AArch64_Q14_Q15_Q16, AArch64_Q15_Q16_Q17, AArch64_Q16_Q17_Q18, AArch64_Q17_Q18_Q19, AArch64_Q18_Q19_Q20, AArch64_Q19_Q20_Q21, AArch64_Q20_Q21_Q22, AArch64_Q21_Q22_Q23, AArch64_Q22_Q23_Q24, AArch64_Q23_Q24_Q25, AArch64_Q24_Q25_Q26, AArch64_Q25_Q26_Q27, AArch64_Q26_Q27_Q28, AArch64_Q27_Q28_Q29, AArch64_Q28_Q29_Q30, AArch64_Q29_Q30_Q31, AArch64_Q30_Q31_Q0, AArch64_Q31_Q0_Q1, 
  };

  // QTriple Bit set.
  static uint8_t QTripleBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // QTriple_with_qsub_0_in_FPR128Lo Register Class...
  static uint16_t QTriple_with_qsub_0_in_FPR128Lo[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, AArch64_Q14_Q15_Q16, AArch64_Q15_Q16_Q17, 
  };

  // QTriple_with_qsub_0_in_FPR128Lo Bit set.
  static uint8_t QTriple_with_qsub_0_in_FPR128LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // QTriple_with_qsub_1_in_FPR128Lo Register Class...
  static uint16_t QTriple_with_qsub_1_in_FPR128Lo[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, AArch64_Q14_Q15_Q16, AArch64_Q31_Q0_Q1, 
  };

  // QTriple_with_qsub_1_in_FPR128Lo Bit set.
  static uint8_t QTriple_with_qsub_1_in_FPR128LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 0x00, 0x08, 
  };

  // QTriple_with_qsub_2_in_FPR128Lo Register Class...
  static uint16_t QTriple_with_qsub_2_in_FPR128Lo[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, AArch64_Q30_Q31_Q0, AArch64_Q31_Q0_Q1, 
  };

  // QTriple_with_qsub_2_in_FPR128Lo Bit set.
  static uint8_t QTriple_with_qsub_2_in_FPR128LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x03, 0x00, 0x0c, 
  };

  // QTriple_with_qsub_0_in_FPR128Lo_and_QTriple_with_qsub_1_in_FPR128Lo Register Class...
  static uint16_t QTriple_with_qsub_0_in_FPR128Lo_and_QTriple_with_qsub_1_in_FPR128Lo[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, AArch64_Q14_Q15_Q16, 
  };

  // QTriple_with_qsub_0_in_FPR128Lo_and_QTriple_with_qsub_1_in_FPR128Lo Bit set.
  static uint8_t QTriple_with_qsub_0_in_FPR128Lo_and_QTriple_with_qsub_1_in_FPR128LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 
  };

  // QTriple_with_qsub_1_in_FPR128Lo_and_QTriple_with_qsub_2_in_FPR128Lo Register Class...
  static uint16_t QTriple_with_qsub_1_in_FPR128Lo_and_QTriple_with_qsub_2_in_FPR128Lo[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, AArch64_Q31_Q0_Q1, 
  };

  // QTriple_with_qsub_1_in_FPR128Lo_and_QTriple_with_qsub_2_in_FPR128Lo Bit set.
  static uint8_t QTriple_with_qsub_1_in_FPR128Lo_and_QTriple_with_qsub_2_in_FPR128LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x03, 0x00, 0x08, 
  };

  // QTriple_with_qsub_0_in_FPR128Lo_and_QTriple_with_qsub_2_in_FPR128Lo Register Class...
  static uint16_t QTriple_with_qsub_0_in_FPR128Lo_and_QTriple_with_qsub_2_in_FPR128Lo[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, 
  };

  // QTriple_with_qsub_0_in_FPR128Lo_and_QTriple_with_qsub_2_in_FPR128Lo Bit set.
  static uint8_t QTriple_with_qsub_0_in_FPR128Lo_and_QTriple_with_qsub_2_in_FPR128LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x03, 
  };

  // QQuad Register Class...
  static uint16_t QQuad[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, AArch64_Q14_Q15_Q16_Q17, AArch64_Q15_Q16_Q17_Q18, AArch64_Q16_Q17_Q18_Q19, AArch64_Q17_Q18_Q19_Q20, AArch64_Q18_Q19_Q20_Q21, AArch64_Q19_Q20_Q21_Q22, AArch64_Q20_Q21_Q22_Q23, AArch64_Q21_Q22_Q23_Q24, AArch64_Q22_Q23_Q24_Q25, AArch64_Q23_Q24_Q25_Q26, AArch64_Q24_Q25_Q26_Q27, AArch64_Q25_Q26_Q27_Q28, AArch64_Q26_Q27_Q28_Q29, AArch64_Q27_Q28_Q29_Q30, AArch64_Q28_Q29_Q30_Q31, AArch64_Q29_Q30_Q31_Q0, AArch64_Q30_Q31_Q0_Q1, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQuad Bit set.
  static uint8_t QQuadBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // QQuad_with_qsub_0_in_FPR128Lo Register Class...
  static uint16_t QQuad_with_qsub_0_in_FPR128Lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, AArch64_Q14_Q15_Q16_Q17, AArch64_Q15_Q16_Q17_Q18, 
  };

  // QQuad_with_qsub_0_in_FPR128Lo Bit set.
  static uint8_t QQuad_with_qsub_0_in_FPR128LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // QQuad_with_qsub_1_in_FPR128Lo Register Class...
  static uint16_t QQuad_with_qsub_1_in_FPR128Lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, AArch64_Q14_Q15_Q16_Q17, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQuad_with_qsub_1_in_FPR128Lo Bit set.
  static uint8_t QQuad_with_qsub_1_in_FPR128LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 0x00, 0x08, 
  };

  // QQuad_with_qsub_2_in_FPR128Lo Register Class...
  static uint16_t QQuad_with_qsub_2_in_FPR128Lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, AArch64_Q30_Q31_Q0_Q1, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQuad_with_qsub_2_in_FPR128Lo Bit set.
  static uint8_t QQuad_with_qsub_2_in_FPR128LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x03, 0x00, 0x0c, 
  };

  // QQuad_with_qsub_3_in_FPR128Lo Register Class...
  static uint16_t QQuad_with_qsub_3_in_FPR128Lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q29_Q30_Q31_Q0, AArch64_Q30_Q31_Q0_Q1, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQuad_with_qsub_3_in_FPR128Lo Bit set.
  static uint8_t QQuad_with_qsub_3_in_FPR128LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x01, 0x00, 0x0e, 
  };

  // QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_1_in_FPR128Lo Register Class...
  static uint16_t QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_1_in_FPR128Lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, AArch64_Q14_Q15_Q16_Q17, 
  };

  // QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_1_in_FPR128Lo Bit set.
  static uint8_t QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_1_in_FPR128LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 
  };

  // QQuad_with_qsub_1_in_FPR128Lo_and_QQuad_with_qsub_2_in_FPR128Lo Register Class...
  static uint16_t QQuad_with_qsub_1_in_FPR128Lo_and_QQuad_with_qsub_2_in_FPR128Lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQuad_with_qsub_1_in_FPR128Lo_and_QQuad_with_qsub_2_in_FPR128Lo Bit set.
  static uint8_t QQuad_with_qsub_1_in_FPR128Lo_and_QQuad_with_qsub_2_in_FPR128LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x03, 0x00, 0x08, 
  };

  // QQuad_with_qsub_2_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128Lo Register Class...
  static uint16_t QQuad_with_qsub_2_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128Lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q30_Q31_Q0_Q1, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQuad_with_qsub_2_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128Lo Bit set.
  static uint8_t QQuad_with_qsub_2_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x01, 0x00, 0x0c, 
  };

  // QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_2_in_FPR128Lo Register Class...
  static uint16_t QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_2_in_FPR128Lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, 
  };

  // QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_2_in_FPR128Lo Bit set.
  static uint8_t QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_2_in_FPR128LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x03, 
  };

  // QQuad_with_qsub_1_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128Lo Register Class...
  static uint16_t QQuad_with_qsub_1_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128Lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQuad_with_qsub_1_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128Lo Bit set.
  static uint8_t QQuad_with_qsub_1_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x01, 0x00, 0x08, 
  };

  // QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128Lo Register Class...
  static uint16_t QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128Lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, 
  };

  // QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128Lo Bit set.
  static uint8_t QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128LoBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x01, 
  };

static MCRegisterClass AArch64MCRegisterClasses[] = {
  { "FPR8", FPR8, FPR8Bits, 32, sizeof(FPR8Bits), AArch64_FPR8RegClassID, 1, 1, 1, 1 },
  { "FPR16", FPR16, FPR16Bits, 32, sizeof(FPR16Bits), AArch64_FPR16RegClassID, 2, 2, 1, 1 },
  { "FPR32", FPR32, FPR32Bits, 32, sizeof(FPR32Bits), AArch64_FPR32RegClassID, 4, 4, 1, 1 },
  { "GPR32", GPR32, GPR32Bits, 32, sizeof(GPR32Bits), AArch64_GPR32RegClassID, 4, 4, 1, 1 },
  { "GPR32wsp", GPR32wsp, GPR32wspBits, 32, sizeof(GPR32wspBits), AArch64_GPR32wspRegClassID, 4, 4, 1, 1 },
  { "GPR32nowzr", GPR32nowzr, GPR32nowzrBits, 31, sizeof(GPR32nowzrBits), AArch64_GPR32nowzrRegClassID, 4, 4, 1, 1 },
  { "FlagClass", FlagClass, FlagClassBits, 1, sizeof(FlagClassBits), AArch64_FlagClassRegClassID, 4, 4, -1, 0 },
  { "Rwsp", Rwsp, RwspBits, 1, sizeof(RwspBits), AArch64_RwspRegClassID, 4, 4, 1, 1 },
  { "FPR64", FPR64, FPR64Bits, 32, sizeof(FPR64Bits), AArch64_FPR64RegClassID, 8, 8, 1, 1 },
  { "GPR64", GPR64, GPR64Bits, 32, sizeof(GPR64Bits), AArch64_GPR64RegClassID, 8, 8, 1, 1 },
  { "GPR64xsp", GPR64xsp, GPR64xspBits, 32, sizeof(GPR64xspBits), AArch64_GPR64xspRegClassID, 8, 8, 1, 1 },
  { "GPR64noxzr", GPR64noxzr, GPR64noxzrBits, 31, sizeof(GPR64noxzrBits), AArch64_GPR64noxzrRegClassID, 8, 8, 1, 1 },
  { "tcGPR64", tcGPR64, tcGPR64Bits, 18, sizeof(tcGPR64Bits), AArch64_tcGPR64RegClassID, 8, 8, 1, 1 },
  { "FPR64Lo", FPR64Lo, FPR64LoBits, 16, sizeof(FPR64LoBits), AArch64_FPR64LoRegClassID, 8, 8, 1, 1 },
  { "Rxsp", Rxsp, RxspBits, 1, sizeof(RxspBits), AArch64_RxspRegClassID, 8, 8, 1, 1 },
  { "DPair", DPair, DPairBits, 32, sizeof(DPairBits), AArch64_DPairRegClassID, 16, 8, 1, 1 },
  { "DPair_with_dsub_0_in_FPR64Lo", DPair_with_dsub_0_in_FPR64Lo, DPair_with_dsub_0_in_FPR64LoBits, 16, sizeof(DPair_with_dsub_0_in_FPR64LoBits), AArch64_DPair_with_dsub_0_in_FPR64LoRegClassID, 16, 8, 1, 1 },
  { "DPair_with_dsub_1_in_FPR64Lo", DPair_with_dsub_1_in_FPR64Lo, DPair_with_dsub_1_in_FPR64LoBits, 16, sizeof(DPair_with_dsub_1_in_FPR64LoBits), AArch64_DPair_with_dsub_1_in_FPR64LoRegClassID, 16, 8, 1, 1 },
  { "DPair_with_dsub_0_in_FPR64Lo_and_DPair_with_dsub_1_in_FPR64Lo", DPair_with_dsub_0_in_FPR64Lo_and_DPair_with_dsub_1_in_FPR64Lo, DPair_with_dsub_0_in_FPR64Lo_and_DPair_with_dsub_1_in_FPR64LoBits, 15, sizeof(DPair_with_dsub_0_in_FPR64Lo_and_DPair_with_dsub_1_in_FPR64LoBits), AArch64_DPair_with_dsub_0_in_FPR64Lo_and_DPair_with_dsub_1_in_FPR64LoRegClassID, 16, 8, 1, 1 },
  { "FPR128", FPR128, FPR128Bits, 32, sizeof(FPR128Bits), AArch64_FPR128RegClassID, 16, 16, 1, 1 },
  { "FPR128Lo", FPR128Lo, FPR128LoBits, 16, sizeof(FPR128LoBits), AArch64_FPR128LoRegClassID, 16, 16, 1, 1 },
  { "DTriple", DTriple, DTripleBits, 32, sizeof(DTripleBits), AArch64_DTripleRegClassID, 24, 8, 1, 1 },
  { "DTriple_with_dsub_0_in_FPR64Lo", DTriple_with_dsub_0_in_FPR64Lo, DTriple_with_dsub_0_in_FPR64LoBits, 16, sizeof(DTriple_with_dsub_0_in_FPR64LoBits), AArch64_DTriple_with_dsub_0_in_FPR64LoRegClassID, 24, 8, 1, 1 },
  { "DTriple_with_dsub_1_in_FPR64Lo", DTriple_with_dsub_1_in_FPR64Lo, DTriple_with_dsub_1_in_FPR64LoBits, 16, sizeof(DTriple_with_dsub_1_in_FPR64LoBits), AArch64_DTriple_with_dsub_1_in_FPR64LoRegClassID, 24, 8, 1, 1 },
  { "DTriple_with_dsub_2_in_FPR64Lo", DTriple_with_dsub_2_in_FPR64Lo, DTriple_with_dsub_2_in_FPR64LoBits, 16, sizeof(DTriple_with_dsub_2_in_FPR64LoBits), AArch64_DTriple_with_dsub_2_in_FPR64LoRegClassID, 24, 8, 1, 1 },
  { "DTriple_with_dsub_0_in_FPR64Lo_and_DTriple_with_dsub_1_in_FPR64Lo", DTriple_with_dsub_0_in_FPR64Lo_and_DTriple_with_dsub_1_in_FPR64Lo, DTriple_with_dsub_0_in_FPR64Lo_and_DTriple_with_dsub_1_in_FPR64LoBits, 15, sizeof(DTriple_with_dsub_0_in_FPR64Lo_and_DTriple_with_dsub_1_in_FPR64LoBits), AArch64_DTriple_with_dsub_0_in_FPR64Lo_and_DTriple_with_dsub_1_in_FPR64LoRegClassID, 24, 8, 1, 1 },
  { "DTriple_with_dsub_1_in_FPR64Lo_and_DTriple_with_dsub_2_in_FPR64Lo", DTriple_with_dsub_1_in_FPR64Lo_and_DTriple_with_dsub_2_in_FPR64Lo, DTriple_with_dsub_1_in_FPR64Lo_and_DTriple_with_dsub_2_in_FPR64LoBits, 15, sizeof(DTriple_with_dsub_1_in_FPR64Lo_and_DTriple_with_dsub_2_in_FPR64LoBits), AArch64_DTriple_with_dsub_1_in_FPR64Lo_and_DTriple_with_dsub_2_in_FPR64LoRegClassID, 24, 8, 1, 1 },
  { "DTriple_with_dsub_0_in_FPR64Lo_and_DTriple_with_dsub_2_in_FPR64Lo", DTriple_with_dsub_0_in_FPR64Lo_and_DTriple_with_dsub_2_in_FPR64Lo, DTriple_with_dsub_0_in_FPR64Lo_and_DTriple_with_dsub_2_in_FPR64LoBits, 14, sizeof(DTriple_with_dsub_0_in_FPR64Lo_and_DTriple_with_dsub_2_in_FPR64LoBits), AArch64_DTriple_with_dsub_0_in_FPR64Lo_and_DTriple_with_dsub_2_in_FPR64LoRegClassID, 24, 8, 1, 1 },
  { "DQuad", DQuad, DQuadBits, 32, sizeof(DQuadBits), AArch64_DQuadRegClassID, 32, 8, 1, 1 },
  { "DQuad_with_dsub_0_in_FPR64Lo", DQuad_with_dsub_0_in_FPR64Lo, DQuad_with_dsub_0_in_FPR64LoBits, 16, sizeof(DQuad_with_dsub_0_in_FPR64LoBits), AArch64_DQuad_with_dsub_0_in_FPR64LoRegClassID, 32, 8, 1, 1 },
  { "DQuad_with_dsub_1_in_FPR64Lo", DQuad_with_dsub_1_in_FPR64Lo, DQuad_with_dsub_1_in_FPR64LoBits, 16, sizeof(DQuad_with_dsub_1_in_FPR64LoBits), AArch64_DQuad_with_dsub_1_in_FPR64LoRegClassID, 32, 8, 1, 1 },
  { "DQuad_with_dsub_2_in_FPR64Lo", DQuad_with_dsub_2_in_FPR64Lo, DQuad_with_dsub_2_in_FPR64LoBits, 16, sizeof(DQuad_with_dsub_2_in_FPR64LoBits), AArch64_DQuad_with_dsub_2_in_FPR64LoRegClassID, 32, 8, 1, 1 },
  { "DQuad_with_dsub_3_in_FPR64Lo", DQuad_with_dsub_3_in_FPR64Lo, DQuad_with_dsub_3_in_FPR64LoBits, 16, sizeof(DQuad_with_dsub_3_in_FPR64LoBits), AArch64_DQuad_with_dsub_3_in_FPR64LoRegClassID, 32, 8, 1, 1 },
  { "DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_1_in_FPR64Lo", DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_1_in_FPR64Lo, DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_1_in_FPR64LoBits, 15, sizeof(DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_1_in_FPR64LoBits), AArch64_DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_1_in_FPR64LoRegClassID, 32, 8, 1, 1 },
  { "DQuad_with_dsub_1_in_FPR64Lo_and_DQuad_with_dsub_2_in_FPR64Lo", DQuad_with_dsub_1_in_FPR64Lo_and_DQuad_with_dsub_2_in_FPR64Lo, DQuad_with_dsub_1_in_FPR64Lo_and_DQuad_with_dsub_2_in_FPR64LoBits, 15, sizeof(DQuad_with_dsub_1_in_FPR64Lo_and_DQuad_with_dsub_2_in_FPR64LoBits), AArch64_DQuad_with_dsub_1_in_FPR64Lo_and_DQuad_with_dsub_2_in_FPR64LoRegClassID, 32, 8, 1, 1 },
  { "DQuad_with_dsub_2_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64Lo", DQuad_with_dsub_2_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64Lo, DQuad_with_dsub_2_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64LoBits, 15, sizeof(DQuad_with_dsub_2_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64LoBits), AArch64_DQuad_with_dsub_2_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64LoRegClassID, 32, 8, 1, 1 },
  { "DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_2_in_FPR64Lo", DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_2_in_FPR64Lo, DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_2_in_FPR64LoBits, 14, sizeof(DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_2_in_FPR64LoBits), AArch64_DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_2_in_FPR64LoRegClassID, 32, 8, 1, 1 },
  { "DQuad_with_dsub_1_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64Lo", DQuad_with_dsub_1_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64Lo, DQuad_with_dsub_1_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64LoBits, 14, sizeof(DQuad_with_dsub_1_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64LoBits), AArch64_DQuad_with_dsub_1_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64LoRegClassID, 32, 8, 1, 1 },
  { "DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64Lo", DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64Lo, DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64LoBits, 13, sizeof(DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64LoBits), AArch64_DQuad_with_dsub_0_in_FPR64Lo_and_DQuad_with_dsub_3_in_FPR64LoRegClassID, 32, 8, 1, 1 },
  { "QPair", QPair, QPairBits, 32, sizeof(QPairBits), AArch64_QPairRegClassID, 32, 16, 1, 1 },
  { "QPair_with_qsub_0_in_FPR128Lo", QPair_with_qsub_0_in_FPR128Lo, QPair_with_qsub_0_in_FPR128LoBits, 16, sizeof(QPair_with_qsub_0_in_FPR128LoBits), AArch64_QPair_with_qsub_0_in_FPR128LoRegClassID, 32, 16, 1, 1 },
  { "QPair_with_qsub_1_in_FPR128Lo", QPair_with_qsub_1_in_FPR128Lo, QPair_with_qsub_1_in_FPR128LoBits, 16, sizeof(QPair_with_qsub_1_in_FPR128LoBits), AArch64_QPair_with_qsub_1_in_FPR128LoRegClassID, 32, 16, 1, 1 },
  { "QPair_with_qsub_0_in_FPR128Lo_and_QPair_with_qsub_1_in_FPR128Lo", QPair_with_qsub_0_in_FPR128Lo_and_QPair_with_qsub_1_in_FPR128Lo, QPair_with_qsub_0_in_FPR128Lo_and_QPair_with_qsub_1_in_FPR128LoBits, 15, sizeof(QPair_with_qsub_0_in_FPR128Lo_and_QPair_with_qsub_1_in_FPR128LoBits), AArch64_QPair_with_qsub_0_in_FPR128Lo_and_QPair_with_qsub_1_in_FPR128LoRegClassID, 32, 16, 1, 1 },
  { "QTriple", QTriple, QTripleBits, 32, sizeof(QTripleBits), AArch64_QTripleRegClassID, 48, 16, 1, 1 },
  { "QTriple_with_qsub_0_in_FPR128Lo", QTriple_with_qsub_0_in_FPR128Lo, QTriple_with_qsub_0_in_FPR128LoBits, 16, sizeof(QTriple_with_qsub_0_in_FPR128LoBits), AArch64_QTriple_with_qsub_0_in_FPR128LoRegClassID, 48, 16, 1, 1 },
  { "QTriple_with_qsub_1_in_FPR128Lo", QTriple_with_qsub_1_in_FPR128Lo, QTriple_with_qsub_1_in_FPR128LoBits, 16, sizeof(QTriple_with_qsub_1_in_FPR128LoBits), AArch64_QTriple_with_qsub_1_in_FPR128LoRegClassID, 48, 16, 1, 1 },
  { "QTriple_with_qsub_2_in_FPR128Lo", QTriple_with_qsub_2_in_FPR128Lo, QTriple_with_qsub_2_in_FPR128LoBits, 16, sizeof(QTriple_with_qsub_2_in_FPR128LoBits), AArch64_QTriple_with_qsub_2_in_FPR128LoRegClassID, 48, 16, 1, 1 },
  { "QTriple_with_qsub_0_in_FPR128Lo_and_QTriple_with_qsub_1_in_FPR128Lo", QTriple_with_qsub_0_in_FPR128Lo_and_QTriple_with_qsub_1_in_FPR128Lo, QTriple_with_qsub_0_in_FPR128Lo_and_QTriple_with_qsub_1_in_FPR128LoBits, 15, sizeof(QTriple_with_qsub_0_in_FPR128Lo_and_QTriple_with_qsub_1_in_FPR128LoBits), AArch64_QTriple_with_qsub_0_in_FPR128Lo_and_QTriple_with_qsub_1_in_FPR128LoRegClassID, 48, 16, 1, 1 },
  { "QTriple_with_qsub_1_in_FPR128Lo_and_QTriple_with_qsub_2_in_FPR128Lo", QTriple_with_qsub_1_in_FPR128Lo_and_QTriple_with_qsub_2_in_FPR128Lo, QTriple_with_qsub_1_in_FPR128Lo_and_QTriple_with_qsub_2_in_FPR128LoBits, 15, sizeof(QTriple_with_qsub_1_in_FPR128Lo_and_QTriple_with_qsub_2_in_FPR128LoBits), AArch64_QTriple_with_qsub_1_in_FPR128Lo_and_QTriple_with_qsub_2_in_FPR128LoRegClassID, 48, 16, 1, 1 },
  { "QTriple_with_qsub_0_in_FPR128Lo_and_QTriple_with_qsub_2_in_FPR128Lo", QTriple_with_qsub_0_in_FPR128Lo_and_QTriple_with_qsub_2_in_FPR128Lo, QTriple_with_qsub_0_in_FPR128Lo_and_QTriple_with_qsub_2_in_FPR128LoBits, 14, sizeof(QTriple_with_qsub_0_in_FPR128Lo_and_QTriple_with_qsub_2_in_FPR128LoBits), AArch64_QTriple_with_qsub_0_in_FPR128Lo_and_QTriple_with_qsub_2_in_FPR128LoRegClassID, 48, 16, 1, 1 },
  { "QQuad", QQuad, QQuadBits, 32, sizeof(QQuadBits), AArch64_QQuadRegClassID, 64, 16, 1, 1 },
  { "QQuad_with_qsub_0_in_FPR128Lo", QQuad_with_qsub_0_in_FPR128Lo, QQuad_with_qsub_0_in_FPR128LoBits, 16, sizeof(QQuad_with_qsub_0_in_FPR128LoBits), AArch64_QQuad_with_qsub_0_in_FPR128LoRegClassID, 64, 16, 1, 1 },
  { "QQuad_with_qsub_1_in_FPR128Lo", QQuad_with_qsub_1_in_FPR128Lo, QQuad_with_qsub_1_in_FPR128LoBits, 16, sizeof(QQuad_with_qsub_1_in_FPR128LoBits), AArch64_QQuad_with_qsub_1_in_FPR128LoRegClassID, 64, 16, 1, 1 },
  { "QQuad_with_qsub_2_in_FPR128Lo", QQuad_with_qsub_2_in_FPR128Lo, QQuad_with_qsub_2_in_FPR128LoBits, 16, sizeof(QQuad_with_qsub_2_in_FPR128LoBits), AArch64_QQuad_with_qsub_2_in_FPR128LoRegClassID, 64, 16, 1, 1 },
  { "QQuad_with_qsub_3_in_FPR128Lo", QQuad_with_qsub_3_in_FPR128Lo, QQuad_with_qsub_3_in_FPR128LoBits, 16, sizeof(QQuad_with_qsub_3_in_FPR128LoBits), AArch64_QQuad_with_qsub_3_in_FPR128LoRegClassID, 64, 16, 1, 1 },
  { "QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_1_in_FPR128Lo", QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_1_in_FPR128Lo, QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_1_in_FPR128LoBits, 15, sizeof(QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_1_in_FPR128LoBits), AArch64_QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_1_in_FPR128LoRegClassID, 64, 16, 1, 1 },
  { "QQuad_with_qsub_1_in_FPR128Lo_and_QQuad_with_qsub_2_in_FPR128Lo", QQuad_with_qsub_1_in_FPR128Lo_and_QQuad_with_qsub_2_in_FPR128Lo, QQuad_with_qsub_1_in_FPR128Lo_and_QQuad_with_qsub_2_in_FPR128LoBits, 15, sizeof(QQuad_with_qsub_1_in_FPR128Lo_and_QQuad_with_qsub_2_in_FPR128LoBits), AArch64_QQuad_with_qsub_1_in_FPR128Lo_and_QQuad_with_qsub_2_in_FPR128LoRegClassID, 64, 16, 1, 1 },
  { "QQuad_with_qsub_2_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128Lo", QQuad_with_qsub_2_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128Lo, QQuad_with_qsub_2_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128LoBits, 15, sizeof(QQuad_with_qsub_2_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128LoBits), AArch64_QQuad_with_qsub_2_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128LoRegClassID, 64, 16, 1, 1 },
  { "QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_2_in_FPR128Lo", QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_2_in_FPR128Lo, QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_2_in_FPR128LoBits, 14, sizeof(QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_2_in_FPR128LoBits), AArch64_QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_2_in_FPR128LoRegClassID, 64, 16, 1, 1 },
  { "QQuad_with_qsub_1_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128Lo", QQuad_with_qsub_1_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128Lo, QQuad_with_qsub_1_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128LoBits, 14, sizeof(QQuad_with_qsub_1_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128LoBits), AArch64_QQuad_with_qsub_1_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128LoRegClassID, 64, 16, 1, 1 },
  { "QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128Lo", QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128Lo, QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128LoBits, 13, sizeof(QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128LoBits), AArch64_QQuad_with_qsub_0_in_FPR128Lo_and_QQuad_with_qsub_3_in_FPR128LoRegClassID, 64, 16, 1, 1 },
};

#endif // GET_REGINFO_MC_DESC

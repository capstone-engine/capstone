/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/*    Rot127 <unisono@quyllur.org> 2022-2023 */
/* Automatically generated file by Capstone's LLVM TableGen Disassembler Backend. */

/* LLVM-commit: <commit> */
/* LLVM-tag: <tag> */

/* Do not edit. */

/* Capstone's LLVM TableGen Backends: */
/* https://github.com/capstone-engine/llvm-capstone */

#ifdef GET_REGINFO_ENUM
#undef GET_REGINFO_ENUM

enum {
  AArch64_NoRegister,
  AArch64_FFR = 1,
  AArch64_FP = 2,
  AArch64_FPCR = 3,
  AArch64_LR = 4,
  AArch64_NZCV = 5,
  AArch64_SP = 6,
  AArch64_VG = 7,
  AArch64_WSP = 8,
  AArch64_WZR = 9,
  AArch64_XZR = 10,
  AArch64_ZA = 11,
  AArch64_B0 = 12,
  AArch64_B1 = 13,
  AArch64_B2 = 14,
  AArch64_B3 = 15,
  AArch64_B4 = 16,
  AArch64_B5 = 17,
  AArch64_B6 = 18,
  AArch64_B7 = 19,
  AArch64_B8 = 20,
  AArch64_B9 = 21,
  AArch64_B10 = 22,
  AArch64_B11 = 23,
  AArch64_B12 = 24,
  AArch64_B13 = 25,
  AArch64_B14 = 26,
  AArch64_B15 = 27,
  AArch64_B16 = 28,
  AArch64_B17 = 29,
  AArch64_B18 = 30,
  AArch64_B19 = 31,
  AArch64_B20 = 32,
  AArch64_B21 = 33,
  AArch64_B22 = 34,
  AArch64_B23 = 35,
  AArch64_B24 = 36,
  AArch64_B25 = 37,
  AArch64_B26 = 38,
  AArch64_B27 = 39,
  AArch64_B28 = 40,
  AArch64_B29 = 41,
  AArch64_B30 = 42,
  AArch64_B31 = 43,
  AArch64_D0 = 44,
  AArch64_D1 = 45,
  AArch64_D2 = 46,
  AArch64_D3 = 47,
  AArch64_D4 = 48,
  AArch64_D5 = 49,
  AArch64_D6 = 50,
  AArch64_D7 = 51,
  AArch64_D8 = 52,
  AArch64_D9 = 53,
  AArch64_D10 = 54,
  AArch64_D11 = 55,
  AArch64_D12 = 56,
  AArch64_D13 = 57,
  AArch64_D14 = 58,
  AArch64_D15 = 59,
  AArch64_D16 = 60,
  AArch64_D17 = 61,
  AArch64_D18 = 62,
  AArch64_D19 = 63,
  AArch64_D20 = 64,
  AArch64_D21 = 65,
  AArch64_D22 = 66,
  AArch64_D23 = 67,
  AArch64_D24 = 68,
  AArch64_D25 = 69,
  AArch64_D26 = 70,
  AArch64_D27 = 71,
  AArch64_D28 = 72,
  AArch64_D29 = 73,
  AArch64_D30 = 74,
  AArch64_D31 = 75,
  AArch64_H0 = 76,
  AArch64_H1 = 77,
  AArch64_H2 = 78,
  AArch64_H3 = 79,
  AArch64_H4 = 80,
  AArch64_H5 = 81,
  AArch64_H6 = 82,
  AArch64_H7 = 83,
  AArch64_H8 = 84,
  AArch64_H9 = 85,
  AArch64_H10 = 86,
  AArch64_H11 = 87,
  AArch64_H12 = 88,
  AArch64_H13 = 89,
  AArch64_H14 = 90,
  AArch64_H15 = 91,
  AArch64_H16 = 92,
  AArch64_H17 = 93,
  AArch64_H18 = 94,
  AArch64_H19 = 95,
  AArch64_H20 = 96,
  AArch64_H21 = 97,
  AArch64_H22 = 98,
  AArch64_H23 = 99,
  AArch64_H24 = 100,
  AArch64_H25 = 101,
  AArch64_H26 = 102,
  AArch64_H27 = 103,
  AArch64_H28 = 104,
  AArch64_H29 = 105,
  AArch64_H30 = 106,
  AArch64_H31 = 107,
  AArch64_P0 = 108,
  AArch64_P1 = 109,
  AArch64_P2 = 110,
  AArch64_P3 = 111,
  AArch64_P4 = 112,
  AArch64_P5 = 113,
  AArch64_P6 = 114,
  AArch64_P7 = 115,
  AArch64_P8 = 116,
  AArch64_P9 = 117,
  AArch64_P10 = 118,
  AArch64_P11 = 119,
  AArch64_P12 = 120,
  AArch64_P13 = 121,
  AArch64_P14 = 122,
  AArch64_P15 = 123,
  AArch64_Q0 = 124,
  AArch64_Q1 = 125,
  AArch64_Q2 = 126,
  AArch64_Q3 = 127,
  AArch64_Q4 = 128,
  AArch64_Q5 = 129,
  AArch64_Q6 = 130,
  AArch64_Q7 = 131,
  AArch64_Q8 = 132,
  AArch64_Q9 = 133,
  AArch64_Q10 = 134,
  AArch64_Q11 = 135,
  AArch64_Q12 = 136,
  AArch64_Q13 = 137,
  AArch64_Q14 = 138,
  AArch64_Q15 = 139,
  AArch64_Q16 = 140,
  AArch64_Q17 = 141,
  AArch64_Q18 = 142,
  AArch64_Q19 = 143,
  AArch64_Q20 = 144,
  AArch64_Q21 = 145,
  AArch64_Q22 = 146,
  AArch64_Q23 = 147,
  AArch64_Q24 = 148,
  AArch64_Q25 = 149,
  AArch64_Q26 = 150,
  AArch64_Q27 = 151,
  AArch64_Q28 = 152,
  AArch64_Q29 = 153,
  AArch64_Q30 = 154,
  AArch64_Q31 = 155,
  AArch64_S0 = 156,
  AArch64_S1 = 157,
  AArch64_S2 = 158,
  AArch64_S3 = 159,
  AArch64_S4 = 160,
  AArch64_S5 = 161,
  AArch64_S6 = 162,
  AArch64_S7 = 163,
  AArch64_S8 = 164,
  AArch64_S9 = 165,
  AArch64_S10 = 166,
  AArch64_S11 = 167,
  AArch64_S12 = 168,
  AArch64_S13 = 169,
  AArch64_S14 = 170,
  AArch64_S15 = 171,
  AArch64_S16 = 172,
  AArch64_S17 = 173,
  AArch64_S18 = 174,
  AArch64_S19 = 175,
  AArch64_S20 = 176,
  AArch64_S21 = 177,
  AArch64_S22 = 178,
  AArch64_S23 = 179,
  AArch64_S24 = 180,
  AArch64_S25 = 181,
  AArch64_S26 = 182,
  AArch64_S27 = 183,
  AArch64_S28 = 184,
  AArch64_S29 = 185,
  AArch64_S30 = 186,
  AArch64_S31 = 187,
  AArch64_W0 = 188,
  AArch64_W1 = 189,
  AArch64_W2 = 190,
  AArch64_W3 = 191,
  AArch64_W4 = 192,
  AArch64_W5 = 193,
  AArch64_W6 = 194,
  AArch64_W7 = 195,
  AArch64_W8 = 196,
  AArch64_W9 = 197,
  AArch64_W10 = 198,
  AArch64_W11 = 199,
  AArch64_W12 = 200,
  AArch64_W13 = 201,
  AArch64_W14 = 202,
  AArch64_W15 = 203,
  AArch64_W16 = 204,
  AArch64_W17 = 205,
  AArch64_W18 = 206,
  AArch64_W19 = 207,
  AArch64_W20 = 208,
  AArch64_W21 = 209,
  AArch64_W22 = 210,
  AArch64_W23 = 211,
  AArch64_W24 = 212,
  AArch64_W25 = 213,
  AArch64_W26 = 214,
  AArch64_W27 = 215,
  AArch64_W28 = 216,
  AArch64_W29 = 217,
  AArch64_W30 = 218,
  AArch64_X0 = 219,
  AArch64_X1 = 220,
  AArch64_X2 = 221,
  AArch64_X3 = 222,
  AArch64_X4 = 223,
  AArch64_X5 = 224,
  AArch64_X6 = 225,
  AArch64_X7 = 226,
  AArch64_X8 = 227,
  AArch64_X9 = 228,
  AArch64_X10 = 229,
  AArch64_X11 = 230,
  AArch64_X12 = 231,
  AArch64_X13 = 232,
  AArch64_X14 = 233,
  AArch64_X15 = 234,
  AArch64_X16 = 235,
  AArch64_X17 = 236,
  AArch64_X18 = 237,
  AArch64_X19 = 238,
  AArch64_X20 = 239,
  AArch64_X21 = 240,
  AArch64_X22 = 241,
  AArch64_X23 = 242,
  AArch64_X24 = 243,
  AArch64_X25 = 244,
  AArch64_X26 = 245,
  AArch64_X27 = 246,
  AArch64_X28 = 247,
  AArch64_Z0 = 248,
  AArch64_Z1 = 249,
  AArch64_Z2 = 250,
  AArch64_Z3 = 251,
  AArch64_Z4 = 252,
  AArch64_Z5 = 253,
  AArch64_Z6 = 254,
  AArch64_Z7 = 255,
  AArch64_Z8 = 256,
  AArch64_Z9 = 257,
  AArch64_Z10 = 258,
  AArch64_Z11 = 259,
  AArch64_Z12 = 260,
  AArch64_Z13 = 261,
  AArch64_Z14 = 262,
  AArch64_Z15 = 263,
  AArch64_Z16 = 264,
  AArch64_Z17 = 265,
  AArch64_Z18 = 266,
  AArch64_Z19 = 267,
  AArch64_Z20 = 268,
  AArch64_Z21 = 269,
  AArch64_Z22 = 270,
  AArch64_Z23 = 271,
  AArch64_Z24 = 272,
  AArch64_Z25 = 273,
  AArch64_Z26 = 274,
  AArch64_Z27 = 275,
  AArch64_Z28 = 276,
  AArch64_Z29 = 277,
  AArch64_Z30 = 278,
  AArch64_Z31 = 279,
  AArch64_ZAB0 = 280,
  AArch64_ZAD0 = 281,
  AArch64_ZAD1 = 282,
  AArch64_ZAD2 = 283,
  AArch64_ZAD3 = 284,
  AArch64_ZAD4 = 285,
  AArch64_ZAD5 = 286,
  AArch64_ZAD6 = 287,
  AArch64_ZAD7 = 288,
  AArch64_ZAH0 = 289,
  AArch64_ZAH1 = 290,
  AArch64_ZAQ0 = 291,
  AArch64_ZAQ1 = 292,
  AArch64_ZAQ2 = 293,
  AArch64_ZAQ3 = 294,
  AArch64_ZAQ4 = 295,
  AArch64_ZAQ5 = 296,
  AArch64_ZAQ6 = 297,
  AArch64_ZAQ7 = 298,
  AArch64_ZAQ8 = 299,
  AArch64_ZAQ9 = 300,
  AArch64_ZAQ10 = 301,
  AArch64_ZAQ11 = 302,
  AArch64_ZAQ12 = 303,
  AArch64_ZAQ13 = 304,
  AArch64_ZAQ14 = 305,
  AArch64_ZAQ15 = 306,
  AArch64_ZAS0 = 307,
  AArch64_ZAS1 = 308,
  AArch64_ZAS2 = 309,
  AArch64_ZAS3 = 310,
  AArch64_ZT0 = 311,
  AArch64_Z0_HI = 312,
  AArch64_Z1_HI = 313,
  AArch64_Z2_HI = 314,
  AArch64_Z3_HI = 315,
  AArch64_Z4_HI = 316,
  AArch64_Z5_HI = 317,
  AArch64_Z6_HI = 318,
  AArch64_Z7_HI = 319,
  AArch64_Z8_HI = 320,
  AArch64_Z9_HI = 321,
  AArch64_Z10_HI = 322,
  AArch64_Z11_HI = 323,
  AArch64_Z12_HI = 324,
  AArch64_Z13_HI = 325,
  AArch64_Z14_HI = 326,
  AArch64_Z15_HI = 327,
  AArch64_Z16_HI = 328,
  AArch64_Z17_HI = 329,
  AArch64_Z18_HI = 330,
  AArch64_Z19_HI = 331,
  AArch64_Z20_HI = 332,
  AArch64_Z21_HI = 333,
  AArch64_Z22_HI = 334,
  AArch64_Z23_HI = 335,
  AArch64_Z24_HI = 336,
  AArch64_Z25_HI = 337,
  AArch64_Z26_HI = 338,
  AArch64_Z27_HI = 339,
  AArch64_Z28_HI = 340,
  AArch64_Z29_HI = 341,
  AArch64_Z30_HI = 342,
  AArch64_Z31_HI = 343,
  AArch64_D0_D1 = 344,
  AArch64_D1_D2 = 345,
  AArch64_D2_D3 = 346,
  AArch64_D3_D4 = 347,
  AArch64_D4_D5 = 348,
  AArch64_D5_D6 = 349,
  AArch64_D6_D7 = 350,
  AArch64_D7_D8 = 351,
  AArch64_D8_D9 = 352,
  AArch64_D9_D10 = 353,
  AArch64_D10_D11 = 354,
  AArch64_D11_D12 = 355,
  AArch64_D12_D13 = 356,
  AArch64_D13_D14 = 357,
  AArch64_D14_D15 = 358,
  AArch64_D15_D16 = 359,
  AArch64_D16_D17 = 360,
  AArch64_D17_D18 = 361,
  AArch64_D18_D19 = 362,
  AArch64_D19_D20 = 363,
  AArch64_D20_D21 = 364,
  AArch64_D21_D22 = 365,
  AArch64_D22_D23 = 366,
  AArch64_D23_D24 = 367,
  AArch64_D24_D25 = 368,
  AArch64_D25_D26 = 369,
  AArch64_D26_D27 = 370,
  AArch64_D27_D28 = 371,
  AArch64_D28_D29 = 372,
  AArch64_D29_D30 = 373,
  AArch64_D30_D31 = 374,
  AArch64_D31_D0 = 375,
  AArch64_D0_D1_D2_D3 = 376,
  AArch64_D1_D2_D3_D4 = 377,
  AArch64_D2_D3_D4_D5 = 378,
  AArch64_D3_D4_D5_D6 = 379,
  AArch64_D4_D5_D6_D7 = 380,
  AArch64_D5_D6_D7_D8 = 381,
  AArch64_D6_D7_D8_D9 = 382,
  AArch64_D7_D8_D9_D10 = 383,
  AArch64_D8_D9_D10_D11 = 384,
  AArch64_D9_D10_D11_D12 = 385,
  AArch64_D10_D11_D12_D13 = 386,
  AArch64_D11_D12_D13_D14 = 387,
  AArch64_D12_D13_D14_D15 = 388,
  AArch64_D13_D14_D15_D16 = 389,
  AArch64_D14_D15_D16_D17 = 390,
  AArch64_D15_D16_D17_D18 = 391,
  AArch64_D16_D17_D18_D19 = 392,
  AArch64_D17_D18_D19_D20 = 393,
  AArch64_D18_D19_D20_D21 = 394,
  AArch64_D19_D20_D21_D22 = 395,
  AArch64_D20_D21_D22_D23 = 396,
  AArch64_D21_D22_D23_D24 = 397,
  AArch64_D22_D23_D24_D25 = 398,
  AArch64_D23_D24_D25_D26 = 399,
  AArch64_D24_D25_D26_D27 = 400,
  AArch64_D25_D26_D27_D28 = 401,
  AArch64_D26_D27_D28_D29 = 402,
  AArch64_D27_D28_D29_D30 = 403,
  AArch64_D28_D29_D30_D31 = 404,
  AArch64_D29_D30_D31_D0 = 405,
  AArch64_D30_D31_D0_D1 = 406,
  AArch64_D31_D0_D1_D2 = 407,
  AArch64_D0_D1_D2 = 408,
  AArch64_D1_D2_D3 = 409,
  AArch64_D2_D3_D4 = 410,
  AArch64_D3_D4_D5 = 411,
  AArch64_D4_D5_D6 = 412,
  AArch64_D5_D6_D7 = 413,
  AArch64_D6_D7_D8 = 414,
  AArch64_D7_D8_D9 = 415,
  AArch64_D8_D9_D10 = 416,
  AArch64_D9_D10_D11 = 417,
  AArch64_D10_D11_D12 = 418,
  AArch64_D11_D12_D13 = 419,
  AArch64_D12_D13_D14 = 420,
  AArch64_D13_D14_D15 = 421,
  AArch64_D14_D15_D16 = 422,
  AArch64_D15_D16_D17 = 423,
  AArch64_D16_D17_D18 = 424,
  AArch64_D17_D18_D19 = 425,
  AArch64_D18_D19_D20 = 426,
  AArch64_D19_D20_D21 = 427,
  AArch64_D20_D21_D22 = 428,
  AArch64_D21_D22_D23 = 429,
  AArch64_D22_D23_D24 = 430,
  AArch64_D23_D24_D25 = 431,
  AArch64_D24_D25_D26 = 432,
  AArch64_D25_D26_D27 = 433,
  AArch64_D26_D27_D28 = 434,
  AArch64_D27_D28_D29 = 435,
  AArch64_D28_D29_D30 = 436,
  AArch64_D29_D30_D31 = 437,
  AArch64_D30_D31_D0 = 438,
  AArch64_D31_D0_D1 = 439,
  AArch64_P0_P1 = 440,
  AArch64_P1_P2 = 441,
  AArch64_P2_P3 = 442,
  AArch64_P3_P4 = 443,
  AArch64_P4_P5 = 444,
  AArch64_P5_P6 = 445,
  AArch64_P6_P7 = 446,
  AArch64_P7_P8 = 447,
  AArch64_P8_P9 = 448,
  AArch64_P9_P10 = 449,
  AArch64_P10_P11 = 450,
  AArch64_P11_P12 = 451,
  AArch64_P12_P13 = 452,
  AArch64_P13_P14 = 453,
  AArch64_P14_P15 = 454,
  AArch64_P15_P0 = 455,
  AArch64_Q0_Q1 = 456,
  AArch64_Q1_Q2 = 457,
  AArch64_Q2_Q3 = 458,
  AArch64_Q3_Q4 = 459,
  AArch64_Q4_Q5 = 460,
  AArch64_Q5_Q6 = 461,
  AArch64_Q6_Q7 = 462,
  AArch64_Q7_Q8 = 463,
  AArch64_Q8_Q9 = 464,
  AArch64_Q9_Q10 = 465,
  AArch64_Q10_Q11 = 466,
  AArch64_Q11_Q12 = 467,
  AArch64_Q12_Q13 = 468,
  AArch64_Q13_Q14 = 469,
  AArch64_Q14_Q15 = 470,
  AArch64_Q15_Q16 = 471,
  AArch64_Q16_Q17 = 472,
  AArch64_Q17_Q18 = 473,
  AArch64_Q18_Q19 = 474,
  AArch64_Q19_Q20 = 475,
  AArch64_Q20_Q21 = 476,
  AArch64_Q21_Q22 = 477,
  AArch64_Q22_Q23 = 478,
  AArch64_Q23_Q24 = 479,
  AArch64_Q24_Q25 = 480,
  AArch64_Q25_Q26 = 481,
  AArch64_Q26_Q27 = 482,
  AArch64_Q27_Q28 = 483,
  AArch64_Q28_Q29 = 484,
  AArch64_Q29_Q30 = 485,
  AArch64_Q30_Q31 = 486,
  AArch64_Q31_Q0 = 487,
  AArch64_Q0_Q1_Q2_Q3 = 488,
  AArch64_Q1_Q2_Q3_Q4 = 489,
  AArch64_Q2_Q3_Q4_Q5 = 490,
  AArch64_Q3_Q4_Q5_Q6 = 491,
  AArch64_Q4_Q5_Q6_Q7 = 492,
  AArch64_Q5_Q6_Q7_Q8 = 493,
  AArch64_Q6_Q7_Q8_Q9 = 494,
  AArch64_Q7_Q8_Q9_Q10 = 495,
  AArch64_Q8_Q9_Q10_Q11 = 496,
  AArch64_Q9_Q10_Q11_Q12 = 497,
  AArch64_Q10_Q11_Q12_Q13 = 498,
  AArch64_Q11_Q12_Q13_Q14 = 499,
  AArch64_Q12_Q13_Q14_Q15 = 500,
  AArch64_Q13_Q14_Q15_Q16 = 501,
  AArch64_Q14_Q15_Q16_Q17 = 502,
  AArch64_Q15_Q16_Q17_Q18 = 503,
  AArch64_Q16_Q17_Q18_Q19 = 504,
  AArch64_Q17_Q18_Q19_Q20 = 505,
  AArch64_Q18_Q19_Q20_Q21 = 506,
  AArch64_Q19_Q20_Q21_Q22 = 507,
  AArch64_Q20_Q21_Q22_Q23 = 508,
  AArch64_Q21_Q22_Q23_Q24 = 509,
  AArch64_Q22_Q23_Q24_Q25 = 510,
  AArch64_Q23_Q24_Q25_Q26 = 511,
  AArch64_Q24_Q25_Q26_Q27 = 512,
  AArch64_Q25_Q26_Q27_Q28 = 513,
  AArch64_Q26_Q27_Q28_Q29 = 514,
  AArch64_Q27_Q28_Q29_Q30 = 515,
  AArch64_Q28_Q29_Q30_Q31 = 516,
  AArch64_Q29_Q30_Q31_Q0 = 517,
  AArch64_Q30_Q31_Q0_Q1 = 518,
  AArch64_Q31_Q0_Q1_Q2 = 519,
  AArch64_Q0_Q1_Q2 = 520,
  AArch64_Q1_Q2_Q3 = 521,
  AArch64_Q2_Q3_Q4 = 522,
  AArch64_Q3_Q4_Q5 = 523,
  AArch64_Q4_Q5_Q6 = 524,
  AArch64_Q5_Q6_Q7 = 525,
  AArch64_Q6_Q7_Q8 = 526,
  AArch64_Q7_Q8_Q9 = 527,
  AArch64_Q8_Q9_Q10 = 528,
  AArch64_Q9_Q10_Q11 = 529,
  AArch64_Q10_Q11_Q12 = 530,
  AArch64_Q11_Q12_Q13 = 531,
  AArch64_Q12_Q13_Q14 = 532,
  AArch64_Q13_Q14_Q15 = 533,
  AArch64_Q14_Q15_Q16 = 534,
  AArch64_Q15_Q16_Q17 = 535,
  AArch64_Q16_Q17_Q18 = 536,
  AArch64_Q17_Q18_Q19 = 537,
  AArch64_Q18_Q19_Q20 = 538,
  AArch64_Q19_Q20_Q21 = 539,
  AArch64_Q20_Q21_Q22 = 540,
  AArch64_Q21_Q22_Q23 = 541,
  AArch64_Q22_Q23_Q24 = 542,
  AArch64_Q23_Q24_Q25 = 543,
  AArch64_Q24_Q25_Q26 = 544,
  AArch64_Q25_Q26_Q27 = 545,
  AArch64_Q26_Q27_Q28 = 546,
  AArch64_Q27_Q28_Q29 = 547,
  AArch64_Q28_Q29_Q30 = 548,
  AArch64_Q29_Q30_Q31 = 549,
  AArch64_Q30_Q31_Q0 = 550,
  AArch64_Q31_Q0_Q1 = 551,
  AArch64_X22_X23_X24_X25_X26_X27_X28_FP = 552,
  AArch64_X0_X1_X2_X3_X4_X5_X6_X7 = 553,
  AArch64_X2_X3_X4_X5_X6_X7_X8_X9 = 554,
  AArch64_X4_X5_X6_X7_X8_X9_X10_X11 = 555,
  AArch64_X6_X7_X8_X9_X10_X11_X12_X13 = 556,
  AArch64_X8_X9_X10_X11_X12_X13_X14_X15 = 557,
  AArch64_X10_X11_X12_X13_X14_X15_X16_X17 = 558,
  AArch64_X12_X13_X14_X15_X16_X17_X18_X19 = 559,
  AArch64_X14_X15_X16_X17_X18_X19_X20_X21 = 560,
  AArch64_X16_X17_X18_X19_X20_X21_X22_X23 = 561,
  AArch64_X18_X19_X20_X21_X22_X23_X24_X25 = 562,
  AArch64_X20_X21_X22_X23_X24_X25_X26_X27 = 563,
  AArch64_W30_WZR = 564,
  AArch64_W0_W1 = 565,
  AArch64_W2_W3 = 566,
  AArch64_W4_W5 = 567,
  AArch64_W6_W7 = 568,
  AArch64_W8_W9 = 569,
  AArch64_W10_W11 = 570,
  AArch64_W12_W13 = 571,
  AArch64_W14_W15 = 572,
  AArch64_W16_W17 = 573,
  AArch64_W18_W19 = 574,
  AArch64_W20_W21 = 575,
  AArch64_W22_W23 = 576,
  AArch64_W24_W25 = 577,
  AArch64_W26_W27 = 578,
  AArch64_W28_W29 = 579,
  AArch64_LR_XZR = 580,
  AArch64_X28_FP = 581,
  AArch64_X0_X1 = 582,
  AArch64_X2_X3 = 583,
  AArch64_X4_X5 = 584,
  AArch64_X6_X7 = 585,
  AArch64_X8_X9 = 586,
  AArch64_X10_X11 = 587,
  AArch64_X12_X13 = 588,
  AArch64_X14_X15 = 589,
  AArch64_X16_X17 = 590,
  AArch64_X18_X19 = 591,
  AArch64_X20_X21 = 592,
  AArch64_X22_X23 = 593,
  AArch64_X24_X25 = 594,
  AArch64_X26_X27 = 595,
  AArch64_Z0_Z1 = 596,
  AArch64_Z1_Z2 = 597,
  AArch64_Z2_Z3 = 598,
  AArch64_Z3_Z4 = 599,
  AArch64_Z4_Z5 = 600,
  AArch64_Z5_Z6 = 601,
  AArch64_Z6_Z7 = 602,
  AArch64_Z7_Z8 = 603,
  AArch64_Z8_Z9 = 604,
  AArch64_Z9_Z10 = 605,
  AArch64_Z10_Z11 = 606,
  AArch64_Z11_Z12 = 607,
  AArch64_Z12_Z13 = 608,
  AArch64_Z13_Z14 = 609,
  AArch64_Z14_Z15 = 610,
  AArch64_Z15_Z16 = 611,
  AArch64_Z16_Z17 = 612,
  AArch64_Z17_Z18 = 613,
  AArch64_Z18_Z19 = 614,
  AArch64_Z19_Z20 = 615,
  AArch64_Z20_Z21 = 616,
  AArch64_Z21_Z22 = 617,
  AArch64_Z22_Z23 = 618,
  AArch64_Z23_Z24 = 619,
  AArch64_Z24_Z25 = 620,
  AArch64_Z25_Z26 = 621,
  AArch64_Z26_Z27 = 622,
  AArch64_Z27_Z28 = 623,
  AArch64_Z28_Z29 = 624,
  AArch64_Z29_Z30 = 625,
  AArch64_Z30_Z31 = 626,
  AArch64_Z31_Z0 = 627,
  AArch64_Z0_Z1_Z2_Z3 = 628,
  AArch64_Z1_Z2_Z3_Z4 = 629,
  AArch64_Z2_Z3_Z4_Z5 = 630,
  AArch64_Z3_Z4_Z5_Z6 = 631,
  AArch64_Z4_Z5_Z6_Z7 = 632,
  AArch64_Z5_Z6_Z7_Z8 = 633,
  AArch64_Z6_Z7_Z8_Z9 = 634,
  AArch64_Z7_Z8_Z9_Z10 = 635,
  AArch64_Z8_Z9_Z10_Z11 = 636,
  AArch64_Z9_Z10_Z11_Z12 = 637,
  AArch64_Z10_Z11_Z12_Z13 = 638,
  AArch64_Z11_Z12_Z13_Z14 = 639,
  AArch64_Z12_Z13_Z14_Z15 = 640,
  AArch64_Z13_Z14_Z15_Z16 = 641,
  AArch64_Z14_Z15_Z16_Z17 = 642,
  AArch64_Z15_Z16_Z17_Z18 = 643,
  AArch64_Z16_Z17_Z18_Z19 = 644,
  AArch64_Z17_Z18_Z19_Z20 = 645,
  AArch64_Z18_Z19_Z20_Z21 = 646,
  AArch64_Z19_Z20_Z21_Z22 = 647,
  AArch64_Z20_Z21_Z22_Z23 = 648,
  AArch64_Z21_Z22_Z23_Z24 = 649,
  AArch64_Z22_Z23_Z24_Z25 = 650,
  AArch64_Z23_Z24_Z25_Z26 = 651,
  AArch64_Z24_Z25_Z26_Z27 = 652,
  AArch64_Z25_Z26_Z27_Z28 = 653,
  AArch64_Z26_Z27_Z28_Z29 = 654,
  AArch64_Z27_Z28_Z29_Z30 = 655,
  AArch64_Z28_Z29_Z30_Z31 = 656,
  AArch64_Z29_Z30_Z31_Z0 = 657,
  AArch64_Z30_Z31_Z0_Z1 = 658,
  AArch64_Z31_Z0_Z1_Z2 = 659,
  AArch64_Z0_Z1_Z2 = 660,
  AArch64_Z1_Z2_Z3 = 661,
  AArch64_Z2_Z3_Z4 = 662,
  AArch64_Z3_Z4_Z5 = 663,
  AArch64_Z4_Z5_Z6 = 664,
  AArch64_Z5_Z6_Z7 = 665,
  AArch64_Z6_Z7_Z8 = 666,
  AArch64_Z7_Z8_Z9 = 667,
  AArch64_Z8_Z9_Z10 = 668,
  AArch64_Z9_Z10_Z11 = 669,
  AArch64_Z10_Z11_Z12 = 670,
  AArch64_Z11_Z12_Z13 = 671,
  AArch64_Z12_Z13_Z14 = 672,
  AArch64_Z13_Z14_Z15 = 673,
  AArch64_Z14_Z15_Z16 = 674,
  AArch64_Z15_Z16_Z17 = 675,
  AArch64_Z16_Z17_Z18 = 676,
  AArch64_Z17_Z18_Z19 = 677,
  AArch64_Z18_Z19_Z20 = 678,
  AArch64_Z19_Z20_Z21 = 679,
  AArch64_Z20_Z21_Z22 = 680,
  AArch64_Z21_Z22_Z23 = 681,
  AArch64_Z22_Z23_Z24 = 682,
  AArch64_Z23_Z24_Z25 = 683,
  AArch64_Z24_Z25_Z26 = 684,
  AArch64_Z25_Z26_Z27 = 685,
  AArch64_Z26_Z27_Z28 = 686,
  AArch64_Z27_Z28_Z29 = 687,
  AArch64_Z28_Z29_Z30 = 688,
  AArch64_Z29_Z30_Z31 = 689,
  AArch64_Z30_Z31_Z0 = 690,
  AArch64_Z31_Z0_Z1 = 691,
  AArch64_Z16_Z24 = 692,
  AArch64_Z17_Z25 = 693,
  AArch64_Z18_Z26 = 694,
  AArch64_Z19_Z27 = 695,
  AArch64_Z20_Z28 = 696,
  AArch64_Z21_Z29 = 697,
  AArch64_Z22_Z30 = 698,
  AArch64_Z23_Z31 = 699,
  AArch64_Z0_Z8 = 700,
  AArch64_Z1_Z9 = 701,
  AArch64_Z2_Z10 = 702,
  AArch64_Z3_Z11 = 703,
  AArch64_Z4_Z12 = 704,
  AArch64_Z5_Z13 = 705,
  AArch64_Z6_Z14 = 706,
  AArch64_Z7_Z15 = 707,
  AArch64_Z16_Z20_Z24_Z28 = 708,
  AArch64_Z17_Z21_Z25_Z29 = 709,
  AArch64_Z18_Z22_Z26_Z30 = 710,
  AArch64_Z19_Z23_Z27_Z31 = 711,
  AArch64_Z0_Z4_Z8_Z12 = 712,
  AArch64_Z1_Z5_Z9_Z13 = 713,
  AArch64_Z2_Z6_Z10_Z14 = 714,
  AArch64_Z3_Z7_Z11_Z15 = 715,
  NUM_TARGET_REGS // 716
};

// Register classes

enum {
  AArch64_FPR8RegClassID = 0,
  AArch64_FPR16RegClassID = 1,
  AArch64_FPR16_loRegClassID = 2,
  AArch64_PPRRegClassID = 3,
  AArch64_PPR_3bRegClassID = 4,
  AArch64_PPR_p8to15RegClassID = 5,
  AArch64_PPR2RegClassID = 6,
  AArch64_PPR2Mul2RegClassID = 7,
  AArch64_PPR2_with_psub0_in_PPR_3bRegClassID = 8,
  AArch64_PPR2_with_psub0_in_PPR_p8to15RegClassID = 9,
  AArch64_PPR2_with_psub1_in_PPR_3bRegClassID = 10,
  AArch64_PPR2_with_psub1_in_PPR_p8to15RegClassID = 11,
  AArch64_PPR2_with_psub0_in_PPR_3b_and_PPR2_with_psub1_in_PPR_3bRegClassID = 12,
  AArch64_PPR2_with_psub0_in_PPR_p8to15_and_PPR2_with_psub1_in_PPR_p8to15RegClassID = 13,
  AArch64_PPR2Mul2_and_PPR2_with_psub0_in_PPR_3bRegClassID = 14,
  AArch64_PPR2Mul2_and_PPR2_with_psub0_in_PPR_p8to15RegClassID = 15,
  AArch64_PPR2_with_psub0_in_PPR_3b_and_PPR2_with_psub1_in_PPR_p8to15RegClassID = 16,
  AArch64_PPR2_with_psub0_in_PPR_p8to15_and_PPR2_with_psub1_in_PPR_3bRegClassID = 17,
  AArch64_GPR32allRegClassID = 18,
  AArch64_FPR32RegClassID = 19,
  AArch64_GPR32RegClassID = 20,
  AArch64_GPR32spRegClassID = 21,
  AArch64_GPR32commonRegClassID = 22,
  AArch64_FPR32_with_hsub_in_FPR16_loRegClassID = 23,
  AArch64_GPR32argRegClassID = 24,
  AArch64_MatrixIndexGPR32_12_15RegClassID = 25,
  AArch64_MatrixIndexGPR32_8_11RegClassID = 26,
  AArch64_CCRRegClassID = 27,
  AArch64_GPR32sponlyRegClassID = 28,
  AArch64_WSeqPairsClassRegClassID = 29,
  AArch64_WSeqPairsClass_with_subo32_in_GPR32commonRegClassID = 30,
  AArch64_WSeqPairsClass_with_sube32_in_GPR32argRegClassID = 31,
  AArch64_WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_12_15RegClassID = 32,
  AArch64_WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_8_11RegClassID = 33,
  AArch64_GPR64allRegClassID = 34,
  AArch64_FPR64RegClassID = 35,
  AArch64_GPR64RegClassID = 36,
  AArch64_GPR64spRegClassID = 37,
  AArch64_GPR64commonRegClassID = 38,
  AArch64_GPR64noipRegClassID = 39,
  AArch64_GPR64common_and_GPR64noipRegClassID = 40,
  AArch64_tcGPR64RegClassID = 41,
  AArch64_GPR64noip_and_tcGPR64RegClassID = 42,
  AArch64_FPR64_loRegClassID = 43,
  AArch64_GPR64argRegClassID = 44,
  AArch64_FIXED_REGSRegClassID = 45,
  AArch64_GPR64_with_sub_32_in_MatrixIndexGPR32_12_15RegClassID = 46,
  AArch64_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11RegClassID = 47,
  AArch64_FIXED_REGS_with_sub_32RegClassID = 48,
  AArch64_rtcGPR64RegClassID = 49,
  AArch64_FIXED_REGS_and_GPR64RegClassID = 50,
  AArch64_GPR64sponlyRegClassID = 51,
  AArch64_DDRegClassID = 52,
  AArch64_DD_with_dsub0_in_FPR64_loRegClassID = 53,
  AArch64_DD_with_dsub1_in_FPR64_loRegClassID = 54,
  AArch64_XSeqPairsClassRegClassID = 55,
  AArch64_DD_with_dsub0_in_FPR64_lo_and_DD_with_dsub1_in_FPR64_loRegClassID = 56,
  AArch64_XSeqPairsClass_with_subo64_in_GPR64commonRegClassID = 57,
  AArch64_XSeqPairsClass_with_subo64_in_GPR64noipRegClassID = 58,
  AArch64_XSeqPairsClass_with_sube64_in_GPR64noipRegClassID = 59,
  AArch64_XSeqPairsClass_with_sube64_in_tcGPR64RegClassID = 60,
  AArch64_XSeqPairsClass_with_sube64_in_GPR64noip_and_tcGPR64RegClassID = 61,
  AArch64_XSeqPairsClass_with_subo64_in_tcGPR64RegClassID = 62,
  AArch64_XSeqPairsClass_with_subo64_in_GPR64noip_and_tcGPR64RegClassID = 63,
  AArch64_XSeqPairsClass_with_sub_32_in_GPR32argRegClassID = 64,
  AArch64_XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_12_15RegClassID = 65,
  AArch64_XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_8_11RegClassID = 66,
  AArch64_XSeqPairsClass_with_sube64_in_rtcGPR64RegClassID = 67,
  AArch64_XSeqPairsClass_with_subo64_in_FIXED_REGSRegClassID = 68,
  AArch64_FPR128RegClassID = 69,
  AArch64_ZPRRegClassID = 70,
  AArch64_FPR128_loRegClassID = 71,
  AArch64_MPR128RegClassID = 72,
  AArch64_ZPR_4bRegClassID = 73,
  AArch64_ZPR_3bRegClassID = 74,
  AArch64_DDDRegClassID = 75,
  AArch64_DDD_with_dsub0_in_FPR64_loRegClassID = 76,
  AArch64_DDD_with_dsub1_in_FPR64_loRegClassID = 77,
  AArch64_DDD_with_dsub2_in_FPR64_loRegClassID = 78,
  AArch64_DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub1_in_FPR64_loRegClassID = 79,
  AArch64_DDD_with_dsub1_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_loRegClassID = 80,
  AArch64_DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_loRegClassID = 81,
  AArch64_DDDDRegClassID = 82,
  AArch64_DDDD_with_dsub0_in_FPR64_loRegClassID = 83,
  AArch64_DDDD_with_dsub1_in_FPR64_loRegClassID = 84,
  AArch64_DDDD_with_dsub2_in_FPR64_loRegClassID = 85,
  AArch64_DDDD_with_dsub3_in_FPR64_loRegClassID = 86,
  AArch64_DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub1_in_FPR64_loRegClassID = 87,
  AArch64_DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_loRegClassID = 88,
  AArch64_DDDD_with_dsub2_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_loRegClassID = 89,
  AArch64_DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_loRegClassID = 90,
  AArch64_DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_loRegClassID = 91,
  AArch64_DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_loRegClassID = 92,
  AArch64_QQRegClassID = 93,
  AArch64_ZPR2RegClassID = 94,
  AArch64_QQ_with_dsub_in_FPR64_loRegClassID = 95,
  AArch64_QQ_with_qsub1_in_FPR128_loRegClassID = 96,
  AArch64_ZPR2Mul2RegClassID = 97,
  AArch64_ZPR2_with_dsub_in_FPR64_loRegClassID = 98,
  AArch64_ZPR2_with_zsub1_in_ZPR_4bRegClassID = 99,
  AArch64_QQ_with_dsub_in_FPR64_lo_and_QQ_with_qsub1_in_FPR128_loRegClassID = 100,
  AArch64_ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_4bRegClassID = 101,
  AArch64_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loRegClassID = 102,
  AArch64_ZPR2_with_zsub0_in_ZPR_3bRegClassID = 103,
  AArch64_ZPR2_with_zsub1_in_ZPR_3bRegClassID = 104,
  AArch64_ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_3bRegClassID = 105,
  AArch64_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bRegClassID = 106,
  AArch64_ZPR2StridedRegClassID = 107,
  AArch64_MPR64RegClassID = 108,
  AArch64_ZPR2Strided_with_dsub_in_FPR64_loRegClassID = 109,
  AArch64_QQQRegClassID = 110,
  AArch64_ZPR3RegClassID = 111,
  AArch64_QQQ_with_dsub_in_FPR64_loRegClassID = 112,
  AArch64_QQQ_with_qsub1_in_FPR128_loRegClassID = 113,
  AArch64_QQQ_with_qsub2_in_FPR128_loRegClassID = 114,
  AArch64_ZPR3_with_dsub_in_FPR64_loRegClassID = 115,
  AArch64_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2RegClassID = 116,
  AArch64_ZPR3_with_zsub1_in_ZPR_4bRegClassID = 117,
  AArch64_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2RegClassID = 118,
  AArch64_ZPR3_with_zsub2_in_ZPR_4bRegClassID = 119,
  AArch64_QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub1_in_FPR128_loRegClassID = 120,
  AArch64_QQQ_with_qsub1_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_loRegClassID = 121,
  AArch64_ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_4bRegClassID = 122,
  AArch64_ZPR3_with_zsub1_in_ZPR_4b_and_ZPR3_with_zsub2_in_ZPR_4bRegClassID = 123,
  AArch64_QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub2_in_FPR128_loRegClassID = 124,
  AArch64_ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_4bRegClassID = 125,
  AArch64_ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2RegClassID = 126,
  AArch64_ZPR3_with_zsub0_in_ZPR_3bRegClassID = 127,
  AArch64_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loRegClassID = 128,
  AArch64_ZPR3_with_zsub1_in_ZPR_3bRegClassID = 129,
  AArch64_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loRegClassID = 130,
  AArch64_ZPR3_with_zsub2_in_ZPR_3bRegClassID = 131,
  AArch64_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2RegClassID = 132,
  AArch64_ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_3bRegClassID = 133,
  AArch64_ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loRegClassID = 134,
  AArch64_ZPR3_with_zsub1_in_ZPR_3b_and_ZPR3_with_zsub2_in_ZPR_3bRegClassID = 135,
  AArch64_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loRegClassID = 136,
  AArch64_ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_3bRegClassID = 137,
  AArch64_ZPR3_with_zsub0_in_ZPR_3b_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2RegClassID = 138,
  AArch64_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bRegClassID = 139,
  AArch64_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bRegClassID = 140,
  AArch64_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2RegClassID = 141,
  AArch64_ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bRegClassID = 142,
  AArch64_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loRegClassID = 143,
  AArch64_QQQQRegClassID = 144,
  AArch64_ZPR4RegClassID = 145,
  AArch64_QQQQ_with_dsub_in_FPR64_loRegClassID = 146,
  AArch64_QQQQ_with_qsub1_in_FPR128_loRegClassID = 147,
  AArch64_QQQQ_with_qsub2_in_FPR128_loRegClassID = 148,
  AArch64_QQQQ_with_qsub3_in_FPR128_loRegClassID = 149,
  AArch64_ZPR4_with_dsub_in_FPR64_loRegClassID = 150,
  AArch64_ZPR4_with_zsub0_zsub1_in_ZPR2Mul2RegClassID = 151,
  AArch64_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2RegClassID = 152,
  AArch64_ZPR4_with_zsub1_in_ZPR_4bRegClassID = 153,
  AArch64_ZPR4_with_zsub2_in_ZPR_4bRegClassID = 154,
  AArch64_ZPR4_with_zsub3_in_ZPR_4bRegClassID = 155,
  AArch64_QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub1_in_FPR128_loRegClassID = 156,
  AArch64_QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_loRegClassID = 157,
  AArch64_QQQQ_with_qsub2_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_loRegClassID = 158,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_4bRegClassID = 159,
  AArch64_ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub2_in_ZPR_4bRegClassID = 160,
  AArch64_ZPR4_with_zsub2_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4bRegClassID = 161,
  AArch64_QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub2_in_FPR128_loRegClassID = 162,
  AArch64_QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_loRegClassID = 163,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_4bRegClassID = 164,
  AArch64_ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4bRegClassID = 165,
  AArch64_QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub3_in_FPR128_loRegClassID = 166,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_4bRegClassID = 167,
  AArch64_ZPR4Mul4RegClassID = 168,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2RegClassID = 169,
  AArch64_ZPR4_with_zsub0_in_ZPR_3bRegClassID = 170,
  AArch64_ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loRegClassID = 171,
  AArch64_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loRegClassID = 172,
  AArch64_ZPR4_with_zsub1_in_ZPR_3bRegClassID = 173,
  AArch64_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loRegClassID = 174,
  AArch64_ZPR4_with_zsub2_in_ZPR_3bRegClassID = 175,
  AArch64_ZPR4_with_zsub3_in_ZPR_3bRegClassID = 176,
  AArch64_ZPR4_with_zsub3_in_ZPR_4b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2RegClassID = 177,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loRegClassID = 178,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_3bRegClassID = 179,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loRegClassID = 180,
  AArch64_ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub2_in_ZPR_3bRegClassID = 181,
  AArch64_ZPR4_with_zsub1_in_ZPR_4b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2RegClassID = 182,
  AArch64_ZPR4_with_zsub2_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3bRegClassID = 183,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_3bRegClassID = 184,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2RegClassID = 185,
  AArch64_ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3bRegClassID = 186,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_3bRegClassID = 187,
  AArch64_ZPR4Mul4_and_ZPR4_with_dsub_in_FPR64_loRegClassID = 188,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub0_in_ZPR_3b_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2RegClassID = 189,
  AArch64_ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bRegClassID = 190,
  AArch64_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bRegClassID = 191,
  AArch64_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bRegClassID = 192,
  AArch64_ZPR4_with_zsub3_in_ZPR_3b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2RegClassID = 193,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bRegClassID = 194,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bRegClassID = 195,
  AArch64_ZPR4_with_zsub1_in_ZPR_3b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2RegClassID = 196,
  AArch64_ZPR4Mul4_and_ZPR4_with_zsub0_in_ZPR_3bRegClassID = 197,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2RegClassID = 198,
  AArch64_GPR64x8ClassRegClassID = 199,
  AArch64_GPR64x8Class_with_x8sub_0_in_GPR64noipRegClassID = 200,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64noipRegClassID = 201,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noipRegClassID = 202,
  AArch64_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 203,
  AArch64_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noipRegClassID = 204,
  AArch64_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipRegClassID = 205,
  AArch64_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 206,
  AArch64_GPR64x8Class_with_x8sub_0_in_tcGPR64RegClassID = 207,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipRegClassID = 208,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 209,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 210,
  AArch64_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_tcGPR64RegClassID = 211,
  AArch64_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_2_in_GPR64noipRegClassID = 212,
  AArch64_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noipRegClassID = 213,
  AArch64_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 214,
  AArch64_GPR64x8Class_with_x8sub_1_in_tcGPR64RegClassID = 215,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipRegClassID = 216,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 217,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 218,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 219,
  AArch64_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noipRegClassID = 220,
  AArch64_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipRegClassID = 221,
  AArch64_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 222,
  AArch64_GPR64x8Class_with_x8sub_1_in_GPR64noip_and_tcGPR64RegClassID = 223,
  AArch64_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noipRegClassID = 224,
  AArch64_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 225,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noipRegClassID = 226,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 227,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_tcGPR64RegClassID = 228,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 229,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 230,
  AArch64_ZPR4StridedRegClassID = 231,
  AArch64_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 232,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipRegClassID = 233,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 234,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noipRegClassID = 235,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 236,
  AArch64_GPR64x8Class_with_x8sub_3_in_GPR64noip_and_tcGPR64RegClassID = 237,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 238,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 239,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 240,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noip_and_tcGPR64RegClassID = 241,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 242,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 243,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 244,
  AArch64_GPR64x8Class_with_x8sub_5_in_GPR64noip_and_tcGPR64RegClassID = 245,
  AArch64_GPR64x8Class_with_x8sub_6_in_GPR64noip_and_tcGPR64RegClassID = 246,
  AArch64_GPR64x8Class_with_x8sub_7_in_GPR64noip_and_tcGPR64RegClassID = 247,
  AArch64_GPR64x8Class_with_sub_32_in_GPR32argRegClassID = 248,
  AArch64_MPR32RegClassID = 249,
  AArch64_ZPR4Strided_with_dsub_in_FPR64_loRegClassID = 250,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64argRegClassID = 251,
  AArch64_GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_12_15RegClassID = 252,
  AArch64_GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11RegClassID = 253,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_12_15RegClassID = 254,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11RegClassID = 255,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11RegClassID = 256,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64argRegClassID = 257,
  AArch64_GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11RegClassID = 258,
  AArch64_GPR64x8Class_with_sub_32_in_GPR32arg_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11RegClassID = 259,
  AArch64_GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11RegClassID = 260,
  AArch64_GPR64x8Class_with_x8sub_0_in_rtcGPR64RegClassID = 261,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64arg_and_GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11RegClassID = 262,
  AArch64_GPR64x8Class_with_x8sub_2_in_rtcGPR64RegClassID = 263,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64arg_and_GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11RegClassID = 264,
  AArch64_GPR64x8Class_with_x8sub_4_in_rtcGPR64RegClassID = 265,
  AArch64_GPR64x8Class_with_x8sub_6_in_GPR64argRegClassID = 266,
  AArch64_GPR64x8Class_with_x8sub_6_in_rtcGPR64RegClassID = 267,
  AArch64_GPR64x8Class_with_x8sub_7_in_FIXED_REGSRegClassID = 268,
  AArch64_ZTRRegClassID = 269,
  AArch64_MPR16RegClassID = 270,
  AArch64_MPRRegClassID = 271,
  AArch64_MPR8RegClassID = 272,

};

// Register alternate name indices

enum {
  AArch64_NoRegAltName,	// 0
  AArch64_vlist1,	// 1
  AArch64_vreg,	// 2
  NUM_TARGET_REG_ALT_NAMES = 3
};

// Subregister indices

enum {
  AArch64_NoSubRegister,
  AArch64_bsub,	// 1
  AArch64_dsub,	// 2
  AArch64_dsub0,	// 3
  AArch64_dsub1,	// 4
  AArch64_dsub2,	// 5
  AArch64_dsub3,	// 6
  AArch64_hsub,	// 7
  AArch64_psub0,	// 8
  AArch64_psub1,	// 9
  AArch64_qsub0,	// 10
  AArch64_qsub1,	// 11
  AArch64_qsub2,	// 12
  AArch64_qsub3,	// 13
  AArch64_ssub,	// 14
  AArch64_sub_32,	// 15
  AArch64_sube32,	// 16
  AArch64_sube64,	// 17
  AArch64_subo32,	// 18
  AArch64_subo64,	// 19
  AArch64_x8sub_0,	// 20
  AArch64_x8sub_1,	// 21
  AArch64_x8sub_2,	// 22
  AArch64_x8sub_3,	// 23
  AArch64_x8sub_4,	// 24
  AArch64_x8sub_5,	// 25
  AArch64_x8sub_6,	// 26
  AArch64_x8sub_7,	// 27
  AArch64_zasubb,	// 28
  AArch64_zasubd0,	// 29
  AArch64_zasubd1,	// 30
  AArch64_zasubh0,	// 31
  AArch64_zasubh1,	// 32
  AArch64_zasubq0,	// 33
  AArch64_zasubq1,	// 34
  AArch64_zasubs0,	// 35
  AArch64_zasubs1,	// 36
  AArch64_zsub,	// 37
  AArch64_zsub0,	// 38
  AArch64_zsub1,	// 39
  AArch64_zsub2,	// 40
  AArch64_zsub3,	// 41
  AArch64_zsub_hi,	// 42
  AArch64_zasubd1_then_zasubq0,	// 43
  AArch64_zasubd1_then_zasubq1,	// 44
  AArch64_zasubs1_then_zasubd0,	// 45
  AArch64_zasubs1_then_zasubd1,	// 46
  AArch64_zasubs1_then_zasubq0,	// 47
  AArch64_zasubs1_then_zasubq1,	// 48
  AArch64_zasubs1_then_zasubd1_then_zasubq0,	// 49
  AArch64_zasubs1_then_zasubd1_then_zasubq1,	// 50
  AArch64_zasubh1_then_zasubd0,	// 51
  AArch64_zasubh1_then_zasubd1,	// 52
  AArch64_zasubh1_then_zasubq0,	// 53
  AArch64_zasubh1_then_zasubq1,	// 54
  AArch64_zasubh1_then_zasubs0,	// 55
  AArch64_zasubh1_then_zasubs1,	// 56
  AArch64_zasubh1_then_zasubd1_then_zasubq0,	// 57
  AArch64_zasubh1_then_zasubd1_then_zasubq1,	// 58
  AArch64_zasubh1_then_zasubs1_then_zasubd0,	// 59
  AArch64_zasubh1_then_zasubs1_then_zasubd1,	// 60
  AArch64_zasubh1_then_zasubs1_then_zasubq0,	// 61
  AArch64_zasubh1_then_zasubs1_then_zasubq1,	// 62
  AArch64_zasubh1_then_zasubs1_then_zasubd1_then_zasubq0,	// 63
  AArch64_zasubh1_then_zasubs1_then_zasubd1_then_zasubq1,	// 64
  AArch64_dsub1_then_bsub,	// 65
  AArch64_dsub1_then_hsub,	// 66
  AArch64_dsub1_then_ssub,	// 67
  AArch64_dsub3_then_bsub,	// 68
  AArch64_dsub3_then_hsub,	// 69
  AArch64_dsub3_then_ssub,	// 70
  AArch64_dsub2_then_bsub,	// 71
  AArch64_dsub2_then_hsub,	// 72
  AArch64_dsub2_then_ssub,	// 73
  AArch64_qsub1_then_bsub,	// 74
  AArch64_qsub1_then_dsub,	// 75
  AArch64_qsub1_then_hsub,	// 76
  AArch64_qsub1_then_ssub,	// 77
  AArch64_qsub3_then_bsub,	// 78
  AArch64_qsub3_then_dsub,	// 79
  AArch64_qsub3_then_hsub,	// 80
  AArch64_qsub3_then_ssub,	// 81
  AArch64_qsub2_then_bsub,	// 82
  AArch64_qsub2_then_dsub,	// 83
  AArch64_qsub2_then_hsub,	// 84
  AArch64_qsub2_then_ssub,	// 85
  AArch64_x8sub_7_then_sub_32,	// 86
  AArch64_x8sub_6_then_sub_32,	// 87
  AArch64_x8sub_5_then_sub_32,	// 88
  AArch64_x8sub_4_then_sub_32,	// 89
  AArch64_x8sub_3_then_sub_32,	// 90
  AArch64_x8sub_2_then_sub_32,	// 91
  AArch64_x8sub_1_then_sub_32,	// 92
  AArch64_subo64_then_sub_32,	// 93
  AArch64_zsub1_then_bsub,	// 94
  AArch64_zsub1_then_dsub,	// 95
  AArch64_zsub1_then_hsub,	// 96
  AArch64_zsub1_then_ssub,	// 97
  AArch64_zsub1_then_zsub,	// 98
  AArch64_zsub1_then_zsub_hi,	// 99
  AArch64_zsub3_then_bsub,	// 100
  AArch64_zsub3_then_dsub,	// 101
  AArch64_zsub3_then_hsub,	// 102
  AArch64_zsub3_then_ssub,	// 103
  AArch64_zsub3_then_zsub,	// 104
  AArch64_zsub3_then_zsub_hi,	// 105
  AArch64_zsub2_then_bsub,	// 106
  AArch64_zsub2_then_dsub,	// 107
  AArch64_zsub2_then_hsub,	// 108
  AArch64_zsub2_then_ssub,	// 109
  AArch64_zsub2_then_zsub,	// 110
  AArch64_zsub2_then_zsub_hi,	// 111
  AArch64_dsub0_dsub1,	// 112
  AArch64_dsub0_dsub1_dsub2,	// 113
  AArch64_dsub1_dsub2,	// 114
  AArch64_dsub1_dsub2_dsub3,	// 115
  AArch64_dsub2_dsub3,	// 116
  AArch64_dsub_qsub1_then_dsub,	// 117
  AArch64_dsub_qsub1_then_dsub_qsub2_then_dsub_qsub3_then_dsub,	// 118
  AArch64_dsub_qsub1_then_dsub_qsub2_then_dsub,	// 119
  AArch64_qsub0_qsub1,	// 120
  AArch64_qsub0_qsub1_qsub2,	// 121
  AArch64_qsub1_qsub2,	// 122
  AArch64_qsub1_qsub2_qsub3,	// 123
  AArch64_qsub2_qsub3,	// 124
  AArch64_qsub1_then_dsub_qsub2_then_dsub,	// 125
  AArch64_qsub1_then_dsub_qsub2_then_dsub_qsub3_then_dsub,	// 126
  AArch64_qsub2_then_dsub_qsub3_then_dsub,	// 127
  AArch64_sub_32_x8sub_1_then_sub_32,	// 128
  AArch64_x8sub_0_x8sub_1,	// 129
  AArch64_x8sub_2_x8sub_3,	// 130
  AArch64_x8sub_4_x8sub_5,	// 131
  AArch64_x8sub_6_x8sub_7,	// 132
  AArch64_x8sub_6_then_sub_32_x8sub_7_then_sub_32,	// 133
  AArch64_x8sub_4_then_sub_32_x8sub_5_then_sub_32,	// 134
  AArch64_x8sub_2_then_sub_32_x8sub_3_then_sub_32,	// 135
  AArch64_sub_32_subo64_then_sub_32,	// 136
  AArch64_dsub_zsub1_then_dsub,	// 137
  AArch64_zsub_zsub1_then_zsub,	// 138
  AArch64_dsub_zsub1_then_dsub_zsub2_then_dsub_zsub3_then_dsub,	// 139
  AArch64_dsub_zsub1_then_dsub_zsub2_then_dsub,	// 140
  AArch64_zsub_zsub1_then_zsub_zsub2_then_zsub_zsub3_then_zsub,	// 141
  AArch64_zsub_zsub1_then_zsub_zsub2_then_zsub,	// 142
  AArch64_zsub0_zsub1,	// 143
  AArch64_zsub0_zsub1_zsub2,	// 144
  AArch64_zsub1_zsub2,	// 145
  AArch64_zsub1_zsub2_zsub3,	// 146
  AArch64_zsub2_zsub3,	// 147
  AArch64_zsub1_then_dsub_zsub2_then_dsub,	// 148
  AArch64_zsub1_then_dsub_zsub2_then_dsub_zsub3_then_dsub,	// 149
  AArch64_zsub1_then_zsub_zsub2_then_zsub,	// 150
  AArch64_zsub1_then_zsub_zsub2_then_zsub_zsub3_then_zsub,	// 151
  AArch64_zsub2_then_dsub_zsub3_then_dsub,	// 152
  AArch64_zsub2_then_zsub_zsub3_then_zsub,	// 153
  AArch64_zsub0_zsub2,	// 154
  AArch64_zsub1_zsub3,	// 155
  AArch64_NUM_TARGET_SUBREGS
};
#endif // GET_REGINFO_ENUM

#ifdef GET_REGINFO_MC_DESC
#undef GET_REGINFO_MC_DESC

static const MCPhysReg AArch64RegDiffLists[] = {
  /* 0 */ 8, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
  /* 17 */ 63232, 1, 1, 1, 1, 1, 1, 1, 0,
  /* 26 */ 64502, 1, 1, 1, 1, 1, 1, 1, 0,
  /* 35 */ 1, 93, 1, 1, 1, 1, 1, 1, 0,
  /* 44 */ 64932, 1, 1, 1, 74, 1, 1, 1, 0,
  /* 53 */ 63076, 1, 1, 1, 0,
  /* 58 */ 63088, 1, 1, 1, 0,
  /* 63 */ 65072, 1, 1, 1, 0,
  /* 68 */ 65184, 1, 1, 1, 0,
  /* 73 */ 31, 335, 17, 65504, 1, 1, 1, 0,
  /* 81 */ 31, 336, 17, 65504, 1, 1, 1, 0,
  /* 89 */ 31, 337, 17, 65504, 1, 1, 1, 0,
  /* 97 */ 31, 338, 17, 65504, 1, 1, 1, 0,
  /* 105 */ 31, 339, 17, 65504, 1, 1, 1, 0,
  /* 113 */ 31, 340, 17, 65504, 1, 1, 1, 0,
  /* 121 */ 31, 341, 17, 65504, 1, 1, 1, 0,
  /* 129 */ 31, 342, 17, 65504, 1, 1, 1, 0,
  /* 137 */ 31, 343, 17, 65504, 1, 1, 1, 0,
  /* 145 */ 352, 65504, 1, 1, 1, 0,
  /* 151 */ 353, 65504, 1, 1, 1, 0,
  /* 157 */ 354, 65504, 1, 1, 1, 0,
  /* 163 */ 355, 65504, 1, 1, 1, 0,
  /* 169 */ 356, 65504, 1, 1, 1, 0,
  /* 175 */ 357, 65504, 1, 1, 1, 0,
  /* 181 */ 358, 65504, 1, 1, 1, 0,
  /* 187 */ 359, 65504, 1, 1, 1, 0,
  /* 193 */ 360, 65504, 1, 1, 1, 0,
  /* 199 */ 31, 334, 17, 65495, 9, 1, 1, 0,
  /* 207 */ 31, 335, 17, 65495, 9, 1, 1, 0,
  /* 215 */ 351, 65495, 9, 1, 1, 0,
  /* 221 */ 352, 65495, 9, 1, 1, 0,
  /* 227 */ 24, 29, 1, 1, 0,
  /* 232 */ 24, 29, 1, 1, 46, 29, 1, 1, 0,
  /* 241 */ 64900, 1, 1, 75, 1, 1, 0,
  /* 248 */ 65040, 1, 1, 0,
  /* 252 */ 65152, 1, 1, 0,
  /* 256 */ 31, 343, 17, 65505, 1, 1, 0,
  /* 263 */ 31, 344, 17, 65505, 1, 1, 0,
  /* 270 */ 360, 65505, 1, 1, 0,
  /* 275 */ 361, 65505, 1, 1, 0,
  /* 280 */ 31, 333, 17, 65494, 10, 1, 0,
  /* 287 */ 31, 334, 17, 65494, 10, 1, 0,
  /* 294 */ 350, 65494, 10, 1, 0,
  /* 299 */ 351, 65494, 10, 1, 0,
  /* 304 */ 24, 1, 29, 1, 0,
  /* 309 */ 24, 1, 29, 1, 46, 1, 29, 1, 0,
  /* 318 */ 24, 30, 1, 0,
  /* 322 */ 24, 30, 1, 46, 30, 1, 0,
  /* 329 */ 64964, 1, 76, 1, 0,
  /* 334 */ 65172, 112, 65456, 65472, 33, 112, 65456, 65472, 33, 112, 65456, 65472, 330, 1, 0,
  /* 349 */ 331, 1, 0,
  /* 352 */ 65172, 112, 65456, 65472, 33, 112, 65456, 65472, 1, 112, 65456, 65472, 362, 1, 0,
  /* 367 */ 63254, 1, 0,
  /* 370 */ 63266, 1, 0,
  /* 373 */ 63284, 1, 0,
  /* 376 */ 63296, 1, 0,
  /* 379 */ 64444, 1, 0,
  /* 382 */ 64478, 1, 0,
  /* 385 */ 65104, 1, 0,
  /* 388 */ 65152, 1, 0,
  /* 391 */ 65159, 1, 0,
  /* 394 */ 65160, 1, 0,
  /* 397 */ 65161, 1, 0,
  /* 400 */ 65162, 1, 0,
  /* 403 */ 65163, 1, 0,
  /* 406 */ 65164, 1, 0,
  /* 409 */ 65165, 1, 0,
  /* 412 */ 65166, 1, 0,
  /* 415 */ 65167, 1, 0,
  /* 418 */ 65168, 1, 0,
  /* 421 */ 65169, 1, 0,
  /* 424 */ 65170, 1, 0,
  /* 427 */ 65171, 1, 0,
  /* 430 */ 65172, 1, 0,
  /* 433 */ 65173, 1, 0,
  /* 436 */ 65204, 1, 0,
  /* 439 */ 65216, 1, 0,
  /* 442 */ 63, 65503, 34, 65503, 1, 80, 63, 65503, 34, 65503, 1, 108, 63, 65503, 34, 65503, 1, 0,
  /* 460 */ 64, 65504, 63, 65503, 1, 49, 64, 65504, 63, 65503, 1, 77, 64, 65504, 63, 65503, 1, 0,
  /* 478 */ 65503, 1, 144, 65503, 1, 172, 65503, 1, 0,
  /* 487 */ 31, 344, 17, 65506, 1, 0,
  /* 493 */ 31, 345, 17, 65506, 1, 0,
  /* 499 */ 361, 65506, 1, 0,
  /* 503 */ 362, 65506, 1, 0,
  /* 507 */ 2, 0,
  /* 509 */ 3, 4, 0,
  /* 512 */ 64848, 4, 4, 4, 65, 4, 4, 4, 0,
  /* 521 */ 64868, 4, 4, 4, 65, 4, 4, 4, 0,
  /* 530 */ 65092, 65412, 65456, 112, 65456, 65472, 300, 65476, 65412, 65456, 112, 65456, 65472, 300, 65476, 65412, 65456, 112, 65456, 65472, 300, 65476, 65412, 65456, 112, 65456, 65472, 300, 352, 4, 0,
  /* 561 */ 65072, 65412, 65456, 112, 65456, 65472, 300, 65476, 65412, 65456, 112, 65456, 65472, 300, 65476, 65412, 65456, 112, 65456, 65472, 300, 65476, 65412, 65456, 112, 65456, 65472, 300, 376, 4, 0,
  /* 592 */ 64379, 4, 0,
  /* 595 */ 7, 0,
  /* 597 */ 269, 9, 18, 65510, 10, 8, 65522, 10, 8, 6, 65510, 10, 8, 65522, 10, 8, 65521, 18, 65510, 10, 8, 65522, 10, 8, 6, 65510, 10, 8, 65522, 10, 8, 0,
  /* 629 */ 64, 80, 65424, 80, 124, 95, 1, 62, 65503, 34, 65503, 34, 65503, 1, 79, 1, 62, 65503, 34, 65503, 34, 65503, 1, 107, 1, 62, 65503, 34, 65503, 34, 65503, 1, 64, 8, 0,
  /* 664 */ 124, 207, 1, 62, 65503, 34, 65503, 34, 65503, 1, 107, 1, 62, 65503, 34, 65503, 34, 65503, 1, 64, 8, 0,
  /* 686 */ 65472, 347, 1, 62, 65503, 34, 65503, 34, 65503, 1, 64, 8, 0,
  /* 699 */ 64860, 8, 69, 8, 0,
  /* 704 */ 64884, 8, 69, 8, 0,
  /* 709 */ 64, 80, 65424, 80, 124, 95, 1, 62, 65503, 34, 65503, 34, 65503, 1, 79, 1, 62, 65503, 34, 65503, 34, 65503, 1, 107, 1, 62, 65503, 34, 65503, 34, 65503, 1, 72, 8, 0,
  /* 744 */ 124, 207, 1, 62, 65503, 34, 65503, 34, 65503, 1, 107, 1, 62, 65503, 34, 65503, 34, 65503, 1, 72, 8, 0,
  /* 766 */ 65472, 347, 1, 62, 65503, 34, 65503, 34, 65503, 1, 72, 8, 0,
  /* 779 */ 31, 332, 17, 65493, 11, 0,
  /* 785 */ 31, 333, 17, 65493, 11, 0,
  /* 791 */ 349, 65493, 11, 0,
  /* 795 */ 350, 65493, 11, 0,
  /* 799 */ 64, 80, 65424, 80, 124, 95, 1, 62, 65503, 34, 65503, 34, 65503, 1, 79, 1, 62, 65503, 34, 65503, 34, 65503, 1, 107, 1, 62, 65503, 34, 65503, 34, 65503, 1, 40, 12, 0,
  /* 834 */ 124, 207, 1, 62, 65503, 34, 65503, 34, 65503, 1, 107, 1, 62, 65503, 34, 65503, 34, 65503, 1, 40, 12, 0,
  /* 856 */ 65472, 347, 1, 62, 65503, 34, 65503, 34, 65503, 1, 40, 12, 0,
  /* 869 */ 64, 80, 65424, 80, 124, 96, 31, 33, 65504, 62, 65503, 34, 65503, 1, 49, 31, 33, 65504, 62, 65503, 34, 65503, 1, 77, 31, 33, 65504, 62, 65503, 34, 65503, 1, 41, 12, 0,
  /* 904 */ 124, 208, 31, 33, 65504, 62, 65503, 34, 65503, 1, 77, 31, 33, 65504, 62, 65503, 34, 65503, 1, 41, 12, 0,
  /* 926 */ 65472, 348, 31, 33, 65504, 62, 65503, 34, 65503, 1, 41, 12, 0,
  /* 939 */ 64, 80, 65424, 80, 124, 95, 1, 63, 1, 65503, 1, 62, 65503, 1, 49, 1, 63, 1, 65503, 1, 62, 65503, 1, 77, 1, 63, 1, 65503, 1, 62, 65503, 1, 42, 12, 0,
  /* 974 */ 124, 207, 1, 63, 1, 65503, 1, 62, 65503, 1, 77, 1, 63, 1, 65503, 1, 62, 65503, 1, 42, 12, 0,
  /* 996 */ 65472, 347, 1, 63, 1, 65503, 1, 62, 65503, 1, 42, 12, 0,
  /* 1009 */ 64, 80, 65424, 80, 124, 95, 1, 62, 1, 65503, 34, 65503, 1, 29, 50, 1, 62, 1, 65503, 34, 65503, 1, 29, 78, 1, 62, 1, 65503, 34, 65503, 1, 29, 43, 12, 0,
  /* 1044 */ 124, 207, 1, 62, 1, 65503, 34, 65503, 1, 29, 78, 1, 62, 1, 65503, 34, 65503, 1, 29, 43, 12, 0,
  /* 1066 */ 65472, 347, 1, 62, 1, 65503, 34, 65503, 1, 29, 43, 12, 0,
  /* 1079 */ 64, 80, 65424, 80, 124, 95, 1, 62, 65503, 34, 65503, 34, 65503, 1, 79, 1, 62, 65503, 34, 65503, 34, 65503, 1, 107, 1, 62, 65503, 34, 65503, 34, 65503, 1, 48, 12, 0,
  /* 1114 */ 124, 207, 1, 62, 65503, 34, 65503, 34, 65503, 1, 107, 1, 62, 65503, 34, 65503, 34, 65503, 1, 48, 12, 0,
  /* 1136 */ 65472, 347, 1, 62, 65503, 34, 65503, 34, 65503, 1, 48, 12, 0,
  /* 1149 */ 64, 80, 65424, 80, 124, 95, 1, 62, 65503, 34, 65503, 34, 65503, 1, 79, 1, 62, 65503, 34, 65503, 34, 65503, 1, 107, 1, 62, 65503, 34, 65503, 34, 65503, 1, 64, 12, 0,
  /* 1184 */ 124, 207, 1, 62, 65503, 34, 65503, 34, 65503, 1, 107, 1, 62, 65503, 34, 65503, 34, 65503, 1, 64, 12, 0,
  /* 1206 */ 65472, 347, 1, 62, 65503, 34, 65503, 34, 65503, 1, 64, 12, 0,
  /* 1219 */ 64, 80, 65424, 80, 124, 95, 1, 62, 65503, 34, 65503, 34, 65503, 1, 79, 1, 62, 65503, 34, 65503, 34, 65503, 1, 107, 1, 62, 65503, 34, 65503, 34, 65503, 1, 72, 12, 0,
  /* 1254 */ 124, 207, 1, 62, 65503, 34, 65503, 34, 65503, 1, 107, 1, 62, 65503, 34, 65503, 34, 65503, 1, 72, 12, 0,
  /* 1276 */ 65472, 347, 1, 62, 65503, 34, 65503, 34, 65503, 1, 72, 12, 0,
  /* 1289 */ 56, 15, 0,
  /* 1292 */ 332, 15, 0,
  /* 1295 */ 64, 80, 65424, 80, 124, 95, 1, 62, 65503, 34, 65503, 34, 65503, 1, 79, 1, 62, 65503, 34, 65503, 34, 65503, 1, 107, 1, 62, 65503, 34, 65503, 34, 65503, 1, 40, 16, 0,
  /* 1330 */ 124, 207, 1, 62, 65503, 34, 65503, 34, 65503, 1, 107, 1, 62, 65503, 34, 65503, 34, 65503, 1, 40, 16, 0,
  /* 1352 */ 65472, 347, 1, 62, 65503, 34, 65503, 34, 65503, 1, 40, 16, 0,
  /* 1365 */ 64, 80, 65424, 80, 124, 95, 1, 62, 65503, 34, 65503, 34, 65503, 1, 79, 1, 62, 65503, 34, 65503, 34, 65503, 1, 107, 1, 62, 65503, 34, 65503, 34, 65503, 1, 48, 16, 0,
  /* 1400 */ 124, 207, 1, 62, 65503, 34, 65503, 34, 65503, 1, 107, 1, 62, 65503, 34, 65503, 34, 65503, 1, 48, 16, 0,
  /* 1422 */ 65472, 347, 1, 62, 65503, 34, 65503, 34, 65503, 1, 48, 16, 0,
  /* 1435 */ 1, 554, 16, 0,
  /* 1439 */ 65322, 560, 16, 0,
  /* 1443 */ 24, 1, 1, 29, 0,
  /* 1448 */ 24, 1, 1, 29, 46, 1, 1, 29, 0,
  /* 1457 */ 24, 1, 30, 0,
  /* 1461 */ 24, 1, 30, 46, 1, 30, 0,
  /* 1468 */ 63, 1, 65503, 1, 30, 50, 63, 1, 65503, 1, 30, 78, 63, 1, 65503, 1, 30, 0,
  /* 1486 */ 24, 31, 0,
  /* 1489 */ 24, 31, 46, 31, 0,
  /* 1494 */ 65504, 31, 113, 65504, 31, 141, 65504, 31, 0,
  /* 1503 */ 65312, 77, 0,
  /* 1506 */ 1, 99, 0,
  /* 1509 */ 64379, 99, 0,
  /* 1512 */ 65188, 65412, 65456, 112, 65456, 65472, 300, 65473, 65412, 65456, 112, 65456, 65472, 300, 31, 112, 0,
  /* 1529 */ 65188, 65412, 65456, 112, 65456, 65472, 300, 65441, 65412, 65456, 112, 65456, 65472, 300, 63, 112, 0,
  /* 1546 */ 65124, 65412, 65456, 112, 65456, 65472, 300, 65473, 65412, 65456, 112, 65456, 65472, 300, 65473, 65412, 65456, 112, 65456, 65472, 300, 30, 112, 65488, 112, 76, 1, 65284, 112, 0,
  /* 1576 */ 65124, 65412, 65456, 112, 65456, 65472, 300, 65473, 65412, 65456, 112, 65456, 65472, 300, 65441, 65412, 65456, 112, 65456, 65472, 300, 62, 112, 65488, 112, 76, 1, 65284, 112, 0,
  /* 1606 */ 65124, 65412, 65456, 112, 65456, 65472, 300, 65441, 65412, 65456, 112, 65456, 65472, 300, 65473, 65412, 65456, 112, 65456, 65472, 300, 62, 112, 65488, 112, 76, 65505, 65284, 112, 0,
  /* 1636 */ 65156, 65412, 65456, 112, 65456, 65472, 300, 65473, 65412, 65456, 112, 65456, 65472, 300, 65441, 65412, 65456, 112, 65456, 65472, 300, 65473, 65412, 65456, 112, 65456, 65472, 300, 61, 112, 65456, 32, 80, 32, 76, 64, 65473, 64, 65441, 65315, 64, 48, 64, 65329, 112, 0,
  /* 1682 */ 65156, 65412, 65456, 112, 65456, 65472, 300, 65441, 65412, 65456, 112, 65456, 65472, 300, 65473, 65412, 65456, 112, 65456, 65472, 300, 65473, 65412, 65456, 112, 65456, 65472, 300, 61, 112, 65456, 32, 80, 32, 76, 64, 65441, 64, 65473, 65283, 64, 48, 64, 65361, 112, 0,
  /* 1728 */ 65156, 65412, 65456, 112, 65456, 65472, 300, 65473, 65412, 65456, 112, 65456, 65472, 300, 65473, 65412, 65456, 112, 65456, 65472, 300, 65473, 65412, 65456, 112, 65456, 65472, 300, 29, 112, 65456, 32, 80, 32, 76, 64, 65473, 64, 65473, 65283, 64, 48, 64, 65361, 112, 0,
  /* 1774 */ 65156, 65412, 65456, 112, 65456, 65472, 300, 65473, 65412, 65456, 112, 65456, 65472, 300, 65473, 65412, 65456, 112, 65456, 65472, 300, 65441, 65412, 65456, 112, 65456, 65472, 300, 61, 112, 65456, 32, 80, 32, 76, 64, 65473, 64, 65473, 65283, 64, 48, 64, 65361, 112, 0,
  /* 1820 */ 133, 0,
  /* 1822 */ 112, 140, 0,
  /* 1825 */ 214, 0,
  /* 1827 */ 215, 0,
  /* 1829 */ 65084, 65412, 65456, 112, 65456, 65472, 300, 65480, 65412, 65456, 112, 65456, 65472, 300, 0,
  /* 1844 */ 65108, 65412, 65456, 112, 65456, 65472, 300, 65480, 65412, 65456, 112, 65456, 65472, 300, 0,
  /* 1859 */ 65204, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 331, 0,
  /* 1871 */ 65202, 65505, 65322, 215, 362, 0,
  /* 1877 */ 65204, 65456, 112, 65456, 65472, 81, 65456, 112, 65456, 65472, 363, 0,
  /* 1889 */ 65186, 65505, 32, 65505, 363, 0,
  /* 1895 */ 65185, 65505, 32, 65505, 364, 0,
  /* 1901 */ 65184, 65505, 32, 65505, 365, 0,
  /* 1907 */ 65183, 65505, 32, 65505, 366, 0,
  /* 1913 */ 65182, 65505, 32, 65505, 367, 0,
  /* 1919 */ 65181, 65505, 32, 65505, 368, 0,
  /* 1925 */ 65180, 65505, 32, 65505, 369, 0,
  /* 1931 */ 65179, 65505, 32, 65505, 370, 0,
  /* 1937 */ 65178, 65505, 32, 65505, 371, 0,
  /* 1943 */ 65177, 65505, 32, 65505, 372, 0,
  /* 1949 */ 65176, 65505, 32, 65505, 373, 0,
  /* 1955 */ 65175, 65505, 32, 65505, 374, 0,
  /* 1961 */ 65174, 65505, 32, 65505, 375, 0,
  /* 1967 */ 65173, 65505, 32, 65505, 376, 0,
  /* 1973 */ 64960, 214, 65328, 65535, 555, 0,
  /* 1979 */ 570, 0,
  /* 1981 */ 576, 0,
  /* 1983 */ 63111, 0,
  /* 1985 */ 63123, 0,
  /* 1987 */ 63141, 0,
  /* 1989 */ 63153, 0,
  /* 1991 */ 63174, 0,
  /* 1993 */ 63186, 0,
  /* 1995 */ 63204, 0,
  /* 1997 */ 63216, 0,
  /* 1999 */ 65103, 0,
  /* 2001 */ 65518, 22, 65516, 65526, 65267, 0,
  /* 2007 */ 65526, 22, 65516, 65526, 65267, 0,
  /* 2013 */ 65518, 26, 65516, 65526, 65267, 0,
  /* 2019 */ 65526, 26, 65516, 65526, 65267, 0,
  /* 2025 */ 65518, 22, 65518, 65526, 65267, 0,
  /* 2031 */ 65526, 22, 65518, 65526, 65267, 0,
  /* 2037 */ 65518, 26, 65518, 65526, 65267, 0,
  /* 2043 */ 65526, 26, 65518, 65526, 65267, 0,
  /* 2049 */ 65518, 22, 65516, 65527, 65267, 0,
  /* 2055 */ 65526, 22, 65516, 65527, 65267, 0,
  /* 2061 */ 65518, 26, 65516, 65527, 65267, 0,
  /* 2067 */ 65526, 26, 65516, 65527, 65267, 0,
  /* 2073 */ 65518, 22, 65518, 65527, 65267, 0,
  /* 2079 */ 65526, 22, 65518, 65527, 65267, 0,
  /* 2085 */ 65518, 26, 65518, 65527, 65267, 0,
  /* 2091 */ 65526, 26, 65518, 65527, 65267, 0,
  /* 2097 */ 65325, 0,
  /* 2099 */ 65190, 65327, 0,
  /* 2102 */ 65389, 0,
  /* 2104 */ 65404, 0,
  /* 2106 */ 65420, 0,
  /* 2108 */ 65140, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 330, 64, 48, 1, 65424, 0,
  /* 2129 */ 65140, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 81, 65456, 112, 65456, 65472, 362, 64, 48, 1, 65424, 0,
  /* 2150 */ 65140, 65456, 112, 65456, 65472, 81, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 362, 64, 48, 65505, 65424, 0,
  /* 2171 */ 65436, 0,
  /* 2173 */ 65172, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 81, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 361, 32, 32, 48, 64, 65473, 64, 65441, 65455, 64, 65441, 0,
  /* 2205 */ 65204, 112, 65456, 65472, 33, 112, 65456, 65472, 1, 112, 65456, 65472, 33, 112, 65456, 65472, 361, 64, 65473, 64, 65441, 0,
  /* 2227 */ 65236, 112, 65456, 65472, 1, 112, 65456, 65472, 0,
  /* 2236 */ 65236, 112, 65456, 65472, 33, 112, 65456, 65472, 0,
  /* 2245 */ 65456, 112, 65456, 65472, 0,
  /* 2250 */ 65172, 65456, 112, 65456, 65472, 81, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 361, 32, 32, 48, 64, 65441, 64, 65473, 65423, 64, 65473, 0,
  /* 2282 */ 65172, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 329, 32, 32, 48, 64, 65473, 64, 65473, 65423, 64, 65473, 0,
  /* 2314 */ 65172, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 81, 65456, 112, 65456, 65472, 361, 32, 32, 48, 64, 65473, 64, 65473, 65423, 64, 65473, 0,
  /* 2346 */ 65204, 112, 65456, 65472, 1, 112, 65456, 65472, 33, 112, 65456, 65472, 33, 112, 65456, 65472, 361, 64, 65441, 64, 65473, 0,
  /* 2368 */ 65204, 112, 65456, 65472, 33, 112, 65456, 65472, 33, 112, 65456, 65472, 33, 112, 65456, 65472, 329, 64, 65473, 64, 65473, 0,
  /* 2390 */ 65204, 112, 65456, 65472, 33, 112, 65456, 65472, 33, 112, 65456, 65472, 1, 112, 65456, 65472, 361, 64, 65473, 64, 65473, 0,
  /* 2412 */ 65484, 0,
  /* 2414 */ 65172, 112, 65456, 65472, 1, 112, 65456, 65472, 33, 112, 65456, 65472, 362, 65505, 0,
  /* 2429 */ 31, 332, 2, 65507, 0,
  /* 2434 */ 65321, 577, 2, 65507, 0,
  /* 2439 */ 31, 345, 17, 65507, 0,
  /* 2444 */ 31, 346, 17, 65507, 0,
  /* 2449 */ 334, 65507, 0,
  /* 2452 */ 362, 65507, 0,
  /* 2455 */ 363, 65507, 0,
  /* 2458 */ 579, 65507, 0,
  /* 2461 */ 65516, 0,
  /* 2463 */ 65204, 65521, 0,
  /* 2466 */ 65525, 0,
  /* 2468 */ 65534, 0,
  /* 2470 */ 65212, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 360, 17, 1, 1, 1, 65519, 65535, 65535, 0,
  /* 2495 */ 65211, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 361, 17, 1, 1, 1, 65519, 65535, 65535, 0,
  /* 2520 */ 65210, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 362, 17, 1, 1, 1, 65519, 65535, 65535, 0,
  /* 2545 */ 65209, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 363, 17, 1, 1, 1, 65519, 65535, 65535, 0,
  /* 2570 */ 65208, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 364, 17, 1, 1, 1, 65519, 65535, 65535, 0,
  /* 2595 */ 65207, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 365, 17, 1, 1, 1, 65519, 65535, 65535, 0,
  /* 2620 */ 65206, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 366, 17, 1, 1, 1, 65519, 65535, 65535, 0,
  /* 2645 */ 65205, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 367, 17, 1, 1, 1, 65519, 65535, 65535, 0,
  /* 2670 */ 65204, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 368, 17, 1, 1, 1, 65519, 65535, 65535, 0,
  /* 2695 */ 65203, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 369, 17, 1, 1, 1, 65519, 65535, 65535, 0,
  /* 2720 */ 65202, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 370, 17, 1, 1, 1, 65519, 65535, 65535, 0,
  /* 2745 */ 65225, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 32, 65505, 65322, 215, 359, 17, 1, 1, 65522, 65534, 65535, 65535, 0,
};

static const uint16_t AArch64SubRegIdxLists[] = {
  /* 0 */ 2, 14, 7, 1, 0,
  /* 5 */ 8, 9, 0,
  /* 8 */ 15, 0,
  /* 10 */ 16, 18, 0,
  /* 13 */ 33, 34, 0,
  /* 16 */ 37, 2, 14, 7, 1, 42, 0,
  /* 23 */ 29, 33, 34, 30, 43, 44, 0,
  /* 30 */ 35, 29, 33, 34, 30, 43, 44, 36, 45, 47, 48, 46, 49, 50, 0,
  /* 45 */ 28, 31, 35, 29, 33, 34, 30, 43, 44, 36, 45, 47, 48, 46, 49, 50, 32, 55, 51, 53, 54, 52, 57, 58, 56, 59, 61, 62, 60, 63, 64, 0,
  /* 77 */ 3, 14, 7, 1, 4, 67, 66, 65, 0,
  /* 86 */ 38, 37, 2, 14, 7, 1, 42, 39, 98, 95, 97, 96, 94, 99, 0,
  /* 101 */ 3, 14, 7, 1, 4, 67, 66, 65, 5, 73, 72, 71, 112, 114, 0,
  /* 116 */ 3, 14, 7, 1, 4, 67, 66, 65, 5, 73, 72, 71, 6, 70, 69, 68, 112, 113, 114, 115, 116, 0,
  /* 138 */ 10, 2, 14, 7, 1, 11, 75, 77, 76, 74, 117, 0,
  /* 150 */ 10, 2, 14, 7, 1, 11, 75, 77, 76, 74, 12, 83, 85, 84, 82, 117, 119, 120, 122, 125, 0,
  /* 171 */ 10, 2, 14, 7, 1, 11, 75, 77, 76, 74, 12, 83, 85, 84, 82, 13, 79, 81, 80, 78, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 0,
  /* 203 */ 20, 15, 21, 92, 22, 91, 23, 90, 24, 89, 25, 88, 26, 87, 27, 86, 128, 129, 130, 131, 132, 133, 134, 135, 0,
  /* 228 */ 17, 15, 19, 93, 136, 0,
  /* 234 */ 38, 37, 2, 14, 7, 1, 42, 39, 98, 95, 97, 96, 94, 99, 137, 138, 0,
  /* 251 */ 38, 37, 2, 14, 7, 1, 42, 39, 98, 95, 97, 96, 94, 99, 40, 110, 107, 109, 108, 106, 111, 137, 138, 140, 142, 143, 145, 148, 150, 0,
  /* 281 */ 38, 37, 2, 14, 7, 1, 42, 39, 98, 95, 97, 96, 94, 99, 40, 110, 107, 109, 108, 106, 111, 41, 104, 101, 103, 102, 100, 105, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 0,
  /* 327 */ 38, 37, 2, 14, 7, 1, 42, 39, 98, 95, 97, 96, 94, 99, 40, 110, 107, 109, 108, 106, 111, 41, 104, 101, 103, 102, 100, 105, 154, 155, 0,
};

static const MCRegisterDesc AArch64RegDesc[] = { // Descriptors
  { 3, 0, 0, 0, 0, 0 },
  { 3084, 16, 16, 4, 39889, 0 },
  { 3072, 1827, 2458, 8, 39889, 33 },
  { 3079, 16, 16, 4, 39889, 0 },
  { 3088, 1825, 1981, 8, 39889, 33 },
  { 3106, 16, 16, 4, 39889, 0 },
  { 3076, 507, 16, 8, 39889, 33 },
  { 2827, 16, 16, 4, 39889, 0 },
  { 3075, 16, 2468, 4, 39458, 0 },
  { 3095, 16, 1435, 4, 9520, 0 },
  { 3102, 2493, 1979, 8, 9520, 33 },
  { 2824, 597, 16, 45, 0, 82 },
  { 237, 16, 869, 4, 13313, 0 },
  { 615, 16, 939, 4, 13313, 0 },
  { 865, 16, 1009, 4, 13313, 0 },
  { 1167, 16, 1219, 4, 13313, 0 },
  { 1421, 16, 709, 4, 13313, 0 },
  { 1729, 16, 709, 4, 13313, 0 },
  { 1946, 16, 709, 4, 13313, 0 },
  { 2221, 16, 709, 4, 13313, 0 },
  { 2472, 16, 1149, 4, 13313, 0 },
  { 2732, 16, 1149, 4, 13313, 0 },
  { 0, 16, 1149, 4, 13313, 0 },
  { 322, 16, 1149, 4, 13313, 0 },
  { 698, 16, 629, 4, 13313, 0 },
  { 937, 16, 629, 4, 13313, 0 },
  { 1242, 16, 629, 4, 13313, 0 },
  { 1488, 16, 629, 4, 13313, 0 },
  { 1802, 16, 1365, 4, 13313, 0 },
  { 2013, 16, 1365, 4, 13313, 0 },
  { 2312, 16, 1365, 4, 13313, 0 },
  { 2540, 16, 1365, 4, 13313, 0 },
  { 79, 16, 1079, 4, 13313, 0 },
  { 431, 16, 1079, 4, 13313, 0 },
  { 797, 16, 1079, 4, 13313, 0 },
  { 1067, 16, 1079, 4, 13313, 0 },
  { 1345, 16, 1295, 4, 13313, 0 },
  { 1621, 16, 1295, 4, 13313, 0 },
  { 1870, 16, 1295, 4, 13313, 0 },
  { 2113, 16, 1295, 4, 13313, 0 },
  { 2380, 16, 799, 4, 13313, 0 },
  { 2640, 16, 799, 4, 13313, 0 },
  { 147, 16, 799, 4, 13313, 0 },
  { 531, 16, 799, 4, 13313, 0 },
  { 242, 2232, 872, 1, 39377, 3 },
  { 620, 2232, 942, 1, 39377, 3 },
  { 870, 2232, 1012, 1, 39377, 3 },
  { 1172, 2232, 1222, 1, 39377, 3 },
  { 1426, 2232, 712, 1, 39377, 3 },
  { 1734, 2232, 712, 1, 39377, 3 },
  { 1951, 2232, 712, 1, 39377, 3 },
  { 2226, 2232, 712, 1, 39377, 3 },
  { 2484, 2232, 1152, 1, 39377, 3 },
  { 2744, 2232, 1152, 1, 39377, 3 },
  { 13, 2232, 1152, 1, 39377, 3 },
  { 336, 2232, 1152, 1, 39377, 3 },
  { 713, 2232, 632, 1, 39377, 3 },
  { 953, 2232, 632, 1, 39377, 3 },
  { 1258, 2232, 632, 1, 39377, 3 },
  { 1504, 2232, 632, 1, 39377, 3 },
  { 1818, 2232, 1368, 1, 39377, 3 },
  { 2029, 2232, 1368, 1, 39377, 3 },
  { 2328, 2232, 1368, 1, 39377, 3 },
  { 2556, 2232, 1368, 1, 39377, 3 },
  { 95, 2232, 1082, 1, 39377, 3 },
  { 447, 2232, 1082, 1, 39377, 3 },
  { 813, 2232, 1082, 1, 39377, 3 },
  { 1083, 2232, 1082, 1, 39377, 3 },
  { 1361, 2232, 1298, 1, 39377, 3 },
  { 1637, 2232, 1298, 1, 39377, 3 },
  { 1886, 2232, 1298, 1, 39377, 3 },
  { 2129, 2232, 1298, 1, 39377, 3 },
  { 2396, 2232, 802, 1, 39377, 3 },
  { 2656, 2232, 802, 1, 39377, 3 },
  { 163, 2232, 802, 1, 39377, 3 },
  { 547, 2232, 802, 1, 39377, 3 },
  { 262, 2234, 870, 3, 38593, 3 },
  { 639, 2234, 940, 3, 38593, 3 },
  { 886, 2234, 1010, 3, 38593, 3 },
  { 1187, 2234, 1220, 3, 38593, 3 },
  { 1441, 2234, 710, 3, 38593, 3 },
  { 1749, 2234, 710, 3, 38593, 3 },
  { 1966, 2234, 710, 3, 38593, 3 },
  { 2241, 2234, 710, 3, 38593, 3 },
  { 2487, 2234, 1150, 3, 38593, 3 },
  { 2747, 2234, 1150, 3, 38593, 3 },
  { 17, 2234, 1150, 3, 38593, 3 },
  { 340, 2234, 1150, 3, 38593, 3 },
  { 717, 2234, 630, 3, 38593, 3 },
  { 957, 2234, 630, 3, 38593, 3 },
  { 1262, 2234, 630, 3, 38593, 3 },
  { 1508, 2234, 630, 3, 38593, 3 },
  { 1822, 2234, 1366, 3, 38593, 3 },
  { 2033, 2234, 1366, 3, 38593, 3 },
  { 2332, 2234, 1366, 3, 38593, 3 },
  { 2560, 2234, 1366, 3, 38593, 3 },
  { 99, 2234, 1080, 3, 38593, 3 },
  { 451, 2234, 1080, 3, 38593, 3 },
  { 817, 2234, 1080, 3, 38593, 3 },
  { 1087, 2234, 1080, 3, 38593, 3 },
  { 1365, 2234, 1296, 3, 38593, 3 },
  { 1641, 2234, 1296, 3, 38593, 3 },
  { 1890, 2234, 1296, 3, 38593, 3 },
  { 2133, 2234, 1296, 3, 38593, 3 },
  { 2400, 2234, 800, 3, 38593, 3 },
  { 2660, 2234, 800, 3, 38593, 3 },
  { 167, 2234, 800, 3, 38593, 3 },
  { 551, 2234, 800, 3, 38593, 3 },
  { 269, 16, 1292, 4, 38593, 0 },
  { 645, 16, 349, 4, 38593, 0 },
  { 892, 16, 349, 4, 38593, 0 },
  { 1193, 16, 349, 4, 38593, 0 },
  { 1447, 16, 349, 4, 38593, 0 },
  { 1755, 16, 349, 4, 38593, 0 },
  { 1972, 16, 349, 4, 38593, 0 },
  { 2247, 16, 349, 4, 38593, 0 },
  { 2493, 16, 349, 4, 38593, 0 },
  { 2753, 16, 349, 4, 38593, 0 },
  { 24, 16, 349, 4, 38593, 0 },
  { 348, 16, 349, 4, 38593, 0 },
  { 725, 16, 349, 4, 38593, 0 },
  { 965, 16, 349, 4, 38593, 0 },
  { 1270, 16, 349, 4, 38593, 0 },
  { 1516, 16, 349, 4, 38593, 0 },
  { 274, 2245, 904, 0, 34737, 3 },
  { 650, 2245, 974, 0, 34737, 3 },
  { 897, 2245, 1044, 0, 34737, 3 },
  { 1198, 2245, 1254, 0, 34737, 3 },
  { 1452, 2245, 744, 0, 34737, 3 },
  { 1760, 2245, 744, 0, 34737, 3 },
  { 1977, 2245, 744, 0, 34737, 3 },
  { 2252, 2245, 744, 0, 34737, 3 },
  { 2498, 2245, 1184, 0, 34737, 3 },
  { 2758, 2245, 1184, 0, 34737, 3 },
  { 30, 2245, 1184, 0, 34737, 3 },
  { 354, 2245, 1184, 0, 34737, 3 },
  { 731, 2245, 664, 0, 34737, 3 },
  { 971, 2245, 664, 0, 34737, 3 },
  { 1276, 2245, 664, 0, 34737, 3 },
  { 1522, 2245, 664, 0, 34737, 3 },
  { 1838, 2245, 1400, 0, 34737, 3 },
  { 2049, 2245, 1400, 0, 34737, 3 },
  { 2348, 2245, 1400, 0, 34737, 3 },
  { 2576, 2245, 1400, 0, 34737, 3 },
  { 115, 2245, 1114, 0, 34737, 3 },
  { 467, 2245, 1114, 0, 34737, 3 },
  { 833, 2245, 1114, 0, 34737, 3 },
  { 1103, 2245, 1114, 0, 34737, 3 },
  { 1381, 2245, 1330, 0, 34737, 3 },
  { 1657, 2245, 1330, 0, 34737, 3 },
  { 1906, 2245, 1330, 0, 34737, 3 },
  { 2149, 2245, 1330, 0, 34737, 3 },
  { 2416, 2245, 834, 0, 34737, 3 },
  { 2676, 2245, 834, 0, 34737, 3 },
  { 183, 2245, 834, 0, 34737, 3 },
  { 567, 2245, 834, 0, 34737, 3 },
  { 294, 2233, 871, 2, 33665, 3 },
  { 669, 2233, 941, 2, 33665, 3 },
  { 915, 2233, 1011, 2, 33665, 3 },
  { 1215, 2233, 1221, 2, 33665, 3 },
  { 1467, 2233, 711, 2, 33665, 3 },
  { 1775, 2233, 711, 2, 33665, 3 },
  { 1992, 2233, 711, 2, 33665, 3 },
  { 2267, 2233, 711, 2, 33665, 3 },
  { 2513, 2233, 1151, 2, 33665, 3 },
  { 2773, 2233, 1151, 2, 33665, 3 },
  { 47, 2233, 1151, 2, 33665, 3 },
  { 372, 2233, 1151, 2, 33665, 3 },
  { 750, 2233, 631, 2, 33665, 3 },
  { 991, 2233, 631, 2, 33665, 3 },
  { 1296, 2233, 631, 2, 33665, 3 },
  { 1542, 2233, 631, 2, 33665, 3 },
  { 1842, 2233, 1367, 2, 33665, 3 },
  { 2053, 2233, 1367, 2, 33665, 3 },
  { 2352, 2233, 1367, 2, 33665, 3 },
  { 2580, 2233, 1367, 2, 33665, 3 },
  { 119, 2233, 1081, 2, 33665, 3 },
  { 471, 2233, 1081, 2, 33665, 3 },
  { 837, 2233, 1081, 2, 33665, 3 },
  { 1107, 2233, 1081, 2, 33665, 3 },
  { 1385, 2233, 1297, 2, 33665, 3 },
  { 1661, 2233, 1297, 2, 33665, 3 },
  { 1910, 2233, 1297, 2, 33665, 3 },
  { 2153, 2233, 1297, 2, 33665, 3 },
  { 2420, 2233, 801, 2, 33665, 3 },
  { 2680, 2233, 801, 2, 33665, 3 },
  { 187, 2233, 801, 2, 33665, 3 },
  { 571, 2233, 801, 2, 33665, 3 },
  { 301, 16, 2444, 4, 33697, 0 },
  { 675, 16, 2439, 4, 33697, 0 },
  { 918, 16, 493, 4, 33697, 0 },
  { 1221, 16, 487, 4, 33697, 0 },
  { 1470, 16, 263, 4, 33697, 0 },
  { 1781, 16, 256, 4, 33697, 0 },
  { 1995, 16, 137, 4, 33697, 0 },
  { 2273, 16, 129, 4, 33697, 0 },
  { 2516, 16, 129, 4, 33697, 0 },
  { 2779, 16, 121, 4, 33697, 0 },
  { 51, 16, 121, 4, 33697, 0 },
  { 380, 16, 113, 4, 33697, 0 },
  { 754, 16, 113, 4, 33697, 0 },
  { 999, 16, 105, 4, 33697, 0 },
  { 1300, 16, 105, 4, 33697, 0 },
  { 1550, 16, 97, 4, 33697, 0 },
  { 1846, 16, 97, 4, 33697, 0 },
  { 2061, 16, 89, 4, 33697, 0 },
  { 2356, 16, 89, 4, 33697, 0 },
  { 2588, 16, 81, 4, 33697, 0 },
  { 123, 16, 81, 4, 33697, 0 },
  { 479, 16, 73, 4, 33697, 0 },
  { 841, 16, 207, 4, 33697, 0 },
  { 1115, 16, 199, 4, 33697, 0 },
  { 1389, 16, 287, 4, 33697, 0 },
  { 1669, 16, 280, 4, 33697, 0 },
  { 1914, 16, 785, 4, 33697, 0 },
  { 2161, 16, 779, 4, 33697, 0 },
  { 2424, 16, 2429, 4, 33697, 0 },
  { 2688, 16, 2434, 4, 31986, 0 },
  { 191, 16, 1439, 4, 31986, 0 },
  { 304, 2427, 2455, 8, 33633, 33 },
  { 681, 2427, 2452, 8, 33633, 33 },
  { 921, 2427, 503, 8, 33633, 33 },
  { 1227, 2427, 499, 8, 33633, 33 },
  { 1473, 2427, 275, 8, 33633, 33 },
  { 1787, 2427, 270, 8, 33633, 33 },
  { 1998, 2427, 193, 8, 33633, 33 },
  { 2297, 2427, 187, 8, 33633, 33 },
  { 2519, 2427, 187, 8, 33633, 33 },
  { 2803, 2427, 181, 8, 33633, 33 },
  { 55, 2427, 181, 8, 33633, 33 },
  { 406, 2427, 175, 8, 33633, 33 },
  { 758, 2427, 175, 8, 33633, 33 },
  { 1027, 2427, 169, 8, 33633, 33 },
  { 1304, 2427, 169, 8, 33633, 33 },
  { 1580, 2427, 163, 8, 33633, 33 },
  { 1850, 2427, 163, 8, 33633, 33 },
  { 2093, 2427, 157, 8, 33633, 33 },
  { 2360, 2427, 157, 8, 33633, 33 },
  { 2620, 2427, 151, 8, 33633, 33 },
  { 127, 2427, 151, 8, 33633, 33 },
  { 511, 2427, 145, 8, 33633, 33 },
  { 845, 2427, 221, 8, 33633, 33 },
  { 1147, 2427, 215, 8, 33633, 33 },
  { 1393, 2427, 299, 8, 33633, 33 },
  { 1701, 2427, 294, 8, 33633, 33 },
  { 1918, 2427, 795, 8, 33633, 33 },
  { 2193, 2427, 791, 8, 33633, 33 },
  { 2428, 2427, 2449, 8, 33633, 33 },
  { 319, 1837, 927, 16, 24049, 44 },
  { 695, 1837, 997, 16, 24049, 44 },
  { 934, 1837, 1067, 16, 24049, 44 },
  { 1239, 1837, 1277, 16, 24049, 44 },
  { 1485, 1837, 767, 16, 24049, 44 },
  { 1799, 1837, 767, 16, 24049, 44 },
  { 2010, 1837, 767, 16, 24049, 44 },
  { 2309, 1837, 767, 16, 24049, 44 },
  { 2525, 1837, 1207, 16, 24049, 44 },
  { 2809, 1837, 1207, 16, 24049, 44 },
  { 62, 1837, 1207, 16, 24049, 44 },
  { 420, 1837, 1207, 16, 24049, 44 },
  { 773, 1837, 687, 16, 24049, 44 },
  { 1043, 1837, 687, 16, 24049, 44 },
  { 1318, 1837, 687, 16, 24049, 44 },
  { 1594, 1837, 687, 16, 24049, 44 },
  { 1866, 1837, 1423, 16, 24049, 44 },
  { 2109, 1837, 1423, 16, 24049, 44 },
  { 2376, 1837, 1423, 16, 24049, 44 },
  { 2636, 1837, 1423, 16, 24049, 44 },
  { 143, 1837, 1137, 16, 24049, 44 },
  { 527, 1837, 1137, 16, 24049, 44 },
  { 861, 1837, 1137, 16, 24049, 44 },
  { 1163, 1837, 1137, 16, 24049, 44 },
  { 1409, 1837, 1353, 16, 24049, 44 },
  { 1717, 1837, 1353, 16, 24049, 44 },
  { 1934, 1837, 1353, 16, 24049, 44 },
  { 2209, 1837, 1353, 16, 24049, 44 },
  { 2436, 1837, 857, 16, 24049, 44 },
  { 2696, 1837, 857, 16, 24049, 44 },
  { 199, 1837, 857, 16, 24049, 44 },
  { 587, 1837, 857, 16, 24049, 44 },
  { 235, 598, 2005, 46, 0, 82 },
  { 240, 626, 2086, 13, 6024, 41 },
  { 618, 626, 2038, 13, 6024, 41 },
  { 868, 626, 2062, 13, 5976, 41 },
  { 1170, 626, 2014, 13, 5976, 41 },
  { 1424, 626, 2074, 13, 5928, 41 },
  { 1732, 626, 2026, 13, 5928, 41 },
  { 1949, 626, 2050, 13, 5880, 41 },
  { 2224, 626, 2002, 13, 5880, 41 },
  { 260, 614, 2052, 30, 280, 73 },
  { 637, 614, 2004, 30, 280, 73 },
  { 272, 16, 2091, 4, 31960, 0 },
  { 648, 16, 2043, 4, 31960, 0 },
  { 895, 16, 2067, 4, 31928, 0 },
  { 1196, 16, 2019, 4, 31928, 0 },
  { 1450, 16, 2079, 4, 31896, 0 },
  { 1758, 16, 2031, 4, 31896, 0 },
  { 1975, 16, 2055, 4, 31864, 0 },
  { 2250, 16, 2007, 4, 31864, 0 },
  { 2496, 16, 2085, 4, 31832, 0 },
  { 2756, 16, 2037, 4, 31832, 0 },
  { 28, 16, 2061, 4, 31800, 0 },
  { 352, 16, 2013, 4, 31800, 0 },
  { 729, 16, 2073, 4, 31768, 0 },
  { 969, 16, 2025, 4, 31768, 0 },
  { 1274, 16, 2049, 4, 31736, 0 },
  { 1520, 16, 2001, 4, 31736, 0 },
  { 292, 622, 2075, 23, 936, 68 },
  { 667, 622, 2027, 23, 936, 68 },
  { 913, 622, 2051, 23, 856, 68 },
  { 1213, 622, 2003, 23, 856, 68 },
  { 297, 16, 16, 4, 29120, 0 },
  { 2851, 16, 926, 4, 33553, 0 },
  { 2878, 16, 996, 4, 33553, 0 },
  { 2898, 16, 1066, 4, 33553, 0 },
  { 2918, 16, 1276, 4, 33553, 0 },
  { 2938, 16, 766, 4, 33553, 0 },
  { 2958, 16, 766, 4, 33553, 0 },
  { 2978, 16, 766, 4, 33553, 0 },
  { 2998, 16, 766, 4, 33553, 0 },
  { 3018, 16, 1206, 4, 33553, 0 },
  { 3038, 16, 1206, 4, 33553, 0 },
  { 2830, 16, 1206, 4, 33553, 0 },
  { 2857, 16, 1206, 4, 33553, 0 },
  { 2884, 16, 686, 4, 33553, 0 },
  { 2904, 16, 686, 4, 33553, 0 },
  { 2924, 16, 686, 4, 33553, 0 },
  { 2944, 16, 686, 4, 33553, 0 },
  { 2964, 16, 1422, 4, 33553, 0 },
  { 2984, 16, 1422, 4, 33553, 0 },
  { 3004, 16, 1422, 4, 33553, 0 },
  { 3024, 16, 1422, 4, 33553, 0 },
  { 2837, 16, 1136, 4, 33553, 0 },
  { 2864, 16, 1136, 4, 33553, 0 },
  { 2891, 16, 1136, 4, 33553, 0 },
  { 2911, 16, 1136, 4, 33553, 0 },
  { 2931, 16, 1352, 4, 33553, 0 },
  { 2951, 16, 1352, 4, 33553, 0 },
  { 2971, 16, 1352, 4, 33553, 0 },
  { 2991, 16, 1352, 4, 33553, 0 },
  { 3011, 16, 856, 4, 33553, 0 },
  { 3031, 16, 856, 4, 33553, 0 },
  { 2844, 16, 856, 4, 33553, 0 },
  { 2871, 16, 856, 4, 33553, 0 },
  { 631, 2236, 460, 77, 7025, 101 },
  { 880, 2236, 1468, 77, 7025, 101 },
  { 1181, 2236, 442, 77, 7025, 101 },
  { 1435, 2236, 442, 77, 7025, 101 },
  { 1743, 2236, 442, 77, 7025, 101 },
  { 1960, 2236, 442, 77, 7025, 101 },
  { 2235, 2236, 442, 77, 7025, 101 },
  { 2481, 2236, 442, 77, 7025, 101 },
  { 2741, 2236, 442, 77, 7025, 101 },
  { 10, 2236, 442, 77, 7025, 101 },
  { 332, 2236, 442, 77, 7025, 101 },
  { 709, 2236, 442, 77, 7025, 101 },
  { 949, 2236, 442, 77, 7025, 101 },
  { 1254, 2236, 442, 77, 7025, 101 },
  { 1500, 2236, 442, 77, 7025, 101 },
  { 1814, 2236, 442, 77, 7025, 101 },
  { 2025, 2236, 442, 77, 7025, 101 },
  { 2324, 2236, 442, 77, 7025, 101 },
  { 2552, 2236, 442, 77, 7025, 101 },
  { 91, 2236, 442, 77, 7025, 101 },
  { 443, 2236, 442, 77, 7025, 101 },
  { 809, 2236, 442, 77, 7025, 101 },
  { 1079, 2236, 442, 77, 7025, 101 },
  { 1357, 2236, 442, 77, 7025, 101 },
  { 1633, 2236, 442, 77, 7025, 101 },
  { 1882, 2236, 442, 77, 7025, 101 },
  { 2125, 2236, 442, 77, 7025, 101 },
  { 2392, 2236, 442, 77, 7025, 101 },
  { 2652, 2236, 442, 77, 7025, 101 },
  { 159, 2236, 442, 77, 7025, 101 },
  { 543, 2236, 442, 77, 7025, 101 },
  { 253, 2227, 442, 77, 23776, 2 },
  { 1175, 2368, 1822, 116, 1089, 108 },
  { 1429, 2368, 1822, 116, 1089, 108 },
  { 1737, 2368, 1822, 116, 1089, 108 },
  { 1954, 2368, 1822, 116, 1089, 108 },
  { 2229, 2368, 1822, 116, 1089, 108 },
  { 2475, 2368, 1822, 116, 1089, 108 },
  { 2735, 2368, 1822, 116, 1089, 108 },
  { 4, 2368, 1822, 116, 1089, 108 },
  { 326, 2368, 1822, 116, 1089, 108 },
  { 702, 2368, 1822, 116, 1089, 108 },
  { 941, 2368, 1822, 116, 1089, 108 },
  { 1246, 2368, 1822, 116, 1089, 108 },
  { 1492, 2368, 1822, 116, 1089, 108 },
  { 1806, 2368, 1822, 116, 1089, 108 },
  { 2017, 2368, 1822, 116, 1089, 108 },
  { 2316, 2368, 1822, 116, 1089, 108 },
  { 2544, 2368, 1822, 116, 1089, 108 },
  { 83, 2368, 1822, 116, 1089, 108 },
  { 435, 2368, 1822, 116, 1089, 108 },
  { 801, 2368, 1822, 116, 1089, 108 },
  { 1071, 2368, 1822, 116, 1089, 108 },
  { 1349, 2368, 1822, 116, 1089, 108 },
  { 1625, 2368, 1822, 116, 1089, 108 },
  { 1874, 2368, 1822, 116, 1089, 108 },
  { 2117, 2368, 1822, 116, 1089, 108 },
  { 2384, 2368, 1822, 116, 1089, 108 },
  { 2644, 2368, 1822, 116, 1089, 108 },
  { 151, 2368, 1822, 116, 1089, 108 },
  { 535, 2368, 1822, 116, 1089, 108 },
  { 245, 2390, 1822, 116, 3632, 113 },
  { 623, 2205, 1822, 116, 4864, 99 },
  { 873, 2346, 1822, 116, 23088, 5 },
  { 877, 334, 1494, 101, 4033, 114 },
  { 1178, 334, 478, 101, 4033, 114 },
  { 1432, 334, 478, 101, 4033, 114 },
  { 1740, 334, 478, 101, 4033, 114 },
  { 1957, 334, 478, 101, 4033, 114 },
  { 2232, 334, 478, 101, 4033, 114 },
  { 2478, 334, 478, 101, 4033, 114 },
  { 2738, 334, 478, 101, 4033, 114 },
  { 7, 334, 478, 101, 4033, 114 },
  { 329, 334, 478, 101, 4033, 114 },
  { 705, 334, 478, 101, 4033, 114 },
  { 945, 334, 478, 101, 4033, 114 },
  { 1250, 334, 478, 101, 4033, 114 },
  { 1496, 334, 478, 101, 4033, 114 },
  { 1810, 334, 478, 101, 4033, 114 },
  { 2021, 334, 478, 101, 4033, 114 },
  { 2320, 334, 478, 101, 4033, 114 },
  { 2548, 334, 478, 101, 4033, 114 },
  { 87, 334, 478, 101, 4033, 114 },
  { 439, 334, 478, 101, 4033, 114 },
  { 805, 334, 478, 101, 4033, 114 },
  { 1075, 334, 478, 101, 4033, 114 },
  { 1353, 334, 478, 101, 4033, 114 },
  { 1629, 334, 478, 101, 4033, 114 },
  { 1878, 334, 478, 101, 4033, 114 },
  { 2121, 334, 478, 101, 4033, 114 },
  { 2388, 334, 478, 101, 4033, 114 },
  { 2648, 334, 478, 101, 4033, 114 },
  { 155, 334, 478, 101, 4033, 114 },
  { 539, 334, 478, 101, 4033, 114 },
  { 249, 352, 478, 101, 5088, 104 },
  { 627, 2414, 478, 101, 23312, 10 },
  { 642, 436, 16, 5, 6209, 29 },
  { 889, 436, 16, 5, 6209, 29 },
  { 1190, 436, 16, 5, 6209, 29 },
  { 1444, 436, 16, 5, 6209, 29 },
  { 1752, 436, 16, 5, 6209, 29 },
  { 1969, 436, 16, 5, 6209, 29 },
  { 2244, 436, 16, 5, 6209, 29 },
  { 2490, 436, 16, 5, 6209, 29 },
  { 2750, 436, 16, 5, 6209, 29 },
  { 21, 436, 16, 5, 6209, 29 },
  { 344, 436, 16, 5, 6209, 29 },
  { 721, 436, 16, 5, 6209, 29 },
  { 961, 436, 16, 5, 6209, 29 },
  { 1266, 436, 16, 5, 6209, 29 },
  { 1512, 436, 16, 5, 6209, 29 },
  { 265, 2463, 16, 5, 20624, 26 },
  { 661, 1859, 466, 138, 6161, 120 },
  { 907, 1859, 1474, 138, 6161, 120 },
  { 1207, 1859, 448, 138, 6161, 120 },
  { 1461, 1859, 448, 138, 6161, 120 },
  { 1769, 1859, 448, 138, 6161, 120 },
  { 1986, 1859, 448, 138, 6161, 120 },
  { 2261, 1859, 448, 138, 6161, 120 },
  { 2507, 1859, 448, 138, 6161, 120 },
  { 2767, 1859, 448, 138, 6161, 120 },
  { 40, 1859, 448, 138, 6161, 120 },
  { 364, 1859, 448, 138, 6161, 120 },
  { 742, 1859, 448, 138, 6161, 120 },
  { 983, 1859, 448, 138, 6161, 120 },
  { 1288, 1859, 448, 138, 6161, 120 },
  { 1534, 1859, 448, 138, 6161, 120 },
  { 1834, 1859, 448, 138, 6161, 120 },
  { 2045, 1859, 448, 138, 6161, 120 },
  { 2344, 1859, 448, 138, 6161, 120 },
  { 2572, 1859, 448, 138, 6161, 120 },
  { 111, 1859, 448, 138, 6161, 120 },
  { 463, 1859, 448, 138, 6161, 120 },
  { 829, 1859, 448, 138, 6161, 120 },
  { 1099, 1859, 448, 138, 6161, 120 },
  { 1377, 1859, 448, 138, 6161, 120 },
  { 1653, 1859, 448, 138, 6161, 120 },
  { 1902, 1859, 448, 138, 6161, 120 },
  { 2145, 1859, 448, 138, 6161, 120 },
  { 2412, 1859, 448, 138, 6161, 120 },
  { 2672, 1859, 448, 138, 6161, 120 },
  { 179, 1859, 448, 138, 6161, 120 },
  { 563, 1859, 448, 138, 6161, 120 },
  { 285, 1877, 448, 138, 23776, 14 },
  { 1201, 2282, 1823, 171, 1009, 127 },
  { 1455, 2282, 1823, 171, 1009, 127 },
  { 1763, 2282, 1823, 171, 1009, 127 },
  { 1980, 2282, 1823, 171, 1009, 127 },
  { 2255, 2282, 1823, 171, 1009, 127 },
  { 2501, 2282, 1823, 171, 1009, 127 },
  { 2761, 2282, 1823, 171, 1009, 127 },
  { 34, 2282, 1823, 171, 1009, 127 },
  { 358, 2282, 1823, 171, 1009, 127 },
  { 735, 2282, 1823, 171, 1009, 127 },
  { 975, 2282, 1823, 171, 1009, 127 },
  { 1280, 2282, 1823, 171, 1009, 127 },
  { 1526, 2282, 1823, 171, 1009, 127 },
  { 1826, 2282, 1823, 171, 1009, 127 },
  { 2037, 2282, 1823, 171, 1009, 127 },
  { 2336, 2282, 1823, 171, 1009, 127 },
  { 2564, 2282, 1823, 171, 1009, 127 },
  { 103, 2282, 1823, 171, 1009, 127 },
  { 455, 2282, 1823, 171, 1009, 127 },
  { 821, 2282, 1823, 171, 1009, 127 },
  { 1091, 2282, 1823, 171, 1009, 127 },
  { 1369, 2282, 1823, 171, 1009, 127 },
  { 1645, 2282, 1823, 171, 1009, 127 },
  { 1894, 2282, 1823, 171, 1009, 127 },
  { 2137, 2282, 1823, 171, 1009, 127 },
  { 2404, 2282, 1823, 171, 1009, 127 },
  { 2664, 2282, 1823, 171, 1009, 127 },
  { 171, 2282, 1823, 171, 1009, 127 },
  { 555, 2282, 1823, 171, 1009, 127 },
  { 277, 2314, 1823, 171, 3632, 132 },
  { 653, 2173, 1823, 171, 4864, 118 },
  { 900, 2250, 1823, 171, 23088, 17 },
  { 904, 2108, 1497, 150, 3969, 133 },
  { 1204, 2108, 481, 150, 3969, 133 },
  { 1458, 2108, 481, 150, 3969, 133 },
  { 1766, 2108, 481, 150, 3969, 133 },
  { 1983, 2108, 481, 150, 3969, 133 },
  { 2258, 2108, 481, 150, 3969, 133 },
  { 2504, 2108, 481, 150, 3969, 133 },
  { 2764, 2108, 481, 150, 3969, 133 },
  { 37, 2108, 481, 150, 3969, 133 },
  { 361, 2108, 481, 150, 3969, 133 },
  { 738, 2108, 481, 150, 3969, 133 },
  { 979, 2108, 481, 150, 3969, 133 },
  { 1284, 2108, 481, 150, 3969, 133 },
  { 1530, 2108, 481, 150, 3969, 133 },
  { 1830, 2108, 481, 150, 3969, 133 },
  { 2041, 2108, 481, 150, 3969, 133 },
  { 2340, 2108, 481, 150, 3969, 133 },
  { 2568, 2108, 481, 150, 3969, 133 },
  { 107, 2108, 481, 150, 3969, 133 },
  { 459, 2108, 481, 150, 3969, 133 },
  { 825, 2108, 481, 150, 3969, 133 },
  { 1095, 2108, 481, 150, 3969, 133 },
  { 1373, 2108, 481, 150, 3969, 133 },
  { 1649, 2108, 481, 150, 3969, 133 },
  { 1898, 2108, 481, 150, 3969, 133 },
  { 2141, 2108, 481, 150, 3969, 133 },
  { 2408, 2108, 481, 150, 3969, 133 },
  { 2668, 2108, 481, 150, 3969, 133 },
  { 175, 2108, 481, 150, 3969, 133 },
  { 559, 2108, 481, 150, 3969, 133 },
  { 281, 2129, 481, 150, 5088, 123 },
  { 657, 2150, 481, 150, 23312, 22 },
  { 3044, 2745, 16, 203, 560, 146 },
  { 2276, 2720, 16, 203, 418, 137 },
  { 2782, 2695, 16, 203, 418, 137 },
  { 384, 2670, 16, 203, 418, 137 },
  { 1003, 2645, 16, 203, 418, 137 },
  { 1554, 2620, 16, 203, 418, 137 },
  { 2065, 2595, 16, 203, 418, 137 },
  { 2592, 2570, 16, 203, 418, 137 },
  { 483, 2545, 16, 203, 418, 137 },
  { 1119, 2520, 16, 203, 418, 137 },
  { 1673, 2495, 16, 203, 418, 137 },
  { 2165, 2470, 16, 203, 418, 137 },
  { 3091, 2099, 1328, 10, 8144, 38 },
  { 672, 391, 2441, 10, 6114, 38 },
  { 1218, 394, 489, 10, 6114, 38 },
  { 1778, 397, 258, 10, 6114, 38 },
  { 2270, 400, 75, 10, 6114, 38 },
  { 2776, 403, 75, 10, 6114, 38 },
  { 376, 406, 75, 10, 6114, 38 },
  { 995, 409, 75, 10, 6114, 38 },
  { 1546, 412, 75, 10, 6114, 38 },
  { 2057, 415, 75, 10, 6114, 38 },
  { 2584, 418, 75, 10, 6114, 38 },
  { 475, 421, 75, 10, 6114, 38 },
  { 1111, 424, 201, 10, 6114, 38 },
  { 1665, 427, 282, 10, 6114, 38 },
  { 2157, 430, 781, 10, 6114, 38 },
  { 2684, 433, 2431, 10, 24146, 35 },
  { 3099, 1973, 16, 228, 9474, 155 },
  { 3068, 1871, 2432, 228, 24096, 32 },
  { 678, 1967, 2432, 228, 6066, 155 },
  { 1224, 1961, 490, 228, 6066, 155 },
  { 1784, 1955, 259, 228, 6066, 155 },
  { 2294, 1949, 76, 228, 6066, 155 },
  { 2800, 1943, 76, 228, 6066, 155 },
  { 402, 1937, 76, 228, 6066, 155 },
  { 1023, 1931, 76, 228, 6066, 155 },
  { 1576, 1925, 76, 228, 6066, 155 },
  { 2089, 1919, 76, 228, 6066, 155 },
  { 2616, 1913, 76, 228, 6066, 155 },
  { 507, 1907, 76, 228, 6066, 155 },
  { 1143, 1901, 202, 228, 6066, 155 },
  { 1697, 1895, 283, 228, 6066, 155 },
  { 2189, 1889, 782, 228, 6066, 155 },
  { 692, 1512, 472, 234, 5265, 158 },
  { 931, 1512, 1480, 234, 5265, 158 },
  { 1236, 1512, 454, 234, 5265, 158 },
  { 1482, 1512, 454, 234, 5265, 158 },
  { 1796, 1512, 454, 234, 5265, 158 },
  { 2007, 1512, 454, 234, 5265, 158 },
  { 2306, 1512, 454, 234, 5265, 158 },
  { 2534, 1512, 454, 234, 5265, 158 },
  { 2818, 1512, 454, 234, 5265, 158 },
  { 72, 1512, 454, 234, 5265, 158 },
  { 416, 1512, 454, 234, 5265, 158 },
  { 769, 1512, 454, 234, 5265, 158 },
  { 1039, 1512, 454, 234, 5265, 158 },
  { 1330, 1512, 454, 234, 5265, 158 },
  { 1606, 1512, 454, 234, 5265, 158 },
  { 1862, 1512, 454, 234, 5265, 158 },
  { 2105, 1512, 454, 234, 5265, 158 },
  { 2372, 1512, 454, 234, 5265, 158 },
  { 2632, 1512, 454, 234, 5265, 158 },
  { 139, 1512, 454, 234, 5265, 158 },
  { 523, 1512, 454, 234, 5265, 158 },
  { 857, 1512, 454, 234, 5265, 158 },
  { 1159, 1512, 454, 234, 5265, 158 },
  { 1405, 1512, 454, 234, 5265, 158 },
  { 1713, 1512, 454, 234, 5265, 158 },
  { 1930, 1512, 454, 234, 5265, 158 },
  { 2205, 1512, 454, 234, 5265, 158 },
  { 2464, 1512, 454, 234, 5265, 158 },
  { 2724, 1512, 454, 234, 5265, 158 },
  { 227, 1512, 454, 234, 5265, 158 },
  { 583, 1512, 454, 234, 5265, 158 },
  { 315, 1529, 454, 234, 23824, 47 },
  { 1230, 1728, 16, 281, 705, 179 },
  { 1476, 1728, 16, 281, 705, 179 },
  { 1790, 1728, 16, 281, 705, 179 },
  { 2001, 1728, 16, 281, 705, 179 },
  { 2300, 1728, 16, 281, 705, 179 },
  { 2528, 1728, 16, 281, 705, 179 },
  { 2812, 1728, 16, 281, 705, 179 },
  { 66, 1728, 16, 281, 705, 179 },
  { 410, 1728, 16, 281, 705, 179 },
  { 762, 1728, 16, 281, 705, 179 },
  { 1031, 1728, 16, 281, 705, 179 },
  { 1322, 1728, 16, 281, 705, 179 },
  { 1598, 1728, 16, 281, 705, 179 },
  { 1854, 1728, 16, 281, 705, 179 },
  { 2097, 1728, 16, 281, 705, 179 },
  { 2364, 1728, 16, 281, 705, 179 },
  { 2624, 1728, 16, 281, 705, 179 },
  { 131, 1728, 16, 281, 705, 179 },
  { 515, 1728, 16, 281, 705, 179 },
  { 849, 1728, 16, 281, 705, 179 },
  { 1151, 1728, 16, 281, 705, 179 },
  { 1397, 1728, 16, 281, 705, 179 },
  { 1705, 1728, 16, 281, 705, 179 },
  { 1922, 1728, 16, 281, 705, 179 },
  { 2197, 1728, 16, 281, 705, 179 },
  { 2456, 1728, 16, 281, 705, 179 },
  { 2716, 1728, 16, 281, 705, 179 },
  { 219, 1728, 16, 281, 705, 179 },
  { 575, 1728, 16, 281, 705, 179 },
  { 307, 1774, 16, 281, 3712, 188 },
  { 684, 1636, 16, 281, 4944, 163 },
  { 924, 1682, 16, 281, 23168, 52 },
  { 928, 1546, 1500, 251, 3857, 197 },
  { 1233, 1546, 457, 251, 3857, 197 },
  { 1479, 1546, 457, 251, 3857, 197 },
  { 1793, 1546, 457, 251, 3857, 197 },
  { 2004, 1546, 457, 251, 3857, 197 },
  { 2303, 1546, 457, 251, 3857, 197 },
  { 2531, 1546, 457, 251, 3857, 197 },
  { 2815, 1546, 457, 251, 3857, 197 },
  { 69, 1546, 457, 251, 3857, 197 },
  { 413, 1546, 457, 251, 3857, 197 },
  { 765, 1546, 457, 251, 3857, 197 },
  { 1035, 1546, 457, 251, 3857, 197 },
  { 1326, 1546, 457, 251, 3857, 197 },
  { 1602, 1546, 457, 251, 3857, 197 },
  { 1858, 1546, 457, 251, 3857, 197 },
  { 2101, 1546, 457, 251, 3857, 197 },
  { 2368, 1546, 457, 251, 3857, 197 },
  { 2628, 1546, 457, 251, 3857, 197 },
  { 135, 1546, 457, 251, 3857, 197 },
  { 519, 1546, 457, 251, 3857, 197 },
  { 853, 1546, 457, 251, 3857, 197 },
  { 1155, 1546, 457, 251, 3857, 197 },
  { 1401, 1546, 457, 251, 3857, 197 },
  { 1709, 1546, 457, 251, 3857, 197 },
  { 1926, 1546, 457, 251, 3857, 197 },
  { 2201, 1546, 457, 251, 3857, 197 },
  { 2460, 1546, 457, 251, 3857, 197 },
  { 2720, 1546, 457, 251, 3857, 197 },
  { 223, 1546, 457, 251, 3857, 197 },
  { 579, 1546, 457, 251, 3857, 197 },
  { 311, 1576, 457, 251, 5152, 172 },
  { 688, 1606, 457, 251, 23376, 61 },
  { 1413, 1844, 1328, 86, 11265, 158 },
  { 1721, 1844, 1328, 86, 11265, 158 },
  { 1938, 1844, 1328, 86, 11265, 158 },
  { 2213, 1844, 1328, 86, 11265, 158 },
  { 2432, 1844, 832, 86, 11265, 158 },
  { 2692, 1844, 832, 86, 11265, 158 },
  { 195, 1844, 832, 86, 11265, 158 },
  { 591, 1844, 832, 86, 11265, 158 },
  { 2522, 1829, 832, 86, 11185, 158 },
  { 2806, 1829, 832, 86, 11185, 158 },
  { 59, 1829, 832, 86, 11185, 158 },
  { 424, 1829, 832, 86, 11185, 158 },
  { 777, 1829, 627, 86, 11185, 158 },
  { 1047, 1829, 627, 86, 11185, 158 },
  { 1338, 1829, 627, 86, 11185, 158 },
  { 1614, 1829, 627, 86, 11185, 158 },
  { 2440, 530, 16, 327, 8337, 179 },
  { 2700, 530, 16, 327, 8337, 179 },
  { 203, 530, 16, 327, 8337, 179 },
  { 599, 530, 16, 327, 8337, 179 },
  { 784, 561, 16, 327, 8193, 179 },
  { 1054, 561, 16, 327, 8193, 179 },
  { 1308, 561, 16, 327, 8193, 179 },
  { 1584, 561, 16, 327, 8193, 179 },
};

  // FPR8 Register Class...
  static const MCPhysReg FPR8[] = {
    AArch64_B0, AArch64_B1, AArch64_B2, AArch64_B3, AArch64_B4, AArch64_B5, AArch64_B6, AArch64_B7, AArch64_B8, AArch64_B9, AArch64_B10, AArch64_B11, AArch64_B12, AArch64_B13, AArch64_B14, AArch64_B15, AArch64_B16, AArch64_B17, AArch64_B18, AArch64_B19, AArch64_B20, AArch64_B21, AArch64_B22, AArch64_B23, AArch64_B24, AArch64_B25, AArch64_B26, AArch64_B27, AArch64_B28, AArch64_B29, AArch64_B30, AArch64_B31, 
  };

  // FPR8 Bit set.
  static const uint8_t FPR8Bits[] = {
    0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // FPR16 Register Class...
  static const MCPhysReg FPR16[] = {
    AArch64_H0, AArch64_H1, AArch64_H2, AArch64_H3, AArch64_H4, AArch64_H5, AArch64_H6, AArch64_H7, AArch64_H8, AArch64_H9, AArch64_H10, AArch64_H11, AArch64_H12, AArch64_H13, AArch64_H14, AArch64_H15, AArch64_H16, AArch64_H17, AArch64_H18, AArch64_H19, AArch64_H20, AArch64_H21, AArch64_H22, AArch64_H23, AArch64_H24, AArch64_H25, AArch64_H26, AArch64_H27, AArch64_H28, AArch64_H29, AArch64_H30, AArch64_H31, 
  };

  // FPR16 Bit set.
  static const uint8_t FPR16Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // FPR16_lo Register Class...
  static const MCPhysReg FPR16_lo[] = {
    AArch64_H0, AArch64_H1, AArch64_H2, AArch64_H3, AArch64_H4, AArch64_H5, AArch64_H6, AArch64_H7, AArch64_H8, AArch64_H9, AArch64_H10, AArch64_H11, AArch64_H12, AArch64_H13, AArch64_H14, AArch64_H15, 
  };

  // FPR16_lo Bit set.
  static const uint8_t FPR16_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // PPR Register Class...
  static const MCPhysReg PPR[] = {
    AArch64_P0, AArch64_P1, AArch64_P2, AArch64_P3, AArch64_P4, AArch64_P5, AArch64_P6, AArch64_P7, AArch64_P8, AArch64_P9, AArch64_P10, AArch64_P11, AArch64_P12, AArch64_P13, AArch64_P14, AArch64_P15, 
  };

  // PPR Bit set.
  static const uint8_t PPRBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // PPR_3b Register Class...
  static const MCPhysReg PPR_3b[] = {
    AArch64_P0, AArch64_P1, AArch64_P2, AArch64_P3, AArch64_P4, AArch64_P5, AArch64_P6, AArch64_P7, 
  };

  // PPR_3b Bit set.
  static const uint8_t PPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 
  };

  // PPR_p8to15 Register Class...
  static const MCPhysReg PPR_p8to15[] = {
    AArch64_P8, AArch64_P9, AArch64_P10, AArch64_P11, AArch64_P12, AArch64_P13, AArch64_P14, AArch64_P15, 
  };

  // PPR_p8to15 Bit set.
  static const uint8_t PPR_p8to15Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 
  };

  // PPR2 Register Class...
  static const MCPhysReg PPR2[] = {
    AArch64_P0_P1, AArch64_P1_P2, AArch64_P2_P3, AArch64_P3_P4, AArch64_P4_P5, AArch64_P5_P6, AArch64_P6_P7, AArch64_P7_P8, AArch64_P8_P9, AArch64_P9_P10, AArch64_P10_P11, AArch64_P11_P12, AArch64_P12_P13, AArch64_P13_P14, AArch64_P14_P15, AArch64_P15_P0, 
  };

  // PPR2 Bit set.
  static const uint8_t PPR2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 
  };

  // PPR2Mul2 Register Class...
  static const MCPhysReg PPR2Mul2[] = {
    AArch64_P0_P1, AArch64_P2_P3, AArch64_P4_P5, AArch64_P6_P7, AArch64_P8_P9, AArch64_P10_P11, AArch64_P12_P13, AArch64_P14_P15, 
  };

  // PPR2Mul2 Bit set.
  static const uint8_t PPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x55, 
  };

  // PPR2_with_psub0_in_PPR_3b Register Class...
  static const MCPhysReg PPR2_with_psub0_in_PPR_3b[] = {
    AArch64_P0_P1, AArch64_P1_P2, AArch64_P2_P3, AArch64_P3_P4, AArch64_P4_P5, AArch64_P5_P6, AArch64_P6_P7, AArch64_P7_P8, 
  };

  // PPR2_with_psub0_in_PPR_3b Bit set.
  static const uint8_t PPR2_with_psub0_in_PPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 
  };

  // PPR2_with_psub0_in_PPR_p8to15 Register Class...
  static const MCPhysReg PPR2_with_psub0_in_PPR_p8to15[] = {
    AArch64_P8_P9, AArch64_P9_P10, AArch64_P10_P11, AArch64_P11_P12, AArch64_P12_P13, AArch64_P13_P14, AArch64_P14_P15, AArch64_P15_P0, 
  };

  // PPR2_with_psub0_in_PPR_p8to15 Bit set.
  static const uint8_t PPR2_with_psub0_in_PPR_p8to15Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 
  };

  // PPR2_with_psub1_in_PPR_3b Register Class...
  static const MCPhysReg PPR2_with_psub1_in_PPR_3b[] = {
    AArch64_P0_P1, AArch64_P1_P2, AArch64_P2_P3, AArch64_P3_P4, AArch64_P4_P5, AArch64_P5_P6, AArch64_P6_P7, AArch64_P15_P0, 
  };

  // PPR2_with_psub1_in_PPR_3b Bit set.
  static const uint8_t PPR2_with_psub1_in_PPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x80, 
  };

  // PPR2_with_psub1_in_PPR_p8to15 Register Class...
  static const MCPhysReg PPR2_with_psub1_in_PPR_p8to15[] = {
    AArch64_P7_P8, AArch64_P8_P9, AArch64_P9_P10, AArch64_P10_P11, AArch64_P11_P12, AArch64_P12_P13, AArch64_P13_P14, AArch64_P14_P15, 
  };

  // PPR2_with_psub1_in_PPR_p8to15 Bit set.
  static const uint8_t PPR2_with_psub1_in_PPR_p8to15Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x7f, 
  };

  // PPR2_with_psub0_in_PPR_3b_and_PPR2_with_psub1_in_PPR_3b Register Class...
  static const MCPhysReg PPR2_with_psub0_in_PPR_3b_and_PPR2_with_psub1_in_PPR_3b[] = {
    AArch64_P0_P1, AArch64_P1_P2, AArch64_P2_P3, AArch64_P3_P4, AArch64_P4_P5, AArch64_P5_P6, AArch64_P6_P7, 
  };

  // PPR2_with_psub0_in_PPR_3b_and_PPR2_with_psub1_in_PPR_3b Bit set.
  static const uint8_t PPR2_with_psub0_in_PPR_3b_and_PPR2_with_psub1_in_PPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 
  };

  // PPR2_with_psub0_in_PPR_p8to15_and_PPR2_with_psub1_in_PPR_p8to15 Register Class...
  static const MCPhysReg PPR2_with_psub0_in_PPR_p8to15_and_PPR2_with_psub1_in_PPR_p8to15[] = {
    AArch64_P8_P9, AArch64_P9_P10, AArch64_P10_P11, AArch64_P11_P12, AArch64_P12_P13, AArch64_P13_P14, AArch64_P14_P15, 
  };

  // PPR2_with_psub0_in_PPR_p8to15_and_PPR2_with_psub1_in_PPR_p8to15 Bit set.
  static const uint8_t PPR2_with_psub0_in_PPR_p8to15_and_PPR2_with_psub1_in_PPR_p8to15Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 
  };

  // PPR2Mul2_and_PPR2_with_psub0_in_PPR_3b Register Class...
  static const MCPhysReg PPR2Mul2_and_PPR2_with_psub0_in_PPR_3b[] = {
    AArch64_P0_P1, AArch64_P2_P3, AArch64_P4_P5, AArch64_P6_P7, 
  };

  // PPR2Mul2_and_PPR2_with_psub0_in_PPR_3b Bit set.
  static const uint8_t PPR2Mul2_and_PPR2_with_psub0_in_PPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 
  };

  // PPR2Mul2_and_PPR2_with_psub0_in_PPR_p8to15 Register Class...
  static const MCPhysReg PPR2Mul2_and_PPR2_with_psub0_in_PPR_p8to15[] = {
    AArch64_P8_P9, AArch64_P10_P11, AArch64_P12_P13, AArch64_P14_P15, 
  };

  // PPR2Mul2_and_PPR2_with_psub0_in_PPR_p8to15 Bit set.
  static const uint8_t PPR2Mul2_and_PPR2_with_psub0_in_PPR_p8to15Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 
  };

  // PPR2_with_psub0_in_PPR_3b_and_PPR2_with_psub1_in_PPR_p8to15 Register Class...
  static const MCPhysReg PPR2_with_psub0_in_PPR_3b_and_PPR2_with_psub1_in_PPR_p8to15[] = {
    AArch64_P7_P8, 
  };

  // PPR2_with_psub0_in_PPR_3b_and_PPR2_with_psub1_in_PPR_p8to15 Bit set.
  static const uint8_t PPR2_with_psub0_in_PPR_3b_and_PPR2_with_psub1_in_PPR_p8to15Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 
  };

  // PPR2_with_psub0_in_PPR_p8to15_and_PPR2_with_psub1_in_PPR_3b Register Class...
  static const MCPhysReg PPR2_with_psub0_in_PPR_p8to15_and_PPR2_with_psub1_in_PPR_3b[] = {
    AArch64_P15_P0, 
  };

  // PPR2_with_psub0_in_PPR_p8to15_and_PPR2_with_psub1_in_PPR_3b Bit set.
  static const uint8_t PPR2_with_psub0_in_PPR_p8to15_and_PPR2_with_psub1_in_PPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 
  };

  // GPR32all Register Class...
  static const MCPhysReg GPR32all[] = {
    AArch64_W0, AArch64_W1, AArch64_W2, AArch64_W3, AArch64_W4, AArch64_W5, AArch64_W6, AArch64_W7, AArch64_W8, AArch64_W9, AArch64_W10, AArch64_W11, AArch64_W12, AArch64_W13, AArch64_W14, AArch64_W15, AArch64_W16, AArch64_W17, AArch64_W18, AArch64_W19, AArch64_W20, AArch64_W21, AArch64_W22, AArch64_W23, AArch64_W24, AArch64_W25, AArch64_W26, AArch64_W27, AArch64_W28, AArch64_W29, AArch64_W30, AArch64_WZR, AArch64_WSP, 
  };

  // GPR32all Bit set.
  static const uint8_t GPR32allBits[] = {
    0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x07, 
  };

  // FPR32 Register Class...
  static const MCPhysReg FPR32[] = {
    AArch64_S0, AArch64_S1, AArch64_S2, AArch64_S3, AArch64_S4, AArch64_S5, AArch64_S6, AArch64_S7, AArch64_S8, AArch64_S9, AArch64_S10, AArch64_S11, AArch64_S12, AArch64_S13, AArch64_S14, AArch64_S15, AArch64_S16, AArch64_S17, AArch64_S18, AArch64_S19, AArch64_S20, AArch64_S21, AArch64_S22, AArch64_S23, AArch64_S24, AArch64_S25, AArch64_S26, AArch64_S27, AArch64_S28, AArch64_S29, AArch64_S30, AArch64_S31, 
  };

  // FPR32 Bit set.
  static const uint8_t FPR32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // GPR32 Register Class...
  static const MCPhysReg GPR32[] = {
    AArch64_W0, AArch64_W1, AArch64_W2, AArch64_W3, AArch64_W4, AArch64_W5, AArch64_W6, AArch64_W7, AArch64_W8, AArch64_W9, AArch64_W10, AArch64_W11, AArch64_W12, AArch64_W13, AArch64_W14, AArch64_W15, AArch64_W16, AArch64_W17, AArch64_W18, AArch64_W19, AArch64_W20, AArch64_W21, AArch64_W22, AArch64_W23, AArch64_W24, AArch64_W25, AArch64_W26, AArch64_W27, AArch64_W28, AArch64_W29, AArch64_W30, AArch64_WZR, 
  };

  // GPR32 Bit set.
  static const uint8_t GPR32Bits[] = {
    0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x07, 
  };

  // GPR32sp Register Class...
  static const MCPhysReg GPR32sp[] = {
    AArch64_W0, AArch64_W1, AArch64_W2, AArch64_W3, AArch64_W4, AArch64_W5, AArch64_W6, AArch64_W7, AArch64_W8, AArch64_W9, AArch64_W10, AArch64_W11, AArch64_W12, AArch64_W13, AArch64_W14, AArch64_W15, AArch64_W16, AArch64_W17, AArch64_W18, AArch64_W19, AArch64_W20, AArch64_W21, AArch64_W22, AArch64_W23, AArch64_W24, AArch64_W25, AArch64_W26, AArch64_W27, AArch64_W28, AArch64_W29, AArch64_W30, AArch64_WSP, 
  };

  // GPR32sp Bit set.
  static const uint8_t GPR32spBits[] = {
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x07, 
  };

  // GPR32common Register Class...
  static const MCPhysReg GPR32common[] = {
    AArch64_W0, AArch64_W1, AArch64_W2, AArch64_W3, AArch64_W4, AArch64_W5, AArch64_W6, AArch64_W7, AArch64_W8, AArch64_W9, AArch64_W10, AArch64_W11, AArch64_W12, AArch64_W13, AArch64_W14, AArch64_W15, AArch64_W16, AArch64_W17, AArch64_W18, AArch64_W19, AArch64_W20, AArch64_W21, AArch64_W22, AArch64_W23, AArch64_W24, AArch64_W25, AArch64_W26, AArch64_W27, AArch64_W28, AArch64_W29, AArch64_W30, 
  };

  // GPR32common Bit set.
  static const uint8_t GPR32commonBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x07, 
  };

  // FPR32_with_hsub_in_FPR16_lo Register Class...
  static const MCPhysReg FPR32_with_hsub_in_FPR16_lo[] = {
    AArch64_S0, AArch64_S1, AArch64_S2, AArch64_S3, AArch64_S4, AArch64_S5, AArch64_S6, AArch64_S7, AArch64_S8, AArch64_S9, AArch64_S10, AArch64_S11, AArch64_S12, AArch64_S13, AArch64_S14, AArch64_S15, 
  };

  // FPR32_with_hsub_in_FPR16_lo Bit set.
  static const uint8_t FPR32_with_hsub_in_FPR16_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // GPR32arg Register Class...
  static const MCPhysReg GPR32arg[] = {
    AArch64_W0, AArch64_W1, AArch64_W2, AArch64_W3, AArch64_W4, AArch64_W5, AArch64_W6, AArch64_W7, 
  };

  // GPR32arg Bit set.
  static const uint8_t GPR32argBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 
  };

  // MatrixIndexGPR32_12_15 Register Class...
  static const MCPhysReg MatrixIndexGPR32_12_15[] = {
    AArch64_W12, AArch64_W13, AArch64_W14, AArch64_W15, 
  };

  // MatrixIndexGPR32_12_15 Bit set.
  static const uint8_t MatrixIndexGPR32_12_15Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 
  };

  // MatrixIndexGPR32_8_11 Register Class...
  static const MCPhysReg MatrixIndexGPR32_8_11[] = {
    AArch64_W8, AArch64_W9, AArch64_W10, AArch64_W11, 
  };

  // MatrixIndexGPR32_8_11 Bit set.
  static const uint8_t MatrixIndexGPR32_8_11Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 
  };

  // CCR Register Class...
  static const MCPhysReg CCR[] = {
    AArch64_NZCV, 
  };

  // CCR Bit set.
  static const uint8_t CCRBits[] = {
    0x20, 
  };

  // GPR32sponly Register Class...
  static const MCPhysReg GPR32sponly[] = {
    AArch64_WSP, 
  };

  // GPR32sponly Bit set.
  static const uint8_t GPR32sponlyBits[] = {
    0x00, 0x01, 
  };

  // WSeqPairsClass Register Class...
  static const MCPhysReg WSeqPairsClass[] = {
    AArch64_W0_W1, AArch64_W2_W3, AArch64_W4_W5, AArch64_W6_W7, AArch64_W8_W9, AArch64_W10_W11, AArch64_W12_W13, AArch64_W14_W15, AArch64_W16_W17, AArch64_W18_W19, AArch64_W20_W21, AArch64_W22_W23, AArch64_W24_W25, AArch64_W26_W27, AArch64_W28_W29, AArch64_W30_WZR, 
  };

  // WSeqPairsClass Bit set.
  static const uint8_t WSeqPairsClassBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // WSeqPairsClass_with_subo32_in_GPR32common Register Class...
  static const MCPhysReg WSeqPairsClass_with_subo32_in_GPR32common[] = {
    AArch64_W0_W1, AArch64_W2_W3, AArch64_W4_W5, AArch64_W6_W7, AArch64_W8_W9, AArch64_W10_W11, AArch64_W12_W13, AArch64_W14_W15, AArch64_W16_W17, AArch64_W18_W19, AArch64_W20_W21, AArch64_W22_W23, AArch64_W24_W25, AArch64_W26_W27, AArch64_W28_W29, 
  };

  // WSeqPairsClass_with_subo32_in_GPR32common Bit set.
  static const uint8_t WSeqPairsClass_with_subo32_in_GPR32commonBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x0f, 
  };

  // WSeqPairsClass_with_sube32_in_GPR32arg Register Class...
  static const MCPhysReg WSeqPairsClass_with_sube32_in_GPR32arg[] = {
    AArch64_W0_W1, AArch64_W2_W3, AArch64_W4_W5, AArch64_W6_W7, 
  };

  // WSeqPairsClass_with_sube32_in_GPR32arg Bit set.
  static const uint8_t WSeqPairsClass_with_sube32_in_GPR32argBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x01, 
  };

  // WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_12_15 Register Class...
  static const MCPhysReg WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_12_15[] = {
    AArch64_W12_W13, AArch64_W14_W15, 
  };

  // WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_12_15 Bit set.
  static const uint8_t WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_12_15Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 
  };

  // WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_8_11 Register Class...
  static const MCPhysReg WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_8_11[] = {
    AArch64_W8_W9, AArch64_W10_W11, 
  };

  // WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_8_11 Bit set.
  static const uint8_t WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_8_11Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 
  };

  // GPR64all Register Class...
  static const MCPhysReg GPR64all[] = {
    AArch64_X0, AArch64_X1, AArch64_X2, AArch64_X3, AArch64_X4, AArch64_X5, AArch64_X6, AArch64_X7, AArch64_X8, AArch64_X9, AArch64_X10, AArch64_X11, AArch64_X12, AArch64_X13, AArch64_X14, AArch64_X15, AArch64_X16, AArch64_X17, AArch64_X18, AArch64_X19, AArch64_X20, AArch64_X21, AArch64_X22, AArch64_X23, AArch64_X24, AArch64_X25, AArch64_X26, AArch64_X27, AArch64_X28, AArch64_FP, AArch64_LR, AArch64_XZR, AArch64_SP, 
  };

  // GPR64all Bit set.
  static const uint8_t GPR64allBits[] = {
    0x54, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 
  };

  // FPR64 Register Class...
  static const MCPhysReg FPR64[] = {
    AArch64_D0, AArch64_D1, AArch64_D2, AArch64_D3, AArch64_D4, AArch64_D5, AArch64_D6, AArch64_D7, AArch64_D8, AArch64_D9, AArch64_D10, AArch64_D11, AArch64_D12, AArch64_D13, AArch64_D14, AArch64_D15, AArch64_D16, AArch64_D17, AArch64_D18, AArch64_D19, AArch64_D20, AArch64_D21, AArch64_D22, AArch64_D23, AArch64_D24, AArch64_D25, AArch64_D26, AArch64_D27, AArch64_D28, AArch64_D29, AArch64_D30, AArch64_D31, 
  };

  // FPR64 Bit set.
  static const uint8_t FPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // GPR64 Register Class...
  static const MCPhysReg GPR64[] = {
    AArch64_X0, AArch64_X1, AArch64_X2, AArch64_X3, AArch64_X4, AArch64_X5, AArch64_X6, AArch64_X7, AArch64_X8, AArch64_X9, AArch64_X10, AArch64_X11, AArch64_X12, AArch64_X13, AArch64_X14, AArch64_X15, AArch64_X16, AArch64_X17, AArch64_X18, AArch64_X19, AArch64_X20, AArch64_X21, AArch64_X22, AArch64_X23, AArch64_X24, AArch64_X25, AArch64_X26, AArch64_X27, AArch64_X28, AArch64_FP, AArch64_LR, AArch64_XZR, 
  };

  // GPR64 Bit set.
  static const uint8_t GPR64Bits[] = {
    0x14, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 
  };

  // GPR64sp Register Class...
  static const MCPhysReg GPR64sp[] = {
    AArch64_X0, AArch64_X1, AArch64_X2, AArch64_X3, AArch64_X4, AArch64_X5, AArch64_X6, AArch64_X7, AArch64_X8, AArch64_X9, AArch64_X10, AArch64_X11, AArch64_X12, AArch64_X13, AArch64_X14, AArch64_X15, AArch64_X16, AArch64_X17, AArch64_X18, AArch64_X19, AArch64_X20, AArch64_X21, AArch64_X22, AArch64_X23, AArch64_X24, AArch64_X25, AArch64_X26, AArch64_X27, AArch64_X28, AArch64_FP, AArch64_LR, AArch64_SP, 
  };

  // GPR64sp Bit set.
  static const uint8_t GPR64spBits[] = {
    0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 
  };

  // GPR64common Register Class...
  static const MCPhysReg GPR64common[] = {
    AArch64_X0, AArch64_X1, AArch64_X2, AArch64_X3, AArch64_X4, AArch64_X5, AArch64_X6, AArch64_X7, AArch64_X8, AArch64_X9, AArch64_X10, AArch64_X11, AArch64_X12, AArch64_X13, AArch64_X14, AArch64_X15, AArch64_X16, AArch64_X17, AArch64_X18, AArch64_X19, AArch64_X20, AArch64_X21, AArch64_X22, AArch64_X23, AArch64_X24, AArch64_X25, AArch64_X26, AArch64_X27, AArch64_X28, AArch64_FP, AArch64_LR, 
  };

  // GPR64common Bit set.
  static const uint8_t GPR64commonBits[] = {
    0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 
  };

  // GPR64noip Register Class...
  static const MCPhysReg GPR64noip[] = {
    AArch64_X0, AArch64_X1, AArch64_X2, AArch64_X3, AArch64_X4, AArch64_X5, AArch64_X6, AArch64_X7, AArch64_X8, AArch64_X9, AArch64_X10, AArch64_X11, AArch64_X12, AArch64_X13, AArch64_X14, AArch64_X15, AArch64_X18, AArch64_X19, AArch64_X20, AArch64_X21, AArch64_X22, AArch64_X23, AArch64_X24, AArch64_X25, AArch64_X26, AArch64_X27, AArch64_X28, AArch64_FP, AArch64_XZR, 
  };

  // GPR64noip Bit set.
  static const uint8_t GPR64noipBits[] = {
    0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xe7, 0xff, 
  };

  // GPR64common_and_GPR64noip Register Class...
  static const MCPhysReg GPR64common_and_GPR64noip[] = {
    AArch64_X0, AArch64_X1, AArch64_X2, AArch64_X3, AArch64_X4, AArch64_X5, AArch64_X6, AArch64_X7, AArch64_X8, AArch64_X9, AArch64_X10, AArch64_X11, AArch64_X12, AArch64_X13, AArch64_X14, AArch64_X15, AArch64_X18, AArch64_X19, AArch64_X20, AArch64_X21, AArch64_X22, AArch64_X23, AArch64_X24, AArch64_X25, AArch64_X26, AArch64_X27, AArch64_X28, AArch64_FP, 
  };

  // GPR64common_and_GPR64noip Bit set.
  static const uint8_t GPR64common_and_GPR64noipBits[] = {
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xe7, 0xff, 
  };

  // tcGPR64 Register Class...
  static const MCPhysReg tcGPR64[] = {
    AArch64_X0, AArch64_X1, AArch64_X2, AArch64_X3, AArch64_X4, AArch64_X5, AArch64_X6, AArch64_X7, AArch64_X8, AArch64_X9, AArch64_X10, AArch64_X11, AArch64_X12, AArch64_X13, AArch64_X14, AArch64_X15, AArch64_X16, AArch64_X17, AArch64_X18, 
  };

  // tcGPR64 Bit set.
  static const uint8_t tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x3f, 
  };

  // GPR64noip_and_tcGPR64 Register Class...
  static const MCPhysReg GPR64noip_and_tcGPR64[] = {
    AArch64_X0, AArch64_X1, AArch64_X2, AArch64_X3, AArch64_X4, AArch64_X5, AArch64_X6, AArch64_X7, AArch64_X8, AArch64_X9, AArch64_X10, AArch64_X11, AArch64_X12, AArch64_X13, AArch64_X14, AArch64_X15, AArch64_X18, 
  };

  // GPR64noip_and_tcGPR64 Bit set.
  static const uint8_t GPR64noip_and_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x27, 
  };

  // FPR64_lo Register Class...
  static const MCPhysReg FPR64_lo[] = {
    AArch64_D0, AArch64_D1, AArch64_D2, AArch64_D3, AArch64_D4, AArch64_D5, AArch64_D6, AArch64_D7, AArch64_D8, AArch64_D9, AArch64_D10, AArch64_D11, AArch64_D12, AArch64_D13, AArch64_D14, AArch64_D15, 
  };

  // FPR64_lo Bit set.
  static const uint8_t FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // GPR64arg Register Class...
  static const MCPhysReg GPR64arg[] = {
    AArch64_X0, AArch64_X1, AArch64_X2, AArch64_X3, AArch64_X4, AArch64_X5, AArch64_X6, AArch64_X7, 
  };

  // GPR64arg Bit set.
  static const uint8_t GPR64argBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x07, 
  };

  // FIXED_REGS Register Class...
  static const MCPhysReg FIXED_REGS[] = {
    AArch64_FP, AArch64_SP, AArch64_VG, AArch64_FFR, 
  };

  // FIXED_REGS Bit set.
  static const uint8_t FIXED_REGSBits[] = {
    0xc6, 
  };

  // GPR64_with_sub_32_in_MatrixIndexGPR32_12_15 Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_MatrixIndexGPR32_12_15[] = {
    AArch64_X12, AArch64_X13, AArch64_X14, AArch64_X15, 
  };

  // GPR64_with_sub_32_in_MatrixIndexGPR32_12_15 Bit set.
  static const uint8_t GPR64_with_sub_32_in_MatrixIndexGPR32_12_15Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x07, 
  };

  // GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_MatrixIndexGPR32_8_11[] = {
    AArch64_X8, AArch64_X9, AArch64_X10, AArch64_X11, 
  };

  // GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Bit set.
  static const uint8_t GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 
  };

  // FIXED_REGS_with_sub_32 Register Class...
  static const MCPhysReg FIXED_REGS_with_sub_32[] = {
    AArch64_FP, AArch64_SP, 
  };

  // FIXED_REGS_with_sub_32 Bit set.
  static const uint8_t FIXED_REGS_with_sub_32Bits[] = {
    0x44, 
  };

  // rtcGPR64 Register Class...
  static const MCPhysReg rtcGPR64[] = {
    AArch64_X16, AArch64_X17, 
  };

  // rtcGPR64 Bit set.
  static const uint8_t rtcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 
  };

  // FIXED_REGS_and_GPR64 Register Class...
  static const MCPhysReg FIXED_REGS_and_GPR64[] = {
    AArch64_FP, 
  };

  // FIXED_REGS_and_GPR64 Bit set.
  static const uint8_t FIXED_REGS_and_GPR64Bits[] = {
    0x04, 
  };

  // GPR64sponly Register Class...
  static const MCPhysReg GPR64sponly[] = {
    AArch64_SP, 
  };

  // GPR64sponly Bit set.
  static const uint8_t GPR64sponlyBits[] = {
    0x40, 
  };

  // DD Register Class...
  static const MCPhysReg DD[] = {
    AArch64_D0_D1, AArch64_D1_D2, AArch64_D2_D3, AArch64_D3_D4, AArch64_D4_D5, AArch64_D5_D6, AArch64_D6_D7, AArch64_D7_D8, AArch64_D8_D9, AArch64_D9_D10, AArch64_D10_D11, AArch64_D11_D12, AArch64_D12_D13, AArch64_D13_D14, AArch64_D14_D15, AArch64_D15_D16, AArch64_D16_D17, AArch64_D17_D18, AArch64_D18_D19, AArch64_D19_D20, AArch64_D20_D21, AArch64_D21_D22, AArch64_D22_D23, AArch64_D23_D24, AArch64_D24_D25, AArch64_D25_D26, AArch64_D26_D27, AArch64_D27_D28, AArch64_D28_D29, AArch64_D29_D30, AArch64_D30_D31, AArch64_D31_D0, 
  };

  // DD Bit set.
  static const uint8_t DDBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 
  };

  // DD_with_dsub0_in_FPR64_lo Register Class...
  static const MCPhysReg DD_with_dsub0_in_FPR64_lo[] = {
    AArch64_D0_D1, AArch64_D1_D2, AArch64_D2_D3, AArch64_D3_D4, AArch64_D4_D5, AArch64_D5_D6, AArch64_D6_D7, AArch64_D7_D8, AArch64_D8_D9, AArch64_D9_D10, AArch64_D10_D11, AArch64_D11_D12, AArch64_D12_D13, AArch64_D13_D14, AArch64_D14_D15, AArch64_D15_D16, 
  };

  // DD_with_dsub0_in_FPR64_lo Bit set.
  static const uint8_t DD_with_dsub0_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 
  };

  // DD_with_dsub1_in_FPR64_lo Register Class...
  static const MCPhysReg DD_with_dsub1_in_FPR64_lo[] = {
    AArch64_D0_D1, AArch64_D1_D2, AArch64_D2_D3, AArch64_D3_D4, AArch64_D4_D5, AArch64_D5_D6, AArch64_D6_D7, AArch64_D7_D8, AArch64_D8_D9, AArch64_D9_D10, AArch64_D10_D11, AArch64_D11_D12, AArch64_D12_D13, AArch64_D13_D14, AArch64_D14_D15, AArch64_D31_D0, 
  };

  // DD_with_dsub1_in_FPR64_lo Bit set.
  static const uint8_t DD_with_dsub1_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, 0x00, 0x80, 
  };

  // XSeqPairsClass Register Class...
  static const MCPhysReg XSeqPairsClass[] = {
    AArch64_X0_X1, AArch64_X2_X3, AArch64_X4_X5, AArch64_X6_X7, AArch64_X8_X9, AArch64_X10_X11, AArch64_X12_X13, AArch64_X14_X15, AArch64_X16_X17, AArch64_X18_X19, AArch64_X20_X21, AArch64_X22_X23, AArch64_X24_X25, AArch64_X26_X27, AArch64_X28_FP, AArch64_LR_XZR, 
  };

  // XSeqPairsClass Bit set.
  static const uint8_t XSeqPairsClassBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // DD_with_dsub0_in_FPR64_lo_and_DD_with_dsub1_in_FPR64_lo Register Class...
  static const MCPhysReg DD_with_dsub0_in_FPR64_lo_and_DD_with_dsub1_in_FPR64_lo[] = {
    AArch64_D0_D1, AArch64_D1_D2, AArch64_D2_D3, AArch64_D3_D4, AArch64_D4_D5, AArch64_D5_D6, AArch64_D6_D7, AArch64_D7_D8, AArch64_D8_D9, AArch64_D9_D10, AArch64_D10_D11, AArch64_D11_D12, AArch64_D12_D13, AArch64_D13_D14, AArch64_D14_D15, 
  };

  // DD_with_dsub0_in_FPR64_lo_and_DD_with_dsub1_in_FPR64_lo Bit set.
  static const uint8_t DD_with_dsub0_in_FPR64_lo_and_DD_with_dsub1_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, 
  };

  // XSeqPairsClass_with_subo64_in_GPR64common Register Class...
  static const MCPhysReg XSeqPairsClass_with_subo64_in_GPR64common[] = {
    AArch64_X0_X1, AArch64_X2_X3, AArch64_X4_X5, AArch64_X6_X7, AArch64_X8_X9, AArch64_X10_X11, AArch64_X12_X13, AArch64_X14_X15, AArch64_X16_X17, AArch64_X18_X19, AArch64_X20_X21, AArch64_X22_X23, AArch64_X24_X25, AArch64_X26_X27, AArch64_X28_FP, 
  };

  // XSeqPairsClass_with_subo64_in_GPR64common Bit set.
  static const uint8_t XSeqPairsClass_with_subo64_in_GPR64commonBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x0f, 
  };

  // XSeqPairsClass_with_subo64_in_GPR64noip Register Class...
  static const MCPhysReg XSeqPairsClass_with_subo64_in_GPR64noip[] = {
    AArch64_X0_X1, AArch64_X2_X3, AArch64_X4_X5, AArch64_X6_X7, AArch64_X8_X9, AArch64_X10_X11, AArch64_X12_X13, AArch64_X14_X15, AArch64_X18_X19, AArch64_X20_X21, AArch64_X22_X23, AArch64_X24_X25, AArch64_X26_X27, AArch64_X28_FP, AArch64_LR_XZR, 
  };

  // XSeqPairsClass_with_subo64_in_GPR64noip Bit set.
  static const uint8_t XSeqPairsClass_with_subo64_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xbf, 0x0f, 
  };

  // XSeqPairsClass_with_sube64_in_GPR64noip Register Class...
  static const MCPhysReg XSeqPairsClass_with_sube64_in_GPR64noip[] = {
    AArch64_X0_X1, AArch64_X2_X3, AArch64_X4_X5, AArch64_X6_X7, AArch64_X8_X9, AArch64_X10_X11, AArch64_X12_X13, AArch64_X14_X15, AArch64_X18_X19, AArch64_X20_X21, AArch64_X22_X23, AArch64_X24_X25, AArch64_X26_X27, AArch64_X28_FP, 
  };

  // XSeqPairsClass_with_sube64_in_GPR64noip Bit set.
  static const uint8_t XSeqPairsClass_with_sube64_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xbf, 0x0f, 
  };

  // XSeqPairsClass_with_sube64_in_tcGPR64 Register Class...
  static const MCPhysReg XSeqPairsClass_with_sube64_in_tcGPR64[] = {
    AArch64_X0_X1, AArch64_X2_X3, AArch64_X4_X5, AArch64_X6_X7, AArch64_X8_X9, AArch64_X10_X11, AArch64_X12_X13, AArch64_X14_X15, AArch64_X16_X17, AArch64_X18_X19, 
  };

  // XSeqPairsClass_with_sube64_in_tcGPR64 Bit set.
  static const uint8_t XSeqPairsClass_with_sube64_in_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 
  };

  // XSeqPairsClass_with_sube64_in_GPR64noip_and_tcGPR64 Register Class...
  static const MCPhysReg XSeqPairsClass_with_sube64_in_GPR64noip_and_tcGPR64[] = {
    AArch64_X0_X1, AArch64_X2_X3, AArch64_X4_X5, AArch64_X6_X7, AArch64_X8_X9, AArch64_X10_X11, AArch64_X12_X13, AArch64_X14_X15, AArch64_X18_X19, 
  };

  // XSeqPairsClass_with_sube64_in_GPR64noip_and_tcGPR64 Bit set.
  static const uint8_t XSeqPairsClass_with_sube64_in_GPR64noip_and_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xbf, 
  };

  // XSeqPairsClass_with_subo64_in_tcGPR64 Register Class...
  static const MCPhysReg XSeqPairsClass_with_subo64_in_tcGPR64[] = {
    AArch64_X0_X1, AArch64_X2_X3, AArch64_X4_X5, AArch64_X6_X7, AArch64_X8_X9, AArch64_X10_X11, AArch64_X12_X13, AArch64_X14_X15, AArch64_X16_X17, 
  };

  // XSeqPairsClass_with_subo64_in_tcGPR64 Bit set.
  static const uint8_t XSeqPairsClass_with_subo64_in_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x7f, 
  };

  // XSeqPairsClass_with_subo64_in_GPR64noip_and_tcGPR64 Register Class...
  static const MCPhysReg XSeqPairsClass_with_subo64_in_GPR64noip_and_tcGPR64[] = {
    AArch64_X0_X1, AArch64_X2_X3, AArch64_X4_X5, AArch64_X6_X7, AArch64_X8_X9, AArch64_X10_X11, AArch64_X12_X13, AArch64_X14_X15, 
  };

  // XSeqPairsClass_with_subo64_in_GPR64noip_and_tcGPR64 Bit set.
  static const uint8_t XSeqPairsClass_with_subo64_in_GPR64noip_and_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 
  };

  // XSeqPairsClass_with_sub_32_in_GPR32arg Register Class...
  static const MCPhysReg XSeqPairsClass_with_sub_32_in_GPR32arg[] = {
    AArch64_X0_X1, AArch64_X2_X3, AArch64_X4_X5, AArch64_X6_X7, 
  };

  // XSeqPairsClass_with_sub_32_in_GPR32arg Bit set.
  static const uint8_t XSeqPairsClass_with_sub_32_in_GPR32argBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x03, 
  };

  // XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_12_15 Register Class...
  static const MCPhysReg XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_12_15[] = {
    AArch64_X12_X13, AArch64_X14_X15, 
  };

  // XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_12_15 Bit set.
  static const uint8_t XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_12_15Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 
  };

  // XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_8_11 Register Class...
  static const MCPhysReg XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_8_11[] = {
    AArch64_X8_X9, AArch64_X10_X11, 
  };

  // XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_8_11 Bit set.
  static const uint8_t XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_8_11Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 
  };

  // XSeqPairsClass_with_sube64_in_rtcGPR64 Register Class...
  static const MCPhysReg XSeqPairsClass_with_sube64_in_rtcGPR64[] = {
    AArch64_X16_X17, 
  };

  // XSeqPairsClass_with_sube64_in_rtcGPR64 Bit set.
  static const uint8_t XSeqPairsClass_with_sube64_in_rtcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 
  };

  // XSeqPairsClass_with_subo64_in_FIXED_REGS Register Class...
  static const MCPhysReg XSeqPairsClass_with_subo64_in_FIXED_REGS[] = {
    AArch64_X28_FP, 
  };

  // XSeqPairsClass_with_subo64_in_FIXED_REGS Bit set.
  static const uint8_t XSeqPairsClass_with_subo64_in_FIXED_REGSBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 
  };

  // FPR128 Register Class...
  static const MCPhysReg FPR128[] = {
    AArch64_Q0, AArch64_Q1, AArch64_Q2, AArch64_Q3, AArch64_Q4, AArch64_Q5, AArch64_Q6, AArch64_Q7, AArch64_Q8, AArch64_Q9, AArch64_Q10, AArch64_Q11, AArch64_Q12, AArch64_Q13, AArch64_Q14, AArch64_Q15, AArch64_Q16, AArch64_Q17, AArch64_Q18, AArch64_Q19, AArch64_Q20, AArch64_Q21, AArch64_Q22, AArch64_Q23, AArch64_Q24, AArch64_Q25, AArch64_Q26, AArch64_Q27, AArch64_Q28, AArch64_Q29, AArch64_Q30, AArch64_Q31, 
  };

  // FPR128 Bit set.
  static const uint8_t FPR128Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // ZPR Register Class...
  static const MCPhysReg ZPR[] = {
    AArch64_Z0, AArch64_Z1, AArch64_Z2, AArch64_Z3, AArch64_Z4, AArch64_Z5, AArch64_Z6, AArch64_Z7, AArch64_Z8, AArch64_Z9, AArch64_Z10, AArch64_Z11, AArch64_Z12, AArch64_Z13, AArch64_Z14, AArch64_Z15, AArch64_Z16, AArch64_Z17, AArch64_Z18, AArch64_Z19, AArch64_Z20, AArch64_Z21, AArch64_Z22, AArch64_Z23, AArch64_Z24, AArch64_Z25, AArch64_Z26, AArch64_Z27, AArch64_Z28, AArch64_Z29, AArch64_Z30, AArch64_Z31, 
  };

  // ZPR Bit set.
  static const uint8_t ZPRBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 
  };

  // FPR128_lo Register Class...
  static const MCPhysReg FPR128_lo[] = {
    AArch64_Q0, AArch64_Q1, AArch64_Q2, AArch64_Q3, AArch64_Q4, AArch64_Q5, AArch64_Q6, AArch64_Q7, AArch64_Q8, AArch64_Q9, AArch64_Q10, AArch64_Q11, AArch64_Q12, AArch64_Q13, AArch64_Q14, AArch64_Q15, 
  };

  // FPR128_lo Bit set.
  static const uint8_t FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // MPR128 Register Class...
  static const MCPhysReg MPR128[] = {
    AArch64_ZAQ0, AArch64_ZAQ1, AArch64_ZAQ2, AArch64_ZAQ3, AArch64_ZAQ4, AArch64_ZAQ5, AArch64_ZAQ6, AArch64_ZAQ7, AArch64_ZAQ8, AArch64_ZAQ9, AArch64_ZAQ10, AArch64_ZAQ11, AArch64_ZAQ12, AArch64_ZAQ13, AArch64_ZAQ14, AArch64_ZAQ15, 
  };

  // MPR128 Bit set.
  static const uint8_t MPR128Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x07, 
  };

  // ZPR_4b Register Class...
  static const MCPhysReg ZPR_4b[] = {
    AArch64_Z0, AArch64_Z1, AArch64_Z2, AArch64_Z3, AArch64_Z4, AArch64_Z5, AArch64_Z6, AArch64_Z7, AArch64_Z8, AArch64_Z9, AArch64_Z10, AArch64_Z11, AArch64_Z12, AArch64_Z13, AArch64_Z14, AArch64_Z15, 
  };

  // ZPR_4b Bit set.
  static const uint8_t ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 
  };

  // ZPR_3b Register Class...
  static const MCPhysReg ZPR_3b[] = {
    AArch64_Z0, AArch64_Z1, AArch64_Z2, AArch64_Z3, AArch64_Z4, AArch64_Z5, AArch64_Z6, AArch64_Z7, 
  };

  // ZPR_3b Bit set.
  static const uint8_t ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 
  };

  // DDD Register Class...
  static const MCPhysReg DDD[] = {
    AArch64_D0_D1_D2, AArch64_D1_D2_D3, AArch64_D2_D3_D4, AArch64_D3_D4_D5, AArch64_D4_D5_D6, AArch64_D5_D6_D7, AArch64_D6_D7_D8, AArch64_D7_D8_D9, AArch64_D8_D9_D10, AArch64_D9_D10_D11, AArch64_D10_D11_D12, AArch64_D11_D12_D13, AArch64_D12_D13_D14, AArch64_D13_D14_D15, AArch64_D14_D15_D16, AArch64_D15_D16_D17, AArch64_D16_D17_D18, AArch64_D17_D18_D19, AArch64_D18_D19_D20, AArch64_D19_D20_D21, AArch64_D20_D21_D22, AArch64_D21_D22_D23, AArch64_D22_D23_D24, AArch64_D23_D24_D25, AArch64_D24_D25_D26, AArch64_D25_D26_D27, AArch64_D26_D27_D28, AArch64_D27_D28_D29, AArch64_D28_D29_D30, AArch64_D29_D30_D31, AArch64_D30_D31_D0, AArch64_D31_D0_D1, 
  };

  // DDD Bit set.
  static const uint8_t DDDBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 
  };

  // DDD_with_dsub0_in_FPR64_lo Register Class...
  static const MCPhysReg DDD_with_dsub0_in_FPR64_lo[] = {
    AArch64_D0_D1_D2, AArch64_D1_D2_D3, AArch64_D2_D3_D4, AArch64_D3_D4_D5, AArch64_D4_D5_D6, AArch64_D5_D6_D7, AArch64_D6_D7_D8, AArch64_D7_D8_D9, AArch64_D8_D9_D10, AArch64_D9_D10_D11, AArch64_D10_D11_D12, AArch64_D11_D12_D13, AArch64_D12_D13_D14, AArch64_D13_D14_D15, AArch64_D14_D15_D16, AArch64_D15_D16_D17, 
  };

  // DDD_with_dsub0_in_FPR64_lo Bit set.
  static const uint8_t DDD_with_dsub0_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 
  };

  // DDD_with_dsub1_in_FPR64_lo Register Class...
  static const MCPhysReg DDD_with_dsub1_in_FPR64_lo[] = {
    AArch64_D0_D1_D2, AArch64_D1_D2_D3, AArch64_D2_D3_D4, AArch64_D3_D4_D5, AArch64_D4_D5_D6, AArch64_D5_D6_D7, AArch64_D6_D7_D8, AArch64_D7_D8_D9, AArch64_D8_D9_D10, AArch64_D9_D10_D11, AArch64_D10_D11_D12, AArch64_D11_D12_D13, AArch64_D12_D13_D14, AArch64_D13_D14_D15, AArch64_D14_D15_D16, AArch64_D31_D0_D1, 
  };

  // DDD_with_dsub1_in_FPR64_lo Bit set.
  static const uint8_t DDD_with_dsub1_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, 0x00, 0x80, 
  };

  // DDD_with_dsub2_in_FPR64_lo Register Class...
  static const MCPhysReg DDD_with_dsub2_in_FPR64_lo[] = {
    AArch64_D0_D1_D2, AArch64_D1_D2_D3, AArch64_D2_D3_D4, AArch64_D3_D4_D5, AArch64_D4_D5_D6, AArch64_D5_D6_D7, AArch64_D6_D7_D8, AArch64_D7_D8_D9, AArch64_D8_D9_D10, AArch64_D9_D10_D11, AArch64_D10_D11_D12, AArch64_D11_D12_D13, AArch64_D12_D13_D14, AArch64_D13_D14_D15, AArch64_D30_D31_D0, AArch64_D31_D0_D1, 
  };

  // DDD_with_dsub2_in_FPR64_lo Bit set.
  static const uint8_t DDD_with_dsub2_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x3f, 0x00, 0xc0, 
  };

  // DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub1_in_FPR64_lo Register Class...
  static const MCPhysReg DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub1_in_FPR64_lo[] = {
    AArch64_D0_D1_D2, AArch64_D1_D2_D3, AArch64_D2_D3_D4, AArch64_D3_D4_D5, AArch64_D4_D5_D6, AArch64_D5_D6_D7, AArch64_D6_D7_D8, AArch64_D7_D8_D9, AArch64_D8_D9_D10, AArch64_D9_D10_D11, AArch64_D10_D11_D12, AArch64_D11_D12_D13, AArch64_D12_D13_D14, AArch64_D13_D14_D15, AArch64_D14_D15_D16, 
  };

  // DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub1_in_FPR64_lo Bit set.
  static const uint8_t DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub1_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, 
  };

  // DDD_with_dsub1_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_lo Register Class...
  static const MCPhysReg DDD_with_dsub1_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_lo[] = {
    AArch64_D0_D1_D2, AArch64_D1_D2_D3, AArch64_D2_D3_D4, AArch64_D3_D4_D5, AArch64_D4_D5_D6, AArch64_D5_D6_D7, AArch64_D6_D7_D8, AArch64_D7_D8_D9, AArch64_D8_D9_D10, AArch64_D9_D10_D11, AArch64_D10_D11_D12, AArch64_D11_D12_D13, AArch64_D12_D13_D14, AArch64_D13_D14_D15, AArch64_D31_D0_D1, 
  };

  // DDD_with_dsub1_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_lo Bit set.
  static const uint8_t DDD_with_dsub1_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x3f, 0x00, 0x80, 
  };

  // DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_lo Register Class...
  static const MCPhysReg DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_lo[] = {
    AArch64_D0_D1_D2, AArch64_D1_D2_D3, AArch64_D2_D3_D4, AArch64_D3_D4_D5, AArch64_D4_D5_D6, AArch64_D5_D6_D7, AArch64_D6_D7_D8, AArch64_D7_D8_D9, AArch64_D8_D9_D10, AArch64_D9_D10_D11, AArch64_D10_D11_D12, AArch64_D11_D12_D13, AArch64_D12_D13_D14, AArch64_D13_D14_D15, 
  };

  // DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_lo Bit set.
  static const uint8_t DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x3f, 
  };

  // DDDD Register Class...
  static const MCPhysReg DDDD[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D13_D14_D15_D16, AArch64_D14_D15_D16_D17, AArch64_D15_D16_D17_D18, AArch64_D16_D17_D18_D19, AArch64_D17_D18_D19_D20, AArch64_D18_D19_D20_D21, AArch64_D19_D20_D21_D22, AArch64_D20_D21_D22_D23, AArch64_D21_D22_D23_D24, AArch64_D22_D23_D24_D25, AArch64_D23_D24_D25_D26, AArch64_D24_D25_D26_D27, AArch64_D25_D26_D27_D28, AArch64_D26_D27_D28_D29, AArch64_D27_D28_D29_D30, AArch64_D28_D29_D30_D31, AArch64_D29_D30_D31_D0, AArch64_D30_D31_D0_D1, AArch64_D31_D0_D1_D2, 
  };

  // DDDD Bit set.
  static const uint8_t DDDDBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 
  };

  // DDDD_with_dsub0_in_FPR64_lo Register Class...
  static const MCPhysReg DDDD_with_dsub0_in_FPR64_lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D13_D14_D15_D16, AArch64_D14_D15_D16_D17, AArch64_D15_D16_D17_D18, 
  };

  // DDDD_with_dsub0_in_FPR64_lo Bit set.
  static const uint8_t DDDD_with_dsub0_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 
  };

  // DDDD_with_dsub1_in_FPR64_lo Register Class...
  static const MCPhysReg DDDD_with_dsub1_in_FPR64_lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D13_D14_D15_D16, AArch64_D14_D15_D16_D17, AArch64_D31_D0_D1_D2, 
  };

  // DDDD_with_dsub1_in_FPR64_lo Bit set.
  static const uint8_t DDDD_with_dsub1_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, 0x00, 0x80, 
  };

  // DDDD_with_dsub2_in_FPR64_lo Register Class...
  static const MCPhysReg DDDD_with_dsub2_in_FPR64_lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D13_D14_D15_D16, AArch64_D30_D31_D0_D1, AArch64_D31_D0_D1_D2, 
  };

  // DDDD_with_dsub2_in_FPR64_lo Bit set.
  static const uint8_t DDDD_with_dsub2_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x3f, 0x00, 0xc0, 
  };

  // DDDD_with_dsub3_in_FPR64_lo Register Class...
  static const MCPhysReg DDDD_with_dsub3_in_FPR64_lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D29_D30_D31_D0, AArch64_D30_D31_D0_D1, AArch64_D31_D0_D1_D2, 
  };

  // DDDD_with_dsub3_in_FPR64_lo Bit set.
  static const uint8_t DDDD_with_dsub3_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x1f, 0x00, 0xe0, 
  };

  // DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub1_in_FPR64_lo Register Class...
  static const MCPhysReg DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub1_in_FPR64_lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D13_D14_D15_D16, AArch64_D14_D15_D16_D17, 
  };

  // DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub1_in_FPR64_lo Bit set.
  static const uint8_t DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub1_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, 
  };

  // DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_lo Register Class...
  static const MCPhysReg DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D13_D14_D15_D16, AArch64_D31_D0_D1_D2, 
  };

  // DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_lo Bit set.
  static const uint8_t DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x3f, 0x00, 0x80, 
  };

  // DDDD_with_dsub2_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_lo Register Class...
  static const MCPhysReg DDDD_with_dsub2_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D30_D31_D0_D1, AArch64_D31_D0_D1_D2, 
  };

  // DDDD_with_dsub2_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_lo Bit set.
  static const uint8_t DDDD_with_dsub2_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x1f, 0x00, 0xc0, 
  };

  // DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_lo Register Class...
  static const MCPhysReg DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D13_D14_D15_D16, 
  };

  // DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_lo Bit set.
  static const uint8_t DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x3f, 
  };

  // DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_lo Register Class...
  static const MCPhysReg DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D31_D0_D1_D2, 
  };

  // DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_lo Bit set.
  static const uint8_t DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x1f, 0x00, 0x80, 
  };

  // DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_lo Register Class...
  static const MCPhysReg DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, 
  };

  // DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_lo Bit set.
  static const uint8_t DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x1f, 
  };

  // QQ Register Class...
  static const MCPhysReg QQ[] = {
    AArch64_Q0_Q1, AArch64_Q1_Q2, AArch64_Q2_Q3, AArch64_Q3_Q4, AArch64_Q4_Q5, AArch64_Q5_Q6, AArch64_Q6_Q7, AArch64_Q7_Q8, AArch64_Q8_Q9, AArch64_Q9_Q10, AArch64_Q10_Q11, AArch64_Q11_Q12, AArch64_Q12_Q13, AArch64_Q13_Q14, AArch64_Q14_Q15, AArch64_Q15_Q16, AArch64_Q16_Q17, AArch64_Q17_Q18, AArch64_Q18_Q19, AArch64_Q19_Q20, AArch64_Q20_Q21, AArch64_Q21_Q22, AArch64_Q22_Q23, AArch64_Q23_Q24, AArch64_Q24_Q25, AArch64_Q25_Q26, AArch64_Q26_Q27, AArch64_Q27_Q28, AArch64_Q28_Q29, AArch64_Q29_Q30, AArch64_Q30_Q31, AArch64_Q31_Q0, 
  };

  // QQ Bit set.
  static const uint8_t QQBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 
  };

  // ZPR2 Register Class...
  static const MCPhysReg ZPR2[] = {
    AArch64_Z0_Z1, AArch64_Z1_Z2, AArch64_Z2_Z3, AArch64_Z3_Z4, AArch64_Z4_Z5, AArch64_Z5_Z6, AArch64_Z6_Z7, AArch64_Z7_Z8, AArch64_Z8_Z9, AArch64_Z9_Z10, AArch64_Z10_Z11, AArch64_Z11_Z12, AArch64_Z12_Z13, AArch64_Z13_Z14, AArch64_Z14_Z15, AArch64_Z15_Z16, AArch64_Z16_Z17, AArch64_Z17_Z18, AArch64_Z18_Z19, AArch64_Z19_Z20, AArch64_Z20_Z21, AArch64_Z21_Z22, AArch64_Z22_Z23, AArch64_Z23_Z24, AArch64_Z24_Z25, AArch64_Z25_Z26, AArch64_Z26_Z27, AArch64_Z27_Z28, AArch64_Z28_Z29, AArch64_Z29_Z30, AArch64_Z30_Z31, AArch64_Z31_Z0, 
  };

  // ZPR2 Bit set.
  static const uint8_t ZPR2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // QQ_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg QQ_with_dsub_in_FPR64_lo[] = {
    AArch64_Q0_Q1, AArch64_Q1_Q2, AArch64_Q2_Q3, AArch64_Q3_Q4, AArch64_Q4_Q5, AArch64_Q5_Q6, AArch64_Q6_Q7, AArch64_Q7_Q8, AArch64_Q8_Q9, AArch64_Q9_Q10, AArch64_Q10_Q11, AArch64_Q11_Q12, AArch64_Q12_Q13, AArch64_Q13_Q14, AArch64_Q14_Q15, AArch64_Q15_Q16, 
  };

  // QQ_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t QQ_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 
  };

  // QQ_with_qsub1_in_FPR128_lo Register Class...
  static const MCPhysReg QQ_with_qsub1_in_FPR128_lo[] = {
    AArch64_Q0_Q1, AArch64_Q1_Q2, AArch64_Q2_Q3, AArch64_Q3_Q4, AArch64_Q4_Q5, AArch64_Q5_Q6, AArch64_Q6_Q7, AArch64_Q7_Q8, AArch64_Q8_Q9, AArch64_Q9_Q10, AArch64_Q10_Q11, AArch64_Q11_Q12, AArch64_Q12_Q13, AArch64_Q13_Q14, AArch64_Q14_Q15, AArch64_Q31_Q0, 
  };

  // QQ_with_qsub1_in_FPR128_lo Bit set.
  static const uint8_t QQ_with_qsub1_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, 0x00, 0x80, 
  };

  // ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR2Mul2[] = {
    AArch64_Z0_Z1, AArch64_Z2_Z3, AArch64_Z4_Z5, AArch64_Z6_Z7, AArch64_Z8_Z9, AArch64_Z10_Z11, AArch64_Z12_Z13, AArch64_Z14_Z15, AArch64_Z16_Z17, AArch64_Z18_Z19, AArch64_Z20_Z21, AArch64_Z22_Z23, AArch64_Z24_Z25, AArch64_Z26_Z27, AArch64_Z28_Z29, AArch64_Z30_Z31, 
  };

  // ZPR2Mul2 Bit set.
  static const uint8_t ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x55, 0x55, 0x05, 
  };

  // ZPR2_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR2_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z1, AArch64_Z1_Z2, AArch64_Z2_Z3, AArch64_Z3_Z4, AArch64_Z4_Z5, AArch64_Z5_Z6, AArch64_Z6_Z7, AArch64_Z7_Z8, AArch64_Z8_Z9, AArch64_Z9_Z10, AArch64_Z10_Z11, AArch64_Z11_Z12, AArch64_Z12_Z13, AArch64_Z13_Z14, AArch64_Z14_Z15, AArch64_Z15_Z16, 
  };

  // ZPR2_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR2_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // ZPR2_with_zsub1_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR2_with_zsub1_in_ZPR_4b[] = {
    AArch64_Z0_Z1, AArch64_Z1_Z2, AArch64_Z2_Z3, AArch64_Z3_Z4, AArch64_Z4_Z5, AArch64_Z5_Z6, AArch64_Z6_Z7, AArch64_Z7_Z8, AArch64_Z8_Z9, AArch64_Z9_Z10, AArch64_Z10_Z11, AArch64_Z11_Z12, AArch64_Z12_Z13, AArch64_Z13_Z14, AArch64_Z14_Z15, AArch64_Z31_Z0, 
  };

  // ZPR2_with_zsub1_in_ZPR_4b Bit set.
  static const uint8_t ZPR2_with_zsub1_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 0x00, 0x08, 
  };

  // QQ_with_dsub_in_FPR64_lo_and_QQ_with_qsub1_in_FPR128_lo Register Class...
  static const MCPhysReg QQ_with_dsub_in_FPR64_lo_and_QQ_with_qsub1_in_FPR128_lo[] = {
    AArch64_Q0_Q1, AArch64_Q1_Q2, AArch64_Q2_Q3, AArch64_Q3_Q4, AArch64_Q4_Q5, AArch64_Q5_Q6, AArch64_Q6_Q7, AArch64_Q7_Q8, AArch64_Q8_Q9, AArch64_Q9_Q10, AArch64_Q10_Q11, AArch64_Q11_Q12, AArch64_Q12_Q13, AArch64_Q13_Q14, AArch64_Q14_Q15, 
  };

  // QQ_with_dsub_in_FPR64_lo_and_QQ_with_qsub1_in_FPR128_lo Bit set.
  static const uint8_t QQ_with_dsub_in_FPR64_lo_and_QQ_with_qsub1_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, 
  };

  // ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_4b[] = {
    AArch64_Z0_Z1, AArch64_Z1_Z2, AArch64_Z2_Z3, AArch64_Z3_Z4, AArch64_Z4_Z5, AArch64_Z5_Z6, AArch64_Z6_Z7, AArch64_Z7_Z8, AArch64_Z8_Z9, AArch64_Z9_Z10, AArch64_Z10_Z11, AArch64_Z11_Z12, AArch64_Z12_Z13, AArch64_Z13_Z14, AArch64_Z14_Z15, 
  };

  // ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_4b Bit set.
  static const uint8_t ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 
  };

  // ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z1, AArch64_Z2_Z3, AArch64_Z4_Z5, AArch64_Z6_Z7, AArch64_Z8_Z9, AArch64_Z10_Z11, AArch64_Z12_Z13, AArch64_Z14_Z15, 
  };

  // ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x05, 
  };

  // ZPR2_with_zsub0_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR2_with_zsub0_in_ZPR_3b[] = {
    AArch64_Z0_Z1, AArch64_Z1_Z2, AArch64_Z2_Z3, AArch64_Z3_Z4, AArch64_Z4_Z5, AArch64_Z5_Z6, AArch64_Z6_Z7, AArch64_Z7_Z8, 
  };

  // ZPR2_with_zsub0_in_ZPR_3b Bit set.
  static const uint8_t ZPR2_with_zsub0_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 
  };

  // ZPR2_with_zsub1_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR2_with_zsub1_in_ZPR_3b[] = {
    AArch64_Z0_Z1, AArch64_Z1_Z2, AArch64_Z2_Z3, AArch64_Z3_Z4, AArch64_Z4_Z5, AArch64_Z5_Z6, AArch64_Z6_Z7, AArch64_Z31_Z0, 
  };

  // ZPR2_with_zsub1_in_ZPR_3b Bit set.
  static const uint8_t ZPR2_with_zsub1_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x07, 0x00, 0x00, 0x08, 
  };

  // ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_3b[] = {
    AArch64_Z0_Z1, AArch64_Z1_Z2, AArch64_Z2_Z3, AArch64_Z3_Z4, AArch64_Z4_Z5, AArch64_Z5_Z6, AArch64_Z6_Z7, 
  };

  // ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_3b Bit set.
  static const uint8_t ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x07, 
  };

  // ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b[] = {
    AArch64_Z0_Z1, AArch64_Z2_Z3, AArch64_Z4_Z5, AArch64_Z6_Z7, 
  };

  // ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b Bit set.
  static const uint8_t ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x05, 
  };

  // ZPR2Strided Register Class...
  static const MCPhysReg ZPR2Strided[] = {
    AArch64_Z0_Z8, AArch64_Z1_Z9, AArch64_Z2_Z10, AArch64_Z3_Z11, AArch64_Z4_Z12, AArch64_Z5_Z13, AArch64_Z6_Z14, AArch64_Z7_Z15, AArch64_Z16_Z24, AArch64_Z17_Z25, AArch64_Z18_Z26, AArch64_Z19_Z27, AArch64_Z20_Z28, AArch64_Z21_Z29, AArch64_Z22_Z30, AArch64_Z23_Z31, 
  };

  // ZPR2Strided Bit set.
  static const uint8_t ZPR2StridedBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // MPR64 Register Class...
  static const MCPhysReg MPR64[] = {
    AArch64_ZAD0, AArch64_ZAD1, AArch64_ZAD2, AArch64_ZAD3, AArch64_ZAD4, AArch64_ZAD5, AArch64_ZAD6, AArch64_ZAD7, 
  };

  // MPR64 Bit set.
  static const uint8_t MPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x01, 
  };

  // ZPR2Strided_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR2Strided_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z8, AArch64_Z1_Z9, AArch64_Z2_Z10, AArch64_Z3_Z11, AArch64_Z4_Z12, AArch64_Z5_Z13, AArch64_Z6_Z14, AArch64_Z7_Z15, 
  };

  // ZPR2Strided_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR2Strided_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 
  };

  // QQQ Register Class...
  static const MCPhysReg QQQ[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, AArch64_Q14_Q15_Q16, AArch64_Q15_Q16_Q17, AArch64_Q16_Q17_Q18, AArch64_Q17_Q18_Q19, AArch64_Q18_Q19_Q20, AArch64_Q19_Q20_Q21, AArch64_Q20_Q21_Q22, AArch64_Q21_Q22_Q23, AArch64_Q22_Q23_Q24, AArch64_Q23_Q24_Q25, AArch64_Q24_Q25_Q26, AArch64_Q25_Q26_Q27, AArch64_Q26_Q27_Q28, AArch64_Q27_Q28_Q29, AArch64_Q28_Q29_Q30, AArch64_Q29_Q30_Q31, AArch64_Q30_Q31_Q0, AArch64_Q31_Q0_Q1, 
  };

  // QQQ Bit set.
  static const uint8_t QQQBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 
  };

  // ZPR3 Register Class...
  static const MCPhysReg ZPR3[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z7_Z8_Z9, AArch64_Z8_Z9_Z10, AArch64_Z9_Z10_Z11, AArch64_Z10_Z11_Z12, AArch64_Z11_Z12_Z13, AArch64_Z12_Z13_Z14, AArch64_Z13_Z14_Z15, AArch64_Z14_Z15_Z16, AArch64_Z15_Z16_Z17, AArch64_Z16_Z17_Z18, AArch64_Z17_Z18_Z19, AArch64_Z18_Z19_Z20, AArch64_Z19_Z20_Z21, AArch64_Z20_Z21_Z22, AArch64_Z21_Z22_Z23, AArch64_Z22_Z23_Z24, AArch64_Z23_Z24_Z25, AArch64_Z24_Z25_Z26, AArch64_Z25_Z26_Z27, AArch64_Z26_Z27_Z28, AArch64_Z27_Z28_Z29, AArch64_Z28_Z29_Z30, AArch64_Z29_Z30_Z31, AArch64_Z30_Z31_Z0, AArch64_Z31_Z0_Z1, 
  };

  // ZPR3 Bit set.
  static const uint8_t ZPR3Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // QQQ_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg QQQ_with_dsub_in_FPR64_lo[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, AArch64_Q14_Q15_Q16, AArch64_Q15_Q16_Q17, 
  };

  // QQQ_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t QQQ_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 
  };

  // QQQ_with_qsub1_in_FPR128_lo Register Class...
  static const MCPhysReg QQQ_with_qsub1_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, AArch64_Q14_Q15_Q16, AArch64_Q31_Q0_Q1, 
  };

  // QQQ_with_qsub1_in_FPR128_lo Bit set.
  static const uint8_t QQQ_with_qsub1_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, 0x00, 0x80, 
  };

  // QQQ_with_qsub2_in_FPR128_lo Register Class...
  static const MCPhysReg QQQ_with_qsub2_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, AArch64_Q30_Q31_Q0, AArch64_Q31_Q0_Q1, 
  };

  // QQQ_with_qsub2_in_FPR128_lo Bit set.
  static const uint8_t QQQ_with_qsub2_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x3f, 0x00, 0xc0, 
  };

  // ZPR3_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR3_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z7_Z8_Z9, AArch64_Z8_Z9_Z10, AArch64_Z9_Z10_Z11, AArch64_Z10_Z11_Z12, AArch64_Z11_Z12_Z13, AArch64_Z12_Z13_Z14, AArch64_Z13_Z14_Z15, AArch64_Z14_Z15_Z16, AArch64_Z15_Z16_Z17, 
  };

  // ZPR3_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR3_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR3_with_zsub0_zsub1_in_ZPR2Mul2[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z2_Z3_Z4, AArch64_Z4_Z5_Z6, AArch64_Z6_Z7_Z8, AArch64_Z8_Z9_Z10, AArch64_Z10_Z11_Z12, AArch64_Z12_Z13_Z14, AArch64_Z14_Z15_Z16, AArch64_Z16_Z17_Z18, AArch64_Z18_Z19_Z20, AArch64_Z20_Z21_Z22, AArch64_Z22_Z23_Z24, AArch64_Z24_Z25_Z26, AArch64_Z26_Z27_Z28, AArch64_Z28_Z29_Z30, AArch64_Z30_Z31_Z0, 
  };

  // ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x55, 0x55, 0x05, 
  };

  // ZPR3_with_zsub1_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR3_with_zsub1_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z7_Z8_Z9, AArch64_Z8_Z9_Z10, AArch64_Z9_Z10_Z11, AArch64_Z10_Z11_Z12, AArch64_Z11_Z12_Z13, AArch64_Z12_Z13_Z14, AArch64_Z13_Z14_Z15, AArch64_Z14_Z15_Z16, AArch64_Z31_Z0_Z1, 
  };

  // ZPR3_with_zsub1_in_ZPR_4b Bit set.
  static const uint8_t ZPR3_with_zsub1_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 0x00, 0x08, 
  };

  // ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR3_with_zsub1_zsub2_in_ZPR2Mul2[] = {
    AArch64_Z1_Z2_Z3, AArch64_Z3_Z4_Z5, AArch64_Z5_Z6_Z7, AArch64_Z7_Z8_Z9, AArch64_Z9_Z10_Z11, AArch64_Z11_Z12_Z13, AArch64_Z13_Z14_Z15, AArch64_Z15_Z16_Z17, AArch64_Z17_Z18_Z19, AArch64_Z19_Z20_Z21, AArch64_Z21_Z22_Z23, AArch64_Z23_Z24_Z25, AArch64_Z25_Z26_Z27, AArch64_Z27_Z28_Z29, AArch64_Z29_Z30_Z31, AArch64_Z31_Z0_Z1, 
  };

  // ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 0xaa, 0xaa, 0x0a, 
  };

  // ZPR3_with_zsub2_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR3_with_zsub2_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z7_Z8_Z9, AArch64_Z8_Z9_Z10, AArch64_Z9_Z10_Z11, AArch64_Z10_Z11_Z12, AArch64_Z11_Z12_Z13, AArch64_Z12_Z13_Z14, AArch64_Z13_Z14_Z15, AArch64_Z30_Z31_Z0, AArch64_Z31_Z0_Z1, 
  };

  // ZPR3_with_zsub2_in_ZPR_4b Bit set.
  static const uint8_t ZPR3_with_zsub2_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x03, 0x00, 0x0c, 
  };

  // QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub1_in_FPR128_lo Register Class...
  static const MCPhysReg QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub1_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, AArch64_Q14_Q15_Q16, 
  };

  // QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub1_in_FPR128_lo Bit set.
  static const uint8_t QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub1_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, 
  };

  // QQQ_with_qsub1_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_lo Register Class...
  static const MCPhysReg QQQ_with_qsub1_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, AArch64_Q31_Q0_Q1, 
  };

  // QQQ_with_qsub1_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_lo Bit set.
  static const uint8_t QQQ_with_qsub1_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x3f, 0x00, 0x80, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z7_Z8_Z9, AArch64_Z8_Z9_Z10, AArch64_Z9_Z10_Z11, AArch64_Z10_Z11_Z12, AArch64_Z11_Z12_Z13, AArch64_Z12_Z13_Z14, AArch64_Z13_Z14_Z15, AArch64_Z14_Z15_Z16, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_4b Bit set.
  static const uint8_t ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 
  };

  // ZPR3_with_zsub1_in_ZPR_4b_and_ZPR3_with_zsub2_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR3_with_zsub1_in_ZPR_4b_and_ZPR3_with_zsub2_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z7_Z8_Z9, AArch64_Z8_Z9_Z10, AArch64_Z9_Z10_Z11, AArch64_Z10_Z11_Z12, AArch64_Z11_Z12_Z13, AArch64_Z12_Z13_Z14, AArch64_Z13_Z14_Z15, AArch64_Z31_Z0_Z1, 
  };

  // ZPR3_with_zsub1_in_ZPR_4b_and_ZPR3_with_zsub2_in_ZPR_4b Bit set.
  static const uint8_t ZPR3_with_zsub1_in_ZPR_4b_and_ZPR3_with_zsub2_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x03, 0x00, 0x08, 
  };

  // QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub2_in_FPR128_lo Register Class...
  static const MCPhysReg QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub2_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, 
  };

  // QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub2_in_FPR128_lo Bit set.
  static const uint8_t QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub2_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x3f, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z7_Z8_Z9, AArch64_Z8_Z9_Z10, AArch64_Z9_Z10_Z11, AArch64_Z10_Z11_Z12, AArch64_Z11_Z12_Z13, AArch64_Z12_Z13_Z14, AArch64_Z13_Z14_Z15, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_4b Bit set.
  static const uint8_t ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x03, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2[] = {
    AArch64_Z1_Z2_Z3, AArch64_Z3_Z4_Z5, AArch64_Z5_Z6_Z7, AArch64_Z7_Z8_Z9, AArch64_Z9_Z10_Z11, AArch64_Z11_Z12_Z13, AArch64_Z13_Z14_Z15, AArch64_Z15_Z16_Z17, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 0x0a, 
  };

  // ZPR3_with_zsub0_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR3_with_zsub0_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z7_Z8_Z9, 
  };

  // ZPR3_with_zsub0_in_ZPR_3b Bit set.
  static const uint8_t ZPR3_with_zsub0_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 
  };

  // ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z2_Z3_Z4, AArch64_Z4_Z5_Z6, AArch64_Z6_Z7_Z8, AArch64_Z8_Z9_Z10, AArch64_Z10_Z11_Z12, AArch64_Z12_Z13_Z14, AArch64_Z14_Z15_Z16, 
  };

  // ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x05, 
  };

  // ZPR3_with_zsub1_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR3_with_zsub1_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z31_Z0_Z1, 
  };

  // ZPR3_with_zsub1_in_ZPR_3b Bit set.
  static const uint8_t ZPR3_with_zsub1_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x07, 0x00, 0x00, 0x08, 
  };

  // ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo[] = {
    AArch64_Z1_Z2_Z3, AArch64_Z3_Z4_Z5, AArch64_Z5_Z6_Z7, AArch64_Z7_Z8_Z9, AArch64_Z9_Z10_Z11, AArch64_Z11_Z12_Z13, AArch64_Z13_Z14_Z15, AArch64_Z31_Z0_Z1, 
  };

  // ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 0x02, 0x00, 0x08, 
  };

  // ZPR3_with_zsub2_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR3_with_zsub2_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z30_Z31_Z0, AArch64_Z31_Z0_Z1, 
  };

  // ZPR3_with_zsub2_in_ZPR_3b Bit set.
  static const uint8_t ZPR3_with_zsub2_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x03, 0x00, 0x00, 0x0c, 
  };

  // ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z2_Z3_Z4, AArch64_Z4_Z5_Z6, AArch64_Z6_Z7_Z8, AArch64_Z8_Z9_Z10, AArch64_Z10_Z11_Z12, AArch64_Z12_Z13_Z14, AArch64_Z30_Z31_Z0, 
  };

  // ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x01, 0x00, 0x04, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_3b Bit set.
  static const uint8_t ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x07, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo[] = {
    AArch64_Z1_Z2_Z3, AArch64_Z3_Z4_Z5, AArch64_Z5_Z6_Z7, AArch64_Z7_Z8_Z9, AArch64_Z9_Z10_Z11, AArch64_Z11_Z12_Z13, AArch64_Z13_Z14_Z15, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 0x02, 
  };

  // ZPR3_with_zsub1_in_ZPR_3b_and_ZPR3_with_zsub2_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR3_with_zsub1_in_ZPR_3b_and_ZPR3_with_zsub2_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z31_Z0_Z1, 
  };

  // ZPR3_with_zsub1_in_ZPR_3b_and_ZPR3_with_zsub2_in_ZPR_3b Bit set.
  static const uint8_t ZPR3_with_zsub1_in_ZPR_3b_and_ZPR3_with_zsub2_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x03, 0x00, 0x00, 0x08, 
  };

  // ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z2_Z3_Z4, AArch64_Z4_Z5_Z6, AArch64_Z6_Z7_Z8, AArch64_Z8_Z9_Z10, AArch64_Z10_Z11_Z12, AArch64_Z12_Z13_Z14, 
  };

  // ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x01, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_3b Bit set.
  static const uint8_t ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x03, 
  };

  // ZPR3_with_zsub0_in_ZPR_3b_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR3_with_zsub0_in_ZPR_3b_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2[] = {
    AArch64_Z1_Z2_Z3, AArch64_Z3_Z4_Z5, AArch64_Z5_Z6_Z7, AArch64_Z7_Z8_Z9, 
  };

  // ZPR3_with_zsub0_in_ZPR_3b_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR3_with_zsub0_in_ZPR_3b_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x0a, 
  };

  // ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z2_Z3_Z4, AArch64_Z4_Z5_Z6, AArch64_Z6_Z7_Z8, 
  };

  // ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b Bit set.
  static const uint8_t ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x05, 
  };

  // ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b[] = {
    AArch64_Z1_Z2_Z3, AArch64_Z3_Z4_Z5, AArch64_Z5_Z6_Z7, AArch64_Z31_Z0_Z1, 
  };

  // ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b Bit set.
  static const uint8_t ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x00, 0x00, 0x08, 
  };

  // ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z2_Z3_Z4, AArch64_Z4_Z5_Z6, AArch64_Z30_Z31_Z0, 
  };

  // ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x01, 0x00, 0x00, 0x04, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b[] = {
    AArch64_Z1_Z2_Z3, AArch64_Z3_Z4_Z5, AArch64_Z5_Z6_Z7, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b Bit set.
  static const uint8_t ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 
  };

  // ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z2_Z3_Z4, AArch64_Z4_Z5_Z6, 
  };

  // ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x01, 
  };

  // QQQQ Register Class...
  static const MCPhysReg QQQQ[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, AArch64_Q14_Q15_Q16_Q17, AArch64_Q15_Q16_Q17_Q18, AArch64_Q16_Q17_Q18_Q19, AArch64_Q17_Q18_Q19_Q20, AArch64_Q18_Q19_Q20_Q21, AArch64_Q19_Q20_Q21_Q22, AArch64_Q20_Q21_Q22_Q23, AArch64_Q21_Q22_Q23_Q24, AArch64_Q22_Q23_Q24_Q25, AArch64_Q23_Q24_Q25_Q26, AArch64_Q24_Q25_Q26_Q27, AArch64_Q25_Q26_Q27_Q28, AArch64_Q26_Q27_Q28_Q29, AArch64_Q27_Q28_Q29_Q30, AArch64_Q28_Q29_Q30_Q31, AArch64_Q29_Q30_Q31_Q0, AArch64_Q30_Q31_Q0_Q1, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQQQ Bit set.
  static const uint8_t QQQQBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 
  };

  // ZPR4 Register Class...
  static const MCPhysReg ZPR4[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z13_Z14_Z15_Z16, AArch64_Z14_Z15_Z16_Z17, AArch64_Z15_Z16_Z17_Z18, AArch64_Z16_Z17_Z18_Z19, AArch64_Z17_Z18_Z19_Z20, AArch64_Z18_Z19_Z20_Z21, AArch64_Z19_Z20_Z21_Z22, AArch64_Z20_Z21_Z22_Z23, AArch64_Z21_Z22_Z23_Z24, AArch64_Z22_Z23_Z24_Z25, AArch64_Z23_Z24_Z25_Z26, AArch64_Z24_Z25_Z26_Z27, AArch64_Z25_Z26_Z27_Z28, AArch64_Z26_Z27_Z28_Z29, AArch64_Z27_Z28_Z29_Z30, AArch64_Z28_Z29_Z30_Z31, AArch64_Z29_Z30_Z31_Z0, AArch64_Z30_Z31_Z0_Z1, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4 Bit set.
  static const uint8_t ZPR4Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // QQQQ_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg QQQQ_with_dsub_in_FPR64_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, AArch64_Q14_Q15_Q16_Q17, AArch64_Q15_Q16_Q17_Q18, 
  };

  // QQQQ_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t QQQQ_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 
  };

  // QQQQ_with_qsub1_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_qsub1_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, AArch64_Q14_Q15_Q16_Q17, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQQQ_with_qsub1_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_qsub1_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, 0x00, 0x80, 
  };

  // QQQQ_with_qsub2_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_qsub2_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, AArch64_Q30_Q31_Q0_Q1, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQQQ_with_qsub2_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_qsub2_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x3f, 0x00, 0xc0, 
  };

  // QQQQ_with_qsub3_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_qsub3_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q29_Q30_Q31_Q0, AArch64_Q30_Q31_Q0_Q1, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQQQ_with_qsub3_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_qsub3_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x1f, 0x00, 0xe0, 
  };

  // ZPR4_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z13_Z14_Z15_Z16, AArch64_Z14_Z15_Z16_Z17, AArch64_Z15_Z16_Z17_Z18, 
  };

  // ZPR4_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // ZPR4_with_zsub0_zsub1_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR4_with_zsub0_zsub1_in_ZPR2Mul2[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z2_Z3_Z4_Z5, AArch64_Z4_Z5_Z6_Z7, AArch64_Z6_Z7_Z8_Z9, AArch64_Z8_Z9_Z10_Z11, AArch64_Z10_Z11_Z12_Z13, AArch64_Z12_Z13_Z14_Z15, AArch64_Z14_Z15_Z16_Z17, AArch64_Z16_Z17_Z18_Z19, AArch64_Z18_Z19_Z20_Z21, AArch64_Z20_Z21_Z22_Z23, AArch64_Z22_Z23_Z24_Z25, AArch64_Z24_Z25_Z26_Z27, AArch64_Z26_Z27_Z28_Z29, AArch64_Z28_Z29_Z30_Z31, AArch64_Z30_Z31_Z0_Z1, 
  };

  // ZPR4_with_zsub0_zsub1_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR4_with_zsub0_zsub1_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x55, 0x55, 0x05, 
  };

  // ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, AArch64_Z5_Z6_Z7_Z8, AArch64_Z7_Z8_Z9_Z10, AArch64_Z9_Z10_Z11_Z12, AArch64_Z11_Z12_Z13_Z14, AArch64_Z13_Z14_Z15_Z16, AArch64_Z15_Z16_Z17_Z18, AArch64_Z17_Z18_Z19_Z20, AArch64_Z19_Z20_Z21_Z22, AArch64_Z21_Z22_Z23_Z24, AArch64_Z23_Z24_Z25_Z26, AArch64_Z25_Z26_Z27_Z28, AArch64_Z27_Z28_Z29_Z30, AArch64_Z29_Z30_Z31_Z0, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 0xaa, 0xaa, 0x0a, 
  };

  // ZPR4_with_zsub1_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_zsub1_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z13_Z14_Z15_Z16, AArch64_Z14_Z15_Z16_Z17, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub1_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_zsub1_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 0x00, 0x08, 
  };

  // ZPR4_with_zsub2_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_zsub2_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z13_Z14_Z15_Z16, AArch64_Z30_Z31_Z0_Z1, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub2_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_zsub2_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x03, 0x00, 0x0c, 
  };

  // ZPR4_with_zsub3_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_zsub3_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z29_Z30_Z31_Z0, AArch64_Z30_Z31_Z0_Z1, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub3_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_zsub3_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x01, 0x00, 0x0e, 
  };

  // QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub1_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub1_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, AArch64_Q14_Q15_Q16_Q17, 
  };

  // QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub1_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub1_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, 
  };

  // QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x3f, 0x00, 0x80, 
  };

  // QQQQ_with_qsub2_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_qsub2_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q30_Q31_Q0_Q1, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQQQ_with_qsub2_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_qsub2_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x1f, 0x00, 0xc0, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z13_Z14_Z15_Z16, AArch64_Z14_Z15_Z16_Z17, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 
  };

  // ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub2_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub2_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z13_Z14_Z15_Z16, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub2_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub2_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x03, 0x00, 0x08, 
  };

  // ZPR4_with_zsub2_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_zsub2_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z30_Z31_Z0_Z1, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub2_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_zsub2_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x01, 0x00, 0x0c, 
  };

  // QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub2_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub2_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, 
  };

  // QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub2_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub2_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x3f, 
  };

  // QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x1f, 0x00, 0x80, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z13_Z14_Z15_Z16, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x03, 
  };

  // ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x01, 0x00, 0x08, 
  };

  // QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub3_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub3_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, 
  };

  // QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub3_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub3_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x1f, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x01, 
  };

  // ZPR4Mul4 Register Class...
  static const MCPhysReg ZPR4Mul4[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z4_Z5_Z6_Z7, AArch64_Z8_Z9_Z10_Z11, AArch64_Z12_Z13_Z14_Z15, AArch64_Z16_Z17_Z18_Z19, AArch64_Z20_Z21_Z22_Z23, AArch64_Z24_Z25_Z26_Z27, AArch64_Z28_Z29_Z30_Z31, 
  };

  // ZPR4Mul4 Bit set.
  static const uint8_t ZPR4Mul4Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x11, 0x11, 0x01, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, AArch64_Z5_Z6_Z7_Z8, AArch64_Z7_Z8_Z9_Z10, AArch64_Z9_Z10_Z11_Z12, AArch64_Z11_Z12_Z13_Z14, AArch64_Z13_Z14_Z15_Z16, AArch64_Z15_Z16_Z17_Z18, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 0x0a, 
  };

  // ZPR4_with_zsub0_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub0_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, 
  };

  // ZPR4_with_zsub0_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub0_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 
  };

  // ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z2_Z3_Z4_Z5, AArch64_Z4_Z5_Z6_Z7, AArch64_Z6_Z7_Z8_Z9, AArch64_Z8_Z9_Z10_Z11, AArch64_Z10_Z11_Z12_Z13, AArch64_Z12_Z13_Z14_Z15, AArch64_Z14_Z15_Z16_Z17, 
  };

  // ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x05, 
  };

  // ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, AArch64_Z5_Z6_Z7_Z8, AArch64_Z7_Z8_Z9_Z10, AArch64_Z9_Z10_Z11_Z12, AArch64_Z11_Z12_Z13_Z14, AArch64_Z13_Z14_Z15_Z16, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 0x02, 0x00, 0x08, 
  };

  // ZPR4_with_zsub1_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub1_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub1_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub1_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x07, 0x00, 0x00, 0x08, 
  };

  // ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z2_Z3_Z4_Z5, AArch64_Z4_Z5_Z6_Z7, AArch64_Z6_Z7_Z8_Z9, AArch64_Z8_Z9_Z10_Z11, AArch64_Z10_Z11_Z12_Z13, AArch64_Z12_Z13_Z14_Z15, AArch64_Z30_Z31_Z0_Z1, 
  };

  // ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x01, 0x00, 0x04, 
  };

  // ZPR4_with_zsub2_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub2_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z30_Z31_Z0_Z1, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub2_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub2_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x03, 0x00, 0x00, 0x0c, 
  };

  // ZPR4_with_zsub3_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub3_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z29_Z30_Z31_Z0, AArch64_Z30_Z31_Z0_Z1, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub3_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub3_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x01, 0x00, 0x00, 0x0e, 
  };

  // ZPR4_with_zsub3_in_ZPR_4b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR4_with_zsub3_in_ZPR_4b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, AArch64_Z5_Z6_Z7_Z8, AArch64_Z7_Z8_Z9_Z10, AArch64_Z9_Z10_Z11_Z12, AArch64_Z11_Z12_Z13_Z14, AArch64_Z29_Z30_Z31_Z0, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub3_in_ZPR_4b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR4_with_zsub3_in_ZPR_4b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 0x00, 0x00, 0x0a, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, AArch64_Z5_Z6_Z7_Z8, AArch64_Z7_Z8_Z9_Z10, AArch64_Z9_Z10_Z11_Z12, AArch64_Z11_Z12_Z13_Z14, AArch64_Z13_Z14_Z15_Z16, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 0x02, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x07, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z2_Z3_Z4_Z5, AArch64_Z4_Z5_Z6_Z7, AArch64_Z6_Z7_Z8_Z9, AArch64_Z8_Z9_Z10_Z11, AArch64_Z10_Z11_Z12_Z13, AArch64_Z12_Z13_Z14_Z15, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x01, 
  };

  // ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub2_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub2_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub2_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub2_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x03, 0x00, 0x00, 0x08, 
  };

  // ZPR4_with_zsub1_in_ZPR_4b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR4_with_zsub1_in_ZPR_4b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, AArch64_Z5_Z6_Z7_Z8, AArch64_Z7_Z8_Z9_Z10, AArch64_Z9_Z10_Z11_Z12, AArch64_Z11_Z12_Z13_Z14, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub1_in_ZPR_4b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR4_with_zsub1_in_ZPR_4b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 0x00, 0x00, 0x08, 
  };

  // ZPR4_with_zsub2_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub2_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z30_Z31_Z0_Z1, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub2_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub2_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x01, 0x00, 0x00, 0x0c, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x03, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, AArch64_Z5_Z6_Z7_Z8, AArch64_Z7_Z8_Z9_Z10, AArch64_Z9_Z10_Z11_Z12, AArch64_Z11_Z12_Z13_Z14, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 
  };

  // ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x01, 0x00, 0x00, 0x08, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x01, 
  };

  // ZPR4Mul4_and_ZPR4_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR4Mul4_and_ZPR4_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z4_Z5_Z6_Z7, AArch64_Z8_Z9_Z10_Z11, AArch64_Z12_Z13_Z14_Z15, 
  };

  // ZPR4Mul4_and_ZPR4_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR4Mul4_and_ZPR4_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x01, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub0_in_ZPR_3b_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub0_in_ZPR_3b_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, AArch64_Z5_Z6_Z7_Z8, AArch64_Z7_Z8_Z9_Z10, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub0_in_ZPR_3b_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub0_in_ZPR_3b_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x0a, 
  };

  // ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z2_Z3_Z4_Z5, AArch64_Z4_Z5_Z6_Z7, AArch64_Z6_Z7_Z8_Z9, 
  };

  // ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x05, 
  };

  // ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, AArch64_Z5_Z6_Z7_Z8, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x00, 0x00, 0x08, 
  };

  // ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z2_Z3_Z4_Z5, AArch64_Z4_Z5_Z6_Z7, AArch64_Z30_Z31_Z0_Z1, 
  };

  // ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x01, 0x00, 0x00, 0x04, 
  };

  // ZPR4_with_zsub3_in_ZPR_3b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR4_with_zsub3_in_ZPR_3b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, AArch64_Z29_Z30_Z31_Z0, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub3_in_ZPR_3b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR4_with_zsub3_in_ZPR_3b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x0a, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, AArch64_Z5_Z6_Z7_Z8, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z2_Z3_Z4_Z5, AArch64_Z4_Z5_Z6_Z7, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x01, 
  };

  // ZPR4_with_zsub1_in_ZPR_3b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR4_with_zsub1_in_ZPR_3b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub1_in_ZPR_3b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR4_with_zsub1_in_ZPR_3b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x08, 
  };

  // ZPR4Mul4_and_ZPR4_with_zsub0_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4Mul4_and_ZPR4_with_zsub0_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z4_Z5_Z6_Z7, 
  };

  // ZPR4Mul4_and_ZPR4_with_zsub0_in_ZPR_3b Bit set.
  static const uint8_t ZPR4Mul4_and_ZPR4_with_zsub0_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 
  };

  // GPR64x8Class Register Class...
  static const MCPhysReg GPR64x8Class[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class Bit set.
  static const uint8_t GPR64x8ClassBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x0f, 
  };

  // GPR64x8Class_with_x8sub_0_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_0_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x0d, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x0e, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x0f, 
  };

  // GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbf, 0x0f, 
  };

  // GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x0c, 
  };

  // GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x0d, 
  };

  // GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbf, 0x0d, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_tcGPR64[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x07, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x0e, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbf, 0x0e, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x0f, 
  };

  // GPR64x8Class_with_x8sub_0_in_GPR64noip_and_tcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_GPR64noip_and_tcGPR64[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_0_in_GPR64noip_and_tcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_GPR64noip_and_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x05, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_2_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_2_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_2_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_2_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x06, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7e, 0x07, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x07, 
  };

  // GPR64x8Class_with_x8sub_1_in_tcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_1_in_tcGPR64[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, 
  };

  // GPR64x8Class_with_x8sub_1_in_tcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_1_in_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x03, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x0c, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbf, 0x0c, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x0d, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x0e, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x04, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7e, 0x05, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x05, 
  };

  // GPR64x8Class_with_x8sub_1_in_GPR64noip_and_tcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_1_in_GPR64noip_and_tcGPR64[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, 
  };

  // GPR64x8Class_with_x8sub_1_in_GPR64noip_and_tcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_1_in_GPR64noip_and_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x01, 
  };

  // GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, 
  };

  // GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7e, 0x03, 
  };

  // GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, 
  };

  // GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x03, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7e, 0x06, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x06, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_tcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64noip_and_tcGPR64[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_tcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64noip_and_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x02, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x07, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x0c, 
  };

  // ZPR4Strided Register Class...
  static const MCPhysReg ZPR4Strided[] = {
    AArch64_Z0_Z4_Z8_Z12, AArch64_Z1_Z5_Z9_Z13, AArch64_Z2_Z6_Z10_Z14, AArch64_Z3_Z7_Z11_Z15, AArch64_Z16_Z20_Z24_Z28, AArch64_Z17_Z21_Z25_Z29, AArch64_Z18_Z22_Z26_Z30, AArch64_Z19_Z23_Z27_Z31, 
  };

  // ZPR4Strided Bit set.
  static const uint8_t ZPR4StridedBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 
  };

  // GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, 
  };

  // GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x01, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7e, 0x04, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x04, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7e, 0x02, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x02, 
  };

  // GPR64x8Class_with_x8sub_3_in_GPR64noip_and_tcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_3_in_GPR64noip_and_tcGPR64[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, 
  };

  // GPR64x8Class_with_x8sub_3_in_GPR64noip_and_tcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_3_in_GPR64noip_and_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x05, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x03, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x06, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_tcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip_and_tcGPR64[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_tcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noip_and_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7e, 0x01, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x01, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x04, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x02, 
  };

  // GPR64x8Class_with_x8sub_5_in_GPR64noip_and_tcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_5_in_GPR64noip_and_tcGPR64[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, 
  };

  // GPR64x8Class_with_x8sub_5_in_GPR64noip_and_tcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_5_in_GPR64noip_and_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7e, 
  };

  // GPR64x8Class_with_x8sub_6_in_GPR64noip_and_tcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_6_in_GPR64noip_and_tcGPR64[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, 
  };

  // GPR64x8Class_with_x8sub_6_in_GPR64noip_and_tcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_6_in_GPR64noip_and_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 
  };

  // GPR64x8Class_with_x8sub_7_in_GPR64noip_and_tcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_7_in_GPR64noip_and_tcGPR64[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, 
  };

  // GPR64x8Class_with_x8sub_7_in_GPR64noip_and_tcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_7_in_GPR64noip_and_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 
  };

  // GPR64x8Class_with_sub_32_in_GPR32arg Register Class...
  static const MCPhysReg GPR64x8Class_with_sub_32_in_GPR32arg[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, 
  };

  // GPR64x8Class_with_sub_32_in_GPR32arg Bit set.
  static const uint8_t GPR64x8Class_with_sub_32_in_GPR32argBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 
  };

  // MPR32 Register Class...
  static const MCPhysReg MPR32[] = {
    AArch64_ZAS0, AArch64_ZAS1, AArch64_ZAS2, AArch64_ZAS3, 
  };

  // MPR32 Bit set.
  static const uint8_t MPR32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 
  };

  // ZPR4Strided_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR4Strided_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z4_Z8_Z12, AArch64_Z1_Z5_Z9_Z13, AArch64_Z2_Z6_Z10_Z14, AArch64_Z3_Z7_Z11_Z15, 
  };

  // ZPR4Strided_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR4Strided_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64arg Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64arg[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64arg Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64argBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 
  };

  // GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_12_15 Register Class...
  static const MCPhysReg GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_12_15[] = {
    AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, 
  };

  // GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_12_15 Bit set.
  static const uint8_t GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_12_15Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 
  };

  // GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11 Register Class...
  static const MCPhysReg GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11[] = {
    AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, 
  };

  // GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11 Bit set.
  static const uint8_t GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_12_15 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_12_15[] = {
    AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_12_15 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_12_15Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11[] = {
    AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11[] = {
    AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64arg Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64arg[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64arg Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64argBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 
  };

  // GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11[] = {
    AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, 
  };

  // GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 
  };

  // GPR64x8Class_with_sub_32_in_GPR32arg_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Register Class...
  static const MCPhysReg GPR64x8Class_with_sub_32_in_GPR32arg_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11[] = {
    AArch64_X6_X7_X8_X9_X10_X11_X12_X13, 
  };

  // GPR64x8Class_with_sub_32_in_GPR32arg_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Bit set.
  static const uint8_t GPR64x8Class_with_sub_32_in_GPR32arg_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 
  };

  // GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Register Class...
  static const MCPhysReg GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11[] = {
    AArch64_X8_X9_X10_X11_X12_X13_X14_X15, 
  };

  // GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Bit set.
  static const uint8_t GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 
  };

  // GPR64x8Class_with_x8sub_0_in_rtcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_rtcGPR64[] = {
    AArch64_X16_X17_X18_X19_X20_X21_X22_X23, 
  };

  // GPR64x8Class_with_x8sub_0_in_rtcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_rtcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64arg_and_GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64arg_and_GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11[] = {
    AArch64_X4_X5_X6_X7_X8_X9_X10_X11, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64arg_and_GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64arg_and_GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 
  };

  // GPR64x8Class_with_x8sub_2_in_rtcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_rtcGPR64[] = {
    AArch64_X14_X15_X16_X17_X18_X19_X20_X21, 
  };

  // GPR64x8Class_with_x8sub_2_in_rtcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_rtcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64arg_and_GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64arg_and_GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11[] = {
    AArch64_X2_X3_X4_X5_X6_X7_X8_X9, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64arg_and_GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64arg_and_GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 
  };

  // GPR64x8Class_with_x8sub_4_in_rtcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_rtcGPR64[] = {
    AArch64_X12_X13_X14_X15_X16_X17_X18_X19, 
  };

  // GPR64x8Class_with_x8sub_4_in_rtcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_rtcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 
  };

  // GPR64x8Class_with_x8sub_6_in_GPR64arg Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_6_in_GPR64arg[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, 
  };

  // GPR64x8Class_with_x8sub_6_in_GPR64arg Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_6_in_GPR64argBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 
  };

  // GPR64x8Class_with_x8sub_6_in_rtcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_6_in_rtcGPR64[] = {
    AArch64_X10_X11_X12_X13_X14_X15_X16_X17, 
  };

  // GPR64x8Class_with_x8sub_6_in_rtcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_6_in_rtcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 
  };

  // GPR64x8Class_with_x8sub_7_in_FIXED_REGS Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_7_in_FIXED_REGS[] = {
    AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_7_in_FIXED_REGS Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_7_in_FIXED_REGSBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
  };

  // ZTR Register Class...
  static const MCPhysReg ZTR[] = {
    AArch64_ZT0, 
  };

  // ZTR Bit set.
  static const uint8_t ZTRBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 
  };

  // MPR16 Register Class...
  static const MCPhysReg MPR16[] = {
    AArch64_ZAH0, AArch64_ZAH1, 
  };

  // MPR16 Bit set.
  static const uint8_t MPR16Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 
  };

  // MPR Register Class...
  static const MCPhysReg MPR[] = {
    AArch64_ZA, 
  };

  // MPR Bit set.
  static const uint8_t MPRBits[] = {
    0x00, 0x08, 
  };

  // MPR8 Register Class...
  static const MCPhysReg MPR8[] = {
    AArch64_ZAB0, 
  };

  // MPR8 Bit set.
  static const uint8_t MPR8Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
  };

static const MCRegisterClass AArch64MCRegisterClasses[] = {
  { FPR8, FPR8Bits, sizeof(FPR8Bits) },
  { FPR16, FPR16Bits, sizeof(FPR16Bits) },
  { FPR16_lo, FPR16_loBits, sizeof(FPR16_loBits) },
  { PPR, PPRBits, sizeof(PPRBits) },
  { PPR_3b, PPR_3bBits, sizeof(PPR_3bBits) },
  { PPR_p8to15, PPR_p8to15Bits, sizeof(PPR_p8to15Bits) },
  { PPR2, PPR2Bits, sizeof(PPR2Bits) },
  { PPR2Mul2, PPR2Mul2Bits, sizeof(PPR2Mul2Bits) },
  { PPR2_with_psub0_in_PPR_3b, PPR2_with_psub0_in_PPR_3bBits, sizeof(PPR2_with_psub0_in_PPR_3bBits) },
  { PPR2_with_psub0_in_PPR_p8to15, PPR2_with_psub0_in_PPR_p8to15Bits, sizeof(PPR2_with_psub0_in_PPR_p8to15Bits) },
  { PPR2_with_psub1_in_PPR_3b, PPR2_with_psub1_in_PPR_3bBits, sizeof(PPR2_with_psub1_in_PPR_3bBits) },
  { PPR2_with_psub1_in_PPR_p8to15, PPR2_with_psub1_in_PPR_p8to15Bits, sizeof(PPR2_with_psub1_in_PPR_p8to15Bits) },
  { PPR2_with_psub0_in_PPR_3b_and_PPR2_with_psub1_in_PPR_3b, PPR2_with_psub0_in_PPR_3b_and_PPR2_with_psub1_in_PPR_3bBits, sizeof(PPR2_with_psub0_in_PPR_3b_and_PPR2_with_psub1_in_PPR_3bBits) },
  { PPR2_with_psub0_in_PPR_p8to15_and_PPR2_with_psub1_in_PPR_p8to15, PPR2_with_psub0_in_PPR_p8to15_and_PPR2_with_psub1_in_PPR_p8to15Bits, sizeof(PPR2_with_psub0_in_PPR_p8to15_and_PPR2_with_psub1_in_PPR_p8to15Bits) },
  { PPR2Mul2_and_PPR2_with_psub0_in_PPR_3b, PPR2Mul2_and_PPR2_with_psub0_in_PPR_3bBits, sizeof(PPR2Mul2_and_PPR2_with_psub0_in_PPR_3bBits) },
  { PPR2Mul2_and_PPR2_with_psub0_in_PPR_p8to15, PPR2Mul2_and_PPR2_with_psub0_in_PPR_p8to15Bits, sizeof(PPR2Mul2_and_PPR2_with_psub0_in_PPR_p8to15Bits) },
  { PPR2_with_psub0_in_PPR_3b_and_PPR2_with_psub1_in_PPR_p8to15, PPR2_with_psub0_in_PPR_3b_and_PPR2_with_psub1_in_PPR_p8to15Bits, sizeof(PPR2_with_psub0_in_PPR_3b_and_PPR2_with_psub1_in_PPR_p8to15Bits) },
  { PPR2_with_psub0_in_PPR_p8to15_and_PPR2_with_psub1_in_PPR_3b, PPR2_with_psub0_in_PPR_p8to15_and_PPR2_with_psub1_in_PPR_3bBits, sizeof(PPR2_with_psub0_in_PPR_p8to15_and_PPR2_with_psub1_in_PPR_3bBits) },
  { GPR32all, GPR32allBits, sizeof(GPR32allBits) },
  { FPR32, FPR32Bits, sizeof(FPR32Bits) },
  { GPR32, GPR32Bits, sizeof(GPR32Bits) },
  { GPR32sp, GPR32spBits, sizeof(GPR32spBits) },
  { GPR32common, GPR32commonBits, sizeof(GPR32commonBits) },
  { FPR32_with_hsub_in_FPR16_lo, FPR32_with_hsub_in_FPR16_loBits, sizeof(FPR32_with_hsub_in_FPR16_loBits) },
  { GPR32arg, GPR32argBits, sizeof(GPR32argBits) },
  { MatrixIndexGPR32_12_15, MatrixIndexGPR32_12_15Bits, sizeof(MatrixIndexGPR32_12_15Bits) },
  { MatrixIndexGPR32_8_11, MatrixIndexGPR32_8_11Bits, sizeof(MatrixIndexGPR32_8_11Bits) },
  { CCR, CCRBits, sizeof(CCRBits) },
  { GPR32sponly, GPR32sponlyBits, sizeof(GPR32sponlyBits) },
  { WSeqPairsClass, WSeqPairsClassBits, sizeof(WSeqPairsClassBits) },
  { WSeqPairsClass_with_subo32_in_GPR32common, WSeqPairsClass_with_subo32_in_GPR32commonBits, sizeof(WSeqPairsClass_with_subo32_in_GPR32commonBits) },
  { WSeqPairsClass_with_sube32_in_GPR32arg, WSeqPairsClass_with_sube32_in_GPR32argBits, sizeof(WSeqPairsClass_with_sube32_in_GPR32argBits) },
  { WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_12_15, WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_12_15Bits, sizeof(WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_12_15Bits) },
  { WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_8_11, WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_8_11Bits, sizeof(WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_8_11Bits) },
  { GPR64all, GPR64allBits, sizeof(GPR64allBits) },
  { FPR64, FPR64Bits, sizeof(FPR64Bits) },
  { GPR64, GPR64Bits, sizeof(GPR64Bits) },
  { GPR64sp, GPR64spBits, sizeof(GPR64spBits) },
  { GPR64common, GPR64commonBits, sizeof(GPR64commonBits) },
  { GPR64noip, GPR64noipBits, sizeof(GPR64noipBits) },
  { GPR64common_and_GPR64noip, GPR64common_and_GPR64noipBits, sizeof(GPR64common_and_GPR64noipBits) },
  { tcGPR64, tcGPR64Bits, sizeof(tcGPR64Bits) },
  { GPR64noip_and_tcGPR64, GPR64noip_and_tcGPR64Bits, sizeof(GPR64noip_and_tcGPR64Bits) },
  { FPR64_lo, FPR64_loBits, sizeof(FPR64_loBits) },
  { GPR64arg, GPR64argBits, sizeof(GPR64argBits) },
  { FIXED_REGS, FIXED_REGSBits, sizeof(FIXED_REGSBits) },
  { GPR64_with_sub_32_in_MatrixIndexGPR32_12_15, GPR64_with_sub_32_in_MatrixIndexGPR32_12_15Bits, sizeof(GPR64_with_sub_32_in_MatrixIndexGPR32_12_15Bits) },
  { GPR64_with_sub_32_in_MatrixIndexGPR32_8_11, GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits, sizeof(GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits) },
  { FIXED_REGS_with_sub_32, FIXED_REGS_with_sub_32Bits, sizeof(FIXED_REGS_with_sub_32Bits) },
  { rtcGPR64, rtcGPR64Bits, sizeof(rtcGPR64Bits) },
  { FIXED_REGS_and_GPR64, FIXED_REGS_and_GPR64Bits, sizeof(FIXED_REGS_and_GPR64Bits) },
  { GPR64sponly, GPR64sponlyBits, sizeof(GPR64sponlyBits) },
  { DD, DDBits, sizeof(DDBits) },
  { DD_with_dsub0_in_FPR64_lo, DD_with_dsub0_in_FPR64_loBits, sizeof(DD_with_dsub0_in_FPR64_loBits) },
  { DD_with_dsub1_in_FPR64_lo, DD_with_dsub1_in_FPR64_loBits, sizeof(DD_with_dsub1_in_FPR64_loBits) },
  { XSeqPairsClass, XSeqPairsClassBits, sizeof(XSeqPairsClassBits) },
  { DD_with_dsub0_in_FPR64_lo_and_DD_with_dsub1_in_FPR64_lo, DD_with_dsub0_in_FPR64_lo_and_DD_with_dsub1_in_FPR64_loBits, sizeof(DD_with_dsub0_in_FPR64_lo_and_DD_with_dsub1_in_FPR64_loBits) },
  { XSeqPairsClass_with_subo64_in_GPR64common, XSeqPairsClass_with_subo64_in_GPR64commonBits, sizeof(XSeqPairsClass_with_subo64_in_GPR64commonBits) },
  { XSeqPairsClass_with_subo64_in_GPR64noip, XSeqPairsClass_with_subo64_in_GPR64noipBits, sizeof(XSeqPairsClass_with_subo64_in_GPR64noipBits) },
  { XSeqPairsClass_with_sube64_in_GPR64noip, XSeqPairsClass_with_sube64_in_GPR64noipBits, sizeof(XSeqPairsClass_with_sube64_in_GPR64noipBits) },
  { XSeqPairsClass_with_sube64_in_tcGPR64, XSeqPairsClass_with_sube64_in_tcGPR64Bits, sizeof(XSeqPairsClass_with_sube64_in_tcGPR64Bits) },
  { XSeqPairsClass_with_sube64_in_GPR64noip_and_tcGPR64, XSeqPairsClass_with_sube64_in_GPR64noip_and_tcGPR64Bits, sizeof(XSeqPairsClass_with_sube64_in_GPR64noip_and_tcGPR64Bits) },
  { XSeqPairsClass_with_subo64_in_tcGPR64, XSeqPairsClass_with_subo64_in_tcGPR64Bits, sizeof(XSeqPairsClass_with_subo64_in_tcGPR64Bits) },
  { XSeqPairsClass_with_subo64_in_GPR64noip_and_tcGPR64, XSeqPairsClass_with_subo64_in_GPR64noip_and_tcGPR64Bits, sizeof(XSeqPairsClass_with_subo64_in_GPR64noip_and_tcGPR64Bits) },
  { XSeqPairsClass_with_sub_32_in_GPR32arg, XSeqPairsClass_with_sub_32_in_GPR32argBits, sizeof(XSeqPairsClass_with_sub_32_in_GPR32argBits) },
  { XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_12_15, XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_12_15Bits, sizeof(XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_12_15Bits) },
  { XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_8_11, XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_8_11Bits, sizeof(XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_8_11Bits) },
  { XSeqPairsClass_with_sube64_in_rtcGPR64, XSeqPairsClass_with_sube64_in_rtcGPR64Bits, sizeof(XSeqPairsClass_with_sube64_in_rtcGPR64Bits) },
  { XSeqPairsClass_with_subo64_in_FIXED_REGS, XSeqPairsClass_with_subo64_in_FIXED_REGSBits, sizeof(XSeqPairsClass_with_subo64_in_FIXED_REGSBits) },
  { FPR128, FPR128Bits, sizeof(FPR128Bits) },
  { ZPR, ZPRBits, sizeof(ZPRBits) },
  { FPR128_lo, FPR128_loBits, sizeof(FPR128_loBits) },
  { MPR128, MPR128Bits, sizeof(MPR128Bits) },
  { ZPR_4b, ZPR_4bBits, sizeof(ZPR_4bBits) },
  { ZPR_3b, ZPR_3bBits, sizeof(ZPR_3bBits) },
  { DDD, DDDBits, sizeof(DDDBits) },
  { DDD_with_dsub0_in_FPR64_lo, DDD_with_dsub0_in_FPR64_loBits, sizeof(DDD_with_dsub0_in_FPR64_loBits) },
  { DDD_with_dsub1_in_FPR64_lo, DDD_with_dsub1_in_FPR64_loBits, sizeof(DDD_with_dsub1_in_FPR64_loBits) },
  { DDD_with_dsub2_in_FPR64_lo, DDD_with_dsub2_in_FPR64_loBits, sizeof(DDD_with_dsub2_in_FPR64_loBits) },
  { DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub1_in_FPR64_lo, DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub1_in_FPR64_loBits, sizeof(DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub1_in_FPR64_loBits) },
  { DDD_with_dsub1_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_lo, DDD_with_dsub1_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_loBits, sizeof(DDD_with_dsub1_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_loBits) },
  { DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_lo, DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_loBits, sizeof(DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_loBits) },
  { DDDD, DDDDBits, sizeof(DDDDBits) },
  { DDDD_with_dsub0_in_FPR64_lo, DDDD_with_dsub0_in_FPR64_loBits, sizeof(DDDD_with_dsub0_in_FPR64_loBits) },
  { DDDD_with_dsub1_in_FPR64_lo, DDDD_with_dsub1_in_FPR64_loBits, sizeof(DDDD_with_dsub1_in_FPR64_loBits) },
  { DDDD_with_dsub2_in_FPR64_lo, DDDD_with_dsub2_in_FPR64_loBits, sizeof(DDDD_with_dsub2_in_FPR64_loBits) },
  { DDDD_with_dsub3_in_FPR64_lo, DDDD_with_dsub3_in_FPR64_loBits, sizeof(DDDD_with_dsub3_in_FPR64_loBits) },
  { DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub1_in_FPR64_lo, DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub1_in_FPR64_loBits, sizeof(DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub1_in_FPR64_loBits) },
  { DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_lo, DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_loBits, sizeof(DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_loBits) },
  { DDDD_with_dsub2_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_lo, DDDD_with_dsub2_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_loBits, sizeof(DDDD_with_dsub2_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_loBits) },
  { DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_lo, DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_loBits, sizeof(DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_loBits) },
  { DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_lo, DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_loBits, sizeof(DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_loBits) },
  { DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_lo, DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_loBits, sizeof(DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_loBits) },
  { QQ, QQBits, sizeof(QQBits) },
  { ZPR2, ZPR2Bits, sizeof(ZPR2Bits) },
  { QQ_with_dsub_in_FPR64_lo, QQ_with_dsub_in_FPR64_loBits, sizeof(QQ_with_dsub_in_FPR64_loBits) },
  { QQ_with_qsub1_in_FPR128_lo, QQ_with_qsub1_in_FPR128_loBits, sizeof(QQ_with_qsub1_in_FPR128_loBits) },
  { ZPR2Mul2, ZPR2Mul2Bits, sizeof(ZPR2Mul2Bits) },
  { ZPR2_with_dsub_in_FPR64_lo, ZPR2_with_dsub_in_FPR64_loBits, sizeof(ZPR2_with_dsub_in_FPR64_loBits) },
  { ZPR2_with_zsub1_in_ZPR_4b, ZPR2_with_zsub1_in_ZPR_4bBits, sizeof(ZPR2_with_zsub1_in_ZPR_4bBits) },
  { QQ_with_dsub_in_FPR64_lo_and_QQ_with_qsub1_in_FPR128_lo, QQ_with_dsub_in_FPR64_lo_and_QQ_with_qsub1_in_FPR128_loBits, sizeof(QQ_with_dsub_in_FPR64_lo_and_QQ_with_qsub1_in_FPR128_loBits) },
  { ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_4b, ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_4bBits, sizeof(ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_4bBits) },
  { ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo, ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits, sizeof(ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits) },
  { ZPR2_with_zsub0_in_ZPR_3b, ZPR2_with_zsub0_in_ZPR_3bBits, sizeof(ZPR2_with_zsub0_in_ZPR_3bBits) },
  { ZPR2_with_zsub1_in_ZPR_3b, ZPR2_with_zsub1_in_ZPR_3bBits, sizeof(ZPR2_with_zsub1_in_ZPR_3bBits) },
  { ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_3b, ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_3bBits, sizeof(ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_3bBits) },
  { ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b, ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits, sizeof(ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits) },
  { ZPR2Strided, ZPR2StridedBits, sizeof(ZPR2StridedBits) },
  { MPR64, MPR64Bits, sizeof(MPR64Bits) },
  { ZPR2Strided_with_dsub_in_FPR64_lo, ZPR2Strided_with_dsub_in_FPR64_loBits, sizeof(ZPR2Strided_with_dsub_in_FPR64_loBits) },
  { QQQ, QQQBits, sizeof(QQQBits) },
  { ZPR3, ZPR3Bits, sizeof(ZPR3Bits) },
  { QQQ_with_dsub_in_FPR64_lo, QQQ_with_dsub_in_FPR64_loBits, sizeof(QQQ_with_dsub_in_FPR64_loBits) },
  { QQQ_with_qsub1_in_FPR128_lo, QQQ_with_qsub1_in_FPR128_loBits, sizeof(QQQ_with_qsub1_in_FPR128_loBits) },
  { QQQ_with_qsub2_in_FPR128_lo, QQQ_with_qsub2_in_FPR128_loBits, sizeof(QQQ_with_qsub2_in_FPR128_loBits) },
  { ZPR3_with_dsub_in_FPR64_lo, ZPR3_with_dsub_in_FPR64_loBits, sizeof(ZPR3_with_dsub_in_FPR64_loBits) },
  { ZPR3_with_zsub0_zsub1_in_ZPR2Mul2, ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits, sizeof(ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits) },
  { ZPR3_with_zsub1_in_ZPR_4b, ZPR3_with_zsub1_in_ZPR_4bBits, sizeof(ZPR3_with_zsub1_in_ZPR_4bBits) },
  { ZPR3_with_zsub1_zsub2_in_ZPR2Mul2, ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits, sizeof(ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits) },
  { ZPR3_with_zsub2_in_ZPR_4b, ZPR3_with_zsub2_in_ZPR_4bBits, sizeof(ZPR3_with_zsub2_in_ZPR_4bBits) },
  { QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub1_in_FPR128_lo, QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub1_in_FPR128_loBits, sizeof(QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub1_in_FPR128_loBits) },
  { QQQ_with_qsub1_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_lo, QQQ_with_qsub1_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_loBits, sizeof(QQQ_with_qsub1_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_loBits) },
  { ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_4b, ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_4bBits, sizeof(ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_4bBits) },
  { ZPR3_with_zsub1_in_ZPR_4b_and_ZPR3_with_zsub2_in_ZPR_4b, ZPR3_with_zsub1_in_ZPR_4b_and_ZPR3_with_zsub2_in_ZPR_4bBits, sizeof(ZPR3_with_zsub1_in_ZPR_4b_and_ZPR3_with_zsub2_in_ZPR_4bBits) },
  { QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub2_in_FPR128_lo, QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub2_in_FPR128_loBits, sizeof(QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub2_in_FPR128_loBits) },
  { ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_4b, ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_4bBits, sizeof(ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_4bBits) },
  { ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2, ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits, sizeof(ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits) },
  { ZPR3_with_zsub0_in_ZPR_3b, ZPR3_with_zsub0_in_ZPR_3bBits, sizeof(ZPR3_with_zsub0_in_ZPR_3bBits) },
  { ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo, ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits, sizeof(ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits) },
  { ZPR3_with_zsub1_in_ZPR_3b, ZPR3_with_zsub1_in_ZPR_3bBits, sizeof(ZPR3_with_zsub1_in_ZPR_3bBits) },
  { ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo, ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits, sizeof(ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits) },
  { ZPR3_with_zsub2_in_ZPR_3b, ZPR3_with_zsub2_in_ZPR_3bBits, sizeof(ZPR3_with_zsub2_in_ZPR_3bBits) },
  { ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2, ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits, sizeof(ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits) },
  { ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_3b, ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_3bBits, sizeof(ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_3bBits) },
  { ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo, ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits, sizeof(ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits) },
  { ZPR3_with_zsub1_in_ZPR_3b_and_ZPR3_with_zsub2_in_ZPR_3b, ZPR3_with_zsub1_in_ZPR_3b_and_ZPR3_with_zsub2_in_ZPR_3bBits, sizeof(ZPR3_with_zsub1_in_ZPR_3b_and_ZPR3_with_zsub2_in_ZPR_3bBits) },
  { ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo, ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits, sizeof(ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits) },
  { ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_3b, ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_3bBits, sizeof(ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_3bBits) },
  { ZPR3_with_zsub0_in_ZPR_3b_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2, ZPR3_with_zsub0_in_ZPR_3b_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits, sizeof(ZPR3_with_zsub0_in_ZPR_3b_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits) },
  { ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b, ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits, sizeof(ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits) },
  { ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b, ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits, sizeof(ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits) },
  { ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2, ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits, sizeof(ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits) },
  { ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b, ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits, sizeof(ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits) },
  { ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo, ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits, sizeof(ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits) },
  { QQQQ, QQQQBits, sizeof(QQQQBits) },
  { ZPR4, ZPR4Bits, sizeof(ZPR4Bits) },
  { QQQQ_with_dsub_in_FPR64_lo, QQQQ_with_dsub_in_FPR64_loBits, sizeof(QQQQ_with_dsub_in_FPR64_loBits) },
  { QQQQ_with_qsub1_in_FPR128_lo, QQQQ_with_qsub1_in_FPR128_loBits, sizeof(QQQQ_with_qsub1_in_FPR128_loBits) },
  { QQQQ_with_qsub2_in_FPR128_lo, QQQQ_with_qsub2_in_FPR128_loBits, sizeof(QQQQ_with_qsub2_in_FPR128_loBits) },
  { QQQQ_with_qsub3_in_FPR128_lo, QQQQ_with_qsub3_in_FPR128_loBits, sizeof(QQQQ_with_qsub3_in_FPR128_loBits) },
  { ZPR4_with_dsub_in_FPR64_lo, ZPR4_with_dsub_in_FPR64_loBits, sizeof(ZPR4_with_dsub_in_FPR64_loBits) },
  { ZPR4_with_zsub0_zsub1_in_ZPR2Mul2, ZPR4_with_zsub0_zsub1_in_ZPR2Mul2Bits, sizeof(ZPR4_with_zsub0_zsub1_in_ZPR2Mul2Bits) },
  { ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2, ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits, sizeof(ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits) },
  { ZPR4_with_zsub1_in_ZPR_4b, ZPR4_with_zsub1_in_ZPR_4bBits, sizeof(ZPR4_with_zsub1_in_ZPR_4bBits) },
  { ZPR4_with_zsub2_in_ZPR_4b, ZPR4_with_zsub2_in_ZPR_4bBits, sizeof(ZPR4_with_zsub2_in_ZPR_4bBits) },
  { ZPR4_with_zsub3_in_ZPR_4b, ZPR4_with_zsub3_in_ZPR_4bBits, sizeof(ZPR4_with_zsub3_in_ZPR_4bBits) },
  { QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub1_in_FPR128_lo, QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub1_in_FPR128_loBits, sizeof(QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub1_in_FPR128_loBits) },
  { QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_lo, QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_loBits, sizeof(QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_loBits) },
  { QQQQ_with_qsub2_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo, QQQQ_with_qsub2_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_loBits, sizeof(QQQQ_with_qsub2_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_loBits) },
  { ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_4b, ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_4bBits, sizeof(ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_4bBits) },
  { ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub2_in_ZPR_4b, ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub2_in_ZPR_4bBits, sizeof(ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub2_in_ZPR_4bBits) },
  { ZPR4_with_zsub2_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4b, ZPR4_with_zsub2_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4bBits, sizeof(ZPR4_with_zsub2_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4bBits) },
  { QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub2_in_FPR128_lo, QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub2_in_FPR128_loBits, sizeof(QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub2_in_FPR128_loBits) },
  { QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo, QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_loBits, sizeof(QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_loBits) },
  { ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_4b, ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_4bBits, sizeof(ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_4bBits) },
  { ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4b, ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4bBits, sizeof(ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4bBits) },
  { QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub3_in_FPR128_lo, QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub3_in_FPR128_loBits, sizeof(QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub3_in_FPR128_loBits) },
  { ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_4b, ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_4bBits, sizeof(ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_4bBits) },
  { ZPR4Mul4, ZPR4Mul4Bits, sizeof(ZPR4Mul4Bits) },
  { ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2, ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits, sizeof(ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits) },
  { ZPR4_with_zsub0_in_ZPR_3b, ZPR4_with_zsub0_in_ZPR_3bBits, sizeof(ZPR4_with_zsub0_in_ZPR_3bBits) },
  { ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo, ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits, sizeof(ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits) },
  { ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo, ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits, sizeof(ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits) },
  { ZPR4_with_zsub1_in_ZPR_3b, ZPR4_with_zsub1_in_ZPR_3bBits, sizeof(ZPR4_with_zsub1_in_ZPR_3bBits) },
  { ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo, ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits, sizeof(ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits) },
  { ZPR4_with_zsub2_in_ZPR_3b, ZPR4_with_zsub2_in_ZPR_3bBits, sizeof(ZPR4_with_zsub2_in_ZPR_3bBits) },
  { ZPR4_with_zsub3_in_ZPR_3b, ZPR4_with_zsub3_in_ZPR_3bBits, sizeof(ZPR4_with_zsub3_in_ZPR_3bBits) },
  { ZPR4_with_zsub3_in_ZPR_4b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2, ZPR4_with_zsub3_in_ZPR_4b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits, sizeof(ZPR4_with_zsub3_in_ZPR_4b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits) },
  { ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo, ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits, sizeof(ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits) },
  { ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_3b, ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_3bBits, sizeof(ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_3bBits) },
  { ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo, ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits, sizeof(ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits) },
  { ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub2_in_ZPR_3b, ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub2_in_ZPR_3bBits, sizeof(ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub2_in_ZPR_3bBits) },
  { ZPR4_with_zsub1_in_ZPR_4b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2, ZPR4_with_zsub1_in_ZPR_4b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits, sizeof(ZPR4_with_zsub1_in_ZPR_4b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits) },
  { ZPR4_with_zsub2_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3b, ZPR4_with_zsub2_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3bBits, sizeof(ZPR4_with_zsub2_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3bBits) },
  { ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_3b, ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_3bBits, sizeof(ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_3bBits) },
  { ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2, ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits, sizeof(ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits) },
  { ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3b, ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3bBits, sizeof(ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3bBits) },
  { ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_3b, ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_3bBits, sizeof(ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_3bBits) },
  { ZPR4Mul4_and_ZPR4_with_dsub_in_FPR64_lo, ZPR4Mul4_and_ZPR4_with_dsub_in_FPR64_loBits, sizeof(ZPR4Mul4_and_ZPR4_with_dsub_in_FPR64_loBits) },
  { ZPR4_with_dsub_in_FPR64_lo_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub0_in_ZPR_3b_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2, ZPR4_with_dsub_in_FPR64_lo_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub0_in_ZPR_3b_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits, sizeof(ZPR4_with_dsub_in_FPR64_lo_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub0_in_ZPR_3b_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits) },
  { ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b, ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits, sizeof(ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits) },
  { ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b, ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits, sizeof(ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits) },
  { ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b, ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits, sizeof(ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits) },
  { ZPR4_with_zsub3_in_ZPR_3b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2, ZPR4_with_zsub3_in_ZPR_3b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits, sizeof(ZPR4_with_zsub3_in_ZPR_3b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits) },
  { ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b, ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits, sizeof(ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits) },
  { ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3b, ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits, sizeof(ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub0_in_ZPR_3bBits) },
  { ZPR4_with_zsub1_in_ZPR_3b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2, ZPR4_with_zsub1_in_ZPR_3b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits, sizeof(ZPR4_with_zsub1_in_ZPR_3b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits) },
  { ZPR4Mul4_and_ZPR4_with_zsub0_in_ZPR_3b, ZPR4Mul4_and_ZPR4_with_zsub0_in_ZPR_3bBits, sizeof(ZPR4Mul4_and_ZPR4_with_zsub0_in_ZPR_3bBits) },
  { ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2, ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits, sizeof(ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits) },
  { GPR64x8Class, GPR64x8ClassBits, sizeof(GPR64x8ClassBits) },
  { GPR64x8Class_with_x8sub_0_in_GPR64noip, GPR64x8Class_with_x8sub_0_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_0_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_2_in_GPR64noip, GPR64x8Class_with_x8sub_2_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_2_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_4_in_GPR64noip, GPR64x8Class_with_x8sub_4_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_4_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_6_in_GPR64noip, GPR64x8Class_with_x8sub_6_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_6_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip, GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip, GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip, GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_0_in_tcGPR64, GPR64x8Class_with_x8sub_0_in_tcGPR64Bits, sizeof(GPR64x8Class_with_x8sub_0_in_tcGPR64Bits) },
  { GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip, GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip, GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip, GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_0_in_GPR64noip_and_tcGPR64, GPR64x8Class_with_x8sub_0_in_GPR64noip_and_tcGPR64Bits, sizeof(GPR64x8Class_with_x8sub_0_in_GPR64noip_and_tcGPR64Bits) },
  { GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_2_in_GPR64noip, GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_2_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_2_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip, GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip, GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_1_in_tcGPR64, GPR64x8Class_with_x8sub_1_in_tcGPR64Bits, sizeof(GPR64x8Class_with_x8sub_1_in_tcGPR64Bits) },
  { GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip, GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip, GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip, GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip, GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip, GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip, GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip, GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_1_in_GPR64noip_and_tcGPR64, GPR64x8Class_with_x8sub_1_in_GPR64noip_and_tcGPR64Bits, sizeof(GPR64x8Class_with_x8sub_1_in_GPR64noip_and_tcGPR64Bits) },
  { GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip, GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip, GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip, GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip, GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_2_in_GPR64noip_and_tcGPR64, GPR64x8Class_with_x8sub_2_in_GPR64noip_and_tcGPR64Bits, sizeof(GPR64x8Class_with_x8sub_2_in_GPR64noip_and_tcGPR64Bits) },
  { GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip, GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip, GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits) },
  { ZPR4Strided, ZPR4StridedBits, sizeof(ZPR4StridedBits) },
  { GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip, GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip, GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip, GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip, GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip, GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_3_in_GPR64noip_and_tcGPR64, GPR64x8Class_with_x8sub_3_in_GPR64noip_and_tcGPR64Bits, sizeof(GPR64x8Class_with_x8sub_3_in_GPR64noip_and_tcGPR64Bits) },
  { GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip, GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip, GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip, GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_4_in_GPR64noip_and_tcGPR64, GPR64x8Class_with_x8sub_4_in_GPR64noip_and_tcGPR64Bits, sizeof(GPR64x8Class_with_x8sub_4_in_GPR64noip_and_tcGPR64Bits) },
  { GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip, GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip, GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip, GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits, sizeof(GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits) },
  { GPR64x8Class_with_x8sub_5_in_GPR64noip_and_tcGPR64, GPR64x8Class_with_x8sub_5_in_GPR64noip_and_tcGPR64Bits, sizeof(GPR64x8Class_with_x8sub_5_in_GPR64noip_and_tcGPR64Bits) },
  { GPR64x8Class_with_x8sub_6_in_GPR64noip_and_tcGPR64, GPR64x8Class_with_x8sub_6_in_GPR64noip_and_tcGPR64Bits, sizeof(GPR64x8Class_with_x8sub_6_in_GPR64noip_and_tcGPR64Bits) },
  { GPR64x8Class_with_x8sub_7_in_GPR64noip_and_tcGPR64, GPR64x8Class_with_x8sub_7_in_GPR64noip_and_tcGPR64Bits, sizeof(GPR64x8Class_with_x8sub_7_in_GPR64noip_and_tcGPR64Bits) },
  { GPR64x8Class_with_sub_32_in_GPR32arg, GPR64x8Class_with_sub_32_in_GPR32argBits, sizeof(GPR64x8Class_with_sub_32_in_GPR32argBits) },
  { MPR32, MPR32Bits, sizeof(MPR32Bits) },
  { ZPR4Strided_with_dsub_in_FPR64_lo, ZPR4Strided_with_dsub_in_FPR64_loBits, sizeof(ZPR4Strided_with_dsub_in_FPR64_loBits) },
  { GPR64x8Class_with_x8sub_2_in_GPR64arg, GPR64x8Class_with_x8sub_2_in_GPR64argBits, sizeof(GPR64x8Class_with_x8sub_2_in_GPR64argBits) },
  { GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_12_15, GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_12_15Bits, sizeof(GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_12_15Bits) },
  { GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11, GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11Bits, sizeof(GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11Bits) },
  { GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_12_15, GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_12_15Bits, sizeof(GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_12_15Bits) },
  { GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11, GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits, sizeof(GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits) },
  { GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11, GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits, sizeof(GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits) },
  { GPR64x8Class_with_x8sub_4_in_GPR64arg, GPR64x8Class_with_x8sub_4_in_GPR64argBits, sizeof(GPR64x8Class_with_x8sub_4_in_GPR64argBits) },
  { GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11, GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits, sizeof(GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits) },
  { GPR64x8Class_with_sub_32_in_GPR32arg_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11, GPR64x8Class_with_sub_32_in_GPR32arg_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits, sizeof(GPR64x8Class_with_sub_32_in_GPR32arg_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits) },
  { GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11, GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits, sizeof(GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits) },
  { GPR64x8Class_with_x8sub_0_in_rtcGPR64, GPR64x8Class_with_x8sub_0_in_rtcGPR64Bits, sizeof(GPR64x8Class_with_x8sub_0_in_rtcGPR64Bits) },
  { GPR64x8Class_with_x8sub_2_in_GPR64arg_and_GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11, GPR64x8Class_with_x8sub_2_in_GPR64arg_and_GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits, sizeof(GPR64x8Class_with_x8sub_2_in_GPR64arg_and_GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits) },
  { GPR64x8Class_with_x8sub_2_in_rtcGPR64, GPR64x8Class_with_x8sub_2_in_rtcGPR64Bits, sizeof(GPR64x8Class_with_x8sub_2_in_rtcGPR64Bits) },
  { GPR64x8Class_with_x8sub_4_in_GPR64arg_and_GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11, GPR64x8Class_with_x8sub_4_in_GPR64arg_and_GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits, sizeof(GPR64x8Class_with_x8sub_4_in_GPR64arg_and_GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits) },
  { GPR64x8Class_with_x8sub_4_in_rtcGPR64, GPR64x8Class_with_x8sub_4_in_rtcGPR64Bits, sizeof(GPR64x8Class_with_x8sub_4_in_rtcGPR64Bits) },
  { GPR64x8Class_with_x8sub_6_in_GPR64arg, GPR64x8Class_with_x8sub_6_in_GPR64argBits, sizeof(GPR64x8Class_with_x8sub_6_in_GPR64argBits) },
  { GPR64x8Class_with_x8sub_6_in_rtcGPR64, GPR64x8Class_with_x8sub_6_in_rtcGPR64Bits, sizeof(GPR64x8Class_with_x8sub_6_in_rtcGPR64Bits) },
  { GPR64x8Class_with_x8sub_7_in_FIXED_REGS, GPR64x8Class_with_x8sub_7_in_FIXED_REGSBits, sizeof(GPR64x8Class_with_x8sub_7_in_FIXED_REGSBits) },
  { ZTR, ZTRBits, sizeof(ZTRBits) },
  { MPR16, MPR16Bits, sizeof(MPR16Bits) },
  { MPR, MPRBits, sizeof(MPRBits) },
  { MPR8, MPR8Bits, sizeof(MPR8Bits) },
};

static const uint16_t AArch64RegEncodingTable[] = {
  0,
  0,
  29,
  0,
  30,
  0,
  31,
  0,
  31,
  31,
  31,
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
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
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
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  0,
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
  10,
  11,
  12,
  13,
  14,
  15,
  0,
  1,
  2,
  3,
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
  8,
  9,
  10,
  11,
  12,
  13,
  14,
  15,
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
  22,
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
  30,
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
  28,
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
  16,
  17,
  18,
  19,
  20,
  21,
  22,
  23,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  16,
  17,
  18,
  19,
  0,
  1,
  2,
  3,
};
#endif // GET_REGINFO_MC_DESC




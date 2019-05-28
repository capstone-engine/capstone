
/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */

/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Register Enum Values                                                *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

#ifdef GET_REGINFO_ENUM
#undef GET_REGINFO_ENUM

enum {
  AArch64_NoRegister,
  AArch64_FFR = 1,
  AArch64_FP = 2,
  AArch64_LR = 3,
  AArch64_NZCV = 4,
  AArch64_SP = 5,
  AArch64_WSP = 6,
  AArch64_WZR = 7,
  AArch64_XZR = 8,
  AArch64_B0 = 9,
  AArch64_B1 = 10,
  AArch64_B2 = 11,
  AArch64_B3 = 12,
  AArch64_B4 = 13,
  AArch64_B5 = 14,
  AArch64_B6 = 15,
  AArch64_B7 = 16,
  AArch64_B8 = 17,
  AArch64_B9 = 18,
  AArch64_B10 = 19,
  AArch64_B11 = 20,
  AArch64_B12 = 21,
  AArch64_B13 = 22,
  AArch64_B14 = 23,
  AArch64_B15 = 24,
  AArch64_B16 = 25,
  AArch64_B17 = 26,
  AArch64_B18 = 27,
  AArch64_B19 = 28,
  AArch64_B20 = 29,
  AArch64_B21 = 30,
  AArch64_B22 = 31,
  AArch64_B23 = 32,
  AArch64_B24 = 33,
  AArch64_B25 = 34,
  AArch64_B26 = 35,
  AArch64_B27 = 36,
  AArch64_B28 = 37,
  AArch64_B29 = 38,
  AArch64_B30 = 39,
  AArch64_B31 = 40,
  AArch64_D0 = 41,
  AArch64_D1 = 42,
  AArch64_D2 = 43,
  AArch64_D3 = 44,
  AArch64_D4 = 45,
  AArch64_D5 = 46,
  AArch64_D6 = 47,
  AArch64_D7 = 48,
  AArch64_D8 = 49,
  AArch64_D9 = 50,
  AArch64_D10 = 51,
  AArch64_D11 = 52,
  AArch64_D12 = 53,
  AArch64_D13 = 54,
  AArch64_D14 = 55,
  AArch64_D15 = 56,
  AArch64_D16 = 57,
  AArch64_D17 = 58,
  AArch64_D18 = 59,
  AArch64_D19 = 60,
  AArch64_D20 = 61,
  AArch64_D21 = 62,
  AArch64_D22 = 63,
  AArch64_D23 = 64,
  AArch64_D24 = 65,
  AArch64_D25 = 66,
  AArch64_D26 = 67,
  AArch64_D27 = 68,
  AArch64_D28 = 69,
  AArch64_D29 = 70,
  AArch64_D30 = 71,
  AArch64_D31 = 72,
  AArch64_H0 = 73,
  AArch64_H1 = 74,
  AArch64_H2 = 75,
  AArch64_H3 = 76,
  AArch64_H4 = 77,
  AArch64_H5 = 78,
  AArch64_H6 = 79,
  AArch64_H7 = 80,
  AArch64_H8 = 81,
  AArch64_H9 = 82,
  AArch64_H10 = 83,
  AArch64_H11 = 84,
  AArch64_H12 = 85,
  AArch64_H13 = 86,
  AArch64_H14 = 87,
  AArch64_H15 = 88,
  AArch64_H16 = 89,
  AArch64_H17 = 90,
  AArch64_H18 = 91,
  AArch64_H19 = 92,
  AArch64_H20 = 93,
  AArch64_H21 = 94,
  AArch64_H22 = 95,
  AArch64_H23 = 96,
  AArch64_H24 = 97,
  AArch64_H25 = 98,
  AArch64_H26 = 99,
  AArch64_H27 = 100,
  AArch64_H28 = 101,
  AArch64_H29 = 102,
  AArch64_H30 = 103,
  AArch64_H31 = 104,
  AArch64_P0 = 105,
  AArch64_P1 = 106,
  AArch64_P2 = 107,
  AArch64_P3 = 108,
  AArch64_P4 = 109,
  AArch64_P5 = 110,
  AArch64_P6 = 111,
  AArch64_P7 = 112,
  AArch64_P8 = 113,
  AArch64_P9 = 114,
  AArch64_P10 = 115,
  AArch64_P11 = 116,
  AArch64_P12 = 117,
  AArch64_P13 = 118,
  AArch64_P14 = 119,
  AArch64_P15 = 120,
  AArch64_Q0 = 121,
  AArch64_Q1 = 122,
  AArch64_Q2 = 123,
  AArch64_Q3 = 124,
  AArch64_Q4 = 125,
  AArch64_Q5 = 126,
  AArch64_Q6 = 127,
  AArch64_Q7 = 128,
  AArch64_Q8 = 129,
  AArch64_Q9 = 130,
  AArch64_Q10 = 131,
  AArch64_Q11 = 132,
  AArch64_Q12 = 133,
  AArch64_Q13 = 134,
  AArch64_Q14 = 135,
  AArch64_Q15 = 136,
  AArch64_Q16 = 137,
  AArch64_Q17 = 138,
  AArch64_Q18 = 139,
  AArch64_Q19 = 140,
  AArch64_Q20 = 141,
  AArch64_Q21 = 142,
  AArch64_Q22 = 143,
  AArch64_Q23 = 144,
  AArch64_Q24 = 145,
  AArch64_Q25 = 146,
  AArch64_Q26 = 147,
  AArch64_Q27 = 148,
  AArch64_Q28 = 149,
  AArch64_Q29 = 150,
  AArch64_Q30 = 151,
  AArch64_Q31 = 152,
  AArch64_S0 = 153,
  AArch64_S1 = 154,
  AArch64_S2 = 155,
  AArch64_S3 = 156,
  AArch64_S4 = 157,
  AArch64_S5 = 158,
  AArch64_S6 = 159,
  AArch64_S7 = 160,
  AArch64_S8 = 161,
  AArch64_S9 = 162,
  AArch64_S10 = 163,
  AArch64_S11 = 164,
  AArch64_S12 = 165,
  AArch64_S13 = 166,
  AArch64_S14 = 167,
  AArch64_S15 = 168,
  AArch64_S16 = 169,
  AArch64_S17 = 170,
  AArch64_S18 = 171,
  AArch64_S19 = 172,
  AArch64_S20 = 173,
  AArch64_S21 = 174,
  AArch64_S22 = 175,
  AArch64_S23 = 176,
  AArch64_S24 = 177,
  AArch64_S25 = 178,
  AArch64_S26 = 179,
  AArch64_S27 = 180,
  AArch64_S28 = 181,
  AArch64_S29 = 182,
  AArch64_S30 = 183,
  AArch64_S31 = 184,
  AArch64_W0 = 185,
  AArch64_W1 = 186,
  AArch64_W2 = 187,
  AArch64_W3 = 188,
  AArch64_W4 = 189,
  AArch64_W5 = 190,
  AArch64_W6 = 191,
  AArch64_W7 = 192,
  AArch64_W8 = 193,
  AArch64_W9 = 194,
  AArch64_W10 = 195,
  AArch64_W11 = 196,
  AArch64_W12 = 197,
  AArch64_W13 = 198,
  AArch64_W14 = 199,
  AArch64_W15 = 200,
  AArch64_W16 = 201,
  AArch64_W17 = 202,
  AArch64_W18 = 203,
  AArch64_W19 = 204,
  AArch64_W20 = 205,
  AArch64_W21 = 206,
  AArch64_W22 = 207,
  AArch64_W23 = 208,
  AArch64_W24 = 209,
  AArch64_W25 = 210,
  AArch64_W26 = 211,
  AArch64_W27 = 212,
  AArch64_W28 = 213,
  AArch64_W29 = 214,
  AArch64_W30 = 215,
  AArch64_X0 = 216,
  AArch64_X1 = 217,
  AArch64_X2 = 218,
  AArch64_X3 = 219,
  AArch64_X4 = 220,
  AArch64_X5 = 221,
  AArch64_X6 = 222,
  AArch64_X7 = 223,
  AArch64_X8 = 224,
  AArch64_X9 = 225,
  AArch64_X10 = 226,
  AArch64_X11 = 227,
  AArch64_X12 = 228,
  AArch64_X13 = 229,
  AArch64_X14 = 230,
  AArch64_X15 = 231,
  AArch64_X16 = 232,
  AArch64_X17 = 233,
  AArch64_X18 = 234,
  AArch64_X19 = 235,
  AArch64_X20 = 236,
  AArch64_X21 = 237,
  AArch64_X22 = 238,
  AArch64_X23 = 239,
  AArch64_X24 = 240,
  AArch64_X25 = 241,
  AArch64_X26 = 242,
  AArch64_X27 = 243,
  AArch64_X28 = 244,
  AArch64_Z0 = 245,
  AArch64_Z1 = 246,
  AArch64_Z2 = 247,
  AArch64_Z3 = 248,
  AArch64_Z4 = 249,
  AArch64_Z5 = 250,
  AArch64_Z6 = 251,
  AArch64_Z7 = 252,
  AArch64_Z8 = 253,
  AArch64_Z9 = 254,
  AArch64_Z10 = 255,
  AArch64_Z11 = 256,
  AArch64_Z12 = 257,
  AArch64_Z13 = 258,
  AArch64_Z14 = 259,
  AArch64_Z15 = 260,
  AArch64_Z16 = 261,
  AArch64_Z17 = 262,
  AArch64_Z18 = 263,
  AArch64_Z19 = 264,
  AArch64_Z20 = 265,
  AArch64_Z21 = 266,
  AArch64_Z22 = 267,
  AArch64_Z23 = 268,
  AArch64_Z24 = 269,
  AArch64_Z25 = 270,
  AArch64_Z26 = 271,
  AArch64_Z27 = 272,
  AArch64_Z28 = 273,
  AArch64_Z29 = 274,
  AArch64_Z30 = 275,
  AArch64_Z31 = 276,
  AArch64_Z0_HI = 277,
  AArch64_Z1_HI = 278,
  AArch64_Z2_HI = 279,
  AArch64_Z3_HI = 280,
  AArch64_Z4_HI = 281,
  AArch64_Z5_HI = 282,
  AArch64_Z6_HI = 283,
  AArch64_Z7_HI = 284,
  AArch64_Z8_HI = 285,
  AArch64_Z9_HI = 286,
  AArch64_Z10_HI = 287,
  AArch64_Z11_HI = 288,
  AArch64_Z12_HI = 289,
  AArch64_Z13_HI = 290,
  AArch64_Z14_HI = 291,
  AArch64_Z15_HI = 292,
  AArch64_Z16_HI = 293,
  AArch64_Z17_HI = 294,
  AArch64_Z18_HI = 295,
  AArch64_Z19_HI = 296,
  AArch64_Z20_HI = 297,
  AArch64_Z21_HI = 298,
  AArch64_Z22_HI = 299,
  AArch64_Z23_HI = 300,
  AArch64_Z24_HI = 301,
  AArch64_Z25_HI = 302,
  AArch64_Z26_HI = 303,
  AArch64_Z27_HI = 304,
  AArch64_Z28_HI = 305,
  AArch64_Z29_HI = 306,
  AArch64_Z30_HI = 307,
  AArch64_Z31_HI = 308,
  AArch64_D0_D1 = 309,
  AArch64_D1_D2 = 310,
  AArch64_D2_D3 = 311,
  AArch64_D3_D4 = 312,
  AArch64_D4_D5 = 313,
  AArch64_D5_D6 = 314,
  AArch64_D6_D7 = 315,
  AArch64_D7_D8 = 316,
  AArch64_D8_D9 = 317,
  AArch64_D9_D10 = 318,
  AArch64_D10_D11 = 319,
  AArch64_D11_D12 = 320,
  AArch64_D12_D13 = 321,
  AArch64_D13_D14 = 322,
  AArch64_D14_D15 = 323,
  AArch64_D15_D16 = 324,
  AArch64_D16_D17 = 325,
  AArch64_D17_D18 = 326,
  AArch64_D18_D19 = 327,
  AArch64_D19_D20 = 328,
  AArch64_D20_D21 = 329,
  AArch64_D21_D22 = 330,
  AArch64_D22_D23 = 331,
  AArch64_D23_D24 = 332,
  AArch64_D24_D25 = 333,
  AArch64_D25_D26 = 334,
  AArch64_D26_D27 = 335,
  AArch64_D27_D28 = 336,
  AArch64_D28_D29 = 337,
  AArch64_D29_D30 = 338,
  AArch64_D30_D31 = 339,
  AArch64_D31_D0 = 340,
  AArch64_D0_D1_D2_D3 = 341,
  AArch64_D1_D2_D3_D4 = 342,
  AArch64_D2_D3_D4_D5 = 343,
  AArch64_D3_D4_D5_D6 = 344,
  AArch64_D4_D5_D6_D7 = 345,
  AArch64_D5_D6_D7_D8 = 346,
  AArch64_D6_D7_D8_D9 = 347,
  AArch64_D7_D8_D9_D10 = 348,
  AArch64_D8_D9_D10_D11 = 349,
  AArch64_D9_D10_D11_D12 = 350,
  AArch64_D10_D11_D12_D13 = 351,
  AArch64_D11_D12_D13_D14 = 352,
  AArch64_D12_D13_D14_D15 = 353,
  AArch64_D13_D14_D15_D16 = 354,
  AArch64_D14_D15_D16_D17 = 355,
  AArch64_D15_D16_D17_D18 = 356,
  AArch64_D16_D17_D18_D19 = 357,
  AArch64_D17_D18_D19_D20 = 358,
  AArch64_D18_D19_D20_D21 = 359,
  AArch64_D19_D20_D21_D22 = 360,
  AArch64_D20_D21_D22_D23 = 361,
  AArch64_D21_D22_D23_D24 = 362,
  AArch64_D22_D23_D24_D25 = 363,
  AArch64_D23_D24_D25_D26 = 364,
  AArch64_D24_D25_D26_D27 = 365,
  AArch64_D25_D26_D27_D28 = 366,
  AArch64_D26_D27_D28_D29 = 367,
  AArch64_D27_D28_D29_D30 = 368,
  AArch64_D28_D29_D30_D31 = 369,
  AArch64_D29_D30_D31_D0 = 370,
  AArch64_D30_D31_D0_D1 = 371,
  AArch64_D31_D0_D1_D2 = 372,
  AArch64_D0_D1_D2 = 373,
  AArch64_D1_D2_D3 = 374,
  AArch64_D2_D3_D4 = 375,
  AArch64_D3_D4_D5 = 376,
  AArch64_D4_D5_D6 = 377,
  AArch64_D5_D6_D7 = 378,
  AArch64_D6_D7_D8 = 379,
  AArch64_D7_D8_D9 = 380,
  AArch64_D8_D9_D10 = 381,
  AArch64_D9_D10_D11 = 382,
  AArch64_D10_D11_D12 = 383,
  AArch64_D11_D12_D13 = 384,
  AArch64_D12_D13_D14 = 385,
  AArch64_D13_D14_D15 = 386,
  AArch64_D14_D15_D16 = 387,
  AArch64_D15_D16_D17 = 388,
  AArch64_D16_D17_D18 = 389,
  AArch64_D17_D18_D19 = 390,
  AArch64_D18_D19_D20 = 391,
  AArch64_D19_D20_D21 = 392,
  AArch64_D20_D21_D22 = 393,
  AArch64_D21_D22_D23 = 394,
  AArch64_D22_D23_D24 = 395,
  AArch64_D23_D24_D25 = 396,
  AArch64_D24_D25_D26 = 397,
  AArch64_D25_D26_D27 = 398,
  AArch64_D26_D27_D28 = 399,
  AArch64_D27_D28_D29 = 400,
  AArch64_D28_D29_D30 = 401,
  AArch64_D29_D30_D31 = 402,
  AArch64_D30_D31_D0 = 403,
  AArch64_D31_D0_D1 = 404,
  AArch64_Q0_Q1 = 405,
  AArch64_Q1_Q2 = 406,
  AArch64_Q2_Q3 = 407,
  AArch64_Q3_Q4 = 408,
  AArch64_Q4_Q5 = 409,
  AArch64_Q5_Q6 = 410,
  AArch64_Q6_Q7 = 411,
  AArch64_Q7_Q8 = 412,
  AArch64_Q8_Q9 = 413,
  AArch64_Q9_Q10 = 414,
  AArch64_Q10_Q11 = 415,
  AArch64_Q11_Q12 = 416,
  AArch64_Q12_Q13 = 417,
  AArch64_Q13_Q14 = 418,
  AArch64_Q14_Q15 = 419,
  AArch64_Q15_Q16 = 420,
  AArch64_Q16_Q17 = 421,
  AArch64_Q17_Q18 = 422,
  AArch64_Q18_Q19 = 423,
  AArch64_Q19_Q20 = 424,
  AArch64_Q20_Q21 = 425,
  AArch64_Q21_Q22 = 426,
  AArch64_Q22_Q23 = 427,
  AArch64_Q23_Q24 = 428,
  AArch64_Q24_Q25 = 429,
  AArch64_Q25_Q26 = 430,
  AArch64_Q26_Q27 = 431,
  AArch64_Q27_Q28 = 432,
  AArch64_Q28_Q29 = 433,
  AArch64_Q29_Q30 = 434,
  AArch64_Q30_Q31 = 435,
  AArch64_Q31_Q0 = 436,
  AArch64_Q0_Q1_Q2_Q3 = 437,
  AArch64_Q1_Q2_Q3_Q4 = 438,
  AArch64_Q2_Q3_Q4_Q5 = 439,
  AArch64_Q3_Q4_Q5_Q6 = 440,
  AArch64_Q4_Q5_Q6_Q7 = 441,
  AArch64_Q5_Q6_Q7_Q8 = 442,
  AArch64_Q6_Q7_Q8_Q9 = 443,
  AArch64_Q7_Q8_Q9_Q10 = 444,
  AArch64_Q8_Q9_Q10_Q11 = 445,
  AArch64_Q9_Q10_Q11_Q12 = 446,
  AArch64_Q10_Q11_Q12_Q13 = 447,
  AArch64_Q11_Q12_Q13_Q14 = 448,
  AArch64_Q12_Q13_Q14_Q15 = 449,
  AArch64_Q13_Q14_Q15_Q16 = 450,
  AArch64_Q14_Q15_Q16_Q17 = 451,
  AArch64_Q15_Q16_Q17_Q18 = 452,
  AArch64_Q16_Q17_Q18_Q19 = 453,
  AArch64_Q17_Q18_Q19_Q20 = 454,
  AArch64_Q18_Q19_Q20_Q21 = 455,
  AArch64_Q19_Q20_Q21_Q22 = 456,
  AArch64_Q20_Q21_Q22_Q23 = 457,
  AArch64_Q21_Q22_Q23_Q24 = 458,
  AArch64_Q22_Q23_Q24_Q25 = 459,
  AArch64_Q23_Q24_Q25_Q26 = 460,
  AArch64_Q24_Q25_Q26_Q27 = 461,
  AArch64_Q25_Q26_Q27_Q28 = 462,
  AArch64_Q26_Q27_Q28_Q29 = 463,
  AArch64_Q27_Q28_Q29_Q30 = 464,
  AArch64_Q28_Q29_Q30_Q31 = 465,
  AArch64_Q29_Q30_Q31_Q0 = 466,
  AArch64_Q30_Q31_Q0_Q1 = 467,
  AArch64_Q31_Q0_Q1_Q2 = 468,
  AArch64_Q0_Q1_Q2 = 469,
  AArch64_Q1_Q2_Q3 = 470,
  AArch64_Q2_Q3_Q4 = 471,
  AArch64_Q3_Q4_Q5 = 472,
  AArch64_Q4_Q5_Q6 = 473,
  AArch64_Q5_Q6_Q7 = 474,
  AArch64_Q6_Q7_Q8 = 475,
  AArch64_Q7_Q8_Q9 = 476,
  AArch64_Q8_Q9_Q10 = 477,
  AArch64_Q9_Q10_Q11 = 478,
  AArch64_Q10_Q11_Q12 = 479,
  AArch64_Q11_Q12_Q13 = 480,
  AArch64_Q12_Q13_Q14 = 481,
  AArch64_Q13_Q14_Q15 = 482,
  AArch64_Q14_Q15_Q16 = 483,
  AArch64_Q15_Q16_Q17 = 484,
  AArch64_Q16_Q17_Q18 = 485,
  AArch64_Q17_Q18_Q19 = 486,
  AArch64_Q18_Q19_Q20 = 487,
  AArch64_Q19_Q20_Q21 = 488,
  AArch64_Q20_Q21_Q22 = 489,
  AArch64_Q21_Q22_Q23 = 490,
  AArch64_Q22_Q23_Q24 = 491,
  AArch64_Q23_Q24_Q25 = 492,
  AArch64_Q24_Q25_Q26 = 493,
  AArch64_Q25_Q26_Q27 = 494,
  AArch64_Q26_Q27_Q28 = 495,
  AArch64_Q27_Q28_Q29 = 496,
  AArch64_Q28_Q29_Q30 = 497,
  AArch64_Q29_Q30_Q31 = 498,
  AArch64_Q30_Q31_Q0 = 499,
  AArch64_Q31_Q0_Q1 = 500,
  AArch64_WZR_W0 = 501,
  AArch64_W30_WZR = 502,
  AArch64_W0_W1 = 503,
  AArch64_W1_W2 = 504,
  AArch64_W2_W3 = 505,
  AArch64_W3_W4 = 506,
  AArch64_W4_W5 = 507,
  AArch64_W5_W6 = 508,
  AArch64_W6_W7 = 509,
  AArch64_W7_W8 = 510,
  AArch64_W8_W9 = 511,
  AArch64_W9_W10 = 512,
  AArch64_W10_W11 = 513,
  AArch64_W11_W12 = 514,
  AArch64_W12_W13 = 515,
  AArch64_W13_W14 = 516,
  AArch64_W14_W15 = 517,
  AArch64_W15_W16 = 518,
  AArch64_W16_W17 = 519,
  AArch64_W17_W18 = 520,
  AArch64_W18_W19 = 521,
  AArch64_W19_W20 = 522,
  AArch64_W20_W21 = 523,
  AArch64_W21_W22 = 524,
  AArch64_W22_W23 = 525,
  AArch64_W23_W24 = 526,
  AArch64_W24_W25 = 527,
  AArch64_W25_W26 = 528,
  AArch64_W26_W27 = 529,
  AArch64_W27_W28 = 530,
  AArch64_W28_W29 = 531,
  AArch64_W29_W30 = 532,
  AArch64_FP_LR = 533,
  AArch64_LR_XZR = 534,
  AArch64_XZR_X0 = 535,
  AArch64_X28_FP = 536,
  AArch64_X0_X1 = 537,
  AArch64_X1_X2 = 538,
  AArch64_X2_X3 = 539,
  AArch64_X3_X4 = 540,
  AArch64_X4_X5 = 541,
  AArch64_X5_X6 = 542,
  AArch64_X6_X7 = 543,
  AArch64_X7_X8 = 544,
  AArch64_X8_X9 = 545,
  AArch64_X9_X10 = 546,
  AArch64_X10_X11 = 547,
  AArch64_X11_X12 = 548,
  AArch64_X12_X13 = 549,
  AArch64_X13_X14 = 550,
  AArch64_X14_X15 = 551,
  AArch64_X15_X16 = 552,
  AArch64_X16_X17 = 553,
  AArch64_X17_X18 = 554,
  AArch64_X18_X19 = 555,
  AArch64_X19_X20 = 556,
  AArch64_X20_X21 = 557,
  AArch64_X21_X22 = 558,
  AArch64_X22_X23 = 559,
  AArch64_X23_X24 = 560,
  AArch64_X24_X25 = 561,
  AArch64_X25_X26 = 562,
  AArch64_X26_X27 = 563,
  AArch64_X27_X28 = 564,
  AArch64_Z0_Z1 = 565,
  AArch64_Z1_Z2 = 566,
  AArch64_Z2_Z3 = 567,
  AArch64_Z3_Z4 = 568,
  AArch64_Z4_Z5 = 569,
  AArch64_Z5_Z6 = 570,
  AArch64_Z6_Z7 = 571,
  AArch64_Z7_Z8 = 572,
  AArch64_Z8_Z9 = 573,
  AArch64_Z9_Z10 = 574,
  AArch64_Z10_Z11 = 575,
  AArch64_Z11_Z12 = 576,
  AArch64_Z12_Z13 = 577,
  AArch64_Z13_Z14 = 578,
  AArch64_Z14_Z15 = 579,
  AArch64_Z15_Z16 = 580,
  AArch64_Z16_Z17 = 581,
  AArch64_Z17_Z18 = 582,
  AArch64_Z18_Z19 = 583,
  AArch64_Z19_Z20 = 584,
  AArch64_Z20_Z21 = 585,
  AArch64_Z21_Z22 = 586,
  AArch64_Z22_Z23 = 587,
  AArch64_Z23_Z24 = 588,
  AArch64_Z24_Z25 = 589,
  AArch64_Z25_Z26 = 590,
  AArch64_Z26_Z27 = 591,
  AArch64_Z27_Z28 = 592,
  AArch64_Z28_Z29 = 593,
  AArch64_Z29_Z30 = 594,
  AArch64_Z30_Z31 = 595,
  AArch64_Z31_Z0 = 596,
  AArch64_Z0_Z1_Z2_Z3 = 597,
  AArch64_Z1_Z2_Z3_Z4 = 598,
  AArch64_Z2_Z3_Z4_Z5 = 599,
  AArch64_Z3_Z4_Z5_Z6 = 600,
  AArch64_Z4_Z5_Z6_Z7 = 601,
  AArch64_Z5_Z6_Z7_Z8 = 602,
  AArch64_Z6_Z7_Z8_Z9 = 603,
  AArch64_Z7_Z8_Z9_Z10 = 604,
  AArch64_Z8_Z9_Z10_Z11 = 605,
  AArch64_Z9_Z10_Z11_Z12 = 606,
  AArch64_Z10_Z11_Z12_Z13 = 607,
  AArch64_Z11_Z12_Z13_Z14 = 608,
  AArch64_Z12_Z13_Z14_Z15 = 609,
  AArch64_Z13_Z14_Z15_Z16 = 610,
  AArch64_Z14_Z15_Z16_Z17 = 611,
  AArch64_Z15_Z16_Z17_Z18 = 612,
  AArch64_Z16_Z17_Z18_Z19 = 613,
  AArch64_Z17_Z18_Z19_Z20 = 614,
  AArch64_Z18_Z19_Z20_Z21 = 615,
  AArch64_Z19_Z20_Z21_Z22 = 616,
  AArch64_Z20_Z21_Z22_Z23 = 617,
  AArch64_Z21_Z22_Z23_Z24 = 618,
  AArch64_Z22_Z23_Z24_Z25 = 619,
  AArch64_Z23_Z24_Z25_Z26 = 620,
  AArch64_Z24_Z25_Z26_Z27 = 621,
  AArch64_Z25_Z26_Z27_Z28 = 622,
  AArch64_Z26_Z27_Z28_Z29 = 623,
  AArch64_Z27_Z28_Z29_Z30 = 624,
  AArch64_Z28_Z29_Z30_Z31 = 625,
  AArch64_Z29_Z30_Z31_Z0 = 626,
  AArch64_Z30_Z31_Z0_Z1 = 627,
  AArch64_Z31_Z0_Z1_Z2 = 628,
  AArch64_Z0_Z1_Z2 = 629,
  AArch64_Z1_Z2_Z3 = 630,
  AArch64_Z2_Z3_Z4 = 631,
  AArch64_Z3_Z4_Z5 = 632,
  AArch64_Z4_Z5_Z6 = 633,
  AArch64_Z5_Z6_Z7 = 634,
  AArch64_Z6_Z7_Z8 = 635,
  AArch64_Z7_Z8_Z9 = 636,
  AArch64_Z8_Z9_Z10 = 637,
  AArch64_Z9_Z10_Z11 = 638,
  AArch64_Z10_Z11_Z12 = 639,
  AArch64_Z11_Z12_Z13 = 640,
  AArch64_Z12_Z13_Z14 = 641,
  AArch64_Z13_Z14_Z15 = 642,
  AArch64_Z14_Z15_Z16 = 643,
  AArch64_Z15_Z16_Z17 = 644,
  AArch64_Z16_Z17_Z18 = 645,
  AArch64_Z17_Z18_Z19 = 646,
  AArch64_Z18_Z19_Z20 = 647,
  AArch64_Z19_Z20_Z21 = 648,
  AArch64_Z20_Z21_Z22 = 649,
  AArch64_Z21_Z22_Z23 = 650,
  AArch64_Z22_Z23_Z24 = 651,
  AArch64_Z23_Z24_Z25 = 652,
  AArch64_Z24_Z25_Z26 = 653,
  AArch64_Z25_Z26_Z27 = 654,
  AArch64_Z26_Z27_Z28 = 655,
  AArch64_Z27_Z28_Z29 = 656,
  AArch64_Z28_Z29_Z30 = 657,
  AArch64_Z29_Z30_Z31 = 658,
  AArch64_Z30_Z31_Z0 = 659,
  AArch64_Z31_Z0_Z1 = 660,
  AArch64_NUM_TARGET_REGS 	// 661
};

// Register classes
enum {
  AArch64_FPR8RegClassID = 0,
  AArch64_FPR16RegClassID = 1,
  AArch64_PPRRegClassID = 2,
  AArch64_PPR_3bRegClassID = 3,
  AArch64_GPR32allRegClassID = 4,
  AArch64_FPR32RegClassID = 5,
  AArch64_GPR32RegClassID = 6,
  AArch64_GPR32spRegClassID = 7,
  AArch64_GPR32commonRegClassID = 8,
  AArch64_CCRRegClassID = 9,
  AArch64_GPR32sponlyRegClassID = 10,
  AArch64_WSeqPairsClassRegClassID = 11,
  AArch64_WSeqPairsClass_with_sube32_in_GPR32commonRegClassID = 12,
  AArch64_WSeqPairsClass_with_subo32_in_GPR32commonRegClassID = 13,
  AArch64_WSeqPairsClass_with_sube32_in_GPR32common_and_WSeqPairsClass_with_subo32_in_GPR32commonRegClassID = 14,
  AArch64_GPR64allRegClassID = 15,
  AArch64_FPR64RegClassID = 16,
  AArch64_GPR64RegClassID = 17,
  AArch64_GPR64spRegClassID = 18,
  AArch64_GPR64commonRegClassID = 19,
  AArch64_tcGPR64RegClassID = 20,
  AArch64_GPR64sponlyRegClassID = 21,
  AArch64_DDRegClassID = 22,
  AArch64_XSeqPairsClassRegClassID = 23,
  AArch64_XSeqPairsClass_with_sub_32_in_GPR32commonRegClassID = 24,
  AArch64_XSeqPairsClass_with_subo64_in_GPR64commonRegClassID = 25,
  AArch64_XSeqPairsClass_with_sub_32_in_GPR32common_and_XSeqPairsClass_with_subo64_in_GPR64commonRegClassID = 26,
  AArch64_XSeqPairsClass_with_sube64_in_tcGPR64RegClassID = 27,
  AArch64_XSeqPairsClass_with_subo64_in_tcGPR64RegClassID = 28,
  AArch64_XSeqPairsClass_with_sub_32_in_GPR32common_and_XSeqPairsClass_with_subo64_in_tcGPR64RegClassID = 29,
  AArch64_FPR128RegClassID = 30,
  AArch64_ZPRRegClassID = 31,
  AArch64_FPR128_loRegClassID = 32,
  AArch64_ZPR_4bRegClassID = 33,
  AArch64_ZPR_3bRegClassID = 34,
  AArch64_DDDRegClassID = 35,
  AArch64_DDDDRegClassID = 36,
  AArch64_QQRegClassID = 37,
  AArch64_ZPR2RegClassID = 38,
  AArch64_QQ_with_qsub0_in_FPR128_loRegClassID = 39,
  AArch64_QQ_with_qsub1_in_FPR128_loRegClassID = 40,
  AArch64_ZPR2_with_zsub1_in_ZPR_4bRegClassID = 41,
  AArch64_ZPR2_with_zsub_in_FPR128_loRegClassID = 42,
  AArch64_QQ_with_qsub0_in_FPR128_lo_and_QQ_with_qsub1_in_FPR128_loRegClassID = 43,
  AArch64_ZPR2_with_zsub_in_FPR128_lo_and_ZPR2_with_zsub1_in_ZPR_4bRegClassID = 44,
  AArch64_ZPR2_with_zsub0_in_ZPR_3bRegClassID = 45,
  AArch64_ZPR2_with_zsub1_in_ZPR_3bRegClassID = 46,
  AArch64_ZPR2_with_zsub_in_FPR128_lo_and_ZPR2_with_zsub1_in_ZPR_3bRegClassID = 47,
  AArch64_QQQRegClassID = 48,
  AArch64_ZPR3RegClassID = 49,
  AArch64_QQQ_with_qsub0_in_FPR128_loRegClassID = 50,
  AArch64_QQQ_with_qsub1_in_FPR128_loRegClassID = 51,
  AArch64_QQQ_with_qsub2_in_FPR128_loRegClassID = 52,
  AArch64_ZPR3_with_zsub1_in_ZPR_4bRegClassID = 53,
  AArch64_ZPR3_with_zsub2_in_ZPR_4bRegClassID = 54,
  AArch64_ZPR3_with_zsub_in_FPR128_loRegClassID = 55,
  AArch64_QQQ_with_qsub0_in_FPR128_lo_and_QQQ_with_qsub1_in_FPR128_loRegClassID = 56,
  AArch64_QQQ_with_qsub1_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_loRegClassID = 57,
  AArch64_ZPR3_with_zsub1_in_ZPR_4b_and_ZPR3_with_zsub2_in_ZPR_4bRegClassID = 58,
  AArch64_ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub1_in_ZPR_4bRegClassID = 59,
  AArch64_QQQ_with_qsub0_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_loRegClassID = 60,
  AArch64_ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub2_in_ZPR_4bRegClassID = 61,
  AArch64_ZPR3_with_zsub0_in_ZPR_3bRegClassID = 62,
  AArch64_ZPR3_with_zsub1_in_ZPR_3bRegClassID = 63,
  AArch64_ZPR3_with_zsub2_in_ZPR_3bRegClassID = 64,
  AArch64_ZPR3_with_zsub1_in_ZPR_3b_and_ZPR3_with_zsub2_in_ZPR_3bRegClassID = 65,
  AArch64_ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub1_in_ZPR_3bRegClassID = 66,
  AArch64_ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub2_in_ZPR_3bRegClassID = 67,
  AArch64_QQQQRegClassID = 68,
  AArch64_ZPR4RegClassID = 69,
  AArch64_QQQQ_with_qsub0_in_FPR128_loRegClassID = 70,
  AArch64_QQQQ_with_qsub1_in_FPR128_loRegClassID = 71,
  AArch64_QQQQ_with_qsub2_in_FPR128_loRegClassID = 72,
  AArch64_QQQQ_with_qsub3_in_FPR128_loRegClassID = 73,
  AArch64_ZPR4_with_zsub1_in_ZPR_4bRegClassID = 74,
  AArch64_ZPR4_with_zsub2_in_ZPR_4bRegClassID = 75,
  AArch64_ZPR4_with_zsub3_in_ZPR_4bRegClassID = 76,
  AArch64_ZPR4_with_zsub_in_FPR128_loRegClassID = 77,
  AArch64_QQQQ_with_qsub0_in_FPR128_lo_and_QQQQ_with_qsub1_in_FPR128_loRegClassID = 78,
  AArch64_QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_loRegClassID = 79,
  AArch64_QQQQ_with_qsub2_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_loRegClassID = 80,
  AArch64_ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub2_in_ZPR_4bRegClassID = 81,
  AArch64_ZPR4_with_zsub2_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4bRegClassID = 82,
  AArch64_ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub1_in_ZPR_4bRegClassID = 83,
  AArch64_QQQQ_with_qsub0_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_loRegClassID = 84,
  AArch64_QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_loRegClassID = 85,
  AArch64_ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4bRegClassID = 86,
  AArch64_ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub2_in_ZPR_4bRegClassID = 87,
  AArch64_QQQQ_with_qsub0_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_loRegClassID = 88,
  AArch64_ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub3_in_ZPR_4bRegClassID = 89,
  AArch64_ZPR4_with_zsub0_in_ZPR_3bRegClassID = 90,
  AArch64_ZPR4_with_zsub1_in_ZPR_3bRegClassID = 91,
  AArch64_ZPR4_with_zsub2_in_ZPR_3bRegClassID = 92,
  AArch64_ZPR4_with_zsub3_in_ZPR_3bRegClassID = 93,
  AArch64_ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub2_in_ZPR_3bRegClassID = 94,
  AArch64_ZPR4_with_zsub2_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3bRegClassID = 95,
  AArch64_ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub1_in_ZPR_3bRegClassID = 96,
  AArch64_ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3bRegClassID = 97,
  AArch64_ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub2_in_ZPR_3bRegClassID = 98,
  AArch64_ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub3_in_ZPR_3bRegClassID = 99,
};

// Register alternate name indices
enum {
  AArch64_NoRegAltName,	// 0
  AArch64_vlist1,	// 1
  AArch64_vreg,	// 2
  AArch64_NUM_TARGET_REG_ALT_NAMES = 3
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
  AArch64_qhisub,	// 8
  AArch64_qsub,	// 9
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
  AArch64_zsub,	// 20
  AArch64_zsub0,	// 21
  AArch64_zsub1,	// 22
  AArch64_zsub2,	// 23
  AArch64_zsub3,	// 24
  AArch64_zsub_hi,	// 25
  AArch64_dsub1_then_bsub,	// 26
  AArch64_dsub1_then_hsub,	// 27
  AArch64_dsub1_then_ssub,	// 28
  AArch64_dsub3_then_bsub,	// 29
  AArch64_dsub3_then_hsub,	// 30
  AArch64_dsub3_then_ssub,	// 31
  AArch64_dsub2_then_bsub,	// 32
  AArch64_dsub2_then_hsub,	// 33
  AArch64_dsub2_then_ssub,	// 34
  AArch64_qsub1_then_bsub,	// 35
  AArch64_qsub1_then_dsub,	// 36
  AArch64_qsub1_then_hsub,	// 37
  AArch64_qsub1_then_ssub,	// 38
  AArch64_qsub3_then_bsub,	// 39
  AArch64_qsub3_then_dsub,	// 40
  AArch64_qsub3_then_hsub,	// 41
  AArch64_qsub3_then_ssub,	// 42
  AArch64_qsub2_then_bsub,	// 43
  AArch64_qsub2_then_dsub,	// 44
  AArch64_qsub2_then_hsub,	// 45
  AArch64_qsub2_then_ssub,	// 46
  AArch64_subo64_then_sub_32,	// 47
  AArch64_zsub1_then_bsub,	// 48
  AArch64_zsub1_then_dsub,	// 49
  AArch64_zsub1_then_hsub,	// 50
  AArch64_zsub1_then_ssub,	// 51
  AArch64_zsub1_then_zsub,	// 52
  AArch64_zsub1_then_zsub_hi,	// 53
  AArch64_zsub3_then_bsub,	// 54
  AArch64_zsub3_then_dsub,	// 55
  AArch64_zsub3_then_hsub,	// 56
  AArch64_zsub3_then_ssub,	// 57
  AArch64_zsub3_then_zsub,	// 58
  AArch64_zsub3_then_zsub_hi,	// 59
  AArch64_zsub2_then_bsub,	// 60
  AArch64_zsub2_then_dsub,	// 61
  AArch64_zsub2_then_hsub,	// 62
  AArch64_zsub2_then_ssub,	// 63
  AArch64_zsub2_then_zsub,	// 64
  AArch64_zsub2_then_zsub_hi,	// 65
  AArch64_dsub0_dsub1,	// 66
  AArch64_dsub0_dsub1_dsub2,	// 67
  AArch64_dsub1_dsub2,	// 68
  AArch64_dsub1_dsub2_dsub3,	// 69
  AArch64_dsub2_dsub3,	// 70
  AArch64_dsub_qsub1_then_dsub,	// 71
  AArch64_dsub_qsub1_then_dsub_qsub2_then_dsub_qsub3_then_dsub,	// 72
  AArch64_dsub_qsub1_then_dsub_qsub2_then_dsub,	// 73
  AArch64_qsub0_qsub1,	// 74
  AArch64_qsub0_qsub1_qsub2,	// 75
  AArch64_qsub1_qsub2,	// 76
  AArch64_qsub1_qsub2_qsub3,	// 77
  AArch64_qsub2_qsub3,	// 78
  AArch64_qsub1_then_dsub_qsub2_then_dsub,	// 79
  AArch64_qsub1_then_dsub_qsub2_then_dsub_qsub3_then_dsub,	// 80
  AArch64_qsub2_then_dsub_qsub3_then_dsub,	// 81
  AArch64_sub_32_subo64_then_sub_32,	// 82
  AArch64_dsub_zsub1_then_dsub,	// 83
  AArch64_zsub_zsub1_then_zsub,	// 84
  AArch64_dsub_zsub1_then_dsub_zsub2_then_dsub_zsub3_then_dsub,	// 85
  AArch64_dsub_zsub1_then_dsub_zsub2_then_dsub,	// 86
  AArch64_zsub_zsub1_then_zsub_zsub2_then_zsub_zsub3_then_zsub,	// 87
  AArch64_zsub_zsub1_then_zsub_zsub2_then_zsub,	// 88
  AArch64_zsub0_zsub1,	// 89
  AArch64_zsub0_zsub1_zsub2,	// 90
  AArch64_zsub1_zsub2,	// 91
  AArch64_zsub1_zsub2_zsub3,	// 92
  AArch64_zsub2_zsub3,	// 93
  AArch64_zsub1_then_dsub_zsub2_then_dsub,	// 94
  AArch64_zsub1_then_dsub_zsub2_then_dsub_zsub3_then_dsub,	// 95
  AArch64_zsub1_then_zsub_zsub2_then_zsub,	// 96
  AArch64_zsub1_then_zsub_zsub2_then_zsub_zsub3_then_zsub,	// 97
  AArch64_zsub2_then_dsub_zsub3_then_dsub,	// 98
  AArch64_zsub2_then_zsub_zsub3_then_zsub,	// 99
  AArch64_NUM_TARGET_SUBREGS
};

#endif // GET_REGINFO_ENUM

#ifdef GET_REGINFO_MC_DESC
#undef GET_REGINFO_MC_DESC


static const MCPhysReg AArch64RegDiffLists[] = {
  /* 0 */ 64945, 1, 1, 1, 74, 1, 1, 1, 0,
  /* 9 */ 65105, 1, 1, 1, 0,
  /* 14 */ 65201, 1, 1, 1, 0,
  /* 19 */ 6, 29, 1, 1, 0,
  /* 24 */ 6, 29, 1, 1, 46, 29, 1, 1, 0,
  /* 33 */ 65324, 499, 30, 1, 1, 0,
  /* 39 */ 64913, 1, 1, 75, 1, 1, 0,
  /* 46 */ 65073, 1, 1, 0,
  /* 50 */ 65169, 1, 1, 0,
  /* 54 */ 6, 1, 29, 1, 0,
  /* 59 */ 6, 1, 29, 1, 46, 1, 29, 1, 0,
  /* 68 */ 6, 30, 1, 0,
  /* 72 */ 6, 30, 1, 46, 30, 1, 0,
  /* 79 */ 1, 493, 1, 32, 1, 0,
  /* 85 */ 31, 286, 1, 33, 1, 0,
  /* 91 */ 64977, 1, 76, 1, 0,
  /* 96 */ 65204, 112, 65456, 65472, 33, 112, 65456, 65472, 33, 112, 65456, 65472, 298, 1, 0,
  /* 111 */ 320, 1, 0,
  /* 114 */ 65204, 112, 65456, 65472, 33, 112, 65456, 65472, 1, 112, 65456, 65472, 330, 1, 0,
  /* 129 */ 526, 1, 0,
  /* 132 */ 530, 1, 0,
  /* 135 */ 65053, 1, 0,
  /* 138 */ 65087, 1, 0,
  /* 141 */ 65137, 1, 0,
  /* 144 */ 65218, 1, 0,
  /* 147 */ 65233, 1, 0,
  /* 150 */ 64, 80, 65424, 80, 124, 63, 1, 62, 65503, 34, 65503, 34, 65503, 1, 63, 1, 62, 65503, 34, 65503, 34, 65503, 1, 127, 1, 62, 65503, 34, 65503, 34, 65503, 1, 0,
  /* 183 */ 124, 159, 1, 62, 65503, 34, 65503, 34, 65503, 1, 127, 1, 62, 65503, 34, 65503, 34, 65503, 1, 0,
  /* 203 */ 65504, 319, 1, 62, 65503, 34, 65503, 34, 65503, 1, 0,
  /* 214 */ 64, 80, 65424, 80, 124, 64, 31, 33, 65504, 62, 65503, 34, 65503, 1, 33, 31, 33, 65504, 62, 65503, 34, 65503, 1, 97, 31, 33, 65504, 62, 65503, 34, 65503, 1, 0,
  /* 247 */ 124, 160, 31, 33, 65504, 62, 65503, 34, 65503, 1, 97, 31, 33, 65504, 62, 65503, 34, 65503, 1, 0,
  /* 267 */ 65504, 320, 31, 33, 65504, 62, 65503, 34, 65503, 1, 0,
  /* 278 */ 63, 65503, 34, 65503, 1, 64, 63, 65503, 34, 65503, 1, 128, 63, 65503, 34, 65503, 1, 0,
  /* 296 */ 64, 80, 65424, 80, 124, 63, 1, 63, 1, 65503, 1, 62, 65503, 1, 33, 1, 63, 1, 65503, 1, 62, 65503, 1, 97, 1, 63, 1, 65503, 1, 62, 65503, 1, 0,
  /* 329 */ 124, 159, 1, 63, 1, 65503, 1, 62, 65503, 1, 97, 1, 63, 1, 65503, 1, 62, 65503, 1, 0,
  /* 349 */ 65504, 319, 1, 63, 1, 65503, 1, 62, 65503, 1, 0,
  /* 360 */ 64, 65504, 63, 65503, 1, 33, 64, 65504, 63, 65503, 1, 97, 64, 65504, 63, 65503, 1, 0,
  /* 378 */ 65503, 1, 128, 65503, 1, 192, 65503, 1, 0,
  /* 387 */ 31, 285, 2, 32, 2, 0,
  /* 393 */ 319, 2, 0,
  /* 396 */ 65324, 529, 1, 1, 3, 0,
  /* 402 */ 2, 3, 0,
  /* 405 */ 531, 3, 0,
  /* 408 */ 65004, 3, 0,
  /* 411 */ 4, 0,
  /* 413 */ 5, 0,
  /* 415 */ 31, 286, 1, 5, 28, 0,
  /* 421 */ 292, 28, 0,
  /* 424 */ 6, 1, 1, 29, 0,
  /* 429 */ 6, 1, 1, 29, 46, 1, 1, 29, 0,
  /* 438 */ 64, 80, 65424, 80, 124, 63, 1, 62, 1, 65503, 34, 65503, 1, 29, 34, 1, 62, 1, 65503, 34, 65503, 1, 29, 98, 1, 62, 1, 65503, 34, 65503, 1, 29, 0,
  /* 471 */ 124, 159, 1, 62, 1, 65503, 34, 65503, 1, 29, 98, 1, 62, 1, 65503, 34, 65503, 1, 29, 0,
  /* 491 */ 65504, 319, 1, 62, 1, 65503, 34, 65503, 1, 29, 0,
  /* 502 */ 6, 1, 30, 0,
  /* 506 */ 6, 1, 30, 46, 1, 30, 0,
  /* 513 */ 63, 1, 65503, 1, 30, 34, 63, 1, 65503, 1, 30, 98, 63, 1, 65503, 1, 30, 0,
  /* 531 */ 6, 31, 0,
  /* 534 */ 6, 31, 46, 31, 0,
  /* 539 */ 65504, 31, 97, 65504, 31, 161, 65504, 31, 0,
  /* 548 */ 32, 0,
  /* 550 */ 34, 0,
  /* 552 */ 5, 49, 0,
  /* 555 */ 63936, 49, 0,
  /* 558 */ 65297, 77, 0,
  /* 561 */ 1, 81, 0,
  /* 564 */ 65216, 65412, 65456, 112, 65456, 65472, 268, 65505, 65412, 65456, 112, 65456, 65472, 268, 31, 96, 0,
  /* 581 */ 65216, 65412, 65456, 112, 65456, 65472, 268, 65473, 65412, 65456, 112, 65456, 65472, 268, 63, 96, 0,
  /* 598 */ 65152, 65412, 65456, 112, 65456, 65472, 268, 65505, 65412, 65456, 112, 65456, 65472, 268, 65505, 65412, 65456, 112, 65456, 65472, 268, 30, 96, 65504, 96, 96, 1, 65280, 96, 0,
  /* 628 */ 65152, 65412, 65456, 112, 65456, 65472, 268, 65505, 65412, 65456, 112, 65456, 65472, 268, 65473, 65412, 65456, 112, 65456, 65472, 268, 62, 96, 65504, 96, 96, 1, 65280, 96, 0,
  /* 658 */ 65152, 65412, 65456, 112, 65456, 65472, 268, 65473, 65412, 65456, 112, 65456, 65472, 268, 65505, 65412, 65456, 112, 65456, 65472, 268, 62, 96, 65504, 96, 96, 65505, 65280, 96, 0,
  /* 688 */ 65184, 65412, 65456, 112, 65456, 65472, 268, 65505, 65412, 65456, 112, 65456, 65472, 268, 65473, 65412, 65456, 112, 65456, 65472, 268, 65505, 65412, 65456, 112, 65456, 65472, 268, 61, 96, 65472, 32, 64, 32, 96, 64, 65473, 64, 65441, 65311, 64, 32, 64, 65345, 96, 0,
  /* 734 */ 65184, 65412, 65456, 112, 65456, 65472, 268, 65473, 65412, 65456, 112, 65456, 65472, 268, 65505, 65412, 65456, 112, 65456, 65472, 268, 65505, 65412, 65456, 112, 65456, 65472, 268, 61, 96, 65472, 32, 64, 32, 96, 64, 65441, 64, 65473, 65279, 64, 32, 64, 65377, 96, 0,
  /* 780 */ 65184, 65412, 65456, 112, 65456, 65472, 268, 65505, 65412, 65456, 112, 65456, 65472, 268, 65505, 65412, 65456, 112, 65456, 65472, 268, 65505, 65412, 65456, 112, 65456, 65472, 268, 29, 96, 65472, 32, 64, 32, 96, 64, 65473, 64, 65473, 65279, 64, 32, 64, 65377, 96, 0,
  /* 826 */ 65184, 65412, 65456, 112, 65456, 65472, 268, 65505, 65412, 65456, 112, 65456, 65472, 268, 65505, 65412, 65456, 112, 65456, 65472, 268, 65473, 65412, 65456, 112, 65456, 65472, 268, 61, 96, 65472, 32, 64, 32, 96, 64, 65473, 64, 65473, 65279, 64, 32, 64, 65377, 96, 0,
  /* 872 */ 96, 160, 0,
  /* 875 */ 65042, 178, 0,
  /* 878 */ 212, 0,
  /* 880 */ 65412, 65456, 112, 65456, 65472, 268, 0,
  /* 887 */ 65252, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 299, 0,
  /* 899 */ 65009, 65535, 209, 65505, 316, 0,
  /* 905 */ 65005, 212, 65325, 212, 317, 0,
  /* 911 */ 65244, 65505, 65325, 212, 317, 0,
  /* 917 */ 65215, 65505, 32, 65505, 317, 0,
  /* 923 */ 65252, 65456, 112, 65456, 65472, 81, 65456, 112, 65456, 65472, 331, 0,
  /* 935 */ 65005, 212, 65329, 65535, 495, 0,
  /* 941 */ 65323, 0,
  /* 943 */ 65249, 65328, 0,
  /* 946 */ 65342, 0,
  /* 948 */ 65374, 0,
  /* 950 */ 65389, 0,
  /* 952 */ 65405, 0,
  /* 954 */ 65421, 0,
  /* 956 */ 65188, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 298, 64, 32, 1, 65440, 0,
  /* 977 */ 65188, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 81, 65456, 112, 65456, 65472, 330, 64, 32, 1, 65440, 0,
  /* 998 */ 65188, 65456, 112, 65456, 65472, 81, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 330, 64, 32, 65505, 65440, 0,
  /* 1019 */ 65220, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 81, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 329, 32, 32, 32, 64, 65473, 64, 65441, 65471, 64, 65441, 0,
  /* 1051 */ 65236, 112, 65456, 65472, 33, 112, 65456, 65472, 1, 112, 65456, 65472, 33, 112, 65456, 65472, 329, 64, 65473, 64, 65441, 0,
  /* 1073 */ 65469, 0,
  /* 1075 */ 65268, 112, 65456, 65472, 1, 112, 65456, 65472, 0,
  /* 1084 */ 65268, 112, 65456, 65472, 33, 112, 65456, 65472, 0,
  /* 1093 */ 65456, 112, 65456, 65472, 0,
  /* 1098 */ 65220, 65456, 112, 65456, 65472, 81, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 329, 32, 32, 32, 64, 65441, 64, 65473, 65439, 64, 65473, 0,
  /* 1130 */ 65220, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 297, 32, 32, 32, 64, 65473, 64, 65473, 65439, 64, 65473, 0,
  /* 1162 */ 65220, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 113, 65456, 112, 65456, 65472, 81, 65456, 112, 65456, 65472, 329, 32, 32, 32, 64, 65473, 64, 65473, 65439, 64, 65473, 0,
  /* 1194 */ 65236, 112, 65456, 65472, 1, 112, 65456, 65472, 33, 112, 65456, 65472, 33, 112, 65456, 65472, 329, 64, 65441, 64, 65473, 0,
  /* 1216 */ 65236, 112, 65456, 65472, 33, 112, 65456, 65472, 33, 112, 65456, 65472, 33, 112, 65456, 65472, 297, 64, 65473, 64, 65473, 0,
  /* 1238 */ 65236, 112, 65456, 65472, 33, 112, 65456, 65472, 33, 112, 65456, 65472, 1, 112, 65456, 65472, 329, 64, 65473, 64, 65473, 0,
  /* 1260 */ 65501, 0,
  /* 1262 */ 65204, 112, 65456, 65472, 1, 112, 65456, 65472, 33, 112, 65456, 65472, 330, 65505, 0,
  /* 1277 */ 65533, 0,
  /* 1279 */ 65535, 0,
};

static const uint16_t AArch64SubRegIdxLists[] = {
  /* 0 */ 2, 14, 7, 1, 0,
  /* 5 */ 15, 0,
  /* 7 */ 16, 18, 0,
  /* 10 */ 20, 2, 14, 7, 1, 25, 0,
  /* 17 */ 3, 14, 7, 1, 4, 28, 27, 26, 0,
  /* 26 */ 3, 14, 7, 1, 4, 28, 27, 26, 5, 34, 33, 32, 66, 68, 0,
  /* 41 */ 3, 14, 7, 1, 4, 28, 27, 26, 5, 34, 33, 32, 6, 31, 30, 29, 66, 67, 68, 69, 70, 0,
  /* 63 */ 10, 2, 14, 7, 1, 11, 36, 38, 37, 35, 71, 0,
  /* 75 */ 10, 2, 14, 7, 1, 11, 36, 38, 37, 35, 12, 44, 46, 45, 43, 71, 73, 74, 76, 79, 0,
  /* 96 */ 10, 2, 14, 7, 1, 11, 36, 38, 37, 35, 12, 44, 46, 45, 43, 13, 40, 42, 41, 39, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 0,
  /* 128 */ 17, 15, 19, 47, 82, 0,
  /* 134 */ 21, 20, 2, 14, 7, 1, 25, 22, 52, 49, 51, 50, 48, 53, 83, 84, 0,
  /* 151 */ 21, 20, 2, 14, 7, 1, 25, 22, 52, 49, 51, 50, 48, 53, 23, 64, 61, 63, 62, 60, 65, 83, 84, 86, 88, 89, 91, 94, 96, 0,
  /* 181 */ 21, 20, 2, 14, 7, 1, 25, 22, 52, 49, 51, 50, 48, 53, 23, 64, 61, 63, 62, 60, 65, 24, 58, 55, 57, 56, 54, 59, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 0,
};

static const MCRegisterDesc AArch64RegDesc[] = {
  { 3, 0, 0, 0, 0, 0 },
  { 2489, 8, 8, 4, 20465, 0 },
  { 2482, 878, 405, 5, 20465, 27 },
  { 2496, 878, 132, 5, 20465, 27 },
  { 2514, 8, 8, 4, 20465, 0 },
  { 2486, 7, 8, 5, 6576, 27 },
  { 2485, 8, 1279, 4, 6576, 0 },
  { 2503, 8, 79, 4, 6608, 0 },
  { 2510, 1279, 129, 5, 6608, 27 },
  { 213, 8, 214, 4, 20433, 0 },
  { 494, 8, 296, 4, 20433, 0 },
  { 713, 8, 438, 4, 20433, 0 },
  { 932, 8, 150, 4, 20433, 0 },
  { 1148, 8, 150, 4, 20433, 0 },
  { 1364, 8, 150, 4, 20433, 0 },
  { 1576, 8, 150, 4, 20433, 0 },
  { 1788, 8, 150, 4, 20433, 0 },
  { 2000, 8, 150, 4, 20433, 0 },
  { 2204, 8, 150, 4, 20433, 0 },
  { 0, 8, 150, 4, 20433, 0 },
  { 284, 8, 150, 4, 20433, 0 },
  { 560, 8, 150, 4, 20433, 0 },
  { 776, 8, 150, 4, 20433, 0 },
  { 992, 8, 150, 4, 20433, 0 },
  { 1208, 8, 150, 4, 20433, 0 },
  { 1424, 8, 150, 4, 20433, 0 },
  { 1636, 8, 150, 4, 20433, 0 },
  { 1848, 8, 150, 4, 20433, 0 },
  { 2060, 8, 150, 4, 20433, 0 },
  { 69, 8, 150, 4, 20433, 0 },
  { 358, 8, 150, 4, 20433, 0 },
  { 637, 8, 150, 4, 20433, 0 },
  { 856, 8, 150, 4, 20433, 0 },
  { 1072, 8, 150, 4, 20433, 0 },
  { 1288, 8, 150, 4, 20433, 0 },
  { 1500, 8, 150, 4, 20433, 0 },
  { 1712, 8, 150, 4, 20433, 0 },
  { 1924, 8, 150, 4, 20433, 0 },
  { 2136, 8, 150, 4, 20433, 0 },
  { 145, 8, 150, 4, 20433, 0 },
  { 434, 8, 150, 4, 20433, 0 },
  { 228, 1080, 217, 1, 20161, 3 },
  { 508, 1080, 299, 1, 20161, 3 },
  { 726, 1080, 441, 1, 20161, 3 },
  { 944, 1080, 153, 1, 20161, 3 },
  { 1160, 1080, 153, 1, 20161, 3 },
  { 1376, 1080, 153, 1, 20161, 3 },
  { 1588, 1080, 153, 1, 20161, 3 },
  { 1800, 1080, 153, 1, 20161, 3 },
  { 2012, 1080, 153, 1, 20161, 3 },
  { 2216, 1080, 153, 1, 20161, 3 },
  { 13, 1080, 153, 1, 20161, 3 },
  { 298, 1080, 153, 1, 20161, 3 },
  { 575, 1080, 153, 1, 20161, 3 },
  { 792, 1080, 153, 1, 20161, 3 },
  { 1008, 1080, 153, 1, 20161, 3 },
  { 1224, 1080, 153, 1, 20161, 3 },
  { 1440, 1080, 153, 1, 20161, 3 },
  { 1652, 1080, 153, 1, 20161, 3 },
  { 1864, 1080, 153, 1, 20161, 3 },
  { 2076, 1080, 153, 1, 20161, 3 },
  { 85, 1080, 153, 1, 20161, 3 },
  { 374, 1080, 153, 1, 20161, 3 },
  { 653, 1080, 153, 1, 20161, 3 },
  { 872, 1080, 153, 1, 20161, 3 },
  { 1088, 1080, 153, 1, 20161, 3 },
  { 1304, 1080, 153, 1, 20161, 3 },
  { 1516, 1080, 153, 1, 20161, 3 },
  { 1728, 1080, 153, 1, 20161, 3 },
  { 1940, 1080, 153, 1, 20161, 3 },
  { 2152, 1080, 153, 1, 20161, 3 },
  { 161, 1080, 153, 1, 20161, 3 },
  { 450, 1080, 153, 1, 20161, 3 },
  { 231, 1082, 215, 3, 17169, 3 },
  { 511, 1082, 297, 3, 17169, 3 },
  { 729, 1082, 439, 3, 17169, 3 },
  { 947, 1082, 151, 3, 17169, 3 },
  { 1163, 1082, 151, 3, 17169, 3 },
  { 1379, 1082, 151, 3, 17169, 3 },
  { 1591, 1082, 151, 3, 17169, 3 },
  { 1803, 1082, 151, 3, 17169, 3 },
  { 2015, 1082, 151, 3, 17169, 3 },
  { 2219, 1082, 151, 3, 17169, 3 },
  { 17, 1082, 151, 3, 17169, 3 },
  { 302, 1082, 151, 3, 17169, 3 },
  { 579, 1082, 151, 3, 17169, 3 },
  { 796, 1082, 151, 3, 17169, 3 },
  { 1012, 1082, 151, 3, 17169, 3 },
  { 1228, 1082, 151, 3, 17169, 3 },
  { 1444, 1082, 151, 3, 17169, 3 },
  { 1656, 1082, 151, 3, 17169, 3 },
  { 1868, 1082, 151, 3, 17169, 3 },
  { 2080, 1082, 151, 3, 17169, 3 },
  { 89, 1082, 151, 3, 17169, 3 },
  { 378, 1082, 151, 3, 17169, 3 },
  { 657, 1082, 151, 3, 17169, 3 },
  { 876, 1082, 151, 3, 17169, 3 },
  { 1092, 1082, 151, 3, 17169, 3 },
  { 1308, 1082, 151, 3, 17169, 3 },
  { 1520, 1082, 151, 3, 17169, 3 },
  { 1732, 1082, 151, 3, 17169, 3 },
  { 1944, 1082, 151, 3, 17169, 3 },
  { 2156, 1082, 151, 3, 17169, 3 },
  { 165, 1082, 151, 3, 17169, 3 },
  { 454, 1082, 151, 3, 17169, 3 },
  { 234, 8, 8, 4, 17169, 0 },
  { 514, 8, 8, 4, 17169, 0 },
  { 732, 8, 8, 4, 17169, 0 },
  { 950, 8, 8, 4, 17169, 0 },
  { 1166, 8, 8, 4, 17169, 0 },
  { 1382, 8, 8, 4, 17169, 0 },
  { 1594, 8, 8, 4, 17169, 0 },
  { 1806, 8, 8, 4, 17169, 0 },
  { 2018, 8, 8, 4, 17169, 0 },
  { 2222, 8, 8, 4, 17169, 0 },
  { 21, 8, 8, 4, 17169, 0 },
  { 306, 8, 8, 4, 17169, 0 },
  { 583, 8, 8, 4, 17169, 0 },
  { 800, 8, 8, 4, 17169, 0 },
  { 1016, 8, 8, 4, 17169, 0 },
  { 1232, 8, 8, 4, 17169, 0 },
  { 249, 1093, 247, 0, 15265, 3 },
  { 528, 1093, 329, 0, 15265, 3 },
  { 745, 1093, 471, 0, 15265, 3 },
  { 962, 1093, 183, 0, 15265, 3 },
  { 1178, 1093, 183, 0, 15265, 3 },
  { 1394, 1093, 183, 0, 15265, 3 },
  { 1606, 1093, 183, 0, 15265, 3 },
  { 1818, 1093, 183, 0, 15265, 3 },
  { 2030, 1093, 183, 0, 15265, 3 },
  { 2234, 1093, 183, 0, 15265, 3 },
  { 34, 1093, 183, 0, 15265, 3 },
  { 320, 1093, 183, 0, 15265, 3 },
  { 598, 1093, 183, 0, 15265, 3 },
  { 816, 1093, 183, 0, 15265, 3 },
  { 1032, 1093, 183, 0, 15265, 3 },
  { 1248, 1093, 183, 0, 15265, 3 },
  { 1460, 1093, 183, 0, 15265, 3 },
  { 1672, 1093, 183, 0, 15265, 3 },
  { 1884, 1093, 183, 0, 15265, 3 },
  { 2096, 1093, 183, 0, 15265, 3 },
  { 105, 1093, 183, 0, 15265, 3 },
  { 394, 1093, 183, 0, 15265, 3 },
  { 673, 1093, 183, 0, 15265, 3 },
  { 892, 1093, 183, 0, 15265, 3 },
  { 1108, 1093, 183, 0, 15265, 3 },
  { 1324, 1093, 183, 0, 15265, 3 },
  { 1536, 1093, 183, 0, 15265, 3 },
  { 1748, 1093, 183, 0, 15265, 3 },
  { 1960, 1093, 183, 0, 15265, 3 },
  { 2172, 1093, 183, 0, 15265, 3 },
  { 181, 1093, 183, 0, 15265, 3 },
  { 470, 1093, 183, 0, 15265, 3 },
  { 252, 1081, 216, 2, 15201, 3 },
  { 531, 1081, 298, 2, 15201, 3 },
  { 748, 1081, 440, 2, 15201, 3 },
  { 965, 1081, 152, 2, 15201, 3 },
  { 1181, 1081, 152, 2, 15201, 3 },
  { 1397, 1081, 152, 2, 15201, 3 },
  { 1609, 1081, 152, 2, 15201, 3 },
  { 1821, 1081, 152, 2, 15201, 3 },
  { 2033, 1081, 152, 2, 15201, 3 },
  { 2237, 1081, 152, 2, 15201, 3 },
  { 38, 1081, 152, 2, 15201, 3 },
  { 324, 1081, 152, 2, 15201, 3 },
  { 602, 1081, 152, 2, 15201, 3 },
  { 820, 1081, 152, 2, 15201, 3 },
  { 1036, 1081, 152, 2, 15201, 3 },
  { 1252, 1081, 152, 2, 15201, 3 },
  { 1464, 1081, 152, 2, 15201, 3 },
  { 1676, 1081, 152, 2, 15201, 3 },
  { 1888, 1081, 152, 2, 15201, 3 },
  { 2100, 1081, 152, 2, 15201, 3 },
  { 109, 1081, 152, 2, 15201, 3 },
  { 398, 1081, 152, 2, 15201, 3 },
  { 677, 1081, 152, 2, 15201, 3 },
  { 896, 1081, 152, 2, 15201, 3 },
  { 1112, 1081, 152, 2, 15201, 3 },
  { 1328, 1081, 152, 2, 15201, 3 },
  { 1540, 1081, 152, 2, 15201, 3 },
  { 1752, 1081, 152, 2, 15201, 3 },
  { 1964, 1081, 152, 2, 15201, 3 },
  { 2176, 1081, 152, 2, 15201, 3 },
  { 185, 1081, 152, 2, 15201, 3 },
  { 474, 1081, 152, 2, 15201, 3 },
  { 259, 8, 387, 4, 15233, 0 },
  { 537, 8, 85, 4, 15233, 0 },
  { 754, 8, 85, 4, 15233, 0 },
  { 971, 8, 85, 4, 15233, 0 },
  { 1187, 8, 85, 4, 15233, 0 },
  { 1403, 8, 85, 4, 15233, 0 },
  { 1615, 8, 85, 4, 15233, 0 },
  { 1827, 8, 85, 4, 15233, 0 },
  { 2039, 8, 85, 4, 15233, 0 },
  { 2243, 8, 85, 4, 15233, 0 },
  { 45, 8, 85, 4, 15233, 0 },
  { 332, 8, 85, 4, 15233, 0 },
  { 610, 8, 85, 4, 15233, 0 },
  { 828, 8, 85, 4, 15233, 0 },
  { 1044, 8, 85, 4, 15233, 0 },
  { 1260, 8, 85, 4, 15233, 0 },
  { 1472, 8, 85, 4, 15233, 0 },
  { 1684, 8, 85, 4, 15233, 0 },
  { 1896, 8, 85, 4, 15233, 0 },
  { 2108, 8, 85, 4, 15233, 0 },
  { 117, 8, 85, 4, 15233, 0 },
  { 406, 8, 85, 4, 15233, 0 },
  { 685, 8, 85, 4, 15233, 0 },
  { 904, 8, 85, 4, 15233, 0 },
  { 1120, 8, 85, 4, 15233, 0 },
  { 1336, 8, 85, 4, 15233, 0 },
  { 1548, 8, 85, 4, 15233, 0 },
  { 1760, 8, 85, 4, 15233, 0 },
  { 1972, 8, 415, 4, 15233, 0 },
  { 2184, 8, 396, 4, 15057, 0 },
  { 193, 8, 33, 4, 15057, 0 },
  { 266, 1275, 393, 5, 15169, 27 },
  { 543, 1275, 111, 5, 15169, 27 },
  { 760, 1275, 111, 5, 15169, 27 },
  { 977, 1275, 111, 5, 15169, 27 },
  { 1193, 1275, 111, 5, 15169, 27 },
  { 1409, 1275, 111, 5, 15169, 27 },
  { 1621, 1275, 111, 5, 15169, 27 },
  { 1833, 1275, 111, 5, 15169, 27 },
  { 2045, 1275, 111, 5, 15169, 27 },
  { 2249, 1275, 111, 5, 15169, 27 },
  { 52, 1275, 111, 5, 15169, 27 },
  { 340, 1275, 111, 5, 15169, 27 },
  { 618, 1275, 111, 5, 15169, 27 },
  { 836, 1275, 111, 5, 15169, 27 },
  { 1052, 1275, 111, 5, 15169, 27 },
  { 1268, 1275, 111, 5, 15169, 27 },
  { 1480, 1275, 111, 5, 15169, 27 },
  { 1692, 1275, 111, 5, 15169, 27 },
  { 1904, 1275, 111, 5, 15169, 27 },
  { 2116, 1275, 111, 5, 15169, 27 },
  { 125, 1275, 111, 5, 15169, 27 },
  { 414, 1275, 111, 5, 15169, 27 },
  { 693, 1275, 111, 5, 15169, 27 },
  { 912, 1275, 111, 5, 15169, 27 },
  { 1128, 1275, 111, 5, 15169, 27 },
  { 1344, 1275, 111, 5, 15169, 27 },
  { 1556, 1275, 111, 5, 15169, 27 },
  { 1768, 1275, 111, 5, 15169, 27 },
  { 1980, 1275, 421, 5, 15169, 27 },
  { 281, 880, 268, 10, 8929, 35 },
  { 557, 880, 350, 10, 8929, 35 },
  { 773, 880, 492, 10, 8929, 35 },
  { 989, 880, 204, 10, 8929, 35 },
  { 1205, 880, 204, 10, 8929, 35 },
  { 1421, 880, 204, 10, 8929, 35 },
  { 1633, 880, 204, 10, 8929, 35 },
  { 1845, 880, 204, 10, 8929, 35 },
  { 2057, 880, 204, 10, 8929, 35 },
  { 2261, 880, 204, 10, 8929, 35 },
  { 65, 880, 204, 10, 8929, 35 },
  { 354, 880, 204, 10, 8929, 35 },
  { 633, 880, 204, 10, 8929, 35 },
  { 852, 880, 204, 10, 8929, 35 },
  { 1068, 880, 204, 10, 8929, 35 },
  { 1284, 880, 204, 10, 8929, 35 },
  { 1496, 880, 204, 10, 8929, 35 },
  { 1708, 880, 204, 10, 8929, 35 },
  { 1920, 880, 204, 10, 8929, 35 },
  { 2132, 880, 204, 10, 8929, 35 },
  { 141, 880, 204, 10, 8929, 35 },
  { 430, 880, 204, 10, 8929, 35 },
  { 709, 880, 204, 10, 8929, 35 },
  { 928, 880, 204, 10, 8929, 35 },
  { 1144, 880, 204, 10, 8929, 35 },
  { 1360, 880, 204, 10, 8929, 35 },
  { 1572, 880, 204, 10, 8929, 35 },
  { 1784, 880, 204, 10, 8929, 35 },
  { 1996, 880, 204, 10, 8929, 35 },
  { 2200, 880, 204, 10, 8929, 35 },
  { 209, 880, 204, 10, 8929, 35 },
  { 490, 880, 204, 10, 8929, 35 },
  { 2285, 8, 267, 4, 15137, 0 },
  { 2312, 8, 349, 4, 15137, 0 },
  { 2332, 8, 491, 4, 15137, 0 },
  { 2352, 8, 203, 4, 15137, 0 },
  { 2372, 8, 203, 4, 15137, 0 },
  { 2392, 8, 203, 4, 15137, 0 },
  { 2412, 8, 203, 4, 15137, 0 },
  { 2432, 8, 203, 4, 15137, 0 },
  { 2452, 8, 203, 4, 15137, 0 },
  { 2472, 8, 203, 4, 15137, 0 },
  { 2264, 8, 203, 4, 15137, 0 },
  { 2291, 8, 203, 4, 15137, 0 },
  { 2318, 8, 203, 4, 15137, 0 },
  { 2338, 8, 203, 4, 15137, 0 },
  { 2358, 8, 203, 4, 15137, 0 },
  { 2378, 8, 203, 4, 15137, 0 },
  { 2398, 8, 203, 4, 15137, 0 },
  { 2418, 8, 203, 4, 15137, 0 },
  { 2438, 8, 203, 4, 15137, 0 },
  { 2458, 8, 203, 4, 15137, 0 },
  { 2271, 8, 203, 4, 15137, 0 },
  { 2298, 8, 203, 4, 15137, 0 },
  { 2325, 8, 203, 4, 15137, 0 },
  { 2345, 8, 203, 4, 15137, 0 },
  { 2365, 8, 203, 4, 15137, 0 },
  { 2385, 8, 203, 4, 15137, 0 },
  { 2405, 8, 203, 4, 15137, 0 },
  { 2425, 8, 203, 4, 15137, 0 },
  { 2445, 8, 203, 4, 15137, 0 },
  { 2465, 8, 203, 4, 15137, 0 },
  { 2278, 8, 203, 4, 15137, 0 },
  { 2305, 8, 203, 4, 15137, 0 },
  { 505, 1084, 360, 17, 2353, 61 },
  { 723, 1084, 513, 17, 2353, 61 },
  { 941, 1084, 278, 17, 2353, 61 },
  { 1157, 1084, 278, 17, 2353, 61 },
  { 1373, 1084, 278, 17, 2353, 61 },
  { 1585, 1084, 278, 17, 2353, 61 },
  { 1797, 1084, 278, 17, 2353, 61 },
  { 2009, 1084, 278, 17, 2353, 61 },
  { 2213, 1084, 278, 17, 2353, 61 },
  { 10, 1084, 278, 17, 2353, 61 },
  { 294, 1084, 278, 17, 2353, 61 },
  { 571, 1084, 278, 17, 2353, 61 },
  { 788, 1084, 278, 17, 2353, 61 },
  { 1004, 1084, 278, 17, 2353, 61 },
  { 1220, 1084, 278, 17, 2353, 61 },
  { 1436, 1084, 278, 17, 2353, 61 },
  { 1648, 1084, 278, 17, 2353, 61 },
  { 1860, 1084, 278, 17, 2353, 61 },
  { 2072, 1084, 278, 17, 2353, 61 },
  { 81, 1084, 278, 17, 2353, 61 },
  { 370, 1084, 278, 17, 2353, 61 },
  { 649, 1084, 278, 17, 2353, 61 },
  { 868, 1084, 278, 17, 2353, 61 },
  { 1084, 1084, 278, 17, 2353, 61 },
  { 1300, 1084, 278, 17, 2353, 61 },
  { 1512, 1084, 278, 17, 2353, 61 },
  { 1724, 1084, 278, 17, 2353, 61 },
  { 1936, 1084, 278, 17, 2353, 61 },
  { 2148, 1084, 278, 17, 2353, 61 },
  { 157, 1084, 278, 17, 2353, 61 },
  { 446, 1084, 278, 17, 2353, 61 },
  { 224, 1075, 278, 17, 8496, 2 },
  { 935, 1216, 872, 41, 225, 68 },
  { 1151, 1216, 872, 41, 225, 68 },
  { 1367, 1216, 872, 41, 225, 68 },
  { 1579, 1216, 872, 41, 225, 68 },
  { 1791, 1216, 872, 41, 225, 68 },
  { 2003, 1216, 872, 41, 225, 68 },
  { 2207, 1216, 872, 41, 225, 68 },
  { 4, 1216, 872, 41, 225, 68 },
  { 288, 1216, 872, 41, 225, 68 },
  { 564, 1216, 872, 41, 225, 68 },
  { 780, 1216, 872, 41, 225, 68 },
  { 996, 1216, 872, 41, 225, 68 },
  { 1212, 1216, 872, 41, 225, 68 },
  { 1428, 1216, 872, 41, 225, 68 },
  { 1640, 1216, 872, 41, 225, 68 },
  { 1852, 1216, 872, 41, 225, 68 },
  { 2064, 1216, 872, 41, 225, 68 },
  { 73, 1216, 872, 41, 225, 68 },
  { 362, 1216, 872, 41, 225, 68 },
  { 641, 1216, 872, 41, 225, 68 },
  { 860, 1216, 872, 41, 225, 68 },
  { 1076, 1216, 872, 41, 225, 68 },
  { 1292, 1216, 872, 41, 225, 68 },
  { 1504, 1216, 872, 41, 225, 68 },
  { 1716, 1216, 872, 41, 225, 68 },
  { 1928, 1216, 872, 41, 225, 68 },
  { 2140, 1216, 872, 41, 225, 68 },
  { 149, 1216, 872, 41, 225, 68 },
  { 438, 1216, 872, 41, 225, 68 },
  { 216, 1238, 872, 41, 304, 73 },
  { 497, 1051, 872, 41, 864, 59 },
  { 716, 1194, 872, 41, 6784, 5 },
  { 720, 96, 539, 26, 801, 74 },
  { 938, 96, 378, 26, 801, 74 },
  { 1154, 96, 378, 26, 801, 74 },
  { 1370, 96, 378, 26, 801, 74 },
  { 1582, 96, 378, 26, 801, 74 },
  { 1794, 96, 378, 26, 801, 74 },
  { 2006, 96, 378, 26, 801, 74 },
  { 2210, 96, 378, 26, 801, 74 },
  { 7, 96, 378, 26, 801, 74 },
  { 291, 96, 378, 26, 801, 74 },
  { 567, 96, 378, 26, 801, 74 },
  { 784, 96, 378, 26, 801, 74 },
  { 1000, 96, 378, 26, 801, 74 },
  { 1216, 96, 378, 26, 801, 74 },
  { 1432, 96, 378, 26, 801, 74 },
  { 1644, 96, 378, 26, 801, 74 },
  { 1856, 96, 378, 26, 801, 74 },
  { 2068, 96, 378, 26, 801, 74 },
  { 77, 96, 378, 26, 801, 74 },
  { 366, 96, 378, 26, 801, 74 },
  { 645, 96, 378, 26, 801, 74 },
  { 864, 96, 378, 26, 801, 74 },
  { 1080, 96, 378, 26, 801, 74 },
  { 1296, 96, 378, 26, 801, 74 },
  { 1508, 96, 378, 26, 801, 74 },
  { 1720, 96, 378, 26, 801, 74 },
  { 1932, 96, 378, 26, 801, 74 },
  { 2144, 96, 378, 26, 801, 74 },
  { 153, 96, 378, 26, 801, 74 },
  { 442, 96, 378, 26, 801, 74 },
  { 220, 114, 378, 26, 1088, 64 },
  { 501, 1262, 378, 26, 8032, 10 },
  { 525, 887, 366, 63, 2257, 80 },
  { 742, 887, 519, 63, 2257, 80 },
  { 959, 887, 284, 63, 2257, 80 },
  { 1175, 887, 284, 63, 2257, 80 },
  { 1391, 887, 284, 63, 2257, 80 },
  { 1603, 887, 284, 63, 2257, 80 },
  { 1815, 887, 284, 63, 2257, 80 },
  { 2027, 887, 284, 63, 2257, 80 },
  { 2231, 887, 284, 63, 2257, 80 },
  { 31, 887, 284, 63, 2257, 80 },
  { 316, 887, 284, 63, 2257, 80 },
  { 594, 887, 284, 63, 2257, 80 },
  { 812, 887, 284, 63, 2257, 80 },
  { 1028, 887, 284, 63, 2257, 80 },
  { 1244, 887, 284, 63, 2257, 80 },
  { 1456, 887, 284, 63, 2257, 80 },
  { 1668, 887, 284, 63, 2257, 80 },
  { 1880, 887, 284, 63, 2257, 80 },
  { 2092, 887, 284, 63, 2257, 80 },
  { 101, 887, 284, 63, 2257, 80 },
  { 390, 887, 284, 63, 2257, 80 },
  { 669, 887, 284, 63, 2257, 80 },
  { 888, 887, 284, 63, 2257, 80 },
  { 1104, 887, 284, 63, 2257, 80 },
  { 1320, 887, 284, 63, 2257, 80 },
  { 1532, 887, 284, 63, 2257, 80 },
  { 1744, 887, 284, 63, 2257, 80 },
  { 1956, 887, 284, 63, 2257, 80 },
  { 2168, 887, 284, 63, 2257, 80 },
  { 177, 887, 284, 63, 2257, 80 },
  { 466, 887, 284, 63, 2257, 80 },
  { 245, 923, 284, 63, 8496, 14 },
  { 953, 1130, 873, 96, 145, 87 },
  { 1169, 1130, 873, 96, 145, 87 },
  { 1385, 1130, 873, 96, 145, 87 },
  { 1597, 1130, 873, 96, 145, 87 },
  { 1809, 1130, 873, 96, 145, 87 },
  { 2021, 1130, 873, 96, 145, 87 },
  { 2225, 1130, 873, 96, 145, 87 },
  { 25, 1130, 873, 96, 145, 87 },
  { 310, 1130, 873, 96, 145, 87 },
  { 587, 1130, 873, 96, 145, 87 },
  { 804, 1130, 873, 96, 145, 87 },
  { 1020, 1130, 873, 96, 145, 87 },
  { 1236, 1130, 873, 96, 145, 87 },
  { 1448, 1130, 873, 96, 145, 87 },
  { 1660, 1130, 873, 96, 145, 87 },
  { 1872, 1130, 873, 96, 145, 87 },
  { 2084, 1130, 873, 96, 145, 87 },
  { 93, 1130, 873, 96, 145, 87 },
  { 382, 1130, 873, 96, 145, 87 },
  { 661, 1130, 873, 96, 145, 87 },
  { 880, 1130, 873, 96, 145, 87 },
  { 1096, 1130, 873, 96, 145, 87 },
  { 1312, 1130, 873, 96, 145, 87 },
  { 1524, 1130, 873, 96, 145, 87 },
  { 1736, 1130, 873, 96, 145, 87 },
  { 1948, 1130, 873, 96, 145, 87 },
  { 2160, 1130, 873, 96, 145, 87 },
  { 169, 1130, 873, 96, 145, 87 },
  { 458, 1130, 873, 96, 145, 87 },
  { 237, 1162, 873, 96, 304, 92 },
  { 517, 1019, 873, 96, 864, 78 },
  { 735, 1098, 873, 96, 6784, 17 },
  { 739, 956, 542, 75, 737, 93 },
  { 956, 956, 381, 75, 737, 93 },
  { 1172, 956, 381, 75, 737, 93 },
  { 1388, 956, 381, 75, 737, 93 },
  { 1600, 956, 381, 75, 737, 93 },
  { 1812, 956, 381, 75, 737, 93 },
  { 2024, 956, 381, 75, 737, 93 },
  { 2228, 956, 381, 75, 737, 93 },
  { 28, 956, 381, 75, 737, 93 },
  { 313, 956, 381, 75, 737, 93 },
  { 590, 956, 381, 75, 737, 93 },
  { 808, 956, 381, 75, 737, 93 },
  { 1024, 956, 381, 75, 737, 93 },
  { 1240, 956, 381, 75, 737, 93 },
  { 1452, 956, 381, 75, 737, 93 },
  { 1664, 956, 381, 75, 737, 93 },
  { 1876, 956, 381, 75, 737, 93 },
  { 2088, 956, 381, 75, 737, 93 },
  { 97, 956, 381, 75, 737, 93 },
  { 386, 956, 381, 75, 737, 93 },
  { 665, 956, 381, 75, 737, 93 },
  { 884, 956, 381, 75, 737, 93 },
  { 1100, 956, 381, 75, 737, 93 },
  { 1316, 956, 381, 75, 737, 93 },
  { 1528, 956, 381, 75, 737, 93 },
  { 1740, 956, 381, 75, 737, 93 },
  { 1952, 956, 381, 75, 737, 93 },
  { 2164, 956, 381, 75, 737, 93 },
  { 173, 956, 381, 75, 737, 93 },
  { 462, 956, 381, 75, 737, 93 },
  { 241, 977, 381, 75, 1088, 83 },
  { 521, 998, 381, 75, 8032, 22 },
  { 255, 875, 550, 7, 8832, 32 },
  { 2499, 943, 548, 7, 6432, 32 },
  { 534, 144, 550, 7, 2209, 32 },
  { 751, 144, 550, 7, 2209, 32 },
  { 968, 144, 550, 7, 2209, 32 },
  { 1184, 144, 550, 7, 2209, 32 },
  { 1400, 144, 550, 7, 2209, 32 },
  { 1612, 144, 550, 7, 2209, 32 },
  { 1824, 144, 550, 7, 2209, 32 },
  { 2036, 144, 550, 7, 2209, 32 },
  { 2240, 144, 550, 7, 2209, 32 },
  { 42, 144, 550, 7, 2209, 32 },
  { 328, 144, 550, 7, 2209, 32 },
  { 606, 144, 550, 7, 2209, 32 },
  { 824, 144, 550, 7, 2209, 32 },
  { 1040, 144, 550, 7, 2209, 32 },
  { 1256, 144, 550, 7, 2209, 32 },
  { 1468, 144, 550, 7, 2209, 32 },
  { 1680, 144, 550, 7, 2209, 32 },
  { 1892, 144, 550, 7, 2209, 32 },
  { 2104, 144, 550, 7, 2209, 32 },
  { 113, 144, 550, 7, 2209, 32 },
  { 402, 144, 550, 7, 2209, 32 },
  { 681, 144, 550, 7, 2209, 32 },
  { 900, 144, 550, 7, 2209, 32 },
  { 1116, 144, 550, 7, 2209, 32 },
  { 1332, 144, 550, 7, 2209, 32 },
  { 1544, 144, 550, 7, 2209, 32 },
  { 1756, 144, 550, 7, 2209, 32 },
  { 1968, 144, 550, 7, 2209, 32 },
  { 2180, 144, 413, 7, 8976, 29 },
  { 189, 144, 7, 7, 96, 32 },
  { 2493, 905, 8, 128, 96, 97 },
  { 2507, 935, 8, 128, 6529, 97 },
  { 262, 899, 8, 128, 8883, 97 },
  { 2478, 911, 8, 128, 8976, 26 },
  { 540, 917, 8, 128, 2161, 97 },
  { 757, 917, 8, 128, 2161, 97 },
  { 974, 917, 8, 128, 2161, 97 },
  { 1190, 917, 8, 128, 2161, 97 },
  { 1406, 917, 8, 128, 2161, 97 },
  { 1618, 917, 8, 128, 2161, 97 },
  { 1830, 917, 8, 128, 2161, 97 },
  { 2042, 917, 8, 128, 2161, 97 },
  { 2246, 917, 8, 128, 2161, 97 },
  { 49, 917, 8, 128, 2161, 97 },
  { 336, 917, 8, 128, 2161, 97 },
  { 614, 917, 8, 128, 2161, 97 },
  { 832, 917, 8, 128, 2161, 97 },
  { 1048, 917, 8, 128, 2161, 97 },
  { 1264, 917, 8, 128, 2161, 97 },
  { 1476, 917, 8, 128, 2161, 97 },
  { 1688, 917, 8, 128, 2161, 97 },
  { 1900, 917, 8, 128, 2161, 97 },
  { 2112, 917, 8, 128, 2161, 97 },
  { 121, 917, 8, 128, 2161, 97 },
  { 410, 917, 8, 128, 2161, 97 },
  { 689, 917, 8, 128, 2161, 97 },
  { 908, 917, 8, 128, 2161, 97 },
  { 1124, 917, 8, 128, 2161, 97 },
  { 1340, 917, 8, 128, 2161, 97 },
  { 1552, 917, 8, 128, 2161, 97 },
  { 1764, 917, 8, 128, 2161, 97 },
  { 1976, 917, 8, 128, 2161, 97 },
  { 554, 564, 372, 134, 1457, 100 },
  { 770, 564, 525, 134, 1457, 100 },
  { 986, 564, 290, 134, 1457, 100 },
  { 1202, 564, 290, 134, 1457, 100 },
  { 1418, 564, 290, 134, 1457, 100 },
  { 1630, 564, 290, 134, 1457, 100 },
  { 1842, 564, 290, 134, 1457, 100 },
  { 2054, 564, 290, 134, 1457, 100 },
  { 2258, 564, 290, 134, 1457, 100 },
  { 62, 564, 290, 134, 1457, 100 },
  { 350, 564, 290, 134, 1457, 100 },
  { 629, 564, 290, 134, 1457, 100 },
  { 848, 564, 290, 134, 1457, 100 },
  { 1064, 564, 290, 134, 1457, 100 },
  { 1280, 564, 290, 134, 1457, 100 },
  { 1492, 564, 290, 134, 1457, 100 },
  { 1704, 564, 290, 134, 1457, 100 },
  { 1916, 564, 290, 134, 1457, 100 },
  { 2128, 564, 290, 134, 1457, 100 },
  { 137, 564, 290, 134, 1457, 100 },
  { 426, 564, 290, 134, 1457, 100 },
  { 705, 564, 290, 134, 1457, 100 },
  { 924, 564, 290, 134, 1457, 100 },
  { 1140, 564, 290, 134, 1457, 100 },
  { 1356, 564, 290, 134, 1457, 100 },
  { 1568, 564, 290, 134, 1457, 100 },
  { 1780, 564, 290, 134, 1457, 100 },
  { 1992, 564, 290, 134, 1457, 100 },
  { 2196, 564, 290, 134, 1457, 100 },
  { 205, 564, 290, 134, 1457, 100 },
  { 486, 564, 290, 134, 1457, 100 },
  { 277, 581, 290, 134, 8544, 38 },
  { 980, 780, 8, 181, 1, 121 },
  { 1196, 780, 8, 181, 1, 121 },
  { 1412, 780, 8, 181, 1, 121 },
  { 1624, 780, 8, 181, 1, 121 },
  { 1836, 780, 8, 181, 1, 121 },
  { 2048, 780, 8, 181, 1, 121 },
  { 2252, 780, 8, 181, 1, 121 },
  { 56, 780, 8, 181, 1, 121 },
  { 344, 780, 8, 181, 1, 121 },
  { 622, 780, 8, 181, 1, 121 },
  { 840, 780, 8, 181, 1, 121 },
  { 1056, 780, 8, 181, 1, 121 },
  { 1272, 780, 8, 181, 1, 121 },
  { 1484, 780, 8, 181, 1, 121 },
  { 1696, 780, 8, 181, 1, 121 },
  { 1908, 780, 8, 181, 1, 121 },
  { 2120, 780, 8, 181, 1, 121 },
  { 129, 780, 8, 181, 1, 121 },
  { 418, 780, 8, 181, 1, 121 },
  { 697, 780, 8, 181, 1, 121 },
  { 916, 780, 8, 181, 1, 121 },
  { 1132, 780, 8, 181, 1, 121 },
  { 1348, 780, 8, 181, 1, 121 },
  { 1560, 780, 8, 181, 1, 121 },
  { 1772, 780, 8, 181, 1, 121 },
  { 1984, 780, 8, 181, 1, 121 },
  { 2188, 780, 8, 181, 1, 121 },
  { 197, 780, 8, 181, 1, 121 },
  { 478, 780, 8, 181, 1, 121 },
  { 269, 826, 8, 181, 384, 130 },
  { 546, 688, 8, 181, 944, 105 },
  { 763, 734, 8, 181, 6864, 43 },
  { 767, 598, 545, 151, 625, 139 },
  { 983, 598, 180, 151, 625, 139 },
  { 1199, 598, 180, 151, 625, 139 },
  { 1415, 598, 180, 151, 625, 139 },
  { 1627, 598, 180, 151, 625, 139 },
  { 1839, 598, 180, 151, 625, 139 },
  { 2051, 598, 180, 151, 625, 139 },
  { 2255, 598, 180, 151, 625, 139 },
  { 59, 598, 180, 151, 625, 139 },
  { 347, 598, 180, 151, 625, 139 },
  { 625, 598, 180, 151, 625, 139 },
  { 844, 598, 180, 151, 625, 139 },
  { 1060, 598, 180, 151, 625, 139 },
  { 1276, 598, 180, 151, 625, 139 },
  { 1488, 598, 180, 151, 625, 139 },
  { 1700, 598, 180, 151, 625, 139 },
  { 1912, 598, 180, 151, 625, 139 },
  { 2124, 598, 180, 151, 625, 139 },
  { 133, 598, 180, 151, 625, 139 },
  { 422, 598, 180, 151, 625, 139 },
  { 701, 598, 180, 151, 625, 139 },
  { 920, 598, 180, 151, 625, 139 },
  { 1136, 598, 180, 151, 625, 139 },
  { 1352, 598, 180, 151, 625, 139 },
  { 1564, 598, 180, 151, 625, 139 },
  { 1776, 598, 180, 151, 625, 139 },
  { 1988, 598, 180, 151, 625, 139 },
  { 2192, 598, 180, 151, 625, 139 },
  { 201, 598, 180, 151, 625, 139 },
  { 482, 598, 180, 151, 625, 139 },
  { 273, 628, 180, 151, 1152, 114 },
  { 550, 658, 180, 151, 8096, 52 },
};

  // FPR8 Register Class...
  static const MCPhysReg FPR8[] = {
    AArch64_B0, AArch64_B1, AArch64_B2, AArch64_B3, AArch64_B4, AArch64_B5, AArch64_B6, AArch64_B7, AArch64_B8, AArch64_B9, AArch64_B10, AArch64_B11, AArch64_B12, AArch64_B13, AArch64_B14, AArch64_B15, AArch64_B16, AArch64_B17, AArch64_B18, AArch64_B19, AArch64_B20, AArch64_B21, AArch64_B22, AArch64_B23, AArch64_B24, AArch64_B25, AArch64_B26, AArch64_B27, AArch64_B28, AArch64_B29, AArch64_B30, AArch64_B31,
  };
  // FPR8 Bit set.
  static const uint8_t FPR8Bits[] = {
    0x00, 0xfe, 0xff, 0xff, 0xff, 0x01,
  };
  // FPR16 Register Class...
  static const MCPhysReg FPR16[] = {
    AArch64_H0, AArch64_H1, AArch64_H2, AArch64_H3, AArch64_H4, AArch64_H5, AArch64_H6, AArch64_H7, AArch64_H8, AArch64_H9, AArch64_H10, AArch64_H11, AArch64_H12, AArch64_H13, AArch64_H14, AArch64_H15, AArch64_H16, AArch64_H17, AArch64_H18, AArch64_H19, AArch64_H20, AArch64_H21, AArch64_H22, AArch64_H23, AArch64_H24, AArch64_H25, AArch64_H26, AArch64_H27, AArch64_H28, AArch64_H29, AArch64_H30, AArch64_H31,
  };
  // FPR16 Bit set.
  static const uint8_t FPR16Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01,
  };
  // PPR Register Class...
  static const MCPhysReg PPR[] = {
    AArch64_P0, AArch64_P1, AArch64_P2, AArch64_P3, AArch64_P4, AArch64_P5, AArch64_P6, AArch64_P7, AArch64_P8, AArch64_P9, AArch64_P10, AArch64_P11, AArch64_P12, AArch64_P13, AArch64_P14, AArch64_P15,
  };
  // PPR Bit set.
  static const uint8_t PPRBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0x01,
  };
  // PPR_3b Register Class...
  static const MCPhysReg PPR_3b[] = {
    AArch64_P0, AArch64_P1, AArch64_P2, AArch64_P3, AArch64_P4, AArch64_P5, AArch64_P6, AArch64_P7,
  };
  // PPR_3b Bit set.
  static const uint8_t PPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x01,
  };
  // GPR32all Register Class...
  static const MCPhysReg GPR32all[] = {
    AArch64_W0, AArch64_W1, AArch64_W2, AArch64_W3, AArch64_W4, AArch64_W5, AArch64_W6, AArch64_W7, AArch64_W8, AArch64_W9, AArch64_W10, AArch64_W11, AArch64_W12, AArch64_W13, AArch64_W14, AArch64_W15, AArch64_W16, AArch64_W17, AArch64_W18, AArch64_W19, AArch64_W20, AArch64_W21, AArch64_W22, AArch64_W23, AArch64_W24, AArch64_W25, AArch64_W26, AArch64_W27, AArch64_W28, AArch64_W29, AArch64_W30, AArch64_WZR, AArch64_WSP,
  };
  // GPR32all Bit set.
  static const uint8_t GPR32allBits[] = {
    0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff,
  };
  // FPR32 Register Class...
  static const MCPhysReg FPR32[] = {
    AArch64_S0, AArch64_S1, AArch64_S2, AArch64_S3, AArch64_S4, AArch64_S5, AArch64_S6, AArch64_S7, AArch64_S8, AArch64_S9, AArch64_S10, AArch64_S11, AArch64_S12, AArch64_S13, AArch64_S14, AArch64_S15, AArch64_S16, AArch64_S17, AArch64_S18, AArch64_S19, AArch64_S20, AArch64_S21, AArch64_S22, AArch64_S23, AArch64_S24, AArch64_S25, AArch64_S26, AArch64_S27, AArch64_S28, AArch64_S29, AArch64_S30, AArch64_S31,
  };
  // FPR32 Bit set.
  static const uint8_t FPR32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01,
  };
  // GPR32 Register Class...
  static const MCPhysReg GPR32[] = {
    AArch64_W0, AArch64_W1, AArch64_W2, AArch64_W3, AArch64_W4, AArch64_W5, AArch64_W6, AArch64_W7, AArch64_W8, AArch64_W9, AArch64_W10, AArch64_W11, AArch64_W12, AArch64_W13, AArch64_W14, AArch64_W15, AArch64_W16, AArch64_W17, AArch64_W18, AArch64_W19, AArch64_W20, AArch64_W21, AArch64_W22, AArch64_W23, AArch64_W24, AArch64_W25, AArch64_W26, AArch64_W27, AArch64_W28, AArch64_W29, AArch64_W30, AArch64_WZR,
  };
  // GPR32 Bit set.
  static const uint8_t GPR32Bits[] = {
    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff,
  };
  // GPR32sp Register Class...
  static const MCPhysReg GPR32sp[] = {
    AArch64_W0, AArch64_W1, AArch64_W2, AArch64_W3, AArch64_W4, AArch64_W5, AArch64_W6, AArch64_W7, AArch64_W8, AArch64_W9, AArch64_W10, AArch64_W11, AArch64_W12, AArch64_W13, AArch64_W14, AArch64_W15, AArch64_W16, AArch64_W17, AArch64_W18, AArch64_W19, AArch64_W20, AArch64_W21, AArch64_W22, AArch64_W23, AArch64_W24, AArch64_W25, AArch64_W26, AArch64_W27, AArch64_W28, AArch64_W29, AArch64_W30, AArch64_WSP,
  };
  // GPR32sp Bit set.
  static const uint8_t GPR32spBits[] = {
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff,
  };
  // GPR32common Register Class...
  static const MCPhysReg GPR32common[] = {
    AArch64_W0, AArch64_W1, AArch64_W2, AArch64_W3, AArch64_W4, AArch64_W5, AArch64_W6, AArch64_W7, AArch64_W8, AArch64_W9, AArch64_W10, AArch64_W11, AArch64_W12, AArch64_W13, AArch64_W14, AArch64_W15, AArch64_W16, AArch64_W17, AArch64_W18, AArch64_W19, AArch64_W20, AArch64_W21, AArch64_W22, AArch64_W23, AArch64_W24, AArch64_W25, AArch64_W26, AArch64_W27, AArch64_W28, AArch64_W29, AArch64_W30,
  };
  // GPR32common Bit set.
  static const uint8_t GPR32commonBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff,
  };
  // CCR Register Class...
  static const MCPhysReg CCR[] = {
    AArch64_NZCV,
  };
  // CCR Bit set.
  static const uint8_t CCRBits[] = {
    0x10,
  };
  // GPR32sponly Register Class...
  static const MCPhysReg GPR32sponly[] = {
    AArch64_WSP,
  };
  // GPR32sponly Bit set.
  static const uint8_t GPR32sponlyBits[] = {
    0x40,
  };
  // WSeqPairsClass Register Class...
  static const MCPhysReg WSeqPairsClass[] = {
    AArch64_W0_W1, AArch64_W1_W2, AArch64_W2_W3, AArch64_W3_W4, AArch64_W4_W5, AArch64_W5_W6, AArch64_W6_W7, AArch64_W7_W8, AArch64_W8_W9, AArch64_W9_W10, AArch64_W10_W11, AArch64_W11_W12, AArch64_W12_W13, AArch64_W13_W14, AArch64_W14_W15, AArch64_W15_W16, AArch64_W16_W17, AArch64_W17_W18, AArch64_W18_W19, AArch64_W19_W20, AArch64_W20_W21, AArch64_W21_W22, AArch64_W22_W23, AArch64_W23_W24, AArch64_W24_W25, AArch64_W25_W26, AArch64_W26_W27, AArch64_W27_W28, AArch64_W28_W29, AArch64_W29_W30, AArch64_W30_WZR, AArch64_WZR_W0,
  };
  // WSeqPairsClass Bit set.
  static const uint8_t WSeqPairsClassBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0xff, 0xff, 0x1f,
  };
  // WSeqPairsClass_with_sube32_in_GPR32common Register Class...
  static const MCPhysReg WSeqPairsClass_with_sube32_in_GPR32common[] = {
    AArch64_W0_W1, AArch64_W1_W2, AArch64_W2_W3, AArch64_W3_W4, AArch64_W4_W5, AArch64_W5_W6, AArch64_W6_W7, AArch64_W7_W8, AArch64_W8_W9, AArch64_W9_W10, AArch64_W10_W11, AArch64_W11_W12, AArch64_W12_W13, AArch64_W13_W14, AArch64_W14_W15, AArch64_W15_W16, AArch64_W16_W17, AArch64_W17_W18, AArch64_W18_W19, AArch64_W19_W20, AArch64_W20_W21, AArch64_W21_W22, AArch64_W22_W23, AArch64_W23_W24, AArch64_W24_W25, AArch64_W25_W26, AArch64_W26_W27, AArch64_W27_W28, AArch64_W28_W29, AArch64_W29_W30, AArch64_W30_WZR,
  };
  // WSeqPairsClass_with_sube32_in_GPR32common Bit set.
  static const uint8_t WSeqPairsClass_with_sube32_in_GPR32commonBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x1f,
  };
  // WSeqPairsClass_with_subo32_in_GPR32common Register Class...
  static const MCPhysReg WSeqPairsClass_with_subo32_in_GPR32common[] = {
    AArch64_W0_W1, AArch64_W1_W2, AArch64_W2_W3, AArch64_W3_W4, AArch64_W4_W5, AArch64_W5_W6, AArch64_W6_W7, AArch64_W7_W8, AArch64_W8_W9, AArch64_W9_W10, AArch64_W10_W11, AArch64_W11_W12, AArch64_W12_W13, AArch64_W13_W14, AArch64_W14_W15, AArch64_W15_W16, AArch64_W16_W17, AArch64_W17_W18, AArch64_W18_W19, AArch64_W19_W20, AArch64_W20_W21, AArch64_W21_W22, AArch64_W22_W23, AArch64_W23_W24, AArch64_W24_W25, AArch64_W25_W26, AArch64_W26_W27, AArch64_W27_W28, AArch64_W28_W29, AArch64_W29_W30, AArch64_WZR_W0,
  };
  // WSeqPairsClass_with_subo32_in_GPR32common Bit set.
  static const uint8_t WSeqPairsClass_with_subo32_in_GPR32commonBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xff, 0xff, 0xff, 0x1f,
  };
  // WSeqPairsClass_with_sube32_in_GPR32common_and_WSeqPairsClass_with_subo32_in_GPR32common Register Class...
  static const MCPhysReg WSeqPairsClass_with_sube32_in_GPR32common_and_WSeqPairsClass_with_subo32_in_GPR32common[] = {
    AArch64_W0_W1, AArch64_W1_W2, AArch64_W2_W3, AArch64_W3_W4, AArch64_W4_W5, AArch64_W5_W6, AArch64_W6_W7, AArch64_W7_W8, AArch64_W8_W9, AArch64_W9_W10, AArch64_W10_W11, AArch64_W11_W12, AArch64_W12_W13, AArch64_W13_W14, AArch64_W14_W15, AArch64_W15_W16, AArch64_W16_W17, AArch64_W17_W18, AArch64_W18_W19, AArch64_W19_W20, AArch64_W20_W21, AArch64_W21_W22, AArch64_W22_W23, AArch64_W23_W24, AArch64_W24_W25, AArch64_W25_W26, AArch64_W26_W27, AArch64_W27_W28, AArch64_W28_W29, AArch64_W29_W30,
  };
  // WSeqPairsClass_with_sube32_in_GPR32common_and_WSeqPairsClass_with_subo32_in_GPR32common Bit set.
  static const uint8_t WSeqPairsClass_with_sube32_in_GPR32common_and_WSeqPairsClass_with_subo32_in_GPR32commonBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0xff, 0x1f,
  };
  // GPR64all Register Class...
  static const MCPhysReg GPR64all[] = {
    AArch64_X0, AArch64_X1, AArch64_X2, AArch64_X3, AArch64_X4, AArch64_X5, AArch64_X6, AArch64_X7, AArch64_X8, AArch64_X9, AArch64_X10, AArch64_X11, AArch64_X12, AArch64_X13, AArch64_X14, AArch64_X15, AArch64_X16, AArch64_X17, AArch64_X18, AArch64_X19, AArch64_X20, AArch64_X21, AArch64_X22, AArch64_X23, AArch64_X24, AArch64_X25, AArch64_X26, AArch64_X27, AArch64_X28, AArch64_FP, AArch64_LR, AArch64_XZR, AArch64_SP,
  };
  // GPR64all Bit set.
  static const uint8_t GPR64allBits[] = {
    0x2c, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x1f,
  };
  // FPR64 Register Class...
  static const MCPhysReg FPR64[] = {
    AArch64_D0, AArch64_D1, AArch64_D2, AArch64_D3, AArch64_D4, AArch64_D5, AArch64_D6, AArch64_D7, AArch64_D8, AArch64_D9, AArch64_D10, AArch64_D11, AArch64_D12, AArch64_D13, AArch64_D14, AArch64_D15, AArch64_D16, AArch64_D17, AArch64_D18, AArch64_D19, AArch64_D20, AArch64_D21, AArch64_D22, AArch64_D23, AArch64_D24, AArch64_D25, AArch64_D26, AArch64_D27, AArch64_D28, AArch64_D29, AArch64_D30, AArch64_D31,
  };
  // FPR64 Bit set.
  static const uint8_t FPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01,
  };
  // GPR64 Register Class...
  static const MCPhysReg GPR64[] = {
    AArch64_X0, AArch64_X1, AArch64_X2, AArch64_X3, AArch64_X4, AArch64_X5, AArch64_X6, AArch64_X7, AArch64_X8, AArch64_X9, AArch64_X10, AArch64_X11, AArch64_X12, AArch64_X13, AArch64_X14, AArch64_X15, AArch64_X16, AArch64_X17, AArch64_X18, AArch64_X19, AArch64_X20, AArch64_X21, AArch64_X22, AArch64_X23, AArch64_X24, AArch64_X25, AArch64_X26, AArch64_X27, AArch64_X28, AArch64_FP, AArch64_LR, AArch64_XZR,
  };
  // GPR64 Bit set.
  static const uint8_t GPR64Bits[] = {
    0x0c, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x1f,
  };
  // GPR64sp Register Class...
  static const MCPhysReg GPR64sp[] = {
    AArch64_X0, AArch64_X1, AArch64_X2, AArch64_X3, AArch64_X4, AArch64_X5, AArch64_X6, AArch64_X7, AArch64_X8, AArch64_X9, AArch64_X10, AArch64_X11, AArch64_X12, AArch64_X13, AArch64_X14, AArch64_X15, AArch64_X16, AArch64_X17, AArch64_X18, AArch64_X19, AArch64_X20, AArch64_X21, AArch64_X22, AArch64_X23, AArch64_X24, AArch64_X25, AArch64_X26, AArch64_X27, AArch64_X28, AArch64_FP, AArch64_LR, AArch64_SP,
  };
  // GPR64sp Bit set.
  static const uint8_t GPR64spBits[] = {
    0x2c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x1f,
  };
  // GPR64common Register Class...
  static const MCPhysReg GPR64common[] = {
    AArch64_X0, AArch64_X1, AArch64_X2, AArch64_X3, AArch64_X4, AArch64_X5, AArch64_X6, AArch64_X7, AArch64_X8, AArch64_X9, AArch64_X10, AArch64_X11, AArch64_X12, AArch64_X13, AArch64_X14, AArch64_X15, AArch64_X16, AArch64_X17, AArch64_X18, AArch64_X19, AArch64_X20, AArch64_X21, AArch64_X22, AArch64_X23, AArch64_X24, AArch64_X25, AArch64_X26, AArch64_X27, AArch64_X28, AArch64_FP, AArch64_LR,
  };
  // GPR64common Bit set.
  static const uint8_t GPR64commonBits[] = {
    0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x1f,
  };
  // tcGPR64 Register Class...
  static const MCPhysReg tcGPR64[] = {
    AArch64_X0, AArch64_X1, AArch64_X2, AArch64_X3, AArch64_X4, AArch64_X5, AArch64_X6, AArch64_X7, AArch64_X8, AArch64_X9, AArch64_X10, AArch64_X11, AArch64_X12, AArch64_X13, AArch64_X14, AArch64_X15, AArch64_X16, AArch64_X17, AArch64_X18,
  };
  // tcGPR64 Bit set.
  static const uint8_t tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x07,
  };
  // GPR64sponly Register Class...
  static const MCPhysReg GPR64sponly[] = {
    AArch64_SP,
  };
  // GPR64sponly Bit set.
  static const uint8_t GPR64sponlyBits[] = {
    0x20,
  };
  // DD Register Class...
  static const MCPhysReg DD[] = {
    AArch64_D0_D1, AArch64_D1_D2, AArch64_D2_D3, AArch64_D3_D4, AArch64_D4_D5, AArch64_D5_D6, AArch64_D6_D7, AArch64_D7_D8, AArch64_D8_D9, AArch64_D9_D10, AArch64_D10_D11, AArch64_D11_D12, AArch64_D12_D13, AArch64_D13_D14, AArch64_D14_D15, AArch64_D15_D16, AArch64_D16_D17, AArch64_D17_D18, AArch64_D18_D19, AArch64_D19_D20, AArch64_D20_D21, AArch64_D21_D22, AArch64_D22_D23, AArch64_D23_D24, AArch64_D24_D25, AArch64_D25_D26, AArch64_D26_D27, AArch64_D27_D28, AArch64_D28_D29, AArch64_D29_D30, AArch64_D30_D31, AArch64_D31_D0,
  };
  // DD Bit set.
  static const uint8_t DDBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0xff, 0xff, 0x1f,
  };
  // XSeqPairsClass Register Class...
  static const MCPhysReg XSeqPairsClass[] = {
    AArch64_X0_X1, AArch64_X1_X2, AArch64_X2_X3, AArch64_X3_X4, AArch64_X4_X5, AArch64_X5_X6, AArch64_X6_X7, AArch64_X7_X8, AArch64_X8_X9, AArch64_X9_X10, AArch64_X10_X11, AArch64_X11_X12, AArch64_X12_X13, AArch64_X13_X14, AArch64_X14_X15, AArch64_X15_X16, AArch64_X16_X17, AArch64_X17_X18, AArch64_X18_X19, AArch64_X19_X20, AArch64_X20_X21, AArch64_X21_X22, AArch64_X22_X23, AArch64_X23_X24, AArch64_X24_X25, AArch64_X25_X26, AArch64_X26_X27, AArch64_X27_X28, AArch64_X28_FP, AArch64_FP_LR, AArch64_LR_XZR, AArch64_XZR_X0,
  };
  // XSeqPairsClass Bit set.
  static const uint8_t XSeqPairsClassBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0xff, 0xff, 0x1f,
  };
  // XSeqPairsClass_with_sub_32_in_GPR32common Register Class...
  static const MCPhysReg XSeqPairsClass_with_sub_32_in_GPR32common[] = {
    AArch64_X0_X1, AArch64_X1_X2, AArch64_X2_X3, AArch64_X3_X4, AArch64_X4_X5, AArch64_X5_X6, AArch64_X6_X7, AArch64_X7_X8, AArch64_X8_X9, AArch64_X9_X10, AArch64_X10_X11, AArch64_X11_X12, AArch64_X12_X13, AArch64_X13_X14, AArch64_X14_X15, AArch64_X15_X16, AArch64_X16_X17, AArch64_X17_X18, AArch64_X18_X19, AArch64_X19_X20, AArch64_X20_X21, AArch64_X21_X22, AArch64_X22_X23, AArch64_X23_X24, AArch64_X24_X25, AArch64_X25_X26, AArch64_X26_X27, AArch64_X27_X28, AArch64_X28_FP, AArch64_FP_LR, AArch64_LR_XZR,
  };
  // XSeqPairsClass_with_sub_32_in_GPR32common Bit set.
  static const uint8_t XSeqPairsClass_with_sub_32_in_GPR32commonBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 0xff, 0xff, 0xff, 0x1f,
  };
  // XSeqPairsClass_with_subo64_in_GPR64common Register Class...
  static const MCPhysReg XSeqPairsClass_with_subo64_in_GPR64common[] = {
    AArch64_X0_X1, AArch64_X1_X2, AArch64_X2_X3, AArch64_X3_X4, AArch64_X4_X5, AArch64_X5_X6, AArch64_X6_X7, AArch64_X7_X8, AArch64_X8_X9, AArch64_X9_X10, AArch64_X10_X11, AArch64_X11_X12, AArch64_X12_X13, AArch64_X13_X14, AArch64_X14_X15, AArch64_X15_X16, AArch64_X16_X17, AArch64_X17_X18, AArch64_X18_X19, AArch64_X19_X20, AArch64_X20_X21, AArch64_X21_X22, AArch64_X22_X23, AArch64_X23_X24, AArch64_X24_X25, AArch64_X25_X26, AArch64_X26_X27, AArch64_X27_X28, AArch64_X28_FP, AArch64_FP_LR, AArch64_XZR_X0,
  };
  // XSeqPairsClass_with_subo64_in_GPR64common Bit set.
  static const uint8_t XSeqPairsClass_with_subo64_in_GPR64commonBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xff, 0xff, 0xff, 0x1f,
  };
  // XSeqPairsClass_with_sub_32_in_GPR32common_and_XSeqPairsClass_with_subo64_in_GPR64common Register Class...
  static const MCPhysReg XSeqPairsClass_with_sub_32_in_GPR32common_and_XSeqPairsClass_with_subo64_in_GPR64common[] = {
    AArch64_X0_X1, AArch64_X1_X2, AArch64_X2_X3, AArch64_X3_X4, AArch64_X4_X5, AArch64_X5_X6, AArch64_X6_X7, AArch64_X7_X8, AArch64_X8_X9, AArch64_X9_X10, AArch64_X10_X11, AArch64_X11_X12, AArch64_X12_X13, AArch64_X13_X14, AArch64_X14_X15, AArch64_X15_X16, AArch64_X16_X17, AArch64_X17_X18, AArch64_X18_X19, AArch64_X19_X20, AArch64_X20_X21, AArch64_X21_X22, AArch64_X22_X23, AArch64_X23_X24, AArch64_X24_X25, AArch64_X25_X26, AArch64_X26_X27, AArch64_X27_X28, AArch64_X28_FP, AArch64_FP_LR,
  };
  // XSeqPairsClass_with_sub_32_in_GPR32common_and_XSeqPairsClass_with_subo64_in_GPR64common Bit set.
  static const uint8_t XSeqPairsClass_with_sub_32_in_GPR32common_and_XSeqPairsClass_with_subo64_in_GPR64commonBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0xff, 0xff, 0xff, 0x1f,
  };
  // XSeqPairsClass_with_sube64_in_tcGPR64 Register Class...
  static const MCPhysReg XSeqPairsClass_with_sube64_in_tcGPR64[] = {
    AArch64_X0_X1, AArch64_X1_X2, AArch64_X2_X3, AArch64_X3_X4, AArch64_X4_X5, AArch64_X5_X6, AArch64_X6_X7, AArch64_X7_X8, AArch64_X8_X9, AArch64_X9_X10, AArch64_X10_X11, AArch64_X11_X12, AArch64_X12_X13, AArch64_X13_X14, AArch64_X14_X15, AArch64_X15_X16, AArch64_X16_X17, AArch64_X17_X18, AArch64_X18_X19,
  };
  // XSeqPairsClass_with_sube64_in_tcGPR64 Bit set.
  static const uint8_t XSeqPairsClass_with_sube64_in_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0x0f,
  };
  // XSeqPairsClass_with_subo64_in_tcGPR64 Register Class...
  static const MCPhysReg XSeqPairsClass_with_subo64_in_tcGPR64[] = {
    AArch64_X0_X1, AArch64_X1_X2, AArch64_X2_X3, AArch64_X3_X4, AArch64_X4_X5, AArch64_X5_X6, AArch64_X6_X7, AArch64_X7_X8, AArch64_X8_X9, AArch64_X9_X10, AArch64_X10_X11, AArch64_X11_X12, AArch64_X12_X13, AArch64_X13_X14, AArch64_X14_X15, AArch64_X15_X16, AArch64_X16_X17, AArch64_X17_X18, AArch64_XZR_X0,
  };
  // XSeqPairsClass_with_subo64_in_tcGPR64 Bit set.
  static const uint8_t XSeqPairsClass_with_subo64_in_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xfe, 0xff, 0x07,
  };
  // XSeqPairsClass_with_sub_32_in_GPR32common_and_XSeqPairsClass_with_subo64_in_tcGPR64 Register Class...
  static const MCPhysReg XSeqPairsClass_with_sub_32_in_GPR32common_and_XSeqPairsClass_with_subo64_in_tcGPR64[] = {
    AArch64_X0_X1, AArch64_X1_X2, AArch64_X2_X3, AArch64_X3_X4, AArch64_X4_X5, AArch64_X5_X6, AArch64_X6_X7, AArch64_X7_X8, AArch64_X8_X9, AArch64_X9_X10, AArch64_X10_X11, AArch64_X11_X12, AArch64_X12_X13, AArch64_X13_X14, AArch64_X14_X15, AArch64_X15_X16, AArch64_X16_X17, AArch64_X17_X18,
  };
  // XSeqPairsClass_with_sub_32_in_GPR32common_and_XSeqPairsClass_with_subo64_in_tcGPR64 Bit set.
  static const uint8_t XSeqPairsClass_with_sub_32_in_GPR32common_and_XSeqPairsClass_with_subo64_in_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0x07,
  };
  // FPR128 Register Class...
  static const MCPhysReg FPR128[] = {
    AArch64_Q0, AArch64_Q1, AArch64_Q2, AArch64_Q3, AArch64_Q4, AArch64_Q5, AArch64_Q6, AArch64_Q7, AArch64_Q8, AArch64_Q9, AArch64_Q10, AArch64_Q11, AArch64_Q12, AArch64_Q13, AArch64_Q14, AArch64_Q15, AArch64_Q16, AArch64_Q17, AArch64_Q18, AArch64_Q19, AArch64_Q20, AArch64_Q21, AArch64_Q22, AArch64_Q23, AArch64_Q24, AArch64_Q25, AArch64_Q26, AArch64_Q27, AArch64_Q28, AArch64_Q29, AArch64_Q30, AArch64_Q31,
  };
  // FPR128 Bit set.
  static const uint8_t FPR128Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01,
  };
  // ZPR Register Class...
  static const MCPhysReg ZPR[] = {
    AArch64_Z0, AArch64_Z1, AArch64_Z2, AArch64_Z3, AArch64_Z4, AArch64_Z5, AArch64_Z6, AArch64_Z7, AArch64_Z8, AArch64_Z9, AArch64_Z10, AArch64_Z11, AArch64_Z12, AArch64_Z13, AArch64_Z14, AArch64_Z15, AArch64_Z16, AArch64_Z17, AArch64_Z18, AArch64_Z19, AArch64_Z20, AArch64_Z21, AArch64_Z22, AArch64_Z23, AArch64_Z24, AArch64_Z25, AArch64_Z26, AArch64_Z27, AArch64_Z28, AArch64_Z29, AArch64_Z30, AArch64_Z31,
  };
  // ZPR Bit set.
  static const uint8_t ZPRBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0xff, 0xff, 0x1f,
  };
  // FPR128_lo Register Class...
  static const MCPhysReg FPR128_lo[] = {
    AArch64_Q0, AArch64_Q1, AArch64_Q2, AArch64_Q3, AArch64_Q4, AArch64_Q5, AArch64_Q6, AArch64_Q7, AArch64_Q8, AArch64_Q9, AArch64_Q10, AArch64_Q11, AArch64_Q12, AArch64_Q13, AArch64_Q14, AArch64_Q15,
  };
  // FPR128_lo Bit set.
  static const uint8_t FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0x01,
  };
  // ZPR_4b Register Class...
  static const MCPhysReg ZPR_4b[] = {
    AArch64_Z0, AArch64_Z1, AArch64_Z2, AArch64_Z3, AArch64_Z4, AArch64_Z5, AArch64_Z6, AArch64_Z7, AArch64_Z8, AArch64_Z9, AArch64_Z10, AArch64_Z11, AArch64_Z12, AArch64_Z13, AArch64_Z14, AArch64_Z15,
  };
  // ZPR_4b Bit set.
  static const uint8_t ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x1f,
  };
  // ZPR_3b Register Class...
  static const MCPhysReg ZPR_3b[] = {
    AArch64_Z0, AArch64_Z1, AArch64_Z2, AArch64_Z3, AArch64_Z4, AArch64_Z5, AArch64_Z6, AArch64_Z7,
  };
  // ZPR_3b Bit set.
  static const uint8_t ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x1f,
  };
  // DDD Register Class...
  static const MCPhysReg DDD[] = {
    AArch64_D0_D1_D2, AArch64_D1_D2_D3, AArch64_D2_D3_D4, AArch64_D3_D4_D5, AArch64_D4_D5_D6, AArch64_D5_D6_D7, AArch64_D6_D7_D8, AArch64_D7_D8_D9, AArch64_D8_D9_D10, AArch64_D9_D10_D11, AArch64_D10_D11_D12, AArch64_D11_D12_D13, AArch64_D12_D13_D14, AArch64_D13_D14_D15, AArch64_D14_D15_D16, AArch64_D15_D16_D17, AArch64_D16_D17_D18, AArch64_D17_D18_D19, AArch64_D18_D19_D20, AArch64_D19_D20_D21, AArch64_D20_D21_D22, AArch64_D21_D22_D23, AArch64_D22_D23_D24, AArch64_D23_D24_D25, AArch64_D24_D25_D26, AArch64_D25_D26_D27, AArch64_D26_D27_D28, AArch64_D27_D28_D29, AArch64_D28_D29_D30, AArch64_D29_D30_D31, AArch64_D30_D31_D0, AArch64_D31_D0_D1,
  };
  // DDD Bit set.
  static const uint8_t DDDBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0xff, 0xff, 0x1f,
  };
  // DDDD Register Class...
  static const MCPhysReg DDDD[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D13_D14_D15_D16, AArch64_D14_D15_D16_D17, AArch64_D15_D16_D17_D18, AArch64_D16_D17_D18_D19, AArch64_D17_D18_D19_D20, AArch64_D18_D19_D20_D21, AArch64_D19_D20_D21_D22, AArch64_D20_D21_D22_D23, AArch64_D21_D22_D23_D24, AArch64_D22_D23_D24_D25, AArch64_D23_D24_D25_D26, AArch64_D24_D25_D26_D27, AArch64_D25_D26_D27_D28, AArch64_D26_D27_D28_D29, AArch64_D27_D28_D29_D30, AArch64_D28_D29_D30_D31, AArch64_D29_D30_D31_D0, AArch64_D30_D31_D0_D1, AArch64_D31_D0_D1_D2,
  };
  // DDDD Bit set.
  static const uint8_t DDDDBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0xff, 0xff, 0x1f,
  };
  // QQ Register Class...
  static const MCPhysReg QQ[] = {
    AArch64_Q0_Q1, AArch64_Q1_Q2, AArch64_Q2_Q3, AArch64_Q3_Q4, AArch64_Q4_Q5, AArch64_Q5_Q6, AArch64_Q6_Q7, AArch64_Q7_Q8, AArch64_Q8_Q9, AArch64_Q9_Q10, AArch64_Q10_Q11, AArch64_Q11_Q12, AArch64_Q12_Q13, AArch64_Q13_Q14, AArch64_Q14_Q15, AArch64_Q15_Q16, AArch64_Q16_Q17, AArch64_Q17_Q18, AArch64_Q18_Q19, AArch64_Q19_Q20, AArch64_Q20_Q21, AArch64_Q21_Q22, AArch64_Q22_Q23, AArch64_Q23_Q24, AArch64_Q24_Q25, AArch64_Q25_Q26, AArch64_Q26_Q27, AArch64_Q27_Q28, AArch64_Q28_Q29, AArch64_Q29_Q30, AArch64_Q30_Q31, AArch64_Q31_Q0,
  };
  // QQ Bit set.
  static const uint8_t QQBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0xff, 0xff, 0x1f,
  };
  // ZPR2 Register Class...
  static const MCPhysReg ZPR2[] = {
    AArch64_Z0_Z1, AArch64_Z1_Z2, AArch64_Z2_Z3, AArch64_Z3_Z4, AArch64_Z4_Z5, AArch64_Z5_Z6, AArch64_Z6_Z7, AArch64_Z7_Z8, AArch64_Z8_Z9, AArch64_Z9_Z10, AArch64_Z10_Z11, AArch64_Z11_Z12, AArch64_Z12_Z13, AArch64_Z13_Z14, AArch64_Z14_Z15, AArch64_Z15_Z16, AArch64_Z16_Z17, AArch64_Z17_Z18, AArch64_Z18_Z19, AArch64_Z19_Z20, AArch64_Z20_Z21, AArch64_Z21_Z22, AArch64_Z22_Z23, AArch64_Z23_Z24, AArch64_Z24_Z25, AArch64_Z25_Z26, AArch64_Z26_Z27, AArch64_Z27_Z28, AArch64_Z28_Z29, AArch64_Z29_Z30, AArch64_Z30_Z31, AArch64_Z31_Z0,
  };
  // ZPR2 Bit set.
  static const uint8_t ZPR2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0xff, 0xff, 0x1f,
  };
  // QQ_with_qsub0_in_FPR128_lo Register Class...
  static const MCPhysReg QQ_with_qsub0_in_FPR128_lo[] = {
    AArch64_Q0_Q1, AArch64_Q1_Q2, AArch64_Q2_Q3, AArch64_Q3_Q4, AArch64_Q4_Q5, AArch64_Q5_Q6, AArch64_Q6_Q7, AArch64_Q7_Q8, AArch64_Q8_Q9, AArch64_Q9_Q10, AArch64_Q10_Q11, AArch64_Q11_Q12, AArch64_Q12_Q13, AArch64_Q13_Q14, AArch64_Q14_Q15, AArch64_Q15_Q16,
  };
  // QQ_with_qsub0_in_FPR128_lo Bit set.
  static const uint8_t QQ_with_qsub0_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x1f,
  };
  // QQ_with_qsub1_in_FPR128_lo Register Class...
  static const MCPhysReg QQ_with_qsub1_in_FPR128_lo[] = {
    AArch64_Q0_Q1, AArch64_Q1_Q2, AArch64_Q2_Q3, AArch64_Q3_Q4, AArch64_Q4_Q5, AArch64_Q5_Q6, AArch64_Q6_Q7, AArch64_Q7_Q8, AArch64_Q8_Q9, AArch64_Q9_Q10, AArch64_Q10_Q11, AArch64_Q11_Q12, AArch64_Q12_Q13, AArch64_Q13_Q14, AArch64_Q14_Q15, AArch64_Q31_Q0,
  };
  // QQ_with_qsub1_in_FPR128_lo Bit set.
  static const uint8_t QQ_with_qsub1_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x0f, 0x00, 0x10,
  };
  // ZPR2_with_zsub1_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR2_with_zsub1_in_ZPR_4b[] = {
    AArch64_Z0_Z1, AArch64_Z1_Z2, AArch64_Z2_Z3, AArch64_Z3_Z4, AArch64_Z4_Z5, AArch64_Z5_Z6, AArch64_Z6_Z7, AArch64_Z7_Z8, AArch64_Z8_Z9, AArch64_Z9_Z10, AArch64_Z10_Z11, AArch64_Z11_Z12, AArch64_Z12_Z13, AArch64_Z13_Z14, AArch64_Z14_Z15, AArch64_Z31_Z0,
  };
  // ZPR2_with_zsub1_in_ZPR_4b Bit set.
  static const uint8_t ZPR2_with_zsub1_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x0f, 0x00, 0x10,
  };
  // ZPR2_with_zsub_in_FPR128_lo Register Class...
  static const MCPhysReg ZPR2_with_zsub_in_FPR128_lo[] = {
    AArch64_Z0_Z1, AArch64_Z1_Z2, AArch64_Z2_Z3, AArch64_Z3_Z4, AArch64_Z4_Z5, AArch64_Z5_Z6, AArch64_Z6_Z7, AArch64_Z7_Z8, AArch64_Z8_Z9, AArch64_Z9_Z10, AArch64_Z10_Z11, AArch64_Z11_Z12, AArch64_Z12_Z13, AArch64_Z13_Z14, AArch64_Z14_Z15, AArch64_Z15_Z16,
  };
  // ZPR2_with_zsub_in_FPR128_lo Bit set.
  static const uint8_t ZPR2_with_zsub_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x1f,
  };
  // QQ_with_qsub0_in_FPR128_lo_and_QQ_with_qsub1_in_FPR128_lo Register Class...
  static const MCPhysReg QQ_with_qsub0_in_FPR128_lo_and_QQ_with_qsub1_in_FPR128_lo[] = {
    AArch64_Q0_Q1, AArch64_Q1_Q2, AArch64_Q2_Q3, AArch64_Q3_Q4, AArch64_Q4_Q5, AArch64_Q5_Q6, AArch64_Q6_Q7, AArch64_Q7_Q8, AArch64_Q8_Q9, AArch64_Q9_Q10, AArch64_Q10_Q11, AArch64_Q11_Q12, AArch64_Q12_Q13, AArch64_Q13_Q14, AArch64_Q14_Q15,
  };
  // QQ_with_qsub0_in_FPR128_lo_and_QQ_with_qsub1_in_FPR128_lo Bit set.
  static const uint8_t QQ_with_qsub0_in_FPR128_lo_and_QQ_with_qsub1_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x0f,
  };
  // ZPR2_with_zsub_in_FPR128_lo_and_ZPR2_with_zsub1_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR2_with_zsub_in_FPR128_lo_and_ZPR2_with_zsub1_in_ZPR_4b[] = {
    AArch64_Z0_Z1, AArch64_Z1_Z2, AArch64_Z2_Z3, AArch64_Z3_Z4, AArch64_Z4_Z5, AArch64_Z5_Z6, AArch64_Z6_Z7, AArch64_Z7_Z8, AArch64_Z8_Z9, AArch64_Z9_Z10, AArch64_Z10_Z11, AArch64_Z11_Z12, AArch64_Z12_Z13, AArch64_Z13_Z14, AArch64_Z14_Z15,
  };
  // ZPR2_with_zsub_in_FPR128_lo_and_ZPR2_with_zsub1_in_ZPR_4b Bit set.
  static const uint8_t ZPR2_with_zsub_in_FPR128_lo_and_ZPR2_with_zsub1_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x0f,
  };
  // ZPR2_with_zsub0_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR2_with_zsub0_in_ZPR_3b[] = {
    AArch64_Z0_Z1, AArch64_Z1_Z2, AArch64_Z2_Z3, AArch64_Z3_Z4, AArch64_Z4_Z5, AArch64_Z5_Z6, AArch64_Z6_Z7, AArch64_Z7_Z8,
  };
  // ZPR2_with_zsub0_in_ZPR_3b Bit set.
  static const uint8_t ZPR2_with_zsub0_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x1f,
  };
  // ZPR2_with_zsub1_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR2_with_zsub1_in_ZPR_3b[] = {
    AArch64_Z0_Z1, AArch64_Z1_Z2, AArch64_Z2_Z3, AArch64_Z3_Z4, AArch64_Z4_Z5, AArch64_Z5_Z6, AArch64_Z6_Z7, AArch64_Z31_Z0,
  };
  // ZPR2_with_zsub1_in_ZPR_3b Bit set.
  static const uint8_t ZPR2_with_zsub1_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x0f, 0x00, 0x00, 0x10,
  };
  // ZPR2_with_zsub_in_FPR128_lo_and_ZPR2_with_zsub1_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR2_with_zsub_in_FPR128_lo_and_ZPR2_with_zsub1_in_ZPR_3b[] = {
    AArch64_Z0_Z1, AArch64_Z1_Z2, AArch64_Z2_Z3, AArch64_Z3_Z4, AArch64_Z4_Z5, AArch64_Z5_Z6, AArch64_Z6_Z7,
  };
  // ZPR2_with_zsub_in_FPR128_lo_and_ZPR2_with_zsub1_in_ZPR_3b Bit set.
  static const uint8_t ZPR2_with_zsub_in_FPR128_lo_and_ZPR2_with_zsub1_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x0f,
  };
  // QQQ Register Class...
  static const MCPhysReg QQQ[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, AArch64_Q14_Q15_Q16, AArch64_Q15_Q16_Q17, AArch64_Q16_Q17_Q18, AArch64_Q17_Q18_Q19, AArch64_Q18_Q19_Q20, AArch64_Q19_Q20_Q21, AArch64_Q20_Q21_Q22, AArch64_Q21_Q22_Q23, AArch64_Q22_Q23_Q24, AArch64_Q23_Q24_Q25, AArch64_Q24_Q25_Q26, AArch64_Q25_Q26_Q27, AArch64_Q26_Q27_Q28, AArch64_Q27_Q28_Q29, AArch64_Q28_Q29_Q30, AArch64_Q29_Q30_Q31, AArch64_Q30_Q31_Q0, AArch64_Q31_Q0_Q1,
  };
  // QQQ Bit set.
  static const uint8_t QQQBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0xff, 0xff, 0x1f,
  };
  // ZPR3 Register Class...
  static const MCPhysReg ZPR3[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z7_Z8_Z9, AArch64_Z8_Z9_Z10, AArch64_Z9_Z10_Z11, AArch64_Z10_Z11_Z12, AArch64_Z11_Z12_Z13, AArch64_Z12_Z13_Z14, AArch64_Z13_Z14_Z15, AArch64_Z14_Z15_Z16, AArch64_Z15_Z16_Z17, AArch64_Z16_Z17_Z18, AArch64_Z17_Z18_Z19, AArch64_Z18_Z19_Z20, AArch64_Z19_Z20_Z21, AArch64_Z20_Z21_Z22, AArch64_Z21_Z22_Z23, AArch64_Z22_Z23_Z24, AArch64_Z23_Z24_Z25, AArch64_Z24_Z25_Z26, AArch64_Z25_Z26_Z27, AArch64_Z26_Z27_Z28, AArch64_Z27_Z28_Z29, AArch64_Z28_Z29_Z30, AArch64_Z29_Z30_Z31, AArch64_Z30_Z31_Z0, AArch64_Z31_Z0_Z1,
  };
  // ZPR3 Bit set.
  static const uint8_t ZPR3Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0xff, 0xff, 0x1f,
  };
  // QQQ_with_qsub0_in_FPR128_lo Register Class...
  static const MCPhysReg QQQ_with_qsub0_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, AArch64_Q14_Q15_Q16, AArch64_Q15_Q16_Q17,
  };
  // QQQ_with_qsub0_in_FPR128_lo Bit set.
  static const uint8_t QQQ_with_qsub0_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x1f,
  };
  // QQQ_with_qsub1_in_FPR128_lo Register Class...
  static const MCPhysReg QQQ_with_qsub1_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, AArch64_Q14_Q15_Q16, AArch64_Q31_Q0_Q1,
  };
  // QQQ_with_qsub1_in_FPR128_lo Bit set.
  static const uint8_t QQQ_with_qsub1_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x0f, 0x00, 0x10,
  };
  // QQQ_with_qsub2_in_FPR128_lo Register Class...
  static const MCPhysReg QQQ_with_qsub2_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, AArch64_Q30_Q31_Q0, AArch64_Q31_Q0_Q1,
  };
  // QQQ_with_qsub2_in_FPR128_lo Bit set.
  static const uint8_t QQQ_with_qsub2_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x07, 0x00, 0x18,
  };
  // ZPR3_with_zsub1_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR3_with_zsub1_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z7_Z8_Z9, AArch64_Z8_Z9_Z10, AArch64_Z9_Z10_Z11, AArch64_Z10_Z11_Z12, AArch64_Z11_Z12_Z13, AArch64_Z12_Z13_Z14, AArch64_Z13_Z14_Z15, AArch64_Z14_Z15_Z16, AArch64_Z31_Z0_Z1,
  };
  // ZPR3_with_zsub1_in_ZPR_4b Bit set.
  static const uint8_t ZPR3_with_zsub1_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x0f, 0x00, 0x10,
  };
  // ZPR3_with_zsub2_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR3_with_zsub2_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z7_Z8_Z9, AArch64_Z8_Z9_Z10, AArch64_Z9_Z10_Z11, AArch64_Z10_Z11_Z12, AArch64_Z11_Z12_Z13, AArch64_Z12_Z13_Z14, AArch64_Z13_Z14_Z15, AArch64_Z30_Z31_Z0, AArch64_Z31_Z0_Z1,
  };
  // ZPR3_with_zsub2_in_ZPR_4b Bit set.
  static const uint8_t ZPR3_with_zsub2_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x07, 0x00, 0x18,
  };
  // ZPR3_with_zsub_in_FPR128_lo Register Class...
  static const MCPhysReg ZPR3_with_zsub_in_FPR128_lo[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z7_Z8_Z9, AArch64_Z8_Z9_Z10, AArch64_Z9_Z10_Z11, AArch64_Z10_Z11_Z12, AArch64_Z11_Z12_Z13, AArch64_Z12_Z13_Z14, AArch64_Z13_Z14_Z15, AArch64_Z14_Z15_Z16, AArch64_Z15_Z16_Z17,
  };
  // ZPR3_with_zsub_in_FPR128_lo Bit set.
  static const uint8_t ZPR3_with_zsub_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x1f,
  };
  // QQQ_with_qsub0_in_FPR128_lo_and_QQQ_with_qsub1_in_FPR128_lo Register Class...
  static const MCPhysReg QQQ_with_qsub0_in_FPR128_lo_and_QQQ_with_qsub1_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, AArch64_Q14_Q15_Q16,
  };
  // QQQ_with_qsub0_in_FPR128_lo_and_QQQ_with_qsub1_in_FPR128_lo Bit set.
  static const uint8_t QQQ_with_qsub0_in_FPR128_lo_and_QQQ_with_qsub1_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x0f,
  };
  // QQQ_with_qsub1_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_lo Register Class...
  static const MCPhysReg QQQ_with_qsub1_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, AArch64_Q31_Q0_Q1,
  };
  // QQQ_with_qsub1_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_lo Bit set.
  static const uint8_t QQQ_with_qsub1_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x07, 0x00, 0x10,
  };
  // ZPR3_with_zsub1_in_ZPR_4b_and_ZPR3_with_zsub2_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR3_with_zsub1_in_ZPR_4b_and_ZPR3_with_zsub2_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z7_Z8_Z9, AArch64_Z8_Z9_Z10, AArch64_Z9_Z10_Z11, AArch64_Z10_Z11_Z12, AArch64_Z11_Z12_Z13, AArch64_Z12_Z13_Z14, AArch64_Z13_Z14_Z15, AArch64_Z31_Z0_Z1,
  };
  // ZPR3_with_zsub1_in_ZPR_4b_and_ZPR3_with_zsub2_in_ZPR_4b Bit set.
  static const uint8_t ZPR3_with_zsub1_in_ZPR_4b_and_ZPR3_with_zsub2_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x07, 0x00, 0x10,
  };
  // ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub1_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub1_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z7_Z8_Z9, AArch64_Z8_Z9_Z10, AArch64_Z9_Z10_Z11, AArch64_Z10_Z11_Z12, AArch64_Z11_Z12_Z13, AArch64_Z12_Z13_Z14, AArch64_Z13_Z14_Z15, AArch64_Z14_Z15_Z16,
  };
  // ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub1_in_ZPR_4b Bit set.
  static const uint8_t ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub1_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x0f,
  };
  // QQQ_with_qsub0_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_lo Register Class...
  static const MCPhysReg QQQ_with_qsub0_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15,
  };
  // QQQ_with_qsub0_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_lo Bit set.
  static const uint8_t QQQ_with_qsub0_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x07,
  };
  // ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub2_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub2_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z7_Z8_Z9, AArch64_Z8_Z9_Z10, AArch64_Z9_Z10_Z11, AArch64_Z10_Z11_Z12, AArch64_Z11_Z12_Z13, AArch64_Z12_Z13_Z14, AArch64_Z13_Z14_Z15,
  };
  // ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub2_in_ZPR_4b Bit set.
  static const uint8_t ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub2_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x07,
  };
  // ZPR3_with_zsub0_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR3_with_zsub0_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z7_Z8_Z9,
  };
  // ZPR3_with_zsub0_in_ZPR_3b Bit set.
  static const uint8_t ZPR3_with_zsub0_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x1f,
  };
  // ZPR3_with_zsub1_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR3_with_zsub1_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z31_Z0_Z1,
  };
  // ZPR3_with_zsub1_in_ZPR_3b Bit set.
  static const uint8_t ZPR3_with_zsub1_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x0f, 0x00, 0x00, 0x10,
  };
  // ZPR3_with_zsub2_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR3_with_zsub2_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z30_Z31_Z0, AArch64_Z31_Z0_Z1,
  };
  // ZPR3_with_zsub2_in_ZPR_3b Bit set.
  static const uint8_t ZPR3_with_zsub2_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x07, 0x00, 0x00, 0x18,
  };
  // ZPR3_with_zsub1_in_ZPR_3b_and_ZPR3_with_zsub2_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR3_with_zsub1_in_ZPR_3b_and_ZPR3_with_zsub2_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z31_Z0_Z1,
  };
  // ZPR3_with_zsub1_in_ZPR_3b_and_ZPR3_with_zsub2_in_ZPR_3b Bit set.
  static const uint8_t ZPR3_with_zsub1_in_ZPR_3b_and_ZPR3_with_zsub2_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x07, 0x00, 0x00, 0x10,
  };
  // ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub1_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub1_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8,
  };
  // ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub1_in_ZPR_3b Bit set.
  static const uint8_t ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub1_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x0f,
  };
  // ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub2_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub2_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7,
  };
  // ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub2_in_ZPR_3b Bit set.
  static const uint8_t ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub2_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x07,
  };
  // QQQQ Register Class...
  static const MCPhysReg QQQQ[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, AArch64_Q14_Q15_Q16_Q17, AArch64_Q15_Q16_Q17_Q18, AArch64_Q16_Q17_Q18_Q19, AArch64_Q17_Q18_Q19_Q20, AArch64_Q18_Q19_Q20_Q21, AArch64_Q19_Q20_Q21_Q22, AArch64_Q20_Q21_Q22_Q23, AArch64_Q21_Q22_Q23_Q24, AArch64_Q22_Q23_Q24_Q25, AArch64_Q23_Q24_Q25_Q26, AArch64_Q24_Q25_Q26_Q27, AArch64_Q25_Q26_Q27_Q28, AArch64_Q26_Q27_Q28_Q29, AArch64_Q27_Q28_Q29_Q30, AArch64_Q28_Q29_Q30_Q31, AArch64_Q29_Q30_Q31_Q0, AArch64_Q30_Q31_Q0_Q1, AArch64_Q31_Q0_Q1_Q2,
  };
  // QQQQ Bit set.
  static const uint8_t QQQQBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0xff, 0xff, 0x1f,
  };
  // ZPR4 Register Class...
  static const MCPhysReg ZPR4[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z13_Z14_Z15_Z16, AArch64_Z14_Z15_Z16_Z17, AArch64_Z15_Z16_Z17_Z18, AArch64_Z16_Z17_Z18_Z19, AArch64_Z17_Z18_Z19_Z20, AArch64_Z18_Z19_Z20_Z21, AArch64_Z19_Z20_Z21_Z22, AArch64_Z20_Z21_Z22_Z23, AArch64_Z21_Z22_Z23_Z24, AArch64_Z22_Z23_Z24_Z25, AArch64_Z23_Z24_Z25_Z26, AArch64_Z24_Z25_Z26_Z27, AArch64_Z25_Z26_Z27_Z28, AArch64_Z26_Z27_Z28_Z29, AArch64_Z27_Z28_Z29_Z30, AArch64_Z28_Z29_Z30_Z31, AArch64_Z29_Z30_Z31_Z0, AArch64_Z30_Z31_Z0_Z1, AArch64_Z31_Z0_Z1_Z2,
  };
  // ZPR4 Bit set.
  static const uint8_t ZPR4Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0xff, 0xff, 0x1f,
  };
  // QQQQ_with_qsub0_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_qsub0_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, AArch64_Q14_Q15_Q16_Q17, AArch64_Q15_Q16_Q17_Q18,
  };
  // QQQQ_with_qsub0_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_qsub0_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x1f,
  };
  // QQQQ_with_qsub1_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_qsub1_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, AArch64_Q14_Q15_Q16_Q17, AArch64_Q31_Q0_Q1_Q2,
  };
  // QQQQ_with_qsub1_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_qsub1_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x0f, 0x00, 0x10,
  };
  // QQQQ_with_qsub2_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_qsub2_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, AArch64_Q30_Q31_Q0_Q1, AArch64_Q31_Q0_Q1_Q2,
  };
  // QQQQ_with_qsub2_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_qsub2_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x07, 0x00, 0x18,
  };
  // QQQQ_with_qsub3_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_qsub3_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q29_Q30_Q31_Q0, AArch64_Q30_Q31_Q0_Q1, AArch64_Q31_Q0_Q1_Q2,
  };
  // QQQQ_with_qsub3_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_qsub3_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x03, 0x00, 0x1c,
  };
  // ZPR4_with_zsub1_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_zsub1_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z13_Z14_Z15_Z16, AArch64_Z14_Z15_Z16_Z17, AArch64_Z31_Z0_Z1_Z2,
  };
  // ZPR4_with_zsub1_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_zsub1_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x0f, 0x00, 0x10,
  };
  // ZPR4_with_zsub2_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_zsub2_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z13_Z14_Z15_Z16, AArch64_Z30_Z31_Z0_Z1, AArch64_Z31_Z0_Z1_Z2,
  };
  // ZPR4_with_zsub2_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_zsub2_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x07, 0x00, 0x18,
  };
  // ZPR4_with_zsub3_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_zsub3_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z29_Z30_Z31_Z0, AArch64_Z30_Z31_Z0_Z1, AArch64_Z31_Z0_Z1_Z2,
  };
  // ZPR4_with_zsub3_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_zsub3_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x03, 0x00, 0x1c,
  };
  // ZPR4_with_zsub_in_FPR128_lo Register Class...
  static const MCPhysReg ZPR4_with_zsub_in_FPR128_lo[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z13_Z14_Z15_Z16, AArch64_Z14_Z15_Z16_Z17, AArch64_Z15_Z16_Z17_Z18,
  };
  // ZPR4_with_zsub_in_FPR128_lo Bit set.
  static const uint8_t ZPR4_with_zsub_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x1f,
  };
  // QQQQ_with_qsub0_in_FPR128_lo_and_QQQQ_with_qsub1_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_qsub0_in_FPR128_lo_and_QQQQ_with_qsub1_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, AArch64_Q14_Q15_Q16_Q17,
  };
  // QQQQ_with_qsub0_in_FPR128_lo_and_QQQQ_with_qsub1_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_qsub0_in_FPR128_lo_and_QQQQ_with_qsub1_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x0f,
  };
  // QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, AArch64_Q31_Q0_Q1_Q2,
  };
  // QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x07, 0x00, 0x10,
  };
  // QQQQ_with_qsub2_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_qsub2_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q30_Q31_Q0_Q1, AArch64_Q31_Q0_Q1_Q2,
  };
  // QQQQ_with_qsub2_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_qsub2_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x03, 0x00, 0x18,
  };
  // ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub2_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub2_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z13_Z14_Z15_Z16, AArch64_Z31_Z0_Z1_Z2,
  };
  // ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub2_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub2_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x07, 0x00, 0x10,
  };
  // ZPR4_with_zsub2_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_zsub2_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z30_Z31_Z0_Z1, AArch64_Z31_Z0_Z1_Z2,
  };
  // ZPR4_with_zsub2_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_zsub2_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x03, 0x00, 0x18,
  };
  // ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub1_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub1_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z13_Z14_Z15_Z16, AArch64_Z14_Z15_Z16_Z17,
  };
  // ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub1_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub1_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x0f,
  };
  // QQQQ_with_qsub0_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_qsub0_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16,
  };
  // QQQQ_with_qsub0_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_qsub0_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x07,
  };
  // QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q31_Q0_Q1_Q2,
  };
  // QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x03, 0x00, 0x10,
  };
  // ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z31_Z0_Z1_Z2,
  };
  // ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x03, 0x00, 0x10,
  };
  // ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub2_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub2_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z13_Z14_Z15_Z16,
  };
  // ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub2_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub2_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x07,
  };
  // QQQQ_with_qsub0_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_qsub0_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15,
  };
  // QQQQ_with_qsub0_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_qsub0_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x03,
  };
  // ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub3_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub3_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15,
  };
  // ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub3_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub3_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x03,
  };
  // ZPR4_with_zsub0_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub0_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10,
  };
  // ZPR4_with_zsub0_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub0_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x1f,
  };
  // ZPR4_with_zsub1_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub1_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z31_Z0_Z1_Z2,
  };
  // ZPR4_with_zsub1_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub1_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x0f, 0x00, 0x00, 0x10,
  };
  // ZPR4_with_zsub2_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub2_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z30_Z31_Z0_Z1, AArch64_Z31_Z0_Z1_Z2,
  };
  // ZPR4_with_zsub2_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub2_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x07, 0x00, 0x00, 0x18,
  };
  // ZPR4_with_zsub3_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub3_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z29_Z30_Z31_Z0, AArch64_Z30_Z31_Z0_Z1, AArch64_Z31_Z0_Z1_Z2,
  };
  // ZPR4_with_zsub3_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub3_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x03, 0x00, 0x00, 0x1c,
  };
  // ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub2_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub2_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z31_Z0_Z1_Z2,
  };
  // ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub2_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub2_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x07, 0x00, 0x00, 0x10,
  };
  // ZPR4_with_zsub2_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub2_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z30_Z31_Z0_Z1, AArch64_Z31_Z0_Z1_Z2,
  };
  // ZPR4_with_zsub2_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub2_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x03, 0x00, 0x00, 0x18,
  };
  // ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub1_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub1_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9,
  };
  // ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub1_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub1_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x0f,
  };
  // ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z31_Z0_Z1_Z2,
  };
  // ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x03, 0x00, 0x00, 0x10,
  };
  // ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub2_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub2_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8,
  };
  // ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub2_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub2_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x07,
  };
  // ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub3_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub3_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7,
  };
  // ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub3_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub3_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x03,
  };


static const MCRegisterClass AArch64MCRegisterClasses[] = {
  { FPR8, FPR8Bits, sizeof(FPR8Bits) },
  { FPR16, FPR16Bits, sizeof(FPR16Bits) },
  { PPR, PPRBits, sizeof(PPRBits) },
  { PPR_3b, PPR_3bBits, sizeof(PPR_3bBits) },
  { GPR32all, GPR32allBits, sizeof(GPR32allBits) },
  { FPR32, FPR32Bits, sizeof(FPR32Bits) },
  { GPR32, GPR32Bits, sizeof(GPR32Bits) },
  { GPR32sp, GPR32spBits, sizeof(GPR32spBits) },
  { GPR32common, GPR32commonBits, sizeof(GPR32commonBits) },
  { CCR, CCRBits, sizeof(CCRBits) },
  { GPR32sponly, GPR32sponlyBits, sizeof(GPR32sponlyBits) },
  { WSeqPairsClass, WSeqPairsClassBits, sizeof(WSeqPairsClassBits) },
  { WSeqPairsClass_with_sube32_in_GPR32common, WSeqPairsClass_with_sube32_in_GPR32commonBits, sizeof(WSeqPairsClass_with_sube32_in_GPR32commonBits) },
  { WSeqPairsClass_with_subo32_in_GPR32common, WSeqPairsClass_with_subo32_in_GPR32commonBits, sizeof(WSeqPairsClass_with_subo32_in_GPR32commonBits) },
  { WSeqPairsClass_with_sube32_in_GPR32common_and_WSeqPairsClass_with_subo32_in_GPR32common, WSeqPairsClass_with_sube32_in_GPR32common_and_WSeqPairsClass_with_subo32_in_GPR32commonBits, sizeof(WSeqPairsClass_with_sube32_in_GPR32common_and_WSeqPairsClass_with_subo32_in_GPR32commonBits) },
  { GPR64all, GPR64allBits, sizeof(GPR64allBits) },
  { FPR64, FPR64Bits, sizeof(FPR64Bits) },
  { GPR64, GPR64Bits, sizeof(GPR64Bits) },
  { GPR64sp, GPR64spBits, sizeof(GPR64spBits) },
  { GPR64common, GPR64commonBits, sizeof(GPR64commonBits) },
  { tcGPR64, tcGPR64Bits, sizeof(tcGPR64Bits) },
  { GPR64sponly, GPR64sponlyBits, sizeof(GPR64sponlyBits) },
  { DD, DDBits, sizeof(DDBits) },
  { XSeqPairsClass, XSeqPairsClassBits, sizeof(XSeqPairsClassBits) },
  { XSeqPairsClass_with_sub_32_in_GPR32common, XSeqPairsClass_with_sub_32_in_GPR32commonBits, sizeof(XSeqPairsClass_with_sub_32_in_GPR32commonBits) },
  { XSeqPairsClass_with_subo64_in_GPR64common, XSeqPairsClass_with_subo64_in_GPR64commonBits, sizeof(XSeqPairsClass_with_subo64_in_GPR64commonBits) },
  { XSeqPairsClass_with_sub_32_in_GPR32common_and_XSeqPairsClass_with_subo64_in_GPR64common, XSeqPairsClass_with_sub_32_in_GPR32common_and_XSeqPairsClass_with_subo64_in_GPR64commonBits, sizeof(XSeqPairsClass_with_sub_32_in_GPR32common_and_XSeqPairsClass_with_subo64_in_GPR64commonBits) },
  { XSeqPairsClass_with_sube64_in_tcGPR64, XSeqPairsClass_with_sube64_in_tcGPR64Bits, sizeof(XSeqPairsClass_with_sube64_in_tcGPR64Bits) },
  { XSeqPairsClass_with_subo64_in_tcGPR64, XSeqPairsClass_with_subo64_in_tcGPR64Bits, sizeof(XSeqPairsClass_with_subo64_in_tcGPR64Bits) },
  { XSeqPairsClass_with_sub_32_in_GPR32common_and_XSeqPairsClass_with_subo64_in_tcGPR64, XSeqPairsClass_with_sub_32_in_GPR32common_and_XSeqPairsClass_with_subo64_in_tcGPR64Bits, sizeof(XSeqPairsClass_with_sub_32_in_GPR32common_and_XSeqPairsClass_with_subo64_in_tcGPR64Bits) },
  { FPR128, FPR128Bits, sizeof(FPR128Bits) },
  { ZPR, ZPRBits, sizeof(ZPRBits) },
  { FPR128_lo, FPR128_loBits, sizeof(FPR128_loBits) },
  { ZPR_4b, ZPR_4bBits, sizeof(ZPR_4bBits) },
  { ZPR_3b, ZPR_3bBits, sizeof(ZPR_3bBits) },
  { DDD, DDDBits, sizeof(DDDBits) },
  { DDDD, DDDDBits, sizeof(DDDDBits) },
  { QQ, QQBits, sizeof(QQBits) },
  { ZPR2, ZPR2Bits, sizeof(ZPR2Bits) },
  { QQ_with_qsub0_in_FPR128_lo, QQ_with_qsub0_in_FPR128_loBits, sizeof(QQ_with_qsub0_in_FPR128_loBits) },
  { QQ_with_qsub1_in_FPR128_lo, QQ_with_qsub1_in_FPR128_loBits, sizeof(QQ_with_qsub1_in_FPR128_loBits) },
  { ZPR2_with_zsub1_in_ZPR_4b, ZPR2_with_zsub1_in_ZPR_4bBits, sizeof(ZPR2_with_zsub1_in_ZPR_4bBits) },
  { ZPR2_with_zsub_in_FPR128_lo, ZPR2_with_zsub_in_FPR128_loBits, sizeof(ZPR2_with_zsub_in_FPR128_loBits) },
  { QQ_with_qsub0_in_FPR128_lo_and_QQ_with_qsub1_in_FPR128_lo, QQ_with_qsub0_in_FPR128_lo_and_QQ_with_qsub1_in_FPR128_loBits, sizeof(QQ_with_qsub0_in_FPR128_lo_and_QQ_with_qsub1_in_FPR128_loBits) },
  { ZPR2_with_zsub_in_FPR128_lo_and_ZPR2_with_zsub1_in_ZPR_4b, ZPR2_with_zsub_in_FPR128_lo_and_ZPR2_with_zsub1_in_ZPR_4bBits, sizeof(ZPR2_with_zsub_in_FPR128_lo_and_ZPR2_with_zsub1_in_ZPR_4bBits) },
  { ZPR2_with_zsub0_in_ZPR_3b, ZPR2_with_zsub0_in_ZPR_3bBits, sizeof(ZPR2_with_zsub0_in_ZPR_3bBits) },
  { ZPR2_with_zsub1_in_ZPR_3b, ZPR2_with_zsub1_in_ZPR_3bBits, sizeof(ZPR2_with_zsub1_in_ZPR_3bBits) },
  { ZPR2_with_zsub_in_FPR128_lo_and_ZPR2_with_zsub1_in_ZPR_3b, ZPR2_with_zsub_in_FPR128_lo_and_ZPR2_with_zsub1_in_ZPR_3bBits, sizeof(ZPR2_with_zsub_in_FPR128_lo_and_ZPR2_with_zsub1_in_ZPR_3bBits) },
  { QQQ, QQQBits, sizeof(QQQBits) },
  { ZPR3, ZPR3Bits, sizeof(ZPR3Bits) },
  { QQQ_with_qsub0_in_FPR128_lo, QQQ_with_qsub0_in_FPR128_loBits, sizeof(QQQ_with_qsub0_in_FPR128_loBits) },
  { QQQ_with_qsub1_in_FPR128_lo, QQQ_with_qsub1_in_FPR128_loBits, sizeof(QQQ_with_qsub1_in_FPR128_loBits) },
  { QQQ_with_qsub2_in_FPR128_lo, QQQ_with_qsub2_in_FPR128_loBits, sizeof(QQQ_with_qsub2_in_FPR128_loBits) },
  { ZPR3_with_zsub1_in_ZPR_4b, ZPR3_with_zsub1_in_ZPR_4bBits, sizeof(ZPR3_with_zsub1_in_ZPR_4bBits) },
  { ZPR3_with_zsub2_in_ZPR_4b, ZPR3_with_zsub2_in_ZPR_4bBits, sizeof(ZPR3_with_zsub2_in_ZPR_4bBits) },
  { ZPR3_with_zsub_in_FPR128_lo, ZPR3_with_zsub_in_FPR128_loBits, sizeof(ZPR3_with_zsub_in_FPR128_loBits) },
  { QQQ_with_qsub0_in_FPR128_lo_and_QQQ_with_qsub1_in_FPR128_lo, QQQ_with_qsub0_in_FPR128_lo_and_QQQ_with_qsub1_in_FPR128_loBits, sizeof(QQQ_with_qsub0_in_FPR128_lo_and_QQQ_with_qsub1_in_FPR128_loBits) },
  { QQQ_with_qsub1_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_lo, QQQ_with_qsub1_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_loBits, sizeof(QQQ_with_qsub1_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_loBits) },
  { ZPR3_with_zsub1_in_ZPR_4b_and_ZPR3_with_zsub2_in_ZPR_4b, ZPR3_with_zsub1_in_ZPR_4b_and_ZPR3_with_zsub2_in_ZPR_4bBits, sizeof(ZPR3_with_zsub1_in_ZPR_4b_and_ZPR3_with_zsub2_in_ZPR_4bBits) },
  { ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub1_in_ZPR_4b, ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub1_in_ZPR_4bBits, sizeof(ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub1_in_ZPR_4bBits) },
  { QQQ_with_qsub0_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_lo, QQQ_with_qsub0_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_loBits, sizeof(QQQ_with_qsub0_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_loBits) },
  { ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub2_in_ZPR_4b, ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub2_in_ZPR_4bBits, sizeof(ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub2_in_ZPR_4bBits) },
  { ZPR3_with_zsub0_in_ZPR_3b, ZPR3_with_zsub0_in_ZPR_3bBits, sizeof(ZPR3_with_zsub0_in_ZPR_3bBits) },
  { ZPR3_with_zsub1_in_ZPR_3b, ZPR3_with_zsub1_in_ZPR_3bBits, sizeof(ZPR3_with_zsub1_in_ZPR_3bBits) },
  { ZPR3_with_zsub2_in_ZPR_3b, ZPR3_with_zsub2_in_ZPR_3bBits, sizeof(ZPR3_with_zsub2_in_ZPR_3bBits) },
  { ZPR3_with_zsub1_in_ZPR_3b_and_ZPR3_with_zsub2_in_ZPR_3b, ZPR3_with_zsub1_in_ZPR_3b_and_ZPR3_with_zsub2_in_ZPR_3bBits, sizeof(ZPR3_with_zsub1_in_ZPR_3b_and_ZPR3_with_zsub2_in_ZPR_3bBits) },
  { ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub1_in_ZPR_3b, ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub1_in_ZPR_3bBits, sizeof(ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub1_in_ZPR_3bBits) },
  { ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub2_in_ZPR_3b, ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub2_in_ZPR_3bBits, sizeof(ZPR3_with_zsub_in_FPR128_lo_and_ZPR3_with_zsub2_in_ZPR_3bBits) },
  { QQQQ, QQQQBits, sizeof(QQQQBits) },
  { ZPR4, ZPR4Bits, sizeof(ZPR4Bits) },
  { QQQQ_with_qsub0_in_FPR128_lo, QQQQ_with_qsub0_in_FPR128_loBits, sizeof(QQQQ_with_qsub0_in_FPR128_loBits) },
  { QQQQ_with_qsub1_in_FPR128_lo, QQQQ_with_qsub1_in_FPR128_loBits, sizeof(QQQQ_with_qsub1_in_FPR128_loBits) },
  { QQQQ_with_qsub2_in_FPR128_lo, QQQQ_with_qsub2_in_FPR128_loBits, sizeof(QQQQ_with_qsub2_in_FPR128_loBits) },
  { QQQQ_with_qsub3_in_FPR128_lo, QQQQ_with_qsub3_in_FPR128_loBits, sizeof(QQQQ_with_qsub3_in_FPR128_loBits) },
  { ZPR4_with_zsub1_in_ZPR_4b, ZPR4_with_zsub1_in_ZPR_4bBits, sizeof(ZPR4_with_zsub1_in_ZPR_4bBits) },
  { ZPR4_with_zsub2_in_ZPR_4b, ZPR4_with_zsub2_in_ZPR_4bBits, sizeof(ZPR4_with_zsub2_in_ZPR_4bBits) },
  { ZPR4_with_zsub3_in_ZPR_4b, ZPR4_with_zsub3_in_ZPR_4bBits, sizeof(ZPR4_with_zsub3_in_ZPR_4bBits) },
  { ZPR4_with_zsub_in_FPR128_lo, ZPR4_with_zsub_in_FPR128_loBits, sizeof(ZPR4_with_zsub_in_FPR128_loBits) },
  { QQQQ_with_qsub0_in_FPR128_lo_and_QQQQ_with_qsub1_in_FPR128_lo, QQQQ_with_qsub0_in_FPR128_lo_and_QQQQ_with_qsub1_in_FPR128_loBits, sizeof(QQQQ_with_qsub0_in_FPR128_lo_and_QQQQ_with_qsub1_in_FPR128_loBits) },
  { QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_lo, QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_loBits, sizeof(QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_loBits) },
  { QQQQ_with_qsub2_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo, QQQQ_with_qsub2_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_loBits, sizeof(QQQQ_with_qsub2_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_loBits) },
  { ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub2_in_ZPR_4b, ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub2_in_ZPR_4bBits, sizeof(ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub2_in_ZPR_4bBits) },
  { ZPR4_with_zsub2_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4b, ZPR4_with_zsub2_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4bBits, sizeof(ZPR4_with_zsub2_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4bBits) },
  { ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub1_in_ZPR_4b, ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub1_in_ZPR_4bBits, sizeof(ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub1_in_ZPR_4bBits) },
  { QQQQ_with_qsub0_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_lo, QQQQ_with_qsub0_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_loBits, sizeof(QQQQ_with_qsub0_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_loBits) },
  { QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo, QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_loBits, sizeof(QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_loBits) },
  { ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4b, ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4bBits, sizeof(ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4bBits) },
  { ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub2_in_ZPR_4b, ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub2_in_ZPR_4bBits, sizeof(ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub2_in_ZPR_4bBits) },
  { QQQQ_with_qsub0_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo, QQQQ_with_qsub0_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_loBits, sizeof(QQQQ_with_qsub0_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_loBits) },
  { ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub3_in_ZPR_4b, ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub3_in_ZPR_4bBits, sizeof(ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub3_in_ZPR_4bBits) },
  { ZPR4_with_zsub0_in_ZPR_3b, ZPR4_with_zsub0_in_ZPR_3bBits, sizeof(ZPR4_with_zsub0_in_ZPR_3bBits) },
  { ZPR4_with_zsub1_in_ZPR_3b, ZPR4_with_zsub1_in_ZPR_3bBits, sizeof(ZPR4_with_zsub1_in_ZPR_3bBits) },
  { ZPR4_with_zsub2_in_ZPR_3b, ZPR4_with_zsub2_in_ZPR_3bBits, sizeof(ZPR4_with_zsub2_in_ZPR_3bBits) },
  { ZPR4_with_zsub3_in_ZPR_3b, ZPR4_with_zsub3_in_ZPR_3bBits, sizeof(ZPR4_with_zsub3_in_ZPR_3bBits) },
  { ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub2_in_ZPR_3b, ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub2_in_ZPR_3bBits, sizeof(ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub2_in_ZPR_3bBits) },
  { ZPR4_with_zsub2_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3b, ZPR4_with_zsub2_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3bBits, sizeof(ZPR4_with_zsub2_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3bBits) },
  { ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub1_in_ZPR_3b, ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub1_in_ZPR_3bBits, sizeof(ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub1_in_ZPR_3bBits) },
  { ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3b, ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3bBits, sizeof(ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3bBits) },
  { ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub2_in_ZPR_3b, ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub2_in_ZPR_3bBits, sizeof(ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub2_in_ZPR_3bBits) },
  { ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub3_in_ZPR_3b, ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub3_in_ZPR_3bBits, sizeof(ZPR4_with_zsub_in_FPR128_lo_and_ZPR4_with_zsub3_in_ZPR_3bBits) },
};

#endif // GET_REGINFO_MC_DESC

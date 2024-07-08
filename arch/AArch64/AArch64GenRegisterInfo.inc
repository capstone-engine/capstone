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
  AArch64_PN0 = 124,
  AArch64_PN1 = 125,
  AArch64_PN2 = 126,
  AArch64_PN3 = 127,
  AArch64_PN4 = 128,
  AArch64_PN5 = 129,
  AArch64_PN6 = 130,
  AArch64_PN7 = 131,
  AArch64_PN8 = 132,
  AArch64_PN9 = 133,
  AArch64_PN10 = 134,
  AArch64_PN11 = 135,
  AArch64_PN12 = 136,
  AArch64_PN13 = 137,
  AArch64_PN14 = 138,
  AArch64_PN15 = 139,
  AArch64_Q0 = 140,
  AArch64_Q1 = 141,
  AArch64_Q2 = 142,
  AArch64_Q3 = 143,
  AArch64_Q4 = 144,
  AArch64_Q5 = 145,
  AArch64_Q6 = 146,
  AArch64_Q7 = 147,
  AArch64_Q8 = 148,
  AArch64_Q9 = 149,
  AArch64_Q10 = 150,
  AArch64_Q11 = 151,
  AArch64_Q12 = 152,
  AArch64_Q13 = 153,
  AArch64_Q14 = 154,
  AArch64_Q15 = 155,
  AArch64_Q16 = 156,
  AArch64_Q17 = 157,
  AArch64_Q18 = 158,
  AArch64_Q19 = 159,
  AArch64_Q20 = 160,
  AArch64_Q21 = 161,
  AArch64_Q22 = 162,
  AArch64_Q23 = 163,
  AArch64_Q24 = 164,
  AArch64_Q25 = 165,
  AArch64_Q26 = 166,
  AArch64_Q27 = 167,
  AArch64_Q28 = 168,
  AArch64_Q29 = 169,
  AArch64_Q30 = 170,
  AArch64_Q31 = 171,
  AArch64_S0 = 172,
  AArch64_S1 = 173,
  AArch64_S2 = 174,
  AArch64_S3 = 175,
  AArch64_S4 = 176,
  AArch64_S5 = 177,
  AArch64_S6 = 178,
  AArch64_S7 = 179,
  AArch64_S8 = 180,
  AArch64_S9 = 181,
  AArch64_S10 = 182,
  AArch64_S11 = 183,
  AArch64_S12 = 184,
  AArch64_S13 = 185,
  AArch64_S14 = 186,
  AArch64_S15 = 187,
  AArch64_S16 = 188,
  AArch64_S17 = 189,
  AArch64_S18 = 190,
  AArch64_S19 = 191,
  AArch64_S20 = 192,
  AArch64_S21 = 193,
  AArch64_S22 = 194,
  AArch64_S23 = 195,
  AArch64_S24 = 196,
  AArch64_S25 = 197,
  AArch64_S26 = 198,
  AArch64_S27 = 199,
  AArch64_S28 = 200,
  AArch64_S29 = 201,
  AArch64_S30 = 202,
  AArch64_S31 = 203,
  AArch64_W0 = 204,
  AArch64_W1 = 205,
  AArch64_W2 = 206,
  AArch64_W3 = 207,
  AArch64_W4 = 208,
  AArch64_W5 = 209,
  AArch64_W6 = 210,
  AArch64_W7 = 211,
  AArch64_W8 = 212,
  AArch64_W9 = 213,
  AArch64_W10 = 214,
  AArch64_W11 = 215,
  AArch64_W12 = 216,
  AArch64_W13 = 217,
  AArch64_W14 = 218,
  AArch64_W15 = 219,
  AArch64_W16 = 220,
  AArch64_W17 = 221,
  AArch64_W18 = 222,
  AArch64_W19 = 223,
  AArch64_W20 = 224,
  AArch64_W21 = 225,
  AArch64_W22 = 226,
  AArch64_W23 = 227,
  AArch64_W24 = 228,
  AArch64_W25 = 229,
  AArch64_W26 = 230,
  AArch64_W27 = 231,
  AArch64_W28 = 232,
  AArch64_W29 = 233,
  AArch64_W30 = 234,
  AArch64_X0 = 235,
  AArch64_X1 = 236,
  AArch64_X2 = 237,
  AArch64_X3 = 238,
  AArch64_X4 = 239,
  AArch64_X5 = 240,
  AArch64_X6 = 241,
  AArch64_X7 = 242,
  AArch64_X8 = 243,
  AArch64_X9 = 244,
  AArch64_X10 = 245,
  AArch64_X11 = 246,
  AArch64_X12 = 247,
  AArch64_X13 = 248,
  AArch64_X14 = 249,
  AArch64_X15 = 250,
  AArch64_X16 = 251,
  AArch64_X17 = 252,
  AArch64_X18 = 253,
  AArch64_X19 = 254,
  AArch64_X20 = 255,
  AArch64_X21 = 256,
  AArch64_X22 = 257,
  AArch64_X23 = 258,
  AArch64_X24 = 259,
  AArch64_X25 = 260,
  AArch64_X26 = 261,
  AArch64_X27 = 262,
  AArch64_X28 = 263,
  AArch64_Z0 = 264,
  AArch64_Z1 = 265,
  AArch64_Z2 = 266,
  AArch64_Z3 = 267,
  AArch64_Z4 = 268,
  AArch64_Z5 = 269,
  AArch64_Z6 = 270,
  AArch64_Z7 = 271,
  AArch64_Z8 = 272,
  AArch64_Z9 = 273,
  AArch64_Z10 = 274,
  AArch64_Z11 = 275,
  AArch64_Z12 = 276,
  AArch64_Z13 = 277,
  AArch64_Z14 = 278,
  AArch64_Z15 = 279,
  AArch64_Z16 = 280,
  AArch64_Z17 = 281,
  AArch64_Z18 = 282,
  AArch64_Z19 = 283,
  AArch64_Z20 = 284,
  AArch64_Z21 = 285,
  AArch64_Z22 = 286,
  AArch64_Z23 = 287,
  AArch64_Z24 = 288,
  AArch64_Z25 = 289,
  AArch64_Z26 = 290,
  AArch64_Z27 = 291,
  AArch64_Z28 = 292,
  AArch64_Z29 = 293,
  AArch64_Z30 = 294,
  AArch64_Z31 = 295,
  AArch64_ZAB0 = 296,
  AArch64_ZAD0 = 297,
  AArch64_ZAD1 = 298,
  AArch64_ZAD2 = 299,
  AArch64_ZAD3 = 300,
  AArch64_ZAD4 = 301,
  AArch64_ZAD5 = 302,
  AArch64_ZAD6 = 303,
  AArch64_ZAD7 = 304,
  AArch64_ZAH0 = 305,
  AArch64_ZAH1 = 306,
  AArch64_ZAQ0 = 307,
  AArch64_ZAQ1 = 308,
  AArch64_ZAQ2 = 309,
  AArch64_ZAQ3 = 310,
  AArch64_ZAQ4 = 311,
  AArch64_ZAQ5 = 312,
  AArch64_ZAQ6 = 313,
  AArch64_ZAQ7 = 314,
  AArch64_ZAQ8 = 315,
  AArch64_ZAQ9 = 316,
  AArch64_ZAQ10 = 317,
  AArch64_ZAQ11 = 318,
  AArch64_ZAQ12 = 319,
  AArch64_ZAQ13 = 320,
  AArch64_ZAQ14 = 321,
  AArch64_ZAQ15 = 322,
  AArch64_ZAS0 = 323,
  AArch64_ZAS1 = 324,
  AArch64_ZAS2 = 325,
  AArch64_ZAS3 = 326,
  AArch64_ZT0 = 327,
  AArch64_D0_D1 = 328,
  AArch64_D1_D2 = 329,
  AArch64_D2_D3 = 330,
  AArch64_D3_D4 = 331,
  AArch64_D4_D5 = 332,
  AArch64_D5_D6 = 333,
  AArch64_D6_D7 = 334,
  AArch64_D7_D8 = 335,
  AArch64_D8_D9 = 336,
  AArch64_D9_D10 = 337,
  AArch64_D10_D11 = 338,
  AArch64_D11_D12 = 339,
  AArch64_D12_D13 = 340,
  AArch64_D13_D14 = 341,
  AArch64_D14_D15 = 342,
  AArch64_D15_D16 = 343,
  AArch64_D16_D17 = 344,
  AArch64_D17_D18 = 345,
  AArch64_D18_D19 = 346,
  AArch64_D19_D20 = 347,
  AArch64_D20_D21 = 348,
  AArch64_D21_D22 = 349,
  AArch64_D22_D23 = 350,
  AArch64_D23_D24 = 351,
  AArch64_D24_D25 = 352,
  AArch64_D25_D26 = 353,
  AArch64_D26_D27 = 354,
  AArch64_D27_D28 = 355,
  AArch64_D28_D29 = 356,
  AArch64_D29_D30 = 357,
  AArch64_D30_D31 = 358,
  AArch64_D31_D0 = 359,
  AArch64_D0_D1_D2_D3 = 360,
  AArch64_D1_D2_D3_D4 = 361,
  AArch64_D2_D3_D4_D5 = 362,
  AArch64_D3_D4_D5_D6 = 363,
  AArch64_D4_D5_D6_D7 = 364,
  AArch64_D5_D6_D7_D8 = 365,
  AArch64_D6_D7_D8_D9 = 366,
  AArch64_D7_D8_D9_D10 = 367,
  AArch64_D8_D9_D10_D11 = 368,
  AArch64_D9_D10_D11_D12 = 369,
  AArch64_D10_D11_D12_D13 = 370,
  AArch64_D11_D12_D13_D14 = 371,
  AArch64_D12_D13_D14_D15 = 372,
  AArch64_D13_D14_D15_D16 = 373,
  AArch64_D14_D15_D16_D17 = 374,
  AArch64_D15_D16_D17_D18 = 375,
  AArch64_D16_D17_D18_D19 = 376,
  AArch64_D17_D18_D19_D20 = 377,
  AArch64_D18_D19_D20_D21 = 378,
  AArch64_D19_D20_D21_D22 = 379,
  AArch64_D20_D21_D22_D23 = 380,
  AArch64_D21_D22_D23_D24 = 381,
  AArch64_D22_D23_D24_D25 = 382,
  AArch64_D23_D24_D25_D26 = 383,
  AArch64_D24_D25_D26_D27 = 384,
  AArch64_D25_D26_D27_D28 = 385,
  AArch64_D26_D27_D28_D29 = 386,
  AArch64_D27_D28_D29_D30 = 387,
  AArch64_D28_D29_D30_D31 = 388,
  AArch64_D29_D30_D31_D0 = 389,
  AArch64_D30_D31_D0_D1 = 390,
  AArch64_D31_D0_D1_D2 = 391,
  AArch64_D0_D1_D2 = 392,
  AArch64_D1_D2_D3 = 393,
  AArch64_D2_D3_D4 = 394,
  AArch64_D3_D4_D5 = 395,
  AArch64_D4_D5_D6 = 396,
  AArch64_D5_D6_D7 = 397,
  AArch64_D6_D7_D8 = 398,
  AArch64_D7_D8_D9 = 399,
  AArch64_D8_D9_D10 = 400,
  AArch64_D9_D10_D11 = 401,
  AArch64_D10_D11_D12 = 402,
  AArch64_D11_D12_D13 = 403,
  AArch64_D12_D13_D14 = 404,
  AArch64_D13_D14_D15 = 405,
  AArch64_D14_D15_D16 = 406,
  AArch64_D15_D16_D17 = 407,
  AArch64_D16_D17_D18 = 408,
  AArch64_D17_D18_D19 = 409,
  AArch64_D18_D19_D20 = 410,
  AArch64_D19_D20_D21 = 411,
  AArch64_D20_D21_D22 = 412,
  AArch64_D21_D22_D23 = 413,
  AArch64_D22_D23_D24 = 414,
  AArch64_D23_D24_D25 = 415,
  AArch64_D24_D25_D26 = 416,
  AArch64_D25_D26_D27 = 417,
  AArch64_D26_D27_D28 = 418,
  AArch64_D27_D28_D29 = 419,
  AArch64_D28_D29_D30 = 420,
  AArch64_D29_D30_D31 = 421,
  AArch64_D30_D31_D0 = 422,
  AArch64_D31_D0_D1 = 423,
  AArch64_P0_P1 = 424,
  AArch64_P1_P2 = 425,
  AArch64_P2_P3 = 426,
  AArch64_P3_P4 = 427,
  AArch64_P4_P5 = 428,
  AArch64_P5_P6 = 429,
  AArch64_P6_P7 = 430,
  AArch64_P7_P8 = 431,
  AArch64_P8_P9 = 432,
  AArch64_P9_P10 = 433,
  AArch64_P10_P11 = 434,
  AArch64_P11_P12 = 435,
  AArch64_P12_P13 = 436,
  AArch64_P13_P14 = 437,
  AArch64_P14_P15 = 438,
  AArch64_P15_P0 = 439,
  AArch64_Q0_Q1 = 440,
  AArch64_Q1_Q2 = 441,
  AArch64_Q2_Q3 = 442,
  AArch64_Q3_Q4 = 443,
  AArch64_Q4_Q5 = 444,
  AArch64_Q5_Q6 = 445,
  AArch64_Q6_Q7 = 446,
  AArch64_Q7_Q8 = 447,
  AArch64_Q8_Q9 = 448,
  AArch64_Q9_Q10 = 449,
  AArch64_Q10_Q11 = 450,
  AArch64_Q11_Q12 = 451,
  AArch64_Q12_Q13 = 452,
  AArch64_Q13_Q14 = 453,
  AArch64_Q14_Q15 = 454,
  AArch64_Q15_Q16 = 455,
  AArch64_Q16_Q17 = 456,
  AArch64_Q17_Q18 = 457,
  AArch64_Q18_Q19 = 458,
  AArch64_Q19_Q20 = 459,
  AArch64_Q20_Q21 = 460,
  AArch64_Q21_Q22 = 461,
  AArch64_Q22_Q23 = 462,
  AArch64_Q23_Q24 = 463,
  AArch64_Q24_Q25 = 464,
  AArch64_Q25_Q26 = 465,
  AArch64_Q26_Q27 = 466,
  AArch64_Q27_Q28 = 467,
  AArch64_Q28_Q29 = 468,
  AArch64_Q29_Q30 = 469,
  AArch64_Q30_Q31 = 470,
  AArch64_Q31_Q0 = 471,
  AArch64_Q0_Q1_Q2_Q3 = 472,
  AArch64_Q1_Q2_Q3_Q4 = 473,
  AArch64_Q2_Q3_Q4_Q5 = 474,
  AArch64_Q3_Q4_Q5_Q6 = 475,
  AArch64_Q4_Q5_Q6_Q7 = 476,
  AArch64_Q5_Q6_Q7_Q8 = 477,
  AArch64_Q6_Q7_Q8_Q9 = 478,
  AArch64_Q7_Q8_Q9_Q10 = 479,
  AArch64_Q8_Q9_Q10_Q11 = 480,
  AArch64_Q9_Q10_Q11_Q12 = 481,
  AArch64_Q10_Q11_Q12_Q13 = 482,
  AArch64_Q11_Q12_Q13_Q14 = 483,
  AArch64_Q12_Q13_Q14_Q15 = 484,
  AArch64_Q13_Q14_Q15_Q16 = 485,
  AArch64_Q14_Q15_Q16_Q17 = 486,
  AArch64_Q15_Q16_Q17_Q18 = 487,
  AArch64_Q16_Q17_Q18_Q19 = 488,
  AArch64_Q17_Q18_Q19_Q20 = 489,
  AArch64_Q18_Q19_Q20_Q21 = 490,
  AArch64_Q19_Q20_Q21_Q22 = 491,
  AArch64_Q20_Q21_Q22_Q23 = 492,
  AArch64_Q21_Q22_Q23_Q24 = 493,
  AArch64_Q22_Q23_Q24_Q25 = 494,
  AArch64_Q23_Q24_Q25_Q26 = 495,
  AArch64_Q24_Q25_Q26_Q27 = 496,
  AArch64_Q25_Q26_Q27_Q28 = 497,
  AArch64_Q26_Q27_Q28_Q29 = 498,
  AArch64_Q27_Q28_Q29_Q30 = 499,
  AArch64_Q28_Q29_Q30_Q31 = 500,
  AArch64_Q29_Q30_Q31_Q0 = 501,
  AArch64_Q30_Q31_Q0_Q1 = 502,
  AArch64_Q31_Q0_Q1_Q2 = 503,
  AArch64_Q0_Q1_Q2 = 504,
  AArch64_Q1_Q2_Q3 = 505,
  AArch64_Q2_Q3_Q4 = 506,
  AArch64_Q3_Q4_Q5 = 507,
  AArch64_Q4_Q5_Q6 = 508,
  AArch64_Q5_Q6_Q7 = 509,
  AArch64_Q6_Q7_Q8 = 510,
  AArch64_Q7_Q8_Q9 = 511,
  AArch64_Q8_Q9_Q10 = 512,
  AArch64_Q9_Q10_Q11 = 513,
  AArch64_Q10_Q11_Q12 = 514,
  AArch64_Q11_Q12_Q13 = 515,
  AArch64_Q12_Q13_Q14 = 516,
  AArch64_Q13_Q14_Q15 = 517,
  AArch64_Q14_Q15_Q16 = 518,
  AArch64_Q15_Q16_Q17 = 519,
  AArch64_Q16_Q17_Q18 = 520,
  AArch64_Q17_Q18_Q19 = 521,
  AArch64_Q18_Q19_Q20 = 522,
  AArch64_Q19_Q20_Q21 = 523,
  AArch64_Q20_Q21_Q22 = 524,
  AArch64_Q21_Q22_Q23 = 525,
  AArch64_Q22_Q23_Q24 = 526,
  AArch64_Q23_Q24_Q25 = 527,
  AArch64_Q24_Q25_Q26 = 528,
  AArch64_Q25_Q26_Q27 = 529,
  AArch64_Q26_Q27_Q28 = 530,
  AArch64_Q27_Q28_Q29 = 531,
  AArch64_Q28_Q29_Q30 = 532,
  AArch64_Q29_Q30_Q31 = 533,
  AArch64_Q30_Q31_Q0 = 534,
  AArch64_Q31_Q0_Q1 = 535,
  AArch64_X22_X23_X24_X25_X26_X27_X28_FP = 536,
  AArch64_X0_X1_X2_X3_X4_X5_X6_X7 = 537,
  AArch64_X2_X3_X4_X5_X6_X7_X8_X9 = 538,
  AArch64_X4_X5_X6_X7_X8_X9_X10_X11 = 539,
  AArch64_X6_X7_X8_X9_X10_X11_X12_X13 = 540,
  AArch64_X8_X9_X10_X11_X12_X13_X14_X15 = 541,
  AArch64_X10_X11_X12_X13_X14_X15_X16_X17 = 542,
  AArch64_X12_X13_X14_X15_X16_X17_X18_X19 = 543,
  AArch64_X14_X15_X16_X17_X18_X19_X20_X21 = 544,
  AArch64_X16_X17_X18_X19_X20_X21_X22_X23 = 545,
  AArch64_X18_X19_X20_X21_X22_X23_X24_X25 = 546,
  AArch64_X20_X21_X22_X23_X24_X25_X26_X27 = 547,
  AArch64_W30_WZR = 548,
  AArch64_W0_W1 = 549,
  AArch64_W2_W3 = 550,
  AArch64_W4_W5 = 551,
  AArch64_W6_W7 = 552,
  AArch64_W8_W9 = 553,
  AArch64_W10_W11 = 554,
  AArch64_W12_W13 = 555,
  AArch64_W14_W15 = 556,
  AArch64_W16_W17 = 557,
  AArch64_W18_W19 = 558,
  AArch64_W20_W21 = 559,
  AArch64_W22_W23 = 560,
  AArch64_W24_W25 = 561,
  AArch64_W26_W27 = 562,
  AArch64_W28_W29 = 563,
  AArch64_LR_XZR = 564,
  AArch64_X28_FP = 565,
  AArch64_X0_X1 = 566,
  AArch64_X2_X3 = 567,
  AArch64_X4_X5 = 568,
  AArch64_X6_X7 = 569,
  AArch64_X8_X9 = 570,
  AArch64_X10_X11 = 571,
  AArch64_X12_X13 = 572,
  AArch64_X14_X15 = 573,
  AArch64_X16_X17 = 574,
  AArch64_X18_X19 = 575,
  AArch64_X20_X21 = 576,
  AArch64_X22_X23 = 577,
  AArch64_X24_X25 = 578,
  AArch64_X26_X27 = 579,
  AArch64_Z0_Z1 = 580,
  AArch64_Z1_Z2 = 581,
  AArch64_Z2_Z3 = 582,
  AArch64_Z3_Z4 = 583,
  AArch64_Z4_Z5 = 584,
  AArch64_Z5_Z6 = 585,
  AArch64_Z6_Z7 = 586,
  AArch64_Z7_Z8 = 587,
  AArch64_Z8_Z9 = 588,
  AArch64_Z9_Z10 = 589,
  AArch64_Z10_Z11 = 590,
  AArch64_Z11_Z12 = 591,
  AArch64_Z12_Z13 = 592,
  AArch64_Z13_Z14 = 593,
  AArch64_Z14_Z15 = 594,
  AArch64_Z15_Z16 = 595,
  AArch64_Z16_Z17 = 596,
  AArch64_Z17_Z18 = 597,
  AArch64_Z18_Z19 = 598,
  AArch64_Z19_Z20 = 599,
  AArch64_Z20_Z21 = 600,
  AArch64_Z21_Z22 = 601,
  AArch64_Z22_Z23 = 602,
  AArch64_Z23_Z24 = 603,
  AArch64_Z24_Z25 = 604,
  AArch64_Z25_Z26 = 605,
  AArch64_Z26_Z27 = 606,
  AArch64_Z27_Z28 = 607,
  AArch64_Z28_Z29 = 608,
  AArch64_Z29_Z30 = 609,
  AArch64_Z30_Z31 = 610,
  AArch64_Z31_Z0 = 611,
  AArch64_Z0_Z1_Z2_Z3 = 612,
  AArch64_Z1_Z2_Z3_Z4 = 613,
  AArch64_Z2_Z3_Z4_Z5 = 614,
  AArch64_Z3_Z4_Z5_Z6 = 615,
  AArch64_Z4_Z5_Z6_Z7 = 616,
  AArch64_Z5_Z6_Z7_Z8 = 617,
  AArch64_Z6_Z7_Z8_Z9 = 618,
  AArch64_Z7_Z8_Z9_Z10 = 619,
  AArch64_Z8_Z9_Z10_Z11 = 620,
  AArch64_Z9_Z10_Z11_Z12 = 621,
  AArch64_Z10_Z11_Z12_Z13 = 622,
  AArch64_Z11_Z12_Z13_Z14 = 623,
  AArch64_Z12_Z13_Z14_Z15 = 624,
  AArch64_Z13_Z14_Z15_Z16 = 625,
  AArch64_Z14_Z15_Z16_Z17 = 626,
  AArch64_Z15_Z16_Z17_Z18 = 627,
  AArch64_Z16_Z17_Z18_Z19 = 628,
  AArch64_Z17_Z18_Z19_Z20 = 629,
  AArch64_Z18_Z19_Z20_Z21 = 630,
  AArch64_Z19_Z20_Z21_Z22 = 631,
  AArch64_Z20_Z21_Z22_Z23 = 632,
  AArch64_Z21_Z22_Z23_Z24 = 633,
  AArch64_Z22_Z23_Z24_Z25 = 634,
  AArch64_Z23_Z24_Z25_Z26 = 635,
  AArch64_Z24_Z25_Z26_Z27 = 636,
  AArch64_Z25_Z26_Z27_Z28 = 637,
  AArch64_Z26_Z27_Z28_Z29 = 638,
  AArch64_Z27_Z28_Z29_Z30 = 639,
  AArch64_Z28_Z29_Z30_Z31 = 640,
  AArch64_Z29_Z30_Z31_Z0 = 641,
  AArch64_Z30_Z31_Z0_Z1 = 642,
  AArch64_Z31_Z0_Z1_Z2 = 643,
  AArch64_Z0_Z1_Z2 = 644,
  AArch64_Z1_Z2_Z3 = 645,
  AArch64_Z2_Z3_Z4 = 646,
  AArch64_Z3_Z4_Z5 = 647,
  AArch64_Z4_Z5_Z6 = 648,
  AArch64_Z5_Z6_Z7 = 649,
  AArch64_Z6_Z7_Z8 = 650,
  AArch64_Z7_Z8_Z9 = 651,
  AArch64_Z8_Z9_Z10 = 652,
  AArch64_Z9_Z10_Z11 = 653,
  AArch64_Z10_Z11_Z12 = 654,
  AArch64_Z11_Z12_Z13 = 655,
  AArch64_Z12_Z13_Z14 = 656,
  AArch64_Z13_Z14_Z15 = 657,
  AArch64_Z14_Z15_Z16 = 658,
  AArch64_Z15_Z16_Z17 = 659,
  AArch64_Z16_Z17_Z18 = 660,
  AArch64_Z17_Z18_Z19 = 661,
  AArch64_Z18_Z19_Z20 = 662,
  AArch64_Z19_Z20_Z21 = 663,
  AArch64_Z20_Z21_Z22 = 664,
  AArch64_Z21_Z22_Z23 = 665,
  AArch64_Z22_Z23_Z24 = 666,
  AArch64_Z23_Z24_Z25 = 667,
  AArch64_Z24_Z25_Z26 = 668,
  AArch64_Z25_Z26_Z27 = 669,
  AArch64_Z26_Z27_Z28 = 670,
  AArch64_Z27_Z28_Z29 = 671,
  AArch64_Z28_Z29_Z30 = 672,
  AArch64_Z29_Z30_Z31 = 673,
  AArch64_Z30_Z31_Z0 = 674,
  AArch64_Z31_Z0_Z1 = 675,
  AArch64_Z16_Z24 = 676,
  AArch64_Z17_Z25 = 677,
  AArch64_Z18_Z26 = 678,
  AArch64_Z19_Z27 = 679,
  AArch64_Z20_Z28 = 680,
  AArch64_Z21_Z29 = 681,
  AArch64_Z22_Z30 = 682,
  AArch64_Z23_Z31 = 683,
  AArch64_Z0_Z8 = 684,
  AArch64_Z1_Z9 = 685,
  AArch64_Z2_Z10 = 686,
  AArch64_Z3_Z11 = 687,
  AArch64_Z4_Z12 = 688,
  AArch64_Z5_Z13 = 689,
  AArch64_Z6_Z14 = 690,
  AArch64_Z7_Z15 = 691,
  AArch64_Z16_Z20_Z24_Z28 = 692,
  AArch64_Z17_Z21_Z25_Z29 = 693,
  AArch64_Z18_Z22_Z26_Z30 = 694,
  AArch64_Z19_Z23_Z27_Z31 = 695,
  AArch64_Z0_Z4_Z8_Z12 = 696,
  AArch64_Z1_Z5_Z9_Z13 = 697,
  AArch64_Z2_Z6_Z10_Z14 = 698,
  AArch64_Z3_Z7_Z11_Z15 = 699,
  NUM_TARGET_REGS // 700
};

// Register classes

enum {
  AArch64_FPR8RegClassID = 0,
  AArch64_FPR16RegClassID = 1,
  AArch64_FPR16_loRegClassID = 2,
  AArch64_PNRRegClassID = 3,
  AArch64_PPRRegClassID = 4,
  AArch64_PNR_3bRegClassID = 5,
  AArch64_PNR_p8to15RegClassID = 6,
  AArch64_PPR_3bRegClassID = 7,
  AArch64_PPR_p8to15RegClassID = 8,
  AArch64_PPR2RegClassID = 9,
  AArch64_PPR2Mul2RegClassID = 10,
  AArch64_PPR2_with_psub1_in_PPR_3bRegClassID = 11,
  AArch64_PPR2_with_psub1_in_PPR_p8to15RegClassID = 12,
  AArch64_PPR2_with_psub_in_PNR_3bRegClassID = 13,
  AArch64_PPR2_with_psub_in_PNR_p8to15RegClassID = 14,
  AArch64_PPR2_with_psub_in_PNR_3b_and_PPR2_with_psub1_in_PPR_3bRegClassID = 15,
  AArch64_PPR2_with_psub_in_PNR_p8to15_and_PPR2_with_psub1_in_PPR_p8to15RegClassID = 16,
  AArch64_PPR2Mul2_and_PPR2_with_psub_in_PNR_3bRegClassID = 17,
  AArch64_PPR2Mul2_and_PPR2_with_psub_in_PNR_p8to15RegClassID = 18,
  AArch64_PPR2_with_psub_in_PNR_3b_and_PPR2_with_psub1_in_PPR_p8to15RegClassID = 19,
  AArch64_PPR2_with_psub_in_PNR_p8to15_and_PPR2_with_psub1_in_PPR_3bRegClassID = 20,
  AArch64_GPR32allRegClassID = 21,
  AArch64_FPR32RegClassID = 22,
  AArch64_GPR32RegClassID = 23,
  AArch64_GPR32spRegClassID = 24,
  AArch64_GPR32commonRegClassID = 25,
  AArch64_FPR32_with_hsub_in_FPR16_loRegClassID = 26,
  AArch64_GPR32argRegClassID = 27,
  AArch64_MatrixIndexGPR32_12_15RegClassID = 28,
  AArch64_MatrixIndexGPR32_8_11RegClassID = 29,
  AArch64_CCRRegClassID = 30,
  AArch64_GPR32sponlyRegClassID = 31,
  AArch64_WSeqPairsClassRegClassID = 32,
  AArch64_WSeqPairsClass_with_subo32_in_GPR32commonRegClassID = 33,
  AArch64_WSeqPairsClass_with_sube32_in_GPR32argRegClassID = 34,
  AArch64_WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_12_15RegClassID = 35,
  AArch64_WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_8_11RegClassID = 36,
  AArch64_GPR64allRegClassID = 37,
  AArch64_FPR64RegClassID = 38,
  AArch64_GPR64RegClassID = 39,
  AArch64_GPR64spRegClassID = 40,
  AArch64_GPR64commonRegClassID = 41,
  AArch64_GPR64noipRegClassID = 42,
  AArch64_GPR64common_and_GPR64noipRegClassID = 43,
  AArch64_tcGPR64RegClassID = 44,
  AArch64_GPR64noip_and_tcGPR64RegClassID = 45,
  AArch64_FPR64_loRegClassID = 46,
  AArch64_GPR64argRegClassID = 47,
  AArch64_FIXED_REGSRegClassID = 48,
  AArch64_GPR64_with_sub_32_in_MatrixIndexGPR32_12_15RegClassID = 49,
  AArch64_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11RegClassID = 50,
  AArch64_FIXED_REGS_with_sub_32RegClassID = 51,
  AArch64_rtcGPR64RegClassID = 52,
  AArch64_FIXED_REGS_and_GPR64RegClassID = 53,
  AArch64_GPR64sponlyRegClassID = 54,
  AArch64_DDRegClassID = 55,
  AArch64_DD_with_dsub0_in_FPR64_loRegClassID = 56,
  AArch64_DD_with_dsub1_in_FPR64_loRegClassID = 57,
  AArch64_XSeqPairsClassRegClassID = 58,
  AArch64_DD_with_dsub0_in_FPR64_lo_and_DD_with_dsub1_in_FPR64_loRegClassID = 59,
  AArch64_XSeqPairsClass_with_subo64_in_GPR64commonRegClassID = 60,
  AArch64_XSeqPairsClass_with_subo64_in_GPR64noipRegClassID = 61,
  AArch64_XSeqPairsClass_with_sube64_in_GPR64noipRegClassID = 62,
  AArch64_XSeqPairsClass_with_sube64_in_tcGPR64RegClassID = 63,
  AArch64_XSeqPairsClass_with_sube64_in_GPR64noip_and_tcGPR64RegClassID = 64,
  AArch64_XSeqPairsClass_with_subo64_in_tcGPR64RegClassID = 65,
  AArch64_XSeqPairsClass_with_subo64_in_GPR64noip_and_tcGPR64RegClassID = 66,
  AArch64_XSeqPairsClass_with_sub_32_in_GPR32argRegClassID = 67,
  AArch64_XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_12_15RegClassID = 68,
  AArch64_XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_8_11RegClassID = 69,
  AArch64_XSeqPairsClass_with_sube64_in_rtcGPR64RegClassID = 70,
  AArch64_XSeqPairsClass_with_subo64_in_FIXED_REGSRegClassID = 71,
  AArch64_FPR128RegClassID = 72,
  AArch64_ZPRRegClassID = 73,
  AArch64_FPR128_loRegClassID = 74,
  AArch64_MPR128RegClassID = 75,
  AArch64_ZPR_4bRegClassID = 76,
  AArch64_FPR128_0to7RegClassID = 77,
  AArch64_ZPR_3bRegClassID = 78,
  AArch64_DDDRegClassID = 79,
  AArch64_DDD_with_dsub0_in_FPR64_loRegClassID = 80,
  AArch64_DDD_with_dsub1_in_FPR64_loRegClassID = 81,
  AArch64_DDD_with_dsub2_in_FPR64_loRegClassID = 82,
  AArch64_DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub1_in_FPR64_loRegClassID = 83,
  AArch64_DDD_with_dsub1_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_loRegClassID = 84,
  AArch64_DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_loRegClassID = 85,
  AArch64_DDDDRegClassID = 86,
  AArch64_DDDD_with_dsub0_in_FPR64_loRegClassID = 87,
  AArch64_DDDD_with_dsub1_in_FPR64_loRegClassID = 88,
  AArch64_DDDD_with_dsub2_in_FPR64_loRegClassID = 89,
  AArch64_DDDD_with_dsub3_in_FPR64_loRegClassID = 90,
  AArch64_DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub1_in_FPR64_loRegClassID = 91,
  AArch64_DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_loRegClassID = 92,
  AArch64_DDDD_with_dsub2_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_loRegClassID = 93,
  AArch64_DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_loRegClassID = 94,
  AArch64_DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_loRegClassID = 95,
  AArch64_DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_loRegClassID = 96,
  AArch64_QQRegClassID = 97,
  AArch64_ZPR2RegClassID = 98,
  AArch64_ZPR2StridedOrContiguousRegClassID = 99,
  AArch64_QQ_with_dsub_in_FPR64_loRegClassID = 100,
  AArch64_QQ_with_qsub1_in_FPR128_loRegClassID = 101,
  AArch64_ZPR2Mul2RegClassID = 102,
  AArch64_ZPR2StridedRegClassID = 103,
  AArch64_ZPR2StridedOrContiguous_with_dsub_in_FPR64_loRegClassID = 104,
  AArch64_ZPR2_with_dsub_in_FPR64_loRegClassID = 105,
  AArch64_ZPR2_with_zsub1_in_ZPR_4bRegClassID = 106,
  AArch64_QQ_with_dsub_in_FPR64_lo_and_QQ_with_qsub1_in_FPR128_loRegClassID = 107,
  AArch64_ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_4bRegClassID = 108,
  AArch64_ZPR2StridedOrContiguous_with_zsub_in_FPR128_0to7RegClassID = 109,
  AArch64_QQ_with_qsub0_in_FPR128_0to7RegClassID = 110,
  AArch64_QQ_with_qsub1_in_FPR128_0to7RegClassID = 111,
  AArch64_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loRegClassID = 112,
  AArch64_ZPR2Strided_with_dsub_in_FPR64_loRegClassID = 113,
  AArch64_ZPR2_with_zsub1_in_ZPR_3bRegClassID = 114,
  AArch64_ZPR2_with_zsub_in_FPR128_0to7RegClassID = 115,
  AArch64_QQ_with_dsub_in_FPR64_lo_and_QQ_with_qsub1_in_FPR128_0to7RegClassID = 116,
  AArch64_ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_3bRegClassID = 117,
  AArch64_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7RegClassID = 118,
  AArch64_MPR64RegClassID = 119,
  AArch64_QQQRegClassID = 120,
  AArch64_ZPR3RegClassID = 121,
  AArch64_QQQ_with_dsub_in_FPR64_loRegClassID = 122,
  AArch64_QQQ_with_qsub1_in_FPR128_loRegClassID = 123,
  AArch64_QQQ_with_qsub2_in_FPR128_loRegClassID = 124,
  AArch64_ZPR3_with_dsub_in_FPR64_loRegClassID = 125,
  AArch64_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2RegClassID = 126,
  AArch64_ZPR3_with_zsub1_in_ZPR_4bRegClassID = 127,
  AArch64_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2RegClassID = 128,
  AArch64_ZPR3_with_zsub2_in_ZPR_4bRegClassID = 129,
  AArch64_QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub1_in_FPR128_loRegClassID = 130,
  AArch64_QQQ_with_qsub1_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_loRegClassID = 131,
  AArch64_ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_4bRegClassID = 132,
  AArch64_ZPR3_with_zsub1_in_ZPR_4b_and_ZPR3_with_zsub2_in_ZPR_4bRegClassID = 133,
  AArch64_QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub2_in_FPR128_loRegClassID = 134,
  AArch64_ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_4bRegClassID = 135,
  AArch64_QQQ_with_qsub0_in_FPR128_0to7RegClassID = 136,
  AArch64_QQQ_with_qsub1_in_FPR128_0to7RegClassID = 137,
  AArch64_QQQ_with_qsub2_in_FPR128_0to7RegClassID = 138,
  AArch64_ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2RegClassID = 139,
  AArch64_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loRegClassID = 140,
  AArch64_ZPR3_with_zsub1_in_ZPR_3bRegClassID = 141,
  AArch64_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loRegClassID = 142,
  AArch64_ZPR3_with_zsub2_in_ZPR_3bRegClassID = 143,
  AArch64_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2RegClassID = 144,
  AArch64_ZPR3_with_zsub_in_FPR128_0to7RegClassID = 145,
  AArch64_QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub1_in_FPR128_0to7RegClassID = 146,
  AArch64_QQQ_with_qsub1_in_FPR128_0to7_and_QQQ_with_qsub2_in_FPR128_0to7RegClassID = 147,
  AArch64_ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_3bRegClassID = 148,
  AArch64_ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loRegClassID = 149,
  AArch64_ZPR3_with_zsub1_in_ZPR_3b_and_ZPR3_with_zsub2_in_ZPR_3bRegClassID = 150,
  AArch64_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loRegClassID = 151,
  AArch64_QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub2_in_FPR128_0to7RegClassID = 152,
  AArch64_ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_3bRegClassID = 153,
  AArch64_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7RegClassID = 154,
  AArch64_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7RegClassID = 155,
  AArch64_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2RegClassID = 156,
  AArch64_ZPR3_with_zsub_in_FPR128_0to7_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2RegClassID = 157,
  AArch64_ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7RegClassID = 158,
  AArch64_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loRegClassID = 159,
  AArch64_QQQQRegClassID = 160,
  AArch64_ZPR4RegClassID = 161,
  AArch64_QQQQ_with_dsub_in_FPR64_loRegClassID = 162,
  AArch64_QQQQ_with_qsub1_in_FPR128_loRegClassID = 163,
  AArch64_QQQQ_with_qsub2_in_FPR128_loRegClassID = 164,
  AArch64_QQQQ_with_qsub3_in_FPR128_loRegClassID = 165,
  AArch64_ZPR4StridedOrContiguousRegClassID = 166,
  AArch64_ZPR4_with_dsub_in_FPR64_loRegClassID = 167,
  AArch64_ZPR4_with_zsub0_zsub1_in_ZPR2Mul2RegClassID = 168,
  AArch64_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2RegClassID = 169,
  AArch64_ZPR4_with_zsub1_in_ZPR_4bRegClassID = 170,
  AArch64_ZPR4_with_zsub2_in_ZPR_4bRegClassID = 171,
  AArch64_ZPR4_with_zsub3_in_ZPR_4bRegClassID = 172,
  AArch64_QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub1_in_FPR128_loRegClassID = 173,
  AArch64_QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_loRegClassID = 174,
  AArch64_QQQQ_with_qsub2_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_loRegClassID = 175,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_4bRegClassID = 176,
  AArch64_ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub2_in_ZPR_4bRegClassID = 177,
  AArch64_ZPR4_with_zsub2_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4bRegClassID = 178,
  AArch64_QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub2_in_FPR128_loRegClassID = 179,
  AArch64_QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_loRegClassID = 180,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_4bRegClassID = 181,
  AArch64_ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4bRegClassID = 182,
  AArch64_QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub3_in_FPR128_loRegClassID = 183,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_4bRegClassID = 184,
  AArch64_QQQQ_with_qsub0_in_FPR128_0to7RegClassID = 185,
  AArch64_QQQQ_with_qsub1_in_FPR128_0to7RegClassID = 186,
  AArch64_QQQQ_with_qsub2_in_FPR128_0to7RegClassID = 187,
  AArch64_QQQQ_with_qsub3_in_FPR128_0to7RegClassID = 188,
  AArch64_ZPR4Mul4RegClassID = 189,
  AArch64_ZPR4StridedRegClassID = 190,
  AArch64_ZPR4StridedOrContiguous_with_dsub_in_FPR64_loRegClassID = 191,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2RegClassID = 192,
  AArch64_ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loRegClassID = 193,
  AArch64_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loRegClassID = 194,
  AArch64_ZPR4_with_zsub1_in_ZPR_3bRegClassID = 195,
  AArch64_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loRegClassID = 196,
  AArch64_ZPR4_with_zsub2_in_ZPR_3bRegClassID = 197,
  AArch64_ZPR4_with_zsub3_in_ZPR_3bRegClassID = 198,
  AArch64_ZPR4_with_zsub3_in_ZPR_4b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2RegClassID = 199,
  AArch64_ZPR4_with_zsub_in_FPR128_0to7RegClassID = 200,
  AArch64_QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub1_in_FPR128_0to7RegClassID = 201,
  AArch64_QQQQ_with_qsub1_in_FPR128_0to7_and_QQQQ_with_qsub2_in_FPR128_0to7RegClassID = 202,
  AArch64_QQQQ_with_qsub2_in_FPR128_0to7_and_QQQQ_with_qsub3_in_FPR128_0to7RegClassID = 203,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loRegClassID = 204,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_3bRegClassID = 205,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loRegClassID = 206,
  AArch64_ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub2_in_ZPR_3bRegClassID = 207,
  AArch64_ZPR4_with_zsub1_in_ZPR_4b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2RegClassID = 208,
  AArch64_ZPR4_with_zsub2_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3bRegClassID = 209,
  AArch64_QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub2_in_FPR128_0to7RegClassID = 210,
  AArch64_QQQQ_with_qsub1_in_FPR128_0to7_and_QQQQ_with_qsub3_in_FPR128_0to7RegClassID = 211,
  AArch64_ZPR4StridedOrContiguous_with_zsub_in_FPR128_0to7RegClassID = 212,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_3bRegClassID = 213,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2RegClassID = 214,
  AArch64_ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3bRegClassID = 215,
  AArch64_QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub3_in_FPR128_0to7RegClassID = 216,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_3bRegClassID = 217,
  AArch64_ZPR4Mul4_and_ZPR4_with_dsub_in_FPR64_loRegClassID = 218,
  AArch64_ZPR4Strided_with_dsub_in_FPR64_loRegClassID = 219,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub_in_FPR128_0to7_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2RegClassID = 220,
  AArch64_ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7RegClassID = 221,
  AArch64_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7RegClassID = 222,
  AArch64_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7RegClassID = 223,
  AArch64_ZPR4_with_zsub3_in_ZPR_3b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2RegClassID = 224,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7RegClassID = 225,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7RegClassID = 226,
  AArch64_ZPR4_with_zsub1_in_ZPR_3b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2RegClassID = 227,
  AArch64_ZPR4Mul4_and_ZPR4_with_zsub_in_FPR128_0to7RegClassID = 228,
  AArch64_ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2RegClassID = 229,
  AArch64_GPR64x8ClassRegClassID = 230,
  AArch64_GPR64x8Class_with_x8sub_0_in_GPR64noipRegClassID = 231,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64noipRegClassID = 232,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noipRegClassID = 233,
  AArch64_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 234,
  AArch64_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noipRegClassID = 235,
  AArch64_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipRegClassID = 236,
  AArch64_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 237,
  AArch64_GPR64x8Class_with_x8sub_0_in_tcGPR64RegClassID = 238,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipRegClassID = 239,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 240,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 241,
  AArch64_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_tcGPR64RegClassID = 242,
  AArch64_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_2_in_GPR64noipRegClassID = 243,
  AArch64_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noipRegClassID = 244,
  AArch64_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 245,
  AArch64_GPR64x8Class_with_x8sub_1_in_tcGPR64RegClassID = 246,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipRegClassID = 247,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 248,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 249,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 250,
  AArch64_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noipRegClassID = 251,
  AArch64_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipRegClassID = 252,
  AArch64_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 253,
  AArch64_GPR64x8Class_with_x8sub_1_in_GPR64noip_and_tcGPR64RegClassID = 254,
  AArch64_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noipRegClassID = 255,
  AArch64_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 256,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noipRegClassID = 257,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 258,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_tcGPR64RegClassID = 259,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 260,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 261,
  AArch64_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 262,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipRegClassID = 263,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 264,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noipRegClassID = 265,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 266,
  AArch64_GPR64x8Class_with_x8sub_3_in_GPR64noip_and_tcGPR64RegClassID = 267,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 268,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 269,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 270,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noip_and_tcGPR64RegClassID = 271,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 272,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 273,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipRegClassID = 274,
  AArch64_GPR64x8Class_with_x8sub_5_in_GPR64noip_and_tcGPR64RegClassID = 275,
  AArch64_GPR64x8Class_with_x8sub_6_in_GPR64noip_and_tcGPR64RegClassID = 276,
  AArch64_GPR64x8Class_with_x8sub_7_in_GPR64noip_and_tcGPR64RegClassID = 277,
  AArch64_GPR64x8Class_with_sub_32_in_GPR32argRegClassID = 278,
  AArch64_MPR32RegClassID = 279,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64argRegClassID = 280,
  AArch64_GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_12_15RegClassID = 281,
  AArch64_GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11RegClassID = 282,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_12_15RegClassID = 283,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11RegClassID = 284,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11RegClassID = 285,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64argRegClassID = 286,
  AArch64_GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11RegClassID = 287,
  AArch64_GPR64x8Class_with_sub_32_in_GPR32arg_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11RegClassID = 288,
  AArch64_GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11RegClassID = 289,
  AArch64_GPR64x8Class_with_x8sub_0_in_rtcGPR64RegClassID = 290,
  AArch64_GPR64x8Class_with_x8sub_2_in_GPR64arg_and_GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11RegClassID = 291,
  AArch64_GPR64x8Class_with_x8sub_2_in_rtcGPR64RegClassID = 292,
  AArch64_GPR64x8Class_with_x8sub_4_in_GPR64arg_and_GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11RegClassID = 293,
  AArch64_GPR64x8Class_with_x8sub_4_in_rtcGPR64RegClassID = 294,
  AArch64_GPR64x8Class_with_x8sub_6_in_GPR64argRegClassID = 295,
  AArch64_GPR64x8Class_with_x8sub_6_in_rtcGPR64RegClassID = 296,
  AArch64_GPR64x8Class_with_x8sub_7_in_FIXED_REGSRegClassID = 297,
  AArch64_ZTRRegClassID = 298,
  AArch64_MPR16RegClassID = 299,
  AArch64_MPRRegClassID = 300,
  AArch64_MPR8RegClassID = 301,

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
  AArch64_psub,	// 8
  AArch64_psub0,	// 9
  AArch64_psub1,	// 10
  AArch64_qsub0,	// 11
  AArch64_qsub1,	// 12
  AArch64_qsub2,	// 13
  AArch64_qsub3,	// 14
  AArch64_ssub,	// 15
  AArch64_sub_32,	// 16
  AArch64_sube32,	// 17
  AArch64_sube64,	// 18
  AArch64_subo32,	// 19
  AArch64_subo64,	// 20
  AArch64_x8sub_0,	// 21
  AArch64_x8sub_1,	// 22
  AArch64_x8sub_2,	// 23
  AArch64_x8sub_3,	// 24
  AArch64_x8sub_4,	// 25
  AArch64_x8sub_5,	// 26
  AArch64_x8sub_6,	// 27
  AArch64_x8sub_7,	// 28
  AArch64_zasubb,	// 29
  AArch64_zasubd0,	// 30
  AArch64_zasubd1,	// 31
  AArch64_zasubh0,	// 32
  AArch64_zasubh1,	// 33
  AArch64_zasubq0,	// 34
  AArch64_zasubq1,	// 35
  AArch64_zasubs0,	// 36
  AArch64_zasubs1,	// 37
  AArch64_zsub,	// 38
  AArch64_zsub0,	// 39
  AArch64_zsub1,	// 40
  AArch64_zsub2,	// 41
  AArch64_zsub3,	// 42
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
  AArch64_psub1_then_psub,	// 74
  AArch64_qsub1_then_bsub,	// 75
  AArch64_qsub1_then_dsub,	// 76
  AArch64_qsub1_then_hsub,	// 77
  AArch64_qsub1_then_ssub,	// 78
  AArch64_qsub3_then_bsub,	// 79
  AArch64_qsub3_then_dsub,	// 80
  AArch64_qsub3_then_hsub,	// 81
  AArch64_qsub3_then_ssub,	// 82
  AArch64_qsub2_then_bsub,	// 83
  AArch64_qsub2_then_dsub,	// 84
  AArch64_qsub2_then_hsub,	// 85
  AArch64_qsub2_then_ssub,	// 86
  AArch64_x8sub_7_then_sub_32,	// 87
  AArch64_x8sub_6_then_sub_32,	// 88
  AArch64_x8sub_5_then_sub_32,	// 89
  AArch64_x8sub_4_then_sub_32,	// 90
  AArch64_x8sub_3_then_sub_32,	// 91
  AArch64_x8sub_2_then_sub_32,	// 92
  AArch64_x8sub_1_then_sub_32,	// 93
  AArch64_subo64_then_sub_32,	// 94
  AArch64_zsub1_then_bsub,	// 95
  AArch64_zsub1_then_dsub,	// 96
  AArch64_zsub1_then_hsub,	// 97
  AArch64_zsub1_then_ssub,	// 98
  AArch64_zsub1_then_zsub,	// 99
  AArch64_zsub3_then_bsub,	// 100
  AArch64_zsub3_then_dsub,	// 101
  AArch64_zsub3_then_hsub,	// 102
  AArch64_zsub3_then_ssub,	// 103
  AArch64_zsub3_then_zsub,	// 104
  AArch64_zsub2_then_bsub,	// 105
  AArch64_zsub2_then_dsub,	// 106
  AArch64_zsub2_then_hsub,	// 107
  AArch64_zsub2_then_ssub,	// 108
  AArch64_zsub2_then_zsub,	// 109
  AArch64_dsub0_dsub1,	// 110
  AArch64_dsub0_dsub1_dsub2,	// 111
  AArch64_dsub1_dsub2,	// 112
  AArch64_dsub1_dsub2_dsub3,	// 113
  AArch64_dsub2_dsub3,	// 114
  AArch64_dsub_qsub1_then_dsub,	// 115
  AArch64_dsub_qsub1_then_dsub_qsub2_then_dsub_qsub3_then_dsub,	// 116
  AArch64_dsub_qsub1_then_dsub_qsub2_then_dsub,	// 117
  AArch64_qsub0_qsub1,	// 118
  AArch64_qsub0_qsub1_qsub2,	// 119
  AArch64_qsub1_qsub2,	// 120
  AArch64_qsub1_qsub2_qsub3,	// 121
  AArch64_qsub2_qsub3,	// 122
  AArch64_qsub1_then_dsub_qsub2_then_dsub,	// 123
  AArch64_qsub1_then_dsub_qsub2_then_dsub_qsub3_then_dsub,	// 124
  AArch64_qsub2_then_dsub_qsub3_then_dsub,	// 125
  AArch64_sub_32_x8sub_1_then_sub_32,	// 126
  AArch64_x8sub_0_x8sub_1,	// 127
  AArch64_x8sub_2_x8sub_3,	// 128
  AArch64_x8sub_4_x8sub_5,	// 129
  AArch64_x8sub_6_x8sub_7,	// 130
  AArch64_x8sub_6_then_sub_32_x8sub_7_then_sub_32,	// 131
  AArch64_x8sub_4_then_sub_32_x8sub_5_then_sub_32,	// 132
  AArch64_x8sub_2_then_sub_32_x8sub_3_then_sub_32,	// 133
  AArch64_sub_32_subo64_then_sub_32,	// 134
  AArch64_dsub_zsub1_then_dsub,	// 135
  AArch64_zsub_zsub1_then_zsub,	// 136
  AArch64_dsub_zsub1_then_dsub_zsub2_then_dsub_zsub3_then_dsub,	// 137
  AArch64_dsub_zsub1_then_dsub_zsub2_then_dsub,	// 138
  AArch64_zsub_zsub1_then_zsub_zsub2_then_zsub_zsub3_then_zsub,	// 139
  AArch64_zsub_zsub1_then_zsub_zsub2_then_zsub,	// 140
  AArch64_zsub0_zsub1,	// 141
  AArch64_zsub0_zsub1_zsub2,	// 142
  AArch64_zsub1_zsub2,	// 143
  AArch64_zsub1_zsub2_zsub3,	// 144
  AArch64_zsub2_zsub3,	// 145
  AArch64_zsub1_then_dsub_zsub2_then_dsub,	// 146
  AArch64_zsub1_then_dsub_zsub2_then_dsub_zsub3_then_dsub,	// 147
  AArch64_zsub1_then_zsub_zsub2_then_zsub,	// 148
  AArch64_zsub1_then_zsub_zsub2_then_zsub_zsub3_then_zsub,	// 149
  AArch64_zsub2_then_dsub_zsub3_then_dsub,	// 150
  AArch64_zsub2_then_zsub_zsub3_then_zsub,	// 151
  AArch64_zsub0_zsub2,	// 152
  AArch64_zsub1_zsub3,	// 153
  AArch64_NUM_TARGET_SUBREGS
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

static const MCPhysReg AArch64RegDiffLists[] = {
  /* 0 */ -18, 22, -20, -10, -285, 0,
  /* 6 */ -10, 22, -20, -10, -285, 0,
  /* 12 */ -18, 26, -20, -10, -285, 0,
  /* 18 */ -10, 26, -20, -10, -285, 0,
  /* 24 */ -18, 22, -18, -10, -285, 0,
  /* 30 */ -10, 22, -18, -10, -285, 0,
  /* 36 */ -18, 26, -18, -10, -285, 0,
  /* 42 */ -10, 26, -18, -10, -285, 0,
  /* 48 */ -18, 22, -20, -9, -285, 0,
  /* 54 */ -10, 22, -20, -9, -285, 0,
  /* 60 */ -18, 26, -20, -9, -285, 0,
  /* 66 */ -10, 26, -20, -9, -285, 0,
  /* 72 */ -18, 22, -18, -9, -285, 0,
  /* 78 */ -10, 22, -18, -9, -285, 0,
  /* 84 */ -18, 26, -18, -9, -285, 0,
  /* 90 */ -10, 26, -18, -9, -285, 0,
  /* 96 */ -314, -225, 0,
  /* 99 */ -364, -96, 128, -96, -64, 97, -96, 128, -96, -64, 129, -96, 128, -96, -64, 346, 64, 48, -31, -112, 0,
  /* 120 */ -364, -96, 128, -96, -64, 129, -96, 128, -96, -64, 129, -96, 128, -96, -64, 314, 64, 48, 1, -112, 0,
  /* 141 */ -364, -96, 128, -96, -64, 129, -96, 128, -96, -64, 97, -96, 128, -96, -64, 346, 64, 48, 1, -112, 0,
  /* 162 */ -332, -96, 128, -96, -64, 129, -96, 128, -96, -64, 97, -96, 128, -96, -64, 129, -96, 128, -96, -64, 345, 32, 32, 48, 64, -63, 64, -95, -81, 64, -95, 0,
  /* 194 */ -316, 128, -96, -64, 33, 128, -96, -64, 1, 128, -96, -64, 33, 128, -96, -64, 345, 64, -63, 64, -95, 0,
  /* 216 */ -420, -124, -96, 128, -96, -64, 260, -124, -96, 128, -96, -64, 0,
  /* 229 */ -396, -124, -96, 128, -96, -64, 260, -124, -96, 128, -96, -64, 0,
  /* 242 */ -284, 128, -96, -64, 1, 128, -96, -64, 0,
  /* 251 */ -284, 128, -96, -64, 33, 128, -96, -64, 0,
  /* 260 */ -332, -96, 128, -96, -64, 97, -96, 128, -96, -64, 129, -96, 128, -96, -64, 129, -96, 128, -96, -64, 345, 32, 32, 48, 64, -95, 64, -63, -113, 64, -63, 0,
  /* 292 */ -332, -96, 128, -96, -64, 129, -96, 128, -96, -64, 129, -96, 128, -96, -64, 129, -96, 128, -96, -64, 313, 32, 32, 48, 64, -63, 64, -63, -113, 64, -63, 0,
  /* 324 */ -332, -96, 128, -96, -64, 129, -96, 128, -96, -64, 129, -96, 128, -96, -64, 97, -96, 128, -96, -64, 345, 32, 32, 48, 64, -63, 64, -63, -113, 64, -63, 0,
  /* 356 */ -316, 128, -96, -64, 1, 128, -96, -64, 33, 128, -96, -64, 33, 128, -96, -64, 345, 64, -95, 64, -63, 0,
  /* 378 */ -316, 128, -96, -64, 33, 128, -96, -64, 33, 128, -96, -64, 33, 128, -96, -64, 313, 64, -63, 64, -63, 0,
  /* 400 */ -316, 128, -96, -64, 33, 128, -96, -64, 33, 128, -96, -64, 1, 128, -96, -64, 345, 64, -63, 64, -63, 0,
  /* 422 */ -348, 128, -96, -64, 1, 128, -96, -64, 33, 128, -96, -64, 346, -31, 0,
  /* 437 */ 31, 300, 2, -29, 0,
  /* 442 */ -231, 561, 2, -29, 0,
  /* 447 */ 31, 313, 17, -29, 0,
  /* 452 */ 31, 314, 17, -29, 0,
  /* 457 */ 302, -29, 0,
  /* 460 */ 330, -29, 0,
  /* 463 */ 331, -29, 0,
  /* 466 */ 563, -29, 0,
  /* 469 */ -2, 0,
  /* 471 */ -292, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 328, 17, 1, 1, 1, -17, -1, -1, 0,
  /* 496 */ -293, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 329, 17, 1, 1, 1, -17, -1, -1, 0,
  /* 521 */ -294, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 330, 17, 1, 1, 1, -17, -1, -1, 0,
  /* 546 */ -295, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 331, 17, 1, 1, 1, -17, -1, -1, 0,
  /* 571 */ -296, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 332, 17, 1, 1, 1, -17, -1, -1, 0,
  /* 596 */ -297, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 333, 17, 1, 1, 1, -17, -1, -1, 0,
  /* 621 */ -298, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 334, 17, 1, 1, 1, -17, -1, -1, 0,
  /* 646 */ -299, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 335, 17, 1, 1, 1, -17, -1, -1, 0,
  /* 671 */ -300, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 336, 17, 1, 1, 1, -17, -1, -1, 0,
  /* 696 */ -301, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 337, 17, 1, 1, 1, -17, -1, -1, 0,
  /* 721 */ -302, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 338, 17, 1, 1, 1, -17, -1, -1, 0,
  /* 746 */ -279, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, 32, -31, -230, 231, 327, 17, 1, 1, -14, -2, -1, -1, 0,
  /* 771 */ -345, 1, 0,
  /* 774 */ -344, 1, 0,
  /* 777 */ -343, 1, 0,
  /* 780 */ -342, 1, 0,
  /* 783 */ -341, 1, 0,
  /* 786 */ -340, 1, 0,
  /* 789 */ -339, 1, 0,
  /* 792 */ -338, 1, 0,
  /* 795 */ -337, 1, 0,
  /* 798 */ -336, 1, 0,
  /* 801 */ -335, 1, 0,
  /* 804 */ -334, 1, 0,
  /* 807 */ -333, 1, 0,
  /* 810 */ -332, 1, 0,
  /* 813 */ -331, 1, 0,
  /* 816 */ 63, -33, 34, -33, 1, 80, 63, -33, 34, -33, 1, 108, 63, -33, 34, -33, 1, 0,
  /* 834 */ 64, -32, 63, -33, 1, 49, 64, -32, 63, -33, 1, 77, 64, -32, 63, -33, 1, 0,
  /* 852 */ -33, 1, 144, -33, 1, 172, -33, 1, 0,
  /* 861 */ 31, 312, 17, -30, 1, 0,
  /* 867 */ 31, 313, 17, -30, 1, 0,
  /* 873 */ 329, -30, 1, 0,
  /* 877 */ 330, -30, 1, 0,
  /* 881 */ 31, 311, 17, -31, 1, 1, 0,
  /* 888 */ 31, 312, 17, -31, 1, 1, 0,
  /* 895 */ 328, -31, 1, 1, 0,
  /* 900 */ 329, -31, 1, 1, 0,
  /* 905 */ 31, 303, 17, -32, 1, 1, 1, 0,
  /* 913 */ 31, 304, 17, -32, 1, 1, 1, 0,
  /* 921 */ 31, 305, 17, -32, 1, 1, 1, 0,
  /* 929 */ 31, 306, 17, -32, 1, 1, 1, 0,
  /* 937 */ 31, 307, 17, -32, 1, 1, 1, 0,
  /* 945 */ 31, 308, 17, -32, 1, 1, 1, 0,
  /* 953 */ 31, 309, 17, -32, 1, 1, 1, 0,
  /* 961 */ 31, 310, 17, -32, 1, 1, 1, 0,
  /* 969 */ 31, 311, 17, -32, 1, 1, 1, 0,
  /* 977 */ 320, -32, 1, 1, 1, 0,
  /* 983 */ 321, -32, 1, 1, 1, 0,
  /* 989 */ 322, -32, 1, 1, 1, 0,
  /* 995 */ 323, -32, 1, 1, 1, 0,
  /* 1001 */ 324, -32, 1, 1, 1, 0,
  /* 1007 */ 325, -32, 1, 1, 1, 0,
  /* 1013 */ 326, -32, 1, 1, 1, 0,
  /* 1019 */ 327, -32, 1, 1, 1, 0,
  /* 1025 */ 328, -32, 1, 1, 1, 0,
  /* 1031 */ 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
  /* 1047 */ 93, 1, 1, 1, 1, 1, 1, 0,
  /* 1055 */ 31, 302, 17, -41, 9, 1, 1, 0,
  /* 1063 */ 31, 303, 17, -41, 9, 1, 1, 0,
  /* 1071 */ 319, -41, 9, 1, 1, 0,
  /* 1077 */ 320, -41, 9, 1, 1, 0,
  /* 1083 */ 29, 1, 1, 0,
  /* 1087 */ 31, 301, 17, -42, 10, 1, 0,
  /* 1094 */ 31, 302, 17, -42, 10, 1, 0,
  /* 1101 */ 318, -42, 10, 1, 0,
  /* 1106 */ 319, -42, 10, 1, 0,
  /* 1111 */ 1, 29, 1, 0,
  /* 1115 */ 30, 1, 0,
  /* 1118 */ -348, 128, -96, -64, 33, 128, -96, -64, 33, 128, -96, -64, 314, 1, 0,
  /* 1133 */ -16, 315, 1, 0,
  /* 1137 */ -348, 128, -96, -64, 33, 128, -96, -64, 1, 128, -96, -64, 346, 1, 0,
  /* 1152 */ 2, 0,
  /* 1154 */ 4, 4, 4, 0,
  /* 1158 */ -412, -124, -96, 128, -96, -64, 256, -124, -96, 128, -96, -64, 256, -124, -96, 128, -96, -64, 256, -124, -96, 128, -96, -64, 636, 4, 0,
  /* 1185 */ -432, -124, -96, 128, -96, -64, 256, -124, -96, 128, -96, -64, 256, -124, -96, 128, -96, -64, 256, -124, -96, 128, -96, -64, 660, 4, 0,
  /* 1212 */ 285, 9, 18, -26, 10, 8, -14, 10, 8, 6, -26, 10, 8, -14, 10, 8, -15, 18, -26, 10, 8, -14, 10, 8, 6, -26, 10, 8, -14, 10, 8, 0,
  /* 1244 */ 64, 96, -128, 96, 124, 63, 1, 62, -33, 34, -33, 34, -33, 1, 79, 1, 62, -33, 34, -33, 34, -33, 1, 107, 1, 62, -33, 34, -33, 34, -33, 1, 64, 8, 0,
  /* 1279 */ 124, 175, 1, 62, -33, 34, -33, 34, -33, 1, 107, 1, 62, -33, 34, -33, 34, -33, 1, 64, 8, 0,
  /* 1301 */ 315, 1, 62, -33, 34, -33, 34, -33, 1, 64, 8, 0,
  /* 1313 */ 64, 96, -128, 96, 124, 63, 1, 62, -33, 34, -33, 34, -33, 1, 79, 1, 62, -33, 34, -33, 34, -33, 1, 107, 1, 62, -33, 34, -33, 34, -33, 1, 72, 8, 0,
  /* 1348 */ 124, 175, 1, 62, -33, 34, -33, 34, -33, 1, 107, 1, 62, -33, 34, -33, 34, -33, 1, 72, 8, 0,
  /* 1370 */ 315, 1, 62, -33, 34, -33, 34, -33, 1, 72, 8, 0,
  /* 1382 */ 31, 300, 17, -43, 11, 0,
  /* 1388 */ 31, 301, 17, -43, 11, 0,
  /* 1394 */ 317, -43, 11, 0,
  /* 1398 */ 318, -43, 11, 0,
  /* 1402 */ 64, 96, -128, 96, 124, 63, 1, 62, -33, 34, -33, 34, -33, 1, 79, 1, 62, -33, 34, -33, 34, -33, 1, 107, 1, 62, -33, 34, -33, 34, -33, 1, 40, 12, 0,
  /* 1437 */ 124, 175, 1, 62, -33, 34, -33, 34, -33, 1, 107, 1, 62, -33, 34, -33, 34, -33, 1, 40, 12, 0,
  /* 1459 */ 315, 1, 62, -33, 34, -33, 34, -33, 1, 40, 12, 0,
  /* 1471 */ 64, 96, -128, 96, 124, 64, 31, 33, -32, 62, -33, 34, -33, 1, 49, 31, 33, -32, 62, -33, 34, -33, 1, 77, 31, 33, -32, 62, -33, 34, -33, 1, 41, 12, 0,
  /* 1506 */ 124, 176, 31, 33, -32, 62, -33, 34, -33, 1, 77, 31, 33, -32, 62, -33, 34, -33, 1, 41, 12, 0,
  /* 1528 */ 316, 31, 33, -32, 62, -33, 34, -33, 1, 41, 12, 0,
  /* 1540 */ 64, 96, -128, 96, 124, 63, 1, 63, 1, -33, 1, 62, -33, 1, 49, 1, 63, 1, -33, 1, 62, -33, 1, 77, 1, 63, 1, -33, 1, 62, -33, 1, 42, 12, 0,
  /* 1575 */ 124, 175, 1, 63, 1, -33, 1, 62, -33, 1, 77, 1, 63, 1, -33, 1, 62, -33, 1, 42, 12, 0,
  /* 1597 */ 315, 1, 63, 1, -33, 1, 62, -33, 1, 42, 12, 0,
  /* 1609 */ 64, 96, -128, 96, 124, 63, 1, 62, 1, -33, 34, -33, 1, 29, 50, 1, 62, 1, -33, 34, -33, 1, 29, 78, 1, 62, 1, -33, 34, -33, 1, 29, 43, 12, 0,
  /* 1644 */ 124, 175, 1, 62, 1, -33, 34, -33, 1, 29, 78, 1, 62, 1, -33, 34, -33, 1, 29, 43, 12, 0,
  /* 1666 */ 315, 1, 62, 1, -33, 34, -33, 1, 29, 43, 12, 0,
  /* 1678 */ 64, 96, -128, 96, 124, 63, 1, 62, -33, 34, -33, 34, -33, 1, 79, 1, 62, -33, 34, -33, 34, -33, 1, 107, 1, 62, -33, 34, -33, 34, -33, 1, 48, 12, 0,
  /* 1713 */ 124, 175, 1, 62, -33, 34, -33, 34, -33, 1, 107, 1, 62, -33, 34, -33, 34, -33, 1, 48, 12, 0,
  /* 1735 */ 315, 1, 62, -33, 34, -33, 34, -33, 1, 48, 12, 0,
  /* 1747 */ 64, 96, -128, 96, 124, 63, 1, 62, -33, 34, -33, 34, -33, 1, 79, 1, 62, -33, 34, -33, 34, -33, 1, 107, 1, 62, -33, 34, -33, 34, -33, 1, 64, 12, 0,
  /* 1782 */ 124, 175, 1, 62, -33, 34, -33, 34, -33, 1, 107, 1, 62, -33, 34, -33, 34, -33, 1, 64, 12, 0,
  /* 1804 */ 315, 1, 62, -33, 34, -33, 34, -33, 1, 64, 12, 0,
  /* 1816 */ 64, 96, -128, 96, 124, 63, 1, 62, -33, 34, -33, 34, -33, 1, 79, 1, 62, -33, 34, -33, 34, -33, 1, 107, 1, 62, -33, 34, -33, 34, -33, 1, 72, 12, 0,
  /* 1851 */ 124, 175, 1, 62, -33, 34, -33, 34, -33, 1, 107, 1, 62, -33, 34, -33, 34, -33, 1, 72, 12, 0,
  /* 1873 */ 315, 1, 62, -33, 34, -33, 34, -33, 1, 72, 12, 0,
  /* 1885 */ -16, 316, 15, 0,
  /* 1889 */ -316, 16, -31, 16, 0,
  /* 1894 */ -316, 16, -15, 16, 0,
  /* 1899 */ 64, 96, -128, 96, 124, 63, 1, 62, -33, 34, -33, 34, -33, 1, 79, 1, 62, -33, 34, -33, 34, -33, 1, 107, 1, 62, -33, 34, -33, 34, -33, 1, 40, 16, 0,
  /* 1934 */ 124, 175, 1, 62, -33, 34, -33, 34, -33, 1, 107, 1, 62, -33, 34, -33, 34, -33, 1, 40, 16, 0,
  /* 1956 */ 315, 1, 62, -33, 34, -33, 34, -33, 1, 40, 16, 0,
  /* 1968 */ 64, 96, -128, 96, 124, 63, 1, 62, -33, 34, -33, 34, -33, 1, 79, 1, 62, -33, 34, -33, 34, -33, 1, 107, 1, 62, -33, 34, -33, 34, -33, 1, 48, 16, 0,
  /* 2003 */ 124, 175, 1, 62, -33, 34, -33, 34, -33, 1, 107, 1, 62, -33, 34, -33, 34, -33, 1, 48, 16, 0,
  /* 2025 */ 315, 1, 62, -33, 34, -33, 34, -33, 1, 48, 16, 0,
  /* 2037 */ 1, 538, 16, 0,
  /* 2041 */ -230, 544, 16, 0,
  /* 2045 */ 1, 1, 29, 0,
  /* 2049 */ 63, 1, -33, 1, 30, 50, 63, 1, -33, 1, 30, 78, 63, 1, -33, 1, 30, 0,
  /* 2067 */ -32, 31, 113, -32, 31, 141, -32, 31, 0,
  /* 2076 */ 99, 0,
  /* 2078 */ -380, -124, -96, 128, -96, -64, 221, -124, -96, 128, -96, -64, 253, -124, -96, 128, -96, -64, 346, 112, -48, 112, 76, -31, -252, 112, 0,
  /* 2105 */ -380, -124, -96, 128, -96, -64, 253, -124, -96, 128, -96, -64, 253, -124, -96, 128, -96, -64, 314, 112, -48, 112, 76, 1, -252, 112, 0,
  /* 2132 */ -380, -124, -96, 128, -96, -64, 253, -124, -96, 128, -96, -64, 221, -124, -96, 128, -96, -64, 346, 112, -48, 112, 76, 1, -252, 112, 0,
  /* 2159 */ -348, -124, -96, 128, -96, -64, 253, -124, -96, 128, -96, -64, 221, -124, -96, 128, -96, -64, 253, -124, -96, 128, -96, -64, 345, 112, -80, 32, 80, 32, 76, 64, -63, 64, -95, -221, 64, 48, 64, -207, 112, 0,
  /* 2201 */ -348, -124, -96, 128, -96, -64, 221, -124, -96, 128, -96, -64, 253, -124, -96, 128, -96, -64, 253, -124, -96, 128, -96, -64, 345, 112, -80, 32, 80, 32, 76, 64, -95, 64, -63, -253, 64, 48, 64, -175, 112, 0,
  /* 2243 */ -348, -124, -96, 128, -96, -64, 253, -124, -96, 128, -96, -64, 253, -124, -96, 128, -96, -64, 253, -124, -96, 128, -96, -64, 313, 112, -80, 32, 80, 32, 76, 64, -63, 64, -63, -253, 64, 48, 64, -175, 112, 0,
  /* 2285 */ -348, -124, -96, 128, -96, -64, 253, -124, -96, 128, -96, -64, 253, -124, -96, 128, -96, -64, 221, -124, -96, 128, -96, -64, 345, 112, -80, 32, 80, 32, 76, 64, -63, 64, -63, -253, 64, 48, 64, -175, 112, 0,
  /* 2327 */ -316, -124, -96, 128, -96, -64, 253, -124, -96, 128, -96, -64, 315, 112, 0,
  /* 2342 */ -316, -124, -96, 128, -96, -64, 221, -124, -96, 128, -96, -64, 347, 112, 0,
  /* 2357 */ 112, 140, 0,
  /* 2360 */ 230, 0,
  /* 2362 */ 231, 0,
  /* 2364 */ -300, -96, 128, -96, -64, 129, -96, 128, -96, -64, 315, 0,
  /* 2376 */ -302, -31, -230, 231, 330, 0,
  /* 2382 */ -318, -31, 32, -31, 331, 0,
  /* 2388 */ -319, -31, 32, -31, 332, 0,
  /* 2394 */ -320, -31, 32, -31, 333, 0,
  /* 2400 */ -321, -31, 32, -31, 334, 0,
  /* 2406 */ -322, -31, 32, -31, 335, 0,
  /* 2412 */ -323, -31, 32, -31, 336, 0,
  /* 2418 */ -324, -31, 32, -31, 337, 0,
  /* 2424 */ -325, -31, 32, -31, 338, 0,
  /* 2430 */ -326, -31, 32, -31, 339, 0,
  /* 2436 */ -327, -31, 32, -31, 340, 0,
  /* 2442 */ -328, -31, 32, -31, 341, 0,
  /* 2448 */ -329, -31, 32, -31, 342, 0,
  /* 2454 */ -330, -31, 32, -31, 343, 0,
  /* 2460 */ -331, -31, 32, -31, 344, 0,
  /* 2466 */ -300, -96, 128, -96, -64, 97, -96, 128, -96, -64, 347, 0,
  /* 2478 */ -560, 230, -224, -1, 539, 0,
  /* 2484 */ 554, 0,
  /* 2486 */ 560, 0,
};

static const uint16_t AArch64SubRegIdxLists[] = {
  /* 0 */ 38, 2, 15, 7, 1, 0,
  /* 6 */ 8, 0,
  /* 8 */ 16, 0,
  /* 10 */ 17, 19, 0,
  /* 13 */ 34, 35, 0,
  /* 16 */ 30, 34, 35, 31, 43, 44, 0,
  /* 23 */ 36, 30, 34, 35, 31, 43, 44, 37, 45, 47, 48, 46, 49, 50, 0,
  /* 38 */ 29, 32, 36, 30, 34, 35, 31, 43, 44, 37, 45, 47, 48, 46, 49, 50, 33, 55, 51, 53, 54, 52, 57, 58, 56, 59, 61, 62, 60, 63, 64, 0,
  /* 70 */ 3, 15, 7, 1, 4, 67, 66, 65, 0,
  /* 79 */ 9, 8, 10, 74, 0,
  /* 84 */ 39, 38, 2, 15, 7, 1, 40, 99, 96, 98, 97, 95, 0,
  /* 97 */ 3, 15, 7, 1, 4, 67, 66, 65, 5, 73, 72, 71, 110, 112, 0,
  /* 112 */ 3, 15, 7, 1, 4, 67, 66, 65, 5, 73, 72, 71, 6, 70, 69, 68, 110, 111, 112, 113, 114, 0,
  /* 134 */ 11, 2, 15, 7, 1, 12, 76, 78, 77, 75, 115, 0,
  /* 146 */ 11, 2, 15, 7, 1, 12, 76, 78, 77, 75, 13, 84, 86, 85, 83, 115, 117, 118, 120, 123, 0,
  /* 167 */ 11, 2, 15, 7, 1, 12, 76, 78, 77, 75, 13, 84, 86, 85, 83, 14, 80, 82, 81, 79, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 0,
  /* 199 */ 21, 16, 22, 93, 23, 92, 24, 91, 25, 90, 26, 89, 27, 88, 28, 87, 126, 127, 128, 129, 130, 131, 132, 133, 0,
  /* 224 */ 18, 16, 20, 94, 134, 0,
  /* 230 */ 39, 38, 2, 15, 7, 1, 40, 99, 96, 98, 97, 95, 135, 136, 0,
  /* 245 */ 39, 38, 2, 15, 7, 1, 40, 99, 96, 98, 97, 95, 41, 109, 106, 108, 107, 105, 135, 136, 138, 140, 141, 143, 146, 148, 0,
  /* 272 */ 39, 38, 2, 15, 7, 1, 40, 99, 96, 98, 97, 95, 41, 109, 106, 108, 107, 105, 42, 104, 101, 103, 102, 100, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 0,
  /* 314 */ 39, 38, 2, 15, 7, 1, 40, 99, 96, 98, 97, 95, 41, 109, 106, 108, 107, 105, 42, 104, 101, 103, 102, 100, 152, 153, 0,
};

static const MCRegisterDesc AArch64RegDesc[] = { // Descriptors
  { 3, 0, 0, 0, 0, 0 },
  { 2940, 5, 5, 5, 20480, 163 },
  { 2928, 2362, 466, 8, 20481, 40 },
  { 2935, 5, 5, 5, 20482, 163 },
  { 2944, 2360, 2486, 8, 20483, 40 },
  { 2962, 5, 5, 5, 20484, 163 },
  { 2932, 1152, 5, 8, 20485, 40 },
  { 2897, 5, 5, 5, 20486, 163 },
  { 2931, 5, 469, 5, 20485, 163 },
  { 2951, 5, 2037, 5, 20487, 163 },
  { 2958, 494, 2484, 8, 20487, 40 },
  { 2894, 1212, 5, 38, 4222984, 65 },
  { 242, 5, 1471, 5, 20504, 163 },
  { 629, 5, 1540, 5, 20505, 163 },
  { 888, 5, 1609, 5, 20506, 163 },
  { 1199, 5, 1816, 5, 20507, 163 },
  { 1462, 5, 1313, 5, 20508, 163 },
  { 1779, 5, 1313, 5, 20509, 163 },
  { 2000, 5, 1313, 5, 20510, 163 },
  { 2279, 5, 1313, 5, 20511, 163 },
  { 2534, 5, 1747, 5, 20512, 163 },
  { 2798, 5, 1747, 5, 20513, 163 },
  { 0, 5, 1747, 5, 20514, 163 },
  { 331, 5, 1747, 5, 20515, 163 },
  { 716, 5, 1244, 5, 20516, 163 },
  { 964, 5, 1244, 5, 20517, 163 },
  { 1278, 5, 1244, 5, 20518, 163 },
  { 1533, 5, 1244, 5, 20519, 163 },
  { 1856, 5, 1968, 5, 20520, 163 },
  { 2071, 5, 1968, 5, 20521, 163 },
  { 2374, 5, 1968, 5, 20522, 163 },
  { 2606, 5, 1968, 5, 20523, 163 },
  { 84, 5, 1678, 5, 20524, 163 },
  { 445, 5, 1678, 5, 20525, 163 },
  { 820, 5, 1678, 5, 20526, 163 },
  { 1099, 5, 1678, 5, 20527, 163 },
  { 1386, 5, 1899, 5, 20528, 163 },
  { 1671, 5, 1899, 5, 20529, 163 },
  { 1924, 5, 1899, 5, 20530, 163 },
  { 2171, 5, 1899, 5, 20531, 163 },
  { 2442, 5, 1402, 5, 20532, 163 },
  { 2706, 5, 1402, 5, 20533, 163 },
  { 152, 5, 1402, 5, 20534, 163 },
  { 545, 5, 1402, 5, 20535, 163 },
  { 247, 225, 1474, 2, 20504, 1 },
  { 634, 225, 1543, 2, 20505, 1 },
  { 893, 225, 1612, 2, 20506, 1 },
  { 1204, 225, 1819, 2, 20507, 1 },
  { 1467, 225, 1316, 2, 20508, 1 },
  { 1784, 225, 1316, 2, 20509, 1 },
  { 2005, 225, 1316, 2, 20510, 1 },
  { 2284, 225, 1316, 2, 20511, 1 },
  { 2546, 225, 1750, 2, 20512, 1 },
  { 2810, 225, 1750, 2, 20513, 1 },
  { 13, 225, 1750, 2, 20514, 1 },
  { 345, 225, 1750, 2, 20515, 1 },
  { 731, 225, 1247, 2, 20516, 1 },
  { 980, 225, 1247, 2, 20517, 1 },
  { 1294, 225, 1247, 2, 20518, 1 },
  { 1549, 225, 1247, 2, 20519, 1 },
  { 1872, 225, 1971, 2, 20520, 1 },
  { 2087, 225, 1971, 2, 20521, 1 },
  { 2390, 225, 1971, 2, 20522, 1 },
  { 2622, 225, 1971, 2, 20523, 1 },
  { 100, 225, 1681, 2, 20524, 1 },
  { 461, 225, 1681, 2, 20525, 1 },
  { 836, 225, 1681, 2, 20526, 1 },
  { 1115, 225, 1681, 2, 20527, 1 },
  { 1402, 225, 1902, 2, 20528, 1 },
  { 1687, 225, 1902, 2, 20529, 1 },
  { 1940, 225, 1902, 2, 20530, 1 },
  { 2187, 225, 1902, 2, 20531, 1 },
  { 2458, 225, 1405, 2, 20532, 1 },
  { 2722, 225, 1405, 2, 20533, 1 },
  { 168, 225, 1405, 2, 20534, 1 },
  { 561, 225, 1405, 2, 20535, 1 },
  { 267, 227, 1472, 4, 20504, 1 },
  { 653, 227, 1541, 4, 20505, 1 },
  { 909, 227, 1610, 4, 20506, 1 },
  { 1219, 227, 1817, 4, 20507, 1 },
  { 1482, 227, 1314, 4, 20508, 1 },
  { 1799, 227, 1314, 4, 20509, 1 },
  { 2020, 227, 1314, 4, 20510, 1 },
  { 2299, 227, 1314, 4, 20511, 1 },
  { 2549, 227, 1748, 4, 20512, 1 },
  { 2813, 227, 1748, 4, 20513, 1 },
  { 17, 227, 1748, 4, 20514, 1 },
  { 349, 227, 1748, 4, 20515, 1 },
  { 735, 227, 1245, 4, 20516, 1 },
  { 984, 227, 1245, 4, 20517, 1 },
  { 1298, 227, 1245, 4, 20518, 1 },
  { 1553, 227, 1245, 4, 20519, 1 },
  { 1876, 227, 1969, 4, 20520, 1 },
  { 2091, 227, 1969, 4, 20521, 1 },
  { 2394, 227, 1969, 4, 20522, 1 },
  { 2626, 227, 1969, 4, 20523, 1 },
  { 104, 227, 1679, 4, 20524, 1 },
  { 465, 227, 1679, 4, 20525, 1 },
  { 840, 227, 1679, 4, 20526, 1 },
  { 1119, 227, 1679, 4, 20527, 1 },
  { 1406, 227, 1900, 4, 20528, 1 },
  { 1691, 227, 1900, 4, 20529, 1 },
  { 1944, 227, 1900, 4, 20530, 1 },
  { 2191, 227, 1900, 4, 20531, 1 },
  { 2462, 227, 1403, 4, 20532, 1 },
  { 2726, 227, 1403, 4, 20533, 1 },
  { 172, 227, 1403, 4, 20534, 1 },
  { 565, 227, 1403, 4, 20535, 1 },
  { 278, 1892, 1886, 6, 20536, 37 },
  { 663, 1892, 1134, 6, 20537, 37 },
  { 919, 1892, 1134, 6, 20538, 37 },
  { 1229, 1892, 1134, 6, 20539, 37 },
  { 1492, 1892, 1134, 6, 20540, 37 },
  { 1809, 1892, 1134, 6, 20541, 37 },
  { 2030, 1892, 1134, 6, 20542, 37 },
  { 2309, 1892, 1134, 6, 20543, 37 },
  { 2559, 1892, 1134, 6, 20544, 37 },
  { 2823, 1892, 1134, 6, 20545, 37 },
  { 29, 1892, 1134, 6, 20546, 37 },
  { 362, 1892, 1134, 6, 20547, 37 },
  { 748, 1892, 1134, 6, 20548, 37 },
  { 997, 1892, 1134, 6, 20549, 37 },
  { 1311, 1892, 1134, 6, 20550, 37 },
  { 1566, 1892, 1134, 6, 20551, 37 },
  { 270, 5, 1885, 5, 20536, 163 },
  { 656, 5, 1133, 5, 20537, 163 },
  { 912, 5, 1133, 5, 20538, 163 },
  { 1222, 5, 1133, 5, 20539, 163 },
  { 1485, 5, 1133, 5, 20540, 163 },
  { 1802, 5, 1133, 5, 20541, 163 },
  { 2023, 5, 1133, 5, 20542, 163 },
  { 2302, 5, 1133, 5, 20543, 163 },
  { 2552, 5, 1133, 5, 20544, 163 },
  { 2816, 5, 1133, 5, 20545, 163 },
  { 21, 5, 1133, 5, 20546, 163 },
  { 353, 5, 1133, 5, 20547, 163 },
  { 739, 5, 1133, 5, 20548, 163 },
  { 988, 5, 1133, 5, 20549, 163 },
  { 1302, 5, 1133, 5, 20550, 163 },
  { 1557, 5, 1133, 5, 20551, 163 },
  { 283, 224, 1506, 1, 20504, 1 },
  { 668, 224, 1575, 1, 20505, 1 },
  { 924, 224, 1644, 1, 20506, 1 },
  { 1234, 224, 1851, 1, 20507, 1 },
  { 1497, 224, 1348, 1, 20508, 1 },
  { 1814, 224, 1348, 1, 20509, 1 },
  { 2035, 224, 1348, 1, 20510, 1 },
  { 2314, 224, 1348, 1, 20511, 1 },
  { 2564, 224, 1782, 1, 20512, 1 },
  { 2828, 224, 1782, 1, 20513, 1 },
  { 35, 224, 1782, 1, 20514, 1 },
  { 368, 224, 1782, 1, 20515, 1 },
  { 754, 224, 1279, 1, 20516, 1 },
  { 1003, 224, 1279, 1, 20517, 1 },
  { 1317, 224, 1279, 1, 20518, 1 },
  { 1572, 224, 1279, 1, 20519, 1 },
  { 1892, 224, 2003, 1, 20520, 1 },
  { 2107, 224, 2003, 1, 20521, 1 },
  { 2410, 224, 2003, 1, 20522, 1 },
  { 2642, 224, 2003, 1, 20523, 1 },
  { 120, 224, 1713, 1, 20524, 1 },
  { 481, 224, 1713, 1, 20525, 1 },
  { 856, 224, 1713, 1, 20526, 1 },
  { 1135, 224, 1713, 1, 20527, 1 },
  { 1422, 224, 1934, 1, 20528, 1 },
  { 1707, 224, 1934, 1, 20529, 1 },
  { 1960, 224, 1934, 1, 20530, 1 },
  { 2207, 224, 1934, 1, 20531, 1 },
  { 2478, 224, 1437, 1, 20532, 1 },
  { 2742, 224, 1437, 1, 20533, 1 },
  { 188, 224, 1437, 1, 20534, 1 },
  { 581, 224, 1437, 1, 20535, 1 },
  { 303, 226, 1473, 3, 20504, 1 },
  { 687, 226, 1542, 3, 20505, 1 },
  { 942, 226, 1611, 3, 20506, 1 },
  { 1251, 226, 1818, 3, 20507, 1 },
  { 1512, 226, 1315, 3, 20508, 1 },
  { 1829, 226, 1315, 3, 20509, 1 },
  { 2050, 226, 1315, 3, 20510, 1 },
  { 2329, 226, 1315, 3, 20511, 1 },
  { 2579, 226, 1749, 3, 20512, 1 },
  { 2843, 226, 1749, 3, 20513, 1 },
  { 52, 226, 1749, 3, 20514, 1 },
  { 386, 226, 1749, 3, 20515, 1 },
  { 773, 226, 1246, 3, 20516, 1 },
  { 1023, 226, 1246, 3, 20517, 1 },
  { 1337, 226, 1246, 3, 20518, 1 },
  { 1592, 226, 1246, 3, 20519, 1 },
  { 1896, 226, 1970, 3, 20520, 1 },
  { 2111, 226, 1970, 3, 20521, 1 },
  { 2414, 226, 1970, 3, 20522, 1 },
  { 2646, 226, 1970, 3, 20523, 1 },
  { 124, 226, 1680, 3, 20524, 1 },
  { 485, 226, 1680, 3, 20525, 1 },
  { 860, 226, 1680, 3, 20526, 1 },
  { 1139, 226, 1680, 3, 20527, 1 },
  { 1426, 226, 1901, 3, 20528, 1 },
  { 1711, 226, 1901, 3, 20529, 1 },
  { 1964, 226, 1901, 3, 20530, 1 },
  { 2211, 226, 1901, 3, 20531, 1 },
  { 2482, 226, 1404, 3, 20532, 1 },
  { 2746, 226, 1404, 3, 20533, 1 },
  { 192, 226, 1404, 3, 20534, 1 },
  { 585, 226, 1404, 3, 20535, 1 },
  { 310, 5, 452, 5, 20552, 163 },
  { 693, 5, 447, 5, 20553, 163 },
  { 945, 5, 867, 5, 20554, 163 },
  { 1257, 5, 861, 5, 20555, 163 },
  { 1515, 5, 888, 5, 20556, 163 },
  { 1835, 5, 881, 5, 20557, 163 },
  { 2053, 5, 969, 5, 20558, 163 },
  { 2335, 5, 961, 5, 20559, 163 },
  { 2582, 5, 961, 5, 20560, 163 },
  { 2849, 5, 953, 5, 20561, 163 },
  { 56, 5, 953, 5, 20562, 163 },
  { 394, 5, 945, 5, 20563, 163 },
  { 777, 5, 945, 5, 20564, 163 },
  { 1031, 5, 937, 5, 20565, 163 },
  { 1341, 5, 937, 5, 20566, 163 },
  { 1600, 5, 929, 5, 20567, 163 },
  { 1900, 5, 929, 5, 20568, 163 },
  { 2119, 5, 921, 5, 20569, 163 },
  { 2418, 5, 921, 5, 20570, 163 },
  { 2654, 5, 913, 5, 20571, 163 },
  { 128, 5, 913, 5, 20572, 163 },
  { 493, 5, 905, 5, 20573, 163 },
  { 864, 5, 1063, 5, 20574, 163 },
  { 1147, 5, 1055, 5, 20575, 163 },
  { 1430, 5, 1094, 5, 20576, 163 },
  { 1719, 5, 1087, 5, 20577, 163 },
  { 1968, 5, 1388, 5, 20578, 163 },
  { 2219, 5, 1382, 5, 20579, 163 },
  { 2486, 5, 437, 5, 20580, 163 },
  { 2754, 5, 442, 5, 20481, 163 },
  { 196, 5, 2041, 5, 20483, 163 },
  { 313, 435, 463, 8, 20552, 40 },
  { 699, 435, 460, 8, 20553, 40 },
  { 948, 435, 877, 8, 20554, 40 },
  { 1263, 435, 873, 8, 20555, 40 },
  { 1518, 435, 900, 8, 20556, 40 },
  { 1841, 435, 895, 8, 20557, 40 },
  { 2056, 435, 1025, 8, 20558, 40 },
  { 2359, 435, 1019, 8, 20559, 40 },
  { 2585, 435, 1019, 8, 20560, 40 },
  { 2873, 435, 1013, 8, 20561, 40 },
  { 60, 435, 1013, 8, 20562, 40 },
  { 420, 435, 1007, 8, 20563, 40 },
  { 781, 435, 1007, 8, 20564, 40 },
  { 1059, 435, 1001, 8, 20565, 40 },
  { 1345, 435, 1001, 8, 20566, 40 },
  { 1630, 435, 995, 8, 20567, 40 },
  { 1904, 435, 995, 8, 20568, 40 },
  { 2151, 435, 989, 8, 20569, 40 },
  { 2422, 435, 989, 8, 20570, 40 },
  { 2686, 435, 983, 8, 20571, 40 },
  { 132, 435, 983, 8, 20572, 40 },
  { 525, 435, 977, 8, 20573, 40 },
  { 868, 435, 1077, 8, 20574, 40 },
  { 1179, 435, 1071, 8, 20575, 40 },
  { 1434, 435, 1106, 8, 20576, 40 },
  { 1751, 435, 1101, 8, 20577, 40 },
  { 1972, 435, 1398, 8, 20578, 40 },
  { 2251, 435, 1394, 8, 20579, 40 },
  { 2490, 435, 457, 8, 20580, 40 },
  { 328, 223, 1528, 0, 20504, 1 },
  { 713, 223, 1597, 0, 20505, 1 },
  { 961, 223, 1666, 0, 20506, 1 },
  { 1275, 223, 1873, 0, 20507, 1 },
  { 1530, 223, 1370, 0, 20508, 1 },
  { 1853, 223, 1370, 0, 20509, 1 },
  { 2068, 223, 1370, 0, 20510, 1 },
  { 2371, 223, 1370, 0, 20511, 1 },
  { 2591, 223, 1804, 0, 20512, 1 },
  { 2879, 223, 1804, 0, 20513, 1 },
  { 67, 223, 1804, 0, 20514, 1 },
  { 434, 223, 1804, 0, 20515, 1 },
  { 796, 223, 1301, 0, 20516, 1 },
  { 1075, 223, 1301, 0, 20517, 1 },
  { 1359, 223, 1301, 0, 20518, 1 },
  { 1644, 223, 1301, 0, 20519, 1 },
  { 1920, 223, 2025, 0, 20520, 1 },
  { 2167, 223, 2025, 0, 20521, 1 },
  { 2438, 223, 2025, 0, 20522, 1 },
  { 2702, 223, 2025, 0, 20523, 1 },
  { 148, 223, 1735, 0, 20524, 1 },
  { 541, 223, 1735, 0, 20525, 1 },
  { 884, 223, 1735, 0, 20526, 1 },
  { 1195, 223, 1735, 0, 20527, 1 },
  { 1450, 223, 1956, 0, 20528, 1 },
  { 1767, 223, 1956, 0, 20529, 1 },
  { 1988, 223, 1956, 0, 20530, 1 },
  { 2267, 223, 1956, 0, 20531, 1 },
  { 2498, 223, 1459, 0, 20532, 1 },
  { 2762, 223, 1459, 0, 20533, 1 },
  { 204, 223, 1459, 0, 20534, 1 },
  { 601, 223, 1459, 0, 20535, 1 },
  { 240, 1213, 4, 39, 4222984, 65 },
  { 245, 1241, 85, 13, 3162120, 48 },
  { 632, 1241, 37, 13, 3162128, 48 },
  { 891, 1241, 61, 13, 3162124, 48 },
  { 1202, 1241, 13, 13, 3162132, 48 },
  { 1465, 1241, 73, 13, 3162122, 48 },
  { 1782, 1241, 25, 13, 3162130, 48 },
  { 2003, 1241, 49, 13, 3162126, 48 },
  { 2282, 1241, 1, 13, 3162134, 48 },
  { 265, 1229, 51, 23, 4255752, 56 },
  { 651, 1229, 3, 23, 4255760, 56 },
  { 281, 5, 90, 5, 20488, 163 },
  { 666, 5, 42, 5, 20496, 163 },
  { 922, 5, 66, 5, 20492, 163 },
  { 1232, 5, 18, 5, 20500, 163 },
  { 1495, 5, 78, 5, 20490, 163 },
  { 1812, 5, 30, 5, 20498, 163 },
  { 2033, 5, 54, 5, 20494, 163 },
  { 2312, 5, 6, 5, 20502, 163 },
  { 2562, 5, 84, 5, 20489, 163 },
  { 2826, 5, 36, 5, 20497, 163 },
  { 33, 5, 60, 5, 20493, 163 },
  { 366, 5, 12, 5, 20501, 163 },
  { 752, 5, 72, 5, 20491, 163 },
  { 1001, 5, 24, 5, 20499, 163 },
  { 1315, 5, 48, 5, 20495, 163 },
  { 1570, 5, 0, 5, 20503, 163 },
  { 301, 1237, 74, 16, 3723272, 51 },
  { 685, 1237, 26, 16, 3723280, 51 },
  { 940, 1237, 50, 16, 3723276, 51 },
  { 1249, 1237, 2, 16, 3723284, 51 },
  { 306, 5, 5, 5, 20581, 163 },
  { 645, 251, 834, 70, 3162136, 84 },
  { 903, 251, 2049, 70, 3162137, 84 },
  { 1213, 251, 816, 70, 3162138, 84 },
  { 1476, 251, 816, 70, 3162139, 84 },
  { 1793, 251, 816, 70, 3162140, 84 },
  { 2014, 251, 816, 70, 3162141, 84 },
  { 2293, 251, 816, 70, 3162142, 84 },
  { 2543, 251, 816, 70, 3162143, 84 },
  { 2807, 251, 816, 70, 3162144, 84 },
  { 10, 251, 816, 70, 3162145, 84 },
  { 341, 251, 816, 70, 3162146, 84 },
  { 727, 251, 816, 70, 3162147, 84 },
  { 976, 251, 816, 70, 3162148, 84 },
  { 1290, 251, 816, 70, 3162149, 84 },
  { 1545, 251, 816, 70, 3162150, 84 },
  { 1868, 251, 816, 70, 3162151, 84 },
  { 2083, 251, 816, 70, 3162152, 84 },
  { 2386, 251, 816, 70, 3162153, 84 },
  { 2618, 251, 816, 70, 3162154, 84 },
  { 96, 251, 816, 70, 3162155, 84 },
  { 457, 251, 816, 70, 3162156, 84 },
  { 832, 251, 816, 70, 3162157, 84 },
  { 1111, 251, 816, 70, 3162158, 84 },
  { 1398, 251, 816, 70, 3162159, 84 },
  { 1683, 251, 816, 70, 3162160, 84 },
  { 1936, 251, 816, 70, 3162161, 84 },
  { 2183, 251, 816, 70, 3162162, 84 },
  { 2454, 251, 816, 70, 3162163, 84 },
  { 2718, 251, 816, 70, 3162164, 84 },
  { 164, 251, 816, 70, 3162165, 84 },
  { 557, 251, 816, 70, 3162166, 84 },
  { 258, 242, 816, 70, 8495128, 0 },
  { 1207, 378, 2357, 112, 3723288, 91 },
  { 1470, 378, 2357, 112, 3723289, 91 },
  { 1787, 378, 2357, 112, 3723290, 91 },
  { 2008, 378, 2357, 112, 3723291, 91 },
  { 2287, 378, 2357, 112, 3723292, 91 },
  { 2537, 378, 2357, 112, 3723293, 91 },
  { 2801, 378, 2357, 112, 3723294, 91 },
  { 4, 378, 2357, 112, 3723295, 91 },
  { 335, 378, 2357, 112, 3723296, 91 },
  { 720, 378, 2357, 112, 3723297, 91 },
  { 968, 378, 2357, 112, 3723298, 91 },
  { 1282, 378, 2357, 112, 3723299, 91 },
  { 1537, 378, 2357, 112, 3723300, 91 },
  { 1860, 378, 2357, 112, 3723301, 91 },
  { 2075, 378, 2357, 112, 3723302, 91 },
  { 2378, 378, 2357, 112, 3723303, 91 },
  { 2610, 378, 2357, 112, 3723304, 91 },
  { 88, 378, 2357, 112, 3723305, 91 },
  { 449, 378, 2357, 112, 3723306, 91 },
  { 824, 378, 2357, 112, 3723307, 91 },
  { 1103, 378, 2357, 112, 3723308, 91 },
  { 1390, 378, 2357, 112, 3723309, 91 },
  { 1675, 378, 2357, 112, 3723310, 91 },
  { 1928, 378, 2357, 112, 3723311, 91 },
  { 2175, 378, 2357, 112, 3723312, 91 },
  { 2446, 378, 2357, 112, 3723313, 91 },
  { 2710, 378, 2357, 112, 3723314, 91 },
  { 156, 378, 2357, 112, 3723315, 91 },
  { 549, 378, 2357, 112, 3723316, 91 },
  { 250, 400, 2357, 112, 4435992, 96 },
  { 637, 194, 2357, 112, 4550680, 82 },
  { 896, 356, 2357, 112, 8376344, 3 },
  { 900, 1118, 2067, 97, 3624984, 97 },
  { 1210, 1118, 852, 97, 3624985, 97 },
  { 1473, 1118, 852, 97, 3624986, 97 },
  { 1790, 1118, 852, 97, 3624987, 97 },
  { 2011, 1118, 852, 97, 3624988, 97 },
  { 2290, 1118, 852, 97, 3624989, 97 },
  { 2540, 1118, 852, 97, 3624990, 97 },
  { 2804, 1118, 852, 97, 3624991, 97 },
  { 7, 1118, 852, 97, 3624992, 97 },
  { 338, 1118, 852, 97, 3624993, 97 },
  { 723, 1118, 852, 97, 3624994, 97 },
  { 972, 1118, 852, 97, 3624995, 97 },
  { 1286, 1118, 852, 97, 3624996, 97 },
  { 1541, 1118, 852, 97, 3624997, 97 },
  { 1864, 1118, 852, 97, 3624998, 97 },
  { 2079, 1118, 852, 97, 3624999, 97 },
  { 2382, 1118, 852, 97, 3625000, 97 },
  { 2614, 1118, 852, 97, 3625001, 97 },
  { 92, 1118, 852, 97, 3625002, 97 },
  { 453, 1118, 852, 97, 3625003, 97 },
  { 828, 1118, 852, 97, 3625004, 97 },
  { 1107, 1118, 852, 97, 3625005, 97 },
  { 1394, 1118, 852, 97, 3625006, 97 },
  { 1679, 1118, 852, 97, 3625007, 97 },
  { 1932, 1118, 852, 97, 3625008, 97 },
  { 2179, 1118, 852, 97, 3625009, 97 },
  { 2450, 1118, 852, 97, 3625010, 97 },
  { 2714, 1118, 852, 97, 3625011, 97 },
  { 160, 1118, 852, 97, 3625012, 97 },
  { 553, 1118, 852, 97, 3625013, 97 },
  { 254, 1137, 852, 97, 4567064, 87 },
  { 641, 422, 852, 97, 8454168, 8 },
  { 660, 1894, 5, 79, 3162168, 101 },
  { 916, 1894, 5, 79, 3162169, 101 },
  { 1226, 1894, 5, 79, 3162170, 101 },
  { 1489, 1894, 5, 79, 3162171, 101 },
  { 1806, 1894, 5, 79, 3162172, 101 },
  { 2027, 1894, 5, 79, 3162173, 101 },
  { 2306, 1894, 5, 79, 3162174, 101 },
  { 2556, 1894, 5, 79, 3162175, 101 },
  { 2820, 1894, 5, 79, 3162176, 101 },
  { 26, 1894, 5, 79, 3162177, 101 },
  { 358, 1894, 5, 79, 3162178, 101 },
  { 744, 1894, 5, 79, 3162179, 101 },
  { 993, 1894, 5, 79, 3162180, 101 },
  { 1307, 1894, 5, 79, 3162181, 101 },
  { 1562, 1894, 5, 79, 3162182, 101 },
  { 274, 1889, 5, 79, 7729208, 36 },
  { 679, 2364, 840, 134, 3162136, 106 },
  { 934, 2364, 2055, 134, 3162137, 106 },
  { 1243, 2364, 822, 134, 3162138, 106 },
  { 1506, 2364, 822, 134, 3162139, 106 },
  { 1823, 2364, 822, 134, 3162140, 106 },
  { 2044, 2364, 822, 134, 3162141, 106 },
  { 2323, 2364, 822, 134, 3162142, 106 },
  { 2573, 2364, 822, 134, 3162143, 106 },
  { 2837, 2364, 822, 134, 3162144, 106 },
  { 45, 2364, 822, 134, 3162145, 106 },
  { 378, 2364, 822, 134, 3162146, 106 },
  { 765, 2364, 822, 134, 3162147, 106 },
  { 1015, 2364, 822, 134, 3162148, 106 },
  { 1329, 2364, 822, 134, 3162149, 106 },
  { 1584, 2364, 822, 134, 3162150, 106 },
  { 1888, 2364, 822, 134, 3162151, 106 },
  { 2103, 2364, 822, 134, 3162152, 106 },
  { 2406, 2364, 822, 134, 3162153, 106 },
  { 2638, 2364, 822, 134, 3162154, 106 },
  { 116, 2364, 822, 134, 3162155, 106 },
  { 477, 2364, 822, 134, 3162156, 106 },
  { 852, 2364, 822, 134, 3162157, 106 },
  { 1131, 2364, 822, 134, 3162158, 106 },
  { 1418, 2364, 822, 134, 3162159, 106 },
  { 1703, 2364, 822, 134, 3162160, 106 },
  { 1956, 2364, 822, 134, 3162161, 106 },
  { 2203, 2364, 822, 134, 3162162, 106 },
  { 2474, 2364, 822, 134, 3162163, 106 },
  { 2738, 2364, 822, 134, 3162164, 106 },
  { 184, 2364, 822, 134, 3162165, 106 },
  { 577, 2364, 822, 134, 3162166, 106 },
  { 294, 2466, 822, 134, 8495128, 12 },
  { 1237, 292, 2358, 167, 3723288, 113 },
  { 1500, 292, 2358, 167, 3723289, 113 },
  { 1817, 292, 2358, 167, 3723290, 113 },
  { 2038, 292, 2358, 167, 3723291, 113 },
  { 2317, 292, 2358, 167, 3723292, 113 },
  { 2567, 292, 2358, 167, 3723293, 113 },
  { 2831, 292, 2358, 167, 3723294, 113 },
  { 39, 292, 2358, 167, 3723295, 113 },
  { 372, 292, 2358, 167, 3723296, 113 },
  { 758, 292, 2358, 167, 3723297, 113 },
  { 1007, 292, 2358, 167, 3723298, 113 },
  { 1321, 292, 2358, 167, 3723299, 113 },
  { 1576, 292, 2358, 167, 3723300, 113 },
  { 1880, 292, 2358, 167, 3723301, 113 },
  { 2095, 292, 2358, 167, 3723302, 113 },
  { 2398, 292, 2358, 167, 3723303, 113 },
  { 2630, 292, 2358, 167, 3723304, 113 },
  { 108, 292, 2358, 167, 3723305, 113 },
  { 469, 292, 2358, 167, 3723306, 113 },
  { 844, 292, 2358, 167, 3723307, 113 },
  { 1123, 292, 2358, 167, 3723308, 113 },
  { 1410, 292, 2358, 167, 3723309, 113 },
  { 1695, 292, 2358, 167, 3723310, 113 },
  { 1948, 292, 2358, 167, 3723311, 113 },
  { 2195, 292, 2358, 167, 3723312, 113 },
  { 2466, 292, 2358, 167, 3723313, 113 },
  { 2730, 292, 2358, 167, 3723314, 113 },
  { 176, 292, 2358, 167, 3723315, 113 },
  { 569, 292, 2358, 167, 3723316, 113 },
  { 286, 324, 2358, 167, 4435992, 118 },
  { 671, 162, 2358, 167, 4550680, 104 },
  { 927, 260, 2358, 167, 8376344, 15 },
  { 931, 120, 2070, 146, 3624984, 119 },
  { 1240, 120, 855, 146, 3624985, 119 },
  { 1503, 120, 855, 146, 3624986, 119 },
  { 1820, 120, 855, 146, 3624987, 119 },
  { 2041, 120, 855, 146, 3624988, 119 },
  { 2320, 120, 855, 146, 3624989, 119 },
  { 2570, 120, 855, 146, 3624990, 119 },
  { 2834, 120, 855, 146, 3624991, 119 },
  { 42, 120, 855, 146, 3624992, 119 },
  { 375, 120, 855, 146, 3624993, 119 },
  { 761, 120, 855, 146, 3624994, 119 },
  { 1011, 120, 855, 146, 3624995, 119 },
  { 1325, 120, 855, 146, 3624996, 119 },
  { 1580, 120, 855, 146, 3624997, 119 },
  { 1884, 120, 855, 146, 3624998, 119 },
  { 2099, 120, 855, 146, 3624999, 119 },
  { 2402, 120, 855, 146, 3625000, 119 },
  { 2634, 120, 855, 146, 3625001, 119 },
  { 112, 120, 855, 146, 3625002, 119 },
  { 473, 120, 855, 146, 3625003, 119 },
  { 848, 120, 855, 146, 3625004, 119 },
  { 1127, 120, 855, 146, 3625005, 119 },
  { 1414, 120, 855, 146, 3625006, 119 },
  { 1699, 120, 855, 146, 3625007, 119 },
  { 1952, 120, 855, 146, 3625008, 119 },
  { 2199, 120, 855, 146, 3625009, 119 },
  { 2470, 120, 855, 146, 3625010, 119 },
  { 2734, 120, 855, 146, 3625011, 119 },
  { 180, 120, 855, 146, 3625012, 119 },
  { 573, 120, 855, 146, 3625013, 119 },
  { 290, 141, 855, 146, 4567064, 109 },
  { 675, 99, 855, 146, 8454168, 20 },
  { 2900, 746, 5, 199, 4288513, 132 },
  { 2338, 721, 5, 199, 4255816, 123 },
  { 2852, 696, 5, 199, 4255818, 123 },
  { 398, 671, 5, 199, 4255820, 123 },
  { 1035, 646, 5, 199, 4255822, 123 },
  { 1604, 621, 5, 199, 4255824, 123 },
  { 2123, 596, 5, 199, 4255826, 123 },
  { 2658, 571, 5, 199, 4255828, 123 },
  { 497, 546, 5, 199, 4255830, 123 },
  { 1151, 521, 5, 199, 4255832, 123 },
  { 1723, 496, 5, 199, 4255834, 123 },
  { 2223, 471, 5, 199, 4255836, 123 },
  { 2947, 96, 1892, 10, 4734979, 45 },
  { 690, 771, 449, 10, 3162184, 45 },
  { 1254, 774, 863, 10, 3162186, 45 },
  { 1832, 777, 883, 10, 3162188, 45 },
  { 2332, 780, 907, 10, 3162190, 45 },
  { 2846, 783, 907, 10, 3162192, 45 },
  { 390, 786, 907, 10, 3162194, 45 },
  { 1027, 789, 907, 10, 3162196, 45 },
  { 1596, 792, 907, 10, 3162198, 45 },
  { 2115, 795, 907, 10, 3162200, 45 },
  { 2650, 798, 907, 10, 3162202, 45 },
  { 489, 801, 907, 10, 3162204, 45 },
  { 1143, 804, 1057, 10, 3162206, 45 },
  { 1715, 807, 1089, 10, 3162208, 45 },
  { 2215, 810, 1384, 10, 3162210, 45 },
  { 2750, 813, 439, 10, 8503297, 42 },
  { 2955, 2478, 5, 224, 4734979, 141 },
  { 2924, 2376, 440, 224, 8503297, 39 },
  { 696, 2460, 440, 224, 3162184, 141 },
  { 1260, 2454, 864, 224, 3162186, 141 },
  { 1838, 2448, 884, 224, 3162188, 141 },
  { 2356, 2442, 908, 224, 3162190, 141 },
  { 2870, 2436, 908, 224, 3162192, 141 },
  { 416, 2430, 908, 224, 3162194, 141 },
  { 1055, 2424, 908, 224, 3162196, 141 },
  { 1626, 2418, 908, 224, 3162198, 141 },
  { 2147, 2412, 908, 224, 3162200, 141 },
  { 2682, 2406, 908, 224, 3162202, 141 },
  { 521, 2400, 908, 224, 3162204, 141 },
  { 1175, 2394, 1058, 224, 3162206, 141 },
  { 1747, 2388, 1090, 224, 3162208, 141 },
  { 2247, 2382, 1385, 224, 3162210, 141 },
  { 710, 2327, 846, 230, 3162136, 146 },
  { 958, 2327, 2061, 230, 3162137, 146 },
  { 1272, 2327, 828, 230, 3162138, 146 },
  { 1527, 2327, 828, 230, 3162139, 146 },
  { 1850, 2327, 828, 230, 3162140, 146 },
  { 2065, 2327, 828, 230, 3162141, 146 },
  { 2368, 2327, 828, 230, 3162142, 146 },
  { 2600, 2327, 828, 230, 3162143, 146 },
  { 2888, 2327, 828, 230, 3162144, 146 },
  { 77, 2327, 828, 230, 3162145, 146 },
  { 430, 2327, 828, 230, 3162146, 146 },
  { 792, 2327, 828, 230, 3162147, 146 },
  { 1071, 2327, 828, 230, 3162148, 146 },
  { 1371, 2327, 828, 230, 3162149, 146 },
  { 1656, 2327, 828, 230, 3162150, 146 },
  { 1916, 2327, 828, 230, 3162151, 146 },
  { 2163, 2327, 828, 230, 3162152, 146 },
  { 2434, 2327, 828, 230, 3162153, 146 },
  { 2698, 2327, 828, 230, 3162154, 146 },
  { 144, 2327, 828, 230, 3162155, 146 },
  { 537, 2327, 828, 230, 3162156, 146 },
  { 880, 2327, 828, 230, 3162157, 146 },
  { 1191, 2327, 828, 230, 3162158, 146 },
  { 1446, 2327, 828, 230, 3162159, 146 },
  { 1763, 2327, 828, 230, 3162160, 146 },
  { 1984, 2327, 828, 230, 3162161, 146 },
  { 2263, 2327, 828, 230, 3162162, 146 },
  { 2526, 2327, 828, 230, 3162163, 146 },
  { 2790, 2327, 828, 230, 3162164, 146 },
  { 232, 2327, 828, 230, 3162165, 146 },
  { 597, 2327, 828, 230, 3162166, 146 },
  { 324, 2342, 828, 230, 8495128, 24 },
  { 1266, 2243, 5, 272, 3723288, 153 },
  { 1521, 2243, 5, 272, 3723289, 153 },
  { 1844, 2243, 5, 272, 3723290, 153 },
  { 2059, 2243, 5, 272, 3723291, 153 },
  { 2362, 2243, 5, 272, 3723292, 153 },
  { 2594, 2243, 5, 272, 3723293, 153 },
  { 2882, 2243, 5, 272, 3723294, 153 },
  { 71, 2243, 5, 272, 3723295, 153 },
  { 424, 2243, 5, 272, 3723296, 153 },
  { 785, 2243, 5, 272, 3723297, 153 },
  { 1063, 2243, 5, 272, 3723298, 153 },
  { 1363, 2243, 5, 272, 3723299, 153 },
  { 1648, 2243, 5, 272, 3723300, 153 },
  { 1908, 2243, 5, 272, 3723301, 153 },
  { 2155, 2243, 5, 272, 3723302, 153 },
  { 2426, 2243, 5, 272, 3723303, 153 },
  { 2690, 2243, 5, 272, 3723304, 153 },
  { 136, 2243, 5, 272, 3723305, 153 },
  { 529, 2243, 5, 272, 3723306, 153 },
  { 872, 2243, 5, 272, 3723307, 153 },
  { 1183, 2243, 5, 272, 3723308, 153 },
  { 1438, 2243, 5, 272, 3723309, 153 },
  { 1755, 2243, 5, 272, 3723310, 153 },
  { 1976, 2243, 5, 272, 3723311, 153 },
  { 2255, 2243, 5, 272, 3723312, 153 },
  { 2518, 2243, 5, 272, 3723313, 153 },
  { 2782, 2243, 5, 272, 3723314, 153 },
  { 224, 2243, 5, 272, 3723315, 153 },
  { 589, 2243, 5, 272, 3723316, 153 },
  { 316, 2285, 5, 272, 4435992, 158 },
  { 702, 2159, 5, 272, 4550680, 144 },
  { 951, 2201, 5, 272, 8376344, 27 },
  { 955, 2105, 2073, 245, 3624984, 159 },
  { 1269, 2105, 831, 245, 3624985, 159 },
  { 1524, 2105, 831, 245, 3624986, 159 },
  { 1847, 2105, 831, 245, 3624987, 159 },
  { 2062, 2105, 831, 245, 3624988, 159 },
  { 2365, 2105, 831, 245, 3624989, 159 },
  { 2597, 2105, 831, 245, 3624990, 159 },
  { 2885, 2105, 831, 245, 3624991, 159 },
  { 74, 2105, 831, 245, 3624992, 159 },
  { 427, 2105, 831, 245, 3624993, 159 },
  { 788, 2105, 831, 245, 3624994, 159 },
  { 1067, 2105, 831, 245, 3624995, 159 },
  { 1367, 2105, 831, 245, 3624996, 159 },
  { 1652, 2105, 831, 245, 3624997, 159 },
  { 1912, 2105, 831, 245, 3624998, 159 },
  { 2159, 2105, 831, 245, 3624999, 159 },
  { 2430, 2105, 831, 245, 3625000, 159 },
  { 2694, 2105, 831, 245, 3625001, 159 },
  { 140, 2105, 831, 245, 3625002, 159 },
  { 533, 2105, 831, 245, 3625003, 159 },
  { 876, 2105, 831, 245, 3625004, 159 },
  { 1187, 2105, 831, 245, 3625005, 159 },
  { 1442, 2105, 831, 245, 3625006, 159 },
  { 1759, 2105, 831, 245, 3625007, 159 },
  { 1980, 2105, 831, 245, 3625008, 159 },
  { 2259, 2105, 831, 245, 3625009, 159 },
  { 2522, 2105, 831, 245, 3625010, 159 },
  { 2786, 2105, 831, 245, 3625011, 159 },
  { 228, 2105, 831, 245, 3625012, 159 },
  { 593, 2105, 831, 245, 3625013, 159 },
  { 320, 2132, 831, 245, 4567064, 149 },
  { 706, 2078, 831, 245, 8454168, 32 },
  { 1454, 229, 1892, 84, 5087272, 146 },
  { 1771, 229, 1892, 84, 5087273, 146 },
  { 1992, 229, 1892, 84, 5087274, 146 },
  { 2271, 229, 1892, 84, 5087275, 146 },
  { 2494, 229, 1435, 84, 5087276, 146 },
  { 2758, 229, 1435, 84, 5087277, 146 },
  { 200, 229, 1435, 84, 5087278, 146 },
  { 605, 229, 1435, 84, 5087279, 146 },
  { 2588, 216, 1435, 84, 5087256, 146 },
  { 2876, 216, 1435, 84, 5087257, 146 },
  { 64, 216, 1435, 84, 5087258, 146 },
  { 438, 216, 1435, 84, 5087259, 146 },
  { 800, 216, 1242, 84, 5087260, 146 },
  { 1079, 216, 1242, 84, 5087261, 146 },
  { 1379, 216, 1242, 84, 5087262, 146 },
  { 1664, 216, 1242, 84, 5087263, 146 },
  { 2502, 1158, 5, 314, 4726824, 153 },
  { 2766, 1158, 5, 314, 4726825, 153 },
  { 208, 1158, 5, 314, 4726826, 153 },
  { 613, 1158, 5, 314, 4726827, 153 },
  { 807, 1185, 5, 314, 4726808, 153 },
  { 1086, 1185, 5, 314, 4726809, 153 },
  { 1349, 1185, 5, 314, 4726810, 153 },
  { 1634, 1185, 5, 314, 4726811, 153 },
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

  // PNR Register Class...
  static const MCPhysReg PNR[] = {
    AArch64_PN0, AArch64_PN1, AArch64_PN2, AArch64_PN3, AArch64_PN4, AArch64_PN5, AArch64_PN6, AArch64_PN7, AArch64_PN8, AArch64_PN9, AArch64_PN10, AArch64_PN11, AArch64_PN12, AArch64_PN13, AArch64_PN14, AArch64_PN15, 
  };

  // PNR Bit set.
  static const uint8_t PNRBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // PPR Register Class...
  static const MCPhysReg PPR[] = {
    AArch64_P0, AArch64_P1, AArch64_P2, AArch64_P3, AArch64_P4, AArch64_P5, AArch64_P6, AArch64_P7, AArch64_P8, AArch64_P9, AArch64_P10, AArch64_P11, AArch64_P12, AArch64_P13, AArch64_P14, AArch64_P15, 
  };

  // PPR Bit set.
  static const uint8_t PPRBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // PNR_3b Register Class...
  static const MCPhysReg PNR_3b[] = {
    AArch64_PN0, AArch64_PN1, AArch64_PN2, AArch64_PN3, AArch64_PN4, AArch64_PN5, AArch64_PN6, AArch64_PN7, 
  };

  // PNR_3b Bit set.
  static const uint8_t PNR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 
  };

  // PNR_p8to15 Register Class...
  static const MCPhysReg PNR_p8to15[] = {
    AArch64_PN8, AArch64_PN9, AArch64_PN10, AArch64_PN11, AArch64_PN12, AArch64_PN13, AArch64_PN14, AArch64_PN15, 
  };

  // PNR_p8to15 Bit set.
  static const uint8_t PNR_p8to15Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 
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
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 
  };

  // PPR2Mul2 Register Class...
  static const MCPhysReg PPR2Mul2[] = {
    AArch64_P0_P1, AArch64_P2_P3, AArch64_P4_P5, AArch64_P6_P7, AArch64_P8_P9, AArch64_P10_P11, AArch64_P12_P13, AArch64_P14_P15, 
  };

  // PPR2Mul2 Bit set.
  static const uint8_t PPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x55, 
  };

  // PPR2_with_psub1_in_PPR_3b Register Class...
  static const MCPhysReg PPR2_with_psub1_in_PPR_3b[] = {
    AArch64_P0_P1, AArch64_P1_P2, AArch64_P2_P3, AArch64_P3_P4, AArch64_P4_P5, AArch64_P5_P6, AArch64_P6_P7, AArch64_P15_P0, 
  };

  // PPR2_with_psub1_in_PPR_3b Bit set.
  static const uint8_t PPR2_with_psub1_in_PPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x80, 
  };

  // PPR2_with_psub1_in_PPR_p8to15 Register Class...
  static const MCPhysReg PPR2_with_psub1_in_PPR_p8to15[] = {
    AArch64_P7_P8, AArch64_P8_P9, AArch64_P9_P10, AArch64_P10_P11, AArch64_P11_P12, AArch64_P12_P13, AArch64_P13_P14, AArch64_P14_P15, 
  };

  // PPR2_with_psub1_in_PPR_p8to15 Bit set.
  static const uint8_t PPR2_with_psub1_in_PPR_p8to15Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x7f, 
  };

  // PPR2_with_psub_in_PNR_3b Register Class...
  static const MCPhysReg PPR2_with_psub_in_PNR_3b[] = {
    AArch64_P0_P1, AArch64_P1_P2, AArch64_P2_P3, AArch64_P3_P4, AArch64_P4_P5, AArch64_P5_P6, AArch64_P6_P7, AArch64_P7_P8, 
  };

  // PPR2_with_psub_in_PNR_3b Bit set.
  static const uint8_t PPR2_with_psub_in_PNR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 
  };

  // PPR2_with_psub_in_PNR_p8to15 Register Class...
  static const MCPhysReg PPR2_with_psub_in_PNR_p8to15[] = {
    AArch64_P8_P9, AArch64_P9_P10, AArch64_P10_P11, AArch64_P11_P12, AArch64_P12_P13, AArch64_P13_P14, AArch64_P14_P15, AArch64_P15_P0, 
  };

  // PPR2_with_psub_in_PNR_p8to15 Bit set.
  static const uint8_t PPR2_with_psub_in_PNR_p8to15Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 
  };

  // PPR2_with_psub_in_PNR_3b_and_PPR2_with_psub1_in_PPR_3b Register Class...
  static const MCPhysReg PPR2_with_psub_in_PNR_3b_and_PPR2_with_psub1_in_PPR_3b[] = {
    AArch64_P0_P1, AArch64_P1_P2, AArch64_P2_P3, AArch64_P3_P4, AArch64_P4_P5, AArch64_P5_P6, AArch64_P6_P7, 
  };

  // PPR2_with_psub_in_PNR_3b_and_PPR2_with_psub1_in_PPR_3b Bit set.
  static const uint8_t PPR2_with_psub_in_PNR_3b_and_PPR2_with_psub1_in_PPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 
  };

  // PPR2_with_psub_in_PNR_p8to15_and_PPR2_with_psub1_in_PPR_p8to15 Register Class...
  static const MCPhysReg PPR2_with_psub_in_PNR_p8to15_and_PPR2_with_psub1_in_PPR_p8to15[] = {
    AArch64_P8_P9, AArch64_P9_P10, AArch64_P10_P11, AArch64_P11_P12, AArch64_P12_P13, AArch64_P13_P14, AArch64_P14_P15, 
  };

  // PPR2_with_psub_in_PNR_p8to15_and_PPR2_with_psub1_in_PPR_p8to15 Bit set.
  static const uint8_t PPR2_with_psub_in_PNR_p8to15_and_PPR2_with_psub1_in_PPR_p8to15Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 
  };

  // PPR2Mul2_and_PPR2_with_psub_in_PNR_3b Register Class...
  static const MCPhysReg PPR2Mul2_and_PPR2_with_psub_in_PNR_3b[] = {
    AArch64_P0_P1, AArch64_P2_P3, AArch64_P4_P5, AArch64_P6_P7, 
  };

  // PPR2Mul2_and_PPR2_with_psub_in_PNR_3b Bit set.
  static const uint8_t PPR2Mul2_and_PPR2_with_psub_in_PNR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 
  };

  // PPR2Mul2_and_PPR2_with_psub_in_PNR_p8to15 Register Class...
  static const MCPhysReg PPR2Mul2_and_PPR2_with_psub_in_PNR_p8to15[] = {
    AArch64_P8_P9, AArch64_P10_P11, AArch64_P12_P13, AArch64_P14_P15, 
  };

  // PPR2Mul2_and_PPR2_with_psub_in_PNR_p8to15 Bit set.
  static const uint8_t PPR2Mul2_and_PPR2_with_psub_in_PNR_p8to15Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 
  };

  // PPR2_with_psub_in_PNR_3b_and_PPR2_with_psub1_in_PPR_p8to15 Register Class...
  static const MCPhysReg PPR2_with_psub_in_PNR_3b_and_PPR2_with_psub1_in_PPR_p8to15[] = {
    AArch64_P7_P8, 
  };

  // PPR2_with_psub_in_PNR_3b_and_PPR2_with_psub1_in_PPR_p8to15 Bit set.
  static const uint8_t PPR2_with_psub_in_PNR_3b_and_PPR2_with_psub1_in_PPR_p8to15Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 
  };

  // PPR2_with_psub_in_PNR_p8to15_and_PPR2_with_psub1_in_PPR_3b Register Class...
  static const MCPhysReg PPR2_with_psub_in_PNR_p8to15_and_PPR2_with_psub1_in_PPR_3b[] = {
    AArch64_P15_P0, 
  };

  // PPR2_with_psub_in_PNR_p8to15_and_PPR2_with_psub1_in_PPR_3b Bit set.
  static const uint8_t PPR2_with_psub_in_PNR_p8to15_and_PPR2_with_psub1_in_PPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 
  };

  // GPR32all Register Class...
  static const MCPhysReg GPR32all[] = {
    AArch64_W0, AArch64_W1, AArch64_W2, AArch64_W3, AArch64_W4, AArch64_W5, AArch64_W6, AArch64_W7, AArch64_W8, AArch64_W9, AArch64_W10, AArch64_W11, AArch64_W12, AArch64_W13, AArch64_W14, AArch64_W15, AArch64_W16, AArch64_W17, AArch64_W18, AArch64_W19, AArch64_W20, AArch64_W21, AArch64_W22, AArch64_W23, AArch64_W24, AArch64_W25, AArch64_W26, AArch64_W27, AArch64_W28, AArch64_W29, AArch64_W30, AArch64_WZR, AArch64_WSP, 
  };

  // GPR32all Bit set.
  static const uint8_t GPR32allBits[] = {
    0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x07, 
  };

  // FPR32 Register Class...
  static const MCPhysReg FPR32[] = {
    AArch64_S0, AArch64_S1, AArch64_S2, AArch64_S3, AArch64_S4, AArch64_S5, AArch64_S6, AArch64_S7, AArch64_S8, AArch64_S9, AArch64_S10, AArch64_S11, AArch64_S12, AArch64_S13, AArch64_S14, AArch64_S15, AArch64_S16, AArch64_S17, AArch64_S18, AArch64_S19, AArch64_S20, AArch64_S21, AArch64_S22, AArch64_S23, AArch64_S24, AArch64_S25, AArch64_S26, AArch64_S27, AArch64_S28, AArch64_S29, AArch64_S30, AArch64_S31, 
  };

  // FPR32 Bit set.
  static const uint8_t FPR32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // GPR32 Register Class...
  static const MCPhysReg GPR32[] = {
    AArch64_W0, AArch64_W1, AArch64_W2, AArch64_W3, AArch64_W4, AArch64_W5, AArch64_W6, AArch64_W7, AArch64_W8, AArch64_W9, AArch64_W10, AArch64_W11, AArch64_W12, AArch64_W13, AArch64_W14, AArch64_W15, AArch64_W16, AArch64_W17, AArch64_W18, AArch64_W19, AArch64_W20, AArch64_W21, AArch64_W22, AArch64_W23, AArch64_W24, AArch64_W25, AArch64_W26, AArch64_W27, AArch64_W28, AArch64_W29, AArch64_W30, AArch64_WZR, 
  };

  // GPR32 Bit set.
  static const uint8_t GPR32Bits[] = {
    0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x07, 
  };

  // GPR32sp Register Class...
  static const MCPhysReg GPR32sp[] = {
    AArch64_W0, AArch64_W1, AArch64_W2, AArch64_W3, AArch64_W4, AArch64_W5, AArch64_W6, AArch64_W7, AArch64_W8, AArch64_W9, AArch64_W10, AArch64_W11, AArch64_W12, AArch64_W13, AArch64_W14, AArch64_W15, AArch64_W16, AArch64_W17, AArch64_W18, AArch64_W19, AArch64_W20, AArch64_W21, AArch64_W22, AArch64_W23, AArch64_W24, AArch64_W25, AArch64_W26, AArch64_W27, AArch64_W28, AArch64_W29, AArch64_W30, AArch64_WSP, 
  };

  // GPR32sp Bit set.
  static const uint8_t GPR32spBits[] = {
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x07, 
  };

  // GPR32common Register Class...
  static const MCPhysReg GPR32common[] = {
    AArch64_W0, AArch64_W1, AArch64_W2, AArch64_W3, AArch64_W4, AArch64_W5, AArch64_W6, AArch64_W7, AArch64_W8, AArch64_W9, AArch64_W10, AArch64_W11, AArch64_W12, AArch64_W13, AArch64_W14, AArch64_W15, AArch64_W16, AArch64_W17, AArch64_W18, AArch64_W19, AArch64_W20, AArch64_W21, AArch64_W22, AArch64_W23, AArch64_W24, AArch64_W25, AArch64_W26, AArch64_W27, AArch64_W28, AArch64_W29, AArch64_W30, 
  };

  // GPR32common Bit set.
  static const uint8_t GPR32commonBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x07, 
  };

  // FPR32_with_hsub_in_FPR16_lo Register Class...
  static const MCPhysReg FPR32_with_hsub_in_FPR16_lo[] = {
    AArch64_S0, AArch64_S1, AArch64_S2, AArch64_S3, AArch64_S4, AArch64_S5, AArch64_S6, AArch64_S7, AArch64_S8, AArch64_S9, AArch64_S10, AArch64_S11, AArch64_S12, AArch64_S13, AArch64_S14, AArch64_S15, 
  };

  // FPR32_with_hsub_in_FPR16_lo Bit set.
  static const uint8_t FPR32_with_hsub_in_FPR16_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // GPR32arg Register Class...
  static const MCPhysReg GPR32arg[] = {
    AArch64_W0, AArch64_W1, AArch64_W2, AArch64_W3, AArch64_W4, AArch64_W5, AArch64_W6, AArch64_W7, 
  };

  // GPR32arg Bit set.
  static const uint8_t GPR32argBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 
  };

  // MatrixIndexGPR32_12_15 Register Class...
  static const MCPhysReg MatrixIndexGPR32_12_15[] = {
    AArch64_W12, AArch64_W13, AArch64_W14, AArch64_W15, 
  };

  // MatrixIndexGPR32_12_15 Bit set.
  static const uint8_t MatrixIndexGPR32_12_15Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 
  };

  // MatrixIndexGPR32_8_11 Register Class...
  static const MCPhysReg MatrixIndexGPR32_8_11[] = {
    AArch64_W8, AArch64_W9, AArch64_W10, AArch64_W11, 
  };

  // MatrixIndexGPR32_8_11 Bit set.
  static const uint8_t MatrixIndexGPR32_8_11Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 
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
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // WSeqPairsClass_with_subo32_in_GPR32common Register Class...
  static const MCPhysReg WSeqPairsClass_with_subo32_in_GPR32common[] = {
    AArch64_W0_W1, AArch64_W2_W3, AArch64_W4_W5, AArch64_W6_W7, AArch64_W8_W9, AArch64_W10_W11, AArch64_W12_W13, AArch64_W14_W15, AArch64_W16_W17, AArch64_W18_W19, AArch64_W20_W21, AArch64_W22_W23, AArch64_W24_W25, AArch64_W26_W27, AArch64_W28_W29, 
  };

  // WSeqPairsClass_with_subo32_in_GPR32common Bit set.
  static const uint8_t WSeqPairsClass_with_subo32_in_GPR32commonBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x0f, 
  };

  // WSeqPairsClass_with_sube32_in_GPR32arg Register Class...
  static const MCPhysReg WSeqPairsClass_with_sube32_in_GPR32arg[] = {
    AArch64_W0_W1, AArch64_W2_W3, AArch64_W4_W5, AArch64_W6_W7, 
  };

  // WSeqPairsClass_with_sube32_in_GPR32arg Bit set.
  static const uint8_t WSeqPairsClass_with_sube32_in_GPR32argBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x01, 
  };

  // WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_12_15 Register Class...
  static const MCPhysReg WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_12_15[] = {
    AArch64_W12_W13, AArch64_W14_W15, 
  };

  // WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_12_15 Bit set.
  static const uint8_t WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_12_15Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 
  };

  // WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_8_11 Register Class...
  static const MCPhysReg WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_8_11[] = {
    AArch64_W8_W9, AArch64_W10_W11, 
  };

  // WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_8_11 Bit set.
  static const uint8_t WSeqPairsClass_with_sube32_in_MatrixIndexGPR32_8_11Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 
  };

  // GPR64all Register Class...
  static const MCPhysReg GPR64all[] = {
    AArch64_X0, AArch64_X1, AArch64_X2, AArch64_X3, AArch64_X4, AArch64_X5, AArch64_X6, AArch64_X7, AArch64_X8, AArch64_X9, AArch64_X10, AArch64_X11, AArch64_X12, AArch64_X13, AArch64_X14, AArch64_X15, AArch64_X16, AArch64_X17, AArch64_X18, AArch64_X19, AArch64_X20, AArch64_X21, AArch64_X22, AArch64_X23, AArch64_X24, AArch64_X25, AArch64_X26, AArch64_X27, AArch64_X28, AArch64_FP, AArch64_LR, AArch64_XZR, AArch64_SP, 
  };

  // GPR64all Bit set.
  static const uint8_t GPR64allBits[] = {
    0x54, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 
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
    0x14, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 
  };

  // GPR64sp Register Class...
  static const MCPhysReg GPR64sp[] = {
    AArch64_X0, AArch64_X1, AArch64_X2, AArch64_X3, AArch64_X4, AArch64_X5, AArch64_X6, AArch64_X7, AArch64_X8, AArch64_X9, AArch64_X10, AArch64_X11, AArch64_X12, AArch64_X13, AArch64_X14, AArch64_X15, AArch64_X16, AArch64_X17, AArch64_X18, AArch64_X19, AArch64_X20, AArch64_X21, AArch64_X22, AArch64_X23, AArch64_X24, AArch64_X25, AArch64_X26, AArch64_X27, AArch64_X28, AArch64_FP, AArch64_LR, AArch64_SP, 
  };

  // GPR64sp Bit set.
  static const uint8_t GPR64spBits[] = {
    0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 
  };

  // GPR64common Register Class...
  static const MCPhysReg GPR64common[] = {
    AArch64_X0, AArch64_X1, AArch64_X2, AArch64_X3, AArch64_X4, AArch64_X5, AArch64_X6, AArch64_X7, AArch64_X8, AArch64_X9, AArch64_X10, AArch64_X11, AArch64_X12, AArch64_X13, AArch64_X14, AArch64_X15, AArch64_X16, AArch64_X17, AArch64_X18, AArch64_X19, AArch64_X20, AArch64_X21, AArch64_X22, AArch64_X23, AArch64_X24, AArch64_X25, AArch64_X26, AArch64_X27, AArch64_X28, AArch64_FP, AArch64_LR, 
  };

  // GPR64common Bit set.
  static const uint8_t GPR64commonBits[] = {
    0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 
  };

  // GPR64noip Register Class...
  static const MCPhysReg GPR64noip[] = {
    AArch64_X0, AArch64_X1, AArch64_X2, AArch64_X3, AArch64_X4, AArch64_X5, AArch64_X6, AArch64_X7, AArch64_X8, AArch64_X9, AArch64_X10, AArch64_X11, AArch64_X12, AArch64_X13, AArch64_X14, AArch64_X15, AArch64_X18, AArch64_X19, AArch64_X20, AArch64_X21, AArch64_X22, AArch64_X23, AArch64_X24, AArch64_X25, AArch64_X26, AArch64_X27, AArch64_X28, AArch64_FP, AArch64_XZR, 
  };

  // GPR64noip Bit set.
  static const uint8_t GPR64noipBits[] = {
    0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xe7, 0xff, 
  };

  // GPR64common_and_GPR64noip Register Class...
  static const MCPhysReg GPR64common_and_GPR64noip[] = {
    AArch64_X0, AArch64_X1, AArch64_X2, AArch64_X3, AArch64_X4, AArch64_X5, AArch64_X6, AArch64_X7, AArch64_X8, AArch64_X9, AArch64_X10, AArch64_X11, AArch64_X12, AArch64_X13, AArch64_X14, AArch64_X15, AArch64_X18, AArch64_X19, AArch64_X20, AArch64_X21, AArch64_X22, AArch64_X23, AArch64_X24, AArch64_X25, AArch64_X26, AArch64_X27, AArch64_X28, AArch64_FP, 
  };

  // GPR64common_and_GPR64noip Bit set.
  static const uint8_t GPR64common_and_GPR64noipBits[] = {
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xe7, 0xff, 
  };

  // tcGPR64 Register Class...
  static const MCPhysReg tcGPR64[] = {
    AArch64_X0, AArch64_X1, AArch64_X2, AArch64_X3, AArch64_X4, AArch64_X5, AArch64_X6, AArch64_X7, AArch64_X8, AArch64_X9, AArch64_X10, AArch64_X11, AArch64_X12, AArch64_X13, AArch64_X14, AArch64_X15, AArch64_X16, AArch64_X17, AArch64_X18, 
  };

  // tcGPR64 Bit set.
  static const uint8_t tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x3f, 
  };

  // GPR64noip_and_tcGPR64 Register Class...
  static const MCPhysReg GPR64noip_and_tcGPR64[] = {
    AArch64_X0, AArch64_X1, AArch64_X2, AArch64_X3, AArch64_X4, AArch64_X5, AArch64_X6, AArch64_X7, AArch64_X8, AArch64_X9, AArch64_X10, AArch64_X11, AArch64_X12, AArch64_X13, AArch64_X14, AArch64_X15, AArch64_X18, 
  };

  // GPR64noip_and_tcGPR64 Bit set.
  static const uint8_t GPR64noip_and_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x27, 
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
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x07, 
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
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x07, 
  };

  // GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Register Class...
  static const MCPhysReg GPR64_with_sub_32_in_MatrixIndexGPR32_8_11[] = {
    AArch64_X8, AArch64_X9, AArch64_X10, AArch64_X11, 
  };

  // GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Bit set.
  static const uint8_t GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 
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
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 
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
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 
  };

  // DD_with_dsub0_in_FPR64_lo Register Class...
  static const MCPhysReg DD_with_dsub0_in_FPR64_lo[] = {
    AArch64_D0_D1, AArch64_D1_D2, AArch64_D2_D3, AArch64_D3_D4, AArch64_D4_D5, AArch64_D5_D6, AArch64_D6_D7, AArch64_D7_D8, AArch64_D8_D9, AArch64_D9_D10, AArch64_D10_D11, AArch64_D11_D12, AArch64_D12_D13, AArch64_D13_D14, AArch64_D14_D15, AArch64_D15_D16, 
  };

  // DD_with_dsub0_in_FPR64_lo Bit set.
  static const uint8_t DD_with_dsub0_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 
  };

  // DD_with_dsub1_in_FPR64_lo Register Class...
  static const MCPhysReg DD_with_dsub1_in_FPR64_lo[] = {
    AArch64_D0_D1, AArch64_D1_D2, AArch64_D2_D3, AArch64_D3_D4, AArch64_D4_D5, AArch64_D5_D6, AArch64_D6_D7, AArch64_D7_D8, AArch64_D8_D9, AArch64_D9_D10, AArch64_D10_D11, AArch64_D11_D12, AArch64_D12_D13, AArch64_D13_D14, AArch64_D14_D15, AArch64_D31_D0, 
  };

  // DD_with_dsub1_in_FPR64_lo Bit set.
  static const uint8_t DD_with_dsub1_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, 0x00, 0x80, 
  };

  // XSeqPairsClass Register Class...
  static const MCPhysReg XSeqPairsClass[] = {
    AArch64_X0_X1, AArch64_X2_X3, AArch64_X4_X5, AArch64_X6_X7, AArch64_X8_X9, AArch64_X10_X11, AArch64_X12_X13, AArch64_X14_X15, AArch64_X16_X17, AArch64_X18_X19, AArch64_X20_X21, AArch64_X22_X23, AArch64_X24_X25, AArch64_X26_X27, AArch64_X28_FP, AArch64_LR_XZR, 
  };

  // XSeqPairsClass Bit set.
  static const uint8_t XSeqPairsClassBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // DD_with_dsub0_in_FPR64_lo_and_DD_with_dsub1_in_FPR64_lo Register Class...
  static const MCPhysReg DD_with_dsub0_in_FPR64_lo_and_DD_with_dsub1_in_FPR64_lo[] = {
    AArch64_D0_D1, AArch64_D1_D2, AArch64_D2_D3, AArch64_D3_D4, AArch64_D4_D5, AArch64_D5_D6, AArch64_D6_D7, AArch64_D7_D8, AArch64_D8_D9, AArch64_D9_D10, AArch64_D10_D11, AArch64_D11_D12, AArch64_D12_D13, AArch64_D13_D14, AArch64_D14_D15, 
  };

  // DD_with_dsub0_in_FPR64_lo_and_DD_with_dsub1_in_FPR64_lo Bit set.
  static const uint8_t DD_with_dsub0_in_FPR64_lo_and_DD_with_dsub1_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, 
  };

  // XSeqPairsClass_with_subo64_in_GPR64common Register Class...
  static const MCPhysReg XSeqPairsClass_with_subo64_in_GPR64common[] = {
    AArch64_X0_X1, AArch64_X2_X3, AArch64_X4_X5, AArch64_X6_X7, AArch64_X8_X9, AArch64_X10_X11, AArch64_X12_X13, AArch64_X14_X15, AArch64_X16_X17, AArch64_X18_X19, AArch64_X20_X21, AArch64_X22_X23, AArch64_X24_X25, AArch64_X26_X27, AArch64_X28_FP, 
  };

  // XSeqPairsClass_with_subo64_in_GPR64common Bit set.
  static const uint8_t XSeqPairsClass_with_subo64_in_GPR64commonBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0x0f, 
  };

  // XSeqPairsClass_with_subo64_in_GPR64noip Register Class...
  static const MCPhysReg XSeqPairsClass_with_subo64_in_GPR64noip[] = {
    AArch64_X0_X1, AArch64_X2_X3, AArch64_X4_X5, AArch64_X6_X7, AArch64_X8_X9, AArch64_X10_X11, AArch64_X12_X13, AArch64_X14_X15, AArch64_X18_X19, AArch64_X20_X21, AArch64_X22_X23, AArch64_X24_X25, AArch64_X26_X27, AArch64_X28_FP, AArch64_LR_XZR, 
  };

  // XSeqPairsClass_with_subo64_in_GPR64noip Bit set.
  static const uint8_t XSeqPairsClass_with_subo64_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xbf, 0x0f, 
  };

  // XSeqPairsClass_with_sube64_in_GPR64noip Register Class...
  static const MCPhysReg XSeqPairsClass_with_sube64_in_GPR64noip[] = {
    AArch64_X0_X1, AArch64_X2_X3, AArch64_X4_X5, AArch64_X6_X7, AArch64_X8_X9, AArch64_X10_X11, AArch64_X12_X13, AArch64_X14_X15, AArch64_X18_X19, AArch64_X20_X21, AArch64_X22_X23, AArch64_X24_X25, AArch64_X26_X27, AArch64_X28_FP, 
  };

  // XSeqPairsClass_with_sube64_in_GPR64noip Bit set.
  static const uint8_t XSeqPairsClass_with_sube64_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xbf, 0x0f, 
  };

  // XSeqPairsClass_with_sube64_in_tcGPR64 Register Class...
  static const MCPhysReg XSeqPairsClass_with_sube64_in_tcGPR64[] = {
    AArch64_X0_X1, AArch64_X2_X3, AArch64_X4_X5, AArch64_X6_X7, AArch64_X8_X9, AArch64_X10_X11, AArch64_X12_X13, AArch64_X14_X15, AArch64_X16_X17, AArch64_X18_X19, 
  };

  // XSeqPairsClass_with_sube64_in_tcGPR64 Bit set.
  static const uint8_t XSeqPairsClass_with_sube64_in_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 
  };

  // XSeqPairsClass_with_sube64_in_GPR64noip_and_tcGPR64 Register Class...
  static const MCPhysReg XSeqPairsClass_with_sube64_in_GPR64noip_and_tcGPR64[] = {
    AArch64_X0_X1, AArch64_X2_X3, AArch64_X4_X5, AArch64_X6_X7, AArch64_X8_X9, AArch64_X10_X11, AArch64_X12_X13, AArch64_X14_X15, AArch64_X18_X19, 
  };

  // XSeqPairsClass_with_sube64_in_GPR64noip_and_tcGPR64 Bit set.
  static const uint8_t XSeqPairsClass_with_sube64_in_GPR64noip_and_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xbf, 
  };

  // XSeqPairsClass_with_subo64_in_tcGPR64 Register Class...
  static const MCPhysReg XSeqPairsClass_with_subo64_in_tcGPR64[] = {
    AArch64_X0_X1, AArch64_X2_X3, AArch64_X4_X5, AArch64_X6_X7, AArch64_X8_X9, AArch64_X10_X11, AArch64_X12_X13, AArch64_X14_X15, AArch64_X16_X17, 
  };

  // XSeqPairsClass_with_subo64_in_tcGPR64 Bit set.
  static const uint8_t XSeqPairsClass_with_subo64_in_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x7f, 
  };

  // XSeqPairsClass_with_subo64_in_GPR64noip_and_tcGPR64 Register Class...
  static const MCPhysReg XSeqPairsClass_with_subo64_in_GPR64noip_and_tcGPR64[] = {
    AArch64_X0_X1, AArch64_X2_X3, AArch64_X4_X5, AArch64_X6_X7, AArch64_X8_X9, AArch64_X10_X11, AArch64_X12_X13, AArch64_X14_X15, 
  };

  // XSeqPairsClass_with_subo64_in_GPR64noip_and_tcGPR64 Bit set.
  static const uint8_t XSeqPairsClass_with_subo64_in_GPR64noip_and_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 
  };

  // XSeqPairsClass_with_sub_32_in_GPR32arg Register Class...
  static const MCPhysReg XSeqPairsClass_with_sub_32_in_GPR32arg[] = {
    AArch64_X0_X1, AArch64_X2_X3, AArch64_X4_X5, AArch64_X6_X7, 
  };

  // XSeqPairsClass_with_sub_32_in_GPR32arg Bit set.
  static const uint8_t XSeqPairsClass_with_sub_32_in_GPR32argBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x03, 
  };

  // XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_12_15 Register Class...
  static const MCPhysReg XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_12_15[] = {
    AArch64_X12_X13, AArch64_X14_X15, 
  };

  // XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_12_15 Bit set.
  static const uint8_t XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_12_15Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 
  };

  // XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_8_11 Register Class...
  static const MCPhysReg XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_8_11[] = {
    AArch64_X8_X9, AArch64_X10_X11, 
  };

  // XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_8_11 Bit set.
  static const uint8_t XSeqPairsClass_with_sub_32_in_MatrixIndexGPR32_8_11Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 
  };

  // XSeqPairsClass_with_sube64_in_rtcGPR64 Register Class...
  static const MCPhysReg XSeqPairsClass_with_sube64_in_rtcGPR64[] = {
    AArch64_X16_X17, 
  };

  // XSeqPairsClass_with_sube64_in_rtcGPR64 Bit set.
  static const uint8_t XSeqPairsClass_with_sube64_in_rtcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 
  };

  // XSeqPairsClass_with_subo64_in_FIXED_REGS Register Class...
  static const MCPhysReg XSeqPairsClass_with_subo64_in_FIXED_REGS[] = {
    AArch64_X28_FP, 
  };

  // XSeqPairsClass_with_subo64_in_FIXED_REGS Bit set.
  static const uint8_t XSeqPairsClass_with_subo64_in_FIXED_REGSBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 
  };

  // FPR128 Register Class...
  static const MCPhysReg FPR128[] = {
    AArch64_Q0, AArch64_Q1, AArch64_Q2, AArch64_Q3, AArch64_Q4, AArch64_Q5, AArch64_Q6, AArch64_Q7, AArch64_Q8, AArch64_Q9, AArch64_Q10, AArch64_Q11, AArch64_Q12, AArch64_Q13, AArch64_Q14, AArch64_Q15, AArch64_Q16, AArch64_Q17, AArch64_Q18, AArch64_Q19, AArch64_Q20, AArch64_Q21, AArch64_Q22, AArch64_Q23, AArch64_Q24, AArch64_Q25, AArch64_Q26, AArch64_Q27, AArch64_Q28, AArch64_Q29, AArch64_Q30, AArch64_Q31, 
  };

  // FPR128 Bit set.
  static const uint8_t FPR128Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // ZPR Register Class...
  static const MCPhysReg ZPR[] = {
    AArch64_Z0, AArch64_Z1, AArch64_Z2, AArch64_Z3, AArch64_Z4, AArch64_Z5, AArch64_Z6, AArch64_Z7, AArch64_Z8, AArch64_Z9, AArch64_Z10, AArch64_Z11, AArch64_Z12, AArch64_Z13, AArch64_Z14, AArch64_Z15, AArch64_Z16, AArch64_Z17, AArch64_Z18, AArch64_Z19, AArch64_Z20, AArch64_Z21, AArch64_Z22, AArch64_Z23, AArch64_Z24, AArch64_Z25, AArch64_Z26, AArch64_Z27, AArch64_Z28, AArch64_Z29, AArch64_Z30, AArch64_Z31, 
  };

  // ZPR Bit set.
  static const uint8_t ZPRBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 
  };

  // FPR128_lo Register Class...
  static const MCPhysReg FPR128_lo[] = {
    AArch64_Q0, AArch64_Q1, AArch64_Q2, AArch64_Q3, AArch64_Q4, AArch64_Q5, AArch64_Q6, AArch64_Q7, AArch64_Q8, AArch64_Q9, AArch64_Q10, AArch64_Q11, AArch64_Q12, AArch64_Q13, AArch64_Q14, AArch64_Q15, 
  };

  // FPR128_lo Bit set.
  static const uint8_t FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // MPR128 Register Class...
  static const MCPhysReg MPR128[] = {
    AArch64_ZAQ0, AArch64_ZAQ1, AArch64_ZAQ2, AArch64_ZAQ3, AArch64_ZAQ4, AArch64_ZAQ5, AArch64_ZAQ6, AArch64_ZAQ7, AArch64_ZAQ8, AArch64_ZAQ9, AArch64_ZAQ10, AArch64_ZAQ11, AArch64_ZAQ12, AArch64_ZAQ13, AArch64_ZAQ14, AArch64_ZAQ15, 
  };

  // MPR128 Bit set.
  static const uint8_t MPR128Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x07, 
  };

  // ZPR_4b Register Class...
  static const MCPhysReg ZPR_4b[] = {
    AArch64_Z0, AArch64_Z1, AArch64_Z2, AArch64_Z3, AArch64_Z4, AArch64_Z5, AArch64_Z6, AArch64_Z7, AArch64_Z8, AArch64_Z9, AArch64_Z10, AArch64_Z11, AArch64_Z12, AArch64_Z13, AArch64_Z14, AArch64_Z15, 
  };

  // ZPR_4b Bit set.
  static const uint8_t ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 
  };

  // FPR128_0to7 Register Class...
  static const MCPhysReg FPR128_0to7[] = {
    AArch64_Q0, AArch64_Q1, AArch64_Q2, AArch64_Q3, AArch64_Q4, AArch64_Q5, AArch64_Q6, AArch64_Q7, 
  };

  // FPR128_0to7 Bit set.
  static const uint8_t FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 
  };

  // ZPR_3b Register Class...
  static const MCPhysReg ZPR_3b[] = {
    AArch64_Z0, AArch64_Z1, AArch64_Z2, AArch64_Z3, AArch64_Z4, AArch64_Z5, AArch64_Z6, AArch64_Z7, 
  };

  // ZPR_3b Bit set.
  static const uint8_t ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 
  };

  // DDD Register Class...
  static const MCPhysReg DDD[] = {
    AArch64_D0_D1_D2, AArch64_D1_D2_D3, AArch64_D2_D3_D4, AArch64_D3_D4_D5, AArch64_D4_D5_D6, AArch64_D5_D6_D7, AArch64_D6_D7_D8, AArch64_D7_D8_D9, AArch64_D8_D9_D10, AArch64_D9_D10_D11, AArch64_D10_D11_D12, AArch64_D11_D12_D13, AArch64_D12_D13_D14, AArch64_D13_D14_D15, AArch64_D14_D15_D16, AArch64_D15_D16_D17, AArch64_D16_D17_D18, AArch64_D17_D18_D19, AArch64_D18_D19_D20, AArch64_D19_D20_D21, AArch64_D20_D21_D22, AArch64_D21_D22_D23, AArch64_D22_D23_D24, AArch64_D23_D24_D25, AArch64_D24_D25_D26, AArch64_D25_D26_D27, AArch64_D26_D27_D28, AArch64_D27_D28_D29, AArch64_D28_D29_D30, AArch64_D29_D30_D31, AArch64_D30_D31_D0, AArch64_D31_D0_D1, 
  };

  // DDD Bit set.
  static const uint8_t DDDBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 
  };

  // DDD_with_dsub0_in_FPR64_lo Register Class...
  static const MCPhysReg DDD_with_dsub0_in_FPR64_lo[] = {
    AArch64_D0_D1_D2, AArch64_D1_D2_D3, AArch64_D2_D3_D4, AArch64_D3_D4_D5, AArch64_D4_D5_D6, AArch64_D5_D6_D7, AArch64_D6_D7_D8, AArch64_D7_D8_D9, AArch64_D8_D9_D10, AArch64_D9_D10_D11, AArch64_D10_D11_D12, AArch64_D11_D12_D13, AArch64_D12_D13_D14, AArch64_D13_D14_D15, AArch64_D14_D15_D16, AArch64_D15_D16_D17, 
  };

  // DDD_with_dsub0_in_FPR64_lo Bit set.
  static const uint8_t DDD_with_dsub0_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 
  };

  // DDD_with_dsub1_in_FPR64_lo Register Class...
  static const MCPhysReg DDD_with_dsub1_in_FPR64_lo[] = {
    AArch64_D0_D1_D2, AArch64_D1_D2_D3, AArch64_D2_D3_D4, AArch64_D3_D4_D5, AArch64_D4_D5_D6, AArch64_D5_D6_D7, AArch64_D6_D7_D8, AArch64_D7_D8_D9, AArch64_D8_D9_D10, AArch64_D9_D10_D11, AArch64_D10_D11_D12, AArch64_D11_D12_D13, AArch64_D12_D13_D14, AArch64_D13_D14_D15, AArch64_D14_D15_D16, AArch64_D31_D0_D1, 
  };

  // DDD_with_dsub1_in_FPR64_lo Bit set.
  static const uint8_t DDD_with_dsub1_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, 0x00, 0x80, 
  };

  // DDD_with_dsub2_in_FPR64_lo Register Class...
  static const MCPhysReg DDD_with_dsub2_in_FPR64_lo[] = {
    AArch64_D0_D1_D2, AArch64_D1_D2_D3, AArch64_D2_D3_D4, AArch64_D3_D4_D5, AArch64_D4_D5_D6, AArch64_D5_D6_D7, AArch64_D6_D7_D8, AArch64_D7_D8_D9, AArch64_D8_D9_D10, AArch64_D9_D10_D11, AArch64_D10_D11_D12, AArch64_D11_D12_D13, AArch64_D12_D13_D14, AArch64_D13_D14_D15, AArch64_D30_D31_D0, AArch64_D31_D0_D1, 
  };

  // DDD_with_dsub2_in_FPR64_lo Bit set.
  static const uint8_t DDD_with_dsub2_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x3f, 0x00, 0xc0, 
  };

  // DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub1_in_FPR64_lo Register Class...
  static const MCPhysReg DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub1_in_FPR64_lo[] = {
    AArch64_D0_D1_D2, AArch64_D1_D2_D3, AArch64_D2_D3_D4, AArch64_D3_D4_D5, AArch64_D4_D5_D6, AArch64_D5_D6_D7, AArch64_D6_D7_D8, AArch64_D7_D8_D9, AArch64_D8_D9_D10, AArch64_D9_D10_D11, AArch64_D10_D11_D12, AArch64_D11_D12_D13, AArch64_D12_D13_D14, AArch64_D13_D14_D15, AArch64_D14_D15_D16, 
  };

  // DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub1_in_FPR64_lo Bit set.
  static const uint8_t DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub1_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, 
  };

  // DDD_with_dsub1_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_lo Register Class...
  static const MCPhysReg DDD_with_dsub1_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_lo[] = {
    AArch64_D0_D1_D2, AArch64_D1_D2_D3, AArch64_D2_D3_D4, AArch64_D3_D4_D5, AArch64_D4_D5_D6, AArch64_D5_D6_D7, AArch64_D6_D7_D8, AArch64_D7_D8_D9, AArch64_D8_D9_D10, AArch64_D9_D10_D11, AArch64_D10_D11_D12, AArch64_D11_D12_D13, AArch64_D12_D13_D14, AArch64_D13_D14_D15, AArch64_D31_D0_D1, 
  };

  // DDD_with_dsub1_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_lo Bit set.
  static const uint8_t DDD_with_dsub1_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x3f, 0x00, 0x80, 
  };

  // DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_lo Register Class...
  static const MCPhysReg DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_lo[] = {
    AArch64_D0_D1_D2, AArch64_D1_D2_D3, AArch64_D2_D3_D4, AArch64_D3_D4_D5, AArch64_D4_D5_D6, AArch64_D5_D6_D7, AArch64_D6_D7_D8, AArch64_D7_D8_D9, AArch64_D8_D9_D10, AArch64_D9_D10_D11, AArch64_D10_D11_D12, AArch64_D11_D12_D13, AArch64_D12_D13_D14, AArch64_D13_D14_D15, 
  };

  // DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_lo Bit set.
  static const uint8_t DDD_with_dsub0_in_FPR64_lo_and_DDD_with_dsub2_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x3f, 
  };

  // DDDD Register Class...
  static const MCPhysReg DDDD[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D13_D14_D15_D16, AArch64_D14_D15_D16_D17, AArch64_D15_D16_D17_D18, AArch64_D16_D17_D18_D19, AArch64_D17_D18_D19_D20, AArch64_D18_D19_D20_D21, AArch64_D19_D20_D21_D22, AArch64_D20_D21_D22_D23, AArch64_D21_D22_D23_D24, AArch64_D22_D23_D24_D25, AArch64_D23_D24_D25_D26, AArch64_D24_D25_D26_D27, AArch64_D25_D26_D27_D28, AArch64_D26_D27_D28_D29, AArch64_D27_D28_D29_D30, AArch64_D28_D29_D30_D31, AArch64_D29_D30_D31_D0, AArch64_D30_D31_D0_D1, AArch64_D31_D0_D1_D2, 
  };

  // DDDD Bit set.
  static const uint8_t DDDDBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 
  };

  // DDDD_with_dsub0_in_FPR64_lo Register Class...
  static const MCPhysReg DDDD_with_dsub0_in_FPR64_lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D13_D14_D15_D16, AArch64_D14_D15_D16_D17, AArch64_D15_D16_D17_D18, 
  };

  // DDDD_with_dsub0_in_FPR64_lo Bit set.
  static const uint8_t DDDD_with_dsub0_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 
  };

  // DDDD_with_dsub1_in_FPR64_lo Register Class...
  static const MCPhysReg DDDD_with_dsub1_in_FPR64_lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D13_D14_D15_D16, AArch64_D14_D15_D16_D17, AArch64_D31_D0_D1_D2, 
  };

  // DDDD_with_dsub1_in_FPR64_lo Bit set.
  static const uint8_t DDDD_with_dsub1_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, 0x00, 0x80, 
  };

  // DDDD_with_dsub2_in_FPR64_lo Register Class...
  static const MCPhysReg DDDD_with_dsub2_in_FPR64_lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D13_D14_D15_D16, AArch64_D30_D31_D0_D1, AArch64_D31_D0_D1_D2, 
  };

  // DDDD_with_dsub2_in_FPR64_lo Bit set.
  static const uint8_t DDDD_with_dsub2_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x3f, 0x00, 0xc0, 
  };

  // DDDD_with_dsub3_in_FPR64_lo Register Class...
  static const MCPhysReg DDDD_with_dsub3_in_FPR64_lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D29_D30_D31_D0, AArch64_D30_D31_D0_D1, AArch64_D31_D0_D1_D2, 
  };

  // DDDD_with_dsub3_in_FPR64_lo Bit set.
  static const uint8_t DDDD_with_dsub3_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x1f, 0x00, 0xe0, 
  };

  // DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub1_in_FPR64_lo Register Class...
  static const MCPhysReg DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub1_in_FPR64_lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D13_D14_D15_D16, AArch64_D14_D15_D16_D17, 
  };

  // DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub1_in_FPR64_lo Bit set.
  static const uint8_t DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub1_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, 
  };

  // DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_lo Register Class...
  static const MCPhysReg DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D13_D14_D15_D16, AArch64_D31_D0_D1_D2, 
  };

  // DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_lo Bit set.
  static const uint8_t DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x3f, 0x00, 0x80, 
  };

  // DDDD_with_dsub2_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_lo Register Class...
  static const MCPhysReg DDDD_with_dsub2_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D30_D31_D0_D1, AArch64_D31_D0_D1_D2, 
  };

  // DDDD_with_dsub2_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_lo Bit set.
  static const uint8_t DDDD_with_dsub2_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x1f, 0x00, 0xc0, 
  };

  // DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_lo Register Class...
  static const MCPhysReg DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D13_D14_D15_D16, 
  };

  // DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_lo Bit set.
  static const uint8_t DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub2_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x3f, 
  };

  // DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_lo Register Class...
  static const MCPhysReg DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, AArch64_D31_D0_D1_D2, 
  };

  // DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_lo Bit set.
  static const uint8_t DDDD_with_dsub1_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x1f, 0x00, 0x80, 
  };

  // DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_lo Register Class...
  static const MCPhysReg DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_lo[] = {
    AArch64_D0_D1_D2_D3, AArch64_D1_D2_D3_D4, AArch64_D2_D3_D4_D5, AArch64_D3_D4_D5_D6, AArch64_D4_D5_D6_D7, AArch64_D5_D6_D7_D8, AArch64_D6_D7_D8_D9, AArch64_D7_D8_D9_D10, AArch64_D8_D9_D10_D11, AArch64_D9_D10_D11_D12, AArch64_D10_D11_D12_D13, AArch64_D11_D12_D13_D14, AArch64_D12_D13_D14_D15, 
  };

  // DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_lo Bit set.
  static const uint8_t DDDD_with_dsub0_in_FPR64_lo_and_DDDD_with_dsub3_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x1f, 
  };

  // QQ Register Class...
  static const MCPhysReg QQ[] = {
    AArch64_Q0_Q1, AArch64_Q1_Q2, AArch64_Q2_Q3, AArch64_Q3_Q4, AArch64_Q4_Q5, AArch64_Q5_Q6, AArch64_Q6_Q7, AArch64_Q7_Q8, AArch64_Q8_Q9, AArch64_Q9_Q10, AArch64_Q10_Q11, AArch64_Q11_Q12, AArch64_Q12_Q13, AArch64_Q13_Q14, AArch64_Q14_Q15, AArch64_Q15_Q16, AArch64_Q16_Q17, AArch64_Q17_Q18, AArch64_Q18_Q19, AArch64_Q19_Q20, AArch64_Q20_Q21, AArch64_Q21_Q22, AArch64_Q22_Q23, AArch64_Q23_Q24, AArch64_Q24_Q25, AArch64_Q25_Q26, AArch64_Q26_Q27, AArch64_Q27_Q28, AArch64_Q28_Q29, AArch64_Q29_Q30, AArch64_Q30_Q31, AArch64_Q31_Q0, 
  };

  // QQ Bit set.
  static const uint8_t QQBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 
  };

  // ZPR2 Register Class...
  static const MCPhysReg ZPR2[] = {
    AArch64_Z0_Z1, AArch64_Z1_Z2, AArch64_Z2_Z3, AArch64_Z3_Z4, AArch64_Z4_Z5, AArch64_Z5_Z6, AArch64_Z6_Z7, AArch64_Z7_Z8, AArch64_Z8_Z9, AArch64_Z9_Z10, AArch64_Z10_Z11, AArch64_Z11_Z12, AArch64_Z12_Z13, AArch64_Z13_Z14, AArch64_Z14_Z15, AArch64_Z15_Z16, AArch64_Z16_Z17, AArch64_Z17_Z18, AArch64_Z18_Z19, AArch64_Z19_Z20, AArch64_Z20_Z21, AArch64_Z21_Z22, AArch64_Z22_Z23, AArch64_Z23_Z24, AArch64_Z24_Z25, AArch64_Z25_Z26, AArch64_Z26_Z27, AArch64_Z27_Z28, AArch64_Z28_Z29, AArch64_Z29_Z30, AArch64_Z30_Z31, AArch64_Z31_Z0, 
  };

  // ZPR2 Bit set.
  static const uint8_t ZPR2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // ZPR2StridedOrContiguous Register Class...
  static const MCPhysReg ZPR2StridedOrContiguous[] = {
    AArch64_Z0_Z8, AArch64_Z1_Z9, AArch64_Z2_Z10, AArch64_Z3_Z11, AArch64_Z4_Z12, AArch64_Z5_Z13, AArch64_Z6_Z14, AArch64_Z7_Z15, AArch64_Z16_Z24, AArch64_Z17_Z25, AArch64_Z18_Z26, AArch64_Z19_Z27, AArch64_Z20_Z28, AArch64_Z21_Z29, AArch64_Z22_Z30, AArch64_Z23_Z31, AArch64_Z0_Z1, AArch64_Z2_Z3, AArch64_Z4_Z5, AArch64_Z6_Z7, AArch64_Z8_Z9, AArch64_Z10_Z11, AArch64_Z12_Z13, AArch64_Z14_Z15, AArch64_Z16_Z17, AArch64_Z18_Z19, AArch64_Z20_Z21, AArch64_Z22_Z23, AArch64_Z24_Z25, AArch64_Z26_Z27, AArch64_Z28_Z29, AArch64_Z30_Z31, 
  };

  // ZPR2StridedOrContiguous Bit set.
  static const uint8_t ZPR2StridedOrContiguousBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x55, 0x55, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // QQ_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg QQ_with_dsub_in_FPR64_lo[] = {
    AArch64_Q0_Q1, AArch64_Q1_Q2, AArch64_Q2_Q3, AArch64_Q3_Q4, AArch64_Q4_Q5, AArch64_Q5_Q6, AArch64_Q6_Q7, AArch64_Q7_Q8, AArch64_Q8_Q9, AArch64_Q9_Q10, AArch64_Q10_Q11, AArch64_Q11_Q12, AArch64_Q12_Q13, AArch64_Q13_Q14, AArch64_Q14_Q15, AArch64_Q15_Q16, 
  };

  // QQ_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t QQ_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 
  };

  // QQ_with_qsub1_in_FPR128_lo Register Class...
  static const MCPhysReg QQ_with_qsub1_in_FPR128_lo[] = {
    AArch64_Q0_Q1, AArch64_Q1_Q2, AArch64_Q2_Q3, AArch64_Q3_Q4, AArch64_Q4_Q5, AArch64_Q5_Q6, AArch64_Q6_Q7, AArch64_Q7_Q8, AArch64_Q8_Q9, AArch64_Q9_Q10, AArch64_Q10_Q11, AArch64_Q11_Q12, AArch64_Q12_Q13, AArch64_Q13_Q14, AArch64_Q14_Q15, AArch64_Q31_Q0, 
  };

  // QQ_with_qsub1_in_FPR128_lo Bit set.
  static const uint8_t QQ_with_qsub1_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, 0x00, 0x80, 
  };

  // ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR2Mul2[] = {
    AArch64_Z0_Z1, AArch64_Z2_Z3, AArch64_Z4_Z5, AArch64_Z6_Z7, AArch64_Z8_Z9, AArch64_Z10_Z11, AArch64_Z12_Z13, AArch64_Z14_Z15, AArch64_Z16_Z17, AArch64_Z18_Z19, AArch64_Z20_Z21, AArch64_Z22_Z23, AArch64_Z24_Z25, AArch64_Z26_Z27, AArch64_Z28_Z29, AArch64_Z30_Z31, 
  };

  // ZPR2Mul2 Bit set.
  static const uint8_t ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x55, 0x55, 0x05, 
  };

  // ZPR2Strided Register Class...
  static const MCPhysReg ZPR2Strided[] = {
    AArch64_Z0_Z8, AArch64_Z1_Z9, AArch64_Z2_Z10, AArch64_Z3_Z11, AArch64_Z4_Z12, AArch64_Z5_Z13, AArch64_Z6_Z14, AArch64_Z7_Z15, AArch64_Z16_Z24, AArch64_Z17_Z25, AArch64_Z18_Z26, AArch64_Z19_Z27, AArch64_Z20_Z28, AArch64_Z21_Z29, AArch64_Z22_Z30, AArch64_Z23_Z31, 
  };

  // ZPR2Strided Bit set.
  static const uint8_t ZPR2StridedBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // ZPR2StridedOrContiguous_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR2StridedOrContiguous_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z8, AArch64_Z1_Z9, AArch64_Z2_Z10, AArch64_Z3_Z11, AArch64_Z4_Z12, AArch64_Z5_Z13, AArch64_Z6_Z14, AArch64_Z7_Z15, AArch64_Z0_Z1, AArch64_Z2_Z3, AArch64_Z4_Z5, AArch64_Z6_Z7, AArch64_Z8_Z9, AArch64_Z10_Z11, AArch64_Z12_Z13, AArch64_Z14_Z15, 
  };

  // ZPR2StridedOrContiguous_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR2StridedOrContiguous_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 
  };

  // ZPR2_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR2_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z1, AArch64_Z1_Z2, AArch64_Z2_Z3, AArch64_Z3_Z4, AArch64_Z4_Z5, AArch64_Z5_Z6, AArch64_Z6_Z7, AArch64_Z7_Z8, AArch64_Z8_Z9, AArch64_Z9_Z10, AArch64_Z10_Z11, AArch64_Z11_Z12, AArch64_Z12_Z13, AArch64_Z13_Z14, AArch64_Z14_Z15, AArch64_Z15_Z16, 
  };

  // ZPR2_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR2_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // ZPR2_with_zsub1_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR2_with_zsub1_in_ZPR_4b[] = {
    AArch64_Z0_Z1, AArch64_Z1_Z2, AArch64_Z2_Z3, AArch64_Z3_Z4, AArch64_Z4_Z5, AArch64_Z5_Z6, AArch64_Z6_Z7, AArch64_Z7_Z8, AArch64_Z8_Z9, AArch64_Z9_Z10, AArch64_Z10_Z11, AArch64_Z11_Z12, AArch64_Z12_Z13, AArch64_Z13_Z14, AArch64_Z14_Z15, AArch64_Z31_Z0, 
  };

  // ZPR2_with_zsub1_in_ZPR_4b Bit set.
  static const uint8_t ZPR2_with_zsub1_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 0x00, 0x08, 
  };

  // QQ_with_dsub_in_FPR64_lo_and_QQ_with_qsub1_in_FPR128_lo Register Class...
  static const MCPhysReg QQ_with_dsub_in_FPR64_lo_and_QQ_with_qsub1_in_FPR128_lo[] = {
    AArch64_Q0_Q1, AArch64_Q1_Q2, AArch64_Q2_Q3, AArch64_Q3_Q4, AArch64_Q4_Q5, AArch64_Q5_Q6, AArch64_Q6_Q7, AArch64_Q7_Q8, AArch64_Q8_Q9, AArch64_Q9_Q10, AArch64_Q10_Q11, AArch64_Q11_Q12, AArch64_Q12_Q13, AArch64_Q13_Q14, AArch64_Q14_Q15, 
  };

  // QQ_with_dsub_in_FPR64_lo_and_QQ_with_qsub1_in_FPR128_lo Bit set.
  static const uint8_t QQ_with_dsub_in_FPR64_lo_and_QQ_with_qsub1_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, 
  };

  // ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_4b[] = {
    AArch64_Z0_Z1, AArch64_Z1_Z2, AArch64_Z2_Z3, AArch64_Z3_Z4, AArch64_Z4_Z5, AArch64_Z5_Z6, AArch64_Z6_Z7, AArch64_Z7_Z8, AArch64_Z8_Z9, AArch64_Z9_Z10, AArch64_Z10_Z11, AArch64_Z11_Z12, AArch64_Z12_Z13, AArch64_Z13_Z14, AArch64_Z14_Z15, 
  };

  // ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_4b Bit set.
  static const uint8_t ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 
  };

  // ZPR2StridedOrContiguous_with_zsub_in_FPR128_0to7 Register Class...
  static const MCPhysReg ZPR2StridedOrContiguous_with_zsub_in_FPR128_0to7[] = {
    AArch64_Z0_Z8, AArch64_Z1_Z9, AArch64_Z2_Z10, AArch64_Z3_Z11, AArch64_Z4_Z12, AArch64_Z5_Z13, AArch64_Z6_Z14, AArch64_Z7_Z15, AArch64_Z0_Z1, AArch64_Z2_Z3, AArch64_Z4_Z5, AArch64_Z6_Z7, 
  };

  // ZPR2StridedOrContiguous_with_zsub_in_FPR128_0to7 Bit set.
  static const uint8_t ZPR2StridedOrContiguous_with_zsub_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 
  };

  // QQ_with_qsub0_in_FPR128_0to7 Register Class...
  static const MCPhysReg QQ_with_qsub0_in_FPR128_0to7[] = {
    AArch64_Q0_Q1, AArch64_Q1_Q2, AArch64_Q2_Q3, AArch64_Q3_Q4, AArch64_Q4_Q5, AArch64_Q5_Q6, AArch64_Q6_Q7, AArch64_Q7_Q8, 
  };

  // QQ_with_qsub0_in_FPR128_0to7 Bit set.
  static const uint8_t QQ_with_qsub0_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 
  };

  // QQ_with_qsub1_in_FPR128_0to7 Register Class...
  static const MCPhysReg QQ_with_qsub1_in_FPR128_0to7[] = {
    AArch64_Q0_Q1, AArch64_Q1_Q2, AArch64_Q2_Q3, AArch64_Q3_Q4, AArch64_Q4_Q5, AArch64_Q5_Q6, AArch64_Q6_Q7, AArch64_Q31_Q0, 
  };

  // QQ_with_qsub1_in_FPR128_0to7 Bit set.
  static const uint8_t QQ_with_qsub1_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x80, 
  };

  // ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z1, AArch64_Z2_Z3, AArch64_Z4_Z5, AArch64_Z6_Z7, AArch64_Z8_Z9, AArch64_Z10_Z11, AArch64_Z12_Z13, AArch64_Z14_Z15, 
  };

  // ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x05, 
  };

  // ZPR2Strided_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR2Strided_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z8, AArch64_Z1_Z9, AArch64_Z2_Z10, AArch64_Z3_Z11, AArch64_Z4_Z12, AArch64_Z5_Z13, AArch64_Z6_Z14, AArch64_Z7_Z15, 
  };

  // ZPR2Strided_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR2Strided_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 
  };

  // ZPR2_with_zsub1_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR2_with_zsub1_in_ZPR_3b[] = {
    AArch64_Z0_Z1, AArch64_Z1_Z2, AArch64_Z2_Z3, AArch64_Z3_Z4, AArch64_Z4_Z5, AArch64_Z5_Z6, AArch64_Z6_Z7, AArch64_Z31_Z0, 
  };

  // ZPR2_with_zsub1_in_ZPR_3b Bit set.
  static const uint8_t ZPR2_with_zsub1_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x07, 0x00, 0x00, 0x08, 
  };

  // ZPR2_with_zsub_in_FPR128_0to7 Register Class...
  static const MCPhysReg ZPR2_with_zsub_in_FPR128_0to7[] = {
    AArch64_Z0_Z1, AArch64_Z1_Z2, AArch64_Z2_Z3, AArch64_Z3_Z4, AArch64_Z4_Z5, AArch64_Z5_Z6, AArch64_Z6_Z7, AArch64_Z7_Z8, 
  };

  // ZPR2_with_zsub_in_FPR128_0to7 Bit set.
  static const uint8_t ZPR2_with_zsub_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 
  };

  // QQ_with_dsub_in_FPR64_lo_and_QQ_with_qsub1_in_FPR128_0to7 Register Class...
  static const MCPhysReg QQ_with_dsub_in_FPR64_lo_and_QQ_with_qsub1_in_FPR128_0to7[] = {
    AArch64_Q0_Q1, AArch64_Q1_Q2, AArch64_Q2_Q3, AArch64_Q3_Q4, AArch64_Q4_Q5, AArch64_Q5_Q6, AArch64_Q6_Q7, 
  };

  // QQ_with_dsub_in_FPR64_lo_and_QQ_with_qsub1_in_FPR128_0to7 Bit set.
  static const uint8_t QQ_with_dsub_in_FPR64_lo_and_QQ_with_qsub1_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 
  };

  // ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_3b[] = {
    AArch64_Z0_Z1, AArch64_Z1_Z2, AArch64_Z2_Z3, AArch64_Z3_Z4, AArch64_Z4_Z5, AArch64_Z5_Z6, AArch64_Z6_Z7, 
  };

  // ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_3b Bit set.
  static const uint8_t ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x07, 
  };

  // ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7 Register Class...
  static const MCPhysReg ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7[] = {
    AArch64_Z0_Z1, AArch64_Z2_Z3, AArch64_Z4_Z5, AArch64_Z6_Z7, 
  };

  // ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7 Bit set.
  static const uint8_t ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x05, 
  };

  // MPR64 Register Class...
  static const MCPhysReg MPR64[] = {
    AArch64_ZAD0, AArch64_ZAD1, AArch64_ZAD2, AArch64_ZAD3, AArch64_ZAD4, AArch64_ZAD5, AArch64_ZAD6, AArch64_ZAD7, 
  };

  // MPR64 Bit set.
  static const uint8_t MPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x01, 
  };

  // QQQ Register Class...
  static const MCPhysReg QQQ[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, AArch64_Q14_Q15_Q16, AArch64_Q15_Q16_Q17, AArch64_Q16_Q17_Q18, AArch64_Q17_Q18_Q19, AArch64_Q18_Q19_Q20, AArch64_Q19_Q20_Q21, AArch64_Q20_Q21_Q22, AArch64_Q21_Q22_Q23, AArch64_Q22_Q23_Q24, AArch64_Q23_Q24_Q25, AArch64_Q24_Q25_Q26, AArch64_Q25_Q26_Q27, AArch64_Q26_Q27_Q28, AArch64_Q27_Q28_Q29, AArch64_Q28_Q29_Q30, AArch64_Q29_Q30_Q31, AArch64_Q30_Q31_Q0, AArch64_Q31_Q0_Q1, 
  };

  // QQQ Bit set.
  static const uint8_t QQQBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 
  };

  // ZPR3 Register Class...
  static const MCPhysReg ZPR3[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z7_Z8_Z9, AArch64_Z8_Z9_Z10, AArch64_Z9_Z10_Z11, AArch64_Z10_Z11_Z12, AArch64_Z11_Z12_Z13, AArch64_Z12_Z13_Z14, AArch64_Z13_Z14_Z15, AArch64_Z14_Z15_Z16, AArch64_Z15_Z16_Z17, AArch64_Z16_Z17_Z18, AArch64_Z17_Z18_Z19, AArch64_Z18_Z19_Z20, AArch64_Z19_Z20_Z21, AArch64_Z20_Z21_Z22, AArch64_Z21_Z22_Z23, AArch64_Z22_Z23_Z24, AArch64_Z23_Z24_Z25, AArch64_Z24_Z25_Z26, AArch64_Z25_Z26_Z27, AArch64_Z26_Z27_Z28, AArch64_Z27_Z28_Z29, AArch64_Z28_Z29_Z30, AArch64_Z29_Z30_Z31, AArch64_Z30_Z31_Z0, AArch64_Z31_Z0_Z1, 
  };

  // ZPR3 Bit set.
  static const uint8_t ZPR3Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // QQQ_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg QQQ_with_dsub_in_FPR64_lo[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, AArch64_Q14_Q15_Q16, AArch64_Q15_Q16_Q17, 
  };

  // QQQ_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t QQQ_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 
  };

  // QQQ_with_qsub1_in_FPR128_lo Register Class...
  static const MCPhysReg QQQ_with_qsub1_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, AArch64_Q14_Q15_Q16, AArch64_Q31_Q0_Q1, 
  };

  // QQQ_with_qsub1_in_FPR128_lo Bit set.
  static const uint8_t QQQ_with_qsub1_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, 0x00, 0x80, 
  };

  // QQQ_with_qsub2_in_FPR128_lo Register Class...
  static const MCPhysReg QQQ_with_qsub2_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, AArch64_Q30_Q31_Q0, AArch64_Q31_Q0_Q1, 
  };

  // QQQ_with_qsub2_in_FPR128_lo Bit set.
  static const uint8_t QQQ_with_qsub2_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x3f, 0x00, 0xc0, 
  };

  // ZPR3_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR3_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z7_Z8_Z9, AArch64_Z8_Z9_Z10, AArch64_Z9_Z10_Z11, AArch64_Z10_Z11_Z12, AArch64_Z11_Z12_Z13, AArch64_Z12_Z13_Z14, AArch64_Z13_Z14_Z15, AArch64_Z14_Z15_Z16, AArch64_Z15_Z16_Z17, 
  };

  // ZPR3_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR3_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR3_with_zsub0_zsub1_in_ZPR2Mul2[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z2_Z3_Z4, AArch64_Z4_Z5_Z6, AArch64_Z6_Z7_Z8, AArch64_Z8_Z9_Z10, AArch64_Z10_Z11_Z12, AArch64_Z12_Z13_Z14, AArch64_Z14_Z15_Z16, AArch64_Z16_Z17_Z18, AArch64_Z18_Z19_Z20, AArch64_Z20_Z21_Z22, AArch64_Z22_Z23_Z24, AArch64_Z24_Z25_Z26, AArch64_Z26_Z27_Z28, AArch64_Z28_Z29_Z30, AArch64_Z30_Z31_Z0, 
  };

  // ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x55, 0x55, 0x05, 
  };

  // ZPR3_with_zsub1_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR3_with_zsub1_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z7_Z8_Z9, AArch64_Z8_Z9_Z10, AArch64_Z9_Z10_Z11, AArch64_Z10_Z11_Z12, AArch64_Z11_Z12_Z13, AArch64_Z12_Z13_Z14, AArch64_Z13_Z14_Z15, AArch64_Z14_Z15_Z16, AArch64_Z31_Z0_Z1, 
  };

  // ZPR3_with_zsub1_in_ZPR_4b Bit set.
  static const uint8_t ZPR3_with_zsub1_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 0x00, 0x08, 
  };

  // ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR3_with_zsub1_zsub2_in_ZPR2Mul2[] = {
    AArch64_Z1_Z2_Z3, AArch64_Z3_Z4_Z5, AArch64_Z5_Z6_Z7, AArch64_Z7_Z8_Z9, AArch64_Z9_Z10_Z11, AArch64_Z11_Z12_Z13, AArch64_Z13_Z14_Z15, AArch64_Z15_Z16_Z17, AArch64_Z17_Z18_Z19, AArch64_Z19_Z20_Z21, AArch64_Z21_Z22_Z23, AArch64_Z23_Z24_Z25, AArch64_Z25_Z26_Z27, AArch64_Z27_Z28_Z29, AArch64_Z29_Z30_Z31, AArch64_Z31_Z0_Z1, 
  };

  // ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 0xaa, 0xaa, 0x0a, 
  };

  // ZPR3_with_zsub2_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR3_with_zsub2_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z7_Z8_Z9, AArch64_Z8_Z9_Z10, AArch64_Z9_Z10_Z11, AArch64_Z10_Z11_Z12, AArch64_Z11_Z12_Z13, AArch64_Z12_Z13_Z14, AArch64_Z13_Z14_Z15, AArch64_Z30_Z31_Z0, AArch64_Z31_Z0_Z1, 
  };

  // ZPR3_with_zsub2_in_ZPR_4b Bit set.
  static const uint8_t ZPR3_with_zsub2_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x03, 0x00, 0x0c, 
  };

  // QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub1_in_FPR128_lo Register Class...
  static const MCPhysReg QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub1_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, AArch64_Q14_Q15_Q16, 
  };

  // QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub1_in_FPR128_lo Bit set.
  static const uint8_t QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub1_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, 
  };

  // QQQ_with_qsub1_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_lo Register Class...
  static const MCPhysReg QQQ_with_qsub1_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, AArch64_Q31_Q0_Q1, 
  };

  // QQQ_with_qsub1_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_lo Bit set.
  static const uint8_t QQQ_with_qsub1_in_FPR128_lo_and_QQQ_with_qsub2_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x3f, 0x00, 0x80, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z7_Z8_Z9, AArch64_Z8_Z9_Z10, AArch64_Z9_Z10_Z11, AArch64_Z10_Z11_Z12, AArch64_Z11_Z12_Z13, AArch64_Z12_Z13_Z14, AArch64_Z13_Z14_Z15, AArch64_Z14_Z15_Z16, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_4b Bit set.
  static const uint8_t ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 
  };

  // ZPR3_with_zsub1_in_ZPR_4b_and_ZPR3_with_zsub2_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR3_with_zsub1_in_ZPR_4b_and_ZPR3_with_zsub2_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z7_Z8_Z9, AArch64_Z8_Z9_Z10, AArch64_Z9_Z10_Z11, AArch64_Z10_Z11_Z12, AArch64_Z11_Z12_Z13, AArch64_Z12_Z13_Z14, AArch64_Z13_Z14_Z15, AArch64_Z31_Z0_Z1, 
  };

  // ZPR3_with_zsub1_in_ZPR_4b_and_ZPR3_with_zsub2_in_ZPR_4b Bit set.
  static const uint8_t ZPR3_with_zsub1_in_ZPR_4b_and_ZPR3_with_zsub2_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x03, 0x00, 0x08, 
  };

  // QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub2_in_FPR128_lo Register Class...
  static const MCPhysReg QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub2_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, AArch64_Q8_Q9_Q10, AArch64_Q9_Q10_Q11, AArch64_Q10_Q11_Q12, AArch64_Q11_Q12_Q13, AArch64_Q12_Q13_Q14, AArch64_Q13_Q14_Q15, 
  };

  // QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub2_in_FPR128_lo Bit set.
  static const uint8_t QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub2_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x3f, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z7_Z8_Z9, AArch64_Z8_Z9_Z10, AArch64_Z9_Z10_Z11, AArch64_Z10_Z11_Z12, AArch64_Z11_Z12_Z13, AArch64_Z12_Z13_Z14, AArch64_Z13_Z14_Z15, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_4b Bit set.
  static const uint8_t ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x03, 
  };

  // QQQ_with_qsub0_in_FPR128_0to7 Register Class...
  static const MCPhysReg QQQ_with_qsub0_in_FPR128_0to7[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q7_Q8_Q9, 
  };

  // QQQ_with_qsub0_in_FPR128_0to7 Bit set.
  static const uint8_t QQQ_with_qsub0_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 
  };

  // QQQ_with_qsub1_in_FPR128_0to7 Register Class...
  static const MCPhysReg QQQ_with_qsub1_in_FPR128_0to7[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, AArch64_Q31_Q0_Q1, 
  };

  // QQQ_with_qsub1_in_FPR128_0to7 Bit set.
  static const uint8_t QQQ_with_qsub1_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x80, 
  };

  // QQQ_with_qsub2_in_FPR128_0to7 Register Class...
  static const MCPhysReg QQQ_with_qsub2_in_FPR128_0to7[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q30_Q31_Q0, AArch64_Q31_Q0_Q1, 
  };

  // QQQ_with_qsub2_in_FPR128_0to7 Bit set.
  static const uint8_t QQQ_with_qsub2_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x00, 0x00, 0xc0, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2[] = {
    AArch64_Z1_Z2_Z3, AArch64_Z3_Z4_Z5, AArch64_Z5_Z6_Z7, AArch64_Z7_Z8_Z9, AArch64_Z9_Z10_Z11, AArch64_Z11_Z12_Z13, AArch64_Z13_Z14_Z15, AArch64_Z15_Z16_Z17, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 0x0a, 
  };

  // ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z2_Z3_Z4, AArch64_Z4_Z5_Z6, AArch64_Z6_Z7_Z8, AArch64_Z8_Z9_Z10, AArch64_Z10_Z11_Z12, AArch64_Z12_Z13_Z14, AArch64_Z14_Z15_Z16, 
  };

  // ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x05, 
  };

  // ZPR3_with_zsub1_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR3_with_zsub1_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z31_Z0_Z1, 
  };

  // ZPR3_with_zsub1_in_ZPR_3b Bit set.
  static const uint8_t ZPR3_with_zsub1_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x07, 0x00, 0x00, 0x08, 
  };

  // ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo[] = {
    AArch64_Z1_Z2_Z3, AArch64_Z3_Z4_Z5, AArch64_Z5_Z6_Z7, AArch64_Z7_Z8_Z9, AArch64_Z9_Z10_Z11, AArch64_Z11_Z12_Z13, AArch64_Z13_Z14_Z15, AArch64_Z31_Z0_Z1, 
  };

  // ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 0x02, 0x00, 0x08, 
  };

  // ZPR3_with_zsub2_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR3_with_zsub2_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z30_Z31_Z0, AArch64_Z31_Z0_Z1, 
  };

  // ZPR3_with_zsub2_in_ZPR_3b Bit set.
  static const uint8_t ZPR3_with_zsub2_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x03, 0x00, 0x00, 0x0c, 
  };

  // ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z2_Z3_Z4, AArch64_Z4_Z5_Z6, AArch64_Z6_Z7_Z8, AArch64_Z8_Z9_Z10, AArch64_Z10_Z11_Z12, AArch64_Z12_Z13_Z14, AArch64_Z30_Z31_Z0, 
  };

  // ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x01, 0x00, 0x04, 
  };

  // ZPR3_with_zsub_in_FPR128_0to7 Register Class...
  static const MCPhysReg ZPR3_with_zsub_in_FPR128_0to7[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, AArch64_Z7_Z8_Z9, 
  };

  // ZPR3_with_zsub_in_FPR128_0to7 Bit set.
  static const uint8_t ZPR3_with_zsub_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 
  };

  // QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub1_in_FPR128_0to7 Register Class...
  static const MCPhysReg QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub1_in_FPR128_0to7[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q6_Q7_Q8, 
  };

  // QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub1_in_FPR128_0to7 Bit set.
  static const uint8_t QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub1_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 
  };

  // QQQ_with_qsub1_in_FPR128_0to7_and_QQQ_with_qsub2_in_FPR128_0to7 Register Class...
  static const MCPhysReg QQQ_with_qsub1_in_FPR128_0to7_and_QQQ_with_qsub2_in_FPR128_0to7[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, AArch64_Q31_Q0_Q1, 
  };

  // QQQ_with_qsub1_in_FPR128_0to7_and_QQQ_with_qsub2_in_FPR128_0to7 Bit set.
  static const uint8_t QQQ_with_qsub1_in_FPR128_0to7_and_QQQ_with_qsub2_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x80, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z6_Z7_Z8, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_3b Bit set.
  static const uint8_t ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x07, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo[] = {
    AArch64_Z1_Z2_Z3, AArch64_Z3_Z4_Z5, AArch64_Z5_Z6_Z7, AArch64_Z7_Z8_Z9, AArch64_Z9_Z10_Z11, AArch64_Z11_Z12_Z13, AArch64_Z13_Z14_Z15, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 0x02, 
  };

  // ZPR3_with_zsub1_in_ZPR_3b_and_ZPR3_with_zsub2_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR3_with_zsub1_in_ZPR_3b_and_ZPR3_with_zsub2_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, AArch64_Z31_Z0_Z1, 
  };

  // ZPR3_with_zsub1_in_ZPR_3b_and_ZPR3_with_zsub2_in_ZPR_3b Bit set.
  static const uint8_t ZPR3_with_zsub1_in_ZPR_3b_and_ZPR3_with_zsub2_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x03, 0x00, 0x00, 0x08, 
  };

  // ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z2_Z3_Z4, AArch64_Z4_Z5_Z6, AArch64_Z6_Z7_Z8, AArch64_Z8_Z9_Z10, AArch64_Z10_Z11_Z12, AArch64_Z12_Z13_Z14, 
  };

  // ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x01, 
  };

  // QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub2_in_FPR128_0to7 Register Class...
  static const MCPhysReg QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub2_in_FPR128_0to7[] = {
    AArch64_Q0_Q1_Q2, AArch64_Q1_Q2_Q3, AArch64_Q2_Q3_Q4, AArch64_Q3_Q4_Q5, AArch64_Q4_Q5_Q6, AArch64_Q5_Q6_Q7, 
  };

  // QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub2_in_FPR128_0to7 Bit set.
  static const uint8_t QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub2_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z1_Z2_Z3, AArch64_Z2_Z3_Z4, AArch64_Z3_Z4_Z5, AArch64_Z4_Z5_Z6, AArch64_Z5_Z6_Z7, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_3b Bit set.
  static const uint8_t ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x03, 
  };

  // ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7 Register Class...
  static const MCPhysReg ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z2_Z3_Z4, AArch64_Z4_Z5_Z6, AArch64_Z6_Z7_Z8, 
  };

  // ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7 Bit set.
  static const uint8_t ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x05, 
  };

  // ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7 Register Class...
  static const MCPhysReg ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7[] = {
    AArch64_Z1_Z2_Z3, AArch64_Z3_Z4_Z5, AArch64_Z5_Z6_Z7, AArch64_Z31_Z0_Z1, 
  };

  // ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7 Bit set.
  static const uint8_t ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x00, 0x00, 0x08, 
  };

  // ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z2_Z3_Z4, AArch64_Z4_Z5_Z6, AArch64_Z30_Z31_Z0, 
  };

  // ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x01, 0x00, 0x00, 0x04, 
  };

  // ZPR3_with_zsub_in_FPR128_0to7_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR3_with_zsub_in_FPR128_0to7_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2[] = {
    AArch64_Z1_Z2_Z3, AArch64_Z3_Z4_Z5, AArch64_Z5_Z6_Z7, AArch64_Z7_Z8_Z9, 
  };

  // ZPR3_with_zsub_in_FPR128_0to7_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR3_with_zsub_in_FPR128_0to7_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x0a, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7 Register Class...
  static const MCPhysReg ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7[] = {
    AArch64_Z1_Z2_Z3, AArch64_Z3_Z4_Z5, AArch64_Z5_Z6_Z7, 
  };

  // ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7 Bit set.
  static const uint8_t ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 
  };

  // ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z1_Z2, AArch64_Z2_Z3_Z4, AArch64_Z4_Z5_Z6, 
  };

  // ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x01, 
  };

  // QQQQ Register Class...
  static const MCPhysReg QQQQ[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, AArch64_Q14_Q15_Q16_Q17, AArch64_Q15_Q16_Q17_Q18, AArch64_Q16_Q17_Q18_Q19, AArch64_Q17_Q18_Q19_Q20, AArch64_Q18_Q19_Q20_Q21, AArch64_Q19_Q20_Q21_Q22, AArch64_Q20_Q21_Q22_Q23, AArch64_Q21_Q22_Q23_Q24, AArch64_Q22_Q23_Q24_Q25, AArch64_Q23_Q24_Q25_Q26, AArch64_Q24_Q25_Q26_Q27, AArch64_Q25_Q26_Q27_Q28, AArch64_Q26_Q27_Q28_Q29, AArch64_Q27_Q28_Q29_Q30, AArch64_Q28_Q29_Q30_Q31, AArch64_Q29_Q30_Q31_Q0, AArch64_Q30_Q31_Q0_Q1, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQQQ Bit set.
  static const uint8_t QQQQBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 
  };

  // ZPR4 Register Class...
  static const MCPhysReg ZPR4[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z13_Z14_Z15_Z16, AArch64_Z14_Z15_Z16_Z17, AArch64_Z15_Z16_Z17_Z18, AArch64_Z16_Z17_Z18_Z19, AArch64_Z17_Z18_Z19_Z20, AArch64_Z18_Z19_Z20_Z21, AArch64_Z19_Z20_Z21_Z22, AArch64_Z20_Z21_Z22_Z23, AArch64_Z21_Z22_Z23_Z24, AArch64_Z22_Z23_Z24_Z25, AArch64_Z23_Z24_Z25_Z26, AArch64_Z24_Z25_Z26_Z27, AArch64_Z25_Z26_Z27_Z28, AArch64_Z26_Z27_Z28_Z29, AArch64_Z27_Z28_Z29_Z30, AArch64_Z28_Z29_Z30_Z31, AArch64_Z29_Z30_Z31_Z0, AArch64_Z30_Z31_Z0_Z1, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4 Bit set.
  static const uint8_t ZPR4Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // QQQQ_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg QQQQ_with_dsub_in_FPR64_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, AArch64_Q14_Q15_Q16_Q17, AArch64_Q15_Q16_Q17_Q18, 
  };

  // QQQQ_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t QQQQ_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 
  };

  // QQQQ_with_qsub1_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_qsub1_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, AArch64_Q14_Q15_Q16_Q17, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQQQ_with_qsub1_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_qsub1_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, 0x00, 0x80, 
  };

  // QQQQ_with_qsub2_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_qsub2_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, AArch64_Q30_Q31_Q0_Q1, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQQQ_with_qsub2_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_qsub2_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x3f, 0x00, 0xc0, 
  };

  // QQQQ_with_qsub3_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_qsub3_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q29_Q30_Q31_Q0, AArch64_Q30_Q31_Q0_Q1, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQQQ_with_qsub3_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_qsub3_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x1f, 0x00, 0xe0, 
  };

  // ZPR4StridedOrContiguous Register Class...
  static const MCPhysReg ZPR4StridedOrContiguous[] = {
    AArch64_Z0_Z4_Z8_Z12, AArch64_Z1_Z5_Z9_Z13, AArch64_Z2_Z6_Z10_Z14, AArch64_Z3_Z7_Z11_Z15, AArch64_Z16_Z20_Z24_Z28, AArch64_Z17_Z21_Z25_Z29, AArch64_Z18_Z22_Z26_Z30, AArch64_Z19_Z23_Z27_Z31, AArch64_Z0_Z1_Z2_Z3, AArch64_Z4_Z5_Z6_Z7, AArch64_Z8_Z9_Z10_Z11, AArch64_Z12_Z13_Z14_Z15, AArch64_Z16_Z17_Z18_Z19, AArch64_Z20_Z21_Z22_Z23, AArch64_Z24_Z25_Z26_Z27, AArch64_Z28_Z29_Z30_Z31, 
  };

  // ZPR4StridedOrContiguous Bit set.
  static const uint8_t ZPR4StridedOrContiguousBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x11, 0x11, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 
  };

  // ZPR4_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z13_Z14_Z15_Z16, AArch64_Z14_Z15_Z16_Z17, AArch64_Z15_Z16_Z17_Z18, 
  };

  // ZPR4_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // ZPR4_with_zsub0_zsub1_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR4_with_zsub0_zsub1_in_ZPR2Mul2[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z2_Z3_Z4_Z5, AArch64_Z4_Z5_Z6_Z7, AArch64_Z6_Z7_Z8_Z9, AArch64_Z8_Z9_Z10_Z11, AArch64_Z10_Z11_Z12_Z13, AArch64_Z12_Z13_Z14_Z15, AArch64_Z14_Z15_Z16_Z17, AArch64_Z16_Z17_Z18_Z19, AArch64_Z18_Z19_Z20_Z21, AArch64_Z20_Z21_Z22_Z23, AArch64_Z22_Z23_Z24_Z25, AArch64_Z24_Z25_Z26_Z27, AArch64_Z26_Z27_Z28_Z29, AArch64_Z28_Z29_Z30_Z31, AArch64_Z30_Z31_Z0_Z1, 
  };

  // ZPR4_with_zsub0_zsub1_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR4_with_zsub0_zsub1_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x55, 0x55, 0x05, 
  };

  // ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, AArch64_Z5_Z6_Z7_Z8, AArch64_Z7_Z8_Z9_Z10, AArch64_Z9_Z10_Z11_Z12, AArch64_Z11_Z12_Z13_Z14, AArch64_Z13_Z14_Z15_Z16, AArch64_Z15_Z16_Z17_Z18, AArch64_Z17_Z18_Z19_Z20, AArch64_Z19_Z20_Z21_Z22, AArch64_Z21_Z22_Z23_Z24, AArch64_Z23_Z24_Z25_Z26, AArch64_Z25_Z26_Z27_Z28, AArch64_Z27_Z28_Z29_Z30, AArch64_Z29_Z30_Z31_Z0, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 0xaa, 0xaa, 0x0a, 
  };

  // ZPR4_with_zsub1_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_zsub1_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z13_Z14_Z15_Z16, AArch64_Z14_Z15_Z16_Z17, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub1_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_zsub1_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 0x00, 0x08, 
  };

  // ZPR4_with_zsub2_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_zsub2_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z13_Z14_Z15_Z16, AArch64_Z30_Z31_Z0_Z1, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub2_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_zsub2_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x03, 0x00, 0x0c, 
  };

  // ZPR4_with_zsub3_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_zsub3_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z29_Z30_Z31_Z0, AArch64_Z30_Z31_Z0_Z1, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub3_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_zsub3_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x01, 0x00, 0x0e, 
  };

  // QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub1_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub1_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, AArch64_Q14_Q15_Q16_Q17, 
  };

  // QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub1_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub1_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x7f, 
  };

  // QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub2_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x3f, 0x00, 0x80, 
  };

  // QQQQ_with_qsub2_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_qsub2_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q30_Q31_Q0_Q1, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQQQ_with_qsub2_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_qsub2_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x1f, 0x00, 0xc0, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z13_Z14_Z15_Z16, AArch64_Z14_Z15_Z16_Z17, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 
  };

  // ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub2_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub2_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z13_Z14_Z15_Z16, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub2_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub2_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x03, 0x00, 0x08, 
  };

  // ZPR4_with_zsub2_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_zsub2_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z30_Z31_Z0_Z1, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub2_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_zsub2_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x01, 0x00, 0x0c, 
  };

  // QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub2_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub2_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q13_Q14_Q15_Q16, 
  };

  // QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub2_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub2_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x3f, 
  };

  // QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_qsub1_in_FPR128_lo_and_QQQQ_with_qsub3_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x1f, 0x00, 0x80, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z13_Z14_Z15_Z16, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x03, 
  };

  // ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_zsub1_in_ZPR_4b_and_ZPR4_with_zsub3_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x01, 0x00, 0x08, 
  };

  // QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub3_in_FPR128_lo Register Class...
  static const MCPhysReg QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub3_in_FPR128_lo[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, AArch64_Q8_Q9_Q10_Q11, AArch64_Q9_Q10_Q11_Q12, AArch64_Q10_Q11_Q12_Q13, AArch64_Q11_Q12_Q13_Q14, AArch64_Q12_Q13_Q14_Q15, 
  };

  // QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub3_in_FPR128_lo Bit set.
  static const uint8_t QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub3_in_FPR128_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x1f, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_4b Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_4b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, AArch64_Z8_Z9_Z10_Z11, AArch64_Z9_Z10_Z11_Z12, AArch64_Z10_Z11_Z12_Z13, AArch64_Z11_Z12_Z13_Z14, AArch64_Z12_Z13_Z14_Z15, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_4b Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_4bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x01, 
  };

  // QQQQ_with_qsub0_in_FPR128_0to7 Register Class...
  static const MCPhysReg QQQQ_with_qsub0_in_FPR128_0to7[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q7_Q8_Q9_Q10, 
  };

  // QQQQ_with_qsub0_in_FPR128_0to7 Bit set.
  static const uint8_t QQQQ_with_qsub0_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 
  };

  // QQQQ_with_qsub1_in_FPR128_0to7 Register Class...
  static const MCPhysReg QQQQ_with_qsub1_in_FPR128_0to7[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQQQ_with_qsub1_in_FPR128_0to7 Bit set.
  static const uint8_t QQQQ_with_qsub1_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x00, 0x00, 0x80, 
  };

  // QQQQ_with_qsub2_in_FPR128_0to7 Register Class...
  static const MCPhysReg QQQQ_with_qsub2_in_FPR128_0to7[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q30_Q31_Q0_Q1, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQQQ_with_qsub2_in_FPR128_0to7 Bit set.
  static const uint8_t QQQQ_with_qsub2_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x00, 0x00, 0xc0, 
  };

  // QQQQ_with_qsub3_in_FPR128_0to7 Register Class...
  static const MCPhysReg QQQQ_with_qsub3_in_FPR128_0to7[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q29_Q30_Q31_Q0, AArch64_Q30_Q31_Q0_Q1, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQQQ_with_qsub3_in_FPR128_0to7 Bit set.
  static const uint8_t QQQQ_with_qsub3_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0xe0, 
  };

  // ZPR4Mul4 Register Class...
  static const MCPhysReg ZPR4Mul4[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z4_Z5_Z6_Z7, AArch64_Z8_Z9_Z10_Z11, AArch64_Z12_Z13_Z14_Z15, AArch64_Z16_Z17_Z18_Z19, AArch64_Z20_Z21_Z22_Z23, AArch64_Z24_Z25_Z26_Z27, AArch64_Z28_Z29_Z30_Z31, 
  };

  // ZPR4Mul4 Bit set.
  static const uint8_t ZPR4Mul4Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x11, 0x11, 0x01, 
  };

  // ZPR4Strided Register Class...
  static const MCPhysReg ZPR4Strided[] = {
    AArch64_Z0_Z4_Z8_Z12, AArch64_Z1_Z5_Z9_Z13, AArch64_Z2_Z6_Z10_Z14, AArch64_Z3_Z7_Z11_Z15, AArch64_Z16_Z20_Z24_Z28, AArch64_Z17_Z21_Z25_Z29, AArch64_Z18_Z22_Z26_Z30, AArch64_Z19_Z23_Z27_Z31, 
  };

  // ZPR4Strided Bit set.
  static const uint8_t ZPR4StridedBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 
  };

  // ZPR4StridedOrContiguous_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR4StridedOrContiguous_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z4_Z8_Z12, AArch64_Z1_Z5_Z9_Z13, AArch64_Z2_Z6_Z10_Z14, AArch64_Z3_Z7_Z11_Z15, AArch64_Z0_Z1_Z2_Z3, AArch64_Z4_Z5_Z6_Z7, AArch64_Z8_Z9_Z10_Z11, AArch64_Z12_Z13_Z14_Z15, 
  };

  // ZPR4StridedOrContiguous_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR4StridedOrContiguous_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, AArch64_Z5_Z6_Z7_Z8, AArch64_Z7_Z8_Z9_Z10, AArch64_Z9_Z10_Z11_Z12, AArch64_Z11_Z12_Z13_Z14, AArch64_Z13_Z14_Z15_Z16, AArch64_Z15_Z16_Z17_Z18, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 0x0a, 
  };

  // ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z2_Z3_Z4_Z5, AArch64_Z4_Z5_Z6_Z7, AArch64_Z6_Z7_Z8_Z9, AArch64_Z8_Z9_Z10_Z11, AArch64_Z10_Z11_Z12_Z13, AArch64_Z12_Z13_Z14_Z15, AArch64_Z14_Z15_Z16_Z17, 
  };

  // ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x05, 
  };

  // ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, AArch64_Z5_Z6_Z7_Z8, AArch64_Z7_Z8_Z9_Z10, AArch64_Z9_Z10_Z11_Z12, AArch64_Z11_Z12_Z13_Z14, AArch64_Z13_Z14_Z15_Z16, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 0x02, 0x00, 0x08, 
  };

  // ZPR4_with_zsub1_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub1_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub1_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub1_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x07, 0x00, 0x00, 0x08, 
  };

  // ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z2_Z3_Z4_Z5, AArch64_Z4_Z5_Z6_Z7, AArch64_Z6_Z7_Z8_Z9, AArch64_Z8_Z9_Z10_Z11, AArch64_Z10_Z11_Z12_Z13, AArch64_Z12_Z13_Z14_Z15, AArch64_Z30_Z31_Z0_Z1, 
  };

  // ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x01, 0x00, 0x04, 
  };

  // ZPR4_with_zsub2_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub2_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z30_Z31_Z0_Z1, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub2_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub2_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x03, 0x00, 0x00, 0x0c, 
  };

  // ZPR4_with_zsub3_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub3_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z29_Z30_Z31_Z0, AArch64_Z30_Z31_Z0_Z1, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub3_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub3_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x01, 0x00, 0x00, 0x0e, 
  };

  // ZPR4_with_zsub3_in_ZPR_4b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR4_with_zsub3_in_ZPR_4b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, AArch64_Z5_Z6_Z7_Z8, AArch64_Z7_Z8_Z9_Z10, AArch64_Z9_Z10_Z11_Z12, AArch64_Z11_Z12_Z13_Z14, AArch64_Z29_Z30_Z31_Z0, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub3_in_ZPR_4b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR4_with_zsub3_in_ZPR_4b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 0x00, 0x00, 0x0a, 
  };

  // ZPR4_with_zsub_in_FPR128_0to7 Register Class...
  static const MCPhysReg ZPR4_with_zsub_in_FPR128_0to7[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, AArch64_Z7_Z8_Z9_Z10, 
  };

  // ZPR4_with_zsub_in_FPR128_0to7 Bit set.
  static const uint8_t ZPR4_with_zsub_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x0f, 
  };

  // QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub1_in_FPR128_0to7 Register Class...
  static const MCPhysReg QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub1_in_FPR128_0to7[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q6_Q7_Q8_Q9, 
  };

  // QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub1_in_FPR128_0to7 Bit set.
  static const uint8_t QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub1_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 
  };

  // QQQQ_with_qsub1_in_FPR128_0to7_and_QQQQ_with_qsub2_in_FPR128_0to7 Register Class...
  static const MCPhysReg QQQQ_with_qsub1_in_FPR128_0to7_and_QQQQ_with_qsub2_in_FPR128_0to7[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQQQ_with_qsub1_in_FPR128_0to7_and_QQQQ_with_qsub2_in_FPR128_0to7 Bit set.
  static const uint8_t QQQQ_with_qsub1_in_FPR128_0to7_and_QQQQ_with_qsub2_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x80, 
  };

  // QQQQ_with_qsub2_in_FPR128_0to7_and_QQQQ_with_qsub3_in_FPR128_0to7 Register Class...
  static const MCPhysReg QQQQ_with_qsub2_in_FPR128_0to7_and_QQQQ_with_qsub3_in_FPR128_0to7[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q30_Q31_Q0_Q1, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQQQ_with_qsub2_in_FPR128_0to7_and_QQQQ_with_qsub3_in_FPR128_0to7 Bit set.
  static const uint8_t QQQQ_with_qsub2_in_FPR128_0to7_and_QQQQ_with_qsub3_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0xc0, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, AArch64_Z5_Z6_Z7_Z8, AArch64_Z7_Z8_Z9_Z10, AArch64_Z9_Z10_Z11_Z12, AArch64_Z11_Z12_Z13_Z14, AArch64_Z13_Z14_Z15_Z16, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 0x02, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z6_Z7_Z8_Z9, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x07, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z2_Z3_Z4_Z5, AArch64_Z4_Z5_Z6_Z7, AArch64_Z6_Z7_Z8_Z9, AArch64_Z8_Z9_Z10_Z11, AArch64_Z10_Z11_Z12_Z13, AArch64_Z12_Z13_Z14_Z15, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x55, 0x01, 
  };

  // ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub2_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub2_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub2_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub2_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x03, 0x00, 0x00, 0x08, 
  };

  // ZPR4_with_zsub1_in_ZPR_4b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR4_with_zsub1_in_ZPR_4b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, AArch64_Z5_Z6_Z7_Z8, AArch64_Z7_Z8_Z9_Z10, AArch64_Z9_Z10_Z11_Z12, AArch64_Z11_Z12_Z13_Z14, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub1_in_ZPR_4b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR4_with_zsub1_in_ZPR_4b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 0x00, 0x00, 0x08, 
  };

  // ZPR4_with_zsub2_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub2_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z30_Z31_Z0_Z1, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub2_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub2_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x01, 0x00, 0x00, 0x0c, 
  };

  // QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub2_in_FPR128_0to7 Register Class...
  static const MCPhysReg QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub2_in_FPR128_0to7[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q5_Q6_Q7_Q8, 
  };

  // QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub2_in_FPR128_0to7 Bit set.
  static const uint8_t QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub2_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 
  };

  // QQQQ_with_qsub1_in_FPR128_0to7_and_QQQQ_with_qsub3_in_FPR128_0to7 Register Class...
  static const MCPhysReg QQQQ_with_qsub1_in_FPR128_0to7_and_QQQQ_with_qsub3_in_FPR128_0to7[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, AArch64_Q31_Q0_Q1_Q2, 
  };

  // QQQQ_with_qsub1_in_FPR128_0to7_and_QQQQ_with_qsub3_in_FPR128_0to7 Bit set.
  static const uint8_t QQQQ_with_qsub1_in_FPR128_0to7_and_QQQQ_with_qsub3_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x80, 
  };

  // ZPR4StridedOrContiguous_with_zsub_in_FPR128_0to7 Register Class...
  static const MCPhysReg ZPR4StridedOrContiguous_with_zsub_in_FPR128_0to7[] = {
    AArch64_Z0_Z4_Z8_Z12, AArch64_Z1_Z5_Z9_Z13, AArch64_Z2_Z6_Z10_Z14, AArch64_Z3_Z7_Z11_Z15, AArch64_Z0_Z1_Z2_Z3, AArch64_Z4_Z5_Z6_Z7, 
  };

  // ZPR4StridedOrContiguous_with_zsub_in_FPR128_0to7 Bit set.
  static const uint8_t ZPR4StridedOrContiguous_with_zsub_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z5_Z6_Z7_Z8, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x03, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, AArch64_Z5_Z6_Z7_Z8, AArch64_Z7_Z8_Z9_Z10, AArch64_Z9_Z10_Z11_Z12, AArch64_Z11_Z12_Z13_Z14, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0xaa, 
  };

  // ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x01, 0x00, 0x00, 0x08, 
  };

  // QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub3_in_FPR128_0to7 Register Class...
  static const MCPhysReg QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub3_in_FPR128_0to7[] = {
    AArch64_Q0_Q1_Q2_Q3, AArch64_Q1_Q2_Q3_Q4, AArch64_Q2_Q3_Q4_Q5, AArch64_Q3_Q4_Q5_Q6, AArch64_Q4_Q5_Q6_Q7, 
  };

  // QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub3_in_FPR128_0to7 Bit set.
  static const uint8_t QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub3_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_3b Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_3b[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z1_Z2_Z3_Z4, AArch64_Z2_Z3_Z4_Z5, AArch64_Z3_Z4_Z5_Z6, AArch64_Z4_Z5_Z6_Z7, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_3b Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_3bBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x01, 
  };

  // ZPR4Mul4_and_ZPR4_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR4Mul4_and_ZPR4_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z4_Z5_Z6_Z7, AArch64_Z8_Z9_Z10_Z11, AArch64_Z12_Z13_Z14_Z15, 
  };

  // ZPR4Mul4_and_ZPR4_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR4Mul4_and_ZPR4_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x01, 
  };

  // ZPR4Strided_with_dsub_in_FPR64_lo Register Class...
  static const MCPhysReg ZPR4Strided_with_dsub_in_FPR64_lo[] = {
    AArch64_Z0_Z4_Z8_Z12, AArch64_Z1_Z5_Z9_Z13, AArch64_Z2_Z6_Z10_Z14, AArch64_Z3_Z7_Z11_Z15, 
  };

  // ZPR4Strided_with_dsub_in_FPR64_lo Bit set.
  static const uint8_t ZPR4Strided_with_dsub_in_FPR64_loBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub_in_FPR128_0to7_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub_in_FPR128_0to7_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, AArch64_Z5_Z6_Z7_Z8, AArch64_Z7_Z8_Z9_Z10, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub_in_FPR128_0to7_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub_in_FPR128_0to7_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x0a, 
  };

  // ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7 Register Class...
  static const MCPhysReg ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z2_Z3_Z4_Z5, AArch64_Z4_Z5_Z6_Z7, AArch64_Z6_Z7_Z8_Z9, 
  };

  // ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7 Bit set.
  static const uint8_t ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x05, 
  };

  // ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7 Register Class...
  static const MCPhysReg ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, AArch64_Z5_Z6_Z7_Z8, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7 Bit set.
  static const uint8_t ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x00, 0x00, 0x08, 
  };

  // ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7 Register Class...
  static const MCPhysReg ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z2_Z3_Z4_Z5, AArch64_Z4_Z5_Z6_Z7, AArch64_Z30_Z31_Z0_Z1, 
  };

  // ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7 Bit set.
  static const uint8_t ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x01, 0x00, 0x00, 0x04, 
  };

  // ZPR4_with_zsub3_in_ZPR_3b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR4_with_zsub3_in_ZPR_3b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, AArch64_Z29_Z30_Z31_Z0, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub3_in_ZPR_3b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR4_with_zsub3_in_ZPR_3b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x0a, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7 Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, AArch64_Z5_Z6_Z7_Z8, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7 Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7 Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z2_Z3_Z4_Z5, AArch64_Z4_Z5_Z6_Z7, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7 Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x01, 
  };

  // ZPR4_with_zsub1_in_ZPR_3b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR4_with_zsub1_in_ZPR_3b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, AArch64_Z31_Z0_Z1_Z2, 
  };

  // ZPR4_with_zsub1_in_ZPR_3b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR4_with_zsub1_in_ZPR_3b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x08, 
  };

  // ZPR4Mul4_and_ZPR4_with_zsub_in_FPR128_0to7 Register Class...
  static const MCPhysReg ZPR4Mul4_and_ZPR4_with_zsub_in_FPR128_0to7[] = {
    AArch64_Z0_Z1_Z2_Z3, AArch64_Z4_Z5_Z6_Z7, 
  };

  // ZPR4Mul4_and_ZPR4_with_zsub_in_FPR128_0to7 Bit set.
  static const uint8_t ZPR4Mul4_and_ZPR4_with_zsub_in_FPR128_0to7Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Register Class...
  static const MCPhysReg ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2[] = {
    AArch64_Z1_Z2_Z3_Z4, AArch64_Z3_Z4_Z5_Z6, 
  };

  // ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2 Bit set.
  static const uint8_t ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0, 
  };

  // GPR64x8Class Register Class...
  static const MCPhysReg GPR64x8Class[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class Bit set.
  static const uint8_t GPR64x8ClassBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x0f, 
  };

  // GPR64x8Class_with_x8sub_0_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_0_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x0d, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x0e, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x0f, 
  };

  // GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbf, 0x0f, 
  };

  // GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0x0c, 
  };

  // GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x0d, 
  };

  // GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbf, 0x0d, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_tcGPR64[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x07, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x0e, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbf, 0x0e, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x0f, 
  };

  // GPR64x8Class_with_x8sub_0_in_GPR64noip_and_tcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_GPR64noip_and_tcGPR64[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_0_in_GPR64noip_and_tcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_GPR64noip_and_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x05, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_2_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_2_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_2_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_2_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x06, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7e, 0x07, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x07, 
  };

  // GPR64x8Class_with_x8sub_1_in_tcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_1_in_tcGPR64[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, 
  };

  // GPR64x8Class_with_x8sub_1_in_tcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_1_in_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x03, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7f, 0x0c, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbf, 0x0c, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x0d, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x0e, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x04, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7e, 0x05, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x05, 
  };

  // GPR64x8Class_with_x8sub_1_in_GPR64noip_and_tcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_1_in_GPR64noip_and_tcGPR64[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, 
  };

  // GPR64x8Class_with_x8sub_1_in_GPR64noip_and_tcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_1_in_GPR64noip_and_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x01, 
  };

  // GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, 
  };

  // GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7e, 0x03, 
  };

  // GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, 
  };

  // GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x03, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7e, 0x06, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x06, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_tcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64noip_and_tcGPR64[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_tcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64noip_and_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x02, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x07, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, AArch64_X20_X21_X22_X23_X24_X25_X26_X27, AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x0c, 
  };

  // GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, 
  };

  // GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x01, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7e, 0x04, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x04, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_4_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7e, 0x02, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 0x02, 
  };

  // GPR64x8Class_with_x8sub_3_in_GPR64noip_and_tcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_3_in_GPR64noip_and_tcGPR64[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, 
  };

  // GPR64x8Class_with_x8sub_3_in_GPR64noip_and_tcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_3_in_GPR64noip_and_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x05, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x03, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x06, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_tcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip_and_tcGPR64[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_tcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noip_and_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7e, 0x01, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x01, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X18_X19_X20_X21_X22_X23_X24_X25, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_0_in_tcGPR64_and_GPR64x8Class_with_x8sub_0_in_GPR64noip_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x04, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X16_X17_X18_X19_X20_X21_X22_X23, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noip Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64noip_and_GPR64x8Class_with_x8sub_2_in_GPR64noip_and_GPR64x8Class_with_x8sub_1_in_tcGPR64_and_GPR64x8Class_with_x8sub_6_in_GPR64noipBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0x02, 
  };

  // GPR64x8Class_with_x8sub_5_in_GPR64noip_and_tcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_5_in_GPR64noip_and_tcGPR64[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, 
  };

  // GPR64x8Class_with_x8sub_5_in_GPR64noip_and_tcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_5_in_GPR64noip_and_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7e, 
  };

  // GPR64x8Class_with_x8sub_6_in_GPR64noip_and_tcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_6_in_GPR64noip_and_tcGPR64[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, 
  };

  // GPR64x8Class_with_x8sub_6_in_GPR64noip_and_tcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_6_in_GPR64noip_and_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xbe, 
  };

  // GPR64x8Class_with_x8sub_7_in_GPR64noip_and_tcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_7_in_GPR64noip_and_tcGPR64[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, 
  };

  // GPR64x8Class_with_x8sub_7_in_GPR64noip_and_tcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_7_in_GPR64noip_and_tcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 
  };

  // GPR64x8Class_with_sub_32_in_GPR32arg Register Class...
  static const MCPhysReg GPR64x8Class_with_sub_32_in_GPR32arg[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, 
  };

  // GPR64x8Class_with_sub_32_in_GPR32arg Bit set.
  static const uint8_t GPR64x8Class_with_sub_32_in_GPR32argBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e, 
  };

  // MPR32 Register Class...
  static const MCPhysReg MPR32[] = {
    AArch64_ZAS0, AArch64_ZAS1, AArch64_ZAS2, AArch64_ZAS3, 
  };

  // MPR32 Bit set.
  static const uint8_t MPR32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64arg Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64arg[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64arg Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64argBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 
  };

  // GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_12_15 Register Class...
  static const MCPhysReg GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_12_15[] = {
    AArch64_X12_X13_X14_X15_X16_X17_X18_X19, AArch64_X14_X15_X16_X17_X18_X19_X20_X21, 
  };

  // GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_12_15 Bit set.
  static const uint8_t GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_12_15Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 
  };

  // GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11 Register Class...
  static const MCPhysReg GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11[] = {
    AArch64_X8_X9_X10_X11_X12_X13_X14_X15, AArch64_X10_X11_X12_X13_X14_X15_X16_X17, 
  };

  // GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11 Bit set.
  static const uint8_t GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_12_15 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_12_15[] = {
    AArch64_X10_X11_X12_X13_X14_X15_X16_X17, AArch64_X12_X13_X14_X15_X16_X17_X18_X19, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_12_15 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_12_15Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11[] = {
    AArch64_X6_X7_X8_X9_X10_X11_X12_X13, AArch64_X8_X9_X10_X11_X12_X13_X14_X15, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11[] = {
    AArch64_X4_X5_X6_X7_X8_X9_X10_X11, AArch64_X6_X7_X8_X9_X10_X11_X12_X13, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64arg Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64arg[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, AArch64_X2_X3_X4_X5_X6_X7_X8_X9, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64arg Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64argBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 
  };

  // GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11[] = {
    AArch64_X2_X3_X4_X5_X6_X7_X8_X9, AArch64_X4_X5_X6_X7_X8_X9_X10_X11, 
  };

  // GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 
  };

  // GPR64x8Class_with_sub_32_in_GPR32arg_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Register Class...
  static const MCPhysReg GPR64x8Class_with_sub_32_in_GPR32arg_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11[] = {
    AArch64_X6_X7_X8_X9_X10_X11_X12_X13, 
  };

  // GPR64x8Class_with_sub_32_in_GPR32arg_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Bit set.
  static const uint8_t GPR64x8Class_with_sub_32_in_GPR32arg_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 
  };

  // GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Register Class...
  static const MCPhysReg GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11[] = {
    AArch64_X8_X9_X10_X11_X12_X13_X14_X15, 
  };

  // GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Bit set.
  static const uint8_t GPR64x8Class_with_sub_32_in_MatrixIndexGPR32_8_11_and_GPR64x8Class_with_x8sub_2_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 
  };

  // GPR64x8Class_with_x8sub_0_in_rtcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_0_in_rtcGPR64[] = {
    AArch64_X16_X17_X18_X19_X20_X21_X22_X23, 
  };

  // GPR64x8Class_with_x8sub_0_in_rtcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_0_in_rtcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64arg_and_GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_GPR64arg_and_GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11[] = {
    AArch64_X4_X5_X6_X7_X8_X9_X10_X11, 
  };

  // GPR64x8Class_with_x8sub_2_in_GPR64arg_and_GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_GPR64arg_and_GPR64x8Class_with_x8sub_4_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 
  };

  // GPR64x8Class_with_x8sub_2_in_rtcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_2_in_rtcGPR64[] = {
    AArch64_X14_X15_X16_X17_X18_X19_X20_X21, 
  };

  // GPR64x8Class_with_x8sub_2_in_rtcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_2_in_rtcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64arg_and_GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_GPR64arg_and_GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11[] = {
    AArch64_X2_X3_X4_X5_X6_X7_X8_X9, 
  };

  // GPR64x8Class_with_x8sub_4_in_GPR64arg_and_GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_GPR64arg_and_GPR64x8Class_with_x8sub_6_in_GPR64_with_sub_32_in_MatrixIndexGPR32_8_11Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 
  };

  // GPR64x8Class_with_x8sub_4_in_rtcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_4_in_rtcGPR64[] = {
    AArch64_X12_X13_X14_X15_X16_X17_X18_X19, 
  };

  // GPR64x8Class_with_x8sub_4_in_rtcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_4_in_rtcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 
  };

  // GPR64x8Class_with_x8sub_6_in_GPR64arg Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_6_in_GPR64arg[] = {
    AArch64_X0_X1_X2_X3_X4_X5_X6_X7, 
  };

  // GPR64x8Class_with_x8sub_6_in_GPR64arg Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_6_in_GPR64argBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 
  };

  // GPR64x8Class_with_x8sub_6_in_rtcGPR64 Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_6_in_rtcGPR64[] = {
    AArch64_X10_X11_X12_X13_X14_X15_X16_X17, 
  };

  // GPR64x8Class_with_x8sub_6_in_rtcGPR64 Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_6_in_rtcGPR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 
  };

  // GPR64x8Class_with_x8sub_7_in_FIXED_REGS Register Class...
  static const MCPhysReg GPR64x8Class_with_x8sub_7_in_FIXED_REGS[] = {
    AArch64_X22_X23_X24_X25_X26_X27_X28_FP, 
  };

  // GPR64x8Class_with_x8sub_7_in_FIXED_REGS Bit set.
  static const uint8_t GPR64x8Class_with_x8sub_7_in_FIXED_REGSBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
  };

  // ZTR Register Class...
  static const MCPhysReg ZTR[] = {
    AArch64_ZT0, 
  };

  // ZTR Bit set.
  static const uint8_t ZTRBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 
  };

  // MPR16 Register Class...
  static const MCPhysReg MPR16[] = {
    AArch64_ZAH0, AArch64_ZAH1, 
  };

  // MPR16 Bit set.
  static const uint8_t MPR16Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 
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
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
  };

static const MCRegisterClass AArch64MCRegisterClasses[] = {
  { FPR8, FPR8Bits, sizeof(FPR8Bits) },
  { FPR16, FPR16Bits, sizeof(FPR16Bits) },
  { FPR16_lo, FPR16_loBits, sizeof(FPR16_loBits) },
  { PNR, PNRBits, sizeof(PNRBits) },
  { PPR, PPRBits, sizeof(PPRBits) },
  { PNR_3b, PNR_3bBits, sizeof(PNR_3bBits) },
  { PNR_p8to15, PNR_p8to15Bits, sizeof(PNR_p8to15Bits) },
  { PPR_3b, PPR_3bBits, sizeof(PPR_3bBits) },
  { PPR_p8to15, PPR_p8to15Bits, sizeof(PPR_p8to15Bits) },
  { PPR2, PPR2Bits, sizeof(PPR2Bits) },
  { PPR2Mul2, PPR2Mul2Bits, sizeof(PPR2Mul2Bits) },
  { PPR2_with_psub1_in_PPR_3b, PPR2_with_psub1_in_PPR_3bBits, sizeof(PPR2_with_psub1_in_PPR_3bBits) },
  { PPR2_with_psub1_in_PPR_p8to15, PPR2_with_psub1_in_PPR_p8to15Bits, sizeof(PPR2_with_psub1_in_PPR_p8to15Bits) },
  { PPR2_with_psub_in_PNR_3b, PPR2_with_psub_in_PNR_3bBits, sizeof(PPR2_with_psub_in_PNR_3bBits) },
  { PPR2_with_psub_in_PNR_p8to15, PPR2_with_psub_in_PNR_p8to15Bits, sizeof(PPR2_with_psub_in_PNR_p8to15Bits) },
  { PPR2_with_psub_in_PNR_3b_and_PPR2_with_psub1_in_PPR_3b, PPR2_with_psub_in_PNR_3b_and_PPR2_with_psub1_in_PPR_3bBits, sizeof(PPR2_with_psub_in_PNR_3b_and_PPR2_with_psub1_in_PPR_3bBits) },
  { PPR2_with_psub_in_PNR_p8to15_and_PPR2_with_psub1_in_PPR_p8to15, PPR2_with_psub_in_PNR_p8to15_and_PPR2_with_psub1_in_PPR_p8to15Bits, sizeof(PPR2_with_psub_in_PNR_p8to15_and_PPR2_with_psub1_in_PPR_p8to15Bits) },
  { PPR2Mul2_and_PPR2_with_psub_in_PNR_3b, PPR2Mul2_and_PPR2_with_psub_in_PNR_3bBits, sizeof(PPR2Mul2_and_PPR2_with_psub_in_PNR_3bBits) },
  { PPR2Mul2_and_PPR2_with_psub_in_PNR_p8to15, PPR2Mul2_and_PPR2_with_psub_in_PNR_p8to15Bits, sizeof(PPR2Mul2_and_PPR2_with_psub_in_PNR_p8to15Bits) },
  { PPR2_with_psub_in_PNR_3b_and_PPR2_with_psub1_in_PPR_p8to15, PPR2_with_psub_in_PNR_3b_and_PPR2_with_psub1_in_PPR_p8to15Bits, sizeof(PPR2_with_psub_in_PNR_3b_and_PPR2_with_psub1_in_PPR_p8to15Bits) },
  { PPR2_with_psub_in_PNR_p8to15_and_PPR2_with_psub1_in_PPR_3b, PPR2_with_psub_in_PNR_p8to15_and_PPR2_with_psub1_in_PPR_3bBits, sizeof(PPR2_with_psub_in_PNR_p8to15_and_PPR2_with_psub1_in_PPR_3bBits) },
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
  { FPR128_0to7, FPR128_0to7Bits, sizeof(FPR128_0to7Bits) },
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
  { ZPR2StridedOrContiguous, ZPR2StridedOrContiguousBits, sizeof(ZPR2StridedOrContiguousBits) },
  { QQ_with_dsub_in_FPR64_lo, QQ_with_dsub_in_FPR64_loBits, sizeof(QQ_with_dsub_in_FPR64_loBits) },
  { QQ_with_qsub1_in_FPR128_lo, QQ_with_qsub1_in_FPR128_loBits, sizeof(QQ_with_qsub1_in_FPR128_loBits) },
  { ZPR2Mul2, ZPR2Mul2Bits, sizeof(ZPR2Mul2Bits) },
  { ZPR2Strided, ZPR2StridedBits, sizeof(ZPR2StridedBits) },
  { ZPR2StridedOrContiguous_with_dsub_in_FPR64_lo, ZPR2StridedOrContiguous_with_dsub_in_FPR64_loBits, sizeof(ZPR2StridedOrContiguous_with_dsub_in_FPR64_loBits) },
  { ZPR2_with_dsub_in_FPR64_lo, ZPR2_with_dsub_in_FPR64_loBits, sizeof(ZPR2_with_dsub_in_FPR64_loBits) },
  { ZPR2_with_zsub1_in_ZPR_4b, ZPR2_with_zsub1_in_ZPR_4bBits, sizeof(ZPR2_with_zsub1_in_ZPR_4bBits) },
  { QQ_with_dsub_in_FPR64_lo_and_QQ_with_qsub1_in_FPR128_lo, QQ_with_dsub_in_FPR64_lo_and_QQ_with_qsub1_in_FPR128_loBits, sizeof(QQ_with_dsub_in_FPR64_lo_and_QQ_with_qsub1_in_FPR128_loBits) },
  { ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_4b, ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_4bBits, sizeof(ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_4bBits) },
  { ZPR2StridedOrContiguous_with_zsub_in_FPR128_0to7, ZPR2StridedOrContiguous_with_zsub_in_FPR128_0to7Bits, sizeof(ZPR2StridedOrContiguous_with_zsub_in_FPR128_0to7Bits) },
  { QQ_with_qsub0_in_FPR128_0to7, QQ_with_qsub0_in_FPR128_0to7Bits, sizeof(QQ_with_qsub0_in_FPR128_0to7Bits) },
  { QQ_with_qsub1_in_FPR128_0to7, QQ_with_qsub1_in_FPR128_0to7Bits, sizeof(QQ_with_qsub1_in_FPR128_0to7Bits) },
  { ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo, ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits, sizeof(ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits) },
  { ZPR2Strided_with_dsub_in_FPR64_lo, ZPR2Strided_with_dsub_in_FPR64_loBits, sizeof(ZPR2Strided_with_dsub_in_FPR64_loBits) },
  { ZPR2_with_zsub1_in_ZPR_3b, ZPR2_with_zsub1_in_ZPR_3bBits, sizeof(ZPR2_with_zsub1_in_ZPR_3bBits) },
  { ZPR2_with_zsub_in_FPR128_0to7, ZPR2_with_zsub_in_FPR128_0to7Bits, sizeof(ZPR2_with_zsub_in_FPR128_0to7Bits) },
  { QQ_with_dsub_in_FPR64_lo_and_QQ_with_qsub1_in_FPR128_0to7, QQ_with_dsub_in_FPR64_lo_and_QQ_with_qsub1_in_FPR128_0to7Bits, sizeof(QQ_with_dsub_in_FPR64_lo_and_QQ_with_qsub1_in_FPR128_0to7Bits) },
  { ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_3b, ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_3bBits, sizeof(ZPR2_with_dsub_in_FPR64_lo_and_ZPR2_with_zsub1_in_ZPR_3bBits) },
  { ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7, ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits, sizeof(ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits) },
  { MPR64, MPR64Bits, sizeof(MPR64Bits) },
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
  { QQQ_with_qsub0_in_FPR128_0to7, QQQ_with_qsub0_in_FPR128_0to7Bits, sizeof(QQQ_with_qsub0_in_FPR128_0to7Bits) },
  { QQQ_with_qsub1_in_FPR128_0to7, QQQ_with_qsub1_in_FPR128_0to7Bits, sizeof(QQQ_with_qsub1_in_FPR128_0to7Bits) },
  { QQQ_with_qsub2_in_FPR128_0to7, QQQ_with_qsub2_in_FPR128_0to7Bits, sizeof(QQQ_with_qsub2_in_FPR128_0to7Bits) },
  { ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2, ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits, sizeof(ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits) },
  { ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo, ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits, sizeof(ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits) },
  { ZPR3_with_zsub1_in_ZPR_3b, ZPR3_with_zsub1_in_ZPR_3bBits, sizeof(ZPR3_with_zsub1_in_ZPR_3bBits) },
  { ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo, ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits, sizeof(ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits) },
  { ZPR3_with_zsub2_in_ZPR_3b, ZPR3_with_zsub2_in_ZPR_3bBits, sizeof(ZPR3_with_zsub2_in_ZPR_3bBits) },
  { ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2, ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits, sizeof(ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits) },
  { ZPR3_with_zsub_in_FPR128_0to7, ZPR3_with_zsub_in_FPR128_0to7Bits, sizeof(ZPR3_with_zsub_in_FPR128_0to7Bits) },
  { QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub1_in_FPR128_0to7, QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub1_in_FPR128_0to7Bits, sizeof(QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub1_in_FPR128_0to7Bits) },
  { QQQ_with_qsub1_in_FPR128_0to7_and_QQQ_with_qsub2_in_FPR128_0to7, QQQ_with_qsub1_in_FPR128_0to7_and_QQQ_with_qsub2_in_FPR128_0to7Bits, sizeof(QQQ_with_qsub1_in_FPR128_0to7_and_QQQ_with_qsub2_in_FPR128_0to7Bits) },
  { ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_3b, ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_3bBits, sizeof(ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_in_ZPR_3bBits) },
  { ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo, ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits, sizeof(ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits) },
  { ZPR3_with_zsub1_in_ZPR_3b_and_ZPR3_with_zsub2_in_ZPR_3b, ZPR3_with_zsub1_in_ZPR_3b_and_ZPR3_with_zsub2_in_ZPR_3bBits, sizeof(ZPR3_with_zsub1_in_ZPR_3b_and_ZPR3_with_zsub2_in_ZPR_3bBits) },
  { ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo, ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits, sizeof(ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits) },
  { QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub2_in_FPR128_0to7, QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub2_in_FPR128_0to7Bits, sizeof(QQQ_with_dsub_in_FPR64_lo_and_QQQ_with_qsub2_in_FPR128_0to7Bits) },
  { ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_3b, ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_3bBits, sizeof(ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub2_in_ZPR_3bBits) },
  { ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7, ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits, sizeof(ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits) },
  { ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7, ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits, sizeof(ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits) },
  { ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2, ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits, sizeof(ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits) },
  { ZPR3_with_zsub_in_FPR128_0to7_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2, ZPR3_with_zsub_in_FPR128_0to7_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits, sizeof(ZPR3_with_zsub_in_FPR128_0to7_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits) },
  { ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7, ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits, sizeof(ZPR3_with_dsub_in_FPR64_lo_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits) },
  { ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo, ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits, sizeof(ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits) },
  { QQQQ, QQQQBits, sizeof(QQQQBits) },
  { ZPR4, ZPR4Bits, sizeof(ZPR4Bits) },
  { QQQQ_with_dsub_in_FPR64_lo, QQQQ_with_dsub_in_FPR64_loBits, sizeof(QQQQ_with_dsub_in_FPR64_loBits) },
  { QQQQ_with_qsub1_in_FPR128_lo, QQQQ_with_qsub1_in_FPR128_loBits, sizeof(QQQQ_with_qsub1_in_FPR128_loBits) },
  { QQQQ_with_qsub2_in_FPR128_lo, QQQQ_with_qsub2_in_FPR128_loBits, sizeof(QQQQ_with_qsub2_in_FPR128_loBits) },
  { QQQQ_with_qsub3_in_FPR128_lo, QQQQ_with_qsub3_in_FPR128_loBits, sizeof(QQQQ_with_qsub3_in_FPR128_loBits) },
  { ZPR4StridedOrContiguous, ZPR4StridedOrContiguousBits, sizeof(ZPR4StridedOrContiguousBits) },
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
  { QQQQ_with_qsub0_in_FPR128_0to7, QQQQ_with_qsub0_in_FPR128_0to7Bits, sizeof(QQQQ_with_qsub0_in_FPR128_0to7Bits) },
  { QQQQ_with_qsub1_in_FPR128_0to7, QQQQ_with_qsub1_in_FPR128_0to7Bits, sizeof(QQQQ_with_qsub1_in_FPR128_0to7Bits) },
  { QQQQ_with_qsub2_in_FPR128_0to7, QQQQ_with_qsub2_in_FPR128_0to7Bits, sizeof(QQQQ_with_qsub2_in_FPR128_0to7Bits) },
  { QQQQ_with_qsub3_in_FPR128_0to7, QQQQ_with_qsub3_in_FPR128_0to7Bits, sizeof(QQQQ_with_qsub3_in_FPR128_0to7Bits) },
  { ZPR4Mul4, ZPR4Mul4Bits, sizeof(ZPR4Mul4Bits) },
  { ZPR4Strided, ZPR4StridedBits, sizeof(ZPR4StridedBits) },
  { ZPR4StridedOrContiguous_with_dsub_in_FPR64_lo, ZPR4StridedOrContiguous_with_dsub_in_FPR64_loBits, sizeof(ZPR4StridedOrContiguous_with_dsub_in_FPR64_loBits) },
  { ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2, ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits, sizeof(ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits) },
  { ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo, ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits, sizeof(ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits) },
  { ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo, ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits, sizeof(ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits) },
  { ZPR4_with_zsub1_in_ZPR_3b, ZPR4_with_zsub1_in_ZPR_3bBits, sizeof(ZPR4_with_zsub1_in_ZPR_3bBits) },
  { ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo, ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits, sizeof(ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits) },
  { ZPR4_with_zsub2_in_ZPR_3b, ZPR4_with_zsub2_in_ZPR_3bBits, sizeof(ZPR4_with_zsub2_in_ZPR_3bBits) },
  { ZPR4_with_zsub3_in_ZPR_3b, ZPR4_with_zsub3_in_ZPR_3bBits, sizeof(ZPR4_with_zsub3_in_ZPR_3bBits) },
  { ZPR4_with_zsub3_in_ZPR_4b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2, ZPR4_with_zsub3_in_ZPR_4b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits, sizeof(ZPR4_with_zsub3_in_ZPR_4b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits) },
  { ZPR4_with_zsub_in_FPR128_0to7, ZPR4_with_zsub_in_FPR128_0to7Bits, sizeof(ZPR4_with_zsub_in_FPR128_0to7Bits) },
  { QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub1_in_FPR128_0to7, QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub1_in_FPR128_0to7Bits, sizeof(QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub1_in_FPR128_0to7Bits) },
  { QQQQ_with_qsub1_in_FPR128_0to7_and_QQQQ_with_qsub2_in_FPR128_0to7, QQQQ_with_qsub1_in_FPR128_0to7_and_QQQQ_with_qsub2_in_FPR128_0to7Bits, sizeof(QQQQ_with_qsub1_in_FPR128_0to7_and_QQQQ_with_qsub2_in_FPR128_0to7Bits) },
  { QQQQ_with_qsub2_in_FPR128_0to7_and_QQQQ_with_qsub3_in_FPR128_0to7, QQQQ_with_qsub2_in_FPR128_0to7_and_QQQQ_with_qsub3_in_FPR128_0to7Bits, sizeof(QQQQ_with_qsub2_in_FPR128_0to7_and_QQQQ_with_qsub3_in_FPR128_0to7Bits) },
  { ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo, ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits, sizeof(ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits) },
  { ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_3b, ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_3bBits, sizeof(ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_in_ZPR_3bBits) },
  { ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_lo, ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits, sizeof(ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_dsub_in_FPR64_loBits) },
  { ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub2_in_ZPR_3b, ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub2_in_ZPR_3bBits, sizeof(ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub2_in_ZPR_3bBits) },
  { ZPR4_with_zsub1_in_ZPR_4b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2, ZPR4_with_zsub1_in_ZPR_4b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits, sizeof(ZPR4_with_zsub1_in_ZPR_4b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits) },
  { ZPR4_with_zsub2_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3b, ZPR4_with_zsub2_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3bBits, sizeof(ZPR4_with_zsub2_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3bBits) },
  { QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub2_in_FPR128_0to7, QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub2_in_FPR128_0to7Bits, sizeof(QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub2_in_FPR128_0to7Bits) },
  { QQQQ_with_qsub1_in_FPR128_0to7_and_QQQQ_with_qsub3_in_FPR128_0to7, QQQQ_with_qsub1_in_FPR128_0to7_and_QQQQ_with_qsub3_in_FPR128_0to7Bits, sizeof(QQQQ_with_qsub1_in_FPR128_0to7_and_QQQQ_with_qsub3_in_FPR128_0to7Bits) },
  { ZPR4StridedOrContiguous_with_zsub_in_FPR128_0to7, ZPR4StridedOrContiguous_with_zsub_in_FPR128_0to7Bits, sizeof(ZPR4StridedOrContiguous_with_zsub_in_FPR128_0to7Bits) },
  { ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_3b, ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_3bBits, sizeof(ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub2_in_ZPR_3bBits) },
  { ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2, ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits, sizeof(ZPR4_with_dsub_in_FPR64_lo_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_4b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits) },
  { ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3b, ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3bBits, sizeof(ZPR4_with_zsub1_in_ZPR_3b_and_ZPR4_with_zsub3_in_ZPR_3bBits) },
  { QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub3_in_FPR128_0to7, QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub3_in_FPR128_0to7Bits, sizeof(QQQQ_with_dsub_in_FPR64_lo_and_QQQQ_with_qsub3_in_FPR128_0to7Bits) },
  { ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_3b, ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_3bBits, sizeof(ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub3_in_ZPR_3bBits) },
  { ZPR4Mul4_and_ZPR4_with_dsub_in_FPR64_lo, ZPR4Mul4_and_ZPR4_with_dsub_in_FPR64_loBits, sizeof(ZPR4Mul4_and_ZPR4_with_dsub_in_FPR64_loBits) },
  { ZPR4Strided_with_dsub_in_FPR64_lo, ZPR4Strided_with_dsub_in_FPR64_loBits, sizeof(ZPR4Strided_with_dsub_in_FPR64_loBits) },
  { ZPR4_with_dsub_in_FPR64_lo_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub_in_FPR128_0to7_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2, ZPR4_with_dsub_in_FPR64_lo_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub_in_FPR128_0to7_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits, sizeof(ZPR4_with_dsub_in_FPR64_lo_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub_in_FPR128_0to7_and_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits) },
  { ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7, ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits, sizeof(ZPR4_with_zsub0_zsub1_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits) },
  { ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7, ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits, sizeof(ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits) },
  { ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7, ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits, sizeof(ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits) },
  { ZPR4_with_zsub3_in_ZPR_3b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2, ZPR4_with_zsub3_in_ZPR_3b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits, sizeof(ZPR4_with_zsub3_in_ZPR_3b_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2Bits) },
  { ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7, ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits, sizeof(ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub0_zsub1_zsub2_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits) },
  { ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7, ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits, sizeof(ZPR4_with_dsub_in_FPR64_lo_and_ZPR4_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub1_zsub2_in_ZPR2Mul2_and_ZPR2_with_zsub_in_FPR128_0to7Bits) },
  { ZPR4_with_zsub1_in_ZPR_3b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2, ZPR4_with_zsub1_in_ZPR_3b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits, sizeof(ZPR4_with_zsub1_in_ZPR_3b_with_zsub1_zsub2_zsub3_in_ZPR3_with_zsub2_in_ZPR_3b_and_ZPR3_with_zsub0_zsub1_in_ZPR2Mul2Bits) },
  { ZPR4Mul4_and_ZPR4_with_zsub_in_FPR128_0to7, ZPR4Mul4_and_ZPR4_with_zsub_in_FPR128_0to7Bits, sizeof(ZPR4Mul4_and_ZPR4_with_zsub_in_FPR128_0to7Bits) },
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




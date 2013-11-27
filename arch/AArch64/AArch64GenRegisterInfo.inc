/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|*Target Register Enum Values                                                 *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

/* Capstone Disassembler Engine */
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
  AArch64_NUM_TARGET_REGS 	// 228
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
  AArch64_RxspRegClassID = 13,
  AArch64_FPR128RegClassID = 14
};

// Subregister indices
enum {
  AArch64_NoSubRegister,
  AArch64_sub_8,	// 1
  AArch64_sub_16,	// 2
  AArch64_sub_32,	// 3
  AArch64_sub_64,	// 4
  AArch64_sub_128,	// 5
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


#ifdef GET_REGINFO_MC_DESC
#undef GET_REGINFO_MC_DESC

static MCPhysReg AArch64RegDiffLists[] = {
  /* 0 */ 2, 0,
  /* 2 */ 31, 0,
  /* 4 */ 64, 64, 65440, 64, 0,
  /* 9 */ 65374, 0,
  /* 11 */ 65405, 0,
  /* 13 */ 65437, 0,
  /* 15 */ 65469, 0,
  /* 17 */ 65472, 96, 65472, 65472, 0,
  /* 22 */ 65501, 0,
  /* 24 */ 65505, 0,
  /* 26 */ 65533, 0,
  /* 28 */ 65534, 0,
  /* 30 */ 65535, 0,
};

static uint16_t AArch64SubRegIdxLists[] = {
  /* 0 */ 4, 3, 2, 1, 0,
  /* 5 */ 3, 0,
};

static MCRegisterDesc AArch64RegDesc[] = { // Descriptors
  { 3, 0, 0, 0, 0 },
  { 834, 1, 1, 4, 481 },
  { 818, 1, 0, 4, 481 },
  { 826, 1, 0, 4, 481 },
  { 822, 28, 1, 5, 417 },
  { 830, 28, 1, 5, 417 },
  { 84, 1, 4, 4, 417 },
  { 181, 1, 4, 4, 417 },
  { 258, 1, 4, 4, 417 },
  { 335, 1, 4, 4, 417 },
  { 412, 1, 4, 4, 417 },
  { 489, 1, 4, 4, 417 },
  { 566, 1, 4, 4, 417 },
  { 643, 1, 4, 4, 417 },
  { 720, 1, 4, 4, 417 },
  { 797, 1, 4, 4, 417 },
  { 0, 1, 4, 4, 417 },
  { 105, 1, 4, 4, 417 },
  { 202, 1, 4, 4, 417 },
  { 279, 1, 4, 4, 417 },
  { 356, 1, 4, 4, 417 },
  { 433, 1, 4, 4, 417 },
  { 510, 1, 4, 4, 417 },
  { 587, 1, 4, 4, 417 },
  { 664, 1, 4, 4, 417 },
  { 741, 1, 4, 4, 417 },
  { 28, 1, 4, 4, 417 },
  { 133, 1, 4, 4, 417 },
  { 230, 1, 4, 4, 417 },
  { 307, 1, 4, 4, 417 },
  { 384, 1, 4, 4, 417 },
  { 461, 1, 4, 4, 417 },
  { 538, 1, 4, 4, 417 },
  { 615, 1, 4, 4, 417 },
  { 692, 1, 4, 4, 417 },
  { 769, 1, 4, 4, 417 },
  { 56, 1, 4, 4, 417 },
  { 161, 1, 4, 4, 417 },
  { 87, 18, 7, 1, 353 },
  { 184, 18, 7, 1, 353 },
  { 261, 18, 7, 1, 353 },
  { 338, 18, 7, 1, 353 },
  { 415, 18, 7, 1, 353 },
  { 492, 18, 7, 1, 353 },
  { 569, 18, 7, 1, 353 },
  { 646, 18, 7, 1, 353 },
  { 723, 18, 7, 1, 353 },
  { 800, 18, 7, 1, 353 },
  { 4, 18, 7, 1, 353 },
  { 109, 18, 7, 1, 353 },
  { 206, 18, 7, 1, 353 },
  { 283, 18, 7, 1, 353 },
  { 360, 18, 7, 1, 353 },
  { 437, 18, 7, 1, 353 },
  { 514, 18, 7, 1, 353 },
  { 591, 18, 7, 1, 353 },
  { 668, 18, 7, 1, 353 },
  { 745, 18, 7, 1, 353 },
  { 32, 18, 7, 1, 353 },
  { 137, 18, 7, 1, 353 },
  { 234, 18, 7, 1, 353 },
  { 311, 18, 7, 1, 353 },
  { 388, 18, 7, 1, 353 },
  { 465, 18, 7, 1, 353 },
  { 542, 18, 7, 1, 353 },
  { 619, 18, 7, 1, 353 },
  { 696, 18, 7, 1, 353 },
  { 773, 18, 7, 1, 353 },
  { 60, 18, 7, 1, 353 },
  { 165, 18, 7, 1, 353 },
  { 90, 20, 5, 3, 241 },
  { 187, 20, 5, 3, 241 },
  { 264, 20, 5, 3, 241 },
  { 341, 20, 5, 3, 241 },
  { 418, 20, 5, 3, 241 },
  { 495, 20, 5, 3, 241 },
  { 572, 20, 5, 3, 241 },
  { 649, 20, 5, 3, 241 },
  { 726, 20, 5, 3, 241 },
  { 803, 20, 5, 3, 241 },
  { 8, 20, 5, 3, 241 },
  { 113, 20, 5, 3, 241 },
  { 210, 20, 5, 3, 241 },
  { 287, 20, 5, 3, 241 },
  { 364, 20, 5, 3, 241 },
  { 441, 20, 5, 3, 241 },
  { 518, 20, 5, 3, 241 },
  { 595, 20, 5, 3, 241 },
  { 672, 20, 5, 3, 241 },
  { 749, 20, 5, 3, 241 },
  { 36, 20, 5, 3, 241 },
  { 141, 20, 5, 3, 241 },
  { 238, 20, 5, 3, 241 },
  { 315, 20, 5, 3, 241 },
  { 392, 20, 5, 3, 241 },
  { 469, 20, 5, 3, 241 },
  { 546, 20, 5, 3, 241 },
  { 623, 20, 5, 3, 241 },
  { 700, 20, 5, 3, 241 },
  { 777, 20, 5, 3, 241 },
  { 64, 20, 5, 3, 241 },
  { 169, 20, 5, 3, 241 },
  { 93, 17, 1, 0, 209 },
  { 190, 17, 1, 0, 209 },
  { 267, 17, 1, 0, 209 },
  { 344, 17, 1, 0, 209 },
  { 421, 17, 1, 0, 209 },
  { 498, 17, 1, 0, 209 },
  { 575, 17, 1, 0, 209 },
  { 652, 17, 1, 0, 209 },
  { 729, 17, 1, 0, 209 },
  { 806, 17, 1, 0, 209 },
  { 12, 17, 1, 0, 209 },
  { 117, 17, 1, 0, 209 },
  { 214, 17, 1, 0, 209 },
  { 291, 17, 1, 0, 209 },
  { 368, 17, 1, 0, 209 },
  { 445, 17, 1, 0, 209 },
  { 522, 17, 1, 0, 209 },
  { 599, 17, 1, 0, 209 },
  { 676, 17, 1, 0, 209 },
  { 753, 17, 1, 0, 209 },
  { 40, 17, 1, 0, 209 },
  { 145, 17, 1, 0, 209 },
  { 242, 17, 1, 0, 209 },
  { 319, 17, 1, 0, 209 },
  { 396, 17, 1, 0, 209 },
  { 473, 17, 1, 0, 209 },
  { 550, 17, 1, 0, 209 },
  { 627, 17, 1, 0, 209 },
  { 704, 17, 1, 0, 209 },
  { 781, 17, 1, 0, 209 },
  { 68, 17, 1, 0, 209 },
  { 173, 17, 1, 0, 209 },
  { 96, 19, 6, 2, 177 },
  { 193, 19, 6, 2, 177 },
  { 270, 19, 6, 2, 177 },
  { 347, 19, 6, 2, 177 },
  { 424, 19, 6, 2, 177 },
  { 501, 19, 6, 2, 177 },
  { 578, 19, 6, 2, 177 },
  { 655, 19, 6, 2, 177 },
  { 732, 19, 6, 2, 177 },
  { 809, 19, 6, 2, 177 },
  { 16, 19, 6, 2, 177 },
  { 121, 19, 6, 2, 177 },
  { 218, 19, 6, 2, 177 },
  { 295, 19, 6, 2, 177 },
  { 372, 19, 6, 2, 177 },
  { 449, 19, 6, 2, 177 },
  { 526, 19, 6, 2, 177 },
  { 603, 19, 6, 2, 177 },
  { 680, 19, 6, 2, 177 },
  { 757, 19, 6, 2, 177 },
  { 44, 19, 6, 2, 177 },
  { 149, 19, 6, 2, 177 },
  { 246, 19, 6, 2, 177 },
  { 323, 19, 6, 2, 177 },
  { 400, 19, 6, 2, 177 },
  { 477, 19, 6, 2, 177 },
  { 554, 19, 6, 2, 177 },
  { 631, 19, 6, 2, 177 },
  { 708, 19, 6, 2, 177 },
  { 785, 19, 6, 2, 177 },
  { 72, 19, 6, 2, 177 },
  { 177, 19, 6, 2, 177 },
  { 99, 1, 2, 4, 177 },
  { 196, 1, 2, 4, 177 },
  { 273, 1, 2, 4, 177 },
  { 350, 1, 2, 4, 177 },
  { 427, 1, 2, 4, 177 },
  { 504, 1, 2, 4, 177 },
  { 581, 1, 2, 4, 177 },
  { 658, 1, 2, 4, 177 },
  { 735, 1, 2, 4, 177 },
  { 812, 1, 2, 4, 177 },
  { 20, 1, 2, 4, 177 },
  { 125, 1, 2, 4, 177 },
  { 222, 1, 2, 4, 177 },
  { 299, 1, 2, 4, 177 },
  { 376, 1, 2, 4, 177 },
  { 453, 1, 2, 4, 177 },
  { 530, 1, 2, 4, 177 },
  { 607, 1, 2, 4, 177 },
  { 684, 1, 2, 4, 177 },
  { 761, 1, 2, 4, 177 },
  { 48, 1, 2, 4, 177 },
  { 153, 1, 2, 4, 177 },
  { 250, 1, 2, 4, 177 },
  { 327, 1, 2, 4, 177 },
  { 404, 1, 2, 4, 177 },
  { 481, 1, 2, 4, 177 },
  { 558, 1, 2, 4, 177 },
  { 635, 1, 2, 4, 177 },
  { 712, 1, 2, 4, 177 },
  { 789, 1, 2, 4, 177 },
  { 76, 1, 2, 4, 177 },
  { 102, 24, 1, 5, 145 },
  { 199, 24, 1, 5, 145 },
  { 276, 24, 1, 5, 145 },
  { 353, 24, 1, 5, 145 },
  { 430, 24, 1, 5, 145 },
  { 507, 24, 1, 5, 145 },
  { 584, 24, 1, 5, 145 },
  { 661, 24, 1, 5, 145 },
  { 738, 24, 1, 5, 145 },
  { 815, 24, 1, 5, 145 },
  { 24, 24, 1, 5, 145 },
  { 129, 24, 1, 5, 145 },
  { 226, 24, 1, 5, 145 },
  { 303, 24, 1, 5, 145 },
  { 380, 24, 1, 5, 145 },
  { 457, 24, 1, 5, 145 },
  { 534, 24, 1, 5, 145 },
  { 611, 24, 1, 5, 145 },
  { 688, 24, 1, 5, 145 },
  { 765, 24, 1, 5, 145 },
  { 52, 24, 1, 5, 145 },
  { 157, 24, 1, 5, 145 },
  { 254, 24, 1, 5, 145 },
  { 331, 24, 1, 5, 145 },
  { 408, 24, 1, 5, 145 },
  { 485, 24, 1, 5, 145 },
  { 562, 24, 1, 5, 145 },
  { 639, 24, 1, 5, 145 },
  { 716, 24, 1, 5, 145 },
  { 793, 24, 1, 5, 145 },
  { 80, 24, 1, 5, 145 },
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

// Rxsp Register Class...
static uint16_t Rxsp[] = {
  AArch64_XSP, 
};

// Rxsp Bit set.
static uint8_t RxspBits[] = {
  0x10, 
};

// FPR128 Register Class...
static uint16_t FPR128[] = {
  AArch64_Q0, AArch64_Q1, AArch64_Q2, AArch64_Q3, AArch64_Q4, AArch64_Q5, AArch64_Q6, AArch64_Q7, AArch64_Q8, AArch64_Q9, AArch64_Q10, AArch64_Q11, AArch64_Q12, AArch64_Q13, AArch64_Q14, AArch64_Q15, AArch64_Q16, AArch64_Q17, AArch64_Q18, AArch64_Q19, AArch64_Q20, AArch64_Q21, AArch64_Q22, AArch64_Q23, AArch64_Q24, AArch64_Q25, AArch64_Q26, AArch64_Q27, AArch64_Q28, AArch64_Q29, AArch64_Q30, AArch64_Q31, 
};

// FPR128 Bit set.
static uint8_t FPR128Bits[] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f, 
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
  { "Rxsp", Rxsp, RxspBits, 1, sizeof(RxspBits), AArch64_RxspRegClassID, 8, 8, 1, 1 },
  { "FPR128", FPR128, FPR128Bits, 32, sizeof(FPR128Bits), AArch64_FPR128RegClassID, 16, 16, 1, 1 },
};

#endif // GET_REGINFO_MC_DESC

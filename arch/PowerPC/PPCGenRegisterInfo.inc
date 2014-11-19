/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|*Target Register Enum Values                                                 *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */


#ifdef GET_REGINFO_ENUM
#undef GET_REGINFO_ENUM

enum {
  PPC_NoRegister,
  PPC_BP = 1,
  PPC_CARRY = 2,
  PPC_CC = 3,
  PPC_CTR = 4,
  PPC_FP = 5,
  PPC_LR = 6,
  PPC_RM = 7,
  PPC_VRSAVE = 8,
  PPC_ZERO = 9,
  PPC_BP8 = 10,
  PPC_CR0 = 11,
  PPC_CR1 = 12,
  PPC_CR2 = 13,
  PPC_CR3 = 14,
  PPC_CR4 = 15,
  PPC_CR5 = 16,
  PPC_CR6 = 17,
  PPC_CR7 = 18,
  PPC_CTR8 = 19,
  PPC_F0 = 20,
  PPC_F1 = 21,
  PPC_F2 = 22,
  PPC_F3 = 23,
  PPC_F4 = 24,
  PPC_F5 = 25,
  PPC_F6 = 26,
  PPC_F7 = 27,
  PPC_F8 = 28,
  PPC_F9 = 29,
  PPC_F10 = 30,
  PPC_F11 = 31,
  PPC_F12 = 32,
  PPC_F13 = 33,
  PPC_F14 = 34,
  PPC_F15 = 35,
  PPC_F16 = 36,
  PPC_F17 = 37,
  PPC_F18 = 38,
  PPC_F19 = 39,
  PPC_F20 = 40,
  PPC_F21 = 41,
  PPC_F22 = 42,
  PPC_F23 = 43,
  PPC_F24 = 44,
  PPC_F25 = 45,
  PPC_F26 = 46,
  PPC_F27 = 47,
  PPC_F28 = 48,
  PPC_F29 = 49,
  PPC_F30 = 50,
  PPC_F31 = 51,
  PPC_FP8 = 52,
  PPC_LR8 = 53,
  PPC_R0 = 54,
  PPC_R1 = 55,
  PPC_R2 = 56,
  PPC_R3 = 57,
  PPC_R4 = 58,
  PPC_R5 = 59,
  PPC_R6 = 60,
  PPC_R7 = 61,
  PPC_R8 = 62,
  PPC_R9 = 63,
  PPC_R10 = 64,
  PPC_R11 = 65,
  PPC_R12 = 66,
  PPC_R13 = 67,
  PPC_R14 = 68,
  PPC_R15 = 69,
  PPC_R16 = 70,
  PPC_R17 = 71,
  PPC_R18 = 72,
  PPC_R19 = 73,
  PPC_R20 = 74,
  PPC_R21 = 75,
  PPC_R22 = 76,
  PPC_R23 = 77,
  PPC_R24 = 78,
  PPC_R25 = 79,
  PPC_R26 = 80,
  PPC_R27 = 81,
  PPC_R28 = 82,
  PPC_R29 = 83,
  PPC_R30 = 84,
  PPC_R31 = 85,
  PPC_V0 = 86,
  PPC_V1 = 87,
  PPC_V2 = 88,
  PPC_V3 = 89,
  PPC_V4 = 90,
  PPC_V5 = 91,
  PPC_V6 = 92,
  PPC_V7 = 93,
  PPC_V8 = 94,
  PPC_V9 = 95,
  PPC_V10 = 96,
  PPC_V11 = 97,
  PPC_V12 = 98,
  PPC_V13 = 99,
  PPC_V14 = 100,
  PPC_V15 = 101,
  PPC_V16 = 102,
  PPC_V17 = 103,
  PPC_V18 = 104,
  PPC_V19 = 105,
  PPC_V20 = 106,
  PPC_V21 = 107,
  PPC_V22 = 108,
  PPC_V23 = 109,
  PPC_V24 = 110,
  PPC_V25 = 111,
  PPC_V26 = 112,
  PPC_V27 = 113,
  PPC_V28 = 114,
  PPC_V29 = 115,
  PPC_V30 = 116,
  PPC_V31 = 117,
  PPC_VF0 = 118,
  PPC_VF1 = 119,
  PPC_VF2 = 120,
  PPC_VF3 = 121,
  PPC_VF4 = 122,
  PPC_VF5 = 123,
  PPC_VF6 = 124,
  PPC_VF7 = 125,
  PPC_VF8 = 126,
  PPC_VF9 = 127,
  PPC_VF10 = 128,
  PPC_VF11 = 129,
  PPC_VF12 = 130,
  PPC_VF13 = 131,
  PPC_VF14 = 132,
  PPC_VF15 = 133,
  PPC_VF16 = 134,
  PPC_VF17 = 135,
  PPC_VF18 = 136,
  PPC_VF19 = 137,
  PPC_VF20 = 138,
  PPC_VF21 = 139,
  PPC_VF22 = 140,
  PPC_VF23 = 141,
  PPC_VF24 = 142,
  PPC_VF25 = 143,
  PPC_VF26 = 144,
  PPC_VF27 = 145,
  PPC_VF28 = 146,
  PPC_VF29 = 147,
  PPC_VF30 = 148,
  PPC_VF31 = 149,
  PPC_VSH0 = 150,
  PPC_VSH1 = 151,
  PPC_VSH2 = 152,
  PPC_VSH3 = 153,
  PPC_VSH4 = 154,
  PPC_VSH5 = 155,
  PPC_VSH6 = 156,
  PPC_VSH7 = 157,
  PPC_VSH8 = 158,
  PPC_VSH9 = 159,
  PPC_VSH10 = 160,
  PPC_VSH11 = 161,
  PPC_VSH12 = 162,
  PPC_VSH13 = 163,
  PPC_VSH14 = 164,
  PPC_VSH15 = 165,
  PPC_VSH16 = 166,
  PPC_VSH17 = 167,
  PPC_VSH18 = 168,
  PPC_VSH19 = 169,
  PPC_VSH20 = 170,
  PPC_VSH21 = 171,
  PPC_VSH22 = 172,
  PPC_VSH23 = 173,
  PPC_VSH24 = 174,
  PPC_VSH25 = 175,
  PPC_VSH26 = 176,
  PPC_VSH27 = 177,
  PPC_VSH28 = 178,
  PPC_VSH29 = 179,
  PPC_VSH30 = 180,
  PPC_VSH31 = 181,
  PPC_VSL0 = 182,
  PPC_VSL1 = 183,
  PPC_VSL2 = 184,
  PPC_VSL3 = 185,
  PPC_VSL4 = 186,
  PPC_VSL5 = 187,
  PPC_VSL6 = 188,
  PPC_VSL7 = 189,
  PPC_VSL8 = 190,
  PPC_VSL9 = 191,
  PPC_VSL10 = 192,
  PPC_VSL11 = 193,
  PPC_VSL12 = 194,
  PPC_VSL13 = 195,
  PPC_VSL14 = 196,
  PPC_VSL15 = 197,
  PPC_VSL16 = 198,
  PPC_VSL17 = 199,
  PPC_VSL18 = 200,
  PPC_VSL19 = 201,
  PPC_VSL20 = 202,
  PPC_VSL21 = 203,
  PPC_VSL22 = 204,
  PPC_VSL23 = 205,
  PPC_VSL24 = 206,
  PPC_VSL25 = 207,
  PPC_VSL26 = 208,
  PPC_VSL27 = 209,
  PPC_VSL28 = 210,
  PPC_VSL29 = 211,
  PPC_VSL30 = 212,
  PPC_VSL31 = 213,
  PPC_X0 = 214,
  PPC_X1 = 215,
  PPC_X2 = 216,
  PPC_X3 = 217,
  PPC_X4 = 218,
  PPC_X5 = 219,
  PPC_X6 = 220,
  PPC_X7 = 221,
  PPC_X8 = 222,
  PPC_X9 = 223,
  PPC_X10 = 224,
  PPC_X11 = 225,
  PPC_X12 = 226,
  PPC_X13 = 227,
  PPC_X14 = 228,
  PPC_X15 = 229,
  PPC_X16 = 230,
  PPC_X17 = 231,
  PPC_X18 = 232,
  PPC_X19 = 233,
  PPC_X20 = 234,
  PPC_X21 = 235,
  PPC_X22 = 236,
  PPC_X23 = 237,
  PPC_X24 = 238,
  PPC_X25 = 239,
  PPC_X26 = 240,
  PPC_X27 = 241,
  PPC_X28 = 242,
  PPC_X29 = 243,
  PPC_X30 = 244,
  PPC_X31 = 245,
  PPC_ZERO8 = 246,
  PPC_CR0EQ = 247,
  PPC_CR1EQ = 248,
  PPC_CR2EQ = 249,
  PPC_CR3EQ = 250,
  PPC_CR4EQ = 251,
  PPC_CR5EQ = 252,
  PPC_CR6EQ = 253,
  PPC_CR7EQ = 254,
  PPC_CR0GT = 255,
  PPC_CR1GT = 256,
  PPC_CR2GT = 257,
  PPC_CR3GT = 258,
  PPC_CR4GT = 259,
  PPC_CR5GT = 260,
  PPC_CR6GT = 261,
  PPC_CR7GT = 262,
  PPC_CR0LT = 263,
  PPC_CR1LT = 264,
  PPC_CR2LT = 265,
  PPC_CR3LT = 266,
  PPC_CR4LT = 267,
  PPC_CR5LT = 268,
  PPC_CR6LT = 269,
  PPC_CR7LT = 270,
  PPC_CR0UN = 271,
  PPC_CR1UN = 272,
  PPC_CR2UN = 273,
  PPC_CR3UN = 274,
  PPC_CR4UN = 275,
  PPC_CR5UN = 276,
  PPC_CR6UN = 277,
  PPC_CR7UN = 278,
  PPC_NUM_TARGET_REGS 	// 279
};

// Register classes
enum {
  PPC_GPRCRegClassID = 0,
  PPC_GPRC_NOR0RegClassID = 1,
  PPC_GPRC_and_GPRC_NOR0RegClassID = 2,
  PPC_CRBITRCRegClassID = 3,
  PPC_F4RCRegClassID = 4,
  PPC_CRRCRegClassID = 5,
  PPC_CARRYRCRegClassID = 6,
  PPC_CCRCRegClassID = 7,
  PPC_CTRRCRegClassID = 8,
  PPC_VRSAVERCRegClassID = 9,
  PPC_VSFRCRegClassID = 10,
  PPC_G8RCRegClassID = 11,
  PPC_G8RC_NOX0RegClassID = 12,
  PPC_G8RC_and_G8RC_NOX0RegClassID = 13,
  PPC_F8RCRegClassID = 14,
  PPC_VFRCRegClassID = 15,
  PPC_CTRRC8RegClassID = 16,
  PPC_VSRCRegClassID = 17,
  PPC_VRRCRegClassID = 18,
  PPC_VSHRCRegClassID = 19,
  PPC_VSLRCRegClassID = 20
};

// Subregister indices
enum {
  PPC_NoSubRegister,
  PPC_sub_32,	// 1
  PPC_sub_64,	// 2
  PPC_sub_128,	// 3
  PPC_sub_eq,	// 4
  PPC_sub_gt,	// 5
  PPC_sub_lt,	// 6
  PPC_sub_un,	// 7
  PPC_NUM_TARGET_SUBREGS
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

static MCPhysReg PPCRegDiffLists[] = {
  /* 0 */ 0, 0,
  /* 2 */ 2, 1, 1, 1, 1, 1, 1, 1, 0,
  /* 11 */ 65527, 14, 1, 1, 1, 0,
  /* 17 */ 65527, 17, 1, 1, 1, 0,
  /* 23 */ 65527, 20, 1, 1, 1, 0,
  /* 29 */ 65527, 23, 1, 1, 1, 0,
  /* 35 */ 65527, 26, 1, 1, 1, 0,
  /* 41 */ 65527, 29, 1, 1, 1, 0,
  /* 47 */ 65527, 32, 1, 1, 1, 0,
  /* 53 */ 65527, 35, 1, 1, 1, 0,
  /* 59 */ 6, 0,
  /* 61 */ 9, 0,
  /* 63 */ 11, 0,
  /* 65 */ 252, 65528, 65528, 24, 0,
  /* 70 */ 28, 0,
  /* 72 */ 29, 0,
  /* 74 */ 65472, 32, 0,
  /* 77 */ 47, 0,
  /* 79 */ 65504, 64, 0,
  /* 82 */ 160, 0,
  /* 84 */ 162, 0,
  /* 86 */ 237, 0,
  /* 88 */ 64471, 0,
  /* 90 */ 64500, 0,
  /* 92 */ 64533, 0,
  /* 94 */ 64566, 0,
  /* 96 */ 64813, 0,
  /* 98 */ 65276, 0,
  /* 100 */ 65284, 0,
  /* 102 */ 65292, 0,
  /* 104 */ 65299, 0,
  /* 106 */ 65300, 0,
  /* 108 */ 65374, 0,
  /* 110 */ 65376, 0,
  /* 112 */ 65403, 0,
  /* 114 */ 65404, 0,
  /* 116 */ 65489, 0,
  /* 118 */ 65500, 0,
  /* 120 */ 65527, 0,
  /* 122 */ 65532, 0,
  /* 124 */ 65535, 0,
};

static uint16_t PPCSubRegIdxLists[] = {
  /* 0 */ 1, 0,
  /* 2 */ 3, 2, 0,
  /* 5 */ 6, 5, 4, 7, 0,
};

static MCRegisterDesc PPCRegDesc[] = { // Descriptors
  { 4, 0, 0, 0, 0 },
  { 962, 1, 61, 1, 1985 },
  { 1119, 1, 1, 1, 1985 },
  { 896, 1, 1, 1, 32 },
  { 1019, 1, 1, 1, 945 },
  { 965, 1, 77, 1, 945 },
  { 1016, 1, 1, 1, 945 },
  { 906, 1, 1, 1, 945 },
  { 899, 1, 1, 1, 945 },
  { 957, 1, 86, 1, 945 },
  { 792, 120, 1, 0, 0 },
  { 101, 65, 1, 5, 177 },
  { 212, 65, 1, 5, 273 },
  { 294, 65, 1, 5, 369 },
  { 376, 65, 1, 5, 465 },
  { 458, 65, 1, 5, 561 },
  { 540, 65, 1, 5, 657 },
  { 622, 65, 1, 5, 753 },
  { 704, 65, 1, 5, 849 },
  { 804, 1, 1, 1, 1153 },
  { 88, 1, 84, 1, 1153 },
  { 199, 1, 84, 1, 1153 },
  { 281, 1, 84, 1, 1153 },
  { 363, 1, 84, 1, 1153 },
  { 445, 1, 84, 1, 1153 },
  { 527, 1, 84, 1, 1153 },
  { 609, 1, 84, 1, 1153 },
  { 691, 1, 84, 1, 1153 },
  { 773, 1, 84, 1, 1153 },
  { 874, 1, 84, 1, 1153 },
  { 1, 1, 84, 1, 1153 },
  { 112, 1, 84, 1, 1153 },
  { 223, 1, 84, 1, 1153 },
  { 305, 1, 84, 1, 1153 },
  { 387, 1, 84, 1, 1153 },
  { 469, 1, 84, 1, 1153 },
  { 551, 1, 84, 1, 1153 },
  { 633, 1, 84, 1, 1153 },
  { 715, 1, 84, 1, 1153 },
  { 816, 1, 84, 1, 1153 },
  { 30, 1, 84, 1, 1153 },
  { 141, 1, 84, 1, 1153 },
  { 252, 1, 84, 1, 1153 },
  { 334, 1, 84, 1, 1153 },
  { 416, 1, 84, 1, 1153 },
  { 498, 1, 84, 1, 1153 },
  { 580, 1, 84, 1, 1153 },
  { 662, 1, 84, 1, 1153 },
  { 744, 1, 84, 1, 1153 },
  { 845, 1, 84, 1, 1153 },
  { 59, 1, 84, 1, 1153 },
  { 170, 1, 84, 1, 1153 },
  { 796, 116, 1, 0, 1008 },
  { 800, 1, 1, 1, 1121 },
  { 102, 1, 82, 1, 1121 },
  { 213, 1, 82, 1, 1121 },
  { 295, 1, 82, 1, 1121 },
  { 377, 1, 82, 1, 1121 },
  { 459, 1, 82, 1, 1121 },
  { 541, 1, 82, 1, 1121 },
  { 623, 1, 82, 1, 1121 },
  { 705, 1, 82, 1, 1121 },
  { 801, 1, 82, 1, 1121 },
  { 887, 1, 82, 1, 1121 },
  { 17, 1, 82, 1, 1121 },
  { 128, 1, 82, 1, 1121 },
  { 239, 1, 82, 1, 1121 },
  { 321, 1, 82, 1, 1121 },
  { 403, 1, 82, 1, 1121 },
  { 485, 1, 82, 1, 1121 },
  { 567, 1, 82, 1, 1121 },
  { 649, 1, 82, 1, 1121 },
  { 731, 1, 82, 1, 1121 },
  { 832, 1, 82, 1, 1121 },
  { 46, 1, 82, 1, 1121 },
  { 157, 1, 82, 1, 1121 },
  { 268, 1, 82, 1, 1121 },
  { 350, 1, 82, 1, 1121 },
  { 432, 1, 82, 1, 1121 },
  { 514, 1, 82, 1, 1121 },
  { 596, 1, 82, 1, 1121 },
  { 678, 1, 82, 1, 1121 },
  { 760, 1, 82, 1, 1121 },
  { 861, 1, 82, 1, 1121 },
  { 75, 1, 82, 1, 1121 },
  { 186, 1, 82, 1, 1121 },
  { 105, 75, 80, 3, 1121 },
  { 216, 75, 80, 3, 1121 },
  { 298, 75, 80, 3, 1121 },
  { 380, 75, 80, 3, 1121 },
  { 462, 75, 80, 3, 1121 },
  { 544, 75, 80, 3, 1121 },
  { 626, 75, 80, 3, 1121 },
  { 708, 75, 80, 3, 1121 },
  { 809, 75, 80, 3, 1121 },
  { 890, 75, 80, 3, 1121 },
  { 21, 75, 80, 3, 1121 },
  { 132, 75, 80, 3, 1121 },
  { 243, 75, 80, 3, 1121 },
  { 325, 75, 80, 3, 1121 },
  { 407, 75, 80, 3, 1121 },
  { 489, 75, 80, 3, 1121 },
  { 571, 75, 80, 3, 1121 },
  { 653, 75, 80, 3, 1121 },
  { 735, 75, 80, 3, 1121 },
  { 836, 75, 80, 3, 1121 },
  { 50, 75, 80, 3, 1121 },
  { 161, 75, 80, 3, 1121 },
  { 272, 75, 80, 3, 1121 },
  { 354, 75, 80, 3, 1121 },
  { 436, 75, 80, 3, 1121 },
  { 518, 75, 80, 3, 1121 },
  { 600, 75, 80, 3, 1121 },
  { 682, 75, 80, 3, 1121 },
  { 764, 75, 80, 3, 1121 },
  { 865, 75, 80, 3, 1121 },
  { 79, 75, 80, 3, 1121 },
  { 190, 75, 80, 3, 1121 },
  { 87, 1, 79, 1, 1953 },
  { 198, 1, 79, 1, 1953 },
  { 280, 1, 79, 1, 1953 },
  { 362, 1, 79, 1, 1953 },
  { 444, 1, 79, 1, 1953 },
  { 526, 1, 79, 1, 1953 },
  { 608, 1, 79, 1, 1953 },
  { 690, 1, 79, 1, 1953 },
  { 772, 1, 79, 1, 1953 },
  { 873, 1, 79, 1, 1953 },
  { 0, 1, 79, 1, 1953 },
  { 111, 1, 79, 1, 1953 },
  { 222, 1, 79, 1, 1953 },
  { 304, 1, 79, 1, 1953 },
  { 386, 1, 79, 1, 1953 },
  { 468, 1, 79, 1, 1953 },
  { 550, 1, 79, 1, 1953 },
  { 632, 1, 79, 1, 1953 },
  { 714, 1, 79, 1, 1953 },
  { 815, 1, 79, 1, 1953 },
  { 29, 1, 79, 1, 1953 },
  { 140, 1, 79, 1, 1953 },
  { 251, 1, 79, 1, 1953 },
  { 333, 1, 79, 1, 1953 },
  { 415, 1, 79, 1, 1953 },
  { 497, 1, 79, 1, 1953 },
  { 579, 1, 79, 1, 1953 },
  { 661, 1, 79, 1, 1953 },
  { 743, 1, 79, 1, 1953 },
  { 844, 1, 79, 1, 1953 },
  { 58, 1, 79, 1, 1953 },
  { 169, 1, 79, 1, 1953 },
  { 91, 74, 1, 2, 1889 },
  { 202, 74, 1, 2, 1889 },
  { 284, 74, 1, 2, 1889 },
  { 366, 74, 1, 2, 1889 },
  { 448, 74, 1, 2, 1889 },
  { 530, 74, 1, 2, 1889 },
  { 612, 74, 1, 2, 1889 },
  { 694, 74, 1, 2, 1889 },
  { 776, 74, 1, 2, 1889 },
  { 877, 74, 1, 2, 1889 },
  { 5, 74, 1, 2, 1889 },
  { 116, 74, 1, 2, 1889 },
  { 227, 74, 1, 2, 1889 },
  { 309, 74, 1, 2, 1889 },
  { 391, 74, 1, 2, 1889 },
  { 473, 74, 1, 2, 1889 },
  { 555, 74, 1, 2, 1889 },
  { 637, 74, 1, 2, 1889 },
  { 719, 74, 1, 2, 1889 },
  { 820, 74, 1, 2, 1889 },
  { 34, 74, 1, 2, 1889 },
  { 145, 74, 1, 2, 1889 },
  { 256, 74, 1, 2, 1889 },
  { 338, 74, 1, 2, 1889 },
  { 420, 74, 1, 2, 1889 },
  { 502, 74, 1, 2, 1889 },
  { 584, 74, 1, 2, 1889 },
  { 666, 74, 1, 2, 1889 },
  { 748, 74, 1, 2, 1889 },
  { 849, 74, 1, 2, 1889 },
  { 63, 74, 1, 2, 1889 },
  { 174, 74, 1, 2, 1889 },
  { 96, 108, 1, 3, 1793 },
  { 207, 108, 1, 3, 1793 },
  { 289, 108, 1, 3, 1793 },
  { 371, 108, 1, 3, 1793 },
  { 453, 108, 1, 3, 1793 },
  { 535, 108, 1, 3, 1793 },
  { 617, 108, 1, 3, 1793 },
  { 699, 108, 1, 3, 1793 },
  { 781, 108, 1, 3, 1793 },
  { 882, 108, 1, 3, 1793 },
  { 11, 108, 1, 3, 1793 },
  { 122, 108, 1, 3, 1793 },
  { 233, 108, 1, 3, 1793 },
  { 315, 108, 1, 3, 1793 },
  { 397, 108, 1, 3, 1793 },
  { 479, 108, 1, 3, 1793 },
  { 561, 108, 1, 3, 1793 },
  { 643, 108, 1, 3, 1793 },
  { 725, 108, 1, 3, 1793 },
  { 826, 108, 1, 3, 1793 },
  { 40, 108, 1, 3, 1793 },
  { 151, 108, 1, 3, 1793 },
  { 262, 108, 1, 3, 1793 },
  { 344, 108, 1, 3, 1793 },
  { 426, 108, 1, 3, 1793 },
  { 508, 108, 1, 3, 1793 },
  { 590, 108, 1, 3, 1793 },
  { 672, 108, 1, 3, 1793 },
  { 754, 108, 1, 3, 1793 },
  { 855, 108, 1, 3, 1793 },
  { 69, 108, 1, 3, 1793 },
  { 180, 108, 1, 3, 1793 },
  { 108, 110, 1, 0, 1825 },
  { 219, 110, 1, 0, 1825 },
  { 301, 110, 1, 0, 1825 },
  { 383, 110, 1, 0, 1825 },
  { 465, 110, 1, 0, 1825 },
  { 547, 110, 1, 0, 1825 },
  { 629, 110, 1, 0, 1825 },
  { 711, 110, 1, 0, 1825 },
  { 812, 110, 1, 0, 1825 },
  { 893, 110, 1, 0, 1825 },
  { 25, 110, 1, 0, 1825 },
  { 136, 110, 1, 0, 1825 },
  { 247, 110, 1, 0, 1825 },
  { 329, 110, 1, 0, 1825 },
  { 411, 110, 1, 0, 1825 },
  { 493, 110, 1, 0, 1825 },
  { 575, 110, 1, 0, 1825 },
  { 657, 110, 1, 0, 1825 },
  { 739, 110, 1, 0, 1825 },
  { 840, 110, 1, 0, 1825 },
  { 54, 110, 1, 0, 1825 },
  { 165, 110, 1, 0, 1825 },
  { 276, 110, 1, 0, 1825 },
  { 358, 110, 1, 0, 1825 },
  { 440, 110, 1, 0, 1825 },
  { 522, 110, 1, 0, 1825 },
  { 604, 110, 1, 0, 1825 },
  { 686, 110, 1, 0, 1825 },
  { 768, 110, 1, 0, 1825 },
  { 869, 110, 1, 0, 1825 },
  { 83, 110, 1, 0, 1825 },
  { 194, 110, 1, 0, 1825 },
  { 786, 104, 1, 0, 1539 },
  { 968, 1, 106, 1, 1539 },
  { 974, 1, 106, 1, 1508 },
  { 980, 1, 106, 1, 1508 },
  { 986, 1, 106, 1, 1508 },
  { 992, 1, 106, 1, 1508 },
  { 998, 1, 106, 1, 1508 },
  { 1004, 1, 106, 1, 1508 },
  { 1010, 1, 106, 1, 1508 },
  { 1023, 1, 102, 1, 1476 },
  { 1029, 1, 102, 1, 1476 },
  { 1035, 1, 102, 1, 1476 },
  { 1041, 1, 102, 1, 1476 },
  { 1047, 1, 102, 1, 1476 },
  { 1053, 1, 102, 1, 1476 },
  { 1059, 1, 102, 1, 1476 },
  { 1065, 1, 102, 1, 1476 },
  { 1071, 1, 100, 1, 1444 },
  { 1077, 1, 100, 1, 1444 },
  { 1083, 1, 100, 1, 1444 },
  { 1089, 1, 100, 1, 1444 },
  { 1095, 1, 100, 1, 1444 },
  { 1101, 1, 100, 1, 1444 },
  { 1107, 1, 100, 1, 1444 },
  { 1113, 1, 100, 1, 1444 },
  { 909, 1, 98, 1, 1412 },
  { 915, 1, 98, 1, 1412 },
  { 921, 1, 98, 1, 1412 },
  { 927, 1, 98, 1, 1412 },
  { 933, 1, 98, 1, 1412 },
  { 939, 1, 98, 1, 1412 },
  { 945, 1, 98, 1, 1412 },
  { 951, 1, 98, 1, 1412 },
};


  // GPRC Register Class...
  static MCPhysReg GPRC[] = {
    PPC_R2, PPC_R3, PPC_R4, PPC_R5, PPC_R6, PPC_R7, PPC_R8, PPC_R9, PPC_R10, PPC_R11, PPC_R12, PPC_R30, PPC_R29, PPC_R28, PPC_R27, PPC_R26, PPC_R25, PPC_R24, PPC_R23, PPC_R22, PPC_R21, PPC_R20, PPC_R19, PPC_R18, PPC_R17, PPC_R16, PPC_R15, PPC_R14, PPC_R13, PPC_R31, PPC_R0, PPC_R1, PPC_FP, PPC_BP, 
  };

  // GPRC Bit set.
  static uint8_t GPRCBits[] = {
    0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f, 
  };

  // GPRC_NOR0 Register Class...
  static MCPhysReg GPRC_NOR0[] = {
    PPC_R2, PPC_R3, PPC_R4, PPC_R5, PPC_R6, PPC_R7, PPC_R8, PPC_R9, PPC_R10, PPC_R11, PPC_R12, PPC_R30, PPC_R29, PPC_R28, PPC_R27, PPC_R26, PPC_R25, PPC_R24, PPC_R23, PPC_R22, PPC_R21, PPC_R20, PPC_R19, PPC_R18, PPC_R17, PPC_R16, PPC_R15, PPC_R14, PPC_R13, PPC_R31, PPC_R1, PPC_FP, PPC_BP, PPC_ZERO, 
  };

  // GPRC_NOR0 Bit set.
  static uint8_t GPRC_NOR0Bits[] = {
    0x22, 0x02, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0xff, 0x3f, 
  };

  // GPRC_and_GPRC_NOR0 Register Class...
  static MCPhysReg GPRC_and_GPRC_NOR0[] = {
    PPC_R2, PPC_R3, PPC_R4, PPC_R5, PPC_R6, PPC_R7, PPC_R8, PPC_R9, PPC_R10, PPC_R11, PPC_R12, PPC_R30, PPC_R29, PPC_R28, PPC_R27, PPC_R26, PPC_R25, PPC_R24, PPC_R23, PPC_R22, PPC_R21, PPC_R20, PPC_R19, PPC_R18, PPC_R17, PPC_R16, PPC_R15, PPC_R14, PPC_R13, PPC_R31, PPC_R1, PPC_FP, PPC_BP, 
  };

  // GPRC_and_GPRC_NOR0 Bit set.
  static uint8_t GPRC_and_GPRC_NOR0Bits[] = {
    0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0xff, 0x3f, 
  };

  // CRBITRC Register Class...
  static MCPhysReg CRBITRC[] = {
    PPC_CR2LT, PPC_CR2GT, PPC_CR2EQ, PPC_CR2UN, PPC_CR3LT, PPC_CR3GT, PPC_CR3EQ, PPC_CR3UN, PPC_CR4LT, PPC_CR4GT, PPC_CR4EQ, PPC_CR4UN, PPC_CR5LT, PPC_CR5GT, PPC_CR5EQ, PPC_CR5UN, PPC_CR6LT, PPC_CR6GT, PPC_CR6EQ, PPC_CR6UN, PPC_CR7LT, PPC_CR7GT, PPC_CR7EQ, PPC_CR7UN, PPC_CR1LT, PPC_CR1GT, PPC_CR1EQ, PPC_CR1UN, PPC_CR0LT, PPC_CR0GT, PPC_CR0EQ, PPC_CR0UN, 
  };

  // CRBITRC Bit set.
  static uint8_t CRBITRCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0xff, 0x7f, 
  };

  // F4RC Register Class...
  static MCPhysReg F4RC[] = {
    PPC_F0, PPC_F1, PPC_F2, PPC_F3, PPC_F4, PPC_F5, PPC_F6, PPC_F7, PPC_F8, PPC_F9, PPC_F10, PPC_F11, PPC_F12, PPC_F13, PPC_F31, PPC_F30, PPC_F29, PPC_F28, PPC_F27, PPC_F26, PPC_F25, PPC_F24, PPC_F23, PPC_F22, PPC_F21, PPC_F20, PPC_F19, PPC_F18, PPC_F17, PPC_F16, PPC_F15, PPC_F14, 
  };

  // F4RC Bit set.
  static uint8_t F4RCBits[] = {
    0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // CRRC Register Class...
  static MCPhysReg CRRC[] = {
    PPC_CR0, PPC_CR1, PPC_CR5, PPC_CR6, PPC_CR7, PPC_CR2, PPC_CR3, PPC_CR4, 
  };

  // CRRC Bit set.
  static uint8_t CRRCBits[] = {
    0x00, 0xf8, 0x07, 
  };

  // CARRYRC Register Class...
  static MCPhysReg CARRYRC[] = {
    PPC_CARRY, 
  };

  // CARRYRC Bit set.
  static uint8_t CARRYRCBits[] = {
    0x04, 
  };

  // CCRC Register Class...
  static MCPhysReg CCRC[] = {
    PPC_CC, 
  };

  // CCRC Bit set.
  static uint8_t CCRCBits[] = {
    0x08, 
  };

  // CTRRC Register Class...
  static MCPhysReg CTRRC[] = {
    PPC_CTR, 
  };

  // CTRRC Bit set.
  static uint8_t CTRRCBits[] = {
    0x10, 
  };

  // VRSAVERC Register Class...
  static MCPhysReg VRSAVERC[] = {
    PPC_VRSAVE, 
  };

  // VRSAVERC Bit set.
  static uint8_t VRSAVERCBits[] = {
    0x00, 0x01, 
  };

  // VSFRC Register Class...
  static MCPhysReg VSFRC[] = {
    PPC_F0, PPC_F1, PPC_F2, PPC_F3, PPC_F4, PPC_F5, PPC_F6, PPC_F7, PPC_F8, PPC_F9, PPC_F10, PPC_F11, PPC_F12, PPC_F13, PPC_F31, PPC_F30, PPC_F29, PPC_F28, PPC_F27, PPC_F26, PPC_F25, PPC_F24, PPC_F23, PPC_F22, PPC_F21, PPC_F20, PPC_F19, PPC_F18, PPC_F17, PPC_F16, PPC_F15, PPC_F14, PPC_VF2, PPC_VF3, PPC_VF4, PPC_VF5, PPC_VF0, PPC_VF1, PPC_VF6, PPC_VF7, PPC_VF8, PPC_VF9, PPC_VF10, PPC_VF11, PPC_VF12, PPC_VF13, PPC_VF14, PPC_VF15, PPC_VF16, PPC_VF17, PPC_VF18, PPC_VF19, PPC_VF31, PPC_VF30, PPC_VF29, PPC_VF28, PPC_VF27, PPC_VF26, PPC_VF25, PPC_VF24, PPC_VF23, PPC_VF22, PPC_VF21, PPC_VF20, 
  };

  // VSFRC Bit set.
  static uint8_t VSFRCBits[] = {
    0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f, 
  };

  // G8RC Register Class...
  static MCPhysReg G8RC[] = {
    PPC_X2, PPC_X3, PPC_X4, PPC_X5, PPC_X6, PPC_X7, PPC_X8, PPC_X9, PPC_X10, PPC_X11, PPC_X12, PPC_X30, PPC_X29, PPC_X28, PPC_X27, PPC_X26, PPC_X25, PPC_X24, PPC_X23, PPC_X22, PPC_X21, PPC_X20, PPC_X19, PPC_X18, PPC_X17, PPC_X16, PPC_X15, PPC_X14, PPC_X31, PPC_X13, PPC_X0, PPC_X1, PPC_FP8, PPC_BP8, 
  };

  // G8RC Bit set.
  static uint8_t G8RCBits[] = {
    0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f, 
  };

  // G8RC_NOX0 Register Class...
  static MCPhysReg G8RC_NOX0[] = {
    PPC_X2, PPC_X3, PPC_X4, PPC_X5, PPC_X6, PPC_X7, PPC_X8, PPC_X9, PPC_X10, PPC_X11, PPC_X12, PPC_X30, PPC_X29, PPC_X28, PPC_X27, PPC_X26, PPC_X25, PPC_X24, PPC_X23, PPC_X22, PPC_X21, PPC_X20, PPC_X19, PPC_X18, PPC_X17, PPC_X16, PPC_X15, PPC_X14, PPC_X31, PPC_X13, PPC_X1, PPC_FP8, PPC_BP8, PPC_ZERO8, 
  };

  // G8RC_NOX0 Bit set.
  static uint8_t G8RC_NOX0Bits[] = {
    0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0xff, 0x7f, 
  };

  // G8RC_and_G8RC_NOX0 Register Class...
  static MCPhysReg G8RC_and_G8RC_NOX0[] = {
    PPC_X2, PPC_X3, PPC_X4, PPC_X5, PPC_X6, PPC_X7, PPC_X8, PPC_X9, PPC_X10, PPC_X11, PPC_X12, PPC_X30, PPC_X29, PPC_X28, PPC_X27, PPC_X26, PPC_X25, PPC_X24, PPC_X23, PPC_X22, PPC_X21, PPC_X20, PPC_X19, PPC_X18, PPC_X17, PPC_X16, PPC_X15, PPC_X14, PPC_X31, PPC_X13, PPC_X1, PPC_FP8, PPC_BP8, 
  };

  // G8RC_and_G8RC_NOX0 Bit set.
  static uint8_t G8RC_and_G8RC_NOX0Bits[] = {
    0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0xff, 0x3f, 
  };

  // F8RC Register Class...
  static MCPhysReg F8RC[] = {
    PPC_F0, PPC_F1, PPC_F2, PPC_F3, PPC_F4, PPC_F5, PPC_F6, PPC_F7, PPC_F8, PPC_F9, PPC_F10, PPC_F11, PPC_F12, PPC_F13, PPC_F31, PPC_F30, PPC_F29, PPC_F28, PPC_F27, PPC_F26, PPC_F25, PPC_F24, PPC_F23, PPC_F22, PPC_F21, PPC_F20, PPC_F19, PPC_F18, PPC_F17, PPC_F16, PPC_F15, PPC_F14, 
  };

  // F8RC Bit set.
  static uint8_t F8RCBits[] = {
    0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // VFRC Register Class...
  static MCPhysReg VFRC[] = {
    PPC_VF2, PPC_VF3, PPC_VF4, PPC_VF5, PPC_VF0, PPC_VF1, PPC_VF6, PPC_VF7, PPC_VF8, PPC_VF9, PPC_VF10, PPC_VF11, PPC_VF12, PPC_VF13, PPC_VF14, PPC_VF15, PPC_VF16, PPC_VF17, PPC_VF18, PPC_VF19, PPC_VF31, PPC_VF30, PPC_VF29, PPC_VF28, PPC_VF27, PPC_VF26, PPC_VF25, PPC_VF24, PPC_VF23, PPC_VF22, PPC_VF21, PPC_VF20, 
  };

  // VFRC Bit set.
  static uint8_t VFRCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f, 
  };

  // CTRRC8 Register Class...
  static MCPhysReg CTRRC8[] = {
    PPC_CTR8, 
  };

  // CTRRC8 Bit set.
  static uint8_t CTRRC8Bits[] = {
    0x00, 0x00, 0x08, 
  };

  // VSRC Register Class...
  static MCPhysReg VSRC[] = {
    PPC_VSL0, PPC_VSL1, PPC_VSL2, PPC_VSL3, PPC_VSL4, PPC_VSL5, PPC_VSL6, PPC_VSL7, PPC_VSL8, PPC_VSL9, PPC_VSL10, PPC_VSL11, PPC_VSL12, PPC_VSL13, PPC_VSL31, PPC_VSL30, PPC_VSL29, PPC_VSL28, PPC_VSL27, PPC_VSL26, PPC_VSL25, PPC_VSL24, PPC_VSL23, PPC_VSL22, PPC_VSL21, PPC_VSL20, PPC_VSL19, PPC_VSL18, PPC_VSL17, PPC_VSL16, PPC_VSL15, PPC_VSL14, PPC_VSH2, PPC_VSH3, PPC_VSH4, PPC_VSH5, PPC_VSH0, PPC_VSH1, PPC_VSH6, PPC_VSH7, PPC_VSH8, PPC_VSH9, PPC_VSH10, PPC_VSH11, PPC_VSH12, PPC_VSH13, PPC_VSH14, PPC_VSH15, PPC_VSH16, PPC_VSH17, PPC_VSH18, PPC_VSH19, PPC_VSH31, PPC_VSH30, PPC_VSH29, PPC_VSH28, PPC_VSH27, PPC_VSH26, PPC_VSH25, PPC_VSH24, PPC_VSH23, PPC_VSH22, PPC_VSH21, PPC_VSH20, 
  };

  // VSRC Bit set.
  static uint8_t VSRCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f, 
  };

  // VRRC Register Class...
  static MCPhysReg VRRC[] = {
    PPC_V2, PPC_V3, PPC_V4, PPC_V5, PPC_V0, PPC_V1, PPC_V6, PPC_V7, PPC_V8, PPC_V9, PPC_V10, PPC_V11, PPC_V12, PPC_V13, PPC_V14, PPC_V15, PPC_V16, PPC_V17, PPC_V18, PPC_V19, PPC_V31, PPC_V30, PPC_V29, PPC_V28, PPC_V27, PPC_V26, PPC_V25, PPC_V24, PPC_V23, PPC_V22, PPC_V21, PPC_V20, 
  };

  // VRRC Bit set.
  static uint8_t VRRCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f, 
  };

  // VSHRC Register Class...
  static MCPhysReg VSHRC[] = {
    PPC_VSH2, PPC_VSH3, PPC_VSH4, PPC_VSH5, PPC_VSH0, PPC_VSH1, PPC_VSH6, PPC_VSH7, PPC_VSH8, PPC_VSH9, PPC_VSH10, PPC_VSH11, PPC_VSH12, PPC_VSH13, PPC_VSH14, PPC_VSH15, PPC_VSH16, PPC_VSH17, PPC_VSH18, PPC_VSH19, PPC_VSH31, PPC_VSH30, PPC_VSH29, PPC_VSH28, PPC_VSH27, PPC_VSH26, PPC_VSH25, PPC_VSH24, PPC_VSH23, PPC_VSH22, PPC_VSH21, PPC_VSH20, 
  };

  // VSHRC Bit set.
  static uint8_t VSHRCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f, 
  };

  // VSLRC Register Class...
  static MCPhysReg VSLRC[] = {
    PPC_VSL0, PPC_VSL1, PPC_VSL2, PPC_VSL3, PPC_VSL4, PPC_VSL5, PPC_VSL6, PPC_VSL7, PPC_VSL8, PPC_VSL9, PPC_VSL10, PPC_VSL11, PPC_VSL12, PPC_VSL13, PPC_VSL31, PPC_VSL30, PPC_VSL29, PPC_VSL28, PPC_VSL27, PPC_VSL26, PPC_VSL25, PPC_VSL24, PPC_VSL23, PPC_VSL22, PPC_VSL21, PPC_VSL20, PPC_VSL19, PPC_VSL18, PPC_VSL17, PPC_VSL16, PPC_VSL15, PPC_VSL14, 
  };

  // VSLRC Bit set.
  static uint8_t VSLRCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f, 
  };

static MCRegisterClass PPCMCRegisterClasses[] = {
  { "GPRC", GPRC, GPRCBits, 34, sizeof(GPRCBits), PPC_GPRCRegClassID, 4, 4, 1, 1 },
  { "GPRC_NOR0", GPRC_NOR0, GPRC_NOR0Bits, 34, sizeof(GPRC_NOR0Bits), PPC_GPRC_NOR0RegClassID, 4, 4, 1, 1 },
  { "GPRC_and_GPRC_NOR0", GPRC_and_GPRC_NOR0, GPRC_and_GPRC_NOR0Bits, 33, sizeof(GPRC_and_GPRC_NOR0Bits), PPC_GPRC_and_GPRC_NOR0RegClassID, 4, 4, 1, 1 },
  { "CRBITRC", CRBITRC, CRBITRCBits, 32, sizeof(CRBITRCBits), PPC_CRBITRCRegClassID, 4, 4, 1, 1 },
  { "F4RC", F4RC, F4RCBits, 32, sizeof(F4RCBits), PPC_F4RCRegClassID, 4, 4, 1, 1 },
  { "CRRC", CRRC, CRRCBits, 8, sizeof(CRRCBits), PPC_CRRCRegClassID, 4, 4, 1, 1 },
  { "CARRYRC", CARRYRC, CARRYRCBits, 1, sizeof(CARRYRCBits), PPC_CARRYRCRegClassID, 4, 4, -1, 1 },
  { "CCRC", CCRC, CCRCBits, 1, sizeof(CCRCBits), PPC_CCRCRegClassID, 4, 4, 1, 0 },
  { "CTRRC", CTRRC, CTRRCBits, 1, sizeof(CTRRCBits), PPC_CTRRCRegClassID, 4, 4, 1, 0 },
  { "VRSAVERC", VRSAVERC, VRSAVERCBits, 1, sizeof(VRSAVERCBits), PPC_VRSAVERCRegClassID, 4, 4, 1, 1 },
  { "VSFRC", VSFRC, VSFRCBits, 64, sizeof(VSFRCBits), PPC_VSFRCRegClassID, 8, 8, 1, 1 },
  { "G8RC", G8RC, G8RCBits, 34, sizeof(G8RCBits), PPC_G8RCRegClassID, 8, 8, 1, 1 },
  { "G8RC_NOX0", G8RC_NOX0, G8RC_NOX0Bits, 34, sizeof(G8RC_NOX0Bits), PPC_G8RC_NOX0RegClassID, 8, 8, 1, 1 },
  { "G8RC_and_G8RC_NOX0", G8RC_and_G8RC_NOX0, G8RC_and_G8RC_NOX0Bits, 33, sizeof(G8RC_and_G8RC_NOX0Bits), PPC_G8RC_and_G8RC_NOX0RegClassID, 8, 8, 1, 1 },
  { "F8RC", F8RC, F8RCBits, 32, sizeof(F8RCBits), PPC_F8RCRegClassID, 8, 8, 1, 1 },
  { "VFRC", VFRC, VFRCBits, 32, sizeof(VFRCBits), PPC_VFRCRegClassID, 8, 8, 1, 1 },
  { "CTRRC8", CTRRC8, CTRRC8Bits, 1, sizeof(CTRRC8Bits), PPC_CTRRC8RegClassID, 8, 8, 1, 0 },
  { "VSRC", VSRC, VSRCBits, 64, sizeof(VSRCBits), PPC_VSRCRegClassID, 16, 16, 1, 1 },
  { "VRRC", VRRC, VRRCBits, 32, sizeof(VRRCBits), PPC_VRRCRegClassID, 16, 16, 1, 1 },
  { "VSHRC", VSHRC, VSHRCBits, 32, sizeof(VSHRCBits), PPC_VSHRCRegClassID, 16, 16, 1, 1 },
  { "VSLRC", VSLRC, VSLRCBits, 32, sizeof(VSLRCBits), PPC_VSLRCRegClassID, 16, 16, 1, 1 },
};

#endif // GET_REGINFO_MC_DESC

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
  PPC_NoRegister,
  PPC_BP = 1,
  PPC_CARRY = 2,
  PPC_CTR = 3,
  PPC_FP = 4,
  PPC_LR = 5,
  PPC_RM = 6,
  PPC_VRSAVE = 7,
  PPC_ZERO = 8,
  PPC_BP8 = 9,
  PPC_CR0 = 10,
  PPC_CR1 = 11,
  PPC_CR2 = 12,
  PPC_CR3 = 13,
  PPC_CR4 = 14,
  PPC_CR5 = 15,
  PPC_CR6 = 16,
  PPC_CR7 = 17,
  PPC_CTR8 = 18,
  PPC_F0 = 19,
  PPC_F1 = 20,
  PPC_F2 = 21,
  PPC_F3 = 22,
  PPC_F4 = 23,
  PPC_F5 = 24,
  PPC_F6 = 25,
  PPC_F7 = 26,
  PPC_F8 = 27,
  PPC_F9 = 28,
  PPC_F10 = 29,
  PPC_F11 = 30,
  PPC_F12 = 31,
  PPC_F13 = 32,
  PPC_F14 = 33,
  PPC_F15 = 34,
  PPC_F16 = 35,
  PPC_F17 = 36,
  PPC_F18 = 37,
  PPC_F19 = 38,
  PPC_F20 = 39,
  PPC_F21 = 40,
  PPC_F22 = 41,
  PPC_F23 = 42,
  PPC_F24 = 43,
  PPC_F25 = 44,
  PPC_F26 = 45,
  PPC_F27 = 46,
  PPC_F28 = 47,
  PPC_F29 = 48,
  PPC_F30 = 49,
  PPC_F31 = 50,
  PPC_FP8 = 51,
  PPC_LR8 = 52,
  PPC_R0 = 53,
  PPC_R1 = 54,
  PPC_R2 = 55,
  PPC_R3 = 56,
  PPC_R4 = 57,
  PPC_R5 = 58,
  PPC_R6 = 59,
  PPC_R7 = 60,
  PPC_R8 = 61,
  PPC_R9 = 62,
  PPC_R10 = 63,
  PPC_R11 = 64,
  PPC_R12 = 65,
  PPC_R13 = 66,
  PPC_R14 = 67,
  PPC_R15 = 68,
  PPC_R16 = 69,
  PPC_R17 = 70,
  PPC_R18 = 71,
  PPC_R19 = 72,
  PPC_R20 = 73,
  PPC_R21 = 74,
  PPC_R22 = 75,
  PPC_R23 = 76,
  PPC_R24 = 77,
  PPC_R25 = 78,
  PPC_R26 = 79,
  PPC_R27 = 80,
  PPC_R28 = 81,
  PPC_R29 = 82,
  PPC_R30 = 83,
  PPC_R31 = 84,
  PPC_V0 = 85,
  PPC_V1 = 86,
  PPC_V2 = 87,
  PPC_V3 = 88,
  PPC_V4 = 89,
  PPC_V5 = 90,
  PPC_V6 = 91,
  PPC_V7 = 92,
  PPC_V8 = 93,
  PPC_V9 = 94,
  PPC_V10 = 95,
  PPC_V11 = 96,
  PPC_V12 = 97,
  PPC_V13 = 98,
  PPC_V14 = 99,
  PPC_V15 = 100,
  PPC_V16 = 101,
  PPC_V17 = 102,
  PPC_V18 = 103,
  PPC_V19 = 104,
  PPC_V20 = 105,
  PPC_V21 = 106,
  PPC_V22 = 107,
  PPC_V23 = 108,
  PPC_V24 = 109,
  PPC_V25 = 110,
  PPC_V26 = 111,
  PPC_V27 = 112,
  PPC_V28 = 113,
  PPC_V29 = 114,
  PPC_V30 = 115,
  PPC_V31 = 116,
  PPC_X0 = 117,
  PPC_X1 = 118,
  PPC_X2 = 119,
  PPC_X3 = 120,
  PPC_X4 = 121,
  PPC_X5 = 122,
  PPC_X6 = 123,
  PPC_X7 = 124,
  PPC_X8 = 125,
  PPC_X9 = 126,
  PPC_X10 = 127,
  PPC_X11 = 128,
  PPC_X12 = 129,
  PPC_X13 = 130,
  PPC_X14 = 131,
  PPC_X15 = 132,
  PPC_X16 = 133,
  PPC_X17 = 134,
  PPC_X18 = 135,
  PPC_X19 = 136,
  PPC_X20 = 137,
  PPC_X21 = 138,
  PPC_X22 = 139,
  PPC_X23 = 140,
  PPC_X24 = 141,
  PPC_X25 = 142,
  PPC_X26 = 143,
  PPC_X27 = 144,
  PPC_X28 = 145,
  PPC_X29 = 146,
  PPC_X30 = 147,
  PPC_X31 = 148,
  PPC_ZERO8 = 149,
  PPC_CR0EQ = 150,
  PPC_CR1EQ = 151,
  PPC_CR2EQ = 152,
  PPC_CR3EQ = 153,
  PPC_CR4EQ = 154,
  PPC_CR5EQ = 155,
  PPC_CR6EQ = 156,
  PPC_CR7EQ = 157,
  PPC_CR0GT = 158,
  PPC_CR1GT = 159,
  PPC_CR2GT = 160,
  PPC_CR3GT = 161,
  PPC_CR4GT = 162,
  PPC_CR5GT = 163,
  PPC_CR6GT = 164,
  PPC_CR7GT = 165,
  PPC_CR0LT = 166,
  PPC_CR1LT = 167,
  PPC_CR2LT = 168,
  PPC_CR3LT = 169,
  PPC_CR4LT = 170,
  PPC_CR5LT = 171,
  PPC_CR6LT = 172,
  PPC_CR7LT = 173,
  PPC_CR0UN = 174,
  PPC_CR1UN = 175,
  PPC_CR2UN = 176,
  PPC_CR3UN = 177,
  PPC_CR4UN = 178,
  PPC_CR5UN = 179,
  PPC_CR6UN = 180,
  PPC_CR7UN = 181,
  PPC_NUM_TARGET_REGS 	// 182
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
  PPC_CTRRCRegClassID = 7,
  PPC_VRSAVERCRegClassID = 8,
  PPC_G8RCRegClassID = 9,
  PPC_G8RC_NOX0RegClassID = 10,
  PPC_G8RC_and_G8RC_NOX0RegClassID = 11,
  PPC_F8RCRegClassID = 12,
  PPC_CTRRC8RegClassID = 13,
  PPC_VRRCRegClassID = 14
};

// Subregister indices
enum {
  PPC_NoSubRegister,
  PPC_sub_32,	// 1
  PPC_sub_eq,	// 2
  PPC_sub_gt,	// 3
  PPC_sub_lt,	// 4
  PPC_sub_un,	// 5
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
  /* 2 */ 65504, 1, 1, 1, 0,
  /* 7 */ 3, 0,
  /* 9 */ 8, 0,
  /* 11 */ 21, 0,
  /* 13 */ 22, 0,
  /* 15 */ 156, 65528, 65528, 24, 0,
  /* 20 */ 47, 0,
  /* 22 */ 64, 0,
  /* 24 */ 141, 0,
  /* 26 */ 64851, 0,
  /* 28 */ 64880, 0,
  /* 30 */ 64913, 0,
  /* 32 */ 64946, 0,
  /* 34 */ 65096, 0,
  /* 36 */ 65372, 0,
  /* 38 */ 65380, 0,
  /* 40 */ 65388, 0,
  /* 42 */ 65395, 0,
  /* 44 */ 65396, 0,
  /* 46 */ 65472, 0,
  /* 48 */ 65489, 0,
  /* 50 */ 65493, 0,
  /* 52 */ 65528, 0,
  /* 54 */ 65535, 0,
};

static uint16_t PPCSubRegIdxLists[] = {
  /* 0 */ 1, 0,
  /* 2 */ 4, 3, 2, 5, 0,
};

static MCRegisterDesc PPCRegDesc[] = { // Descriptors
  { 3, 0, 0, 0, 0 },
  { 563, 1, 9, 1, 865 },
  { 720, 1, 1, 1, 865 },
  { 620, 1, 1, 1, 865 },
  { 566, 1, 20, 1, 865 },
  { 617, 1, 1, 1, 865 },
  { 507, 1, 1, 1, 865 },
  { 500, 1, 1, 1, 865 },
  { 558, 1, 24, 1, 865 },
  { 433, 52, 1, 0, 0 },
  { 51, 15, 1, 2, 36 },
  { 112, 15, 1, 2, 36 },
  { 157, 15, 1, 2, 36 },
  { 202, 15, 1, 2, 36 },
  { 247, 15, 1, 2, 36 },
  { 292, 15, 1, 2, 36 },
  { 337, 15, 1, 2, 36 },
  { 382, 15, 1, 2, 36 },
  { 445, 1, 1, 1, 209 },
  { 48, 1, 1, 1, 209 },
  { 109, 1, 1, 1, 209 },
  { 154, 1, 1, 1, 209 },
  { 199, 1, 1, 1, 209 },
  { 244, 1, 1, 1, 209 },
  { 289, 1, 1, 1, 209 },
  { 334, 1, 1, 1, 209 },
  { 379, 1, 1, 1, 209 },
  { 424, 1, 1, 1, 209 },
  { 488, 1, 1, 1, 209 },
  { 0, 1, 1, 1, 209 },
  { 61, 1, 1, 1, 209 },
  { 122, 1, 1, 1, 209 },
  { 167, 1, 1, 1, 209 },
  { 212, 1, 1, 1, 209 },
  { 257, 1, 1, 1, 209 },
  { 302, 1, 1, 1, 209 },
  { 347, 1, 1, 1, 209 },
  { 392, 1, 1, 1, 209 },
  { 456, 1, 1, 1, 209 },
  { 16, 1, 1, 1, 209 },
  { 77, 1, 1, 1, 209 },
  { 138, 1, 1, 1, 209 },
  { 183, 1, 1, 1, 209 },
  { 228, 1, 1, 1, 209 },
  { 273, 1, 1, 1, 209 },
  { 318, 1, 1, 1, 209 },
  { 363, 1, 1, 1, 209 },
  { 408, 1, 1, 1, 209 },
  { 472, 1, 1, 1, 209 },
  { 32, 1, 1, 1, 209 },
  { 93, 1, 1, 1, 209 },
  { 437, 48, 1, 0, 112 },
  { 441, 1, 1, 1, 177 },
  { 52, 1, 22, 1, 177 },
  { 113, 1, 22, 1, 177 },
  { 158, 1, 22, 1, 177 },
  { 203, 1, 22, 1, 177 },
  { 248, 1, 22, 1, 177 },
  { 293, 1, 22, 1, 177 },
  { 338, 1, 22, 1, 177 },
  { 383, 1, 22, 1, 177 },
  { 442, 1, 22, 1, 177 },
  { 491, 1, 22, 1, 177 },
  { 4, 1, 22, 1, 177 },
  { 65, 1, 22, 1, 177 },
  { 126, 1, 22, 1, 177 },
  { 171, 1, 22, 1, 177 },
  { 216, 1, 22, 1, 177 },
  { 261, 1, 22, 1, 177 },
  { 306, 1, 22, 1, 177 },
  { 351, 1, 22, 1, 177 },
  { 396, 1, 22, 1, 177 },
  { 460, 1, 22, 1, 177 },
  { 20, 1, 22, 1, 177 },
  { 81, 1, 22, 1, 177 },
  { 142, 1, 22, 1, 177 },
  { 187, 1, 22, 1, 177 },
  { 232, 1, 22, 1, 177 },
  { 277, 1, 22, 1, 177 },
  { 322, 1, 22, 1, 177 },
  { 367, 1, 22, 1, 177 },
  { 412, 1, 22, 1, 177 },
  { 476, 1, 22, 1, 177 },
  { 36, 1, 22, 1, 177 },
  { 97, 1, 22, 1, 177 },
  { 55, 1, 1, 1, 177 },
  { 116, 1, 1, 1, 177 },
  { 161, 1, 1, 1, 177 },
  { 206, 1, 1, 1, 177 },
  { 251, 1, 1, 1, 177 },
  { 296, 1, 1, 1, 177 },
  { 341, 1, 1, 1, 177 },
  { 386, 1, 1, 1, 177 },
  { 450, 1, 1, 1, 177 },
  { 494, 1, 1, 1, 177 },
  { 8, 1, 1, 1, 177 },
  { 69, 1, 1, 1, 177 },
  { 130, 1, 1, 1, 177 },
  { 175, 1, 1, 1, 177 },
  { 220, 1, 1, 1, 177 },
  { 265, 1, 1, 1, 177 },
  { 310, 1, 1, 1, 177 },
  { 355, 1, 1, 1, 177 },
  { 400, 1, 1, 1, 177 },
  { 464, 1, 1, 1, 177 },
  { 24, 1, 1, 1, 177 },
  { 85, 1, 1, 1, 177 },
  { 146, 1, 1, 1, 177 },
  { 191, 1, 1, 1, 177 },
  { 236, 1, 1, 1, 177 },
  { 281, 1, 1, 1, 177 },
  { 326, 1, 1, 1, 177 },
  { 371, 1, 1, 1, 177 },
  { 416, 1, 1, 1, 177 },
  { 480, 1, 1, 1, 177 },
  { 40, 1, 1, 1, 177 },
  { 101, 1, 1, 1, 177 },
  { 58, 46, 1, 0, 801 },
  { 119, 46, 1, 0, 801 },
  { 164, 46, 1, 0, 801 },
  { 209, 46, 1, 0, 801 },
  { 254, 46, 1, 0, 801 },
  { 299, 46, 1, 0, 801 },
  { 344, 46, 1, 0, 801 },
  { 389, 46, 1, 0, 801 },
  { 453, 46, 1, 0, 801 },
  { 497, 46, 1, 0, 801 },
  { 12, 46, 1, 0, 801 },
  { 73, 46, 1, 0, 801 },
  { 134, 46, 1, 0, 801 },
  { 179, 46, 1, 0, 801 },
  { 224, 46, 1, 0, 801 },
  { 269, 46, 1, 0, 801 },
  { 314, 46, 1, 0, 801 },
  { 359, 46, 1, 0, 801 },
  { 404, 46, 1, 0, 801 },
  { 468, 46, 1, 0, 801 },
  { 28, 46, 1, 0, 801 },
  { 89, 46, 1, 0, 801 },
  { 150, 46, 1, 0, 801 },
  { 195, 46, 1, 0, 801 },
  { 240, 46, 1, 0, 801 },
  { 285, 46, 1, 0, 801 },
  { 330, 46, 1, 0, 801 },
  { 375, 46, 1, 0, 801 },
  { 420, 46, 1, 0, 801 },
  { 484, 46, 1, 0, 801 },
  { 44, 46, 1, 0, 801 },
  { 105, 46, 1, 0, 801 },
  { 427, 42, 1, 0, 547 },
  { 569, 1, 44, 1, 547 },
  { 575, 1, 44, 1, 516 },
  { 581, 1, 44, 1, 516 },
  { 587, 1, 44, 1, 516 },
  { 593, 1, 44, 1, 516 },
  { 599, 1, 44, 1, 516 },
  { 605, 1, 44, 1, 516 },
  { 611, 1, 44, 1, 516 },
  { 624, 1, 40, 1, 484 },
  { 630, 1, 40, 1, 484 },
  { 636, 1, 40, 1, 484 },
  { 642, 1, 40, 1, 484 },
  { 648, 1, 40, 1, 484 },
  { 654, 1, 40, 1, 484 },
  { 660, 1, 40, 1, 484 },
  { 666, 1, 40, 1, 484 },
  { 672, 1, 38, 1, 452 },
  { 678, 1, 38, 1, 452 },
  { 684, 1, 38, 1, 452 },
  { 690, 1, 38, 1, 452 },
  { 696, 1, 38, 1, 452 },
  { 702, 1, 38, 1, 452 },
  { 708, 1, 38, 1, 452 },
  { 714, 1, 38, 1, 452 },
  { 510, 1, 36, 1, 420 },
  { 516, 1, 36, 1, 420 },
  { 522, 1, 36, 1, 420 },
  { 528, 1, 36, 1, 420 },
  { 534, 1, 36, 1, 420 },
  { 540, 1, 36, 1, 420 },
  { 546, 1, 36, 1, 420 },
  { 552, 1, 36, 1, 420 },
};


  // GPRC Register Class...
  static uint16_t GPRC[] = {
    PPC_R2, PPC_R3, PPC_R4, PPC_R5, PPC_R6, PPC_R7, PPC_R8, PPC_R9, PPC_R10, PPC_R11, PPC_R12, PPC_R30, PPC_R29, PPC_R28, PPC_R27, PPC_R26, PPC_R25, PPC_R24, PPC_R23, PPC_R22, PPC_R21, PPC_R20, PPC_R19, PPC_R18, PPC_R17, PPC_R16, PPC_R15, PPC_R14, PPC_R13, PPC_R31, PPC_R0, PPC_R1, PPC_FP, PPC_BP, 
  };

  // GPRC Bit set.
  static uint8_t GPRCBits[] = {
    0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0xff, 0xff, 0x1f, 
  };

  // GPRC_NOR0 Register Class...
  static uint16_t GPRC_NOR0[] = {
    PPC_R2, PPC_R3, PPC_R4, PPC_R5, PPC_R6, PPC_R7, PPC_R8, PPC_R9, PPC_R10, PPC_R11, PPC_R12, PPC_R30, PPC_R29, PPC_R28, PPC_R27, PPC_R26, PPC_R25, PPC_R24, PPC_R23, PPC_R22, PPC_R21, PPC_R20, PPC_R19, PPC_R18, PPC_R17, PPC_R16, PPC_R15, PPC_R14, PPC_R13, PPC_R31, PPC_R1, PPC_FP, PPC_BP, PPC_ZERO, 
  };

  // GPRC_NOR0 Bit set.
  static uint8_t GPRC_NOR0Bits[] = {
    0x12, 0x01, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x1f, 
  };

  // GPRC_and_GPRC_NOR0 Register Class...
  static uint16_t GPRC_and_GPRC_NOR0[] = {
    PPC_R2, PPC_R3, PPC_R4, PPC_R5, PPC_R6, PPC_R7, PPC_R8, PPC_R9, PPC_R10, PPC_R11, PPC_R12, PPC_R30, PPC_R29, PPC_R28, PPC_R27, PPC_R26, PPC_R25, PPC_R24, PPC_R23, PPC_R22, PPC_R21, PPC_R20, PPC_R19, PPC_R18, PPC_R17, PPC_R16, PPC_R15, PPC_R14, PPC_R13, PPC_R31, PPC_R1, PPC_FP, PPC_BP, 
  };

  // GPRC_and_GPRC_NOR0 Bit set.
  static uint8_t GPRC_and_GPRC_NOR0Bits[] = {
    0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x1f, 
  };

  // CRBITRC Register Class...
  static uint16_t CRBITRC[] = {
    PPC_CR0LT, PPC_CR0GT, PPC_CR0EQ, PPC_CR0UN, PPC_CR1LT, PPC_CR1GT, PPC_CR1EQ, PPC_CR1UN, PPC_CR2LT, PPC_CR2GT, PPC_CR2EQ, PPC_CR2UN, PPC_CR3LT, PPC_CR3GT, PPC_CR3EQ, PPC_CR3UN, PPC_CR4LT, PPC_CR4GT, PPC_CR4EQ, PPC_CR4UN, PPC_CR5LT, PPC_CR5GT, PPC_CR5EQ, PPC_CR5UN, PPC_CR6LT, PPC_CR6GT, PPC_CR6EQ, PPC_CR6UN, PPC_CR7LT, PPC_CR7GT, PPC_CR7EQ, PPC_CR7UN, 
  };

  // CRBITRC Bit set.
  static uint8_t CRBITRCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f, 
  };

  // F4RC Register Class...
  static uint16_t F4RC[] = {
    PPC_F0, PPC_F1, PPC_F2, PPC_F3, PPC_F4, PPC_F5, PPC_F6, PPC_F7, PPC_F8, PPC_F9, PPC_F10, PPC_F11, PPC_F12, PPC_F13, PPC_F31, PPC_F30, PPC_F29, PPC_F28, PPC_F27, PPC_F26, PPC_F25, PPC_F24, PPC_F23, PPC_F22, PPC_F21, PPC_F20, PPC_F19, PPC_F18, PPC_F17, PPC_F16, PPC_F15, PPC_F14, 
  };

  // F4RC Bit set.
  static uint8_t F4RCBits[] = {
    0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // CRRC Register Class...
  static uint16_t CRRC[] = {
    PPC_CR0, PPC_CR1, PPC_CR5, PPC_CR6, PPC_CR7, PPC_CR2, PPC_CR3, PPC_CR4, 
  };

  // CRRC Bit set.
  static uint8_t CRRCBits[] = {
    0x00, 0xfc, 0x03, 
  };

  // CARRYRC Register Class...
  static uint16_t CARRYRC[] = {
    PPC_CARRY, 
  };

  // CARRYRC Bit set.
  static uint8_t CARRYRCBits[] = {
    0x04, 
  };

  // CTRRC Register Class...
  static uint16_t CTRRC[] = {
    PPC_CTR, 
  };

  // CTRRC Bit set.
  static uint8_t CTRRCBits[] = {
    0x08, 
  };

  // VRSAVERC Register Class...
  static uint16_t VRSAVERC[] = {
    PPC_VRSAVE, 
  };

  // VRSAVERC Bit set.
  static uint8_t VRSAVERCBits[] = {
    0x80, 
  };

  // G8RC Register Class...
  static uint16_t G8RC[] = {
    PPC_X2, PPC_X3, PPC_X4, PPC_X5, PPC_X6, PPC_X7, PPC_X8, PPC_X9, PPC_X10, PPC_X11, PPC_X12, PPC_X30, PPC_X29, PPC_X28, PPC_X27, PPC_X26, PPC_X25, PPC_X24, PPC_X23, PPC_X22, PPC_X21, PPC_X20, PPC_X19, PPC_X18, PPC_X17, PPC_X16, PPC_X15, PPC_X14, PPC_X31, PPC_X13, PPC_X0, PPC_X1, PPC_FP8, PPC_BP8, 
  };

  // G8RC Bit set.
  static uint8_t G8RCBits[] = {
    0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0xff, 0xff, 0x1f, 
  };

  // G8RC_NOX0 Register Class...
  static uint16_t G8RC_NOX0[] = {
    PPC_X2, PPC_X3, PPC_X4, PPC_X5, PPC_X6, PPC_X7, PPC_X8, PPC_X9, PPC_X10, PPC_X11, PPC_X12, PPC_X30, PPC_X29, PPC_X28, PPC_X27, PPC_X26, PPC_X25, PPC_X24, PPC_X23, PPC_X22, PPC_X21, PPC_X20, PPC_X19, PPC_X18, PPC_X17, PPC_X16, PPC_X15, PPC_X14, PPC_X31, PPC_X13, PPC_X1, PPC_FP8, PPC_BP8, PPC_ZERO8, 
  };

  // G8RC_NOX0 Bit set.
  static uint8_t G8RC_NOX0Bits[] = {
    0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f, 
  };

  // G8RC_and_G8RC_NOX0 Register Class...
  static uint16_t G8RC_and_G8RC_NOX0[] = {
    PPC_X2, PPC_X3, PPC_X4, PPC_X5, PPC_X6, PPC_X7, PPC_X8, PPC_X9, PPC_X10, PPC_X11, PPC_X12, PPC_X30, PPC_X29, PPC_X28, PPC_X27, PPC_X26, PPC_X25, PPC_X24, PPC_X23, PPC_X22, PPC_X21, PPC_X20, PPC_X19, PPC_X18, PPC_X17, PPC_X16, PPC_X15, PPC_X14, PPC_X31, PPC_X13, PPC_X1, PPC_FP8, PPC_BP8, 
  };

  // G8RC_and_G8RC_NOX0 Bit set.
  static uint8_t G8RC_and_G8RC_NOX0Bits[] = {
    0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x1f, 
  };

  // F8RC Register Class...
  static uint16_t F8RC[] = {
    PPC_F0, PPC_F1, PPC_F2, PPC_F3, PPC_F4, PPC_F5, PPC_F6, PPC_F7, PPC_F8, PPC_F9, PPC_F10, PPC_F11, PPC_F12, PPC_F13, PPC_F31, PPC_F30, PPC_F29, PPC_F28, PPC_F27, PPC_F26, PPC_F25, PPC_F24, PPC_F23, PPC_F22, PPC_F21, PPC_F20, PPC_F19, PPC_F18, PPC_F17, PPC_F16, PPC_F15, PPC_F14, 
  };

  // F8RC Bit set.
  static uint8_t F8RCBits[] = {
    0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // CTRRC8 Register Class...
  static uint16_t CTRRC8[] = {
    PPC_CTR8, 
  };

  // CTRRC8 Bit set.
  static uint8_t CTRRC8Bits[] = {
    0x00, 0x00, 0x04, 
  };

  // VRRC Register Class...
  static uint16_t VRRC[] = {
    PPC_V2, PPC_V3, PPC_V4, PPC_V5, PPC_V0, PPC_V1, PPC_V6, PPC_V7, PPC_V8, PPC_V9, PPC_V10, PPC_V11, PPC_V12, PPC_V13, PPC_V14, PPC_V15, PPC_V16, PPC_V17, PPC_V18, PPC_V19, PPC_V31, PPC_V30, PPC_V29, PPC_V28, PPC_V27, PPC_V26, PPC_V25, PPC_V24, PPC_V23, PPC_V22, PPC_V21, PPC_V20, 
  };

  // VRRC Bit set.
  static uint8_t VRRCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0xff, 0xff, 0xff, 0x1f, 
  };


static MCRegisterClass PPCMCRegisterClasses[] = {
  { "GPRC", GPRC, GPRCBits, 34, sizeof(GPRCBits), PPC_GPRCRegClassID, 4, 4, 1, 1 },
  { "GPRC_NOR0", GPRC_NOR0, GPRC_NOR0Bits, 34, sizeof(GPRC_NOR0Bits), PPC_GPRC_NOR0RegClassID, 4, 4, 1, 1 },
  { "GPRC_and_GPRC_NOR0", GPRC_and_GPRC_NOR0, GPRC_and_GPRC_NOR0Bits, 33, sizeof(GPRC_and_GPRC_NOR0Bits), PPC_GPRC_and_GPRC_NOR0RegClassID, 4, 4, 1, 1 },
  { "CRBITRC", CRBITRC, CRBITRCBits, 32, sizeof(CRBITRCBits), PPC_CRBITRCRegClassID, 4, 4, -1, 1 },
  { "F4RC", F4RC, F4RCBits, 32, sizeof(F4RCBits), PPC_F4RCRegClassID, 4, 4, 1, 1 },
  { "CRRC", CRRC, CRRCBits, 8, sizeof(CRRCBits), PPC_CRRCRegClassID, 4, 4, 1, 1 },
  { "CARRYRC", CARRYRC, CARRYRCBits, 1, sizeof(CARRYRCBits), PPC_CARRYRCRegClassID, 4, 4, -1, 1 },
  { "CTRRC", CTRRC, CTRRCBits, 1, sizeof(CTRRCBits), PPC_CTRRCRegClassID, 4, 4, 1, 0 },
  { "VRSAVERC", VRSAVERC, VRSAVERCBits, 1, sizeof(VRSAVERCBits), PPC_VRSAVERCRegClassID, 4, 4, 1, 1 },
  { "G8RC", G8RC, G8RCBits, 34, sizeof(G8RCBits), PPC_G8RCRegClassID, 8, 8, 1, 1 },
  { "G8RC_NOX0", G8RC_NOX0, G8RC_NOX0Bits, 34, sizeof(G8RC_NOX0Bits), PPC_G8RC_NOX0RegClassID, 8, 8, 1, 1 },
  { "G8RC_and_G8RC_NOX0", G8RC_and_G8RC_NOX0, G8RC_and_G8RC_NOX0Bits, 33, sizeof(G8RC_and_G8RC_NOX0Bits), PPC_G8RC_and_G8RC_NOX0RegClassID, 8, 8, 1, 1 },
  { "F8RC", F8RC, F8RCBits, 32, sizeof(F8RCBits), PPC_F8RCRegClassID, 8, 8, 1, 1 },
  { "CTRRC8", CTRRC8, CTRRC8Bits, 1, sizeof(CTRRC8Bits), PPC_CTRRC8RegClassID, 8, 8, 1, 0 },
  { "VRRC", VRRC, VRRCBits, 32, sizeof(VRRCBits), PPC_VRRCRegClassID, 16, 16, 1, 1 },
};

#endif // GET_REGINFO_MC_DESC

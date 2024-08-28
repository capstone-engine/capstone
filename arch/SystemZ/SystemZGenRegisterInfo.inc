#ifdef GET_REGINFO_ENUM
#undef GET_REGINFO_ENUM

enum {
  SystemZ_NoRegister,
  SystemZ_CC = 1,
  SystemZ_FPC = 2,
  SystemZ_A0 = 3,
  SystemZ_A1 = 4,
  SystemZ_A2 = 5,
  SystemZ_A3 = 6,
  SystemZ_A4 = 7,
  SystemZ_A5 = 8,
  SystemZ_A6 = 9,
  SystemZ_A7 = 10,
  SystemZ_A8 = 11,
  SystemZ_A9 = 12,
  SystemZ_A10 = 13,
  SystemZ_A11 = 14,
  SystemZ_A12 = 15,
  SystemZ_A13 = 16,
  SystemZ_A14 = 17,
  SystemZ_A15 = 18,
  SystemZ_C0 = 19,
  SystemZ_C1 = 20,
  SystemZ_C2 = 21,
  SystemZ_C3 = 22,
  SystemZ_C4 = 23,
  SystemZ_C5 = 24,
  SystemZ_C6 = 25,
  SystemZ_C7 = 26,
  SystemZ_C8 = 27,
  SystemZ_C9 = 28,
  SystemZ_C10 = 29,
  SystemZ_C11 = 30,
  SystemZ_C12 = 31,
  SystemZ_C13 = 32,
  SystemZ_C14 = 33,
  SystemZ_C15 = 34,
  SystemZ_V0 = 35,
  SystemZ_V1 = 36,
  SystemZ_V2 = 37,
  SystemZ_V3 = 38,
  SystemZ_V4 = 39,
  SystemZ_V5 = 40,
  SystemZ_V6 = 41,
  SystemZ_V7 = 42,
  SystemZ_V8 = 43,
  SystemZ_V9 = 44,
  SystemZ_V10 = 45,
  SystemZ_V11 = 46,
  SystemZ_V12 = 47,
  SystemZ_V13 = 48,
  SystemZ_V14 = 49,
  SystemZ_V15 = 50,
  SystemZ_V16 = 51,
  SystemZ_V17 = 52,
  SystemZ_V18 = 53,
  SystemZ_V19 = 54,
  SystemZ_V20 = 55,
  SystemZ_V21 = 56,
  SystemZ_V22 = 57,
  SystemZ_V23 = 58,
  SystemZ_V24 = 59,
  SystemZ_V25 = 60,
  SystemZ_V26 = 61,
  SystemZ_V27 = 62,
  SystemZ_V28 = 63,
  SystemZ_V29 = 64,
  SystemZ_V30 = 65,
  SystemZ_V31 = 66,
  SystemZ_F0D = 67,
  SystemZ_F1D = 68,
  SystemZ_F2D = 69,
  SystemZ_F3D = 70,
  SystemZ_F4D = 71,
  SystemZ_F5D = 72,
  SystemZ_F6D = 73,
  SystemZ_F7D = 74,
  SystemZ_F8D = 75,
  SystemZ_F9D = 76,
  SystemZ_F10D = 77,
  SystemZ_F11D = 78,
  SystemZ_F12D = 79,
  SystemZ_F13D = 80,
  SystemZ_F14D = 81,
  SystemZ_F15D = 82,
  SystemZ_F16D = 83,
  SystemZ_F17D = 84,
  SystemZ_F18D = 85,
  SystemZ_F19D = 86,
  SystemZ_F20D = 87,
  SystemZ_F21D = 88,
  SystemZ_F22D = 89,
  SystemZ_F23D = 90,
  SystemZ_F24D = 91,
  SystemZ_F25D = 92,
  SystemZ_F26D = 93,
  SystemZ_F27D = 94,
  SystemZ_F28D = 95,
  SystemZ_F29D = 96,
  SystemZ_F30D = 97,
  SystemZ_F31D = 98,
  SystemZ_F0Q = 99,
  SystemZ_F1Q = 100,
  SystemZ_F4Q = 101,
  SystemZ_F5Q = 102,
  SystemZ_F8Q = 103,
  SystemZ_F9Q = 104,
  SystemZ_F12Q = 105,
  SystemZ_F13Q = 106,
  SystemZ_F0S = 107,
  SystemZ_F1S = 108,
  SystemZ_F2S = 109,
  SystemZ_F3S = 110,
  SystemZ_F4S = 111,
  SystemZ_F5S = 112,
  SystemZ_F6S = 113,
  SystemZ_F7S = 114,
  SystemZ_F8S = 115,
  SystemZ_F9S = 116,
  SystemZ_F10S = 117,
  SystemZ_F11S = 118,
  SystemZ_F12S = 119,
  SystemZ_F13S = 120,
  SystemZ_F14S = 121,
  SystemZ_F15S = 122,
  SystemZ_F16S = 123,
  SystemZ_F17S = 124,
  SystemZ_F18S = 125,
  SystemZ_F19S = 126,
  SystemZ_F20S = 127,
  SystemZ_F21S = 128,
  SystemZ_F22S = 129,
  SystemZ_F23S = 130,
  SystemZ_F24S = 131,
  SystemZ_F25S = 132,
  SystemZ_F26S = 133,
  SystemZ_F27S = 134,
  SystemZ_F28S = 135,
  SystemZ_F29S = 136,
  SystemZ_F30S = 137,
  SystemZ_F31S = 138,
  SystemZ_R0D = 139,
  SystemZ_R1D = 140,
  SystemZ_R2D = 141,
  SystemZ_R3D = 142,
  SystemZ_R4D = 143,
  SystemZ_R5D = 144,
  SystemZ_R6D = 145,
  SystemZ_R7D = 146,
  SystemZ_R8D = 147,
  SystemZ_R9D = 148,
  SystemZ_R10D = 149,
  SystemZ_R11D = 150,
  SystemZ_R12D = 151,
  SystemZ_R13D = 152,
  SystemZ_R14D = 153,
  SystemZ_R15D = 154,
  SystemZ_R0H = 155,
  SystemZ_R1H = 156,
  SystemZ_R2H = 157,
  SystemZ_R3H = 158,
  SystemZ_R4H = 159,
  SystemZ_R5H = 160,
  SystemZ_R6H = 161,
  SystemZ_R7H = 162,
  SystemZ_R8H = 163,
  SystemZ_R9H = 164,
  SystemZ_R10H = 165,
  SystemZ_R11H = 166,
  SystemZ_R12H = 167,
  SystemZ_R13H = 168,
  SystemZ_R14H = 169,
  SystemZ_R15H = 170,
  SystemZ_R0L = 171,
  SystemZ_R1L = 172,
  SystemZ_R2L = 173,
  SystemZ_R3L = 174,
  SystemZ_R4L = 175,
  SystemZ_R5L = 176,
  SystemZ_R6L = 177,
  SystemZ_R7L = 178,
  SystemZ_R8L = 179,
  SystemZ_R9L = 180,
  SystemZ_R10L = 181,
  SystemZ_R11L = 182,
  SystemZ_R12L = 183,
  SystemZ_R13L = 184,
  SystemZ_R14L = 185,
  SystemZ_R15L = 186,
  SystemZ_R0Q = 187,
  SystemZ_R2Q = 188,
  SystemZ_R4Q = 189,
  SystemZ_R6Q = 190,
  SystemZ_R8Q = 191,
  SystemZ_R10Q = 192,
  SystemZ_R12Q = 193,
  SystemZ_R14Q = 194,
  NUM_TARGET_REGS // 195
};

// Register classes

enum {
  SystemZ_GRX32BitRegClassID = 0,
  SystemZ_VR32BitRegClassID = 1,
  SystemZ_AR32BitRegClassID = 2,
  SystemZ_FP32BitRegClassID = 3,
  SystemZ_GR32BitRegClassID = 4,
  SystemZ_GRH32BitRegClassID = 5,
  SystemZ_ADDR32BitRegClassID = 6,
  SystemZ_CCRRegClassID = 7,
  SystemZ_FPCRegsRegClassID = 8,
  SystemZ_AnyRegBitRegClassID = 9,
  SystemZ_AnyRegBit_with_subreg_h32_in_FP32BitRegClassID = 10,
  SystemZ_VR64BitRegClassID = 11,
  SystemZ_AnyRegBit_with_subreg_h64RegClassID = 12,
  SystemZ_CR64BitRegClassID = 13,
  SystemZ_FP64BitRegClassID = 14,
  SystemZ_GR64BitRegClassID = 15,
  SystemZ_ADDR64BitRegClassID = 16,
  SystemZ_VR128BitRegClassID = 17,
  SystemZ_VF128BitRegClassID = 18,
  SystemZ_FP128BitRegClassID = 19,
  SystemZ_GR128BitRegClassID = 20,
  SystemZ_ADDR128BitRegClassID = 21,

};

// Subregister indices

enum {
  SystemZ_NoSubRegister,
  SystemZ_subreg_h32,	// 1
  SystemZ_subreg_h64,	// 2
  SystemZ_subreg_l32,	// 3
  SystemZ_subreg_l64,	// 4
  SystemZ_subreg_lh32,	// 5
  SystemZ_subreg_ll32,	// 6
  SystemZ_NUM_TARGET_SUBREGS
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

static const MCPhysReg SystemZRegDiffLists[] = {
  /* 0 */ -40, -32, 0,
  /* 3 */ -48, 32, -16, -15, 32, -16, 0,
  /* 10 */ -47, 32, -16, -15, 32, -16, 0,
  /* 17 */ -46, 32, -16, -15, 32, -16, 0,
  /* 24 */ -45, 32, -16, -15, 32, -16, 0,
  /* 31 */ -44, 32, -16, -15, 32, -16, 0,
  /* 38 */ -43, 32, -16, -15, 32, -16, 0,
  /* 45 */ -42, 32, -16, -15, 32, -16, 0,
  /* 52 */ -41, 32, -16, -15, 32, -16, 0,
  /* 59 */ 1, 1, 1, 0,
  /* 63 */ 2, 0,
  /* 65 */ -32, 40, -38, 40, 0,
  /* 70 */ -30, 40, -38, 40, 0,
  /* 75 */ -28, 40, -38, 40, 0,
  /* 80 */ -26, 40, -38, 40, 0,
  /* 85 */ -32, 40, 0,
  /* 88 */ -16, 40, 0,
  /* 91 */ 32, 40, 0,
  /* 94 */ -32, 41, 0,
  /* 97 */ -16, 41, 0,
  /* 100 */ -32, 42, 0,
  /* 103 */ -16, 42, 0,
  /* 106 */ -32, 43, 0,
  /* 109 */ -16, 43, 0,
  /* 112 */ -32, 44, 0,
  /* 115 */ -16, 44, 0,
  /* 118 */ -32, 45, 0,
  /* 121 */ -16, 45, 0,
  /* 124 */ -32, 46, 0,
  /* 127 */ -16, 46, 0,
  /* 130 */ -32, 47, 0,
  /* 133 */ -16, 47, 0,
  /* 136 */ -32, 48, 0,
  /* 139 */ -16, 48, 0,
  /* 142 */ -40, -32, 56, 0,
  /* 146 */ -40, -32, 58, 0,
  /* 150 */ -40, -32, 60, 0,
  /* 154 */ -40, -32, 62, 0,
  /* 158 */ -40, -32, 64, 0,
};

static const uint16_t SystemZSubRegIdxLists[] = {
  /* 0 */ 2, 1, 0,
  /* 3 */ 3, 1, 0,
  /* 6 */ 2, 1, 4, 5, 0,
  /* 11 */ 2, 3, 1, 4, 6, 5, 0,
};

static const MCRegisterDesc SystemZRegDesc[] = { // Descriptors
  { 3, 0, 0, 0, 0, 0 },
  { 226, 2, 2, 2, 8192, 11 },
  { 229, 2, 2, 2, 8193, 11 },
  { 20, 2, 2, 2, 8194, 11 },
  { 49, 2, 2, 2, 8195, 11 },
  { 74, 2, 2, 2, 8196, 11 },
  { 99, 2, 2, 2, 8197, 11 },
  { 124, 2, 2, 2, 8198, 11 },
  { 149, 2, 2, 2, 8199, 11 },
  { 166, 2, 2, 2, 8200, 11 },
  { 183, 2, 2, 2, 8201, 11 },
  { 200, 2, 2, 2, 8202, 11 },
  { 217, 2, 2, 2, 8203, 11 },
  { 0, 2, 2, 2, 8204, 11 },
  { 29, 2, 2, 2, 8205, 11 },
  { 58, 2, 2, 2, 8206, 11 },
  { 83, 2, 2, 2, 8207, 11 },
  { 108, 2, 2, 2, 8208, 11 },
  { 133, 2, 2, 2, 8209, 11 },
  { 23, 2, 2, 2, 8210, 11 },
  { 52, 2, 2, 2, 8211, 11 },
  { 77, 2, 2, 2, 8212, 11 },
  { 102, 2, 2, 2, 8213, 11 },
  { 127, 2, 2, 2, 8214, 11 },
  { 152, 2, 2, 2, 8215, 11 },
  { 169, 2, 2, 2, 8216, 11 },
  { 186, 2, 2, 2, 8217, 11 },
  { 203, 2, 2, 2, 8218, 11 },
  { 220, 2, 2, 2, 8219, 11 },
  { 4, 2, 2, 2, 8220, 11 },
  { 33, 2, 2, 2, 8221, 11 },
  { 62, 2, 2, 2, 8222, 11 },
  { 87, 2, 2, 2, 8223, 11 },
  { 112, 2, 2, 2, 8224, 11 },
  { 137, 2, 2, 2, 8225, 11 },
  { 26, 91, 2, 0, 8226, 1 },
  { 55, 91, 2, 0, 8227, 1 },
  { 80, 91, 2, 0, 8228, 1 },
  { 105, 91, 2, 0, 8229, 1 },
  { 130, 91, 2, 0, 8230, 1 },
  { 155, 91, 2, 0, 8231, 1 },
  { 172, 91, 2, 0, 8232, 1 },
  { 189, 91, 2, 0, 8233, 1 },
  { 206, 91, 2, 0, 8234, 1 },
  { 223, 91, 2, 0, 8235, 1 },
  { 8, 91, 2, 0, 8236, 1 },
  { 37, 91, 2, 0, 8237, 1 },
  { 66, 91, 2, 0, 8238, 1 },
  { 91, 91, 2, 0, 8239, 1 },
  { 116, 91, 2, 0, 8240, 1 },
  { 141, 91, 2, 0, 8241, 1 },
  { 158, 91, 2, 0, 8242, 1 },
  { 175, 91, 2, 0, 8243, 1 },
  { 192, 91, 2, 0, 8244, 1 },
  { 209, 91, 2, 0, 8245, 1 },
  { 12, 91, 2, 0, 8246, 1 },
  { 41, 91, 2, 0, 8247, 1 },
  { 70, 91, 2, 0, 8248, 1 },
  { 95, 91, 2, 0, 8249, 1 },
  { 120, 91, 2, 0, 8250, 1 },
  { 145, 91, 2, 0, 8251, 1 },
  { 162, 91, 2, 0, 8252, 1 },
  { 179, 91, 2, 0, 8253, 1 },
  { 196, 91, 2, 0, 8254, 1 },
  { 213, 91, 2, 0, 8255, 1 },
  { 16, 91, 2, 0, 8256, 1 },
  { 45, 91, 2, 0, 8257, 1 },
  { 253, 68, 159, 1, 8226, 1 },
  { 281, 68, 159, 1, 8227, 1 },
  { 304, 68, 155, 1, 8228, 1 },
  { 327, 68, 155, 1, 8229, 1 },
  { 350, 68, 155, 1, 8230, 1 },
  { 373, 68, 155, 1, 8231, 1 },
  { 391, 68, 151, 1, 8232, 1 },
  { 409, 68, 151, 1, 8233, 1 },
  { 427, 68, 151, 1, 8234, 1 },
  { 445, 68, 151, 1, 8235, 1 },
  { 233, 68, 147, 1, 8236, 1 },
  { 261, 68, 147, 1, 8237, 1 },
  { 289, 68, 147, 1, 8238, 1 },
  { 312, 68, 147, 1, 8239, 1 },
  { 335, 68, 143, 1, 8240, 1 },
  { 358, 68, 143, 1, 8241, 1 },
  { 381, 68, 1, 1, 8242, 1 },
  { 399, 68, 1, 1, 8243, 1 },
  { 417, 68, 1, 1, 8244, 1 },
  { 435, 68, 1, 1, 8245, 1 },
  { 243, 68, 1, 1, 8246, 1 },
  { 271, 68, 1, 1, 8247, 1 },
  { 299, 68, 1, 1, 8248, 1 },
  { 322, 68, 1, 1, 8249, 1 },
  { 345, 68, 1, 1, 8250, 1 },
  { 368, 68, 1, 1, 8251, 1 },
  { 386, 68, 1, 1, 8252, 1 },
  { 404, 68, 1, 1, 8253, 1 },
  { 422, 68, 1, 1, 8254, 1 },
  { 440, 68, 1, 1, 8255, 1 },
  { 248, 68, 1, 1, 8256, 1 },
  { 276, 68, 1, 1, 8257, 1 },
  { 598, 65, 2, 6, 258082, 3 },
  { 606, 65, 2, 6, 258083, 3 },
  { 634, 70, 2, 6, 258086, 3 },
  { 642, 70, 2, 6, 258087, 3 },
  { 650, 75, 2, 6, 258090, 3 },
  { 658, 75, 2, 6, 258091, 3 },
  { 610, 80, 2, 6, 258094, 3 },
  { 624, 80, 2, 6, 258095, 3 },
  { 677, 2, 158, 2, 8226, 11 },
  { 696, 2, 158, 2, 8227, 11 },
  { 710, 2, 154, 2, 8228, 11 },
  { 724, 2, 154, 2, 8229, 11 },
  { 738, 2, 154, 2, 8230, 11 },
  { 752, 2, 154, 2, 8231, 11 },
  { 766, 2, 150, 2, 8232, 11 },
  { 780, 2, 150, 2, 8233, 11 },
  { 794, 2, 150, 2, 8234, 11 },
  { 808, 2, 150, 2, 8235, 11 },
  { 662, 2, 146, 2, 8236, 11 },
  { 681, 2, 146, 2, 8237, 11 },
  { 700, 2, 146, 2, 8238, 11 },
  { 714, 2, 146, 2, 8239, 11 },
  { 728, 2, 142, 2, 8240, 11 },
  { 742, 2, 142, 2, 8241, 11 },
  { 756, 2, 0, 2, 8242, 11 },
  { 770, 2, 0, 2, 8243, 11 },
  { 784, 2, 0, 2, 8244, 11 },
  { 798, 2, 0, 2, 8245, 11 },
  { 667, 2, 0, 2, 8246, 11 },
  { 686, 2, 0, 2, 8247, 11 },
  { 705, 2, 0, 2, 8248, 11 },
  { 719, 2, 0, 2, 8249, 11 },
  { 733, 2, 0, 2, 8250, 11 },
  { 747, 2, 0, 2, 8251, 11 },
  { 761, 2, 0, 2, 8252, 11 },
  { 775, 2, 0, 2, 8253, 11 },
  { 789, 2, 0, 2, 8254, 11 },
  { 803, 2, 0, 2, 8255, 11 },
  { 672, 2, 0, 2, 8256, 11 },
  { 691, 2, 0, 2, 8257, 11 },
  { 257, 7, 137, 3, 249922, 0 },
  { 285, 7, 131, 3, 249924, 0 },
  { 308, 7, 131, 3, 249926, 0 },
  { 331, 7, 125, 3, 249928, 0 },
  { 354, 7, 125, 3, 249930, 0 },
  { 377, 7, 119, 3, 249932, 0 },
  { 395, 7, 119, 3, 249934, 0 },
  { 413, 7, 113, 3, 249936, 0 },
  { 431, 7, 113, 3, 249938, 0 },
  { 449, 7, 107, 3, 249940, 0 },
  { 238, 7, 107, 3, 249942, 0 },
  { 266, 7, 101, 3, 249944, 0 },
  { 294, 7, 101, 3, 249946, 0 },
  { 317, 7, 95, 3, 249948, 0 },
  { 340, 7, 95, 3, 249950, 0 },
  { 363, 7, 68, 3, 249952, 0 },
  { 458, 2, 139, 2, 8259, 11 },
  { 467, 2, 133, 2, 8261, 11 },
  { 476, 2, 133, 2, 8263, 11 },
  { 485, 2, 127, 2, 8265, 11 },
  { 494, 2, 127, 2, 8267, 11 },
  { 503, 2, 121, 2, 8269, 11 },
  { 507, 2, 121, 2, 8271, 11 },
  { 511, 2, 115, 2, 8273, 11 },
  { 515, 2, 115, 2, 8275, 11 },
  { 519, 2, 109, 2, 8277, 11 },
  { 453, 2, 109, 2, 8279, 11 },
  { 462, 2, 103, 2, 8281, 11 },
  { 471, 2, 103, 2, 8283, 11 },
  { 480, 2, 97, 2, 8285, 11 },
  { 489, 2, 97, 2, 8287, 11 },
  { 498, 2, 88, 2, 8289, 11 },
  { 528, 2, 136, 2, 8258, 11 },
  { 537, 2, 130, 2, 8260, 11 },
  { 546, 2, 130, 2, 8262, 11 },
  { 555, 2, 124, 2, 8264, 11 },
  { 564, 2, 124, 2, 8266, 11 },
  { 573, 2, 118, 2, 8268, 11 },
  { 577, 2, 118, 2, 8270, 11 },
  { 581, 2, 112, 2, 8272, 11 },
  { 585, 2, 112, 2, 8274, 11 },
  { 589, 2, 106, 2, 8276, 11 },
  { 523, 2, 106, 2, 8278, 11 },
  { 532, 2, 100, 2, 8280, 11 },
  { 541, 2, 100, 2, 8282, 11 },
  { 550, 2, 94, 2, 8284, 11 },
  { 559, 2, 94, 2, 8286, 11 },
  { 568, 2, 85, 2, 8288, 11 },
  { 602, 3, 2, 11, 241730, 6 },
  { 620, 10, 2, 11, 241734, 6 },
  { 638, 17, 2, 11, 241738, 6 },
  { 646, 24, 2, 11, 241742, 6 },
  { 654, 31, 2, 11, 241746, 6 },
  { 593, 38, 2, 11, 241750, 6 },
  { 615, 45, 2, 11, 241754, 6 },
  { 629, 52, 2, 11, 241758, 6 },
};

  // GRX32Bit Register Class...
  static const MCPhysReg GRX32Bit[] = {
    SystemZ_R0L, SystemZ_R1L, SystemZ_R2L, SystemZ_R3L, SystemZ_R4L, SystemZ_R5L, SystemZ_R0H, SystemZ_R1H, SystemZ_R2H, SystemZ_R3H, SystemZ_R4H, SystemZ_R5H, SystemZ_R15L, SystemZ_R15H, SystemZ_R14L, SystemZ_R14H, SystemZ_R13L, SystemZ_R13H, SystemZ_R12L, SystemZ_R12H, SystemZ_R11L, SystemZ_R11H, SystemZ_R10L, SystemZ_R10H, SystemZ_R9L, SystemZ_R9H, SystemZ_R8L, SystemZ_R8H, SystemZ_R7L, SystemZ_R7H, SystemZ_R6L, SystemZ_R6H, 
  };

  // GRX32Bit Bit set.
  static const uint8_t GRX32BitBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // VR32Bit Register Class...
  static const MCPhysReg VR32Bit[] = {
    SystemZ_F0S, SystemZ_F1S, SystemZ_F2S, SystemZ_F3S, SystemZ_F4S, SystemZ_F5S, SystemZ_F6S, SystemZ_F7S, SystemZ_F16S, SystemZ_F17S, SystemZ_F18S, SystemZ_F19S, SystemZ_F20S, SystemZ_F21S, SystemZ_F22S, SystemZ_F23S, SystemZ_F24S, SystemZ_F25S, SystemZ_F26S, SystemZ_F27S, SystemZ_F28S, SystemZ_F29S, SystemZ_F30S, SystemZ_F31S, SystemZ_F8S, SystemZ_F9S, SystemZ_F10S, SystemZ_F11S, SystemZ_F12S, SystemZ_F13S, SystemZ_F14S, SystemZ_F15S, 
  };

  // VR32Bit Bit set.
  static const uint8_t VR32BitBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // AR32Bit Register Class...
  static const MCPhysReg AR32Bit[] = {
    SystemZ_A0, SystemZ_A1, SystemZ_A2, SystemZ_A3, SystemZ_A4, SystemZ_A5, SystemZ_A6, SystemZ_A7, SystemZ_A8, SystemZ_A9, SystemZ_A10, SystemZ_A11, SystemZ_A12, SystemZ_A13, SystemZ_A14, SystemZ_A15, 
  };

  // AR32Bit Bit set.
  static const uint8_t AR32BitBits[] = {
    0xf8, 0xff, 0x07, 
  };

  // FP32Bit Register Class...
  static const MCPhysReg FP32Bit[] = {
    SystemZ_F0S, SystemZ_F1S, SystemZ_F2S, SystemZ_F3S, SystemZ_F4S, SystemZ_F5S, SystemZ_F6S, SystemZ_F7S, SystemZ_F8S, SystemZ_F9S, SystemZ_F10S, SystemZ_F11S, SystemZ_F12S, SystemZ_F13S, SystemZ_F14S, SystemZ_F15S, 
  };

  // FP32Bit Bit set.
  static const uint8_t FP32BitBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x07, 
  };

  // GR32Bit Register Class...
  static const MCPhysReg GR32Bit[] = {
    SystemZ_R0L, SystemZ_R1L, SystemZ_R2L, SystemZ_R3L, SystemZ_R4L, SystemZ_R5L, SystemZ_R15L, SystemZ_R14L, SystemZ_R13L, SystemZ_R12L, SystemZ_R11L, SystemZ_R10L, SystemZ_R9L, SystemZ_R8L, SystemZ_R7L, SystemZ_R6L, 
  };

  // GR32Bit Bit set.
  static const uint8_t GR32BitBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x07, 
  };

  // GRH32Bit Register Class...
  static const MCPhysReg GRH32Bit[] = {
    SystemZ_R0H, SystemZ_R1H, SystemZ_R2H, SystemZ_R3H, SystemZ_R4H, SystemZ_R5H, SystemZ_R15H, SystemZ_R14H, SystemZ_R13H, SystemZ_R12H, SystemZ_R11H, SystemZ_R10H, SystemZ_R9H, SystemZ_R8H, SystemZ_R7H, SystemZ_R6H, 
  };

  // GRH32Bit Bit set.
  static const uint8_t GRH32BitBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x07, 
  };

  // ADDR32Bit Register Class...
  static const MCPhysReg ADDR32Bit[] = {
    SystemZ_R1L, SystemZ_R2L, SystemZ_R3L, SystemZ_R4L, SystemZ_R5L, SystemZ_R15L, SystemZ_R14L, SystemZ_R13L, SystemZ_R12L, SystemZ_R11L, SystemZ_R10L, SystemZ_R9L, SystemZ_R8L, SystemZ_R7L, SystemZ_R6L, 
  };

  // ADDR32Bit Bit set.
  static const uint8_t ADDR32BitBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 
  };

  // CCR Register Class...
  static const MCPhysReg CCR[] = {
    SystemZ_CC, 
  };

  // CCR Bit set.
  static const uint8_t CCRBits[] = {
    0x02, 
  };

  // FPCRegs Register Class...
  static const MCPhysReg FPCRegs[] = {
    SystemZ_FPC, 
  };

  // FPCRegs Bit set.
  static const uint8_t FPCRegsBits[] = {
    0x04, 
  };

  // AnyRegBit Register Class...
  static const MCPhysReg AnyRegBit[] = {
    SystemZ_R0D, SystemZ_R1D, SystemZ_R2D, SystemZ_R3D, SystemZ_R4D, SystemZ_R5D, SystemZ_R6D, SystemZ_R7D, SystemZ_R8D, SystemZ_R9D, SystemZ_R10D, SystemZ_R11D, SystemZ_R12D, SystemZ_R13D, SystemZ_R14D, SystemZ_R15D, SystemZ_F0D, SystemZ_F1D, SystemZ_F2D, SystemZ_F3D, SystemZ_F4D, SystemZ_F5D, SystemZ_F6D, SystemZ_F7D, SystemZ_F8D, SystemZ_F9D, SystemZ_F10D, SystemZ_F11D, SystemZ_F12D, SystemZ_F13D, SystemZ_F14D, SystemZ_F15D, SystemZ_V0, SystemZ_V1, SystemZ_V2, SystemZ_V3, SystemZ_V4, SystemZ_V5, SystemZ_V6, SystemZ_V7, SystemZ_V8, SystemZ_V9, SystemZ_V10, SystemZ_V11, SystemZ_V12, SystemZ_V13, SystemZ_V14, SystemZ_V15, 
  };

  // AnyRegBit Bit set.
  static const uint8_t AnyRegBitBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x07, 0x00, 0xf8, 0xff, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x07, 
  };

  // AnyRegBit_with_subreg_h32_in_FP32Bit Register Class...
  static const MCPhysReg AnyRegBit_with_subreg_h32_in_FP32Bit[] = {
    SystemZ_F0D, SystemZ_F1D, SystemZ_F2D, SystemZ_F3D, SystemZ_F4D, SystemZ_F5D, SystemZ_F6D, SystemZ_F7D, SystemZ_F8D, SystemZ_F9D, SystemZ_F10D, SystemZ_F11D, SystemZ_F12D, SystemZ_F13D, SystemZ_F14D, SystemZ_F15D, SystemZ_V0, SystemZ_V1, SystemZ_V2, SystemZ_V3, SystemZ_V4, SystemZ_V5, SystemZ_V6, SystemZ_V7, SystemZ_V8, SystemZ_V9, SystemZ_V10, SystemZ_V11, SystemZ_V12, SystemZ_V13, SystemZ_V14, SystemZ_V15, 
  };

  // AnyRegBit_with_subreg_h32_in_FP32Bit Bit set.
  static const uint8_t AnyRegBit_with_subreg_h32_in_FP32BitBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x07, 0x00, 0xf8, 0xff, 0x07, 
  };

  // VR64Bit Register Class...
  static const MCPhysReg VR64Bit[] = {
    SystemZ_F0D, SystemZ_F1D, SystemZ_F2D, SystemZ_F3D, SystemZ_F4D, SystemZ_F5D, SystemZ_F6D, SystemZ_F7D, SystemZ_F16D, SystemZ_F17D, SystemZ_F18D, SystemZ_F19D, SystemZ_F20D, SystemZ_F21D, SystemZ_F22D, SystemZ_F23D, SystemZ_F24D, SystemZ_F25D, SystemZ_F26D, SystemZ_F27D, SystemZ_F28D, SystemZ_F29D, SystemZ_F30D, SystemZ_F31D, SystemZ_F8D, SystemZ_F9D, SystemZ_F10D, SystemZ_F11D, SystemZ_F12D, SystemZ_F13D, SystemZ_F14D, SystemZ_F15D, 
  };

  // VR64Bit Bit set.
  static const uint8_t VR64BitBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // AnyRegBit_with_subreg_h64 Register Class...
  static const MCPhysReg AnyRegBit_with_subreg_h64[] = {
    SystemZ_V0, SystemZ_V1, SystemZ_V2, SystemZ_V3, SystemZ_V4, SystemZ_V5, SystemZ_V6, SystemZ_V7, SystemZ_V8, SystemZ_V9, SystemZ_V10, SystemZ_V11, SystemZ_V12, SystemZ_V13, SystemZ_V14, SystemZ_V15, 
  };

  // AnyRegBit_with_subreg_h64 Bit set.
  static const uint8_t AnyRegBit_with_subreg_h64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x07, 
  };

  // CR64Bit Register Class...
  static const MCPhysReg CR64Bit[] = {
    SystemZ_C0, SystemZ_C1, SystemZ_C2, SystemZ_C3, SystemZ_C4, SystemZ_C5, SystemZ_C6, SystemZ_C7, SystemZ_C8, SystemZ_C9, SystemZ_C10, SystemZ_C11, SystemZ_C12, SystemZ_C13, SystemZ_C14, SystemZ_C15, 
  };

  // CR64Bit Bit set.
  static const uint8_t CR64BitBits[] = {
    0x00, 0x00, 0xf8, 0xff, 0x07, 
  };

  // FP64Bit Register Class...
  static const MCPhysReg FP64Bit[] = {
    SystemZ_F0D, SystemZ_F1D, SystemZ_F2D, SystemZ_F3D, SystemZ_F4D, SystemZ_F5D, SystemZ_F6D, SystemZ_F7D, SystemZ_F8D, SystemZ_F9D, SystemZ_F10D, SystemZ_F11D, SystemZ_F12D, SystemZ_F13D, SystemZ_F14D, SystemZ_F15D, 
  };

  // FP64Bit Bit set.
  static const uint8_t FP64BitBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x07, 
  };

  // GR64Bit Register Class...
  static const MCPhysReg GR64Bit[] = {
    SystemZ_R0D, SystemZ_R1D, SystemZ_R2D, SystemZ_R3D, SystemZ_R4D, SystemZ_R5D, SystemZ_R15D, SystemZ_R14D, SystemZ_R13D, SystemZ_R12D, SystemZ_R11D, SystemZ_R10D, SystemZ_R9D, SystemZ_R8D, SystemZ_R7D, SystemZ_R6D, 
  };

  // GR64Bit Bit set.
  static const uint8_t GR64BitBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x07, 
  };

  // ADDR64Bit Register Class...
  static const MCPhysReg ADDR64Bit[] = {
    SystemZ_R1D, SystemZ_R2D, SystemZ_R3D, SystemZ_R4D, SystemZ_R5D, SystemZ_R15D, SystemZ_R14D, SystemZ_R13D, SystemZ_R12D, SystemZ_R11D, SystemZ_R10D, SystemZ_R9D, SystemZ_R8D, SystemZ_R7D, SystemZ_R6D, 
  };

  // ADDR64Bit Bit set.
  static const uint8_t ADDR64BitBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x07, 
  };

  // VR128Bit Register Class...
  static const MCPhysReg VR128Bit[] = {
    SystemZ_V0, SystemZ_V1, SystemZ_V2, SystemZ_V3, SystemZ_V4, SystemZ_V5, SystemZ_V6, SystemZ_V7, SystemZ_V16, SystemZ_V17, SystemZ_V18, SystemZ_V19, SystemZ_V20, SystemZ_V21, SystemZ_V22, SystemZ_V23, SystemZ_V24, SystemZ_V25, SystemZ_V26, SystemZ_V27, SystemZ_V28, SystemZ_V29, SystemZ_V30, SystemZ_V31, SystemZ_V8, SystemZ_V9, SystemZ_V10, SystemZ_V11, SystemZ_V12, SystemZ_V13, SystemZ_V14, SystemZ_V15, 
  };

  // VR128Bit Bit set.
  static const uint8_t VR128BitBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // VF128Bit Register Class...
  static const MCPhysReg VF128Bit[] = {
    SystemZ_V0, SystemZ_V1, SystemZ_V2, SystemZ_V3, SystemZ_V4, SystemZ_V5, SystemZ_V6, SystemZ_V7, SystemZ_V8, SystemZ_V9, SystemZ_V10, SystemZ_V11, SystemZ_V12, SystemZ_V13, SystemZ_V14, SystemZ_V15, 
  };

  // VF128Bit Bit set.
  static const uint8_t VF128BitBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0x07, 
  };

  // FP128Bit Register Class...
  static const MCPhysReg FP128Bit[] = {
    SystemZ_F0Q, SystemZ_F1Q, SystemZ_F4Q, SystemZ_F5Q, SystemZ_F8Q, SystemZ_F9Q, SystemZ_F12Q, SystemZ_F13Q, 
  };

  // FP128Bit Bit set.
  static const uint8_t FP128BitBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x07, 
  };

  // GR128Bit Register Class...
  static const MCPhysReg GR128Bit[] = {
    SystemZ_R0Q, SystemZ_R2Q, SystemZ_R4Q, SystemZ_R12Q, SystemZ_R10Q, SystemZ_R8Q, SystemZ_R6Q, SystemZ_R14Q, 
  };

  // GR128Bit Bit set.
  static const uint8_t GR128BitBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x07, 
  };

  // ADDR128Bit Register Class...
  static const MCPhysReg ADDR128Bit[] = {
    SystemZ_R2Q, SystemZ_R4Q, SystemZ_R12Q, SystemZ_R10Q, SystemZ_R8Q, SystemZ_R6Q, SystemZ_R14Q, 
  };

  // ADDR128Bit Bit set.
  static const uint8_t ADDR128BitBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x07, 
  };

static const MCRegisterClass SystemZMCRegisterClasses[] = {
  { GRX32Bit, GRX32BitBits, sizeof(GRX32BitBits) },
  { VR32Bit, VR32BitBits, sizeof(VR32BitBits) },
  { AR32Bit, AR32BitBits, sizeof(AR32BitBits) },
  { FP32Bit, FP32BitBits, sizeof(FP32BitBits) },
  { GR32Bit, GR32BitBits, sizeof(GR32BitBits) },
  { GRH32Bit, GRH32BitBits, sizeof(GRH32BitBits) },
  { ADDR32Bit, ADDR32BitBits, sizeof(ADDR32BitBits) },
  { CCR, CCRBits, sizeof(CCRBits) },
  { FPCRegs, FPCRegsBits, sizeof(FPCRegsBits) },
  { AnyRegBit, AnyRegBitBits, sizeof(AnyRegBitBits) },
  { AnyRegBit_with_subreg_h32_in_FP32Bit, AnyRegBit_with_subreg_h32_in_FP32BitBits, sizeof(AnyRegBit_with_subreg_h32_in_FP32BitBits) },
  { VR64Bit, VR64BitBits, sizeof(VR64BitBits) },
  { AnyRegBit_with_subreg_h64, AnyRegBit_with_subreg_h64Bits, sizeof(AnyRegBit_with_subreg_h64Bits) },
  { CR64Bit, CR64BitBits, sizeof(CR64BitBits) },
  { FP64Bit, FP64BitBits, sizeof(FP64BitBits) },
  { GR64Bit, GR64BitBits, sizeof(GR64BitBits) },
  { ADDR64Bit, ADDR64BitBits, sizeof(ADDR64BitBits) },
  { VR128Bit, VR128BitBits, sizeof(VR128BitBits) },
  { VF128Bit, VF128BitBits, sizeof(VF128BitBits) },
  { FP128Bit, FP128BitBits, sizeof(FP128BitBits) },
  { GR128Bit, GR128BitBits, sizeof(GR128BitBits) },
  { ADDR128Bit, ADDR128BitBits, sizeof(ADDR128BitBits) },
};

static const uint16_t SystemZRegEncodingTable[] = {
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
  4,
  5,
  8,
  9,
  12,
  13,
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
  0,
  2,
  4,
  6,
  8,
  10,
  12,
  14,
};
#endif // GET_REGINFO_MC_DESC




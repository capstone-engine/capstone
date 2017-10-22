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
  X86_NoRegister,
  X86_AH = 1,
  X86_AL = 2,
  X86_AX = 3,
  X86_BH = 4,
  X86_BL = 5,
  X86_BP = 6,
  X86_BPL = 7,
  X86_BX = 8,
  X86_CH = 9,
  X86_CL = 10,
  X86_CS = 11,
  X86_CX = 12,
  X86_DH = 13,
  X86_DI = 14,
  X86_DIL = 15,
  X86_DL = 16,
  X86_DS = 17,
  X86_DX = 18,
  X86_EAX = 19,
  X86_EBP = 20,
  X86_EBX = 21,
  X86_ECX = 22,
  X86_EDI = 23,
  X86_EDX = 24,
  X86_EFLAGS = 25,
  X86_EIP = 26,
  X86_EIZ = 27,
  X86_ES = 28,
  X86_ESI = 29,
  X86_ESP = 30,
  X86_FPSW = 31,
  X86_FS = 32,
  X86_GS = 33,
  X86_IP = 34,
  X86_RAX = 35,
  X86_RBP = 36,
  X86_RBX = 37,
  X86_RCX = 38,
  X86_RDI = 39,
  X86_RDX = 40,
  X86_RIP = 41,
  X86_RIZ = 42,
  X86_RSI = 43,
  X86_RSP = 44,
  X86_SI = 45,
  X86_SIL = 46,
  X86_SP = 47,
  X86_SPL = 48,
  X86_SS = 49,
  X86_CR0 = 50,
  X86_CR1 = 51,
  X86_CR2 = 52,
  X86_CR3 = 53,
  X86_CR4 = 54,
  X86_CR5 = 55,
  X86_CR6 = 56,
  X86_CR7 = 57,
  X86_CR8 = 58,
  X86_CR9 = 59,
  X86_CR10 = 60,
  X86_CR11 = 61,
  X86_CR12 = 62,
  X86_CR13 = 63,
  X86_CR14 = 64,
  X86_CR15 = 65,
  X86_DR0 = 66,
  X86_DR1 = 67,
  X86_DR2 = 68,
  X86_DR3 = 69,
  X86_DR4 = 70,
  X86_DR5 = 71,
  X86_DR6 = 72,
  X86_DR7 = 73,
  X86_FP0 = 74,
  X86_FP1 = 75,
  X86_FP2 = 76,
  X86_FP3 = 77,
  X86_FP4 = 78,
  X86_FP5 = 79,
  X86_FP6 = 80,
  X86_FP7 = 81,
  X86_K0 = 82,
  X86_K1 = 83,
  X86_K2 = 84,
  X86_K3 = 85,
  X86_K4 = 86,
  X86_K5 = 87,
  X86_K6 = 88,
  X86_K7 = 89,
  X86_MM0 = 90,
  X86_MM1 = 91,
  X86_MM2 = 92,
  X86_MM3 = 93,
  X86_MM4 = 94,
  X86_MM5 = 95,
  X86_MM6 = 96,
  X86_MM7 = 97,
  X86_R8 = 98,
  X86_R9 = 99,
  X86_R10 = 100,
  X86_R11 = 101,
  X86_R12 = 102,
  X86_R13 = 103,
  X86_R14 = 104,
  X86_R15 = 105,
  X86_ST0 = 106,
  X86_ST1 = 107,
  X86_ST2 = 108,
  X86_ST3 = 109,
  X86_ST4 = 110,
  X86_ST5 = 111,
  X86_ST6 = 112,
  X86_ST7 = 113,
  X86_XMM0 = 114,
  X86_XMM1 = 115,
  X86_XMM2 = 116,
  X86_XMM3 = 117,
  X86_XMM4 = 118,
  X86_XMM5 = 119,
  X86_XMM6 = 120,
  X86_XMM7 = 121,
  X86_XMM8 = 122,
  X86_XMM9 = 123,
  X86_XMM10 = 124,
  X86_XMM11 = 125,
  X86_XMM12 = 126,
  X86_XMM13 = 127,
  X86_XMM14 = 128,
  X86_XMM15 = 129,
  X86_XMM16 = 130,
  X86_XMM17 = 131,
  X86_XMM18 = 132,
  X86_XMM19 = 133,
  X86_XMM20 = 134,
  X86_XMM21 = 135,
  X86_XMM22 = 136,
  X86_XMM23 = 137,
  X86_XMM24 = 138,
  X86_XMM25 = 139,
  X86_XMM26 = 140,
  X86_XMM27 = 141,
  X86_XMM28 = 142,
  X86_XMM29 = 143,
  X86_XMM30 = 144,
  X86_XMM31 = 145,
  X86_YMM0 = 146,
  X86_YMM1 = 147,
  X86_YMM2 = 148,
  X86_YMM3 = 149,
  X86_YMM4 = 150,
  X86_YMM5 = 151,
  X86_YMM6 = 152,
  X86_YMM7 = 153,
  X86_YMM8 = 154,
  X86_YMM9 = 155,
  X86_YMM10 = 156,
  X86_YMM11 = 157,
  X86_YMM12 = 158,
  X86_YMM13 = 159,
  X86_YMM14 = 160,
  X86_YMM15 = 161,
  X86_YMM16 = 162,
  X86_YMM17 = 163,
  X86_YMM18 = 164,
  X86_YMM19 = 165,
  X86_YMM20 = 166,
  X86_YMM21 = 167,
  X86_YMM22 = 168,
  X86_YMM23 = 169,
  X86_YMM24 = 170,
  X86_YMM25 = 171,
  X86_YMM26 = 172,
  X86_YMM27 = 173,
  X86_YMM28 = 174,
  X86_YMM29 = 175,
  X86_YMM30 = 176,
  X86_YMM31 = 177,
  X86_ZMM0 = 178,
  X86_ZMM1 = 179,
  X86_ZMM2 = 180,
  X86_ZMM3 = 181,
  X86_ZMM4 = 182,
  X86_ZMM5 = 183,
  X86_ZMM6 = 184,
  X86_ZMM7 = 185,
  X86_ZMM8 = 186,
  X86_ZMM9 = 187,
  X86_ZMM10 = 188,
  X86_ZMM11 = 189,
  X86_ZMM12 = 190,
  X86_ZMM13 = 191,
  X86_ZMM14 = 192,
  X86_ZMM15 = 193,
  X86_ZMM16 = 194,
  X86_ZMM17 = 195,
  X86_ZMM18 = 196,
  X86_ZMM19 = 197,
  X86_ZMM20 = 198,
  X86_ZMM21 = 199,
  X86_ZMM22 = 200,
  X86_ZMM23 = 201,
  X86_ZMM24 = 202,
  X86_ZMM25 = 203,
  X86_ZMM26 = 204,
  X86_ZMM27 = 205,
  X86_ZMM28 = 206,
  X86_ZMM29 = 207,
  X86_ZMM30 = 208,
  X86_ZMM31 = 209,
  X86_R8B = 210,
  X86_R9B = 211,
  X86_R10B = 212,
  X86_R11B = 213,
  X86_R12B = 214,
  X86_R13B = 215,
  X86_R14B = 216,
  X86_R15B = 217,
  X86_R8D = 218,
  X86_R9D = 219,
  X86_R10D = 220,
  X86_R11D = 221,
  X86_R12D = 222,
  X86_R13D = 223,
  X86_R14D = 224,
  X86_R15D = 225,
  X86_R8W = 226,
  X86_R9W = 227,
  X86_R10W = 228,
  X86_R11W = 229,
  X86_R12W = 230,
  X86_R13W = 231,
  X86_R14W = 232,
  X86_R15W = 233,
  X86_NUM_TARGET_REGS 	// 234
};

// Register classes
enum {
  X86_GR8RegClassID = 0,
  X86_GR8_NOREXRegClassID = 1,
  X86_GR8_ABCD_HRegClassID = 2,
  X86_GR8_ABCD_LRegClassID = 3,
  X86_GR16RegClassID = 4,
  X86_GR16_NOREXRegClassID = 5,
  X86_VK1RegClassID = 6,
  X86_VK16RegClassID = 7,
  X86_VK2RegClassID = 8,
  X86_VK4RegClassID = 9,
  X86_VK8RegClassID = 10,
  X86_VK16WMRegClassID = 11,
  X86_VK1WMRegClassID = 12,
  X86_VK2WMRegClassID = 13,
  X86_VK4WMRegClassID = 14,
  X86_VK8WMRegClassID = 15,
  X86_SEGMENT_REGRegClassID = 16,
  X86_GR16_ABCDRegClassID = 17,
  X86_FPCCRRegClassID = 18,
  X86_FR32XRegClassID = 19,
  X86_FR32RegClassID = 20,
  X86_GR32RegClassID = 21,
  X86_GR32_NOAXRegClassID = 22,
  X86_GR32_NOSPRegClassID = 23,
  X86_GR32_NOAX_and_GR32_NOSPRegClassID = 24,
  X86_DEBUG_REGRegClassID = 25,
  X86_GR32_NOREXRegClassID = 26,
  X86_VK32RegClassID = 27,
  X86_GR32_NOAX_and_GR32_NOREXRegClassID = 28,
  X86_GR32_NOREX_NOSPRegClassID = 29,
  X86_RFP32RegClassID = 30,
  X86_VK32WMRegClassID = 31,
  X86_GR32_NOAX_and_GR32_NOREX_NOSPRegClassID = 32,
  X86_GR32_ABCDRegClassID = 33,
  X86_GR32_ABCD_and_GR32_NOAXRegClassID = 34,
  X86_GR32_TCRegClassID = 35,
  X86_GR32_ADRegClassID = 36,
  X86_GR32_NOAX_and_GR32_TCRegClassID = 37,
  X86_CCRRegClassID = 38,
  X86_GR32_AD_and_GR32_NOAXRegClassID = 39,
  X86_RFP64RegClassID = 40,
  X86_FR64XRegClassID = 41,
  X86_GR64RegClassID = 42,
  X86_CONTROL_REGRegClassID = 43,
  X86_FR64RegClassID = 44,
  X86_GR64_with_sub_8bitRegClassID = 45,
  X86_GR64_NOSPRegClassID = 46,
  X86_GR64_with_sub_32bit_in_GR32_NOAXRegClassID = 47,
  X86_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOSPRegClassID = 48,
  X86_GR64_NOREXRegClassID = 49,
  X86_GR64_TCRegClassID = 50,
  X86_GR64_NOSP_and_GR64_TCRegClassID = 51,
  X86_GR64_with_sub_16bit_in_GR16_NOREXRegClassID = 52,
  X86_VK64RegClassID = 53,
  X86_VR64RegClassID = 54,
  X86_GR64_NOREX_NOSPRegClassID = 55,
  X86_GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAXRegClassID = 56,
  X86_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREXRegClassID = 57,
  X86_VK64WMRegClassID = 58,
  X86_GR64_NOREX_and_GR64_TCRegClassID = 59,
  X86_GR64_TCW64RegClassID = 60,
  X86_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX_NOSPRegClassID = 61,
  X86_GR64_NOREX_NOSP_and_GR64_TCRegClassID = 62,
  X86_GR64_TCW64_and_GR64_with_sub_32bit_in_GR32_NOAXRegClassID = 63,
  X86_GR64_ABCDRegClassID = 64,
  X86_GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREXRegClassID = 65,
  X86_GR64_with_sub_32bit_in_GR32_ABCD_and_GR32_NOAXRegClassID = 66,
  X86_GR64_with_sub_32bit_in_GR32_TCRegClassID = 67,
  X86_GR64_with_sub_32bit_in_GR32_ADRegClassID = 68,
  X86_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_TCRegClassID = 69,
  X86_GR64_with_sub_32bit_in_GR32_AD_and_GR32_NOAXRegClassID = 70,
  X86_RSTRegClassID = 71,
  X86_RFP80RegClassID = 72,
  X86_VR128XRegClassID = 73,
  X86_VR128RegClassID = 74,
  X86_VR256XRegClassID = 75,
  X86_VR256RegClassID = 76,
  X86_VR512RegClassID = 77,
  X86_VR512_with_sub_xmm_in_FR32RegClassID = 78
};

#endif // GET_REGINFO_ENUM

#ifdef GET_REGINFO_MC_DESC
#undef GET_REGINFO_MC_DESC

static const MCPhysReg X86RegDiffLists[] = {
  /* 0 */ 0, 1, 0,
  /* 3 */ 2, 1, 0,
  /* 6 */ 5, 1, 0,
  /* 9 */ 65522, 16, 1, 0,
  /* 13 */ 65522, 17, 1, 0,
  /* 17 */ 65427, 1, 0,
  /* 20 */ 65475, 1, 0,
  /* 23 */ 65520, 65522, 1, 0,
  /* 27 */ 65520, 65527, 1, 0,
  /* 31 */ 8, 2, 0,
  /* 34 */ 4, 0,
  /* 36 */ 65521, 8, 0,
  /* 39 */ 9, 0,
  /* 41 */ 13, 0,
  /* 43 */ 65535, 65519, 14, 0,
  /* 47 */ 65535, 65520, 14, 0,
  /* 51 */ 65528, 15, 0,
  /* 54 */ 2, 6, 16, 0,
  /* 58 */ 5, 6, 16, 0,
  /* 62 */ 65535, 9, 16, 0,
  /* 66 */ 2, 10, 16, 0,
  /* 70 */ 3, 10, 16, 0,
  /* 74 */ 3, 13, 16, 0,
  /* 78 */ 4, 13, 16, 0,
  /* 82 */ 65535, 14, 16, 0,
  /* 86 */ 1, 16, 16, 0,
  /* 90 */ 2, 16, 16, 0,
  /* 94 */ 17, 0,
  /* 96 */ 32, 32, 0,
  /* 99 */ 65221, 0,
  /* 101 */ 65381, 0,
  /* 103 */ 65389, 0,
  /* 105 */ 65397, 0,
  /* 107 */ 16, 65528, 65416, 0,
  /* 111 */ 65445, 0,
  /* 113 */ 65477, 0,
  /* 115 */ 65504, 65504, 0,
  /* 118 */ 65509, 0,
  /* 120 */ 120, 8, 65520, 0,
  /* 124 */ 65523, 0,
  /* 126 */ 65530, 0,
  /* 128 */ 65531, 0,
  /* 130 */ 65532, 0,
  /* 132 */ 65520, 65530, 65534, 65533, 0,
  /* 137 */ 65534, 0,
  /* 139 */ 65520, 65523, 65533, 65535, 0,
  /* 144 */ 65520, 65526, 65534, 65535, 0,
  /* 149 */ 65520, 65520, 65535, 65535, 0,
};

static const uint16_t X86SubRegIdxLists[] = {
  /* 0 */ 4, 3, 1, 0,
  /* 4 */ 4, 3, 1, 2, 0,
  /* 9 */ 4, 3, 0,
  /* 12 */ 6, 5, 0,
};

static const MCRegisterDesc X86RegDesc[] = { // Descriptors
  { 5, 0, 0, 0, 0 },
  { 812, 2, 90, 3, 2273 },
  { 840, 2, 86, 3, 2273 },
  { 958, 151, 87, 6, 0 },
  { 815, 2, 78, 3, 2193 },
  { 843, 2, 74, 3, 2193 },
  { 869, 1, 83, 2, 544 },
  { 860, 2, 82, 3, 544 },
  { 966, 141, 75, 6, 48 },
  { 818, 2, 70, 3, 2081 },
  { 846, 2, 66, 3, 2081 },
  { 892, 2, 2, 3, 2081 },
  { 974, 146, 67, 6, 96 },
  { 821, 2, 58, 3, 2049 },
  { 825, 1, 63, 2, 624 },
  { 852, 2, 62, 3, 624 },
  { 849, 2, 54, 3, 2017 },
  { 895, 2, 2, 3, 2017 },
  { 982, 134, 55, 6, 496 },
  { 957, 150, 56, 5, 0 },
  { 868, 24, 56, 1, 544 },
  { 965, 140, 56, 5, 323 },
  { 973, 145, 56, 5, 323 },
  { 824, 28, 56, 1, 624 },
  { 981, 133, 56, 5, 496 },
  { 904, 2, 2, 3, 1985 },
  { 876, 37, 52, 10, 1985 },
  { 989, 2, 2, 3, 1985 },
  { 898, 2, 2, 3, 1985 },
  { 832, 10, 45, 1, 1985 },
  { 884, 14, 45, 1, 1985 },
  { 952, 2, 2, 3, 1985 },
  { 901, 2, 2, 3, 1985 },
  { 908, 2, 2, 3, 1985 },
  { 877, 2, 51, 3, 656 },
  { 961, 149, 2, 4, 0 },
  { 872, 23, 2, 0, 544 },
  { 969, 139, 2, 4, 275 },
  { 977, 144, 2, 4, 275 },
  { 828, 27, 2, 0, 624 },
  { 985, 132, 2, 4, 496 },
  { 880, 36, 2, 9, 1592 },
  { 993, 2, 2, 3, 1592 },
  { 836, 9, 2, 0, 1889 },
  { 888, 13, 2, 0, 1889 },
  { 833, 1, 48, 2, 896 },
  { 856, 2, 47, 3, 896 },
  { 885, 1, 44, 2, 1504 },
  { 864, 2, 43, 3, 1504 },
  { 911, 2, 2, 3, 1889 },
  { 81, 2, 2, 3, 1889 },
  { 174, 2, 2, 3, 1889 },
  { 249, 2, 2, 3, 1889 },
  { 324, 2, 2, 3, 1889 },
  { 399, 2, 2, 3, 1889 },
  { 474, 2, 2, 3, 1889 },
  { 544, 2, 2, 3, 1889 },
  { 614, 2, 2, 3, 1889 },
  { 677, 2, 2, 3, 1889 },
  { 732, 2, 2, 3, 1889 },
  { 18, 2, 2, 3, 1889 },
  { 111, 2, 2, 3, 1889 },
  { 204, 2, 2, 3, 1889 },
  { 279, 2, 2, 3, 1889 },
  { 354, 2, 2, 3, 1889 },
  { 429, 2, 2, 3, 1889 },
  { 85, 2, 2, 3, 1889 },
  { 178, 2, 2, 3, 1889 },
  { 253, 2, 2, 3, 1889 },
  { 328, 2, 2, 3, 1889 },
  { 403, 2, 2, 3, 1889 },
  { 478, 2, 2, 3, 1889 },
  { 548, 2, 2, 3, 1889 },
  { 618, 2, 2, 3, 1889 },
  { 77, 2, 2, 3, 1889 },
  { 170, 2, 2, 3, 1889 },
  { 245, 2, 2, 3, 1889 },
  { 320, 2, 2, 3, 1889 },
  { 395, 2, 2, 3, 1889 },
  { 470, 2, 2, 3, 1889 },
  { 540, 2, 2, 3, 1889 },
  { 610, 2, 2, 3, 1889 },
  { 59, 2, 2, 3, 1889 },
  { 152, 2, 2, 3, 1889 },
  { 227, 2, 2, 3, 1889 },
  { 302, 2, 2, 3, 1889 },
  { 377, 2, 2, 3, 1889 },
  { 452, 2, 2, 3, 1889 },
  { 522, 2, 2, 3, 1889 },
  { 592, 2, 2, 3, 1889 },
  { 63, 2, 2, 3, 1889 },
  { 156, 2, 2, 3, 1889 },
  { 231, 2, 2, 3, 1889 },
  { 306, 2, 2, 3, 1889 },
  { 381, 2, 2, 3, 1889 },
  { 456, 2, 2, 3, 1889 },
  { 526, 2, 2, 3, 1889 },
  { 596, 2, 2, 3, 1889 },
  { 678, 120, 2, 0, 1889 },
  { 733, 120, 2, 0, 1889 },
  { 19, 120, 2, 0, 1889 },
  { 112, 120, 2, 0, 1889 },
  { 205, 120, 2, 0, 1889 },
  { 280, 120, 2, 0, 1889 },
  { 355, 120, 2, 0, 1889 },
  { 430, 120, 2, 0, 1889 },
  { 89, 2, 2, 3, 1889 },
  { 182, 2, 2, 3, 1889 },
  { 257, 2, 2, 3, 1889 },
  { 332, 2, 2, 3, 1889 },
  { 407, 2, 2, 3, 1889 },
  { 482, 2, 2, 3, 1889 },
  { 552, 2, 2, 3, 1889 },
  { 622, 2, 2, 3, 1889 },
  { 62, 2, 96, 3, 1889 },
  { 155, 2, 96, 3, 1889 },
  { 230, 2, 96, 3, 1889 },
  { 305, 2, 96, 3, 1889 },
  { 380, 2, 96, 3, 1889 },
  { 455, 2, 96, 3, 1889 },
  { 525, 2, 96, 3, 1889 },
  { 595, 2, 96, 3, 1889 },
  { 662, 2, 96, 3, 1889 },
  { 717, 2, 96, 3, 1889 },
  { 0, 2, 96, 3, 1889 },
  { 93, 2, 96, 3, 1889 },
  { 186, 2, 96, 3, 1889 },
  { 261, 2, 96, 3, 1889 },
  { 336, 2, 96, 3, 1889 },
  { 411, 2, 96, 3, 1889 },
  { 486, 2, 96, 3, 1889 },
  { 556, 2, 96, 3, 1889 },
  { 626, 2, 96, 3, 1889 },
  { 681, 2, 96, 3, 1889 },
  { 23, 2, 96, 3, 1889 },
  { 116, 2, 96, 3, 1889 },
  { 209, 2, 96, 3, 1889 },
  { 284, 2, 96, 3, 1889 },
  { 359, 2, 96, 3, 1889 },
  { 434, 2, 96, 3, 1889 },
  { 504, 2, 96, 3, 1889 },
  { 574, 2, 96, 3, 1889 },
  { 644, 2, 96, 3, 1889 },
  { 699, 2, 96, 3, 1889 },
  { 41, 2, 96, 3, 1889 },
  { 134, 2, 96, 3, 1889 },
  { 67, 116, 97, 13, 1809 },
  { 160, 116, 97, 13, 1809 },
  { 235, 116, 97, 13, 1809 },
  { 310, 116, 97, 13, 1809 },
  { 385, 116, 97, 13, 1809 },
  { 460, 116, 97, 13, 1809 },
  { 530, 116, 97, 13, 1809 },
  { 600, 116, 97, 13, 1809 },
  { 667, 116, 97, 13, 1809 },
  { 722, 116, 97, 13, 1809 },
  { 6, 116, 97, 13, 1809 },
  { 99, 116, 97, 13, 1809 },
  { 192, 116, 97, 13, 1809 },
  { 267, 116, 97, 13, 1809 },
  { 342, 116, 97, 13, 1809 },
  { 417, 116, 97, 13, 1809 },
  { 492, 116, 97, 13, 1809 },
  { 562, 116, 97, 13, 1809 },
  { 632, 116, 97, 13, 1809 },
  { 687, 116, 97, 13, 1809 },
  { 29, 116, 97, 13, 1809 },
  { 122, 116, 97, 13, 1809 },
  { 215, 116, 97, 13, 1809 },
  { 290, 116, 97, 13, 1809 },
  { 365, 116, 97, 13, 1809 },
  { 440, 116, 97, 13, 1809 },
  { 510, 116, 97, 13, 1809 },
  { 580, 116, 97, 13, 1809 },
  { 650, 116, 97, 13, 1809 },
  { 705, 116, 97, 13, 1809 },
  { 47, 116, 97, 13, 1809 },
  { 140, 116, 97, 13, 1809 },
  { 72, 115, 2, 12, 1777 },
  { 165, 115, 2, 12, 1777 },
  { 240, 115, 2, 12, 1777 },
  { 315, 115, 2, 12, 1777 },
  { 390, 115, 2, 12, 1777 },
  { 465, 115, 2, 12, 1777 },
  { 535, 115, 2, 12, 1777 },
  { 605, 115, 2, 12, 1777 },
  { 672, 115, 2, 12, 1777 },
  { 727, 115, 2, 12, 1777 },
  { 12, 115, 2, 12, 1777 },
  { 105, 115, 2, 12, 1777 },
  { 198, 115, 2, 12, 1777 },
  { 273, 115, 2, 12, 1777 },
  { 348, 115, 2, 12, 1777 },
  { 423, 115, 2, 12, 1777 },
  { 498, 115, 2, 12, 1777 },
  { 568, 115, 2, 12, 1777 },
  { 638, 115, 2, 12, 1777 },
  { 693, 115, 2, 12, 1777 },
  { 35, 115, 2, 12, 1777 },
  { 128, 115, 2, 12, 1777 },
  { 221, 115, 2, 12, 1777 },
  { 296, 115, 2, 12, 1777 },
  { 371, 115, 2, 12, 1777 },
  { 446, 115, 2, 12, 1777 },
  { 516, 115, 2, 12, 1777 },
  { 586, 115, 2, 12, 1777 },
  { 656, 115, 2, 12, 1777 },
  { 711, 115, 2, 12, 1777 },
  { 53, 115, 2, 12, 1777 },
  { 146, 115, 2, 12, 1777 },
  { 766, 2, 107, 3, 1681 },
  { 770, 2, 107, 3, 1681 },
  { 736, 2, 107, 3, 1681 },
  { 741, 2, 107, 3, 1681 },
  { 746, 2, 107, 3, 1681 },
  { 751, 2, 107, 3, 1681 },
  { 756, 2, 107, 3, 1681 },
  { 761, 2, 107, 3, 1681 },
  { 804, 121, 109, 1, 1649 },
  { 808, 121, 109, 1, 1649 },
  { 774, 121, 109, 1, 1649 },
  { 779, 121, 109, 1, 1649 },
  { 784, 121, 109, 1, 1649 },
  { 789, 121, 109, 1, 1649 },
  { 794, 121, 109, 1, 1649 },
  { 799, 121, 109, 1, 1649 },
  { 944, 122, 108, 2, 1617 },
  { 948, 122, 108, 2, 1617 },
  { 914, 122, 108, 2, 1617 },
  { 919, 122, 108, 2, 1617 },
  { 924, 122, 108, 2, 1617 },
  { 929, 122, 108, 2, 1617 },
  { 934, 122, 108, 2, 1617 },
  { 939, 122, 108, 2, 1617 },
};

  // GR8 Register Class...
  static const MCPhysReg GR8[] = {
    X86_AL, X86_CL, X86_DL, X86_AH, X86_CH, X86_DH, X86_BL, X86_BH, X86_SIL, X86_DIL, X86_BPL, X86_SPL, X86_R8B, X86_R9B, X86_R10B, X86_R11B, X86_R14B, X86_R15B, X86_R12B, X86_R13B, 
  };

  // GR8 Bit set.
  static const uint8_t GR8Bits[] = {
    0xb6, 0xa6, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 
  };

  // GR8_NOREX Register Class...
  static const MCPhysReg GR8_NOREX[] = {
    X86_AL, X86_CL, X86_DL, X86_AH, X86_CH, X86_DH, X86_BL, X86_BH, 
  };

  // GR8_NOREX Bit set.
  static const uint8_t GR8_NOREXBits[] = {
    0x36, 0x26, 0x01, 
  };

  // GR8_ABCD_H Register Class...
  static const MCPhysReg GR8_ABCD_H[] = {
    X86_AH, X86_CH, X86_DH, X86_BH, 
  };

  // GR8_ABCD_H Bit set.
  static const uint8_t GR8_ABCD_HBits[] = {
    0x12, 0x22, 
  };

  // GR8_ABCD_L Register Class...
  static const MCPhysReg GR8_ABCD_L[] = {
    X86_AL, X86_CL, X86_DL, X86_BL, 
  };

  // GR8_ABCD_L Bit set.
  static const uint8_t GR8_ABCD_LBits[] = {
    0x24, 0x04, 0x01, 
  };

  // GR16 Register Class...
  static const MCPhysReg GR16[] = {
    X86_AX, X86_CX, X86_DX, X86_SI, X86_DI, X86_BX, X86_BP, X86_SP, X86_R8W, X86_R9W, X86_R10W, X86_R11W, X86_R14W, X86_R15W, X86_R12W, X86_R13W, 
  };

  // GR16 Bit set.
  static const uint8_t GR16Bits[] = {
    0x48, 0x51, 0x04, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 
  };

  // GR16_NOREX Register Class...
  static const MCPhysReg GR16_NOREX[] = {
    X86_AX, X86_CX, X86_DX, X86_SI, X86_DI, X86_BX, X86_BP, X86_SP, 
  };

  // GR16_NOREX Bit set.
  static const uint8_t GR16_NOREXBits[] = {
    0x48, 0x51, 0x04, 0x00, 0x00, 0xa0, 
  };

  // VK1 Register Class...
  static const MCPhysReg VK1[] = {
    X86_K0, X86_K1, X86_K2, X86_K3, X86_K4, X86_K5, X86_K6, X86_K7, 
  };

  // VK1 Bit set.
  static const uint8_t VK1Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 
  };

  // VK16 Register Class...
  static const MCPhysReg VK16[] = {
    X86_K0, X86_K1, X86_K2, X86_K3, X86_K4, X86_K5, X86_K6, X86_K7, 
  };

  // VK16 Bit set.
  static const uint8_t VK16Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 
  };

  // VK2 Register Class...
  static const MCPhysReg VK2[] = {
    X86_K0, X86_K1, X86_K2, X86_K3, X86_K4, X86_K5, X86_K6, X86_K7, 
  };

  // VK2 Bit set.
  static const uint8_t VK2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 
  };

  // VK4 Register Class...
  static const MCPhysReg VK4[] = {
    X86_K0, X86_K1, X86_K2, X86_K3, X86_K4, X86_K5, X86_K6, X86_K7, 
  };

  // VK4 Bit set.
  static const uint8_t VK4Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 
  };

  // VK8 Register Class...
  static const MCPhysReg VK8[] = {
    X86_K0, X86_K1, X86_K2, X86_K3, X86_K4, X86_K5, X86_K6, X86_K7, 
  };

  // VK8 Bit set.
  static const uint8_t VK8Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 
  };

  // VK16WM Register Class...
  static const MCPhysReg VK16WM[] = {
    X86_K1, X86_K2, X86_K3, X86_K4, X86_K5, X86_K6, X86_K7, 
  };

  // VK16WM Bit set.
  static const uint8_t VK16WMBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x03, 
  };

  // VK1WM Register Class...
  static const MCPhysReg VK1WM[] = {
    X86_K1, X86_K2, X86_K3, X86_K4, X86_K5, X86_K6, X86_K7, 
  };

  // VK1WM Bit set.
  static const uint8_t VK1WMBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x03, 
  };

  // VK2WM Register Class...
  static const MCPhysReg VK2WM[] = {
    X86_K1, X86_K2, X86_K3, X86_K4, X86_K5, X86_K6, X86_K7, 
  };

  // VK2WM Bit set.
  static const uint8_t VK2WMBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x03, 
  };

  // VK4WM Register Class...
  static const MCPhysReg VK4WM[] = {
    X86_K1, X86_K2, X86_K3, X86_K4, X86_K5, X86_K6, X86_K7, 
  };

  // VK4WM Bit set.
  static const uint8_t VK4WMBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x03, 
  };

  // VK8WM Register Class...
  static const MCPhysReg VK8WM[] = {
    X86_K1, X86_K2, X86_K3, X86_K4, X86_K5, X86_K6, X86_K7, 
  };

  // VK8WM Bit set.
  static const uint8_t VK8WMBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x03, 
  };

  // SEGMENT_REG Register Class...
  static const MCPhysReg SEGMENT_REG[] = {
    X86_CS, X86_DS, X86_SS, X86_ES, X86_FS, X86_GS, 
  };

  // SEGMENT_REG Bit set.
  static const uint8_t SEGMENT_REGBits[] = {
    0x00, 0x08, 0x02, 0x10, 0x03, 0x00, 0x02, 
  };

  // GR16_ABCD Register Class...
  static const MCPhysReg GR16_ABCD[] = {
    X86_AX, X86_CX, X86_DX, X86_BX, 
  };

  // GR16_ABCD Bit set.
  static const uint8_t GR16_ABCDBits[] = {
    0x08, 0x11, 0x04, 
  };

  // FPCCR Register Class...
  static const MCPhysReg FPCCR[] = {
    X86_FPSW, 
  };

  // FPCCR Bit set.
  static const uint8_t FPCCRBits[] = {
    0x00, 0x00, 0x00, 0x80, 
  };

  // FR32X Register Class...
  static const MCPhysReg FR32X[] = {
    X86_XMM0, X86_XMM1, X86_XMM2, X86_XMM3, X86_XMM4, X86_XMM5, X86_XMM6, X86_XMM7, X86_XMM8, X86_XMM9, X86_XMM10, X86_XMM11, X86_XMM12, X86_XMM13, X86_XMM14, X86_XMM15, X86_XMM16, X86_XMM17, X86_XMM18, X86_XMM19, X86_XMM20, X86_XMM21, X86_XMM22, X86_XMM23, X86_XMM24, X86_XMM25, X86_XMM26, X86_XMM27, X86_XMM28, X86_XMM29, X86_XMM30, X86_XMM31, 
  };

  // FR32X Bit set.
  static const uint8_t FR32XBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0xff, 0xff, 0xff, 0x03, 
  };

  // FR32 Register Class...
  static const MCPhysReg FR32[] = {
    X86_XMM0, X86_XMM1, X86_XMM2, X86_XMM3, X86_XMM4, X86_XMM5, X86_XMM6, X86_XMM7, X86_XMM8, X86_XMM9, X86_XMM10, X86_XMM11, X86_XMM12, X86_XMM13, X86_XMM14, X86_XMM15, 
  };

  // FR32 Bit set.
  static const uint8_t FR32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0xff, 0x03, 
  };

  // GR32 Register Class...
  static const MCPhysReg GR32[] = {
    X86_EAX, X86_ECX, X86_EDX, X86_ESI, X86_EDI, X86_EBX, X86_EBP, X86_ESP, X86_R8D, X86_R9D, X86_R10D, X86_R11D, X86_R14D, X86_R15D, X86_R12D, X86_R13D, 
  };

  // GR32 Bit set.
  static const uint8_t GR32Bits[] = {
    0x00, 0x00, 0xf8, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 
  };

  // GR32_NOAX Register Class...
  static const MCPhysReg GR32_NOAX[] = {
    X86_ECX, X86_EDX, X86_ESI, X86_EDI, X86_EBX, X86_EBP, X86_ESP, X86_R8D, X86_R9D, X86_R10D, X86_R11D, X86_R14D, X86_R15D, X86_R12D, X86_R13D, 
  };

  // GR32_NOAX Bit set.
  static const uint8_t GR32_NOAXBits[] = {
    0x00, 0x00, 0xf0, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 
  };

  // GR32_NOSP Register Class...
  static const MCPhysReg GR32_NOSP[] = {
    X86_EAX, X86_ECX, X86_EDX, X86_ESI, X86_EDI, X86_EBX, X86_EBP, X86_R8D, X86_R9D, X86_R10D, X86_R11D, X86_R14D, X86_R15D, X86_R12D, X86_R13D, 
  };

  // GR32_NOSP Bit set.
  static const uint8_t GR32_NOSPBits[] = {
    0x00, 0x00, 0xf8, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 
  };

  // GR32_NOAX_and_GR32_NOSP Register Class...
  static const MCPhysReg GR32_NOAX_and_GR32_NOSP[] = {
    X86_ECX, X86_EDX, X86_ESI, X86_EDI, X86_EBX, X86_EBP, X86_R8D, X86_R9D, X86_R10D, X86_R11D, X86_R14D, X86_R15D, X86_R12D, X86_R13D, 
  };

  // GR32_NOAX_and_GR32_NOSP Bit set.
  static const uint8_t GR32_NOAX_and_GR32_NOSPBits[] = {
    0x00, 0x00, 0xf0, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 
  };

  // DEBUG_REG Register Class...
  static const MCPhysReg DEBUG_REG[] = {
    X86_DR0, X86_DR1, X86_DR2, X86_DR3, X86_DR4, X86_DR5, X86_DR6, X86_DR7, 
  };

  // DEBUG_REG Bit set.
  static const uint8_t DEBUG_REGBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 
  };

  // GR32_NOREX Register Class...
  static const MCPhysReg GR32_NOREX[] = {
    X86_EAX, X86_ECX, X86_EDX, X86_ESI, X86_EDI, X86_EBX, X86_EBP, X86_ESP, 
  };

  // GR32_NOREX Bit set.
  static const uint8_t GR32_NOREXBits[] = {
    0x00, 0x00, 0xf8, 0x61, 
  };

  // VK32 Register Class...
  static const MCPhysReg VK32[] = {
    X86_K0, X86_K1, X86_K2, X86_K3, X86_K4, X86_K5, X86_K6, X86_K7, 
  };

  // VK32 Bit set.
  static const uint8_t VK32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 
  };

  // GR32_NOAX_and_GR32_NOREX Register Class...
  static const MCPhysReg GR32_NOAX_and_GR32_NOREX[] = {
    X86_ECX, X86_EDX, X86_ESI, X86_EDI, X86_EBX, X86_EBP, X86_ESP, 
  };

  // GR32_NOAX_and_GR32_NOREX Bit set.
  static const uint8_t GR32_NOAX_and_GR32_NOREXBits[] = {
    0x00, 0x00, 0xf0, 0x61, 
  };

  // GR32_NOREX_NOSP Register Class...
  static const MCPhysReg GR32_NOREX_NOSP[] = {
    X86_EAX, X86_ECX, X86_EDX, X86_ESI, X86_EDI, X86_EBX, X86_EBP, 
  };

  // GR32_NOREX_NOSP Bit set.
  static const uint8_t GR32_NOREX_NOSPBits[] = {
    0x00, 0x00, 0xf8, 0x21, 
  };

  // RFP32 Register Class...
  static const MCPhysReg RFP32[] = {
    X86_FP0, X86_FP1, X86_FP2, X86_FP3, X86_FP4, X86_FP5, X86_FP6, 
  };

  // RFP32 Bit set.
  static const uint8_t RFP32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x01, 
  };

  // VK32WM Register Class...
  static const MCPhysReg VK32WM[] = {
    X86_K1, X86_K2, X86_K3, X86_K4, X86_K5, X86_K6, X86_K7, 
  };

  // VK32WM Bit set.
  static const uint8_t VK32WMBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x03, 
  };

  // GR32_NOAX_and_GR32_NOREX_NOSP Register Class...
  static const MCPhysReg GR32_NOAX_and_GR32_NOREX_NOSP[] = {
    X86_ECX, X86_EDX, X86_ESI, X86_EDI, X86_EBX, X86_EBP, 
  };

  // GR32_NOAX_and_GR32_NOREX_NOSP Bit set.
  static const uint8_t GR32_NOAX_and_GR32_NOREX_NOSPBits[] = {
    0x00, 0x00, 0xf0, 0x21, 
  };

  // GR32_ABCD Register Class...
  static const MCPhysReg GR32_ABCD[] = {
    X86_EAX, X86_ECX, X86_EDX, X86_EBX, 
  };

  // GR32_ABCD Bit set.
  static const uint8_t GR32_ABCDBits[] = {
    0x00, 0x00, 0x68, 0x01, 
  };

  // GR32_ABCD_and_GR32_NOAX Register Class...
  static const MCPhysReg GR32_ABCD_and_GR32_NOAX[] = {
    X86_ECX, X86_EDX, X86_EBX, 
  };

  // GR32_ABCD_and_GR32_NOAX Bit set.
  static const uint8_t GR32_ABCD_and_GR32_NOAXBits[] = {
    0x00, 0x00, 0x60, 0x01, 
  };

  // GR32_TC Register Class...
  static const MCPhysReg GR32_TC[] = {
    X86_EAX, X86_ECX, X86_EDX, 
  };

  // GR32_TC Bit set.
  static const uint8_t GR32_TCBits[] = {
    0x00, 0x00, 0x48, 0x01, 
  };

  // GR32_AD Register Class...
  static const MCPhysReg GR32_AD[] = {
    X86_EAX, X86_EDX, 
  };

  // GR32_AD Bit set.
  static const uint8_t GR32_ADBits[] = {
    0x00, 0x00, 0x08, 0x01, 
  };

  // GR32_NOAX_and_GR32_TC Register Class...
  static const MCPhysReg GR32_NOAX_and_GR32_TC[] = {
    X86_ECX, X86_EDX, 
  };

  // GR32_NOAX_and_GR32_TC Bit set.
  static const uint8_t GR32_NOAX_and_GR32_TCBits[] = {
    0x00, 0x00, 0x40, 0x01, 
  };

  // CCR Register Class...
  static const MCPhysReg CCR[] = {
    X86_EFLAGS, 
  };

  // CCR Bit set.
  static const uint8_t CCRBits[] = {
    0x00, 0x00, 0x00, 0x02, 
  };

  // GR32_AD_and_GR32_NOAX Register Class...
  static const MCPhysReg GR32_AD_and_GR32_NOAX[] = {
    X86_EDX, 
  };

  // GR32_AD_and_GR32_NOAX Bit set.
  static const uint8_t GR32_AD_and_GR32_NOAXBits[] = {
    0x00, 0x00, 0x00, 0x01, 
  };

  // RFP64 Register Class...
  static const MCPhysReg RFP64[] = {
    X86_FP0, X86_FP1, X86_FP2, X86_FP3, X86_FP4, X86_FP5, X86_FP6, 
  };

  // RFP64 Bit set.
  static const uint8_t RFP64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x01, 
  };

  // FR64X Register Class...
  static const MCPhysReg FR64X[] = {
    X86_XMM0, X86_XMM1, X86_XMM2, X86_XMM3, X86_XMM4, X86_XMM5, X86_XMM6, X86_XMM7, X86_XMM8, X86_XMM9, X86_XMM10, X86_XMM11, X86_XMM12, X86_XMM13, X86_XMM14, X86_XMM15, X86_XMM16, X86_XMM17, X86_XMM18, X86_XMM19, X86_XMM20, X86_XMM21, X86_XMM22, X86_XMM23, X86_XMM24, X86_XMM25, X86_XMM26, X86_XMM27, X86_XMM28, X86_XMM29, X86_XMM30, X86_XMM31, 
  };

  // FR64X Bit set.
  static const uint8_t FR64XBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0xff, 0xff, 0xff, 0x03, 
  };

  // GR64 Register Class...
  static const MCPhysReg GR64[] = {
    X86_RAX, X86_RCX, X86_RDX, X86_RSI, X86_RDI, X86_R8, X86_R9, X86_R10, X86_R11, X86_RBX, X86_R14, X86_R15, X86_R12, X86_R13, X86_RBP, X86_RSP, X86_RIP, 
  };

  // GR64 Bit set.
  static const uint8_t GR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0xf8, 0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 
  };

  // CONTROL_REG Register Class...
  static const MCPhysReg CONTROL_REG[] = {
    X86_CR0, X86_CR1, X86_CR2, X86_CR3, X86_CR4, X86_CR5, X86_CR6, X86_CR7, X86_CR8, X86_CR9, X86_CR10, X86_CR11, X86_CR12, X86_CR13, X86_CR14, X86_CR15, 
  };

  // CONTROL_REG Bit set.
  static const uint8_t CONTROL_REGBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0xff, 0x03, 
  };

  // FR64 Register Class...
  static const MCPhysReg FR64[] = {
    X86_XMM0, X86_XMM1, X86_XMM2, X86_XMM3, X86_XMM4, X86_XMM5, X86_XMM6, X86_XMM7, X86_XMM8, X86_XMM9, X86_XMM10, X86_XMM11, X86_XMM12, X86_XMM13, X86_XMM14, X86_XMM15, 
  };

  // FR64 Bit set.
  static const uint8_t FR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0xff, 0x03, 
  };

  // GR64_with_sub_8bit Register Class...
  static const MCPhysReg GR64_with_sub_8bit[] = {
    X86_RAX, X86_RCX, X86_RDX, X86_RSI, X86_RDI, X86_R8, X86_R9, X86_R10, X86_R11, X86_RBX, X86_R14, X86_R15, X86_R12, X86_R13, X86_RBP, X86_RSP, 
  };

  // GR64_with_sub_8bit Bit set.
  static const uint8_t GR64_with_sub_8bitBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xf8, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 
  };

  // GR64_NOSP Register Class...
  static const MCPhysReg GR64_NOSP[] = {
    X86_RAX, X86_RCX, X86_RDX, X86_RSI, X86_RDI, X86_R8, X86_R9, X86_R10, X86_R11, X86_RBX, X86_R14, X86_R15, X86_R12, X86_R13, X86_RBP, 
  };

  // GR64_NOSP Bit set.
  static const uint8_t GR64_NOSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xf8, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 
  };

  // GR64_with_sub_32bit_in_GR32_NOAX Register Class...
  static const MCPhysReg GR64_with_sub_32bit_in_GR32_NOAX[] = {
    X86_RCX, X86_RDX, X86_RSI, X86_RDI, X86_R8, X86_R9, X86_R10, X86_R11, X86_RBX, X86_R14, X86_R15, X86_R12, X86_R13, X86_RBP, X86_RSP, 
  };

  // GR64_with_sub_32bit_in_GR32_NOAX Bit set.
  static const uint8_t GR64_with_sub_32bit_in_GR32_NOAXBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xf0, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 
  };

  // GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOSP Register Class...
  static const MCPhysReg GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOSP[] = {
    X86_RCX, X86_RDX, X86_RSI, X86_RDI, X86_R8, X86_R9, X86_R10, X86_R11, X86_RBX, X86_R14, X86_R15, X86_R12, X86_R13, X86_RBP, 
  };

  // GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOSP Bit set.
  static const uint8_t GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xf0, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 
  };

  // GR64_NOREX Register Class...
  static const MCPhysReg GR64_NOREX[] = {
    X86_RAX, X86_RCX, X86_RDX, X86_RSI, X86_RDI, X86_RBX, X86_RBP, X86_RSP, X86_RIP, 
  };

  // GR64_NOREX Bit set.
  static const uint8_t GR64_NOREXBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xf8, 0x1b, 
  };

  // GR64_TC Register Class...
  static const MCPhysReg GR64_TC[] = {
    X86_RAX, X86_RCX, X86_RDX, X86_RSI, X86_RDI, X86_R8, X86_R9, X86_R11, X86_RIP, 
  };

  // GR64_TC Bit set.
  static const uint8_t GR64_TCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xc8, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 
  };

  // GR64_NOSP_and_GR64_TC Register Class...
  static const MCPhysReg GR64_NOSP_and_GR64_TC[] = {
    X86_RAX, X86_RCX, X86_RDX, X86_RSI, X86_RDI, X86_R8, X86_R9, X86_R11, 
  };

  // GR64_NOSP_and_GR64_TC Bit set.
  static const uint8_t GR64_NOSP_and_GR64_TCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xc8, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 
  };

  // GR64_with_sub_16bit_in_GR16_NOREX Register Class...
  static const MCPhysReg GR64_with_sub_16bit_in_GR16_NOREX[] = {
    X86_RAX, X86_RCX, X86_RDX, X86_RSI, X86_RDI, X86_RBX, X86_RBP, X86_RSP, 
  };

  // GR64_with_sub_16bit_in_GR16_NOREX Bit set.
  static const uint8_t GR64_with_sub_16bit_in_GR16_NOREXBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xf8, 0x19, 
  };

  // VK64 Register Class...
  static const MCPhysReg VK64[] = {
    X86_K0, X86_K1, X86_K2, X86_K3, X86_K4, X86_K5, X86_K6, X86_K7, 
  };

  // VK64 Bit set.
  static const uint8_t VK64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 
  };

  // VR64 Register Class...
  static const MCPhysReg VR64[] = {
    X86_MM0, X86_MM1, X86_MM2, X86_MM3, X86_MM4, X86_MM5, X86_MM6, X86_MM7, 
  };

  // VR64 Bit set.
  static const uint8_t VR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 
  };

  // GR64_NOREX_NOSP Register Class...
  static const MCPhysReg GR64_NOREX_NOSP[] = {
    X86_RAX, X86_RCX, X86_RDX, X86_RSI, X86_RDI, X86_RBX, X86_RBP, 
  };

  // GR64_NOREX_NOSP Bit set.
  static const uint8_t GR64_NOREX_NOSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xf8, 0x09, 
  };

  // GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX Register Class...
  static const MCPhysReg GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX[] = {
    X86_RCX, X86_RDX, X86_RSI, X86_RDI, X86_R8, X86_R9, X86_R11, 
  };

  // GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX Bit set.
  static const uint8_t GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAXBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xc0, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 
  };

  // GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX Register Class...
  static const MCPhysReg GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX[] = {
    X86_RCX, X86_RDX, X86_RSI, X86_RDI, X86_RBX, X86_RBP, X86_RSP, 
  };

  // GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX Bit set.
  static const uint8_t GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREXBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xf0, 0x19, 
  };

  // VK64WM Register Class...
  static const MCPhysReg VK64WM[] = {
    X86_K1, X86_K2, X86_K3, X86_K4, X86_K5, X86_K6, X86_K7, 
  };

  // VK64WM Bit set.
  static const uint8_t VK64WMBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x03, 
  };

  // GR64_NOREX_and_GR64_TC Register Class...
  static const MCPhysReg GR64_NOREX_and_GR64_TC[] = {
    X86_RAX, X86_RCX, X86_RDX, X86_RSI, X86_RDI, X86_RIP, 
  };

  // GR64_NOREX_and_GR64_TC Bit set.
  static const uint8_t GR64_NOREX_and_GR64_TCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xc8, 0x0b, 
  };

  // GR64_TCW64 Register Class...
  static const MCPhysReg GR64_TCW64[] = {
    X86_RAX, X86_RCX, X86_RDX, X86_R8, X86_R9, X86_R11, 
  };

  // GR64_TCW64 Bit set.
  static const uint8_t GR64_TCW64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x48, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 
  };

  // GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX_NOSP Register Class...
  static const MCPhysReg GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX_NOSP[] = {
    X86_RCX, X86_RDX, X86_RSI, X86_RDI, X86_RBX, X86_RBP, 
  };

  // GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX_NOSP Bit set.
  static const uint8_t GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX_NOSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xf0, 0x09, 
  };

  // GR64_NOREX_NOSP_and_GR64_TC Register Class...
  static const MCPhysReg GR64_NOREX_NOSP_and_GR64_TC[] = {
    X86_RAX, X86_RCX, X86_RDX, X86_RSI, X86_RDI, 
  };

  // GR64_NOREX_NOSP_and_GR64_TC Bit set.
  static const uint8_t GR64_NOREX_NOSP_and_GR64_TCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xc8, 0x09, 
  };

  // GR64_TCW64_and_GR64_with_sub_32bit_in_GR32_NOAX Register Class...
  static const MCPhysReg GR64_TCW64_and_GR64_with_sub_32bit_in_GR32_NOAX[] = {
    X86_RCX, X86_RDX, X86_R8, X86_R9, X86_R11, 
  };

  // GR64_TCW64_and_GR64_with_sub_32bit_in_GR32_NOAX Bit set.
  static const uint8_t GR64_TCW64_and_GR64_with_sub_32bit_in_GR32_NOAXBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2c, 
  };

  // GR64_ABCD Register Class...
  static const MCPhysReg GR64_ABCD[] = {
    X86_RAX, X86_RCX, X86_RDX, X86_RBX, 
  };

  // GR64_ABCD Bit set.
  static const uint8_t GR64_ABCDBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x68, 0x01, 
  };

  // GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX Register Class...
  static const MCPhysReg GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX[] = {
    X86_RCX, X86_RDX, X86_RSI, X86_RDI, 
  };

  // GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX Bit set.
  static const uint8_t GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREXBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xc0, 0x09, 
  };

  // GR64_with_sub_32bit_in_GR32_ABCD_and_GR32_NOAX Register Class...
  static const MCPhysReg GR64_with_sub_32bit_in_GR32_ABCD_and_GR32_NOAX[] = {
    X86_RCX, X86_RDX, X86_RBX, 
  };

  // GR64_with_sub_32bit_in_GR32_ABCD_and_GR32_NOAX Bit set.
  static const uint8_t GR64_with_sub_32bit_in_GR32_ABCD_and_GR32_NOAXBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x60, 0x01, 
  };

  // GR64_with_sub_32bit_in_GR32_TC Register Class...
  static const MCPhysReg GR64_with_sub_32bit_in_GR32_TC[] = {
    X86_RAX, X86_RCX, X86_RDX, 
  };

  // GR64_with_sub_32bit_in_GR32_TC Bit set.
  static const uint8_t GR64_with_sub_32bit_in_GR32_TCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x48, 0x01, 
  };

  // GR64_with_sub_32bit_in_GR32_AD Register Class...
  static const MCPhysReg GR64_with_sub_32bit_in_GR32_AD[] = {
    X86_RAX, X86_RDX, 
  };

  // GR64_with_sub_32bit_in_GR32_AD Bit set.
  static const uint8_t GR64_with_sub_32bit_in_GR32_ADBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x08, 0x01, 
  };

  // GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_TC Register Class...
  static const MCPhysReg GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_TC[] = {
    X86_RCX, X86_RDX, 
  };

  // GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_TC Bit set.
  static const uint8_t GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_TCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x40, 0x01, 
  };

  // GR64_with_sub_32bit_in_GR32_AD_and_GR32_NOAX Register Class...
  static const MCPhysReg GR64_with_sub_32bit_in_GR32_AD_and_GR32_NOAX[] = {
    X86_RDX, 
  };

  // GR64_with_sub_32bit_in_GR32_AD_and_GR32_NOAX Bit set.
  static const uint8_t GR64_with_sub_32bit_in_GR32_AD_and_GR32_NOAXBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
  };

  // RST Register Class...
  static const MCPhysReg RST[] = {
    X86_ST0, X86_ST1, X86_ST2, X86_ST3, X86_ST4, X86_ST5, X86_ST6, X86_ST7, 
  };

  // RST Bit set.
  static const uint8_t RSTBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x03, 
  };

  // RFP80 Register Class...
  static const MCPhysReg RFP80[] = {
    X86_FP0, X86_FP1, X86_FP2, X86_FP3, X86_FP4, X86_FP5, X86_FP6, 
  };

  // RFP80 Bit set.
  static const uint8_t RFP80Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0x01, 
  };

  // VR128X Register Class...
  static const MCPhysReg VR128X[] = {
    X86_XMM0, X86_XMM1, X86_XMM2, X86_XMM3, X86_XMM4, X86_XMM5, X86_XMM6, X86_XMM7, X86_XMM8, X86_XMM9, X86_XMM10, X86_XMM11, X86_XMM12, X86_XMM13, X86_XMM14, X86_XMM15, X86_XMM16, X86_XMM17, X86_XMM18, X86_XMM19, X86_XMM20, X86_XMM21, X86_XMM22, X86_XMM23, X86_XMM24, X86_XMM25, X86_XMM26, X86_XMM27, X86_XMM28, X86_XMM29, X86_XMM30, X86_XMM31, 
  };

  // VR128X Bit set.
  static const uint8_t VR128XBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0xff, 0xff, 0xff, 0x03, 
  };

  // VR128 Register Class...
  static const MCPhysReg VR128[] = {
    X86_XMM0, X86_XMM1, X86_XMM2, X86_XMM3, X86_XMM4, X86_XMM5, X86_XMM6, X86_XMM7, X86_XMM8, X86_XMM9, X86_XMM10, X86_XMM11, X86_XMM12, X86_XMM13, X86_XMM14, X86_XMM15, 
  };

  // VR128 Bit set.
  static const uint8_t VR128Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0xff, 0x03, 
  };

  // VR256X Register Class...
  static const MCPhysReg VR256X[] = {
    X86_YMM0, X86_YMM1, X86_YMM2, X86_YMM3, X86_YMM4, X86_YMM5, X86_YMM6, X86_YMM7, X86_YMM8, X86_YMM9, X86_YMM10, X86_YMM11, X86_YMM12, X86_YMM13, X86_YMM14, X86_YMM15, X86_YMM16, X86_YMM17, X86_YMM18, X86_YMM19, X86_YMM20, X86_YMM21, X86_YMM22, X86_YMM23, X86_YMM24, X86_YMM25, X86_YMM26, X86_YMM27, X86_YMM28, X86_YMM29, X86_YMM30, X86_YMM31, 
  };

  // VR256X Bit set.
  static const uint8_t VR256XBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0xff, 0xff, 0xff, 0x03, 
  };

  // VR256 Register Class...
  static const MCPhysReg VR256[] = {
    X86_YMM0, X86_YMM1, X86_YMM2, X86_YMM3, X86_YMM4, X86_YMM5, X86_YMM6, X86_YMM7, X86_YMM8, X86_YMM9, X86_YMM10, X86_YMM11, X86_YMM12, X86_YMM13, X86_YMM14, X86_YMM15, 
  };

  // VR256 Bit set.
  static const uint8_t VR256Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0xff, 0x03, 
  };

  // VR512 Register Class...
  static const MCPhysReg VR512[] = {
    X86_ZMM0, X86_ZMM1, X86_ZMM2, X86_ZMM3, X86_ZMM4, X86_ZMM5, X86_ZMM6, X86_ZMM7, X86_ZMM8, X86_ZMM9, X86_ZMM10, X86_ZMM11, X86_ZMM12, X86_ZMM13, X86_ZMM14, X86_ZMM15, X86_ZMM16, X86_ZMM17, X86_ZMM18, X86_ZMM19, X86_ZMM20, X86_ZMM21, X86_ZMM22, X86_ZMM23, X86_ZMM24, X86_ZMM25, X86_ZMM26, X86_ZMM27, X86_ZMM28, X86_ZMM29, X86_ZMM30, X86_ZMM31, 
  };

  // VR512 Bit set.
  static const uint8_t VR512Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0xff, 0xff, 0xff, 0x03, 
  };

  // VR512_with_sub_xmm_in_FR32 Register Class...
  static const MCPhysReg VR512_with_sub_xmm_in_FR32[] = {
    X86_ZMM0, X86_ZMM1, X86_ZMM2, X86_ZMM3, X86_ZMM4, X86_ZMM5, X86_ZMM6, X86_ZMM7, X86_ZMM8, X86_ZMM9, X86_ZMM10, X86_ZMM11, X86_ZMM12, X86_ZMM13, X86_ZMM14, X86_ZMM15, 
  };

  // VR512_with_sub_xmm_in_FR32 Bit set.
  static const uint8_t VR512_with_sub_xmm_in_FR32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfc, 0xff, 0x03, 
  };

#ifdef CAPSTONE_DIET
#define CAPSTONE_REGISTER_CLASS(x) NULL
#else
#define CAPSTONE_REGISTER_CLASS(x) x
#endif

static const MCRegisterClass X86MCRegisterClasses[] = {
  { CAPSTONE_REGISTER_CLASS("GR8"), GR8, GR8Bits, 20, sizeof(GR8Bits), X86_GR8RegClassID, 1, 1, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR8_NOREX"), GR8_NOREX, GR8_NOREXBits, 8, sizeof(GR8_NOREXBits), X86_GR8_NOREXRegClassID, 1, 1, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR8_ABCD_H"), GR8_ABCD_H, GR8_ABCD_HBits, 4, sizeof(GR8_ABCD_HBits), X86_GR8_ABCD_HRegClassID, 1, 1, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR8_ABCD_L"), GR8_ABCD_L, GR8_ABCD_LBits, 4, sizeof(GR8_ABCD_LBits), X86_GR8_ABCD_LRegClassID, 1, 1, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR16"), GR16, GR16Bits, 16, sizeof(GR16Bits), X86_GR16RegClassID, 2, 2, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR16_NOREX"), GR16_NOREX, GR16_NOREXBits, 8, sizeof(GR16_NOREXBits), X86_GR16_NOREXRegClassID, 2, 2, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("VK1"), VK1, VK1Bits, 8, sizeof(VK1Bits), X86_VK1RegClassID, 2, 2, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("VK16"), VK16, VK16Bits, 8, sizeof(VK16Bits), X86_VK16RegClassID, 2, 2, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("VK2"), VK2, VK2Bits, 8, sizeof(VK2Bits), X86_VK2RegClassID, 2, 2, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("VK4"), VK4, VK4Bits, 8, sizeof(VK4Bits), X86_VK4RegClassID, 2, 2, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("VK8"), VK8, VK8Bits, 8, sizeof(VK8Bits), X86_VK8RegClassID, 2, 2, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("VK16WM"), VK16WM, VK16WMBits, 7, sizeof(VK16WMBits), X86_VK16WMRegClassID, 2, 2, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("VK1WM"), VK1WM, VK1WMBits, 7, sizeof(VK1WMBits), X86_VK1WMRegClassID, 2, 2, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("VK2WM"), VK2WM, VK2WMBits, 7, sizeof(VK2WMBits), X86_VK2WMRegClassID, 2, 2, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("VK4WM"), VK4WM, VK4WMBits, 7, sizeof(VK4WMBits), X86_VK4WMRegClassID, 2, 2, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("VK8WM"), VK8WM, VK8WMBits, 7, sizeof(VK8WMBits), X86_VK8WMRegClassID, 2, 2, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("SEGMENT_REG"), SEGMENT_REG, SEGMENT_REGBits, 6, sizeof(SEGMENT_REGBits), X86_SEGMENT_REGRegClassID, 2, 2, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR16_ABCD"), GR16_ABCD, GR16_ABCDBits, 4, sizeof(GR16_ABCDBits), X86_GR16_ABCDRegClassID, 2, 2, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("FPCCR"), FPCCR, FPCCRBits, 1, sizeof(FPCCRBits), X86_FPCCRRegClassID, 2, 2, -1, 0 },
  { CAPSTONE_REGISTER_CLASS("FR32X"), FR32X, FR32XBits, 32, sizeof(FR32XBits), X86_FR32XRegClassID, 4, 4, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("FR32"), FR32, FR32Bits, 16, sizeof(FR32Bits), X86_FR32RegClassID, 4, 4, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR32"), GR32, GR32Bits, 16, sizeof(GR32Bits), X86_GR32RegClassID, 4, 4, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR32_NOAX"), GR32_NOAX, GR32_NOAXBits, 15, sizeof(GR32_NOAXBits), X86_GR32_NOAXRegClassID, 4, 4, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR32_NOSP"), GR32_NOSP, GR32_NOSPBits, 15, sizeof(GR32_NOSPBits), X86_GR32_NOSPRegClassID, 4, 4, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR32_NOAX_and_GR32_NOSP"), GR32_NOAX_and_GR32_NOSP, GR32_NOAX_and_GR32_NOSPBits, 14, sizeof(GR32_NOAX_and_GR32_NOSPBits), X86_GR32_NOAX_and_GR32_NOSPRegClassID, 4, 4, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("DEBUG_REG"), DEBUG_REG, DEBUG_REGBits, 8, sizeof(DEBUG_REGBits), X86_DEBUG_REGRegClassID, 4, 4, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR32_NOREX"), GR32_NOREX, GR32_NOREXBits, 8, sizeof(GR32_NOREXBits), X86_GR32_NOREXRegClassID, 4, 4, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("VK32"), VK32, VK32Bits, 8, sizeof(VK32Bits), X86_VK32RegClassID, 4, 4, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR32_NOAX_and_GR32_NOREX"), GR32_NOAX_and_GR32_NOREX, GR32_NOAX_and_GR32_NOREXBits, 7, sizeof(GR32_NOAX_and_GR32_NOREXBits), X86_GR32_NOAX_and_GR32_NOREXRegClassID, 4, 4, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR32_NOREX_NOSP"), GR32_NOREX_NOSP, GR32_NOREX_NOSPBits, 7, sizeof(GR32_NOREX_NOSPBits), X86_GR32_NOREX_NOSPRegClassID, 4, 4, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("RFP32"), RFP32, RFP32Bits, 7, sizeof(RFP32Bits), X86_RFP32RegClassID, 4, 4, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("VK32WM"), VK32WM, VK32WMBits, 7, sizeof(VK32WMBits), X86_VK32WMRegClassID, 4, 4, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR32_NOAX_and_GR32_NOREX_NOSP"), GR32_NOAX_and_GR32_NOREX_NOSP, GR32_NOAX_and_GR32_NOREX_NOSPBits, 6, sizeof(GR32_NOAX_and_GR32_NOREX_NOSPBits), X86_GR32_NOAX_and_GR32_NOREX_NOSPRegClassID, 4, 4, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR32_ABCD"), GR32_ABCD, GR32_ABCDBits, 4, sizeof(GR32_ABCDBits), X86_GR32_ABCDRegClassID, 4, 4, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR32_ABCD_and_GR32_NOAX"), GR32_ABCD_and_GR32_NOAX, GR32_ABCD_and_GR32_NOAXBits, 3, sizeof(GR32_ABCD_and_GR32_NOAXBits), X86_GR32_ABCD_and_GR32_NOAXRegClassID, 4, 4, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR32_TC"), GR32_TC, GR32_TCBits, 3, sizeof(GR32_TCBits), X86_GR32_TCRegClassID, 4, 4, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR32_AD"), GR32_AD, GR32_ADBits, 2, sizeof(GR32_ADBits), X86_GR32_ADRegClassID, 4, 4, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR32_NOAX_and_GR32_TC"), GR32_NOAX_and_GR32_TC, GR32_NOAX_and_GR32_TCBits, 2, sizeof(GR32_NOAX_and_GR32_TCBits), X86_GR32_NOAX_and_GR32_TCRegClassID, 4, 4, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("CCR"), CCR, CCRBits, 1, sizeof(CCRBits), X86_CCRRegClassID, 4, 4, -1, 0 },
  { CAPSTONE_REGISTER_CLASS("GR32_AD_and_GR32_NOAX"), GR32_AD_and_GR32_NOAX, GR32_AD_and_GR32_NOAXBits, 1, sizeof(GR32_AD_and_GR32_NOAXBits), X86_GR32_AD_and_GR32_NOAXRegClassID, 4, 4, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("RFP64"), RFP64, RFP64Bits, 7, sizeof(RFP64Bits), X86_RFP64RegClassID, 8, 4, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("FR64X"), FR64X, FR64XBits, 32, sizeof(FR64XBits), X86_FR64XRegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR64"), GR64, GR64Bits, 17, sizeof(GR64Bits), X86_GR64RegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("CONTROL_REG"), CONTROL_REG, CONTROL_REGBits, 16, sizeof(CONTROL_REGBits), X86_CONTROL_REGRegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("FR64"), FR64, FR64Bits, 16, sizeof(FR64Bits), X86_FR64RegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR64_with_sub_8bit"), GR64_with_sub_8bit, GR64_with_sub_8bitBits, 16, sizeof(GR64_with_sub_8bitBits), X86_GR64_with_sub_8bitRegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR64_NOSP"), GR64_NOSP, GR64_NOSPBits, 15, sizeof(GR64_NOSPBits), X86_GR64_NOSPRegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR64_with_sub_32bit_in_GR32_NOAX"), GR64_with_sub_32bit_in_GR32_NOAX, GR64_with_sub_32bit_in_GR32_NOAXBits, 15, sizeof(GR64_with_sub_32bit_in_GR32_NOAXBits), X86_GR64_with_sub_32bit_in_GR32_NOAXRegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOSP"), GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOSP, GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOSPBits, 14, sizeof(GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOSPBits), X86_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOSPRegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR64_NOREX"), GR64_NOREX, GR64_NOREXBits, 9, sizeof(GR64_NOREXBits), X86_GR64_NOREXRegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR64_TC"), GR64_TC, GR64_TCBits, 9, sizeof(GR64_TCBits), X86_GR64_TCRegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR64_NOSP_and_GR64_TC"), GR64_NOSP_and_GR64_TC, GR64_NOSP_and_GR64_TCBits, 8, sizeof(GR64_NOSP_and_GR64_TCBits), X86_GR64_NOSP_and_GR64_TCRegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR64_with_sub_16bit_in_GR16_NOREX"), GR64_with_sub_16bit_in_GR16_NOREX, GR64_with_sub_16bit_in_GR16_NOREXBits, 8, sizeof(GR64_with_sub_16bit_in_GR16_NOREXBits), X86_GR64_with_sub_16bit_in_GR16_NOREXRegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("VK64"), VK64, VK64Bits, 8, sizeof(VK64Bits), X86_VK64RegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("VR64"), VR64, VR64Bits, 8, sizeof(VR64Bits), X86_VR64RegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR64_NOREX_NOSP"), GR64_NOREX_NOSP, GR64_NOREX_NOSPBits, 7, sizeof(GR64_NOREX_NOSPBits), X86_GR64_NOREX_NOSPRegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX"), GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX, GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAXBits, 7, sizeof(GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAXBits), X86_GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAXRegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX"), GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX, GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREXBits, 7, sizeof(GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREXBits), X86_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREXRegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("VK64WM"), VK64WM, VK64WMBits, 7, sizeof(VK64WMBits), X86_VK64WMRegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR64_NOREX_and_GR64_TC"), GR64_NOREX_and_GR64_TC, GR64_NOREX_and_GR64_TCBits, 6, sizeof(GR64_NOREX_and_GR64_TCBits), X86_GR64_NOREX_and_GR64_TCRegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR64_TCW64"), GR64_TCW64, GR64_TCW64Bits, 6, sizeof(GR64_TCW64Bits), X86_GR64_TCW64RegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX_NOSP"), GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX_NOSP, GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX_NOSPBits, 6, sizeof(GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX_NOSPBits), X86_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX_NOSPRegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR64_NOREX_NOSP_and_GR64_TC"), GR64_NOREX_NOSP_and_GR64_TC, GR64_NOREX_NOSP_and_GR64_TCBits, 5, sizeof(GR64_NOREX_NOSP_and_GR64_TCBits), X86_GR64_NOREX_NOSP_and_GR64_TCRegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR64_TCW64_and_GR64_with_sub_32bit_in_GR32_NOAX"), GR64_TCW64_and_GR64_with_sub_32bit_in_GR32_NOAX, GR64_TCW64_and_GR64_with_sub_32bit_in_GR32_NOAXBits, 5, sizeof(GR64_TCW64_and_GR64_with_sub_32bit_in_GR32_NOAXBits), X86_GR64_TCW64_and_GR64_with_sub_32bit_in_GR32_NOAXRegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR64_ABCD"), GR64_ABCD, GR64_ABCDBits, 4, sizeof(GR64_ABCDBits), X86_GR64_ABCDRegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX"), GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREX, GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREXBits, 4, sizeof(GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREXBits), X86_GR64_TC_and_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_NOREXRegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR64_with_sub_32bit_in_GR32_ABCD_and_GR32_NOAX"), GR64_with_sub_32bit_in_GR32_ABCD_and_GR32_NOAX, GR64_with_sub_32bit_in_GR32_ABCD_and_GR32_NOAXBits, 3, sizeof(GR64_with_sub_32bit_in_GR32_ABCD_and_GR32_NOAXBits), X86_GR64_with_sub_32bit_in_GR32_ABCD_and_GR32_NOAXRegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR64_with_sub_32bit_in_GR32_TC"), GR64_with_sub_32bit_in_GR32_TC, GR64_with_sub_32bit_in_GR32_TCBits, 3, sizeof(GR64_with_sub_32bit_in_GR32_TCBits), X86_GR64_with_sub_32bit_in_GR32_TCRegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR64_with_sub_32bit_in_GR32_AD"), GR64_with_sub_32bit_in_GR32_AD, GR64_with_sub_32bit_in_GR32_ADBits, 2, sizeof(GR64_with_sub_32bit_in_GR32_ADBits), X86_GR64_with_sub_32bit_in_GR32_ADRegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_TC"), GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_TC, GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_TCBits, 2, sizeof(GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_TCBits), X86_GR64_with_sub_32bit_in_GR32_NOAX_and_GR32_TCRegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("GR64_with_sub_32bit_in_GR32_AD_and_GR32_NOAX"), GR64_with_sub_32bit_in_GR32_AD_and_GR32_NOAX, GR64_with_sub_32bit_in_GR32_AD_and_GR32_NOAXBits, 1, sizeof(GR64_with_sub_32bit_in_GR32_AD_and_GR32_NOAXBits), X86_GR64_with_sub_32bit_in_GR32_AD_and_GR32_NOAXRegClassID, 8, 8, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("RST"), RST, RSTBits, 8, sizeof(RSTBits), X86_RSTRegClassID, 10, 4, 1, 0 },
  { CAPSTONE_REGISTER_CLASS("RFP80"), RFP80, RFP80Bits, 7, sizeof(RFP80Bits), X86_RFP80RegClassID, 10, 4, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("VR128X"), VR128X, VR128XBits, 32, sizeof(VR128XBits), X86_VR128XRegClassID, 16, 16, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("VR128"), VR128, VR128Bits, 16, sizeof(VR128Bits), X86_VR128RegClassID, 16, 16, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("VR256X"), VR256X, VR256XBits, 32, sizeof(VR256XBits), X86_VR256XRegClassID, 32, 32, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("VR256"), VR256, VR256Bits, 16, sizeof(VR256Bits), X86_VR256RegClassID, 32, 32, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("VR512"), VR512, VR512Bits, 32, sizeof(VR512Bits), X86_VR512RegClassID, 64, 64, 1, 1 },
  { CAPSTONE_REGISTER_CLASS("VR512_with_sub_xmm_in_FR32"), VR512_with_sub_xmm_in_FR32, VR512_with_sub_xmm_in_FR32Bits, 16, sizeof(VR512_with_sub_xmm_in_FR32Bits), X86_VR512_with_sub_xmm_in_FR32RegClassID, 64, 64, 1, 1 },
};

#endif // GET_REGINFO_MC_DESC

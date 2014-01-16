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
  Mips_COP210 = 41,
  Mips_COP211 = 42,
  Mips_COP212 = 43,
  Mips_COP213 = 44,
  Mips_COP214 = 45,
  Mips_COP215 = 46,
  Mips_COP216 = 47,
  Mips_COP217 = 48,
  Mips_COP218 = 49,
  Mips_COP219 = 50,
  Mips_COP220 = 51,
  Mips_COP221 = 52,
  Mips_COP222 = 53,
  Mips_COP223 = 54,
  Mips_COP224 = 55,
  Mips_COP225 = 56,
  Mips_COP226 = 57,
  Mips_COP227 = 58,
  Mips_COP228 = 59,
  Mips_COP229 = 60,
  Mips_COP230 = 61,
  Mips_COP231 = 62,
  Mips_D0 = 63,
  Mips_D1 = 64,
  Mips_D2 = 65,
  Mips_D3 = 66,
  Mips_D4 = 67,
  Mips_D5 = 68,
  Mips_D6 = 69,
  Mips_D7 = 70,
  Mips_D8 = 71,
  Mips_D9 = 72,
  Mips_D10 = 73,
  Mips_D11 = 74,
  Mips_D12 = 75,
  Mips_D13 = 76,
  Mips_D14 = 77,
  Mips_D15 = 78,
  Mips_DSPOutFlag20 = 79,
  Mips_DSPOutFlag21 = 80,
  Mips_DSPOutFlag22 = 81,
  Mips_DSPOutFlag23 = 82,
  Mips_F0 = 83,
  Mips_F1 = 84,
  Mips_F2 = 85,
  Mips_F3 = 86,
  Mips_F4 = 87,
  Mips_F5 = 88,
  Mips_F6 = 89,
  Mips_F7 = 90,
  Mips_F8 = 91,
  Mips_F9 = 92,
  Mips_F10 = 93,
  Mips_F11 = 94,
  Mips_F12 = 95,
  Mips_F13 = 96,
  Mips_F14 = 97,
  Mips_F15 = 98,
  Mips_F16 = 99,
  Mips_F17 = 100,
  Mips_F18 = 101,
  Mips_F19 = 102,
  Mips_F20 = 103,
  Mips_F21 = 104,
  Mips_F22 = 105,
  Mips_F23 = 106,
  Mips_F24 = 107,
  Mips_F25 = 108,
  Mips_F26 = 109,
  Mips_F27 = 110,
  Mips_F28 = 111,
  Mips_F29 = 112,
  Mips_F30 = 113,
  Mips_F31 = 114,
  Mips_FCC0 = 115,
  Mips_FCC1 = 116,
  Mips_FCC2 = 117,
  Mips_FCC3 = 118,
  Mips_FCC4 = 119,
  Mips_FCC5 = 120,
  Mips_FCC6 = 121,
  Mips_FCC7 = 122,
  Mips_FCR0 = 123,
  Mips_FCR1 = 124,
  Mips_FCR2 = 125,
  Mips_FCR3 = 126,
  Mips_FCR4 = 127,
  Mips_FCR5 = 128,
  Mips_FCR6 = 129,
  Mips_FCR7 = 130,
  Mips_FCR8 = 131,
  Mips_FCR9 = 132,
  Mips_FCR10 = 133,
  Mips_FCR11 = 134,
  Mips_FCR12 = 135,
  Mips_FCR13 = 136,
  Mips_FCR14 = 137,
  Mips_FCR15 = 138,
  Mips_FCR16 = 139,
  Mips_FCR17 = 140,
  Mips_FCR18 = 141,
  Mips_FCR19 = 142,
  Mips_FCR20 = 143,
  Mips_FCR21 = 144,
  Mips_FCR22 = 145,
  Mips_FCR23 = 146,
  Mips_FCR24 = 147,
  Mips_FCR25 = 148,
  Mips_FCR26 = 149,
  Mips_FCR27 = 150,
  Mips_FCR28 = 151,
  Mips_FCR29 = 152,
  Mips_FCR30 = 153,
  Mips_FCR31 = 154,
  Mips_FP_64 = 155,
  Mips_F_HI0 = 156,
  Mips_F_HI1 = 157,
  Mips_F_HI2 = 158,
  Mips_F_HI3 = 159,
  Mips_F_HI4 = 160,
  Mips_F_HI5 = 161,
  Mips_F_HI6 = 162,
  Mips_F_HI7 = 163,
  Mips_F_HI8 = 164,
  Mips_F_HI9 = 165,
  Mips_F_HI10 = 166,
  Mips_F_HI11 = 167,
  Mips_F_HI12 = 168,
  Mips_F_HI13 = 169,
  Mips_F_HI14 = 170,
  Mips_F_HI15 = 171,
  Mips_F_HI16 = 172,
  Mips_F_HI17 = 173,
  Mips_F_HI18 = 174,
  Mips_F_HI19 = 175,
  Mips_F_HI20 = 176,
  Mips_F_HI21 = 177,
  Mips_F_HI22 = 178,
  Mips_F_HI23 = 179,
  Mips_F_HI24 = 180,
  Mips_F_HI25 = 181,
  Mips_F_HI26 = 182,
  Mips_F_HI27 = 183,
  Mips_F_HI28 = 184,
  Mips_F_HI29 = 185,
  Mips_F_HI30 = 186,
  Mips_F_HI31 = 187,
  Mips_GP_64 = 188,
  Mips_HI0 = 189,
  Mips_HI1 = 190,
  Mips_HI2 = 191,
  Mips_HI3 = 192,
  Mips_HWR29 = 193,
  Mips_K0 = 194,
  Mips_K1 = 195,
  Mips_LO0 = 196,
  Mips_LO1 = 197,
  Mips_LO2 = 198,
  Mips_LO3 = 199,
  Mips_RA_64 = 200,
  Mips_S0 = 201,
  Mips_S1 = 202,
  Mips_S2 = 203,
  Mips_S3 = 204,
  Mips_S4 = 205,
  Mips_S5 = 206,
  Mips_S6 = 207,
  Mips_S7 = 208,
  Mips_SP_64 = 209,
  Mips_T0 = 210,
  Mips_T1 = 211,
  Mips_T2 = 212,
  Mips_T3 = 213,
  Mips_T4 = 214,
  Mips_T5 = 215,
  Mips_T6 = 216,
  Mips_T7 = 217,
  Mips_T8 = 218,
  Mips_T9 = 219,
  Mips_V0 = 220,
  Mips_V1 = 221,
  Mips_W0 = 222,
  Mips_W1 = 223,
  Mips_W2 = 224,
  Mips_W3 = 225,
  Mips_W4 = 226,
  Mips_W5 = 227,
  Mips_W6 = 228,
  Mips_W7 = 229,
  Mips_W8 = 230,
  Mips_W9 = 231,
  Mips_W10 = 232,
  Mips_W11 = 233,
  Mips_W12 = 234,
  Mips_W13 = 235,
  Mips_W14 = 236,
  Mips_W15 = 237,
  Mips_W16 = 238,
  Mips_W17 = 239,
  Mips_W18 = 240,
  Mips_W19 = 241,
  Mips_W20 = 242,
  Mips_W21 = 243,
  Mips_W22 = 244,
  Mips_W23 = 245,
  Mips_W24 = 246,
  Mips_W25 = 247,
  Mips_W26 = 248,
  Mips_W27 = 249,
  Mips_W28 = 250,
  Mips_W29 = 251,
  Mips_W30 = 252,
  Mips_W31 = 253,
  Mips_ZERO_64 = 254,
  Mips_A0_64 = 255,
  Mips_A1_64 = 256,
  Mips_A2_64 = 257,
  Mips_A3_64 = 258,
  Mips_AC0_64 = 259,
  Mips_D0_64 = 260,
  Mips_D1_64 = 261,
  Mips_D2_64 = 262,
  Mips_D3_64 = 263,
  Mips_D4_64 = 264,
  Mips_D5_64 = 265,
  Mips_D6_64 = 266,
  Mips_D7_64 = 267,
  Mips_D8_64 = 268,
  Mips_D9_64 = 269,
  Mips_D10_64 = 270,
  Mips_D11_64 = 271,
  Mips_D12_64 = 272,
  Mips_D13_64 = 273,
  Mips_D14_64 = 274,
  Mips_D15_64 = 275,
  Mips_D16_64 = 276,
  Mips_D17_64 = 277,
  Mips_D18_64 = 278,
  Mips_D19_64 = 279,
  Mips_D20_64 = 280,
  Mips_D21_64 = 281,
  Mips_D22_64 = 282,
  Mips_D23_64 = 283,
  Mips_D24_64 = 284,
  Mips_D25_64 = 285,
  Mips_D26_64 = 286,
  Mips_D27_64 = 287,
  Mips_D28_64 = 288,
  Mips_D29_64 = 289,
  Mips_D30_64 = 290,
  Mips_D31_64 = 291,
  Mips_DSPOutFlag16_19 = 292,
  Mips_HI0_64 = 293,
  Mips_K0_64 = 294,
  Mips_K1_64 = 295,
  Mips_LO0_64 = 296,
  Mips_S0_64 = 297,
  Mips_S1_64 = 298,
  Mips_S2_64 = 299,
  Mips_S3_64 = 300,
  Mips_S4_64 = 301,
  Mips_S5_64 = 302,
  Mips_S6_64 = 303,
  Mips_S7_64 = 304,
  Mips_T0_64 = 305,
  Mips_T1_64 = 306,
  Mips_T2_64 = 307,
  Mips_T3_64 = 308,
  Mips_T4_64 = 309,
  Mips_T5_64 = 310,
  Mips_T6_64 = 311,
  Mips_T7_64 = 312,
  Mips_T8_64 = 313,
  Mips_T9_64 = 314,
  Mips_V0_64 = 315,
  Mips_V1_64 = 316,
  Mips_NUM_TARGET_REGS 	// 317
};

// Register classes
enum {
  Mips_CCRRegClassID = 0,
  Mips_COP2RegClassID = 1,
  Mips_DSPRRegClassID = 2,
  Mips_FGR32RegClassID = 3,
  Mips_FGRH32RegClassID = 4,
  Mips_GPR32RegClassID = 5,
  Mips_CPU16RegsPlusSPRegClassID = 6,
  Mips_CPU16RegsRegClassID = 7,
  Mips_FCCRegClassID = 8,
  Mips_MSACtrlRegClassID = 9,
  Mips_HI32DSPRegClassID = 10,
  Mips_LO32DSPRegClassID = 11,
  Mips_CPURARegRegClassID = 12,
  Mips_CPUSPRegRegClassID = 13,
  Mips_DSPCCRegClassID = 14,
  Mips_HI32RegClassID = 15,
  Mips_HWRegsRegClassID = 16,
  Mips_LO32RegClassID = 17,
  Mips_FGR64RegClassID = 18,
  Mips_GPR64RegClassID = 19,
  Mips_AFGR64RegClassID = 20,
  Mips_GPR64_with_sub_32_in_CPU16RegsPlusSPRegClassID = 21,
  Mips_GPR64_with_sub_32_in_CPU16RegsRegClassID = 22,
  Mips_ACC64DSPRegClassID = 23,
  Mips_ACC64RegClassID = 24,
  Mips_GPR64_with_sub_32_in_CPURARegRegClassID = 25,
  Mips_GPR64_with_sub_32_in_CPUSPRegRegClassID = 26,
  Mips_HI64RegClassID = 27,
  Mips_LO64RegClassID = 28,
  Mips_MSA128BRegClassID = 29,
  Mips_MSA128DRegClassID = 30,
  Mips_MSA128HRegClassID = 31,
  Mips_MSA128WRegClassID = 32,
  Mips_ACC128RegClassID = 33
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
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */


#ifdef GET_REGINFO_MC_DESC
#undef GET_REGINFO_MC_DESC

static MCPhysReg MipsRegDiffLists[] = {
  /* 0 */ 0, 0,
  /* 2 */ 4, 1, 1, 1, 1, 0,
  /* 8 */ 287, 65323, 1, 1, 1, 0,
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
  /* 62 */ 65479, 1, 0,
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
  /* 86 */ 65345, 72, 0,
  /* 89 */ 65383, 72, 0,
  /* 92 */ 38, 65359, 73, 0,
  /* 96 */ 95, 0,
  /* 98 */ 96, 0,
  /* 100 */ 100, 0,
  /* 102 */ 147, 0,
  /* 104 */ 179, 0,
  /* 106 */ 181, 0,
  /* 108 */ 189, 0,
  /* 110 */ 233, 0,
  /* 112 */ 65173, 0,
  /* 114 */ 65188, 0,
  /* 116 */ 65249, 0,
  /* 118 */ 65303, 0,
  /* 120 */ 65306, 0,
  /* 122 */ 65347, 0,
  /* 124 */ 65355, 0,
  /* 126 */ 65357, 0,
  /* 128 */ 65366, 0,
  /* 130 */ 37, 65436, 97, 65432, 65373, 0,
  /* 136 */ 65389, 0,
  /* 138 */ 65415, 0,
  /* 140 */ 65416, 0,
  /* 142 */ 65432, 0,
  /* 144 */ 65436, 0,
  /* 146 */ 65440, 0,
  /* 148 */ 65441, 0,
  /* 150 */ 65459, 0,
  /* 152 */ 65460, 0,
  /* 154 */ 65461, 0,
  /* 156 */ 65462, 0,
  /* 158 */ 104, 65498, 0,
  /* 161 */ 65516, 197, 65498, 0,
  /* 165 */ 65515, 198, 65498, 0,
  /* 169 */ 65514, 199, 65498, 0,
  /* 173 */ 65513, 200, 65498, 0,
  /* 177 */ 65512, 201, 65498, 0,
  /* 181 */ 65511, 202, 65498, 0,
  /* 185 */ 65510, 203, 65498, 0,
  /* 189 */ 65509, 204, 65498, 0,
  /* 193 */ 65508, 205, 65498, 0,
  /* 197 */ 65507, 206, 65498, 0,
  /* 201 */ 65506, 207, 65498, 0,
  /* 205 */ 65505, 208, 65498, 0,
  /* 209 */ 65504, 209, 65498, 0,
  /* 213 */ 65503, 210, 65498, 0,
  /* 217 */ 65502, 211, 65498, 0,
  /* 221 */ 65501, 212, 65498, 0,
  /* 225 */ 65500, 213, 65498, 0,
  /* 229 */ 65366, 270, 65499, 0,
  /* 233 */ 65373, 267, 65502, 0,
  /* 237 */ 65507, 0,
  /* 239 */ 65510, 0,
  /* 241 */ 65511, 0,
  /* 243 */ 65516, 0,
  /* 245 */ 65521, 0,
  /* 247 */ 65522, 0,
  /* 249 */ 170, 65529, 0,
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
  { 1593, 1, 82, 1, 4033 },
  { 1596, 1, 1, 1, 4033 },
  { 1688, 1, 1, 1, 4033 },
  { 1559, 1, 1, 1, 4033 },
  { 1613, 8, 1, 2, 32 },
  { 1640, 1, 1, 1, 1089 },
  { 1657, 1, 1, 1, 1089 },
  { 1571, 1, 102, 1, 1089 },
  { 1574, 1, 104, 1, 1089 },
  { 1647, 1, 1, 1, 1089 },
  { 1586, 1, 1, 1, 1089 },
  { 1580, 1, 1, 1, 1089 },
  { 1624, 1, 1, 1, 1089 },
  { 1678, 1, 1, 1, 1089 },
  { 1667, 1, 1, 1, 1089 },
  { 1605, 1, 1, 1, 1089 },
  { 1631, 1, 1, 1, 1089 },
  { 1556, 1, 1, 1, 1089 },
  { 1553, 1, 106, 1, 1089 },
  { 1577, 1, 108, 1, 1089 },
  { 1566, 1, 110, 1, 1089 },
  { 107, 1, 110, 1, 1089 },
  { 262, 1, 110, 1, 1089 },
  { 389, 1, 110, 1, 1089 },
  { 510, 1, 110, 1, 1089 },
  { 110, 249, 110, 9, 1042 },
  { 265, 249, 1, 9, 1042 },
  { 392, 249, 1, 9, 1042 },
  { 513, 249, 1, 9, 1042 },
  { 1041, 237, 1, 0, 0 },
  { 50, 1, 1, 1, 1153 },
  { 205, 1, 1, 1, 1153 },
  { 360, 1, 1, 1, 1153 },
  { 481, 1, 1, 1, 1153 },
  { 602, 1, 1, 1, 1153 },
  { 1128, 1, 1, 1, 1153 },
  { 1221, 1, 1, 1, 1153 },
  { 1314, 1, 1, 1, 1153 },
  { 1407, 1, 1, 1, 1153 },
  { 1508, 1, 1, 1, 1153 },
  { 0, 1, 1, 1, 1153 },
  { 155, 1, 1, 1, 1153 },
  { 310, 1, 1, 1, 1153 },
  { 431, 1, 1, 1, 1153 },
  { 552, 1, 1, 1, 1153 },
  { 1078, 1, 1, 1, 1153 },
  { 1175, 1, 1, 1, 1153 },
  { 1268, 1, 1, 1, 1153 },
  { 1361, 1, 1, 1, 1153 },
  { 1446, 1, 1, 1, 1153 },
  { 32, 1, 1, 1, 1153 },
  { 187, 1, 1, 1, 1153 },
  { 342, 1, 1, 1, 1153 },
  { 463, 1, 1, 1, 1153 },
  { 584, 1, 1, 1, 1153 },
  { 1110, 1, 1, 1, 1153 },
  { 1203, 1, 1, 1, 1153 },
  { 1296, 1, 1, 1, 1153 },
  { 1389, 1, 1, 1, 1153 },
  { 1490, 1, 1, 1, 1153 },
  { 79, 1, 1, 1, 1153 },
  { 234, 1, 1, 1, 1153 },
  { 119, 14, 1, 9, 994 },
  { 274, 17, 1, 9, 994 },
  { 401, 20, 1, 9, 994 },
  { 522, 23, 1, 9, 994 },
  { 1052, 26, 1, 9, 994 },
  { 1149, 29, 1, 9, 994 },
  { 1242, 32, 1, 9, 994 },
  { 1335, 35, 1, 9, 994 },
  { 1423, 38, 1, 9, 994 },
  { 1530, 41, 1, 9, 994 },
  { 7, 44, 1, 9, 994 },
  { 162, 47, 1, 9, 994 },
  { 317, 50, 1, 9, 994 },
  { 438, 53, 1, 9, 994 },
  { 559, 56, 1, 9, 994 },
  { 1085, 59, 1, 9, 994 },
  { 66, 1, 156, 1, 2497 },
  { 221, 1, 154, 1, 2497 },
  { 376, 1, 152, 1, 2497 },
  { 497, 1, 150, 1, 2497 },
  { 122, 1, 161, 1, 3953 },
  { 277, 1, 165, 1, 3953 },
  { 404, 1, 165, 1, 3953 },
  { 525, 1, 169, 1, 3953 },
  { 1055, 1, 169, 1, 3953 },
  { 1152, 1, 173, 1, 3953 },
  { 1245, 1, 173, 1, 3953 },
  { 1338, 1, 177, 1, 3953 },
  { 1426, 1, 177, 1, 3953 },
  { 1533, 1, 181, 1, 3953 },
  { 11, 1, 181, 1, 3953 },
  { 166, 1, 185, 1, 3953 },
  { 321, 1, 185, 1, 3953 },
  { 442, 1, 189, 1, 3953 },
  { 563, 1, 189, 1, 3953 },
  { 1089, 1, 193, 1, 3953 },
  { 1182, 1, 193, 1, 3953 },
  { 1275, 1, 197, 1, 3953 },
  { 1368, 1, 197, 1, 3953 },
  { 1453, 1, 201, 1, 3953 },
  { 39, 1, 201, 1, 3953 },
  { 194, 1, 205, 1, 3953 },
  { 349, 1, 205, 1, 3953 },
  { 470, 1, 209, 1, 3953 },
  { 591, 1, 209, 1, 3953 },
  { 1117, 1, 213, 1, 3953 },
  { 1210, 1, 213, 1, 3953 },
  { 1303, 1, 217, 1, 3953 },
  { 1396, 1, 217, 1, 3953 },
  { 1497, 1, 221, 1, 3953 },
  { 86, 1, 221, 1, 3953 },
  { 241, 1, 225, 1, 3953 },
  { 114, 1, 1, 1, 3953 },
  { 269, 1, 1, 1, 3953 },
  { 396, 1, 1, 1, 3953 },
  { 517, 1, 1, 1, 3953 },
  { 1047, 1, 1, 1, 3953 },
  { 1144, 1, 1, 1, 3953 },
  { 1237, 1, 1, 1, 3953 },
  { 1330, 1, 1, 1, 3953 },
  { 138, 1, 1, 1, 3953 },
  { 293, 1, 1, 1, 3953 },
  { 417, 1, 1, 1, 3953 },
  { 538, 1, 1, 1, 3953 },
  { 1064, 1, 1, 1, 3953 },
  { 1161, 1, 1, 1, 3953 },
  { 1254, 1, 1, 1, 3953 },
  { 1347, 1, 1, 1, 3953 },
  { 1435, 1, 1, 1, 3953 },
  { 1542, 1, 1, 1, 3953 },
  { 22, 1, 1, 1, 3953 },
  { 177, 1, 1, 1, 3953 },
  { 332, 1, 1, 1, 3953 },
  { 453, 1, 1, 1, 3953 },
  { 574, 1, 1, 1, 3953 },
  { 1100, 1, 1, 1, 3953 },
  { 1193, 1, 1, 1, 3953 },
  { 1286, 1, 1, 1, 3953 },
  { 1379, 1, 1, 1, 3953 },
  { 1464, 1, 1, 1, 3953 },
  { 56, 1, 1, 1, 3953 },
  { 211, 1, 1, 1, 3953 },
  { 366, 1, 1, 1, 3953 },
  { 487, 1, 1, 1, 3953 },
  { 608, 1, 1, 1, 3953 },
  { 1134, 1, 1, 1, 3953 },
  { 1227, 1, 1, 1, 3953 },
  { 1320, 1, 1, 1, 3953 },
  { 1413, 1, 1, 1, 3953 },
  { 1514, 1, 1, 1, 3953 },
  { 97, 1, 1, 1, 3953 },
  { 252, 1, 1, 1, 3953 },
  { 1023, 136, 1, 0, 1184 },
  { 125, 1, 158, 1, 3921 },
  { 280, 1, 158, 1, 3921 },
  { 407, 1, 158, 1, 3921 },
  { 528, 1, 158, 1, 3921 },
  { 1058, 1, 158, 1, 3921 },
  { 1155, 1, 158, 1, 3921 },
  { 1248, 1, 158, 1, 3921 },
  { 1341, 1, 158, 1, 3921 },
  { 1429, 1, 158, 1, 3921 },
  { 1536, 1, 158, 1, 3921 },
  { 15, 1, 158, 1, 3921 },
  { 170, 1, 158, 1, 3921 },
  { 325, 1, 158, 1, 3921 },
  { 446, 1, 158, 1, 3921 },
  { 567, 1, 158, 1, 3921 },
  { 1093, 1, 158, 1, 3921 },
  { 1186, 1, 158, 1, 3921 },
  { 1279, 1, 158, 1, 3921 },
  { 1372, 1, 158, 1, 3921 },
  { 1457, 1, 158, 1, 3921 },
  { 43, 1, 158, 1, 3921 },
  { 198, 1, 158, 1, 3921 },
  { 353, 1, 158, 1, 3921 },
  { 474, 1, 158, 1, 3921 },
  { 595, 1, 158, 1, 3921 },
  { 1121, 1, 158, 1, 3921 },
  { 1214, 1, 158, 1, 3921 },
  { 1307, 1, 158, 1, 3921 },
  { 1400, 1, 158, 1, 3921 },
  { 1501, 1, 158, 1, 3921 },
  { 90, 1, 158, 1, 3921 },
  { 245, 1, 158, 1, 3921 },
  { 1029, 126, 1, 0, 1216 },
  { 127, 1, 233, 1, 1826 },
  { 282, 1, 134, 1, 1826 },
  { 409, 1, 134, 1, 1826 },
  { 530, 1, 134, 1, 1826 },
  { 1520, 1, 1, 1, 3889 },
  { 131, 1, 100, 1, 3889 },
  { 286, 1, 100, 1, 3889 },
  { 134, 1, 229, 1, 1794 },
  { 289, 1, 128, 1, 1794 },
  { 413, 1, 128, 1, 1794 },
  { 534, 1, 128, 1, 1794 },
  { 1009, 124, 1, 0, 1248 },
  { 143, 1, 98, 1, 3857 },
  { 298, 1, 98, 1, 3857 },
  { 422, 1, 98, 1, 3857 },
  { 543, 1, 98, 1, 3857 },
  { 1069, 1, 98, 1, 3857 },
  { 1166, 1, 98, 1, 3857 },
  { 1259, 1, 98, 1, 3857 },
  { 1352, 1, 98, 1, 3857 },
  { 1035, 122, 1, 0, 1280 },
  { 146, 1, 96, 1, 3825 },
  { 301, 1, 96, 1, 3825 },
  { 425, 1, 96, 1, 3825 },
  { 546, 1, 96, 1, 3825 },
  { 1072, 1, 96, 1, 3825 },
  { 1169, 1, 96, 1, 3825 },
  { 1262, 1, 96, 1, 3825 },
  { 1355, 1, 96, 1, 3825 },
  { 1440, 1, 96, 1, 3825 },
  { 1547, 1, 96, 1, 3825 },
  { 149, 1, 96, 1, 3825 },
  { 304, 1, 96, 1, 3825 },
  { 152, 92, 1, 8, 1425 },
  { 307, 92, 1, 8, 1425 },
  { 428, 92, 1, 8, 1425 },
  { 549, 92, 1, 8, 1425 },
  { 1075, 92, 1, 8, 1425 },
  { 1172, 92, 1, 8, 1425 },
  { 1265, 92, 1, 8, 1425 },
  { 1358, 92, 1, 8, 1425 },
  { 1443, 92, 1, 8, 1425 },
  { 1550, 92, 1, 8, 1425 },
  { 28, 92, 1, 8, 1425 },
  { 183, 92, 1, 8, 1425 },
  { 338, 92, 1, 8, 1425 },
  { 459, 92, 1, 8, 1425 },
  { 580, 92, 1, 8, 1425 },
  { 1106, 92, 1, 8, 1425 },
  { 1199, 92, 1, 8, 1425 },
  { 1292, 92, 1, 8, 1425 },
  { 1385, 92, 1, 8, 1425 },
  { 1470, 92, 1, 8, 1425 },
  { 62, 92, 1, 8, 1425 },
  { 217, 92, 1, 8, 1425 },
  { 372, 92, 1, 8, 1425 },
  { 493, 92, 1, 8, 1425 },
  { 614, 92, 1, 8, 1425 },
  { 1140, 92, 1, 8, 1425 },
  { 1233, 92, 1, 8, 1425 },
  { 1326, 92, 1, 8, 1425 },
  { 1419, 92, 1, 8, 1425 },
  { 1526, 92, 1, 8, 1425 },
  { 103, 92, 1, 8, 1425 },
  { 258, 92, 1, 8, 1425 },
  { 1015, 118, 1, 0, 1921 },
  { 639, 118, 1, 0, 1921 },
  { 717, 118, 1, 0, 1921 },
  { 767, 118, 1, 0, 1921 },
  { 805, 118, 1, 0, 1921 },
  { 645, 130, 1, 12, 656 },
  { 652, 93, 159, 9, 1377 },
  { 723, 93, 159, 9, 1377 },
  { 773, 93, 159, 9, 1377 },
  { 811, 93, 159, 9, 1377 },
  { 843, 93, 159, 9, 1377 },
  { 875, 93, 159, 9, 1377 },
  { 907, 93, 159, 9, 1377 },
  { 939, 93, 159, 9, 1377 },
  { 971, 93, 159, 9, 1377 },
  { 997, 93, 159, 9, 1377 },
  { 618, 93, 159, 9, 1377 },
  { 696, 93, 159, 9, 1377 },
  { 753, 93, 159, 9, 1377 },
  { 791, 93, 159, 9, 1377 },
  { 829, 93, 159, 9, 1377 },
  { 861, 93, 159, 9, 1377 },
  { 893, 93, 159, 9, 1377 },
  { 925, 93, 159, 9, 1377 },
  { 957, 93, 159, 9, 1377 },
  { 983, 93, 159, 9, 1377 },
  { 625, 93, 159, 9, 1377 },
  { 703, 93, 159, 9, 1377 },
  { 760, 93, 159, 9, 1377 },
  { 798, 93, 159, 9, 1377 },
  { 836, 93, 159, 9, 1377 },
  { 868, 93, 159, 9, 1377 },
  { 900, 93, 159, 9, 1377 },
  { 932, 93, 159, 9, 1377 },
  { 964, 93, 159, 9, 1377 },
  { 990, 93, 159, 9, 1377 },
  { 632, 93, 159, 9, 1377 },
  { 710, 93, 159, 9, 1377 },
  { 1474, 1, 116, 1, 1120 },
  { 658, 142, 235, 0, 1344 },
  { 665, 144, 1, 0, 2241 },
  { 729, 144, 1, 0, 2241 },
  { 671, 144, 231, 0, 1312 },
  { 678, 146, 1, 0, 2209 },
  { 735, 146, 1, 0, 2209 },
  { 779, 146, 1, 0, 2209 },
  { 817, 146, 1, 0, 2209 },
  { 849, 146, 1, 0, 2209 },
  { 881, 146, 1, 0, 2209 },
  { 913, 146, 1, 0, 2209 },
  { 945, 146, 1, 0, 2209 },
  { 684, 148, 1, 0, 2209 },
  { 741, 148, 1, 0, 2209 },
  { 785, 148, 1, 0, 2209 },
  { 823, 148, 1, 0, 2209 },
  { 855, 148, 1, 0, 2209 },
  { 887, 148, 1, 0, 2209 },
  { 919, 148, 1, 0, 2209 },
  { 951, 148, 1, 0, 2209 },
  { 977, 148, 1, 0, 2209 },
  { 1003, 148, 1, 0, 2209 },
  { 690, 148, 1, 0, 2209 },
  { 747, 148, 1, 0, 2209 },
};

  // CCR Register Class...
  static uint16_t CCR[] = {
    Mips_FCR0, Mips_FCR1, Mips_FCR2, Mips_FCR3, Mips_FCR4, Mips_FCR5, Mips_FCR6, Mips_FCR7, Mips_FCR8, Mips_FCR9, Mips_FCR10, Mips_FCR11, Mips_FCR12, Mips_FCR13, Mips_FCR14, Mips_FCR15, Mips_FCR16, Mips_FCR17, Mips_FCR18, Mips_FCR19, Mips_FCR20, Mips_FCR21, Mips_FCR22, Mips_FCR23, Mips_FCR24, Mips_FCR25, Mips_FCR26, Mips_FCR27, Mips_FCR28, Mips_FCR29, Mips_FCR30, Mips_FCR31, 
  };

  // CCR Bit set.
  static uint8_t CCRBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // COP2 Register Class...
  static uint16_t COP2[] = {
    Mips_COP20, Mips_COP21, Mips_COP22, Mips_COP23, Mips_COP24, Mips_COP25, Mips_COP26, Mips_COP27, Mips_COP28, Mips_COP29, Mips_COP210, Mips_COP211, Mips_COP212, Mips_COP213, Mips_COP214, Mips_COP215, Mips_COP216, Mips_COP217, Mips_COP218, Mips_COP219, Mips_COP220, Mips_COP221, Mips_COP222, Mips_COP223, Mips_COP224, Mips_COP225, Mips_COP226, Mips_COP227, Mips_COP228, Mips_COP229, Mips_COP230, Mips_COP231, 
  };

  // COP2 Bit set.
  static uint8_t COP2Bits[] = {
    0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0xff, 0x7f, 
  };

  // DSPR Register Class...
  static uint16_t DSPR[] = {
    Mips_ZERO, Mips_AT, Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, Mips_T0, Mips_T1, Mips_T2, Mips_T3, Mips_T4, Mips_T5, Mips_T6, Mips_T7, Mips_S0, Mips_S1, Mips_S2, Mips_S3, Mips_S4, Mips_S5, Mips_S6, Mips_S7, Mips_T8, Mips_T9, Mips_K0, Mips_K1, Mips_GP, Mips_SP, Mips_FP, Mips_RA, 
  };

  // DSPR Bit set.
  static uint8_t DSPRBits[] = {
    0x02, 0x03, 0xf8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0xfe, 0xfd, 0x3f, 
  };

  // FGR32 Register Class...
  static uint16_t FGR32[] = {
    Mips_F0, Mips_F1, Mips_F2, Mips_F3, Mips_F4, Mips_F5, Mips_F6, Mips_F7, Mips_F8, Mips_F9, Mips_F10, Mips_F11, Mips_F12, Mips_F13, Mips_F14, Mips_F15, Mips_F16, Mips_F17, Mips_F18, Mips_F19, Mips_F20, Mips_F21, Mips_F22, Mips_F23, Mips_F24, Mips_F25, Mips_F26, Mips_F27, Mips_F28, Mips_F29, Mips_F30, Mips_F31, 
  };

  // FGR32 Bit set.
  static uint8_t FGR32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0xff, 0xff, 0xff, 0x07, 
  };

  // FGRH32 Register Class...
  static uint16_t FGRH32[] = {
    Mips_F_HI0, Mips_F_HI1, Mips_F_HI2, Mips_F_HI3, Mips_F_HI4, Mips_F_HI5, Mips_F_HI6, Mips_F_HI7, Mips_F_HI8, Mips_F_HI9, Mips_F_HI10, Mips_F_HI11, Mips_F_HI12, Mips_F_HI13, Mips_F_HI14, Mips_F_HI15, Mips_F_HI16, Mips_F_HI17, Mips_F_HI18, Mips_F_HI19, Mips_F_HI20, Mips_F_HI21, Mips_F_HI22, Mips_F_HI23, Mips_F_HI24, Mips_F_HI25, Mips_F_HI26, Mips_F_HI27, Mips_F_HI28, Mips_F_HI29, Mips_F_HI30, Mips_F_HI31, 
  };

  // FGRH32 Bit set.
  static uint8_t FGRH32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // GPR32 Register Class...
  static uint16_t GPR32[] = {
    Mips_ZERO, Mips_AT, Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, Mips_T0, Mips_T1, Mips_T2, Mips_T3, Mips_T4, Mips_T5, Mips_T6, Mips_T7, Mips_S0, Mips_S1, Mips_S2, Mips_S3, Mips_S4, Mips_S5, Mips_S6, Mips_S7, Mips_T8, Mips_T9, Mips_K0, Mips_K1, Mips_GP, Mips_SP, Mips_FP, Mips_RA, 
  };

  // GPR32 Bit set.
  static uint8_t GPR32Bits[] = {
    0x02, 0x03, 0xf8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0xfe, 0xfd, 0x3f, 
  };

  // CPU16RegsPlusSP Register Class...
  static uint16_t CPU16RegsPlusSP[] = {
    Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, Mips_S0, Mips_S1, Mips_SP, 
  };

  // CPU16RegsPlusSP Bit set.
  static uint8_t CPU16RegsPlusSPBits[] = {
    0x00, 0x00, 0xd0, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x30, 
  };

  // CPU16Regs Register Class...
  static uint16_t CPU16Regs[] = {
    Mips_V0, Mips_V1, Mips_A0, Mips_A1, Mips_A2, Mips_A3, Mips_S0, Mips_S1, 
  };

  // CPU16Regs Bit set.
  static uint8_t CPU16RegsBits[] = {
    0x00, 0x00, 0xc0, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x30, 
  };

  // FCC Register Class...
  static uint16_t FCC[] = {
    Mips_FCC0, Mips_FCC1, Mips_FCC2, Mips_FCC3, Mips_FCC4, Mips_FCC5, Mips_FCC6, Mips_FCC7, 
  };

  // FCC Bit set.
  static uint8_t FCCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf8, 0x07, 
  };

  // MSACtrl Register Class...
  static uint16_t MSACtrl[] = {
    Mips_MSAIR, Mips_MSACSR, Mips_MSAAccess, Mips_MSASave, Mips_MSAModify, Mips_MSARequest, Mips_MSAMap, Mips_MSAUnmap, 
  };

  // MSACtrl Bit set.
  static uint8_t MSACtrlBits[] = {
    0x00, 0xfc, 0x03, 
  };

  // HI32DSP Register Class...
  static uint16_t HI32DSP[] = {
    Mips_HI0, Mips_HI1, Mips_HI2, Mips_HI3, 
  };

  // HI32DSP Bit set.
  static uint8_t HI32DSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x01, 
  };

  // LO32DSP Register Class...
  static uint16_t LO32DSP[] = {
    Mips_LO0, Mips_LO1, Mips_LO2, Mips_LO3, 
  };

  // LO32DSP Bit set.
  static uint8_t LO32DSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 
  };

  // CPURAReg Register Class...
  static uint16_t CPURAReg[] = {
    Mips_RA, 
  };

  // CPURAReg Bit set.
  static uint8_t CPURARegBits[] = {
    0x00, 0x00, 0x08, 
  };

  // CPUSPReg Register Class...
  static uint16_t CPUSPReg[] = {
    Mips_SP, 
  };

  // CPUSPReg Bit set.
  static uint8_t CPUSPRegBits[] = {
    0x00, 0x00, 0x10, 
  };

  // DSPCC Register Class...
  static uint16_t DSPCC[] = {
    Mips_DSPCCond, 
  };

  // DSPCC Bit set.
  static uint8_t DSPCCBits[] = {
    0x04, 
  };

  // HI32 Register Class...
  static uint16_t HI32[] = {
    Mips_HI0, 
  };

  // HI32 Bit set.
  static uint8_t HI32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 
  };

  // HWRegs Register Class...
  static uint16_t HWRegs[] = {
    Mips_HWR29, 
  };

  // HWRegs Bit set.
  static uint8_t HWRegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 
  };

  // LO32 Register Class...
  static uint16_t LO32[] = {
    Mips_LO0, 
  };

  // LO32 Bit set.
  static uint8_t LO32Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 
  };

  // FGR64 Register Class...
  static uint16_t FGR64[] = {
    Mips_D0_64, Mips_D1_64, Mips_D2_64, Mips_D3_64, Mips_D4_64, Mips_D5_64, Mips_D6_64, Mips_D7_64, Mips_D8_64, Mips_D9_64, Mips_D10_64, Mips_D11_64, Mips_D12_64, Mips_D13_64, Mips_D14_64, Mips_D15_64, Mips_D16_64, Mips_D17_64, Mips_D18_64, Mips_D19_64, Mips_D20_64, Mips_D21_64, Mips_D22_64, Mips_D23_64, Mips_D24_64, Mips_D25_64, Mips_D26_64, Mips_D27_64, Mips_D28_64, Mips_D29_64, Mips_D30_64, Mips_D31_64, 
  };

  // FGR64 Bit set.
  static uint8_t FGR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0xff, 0xff, 0x0f, 
  };

  // GPR64 Register Class...
  static uint16_t GPR64[] = {
    Mips_ZERO_64, Mips_AT_64, Mips_V0_64, Mips_V1_64, Mips_A0_64, Mips_A1_64, Mips_A2_64, Mips_A3_64, Mips_T0_64, Mips_T1_64, Mips_T2_64, Mips_T3_64, Mips_T4_64, Mips_T5_64, Mips_T6_64, Mips_T7_64, Mips_S0_64, Mips_S1_64, Mips_S2_64, Mips_S3_64, Mips_S4_64, Mips_S5_64, Mips_S6_64, Mips_S7_64, Mips_T8_64, Mips_T9_64, Mips_K0_64, Mips_K1_64, Mips_GP_64, Mips_SP_64, Mips_FP_64, Mips_RA_64, 
  };

  // GPR64 Bit set.
  static uint8_t GPR64Bits[] = {
    0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x07, 0x00, 0x00, 0x00, 0xc0, 0xfe, 0xff, 0x1f, 
  };

  // AFGR64 Register Class...
  static uint16_t AFGR64[] = {
    Mips_D0, Mips_D1, Mips_D2, Mips_D3, Mips_D4, Mips_D5, Mips_D6, Mips_D7, Mips_D8, Mips_D9, Mips_D10, Mips_D11, Mips_D12, Mips_D13, Mips_D14, Mips_D15, 
  };

  // AFGR64 Bit set.
  static uint8_t AFGR64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0x7f, 
  };

  // GPR64_with_sub_32_in_CPU16RegsPlusSP Register Class...
  static uint16_t GPR64_with_sub_32_in_CPU16RegsPlusSP[] = {
    Mips_V0_64, Mips_V1_64, Mips_A0_64, Mips_A1_64, Mips_A2_64, Mips_A3_64, Mips_S0_64, Mips_S1_64, Mips_SP_64, 
  };

  // GPR64_with_sub_32_in_CPU16RegsPlusSP Bit set.
  static uint8_t GPR64_with_sub_32_in_CPU16RegsPlusSPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x80, 0x07, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x18, 
  };

  // GPR64_with_sub_32_in_CPU16Regs Register Class...
  static uint16_t GPR64_with_sub_32_in_CPU16Regs[] = {
    Mips_V0_64, Mips_V1_64, Mips_A0_64, Mips_A1_64, Mips_A2_64, Mips_A3_64, Mips_S0_64, Mips_S1_64, 
  };

  // GPR64_with_sub_32_in_CPU16Regs Bit set.
  static uint8_t GPR64_with_sub_32_in_CPU16RegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x07, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x18, 
  };

  // ACC64DSP Register Class...
  static uint16_t ACC64DSP[] = {
    Mips_AC0, Mips_AC1, Mips_AC2, Mips_AC3, 
  };

  // ACC64DSP Bit set.
  static uint8_t ACC64DSPBits[] = {
    0x00, 0x00, 0x00, 0x3c, 
  };

  // ACC64 Register Class...
  static uint16_t ACC64[] = {
    Mips_AC0, 
  };

  // ACC64 Bit set.
  static uint8_t ACC64Bits[] = {
    0x00, 0x00, 0x00, 0x04, 
  };

  // GPR64_with_sub_32_in_CPURAReg Register Class...
  static uint16_t GPR64_with_sub_32_in_CPURAReg[] = {
    Mips_RA_64, 
  };

  // GPR64_with_sub_32_in_CPURAReg Bit set.
  static uint8_t GPR64_with_sub_32_in_CPURARegBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
  };

  // GPR64_with_sub_32_in_CPUSPReg Register Class...
  static uint16_t GPR64_with_sub_32_in_CPUSPReg[] = {
    Mips_SP_64, 
  };

  // GPR64_with_sub_32_in_CPUSPReg Bit set.
  static uint8_t GPR64_with_sub_32_in_CPUSPRegBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 
  };

  // HI64 Register Class...
  static uint16_t HI64[] = {
    Mips_HI0_64, 
  };

  // HI64 Bit set.
  static uint8_t HI64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 
  };

  // LO64 Register Class...
  static uint16_t LO64[] = {
    Mips_LO0_64, 
  };

  // LO64 Bit set.
  static uint8_t LO64Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 
  };

  // MSA128B Register Class...
  static uint16_t MSA128B[] = {
    Mips_W0, Mips_W1, Mips_W2, Mips_W3, Mips_W4, Mips_W5, Mips_W6, Mips_W7, Mips_W8, Mips_W9, Mips_W10, Mips_W11, Mips_W12, Mips_W13, Mips_W14, Mips_W15, Mips_W16, Mips_W17, Mips_W18, Mips_W19, Mips_W20, Mips_W21, Mips_W22, Mips_W23, Mips_W24, Mips_W25, Mips_W26, Mips_W27, Mips_W28, Mips_W29, Mips_W30, Mips_W31, 
  };

  // MSA128B Bit set.
  static uint8_t MSA128BBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f, 
  };

  // MSA128D Register Class...
  static uint16_t MSA128D[] = {
    Mips_W0, Mips_W1, Mips_W2, Mips_W3, Mips_W4, Mips_W5, Mips_W6, Mips_W7, Mips_W8, Mips_W9, Mips_W10, Mips_W11, Mips_W12, Mips_W13, Mips_W14, Mips_W15, Mips_W16, Mips_W17, Mips_W18, Mips_W19, Mips_W20, Mips_W21, Mips_W22, Mips_W23, Mips_W24, Mips_W25, Mips_W26, Mips_W27, Mips_W28, Mips_W29, Mips_W30, Mips_W31, 
  };

  // MSA128D Bit set.
  static uint8_t MSA128DBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f, 
  };

  // MSA128H Register Class...
  static uint16_t MSA128H[] = {
    Mips_W0, Mips_W1, Mips_W2, Mips_W3, Mips_W4, Mips_W5, Mips_W6, Mips_W7, Mips_W8, Mips_W9, Mips_W10, Mips_W11, Mips_W12, Mips_W13, Mips_W14, Mips_W15, Mips_W16, Mips_W17, Mips_W18, Mips_W19, Mips_W20, Mips_W21, Mips_W22, Mips_W23, Mips_W24, Mips_W25, Mips_W26, Mips_W27, Mips_W28, Mips_W29, Mips_W30, Mips_W31, 
  };

  // MSA128H Bit set.
  static uint8_t MSA128HBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f, 
  };

  // MSA128W Register Class...
  static uint16_t MSA128W[] = {
    Mips_W0, Mips_W1, Mips_W2, Mips_W3, Mips_W4, Mips_W5, Mips_W6, Mips_W7, Mips_W8, Mips_W9, Mips_W10, Mips_W11, Mips_W12, Mips_W13, Mips_W14, Mips_W15, Mips_W16, Mips_W17, Mips_W18, Mips_W19, Mips_W20, Mips_W21, Mips_W22, Mips_W23, Mips_W24, Mips_W25, Mips_W26, Mips_W27, Mips_W28, Mips_W29, Mips_W30, Mips_W31, 
  };

  // MSA128W Bit set.
  static uint8_t MSA128WBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0xff, 0xff, 0xff, 0x3f, 
  };

  // ACC128 Register Class...
  static uint16_t ACC128[] = {
    Mips_AC0_64, 
  };

  // ACC128 Bit set.
  static uint8_t ACC128Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 
  };

static MCRegisterClass MipsMCRegisterClasses[] = {
  { "CCR", CCR, CCRBits, 32, sizeof(CCRBits), Mips_CCRRegClassID, 4, 4, 1, 0 },
  { "COP2", COP2, COP2Bits, 32, sizeof(COP2Bits), Mips_COP2RegClassID, 4, 4, 1, 0 },
  { "DSPR", DSPR, DSPRBits, 32, sizeof(DSPRBits), Mips_DSPRRegClassID, 4, 4, 1, 1 },
  { "FGR32", FGR32, FGR32Bits, 32, sizeof(FGR32Bits), Mips_FGR32RegClassID, 4, 4, 1, 1 },
  { "FGRH32", FGRH32, FGRH32Bits, 32, sizeof(FGRH32Bits), Mips_FGRH32RegClassID, 4, 4, 1, 0 },
  { "GPR32", GPR32, GPR32Bits, 32, sizeof(GPR32Bits), Mips_GPR32RegClassID, 4, 4, 1, 1 },
  { "CPU16RegsPlusSP", CPU16RegsPlusSP, CPU16RegsPlusSPBits, 9, sizeof(CPU16RegsPlusSPBits), Mips_CPU16RegsPlusSPRegClassID, 4, 4, 1, 1 },
  { "CPU16Regs", CPU16Regs, CPU16RegsBits, 8, sizeof(CPU16RegsBits), Mips_CPU16RegsRegClassID, 4, 4, 1, 1 },
  { "FCC", FCC, FCCBits, 8, sizeof(FCCBits), Mips_FCCRegClassID, 4, 4, 1, 0 },
  { "MSACtrl", MSACtrl, MSACtrlBits, 8, sizeof(MSACtrlBits), Mips_MSACtrlRegClassID, 4, 4, 1, 1 },
  { "HI32DSP", HI32DSP, HI32DSPBits, 4, sizeof(HI32DSPBits), Mips_HI32DSPRegClassID, 4, 4, 1, 1 },
  { "LO32DSP", LO32DSP, LO32DSPBits, 4, sizeof(LO32DSPBits), Mips_LO32DSPRegClassID, 4, 4, 1, 1 },
  { "CPURAReg", CPURAReg, CPURARegBits, 1, sizeof(CPURARegBits), Mips_CPURARegRegClassID, 4, 4, 1, 0 },
  { "CPUSPReg", CPUSPReg, CPUSPRegBits, 1, sizeof(CPUSPRegBits), Mips_CPUSPRegRegClassID, 4, 4, 1, 0 },
  { "DSPCC", DSPCC, DSPCCBits, 1, sizeof(DSPCCBits), Mips_DSPCCRegClassID, 4, 4, 1, 1 },
  { "HI32", HI32, HI32Bits, 1, sizeof(HI32Bits), Mips_HI32RegClassID, 4, 4, 1, 1 },
  { "HWRegs", HWRegs, HWRegsBits, 1, sizeof(HWRegsBits), Mips_HWRegsRegClassID, 4, 4, 1, 0 },
  { "LO32", LO32, LO32Bits, 1, sizeof(LO32Bits), Mips_LO32RegClassID, 4, 4, 1, 1 },
  { "FGR64", FGR64, FGR64Bits, 32, sizeof(FGR64Bits), Mips_FGR64RegClassID, 8, 8, 1, 1 },
  { "GPR64", GPR64, GPR64Bits, 32, sizeof(GPR64Bits), Mips_GPR64RegClassID, 8, 8, 1, 1 },
  { "AFGR64", AFGR64, AFGR64Bits, 16, sizeof(AFGR64Bits), Mips_AFGR64RegClassID, 8, 8, 1, 1 },
  { "GPR64_with_sub_32_in_CPU16RegsPlusSP", GPR64_with_sub_32_in_CPU16RegsPlusSP, GPR64_with_sub_32_in_CPU16RegsPlusSPBits, 9, sizeof(GPR64_with_sub_32_in_CPU16RegsPlusSPBits), Mips_GPR64_with_sub_32_in_CPU16RegsPlusSPRegClassID, 8, 8, 1, 1 },
  { "GPR64_with_sub_32_in_CPU16Regs", GPR64_with_sub_32_in_CPU16Regs, GPR64_with_sub_32_in_CPU16RegsBits, 8, sizeof(GPR64_with_sub_32_in_CPU16RegsBits), Mips_GPR64_with_sub_32_in_CPU16RegsRegClassID, 8, 8, 1, 1 },
  { "ACC64DSP", ACC64DSP, ACC64DSPBits, 4, sizeof(ACC64DSPBits), Mips_ACC64DSPRegClassID, 8, 8, 1, 1 },
  { "ACC64", ACC64, ACC64Bits, 1, sizeof(ACC64Bits), Mips_ACC64RegClassID, 8, 8, 1, 1 },
  { "GPR64_with_sub_32_in_CPURAReg", GPR64_with_sub_32_in_CPURAReg, GPR64_with_sub_32_in_CPURARegBits, 1, sizeof(GPR64_with_sub_32_in_CPURARegBits), Mips_GPR64_with_sub_32_in_CPURARegRegClassID, 8, 8, 1, 1 },
  { "GPR64_with_sub_32_in_CPUSPReg", GPR64_with_sub_32_in_CPUSPReg, GPR64_with_sub_32_in_CPUSPRegBits, 1, sizeof(GPR64_with_sub_32_in_CPUSPRegBits), Mips_GPR64_with_sub_32_in_CPUSPRegRegClassID, 8, 8, 1, 1 },
  { "HI64", HI64, HI64Bits, 1, sizeof(HI64Bits), Mips_HI64RegClassID, 8, 8, 1, 1 },
  { "LO64", LO64, LO64Bits, 1, sizeof(LO64Bits), Mips_LO64RegClassID, 8, 8, 1, 1 },
  { "MSA128B", MSA128B, MSA128BBits, 32, sizeof(MSA128BBits), Mips_MSA128BRegClassID, 16, 16, 1, 1 },
  { "MSA128D", MSA128D, MSA128DBits, 32, sizeof(MSA128DBits), Mips_MSA128DRegClassID, 16, 16, 1, 1 },
  { "MSA128H", MSA128H, MSA128HBits, 32, sizeof(MSA128HBits), Mips_MSA128HRegClassID, 16, 16, 1, 1 },
  { "MSA128W", MSA128W, MSA128WBits, 32, sizeof(MSA128WBits), Mips_MSA128WRegClassID, 16, 16, 1, 1 },
  { "ACC128", ACC128, ACC128Bits, 1, sizeof(ACC128Bits), Mips_ACC128RegClassID, 16, 16, 1, 1 },
};

#endif // GET_REGINFO_MC_DESC

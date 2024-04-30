/* Capstone Disassembly Engine, https://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/*    Rot127 <unisono@quyllur.org> 2022-2023 */
/* Automatically generated file by Capstone's LLVM TableGen Disassembler Backend. */

/* LLVM-commit: 083d57d0731afc1746680d828bdfe2fa41f62a61 */
/* LLVM-tag: llvmorg-3.0.0-2-g083d57d0731a */

/* Do not edit. */

/* Capstone's LLVM TableGen Backends: */
/* https://github.com/capstone-engine/llvm-capstone */

#ifdef GET_REGINFO_ENUM
#undef GET_REGINFO_ENUM

enum {
  Alpha_NoRegister,
  Alpha_F0 = 1,
  Alpha_F1 = 2,
  Alpha_F2 = 3,
  Alpha_F3 = 4,
  Alpha_F4 = 5,
  Alpha_F5 = 6,
  Alpha_F6 = 7,
  Alpha_F7 = 8,
  Alpha_F8 = 9,
  Alpha_F9 = 10,
  Alpha_F10 = 11,
  Alpha_F11 = 12,
  Alpha_F12 = 13,
  Alpha_F13 = 14,
  Alpha_F14 = 15,
  Alpha_F15 = 16,
  Alpha_F16 = 17,
  Alpha_F17 = 18,
  Alpha_F18 = 19,
  Alpha_F19 = 20,
  Alpha_F20 = 21,
  Alpha_F21 = 22,
  Alpha_F22 = 23,
  Alpha_F23 = 24,
  Alpha_F24 = 25,
  Alpha_F25 = 26,
  Alpha_F26 = 27,
  Alpha_F27 = 28,
  Alpha_F28 = 29,
  Alpha_F29 = 30,
  Alpha_F30 = 31,
  Alpha_F31 = 32,
  Alpha_R0 = 33,
  Alpha_R1 = 34,
  Alpha_R2 = 35,
  Alpha_R3 = 36,
  Alpha_R4 = 37,
  Alpha_R5 = 38,
  Alpha_R6 = 39,
  Alpha_R7 = 40,
  Alpha_R8 = 41,
  Alpha_R9 = 42,
  Alpha_R10 = 43,
  Alpha_R11 = 44,
  Alpha_R12 = 45,
  Alpha_R13 = 46,
  Alpha_R14 = 47,
  Alpha_R15 = 48,
  Alpha_R16 = 49,
  Alpha_R17 = 50,
  Alpha_R18 = 51,
  Alpha_R19 = 52,
  Alpha_R20 = 53,
  Alpha_R21 = 54,
  Alpha_R22 = 55,
  Alpha_R23 = 56,
  Alpha_R24 = 57,
  Alpha_R25 = 58,
  Alpha_R26 = 59,
  Alpha_R27 = 60,
  Alpha_R28 = 61,
  Alpha_R29 = 62,
  Alpha_R30 = 63,
  Alpha_R31 = 64,
  NUM_TARGET_REGS // 65
};

// Register classes

enum {
  Alpha_F4RCRegClassID = 0,
  Alpha_F8RCRegClassID = 1,
  Alpha_GPRCRegClassID = 2,

};
#endif // GET_REGINFO_ENUM

#ifdef GET_REGINFO_MC_DESC
#undef GET_REGINFO_MC_DESC

static const MCPhysReg AlphaRegDiffLists[] = {
  /* 0 */ -1, 0,
};

static const uint16_t AlphaSubRegIdxLists[] = {
  /* 0 */ 0,
};

static const MCRegisterDesc AlphaRegDesc[] = { // Descriptors
  { 3, 0, 0, 0, 0, 0 },
  { 24, 1, 1, 0, 1, 0 },
  { 54, 1, 1, 0, 1, 0 },
  { 76, 1, 1, 0, 1, 0 },
  { 98, 1, 1, 0, 1, 0 },
  { 120, 1, 1, 0, 1, 0 },
  { 142, 1, 1, 0, 1, 0 },
  { 164, 1, 1, 0, 1, 0 },
  { 186, 1, 1, 0, 1, 0 },
  { 208, 1, 1, 0, 1, 0 },
  { 230, 1, 1, 0, 1, 0 },
  { 0, 1, 1, 0, 1, 0 },
  { 30, 1, 1, 0, 1, 0 },
  { 60, 1, 1, 0, 1, 0 },
  { 82, 1, 1, 0, 1, 0 },
  { 104, 1, 1, 0, 1, 0 },
  { 126, 1, 1, 0, 1, 0 },
  { 148, 1, 1, 0, 1, 0 },
  { 170, 1, 1, 0, 1, 0 },
  { 192, 1, 1, 0, 1, 0 },
  { 214, 1, 1, 0, 1, 0 },
  { 8, 1, 1, 0, 1, 0 },
  { 38, 1, 1, 0, 1, 0 },
  { 68, 1, 1, 0, 1, 0 },
  { 90, 1, 1, 0, 1, 0 },
  { 112, 1, 1, 0, 1, 0 },
  { 134, 1, 1, 0, 1, 0 },
  { 156, 1, 1, 0, 1, 0 },
  { 178, 1, 1, 0, 1, 0 },
  { 200, 1, 1, 0, 1, 0 },
  { 222, 1, 1, 0, 1, 0 },
  { 16, 1, 1, 0, 1, 0 },
  { 46, 1, 1, 0, 1, 0 },
  { 27, 1, 1, 0, 1, 0 },
  { 57, 1, 1, 0, 1, 0 },
  { 79, 1, 1, 0, 1, 0 },
  { 101, 1, 1, 0, 1, 0 },
  { 123, 1, 1, 0, 1, 0 },
  { 145, 1, 1, 0, 1, 0 },
  { 167, 1, 1, 0, 1, 0 },
  { 189, 1, 1, 0, 1, 0 },
  { 211, 1, 1, 0, 1, 0 },
  { 233, 1, 1, 0, 1, 0 },
  { 4, 1, 1, 0, 1, 0 },
  { 34, 1, 1, 0, 1, 0 },
  { 64, 1, 1, 0, 1, 0 },
  { 86, 1, 1, 0, 1, 0 },
  { 108, 1, 1, 0, 1, 0 },
  { 130, 1, 1, 0, 1, 0 },
  { 152, 1, 1, 0, 1, 0 },
  { 174, 1, 1, 0, 1, 0 },
  { 196, 1, 1, 0, 1, 0 },
  { 218, 1, 1, 0, 1, 0 },
  { 12, 1, 1, 0, 1, 0 },
  { 42, 1, 1, 0, 1, 0 },
  { 72, 1, 1, 0, 1, 0 },
  { 94, 1, 1, 0, 1, 0 },
  { 116, 1, 1, 0, 1, 0 },
  { 138, 1, 1, 0, 1, 0 },
  { 160, 1, 1, 0, 1, 0 },
  { 182, 1, 1, 0, 1, 0 },
  { 204, 1, 1, 0, 1, 0 },
  { 226, 1, 1, 0, 1, 0 },
  { 20, 1, 1, 0, 1, 0 },
  { 50, 1, 1, 0, 1, 0 },
};

  // F4RC Register Class...
  static const MCPhysReg F4RC[] = {
    Alpha_F0, Alpha_F1, Alpha_F10, Alpha_F11, Alpha_F12, Alpha_F13, Alpha_F14, Alpha_F15, Alpha_F16, Alpha_F17, Alpha_F18, Alpha_F19, Alpha_F20, Alpha_F21, Alpha_F22, Alpha_F23, Alpha_F24, Alpha_F25, Alpha_F26, Alpha_F27, Alpha_F28, Alpha_F29, Alpha_F30, Alpha_F2, Alpha_F3, Alpha_F4, Alpha_F5, Alpha_F6, Alpha_F7, Alpha_F8, Alpha_F9, Alpha_F31, 
  };

  // F4RC Bit set.
  static const uint8_t F4RCBits[] = {
    0xfe, 0xff, 0xff, 0xff, 0x01, 
  };

  // F8RC Register Class...
  static const MCPhysReg F8RC[] = {
    Alpha_F0, Alpha_F1, Alpha_F10, Alpha_F11, Alpha_F12, Alpha_F13, Alpha_F14, Alpha_F15, Alpha_F16, Alpha_F17, Alpha_F18, Alpha_F19, Alpha_F20, Alpha_F21, Alpha_F22, Alpha_F23, Alpha_F24, Alpha_F25, Alpha_F26, Alpha_F27, Alpha_F28, Alpha_F29, Alpha_F30, Alpha_F2, Alpha_F3, Alpha_F4, Alpha_F5, Alpha_F6, Alpha_F7, Alpha_F8, Alpha_F9, Alpha_F31, 
  };

  // F8RC Bit set.
  static const uint8_t F8RCBits[] = {
    0xfe, 0xff, 0xff, 0xff, 0x01, 
  };

  // GPRC Register Class...
  static const MCPhysReg GPRC[] = {
    Alpha_R0, Alpha_R1, Alpha_R2, Alpha_R3, Alpha_R4, Alpha_R5, Alpha_R6, Alpha_R7, Alpha_R8, Alpha_R16, Alpha_R17, Alpha_R18, Alpha_R19, Alpha_R20, Alpha_R21, Alpha_R22, Alpha_R23, Alpha_R24, Alpha_R25, Alpha_R28, Alpha_R27, Alpha_R26, Alpha_R29, Alpha_R9, Alpha_R10, Alpha_R11, Alpha_R12, Alpha_R13, Alpha_R14, Alpha_R15, Alpha_R30, Alpha_R31, 
  };

  // GPRC Bit set.
  static const uint8_t GPRCBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xfe, 0xff, 0xff, 0xff, 0x01, 
  };

static const MCRegisterClass AlphaMCRegisterClasses[] = {
  { F4RC, F4RCBits, sizeof(F4RCBits) },
  { F8RC, F8RCBits, sizeof(F8RCBits) },
  { GPRC, GPRCBits, sizeof(GPRCBits) },
};

static const uint16_t AlphaRegEncodingTable[] = {
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
};
#endif // GET_REGINFO_MC_DESC



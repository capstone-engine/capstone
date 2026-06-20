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
  ALPHA_NoRegister,
  ALPHA_F0 = 1,
  ALPHA_F1 = 2,
  ALPHA_F2 = 3,
  ALPHA_F3 = 4,
  ALPHA_F4 = 5,
  ALPHA_F5 = 6,
  ALPHA_F6 = 7,
  ALPHA_F7 = 8,
  ALPHA_F8 = 9,
  ALPHA_F9 = 10,
  ALPHA_F10 = 11,
  ALPHA_F11 = 12,
  ALPHA_F12 = 13,
  ALPHA_F13 = 14,
  ALPHA_F14 = 15,
  ALPHA_F15 = 16,
  ALPHA_F16 = 17,
  ALPHA_F17 = 18,
  ALPHA_F18 = 19,
  ALPHA_F19 = 20,
  ALPHA_F20 = 21,
  ALPHA_F21 = 22,
  ALPHA_F22 = 23,
  ALPHA_F23 = 24,
  ALPHA_F24 = 25,
  ALPHA_F25 = 26,
  ALPHA_F26 = 27,
  ALPHA_F27 = 28,
  ALPHA_F28 = 29,
  ALPHA_F29 = 30,
  ALPHA_F30 = 31,
  ALPHA_F31 = 32,
  ALPHA_R0 = 33,
  ALPHA_R1 = 34,
  ALPHA_R2 = 35,
  ALPHA_R3 = 36,
  ALPHA_R4 = 37,
  ALPHA_R5 = 38,
  ALPHA_R6 = 39,
  ALPHA_R7 = 40,
  ALPHA_R8 = 41,
  ALPHA_R9 = 42,
  ALPHA_R10 = 43,
  ALPHA_R11 = 44,
  ALPHA_R12 = 45,
  ALPHA_R13 = 46,
  ALPHA_R14 = 47,
  ALPHA_R15 = 48,
  ALPHA_R16 = 49,
  ALPHA_R17 = 50,
  ALPHA_R18 = 51,
  ALPHA_R19 = 52,
  ALPHA_R20 = 53,
  ALPHA_R21 = 54,
  ALPHA_R22 = 55,
  ALPHA_R23 = 56,
  ALPHA_R24 = 57,
  ALPHA_R25 = 58,
  ALPHA_R26 = 59,
  ALPHA_R27 = 60,
  ALPHA_R28 = 61,
  ALPHA_R29 = 62,
  ALPHA_R30 = 63,
  ALPHA_R31 = 64,
  NUM_TARGET_REGS // 65
};

// Register classes

enum {
  ALPHA_F4RCRegClassID = 0,
  ALPHA_F8RCRegClassID = 1,
  ALPHA_GPRCRegClassID = 2,

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
    ALPHA_F0, ALPHA_F1, ALPHA_F10, ALPHA_F11, ALPHA_F12, ALPHA_F13, ALPHA_F14, ALPHA_F15, ALPHA_F16, ALPHA_F17, ALPHA_F18, ALPHA_F19, ALPHA_F20, ALPHA_F21, ALPHA_F22, ALPHA_F23, ALPHA_F24, ALPHA_F25, ALPHA_F26, ALPHA_F27, ALPHA_F28, ALPHA_F29, ALPHA_F30, ALPHA_F2, ALPHA_F3, ALPHA_F4, ALPHA_F5, ALPHA_F6, ALPHA_F7, ALPHA_F8, ALPHA_F9, ALPHA_F31, 
  };

  // F4RC Bit set.
  static const uint8_t F4RCBits[] = {
    0xfe, 0xff, 0xff, 0xff, 0x01, 
  };

  // F8RC Register Class...
  static const MCPhysReg F8RC[] = {
    ALPHA_F0, ALPHA_F1, ALPHA_F10, ALPHA_F11, ALPHA_F12, ALPHA_F13, ALPHA_F14, ALPHA_F15, ALPHA_F16, ALPHA_F17, ALPHA_F18, ALPHA_F19, ALPHA_F20, ALPHA_F21, ALPHA_F22, ALPHA_F23, ALPHA_F24, ALPHA_F25, ALPHA_F26, ALPHA_F27, ALPHA_F28, ALPHA_F29, ALPHA_F30, ALPHA_F2, ALPHA_F3, ALPHA_F4, ALPHA_F5, ALPHA_F6, ALPHA_F7, ALPHA_F8, ALPHA_F9, ALPHA_F31, 
  };

  // F8RC Bit set.
  static const uint8_t F8RCBits[] = {
    0xfe, 0xff, 0xff, 0xff, 0x01, 
  };

  // GPRC Register Class...
  static const MCPhysReg GPRC[] = {
    ALPHA_R0, ALPHA_R1, ALPHA_R2, ALPHA_R3, ALPHA_R4, ALPHA_R5, ALPHA_R6, ALPHA_R7, ALPHA_R8, ALPHA_R16, ALPHA_R17, ALPHA_R18, ALPHA_R19, ALPHA_R20, ALPHA_R21, ALPHA_R22, ALPHA_R23, ALPHA_R24, ALPHA_R25, ALPHA_R28, ALPHA_R27, ALPHA_R26, ALPHA_R29, ALPHA_R9, ALPHA_R10, ALPHA_R11, ALPHA_R12, ALPHA_R13, ALPHA_R14, ALPHA_R15, ALPHA_R30, ALPHA_R31, 
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



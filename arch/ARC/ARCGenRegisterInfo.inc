#ifdef GET_REGINFO_ENUM
#undef GET_REGINFO_ENUM

enum {
  ARC_NoRegister,
  ARC_BLINK = 1,
  ARC_FP = 2,
  ARC_GP = 3,
  ARC_ILINK = 4,
  ARC_SP = 5,
  ARC_R0 = 6,
  ARC_R1 = 7,
  ARC_R2 = 8,
  ARC_R3 = 9,
  ARC_R4 = 10,
  ARC_R5 = 11,
  ARC_R6 = 12,
  ARC_R7 = 13,
  ARC_R8 = 14,
  ARC_R9 = 15,
  ARC_R10 = 16,
  ARC_R11 = 17,
  ARC_R12 = 18,
  ARC_R13 = 19,
  ARC_R14 = 20,
  ARC_R15 = 21,
  ARC_R16 = 22,
  ARC_R17 = 23,
  ARC_R18 = 24,
  ARC_R19 = 25,
  ARC_R20 = 26,
  ARC_R21 = 27,
  ARC_R22 = 28,
  ARC_R23 = 29,
  ARC_R24 = 30,
  ARC_R25 = 31,
  ARC_R30 = 32,
  ARC_R32 = 33,
  ARC_R33 = 34,
  ARC_R34 = 35,
  ARC_R35 = 36,
  ARC_R36 = 37,
  ARC_R37 = 38,
  ARC_R38 = 39,
  ARC_R39 = 40,
  ARC_R40 = 41,
  ARC_R41 = 42,
  ARC_R42 = 43,
  ARC_R43 = 44,
  ARC_R44 = 45,
  ARC_R45 = 46,
  ARC_R46 = 47,
  ARC_R47 = 48,
  ARC_R48 = 49,
  ARC_R49 = 50,
  ARC_R50 = 51,
  ARC_R51 = 52,
  ARC_R52 = 53,
  ARC_R53 = 54,
  ARC_R54 = 55,
  ARC_R55 = 56,
  ARC_R56 = 57,
  ARC_R57 = 58,
  ARC_R58 = 59,
  ARC_R59 = 60,
  ARC_R60 = 61,
  ARC_R61 = 62,
  ARC_R62 = 63,
  ARC_R63 = 64,
  ARC_STATUS32 = 65,
  NUM_TARGET_REGS // 66
};

// Register classes

enum {
  ARC_SREGRegClassID = 0,
  ARC_GPR_SRegClassID = 1,
  ARC_GPR32RegClassID = 2,
  ARC_GPR32_and_GPR_SRegClassID = 3,

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

static const MCPhysReg ARCRegDiffLists[] = {
  /* 0 */ 0,
};

static const uint16_t ARCSubRegIdxLists[] = {
  /* 0 */ 0,
};

static const MCRegisterDesc ARCRegDesc[] = { // Descriptors
  { 3, 0, 0, 0, 0, 0 },
  { 235, 0, 0, 0, 0, 0 },
  { 247, 0, 0, 0, 1, 0 },
  { 250, 0, 0, 0, 2, 0 },
  { 241, 0, 0, 0, 3, 0 },
  { 253, 0, 0, 0, 4, 0 },
  { 24, 0, 0, 0, 5, 0 },
  { 47, 0, 0, 0, 6, 0 },
  { 83, 0, 0, 0, 7, 0 },
  { 110, 0, 0, 0, 8, 0 },
  { 133, 0, 0, 0, 9, 0 },
  { 156, 0, 0, 0, 10, 0 },
  { 175, 0, 0, 0, 11, 0 },
  { 194, 0, 0, 0, 12, 0 },
  { 213, 0, 0, 0, 13, 0 },
  { 232, 0, 0, 0, 14, 0 },
  { 0, 0, 0, 0, 15, 0 },
  { 27, 0, 0, 0, 16, 0 },
  { 50, 0, 0, 0, 17, 0 },
  { 86, 0, 0, 0, 18, 0 },
  { 113, 0, 0, 0, 19, 0 },
  { 136, 0, 0, 0, 20, 0 },
  { 159, 0, 0, 0, 21, 0 },
  { 178, 0, 0, 0, 22, 0 },
  { 197, 0, 0, 0, 23, 0 },
  { 216, 0, 0, 0, 24, 0 },
  { 4, 0, 0, 0, 25, 0 },
  { 31, 0, 0, 0, 26, 0 },
  { 54, 0, 0, 0, 27, 0 },
  { 90, 0, 0, 0, 28, 0 },
  { 117, 0, 0, 0, 29, 0 },
  { 140, 0, 0, 0, 30, 0 },
  { 8, 0, 0, 0, 31, 0 },
  { 58, 0, 0, 0, 32, 0 },
  { 94, 0, 0, 0, 33, 0 },
  { 121, 0, 0, 0, 34, 0 },
  { 144, 0, 0, 0, 35, 0 },
  { 163, 0, 0, 0, 36, 0 },
  { 182, 0, 0, 0, 37, 0 },
  { 201, 0, 0, 0, 38, 0 },
  { 220, 0, 0, 0, 39, 0 },
  { 12, 0, 0, 0, 40, 0 },
  { 35, 0, 0, 0, 41, 0 },
  { 71, 0, 0, 0, 42, 0 },
  { 98, 0, 0, 0, 43, 0 },
  { 125, 0, 0, 0, 44, 0 },
  { 148, 0, 0, 0, 45, 0 },
  { 167, 0, 0, 0, 46, 0 },
  { 186, 0, 0, 0, 47, 0 },
  { 205, 0, 0, 0, 48, 0 },
  { 224, 0, 0, 0, 49, 0 },
  { 16, 0, 0, 0, 50, 0 },
  { 39, 0, 0, 0, 51, 0 },
  { 75, 0, 0, 0, 52, 0 },
  { 102, 0, 0, 0, 53, 0 },
  { 129, 0, 0, 0, 54, 0 },
  { 152, 0, 0, 0, 55, 0 },
  { 171, 0, 0, 0, 56, 0 },
  { 190, 0, 0, 0, 57, 0 },
  { 209, 0, 0, 0, 58, 0 },
  { 228, 0, 0, 0, 59, 0 },
  { 20, 0, 0, 0, 60, 0 },
  { 43, 0, 0, 0, 61, 0 },
  { 79, 0, 0, 0, 62, 0 },
  { 106, 0, 0, 0, 63, 0 },
  { 62, 0, 0, 0, 64, 0 },
};

  // SREG Register Class...
  static const MCPhysReg SREG[] = {
    ARC_STATUS32, 
  };

  // SREG Bit set.
  static const uint8_t SREGBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 
  };

  // GPR_S Register Class...
  static const MCPhysReg GPR_S[] = {
    ARC_R0, ARC_R1, ARC_R2, ARC_R3, ARC_R12, ARC_R13, ARC_R14, ARC_R15, 
  };

  // GPR_S Bit set.
  static const uint8_t GPR_SBits[] = {
    0xc0, 0x03, 0x3c, 
  };

  // GPR32 Register Class...
  static const MCPhysReg GPR32[] = {
    ARC_R0, ARC_R1, ARC_R2, ARC_R3, ARC_R4, ARC_R5, ARC_R6, ARC_R7, ARC_R8, ARC_R9, ARC_R10, ARC_R11, ARC_R12, ARC_R13, ARC_R14, ARC_R15, ARC_R16, ARC_R17, ARC_R18, ARC_R19, ARC_R20, ARC_R21, ARC_R22, ARC_R23, ARC_R24, ARC_R25, ARC_GP, ARC_FP, ARC_SP, ARC_ILINK, ARC_R30, ARC_BLINK, ARC_R32, ARC_R33, ARC_R34, ARC_R35, ARC_R36, ARC_R37, ARC_R38, ARC_R39, ARC_R40, ARC_R41, ARC_R42, ARC_R43, ARC_R44, ARC_R45, ARC_R46, ARC_R47, ARC_R48, ARC_R49, ARC_R50, ARC_R51, ARC_R52, ARC_R53, ARC_R54, ARC_R55, ARC_R56, ARC_R57, ARC_R58, ARC_R59, ARC_R60, ARC_R61, ARC_R62, ARC_R63, 
  };

  // GPR32 Bit set.
  static const uint8_t GPR32Bits[] = {
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 
  };

  // GPR32_and_GPR_S Register Class...
  static const MCPhysReg GPR32_and_GPR_S[] = {
    ARC_R0, ARC_R1, ARC_R2, ARC_R3, ARC_R12, ARC_R13, ARC_R14, ARC_R15, 
  };

  // GPR32_and_GPR_S Bit set.
  static const uint8_t GPR32_and_GPR_SBits[] = {
    0xc0, 0x03, 0x3c, 
  };

static const MCRegisterClass ARCMCRegisterClasses[] = {
  { SREG, SREGBits, sizeof(SREGBits) },
  { GPR_S, GPR_SBits, sizeof(GPR_SBits) },
  { GPR32, GPR32Bits, sizeof(GPR32Bits) },
  { GPR32_and_GPR_S, GPR32_and_GPR_SBits, sizeof(GPR32_and_GPR_SBits) },
};

static const uint16_t ARCRegEncodingTable[] = {
  0,
  31,
  27,
  26,
  29,
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
  30,
  32,
  33,
  34,
  35,
  36,
  37,
  38,
  39,
  40,
  41,
  42,
  43,
  44,
  45,
  46,
  47,
  48,
  49,
  50,
  51,
  52,
  53,
  54,
  55,
  56,
  57,
  58,
  59,
  60,
  61,
  62,
  63,
  10,
};
#endif // GET_REGINFO_MC_DESC




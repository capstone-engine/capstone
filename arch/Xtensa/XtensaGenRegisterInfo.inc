#ifdef GET_REGINFO_ENUM
#undef GET_REGINFO_ENUM

enum {
  Xtensa_NoRegister,
  Xtensa_SAR = 1,
  Xtensa_SP = 2,
  Xtensa_A0 = 3,
  Xtensa_A2 = 4,
  Xtensa_A3 = 5,
  Xtensa_A4 = 6,
  Xtensa_A5 = 7,
  Xtensa_A6 = 8,
  Xtensa_A7 = 9,
  Xtensa_A8 = 10,
  Xtensa_A9 = 11,
  Xtensa_A10 = 12,
  Xtensa_A11 = 13,
  Xtensa_A12 = 14,
  Xtensa_A13 = 15,
  Xtensa_A14 = 16,
  Xtensa_A15 = 17,
  NUM_TARGET_REGS // 18
};

// Register classes

enum {
  Xtensa_ARRegClassID = 0,
  Xtensa_SRRegClassID = 1,

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

static const MCPhysReg XtensaRegDiffLists[] = {
  /* 0 */ 0,
};

static const uint16_t XtensaSubRegIdxLists[] = {
  /* 0 */ 0,
};

static const MCRegisterDesc XtensaRegDesc[] = { // Descriptors
  { 3, 0, 0, 0, 0, 0 },
  { 54, 0, 0, 0, 0, 0 },
  { 51, 0, 0, 0, 1, 0 },
  { 4, 0, 0, 0, 2, 0 },
  { 15, 0, 0, 0, 3, 0 },
  { 22, 0, 0, 0, 4, 0 },
  { 29, 0, 0, 0, 5, 0 },
  { 36, 0, 0, 0, 6, 0 },
  { 39, 0, 0, 0, 7, 0 },
  { 42, 0, 0, 0, 8, 0 },
  { 45, 0, 0, 0, 9, 0 },
  { 48, 0, 0, 0, 10, 0 },
  { 0, 0, 0, 0, 11, 0 },
  { 7, 0, 0, 0, 12, 0 },
  { 11, 0, 0, 0, 13, 0 },
  { 18, 0, 0, 0, 14, 0 },
  { 25, 0, 0, 0, 15, 0 },
  { 32, 0, 0, 0, 16, 0 },
};

  // AR Register Class...
  static const MCPhysReg AR[] = {
    Xtensa_A8, Xtensa_A9, Xtensa_A10, Xtensa_A11, Xtensa_A12, Xtensa_A13, Xtensa_A14, Xtensa_A15, Xtensa_A7, Xtensa_A6, Xtensa_A5, Xtensa_A4, Xtensa_A3, Xtensa_A2, Xtensa_A0, Xtensa_SP, 
  };

  // AR Bit set.
  static const uint8_t ARBits[] = {
    0xfc, 0xff, 0x03, 
  };

  // SR Register Class...
  static const MCPhysReg SR[] = {
    Xtensa_SAR, 
  };

  // SR Bit set.
  static const uint8_t SRBits[] = {
    0x02, 
  };

static const MCRegisterClass XtensaMCRegisterClasses[] = {
  { AR, ARBits, sizeof(ARBits) },
  { SR, SRBits, sizeof(SRBits) },
};

static const uint16_t XtensaRegEncodingTable[] = {
  0,
  3,
  1,
  0,
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
};
#endif // GET_REGINFO_MC_DESC




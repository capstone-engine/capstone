#ifdef GET_REGINFO_ENUM
#undef GET_REGINFO_ENUM

enum {
  TriCore_NoRegister,
  TriCore_FCX = 1,
  TriCore_PC = 2,
  TriCore_PCXI = 3,
  TriCore_PSW = 4,
  TriCore_A0 = 5,
  TriCore_A1 = 6,
  TriCore_A2 = 7,
  TriCore_A3 = 8,
  TriCore_A4 = 9,
  TriCore_A5 = 10,
  TriCore_A6 = 11,
  TriCore_A7 = 12,
  TriCore_A8 = 13,
  TriCore_A9 = 14,
  TriCore_A10 = 15,
  TriCore_A11 = 16,
  TriCore_A12 = 17,
  TriCore_A13 = 18,
  TriCore_A14 = 19,
  TriCore_A15 = 20,
  TriCore_D0 = 21,
  TriCore_D1 = 22,
  TriCore_D2 = 23,
  TriCore_D3 = 24,
  TriCore_D4 = 25,
  TriCore_D5 = 26,
  TriCore_D6 = 27,
  TriCore_D7 = 28,
  TriCore_D8 = 29,
  TriCore_D9 = 30,
  TriCore_D10 = 31,
  TriCore_D11 = 32,
  TriCore_D12 = 33,
  TriCore_D13 = 34,
  TriCore_D14 = 35,
  TriCore_D15 = 36,
  TriCore_E0 = 37,
  TriCore_E2 = 38,
  TriCore_E4 = 39,
  TriCore_E6 = 40,
  TriCore_E8 = 41,
  TriCore_E10 = 42,
  TriCore_E12 = 43,
  TriCore_E14 = 44,
  TriCore_P0 = 45,
  TriCore_P2 = 46,
  TriCore_P4 = 47,
  TriCore_P6 = 48,
  TriCore_P8 = 49,
  TriCore_P10 = 50,
  TriCore_P12 = 51,
  TriCore_P14 = 52,
  TriCore_A0_A1 = 53,
  TriCore_A2_A3 = 54,
  TriCore_A4_A5 = 55,
  TriCore_A6_A7 = 56,
  TriCore_A8_A9 = 57,
  TriCore_A10_A11 = 58,
  TriCore_A12_A13 = 59,
  TriCore_A14_A15 = 60,
  NUM_TARGET_REGS // 61
};

// Register classes

enum {
  TriCore_RARegClassID = 0,
  TriCore_RDRegClassID = 1,
  TriCore_PSRegsRegClassID = 2,
  TriCore_PairAddrRegsRegClassID = 3,
  TriCore_RERegClassID = 4,
  TriCore_RPRegClassID = 5,

};

// Subregister indices

enum {
  TriCore_NoSubRegister,
  TriCore_subreg_even,	// 1
  TriCore_subreg_odd,	// 2
  TriCore_NUM_TARGET_SUBREGS
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

static const MCPhysReg TriCoreRegDiffLists[] = {
  /* 0 */ -48, 1, 0,
  /* 3 */ -47, 1, 0,
  /* 6 */ -46, 1, 0,
  /* 9 */ -45, 1, 0,
  /* 12 */ -44, 1, 0,
  /* 15 */ -43, 1, 0,
  /* 18 */ -42, 1, 0,
  /* 21 */ -41, 1, 0,
  /* 24 */ -40, 1, 0,
  /* 27 */ -39, 1, 0,
  /* 30 */ -38, 1, 0,
  /* 33 */ -37, 1, 0,
  /* 36 */ -36, 1, 0,
  /* 39 */ -35, 1, 0,
  /* 42 */ -34, 1, 0,
  /* 45 */ -33, 1, 0,
  /* 48 */ -16, 1, 0,
  /* 51 */ -15, 1, 0,
  /* 54 */ -14, 1, 0,
  /* 57 */ -13, 1, 0,
  /* 60 */ -12, 1, 0,
  /* 63 */ -11, 1, 0,
  /* 66 */ -10, 1, 0,
  /* 69 */ -9, 1, 0,
  /* 72 */ 32, 8, 0,
  /* 75 */ 33, 8, 0,
  /* 78 */ 34, 8, 0,
  /* 81 */ 35, 8, 0,
  /* 84 */ 36, 8, 0,
  /* 87 */ 37, 8, 0,
  /* 90 */ 38, 8, 0,
  /* 93 */ 39, 8, 0,
  /* 96 */ 40, 8, 0,
  /* 99 */ 9, 0,
  /* 101 */ 10, 0,
  /* 103 */ 11, 0,
  /* 105 */ 12, 0,
  /* 107 */ 13, 0,
  /* 109 */ 14, 0,
  /* 111 */ 15, 0,
  /* 113 */ 16, 0,
};

static const uint16_t TriCoreSubRegIdxLists[] = {
  /* 0 */ 1, 2, 0,
};

static const MCRegisterDesc TriCoreRegDesc[] = { // Descriptors
  { 3, 0, 0, 0, 0, 0 },
  { 201, 2, 2, 2, 8192, 3 },
  { 189, 2, 2, 2, 8193, 3 },
  { 192, 2, 2, 2, 8194, 3 },
  { 197, 2, 2, 2, 8195, 3 },
  { 16, 2, 96, 2, 8196, 3 },
  { 43, 2, 93, 2, 8197, 3 },
  { 65, 2, 93, 2, 8198, 3 },
  { 92, 2, 90, 2, 8199, 3 },
  { 114, 2, 90, 2, 8200, 3 },
  { 141, 2, 87, 2, 8201, 3 },
  { 147, 2, 87, 2, 8202, 3 },
  { 162, 2, 84, 2, 8203, 3 },
  { 168, 2, 84, 2, 8204, 3 },
  { 183, 2, 81, 2, 8205, 3 },
  { 0, 2, 81, 2, 8206, 3 },
  { 32, 2, 78, 2, 8207, 3 },
  { 49, 2, 78, 2, 8208, 3 },
  { 81, 2, 75, 2, 8209, 3 },
  { 98, 2, 75, 2, 8210, 3 },
  { 130, 2, 72, 2, 8211, 3 },
  { 19, 2, 113, 2, 8212, 3 },
  { 46, 2, 111, 2, 8213, 3 },
  { 68, 2, 111, 2, 8214, 3 },
  { 95, 2, 109, 2, 8215, 3 },
  { 117, 2, 109, 2, 8216, 3 },
  { 144, 2, 107, 2, 8217, 3 },
  { 150, 2, 107, 2, 8218, 3 },
  { 165, 2, 105, 2, 8219, 3 },
  { 171, 2, 105, 2, 8220, 3 },
  { 186, 2, 103, 2, 8221, 3 },
  { 4, 2, 103, 2, 8222, 3 },
  { 36, 2, 101, 2, 8223, 3 },
  { 53, 2, 101, 2, 8224, 3 },
  { 85, 2, 99, 2, 8225, 3 },
  { 102, 2, 99, 2, 8226, 3 },
  { 134, 2, 73, 2, 8227, 3 },
  { 22, 48, 2, 0, 4116, 0 },
  { 71, 51, 2, 0, 4118, 0 },
  { 120, 54, 2, 0, 4120, 0 },
  { 153, 57, 2, 0, 4122, 0 },
  { 174, 60, 2, 0, 4124, 0 },
  { 8, 63, 2, 0, 4126, 0 },
  { 57, 66, 2, 0, 4128, 0 },
  { 106, 69, 2, 0, 4130, 0 },
  { 25, 24, 2, 0, 4100, 0 },
  { 74, 27, 2, 0, 4102, 0 },
  { 123, 30, 2, 0, 4104, 0 },
  { 156, 33, 2, 0, 4106, 0 },
  { 177, 36, 2, 0, 4108, 0 },
  { 12, 39, 2, 0, 4110, 0 },
  { 61, 42, 2, 0, 4112, 0 },
  { 110, 45, 2, 0, 4114, 0 },
  { 40, 0, 2, 0, 4100, 0 },
  { 89, 3, 2, 0, 4102, 0 },
  { 138, 6, 2, 0, 4104, 0 },
  { 159, 9, 2, 0, 4106, 0 },
  { 180, 12, 2, 0, 4108, 0 },
  { 28, 15, 2, 0, 4110, 0 },
  { 77, 18, 2, 0, 4112, 0 },
  { 126, 21, 2, 0, 4114, 0 },
};

  // RA Register Class...
  static const MCPhysReg RA[] = {
    TriCore_A0, TriCore_A1, TriCore_A2, TriCore_A3, TriCore_A4, TriCore_A5, TriCore_A6, TriCore_A7, TriCore_A8, TriCore_A9, TriCore_A10, TriCore_A11, TriCore_A12, TriCore_A13, TriCore_A14, TriCore_A15, 
  };

  // RA Bit set.
  static const uint8_t RABits[] = {
    0xe0, 0xff, 0x1f, 
  };

  // RD Register Class...
  static const MCPhysReg RD[] = {
    TriCore_D0, TriCore_D1, TriCore_D2, TriCore_D3, TriCore_D4, TriCore_D5, TriCore_D6, TriCore_D7, TriCore_D8, TriCore_D9, TriCore_D10, TriCore_D11, TriCore_D12, TriCore_D13, TriCore_D14, TriCore_D15, 
  };

  // RD Bit set.
  static const uint8_t RDBits[] = {
    0x00, 0x00, 0xe0, 0xff, 0x1f, 
  };

  // PSRegs Register Class...
  static const MCPhysReg PSRegs[] = {
    TriCore_PSW, TriCore_PCXI, TriCore_PC, TriCore_FCX, 
  };

  // PSRegs Bit set.
  static const uint8_t PSRegsBits[] = {
    0x1e, 
  };

  // PairAddrRegs Register Class...
  static const MCPhysReg PairAddrRegs[] = {
    TriCore_A0_A1, TriCore_A2_A3, TriCore_A4_A5, TriCore_A6_A7, TriCore_A8_A9, TriCore_A10_A11, TriCore_A12_A13, TriCore_A14_A15, 
  };

  // PairAddrRegs Bit set.
  static const uint8_t PairAddrRegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x1f, 
  };

  // RE Register Class...
  static const MCPhysReg RE[] = {
    TriCore_E0, TriCore_E2, TriCore_E4, TriCore_E6, TriCore_E8, TriCore_E10, TriCore_E12, TriCore_E14, 
  };

  // RE Bit set.
  static const uint8_t REBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xe0, 0x1f, 
  };

  // RP Register Class...
  static const MCPhysReg RP[] = {
    TriCore_P0, TriCore_P2, TriCore_P4, TriCore_P6, TriCore_P8, TriCore_P10, TriCore_P12, TriCore_P14, 
  };

  // RP Bit set.
  static const uint8_t RPBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x1f, 
  };

static const MCRegisterClass TriCoreMCRegisterClasses[] = {
  { RA, RABits, sizeof(RABits) },
  { RD, RDBits, sizeof(RDBits) },
  { PSRegs, PSRegsBits, sizeof(PSRegsBits) },
  { PairAddrRegs, PairAddrRegsBits, sizeof(PairAddrRegsBits) },
  { RE, REBits, sizeof(REBits) },
  { RP, RPBits, sizeof(RPBits) },
};

static const uint16_t TriCoreRegEncodingTable[] = {
  0,
  3,
  2,
  1,
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
  2,
  4,
  6,
  8,
  10,
  12,
  14,
};
#endif // GET_REGINFO_MC_DESC




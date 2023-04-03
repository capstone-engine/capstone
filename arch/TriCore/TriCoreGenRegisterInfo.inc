/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/*    Rot127 <unisono@quyllur.org> 2022-2023 */
/* Automatically generated file by the LLVM TableGen Disassembler Backend. */
/* Do not edit. */

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

#ifdef GET_REGINFO_MC_DESC
#undef GET_REGINFO_MC_DESC

static const MCPhysReg TriCoreRegDiffLists[] = {
  /* 0 */ 65434, 1, 0,
  /* 3 */ 65450, 1, 0,
  /* 6 */ 65482, 1, 0,
  /* 9 */ 65488, 1, 0,
  /* 12 */ 65489, 1, 0,
  /* 15 */ 65490, 1, 0,
  /* 18 */ 65491, 1, 0,
  /* 21 */ 65492, 1, 0,
  /* 24 */ 65493, 1, 0,
  /* 27 */ 65494, 1, 0,
  /* 30 */ 65495, 1, 0,
  /* 33 */ 65496, 1, 0,
  /* 36 */ 65497, 1, 0,
  /* 39 */ 65498, 1, 0,
  /* 42 */ 65499, 1, 0,
  /* 45 */ 65500, 1, 0,
  /* 48 */ 65501, 1, 0,
  /* 51 */ 65502, 1, 0,
  /* 54 */ 65503, 1, 0,
  /* 57 */ 65520, 1, 0,
  /* 60 */ 65521, 1, 0,
  /* 63 */ 65522, 1, 0,
  /* 66 */ 65523, 1, 0,
  /* 69 */ 65524, 1, 0,
  /* 72 */ 65525, 1, 0,
  /* 75 */ 65526, 1, 0,
  /* 78 */ 65527, 1, 0,
  /* 81 */ 32, 8, 0,
  /* 84 */ 33, 8, 0,
  /* 87 */ 34, 8, 0,
  /* 90 */ 35, 8, 0,
  /* 93 */ 36, 8, 0,
  /* 96 */ 37, 8, 0,
  /* 99 */ 38, 8, 0,
  /* 102 */ 39, 8, 0,
  /* 105 */ 40, 8, 0,
  /* 108 */ 9, 0,
  /* 110 */ 10, 0,
  /* 112 */ 11, 0,
  /* 114 */ 12, 0,
  /* 116 */ 13, 0,
  /* 118 */ 14, 0,
  /* 120 */ 15, 0,
  /* 122 */ 16, 0,
  /* 124 */ 65535, 0,
};

static const uint16_t TriCoreSubRegIdxLists[] = {
  /* 0 */ 1, 2, 0,
};

static const MCRegisterDesc TriCoreRegDesc[] = { // Descriptors
  { 3, 0, 0, 0, 0, 0 },
  { 201, 2, 2, 2, 1985, 0 },
  { 189, 2, 2, 2, 1985, 0 },
  { 192, 2, 2, 2, 1985, 0 },
  { 197, 2, 2, 2, 1985, 0 },
  { 16, 2, 105, 2, 1985, 0 },
  { 43, 2, 102, 2, 1985, 0 },
  { 65, 2, 102, 2, 1985, 0 },
  { 92, 2, 99, 2, 1985, 0 },
  { 114, 2, 99, 2, 1985, 0 },
  { 141, 2, 96, 2, 1985, 0 },
  { 147, 2, 96, 2, 1985, 0 },
  { 162, 2, 93, 2, 1985, 0 },
  { 168, 2, 93, 2, 1985, 0 },
  { 183, 2, 90, 2, 1985, 0 },
  { 0, 2, 90, 2, 1985, 0 },
  { 32, 2, 87, 2, 1985, 0 },
  { 49, 2, 87, 2, 1985, 0 },
  { 81, 2, 84, 2, 1985, 0 },
  { 98, 2, 84, 2, 1985, 0 },
  { 130, 2, 81, 2, 1985, 0 },
  { 19, 2, 122, 2, 1985, 0 },
  { 46, 2, 120, 2, 1985, 0 },
  { 68, 2, 120, 2, 1985, 0 },
  { 95, 2, 118, 2, 1985, 0 },
  { 117, 2, 118, 2, 1985, 0 },
  { 144, 2, 116, 2, 1985, 0 },
  { 150, 2, 116, 2, 1985, 0 },
  { 165, 2, 114, 2, 1985, 0 },
  { 171, 2, 114, 2, 1985, 0 },
  { 186, 2, 112, 2, 1985, 0 },
  { 4, 2, 112, 2, 1985, 0 },
  { 36, 2, 110, 2, 1985, 0 },
  { 53, 2, 110, 2, 1985, 0 },
  { 85, 2, 108, 2, 1985, 0 },
  { 102, 2, 108, 2, 1985, 0 },
  { 134, 2, 82, 2, 1985, 0 },
  { 22, 57, 2, 0, 98, 2 },
  { 71, 60, 2, 0, 98, 2 },
  { 120, 63, 2, 0, 98, 2 },
  { 153, 66, 2, 0, 98, 2 },
  { 174, 69, 2, 0, 98, 2 },
  { 8, 72, 2, 0, 98, 2 },
  { 57, 75, 2, 0, 98, 2 },
  { 106, 78, 2, 0, 98, 2 },
  { 25, 33, 2, 0, 50, 2 },
  { 74, 36, 2, 0, 50, 2 },
  { 123, 39, 2, 0, 50, 2 },
  { 156, 42, 2, 0, 50, 2 },
  { 177, 45, 2, 0, 50, 2 },
  { 12, 48, 2, 0, 50, 2 },
  { 61, 51, 2, 0, 50, 2 },
  { 110, 54, 2, 0, 50, 2 },
  { 40, 9, 2, 0, 2, 2 },
  { 89, 12, 2, 0, 2, 2 },
  { 138, 15, 2, 0, 2, 2 },
  { 159, 18, 2, 0, 2, 2 },
  { 180, 21, 2, 0, 2, 2 },
  { 28, 24, 2, 0, 2, 2 },
  { 77, 27, 2, 0, 2, 2 },
  { 126, 30, 2, 0, 2, 2 },
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

#endif // GET_REGINFO_MC_DESC




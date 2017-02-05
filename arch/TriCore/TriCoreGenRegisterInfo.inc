/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|*Target Register Enum Values                                                 *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */


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
  TriCore_A0_A1 = 45,
  TriCore_A2_A3 = 46,
  TriCore_A4_A5 = 47,
  TriCore_A6_A7 = 48,
  TriCore_A8_A9 = 49,
  TriCore_A10_A11 = 50,
  TriCore_A12_A13 = 51,
  TriCore_A14_A15 = 52,
  TriCore_NUM_TARGET_REGS 	// 53
};

// Register classes
enum {
  TriCore_AddrRegsRegClassID = 0,
  TriCore_DataRegsRegClassID = 1,
  TriCore_PSRegsRegClassID = 2,
  TriCore_ExtRegsRegClassID = 3,
  TriCore_PairAddrRegsRegClassID = 4
};

// Subregister indices
enum {
  TriCore_NoSubRegister,
  TriCore_subreg_even,	// 1
  TriCore_subreg_odd,	// 2
  TriCore_NUM_TARGET_SUBREGS
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

static MCPhysReg TriCoreRegDiffLists[] = {
  /* 0 */ 65450, 1, 0,
  /* 3 */ 65482, 1, 0,
  /* 6 */ 65496, 1, 0,
  /* 9 */ 65497, 1, 0,
  /* 12 */ 65498, 1, 0,
  /* 15 */ 65499, 1, 0,
  /* 18 */ 65500, 1, 0,
  /* 21 */ 65501, 1, 0,
  /* 24 */ 65502, 1, 0,
  /* 27 */ 65503, 1, 0,
  /* 30 */ 65520, 1, 0,
  /* 33 */ 65521, 1, 0,
  /* 36 */ 65522, 1, 0,
  /* 39 */ 65523, 1, 0,
  /* 42 */ 65524, 1, 0,
  /* 45 */ 65525, 1, 0,
  /* 48 */ 65526, 1, 0,
  /* 51 */ 65527, 1, 0,
  /* 54 */ 8, 0,
  /* 56 */ 9, 0,
  /* 58 */ 10, 0,
  /* 60 */ 11, 0,
  /* 62 */ 12, 0,
  /* 64 */ 13, 0,
  /* 66 */ 14, 0,
  /* 68 */ 15, 0,
  /* 70 */ 16, 0,
  /* 72 */ 32, 0,
  /* 74 */ 33, 0,
  /* 76 */ 34, 0,
  /* 78 */ 35, 0,
  /* 80 */ 36, 0,
  /* 82 */ 37, 0,
  /* 84 */ 38, 0,
  /* 86 */ 39, 0,
  /* 88 */ 40, 0,
  /* 90 */ 65535, 0,
};

static uint16_t TriCoreSubRegIdxLists[] = {
  /* 0 */ 1, 2, 0,
};

static MCRegisterDesc TriCoreRegDesc[] = { // Descriptors
  { 3, 0, 0, 0, 0 },
  { 174, 2, 2, 2, 1441 },
  { 162, 2, 2, 2, 1441 },
  { 165, 2, 2, 2, 1441 },
  { 170, 2, 2, 2, 1441 },
  { 12, 2, 88, 2, 1441 },
  { 36, 2, 86, 2, 1441 },
  { 54, 2, 86, 2, 1441 },
  { 78, 2, 84, 2, 1441 },
  { 96, 2, 84, 2, 1441 },
  { 120, 2, 82, 2, 1441 },
  { 126, 2, 82, 2, 1441 },
  { 138, 2, 80, 2, 1441 },
  { 144, 2, 80, 2, 1441 },
  { 156, 2, 78, 2, 1441 },
  { 0, 2, 78, 2, 1441 },
  { 25, 2, 76, 2, 1441 },
  { 42, 2, 76, 2, 1441 },
  { 67, 2, 74, 2, 1441 },
  { 84, 2, 74, 2, 1441 },
  { 109, 2, 72, 2, 1441 },
  { 15, 2, 70, 2, 1441 },
  { 39, 2, 68, 2, 1441 },
  { 57, 2, 68, 2, 1441 },
  { 81, 2, 66, 2, 1441 },
  { 99, 2, 66, 2, 1441 },
  { 123, 2, 64, 2, 1441 },
  { 129, 2, 64, 2, 1441 },
  { 141, 2, 62, 2, 1441 },
  { 147, 2, 62, 2, 1441 },
  { 159, 2, 60, 2, 1441 },
  { 4, 2, 60, 2, 1441 },
  { 29, 2, 58, 2, 1441 },
  { 46, 2, 58, 2, 1441 },
  { 71, 2, 56, 2, 1441 },
  { 88, 2, 56, 2, 1441 },
  { 113, 2, 54, 2, 1441 },
  { 18, 30, 2, 0, 50 },
  { 60, 33, 2, 0, 50 },
  { 102, 36, 2, 0, 50 },
  { 132, 39, 2, 0, 50 },
  { 150, 42, 2, 0, 50 },
  { 8, 45, 2, 0, 50 },
  { 50, 48, 2, 0, 50 },
  { 92, 51, 2, 0, 50 },
  { 33, 6, 2, 0, 2 },
  { 75, 9, 2, 0, 2 },
  { 117, 12, 2, 0, 2 },
  { 135, 15, 2, 0, 2 },
  { 153, 18, 2, 0, 2 },
  { 21, 21, 2, 0, 2 },
  { 63, 24, 2, 0, 2 },
  { 105, 27, 2, 0, 2 },
};

  // AddrRegs Register Class...
  static MCPhysReg AddrRegs[] = {
    TriCore_A15, TriCore_A2, TriCore_A3, TriCore_A4, TriCore_A5, TriCore_A6, TriCore_A7, TriCore_A12, TriCore_A13, TriCore_A14, TriCore_A10, TriCore_A11, TriCore_A0, TriCore_A1, TriCore_A8, TriCore_A9,
  };

  // AddrRegs Bit set.
  static uint8_t AddrRegsBits[] = {
    0xe0, 0xff, 0x1f,
  };

  // DataRegs Register Class...
  static MCPhysReg DataRegs[] = {
    TriCore_D15, TriCore_D2, TriCore_D3, TriCore_D4, TriCore_D5, TriCore_D6, TriCore_D7, TriCore_D8, TriCore_D9, TriCore_D10, TriCore_D11, TriCore_D12, TriCore_D13, TriCore_D14, TriCore_D0, TriCore_D1,
  };

  // DataRegs Bit set.
  static uint8_t DataRegsBits[] = {
    0x00, 0x00, 0xe0, 0xff, 0x1f,
  };

  // PSRegs Register Class...
  static MCPhysReg PSRegs[] = {
    TriCore_PSW, TriCore_PCXI, TriCore_PC, TriCore_FCX,
  };

  // PSRegs Bit set.
  static uint8_t PSRegsBits[] = {
    0x1e,
  };

  // ExtRegs Register Class...
  static MCPhysReg ExtRegs[] = {
    TriCore_E2, TriCore_E4, TriCore_E6, TriCore_E8, TriCore_E10, TriCore_E12, TriCore_E14, TriCore_E0,
  };

  // ExtRegs Bit set.
  static uint8_t ExtRegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xe0, 0x1f,
  };

  // PairAddrRegs Register Class...
  static MCPhysReg PairAddrRegs[] = {
    TriCore_A0_A1, TriCore_A2_A3, TriCore_A4_A5, TriCore_A6_A7, TriCore_A8_A9, TriCore_A10_A11, TriCore_A12_A13, TriCore_A14_A15,
  };

  // PairAddrRegs Bit set.
  static uint8_t PairAddrRegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x1f,
  };

static MCRegisterClass TriCoreMCRegisterClasses[] = {
  { "AddrRegs", AddrRegs, AddrRegsBits, 16, sizeof(AddrRegsBits), TriCore_AddrRegsRegClassID, 4, 4, 1, 1 },
  { "DataRegs", DataRegs, DataRegsBits, 16, sizeof(DataRegsBits), TriCore_DataRegsRegClassID, 4, 4, 1, 1 },
  { "PSRegs", PSRegs, PSRegsBits, 4, sizeof(PSRegsBits), TriCore_PSRegsRegClassID, 4, 4, 1, 1 },
  { "ExtRegs", ExtRegs, ExtRegsBits, 8, sizeof(ExtRegsBits), TriCore_ExtRegsRegClassID, 8, 8, 1, 1 },
  { "PairAddrRegs", PairAddrRegs, PairAddrRegsBits, 8, sizeof(PairAddrRegsBits), TriCore_PairAddrRegsRegClassID, 8, 8, 1, 1 },
};


#endif // GET_REGINFO_MC_DESC

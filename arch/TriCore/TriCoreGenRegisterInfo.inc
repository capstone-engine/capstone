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
  TriCore_NUM_TARGET_REGS 	// 45
};

// Register classes
enum {
  TriCore_AddrRegsRegClassID = 0,
  TriCore_DataRegsRegClassID = 1,
  TriCore_PSRegsRegClassID = 2,
  TriCore_ExtRegsRegClassID = 3
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
  /* 0 */ 65482, 1, 0,
  /* 3 */ 65520, 1, 0,
  /* 6 */ 65521, 1, 0,
  /* 9 */ 65522, 1, 0,
  /* 12 */ 65523, 1, 0,
  /* 15 */ 65524, 1, 0,
  /* 18 */ 65525, 1, 0,
  /* 21 */ 65526, 1, 0,
  /* 24 */ 65527, 1, 0,
  /* 27 */ 8, 0,
  /* 29 */ 9, 0,
  /* 31 */ 10, 0,
  /* 33 */ 11, 0,
  /* 35 */ 12, 0,
  /* 37 */ 13, 0,
  /* 39 */ 14, 0,
  /* 41 */ 15, 0,
  /* 43 */ 16, 0,
  /* 45 */ 65535, 0,
};

static uint16_t TriCoreSubRegIdxLists[] = {
  /* 0 */ 1, 2, 0,
};

static MCRegisterDesc TriCoreRegDesc[] = { // Descriptors
  { 3, 0, 0, 0, 0 },
  { 147, 2, 2, 2, 721 },
  { 135, 2, 2, 2, 721 },
  { 138, 2, 2, 2, 721 },
  { 143, 2, 2, 2, 721 },
  { 12, 2, 2, 2, 721 },
  { 29, 2, 2, 2, 721 },
  { 47, 2, 2, 2, 721 },
  { 64, 2, 2, 2, 721 },
  { 82, 2, 2, 2, 721 },
  { 99, 2, 2, 2, 721 },
  { 105, 2, 2, 2, 721 },
  { 114, 2, 2, 2, 721 },
  { 120, 2, 2, 2, 721 },
  { 129, 2, 2, 2, 721 },
  { 0, 2, 2, 2, 721 },
  { 21, 2, 2, 2, 721 },
  { 35, 2, 2, 2, 721 },
  { 56, 2, 2, 2, 721 },
  { 70, 2, 2, 2, 721 },
  { 91, 2, 2, 2, 721 },
  { 15, 2, 43, 2, 721 },
  { 32, 2, 41, 2, 721 },
  { 50, 2, 41, 2, 721 },
  { 67, 2, 39, 2, 721 },
  { 85, 2, 39, 2, 721 },
  { 102, 2, 37, 2, 721 },
  { 108, 2, 37, 2, 721 },
  { 117, 2, 35, 2, 721 },
  { 123, 2, 35, 2, 721 },
  { 132, 2, 33, 2, 721 },
  { 4, 2, 33, 2, 721 },
  { 25, 2, 31, 2, 721 },
  { 39, 2, 31, 2, 721 },
  { 60, 2, 29, 2, 721 },
  { 74, 2, 29, 2, 721 },
  { 95, 2, 27, 2, 721 },
  { 18, 3, 2, 0, 2 },
  { 53, 6, 2, 0, 2 },
  { 88, 9, 2, 0, 2 },
  { 111, 12, 2, 0, 2 },
  { 126, 15, 2, 0, 2 },
  { 8, 18, 2, 0, 2 },
  { 43, 21, 2, 0, 2 },
  { 78, 24, 2, 0, 2 },
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

static MCRegisterClass TriCoreMCRegisterClasses[] = {
  { "AddrRegs", AddrRegs, AddrRegsBits, 16, sizeof(AddrRegsBits), TriCore_AddrRegsRegClassID, 4, 4, 1, 1 },
  { "DataRegs", DataRegs, DataRegsBits, 16, sizeof(DataRegsBits), TriCore_DataRegsRegClassID, 4, 4, 1, 1 },
  { "PSRegs", PSRegs, PSRegsBits, 4, sizeof(PSRegsBits), TriCore_PSRegsRegClassID, 4, 4, 1, 1 },
  { "ExtRegs", ExtRegs, ExtRegsBits, 8, sizeof(ExtRegsBits), TriCore_ExtRegsRegClassID, 8, 4, 1, 1 },
};


#endif // GET_REGINFO_MC_DESC

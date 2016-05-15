/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Register Enum Values                                                *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/


#ifdef GET_REGINFO_ENUM
#undef GET_REGINFO_ENUM

enum {
  NoRegister,
  FCX = 1,
  PC = 2,
  PCXI = 3,
  PSW = 4,
  A0 = 5,
  A1 = 6,
  A2 = 7,
  A3 = 8,
  A4 = 9,
  A5 = 10,
  A6 = 11,
  A7 = 12,
  A8 = 13,
  A9 = 14,
  A10 = 15,
  A11 = 16,
  A12 = 17,
  A13 = 18,
  A14 = 19,
  A15 = 20,
  D0 = 21,
  D1 = 22,
  D2 = 23,
  D3 = 24,
  D4 = 25,
  D5 = 26,
  D6 = 27,
  D7 = 28,
  D8 = 29,
  D9 = 30,
  D10 = 31,
  D11 = 32,
  D12 = 33,
  D13 = 34,
  D14 = 35,
  D15 = 36,
  E0 = 37,
  E2 = 38,
  E4 = 39,
  E6 = 40,
  E8 = 41,
  E10 = 42,
  E12 = 43,
  E14 = 44,
  NUM_TARGET_REGS 	// 45
};

// Register classes
enum {
  AddrRegsRegClassID = 0,
  DataRegsRegClassID = 1,
  PSRegsRegClassID = 2,
  ExtRegsRegClassID = 3,

};

// Subregister indices
enum {
  NoSubRegister,
  subreg_even,	// 1
  subreg_odd,	// 2
  NUM_TARGET_SUBREGS
};

#endif // GET_REGINFO_ENUM

/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* MC Register Information                                                    *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/


#ifdef GET_REGINFO_MC_DESC
#undef GET_REGINFO_MC_DESC

const MCPhysReg TriCoreRegDiffLists[] = {
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

const unsigned TriCoreLaneMaskLists[] = {
  /* 0 */ 0x00000000, ~0u,
  /* 2 */ 0x00000001, 0x00000002, ~0u,
};

const uint16_t TriCoreSubRegIdxLists[] = {
  /* 0 */ 1, 2, 0,
};

const char TriCoreRegStrings[] = {
  /* 0 */ 'A', '1', '0', 0,
  /* 4 */ 'D', '1', '0', 0,
  /* 8 */ 'E', '1', '0', 0,
  /* 12 */ 'A', '0', 0,
  /* 15 */ 'D', '0', 0,
  /* 18 */ 'E', '0', 0,
  /* 21 */ 'A', '1', '1', 0,
  /* 25 */ 'D', '1', '1', 0,
  /* 29 */ 'A', '1', 0,
  /* 32 */ 'D', '1', 0,
  /* 35 */ 'A', '1', '2', 0,
  /* 39 */ 'D', '1', '2', 0,
  /* 43 */ 'E', '1', '2', 0,
  /* 47 */ 'A', '2', 0,
  /* 50 */ 'D', '2', 0,
  /* 53 */ 'E', '2', 0,
  /* 56 */ 'A', '1', '3', 0,
  /* 60 */ 'D', '1', '3', 0,
  /* 64 */ 'A', '3', 0,
  /* 67 */ 'D', '3', 0,
  /* 70 */ 'A', '1', '4', 0,
  /* 74 */ 'D', '1', '4', 0,
  /* 78 */ 'E', '1', '4', 0,
  /* 82 */ 'A', '4', 0,
  /* 85 */ 'D', '4', 0,
  /* 88 */ 'E', '4', 0,
  /* 91 */ 'A', '1', '5', 0,
  /* 95 */ 'D', '1', '5', 0,
  /* 99 */ 'A', '5', 0,
  /* 102 */ 'D', '5', 0,
  /* 105 */ 'A', '6', 0,
  /* 108 */ 'D', '6', 0,
  /* 111 */ 'E', '6', 0,
  /* 114 */ 'A', '7', 0,
  /* 117 */ 'D', '7', 0,
  /* 120 */ 'A', '8', 0,
  /* 123 */ 'D', '8', 0,
  /* 126 */ 'E', '8', 0,
  /* 129 */ 'A', '9', 0,
  /* 132 */ 'D', '9', 0,
  /* 135 */ 'P', 'C', 0,
  /* 138 */ 'P', 'C', 'X', 'I', 0,
  /* 143 */ 'P', 'S', 'W', 0,
  /* 147 */ 'F', 'C', 'X', 0,
};

const MCRegisterDesc TriCoreRegDesc[] = { // Descriptors
  { 3, 0, 0, 0, 0, 0 },
  { 147, 2, 2, 2, 721, 0 },
  { 135, 2, 2, 2, 721, 0 },
  { 138, 2, 2, 2, 721, 0 },
  { 143, 2, 2, 2, 721, 0 },
  { 12, 2, 2, 2, 721, 0 },
  { 29, 2, 2, 2, 721, 0 },
  { 47, 2, 2, 2, 721, 0 },
  { 64, 2, 2, 2, 721, 0 },
  { 82, 2, 2, 2, 721, 0 },
  { 99, 2, 2, 2, 721, 0 },
  { 105, 2, 2, 2, 721, 0 },
  { 114, 2, 2, 2, 721, 0 },
  { 120, 2, 2, 2, 721, 0 },
  { 129, 2, 2, 2, 721, 0 },
  { 0, 2, 2, 2, 721, 0 },
  { 21, 2, 2, 2, 721, 0 },
  { 35, 2, 2, 2, 721, 0 },
  { 56, 2, 2, 2, 721, 0 },
  { 70, 2, 2, 2, 721, 0 },
  { 91, 2, 2, 2, 721, 0 },
  { 15, 2, 43, 2, 721, 0 },
  { 32, 2, 41, 2, 721, 0 },
  { 50, 2, 41, 2, 721, 0 },
  { 67, 2, 39, 2, 721, 0 },
  { 85, 2, 39, 2, 721, 0 },
  { 102, 2, 37, 2, 721, 0 },
  { 108, 2, 37, 2, 721, 0 },
  { 117, 2, 35, 2, 721, 0 },
  { 123, 2, 35, 2, 721, 0 },
  { 132, 2, 33, 2, 721, 0 },
  { 4, 2, 33, 2, 721, 0 },
  { 25, 2, 31, 2, 721, 0 },
  { 39, 2, 31, 2, 721, 0 },
  { 60, 2, 29, 2, 721, 0 },
  { 74, 2, 29, 2, 721, 0 },
  { 95, 2, 27, 2, 721, 0 },
  { 18, 3, 2, 0, 2, 2 },
  { 53, 6, 2, 0, 2, 2 },
  { 88, 9, 2, 0, 2, 2 },
  { 111, 12, 2, 0, 2, 2 },
  { 126, 15, 2, 0, 2, 2 },
  { 8, 18, 2, 0, 2, 2 },
  { 43, 21, 2, 0, 2, 2 },
  { 78, 24, 2, 0, 2, 2 },
};

  // AddrRegs Register Class...
  const MCPhysReg AddrRegs[] = {
    TriCore::A15, TriCore::A2, TriCore::A3, TriCore::A4, TriCore::A5, TriCore::A6, TriCore::A7, TriCore::A12, TriCore::A13, TriCore::A14, TriCore::A10, TriCore::A11, TriCore::A0, TriCore::A1, TriCore::A8, TriCore::A9, 
  };

  // AddrRegs Bit set.
  const uint8_t AddrRegsBits[] = {
    0xe0, 0xff, 0x1f, 
  };

  // DataRegs Register Class...
  const MCPhysReg DataRegs[] = {
    TriCore::D15, TriCore::D2, TriCore::D3, TriCore::D4, TriCore::D5, TriCore::D6, TriCore::D7, TriCore::D8, TriCore::D9, TriCore::D10, TriCore::D11, TriCore::D12, TriCore::D13, TriCore::D14, TriCore::D0, TriCore::D1, 
  };

  // DataRegs Bit set.
  const uint8_t DataRegsBits[] = {
    0x00, 0x00, 0xe0, 0xff, 0x1f, 
  };

  // PSRegs Register Class...
  const MCPhysReg PSRegs[] = {
    TriCore::PSW, TriCore::PCXI, TriCore::PC, TriCore::FCX, 
  };

  // PSRegs Bit set.
  const uint8_t PSRegsBits[] = {
    0x1e, 
  };

  // ExtRegs Register Class...
  const MCPhysReg ExtRegs[] = {
    TriCore::E2, TriCore::E4, TriCore::E6, TriCore::E8, TriCore::E10, TriCore::E12, TriCore::E14, TriCore::E0, 
  };

  // ExtRegs Bit set.
  const uint8_t ExtRegsBits[] = {
    0x00, 0x00, 0x00, 0x00, 0xe0, 0x1f, 
  };


const char TriCoreRegClassStrings[] = {
  /* 0 */ 'P', 'S', 'R', 'e', 'g', 's', 0,
  /* 7 */ 'D', 'a', 't', 'a', 'R', 'e', 'g', 's', 0,
  /* 16 */ 'A', 'd', 'd', 'r', 'R', 'e', 'g', 's', 0,
  /* 25 */ 'E', 'x', 't', 'R', 'e', 'g', 's', 0,
};

const MCRegisterClass TriCoreMCRegisterClasses[] = {
  { "AddrRegs", AddrRegs, AddrRegsBits, 16, 16, sizeof(AddrRegsBits), TriCore_AddrRegsRegClassID, 4, 4, 1, 1 },
  { "DataRegs", DataRegs, DataRegsBits, 7, 16, sizeof(DataRegsBits), TriCore_DataRegsRegClassID, 4, 4, 1, 1 },
  { "PSRegs", PSRegs, PSRegsBits, 0, 4, sizeof(PSRegsBits), TriCore_PSRegsRegClassID, 4, 4, 1, 1 },
  { "ExtRegs", ExtRegs, ExtRegsBits, 25, 8, sizeof(ExtRegsBits), TriCore_ExtRegsRegClassID, 8, 4, 1, 1 },
};

#endif // GET_REGINFO_MC_DESC

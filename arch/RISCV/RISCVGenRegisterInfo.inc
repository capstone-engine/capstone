/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|* Target Register Enum Values                                                *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/


#ifdef GET_REGINFO_ENUM
#undef GET_REGINFO_ENUM

enum
{
	RISCV_NoRegister,
	RISCV_X0 = 1,
	RISCV_X1 = 2,
	RISCV_X2 = 3,
	RISCV_X3 = 4,
	RISCV_X4 = 5,
	RISCV_X5 = 6,
	RISCV_X6 = 7,
	RISCV_X7 = 8,
	RISCV_X8 = 9,
	RISCV_X9 = 10,
	RISCV_X10 = 11,
	RISCV_X11 = 12,
	RISCV_X12 = 13,
	RISCV_X13 = 14,
	RISCV_X14 = 15,
	RISCV_X15 = 16,
	RISCV_X16 = 17,
	RISCV_X17 = 18,
	RISCV_X18 = 19,
	RISCV_X19 = 20,
	RISCV_X20 = 21,
	RISCV_X21 = 22,
	RISCV_X22 = 23,
	RISCV_X23 = 24,
	RISCV_X24 = 25,
	RISCV_X25 = 26,
	RISCV_X26 = 27,
	RISCV_X27 = 28,
	RISCV_X28 = 29,
	RISCV_X29 = 30,
	RISCV_X30 = 31,
	RISCV_X31 = 32,
	RISCV_F0_32 = 33,
	RISCV_F0_64 = 34,
	RISCV_F1_32 = 35,
	RISCV_F1_64 = 36,
	RISCV_F2_32 = 37,
	RISCV_F2_64 = 38,
	RISCV_F3_32 = 39,
	RISCV_F3_64 = 40,
	RISCV_F4_32 = 41,
	RISCV_F4_64 = 42,
	RISCV_F5_32 = 43,
	RISCV_F5_64 = 44,
	RISCV_F6_32 = 45,
	RISCV_F6_64 = 46,
	RISCV_F7_32 = 47,
	RISCV_F7_64 = 48,
	RISCV_F8_32 = 49,
	RISCV_F8_64 = 50,
	RISCV_F9_32 = 51,
	RISCV_F9_64 = 52,
	RISCV_F10_32 = 53,
	RISCV_F10_64 = 54,
	RISCV_F11_32 = 55,
	RISCV_F11_64 = 56,
	RISCV_F12_32 = 57,
	RISCV_F12_64 = 58,
	RISCV_F13_32 = 59,
	RISCV_F13_64 = 60,
	RISCV_F14_32 = 61,
	RISCV_F14_64 = 62,
	RISCV_F15_32 = 63,
	RISCV_F15_64 = 64,
	RISCV_F16_32 = 65,
	RISCV_F16_64 = 66,
	RISCV_F17_32 = 67,
	RISCV_F17_64 = 68,
	RISCV_F18_32 = 69,
	RISCV_F18_64 = 70,
	RISCV_F19_32 = 71,
	RISCV_F19_64 = 72,
	RISCV_F20_32 = 73,
	RISCV_F20_64 = 74,
	RISCV_F21_32 = 75,
	RISCV_F21_64 = 76,
	RISCV_F22_32 = 77,
	RISCV_F22_64 = 78,
	RISCV_F23_32 = 79,
	RISCV_F23_64 = 80,
	RISCV_F24_32 = 81,
	RISCV_F24_64 = 82,
	RISCV_F25_32 = 83,
	RISCV_F25_64 = 84,
	RISCV_F26_32 = 85,
	RISCV_F26_64 = 86,
	RISCV_F27_32 = 87,
	RISCV_F27_64 = 88,
	RISCV_F28_32 = 89,
	RISCV_F28_64 = 90,
	RISCV_F29_32 = 91,
	RISCV_F29_64 = 92,
	RISCV_F30_32 = 93,
	RISCV_F30_64 = 94,
	RISCV_F31_32 = 95,
	RISCV_F31_64 = 96,
	RISCV_NUM_TARGET_REGS	// 97
};

// Register classes

enum
{
	RISCV_FPR32RegClassID = 0,
	RISCV_GPRRegClassID = 1,
	RISCV_FPR64RegClassID = 2,

};


// Register alternate name indices

enum
{
	RISCV_ABIRegAltName,	// 0
	RISCV_NoRegAltName,	// 1
	RISCV_NUM_TARGET_REG_ALT_NAMES = 2
};


// Subregister indices

enum
{
	RISCV_NoSubRegister,
	RISCV_sub_32,		// 1
	RISCV_NUM_TARGET_SUBREGS
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

static const MCPhysReg RISCVRegDiffLists[] = {
	/* 0 */ 1, 0,
	/* 2 */ 32, 0,
	/* 4 */ 33, 0,
	/* 6 */ 34, 0,
	/* 8 */ 35, 0,
	/* 10 */ 36, 0,
	/* 12 */ 37, 0,
	/* 14 */ 38, 0,
	/* 16 */ 39, 0,
	/* 18 */ 40, 0,
	/* 20 */ 41, 0,
	/* 22 */ 42, 0,
	/* 24 */ 43, 0,
	/* 26 */ 44, 0,
	/* 28 */ 45, 0,
	/* 30 */ 46, 0,
	/* 32 */ 47, 0,
	/* 34 */ 48, 0,
	/* 36 */ 49, 0,
	/* 38 */ 50, 0,
	/* 40 */ 51, 0,
	/* 42 */ 52, 0,
	/* 44 */ 53, 0,
	/* 46 */ 54, 0,
	/* 48 */ 55, 0,
	/* 50 */ 56, 0,
	/* 52 */ 57, 0,
	/* 54 */ 58, 0,
	/* 56 */ 59, 0,
	/* 58 */ 60, 0,
	/* 60 */ 61, 0,
	/* 62 */ 62, 0,
	/* 64 */ 63, 0,
	/* 66 */ 65535, 0,
};

static const uint16_t RISCVSubRegIdxLists[] = {
	/* 0 */ 1, 0,
};

static const MCRegisterDesc RISCVRegDesc[] = {	// Descriptors
	{3, 0, 0, 0, 0},
	{12, 1, 1, 1, 1057},
	{27, 1, 1, 1, 1057},
	{252, 1, 1, 1, 1057},
	{263, 1, 1, 1, 1057},
	{488, 1, 1, 1, 1057},
	{499, 1, 1, 1, 1057},
	{510, 1, 1, 1, 1057},
	{521, 1, 1, 1, 1057},
	{532, 1, 1, 1, 1057},
	{543, 1, 1, 1, 1057},
	{0, 1, 1, 1, 1057},
	{15, 1, 1, 1, 1057},
	{30, 1, 1, 1, 1057},
	{255, 1, 1, 1, 1057},
	{266, 1, 1, 1, 1057},
	{491, 1, 1, 1, 1057},
	{502, 1, 1, 1, 1057},
	{513, 1, 1, 1, 1057},
	{524, 1, 1, 1, 1057},
	{535, 1, 1, 1, 1057},
	{4, 1, 1, 1, 1057},
	{19, 1, 1, 1, 1057},
	{34, 1, 1, 1, 1057},
	{259, 1, 1, 1, 1057},
	{270, 1, 1, 1, 1057},
	{495, 1, 1, 1, 1057},
	{506, 1, 1, 1, 1057},
	{517, 1, 1, 1, 1057},
	{528, 1, 1, 1, 1057},
	{539, 1, 1, 1, 1057},
	{8, 1, 1, 1, 1057},
	{23, 1, 1, 1, 1057},
	{59, 1, 0, 1, 32},
	{295, 66, 1, 0, 32},
	{86, 1, 0, 1, 64},
	{322, 66, 1, 0, 64},
	{106, 1, 0, 1, 96},
	{342, 66, 1, 0, 96},
	{126, 1, 0, 1, 128},
	{362, 66, 1, 0, 128},
	{146, 1, 0, 1, 160},
	{382, 66, 1, 0, 160},
	{166, 1, 0, 1, 192},
	{402, 66, 1, 0, 192},
	{186, 1, 0, 1, 224},
	{422, 66, 1, 0, 224},
	{206, 1, 0, 1, 256},
	{442, 66, 1, 0, 256},
	{226, 1, 0, 1, 288},
	{462, 66, 1, 0, 288},
	{246, 1, 0, 1, 320},
	{482, 66, 1, 0, 320},
	{38, 1, 0, 1, 352},
	{274, 66, 1, 0, 352},
	{65, 1, 0, 1, 384},
	{301, 66, 1, 0, 384},
	{92, 1, 0, 1, 416},
	{328, 66, 1, 0, 416},
	{112, 1, 0, 1, 448},
	{348, 66, 1, 0, 448},
	{132, 1, 0, 1, 480},
	{368, 66, 1, 0, 480},
	{152, 1, 0, 1, 512},
	{388, 66, 1, 0, 512},
	{172, 1, 0, 1, 544},
	{408, 66, 1, 0, 544},
	{192, 1, 0, 1, 576},
	{428, 66, 1, 0, 576},
	{212, 1, 0, 1, 608},
	{448, 66, 1, 0, 608},
	{232, 1, 0, 1, 640},
	{468, 66, 1, 0, 640},
	{45, 1, 0, 1, 672},
	{281, 66, 1, 0, 672},
	{72, 1, 0, 1, 704},
	{308, 66, 1, 0, 704},
	{99, 1, 0, 1, 736},
	{335, 66, 1, 0, 736},
	{119, 1, 0, 1, 768},
	{355, 66, 1, 0, 768},
	{139, 1, 0, 1, 800},
	{375, 66, 1, 0, 800},
	{159, 1, 0, 1, 832},
	{395, 66, 1, 0, 832},
	{179, 1, 0, 1, 864},
	{415, 66, 1, 0, 864},
	{199, 1, 0, 1, 896},
	{435, 66, 1, 0, 896},
	{219, 1, 0, 1, 928},
	{455, 66, 1, 0, 928},
	{239, 1, 0, 1, 960},
	{475, 66, 1, 0, 960},
	{52, 1, 0, 1, 992},
	{288, 66, 1, 0, 992},
	{79, 1, 0, 1, 1024},
	{315, 66, 1, 0, 1024},
};

  // FPR32 Register Class...
static const MCPhysReg FPR32[] = {
	RISCV_F0_32, RISCV_F1_32, RISCV_F2_32, RISCV_F3_32, RISCV_F4_32,
		RISCV_F5_32, RISCV_F6_32, RISCV_F7_32, RISCV_F10_32,
		RISCV_F11_32, RISCV_F12_32, RISCV_F13_32, RISCV_F14_32,
		RISCV_F15_32, RISCV_F16_32, RISCV_F17_32, RISCV_F28_32,
		RISCV_F29_32, RISCV_F30_32, RISCV_F31_32, RISCV_F8_32,
		RISCV_F9_32, RISCV_F18_32, RISCV_F19_32, RISCV_F20_32,
		RISCV_F21_32, RISCV_F22_32, RISCV_F23_32, RISCV_F24_32,
		RISCV_F25_32, RISCV_F26_32, RISCV_F27_32,
};

  // FPR32 Bit set.
static const uint8_t FPR32Bits[] = {
	0x00, 0x00, 0x00, 0x00, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
		0xaa,
};

  // GPR Register Class...
static const MCPhysReg GPR[] = {
	RISCV_X10, RISCV_X11, RISCV_X12, RISCV_X13, RISCV_X14, RISCV_X15,
		RISCV_X16, RISCV_X17, RISCV_X5, RISCV_X6, RISCV_X7, RISCV_X28,
		RISCV_X29, RISCV_X30, RISCV_X31, RISCV_X8, RISCV_X9,
		RISCV_X18, RISCV_X19, RISCV_X20, RISCV_X21, RISCV_X22,
		RISCV_X23, RISCV_X24, RISCV_X25, RISCV_X26, RISCV_X27,
		RISCV_X0, RISCV_X1, RISCV_X2, RISCV_X3, RISCV_X4,
};

  // GPR Bit set.
static const uint8_t GPRBits[] = {
	0xfe, 0xff, 0xff, 0xff, 0x01,
};

  // FPR64 Register Class...
static const MCPhysReg FPR64[] = {
	RISCV_F0_64, RISCV_F1_64, RISCV_F2_64, RISCV_F3_64, RISCV_F4_64,
		RISCV_F5_64, RISCV_F6_64, RISCV_F7_64, RISCV_F10_64,
		RISCV_F11_64, RISCV_F12_64, RISCV_F13_64, RISCV_F14_64,
		RISCV_F15_64, RISCV_F16_64, RISCV_F17_64, RISCV_F28_64,
		RISCV_F29_64, RISCV_F30_64, RISCV_F31_64, RISCV_F8_64,
		RISCV_F9_64, RISCV_F18_64, RISCV_F19_64, RISCV_F20_64,
		RISCV_F21_64, RISCV_F22_64, RISCV_F23_64, RISCV_F24_64,
		RISCV_F25_64, RISCV_F26_64, RISCV_F27_64,
};

  // FPR64 Bit set.
static const uint8_t FPR64Bits[] = {
	0x00, 0x00, 0x00, 0x00, 0x54, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
		0x55, 0x01,
};

//NOTE_rod: Comparing with the definition of MCRegisterClass of MCRegisterInfo.h of llvm and Capstone, Keep in mind that Capstone uses a new value Alignment, which I am using with the same value as RegSize (PhysRegSize in llvm).
static const MCRegisterClass RISCVMCRegisterClasses[] = {
	{FPR32, FPR32Bits, 32, sizeof (FPR32Bits), RISCV_FPR32RegClassID, 4,
	 4, 1, 1}
	,
	{GPR, GPRBits, 32, sizeof (GPRBits), RISCV_GPRRegClassID, 0, 0, 1, 1}
	,
	{FPR64, FPR64Bits, 32, sizeof (FPR64Bits), RISCV_FPR64RegClassID, 8,
	 8, 1, 1}
	,
};

#endif // GET_REGINFO_MC_DESC

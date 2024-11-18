#ifdef GET_REGINFO_ENUM
#undef GET_REGINFO_ENUM

enum {
  Xtensa_NoRegister,
  Xtensa_ACCHI = 1,
  Xtensa_ACCLO = 2,
  Xtensa_ACCX = 3,
  Xtensa_ATOMCTL = 4,
  Xtensa_BREG = 5,
  Xtensa_CCOUNT = 6,
  Xtensa_CPENABLE = 7,
  Xtensa_DDR = 8,
  Xtensa_DEBUGCAUSE = 9,
  Xtensa_DEPC = 10,
  Xtensa_EXCCAUSE = 11,
  Xtensa_EXCVADDR = 12,
  Xtensa_EXPSTATE = 13,
  Xtensa_FCR = 14,
  Xtensa_FFT_BIT_WIDTH = 15,
  Xtensa_FSR = 16,
  Xtensa_GPIO_OUT = 17,
  Xtensa_IBREAKENABLE = 18,
  Xtensa_ICOUNT = 19,
  Xtensa_ICOUNTLEVEL = 20,
  Xtensa_INTCLEAR = 21,
  Xtensa_INTENABLE = 22,
  Xtensa_INTERRUPT = 23,
  Xtensa_LBEG = 24,
  Xtensa_LCOUNT = 25,
  Xtensa_LEND = 26,
  Xtensa_LITBASE = 27,
  Xtensa_MEMCTL = 28,
  Xtensa_PRID = 29,
  Xtensa_PS = 30,
  Xtensa_QACC = 31,
  Xtensa_SAR = 32,
  Xtensa_SAR_BYTE = 33,
  Xtensa_SP = 34,
  Xtensa_THREADPTR = 35,
  Xtensa_UA_STATE = 36,
  Xtensa_VECBASE = 37,
  Xtensa_WINDOWBASE = 38,
  Xtensa_WINDOWSTART = 39,
  Xtensa_A0 = 40,
  Xtensa_A2 = 41,
  Xtensa_A3 = 42,
  Xtensa_A4 = 43,
  Xtensa_A5 = 44,
  Xtensa_A6 = 45,
  Xtensa_A7 = 46,
  Xtensa_A8 = 47,
  Xtensa_A9 = 48,
  Xtensa_A10 = 49,
  Xtensa_A11 = 50,
  Xtensa_A12 = 51,
  Xtensa_A13 = 52,
  Xtensa_A14 = 53,
  Xtensa_A15 = 54,
  Xtensa_AED0 = 55,
  Xtensa_AED1 = 56,
  Xtensa_AED2 = 57,
  Xtensa_AED3 = 58,
  Xtensa_AED4 = 59,
  Xtensa_AED5 = 60,
  Xtensa_AED6 = 61,
  Xtensa_AED7 = 62,
  Xtensa_AED8 = 63,
  Xtensa_AED9 = 64,
  Xtensa_AED10 = 65,
  Xtensa_AED11 = 66,
  Xtensa_AED12 = 67,
  Xtensa_AED13 = 68,
  Xtensa_AED14 = 69,
  Xtensa_AED15 = 70,
  Xtensa_B0 = 71,
  Xtensa_B1 = 72,
  Xtensa_B2 = 73,
  Xtensa_B3 = 74,
  Xtensa_B4 = 75,
  Xtensa_B5 = 76,
  Xtensa_B6 = 77,
  Xtensa_B7 = 78,
  Xtensa_B8 = 79,
  Xtensa_B9 = 80,
  Xtensa_B10 = 81,
  Xtensa_B11 = 82,
  Xtensa_B12 = 83,
  Xtensa_B13 = 84,
  Xtensa_B14 = 85,
  Xtensa_B15 = 86,
  Xtensa_CCOMPARE0 = 87,
  Xtensa_CCOMPARE1 = 88,
  Xtensa_CCOMPARE2 = 89,
  Xtensa_CONFIGID0 = 90,
  Xtensa_CONFIGID1 = 91,
  Xtensa_DBREAKA0 = 92,
  Xtensa_DBREAKA1 = 93,
  Xtensa_DBREAKC0 = 94,
  Xtensa_DBREAKC1 = 95,
  Xtensa_EPC1 = 96,
  Xtensa_EPC2 = 97,
  Xtensa_EPC3 = 98,
  Xtensa_EPC4 = 99,
  Xtensa_EPC5 = 100,
  Xtensa_EPC6 = 101,
  Xtensa_EPC7 = 102,
  Xtensa_EPS2 = 103,
  Xtensa_EPS3 = 104,
  Xtensa_EPS4 = 105,
  Xtensa_EPS5 = 106,
  Xtensa_EPS6 = 107,
  Xtensa_EPS7 = 108,
  Xtensa_EXCSAVE1 = 109,
  Xtensa_EXCSAVE2 = 110,
  Xtensa_EXCSAVE3 = 111,
  Xtensa_EXCSAVE4 = 112,
  Xtensa_EXCSAVE5 = 113,
  Xtensa_EXCSAVE6 = 114,
  Xtensa_EXCSAVE7 = 115,
  Xtensa_F0 = 116,
  Xtensa_F1 = 117,
  Xtensa_F2 = 118,
  Xtensa_F3 = 119,
  Xtensa_F4 = 120,
  Xtensa_F5 = 121,
  Xtensa_F6 = 122,
  Xtensa_F7 = 123,
  Xtensa_F8 = 124,
  Xtensa_F9 = 125,
  Xtensa_F10 = 126,
  Xtensa_F11 = 127,
  Xtensa_F12 = 128,
  Xtensa_F13 = 129,
  Xtensa_F14 = 130,
  Xtensa_F15 = 131,
  Xtensa_IBREAKA0 = 132,
  Xtensa_IBREAKA1 = 133,
  Xtensa_M0 = 134,
  Xtensa_M1 = 135,
  Xtensa_M2 = 136,
  Xtensa_M3 = 137,
  Xtensa_MISC0 = 138,
  Xtensa_MISC1 = 139,
  Xtensa_MISC2 = 140,
  Xtensa_MISC3 = 141,
  Xtensa_Q0 = 142,
  Xtensa_Q1 = 143,
  Xtensa_Q2 = 144,
  Xtensa_Q3 = 145,
  Xtensa_Q4 = 146,
  Xtensa_Q5 = 147,
  Xtensa_Q6 = 148,
  Xtensa_Q7 = 149,
  Xtensa_SCOMPARE1 = 150,
  Xtensa_U0 = 151,
  Xtensa_U1 = 152,
  Xtensa_U2 = 153,
  Xtensa_U3 = 154,
  Xtensa_F64R_HI = 155,
  Xtensa_F64R_LO = 156,
  Xtensa_F64S = 157,
  Xtensa_B0_B1 = 158,
  Xtensa_B2_B3 = 159,
  Xtensa_B4_B5 = 160,
  Xtensa_B6_B7 = 161,
  Xtensa_B8_B9 = 162,
  Xtensa_B10_B11 = 163,
  Xtensa_B12_B13 = 164,
  Xtensa_B14_B15 = 165,
  Xtensa_B0_B1_B2_B3 = 166,
  Xtensa_B4_B5_B6_B7 = 167,
  Xtensa_B8_B9_B10_B11 = 168,
  Xtensa_B12_B13_B14_B15 = 169,
  NUM_TARGET_REGS // 170
};

// Register classes

enum {
  Xtensa_BRRegClassID = 0,
  Xtensa_BR2RegClassID = 1,
  Xtensa_BR4RegClassID = 2,
  Xtensa_SRRegClassID = 3,
  Xtensa_ARRegClassID = 4,
  Xtensa_FPRRegClassID = 5,
  Xtensa_URRegClassID = 6,
  Xtensa_MRRegClassID = 7,
  Xtensa_MR01RegClassID = 8,
  Xtensa_MR23RegClassID = 9,
  Xtensa_AE_DRRegClassID = 10,
  Xtensa_AE_VALIGNRegClassID = 11,
  Xtensa_QRRegClassID = 12,

};

// Subregister indices

enum {
  Xtensa_NoSubRegister,
  Xtensa_bsub0,	// 1
  Xtensa_bsub1,	// 2
  Xtensa_bsub2,	// 3
  Xtensa_bsub3,	// 4
  Xtensa_NUM_TARGET_SUBREGS
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
  /* 0 */ -87, 1, 0,
  /* 3 */ -86, 1, 0,
  /* 6 */ -85, 1, 0,
  /* 9 */ -84, 1, 0,
  /* 12 */ -83, 1, 0,
  /* 15 */ -82, 1, 0,
  /* 18 */ -81, 1, 0,
  /* 21 */ -80, 1, 0,
  /* 24 */ -95, 1, 1, 1, 0,
  /* 29 */ -92, 1, 1, 1, 0,
  /* 34 */ -89, 1, 1, 1, 0,
  /* 39 */ -86, 1, 1, 1, 0,
  /* 44 */ 79, 4, 0,
  /* 47 */ 80, 4, 0,
  /* 50 */ 80, 5, 0,
  /* 53 */ 81, 5, 0,
  /* 56 */ 82, 5, 0,
  /* 59 */ 82, 6, 0,
  /* 62 */ 83, 6, 0,
  /* 65 */ 84, 6, 0,
  /* 68 */ 84, 7, 0,
  /* 71 */ 85, 7, 0,
  /* 74 */ 86, 7, 0,
  /* 77 */ 86, 8, 0,
  /* 80 */ 87, 8, 0,
};

static const uint16_t XtensaSubRegIdxLists[] = {
  /* 0 */ 1, 2, 0,
  /* 3 */ 1, 2, 3, 4, 0,
};

static const MCRegisterDesc XtensaRegDesc[] = { // Descriptors
  { 3, 0, 0, 0, 0, 0 },
  { 759, 2, 2, 2, 8192, 8 },
  { 800, 2, 2, 2, 8193, 8 },
  { 917, 2, 2, 2, 8194, 8 },
  { 792, 2, 2, 2, 8195, 8 },
  { 740, 2, 2, 2, 8196, 8 },
  { 865, 2, 2, 2, 8197, 8 },
  { 642, 2, 2, 2, 8198, 8 },
  { 839, 2, 2, 2, 8199, 8 },
  { 697, 2, 2, 2, 8200, 8 },
  { 614, 2, 2, 2, 8201, 8 },
  { 688, 2, 2, 2, 8202, 8 },
  { 834, 2, 2, 2, 8203, 8 },
  { 708, 2, 2, 2, 8204, 8 },
  { 830, 2, 2, 2, 8205, 8 },
  { 745, 2, 2, 2, 8206, 8 },
  { 843, 2, 2, 2, 8207, 8 },
  { 908, 2, 2, 2, 8208, 8 },
  { 629, 2, 2, 2, 8209, 8 },
  { 872, 2, 2, 2, 8210, 8 },
  { 773, 2, 2, 2, 8211, 8 },
  { 817, 2, 2, 2, 8212, 8 },
  { 651, 2, 2, 2, 8213, 8 },
  { 886, 2, 2, 2, 8214, 8 },
  { 735, 2, 2, 2, 8215, 8 },
  { 879, 2, 2, 2, 8216, 8 },
  { 624, 2, 2, 2, 8217, 8 },
  { 669, 2, 2, 2, 8218, 8 },
  { 785, 2, 2, 2, 8219, 8 },
  { 619, 2, 2, 2, 8220, 8 },
  { 862, 2, 2, 2, 8221, 8 },
  { 609, 2, 2, 2, 8222, 8 },
  { 826, 2, 2, 2, 8223, 8 },
  { 726, 2, 2, 2, 8224, 8 },
  { 814, 2, 2, 2, 8225, 8 },
  { 847, 2, 2, 2, 8226, 8 },
  { 717, 2, 2, 2, 8227, 8 },
  { 661, 2, 2, 2, 8228, 8 },
  { 677, 2, 2, 2, 8229, 8 },
  { 896, 2, 2, 2, 8230, 8 },
  { 24, 2, 2, 2, 8231, 8 },
  { 237, 2, 2, 2, 8232, 8 },
  { 317, 2, 2, 2, 8233, 8 },
  { 392, 2, 2, 2, 8234, 8 },
  { 458, 2, 2, 2, 8235, 8 },
  { 497, 2, 2, 2, 8236, 8 },
  { 533, 2, 2, 2, 8237, 8 },
  { 578, 2, 2, 2, 8238, 8 },
  { 592, 2, 2, 2, 8239, 8 },
  { 0, 2, 2, 2, 8240, 8 },
  { 91, 2, 2, 2, 8241, 8 },
  { 219, 2, 2, 2, 8242, 8 },
  { 295, 2, 2, 2, 8243, 8 },
  { 374, 2, 2, 2, 8244, 8 },
  { 428, 2, 2, 2, 8245, 8 },
  { 54, 2, 2, 2, 8246, 8 },
  { 163, 2, 2, 2, 8247, 8 },
  { 254, 2, 2, 2, 8248, 8 },
  { 343, 2, 2, 2, 8249, 8 },
  { 403, 2, 2, 2, 8250, 8 },
  { 472, 2, 2, 2, 8251, 8 },
  { 508, 2, 2, 2, 8252, 8 },
  { 553, 2, 2, 2, 8253, 8 },
  { 584, 2, 2, 2, 8254, 8 },
  { 601, 2, 2, 2, 8255, 8 },
  { 8, 2, 2, 2, 8256, 8 },
  { 109, 2, 2, 2, 8257, 8 },
  { 227, 2, 2, 2, 8258, 8 },
  { 307, 2, 2, 2, 8259, 8 },
  { 382, 2, 2, 2, 8260, 8 },
  { 448, 2, 2, 2, 8261, 8 },
  { 36, 2, 80, 2, 8262, 8 },
  { 140, 2, 77, 2, 8263, 8 },
  { 240, 2, 74, 2, 8264, 8 },
  { 329, 2, 71, 2, 8265, 8 },
  { 395, 2, 71, 2, 8266, 8 },
  { 464, 2, 68, 2, 8267, 8 },
  { 500, 2, 65, 2, 8268, 8 },
  { 545, 2, 62, 2, 8269, 8 },
  { 581, 2, 62, 2, 8270, 8 },
  { 598, 2, 59, 2, 8271, 8 },
  { 4, 2, 56, 2, 8272, 8 },
  { 105, 2, 53, 2, 8273, 8 },
  { 223, 2, 53, 2, 8274, 8 },
  { 303, 2, 50, 2, 8275, 8 },
  { 378, 2, 47, 2, 8276, 8 },
  { 444, 2, 44, 2, 8277, 8 },
  { 69, 2, 2, 2, 8278, 8 },
  { 178, 2, 2, 2, 8279, 8 },
  { 259, 2, 2, 2, 8280, 8 },
  { 59, 2, 2, 2, 8281, 8 },
  { 168, 2, 2, 2, 8282, 8 },
  { 18, 2, 2, 2, 8283, 8 },
  { 119, 2, 2, 2, 8284, 8 },
  { 39, 2, 2, 2, 8285, 8 },
  { 143, 2, 2, 2, 8286, 8 },
  { 152, 2, 2, 2, 8287, 8 },
  { 243, 2, 2, 2, 8288, 8 },
  { 332, 2, 2, 2, 8289, 8 },
  { 398, 2, 2, 2, 8290, 8 },
  { 467, 2, 2, 2, 8291, 8 },
  { 503, 2, 2, 2, 8292, 8 },
  { 548, 2, 2, 2, 8293, 8 },
  { 287, 2, 2, 2, 8294, 8 },
  { 366, 2, 2, 2, 8295, 8 },
  { 423, 2, 2, 2, 8296, 8 },
  { 492, 2, 2, 2, 8297, 8 },
  { 528, 2, 2, 2, 8298, 8 },
  { 573, 2, 2, 2, 8299, 8 },
  { 198, 2, 2, 2, 8300, 8 },
  { 269, 2, 2, 2, 8301, 8 },
  { 348, 2, 2, 2, 8302, 8 },
  { 408, 2, 2, 2, 8303, 8 },
  { 477, 2, 2, 2, 8304, 8 },
  { 513, 2, 2, 2, 8305, 8 },
  { 558, 2, 2, 2, 8306, 8 },
  { 79, 2, 2, 2, 8307, 8 },
  { 207, 2, 2, 2, 8308, 8 },
  { 278, 2, 2, 2, 8309, 8 },
  { 357, 2, 2, 2, 8310, 8 },
  { 417, 2, 2, 2, 8311, 8 },
  { 486, 2, 2, 2, 8312, 8 },
  { 522, 2, 2, 2, 8313, 8 },
  { 567, 2, 2, 2, 8314, 8 },
  { 589, 2, 2, 2, 8315, 8 },
  { 606, 2, 2, 2, 8316, 8 },
  { 14, 2, 2, 2, 8317, 8 },
  { 115, 2, 2, 2, 8318, 8 },
  { 233, 2, 2, 2, 8319, 8 },
  { 313, 2, 2, 2, 8320, 8 },
  { 388, 2, 2, 2, 8321, 8 },
  { 454, 2, 2, 2, 8322, 8 },
  { 27, 2, 2, 2, 8323, 8 },
  { 128, 2, 2, 2, 8324, 8 },
  { 82, 2, 2, 2, 8325, 8 },
  { 210, 2, 2, 2, 8326, 8 },
  { 281, 2, 2, 2, 8327, 8 },
  { 360, 2, 2, 2, 8328, 8 },
  { 48, 2, 2, 2, 8329, 8 },
  { 157, 2, 2, 2, 8330, 8 },
  { 248, 2, 2, 2, 8331, 8 },
  { 337, 2, 2, 2, 8332, 8 },
  { 85, 2, 2, 2, 8333, 8 },
  { 213, 2, 2, 2, 8334, 8 },
  { 284, 2, 2, 2, 8335, 8 },
  { 363, 2, 2, 2, 8336, 8 },
  { 420, 2, 2, 2, 8337, 8 },
  { 489, 2, 2, 2, 8338, 8 },
  { 525, 2, 2, 2, 8339, 8 },
  { 570, 2, 2, 2, 8340, 8 },
  { 188, 2, 2, 2, 8341, 8 },
  { 88, 2, 2, 2, 8342, 8 },
  { 216, 2, 2, 2, 8343, 8 },
  { 292, 2, 2, 2, 8344, 8 },
  { 371, 2, 2, 2, 8345, 8 },
  { 765, 2, 2, 2, 8346, 8 },
  { 806, 2, 2, 2, 8347, 8 },
  { 857, 2, 2, 2, 8348, 8 },
  { 137, 0, 2, 0, 4166, 0 },
  { 326, 3, 2, 0, 4168, 0 },
  { 461, 6, 2, 0, 4170, 0 },
  { 542, 9, 2, 0, 4172, 0 },
  { 595, 12, 2, 0, 4174, 0 },
  { 101, 15, 2, 0, 4176, 0 },
  { 299, 18, 2, 0, 4178, 0 },
  { 440, 21, 2, 0, 4180, 0 },
  { 320, 24, 2, 3, 102470, 3 },
  { 536, 29, 2, 3, 102474, 3 },
  { 95, 34, 2, 3, 102478, 3 },
  { 432, 39, 2, 3, 102482, 3 },
};

  // BR Register Class...
  static const MCPhysReg BR[] = {
    Xtensa_B0, Xtensa_B1, Xtensa_B2, Xtensa_B3, Xtensa_B4, Xtensa_B5, Xtensa_B6, Xtensa_B7, Xtensa_B8, Xtensa_B9, Xtensa_B10, Xtensa_B11, Xtensa_B12, Xtensa_B13, Xtensa_B14, Xtensa_B15, 
  };

  // BR Bit set.
  static const uint8_t BRBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0x7f, 
  };

  // BR2 Register Class...
  static const MCPhysReg BR2[] = {
    Xtensa_B0_B1, Xtensa_B2_B3, Xtensa_B4_B5, Xtensa_B6_B7, Xtensa_B8_B9, Xtensa_B10_B11, Xtensa_B12_B13, Xtensa_B14_B15, 
  };

  // BR2 Bit set.
  static const uint8_t BR2Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 
  };

  // BR4 Register Class...
  static const MCPhysReg BR4[] = {
    Xtensa_B0_B1_B2_B3, Xtensa_B4_B5_B6_B7, Xtensa_B8_B9_B10_B11, Xtensa_B12_B13_B14_B15, 
  };

  // BR4 Bit set.
  static const uint8_t BR4Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x03, 
  };

  // SR Register Class...
  static const MCPhysReg SR[] = {
    Xtensa_LBEG, Xtensa_LEND, Xtensa_LCOUNT, Xtensa_SAR, Xtensa_BREG, Xtensa_LITBASE, Xtensa_SCOMPARE1, Xtensa_ACCLO, Xtensa_ACCHI, Xtensa_M0, Xtensa_M1, Xtensa_M2, Xtensa_M3, Xtensa_WINDOWBASE, Xtensa_WINDOWSTART, Xtensa_IBREAKENABLE, Xtensa_MEMCTL, Xtensa_ATOMCTL, Xtensa_DDR, Xtensa_IBREAKA0, Xtensa_IBREAKA1, Xtensa_DBREAKA0, Xtensa_DBREAKA1, Xtensa_DBREAKC0, Xtensa_DBREAKC1, Xtensa_CONFIGID0, Xtensa_EPC1, Xtensa_EPC2, Xtensa_EPC3, Xtensa_EPC4, Xtensa_EPC5, Xtensa_EPC6, Xtensa_EPC7, Xtensa_DEPC, Xtensa_EPS2, Xtensa_EPS3, Xtensa_EPS4, Xtensa_EPS5, Xtensa_EPS6, Xtensa_EPS7, Xtensa_CONFIGID1, Xtensa_EXCSAVE1, Xtensa_EXCSAVE2, Xtensa_EXCSAVE3, Xtensa_EXCSAVE4, Xtensa_EXCSAVE5, Xtensa_EXCSAVE6, Xtensa_EXCSAVE7, Xtensa_CPENABLE, Xtensa_INTERRUPT, Xtensa_INTCLEAR, Xtensa_INTENABLE, Xtensa_PS, Xtensa_VECBASE, Xtensa_EXCCAUSE, Xtensa_DEBUGCAUSE, Xtensa_CCOUNT, Xtensa_PRID, Xtensa_ICOUNT, Xtensa_ICOUNTLEVEL, Xtensa_EXCVADDR, Xtensa_CCOMPARE0, Xtensa_CCOMPARE1, Xtensa_CCOMPARE2, Xtensa_MISC0, Xtensa_MISC1, Xtensa_MISC2, Xtensa_MISC3, 
  };

  // SR Bit set.
  static const uint8_t SRBits[] = {
    0xf6, 0x1f, 0xfc, 0x7f, 0xe1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0xff, 0xff, 0x0f, 0x00, 0xf0, 0x3f, 0x40, 
  };

  // AR Register Class...
  static const MCPhysReg AR[] = {
    Xtensa_A8, Xtensa_A9, Xtensa_A10, Xtensa_A11, Xtensa_A12, Xtensa_A13, Xtensa_A14, Xtensa_A15, Xtensa_A7, Xtensa_A6, Xtensa_A5, Xtensa_A4, Xtensa_A3, Xtensa_A2, Xtensa_A0, Xtensa_SP, 
  };

  // AR Bit set.
  static const uint8_t ARBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x04, 0xff, 0x7f, 
  };

  // FPR Register Class...
  static const MCPhysReg FPR[] = {
    Xtensa_F8, Xtensa_F9, Xtensa_F10, Xtensa_F11, Xtensa_F12, Xtensa_F13, Xtensa_F14, Xtensa_F15, Xtensa_F7, Xtensa_F6, Xtensa_F5, Xtensa_F4, Xtensa_F3, Xtensa_F2, Xtensa_F1, Xtensa_F0, 
  };

  // FPR Bit set.
  static const uint8_t FPRBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xff, 0x0f, 
  };

  // UR Register Class...
  static const MCPhysReg UR[] = {
    Xtensa_GPIO_OUT, Xtensa_EXPSTATE, Xtensa_THREADPTR, Xtensa_FCR, Xtensa_FSR, Xtensa_F64R_LO, Xtensa_F64R_HI, Xtensa_F64S, Xtensa_ACCX, Xtensa_QACC, Xtensa_FFT_BIT_WIDTH, Xtensa_SAR_BYTE, Xtensa_UA_STATE, 
  };

  // UR Bit set.
  static const uint8_t URBits[] = {
    0x08, 0xe0, 0x03, 0x80, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 
  };

  // MR Register Class...
  static const MCPhysReg MR[] = {
    Xtensa_M0, Xtensa_M1, Xtensa_M2, Xtensa_M3, 
  };

  // MR Bit set.
  static const uint8_t MRBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x03, 
  };

  // MR01 Register Class...
  static const MCPhysReg MR01[] = {
    Xtensa_M0, Xtensa_M1, 
  };

  // MR01 Bit set.
  static const uint8_t MR01Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 
  };

  // MR23 Register Class...
  static const MCPhysReg MR23[] = {
    Xtensa_M2, Xtensa_M3, 
  };

  // MR23 Bit set.
  static const uint8_t MR23Bits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 
  };

  // AE_DR Register Class...
  static const MCPhysReg AE_DR[] = {
    Xtensa_AED0, Xtensa_AED1, Xtensa_AED2, Xtensa_AED3, Xtensa_AED4, Xtensa_AED5, Xtensa_AED6, Xtensa_AED7, Xtensa_AED8, Xtensa_AED9, Xtensa_AED10, Xtensa_AED11, Xtensa_AED12, Xtensa_AED13, Xtensa_AED14, Xtensa_AED15, 
  };

  // AE_DR Bit set.
  static const uint8_t AE_DRBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xff, 0x7f, 
  };

  // AE_VALIGN Register Class...
  static const MCPhysReg AE_VALIGN[] = {
    Xtensa_U0, Xtensa_U1, Xtensa_U2, Xtensa_U3, 
  };

  // AE_VALIGN Bit set.
  static const uint8_t AE_VALIGNBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x07, 
  };

  // QR Register Class...
  static const MCPhysReg QR[] = {
    Xtensa_Q0, Xtensa_Q1, Xtensa_Q2, Xtensa_Q3, Xtensa_Q4, Xtensa_Q5, Xtensa_Q6, Xtensa_Q7, 
  };

  // QR Bit set.
  static const uint8_t QRBits[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x3f, 
  };

static const MCRegisterClass XtensaMCRegisterClasses[] = {
  { BR, BRBits, sizeof(BRBits) },
  { BR2, BR2Bits, sizeof(BR2Bits) },
  { BR4, BR4Bits, sizeof(BR4Bits) },
  { SR, SRBits, sizeof(SRBits) },
  { AR, ARBits, sizeof(ARBits) },
  { FPR, FPRBits, sizeof(FPRBits) },
  { UR, URBits, sizeof(URBits) },
  { MR, MRBits, sizeof(MRBits) },
  { MR01, MR01Bits, sizeof(MR01Bits) },
  { MR23, MR23Bits, sizeof(MR23Bits) },
  { AE_DR, AE_DRBits, sizeof(AE_DRBits) },
  { AE_VALIGN, AE_VALIGNBits, sizeof(AE_VALIGNBits) },
  { QR, QRBits, sizeof(QRBits) },
};

static const uint16_t XtensaRegEncodingTable[] = {
  0,
  17,
  16,
  237,
  99,
  4,
  234,
  224,
  104,
  233,
  192,
  232,
  238,
  230,
  232,
  239,
  233,
  0,
  96,
  236,
  237,
  227,
  228,
  226,
  0,
  2,
  1,
  5,
  97,
  235,
  230,
  238,
  3,
  240,
  1,
  231,
  241,
  231,
  72,
  73,
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
  240,
  241,
  242,
  176,
  208,
  144,
  145,
  160,
  161,
  177,
  178,
  179,
  180,
  181,
  182,
  183,
  194,
  195,
  196,
  197,
  198,
  199,
  209,
  210,
  211,
  212,
  213,
  214,
  215,
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
  128,
  129,
  32,
  33,
  34,
  35,
  244,
  245,
  246,
  247,
  0,
  1,
  2,
  3,
  4,
  5,
  6,
  7,
  12,
  0,
  1,
  2,
  3,
  235,
  234,
  236,
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




/* Capstone Disassembly Engine, https://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/*    Rot127 <unisono@quyllur.org> 2022-2024 */
/* Automatically generated file by Capstone's LLVM TableGen Disassembler Backend. */

/* LLVM-commit: <commit> */
/* LLVM-tag: <tag> */

/* Do not edit. */

/* Capstone's LLVM TableGen Backends: */
/* https://github.com/capstone-engine/llvm-capstone */

#ifdef GET_BANKEDREG_DECL
#endif

#ifdef GET_MCLASSSYSREG_DECL
#endif

#ifdef GET_BANKEDREG_DECL
const ARMBankedReg_BankedReg *ARMBankedReg_lookupBankedRegByName(const char * Name);
const ARMBankedReg_BankedReg *ARMBankedReg_lookupBankedRegByEncoding(uint8_t Encoding);
#endif

#ifdef GET_MCLASSSYSREG_DECL
const ARMSysReg_MClassSysReg *ARMSysReg_lookupMClassSysRegByName(const char * Name);
const ARMSysReg_MClassSysReg *ARMSysReg_lookupMClassSysRegByM1Encoding12(uint16_t M1Encoding12);
const ARMSysReg_MClassSysReg *ARMSysReg_lookupMClassSysRegByM2M3Encoding8(uint16_t M2M3Encoding8);
const ARMSysReg_MClassSysReg *ARMSysReg_lookupMClassSysRegByEncoding(uint16_t Encoding);
#endif

#ifdef GET_BANKEDREG_IMPL
static const ARMBankedReg_BankedReg BankedRegsList[] = {
  { "elr_hyp", { .raw_val = ARM_BANKEDREG_ELR_HYP }, 0x1E }, // 0
  { "lr_abt", { .raw_val = ARM_BANKEDREG_LR_ABT }, 0x14 }, // 1
  { "lr_fiq", { .raw_val = ARM_BANKEDREG_LR_FIQ }, 0xE }, // 2
  { "lr_irq", { .raw_val = ARM_BANKEDREG_LR_IRQ }, 0x10 }, // 3
  { "lr_mon", { .raw_val = ARM_BANKEDREG_LR_MON }, 0x1C }, // 4
  { "lr_svc", { .raw_val = ARM_BANKEDREG_LR_SVC }, 0x12 }, // 5
  { "lr_und", { .raw_val = ARM_BANKEDREG_LR_UND }, 0x16 }, // 6
  { "lr_usr", { .raw_val = ARM_BANKEDREG_LR_USR }, 0x6 }, // 7
  { "r10_fiq", { .raw_val = ARM_BANKEDREG_R10_FIQ }, 0xA }, // 8
  { "r10_usr", { .raw_val = ARM_BANKEDREG_R10_USR }, 0x2 }, // 9
  { "r11_fiq", { .raw_val = ARM_BANKEDREG_R11_FIQ }, 0xB }, // 10
  { "r11_usr", { .raw_val = ARM_BANKEDREG_R11_USR }, 0x3 }, // 11
  { "r12_fiq", { .raw_val = ARM_BANKEDREG_R12_FIQ }, 0xC }, // 12
  { "r12_usr", { .raw_val = ARM_BANKEDREG_R12_USR }, 0x4 }, // 13
  { "r8_fiq", { .raw_val = ARM_BANKEDREG_R8_FIQ }, 0x8 }, // 14
  { "r8_usr", { .raw_val = ARM_BANKEDREG_R8_USR }, 0x0 }, // 15
  { "r9_fiq", { .raw_val = ARM_BANKEDREG_R9_FIQ }, 0x9 }, // 16
  { "r9_usr", { .raw_val = ARM_BANKEDREG_R9_USR }, 0x1 }, // 17
  { "spsr_abt", { .raw_val = ARM_BANKEDREG_SPSR_ABT }, 0x34 }, // 18
  { "spsr_fiq", { .raw_val = ARM_BANKEDREG_SPSR_FIQ }, 0x2E }, // 19
  { "spsr_hyp", { .raw_val = ARM_BANKEDREG_SPSR_HYP }, 0x3E }, // 20
  { "spsr_irq", { .raw_val = ARM_BANKEDREG_SPSR_IRQ }, 0x30 }, // 21
  { "spsr_mon", { .raw_val = ARM_BANKEDREG_SPSR_MON }, 0x3C }, // 22
  { "spsr_svc", { .raw_val = ARM_BANKEDREG_SPSR_SVC }, 0x32 }, // 23
  { "spsr_und", { .raw_val = ARM_BANKEDREG_SPSR_UND }, 0x36 }, // 24
  { "sp_abt", { .raw_val = ARM_BANKEDREG_SP_ABT }, 0x15 }, // 25
  { "sp_fiq", { .raw_val = ARM_BANKEDREG_SP_FIQ }, 0xD }, // 26
  { "sp_hyp", { .raw_val = ARM_BANKEDREG_SP_HYP }, 0x1F }, // 27
  { "sp_irq", { .raw_val = ARM_BANKEDREG_SP_IRQ }, 0x11 }, // 28
  { "sp_mon", { .raw_val = ARM_BANKEDREG_SP_MON }, 0x1D }, // 29
  { "sp_svc", { .raw_val = ARM_BANKEDREG_SP_SVC }, 0x13 }, // 30
  { "sp_und", { .raw_val = ARM_BANKEDREG_SP_UND }, 0x17 }, // 31
  { "sp_usr", { .raw_val = ARM_BANKEDREG_SP_USR }, 0x5 }, // 32
  };

const ARMBankedReg_BankedReg *ARMBankedReg_lookupBankedRegByName(const char * Name) {
  static const struct IndexTypeStr Index[] = {
    { "ELR_HYP", 0 },
    { "LR_ABT", 1 },
    { "LR_FIQ", 2 },
    { "LR_IRQ", 3 },
    { "LR_MON", 4 },
    { "LR_SVC", 5 },
    { "LR_UND", 6 },
    { "LR_USR", 7 },
    { "R10_FIQ", 8 },
    { "R10_USR", 9 },
    { "R11_FIQ", 10 },
    { "R11_USR", 11 },
    { "R12_FIQ", 12 },
    { "R12_USR", 13 },
    { "R8_FIQ", 14 },
    { "R8_USR", 15 },
    { "R9_FIQ", 16 },
    { "R9_USR", 17 },
    { "SPSR_ABT", 18 },
    { "SPSR_FIQ", 19 },
    { "SPSR_HYP", 20 },
    { "SPSR_IRQ", 21 },
    { "SPSR_MON", 22 },
    { "SPSR_SVC", 23 },
    { "SPSR_UND", 24 },
    { "SP_ABT", 25 },
    { "SP_FIQ", 26 },
    { "SP_HYP", 27 },
    { "SP_IRQ", 28 },
    { "SP_MON", 29 },
    { "SP_SVC", 30 },
    { "SP_UND", 31 },
    { "SP_USR", 32 },
  };

   unsigned i = binsearch_IndexTypeStrEncoding(Index, ARR_SIZE(Index), Name);
   if (i == -1)
      return NULL;
   else
      return &BankedRegsList[Index[i].index];
}

const ARMBankedReg_BankedReg *ARMBankedReg_lookupBankedRegByEncoding(uint8_t Encoding) {
  static const struct IndexType Index[] = {
    { 0x0, 15 },
    { 0x1, 17 },
    { 0x2, 9 },
    { 0x3, 11 },
    { 0x4, 13 },
    { 0x5, 32 },
    { 0x6, 7 },
    { 0x8, 14 },
    { 0x9, 16 },
    { 0xA, 8 },
    { 0xB, 10 },
    { 0xC, 12 },
    { 0xD, 26 },
    { 0xE, 2 },
    { 0x10, 3 },
    { 0x11, 28 },
    { 0x12, 5 },
    { 0x13, 30 },
    { 0x14, 1 },
    { 0x15, 25 },
    { 0x16, 6 },
    { 0x17, 31 },
    { 0x1C, 4 },
    { 0x1D, 29 },
    { 0x1E, 0 },
    { 0x1F, 27 },
    { 0x2E, 19 },
    { 0x30, 21 },
    { 0x32, 23 },
    { 0x34, 18 },
    { 0x36, 24 },
    { 0x3C, 22 },
    { 0x3E, 20 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
   if (i == -1)
      return NULL;
   else
      return &BankedRegsList[Index[i].index];
}

#endif

#ifdef GET_MCLASSSYSREG_IMPL
static const ARMSysReg_MClassSysReg MClassSysRegsList[] = {
  { "apsr", { .raw_val = ARM_MCLASSSYSREG_APSR }, 0x800, 0x100, 0x800,  {0}  }, // 0
  { "apsr_g", { .raw_val = ARM_MCLASSSYSREG_APSR_G }, 0x400, 0x0, 0x400,  {ARM_FeatureDSP}  }, // 1
  { "apsr_nzcvq", { .raw_val = ARM_MCLASSSYSREG_APSR_NZCVQ }, 0x1800, 0x200, 0x800,  {0}  }, // 2
  { "apsr_nzcvqg", { .raw_val = ARM_MCLASSSYSREG_APSR_NZCVQG }, 0xC00, 0x300, 0xC00,  {ARM_FeatureDSP}  }, // 3
  { "basepri", { .raw_val = ARM_MCLASSSYSREG_BASEPRI }, 0x811, 0x111, 0x811,  {ARM_HasV7Ops}  }, // 4
  { "basepri_max", { .raw_val = ARM_MCLASSSYSREG_BASEPRI_MAX }, 0x812, 0x112, 0x812,  {ARM_HasV7Ops}  }, // 5
  { "basepri_ns", { .raw_val = ARM_MCLASSSYSREG_BASEPRI_NS }, 0x891, 0x191, 0x891,  {ARM_Feature8MSecExt, ARM_HasV7Ops}  }, // 6
  { "control", { .raw_val = ARM_MCLASSSYSREG_CONTROL }, 0x814, 0x114, 0x814,  {0}  }, // 7
  { "control_ns", { .raw_val = ARM_MCLASSSYSREG_CONTROL_NS }, 0x894, 0x194, 0x894,  {ARM_Feature8MSecExt}  }, // 8
  { "eapsr", { .raw_val = ARM_MCLASSSYSREG_EAPSR }, 0x802, 0x102, 0x802,  {0}  }, // 9
  { "eapsr_g", { .raw_val = ARM_MCLASSSYSREG_EAPSR_G }, 0x402, 0x2, 0x402,  {ARM_FeatureDSP}  }, // 10
  { "eapsr_nzcvq", { .raw_val = ARM_MCLASSSYSREG_EAPSR_NZCVQ }, 0x1802, 0x202, 0x802,  {0}  }, // 11
  { "eapsr_nzcvqg", { .raw_val = ARM_MCLASSSYSREG_EAPSR_NZCVQG }, 0xC02, 0x302, 0xC02,  {ARM_FeatureDSP}  }, // 12
  { "epsr", { .raw_val = ARM_MCLASSSYSREG_EPSR }, 0x806, 0x106, 0x806,  {0}  }, // 13
  { "faultmask", { .raw_val = ARM_MCLASSSYSREG_FAULTMASK }, 0x813, 0x113, 0x813,  {ARM_HasV7Ops}  }, // 14
  { "faultmask_ns", { .raw_val = ARM_MCLASSSYSREG_FAULTMASK_NS }, 0x893, 0x193, 0x893,  {ARM_Feature8MSecExt, ARM_HasV7Ops}  }, // 15
  { "iapsr", { .raw_val = ARM_MCLASSSYSREG_IAPSR }, 0x801, 0x101, 0x801,  {0}  }, // 16
  { "iapsr_g", { .raw_val = ARM_MCLASSSYSREG_IAPSR_G }, 0x401, 0x1, 0x401,  {ARM_FeatureDSP}  }, // 17
  { "iapsr_nzcvq", { .raw_val = ARM_MCLASSSYSREG_IAPSR_NZCVQ }, 0x1801, 0x201, 0x801,  {0}  }, // 18
  { "iapsr_nzcvqg", { .raw_val = ARM_MCLASSSYSREG_IAPSR_NZCVQG }, 0xC01, 0x301, 0xC01,  {ARM_FeatureDSP}  }, // 19
  { "iepsr", { .raw_val = ARM_MCLASSSYSREG_IEPSR }, 0x807, 0x107, 0x807,  {0}  }, // 20
  { "ipsr", { .raw_val = ARM_MCLASSSYSREG_IPSR }, 0x805, 0x105, 0x805,  {0}  }, // 21
  { "msp", { .raw_val = ARM_MCLASSSYSREG_MSP }, 0x808, 0x108, 0x808,  {0}  }, // 22
  { "msplim", { .raw_val = ARM_MCLASSSYSREG_MSPLIM }, 0x80A, 0x10A, 0x80A,  {ARM_HasV8MBaselineOps}  }, // 23
  { "msplim_ns", { .raw_val = ARM_MCLASSSYSREG_MSPLIM_NS }, 0x88A, 0x18A, 0x88A,  {ARM_Feature8MSecExt, ARM_HasV8MBaselineOps}  }, // 24
  { "msp_ns", { .raw_val = ARM_MCLASSSYSREG_MSP_NS }, 0x888, 0x188, 0x888,  {ARM_Feature8MSecExt}  }, // 25
  { "pac_key_p_0", { .raw_val = ARM_MCLASSSYSREG_PAC_KEY_P_0 }, 0x820, 0x120, 0x820,  {ARM_FeaturePACBTI}  }, // 26
  { "pac_key_p_0_ns", { .raw_val = ARM_MCLASSSYSREG_PAC_KEY_P_0_NS }, 0x8A0, 0x1A0, 0x8A0,  {ARM_FeaturePACBTI}  }, // 27
  { "pac_key_p_1", { .raw_val = ARM_MCLASSSYSREG_PAC_KEY_P_1 }, 0x821, 0x121, 0x821,  {ARM_FeaturePACBTI}  }, // 28
  { "pac_key_p_1_ns", { .raw_val = ARM_MCLASSSYSREG_PAC_KEY_P_1_NS }, 0x8A1, 0x1A1, 0x8A1,  {ARM_FeaturePACBTI}  }, // 29
  { "pac_key_p_2", { .raw_val = ARM_MCLASSSYSREG_PAC_KEY_P_2 }, 0x822, 0x122, 0x822,  {ARM_FeaturePACBTI}  }, // 30
  { "pac_key_p_2_ns", { .raw_val = ARM_MCLASSSYSREG_PAC_KEY_P_2_NS }, 0x8A2, 0x1A2, 0x8A2,  {ARM_FeaturePACBTI}  }, // 31
  { "pac_key_p_3", { .raw_val = ARM_MCLASSSYSREG_PAC_KEY_P_3 }, 0x823, 0x123, 0x823,  {ARM_FeaturePACBTI}  }, // 32
  { "pac_key_p_3_ns", { .raw_val = ARM_MCLASSSYSREG_PAC_KEY_P_3_NS }, 0x8A3, 0x1A3, 0x8A3,  {ARM_FeaturePACBTI}  }, // 33
  { "pac_key_u_0", { .raw_val = ARM_MCLASSSYSREG_PAC_KEY_U_0 }, 0x824, 0x124, 0x824,  {ARM_FeaturePACBTI}  }, // 34
  { "pac_key_u_0_ns", { .raw_val = ARM_MCLASSSYSREG_PAC_KEY_U_0_NS }, 0x8A4, 0x1A4, 0x8A4,  {ARM_FeaturePACBTI}  }, // 35
  { "pac_key_u_1", { .raw_val = ARM_MCLASSSYSREG_PAC_KEY_U_1 }, 0x825, 0x125, 0x825,  {ARM_FeaturePACBTI}  }, // 36
  { "pac_key_u_1_ns", { .raw_val = ARM_MCLASSSYSREG_PAC_KEY_U_1_NS }, 0x8A5, 0x1A5, 0x8A5,  {ARM_FeaturePACBTI}  }, // 37
  { "pac_key_u_2", { .raw_val = ARM_MCLASSSYSREG_PAC_KEY_U_2 }, 0x826, 0x126, 0x826,  {ARM_FeaturePACBTI}  }, // 38
  { "pac_key_u_2_ns", { .raw_val = ARM_MCLASSSYSREG_PAC_KEY_U_2_NS }, 0x8A6, 0x1A6, 0x8A6,  {ARM_FeaturePACBTI}  }, // 39
  { "pac_key_u_3", { .raw_val = ARM_MCLASSSYSREG_PAC_KEY_U_3 }, 0x827, 0x127, 0x827,  {ARM_FeaturePACBTI}  }, // 40
  { "pac_key_u_3_ns", { .raw_val = ARM_MCLASSSYSREG_PAC_KEY_U_3_NS }, 0x8A7, 0x1A7, 0x8A7,  {ARM_FeaturePACBTI}  }, // 41
  { "primask", { .raw_val = ARM_MCLASSSYSREG_PRIMASK }, 0x810, 0x110, 0x810,  {0}  }, // 42
  { "primask_ns", { .raw_val = ARM_MCLASSSYSREG_PRIMASK_NS }, 0x890, 0x190, 0x890,  {0}  }, // 43
  { "psp", { .raw_val = ARM_MCLASSSYSREG_PSP }, 0x809, 0x109, 0x809,  {0}  }, // 44
  { "psplim", { .raw_val = ARM_MCLASSSYSREG_PSPLIM }, 0x80B, 0x10B, 0x80B,  {ARM_HasV8MBaselineOps}  }, // 45
  { "psplim_ns", { .raw_val = ARM_MCLASSSYSREG_PSPLIM_NS }, 0x88B, 0x18B, 0x88B,  {ARM_Feature8MSecExt, ARM_HasV8MBaselineOps}  }, // 46
  { "psp_ns", { .raw_val = ARM_MCLASSSYSREG_PSP_NS }, 0x889, 0x189, 0x889,  {ARM_Feature8MSecExt}  }, // 47
  { "sp_ns", { .raw_val = ARM_MCLASSSYSREG_SP_NS }, 0x898, 0x198, 0x898,  {ARM_Feature8MSecExt}  }, // 48
  { "xpsr", { .raw_val = ARM_MCLASSSYSREG_XPSR }, 0x803, 0x103, 0x803,  {0}  }, // 49
  { "xpsr_g", { .raw_val = ARM_MCLASSSYSREG_XPSR_G }, 0x403, 0x3, 0x403,  {ARM_FeatureDSP}  }, // 50
  { "xpsr_nzcvq", { .raw_val = ARM_MCLASSSYSREG_XPSR_NZCVQ }, 0x1803, 0x203, 0x803,  {0}  }, // 51
  { "xpsr_nzcvqg", { .raw_val = ARM_MCLASSSYSREG_XPSR_NZCVQG }, 0xC03, 0x303, 0xC03,  {ARM_FeatureDSP}  }, // 52
  };

const ARMSysReg_MClassSysReg *ARMSysReg_lookupMClassSysRegByName(const char * Name) {
  static const struct IndexTypeStr Index[] = {
    { "APSR", 0 },
    { "APSR_G", 1 },
    { "APSR_NZCVQ", 2 },
    { "APSR_NZCVQG", 3 },
    { "BASEPRI", 4 },
    { "BASEPRI_MAX", 5 },
    { "BASEPRI_NS", 6 },
    { "CONTROL", 7 },
    { "CONTROL_NS", 8 },
    { "EAPSR", 9 },
    { "EAPSR_G", 10 },
    { "EAPSR_NZCVQ", 11 },
    { "EAPSR_NZCVQG", 12 },
    { "EPSR", 13 },
    { "FAULTMASK", 14 },
    { "FAULTMASK_NS", 15 },
    { "IAPSR", 16 },
    { "IAPSR_G", 17 },
    { "IAPSR_NZCVQ", 18 },
    { "IAPSR_NZCVQG", 19 },
    { "IEPSR", 20 },
    { "IPSR", 21 },
    { "MSP", 22 },
    { "MSPLIM", 23 },
    { "MSPLIM_NS", 24 },
    { "MSP_NS", 25 },
    { "PAC_KEY_P_0", 26 },
    { "PAC_KEY_P_0_NS", 27 },
    { "PAC_KEY_P_1", 28 },
    { "PAC_KEY_P_1_NS", 29 },
    { "PAC_KEY_P_2", 30 },
    { "PAC_KEY_P_2_NS", 31 },
    { "PAC_KEY_P_3", 32 },
    { "PAC_KEY_P_3_NS", 33 },
    { "PAC_KEY_U_0", 34 },
    { "PAC_KEY_U_0_NS", 35 },
    { "PAC_KEY_U_1", 36 },
    { "PAC_KEY_U_1_NS", 37 },
    { "PAC_KEY_U_2", 38 },
    { "PAC_KEY_U_2_NS", 39 },
    { "PAC_KEY_U_3", 40 },
    { "PAC_KEY_U_3_NS", 41 },
    { "PRIMASK", 42 },
    { "PRIMASK_NS", 43 },
    { "PSP", 44 },
    { "PSPLIM", 45 },
    { "PSPLIM_NS", 46 },
    { "PSP_NS", 47 },
    { "SP_NS", 48 },
    { "XPSR", 49 },
    { "XPSR_G", 50 },
    { "XPSR_NZCVQ", 51 },
    { "XPSR_NZCVQG", 52 },
  };

   unsigned i = binsearch_IndexTypeStrEncoding(Index, ARR_SIZE(Index), Name);
   if (i == -1)
      return NULL;
   else
      return &MClassSysRegsList[Index[i].index];
}

const ARMSysReg_MClassSysReg *ARMSysReg_lookupMClassSysRegByM1Encoding12(uint16_t M1Encoding12) {
  static const struct IndexType Index[] = {
    { 0x400, 1 },
    { 0x401, 17 },
    { 0x402, 10 },
    { 0x403, 50 },
    { 0x800, 0 },
    { 0x801, 16 },
    { 0x802, 9 },
    { 0x803, 49 },
    { 0x805, 21 },
    { 0x806, 13 },
    { 0x807, 20 },
    { 0x808, 22 },
    { 0x809, 44 },
    { 0x80A, 23 },
    { 0x80B, 45 },
    { 0x810, 42 },
    { 0x811, 4 },
    { 0x812, 5 },
    { 0x813, 14 },
    { 0x814, 7 },
    { 0x820, 26 },
    { 0x821, 28 },
    { 0x822, 30 },
    { 0x823, 32 },
    { 0x824, 34 },
    { 0x825, 36 },
    { 0x826, 38 },
    { 0x827, 40 },
    { 0x888, 25 },
    { 0x889, 47 },
    { 0x88A, 24 },
    { 0x88B, 46 },
    { 0x890, 43 },
    { 0x891, 6 },
    { 0x893, 15 },
    { 0x894, 8 },
    { 0x898, 48 },
    { 0x8A0, 27 },
    { 0x8A1, 29 },
    { 0x8A2, 31 },
    { 0x8A3, 33 },
    { 0x8A4, 35 },
    { 0x8A5, 37 },
    { 0x8A6, 39 },
    { 0x8A7, 41 },
    { 0xC00, 3 },
    { 0xC01, 19 },
    { 0xC02, 12 },
    { 0xC03, 52 },
    { 0x1800, 2 },
    { 0x1801, 18 },
    { 0x1802, 11 },
    { 0x1803, 51 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), M1Encoding12);
   if (i == -1)
      return NULL;
   else
      return &MClassSysRegsList[Index[i].index];
}

const ARMSysReg_MClassSysReg *ARMSysReg_lookupMClassSysRegByM2M3Encoding8(uint16_t M2M3Encoding8) {
  static const struct IndexType Index[] = {
    { 0x0, 1 },
    { 0x1, 17 },
    { 0x2, 10 },
    { 0x3, 50 },
    { 0x100, 0 },
    { 0x101, 16 },
    { 0x102, 9 },
    { 0x103, 49 },
    { 0x105, 21 },
    { 0x106, 13 },
    { 0x107, 20 },
    { 0x108, 22 },
    { 0x109, 44 },
    { 0x10A, 23 },
    { 0x10B, 45 },
    { 0x110, 42 },
    { 0x111, 4 },
    { 0x112, 5 },
    { 0x113, 14 },
    { 0x114, 7 },
    { 0x120, 26 },
    { 0x121, 28 },
    { 0x122, 30 },
    { 0x123, 32 },
    { 0x124, 34 },
    { 0x125, 36 },
    { 0x126, 38 },
    { 0x127, 40 },
    { 0x188, 25 },
    { 0x189, 47 },
    { 0x18A, 24 },
    { 0x18B, 46 },
    { 0x190, 43 },
    { 0x191, 6 },
    { 0x193, 15 },
    { 0x194, 8 },
    { 0x198, 48 },
    { 0x1A0, 27 },
    { 0x1A1, 29 },
    { 0x1A2, 31 },
    { 0x1A3, 33 },
    { 0x1A4, 35 },
    { 0x1A5, 37 },
    { 0x1A6, 39 },
    { 0x1A7, 41 },
    { 0x200, 2 },
    { 0x201, 18 },
    { 0x202, 11 },
    { 0x203, 51 },
    { 0x300, 3 },
    { 0x301, 19 },
    { 0x302, 12 },
    { 0x303, 52 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), M2M3Encoding8);
   if (i == -1)
      return NULL;
   else
      return &MClassSysRegsList[Index[i].index];
}

const ARMSysReg_MClassSysReg *ARMSysReg_lookupMClassSysRegByEncoding(uint16_t Encoding) {
  static const struct IndexType Index[] = {
    { 0x400, 1 },
    { 0x401, 17 },
    { 0x402, 10 },
    { 0x403, 50 },
    { 0x800, 0 },
    { 0x800, 2 },
    { 0x801, 16 },
    { 0x801, 18 },
    { 0x802, 9 },
    { 0x802, 11 },
    { 0x803, 49 },
    { 0x803, 51 },
    { 0x805, 21 },
    { 0x806, 13 },
    { 0x807, 20 },
    { 0x808, 22 },
    { 0x809, 44 },
    { 0x80A, 23 },
    { 0x80B, 45 },
    { 0x810, 42 },
    { 0x811, 4 },
    { 0x812, 5 },
    { 0x813, 14 },
    { 0x814, 7 },
    { 0x820, 26 },
    { 0x821, 28 },
    { 0x822, 30 },
    { 0x823, 32 },
    { 0x824, 34 },
    { 0x825, 36 },
    { 0x826, 38 },
    { 0x827, 40 },
    { 0x888, 25 },
    { 0x889, 47 },
    { 0x88A, 24 },
    { 0x88B, 46 },
    { 0x890, 43 },
    { 0x891, 6 },
    { 0x893, 15 },
    { 0x894, 8 },
    { 0x898, 48 },
    { 0x8A0, 27 },
    { 0x8A1, 29 },
    { 0x8A2, 31 },
    { 0x8A3, 33 },
    { 0x8A4, 35 },
    { 0x8A5, 37 },
    { 0x8A6, 39 },
    { 0x8A7, 41 },
    { 0xC00, 3 },
    { 0xC01, 19 },
    { 0xC02, 12 },
    { 0xC03, 52 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
   if (i == -1)
      return NULL;
   else
      return &MClassSysRegsList[Index[i].index];
}

#endif

#undef GET_BANKEDREG_DECL
#undef GET_BANKEDREG_IMPL
#undef GET_MCLASSSYSREG_DECL
#undef GET_MCLASSSYSREG_IMPL

/* Capstone Disassembly Engine, https://www.capstone-engine.org */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2022, */
/*    Rot127 <unisono@quyllur.org> 2022-2024 */
/* Automatically generated file by Capstone's LLVM TableGen Disassembler Backend. */

/* LLVM-commit: <commit> */
/* LLVM-tag: <tag> */

/* Do not edit. */

/* Capstone's LLVM TableGen Backends: */
/* https://github.com/capstone-engine/llvm-capstone */

#ifdef GET_AT_DECL
#endif

#ifdef GET_BTI_DECL
#endif

#ifdef GET_DB_DECL
#endif

#ifdef GET_DBNXS_DECL
#endif

#ifdef GET_DC_DECL
#endif

#ifdef GET_EXACTFPIMM_DECL
#endif

#ifdef GET_IC_DECL
#endif

#ifdef GET_ISB_DECL
#endif

#ifdef GET_PRFM_DECL
#endif

#ifdef GET_PSB_DECL
#endif

#ifdef GET_PSTATEIMM0_1_DECL
#endif

#ifdef GET_PSTATEIMM0_15_DECL
#endif

#ifdef GET_RPRFM_DECL
#endif

#ifdef GET_SVCR_DECL
#endif

#ifdef GET_SVEPREDPAT_DECL
#endif

#ifdef GET_SVEPRFM_DECL
#endif

#ifdef GET_SVEVECLENSPECIFIER_DECL
#endif

#ifdef GET_SYSREG_DECL
#endif

#ifdef GET_TSB_DECL
#endif

#ifdef GET_TLBITable_DECL
const AArch64TLBI_TLBI *AArch64TLBI_lookupTLBIByEncoding(uint16_t Encoding);
const AArch64TLBI_TLBI *AArch64TLBI_lookupTLBIByName(const char * Name);
#endif

#ifdef GET_AT_DECL
const AArch64AT_AT *AArch64AT_lookupATByName(const char * Name);
const AArch64AT_AT *AArch64AT_lookupATByEncoding(uint16_t Encoding);
#endif

#ifdef GET_BTI_DECL
const AArch64BTIHint_BTI *AArch64BTIHint_lookupBTIByName(const char * Name);
const AArch64BTIHint_BTI *AArch64BTIHint_lookupBTIByEncoding(uint8_t Encoding);
#endif

#ifdef GET_DB_DECL
const AArch64DB_DB *AArch64DB_lookupDBByName(const char * Name);
const AArch64DB_DB *AArch64DB_lookupDBByEncoding(uint8_t Encoding);
#endif

#ifdef GET_DBNXS_DECL
const AArch64DBnXS_DBnXS *AArch64DBnXS_lookupDBnXSByName(const char * Name);
const AArch64DBnXS_DBnXS *AArch64DBnXS_lookupDBnXSByEncoding(uint8_t Encoding);
const AArch64DBnXS_DBnXS *AArch64DBnXS_lookupDBnXSByImmValue(uint8_t ImmValue);
#endif

#ifdef GET_DC_DECL
const AArch64DC_DC *AArch64DC_lookupDCByName(const char * Name);
const AArch64DC_DC *AArch64DC_lookupDCByEncoding(uint16_t Encoding);
#endif

#ifdef GET_EXACTFPIMM_DECL
const AArch64ExactFPImm_ExactFPImm *AArch64ExactFPImm_lookupExactFPImmByEnum(uint8_t Enum);
const AArch64ExactFPImm_ExactFPImm *AArch64ExactFPImm_lookupExactFPImmByRepr(const char * Repr);
#endif

#ifdef GET_IC_DECL
const AArch64IC_IC *AArch64IC_lookupICByName(const char * Name);
const AArch64IC_IC *AArch64IC_lookupICByEncoding(uint16_t Encoding);
#endif

#ifdef GET_ISB_DECL
const AArch64ISB_ISB *AArch64ISB_lookupISBByName(const char * Name);
const AArch64ISB_ISB *AArch64ISB_lookupISBByEncoding(uint8_t Encoding);
#endif

#ifdef GET_PRFM_DECL
const AArch64PRFM_PRFM *AArch64PRFM_lookupPRFMByName(const char * Name);
const AArch64PRFM_PRFM *AArch64PRFM_lookupPRFMByEncoding(uint8_t Encoding);
#endif

#ifdef GET_PSB_DECL
const AArch64PSBHint_PSB *AArch64PSBHint_lookupPSBByName(const char * Name);
const AArch64PSBHint_PSB *AArch64PSBHint_lookupPSBByEncoding(uint8_t Encoding);
#endif

#ifdef GET_PSTATEIMM0_1_DECL
const AArch64PState_PStateImm0_1 *AArch64PState_lookupPStateImm0_1ByName(const char * Name);
const AArch64PState_PStateImm0_1 *AArch64PState_lookupPStateImm0_1ByEncoding(uint16_t Encoding);
#endif

#ifdef GET_PSTATEIMM0_15_DECL
const AArch64PState_PStateImm0_15 *AArch64PState_lookupPStateImm0_15ByName(const char * Name);
const AArch64PState_PStateImm0_15 *AArch64PState_lookupPStateImm0_15ByEncoding(uint8_t Encoding);
#endif

#ifdef GET_RPRFM_DECL
const AArch64RPRFM_RPRFM *AArch64RPRFM_lookupRPRFMByName(const char * Name);
const AArch64RPRFM_RPRFM *AArch64RPRFM_lookupRPRFMByEncoding(uint8_t Encoding);
#endif

#ifdef GET_SVCR_DECL
const AArch64SVCR_SVCR *AArch64SVCR_lookupSVCRByName(const char * Name);
const AArch64SVCR_SVCR *AArch64SVCR_lookupSVCRByEncoding(uint8_t Encoding);
#endif

#ifdef GET_SVEPREDPAT_DECL
const AArch64SVEPredPattern_SVEPREDPAT *AArch64SVEPredPattern_lookupSVEPREDPATByName(const char * Name);
const AArch64SVEPredPattern_SVEPREDPAT *AArch64SVEPredPattern_lookupSVEPREDPATByEncoding(uint8_t Encoding);
#endif

#ifdef GET_SVEPRFM_DECL
const AArch64SVEPRFM_SVEPRFM *AArch64SVEPRFM_lookupSVEPRFMByName(const char * Name);
const AArch64SVEPRFM_SVEPRFM *AArch64SVEPRFM_lookupSVEPRFMByEncoding(uint8_t Encoding);
#endif

#ifdef GET_SVEVECLENSPECIFIER_DECL
const AArch64SVEVecLenSpecifier_SVEVECLENSPECIFIER *AArch64SVEVecLenSpecifier_lookupSVEVECLENSPECIFIERByName(const char * Name);
const AArch64SVEVecLenSpecifier_SVEVECLENSPECIFIER *AArch64SVEVecLenSpecifier_lookupSVEVECLENSPECIFIERByEncoding(uint8_t Encoding);
#endif

#ifdef GET_SYSREG_DECL
const AArch64SysReg_SysReg *AArch64SysReg_lookupSysRegByName(const char * Name);
const AArch64SysReg_SysReg *AArch64SysReg_lookupSysRegByEncoding(uint16_t Encoding);
#endif

#ifdef GET_TSB_DECL
const AArch64TSB_TSB *AArch64TSB_lookupTSBByName(const char * Name);
const AArch64TSB_TSB *AArch64TSB_lookupTSBByEncoding(uint8_t Encoding);
#endif

#ifdef GET_TLBITable_IMPL
static const AArch64TLBI_TLBI TLBITable[] = {
  { "ALLE1", { .raw_val = AARCH64_TLBI_ALLE1 }, 0x243C, false,  {0}  }, // 0
  { "ALLE1IS", { .raw_val = AARCH64_TLBI_ALLE1IS }, 0x241C, false,  {0}  }, // 1
  { "ALLE1ISnXS", { .raw_val = AARCH64_TLBI_ALLE1ISNXS }, 0x249C, false,  { AArch64_FeatureXS }  }, // 2
  { "ALLE1nXS", { .raw_val = AARCH64_TLBI_ALLE1NXS }, 0x24BC, false,  { AArch64_FeatureXS }  }, // 3
  { "ALLE1OS", { .raw_val = AARCH64_TLBI_ALLE1OS }, 0x240C, false,  { AArch64_FeatureTLB_RMI }  }, // 4
  { "ALLE1OSnXS", { .raw_val = AARCH64_TLBI_ALLE1OSNXS }, 0x248C, false,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 5
  { "ALLE2", { .raw_val = AARCH64_TLBI_ALLE2 }, 0x2438, false,  {0}  }, // 6
  { "ALLE2IS", { .raw_val = AARCH64_TLBI_ALLE2IS }, 0x2418, false,  {0}  }, // 7
  { "ALLE2ISnXS", { .raw_val = AARCH64_TLBI_ALLE2ISNXS }, 0x2498, false,  { AArch64_FeatureXS }  }, // 8
  { "ALLE2nXS", { .raw_val = AARCH64_TLBI_ALLE2NXS }, 0x24B8, false,  { AArch64_FeatureXS }  }, // 9
  { "ALLE2OS", { .raw_val = AARCH64_TLBI_ALLE2OS }, 0x2408, false,  { AArch64_FeatureTLB_RMI }  }, // 10
  { "ALLE2OSnXS", { .raw_val = AARCH64_TLBI_ALLE2OSNXS }, 0x2488, false,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 11
  { "ALLE3", { .raw_val = AARCH64_TLBI_ALLE3 }, 0x3438, false,  {0}  }, // 12
  { "ALLE3IS", { .raw_val = AARCH64_TLBI_ALLE3IS }, 0x3418, false,  {0}  }, // 13
  { "ALLE3ISnXS", { .raw_val = AARCH64_TLBI_ALLE3ISNXS }, 0x3498, false,  { AArch64_FeatureXS }  }, // 14
  { "ALLE3nXS", { .raw_val = AARCH64_TLBI_ALLE3NXS }, 0x34B8, false,  { AArch64_FeatureXS }  }, // 15
  { "ALLE3OS", { .raw_val = AARCH64_TLBI_ALLE3OS }, 0x3408, false,  { AArch64_FeatureTLB_RMI }  }, // 16
  { "ALLE3OSnXS", { .raw_val = AARCH64_TLBI_ALLE3OSNXS }, 0x3488, false,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 17
  { "ASIDE1", { .raw_val = AARCH64_TLBI_ASIDE1 }, 0x43A, true,  {0}  }, // 18
  { "ASIDE1IS", { .raw_val = AARCH64_TLBI_ASIDE1IS }, 0x41A, true,  {0}  }, // 19
  { "ASIDE1ISnXS", { .raw_val = AARCH64_TLBI_ASIDE1ISNXS }, 0x49A, true,  { AArch64_FeatureXS }  }, // 20
  { "ASIDE1nXS", { .raw_val = AARCH64_TLBI_ASIDE1NXS }, 0x4BA, true,  { AArch64_FeatureXS }  }, // 21
  { "ASIDE1OS", { .raw_val = AARCH64_TLBI_ASIDE1OS }, 0x40A, true,  { AArch64_FeatureTLB_RMI }  }, // 22
  { "ASIDE1OSnXS", { .raw_val = AARCH64_TLBI_ASIDE1OSNXS }, 0x48A, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 23
  { "IPAS2E1", { .raw_val = AARCH64_TLBI_IPAS2E1 }, 0x2421, true,  {0}  }, // 24
  { "IPAS2E1IS", { .raw_val = AARCH64_TLBI_IPAS2E1IS }, 0x2401, true,  {0}  }, // 25
  { "IPAS2E1ISnXS", { .raw_val = AARCH64_TLBI_IPAS2E1ISNXS }, 0x2481, true,  { AArch64_FeatureXS }  }, // 26
  { "IPAS2E1nXS", { .raw_val = AARCH64_TLBI_IPAS2E1NXS }, 0x24A1, true,  { AArch64_FeatureXS }  }, // 27
  { "IPAS2E1OS", { .raw_val = AARCH64_TLBI_IPAS2E1OS }, 0x2420, true,  { AArch64_FeatureTLB_RMI }  }, // 28
  { "IPAS2E1OSnXS", { .raw_val = AARCH64_TLBI_IPAS2E1OSNXS }, 0x24A0, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 29
  { "IPAS2LE1", { .raw_val = AARCH64_TLBI_IPAS2LE1 }, 0x2425, true,  {0}  }, // 30
  { "IPAS2LE1IS", { .raw_val = AARCH64_TLBI_IPAS2LE1IS }, 0x2405, true,  {0}  }, // 31
  { "IPAS2LE1ISnXS", { .raw_val = AARCH64_TLBI_IPAS2LE1ISNXS }, 0x2485, true,  { AArch64_FeatureXS }  }, // 32
  { "IPAS2LE1nXS", { .raw_val = AARCH64_TLBI_IPAS2LE1NXS }, 0x24A5, true,  { AArch64_FeatureXS }  }, // 33
  { "IPAS2LE1OS", { .raw_val = AARCH64_TLBI_IPAS2LE1OS }, 0x2424, true,  { AArch64_FeatureTLB_RMI }  }, // 34
  { "IPAS2LE1OSnXS", { .raw_val = AARCH64_TLBI_IPAS2LE1OSNXS }, 0x24A4, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 35
  { "PAALL", { .raw_val = AARCH64_TLBI_PAALL }, 0x343C, false,  { AArch64_FeatureRME }  }, // 36
  { "PAALLnXS", { .raw_val = AARCH64_TLBI_PAALLNXS }, 0x34BC, false,  { AArch64_FeatureRME, AArch64_FeatureXS }  }, // 37
  { "PAALLOS", { .raw_val = AARCH64_TLBI_PAALLOS }, 0x340C, false,  { AArch64_FeatureRME }  }, // 38
  { "PAALLOSnXS", { .raw_val = AARCH64_TLBI_PAALLOSNXS }, 0x348C, false,  { AArch64_FeatureRME, AArch64_FeatureXS }  }, // 39
  { "RIPAS2E1", { .raw_val = AARCH64_TLBI_RIPAS2E1 }, 0x2422, true,  { AArch64_FeatureTLB_RMI }  }, // 40
  { "RIPAS2E1IS", { .raw_val = AARCH64_TLBI_RIPAS2E1IS }, 0x2402, true,  { AArch64_FeatureTLB_RMI }  }, // 41
  { "RIPAS2E1ISnXS", { .raw_val = AARCH64_TLBI_RIPAS2E1ISNXS }, 0x2482, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 42
  { "RIPAS2E1nXS", { .raw_val = AARCH64_TLBI_RIPAS2E1NXS }, 0x24A2, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 43
  { "RIPAS2E1OS", { .raw_val = AARCH64_TLBI_RIPAS2E1OS }, 0x2423, true,  { AArch64_FeatureTLB_RMI }  }, // 44
  { "RIPAS2E1OSnXS", { .raw_val = AARCH64_TLBI_RIPAS2E1OSNXS }, 0x24A3, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 45
  { "RIPAS2LE1", { .raw_val = AARCH64_TLBI_RIPAS2LE1 }, 0x2426, true,  { AArch64_FeatureTLB_RMI }  }, // 46
  { "RIPAS2LE1IS", { .raw_val = AARCH64_TLBI_RIPAS2LE1IS }, 0x2406, true,  { AArch64_FeatureTLB_RMI }  }, // 47
  { "RIPAS2LE1ISnXS", { .raw_val = AARCH64_TLBI_RIPAS2LE1ISNXS }, 0x2486, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 48
  { "RIPAS2LE1nXS", { .raw_val = AARCH64_TLBI_RIPAS2LE1NXS }, 0x24A6, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 49
  { "RIPAS2LE1OS", { .raw_val = AARCH64_TLBI_RIPAS2LE1OS }, 0x2427, true,  { AArch64_FeatureTLB_RMI }  }, // 50
  { "RIPAS2LE1OSnXS", { .raw_val = AARCH64_TLBI_RIPAS2LE1OSNXS }, 0x24A7, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 51
  { "RPALOS", { .raw_val = AARCH64_TLBI_RPALOS }, 0x3427, true,  { AArch64_FeatureRME }  }, // 52
  { "RPALOSnXS", { .raw_val = AARCH64_TLBI_RPALOSNXS }, 0x34A7, true,  { AArch64_FeatureRME, AArch64_FeatureXS }  }, // 53
  { "RPAOS", { .raw_val = AARCH64_TLBI_RPAOS }, 0x3423, true,  { AArch64_FeatureRME }  }, // 54
  { "RPAOSnXS", { .raw_val = AARCH64_TLBI_RPAOSNXS }, 0x34A3, true,  { AArch64_FeatureRME, AArch64_FeatureXS }  }, // 55
  { "RVAAE1", { .raw_val = AARCH64_TLBI_RVAAE1 }, 0x433, true,  { AArch64_FeatureTLB_RMI }  }, // 56
  { "RVAAE1IS", { .raw_val = AARCH64_TLBI_RVAAE1IS }, 0x413, true,  { AArch64_FeatureTLB_RMI }  }, // 57
  { "RVAAE1ISnXS", { .raw_val = AARCH64_TLBI_RVAAE1ISNXS }, 0x493, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 58
  { "RVAAE1nXS", { .raw_val = AARCH64_TLBI_RVAAE1NXS }, 0x4B3, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 59
  { "RVAAE1OS", { .raw_val = AARCH64_TLBI_RVAAE1OS }, 0x42B, true,  { AArch64_FeatureTLB_RMI }  }, // 60
  { "RVAAE1OSnXS", { .raw_val = AARCH64_TLBI_RVAAE1OSNXS }, 0x4AB, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 61
  { "RVAALE1", { .raw_val = AARCH64_TLBI_RVAALE1 }, 0x437, true,  { AArch64_FeatureTLB_RMI }  }, // 62
  { "RVAALE1IS", { .raw_val = AARCH64_TLBI_RVAALE1IS }, 0x417, true,  { AArch64_FeatureTLB_RMI }  }, // 63
  { "RVAALE1ISnXS", { .raw_val = AARCH64_TLBI_RVAALE1ISNXS }, 0x497, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 64
  { "RVAALE1nXS", { .raw_val = AARCH64_TLBI_RVAALE1NXS }, 0x4B7, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 65
  { "RVAALE1OS", { .raw_val = AARCH64_TLBI_RVAALE1OS }, 0x42F, true,  { AArch64_FeatureTLB_RMI }  }, // 66
  { "RVAALE1OSnXS", { .raw_val = AARCH64_TLBI_RVAALE1OSNXS }, 0x4AF, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 67
  { "RVAE1", { .raw_val = AARCH64_TLBI_RVAE1 }, 0x431, true,  { AArch64_FeatureTLB_RMI }  }, // 68
  { "RVAE1IS", { .raw_val = AARCH64_TLBI_RVAE1IS }, 0x411, true,  { AArch64_FeatureTLB_RMI }  }, // 69
  { "RVAE1ISnXS", { .raw_val = AARCH64_TLBI_RVAE1ISNXS }, 0x491, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 70
  { "RVAE1nXS", { .raw_val = AARCH64_TLBI_RVAE1NXS }, 0x4B1, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 71
  { "RVAE1OS", { .raw_val = AARCH64_TLBI_RVAE1OS }, 0x429, true,  { AArch64_FeatureTLB_RMI }  }, // 72
  { "RVAE1OSnXS", { .raw_val = AARCH64_TLBI_RVAE1OSNXS }, 0x4A9, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 73
  { "RVAE2", { .raw_val = AARCH64_TLBI_RVAE2 }, 0x2431, true,  { AArch64_FeatureTLB_RMI }  }, // 74
  { "RVAE2IS", { .raw_val = AARCH64_TLBI_RVAE2IS }, 0x2411, true,  { AArch64_FeatureTLB_RMI }  }, // 75
  { "RVAE2ISnXS", { .raw_val = AARCH64_TLBI_RVAE2ISNXS }, 0x2491, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 76
  { "RVAE2nXS", { .raw_val = AARCH64_TLBI_RVAE2NXS }, 0x24B1, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 77
  { "RVAE2OS", { .raw_val = AARCH64_TLBI_RVAE2OS }, 0x2429, true,  { AArch64_FeatureTLB_RMI }  }, // 78
  { "RVAE2OSnXS", { .raw_val = AARCH64_TLBI_RVAE2OSNXS }, 0x24A9, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 79
  { "RVAE3", { .raw_val = AARCH64_TLBI_RVAE3 }, 0x3431, true,  { AArch64_FeatureTLB_RMI }  }, // 80
  { "RVAE3IS", { .raw_val = AARCH64_TLBI_RVAE3IS }, 0x3411, true,  { AArch64_FeatureTLB_RMI }  }, // 81
  { "RVAE3ISnXS", { .raw_val = AARCH64_TLBI_RVAE3ISNXS }, 0x3491, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 82
  { "RVAE3nXS", { .raw_val = AARCH64_TLBI_RVAE3NXS }, 0x34B1, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 83
  { "RVAE3OS", { .raw_val = AARCH64_TLBI_RVAE3OS }, 0x3429, true,  { AArch64_FeatureTLB_RMI }  }, // 84
  { "RVAE3OSnXS", { .raw_val = AARCH64_TLBI_RVAE3OSNXS }, 0x34A9, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 85
  { "RVALE1", { .raw_val = AARCH64_TLBI_RVALE1 }, 0x435, true,  { AArch64_FeatureTLB_RMI }  }, // 86
  { "RVALE1IS", { .raw_val = AARCH64_TLBI_RVALE1IS }, 0x415, true,  { AArch64_FeatureTLB_RMI }  }, // 87
  { "RVALE1ISnXS", { .raw_val = AARCH64_TLBI_RVALE1ISNXS }, 0x495, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 88
  { "RVALE1nXS", { .raw_val = AARCH64_TLBI_RVALE1NXS }, 0x4B5, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 89
  { "RVALE1OS", { .raw_val = AARCH64_TLBI_RVALE1OS }, 0x42D, true,  { AArch64_FeatureTLB_RMI }  }, // 90
  { "RVALE1OSnXS", { .raw_val = AARCH64_TLBI_RVALE1OSNXS }, 0x4AD, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 91
  { "RVALE2", { .raw_val = AARCH64_TLBI_RVALE2 }, 0x2435, true,  { AArch64_FeatureTLB_RMI }  }, // 92
  { "RVALE2IS", { .raw_val = AARCH64_TLBI_RVALE2IS }, 0x2415, true,  { AArch64_FeatureTLB_RMI }  }, // 93
  { "RVALE2ISnXS", { .raw_val = AARCH64_TLBI_RVALE2ISNXS }, 0x2495, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 94
  { "RVALE2nXS", { .raw_val = AARCH64_TLBI_RVALE2NXS }, 0x24B5, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 95
  { "RVALE2OS", { .raw_val = AARCH64_TLBI_RVALE2OS }, 0x242D, true,  { AArch64_FeatureTLB_RMI }  }, // 96
  { "RVALE2OSnXS", { .raw_val = AARCH64_TLBI_RVALE2OSNXS }, 0x24AD, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 97
  { "RVALE3", { .raw_val = AARCH64_TLBI_RVALE3 }, 0x3435, true,  { AArch64_FeatureTLB_RMI }  }, // 98
  { "RVALE3IS", { .raw_val = AARCH64_TLBI_RVALE3IS }, 0x3415, true,  { AArch64_FeatureTLB_RMI }  }, // 99
  { "RVALE3ISnXS", { .raw_val = AARCH64_TLBI_RVALE3ISNXS }, 0x3495, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 100
  { "RVALE3nXS", { .raw_val = AARCH64_TLBI_RVALE3NXS }, 0x34B5, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 101
  { "RVALE3OS", { .raw_val = AARCH64_TLBI_RVALE3OS }, 0x342D, true,  { AArch64_FeatureTLB_RMI }  }, // 102
  { "RVALE3OSnXS", { .raw_val = AARCH64_TLBI_RVALE3OSNXS }, 0x34AD, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 103
  { "VAAE1", { .raw_val = AARCH64_TLBI_VAAE1 }, 0x43B, true,  {0}  }, // 104
  { "VAAE1IS", { .raw_val = AARCH64_TLBI_VAAE1IS }, 0x41B, true,  {0}  }, // 105
  { "VAAE1ISnXS", { .raw_val = AARCH64_TLBI_VAAE1ISNXS }, 0x49B, true,  { AArch64_FeatureXS }  }, // 106
  { "VAAE1nXS", { .raw_val = AARCH64_TLBI_VAAE1NXS }, 0x4BB, true,  { AArch64_FeatureXS }  }, // 107
  { "VAAE1OS", { .raw_val = AARCH64_TLBI_VAAE1OS }, 0x40B, true,  { AArch64_FeatureTLB_RMI }  }, // 108
  { "VAAE1OSnXS", { .raw_val = AARCH64_TLBI_VAAE1OSNXS }, 0x48B, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 109
  { "VAALE1", { .raw_val = AARCH64_TLBI_VAALE1 }, 0x43F, true,  {0}  }, // 110
  { "VAALE1IS", { .raw_val = AARCH64_TLBI_VAALE1IS }, 0x41F, true,  {0}  }, // 111
  { "VAALE1ISnXS", { .raw_val = AARCH64_TLBI_VAALE1ISNXS }, 0x49F, true,  { AArch64_FeatureXS }  }, // 112
  { "VAALE1nXS", { .raw_val = AARCH64_TLBI_VAALE1NXS }, 0x4BF, true,  { AArch64_FeatureXS }  }, // 113
  { "VAALE1OS", { .raw_val = AARCH64_TLBI_VAALE1OS }, 0x40F, true,  { AArch64_FeatureTLB_RMI }  }, // 114
  { "VAALE1OSnXS", { .raw_val = AARCH64_TLBI_VAALE1OSNXS }, 0x48F, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 115
  { "VAE1", { .raw_val = AARCH64_TLBI_VAE1 }, 0x439, true,  {0}  }, // 116
  { "VAE1IS", { .raw_val = AARCH64_TLBI_VAE1IS }, 0x419, true,  {0}  }, // 117
  { "VAE1ISnXS", { .raw_val = AARCH64_TLBI_VAE1ISNXS }, 0x499, true,  { AArch64_FeatureXS }  }, // 118
  { "VAE1nXS", { .raw_val = AARCH64_TLBI_VAE1NXS }, 0x4B9, true,  { AArch64_FeatureXS }  }, // 119
  { "VAE1OS", { .raw_val = AARCH64_TLBI_VAE1OS }, 0x409, true,  { AArch64_FeatureTLB_RMI }  }, // 120
  { "VAE1OSnXS", { .raw_val = AARCH64_TLBI_VAE1OSNXS }, 0x489, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 121
  { "VAE2", { .raw_val = AARCH64_TLBI_VAE2 }, 0x2439, true,  {0}  }, // 122
  { "VAE2IS", { .raw_val = AARCH64_TLBI_VAE2IS }, 0x2419, true,  {0}  }, // 123
  { "VAE2ISnXS", { .raw_val = AARCH64_TLBI_VAE2ISNXS }, 0x2499, true,  { AArch64_FeatureXS }  }, // 124
  { "VAE2nXS", { .raw_val = AARCH64_TLBI_VAE2NXS }, 0x24B9, true,  { AArch64_FeatureXS }  }, // 125
  { "VAE2OS", { .raw_val = AARCH64_TLBI_VAE2OS }, 0x2409, true,  { AArch64_FeatureTLB_RMI }  }, // 126
  { "VAE2OSnXS", { .raw_val = AARCH64_TLBI_VAE2OSNXS }, 0x2489, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 127
  { "VAE3", { .raw_val = AARCH64_TLBI_VAE3 }, 0x3439, true,  {0}  }, // 128
  { "VAE3IS", { .raw_val = AARCH64_TLBI_VAE3IS }, 0x3419, true,  {0}  }, // 129
  { "VAE3ISnXS", { .raw_val = AARCH64_TLBI_VAE3ISNXS }, 0x3499, true,  { AArch64_FeatureXS }  }, // 130
  { "VAE3nXS", { .raw_val = AARCH64_TLBI_VAE3NXS }, 0x34B9, true,  { AArch64_FeatureXS }  }, // 131
  { "VAE3OS", { .raw_val = AARCH64_TLBI_VAE3OS }, 0x3409, true,  { AArch64_FeatureTLB_RMI }  }, // 132
  { "VAE3OSnXS", { .raw_val = AARCH64_TLBI_VAE3OSNXS }, 0x3489, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 133
  { "VALE1", { .raw_val = AARCH64_TLBI_VALE1 }, 0x43D, true,  {0}  }, // 134
  { "VALE1IS", { .raw_val = AARCH64_TLBI_VALE1IS }, 0x41D, true,  {0}  }, // 135
  { "VALE1ISnXS", { .raw_val = AARCH64_TLBI_VALE1ISNXS }, 0x49D, true,  { AArch64_FeatureXS }  }, // 136
  { "VALE1nXS", { .raw_val = AARCH64_TLBI_VALE1NXS }, 0x4BD, true,  { AArch64_FeatureXS }  }, // 137
  { "VALE1OS", { .raw_val = AARCH64_TLBI_VALE1OS }, 0x40D, true,  { AArch64_FeatureTLB_RMI }  }, // 138
  { "VALE1OSnXS", { .raw_val = AARCH64_TLBI_VALE1OSNXS }, 0x48D, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 139
  { "VALE2", { .raw_val = AARCH64_TLBI_VALE2 }, 0x243D, true,  {0}  }, // 140
  { "VALE2IS", { .raw_val = AARCH64_TLBI_VALE2IS }, 0x241D, true,  {0}  }, // 141
  { "VALE2ISnXS", { .raw_val = AARCH64_TLBI_VALE2ISNXS }, 0x249D, true,  { AArch64_FeatureXS }  }, // 142
  { "VALE2nXS", { .raw_val = AARCH64_TLBI_VALE2NXS }, 0x24BD, true,  { AArch64_FeatureXS }  }, // 143
  { "VALE2OS", { .raw_val = AARCH64_TLBI_VALE2OS }, 0x240D, true,  { AArch64_FeatureTLB_RMI }  }, // 144
  { "VALE2OSnXS", { .raw_val = AARCH64_TLBI_VALE2OSNXS }, 0x248D, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 145
  { "VALE3", { .raw_val = AARCH64_TLBI_VALE3 }, 0x343D, true,  {0}  }, // 146
  { "VALE3IS", { .raw_val = AARCH64_TLBI_VALE3IS }, 0x341D, true,  {0}  }, // 147
  { "VALE3ISnXS", { .raw_val = AARCH64_TLBI_VALE3ISNXS }, 0x349D, true,  { AArch64_FeatureXS }  }, // 148
  { "VALE3nXS", { .raw_val = AARCH64_TLBI_VALE3NXS }, 0x34BD, true,  { AArch64_FeatureXS }  }, // 149
  { "VALE3OS", { .raw_val = AARCH64_TLBI_VALE3OS }, 0x340D, true,  { AArch64_FeatureTLB_RMI }  }, // 150
  { "VALE3OSnXS", { .raw_val = AARCH64_TLBI_VALE3OSNXS }, 0x348D, true,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 151
  { "VMALLE1", { .raw_val = AARCH64_TLBI_VMALLE1 }, 0x438, false,  {0}  }, // 152
  { "VMALLE1IS", { .raw_val = AARCH64_TLBI_VMALLE1IS }, 0x418, false,  {0}  }, // 153
  { "VMALLE1ISnXS", { .raw_val = AARCH64_TLBI_VMALLE1ISNXS }, 0x498, false,  { AArch64_FeatureXS }  }, // 154
  { "VMALLE1nXS", { .raw_val = AARCH64_TLBI_VMALLE1NXS }, 0x4B8, false,  { AArch64_FeatureXS }  }, // 155
  { "VMALLE1OS", { .raw_val = AARCH64_TLBI_VMALLE1OS }, 0x408, false,  { AArch64_FeatureTLB_RMI }  }, // 156
  { "VMALLE1OSnXS", { .raw_val = AARCH64_TLBI_VMALLE1OSNXS }, 0x488, false,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 157
  { "VMALLS12E1", { .raw_val = AARCH64_TLBI_VMALLS12E1 }, 0x243E, false,  {0}  }, // 158
  { "VMALLS12E1IS", { .raw_val = AARCH64_TLBI_VMALLS12E1IS }, 0x241E, false,  {0}  }, // 159
  { "VMALLS12E1ISnXS", { .raw_val = AARCH64_TLBI_VMALLS12E1ISNXS }, 0x249E, false,  { AArch64_FeatureXS }  }, // 160
  { "VMALLS12E1nXS", { .raw_val = AARCH64_TLBI_VMALLS12E1NXS }, 0x24BE, false,  { AArch64_FeatureXS }  }, // 161
  { "VMALLS12E1OS", { .raw_val = AARCH64_TLBI_VMALLS12E1OS }, 0x240E, false,  { AArch64_FeatureTLB_RMI }  }, // 162
  { "VMALLS12E1OSnXS", { .raw_val = AARCH64_TLBI_VMALLS12E1OSNXS }, 0x248E, false,  { AArch64_FeatureTLB_RMI, AArch64_FeatureXS }  }, // 163
  { "VMALLWS2E1", { .raw_val = AARCH64_TLBI_VMALLWS2E1 }, 0x2432, false,  { AArch64_FeatureTLBIW }  }, // 164
  { "VMALLWS2E1IS", { .raw_val = AARCH64_TLBI_VMALLWS2E1IS }, 0x2412, false,  { AArch64_FeatureTLBIW }  }, // 165
  { "VMALLWS2E1ISnXS", { .raw_val = AARCH64_TLBI_VMALLWS2E1ISNXS }, 0x2492, false,  { AArch64_FeatureTLBIW, AArch64_FeatureXS }  }, // 166
  { "VMALLWS2E1nXS", { .raw_val = AARCH64_TLBI_VMALLWS2E1NXS }, 0x24B2, false,  { AArch64_FeatureTLBIW, AArch64_FeatureXS }  }, // 167
  { "VMALLWS2E1OS", { .raw_val = AARCH64_TLBI_VMALLWS2E1OS }, 0x242A, false,  { AArch64_FeatureTLBIW }  }, // 168
  { "VMALLWS2E1OSnXS", { .raw_val = AARCH64_TLBI_VMALLWS2E1OSNXS }, 0x24AA, false,  { AArch64_FeatureTLBIW, AArch64_FeatureXS }  }, // 169
  };

const AArch64TLBI_TLBI *AArch64TLBI_lookupTLBIByEncoding(uint16_t Encoding) {
  static const struct IndexType Index[] = {
    { 0x408, 156 },
    { 0x409, 120 },
    { 0x40A, 22 },
    { 0x40B, 108 },
    { 0x40D, 138 },
    { 0x40F, 114 },
    { 0x411, 69 },
    { 0x413, 57 },
    { 0x415, 87 },
    { 0x417, 63 },
    { 0x418, 153 },
    { 0x419, 117 },
    { 0x41A, 19 },
    { 0x41B, 105 },
    { 0x41D, 135 },
    { 0x41F, 111 },
    { 0x429, 72 },
    { 0x42B, 60 },
    { 0x42D, 90 },
    { 0x42F, 66 },
    { 0x431, 68 },
    { 0x433, 56 },
    { 0x435, 86 },
    { 0x437, 62 },
    { 0x438, 152 },
    { 0x439, 116 },
    { 0x43A, 18 },
    { 0x43B, 104 },
    { 0x43D, 134 },
    { 0x43F, 110 },
    { 0x488, 157 },
    { 0x489, 121 },
    { 0x48A, 23 },
    { 0x48B, 109 },
    { 0x48D, 139 },
    { 0x48F, 115 },
    { 0x491, 70 },
    { 0x493, 58 },
    { 0x495, 88 },
    { 0x497, 64 },
    { 0x498, 154 },
    { 0x499, 118 },
    { 0x49A, 20 },
    { 0x49B, 106 },
    { 0x49D, 136 },
    { 0x49F, 112 },
    { 0x4A9, 73 },
    { 0x4AB, 61 },
    { 0x4AD, 91 },
    { 0x4AF, 67 },
    { 0x4B1, 71 },
    { 0x4B3, 59 },
    { 0x4B5, 89 },
    { 0x4B7, 65 },
    { 0x4B8, 155 },
    { 0x4B9, 119 },
    { 0x4BA, 21 },
    { 0x4BB, 107 },
    { 0x4BD, 137 },
    { 0x4BF, 113 },
    { 0x2401, 25 },
    { 0x2402, 41 },
    { 0x2405, 31 },
    { 0x2406, 47 },
    { 0x2408, 10 },
    { 0x2409, 126 },
    { 0x240C, 4 },
    { 0x240D, 144 },
    { 0x240E, 162 },
    { 0x2411, 75 },
    { 0x2412, 165 },
    { 0x2415, 93 },
    { 0x2418, 7 },
    { 0x2419, 123 },
    { 0x241C, 1 },
    { 0x241D, 141 },
    { 0x241E, 159 },
    { 0x2420, 28 },
    { 0x2421, 24 },
    { 0x2422, 40 },
    { 0x2423, 44 },
    { 0x2424, 34 },
    { 0x2425, 30 },
    { 0x2426, 46 },
    { 0x2427, 50 },
    { 0x2429, 78 },
    { 0x242A, 168 },
    { 0x242D, 96 },
    { 0x2431, 74 },
    { 0x2432, 164 },
    { 0x2435, 92 },
    { 0x2438, 6 },
    { 0x2439, 122 },
    { 0x243C, 0 },
    { 0x243D, 140 },
    { 0x243E, 158 },
    { 0x2481, 26 },
    { 0x2482, 42 },
    { 0x2485, 32 },
    { 0x2486, 48 },
    { 0x2488, 11 },
    { 0x2489, 127 },
    { 0x248C, 5 },
    { 0x248D, 145 },
    { 0x248E, 163 },
    { 0x2491, 76 },
    { 0x2492, 166 },
    { 0x2495, 94 },
    { 0x2498, 8 },
    { 0x2499, 124 },
    { 0x249C, 2 },
    { 0x249D, 142 },
    { 0x249E, 160 },
    { 0x24A0, 29 },
    { 0x24A1, 27 },
    { 0x24A2, 43 },
    { 0x24A3, 45 },
    { 0x24A4, 35 },
    { 0x24A5, 33 },
    { 0x24A6, 49 },
    { 0x24A7, 51 },
    { 0x24A9, 79 },
    { 0x24AA, 169 },
    { 0x24AD, 97 },
    { 0x24B1, 77 },
    { 0x24B2, 167 },
    { 0x24B5, 95 },
    { 0x24B8, 9 },
    { 0x24B9, 125 },
    { 0x24BC, 3 },
    { 0x24BD, 143 },
    { 0x24BE, 161 },
    { 0x3408, 16 },
    { 0x3409, 132 },
    { 0x340C, 38 },
    { 0x340D, 150 },
    { 0x3411, 81 },
    { 0x3415, 99 },
    { 0x3418, 13 },
    { 0x3419, 129 },
    { 0x341D, 147 },
    { 0x3423, 54 },
    { 0x3427, 52 },
    { 0x3429, 84 },
    { 0x342D, 102 },
    { 0x3431, 80 },
    { 0x3435, 98 },
    { 0x3438, 12 },
    { 0x3439, 128 },
    { 0x343C, 36 },
    { 0x343D, 146 },
    { 0x3488, 17 },
    { 0x3489, 133 },
    { 0x348C, 39 },
    { 0x348D, 151 },
    { 0x3491, 82 },
    { 0x3495, 100 },
    { 0x3498, 14 },
    { 0x3499, 130 },
    { 0x349D, 148 },
    { 0x34A3, 55 },
    { 0x34A7, 53 },
    { 0x34A9, 85 },
    { 0x34AD, 103 },
    { 0x34B1, 83 },
    { 0x34B5, 101 },
    { 0x34B8, 15 },
    { 0x34B9, 131 },
    { 0x34BC, 37 },
    { 0x34BD, 149 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
   if (i == -1)
      return NULL;
   else
      return &TLBITable[Index[i].index];
}

const AArch64TLBI_TLBI *AArch64TLBI_lookupTLBIByName(const char * Name) {
  static const struct IndexTypeStr Index[] = {
    { "ALLE1", 0 },
    { "ALLE1IS", 1 },
    { "ALLE1ISNXS", 2 },
    { "ALLE1NXS", 3 },
    { "ALLE1OS", 4 },
    { "ALLE1OSNXS", 5 },
    { "ALLE2", 6 },
    { "ALLE2IS", 7 },
    { "ALLE2ISNXS", 8 },
    { "ALLE2NXS", 9 },
    { "ALLE2OS", 10 },
    { "ALLE2OSNXS", 11 },
    { "ALLE3", 12 },
    { "ALLE3IS", 13 },
    { "ALLE3ISNXS", 14 },
    { "ALLE3NXS", 15 },
    { "ALLE3OS", 16 },
    { "ALLE3OSNXS", 17 },
    { "ASIDE1", 18 },
    { "ASIDE1IS", 19 },
    { "ASIDE1ISNXS", 20 },
    { "ASIDE1NXS", 21 },
    { "ASIDE1OS", 22 },
    { "ASIDE1OSNXS", 23 },
    { "IPAS2E1", 24 },
    { "IPAS2E1IS", 25 },
    { "IPAS2E1ISNXS", 26 },
    { "IPAS2E1NXS", 27 },
    { "IPAS2E1OS", 28 },
    { "IPAS2E1OSNXS", 29 },
    { "IPAS2LE1", 30 },
    { "IPAS2LE1IS", 31 },
    { "IPAS2LE1ISNXS", 32 },
    { "IPAS2LE1NXS", 33 },
    { "IPAS2LE1OS", 34 },
    { "IPAS2LE1OSNXS", 35 },
    { "PAALL", 36 },
    { "PAALLNXS", 37 },
    { "PAALLOS", 38 },
    { "PAALLOSNXS", 39 },
    { "RIPAS2E1", 40 },
    { "RIPAS2E1IS", 41 },
    { "RIPAS2E1ISNXS", 42 },
    { "RIPAS2E1NXS", 43 },
    { "RIPAS2E1OS", 44 },
    { "RIPAS2E1OSNXS", 45 },
    { "RIPAS2LE1", 46 },
    { "RIPAS2LE1IS", 47 },
    { "RIPAS2LE1ISNXS", 48 },
    { "RIPAS2LE1NXS", 49 },
    { "RIPAS2LE1OS", 50 },
    { "RIPAS2LE1OSNXS", 51 },
    { "RPALOS", 52 },
    { "RPALOSNXS", 53 },
    { "RPAOS", 54 },
    { "RPAOSNXS", 55 },
    { "RVAAE1", 56 },
    { "RVAAE1IS", 57 },
    { "RVAAE1ISNXS", 58 },
    { "RVAAE1NXS", 59 },
    { "RVAAE1OS", 60 },
    { "RVAAE1OSNXS", 61 },
    { "RVAALE1", 62 },
    { "RVAALE1IS", 63 },
    { "RVAALE1ISNXS", 64 },
    { "RVAALE1NXS", 65 },
    { "RVAALE1OS", 66 },
    { "RVAALE1OSNXS", 67 },
    { "RVAE1", 68 },
    { "RVAE1IS", 69 },
    { "RVAE1ISNXS", 70 },
    { "RVAE1NXS", 71 },
    { "RVAE1OS", 72 },
    { "RVAE1OSNXS", 73 },
    { "RVAE2", 74 },
    { "RVAE2IS", 75 },
    { "RVAE2ISNXS", 76 },
    { "RVAE2NXS", 77 },
    { "RVAE2OS", 78 },
    { "RVAE2OSNXS", 79 },
    { "RVAE3", 80 },
    { "RVAE3IS", 81 },
    { "RVAE3ISNXS", 82 },
    { "RVAE3NXS", 83 },
    { "RVAE3OS", 84 },
    { "RVAE3OSNXS", 85 },
    { "RVALE1", 86 },
    { "RVALE1IS", 87 },
    { "RVALE1ISNXS", 88 },
    { "RVALE1NXS", 89 },
    { "RVALE1OS", 90 },
    { "RVALE1OSNXS", 91 },
    { "RVALE2", 92 },
    { "RVALE2IS", 93 },
    { "RVALE2ISNXS", 94 },
    { "RVALE2NXS", 95 },
    { "RVALE2OS", 96 },
    { "RVALE2OSNXS", 97 },
    { "RVALE3", 98 },
    { "RVALE3IS", 99 },
    { "RVALE3ISNXS", 100 },
    { "RVALE3NXS", 101 },
    { "RVALE3OS", 102 },
    { "RVALE3OSNXS", 103 },
    { "VAAE1", 104 },
    { "VAAE1IS", 105 },
    { "VAAE1ISNXS", 106 },
    { "VAAE1NXS", 107 },
    { "VAAE1OS", 108 },
    { "VAAE1OSNXS", 109 },
    { "VAALE1", 110 },
    { "VAALE1IS", 111 },
    { "VAALE1ISNXS", 112 },
    { "VAALE1NXS", 113 },
    { "VAALE1OS", 114 },
    { "VAALE1OSNXS", 115 },
    { "VAE1", 116 },
    { "VAE1IS", 117 },
    { "VAE1ISNXS", 118 },
    { "VAE1NXS", 119 },
    { "VAE1OS", 120 },
    { "VAE1OSNXS", 121 },
    { "VAE2", 122 },
    { "VAE2IS", 123 },
    { "VAE2ISNXS", 124 },
    { "VAE2NXS", 125 },
    { "VAE2OS", 126 },
    { "VAE2OSNXS", 127 },
    { "VAE3", 128 },
    { "VAE3IS", 129 },
    { "VAE3ISNXS", 130 },
    { "VAE3NXS", 131 },
    { "VAE3OS", 132 },
    { "VAE3OSNXS", 133 },
    { "VALE1", 134 },
    { "VALE1IS", 135 },
    { "VALE1ISNXS", 136 },
    { "VALE1NXS", 137 },
    { "VALE1OS", 138 },
    { "VALE1OSNXS", 139 },
    { "VALE2", 140 },
    { "VALE2IS", 141 },
    { "VALE2ISNXS", 142 },
    { "VALE2NXS", 143 },
    { "VALE2OS", 144 },
    { "VALE2OSNXS", 145 },
    { "VALE3", 146 },
    { "VALE3IS", 147 },
    { "VALE3ISNXS", 148 },
    { "VALE3NXS", 149 },
    { "VALE3OS", 150 },
    { "VALE3OSNXS", 151 },
    { "VMALLE1", 152 },
    { "VMALLE1IS", 153 },
    { "VMALLE1ISNXS", 154 },
    { "VMALLE1NXS", 155 },
    { "VMALLE1OS", 156 },
    { "VMALLE1OSNXS", 157 },
    { "VMALLS12E1", 158 },
    { "VMALLS12E1IS", 159 },
    { "VMALLS12E1ISNXS", 160 },
    { "VMALLS12E1NXS", 161 },
    { "VMALLS12E1OS", 162 },
    { "VMALLS12E1OSNXS", 163 },
    { "VMALLWS2E1", 164 },
    { "VMALLWS2E1IS", 165 },
    { "VMALLWS2E1ISNXS", 166 },
    { "VMALLWS2E1NXS", 167 },
    { "VMALLWS2E1OS", 168 },
    { "VMALLWS2E1OSNXS", 169 },
  };

   unsigned i = binsearch_IndexTypeStrEncoding(Index, ARR_SIZE(Index), Name);
   if (i == -1)
      return NULL;
   else
      return &TLBITable[Index[i].index];
}

#endif

#ifdef GET_AT_IMPL
static const AArch64AT_AT ATsList[] = {
  { "S12E0R", { .raw_val = AARCH64_AT_S12E0R }, 0x23C6,  {0}  }, // 0
  { "S12E0W", { .raw_val = AARCH64_AT_S12E0W }, 0x23C7,  {0}  }, // 1
  { "S12E1R", { .raw_val = AARCH64_AT_S12E1R }, 0x23C4,  {0}  }, // 2
  { "S12E1W", { .raw_val = AARCH64_AT_S12E1W }, 0x23C5,  {0}  }, // 3
  { "S1E0R", { .raw_val = AARCH64_AT_S1E0R }, 0x3C2,  {0}  }, // 4
  { "S1E0W", { .raw_val = AARCH64_AT_S1E0W }, 0x3C3,  {0}  }, // 5
  { "S1E1A", { .raw_val = AARCH64_AT_S1E1A }, 0x3CA,  {0}  }, // 6
  { "S1E1R", { .raw_val = AARCH64_AT_S1E1R }, 0x3C0,  {0}  }, // 7
  { "S1E1RP", { .raw_val = AARCH64_AT_S1E1RP }, 0x3C8,  {AArch64_FeaturePAN_RWV}  }, // 8
  { "S1E1W", { .raw_val = AARCH64_AT_S1E1W }, 0x3C1,  {0}  }, // 9
  { "S1E1WP", { .raw_val = AARCH64_AT_S1E1WP }, 0x3C9,  {AArch64_FeaturePAN_RWV}  }, // 10
  { "S1E2A", { .raw_val = AARCH64_AT_S1E2A }, 0x23CA,  {0}  }, // 11
  { "S1E2R", { .raw_val = AARCH64_AT_S1E2R }, 0x23C0,  {0}  }, // 12
  { "S1E2W", { .raw_val = AARCH64_AT_S1E2W }, 0x23C1,  {0}  }, // 13
  { "S1E3A", { .raw_val = AARCH64_AT_S1E3A }, 0x33CA,  {0}  }, // 14
  { "S1E3R", { .raw_val = AARCH64_AT_S1E3R }, 0x33C0,  {0}  }, // 15
  { "S1E3W", { .raw_val = AARCH64_AT_S1E3W }, 0x33C1,  {0}  }, // 16
  };

const AArch64AT_AT *AArch64AT_lookupATByName(const char * Name) {
  static const struct IndexTypeStr Index[] = {
    { "S12E0R", 0 },
    { "S12E0W", 1 },
    { "S12E1R", 2 },
    { "S12E1W", 3 },
    { "S1E0R", 4 },
    { "S1E0W", 5 },
    { "S1E1A", 6 },
    { "S1E1R", 7 },
    { "S1E1RP", 8 },
    { "S1E1W", 9 },
    { "S1E1WP", 10 },
    { "S1E2A", 11 },
    { "S1E2R", 12 },
    { "S1E2W", 13 },
    { "S1E3A", 14 },
    { "S1E3R", 15 },
    { "S1E3W", 16 },
  };

   unsigned i = binsearch_IndexTypeStrEncoding(Index, ARR_SIZE(Index), Name);
   if (i == -1)
      return NULL;
   else
      return &ATsList[Index[i].index];
}

const AArch64AT_AT *AArch64AT_lookupATByEncoding(uint16_t Encoding) {
  static const struct IndexType Index[] = {
    { 0x3C0, 7 },
    { 0x3C1, 9 },
    { 0x3C2, 4 },
    { 0x3C3, 5 },
    { 0x3C8, 8 },
    { 0x3C9, 10 },
    { 0x3CA, 6 },
    { 0x23C0, 12 },
    { 0x23C1, 13 },
    { 0x23C4, 2 },
    { 0x23C5, 3 },
    { 0x23C6, 0 },
    { 0x23C7, 1 },
    { 0x23CA, 11 },
    { 0x33C0, 15 },
    { 0x33C1, 16 },
    { 0x33CA, 14 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
   if (i == -1)
      return NULL;
   else
      return &ATsList[Index[i].index];
}

#endif

#ifdef GET_BTI_IMPL
static const AArch64BTIHint_BTI BTIsList[] = {
  { "c", { .raw_val = AARCH64_BTI_C }, 0x2 }, // 0
  { "j", { .raw_val = AARCH64_BTI_J }, 0x4 }, // 1
  { "jc", { .raw_val = AARCH64_BTI_JC }, 0x6 }, // 2
  };

const AArch64BTIHint_BTI *AArch64BTIHint_lookupBTIByName(const char * Name) {
  static const struct IndexTypeStr Index[] = {
    { "C", 0 },
    { "J", 1 },
    { "JC", 2 },
  };

   unsigned i = binsearch_IndexTypeStrEncoding(Index, ARR_SIZE(Index), Name);
   if (i == -1)
      return NULL;
   else
      return &BTIsList[Index[i].index];
}

const AArch64BTIHint_BTI *AArch64BTIHint_lookupBTIByEncoding(uint8_t Encoding) {
  static const struct IndexType Index[] = {
    { 0x2, 0 },
    { 0x4, 1 },
    { 0x6, 2 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
   if (i == -1)
      return NULL;
   else
      return &BTIsList[Index[i].index];
}

#endif

#ifdef GET_DB_IMPL
static const AArch64DB_DB DBsList[] = {
  { "ish", { .raw_val = AARCH64_DB_ISH }, 0xB }, // 0
  { "ishld", { .raw_val = AARCH64_DB_ISHLD }, 0x9 }, // 1
  { "ishst", { .raw_val = AARCH64_DB_ISHST }, 0xA }, // 2
  { "ld", { .raw_val = AARCH64_DB_LD }, 0xD }, // 3
  { "nsh", { .raw_val = AARCH64_DB_NSH }, 0x7 }, // 4
  { "nshld", { .raw_val = AARCH64_DB_NSHLD }, 0x5 }, // 5
  { "nshst", { .raw_val = AARCH64_DB_NSHST }, 0x6 }, // 6
  { "osh", { .raw_val = AARCH64_DB_OSH }, 0x3 }, // 7
  { "oshld", { .raw_val = AARCH64_DB_OSHLD }, 0x1 }, // 8
  { "oshst", { .raw_val = AARCH64_DB_OSHST }, 0x2 }, // 9
  { "st", { .raw_val = AARCH64_DB_ST }, 0xE }, // 10
  { "sy", { .raw_val = AARCH64_DB_SY }, 0xF }, // 11
  };

const AArch64DB_DB *AArch64DB_lookupDBByName(const char * Name) {
  static const struct IndexTypeStr Index[] = {
    { "ISH", 0 },
    { "ISHLD", 1 },
    { "ISHST", 2 },
    { "LD", 3 },
    { "NSH", 4 },
    { "NSHLD", 5 },
    { "NSHST", 6 },
    { "OSH", 7 },
    { "OSHLD", 8 },
    { "OSHST", 9 },
    { "ST", 10 },
    { "SY", 11 },
  };

   unsigned i = binsearch_IndexTypeStrEncoding(Index, ARR_SIZE(Index), Name);
   if (i == -1)
      return NULL;
   else
      return &DBsList[Index[i].index];
}

const AArch64DB_DB *AArch64DB_lookupDBByEncoding(uint8_t Encoding) {
  static const struct IndexType Index[] = {
    { 0x1, 8 },
    { 0x2, 9 },
    { 0x3, 7 },
    { 0x5, 5 },
    { 0x6, 6 },
    { 0x7, 4 },
    { 0x9, 1 },
    { 0xA, 2 },
    { 0xB, 0 },
    { 0xD, 3 },
    { 0xE, 10 },
    { 0xF, 11 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
   if (i == -1)
      return NULL;
   else
      return &DBsList[Index[i].index];
}

#endif

#ifdef GET_DBNXS_IMPL
static const AArch64DBnXS_DBnXS DBnXSsList[] = {
  { "ishnxs", { .raw_val = AARCH64_DBNXS_ISHNXS }, 0xB, 0x18,  {AArch64_FeatureXS}  }, // 0
  { "nshnxs", { .raw_val = AARCH64_DBNXS_NSHNXS }, 0x7, 0x14,  {AArch64_FeatureXS}  }, // 1
  { "oshnxs", { .raw_val = AARCH64_DBNXS_OSHNXS }, 0x3, 0x10,  {AArch64_FeatureXS}  }, // 2
  { "synxs", { .raw_val = AARCH64_DBNXS_SYNXS }, 0xF, 0x1C,  {AArch64_FeatureXS}  }, // 3
  };

const AArch64DBnXS_DBnXS *AArch64DBnXS_lookupDBnXSByName(const char * Name) {
  static const struct IndexTypeStr Index[] = {
    { "ISHNXS", 0 },
    { "NSHNXS", 1 },
    { "OSHNXS", 2 },
    { "SYNXS", 3 },
  };

   unsigned i = binsearch_IndexTypeStrEncoding(Index, ARR_SIZE(Index), Name);
   if (i == -1)
      return NULL;
   else
      return &DBnXSsList[Index[i].index];
}

const AArch64DBnXS_DBnXS *AArch64DBnXS_lookupDBnXSByEncoding(uint8_t Encoding) {
  static const struct IndexType Index[] = {
    { 0x3, 2 },
    { 0x7, 1 },
    { 0xB, 0 },
    { 0xF, 3 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
   if (i == -1)
      return NULL;
   else
      return &DBnXSsList[Index[i].index];
}

const AArch64DBnXS_DBnXS *AArch64DBnXS_lookupDBnXSByImmValue(uint8_t ImmValue) {
  static const struct IndexType Index[] = {
    { 0x10, 2 },
    { 0x14, 1 },
    { 0x18, 0 },
    { 0x1C, 3 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), ImmValue);
   if (i == -1)
      return NULL;
   else
      return &DBnXSsList[Index[i].index];
}

#endif

#ifdef GET_DC_IMPL
static const AArch64DC_DC DCsList[] = {
  { "CGDSW", { .raw_val = AARCH64_DC_CGDSW }, 0x3D6,  {AArch64_FeatureMTE}  }, // 0
  { "CGDVAC", { .raw_val = AARCH64_DC_CGDVAC }, 0x1BD5,  {AArch64_FeatureMTE}  }, // 1
  { "CGDVADP", { .raw_val = AARCH64_DC_CGDVADP }, 0x1BED,  {AArch64_FeatureMTE}  }, // 2
  { "CGDVAP", { .raw_val = AARCH64_DC_CGDVAP }, 0x1BE5,  {AArch64_FeatureMTE}  }, // 3
  { "CGSW", { .raw_val = AARCH64_DC_CGSW }, 0x3D4,  {AArch64_FeatureMTE}  }, // 4
  { "CGVAC", { .raw_val = AARCH64_DC_CGVAC }, 0x1BD3,  {AArch64_FeatureMTE}  }, // 5
  { "CGVADP", { .raw_val = AARCH64_DC_CGVADP }, 0x1BEB,  {AArch64_FeatureMTE}  }, // 6
  { "CGVAP", { .raw_val = AARCH64_DC_CGVAP }, 0x1BE3,  {AArch64_FeatureMTE}  }, // 7
  { "CIGDPAE", { .raw_val = AARCH64_DC_CIGDPAE }, 0x23F7,  {AArch64_FeatureMEC}  }, // 8
  { "CIGDSW", { .raw_val = AARCH64_DC_CIGDSW }, 0x3F6,  {AArch64_FeatureMTE}  }, // 9
  { "CIGDVAC", { .raw_val = AARCH64_DC_CIGDVAC }, 0x1BF5,  {AArch64_FeatureMTE}  }, // 10
  { "CIGSW", { .raw_val = AARCH64_DC_CIGSW }, 0x3F4,  {AArch64_FeatureMTE}  }, // 11
  { "CIGVAC", { .raw_val = AARCH64_DC_CIGVAC }, 0x1BF3,  {AArch64_FeatureMTE}  }, // 12
  { "CIPAE", { .raw_val = AARCH64_DC_CIPAE }, 0x23F0,  {AArch64_FeatureMEC}  }, // 13
  { "CISW", { .raw_val = AARCH64_DC_CISW }, 0x3F2,  {0}  }, // 14
  { "CIVAC", { .raw_val = AARCH64_DC_CIVAC }, 0x1BF1,  {0}  }, // 15
  { "CSW", { .raw_val = AARCH64_DC_CSW }, 0x3D2,  {0}  }, // 16
  { "CVAC", { .raw_val = AARCH64_DC_CVAC }, 0x1BD1,  {0}  }, // 17
  { "CVADP", { .raw_val = AARCH64_DC_CVADP }, 0x1BE9,  {AArch64_FeatureCacheDeepPersist}  }, // 18
  { "CVAP", { .raw_val = AARCH64_DC_CVAP }, 0x1BE1,  {AArch64_FeatureCCPP}  }, // 19
  { "CVAU", { .raw_val = AARCH64_DC_CVAU }, 0x1BD9,  {0}  }, // 20
  { "GVA", { .raw_val = AARCH64_DC_GVA }, 0x1BA3,  {AArch64_FeatureMTE}  }, // 21
  { "GZVA", { .raw_val = AARCH64_DC_GZVA }, 0x1BA4,  {AArch64_FeatureMTE}  }, // 22
  { "IGDSW", { .raw_val = AARCH64_DC_IGDSW }, 0x3B6,  {AArch64_FeatureMTE}  }, // 23
  { "IGDVAC", { .raw_val = AARCH64_DC_IGDVAC }, 0x3B5,  {AArch64_FeatureMTE}  }, // 24
  { "IGSW", { .raw_val = AARCH64_DC_IGSW }, 0x3B4,  {AArch64_FeatureMTE}  }, // 25
  { "IGVAC", { .raw_val = AARCH64_DC_IGVAC }, 0x3B3,  {AArch64_FeatureMTE}  }, // 26
  { "ISW", { .raw_val = AARCH64_DC_ISW }, 0x3B2,  {0}  }, // 27
  { "IVAC", { .raw_val = AARCH64_DC_IVAC }, 0x3B1,  {0}  }, // 28
  { "ZVA", { .raw_val = AARCH64_DC_ZVA }, 0x1BA1,  {0}  }, // 29
  };

const AArch64DC_DC *AArch64DC_lookupDCByName(const char * Name) {
  static const struct IndexTypeStr Index[] = {
    { "CGDSW", 0 },
    { "CGDVAC", 1 },
    { "CGDVADP", 2 },
    { "CGDVAP", 3 },
    { "CGSW", 4 },
    { "CGVAC", 5 },
    { "CGVADP", 6 },
    { "CGVAP", 7 },
    { "CIGDPAE", 8 },
    { "CIGDSW", 9 },
    { "CIGDVAC", 10 },
    { "CIGSW", 11 },
    { "CIGVAC", 12 },
    { "CIPAE", 13 },
    { "CISW", 14 },
    { "CIVAC", 15 },
    { "CSW", 16 },
    { "CVAC", 17 },
    { "CVADP", 18 },
    { "CVAP", 19 },
    { "CVAU", 20 },
    { "GVA", 21 },
    { "GZVA", 22 },
    { "IGDSW", 23 },
    { "IGDVAC", 24 },
    { "IGSW", 25 },
    { "IGVAC", 26 },
    { "ISW", 27 },
    { "IVAC", 28 },
    { "ZVA", 29 },
  };

   unsigned i = binsearch_IndexTypeStrEncoding(Index, ARR_SIZE(Index), Name);
   if (i == -1)
      return NULL;
   else
      return &DCsList[Index[i].index];
}

const AArch64DC_DC *AArch64DC_lookupDCByEncoding(uint16_t Encoding) {
  static const struct IndexType Index[] = {
    { 0x3B1, 28 },
    { 0x3B2, 27 },
    { 0x3B3, 26 },
    { 0x3B4, 25 },
    { 0x3B5, 24 },
    { 0x3B6, 23 },
    { 0x3D2, 16 },
    { 0x3D4, 4 },
    { 0x3D6, 0 },
    { 0x3F2, 14 },
    { 0x3F4, 11 },
    { 0x3F6, 9 },
    { 0x1BA1, 29 },
    { 0x1BA3, 21 },
    { 0x1BA4, 22 },
    { 0x1BD1, 17 },
    { 0x1BD3, 5 },
    { 0x1BD5, 1 },
    { 0x1BD9, 20 },
    { 0x1BE1, 19 },
    { 0x1BE3, 7 },
    { 0x1BE5, 3 },
    { 0x1BE9, 18 },
    { 0x1BEB, 6 },
    { 0x1BED, 2 },
    { 0x1BF1, 15 },
    { 0x1BF3, 12 },
    { 0x1BF5, 10 },
    { 0x23F0, 13 },
    { 0x23F7, 8 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
   if (i == -1)
      return NULL;
   else
      return &DCsList[Index[i].index];
}

#endif

#ifdef GET_EXACTFPIMM_IMPL
static const AArch64ExactFPImm_ExactFPImm ExactFPImmsList[] = {
  { "half", { .raw_val = AARCH64_EXACTFPIMM_HALF }, 0x1, "0.5" }, // 0
  { "one", { .raw_val = AARCH64_EXACTFPIMM_ONE }, 0x2, "1.0" }, // 1
  { "two", { .raw_val = AARCH64_EXACTFPIMM_TWO }, 0x3, "2.0" }, // 2
  { "zero", { .raw_val = AARCH64_EXACTFPIMM_ZERO }, 0x0, "0.0" }, // 3
  };

const AArch64ExactFPImm_ExactFPImm *AArch64ExactFPImm_lookupExactFPImmByEnum(uint8_t Enum) {
  static const struct IndexType Index[] = {
    { 0x0, 3 },
    { 0x1, 0 },
    { 0x2, 1 },
    { 0x3, 2 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Enum);
   if (i == -1)
      return NULL;
   else
      return &ExactFPImmsList[Index[i].index];
}

const AArch64ExactFPImm_ExactFPImm *AArch64ExactFPImm_lookupExactFPImmByRepr(const char * Repr) {
  static const struct IndexTypeStr Index[] = {
    { "0.0", 3 },
    { "0.5", 0 },
    { "1.0", 1 },
    { "2.0", 2 },
  };

   unsigned i = binsearch_IndexTypeStrEncoding(Index, ARR_SIZE(Index), Repr);
   if (i == -1)
      return NULL;
   else
      return &ExactFPImmsList[Index[i].index];
}

#endif

#ifdef GET_IC_IMPL
static const AArch64IC_IC ICsList[] = {
  { "IALLU", { .raw_val = AARCH64_IC_IALLU }, 0x3A8, false }, // 0
  { "IALLUIS", { .raw_val = AARCH64_IC_IALLUIS }, 0x388, false }, // 1
  { "IVAU", { .raw_val = AARCH64_IC_IVAU }, 0x1BA9, true }, // 2
  };

const AArch64IC_IC *AArch64IC_lookupICByName(const char * Name) {
  static const struct IndexTypeStr Index[] = {
    { "IALLU", 0 },
    { "IALLUIS", 1 },
    { "IVAU", 2 },
  };

   unsigned i = binsearch_IndexTypeStrEncoding(Index, ARR_SIZE(Index), Name);
   if (i == -1)
      return NULL;
   else
      return &ICsList[Index[i].index];
}

const AArch64IC_IC *AArch64IC_lookupICByEncoding(uint16_t Encoding) {
  static const struct IndexType Index[] = {
    { 0x388, 1 },
    { 0x3A8, 0 },
    { 0x1BA9, 2 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
   if (i == -1)
      return NULL;
   else
      return &ICsList[Index[i].index];
}

#endif

#ifdef GET_ISB_IMPL
static const AArch64ISB_ISB ISBsList[] = {
  { "sy", { .raw_val = AARCH64_ISB_SY }, 0xF }, // 0
  };

const AArch64ISB_ISB *AArch64ISB_lookupISBByName(const char * Name) {
  static const struct IndexTypeStr Index[] = {
    { "SY", 0 },
  };

   unsigned i = binsearch_IndexTypeStrEncoding(Index, ARR_SIZE(Index), Name);
   if (i == -1)
      return NULL;
   else
      return &ISBsList[Index[i].index];
}

const AArch64ISB_ISB *AArch64ISB_lookupISBByEncoding(uint8_t Encoding) {
  static const struct IndexType Index[] = {
    { 0xF, 0 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
   if (i == -1)
      return NULL;
   else
      return &ISBsList[Index[i].index];
}

#endif

#ifdef GET_PRFM_IMPL
static const AArch64PRFM_PRFM PRFMsList[] = {
  { "pldl1keep", { .raw_val = AARCH64_PRFM_PLDL1KEEP }, 0x0,  {0}  }, // 0
  { "pldl1strm", { .raw_val = AARCH64_PRFM_PLDL1STRM }, 0x1,  {0}  }, // 1
  { "pldl2keep", { .raw_val = AARCH64_PRFM_PLDL2KEEP }, 0x2,  {0}  }, // 2
  { "pldl2strm", { .raw_val = AARCH64_PRFM_PLDL2STRM }, 0x3,  {0}  }, // 3
  { "pldl3keep", { .raw_val = AARCH64_PRFM_PLDL3KEEP }, 0x4,  {0}  }, // 4
  { "pldl3strm", { .raw_val = AARCH64_PRFM_PLDL3STRM }, 0x5,  {0}  }, // 5
  { "pldslckeep", { .raw_val = AARCH64_PRFM_PLDSLCKEEP }, 0x6,  {AArch64_FeaturePRFM_SLC}  }, // 6
  { "pldslcstrm", { .raw_val = AARCH64_PRFM_PLDSLCSTRM }, 0x7,  {AArch64_FeaturePRFM_SLC}  }, // 7
  { "plil1keep", { .raw_val = AARCH64_PRFM_PLIL1KEEP }, 0x8,  {0}  }, // 8
  { "plil1strm", { .raw_val = AARCH64_PRFM_PLIL1STRM }, 0x9,  {0}  }, // 9
  { "plil2keep", { .raw_val = AARCH64_PRFM_PLIL2KEEP }, 0xA,  {0}  }, // 10
  { "plil2strm", { .raw_val = AARCH64_PRFM_PLIL2STRM }, 0xB,  {0}  }, // 11
  { "plil3keep", { .raw_val = AARCH64_PRFM_PLIL3KEEP }, 0xC,  {0}  }, // 12
  { "plil3strm", { .raw_val = AARCH64_PRFM_PLIL3STRM }, 0xD,  {0}  }, // 13
  { "plislckeep", { .raw_val = AARCH64_PRFM_PLISLCKEEP }, 0xE,  {AArch64_FeaturePRFM_SLC}  }, // 14
  { "plislcstrm", { .raw_val = AARCH64_PRFM_PLISLCSTRM }, 0xF,  {AArch64_FeaturePRFM_SLC}  }, // 15
  { "pstl1keep", { .raw_val = AARCH64_PRFM_PSTL1KEEP }, 0x10,  {0}  }, // 16
  { "pstl1strm", { .raw_val = AARCH64_PRFM_PSTL1STRM }, 0x11,  {0}  }, // 17
  { "pstl2keep", { .raw_val = AARCH64_PRFM_PSTL2KEEP }, 0x12,  {0}  }, // 18
  { "pstl2strm", { .raw_val = AARCH64_PRFM_PSTL2STRM }, 0x13,  {0}  }, // 19
  { "pstl3keep", { .raw_val = AARCH64_PRFM_PSTL3KEEP }, 0x14,  {0}  }, // 20
  { "pstl3strm", { .raw_val = AARCH64_PRFM_PSTL3STRM }, 0x15,  {0}  }, // 21
  { "pstslckeep", { .raw_val = AARCH64_PRFM_PSTSLCKEEP }, 0x16,  {AArch64_FeaturePRFM_SLC}  }, // 22
  { "pstslcstrm", { .raw_val = AARCH64_PRFM_PSTSLCSTRM }, 0x17,  {AArch64_FeaturePRFM_SLC}  }, // 23
  };

const AArch64PRFM_PRFM *AArch64PRFM_lookupPRFMByName(const char * Name) {
  static const struct IndexTypeStr Index[] = {
    { "PLDL1KEEP", 0 },
    { "PLDL1STRM", 1 },
    { "PLDL2KEEP", 2 },
    { "PLDL2STRM", 3 },
    { "PLDL3KEEP", 4 },
    { "PLDL3STRM", 5 },
    { "PLDSLCKEEP", 6 },
    { "PLDSLCSTRM", 7 },
    { "PLIL1KEEP", 8 },
    { "PLIL1STRM", 9 },
    { "PLIL2KEEP", 10 },
    { "PLIL2STRM", 11 },
    { "PLIL3KEEP", 12 },
    { "PLIL3STRM", 13 },
    { "PLISLCKEEP", 14 },
    { "PLISLCSTRM", 15 },
    { "PSTL1KEEP", 16 },
    { "PSTL1STRM", 17 },
    { "PSTL2KEEP", 18 },
    { "PSTL2STRM", 19 },
    { "PSTL3KEEP", 20 },
    { "PSTL3STRM", 21 },
    { "PSTSLCKEEP", 22 },
    { "PSTSLCSTRM", 23 },
  };

   unsigned i = binsearch_IndexTypeStrEncoding(Index, ARR_SIZE(Index), Name);
   if (i == -1)
      return NULL;
   else
      return &PRFMsList[Index[i].index];
}

const AArch64PRFM_PRFM *AArch64PRFM_lookupPRFMByEncoding(uint8_t Encoding) {
  static const struct IndexType Index[] = {
    { 0x0, 0 },
    { 0x1, 1 },
    { 0x2, 2 },
    { 0x3, 3 },
    { 0x4, 4 },
    { 0x5, 5 },
    { 0x6, 6 },
    { 0x7, 7 },
    { 0x8, 8 },
    { 0x9, 9 },
    { 0xA, 10 },
    { 0xB, 11 },
    { 0xC, 12 },
    { 0xD, 13 },
    { 0xE, 14 },
    { 0xF, 15 },
    { 0x10, 16 },
    { 0x11, 17 },
    { 0x12, 18 },
    { 0x13, 19 },
    { 0x14, 20 },
    { 0x15, 21 },
    { 0x16, 22 },
    { 0x17, 23 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
   if (i == -1)
      return NULL;
   else
      return &PRFMsList[Index[i].index];
}

#endif

#ifdef GET_PSB_IMPL
static const AArch64PSBHint_PSB PSBsList[] = {
  { "csync", { .raw_val = AARCH64_PSB_CSYNC }, 0x11 }, // 0
  };

const AArch64PSBHint_PSB *AArch64PSBHint_lookupPSBByName(const char * Name) {
  static const struct IndexTypeStr Index[] = {
    { "CSYNC", 0 },
  };

   unsigned i = binsearch_IndexTypeStrEncoding(Index, ARR_SIZE(Index), Name);
   if (i == -1)
      return NULL;
   else
      return &PSBsList[Index[i].index];
}

const AArch64PSBHint_PSB *AArch64PSBHint_lookupPSBByEncoding(uint8_t Encoding) {
  static const struct IndexType Index[] = {
    { 0x11, 0 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
   if (i == -1)
      return NULL;
   else
      return &PSBsList[Index[i].index];
}

#endif

#ifdef GET_PSTATEIMM0_1_IMPL
static const AArch64PState_PStateImm0_1 PStateImm0_1sList[] = {
  { "ALLINT", { .raw_val = AARCH64_PSTATEIMM0_1_ALLINT }, 0x8,  {AArch64_FeatureNMI}  }, // 0
  { "PM", { .raw_val = AARCH64_PSTATEIMM0_1_PM }, 0x48,  {0}  }, // 1
  };

const AArch64PState_PStateImm0_1 *AArch64PState_lookupPStateImm0_1ByName(const char * Name) {
  static const struct IndexTypeStr Index[] = {
    { "ALLINT", 0 },
    { "PM", 1 },
  };

   unsigned i = binsearch_IndexTypeStrEncoding(Index, ARR_SIZE(Index), Name);
   if (i == -1)
      return NULL;
   else
      return &PStateImm0_1sList[Index[i].index];
}

const AArch64PState_PStateImm0_1 *AArch64PState_lookupPStateImm0_1ByEncoding(uint16_t Encoding) {
  static const struct IndexType Index[] = {
    { 0x8, 0 },
    { 0x48, 1 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
   if (i == -1)
      return NULL;
   else
      return &PStateImm0_1sList[Index[i].index];
}

#endif

#ifdef GET_PSTATEIMM0_15_IMPL
static const AArch64PState_PStateImm0_15 PStateImm0_15sList[] = {
  { "DAIFClr", { .raw_val = AARCH64_PSTATEIMM0_15_DAIFCLR }, 0x1F,  {0}  }, // 0
  { "DAIFSet", { .raw_val = AARCH64_PSTATEIMM0_15_DAIFSET }, 0x1E,  {0}  }, // 1
  { "DIT", { .raw_val = AARCH64_PSTATEIMM0_15_DIT }, 0x1A,  {AArch64_FeatureDIT}  }, // 2
  { "PAN", { .raw_val = AARCH64_PSTATEIMM0_15_PAN }, 0x4,  {AArch64_FeaturePAN}  }, // 3
  { "SPSel", { .raw_val = AARCH64_PSTATEIMM0_15_SPSEL }, 0x5,  {0}  }, // 4
  { "SSBS", { .raw_val = AARCH64_PSTATEIMM0_15_SSBS }, 0x19,  {AArch64_FeatureSSBS}  }, // 5
  { "TCO", { .raw_val = AARCH64_PSTATEIMM0_15_TCO }, 0x1C,  {AArch64_FeatureMTE}  }, // 6
  { "UAO", { .raw_val = AARCH64_PSTATEIMM0_15_UAO }, 0x3,  {AArch64_FeaturePsUAO}  }, // 7
  };

const AArch64PState_PStateImm0_15 *AArch64PState_lookupPStateImm0_15ByName(const char * Name) {
  static const struct IndexTypeStr Index[] = {
    { "DAIFCLR", 0 },
    { "DAIFSET", 1 },
    { "DIT", 2 },
    { "PAN", 3 },
    { "SPSEL", 4 },
    { "SSBS", 5 },
    { "TCO", 6 },
    { "UAO", 7 },
  };

   unsigned i = binsearch_IndexTypeStrEncoding(Index, ARR_SIZE(Index), Name);
   if (i == -1)
      return NULL;
   else
      return &PStateImm0_15sList[Index[i].index];
}

const AArch64PState_PStateImm0_15 *AArch64PState_lookupPStateImm0_15ByEncoding(uint8_t Encoding) {
  static const struct IndexType Index[] = {
    { 0x3, 7 },
    { 0x4, 3 },
    { 0x5, 4 },
    { 0x19, 5 },
    { 0x1A, 2 },
    { 0x1C, 6 },
    { 0x1E, 1 },
    { 0x1F, 0 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
   if (i == -1)
      return NULL;
   else
      return &PStateImm0_15sList[Index[i].index];
}

#endif

#ifdef GET_RPRFM_IMPL
static const AArch64RPRFM_RPRFM RPRFMsList[] = {
  { "pldkeep", { .raw_val = AARCH64_RPRFM_PLDKEEP }, 0x0,  {0}  }, // 0
  { "pldstrm", { .raw_val = AARCH64_RPRFM_PLDSTRM }, 0x4,  {0}  }, // 1
  { "pstkeep", { .raw_val = AARCH64_RPRFM_PSTKEEP }, 0x1,  {0}  }, // 2
  { "pststrm", { .raw_val = AARCH64_RPRFM_PSTSTRM }, 0x5,  {0}  }, // 3
  };

const AArch64RPRFM_RPRFM *AArch64RPRFM_lookupRPRFMByName(const char * Name) {
  static const struct IndexTypeStr Index[] = {
    { "PLDKEEP", 0 },
    { "PLDSTRM", 1 },
    { "PSTKEEP", 2 },
    { "PSTSTRM", 3 },
  };

   unsigned i = binsearch_IndexTypeStrEncoding(Index, ARR_SIZE(Index), Name);
   if (i == -1)
      return NULL;
   else
      return &RPRFMsList[Index[i].index];
}

const AArch64RPRFM_RPRFM *AArch64RPRFM_lookupRPRFMByEncoding(uint8_t Encoding) {
  static const struct IndexType Index[] = {
    { 0x0, 0 },
    { 0x1, 2 },
    { 0x4, 1 },
    { 0x5, 3 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
   if (i == -1)
      return NULL;
   else
      return &RPRFMsList[Index[i].index];
}

#endif

#ifdef GET_SVCR_IMPL
static const AArch64SVCR_SVCR SVCRsList[] = {
  { "SVCRSM", { .raw_val = AARCH64_SVCR_SVCRSM }, 0x1,  {AArch64_FeatureSME}  }, // 0
  { "SVCRSMZA", { .raw_val = AARCH64_SVCR_SVCRSMZA }, 0x3,  {AArch64_FeatureSME}  }, // 1
  { "SVCRZA", { .raw_val = AARCH64_SVCR_SVCRZA }, 0x2,  {AArch64_FeatureSME}  }, // 2
  };

const AArch64SVCR_SVCR *AArch64SVCR_lookupSVCRByName(const char * Name) {
  static const struct IndexTypeStr Index[] = {
    { "SVCRSM", 0 },
    { "SVCRSMZA", 1 },
    { "SVCRZA", 2 },
  };

   unsigned i = binsearch_IndexTypeStrEncoding(Index, ARR_SIZE(Index), Name);
   if (i == -1)
      return NULL;
   else
      return &SVCRsList[Index[i].index];
}

const AArch64SVCR_SVCR *AArch64SVCR_lookupSVCRByEncoding(uint8_t Encoding) {
  static const struct IndexType Index[] = {
    { 0x1, 0 },
    { 0x2, 2 },
    { 0x3, 1 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
   if (i == -1)
      return NULL;
   else
      return &SVCRsList[Index[i].index];
}

#endif

#ifdef GET_SVEPREDPAT_IMPL
static const AArch64SVEPredPattern_SVEPREDPAT SVEPREDPATsList[] = {
  { "all", { .raw_val = AARCH64_SVEPREDPAT_ALL }, 0x1F }, // 0
  { "mul3", { .raw_val = AARCH64_SVEPREDPAT_MUL3 }, 0x1E }, // 1
  { "mul4", { .raw_val = AARCH64_SVEPREDPAT_MUL4 }, 0x1D }, // 2
  { "pow2", { .raw_val = AARCH64_SVEPREDPAT_POW2 }, 0x0 }, // 3
  { "vl1", { .raw_val = AARCH64_SVEPREDPAT_VL1 }, 0x1 }, // 4
  { "vl128", { .raw_val = AARCH64_SVEPREDPAT_VL128 }, 0xC }, // 5
  { "vl16", { .raw_val = AARCH64_SVEPREDPAT_VL16 }, 0x9 }, // 6
  { "vl2", { .raw_val = AARCH64_SVEPREDPAT_VL2 }, 0x2 }, // 7
  { "vl256", { .raw_val = AARCH64_SVEPREDPAT_VL256 }, 0xD }, // 8
  { "vl3", { .raw_val = AARCH64_SVEPREDPAT_VL3 }, 0x3 }, // 9
  { "vl32", { .raw_val = AARCH64_SVEPREDPAT_VL32 }, 0xA }, // 10
  { "vl4", { .raw_val = AARCH64_SVEPREDPAT_VL4 }, 0x4 }, // 11
  { "vl5", { .raw_val = AARCH64_SVEPREDPAT_VL5 }, 0x5 }, // 12
  { "vl6", { .raw_val = AARCH64_SVEPREDPAT_VL6 }, 0x6 }, // 13
  { "vl64", { .raw_val = AARCH64_SVEPREDPAT_VL64 }, 0xB }, // 14
  { "vl7", { .raw_val = AARCH64_SVEPREDPAT_VL7 }, 0x7 }, // 15
  { "vl8", { .raw_val = AARCH64_SVEPREDPAT_VL8 }, 0x8 }, // 16
  };

const AArch64SVEPredPattern_SVEPREDPAT *AArch64SVEPredPattern_lookupSVEPREDPATByName(const char * Name) {
  static const struct IndexTypeStr Index[] = {
    { "ALL", 0 },
    { "MUL3", 1 },
    { "MUL4", 2 },
    { "POW2", 3 },
    { "VL1", 4 },
    { "VL128", 5 },
    { "VL16", 6 },
    { "VL2", 7 },
    { "VL256", 8 },
    { "VL3", 9 },
    { "VL32", 10 },
    { "VL4", 11 },
    { "VL5", 12 },
    { "VL6", 13 },
    { "VL64", 14 },
    { "VL7", 15 },
    { "VL8", 16 },
  };

   unsigned i = binsearch_IndexTypeStrEncoding(Index, ARR_SIZE(Index), Name);
   if (i == -1)
      return NULL;
   else
      return &SVEPREDPATsList[Index[i].index];
}

const AArch64SVEPredPattern_SVEPREDPAT *AArch64SVEPredPattern_lookupSVEPREDPATByEncoding(uint8_t Encoding) {
  static const struct IndexType Index[] = {
    { 0x0, 3 },
    { 0x1, 4 },
    { 0x2, 7 },
    { 0x3, 9 },
    { 0x4, 11 },
    { 0x5, 12 },
    { 0x6, 13 },
    { 0x7, 15 },
    { 0x8, 16 },
    { 0x9, 6 },
    { 0xA, 10 },
    { 0xB, 14 },
    { 0xC, 5 },
    { 0xD, 8 },
    { 0x1D, 2 },
    { 0x1E, 1 },
    { 0x1F, 0 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
   if (i == -1)
      return NULL;
   else
      return &SVEPREDPATsList[Index[i].index];
}

#endif

#ifdef GET_SVEPRFM_IMPL
static const AArch64SVEPRFM_SVEPRFM SVEPRFMsList[] = {
  { "pldl1keep", { .raw_val = AARCH64_SVEPRFM_PLDL1KEEP }, 0x0,  {AArch64_FeatureSVE}  }, // 0
  { "pldl1strm", { .raw_val = AARCH64_SVEPRFM_PLDL1STRM }, 0x1,  {AArch64_FeatureSVE}  }, // 1
  { "pldl2keep", { .raw_val = AARCH64_SVEPRFM_PLDL2KEEP }, 0x2,  {AArch64_FeatureSVE}  }, // 2
  { "pldl2strm", { .raw_val = AARCH64_SVEPRFM_PLDL2STRM }, 0x3,  {AArch64_FeatureSVE}  }, // 3
  { "pldl3keep", { .raw_val = AARCH64_SVEPRFM_PLDL3KEEP }, 0x4,  {AArch64_FeatureSVE}  }, // 4
  { "pldl3strm", { .raw_val = AARCH64_SVEPRFM_PLDL3STRM }, 0x5,  {AArch64_FeatureSVE}  }, // 5
  { "pstl1keep", { .raw_val = AARCH64_SVEPRFM_PSTL1KEEP }, 0x8,  {AArch64_FeatureSVE}  }, // 6
  { "pstl1strm", { .raw_val = AARCH64_SVEPRFM_PSTL1STRM }, 0x9,  {AArch64_FeatureSVE}  }, // 7
  { "pstl2keep", { .raw_val = AARCH64_SVEPRFM_PSTL2KEEP }, 0xA,  {AArch64_FeatureSVE}  }, // 8
  { "pstl2strm", { .raw_val = AARCH64_SVEPRFM_PSTL2STRM }, 0xB,  {AArch64_FeatureSVE}  }, // 9
  { "pstl3keep", { .raw_val = AARCH64_SVEPRFM_PSTL3KEEP }, 0xC,  {AArch64_FeatureSVE}  }, // 10
  { "pstl3strm", { .raw_val = AARCH64_SVEPRFM_PSTL3STRM }, 0xD,  {AArch64_FeatureSVE}  }, // 11
  };

const AArch64SVEPRFM_SVEPRFM *AArch64SVEPRFM_lookupSVEPRFMByName(const char * Name) {
  static const struct IndexTypeStr Index[] = {
    { "PLDL1KEEP", 0 },
    { "PLDL1STRM", 1 },
    { "PLDL2KEEP", 2 },
    { "PLDL2STRM", 3 },
    { "PLDL3KEEP", 4 },
    { "PLDL3STRM", 5 },
    { "PSTL1KEEP", 6 },
    { "PSTL1STRM", 7 },
    { "PSTL2KEEP", 8 },
    { "PSTL2STRM", 9 },
    { "PSTL3KEEP", 10 },
    { "PSTL3STRM", 11 },
  };

   unsigned i = binsearch_IndexTypeStrEncoding(Index, ARR_SIZE(Index), Name);
   if (i == -1)
      return NULL;
   else
      return &SVEPRFMsList[Index[i].index];
}

const AArch64SVEPRFM_SVEPRFM *AArch64SVEPRFM_lookupSVEPRFMByEncoding(uint8_t Encoding) {
  static const struct IndexType Index[] = {
    { 0x0, 0 },
    { 0x1, 1 },
    { 0x2, 2 },
    { 0x3, 3 },
    { 0x4, 4 },
    { 0x5, 5 },
    { 0x8, 6 },
    { 0x9, 7 },
    { 0xA, 8 },
    { 0xB, 9 },
    { 0xC, 10 },
    { 0xD, 11 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
   if (i == -1)
      return NULL;
   else
      return &SVEPRFMsList[Index[i].index];
}

#endif

#ifdef GET_SVEVECLENSPECIFIER_IMPL
static const AArch64SVEVecLenSpecifier_SVEVECLENSPECIFIER SVEVECLENSPECIFIERsList[] = {
  { "vlx2", { .raw_val = AARCH64_SVEVECLENSPECIFIER_VLX2 }, 0x0 }, // 0
  { "vlx4", { .raw_val = AARCH64_SVEVECLENSPECIFIER_VLX4 }, 0x1 }, // 1
  };

const AArch64SVEVecLenSpecifier_SVEVECLENSPECIFIER *AArch64SVEVecLenSpecifier_lookupSVEVECLENSPECIFIERByName(const char * Name) {
  static const struct IndexTypeStr Index[] = {
    { "VLX2", 0 },
    { "VLX4", 1 },
  };

   unsigned i = binsearch_IndexTypeStrEncoding(Index, ARR_SIZE(Index), Name);
   if (i == -1)
      return NULL;
   else
      return &SVEVECLENSPECIFIERsList[Index[i].index];
}

const AArch64SVEVecLenSpecifier_SVEVECLENSPECIFIER *AArch64SVEVecLenSpecifier_lookupSVEVECLENSPECIFIERByEncoding(uint8_t Encoding) {
  static const struct IndexType Index[] = {
    { 0x0, 0 },
    { 0x1, 1 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
   if (i == -1)
      return NULL;
   else
      return &SVEVECLENSPECIFIERsList[Index[i].index];
}

#endif

#ifdef GET_SYSREG_IMPL
static const AArch64SysReg_SysReg SysRegsList[] = {
  { "ACCDATA_EL1", { .raw_val = AARCH64_SYSREG_ACCDATA_EL1 }, "ACCDATA_EL1", { .raw_val = AARCH64_SYSREG_ACCDATA_EL1 }, 0xC685, true, true,  {AArch64_FeatureLS64}  }, // 0
  { "ACTLR_EL1", { .raw_val = AARCH64_SYSREG_ACTLR_EL1 }, "ACTLR_EL1", { .raw_val = AARCH64_SYSREG_ACTLR_EL1 }, 0xC081, true, true,  {0}  }, // 1
  { "ACTLR_EL2", { .raw_val = AARCH64_SYSREG_ACTLR_EL2 }, "ACTLR_EL2", { .raw_val = AARCH64_SYSREG_ACTLR_EL2 }, 0xE081, true, true,  {0}  }, // 2
  { "ACTLR_EL3", { .raw_val = AARCH64_SYSREG_ACTLR_EL3 }, "ACTLR_EL3", { .raw_val = AARCH64_SYSREG_ACTLR_EL3 }, 0xF081, true, true,  {0}  }, // 3
  { "AFSR0_EL1", { .raw_val = AARCH64_SYSREG_AFSR0_EL1 }, "AFSR0_EL1", { .raw_val = AARCH64_SYSREG_AFSR0_EL1 }, 0xC288, true, true,  {0}  }, // 4
  { "AFSR0_EL12", { .raw_val = AARCH64_SYSREG_AFSR0_EL12 }, "AFSR0_EL12", { .raw_val = AARCH64_SYSREG_AFSR0_EL12 }, 0xEA88, true, true,  {AArch64_FeatureVH}  }, // 5
  { "AFSR0_EL2", { .raw_val = AARCH64_SYSREG_AFSR0_EL2 }, "AFSR0_EL2", { .raw_val = AARCH64_SYSREG_AFSR0_EL2 }, 0xE288, true, true,  {0}  }, // 6
  { "AFSR0_EL3", { .raw_val = AARCH64_SYSREG_AFSR0_EL3 }, "AFSR0_EL3", { .raw_val = AARCH64_SYSREG_AFSR0_EL3 }, 0xF288, true, true,  {0}  }, // 7
  { "AFSR1_EL1", { .raw_val = AARCH64_SYSREG_AFSR1_EL1 }, "AFSR1_EL1", { .raw_val = AARCH64_SYSREG_AFSR1_EL1 }, 0xC289, true, true,  {0}  }, // 8
  { "AFSR1_EL12", { .raw_val = AARCH64_SYSREG_AFSR1_EL12 }, "AFSR1_EL12", { .raw_val = AARCH64_SYSREG_AFSR1_EL12 }, 0xEA89, true, true,  {AArch64_FeatureVH}  }, // 9
  { "AFSR1_EL2", { .raw_val = AARCH64_SYSREG_AFSR1_EL2 }, "AFSR1_EL2", { .raw_val = AARCH64_SYSREG_AFSR1_EL2 }, 0xE289, true, true,  {0}  }, // 10
  { "AFSR1_EL3", { .raw_val = AARCH64_SYSREG_AFSR1_EL3 }, "AFSR1_EL3", { .raw_val = AARCH64_SYSREG_AFSR1_EL3 }, 0xF289, true, true,  {0}  }, // 11
  { "AIDR_EL1", { .raw_val = AARCH64_SYSREG_AIDR_EL1 }, "AIDR_EL1", { .raw_val = AARCH64_SYSREG_AIDR_EL1 }, 0xC807, true, false,  {0}  }, // 12
  { "ALLINT", { .raw_val = AARCH64_SYSREG_ALLINT }, "ALLINT", { .raw_val = AARCH64_SYSREG_ALLINT }, 0xC218, true, true,  {AArch64_FeatureNMI}  }, // 13
  { "AMAIR2_EL1", { .raw_val = AARCH64_SYSREG_AMAIR2_EL1 }, "AMAIR2_EL1", { .raw_val = AARCH64_SYSREG_AMAIR2_EL1 }, 0xC519, true, true,  {0}  }, // 14
  { "AMAIR2_EL12", { .raw_val = AARCH64_SYSREG_AMAIR2_EL12 }, "AMAIR2_EL12", { .raw_val = AARCH64_SYSREG_AMAIR2_EL12 }, 0xED19, true, true,  {0}  }, // 15
  { "AMAIR2_EL2", { .raw_val = AARCH64_SYSREG_AMAIR2_EL2 }, "AMAIR2_EL2", { .raw_val = AARCH64_SYSREG_AMAIR2_EL2 }, 0xE519, true, true,  {0}  }, // 16
  { "AMAIR2_EL3", { .raw_val = AARCH64_SYSREG_AMAIR2_EL3 }, "AMAIR2_EL3", { .raw_val = AARCH64_SYSREG_AMAIR2_EL3 }, 0xF519, true, true,  {0}  }, // 17
  { "AMAIR_EL1", { .raw_val = AARCH64_SYSREG_AMAIR_EL1 }, "AMAIR_EL1", { .raw_val = AARCH64_SYSREG_AMAIR_EL1 }, 0xC518, true, true,  {0}  }, // 18
  { "AMAIR_EL12", { .raw_val = AARCH64_SYSREG_AMAIR_EL12 }, "AMAIR_EL12", { .raw_val = AARCH64_SYSREG_AMAIR_EL12 }, 0xED18, true, true,  {AArch64_FeatureVH}  }, // 19
  { "AMAIR_EL2", { .raw_val = AARCH64_SYSREG_AMAIR_EL2 }, "AMAIR_EL2", { .raw_val = AARCH64_SYSREG_AMAIR_EL2 }, 0xE518, true, true,  {0}  }, // 20
  { "AMAIR_EL3", { .raw_val = AARCH64_SYSREG_AMAIR_EL3 }, "AMAIR_EL3", { .raw_val = AARCH64_SYSREG_AMAIR_EL3 }, 0xF518, true, true,  {0}  }, // 21
  { "AMCFGR_EL0", { .raw_val = AARCH64_SYSREG_AMCFGR_EL0 }, "AMCFGR_EL0", { .raw_val = AARCH64_SYSREG_AMCFGR_EL0 }, 0xDE91, true, false,  {AArch64_FeatureAM}  }, // 22
  { "AMCG1IDR_EL0", { .raw_val = AARCH64_SYSREG_AMCG1IDR_EL0 }, "AMCG1IDR_EL0", { .raw_val = AARCH64_SYSREG_AMCG1IDR_EL0 }, 0xDE96, true, false,  {AArch64_FeatureAMVS}  }, // 23
  { "AMCGCR_EL0", { .raw_val = AARCH64_SYSREG_AMCGCR_EL0 }, "AMCGCR_EL0", { .raw_val = AARCH64_SYSREG_AMCGCR_EL0 }, 0xDE92, true, false,  {AArch64_FeatureAM}  }, // 24
  { "AMCNTENCLR0_EL0", { .raw_val = AARCH64_SYSREG_AMCNTENCLR0_EL0 }, "AMCNTENCLR0_EL0", { .raw_val = AARCH64_SYSREG_AMCNTENCLR0_EL0 }, 0xDE94, true, true,  {AArch64_FeatureAM}  }, // 25
  { "AMCNTENCLR1_EL0", { .raw_val = AARCH64_SYSREG_AMCNTENCLR1_EL0 }, "AMCNTENCLR1_EL0", { .raw_val = AARCH64_SYSREG_AMCNTENCLR1_EL0 }, 0xDE98, true, true,  {AArch64_FeatureAM}  }, // 26
  { "AMCNTENSET0_EL0", { .raw_val = AARCH64_SYSREG_AMCNTENSET0_EL0 }, "AMCNTENSET0_EL0", { .raw_val = AARCH64_SYSREG_AMCNTENSET0_EL0 }, 0xDE95, true, true,  {AArch64_FeatureAM}  }, // 27
  { "AMCNTENSET1_EL0", { .raw_val = AARCH64_SYSREG_AMCNTENSET1_EL0 }, "AMCNTENSET1_EL0", { .raw_val = AARCH64_SYSREG_AMCNTENSET1_EL0 }, 0xDE99, true, true,  {AArch64_FeatureAM}  }, // 28
  { "AMCR_EL0", { .raw_val = AARCH64_SYSREG_AMCR_EL0 }, "AMCR_EL0", { .raw_val = AARCH64_SYSREG_AMCR_EL0 }, 0xDE90, true, true,  {AArch64_FeatureAM}  }, // 29
  { "AMEVCNTR00_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR00_EL0 }, "AMEVCNTR00_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR00_EL0 }, 0xDEA0, true, true,  {AArch64_FeatureAM}  }, // 30
  { "AMEVCNTR01_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR01_EL0 }, "AMEVCNTR01_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR01_EL0 }, 0xDEA1, true, true,  {AArch64_FeatureAM}  }, // 31
  { "AMEVCNTR02_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR02_EL0 }, "AMEVCNTR02_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR02_EL0 }, 0xDEA2, true, true,  {AArch64_FeatureAM}  }, // 32
  { "AMEVCNTR03_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR03_EL0 }, "AMEVCNTR03_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR03_EL0 }, 0xDEA3, true, true,  {AArch64_FeatureAM}  }, // 33
  { "AMEVCNTR10_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR10_EL0 }, "AMEVCNTR10_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR10_EL0 }, 0xDEE0, true, true,  {AArch64_FeatureAM}  }, // 34
  { "AMEVCNTR110_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR110_EL0 }, "AMEVCNTR110_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR110_EL0 }, 0xDEEA, true, true,  {AArch64_FeatureAM}  }, // 35
  { "AMEVCNTR111_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR111_EL0 }, "AMEVCNTR111_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR111_EL0 }, 0xDEEB, true, true,  {AArch64_FeatureAM}  }, // 36
  { "AMEVCNTR112_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR112_EL0 }, "AMEVCNTR112_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR112_EL0 }, 0xDEEC, true, true,  {AArch64_FeatureAM}  }, // 37
  { "AMEVCNTR113_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR113_EL0 }, "AMEVCNTR113_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR113_EL0 }, 0xDEED, true, true,  {AArch64_FeatureAM}  }, // 38
  { "AMEVCNTR114_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR114_EL0 }, "AMEVCNTR114_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR114_EL0 }, 0xDEEE, true, true,  {AArch64_FeatureAM}  }, // 39
  { "AMEVCNTR115_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR115_EL0 }, "AMEVCNTR115_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR115_EL0 }, 0xDEEF, true, true,  {AArch64_FeatureAM}  }, // 40
  { "AMEVCNTR11_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR11_EL0 }, "AMEVCNTR11_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR11_EL0 }, 0xDEE1, true, true,  {AArch64_FeatureAM}  }, // 41
  { "AMEVCNTR12_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR12_EL0 }, "AMEVCNTR12_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR12_EL0 }, 0xDEE2, true, true,  {AArch64_FeatureAM}  }, // 42
  { "AMEVCNTR13_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR13_EL0 }, "AMEVCNTR13_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR13_EL0 }, 0xDEE3, true, true,  {AArch64_FeatureAM}  }, // 43
  { "AMEVCNTR14_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR14_EL0 }, "AMEVCNTR14_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR14_EL0 }, 0xDEE4, true, true,  {AArch64_FeatureAM}  }, // 44
  { "AMEVCNTR15_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR15_EL0 }, "AMEVCNTR15_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR15_EL0 }, 0xDEE5, true, true,  {AArch64_FeatureAM}  }, // 45
  { "AMEVCNTR16_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR16_EL0 }, "AMEVCNTR16_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR16_EL0 }, 0xDEE6, true, true,  {AArch64_FeatureAM}  }, // 46
  { "AMEVCNTR17_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR17_EL0 }, "AMEVCNTR17_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR17_EL0 }, 0xDEE7, true, true,  {AArch64_FeatureAM}  }, // 47
  { "AMEVCNTR18_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR18_EL0 }, "AMEVCNTR18_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR18_EL0 }, 0xDEE8, true, true,  {AArch64_FeatureAM}  }, // 48
  { "AMEVCNTR19_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR19_EL0 }, "AMEVCNTR19_EL0", { .raw_val = AARCH64_SYSREG_AMEVCNTR19_EL0 }, 0xDEE9, true, true,  {AArch64_FeatureAM}  }, // 49
  { "AMEVCNTVOFF00_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF00_EL2 }, "AMEVCNTVOFF00_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF00_EL2 }, 0xE6C0, true, true,  {AArch64_FeatureAMVS}  }, // 50
  { "AMEVCNTVOFF010_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF010_EL2 }, "AMEVCNTVOFF010_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF010_EL2 }, 0xE6CA, true, true,  {AArch64_FeatureAMVS}  }, // 51
  { "AMEVCNTVOFF011_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF011_EL2 }, "AMEVCNTVOFF011_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF011_EL2 }, 0xE6CB, true, true,  {AArch64_FeatureAMVS}  }, // 52
  { "AMEVCNTVOFF012_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF012_EL2 }, "AMEVCNTVOFF012_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF012_EL2 }, 0xE6CC, true, true,  {AArch64_FeatureAMVS}  }, // 53
  { "AMEVCNTVOFF013_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF013_EL2 }, "AMEVCNTVOFF013_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF013_EL2 }, 0xE6CD, true, true,  {AArch64_FeatureAMVS}  }, // 54
  { "AMEVCNTVOFF014_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF014_EL2 }, "AMEVCNTVOFF014_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF014_EL2 }, 0xE6CE, true, true,  {AArch64_FeatureAMVS}  }, // 55
  { "AMEVCNTVOFF015_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF015_EL2 }, "AMEVCNTVOFF015_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF015_EL2 }, 0xE6CF, true, true,  {AArch64_FeatureAMVS}  }, // 56
  { "AMEVCNTVOFF01_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF01_EL2 }, "AMEVCNTVOFF01_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF01_EL2 }, 0xE6C1, true, true,  {AArch64_FeatureAMVS}  }, // 57
  { "AMEVCNTVOFF02_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF02_EL2 }, "AMEVCNTVOFF02_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF02_EL2 }, 0xE6C2, true, true,  {AArch64_FeatureAMVS}  }, // 58
  { "AMEVCNTVOFF03_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF03_EL2 }, "AMEVCNTVOFF03_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF03_EL2 }, 0xE6C3, true, true,  {AArch64_FeatureAMVS}  }, // 59
  { "AMEVCNTVOFF04_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF04_EL2 }, "AMEVCNTVOFF04_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF04_EL2 }, 0xE6C4, true, true,  {AArch64_FeatureAMVS}  }, // 60
  { "AMEVCNTVOFF05_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF05_EL2 }, "AMEVCNTVOFF05_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF05_EL2 }, 0xE6C5, true, true,  {AArch64_FeatureAMVS}  }, // 61
  { "AMEVCNTVOFF06_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF06_EL2 }, "AMEVCNTVOFF06_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF06_EL2 }, 0xE6C6, true, true,  {AArch64_FeatureAMVS}  }, // 62
  { "AMEVCNTVOFF07_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF07_EL2 }, "AMEVCNTVOFF07_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF07_EL2 }, 0xE6C7, true, true,  {AArch64_FeatureAMVS}  }, // 63
  { "AMEVCNTVOFF08_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF08_EL2 }, "AMEVCNTVOFF08_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF08_EL2 }, 0xE6C8, true, true,  {AArch64_FeatureAMVS}  }, // 64
  { "AMEVCNTVOFF09_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF09_EL2 }, "AMEVCNTVOFF09_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF09_EL2 }, 0xE6C9, true, true,  {AArch64_FeatureAMVS}  }, // 65
  { "AMEVCNTVOFF10_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF10_EL2 }, "AMEVCNTVOFF10_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF10_EL2 }, 0xE6D0, true, true,  {AArch64_FeatureAMVS}  }, // 66
  { "AMEVCNTVOFF110_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF110_EL2 }, "AMEVCNTVOFF110_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF110_EL2 }, 0xE6DA, true, true,  {AArch64_FeatureAMVS}  }, // 67
  { "AMEVCNTVOFF111_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF111_EL2 }, "AMEVCNTVOFF111_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF111_EL2 }, 0xE6DB, true, true,  {AArch64_FeatureAMVS}  }, // 68
  { "AMEVCNTVOFF112_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF112_EL2 }, "AMEVCNTVOFF112_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF112_EL2 }, 0xE6DC, true, true,  {AArch64_FeatureAMVS}  }, // 69
  { "AMEVCNTVOFF113_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF113_EL2 }, "AMEVCNTVOFF113_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF113_EL2 }, 0xE6DD, true, true,  {AArch64_FeatureAMVS}  }, // 70
  { "AMEVCNTVOFF114_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF114_EL2 }, "AMEVCNTVOFF114_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF114_EL2 }, 0xE6DE, true, true,  {AArch64_FeatureAMVS}  }, // 71
  { "AMEVCNTVOFF115_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF115_EL2 }, "AMEVCNTVOFF115_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF115_EL2 }, 0xE6DF, true, true,  {AArch64_FeatureAMVS}  }, // 72
  { "AMEVCNTVOFF11_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF11_EL2 }, "AMEVCNTVOFF11_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF11_EL2 }, 0xE6D1, true, true,  {AArch64_FeatureAMVS}  }, // 73
  { "AMEVCNTVOFF12_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF12_EL2 }, "AMEVCNTVOFF12_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF12_EL2 }, 0xE6D2, true, true,  {AArch64_FeatureAMVS}  }, // 74
  { "AMEVCNTVOFF13_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF13_EL2 }, "AMEVCNTVOFF13_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF13_EL2 }, 0xE6D3, true, true,  {AArch64_FeatureAMVS}  }, // 75
  { "AMEVCNTVOFF14_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF14_EL2 }, "AMEVCNTVOFF14_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF14_EL2 }, 0xE6D4, true, true,  {AArch64_FeatureAMVS}  }, // 76
  { "AMEVCNTVOFF15_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF15_EL2 }, "AMEVCNTVOFF15_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF15_EL2 }, 0xE6D5, true, true,  {AArch64_FeatureAMVS}  }, // 77
  { "AMEVCNTVOFF16_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF16_EL2 }, "AMEVCNTVOFF16_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF16_EL2 }, 0xE6D6, true, true,  {AArch64_FeatureAMVS}  }, // 78
  { "AMEVCNTVOFF17_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF17_EL2 }, "AMEVCNTVOFF17_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF17_EL2 }, 0xE6D7, true, true,  {AArch64_FeatureAMVS}  }, // 79
  { "AMEVCNTVOFF18_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF18_EL2 }, "AMEVCNTVOFF18_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF18_EL2 }, 0xE6D8, true, true,  {AArch64_FeatureAMVS}  }, // 80
  { "AMEVCNTVOFF19_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF19_EL2 }, "AMEVCNTVOFF19_EL2", { .raw_val = AARCH64_SYSREG_AMEVCNTVOFF19_EL2 }, 0xE6D9, true, true,  {AArch64_FeatureAMVS}  }, // 81
  { "AMEVTYPER00_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER00_EL0 }, "AMEVTYPER00_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER00_EL0 }, 0xDEB0, true, false,  {AArch64_FeatureAM}  }, // 82
  { "AMEVTYPER01_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER01_EL0 }, "AMEVTYPER01_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER01_EL0 }, 0xDEB1, true, false,  {AArch64_FeatureAM}  }, // 83
  { "AMEVTYPER02_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER02_EL0 }, "AMEVTYPER02_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER02_EL0 }, 0xDEB2, true, false,  {AArch64_FeatureAM}  }, // 84
  { "AMEVTYPER03_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER03_EL0 }, "AMEVTYPER03_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER03_EL0 }, 0xDEB3, true, false,  {AArch64_FeatureAM}  }, // 85
  { "AMEVTYPER10_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER10_EL0 }, "AMEVTYPER10_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER10_EL0 }, 0xDEF0, true, true,  {AArch64_FeatureAM}  }, // 86
  { "AMEVTYPER110_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER110_EL0 }, "AMEVTYPER110_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER110_EL0 }, 0xDEFA, true, true,  {AArch64_FeatureAM}  }, // 87
  { "AMEVTYPER111_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER111_EL0 }, "AMEVTYPER111_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER111_EL0 }, 0xDEFB, true, true,  {AArch64_FeatureAM}  }, // 88
  { "AMEVTYPER112_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER112_EL0 }, "AMEVTYPER112_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER112_EL0 }, 0xDEFC, true, true,  {AArch64_FeatureAM}  }, // 89
  { "AMEVTYPER113_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER113_EL0 }, "AMEVTYPER113_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER113_EL0 }, 0xDEFD, true, true,  {AArch64_FeatureAM}  }, // 90
  { "AMEVTYPER114_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER114_EL0 }, "AMEVTYPER114_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER114_EL0 }, 0xDEFE, true, true,  {AArch64_FeatureAM}  }, // 91
  { "AMEVTYPER115_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER115_EL0 }, "AMEVTYPER115_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER115_EL0 }, 0xDEFF, true, true,  {AArch64_FeatureAM}  }, // 92
  { "AMEVTYPER11_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER11_EL0 }, "AMEVTYPER11_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER11_EL0 }, 0xDEF1, true, true,  {AArch64_FeatureAM}  }, // 93
  { "AMEVTYPER12_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER12_EL0 }, "AMEVTYPER12_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER12_EL0 }, 0xDEF2, true, true,  {AArch64_FeatureAM}  }, // 94
  { "AMEVTYPER13_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER13_EL0 }, "AMEVTYPER13_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER13_EL0 }, 0xDEF3, true, true,  {AArch64_FeatureAM}  }, // 95
  { "AMEVTYPER14_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER14_EL0 }, "AMEVTYPER14_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER14_EL0 }, 0xDEF4, true, true,  {AArch64_FeatureAM}  }, // 96
  { "AMEVTYPER15_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER15_EL0 }, "AMEVTYPER15_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER15_EL0 }, 0xDEF5, true, true,  {AArch64_FeatureAM}  }, // 97
  { "AMEVTYPER16_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER16_EL0 }, "AMEVTYPER16_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER16_EL0 }, 0xDEF6, true, true,  {AArch64_FeatureAM}  }, // 98
  { "AMEVTYPER17_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER17_EL0 }, "AMEVTYPER17_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER17_EL0 }, 0xDEF7, true, true,  {AArch64_FeatureAM}  }, // 99
  { "AMEVTYPER18_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER18_EL0 }, "AMEVTYPER18_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER18_EL0 }, 0xDEF8, true, true,  {AArch64_FeatureAM}  }, // 100
  { "AMEVTYPER19_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER19_EL0 }, "AMEVTYPER19_EL0", { .raw_val = AARCH64_SYSREG_AMEVTYPER19_EL0 }, 0xDEF9, true, true,  {AArch64_FeatureAM}  }, // 101
  { "AMUSERENR_EL0", { .raw_val = AARCH64_SYSREG_AMUSERENR_EL0 }, "AMUSERENR_EL0", { .raw_val = AARCH64_SYSREG_AMUSERENR_EL0 }, 0xDE93, true, true,  {AArch64_FeatureAM}  }, // 102
  { "APDAKeyHi_EL1", { .raw_val = AARCH64_SYSREG_APDAKEYHI_EL1 }, "APDAKeyHi_EL1", { .raw_val = AARCH64_SYSREG_APDAKEYHI_EL1 }, 0xC111, true, true,  {AArch64_FeaturePAuth}  }, // 103
  { "APDAKeyLo_EL1", { .raw_val = AARCH64_SYSREG_APDAKEYLO_EL1 }, "APDAKeyLo_EL1", { .raw_val = AARCH64_SYSREG_APDAKEYLO_EL1 }, 0xC110, true, true,  {AArch64_FeaturePAuth}  }, // 104
  { "APDBKeyHi_EL1", { .raw_val = AARCH64_SYSREG_APDBKEYHI_EL1 }, "APDBKeyHi_EL1", { .raw_val = AARCH64_SYSREG_APDBKEYHI_EL1 }, 0xC113, true, true,  {AArch64_FeaturePAuth}  }, // 105
  { "APDBKeyLo_EL1", { .raw_val = AARCH64_SYSREG_APDBKEYLO_EL1 }, "APDBKeyLo_EL1", { .raw_val = AARCH64_SYSREG_APDBKEYLO_EL1 }, 0xC112, true, true,  {AArch64_FeaturePAuth}  }, // 106
  { "APGAKeyHi_EL1", { .raw_val = AARCH64_SYSREG_APGAKEYHI_EL1 }, "APGAKeyHi_EL1", { .raw_val = AARCH64_SYSREG_APGAKEYHI_EL1 }, 0xC119, true, true,  {AArch64_FeaturePAuth}  }, // 107
  { "APGAKeyLo_EL1", { .raw_val = AARCH64_SYSREG_APGAKEYLO_EL1 }, "APGAKeyLo_EL1", { .raw_val = AARCH64_SYSREG_APGAKEYLO_EL1 }, 0xC118, true, true,  {AArch64_FeaturePAuth}  }, // 108
  { "APIAKeyHi_EL1", { .raw_val = AARCH64_SYSREG_APIAKEYHI_EL1 }, "APIAKeyHi_EL1", { .raw_val = AARCH64_SYSREG_APIAKEYHI_EL1 }, 0xC109, true, true,  {AArch64_FeaturePAuth}  }, // 109
  { "APIAKeyLo_EL1", { .raw_val = AARCH64_SYSREG_APIAKEYLO_EL1 }, "APIAKeyLo_EL1", { .raw_val = AARCH64_SYSREG_APIAKEYLO_EL1 }, 0xC108, true, true,  {AArch64_FeaturePAuth}  }, // 110
  { "APIBKeyHi_EL1", { .raw_val = AARCH64_SYSREG_APIBKEYHI_EL1 }, "APIBKeyHi_EL1", { .raw_val = AARCH64_SYSREG_APIBKEYHI_EL1 }, 0xC10B, true, true,  {AArch64_FeaturePAuth}  }, // 111
  { "APIBKeyLo_EL1", { .raw_val = AARCH64_SYSREG_APIBKEYLO_EL1 }, "APIBKeyLo_EL1", { .raw_val = AARCH64_SYSREG_APIBKEYLO_EL1 }, 0xC10A, true, true,  {AArch64_FeaturePAuth}  }, // 112
  { "BRBCR_EL1", { .raw_val = AARCH64_SYSREG_BRBCR_EL1 }, "BRBCR_EL1", { .raw_val = AARCH64_SYSREG_BRBCR_EL1 }, 0x8C80, true, true,  {AArch64_FeatureBRBE}  }, // 113
  { "BRBCR_EL12", { .raw_val = AARCH64_SYSREG_BRBCR_EL12 }, "BRBCR_EL12", { .raw_val = AARCH64_SYSREG_BRBCR_EL12 }, 0xAC80, true, true,  {AArch64_FeatureBRBE}  }, // 114
  { "BRBCR_EL2", { .raw_val = AARCH64_SYSREG_BRBCR_EL2 }, "BRBCR_EL2", { .raw_val = AARCH64_SYSREG_BRBCR_EL2 }, 0xA480, true, true,  {AArch64_FeatureBRBE}  }, // 115
  { "BRBFCR_EL1", { .raw_val = AARCH64_SYSREG_BRBFCR_EL1 }, "BRBFCR_EL1", { .raw_val = AARCH64_SYSREG_BRBFCR_EL1 }, 0x8C81, true, true,  {AArch64_FeatureBRBE}  }, // 116
  { "BRBIDR0_EL1", { .raw_val = AARCH64_SYSREG_BRBIDR0_EL1 }, "BRBIDR0_EL1", { .raw_val = AARCH64_SYSREG_BRBIDR0_EL1 }, 0x8C90, true, false,  {AArch64_FeatureBRBE}  }, // 117
  { "BRBINF0_EL1", { .raw_val = AARCH64_SYSREG_BRBINF0_EL1 }, "BRBINF0_EL1", { .raw_val = AARCH64_SYSREG_BRBINF0_EL1 }, 0x8C00, true, false,  {AArch64_FeatureBRBE}  }, // 118
  { "BRBINF10_EL1", { .raw_val = AARCH64_SYSREG_BRBINF10_EL1 }, "BRBINF10_EL1", { .raw_val = AARCH64_SYSREG_BRBINF10_EL1 }, 0x8C50, true, false,  {AArch64_FeatureBRBE}  }, // 119
  { "BRBINF11_EL1", { .raw_val = AARCH64_SYSREG_BRBINF11_EL1 }, "BRBINF11_EL1", { .raw_val = AARCH64_SYSREG_BRBINF11_EL1 }, 0x8C58, true, false,  {AArch64_FeatureBRBE}  }, // 120
  { "BRBINF12_EL1", { .raw_val = AARCH64_SYSREG_BRBINF12_EL1 }, "BRBINF12_EL1", { .raw_val = AARCH64_SYSREG_BRBINF12_EL1 }, 0x8C60, true, false,  {AArch64_FeatureBRBE}  }, // 121
  { "BRBINF13_EL1", { .raw_val = AARCH64_SYSREG_BRBINF13_EL1 }, "BRBINF13_EL1", { .raw_val = AARCH64_SYSREG_BRBINF13_EL1 }, 0x8C68, true, false,  {AArch64_FeatureBRBE}  }, // 122
  { "BRBINF14_EL1", { .raw_val = AARCH64_SYSREG_BRBINF14_EL1 }, "BRBINF14_EL1", { .raw_val = AARCH64_SYSREG_BRBINF14_EL1 }, 0x8C70, true, false,  {AArch64_FeatureBRBE}  }, // 123
  { "BRBINF15_EL1", { .raw_val = AARCH64_SYSREG_BRBINF15_EL1 }, "BRBINF15_EL1", { .raw_val = AARCH64_SYSREG_BRBINF15_EL1 }, 0x8C78, true, false,  {AArch64_FeatureBRBE}  }, // 124
  { "BRBINF16_EL1", { .raw_val = AARCH64_SYSREG_BRBINF16_EL1 }, "BRBINF16_EL1", { .raw_val = AARCH64_SYSREG_BRBINF16_EL1 }, 0x8C04, true, false,  {AArch64_FeatureBRBE}  }, // 125
  { "BRBINF17_EL1", { .raw_val = AARCH64_SYSREG_BRBINF17_EL1 }, "BRBINF17_EL1", { .raw_val = AARCH64_SYSREG_BRBINF17_EL1 }, 0x8C0C, true, false,  {AArch64_FeatureBRBE}  }, // 126
  { "BRBINF18_EL1", { .raw_val = AARCH64_SYSREG_BRBINF18_EL1 }, "BRBINF18_EL1", { .raw_val = AARCH64_SYSREG_BRBINF18_EL1 }, 0x8C14, true, false,  {AArch64_FeatureBRBE}  }, // 127
  { "BRBINF19_EL1", { .raw_val = AARCH64_SYSREG_BRBINF19_EL1 }, "BRBINF19_EL1", { .raw_val = AARCH64_SYSREG_BRBINF19_EL1 }, 0x8C1C, true, false,  {AArch64_FeatureBRBE}  }, // 128
  { "BRBINF1_EL1", { .raw_val = AARCH64_SYSREG_BRBINF1_EL1 }, "BRBINF1_EL1", { .raw_val = AARCH64_SYSREG_BRBINF1_EL1 }, 0x8C08, true, false,  {AArch64_FeatureBRBE}  }, // 129
  { "BRBINF20_EL1", { .raw_val = AARCH64_SYSREG_BRBINF20_EL1 }, "BRBINF20_EL1", { .raw_val = AARCH64_SYSREG_BRBINF20_EL1 }, 0x8C24, true, false,  {AArch64_FeatureBRBE}  }, // 130
  { "BRBINF21_EL1", { .raw_val = AARCH64_SYSREG_BRBINF21_EL1 }, "BRBINF21_EL1", { .raw_val = AARCH64_SYSREG_BRBINF21_EL1 }, 0x8C2C, true, false,  {AArch64_FeatureBRBE}  }, // 131
  { "BRBINF22_EL1", { .raw_val = AARCH64_SYSREG_BRBINF22_EL1 }, "BRBINF22_EL1", { .raw_val = AARCH64_SYSREG_BRBINF22_EL1 }, 0x8C34, true, false,  {AArch64_FeatureBRBE}  }, // 132
  { "BRBINF23_EL1", { .raw_val = AARCH64_SYSREG_BRBINF23_EL1 }, "BRBINF23_EL1", { .raw_val = AARCH64_SYSREG_BRBINF23_EL1 }, 0x8C3C, true, false,  {AArch64_FeatureBRBE}  }, // 133
  { "BRBINF24_EL1", { .raw_val = AARCH64_SYSREG_BRBINF24_EL1 }, "BRBINF24_EL1", { .raw_val = AARCH64_SYSREG_BRBINF24_EL1 }, 0x8C44, true, false,  {AArch64_FeatureBRBE}  }, // 134
  { "BRBINF25_EL1", { .raw_val = AARCH64_SYSREG_BRBINF25_EL1 }, "BRBINF25_EL1", { .raw_val = AARCH64_SYSREG_BRBINF25_EL1 }, 0x8C4C, true, false,  {AArch64_FeatureBRBE}  }, // 135
  { "BRBINF26_EL1", { .raw_val = AARCH64_SYSREG_BRBINF26_EL1 }, "BRBINF26_EL1", { .raw_val = AARCH64_SYSREG_BRBINF26_EL1 }, 0x8C54, true, false,  {AArch64_FeatureBRBE}  }, // 136
  { "BRBINF27_EL1", { .raw_val = AARCH64_SYSREG_BRBINF27_EL1 }, "BRBINF27_EL1", { .raw_val = AARCH64_SYSREG_BRBINF27_EL1 }, 0x8C5C, true, false,  {AArch64_FeatureBRBE}  }, // 137
  { "BRBINF28_EL1", { .raw_val = AARCH64_SYSREG_BRBINF28_EL1 }, "BRBINF28_EL1", { .raw_val = AARCH64_SYSREG_BRBINF28_EL1 }, 0x8C64, true, false,  {AArch64_FeatureBRBE}  }, // 138
  { "BRBINF29_EL1", { .raw_val = AARCH64_SYSREG_BRBINF29_EL1 }, "BRBINF29_EL1", { .raw_val = AARCH64_SYSREG_BRBINF29_EL1 }, 0x8C6C, true, false,  {AArch64_FeatureBRBE}  }, // 139
  { "BRBINF2_EL1", { .raw_val = AARCH64_SYSREG_BRBINF2_EL1 }, "BRBINF2_EL1", { .raw_val = AARCH64_SYSREG_BRBINF2_EL1 }, 0x8C10, true, false,  {AArch64_FeatureBRBE}  }, // 140
  { "BRBINF30_EL1", { .raw_val = AARCH64_SYSREG_BRBINF30_EL1 }, "BRBINF30_EL1", { .raw_val = AARCH64_SYSREG_BRBINF30_EL1 }, 0x8C74, true, false,  {AArch64_FeatureBRBE}  }, // 141
  { "BRBINF31_EL1", { .raw_val = AARCH64_SYSREG_BRBINF31_EL1 }, "BRBINF31_EL1", { .raw_val = AARCH64_SYSREG_BRBINF31_EL1 }, 0x8C7C, true, false,  {AArch64_FeatureBRBE}  }, // 142
  { "BRBINF3_EL1", { .raw_val = AARCH64_SYSREG_BRBINF3_EL1 }, "BRBINF3_EL1", { .raw_val = AARCH64_SYSREG_BRBINF3_EL1 }, 0x8C18, true, false,  {AArch64_FeatureBRBE}  }, // 143
  { "BRBINF4_EL1", { .raw_val = AARCH64_SYSREG_BRBINF4_EL1 }, "BRBINF4_EL1", { .raw_val = AARCH64_SYSREG_BRBINF4_EL1 }, 0x8C20, true, false,  {AArch64_FeatureBRBE}  }, // 144
  { "BRBINF5_EL1", { .raw_val = AARCH64_SYSREG_BRBINF5_EL1 }, "BRBINF5_EL1", { .raw_val = AARCH64_SYSREG_BRBINF5_EL1 }, 0x8C28, true, false,  {AArch64_FeatureBRBE}  }, // 145
  { "BRBINF6_EL1", { .raw_val = AARCH64_SYSREG_BRBINF6_EL1 }, "BRBINF6_EL1", { .raw_val = AARCH64_SYSREG_BRBINF6_EL1 }, 0x8C30, true, false,  {AArch64_FeatureBRBE}  }, // 146
  { "BRBINF7_EL1", { .raw_val = AARCH64_SYSREG_BRBINF7_EL1 }, "BRBINF7_EL1", { .raw_val = AARCH64_SYSREG_BRBINF7_EL1 }, 0x8C38, true, false,  {AArch64_FeatureBRBE}  }, // 147
  { "BRBINF8_EL1", { .raw_val = AARCH64_SYSREG_BRBINF8_EL1 }, "BRBINF8_EL1", { .raw_val = AARCH64_SYSREG_BRBINF8_EL1 }, 0x8C40, true, false,  {AArch64_FeatureBRBE}  }, // 148
  { "BRBINF9_EL1", { .raw_val = AARCH64_SYSREG_BRBINF9_EL1 }, "BRBINF9_EL1", { .raw_val = AARCH64_SYSREG_BRBINF9_EL1 }, 0x8C48, true, false,  {AArch64_FeatureBRBE}  }, // 149
  { "BRBINFINJ_EL1", { .raw_val = AARCH64_SYSREG_BRBINFINJ_EL1 }, "BRBINFINJ_EL1", { .raw_val = AARCH64_SYSREG_BRBINFINJ_EL1 }, 0x8C88, true, true,  {AArch64_FeatureBRBE}  }, // 150
  { "BRBSRC0_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC0_EL1 }, "BRBSRC0_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC0_EL1 }, 0x8C01, true, false,  {AArch64_FeatureBRBE}  }, // 151
  { "BRBSRC10_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC10_EL1 }, "BRBSRC10_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC10_EL1 }, 0x8C51, true, false,  {AArch64_FeatureBRBE}  }, // 152
  { "BRBSRC11_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC11_EL1 }, "BRBSRC11_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC11_EL1 }, 0x8C59, true, false,  {AArch64_FeatureBRBE}  }, // 153
  { "BRBSRC12_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC12_EL1 }, "BRBSRC12_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC12_EL1 }, 0x8C61, true, false,  {AArch64_FeatureBRBE}  }, // 154
  { "BRBSRC13_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC13_EL1 }, "BRBSRC13_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC13_EL1 }, 0x8C69, true, false,  {AArch64_FeatureBRBE}  }, // 155
  { "BRBSRC14_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC14_EL1 }, "BRBSRC14_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC14_EL1 }, 0x8C71, true, false,  {AArch64_FeatureBRBE}  }, // 156
  { "BRBSRC15_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC15_EL1 }, "BRBSRC15_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC15_EL1 }, 0x8C79, true, false,  {AArch64_FeatureBRBE}  }, // 157
  { "BRBSRC16_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC16_EL1 }, "BRBSRC16_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC16_EL1 }, 0x8C05, true, false,  {AArch64_FeatureBRBE}  }, // 158
  { "BRBSRC17_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC17_EL1 }, "BRBSRC17_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC17_EL1 }, 0x8C0D, true, false,  {AArch64_FeatureBRBE}  }, // 159
  { "BRBSRC18_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC18_EL1 }, "BRBSRC18_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC18_EL1 }, 0x8C15, true, false,  {AArch64_FeatureBRBE}  }, // 160
  { "BRBSRC19_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC19_EL1 }, "BRBSRC19_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC19_EL1 }, 0x8C1D, true, false,  {AArch64_FeatureBRBE}  }, // 161
  { "BRBSRC1_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC1_EL1 }, "BRBSRC1_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC1_EL1 }, 0x8C09, true, false,  {AArch64_FeatureBRBE}  }, // 162
  { "BRBSRC20_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC20_EL1 }, "BRBSRC20_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC20_EL1 }, 0x8C25, true, false,  {AArch64_FeatureBRBE}  }, // 163
  { "BRBSRC21_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC21_EL1 }, "BRBSRC21_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC21_EL1 }, 0x8C2D, true, false,  {AArch64_FeatureBRBE}  }, // 164
  { "BRBSRC22_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC22_EL1 }, "BRBSRC22_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC22_EL1 }, 0x8C35, true, false,  {AArch64_FeatureBRBE}  }, // 165
  { "BRBSRC23_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC23_EL1 }, "BRBSRC23_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC23_EL1 }, 0x8C3D, true, false,  {AArch64_FeatureBRBE}  }, // 166
  { "BRBSRC24_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC24_EL1 }, "BRBSRC24_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC24_EL1 }, 0x8C45, true, false,  {AArch64_FeatureBRBE}  }, // 167
  { "BRBSRC25_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC25_EL1 }, "BRBSRC25_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC25_EL1 }, 0x8C4D, true, false,  {AArch64_FeatureBRBE}  }, // 168
  { "BRBSRC26_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC26_EL1 }, "BRBSRC26_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC26_EL1 }, 0x8C55, true, false,  {AArch64_FeatureBRBE}  }, // 169
  { "BRBSRC27_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC27_EL1 }, "BRBSRC27_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC27_EL1 }, 0x8C5D, true, false,  {AArch64_FeatureBRBE}  }, // 170
  { "BRBSRC28_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC28_EL1 }, "BRBSRC28_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC28_EL1 }, 0x8C65, true, false,  {AArch64_FeatureBRBE}  }, // 171
  { "BRBSRC29_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC29_EL1 }, "BRBSRC29_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC29_EL1 }, 0x8C6D, true, false,  {AArch64_FeatureBRBE}  }, // 172
  { "BRBSRC2_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC2_EL1 }, "BRBSRC2_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC2_EL1 }, 0x8C11, true, false,  {AArch64_FeatureBRBE}  }, // 173
  { "BRBSRC30_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC30_EL1 }, "BRBSRC30_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC30_EL1 }, 0x8C75, true, false,  {AArch64_FeatureBRBE}  }, // 174
  { "BRBSRC31_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC31_EL1 }, "BRBSRC31_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC31_EL1 }, 0x8C7D, true, false,  {AArch64_FeatureBRBE}  }, // 175
  { "BRBSRC3_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC3_EL1 }, "BRBSRC3_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC3_EL1 }, 0x8C19, true, false,  {AArch64_FeatureBRBE}  }, // 176
  { "BRBSRC4_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC4_EL1 }, "BRBSRC4_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC4_EL1 }, 0x8C21, true, false,  {AArch64_FeatureBRBE}  }, // 177
  { "BRBSRC5_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC5_EL1 }, "BRBSRC5_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC5_EL1 }, 0x8C29, true, false,  {AArch64_FeatureBRBE}  }, // 178
  { "BRBSRC6_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC6_EL1 }, "BRBSRC6_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC6_EL1 }, 0x8C31, true, false,  {AArch64_FeatureBRBE}  }, // 179
  { "BRBSRC7_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC7_EL1 }, "BRBSRC7_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC7_EL1 }, 0x8C39, true, false,  {AArch64_FeatureBRBE}  }, // 180
  { "BRBSRC8_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC8_EL1 }, "BRBSRC8_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC8_EL1 }, 0x8C41, true, false,  {AArch64_FeatureBRBE}  }, // 181
  { "BRBSRC9_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC9_EL1 }, "BRBSRC9_EL1", { .raw_val = AARCH64_SYSREG_BRBSRC9_EL1 }, 0x8C49, true, false,  {AArch64_FeatureBRBE}  }, // 182
  { "BRBSRCINJ_EL1", { .raw_val = AARCH64_SYSREG_BRBSRCINJ_EL1 }, "BRBSRCINJ_EL1", { .raw_val = AARCH64_SYSREG_BRBSRCINJ_EL1 }, 0x8C89, true, true,  {AArch64_FeatureBRBE}  }, // 183
  { "BRBTGT0_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT0_EL1 }, "BRBTGT0_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT0_EL1 }, 0x8C02, true, false,  {AArch64_FeatureBRBE}  }, // 184
  { "BRBTGT10_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT10_EL1 }, "BRBTGT10_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT10_EL1 }, 0x8C52, true, false,  {AArch64_FeatureBRBE}  }, // 185
  { "BRBTGT11_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT11_EL1 }, "BRBTGT11_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT11_EL1 }, 0x8C5A, true, false,  {AArch64_FeatureBRBE}  }, // 186
  { "BRBTGT12_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT12_EL1 }, "BRBTGT12_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT12_EL1 }, 0x8C62, true, false,  {AArch64_FeatureBRBE}  }, // 187
  { "BRBTGT13_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT13_EL1 }, "BRBTGT13_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT13_EL1 }, 0x8C6A, true, false,  {AArch64_FeatureBRBE}  }, // 188
  { "BRBTGT14_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT14_EL1 }, "BRBTGT14_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT14_EL1 }, 0x8C72, true, false,  {AArch64_FeatureBRBE}  }, // 189
  { "BRBTGT15_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT15_EL1 }, "BRBTGT15_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT15_EL1 }, 0x8C7A, true, false,  {AArch64_FeatureBRBE}  }, // 190
  { "BRBTGT16_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT16_EL1 }, "BRBTGT16_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT16_EL1 }, 0x8C06, true, false,  {AArch64_FeatureBRBE}  }, // 191
  { "BRBTGT17_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT17_EL1 }, "BRBTGT17_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT17_EL1 }, 0x8C0E, true, false,  {AArch64_FeatureBRBE}  }, // 192
  { "BRBTGT18_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT18_EL1 }, "BRBTGT18_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT18_EL1 }, 0x8C16, true, false,  {AArch64_FeatureBRBE}  }, // 193
  { "BRBTGT19_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT19_EL1 }, "BRBTGT19_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT19_EL1 }, 0x8C1E, true, false,  {AArch64_FeatureBRBE}  }, // 194
  { "BRBTGT1_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT1_EL1 }, "BRBTGT1_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT1_EL1 }, 0x8C0A, true, false,  {AArch64_FeatureBRBE}  }, // 195
  { "BRBTGT20_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT20_EL1 }, "BRBTGT20_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT20_EL1 }, 0x8C26, true, false,  {AArch64_FeatureBRBE}  }, // 196
  { "BRBTGT21_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT21_EL1 }, "BRBTGT21_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT21_EL1 }, 0x8C2E, true, false,  {AArch64_FeatureBRBE}  }, // 197
  { "BRBTGT22_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT22_EL1 }, "BRBTGT22_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT22_EL1 }, 0x8C36, true, false,  {AArch64_FeatureBRBE}  }, // 198
  { "BRBTGT23_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT23_EL1 }, "BRBTGT23_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT23_EL1 }, 0x8C3E, true, false,  {AArch64_FeatureBRBE}  }, // 199
  { "BRBTGT24_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT24_EL1 }, "BRBTGT24_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT24_EL1 }, 0x8C46, true, false,  {AArch64_FeatureBRBE}  }, // 200
  { "BRBTGT25_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT25_EL1 }, "BRBTGT25_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT25_EL1 }, 0x8C4E, true, false,  {AArch64_FeatureBRBE}  }, // 201
  { "BRBTGT26_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT26_EL1 }, "BRBTGT26_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT26_EL1 }, 0x8C56, true, false,  {AArch64_FeatureBRBE}  }, // 202
  { "BRBTGT27_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT27_EL1 }, "BRBTGT27_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT27_EL1 }, 0x8C5E, true, false,  {AArch64_FeatureBRBE}  }, // 203
  { "BRBTGT28_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT28_EL1 }, "BRBTGT28_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT28_EL1 }, 0x8C66, true, false,  {AArch64_FeatureBRBE}  }, // 204
  { "BRBTGT29_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT29_EL1 }, "BRBTGT29_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT29_EL1 }, 0x8C6E, true, false,  {AArch64_FeatureBRBE}  }, // 205
  { "BRBTGT2_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT2_EL1 }, "BRBTGT2_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT2_EL1 }, 0x8C12, true, false,  {AArch64_FeatureBRBE}  }, // 206
  { "BRBTGT30_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT30_EL1 }, "BRBTGT30_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT30_EL1 }, 0x8C76, true, false,  {AArch64_FeatureBRBE}  }, // 207
  { "BRBTGT31_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT31_EL1 }, "BRBTGT31_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT31_EL1 }, 0x8C7E, true, false,  {AArch64_FeatureBRBE}  }, // 208
  { "BRBTGT3_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT3_EL1 }, "BRBTGT3_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT3_EL1 }, 0x8C1A, true, false,  {AArch64_FeatureBRBE}  }, // 209
  { "BRBTGT4_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT4_EL1 }, "BRBTGT4_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT4_EL1 }, 0x8C22, true, false,  {AArch64_FeatureBRBE}  }, // 210
  { "BRBTGT5_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT5_EL1 }, "BRBTGT5_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT5_EL1 }, 0x8C2A, true, false,  {AArch64_FeatureBRBE}  }, // 211
  { "BRBTGT6_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT6_EL1 }, "BRBTGT6_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT6_EL1 }, 0x8C32, true, false,  {AArch64_FeatureBRBE}  }, // 212
  { "BRBTGT7_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT7_EL1 }, "BRBTGT7_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT7_EL1 }, 0x8C3A, true, false,  {AArch64_FeatureBRBE}  }, // 213
  { "BRBTGT8_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT8_EL1 }, "BRBTGT8_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT8_EL1 }, 0x8C42, true, false,  {AArch64_FeatureBRBE}  }, // 214
  { "BRBTGT9_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT9_EL1 }, "BRBTGT9_EL1", { .raw_val = AARCH64_SYSREG_BRBTGT9_EL1 }, 0x8C4A, true, false,  {AArch64_FeatureBRBE}  }, // 215
  { "BRBTGTINJ_EL1", { .raw_val = AARCH64_SYSREG_BRBTGTINJ_EL1 }, "BRBTGTINJ_EL1", { .raw_val = AARCH64_SYSREG_BRBTGTINJ_EL1 }, 0x8C8A, true, true,  {AArch64_FeatureBRBE}  }, // 216
  { "BRBTS_EL1", { .raw_val = AARCH64_SYSREG_BRBTS_EL1 }, "BRBTS_EL1", { .raw_val = AARCH64_SYSREG_BRBTS_EL1 }, 0x8C82, true, true,  {AArch64_FeatureBRBE}  }, // 217
  { "CCSIDR2_EL1", { .raw_val = AARCH64_SYSREG_CCSIDR2_EL1 }, "CCSIDR2_EL1", { .raw_val = AARCH64_SYSREG_CCSIDR2_EL1 }, 0xC802, true, false,  {AArch64_FeatureCCIDX}  }, // 218
  { "CCSIDR_EL1", { .raw_val = AARCH64_SYSREG_CCSIDR_EL1 }, "CCSIDR_EL1", { .raw_val = AARCH64_SYSREG_CCSIDR_EL1 }, 0xC800, true, false,  {0}  }, // 219
  { "CLIDR_EL1", { .raw_val = AARCH64_SYSREG_CLIDR_EL1 }, "CLIDR_EL1", { .raw_val = AARCH64_SYSREG_CLIDR_EL1 }, 0xC801, true, false,  {0}  }, // 220
  { "CNTFRQ_EL0", { .raw_val = AARCH64_SYSREG_CNTFRQ_EL0 }, "CNTFRQ_EL0", { .raw_val = AARCH64_SYSREG_CNTFRQ_EL0 }, 0xDF00, true, true,  {0}  }, // 221
  { "CNTHCTL_EL2", { .raw_val = AARCH64_SYSREG_CNTHCTL_EL2 }, "CNTHCTL_EL2", { .raw_val = AARCH64_SYSREG_CNTHCTL_EL2 }, 0xE708, true, true,  {0}  }, // 222
  { "CNTHPS_CTL_EL2", { .raw_val = AARCH64_SYSREG_CNTHPS_CTL_EL2 }, "CNTHPS_CTL_EL2", { .raw_val = AARCH64_SYSREG_CNTHPS_CTL_EL2 }, 0xE729, true, true,  {AArch64_FeatureSEL2}  }, // 223
  { "CNTHPS_CVAL_EL2", { .raw_val = AARCH64_SYSREG_CNTHPS_CVAL_EL2 }, "CNTHPS_CVAL_EL2", { .raw_val = AARCH64_SYSREG_CNTHPS_CVAL_EL2 }, 0xE72A, true, true,  {AArch64_FeatureSEL2}  }, // 224
  { "CNTHPS_TVAL_EL2", { .raw_val = AARCH64_SYSREG_CNTHPS_TVAL_EL2 }, "CNTHPS_TVAL_EL2", { .raw_val = AARCH64_SYSREG_CNTHPS_TVAL_EL2 }, 0xE728, true, true,  {AArch64_FeatureSEL2}  }, // 225
  { "CNTHP_CTL_EL2", { .raw_val = AARCH64_SYSREG_CNTHP_CTL_EL2 }, "CNTHP_CTL_EL2", { .raw_val = AARCH64_SYSREG_CNTHP_CTL_EL2 }, 0xE711, true, true,  {0}  }, // 226
  { "CNTHP_CVAL_EL2", { .raw_val = AARCH64_SYSREG_CNTHP_CVAL_EL2 }, "CNTHP_CVAL_EL2", { .raw_val = AARCH64_SYSREG_CNTHP_CVAL_EL2 }, 0xE712, true, true,  {0}  }, // 227
  { "CNTHP_TVAL_EL2", { .raw_val = AARCH64_SYSREG_CNTHP_TVAL_EL2 }, "CNTHP_TVAL_EL2", { .raw_val = AARCH64_SYSREG_CNTHP_TVAL_EL2 }, 0xE710, true, true,  {0}  }, // 228
  { "CNTHVS_CTL_EL2", { .raw_val = AARCH64_SYSREG_CNTHVS_CTL_EL2 }, "CNTHVS_CTL_EL2", { .raw_val = AARCH64_SYSREG_CNTHVS_CTL_EL2 }, 0xE721, true, true,  {AArch64_FeatureSEL2}  }, // 229
  { "CNTHVS_CVAL_EL2", { .raw_val = AARCH64_SYSREG_CNTHVS_CVAL_EL2 }, "CNTHVS_CVAL_EL2", { .raw_val = AARCH64_SYSREG_CNTHVS_CVAL_EL2 }, 0xE722, true, true,  {AArch64_FeatureSEL2}  }, // 230
  { "CNTHVS_TVAL_EL2", { .raw_val = AARCH64_SYSREG_CNTHVS_TVAL_EL2 }, "CNTHVS_TVAL_EL2", { .raw_val = AARCH64_SYSREG_CNTHVS_TVAL_EL2 }, 0xE720, true, true,  {AArch64_FeatureSEL2}  }, // 231
  { "CNTHV_CTL_EL2", { .raw_val = AARCH64_SYSREG_CNTHV_CTL_EL2 }, "CNTHV_CTL_EL2", { .raw_val = AARCH64_SYSREG_CNTHV_CTL_EL2 }, 0xE719, true, true,  {AArch64_FeatureVH}  }, // 232
  { "CNTHV_CVAL_EL2", { .raw_val = AARCH64_SYSREG_CNTHV_CVAL_EL2 }, "CNTHV_CVAL_EL2", { .raw_val = AARCH64_SYSREG_CNTHV_CVAL_EL2 }, 0xE71A, true, true,  {AArch64_FeatureVH}  }, // 233
  { "CNTHV_TVAL_EL2", { .raw_val = AARCH64_SYSREG_CNTHV_TVAL_EL2 }, "CNTHV_TVAL_EL2", { .raw_val = AARCH64_SYSREG_CNTHV_TVAL_EL2 }, 0xE718, true, true,  {AArch64_FeatureVH}  }, // 234
  { "CNTISCALE_EL2", { .raw_val = AARCH64_SYSREG_CNTISCALE_EL2 }, "CNTISCALE_EL2", { .raw_val = AARCH64_SYSREG_CNTISCALE_EL2 }, 0xE705, true, true,  {AArch64_FeatureEnhancedCounterVirtualization}  }, // 235
  { "CNTKCTL_EL1", { .raw_val = AARCH64_SYSREG_CNTKCTL_EL1 }, "CNTKCTL_EL1", { .raw_val = AARCH64_SYSREG_CNTKCTL_EL1 }, 0xC708, true, true,  {0}  }, // 236
  { "CNTKCTL_EL12", { .raw_val = AARCH64_SYSREG_CNTKCTL_EL12 }, "CNTKCTL_EL12", { .raw_val = AARCH64_SYSREG_CNTKCTL_EL12 }, 0xEF08, true, true,  {AArch64_FeatureVH}  }, // 237
  { "CNTPCTSS_EL0", { .raw_val = AARCH64_SYSREG_CNTPCTSS_EL0 }, "CNTPCTSS_EL0", { .raw_val = AARCH64_SYSREG_CNTPCTSS_EL0 }, 0xDF05, true, false,  {AArch64_FeatureEnhancedCounterVirtualization}  }, // 238
  { "CNTPCT_EL0", { .raw_val = AARCH64_SYSREG_CNTPCT_EL0 }, "CNTPCT_EL0", { .raw_val = AARCH64_SYSREG_CNTPCT_EL0 }, 0xDF01, true, false,  {0}  }, // 239
  { "CNTPOFF_EL2", { .raw_val = AARCH64_SYSREG_CNTPOFF_EL2 }, "CNTPOFF_EL2", { .raw_val = AARCH64_SYSREG_CNTPOFF_EL2 }, 0xE706, true, true,  {AArch64_FeatureEnhancedCounterVirtualization}  }, // 240
  { "CNTPS_CTL_EL1", { .raw_val = AARCH64_SYSREG_CNTPS_CTL_EL1 }, "CNTPS_CTL_EL1", { .raw_val = AARCH64_SYSREG_CNTPS_CTL_EL1 }, 0xFF11, true, true,  {0}  }, // 241
  { "CNTPS_CVAL_EL1", { .raw_val = AARCH64_SYSREG_CNTPS_CVAL_EL1 }, "CNTPS_CVAL_EL1", { .raw_val = AARCH64_SYSREG_CNTPS_CVAL_EL1 }, 0xFF12, true, true,  {0}  }, // 242
  { "CNTPS_TVAL_EL1", { .raw_val = AARCH64_SYSREG_CNTPS_TVAL_EL1 }, "CNTPS_TVAL_EL1", { .raw_val = AARCH64_SYSREG_CNTPS_TVAL_EL1 }, 0xFF10, true, true,  {0}  }, // 243
  { "CNTP_CTL_EL0", { .raw_val = AARCH64_SYSREG_CNTP_CTL_EL0 }, "CNTP_CTL_EL0", { .raw_val = AARCH64_SYSREG_CNTP_CTL_EL0 }, 0xDF11, true, true,  {0}  }, // 244
  { "CNTP_CTL_EL02", { .raw_val = AARCH64_SYSREG_CNTP_CTL_EL02 }, "CNTP_CTL_EL02", { .raw_val = AARCH64_SYSREG_CNTP_CTL_EL02 }, 0xEF11, true, true,  {AArch64_FeatureVH}  }, // 245
  { "CNTP_CVAL_EL0", { .raw_val = AARCH64_SYSREG_CNTP_CVAL_EL0 }, "CNTP_CVAL_EL0", { .raw_val = AARCH64_SYSREG_CNTP_CVAL_EL0 }, 0xDF12, true, true,  {0}  }, // 246
  { "CNTP_CVAL_EL02", { .raw_val = AARCH64_SYSREG_CNTP_CVAL_EL02 }, "CNTP_CVAL_EL02", { .raw_val = AARCH64_SYSREG_CNTP_CVAL_EL02 }, 0xEF12, true, true,  {AArch64_FeatureVH}  }, // 247
  { "CNTP_TVAL_EL0", { .raw_val = AARCH64_SYSREG_CNTP_TVAL_EL0 }, "CNTP_TVAL_EL0", { .raw_val = AARCH64_SYSREG_CNTP_TVAL_EL0 }, 0xDF10, true, true,  {0}  }, // 248
  { "CNTP_TVAL_EL02", { .raw_val = AARCH64_SYSREG_CNTP_TVAL_EL02 }, "CNTP_TVAL_EL02", { .raw_val = AARCH64_SYSREG_CNTP_TVAL_EL02 }, 0xEF10, true, true,  {AArch64_FeatureVH}  }, // 249
  { "CNTSCALE_EL2", { .raw_val = AARCH64_SYSREG_CNTSCALE_EL2 }, "CNTSCALE_EL2", { .raw_val = AARCH64_SYSREG_CNTSCALE_EL2 }, 0xE704, true, true,  {AArch64_FeatureEnhancedCounterVirtualization}  }, // 250
  { "CNTVCTSS_EL0", { .raw_val = AARCH64_SYSREG_CNTVCTSS_EL0 }, "CNTVCTSS_EL0", { .raw_val = AARCH64_SYSREG_CNTVCTSS_EL0 }, 0xDF06, true, false,  {AArch64_FeatureEnhancedCounterVirtualization}  }, // 251
  { "CNTVCT_EL0", { .raw_val = AARCH64_SYSREG_CNTVCT_EL0 }, "CNTVCT_EL0", { .raw_val = AARCH64_SYSREG_CNTVCT_EL0 }, 0xDF02, true, false,  {0}  }, // 252
  { "CNTVFRQ_EL2", { .raw_val = AARCH64_SYSREG_CNTVFRQ_EL2 }, "CNTVFRQ_EL2", { .raw_val = AARCH64_SYSREG_CNTVFRQ_EL2 }, 0xE707, true, true,  {AArch64_FeatureEnhancedCounterVirtualization}  }, // 253
  { "CNTVOFF_EL2", { .raw_val = AARCH64_SYSREG_CNTVOFF_EL2 }, "CNTVOFF_EL2", { .raw_val = AARCH64_SYSREG_CNTVOFF_EL2 }, 0xE703, true, true,  {0}  }, // 254
  { "CNTV_CTL_EL0", { .raw_val = AARCH64_SYSREG_CNTV_CTL_EL0 }, "CNTV_CTL_EL0", { .raw_val = AARCH64_SYSREG_CNTV_CTL_EL0 }, 0xDF19, true, true,  {0}  }, // 255
  { "CNTV_CTL_EL02", { .raw_val = AARCH64_SYSREG_CNTV_CTL_EL02 }, "CNTV_CTL_EL02", { .raw_val = AARCH64_SYSREG_CNTV_CTL_EL02 }, 0xEF19, true, true,  {AArch64_FeatureVH}  }, // 256
  { "CNTV_CVAL_EL0", { .raw_val = AARCH64_SYSREG_CNTV_CVAL_EL0 }, "CNTV_CVAL_EL0", { .raw_val = AARCH64_SYSREG_CNTV_CVAL_EL0 }, 0xDF1A, true, true,  {0}  }, // 257
  { "CNTV_CVAL_EL02", { .raw_val = AARCH64_SYSREG_CNTV_CVAL_EL02 }, "CNTV_CVAL_EL02", { .raw_val = AARCH64_SYSREG_CNTV_CVAL_EL02 }, 0xEF1A, true, true,  {AArch64_FeatureVH}  }, // 258
  { "CNTV_TVAL_EL0", { .raw_val = AARCH64_SYSREG_CNTV_TVAL_EL0 }, "CNTV_TVAL_EL0", { .raw_val = AARCH64_SYSREG_CNTV_TVAL_EL0 }, 0xDF18, true, true,  {0}  }, // 259
  { "CNTV_TVAL_EL02", { .raw_val = AARCH64_SYSREG_CNTV_TVAL_EL02 }, "CNTV_TVAL_EL02", { .raw_val = AARCH64_SYSREG_CNTV_TVAL_EL02 }, 0xEF18, true, true,  {AArch64_FeatureVH}  }, // 260
  { "CONTEXTIDR_EL1", { .raw_val = AARCH64_SYSREG_CONTEXTIDR_EL1 }, "CONTEXTIDR_EL1", { .raw_val = AARCH64_SYSREG_CONTEXTIDR_EL1 }, 0xC681, true, true,  {0}  }, // 261
  { "CONTEXTIDR_EL12", { .raw_val = AARCH64_SYSREG_CONTEXTIDR_EL12 }, "CONTEXTIDR_EL12", { .raw_val = AARCH64_SYSREG_CONTEXTIDR_EL12 }, 0xEE81, true, true,  {AArch64_FeatureVH}  }, // 262
  { "CONTEXTIDR_EL2", { .raw_val = AARCH64_SYSREG_CONTEXTIDR_EL2 }, "CONTEXTIDR_EL2", { .raw_val = AARCH64_SYSREG_CONTEXTIDR_EL2 }, 0xE681, true, true,  {AArch64_FeatureCONTEXTIDREL2}  }, // 263
  { "CPACR_EL1", { .raw_val = AARCH64_SYSREG_CPACR_EL1 }, "CPACR_EL1", { .raw_val = AARCH64_SYSREG_CPACR_EL1 }, 0xC082, true, true,  {0}  }, // 264
  { "CPACR_EL12", { .raw_val = AARCH64_SYSREG_CPACR_EL12 }, "CPACR_EL12", { .raw_val = AARCH64_SYSREG_CPACR_EL12 }, 0xE882, true, true,  {AArch64_FeatureVH}  }, // 265
  { "CPM_IOACC_CTL_EL3", { .raw_val = AARCH64_SYSREG_CPM_IOACC_CTL_EL3 }, "CPM_IOACC_CTL_EL3", { .raw_val = AARCH64_SYSREG_CPM_IOACC_CTL_EL3 }, 0xFF90, true, true,  {AArch64_FeatureAppleA7SysReg}  }, // 266
  { "CPTR_EL2", { .raw_val = AARCH64_SYSREG_CPTR_EL2 }, "CPTR_EL2", { .raw_val = AARCH64_SYSREG_CPTR_EL2 }, 0xE08A, true, true,  {0}  }, // 267
  { "CPTR_EL3", { .raw_val = AARCH64_SYSREG_CPTR_EL3 }, "CPTR_EL3", { .raw_val = AARCH64_SYSREG_CPTR_EL3 }, 0xF08A, true, true,  {0}  }, // 268
  { "CSSELR_EL1", { .raw_val = AARCH64_SYSREG_CSSELR_EL1 }, "CSSELR_EL1", { .raw_val = AARCH64_SYSREG_CSSELR_EL1 }, 0xD000, true, true,  {0}  }, // 269
  { "CTR_EL0", { .raw_val = AARCH64_SYSREG_CTR_EL0 }, "CTR_EL0", { .raw_val = AARCH64_SYSREG_CTR_EL0 }, 0xD801, true, false,  {0}  }, // 270
  { "CurrentEL", { .raw_val = AARCH64_SYSREG_CURRENTEL }, "CurrentEL", { .raw_val = AARCH64_SYSREG_CURRENTEL }, 0xC212, true, false,  {0}  }, // 271
  { "DACR32_EL2", { .raw_val = AARCH64_SYSREG_DACR32_EL2 }, "DACR32_EL2", { .raw_val = AARCH64_SYSREG_DACR32_EL2 }, 0xE180, true, true,  {0}  }, // 272
  { "DAIF", { .raw_val = AARCH64_SYSREG_DAIF }, "DAIF", { .raw_val = AARCH64_SYSREG_DAIF }, 0xDA11, true, true,  {0}  }, // 273
  { "DBGAUTHSTATUS_EL1", { .raw_val = AARCH64_SYSREG_DBGAUTHSTATUS_EL1 }, "DBGAUTHSTATUS_EL1", { .raw_val = AARCH64_SYSREG_DBGAUTHSTATUS_EL1 }, 0x83F6, true, false,  {0}  }, // 274
  { "DBGBCR0_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR0_EL1 }, "DBGBCR0_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR0_EL1 }, 0x8005, true, true,  {0}  }, // 275
  { "DBGBCR10_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR10_EL1 }, "DBGBCR10_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR10_EL1 }, 0x8055, true, true,  {0}  }, // 276
  { "DBGBCR11_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR11_EL1 }, "DBGBCR11_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR11_EL1 }, 0x805D, true, true,  {0}  }, // 277
  { "DBGBCR12_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR12_EL1 }, "DBGBCR12_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR12_EL1 }, 0x8065, true, true,  {0}  }, // 278
  { "DBGBCR13_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR13_EL1 }, "DBGBCR13_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR13_EL1 }, 0x806D, true, true,  {0}  }, // 279
  { "DBGBCR14_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR14_EL1 }, "DBGBCR14_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR14_EL1 }, 0x8075, true, true,  {0}  }, // 280
  { "DBGBCR15_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR15_EL1 }, "DBGBCR15_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR15_EL1 }, 0x807D, true, true,  {0}  }, // 281
  { "DBGBCR1_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR1_EL1 }, "DBGBCR1_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR1_EL1 }, 0x800D, true, true,  {0}  }, // 282
  { "DBGBCR2_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR2_EL1 }, "DBGBCR2_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR2_EL1 }, 0x8015, true, true,  {0}  }, // 283
  { "DBGBCR3_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR3_EL1 }, "DBGBCR3_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR3_EL1 }, 0x801D, true, true,  {0}  }, // 284
  { "DBGBCR4_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR4_EL1 }, "DBGBCR4_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR4_EL1 }, 0x8025, true, true,  {0}  }, // 285
  { "DBGBCR5_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR5_EL1 }, "DBGBCR5_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR5_EL1 }, 0x802D, true, true,  {0}  }, // 286
  { "DBGBCR6_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR6_EL1 }, "DBGBCR6_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR6_EL1 }, 0x8035, true, true,  {0}  }, // 287
  { "DBGBCR7_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR7_EL1 }, "DBGBCR7_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR7_EL1 }, 0x803D, true, true,  {0}  }, // 288
  { "DBGBCR8_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR8_EL1 }, "DBGBCR8_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR8_EL1 }, 0x8045, true, true,  {0}  }, // 289
  { "DBGBCR9_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR9_EL1 }, "DBGBCR9_EL1", { .raw_val = AARCH64_SYSREG_DBGBCR9_EL1 }, 0x804D, true, true,  {0}  }, // 290
  { "DBGBVR0_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR0_EL1 }, "DBGBVR0_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR0_EL1 }, 0x8004, true, true,  {0}  }, // 291
  { "DBGBVR10_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR10_EL1 }, "DBGBVR10_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR10_EL1 }, 0x8054, true, true,  {0}  }, // 292
  { "DBGBVR11_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR11_EL1 }, "DBGBVR11_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR11_EL1 }, 0x805C, true, true,  {0}  }, // 293
  { "DBGBVR12_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR12_EL1 }, "DBGBVR12_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR12_EL1 }, 0x8064, true, true,  {0}  }, // 294
  { "DBGBVR13_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR13_EL1 }, "DBGBVR13_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR13_EL1 }, 0x806C, true, true,  {0}  }, // 295
  { "DBGBVR14_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR14_EL1 }, "DBGBVR14_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR14_EL1 }, 0x8074, true, true,  {0}  }, // 296
  { "DBGBVR15_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR15_EL1 }, "DBGBVR15_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR15_EL1 }, 0x807C, true, true,  {0}  }, // 297
  { "DBGBVR1_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR1_EL1 }, "DBGBVR1_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR1_EL1 }, 0x800C, true, true,  {0}  }, // 298
  { "DBGBVR2_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR2_EL1 }, "DBGBVR2_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR2_EL1 }, 0x8014, true, true,  {0}  }, // 299
  { "DBGBVR3_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR3_EL1 }, "DBGBVR3_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR3_EL1 }, 0x801C, true, true,  {0}  }, // 300
  { "DBGBVR4_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR4_EL1 }, "DBGBVR4_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR4_EL1 }, 0x8024, true, true,  {0}  }, // 301
  { "DBGBVR5_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR5_EL1 }, "DBGBVR5_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR5_EL1 }, 0x802C, true, true,  {0}  }, // 302
  { "DBGBVR6_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR6_EL1 }, "DBGBVR6_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR6_EL1 }, 0x8034, true, true,  {0}  }, // 303
  { "DBGBVR7_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR7_EL1 }, "DBGBVR7_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR7_EL1 }, 0x803C, true, true,  {0}  }, // 304
  { "DBGBVR8_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR8_EL1 }, "DBGBVR8_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR8_EL1 }, 0x8044, true, true,  {0}  }, // 305
  { "DBGBVR9_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR9_EL1 }, "DBGBVR9_EL1", { .raw_val = AARCH64_SYSREG_DBGBVR9_EL1 }, 0x804C, true, true,  {0}  }, // 306
  { "DBGCLAIMCLR_EL1", { .raw_val = AARCH64_SYSREG_DBGCLAIMCLR_EL1 }, "DBGCLAIMCLR_EL1", { .raw_val = AARCH64_SYSREG_DBGCLAIMCLR_EL1 }, 0x83CE, true, true,  {0}  }, // 307
  { "DBGCLAIMSET_EL1", { .raw_val = AARCH64_SYSREG_DBGCLAIMSET_EL1 }, "DBGCLAIMSET_EL1", { .raw_val = AARCH64_SYSREG_DBGCLAIMSET_EL1 }, 0x83C6, true, true,  {0}  }, // 308
  { "DBGDTRRX_EL0", { .raw_val = AARCH64_SYSREG_DBGDTRRX_EL0 }, "DBGDTRRX_EL0", { .raw_val = AARCH64_SYSREG_DBGDTRRX_EL0 }, 0x9828, true, false,  {0}  }, // 309
  { "DBGDTRTX_EL0", { .raw_val = AARCH64_SYSREG_DBGDTRTX_EL0 }, "DBGDTRTX_EL0", { .raw_val = AARCH64_SYSREG_DBGDTRTX_EL0 }, 0x9828, false, true,  {0}  }, // 310
  { "DBGDTR_EL0", { .raw_val = AARCH64_SYSREG_DBGDTR_EL0 }, "DBGDTR_EL0", { .raw_val = AARCH64_SYSREG_DBGDTR_EL0 }, 0x9820, true, true,  {0}  }, // 311
  { "DBGPRCR_EL1", { .raw_val = AARCH64_SYSREG_DBGPRCR_EL1 }, "DBGPRCR_EL1", { .raw_val = AARCH64_SYSREG_DBGPRCR_EL1 }, 0x80A4, true, true,  {0}  }, // 312
  { "DBGVCR32_EL2", { .raw_val = AARCH64_SYSREG_DBGVCR32_EL2 }, "DBGVCR32_EL2", { .raw_val = AARCH64_SYSREG_DBGVCR32_EL2 }, 0xA038, true, true,  {0}  }, // 313
  { "DBGWCR0_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR0_EL1 }, "DBGWCR0_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR0_EL1 }, 0x8007, true, true,  {0}  }, // 314
  { "DBGWCR10_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR10_EL1 }, "DBGWCR10_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR10_EL1 }, 0x8057, true, true,  {0}  }, // 315
  { "DBGWCR11_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR11_EL1 }, "DBGWCR11_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR11_EL1 }, 0x805F, true, true,  {0}  }, // 316
  { "DBGWCR12_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR12_EL1 }, "DBGWCR12_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR12_EL1 }, 0x8067, true, true,  {0}  }, // 317
  { "DBGWCR13_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR13_EL1 }, "DBGWCR13_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR13_EL1 }, 0x806F, true, true,  {0}  }, // 318
  { "DBGWCR14_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR14_EL1 }, "DBGWCR14_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR14_EL1 }, 0x8077, true, true,  {0}  }, // 319
  { "DBGWCR15_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR15_EL1 }, "DBGWCR15_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR15_EL1 }, 0x807F, true, true,  {0}  }, // 320
  { "DBGWCR1_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR1_EL1 }, "DBGWCR1_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR1_EL1 }, 0x800F, true, true,  {0}  }, // 321
  { "DBGWCR2_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR2_EL1 }, "DBGWCR2_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR2_EL1 }, 0x8017, true, true,  {0}  }, // 322
  { "DBGWCR3_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR3_EL1 }, "DBGWCR3_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR3_EL1 }, 0x801F, true, true,  {0}  }, // 323
  { "DBGWCR4_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR4_EL1 }, "DBGWCR4_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR4_EL1 }, 0x8027, true, true,  {0}  }, // 324
  { "DBGWCR5_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR5_EL1 }, "DBGWCR5_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR5_EL1 }, 0x802F, true, true,  {0}  }, // 325
  { "DBGWCR6_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR6_EL1 }, "DBGWCR6_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR6_EL1 }, 0x8037, true, true,  {0}  }, // 326
  { "DBGWCR7_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR7_EL1 }, "DBGWCR7_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR7_EL1 }, 0x803F, true, true,  {0}  }, // 327
  { "DBGWCR8_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR8_EL1 }, "DBGWCR8_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR8_EL1 }, 0x8047, true, true,  {0}  }, // 328
  { "DBGWCR9_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR9_EL1 }, "DBGWCR9_EL1", { .raw_val = AARCH64_SYSREG_DBGWCR9_EL1 }, 0x804F, true, true,  {0}  }, // 329
  { "DBGWVR0_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR0_EL1 }, "DBGWVR0_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR0_EL1 }, 0x8006, true, true,  {0}  }, // 330
  { "DBGWVR10_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR10_EL1 }, "DBGWVR10_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR10_EL1 }, 0x8056, true, true,  {0}  }, // 331
  { "DBGWVR11_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR11_EL1 }, "DBGWVR11_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR11_EL1 }, 0x805E, true, true,  {0}  }, // 332
  { "DBGWVR12_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR12_EL1 }, "DBGWVR12_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR12_EL1 }, 0x8066, true, true,  {0}  }, // 333
  { "DBGWVR13_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR13_EL1 }, "DBGWVR13_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR13_EL1 }, 0x806E, true, true,  {0}  }, // 334
  { "DBGWVR14_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR14_EL1 }, "DBGWVR14_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR14_EL1 }, 0x8076, true, true,  {0}  }, // 335
  { "DBGWVR15_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR15_EL1 }, "DBGWVR15_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR15_EL1 }, 0x807E, true, true,  {0}  }, // 336
  { "DBGWVR1_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR1_EL1 }, "DBGWVR1_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR1_EL1 }, 0x800E, true, true,  {0}  }, // 337
  { "DBGWVR2_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR2_EL1 }, "DBGWVR2_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR2_EL1 }, 0x8016, true, true,  {0}  }, // 338
  { "DBGWVR3_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR3_EL1 }, "DBGWVR3_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR3_EL1 }, 0x801E, true, true,  {0}  }, // 339
  { "DBGWVR4_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR4_EL1 }, "DBGWVR4_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR4_EL1 }, 0x8026, true, true,  {0}  }, // 340
  { "DBGWVR5_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR5_EL1 }, "DBGWVR5_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR5_EL1 }, 0x802E, true, true,  {0}  }, // 341
  { "DBGWVR6_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR6_EL1 }, "DBGWVR6_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR6_EL1 }, 0x8036, true, true,  {0}  }, // 342
  { "DBGWVR7_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR7_EL1 }, "DBGWVR7_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR7_EL1 }, 0x803E, true, true,  {0}  }, // 343
  { "DBGWVR8_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR8_EL1 }, "DBGWVR8_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR8_EL1 }, 0x8046, true, true,  {0}  }, // 344
  { "DBGWVR9_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR9_EL1 }, "DBGWVR9_EL1", { .raw_val = AARCH64_SYSREG_DBGWVR9_EL1 }, 0x804E, true, true,  {0}  }, // 345
  { "DCZID_EL0", { .raw_val = AARCH64_SYSREG_DCZID_EL0 }, "DCZID_EL0", { .raw_val = AARCH64_SYSREG_DCZID_EL0 }, 0xD807, true, false,  {0}  }, // 346
  { "DISR_EL1", { .raw_val = AARCH64_SYSREG_DISR_EL1 }, "DISR_EL1", { .raw_val = AARCH64_SYSREG_DISR_EL1 }, 0xC609, true, true,  {AArch64_FeatureRAS}  }, // 347
  { "DIT", { .raw_val = AARCH64_SYSREG_DIT }, "DIT", { .raw_val = AARCH64_SYSREG_DIT }, 0xDA15, true, true,  {AArch64_FeatureDIT}  }, // 348
  { "DLR_EL0", { .raw_val = AARCH64_SYSREG_DLR_EL0 }, "DLR_EL0", { .raw_val = AARCH64_SYSREG_DLR_EL0 }, 0xDA29, true, true,  {0}  }, // 349
  { "DSPSR_EL0", { .raw_val = AARCH64_SYSREG_DSPSR_EL0 }, "DSPSR_EL0", { .raw_val = AARCH64_SYSREG_DSPSR_EL0 }, 0xDA28, true, true,  {0}  }, // 350
  { "ELR_EL1", { .raw_val = AARCH64_SYSREG_ELR_EL1 }, "ELR_EL1", { .raw_val = AARCH64_SYSREG_ELR_EL1 }, 0xC201, true, true,  {0}  }, // 351
  { "ELR_EL12", { .raw_val = AARCH64_SYSREG_ELR_EL12 }, "ELR_EL12", { .raw_val = AARCH64_SYSREG_ELR_EL12 }, 0xEA01, true, true,  {AArch64_FeatureVH}  }, // 352
  { "ELR_EL2", { .raw_val = AARCH64_SYSREG_ELR_EL2 }, "ELR_EL2", { .raw_val = AARCH64_SYSREG_ELR_EL2 }, 0xE201, true, true,  {0}  }, // 353
  { "ELR_EL3", { .raw_val = AARCH64_SYSREG_ELR_EL3 }, "ELR_EL3", { .raw_val = AARCH64_SYSREG_ELR_EL3 }, 0xF201, true, true,  {0}  }, // 354
  { "ERRIDR_EL1", { .raw_val = AARCH64_SYSREG_ERRIDR_EL1 }, "ERRIDR_EL1", { .raw_val = AARCH64_SYSREG_ERRIDR_EL1 }, 0xC298, true, false,  {AArch64_FeatureRAS}  }, // 355
  { "ERRSELR_EL1", { .raw_val = AARCH64_SYSREG_ERRSELR_EL1 }, "ERRSELR_EL1", { .raw_val = AARCH64_SYSREG_ERRSELR_EL1 }, 0xC299, true, true,  {AArch64_FeatureRAS}  }, // 356
  { "ERXADDR_EL1", { .raw_val = AARCH64_SYSREG_ERXADDR_EL1 }, "ERXADDR_EL1", { .raw_val = AARCH64_SYSREG_ERXADDR_EL1 }, 0xC2A3, true, true,  {AArch64_FeatureRAS}  }, // 357
  { "ERXCTLR_EL1", { .raw_val = AARCH64_SYSREG_ERXCTLR_EL1 }, "ERXCTLR_EL1", { .raw_val = AARCH64_SYSREG_ERXCTLR_EL1 }, 0xC2A1, true, true,  {AArch64_FeatureRAS}  }, // 358
  { "ERXFR_EL1", { .raw_val = AARCH64_SYSREG_ERXFR_EL1 }, "ERXFR_EL1", { .raw_val = AARCH64_SYSREG_ERXFR_EL1 }, 0xC2A0, true, false,  {AArch64_FeatureRAS}  }, // 359
  { "ERXGSR_EL1", { .raw_val = AARCH64_SYSREG_ERXGSR_EL1 }, "ERXGSR_EL1", { .raw_val = AARCH64_SYSREG_ERXGSR_EL1 }, 0xC29A, true, false,  {AArch64_FeatureRASv2}  }, // 360
  { "ERXMISC0_EL1", { .raw_val = AARCH64_SYSREG_ERXMISC0_EL1 }, "ERXMISC0_EL1", { .raw_val = AARCH64_SYSREG_ERXMISC0_EL1 }, 0xC2A8, true, true,  {AArch64_FeatureRAS}  }, // 361
  { "ERXMISC1_EL1", { .raw_val = AARCH64_SYSREG_ERXMISC1_EL1 }, "ERXMISC1_EL1", { .raw_val = AARCH64_SYSREG_ERXMISC1_EL1 }, 0xC2A9, true, true,  {AArch64_FeatureRAS}  }, // 362
  { "ERXMISC2_EL1", { .raw_val = AARCH64_SYSREG_ERXMISC2_EL1 }, "ERXMISC2_EL1", { .raw_val = AARCH64_SYSREG_ERXMISC2_EL1 }, 0xC2AA, true, true,  {0}  }, // 363
  { "ERXMISC3_EL1", { .raw_val = AARCH64_SYSREG_ERXMISC3_EL1 }, "ERXMISC3_EL1", { .raw_val = AARCH64_SYSREG_ERXMISC3_EL1 }, 0xC2AB, true, true,  {0}  }, // 364
  { "ERXPFGCDN_EL1", { .raw_val = AARCH64_SYSREG_ERXPFGCDN_EL1 }, "ERXPFGCDN_EL1", { .raw_val = AARCH64_SYSREG_ERXPFGCDN_EL1 }, 0xC2A6, true, true,  {0}  }, // 365
  { "ERXPFGCTL_EL1", { .raw_val = AARCH64_SYSREG_ERXPFGCTL_EL1 }, "ERXPFGCTL_EL1", { .raw_val = AARCH64_SYSREG_ERXPFGCTL_EL1 }, 0xC2A5, true, true,  {0}  }, // 366
  { "ERXPFGF_EL1", { .raw_val = AARCH64_SYSREG_ERXPFGF_EL1 }, "ERXPFGF_EL1", { .raw_val = AARCH64_SYSREG_ERXPFGF_EL1 }, 0xC2A4, true, false,  {0}  }, // 367
  { "ERXSTATUS_EL1", { .raw_val = AARCH64_SYSREG_ERXSTATUS_EL1 }, "ERXSTATUS_EL1", { .raw_val = AARCH64_SYSREG_ERXSTATUS_EL1 }, 0xC2A2, true, true,  {AArch64_FeatureRAS}  }, // 368
  { "ESR_EL1", { .raw_val = AARCH64_SYSREG_ESR_EL1 }, "ESR_EL1", { .raw_val = AARCH64_SYSREG_ESR_EL1 }, 0xC290, true, true,  {0}  }, // 369
  { "ESR_EL12", { .raw_val = AARCH64_SYSREG_ESR_EL12 }, "ESR_EL12", { .raw_val = AARCH64_SYSREG_ESR_EL12 }, 0xEA90, true, true,  {AArch64_FeatureVH}  }, // 370
  { "ESR_EL2", { .raw_val = AARCH64_SYSREG_ESR_EL2 }, "ESR_EL2", { .raw_val = AARCH64_SYSREG_ESR_EL2 }, 0xE290, true, true,  {0}  }, // 371
  { "ESR_EL3", { .raw_val = AARCH64_SYSREG_ESR_EL3 }, "ESR_EL3", { .raw_val = AARCH64_SYSREG_ESR_EL3 }, 0xF290, true, true,  {0}  }, // 372
  { "FAR_EL1", { .raw_val = AARCH64_SYSREG_FAR_EL1 }, "FAR_EL1", { .raw_val = AARCH64_SYSREG_FAR_EL1 }, 0xC300, true, true,  {0}  }, // 373
  { "FAR_EL12", { .raw_val = AARCH64_SYSREG_FAR_EL12 }, "FAR_EL12", { .raw_val = AARCH64_SYSREG_FAR_EL12 }, 0xEB00, true, true,  {AArch64_FeatureVH}  }, // 374
  { "FAR_EL2", { .raw_val = AARCH64_SYSREG_FAR_EL2 }, "FAR_EL2", { .raw_val = AARCH64_SYSREG_FAR_EL2 }, 0xE300, true, true,  {0}  }, // 375
  { "FAR_EL3", { .raw_val = AARCH64_SYSREG_FAR_EL3 }, "FAR_EL3", { .raw_val = AARCH64_SYSREG_FAR_EL3 }, 0xF300, true, true,  {0}  }, // 376
  { "FGWTE3_EL3", { .raw_val = AARCH64_SYSREG_FGWTE3_EL3 }, "FGWTE3_EL3", { .raw_val = AARCH64_SYSREG_FGWTE3_EL3 }, 0xF08D, true, true,  {0}  }, // 377
  { "FPCR", { .raw_val = AARCH64_SYSREG_FPCR }, "FPCR", { .raw_val = AARCH64_SYSREG_FPCR }, 0xDA20, true, true,  {AArch64_FeatureFPARMv8}  }, // 378
  { "FPEXC32_EL2", { .raw_val = AARCH64_SYSREG_FPEXC32_EL2 }, "FPEXC32_EL2", { .raw_val = AARCH64_SYSREG_FPEXC32_EL2 }, 0xE298, true, true,  {0}  }, // 379
  { "FPMR", { .raw_val = AARCH64_SYSREG_FPMR }, "FPMR", { .raw_val = AARCH64_SYSREG_FPMR }, 0xDA22, true, true,  {AArch64_FeatureFPMR}  }, // 380
  { "FPSR", { .raw_val = AARCH64_SYSREG_FPSR }, "FPSR", { .raw_val = AARCH64_SYSREG_FPSR }, 0xDA21, true, true,  {AArch64_FeatureFPARMv8}  }, // 381
  { "GCR_EL1", { .raw_val = AARCH64_SYSREG_GCR_EL1 }, "GCR_EL1", { .raw_val = AARCH64_SYSREG_GCR_EL1 }, 0xC086, true, true,  {AArch64_FeatureMTE}  }, // 382
  { "GCSCRE0_EL1", { .raw_val = AARCH64_SYSREG_GCSCRE0_EL1 }, "GCSCRE0_EL1", { .raw_val = AARCH64_SYSREG_GCSCRE0_EL1 }, 0xC12A, true, true,  {0}  }, // 383
  { "GCSCR_EL1", { .raw_val = AARCH64_SYSREG_GCSCR_EL1 }, "GCSCR_EL1", { .raw_val = AARCH64_SYSREG_GCSCR_EL1 }, 0xC128, true, true,  {0}  }, // 384
  { "GCSCR_EL12", { .raw_val = AARCH64_SYSREG_GCSCR_EL12 }, "GCSCR_EL12", { .raw_val = AARCH64_SYSREG_GCSCR_EL12 }, 0xE928, true, true,  {0}  }, // 385
  { "GCSCR_EL2", { .raw_val = AARCH64_SYSREG_GCSCR_EL2 }, "GCSCR_EL2", { .raw_val = AARCH64_SYSREG_GCSCR_EL2 }, 0xE128, true, true,  {0}  }, // 386
  { "GCSCR_EL3", { .raw_val = AARCH64_SYSREG_GCSCR_EL3 }, "GCSCR_EL3", { .raw_val = AARCH64_SYSREG_GCSCR_EL3 }, 0xF128, true, true,  {0}  }, // 387
  { "GCSPR_EL0", { .raw_val = AARCH64_SYSREG_GCSPR_EL0 }, "GCSPR_EL0", { .raw_val = AARCH64_SYSREG_GCSPR_EL0 }, 0xD929, true, true,  {0}  }, // 388
  { "GCSPR_EL1", { .raw_val = AARCH64_SYSREG_GCSPR_EL1 }, "GCSPR_EL1", { .raw_val = AARCH64_SYSREG_GCSPR_EL1 }, 0xC129, true, true,  {0}  }, // 389
  { "GCSPR_EL12", { .raw_val = AARCH64_SYSREG_GCSPR_EL12 }, "GCSPR_EL12", { .raw_val = AARCH64_SYSREG_GCSPR_EL12 }, 0xE929, true, true,  {0}  }, // 390
  { "GCSPR_EL2", { .raw_val = AARCH64_SYSREG_GCSPR_EL2 }, "GCSPR_EL2", { .raw_val = AARCH64_SYSREG_GCSPR_EL2 }, 0xE129, true, true,  {0}  }, // 391
  { "GCSPR_EL3", { .raw_val = AARCH64_SYSREG_GCSPR_EL3 }, "GCSPR_EL3", { .raw_val = AARCH64_SYSREG_GCSPR_EL3 }, 0xF129, true, true,  {0}  }, // 392
  { "GMID_EL1", { .raw_val = AARCH64_SYSREG_GMID_EL1 }, "GMID_EL1", { .raw_val = AARCH64_SYSREG_GMID_EL1 }, 0xC804, true, false,  {AArch64_FeatureMTE}  }, // 393
  { "GPCCR_EL3", { .raw_val = AARCH64_SYSREG_GPCCR_EL3 }, "GPCCR_EL3", { .raw_val = AARCH64_SYSREG_GPCCR_EL3 }, 0xF10E, true, true,  {AArch64_FeatureRME}  }, // 394
  { "GPTBR_EL3", { .raw_val = AARCH64_SYSREG_GPTBR_EL3 }, "GPTBR_EL3", { .raw_val = AARCH64_SYSREG_GPTBR_EL3 }, 0xF10C, true, true,  {AArch64_FeatureRME}  }, // 395
  { "HACDBSBR_EL2", { .raw_val = AARCH64_SYSREG_HACDBSBR_EL2 }, "HACDBSBR_EL2", { .raw_val = AARCH64_SYSREG_HACDBSBR_EL2 }, 0xE11C, true, true,  {0}  }, // 396
  { "HACDBSCONS_EL2", { .raw_val = AARCH64_SYSREG_HACDBSCONS_EL2 }, "HACDBSCONS_EL2", { .raw_val = AARCH64_SYSREG_HACDBSCONS_EL2 }, 0xE11D, true, true,  {0}  }, // 397
  { "HACR_EL2", { .raw_val = AARCH64_SYSREG_HACR_EL2 }, "HACR_EL2", { .raw_val = AARCH64_SYSREG_HACR_EL2 }, 0xE08F, true, true,  {0}  }, // 398
  { "HAFGRTR_EL2", { .raw_val = AARCH64_SYSREG_HAFGRTR_EL2 }, "HAFGRTR_EL2", { .raw_val = AARCH64_SYSREG_HAFGRTR_EL2 }, 0xE18E, true, true,  {AArch64_FeatureFineGrainedTraps}  }, // 399
  { "HCRX_EL2", { .raw_val = AARCH64_SYSREG_HCRX_EL2 }, "HCRX_EL2", { .raw_val = AARCH64_SYSREG_HCRX_EL2 }, 0xE092, true, true,  {AArch64_FeatureHCX}  }, // 400
  { "HCR_EL2", { .raw_val = AARCH64_SYSREG_HCR_EL2 }, "HCR_EL2", { .raw_val = AARCH64_SYSREG_HCR_EL2 }, 0xE088, true, true,  {0}  }, // 401
  { "HDBSSBR_EL2", { .raw_val = AARCH64_SYSREG_HDBSSBR_EL2 }, "HDBSSBR_EL2", { .raw_val = AARCH64_SYSREG_HDBSSBR_EL2 }, 0xE11A, true, true,  {0}  }, // 402
  { "HDBSSPROD_EL2", { .raw_val = AARCH64_SYSREG_HDBSSPROD_EL2 }, "HDBSSPROD_EL2", { .raw_val = AARCH64_SYSREG_HDBSSPROD_EL2 }, 0xE11B, true, true,  {0}  }, // 403
  { "HDFGRTR2_EL2", { .raw_val = AARCH64_SYSREG_HDFGRTR2_EL2 }, "HDFGRTR2_EL2", { .raw_val = AARCH64_SYSREG_HDFGRTR2_EL2 }, 0xE188, true, true,  {AArch64_FeatureFineGrainedTraps}  }, // 404
  { "HDFGRTR_EL2", { .raw_val = AARCH64_SYSREG_HDFGRTR_EL2 }, "HDFGRTR_EL2", { .raw_val = AARCH64_SYSREG_HDFGRTR_EL2 }, 0xE18C, true, true,  {AArch64_FeatureFineGrainedTraps}  }, // 405
  { "HDFGWTR2_EL2", { .raw_val = AARCH64_SYSREG_HDFGWTR2_EL2 }, "HDFGWTR2_EL2", { .raw_val = AARCH64_SYSREG_HDFGWTR2_EL2 }, 0xE189, true, true,  {AArch64_FeatureFineGrainedTraps}  }, // 406
  { "HDFGWTR_EL2", { .raw_val = AARCH64_SYSREG_HDFGWTR_EL2 }, "HDFGWTR_EL2", { .raw_val = AARCH64_SYSREG_HDFGWTR_EL2 }, 0xE18D, true, true,  {AArch64_FeatureFineGrainedTraps}  }, // 407
  { "HFGITR2_EL2", { .raw_val = AARCH64_SYSREG_HFGITR2_EL2 }, "HFGITR2_EL2", { .raw_val = AARCH64_SYSREG_HFGITR2_EL2 }, 0xE18F, true, true,  {AArch64_FeatureFineGrainedTraps}  }, // 408
  { "HFGITR_EL2", { .raw_val = AARCH64_SYSREG_HFGITR_EL2 }, "HFGITR_EL2", { .raw_val = AARCH64_SYSREG_HFGITR_EL2 }, 0xE08E, true, true,  {AArch64_FeatureFineGrainedTraps}  }, // 409
  { "HFGRTR2_EL2", { .raw_val = AARCH64_SYSREG_HFGRTR2_EL2 }, "HFGRTR2_EL2", { .raw_val = AARCH64_SYSREG_HFGRTR2_EL2 }, 0xE18A, true, true,  {AArch64_FeatureFineGrainedTraps}  }, // 410
  { "HFGRTR_EL2", { .raw_val = AARCH64_SYSREG_HFGRTR_EL2 }, "HFGRTR_EL2", { .raw_val = AARCH64_SYSREG_HFGRTR_EL2 }, 0xE08C, true, true,  {AArch64_FeatureFineGrainedTraps}  }, // 411
  { "HFGWTR2_EL2", { .raw_val = AARCH64_SYSREG_HFGWTR2_EL2 }, "HFGWTR2_EL2", { .raw_val = AARCH64_SYSREG_HFGWTR2_EL2 }, 0xE18B, true, true,  {AArch64_FeatureFineGrainedTraps}  }, // 412
  { "HFGWTR_EL2", { .raw_val = AARCH64_SYSREG_HFGWTR_EL2 }, "HFGWTR_EL2", { .raw_val = AARCH64_SYSREG_HFGWTR_EL2 }, 0xE08D, true, true,  {AArch64_FeatureFineGrainedTraps}  }, // 413
  { "HPFAR_EL2", { .raw_val = AARCH64_SYSREG_HPFAR_EL2 }, "HPFAR_EL2", { .raw_val = AARCH64_SYSREG_HPFAR_EL2 }, 0xE304, true, true,  {0}  }, // 414
  { "HSTR_EL2", { .raw_val = AARCH64_SYSREG_HSTR_EL2 }, "HSTR_EL2", { .raw_val = AARCH64_SYSREG_HSTR_EL2 }, 0xE08B, true, true,  {0}  }, // 415
  { "ICC_AP0R0_EL1", { .raw_val = AARCH64_SYSREG_ICC_AP0R0_EL1 }, "ICC_AP0R0_EL1", { .raw_val = AARCH64_SYSREG_ICC_AP0R0_EL1 }, 0xC644, true, true,  {0}  }, // 416
  { "ICC_AP0R1_EL1", { .raw_val = AARCH64_SYSREG_ICC_AP0R1_EL1 }, "ICC_AP0R1_EL1", { .raw_val = AARCH64_SYSREG_ICC_AP0R1_EL1 }, 0xC645, true, true,  {0}  }, // 417
  { "ICC_AP0R2_EL1", { .raw_val = AARCH64_SYSREG_ICC_AP0R2_EL1 }, "ICC_AP0R2_EL1", { .raw_val = AARCH64_SYSREG_ICC_AP0R2_EL1 }, 0xC646, true, true,  {0}  }, // 418
  { "ICC_AP0R3_EL1", { .raw_val = AARCH64_SYSREG_ICC_AP0R3_EL1 }, "ICC_AP0R3_EL1", { .raw_val = AARCH64_SYSREG_ICC_AP0R3_EL1 }, 0xC647, true, true,  {0}  }, // 419
  { "ICC_AP1R0_EL1", { .raw_val = AARCH64_SYSREG_ICC_AP1R0_EL1 }, "ICC_AP1R0_EL1", { .raw_val = AARCH64_SYSREG_ICC_AP1R0_EL1 }, 0xC648, true, true,  {0}  }, // 420
  { "ICC_AP1R1_EL1", { .raw_val = AARCH64_SYSREG_ICC_AP1R1_EL1 }, "ICC_AP1R1_EL1", { .raw_val = AARCH64_SYSREG_ICC_AP1R1_EL1 }, 0xC649, true, true,  {0}  }, // 421
  { "ICC_AP1R2_EL1", { .raw_val = AARCH64_SYSREG_ICC_AP1R2_EL1 }, "ICC_AP1R2_EL1", { .raw_val = AARCH64_SYSREG_ICC_AP1R2_EL1 }, 0xC64A, true, true,  {0}  }, // 422
  { "ICC_AP1R3_EL1", { .raw_val = AARCH64_SYSREG_ICC_AP1R3_EL1 }, "ICC_AP1R3_EL1", { .raw_val = AARCH64_SYSREG_ICC_AP1R3_EL1 }, 0xC64B, true, true,  {0}  }, // 423
  { "ICC_ASGI1R_EL1", { .raw_val = AARCH64_SYSREG_ICC_ASGI1R_EL1 }, "ICC_ASGI1R_EL1", { .raw_val = AARCH64_SYSREG_ICC_ASGI1R_EL1 }, 0xC65E, false, true,  {0}  }, // 424
  { "ICC_BPR0_EL1", { .raw_val = AARCH64_SYSREG_ICC_BPR0_EL1 }, "ICC_BPR0_EL1", { .raw_val = AARCH64_SYSREG_ICC_BPR0_EL1 }, 0xC643, true, true,  {0}  }, // 425
  { "ICC_BPR1_EL1", { .raw_val = AARCH64_SYSREG_ICC_BPR1_EL1 }, "ICC_BPR1_EL1", { .raw_val = AARCH64_SYSREG_ICC_BPR1_EL1 }, 0xC663, true, true,  {0}  }, // 426
  { "ICC_CTLR_EL1", { .raw_val = AARCH64_SYSREG_ICC_CTLR_EL1 }, "ICC_CTLR_EL1", { .raw_val = AARCH64_SYSREG_ICC_CTLR_EL1 }, 0xC664, true, true,  {0}  }, // 427
  { "ICC_CTLR_EL3", { .raw_val = AARCH64_SYSREG_ICC_CTLR_EL3 }, "ICC_CTLR_EL3", { .raw_val = AARCH64_SYSREG_ICC_CTLR_EL3 }, 0xF664, true, true,  {0}  }, // 428
  { "ICC_DIR_EL1", { .raw_val = AARCH64_SYSREG_ICC_DIR_EL1 }, "ICC_DIR_EL1", { .raw_val = AARCH64_SYSREG_ICC_DIR_EL1 }, 0xC659, false, true,  {0}  }, // 429
  { "ICC_EOIR0_EL1", { .raw_val = AARCH64_SYSREG_ICC_EOIR0_EL1 }, "ICC_EOIR0_EL1", { .raw_val = AARCH64_SYSREG_ICC_EOIR0_EL1 }, 0xC641, false, true,  {0}  }, // 430
  { "ICC_EOIR1_EL1", { .raw_val = AARCH64_SYSREG_ICC_EOIR1_EL1 }, "ICC_EOIR1_EL1", { .raw_val = AARCH64_SYSREG_ICC_EOIR1_EL1 }, 0xC661, false, true,  {0}  }, // 431
  { "ICC_HPPIR0_EL1", { .raw_val = AARCH64_SYSREG_ICC_HPPIR0_EL1 }, "ICC_HPPIR0_EL1", { .raw_val = AARCH64_SYSREG_ICC_HPPIR0_EL1 }, 0xC642, true, false,  {0}  }, // 432
  { "ICC_HPPIR1_EL1", { .raw_val = AARCH64_SYSREG_ICC_HPPIR1_EL1 }, "ICC_HPPIR1_EL1", { .raw_val = AARCH64_SYSREG_ICC_HPPIR1_EL1 }, 0xC662, true, false,  {0}  }, // 433
  { "ICC_IAR0_EL1", { .raw_val = AARCH64_SYSREG_ICC_IAR0_EL1 }, "ICC_IAR0_EL1", { .raw_val = AARCH64_SYSREG_ICC_IAR0_EL1 }, 0xC640, true, false,  {0}  }, // 434
  { "ICC_IAR1_EL1", { .raw_val = AARCH64_SYSREG_ICC_IAR1_EL1 }, "ICC_IAR1_EL1", { .raw_val = AARCH64_SYSREG_ICC_IAR1_EL1 }, 0xC660, true, false,  {0}  }, // 435
  { "ICC_IGRPEN0_EL1", { .raw_val = AARCH64_SYSREG_ICC_IGRPEN0_EL1 }, "ICC_IGRPEN0_EL1", { .raw_val = AARCH64_SYSREG_ICC_IGRPEN0_EL1 }, 0xC666, true, true,  {0}  }, // 436
  { "ICC_IGRPEN1_EL1", { .raw_val = AARCH64_SYSREG_ICC_IGRPEN1_EL1 }, "ICC_IGRPEN1_EL1", { .raw_val = AARCH64_SYSREG_ICC_IGRPEN1_EL1 }, 0xC667, true, true,  {0}  }, // 437
  { "ICC_IGRPEN1_EL3", { .raw_val = AARCH64_SYSREG_ICC_IGRPEN1_EL3 }, "ICC_IGRPEN1_EL3", { .raw_val = AARCH64_SYSREG_ICC_IGRPEN1_EL3 }, 0xF667, true, true,  {0}  }, // 438
  { "ICC_NMIAR1_EL1", { .raw_val = AARCH64_SYSREG_ICC_NMIAR1_EL1 }, "ICC_NMIAR1_EL1", { .raw_val = AARCH64_SYSREG_ICC_NMIAR1_EL1 }, 0xC64D, true, false,  {AArch64_FeatureNMI}  }, // 439
  { "ICC_PMR_EL1", { .raw_val = AARCH64_SYSREG_ICC_PMR_EL1 }, "ICC_PMR_EL1", { .raw_val = AARCH64_SYSREG_ICC_PMR_EL1 }, 0xC230, true, true,  {0}  }, // 440
  { "ICC_RPR_EL1", { .raw_val = AARCH64_SYSREG_ICC_RPR_EL1 }, "ICC_RPR_EL1", { .raw_val = AARCH64_SYSREG_ICC_RPR_EL1 }, 0xC65B, true, false,  {0}  }, // 441
  { "ICC_SGI0R_EL1", { .raw_val = AARCH64_SYSREG_ICC_SGI0R_EL1 }, "ICC_SGI0R_EL1", { .raw_val = AARCH64_SYSREG_ICC_SGI0R_EL1 }, 0xC65F, false, true,  {0}  }, // 442
  { "ICC_SGI1R_EL1", { .raw_val = AARCH64_SYSREG_ICC_SGI1R_EL1 }, "ICC_SGI1R_EL1", { .raw_val = AARCH64_SYSREG_ICC_SGI1R_EL1 }, 0xC65D, false, true,  {0}  }, // 443
  { "ICC_SRE_EL1", { .raw_val = AARCH64_SYSREG_ICC_SRE_EL1 }, "ICC_SRE_EL1", { .raw_val = AARCH64_SYSREG_ICC_SRE_EL1 }, 0xC665, true, true,  {0}  }, // 444
  { "ICC_SRE_EL2", { .raw_val = AARCH64_SYSREG_ICC_SRE_EL2 }, "ICC_SRE_EL2", { .raw_val = AARCH64_SYSREG_ICC_SRE_EL2 }, 0xE64D, true, true,  {0}  }, // 445
  { "ICC_SRE_EL3", { .raw_val = AARCH64_SYSREG_ICC_SRE_EL3 }, "ICC_SRE_EL3", { .raw_val = AARCH64_SYSREG_ICC_SRE_EL3 }, 0xF665, true, true,  {0}  }, // 446
  { "ICH_AP0R0_EL2", { .raw_val = AARCH64_SYSREG_ICH_AP0R0_EL2 }, "ICH_AP0R0_EL2", { .raw_val = AARCH64_SYSREG_ICH_AP0R0_EL2 }, 0xE640, true, true,  {0}  }, // 447
  { "ICH_AP0R1_EL2", { .raw_val = AARCH64_SYSREG_ICH_AP0R1_EL2 }, "ICH_AP0R1_EL2", { .raw_val = AARCH64_SYSREG_ICH_AP0R1_EL2 }, 0xE641, true, true,  {0}  }, // 448
  { "ICH_AP0R2_EL2", { .raw_val = AARCH64_SYSREG_ICH_AP0R2_EL2 }, "ICH_AP0R2_EL2", { .raw_val = AARCH64_SYSREG_ICH_AP0R2_EL2 }, 0xE642, true, true,  {0}  }, // 449
  { "ICH_AP0R3_EL2", { .raw_val = AARCH64_SYSREG_ICH_AP0R3_EL2 }, "ICH_AP0R3_EL2", { .raw_val = AARCH64_SYSREG_ICH_AP0R3_EL2 }, 0xE643, true, true,  {0}  }, // 450
  { "ICH_AP1R0_EL2", { .raw_val = AARCH64_SYSREG_ICH_AP1R0_EL2 }, "ICH_AP1R0_EL2", { .raw_val = AARCH64_SYSREG_ICH_AP1R0_EL2 }, 0xE648, true, true,  {0}  }, // 451
  { "ICH_AP1R1_EL2", { .raw_val = AARCH64_SYSREG_ICH_AP1R1_EL2 }, "ICH_AP1R1_EL2", { .raw_val = AARCH64_SYSREG_ICH_AP1R1_EL2 }, 0xE649, true, true,  {0}  }, // 452
  { "ICH_AP1R2_EL2", { .raw_val = AARCH64_SYSREG_ICH_AP1R2_EL2 }, "ICH_AP1R2_EL2", { .raw_val = AARCH64_SYSREG_ICH_AP1R2_EL2 }, 0xE64A, true, true,  {0}  }, // 453
  { "ICH_AP1R3_EL2", { .raw_val = AARCH64_SYSREG_ICH_AP1R3_EL2 }, "ICH_AP1R3_EL2", { .raw_val = AARCH64_SYSREG_ICH_AP1R3_EL2 }, 0xE64B, true, true,  {0}  }, // 454
  { "ICH_EISR_EL2", { .raw_val = AARCH64_SYSREG_ICH_EISR_EL2 }, "ICH_EISR_EL2", { .raw_val = AARCH64_SYSREG_ICH_EISR_EL2 }, 0xE65B, true, false,  {0}  }, // 455
  { "ICH_ELRSR_EL2", { .raw_val = AARCH64_SYSREG_ICH_ELRSR_EL2 }, "ICH_ELRSR_EL2", { .raw_val = AARCH64_SYSREG_ICH_ELRSR_EL2 }, 0xE65D, true, false,  {0}  }, // 456
  { "ICH_HCR_EL2", { .raw_val = AARCH64_SYSREG_ICH_HCR_EL2 }, "ICH_HCR_EL2", { .raw_val = AARCH64_SYSREG_ICH_HCR_EL2 }, 0xE658, true, true,  {0}  }, // 457
  { "ICH_LR0_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR0_EL2 }, "ICH_LR0_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR0_EL2 }, 0xE660, true, true,  {0}  }, // 458
  { "ICH_LR10_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR10_EL2 }, "ICH_LR10_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR10_EL2 }, 0xE66A, true, true,  {0}  }, // 459
  { "ICH_LR11_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR11_EL2 }, "ICH_LR11_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR11_EL2 }, 0xE66B, true, true,  {0}  }, // 460
  { "ICH_LR12_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR12_EL2 }, "ICH_LR12_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR12_EL2 }, 0xE66C, true, true,  {0}  }, // 461
  { "ICH_LR13_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR13_EL2 }, "ICH_LR13_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR13_EL2 }, 0xE66D, true, true,  {0}  }, // 462
  { "ICH_LR14_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR14_EL2 }, "ICH_LR14_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR14_EL2 }, 0xE66E, true, true,  {0}  }, // 463
  { "ICH_LR15_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR15_EL2 }, "ICH_LR15_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR15_EL2 }, 0xE66F, true, true,  {0}  }, // 464
  { "ICH_LR1_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR1_EL2 }, "ICH_LR1_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR1_EL2 }, 0xE661, true, true,  {0}  }, // 465
  { "ICH_LR2_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR2_EL2 }, "ICH_LR2_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR2_EL2 }, 0xE662, true, true,  {0}  }, // 466
  { "ICH_LR3_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR3_EL2 }, "ICH_LR3_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR3_EL2 }, 0xE663, true, true,  {0}  }, // 467
  { "ICH_LR4_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR4_EL2 }, "ICH_LR4_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR4_EL2 }, 0xE664, true, true,  {0}  }, // 468
  { "ICH_LR5_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR5_EL2 }, "ICH_LR5_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR5_EL2 }, 0xE665, true, true,  {0}  }, // 469
  { "ICH_LR6_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR6_EL2 }, "ICH_LR6_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR6_EL2 }, 0xE666, true, true,  {0}  }, // 470
  { "ICH_LR7_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR7_EL2 }, "ICH_LR7_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR7_EL2 }, 0xE667, true, true,  {0}  }, // 471
  { "ICH_LR8_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR8_EL2 }, "ICH_LR8_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR8_EL2 }, 0xE668, true, true,  {0}  }, // 472
  { "ICH_LR9_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR9_EL2 }, "ICH_LR9_EL2", { .raw_val = AARCH64_SYSREG_ICH_LR9_EL2 }, 0xE669, true, true,  {0}  }, // 473
  { "ICH_MISR_EL2", { .raw_val = AARCH64_SYSREG_ICH_MISR_EL2 }, "ICH_MISR_EL2", { .raw_val = AARCH64_SYSREG_ICH_MISR_EL2 }, 0xE65A, true, false,  {0}  }, // 474
  { "ICH_VMCR_EL2", { .raw_val = AARCH64_SYSREG_ICH_VMCR_EL2 }, "ICH_VMCR_EL2", { .raw_val = AARCH64_SYSREG_ICH_VMCR_EL2 }, 0xE65F, true, true,  {0}  }, // 475
  { "ICH_VTR_EL2", { .raw_val = AARCH64_SYSREG_ICH_VTR_EL2 }, "ICH_VTR_EL2", { .raw_val = AARCH64_SYSREG_ICH_VTR_EL2 }, 0xE659, true, false,  {0}  }, // 476
  { "ID_AA64AFR0_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64AFR0_EL1 }, "ID_AA64AFR0_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64AFR0_EL1 }, 0xC02C, true, false,  {0}  }, // 477
  { "ID_AA64AFR1_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64AFR1_EL1 }, "ID_AA64AFR1_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64AFR1_EL1 }, 0xC02D, true, false,  {0}  }, // 478
  { "ID_AA64DFR0_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64DFR0_EL1 }, "ID_AA64DFR0_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64DFR0_EL1 }, 0xC028, true, false,  {0}  }, // 479
  { "ID_AA64DFR1_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64DFR1_EL1 }, "ID_AA64DFR1_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64DFR1_EL1 }, 0xC029, true, false,  {0}  }, // 480
  { "ID_AA64DFR2_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64DFR2_EL1 }, "ID_AA64DFR2_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64DFR2_EL1 }, 0xC02A, true, false,  {0}  }, // 481
  { "ID_AA64FPFR0_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64FPFR0_EL1 }, "ID_AA64FPFR0_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64FPFR0_EL1 }, 0xC027, true, false,  {AArch64_FeatureFPMR}  }, // 482
  { "ID_AA64ISAR0_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64ISAR0_EL1 }, "ID_AA64ISAR0_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64ISAR0_EL1 }, 0xC030, true, false,  {0}  }, // 483
  { "ID_AA64ISAR1_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64ISAR1_EL1 }, "ID_AA64ISAR1_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64ISAR1_EL1 }, 0xC031, true, false,  {0}  }, // 484
  { "ID_AA64ISAR2_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64ISAR2_EL1 }, "ID_AA64ISAR2_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64ISAR2_EL1 }, 0xC032, true, false,  {0}  }, // 485
  { "ID_AA64ISAR3_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64ISAR3_EL1 }, "ID_AA64ISAR3_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64ISAR3_EL1 }, 0xC033, true, false,  {0}  }, // 486
  { "ID_AA64MMFR0_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64MMFR0_EL1 }, "ID_AA64MMFR0_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64MMFR0_EL1 }, 0xC038, true, false,  {0}  }, // 487
  { "ID_AA64MMFR1_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64MMFR1_EL1 }, "ID_AA64MMFR1_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64MMFR1_EL1 }, 0xC039, true, false,  {0}  }, // 488
  { "ID_AA64MMFR2_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64MMFR2_EL1 }, "ID_AA64MMFR2_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64MMFR2_EL1 }, 0xC03A, true, false,  {0}  }, // 489
  { "ID_AA64MMFR3_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64MMFR3_EL1 }, "ID_AA64MMFR3_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64MMFR3_EL1 }, 0xC03B, true, false,  {0}  }, // 490
  { "ID_AA64MMFR4_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64MMFR4_EL1 }, "ID_AA64MMFR4_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64MMFR4_EL1 }, 0xC03C, true, false,  {0}  }, // 491
  { "ID_AA64PFR0_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64PFR0_EL1 }, "ID_AA64PFR0_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64PFR0_EL1 }, 0xC020, true, false,  {0}  }, // 492
  { "ID_AA64PFR1_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64PFR1_EL1 }, "ID_AA64PFR1_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64PFR1_EL1 }, 0xC021, true, false,  {0}  }, // 493
  { "ID_AA64PFR2_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64PFR2_EL1 }, "ID_AA64PFR2_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64PFR2_EL1 }, 0xC022, true, false,  {0}  }, // 494
  { "ID_AA64SMFR0_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64SMFR0_EL1 }, "ID_AA64SMFR0_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64SMFR0_EL1 }, 0xC025, true, false,  {AArch64_FeatureSME}  }, // 495
  { "ID_AA64ZFR0_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64ZFR0_EL1 }, "ID_AA64ZFR0_EL1", { .raw_val = AARCH64_SYSREG_ID_AA64ZFR0_EL1 }, 0xC024, true, false,  {AArch64_FeatureSVE}  }, // 496
  { "ID_AFR0_EL1", { .raw_val = AARCH64_SYSREG_ID_AFR0_EL1 }, "ID_AFR0_EL1", { .raw_val = AARCH64_SYSREG_ID_AFR0_EL1 }, 0xC00B, true, false,  {0}  }, // 497
  { "ID_DFR0_EL1", { .raw_val = AARCH64_SYSREG_ID_DFR0_EL1 }, "ID_DFR0_EL1", { .raw_val = AARCH64_SYSREG_ID_DFR0_EL1 }, 0xC00A, true, false,  {0}  }, // 498
  { "ID_DFR1_EL1", { .raw_val = AARCH64_SYSREG_ID_DFR1_EL1 }, "ID_DFR1_EL1", { .raw_val = AARCH64_SYSREG_ID_DFR1_EL1 }, 0xC01D, true, false,  {0}  }, // 499
  { "ID_ISAR0_EL1", { .raw_val = AARCH64_SYSREG_ID_ISAR0_EL1 }, "ID_ISAR0_EL1", { .raw_val = AARCH64_SYSREG_ID_ISAR0_EL1 }, 0xC010, true, false,  {0}  }, // 500
  { "ID_ISAR1_EL1", { .raw_val = AARCH64_SYSREG_ID_ISAR1_EL1 }, "ID_ISAR1_EL1", { .raw_val = AARCH64_SYSREG_ID_ISAR1_EL1 }, 0xC011, true, false,  {0}  }, // 501
  { "ID_ISAR2_EL1", { .raw_val = AARCH64_SYSREG_ID_ISAR2_EL1 }, "ID_ISAR2_EL1", { .raw_val = AARCH64_SYSREG_ID_ISAR2_EL1 }, 0xC012, true, false,  {0}  }, // 502
  { "ID_ISAR3_EL1", { .raw_val = AARCH64_SYSREG_ID_ISAR3_EL1 }, "ID_ISAR3_EL1", { .raw_val = AARCH64_SYSREG_ID_ISAR3_EL1 }, 0xC013, true, false,  {0}  }, // 503
  { "ID_ISAR4_EL1", { .raw_val = AARCH64_SYSREG_ID_ISAR4_EL1 }, "ID_ISAR4_EL1", { .raw_val = AARCH64_SYSREG_ID_ISAR4_EL1 }, 0xC014, true, false,  {0}  }, // 504
  { "ID_ISAR5_EL1", { .raw_val = AARCH64_SYSREG_ID_ISAR5_EL1 }, "ID_ISAR5_EL1", { .raw_val = AARCH64_SYSREG_ID_ISAR5_EL1 }, 0xC015, true, false,  {0}  }, // 505
  { "ID_ISAR6_EL1", { .raw_val = AARCH64_SYSREG_ID_ISAR6_EL1 }, "ID_ISAR6_EL1", { .raw_val = AARCH64_SYSREG_ID_ISAR6_EL1 }, 0xC017, true, false,  {AArch64_HasV8_2aOps}  }, // 506
  { "ID_MMFR0_EL1", { .raw_val = AARCH64_SYSREG_ID_MMFR0_EL1 }, "ID_MMFR0_EL1", { .raw_val = AARCH64_SYSREG_ID_MMFR0_EL1 }, 0xC00C, true, false,  {0}  }, // 507
  { "ID_MMFR1_EL1", { .raw_val = AARCH64_SYSREG_ID_MMFR1_EL1 }, "ID_MMFR1_EL1", { .raw_val = AARCH64_SYSREG_ID_MMFR1_EL1 }, 0xC00D, true, false,  {0}  }, // 508
  { "ID_MMFR2_EL1", { .raw_val = AARCH64_SYSREG_ID_MMFR2_EL1 }, "ID_MMFR2_EL1", { .raw_val = AARCH64_SYSREG_ID_MMFR2_EL1 }, 0xC00E, true, false,  {0}  }, // 509
  { "ID_MMFR3_EL1", { .raw_val = AARCH64_SYSREG_ID_MMFR3_EL1 }, "ID_MMFR3_EL1", { .raw_val = AARCH64_SYSREG_ID_MMFR3_EL1 }, 0xC00F, true, false,  {0}  }, // 510
  { "ID_MMFR4_EL1", { .raw_val = AARCH64_SYSREG_ID_MMFR4_EL1 }, "ID_MMFR4_EL1", { .raw_val = AARCH64_SYSREG_ID_MMFR4_EL1 }, 0xC016, true, false,  {0}  }, // 511
  { "ID_MMFR5_EL1", { .raw_val = AARCH64_SYSREG_ID_MMFR5_EL1 }, "ID_MMFR5_EL1", { .raw_val = AARCH64_SYSREG_ID_MMFR5_EL1 }, 0xC01E, true, false,  {0}  }, // 512
  { "ID_PFR0_EL1", { .raw_val = AARCH64_SYSREG_ID_PFR0_EL1 }, "ID_PFR0_EL1", { .raw_val = AARCH64_SYSREG_ID_PFR0_EL1 }, 0xC008, true, false,  {0}  }, // 513
  { "ID_PFR1_EL1", { .raw_val = AARCH64_SYSREG_ID_PFR1_EL1 }, "ID_PFR1_EL1", { .raw_val = AARCH64_SYSREG_ID_PFR1_EL1 }, 0xC009, true, false,  {0}  }, // 514
  { "ID_PFR2_EL1", { .raw_val = AARCH64_SYSREG_ID_PFR2_EL1 }, "ID_PFR2_EL1", { .raw_val = AARCH64_SYSREG_ID_PFR2_EL1 }, 0xC01C, true, false,  {AArch64_FeatureSpecRestrict}  }, // 515
  { "IFSR32_EL2", { .raw_val = AARCH64_SYSREG_IFSR32_EL2 }, "IFSR32_EL2", { .raw_val = AARCH64_SYSREG_IFSR32_EL2 }, 0xE281, true, true,  {0}  }, // 516
  { "ISR_EL1", { .raw_val = AARCH64_SYSREG_ISR_EL1 }, "ISR_EL1", { .raw_val = AARCH64_SYSREG_ISR_EL1 }, 0xC608, true, false,  {0}  }, // 517
  { "LORC_EL1", { .raw_val = AARCH64_SYSREG_LORC_EL1 }, "LORC_EL1", { .raw_val = AARCH64_SYSREG_LORC_EL1 }, 0xC523, true, true,  {AArch64_FeatureLOR}  }, // 518
  { "LOREA_EL1", { .raw_val = AARCH64_SYSREG_LOREA_EL1 }, "LOREA_EL1", { .raw_val = AARCH64_SYSREG_LOREA_EL1 }, 0xC521, true, true,  {AArch64_FeatureLOR}  }, // 519
  { "LORID_EL1", { .raw_val = AARCH64_SYSREG_LORID_EL1 }, "LORID_EL1", { .raw_val = AARCH64_SYSREG_LORID_EL1 }, 0xC527, true, false,  {AArch64_FeatureLOR}  }, // 520
  { "LORN_EL1", { .raw_val = AARCH64_SYSREG_LORN_EL1 }, "LORN_EL1", { .raw_val = AARCH64_SYSREG_LORN_EL1 }, 0xC522, true, true,  {AArch64_FeatureLOR}  }, // 521
  { "LORSA_EL1", { .raw_val = AARCH64_SYSREG_LORSA_EL1 }, "LORSA_EL1", { .raw_val = AARCH64_SYSREG_LORSA_EL1 }, 0xC520, true, true,  {AArch64_FeatureLOR}  }, // 522
  { "MAIR2_EL1", { .raw_val = AARCH64_SYSREG_MAIR2_EL1 }, "MAIR2_EL1", { .raw_val = AARCH64_SYSREG_MAIR2_EL1 }, 0xC511, true, true,  {0}  }, // 523
  { "MAIR2_EL12", { .raw_val = AARCH64_SYSREG_MAIR2_EL12 }, "MAIR2_EL12", { .raw_val = AARCH64_SYSREG_MAIR2_EL12 }, 0xED11, true, true,  {0}  }, // 524
  { "MAIR2_EL2", { .raw_val = AARCH64_SYSREG_MAIR2_EL2 }, "MAIR2_EL2", { .raw_val = AARCH64_SYSREG_MAIR2_EL2 }, 0xE509, true, true,  {0}  }, // 525
  { "MAIR2_EL3", { .raw_val = AARCH64_SYSREG_MAIR2_EL3 }, "MAIR2_EL3", { .raw_val = AARCH64_SYSREG_MAIR2_EL3 }, 0xF509, true, true,  {0}  }, // 526
  { "MAIR_EL1", { .raw_val = AARCH64_SYSREG_MAIR_EL1 }, "MAIR_EL1", { .raw_val = AARCH64_SYSREG_MAIR_EL1 }, 0xC510, true, true,  {0}  }, // 527
  { "MAIR_EL12", { .raw_val = AARCH64_SYSREG_MAIR_EL12 }, "MAIR_EL12", { .raw_val = AARCH64_SYSREG_MAIR_EL12 }, 0xED10, true, true,  {AArch64_FeatureVH}  }, // 528
  { "MAIR_EL2", { .raw_val = AARCH64_SYSREG_MAIR_EL2 }, "MAIR_EL2", { .raw_val = AARCH64_SYSREG_MAIR_EL2 }, 0xE510, true, true,  {0}  }, // 529
  { "MAIR_EL3", { .raw_val = AARCH64_SYSREG_MAIR_EL3 }, "MAIR_EL3", { .raw_val = AARCH64_SYSREG_MAIR_EL3 }, 0xF510, true, true,  {0}  }, // 530
  { "MDCCINT_EL1", { .raw_val = AARCH64_SYSREG_MDCCINT_EL1 }, "MDCCINT_EL1", { .raw_val = AARCH64_SYSREG_MDCCINT_EL1 }, 0x8010, true, true,  {0}  }, // 531
  { "MDCCSR_EL0", { .raw_val = AARCH64_SYSREG_MDCCSR_EL0 }, "MDCCSR_EL0", { .raw_val = AARCH64_SYSREG_MDCCSR_EL0 }, 0x9808, true, false,  {0}  }, // 532
  { "MDCR_EL2", { .raw_val = AARCH64_SYSREG_MDCR_EL2 }, "MDCR_EL2", { .raw_val = AARCH64_SYSREG_MDCR_EL2 }, 0xE089, true, true,  {0}  }, // 533
  { "MDCR_EL3", { .raw_val = AARCH64_SYSREG_MDCR_EL3 }, "MDCR_EL3", { .raw_val = AARCH64_SYSREG_MDCR_EL3 }, 0xF099, true, true,  {0}  }, // 534
  { "MDRAR_EL1", { .raw_val = AARCH64_SYSREG_MDRAR_EL1 }, "MDRAR_EL1", { .raw_val = AARCH64_SYSREG_MDRAR_EL1 }, 0x8080, true, false,  {0}  }, // 535
  { "MDSCR_EL1", { .raw_val = AARCH64_SYSREG_MDSCR_EL1 }, "MDSCR_EL1", { .raw_val = AARCH64_SYSREG_MDSCR_EL1 }, 0x8012, true, true,  {0}  }, // 536
  { "MDSELR_EL1", { .raw_val = AARCH64_SYSREG_MDSELR_EL1 }, "MDSELR_EL1", { .raw_val = AARCH64_SYSREG_MDSELR_EL1 }, 0x8022, true, true,  {0}  }, // 537
  { "MDSTEPOP_EL1", { .raw_val = AARCH64_SYSREG_MDSTEPOP_EL1 }, "MDSTEPOP_EL1", { .raw_val = AARCH64_SYSREG_MDSTEPOP_EL1 }, 0x802A, true, true,  {0}  }, // 538
  { "MECIDR_EL2", { .raw_val = AARCH64_SYSREG_MECIDR_EL2 }, "MECIDR_EL2", { .raw_val = AARCH64_SYSREG_MECIDR_EL2 }, 0xE547, true, false,  {AArch64_FeatureMEC}  }, // 539
  { "MECID_A0_EL2", { .raw_val = AARCH64_SYSREG_MECID_A0_EL2 }, "MECID_A0_EL2", { .raw_val = AARCH64_SYSREG_MECID_A0_EL2 }, 0xE541, true, true,  {AArch64_FeatureMEC}  }, // 540
  { "MECID_A1_EL2", { .raw_val = AARCH64_SYSREG_MECID_A1_EL2 }, "MECID_A1_EL2", { .raw_val = AARCH64_SYSREG_MECID_A1_EL2 }, 0xE543, true, true,  {AArch64_FeatureMEC}  }, // 541
  { "MECID_P0_EL2", { .raw_val = AARCH64_SYSREG_MECID_P0_EL2 }, "MECID_P0_EL2", { .raw_val = AARCH64_SYSREG_MECID_P0_EL2 }, 0xE540, true, true,  {AArch64_FeatureMEC}  }, // 542
  { "MECID_P1_EL2", { .raw_val = AARCH64_SYSREG_MECID_P1_EL2 }, "MECID_P1_EL2", { .raw_val = AARCH64_SYSREG_MECID_P1_EL2 }, 0xE542, true, true,  {AArch64_FeatureMEC}  }, // 543
  { "MECID_RL_A_EL3", { .raw_val = AARCH64_SYSREG_MECID_RL_A_EL3 }, "MECID_RL_A_EL3", { .raw_val = AARCH64_SYSREG_MECID_RL_A_EL3 }, 0xF551, true, true,  {AArch64_FeatureMEC}  }, // 544
  { "MFAR_EL3", { .raw_val = AARCH64_SYSREG_MFAR_EL3 }, "MFAR_EL3", { .raw_val = AARCH64_SYSREG_MFAR_EL3 }, 0xF305, true, true,  {0}  }, // 545
  { "MIDR_EL1", { .raw_val = AARCH64_SYSREG_MIDR_EL1 }, "MIDR_EL1", { .raw_val = AARCH64_SYSREG_MIDR_EL1 }, 0xC000, true, false,  {0}  }, // 546
  { "MPAM0_EL1", { .raw_val = AARCH64_SYSREG_MPAM0_EL1 }, "MPAM0_EL1", { .raw_val = AARCH64_SYSREG_MPAM0_EL1 }, 0xC529, true, true,  {AArch64_FeatureMPAM}  }, // 547
  { "MPAM1_EL1", { .raw_val = AARCH64_SYSREG_MPAM1_EL1 }, "MPAM1_EL1", { .raw_val = AARCH64_SYSREG_MPAM1_EL1 }, 0xC528, true, true,  {AArch64_FeatureMPAM}  }, // 548
  { "MPAM1_EL12", { .raw_val = AARCH64_SYSREG_MPAM1_EL12 }, "MPAM1_EL12", { .raw_val = AARCH64_SYSREG_MPAM1_EL12 }, 0xED28, true, true,  {AArch64_FeatureMPAM}  }, // 549
  { "MPAM2_EL2", { .raw_val = AARCH64_SYSREG_MPAM2_EL2 }, "MPAM2_EL2", { .raw_val = AARCH64_SYSREG_MPAM2_EL2 }, 0xE528, true, true,  {AArch64_FeatureMPAM}  }, // 550
  { "MPAM3_EL3", { .raw_val = AARCH64_SYSREG_MPAM3_EL3 }, "MPAM3_EL3", { .raw_val = AARCH64_SYSREG_MPAM3_EL3 }, 0xF528, true, true,  {AArch64_FeatureMPAM}  }, // 551
  { "MPAMHCR_EL2", { .raw_val = AARCH64_SYSREG_MPAMHCR_EL2 }, "MPAMHCR_EL2", { .raw_val = AARCH64_SYSREG_MPAMHCR_EL2 }, 0xE520, true, true,  {AArch64_FeatureMPAM}  }, // 552
  { "MPAMIDR_EL1", { .raw_val = AARCH64_SYSREG_MPAMIDR_EL1 }, "MPAMIDR_EL1", { .raw_val = AARCH64_SYSREG_MPAMIDR_EL1 }, 0xC524, true, false,  {AArch64_FeatureMPAM}  }, // 553
  { "MPAMSM_EL1", { .raw_val = AARCH64_SYSREG_MPAMSM_EL1 }, "MPAMSM_EL1", { .raw_val = AARCH64_SYSREG_MPAMSM_EL1 }, 0xC52B, true, true,  {AArch64_FeatureMPAM, AArch64_FeatureSME}  }, // 554
  { "MPAMVPM0_EL2", { .raw_val = AARCH64_SYSREG_MPAMVPM0_EL2 }, "MPAMVPM0_EL2", { .raw_val = AARCH64_SYSREG_MPAMVPM0_EL2 }, 0xE530, true, true,  {AArch64_FeatureMPAM}  }, // 555
  { "MPAMVPM1_EL2", { .raw_val = AARCH64_SYSREG_MPAMVPM1_EL2 }, "MPAMVPM1_EL2", { .raw_val = AARCH64_SYSREG_MPAMVPM1_EL2 }, 0xE531, true, true,  {AArch64_FeatureMPAM}  }, // 556
  { "MPAMVPM2_EL2", { .raw_val = AARCH64_SYSREG_MPAMVPM2_EL2 }, "MPAMVPM2_EL2", { .raw_val = AARCH64_SYSREG_MPAMVPM2_EL2 }, 0xE532, true, true,  {AArch64_FeatureMPAM}  }, // 557
  { "MPAMVPM3_EL2", { .raw_val = AARCH64_SYSREG_MPAMVPM3_EL2 }, "MPAMVPM3_EL2", { .raw_val = AARCH64_SYSREG_MPAMVPM3_EL2 }, 0xE533, true, true,  {AArch64_FeatureMPAM}  }, // 558
  { "MPAMVPM4_EL2", { .raw_val = AARCH64_SYSREG_MPAMVPM4_EL2 }, "MPAMVPM4_EL2", { .raw_val = AARCH64_SYSREG_MPAMVPM4_EL2 }, 0xE534, true, true,  {AArch64_FeatureMPAM}  }, // 559
  { "MPAMVPM5_EL2", { .raw_val = AARCH64_SYSREG_MPAMVPM5_EL2 }, "MPAMVPM5_EL2", { .raw_val = AARCH64_SYSREG_MPAMVPM5_EL2 }, 0xE535, true, true,  {AArch64_FeatureMPAM}  }, // 560
  { "MPAMVPM6_EL2", { .raw_val = AARCH64_SYSREG_MPAMVPM6_EL2 }, "MPAMVPM6_EL2", { .raw_val = AARCH64_SYSREG_MPAMVPM6_EL2 }, 0xE536, true, true,  {AArch64_FeatureMPAM}  }, // 561
  { "MPAMVPM7_EL2", { .raw_val = AARCH64_SYSREG_MPAMVPM7_EL2 }, "MPAMVPM7_EL2", { .raw_val = AARCH64_SYSREG_MPAMVPM7_EL2 }, 0xE537, true, true,  {AArch64_FeatureMPAM}  }, // 562
  { "MPAMVPMV_EL2", { .raw_val = AARCH64_SYSREG_MPAMVPMV_EL2 }, "MPAMVPMV_EL2", { .raw_val = AARCH64_SYSREG_MPAMVPMV_EL2 }, 0xE521, true, true,  {AArch64_FeatureMPAM}  }, // 563
  { "MPIDR_EL1", { .raw_val = AARCH64_SYSREG_MPIDR_EL1 }, "MPIDR_EL1", { .raw_val = AARCH64_SYSREG_MPIDR_EL1 }, 0xC005, true, false,  {0}  }, // 564
  { "MPUIR_EL1", { .raw_val = AARCH64_SYSREG_MPUIR_EL1 }, "MPUIR_EL1", { .raw_val = AARCH64_SYSREG_MPUIR_EL1 }, 0xC004, true, true,  {AArch64_HasV8_0rOps}  }, // 565
  { "MPUIR_EL2", { .raw_val = AARCH64_SYSREG_MPUIR_EL2 }, "MPUIR_EL2", { .raw_val = AARCH64_SYSREG_MPUIR_EL2 }, 0xE004, true, true,  {AArch64_HasV8_0rOps}  }, // 566
  { "MVFR0_EL1", { .raw_val = AARCH64_SYSREG_MVFR0_EL1 }, "MVFR0_EL1", { .raw_val = AARCH64_SYSREG_MVFR0_EL1 }, 0xC018, true, false,  {0}  }, // 567
  { "MVFR1_EL1", { .raw_val = AARCH64_SYSREG_MVFR1_EL1 }, "MVFR1_EL1", { .raw_val = AARCH64_SYSREG_MVFR1_EL1 }, 0xC019, true, false,  {0}  }, // 568
  { "MVFR2_EL1", { .raw_val = AARCH64_SYSREG_MVFR2_EL1 }, "MVFR2_EL1", { .raw_val = AARCH64_SYSREG_MVFR2_EL1 }, 0xC01A, true, false,  {0}  }, // 569
  { "NZCV", { .raw_val = AARCH64_SYSREG_NZCV }, "NZCV", { .raw_val = AARCH64_SYSREG_NZCV }, 0xDA10, true, true,  {0}  }, // 570
  { "OSDLR_EL1", { .raw_val = AARCH64_SYSREG_OSDLR_EL1 }, "OSDLR_EL1", { .raw_val = AARCH64_SYSREG_OSDLR_EL1 }, 0x809C, true, true,  {0}  }, // 571
  { "OSDTRRX_EL1", { .raw_val = AARCH64_SYSREG_OSDTRRX_EL1 }, "OSDTRRX_EL1", { .raw_val = AARCH64_SYSREG_OSDTRRX_EL1 }, 0x8002, true, true,  {0}  }, // 572
  { "OSDTRTX_EL1", { .raw_val = AARCH64_SYSREG_OSDTRTX_EL1 }, "OSDTRTX_EL1", { .raw_val = AARCH64_SYSREG_OSDTRTX_EL1 }, 0x801A, true, true,  {0}  }, // 573
  { "OSECCR_EL1", { .raw_val = AARCH64_SYSREG_OSECCR_EL1 }, "OSECCR_EL1", { .raw_val = AARCH64_SYSREG_OSECCR_EL1 }, 0x8032, true, true,  {0}  }, // 574
  { "OSLAR_EL1", { .raw_val = AARCH64_SYSREG_OSLAR_EL1 }, "OSLAR_EL1", { .raw_val = AARCH64_SYSREG_OSLAR_EL1 }, 0x8084, false, true,  {0}  }, // 575
  { "OSLSR_EL1", { .raw_val = AARCH64_SYSREG_OSLSR_EL1 }, "OSLSR_EL1", { .raw_val = AARCH64_SYSREG_OSLSR_EL1 }, 0x808C, true, false,  {0}  }, // 576
  { "PAN", { .raw_val = AARCH64_SYSREG_PAN }, "PAN", { .raw_val = AARCH64_SYSREG_PAN }, 0xC213, true, true,  {AArch64_FeaturePAN}  }, // 577
  { "PAR_EL1", { .raw_val = AARCH64_SYSREG_PAR_EL1 }, "PAR_EL1", { .raw_val = AARCH64_SYSREG_PAR_EL1 }, 0xC3A0, true, true,  {0}  }, // 578
  { "PFAR_EL1", { .raw_val = AARCH64_SYSREG_PFAR_EL1 }, "PFAR_EL1", { .raw_val = AARCH64_SYSREG_PFAR_EL1 }, 0xC305, true, true,  {0}  }, // 579
  { "PFAR_EL12", { .raw_val = AARCH64_SYSREG_PFAR_EL12 }, "PFAR_EL12", { .raw_val = AARCH64_SYSREG_PFAR_EL12 }, 0xEB05, true, true,  {0}  }, // 580
  { "PFAR_EL2", { .raw_val = AARCH64_SYSREG_PFAR_EL2 }, "PFAR_EL2", { .raw_val = AARCH64_SYSREG_PFAR_EL2 }, 0xE305, true, true,  {0}  }, // 581
  { "PIRE0_EL1", { .raw_val = AARCH64_SYSREG_PIRE0_EL1 }, "PIRE0_EL1", { .raw_val = AARCH64_SYSREG_PIRE0_EL1 }, 0xC512, true, true,  {0}  }, // 582
  { "PIRE0_EL12", { .raw_val = AARCH64_SYSREG_PIRE0_EL12 }, "PIRE0_EL12", { .raw_val = AARCH64_SYSREG_PIRE0_EL12 }, 0xED12, true, true,  {0}  }, // 583
  { "PIRE0_EL2", { .raw_val = AARCH64_SYSREG_PIRE0_EL2 }, "PIRE0_EL2", { .raw_val = AARCH64_SYSREG_PIRE0_EL2 }, 0xE512, true, true,  {0}  }, // 584
  { "PIR_EL1", { .raw_val = AARCH64_SYSREG_PIR_EL1 }, "PIR_EL1", { .raw_val = AARCH64_SYSREG_PIR_EL1 }, 0xC513, true, true,  {0}  }, // 585
  { "PIR_EL12", { .raw_val = AARCH64_SYSREG_PIR_EL12 }, "PIR_EL12", { .raw_val = AARCH64_SYSREG_PIR_EL12 }, 0xED13, true, true,  {0}  }, // 586
  { "PIR_EL2", { .raw_val = AARCH64_SYSREG_PIR_EL2 }, "PIR_EL2", { .raw_val = AARCH64_SYSREG_PIR_EL2 }, 0xE513, true, true,  {0}  }, // 587
  { "PIR_EL3", { .raw_val = AARCH64_SYSREG_PIR_EL3 }, "PIR_EL3", { .raw_val = AARCH64_SYSREG_PIR_EL3 }, 0xF513, true, true,  {0}  }, // 588
  { "PM", { .raw_val = AARCH64_SYSREG_PM }, "PM", { .raw_val = AARCH64_SYSREG_PM }, 0xC219, true, true,  {0}  }, // 589
  { "PMBIDR_EL1", { .raw_val = AARCH64_SYSREG_PMBIDR_EL1 }, "PMBIDR_EL1", { .raw_val = AARCH64_SYSREG_PMBIDR_EL1 }, 0xC4D7, true, false,  {AArch64_FeatureSPE}  }, // 590
  { "PMBLIMITR_EL1", { .raw_val = AARCH64_SYSREG_PMBLIMITR_EL1 }, "PMBLIMITR_EL1", { .raw_val = AARCH64_SYSREG_PMBLIMITR_EL1 }, 0xC4D0, true, true,  {AArch64_FeatureSPE}  }, // 591
  { "PMBPTR_EL1", { .raw_val = AARCH64_SYSREG_PMBPTR_EL1 }, "PMBPTR_EL1", { .raw_val = AARCH64_SYSREG_PMBPTR_EL1 }, 0xC4D1, true, true,  {AArch64_FeatureSPE}  }, // 592
  { "PMBSR_EL1", { .raw_val = AARCH64_SYSREG_PMBSR_EL1 }, "PMBSR_EL1", { .raw_val = AARCH64_SYSREG_PMBSR_EL1 }, 0xC4D3, true, true,  {AArch64_FeatureSPE}  }, // 593
  { "PMCCFILTR_EL0", { .raw_val = AARCH64_SYSREG_PMCCFILTR_EL0 }, "PMCCFILTR_EL0", { .raw_val = AARCH64_SYSREG_PMCCFILTR_EL0 }, 0xDF7F, true, true,  {0}  }, // 594
  { "PMCCNTR_EL0", { .raw_val = AARCH64_SYSREG_PMCCNTR_EL0 }, "PMCCNTR_EL0", { .raw_val = AARCH64_SYSREG_PMCCNTR_EL0 }, 0xDCE8, true, true,  {0}  }, // 595
  { "PMCCNTSVR_EL1", { .raw_val = AARCH64_SYSREG_PMCCNTSVR_EL1 }, "PMCCNTSVR_EL1", { .raw_val = AARCH64_SYSREG_PMCCNTSVR_EL1 }, 0x875F, true, false,  {0}  }, // 596
  { "PMCEID0_EL0", { .raw_val = AARCH64_SYSREG_PMCEID0_EL0 }, "PMCEID0_EL0", { .raw_val = AARCH64_SYSREG_PMCEID0_EL0 }, 0xDCE6, true, false,  {0}  }, // 597
  { "PMCEID1_EL0", { .raw_val = AARCH64_SYSREG_PMCEID1_EL0 }, "PMCEID1_EL0", { .raw_val = AARCH64_SYSREG_PMCEID1_EL0 }, 0xDCE7, true, false,  {0}  }, // 598
  { "PMCNTENCLR_EL0", { .raw_val = AARCH64_SYSREG_PMCNTENCLR_EL0 }, "PMCNTENCLR_EL0", { .raw_val = AARCH64_SYSREG_PMCNTENCLR_EL0 }, 0xDCE2, true, true,  {0}  }, // 599
  { "PMCNTENSET_EL0", { .raw_val = AARCH64_SYSREG_PMCNTENSET_EL0 }, "PMCNTENSET_EL0", { .raw_val = AARCH64_SYSREG_PMCNTENSET_EL0 }, 0xDCE1, true, true,  {0}  }, // 600
  { "PMCR_EL0", { .raw_val = AARCH64_SYSREG_PMCR_EL0 }, "PMCR_EL0", { .raw_val = AARCH64_SYSREG_PMCR_EL0 }, 0xDCE0, true, true,  {0}  }, // 601
  { "PMECR_EL1", { .raw_val = AARCH64_SYSREG_PMECR_EL1 }, "PMECR_EL1", { .raw_val = AARCH64_SYSREG_PMECR_EL1 }, 0xC4F5, true, true,  {0}  }, // 602
  { "PMEVCNTR0_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR0_EL0 }, "PMEVCNTR0_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR0_EL0 }, 0xDF40, true, true,  {0}  }, // 603
  { "PMEVCNTR10_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR10_EL0 }, "PMEVCNTR10_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR10_EL0 }, 0xDF4A, true, true,  {0}  }, // 604
  { "PMEVCNTR11_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR11_EL0 }, "PMEVCNTR11_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR11_EL0 }, 0xDF4B, true, true,  {0}  }, // 605
  { "PMEVCNTR12_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR12_EL0 }, "PMEVCNTR12_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR12_EL0 }, 0xDF4C, true, true,  {0}  }, // 606
  { "PMEVCNTR13_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR13_EL0 }, "PMEVCNTR13_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR13_EL0 }, 0xDF4D, true, true,  {0}  }, // 607
  { "PMEVCNTR14_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR14_EL0 }, "PMEVCNTR14_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR14_EL0 }, 0xDF4E, true, true,  {0}  }, // 608
  { "PMEVCNTR15_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR15_EL0 }, "PMEVCNTR15_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR15_EL0 }, 0xDF4F, true, true,  {0}  }, // 609
  { "PMEVCNTR16_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR16_EL0 }, "PMEVCNTR16_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR16_EL0 }, 0xDF50, true, true,  {0}  }, // 610
  { "PMEVCNTR17_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR17_EL0 }, "PMEVCNTR17_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR17_EL0 }, 0xDF51, true, true,  {0}  }, // 611
  { "PMEVCNTR18_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR18_EL0 }, "PMEVCNTR18_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR18_EL0 }, 0xDF52, true, true,  {0}  }, // 612
  { "PMEVCNTR19_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR19_EL0 }, "PMEVCNTR19_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR19_EL0 }, 0xDF53, true, true,  {0}  }, // 613
  { "PMEVCNTR1_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR1_EL0 }, "PMEVCNTR1_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR1_EL0 }, 0xDF41, true, true,  {0}  }, // 614
  { "PMEVCNTR20_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR20_EL0 }, "PMEVCNTR20_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR20_EL0 }, 0xDF54, true, true,  {0}  }, // 615
  { "PMEVCNTR21_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR21_EL0 }, "PMEVCNTR21_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR21_EL0 }, 0xDF55, true, true,  {0}  }, // 616
  { "PMEVCNTR22_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR22_EL0 }, "PMEVCNTR22_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR22_EL0 }, 0xDF56, true, true,  {0}  }, // 617
  { "PMEVCNTR23_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR23_EL0 }, "PMEVCNTR23_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR23_EL0 }, 0xDF57, true, true,  {0}  }, // 618
  { "PMEVCNTR24_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR24_EL0 }, "PMEVCNTR24_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR24_EL0 }, 0xDF58, true, true,  {0}  }, // 619
  { "PMEVCNTR25_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR25_EL0 }, "PMEVCNTR25_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR25_EL0 }, 0xDF59, true, true,  {0}  }, // 620
  { "PMEVCNTR26_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR26_EL0 }, "PMEVCNTR26_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR26_EL0 }, 0xDF5A, true, true,  {0}  }, // 621
  { "PMEVCNTR27_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR27_EL0 }, "PMEVCNTR27_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR27_EL0 }, 0xDF5B, true, true,  {0}  }, // 622
  { "PMEVCNTR28_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR28_EL0 }, "PMEVCNTR28_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR28_EL0 }, 0xDF5C, true, true,  {0}  }, // 623
  { "PMEVCNTR29_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR29_EL0 }, "PMEVCNTR29_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR29_EL0 }, 0xDF5D, true, true,  {0}  }, // 624
  { "PMEVCNTR2_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR2_EL0 }, "PMEVCNTR2_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR2_EL0 }, 0xDF42, true, true,  {0}  }, // 625
  { "PMEVCNTR30_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR30_EL0 }, "PMEVCNTR30_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR30_EL0 }, 0xDF5E, true, true,  {0}  }, // 626
  { "PMEVCNTR3_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR3_EL0 }, "PMEVCNTR3_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR3_EL0 }, 0xDF43, true, true,  {0}  }, // 627
  { "PMEVCNTR4_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR4_EL0 }, "PMEVCNTR4_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR4_EL0 }, 0xDF44, true, true,  {0}  }, // 628
  { "PMEVCNTR5_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR5_EL0 }, "PMEVCNTR5_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR5_EL0 }, 0xDF45, true, true,  {0}  }, // 629
  { "PMEVCNTR6_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR6_EL0 }, "PMEVCNTR6_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR6_EL0 }, 0xDF46, true, true,  {0}  }, // 630
  { "PMEVCNTR7_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR7_EL0 }, "PMEVCNTR7_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR7_EL0 }, 0xDF47, true, true,  {0}  }, // 631
  { "PMEVCNTR8_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR8_EL0 }, "PMEVCNTR8_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR8_EL0 }, 0xDF48, true, true,  {0}  }, // 632
  { "PMEVCNTR9_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR9_EL0 }, "PMEVCNTR9_EL0", { .raw_val = AARCH64_SYSREG_PMEVCNTR9_EL0 }, 0xDF49, true, true,  {0}  }, // 633
  { "PMEVCNTSVR0_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR0_EL1 }, "PMEVCNTSVR0_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR0_EL1 }, 0x8740, true, false,  {0}  }, // 634
  { "PMEVCNTSVR10_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR10_EL1 }, "PMEVCNTSVR10_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR10_EL1 }, 0x874A, true, false,  {0}  }, // 635
  { "PMEVCNTSVR11_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR11_EL1 }, "PMEVCNTSVR11_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR11_EL1 }, 0x874B, true, false,  {0}  }, // 636
  { "PMEVCNTSVR12_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR12_EL1 }, "PMEVCNTSVR12_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR12_EL1 }, 0x874C, true, false,  {0}  }, // 637
  { "PMEVCNTSVR13_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR13_EL1 }, "PMEVCNTSVR13_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR13_EL1 }, 0x874D, true, false,  {0}  }, // 638
  { "PMEVCNTSVR14_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR14_EL1 }, "PMEVCNTSVR14_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR14_EL1 }, 0x874E, true, false,  {0}  }, // 639
  { "PMEVCNTSVR15_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR15_EL1 }, "PMEVCNTSVR15_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR15_EL1 }, 0x874F, true, false,  {0}  }, // 640
  { "PMEVCNTSVR16_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR16_EL1 }, "PMEVCNTSVR16_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR16_EL1 }, 0x8750, true, false,  {0}  }, // 641
  { "PMEVCNTSVR17_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR17_EL1 }, "PMEVCNTSVR17_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR17_EL1 }, 0x8751, true, false,  {0}  }, // 642
  { "PMEVCNTSVR18_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR18_EL1 }, "PMEVCNTSVR18_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR18_EL1 }, 0x8752, true, false,  {0}  }, // 643
  { "PMEVCNTSVR19_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR19_EL1 }, "PMEVCNTSVR19_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR19_EL1 }, 0x8753, true, false,  {0}  }, // 644
  { "PMEVCNTSVR1_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR1_EL1 }, "PMEVCNTSVR1_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR1_EL1 }, 0x8741, true, false,  {0}  }, // 645
  { "PMEVCNTSVR20_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR20_EL1 }, "PMEVCNTSVR20_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR20_EL1 }, 0x8754, true, false,  {0}  }, // 646
  { "PMEVCNTSVR21_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR21_EL1 }, "PMEVCNTSVR21_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR21_EL1 }, 0x8755, true, false,  {0}  }, // 647
  { "PMEVCNTSVR22_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR22_EL1 }, "PMEVCNTSVR22_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR22_EL1 }, 0x8756, true, false,  {0}  }, // 648
  { "PMEVCNTSVR23_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR23_EL1 }, "PMEVCNTSVR23_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR23_EL1 }, 0x8757, true, false,  {0}  }, // 649
  { "PMEVCNTSVR24_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR24_EL1 }, "PMEVCNTSVR24_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR24_EL1 }, 0x8758, true, false,  {0}  }, // 650
  { "PMEVCNTSVR25_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR25_EL1 }, "PMEVCNTSVR25_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR25_EL1 }, 0x8759, true, false,  {0}  }, // 651
  { "PMEVCNTSVR26_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR26_EL1 }, "PMEVCNTSVR26_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR26_EL1 }, 0x875A, true, false,  {0}  }, // 652
  { "PMEVCNTSVR27_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR27_EL1 }, "PMEVCNTSVR27_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR27_EL1 }, 0x875B, true, false,  {0}  }, // 653
  { "PMEVCNTSVR28_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR28_EL1 }, "PMEVCNTSVR28_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR28_EL1 }, 0x875C, true, false,  {0}  }, // 654
  { "PMEVCNTSVR29_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR29_EL1 }, "PMEVCNTSVR29_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR29_EL1 }, 0x875D, true, false,  {0}  }, // 655
  { "PMEVCNTSVR2_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR2_EL1 }, "PMEVCNTSVR2_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR2_EL1 }, 0x8742, true, false,  {0}  }, // 656
  { "PMEVCNTSVR30_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR30_EL1 }, "PMEVCNTSVR30_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR30_EL1 }, 0x875E, true, false,  {0}  }, // 657
  { "PMEVCNTSVR3_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR3_EL1 }, "PMEVCNTSVR3_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR3_EL1 }, 0x8743, true, false,  {0}  }, // 658
  { "PMEVCNTSVR4_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR4_EL1 }, "PMEVCNTSVR4_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR4_EL1 }, 0x8744, true, false,  {0}  }, // 659
  { "PMEVCNTSVR5_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR5_EL1 }, "PMEVCNTSVR5_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR5_EL1 }, 0x8745, true, false,  {0}  }, // 660
  { "PMEVCNTSVR6_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR6_EL1 }, "PMEVCNTSVR6_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR6_EL1 }, 0x8746, true, false,  {0}  }, // 661
  { "PMEVCNTSVR7_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR7_EL1 }, "PMEVCNTSVR7_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR7_EL1 }, 0x8747, true, false,  {0}  }, // 662
  { "PMEVCNTSVR8_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR8_EL1 }, "PMEVCNTSVR8_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR8_EL1 }, 0x8748, true, false,  {0}  }, // 663
  { "PMEVCNTSVR9_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR9_EL1 }, "PMEVCNTSVR9_EL1", { .raw_val = AARCH64_SYSREG_PMEVCNTSVR9_EL1 }, 0x8749, true, false,  {0}  }, // 664
  { "PMEVTYPER0_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER0_EL0 }, "PMEVTYPER0_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER0_EL0 }, 0xDF60, true, true,  {0}  }, // 665
  { "PMEVTYPER10_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER10_EL0 }, "PMEVTYPER10_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER10_EL0 }, 0xDF6A, true, true,  {0}  }, // 666
  { "PMEVTYPER11_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER11_EL0 }, "PMEVTYPER11_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER11_EL0 }, 0xDF6B, true, true,  {0}  }, // 667
  { "PMEVTYPER12_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER12_EL0 }, "PMEVTYPER12_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER12_EL0 }, 0xDF6C, true, true,  {0}  }, // 668
  { "PMEVTYPER13_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER13_EL0 }, "PMEVTYPER13_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER13_EL0 }, 0xDF6D, true, true,  {0}  }, // 669
  { "PMEVTYPER14_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER14_EL0 }, "PMEVTYPER14_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER14_EL0 }, 0xDF6E, true, true,  {0}  }, // 670
  { "PMEVTYPER15_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER15_EL0 }, "PMEVTYPER15_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER15_EL0 }, 0xDF6F, true, true,  {0}  }, // 671
  { "PMEVTYPER16_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER16_EL0 }, "PMEVTYPER16_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER16_EL0 }, 0xDF70, true, true,  {0}  }, // 672
  { "PMEVTYPER17_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER17_EL0 }, "PMEVTYPER17_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER17_EL0 }, 0xDF71, true, true,  {0}  }, // 673
  { "PMEVTYPER18_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER18_EL0 }, "PMEVTYPER18_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER18_EL0 }, 0xDF72, true, true,  {0}  }, // 674
  { "PMEVTYPER19_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER19_EL0 }, "PMEVTYPER19_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER19_EL0 }, 0xDF73, true, true,  {0}  }, // 675
  { "PMEVTYPER1_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER1_EL0 }, "PMEVTYPER1_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER1_EL0 }, 0xDF61, true, true,  {0}  }, // 676
  { "PMEVTYPER20_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER20_EL0 }, "PMEVTYPER20_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER20_EL0 }, 0xDF74, true, true,  {0}  }, // 677
  { "PMEVTYPER21_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER21_EL0 }, "PMEVTYPER21_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER21_EL0 }, 0xDF75, true, true,  {0}  }, // 678
  { "PMEVTYPER22_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER22_EL0 }, "PMEVTYPER22_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER22_EL0 }, 0xDF76, true, true,  {0}  }, // 679
  { "PMEVTYPER23_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER23_EL0 }, "PMEVTYPER23_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER23_EL0 }, 0xDF77, true, true,  {0}  }, // 680
  { "PMEVTYPER24_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER24_EL0 }, "PMEVTYPER24_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER24_EL0 }, 0xDF78, true, true,  {0}  }, // 681
  { "PMEVTYPER25_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER25_EL0 }, "PMEVTYPER25_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER25_EL0 }, 0xDF79, true, true,  {0}  }, // 682
  { "PMEVTYPER26_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER26_EL0 }, "PMEVTYPER26_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER26_EL0 }, 0xDF7A, true, true,  {0}  }, // 683
  { "PMEVTYPER27_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER27_EL0 }, "PMEVTYPER27_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER27_EL0 }, 0xDF7B, true, true,  {0}  }, // 684
  { "PMEVTYPER28_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER28_EL0 }, "PMEVTYPER28_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER28_EL0 }, 0xDF7C, true, true,  {0}  }, // 685
  { "PMEVTYPER29_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER29_EL0 }, "PMEVTYPER29_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER29_EL0 }, 0xDF7D, true, true,  {0}  }, // 686
  { "PMEVTYPER2_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER2_EL0 }, "PMEVTYPER2_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER2_EL0 }, 0xDF62, true, true,  {0}  }, // 687
  { "PMEVTYPER30_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER30_EL0 }, "PMEVTYPER30_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER30_EL0 }, 0xDF7E, true, true,  {0}  }, // 688
  { "PMEVTYPER3_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER3_EL0 }, "PMEVTYPER3_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER3_EL0 }, 0xDF63, true, true,  {0}  }, // 689
  { "PMEVTYPER4_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER4_EL0 }, "PMEVTYPER4_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER4_EL0 }, 0xDF64, true, true,  {0}  }, // 690
  { "PMEVTYPER5_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER5_EL0 }, "PMEVTYPER5_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER5_EL0 }, 0xDF65, true, true,  {0}  }, // 691
  { "PMEVTYPER6_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER6_EL0 }, "PMEVTYPER6_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER6_EL0 }, 0xDF66, true, true,  {0}  }, // 692
  { "PMEVTYPER7_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER7_EL0 }, "PMEVTYPER7_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER7_EL0 }, 0xDF67, true, true,  {0}  }, // 693
  { "PMEVTYPER8_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER8_EL0 }, "PMEVTYPER8_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER8_EL0 }, 0xDF68, true, true,  {0}  }, // 694
  { "PMEVTYPER9_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER9_EL0 }, "PMEVTYPER9_EL0", { .raw_val = AARCH64_SYSREG_PMEVTYPER9_EL0 }, 0xDF69, true, true,  {0}  }, // 695
  { "PMIAR_EL1", { .raw_val = AARCH64_SYSREG_PMIAR_EL1 }, "PMIAR_EL1", { .raw_val = AARCH64_SYSREG_PMIAR_EL1 }, 0xC4F7, true, true,  {0}  }, // 696
  { "PMICFILTR_EL0", { .raw_val = AARCH64_SYSREG_PMICFILTR_EL0 }, "PMICFILTR_EL0", { .raw_val = AARCH64_SYSREG_PMICFILTR_EL0 }, 0xDCB0, true, true,  {0}  }, // 697
  { "PMICNTR_EL0", { .raw_val = AARCH64_SYSREG_PMICNTR_EL0 }, "PMICNTR_EL0", { .raw_val = AARCH64_SYSREG_PMICNTR_EL0 }, 0xDCA0, true, true,  {0}  }, // 698
  { "PMICNTSVR_EL1", { .raw_val = AARCH64_SYSREG_PMICNTSVR_EL1 }, "PMICNTSVR_EL1", { .raw_val = AARCH64_SYSREG_PMICNTSVR_EL1 }, 0x8760, true, false,  {0}  }, // 699
  { "PMINTENCLR_EL1", { .raw_val = AARCH64_SYSREG_PMINTENCLR_EL1 }, "PMINTENCLR_EL1", { .raw_val = AARCH64_SYSREG_PMINTENCLR_EL1 }, 0xC4F2, true, true,  {0}  }, // 700
  { "PMINTENSET_EL1", { .raw_val = AARCH64_SYSREG_PMINTENSET_EL1 }, "PMINTENSET_EL1", { .raw_val = AARCH64_SYSREG_PMINTENSET_EL1 }, 0xC4F1, true, true,  {0}  }, // 701
  { "PMMIR_EL1", { .raw_val = AARCH64_SYSREG_PMMIR_EL1 }, "PMMIR_EL1", { .raw_val = AARCH64_SYSREG_PMMIR_EL1 }, 0xC4F6, true, false,  {0}  }, // 702
  { "PMOVSCLR_EL0", { .raw_val = AARCH64_SYSREG_PMOVSCLR_EL0 }, "PMOVSCLR_EL0", { .raw_val = AARCH64_SYSREG_PMOVSCLR_EL0 }, 0xDCE3, true, true,  {0}  }, // 703
  { "PMOVSSET_EL0", { .raw_val = AARCH64_SYSREG_PMOVSSET_EL0 }, "PMOVSSET_EL0", { .raw_val = AARCH64_SYSREG_PMOVSSET_EL0 }, 0xDCF3, true, true,  {0}  }, // 704
  { "PMSCR_EL1", { .raw_val = AARCH64_SYSREG_PMSCR_EL1 }, "PMSCR_EL1", { .raw_val = AARCH64_SYSREG_PMSCR_EL1 }, 0xC4C8, true, true,  {AArch64_FeatureSPE}  }, // 705
  { "PMSCR_EL12", { .raw_val = AARCH64_SYSREG_PMSCR_EL12 }, "PMSCR_EL12", { .raw_val = AARCH64_SYSREG_PMSCR_EL12 }, 0xECC8, true, true,  {AArch64_FeatureSPE}  }, // 706
  { "PMSCR_EL2", { .raw_val = AARCH64_SYSREG_PMSCR_EL2 }, "PMSCR_EL2", { .raw_val = AARCH64_SYSREG_PMSCR_EL2 }, 0xE4C8, true, true,  {AArch64_FeatureSPE}  }, // 707
  { "PMSDSFR_EL1", { .raw_val = AARCH64_SYSREG_PMSDSFR_EL1 }, "PMSDSFR_EL1", { .raw_val = AARCH64_SYSREG_PMSDSFR_EL1 }, 0xC4D4, true, true,  {0}  }, // 708
  { "PMSELR_EL0", { .raw_val = AARCH64_SYSREG_PMSELR_EL0 }, "PMSELR_EL0", { .raw_val = AARCH64_SYSREG_PMSELR_EL0 }, 0xDCE5, true, true,  {0}  }, // 709
  { "PMSEVFR_EL1", { .raw_val = AARCH64_SYSREG_PMSEVFR_EL1 }, "PMSEVFR_EL1", { .raw_val = AARCH64_SYSREG_PMSEVFR_EL1 }, 0xC4CD, true, true,  {AArch64_FeatureSPE}  }, // 710
  { "PMSFCR_EL1", { .raw_val = AARCH64_SYSREG_PMSFCR_EL1 }, "PMSFCR_EL1", { .raw_val = AARCH64_SYSREG_PMSFCR_EL1 }, 0xC4CC, true, true,  {AArch64_FeatureSPE}  }, // 711
  { "PMSICR_EL1", { .raw_val = AARCH64_SYSREG_PMSICR_EL1 }, "PMSICR_EL1", { .raw_val = AARCH64_SYSREG_PMSICR_EL1 }, 0xC4CA, true, true,  {AArch64_FeatureSPE}  }, // 712
  { "PMSIDR_EL1", { .raw_val = AARCH64_SYSREG_PMSIDR_EL1 }, "PMSIDR_EL1", { .raw_val = AARCH64_SYSREG_PMSIDR_EL1 }, 0xC4CF, true, false,  {AArch64_FeatureSPE}  }, // 713
  { "PMSIRR_EL1", { .raw_val = AARCH64_SYSREG_PMSIRR_EL1 }, "PMSIRR_EL1", { .raw_val = AARCH64_SYSREG_PMSIRR_EL1 }, 0xC4CB, true, true,  {AArch64_FeatureSPE}  }, // 714
  { "PMSLATFR_EL1", { .raw_val = AARCH64_SYSREG_PMSLATFR_EL1 }, "PMSLATFR_EL1", { .raw_val = AARCH64_SYSREG_PMSLATFR_EL1 }, 0xC4CE, true, true,  {AArch64_FeatureSPE}  }, // 715
  { "PMSNEVFR_EL1", { .raw_val = AARCH64_SYSREG_PMSNEVFR_EL1 }, "PMSNEVFR_EL1", { .raw_val = AARCH64_SYSREG_PMSNEVFR_EL1 }, 0xC4C9, true, true,  {AArch64_FeatureSPE_EEF}  }, // 716
  { "PMSSCR_EL1", { .raw_val = AARCH64_SYSREG_PMSSCR_EL1 }, "PMSSCR_EL1", { .raw_val = AARCH64_SYSREG_PMSSCR_EL1 }, 0xC4EB, true, true,  {0}  }, // 717
  { "PMSWINC_EL0", { .raw_val = AARCH64_SYSREG_PMSWINC_EL0 }, "PMSWINC_EL0", { .raw_val = AARCH64_SYSREG_PMSWINC_EL0 }, 0xDCE4, false, true,  {0}  }, // 718
  { "PMUACR_EL1", { .raw_val = AARCH64_SYSREG_PMUACR_EL1 }, "PMUACR_EL1", { .raw_val = AARCH64_SYSREG_PMUACR_EL1 }, 0xC4F4, true, true,  {0}  }, // 719
  { "PMUSERENR_EL0", { .raw_val = AARCH64_SYSREG_PMUSERENR_EL0 }, "PMUSERENR_EL0", { .raw_val = AARCH64_SYSREG_PMUSERENR_EL0 }, 0xDCF0, true, true,  {0}  }, // 720
  { "PMXEVCNTR_EL0", { .raw_val = AARCH64_SYSREG_PMXEVCNTR_EL0 }, "PMXEVCNTR_EL0", { .raw_val = AARCH64_SYSREG_PMXEVCNTR_EL0 }, 0xDCEA, true, true,  {0}  }, // 721
  { "PMXEVTYPER_EL0", { .raw_val = AARCH64_SYSREG_PMXEVTYPER_EL0 }, "PMXEVTYPER_EL0", { .raw_val = AARCH64_SYSREG_PMXEVTYPER_EL0 }, 0xDCE9, true, true,  {0}  }, // 722
  { "PMZR_EL0", { .raw_val = AARCH64_SYSREG_PMZR_EL0 }, "PMZR_EL0", { .raw_val = AARCH64_SYSREG_PMZR_EL0 }, 0xDCEC, false, true,  {0}  }, // 723
  { "POR_EL0", { .raw_val = AARCH64_SYSREG_POR_EL0 }, "POR_EL0", { .raw_val = AARCH64_SYSREG_POR_EL0 }, 0xDD14, true, true,  {0}  }, // 724
  { "POR_EL1", { .raw_val = AARCH64_SYSREG_POR_EL1 }, "POR_EL1", { .raw_val = AARCH64_SYSREG_POR_EL1 }, 0xC514, true, true,  {0}  }, // 725
  { "POR_EL12", { .raw_val = AARCH64_SYSREG_POR_EL12 }, "POR_EL12", { .raw_val = AARCH64_SYSREG_POR_EL12 }, 0xED14, true, true,  {0}  }, // 726
  { "POR_EL2", { .raw_val = AARCH64_SYSREG_POR_EL2 }, "POR_EL2", { .raw_val = AARCH64_SYSREG_POR_EL2 }, 0xE514, true, true,  {0}  }, // 727
  { "POR_EL3", { .raw_val = AARCH64_SYSREG_POR_EL3 }, "POR_EL3", { .raw_val = AARCH64_SYSREG_POR_EL3 }, 0xF514, true, true,  {0}  }, // 728
  { "PRBAR10_EL1", { .raw_val = AARCH64_SYSREG_PRBAR10_EL1 }, "PRBAR10_EL1", { .raw_val = AARCH64_SYSREG_PRBAR10_EL1 }, 0xC368, true, true,  {AArch64_HasV8_0rOps}  }, // 729
  { "PRBAR10_EL2", { .raw_val = AARCH64_SYSREG_PRBAR10_EL2 }, "PRBAR10_EL2", { .raw_val = AARCH64_SYSREG_PRBAR10_EL2 }, 0xE368, true, true,  {AArch64_HasV8_0rOps}  }, // 730
  { "PRBAR11_EL1", { .raw_val = AARCH64_SYSREG_PRBAR11_EL1 }, "PRBAR11_EL1", { .raw_val = AARCH64_SYSREG_PRBAR11_EL1 }, 0xC36C, true, true,  {AArch64_HasV8_0rOps}  }, // 731
  { "PRBAR11_EL2", { .raw_val = AARCH64_SYSREG_PRBAR11_EL2 }, "PRBAR11_EL2", { .raw_val = AARCH64_SYSREG_PRBAR11_EL2 }, 0xE36C, true, true,  {AArch64_HasV8_0rOps}  }, // 732
  { "PRBAR12_EL1", { .raw_val = AARCH64_SYSREG_PRBAR12_EL1 }, "PRBAR12_EL1", { .raw_val = AARCH64_SYSREG_PRBAR12_EL1 }, 0xC370, true, true,  {AArch64_HasV8_0rOps}  }, // 733
  { "PRBAR12_EL2", { .raw_val = AARCH64_SYSREG_PRBAR12_EL2 }, "PRBAR12_EL2", { .raw_val = AARCH64_SYSREG_PRBAR12_EL2 }, 0xE370, true, true,  {AArch64_HasV8_0rOps}  }, // 734
  { "PRBAR13_EL1", { .raw_val = AARCH64_SYSREG_PRBAR13_EL1 }, "PRBAR13_EL1", { .raw_val = AARCH64_SYSREG_PRBAR13_EL1 }, 0xC374, true, true,  {AArch64_HasV8_0rOps}  }, // 735
  { "PRBAR13_EL2", { .raw_val = AARCH64_SYSREG_PRBAR13_EL2 }, "PRBAR13_EL2", { .raw_val = AARCH64_SYSREG_PRBAR13_EL2 }, 0xE374, true, true,  {AArch64_HasV8_0rOps}  }, // 736
  { "PRBAR14_EL1", { .raw_val = AARCH64_SYSREG_PRBAR14_EL1 }, "PRBAR14_EL1", { .raw_val = AARCH64_SYSREG_PRBAR14_EL1 }, 0xC378, true, true,  {AArch64_HasV8_0rOps}  }, // 737
  { "PRBAR14_EL2", { .raw_val = AARCH64_SYSREG_PRBAR14_EL2 }, "PRBAR14_EL2", { .raw_val = AARCH64_SYSREG_PRBAR14_EL2 }, 0xE378, true, true,  {AArch64_HasV8_0rOps}  }, // 738
  { "PRBAR15_EL1", { .raw_val = AARCH64_SYSREG_PRBAR15_EL1 }, "PRBAR15_EL1", { .raw_val = AARCH64_SYSREG_PRBAR15_EL1 }, 0xC37C, true, true,  {AArch64_HasV8_0rOps}  }, // 739
  { "PRBAR15_EL2", { .raw_val = AARCH64_SYSREG_PRBAR15_EL2 }, "PRBAR15_EL2", { .raw_val = AARCH64_SYSREG_PRBAR15_EL2 }, 0xE37C, true, true,  {AArch64_HasV8_0rOps}  }, // 740
  { "PRBAR1_EL1", { .raw_val = AARCH64_SYSREG_PRBAR1_EL1 }, "PRBAR1_EL1", { .raw_val = AARCH64_SYSREG_PRBAR1_EL1 }, 0xC344, true, true,  {AArch64_HasV8_0rOps}  }, // 741
  { "PRBAR1_EL2", { .raw_val = AARCH64_SYSREG_PRBAR1_EL2 }, "PRBAR1_EL2", { .raw_val = AARCH64_SYSREG_PRBAR1_EL2 }, 0xE344, true, true,  {AArch64_HasV8_0rOps}  }, // 742
  { "PRBAR2_EL1", { .raw_val = AARCH64_SYSREG_PRBAR2_EL1 }, "PRBAR2_EL1", { .raw_val = AARCH64_SYSREG_PRBAR2_EL1 }, 0xC348, true, true,  {AArch64_HasV8_0rOps}  }, // 743
  { "PRBAR2_EL2", { .raw_val = AARCH64_SYSREG_PRBAR2_EL2 }, "PRBAR2_EL2", { .raw_val = AARCH64_SYSREG_PRBAR2_EL2 }, 0xE348, true, true,  {AArch64_HasV8_0rOps}  }, // 744
  { "PRBAR3_EL1", { .raw_val = AARCH64_SYSREG_PRBAR3_EL1 }, "PRBAR3_EL1", { .raw_val = AARCH64_SYSREG_PRBAR3_EL1 }, 0xC34C, true, true,  {AArch64_HasV8_0rOps}  }, // 745
  { "PRBAR3_EL2", { .raw_val = AARCH64_SYSREG_PRBAR3_EL2 }, "PRBAR3_EL2", { .raw_val = AARCH64_SYSREG_PRBAR3_EL2 }, 0xE34C, true, true,  {AArch64_HasV8_0rOps}  }, // 746
  { "PRBAR4_EL1", { .raw_val = AARCH64_SYSREG_PRBAR4_EL1 }, "PRBAR4_EL1", { .raw_val = AARCH64_SYSREG_PRBAR4_EL1 }, 0xC350, true, true,  {AArch64_HasV8_0rOps}  }, // 747
  { "PRBAR4_EL2", { .raw_val = AARCH64_SYSREG_PRBAR4_EL2 }, "PRBAR4_EL2", { .raw_val = AARCH64_SYSREG_PRBAR4_EL2 }, 0xE350, true, true,  {AArch64_HasV8_0rOps}  }, // 748
  { "PRBAR5_EL1", { .raw_val = AARCH64_SYSREG_PRBAR5_EL1 }, "PRBAR5_EL1", { .raw_val = AARCH64_SYSREG_PRBAR5_EL1 }, 0xC354, true, true,  {AArch64_HasV8_0rOps}  }, // 749
  { "PRBAR5_EL2", { .raw_val = AARCH64_SYSREG_PRBAR5_EL2 }, "PRBAR5_EL2", { .raw_val = AARCH64_SYSREG_PRBAR5_EL2 }, 0xE354, true, true,  {AArch64_HasV8_0rOps}  }, // 750
  { "PRBAR6_EL1", { .raw_val = AARCH64_SYSREG_PRBAR6_EL1 }, "PRBAR6_EL1", { .raw_val = AARCH64_SYSREG_PRBAR6_EL1 }, 0xC358, true, true,  {AArch64_HasV8_0rOps}  }, // 751
  { "PRBAR6_EL2", { .raw_val = AARCH64_SYSREG_PRBAR6_EL2 }, "PRBAR6_EL2", { .raw_val = AARCH64_SYSREG_PRBAR6_EL2 }, 0xE358, true, true,  {AArch64_HasV8_0rOps}  }, // 752
  { "PRBAR7_EL1", { .raw_val = AARCH64_SYSREG_PRBAR7_EL1 }, "PRBAR7_EL1", { .raw_val = AARCH64_SYSREG_PRBAR7_EL1 }, 0xC35C, true, true,  {AArch64_HasV8_0rOps}  }, // 753
  { "PRBAR7_EL2", { .raw_val = AARCH64_SYSREG_PRBAR7_EL2 }, "PRBAR7_EL2", { .raw_val = AARCH64_SYSREG_PRBAR7_EL2 }, 0xE35C, true, true,  {AArch64_HasV8_0rOps}  }, // 754
  { "PRBAR8_EL1", { .raw_val = AARCH64_SYSREG_PRBAR8_EL1 }, "PRBAR8_EL1", { .raw_val = AARCH64_SYSREG_PRBAR8_EL1 }, 0xC360, true, true,  {AArch64_HasV8_0rOps}  }, // 755
  { "PRBAR8_EL2", { .raw_val = AARCH64_SYSREG_PRBAR8_EL2 }, "PRBAR8_EL2", { .raw_val = AARCH64_SYSREG_PRBAR8_EL2 }, 0xE360, true, true,  {AArch64_HasV8_0rOps}  }, // 756
  { "PRBAR9_EL1", { .raw_val = AARCH64_SYSREG_PRBAR9_EL1 }, "PRBAR9_EL1", { .raw_val = AARCH64_SYSREG_PRBAR9_EL1 }, 0xC364, true, true,  {AArch64_HasV8_0rOps}  }, // 757
  { "PRBAR9_EL2", { .raw_val = AARCH64_SYSREG_PRBAR9_EL2 }, "PRBAR9_EL2", { .raw_val = AARCH64_SYSREG_PRBAR9_EL2 }, 0xE364, true, true,  {AArch64_HasV8_0rOps}  }, // 758
  { "PRBAR_EL1", { .raw_val = AARCH64_SYSREG_PRBAR_EL1 }, "PRBAR_EL1", { .raw_val = AARCH64_SYSREG_PRBAR_EL1 }, 0xC340, true, true,  {AArch64_HasV8_0rOps}  }, // 759
  { "PRBAR_EL2", { .raw_val = AARCH64_SYSREG_PRBAR_EL2 }, "PRBAR_EL2", { .raw_val = AARCH64_SYSREG_PRBAR_EL2 }, 0xE340, true, true,  {AArch64_HasV8_0rOps}  }, // 760
  { "PRENR_EL1", { .raw_val = AARCH64_SYSREG_PRENR_EL1 }, "PRENR_EL1", { .raw_val = AARCH64_SYSREG_PRENR_EL1 }, 0xC309, true, true,  {AArch64_HasV8_0rOps}  }, // 761
  { "PRENR_EL2", { .raw_val = AARCH64_SYSREG_PRENR_EL2 }, "PRENR_EL2", { .raw_val = AARCH64_SYSREG_PRENR_EL2 }, 0xE309, true, true,  {AArch64_HasV8_0rOps}  }, // 762
  { "PRLAR10_EL1", { .raw_val = AARCH64_SYSREG_PRLAR10_EL1 }, "PRLAR10_EL1", { .raw_val = AARCH64_SYSREG_PRLAR10_EL1 }, 0xC369, true, true,  {AArch64_HasV8_0rOps}  }, // 763
  { "PRLAR10_EL2", { .raw_val = AARCH64_SYSREG_PRLAR10_EL2 }, "PRLAR10_EL2", { .raw_val = AARCH64_SYSREG_PRLAR10_EL2 }, 0xE369, true, true,  {AArch64_HasV8_0rOps}  }, // 764
  { "PRLAR11_EL1", { .raw_val = AARCH64_SYSREG_PRLAR11_EL1 }, "PRLAR11_EL1", { .raw_val = AARCH64_SYSREG_PRLAR11_EL1 }, 0xC36D, true, true,  {AArch64_HasV8_0rOps}  }, // 765
  { "PRLAR11_EL2", { .raw_val = AARCH64_SYSREG_PRLAR11_EL2 }, "PRLAR11_EL2", { .raw_val = AARCH64_SYSREG_PRLAR11_EL2 }, 0xE36D, true, true,  {AArch64_HasV8_0rOps}  }, // 766
  { "PRLAR12_EL1", { .raw_val = AARCH64_SYSREG_PRLAR12_EL1 }, "PRLAR12_EL1", { .raw_val = AARCH64_SYSREG_PRLAR12_EL1 }, 0xC371, true, true,  {AArch64_HasV8_0rOps}  }, // 767
  { "PRLAR12_EL2", { .raw_val = AARCH64_SYSREG_PRLAR12_EL2 }, "PRLAR12_EL2", { .raw_val = AARCH64_SYSREG_PRLAR12_EL2 }, 0xE371, true, true,  {AArch64_HasV8_0rOps}  }, // 768
  { "PRLAR13_EL1", { .raw_val = AARCH64_SYSREG_PRLAR13_EL1 }, "PRLAR13_EL1", { .raw_val = AARCH64_SYSREG_PRLAR13_EL1 }, 0xC375, true, true,  {AArch64_HasV8_0rOps}  }, // 769
  { "PRLAR13_EL2", { .raw_val = AARCH64_SYSREG_PRLAR13_EL2 }, "PRLAR13_EL2", { .raw_val = AARCH64_SYSREG_PRLAR13_EL2 }, 0xE375, true, true,  {AArch64_HasV8_0rOps}  }, // 770
  { "PRLAR14_EL1", { .raw_val = AARCH64_SYSREG_PRLAR14_EL1 }, "PRLAR14_EL1", { .raw_val = AARCH64_SYSREG_PRLAR14_EL1 }, 0xC379, true, true,  {AArch64_HasV8_0rOps}  }, // 771
  { "PRLAR14_EL2", { .raw_val = AARCH64_SYSREG_PRLAR14_EL2 }, "PRLAR14_EL2", { .raw_val = AARCH64_SYSREG_PRLAR14_EL2 }, 0xE379, true, true,  {AArch64_HasV8_0rOps}  }, // 772
  { "PRLAR15_EL1", { .raw_val = AARCH64_SYSREG_PRLAR15_EL1 }, "PRLAR15_EL1", { .raw_val = AARCH64_SYSREG_PRLAR15_EL1 }, 0xC37D, true, true,  {AArch64_HasV8_0rOps}  }, // 773
  { "PRLAR15_EL2", { .raw_val = AARCH64_SYSREG_PRLAR15_EL2 }, "PRLAR15_EL2", { .raw_val = AARCH64_SYSREG_PRLAR15_EL2 }, 0xE37D, true, true,  {AArch64_HasV8_0rOps}  }, // 774
  { "PRLAR1_EL1", { .raw_val = AARCH64_SYSREG_PRLAR1_EL1 }, "PRLAR1_EL1", { .raw_val = AARCH64_SYSREG_PRLAR1_EL1 }, 0xC345, true, true,  {AArch64_HasV8_0rOps}  }, // 775
  { "PRLAR1_EL2", { .raw_val = AARCH64_SYSREG_PRLAR1_EL2 }, "PRLAR1_EL2", { .raw_val = AARCH64_SYSREG_PRLAR1_EL2 }, 0xE345, true, true,  {AArch64_HasV8_0rOps}  }, // 776
  { "PRLAR2_EL1", { .raw_val = AARCH64_SYSREG_PRLAR2_EL1 }, "PRLAR2_EL1", { .raw_val = AARCH64_SYSREG_PRLAR2_EL1 }, 0xC349, true, true,  {AArch64_HasV8_0rOps}  }, // 777
  { "PRLAR2_EL2", { .raw_val = AARCH64_SYSREG_PRLAR2_EL2 }, "PRLAR2_EL2", { .raw_val = AARCH64_SYSREG_PRLAR2_EL2 }, 0xE349, true, true,  {AArch64_HasV8_0rOps}  }, // 778
  { "PRLAR3_EL1", { .raw_val = AARCH64_SYSREG_PRLAR3_EL1 }, "PRLAR3_EL1", { .raw_val = AARCH64_SYSREG_PRLAR3_EL1 }, 0xC34D, true, true,  {AArch64_HasV8_0rOps}  }, // 779
  { "PRLAR3_EL2", { .raw_val = AARCH64_SYSREG_PRLAR3_EL2 }, "PRLAR3_EL2", { .raw_val = AARCH64_SYSREG_PRLAR3_EL2 }, 0xE34D, true, true,  {AArch64_HasV8_0rOps}  }, // 780
  { "PRLAR4_EL1", { .raw_val = AARCH64_SYSREG_PRLAR4_EL1 }, "PRLAR4_EL1", { .raw_val = AARCH64_SYSREG_PRLAR4_EL1 }, 0xC351, true, true,  {AArch64_HasV8_0rOps}  }, // 781
  { "PRLAR4_EL2", { .raw_val = AARCH64_SYSREG_PRLAR4_EL2 }, "PRLAR4_EL2", { .raw_val = AARCH64_SYSREG_PRLAR4_EL2 }, 0xE351, true, true,  {AArch64_HasV8_0rOps}  }, // 782
  { "PRLAR5_EL1", { .raw_val = AARCH64_SYSREG_PRLAR5_EL1 }, "PRLAR5_EL1", { .raw_val = AARCH64_SYSREG_PRLAR5_EL1 }, 0xC355, true, true,  {AArch64_HasV8_0rOps}  }, // 783
  { "PRLAR5_EL2", { .raw_val = AARCH64_SYSREG_PRLAR5_EL2 }, "PRLAR5_EL2", { .raw_val = AARCH64_SYSREG_PRLAR5_EL2 }, 0xE355, true, true,  {AArch64_HasV8_0rOps}  }, // 784
  { "PRLAR6_EL1", { .raw_val = AARCH64_SYSREG_PRLAR6_EL1 }, "PRLAR6_EL1", { .raw_val = AARCH64_SYSREG_PRLAR6_EL1 }, 0xC359, true, true,  {AArch64_HasV8_0rOps}  }, // 785
  { "PRLAR6_EL2", { .raw_val = AARCH64_SYSREG_PRLAR6_EL2 }, "PRLAR6_EL2", { .raw_val = AARCH64_SYSREG_PRLAR6_EL2 }, 0xE359, true, true,  {AArch64_HasV8_0rOps}  }, // 786
  { "PRLAR7_EL1", { .raw_val = AARCH64_SYSREG_PRLAR7_EL1 }, "PRLAR7_EL1", { .raw_val = AARCH64_SYSREG_PRLAR7_EL1 }, 0xC35D, true, true,  {AArch64_HasV8_0rOps}  }, // 787
  { "PRLAR7_EL2", { .raw_val = AARCH64_SYSREG_PRLAR7_EL2 }, "PRLAR7_EL2", { .raw_val = AARCH64_SYSREG_PRLAR7_EL2 }, 0xE35D, true, true,  {AArch64_HasV8_0rOps}  }, // 788
  { "PRLAR8_EL1", { .raw_val = AARCH64_SYSREG_PRLAR8_EL1 }, "PRLAR8_EL1", { .raw_val = AARCH64_SYSREG_PRLAR8_EL1 }, 0xC361, true, true,  {AArch64_HasV8_0rOps}  }, // 789
  { "PRLAR8_EL2", { .raw_val = AARCH64_SYSREG_PRLAR8_EL2 }, "PRLAR8_EL2", { .raw_val = AARCH64_SYSREG_PRLAR8_EL2 }, 0xE361, true, true,  {AArch64_HasV8_0rOps}  }, // 790
  { "PRLAR9_EL1", { .raw_val = AARCH64_SYSREG_PRLAR9_EL1 }, "PRLAR9_EL1", { .raw_val = AARCH64_SYSREG_PRLAR9_EL1 }, 0xC365, true, true,  {AArch64_HasV8_0rOps}  }, // 791
  { "PRLAR9_EL2", { .raw_val = AARCH64_SYSREG_PRLAR9_EL2 }, "PRLAR9_EL2", { .raw_val = AARCH64_SYSREG_PRLAR9_EL2 }, 0xE365, true, true,  {AArch64_HasV8_0rOps}  }, // 792
  { "PRLAR_EL1", { .raw_val = AARCH64_SYSREG_PRLAR_EL1 }, "PRLAR_EL1", { .raw_val = AARCH64_SYSREG_PRLAR_EL1 }, 0xC341, true, true,  {AArch64_HasV8_0rOps}  }, // 793
  { "PRLAR_EL2", { .raw_val = AARCH64_SYSREG_PRLAR_EL2 }, "PRLAR_EL2", { .raw_val = AARCH64_SYSREG_PRLAR_EL2 }, 0xE341, true, true,  {AArch64_HasV8_0rOps}  }, // 794
  { "PRSELR_EL1", { .raw_val = AARCH64_SYSREG_PRSELR_EL1 }, "PRSELR_EL1", { .raw_val = AARCH64_SYSREG_PRSELR_EL1 }, 0xC311, true, true,  {AArch64_HasV8_0rOps}  }, // 795
  { "PRSELR_EL2", { .raw_val = AARCH64_SYSREG_PRSELR_EL2 }, "PRSELR_EL2", { .raw_val = AARCH64_SYSREG_PRSELR_EL2 }, 0xE311, true, true,  {AArch64_HasV8_0rOps}  }, // 796
  { "RCWMASK_EL1", { .raw_val = AARCH64_SYSREG_RCWMASK_EL1 }, "RCWMASK_EL1", { .raw_val = AARCH64_SYSREG_RCWMASK_EL1 }, 0xC686, true, true,  {AArch64_FeatureTHE}  }, // 797
  { "RCWSMASK_EL1", { .raw_val = AARCH64_SYSREG_RCWSMASK_EL1 }, "RCWSMASK_EL1", { .raw_val = AARCH64_SYSREG_RCWSMASK_EL1 }, 0xC683, true, true,  {AArch64_FeatureTHE}  }, // 798
  { "REVIDR_EL1", { .raw_val = AARCH64_SYSREG_REVIDR_EL1 }, "REVIDR_EL1", { .raw_val = AARCH64_SYSREG_REVIDR_EL1 }, 0xC006, true, false,  {0}  }, // 799
  { "RGSR_EL1", { .raw_val = AARCH64_SYSREG_RGSR_EL1 }, "RGSR_EL1", { .raw_val = AARCH64_SYSREG_RGSR_EL1 }, 0xC085, true, true,  {AArch64_FeatureMTE}  }, // 800
  { "RMR_EL1", { .raw_val = AARCH64_SYSREG_RMR_EL1 }, "RMR_EL1", { .raw_val = AARCH64_SYSREG_RMR_EL1 }, 0xC602, true, true,  {0}  }, // 801
  { "RMR_EL2", { .raw_val = AARCH64_SYSREG_RMR_EL2 }, "RMR_EL2", { .raw_val = AARCH64_SYSREG_RMR_EL2 }, 0xE602, true, true,  {0}  }, // 802
  { "RMR_EL3", { .raw_val = AARCH64_SYSREG_RMR_EL3 }, "RMR_EL3", { .raw_val = AARCH64_SYSREG_RMR_EL3 }, 0xF602, true, true,  {0}  }, // 803
  { "RNDR", { .raw_val = AARCH64_SYSREG_RNDR }, "RNDR", { .raw_val = AARCH64_SYSREG_RNDR }, 0xD920, true, false,  {AArch64_FeatureRandGen}  }, // 804
  { "RNDRRS", { .raw_val = AARCH64_SYSREG_RNDRRS }, "RNDRRS", { .raw_val = AARCH64_SYSREG_RNDRRS }, 0xD921, true, false,  {AArch64_FeatureRandGen}  }, // 805
  { "RVBAR_EL1", { .raw_val = AARCH64_SYSREG_RVBAR_EL1 }, "RVBAR_EL1", { .raw_val = AARCH64_SYSREG_RVBAR_EL1 }, 0xC601, true, false,  {0}  }, // 806
  { "RVBAR_EL2", { .raw_val = AARCH64_SYSREG_RVBAR_EL2 }, "RVBAR_EL2", { .raw_val = AARCH64_SYSREG_RVBAR_EL2 }, 0xE601, true, false,  {0}  }, // 807
  { "RVBAR_EL3", { .raw_val = AARCH64_SYSREG_RVBAR_EL3 }, "RVBAR_EL3", { .raw_val = AARCH64_SYSREG_RVBAR_EL3 }, 0xF601, true, false,  {0}  }, // 808
  { "S2PIR_EL2", { .raw_val = AARCH64_SYSREG_S2PIR_EL2 }, "S2PIR_EL2", { .raw_val = AARCH64_SYSREG_S2PIR_EL2 }, 0xE515, true, true,  {0}  }, // 809
  { "S2POR_EL1", { .raw_val = AARCH64_SYSREG_S2POR_EL1 }, "S2POR_EL1", { .raw_val = AARCH64_SYSREG_S2POR_EL1 }, 0xC515, true, true,  {0}  }, // 810
  { "SCR_EL3", { .raw_val = AARCH64_SYSREG_SCR_EL3 }, "SCR_EL3", { .raw_val = AARCH64_SYSREG_SCR_EL3 }, 0xF088, true, true,  {0}  }, // 811
  { "SCTLR2_EL1", { .raw_val = AARCH64_SYSREG_SCTLR2_EL1 }, "SCTLR2_EL1", { .raw_val = AARCH64_SYSREG_SCTLR2_EL1 }, 0xC083, true, true,  {0}  }, // 812
  { "SCTLR2_EL12", { .raw_val = AARCH64_SYSREG_SCTLR2_EL12 }, "SCTLR2_EL12", { .raw_val = AARCH64_SYSREG_SCTLR2_EL12 }, 0xE883, true, true,  {0}  }, // 813
  { "SCTLR2_EL2", { .raw_val = AARCH64_SYSREG_SCTLR2_EL2 }, "SCTLR2_EL2", { .raw_val = AARCH64_SYSREG_SCTLR2_EL2 }, 0xE083, true, true,  {0}  }, // 814
  { "SCTLR2_EL3", { .raw_val = AARCH64_SYSREG_SCTLR2_EL3 }, "SCTLR2_EL3", { .raw_val = AARCH64_SYSREG_SCTLR2_EL3 }, 0xF083, true, true,  {0}  }, // 815
  { "SCTLR_EL1", { .raw_val = AARCH64_SYSREG_SCTLR_EL1 }, "SCTLR_EL1", { .raw_val = AARCH64_SYSREG_SCTLR_EL1 }, 0xC080, true, true,  {0}  }, // 816
  { "SCTLR_EL12", { .raw_val = AARCH64_SYSREG_SCTLR_EL12 }, "SCTLR_EL12", { .raw_val = AARCH64_SYSREG_SCTLR_EL12 }, 0xE880, true, true,  {AArch64_FeatureVH}  }, // 817
  { "SCTLR_EL2", { .raw_val = AARCH64_SYSREG_SCTLR_EL2 }, "SCTLR_EL2", { .raw_val = AARCH64_SYSREG_SCTLR_EL2 }, 0xE080, true, true,  {0}  }, // 818
  { "SCTLR_EL3", { .raw_val = AARCH64_SYSREG_SCTLR_EL3 }, "SCTLR_EL3", { .raw_val = AARCH64_SYSREG_SCTLR_EL3 }, 0xF080, true, true,  {0}  }, // 819
  { "SCXTNUM_EL0", { .raw_val = AARCH64_SYSREG_SCXTNUM_EL0 }, "SCXTNUM_EL0", { .raw_val = AARCH64_SYSREG_SCXTNUM_EL0 }, 0xDE87, true, true,  {AArch64_FeatureSpecRestrict}  }, // 820
  { "SCXTNUM_EL1", { .raw_val = AARCH64_SYSREG_SCXTNUM_EL1 }, "SCXTNUM_EL1", { .raw_val = AARCH64_SYSREG_SCXTNUM_EL1 }, 0xC687, true, true,  {AArch64_FeatureSpecRestrict}  }, // 821
  { "SCXTNUM_EL12", { .raw_val = AARCH64_SYSREG_SCXTNUM_EL12 }, "SCXTNUM_EL12", { .raw_val = AARCH64_SYSREG_SCXTNUM_EL12 }, 0xEE87, true, true,  {AArch64_FeatureSpecRestrict}  }, // 822
  { "SCXTNUM_EL2", { .raw_val = AARCH64_SYSREG_SCXTNUM_EL2 }, "SCXTNUM_EL2", { .raw_val = AARCH64_SYSREG_SCXTNUM_EL2 }, 0xE687, true, true,  {AArch64_FeatureSpecRestrict}  }, // 823
  { "SCXTNUM_EL3", { .raw_val = AARCH64_SYSREG_SCXTNUM_EL3 }, "SCXTNUM_EL3", { .raw_val = AARCH64_SYSREG_SCXTNUM_EL3 }, 0xF687, true, true,  {AArch64_FeatureSpecRestrict}  }, // 824
  { "SDER32_EL2", { .raw_val = AARCH64_SYSREG_SDER32_EL2 }, "SDER32_EL2", { .raw_val = AARCH64_SYSREG_SDER32_EL2 }, 0xE099, true, true,  {AArch64_FeatureSEL2}  }, // 825
  { "SDER32_EL3", { .raw_val = AARCH64_SYSREG_SDER32_EL3 }, "SDER32_EL3", { .raw_val = AARCH64_SYSREG_SDER32_EL3 }, 0xF089, true, true,  {0}  }, // 826
  { "SMCR_EL1", { .raw_val = AARCH64_SYSREG_SMCR_EL1 }, "SMCR_EL1", { .raw_val = AARCH64_SYSREG_SMCR_EL1 }, 0xC096, true, true,  {AArch64_FeatureSME}  }, // 827
  { "SMCR_EL12", { .raw_val = AARCH64_SYSREG_SMCR_EL12 }, "SMCR_EL12", { .raw_val = AARCH64_SYSREG_SMCR_EL12 }, 0xE896, true, true,  {AArch64_FeatureSME}  }, // 828
  { "SMCR_EL2", { .raw_val = AARCH64_SYSREG_SMCR_EL2 }, "SMCR_EL2", { .raw_val = AARCH64_SYSREG_SMCR_EL2 }, 0xE096, true, true,  {AArch64_FeatureSME}  }, // 829
  { "SMCR_EL3", { .raw_val = AARCH64_SYSREG_SMCR_EL3 }, "SMCR_EL3", { .raw_val = AARCH64_SYSREG_SMCR_EL3 }, 0xF096, true, true,  {AArch64_FeatureSME}  }, // 830
  { "SMIDR_EL1", { .raw_val = AARCH64_SYSREG_SMIDR_EL1 }, "SMIDR_EL1", { .raw_val = AARCH64_SYSREG_SMIDR_EL1 }, 0xC806, true, false,  {AArch64_FeatureSME}  }, // 831
  { "SMPRIMAP_EL2", { .raw_val = AARCH64_SYSREG_SMPRIMAP_EL2 }, "SMPRIMAP_EL2", { .raw_val = AARCH64_SYSREG_SMPRIMAP_EL2 }, 0xE095, true, true,  {AArch64_FeatureSME}  }, // 832
  { "SMPRI_EL1", { .raw_val = AARCH64_SYSREG_SMPRI_EL1 }, "SMPRI_EL1", { .raw_val = AARCH64_SYSREG_SMPRI_EL1 }, 0xC094, true, true,  {AArch64_FeatureSME}  }, // 833
  { "SPMACCESSR_EL1", { .raw_val = AARCH64_SYSREG_SPMACCESSR_EL1 }, "SPMACCESSR_EL1", { .raw_val = AARCH64_SYSREG_SPMACCESSR_EL1 }, 0x84EB, true, true,  {0}  }, // 834
  { "SPMACCESSR_EL12", { .raw_val = AARCH64_SYSREG_SPMACCESSR_EL12 }, "SPMACCESSR_EL12", { .raw_val = AARCH64_SYSREG_SPMACCESSR_EL12 }, 0xACEB, true, true,  {0}  }, // 835
  { "SPMACCESSR_EL2", { .raw_val = AARCH64_SYSREG_SPMACCESSR_EL2 }, "SPMACCESSR_EL2", { .raw_val = AARCH64_SYSREG_SPMACCESSR_EL2 }, 0xA4EB, true, true,  {0}  }, // 836
  { "SPMACCESSR_EL3", { .raw_val = AARCH64_SYSREG_SPMACCESSR_EL3 }, "SPMACCESSR_EL3", { .raw_val = AARCH64_SYSREG_SPMACCESSR_EL3 }, 0xB4EB, true, true,  {0}  }, // 837
  { "SPMCFGR_EL1", { .raw_val = AARCH64_SYSREG_SPMCFGR_EL1 }, "SPMCFGR_EL1", { .raw_val = AARCH64_SYSREG_SPMCFGR_EL1 }, 0x84EF, true, false,  {0}  }, // 838
  { "SPMCGCR0_EL1", { .raw_val = AARCH64_SYSREG_SPMCGCR0_EL1 }, "SPMCGCR0_EL1", { .raw_val = AARCH64_SYSREG_SPMCGCR0_EL1 }, 0x84E8, true, false,  {0}  }, // 839
  { "SPMCGCR1_EL1", { .raw_val = AARCH64_SYSREG_SPMCGCR1_EL1 }, "SPMCGCR1_EL1", { .raw_val = AARCH64_SYSREG_SPMCGCR1_EL1 }, 0x84E9, true, false,  {0}  }, // 840
  { "SPMCNTENCLR_EL0", { .raw_val = AARCH64_SYSREG_SPMCNTENCLR_EL0 }, "SPMCNTENCLR_EL0", { .raw_val = AARCH64_SYSREG_SPMCNTENCLR_EL0 }, 0x9CE2, true, true,  {0}  }, // 841
  { "SPMCNTENSET_EL0", { .raw_val = AARCH64_SYSREG_SPMCNTENSET_EL0 }, "SPMCNTENSET_EL0", { .raw_val = AARCH64_SYSREG_SPMCNTENSET_EL0 }, 0x9CE1, true, true,  {0}  }, // 842
  { "SPMCR_EL0", { .raw_val = AARCH64_SYSREG_SPMCR_EL0 }, "SPMCR_EL0", { .raw_val = AARCH64_SYSREG_SPMCR_EL0 }, 0x9CE0, true, true,  {0}  }, // 843
  { "SPMDEVAFF_EL1", { .raw_val = AARCH64_SYSREG_SPMDEVAFF_EL1 }, "SPMDEVAFF_EL1", { .raw_val = AARCH64_SYSREG_SPMDEVAFF_EL1 }, 0x84EE, true, false,  {0}  }, // 844
  { "SPMDEVARCH_EL1", { .raw_val = AARCH64_SYSREG_SPMDEVARCH_EL1 }, "SPMDEVARCH_EL1", { .raw_val = AARCH64_SYSREG_SPMDEVARCH_EL1 }, 0x84ED, true, false,  {0}  }, // 845
  { "SPMEVCNTR0_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR0_EL0 }, "SPMEVCNTR0_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR0_EL0 }, 0x9F00, true, true,  {0}  }, // 846
  { "SPMEVCNTR10_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR10_EL0 }, "SPMEVCNTR10_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR10_EL0 }, 0x9F0A, true, true,  {0}  }, // 847
  { "SPMEVCNTR11_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR11_EL0 }, "SPMEVCNTR11_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR11_EL0 }, 0x9F0B, true, true,  {0}  }, // 848
  { "SPMEVCNTR12_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR12_EL0 }, "SPMEVCNTR12_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR12_EL0 }, 0x9F0C, true, true,  {0}  }, // 849
  { "SPMEVCNTR13_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR13_EL0 }, "SPMEVCNTR13_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR13_EL0 }, 0x9F0D, true, true,  {0}  }, // 850
  { "SPMEVCNTR14_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR14_EL0 }, "SPMEVCNTR14_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR14_EL0 }, 0x9F0E, true, true,  {0}  }, // 851
  { "SPMEVCNTR15_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR15_EL0 }, "SPMEVCNTR15_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR15_EL0 }, 0x9F0F, true, true,  {0}  }, // 852
  { "SPMEVCNTR1_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR1_EL0 }, "SPMEVCNTR1_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR1_EL0 }, 0x9F01, true, true,  {0}  }, // 853
  { "SPMEVCNTR2_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR2_EL0 }, "SPMEVCNTR2_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR2_EL0 }, 0x9F02, true, true,  {0}  }, // 854
  { "SPMEVCNTR3_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR3_EL0 }, "SPMEVCNTR3_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR3_EL0 }, 0x9F03, true, true,  {0}  }, // 855
  { "SPMEVCNTR4_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR4_EL0 }, "SPMEVCNTR4_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR4_EL0 }, 0x9F04, true, true,  {0}  }, // 856
  { "SPMEVCNTR5_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR5_EL0 }, "SPMEVCNTR5_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR5_EL0 }, 0x9F05, true, true,  {0}  }, // 857
  { "SPMEVCNTR6_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR6_EL0 }, "SPMEVCNTR6_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR6_EL0 }, 0x9F06, true, true,  {0}  }, // 858
  { "SPMEVCNTR7_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR7_EL0 }, "SPMEVCNTR7_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR7_EL0 }, 0x9F07, true, true,  {0}  }, // 859
  { "SPMEVCNTR8_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR8_EL0 }, "SPMEVCNTR8_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR8_EL0 }, 0x9F08, true, true,  {0}  }, // 860
  { "SPMEVCNTR9_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR9_EL0 }, "SPMEVCNTR9_EL0", { .raw_val = AARCH64_SYSREG_SPMEVCNTR9_EL0 }, 0x9F09, true, true,  {0}  }, // 861
  { "SPMEVFILT2R0_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R0_EL0 }, "SPMEVFILT2R0_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R0_EL0 }, 0x9F30, true, true,  {0}  }, // 862
  { "SPMEVFILT2R10_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R10_EL0 }, "SPMEVFILT2R10_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R10_EL0 }, 0x9F3A, true, true,  {0}  }, // 863
  { "SPMEVFILT2R11_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R11_EL0 }, "SPMEVFILT2R11_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R11_EL0 }, 0x9F3B, true, true,  {0}  }, // 864
  { "SPMEVFILT2R12_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R12_EL0 }, "SPMEVFILT2R12_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R12_EL0 }, 0x9F3C, true, true,  {0}  }, // 865
  { "SPMEVFILT2R13_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R13_EL0 }, "SPMEVFILT2R13_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R13_EL0 }, 0x9F3D, true, true,  {0}  }, // 866
  { "SPMEVFILT2R14_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R14_EL0 }, "SPMEVFILT2R14_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R14_EL0 }, 0x9F3E, true, true,  {0}  }, // 867
  { "SPMEVFILT2R15_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R15_EL0 }, "SPMEVFILT2R15_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R15_EL0 }, 0x9F3F, true, true,  {0}  }, // 868
  { "SPMEVFILT2R1_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R1_EL0 }, "SPMEVFILT2R1_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R1_EL0 }, 0x9F31, true, true,  {0}  }, // 869
  { "SPMEVFILT2R2_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R2_EL0 }, "SPMEVFILT2R2_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R2_EL0 }, 0x9F32, true, true,  {0}  }, // 870
  { "SPMEVFILT2R3_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R3_EL0 }, "SPMEVFILT2R3_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R3_EL0 }, 0x9F33, true, true,  {0}  }, // 871
  { "SPMEVFILT2R4_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R4_EL0 }, "SPMEVFILT2R4_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R4_EL0 }, 0x9F34, true, true,  {0}  }, // 872
  { "SPMEVFILT2R5_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R5_EL0 }, "SPMEVFILT2R5_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R5_EL0 }, 0x9F35, true, true,  {0}  }, // 873
  { "SPMEVFILT2R6_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R6_EL0 }, "SPMEVFILT2R6_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R6_EL0 }, 0x9F36, true, true,  {0}  }, // 874
  { "SPMEVFILT2R7_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R7_EL0 }, "SPMEVFILT2R7_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R7_EL0 }, 0x9F37, true, true,  {0}  }, // 875
  { "SPMEVFILT2R8_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R8_EL0 }, "SPMEVFILT2R8_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R8_EL0 }, 0x9F38, true, true,  {0}  }, // 876
  { "SPMEVFILT2R9_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R9_EL0 }, "SPMEVFILT2R9_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILT2R9_EL0 }, 0x9F39, true, true,  {0}  }, // 877
  { "SPMEVFILTR0_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR0_EL0 }, "SPMEVFILTR0_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR0_EL0 }, 0x9F20, true, true,  {0}  }, // 878
  { "SPMEVFILTR10_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR10_EL0 }, "SPMEVFILTR10_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR10_EL0 }, 0x9F2A, true, true,  {0}  }, // 879
  { "SPMEVFILTR11_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR11_EL0 }, "SPMEVFILTR11_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR11_EL0 }, 0x9F2B, true, true,  {0}  }, // 880
  { "SPMEVFILTR12_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR12_EL0 }, "SPMEVFILTR12_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR12_EL0 }, 0x9F2C, true, true,  {0}  }, // 881
  { "SPMEVFILTR13_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR13_EL0 }, "SPMEVFILTR13_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR13_EL0 }, 0x9F2D, true, true,  {0}  }, // 882
  { "SPMEVFILTR14_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR14_EL0 }, "SPMEVFILTR14_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR14_EL0 }, 0x9F2E, true, true,  {0}  }, // 883
  { "SPMEVFILTR15_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR15_EL0 }, "SPMEVFILTR15_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR15_EL0 }, 0x9F2F, true, true,  {0}  }, // 884
  { "SPMEVFILTR1_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR1_EL0 }, "SPMEVFILTR1_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR1_EL0 }, 0x9F21, true, true,  {0}  }, // 885
  { "SPMEVFILTR2_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR2_EL0 }, "SPMEVFILTR2_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR2_EL0 }, 0x9F22, true, true,  {0}  }, // 886
  { "SPMEVFILTR3_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR3_EL0 }, "SPMEVFILTR3_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR3_EL0 }, 0x9F23, true, true,  {0}  }, // 887
  { "SPMEVFILTR4_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR4_EL0 }, "SPMEVFILTR4_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR4_EL0 }, 0x9F24, true, true,  {0}  }, // 888
  { "SPMEVFILTR5_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR5_EL0 }, "SPMEVFILTR5_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR5_EL0 }, 0x9F25, true, true,  {0}  }, // 889
  { "SPMEVFILTR6_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR6_EL0 }, "SPMEVFILTR6_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR6_EL0 }, 0x9F26, true, true,  {0}  }, // 890
  { "SPMEVFILTR7_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR7_EL0 }, "SPMEVFILTR7_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR7_EL0 }, 0x9F27, true, true,  {0}  }, // 891
  { "SPMEVFILTR8_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR8_EL0 }, "SPMEVFILTR8_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR8_EL0 }, 0x9F28, true, true,  {0}  }, // 892
  { "SPMEVFILTR9_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR9_EL0 }, "SPMEVFILTR9_EL0", { .raw_val = AARCH64_SYSREG_SPMEVFILTR9_EL0 }, 0x9F29, true, true,  {0}  }, // 893
  { "SPMEVTYPER0_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER0_EL0 }, "SPMEVTYPER0_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER0_EL0 }, 0x9F10, true, true,  {0}  }, // 894
  { "SPMEVTYPER10_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER10_EL0 }, "SPMEVTYPER10_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER10_EL0 }, 0x9F1A, true, true,  {0}  }, // 895
  { "SPMEVTYPER11_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER11_EL0 }, "SPMEVTYPER11_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER11_EL0 }, 0x9F1B, true, true,  {0}  }, // 896
  { "SPMEVTYPER12_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER12_EL0 }, "SPMEVTYPER12_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER12_EL0 }, 0x9F1C, true, true,  {0}  }, // 897
  { "SPMEVTYPER13_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER13_EL0 }, "SPMEVTYPER13_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER13_EL0 }, 0x9F1D, true, true,  {0}  }, // 898
  { "SPMEVTYPER14_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER14_EL0 }, "SPMEVTYPER14_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER14_EL0 }, 0x9F1E, true, true,  {0}  }, // 899
  { "SPMEVTYPER15_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER15_EL0 }, "SPMEVTYPER15_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER15_EL0 }, 0x9F1F, true, true,  {0}  }, // 900
  { "SPMEVTYPER1_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER1_EL0 }, "SPMEVTYPER1_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER1_EL0 }, 0x9F11, true, true,  {0}  }, // 901
  { "SPMEVTYPER2_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER2_EL0 }, "SPMEVTYPER2_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER2_EL0 }, 0x9F12, true, true,  {0}  }, // 902
  { "SPMEVTYPER3_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER3_EL0 }, "SPMEVTYPER3_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER3_EL0 }, 0x9F13, true, true,  {0}  }, // 903
  { "SPMEVTYPER4_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER4_EL0 }, "SPMEVTYPER4_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER4_EL0 }, 0x9F14, true, true,  {0}  }, // 904
  { "SPMEVTYPER5_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER5_EL0 }, "SPMEVTYPER5_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER5_EL0 }, 0x9F15, true, true,  {0}  }, // 905
  { "SPMEVTYPER6_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER6_EL0 }, "SPMEVTYPER6_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER6_EL0 }, 0x9F16, true, true,  {0}  }, // 906
  { "SPMEVTYPER7_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER7_EL0 }, "SPMEVTYPER7_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER7_EL0 }, 0x9F17, true, true,  {0}  }, // 907
  { "SPMEVTYPER8_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER8_EL0 }, "SPMEVTYPER8_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER8_EL0 }, 0x9F18, true, true,  {0}  }, // 908
  { "SPMEVTYPER9_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER9_EL0 }, "SPMEVTYPER9_EL0", { .raw_val = AARCH64_SYSREG_SPMEVTYPER9_EL0 }, 0x9F19, true, true,  {0}  }, // 909
  { "SPMIIDR_EL1", { .raw_val = AARCH64_SYSREG_SPMIIDR_EL1 }, "SPMIIDR_EL1", { .raw_val = AARCH64_SYSREG_SPMIIDR_EL1 }, 0x84EC, true, false,  {0}  }, // 910
  { "SPMINTENCLR_EL1", { .raw_val = AARCH64_SYSREG_SPMINTENCLR_EL1 }, "SPMINTENCLR_EL1", { .raw_val = AARCH64_SYSREG_SPMINTENCLR_EL1 }, 0x84F2, true, true,  {0}  }, // 911
  { "SPMINTENSET_EL1", { .raw_val = AARCH64_SYSREG_SPMINTENSET_EL1 }, "SPMINTENSET_EL1", { .raw_val = AARCH64_SYSREG_SPMINTENSET_EL1 }, 0x84F1, true, true,  {0}  }, // 912
  { "SPMOVSCLR_EL0", { .raw_val = AARCH64_SYSREG_SPMOVSCLR_EL0 }, "SPMOVSCLR_EL0", { .raw_val = AARCH64_SYSREG_SPMOVSCLR_EL0 }, 0x9CE3, true, true,  {0}  }, // 913
  { "SPMOVSSET_EL0", { .raw_val = AARCH64_SYSREG_SPMOVSSET_EL0 }, "SPMOVSSET_EL0", { .raw_val = AARCH64_SYSREG_SPMOVSSET_EL0 }, 0x9CF3, true, true,  {0}  }, // 914
  { "SPMROOTCR_EL3", { .raw_val = AARCH64_SYSREG_SPMROOTCR_EL3 }, "SPMROOTCR_EL3", { .raw_val = AARCH64_SYSREG_SPMROOTCR_EL3 }, 0xB4F7, true, true,  {0}  }, // 915
  { "SPMSCR_EL1", { .raw_val = AARCH64_SYSREG_SPMSCR_EL1 }, "SPMSCR_EL1", { .raw_val = AARCH64_SYSREG_SPMSCR_EL1 }, 0xBCF7, true, true,  {0}  }, // 916
  { "SPMSELR_EL0", { .raw_val = AARCH64_SYSREG_SPMSELR_EL0 }, "SPMSELR_EL0", { .raw_val = AARCH64_SYSREG_SPMSELR_EL0 }, 0x9CE5, true, true,  {0}  }, // 917
  { "SPMZR_EL0", { .raw_val = AARCH64_SYSREG_SPMZR_EL0 }, "SPMZR_EL0", { .raw_val = AARCH64_SYSREG_SPMZR_EL0 }, 0x9CE4, false, true,  {0}  }, // 918
  { "SPSel", { .raw_val = AARCH64_SYSREG_SPSEL }, "SPSel", { .raw_val = AARCH64_SYSREG_SPSEL }, 0xC210, true, true,  {0}  }, // 919
  { "SPSR_abt", { .raw_val = AARCH64_SYSREG_SPSR_ABT }, "SPSR_abt", { .raw_val = AARCH64_SYSREG_SPSR_ABT }, 0xE219, true, true,  {0}  }, // 920
  { "SPSR_EL1", { .raw_val = AARCH64_SYSREG_SPSR_EL1 }, "SPSR_EL1", { .raw_val = AARCH64_SYSREG_SPSR_EL1 }, 0xC200, true, true,  {0}  }, // 921
  { "SPSR_EL12", { .raw_val = AARCH64_SYSREG_SPSR_EL12 }, "SPSR_EL12", { .raw_val = AARCH64_SYSREG_SPSR_EL12 }, 0xEA00, true, true,  {AArch64_FeatureVH}  }, // 922
  { "SPSR_EL2", { .raw_val = AARCH64_SYSREG_SPSR_EL2 }, "SPSR_EL2", { .raw_val = AARCH64_SYSREG_SPSR_EL2 }, 0xE200, true, true,  {0}  }, // 923
  { "SPSR_EL3", { .raw_val = AARCH64_SYSREG_SPSR_EL3 }, "SPSR_EL3", { .raw_val = AARCH64_SYSREG_SPSR_EL3 }, 0xF200, true, true,  {0}  }, // 924
  { "SPSR_fiq", { .raw_val = AARCH64_SYSREG_SPSR_FIQ }, "SPSR_fiq", { .raw_val = AARCH64_SYSREG_SPSR_FIQ }, 0xE21B, true, true,  {0}  }, // 925
  { "SPSR_irq", { .raw_val = AARCH64_SYSREG_SPSR_IRQ }, "SPSR_irq", { .raw_val = AARCH64_SYSREG_SPSR_IRQ }, 0xE218, true, true,  {0}  }, // 926
  { "SPSR_und", { .raw_val = AARCH64_SYSREG_SPSR_UND }, "SPSR_und", { .raw_val = AARCH64_SYSREG_SPSR_UND }, 0xE21A, true, true,  {0}  }, // 927
  { "SP_EL0", { .raw_val = AARCH64_SYSREG_SP_EL0 }, "SP_EL0", { .raw_val = AARCH64_SYSREG_SP_EL0 }, 0xC208, true, true,  {0}  }, // 928
  { "SP_EL1", { .raw_val = AARCH64_SYSREG_SP_EL1 }, "SP_EL1", { .raw_val = AARCH64_SYSREG_SP_EL1 }, 0xE208, true, true,  {0}  }, // 929
  { "SP_EL2", { .raw_val = AARCH64_SYSREG_SP_EL2 }, "SP_EL2", { .raw_val = AARCH64_SYSREG_SP_EL2 }, 0xF208, true, true,  {0}  }, // 930
  { "SSBS", { .raw_val = AARCH64_SYSREG_SSBS }, "SSBS", { .raw_val = AARCH64_SYSREG_SSBS }, 0xDA16, true, true,  {AArch64_FeatureSSBS}  }, // 931
  { "SVCR", { .raw_val = AARCH64_SYSREG_SVCR }, "SVCR", { .raw_val = AARCH64_SYSREG_SVCR }, 0xDA12, true, true,  {AArch64_FeatureSME}  }, // 932
  { "TCO", { .raw_val = AARCH64_SYSREG_TCO }, "TCO", { .raw_val = AARCH64_SYSREG_TCO }, 0xDA17, true, true,  {AArch64_FeatureMTE}  }, // 933
  { "TCR2_EL1", { .raw_val = AARCH64_SYSREG_TCR2_EL1 }, "TCR2_EL1", { .raw_val = AARCH64_SYSREG_TCR2_EL1 }, 0xC103, true, true,  {0}  }, // 934
  { "TCR2_EL12", { .raw_val = AARCH64_SYSREG_TCR2_EL12 }, "TCR2_EL12", { .raw_val = AARCH64_SYSREG_TCR2_EL12 }, 0xE903, true, true,  {0}  }, // 935
  { "TCR2_EL2", { .raw_val = AARCH64_SYSREG_TCR2_EL2 }, "TCR2_EL2", { .raw_val = AARCH64_SYSREG_TCR2_EL2 }, 0xE103, true, true,  {0}  }, // 936
  { "TCR_EL1", { .raw_val = AARCH64_SYSREG_TCR_EL1 }, "TCR_EL1", { .raw_val = AARCH64_SYSREG_TCR_EL1 }, 0xC102, true, true,  {0}  }, // 937
  { "TCR_EL12", { .raw_val = AARCH64_SYSREG_TCR_EL12 }, "TCR_EL12", { .raw_val = AARCH64_SYSREG_TCR_EL12 }, 0xE902, true, true,  {AArch64_FeatureVH}  }, // 938
  { "TCR_EL2", { .raw_val = AARCH64_SYSREG_TCR_EL2 }, "TCR_EL2", { .raw_val = AARCH64_SYSREG_TCR_EL2 }, 0xE102, true, true,  {0}  }, // 939
  { "TCR_EL3", { .raw_val = AARCH64_SYSREG_TCR_EL3 }, "TCR_EL3", { .raw_val = AARCH64_SYSREG_TCR_EL3 }, 0xF102, true, true,  {0}  }, // 940
  { "TEECR32_EL1", { .raw_val = AARCH64_SYSREG_TEECR32_EL1 }, "TEECR32_EL1", { .raw_val = AARCH64_SYSREG_TEECR32_EL1 }, 0x9000, true, true,  {0}  }, // 941
  { "TEEHBR32_EL1", { .raw_val = AARCH64_SYSREG_TEEHBR32_EL1 }, "TEEHBR32_EL1", { .raw_val = AARCH64_SYSREG_TEEHBR32_EL1 }, 0x9080, true, true,  {0}  }, // 942
  { "TFSRE0_EL1", { .raw_val = AARCH64_SYSREG_TFSRE0_EL1 }, "TFSRE0_EL1", { .raw_val = AARCH64_SYSREG_TFSRE0_EL1 }, 0xC2B1, true, true,  {AArch64_FeatureMTE}  }, // 943
  { "TFSR_EL1", { .raw_val = AARCH64_SYSREG_TFSR_EL1 }, "TFSR_EL1", { .raw_val = AARCH64_SYSREG_TFSR_EL1 }, 0xC2B0, true, true,  {AArch64_FeatureMTE}  }, // 944
  { "TFSR_EL12", { .raw_val = AARCH64_SYSREG_TFSR_EL12 }, "TFSR_EL12", { .raw_val = AARCH64_SYSREG_TFSR_EL12 }, 0xEAB0, true, true,  {AArch64_FeatureMTE}  }, // 945
  { "TFSR_EL2", { .raw_val = AARCH64_SYSREG_TFSR_EL2 }, "TFSR_EL2", { .raw_val = AARCH64_SYSREG_TFSR_EL2 }, 0xE2B0, true, true,  {AArch64_FeatureMTE}  }, // 946
  { "TFSR_EL3", { .raw_val = AARCH64_SYSREG_TFSR_EL3 }, "TFSR_EL3", { .raw_val = AARCH64_SYSREG_TFSR_EL3 }, 0xF2B0, true, true,  {AArch64_FeatureMTE}  }, // 947
  { "TPIDR2_EL0", { .raw_val = AARCH64_SYSREG_TPIDR2_EL0 }, "TPIDR2_EL0", { .raw_val = AARCH64_SYSREG_TPIDR2_EL0 }, 0xDE85, true, true,  {AArch64_FeatureSME}  }, // 948
  { "TPIDRRO_EL0", { .raw_val = AARCH64_SYSREG_TPIDRRO_EL0 }, "TPIDRRO_EL0", { .raw_val = AARCH64_SYSREG_TPIDRRO_EL0 }, 0xDE83, true, true,  {0}  }, // 949
  { "TPIDR_EL0", { .raw_val = AARCH64_SYSREG_TPIDR_EL0 }, "TPIDR_EL0", { .raw_val = AARCH64_SYSREG_TPIDR_EL0 }, 0xDE82, true, true,  {0}  }, // 950
  { "TPIDR_EL1", { .raw_val = AARCH64_SYSREG_TPIDR_EL1 }, "TPIDR_EL1", { .raw_val = AARCH64_SYSREG_TPIDR_EL1 }, 0xC684, true, true,  {0}  }, // 951
  { "TPIDR_EL2", { .raw_val = AARCH64_SYSREG_TPIDR_EL2 }, "TPIDR_EL2", { .raw_val = AARCH64_SYSREG_TPIDR_EL2 }, 0xE682, true, true,  {0}  }, // 952
  { "TPIDR_EL3", { .raw_val = AARCH64_SYSREG_TPIDR_EL3 }, "TPIDR_EL3", { .raw_val = AARCH64_SYSREG_TPIDR_EL3 }, 0xF682, true, true,  {0}  }, // 953
  { "TRBBASER_EL1", { .raw_val = AARCH64_SYSREG_TRBBASER_EL1 }, "TRBBASER_EL1", { .raw_val = AARCH64_SYSREG_TRBBASER_EL1 }, 0xC4DA, true, true,  {AArch64_FeatureTRBE}  }, // 954
  { "TRBIDR_EL1", { .raw_val = AARCH64_SYSREG_TRBIDR_EL1 }, "TRBIDR_EL1", { .raw_val = AARCH64_SYSREG_TRBIDR_EL1 }, 0xC4DF, true, false,  {AArch64_FeatureTRBE}  }, // 955
  { "TRBLIMITR_EL1", { .raw_val = AARCH64_SYSREG_TRBLIMITR_EL1 }, "TRBLIMITR_EL1", { .raw_val = AARCH64_SYSREG_TRBLIMITR_EL1 }, 0xC4D8, true, true,  {AArch64_FeatureTRBE}  }, // 956
  { "TRBMAR_EL1", { .raw_val = AARCH64_SYSREG_TRBMAR_EL1 }, "TRBMAR_EL1", { .raw_val = AARCH64_SYSREG_TRBMAR_EL1 }, 0xC4DC, true, true,  {AArch64_FeatureTRBE}  }, // 957
  { "TRBPTR_EL1", { .raw_val = AARCH64_SYSREG_TRBPTR_EL1 }, "TRBPTR_EL1", { .raw_val = AARCH64_SYSREG_TRBPTR_EL1 }, 0xC4D9, true, true,  {AArch64_FeatureTRBE}  }, // 958
  { "TRBSR_EL1", { .raw_val = AARCH64_SYSREG_TRBSR_EL1 }, "TRBSR_EL1", { .raw_val = AARCH64_SYSREG_TRBSR_EL1 }, 0xC4DB, true, true,  {AArch64_FeatureTRBE}  }, // 959
  { "TRBTRG_EL1", { .raw_val = AARCH64_SYSREG_TRBTRG_EL1 }, "TRBTRG_EL1", { .raw_val = AARCH64_SYSREG_TRBTRG_EL1 }, 0xC4DE, true, true,  {AArch64_FeatureTRBE}  }, // 960
  { "TRCACATR0", { .raw_val = AARCH64_SYSREG_TRCACATR0 }, "TRCACATR0", { .raw_val = AARCH64_SYSREG_TRCACATR0 }, 0x8902, true, true,  {0}  }, // 961
  { "TRCACATR1", { .raw_val = AARCH64_SYSREG_TRCACATR1 }, "TRCACATR1", { .raw_val = AARCH64_SYSREG_TRCACATR1 }, 0x8912, true, true,  {0}  }, // 962
  { "TRCACATR10", { .raw_val = AARCH64_SYSREG_TRCACATR10 }, "TRCACATR10", { .raw_val = AARCH64_SYSREG_TRCACATR10 }, 0x8923, true, true,  {0}  }, // 963
  { "TRCACATR11", { .raw_val = AARCH64_SYSREG_TRCACATR11 }, "TRCACATR11", { .raw_val = AARCH64_SYSREG_TRCACATR11 }, 0x8933, true, true,  {0}  }, // 964
  { "TRCACATR12", { .raw_val = AARCH64_SYSREG_TRCACATR12 }, "TRCACATR12", { .raw_val = AARCH64_SYSREG_TRCACATR12 }, 0x8943, true, true,  {0}  }, // 965
  { "TRCACATR13", { .raw_val = AARCH64_SYSREG_TRCACATR13 }, "TRCACATR13", { .raw_val = AARCH64_SYSREG_TRCACATR13 }, 0x8953, true, true,  {0}  }, // 966
  { "TRCACATR14", { .raw_val = AARCH64_SYSREG_TRCACATR14 }, "TRCACATR14", { .raw_val = AARCH64_SYSREG_TRCACATR14 }, 0x8963, true, true,  {0}  }, // 967
  { "TRCACATR15", { .raw_val = AARCH64_SYSREG_TRCACATR15 }, "TRCACATR15", { .raw_val = AARCH64_SYSREG_TRCACATR15 }, 0x8973, true, true,  {0}  }, // 968
  { "TRCACATR2", { .raw_val = AARCH64_SYSREG_TRCACATR2 }, "TRCACATR2", { .raw_val = AARCH64_SYSREG_TRCACATR2 }, 0x8922, true, true,  {0}  }, // 969
  { "TRCACATR3", { .raw_val = AARCH64_SYSREG_TRCACATR3 }, "TRCACATR3", { .raw_val = AARCH64_SYSREG_TRCACATR3 }, 0x8932, true, true,  {0}  }, // 970
  { "TRCACATR4", { .raw_val = AARCH64_SYSREG_TRCACATR4 }, "TRCACATR4", { .raw_val = AARCH64_SYSREG_TRCACATR4 }, 0x8942, true, true,  {0}  }, // 971
  { "TRCACATR5", { .raw_val = AARCH64_SYSREG_TRCACATR5 }, "TRCACATR5", { .raw_val = AARCH64_SYSREG_TRCACATR5 }, 0x8952, true, true,  {0}  }, // 972
  { "TRCACATR6", { .raw_val = AARCH64_SYSREG_TRCACATR6 }, "TRCACATR6", { .raw_val = AARCH64_SYSREG_TRCACATR6 }, 0x8962, true, true,  {0}  }, // 973
  { "TRCACATR7", { .raw_val = AARCH64_SYSREG_TRCACATR7 }, "TRCACATR7", { .raw_val = AARCH64_SYSREG_TRCACATR7 }, 0x8972, true, true,  {0}  }, // 974
  { "TRCACATR8", { .raw_val = AARCH64_SYSREG_TRCACATR8 }, "TRCACATR8", { .raw_val = AARCH64_SYSREG_TRCACATR8 }, 0x8903, true, true,  {0}  }, // 975
  { "TRCACATR9", { .raw_val = AARCH64_SYSREG_TRCACATR9 }, "TRCACATR9", { .raw_val = AARCH64_SYSREG_TRCACATR9 }, 0x8913, true, true,  {0}  }, // 976
  { "TRCACVR0", { .raw_val = AARCH64_SYSREG_TRCACVR0 }, "TRCACVR0", { .raw_val = AARCH64_SYSREG_TRCACVR0 }, 0x8900, true, true,  {0}  }, // 977
  { "TRCACVR1", { .raw_val = AARCH64_SYSREG_TRCACVR1 }, "TRCACVR1", { .raw_val = AARCH64_SYSREG_TRCACVR1 }, 0x8910, true, true,  {0}  }, // 978
  { "TRCACVR10", { .raw_val = AARCH64_SYSREG_TRCACVR10 }, "TRCACVR10", { .raw_val = AARCH64_SYSREG_TRCACVR10 }, 0x8921, true, true,  {0}  }, // 979
  { "TRCACVR11", { .raw_val = AARCH64_SYSREG_TRCACVR11 }, "TRCACVR11", { .raw_val = AARCH64_SYSREG_TRCACVR11 }, 0x8931, true, true,  {0}  }, // 980
  { "TRCACVR12", { .raw_val = AARCH64_SYSREG_TRCACVR12 }, "TRCACVR12", { .raw_val = AARCH64_SYSREG_TRCACVR12 }, 0x8941, true, true,  {0}  }, // 981
  { "TRCACVR13", { .raw_val = AARCH64_SYSREG_TRCACVR13 }, "TRCACVR13", { .raw_val = AARCH64_SYSREG_TRCACVR13 }, 0x8951, true, true,  {0}  }, // 982
  { "TRCACVR14", { .raw_val = AARCH64_SYSREG_TRCACVR14 }, "TRCACVR14", { .raw_val = AARCH64_SYSREG_TRCACVR14 }, 0x8961, true, true,  {0}  }, // 983
  { "TRCACVR15", { .raw_val = AARCH64_SYSREG_TRCACVR15 }, "TRCACVR15", { .raw_val = AARCH64_SYSREG_TRCACVR15 }, 0x8971, true, true,  {0}  }, // 984
  { "TRCACVR2", { .raw_val = AARCH64_SYSREG_TRCACVR2 }, "TRCACVR2", { .raw_val = AARCH64_SYSREG_TRCACVR2 }, 0x8920, true, true,  {0}  }, // 985
  { "TRCACVR3", { .raw_val = AARCH64_SYSREG_TRCACVR3 }, "TRCACVR3", { .raw_val = AARCH64_SYSREG_TRCACVR3 }, 0x8930, true, true,  {0}  }, // 986
  { "TRCACVR4", { .raw_val = AARCH64_SYSREG_TRCACVR4 }, "TRCACVR4", { .raw_val = AARCH64_SYSREG_TRCACVR4 }, 0x8940, true, true,  {0}  }, // 987
  { "TRCACVR5", { .raw_val = AARCH64_SYSREG_TRCACVR5 }, "TRCACVR5", { .raw_val = AARCH64_SYSREG_TRCACVR5 }, 0x8950, true, true,  {0}  }, // 988
  { "TRCACVR6", { .raw_val = AARCH64_SYSREG_TRCACVR6 }, "TRCACVR6", { .raw_val = AARCH64_SYSREG_TRCACVR6 }, 0x8960, true, true,  {0}  }, // 989
  { "TRCACVR7", { .raw_val = AARCH64_SYSREG_TRCACVR7 }, "TRCACVR7", { .raw_val = AARCH64_SYSREG_TRCACVR7 }, 0x8970, true, true,  {0}  }, // 990
  { "TRCACVR8", { .raw_val = AARCH64_SYSREG_TRCACVR8 }, "TRCACVR8", { .raw_val = AARCH64_SYSREG_TRCACVR8 }, 0x8901, true, true,  {0}  }, // 991
  { "TRCACVR9", { .raw_val = AARCH64_SYSREG_TRCACVR9 }, "TRCACVR9", { .raw_val = AARCH64_SYSREG_TRCACVR9 }, 0x8911, true, true,  {0}  }, // 992
  { "TRCAUTHSTATUS", { .raw_val = AARCH64_SYSREG_TRCAUTHSTATUS }, "TRCAUTHSTATUS", { .raw_val = AARCH64_SYSREG_TRCAUTHSTATUS }, 0x8BF6, true, false,  {0}  }, // 993
  { "TRCAUXCTLR", { .raw_val = AARCH64_SYSREG_TRCAUXCTLR }, "TRCAUXCTLR", { .raw_val = AARCH64_SYSREG_TRCAUXCTLR }, 0x8830, true, true,  {0}  }, // 994
  { "TRCBBCTLR", { .raw_val = AARCH64_SYSREG_TRCBBCTLR }, "TRCBBCTLR", { .raw_val = AARCH64_SYSREG_TRCBBCTLR }, 0x8878, true, true,  {0}  }, // 995
  { "TRCCCCTLR", { .raw_val = AARCH64_SYSREG_TRCCCCTLR }, "TRCCCCTLR", { .raw_val = AARCH64_SYSREG_TRCCCCTLR }, 0x8870, true, true,  {0}  }, // 996
  { "TRCCIDCCTLR0", { .raw_val = AARCH64_SYSREG_TRCCIDCCTLR0 }, "TRCCIDCCTLR0", { .raw_val = AARCH64_SYSREG_TRCCIDCCTLR0 }, 0x8982, true, true,  {0}  }, // 997
  { "TRCCIDCCTLR1", { .raw_val = AARCH64_SYSREG_TRCCIDCCTLR1 }, "TRCCIDCCTLR1", { .raw_val = AARCH64_SYSREG_TRCCIDCCTLR1 }, 0x898A, true, true,  {0}  }, // 998
  { "TRCCIDCVR0", { .raw_val = AARCH64_SYSREG_TRCCIDCVR0 }, "TRCCIDCVR0", { .raw_val = AARCH64_SYSREG_TRCCIDCVR0 }, 0x8980, true, true,  {0}  }, // 999
  { "TRCCIDCVR1", { .raw_val = AARCH64_SYSREG_TRCCIDCVR1 }, "TRCCIDCVR1", { .raw_val = AARCH64_SYSREG_TRCCIDCVR1 }, 0x8990, true, true,  {0}  }, // 1000
  { "TRCCIDCVR2", { .raw_val = AARCH64_SYSREG_TRCCIDCVR2 }, "TRCCIDCVR2", { .raw_val = AARCH64_SYSREG_TRCCIDCVR2 }, 0x89A0, true, true,  {0}  }, // 1001
  { "TRCCIDCVR3", { .raw_val = AARCH64_SYSREG_TRCCIDCVR3 }, "TRCCIDCVR3", { .raw_val = AARCH64_SYSREG_TRCCIDCVR3 }, 0x89B0, true, true,  {0}  }, // 1002
  { "TRCCIDCVR4", { .raw_val = AARCH64_SYSREG_TRCCIDCVR4 }, "TRCCIDCVR4", { .raw_val = AARCH64_SYSREG_TRCCIDCVR4 }, 0x89C0, true, true,  {0}  }, // 1003
  { "TRCCIDCVR5", { .raw_val = AARCH64_SYSREG_TRCCIDCVR5 }, "TRCCIDCVR5", { .raw_val = AARCH64_SYSREG_TRCCIDCVR5 }, 0x89D0, true, true,  {0}  }, // 1004
  { "TRCCIDCVR6", { .raw_val = AARCH64_SYSREG_TRCCIDCVR6 }, "TRCCIDCVR6", { .raw_val = AARCH64_SYSREG_TRCCIDCVR6 }, 0x89E0, true, true,  {0}  }, // 1005
  { "TRCCIDCVR7", { .raw_val = AARCH64_SYSREG_TRCCIDCVR7 }, "TRCCIDCVR7", { .raw_val = AARCH64_SYSREG_TRCCIDCVR7 }, 0x89F0, true, true,  {0}  }, // 1006
  { "TRCCIDR0", { .raw_val = AARCH64_SYSREG_TRCCIDR0 }, "TRCCIDR0", { .raw_val = AARCH64_SYSREG_TRCCIDR0 }, 0x8BE7, true, false,  {0}  }, // 1007
  { "TRCCIDR1", { .raw_val = AARCH64_SYSREG_TRCCIDR1 }, "TRCCIDR1", { .raw_val = AARCH64_SYSREG_TRCCIDR1 }, 0x8BEF, true, false,  {0}  }, // 1008
  { "TRCCIDR2", { .raw_val = AARCH64_SYSREG_TRCCIDR2 }, "TRCCIDR2", { .raw_val = AARCH64_SYSREG_TRCCIDR2 }, 0x8BF7, true, false,  {0}  }, // 1009
  { "TRCCIDR3", { .raw_val = AARCH64_SYSREG_TRCCIDR3 }, "TRCCIDR3", { .raw_val = AARCH64_SYSREG_TRCCIDR3 }, 0x8BFF, true, false,  {0}  }, // 1010
  { "TRCCLAIMCLR", { .raw_val = AARCH64_SYSREG_TRCCLAIMCLR }, "TRCCLAIMCLR", { .raw_val = AARCH64_SYSREG_TRCCLAIMCLR }, 0x8BCE, true, true,  {0}  }, // 1011
  { "TRCCLAIMSET", { .raw_val = AARCH64_SYSREG_TRCCLAIMSET }, "TRCCLAIMSET", { .raw_val = AARCH64_SYSREG_TRCCLAIMSET }, 0x8BC6, true, true,  {0}  }, // 1012
  { "TRCCNTCTLR0", { .raw_val = AARCH64_SYSREG_TRCCNTCTLR0 }, "TRCCNTCTLR0", { .raw_val = AARCH64_SYSREG_TRCCNTCTLR0 }, 0x8825, true, true,  {0}  }, // 1013
  { "TRCCNTCTLR1", { .raw_val = AARCH64_SYSREG_TRCCNTCTLR1 }, "TRCCNTCTLR1", { .raw_val = AARCH64_SYSREG_TRCCNTCTLR1 }, 0x882D, true, true,  {0}  }, // 1014
  { "TRCCNTCTLR2", { .raw_val = AARCH64_SYSREG_TRCCNTCTLR2 }, "TRCCNTCTLR2", { .raw_val = AARCH64_SYSREG_TRCCNTCTLR2 }, 0x8835, true, true,  {0}  }, // 1015
  { "TRCCNTCTLR3", { .raw_val = AARCH64_SYSREG_TRCCNTCTLR3 }, "TRCCNTCTLR3", { .raw_val = AARCH64_SYSREG_TRCCNTCTLR3 }, 0x883D, true, true,  {0}  }, // 1016
  { "TRCCNTRLDVR0", { .raw_val = AARCH64_SYSREG_TRCCNTRLDVR0 }, "TRCCNTRLDVR0", { .raw_val = AARCH64_SYSREG_TRCCNTRLDVR0 }, 0x8805, true, true,  {0}  }, // 1017
  { "TRCCNTRLDVR1", { .raw_val = AARCH64_SYSREG_TRCCNTRLDVR1 }, "TRCCNTRLDVR1", { .raw_val = AARCH64_SYSREG_TRCCNTRLDVR1 }, 0x880D, true, true,  {0}  }, // 1018
  { "TRCCNTRLDVR2", { .raw_val = AARCH64_SYSREG_TRCCNTRLDVR2 }, "TRCCNTRLDVR2", { .raw_val = AARCH64_SYSREG_TRCCNTRLDVR2 }, 0x8815, true, true,  {0}  }, // 1019
  { "TRCCNTRLDVR3", { .raw_val = AARCH64_SYSREG_TRCCNTRLDVR3 }, "TRCCNTRLDVR3", { .raw_val = AARCH64_SYSREG_TRCCNTRLDVR3 }, 0x881D, true, true,  {0}  }, // 1020
  { "TRCCNTVR0", { .raw_val = AARCH64_SYSREG_TRCCNTVR0 }, "TRCCNTVR0", { .raw_val = AARCH64_SYSREG_TRCCNTVR0 }, 0x8845, true, true,  {0}  }, // 1021
  { "TRCCNTVR1", { .raw_val = AARCH64_SYSREG_TRCCNTVR1 }, "TRCCNTVR1", { .raw_val = AARCH64_SYSREG_TRCCNTVR1 }, 0x884D, true, true,  {0}  }, // 1022
  { "TRCCNTVR2", { .raw_val = AARCH64_SYSREG_TRCCNTVR2 }, "TRCCNTVR2", { .raw_val = AARCH64_SYSREG_TRCCNTVR2 }, 0x8855, true, true,  {0}  }, // 1023
  { "TRCCNTVR3", { .raw_val = AARCH64_SYSREG_TRCCNTVR3 }, "TRCCNTVR3", { .raw_val = AARCH64_SYSREG_TRCCNTVR3 }, 0x885D, true, true,  {0}  }, // 1024
  { "TRCCONFIGR", { .raw_val = AARCH64_SYSREG_TRCCONFIGR }, "TRCCONFIGR", { .raw_val = AARCH64_SYSREG_TRCCONFIGR }, 0x8820, true, true,  {0}  }, // 1025
  { "TRCDEVAFF0", { .raw_val = AARCH64_SYSREG_TRCDEVAFF0 }, "TRCDEVAFF0", { .raw_val = AARCH64_SYSREG_TRCDEVAFF0 }, 0x8BD6, true, false,  {0}  }, // 1026
  { "TRCDEVAFF1", { .raw_val = AARCH64_SYSREG_TRCDEVAFF1 }, "TRCDEVAFF1", { .raw_val = AARCH64_SYSREG_TRCDEVAFF1 }, 0x8BDE, true, false,  {0}  }, // 1027
  { "TRCDEVARCH", { .raw_val = AARCH64_SYSREG_TRCDEVARCH }, "TRCDEVARCH", { .raw_val = AARCH64_SYSREG_TRCDEVARCH }, 0x8BFE, true, false,  {0}  }, // 1028
  { "TRCDEVID", { .raw_val = AARCH64_SYSREG_TRCDEVID }, "TRCDEVID", { .raw_val = AARCH64_SYSREG_TRCDEVID }, 0x8B97, true, false,  {0}  }, // 1029
  { "TRCDEVTYPE", { .raw_val = AARCH64_SYSREG_TRCDEVTYPE }, "TRCDEVTYPE", { .raw_val = AARCH64_SYSREG_TRCDEVTYPE }, 0x8B9F, true, false,  {0}  }, // 1030
  { "TRCDVCMR0", { .raw_val = AARCH64_SYSREG_TRCDVCMR0 }, "TRCDVCMR0", { .raw_val = AARCH64_SYSREG_TRCDVCMR0 }, 0x8906, true, true,  {0}  }, // 1031
  { "TRCDVCMR1", { .raw_val = AARCH64_SYSREG_TRCDVCMR1 }, "TRCDVCMR1", { .raw_val = AARCH64_SYSREG_TRCDVCMR1 }, 0x8926, true, true,  {0}  }, // 1032
  { "TRCDVCMR2", { .raw_val = AARCH64_SYSREG_TRCDVCMR2 }, "TRCDVCMR2", { .raw_val = AARCH64_SYSREG_TRCDVCMR2 }, 0x8946, true, true,  {0}  }, // 1033
  { "TRCDVCMR3", { .raw_val = AARCH64_SYSREG_TRCDVCMR3 }, "TRCDVCMR3", { .raw_val = AARCH64_SYSREG_TRCDVCMR3 }, 0x8966, true, true,  {0}  }, // 1034
  { "TRCDVCMR4", { .raw_val = AARCH64_SYSREG_TRCDVCMR4 }, "TRCDVCMR4", { .raw_val = AARCH64_SYSREG_TRCDVCMR4 }, 0x8907, true, true,  {0}  }, // 1035
  { "TRCDVCMR5", { .raw_val = AARCH64_SYSREG_TRCDVCMR5 }, "TRCDVCMR5", { .raw_val = AARCH64_SYSREG_TRCDVCMR5 }, 0x8927, true, true,  {0}  }, // 1036
  { "TRCDVCMR6", { .raw_val = AARCH64_SYSREG_TRCDVCMR6 }, "TRCDVCMR6", { .raw_val = AARCH64_SYSREG_TRCDVCMR6 }, 0x8947, true, true,  {0}  }, // 1037
  { "TRCDVCMR7", { .raw_val = AARCH64_SYSREG_TRCDVCMR7 }, "TRCDVCMR7", { .raw_val = AARCH64_SYSREG_TRCDVCMR7 }, 0x8967, true, true,  {0}  }, // 1038
  { "TRCDVCVR0", { .raw_val = AARCH64_SYSREG_TRCDVCVR0 }, "TRCDVCVR0", { .raw_val = AARCH64_SYSREG_TRCDVCVR0 }, 0x8904, true, true,  {0}  }, // 1039
  { "TRCDVCVR1", { .raw_val = AARCH64_SYSREG_TRCDVCVR1 }, "TRCDVCVR1", { .raw_val = AARCH64_SYSREG_TRCDVCVR1 }, 0x8924, true, true,  {0}  }, // 1040
  { "TRCDVCVR2", { .raw_val = AARCH64_SYSREG_TRCDVCVR2 }, "TRCDVCVR2", { .raw_val = AARCH64_SYSREG_TRCDVCVR2 }, 0x8944, true, true,  {0}  }, // 1041
  { "TRCDVCVR3", { .raw_val = AARCH64_SYSREG_TRCDVCVR3 }, "TRCDVCVR3", { .raw_val = AARCH64_SYSREG_TRCDVCVR3 }, 0x8964, true, true,  {0}  }, // 1042
  { "TRCDVCVR4", { .raw_val = AARCH64_SYSREG_TRCDVCVR4 }, "TRCDVCVR4", { .raw_val = AARCH64_SYSREG_TRCDVCVR4 }, 0x8905, true, true,  {0}  }, // 1043
  { "TRCDVCVR5", { .raw_val = AARCH64_SYSREG_TRCDVCVR5 }, "TRCDVCVR5", { .raw_val = AARCH64_SYSREG_TRCDVCVR5 }, 0x8925, true, true,  {0}  }, // 1044
  { "TRCDVCVR6", { .raw_val = AARCH64_SYSREG_TRCDVCVR6 }, "TRCDVCVR6", { .raw_val = AARCH64_SYSREG_TRCDVCVR6 }, 0x8945, true, true,  {0}  }, // 1045
  { "TRCDVCVR7", { .raw_val = AARCH64_SYSREG_TRCDVCVR7 }, "TRCDVCVR7", { .raw_val = AARCH64_SYSREG_TRCDVCVR7 }, 0x8965, true, true,  {0}  }, // 1046
  { "TRCEVENTCTL0R", { .raw_val = AARCH64_SYSREG_TRCEVENTCTL0R }, "TRCEVENTCTL0R", { .raw_val = AARCH64_SYSREG_TRCEVENTCTL0R }, 0x8840, true, true,  {0}  }, // 1047
  { "TRCEVENTCTL1R", { .raw_val = AARCH64_SYSREG_TRCEVENTCTL1R }, "TRCEVENTCTL1R", { .raw_val = AARCH64_SYSREG_TRCEVENTCTL1R }, 0x8848, true, true,  {0}  }, // 1048
  { "TRCEXTINSELR", { .raw_val = AARCH64_SYSREG_TRCEXTINSELR }, "TRCEXTINSELR", { .raw_val = AARCH64_SYSREG_TRCEXTINSELR }, 0x8844, true, true,  {0}  }, // 1049
  { "TRCEXTINSELR0", { .raw_val = AARCH64_SYSREG_TRCEXTINSELR0 }, "TRCEXTINSELR0", { .raw_val = AARCH64_SYSREG_TRCEXTINSELR0 }, 0x8844, true, true,  {AArch64_FeatureETE}  }, // 1050
  { "TRCEXTINSELR1", { .raw_val = AARCH64_SYSREG_TRCEXTINSELR1 }, "TRCEXTINSELR1", { .raw_val = AARCH64_SYSREG_TRCEXTINSELR1 }, 0x884C, true, true,  {AArch64_FeatureETE}  }, // 1051
  { "TRCEXTINSELR2", { .raw_val = AARCH64_SYSREG_TRCEXTINSELR2 }, "TRCEXTINSELR2", { .raw_val = AARCH64_SYSREG_TRCEXTINSELR2 }, 0x8854, true, true,  {AArch64_FeatureETE}  }, // 1052
  { "TRCEXTINSELR3", { .raw_val = AARCH64_SYSREG_TRCEXTINSELR3 }, "TRCEXTINSELR3", { .raw_val = AARCH64_SYSREG_TRCEXTINSELR3 }, 0x885C, true, true,  {AArch64_FeatureETE}  }, // 1053
  { "TRCIDR0", { .raw_val = AARCH64_SYSREG_TRCIDR0 }, "TRCIDR0", { .raw_val = AARCH64_SYSREG_TRCIDR0 }, 0x8847, true, false,  {0}  }, // 1054
  { "TRCIDR1", { .raw_val = AARCH64_SYSREG_TRCIDR1 }, "TRCIDR1", { .raw_val = AARCH64_SYSREG_TRCIDR1 }, 0x884F, true, false,  {0}  }, // 1055
  { "TRCIDR10", { .raw_val = AARCH64_SYSREG_TRCIDR10 }, "TRCIDR10", { .raw_val = AARCH64_SYSREG_TRCIDR10 }, 0x8816, true, false,  {0}  }, // 1056
  { "TRCIDR11", { .raw_val = AARCH64_SYSREG_TRCIDR11 }, "TRCIDR11", { .raw_val = AARCH64_SYSREG_TRCIDR11 }, 0x881E, true, false,  {0}  }, // 1057
  { "TRCIDR12", { .raw_val = AARCH64_SYSREG_TRCIDR12 }, "TRCIDR12", { .raw_val = AARCH64_SYSREG_TRCIDR12 }, 0x8826, true, false,  {0}  }, // 1058
  { "TRCIDR13", { .raw_val = AARCH64_SYSREG_TRCIDR13 }, "TRCIDR13", { .raw_val = AARCH64_SYSREG_TRCIDR13 }, 0x882E, true, false,  {0}  }, // 1059
  { "TRCIDR2", { .raw_val = AARCH64_SYSREG_TRCIDR2 }, "TRCIDR2", { .raw_val = AARCH64_SYSREG_TRCIDR2 }, 0x8857, true, false,  {0}  }, // 1060
  { "TRCIDR3", { .raw_val = AARCH64_SYSREG_TRCIDR3 }, "TRCIDR3", { .raw_val = AARCH64_SYSREG_TRCIDR3 }, 0x885F, true, false,  {0}  }, // 1061
  { "TRCIDR4", { .raw_val = AARCH64_SYSREG_TRCIDR4 }, "TRCIDR4", { .raw_val = AARCH64_SYSREG_TRCIDR4 }, 0x8867, true, false,  {0}  }, // 1062
  { "TRCIDR5", { .raw_val = AARCH64_SYSREG_TRCIDR5 }, "TRCIDR5", { .raw_val = AARCH64_SYSREG_TRCIDR5 }, 0x886F, true, false,  {0}  }, // 1063
  { "TRCIDR6", { .raw_val = AARCH64_SYSREG_TRCIDR6 }, "TRCIDR6", { .raw_val = AARCH64_SYSREG_TRCIDR6 }, 0x8877, true, false,  {0}  }, // 1064
  { "TRCIDR7", { .raw_val = AARCH64_SYSREG_TRCIDR7 }, "TRCIDR7", { .raw_val = AARCH64_SYSREG_TRCIDR7 }, 0x887F, true, false,  {0}  }, // 1065
  { "TRCIDR8", { .raw_val = AARCH64_SYSREG_TRCIDR8 }, "TRCIDR8", { .raw_val = AARCH64_SYSREG_TRCIDR8 }, 0x8806, true, false,  {0}  }, // 1066
  { "TRCIDR9", { .raw_val = AARCH64_SYSREG_TRCIDR9 }, "TRCIDR9", { .raw_val = AARCH64_SYSREG_TRCIDR9 }, 0x880E, true, false,  {0}  }, // 1067
  { "TRCIMSPEC0", { .raw_val = AARCH64_SYSREG_TRCIMSPEC0 }, "TRCIMSPEC0", { .raw_val = AARCH64_SYSREG_TRCIMSPEC0 }, 0x8807, true, true,  {0}  }, // 1068
  { "TRCIMSPEC1", { .raw_val = AARCH64_SYSREG_TRCIMSPEC1 }, "TRCIMSPEC1", { .raw_val = AARCH64_SYSREG_TRCIMSPEC1 }, 0x880F, true, true,  {0}  }, // 1069
  { "TRCIMSPEC2", { .raw_val = AARCH64_SYSREG_TRCIMSPEC2 }, "TRCIMSPEC2", { .raw_val = AARCH64_SYSREG_TRCIMSPEC2 }, 0x8817, true, true,  {0}  }, // 1070
  { "TRCIMSPEC3", { .raw_val = AARCH64_SYSREG_TRCIMSPEC3 }, "TRCIMSPEC3", { .raw_val = AARCH64_SYSREG_TRCIMSPEC3 }, 0x881F, true, true,  {0}  }, // 1071
  { "TRCIMSPEC4", { .raw_val = AARCH64_SYSREG_TRCIMSPEC4 }, "TRCIMSPEC4", { .raw_val = AARCH64_SYSREG_TRCIMSPEC4 }, 0x8827, true, true,  {0}  }, // 1072
  { "TRCIMSPEC5", { .raw_val = AARCH64_SYSREG_TRCIMSPEC5 }, "TRCIMSPEC5", { .raw_val = AARCH64_SYSREG_TRCIMSPEC5 }, 0x882F, true, true,  {0}  }, // 1073
  { "TRCIMSPEC6", { .raw_val = AARCH64_SYSREG_TRCIMSPEC6 }, "TRCIMSPEC6", { .raw_val = AARCH64_SYSREG_TRCIMSPEC6 }, 0x8837, true, true,  {0}  }, // 1074
  { "TRCIMSPEC7", { .raw_val = AARCH64_SYSREG_TRCIMSPEC7 }, "TRCIMSPEC7", { .raw_val = AARCH64_SYSREG_TRCIMSPEC7 }, 0x883F, true, true,  {0}  }, // 1075
  { "TRCITCTRL", { .raw_val = AARCH64_SYSREG_TRCITCTRL }, "TRCITCTRL", { .raw_val = AARCH64_SYSREG_TRCITCTRL }, 0x8B84, true, true,  {0}  }, // 1076
  { "TRCITECR_EL1", { .raw_val = AARCH64_SYSREG_TRCITECR_EL1 }, "TRCITECR_EL1", { .raw_val = AARCH64_SYSREG_TRCITECR_EL1 }, 0xC093, true, true,  {AArch64_FeatureITE}  }, // 1077
  { "TRCITECR_EL12", { .raw_val = AARCH64_SYSREG_TRCITECR_EL12 }, "TRCITECR_EL12", { .raw_val = AARCH64_SYSREG_TRCITECR_EL12 }, 0xE893, true, true,  {AArch64_FeatureITE}  }, // 1078
  { "TRCITECR_EL2", { .raw_val = AARCH64_SYSREG_TRCITECR_EL2 }, "TRCITECR_EL2", { .raw_val = AARCH64_SYSREG_TRCITECR_EL2 }, 0xE093, true, true,  {AArch64_FeatureITE}  }, // 1079
  { "TRCITEEDCR", { .raw_val = AARCH64_SYSREG_TRCITEEDCR }, "TRCITEEDCR", { .raw_val = AARCH64_SYSREG_TRCITEEDCR }, 0x8811, true, true,  {AArch64_FeatureITE}  }, // 1080
  { "TRCLAR", { .raw_val = AARCH64_SYSREG_TRCLAR }, "TRCLAR", { .raw_val = AARCH64_SYSREG_TRCLAR }, 0x8BE6, false, true,  {0}  }, // 1081
  { "TRCLSR", { .raw_val = AARCH64_SYSREG_TRCLSR }, "TRCLSR", { .raw_val = AARCH64_SYSREG_TRCLSR }, 0x8BEE, true, false,  {0}  }, // 1082
  { "TRCOSLAR", { .raw_val = AARCH64_SYSREG_TRCOSLAR }, "TRCOSLAR", { .raw_val = AARCH64_SYSREG_TRCOSLAR }, 0x8884, false, true,  {0}  }, // 1083
  { "TRCOSLSR", { .raw_val = AARCH64_SYSREG_TRCOSLSR }, "TRCOSLSR", { .raw_val = AARCH64_SYSREG_TRCOSLSR }, 0x888C, true, false,  {0}  }, // 1084
  { "TRCPDCR", { .raw_val = AARCH64_SYSREG_TRCPDCR }, "TRCPDCR", { .raw_val = AARCH64_SYSREG_TRCPDCR }, 0x88A4, true, true,  {0}  }, // 1085
  { "TRCPDSR", { .raw_val = AARCH64_SYSREG_TRCPDSR }, "TRCPDSR", { .raw_val = AARCH64_SYSREG_TRCPDSR }, 0x88AC, true, false,  {0}  }, // 1086
  { "TRCPIDR0", { .raw_val = AARCH64_SYSREG_TRCPIDR0 }, "TRCPIDR0", { .raw_val = AARCH64_SYSREG_TRCPIDR0 }, 0x8BC7, true, false,  {0}  }, // 1087
  { "TRCPIDR1", { .raw_val = AARCH64_SYSREG_TRCPIDR1 }, "TRCPIDR1", { .raw_val = AARCH64_SYSREG_TRCPIDR1 }, 0x8BCF, true, false,  {0}  }, // 1088
  { "TRCPIDR2", { .raw_val = AARCH64_SYSREG_TRCPIDR2 }, "TRCPIDR2", { .raw_val = AARCH64_SYSREG_TRCPIDR2 }, 0x8BD7, true, false,  {0}  }, // 1089
  { "TRCPIDR3", { .raw_val = AARCH64_SYSREG_TRCPIDR3 }, "TRCPIDR3", { .raw_val = AARCH64_SYSREG_TRCPIDR3 }, 0x8BDF, true, false,  {0}  }, // 1090
  { "TRCPIDR4", { .raw_val = AARCH64_SYSREG_TRCPIDR4 }, "TRCPIDR4", { .raw_val = AARCH64_SYSREG_TRCPIDR4 }, 0x8BA7, true, false,  {0}  }, // 1091
  { "TRCPIDR5", { .raw_val = AARCH64_SYSREG_TRCPIDR5 }, "TRCPIDR5", { .raw_val = AARCH64_SYSREG_TRCPIDR5 }, 0x8BAF, true, false,  {0}  }, // 1092
  { "TRCPIDR6", { .raw_val = AARCH64_SYSREG_TRCPIDR6 }, "TRCPIDR6", { .raw_val = AARCH64_SYSREG_TRCPIDR6 }, 0x8BB7, true, false,  {0}  }, // 1093
  { "TRCPIDR7", { .raw_val = AARCH64_SYSREG_TRCPIDR7 }, "TRCPIDR7", { .raw_val = AARCH64_SYSREG_TRCPIDR7 }, 0x8BBF, true, false,  {0}  }, // 1094
  { "TRCPRGCTLR", { .raw_val = AARCH64_SYSREG_TRCPRGCTLR }, "TRCPRGCTLR", { .raw_val = AARCH64_SYSREG_TRCPRGCTLR }, 0x8808, true, true,  {0}  }, // 1095
  { "TRCPROCSELR", { .raw_val = AARCH64_SYSREG_TRCPROCSELR }, "TRCPROCSELR", { .raw_val = AARCH64_SYSREG_TRCPROCSELR }, 0x8810, true, true,  {0}  }, // 1096
  { "TRCQCTLR", { .raw_val = AARCH64_SYSREG_TRCQCTLR }, "TRCQCTLR", { .raw_val = AARCH64_SYSREG_TRCQCTLR }, 0x8809, true, true,  {0}  }, // 1097
  { "TRCRSCTLR10", { .raw_val = AARCH64_SYSREG_TRCRSCTLR10 }, "TRCRSCTLR10", { .raw_val = AARCH64_SYSREG_TRCRSCTLR10 }, 0x88D0, true, true,  {0}  }, // 1098
  { "TRCRSCTLR11", { .raw_val = AARCH64_SYSREG_TRCRSCTLR11 }, "TRCRSCTLR11", { .raw_val = AARCH64_SYSREG_TRCRSCTLR11 }, 0x88D8, true, true,  {0}  }, // 1099
  { "TRCRSCTLR12", { .raw_val = AARCH64_SYSREG_TRCRSCTLR12 }, "TRCRSCTLR12", { .raw_val = AARCH64_SYSREG_TRCRSCTLR12 }, 0x88E0, true, true,  {0}  }, // 1100
  { "TRCRSCTLR13", { .raw_val = AARCH64_SYSREG_TRCRSCTLR13 }, "TRCRSCTLR13", { .raw_val = AARCH64_SYSREG_TRCRSCTLR13 }, 0x88E8, true, true,  {0}  }, // 1101
  { "TRCRSCTLR14", { .raw_val = AARCH64_SYSREG_TRCRSCTLR14 }, "TRCRSCTLR14", { .raw_val = AARCH64_SYSREG_TRCRSCTLR14 }, 0x88F0, true, true,  {0}  }, // 1102
  { "TRCRSCTLR15", { .raw_val = AARCH64_SYSREG_TRCRSCTLR15 }, "TRCRSCTLR15", { .raw_val = AARCH64_SYSREG_TRCRSCTLR15 }, 0x88F8, true, true,  {0}  }, // 1103
  { "TRCRSCTLR16", { .raw_val = AARCH64_SYSREG_TRCRSCTLR16 }, "TRCRSCTLR16", { .raw_val = AARCH64_SYSREG_TRCRSCTLR16 }, 0x8881, true, true,  {0}  }, // 1104
  { "TRCRSCTLR17", { .raw_val = AARCH64_SYSREG_TRCRSCTLR17 }, "TRCRSCTLR17", { .raw_val = AARCH64_SYSREG_TRCRSCTLR17 }, 0x8889, true, true,  {0}  }, // 1105
  { "TRCRSCTLR18", { .raw_val = AARCH64_SYSREG_TRCRSCTLR18 }, "TRCRSCTLR18", { .raw_val = AARCH64_SYSREG_TRCRSCTLR18 }, 0x8891, true, true,  {0}  }, // 1106
  { "TRCRSCTLR19", { .raw_val = AARCH64_SYSREG_TRCRSCTLR19 }, "TRCRSCTLR19", { .raw_val = AARCH64_SYSREG_TRCRSCTLR19 }, 0x8899, true, true,  {0}  }, // 1107
  { "TRCRSCTLR2", { .raw_val = AARCH64_SYSREG_TRCRSCTLR2 }, "TRCRSCTLR2", { .raw_val = AARCH64_SYSREG_TRCRSCTLR2 }, 0x8890, true, true,  {0}  }, // 1108
  { "TRCRSCTLR20", { .raw_val = AARCH64_SYSREG_TRCRSCTLR20 }, "TRCRSCTLR20", { .raw_val = AARCH64_SYSREG_TRCRSCTLR20 }, 0x88A1, true, true,  {0}  }, // 1109
  { "TRCRSCTLR21", { .raw_val = AARCH64_SYSREG_TRCRSCTLR21 }, "TRCRSCTLR21", { .raw_val = AARCH64_SYSREG_TRCRSCTLR21 }, 0x88A9, true, true,  {0}  }, // 1110
  { "TRCRSCTLR22", { .raw_val = AARCH64_SYSREG_TRCRSCTLR22 }, "TRCRSCTLR22", { .raw_val = AARCH64_SYSREG_TRCRSCTLR22 }, 0x88B1, true, true,  {0}  }, // 1111
  { "TRCRSCTLR23", { .raw_val = AARCH64_SYSREG_TRCRSCTLR23 }, "TRCRSCTLR23", { .raw_val = AARCH64_SYSREG_TRCRSCTLR23 }, 0x88B9, true, true,  {0}  }, // 1112
  { "TRCRSCTLR24", { .raw_val = AARCH64_SYSREG_TRCRSCTLR24 }, "TRCRSCTLR24", { .raw_val = AARCH64_SYSREG_TRCRSCTLR24 }, 0x88C1, true, true,  {0}  }, // 1113
  { "TRCRSCTLR25", { .raw_val = AARCH64_SYSREG_TRCRSCTLR25 }, "TRCRSCTLR25", { .raw_val = AARCH64_SYSREG_TRCRSCTLR25 }, 0x88C9, true, true,  {0}  }, // 1114
  { "TRCRSCTLR26", { .raw_val = AARCH64_SYSREG_TRCRSCTLR26 }, "TRCRSCTLR26", { .raw_val = AARCH64_SYSREG_TRCRSCTLR26 }, 0x88D1, true, true,  {0}  }, // 1115
  { "TRCRSCTLR27", { .raw_val = AARCH64_SYSREG_TRCRSCTLR27 }, "TRCRSCTLR27", { .raw_val = AARCH64_SYSREG_TRCRSCTLR27 }, 0x88D9, true, true,  {0}  }, // 1116
  { "TRCRSCTLR28", { .raw_val = AARCH64_SYSREG_TRCRSCTLR28 }, "TRCRSCTLR28", { .raw_val = AARCH64_SYSREG_TRCRSCTLR28 }, 0x88E1, true, true,  {0}  }, // 1117
  { "TRCRSCTLR29", { .raw_val = AARCH64_SYSREG_TRCRSCTLR29 }, "TRCRSCTLR29", { .raw_val = AARCH64_SYSREG_TRCRSCTLR29 }, 0x88E9, true, true,  {0}  }, // 1118
  { "TRCRSCTLR3", { .raw_val = AARCH64_SYSREG_TRCRSCTLR3 }, "TRCRSCTLR3", { .raw_val = AARCH64_SYSREG_TRCRSCTLR3 }, 0x8898, true, true,  {0}  }, // 1119
  { "TRCRSCTLR30", { .raw_val = AARCH64_SYSREG_TRCRSCTLR30 }, "TRCRSCTLR30", { .raw_val = AARCH64_SYSREG_TRCRSCTLR30 }, 0x88F1, true, true,  {0}  }, // 1120
  { "TRCRSCTLR31", { .raw_val = AARCH64_SYSREG_TRCRSCTLR31 }, "TRCRSCTLR31", { .raw_val = AARCH64_SYSREG_TRCRSCTLR31 }, 0x88F9, true, true,  {0}  }, // 1121
  { "TRCRSCTLR4", { .raw_val = AARCH64_SYSREG_TRCRSCTLR4 }, "TRCRSCTLR4", { .raw_val = AARCH64_SYSREG_TRCRSCTLR4 }, 0x88A0, true, true,  {0}  }, // 1122
  { "TRCRSCTLR5", { .raw_val = AARCH64_SYSREG_TRCRSCTLR5 }, "TRCRSCTLR5", { .raw_val = AARCH64_SYSREG_TRCRSCTLR5 }, 0x88A8, true, true,  {0}  }, // 1123
  { "TRCRSCTLR6", { .raw_val = AARCH64_SYSREG_TRCRSCTLR6 }, "TRCRSCTLR6", { .raw_val = AARCH64_SYSREG_TRCRSCTLR6 }, 0x88B0, true, true,  {0}  }, // 1124
  { "TRCRSCTLR7", { .raw_val = AARCH64_SYSREG_TRCRSCTLR7 }, "TRCRSCTLR7", { .raw_val = AARCH64_SYSREG_TRCRSCTLR7 }, 0x88B8, true, true,  {0}  }, // 1125
  { "TRCRSCTLR8", { .raw_val = AARCH64_SYSREG_TRCRSCTLR8 }, "TRCRSCTLR8", { .raw_val = AARCH64_SYSREG_TRCRSCTLR8 }, 0x88C0, true, true,  {0}  }, // 1126
  { "TRCRSCTLR9", { .raw_val = AARCH64_SYSREG_TRCRSCTLR9 }, "TRCRSCTLR9", { .raw_val = AARCH64_SYSREG_TRCRSCTLR9 }, 0x88C8, true, true,  {0}  }, // 1127
  { "TRCRSR", { .raw_val = AARCH64_SYSREG_TRCRSR }, "TRCRSR", { .raw_val = AARCH64_SYSREG_TRCRSR }, 0x8850, true, true,  {AArch64_FeatureETE}  }, // 1128
  { "TRCSEQEVR0", { .raw_val = AARCH64_SYSREG_TRCSEQEVR0 }, "TRCSEQEVR0", { .raw_val = AARCH64_SYSREG_TRCSEQEVR0 }, 0x8804, true, true,  {0}  }, // 1129
  { "TRCSEQEVR1", { .raw_val = AARCH64_SYSREG_TRCSEQEVR1 }, "TRCSEQEVR1", { .raw_val = AARCH64_SYSREG_TRCSEQEVR1 }, 0x880C, true, true,  {0}  }, // 1130
  { "TRCSEQEVR2", { .raw_val = AARCH64_SYSREG_TRCSEQEVR2 }, "TRCSEQEVR2", { .raw_val = AARCH64_SYSREG_TRCSEQEVR2 }, 0x8814, true, true,  {0}  }, // 1131
  { "TRCSEQRSTEVR", { .raw_val = AARCH64_SYSREG_TRCSEQRSTEVR }, "TRCSEQRSTEVR", { .raw_val = AARCH64_SYSREG_TRCSEQRSTEVR }, 0x8834, true, true,  {0}  }, // 1132
  { "TRCSEQSTR", { .raw_val = AARCH64_SYSREG_TRCSEQSTR }, "TRCSEQSTR", { .raw_val = AARCH64_SYSREG_TRCSEQSTR }, 0x883C, true, true,  {0}  }, // 1133
  { "TRCSSCCR0", { .raw_val = AARCH64_SYSREG_TRCSSCCR0 }, "TRCSSCCR0", { .raw_val = AARCH64_SYSREG_TRCSSCCR0 }, 0x8882, true, true,  {0}  }, // 1134
  { "TRCSSCCR1", { .raw_val = AARCH64_SYSREG_TRCSSCCR1 }, "TRCSSCCR1", { .raw_val = AARCH64_SYSREG_TRCSSCCR1 }, 0x888A, true, true,  {0}  }, // 1135
  { "TRCSSCCR2", { .raw_val = AARCH64_SYSREG_TRCSSCCR2 }, "TRCSSCCR2", { .raw_val = AARCH64_SYSREG_TRCSSCCR2 }, 0x8892, true, true,  {0}  }, // 1136
  { "TRCSSCCR3", { .raw_val = AARCH64_SYSREG_TRCSSCCR3 }, "TRCSSCCR3", { .raw_val = AARCH64_SYSREG_TRCSSCCR3 }, 0x889A, true, true,  {0}  }, // 1137
  { "TRCSSCCR4", { .raw_val = AARCH64_SYSREG_TRCSSCCR4 }, "TRCSSCCR4", { .raw_val = AARCH64_SYSREG_TRCSSCCR4 }, 0x88A2, true, true,  {0}  }, // 1138
  { "TRCSSCCR5", { .raw_val = AARCH64_SYSREG_TRCSSCCR5 }, "TRCSSCCR5", { .raw_val = AARCH64_SYSREG_TRCSSCCR5 }, 0x88AA, true, true,  {0}  }, // 1139
  { "TRCSSCCR6", { .raw_val = AARCH64_SYSREG_TRCSSCCR6 }, "TRCSSCCR6", { .raw_val = AARCH64_SYSREG_TRCSSCCR6 }, 0x88B2, true, true,  {0}  }, // 1140
  { "TRCSSCCR7", { .raw_val = AARCH64_SYSREG_TRCSSCCR7 }, "TRCSSCCR7", { .raw_val = AARCH64_SYSREG_TRCSSCCR7 }, 0x88BA, true, true,  {0}  }, // 1141
  { "TRCSSCSR0", { .raw_val = AARCH64_SYSREG_TRCSSCSR0 }, "TRCSSCSR0", { .raw_val = AARCH64_SYSREG_TRCSSCSR0 }, 0x88C2, true, true,  {0}  }, // 1142
  { "TRCSSCSR1", { .raw_val = AARCH64_SYSREG_TRCSSCSR1 }, "TRCSSCSR1", { .raw_val = AARCH64_SYSREG_TRCSSCSR1 }, 0x88CA, true, true,  {0}  }, // 1143
  { "TRCSSCSR2", { .raw_val = AARCH64_SYSREG_TRCSSCSR2 }, "TRCSSCSR2", { .raw_val = AARCH64_SYSREG_TRCSSCSR2 }, 0x88D2, true, true,  {0}  }, // 1144
  { "TRCSSCSR3", { .raw_val = AARCH64_SYSREG_TRCSSCSR3 }, "TRCSSCSR3", { .raw_val = AARCH64_SYSREG_TRCSSCSR3 }, 0x88DA, true, true,  {0}  }, // 1145
  { "TRCSSCSR4", { .raw_val = AARCH64_SYSREG_TRCSSCSR4 }, "TRCSSCSR4", { .raw_val = AARCH64_SYSREG_TRCSSCSR4 }, 0x88E2, true, true,  {0}  }, // 1146
  { "TRCSSCSR5", { .raw_val = AARCH64_SYSREG_TRCSSCSR5 }, "TRCSSCSR5", { .raw_val = AARCH64_SYSREG_TRCSSCSR5 }, 0x88EA, true, true,  {0}  }, // 1147
  { "TRCSSCSR6", { .raw_val = AARCH64_SYSREG_TRCSSCSR6 }, "TRCSSCSR6", { .raw_val = AARCH64_SYSREG_TRCSSCSR6 }, 0x88F2, true, true,  {0}  }, // 1148
  { "TRCSSCSR7", { .raw_val = AARCH64_SYSREG_TRCSSCSR7 }, "TRCSSCSR7", { .raw_val = AARCH64_SYSREG_TRCSSCSR7 }, 0x88FA, true, true,  {0}  }, // 1149
  { "TRCSSPCICR0", { .raw_val = AARCH64_SYSREG_TRCSSPCICR0 }, "TRCSSPCICR0", { .raw_val = AARCH64_SYSREG_TRCSSPCICR0 }, 0x8883, true, true,  {0}  }, // 1150
  { "TRCSSPCICR1", { .raw_val = AARCH64_SYSREG_TRCSSPCICR1 }, "TRCSSPCICR1", { .raw_val = AARCH64_SYSREG_TRCSSPCICR1 }, 0x888B, true, true,  {0}  }, // 1151
  { "TRCSSPCICR2", { .raw_val = AARCH64_SYSREG_TRCSSPCICR2 }, "TRCSSPCICR2", { .raw_val = AARCH64_SYSREG_TRCSSPCICR2 }, 0x8893, true, true,  {0}  }, // 1152
  { "TRCSSPCICR3", { .raw_val = AARCH64_SYSREG_TRCSSPCICR3 }, "TRCSSPCICR3", { .raw_val = AARCH64_SYSREG_TRCSSPCICR3 }, 0x889B, true, true,  {0}  }, // 1153
  { "TRCSSPCICR4", { .raw_val = AARCH64_SYSREG_TRCSSPCICR4 }, "TRCSSPCICR4", { .raw_val = AARCH64_SYSREG_TRCSSPCICR4 }, 0x88A3, true, true,  {0}  }, // 1154
  { "TRCSSPCICR5", { .raw_val = AARCH64_SYSREG_TRCSSPCICR5 }, "TRCSSPCICR5", { .raw_val = AARCH64_SYSREG_TRCSSPCICR5 }, 0x88AB, true, true,  {0}  }, // 1155
  { "TRCSSPCICR6", { .raw_val = AARCH64_SYSREG_TRCSSPCICR6 }, "TRCSSPCICR6", { .raw_val = AARCH64_SYSREG_TRCSSPCICR6 }, 0x88B3, true, true,  {0}  }, // 1156
  { "TRCSSPCICR7", { .raw_val = AARCH64_SYSREG_TRCSSPCICR7 }, "TRCSSPCICR7", { .raw_val = AARCH64_SYSREG_TRCSSPCICR7 }, 0x88BB, true, true,  {0}  }, // 1157
  { "TRCSTALLCTLR", { .raw_val = AARCH64_SYSREG_TRCSTALLCTLR }, "TRCSTALLCTLR", { .raw_val = AARCH64_SYSREG_TRCSTALLCTLR }, 0x8858, true, true,  {0}  }, // 1158
  { "TRCSTATR", { .raw_val = AARCH64_SYSREG_TRCSTATR }, "TRCSTATR", { .raw_val = AARCH64_SYSREG_TRCSTATR }, 0x8818, true, false,  {0}  }, // 1159
  { "TRCSYNCPR", { .raw_val = AARCH64_SYSREG_TRCSYNCPR }, "TRCSYNCPR", { .raw_val = AARCH64_SYSREG_TRCSYNCPR }, 0x8868, true, true,  {0}  }, // 1160
  { "TRCTRACEIDR", { .raw_val = AARCH64_SYSREG_TRCTRACEIDR }, "TRCTRACEIDR", { .raw_val = AARCH64_SYSREG_TRCTRACEIDR }, 0x8801, true, true,  {0}  }, // 1161
  { "TRCTSCTLR", { .raw_val = AARCH64_SYSREG_TRCTSCTLR }, "TRCTSCTLR", { .raw_val = AARCH64_SYSREG_TRCTSCTLR }, 0x8860, true, true,  {0}  }, // 1162
  { "TRCVDARCCTLR", { .raw_val = AARCH64_SYSREG_TRCVDARCCTLR }, "TRCVDARCCTLR", { .raw_val = AARCH64_SYSREG_TRCVDARCCTLR }, 0x8852, true, true,  {0}  }, // 1163
  { "TRCVDCTLR", { .raw_val = AARCH64_SYSREG_TRCVDCTLR }, "TRCVDCTLR", { .raw_val = AARCH64_SYSREG_TRCVDCTLR }, 0x8842, true, true,  {0}  }, // 1164
  { "TRCVDSACCTLR", { .raw_val = AARCH64_SYSREG_TRCVDSACCTLR }, "TRCVDSACCTLR", { .raw_val = AARCH64_SYSREG_TRCVDSACCTLR }, 0x884A, true, true,  {0}  }, // 1165
  { "TRCVICTLR", { .raw_val = AARCH64_SYSREG_TRCVICTLR }, "TRCVICTLR", { .raw_val = AARCH64_SYSREG_TRCVICTLR }, 0x8802, true, true,  {0}  }, // 1166
  { "TRCVIIECTLR", { .raw_val = AARCH64_SYSREG_TRCVIIECTLR }, "TRCVIIECTLR", { .raw_val = AARCH64_SYSREG_TRCVIIECTLR }, 0x880A, true, true,  {0}  }, // 1167
  { "TRCVIPCSSCTLR", { .raw_val = AARCH64_SYSREG_TRCVIPCSSCTLR }, "TRCVIPCSSCTLR", { .raw_val = AARCH64_SYSREG_TRCVIPCSSCTLR }, 0x881A, true, true,  {0}  }, // 1168
  { "TRCVISSCTLR", { .raw_val = AARCH64_SYSREG_TRCVISSCTLR }, "TRCVISSCTLR", { .raw_val = AARCH64_SYSREG_TRCVISSCTLR }, 0x8812, true, true,  {0}  }, // 1169
  { "TRCVMIDCCTLR0", { .raw_val = AARCH64_SYSREG_TRCVMIDCCTLR0 }, "TRCVMIDCCTLR0", { .raw_val = AARCH64_SYSREG_TRCVMIDCCTLR0 }, 0x8992, true, true,  {0}  }, // 1170
  { "TRCVMIDCCTLR1", { .raw_val = AARCH64_SYSREG_TRCVMIDCCTLR1 }, "TRCVMIDCCTLR1", { .raw_val = AARCH64_SYSREG_TRCVMIDCCTLR1 }, 0x899A, true, true,  {0}  }, // 1171
  { "TRCVMIDCVR0", { .raw_val = AARCH64_SYSREG_TRCVMIDCVR0 }, "TRCVMIDCVR0", { .raw_val = AARCH64_SYSREG_TRCVMIDCVR0 }, 0x8981, true, true,  {0}  }, // 1172
  { "TRCVMIDCVR1", { .raw_val = AARCH64_SYSREG_TRCVMIDCVR1 }, "TRCVMIDCVR1", { .raw_val = AARCH64_SYSREG_TRCVMIDCVR1 }, 0x8991, true, true,  {0}  }, // 1173
  { "TRCVMIDCVR2", { .raw_val = AARCH64_SYSREG_TRCVMIDCVR2 }, "TRCVMIDCVR2", { .raw_val = AARCH64_SYSREG_TRCVMIDCVR2 }, 0x89A1, true, true,  {0}  }, // 1174
  { "TRCVMIDCVR3", { .raw_val = AARCH64_SYSREG_TRCVMIDCVR3 }, "TRCVMIDCVR3", { .raw_val = AARCH64_SYSREG_TRCVMIDCVR3 }, 0x89B1, true, true,  {0}  }, // 1175
  { "TRCVMIDCVR4", { .raw_val = AARCH64_SYSREG_TRCVMIDCVR4 }, "TRCVMIDCVR4", { .raw_val = AARCH64_SYSREG_TRCVMIDCVR4 }, 0x89C1, true, true,  {0}  }, // 1176
  { "TRCVMIDCVR5", { .raw_val = AARCH64_SYSREG_TRCVMIDCVR5 }, "TRCVMIDCVR5", { .raw_val = AARCH64_SYSREG_TRCVMIDCVR5 }, 0x89D1, true, true,  {0}  }, // 1177
  { "TRCVMIDCVR6", { .raw_val = AARCH64_SYSREG_TRCVMIDCVR6 }, "TRCVMIDCVR6", { .raw_val = AARCH64_SYSREG_TRCVMIDCVR6 }, 0x89E1, true, true,  {0}  }, // 1178
  { "TRCVMIDCVR7", { .raw_val = AARCH64_SYSREG_TRCVMIDCVR7 }, "TRCVMIDCVR7", { .raw_val = AARCH64_SYSREG_TRCVMIDCVR7 }, 0x89F1, true, true,  {0}  }, // 1179
  { "TRFCR_EL1", { .raw_val = AARCH64_SYSREG_TRFCR_EL1 }, "TRFCR_EL1", { .raw_val = AARCH64_SYSREG_TRFCR_EL1 }, 0xC091, true, true,  {AArch64_FeatureTRACEV8_4}  }, // 1180
  { "TRFCR_EL12", { .raw_val = AARCH64_SYSREG_TRFCR_EL12 }, "TRFCR_EL12", { .raw_val = AARCH64_SYSREG_TRFCR_EL12 }, 0xE891, true, true,  {AArch64_FeatureTRACEV8_4}  }, // 1181
  { "TRFCR_EL2", { .raw_val = AARCH64_SYSREG_TRFCR_EL2 }, "TRFCR_EL2", { .raw_val = AARCH64_SYSREG_TRFCR_EL2 }, 0xE091, true, true,  {AArch64_FeatureTRACEV8_4}  }, // 1182
  { "TTBR0_EL1", { .raw_val = AARCH64_SYSREG_TTBR0_EL1 }, "TTBR0_EL1", { .raw_val = AARCH64_SYSREG_TTBR0_EL1 }, 0xC100, true, true,  {0}  }, // 1183
  { "TTBR0_EL12", { .raw_val = AARCH64_SYSREG_TTBR0_EL12 }, "TTBR0_EL12", { .raw_val = AARCH64_SYSREG_TTBR0_EL12 }, 0xE900, true, true,  {AArch64_FeatureVH}  }, // 1184
  { "TTBR0_EL2", { .raw_val = AARCH64_SYSREG_TTBR0_EL2 }, "VSCTLR_EL2", { .raw_val = AARCH64_SYSREG_VSCTLR_EL2 }, 0xE100, true, true,  {AArch64_FeatureEL2VMSA}  }, // 1185
  { "TTBR0_EL3", { .raw_val = AARCH64_SYSREG_TTBR0_EL3 }, "TTBR0_EL3", { .raw_val = AARCH64_SYSREG_TTBR0_EL3 }, 0xF100, true, true,  {0}  }, // 1186
  { "TTBR1_EL1", { .raw_val = AARCH64_SYSREG_TTBR1_EL1 }, "TTBR1_EL1", { .raw_val = AARCH64_SYSREG_TTBR1_EL1 }, 0xC101, true, true,  {0}  }, // 1187
  { "TTBR1_EL12", { .raw_val = AARCH64_SYSREG_TTBR1_EL12 }, "TTBR1_EL12", { .raw_val = AARCH64_SYSREG_TTBR1_EL12 }, 0xE901, true, true,  {AArch64_FeatureVH}  }, // 1188
  { "TTBR1_EL2", { .raw_val = AARCH64_SYSREG_TTBR1_EL2 }, "TTBR1_EL2", { .raw_val = AARCH64_SYSREG_TTBR1_EL2 }, 0xE101, true, true,  {AArch64_FeatureVH}  }, // 1189
  { "UAO", { .raw_val = AARCH64_SYSREG_UAO }, "UAO", { .raw_val = AARCH64_SYSREG_UAO }, 0xC214, true, true,  {AArch64_FeaturePsUAO}  }, // 1190
  { "VBAR_EL1", { .raw_val = AARCH64_SYSREG_VBAR_EL1 }, "VBAR_EL1", { .raw_val = AARCH64_SYSREG_VBAR_EL1 }, 0xC600, true, true,  {0}  }, // 1191
  { "VBAR_EL12", { .raw_val = AARCH64_SYSREG_VBAR_EL12 }, "VBAR_EL12", { .raw_val = AARCH64_SYSREG_VBAR_EL12 }, 0xEE00, true, true,  {AArch64_FeatureVH}  }, // 1192
  { "VBAR_EL2", { .raw_val = AARCH64_SYSREG_VBAR_EL2 }, "VBAR_EL2", { .raw_val = AARCH64_SYSREG_VBAR_EL2 }, 0xE600, true, true,  {0}  }, // 1193
  { "VBAR_EL3", { .raw_val = AARCH64_SYSREG_VBAR_EL3 }, "VBAR_EL3", { .raw_val = AARCH64_SYSREG_VBAR_EL3 }, 0xF600, true, true,  {0}  }, // 1194
  { "VDISR_EL2", { .raw_val = AARCH64_SYSREG_VDISR_EL2 }, "VDISR_EL2", { .raw_val = AARCH64_SYSREG_VDISR_EL2 }, 0xE609, true, true,  {AArch64_FeatureRAS}  }, // 1195
  { "VDISR_EL3", { .raw_val = AARCH64_SYSREG_VDISR_EL3 }, "VDISR_EL3", { .raw_val = AARCH64_SYSREG_VDISR_EL3 }, 0xF609, true, true,  {0}  }, // 1196
  { "VMECID_A_EL2", { .raw_val = AARCH64_SYSREG_VMECID_A_EL2 }, "VMECID_A_EL2", { .raw_val = AARCH64_SYSREG_VMECID_A_EL2 }, 0xE549, true, true,  {AArch64_FeatureMEC}  }, // 1197
  { "VMECID_P_EL2", { .raw_val = AARCH64_SYSREG_VMECID_P_EL2 }, "VMECID_P_EL2", { .raw_val = AARCH64_SYSREG_VMECID_P_EL2 }, 0xE548, true, true,  {AArch64_FeatureMEC}  }, // 1198
  { "VMPIDR_EL2", { .raw_val = AARCH64_SYSREG_VMPIDR_EL2 }, "VMPIDR_EL2", { .raw_val = AARCH64_SYSREG_VMPIDR_EL2 }, 0xE005, true, true,  {0}  }, // 1199
  { "VNCR_EL2", { .raw_val = AARCH64_SYSREG_VNCR_EL2 }, "VNCR_EL2", { .raw_val = AARCH64_SYSREG_VNCR_EL2 }, 0xE110, true, true,  {AArch64_FeatureNV}  }, // 1200
  { "VPIDR_EL2", { .raw_val = AARCH64_SYSREG_VPIDR_EL2 }, "VPIDR_EL2", { .raw_val = AARCH64_SYSREG_VPIDR_EL2 }, 0xE000, true, true,  {0}  }, // 1201
  { "VSCTLR_EL2", { .raw_val = AARCH64_SYSREG_VSCTLR_EL2 }, "TTBR0_EL2", { .raw_val = AARCH64_SYSREG_TTBR0_EL2 }, 0xE100, true, true,  {AArch64_HasV8_0rOps}  }, // 1202
  { "VSESR_EL2", { .raw_val = AARCH64_SYSREG_VSESR_EL2 }, "VSESR_EL2", { .raw_val = AARCH64_SYSREG_VSESR_EL2 }, 0xE293, true, true,  {AArch64_FeatureRAS}  }, // 1203
  { "VSESR_EL3", { .raw_val = AARCH64_SYSREG_VSESR_EL3 }, "VSESR_EL3", { .raw_val = AARCH64_SYSREG_VSESR_EL3 }, 0xF293, true, true,  {0}  }, // 1204
  { "VSTCR_EL2", { .raw_val = AARCH64_SYSREG_VSTCR_EL2 }, "VSTCR_EL2", { .raw_val = AARCH64_SYSREG_VSTCR_EL2 }, 0xE132, true, true,  {AArch64_FeatureSEL2}  }, // 1205
  { "VSTTBR_EL2", { .raw_val = AARCH64_SYSREG_VSTTBR_EL2 }, "VSTTBR_EL2", { .raw_val = AARCH64_SYSREG_VSTTBR_EL2 }, 0xE130, true, true,  {AArch64_HasV8_0aOps}  }, // 1206
  { "VTCR_EL2", { .raw_val = AARCH64_SYSREG_VTCR_EL2 }, "VTCR_EL2", { .raw_val = AARCH64_SYSREG_VTCR_EL2 }, 0xE10A, true, true,  {0}  }, // 1207
  { "VTTBR_EL2", { .raw_val = AARCH64_SYSREG_VTTBR_EL2 }, "VTTBR_EL2", { .raw_val = AARCH64_SYSREG_VTTBR_EL2 }, 0xE108, true, true,  {AArch64_FeatureEL2VMSA}  }, // 1208
  { "ZCR_EL1", { .raw_val = AARCH64_SYSREG_ZCR_EL1 }, "ZCR_EL1", { .raw_val = AARCH64_SYSREG_ZCR_EL1 }, 0xC090, true, true,  {AArch64_FeatureSVE}  }, // 1209
  { "ZCR_EL12", { .raw_val = AARCH64_SYSREG_ZCR_EL12 }, "ZCR_EL12", { .raw_val = AARCH64_SYSREG_ZCR_EL12 }, 0xE890, true, true,  {AArch64_FeatureSVE}  }, // 1210
  { "ZCR_EL2", { .raw_val = AARCH64_SYSREG_ZCR_EL2 }, "ZCR_EL2", { .raw_val = AARCH64_SYSREG_ZCR_EL2 }, 0xE090, true, true,  {AArch64_FeatureSVE}  }, // 1211
  { "ZCR_EL3", { .raw_val = AARCH64_SYSREG_ZCR_EL3 }, "ZCR_EL3", { .raw_val = AARCH64_SYSREG_ZCR_EL3 }, 0xF090, true, true,  {AArch64_FeatureSVE}  }, // 1212
  };

const AArch64SysReg_SysReg *AArch64SysReg_lookupSysRegByName(const char * Name) {
  static const struct IndexTypeStr Index[] = {
    { "ACCDATA_EL1", 0 },
    { "ACTLR_EL1", 1 },
    { "ACTLR_EL2", 2 },
    { "ACTLR_EL3", 3 },
    { "AFSR0_EL1", 4 },
    { "AFSR0_EL12", 5 },
    { "AFSR0_EL2", 6 },
    { "AFSR0_EL3", 7 },
    { "AFSR1_EL1", 8 },
    { "AFSR1_EL12", 9 },
    { "AFSR1_EL2", 10 },
    { "AFSR1_EL3", 11 },
    { "AIDR_EL1", 12 },
    { "ALLINT", 13 },
    { "AMAIR2_EL1", 14 },
    { "AMAIR2_EL12", 15 },
    { "AMAIR2_EL2", 16 },
    { "AMAIR2_EL3", 17 },
    { "AMAIR_EL1", 18 },
    { "AMAIR_EL12", 19 },
    { "AMAIR_EL2", 20 },
    { "AMAIR_EL3", 21 },
    { "AMCFGR_EL0", 22 },
    { "AMCG1IDR_EL0", 23 },
    { "AMCGCR_EL0", 24 },
    { "AMCNTENCLR0_EL0", 25 },
    { "AMCNTENCLR1_EL0", 26 },
    { "AMCNTENSET0_EL0", 27 },
    { "AMCNTENSET1_EL0", 28 },
    { "AMCR_EL0", 29 },
    { "AMEVCNTR00_EL0", 30 },
    { "AMEVCNTR01_EL0", 31 },
    { "AMEVCNTR02_EL0", 32 },
    { "AMEVCNTR03_EL0", 33 },
    { "AMEVCNTR10_EL0", 34 },
    { "AMEVCNTR110_EL0", 35 },
    { "AMEVCNTR111_EL0", 36 },
    { "AMEVCNTR112_EL0", 37 },
    { "AMEVCNTR113_EL0", 38 },
    { "AMEVCNTR114_EL0", 39 },
    { "AMEVCNTR115_EL0", 40 },
    { "AMEVCNTR11_EL0", 41 },
    { "AMEVCNTR12_EL0", 42 },
    { "AMEVCNTR13_EL0", 43 },
    { "AMEVCNTR14_EL0", 44 },
    { "AMEVCNTR15_EL0", 45 },
    { "AMEVCNTR16_EL0", 46 },
    { "AMEVCNTR17_EL0", 47 },
    { "AMEVCNTR18_EL0", 48 },
    { "AMEVCNTR19_EL0", 49 },
    { "AMEVCNTVOFF00_EL2", 50 },
    { "AMEVCNTVOFF010_EL2", 51 },
    { "AMEVCNTVOFF011_EL2", 52 },
    { "AMEVCNTVOFF012_EL2", 53 },
    { "AMEVCNTVOFF013_EL2", 54 },
    { "AMEVCNTVOFF014_EL2", 55 },
    { "AMEVCNTVOFF015_EL2", 56 },
    { "AMEVCNTVOFF01_EL2", 57 },
    { "AMEVCNTVOFF02_EL2", 58 },
    { "AMEVCNTVOFF03_EL2", 59 },
    { "AMEVCNTVOFF04_EL2", 60 },
    { "AMEVCNTVOFF05_EL2", 61 },
    { "AMEVCNTVOFF06_EL2", 62 },
    { "AMEVCNTVOFF07_EL2", 63 },
    { "AMEVCNTVOFF08_EL2", 64 },
    { "AMEVCNTVOFF09_EL2", 65 },
    { "AMEVCNTVOFF10_EL2", 66 },
    { "AMEVCNTVOFF110_EL2", 67 },
    { "AMEVCNTVOFF111_EL2", 68 },
    { "AMEVCNTVOFF112_EL2", 69 },
    { "AMEVCNTVOFF113_EL2", 70 },
    { "AMEVCNTVOFF114_EL2", 71 },
    { "AMEVCNTVOFF115_EL2", 72 },
    { "AMEVCNTVOFF11_EL2", 73 },
    { "AMEVCNTVOFF12_EL2", 74 },
    { "AMEVCNTVOFF13_EL2", 75 },
    { "AMEVCNTVOFF14_EL2", 76 },
    { "AMEVCNTVOFF15_EL2", 77 },
    { "AMEVCNTVOFF16_EL2", 78 },
    { "AMEVCNTVOFF17_EL2", 79 },
    { "AMEVCNTVOFF18_EL2", 80 },
    { "AMEVCNTVOFF19_EL2", 81 },
    { "AMEVTYPER00_EL0", 82 },
    { "AMEVTYPER01_EL0", 83 },
    { "AMEVTYPER02_EL0", 84 },
    { "AMEVTYPER03_EL0", 85 },
    { "AMEVTYPER10_EL0", 86 },
    { "AMEVTYPER110_EL0", 87 },
    { "AMEVTYPER111_EL0", 88 },
    { "AMEVTYPER112_EL0", 89 },
    { "AMEVTYPER113_EL0", 90 },
    { "AMEVTYPER114_EL0", 91 },
    { "AMEVTYPER115_EL0", 92 },
    { "AMEVTYPER11_EL0", 93 },
    { "AMEVTYPER12_EL0", 94 },
    { "AMEVTYPER13_EL0", 95 },
    { "AMEVTYPER14_EL0", 96 },
    { "AMEVTYPER15_EL0", 97 },
    { "AMEVTYPER16_EL0", 98 },
    { "AMEVTYPER17_EL0", 99 },
    { "AMEVTYPER18_EL0", 100 },
    { "AMEVTYPER19_EL0", 101 },
    { "AMUSERENR_EL0", 102 },
    { "APDAKEYHI_EL1", 103 },
    { "APDAKEYLO_EL1", 104 },
    { "APDBKEYHI_EL1", 105 },
    { "APDBKEYLO_EL1", 106 },
    { "APGAKEYHI_EL1", 107 },
    { "APGAKEYLO_EL1", 108 },
    { "APIAKEYHI_EL1", 109 },
    { "APIAKEYLO_EL1", 110 },
    { "APIBKEYHI_EL1", 111 },
    { "APIBKEYLO_EL1", 112 },
    { "BRBCR_EL1", 113 },
    { "BRBCR_EL12", 114 },
    { "BRBCR_EL2", 115 },
    { "BRBFCR_EL1", 116 },
    { "BRBIDR0_EL1", 117 },
    { "BRBINF0_EL1", 118 },
    { "BRBINF10_EL1", 119 },
    { "BRBINF11_EL1", 120 },
    { "BRBINF12_EL1", 121 },
    { "BRBINF13_EL1", 122 },
    { "BRBINF14_EL1", 123 },
    { "BRBINF15_EL1", 124 },
    { "BRBINF16_EL1", 125 },
    { "BRBINF17_EL1", 126 },
    { "BRBINF18_EL1", 127 },
    { "BRBINF19_EL1", 128 },
    { "BRBINF1_EL1", 129 },
    { "BRBINF20_EL1", 130 },
    { "BRBINF21_EL1", 131 },
    { "BRBINF22_EL1", 132 },
    { "BRBINF23_EL1", 133 },
    { "BRBINF24_EL1", 134 },
    { "BRBINF25_EL1", 135 },
    { "BRBINF26_EL1", 136 },
    { "BRBINF27_EL1", 137 },
    { "BRBINF28_EL1", 138 },
    { "BRBINF29_EL1", 139 },
    { "BRBINF2_EL1", 140 },
    { "BRBINF30_EL1", 141 },
    { "BRBINF31_EL1", 142 },
    { "BRBINF3_EL1", 143 },
    { "BRBINF4_EL1", 144 },
    { "BRBINF5_EL1", 145 },
    { "BRBINF6_EL1", 146 },
    { "BRBINF7_EL1", 147 },
    { "BRBINF8_EL1", 148 },
    { "BRBINF9_EL1", 149 },
    { "BRBINFINJ_EL1", 150 },
    { "BRBSRC0_EL1", 151 },
    { "BRBSRC10_EL1", 152 },
    { "BRBSRC11_EL1", 153 },
    { "BRBSRC12_EL1", 154 },
    { "BRBSRC13_EL1", 155 },
    { "BRBSRC14_EL1", 156 },
    { "BRBSRC15_EL1", 157 },
    { "BRBSRC16_EL1", 158 },
    { "BRBSRC17_EL1", 159 },
    { "BRBSRC18_EL1", 160 },
    { "BRBSRC19_EL1", 161 },
    { "BRBSRC1_EL1", 162 },
    { "BRBSRC20_EL1", 163 },
    { "BRBSRC21_EL1", 164 },
    { "BRBSRC22_EL1", 165 },
    { "BRBSRC23_EL1", 166 },
    { "BRBSRC24_EL1", 167 },
    { "BRBSRC25_EL1", 168 },
    { "BRBSRC26_EL1", 169 },
    { "BRBSRC27_EL1", 170 },
    { "BRBSRC28_EL1", 171 },
    { "BRBSRC29_EL1", 172 },
    { "BRBSRC2_EL1", 173 },
    { "BRBSRC30_EL1", 174 },
    { "BRBSRC31_EL1", 175 },
    { "BRBSRC3_EL1", 176 },
    { "BRBSRC4_EL1", 177 },
    { "BRBSRC5_EL1", 178 },
    { "BRBSRC6_EL1", 179 },
    { "BRBSRC7_EL1", 180 },
    { "BRBSRC8_EL1", 181 },
    { "BRBSRC9_EL1", 182 },
    { "BRBSRCINJ_EL1", 183 },
    { "BRBTGT0_EL1", 184 },
    { "BRBTGT10_EL1", 185 },
    { "BRBTGT11_EL1", 186 },
    { "BRBTGT12_EL1", 187 },
    { "BRBTGT13_EL1", 188 },
    { "BRBTGT14_EL1", 189 },
    { "BRBTGT15_EL1", 190 },
    { "BRBTGT16_EL1", 191 },
    { "BRBTGT17_EL1", 192 },
    { "BRBTGT18_EL1", 193 },
    { "BRBTGT19_EL1", 194 },
    { "BRBTGT1_EL1", 195 },
    { "BRBTGT20_EL1", 196 },
    { "BRBTGT21_EL1", 197 },
    { "BRBTGT22_EL1", 198 },
    { "BRBTGT23_EL1", 199 },
    { "BRBTGT24_EL1", 200 },
    { "BRBTGT25_EL1", 201 },
    { "BRBTGT26_EL1", 202 },
    { "BRBTGT27_EL1", 203 },
    { "BRBTGT28_EL1", 204 },
    { "BRBTGT29_EL1", 205 },
    { "BRBTGT2_EL1", 206 },
    { "BRBTGT30_EL1", 207 },
    { "BRBTGT31_EL1", 208 },
    { "BRBTGT3_EL1", 209 },
    { "BRBTGT4_EL1", 210 },
    { "BRBTGT5_EL1", 211 },
    { "BRBTGT6_EL1", 212 },
    { "BRBTGT7_EL1", 213 },
    { "BRBTGT8_EL1", 214 },
    { "BRBTGT9_EL1", 215 },
    { "BRBTGTINJ_EL1", 216 },
    { "BRBTS_EL1", 217 },
    { "CCSIDR2_EL1", 218 },
    { "CCSIDR_EL1", 219 },
    { "CLIDR_EL1", 220 },
    { "CNTFRQ_EL0", 221 },
    { "CNTHCTL_EL2", 222 },
    { "CNTHPS_CTL_EL2", 223 },
    { "CNTHPS_CVAL_EL2", 224 },
    { "CNTHPS_TVAL_EL2", 225 },
    { "CNTHP_CTL_EL2", 226 },
    { "CNTHP_CVAL_EL2", 227 },
    { "CNTHP_TVAL_EL2", 228 },
    { "CNTHVS_CTL_EL2", 229 },
    { "CNTHVS_CVAL_EL2", 230 },
    { "CNTHVS_TVAL_EL2", 231 },
    { "CNTHV_CTL_EL2", 232 },
    { "CNTHV_CVAL_EL2", 233 },
    { "CNTHV_TVAL_EL2", 234 },
    { "CNTISCALE_EL2", 235 },
    { "CNTKCTL_EL1", 236 },
    { "CNTKCTL_EL12", 237 },
    { "CNTPCTSS_EL0", 238 },
    { "CNTPCT_EL0", 239 },
    { "CNTPOFF_EL2", 240 },
    { "CNTPS_CTL_EL1", 241 },
    { "CNTPS_CVAL_EL1", 242 },
    { "CNTPS_TVAL_EL1", 243 },
    { "CNTP_CTL_EL0", 244 },
    { "CNTP_CTL_EL02", 245 },
    { "CNTP_CVAL_EL0", 246 },
    { "CNTP_CVAL_EL02", 247 },
    { "CNTP_TVAL_EL0", 248 },
    { "CNTP_TVAL_EL02", 249 },
    { "CNTSCALE_EL2", 250 },
    { "CNTVCTSS_EL0", 251 },
    { "CNTVCT_EL0", 252 },
    { "CNTVFRQ_EL2", 253 },
    { "CNTVOFF_EL2", 254 },
    { "CNTV_CTL_EL0", 255 },
    { "CNTV_CTL_EL02", 256 },
    { "CNTV_CVAL_EL0", 257 },
    { "CNTV_CVAL_EL02", 258 },
    { "CNTV_TVAL_EL0", 259 },
    { "CNTV_TVAL_EL02", 260 },
    { "CONTEXTIDR_EL1", 261 },
    { "CONTEXTIDR_EL12", 262 },
    { "CONTEXTIDR_EL2", 263 },
    { "CPACR_EL1", 264 },
    { "CPACR_EL12", 265 },
    { "CPM_IOACC_CTL_EL3", 266 },
    { "CPTR_EL2", 267 },
    { "CPTR_EL3", 268 },
    { "CSSELR_EL1", 269 },
    { "CTR_EL0", 270 },
    { "CURRENTEL", 271 },
    { "DACR32_EL2", 272 },
    { "DAIF", 273 },
    { "DBGAUTHSTATUS_EL1", 274 },
    { "DBGBCR0_EL1", 275 },
    { "DBGBCR10_EL1", 276 },
    { "DBGBCR11_EL1", 277 },
    { "DBGBCR12_EL1", 278 },
    { "DBGBCR13_EL1", 279 },
    { "DBGBCR14_EL1", 280 },
    { "DBGBCR15_EL1", 281 },
    { "DBGBCR1_EL1", 282 },
    { "DBGBCR2_EL1", 283 },
    { "DBGBCR3_EL1", 284 },
    { "DBGBCR4_EL1", 285 },
    { "DBGBCR5_EL1", 286 },
    { "DBGBCR6_EL1", 287 },
    { "DBGBCR7_EL1", 288 },
    { "DBGBCR8_EL1", 289 },
    { "DBGBCR9_EL1", 290 },
    { "DBGBVR0_EL1", 291 },
    { "DBGBVR10_EL1", 292 },
    { "DBGBVR11_EL1", 293 },
    { "DBGBVR12_EL1", 294 },
    { "DBGBVR13_EL1", 295 },
    { "DBGBVR14_EL1", 296 },
    { "DBGBVR15_EL1", 297 },
    { "DBGBVR1_EL1", 298 },
    { "DBGBVR2_EL1", 299 },
    { "DBGBVR3_EL1", 300 },
    { "DBGBVR4_EL1", 301 },
    { "DBGBVR5_EL1", 302 },
    { "DBGBVR6_EL1", 303 },
    { "DBGBVR7_EL1", 304 },
    { "DBGBVR8_EL1", 305 },
    { "DBGBVR9_EL1", 306 },
    { "DBGCLAIMCLR_EL1", 307 },
    { "DBGCLAIMSET_EL1", 308 },
    { "DBGDTRRX_EL0", 309 },
    { "DBGDTRTX_EL0", 310 },
    { "DBGDTR_EL0", 311 },
    { "DBGPRCR_EL1", 312 },
    { "DBGVCR32_EL2", 313 },
    { "DBGWCR0_EL1", 314 },
    { "DBGWCR10_EL1", 315 },
    { "DBGWCR11_EL1", 316 },
    { "DBGWCR12_EL1", 317 },
    { "DBGWCR13_EL1", 318 },
    { "DBGWCR14_EL1", 319 },
    { "DBGWCR15_EL1", 320 },
    { "DBGWCR1_EL1", 321 },
    { "DBGWCR2_EL1", 322 },
    { "DBGWCR3_EL1", 323 },
    { "DBGWCR4_EL1", 324 },
    { "DBGWCR5_EL1", 325 },
    { "DBGWCR6_EL1", 326 },
    { "DBGWCR7_EL1", 327 },
    { "DBGWCR8_EL1", 328 },
    { "DBGWCR9_EL1", 329 },
    { "DBGWVR0_EL1", 330 },
    { "DBGWVR10_EL1", 331 },
    { "DBGWVR11_EL1", 332 },
    { "DBGWVR12_EL1", 333 },
    { "DBGWVR13_EL1", 334 },
    { "DBGWVR14_EL1", 335 },
    { "DBGWVR15_EL1", 336 },
    { "DBGWVR1_EL1", 337 },
    { "DBGWVR2_EL1", 338 },
    { "DBGWVR3_EL1", 339 },
    { "DBGWVR4_EL1", 340 },
    { "DBGWVR5_EL1", 341 },
    { "DBGWVR6_EL1", 342 },
    { "DBGWVR7_EL1", 343 },
    { "DBGWVR8_EL1", 344 },
    { "DBGWVR9_EL1", 345 },
    { "DCZID_EL0", 346 },
    { "DISR_EL1", 347 },
    { "DIT", 348 },
    { "DLR_EL0", 349 },
    { "DSPSR_EL0", 350 },
    { "ELR_EL1", 351 },
    { "ELR_EL12", 352 },
    { "ELR_EL2", 353 },
    { "ELR_EL3", 354 },
    { "ERRIDR_EL1", 355 },
    { "ERRSELR_EL1", 356 },
    { "ERXADDR_EL1", 357 },
    { "ERXCTLR_EL1", 358 },
    { "ERXFR_EL1", 359 },
    { "ERXGSR_EL1", 360 },
    { "ERXMISC0_EL1", 361 },
    { "ERXMISC1_EL1", 362 },
    { "ERXMISC2_EL1", 363 },
    { "ERXMISC3_EL1", 364 },
    { "ERXPFGCDN_EL1", 365 },
    { "ERXPFGCTL_EL1", 366 },
    { "ERXPFGF_EL1", 367 },
    { "ERXSTATUS_EL1", 368 },
    { "ESR_EL1", 369 },
    { "ESR_EL12", 370 },
    { "ESR_EL2", 371 },
    { "ESR_EL3", 372 },
    { "FAR_EL1", 373 },
    { "FAR_EL12", 374 },
    { "FAR_EL2", 375 },
    { "FAR_EL3", 376 },
    { "FGWTE3_EL3", 377 },
    { "FPCR", 378 },
    { "FPEXC32_EL2", 379 },
    { "FPMR", 380 },
    { "FPSR", 381 },
    { "GCR_EL1", 382 },
    { "GCSCRE0_EL1", 383 },
    { "GCSCR_EL1", 384 },
    { "GCSCR_EL12", 385 },
    { "GCSCR_EL2", 386 },
    { "GCSCR_EL3", 387 },
    { "GCSPR_EL0", 388 },
    { "GCSPR_EL1", 389 },
    { "GCSPR_EL12", 390 },
    { "GCSPR_EL2", 391 },
    { "GCSPR_EL3", 392 },
    { "GMID_EL1", 393 },
    { "GPCCR_EL3", 394 },
    { "GPTBR_EL3", 395 },
    { "HACDBSBR_EL2", 396 },
    { "HACDBSCONS_EL2", 397 },
    { "HACR_EL2", 398 },
    { "HAFGRTR_EL2", 399 },
    { "HCRX_EL2", 400 },
    { "HCR_EL2", 401 },
    { "HDBSSBR_EL2", 402 },
    { "HDBSSPROD_EL2", 403 },
    { "HDFGRTR2_EL2", 404 },
    { "HDFGRTR_EL2", 405 },
    { "HDFGWTR2_EL2", 406 },
    { "HDFGWTR_EL2", 407 },
    { "HFGITR2_EL2", 408 },
    { "HFGITR_EL2", 409 },
    { "HFGRTR2_EL2", 410 },
    { "HFGRTR_EL2", 411 },
    { "HFGWTR2_EL2", 412 },
    { "HFGWTR_EL2", 413 },
    { "HPFAR_EL2", 414 },
    { "HSTR_EL2", 415 },
    { "ICC_AP0R0_EL1", 416 },
    { "ICC_AP0R1_EL1", 417 },
    { "ICC_AP0R2_EL1", 418 },
    { "ICC_AP0R3_EL1", 419 },
    { "ICC_AP1R0_EL1", 420 },
    { "ICC_AP1R1_EL1", 421 },
    { "ICC_AP1R2_EL1", 422 },
    { "ICC_AP1R3_EL1", 423 },
    { "ICC_ASGI1R_EL1", 424 },
    { "ICC_BPR0_EL1", 425 },
    { "ICC_BPR1_EL1", 426 },
    { "ICC_CTLR_EL1", 427 },
    { "ICC_CTLR_EL3", 428 },
    { "ICC_DIR_EL1", 429 },
    { "ICC_EOIR0_EL1", 430 },
    { "ICC_EOIR1_EL1", 431 },
    { "ICC_HPPIR0_EL1", 432 },
    { "ICC_HPPIR1_EL1", 433 },
    { "ICC_IAR0_EL1", 434 },
    { "ICC_IAR1_EL1", 435 },
    { "ICC_IGRPEN0_EL1", 436 },
    { "ICC_IGRPEN1_EL1", 437 },
    { "ICC_IGRPEN1_EL3", 438 },
    { "ICC_NMIAR1_EL1", 439 },
    { "ICC_PMR_EL1", 440 },
    { "ICC_RPR_EL1", 441 },
    { "ICC_SGI0R_EL1", 442 },
    { "ICC_SGI1R_EL1", 443 },
    { "ICC_SRE_EL1", 444 },
    { "ICC_SRE_EL2", 445 },
    { "ICC_SRE_EL3", 446 },
    { "ICH_AP0R0_EL2", 447 },
    { "ICH_AP0R1_EL2", 448 },
    { "ICH_AP0R2_EL2", 449 },
    { "ICH_AP0R3_EL2", 450 },
    { "ICH_AP1R0_EL2", 451 },
    { "ICH_AP1R1_EL2", 452 },
    { "ICH_AP1R2_EL2", 453 },
    { "ICH_AP1R3_EL2", 454 },
    { "ICH_EISR_EL2", 455 },
    { "ICH_ELRSR_EL2", 456 },
    { "ICH_HCR_EL2", 457 },
    { "ICH_LR0_EL2", 458 },
    { "ICH_LR10_EL2", 459 },
    { "ICH_LR11_EL2", 460 },
    { "ICH_LR12_EL2", 461 },
    { "ICH_LR13_EL2", 462 },
    { "ICH_LR14_EL2", 463 },
    { "ICH_LR15_EL2", 464 },
    { "ICH_LR1_EL2", 465 },
    { "ICH_LR2_EL2", 466 },
    { "ICH_LR3_EL2", 467 },
    { "ICH_LR4_EL2", 468 },
    { "ICH_LR5_EL2", 469 },
    { "ICH_LR6_EL2", 470 },
    { "ICH_LR7_EL2", 471 },
    { "ICH_LR8_EL2", 472 },
    { "ICH_LR9_EL2", 473 },
    { "ICH_MISR_EL2", 474 },
    { "ICH_VMCR_EL2", 475 },
    { "ICH_VTR_EL2", 476 },
    { "ID_AA64AFR0_EL1", 477 },
    { "ID_AA64AFR1_EL1", 478 },
    { "ID_AA64DFR0_EL1", 479 },
    { "ID_AA64DFR1_EL1", 480 },
    { "ID_AA64DFR2_EL1", 481 },
    { "ID_AA64FPFR0_EL1", 482 },
    { "ID_AA64ISAR0_EL1", 483 },
    { "ID_AA64ISAR1_EL1", 484 },
    { "ID_AA64ISAR2_EL1", 485 },
    { "ID_AA64ISAR3_EL1", 486 },
    { "ID_AA64MMFR0_EL1", 487 },
    { "ID_AA64MMFR1_EL1", 488 },
    { "ID_AA64MMFR2_EL1", 489 },
    { "ID_AA64MMFR3_EL1", 490 },
    { "ID_AA64MMFR4_EL1", 491 },
    { "ID_AA64PFR0_EL1", 492 },
    { "ID_AA64PFR1_EL1", 493 },
    { "ID_AA64PFR2_EL1", 494 },
    { "ID_AA64SMFR0_EL1", 495 },
    { "ID_AA64ZFR0_EL1", 496 },
    { "ID_AFR0_EL1", 497 },
    { "ID_DFR0_EL1", 498 },
    { "ID_DFR1_EL1", 499 },
    { "ID_ISAR0_EL1", 500 },
    { "ID_ISAR1_EL1", 501 },
    { "ID_ISAR2_EL1", 502 },
    { "ID_ISAR3_EL1", 503 },
    { "ID_ISAR4_EL1", 504 },
    { "ID_ISAR5_EL1", 505 },
    { "ID_ISAR6_EL1", 506 },
    { "ID_MMFR0_EL1", 507 },
    { "ID_MMFR1_EL1", 508 },
    { "ID_MMFR2_EL1", 509 },
    { "ID_MMFR3_EL1", 510 },
    { "ID_MMFR4_EL1", 511 },
    { "ID_MMFR5_EL1", 512 },
    { "ID_PFR0_EL1", 513 },
    { "ID_PFR1_EL1", 514 },
    { "ID_PFR2_EL1", 515 },
    { "IFSR32_EL2", 516 },
    { "ISR_EL1", 517 },
    { "LORC_EL1", 518 },
    { "LOREA_EL1", 519 },
    { "LORID_EL1", 520 },
    { "LORN_EL1", 521 },
    { "LORSA_EL1", 522 },
    { "MAIR2_EL1", 523 },
    { "MAIR2_EL12", 524 },
    { "MAIR2_EL2", 525 },
    { "MAIR2_EL3", 526 },
    { "MAIR_EL1", 527 },
    { "MAIR_EL12", 528 },
    { "MAIR_EL2", 529 },
    { "MAIR_EL3", 530 },
    { "MDCCINT_EL1", 531 },
    { "MDCCSR_EL0", 532 },
    { "MDCR_EL2", 533 },
    { "MDCR_EL3", 534 },
    { "MDRAR_EL1", 535 },
    { "MDSCR_EL1", 536 },
    { "MDSELR_EL1", 537 },
    { "MDSTEPOP_EL1", 538 },
    { "MECIDR_EL2", 539 },
    { "MECID_A0_EL2", 540 },
    { "MECID_A1_EL2", 541 },
    { "MECID_P0_EL2", 542 },
    { "MECID_P1_EL2", 543 },
    { "MECID_RL_A_EL3", 544 },
    { "MFAR_EL3", 545 },
    { "MIDR_EL1", 546 },
    { "MPAM0_EL1", 547 },
    { "MPAM1_EL1", 548 },
    { "MPAM1_EL12", 549 },
    { "MPAM2_EL2", 550 },
    { "MPAM3_EL3", 551 },
    { "MPAMHCR_EL2", 552 },
    { "MPAMIDR_EL1", 553 },
    { "MPAMSM_EL1", 554 },
    { "MPAMVPM0_EL2", 555 },
    { "MPAMVPM1_EL2", 556 },
    { "MPAMVPM2_EL2", 557 },
    { "MPAMVPM3_EL2", 558 },
    { "MPAMVPM4_EL2", 559 },
    { "MPAMVPM5_EL2", 560 },
    { "MPAMVPM6_EL2", 561 },
    { "MPAMVPM7_EL2", 562 },
    { "MPAMVPMV_EL2", 563 },
    { "MPIDR_EL1", 564 },
    { "MPUIR_EL1", 565 },
    { "MPUIR_EL2", 566 },
    { "MVFR0_EL1", 567 },
    { "MVFR1_EL1", 568 },
    { "MVFR2_EL1", 569 },
    { "NZCV", 570 },
    { "OSDLR_EL1", 571 },
    { "OSDTRRX_EL1", 572 },
    { "OSDTRTX_EL1", 573 },
    { "OSECCR_EL1", 574 },
    { "OSLAR_EL1", 575 },
    { "OSLSR_EL1", 576 },
    { "PAN", 577 },
    { "PAR_EL1", 578 },
    { "PFAR_EL1", 579 },
    { "PFAR_EL12", 580 },
    { "PFAR_EL2", 581 },
    { "PIRE0_EL1", 582 },
    { "PIRE0_EL12", 583 },
    { "PIRE0_EL2", 584 },
    { "PIR_EL1", 585 },
    { "PIR_EL12", 586 },
    { "PIR_EL2", 587 },
    { "PIR_EL3", 588 },
    { "PM", 589 },
    { "PMBIDR_EL1", 590 },
    { "PMBLIMITR_EL1", 591 },
    { "PMBPTR_EL1", 592 },
    { "PMBSR_EL1", 593 },
    { "PMCCFILTR_EL0", 594 },
    { "PMCCNTR_EL0", 595 },
    { "PMCCNTSVR_EL1", 596 },
    { "PMCEID0_EL0", 597 },
    { "PMCEID1_EL0", 598 },
    { "PMCNTENCLR_EL0", 599 },
    { "PMCNTENSET_EL0", 600 },
    { "PMCR_EL0", 601 },
    { "PMECR_EL1", 602 },
    { "PMEVCNTR0_EL0", 603 },
    { "PMEVCNTR10_EL0", 604 },
    { "PMEVCNTR11_EL0", 605 },
    { "PMEVCNTR12_EL0", 606 },
    { "PMEVCNTR13_EL0", 607 },
    { "PMEVCNTR14_EL0", 608 },
    { "PMEVCNTR15_EL0", 609 },
    { "PMEVCNTR16_EL0", 610 },
    { "PMEVCNTR17_EL0", 611 },
    { "PMEVCNTR18_EL0", 612 },
    { "PMEVCNTR19_EL0", 613 },
    { "PMEVCNTR1_EL0", 614 },
    { "PMEVCNTR20_EL0", 615 },
    { "PMEVCNTR21_EL0", 616 },
    { "PMEVCNTR22_EL0", 617 },
    { "PMEVCNTR23_EL0", 618 },
    { "PMEVCNTR24_EL0", 619 },
    { "PMEVCNTR25_EL0", 620 },
    { "PMEVCNTR26_EL0", 621 },
    { "PMEVCNTR27_EL0", 622 },
    { "PMEVCNTR28_EL0", 623 },
    { "PMEVCNTR29_EL0", 624 },
    { "PMEVCNTR2_EL0", 625 },
    { "PMEVCNTR30_EL0", 626 },
    { "PMEVCNTR3_EL0", 627 },
    { "PMEVCNTR4_EL0", 628 },
    { "PMEVCNTR5_EL0", 629 },
    { "PMEVCNTR6_EL0", 630 },
    { "PMEVCNTR7_EL0", 631 },
    { "PMEVCNTR8_EL0", 632 },
    { "PMEVCNTR9_EL0", 633 },
    { "PMEVCNTSVR0_EL1", 634 },
    { "PMEVCNTSVR10_EL1", 635 },
    { "PMEVCNTSVR11_EL1", 636 },
    { "PMEVCNTSVR12_EL1", 637 },
    { "PMEVCNTSVR13_EL1", 638 },
    { "PMEVCNTSVR14_EL1", 639 },
    { "PMEVCNTSVR15_EL1", 640 },
    { "PMEVCNTSVR16_EL1", 641 },
    { "PMEVCNTSVR17_EL1", 642 },
    { "PMEVCNTSVR18_EL1", 643 },
    { "PMEVCNTSVR19_EL1", 644 },
    { "PMEVCNTSVR1_EL1", 645 },
    { "PMEVCNTSVR20_EL1", 646 },
    { "PMEVCNTSVR21_EL1", 647 },
    { "PMEVCNTSVR22_EL1", 648 },
    { "PMEVCNTSVR23_EL1", 649 },
    { "PMEVCNTSVR24_EL1", 650 },
    { "PMEVCNTSVR25_EL1", 651 },
    { "PMEVCNTSVR26_EL1", 652 },
    { "PMEVCNTSVR27_EL1", 653 },
    { "PMEVCNTSVR28_EL1", 654 },
    { "PMEVCNTSVR29_EL1", 655 },
    { "PMEVCNTSVR2_EL1", 656 },
    { "PMEVCNTSVR30_EL1", 657 },
    { "PMEVCNTSVR3_EL1", 658 },
    { "PMEVCNTSVR4_EL1", 659 },
    { "PMEVCNTSVR5_EL1", 660 },
    { "PMEVCNTSVR6_EL1", 661 },
    { "PMEVCNTSVR7_EL1", 662 },
    { "PMEVCNTSVR8_EL1", 663 },
    { "PMEVCNTSVR9_EL1", 664 },
    { "PMEVTYPER0_EL0", 665 },
    { "PMEVTYPER10_EL0", 666 },
    { "PMEVTYPER11_EL0", 667 },
    { "PMEVTYPER12_EL0", 668 },
    { "PMEVTYPER13_EL0", 669 },
    { "PMEVTYPER14_EL0", 670 },
    { "PMEVTYPER15_EL0", 671 },
    { "PMEVTYPER16_EL0", 672 },
    { "PMEVTYPER17_EL0", 673 },
    { "PMEVTYPER18_EL0", 674 },
    { "PMEVTYPER19_EL0", 675 },
    { "PMEVTYPER1_EL0", 676 },
    { "PMEVTYPER20_EL0", 677 },
    { "PMEVTYPER21_EL0", 678 },
    { "PMEVTYPER22_EL0", 679 },
    { "PMEVTYPER23_EL0", 680 },
    { "PMEVTYPER24_EL0", 681 },
    { "PMEVTYPER25_EL0", 682 },
    { "PMEVTYPER26_EL0", 683 },
    { "PMEVTYPER27_EL0", 684 },
    { "PMEVTYPER28_EL0", 685 },
    { "PMEVTYPER29_EL0", 686 },
    { "PMEVTYPER2_EL0", 687 },
    { "PMEVTYPER30_EL0", 688 },
    { "PMEVTYPER3_EL0", 689 },
    { "PMEVTYPER4_EL0", 690 },
    { "PMEVTYPER5_EL0", 691 },
    { "PMEVTYPER6_EL0", 692 },
    { "PMEVTYPER7_EL0", 693 },
    { "PMEVTYPER8_EL0", 694 },
    { "PMEVTYPER9_EL0", 695 },
    { "PMIAR_EL1", 696 },
    { "PMICFILTR_EL0", 697 },
    { "PMICNTR_EL0", 698 },
    { "PMICNTSVR_EL1", 699 },
    { "PMINTENCLR_EL1", 700 },
    { "PMINTENSET_EL1", 701 },
    { "PMMIR_EL1", 702 },
    { "PMOVSCLR_EL0", 703 },
    { "PMOVSSET_EL0", 704 },
    { "PMSCR_EL1", 705 },
    { "PMSCR_EL12", 706 },
    { "PMSCR_EL2", 707 },
    { "PMSDSFR_EL1", 708 },
    { "PMSELR_EL0", 709 },
    { "PMSEVFR_EL1", 710 },
    { "PMSFCR_EL1", 711 },
    { "PMSICR_EL1", 712 },
    { "PMSIDR_EL1", 713 },
    { "PMSIRR_EL1", 714 },
    { "PMSLATFR_EL1", 715 },
    { "PMSNEVFR_EL1", 716 },
    { "PMSSCR_EL1", 717 },
    { "PMSWINC_EL0", 718 },
    { "PMUACR_EL1", 719 },
    { "PMUSERENR_EL0", 720 },
    { "PMXEVCNTR_EL0", 721 },
    { "PMXEVTYPER_EL0", 722 },
    { "PMZR_EL0", 723 },
    { "POR_EL0", 724 },
    { "POR_EL1", 725 },
    { "POR_EL12", 726 },
    { "POR_EL2", 727 },
    { "POR_EL3", 728 },
    { "PRBAR10_EL1", 729 },
    { "PRBAR10_EL2", 730 },
    { "PRBAR11_EL1", 731 },
    { "PRBAR11_EL2", 732 },
    { "PRBAR12_EL1", 733 },
    { "PRBAR12_EL2", 734 },
    { "PRBAR13_EL1", 735 },
    { "PRBAR13_EL2", 736 },
    { "PRBAR14_EL1", 737 },
    { "PRBAR14_EL2", 738 },
    { "PRBAR15_EL1", 739 },
    { "PRBAR15_EL2", 740 },
    { "PRBAR1_EL1", 741 },
    { "PRBAR1_EL2", 742 },
    { "PRBAR2_EL1", 743 },
    { "PRBAR2_EL2", 744 },
    { "PRBAR3_EL1", 745 },
    { "PRBAR3_EL2", 746 },
    { "PRBAR4_EL1", 747 },
    { "PRBAR4_EL2", 748 },
    { "PRBAR5_EL1", 749 },
    { "PRBAR5_EL2", 750 },
    { "PRBAR6_EL1", 751 },
    { "PRBAR6_EL2", 752 },
    { "PRBAR7_EL1", 753 },
    { "PRBAR7_EL2", 754 },
    { "PRBAR8_EL1", 755 },
    { "PRBAR8_EL2", 756 },
    { "PRBAR9_EL1", 757 },
    { "PRBAR9_EL2", 758 },
    { "PRBAR_EL1", 759 },
    { "PRBAR_EL2", 760 },
    { "PRENR_EL1", 761 },
    { "PRENR_EL2", 762 },
    { "PRLAR10_EL1", 763 },
    { "PRLAR10_EL2", 764 },
    { "PRLAR11_EL1", 765 },
    { "PRLAR11_EL2", 766 },
    { "PRLAR12_EL1", 767 },
    { "PRLAR12_EL2", 768 },
    { "PRLAR13_EL1", 769 },
    { "PRLAR13_EL2", 770 },
    { "PRLAR14_EL1", 771 },
    { "PRLAR14_EL2", 772 },
    { "PRLAR15_EL1", 773 },
    { "PRLAR15_EL2", 774 },
    { "PRLAR1_EL1", 775 },
    { "PRLAR1_EL2", 776 },
    { "PRLAR2_EL1", 777 },
    { "PRLAR2_EL2", 778 },
    { "PRLAR3_EL1", 779 },
    { "PRLAR3_EL2", 780 },
    { "PRLAR4_EL1", 781 },
    { "PRLAR4_EL2", 782 },
    { "PRLAR5_EL1", 783 },
    { "PRLAR5_EL2", 784 },
    { "PRLAR6_EL1", 785 },
    { "PRLAR6_EL2", 786 },
    { "PRLAR7_EL1", 787 },
    { "PRLAR7_EL2", 788 },
    { "PRLAR8_EL1", 789 },
    { "PRLAR8_EL2", 790 },
    { "PRLAR9_EL1", 791 },
    { "PRLAR9_EL2", 792 },
    { "PRLAR_EL1", 793 },
    { "PRLAR_EL2", 794 },
    { "PRSELR_EL1", 795 },
    { "PRSELR_EL2", 796 },
    { "RCWMASK_EL1", 797 },
    { "RCWSMASK_EL1", 798 },
    { "REVIDR_EL1", 799 },
    { "RGSR_EL1", 800 },
    { "RMR_EL1", 801 },
    { "RMR_EL2", 802 },
    { "RMR_EL3", 803 },
    { "RNDR", 804 },
    { "RNDRRS", 805 },
    { "RVBAR_EL1", 806 },
    { "RVBAR_EL2", 807 },
    { "RVBAR_EL3", 808 },
    { "S2PIR_EL2", 809 },
    { "S2POR_EL1", 810 },
    { "SCR_EL3", 811 },
    { "SCTLR2_EL1", 812 },
    { "SCTLR2_EL12", 813 },
    { "SCTLR2_EL2", 814 },
    { "SCTLR2_EL3", 815 },
    { "SCTLR_EL1", 816 },
    { "SCTLR_EL12", 817 },
    { "SCTLR_EL2", 818 },
    { "SCTLR_EL3", 819 },
    { "SCXTNUM_EL0", 820 },
    { "SCXTNUM_EL1", 821 },
    { "SCXTNUM_EL12", 822 },
    { "SCXTNUM_EL2", 823 },
    { "SCXTNUM_EL3", 824 },
    { "SDER32_EL2", 825 },
    { "SDER32_EL3", 826 },
    { "SMCR_EL1", 827 },
    { "SMCR_EL12", 828 },
    { "SMCR_EL2", 829 },
    { "SMCR_EL3", 830 },
    { "SMIDR_EL1", 831 },
    { "SMPRIMAP_EL2", 832 },
    { "SMPRI_EL1", 833 },
    { "SPMACCESSR_EL1", 834 },
    { "SPMACCESSR_EL12", 835 },
    { "SPMACCESSR_EL2", 836 },
    { "SPMACCESSR_EL3", 837 },
    { "SPMCFGR_EL1", 838 },
    { "SPMCGCR0_EL1", 839 },
    { "SPMCGCR1_EL1", 840 },
    { "SPMCNTENCLR_EL0", 841 },
    { "SPMCNTENSET_EL0", 842 },
    { "SPMCR_EL0", 843 },
    { "SPMDEVAFF_EL1", 844 },
    { "SPMDEVARCH_EL1", 845 },
    { "SPMEVCNTR0_EL0", 846 },
    { "SPMEVCNTR10_EL0", 847 },
    { "SPMEVCNTR11_EL0", 848 },
    { "SPMEVCNTR12_EL0", 849 },
    { "SPMEVCNTR13_EL0", 850 },
    { "SPMEVCNTR14_EL0", 851 },
    { "SPMEVCNTR15_EL0", 852 },
    { "SPMEVCNTR1_EL0", 853 },
    { "SPMEVCNTR2_EL0", 854 },
    { "SPMEVCNTR3_EL0", 855 },
    { "SPMEVCNTR4_EL0", 856 },
    { "SPMEVCNTR5_EL0", 857 },
    { "SPMEVCNTR6_EL0", 858 },
    { "SPMEVCNTR7_EL0", 859 },
    { "SPMEVCNTR8_EL0", 860 },
    { "SPMEVCNTR9_EL0", 861 },
    { "SPMEVFILT2R0_EL0", 862 },
    { "SPMEVFILT2R10_EL0", 863 },
    { "SPMEVFILT2R11_EL0", 864 },
    { "SPMEVFILT2R12_EL0", 865 },
    { "SPMEVFILT2R13_EL0", 866 },
    { "SPMEVFILT2R14_EL0", 867 },
    { "SPMEVFILT2R15_EL0", 868 },
    { "SPMEVFILT2R1_EL0", 869 },
    { "SPMEVFILT2R2_EL0", 870 },
    { "SPMEVFILT2R3_EL0", 871 },
    { "SPMEVFILT2R4_EL0", 872 },
    { "SPMEVFILT2R5_EL0", 873 },
    { "SPMEVFILT2R6_EL0", 874 },
    { "SPMEVFILT2R7_EL0", 875 },
    { "SPMEVFILT2R8_EL0", 876 },
    { "SPMEVFILT2R9_EL0", 877 },
    { "SPMEVFILTR0_EL0", 878 },
    { "SPMEVFILTR10_EL0", 879 },
    { "SPMEVFILTR11_EL0", 880 },
    { "SPMEVFILTR12_EL0", 881 },
    { "SPMEVFILTR13_EL0", 882 },
    { "SPMEVFILTR14_EL0", 883 },
    { "SPMEVFILTR15_EL0", 884 },
    { "SPMEVFILTR1_EL0", 885 },
    { "SPMEVFILTR2_EL0", 886 },
    { "SPMEVFILTR3_EL0", 887 },
    { "SPMEVFILTR4_EL0", 888 },
    { "SPMEVFILTR5_EL0", 889 },
    { "SPMEVFILTR6_EL0", 890 },
    { "SPMEVFILTR7_EL0", 891 },
    { "SPMEVFILTR8_EL0", 892 },
    { "SPMEVFILTR9_EL0", 893 },
    { "SPMEVTYPER0_EL0", 894 },
    { "SPMEVTYPER10_EL0", 895 },
    { "SPMEVTYPER11_EL0", 896 },
    { "SPMEVTYPER12_EL0", 897 },
    { "SPMEVTYPER13_EL0", 898 },
    { "SPMEVTYPER14_EL0", 899 },
    { "SPMEVTYPER15_EL0", 900 },
    { "SPMEVTYPER1_EL0", 901 },
    { "SPMEVTYPER2_EL0", 902 },
    { "SPMEVTYPER3_EL0", 903 },
    { "SPMEVTYPER4_EL0", 904 },
    { "SPMEVTYPER5_EL0", 905 },
    { "SPMEVTYPER6_EL0", 906 },
    { "SPMEVTYPER7_EL0", 907 },
    { "SPMEVTYPER8_EL0", 908 },
    { "SPMEVTYPER9_EL0", 909 },
    { "SPMIIDR_EL1", 910 },
    { "SPMINTENCLR_EL1", 911 },
    { "SPMINTENSET_EL1", 912 },
    { "SPMOVSCLR_EL0", 913 },
    { "SPMOVSSET_EL0", 914 },
    { "SPMROOTCR_EL3", 915 },
    { "SPMSCR_EL1", 916 },
    { "SPMSELR_EL0", 917 },
    { "SPMZR_EL0", 918 },
    { "SPSEL", 919 },
    { "SPSR_ABT", 920 },
    { "SPSR_EL1", 921 },
    { "SPSR_EL12", 922 },
    { "SPSR_EL2", 923 },
    { "SPSR_EL3", 924 },
    { "SPSR_FIQ", 925 },
    { "SPSR_IRQ", 926 },
    { "SPSR_UND", 927 },
    { "SP_EL0", 928 },
    { "SP_EL1", 929 },
    { "SP_EL2", 930 },
    { "SSBS", 931 },
    { "SVCR", 932 },
    { "TCO", 933 },
    { "TCR2_EL1", 934 },
    { "TCR2_EL12", 935 },
    { "TCR2_EL2", 936 },
    { "TCR_EL1", 937 },
    { "TCR_EL12", 938 },
    { "TCR_EL2", 939 },
    { "TCR_EL3", 940 },
    { "TEECR32_EL1", 941 },
    { "TEEHBR32_EL1", 942 },
    { "TFSRE0_EL1", 943 },
    { "TFSR_EL1", 944 },
    { "TFSR_EL12", 945 },
    { "TFSR_EL2", 946 },
    { "TFSR_EL3", 947 },
    { "TPIDR2_EL0", 948 },
    { "TPIDRRO_EL0", 949 },
    { "TPIDR_EL0", 950 },
    { "TPIDR_EL1", 951 },
    { "TPIDR_EL2", 952 },
    { "TPIDR_EL3", 953 },
    { "TRBBASER_EL1", 954 },
    { "TRBIDR_EL1", 955 },
    { "TRBLIMITR_EL1", 956 },
    { "TRBMAR_EL1", 957 },
    { "TRBPTR_EL1", 958 },
    { "TRBSR_EL1", 959 },
    { "TRBTRG_EL1", 960 },
    { "TRCACATR0", 961 },
    { "TRCACATR1", 962 },
    { "TRCACATR10", 963 },
    { "TRCACATR11", 964 },
    { "TRCACATR12", 965 },
    { "TRCACATR13", 966 },
    { "TRCACATR14", 967 },
    { "TRCACATR15", 968 },
    { "TRCACATR2", 969 },
    { "TRCACATR3", 970 },
    { "TRCACATR4", 971 },
    { "TRCACATR5", 972 },
    { "TRCACATR6", 973 },
    { "TRCACATR7", 974 },
    { "TRCACATR8", 975 },
    { "TRCACATR9", 976 },
    { "TRCACVR0", 977 },
    { "TRCACVR1", 978 },
    { "TRCACVR10", 979 },
    { "TRCACVR11", 980 },
    { "TRCACVR12", 981 },
    { "TRCACVR13", 982 },
    { "TRCACVR14", 983 },
    { "TRCACVR15", 984 },
    { "TRCACVR2", 985 },
    { "TRCACVR3", 986 },
    { "TRCACVR4", 987 },
    { "TRCACVR5", 988 },
    { "TRCACVR6", 989 },
    { "TRCACVR7", 990 },
    { "TRCACVR8", 991 },
    { "TRCACVR9", 992 },
    { "TRCAUTHSTATUS", 993 },
    { "TRCAUXCTLR", 994 },
    { "TRCBBCTLR", 995 },
    { "TRCCCCTLR", 996 },
    { "TRCCIDCCTLR0", 997 },
    { "TRCCIDCCTLR1", 998 },
    { "TRCCIDCVR0", 999 },
    { "TRCCIDCVR1", 1000 },
    { "TRCCIDCVR2", 1001 },
    { "TRCCIDCVR3", 1002 },
    { "TRCCIDCVR4", 1003 },
    { "TRCCIDCVR5", 1004 },
    { "TRCCIDCVR6", 1005 },
    { "TRCCIDCVR7", 1006 },
    { "TRCCIDR0", 1007 },
    { "TRCCIDR1", 1008 },
    { "TRCCIDR2", 1009 },
    { "TRCCIDR3", 1010 },
    { "TRCCLAIMCLR", 1011 },
    { "TRCCLAIMSET", 1012 },
    { "TRCCNTCTLR0", 1013 },
    { "TRCCNTCTLR1", 1014 },
    { "TRCCNTCTLR2", 1015 },
    { "TRCCNTCTLR3", 1016 },
    { "TRCCNTRLDVR0", 1017 },
    { "TRCCNTRLDVR1", 1018 },
    { "TRCCNTRLDVR2", 1019 },
    { "TRCCNTRLDVR3", 1020 },
    { "TRCCNTVR0", 1021 },
    { "TRCCNTVR1", 1022 },
    { "TRCCNTVR2", 1023 },
    { "TRCCNTVR3", 1024 },
    { "TRCCONFIGR", 1025 },
    { "TRCDEVAFF0", 1026 },
    { "TRCDEVAFF1", 1027 },
    { "TRCDEVARCH", 1028 },
    { "TRCDEVID", 1029 },
    { "TRCDEVTYPE", 1030 },
    { "TRCDVCMR0", 1031 },
    { "TRCDVCMR1", 1032 },
    { "TRCDVCMR2", 1033 },
    { "TRCDVCMR3", 1034 },
    { "TRCDVCMR4", 1035 },
    { "TRCDVCMR5", 1036 },
    { "TRCDVCMR6", 1037 },
    { "TRCDVCMR7", 1038 },
    { "TRCDVCVR0", 1039 },
    { "TRCDVCVR1", 1040 },
    { "TRCDVCVR2", 1041 },
    { "TRCDVCVR3", 1042 },
    { "TRCDVCVR4", 1043 },
    { "TRCDVCVR5", 1044 },
    { "TRCDVCVR6", 1045 },
    { "TRCDVCVR7", 1046 },
    { "TRCEVENTCTL0R", 1047 },
    { "TRCEVENTCTL1R", 1048 },
    { "TRCEXTINSELR", 1049 },
    { "TRCEXTINSELR0", 1050 },
    { "TRCEXTINSELR1", 1051 },
    { "TRCEXTINSELR2", 1052 },
    { "TRCEXTINSELR3", 1053 },
    { "TRCIDR0", 1054 },
    { "TRCIDR1", 1055 },
    { "TRCIDR10", 1056 },
    { "TRCIDR11", 1057 },
    { "TRCIDR12", 1058 },
    { "TRCIDR13", 1059 },
    { "TRCIDR2", 1060 },
    { "TRCIDR3", 1061 },
    { "TRCIDR4", 1062 },
    { "TRCIDR5", 1063 },
    { "TRCIDR6", 1064 },
    { "TRCIDR7", 1065 },
    { "TRCIDR8", 1066 },
    { "TRCIDR9", 1067 },
    { "TRCIMSPEC0", 1068 },
    { "TRCIMSPEC1", 1069 },
    { "TRCIMSPEC2", 1070 },
    { "TRCIMSPEC3", 1071 },
    { "TRCIMSPEC4", 1072 },
    { "TRCIMSPEC5", 1073 },
    { "TRCIMSPEC6", 1074 },
    { "TRCIMSPEC7", 1075 },
    { "TRCITCTRL", 1076 },
    { "TRCITECR_EL1", 1077 },
    { "TRCITECR_EL12", 1078 },
    { "TRCITECR_EL2", 1079 },
    { "TRCITEEDCR", 1080 },
    { "TRCLAR", 1081 },
    { "TRCLSR", 1082 },
    { "TRCOSLAR", 1083 },
    { "TRCOSLSR", 1084 },
    { "TRCPDCR", 1085 },
    { "TRCPDSR", 1086 },
    { "TRCPIDR0", 1087 },
    { "TRCPIDR1", 1088 },
    { "TRCPIDR2", 1089 },
    { "TRCPIDR3", 1090 },
    { "TRCPIDR4", 1091 },
    { "TRCPIDR5", 1092 },
    { "TRCPIDR6", 1093 },
    { "TRCPIDR7", 1094 },
    { "TRCPRGCTLR", 1095 },
    { "TRCPROCSELR", 1096 },
    { "TRCQCTLR", 1097 },
    { "TRCRSCTLR10", 1098 },
    { "TRCRSCTLR11", 1099 },
    { "TRCRSCTLR12", 1100 },
    { "TRCRSCTLR13", 1101 },
    { "TRCRSCTLR14", 1102 },
    { "TRCRSCTLR15", 1103 },
    { "TRCRSCTLR16", 1104 },
    { "TRCRSCTLR17", 1105 },
    { "TRCRSCTLR18", 1106 },
    { "TRCRSCTLR19", 1107 },
    { "TRCRSCTLR2", 1108 },
    { "TRCRSCTLR20", 1109 },
    { "TRCRSCTLR21", 1110 },
    { "TRCRSCTLR22", 1111 },
    { "TRCRSCTLR23", 1112 },
    { "TRCRSCTLR24", 1113 },
    { "TRCRSCTLR25", 1114 },
    { "TRCRSCTLR26", 1115 },
    { "TRCRSCTLR27", 1116 },
    { "TRCRSCTLR28", 1117 },
    { "TRCRSCTLR29", 1118 },
    { "TRCRSCTLR3", 1119 },
    { "TRCRSCTLR30", 1120 },
    { "TRCRSCTLR31", 1121 },
    { "TRCRSCTLR4", 1122 },
    { "TRCRSCTLR5", 1123 },
    { "TRCRSCTLR6", 1124 },
    { "TRCRSCTLR7", 1125 },
    { "TRCRSCTLR8", 1126 },
    { "TRCRSCTLR9", 1127 },
    { "TRCRSR", 1128 },
    { "TRCSEQEVR0", 1129 },
    { "TRCSEQEVR1", 1130 },
    { "TRCSEQEVR2", 1131 },
    { "TRCSEQRSTEVR", 1132 },
    { "TRCSEQSTR", 1133 },
    { "TRCSSCCR0", 1134 },
    { "TRCSSCCR1", 1135 },
    { "TRCSSCCR2", 1136 },
    { "TRCSSCCR3", 1137 },
    { "TRCSSCCR4", 1138 },
    { "TRCSSCCR5", 1139 },
    { "TRCSSCCR6", 1140 },
    { "TRCSSCCR7", 1141 },
    { "TRCSSCSR0", 1142 },
    { "TRCSSCSR1", 1143 },
    { "TRCSSCSR2", 1144 },
    { "TRCSSCSR3", 1145 },
    { "TRCSSCSR4", 1146 },
    { "TRCSSCSR5", 1147 },
    { "TRCSSCSR6", 1148 },
    { "TRCSSCSR7", 1149 },
    { "TRCSSPCICR0", 1150 },
    { "TRCSSPCICR1", 1151 },
    { "TRCSSPCICR2", 1152 },
    { "TRCSSPCICR3", 1153 },
    { "TRCSSPCICR4", 1154 },
    { "TRCSSPCICR5", 1155 },
    { "TRCSSPCICR6", 1156 },
    { "TRCSSPCICR7", 1157 },
    { "TRCSTALLCTLR", 1158 },
    { "TRCSTATR", 1159 },
    { "TRCSYNCPR", 1160 },
    { "TRCTRACEIDR", 1161 },
    { "TRCTSCTLR", 1162 },
    { "TRCVDARCCTLR", 1163 },
    { "TRCVDCTLR", 1164 },
    { "TRCVDSACCTLR", 1165 },
    { "TRCVICTLR", 1166 },
    { "TRCVIIECTLR", 1167 },
    { "TRCVIPCSSCTLR", 1168 },
    { "TRCVISSCTLR", 1169 },
    { "TRCVMIDCCTLR0", 1170 },
    { "TRCVMIDCCTLR1", 1171 },
    { "TRCVMIDCVR0", 1172 },
    { "TRCVMIDCVR1", 1173 },
    { "TRCVMIDCVR2", 1174 },
    { "TRCVMIDCVR3", 1175 },
    { "TRCVMIDCVR4", 1176 },
    { "TRCVMIDCVR5", 1177 },
    { "TRCVMIDCVR6", 1178 },
    { "TRCVMIDCVR7", 1179 },
    { "TRFCR_EL1", 1180 },
    { "TRFCR_EL12", 1181 },
    { "TRFCR_EL2", 1182 },
    { "TTBR0_EL1", 1183 },
    { "TTBR0_EL12", 1184 },
    { "TTBR0_EL2", 1185 },
    { "TTBR0_EL3", 1186 },
    { "TTBR1_EL1", 1187 },
    { "TTBR1_EL12", 1188 },
    { "TTBR1_EL2", 1189 },
    { "UAO", 1190 },
    { "VBAR_EL1", 1191 },
    { "VBAR_EL12", 1192 },
    { "VBAR_EL2", 1193 },
    { "VBAR_EL3", 1194 },
    { "VDISR_EL2", 1195 },
    { "VDISR_EL3", 1196 },
    { "VMECID_A_EL2", 1197 },
    { "VMECID_P_EL2", 1198 },
    { "VMPIDR_EL2", 1199 },
    { "VNCR_EL2", 1200 },
    { "VPIDR_EL2", 1201 },
    { "VSCTLR_EL2", 1202 },
    { "VSESR_EL2", 1203 },
    { "VSESR_EL3", 1204 },
    { "VSTCR_EL2", 1205 },
    { "VSTTBR_EL2", 1206 },
    { "VTCR_EL2", 1207 },
    { "VTTBR_EL2", 1208 },
    { "ZCR_EL1", 1209 },
    { "ZCR_EL12", 1210 },
    { "ZCR_EL2", 1211 },
    { "ZCR_EL3", 1212 },
  };

   unsigned i = binsearch_IndexTypeStrEncoding(Index, ARR_SIZE(Index), Name);
   if (i == -1)
      return NULL;
   else
      return &SysRegsList[Index[i].index];
}

const AArch64SysReg_SysReg *AArch64SysReg_lookupSysRegByEncoding(uint16_t Encoding) {
  static const struct IndexType Index[] = {
    { 0x8002, 572 },
    { 0x8004, 291 },
    { 0x8005, 275 },
    { 0x8006, 330 },
    { 0x8007, 314 },
    { 0x800C, 298 },
    { 0x800D, 282 },
    { 0x800E, 337 },
    { 0x800F, 321 },
    { 0x8010, 531 },
    { 0x8012, 536 },
    { 0x8014, 299 },
    { 0x8015, 283 },
    { 0x8016, 338 },
    { 0x8017, 322 },
    { 0x801A, 573 },
    { 0x801C, 300 },
    { 0x801D, 284 },
    { 0x801E, 339 },
    { 0x801F, 323 },
    { 0x8022, 537 },
    { 0x8024, 301 },
    { 0x8025, 285 },
    { 0x8026, 340 },
    { 0x8027, 324 },
    { 0x802A, 538 },
    { 0x802C, 302 },
    { 0x802D, 286 },
    { 0x802E, 341 },
    { 0x802F, 325 },
    { 0x8032, 574 },
    { 0x8034, 303 },
    { 0x8035, 287 },
    { 0x8036, 342 },
    { 0x8037, 326 },
    { 0x803C, 304 },
    { 0x803D, 288 },
    { 0x803E, 343 },
    { 0x803F, 327 },
    { 0x8044, 305 },
    { 0x8045, 289 },
    { 0x8046, 344 },
    { 0x8047, 328 },
    { 0x804C, 306 },
    { 0x804D, 290 },
    { 0x804E, 345 },
    { 0x804F, 329 },
    { 0x8054, 292 },
    { 0x8055, 276 },
    { 0x8056, 331 },
    { 0x8057, 315 },
    { 0x805C, 293 },
    { 0x805D, 277 },
    { 0x805E, 332 },
    { 0x805F, 316 },
    { 0x8064, 294 },
    { 0x8065, 278 },
    { 0x8066, 333 },
    { 0x8067, 317 },
    { 0x806C, 295 },
    { 0x806D, 279 },
    { 0x806E, 334 },
    { 0x806F, 318 },
    { 0x8074, 296 },
    { 0x8075, 280 },
    { 0x8076, 335 },
    { 0x8077, 319 },
    { 0x807C, 297 },
    { 0x807D, 281 },
    { 0x807E, 336 },
    { 0x807F, 320 },
    { 0x8080, 535 },
    { 0x8084, 575 },
    { 0x808C, 576 },
    { 0x809C, 571 },
    { 0x80A4, 312 },
    { 0x83C6, 308 },
    { 0x83CE, 307 },
    { 0x83F6, 274 },
    { 0x84E8, 839 },
    { 0x84E9, 840 },
    { 0x84EB, 834 },
    { 0x84EC, 910 },
    { 0x84ED, 845 },
    { 0x84EE, 844 },
    { 0x84EF, 838 },
    { 0x84F1, 912 },
    { 0x84F2, 911 },
    { 0x8740, 634 },
    { 0x8741, 645 },
    { 0x8742, 656 },
    { 0x8743, 658 },
    { 0x8744, 659 },
    { 0x8745, 660 },
    { 0x8746, 661 },
    { 0x8747, 662 },
    { 0x8748, 663 },
    { 0x8749, 664 },
    { 0x874A, 635 },
    { 0x874B, 636 },
    { 0x874C, 637 },
    { 0x874D, 638 },
    { 0x874E, 639 },
    { 0x874F, 640 },
    { 0x8750, 641 },
    { 0x8751, 642 },
    { 0x8752, 643 },
    { 0x8753, 644 },
    { 0x8754, 646 },
    { 0x8755, 647 },
    { 0x8756, 648 },
    { 0x8757, 649 },
    { 0x8758, 650 },
    { 0x8759, 651 },
    { 0x875A, 652 },
    { 0x875B, 653 },
    { 0x875C, 654 },
    { 0x875D, 655 },
    { 0x875E, 657 },
    { 0x875F, 596 },
    { 0x8760, 699 },
    { 0x8801, 1161 },
    { 0x8802, 1166 },
    { 0x8804, 1129 },
    { 0x8805, 1017 },
    { 0x8806, 1066 },
    { 0x8807, 1068 },
    { 0x8808, 1095 },
    { 0x8809, 1097 },
    { 0x880A, 1167 },
    { 0x880C, 1130 },
    { 0x880D, 1018 },
    { 0x880E, 1067 },
    { 0x880F, 1069 },
    { 0x8810, 1096 },
    { 0x8811, 1080 },
    { 0x8812, 1169 },
    { 0x8814, 1131 },
    { 0x8815, 1019 },
    { 0x8816, 1056 },
    { 0x8817, 1070 },
    { 0x8818, 1159 },
    { 0x881A, 1168 },
    { 0x881D, 1020 },
    { 0x881E, 1057 },
    { 0x881F, 1071 },
    { 0x8820, 1025 },
    { 0x8825, 1013 },
    { 0x8826, 1058 },
    { 0x8827, 1072 },
    { 0x882D, 1014 },
    { 0x882E, 1059 },
    { 0x882F, 1073 },
    { 0x8830, 994 },
    { 0x8834, 1132 },
    { 0x8835, 1015 },
    { 0x8837, 1074 },
    { 0x883C, 1133 },
    { 0x883D, 1016 },
    { 0x883F, 1075 },
    { 0x8840, 1047 },
    { 0x8842, 1164 },
    { 0x8844, 1049 },
    { 0x8844, 1050 },
    { 0x8845, 1021 },
    { 0x8847, 1054 },
    { 0x8848, 1048 },
    { 0x884A, 1165 },
    { 0x884C, 1051 },
    { 0x884D, 1022 },
    { 0x884F, 1055 },
    { 0x8850, 1128 },
    { 0x8852, 1163 },
    { 0x8854, 1052 },
    { 0x8855, 1023 },
    { 0x8857, 1060 },
    { 0x8858, 1158 },
    { 0x885C, 1053 },
    { 0x885D, 1024 },
    { 0x885F, 1061 },
    { 0x8860, 1162 },
    { 0x8867, 1062 },
    { 0x8868, 1160 },
    { 0x886F, 1063 },
    { 0x8870, 996 },
    { 0x8877, 1064 },
    { 0x8878, 995 },
    { 0x887F, 1065 },
    { 0x8881, 1104 },
    { 0x8882, 1134 },
    { 0x8883, 1150 },
    { 0x8884, 1083 },
    { 0x8889, 1105 },
    { 0x888A, 1135 },
    { 0x888B, 1151 },
    { 0x888C, 1084 },
    { 0x8890, 1108 },
    { 0x8891, 1106 },
    { 0x8892, 1136 },
    { 0x8893, 1152 },
    { 0x8898, 1119 },
    { 0x8899, 1107 },
    { 0x889A, 1137 },
    { 0x889B, 1153 },
    { 0x88A0, 1122 },
    { 0x88A1, 1109 },
    { 0x88A2, 1138 },
    { 0x88A3, 1154 },
    { 0x88A4, 1085 },
    { 0x88A8, 1123 },
    { 0x88A9, 1110 },
    { 0x88AA, 1139 },
    { 0x88AB, 1155 },
    { 0x88AC, 1086 },
    { 0x88B0, 1124 },
    { 0x88B1, 1111 },
    { 0x88B2, 1140 },
    { 0x88B3, 1156 },
    { 0x88B8, 1125 },
    { 0x88B9, 1112 },
    { 0x88BA, 1141 },
    { 0x88BB, 1157 },
    { 0x88C0, 1126 },
    { 0x88C1, 1113 },
    { 0x88C2, 1142 },
    { 0x88C8, 1127 },
    { 0x88C9, 1114 },
    { 0x88CA, 1143 },
    { 0x88D0, 1098 },
    { 0x88D1, 1115 },
    { 0x88D2, 1144 },
    { 0x88D8, 1099 },
    { 0x88D9, 1116 },
    { 0x88DA, 1145 },
    { 0x88E0, 1100 },
    { 0x88E1, 1117 },
    { 0x88E2, 1146 },
    { 0x88E8, 1101 },
    { 0x88E9, 1118 },
    { 0x88EA, 1147 },
    { 0x88F0, 1102 },
    { 0x88F1, 1120 },
    { 0x88F2, 1148 },
    { 0x88F8, 1103 },
    { 0x88F9, 1121 },
    { 0x88FA, 1149 },
    { 0x8900, 977 },
    { 0x8901, 991 },
    { 0x8902, 961 },
    { 0x8903, 975 },
    { 0x8904, 1039 },
    { 0x8905, 1043 },
    { 0x8906, 1031 },
    { 0x8907, 1035 },
    { 0x8910, 978 },
    { 0x8911, 992 },
    { 0x8912, 962 },
    { 0x8913, 976 },
    { 0x8920, 985 },
    { 0x8921, 979 },
    { 0x8922, 969 },
    { 0x8923, 963 },
    { 0x8924, 1040 },
    { 0x8925, 1044 },
    { 0x8926, 1032 },
    { 0x8927, 1036 },
    { 0x8930, 986 },
    { 0x8931, 980 },
    { 0x8932, 970 },
    { 0x8933, 964 },
    { 0x8940, 987 },
    { 0x8941, 981 },
    { 0x8942, 971 },
    { 0x8943, 965 },
    { 0x8944, 1041 },
    { 0x8945, 1045 },
    { 0x8946, 1033 },
    { 0x8947, 1037 },
    { 0x8950, 988 },
    { 0x8951, 982 },
    { 0x8952, 972 },
    { 0x8953, 966 },
    { 0x8960, 989 },
    { 0x8961, 983 },
    { 0x8962, 973 },
    { 0x8963, 967 },
    { 0x8964, 1042 },
    { 0x8965, 1046 },
    { 0x8966, 1034 },
    { 0x8967, 1038 },
    { 0x8970, 990 },
    { 0x8971, 984 },
    { 0x8972, 974 },
    { 0x8973, 968 },
    { 0x8980, 999 },
    { 0x8981, 1172 },
    { 0x8982, 997 },
    { 0x898A, 998 },
    { 0x8990, 1000 },
    { 0x8991, 1173 },
    { 0x8992, 1170 },
    { 0x899A, 1171 },
    { 0x89A0, 1001 },
    { 0x89A1, 1174 },
    { 0x89B0, 1002 },
    { 0x89B1, 1175 },
    { 0x89C0, 1003 },
    { 0x89C1, 1176 },
    { 0x89D0, 1004 },
    { 0x89D1, 1177 },
    { 0x89E0, 1005 },
    { 0x89E1, 1178 },
    { 0x89F0, 1006 },
    { 0x89F1, 1179 },
    { 0x8B84, 1076 },
    { 0x8B97, 1029 },
    { 0x8B9F, 1030 },
    { 0x8BA7, 1091 },
    { 0x8BAF, 1092 },
    { 0x8BB7, 1093 },
    { 0x8BBF, 1094 },
    { 0x8BC6, 1012 },
    { 0x8BC7, 1087 },
    { 0x8BCE, 1011 },
    { 0x8BCF, 1088 },
    { 0x8BD6, 1026 },
    { 0x8BD7, 1089 },
    { 0x8BDE, 1027 },
    { 0x8BDF, 1090 },
    { 0x8BE6, 1081 },
    { 0x8BE7, 1007 },
    { 0x8BEE, 1082 },
    { 0x8BEF, 1008 },
    { 0x8BF6, 993 },
    { 0x8BF7, 1009 },
    { 0x8BFE, 1028 },
    { 0x8BFF, 1010 },
    { 0x8C00, 118 },
    { 0x8C01, 151 },
    { 0x8C02, 184 },
    { 0x8C04, 125 },
    { 0x8C05, 158 },
    { 0x8C06, 191 },
    { 0x8C08, 129 },
    { 0x8C09, 162 },
    { 0x8C0A, 195 },
    { 0x8C0C, 126 },
    { 0x8C0D, 159 },
    { 0x8C0E, 192 },
    { 0x8C10, 140 },
    { 0x8C11, 173 },
    { 0x8C12, 206 },
    { 0x8C14, 127 },
    { 0x8C15, 160 },
    { 0x8C16, 193 },
    { 0x8C18, 143 },
    { 0x8C19, 176 },
    { 0x8C1A, 209 },
    { 0x8C1C, 128 },
    { 0x8C1D, 161 },
    { 0x8C1E, 194 },
    { 0x8C20, 144 },
    { 0x8C21, 177 },
    { 0x8C22, 210 },
    { 0x8C24, 130 },
    { 0x8C25, 163 },
    { 0x8C26, 196 },
    { 0x8C28, 145 },
    { 0x8C29, 178 },
    { 0x8C2A, 211 },
    { 0x8C2C, 131 },
    { 0x8C2D, 164 },
    { 0x8C2E, 197 },
    { 0x8C30, 146 },
    { 0x8C31, 179 },
    { 0x8C32, 212 },
    { 0x8C34, 132 },
    { 0x8C35, 165 },
    { 0x8C36, 198 },
    { 0x8C38, 147 },
    { 0x8C39, 180 },
    { 0x8C3A, 213 },
    { 0x8C3C, 133 },
    { 0x8C3D, 166 },
    { 0x8C3E, 199 },
    { 0x8C40, 148 },
    { 0x8C41, 181 },
    { 0x8C42, 214 },
    { 0x8C44, 134 },
    { 0x8C45, 167 },
    { 0x8C46, 200 },
    { 0x8C48, 149 },
    { 0x8C49, 182 },
    { 0x8C4A, 215 },
    { 0x8C4C, 135 },
    { 0x8C4D, 168 },
    { 0x8C4E, 201 },
    { 0x8C50, 119 },
    { 0x8C51, 152 },
    { 0x8C52, 185 },
    { 0x8C54, 136 },
    { 0x8C55, 169 },
    { 0x8C56, 202 },
    { 0x8C58, 120 },
    { 0x8C59, 153 },
    { 0x8C5A, 186 },
    { 0x8C5C, 137 },
    { 0x8C5D, 170 },
    { 0x8C5E, 203 },
    { 0x8C60, 121 },
    { 0x8C61, 154 },
    { 0x8C62, 187 },
    { 0x8C64, 138 },
    { 0x8C65, 171 },
    { 0x8C66, 204 },
    { 0x8C68, 122 },
    { 0x8C69, 155 },
    { 0x8C6A, 188 },
    { 0x8C6C, 139 },
    { 0x8C6D, 172 },
    { 0x8C6E, 205 },
    { 0x8C70, 123 },
    { 0x8C71, 156 },
    { 0x8C72, 189 },
    { 0x8C74, 141 },
    { 0x8C75, 174 },
    { 0x8C76, 207 },
    { 0x8C78, 124 },
    { 0x8C79, 157 },
    { 0x8C7A, 190 },
    { 0x8C7C, 142 },
    { 0x8C7D, 175 },
    { 0x8C7E, 208 },
    { 0x8C80, 113 },
    { 0x8C81, 116 },
    { 0x8C82, 217 },
    { 0x8C88, 150 },
    { 0x8C89, 183 },
    { 0x8C8A, 216 },
    { 0x8C90, 117 },
    { 0x9000, 941 },
    { 0x9080, 942 },
    { 0x9808, 532 },
    { 0x9820, 311 },
    { 0x9828, 309 },
    { 0x9828, 310 },
    { 0x9CE0, 843 },
    { 0x9CE1, 842 },
    { 0x9CE2, 841 },
    { 0x9CE3, 913 },
    { 0x9CE4, 918 },
    { 0x9CE5, 917 },
    { 0x9CF3, 914 },
    { 0x9F00, 846 },
    { 0x9F01, 853 },
    { 0x9F02, 854 },
    { 0x9F03, 855 },
    { 0x9F04, 856 },
    { 0x9F05, 857 },
    { 0x9F06, 858 },
    { 0x9F07, 859 },
    { 0x9F08, 860 },
    { 0x9F09, 861 },
    { 0x9F0A, 847 },
    { 0x9F0B, 848 },
    { 0x9F0C, 849 },
    { 0x9F0D, 850 },
    { 0x9F0E, 851 },
    { 0x9F0F, 852 },
    { 0x9F10, 894 },
    { 0x9F11, 901 },
    { 0x9F12, 902 },
    { 0x9F13, 903 },
    { 0x9F14, 904 },
    { 0x9F15, 905 },
    { 0x9F16, 906 },
    { 0x9F17, 907 },
    { 0x9F18, 908 },
    { 0x9F19, 909 },
    { 0x9F1A, 895 },
    { 0x9F1B, 896 },
    { 0x9F1C, 897 },
    { 0x9F1D, 898 },
    { 0x9F1E, 899 },
    { 0x9F1F, 900 },
    { 0x9F20, 878 },
    { 0x9F21, 885 },
    { 0x9F22, 886 },
    { 0x9F23, 887 },
    { 0x9F24, 888 },
    { 0x9F25, 889 },
    { 0x9F26, 890 },
    { 0x9F27, 891 },
    { 0x9F28, 892 },
    { 0x9F29, 893 },
    { 0x9F2A, 879 },
    { 0x9F2B, 880 },
    { 0x9F2C, 881 },
    { 0x9F2D, 882 },
    { 0x9F2E, 883 },
    { 0x9F2F, 884 },
    { 0x9F30, 862 },
    { 0x9F31, 869 },
    { 0x9F32, 870 },
    { 0x9F33, 871 },
    { 0x9F34, 872 },
    { 0x9F35, 873 },
    { 0x9F36, 874 },
    { 0x9F37, 875 },
    { 0x9F38, 876 },
    { 0x9F39, 877 },
    { 0x9F3A, 863 },
    { 0x9F3B, 864 },
    { 0x9F3C, 865 },
    { 0x9F3D, 866 },
    { 0x9F3E, 867 },
    { 0x9F3F, 868 },
    { 0xA038, 313 },
    { 0xA480, 115 },
    { 0xA4EB, 836 },
    { 0xAC80, 114 },
    { 0xACEB, 835 },
    { 0xB4EB, 837 },
    { 0xB4F7, 915 },
    { 0xBCF7, 916 },
    { 0xC000, 546 },
    { 0xC004, 565 },
    { 0xC005, 564 },
    { 0xC006, 799 },
    { 0xC008, 513 },
    { 0xC009, 514 },
    { 0xC00A, 498 },
    { 0xC00B, 497 },
    { 0xC00C, 507 },
    { 0xC00D, 508 },
    { 0xC00E, 509 },
    { 0xC00F, 510 },
    { 0xC010, 500 },
    { 0xC011, 501 },
    { 0xC012, 502 },
    { 0xC013, 503 },
    { 0xC014, 504 },
    { 0xC015, 505 },
    { 0xC016, 511 },
    { 0xC017, 506 },
    { 0xC018, 567 },
    { 0xC019, 568 },
    { 0xC01A, 569 },
    { 0xC01C, 515 },
    { 0xC01D, 499 },
    { 0xC01E, 512 },
    { 0xC020, 492 },
    { 0xC021, 493 },
    { 0xC022, 494 },
    { 0xC024, 496 },
    { 0xC025, 495 },
    { 0xC027, 482 },
    { 0xC028, 479 },
    { 0xC029, 480 },
    { 0xC02A, 481 },
    { 0xC02C, 477 },
    { 0xC02D, 478 },
    { 0xC030, 483 },
    { 0xC031, 484 },
    { 0xC032, 485 },
    { 0xC033, 486 },
    { 0xC038, 487 },
    { 0xC039, 488 },
    { 0xC03A, 489 },
    { 0xC03B, 490 },
    { 0xC03C, 491 },
    { 0xC080, 816 },
    { 0xC081, 1 },
    { 0xC082, 264 },
    { 0xC083, 812 },
    { 0xC085, 800 },
    { 0xC086, 382 },
    { 0xC090, 1209 },
    { 0xC091, 1180 },
    { 0xC093, 1077 },
    { 0xC094, 833 },
    { 0xC096, 827 },
    { 0xC100, 1183 },
    { 0xC101, 1187 },
    { 0xC102, 937 },
    { 0xC103, 934 },
    { 0xC108, 110 },
    { 0xC109, 109 },
    { 0xC10A, 112 },
    { 0xC10B, 111 },
    { 0xC110, 104 },
    { 0xC111, 103 },
    { 0xC112, 106 },
    { 0xC113, 105 },
    { 0xC118, 108 },
    { 0xC119, 107 },
    { 0xC128, 384 },
    { 0xC129, 389 },
    { 0xC12A, 383 },
    { 0xC200, 921 },
    { 0xC201, 351 },
    { 0xC208, 928 },
    { 0xC210, 919 },
    { 0xC212, 271 },
    { 0xC213, 577 },
    { 0xC214, 1190 },
    { 0xC218, 13 },
    { 0xC219, 589 },
    { 0xC230, 440 },
    { 0xC288, 4 },
    { 0xC289, 8 },
    { 0xC290, 369 },
    { 0xC298, 355 },
    { 0xC299, 356 },
    { 0xC29A, 360 },
    { 0xC2A0, 359 },
    { 0xC2A1, 358 },
    { 0xC2A2, 368 },
    { 0xC2A3, 357 },
    { 0xC2A4, 367 },
    { 0xC2A5, 366 },
    { 0xC2A6, 365 },
    { 0xC2A8, 361 },
    { 0xC2A9, 362 },
    { 0xC2AA, 363 },
    { 0xC2AB, 364 },
    { 0xC2B0, 944 },
    { 0xC2B1, 943 },
    { 0xC300, 373 },
    { 0xC305, 579 },
    { 0xC309, 761 },
    { 0xC311, 795 },
    { 0xC340, 759 },
    { 0xC341, 793 },
    { 0xC344, 741 },
    { 0xC345, 775 },
    { 0xC348, 743 },
    { 0xC349, 777 },
    { 0xC34C, 745 },
    { 0xC34D, 779 },
    { 0xC350, 747 },
    { 0xC351, 781 },
    { 0xC354, 749 },
    { 0xC355, 783 },
    { 0xC358, 751 },
    { 0xC359, 785 },
    { 0xC35C, 753 },
    { 0xC35D, 787 },
    { 0xC360, 755 },
    { 0xC361, 789 },
    { 0xC364, 757 },
    { 0xC365, 791 },
    { 0xC368, 729 },
    { 0xC369, 763 },
    { 0xC36C, 731 },
    { 0xC36D, 765 },
    { 0xC370, 733 },
    { 0xC371, 767 },
    { 0xC374, 735 },
    { 0xC375, 769 },
    { 0xC378, 737 },
    { 0xC379, 771 },
    { 0xC37C, 739 },
    { 0xC37D, 773 },
    { 0xC3A0, 578 },
    { 0xC4C8, 705 },
    { 0xC4C9, 716 },
    { 0xC4CA, 712 },
    { 0xC4CB, 714 },
    { 0xC4CC, 711 },
    { 0xC4CD, 710 },
    { 0xC4CE, 715 },
    { 0xC4CF, 713 },
    { 0xC4D0, 591 },
    { 0xC4D1, 592 },
    { 0xC4D3, 593 },
    { 0xC4D4, 708 },
    { 0xC4D7, 590 },
    { 0xC4D8, 956 },
    { 0xC4D9, 958 },
    { 0xC4DA, 954 },
    { 0xC4DB, 959 },
    { 0xC4DC, 957 },
    { 0xC4DE, 960 },
    { 0xC4DF, 955 },
    { 0xC4EB, 717 },
    { 0xC4F1, 701 },
    { 0xC4F2, 700 },
    { 0xC4F4, 719 },
    { 0xC4F5, 602 },
    { 0xC4F6, 702 },
    { 0xC4F7, 696 },
    { 0xC510, 527 },
    { 0xC511, 523 },
    { 0xC512, 582 },
    { 0xC513, 585 },
    { 0xC514, 725 },
    { 0xC515, 810 },
    { 0xC518, 18 },
    { 0xC519, 14 },
    { 0xC520, 522 },
    { 0xC521, 519 },
    { 0xC522, 521 },
    { 0xC523, 518 },
    { 0xC524, 553 },
    { 0xC527, 520 },
    { 0xC528, 548 },
    { 0xC529, 547 },
    { 0xC52B, 554 },
    { 0xC600, 1191 },
    { 0xC601, 806 },
    { 0xC602, 801 },
    { 0xC608, 517 },
    { 0xC609, 347 },
    { 0xC640, 434 },
    { 0xC641, 430 },
    { 0xC642, 432 },
    { 0xC643, 425 },
    { 0xC644, 416 },
    { 0xC645, 417 },
    { 0xC646, 418 },
    { 0xC647, 419 },
    { 0xC648, 420 },
    { 0xC649, 421 },
    { 0xC64A, 422 },
    { 0xC64B, 423 },
    { 0xC64D, 439 },
    { 0xC659, 429 },
    { 0xC65B, 441 },
    { 0xC65D, 443 },
    { 0xC65E, 424 },
    { 0xC65F, 442 },
    { 0xC660, 435 },
    { 0xC661, 431 },
    { 0xC662, 433 },
    { 0xC663, 426 },
    { 0xC664, 427 },
    { 0xC665, 444 },
    { 0xC666, 436 },
    { 0xC667, 437 },
    { 0xC681, 261 },
    { 0xC683, 798 },
    { 0xC684, 951 },
    { 0xC685, 0 },
    { 0xC686, 797 },
    { 0xC687, 821 },
    { 0xC708, 236 },
    { 0xC800, 219 },
    { 0xC801, 220 },
    { 0xC802, 218 },
    { 0xC804, 393 },
    { 0xC806, 831 },
    { 0xC807, 12 },
    { 0xD000, 269 },
    { 0xD801, 270 },
    { 0xD807, 346 },
    { 0xD920, 804 },
    { 0xD921, 805 },
    { 0xD929, 388 },
    { 0xDA10, 570 },
    { 0xDA11, 273 },
    { 0xDA12, 932 },
    { 0xDA15, 348 },
    { 0xDA16, 931 },
    { 0xDA17, 933 },
    { 0xDA20, 378 },
    { 0xDA21, 381 },
    { 0xDA22, 380 },
    { 0xDA28, 350 },
    { 0xDA29, 349 },
    { 0xDCA0, 698 },
    { 0xDCB0, 697 },
    { 0xDCE0, 601 },
    { 0xDCE1, 600 },
    { 0xDCE2, 599 },
    { 0xDCE3, 703 },
    { 0xDCE4, 718 },
    { 0xDCE5, 709 },
    { 0xDCE6, 597 },
    { 0xDCE7, 598 },
    { 0xDCE8, 595 },
    { 0xDCE9, 722 },
    { 0xDCEA, 721 },
    { 0xDCEC, 723 },
    { 0xDCF0, 720 },
    { 0xDCF3, 704 },
    { 0xDD14, 724 },
    { 0xDE82, 950 },
    { 0xDE83, 949 },
    { 0xDE85, 948 },
    { 0xDE87, 820 },
    { 0xDE90, 29 },
    { 0xDE91, 22 },
    { 0xDE92, 24 },
    { 0xDE93, 102 },
    { 0xDE94, 25 },
    { 0xDE95, 27 },
    { 0xDE96, 23 },
    { 0xDE98, 26 },
    { 0xDE99, 28 },
    { 0xDEA0, 30 },
    { 0xDEA1, 31 },
    { 0xDEA2, 32 },
    { 0xDEA3, 33 },
    { 0xDEB0, 82 },
    { 0xDEB1, 83 },
    { 0xDEB2, 84 },
    { 0xDEB3, 85 },
    { 0xDEE0, 34 },
    { 0xDEE1, 41 },
    { 0xDEE2, 42 },
    { 0xDEE3, 43 },
    { 0xDEE4, 44 },
    { 0xDEE5, 45 },
    { 0xDEE6, 46 },
    { 0xDEE7, 47 },
    { 0xDEE8, 48 },
    { 0xDEE9, 49 },
    { 0xDEEA, 35 },
    { 0xDEEB, 36 },
    { 0xDEEC, 37 },
    { 0xDEED, 38 },
    { 0xDEEE, 39 },
    { 0xDEEF, 40 },
    { 0xDEF0, 86 },
    { 0xDEF1, 93 },
    { 0xDEF2, 94 },
    { 0xDEF3, 95 },
    { 0xDEF4, 96 },
    { 0xDEF5, 97 },
    { 0xDEF6, 98 },
    { 0xDEF7, 99 },
    { 0xDEF8, 100 },
    { 0xDEF9, 101 },
    { 0xDEFA, 87 },
    { 0xDEFB, 88 },
    { 0xDEFC, 89 },
    { 0xDEFD, 90 },
    { 0xDEFE, 91 },
    { 0xDEFF, 92 },
    { 0xDF00, 221 },
    { 0xDF01, 239 },
    { 0xDF02, 252 },
    { 0xDF05, 238 },
    { 0xDF06, 251 },
    { 0xDF10, 248 },
    { 0xDF11, 244 },
    { 0xDF12, 246 },
    { 0xDF18, 259 },
    { 0xDF19, 255 },
    { 0xDF1A, 257 },
    { 0xDF40, 603 },
    { 0xDF41, 614 },
    { 0xDF42, 625 },
    { 0xDF43, 627 },
    { 0xDF44, 628 },
    { 0xDF45, 629 },
    { 0xDF46, 630 },
    { 0xDF47, 631 },
    { 0xDF48, 632 },
    { 0xDF49, 633 },
    { 0xDF4A, 604 },
    { 0xDF4B, 605 },
    { 0xDF4C, 606 },
    { 0xDF4D, 607 },
    { 0xDF4E, 608 },
    { 0xDF4F, 609 },
    { 0xDF50, 610 },
    { 0xDF51, 611 },
    { 0xDF52, 612 },
    { 0xDF53, 613 },
    { 0xDF54, 615 },
    { 0xDF55, 616 },
    { 0xDF56, 617 },
    { 0xDF57, 618 },
    { 0xDF58, 619 },
    { 0xDF59, 620 },
    { 0xDF5A, 621 },
    { 0xDF5B, 622 },
    { 0xDF5C, 623 },
    { 0xDF5D, 624 },
    { 0xDF5E, 626 },
    { 0xDF60, 665 },
    { 0xDF61, 676 },
    { 0xDF62, 687 },
    { 0xDF63, 689 },
    { 0xDF64, 690 },
    { 0xDF65, 691 },
    { 0xDF66, 692 },
    { 0xDF67, 693 },
    { 0xDF68, 694 },
    { 0xDF69, 695 },
    { 0xDF6A, 666 },
    { 0xDF6B, 667 },
    { 0xDF6C, 668 },
    { 0xDF6D, 669 },
    { 0xDF6E, 670 },
    { 0xDF6F, 671 },
    { 0xDF70, 672 },
    { 0xDF71, 673 },
    { 0xDF72, 674 },
    { 0xDF73, 675 },
    { 0xDF74, 677 },
    { 0xDF75, 678 },
    { 0xDF76, 679 },
    { 0xDF77, 680 },
    { 0xDF78, 681 },
    { 0xDF79, 682 },
    { 0xDF7A, 683 },
    { 0xDF7B, 684 },
    { 0xDF7C, 685 },
    { 0xDF7D, 686 },
    { 0xDF7E, 688 },
    { 0xDF7F, 594 },
    { 0xE000, 1201 },
    { 0xE004, 566 },
    { 0xE005, 1199 },
    { 0xE080, 818 },
    { 0xE081, 2 },
    { 0xE083, 814 },
    { 0xE088, 401 },
    { 0xE089, 533 },
    { 0xE08A, 267 },
    { 0xE08B, 415 },
    { 0xE08C, 411 },
    { 0xE08D, 413 },
    { 0xE08E, 409 },
    { 0xE08F, 398 },
    { 0xE090, 1211 },
    { 0xE091, 1182 },
    { 0xE092, 400 },
    { 0xE093, 1079 },
    { 0xE095, 832 },
    { 0xE096, 829 },
    { 0xE099, 825 },
    { 0xE100, 1185 },
    { 0xE100, 1202 },
    { 0xE101, 1189 },
    { 0xE102, 939 },
    { 0xE103, 936 },
    { 0xE108, 1208 },
    { 0xE10A, 1207 },
    { 0xE110, 1200 },
    { 0xE11A, 402 },
    { 0xE11B, 403 },
    { 0xE11C, 396 },
    { 0xE11D, 397 },
    { 0xE128, 386 },
    { 0xE129, 391 },
    { 0xE130, 1206 },
    { 0xE132, 1205 },
    { 0xE180, 272 },
    { 0xE188, 404 },
    { 0xE189, 406 },
    { 0xE18A, 410 },
    { 0xE18B, 412 },
    { 0xE18C, 405 },
    { 0xE18D, 407 },
    { 0xE18E, 399 },
    { 0xE18F, 408 },
    { 0xE200, 923 },
    { 0xE201, 353 },
    { 0xE208, 929 },
    { 0xE218, 926 },
    { 0xE219, 920 },
    { 0xE21A, 927 },
    { 0xE21B, 925 },
    { 0xE281, 516 },
    { 0xE288, 6 },
    { 0xE289, 10 },
    { 0xE290, 371 },
    { 0xE293, 1203 },
    { 0xE298, 379 },
    { 0xE2B0, 946 },
    { 0xE300, 375 },
    { 0xE304, 414 },
    { 0xE305, 581 },
    { 0xE309, 762 },
    { 0xE311, 796 },
    { 0xE340, 760 },
    { 0xE341, 794 },
    { 0xE344, 742 },
    { 0xE345, 776 },
    { 0xE348, 744 },
    { 0xE349, 778 },
    { 0xE34C, 746 },
    { 0xE34D, 780 },
    { 0xE350, 748 },
    { 0xE351, 782 },
    { 0xE354, 750 },
    { 0xE355, 784 },
    { 0xE358, 752 },
    { 0xE359, 786 },
    { 0xE35C, 754 },
    { 0xE35D, 788 },
    { 0xE360, 756 },
    { 0xE361, 790 },
    { 0xE364, 758 },
    { 0xE365, 792 },
    { 0xE368, 730 },
    { 0xE369, 764 },
    { 0xE36C, 732 },
    { 0xE36D, 766 },
    { 0xE370, 734 },
    { 0xE371, 768 },
    { 0xE374, 736 },
    { 0xE375, 770 },
    { 0xE378, 738 },
    { 0xE379, 772 },
    { 0xE37C, 740 },
    { 0xE37D, 774 },
    { 0xE4C8, 707 },
    { 0xE509, 525 },
    { 0xE510, 529 },
    { 0xE512, 584 },
    { 0xE513, 587 },
    { 0xE514, 727 },
    { 0xE515, 809 },
    { 0xE518, 20 },
    { 0xE519, 16 },
    { 0xE520, 552 },
    { 0xE521, 563 },
    { 0xE528, 550 },
    { 0xE530, 555 },
    { 0xE531, 556 },
    { 0xE532, 557 },
    { 0xE533, 558 },
    { 0xE534, 559 },
    { 0xE535, 560 },
    { 0xE536, 561 },
    { 0xE537, 562 },
    { 0xE540, 542 },
    { 0xE541, 540 },
    { 0xE542, 543 },
    { 0xE543, 541 },
    { 0xE547, 539 },
    { 0xE548, 1198 },
    { 0xE549, 1197 },
    { 0xE600, 1193 },
    { 0xE601, 807 },
    { 0xE602, 802 },
    { 0xE609, 1195 },
    { 0xE640, 447 },
    { 0xE641, 448 },
    { 0xE642, 449 },
    { 0xE643, 450 },
    { 0xE648, 451 },
    { 0xE649, 452 },
    { 0xE64A, 453 },
    { 0xE64B, 454 },
    { 0xE64D, 445 },
    { 0xE658, 457 },
    { 0xE659, 476 },
    { 0xE65A, 474 },
    { 0xE65B, 455 },
    { 0xE65D, 456 },
    { 0xE65F, 475 },
    { 0xE660, 458 },
    { 0xE661, 465 },
    { 0xE662, 466 },
    { 0xE663, 467 },
    { 0xE664, 468 },
    { 0xE665, 469 },
    { 0xE666, 470 },
    { 0xE667, 471 },
    { 0xE668, 472 },
    { 0xE669, 473 },
    { 0xE66A, 459 },
    { 0xE66B, 460 },
    { 0xE66C, 461 },
    { 0xE66D, 462 },
    { 0xE66E, 463 },
    { 0xE66F, 464 },
    { 0xE681, 263 },
    { 0xE682, 952 },
    { 0xE687, 823 },
    { 0xE6C0, 50 },
    { 0xE6C1, 57 },
    { 0xE6C2, 58 },
    { 0xE6C3, 59 },
    { 0xE6C4, 60 },
    { 0xE6C5, 61 },
    { 0xE6C6, 62 },
    { 0xE6C7, 63 },
    { 0xE6C8, 64 },
    { 0xE6C9, 65 },
    { 0xE6CA, 51 },
    { 0xE6CB, 52 },
    { 0xE6CC, 53 },
    { 0xE6CD, 54 },
    { 0xE6CE, 55 },
    { 0xE6CF, 56 },
    { 0xE6D0, 66 },
    { 0xE6D1, 73 },
    { 0xE6D2, 74 },
    { 0xE6D3, 75 },
    { 0xE6D4, 76 },
    { 0xE6D5, 77 },
    { 0xE6D6, 78 },
    { 0xE6D7, 79 },
    { 0xE6D8, 80 },
    { 0xE6D9, 81 },
    { 0xE6DA, 67 },
    { 0xE6DB, 68 },
    { 0xE6DC, 69 },
    { 0xE6DD, 70 },
    { 0xE6DE, 71 },
    { 0xE6DF, 72 },
    { 0xE703, 254 },
    { 0xE704, 250 },
    { 0xE705, 235 },
    { 0xE706, 240 },
    { 0xE707, 253 },
    { 0xE708, 222 },
    { 0xE710, 228 },
    { 0xE711, 226 },
    { 0xE712, 227 },
    { 0xE718, 234 },
    { 0xE719, 232 },
    { 0xE71A, 233 },
    { 0xE720, 231 },
    { 0xE721, 229 },
    { 0xE722, 230 },
    { 0xE728, 225 },
    { 0xE729, 223 },
    { 0xE72A, 224 },
    { 0xE880, 817 },
    { 0xE882, 265 },
    { 0xE883, 813 },
    { 0xE890, 1210 },
    { 0xE891, 1181 },
    { 0xE893, 1078 },
    { 0xE896, 828 },
    { 0xE900, 1184 },
    { 0xE901, 1188 },
    { 0xE902, 938 },
    { 0xE903, 935 },
    { 0xE928, 385 },
    { 0xE929, 390 },
    { 0xEA00, 922 },
    { 0xEA01, 352 },
    { 0xEA88, 5 },
    { 0xEA89, 9 },
    { 0xEA90, 370 },
    { 0xEAB0, 945 },
    { 0xEB00, 374 },
    { 0xEB05, 580 },
    { 0xECC8, 706 },
    { 0xED10, 528 },
    { 0xED11, 524 },
    { 0xED12, 583 },
    { 0xED13, 586 },
    { 0xED14, 726 },
    { 0xED18, 19 },
    { 0xED19, 15 },
    { 0xED28, 549 },
    { 0xEE00, 1192 },
    { 0xEE81, 262 },
    { 0xEE87, 822 },
    { 0xEF08, 237 },
    { 0xEF10, 249 },
    { 0xEF11, 245 },
    { 0xEF12, 247 },
    { 0xEF18, 260 },
    { 0xEF19, 256 },
    { 0xEF1A, 258 },
    { 0xF080, 819 },
    { 0xF081, 3 },
    { 0xF083, 815 },
    { 0xF088, 811 },
    { 0xF089, 826 },
    { 0xF08A, 268 },
    { 0xF08D, 377 },
    { 0xF090, 1212 },
    { 0xF096, 830 },
    { 0xF099, 534 },
    { 0xF100, 1186 },
    { 0xF102, 940 },
    { 0xF10C, 395 },
    { 0xF10E, 394 },
    { 0xF128, 387 },
    { 0xF129, 392 },
    { 0xF200, 924 },
    { 0xF201, 354 },
    { 0xF208, 930 },
    { 0xF288, 7 },
    { 0xF289, 11 },
    { 0xF290, 372 },
    { 0xF293, 1204 },
    { 0xF2B0, 947 },
    { 0xF300, 376 },
    { 0xF305, 545 },
    { 0xF509, 526 },
    { 0xF510, 530 },
    { 0xF513, 588 },
    { 0xF514, 728 },
    { 0xF518, 21 },
    { 0xF519, 17 },
    { 0xF528, 551 },
    { 0xF551, 544 },
    { 0xF600, 1194 },
    { 0xF601, 808 },
    { 0xF602, 803 },
    { 0xF609, 1196 },
    { 0xF664, 428 },
    { 0xF665, 446 },
    { 0xF667, 438 },
    { 0xF682, 953 },
    { 0xF687, 824 },
    { 0xFF10, 243 },
    { 0xFF11, 241 },
    { 0xFF12, 242 },
    { 0xFF90, 266 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
   if (i == -1)
      return NULL;
   else
      return &SysRegsList[Index[i].index];
}

#endif

#ifdef GET_TSB_IMPL
static const AArch64TSB_TSB TSBsList[] = {
  { "csync", { .raw_val = AARCH64_TSB_CSYNC }, 0x0,  {AArch64_FeatureTRACEV8_4}  }, // 0
  };

const AArch64TSB_TSB *AArch64TSB_lookupTSBByName(const char * Name) {
  static const struct IndexTypeStr Index[] = {
    { "CSYNC", 0 },
  };

   unsigned i = binsearch_IndexTypeStrEncoding(Index, ARR_SIZE(Index), Name);
   if (i == -1)
      return NULL;
   else
      return &TSBsList[Index[i].index];
}

const AArch64TSB_TSB *AArch64TSB_lookupTSBByEncoding(uint8_t Encoding) {
  static const struct IndexType Index[] = {
    { 0x0, 0 },
  };

   unsigned i = binsearch_IndexTypeEncoding(Index, ARR_SIZE(Index), Encoding);
   if (i == -1)
      return NULL;
   else
      return &TSBsList[Index[i].index];
}

#endif

#undef GET_AT_DECL
#undef GET_AT_IMPL
#undef GET_BTI_DECL
#undef GET_BTI_IMPL
#undef GET_DBNXS_DECL
#undef GET_DBNXS_IMPL
#undef GET_DB_DECL
#undef GET_DB_IMPL
#undef GET_DC_DECL
#undef GET_DC_IMPL
#undef GET_EXACTFPIMM_DECL
#undef GET_EXACTFPIMM_IMPL
#undef GET_IC_DECL
#undef GET_IC_IMPL
#undef GET_ISB_DECL
#undef GET_ISB_IMPL
#undef GET_PRFM_DECL
#undef GET_PRFM_IMPL
#undef GET_PSB_DECL
#undef GET_PSB_IMPL
#undef GET_PSTATEIMM0_15_DECL
#undef GET_PSTATEIMM0_15_IMPL
#undef GET_PSTATEIMM0_1_DECL
#undef GET_PSTATEIMM0_1_IMPL
#undef GET_RPRFM_DECL
#undef GET_RPRFM_IMPL
#undef GET_SVCR_DECL
#undef GET_SVCR_IMPL
#undef GET_SVEPREDPAT_DECL
#undef GET_SVEPREDPAT_IMPL
#undef GET_SVEPRFM_DECL
#undef GET_SVEPRFM_IMPL
#undef GET_SVEVECLENSPECIFIER_DECL
#undef GET_SVEVECLENSPECIFIER_IMPL
#undef GET_SYSREG_DECL
#undef GET_SYSREG_IMPL
#undef GET_TLBITable_DECL
#undef GET_TLBITable_IMPL
#undef GET_TSB_DECL
#undef GET_TSB_IMPL

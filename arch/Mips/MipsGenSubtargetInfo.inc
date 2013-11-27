/*===- TableGen'erated file -------------------------------------*- C++ -*-===*\
|*                                                                            *|
|*Subtarget Enumeration Source Fragment                                       *|
|*                                                                            *|
|* Automatically generated file, do not edit!                                 *|
|*                                                                            *|
\*===----------------------------------------------------------------------===*/

/* Capstone Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#ifdef GET_SUBTARGETINFO_ENUM
#undef GET_SUBTARGETINFO_ENUM
enum {
  Mips_FeatureBitCount =  1ULL << 0,
  Mips_FeatureCondMov =  1ULL << 1,
  Mips_FeatureDSP =  1ULL << 2,
  Mips_FeatureDSPR2 =  1ULL << 3,
  Mips_FeatureEABI =  1ULL << 4,
  Mips_FeatureFP64Bit =  1ULL << 5,
  Mips_FeatureFPIdx =  1ULL << 6,
  Mips_FeatureGP64Bit =  1ULL << 7,
  Mips_FeatureMSA =  1ULL << 8,
  Mips_FeatureMicroMips =  1ULL << 9,
  Mips_FeatureMips16 =  1ULL << 10,
  Mips_FeatureMips32 =  1ULL << 11,
  Mips_FeatureMips32r2 =  1ULL << 12,
  Mips_FeatureMips64 =  1ULL << 13,
  Mips_FeatureMips64r2 =  1ULL << 14,
  Mips_FeatureN32 =  1ULL << 15,
  Mips_FeatureN64 =  1ULL << 16,
  Mips_FeatureO32 =  1ULL << 17,
  Mips_FeatureSEInReg =  1ULL << 18,
  Mips_FeatureSingleFloat =  1ULL << 19,
  Mips_FeatureSwap =  1ULL << 20,
  Mips_FeatureVFPU =  1ULL << 21

};
#endif // GET_SUBTARGETINFO_ENUM

#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC

static SubtargetFeatureKV MipsFeatureKV[] = {
  { "FPIdx", "Enable 'FP indexed load/store' instructions.", Mips_FeatureFPIdx, 0ULL },
  { "bitcount", "Enable 'count leading bits' instructions.", Mips_FeatureBitCount, 0ULL },
  { "condmov", "Enable 'conditional move' instructions.", Mips_FeatureCondMov, 0ULL },
  { "dsp", "Mips DSP ASE", Mips_FeatureDSP, 0ULL },
  { "dspr2", "Mips DSP-R2 ASE", Mips_FeatureDSPR2, Mips_FeatureDSP },
  { "eabi", "Enable eabi ABI", Mips_FeatureEABI, 0ULL },
  { "fp64", "Support 64-bit FP registers.", Mips_FeatureFP64Bit, 0ULL },
  { "gp64", "General Purpose Registers are 64-bit wide.", Mips_FeatureGP64Bit, 0ULL },
  { "micromips", "microMips mode", Mips_FeatureMicroMips, 0ULL },
  { "mips16", "Mips16 mode", Mips_FeatureMips16, 0ULL },
  { "mips32", "Mips32 ISA Support", Mips_FeatureMips32, Mips_FeatureCondMov | Mips_FeatureBitCount },
  { "mips32r2", "Mips32r2 ISA Support", Mips_FeatureMips32r2, Mips_FeatureMips32 | Mips_FeatureSEInReg | Mips_FeatureSwap | Mips_FeatureFPIdx },
  { "mips64", "Mips64 ISA Support", Mips_FeatureMips64, Mips_FeatureGP64Bit | Mips_FeatureFP64Bit | Mips_FeatureMips32 | Mips_FeatureFPIdx },
  { "mips64r2", "Mips64r2 ISA Support", Mips_FeatureMips64r2, Mips_FeatureMips64 | Mips_FeatureMips32r2 },
  { "msa", "Mips MSA ASE", Mips_FeatureMSA, 0ULL },
  { "n32", "Enable n32 ABI", Mips_FeatureN32, 0ULL },
  { "n64", "Enable n64 ABI", Mips_FeatureN64, 0ULL },
  { "o32", "Enable o32 ABI", Mips_FeatureO32, 0ULL },
  { "seinreg", "Enable 'signext in register' instructions.", Mips_FeatureSEInReg, 0ULL },
  { "single-float", "Only supports single precision float", Mips_FeatureSingleFloat, 0ULL },
  { "swap", "Enable 'byte/half swap' instructions.", Mips_FeatureSwap, 0ULL },
  { "vfpu", "Enable vector FPU instructions.", Mips_FeatureVFPU, 0ULL }
};

#endif // GET_SUBTARGETINFO_MC_DESC

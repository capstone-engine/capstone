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
  AArch64_FeatureCrypto =  1ULL << 0,
  AArch64_FeatureFPARMv8 =  1ULL << 1,
  AArch64_FeatureNEON =  1ULL << 2
};
#endif // GET_SUBTARGETINFO_ENUM


#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC

// Sorted (by key) array of values for CPU features.
static SubtargetFeatureKV AArch64FeatureKV[] = {
  { "crypto", "Enable cryptographic instructions", AArch64_FeatureCrypto, 0ULL },
  { "fp-armv8", "Enable ARMv8 FP", AArch64_FeatureFPARMv8, 0ULL },
  { "neon", "Enable Advanced SIMD instructions", AArch64_FeatureNEON, AArch64_FeatureFPARMv8 }
};

#endif // GET_SUBTARGETINFO_MC_DESC

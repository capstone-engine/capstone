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

#define ARM_FeatureAClass 1ULL << 0
#define ARM_FeatureAvoidMOVsShOp 1ULL << 1
#define ARM_FeatureAvoidPartialCPSR 1ULL << 2
#define ARM_FeatureCrypto 1ULL << 3
#define ARM_FeatureD16 1ULL << 4
#define ARM_FeatureDB 1ULL << 5
#define ARM_FeatureDSPThumb2 1ULL << 6
#define ARM_FeatureFP16 1ULL << 7
#define ARM_FeatureFPARMv8 1ULL << 8
#define ARM_FeatureHWDiv 1ULL << 9
#define ARM_FeatureHWDivARM 1ULL << 10
#define ARM_FeatureHasRAS 1ULL << 11
#define ARM_FeatureHasSlowFPVMLx 1ULL << 12
#define ARM_FeatureMClass 1ULL << 13
#define ARM_FeatureMP 1ULL << 14
#define ARM_FeatureNEON 1ULL << 15
#define ARM_FeatureNEONForFP 1ULL << 16
#define ARM_FeatureNaClTrap 1ULL << 17
#define ARM_FeatureNoARM 1ULL << 18
#define ARM_FeaturePerfMon 1ULL << 19
#define ARM_FeaturePref32BitThumb 1ULL << 20
#define ARM_FeatureRClass 1ULL << 21
#define ARM_FeatureSlowFPBrcc 1ULL << 22
#define ARM_FeatureT2XtPk 1ULL << 23
#define ARM_FeatureThumb2 1ULL << 24
#define ARM_FeatureTrustZone 1ULL << 25
#define ARM_FeatureVFP2 1ULL << 26
#define ARM_FeatureVFP3 1ULL << 27
#define ARM_FeatureVFP4 1ULL << 28
#define ARM_FeatureVFPOnlySP 1ULL << 29
#define ARM_FeatureVMLxForwarding 1ULL << 30
#define ARM_HasV4TOps 1ULL << 31
#define ARM_HasV5TEOps 1ULL << 32
#define ARM_HasV5TOps 1ULL << 33
#define ARM_HasV6Ops 1ULL << 34
#define ARM_HasV6T2Ops 1ULL << 35
#define ARM_HasV7Ops 1ULL << 36
#define ARM_HasV8Ops 1ULL << 37
#define ARM_ModeThumb 1ULL << 38
#define ARM_ProcA5 1ULL << 39
#define ARM_ProcA8 1ULL << 40
#define ARM_ProcA9 1ULL << 41
#define ARM_ProcA15 1ULL << 42
#define ARM_ProcR5 1ULL << 43
#define ARM_ProcSwift 1ULL << 44

#endif // GET_SUBTARGETINFO_ENUM

#ifdef GET_SUBTARGETINFO_MC_DESC
#undef GET_SUBTARGETINFO_MC_DESC
// Sorted (by key) array of values for CPU features.

static SubtargetFeatureKV ARMFeatureKV[] = {
  { "32bit", "Prefer 32-bit Thumb instrs", ARM_FeaturePref32BitThumb, 0ULL },
  { "a15", "Cortex-A15 ARM processors", ARM_ProcA15, ARM_FeatureT2XtPk | ARM_FeatureVFP4 | ARM_FeatureAvoidPartialCPSR | ARM_FeatureTrustZone },
  { "a5", "Cortex-A5 ARM processors", ARM_ProcA5, ARM_FeatureSlowFPBrcc | ARM_FeatureHasSlowFPVMLx | ARM_FeatureVMLxForwarding | ARM_FeatureT2XtPk | ARM_FeatureTrustZone },
  { "a8", "Cortex-A8 ARM processors", ARM_ProcA8, ARM_FeatureSlowFPBrcc | ARM_FeatureHasSlowFPVMLx | ARM_FeatureVMLxForwarding | ARM_FeatureT2XtPk | ARM_FeatureTrustZone },
  { "a9", "Cortex-A9 ARM processors", ARM_ProcA9, ARM_FeatureVMLxForwarding | ARM_FeatureT2XtPk | ARM_FeatureFP16 | ARM_FeatureAvoidPartialCPSR | ARM_FeatureTrustZone },
  { "aclass", "Is application profile ('A' series)", ARM_FeatureAClass, 0ULL },
  { "avoid-movs-shop", "Avoid movs instructions with shifter operand", ARM_FeatureAvoidMOVsShOp, 0ULL },
  { "avoid-partial-cpsr", "Avoid CPSR partial update for OOO execution", ARM_FeatureAvoidPartialCPSR, 0ULL },
  { "crypto", "Enable support for Cryptography extensions", ARM_FeatureCrypto, ARM_FeatureNEON },
  { "d16", "Restrict VFP3 to 16 double registers", ARM_FeatureD16, 0ULL },
  { "db", "Has data barrier (dmb / dsb) instructions", ARM_FeatureDB, 0ULL },
  { "fp-armv8", "Enable ARMv8 FP", ARM_FeatureFPARMv8, ARM_FeatureVFP4 },
  { "fp-only-sp", "Floating point unit supports single precision only", ARM_FeatureVFPOnlySP, 0ULL },
  { "fp16", "Enable half-precision floating point", ARM_FeatureFP16, 0ULL },
  { "hwdiv", "Enable divide instructions", ARM_FeatureHWDiv, 0ULL },
  { "hwdiv-arm", "Enable divide instructions in ARM mode", ARM_FeatureHWDivARM, 0ULL },
  { "mclass", "Is microcontroller profile ('M' series)", ARM_FeatureMClass, 0ULL },
  { "mp", "Supports Multiprocessing extension", ARM_FeatureMP, 0ULL },
  { "nacl-trap", "NaCl trap", ARM_FeatureNaClTrap, 0ULL },
  { "neon", "Enable NEON instructions", ARM_FeatureNEON, ARM_FeatureVFP3 },
  { "neonfp", "Use NEON for single precision FP", ARM_FeatureNEONForFP, 0ULL },
  { "noarm", "Does not support ARM mode execution", ARM_FeatureNoARM, ARM_ModeThumb },
  { "perfmon", "Enable support for Performance Monitor extensions", ARM_FeaturePerfMon, 0ULL },
  { "r5", "Cortex-R5 ARM processors", ARM_ProcR5, ARM_FeatureSlowFPBrcc | ARM_FeatureHWDiv | ARM_FeatureHWDivARM | ARM_FeatureHasSlowFPVMLx | ARM_FeatureAvoidPartialCPSR | ARM_FeatureT2XtPk },
  { "ras", "Has return address stack", ARM_FeatureHasRAS, 0ULL },
  { "rclass", "Is realtime profile ('R' series)", ARM_FeatureRClass, 0ULL },
  { "slow-fp-brcc", "FP compare + branch is slow", ARM_FeatureSlowFPBrcc, 0ULL },
  { "slowfpvmlx", "Disable VFP / NEON MAC instructions", ARM_FeatureHasSlowFPVMLx, 0ULL },
  { "swift", "Swift ARM processors", ARM_ProcSwift, ARM_FeatureNEONForFP | ARM_FeatureT2XtPk | ARM_FeatureVFP4 | ARM_FeatureMP | ARM_FeatureHWDiv | ARM_FeatureHWDivARM | ARM_FeatureAvoidPartialCPSR | ARM_FeatureAvoidMOVsShOp | ARM_FeatureHasSlowFPVMLx | ARM_FeatureTrustZone },
  { "t2dsp", "Supports v7 DSP instructions in Thumb2", ARM_FeatureDSPThumb2, 0ULL },
  { "t2xtpk", "Enable Thumb2 extract and pack instructions", ARM_FeatureT2XtPk, 0ULL },
  { "thumb-mode", "Thumb mode", ARM_ModeThumb, 0ULL },
  { "thumb2", "Enable Thumb2 instructions", ARM_FeatureThumb2, 0ULL },
  { "trustzone", "Enable support for TrustZone security extensions", ARM_FeatureTrustZone, 0ULL },
  { "v4t", "Support ARM v4T instructions", ARM_HasV4TOps, 0ULL },
  { "v5t", "Support ARM v5T instructions", ARM_HasV5TOps, ARM_HasV4TOps },
  { "v5te", "Support ARM v5TE, v5TEj, and v5TExp instructions", ARM_HasV5TEOps, ARM_HasV5TOps },
  { "v6", "Support ARM v6 instructions", ARM_HasV6Ops, ARM_HasV5TEOps },
  { "v6t2", "Support ARM v6t2 instructions", ARM_HasV6T2Ops, ARM_HasV6Ops | ARM_FeatureThumb2 },
  { "v7", "Support ARM v7 instructions", ARM_HasV7Ops, ARM_HasV6T2Ops | ARM_FeaturePerfMon },
  { "v8", "Support ARM v8 instructions", ARM_HasV8Ops, ARM_HasV7Ops },
  { "vfp2", "Enable VFP2 instructions", ARM_FeatureVFP2, 0ULL },
  { "vfp3", "Enable VFP3 instructions", ARM_FeatureVFP3, ARM_FeatureVFP2 },
  { "vfp4", "Enable VFP4 instructions", ARM_FeatureVFP4, ARM_FeatureVFP3 | ARM_FeatureFP16 },
  { "vmlx-forwarding", "Has multiplier accumulator forwarding", ARM_FeatureVMLxForwarding, 0ULL }
};

#endif // GET_SUBTARGETINFO_MC_DESC

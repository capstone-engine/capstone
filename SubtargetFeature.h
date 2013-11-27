//===-- llvm/MC/SubtargetFeature.h - CPU characteristics --------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines and manages user or tool specified CPU characteristics.
// The intent is to be able to package specific features that should or should
// not be used on a specific target processor.  A tool, such as llc, could, as
// as example, gather chip info from the command line, a long with features
// that should be used on that chip.
//
//===----------------------------------------------------------------------===//

/* Second-Best Disassembler Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013> */

#ifndef CS_LLVM_MC_SUBTARGETFEATURE_H
#define CS_LLVM_MC_SUBTARGETFEATURE_H

//===----------------------------------------------------------------------===//
///
/// SubtargetFeatureKV - Used to provide key value pairs for feature and
/// CPU bit flags.
//
typedef struct SubtargetFeatureKV {
  char *Key;                      // K-V key string
  char *Desc;                     // Help descriptor
  const uint64_t Value;                 // K-V integer value
  const uint64_t Implies;               // K-V bit mask
} SubtargetFeatureKV;

#endif

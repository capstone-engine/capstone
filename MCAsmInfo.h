// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

/// The equivalent of the MCAsmInfo class in LLVM.
/// We save only some flags of the original class here.

#ifndef CS_MCASMINFO_H
#define CS_MCASMINFO_H

typedef enum {
  SYSTEMZASMDIALECT_AD_ATT = 0,
  SYSTEMZASMDIALECT_AD_HLASM = 1,
} MCAsmInfoAssemblerDialect;

typedef struct {
  MCAsmInfoAssemblerDialect assemblerDialect;
} MCAsmInfo;

#endif // CS_MCASMINFO_H

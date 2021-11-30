//===------ PPCDisassembler.cpp - Disassembler for PowerPC ------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2015 */

#ifdef CAPSTONE_HAS_POWERPC

#include <stdio.h> // DEBUG
#include <stdlib.h>
#include <string.h>

#include "../../cs_priv.h"
#include "../../utils.h"

#include "PPCDisassembler.h"

#include "../../MCDisassembler.h"
#include "../../MCFixedLenDisassembler.h"
#include "../../MCInst.h"
#include "../../MCInstrDesc.h"
#include "../../MCRegisterInfo.h"
#include "../../MathExtras.h"

// Currently, we have no feature checks upon PPC, but there might be later, so
// dummy
static inline unsigned checkFeatureRequired(unsigned Bits, unsigned Feature,
                                            bool Require) {
  // extended from original arm module
  return Require;
}

#define DecodePointerLikeRegClass0 DecodeGPRCRegisterClass
#define DecodePointerLikeRegClass1 DecodeGPRC_NOR0RegisterClass

#include "CapstonePPCModule.h"

// FIXME: These can be generated by TableGen from the existing register
// encoding values!

#if 0
static uint64_t getFeatureBits(int feature)
{
	// enable all features
	return (uint64_t)-1;
}
#endif

static DecodeStatus getInstruction(MCInst *MI, const uint8_t *code,
                                   size_t code_len, uint16_t *Size,
                                   uint64_t Address, MCRegisterInfo *MRI) {
  uint32_t insn;
  DecodeStatus result;

  // Get the four bytes of the instruction.
  if (code_len < 4) {
    // not enough data
    *Size = 0;
    return MCDisassembler_Fail;
  }

  // The instruction is big-endian encoded.
  if (MODE_IS_BIG_ENDIAN(MI->csh->mode))
    insn = ((uint32_t)code[0] << 24) | (code[1] << 16) | (code[2] << 8) |
           (code[3] << 0);
  else // little endian
    insn = ((uint32_t)code[3] << 24) | (code[2] << 16) | (code[1] << 8) |
           (code[0] << 0);

  if (MI->flat_insn->detail) {
    memset(MI->flat_insn->detail, 0, offsetof(cs_detail, ppc) + sizeof(cs_ppc));
  }

  if (MI->csh->mode & CS_MODE_QPX) {
    // fixme what exactly is qpx
    //		result = decodeInstruction(DecoderTableQPX32, MI, insn,
    // Address);
    if (result != MCDisassembler_Fail) {
      *Size = 4;

      return result;
    }

    // failed to decode
    MCInst_clear(MI);
  } else if (MI->csh->mode & CS_MODE_SPE) {
    result = decodeInstruction4(DecoderTableSPE32, MI, insn, Address, 0, 0);
    if (result != MCDisassembler_Fail) {
      *Size = 4;

      return result;
    }

    // failed to decode
    MCInst_clear(MI);
  }

  result = decodeInstruction4(DecoderTable32, MI, insn, Address, 0, 0);
  if (result != MCDisassembler_Fail) {
    *Size = 4;

    return result;
  }

  // cannot decode, report error
  MCInst_clear(MI);
  *Size = 0;

  return MCDisassembler_Fail;
}

bool PPC_getInstruction(csh ud, const uint8_t *code, size_t code_len,
                        MCInst *instr, uint16_t *size, uint64_t address,
                        void *info) {
  DecodeStatus status = getInstruction(instr, code, code_len, size, address,
                                       (MCRegisterInfo *)info);

  return status == MCDisassembler_Success;
}

void PPC_init(MCRegisterInfo *MRI) {
  /*
     InitMCRegisterInfo(PPCRegDesc, 344,
     RA, PC,
     PPCMCRegisterClasses, 36,
     PPCRegUnitRoots, 171, PPCRegDiffLists, PPCLaneMaskLists, PPCRegStrings,
     PPCRegClassStrings, PPCSubRegIdxLists, 7, PPCSubRegIdxRanges,
     PPCRegEncodingTable);
   */

  MCRegisterInfo_InitMCRegisterInfo(
      MRI, PPCRegDesc, ARR_SIZE(PPCRegDesc), 0, 0, PPCMCRegisterClasses,
      ARR_SIZE(PPCMCRegisterClasses), 0, 0, PPCRegDiffLists, 0,
      PPCSubRegIdxLists, ARR_SIZE(PPCSubRegIdxLists), 0);
}

#endif

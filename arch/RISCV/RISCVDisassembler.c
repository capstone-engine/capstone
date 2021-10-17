//===-- RISCVDisassembler.cpp - Disassembler for RISCV --------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembly Engine */
/* RISC-V Backend By Rodrigo Cortes Porto <porto703@gmail.com> & 
   Shawn Chang <citypw@gmail.com>, HardenedLinux@2018 */
    
#ifdef CAPSTONE_HAS_RISCV

#include <stdio.h>		// DEBUG
#include <stdlib.h>
#include <string.h>

#include "../../cs_priv.h"
#include "../../utils.h"

#include "../../MCInst.h"
#include "../../MCInstrDesc.h"
#include "../../MCFixedLenDisassembler.h"
#include "../../MCRegisterInfo.h"
#include "../../MCDisassembler.h"
#include "../../MathExtras.h"
#include "RISCVBaseInfo.h"
#include "RISCVDisassembler.h"


/* Need the feature infos define in 
  RISCVGenSubtargetInfo.inc. */
#define GET_SUBTARGETINFO_ENUM
#include "RISCVGenSubtargetInfo.inc"

/* When we specify the RISCV64 mode, It means It is RV64IMAFD.
  Similar, RISCV32 means RV32IMAFD.
//*/
static uint64_t getFeatureBits(int mode)
{
	uint64_t ret = RISCV_FeatureStdExtM | RISCV_FeatureStdExtA |
		       RISCV_FeatureStdExtF | RISCV_FeatureStdExtD ;

	if (mode & CS_MODE_RISCV64)
		ret |= RISCV_Feature64Bit;
	if (mode & CS_MODE_RISCVC)
		ret |= RISCV_FeatureStdExtC;

	return ret;
}

static inline unsigned checkFeatureRequired(unsigned Bits, unsigned Feature, bool Require) ;

#include "CapstoneRISCVModule.h"

static inline unsigned checkFeatureRequired(unsigned Bits, unsigned Feature, bool Require) {
  switch (Feature) {
  case RISCV_FeatureStdExtM:
  case RISCV_FeatureStdExtA:
  case RISCV_FeatureStdExtF:
  case RISCV_FeatureStdExtD:
    return Require;
  case RISCV_Feature64Bit: // In no case should we simplify this branch, since 'bool' here is a dummy macro
    if(Bits & CS_MODE_RISCV64)
      return Require;
    else
      return !Require;
  case RISCV_FeatureStdExtC:
    if(Bits & CS_MODE_RISCVC)
      return Require;
    else
      return !Require;
  }
  return Require; // return true for all other conds
}

static void init_MI_insn_detail(MCInst *MI) 
{
  	if (MI->flat_insn->detail) {
    		memset(MI->flat_insn->detail, 0, sizeof(cs_detail));
  	}

  	return;
}

// mark the load/store instructions through the opcode.
static void markLSInsn(MCInst *MI, uint32_t in)
{
	/* 
	   I   ld 0000011 = 0x03
	       st 0100011 = 0x23
	   F/D ld 0000111 = 0x07
	       st 0100111 = 0x27
	*/
#define MASK_LS_INSN 0x0000007f
	uint32_t opcode = in & MASK_LS_INSN;
	if (0 == (opcode ^ 0x03) || 0 == (opcode ^ 0x07) ||
	    0 == (opcode ^ 0x23) || 0 == (opcode ^ 0x27))
		MI->flat_insn->detail->riscv.need_effective_addr = true;
#undef MASK_LS_INSN
	return;
}

static DecodeStatus RISCVDisassembler_getInstruction(int mode, MCInst *MI,
				 const uint8_t *code, size_t code_len,
				 uint16_t *Size, uint64_t Address,
				 MCRegisterInfo *MRI) 
{
  	// TODO: This will need modification when supporting instruction set
  	// extensions with instructions > 32-bits (up to 176 bits wide).
  	uint32_t Inst = 0;
  	DecodeStatus Result;

  	// It's a 32 bit instruction if bit 0 and 1 are 1.
  	if ((code[0] & 0x3) == 0x3) {
      		if (code_len < 4) {
        		*Size = 0;
        		return MCDisassembler_Fail;
      		}

      		*Size = 4;
      		// Get the four bytes of the instruction.
      		//Encoded as little endian 32 bits.
      		Inst = code[0] | (code[1] << 8) | (code[2] << 16) | ((uint32_t)code[3] << 24);
		init_MI_insn_detail(MI);
		// Now we need mark what instruction need fix effective address output.
    		if (MI->csh->detail) 
			markLSInsn(MI, Inst);
      		Result = decodeInstruction(DecoderTable32, MI, Inst, Address, MRI, mode);
  	} else {
    		if (code_len < 2) {
      			*Size = 0;
      			return MCDisassembler_Fail;
    		}

		// If not b4bit.
    		if (! (getFeatureBits(mode) & ((uint64_t)RISCV_Feature64Bit))) {
      			// Trying RISCV32Only_16 table (16-bit Instruction)
      			Inst = code[0] | (code[1] << 8);
      			init_MI_insn_detail(MI);
      			Result = decodeInstruction(DecoderTableRISCV32Only_16, MI, Inst, Address,
                                 	   	   MRI, mode);
      			if (Result != MCDisassembler_Fail) {
        			*Size = 2;
        			return Result;
      			}
    		}
    
    		// Trying RISCV_C table (16-bit Instruction)
    		Inst = code[0] | (code[1] << 8);
    		init_MI_insn_detail(MI);
    		// Calling the auto-generated decoder function.
    		Result = decodeInstruction(DecoderTable16, MI, Inst, Address, MRI, mode);
    		*Size = 2;
  	}

  	return Result;
}

bool RISCV_getInstruction(csh ud, const uint8_t *code, size_t code_len,
		          MCInst *instr, uint16_t *size, uint64_t address,
		          void *info) 
{
  	cs_struct *handle = (cs_struct *)(uintptr_t)ud;

  	return MCDisassembler_Success == 
	   	RISCVDisassembler_getInstruction(handle->mode, instr,
				            	 code, code_len,
			                    	 size, address,
			                    	 (MCRegisterInfo *)info);

}

void RISCV_init(MCRegisterInfo * MRI) 
{
  	/*
  	InitMCRegisterInfo(RISCVRegDesc, 97, RA, PC,
                     RISCVMCRegisterClasses, 11,
                     RISCVRegUnitRoots,
                     64,
                     RISCVRegDiffLists,
                     RISCVLaneMaskLists,
                     RISCVRegStrings,
                     RISCVRegClassStrings,
                     RISCVSubRegIdxLists,
                     2,
                     RISCVSubRegIdxRanges,
                     RISCVRegEncodingTable);
  	*/

  	MCRegisterInfo_InitMCRegisterInfo(MRI, RISCVRegDesc, 97, 0, 0,
				    	  RISCVMCRegisterClasses, 11,
				          0, 
				          0,
				          RISCVRegDiffLists,
				          0, 
				          RISCVSubRegIdxLists, 
				          2, 
				          0);
}

#endif

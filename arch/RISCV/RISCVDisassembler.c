//===-- RISCVDisassembler.cpp - Disassembler for RISCV --------------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifdef CAPSTONE_HAS_RISCV

#include <stdio.h>	// DEBUG
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

static uint64_t getFeatureBits(int mode)
{
	// support everything
	return (uint64_t)-1;
}

//ToDo: Confirm the values for the RISCV_init, refer to RISCVGenRegisterInfo.inc file (in capstone arch/ ) and MCRegisterInfo.h from capstone
//Specifically confirm the values for RISCVRegUnitRoots, 64,
void RISCV_init(MCRegisterInfo *MRI)
{
	/*InitMCRegisterInfo(RISCVRegDesc, 97, RA, PC,
                     RISCVMCRegisterClasses, 3,
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
	
	MCRegisterInfo_InitMCRegisterInfo(MRI, RISCVRegDesc, 97,
			0, 0,
			RISCVMCRegisterClasses, 3,
			0, 0,
			RISCVRegDiffLists,
			0,
			RISCVSubRegIdxLists, 2,
			0);
}

//Todo: decodeInstruction is included in "RISCVGenDisassemblerTables.inc" - Need to include it and make any necessary changes in parameters as done in Mips or ARM. 
//Todo: After verifying correct functionality, change the functions to #define directives (see the .inc of Mips or ARM).
//in .inc, all the calls to MCInst functions like MI.setOpcode(Opc); need to be replaced by MCInst_setOpcode(MI, Opc) and pass MI as *MI and not &MI
static DecodeStatus RISCVDisassembler_getInstruction(MCInst &MI, uint64_t &Size,
                                               ArrayRef<uint8_t> Bytes,
                                               uint64_t Address,
                                               raw_ostream &OS,
                                               raw_ostream &CS) const {
  // TODO: although assuming 4-byte instructions is sufficient for RV32 and
  // RV64, this will need modification when supporting the compressed
  // instruction set extension (RVC) which uses 16-bit instructions. Other
  // instruction set extensions have the option of defining instructions up to
  // 176 bits wide.
  Size = 4;
  if (Bytes.size() < 4) {
    Size = 0;
    return MCDisassembler::Fail;
  }

  // Get the four bytes of the instruction.
  uint32_t Inst = support::endian::read32le(Bytes.data());

  return decodeInstruction(DecoderTable32, MI, Inst, Address, this, STI);
}

	
bool RISCV_getInstruction(csh ud, const uint8_t *code, size_t code_len, MCInst *instr,
		uint16_t *size, uint64_t address, void *info)
{
	cs_struct *handle = (cs_struct *)(uintptr_t)ud;

	/*DecodeStatus status = RISCVDisassembler_getInstruction(handle->mode, instr,
			code, code_len,
			size,
			address, handle->big_endian, (MCRegisterInfo *)info);
			*/

	return status == MCDisassembler_Success;
}

#endif

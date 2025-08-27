/* Capstone Disassembly Engine */
/* By Dmitry Sibirtsev  <sibirtsevdl@gmail.com>, 2023 */

#ifdef CAPSTONE_HAS_ALPHA

#include <stdio.h> // DEBUG
#include <stdlib.h>
#include <string.h>

#include "../../utils.h"

#include "../../MCFixedLenDisassembler.h"
#include "../../Mapping.h"

#include "AlphaDisassembler.h"
#include "AlphaLinkage.h"

static DecodeStatus DecodeGPRCRegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    const void *Decoder);

static DecodeStatus DecodeF4RCRegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    const void *Decoder);

static DecodeStatus DecodeF8RCRegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    const void *Decoder);

#include "AlphaGenDisassemblerTables.inc"

#define GET_REGINFO_ENUM
#define GET_REGINFO_MC_DESC

#include "AlphaGenRegisterInfo.inc"

static DecodeStatus DecodeGPRCRegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;

	unsigned Register = GPRC[RegNo];
	MCOperand_CreateReg0(Inst, (Register));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeF4RCRegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;

	unsigned Register = F4RC[RegNo];
	MCOperand_CreateReg0(Inst, (Register));
	return MCDisassembler_Success;
}

static DecodeStatus DecodeF8RCRegisterClass(MCInst *Inst, unsigned RegNo,
					    uint64_t Address,
					    const void *Decoder)
{
	if (RegNo > 31)
		return MCDisassembler_Fail;

	unsigned Register = F8RC[RegNo];
	MCOperand_CreateReg0(Inst, (Register));
	return MCDisassembler_Success;
}

#define GET_SUBTARGETINFO_ENUM

#include "AlphaGenInstrInfo.inc"

DecodeStatus Alpha_LLVM_getInstruction(csh handle, const uint8_t *Bytes,
				       size_t ByteLen, MCInst *MI,
				       uint16_t *Size, uint64_t Address,
				       void *Info)
{
	if (!handle) {
		return MCDisassembler_Fail;
	}

	if (ByteLen < 4) {
		*Size = 0;
		return MCDisassembler_Fail;
	}

	uint32_t Insn = readBytes32(MI, Bytes);
	// Calling the auto-generated decoder function.
	DecodeStatus Result =
		decodeInstruction_4(DecoderTable32, MI, Insn, Address, NULL);

	if (Result != MCDisassembler_Fail) {
		*Size = 4;
		return Result;
	}

	*Size = 4;
	return MCDisassembler_Fail;
}

void Alpha_init(MCRegisterInfo *MRI)
{
	MCRegisterInfo_InitMCRegisterInfo(
		MRI, AlphaRegDesc, ARR_SIZE(AlphaRegDesc), 0, 0,
		AlphaMCRegisterClasses, ARR_SIZE(AlphaMCRegisterClasses), 0, 0,
		AlphaRegDiffLists, 0, AlphaSubRegIdxLists, 1, 0);
}

#endif
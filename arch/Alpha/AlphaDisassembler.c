#ifdef CAPSTONE_HAS_ALPHA

#include <stdio.h> // DEBUG
#include <stdlib.h>
#include <string.h>

#include "../../utils.h"

#include "../../MCFixedLenDisassembler.h"
#include "../../MCDisassembler.h"

static bool readInstruction32(const uint8_t *code, size_t code_len,
			      uint32_t *insn)
{
	if (code_len < 4)
		// insufficient data
		return false;

	// Encoded as a little-endian 32-bit word in the stream.
	*insn = (code[0] << 0) | (code[1] << 8) | (code[2] << 16) |
		(code[3] << 24);

	return true;
}

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

static inline bool tryGetInstruction32(const uint8_t *code, size_t code_len,
				       MCInst *MI, uint16_t *size,
				       uint64_t address, void *info,
				       const uint8_t *decoderTable32)
{
	uint32_t insn32;
	DecodeStatus Result;
	if (!readInstruction32(code, code_len, &insn32)) {
		return false;
	}
	// Calling the auto-generated decoder function.
	Result = decodeInstruction_4(decoderTable32, MI, insn32, address, NULL);
	if (Result != MCDisassembler_Fail) {
		*size = 4;
		return true;
	}
	return false;
}

bool Alpha_getInstruction(csh handle, const uint8_t *Bytes, size_t ByteLen,
							      MCInst *MI, uint16_t *Size, uint64_t Address,
							      void *Info) 
{
    if (!handle) {
		return false;
	}

	if (MI->flat_insn->detail) {
		memset(MI->flat_insn->detail, 0, sizeof(cs_detail));
	} 

	if (ByteLen < 4) {
		return MCDisassembler_Fail;
	}
	return tryGetInstruction32(Bytes, ByteLen, MI, Size, Address, Info,
				   DecoderTable32);

}

void Alpha_init(MCRegisterInfo *MRI)
{
	MCRegisterInfo_InitMCRegisterInfo(
		MRI, AlphaRegDesc, ARR_SIZE(AlphaRegDesc), 0, 0,
		AlphaMCRegisterClasses, ARR_SIZE(AlphaMCRegisterClasses), 0,
		0, AlphaRegDiffLists, 0, AlphaSubRegIdxLists, 1, 0);
}

#endif
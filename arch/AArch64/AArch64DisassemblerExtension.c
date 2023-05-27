/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */
/*    Rot127 <unisono@quyllur.org>, 2022-2023 */

#include "AArch64DisassemblerExtension.h"
#include "AArch64BaseInfo.h"

bool AArch64_getFeatureBits(unsigned int mode, unsigned int feature)
{
	// we support everything
	return true;
}

bool Check(DecodeStatus *Out, DecodeStatus In)
{
	switch (In) {
	case MCDisassembler_Success:
		// Out stays the same.
		return true;
	case MCDisassembler_SoftFail:
		*Out = In;
		return true;
	case MCDisassembler_Fail:
		*Out = In;
		return false;
	default: // never reached
		return false;
	}
}

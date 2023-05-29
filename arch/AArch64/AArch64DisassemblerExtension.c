/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */
/*    Rot127 <unisono@quyllur.org>, 2022-2023 */

#include "AArch64DisassemblerExtension.h"
#include "AArch64BaseInfo.h"

bool AArch64_getFeatureBits(unsigned int mode, arm64_insn_group feature)
{
	// we support everything
	return true;
}

/// Tests a NULL terminated array of features if they are enabled.
bool AArch64_testFeatureList(unsigned int mode, const arm64_insn_group *features)
{
	int i = 0;
	while (features[i]) {
		if (!AArch64_getFeatureBits(mode, features[i]))
			return false;
	}
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

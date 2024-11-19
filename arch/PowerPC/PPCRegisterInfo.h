/* Capstone Disassembly Engine, http://www.capstone-engine.org */
/* By Rot127 <unisono@quyllur.org> 2022-2023 */

#ifndef CS_PPC_REGISTERINFO_H
#define CS_PPC_REGISTERINFO_H

#include "PPCMCTargetDesc.h"

/// stripRegisterPrefix - This method strips the character prefix from a
/// register name so that only the number is left.  Used by for linux asm.
static const char *PPCRegisterInfo_stripRegisterPrefix(const char *RegName)
{
	switch (RegName[0]) {
	case 'a':
		if (RegName[1] == 'c' && RegName[2] == 'c')
			return RegName + 3;
		break;
	case 'f':
		if (RegName[1] == 'p')
			return RegName + 2;
		// fallthrough
	case 'r':
	case 'v':
		if (RegName[1] == 's') {
			if (RegName[2] == 'p')
				return RegName + 3;
			return RegName + 2;
		}
		return RegName + 1;
	case 'c':
		if (RegName[1] == 'r')
			return RegName + 2;
		break;
	case 'w':
		// For wacc and wacc_hi
		if (RegName[1] == 'a' && RegName[2] == 'c' &&
		    RegName[3] == 'c') {
			if (RegName[4] == '_')
				return RegName + 7;
			else
				return RegName + 4;
		}
		break;
	case 'd':
		// For dmr, dmrp, dmrrow, dmrrowp
		if (RegName[1] == 'm' && RegName[2] == 'r') {
			if (RegName[3] == 'r' && RegName[4] == 'o' &&
			    RegName[5] == 'w' && RegName[6] == 'p')
				return RegName + 7;
			else if (RegName[3] == 'r' && RegName[4] == 'o' &&
				 RegName[5] == 'w')
				return RegName + 6;
			else if (RegName[3] == 'p')
				return RegName + 4;
			else
				return RegName + 3;
		}
		break;
	}

	return RegName;
}

#endif // CS_PPC_REGISTERINFO_H

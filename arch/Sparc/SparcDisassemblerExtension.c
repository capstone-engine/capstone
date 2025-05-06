/* Capstone Disassembly Engine */
/* By Rot127 <unisono@quyllur.org>, 2025 */

#include "SparcDisassemblerExtension.h"
#include "SparcMCTargetDesc.h"

bool Sparc_getFeatureBits(unsigned int mode, unsigned int feature)
{
	if (feature == Sparc_FeatureV9) {
		return mode & CS_MODE_V9;
	}
	return true;
}

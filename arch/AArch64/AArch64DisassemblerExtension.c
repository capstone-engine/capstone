/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */
/*    Rot127 <unisono@quyllur.org>, 2022-2023 */

#include "AArch64DisassemblerExtension.h"
#include "AArch64BaseInfo.h"

bool AArch64_getFeatureBits(unsigned int mode, unsigned int feature)
{
	if (feature == AArch64_FeatureAMX || feature == AArch64_FeatureMUL53 ||
			feature == AArch64_FeatureAppleSys) {
		return mode & CS_MODE_APPLE_PROPRIETARY;
	}
	// we support everything
	return true;
}

/// Tests a NULL terminated array of features if they are enabled.
bool AArch64_testFeatureList(unsigned int mode, const unsigned int *features)
{
	int i = 0;
	while (features[i]) {
		if (!AArch64_getFeatureBits(mode, features[i]))
			return false;
		++i;
	}
	return true;
}

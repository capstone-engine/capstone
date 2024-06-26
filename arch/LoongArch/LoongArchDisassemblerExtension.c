/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2019 */
/*    Rot127 <unisono@quyllur.org>, 2022-2023 */
/*    Jiajie Chen <c@jia.je>, 2024 */
/*    Yanglin Xun <1109673069@qq.com>, 2024 */

#include <capstone/loongarch.h>

#include "LoongArchDisassemblerExtension.h"

#define GET_SUBTARGETINFO_ENUM
#include "LoongArchGenSubtargetInfo.inc"

bool LoongArch_getFeatureBits(unsigned int mode, unsigned int feature)
{
	// handle loongarch32/64
	if (feature == LoongArch_Feature64Bit) {
		if (mode & CS_MODE_LOONGARCH64)
			return true;
		return false;
	}

	// otherwise we support everything
	return true;
}
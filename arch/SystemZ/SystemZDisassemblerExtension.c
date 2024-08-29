/* Capstone Disassembly Engine */
/* By Rot127 <unisono@quyllur.org>, 2022-2023 */

#include <capstone/systemz.h>
#include "SystemZDisassemblerExtension.h"
#include "../../utils.h"

bool SystemZ_getFeatureBits(unsigned int mode, unsigned int feature) {
	switch (mode) {
	case CS_MODE_SYSTEMZ_ARCH14:
	case CS_MODE_SYSTEMZ_Z16:
		if (arr_exist((uint16_t *)systemz_arch14_features, ARR_SIZE(systemz_arch14_features), feature)) {
			return true;
		}
		// fallthrough
	case CS_MODE_SYSTEMZ_ARCH13:
	case CS_MODE_SYSTEMZ_Z15:
		if (arr_exist((uint16_t *)systemz_arch13_features, ARR_SIZE(systemz_arch13_features), feature)) {
			return true;
		}
		// fallthrough
	case CS_MODE_SYSTEMZ_ARCH12:
	case CS_MODE_SYSTEMZ_Z14:
		if (arr_exist((uint16_t *)systemz_arch12_features, ARR_SIZE(systemz_arch12_features), feature)) {
			return true;
		}
		// fallthrough
	case CS_MODE_SYSTEMZ_ARCH11:
	case CS_MODE_SYSTEMZ_Z13:
		if (arr_exist((uint16_t *)systemz_arch11_features, ARR_SIZE(systemz_arch11_features), feature)) {
			return true;
		}
		// fallthrough
	case CS_MODE_SYSTEMZ_ARCH10:
	case CS_MODE_SYSTEMZ_ZEC12:
		if (arr_exist((uint16_t *)systemz_arch10_features, ARR_SIZE(systemz_arch10_features), feature)) {
			return true;
		}
		// fallthrough
	case CS_MODE_SYSTEMZ_ARCH9:
	case CS_MODE_SYSTEMZ_Z196:
		if (arr_exist((uint16_t *)systemz_arch9_features, ARR_SIZE(systemz_arch9_features), feature)) {
			return true;
		}
		// fallthrough
	case CS_MODE_SYSTEMZ_GENERIC:
	case CS_MODE_SYSTEMZ_ARCH8:
	case CS_MODE_SYSTEMZ_Z10:
		if (arr_exist((uint16_t *)systemz_arch8_features, ARR_SIZE(systemz_arch8_features), feature)) {
			return true;
		}
		return false;
	default:
		// Default case is the "allow all features", which is normal Capstone behavior
		// until https://github.com/capstone-engine/capstone/issues/1992 is implemented.
		return true;
	}
}

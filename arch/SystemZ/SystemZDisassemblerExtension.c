/* Capstone Disassembly Engine */
/* By Rot127 <unisono@quyllur.org>, 2022-2023 */

#include <capstone/systemz.h>
#include "SystemZDisassemblerExtension.h"
#include "../../utils.h"

#include "SystemZMCTargetDesc.h"

static int systemz_arch9_features[] = {
	SystemZ_FeatureDistinctOps,
	SystemZ_FeatureFastSerialization,
	SystemZ_FeatureFPExtension,
	SystemZ_FeatureHighWord,
	SystemZ_FeatureInterlockedAccess1,
	SystemZ_FeatureLoadStoreOnCond,
	SystemZ_FeaturePopulationCount,
	SystemZ_FeatureMessageSecurityAssist3,
	SystemZ_FeatureMessageSecurityAssist4,
	SystemZ_FeatureResetReferenceBitsMultiple
};

static int systemz_arch10_features[] = { SystemZ_FeatureExecutionHint,
					 SystemZ_FeatureLoadAndTrap,
					 SystemZ_FeatureMiscellaneousExtensions,
					 SystemZ_FeatureProcessorAssist,
					 SystemZ_FeatureTransactionalExecution,
					 SystemZ_FeatureDFPZonedConversion,
					 SystemZ_FeatureEnhancedDAT2 };

static int systemz_arch11_features[] = {
	SystemZ_FeatureLoadAndZeroRightmostByte,
	SystemZ_FeatureLoadStoreOnCond2, SystemZ_FeatureMessageSecurityAssist5,
	SystemZ_FeatureDFPPackedConversion, SystemZ_FeatureVector
};

static int systemz_arch12_features[] = {
	SystemZ_FeatureMiscellaneousExtensions2,
	SystemZ_FeatureGuardedStorage,
	SystemZ_FeatureMessageSecurityAssist7,
	SystemZ_FeatureMessageSecurityAssist8,
	SystemZ_FeatureVectorEnhancements1,
	SystemZ_FeatureVectorPackedDecimal,
	SystemZ_FeatureInsertReferenceBitsMultiple
};

static int systemz_arch13_features[] = {
	SystemZ_FeatureMiscellaneousExtensions3,
	SystemZ_FeatureMessageSecurityAssist9,
	SystemZ_FeatureVectorEnhancements2,
	SystemZ_FeatureVectorPackedDecimalEnhancement,
	SystemZ_FeatureEnhancedSort,
	SystemZ_FeatureDeflateConversion
};

static int systemz_arch14_features[] = {
	SystemZ_FeatureVectorPackedDecimalEnhancement2,
	SystemZ_FeatureNNPAssist, SystemZ_FeatureBEAREnhancement,
	SystemZ_FeatureResetDATProtection,
	SystemZ_FeatureProcessorActivityInstrumentation
};

bool SystemZ_getFeatureBits(unsigned int mode, unsigned int feature)
{
	switch (mode & ~CS_MODE_BIG_ENDIAN) {
	case CS_MODE_SYSTEMZ_ARCH14:
	case CS_MODE_SYSTEMZ_Z16:
		if (arr_exist_int(systemz_arch14_features,
				  ARR_SIZE(systemz_arch14_features), feature)) {
			return true;
		}
		// fallthrough
	case CS_MODE_SYSTEMZ_ARCH13:
	case CS_MODE_SYSTEMZ_Z15:
		if (arr_exist_int(systemz_arch13_features,
				  ARR_SIZE(systemz_arch13_features), feature)) {
			return true;
		}
		// fallthrough
	case CS_MODE_SYSTEMZ_ARCH12:
	case CS_MODE_SYSTEMZ_Z14:
		if (arr_exist_int(systemz_arch12_features,
				  ARR_SIZE(systemz_arch12_features), feature)) {
			return true;
		}
		// fallthrough
	case CS_MODE_SYSTEMZ_ARCH11:
	case CS_MODE_SYSTEMZ_Z13:
		if (arr_exist_int(systemz_arch11_features,
				  ARR_SIZE(systemz_arch11_features), feature)) {
			return true;
		}
		// fallthrough
	case CS_MODE_SYSTEMZ_ARCH10:
	case CS_MODE_SYSTEMZ_ZEC12:
		if (arr_exist_int(systemz_arch10_features,
				  ARR_SIZE(systemz_arch10_features), feature)) {
			return true;
		}
		// fallthrough
	case CS_MODE_SYSTEMZ_ARCH9:
	case CS_MODE_SYSTEMZ_Z196:
		if (arr_exist_int(systemz_arch9_features,
				  ARR_SIZE(systemz_arch9_features), feature)) {
			return true;
		}
		// fallthrough
	case CS_MODE_SYSTEMZ_GENERIC:
	case CS_MODE_SYSTEMZ_ARCH8:
	case CS_MODE_SYSTEMZ_Z10:
		// There are no features defined for Arch8
		return false;
	default:
		// Default case is the "allow all features", which is normal Capstone behavior
		// until https://github.com/capstone-engine/capstone/issues/1992 is implemented.
		return true;
	}
}

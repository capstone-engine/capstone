/* Capstone Disassembly Engine */
/* By Rot127 <unisono@quyllur.org>, 2022-2023 */

#ifndef CS_SYSTEMZ_DISASSEMBLER_EXTENSION_H
#define CS_SYSTEMZ_DISASSEMBLER_EXTENSION_H

#include <capstone/capstone.h>

#include "SystemZMCTargetDesc.h"

static int systemz_arch8_features[] = {};

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

static int systemz_arch10_features[] = {
	SystemZ_FeatureExecutionHint,
	SystemZ_FeatureLoadAndTrap,
	SystemZ_FeatureMiscellaneousExtensions,
	SystemZ_FeatureProcessorAssist,
	SystemZ_FeatureTransactionalExecution,
	SystemZ_FeatureDFPZonedConversion,
	SystemZ_FeatureEnhancedDAT2
};

static int systemz_arch11_features[] = {
	SystemZ_FeatureLoadAndZeroRightmostByte,
	SystemZ_FeatureLoadStoreOnCond2,
	SystemZ_FeatureMessageSecurityAssist5,
	SystemZ_FeatureDFPPackedConversion,
	SystemZ_FeatureVector
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
	SystemZ_FeatureNNPAssist,
	SystemZ_FeatureBEAREnhancement,
	SystemZ_FeatureResetDATProtection,
	SystemZ_FeatureProcessorActivityInstrumentation
};

bool SystemZ_getFeatureBits(unsigned int mode, unsigned int feature);

#endif // CS_SYSTEMZ_DISASSEMBLER_EXTENSION_H

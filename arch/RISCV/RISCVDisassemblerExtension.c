#include "RISCVDisassemblerExtension.h"

#define GET_SUBTARGETINFO_ENUM
#include "RISCVGenSubtargetInfo.inc"

bool RISCV_getFeatureBits(unsigned int mode, unsigned int feature)
{
	if (feature == RISCV_FeatureNoRVCHints) {
		return false;
	}

	switch (feature) {
	case RISCV_Feature32Bit:
		return mode & CS_MODE_RISCV32;

	case RISCV_Feature64Bit:
		return mode & CS_MODE_RISCV64;

	case RISCV_FeatureStdExtF:
	case RISCV_FeatureStdExtD:
		return mode & CS_MODE_RISCV_FD;

	case RISCV_FeatureStdExtV:
		return mode & CS_MODE_RISCV_V;

	case RISCV_FeatureStdExtZfinx:
	case RISCV_FeatureStdExtZdinx:
	case RISCV_FeatureStdExtZhinx:
	case RISCV_FeatureStdExtZhinxmin:
		return mode & CS_MODE_RISCV_ZFINX;

	case RISCV_FeatureStdExtC:
		return mode & CS_MODE_RISCV_C;

	case RISCV_FeatureStdExtZcmp:
	case RISCV_FeatureStdExtZcmt:
	case RISCV_FeatureStdExtZce:
		return mode & CS_MODE_RISCV_ZCMP_ZCMT_ZCE;

	case RISCV_FeatureStdExtZicfiss:
		return mode & CS_MODE_RISCV_ZICFISS;

	case RISCV_FeatureRVE:
		return mode & CS_MODE_RISCV_E;

	case RISCV_FeatureStdExtA:
		return mode & CS_MODE_RISCV_A;

	case RISCV_FeatureVendorXCVelw:
		return mode & CS_MODE_RISCV_COREV;

	case RISCV_FeatureVendorXSfvcp:
	case RISCV_FeatureVendorXSfvfnrclipxfqf:
	case RISCV_FeatureVendorXSfvfwmaccqqq:
	case RISCV_FeatureVendorXSfvqmaccdod:
	case RISCV_FeatureVendorXSfvqmaccqoq:
		return mode & CS_MODE_RISCV_SIFIVE;

	case RISCV_FeatureVendorXTHeadBa:
	case RISCV_FeatureVendorXTHeadBb:
	case RISCV_FeatureVendorXTHeadBs:
	case RISCV_FeatureVendorXTHeadCmo:
	case RISCV_FeatureVendorXTHeadCondMov:
	case RISCV_FeatureVendorXTHeadFMemIdx:
	case RISCV_FeatureVendorXTHeadMac:
	case RISCV_FeatureVendorXTHeadMemIdx:
	case RISCV_FeatureVendorXTHeadMemPair:
	case RISCV_FeatureVendorXTHeadSync:
	case RISCV_FeatureVendorXTHeadVdot:
		return mode & CS_MODE_RISCV_THEAD;

	case RISCV_FeatureStdExtZba:
		return mode & CS_MODE_RISCV_ZBA;
	case RISCV_FeatureStdExtZbb:
		return mode & CS_MODE_RISCV_ZBB;
	case RISCV_FeatureStdExtZbc:
		return mode & CS_MODE_RISCV_ZBC;
	case RISCV_FeatureStdExtZbkb:
		return mode & CS_MODE_RISCV_ZBKB;
	case RISCV_FeatureStdExtZbkc:
		return mode & CS_MODE_RISCV_ZBKC;
	case RISCV_FeatureStdExtZbkx:
		return mode & CS_MODE_RISCV_ZBKX;
	case RISCV_FeatureStdExtZbs:
		return mode & CS_MODE_RISCV_ZBS;
	default:
		// support everything by default
		return true;
	}
}

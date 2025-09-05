#include "RISCVDisassemblerExtension.h"

#define GET_SUBTARGETINFO_ENUM
#include "RISCVGenSubtargetInfo.inc"

bool RISCV_getFeatureBits(unsigned int mode, unsigned int feature) {
    printf("\n checking feature %u\n", feature);
    if (feature == RISCV_FeatureNoRVCHints) {
        return false;
     }

    switch (feature) {
    case RISCV_Feature32Bit:
        printf("\n _________________ RETURNING %s _________________\n", (mode & CS_MODE_RISCV32)? "true":"FALSE");
        return mode & CS_MODE_RISCV32;
    case RISCV_Feature64Bit:
        printf("\n _________________ RETURNING %s _________________\n", (mode & CS_MODE_RISCV64)? "true":"FALSE");
        return mode & CS_MODE_RISCV64;
    case RISCV_FEATURE_HASSTDEXTF:
    case RISCV_FEATURE_HASSTDEXTD:
        printf("\n _________________ RETURNING %s _________________\n", ( mode & CS_MODE_RISCV_FD)? "true":"FALSE");

        return mode & CS_MODE_RISCV_FD;
    case RISCV_FeatureStdExtV:
        printf("\n _________________ RETURNING %s _________________\n", (mode & CS_MODE_RISCV_V)? "true":"FALSE");

        return mode & CS_MODE_RISCV_V;
    case RISCV_FeatureStdExtZfinx:
    case RISCV_FeatureStdExtZdinx:
    case RISCV_FeatureStdExtZhinx:
    case RISCV_FeatureStdExtZhinxmin:
        printf("\n _________________ RETURNING %s _________________\n", (mode & CS_MODE_RISCV_ZFINX)? "true":"FALSE");

        return mode & CS_MODE_RISCV_ZFINX;
    case RISCV_FeatureStdExtC:
        printf("\n _________________ RETURNING %s _________________\n", (mode & CS_MODE_RISCV_C)? "true":"FALSE");

        return mode & CS_MODE_RISCV_C;

    case RISCV_FeatureStdExtZcmp:
    case RISCV_FeatureStdExtZcmt:
    case RISCV_FeatureStdExtZce:
        printf("\n _________________ RETURNING %s _________________\n", (mode & CS_MODE_RISCV_ZCMP_ZCMT_ZCE)? "true":"FALSE");

        return mode & CS_MODE_RISCV_ZCMP_ZCMT_ZCE;
    case RISCV_FeatureStdExtZicfiss:
        printf("\n _________________ RETURNING %s _________________\n", ( mode & CS_MODE_RISCV_ZICFISS)? "true":"FALSE");

        return mode & CS_MODE_RISCV_ZICFISS;
    case RISCV_FeatureRVE:
        printf("\n _________________ RETURNING %s _________________\n", (mode & CS_MODE_RISCV_E)? "true":"FALSE");

        return mode & CS_MODE_RISCV_E;
    case RISCV_FeatureStdExtA:
        printf("\n _________________ RETURNING %s _________________\n", (true)? "true":"FALSE");

        return true;
        return mode & CS_MODE_RISCV_A;
    case RISCV_FeatureVendorXCVelw:
        printf("\n _________________ RETURNING %s _________________\n",  (mode & CS_MODE_RISCV_COREV)? "true":"FALSE");

        return mode & CS_MODE_RISCV_COREV;
    
    case  RISCV_FeatureVendorXSfvcp:
    case RISCV_FeatureVendorXSfvfnrclipxfqf:
    case RISCV_FeatureVendorXSfvfwmaccqqq:
    case RISCV_FeatureVendorXSfvqmaccdod:
    case RISCV_FeatureVendorXSfvqmaccqoq:
        return mode & CS_MODE_RISCV_SIFIVE;

    case  RISCV_FeatureVendorXTHeadBa:
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
        printf("\n ______________________________ RETURNING TRUE ___________________________________ \n");
        // support everything by default
        return true;
    }
}
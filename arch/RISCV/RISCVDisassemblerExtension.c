#include "RISCVDisassemblerExtension.h"

#define GET_SUBTARGETINFO_ENUM
#include "RISCVGenSubtargetInfo.inc"

bool RISCV_getFeatureBits(unsigned int mode, unsigned int feature) {
    printf("\n____________________ CHECKING FEATURE %d", feature);
    // the embedded ABI makes it an error for the instruction to
    // use a register after than the 16th register, makes decoding fails
    if (feature == RISCV_FeatureRVE
     || feature == RISCV_FeatureNoRVCHints 
     || feature == RISCV_FeatureStdExtZicfiss /* feature == RISCV_FEATURE_HASSTDEXTZDINX*/) {
        printf("\nReturning False ----");
        return false;
     }

    switch (feature) {
    case RISCV_Feature32Bit:
        printf("\nReturning %s -----", (mode & CS_MODE_RISCV32)?"true":"false");
        return mode & CS_MODE_RISCV32;
    case RISCV_Feature64Bit:
        printf("\nReturning %s -----", (mode & CS_MODE_RISCV64)?"true":"false");
        return mode & CS_MODE_RISCV64;
    case RISCV_FEATURE_HASSTDEXTF:
    case RISCV_FEATURE_HASSTDEXTD:
        printf("\nReturning %s -----", (mode & CS_MODE_RISCVFD)?"true":"false");
        return mode & CS_MODE_RISCVFD;
    case RISCV_FeatureStdExtV:
        printf("\nReturning %s -----", (mode & CS_MODE_RISCVV)?"true":"false");
        return mode & CS_MODE_RISCVV;
    case RISCV_FeatureStdExtZfinx:
    case RISCV_FeatureStdExtZdinx:
    case RISCV_FeatureStdExtZhinx:
    case RISCV_FeatureStdExtZhinxmin:
        printf("\nReturning %s -----", (mode & CS_MODE_RISCVZFINX)?"true":"false");
        return mode & CS_MODE_RISCVZFINX;
    case RISCV_FeatureStdExtC:
        printf("\nReturning %s -----", (mode & CS_MODE_RISCVC)?"true":"false");
        return mode & CS_MODE_RISCVC;
    case RISCV_FeatureStdExtZcmp:
    case RISCV_FeatureStdExtZcmt:
    case RISCV_FeatureStdExtZce:
        printf("\nReturning %s -----", (mode & CS_MODE_RISCVZCMP_ZCMT_ZCE)?"true":"false");
        return mode & CS_MODE_RISCVZCMP_ZCMT_ZCE;
    default:
        printf("\nReturning true -----");
        // support everything by default
        return true;
    }
}
#include "RISCVDisassemblerExtension.h"

#define GET_SUBTARGETINFO_ENUM
#include "RISCVGenSubtargetInfo.inc"

bool RISCV_getFeatureBits(unsigned int mode, unsigned int feature) {
    // the embedded ABI makes it an error for the instruction to
    // use a register after than the 16th register, makes decoding fails
    if (feature == RISCV_FeatureRVE) 
        return false;

    if (feature == RISCV_Feature32Bit) 
        return mode & CS_MODE_RISCV32;
    if (feature == RISCV_Feature64Bit)
        return mode & CS_MODE_RISCV64;
        
    // support everything by default
    return true;
}
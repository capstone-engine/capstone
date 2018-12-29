#include "llvm-c/Disassembler.h"
#include "llvm-c/Target.h"
#include "llvm/MC/SubtargetFeature.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

extern "C" void LLVMFuzzerInit() {
    LLVMInitializeAllTargetInfos();
    LLVMInitializeAllTargetMCs();
    LLVMInitializeAllDisassemblers();
}


extern "C" int LLVMFuzzerReturnOneInput(const uint8_t *Data, size_t Size, char * AssemblyText) {
    LLVMDisasmContextRef Ctx;
    std::vector<uint8_t> DataCopy(Data, Data + Size);
    uint8_t *p = DataCopy.data();
    int r = 1;

    switch(Data[0]) {
        case 0:
            Ctx = LLVMCreateDisasmCPUFeatures("i386", "", "", nullptr, 0, nullptr, nullptr);
            if (LLVMSetDisasmOptions(Ctx, LLVMDisassembler_Option_AsmPrinterVariant) == 0) {
                abort();
            }
            break;
            //TODO other cases
        default:
            return 1;
    }
    assert(Ctx);

    if (LLVMDisasmInstruction(Ctx, p+1, Size-1, 0, AssemblyText, 80) > 0) {
        r = 0;
    }
    LLVMDisasmDispose(Ctx);

    return r;
}

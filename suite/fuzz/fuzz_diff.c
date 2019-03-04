
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>

#include <capstone/capstone.h>


struct platform {
    cs_arch arch;
    cs_mode mode;
    char *comment;
};

FILE * outfile = NULL;

struct platform platforms[] = {
    {
        // item 0
        CS_ARCH_X86,
        CS_MODE_32,
        "X86 32 (Intel syntax)"
    },
    {
        // item 1
        CS_ARCH_X86,
        CS_MODE_64,
        "X86 64 (Intel syntax)"
    },
    {
        // item 2
        CS_ARCH_ARM,
        CS_MODE_ARM,
        "ARM"
    },
    {
        // item 3
        CS_ARCH_ARM,
        CS_MODE_THUMB,
        "THUMB"
    },
    {
        // item 4
        CS_ARCH_ARM,
        (cs_mode)(CS_MODE_ARM + CS_MODE_V8),
        "Arm-V8"
    },
    {
        // item 5
        CS_ARCH_ARM,
        (cs_mode)(CS_MODE_THUMB+CS_MODE_V8),
        "THUMB+V8"
    },
    {
        // item 6
        CS_ARCH_ARM,
        (cs_mode)(CS_MODE_THUMB + CS_MODE_MCLASS),
        "Thumb-MClass"
    },
    {
        // item 7
        CS_ARCH_ARM64,
        (cs_mode)0,
        "ARM-64"
    },
    {
        // item 8
        CS_ARCH_MIPS,
        (cs_mode)(CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN),
        "MIPS-32 (Big-endian)"
    },
    {
        // item 9
        CS_ARCH_MIPS,
        (cs_mode)(CS_MODE_MIPS32 + CS_MODE_MICRO),
        "MIPS-32 (micro)"
    },
    {
        //item 10
        CS_ARCH_MIPS,
        CS_MODE_MIPS64,
        "MIPS-64-EL (Little-endian)"
    },
    {
        //item 11
        CS_ARCH_MIPS,
        CS_MODE_MIPS32,
        "MIPS-32-EL (Little-endian)"
    },
    {
        //item 12
        CS_ARCH_MIPS,
        (cs_mode)(CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN),
        "MIPS-64 (Big-endian)"
    },
    {
        //item 13
        CS_ARCH_MIPS,
        (cs_mode)(CS_MODE_MIPS32 + CS_MODE_MICRO + CS_MODE_BIG_ENDIAN),
        "MIPS-32 | Micro (Big-endian)"
    },
    {
        //item 14
        CS_ARCH_PPC,
        CS_MODE_BIG_ENDIAN,
        "PPC-64"
    },
    {
        //item 15
        CS_ARCH_SPARC,
        CS_MODE_BIG_ENDIAN,
        "Sparc"
    },
    {
        //item 16
        CS_ARCH_SPARC,
        (cs_mode)(CS_MODE_BIG_ENDIAN + CS_MODE_V9),
        "SparcV9"
    },
    {
        //item 17
        CS_ARCH_SYSZ,
        (cs_mode)0,
        "SystemZ"
    },
    {
        //item 18
        CS_ARCH_XCORE,
        (cs_mode)0,
        "XCore"
    },
    {
        //item 19
        CS_ARCH_MIPS,
        (cs_mode)(CS_MODE_MIPS32R6 + CS_MODE_BIG_ENDIAN),
        "MIPS-32R6 (Big-endian)"
    },
    {
        //item 20
        CS_ARCH_MIPS,
        (cs_mode)(CS_MODE_MIPS32R6 + CS_MODE_MICRO + CS_MODE_BIG_ENDIAN),
        "MIPS-32R6 (Micro+Big-endian)"
    },
    {
        //item 21
        CS_ARCH_MIPS,
        CS_MODE_MIPS32R6,
        "MIPS-32R6 (Little-endian)"
    },
    {
        //item 22
        CS_ARCH_MIPS,
        (cs_mode)(CS_MODE_MIPS32R6 + CS_MODE_MICRO),
        "MIPS-32R6 (Micro+Little-endian)"
    },
    {
        //item 23
        CS_ARCH_M68K,
        (cs_mode)0,
        "M68K"
    },
    {
        //item 24
        CS_ARCH_M680X,
        (cs_mode)CS_MODE_M680X_6809,
        "M680X_M6809"
    },
    {
        //item 25
        CS_ARCH_EVM,
        (cs_mode)0,
        "EVM"
    },
};

void LLVMFuzzerInit();
int LLVMFuzzerReturnOneInput(const uint8_t *Data, size_t Size, char * AssemblyText);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    csh handle;
    cs_insn *insn;
    cs_err err;
    const uint8_t **Datap = &Data;
    size_t * Sizep = &Size;
    uint64_t address = 0x1000;
    char LLVMAssemblyText[80];
    char CapstoneAssemblyText[80];

    if (Size < 1) {
        // 1 byte for arch choice
        return 0;
    } else if (Size > 0x1000) {
        //limit input to 4kb
        Size = 0x1000;
    }
    if (outfile == NULL) {
        // we compute the output
        outfile = fopen("/dev/null", "w");
        if (outfile == NULL) {
            return 0;
        }
        LLVMFuzzerInit();
    }

    if (Data[0] >= sizeof(platforms)/sizeof(platforms[0])) {
        return 0;
    }

    if (LLVMFuzzerReturnOneInput(Data, Size, LLVMAssemblyText) == 1) {
        return 0;
    }

    err = cs_open(platforms[Data[0]].arch, platforms[Data[0]].mode, &handle);
    if (err) {
        return 0;
    }

    insn = cs_malloc(handle);
    Data++;
    Size--;
    assert(insn);
        if (cs_disasm_iter(handle, Datap, Sizep, &address, insn)) {
            snprintf(CapstoneAssemblyText, 80, "\t%s\t%s", insn->mnemonic, insn->op_str);
            if (strcmp(CapstoneAssemblyText, LLVMAssemblyText) != 0) {
                printf("capstone %s != llvm %s", CapstoneAssemblyText, LLVMAssemblyText);
                abort();
            }
        } else {
            printf("capstone failed with llvm %s", LLVMAssemblyText);
            abort();
        }
    cs_free(insn, 1);
    cs_close(&handle);

    return 0;
}

// the following must precede stdio (woo, thanks msft)
#if defined(_MSC_VER) && _MSC_VER < 1900
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <capstone.h>


struct platform {
    cs_arch arch;
    cs_mode mode;
    char *comment;
};

FILE * outfile = NULL;

struct platform platforms[] = {
    {
        CS_ARCH_X86,
        CS_MODE_32,
        "X86 32 (Intel syntax)"
    },
    {
        CS_ARCH_X86,
        CS_MODE_64,
        "X86 64 (Intel syntax)"
    },
    {
        CS_ARCH_ARM,
        CS_MODE_ARM,
        "ARM"
    },
    {
        CS_ARCH_ARM,
        CS_MODE_THUMB,
        "THUMB-2"
    },
    {
        CS_ARCH_ARM,
        CS_MODE_ARM,
        "ARM: Cortex-A15 + NEON"
    },
    {
        CS_ARCH_ARM,
        CS_MODE_THUMB,
        "THUMB"
    },
    {
        CS_ARCH_ARM,
        (cs_mode)(CS_MODE_THUMB + CS_MODE_MCLASS),
        "Thumb-MClass"
    },
    {
        CS_ARCH_ARM,
        (cs_mode)(CS_MODE_ARM + CS_MODE_V8),
        "Arm-V8"
    },
    {
        CS_ARCH_MIPS,
        (cs_mode)(CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN),
        "MIPS-32 (Big-endian)"
    },
    {
        CS_ARCH_MIPS,
        (cs_mode)(CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN),
        "MIPS-64-EL (Little-endian)"
    },
    {
        CS_ARCH_MIPS,
        (cs_mode)(CS_MODE_MIPS32R6 + CS_MODE_MICRO + CS_MODE_BIG_ENDIAN),
        "MIPS-32R6 | Micro (Big-endian)"
    },
    {
        CS_ARCH_MIPS,
        (cs_mode)(CS_MODE_MIPS32R6 + CS_MODE_BIG_ENDIAN),
        "MIPS-32R6 (Big-endian)"
    },
    {
        CS_ARCH_ARM64,
        CS_MODE_ARM,
        "ARM-64"
    },
    {
        CS_ARCH_PPC,
        CS_MODE_BIG_ENDIAN,
        "PPC-64"
    },
    {
        CS_ARCH_SPARC,
        CS_MODE_BIG_ENDIAN,
        "Sparc"
    },
    {
        CS_ARCH_SPARC,
        (cs_mode)(CS_MODE_BIG_ENDIAN + CS_MODE_V9),
        "SparcV9"
    },
    {
        CS_ARCH_SYSZ,
        (cs_mode)0,
        "SystemZ"
    },
    {
        CS_ARCH_XCORE,
        (cs_mode)0,
        "XCore"
    },
};

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    csh handle;
    cs_insn *all_insn;
    cs_detail *detail;
    cs_err err;

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
    }

    int platforms_len = sizeof(platforms)/sizeof(platforms[0]);
    int i = (int)Data[0] % platforms_len;

    err = cs_open(platforms[i].arch, platforms[i].mode, &handle);
    if (err) {
        return 0;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    uint64_t address = 0x1000;
    size_t count = cs_disasm(handle, Data+1, Size-1, address, 0, &all_insn);

    if (count) {
        size_t j;
        int n;

        for (j = 0; j < count; j++) {
            cs_insn *i = &(all_insn[j]);
            fprintf(outfile, "0x%"PRIx64":\t%s\t\t%s // insn-ID: %u, insn-mnem: %s\n",
                   i->address, i->mnemonic, i->op_str,
                   i->id, cs_insn_name(handle, i->id));

            detail = i->detail;

            if (detail->regs_read_count > 0) {
                fprintf(outfile, "\tImplicit registers read: ");
                for (n = 0; n < detail->regs_read_count; n++) {
                    fprintf(outfile, "%s ", cs_reg_name(handle, detail->regs_read[n]));
                }
            }

            if (detail->regs_write_count > 0) {
                fprintf(outfile, "\tImplicit registers modified: ");
                for (n = 0; n < detail->regs_write_count; n++) {
                    fprintf(outfile, "%s ", cs_reg_name(handle, detail->regs_write[n]));
                }
            }

            if (detail->groups_count > 0) {
                fprintf(outfile, "\tThis instruction belongs to groups: ");
                for (n = 0; n < detail->groups_count; n++) {
                    fprintf(outfile, "%s ", cs_group_name(handle, detail->groups[n]));
                }
            }
        }
        fprintf(outfile, "0x%"PRIx64":\n", all_insn[j-1].address + all_insn[j-1].size);
        cs_free(all_insn, count);
    }

    cs_close(&handle);

    return 0;
}

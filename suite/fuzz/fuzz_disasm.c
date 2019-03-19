// the following must precede stdio (woo, thanks msft)
#if defined(_MSC_VER) && _MSC_VER < 1900
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <capstone/capstone.h>

const char * cs_fuzz_arch(uint8_t arch);

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);


struct platform {
    cs_arch arch;
    cs_mode mode;
    const char *comment;
    const char *cstoolname;
};

static FILE *outfile = NULL;

static struct platform platforms[] = {
    {
        // item 0
        CS_ARCH_X86,
        CS_MODE_32,
        "X86 32 (Intel syntax)",
        "x32"
    },
    {
        // item 1
        CS_ARCH_X86,
        CS_MODE_64,
        "X86 64 (Intel syntax)",
        "x64"
    },
    {
        // item 2
        CS_ARCH_ARM,
        CS_MODE_ARM,
        "ARM",
        "arm"
    },
    {
        // item 3
        CS_ARCH_ARM,
        CS_MODE_THUMB,
        "THUMB",
        "thumb"
    },
    {
        // item 4
        CS_ARCH_ARM,
        (cs_mode)(CS_MODE_ARM + CS_MODE_V8),
        "Arm-V8",
        "armv8"
    },
    {
        // item 5
        CS_ARCH_ARM,
        (cs_mode)(CS_MODE_THUMB+CS_MODE_V8),
        "THUMB+V8",
        "thumbv8"
    },
    {
        // item 6
        CS_ARCH_ARM,
        (cs_mode)(CS_MODE_THUMB + CS_MODE_MCLASS),
        "Thumb-MClass",
        "cortexm"
    },
    {
        // item 7
        CS_ARCH_ARM64,
        (cs_mode)0,
        "ARM-64",
        "arm64"
    },
    {
        // item 8
        CS_ARCH_MIPS,
        (cs_mode)(CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN),
        "MIPS-32 (Big-endian)",
        "mipsbe"
    },
    {
        // item 9
        CS_ARCH_MIPS,
        (cs_mode)(CS_MODE_MIPS32 + CS_MODE_MICRO),
        "MIPS-32 (micro)",
        "mipsmicro"
    },
    {
        //item 10
        CS_ARCH_MIPS,
        CS_MODE_MIPS64,
        "MIPS-64-EL (Little-endian)",
        "mips64"
    },
    {
        //item 11
        CS_ARCH_MIPS,
        CS_MODE_MIPS32,
        "MIPS-32-EL (Little-endian)",
        "mips"
    },
    {
        //item 12
        CS_ARCH_MIPS,
        (cs_mode)(CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN),
        "MIPS-64 (Big-endian)",
        "mips64be"
    },
    {
        //item 13
        CS_ARCH_MIPS,
        (cs_mode)(CS_MODE_MIPS32 + CS_MODE_MICRO + CS_MODE_BIG_ENDIAN),
        "MIPS-32 | Micro (Big-endian)",
        "mipsbemicro"
    },
    {
        //item 14
        CS_ARCH_PPC,
        CS_MODE_BIG_ENDIAN,
        "PPC-64",
        "ppc64"
    },
    {
        //item 15
        CS_ARCH_SPARC,
        CS_MODE_BIG_ENDIAN,
        "Sparc",
        "sparc"
    },
    {
        //item 16
        CS_ARCH_SPARC,
        (cs_mode)(CS_MODE_BIG_ENDIAN + CS_MODE_V9),
        "SparcV9",
        "sparcv9"
    },
    {
        //item 17
        CS_ARCH_SYSZ,
        (cs_mode)0,
        "SystemZ",
        "systemz"
    },
    {
        //item 18
        CS_ARCH_XCORE,
        (cs_mode)0,
        "XCore",
        "xcore"
    },
    {
        //item 19
        CS_ARCH_MIPS,
        (cs_mode)(CS_MODE_MIPS32R6 + CS_MODE_BIG_ENDIAN),
        "MIPS-32R6 (Big-endian)",
        "mipsbe32r6"
    },
    {
        //item 20
        CS_ARCH_MIPS,
        (cs_mode)(CS_MODE_MIPS32R6 + CS_MODE_MICRO + CS_MODE_BIG_ENDIAN),
        "MIPS-32R6 (Micro+Big-endian)",
        "mipsbe32r6micro"
    },
    {
        //item 21
        CS_ARCH_MIPS,
        CS_MODE_MIPS32R6,
        "MIPS-32R6 (Little-endian)",
        "mips32r6"
    },
    {
        //item 22
        CS_ARCH_MIPS,
        (cs_mode)(CS_MODE_MIPS32R6 + CS_MODE_MICRO),
        "MIPS-32R6 (Micro+Little-endian)",
        "mips32r6micro"
    },
    {
        //item 23
        CS_ARCH_M68K,
        (cs_mode)0,
        "M68K",
        "m68k"
    },
    {
        //item 24
        CS_ARCH_M680X,
        (cs_mode)CS_MODE_M680X_6809,
        "M680X_M6809",
        "m6809"
    },
    {
        //item 25
        CS_ARCH_EVM,
        (cs_mode)0,
        "EVM",
        "evm"
    },
    {
        //item 26
        CS_ARCH_MOS65XX,
        (cs_mode)0,
        "MOS65XX",
        "mos65xx"
    },
    {
        //item 27
        CS_ARCH_TMS320C64X,
        CS_MODE_BIG_ENDIAN,
        "tms320c64x",
        "tms320c64x"
    },
    {
        //item 28
        CS_ARCH_WASM,
        (cs_mode)0,
        "WASM",
        "wasm"
    },
    {
        //item 29
        CS_ARCH_BPF,
        CS_MODE_LITTLE_ENDIAN | CS_MODE_BPF_CLASSIC,
        "cBPF",
        "bpf"
    },
    {
        //item 30
        CS_ARCH_BPF,
        CS_MODE_LITTLE_ENDIAN | CS_MODE_BPF_EXTENDED,
        "eBPF",
        "ebpf"
    },
    {
        //item 31
        CS_ARCH_BPF,
        CS_MODE_BIG_ENDIAN | CS_MODE_BPF_CLASSIC,
        "cBPF",
        "bpfbe"
    },
    {
        //item 32
        CS_ARCH_BPF,
        CS_MODE_BIG_ENDIAN | CS_MODE_BPF_EXTENDED,
        "eBPF",
        "ebpfbe"
    },
    {
        // item 33
        CS_ARCH_X86,
        CS_MODE_16,
        "X86 16 (Intel syntax)",
        "x16"
    },
    {
        // item 34
        CS_ARCH_M68K,
        CS_MODE_M68K_040,
        "M68K mode 40",
        "m68k40"
    },
    {
        //item 35
        CS_ARCH_M680X,
        (cs_mode)CS_MODE_M680X_6800,
        "M680X_M6800",
        "m6800"
    },
    {
        //item 36
        CS_ARCH_M680X,
        (cs_mode)CS_MODE_M680X_6801,
        "M680X_M6801",
        "m6801"
    },
    {
        //item 37
        CS_ARCH_M680X,
        (cs_mode)CS_MODE_M680X_6805,
        "M680X_M6805",
        "m6805"
    },
    {
        //item 38
        CS_ARCH_M680X,
        (cs_mode)CS_MODE_M680X_6808,
        "M680X_M6808",
        "m6808"
    },
    {
        //item 39
        CS_ARCH_M680X,
        (cs_mode)CS_MODE_M680X_6811,
        "M680X_M6811",
        "m6811"
    },
    {
        //item 40
        CS_ARCH_M680X,
        (cs_mode)CS_MODE_M680X_CPU12,
        "M680X_cpu12",
        "cpu12"
    },
    {
        //item 41
        CS_ARCH_M680X,
        (cs_mode)CS_MODE_M680X_6301,
        "M680X_M6808",
        "hd6301"
    },
    {
        //item 42
        CS_ARCH_M680X,
        (cs_mode)CS_MODE_M680X_6309,
        "M680X_M6808",
        "hd6309"
    },
    {
        //item 43
        CS_ARCH_M680X,
        (cs_mode)CS_MODE_M680X_HCS08,
        "M680X_M6808",
        "hcs08"
    },
    {
        //item 44
        CS_ARCH_RISCV,
        CS_MODE_RISCV32,
        "RISCV",
        "riscv32"
    },
    {
        //item 45
        CS_ARCH_RISCV,
        CS_MODE_RISCV64,
        "RISCV",
        "riscv64"
    },
    {
        //item 46
        CS_ARCH_PPC,
        CS_MODE_BIG_ENDIAN | CS_MODE_QPX,
        "ppc+qpx",
        "ppcqpxbe"
    },
};

const char * cs_fuzz_arch(uint8_t arch) {
    return platforms[arch % sizeof(platforms)/sizeof(platforms[0])].cstoolname;
}

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
    if (Data[0]&0x80) {
        //hack
        cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
    }

    uint64_t address = 0x1000;
    size_t count = cs_disasm(handle, Data+1, Size-1, address, 0, &all_insn);

    if (count) {
        size_t j;
        unsigned int n;

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

// the following must precede stdio (woo, thanks msft)
#if defined(_MSC_VER) && _MSC_VER < 1900
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#include <capstone/capstone.h>

#include "platform.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);


static FILE *outfile = NULL;

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    csh handle;
    cs_insn *all_insn;
    cs_detail *detail;
    cs_err err;
    unsigned int i;

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

    i = get_platform_entry((uint8_t)Data[0]);

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
            cs_insn *insn = &(all_insn[j]);
            fprintf(outfile, "0x%"PRIx64":\t%s\t\t%s // insn-ID: %u, insn-mnem: %s\n",
                   insn->address, insn->mnemonic, insn->op_str,
                   insn->id, cs_insn_name(handle, insn->id));

            detail = insn->detail;

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

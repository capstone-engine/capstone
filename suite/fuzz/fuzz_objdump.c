#include "bfd.h"
#include "dis-asm.h"
#include "disassemble.h"

void diffFuzzerInit() {
//TODO ?
}

static int objdump_sprintf (void *output, const char *format, ...)
{
    size_t n;
    va_list args;

    va_start (args, format);
    n = vsnprintf (output, 80, format, args);
    va_end (args);

    return n;
}

static void objdump_print_address (bfd_vma vma, struct disassemble_info *inf)
{
    (*inf->fprintf_func) (inf->stream, "0x%x", vma);
}

int diffFuzzerReturnOneInput(const uint8_t *Data, size_t Size, char * AssemblyText) {
    int r = -2;
    struct disassemble_info disasm_info;

    init_disassemble_info (&disasm_info, stdout, (fprintf_ftype) fprintf);
    disasm_info.fprintf_func = objdump_sprintf;
    disasm_info.print_address_func = objdump_print_address;
    disasm_info.display_endian = disasm_info.endian = BFD_ENDIAN_LITTLE;
    disasm_info.buffer = Data+1;
    disasm_info.buffer_vma = 0x1000;
    disasm_info.buffer_length = Size-1;
    disasm_info.insn_info_valid = 0;
    disasm_info.stream = AssemblyText;
    disasm_info.bytes_per_line = 0;

    switch(Data[0]) {
        case 0:
            disasm_info.arch = bfd_arch_i386;
            disassemble_init_for_target(&disasm_info);
            r = print_insn_i386(0x1000, &disasm_info);
            break;
        case 1:
            disasm_info.arch = bfd_arch_ia64;
            disassemble_init_for_target(&disasm_info);
            r = print_insn_ia64(0x1000, &disasm_info);
            break;
        default:
            return -1;
    }

    return r;
}

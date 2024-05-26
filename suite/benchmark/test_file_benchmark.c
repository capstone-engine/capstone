// Modified from https://github.com/athre0z/disas-bench

#include "./load_bin.inc"
#include <capstone/capstone.h>


int main(int argc, char* argv[])
{
    csh handle = 0;
    cs_buffer *buffer = NULL;
    int ret = 0;
    const uint8_t *code_iter = NULL;
    size_t code_len_iter = 0;
    uint64_t ip = 0;
    size_t num_valid_insns = 0;
    size_t num_bad_insn = 0;
    size_t round;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
        fputs("Unable to create Capstone handle\n", stderr);
        ret = 1;
        goto leave;
    }

    uint8_t *code = NULL;
    size_t code_len = 0, loop_count = 0;
    if (!read_file(argc, argv, &code, &code_len, &loop_count))
    {
        ret = 1;
        goto leave;
    }

    buffer = cs_buffer_new(0);
    if (!buffer)
    {
        fputs("Failed to allocate memory\n", stderr);
        ret = 1;
        goto leave;
    }

    clock_t start_time = clock();
    for (round = 0; round < loop_count; ++round)
    {
        code_iter = code;
        code_len_iter = code_len;
        while (code_len_iter > 0)
        {
            if (!cs_disasm_iter(
                handle,
                &code_iter,
                &code_len_iter,
                &ip,
                buffer
            ))
            {
                ++code_iter;
                --code_len_iter;
                ++num_bad_insn;
            }
            else
            {
                ++num_valid_insns;
            }
        }
    }
    clock_t end_time = clock();

    printf(
        "Disassembled %zu instructions (%zu valid, %zu bad), %.2f ms\n", 
        num_valid_insns + num_bad_insn,
        num_valid_insns,
        num_bad_insn,
        (double)(end_time - start_time) * 1000.0 / CLOCKS_PER_SEC
    );

leave:
    if (buffer) cs_buffer_free(buffer);
    if (handle) cs_close(&handle);
    if (code) free(code);
    return ret;
}

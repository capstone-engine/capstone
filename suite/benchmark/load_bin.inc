// From https://github.com/athre0z/disas-bench

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>


int read_file_data(uint8_t** buf, const char* filename, size_t file_offset, size_t bin_len)
{
    FILE* f = fopen(filename, "rb");
    if (!f) return 0;

    // Seek to code section
    if (fseek(f, (long)file_offset, SEEK_SET)) 
    { 
        fclose(f);
        return 0; 
    }

    uint8_t* code = malloc(bin_len);
    if (!code)
    {
        fclose(f);
        return 0;
    }

    if (fread(code, 1, bin_len, f) != bin_len)
    {
        fclose(f);
        free(code);
        return 0;
    }

    *buf = code;

    return 1;
}

int read_file(int argc, char *argv[], uint8_t **buf, size_t *bin_len, size_t *loop_count)
{
    if (argc != 5)
    {
        fputs("Expected args: <loop-count> <code-offset> <code-len> <filename>\n", stderr);
        return 0;
    }

    *loop_count = (size_t)strtoull(argv[1], NULL, 0);
    size_t file_offset = (size_t)strtoull(argv[2], NULL, 0);
    *bin_len = (size_t)strtoull(argv[3], NULL, 0);
    const char *filename = argv[4];

    if (!read_file_data(buf, filename, file_offset, *bin_len))
    {
        fprintf(stderr, "Couldn't read `%s`\n", filename);
        return 0;
    }

    return 1;
}
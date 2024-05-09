#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include <unistd.h>

#include "platform.h"

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int main(int argc, char** argv)
{
    FILE * fp;
    uint8_t Data[0x1000];
    size_t Size;
    DIR *d;
    struct dirent *dir;
    int r = 0;
    int i;

    if (argc != 2) {
        return 1;
    }

    d = opendir(argv[1]);
    if (d == NULL) {
        printf("Invalid directory\n");
        return 2;
    }
    if (chdir(argv[1]) != 0) {
        closedir(d);
        printf("Invalid directory\n");
        return 2;
    }

    while((dir = readdir(d)) != NULL) {
        //opens the file, get its size, and reads it into a buffer
        if (dir->d_type != DT_REG) {
            continue;
        }
        printf("Running file %s ", dir->d_name);
        fflush(stdout);
        fp = fopen(dir->d_name, "rb");
        if (fp == NULL) {
            r = 3;
            break;
        }
        if (fseek(fp, 0L, SEEK_END) != 0) {
            fclose(fp);
            r = 4;
            break;
        }
        Size = ftell(fp);
        if (Size == (size_t) -1) {
            fclose(fp);
            r = 5;
            break;
        } else if (Size > 0x1000) {
            fclose(fp);
            continue;
        }
        if (fseek(fp, 0L, SEEK_SET) != 0) {
            fclose(fp);
            r = 7;
            break;
        }
        if (fread(Data, Size, 1, fp) != 1) {
            fclose(fp);
            r = 8;
            break;
        }
        if (Size > 0) {
            printf("command cstool %s\n", get_platform_cstoolname(Data[0]));
        }
        for (i=0; i<Size; i++) {
            printf("%02x", Data[i]);
        }
        printf("\n");

        //launch fuzzer
        LLVMFuzzerTestOneInput(Data, Size);
        fclose(fp);
    }
    closedir(d);
    printf("Ok : whole directory finished\n");
    return r;
}


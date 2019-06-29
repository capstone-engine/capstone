#include <capstone.h>

#define BINARY "\x3b\x30\x62\x93\x5d\x61\x03\xe8"

int main(int argc, char **argv, char **envp) {
  csh handle;
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle)) {
    printf("cs_open(…) failed\n");
    return 1;
  }
  cs_insn *insn;
  cs_disasm(handle, (uint8_t *)BINARY, sizeof(BINARY) - 1, 0x1000, 0, &insn);
  return 0;
}

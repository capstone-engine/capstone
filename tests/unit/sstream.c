// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "../SStream.h"
#include <stdio.h>
#include <string.h>

#define CHECK_EQUAL_RET_FALSE(OS, str) \
do { \
  if (strcmp(OS.buffer, str) != 0) { \
    printf("OS.buffer != str\n"); \
    printf("OS.buffer: %s\n", OS.buffer); \
    printf("str       : %s\n", str); \
    return false; \
  } \
} while(0);

bool test_markup_os() {
  printf("Test test_markup_os\n");

  SStream OS = { 0 };
  SStream_Init(&OS);
  SStream_concat0(&OS, "0");
  CHECK_EQUAL_RET_FALSE(OS, "0");
  OS.markup_stream = true;
  printUInt64(&OS, 0);
  CHECK_EQUAL_RET_FALSE(OS, "00");
  markup_OS(&OS, Markup_Immediate);
  printUInt64(&OS, 0);
  CHECK_EQUAL_RET_FALSE(OS, "00<imm:0>");
  markup_OS(&OS, Markup_Memory);
  printUInt32(&OS, 0);
  CHECK_EQUAL_RET_FALSE(OS, "00<imm:0><mem:0>");
  markup_OS(&OS, Markup_Target);
  printUInt32(&OS, 0);
  CHECK_EQUAL_RET_FALSE(OS, "00<imm:0><mem:0><tar:0>");
  markup_OS(&OS, Markup_Register);
  SStream_concat0(&OS, "r19");
  CHECK_EQUAL_RET_FALSE(OS, "00<imm:0><mem:0><tar:0><reg:r19>");
  return true;
}

int main() {
  bool result = true;
  result &= test_markup_os();
  if (result) {
    printf("All tests passed.\n");
  } else {
    printf("Some tests failed.\n");
  }
  return result ? 0 : -1;
}

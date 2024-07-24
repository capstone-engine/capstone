// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_mapping.h"
#include <stdint.h>

bool test_cs_enum_get_val() {
  bool found = false;
  // Get first value
  uint32_t val = cs_enum_get_val("AArch64CC_AL", &found);
  if (!found || val != AArch64CC_AL) {
    fprintf(stderr, "cs_enum_get_val(AArch64CC_AL) failed is %d.\n", val);
    return false;
  }

  // Get last value
  val = cs_enum_get_val("CS_AC_WRITE", &found);
  if (!found || val != CS_AC_WRITE) {
    fprintf(stderr, "cs_enum_get_val(CS_AC_WRITE) failed is %d.\n", val);
    return false;
  }

  // Value at index 1
  val = cs_enum_get_val("AArch64CC_EQ", &found);
  if (!found || val != AArch64CC_EQ) {
    fprintf(stderr, "cs_enum_get_val(AArch64CC_EQ) failed is %d.\n", val);
    return false;
  }

  // Value in lower half
  val = cs_enum_get_val("AArch64CC_Invalid", &found);
  if (!found || val != AArch64CC_Invalid) {
    fprintf(stderr, "cs_enum_get_val(AArch64CC_In) failed is %d.\n", val);
    return false;
  }

  return true;
}

int main() {
  bool success = true;
  success &= test_cs_enum_get_val();
  printf("test_cs_enum_get_val: %s\n", success ? "ok" : "fail");
  return success ? 0 : 1;
}

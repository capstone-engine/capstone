// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_detail.h"
#include "test_compare.h"

TestDetail *test_detail_new() {
  return cs_mem_calloc(sizeof(TestDetail), 1);
}

TestDetail *test_detail_clone(TestDetail *detail) {
  assert(detail);
  TestDetail *clone = test_detail_new();

  clone->regs_read = detail->regs_read_count > 0 ? cs_mem_calloc(sizeof(char *), detail->regs_read_count) : NULL;
  clone->regs_read_count = detail->regs_read_count;
  for (size_t i = 0; i < detail->regs_read_count; ++i) {
    clone->regs_read[i] = strdup(detail->regs_read[i]);
  }

  clone->regs_write = detail->regs_write_count > 0 ? cs_mem_calloc(sizeof(char *), detail->regs_write_count) : NULL;
  clone->regs_write_count = detail->regs_write_count;
  for (size_t i = 0; i < detail->regs_write_count; ++i) {
    clone->regs_write[i] = strdup(detail->regs_write[i]);
  }

  clone->groups = detail->groups_count > 0 ? cs_mem_calloc(sizeof(char *), detail->groups_count) : NULL;
  clone->groups_count = detail->groups_count;
  for (size_t i = 0; i < detail->groups_count; ++i) {
    clone->groups[i] = strdup(detail->groups[i]);
  }

  if (detail->aarch64) {
    clone->aarch64 = test_detail_aarch64_clone(detail->aarch64);
  }

  return clone;
}

void test_detail_free(TestDetail *detail) {
  if (!detail) {
    return;
  }

  for (size_t i = 0; i < detail->regs_read_count; ++i) {
    cs_mem_free(detail->regs_read[i]);
  }
  cs_mem_free(detail->regs_read);

  for (size_t i = 0; i < detail->regs_write_count; ++i) {
    cs_mem_free(detail->regs_write[i]);
  }
  cs_mem_free(detail->regs_write);

  for (size_t i = 0; i < detail->groups_count; ++i) {
    cs_mem_free(detail->groups[i]);
  }
  cs_mem_free(detail->groups);

  if (detail->aarch64) {
    test_detail_aarch64_free(detail->aarch64);
  }

  cs_mem_free(detail);
}

bool test_expected_detail(csh *handle, cs_detail *actual,
			   TestDetail *expected) {
  assert(handle && actual && expected);
  compare_uint32_ret(actual->regs_read_count, expected->regs_read_count, false);
  for (size_t i = 0; i < actual->regs_read_count; ++i) {
    compare_reg_ret(*handle, actual->regs_read[i], expected->regs_read[i], false);
  }

  compare_uint32_ret(actual->regs_write_count, expected->regs_write_count, false);
  for (size_t i = 0; i < actual->regs_write_count; ++i) {
    compare_reg_ret(*handle, actual->regs_write[i], expected->regs_write[i], false);
  }

  compare_uint32_ret(actual->groups_count, expected->groups_count, false);
  for (size_t i = 0; i < actual->groups_count; ++i) {
    compare_reg_ret(*handle, actual->groups[i], expected->groups[i], false);
  }

  if (expected->aarch64) {
    return test_expected_aarch64(handle, &actual->aarch64, expected->aarch64);
  }
  return true;
}

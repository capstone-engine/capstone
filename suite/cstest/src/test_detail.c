// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_detail.h"
#include "test_compare.h"
#include <capstone/capstone.h>

TestDetail *test_detail_new()
{
	return cs_mem_calloc(sizeof(TestDetail), 1);
}

TestDetail *test_detail_clone(TestDetail *detail)
{
	assert(detail);
	TestDetail *clone = test_detail_new();

	clone->regs_read =
		detail->regs_read_count > 0 ?
			cs_mem_calloc(sizeof(char *), detail->regs_read_count) :
			NULL;
	clone->regs_read_count = detail->regs_read_count;
	for (size_t i = 0; i < detail->regs_read_count; ++i) {
		clone->regs_read[i] = strdup(detail->regs_read[i]);
	}

	clone->regs_write = detail->regs_write_count > 0 ?
				    cs_mem_calloc(sizeof(char *),
						  detail->regs_write_count) :
				    NULL;
	clone->regs_write_count = detail->regs_write_count;
	for (size_t i = 0; i < detail->regs_write_count; ++i) {
		clone->regs_write[i] = strdup(detail->regs_write[i]);
	}

	clone->groups =
		detail->groups_count > 0 ?
			cs_mem_calloc(sizeof(char *), detail->groups_count) :
			NULL;
	clone->groups_count = detail->groups_count;
	for (size_t i = 0; i < detail->groups_count; ++i) {
		clone->groups[i] = strdup(detail->groups[i]);
	}

	if (detail->aarch64) {
		clone->aarch64 = test_detail_aarch64_clone(detail->aarch64);
	}

	if (detail->arm) {
		clone->arm = test_detail_arm_clone(detail->arm);
	}

	if (detail->ppc) {
		clone->ppc = test_detail_ppc_clone(detail->ppc);
	}

	if (detail->tricore) {
		clone->tricore = test_detail_tricore_clone(detail->tricore);
	}

	return clone;
}

void test_detail_free(TestDetail *detail)
{
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
	if (detail->arm) {
		test_detail_arm_free(detail->arm);
	}
	if (detail->ppc) {
		test_detail_ppc_free(detail->ppc);
	}
	if (detail->tricore) {
		test_detail_tricore_free(detail->tricore);
	}

	cs_mem_free(detail);
}

bool test_expected_detail(csh *handle, const cs_insn *insn,
			  TestDetail *expected)
{
	assert(handle && insn && insn->detail && expected);
	cs_detail *actual = insn->detail;
	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;
	cs_regs_access(*handle, insn, regs_read, &regs_read_count, regs_write,
		       &regs_write_count);

	if (expected->regs_read_count > 0) {
		compare_uint32_ret(regs_read_count, expected->regs_read_count,
				   false);
		for (size_t i = 0; i < regs_read_count; ++i) {
			compare_reg_ret(*handle, regs_read[i],
					expected->regs_read[i], false);
		}
	}

	if (expected->regs_write_count > 0) {
		compare_uint32_ret(regs_write_count, expected->regs_write_count,
				   false);
		for (size_t i = 0; i < regs_write_count; ++i) {
			compare_reg_ret(*handle, regs_write[i],
					expected->regs_write[i], false);
		}
	}

	if (expected->groups_count > 0) {
		compare_uint32_ret(actual->groups_count, expected->groups_count,
				   false);
		for (size_t i = 0; i < actual->groups_count; ++i) {
			compare_reg_ret(*handle, actual->groups[i],
					expected->groups[i], false);
		}
	}

	if (expected->aarch64) {
		return test_expected_aarch64(handle, &actual->aarch64,
					     expected->aarch64);
	}
	if (expected->arm) {
		return test_expected_arm(handle, &actual->arm, expected->arm);
	}
	if (expected->ppc) {
		return test_expected_ppc(handle, &actual->ppc, expected->ppc);
	}
	if (expected->tricore) {
		return test_expected_tricore(handle, &actual->tricore,
					     expected->tricore);
	}
	return true;
}
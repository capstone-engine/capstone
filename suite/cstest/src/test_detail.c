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

	if (detail->alpha) {
		clone->alpha = test_detail_alpha_clone(detail->alpha);
	}
	if (detail->bpf) {
		clone->bpf = test_detail_bpf_clone(detail->bpf);
	}
	if (detail->hppa) {
		clone->hppa = test_detail_hppa_clone(detail->hppa);
	}
	if (detail->xcore) {
		clone->xcore = test_detail_xcore_clone(detail->xcore);
	}
	if (detail->systemz) {
		clone->systemz = test_detail_systemz_clone(detail->systemz);
	}
	if (detail->sparc) {
		clone->sparc = test_detail_sparc_clone(detail->sparc);
	}
	if (detail->sh) {
		clone->sh = test_detail_sh_clone(detail->sh);
	}
	if (detail->mips) {
		clone->mips = test_detail_mips_clone(detail->mips);
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
	if (detail->alpha) {
		test_detail_alpha_free(detail->alpha);
	}
	if (detail->hppa) {
		test_detail_hppa_free(detail->hppa);
	}
	if (detail->bpf) {
		test_detail_bpf_free(detail->bpf);
	}
	if (detail->xcore) {
		test_detail_xcore_free(detail->xcore);
	}
	if (detail->systemz) {
		test_detail_systemz_free(detail->systemz);
	}
	if (detail->sparc) {
		test_detail_sparc_free(detail->sparc);
	}
	if (detail->sh) {
		test_detail_sh_free(detail->sh);
	}
	if (detail->mips) {
		test_detail_mips_free(detail->mips);
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
			compare_enum_ret(actual->groups[i],
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
	if (expected->alpha) {
		return test_expected_alpha(handle, &actual->alpha,
					     expected->alpha);
	}
	if (expected->bpf) {
		return test_expected_bpf(handle, &actual->bpf,
					     expected->bpf);
	}
	if (expected->hppa) {
		return test_expected_hppa(handle, &actual->hppa,
					     expected->hppa);
	}
	if (expected->xcore) {
		return test_expected_xcore(handle, &actual->xcore,
					     expected->xcore);
	}
	if (expected->systemz) {
		return test_expected_systemz(handle, &actual->sysz,
					     expected->systemz);
	}
	if (expected->sparc) {
		return test_expected_sparc(handle, &actual->sparc,
					     expected->sparc);
	}
	if (expected->sh) {
		return test_expected_sh(handle, &actual->sh,
					     expected->sh);
	}
	if (expected->mips) {
		return test_expected_mips(handle, &actual->mips,
					     expected->mips);
	}
	return true;
}

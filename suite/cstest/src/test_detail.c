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

	clone->regs_impl_read =
		detail->regs_impl_read_count > 0 ?
			cs_mem_calloc(sizeof(char *),
				      detail->regs_impl_read_count) :
			NULL;
	clone->regs_impl_read_count = detail->regs_impl_read_count;
	for (size_t i = 0; i < detail->regs_impl_read_count; ++i) {
		clone->regs_impl_read[i] = strdup(detail->regs_impl_read[i]);
	}

	clone->regs_impl_write =
		detail->regs_impl_write_count > 0 ?
			cs_mem_calloc(sizeof(char *),
				      detail->regs_impl_write_count) :
			NULL;
	clone->regs_impl_write_count = detail->regs_impl_write_count;
	for (size_t i = 0; i < detail->regs_impl_write_count; ++i) {
		clone->regs_impl_write[i] = strdup(detail->regs_impl_write[i]);
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
	if (detail->riscv) {
		clone->riscv = test_detail_riscv_clone(detail->riscv);
	}
	if (detail->m680x) {
		clone->m680x = test_detail_m680x_clone(detail->m680x);
	}
	if (detail->tms320c64x) {
		clone->tms320c64x =
			test_detail_tms320c64x_clone(detail->tms320c64x);
	}
	if (detail->mos65xx) {
		clone->mos65xx = test_detail_mos65xx_clone(detail->mos65xx);
	}
	if (detail->evm) {
		clone->evm = test_detail_evm_clone(detail->evm);
	}
	if (detail->loongarch) {
		clone->loongarch =
			test_detail_loongarch_clone(detail->loongarch);
	}
	if (detail->wasm) {
		clone->wasm = test_detail_wasm_clone(detail->wasm);
	}
	if (detail->x86) {
		clone->x86 = test_detail_x86_clone(detail->x86);
	}
	if (detail->m68k) {
		clone->m68k = test_detail_m68k_clone(detail->m68k);
	}
	if (detail->xtensa) {
		clone->xtensa = test_detail_xtensa_clone(detail->xtensa);
	}
	if (detail->arc) {
		clone->arc = test_detail_arc_clone(detail->arc);
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

	for (size_t i = 0; i < detail->regs_impl_read_count; ++i) {
		cs_mem_free(detail->regs_impl_read[i]);
	}
	cs_mem_free(detail->regs_impl_read);

	for (size_t i = 0; i < detail->regs_impl_write_count; ++i) {
		cs_mem_free(detail->regs_impl_write[i]);
	}
	cs_mem_free(detail->regs_impl_write);

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
	if (detail->riscv) {
		test_detail_riscv_free(detail->riscv);
	}
	if (detail->m680x) {
		test_detail_m680x_free(detail->m680x);
	}
	if (detail->tms320c64x) {
		test_detail_tms320c64x_free(detail->tms320c64x);
	}
	if (detail->mos65xx) {
		test_detail_mos65xx_free(detail->mos65xx);
	}
	if (detail->evm) {
		test_detail_evm_free(detail->evm);
	}
	if (detail->loongarch) {
		test_detail_loongarch_free(detail->loongarch);
	}
	if (detail->wasm) {
		test_detail_wasm_free(detail->wasm);
	}
	if (detail->x86) {
		test_detail_x86_free(detail->x86);
	}
	if (detail->m68k) {
		test_detail_m68k_free(detail->m68k);
	}
	if (detail->xtensa) {
		test_detail_xtensa_free(detail->xtensa);
	}
	if (detail->arc) {
		test_detail_arc_free(detail->arc);
	}

	cs_mem_free(detail);
}

static bool test_reg_rw_access(csh *handle, const cs_insn *insn,
			       TestDetail *expected)
{
	assert(handle && insn && expected);
	if (expected->regs_read_count <= 0 && expected->regs_write_count <= 0) {
		return true;
	}

	cs_regs regs_read, regs_write;
	uint8_t regs_read_count, regs_write_count;
	cs_err err = cs_regs_access(*handle, insn, regs_read, &regs_read_count,
				    regs_write, &regs_write_count);
	if (err != CS_ERR_OK) {
		fprintf(stderr, "cs_regs_access() failed with '%s'\n",
			cs_strerror(err));
		return false;
	}

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
	return true;
}

static bool test_impl_reg_rw_access(csh *handle, const cs_insn *insn,
				    TestDetail *expected)
{
	assert(handle && insn && expected);
	if (expected->regs_impl_read_count <= 0 &&
	    expected->regs_impl_write_count <= 0) {
		return true;
	}
	cs_detail *actual = insn->detail;

	// Test exclusively the implicitly read or written register.
	if (expected->regs_impl_read_count > 0) {
		compare_uint32_ret(actual->regs_read_count,
				   expected->regs_impl_read_count, false);
		for (size_t i = 0; i < actual->regs_read_count; ++i) {
			compare_reg_ret(*handle, actual->regs_read[i],
					expected->regs_impl_read[i], false);
		}
	}

	if (expected->regs_impl_write_count > 0) {
		compare_uint32_ret(actual->regs_write_count,
				   expected->regs_impl_write_count, false);
		for (size_t i = 0; i < actual->regs_write_count; ++i) {
			compare_reg_ret(*handle, actual->regs_write[i],
					expected->regs_impl_write[i], false);
		}
	}
	return true;
}

bool test_expected_detail(csh *handle, const cs_insn *insn,
			  TestDetail *expected)
{
	assert(handle && insn && insn->detail && expected);
	cs_detail *actual = insn->detail;

	if (!test_reg_rw_access(handle, insn, expected)) {
		return false;
	}

	if (!test_impl_reg_rw_access(handle, insn, expected)) {
		return false;
	}

	if (expected->groups_count > 0) {
		compare_uint32_ret(actual->groups_count, expected->groups_count,
				   false);
		for (size_t i = 0; i < actual->groups_count; ++i) {
			if (strings_match(cs_group_name(*handle,
							actual->groups[i]),
					  expected->groups[i])) {
				continue;
			}
			compare_enum_ret(actual->groups[i], expected->groups[i],
					 false);
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
		return test_expected_bpf(handle, &actual->bpf, expected->bpf);
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
		return test_expected_systemz(handle, &actual->systemz,
					     expected->systemz);
	}
	if (expected->sparc) {
		return test_expected_sparc(handle, &actual->sparc,
					   expected->sparc);
	}
	if (expected->sh) {
		return test_expected_sh(handle, &actual->sh, expected->sh);
	}
	if (expected->mips) {
		return test_expected_mips(handle, &actual->mips,
					  expected->mips);
	}
	if (expected->riscv) {
		return test_expected_riscv(handle, &actual->riscv,
					   expected->riscv);
	}
	if (expected->m680x) {
		return test_expected_m680x(handle, &actual->m680x,
					   expected->m680x);
	}
	if (expected->tms320c64x) {
		return test_expected_tms320c64x(handle, &actual->tms320c64x,
						expected->tms320c64x);
	}
	if (expected->mos65xx) {
		return test_expected_mos65xx(handle, &actual->mos65xx,
					     expected->mos65xx);
	}
	if (expected->evm) {
		return test_expected_evm(handle, &actual->evm, expected->evm);
	}
	if (expected->loongarch) {
		return test_expected_loongarch(handle, &actual->loongarch,
					       expected->loongarch);
	}
	if (expected->wasm) {
		return test_expected_wasm(handle, &actual->wasm,
					  expected->wasm);
	}
	if (expected->x86) {
		return test_expected_x86(handle, &actual->x86, expected->x86);
	}
	if (expected->m68k) {
		return test_expected_m68k(handle, &actual->m68k,
					  expected->m68k);
	}
	if (expected->xtensa) {
		return test_expected_xtensa(handle, &actual->xtensa,
					    expected->xtensa);
	}
	if (expected->arc) {
		return test_expected_arc(handle, &actual->arc, expected->arc);
	}
	return true;
}

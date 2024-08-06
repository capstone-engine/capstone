// Copyright © 2024 Rot127 <unisono@quyllur.org>
// SPDX-License-Identifier: BSD-3

#include "test_compare.h"
#include "test_detail_wasm.h"
#include <capstone/capstone.h>
#include <stdio.h>
#include <string.h>

TestDetailWASM *test_detail_wasm_new()
{
	return cs_mem_calloc(sizeof(TestDetailWASM), 1);
}

void test_detail_wasm_free(TestDetailWASM *detail)
{
	if (!detail) {
		return;
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		test_detail_wasm_op_free(detail->operands[i]);
	}
	cs_mem_free(detail->operands);
	cs_mem_free(detail);
}

TestDetailWASM *test_detail_wasm_clone(const TestDetailWASM *detail)
{
	TestDetailWASM *clone = test_detail_wasm_new();

	clone->operands_count = detail->operands_count;
	if (detail->operands_count > 0) {
		clone->operands = cs_mem_calloc(sizeof(TestDetailWASMOp *),
						detail->operands_count);
	}
	for (size_t i = 0; i < detail->operands_count; ++i) {
		clone->operands[i] =
			test_detail_wasm_op_clone(detail->operands[i]);
	}

	return clone;
}

TestDetailWASMOp *test_detail_wasm_op_new()
{
	return cs_mem_calloc(sizeof(TestDetailWASMOp), 1);
}

TestDetailWASMOp *test_detail_wasm_op_clone(const TestDetailWASMOp *op)
{
	TestDetailWASMOp *clone = test_detail_wasm_op_new();

	clone->type = op->type ? strdup(op->type) : NULL;
	clone->size = op->size;
	clone->int7 = op->int7;
	clone->varuint32 = op->varuint32;
	clone->varuint64 = op->varuint64;
	clone->uint32 = op->uint32;
	clone->uint64 = op->uint64;
	clone->immediate_0 = op->immediate_0;
	clone->immediate_1 = op->immediate_1;
	clone->brt_length = op->brt_length;
	clone->brt_address = op->brt_address;
	clone->brt_default_target = op->brt_default_target;
	return clone;
}

void test_detail_wasm_op_free(TestDetailWASMOp *op)
{
	if (!op) {
		return;
	}
	cs_mem_free(op->type);
	cs_mem_free(op);
}

bool test_expected_wasm(csh *handle, const cs_wasm *actual,
			const TestDetailWASM *expected)
{
	assert(handle && actual && expected);

	compare_uint8_ret(actual->op_count, expected->operands_count, false);
	for (size_t i = 0; i < actual->op_count; ++i) {
		const cs_wasm_op *op = &actual->operands[i];
		TestDetailWASMOp *eop = expected->operands[i];
		compare_enum_ret(op->type, eop->type, false);
		switch (op->type) {
		default:
			fprintf(stderr,
				"WASM op type %" PRId32 " not handled.\n",
				op->type);
			return false;
		case WASM_OP_INT7:
			compare_int8_ret(op->int7, eop->int7, false);
			break;
		case WASM_OP_VARUINT32:
			compare_uint32_ret(op->varuint32, eop->varuint32,
					   false);
			break;
		case WASM_OP_VARUINT64:
			compare_uint64_ret(op->varuint64, eop->varuint64,
					   false);
			break;
		case WASM_OP_UINT32:
			compare_uint32_ret(op->uint32, eop->uint32, false);
			break;
		case WASM_OP_UINT64:
			compare_uint64_ret(op->uint64, eop->uint64, false);
			break;
		case WASM_OP_IMM:
			compare_uint32_ret(op->immediate[0], eop->immediate_0,
					   false);
			compare_uint32_ret(op->immediate[1], eop->immediate_1,
					   false);
			break;
		case WASM_OP_BRTABLE:
			compare_uint32_ret(op->brtable.length, eop->brt_length,
					   false);
			compare_uint32_ret(op->brtable.default_target,
					   eop->brt_default_target, false);
			compare_uint64_ret(op->brtable.address,
					   eop->brt_address, false);
			break;
		}
	}

	return true;
}

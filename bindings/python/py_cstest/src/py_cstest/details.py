# Copyright © 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

# Typing for Python3.8
from __future__ import annotations

from capstone import (
    Cs,
    CsInsn,
)
from capstone.aarch64_const import (
    AARCH64_OP_SME,
    AARCH64_OP_PRED,
    AARCH64_OP_SYSALIAS,
    AARCH64_OP_SYSIMM,
    AARCH64_OP_SYSREG,
    AARCH64_OP_FP,
    AARCH64_OP_IMM_RANGE,
    AARCH64_OP_MEM,
    AARCH64_OP_IMM,
    AARCH64_OP_REG,
)

from py_cstest.compare import (
    compare_tbool,
    compare_uint8,
    compare_int8,
    compare_uint16,
    compare_int16,
    compare_uint32,
    compare_int32,
    compare_uint64,
    compare_int64,
    compare_fp,
    compare_enum,
    compare_bit_flags,
    compare_reg,
)


def test_reg_rw_access(handle: Cs, insn: CsInsn, expected: dict):
    if ("regs_read_count" not in expected or expected["regs_read_count"] <= 0) and (
        "regs_write_count" not in expected or expected["regs_write_count"] <= 0
    ):
        return True

    regs_read, regs_write = insn.regs_access()
    if "regs_read_count" not in expected or expected["regs_read_count"] <= 0:
        if not compare_uint32(len(regs_read), expected["regs_read_count"]):
            return False
        for i, wreg in enumerate(regs_read):
            if not compare_reg(handle, wreg, expected["regs_read"][i]):
                return False

    if "regs_write_count" not in expected or expected["regs_write_count"] <= 0:
        if not compare_uint32(len(regs_write), expected["regs_write_count"]):
            return False
        for i, wreg in enumerate(regs_write):
            if not compare_reg(handle, wreg, expected["regs_write"][i]):
                return False

    return True


def test_impl_reg_rw_access(handle: Cs, insn: CsInsn, expected: dict):
    if (
        "regs_impl_read_count" not in expected or expected["regs_impl_read_count"] <= 0
    ) and (
        "regs_impl_write_count" not in expected
        or expected["regs_impl_write_count"] <= 0
    ):
        return True

    regs_impl_read = insn.detail.regs_read
    regs_impl_write = insn.detail.regs_write

    if "regs_impl_read_count" not in expected or expected["regs_impl_read_count"] <= 0:
        if not compare_uint32(len(regs_impl_read), expected["regs_impl_read_count"]):
            return False
        for i, wreg in enumerate(regs_impl_read):
            if not compare_reg(handle, wreg, expected["regs_impl_read"][i]):
                return False

    if (
        "regs_impl_write_count" not in expected
        or expected["regs_impl_write_count"] <= 0
    ):
        if not compare_uint32(len(regs_impl_write), expected["regs_impl_write_count"]):
            return False
        for i, wreg in enumerate(regs_impl_write):
            if not compare_reg(handle, wreg, expected["regs_impl_write"][i]):
                return False

    return True


def compare_details(handle: Cs, insn: CsInsn, expected: dict) -> bool:
    if not test_reg_rw_access(handle, insn, expected):
        return False

    if not test_impl_reg_rw_access(handle, insn, expected):
        return False

    # The current Python bindings don't have such a thing as
    # an detail attribute for each architecture.
    # The attributes of each <arch_detail> are directly
    # an attribute of the instruction.
    actual = insn
    if "groups_count" in expected and expected["groups_count"] > 0:
        if not compare_uint32(
            len(actual.groups), len(expected["groups"]), "group_count"
        ):
            return False

        for agroup, egroup in zip(actual.groups, expected["groups"]):
            if handle.group_name(agroup) == egroup:
                continue
            if not compare_enum(agroup, egroup, "group"):
                return False

    if "aarch64" in expected:
        return test_expected_aarch64(handle, actual, expected["aarch64"])
    elif "arm" in expected:
        return test_expected_arm(handle, actual, expected["arm"])
    elif "ppc" in expected:
        return test_expected_ppc(handle, actual, expected["ppc"])
    elif "tricore" in expected:
        return test_expected_tricore(handle, actual, expected["tricore"])
    elif "alpha" in expected:
        return test_expected_alpha(handle, actual, expected["alpha"])
    elif "bpf" in expected:
        return test_expected_bpf(handle, actual, expected["bpf"])
    elif "hppa" in expected:
        return test_expected_hppa(handle, actual, expected["hppa"])
    elif "xcore" in expected:
        return test_expected_xcore(handle, actual, expected["xcore"])
    elif "systemz" in expected:
        return test_expected_sysz(handle, actual, expected["systemz"])
    elif "sparc" in expected:
        return test_expected_sparc(handle, actual, expected["sparc"])
    elif "sh" in expected:
        return test_expected_sh(handle, actual, expected["sh"])
    elif "mips" in expected:
        return test_expected_mips(handle, actual, expected["mips"])
    elif "riscv" in expected:
        return test_expected_riscv(handle, actual, expected["riscv"])
    elif "m680x" in expected:
        return test_expected_m680x(handle, actual, expected["m680x"])
    elif "tms320c64x" in expected:
        return test_expected_tms320c64x(handle, actual, expected["tms320c64x"])
    elif "mos65xx" in expected:
        return test_expected_mos65xx(handle, actual, expected["mos65xx"])
    elif "evm" in expected:
        return test_expected_evm(handle, actual, expected["evm"])
    elif "loongarch" in expected:
        return test_expected_loongarch(handle, actual, expected["loongarch"])
    elif "wasm" in expected:
        return test_expected_wasm(handle, actual, expected["wasm"])
    elif "x86" in expected:
        return test_expected_x86(handle, actual, expected["x86"])
    elif "m68k" in expected:
        return test_expected_m68k(handle, actual, expected["m68k"])

    return True


def test_expected_x86(handle: Cs, actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_sparc(handle: Cs, actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_tricore(handle: Cs, actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_ppc(handle: Cs, actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_evm(handle: Cs, actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_alpha(handle: Cs, actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_arm(handle: Cs, actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_m680x(handle: Cs, actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_xcore(handle: Cs, actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_tms320c64x(handle: Cs, actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_aarch64(handle: Cs, actual: CsInsn, expected: dict) -> bool:
    if not compare_enum(actual.cc, expected.get("cc"), "cc"):
        return False
    if not compare_tbool(
        actual.update_flags, expected.get("update_flags"), "update_flags"
    ):
        return False
    if not compare_tbool(
        actual.post_indexed, expected.get("post_indexed"), "post_indexed"
    ):
        return False

    if not compare_uint32(
        len(actual.operands), expected.get("operands_count"), "operands_count"
    ):
        return False

    for aop, eop in zip(actual.operands, expected["operands"]):
        if not compare_enum(aop.type, eop["type"], "op type"):
            return False

        if not compare_enum(aop.sub_type, eop.get("sub_type"), "sub_type"):
            return False
        if not compare_enum(aop.access, eop.get("access"), "access"):
            return False

        if not compare_enum(aop.shift_type, eop.get("shift_type"), "shift_type"):
            return False
        if not compare_uint32(aop.shift_value, eop.get("shift_value"), "shift_value"):
            return False
        if not compare_enum(aop.ext, eop.get("ext"), "ext"):
            return False

        if not compare_enum(aop.vas, eop.get("vas"), "vas"):
            return False
        if not compare_tbool(aop.is_vreg, eop.get("is_vreg"), "is_vreg"):
            return False

        if eop.get("vector_index_is_set"):
            if compare_int32(
                aop.sme.vector_index, eop.get("vector_index"), "vector_index"
            ):
                return False

        if not compare_tbool(
            aop.is_list_member, eop.get("is_list_member"), "is_list_member"
        ):
            return False

        # Operand
        if aop.type == AARCH64_OP_REG:
            if not compare_reg(handle, aop.reg, eop.get("reg"), "reg"):
                return False
        elif aop.type == AARCH64_OP_IMM:
            if not compare_int64(aop.imm, eop.get("imm"), "imm"):
                return False
        elif aop.type == AARCH64_OP_MEM:
            if not compare_reg(handle, aop.mem_base, eop.get("mem_base"), "mem_base"):
                return False
            if not compare_reg(
                handle, aop.mem_index, eop.get("mem_index"), "mem_index"
            ):
                return False
            if not compare_int32(aop.mem_disp, eop.get("mem_disp"), "mem_disp"):
                return False
        elif aop.type == AARCH64_OP_IMM_RANGE:
            if not compare_int8(
                aop.imm_range_first, eop.get("imm_range_first"), "imm_range_first"
            ):
                return False
            if not compare_int8(
                aop.imm_range_offset, eop.get("imm_range_offset"), "imm_range_offset"
            ):
                return False
        elif aop.type == AARCH64_OP_FP:
            if not compare_fp(aop.fp, eop.get("fp"), "fp"):
                return False
        elif aop.type == AARCH64_OP_SYSREG:
            if not compare_uint64(
                aop.sys_raw_val, eop.get("sys_raw_val"), "sys_raw_val"
            ):
                return False
        elif aop.type == AARCH64_OP_SYSIMM:
            if not compare_uint64(
                aop.sys_raw_val, eop.get("sys_raw_val"), "sys_raw_val"
            ):
                return False
        elif aop.type == AARCH64_OP_SYSALIAS:
            if not compare_uint64(
                aop.sys_raw_val, eop.get("sys_raw_val"), "sys_raw_val"
            ):
                return False
        elif aop.type == AARCH64_OP_PRED:
            if not compare_reg(handle, aop.pred.reg, eop.get("pred_reg"), "pred_reg"):
                return False
            if not compare_reg(
                handle,
                aop.pred.vec_select,
                eop.get("pred_vec_select"),
                "pred_vec_select",
            ):
                return False
            if eop.get("pred_imm_index_set"):
                if not compare_int32(
                    aop.pred.imm_index, eop.get("pred_imm_index"), "pred_imm_index"
                ):
                    return False
        elif aop.type == AARCH64_OP_SME:
            if not compare_enum(aop.sme.type, eop.get("type"), "type"):
                return False
            if not compare_reg(handle, aop.sme.tile, eop.get("tile"), "tile"):
                return False
            if not compare_reg(
                handle, aop.sme.slice_reg, eop.get("slice_reg"), "slice_reg"
            ):
                return False
            if not compare_int8(
                aop.sme.slice_offset.imm,
                eop.get("slice_offset_imm"),
                "slice_offset_imm",
            ):
                return False
            if eop.get("slice_offset_ir_set"):
                if not compare_int8(
                    aop.sme.slice_offset.imm_range.first,
                    eop.get("slice_offset_ir_first"),
                    "slice_offset_ir_first",
                ):
                    return False
                if not compare_int8(
                    aop.sme.slice_offset.imm_range.offset,
                    eop.get("slice_offset_ir_offset"),
                    "slice_offset_ir_offset",
                ):
                    return False
            if not compare_tbool(
                aop.sme.has_range_offset,
                eop.get("has_range_offset"),
                "has_range_offset",
            ):
                return False
            if not compare_tbool(
                aop.sme.is_vertical, eop.get("is_vertical"), "is_vertical"
            ):
                return False
        else:
            raise ValueError(f"Operand type not handled: {aop.type}")
    return True


def test_expected_bpf(handle: Cs, actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_sh(handle: Cs, actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_hppa(handle: Cs, actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_riscv(handle: Cs, actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_m68k(handle: Cs, actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_mips(handle: Cs, actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_sysz(handle: Cs, actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_mos65xx(handle: Cs, actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_loongarch(handle: Cs, actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_wasm(handle: Cs, actual: CsInsn, expected: dict) -> bool:
    return True

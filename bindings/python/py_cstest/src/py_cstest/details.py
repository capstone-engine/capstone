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


def test_reg_rw_access(insn: CsInsn, expected: dict):
    if ("regs_read" not in expected or len(expected["regs_read"]) <= 0) and (
        "regs_write" not in expected or len(expected["regs_write"]) <= 0
    ):
        return True

    regs_read, regs_write = insn.regs_access()
    if "regs_read" in expected and len(expected["regs_read"]) > 0:
        if not compare_uint32(len(regs_read), len(expected["regs_read"]), "regs_read_count"):
            return False
        for i, rreg in enumerate(regs_read):
            if not compare_reg(insn, rreg, expected["regs_read"][i], "regs_read"):
                return False

    if "regs_write" in expected and len(expected["regs_write"]) > 0:
        if not compare_uint32(len(regs_write), len(expected["regs_write"]), "regs_write_count"):
            return False
        for i, wreg in enumerate(regs_write):
            if not compare_reg(insn, wreg, expected["regs_write"][i], "regs_write"):
                return False

    return True


def test_impl_reg_rw_access(insn: CsInsn, expected: dict):
    if ("regs_impl_read" not in expected or len(expected["regs_impl_read"]) <= 0) and (
        "regs_impl_write" not in expected or len(expected["regs_impl_write"]) <= 0
    ):
        return True

    regs_impl_read = insn.regs_read
    regs_impl_write = insn.regs_write

    if "regs_impl_read" in expected and len(expected["regs_impl_read"]) > 0:
        if not compare_uint32(
            len(regs_impl_read), len(expected["regs_impl_read"]), "regs_impl_read_count"
        ):
            return False
        for i, rreg in enumerate(regs_impl_read):
            if not compare_reg(
                insn, rreg, expected["regs_impl_read"][i], "regs_impl_read"
            ):
                return False

    if "regs_impl_write" in expected and len(expected["regs_impl_write"]) > 0:
        if not compare_uint32(
            len(regs_impl_write), len(expected["regs_impl_write"]), "regs_impl_write_count"
        ):
            return False
        for i, wreg in enumerate(regs_impl_write):
            if not compare_reg(
                insn, wreg, expected["regs_impl_write"][i], "regs_impl_write"
            ):
                return False

    return True


def compare_details(insn: CsInsn, expected: dict) -> bool:
    if expected is None:
        return True

    if not test_reg_rw_access(insn, expected):
        return False

    if not test_impl_reg_rw_access(insn, expected):
        return False

    # The current Python bindings don't have such a thing as
    # an detail attribute for each architecture.
    # The attributes of each <arch_detail> are directly
    # an attribute of the instruction.
    actual = insn
    if "groups" in expected and len(expected["groups"]) > 0:
        if not compare_uint32(len(actual.groups), len(expected["groups"]), "group"):
            return False

        for agroup, egroup in zip(actual.groups, expected["groups"]):
            if insn.group_name(agroup) == egroup:
                continue
            if not compare_enum(agroup, egroup, "group"):
                return False

    if not compare_tbool(insn.writeback, expected.get("writeback"), "writeback"):
        return False

    if "aarch64" in expected:
        return test_expected_aarch64(actual, expected["aarch64"])
    elif "arm" in expected:
        return test_expected_arm(actual, expected["arm"])
    elif "ppc" in expected:
        return test_expected_ppc(actual, expected["ppc"])
    elif "tricore" in expected:
        return test_expected_tricore(actual, expected["tricore"])
    elif "alpha" in expected:
        return test_expected_alpha(actual, expected["alpha"])
    elif "bpf" in expected:
        return test_expected_bpf(actual, expected["bpf"])
    elif "hppa" in expected:
        return test_expected_hppa(actual, expected["hppa"])
    elif "xcore" in expected:
        return test_expected_xcore(actual, expected["xcore"])
    elif "systemz" in expected:
        return test_expected_sysz(actual, expected["systemz"])
    elif "sparc" in expected:
        return test_expected_sparc(actual, expected["sparc"])
    elif "sh" in expected:
        return test_expected_sh(actual, expected["sh"])
    elif "mips" in expected:
        return test_expected_mips(actual, expected["mips"])
    elif "riscv" in expected:
        return test_expected_riscv(actual, expected["riscv"])
    elif "m680x" in expected:
        return test_expected_m680x(actual, expected["m680x"])
    elif "tms320c64x" in expected:
        return test_expected_tms320c64x(actual, expected["tms320c64x"])
    elif "mos65xx" in expected:
        return test_expected_mos65xx(actual, expected["mos65xx"])
    elif "evm" in expected:
        return test_expected_evm(actual, expected["evm"])
    elif "loongarch" in expected:
        return test_expected_loongarch(actual, expected["loongarch"])
    elif "wasm" in expected:
        return test_expected_wasm(actual, expected["wasm"])
    elif "x86" in expected:
        return test_expected_x86(actual, expected["x86"])
    elif "m68k" in expected:
        return test_expected_m68k(actual, expected["m68k"])

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


def test_expected_aarch64(actual: CsInsn, expected: dict) -> bool:
    if not compare_enum(actual.cc, expected.get("cc"), "cc"):
        return False
    if not compare_tbool(
        actual.update_flags, expected.get("update_flags"), "update_flags"
    ):
        return False
    if not compare_tbool(
        actual.post_index, expected.get("post_indexed"), "post_indexed"
    ):
        return False

    if "operands" not in expected:
        return True
    elif not compare_uint32(
        len(actual.operands), len(expected.get("operands")), "operands_count"
    ):
        return False

    for aop, eop in zip(actual.operands, expected["operands"]):
        if not compare_enum(aop.access, eop.get("access"), "access"):
            return False

        if not compare_enum(aop.shift.type, eop.get("shift_type"), "shift_type"):
            return False
        if not compare_uint32(aop.shift.value, eop.get("shift_value"), "shift_value"):
            return False
        if not compare_enum(aop.ext, eop.get("ext"), "ext"):
            return False

        if not compare_enum(aop.vas, eop.get("vas"), "vas"):
            return False
        if not compare_tbool(aop.is_vreg, eop.get("is_vreg"), "is_vreg"):
            return False

        if eop.get("vector_index_is_set"):
            if compare_int32(aop.vector_index, eop.get("vector_index"), "vector_index"):
                return False

        if not compare_tbool(
            aop.is_list_member, eop.get("is_list_member"), "is_list_member"
        ):
            return False

        if not compare_enum(aop.type, eop["type"], "op type"):
            return False
        # Operand
        if aop.type == AARCH64_OP_REG:
            if not compare_reg(actual, aop.value.reg, eop.get("reg"), "reg"):
                return False
        elif aop.type == AARCH64_OP_IMM:
            if not compare_int64(aop.value.imm, eop.get("imm"), "imm"):
                return False
        elif aop.type == AARCH64_OP_MEM:
            if not compare_reg(
                actual, aop.value.mem.base, eop.get("mem_base"), "mem_base"
            ):
                return False
            if not compare_reg(
                actual, aop.value.mem.index, eop.get("mem_index"), "mem_index"
            ):
                return False
            if not compare_int32(aop.value.mem.disp, eop.get("mem_disp"), "mem_disp"):
                return False
        elif aop.type == AARCH64_OP_IMM_RANGE:
            if not compare_int8(
                aop.value.imm_range.first, eop.get("imm_range_first"), "imm_range_first"
            ):
                return False
            if not compare_int8(
                aop.value.imm_range.offset,
                eop.get("imm_range_offset"),
                "imm_range_offset",
            ):
                return False
        elif aop.type == AARCH64_OP_FP:
            if not compare_fp(aop.value.fp, eop.get("fp"), "fp"):
                return False
        elif aop.type == AARCH64_OP_SYSREG:
            if not compare_enum(
                aop.value.sysop.sub_type, eop.get("sub_type"), "sub_type"
            ):
                return False
            if not compare_uint64(
                aop.value.sysop.reg.raw_val, eop.get("sys_raw_val"), "sys_raw_val"
            ):
                return False
        elif aop.type == AARCH64_OP_SYSIMM:
            if not compare_enum(
                aop.value.sysop.sub_type, eop.get("sub_type"), "sub_type"
            ):
                return False
            if not compare_uint64(
                aop.value.sysop.imm.raw_val, eop.get("sys_raw_val"), "sys_raw_val"
            ):
                return False
        elif aop.type == AARCH64_OP_SYSALIAS:
            if not compare_enum(
                aop.value.sysop.sub_type, eop.get("sub_type"), "sub_type"
            ):
                return False
            if not compare_uint64(
                aop.value.sysop.alias.raw_val, eop.get("sys_raw_val"), "sys_raw_val"
            ):
                return False
        elif aop.type == AARCH64_OP_PRED:
            if not compare_reg(
                actual, aop.value.pred.reg, eop.get("pred_reg"), "pred_reg"
            ):
                return False
            if not compare_reg(
                actual,
                aop.value.pred.vec_select,
                eop.get("pred_vec_select"),
                "pred_vec_select",
            ):
                return False
            if eop.get("pred_imm_index_set"):
                if not compare_int32(
                    aop.value.pred.imm_index,
                    eop.get("pred_imm_index"),
                    "pred_imm_index",
                ):
                    return False
        elif aop.type == AARCH64_OP_SME:
            if "sme" not in eop:
                continue

            if not compare_enum(aop.value.sme.type, eop["sme"].get("type"), "type"):
                return False
            if not compare_reg(
                actual, aop.value.sme.tile, eop["sme"].get("tile"), "tile"
            ):
                return False
            if not compare_reg(
                actual,
                aop.value.sme.slice_reg,
                eop["sme"].get("slice_reg"),
                "slice_reg",
            ):
                return False
            if not compare_int8(
                aop.value.sme.slice_offset.imm,
                eop["sme"].get("slice_offset_imm"),
                "slice_offset_imm",
            ):
                return False
            if eop["sme"].get("slice_offset_ir_set"):
                if not compare_int8(
                    aop.value.sme.slice_offset.imm_range.first,
                    eop["sme"].get("slice_offset_ir_first"),
                    "slice_offset_ir_first",
                ):
                    return False
                if not compare_int8(
                    aop.value.sme.slice_offset.imm_range.offset,
                    eop["sme"].get("slice_offset_ir_offset"),
                    "slice_offset_ir_offset",
                ):
                    return False
            if not compare_tbool(
                aop.value.sme.has_range_offset,
                eop["sme"].get("has_range_offset"),
                "has_range_offset",
            ):
                return False
            if not compare_tbool(
                aop.value.sme.is_vertical, eop["sme"].get("is_vertical"), "is_vertical"
            ):
                return False
        else:
            raise ValueError(f"Operand type not handled: {aop.type}")
    return True


def test_expected_bpf(actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_sh(actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_hppa(actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_riscv(actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_m68k(actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_mips(actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_sysz(actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_mos65xx(actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_loongarch(actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_wasm(actual: CsInsn, expected: dict) -> bool:
    return True

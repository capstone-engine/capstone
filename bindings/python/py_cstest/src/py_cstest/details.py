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

from capstone.x86_const import (
    X86_OP_MEM,
    X86_OP_IMM,
    X86_OP_REG,
)

from capstone.arm_const import (
    ARM_OP_PRED,
    ARM_OP_CIMM,
    ARM_OP_PIMM,
    ARM_OP_SETEND,
    ARM_OP_SYSREG,
    ARM_OP_BANKEDREG,
    ARM_OP_SPSR,
    ARM_OP_CPSR,
    ARM_OP_SYSM,
    ARM_OP_FP,
    ARM_OP_MEM,
    ARM_OP_IMM,
    ARM_OP_REG,
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
        if not compare_uint32(
            len(regs_read), len(expected["regs_read"]), "regs_read_count"
        ):
            return False
        for i, rreg in enumerate(regs_read):
            if not compare_reg(insn, rreg, expected["regs_read"][i], "regs_read"):
                return False

    if "regs_write" in expected and len(expected["regs_write"]) > 0:
        if not compare_uint32(
            len(regs_write), len(expected["regs_write"]), "regs_write_count"
        ):
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
            len(regs_impl_write),
            len(expected["regs_impl_write"]),
            "regs_impl_write_count",
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


def test_expected_x86(actual: CsInsn, expected: dict) -> bool:
    if not compare_reg(
        actual, actual.sib_index, expected.get("sib_index"), "sib_index"
    ):
        return False
    if not compare_reg(actual, actual.sib_base, expected.get("sib_base"), "sib_base"):
        return False
    if not compare_enum(actual.xop_cc, expected.get("xop_cc"), "xop_cc"):
        return False
    if not compare_enum(actual.sse_cc, expected.get("sse_cc"), "sse_cc"):
        return False
    if not compare_enum(actual.avx_cc, expected.get("avx_cc"), "avx_cc"):
        return False
    if not compare_enum(actual.avx_rm, expected.get("avx_rm"), "avx_rm"):
        return False

    for i, prefix in enumerate(expected.get("prefix")):
        if not compare_enum(actual.prefix[i], expected.get("prefix")[i], "prefix"):
            return False

    for i, opcode in enumerate(expected.get("opcode")):
        if not compare_uint8(actual.opcode[i], expected.get("opcode")[i], "opcode"):
            return False

    if not compare_uint8(actual.rex, expected.get("rex"), "rex"):
        return False
    if not compare_uint8(actual.addr_size, expected.get("addr_size"), "addr_size"):
        return False
    if not compare_uint8(actual.modrm, expected.get("modrm"), "modrm"):
        return False
    if not compare_uint8(actual.sib, expected.get("sib"), "sib"):
        return False
    if not compare_int64(actual.disp, expected.get("disp"), "disp"):
        return False
    if not compare_int8(actual.sib_scale, expected.get("sib_scale"), "sib_scale"):
        return False
    if not compare_tbool(actual.avx_sae, expected.get("avx_sae"), "avx_sae"):
        return False

    if not compare_bit_flags(actual.eflags, expected.get("eflags"), "eflags"):
        return False
    if not compare_bit_flags(actual.fpu_flags, expected.get("fpu_flags"), "fpu_flags"):
        return False

    if not compare_uint8(
        actual.encoding.modrm_offset,
        expected.get("enc_modrm_offset"),
        "enc_modrm_offset",
    ):
        return False
    if not compare_uint8(
        actual.encoding.disp_offset, expected.get("enc_disp_offset"), "enc_disp_offset"
    ):
        return False
    if not compare_uint8(
        actual.encoding.disp_size, expected.get("enc_disp_size"), "enc_disp_size"
    ):
        return False
    if not compare_uint8(
        actual.encoding.imm_offset, expected.get("enc_imm_offset"), "enc_imm_offset"
    ):
        return False
    if not compare_uint8(
        actual.encoding.imm_size, expected.get("enc_imm_size"), "enc_imm_size"
    ):
        return False

    if "operands" not in expected:
        return True
    elif not compare_uint32(
        len(actual.operands), len(expected["operands"]), "operands_count"
    ):
        return False

    for aop, eop in zip(actual.operands, expected["operands"]):
        if not compare_enum(aop.type, eop.get("type"), "type"):
            return False
        if not compare_enum(aop.access, eop.get("access"), "access"):
            return False
        if not compare_uint8(aop.size, eop.get("size"), "size"):
            return False
        if not compare_enum(aop.avx_bcast, eop.get("avx_bcast"), "avx_bcast"):
            return False
        if not compare_tbool(
            aop.avx_zero_opmask, eop.get("avx_zero_opmask"), "avx_zero_opmask"
        ):
            return False

        if aop.type == X86_OP_REG:
            if not compare_reg(actual, aop.reg, eop.get("reg"), "reg"):
                return False
        elif aop.type == X86_OP_IMM:
            if not compare_int64(aop.imm, eop.get("imm"), "imm"):
                return False
        elif aop.type == X86_OP_MEM:
            if not compare_reg(
                actual, aop.mem.segment, eop.get("mem_segment"), "mem_segment"
            ):
                return False
            if not compare_reg(actual, aop.mem.base, eop.get("mem_base"), "mem_base"):
                return False
            if not compare_reg(
                actual, aop.mem.index, eop.get("mem_index"), "mem_index"
            ):
                return False
            if not compare_int32(aop.mem.scale, eop.get("mem_scale"), "mem_scale"):
                return False
            if not compare_int64(aop.mem.disp, eop.get("mem_disp"), "mem_disp"):
                return False
        else:
            raise ValueError("x86 operand type not handled")

    return True


def test_expected_sparc(actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_tricore(actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_ppc(actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_evm(actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_alpha(actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_arm(actual: CsInsn, expected: dict) -> bool:
    if not compare_int32(
        actual.vector_size, expected.get("vector_size"), "vector_size"
    ):
        return False
    if not compare_enum(actual.vector_data, expected.get("vector_data"), "vector_data"):
        return False
    if not compare_enum(actual.cps_mode, expected.get("cps_mode"), "cps_mode"):
        return False
    if not compare_enum(actual.cps_flag, expected.get("cps_flag"), "cps_flag"):
        return False
    if not compare_enum(actual.cc, expected.get("cc"), "cc"):
        return False
    if not compare_enum(actual.vcc, expected.get("vcc"), "vcc"):
        return False
    if not compare_enum(actual.mem_barrier, expected.get("mem_barrier"), "mem_barrier"):
        return False
    if not compare_uint8(actual.pred_mask, expected.get("pred_mask"), "pred_mask"):
        return False

    if not compare_tbool(actual.usermode, expected.get("usermode"), "usermode"):
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
        if not compare_enum(aop.type, eop.get("type"), "type"):
            return False
        if not compare_enum(aop.access, eop.get("access"), "access"):
            return False

        if aop.type == ARM_OP_REG:
            if not compare_reg(actual, aop.reg, eop.get("reg"), "reg"):
                return False
        elif (
            aop.type == ARM_OP_IMM or aop.type == ARM_OP_PIMM or aop.type == ARM_OP_CIMM
        ):
            if not compare_int64(aop.imm, eop.get("imm"), "imm"):
                return False
        elif aop.type == ARM_OP_SETEND:
            if not compare_enum(aop.setend, eop.get("setend"), "setend"):
                return False
        elif aop.type == ARM_OP_PRED:
            if not compare_int32(aop.pred, eop.get("pred"), "pred"):
                return False
        elif aop.type == ARM_OP_FP:
            if not compare_fp(aop.fp, eop.get("fp"), "fp"):
                return False
        elif aop.type == ARM_OP_MEM:
            if not compare_reg(actual, aop.mem.base, eop.get("mem_base"), "mem_base"):
                return False
            if not compare_reg(
                actual, aop.mem.index, eop.get("mem_index"), "mem_index"
            ):
                return False
            if not compare_int32(aop.mem.scale, eop.get("mem_scale"), "mem_scale"):
                return False
            if not compare_int32(aop.mem.disp, eop.get("mem_disp"), "mem_disp"):
                return False
            if not compare_uint32(aop.mem.align, eop.get("mem_align"), "mem_align"):
                return False
        elif aop.type == ARM_OP_SYSREG:
            if not compare_enum(
                aop.sysop.reg.mclasssysreg, eop.get("sys_reg"), "sys_reg"
            ):
                return False
            if not compare_int32(aop.sysop.sysm, eop.get("sys_sysm"), "sys_sysm"):
                return False
            if not compare_int32(
                aop.sysop.msr_mask, eop.get("sys_msr_mask"), "sys_msr_mask"
            ):
                return False
        elif aop.type == ARM_OP_BANKEDREG:
            if not compare_enum(aop.sysop.reg.bankedreg, eop.get("sys_reg"), "sys_reg"):
                return False
            if not compare_int32(aop.sysop.sysm, eop.get("sys_sysm"), "sys_sysm"):
                return False
            if not compare_int32(
                aop.sysop.msr_mask, eop.get("sys_msr_mask"), "sys_msr_mask"
            ):
                return False
        elif aop.type == ARM_OP_SPSR or aop.type == ARM_OP_CPSR:
            if not compare_bit_flags(
                aop.sysop.psr_bits, eop.get("sys_psr_bits"), "sys_psr_bits"
            ):
                return False
            if not compare_int32(aop.sysop.sysm, eop.get("sys_sysm"), "sys_sysm"):
                return False
            if not compare_int32(
                aop.sysop.msr_mask, eop.get("sys_msr_mask"), "sys_msr_mask"
            ):
                return False
        elif aop.type == ARM_OP_SYSM:
            if not compare_int32(aop.sysop.sysm, eop.get("sys_sysm"), "sys_sysm"):
                return False
            if not compare_int32(
                aop.sysop.msr_mask, eop.get("sys_msr_mask"), "sys_msr_mask"
            ):
                return False
        else:
            raise ValueError("ARM operand type not handled")

        if not compare_enum(aop.shift.type, eop.get("shift_type"), "shift_type"):
            return False
        if not compare_uint32(aop.shift.value, eop.get("shift_value"), "shift_value"):
            return False

        if not compare_int8(aop.neon_lane, eop.get("neon_lane"), "neon_lane"):
            return False

        if expected.get("vector_index_is_set"):
            if not compare_int32(
                aop.vector_index, eop.get("vector_index"), "vector_index"
            ):
                return False

        if not compare_tbool(aop.subtracted, eop.get("subtracted"), "subtracted"):
            return False
    return True


def test_expected_m680x(actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_xcore(actual: CsInsn, expected: dict) -> bool:
    return True


def test_expected_tms320c64x(actual: CsInsn, expected: dict) -> bool:
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
            if not compare_int32(
                aop.vector_index, eop.get("vector_index"), "vector_index"
            ):
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

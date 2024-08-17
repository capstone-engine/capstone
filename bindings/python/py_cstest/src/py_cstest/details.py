# Copyright © 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

# Typing for Python3.8
from __future__ import annotations

from capstone import (
    Cs,
    CsInsn,
)

from capstone.x86 import CsX86
from capstone.sparc import CsSparc
from capstone.tricore import CsTriCore
from capstone.ppc import CsPpc
from capstone.evm import CsEvm
from capstone.alpha import CsAlpha
from capstone.arm import CsArm
from capstone.m680x import CsM680x
from capstone.xcore import CsXcore
from capstone.tms320c64x import CsTMS320C64x
from capstone.aarch64 import CsAArch64
from capstone.bpf import CsBPF
from capstone.sh import CsSH
from capstone.hppa import CsHPPA
from capstone.riscv import CsRISCV
from capstone.m68k import CsM68K
from capstone.mips import CsMips
from capstone.systemz import CsSysz
from capstone.mos65xx import CsMOS65xx
from capstone.loongarch import CsLoongArch
from capstone.wasm import CsWasm

from py_cstest.compare import (
    compare_asm_text,
    compare_str,
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
    pass


def test_impl_reg_rw_access(handle: Cs, insn: CsInsn, expected: dict):
    pass


def compare_details(handle: Cs, insn: CsInsn, expected: dict) -> bool:
    if not test_reg_rw_access(handle, insn, expected):
        return False

    if not test_impl_reg_rw_access(handle, insn, expected):
        return False

    actual = insn.detail
    if expected.groups_count > 0:
        if not compare_uint32(len(actual.groups), len(expected.groups)):
            return False

        for agroup, egroup in zip(actual.groups, expected.groups):
            if handle.group_name(agroup) == egroup:
                continue
            if not compare_enum(agroup, egroup):
                return False

    if "aarch64" in expected:
        return test_expected_aarch64(handle, actual.aarch64, expected["aarch64"])
    elif "arm" in expected:
        return test_expected_arm(handle, actual.arm, expected["arm"])
    elif "ppc" in expected:
        return test_expected_ppc(handle, actual.ppc, expected["ppc"])
    elif "tricore" in expected:
        return test_expected_tricore(handle, actual.tricore, expected["tricore"])
    elif "alpha" in expected:
        return test_expected_alpha(handle, actual.alpha, expected["alpha"])
    elif "bpf" in expected:
        return test_expected_bpf(handle, actual.bpf, expected["bpf"])
    elif "hppa" in expected:
        return test_expected_hppa(handle, actual.hppa, expected["hppa"])
    elif "xcore" in expected:
        return test_expected_xcore(handle, actual.xcore, expected["xcore"])
    elif "systemz" in expected:
        return test_expected_sysz(handle, actual.sysz, expected["systemz"])
    elif "sparc" in expected:
        return test_expected_sparc(handle, actual.sparc, expected["sparc"])
    elif "sh" in expected:
        return test_expected_sh(handle, actual.sh, expected["sh"])
    elif "mips" in expected:
        return test_expected_mips(handle, actual.mips, expected["mips"])
    elif "riscv" in expected:
        return test_expected_riscv(handle, actual.riscv, expected["riscv"])
    elif "m680x" in expected:
        return test_expected_m680x(handle, actual.m680x, expected["m680x"])
    elif "tms320c64x" in expected:
        return test_expected_tms320c64x(
            handle, actual.tms320c64x, expected["tms320c64x"]
        )
    elif "mos65xx" in expected:
        return test_expected_mos65xx(handle, actual.mos65xx, expected["mos65xx"])
    elif "evm" in expected:
        return test_expected_evm(handle, actual.evm, expected["evm"])
    elif "loongarch" in expected:
        return test_expected_loongarch(handle, actual.loongarch, expected["loongarch"])
    elif "wasm" in expected:
        return test_expected_wasm(handle, actual.wasm, expected["wasm"])
    elif "x86" in expected:
        return test_expected_x86(handle, actual.x86, expected["x86"])
    elif "m68k" in expected:
        return test_expected_m68k(handle, actual.m68k, expected["m68k"])

    return True


def test_expected_x86(handle: Cs, actual: CsX86, expected: dict):
    pass


def test_expected_sparc(handle: Cs, actual: CsSparc, expected: dict):
    pass


def test_expected_tricore(handle: Cs, actual: CsTriCore, expected: dict):
    pass


def test_expected_ppc(handle: Cs, actual: CsPpc, expected: dict):
    pass


def test_expected_evm(handle: Cs, actual: CsEvm, expected: dict):
    pass


def test_expected_alpha(handle: Cs, actual: CsAlpha, expected: dict):
    pass


def test_expected_arm(handle: Cs, actual: CsArm, expected: dict):
    pass


def test_expected_m680x(handle: Cs, actual: CsM680x, expected: dict):
    pass


def test_expected_xcore(handle: Cs, actual: CsXcore, expected: dict):
    pass


def test_expected_tms320c64x(handle: Cs, actual: CsTMS320C64x, expected: dict):
    pass


def test_expected_aarch64(handle: Cs, actual: CsAArch64, expected: dict):
    pass


def test_expected_bpf(handle: Cs, actual: CsBPF, expected: dict):
    pass


def test_expected_sh(handle: Cs, actual: CsSH, expected: dict):
    pass


def test_expected_hppa(handle: Cs, actual: CsHPPA, expected: dict):
    pass


def test_expected_riscv(handle: Cs, actual: CsRISCV, expected: dict):
    pass


def test_expected_m68k(handle: Cs, actual: CsM68K, expected: dict):
    pass


def test_expected_mips(handle: Cs, actual: CsMips, expected: dict):
    pass


def test_expected_sysz(handle: Cs, actual: CsSysz, expected: dict):
    pass


def test_expected_mos65xx(handle: Cs, actual: CsMOS65xx, expected: dict):
    pass


def test_expected_loongarch(handle: Cs, actual: CsLoongArch, expected: dict):
    pass


def test_expected_wasm(handle: Cs, actual: CsWasm, expected: dict):
    pass

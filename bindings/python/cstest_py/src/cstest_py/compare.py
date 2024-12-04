# Copyright © 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

# Typing for Python3.8
from __future__ import annotations

import struct
import capstone
import re
from capstone import arm_const
from capstone import aarch64_const
from capstone import m68k_const
from capstone import mips_const
from capstone import ppc_const
from capstone import sparc_const
from capstone import systemz_const
from capstone import x86_const
from capstone import xcore_const
from capstone import tms320c64x_const
from capstone import m680x_const
from capstone import evm_const
from capstone import mos65xx_const
from capstone import wasm_const
from capstone import bpf_const
from capstone import riscv_const
from capstone import sh_const
from capstone import tricore_const
from capstone import alpha_const
from capstone import hppa_const
from capstone import loongarch_const
from capstone import arc_const


def cs_const_getattr(identifier: str):
    attr = getattr(capstone, identifier, None)
    if attr is not None:
        return attr
    attr = getattr(arm_const, identifier, None)
    if attr is not None:
        return attr
    attr = getattr(aarch64_const, identifier, None)
    if attr is not None:
        return attr
    attr = getattr(m68k_const, identifier, None)
    if attr is not None:
        return attr
    attr = getattr(mips_const, identifier, None)
    if attr is not None:
        return attr
    attr = getattr(ppc_const, identifier, None)
    if attr is not None:
        return attr
    attr = getattr(sparc_const, identifier, None)
    if attr is not None:
        return attr
    attr = getattr(systemz_const, identifier, None)
    if attr is not None:
        return attr
    attr = getattr(x86_const, identifier, None)
    if attr is not None:
        return attr
    attr = getattr(xcore_const, identifier, None)
    if attr is not None:
        return attr
    attr = getattr(tms320c64x_const, identifier, None)
    if attr is not None:
        return attr
    attr = getattr(m680x_const, identifier, None)
    if attr is not None:
        return attr
    attr = getattr(evm_const, identifier, None)
    if attr is not None:
        return attr
    attr = getattr(mos65xx_const, identifier, None)
    if attr is not None:
        return attr
    attr = getattr(wasm_const, identifier, None)
    if attr is not None:
        return attr
    attr = getattr(bpf_const, identifier, None)
    if attr is not None:
        return attr
    attr = getattr(riscv_const, identifier, None)
    if attr is not None:
        return attr
    attr = getattr(sh_const, identifier, None)
    if attr is not None:
        return attr
    attr = getattr(tricore_const, identifier, None)
    if attr is not None:
        return attr
    attr = getattr(alpha_const, identifier, None)
    if attr is not None:
        return attr
    attr = getattr(hppa_const, identifier, None)
    if attr is not None:
        return attr
    attr = getattr(loongarch_const, identifier, None)
    if attr is not None:
        return attr
    attr = getattr(arc_const, identifier, None)
    if attr is not None:
        return attr
    raise ValueError(f"Python capstone doesn't have the constant: {identifier}")


def twos_complement(val, bits):
    if (val & (1 << (bits - 1))) != 0:
        val = val - (1 << bits)
    return val & ((1 << bits) - 1)


def normalize_asm_text(text: str, arch_bits: int) -> str:
    text = text.strip()
    text = re.sub(r"\s+", " ", text)
    # Replace hex numbers with decimals
    for hex_num in re.findall(r"0x[0-9a-fA-F]+", text):
        text = re.sub(hex_num, f"{int(hex_num, base=16)}", text, count=1)
    # Replace negatives with twos-complement
    for num in re.findall(r"-\d+", text):
        n = twos_complement(int(num, base=10), arch_bits)
        text = re.sub(num, f"{n}", text)
    text = text.lower()
    return text


def compare_asm_text(
    a_insn: capstone.CsInsn, expected: None | str, arch_bits: int
) -> bool:
    if expected is None:
        return True
    from cstest_py.cstest import log

    actual = f"{a_insn.mnemonic} {a_insn.op_str}"
    actual = normalize_asm_text(actual, arch_bits)
    expected = normalize_asm_text(expected, arch_bits)

    if actual != expected:
        log.error(
            "Normalized asm-text doesn't match:\n"
            f"decoded:  '{actual}'\n"
            f"expected: '{expected}'\n"
        )
        return False
    return True


def compare_str(actual: str, expected: None | str, msg: str) -> bool:
    if expected is None:
        return True
    from cstest_py.cstest import log

    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_tbool(actual: bool, expected: None | int, msg: str) -> bool:
    if expected is None:
        return True
    from cstest_py.cstest import log

    if expected == 0:
        # Unset
        return True

    if (expected < 0 and actual) or (expected > 0 and not actual):
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_uint8(actual: int, expected: None | int, msg: str) -> bool:
    if expected is None:
        return True
    from cstest_py.cstest import log

    actual = actual & 0xFF
    expected = expected & 0xFF
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_int8(actual: int, expected: None | int, msg: str) -> bool:
    if expected is None:
        return True
    from cstest_py.cstest import log

    actual = actual & 0xFF
    expected = expected & 0xFF
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_uint16(actual: int, expected: None | int, msg: str) -> bool:
    if expected is None:
        return True
    from cstest_py.cstest import log

    actual = actual & 0xFFFF
    expected = expected & 0xFFFF
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_int16(actual: int, expected: None | int, msg: str) -> bool:
    if expected is None:
        return True
    from cstest_py.cstest import log

    actual = actual & 0xFFFF
    expected = expected & 0xFFFF
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_uint32(actual: int, expected: None | int, msg: str) -> bool:
    if expected is None:
        return True
    from cstest_py.cstest import log

    actual = actual & 0xFFFFFFFF
    expected = expected & 0xFFFFFFFF
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_int32(actual: int, expected: None | int, msg: str) -> bool:
    if expected is None:
        return True
    from cstest_py.cstest import log

    actual = actual & 0xFFFFFFFF
    expected = expected & 0xFFFFFFFF
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_uint64(actual: int, expected: None | int, msg: str) -> bool:
    if expected is None:
        return True
    from cstest_py.cstest import log

    actual = actual & 0xFFFFFFFFFFFFFFFF
    expected = expected & 0xFFFFFFFFFFFFFFFF
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_int64(actual: int, expected: None | int, msg: str) -> bool:
    if expected is None:
        return True
    from cstest_py.cstest import log

    actual = actual & 0xFFFFFFFFFFFFFFFF
    expected = expected & 0xFFFFFFFFFFFFFFFF
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_fp(actual: float, expected: None | float, msg: str) -> bool:
    if expected is None:
        return True
    from cstest_py.cstest import log

    def floatToBits(f):
        return struct.unpack("=L", struct.pack("=f", f))[0]

    if floatToBits(actual) != floatToBits(expected):
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_dp(actual: float, expected: None | float, msg: str) -> bool:
    if expected is None:
        return True
    from cstest_py.cstest import log

    def doubleToBits(f):
        return struct.unpack("=Q", struct.pack("=d", f))[0]

    if doubleToBits(actual) != doubleToBits(expected):
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_enum(actual, expected: None | str, msg: str) -> bool:
    if expected is None:
        return True
    from cstest_py.cstest import log

    enum_val = cs_const_getattr(expected)
    if actual != enum_val:
        log.error(f"{msg}: {actual} != {expected} ({enum_val})")
        return False
    return True


def compare_bit_flags(actual: int, expected: None | list[str], msg: str) -> bool:
    if expected is None:
        return True
    from cstest_py.cstest import log

    for flag in expected:
        enum_val = cs_const_getattr(flag)
        if not actual & enum_val:
            log.error(f"{msg}: In {actual:x} the flag {expected} isn't set.")
            return False
    return True


def compare_reg(
    insn: capstone.CsInsn, actual: int, expected: None | str, msg: str
) -> bool:
    if expected is None:
        return True
    from cstest_py.cstest import log

    if insn.reg_name(actual) != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True

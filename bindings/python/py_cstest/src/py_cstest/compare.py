# Copyright © 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

# Typing for Python3.8
from __future__ import annotations

import capstone
import re


def normalize_asm_text(text: str, arch_bits: int) -> str:
    text = text.strip()
    text = re.sub(r"\s+", " ", text)
    # Replace hex numbers with decimals
    for hex_num in re.findall(r"0x[0-9a-fA-F]+", text):
        text = re.sub(hex_num, f"{int(hex_num, base=16)}", text)
    # Replace negatives with twos-complement
    for num in re.findall(r"-\d+", text):
        text = re.sub(num, f"{~(int(num, base=10) % (1 << arch_bits)) + 1}", text)
    text = text.lower()
    return text


def compare_asm_text(a_insn: capstone.CsInsn, expected: str, arch_bits: int) -> bool:
    from py_cstest.cstest import log

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


def compare_str(actual: str, expected: str, msg: str) -> bool:
    from py_cstest.cstest import log

    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_tbool(actual: bool, expected: int, msg: str) -> bool:
    from py_cstest.cstest import log

    if expected == 0:
        # Unset
        return True

    if (expected < 0 and actual) or (expected > 0 and not actual):
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_uint8(actual: int, expected: int, msg: str) -> bool:
    from py_cstest.cstest import log

    actual = actual & 0xFF
    expected = expected & 0xFF
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_int8(actual: int, expected: int, msg: str) -> bool:
    from py_cstest.cstest import log

    actual = actual & 0xFF
    expected = expected & 0xFF
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_uint16(actual: int, expected: int, msg: str) -> bool:
    from py_cstest.cstest import log

    actual = actual & 0xFFFF
    expected = expected & 0xFFFF
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_int16(actual: int, expected: int, msg: str) -> bool:
    from py_cstest.cstest import log

    actual = actual & 0xFFFF
    expected = expected & 0xFFFF
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_uint32(actual: int, expected: int, msg: str) -> bool:
    from py_cstest.cstest import log

    actual = actual & 0xFFFFFFFF
    expected = expected & 0xFFFFFFFF
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_int32(actual: int, expected: int, msg: str) -> bool:
    from py_cstest.cstest import log

    actual = actual & 0xFFFFFFFF
    expected = expected & 0xFFFFFFFF
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_uint64(actual: int, expected: int, msg: str) -> bool:
    from py_cstest.cstest import log

    actual = actual & 0xFFFFFFFFFFFFFFFF
    expected = expected & 0xFFFFFFFFFFFFFFFF
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_int64(actual: int, expected: int, msg: str) -> bool:
    from py_cstest.cstest import log

    actual = actual & 0xFFFFFFFFFFFFFFFF
    expected = expected & 0xFFFFFFFFFFFFFFFF
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_fp(actual: float, expected: float, msg: str) -> bool:
    from py_cstest.cstest import log

    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_enum(actual, expected, msg: str) -> bool:
    from py_cstest.cstest import log

    enum_val = getattr(capstone, expected)
    if not enum_val:
        log.error(f"capstone package doesn't have the an attribute '{expected}'")
        return False
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_bit_flags(actual: int, expected: list[str], msg: str) -> bool:
    from py_cstest.cstest import log

    for flag in expected:
        enum_val = getattr(capstone, flag)
        if not enum_val:
            log.error(f"capstone package doesn't have the an attribute '{expected}'")
            return False
        if not actual & enum_val:
            log.error(f"{msg}: In {actual:x} the flag {expected} isn't set.")
            return False
    return True


def compare_reg(handle: capstone.Cs, actual: int, expected: str, msg: str) -> bool:
    from py_cstest.cstest import log

    if handle.reg_name(actual) != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True

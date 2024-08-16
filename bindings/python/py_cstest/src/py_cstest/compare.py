# Copyright © 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import capstone
import logging as log
import re


def compare_asm_text(a_insn: capstone.CsInsn, expected: str, arch_bits: int) -> bool:
    actual = f"{a_insn.mnemonic} {a_insn.op_str}"
    actual = actual.strip()
    actual = re.sub(r"\s+", " ", actual)
    # Replace hex numbers with decimals
    for hex_num in re.findall(r"0x[0-9a-fA-F]+", actual):
        actual = re.sub(hex_num, f"{int(hex_num, base=16)}", actual)
    # Replace negatives with twos-complement
    for num in re.findall(r"\d+", actual):
        actual = re.sub(num, f"{~(num % (1 << arch_bits)) + 1}", actual)
    actual = actual.lower()

    if actual != expected:
        log.error(
            "Normalized asm-text doesn't match:\n"
            f"decoded:  '{actual}'\n"
            f"expected: '{expected}'\n"
        )
        return False
    return True


def compare_str(actual: str, expected: str, msg: str) -> bool:
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_tbool(actual: bool, expected: int, msg: str) -> bool:
    if expected == 0:
        # Unset
        return True

    if (expected < 0 and actual) or (expected > 0 and not actual):
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_uint8(actual: int, expected: int, msg: str) -> bool:
    actual = actual & 0xFF
    expected = expected & 0xFF
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_int8(actual: int, expected: int, msg: str) -> bool:
    actual = actual & 0xFF
    expected = expected & 0xFF
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_uint16(actual: int, expected: int, msg: str) -> bool:
    actual = actual & 0xFFFF
    expected = expected & 0xFFFF
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_int16(actual: int, expected: int, msg: str) -> bool:
    actual = actual & 0xFFFF
    expected = expected & 0xFFFF
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_uint32(actual: int, expected: int, msg: str) -> bool:
    actual = actual & 0xFFFFFFFF
    expected = expected & 0xFFFFFFFF
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_int32(actual: int, expected: int, msg: str) -> bool:
    actual = actual & 0xFFFFFFFF
    expected = expected & 0xFFFFFFFF
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_uint64(actual: int, expected: int, msg: str) -> bool:
    actual = actual & 0xFFFFFFFFFFFFFFFF
    expected = expected & 0xFFFFFFFFFFFFFFFF
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_int64(actual: int, expected: int, msg: str) -> bool:
    actual = actual & 0xFFFFFFFFFFFFFFFF
    expected = expected & 0xFFFFFFFFFFFFFFFF
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_fp(actual: float, expected: float, msg: str) -> bool:
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_enum(actual, expected, msg: str) -> bool:
    enum_val = getattr(capstone, expected)
    if not enum_val:
        log.error(f"capstone package doesn't have the an attribute '{expected}'")
        return False
    if actual != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True


def compare_bit_flags(actual: int, expected: list[str], msg: str) -> bool:
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
    if handle.reg_name(actual) != expected:
        log.error(f"{msg}: {actual} != {expected}")
        return False
    return True

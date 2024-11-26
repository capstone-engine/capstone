#!/usr/bin/env python3
# Copyright © 2024 Peace-Maker <peacemakerctf@gmail.com>
# SPDX-License-Identifier: BSD-3

import capstone.arm64
import capstone.sysz_const
from capstone import *
import capstone.aarch64
import capstone.arm
import capstone.systemz
from xprint import to_hex


AARCH64_CODE = b"\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9"
SYSZ_CODE = b"\xed\x00\x00\x00\x00\x1a\x5a\x0f\x1f\xff\xc2\x09\x80\x00\x00\x00\x07\xf7\xeb\x2a\xff\xff\x7f\x57\xe3\x01\xff\xff\x7f\x57\xeb\x00\xf0\x00\x00\x24\xb2\x4f\x00\x78"


all_tests = (
    (CS_ARCH_ARM64, CS_MODE_ARM, AARCH64_CODE, "ARM64"),
    (CS_ARCH_SYSZ, CS_MODE_BIG_ENDIAN, SYSZ_CODE, "SysZ"),
)


# Test arm64 and sysz compatibility layer
def test_compatibility():
    errors = []
    for arch, mode, code, comment in all_tests:
        print("*" * 16)
        print("Platform: %s" % comment)
        print("Code: %s" % to_hex(code))
        print("Disasm:")

        try:
            md = Cs(arch, mode)
            md.detail = True

            for insn in md.disasm(code, 0x1000):
                print("0x%x:\t%s\t%s\t(cc: %s)" % (insn.address, insn.mnemonic, insn.op_str, insn.cc))

            print("0x%x:" % (insn.address + insn.size))
            print()
        except CsError as e:
            print("ERROR: %s" % e)
            errors.append(str(e))

    # Test ARM64_ constants
    print("arm64.ARM64_CC_AL = %d" % capstone.arm64.ARM64_CC_AL)
    print("aarch64.AArch64CC_AL = %d" % capstone.aarch64.AArch64CC_AL)
    assert capstone.arm64.ARM64_CC_AL == capstone.aarch64.AArch64CC_AL
    print("arm64.ARM64_INS_FDIV = %d" % capstone.arm64.ARM64_INS_FDIV)
    print("aarch64.AARCH64_INS_FDIV = %d" % capstone.aarch64.AARCH64_INS_FDIV)
    assert capstone.arm64.ARM64_INS_FDIV == capstone.aarch64.AARCH64_INS_FDIV

    # Test SYSZ_ constants
    print("systemz.SYSZ_INS_LG = %d" % capstone.systemz.SYSZ_INS_LG)
    print("systemz.SYSTEMZ_INS_LG = %d" % capstone.systemz.SYSTEMZ_INS_LG)
    assert capstone.systemz.SYSZ_INS_LG == capstone.systemz.SYSTEMZ_INS_LG

    # Test ARM_CC_ constants
    print("arm.ARM_CC_MI = %d" % capstone.arm.ARM_CC_MI)
    print("arm.ARMCC_MI = %d" % capstone.arm.ARMCC_MI)
    assert capstone.arm.ARM_CC_MI == capstone.arm.ARMCC_MI
    print("arm.ARM_CC_INVALID = %d" % capstone.arm.ARM_CC_INVALID)
    print("arm.ARMCC_Invalid = %d" % capstone.arm.ARMCC_Invalid)
    assert capstone.arm.ARM_CC_INVALID == capstone.arm.ARMCC_Invalid

    return errors


if __name__ == "__main__":
    if test_compatibility():
        print("Some errors happened. Please check the output")
        exit(1)

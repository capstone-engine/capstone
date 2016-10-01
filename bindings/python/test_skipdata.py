#!/usr/bin/env python

# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

from __future__ import print_function
from capstone import *
import binascii
from xprint import to_hex


X86_CODE32 = b"\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x00\x91\x92"
RANDOM_CODE = b"\xed\x00\x00\x00\x00\x1a\x5a\x0f\x1f\xff\xc2\x09\x80\x00\x00\x00\x07\xf7\xeb\x2a\xff\xff\x7f\x57\xe3\x01\xff\xff\x7f\x57\xeb\x00\xf0\x00\x00\x24\xb2\x4f\x00\x78"

all_tests = (
        (CS_ARCH_X86, CS_MODE_32, X86_CODE32, "X86 32 (Intel syntax)", None),
        (CS_ARCH_ARM, CS_MODE_ARM, RANDOM_CODE, "Arm", None),
)


# Sample callback for SKIPDATA option
def testcb(buffer, size, offset, userdata):
    # always skip 2 bytes of data
    return 2


# ## Test class Cs
def test_class():
    for (arch, mode, code, comment, syntax) in all_tests:
        print('*' * 16)
        print("Platform: %s" %comment)
        print("Code: %s" % to_hex(code))
        print("Disasm:")

        try:
            md = Cs(arch, mode)

            if syntax is not None:
                md.syntax = syntax

            md.skipdata = True

            # Default "data" instruction's name is ".byte". To rename it to "db", just uncomment
            # the code below.
            # md.skipdata_setup = ("db", None, None)
            # NOTE: This example ignores SKIPDATA's callback (first None) & user_data (second None)

            # To customize the SKIPDATA callback, uncomment the line below.
            # md.skipdata_setup = (".db", testcb, None)

            for insn in md.disasm(code, 0x1000):
                #bytes = binascii.hexlify(insn.bytes)
                #print("0x%x:\t%s\t%s\t// hex-code: %s" %(insn.address, insn.mnemonic, insn.op_str, bytes))
                print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))

            print("0x%x:" % (insn.address + insn.size))
            print
        except CsError as e:
            print("ERROR: %s" % e)


if __name__ == '__main__':
    test_class()

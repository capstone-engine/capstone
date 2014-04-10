#!/usr/bin/env python

# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

from capstone import *
import binascii

X86_CODE32 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x00\x91\x92"
RANDOM_CODE = "\xed\x00\x00\x00\x00\x1a\x5a\x0f\x1f\xff\xc2\x09\x80\x00\x00\x00\x07\xf7\xeb\x2a\xff\xff\x7f\x57\xe3\x01\xff\xff\x7f\x57\xeb\x00\xf0\x00\x00\x24\xb2\x4f\x00\x78"

all_tests = (
        (CS_ARCH_X86, CS_MODE_32, X86_CODE32, "X86 32 (Intel syntax)", 0),
        (CS_ARCH_ARM, 0, RANDOM_CODE, "Arm", 0),
        )


def to_hex(s):
    return " ".join("0x" + "{0:x}".format(ord(c)).zfill(2) for c in s) # <-- Python 3 is OK


### Test cs_disasm_quick()
def test_cs_disasm_quick():
    for (arch, mode, code, comment, syntax) in all_tests:
        print('*' * 40)
        print("Platform: %s" %comment)
        print("Disasm:"),
        print to_hex(code)
        for insn in cs_disasm_quick(arch, mode, code, 0x1000):
            print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))
        print


### Test class Cs
def test_class():
    for (arch, mode, code, comment, syntax) in all_tests:
        print('*' * 16)
        print("Platform: %s" %comment)
        print("Code: %s" % to_hex(code))
        print("Disasm:")

        try:
            md = Cs(arch, mode)

            if syntax != 0:
                md.syntax = syntax

            md.skipdata = True
            # To rename "data" instruction's mnemonic to "db", uncomment the line below
            # This example ignores SKIPDATA's callback (first None) & user_data (second None)
            md.skipdata_opt = ("db", None, None)

            for insn in md.disasm(code, 0x1000):
                #bytes = binascii.hexlify(insn.bytes)
                #print("0x%x:\t%s\t%s\t// hex-code: %s" %(insn.address, insn.mnemonic, insn.op_str, bytes))
                print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))

            print("0x%x:" % (insn.address + insn.size))
            print
        except CsError as e:
            print("ERROR: %s" %e)


test_class()

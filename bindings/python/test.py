#!/usr/bin/env python

# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

from capstone import *
import binascii

X86_CODE16 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00"
X86_CODE32 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00"
X86_CODE64 = "\x55\x48\x8b\x05\xb8\x13\x00\x00"
ARM_CODE = "\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3"
ARM_CODE2 = "\x10\xf1\x10\xe7\x11\xf2\x31\xe7\xdc\xa1\x2e\xf3\xe8\x4e\x62\xf3"
THUMB_CODE = "\x70\x47\xeb\x46\x83\xb0\xc9\x68"
THUMB_CODE2 = "\x4f\xf0\x00\x01\xbd\xe8\x00\x88\xd1\xe8\x00\xf0"
MIPS_CODE = "\x0C\x10\x00\x97\x00\x00\x00\x00\x24\x02\x00\x0c\x8f\xa2\x00\x00\x34\x21\x34\x56"
MIPS_CODE2 = "\x56\x34\x21\x34\xc2\x17\x01\x00"
ARM64_CODE = "\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9"
PPC64_CODE = "\x80\x20\x00\x00\x80\x3f\x00\x00\x10\x43\x23\x0e\xd0\x44\x00\x80"

all_tests = (
        (CS_ARCH_X86, CS_MODE_16, X86_CODE16, "X86 16bit (Intel syntax)", 0),
        (CS_ARCH_X86, CS_MODE_32, X86_CODE32, "X86 32bit (ATT syntax)", CS_OPT_SYNTAX_ATT),
        (CS_ARCH_X86, CS_MODE_32, X86_CODE32, "X86 32 (Intel syntax)", 0),
        (CS_ARCH_X86, CS_MODE_64, X86_CODE64, "X86 64 (Intel syntax)", 0),
        (CS_ARCH_ARM, CS_MODE_ARM, ARM_CODE, "ARM", 0),
        (CS_ARCH_ARM, CS_MODE_THUMB, THUMB_CODE2, "THUMB-2", 0),
        (CS_ARCH_ARM, CS_MODE_ARM, ARM_CODE2, "ARM: Cortex-A15 + NEON", 0),
        (CS_ARCH_ARM, CS_MODE_THUMB, THUMB_CODE, "THUMB", 0),
        (CS_ARCH_MIPS, CS_MODE_32 + CS_MODE_BIG_ENDIAN, MIPS_CODE, "MIPS-32 (Big-endian)", 0),
        (CS_ARCH_MIPS, CS_MODE_64+ CS_MODE_LITTLE_ENDIAN, MIPS_CODE2, "MIPS-64-EL (Little-endian)", 0),
        (CS_ARCH_ARM64, CS_MODE_ARM, ARM64_CODE, "ARM-64", 0),
        (CS_ARCH_PPC, CS_MODE_64 + CS_MODE_BIG_ENDIAN, PPC64_CODE, "PPC-64", 0),
        )


def to_hex(s):
    return " ".join("0x" + "{0:x}".format(ord(c)).zfill(2) for c in s) # <-- Python 3 is OK


### Test cs_disasm_quick()
def test_cs_disasm_quick():
    for (arch, mode, code, comment) in all_tests:
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
            # md.detail = False

            if syntax != 0:
                md.syntax = syntax

            for insn in md.disasm(code, 0x1000):
                #bytes = binascii.hexlify(insn.bytes)
                #print("0x%x:\t%s\t%s\t// hex-code: %s" %(insn.address, insn.mnemonic, insn.op_str, bytes))
                print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))

            print("0x%x:" % (insn.address + insn.size))
            print
        except CsError as e:
            print("ERROR: %s" %e)


#test_cs_disasm_quick()
#print "*" * 40
test_class()

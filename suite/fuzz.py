#!/usr/bin/python

# Simple fuzzing tool by disassembling random code. By Nguyen Anh Quynh, 2014
# Syntax:
# ./suite/fuzz.py          --> Fuzz all archs
# ./suite/fuzz.py x86      --> Fuzz all X86 (all 16bit, 32bit, 64bit)
# ./suite/fuzz.py x86-16   --> Fuzz X86-32 arch only
# ./suite/fuzz.py x86-32   --> Fuzz X86-32 arch only
# ./suite/fuzz.py x86-64   --> Fuzz X86-64 arch only
# ./suite/fuzz.py arm      --> Fuzz all ARM (arm, thumb)
# ./suite/fuzz.py aarch64  --> Fuzz ARM-64
# ./suite/fuzz.py mips     --> Fuzz all Mips (32bit, 64bit)
# ./suite/fuzz.py ppc      --> Fuzz PPC

from capstone import *

from time import time
from random import randint
import sys


# file providing code to disassemble
FILE = '/usr/bin/python'

TIMES = 64
INTERVALS = (4, 5, 7, 9, 11, 13)

all_tests = (
        (CS_ARCH_X86, CS_MODE_16, "X86-16bit (Intel syntax)", 0),
        (CS_ARCH_X86, CS_MODE_16, "X86-16bit (ATT syntax)", CS_OPT_SYNTAX_ATT),
        (CS_ARCH_X86, CS_MODE_32, "X86-32 (Intel syntax)", 0),
        (CS_ARCH_X86, CS_MODE_32, "X86-32 (ATT syntax)", CS_OPT_SYNTAX_ATT),
        (CS_ARCH_X86, CS_MODE_64, "X86-64 (Intel syntax)", 0),
        (CS_ARCH_X86, CS_MODE_64, "X86-64 (ATT syntax)", CS_OPT_SYNTAX_ATT),
        (CS_ARCH_ARM, CS_MODE_ARM, "ARM", 0),
        (CS_ARCH_ARM, CS_MODE_THUMB, "THUMB (ARM)", 0),
        (CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN, "MIPS-32 (Big-endian)", 0),
        (CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN, "MIPS-64-EL (Little-endian)", 0),
        (CS_ARCH_ARM64, CS_MODE_ARM, "ARM-64 (AArch64)", 0),
        (CS_ARCH_PPC, CS_MODE_BIG_ENDIAN, "PPC", 0),
        (CS_ARCH_PPC, CS_MODE_BIG_ENDIAN, "PPC, print register with number only", CS_OPT_SYNTAX_NOREGNAME),
        (CS_ARCH_SPARC, CS_MODE_BIG_ENDIAN, "Sparc", 0),
        (CS_ARCH_SYSZ, 0, "SystemZ", 0),
        (CS_ARCH_XCORE, 0, "XCore", 0),
        (CS_ARCH_M68K, 0, "M68K", 0),
        (CS_ARCH_RISCV, CS_MODE_RISCV32, "riscv32", 0),
        (CS_ARCH_RISCV, CS_MODE_RISCV64, "riscv64", 0),
        )


# for debugging
def to_hex(s):
    return " ".join("0x" + "{0:x}".format(ord(c)).zfill(2) for c in s) # <-- Python 3 is OK


# read @size bytes from @f & return data.
# return None when there is not enough data
def get_code(f, size):
    code = f.read(size)
    if len(code) != size:  # reached end-of-file?
        # then reset file position to begin-of-file
        f.seek(0)
        return None

    return code


def cs(md, code):
    insns = md.disasm(code, 0)
    for i in insns:
        if i.address == 0x100000:
            print i


def cs_lite(md, code):
    insns = md.disasm_lite(code, 0)
    for (addr, size, mnem, ops) in insns:
        if addr == 0x100000:
            print i


cfile = open(FILE)

for (arch, mode, comment, syntax) in all_tests:
    try:
        request = sys.argv[1]
        if not request in comment.lower():
            continue
    except:
        pass

    try:
        md = Cs(arch, mode)
        md.detail = True

        if syntax != 0:
            md.syntax = syntax

        # test disasm()
        print("\nFuzzing disasm() @platform: %s" %comment)
        for ii in INTERVALS:
            print("Interval: %u" %ii)
            for j in xrange(1, TIMES):
                while (True):
                    code = get_code(cfile, j * ii)
                    if code is None:
                        # EOF? break
                        break
                    #print to_hex(code)
                    cs(md, code)

        # test disasm_lite()
        print("Fuzzing disasm_lite() @platform: %s" %comment)
        for ii in INTERVALS:
            print("Interval: %u" %ii)
            for j in xrange(1, TIMES):
                while (True):
                    code = get_code(cfile, j * ii)
                    if code is None:
                        # EOF? break
                        break
                    #print to_hex(code)
                    cs_lite(md, code)

    except CsError as e:
        print("ERROR: %s" %e)

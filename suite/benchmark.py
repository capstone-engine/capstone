#!/usr/bin/python

# Simple benchmark for Capstone by disassembling random code. By Nguyen Anh Quynh, 2014
# Syntax:
# ./suite/benchmark.py          --> Benchmark all archs
# ./suite/benchmark.py x86      --> Benchmark all X86 (all 16bit, 32bit, 64bit)
# ./suite/benchmark.py x86-32   --> Benchmark X86-32 arch only
# ./suite/benchmark.py arm      --> Benchmark all ARM (arm, thumb)
# ./suite/benchmark.py aarch64  --> Benchmark ARM-64
# ./suite/benchmark.py mips     --> Benchmark all Mips (32bit, 64bit)
# ./suite/benchmark.py ppc      --> Benchmark PPC

from capstone import *

from time import time
from random import randint
import sys


# file providing code to disassemble
FILE = '/usr/bin/python'


all_tests = (
        (CS_ARCH_X86, CS_MODE_16, "X86-16 (Intel syntax)", 0),
        (CS_ARCH_X86, CS_MODE_32, "X86-32 (ATT syntax)", CS_OPT_SYNTAX_ATT),
        (CS_ARCH_X86, CS_MODE_32, "X86-32 (Intel syntax)", 0),
        (CS_ARCH_X86, CS_MODE_64, "X86-64 (Intel syntax)", 0),
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
        )


# for debugging
def to_hex(s):
    return " ".join("0x" + "{0:x}".format(ord(c)).zfill(2) for c in s) # <-- Python 3 is OK

def get_code(f, size):
    code = f.read(size)
    if len(code) != size:  # reached end-of-file?
        # then reset file position to begin-of-file
        f.seek(0)
        code = f.read(size)

    return code


def cs(md, code):
    insns = md.disasm(code, 0)
    # uncomment below line to speed up this function 200 times!
    # return
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

    print("Platform: %s" %comment)

    try:
        md = Cs(arch, mode)
        #md.detail = True

        if syntax != 0:
            md.syntax = syntax

        # warm up few times
        cfile.seek(0)
        for i in xrange(3):
            code = get_code(cfile, 128)
            #print to_hex(code)
            #print
            cs(md, code)

        # start real benchmark
        c_t = 0
        for i in xrange(50000):
            code = get_code(cfile, 128)
            #print to_hex(code)
            #print

            t1 = time()
            cs(md, code)
            c_t += time() - t1

        print "Benchmark - full obj:", c_t, "seconds"
        print

        cfile.seek(0)
        c_t = 0
        for i in xrange(50000):
            code = get_code(cfile, 128)
            #print to_hex(code)
            #print

            t1 = time()
            cs_lite(md, code)
            c_t += time() - t1

        print "Benchmark - lite:", c_t, "seconds"
        print
    except CsError as e:
        print("ERROR: %s" %e)

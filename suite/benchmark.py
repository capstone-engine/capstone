#!/usr/bin/python

# Simple benchmark for Capstone by disassembling random code. By Nguyen Anh Quynh, 2014

from capstone import *

from time import time
from random import randint


# file providing code to disassemble
FILE = '/usr/bin/python'


def get_code(f, size):
    code = f.read(size)
    if len(code) != size:  # reached end-of-file?
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


md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = False

cfile = open(FILE)

# warm up few times
for i in xrange(3):
    code = get_code(cfile, 128)
    cs(md, code)

# start real benchmark
c_t = 0
for i in xrange(10000):
    code = get_code(cfile, 128)

    t1 = time()
    cs(md, code)
    c_t += time() - t1


print "Capstone:", c_t, "seconds"

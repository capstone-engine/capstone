#!/usr/bin/env python

# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

from __future__ import print_function
from capstone import *

cs = Cs(CS_ARCH_NEO, 0)
cs.detail = True

for i in cs.disasm("\x02\xaa\xbb", 0x100):
    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
    if i.pop > 0:
        print("\tPop:     %u" %i.pop)
    if i.push > 0:
        print("\tPush:    %u" %i.push)
    if i.fee > 0:
        print("\tGas fee: %u" %i.fee)
    if len(i.groups) > 0:
        print("\tThis instruction belongs to groups: ", end=''),
        for m in i.groups:
            print("%s " % i.group_name(m), end=''),
        print()

#!/usr/bin/env python

# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

from __future__ import print_function
from capstone import *
import sys

from xprint import to_hex

_python3 = sys.version_info.major == 3


EVM_CODE = b"\x60\x61\x50"

all_tests = (
        (CS_ARCH_EVM, 0, EVM_CODE, "EVM"),
)


def test_class():
    address = 0x80001000
    for (arch, mode, code, comment) in all_tests:
        print("Platform: %s" % comment)
        print("Code: %s " % to_hex(code))
        print("Disasm:")

        try:
            md = Cs(arch, mode)
            md.detail = True
            for i in md.disasm(code, address):
                print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
                if i.pop > 0:
                    print("\tPop:     %u" %i.pop)
                if i.push > 0:
                    print("\tPush:    %u" %i.push)
                if i.fee > 0:
                    print("\tGas fee: %u" %i.fee)
                if len(i.groups) > 0:
                    print("\tGroups: ", end=''),
                    for m in i.groups:
                        print("%s " % i.group_name(m), end=''),
                    print()

        except CsError as e:
            print("ERROR: %s" % e.__str__())


if __name__ == '__main__':
    test_class()

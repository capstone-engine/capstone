#!/usr/bin/env python

# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>
from __future__ import print_function
import sys
from capstone import *

all_tests = (
        # arch, mode, syntax, address, hexcode, expected output
        # issue 456 https://github.com/aquynh/capstone/issues/456

        (CS_ARCH_X86, CS_MODE_16, CS_OPT_SYNTAX_INTEL, 0xfc16, b"\xE8\x35\x64", "call 0x604e"),
        (CS_ARCH_X86, CS_MODE_32, CS_OPT_SYNTAX_INTEL, 0x9123fc1b, b"\x66\xE8\x35\x64", "call 0x6054"),
        (CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_INTEL, 0x9123fc1b, b"\x66\xE8\x35\x64", "call 0x6054"),

        (CS_ARCH_X86, CS_MODE_16, CS_OPT_SYNTAX_INTEL, 0xfc26, b"\xE9\x35\x64", "jmp 0x605e"),

        (CS_ARCH_X86, CS_MODE_16, CS_OPT_SYNTAX_INTEL, 0xfff6, b"\x66\xE9\x35\x64\x93\x53", "jmp 0x53946431"),
        (CS_ARCH_X86, CS_MODE_32, CS_OPT_SYNTAX_INTEL, 0x9123fff1, b"\xE9\x35\x64\x93\x53", "jmp 0xe4b7642b"),
        (CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_INTEL, 0x649123fff1, b"\xE9\x35\x64\x93\x53", "jmp 0x64e4b7642b"),

        (CS_ARCH_X86, CS_MODE_16, CS_OPT_SYNTAX_INTEL, 0xffe1, b"\x66\xe8\x35\x64\x93\x53", "call 0x5394641c"),
        (CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_INTEL, 0x649123ffe1, b"\x66\xe8\x35\x64", "call 0x641a"),
        (CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_INTEL, 0x649123ffe1, b"\x66\xe9\x35\x64", "jmp 0x641a"),
        (CS_ARCH_X86, CS_MODE_16, CS_OPT_SYNTAX_INTEL, 0xffe1, b"\x66\xe9\x35\x64\x93\x53", "jmp 0x5394641c"),

        # AT&T syntax
        (CS_ARCH_X86, CS_MODE_16, CS_OPT_SYNTAX_ATT, 0xfc16, b"\xE8\x35\x64", "callw 0x604e"),
        (CS_ARCH_X86, CS_MODE_32, CS_OPT_SYNTAX_ATT, 0x9123fc1b, b"\x66\xE8\x35\x64", "callw 0x6054"),
        (CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_ATT, 0x9123fc1b, b"\x66\xE8\x35\x64", "callw 0x6054"),

        (CS_ARCH_X86, CS_MODE_16, CS_OPT_SYNTAX_ATT, 0xfc26, b"\xE9\x35\x64", "jmp 0x605e"),

        (CS_ARCH_X86, CS_MODE_16, CS_OPT_SYNTAX_ATT, 0xfff6, b"\x66\xE9\x35\x64\x93\x53", "jmp 0x53946431"),
        (CS_ARCH_X86, CS_MODE_32, CS_OPT_SYNTAX_ATT, 0x9123fff1, b"\xE9\x35\x64\x93\x53", "jmp 0xe4b7642b"),
        (CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_ATT, 0x649123fff1, b"\xE9\x35\x64\x93\x53", "jmp 0x64e4b7642b"),

        (CS_ARCH_X86, CS_MODE_16, CS_OPT_SYNTAX_ATT, 0xffe1, b"\x66\xe8\x35\x64\x93\x53", "calll 0x5394641c"),
        (CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_ATT, 0x649123ffe1, b"\x66\xe8\x35\x64", "callw 0x641a"),
        (CS_ARCH_X86, CS_MODE_64, CS_OPT_SYNTAX_ATT, 0x649123ffe1, b"\x66\xe9\x35\x64", "jmp 0x641a"),
        (CS_ARCH_X86, CS_MODE_16, CS_OPT_SYNTAX_ATT, 0xffe1, b"\x66\xe9\x35\x64\x93\x53", "jmp 0x5394641c"),
)

_python3 = sys.version_info.major == 3


def to_hex(s):
    if _python3:
        return " ".join("0x{0:02x}".format(c) for c in s)  # <-- Python 3 is OK
    else:
        return " ".join("0x{0:02x}".format(ord(c)) for c in s)


def str_syntax(syntax):
    slist = {
        0: "",
        CS_OPT_SYNTAX_INTEL: "intel",
        CS_OPT_SYNTAX_ATT: "att",
    }

    return slist[syntax]


def str_arch_mode(a, m):
    amlist = {
        (CS_ARCH_X86, CS_MODE_16): "X86-16bit",
        (CS_ARCH_X86, CS_MODE_32): "X86-32bit",
        (CS_ARCH_X86, CS_MODE_64): "X86-64bit",
    }

    return amlist[(a, m)]


# ## Test cs_disasm_quick()
def test_regression():
    for (arch, mode, syntax, address, code, expected_output) in all_tests:
        print("%s %s: %s = " %(str_arch_mode(arch, mode), str_syntax(syntax), to_hex(code)), end=""),
        md = Cs(arch, mode)
        if syntax != 0:
            md.syntax = syntax
        insn = list(md.disasm(code, address))[0]
        output = "%s %s" % (insn.mnemonic, insn.op_str)
        print(output)
        if output != expected_output:
            print("\t --> ERROR: expected output = %s" %(expected_output))

        print()


if __name__ == '__main__':
    test_regression()

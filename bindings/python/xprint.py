#!/usr/bin/env python
# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

from __future__ import print_function
import sys
_python3 = sys.version_info.major == 3


def to_hex(s):
    if _python3:
        return " ".join("0x{0:02x}".format(c) for c in s)  # <-- Python 3 is OK
    else:
        return " ".join("0x{0:02x}".format(ord(c)) for c in s)

def to_hex2(s):
    if _python3:
        r = "".join("{0:02x}".format(c) for c in s)  # <-- Python 3 is OK
    else:
        r = "".join("{0:02x}".format(ord(c)) for c in s)
    while r[0] == '0': r = r[1:]
    return r

def to_x(s):
    from struct import pack
    if not s: return '0'
    x = pack(">q", s)
    while x[0] in ('\0', 0): x = x[1:]
    return to_hex2(x)

def to_x_32(s):
    from struct import pack
    if not s: return '0'
    x = pack(">i", s)
    while x[0] in ('\0', 0): x = x[1:]
    return to_hex2(x)

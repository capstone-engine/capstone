from capstone import *
import pytest
import struct

TEST_MACHINE_CODES = [b"\x42\x9f\x00\x05",
                      b"\x43\x9f\x00\x05",
                      b"\x43\xbf\x00\x05",
                      b"\x43\xff\x00\x05"]

@pytest.mark.parametrize("test_machine_code", TEST_MACHINE_CODES, ids=lambda t: t)
def test_unconditional_branch(test_machine_code):
    md = Cs(CS_ARCH_PPC, CS_MODE_32 | CS_MODE_BIG_ENDIAN)
    unpacked_mc = struct.unpack('>I', test_machine_code)[0]
    expected_bo = (unpacked_mc & 0x03e00000) >> 21

    inst = md.disasm(test_machine_code, 0).next()
    operands = [to_int_dec_or_hex(o.strip()) for o in inst.op_str.split(',')]

    assert inst.address == 0
    assert inst.mnemonic == "bcl"
    assert len(operands) == 3
    assert operands[0] == expected_bo
    assert operands[1] == 31
    assert operands[2] == 0x4


def to_int_dec_or_hex(s):
    try:
        return int(s, 10)
    except ValueError:
        return int(s, 16)
import sys
import struct
import pytest
from capstone import *
try:
    from keystone import *
except:
    print("Warning: test '{}' requires keystone be installed".format(sys.argv[0]))


TEST_CASES = [
    b"\x38\x43\x80\x00",
    b"\x2f\x84\xff\xff",
    b"\x2f\x80\xff\xff",
    b"\x2f\x83\xff\xff",
    b"\x2f\x80\x80\x00",
    b"\x2f\x85\xff\xfe",
    b"\x2f\x84\xff\xff",
    b"\x2f\x80\xff\xff",
    b"\x2f\x83\xff\xff",
    b"\x2f\x80\x80\x00",
    b"\x2f\x85\xff\xfe",
    b"\x38\x63\xed\x7e",
    b"\x38\x84\xbd\xa8",
    b"\x38\x84\xbd\xac",
    b"\x38\x09\xff\xd0",
    b"\x38\x84\xff\xf3",
    b"\x2f\x84\xff\xff",
    b"\x2f\x80\xff\xff",
    b"\x2f\x83\xff\xff",
    b"\x2f\x80\x80\x00",
    b"\x2f\x85\xff\xfe",
    b"\x38\x63\xed\x7e",
    b"\x38\x84\xbd\xa8",
    b"\x38\x84\xbd\xac",
    b"\x38\x09\xff\xd0",
    b"\x38\x84\xff\xf3",
    b"\x38\x63\xee\x5f",
    b"\x38\x63\xed\xa7",
    b"\x38\x63\x81\x2d",
    b"\x39\x29\xff\x90",
    b"\x38\xc6\x88\x30",
    b"\x2f\x84\xff\xff",
    b"\x2f\x80\xff\xff",
    b"\x2f\x83\xff\xff",
    b"\x2f\x80\x80\x00",
    b"\x2f\x85\xff\xfe",
    b"\x38\x63\xed\x7e",
    b"\x38\x84\xbd\xa8",
    b"\x38\x84\xbd\xac",
    b"\x38\x09\xff\xd0",
    b"\x38\x84\xff\xf3",
    b"\x38\x63\xee\x5f",
    b"\x38\x63\xed\xa7",
    b"\x38\x63\x81\x2d",
    b"\x39\x29\xff\x90",
    b"\x38\xc6\x88\x30",
    b"\x39\x20\xff\xfe",
    b"\x38\x60\xff\xf8",
    b"\x38\x80\xff\xff",
    b"\x38\x00\xff\xfe",
    b"\x38\xa0\xff\xfe",
    b"\x38\x60\xff\xff"
]

@pytest.mark.parametrize("test_case", TEST_CASES, ids=lambda t: t)
def test_disasm_asm(test_case):
    # disassemble with capstone

    assembler = Ks(KS_ARCH_PPC, KS_MODE_BIG_ENDIAN | KS_MODE_32)
    disassembler = Cs(CS_ARCH_PPC, CS_MODE_BIG_ENDIAN | CS_MODE_32)
    disassembler.syntax = CS_OPT_SYNTAX_NOREGNAME

    disasm_instructions = []
    for instr in disassembler.disasm(test_case, 0):
        disasm_instructions.append("{} {}".format(instr.mnemonic, instr.op_str))

    # assemble with keystone
    asm_mc, _ = assembler.asm('; '.join(disasm_instructions), 0)
    packed_mc = struct.pack("BBBB", *asm_mc)

    # assert that the result is the same
    assert packed_mc == test_case
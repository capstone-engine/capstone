import sys
import struct
from capstone import *
try:
    from keystone import *
except:
    print("Warning: test '{}' requires keystone be installed".format(sys.argv[0]))

assembler = None
disassembler = None


TEST_CASES = [
    b"\x38\x43\x80\x00"
]

def run_disasm_asm_testcase(testcase):
    # disassemble with capstone
    disasm_instructions = []
    for instr in disassembler.disasm(testcase, 0):
        disasm_instructions.append("{} {}".format(instr.mnemonic, instr.op_str))

    # assemble with keystone
    asm_mc, _ = assembler.asm('; '.join(disasm_instructions), 0)
    packed_mc = struct.pack("BBBB", *asm_mc)

    # assert that the result is the same
    assert packed_mc == testcase


if __name__ == "__main__":
    try:
        _ = KS_ARCH_PPC
    except:
        print("Warning: test '{}' requires keystone be installed".format(sys.argv[0]))
        exit(1)

    assembler = Ks(KS_ARCH_PPC, KS_MODE_BIG_ENDIAN | KS_MODE_32)
    disassembler = Cs(CS_ARCH_PPC, CS_MODE_BIG_ENDIAN | CS_MODE_32)
    disassembler.syntax = CS_OPT_SYNTAX_NOREGNAME

    failures = False

    for testcase in TEST_CASES:
        # try:
        #     run_disasm_asm_testcase(testcase)
        # except AssertionError as error:
        #     print "Test case <{}> failed: {}".format(testcase, error.message)
        #     failures = True
        run_disasm_asm_testcase(testcase)

    if not failures:
        print "All tests succeeded"
    else:
        print "Tests failed"
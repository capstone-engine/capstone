#!/usr/bin/env python

# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

from capstone import *
from capstone.x86 import *

X86_CODE16 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\xa1\x13\x48\x6d\x3a"
X86_CODE32 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\xa1\x13\x48\x6d\x3a"
X86_CODE32 += "\x8d\x05\x34\x12\x00\x00"
X86_CODE64 = "\x55\x48\x8b\x05\xb8\x13\x00\x00"

all_tests = (
        (CS_ARCH_X86, CS_MODE_16, X86_CODE16, "X86 16bit (Intel syntax)"),
        (CS_ARCH_X86, CS_MODE_32 + CS_MODE_SYNTAX_ATT, X86_CODE32, "X86 32bit (ATT syntax)"),
        (CS_ARCH_X86, CS_MODE_32, X86_CODE32, "X86 32 (Intel syntax)"),
        (CS_ARCH_X86, CS_MODE_64, X86_CODE64, "X86 64 (Intel syntax)"),
        )


### Test class cs
def test_class():
    def print_string_hex(comment, str):
        print(comment),
        for c in str:
            print("0x%02x" %c),
        print

    def print_insn_detail(mode, insn):
        # print address, mnemonic and operands
        print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))

        # print instruction prefix
        print_string_hex("\tPrefix:", insn.prefix)

        # print segment override (if applicable)
        if insn.segment != X86_REG_INVALID:
            print("\tSegment override: %s" %insn.reg_name(insn.segment))

        # print instruction's opcode
        print_string_hex("\tOpcode:", insn.opcode)

        # print operand's size, address size, displacement size & immediate size
        print("\top_size: %u, addr_size: %u, disp_size: %u, imm_size: %u" \
            %(insn.op_size, insn.addr_size, insn.disp_size, insn.imm_size))

        # print modRM byte
        print("\tmodrm: 0x%x" %(insn.modrm))

        # print displacement value
        print("\tdisp: 0x%x" %(insn.disp))

        # SIB is not available in 16-bit mode
        if (mode & CS_MODE_16 == 0):
            # print SIB byte
            print("\tsib: 0x%x" %(insn.sib))

        count = insn.op_count(X86_OP_IMM)
        if count > 0:
            print("\timm_count: %u" %count)
            for i in xrange(count):
                index = insn.op_index(X86_OP_IMM, i + 1)
                print("\t\timms[%u] = 0x%x" %(i+1, (insn.operands[index].value.imm)))

        if len(insn.operands) > 0:
            print("\top_count: %u" %len(insn.operands))
            c = 0
            for i in insn.operands:
                c += 1
                if i.type == X86_OP_REG:
			        print("\t\toperands[%u].type: REG = %s" %(c, insn.reg_name(i.value.reg)))
                if i.type == X86_OP_IMM:
			        print("\t\toperands[%u].type: IMM = 0x%x" %(c, i.value.imm))
                if i.type == X86_OP_FP:
			        print("\t\toperands[%u].type: FP = %f" %(c, i.value.fp))
                if i.type == X86_OP_MEM:
                    print("\t\toperands[%u].type: MEM" %c)
                    if i.value.mem.base != 0:
                        print("\t\t\toperands[%u].mem.base: REG = %s" %(c, insn.reg_name(i.value.mem.base)))
                    if i.value.mem.index != 0:
                        print("\t\t\toperands[%u].mem.index: REG = %s" %(c, insn.reg_name(i.value.mem.index)))
                    if i.value.mem.scale != 1:
                        print("\t\t\toperands[%u].mem.scale: %u" %(c, i.value.mem.scale))
                    if i.value.mem.disp != 0:
                        print("\t\t\toperands[%u].mem.disp: 0x%x" %(c, i.value.mem.disp))


    for (arch, mode, code, comment) in all_tests:
        print("*" * 30)
        print("Platform: %s" %comment)
        print("Disasm:")
    
        try:
            md = cs(arch, mode)
            for insn in md.disasm(code, 0x1000):
                print_insn_detail(mode, insn)
                print
        except:
            print("ERROR: Arch or mode unsupported!")


test_class()

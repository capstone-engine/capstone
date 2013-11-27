#!/usr/bin/env python

# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

from capstone import *
from capstone.arm64 import *

ARM64_CODE = "\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9\x20\x04\x81\xda\x20\x08\x02\x8b"

all_tests = (
        (CS_ARCH_ARM64, CS_MODE_ARM, ARM64_CODE, "ARM-64"),
        )


### Test class cs
def test_class():
    def print_insn_detail(insn):
        # print address, mnemonic and operands
        print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))

        if not insn.cc in [ARM64_CC_AL, ARM64_CC_INVALID]:
            print("\tCode condition: %u" %insn.cc)

        if insn.update_flags:
            print("\tUpdate-flags: True")

        if insn.writeback:
            print("\tWrite-back: True")

        if len(insn.operands) > 0:
            print("\top_count: %u" %len(insn.operands))
            c = 0
            for i in insn.operands:
                c += 1
                if i.type == ARM64_OP_REG:
			        print("\t\toperands[%u].type: REG = %s" %(c, insn.reg_name(i.value.reg)))
                if i.type == ARM64_OP_IMM:
			        print("\t\toperands[%u].type: IMM = %x" %(c, i.value.imm))
                if i.type == ARM64_OP_CIMM:
			        print("\t\toperands[%u].type: C-IMM = %u" %(c, i.value.imm))
                if i.type == ARM64_OP_FP:
			        print("\t\toperands[%u].type: FP = %f" %(c, i.value.fp))
                if i.type == ARM64_OP_MEM:
                    print("\t\toperands[%u].type: MEM" %c)
                    if i.value.mem.base != 0:
                        print("\t\t\toperands[%u].mem.base: REG = %s" \
                            %(c, insn.reg_name(i.value.mem.base)))
                    if i.value.mem.index != 0:
                        print("\t\t\toperands[%u].mem.index: REG = %s" \
                            %(c, insn.reg_name(i.value.mem.index)))
                    if i.value.mem.disp != 0:
                        print("\t\t\toperands[%u].mem.disp: %x" \
                            %(c, i.value.mem.disp))

                if i.shift.type != ARM64_SFT_INVALID and i.shift.value:
		            print("\t\t\tShift: type = %u, value = %u" \
                        %(i.shift.type, i.shift.value))

                if i.ext != ARM64_EXT_INVALID:
		            print("\t\t\tExt: %u" %i.ext)


    for (arch, mode, code, comment) in all_tests:
        print("*" * 30)
        print("Platform: %s" %comment)
        print("Disasm:")
    
        try:
            md = cs(arch, mode)
            for insn in md.disasm(code, 0x1000):
                print_insn_detail(insn)
                print
        except:
            print("ERROR: Arch or mode unsupported!")


test_class()

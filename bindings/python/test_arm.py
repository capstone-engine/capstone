#!/usr/bin/env python

# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

from capstone import *
from capstone.arm import *

ARM_CODE = "\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3"
ARM_CODE2 = "\xd1\xe8\x00\xf0\xf0\x24\x04\x07\x1f\x3c\xf2\xc0\x00\x00\x4f\xf0\x00\x01\x46\x6c"
THUMB_CODE2  = "\x4f\xf0\x00\x01\xbd\xe8\x00\x88\xd1\xe8\x00\xf0"
THUMB_CODE  = "\x70\x47\xeb\x46\x83\xb0\xc9\x68\x1f\xb1"

all_tests = (
        (CS_ARCH_ARM, CS_MODE_ARM, ARM_CODE, "ARM"),
        (CS_ARCH_ARM, CS_MODE_THUMB, THUMB_CODE, "Thumb"),
        (CS_ARCH_ARM, CS_MODE_THUMB, ARM_CODE2, "Thumb-mixed"),
        (CS_ARCH_ARM, CS_MODE_THUMB, THUMB_CODE2, "Thumb-2"),
        )


### Test class cs
def test_class():
    def print_insn_detail(insn):
        # print address, mnemonic and operands
        print("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))

        if not insn.cc in [ARM_CC_AL, ARM_CC_INVALID]:
            print("\tCode condition: %u" %insn.cc)

        if insn.update_flags:
            print("\tUpdate-flags: True")

        if insn.writeback:
            print("\tWriteback: True")

        if len(insn.operands) > 0:
            print("\top_count: %u" %len(insn.operands))
            c = 0
            for i in insn.operands:
                c += 1
                if i.type == ARM_OP_REG:
			        print("\t\toperands[%u].type: REG = %s" %(c, insn.reg_name(i.value.reg)))
                if i.type == ARM_OP_IMM:
			        print("\t\toperands[%u].type: IMM = %x" %(c, i.value.imm))
                if i.type == ARM_OP_PIMM:
			        print("\t\toperands[%u].type: P-IMM = %u" %(c, i.value.imm))
                if i.type == ARM_OP_CIMM:
			        print("\t\toperands[%u].type: C-IMM = %u" %(c, i.value.imm))
                if i.type == ARM_OP_FP:
			        print("\t\toperands[%u].type: FP = %f" %(c, i.value.fp))
                if i.type == ARM_OP_MEM:
                    print("\t\toperands[%u].type: MEM" %c)
                    if i.value.mem.base != 0:
                        print("\t\t\toperands[%u].mem.base: REG = %s" \
                            %(c, insn.reg_name(i.value.mem.base)))
                    if i.value.mem.index != 0:
                        print("\t\t\toperands[%u].mem.index: REG = %s" \
                            %(c, insn.reg_name(i.value.mem.index)))
                    if i.value.mem.scale != 1:
                        print("\t\t\toperands[%u].mem.scale: %u" \
                            %(c, i.value.mem.scale))
                    if i.value.mem.disp != 0:
                        print("\t\t\toperands[%u].mem.disp: %x" \
                            %(c, i.value.mem.disp))

                if i.shift.type != ARM_SFT_INVALID and i.shift.value:
		            print("\t\t\tShift: type = %u, value = %u\n" \
                        %(i.shift.type, i.shift.value))


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

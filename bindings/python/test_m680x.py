#!/usr/bin/env python

# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

from __future__ import print_function
import sys
from capstone import *
from capstone.m680x import *
_python3 = sys.version_info.major == 3


address_modes = (
	"M680X_AM_NONE",
	"M680X_AM_INHERENT",
	"M680X_AM_REGISTER",
	"M680X_AM_IMMEDIATE",
	"M680X_AM_INDEXED",
	"M680X_AM_EXTENDED",
	"M680X_AM_DIRECT",
	"M680X_AM_RELATIVE",
	"M680X_AM_IMM_DIRECT",
	"M680X_AM_IMM_INDEXED",
	)

insn_ids = (
	"M680X_INS_INVLD", "M680X_INS_ABA", "M680X_INS_ABX", "M680X_INS_ADCA",
	"M680X_INS_ADCB", "M680X_INS_ADCD", "M680X_INS_ADDA", "M680X_INS_ADDB",
	"M680X_INS_ADDD", "M680X_INS_ADDE", "M680X_INS_ADDF", "M680X_INS_ADDR",
	"M680X_INS_ADDW", "M680X_INS_AIM", "M680X_INS_ANDA", "M680X_INS_ANDB",
	"M680X_INS_ANDCC", "M680X_INS_ANDD", "M680X_INS_ANDR", "M680X_INS_ASL",
	"M680X_INS_ASLA", "M680X_INS_ASLB", "M680X_INS_ASLD", "M680X_INS_ASR",
	"M680X_INS_ASRA", "M680X_INS_ASRB", "M680X_INS_BAND", "M680X_INS_BCC",
	"M680X_INS_BCS", "M680X_INS_BEOR", "M680X_INS_BEQ", "M680X_INS_BGE",
	"M680X_INS_BGT", "M680X_INS_BHI", "M680X_INS_BIAND", "M680X_INS_BIEOR",
	"M680X_INS_BIOR", "M680X_INS_BITA", "M680X_INS_BITB", "M680X_INS_BITD",
	"M680X_INS_BITMD", "M680X_INS_BLE", "M680X_INS_BLS", "M680X_INS_BLT",
	"M680X_INS_BMI", "M680X_INS_BNE", "M680X_INS_BOR", "M680X_INS_BPL",
	"M680X_INS_BRA", "M680X_INS_BRN", "M680X_INS_BSR", "M680X_INS_BVC",
	"M680X_INS_BVS", "M680X_INS_CBA", "M680X_INS_CLC", "M680X_INS_CLI",
	"M680X_INS_CLR", "M680X_INS_CLRA", "M680X_INS_CLRB", "M680X_INS_CLRD",
	"M680X_INS_CLRE", "M680X_INS_CLRF", "M680X_INS_CLRW", "M680X_INS_CLV",
	"M680X_INS_CMPA", "M680X_INS_CMPB", "M680X_INS_CMPD", "M680X_INS_CMPE",
	"M680X_INS_CMPF", "M680X_INS_CMPR", "M680X_INS_CMPS", "M680X_INS_CMPU",
	"M680X_INS_CMPW", "M680X_INS_CMPX", "M680X_INS_CMPY", "M680X_INS_COM",
	"M680X_INS_COMA", "M680X_INS_COMB", "M680X_INS_COMD", "M680X_INS_COME",
	"M680X_INS_COMF", "M680X_INS_COMW", "M680X_INS_CPX", "M680X_INS_CWAI",
	"M680X_INS_DAA", "M680X_INS_DEC", "M680X_INS_DECA", "M680X_INS_DECB",
	"M680X_INS_DECD", "M680X_INS_DECE", "M680X_INS_DECF", "M680X_INS_DECW",
	"M680X_INS_DES", "M680X_INS_DEX", "M680X_INS_DIVD", "M680X_INS_DIVQ",
	"M680X_INS_EIM", "M680X_INS_EORA", "M680X_INS_EORB", "M680X_INS_EORD",
	"M680X_INS_EORR", "M680X_INS_EXG", "M680X_INS_ILLGL", "M680X_INS_INC",
	"M680X_INS_INCA", "M680X_INS_INCB", "M680X_INS_INCD", "M680X_INS_INCE",
	"M680X_INS_INCF", "M680X_INS_INCW", "M680X_INS_INS", "M680X_INS_INX",
	"M680X_INS_JMP", "M680X_INS_JSR", "M680X_INS_LBCC", "M680X_INS_LBCS",
	"M680X_INS_LBEQ", "M680X_INS_LBGE", "M680X_INS_LBGT", "M680X_INS_LBHI",
	"M680X_INS_LBLE", "M680X_INS_LBLS", "M680X_INS_LBLT", "M680X_INS_LBMI",
	"M680X_INS_LBNE", "M680X_INS_LBPL", "M680X_INS_LBRA", "M680X_INS_LBRN",
	"M680X_INS_LBSR", "M680X_INS_LBVC", "M680X_INS_LBVS", "M680X_INS_LDA",
	"M680X_INS_LDAA", "M680X_INS_LDAB", "M680X_INS_LDB", "M680X_INS_LDBT",
	"M680X_INS_LDD", "M680X_INS_LDE", "M680X_INS_LDF", "M680X_INS_LDMD",
	"M680X_INS_LDQ", "M680X_INS_LDS", "M680X_INS_LDU", "M680X_INS_LDW",
	"M680X_INS_LDX", "M680X_INS_LDY", "M680X_INS_LEAS", "M680X_INS_LEAU",
	"M680X_INS_LEAX", "M680X_INS_LEAY", "M680X_INS_LSL", "M680X_INS_LSLA",
	"M680X_INS_LSLB", "M680X_INS_LSR", "M680X_INS_LSRA", "M680X_INS_LSRB",
	"M680X_INS_LSRD", "M680X_INS_LSRW", "M680X_INS_MUL", "M680X_INS_MULD",
	"M680X_INS_NEG", "M680X_INS_NEGA", "M680X_INS_NEGB", "M680X_INS_NEGD",
	"M680X_INS_NOP", "M680X_INS_OIM", "M680X_INS_ORA", "M680X_INS_ORAA",
	"M680X_INS_ORAB", "M680X_INS_ORB", "M680X_INS_ORCC", "M680X_INS_ORD",
	"M680X_INS_ORR", "M680X_INS_PSHA", "M680X_INS_PSHB", "M680X_INS_PSHS",
	"M680X_INS_PSHSW", "M680X_INS_PSHU", "M680X_INS_PSHUW", "M680X_INS_PSHX",
	"M680X_INS_PULA", "M680X_INS_PULB", "M680X_INS_PULS", "M680X_INS_PULSW",
	"M680X_INS_PULU", "M680X_INS_PULUW", "M680X_INS_PULX", "M680X_INS_ROL",
	"M680X_INS_ROLA", "M680X_INS_ROLB", "M680X_INS_ROLD", "M680X_INS_ROLW",
	"M680X_INS_ROR", "M680X_INS_RORA", "M680X_INS_RORB", "M680X_INS_RORD",
	"M680X_INS_RORW", "M680X_INS_RTI", "M680X_INS_RTS", "M680X_INS_SBA",
	"M680X_INS_SBCA", "M680X_INS_SBCB", "M680X_INS_SBCD", "M680X_INS_SBCR",
	"M680X_INS_SEC", "M680X_INS_SEI", "M680X_INS_SEV", "M680X_INS_SEX",
	"M680X_INS_SEXW", "M680X_INS_STA", "M680X_INS_STAA", "M680X_INS_STAB",
	"M680X_INS_STB", "M680X_INS_STBT", "M680X_INS_STD", "M680X_INS_STE",
	"M680X_INS_STF", "M680X_INS_STQ", "M680X_INS_STS", "M680X_INS_STU",
	"M680X_INS_STW", "M680X_INS_STX", "M680X_INS_STY", "M680X_INS_SUBA",
	"M680X_INS_SUBB", "M680X_INS_SUBD", "M680X_INS_SUBE", "M680X_INS_SUBF",
	"M680X_INS_SUBR", "M680X_INS_SUBW", "M680X_INS_SWI", "M680X_INS_SWI2",
	"M680X_INS_SWI3", "M680X_INS_SYNC", "M680X_INS_TAB", "M680X_INS_TAP",
	"M680X_INS_TBA", "M680X_INS_TPA", "M680X_INS_TFM", "M680X_INS_TFR",
	"M680X_INS_TIM", "M680X_INS_TST", "M680X_INS_TSTA", "M680X_INS_TSTB",
	"M680X_INS_TSTD", "M680X_INS_TSTE", "M680X_INS_TSTF", "M680X_INS_TSTW",
	"M680X_INS_TSX", "M680X_INS_TXS", "M680X_INS_WAI", "M680X_INS_XGDX",
	)

M6800_CODE = b"\x01\x09\x36\x64\x7f\x74\x10\x00\x90\x10\xA4\x10\xb6\x10\x00\x39"

M6801_CODE = b"\x04\x05\x3c\x3d\x38\x93\x10\xec\x10\xed\x10\x39"

HD6301_CODE = b"\x6b\x10\x00\x71\x10\x00\x72\x10\x10\x39"

M6809_CODE = b"\x06\x10\x19\x1a\x55\x1e\x01\x23\xe9\x31\x06\x34\x55\xa6\x81\xa7\x89\x7f\xff\xa6\x9d\x10\x00\xa7\x91\xa6\x9f\x10\x00\x11\xac\x99\x10\x00\x39\xA6\x07\xA6\x27\xA6\x47\xA6\x67\xA6\x0F\xA6\x10\xA6\x80\xA6\x81\xA6\x82\xA6\x83\xA6\x84\xA6\x85\xA6\x86\xA6\x88\x7F\xA6\x88\x80\xA6\x89\x7F\xFF\xA6\x89\x80\x00\xA6\x8B\xA6\x8C\x10\xA6\x8D\x10\x00\xA6\x91\xA6\x93\xA6\x94\xA6\x95\xA6\x96\xA6\x98\x7F\xA6\x98\x80\xA6\x99\x7F\xFF\xA6\x99\x80\x00\xA6\x9B\xA6\x9C\x10\xA6\x9D\x10\x00\xA6\x9F\x10\x00"

all_tests = (
        (CS_ARCH_M680X, CS_MODE_M680X_6800, M6800_CODE, "M680X_M6800", None),
        (CS_ARCH_M680X, CS_MODE_M680X_6801, M6801_CODE, "M680X_M6801", None),
        (CS_ARCH_M680X, CS_MODE_M680X_6301, HD6301_CODE, "M680X_HD6301", None),
        (CS_ARCH_M680X, CS_MODE_M680X_6809, M6809_CODE, "M680X_M6809", None),
        )

# print hex dump from string all upper case
def to_hex_uc(string):
    if _python3:
        return " ".join("0x%02X" % c for c in string)
    else:
        return " ".join("0x%02X" % ord(c) for c in string)

# print short hex dump from byte array all upper case
def to_hex_short_uc(byte_array):
    return "".join("%02X" % b for b in byte_array)

def print_insn_detail(insn):
    # print address, mnemonic and operands
    #print("0x%x:\t%s\t%s\t%s" % (insn.address, binascii.hexlify(bytearray(insn.bytes)), \
    print("0x%04X: %s\t%s\t%s" % (insn.address, to_hex_short_uc(insn.bytes), \
	insn.mnemonic, insn.op_str))

    # "data" instruction generated by SKIPDATA option has no detail
    if insn.id == 0:
        return

    print("\tinsn id: %s" % insn_ids[insn.id])
    print("\taddress_mode: %s" % address_modes[insn.address_mode])

    if len(insn.operands) > 0:
        print("\top_count: %u" % len(insn.operands))
        c = 0
        for i in insn.operands:
            if i.type == M680X_OP_REGISTER:
                print("\t\toperands[%u].type: REGISTER = %s" % (c, insn.reg_name(i.reg)))
            if i.type == M680X_OP_IMMEDIATE:
                print("\t\toperands[%u].type: IMMEDIATE = #%s" % (c, i.imm))
            if i.type == M680X_OP_DIRECT:
                print("\t\toperands[%u].type: DIRECT = 0x%02X" % (c, i.imm))
            if i.type == M680X_OP_EXTENDED:
                if i.ext.indirect:
                    indirect = "INDIRECT"
                else:
                    indirect = ""
                print("\t\toperands[%u].type: EXTENDED %s = 0x%04X" % (c, indirect, i.ext.address))
            if i.type == M680X_OP_RELATIVE:
                print("\t\toperands[%u].type: RELATIVE = 0x%04X" % (c, i.rel.address))
            if i.type == M680X_OP_INDEXED_00:
                print("\t\toperands[%u].type: INDEXED_M6800" % c)
                if i.idx.base_reg != M680X_REG_INVALID:
                    print("\t\t\tbase register: %s" % insn.reg_name(i.idx.base_reg))
                if i.idx.offset_bits != 0:
                    print("\t\t\toffset: %u" % i.idx.offset)
                    print("\t\t\toffset bits: %u" % i.idx.offset_bits)
            if i.type == M680X_OP_INDEXED_09:
                if i.idx.indirect:
                    indirect = "INDIRECT"
                else:
                    indirect = ""
                print("\t\toperands[%u].type: INDEXED_M6809 %s" % (c, indirect))
                if i.idx.base_reg != M680X_REG_INVALID:
                    print("\t\t\tbase register: %s" % insn.reg_name(i.idx.base_reg))
                if i.idx.offset_reg != M680X_REG_INVALID:
                    print("\t\t\toffset register: %s" % insn.reg_name(i.idx.offset_reg))
                if (i.idx.offset_bits != 0) and (i.idx.offset_reg == M680X_REG_INVALID) and (i.idx.inc_dec == 0):
                    print("\t\t\toffset: %u" % i.idx.offset)
                    if i.idx.base_reg == M680X_REG_PC:
                        print("\t\t\toffset address: 0x%04X" % i.idx.offset_addr)
                    print("\t\t\toffset bits: %u" % i.idx.offset_bits)
                if i.idx.inc_dec > 0:
                    print("\t\t\tpost increment: %d" % i.idx.inc_dec)
                if i.idx.inc_dec < 0:
                    print("\t\t\tpre decrement: %d" % i.idx.inc_dec)

            c += 1

    (regs_read, regs_write) = insn.regs_access()

    if len(regs_read) > 0:
        print("\tRegisters read:", end="")
        for r in regs_read:
            print(" %s" %(insn.reg_name(r)), end="")
        print("")

    if len(regs_write) > 0:
        print("\tRegisters modified:", end="")
        for r in regs_write:
            print(" %s" %(insn.reg_name(r)), end="")
        print("")

    if len(insn.groups) > 0:
         print("\tgroups_count: %u" % len(insn.groups))

# ## Test class Cs
def test_class():

    for (arch, mode, code, comment, syntax) in all_tests:
        print("*" * 20)
        print("Platform: %s" % comment)
        print("Code: %s" % to_hex_uc(code))
        print("Disasm:")

        try:
            md = Cs(arch, mode)
            if syntax is not None:
                md.syntax = syntax
            md.detail = True
            for insn in md.disasm(code, 0x1000):
                print_insn_detail(insn)
                print ()
        except CsError as e:
            print("ERROR: %s" % e)


if __name__ == '__main__':
    test_class()

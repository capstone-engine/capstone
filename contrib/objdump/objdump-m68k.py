#!/usr/bin/env python

from __future__ import print_function
import sys
import bitstring
from capstone import *
from capstone.m68k import *

#
# Objdump with the same output as his binary cousin
#

TODO = """
TODO :

  o need more testing on M68K_AM_*_DISP
  o cleanup, etc ...

"""

objdump_cmd_example = 'm68k-atari-mint-objdump -b binary -D -mm68k --adjust-vma 0x30664 u/m68k.bin'
objdump_dumpheader_fmt = """
%s:     file format binary


Disassembly of section .data:

%08x <.data>:"""


M68000_CODE = b"\x04\x40\x00\x40"

all_tests = (
        (CS_ARCH_M68K, CS_MODE_BIG_ENDIAN | CS_MODE_M68K_060, M68000_CODE, "M68060-32 (Big-endian)"),
)


def dump_bytes(b, len):
    str = ''
    i = 0
    while i < len:
        str += format("%02x%02x " % (b[i], b[i+1]))
        i += 2
    return str[:-1]

def dump_op_reg(insn, op_reg):
    if op_reg == M68K_REG_A7:
        return "%sp"
    if op_reg == M68K_REG_A6:
        return "%fp"
    return '%' + insn.reg_name(op_reg)

def s8(value):
    return bitstring.Bits(uint=value, length=8).unpack('int')[0]

def s16(value):
    return bitstring.Bits(uint=value, length=16).unpack('int')[0]

def extsign8(value):
    if value & 0x80:
        return 0xffffffffffffff00 + value
    return value

def extsign1616(value):
    if value & 0x8000:
        return 0xffff0000 + value
    return value

def extsign1632(value):
    if value & 0x8000:
        return 0xffffffffffff0000 + value
    return value


def printRegbitsRange(buffer, data, prefix):
    str = ''
    first = 0
    run_length = 0

    i = 0
    while i < 8:
        if (data & (1 << i)):
            first = i
            run_length = 0

            while (i < 7 and (data & (1 << (i + 1)))):
                i += 1
                run_length += 1

            if len(buffer) or len(str):
                str += "/"

            str += format("%%%s%d" % (prefix, first))
            if run_length > 0:
                str += format("-%%%s%d" % (prefix, first + run_length))
        i += 1
    return str

def registerBits(op):
    str = ''
    data = op.register_bits

    str += printRegbitsRange(str, data & 0xff, "d")
    str += printRegbitsRange(str, (data >> 8) & 0xff, "a")
    str += printRegbitsRange(str, (data >> 16) & 0xff, "fp")
    return str

def dump_op_ea(insn, op):
    s_spacing = " "
    map_index_size_str = { 0: 'w', 1 : 'l' }
    str = ''
    
    if op.address_mode == M68K_AM_NONE:
        if op.type == M68K_OP_REG_BITS:
            return registerBits(op)
        if op.type == M68K_OP_REG_PAIR:
            return registerPair(op)
        if op.type == M68K_OP_REG:
            return dump_op_reg(insn, op.reg)

    if op.address_mode == M68K_AM_REG_DIRECT_DATA:
        return dump_op_reg(insn, op.reg)
    if op.address_mode == M68K_AM_REG_DIRECT_ADDR:
        return dump_op_reg(insn, op.reg) + "@"
    if op.address_mode == M68K_AM_REGI_ADDR:
        return dump_op_reg(insn, op.reg) + "@"
    if op.address_mode == M68K_AM_REGI_ADDR_POST_INC:
        return dump_op_reg(insn, op.reg) + "@+"
    if op.address_mode == M68K_AM_REGI_ADDR_PRE_DEC:
        return dump_op_reg(insn, op.reg) + "@-"
    if op.address_mode == M68K_AM_REGI_ADDR_DISP:
#        str = dump_op_reg(insn, op.mem.base_reg - M68K_REG_A0 + 1) #double check and fixme '+1' : 02af 899f 2622
        str = dump_op_reg(insn, op.mem.base_reg)
        if op.mem.disp:
            str += format("@(%d)" % s16(op.mem.disp))
        return str

    if op.address_mode == M68K_AM_PCI_DISP:
        return format("%%pc@(0x%x)" % ( extsign1616(op.mem.disp + 2))) 
    if op.address_mode == M68K_AM_ABSOLUTE_DATA_SHORT:
        return format("0x%x" % (extsign1616(op.imm & 0xffff)))  
    if op.address_mode == M68K_AM_ABSOLUTE_DATA_LONG:
        return format("0x%x" % (op.imm & 0xffffffff))
    if op.address_mode == M68K_AM_IMMEDIATE:
        if insn.op_size.type == M68K_SIZE_TYPE_FPU:
            map_fpu_size_str = { M68K_FPU_SIZE_SINGLE : op.simm, M68K_FPU_SIZE_DOUBLE : op.dimm }
            return format("#%f" % (insn.op_size.fpu_size[map_fpu_size_str]))
        return format("#$%x" % (op.imm))

    if op.address_mode in [ M68K_AM_PCI_INDEX_8_BIT_DISP, M68K_AM_AREGI_INDEX_8_BIT_DISP ]:
        disp = op.mem.disp
        if op.register_bits == 2:
            disp = extsign8(op.mem.disp)
        if op.register_bits == 4:
            disp = extsign1632(op.mem.disp)
            
        str = dump_op_reg(insn, op.mem.base_reg) + "@(" + "{0:016x}".format(disp) + "," + dump_op_reg(insn, op.mem.index_reg) + ":" + map_index_size_str[op.mem.index_size]
        if op.register_bits:
            str += format(":%u" % (op.register_bits))
        return str + ")"


    if op.address_mode in [ M68K_AM_PCI_INDEX_BASE_DISP, M68K_AM_AREGI_INDEX_BASE_DISP ]:
        str += format("%s" % ( dump_op_reg(insn, op.mem.base_reg) ))
        str += format("@(%016x)@(%016x" % (extsign1632(op.mem.in_disp), extsign1632(op.mem.out_disp)))
        if op.mem.index_reg:
            str += "," + dump_op_reg(insn, op.mem.index_reg) + ":" + map_index_size_str[op.mem.index_size]
        if op.register_bits:
            str += format(":%u" % (op.register_bits))
        str += ")"
        return str

        if op.mem.in_disp > 0:
            str += format("$%x" % ( op.mem.in_disp))

        str += format("(")

        if op.address_mode == M68K_AM_PCI_INDEX_BASE_DISP:
            str_size = ''
            if op.mem.index_size:
                str_size = "l"
            else:
                str_size = "w"
            str += format("pc,%s%s.%s" % ( dump_op_reg(insn, op.mem.index_reg)), s_spacing, str_size)
        else:
            if op.mem.base_reg != M68K_REG_INVALID:
                str += format("a%d,%s" % ( op.mem.base_reg - M68K_REG_A0, s_spacing))
            str_size = ''
            if op.mem.index_size:
                str_size = "l"
            else:
                str_size = "w"
            str += format("%s.%s" % ( dump_op_reg(insn, op.mem.index_reg), str_size))
	
        if op.mem.scale > 0:
            str += format("%s*%s%d)" % ( s_spacing, s_spacing, op.mem.scale))
        else:
            str += ")"
        return str
	
    # It's ok to just use PCMI here as is as we set base_reg to PC in the disassembler.
    # While this is not strictly correct it makes the code
    # easier and that is what actually happens when the code is executed anyway.

    if op.address_mode in [ M68K_AM_PC_MEMI_POST_INDEX, M68K_AM_PC_MEMI_PRE_INDEX, M68K_AM_MEMI_PRE_INDEX, M68K_AM_MEMI_POST_INDEX]:
        if op.mem.base_reg:
            str += format("%s" % ( dump_op_reg(insn, op.mem.base_reg) ))
        if op.mem.in_disp:
            value = op.mem.in_disp
            if op.mem.in_disp & 0x8000:
                value = 0xffffffffffff0000 + op.mem.in_disp
            str += format("@(%016x)@(%016x)" % (value, op.mem.out_disp))
        return str
        
        str += format("([")
        if op.mem.in_disp > 0:
            str += format("$%x" % ( op.mem.in_disp))

        if op.mem.base_reg != M68K_REG_INVALID:
            if op.mem.in_disp > 0:
                str += format(",%s%s" % ( s_spacing, dump_op_reg(insn, op.mem.base_reg))) 
            else:
                str += format("%s" % ( dump_op_reg(insn, op.mem.base_reg)))
                
        if op.address_mode in [ M68K_AM_MEMI_POST_INDEX, M68K_AM_PC_MEMI_POST_INDEX]:
            str += format("]")

        if op.mem.index_reg != M68K_REG_INVALID:
            str_size = ''
            if op.mem.index_size:
                str_size = "l"
            else:
                str_size = "w"
            str += format(",%s%s.%s" % ( s_spacing, dump_op_reg(insn, op.mem.index_reg), str_size))
        if op.mem.scale > 0:
            str += format("%s*%s%d" % ( s_spacing, s_spacing, op.mem.scale))
        if op.address_mode in [ M68K_AM_MEMI_PRE_INDEX, M68K_AM_PC_MEMI_PRE_INDEX]:
            str += format("]")
        if op.mem.out_disp > 0:
            str += format(",%s$%x" % ( s_spacing, op.mem.out_disp))
        str += format(")")
        return str

        
    if op.mem.bitfield:
        return format("%d:%d" % ( op.mem.offset, op.mem.width))

        ############# OK
    if op.address_mode == M68K_AM_AREGI_INDEX_BASE_DISP:
        if op.mem.index_size:
            str_size = "l"
        else:
            str_size = "w"
        bits = op.mem.disp
        return dump_op_reg(insn, op.mem.base_reg) + "@(" + "{0:016b}".format(bits) + "," + dump_op_reg(insn, op.mem.index_reg) + ":" + str_size + ")" 
    return ''



# M68K Addressing Modes

map_address_mode_str = {
    0 : "M68K_AM_NONE",
    1 : "M68K_AM_REG_DIRECT_DATA",
    2 : "M68K_AM_REG_DIRECT_ADDR",
    3 : "M68K_AM_REGI_ADDR",
    4 : "M68K_AM_REGI_ADDR_POST_INC",
    5 : "M68K_AM_REGI_ADDR_PRE_DEC",
    6 : "M68K_AM_REGI_ADDR_DISP",
    7 : "M68K_AM_AREGI_INDEX_8_BIT_DISP",
    8 : "M68K_AM_AREGI_INDEX_BASE_DISP",
    9 : "M68K_AM_MEMI_POST_INDEX",
    10 : "M68K_AM_MEMI_PRE_INDEX",
    11 : "M68K_AM_PCI_DISP",
    12 : "M68K_AM_PCI_INDEX_8_BIT_DISP",
    13 : "M68K_AM_PCI_INDEX_BASE_DISP",
    14 : "M68K_AM_PC_MEMI_POST_INDEX",
    15 : "M68K_AM_PC_MEMI_PRE_INDEX",
    16 : "M68K_AM_ABSOLUTE_DATA_SHORT",
    17 : "M68K_AM_ABSOLUTE_DATA_LONG",
    18 : "M68K_AM_IMMEDIATE",
    }


# Operand type for instruction's operands

map_op_str = {
    0 : "M68K_OP_INVALID",
    1 : "M68K_OP_REG",
    2 : "M68K_OP_IMM",
    3 : "M68K_OP_MEM",
    4 : "M68K_OP_FP",
    5 : "M68K_OP_REG_BITS",
    6 : "M68K_OP_REG_PAIR",
}


def debug(insn, op):
    if len(sys.argv) > 3:
        print("id %d type %s address_mode %s" % (insn.id, map_op_str[op.type], map_address_mode_str[op.address_mode]))

    
def dump_ops(insn):
    str = ''
    mnemonic = insn.insn_name()

    i = 0
    while i < len(insn.operands):
        if i > 0:
            str += ','
        op = insn.operands[i]
        debug(insn, op)
        # "data" instruction generated by SKIPDATA option has no detail
        if insn.id == M68K_INS_INVALID:
            return format("0x%04x" % (op.imm))
        if op.type == M68K_OP_REG:
            str_op_reg = dump_op_ea(insn, op)
            if str_op_reg == '' or op.address_mode == M68K_AM_REG_DIRECT_ADDR:
                str_op_reg = dump_op_reg(insn, op.reg)
            str += str_op_reg
        if op.type == M68K_OP_IMM:
            str_op_imm = format("#%u" % (op.imm))
            if mnemonic in ["bkpt"]:
                str_op_imm = format("%u" % (op.imm))
            signed_insn = [ "move", "moveq", "cmp", "cmpi", "ori", "bclr", "pack", "unpk", "sub", "add" ]
            if mnemonic in signed_insn:
                if insn.op_size.size == 1 or mnemonic == "moveq":
                    str_op_imm = format("#%d" % s8(op.imm))
                if insn.op_size.size == 2 or mnemonic == "pack":
                    str_op_imm = format("#%d" % s16(op.imm))
                if insn.op_size.size == 4:
                    str_op_imm = format("#%d" % (op.imm))

            dbxx_insn = [ "dbt", "dbf", "dbhi", "dbls", "dbcc", "dbcs", "dbne", "dbeq", "dbvc", "dbvs", "dbpl", "dbmi", "dbge", "dblt", "dbgt", "dble", "dbra" ]
            if is_branch(insn) or mnemonic in dbxx_insn:
                str_op_imm = format("0x%x" % (op.imm & 0xffffffff))
            str += str_op_imm
        if op.type == M68K_OP_MEM:
            str_op_mem = dump_op_ea(insn, op)
            if str_op_mem == '':
                str_op_mem = format("0x%x" % (op.imm))
            str += str_op_mem
        if op.type in [ M68K_OP_REG_BITS, M68K_OP_REG_PAIR ]:
            str += dump_op_ea(insn, op)

#        if insn.address == 0x3127c:
#            import pdb;pdb.set_trace()
#        print("type %u am %u\n" % (op.type, op.address_mode))    
        i += 1
    return str


def is_branch(insn):
    mnemonic = insn.insn_name()
    branch_insn = [ "bsr", "bra", "bhi", "bls", "bcc", "bcs", "bne", "beq", "bvc", "bvs", "bpl", "bmi", "bge", "blt", "bgt", "ble" ];
    return mnemonic in branch_insn

def dump_mnemonic(insn):
    # "data" instruction generated by SKIPDATA option has no detail
    if insn.id == M68K_INS_INVALID:
        return ".short"
    mnemonic = insn.insn_name()
    ext = { 0: '', 1:'b', 2:'w', 4:'l' }
    if is_branch(insn):
        ext.update({ 1:'s', 2:'w', 4:'l' })
    
    no_size = [ "pea", "lea", "bset", "bclr", "bchg", "btst", "nbcd", "abcd", "sbcd", "exg", "scc", "sls", "scs", "shi" ]
    sxx_insn = [ "st", "sf", "shi", "sls", "scc", "scs", "sne", "seq", "svc", "svs", "spl", "smi", "sge", "slt", "sgt", "sle", "stop" ]
    no_size += sxx_insn
    no_size += [ "tas" ]
    if mnemonic in no_size:
        ext.update({ 0:'', 1:'', 2:'', 4:'' })
    return mnemonic + ext[insn.op_size.size]

def print_insn_detail_np(insn):
    # objdump format hack
    if insn.size == 2:
        space = ' ' * 11
    if insn.size == 4:
        space = ' ' * 6
    if insn.size >= 6:
        space = ' '
    space_ops = ''
    if len(insn.operands) > 0:
        space_ops = ' '

    print("   %x:\t%s%s\t%s%s%s" % (insn.address, dump_bytes(insn._raw.bytes, min(insn.size, 6)), space, dump_mnemonic(insn), space_ops, dump_ops(insn)))

    if insn.size > 6:
        delta = min(insn.size, 6)
        print("   %x:\t%s " % (insn.address+delta, dump_bytes(insn._raw.bytes[delta:], min(insn.size-delta, 6))))

          
def print_objdump_dumpheader(filename='', address=0):
    print(objdump_dumpheader_fmt % (filename, address))

# ## Test class Cs
def test_class():
    for (arch, mode, code, comment) in all_tests:
        filename = "/dev/stdin"
        address = 0
        if len(sys.argv) > 1:
            filename = sys.argv[1]
        if len(sys.argv) > 2:
            address = int(sys.argv[2],16)
        if len(sys.argv) > 3:
            debug_mode = True
            
        with open(filename, "rb") as f:
            code = f.read()

        try:
            md = Cs(arch, mode)
            md.detail = True

            print_objdump_dumpheader(filename, address)
            
            for insn in md.disasm(code, address):
                print_insn_detail_np(insn)

        except CsError as e:
            print("ERROR: %s" % e)


if __name__ == '__main__':
    test_class()

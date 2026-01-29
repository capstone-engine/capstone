# Capstone Python bindings, by Nicolas PLANEL <nplanel@gmail.com>

import ctypes
from . import copy_ctypes_list
from .m68k_const import *

# define the API
class M68KOpMem(ctypes.Structure):
    _fields_ = (
        ('base_reg', ctypes.c_uint),
        ('index_reg', ctypes.c_uint),
        ('in_base_reg', ctypes.c_uint),
        ('in_disp', ctypes.c_int),
        ('out_disp', ctypes.c_int),
        ('disp', ctypes.c_short),
        ('scale', ctypes.c_ubyte),
        ('bitfield', ctypes.c_ubyte),
        ('width', ctypes.c_ubyte),
        ('offset', ctypes.c_ubyte),
        ('index_size', ctypes.c_ubyte),
        ('in_disp_size', ctypes.c_ubyte),
        ('out_disp_size', ctypes.c_ubyte),
        ('disp_size', ctypes.c_ubyte),
    )

class M68KOpRegPair(ctypes.Structure):
    _fields_ = (
        ('reg_0', ctypes.c_uint),
        ('reg_1', ctypes.c_uint),
    )

class M68KOpValue(ctypes.Union):
    _fields_ = (
        ('imm', ctypes.c_int64),
        ('dimm', ctypes.c_double),
        ('simm', ctypes.c_float),
        ('reg', ctypes.c_uint),
        ('reg_pair', M68KOpRegPair),
    )

class M68KOpBrDisp(ctypes.Structure):
    _fields_ = (
        ('disp', ctypes.c_int),
        ('disp_size', ctypes.c_ubyte),
    )
    
class M68KOp(ctypes.Structure):
    _fields_ = (
        ('value', M68KOpValue),
        ('mem', M68KOpMem),
        ('br_disp', M68KOpBrDisp),
        ('register_bits', ctypes.c_uint),
        ('type', ctypes.c_uint),
        ('address_mode', ctypes.c_uint),
    )

    @property
    def imm(self):
        return self.value.imm

    @property
    def dimm(self):
        return self.value.dimm

    @property
    def simm(self):
        return self.value.simm

    @property
    def reg(self):
        return self.value.reg
    
    @property
    def reg_pair(self):
        return self.value.reg_pair

    @property
    def mem(self):
        return self.mem

    @property
    def register_bits(self):
        return self.register_bits

class M68KOpSize(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_uint),
        ('size', ctypes.c_uint),
    )

    def get(a):
        return copy_ctypes_list(type, size)

class CsM68K(ctypes.Structure):
    M68K_OPERAND_COUNT = 4
    _fields_ = (
        ('operands', M68KOp * M68K_OPERAND_COUNT),
        ('op_size', M68KOpSize),
        ('op_count', ctypes.c_uint8),
    )

def get_arch_info(a):
    return (copy_ctypes_list(a.operands[:a.op_count]), a.op_size)

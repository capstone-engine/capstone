# Capstone Python bindings, by Wolfgang Schwotzer <wolfgang.schwotzer@gmx.net>

import ctypes
from . import copy_ctypes_list
from .m680x_const import *

# define the API
class M680xOpIdx(ctypes.Structure):
    _fields_ = (
        ('base_reg', ctypes.c_uint),
        ('offset_reg', ctypes.c_uint),
        ('offset', ctypes.c_int16),
        ('offset_addr', ctypes.c_uint16),
        ('offset_bits', ctypes.c_uint8),
        ('inc_dec', ctypes.c_int8),
        ('flags', ctypes.c_uint8),
    )

class M680xOpRel(ctypes.Structure):
    _fields_ = (
        ('address', ctypes.c_uint16),
        ('offset', ctypes.c_int16),
    )

class M680xOpExt(ctypes.Structure):
    _fields_ = (
        ('address', ctypes.c_uint16),
        ('indirect', ctypes.c_bool),
    )

class M680xOpValue(ctypes.Union):
    _fields_ = (
        ('imm', ctypes.c_int32),
        ('reg', ctypes.c_uint),
        ('idx', M680xOpIdx),
        ('rel', M680xOpRel),
        ('ext', M680xOpExt),
        ('direct_addr', ctypes.c_uint8),
        ('const_val', ctypes.c_uint8),
    )

class M680xOp(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_uint),
        ('value', M680xOpValue),
        ('size', ctypes.c_uint8),
        ('access', ctypes.c_uint8),
    )

    @property
    def imm(self):
        return self.value.imm

    @property
    def reg(self):
        return self.value.reg

    @property
    def idx(self):
        return self.value.idx

    @property
    def rel(self):
        return self.value.rel

    @property
    def ext(self):
        return self.value.ext

    @property
    def direct_addr(self):
        return self.value.direct_addr

    @property
    def const_val(self):
        return self.value.const_val


class CsM680x(ctypes.Structure):
    _fields_ = (
        ('flags', ctypes.c_uint8),
        ('op_count', ctypes.c_uint8),
        ('operands', M680xOp * 9),
    )

def get_arch_info(a):
    return (a.flags, copy_ctypes_list(a.operands[:a.op_count]))


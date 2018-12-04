# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes
from . import copy_ctypes_list
from .mos65xx_const import *

# define the API
class MOS65xxOpValue(ctypes.Union):
    _fields_ = (
        ('reg', ctypes.c_uint),
        ('imm', ctypes.c_uint8),
        ('mem', ctypes.c_uint16),
    )

class MOS65xxOp(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_uint),
        ('value', MOS65xxOpValue),
    )

    @property
    def imm(self):
        return self.value.imm

    @property
    def reg(self):
        return self.value.reg

    @property
    def mem(self):
        return self.value.mem


class CsMOS65xx(ctypes.Structure):
    _fields_ = (
        ('am', ctypes.c_uint),
        ('modifies_flags', ctypes.c_uint8),
        ('op_count', ctypes.c_uint8),
        ('operands', MOS65xxOp * 3),
    )

def get_arch_info(a):
    return (a.am, a.modifies_flags, copy_ctypes_list(a.operands[:a.op_count]))



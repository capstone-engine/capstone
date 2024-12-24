# Capstone Python bindings, by R33v0LT <sibirtsevdl@gmail.com>

import ctypes
from . import copy_ctypes_list
from .arc_const import *


class ARCOpValue(ctypes.Union):
    _fields_ = (
        ('reg', ctypes.c_uint),
        ('imm', ctypes.c_int64)
    )


class ARCOp(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_int),
        ('value', ARCOpValue),
        ('access', ctypes.c_uint)
    )

    @property
    def imm(self):
        return self.value.imm

    @property
    def reg(self):
        return self.value.reg


# Instruction structure
class CsARC(ctypes.Structure):
    _fields_ = (
        ('op_count', ctypes.c_uint8),
        ('operands', ARCOp * 8),
    )

def get_arch_info(a):
    return (copy_ctypes_list(a.operands[:a.op_count]))

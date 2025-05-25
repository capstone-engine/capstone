import ctypes
from . import copy_ctypes_list
from .alpha_const import *

class AlphaOpMem(ctypes.Structure):
    _fields_ = (
        ('base', ctypes.c_uint8),
        ('disp', ctypes.c_int32),
    )


class AlphaOpValue(ctypes.Union):
    _fields_ = (
        ('reg', ctypes.c_uint),
        ('imm', ctypes.c_int32),
    )


class AlphaOp(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_uint),
        ('value', AlphaOpValue),
        ('access', ctypes.c_uint)
    )

    @property
    def imm(self):
        return self.value.imm

    @property
    def reg(self):
        return self.value.reg


# Instruction structure
class CsAlpha(ctypes.Structure):
    _fields_ = (
        ('op_count', ctypes.c_uint8),
        ('operands', AlphaOp * 3)
    )

def get_arch_info(a):
    return (copy_ctypes_list(a.operands[:a.op_count]))

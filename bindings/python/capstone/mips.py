# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes, copy
from .mips_const import *

# define the API
class MipsOpMem(ctypes.Structure):
    _fields_ = (
        ('base', ctypes.c_uint),
        ('disp', ctypes.c_int64),
    )

class MipsOpValue(ctypes.Union):
    _fields_ = (
        ('reg', ctypes.c_uint),
        ('imm', ctypes.c_int64),
        ('mem', MipsOpMem),
    )

class MipsOp(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_uint),
        ('value', MipsOpValue),
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


class CsMips(ctypes.Structure):
    _fields_ = (
        ('op_count', ctypes.c_uint8),
        ('operands', MipsOp * 8),
    )

def get_arch_info(a):
    return copy.deepcopy(a.operands[:a.op_count])


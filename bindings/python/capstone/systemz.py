# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes, copy
from .sysz_const import *

# define the API
class SyszOpMem(ctypes.Structure):
    _fields_ = (
        ('base', ctypes.c_uint8),
        ('index', ctypes.c_uint8),
        ('length', ctypes.c_uint64),
        ('disp', ctypes.c_int64),
    )

class SyszOpValue(ctypes.Union):
    _fields_ = (
        ('reg', ctypes.c_uint),
        ('imm', ctypes.c_int64),
        ('mem', SyszOpMem),
    )

class SyszOp(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_uint),
        ('value', SyszOpValue),
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


class CsSysz(ctypes.Structure):
    _fields_ = (
        ('cc', ctypes.c_uint),
        ('op_count', ctypes.c_uint8),
        ('operands', SyszOp * 6),
    )

def get_arch_info(a):
    return (a.cc, copy.deepcopy(a.operands[:a.op_count]))


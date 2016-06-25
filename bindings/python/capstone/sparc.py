# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes
from . import copy_ctypes_list
from .sparc_const import *

# define the API
class SparcOpMem(ctypes.Structure):
    _fields_ = (
        ('base', ctypes.c_uint8),
        ('index', ctypes.c_uint8),
        ('disp', ctypes.c_int32),
    )

class SparcOpValue(ctypes.Union):
    _fields_ = (
        ('reg', ctypes.c_uint),
        ('imm', ctypes.c_int32),
        ('mem', SparcOpMem),
    )

class SparcOp(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_uint),
        ('value', SparcOpValue),
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


class CsSparc(ctypes.Structure):
    _fields_ = (
        ('cc', ctypes.c_uint),
        ('hint', ctypes.c_uint),
        ('op_count', ctypes.c_uint8),
        ('operands', SparcOp * 4),
    )

def get_arch_info(a):
    return (a.cc, a.hint, copy_ctypes_list(a.operands[:a.op_count]))


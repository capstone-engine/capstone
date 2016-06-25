# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes
from . import copy_ctypes_list
from .xcore_const import *

# define the API
class XcoreOpMem(ctypes.Structure):
    _fields_ = (
        ('base', ctypes.c_uint8),
        ('index', ctypes.c_uint8),
        ('disp', ctypes.c_int32),
        ('direct', ctypes.c_int),
    )

class XcoreOpValue(ctypes.Union):
    _fields_ = (
        ('reg', ctypes.c_uint),
        ('imm', ctypes.c_int32),
        ('mem', XcoreOpMem),
    )

class XcoreOp(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_uint),
        ('value', XcoreOpValue),
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


class CsXcore(ctypes.Structure):
    _fields_ = (
        ('op_count', ctypes.c_uint8),
        ('operands', XcoreOp * 8),
    )

def get_arch_info(a):
    return (copy_ctypes_list(a.operands[:a.op_count]))


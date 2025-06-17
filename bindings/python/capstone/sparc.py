# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes
from . import copy_ctypes_list
from .sparc_const import *

# define the API
class SparcOpMem(ctypes.Structure):
    _fields_ = (
        ('base', ctypes.c_uint),
        ('index', ctypes.c_uint),
        ('disp', ctypes.c_int32),
    )

class SparcOpValue(ctypes.Union):
    _fields_ = (
        ('reg', ctypes.c_uint),
        ('imm', ctypes.c_int64),
        ('mem', SparcOpMem),
        ('membar_tag', ctypes.c_uint),
        ('asi', ctypes.c_uint),
    )

class SparcOp(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_uint),
        ('value', SparcOpValue),
        ('access', ctypes.c_uint8),
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

    @property
    def asi(self):
        return self.value.asi

    @property
    def membar_tag(self):
        return self.value.membar_tag


class CsSparc(ctypes.Structure):
    _fields_ = (
        ('cc', ctypes.c_uint),
        ('cc_field', ctypes.c_uint),
        ('hint', ctypes.c_uint),
        ('format', ctypes.c_uint),
        ('op_count', ctypes.c_uint8),
        ('operands', SparcOp * 4),
    )

def get_arch_info(a):
    return (a.cc, a.cc_field, a.hint, a.format, copy_ctypes_list(a.operands[:a.op_count]))


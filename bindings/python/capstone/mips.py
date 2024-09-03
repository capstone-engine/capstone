# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes
from . import copy_ctypes_list
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
        ('uimm', ctypes.c_uint64),
        ('mem', MipsOpMem),
    )

class MipsOp(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_uint),
        ('value', MipsOpValue),
        ('is_reglist', ctypes.c_bool),
        ('is_unsigned', ctypes.c_bool),
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


class CsMips(ctypes.Structure):
    _fields_ = (
        ('op_count', ctypes.c_uint8),
        ('operands', MipsOp * 10),
    )

def get_arch_info(a):
    return copy_ctypes_list(a.operands[:a.op_count])


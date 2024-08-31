# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes
from . import copy_ctypes_list
from .ppc_const import *

# define the API
class PpcOpMem(ctypes.Structure):
    _fields_ = (
        ('base', ctypes.c_uint),
        ('disp', ctypes.c_int32),
        ('offset', ctypes.c_uint),
    )

class PpcOpValue(ctypes.Union):
    _fields_ = (
        ('reg', ctypes.c_uint),
        ('imm', ctypes.c_int64),
        ('mem', PpcOpMem),
    )

class PpcOp(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_uint),
        ('value', PpcOpValue),
        ('access', ctypes.c_uint),
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

class PpcBC(ctypes.Structure):
    _fields_ = (
        ('bo', ctypes.c_uint8),
        ('bi', ctypes.c_uint8),
        ('crX_bit', ctypes.c_uint),
        ('crX', ctypes.c_uint),
        ('hint', ctypes.c_uint),
        ('pred_cr', ctypes.c_uint),
        ('pred_ctr', ctypes.c_uint),
        ('bh', ctypes.c_uint),
    )

class CsPpc(ctypes.Structure):
    _fields_ = (
        ('bc', PpcBC),
        ('update_cr0', ctypes.c_bool),
        ('format', ctypes.c_uint32),
        ('op_count', ctypes.c_uint8),
        ('operands', PpcOp * 8),
    )

def get_arch_info(a):
    return (a.bc, a.update_cr0, a.format, copy_ctypes_list(a.operands[:a.op_count]))


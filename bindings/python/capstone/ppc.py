# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes
from . import copy_ctypes_list
from .ppc_const import *

# define the API
class PpcOpMem(ctypes.Structure):
    _fields_ = (
        ('base', ctypes.c_uint),
        ('disp', ctypes.c_int32),
    )

class PpcOpCrx(ctypes.Structure):
    _fields_ = (
        ('scale', ctypes.c_uint),
        ('reg', ctypes.c_uint),
        ('cond', ctypes.c_uint),
    )

class PpcOpValue(ctypes.Union):
    _fields_ = (
        ('reg', ctypes.c_uint),
        ('imm', ctypes.c_int64),
        ('mem', PpcOpMem),
        ('crx', PpcOpCrx),
    )

class PpcOp(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_uint),
        ('value', PpcOpValue),
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
    def crx(self):
        return self.value.crx


class CsPpc(ctypes.Structure):
    _fields_ = (
        ('bc', ctypes.c_uint),
        ('bh', ctypes.c_uint),
        ('update_cr0', ctypes.c_bool),
        ('op_count', ctypes.c_uint8),
        ('operands', PpcOp * 8),
    )

def get_arch_info(a):
    return (a.bc, a.bh, a.update_cr0, copy_ctypes_list(a.operands[:a.op_count]))


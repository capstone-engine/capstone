# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes
from . import copy_ctypes_list
from .riscv_const import *

# define the API
class RISCVOpMem(ctypes.Structure):
    _fields_ = (
        ('base', ctypes.c_uint8),
        ('disp', ctypes.c_int64),
    )

class RISCVOpValue(ctypes.Union):
    _fields_ = (
        ('reg', ctypes.c_uint),
        ('imm', ctypes.c_int64),
        ('mem', RISCVOpMem),
    )

class RISCVOp(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_uint),
        ('value', RISCVOpValue),
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


class CsRISCV(ctypes.Structure):
    _fields_ = (
	('need_effective_addr', ctypes.c_bool),
        ('op_count',            ctypes.c_uint8),
        ('operands',            RISCVOp * 8),
    )

def get_arch_info(a):
    return (copy_ctypes_list(a.operands[:a.op_count]))


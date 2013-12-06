# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes, copy
from mips_const import *

# define the API
class mips_op_mem(ctypes.Structure):
    _fields_ = (
        ('base', ctypes.c_uint),
        ('disp', ctypes.c_int64),
    )

class mips_op_value(ctypes.Union):
    _fields_ = (
        ('reg', ctypes.c_uint),
        ('imm', ctypes.c_int64),
        ('mem', mips_op_mem),
    )

class mips_op(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_uint),
        ('value', mips_op_value),
    )

class _cs_mips(ctypes.Structure):
    _fields_ = (
        ('op_count', ctypes.c_uint8),
        ('operands', mips_op * 8),
    )

def get_arch_info(a):
    return copy.deepcopy(a.operands[:a.op_count])


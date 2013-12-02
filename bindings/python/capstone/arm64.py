# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes, ctypes.util
from Arm64_const import *

# define the API
class arm64_op_mem(ctypes.Structure):
    _fields_ = (
        ('base', ctypes.c_uint),
        ('index', ctypes.c_uint),
        ('disp', ctypes.c_int32),
    )

class arm64_op_shift(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_uint),
        ('value', ctypes.c_uint),
    )

class arm64_op_value(ctypes.Union):
    _fields_ = (
        ('reg', ctypes.c_uint),
        ('imm', ctypes.c_int32),
        ('fp', ctypes.c_double),
        ('mem', arm64_op_mem),
    )

class arm64_op(ctypes.Structure):
    _fields_ = (
        ('shift', arm64_op_shift),
        ('ext', ctypes.c_uint),
        ('type', ctypes.c_uint),
        ('value', arm64_op_value),
    )

class _cs_arm64(ctypes.Structure):
    _fields_ = (
        ('cc', ctypes.c_uint),
        ('update_flags', ctypes.c_bool),
        ('writeback', ctypes.c_bool),
        ('op_count', ctypes.c_uint8),
        ('operands', arm64_op * 8),
    )

def get_arch_info(a):
    op_info = []
    for i in a.operands:
        if i.type == 0:
            break
        op_info.append(i)
    return (a.cc, a.update_flags, a.writeback, op_info)


# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes, ctypes.util
from Arm_const import *

# define the API
class arm_op_mem(ctypes.Structure):
    _fields_ = (
        ('base', ctypes.c_uint),
        ('index', ctypes.c_uint),
        ('scale', ctypes.c_int),
        ('disp', ctypes.c_int),
    )

class arm_op_shift(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_uint),
        ('value', ctypes.c_uint),
    )

class arm_op_value(ctypes.Union):
    _fields_ = (
        ('reg', ctypes.c_uint),
        ('imm', ctypes.c_int),
        ('fp', ctypes.c_double),
        ('mem', arm_op_mem),
    )

class arm_op(ctypes.Structure):
    _fields_ = (
        ('shift', arm_op_shift),
        ('type', ctypes.c_uint),
        ('value', arm_op_value),
    )

class _cs_arm(ctypes.Structure):
    _fields_ = (
        ('cc', ctypes.c_uint),
        ('update_flags', ctypes.c_bool),
        ('writeback', ctypes.c_bool),
        ('op_count', ctypes.c_uint8),
        ('operands', arm_op * 20),
    )

def get_arch_info(arch):
    op_info = []
    for i in arch.operands:
        if i.type == 0:
            break
        op_info.append(i)
    return (arch.cc, arch.update_flags, arch.writeback, op_info)


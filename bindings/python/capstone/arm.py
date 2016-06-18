# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes
from . import copy_ctypes_list
from .arm_const import *

# define the API
class ArmOpMem(ctypes.Structure):
    _fields_ = (
        ('base', ctypes.c_uint),
        ('index', ctypes.c_uint),
        ('scale', ctypes.c_int),
        ('disp', ctypes.c_int),
        ('lshift', ctypes.c_int),
    )

class ArmOpShift(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_uint),
        ('value', ctypes.c_uint),
    )

class ArmOpValue(ctypes.Union):
    _fields_ = (
        ('reg', ctypes.c_uint),
        ('imm', ctypes.c_int32),
        ('fp', ctypes.c_double),
        ('mem', ArmOpMem),
        ('setend', ctypes.c_int),
    )

class ArmOp(ctypes.Structure):
    _fields_ = (
        ('vector_index', ctypes.c_int),
        ('shift', ArmOpShift),
        ('type', ctypes.c_uint),
        ('value', ArmOpValue),
        ('subtracted', ctypes.c_bool),
        ('access', ctypes.c_uint8),
        ('neon_lane', ctypes.c_int8),
    )

    @property
    def imm(self):
        return self.value.imm

    @property
    def reg(self):
        return self.value.reg

    @property
    def fp(self):
        return self.value.fp

    @property
    def mem(self):
        return self.value.mem

    @property
    def setend(self):
        return self.value.setend


class CsArm(ctypes.Structure):
    _fields_ = (
        ('usermode', ctypes.c_bool),
        ('vector_size', ctypes.c_int),
        ('vector_data', ctypes.c_int),
        ('cps_mode', ctypes.c_int),
        ('cps_flag', ctypes.c_int),
        ('cc', ctypes.c_uint),
        ('update_flags', ctypes.c_bool),
        ('writeback', ctypes.c_bool),
        ('mem_barrier', ctypes.c_int),
        ('op_count', ctypes.c_uint8),
        ('operands', ArmOp * 36),
    )

def get_arch_info(a):
    return (a.usermode, a.vector_size, a.vector_data, a.cps_mode, a.cps_flag, a.cc, a.update_flags, \
        a.writeback, a.mem_barrier, copy_ctypes_list(a.operands[:a.op_count]))


# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes, copy
from .arm64_const import *

# define the API
class Arm64OpMem(ctypes.Structure):
    _fields_ = (
        ('base', ctypes.c_uint),
        ('index', ctypes.c_uint),
        ('disp', ctypes.c_int32),
    )

class Arm64OpShift(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_uint),
        ('value', ctypes.c_uint),
    )

class Arm64OpValue(ctypes.Union):
    _fields_ = (
        ('reg', ctypes.c_uint),
        ('imm', ctypes.c_int64),
        ('fp', ctypes.c_double),
        ('mem', Arm64OpMem),
        ('pstate', ctypes.c_int),
        ('sys', ctypes.c_uint),
        ('prefetch', ctypes.c_int),
        ('barrier', ctypes.c_int),
    )

class Arm64Op(ctypes.Structure):
    _fields_ = (
        ('vector_index', ctypes.c_int),
        ('vas', ctypes.c_int),
        ('vess', ctypes.c_int),
        ('shift', Arm64OpShift),
        ('ext', ctypes.c_uint),
        ('type', ctypes.c_uint),
        ('value', Arm64OpValue),
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
    def pstate(self):
        return self.value.pstate

    @property
    def sys(self):
        return self.value.sys

    @property
    def prefetch(self):
        return self.value.prefetch

    @property
    def barrier(self):
        return self.value.barrier



class CsArm64(ctypes.Structure):
    _fields_ = (
        ('cc', ctypes.c_uint),
        ('update_flags', ctypes.c_bool),
        ('writeback', ctypes.c_bool),
        ('op_count', ctypes.c_uint8),
        ('operands', Arm64Op * 8),
    )

def get_arch_info(a):
    return (a.cc, a.update_flags, a.writeback, copy.deepcopy(a.operands[:a.op_count]))


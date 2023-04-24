# Capstone Python bindings, by billow <billow.fun@gmail.com>

import ctypes, copy
from .tricore_const import *

class TriCoreOpMem(ctypes.Structure):
    _fields_ = (
        ('base', ctypes.c_uint8),
        ('disp', ctypes.c_int32),
    )


class TriCoreOpValue(ctypes.Union):
    _fields_ = (
        ('reg', ctypes.c_uint),
        ('imm', ctypes.c_int32),
        ('mem', TriCoreOpMem),
    )


class TriCoreOp(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_uint),
        ('value', TriCoreOpValue),
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


# Instruction structure
class CsTriCore(ctypes.Structure):
    _fields_ = (
        ('op_count', ctypes.c_uint8),
        ('operands', TriCoreOp * 8),
    )

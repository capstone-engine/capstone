# Capstone Python bindings, by billow <billow.fun@gmail.com>

import ctypes
from . import copy_ctypes_list
from .xtensa_const import *


class XtensaOpMem(ctypes.Structure):
    _fields_ = (
        ("base", ctypes.c_uint8),
        ("disp", ctypes.c_int32),
    )


class XtensaOpValue(ctypes.Union):
    _fields_ = (
        ("reg", ctypes.c_uint8),
        ("imm", ctypes.c_int32),
        ("mem", XtensaOpMem),
    )


class XtensaOp(ctypes.Structure):
    _fields_ = (
        ("type", ctypes.c_uint8),
        ("access", ctypes.c_uint8),
        ("value", XtensaOpValue),
    )

    @property
    def reg(self):
        return self.value.reg

    @property
    def imm(self):
        return self.value.imm

    @property
    def mem(self):
        return self.value.mem


# Instruction structure
class CsXtensa(ctypes.Structure):
    _fields_ = (
        ("op_count", ctypes.c_uint8),
        ("operands", XtensaOp * 8),
        ("format", ctypes.c_uint32),
    )


def get_arch_info(a):
    return copy_ctypes_list(a.operands[: a.op_count])

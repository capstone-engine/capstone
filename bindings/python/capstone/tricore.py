# Capstone Python bindings, by billow <billow.fun@gmail.com>

import ctypes

from . import copy_ctypes_list
from .tricore_const import *


class TriCoreOpMem(ctypes.Structure):
    base: int
    disp: int
    _fields_ = (
        ("base", ctypes.c_uint8),
        ("disp", ctypes.c_int64),
    )


class TriCoreOpValue(ctypes.Union):
    reg: int
    imm: int
    mem: TriCoreOpMem
    _fields_ = (
        ("reg", ctypes.c_uint),
        ("imm", ctypes.c_int64),
        ("mem", TriCoreOpMem),
    )


class TriCoreOp(ctypes.Structure):
    type: int
    value: TriCoreOpValue
    access: int
    _fields_ = (
        ("type", ctypes.c_uint),
        ("value", TriCoreOpValue),
        ("access", ctypes.c_uint),
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
    op_count: int
    operands: tuple[
        TriCoreOp,
        TriCoreOp,
        TriCoreOp,
        TriCoreOp,
        TriCoreOp,
        TriCoreOp,
        TriCoreOp,
        TriCoreOp,
    ]
    update_flags: bool
    _fields_ = (
        ("op_count", ctypes.c_uint8),
        ("operands", TriCoreOp * 8),
        ("update_flags", ctypes.c_bool),
    )


def get_arch_info(a):
    return (a.update_flags, copy_ctypes_list(a.operands[: a.op_count]))

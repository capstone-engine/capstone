# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes

from . import copy_ctypes_list
from .systemz_const import *


# define the API
class SystemZOpMem(ctypes.Structure):
    am: int
    base: int
    index: int
    length: int
    disp: int
    _fields_ = (
        ("am", ctypes.c_int),
        ("base", ctypes.c_uint8),
        ("index", ctypes.c_uint8),
        ("length", ctypes.c_uint64),
        ("disp", ctypes.c_int64),
    )


class SystemZOpValue(ctypes.Union):
    reg: int
    imm: int
    mem: SystemZOpMem
    _fields_ = (
        ("reg", ctypes.c_uint),
        ("imm", ctypes.c_int64),
        ("mem", SystemZOpMem),
    )


class SystemZOp(ctypes.Structure):
    type: int
    value: SystemZOpValue
    access: int
    imm_width: int
    _fields_ = (
        ("type", ctypes.c_uint),
        ("value", SystemZOpValue),
        ("access", ctypes.c_uint),
        ("imm_width", ctypes.c_uint8),
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


class CsSystemZ(ctypes.Structure):
    cc: int
    format: int
    op_count: int
    operands: tuple[SystemZOp, ...]
    _fields_ = (
        ("cc", ctypes.c_uint),
        ("format", ctypes.c_int),
        ("op_count", ctypes.c_uint8),
        ("operands", SystemZOp * 6),
    )


def get_arch_info(a):
    return a.cc, a.format, copy_ctypes_list(a.operands[: a.op_count])

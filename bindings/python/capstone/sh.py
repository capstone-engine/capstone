# Capstone Python bindings, by Peace-Maker <peacemakerctf@gmail.com>

import ctypes

from . import copy_ctypes_list
from .sh_const import *


# define the API
class SHOpMem(ctypes.Structure):
    address: int
    reg: int
    disp: int
    _fields_ = (
        ("address", ctypes.c_uint),
        ("reg", ctypes.c_uint),
        ("disp", ctypes.c_uint32),
    )


class SHOpDsp(ctypes.Structure):
    insn: int
    operand: tuple[int, int]
    r: tuple[int, ...]
    cc: int
    imm: int
    size: int
    _fields_ = (
        ("insn", ctypes.c_uint),
        ("operand", ctypes.c_uint * 2),
        ("r", ctypes.c_uint * 6),
        ("cc", ctypes.c_uint),
        ("imm", ctypes.c_uint8),
        ("size", ctypes.c_int),
    )


class SHOpValue(ctypes.Union):
    imm: int
    reg: int
    mem: SHOpMem
    dsp: SHOpDsp
    _fields_ = (
        ("imm", ctypes.c_int64),
        ("reg", ctypes.c_uint),
        ("mem", SHOpMem),
        ("dsp", SHOpDsp),
    )


class SHOp(ctypes.Structure):
    type: int
    value: SHOpValue
    _fields_ = (
        ("type", ctypes.c_uint),
        ("value", SHOpValue),
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

    @property
    def dsp(self):
        return self.value.dsp


class CsSH(ctypes.Structure):
    insn: int
    size: int
    op_count: int
    operands: tuple[SHOp, SHOp, SHOp]
    _fields_ = (
        ("insn", ctypes.c_uint),
        ("size", ctypes.c_uint8),
        ("op_count", ctypes.c_uint8),
        ("operands", SHOp * 3),
    )


def get_arch_info(a):
    return (a.insn, a.size, copy_ctypes_list(a.operands[: a.op_count]))

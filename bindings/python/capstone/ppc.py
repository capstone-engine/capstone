# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes

from . import copy_ctypes_list
from .ppc_const import *


# define the API
class PpcOpMem(ctypes.Structure):
    base: int
    disp: int
    offset: int
    _fields_ = (
        ("base", ctypes.c_uint),
        ("disp", ctypes.c_int32),
        ("offset", ctypes.c_uint),
    )


class PpcOpValue(ctypes.Union):
    reg: int
    imm: int
    mem: PpcOpMem
    _fields_ = (
        ("reg", ctypes.c_uint),
        ("imm", ctypes.c_int64),
        ("mem", PpcOpMem),
    )


class PpcOp(ctypes.Structure):
    type: int
    value: PpcOpValue
    access: int
    _fields_ = (
        ("type", ctypes.c_uint),
        ("value", PpcOpValue),
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


class PpcBC(ctypes.Structure):
    bo: int
    bi: int
    crX_bit: int
    crX: int
    hint: int
    pred_cr: int
    pred_ctr: int
    bh: int
    _fields_ = (
        ("bo", ctypes.c_uint8),
        ("bi", ctypes.c_uint8),
        ("crX_bit", ctypes.c_uint),
        ("crX", ctypes.c_uint),
        ("hint", ctypes.c_uint),
        ("pred_cr", ctypes.c_uint),
        ("pred_ctr", ctypes.c_uint),
        ("bh", ctypes.c_uint),
    )


class CsPpc(ctypes.Structure):
    bc: PpcBC
    update_cr0: bool
    format: int
    op_count: int
    operands: tuple[PpcOp, ...]
    _fields_ = (
        ("bc", PpcBC),
        ("update_cr0", ctypes.c_bool),
        ("format", ctypes.c_uint32),
        ("op_count", ctypes.c_uint8),
        ("operands", PpcOp * 8),
    )


def get_arch_info(a):
    return (a.bc, a.update_cr0, a.format, copy_ctypes_list(a.operands[: a.op_count]))

# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes

from . import copy_ctypes_list
from .riscv_const import *


# define the API
class RISCVOpMem(ctypes.Structure):
    _fields_ = (
        ("base", ctypes.c_uint),
        ("disp", ctypes.c_int64),
    )


class RISCVOpValue(ctypes.Union):
    _fields_ = (
        ("reg", ctypes.c_uint),
        ("imm", ctypes.c_int64),
        ("dimm", ctypes.c_double),
        ("mem", RISCVOpMem),
        ("csr", ctypes.c_uint16),
    )


class RISCVOp(ctypes.Structure):
    _fields_ = (
        ("type", ctypes.c_uint),
        ("value", RISCVOpValue),
        ("access", ctypes.c_uint),
    )

    @property
    def imm(self):
        return self.value.imm

    @property
    def dimm(self):
        return self.value.dimm

    @property
    def reg(self):
        return self.value.reg

    @property
    def mem(self):
        return self.value.mem

    @property
    def csr(self):
        return self.value.csr


class CsRISCV(ctypes.Structure):
    _fields_ = (
        ("need_effective_addr", ctypes.c_bool),
        ("op_count", ctypes.c_uint8),
        ("operands", RISCVOp * 8),
    )


def get_arch_info(a):
    return (a.need_effective_addr, copy_ctypes_list(a.operands[: a.op_count]))

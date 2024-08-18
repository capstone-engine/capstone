# Copyright © 2024 Rot127 <unisono@quyllur.org>
# SPDX-License-Identifier: BSD-3

import ctypes
from . import copy_ctypes_list
from .loongarch_const import *


class LoongArchOpMem(ctypes.Structure):
    _fields_ = (
        ("base", ctypes.c_uint),
        ("index", ctypes.c_uint),
        ("disp", ctypes.c_int64),
    )


class LoongArchOpValue(ctypes.Union):
    _fields_ = (
        ("reg", ctypes.c_uint),
        ("imm", ctypes.c_int64),
        ("mem", LoongArchOpMem),
    )


class LoongArchOp(ctypes.Structure):
    _fields_ = (
        ("type", ctypes.c_uint8),
        ("value", LoongArchOpValue),
        ("access", ctypes.c_uint8),
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
class CsLoongArch(ctypes.Structure):
    _fields_ = (
        ("format", ctypes.c_int),
        ("op_count", ctypes.c_uint8),
        ("operands", LoongArchOp * 8)
    )


def get_arch_info(a):
    return a.format, copy_ctypes_list(a.operands[: a.op_count])

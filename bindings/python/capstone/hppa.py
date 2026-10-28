# Capstone Python bindings, by Dmitry Sibirtsev <sibirtsevdl@gmail.com>

import ctypes

from . import copy_ctypes_list
from .hppa_const import *


class HPPAOpMem(ctypes.Structure):
    base: int
    space: int
    _fields_ = (
        ("base", ctypes.c_uint),
        ("space", ctypes.c_uint),
    )


class HPPAModifierValue(ctypes.Union):
    str_mod: str
    int_mod: int
    _fields_ = (("str_mod", ctypes.c_char_p), ("int_mod", ctypes.c_uint32))


class HPPAModifier(ctypes.Structure):
    type: int
    value: HPPAModifierValue
    _fields_ = (("type", ctypes.c_int), ("value", HPPAModifierValue))


class HPPAExt(ctypes.Structure):
    modifiers: tuple[HPPAModifier, ...]
    mod_num: int
    b_writable: bool
    cmplt: bool
    _fields_ = (
        ("modifiers", HPPAModifier * 5),
        ("mod_num", ctypes.c_uint8),
        ("b_writable", ctypes.c_bool),
        ("cmplt", ctypes.c_bool),
    )


class HPPAOpValue(ctypes.Union):
    reg: int
    imm: int
    mem: HPPAOpMem
    _fields_ = (("reg", ctypes.c_uint), ("imm", ctypes.c_int64), ("mem", HPPAOpMem))


class HPPAOp(ctypes.Structure):
    type: int
    value: HPPAOpValue
    access: int
    _fields_ = (
        ("type", ctypes.c_uint8),
        ("value", HPPAOpValue),
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
class CsHPPA(ctypes.Structure):
    op_count: int
    operands: tuple[HPPAOp, ...]
    _fields_ = (("op_count", ctypes.c_uint8), ("operands", HPPAOp * 5))


def get_arch_info(a):
    return copy_ctypes_list(a.operands[: a.op_count])

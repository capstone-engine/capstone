# Capstone Python bindings, by Peace-Maker <peacemakerctf@gmail.com>

import ctypes

from . import copy_ctypes_list
from .wasm_const import *


# define the API
class WASMBrTable(ctypes.Structure):
    length: int
    address: int
    default_target: int
    _fields_ = (
        ("length", ctypes.c_uint32),
        ("address", ctypes.c_uint64),
        ("default_target", ctypes.c_uint32),
    )


class WASMOpValue(ctypes.Union):
    int7: int
    varuint32: int
    varuint64: int
    uint32: int
    uint64: int
    immediate: tuple[int, int]
    brtable: WASMBrTable
    _fields_ = (
        ("int7", ctypes.c_int8),
        ("varuint32", ctypes.c_uint32),
        ("varuint64", ctypes.c_uint64),
        ("uint32", ctypes.c_uint32),
        ("uint64", ctypes.c_uint64),
        ("immediate", ctypes.c_uint32 * 2),
        ("brtable", WASMBrTable),
    )


class WASMOp(ctypes.Structure):
    type: int
    size: int
    value: WASMOpValue
    _fields_ = (
        ("type", ctypes.c_uint),
        ("size", ctypes.c_uint32),
        ("value", WASMOpValue),
    )

    @property
    def int7(self):
        return self.value.int7

    @property
    def varuint32(self):
        return self.value.varuint32

    @property
    def varuint64(self):
        return self.value.varuint64

    @property
    def uint32(self):
        return self.value.uint32

    @property
    def uint64(self):
        return self.value.uint64

    @property
    def immediate(self):
        return self.value.immediate

    @property
    def brtable(self):
        return self.value.brtable


class CsWasm(ctypes.Structure):
    op_count: int
    operands: tuple[WASMOp, WASMOp]
    _fields_ = (
        ("op_count", ctypes.c_uint8),
        ("operands", WASMOp * 2),
    )


def get_arch_info(a):
    return copy_ctypes_list(a.operands[: a.op_count])

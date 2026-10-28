# Capstone Python bindings, by Nicolas PLANEL <nplanel@gmail.com>

import ctypes

from . import copy_ctypes_list
from .m68k_const import *


# define the API
class M68KOpMem(ctypes.Structure):
    base_reg: int
    index_reg: int
    in_base_reg: int
    in_disp: int
    out_disp: int
    disp: int
    scale: int
    bitfield: int
    width: int
    offset: int
    index_size: int
    in_disp_size: int
    out_disp_size: int
    disp_size: int
    address: int
    _fields_ = (
        ("base_reg", ctypes.c_uint),
        ("index_reg", ctypes.c_uint),
        ("in_base_reg", ctypes.c_uint),
        ("in_disp", ctypes.c_int),
        ("out_disp", ctypes.c_int),
        ("disp", ctypes.c_short),
        ("scale", ctypes.c_ubyte),
        ("bitfield", ctypes.c_ubyte),
        ("width", ctypes.c_ubyte),
        ("offset", ctypes.c_ubyte),
        ("index_size", ctypes.c_ubyte),
        ("in_disp_size", ctypes.c_ubyte),
        ("out_disp_size", ctypes.c_ubyte),
        ("disp_size", ctypes.c_ubyte),
        ("address", ctypes.c_uint64),
    )


class M68KOpRegPair(ctypes.Structure):
    reg_0: int
    reg_1: int
    _fields_ = (
        ("reg_0", ctypes.c_uint),
        ("reg_1", ctypes.c_uint),
    )


class M68KOpFpExtended(ctypes.Structure):
    significand: int
    sign_exp: int
    reserved: int
    _fields_ = (
        ("significand", ctypes.c_uint64),
        ("sign_exp", ctypes.c_uint16),
        ("reserved", ctypes.c_uint16),
    )


class M68KOpFpPacked(ctypes.Structure):
    header: int
    fraction: int
    _fields_ = (
        ("header", ctypes.c_uint32),
        ("fraction", ctypes.c_uint64),
    )


class M68KOpValue(ctypes.Union):
    imm: int
    dimm: float
    simm: float
    fp_extended: M68KOpFpExtended
    fp_packed: M68KOpFpPacked
    reg: int
    reg_pair: M68KOpRegPair
    _fields_ = (
        ("imm", ctypes.c_int64),
        ("dimm", ctypes.c_double),
        ("simm", ctypes.c_float),
        ("fp_extended", M68KOpFpExtended),
        ("fp_packed", M68KOpFpPacked),
        ("reg", ctypes.c_uint),
        ("reg_pair", M68KOpRegPair),
    )


class M68KOpBrDisp(ctypes.Structure):
    disp: int
    disp_size: int
    _fields_ = (
        ("disp", ctypes.c_int),
        ("disp_size", ctypes.c_ubyte),
    )


class M68KOp(ctypes.Structure):
    value: M68KOpValue
    mem: M68KOpMem
    br_disp: M68KOpBrDisp
    register_bits: int
    type: int
    address_mode: int
    flags: int
    _fields_ = (
        ("value", M68KOpValue),
        ("mem", M68KOpMem),
        ("br_disp", M68KOpBrDisp),
        ("register_bits", ctypes.c_uint),
        ("type", ctypes.c_uint),
        ("address_mode", ctypes.c_uint),
        ("flags", ctypes.c_ubyte),
    )

    @property
    def imm(self):
        return self.value.imm

    @property
    def dimm(self):
        return self.value.dimm

    @property
    def simm(self):
        return self.value.simm

    @property
    def fp_extended(self):
        return self.value.fp_extended

    @property
    def fp_packed(self):
        return self.value.fp_packed

    @property
    def reg(self):
        return self.value.reg

    @property
    def reg_pair(self):
        return self.value.reg_pair

    # @property
    # def mem(self):
    #     return self.mem


class M68KOpSize(ctypes.Structure):
    type: int
    size: int
    _fields_ = (
        ("type", ctypes.c_uint),
        ("size", ctypes.c_uint),
    )


class CsM68K(ctypes.Structure):
    operands: tuple[M68KOp, ...]
    op_size: M68KOpSize
    op_count: int
    M68K_OPERAND_COUNT = 6
    _fields_ = (
        ("operands", M68KOp * M68K_OPERAND_COUNT),
        ("op_size", M68KOpSize),
        ("op_count", ctypes.c_uint8),
    )


def get_arch_info(a):
    return (copy_ctypes_list(a.operands[: a.op_count]), a.op_size)

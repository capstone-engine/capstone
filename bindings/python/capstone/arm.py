# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes

from . import copy_ctypes_list
from .arm_const import *


# define the API
class ArmOpMem(ctypes.Structure):
    base: int
    index: int
    scale: int
    disp: int
    align: int
    _fields_ = (
        ("base", ctypes.c_int),
        ("index", ctypes.c_int),
        ("scale", ctypes.c_int),
        ("disp", ctypes.c_int),
        ("align", ctypes.c_uint),
    )


class ArmOpShift(ctypes.Structure):
    type: int
    value: int
    _fields_ = (
        ("type", ctypes.c_uint),
        ("value", ctypes.c_uint),
    )


class ArmSysopReg(ctypes.Union):
    mclasssysreg: int
    bankedreg: int
    raw_val: int
    _fields_ = (
        ("mclasssysreg", ctypes.c_uint),
        ("bankedreg", ctypes.c_uint),
        ("raw_val", ctypes.c_int),
    )


class ArmOpSysop(ctypes.Structure):
    reg: ArmSysopReg
    psr_bits: int
    sysm: int
    msr_mask: int
    _fields_ = (
        ("reg", ArmSysopReg),
        ("psr_bits", ctypes.c_uint),
        ("sysm", ctypes.c_uint16),
        ("msr_mask", ctypes.c_uint8),
    )


class ArmOpValue(ctypes.Union):
    reg: int
    sysop: ArmOpSysop
    imm: int
    pred: int
    fp: float
    mem: ArmOpMem
    setend: int
    _fields_ = (
        ("reg", ctypes.c_uint),
        ("sysop", ArmOpSysop),
        ("imm", ctypes.c_int64),
        ("pred", ctypes.c_int),
        ("fp", ctypes.c_double),
        ("mem", ArmOpMem),
        ("setend", ctypes.c_int),
    )


class ArmOp(ctypes.Structure):
    vector_index: int
    shift: ArmOpShift
    type: int
    value: ArmOpValue
    subtracted: bool
    access: int
    neon_lane: int
    _fields_ = (
        ("vector_index", ctypes.c_int),
        ("shift", ArmOpShift),
        ("type", ctypes.c_uint),
        ("value", ArmOpValue),
        ("subtracted", ctypes.c_bool),
        ("access", ctypes.c_uint),
        ("neon_lane", ctypes.c_int8),
    )

    @property
    def reg(self):
        return self.value.reg

    @property
    def sysop(self):
        return self.value.sysop

    @property
    def imm(self):
        return self.value.imm

    @property
    def pred(self):
        return self.value.pred

    @property
    def fp(self):
        return self.value.fp

    @property
    def mem(self):
        return self.value.mem

    @property
    def setend(self):
        return self.value.setend


class CsArm(ctypes.Structure):
    usermode: bool
    vector_size: int
    vector_data: int
    cps_mode: int
    cps_flag: int
    cc: int
    vcc: int
    update_flags: bool
    post_index: bool
    mem_barrier: int
    pred_mask: int
    op_count: int
    operands: tuple[ArmOp, ...]
    _fields_ = (
        ("usermode", ctypes.c_bool),
        ("vector_size", ctypes.c_int),
        ("vector_data", ctypes.c_int),
        ("cps_mode", ctypes.c_int),
        ("cps_flag", ctypes.c_int),
        ("cc", ctypes.c_uint),
        ("vcc", ctypes.c_uint),
        ("update_flags", ctypes.c_bool),
        ("post_index", ctypes.c_bool),
        ("mem_barrier", ctypes.c_int),
        ("pred_mask", ctypes.c_uint8),
        ("op_count", ctypes.c_uint8),
        ("operands", ArmOp * 36),
    )


def get_arch_info(a):
    return (
        a.usermode,
        a.vector_size,
        a.vector_data,
        a.cps_mode,
        a.cps_flag,
        a.cc,
        a.vcc,
        a.update_flags,
        a.post_index,
        a.mem_barrier,
        a.pred_mask,
        copy_ctypes_list(a.operands[: a.op_count]),
    )

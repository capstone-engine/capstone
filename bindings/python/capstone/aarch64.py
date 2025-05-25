# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes
from . import copy_ctypes_list
from .aarch64_const import *

# define the API
class AArch64OpMem(ctypes.Structure):
    _fields_ = (
        ('base', ctypes.c_uint),
        ('index', ctypes.c_uint),
        ('disp', ctypes.c_int32),
    )

class AArch64ImmRange(ctypes.Structure):
    _fields_ = (
        ('first', ctypes.c_int8),
        ('offset', ctypes.c_int8),
    )

class AArch64SMESliceOffset(ctypes.Union):
    _fields_ = (
        ('imm', ctypes.c_int8),
        ('imm_range', AArch64ImmRange)
    )

class AArch64OpSme(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_uint),
        ('tile', ctypes.c_uint),
        ('slice_reg', ctypes.c_uint),
        ('slice_offset', AArch64SMESliceOffset),
        ('has_range_offset', ctypes.c_bool),
        ('is_vertical', ctypes.c_bool),
    )

class AArch64OpPred(ctypes.Structure):
    _fields_ = (
        ('reg', ctypes.c_uint),
        ('vec_select', ctypes.c_uint),
        ('imm_index', ctypes.c_int),
    )

class AArch64OpShift(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_uint),
        ('value', ctypes.c_uint),
    )

class AArch64SysOpSysReg(ctypes.Union):
    _fields_ = (
        ('sysreg', ctypes.c_uint),
        ('tlbi', ctypes.c_uint),
        ('ic', ctypes.c_uint),
        ('raw_val', ctypes.c_int),
    )

class AArch64SysOpSysImm(ctypes.Union):
    _fields_ = (
        ('dbnxs', ctypes.c_uint),
        ('exactfpimm', ctypes.c_uint),
        ('raw_val', ctypes.c_int),
    )

class AArch64SysOpSysAlias(ctypes.Union):
    _fields_ = (
        ('svcr', ctypes.c_uint),
        ('at', ctypes.c_uint),
        ('db', ctypes.c_uint),
        ('dc', ctypes.c_uint),
        ('isb', ctypes.c_uint),
        ('tsb', ctypes.c_uint),
        ('prfm', ctypes.c_uint),
        ('sveprfm', ctypes.c_uint),
        ('rprfm', ctypes.c_uint),
        ('pstateimm0_15', ctypes.c_uint),
        ('pstateimm0_1', ctypes.c_uint),
        ('psb', ctypes.c_uint),
        ('bti', ctypes.c_uint),
        ('svepredpat', ctypes.c_uint),
        ('sveveclenspecifier', ctypes.c_uint),
        ('raw_val', ctypes.c_int),
    )
class AArch64SysOp(ctypes.Structure):
    _fields_ = (
        ('reg', AArch64SysOpSysReg),
        ('imm', AArch64SysOpSysImm),
        ('alias', AArch64SysOpSysAlias),
        ('sub_type', ctypes.c_uint),
    )

class AArch64OpValue(ctypes.Union):
    _fields_ = (
        ('reg', ctypes.c_uint),
        ('imm', ctypes.c_int64),
        ('imm_range', AArch64ImmRange),
        ('fp', ctypes.c_double),
        ('mem', AArch64OpMem),
        ('sme', AArch64OpSme),
        ('pred', AArch64OpPred),
    )

class AArch64Op(ctypes.Structure):
    _fields_ = (
        ('vector_index', ctypes.c_int),
        ('vas', ctypes.c_uint),
        ('shift', AArch64OpShift),
        ('ext', ctypes.c_uint),
        ('type', ctypes.c_uint),
        ('is_vreg', ctypes.c_bool),
        ('value', AArch64OpValue),
        ('sysop', AArch64SysOp),
        ('access', ctypes.c_uint),
        ('is_list_member', ctypes.c_bool),
    )

    @property
    def imm(self):
        return self.value.imm

    @property
    def reg(self):
        return self.value.reg

    @property
    def fp(self):
        return self.value.fp

    @property
    def mem(self):
        return self.value.mem

    @property
    def imm_range(self):
        return self.value.imm_range

    @property
    def sysop(self):
        return self.sysop

    @property
    def sme(self):
        return self.value.sme



class CsAArch64(ctypes.Structure):
    _fields_ = (
        ('cc', ctypes.c_uint),
        ('update_flags', ctypes.c_bool),
        ('post_index', ctypes.c_bool),
        ('is_doing_sme', ctypes.c_bool),
        ('op_count', ctypes.c_uint8),
        ('operands', AArch64Op * 8),
    )

def get_arch_info(a):
    return (a.cc, a.update_flags, a.post_index, copy_ctypes_list(a.operands[:a.op_count]))


# Capstone Python bindings, by Dmitry Sibirtsev <sibirtsevdl@gmail.com>

import ctypes
from . import copy_ctypes_list
from .hppa_const import *



class HPPAOpMem(ctypes.Structure):
    _fields_ = (
        ('base', ctypes.c_uint),
        ('space', ctypes.c_uint),
        ('base_access', ctypes.c_uint8),
    )

class HPPAModifierValue(ctypes.Union):
    _fields_ = (
        ('str_mod', ctypes.c_char_p),
        ('int_mod', ctypes.c_uint32)
    )

class HPPAModifier(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_int),
        ('value', HPPAModifierValue)
    )

class HPPAExt(ctypes.Structure):
    _fields_ = (
        ('modifiers', HPPAModifier * 5),
        ('mod_num', ctypes.c_uint8),
        ('b_writable', ctypes.c_bool),
        ('cmplt', ctypes.c_bool)
    )

class HPPAOpValue(ctypes.Union):
    _fields_ = (
        ('reg', ctypes.c_uint),
        ('imm', ctypes.c_int64),
        ('mem', HPPAOpMem)
    )


class HPPAOp(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_uint8),
        ('value', HPPAOpValue),
        ('access', ctypes.c_uint)
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
    _fields_ = (
        ('op_count', ctypes.c_uint8),
        ('operands', HPPAOp * 5)
    )

def get_arch_info(a):
    return (copy_ctypes_list(a.operands[:a.op_count]))

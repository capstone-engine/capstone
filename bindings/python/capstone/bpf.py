# Capstone Python bindings
# BPF by david942j <david942j@gmail.com>, 2019

import ctypes
from . import copy_ctypes_list
from .bpf_const import *

class BPFOpMem(ctypes.Structure):
    _fields_ = (
        ('base', ctypes.c_uint8),
        ('disp', ctypes.c_int32),
    )

class BPFOpValue(ctypes.Union):
    _fields_ = (
        ('reg', ctypes.c_uint8),
        ('imm', ctypes.c_uint64),
        ('off', ctypes.c_uint32),
        ('mem', BPFOpMem),
        ('mmem', ctypes.c_uint32),
        ('msh', ctypes.c_uint32),
        ('ext', ctypes.c_uint32),
    )

class BPFOp(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_uint),
        ('value', BPFOpValue),
        ('access', ctypes.c_uint8),
    )

    @property
    def reg(self):
        return self.value.reg

    @property
    def imm(self):
        return self.value.imm

    @property
    def off(self):
        return self.value.off

    @property
    def mem(self):
        return self.value.mem

    @property
    def mmem(self):
        return self.value.mmem

    @property
    def msh(self):
        return self.value.msh

    @property
    def ext(self):
        return self.value.ext


class CsBPF(ctypes.Structure):
    _fields_ = (
        ('op_count', ctypes.c_uint8),
        ('operands', BPFOp * 4),
    )

def get_arch_info(a):
    return (copy_ctypes_list(a.operands[:a.op_count]))


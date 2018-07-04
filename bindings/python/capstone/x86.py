# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes
from . import copy_ctypes_list
from .x86_const import *

# define the API
class X86OpMem(ctypes.Structure):
    _fields_ = (
        ('segment', ctypes.c_uint),
        ('base', ctypes.c_uint),
        ('index', ctypes.c_uint),
        ('scale', ctypes.c_int),
        ('disp', ctypes.c_int64),
    )

class X86OpValue(ctypes.Union):
    _fields_ = (
        ('reg', ctypes.c_uint),
        ('imm', ctypes.c_int64),
        ('mem', X86OpMem),
    )

class X86Op(ctypes.Structure):
    _fields_ = (
        ('type', ctypes.c_uint),
        ('value', X86OpValue),
        ('size', ctypes.c_uint8),
        ('access', ctypes.c_uint8),
        ('avx_bcast', ctypes.c_uint),
        ('avx_zero_opmask', ctypes.c_bool),
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


class CsX86Encoding(ctypes.Structure):
    _fields_ = (
        ('modrm_offset', ctypes.c_uint8),
        ('disp_offset', ctypes.c_uint8),
        ('disp_size', ctypes.c_uint8),
        ('imm_offset', ctypes.c_uint8),
        ('imm_size', ctypes.c_uint8),
    )

class CsX86(ctypes.Structure):
    _fields_ = (
        ('prefix', ctypes.c_uint8 * 4),
        ('opcode', ctypes.c_uint8 * 4),
        ('rex', ctypes.c_uint8),
        ('addr_size', ctypes.c_uint8),
        ('modrm', ctypes.c_uint8),
        ('sib', ctypes.c_uint8),
        ('disp', ctypes.c_int64),
        ('sib_index', ctypes.c_uint),
        ('sib_scale', ctypes.c_int8),
        ('sib_base', ctypes.c_uint),
        ('xop_cc', ctypes.c_uint),
        ('sse_cc', ctypes.c_uint),
        ('avx_cc', ctypes.c_uint),
        ('avx_sae', ctypes.c_bool),
        ('avx_rm', ctypes.c_uint),
        ('eflags', ctypes.c_uint64),
        ('op_count', ctypes.c_uint8),
        ('operands', X86Op * 8),
        ('encoding', CsX86Encoding),
    )

def get_arch_info(a):
    return (a.prefix[:], a.opcode[:], a.rex, a.addr_size, \
            a.modrm, a.sib, a.disp, a.sib_index, a.sib_scale, \
            a.sib_base, a.xop_cc, a.sse_cc, a.avx_cc, a.avx_sae, a.avx_rm, a.eflags, \
            a.encoding.modrm_offset, a.encoding.disp_offset, a.encoding.disp_size, a.encoding.imm_offset, a.encoding.imm_size, \
            copy_ctypes_list(a.operands[:a.op_count]))


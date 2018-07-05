# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes
from . import copy_ctypes_list
from .neo_const import *

# define the API
class CsNeo(ctypes.Structure):
    _fields_ = (
        ('op_size', ctypes.c_byte),
        ('pop', ctypes.c_byte),
        ('push', ctypes.c_byte),
        ('fee', ctypes.c_uint),
    )

def get_arch_info(a):
    if a.fee == NEO_FEE_0:
        return (a.op_size, a.pop, a.push, 0)
    if a.fee == NEO_FEE_01:
        return (a.op_size, a.pop, a.push, 0.1)
    if a.fee == NEO_FEE_001:
        return (a.op_size, a.pop, a.push, 0.01)
    if a.fee == NEO_FEE_002:
        return (a.op_size, a.pop, a.push, 0.02)
    if a.fee == NEO_FEE_0001:
        return (a.op_size, a.pop, a.push, 0.001)
    return None


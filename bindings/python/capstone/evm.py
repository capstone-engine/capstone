# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes
from . import copy_ctypes_list
from .evm_const import *

# define the API
class CsEvm(ctypes.Structure):
    _fields_ = (
        ('pop', ctypes.c_byte),
        ('push', ctypes.c_byte),
        ('fee', ctypes.c_uint),
    )

def get_arch_info(a):
    return (a.pop, a.push, a.fee)


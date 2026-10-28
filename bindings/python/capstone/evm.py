# Capstone Python bindings, by Nguyen Anh Quynnh <aquynh@gmail.com>

import ctypes

from .evm_const import *


# define the API
class CsEvm(ctypes.Structure):
    pop: bytes
    push: bytes
    fee: int
    _fields_ = (
        ("pop", ctypes.c_byte),
        ("push", ctypes.c_byte),
        ("fee", ctypes.c_uint),
    )


def get_arch_info(a):
    return (a.pop, a.push, a.fee)
